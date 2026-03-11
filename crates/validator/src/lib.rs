use std::{collections::HashMap,sync::Arc,time::{Duration, Instant}};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;
use haltchain_policy::{PolicyEngine, PolicyResult, CIRCUIT_BREAK_SECS, MAX_ACTIONS_PER_MINUTE};

///Json body sent to the agent for validation.
#[derive(Debug, Deserialize)]
pub struct ValidationRequest {
    pub agent_id: String.
    pub api_key:  String,//dev mode any is accepted
    pub action:   ActionPayload,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Flat action descriptor.  `action_type` drives which optional fields are checked.
#[derive(Debug, Deserialize)]
pub struct ActionPayload {
    #[serde(rename = "type")]
    pub action_type: String,
    pub amount:      Option<f64>,
    pub currency:    Option<String>,
    pub recipient:   Option<String>,
    pub endpoint:    Option<String>,
    pub method:      Option<String>,
    pub device_id:   Option<String>,
    pub command:     Option<String>,
}

/// Serialised decision value embedded in [`ValidationResponse`].
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Deny,
    CircuitBreak,
}

/// JSON body returned to the agent.
#[derive(Debug, Serialize)]
pub struct ValidationResponse {
    pub decision:               Decision,
    pub transaction_id:         String,
    pub timestamp:              String,
    pub circuit_breaker_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason:                 Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy:                 Option<String>,
    pub actions_this_minute:    usize,
    pub rate_limit:             usize,
}

/// Per-agent snapshot returned by `GET /status/:agent_id`.
#[derive(Debug, Serialize)]
pub struct AgentStatus {
    pub agent_id:               String,
    pub circuit_breaker_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_breaker_reason: Option<String>,
    pub actions_this_minute:    usize,
    pub rate_limit:             usize,
}

//Per-agent mutable state 

struct AgentState {
    /// Timestamps of every action inside the current 60-second sliding window.
    action_timestamps: Vec<Instant>,
    /// `Some((tripped_at, duration, reason))` while the CB is active.
    circuit_break:     Option<(Instant, Duration, String)>,
}

impl AgentState {
    fn new() -> Self {
        Self {
            action_timestamps: Vec::new(),
            circuit_break:     None,
        }
    }

    /// Returns `Some(reason)` if the circuit breaker is currently open.
    /// Automatically clears an *expired* breaker and returns `None`.
    fn circuit_break_active(&mut self) -> Option<String> {
        match &self.circuit_break {
            Some((tripped_at, duration, reason)) if tripped_at.elapsed() < *duration => {
                Some(reason.clone())
            }
            _ => {
                self.circuit_break = None; // reset expired breaker
                None
            }
        }
    }

    fn trip_circuit_breaker(&mut self, duration: Duration, reason: String) {
        self.circuit_break = Some((Instant::now(), duration, reason));
    }

    /// Prunes stale entries and returns the count within the current window.
    fn current_action_count(&mut self) -> usize {
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.action_timestamps.retain(|&t| t > cutoff);
        self.action_timestamps.len()
    }

    fn record_action(&mut self) {
        self.action_timestamps.push(Instant::now());
    }
}

// Shared application state 

/// Thread-safe, cheaply-cloneable handle injected into every Axum route.
pub struct AppState {
    agents: RwLock<HashMap<String, AgentState>>,
    policy: PolicyEngine,
}

impl AppState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            agents: RwLock::new(HashMap::new()),
            policy: PolicyEngine::default(),
        })
    }

    /// Full validation pipeline for a single request.
    pub async fn validate(&self, req: &ValidationRequest) -> ValidationResponse {
        // Week 1 dev-mode auth: any non-empty api_key is accepted.
        // TODO Week 2: replace with HMAC-signed key verification.
        let transaction_id = Uuid::new_v4().to_string();
        let timestamp       = Utc::now().to_rfc3339();

        let mut agents = self.agents.write().await;
        let agent = agents
            .entry(req.agent_id.clone())
            .or_insert_with(AgentState::new);

        // 1. Circuit breaker — checked before anything else.
        if let Some(reason) = agent.circuit_break_active() {
            let actions = agent.current_action_count();
            return ValidationResponse {
                decision:               Decision::CircuitBreak,
                transaction_id,
                timestamp,
                circuit_breaker_active: true,
                reason:                 Some(reason),
                policy:                 Some("CIRCUIT_BREAKER".into()),
                actions_this_minute:    actions,
                rate_limit:             MAX_ACTIONS_PER_MINUTE,
            };
        }

        // 2. Sliding-window rate limit.  Check *before* recording this action.
        let current_count = agent.current_action_count();
        if current_count >= MAX_ACTIONS_PER_MINUTE {
            let reason = format!(
                "Rate limit exceeded: {} actions in the last 60 s (max {})",
                current_count, MAX_ACTIONS_PER_MINUTE
            );
            agent.trip_circuit_breaker(
                Duration::from_secs(CIRCUIT_BREAK_SECS),
                reason.clone(),
            );
            return ValidationResponse {
                decision:               Decision::CircuitBreak,
                transaction_id,
                timestamp,
                circuit_breaker_active: true,
                reason:                 Some(reason),
                policy:                 Some("MAX_ACTIONS_PER_MINUTE".into()),
                actions_this_minute:    current_count,
                rate_limit:             MAX_ACTIONS_PER_MINUTE,
            };
        }

        // 3. Transfer-amount policy.
        if req.action.action_type == "transfer" {
            if let Some(amount) = req.action.amount {
                if let PolicyResult::Deny { reason, policy } =
                    self.policy.check_transfer(amount)
                {
                    agent.record_action(); // attempt still counts against rate limit
                    let actions = agent.current_action_count();
                    return ValidationResponse {
                        decision:               Decision::Deny,
                        transaction_id,
                        timestamp,
                        circuit_breaker_active: false,
                        reason:                 Some(reason),
                        policy:                 Some(policy.into()),
                        actions_this_minute:    actions,
                        rate_limit:             MAX_ACTIONS_PER_MINUTE,
                    };
                }
            }
        }

        // 4. All checks passed.
        agent.record_action();
        let actions = agent.current_action_count();
        ValidationResponse {
            decision:               Decision::Allow,
            transaction_id,
            timestamp,
            circuit_breaker_active: false,
            reason:                 None,
            policy:                 None,
            actions_this_minute:    actions,
            rate_limit:             MAX_ACTIONS_PER_MINUTE,
        }
    }

    /// Returns the current status snapshot for `agent_id` (creates a fresh entry if absent).
    pub async fn agent_status(&self, agent_id: &str) -> AgentStatus {
        let mut agents = self.agents.write().await;
        let agent = agents
            .entry(agent_id.to_string())
            .or_insert_with(AgentState::new);

        let cb_reason  = agent.circuit_break_active();
        let cb_active  = cb_reason.is_some();
        let actions    = agent.current_action_count();

        AgentStatus {
            agent_id:               agent_id.to_string(),
            circuit_breaker_active: cb_active,
            circuit_breaker_reason: cb_reason,
            actions_this_minute:    actions,
            rate_limit:             MAX_ACTIONS_PER_MINUTE,
        }
    }
}
