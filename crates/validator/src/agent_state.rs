use std::time::{Duration, Instant};

use haltchain_analytics::{
    SlidingWindowTracker, features,
    isolation_forest::{ANOMALY_THRESHOLD, AnomalyResult, IsolationForest},
};
use haltchain_embeddings::{EmbedPipeline, ModelKind};

pub(crate) const DEFAULT_MAX_EWMA_VELOCITY: f64 = 600.0;
pub(crate) const DEFAULT_MAX_RECIPIENT_TOTAL_PER_MINUTE: f64 = 1000.0;

/// Per-agent mutable runtime state.
pub(crate) struct AgentState {
    pub action_timestamps: Vec<Instant>,
    pub circuit_break: Option<(Instant, Duration, String)>,
    pub tracker: SlidingWindowTracker,
    pub recent_amounts: Vec<(Instant, f64)>,
    pub recent_recipients: Vec<String>,
    pub recent_features: Vec<Vec<f64>>,
    pub anomaly_model: Option<IsolationForest>,
    pub anomaly_generation: u64,
    pub anomaly_retrain_inflight: bool,
    pub samples_since_retrain: usize,
    pub prev_velocity_1m: f64,
    pub last_anomaly_score: Option<f64>,
}

pub(crate) struct AnomalyRetrainPlan {
    pub generation: u64,
    pub samples: Vec<Vec<f64>>,
}

impl AgentState {
    pub fn new() -> Self {
        Self {
            action_timestamps: Vec::new(),
            circuit_break: None,
            tracker: SlidingWindowTracker::new(),
            recent_amounts: Vec::new(),
            recent_recipients: Vec::new(),
            recent_features: Vec::new(),
            anomaly_model: None,
            anomaly_generation: 0,
            anomaly_retrain_inflight: false,
            samples_since_retrain: 0,
            prev_velocity_1m: 0.0,
            last_anomaly_score: None,
        }
    }

    /// Returns `Some(reason)` if the circuit breaker is open.
    /// Automatically clears an expired breaker and returns `None`.
    pub fn circuit_break_active(&mut self) -> Option<String> {
        match &self.circuit_break {
            Some((tripped_at, duration, reason)) if tripped_at.elapsed() < *duration => {
                Some(reason.clone())
            }
            _ => {
                self.circuit_break = None;
                None
            }
        }
    }

    pub fn trip_circuit_breaker(&mut self, duration: Duration, reason: String) {
        self.circuit_break = Some((Instant::now(), duration, reason));
    }

    /// Prunes stale entries and returns the count within the current window.
    pub fn current_action_count(&mut self) -> usize {
        let cutoff = Instant::now() - Duration::from_secs(60);
        self.action_timestamps.retain(|&t| t > cutoff);
        self.action_timestamps.len()
    }

    pub fn record_action(&mut self) {
        self.action_timestamps.push(Instant::now());
    }

    pub fn observe_signal(
        &mut self,
        amount: f64,
        recipient: Option<&str>,
    ) -> (Option<AnomalyResult>, Option<AnomalyRetrainPlan>) {
        self.tracker.record(amount);

        self.recent_amounts.push((Instant::now(), amount));
        if self.recent_amounts.len() > 512 {
            self.recent_amounts.remove(0);
        }

        self.recent_recipients
            .push(recipient.unwrap_or("unknown").to_string());
        if self.recent_recipients.len() > 512 {
            self.recent_recipients.remove(0);
        }

        let recipient_refs: Vec<&str> = self.recent_recipients.iter().map(String::as_str).collect();
        let feature =
            features::extract(&self.recent_amounts, &recipient_refs, self.prev_velocity_1m);
        self.prev_velocity_1m = feature.velocity_1m;

        let point = vec![
            feature.velocity_1m,
            feature.velocity_5m,
            feature.acceleration,
            feature.entropy,
            feature.mean_amount,
            feature.cv_amount,
            feature.recipient_diversity,
        ];
        self.recent_features.push(point.clone());
        if self.recent_features.len() > 512 {
            self.recent_features.remove(0);
        }

        self.samples_since_retrain = self.samples_since_retrain.saturating_add(1);

        let should_retrain = !self.anomaly_retrain_inflight
            && self.recent_features.len() >= 64
            && (self.anomaly_model.is_none() || self.samples_since_retrain >= 64);
        let retrain_plan = if should_retrain {
            self.anomaly_retrain_inflight = true;
            self.samples_since_retrain = 0;
            self.anomaly_generation = self.anomaly_generation.saturating_add(1);
            let start = self.recent_features.len().saturating_sub(256);
            Some(AnomalyRetrainPlan {
                generation: self.anomaly_generation,
                samples: self.recent_features[start..].to_vec(),
            })
        } else {
            None
        };

        if let Some(model) = &self.anomaly_model {
            let score = model.score(&point);
            let result = AnomalyResult {
                is_anomaly: score > ANOMALY_THRESHOLD,
                score,
            };
            self.last_anomaly_score = Some(score);
            return (Some(result), retrain_plan);
        }

        self.last_anomaly_score = None;
        let result = cold_start_check(&self.recent_amounts, amount);
        (result, retrain_plan)
    }

    pub fn apply_retrained_model(&mut self, generation: u64, model: IsolationForest) -> bool {
        if generation != self.anomaly_generation {
            return false;
        }
        self.anomaly_model = Some(model);
        self.anomaly_retrain_inflight = false;
        true
    }

    pub fn mark_retrain_failed(&mut self, generation: u64) {
        if generation == self.anomaly_generation {
            self.anomaly_retrain_inflight = false;
        }
    }
}

/// Heuristic anomaly check used before the Isolation Forest is trained (cold start).
/// Returns `Some(AnomalyResult)` only when the amount is a clear outlier (|z| > 3).
/// Returns `None` when there is insufficient history (<= 2 samples).
pub(crate) fn cold_start_check(
    recent: &[(Instant, f64)],
    current_amount: f64,
) -> Option<AnomalyResult> {
    if recent.len() < 3 {
        return None;
    }
    let n = recent.len() as f64;
    let mean = recent.iter().map(|(_, a)| a).sum::<f64>() / n;
    let var = recent.iter().map(|(_, a)| (a - mean).powi(2)).sum::<f64>() / (n - 1.0);
    let std_dev = var.sqrt();
    if std_dev < 1e-9 {
        // Uniform baseline: any meaningful shift is a strong anomaly signal.
        let shifted = (current_amount - mean).abs() > 1e-9;
        return Some(AnomalyResult {
            is_anomaly: shifted,
            score: if shifted { 1.0 } else { 0.0 },
        });
    }
    let z = (current_amount - mean).abs() / std_dev;
    let score = z / (z + 3.0);
    let is_anomaly = z > 3.0;
    Some(AnomalyResult { is_anomaly, score })
}

/// Builds an `EmbedPipeline` from environment variables.
pub(crate) fn build_embed_pipeline() -> EmbedPipeline {
    if let Ok(url) = std::env::var("EMBEDDING_URL") {
        let model_name = std::env::var("EMBEDDING_MODEL")
            .unwrap_or_else(|_| "text-embedding-3-small".to_string());
        let dims = std::env::var("EMBEDDING_DIMS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1536);
        let api_key = std::env::var("EMBEDDING_API_KEY").ok();
        tracing::info!(url = %url, model = %model_name, dims, "using remote embedding model");
        EmbedPipeline::new(ModelKind::remote(url, model_name, api_key, dims))
    } else {
        tracing::warn!("EMBEDDING_URL not set; using LocalModel fallback with lexical heuristics");
        EmbedPipeline::new(ModelKind::local_or_hash())
    }
}
