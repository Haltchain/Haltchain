//! Tuesday: Goal declaration API.
//!
//! Agents register their intent at session start by calling [`GoalStore::declare`].
//! The intent string is embedded and stored; subsequent actions are scored
//! against the goal vector by the drift scorer.

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalDeclaration {
    pub agent_id: String,
    pub session_id: String,
    /// Human-readable intent registered by the agent.
    pub intent: String,
    /// Unit-norm embedding of `intent`.
    pub embedding: Vec<f64>,
    pub declared_at: DateTime<Utc>,
}

// ─── Store ────────────────────────────────────────────────────────────────────

pub struct GoalStore {
    inner: Mutex<HashMap<String, GoalDeclaration>>,
}

impl GoalStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Store a goal with a pre-computed embedding (caller embeds via EmbedPipeline).
    pub fn declare(
        &self,
        agent_id: &str,
        session_id: &str,
        intent: &str,
        embedding: Vec<f64>,
    ) -> GoalDeclaration {
        let decl = GoalDeclaration {
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            intent: intent.to_string(),
            embedding,
            declared_at: Utc::now(),
        };
        self.inner
            .lock()
            .insert(Self::key(agent_id, session_id), decl.clone());
        decl
    }

    pub fn get(&self, agent_id: &str, session_id: &str) -> Option<GoalDeclaration> {
        self.inner
            .lock()
            .get(&Self::key(agent_id, session_id))
            .cloned()
    }

    /// Revoke a goal (e.g., when the agent clarifies intent).
    /// Returns `true` if a goal existed.
    pub fn revoke(&self, agent_id: &str, session_id: &str) -> bool {
        self.inner
            .lock()
            .remove(&Self::key(agent_id, session_id))
            .is_some()
    }

    fn key(agent_id: &str, session_id: &str) -> String {
        format!("{agent_id}:{session_id}")
    }
}

impl Default for GoalStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn v() -> Vec<f64> {
        vec![0.1, 0.9]
    }

    #[test]
    fn declare_and_retrieve() {
        let s = GoalStore::new();
        s.declare("a1", "s1", "transfer payments", v());
        let g = s.get("a1", "s1").unwrap();
        assert_eq!(g.agent_id, "a1");
        assert_eq!(g.intent, "transfer payments");
    }

    #[test]
    fn revoke_removes_goal() {
        let s = GoalStore::new();
        s.declare("a1", "s1", "intent", v());
        assert!(s.revoke("a1", "s1"));
        assert!(s.get("a1", "s1").is_none());
        assert!(!s.revoke("a1", "s1")); // already gone
    }

    #[test]
    fn overwrite_goal() {
        let s = GoalStore::new();
        s.declare("a1", "s1", "old", vec![0.0]);
        s.declare("a1", "s1", "new", vec![1.0]);
        assert_eq!(s.get("a1", "s1").unwrap().intent, "new");
    }

    #[test]
    fn different_sessions_are_independent() {
        let s = GoalStore::new();
        s.declare("a1", "s1", "intent A", v());
        s.declare("a1", "s2", "intent B", vec![0.5, 0.5]);
        assert_eq!(s.get("a1", "s1").unwrap().intent, "intent A");
        assert_eq!(s.get("a1", "s2").unwrap().intent, "intent B");
    }
}
