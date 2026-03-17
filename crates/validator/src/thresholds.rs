use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Key format: `"{domain}:{rule_id}"`, e.g. `"resource:max_tokens_per_minute"`.
///
/// Currently wired into `ActionContext` in `validate_inner`:
///   - `resource:max_tokens_per_minute`
///   - `resource:max_compute_seconds_per_hour`
pub struct ThresholdStore {
    overrides: DashMap<String, f64>,
    variants: DashMap<String, PolicyVariant>,
    /// agent_id → variant_id
    agent_variants: DashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVariant {
    pub id: String,
    pub name: String,
    /// Threshold overrides for agents enrolled in this variant.
    pub thresholds: HashMap<String, f64>,
    /// Agents explicitly enrolled.  Empty = unassigned.
    pub agent_ids: Vec<String>,
}

impl ThresholdStore {
    pub fn new() -> Self {
        Self {
            overrides: DashMap::new(),
            variants: DashMap::new(),
            agent_variants: DashMap::new(),
        }
    }

    pub fn get(&self, key: &str) -> Option<f64> {
        self.overrides.get(key).map(|v| *v)
    }

    pub fn set(&self, key: impl Into<String>, value: f64) -> Option<f64> {
        self.overrides.insert(key.into(), value)
    }

    pub fn all_overrides(&self) -> Vec<(String, f64)> {
        let mut out: Vec<(String, f64)> = self
            .overrides
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn add_variant(&self, variant: PolicyVariant) {
        if let Some(previous) = self.variants.get(&variant.id) {
            for agent_id in &previous.agent_ids {
                self.agent_variants.remove(agent_id);
            }
        }
        for agent_id in &variant.agent_ids {
            self.agent_variants
                .insert(agent_id.clone(), variant.id.clone());
        }
        self.variants.insert(variant.id.clone(), variant);
    }

    pub fn list_variants(&self) -> Vec<PolicyVariant> {
        let mut out: Vec<PolicyVariant> = self.variants.iter().map(|e| e.value().clone()).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    pub fn remove_variant(&self, variant_id: &str) -> Option<PolicyVariant> {
        let (_, variant) = self.variants.remove(variant_id)?;
        for agent_id in &variant.agent_ids {
            let assigned = self
                .agent_variants
                .get(agent_id)
                .map(|cur| cur.value().clone());
            if assigned.as_deref() == Some(variant_id) {
                self.agent_variants.remove(agent_id);
            }
        }
        Some(variant)
    }

    pub fn enrolled_variant(&self, agent_id: &str) -> Option<String> {
        self.agent_variants.get(agent_id).map(|v| v.value().clone())
    }

    /// Effective thresholds for an agent: variant overrides layered on global overrides.
    pub fn effective_thresholds(&self, agent_id: &str) -> HashMap<String, f64> {
        let mut base: HashMap<String, f64> = self.all_overrides().into_iter().collect();
        if let Some(vid) = self.agent_variants.get(agent_id)
            && let Some(variant) = self.variants.get(vid.value())
        {
            for (k, v) in &variant.thresholds {
                base.insert(k.clone(), *v);
            }
        }
        base
    }
}

impl Default for ThresholdStore {
    fn default() -> Self {
        Self::new()
    }
}
