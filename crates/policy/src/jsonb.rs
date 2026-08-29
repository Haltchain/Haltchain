/// JSONB-backed policy evaluator for Phase 1b PostgreSQL-native compliance engine.
///
/// Loads policy rules from a `serde_json::Value` (sourced from `policy_configs.rules`
/// in PostgreSQL) and overrides the default `CircuitBreaker` thresholds.
///
/// # Example JSONB rules structure
/// ```json
/// {
///   "max_transfer_usd": 5000.0,
///   "max_actions_per_minute": 20,
///   "max_pii_fields": 3,
///   "max_requested_columns_ratio": 0.5,
///   "blocked_jurisdictions": ["CN", "RU", "IR"],
///   "max_cpu_percent": 90.0,
///   "max_memory_percent": 90.0,
///   "max_dependency_cascade_depth": 5,
///   "max_resource_tokens_per_min": 200000,
///   "max_storage_writes_per_min": 1000
/// }
/// ```
///
/// Any missing key falls back to the compiled-in default constant.
use serde_json::Value;

use crate::{ActionContext, PolicyResult};

/// Policy thresholds loaded from a JSONB `rules` document.
#[derive(Debug, Clone)]
pub struct JsonbPolicy {
    pub max_transfer_usd: f64,
    pub max_actions_per_minute: usize,
    pub max_pii_fields: usize,
    /// Fraction of task-necessary columns that may be requested (0.0–1.0).
    pub max_requested_columns_ratio: f64,
    pub blocked_jurisdictions: Vec<String>,
    pub max_cpu_percent: f64,
    pub max_memory_percent: f64,
    pub max_dependency_cascade_depth: usize,
    pub max_resource_tokens_per_min: u64,
    pub max_storage_writes_per_min: u64,
}

impl Default for JsonbPolicy {
    fn default() -> Self {
        Self {
            max_transfer_usd: crate::MAX_TRANSFER_USD,
            max_actions_per_minute: crate::MAX_ACTIONS_PER_MINUTE,
            max_pii_fields: 0,
            max_requested_columns_ratio: 1.0,
            blocked_jurisdictions: Vec::new(),
            max_cpu_percent: 80.0,
            max_memory_percent: 80.0,
            max_dependency_cascade_depth: 3,
            max_resource_tokens_per_min: 100_000,
            max_storage_writes_per_min: 500,
        }
    }
}

impl JsonbPolicy {
    /// Parse a `serde_json::Value` (from `policy_configs.rules`) into a `JsonbPolicy`.
    /// Unknown or missing keys fall back to compiled-in defaults.
    pub fn from_jsonb(rules: &Value) -> Self {
        let defaults = Self::default();
        Self {
            max_transfer_usd: rules
                .get("max_transfer_usd")
                .and_then(Value::as_f64)
                .unwrap_or(defaults.max_transfer_usd),
            max_actions_per_minute: rules
                .get("max_actions_per_minute")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(defaults.max_actions_per_minute),
            max_pii_fields: rules
                .get("max_pii_fields")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(defaults.max_pii_fields),
            max_requested_columns_ratio: rules
                .get("max_requested_columns_ratio")
                .and_then(Value::as_f64)
                .unwrap_or(defaults.max_requested_columns_ratio),
            blocked_jurisdictions: rules
                .get("blocked_jurisdictions")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(|s| s.to_uppercase())
                        .collect()
                })
                .unwrap_or(defaults.blocked_jurisdictions),
            max_cpu_percent: rules
                .get("max_cpu_percent")
                .and_then(Value::as_f64)
                .unwrap_or(defaults.max_cpu_percent),
            max_memory_percent: rules
                .get("max_memory_percent")
                .and_then(Value::as_f64)
                .unwrap_or(defaults.max_memory_percent),
            max_dependency_cascade_depth: rules
                .get("max_dependency_cascade_depth")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(defaults.max_dependency_cascade_depth),
            max_resource_tokens_per_min: rules
                .get("max_resource_tokens_per_min")
                .and_then(Value::as_u64)
                .unwrap_or(defaults.max_resource_tokens_per_min),
            max_storage_writes_per_min: rules
                .get("max_storage_writes_per_min")
                .and_then(Value::as_u64)
                .unwrap_or(defaults.max_storage_writes_per_min),
        }
    }

    /// Evaluate an `ActionContext` against the JSONB-loaded thresholds.
    /// Returns the first `Deny` encountered, or `Pass` if all checks pass.
    pub fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        // Financial
        if let Some(amount) = ctx.transfer_amount_usd
            && amount > self.max_transfer_usd
        {
            return PolicyResult::Deny {
                reason: format!(
                    "transfer ${amount:.2} exceeds JSONB policy limit ${:.2}",
                    self.max_transfer_usd
                ),
                policy: "MAX_TRANSFER_USD",
            };
        }
        if let Some(apm) = ctx.actions_per_minute
            && apm > self.max_actions_per_minute
        {
            return PolicyResult::Deny {
                reason: format!(
                    "actions/min {apm} exceeds JSONB policy limit {}",
                    self.max_actions_per_minute
                ),
                policy: "MAX_ACTIONS_PER_MINUTE",
            };
        }

        // Privacy — PII field count
        if let Some(pii) = ctx.pii_field_count
            && pii > self.max_pii_fields
        {
            return PolicyResult::Deny {
                reason: format!(
                    "PII fields {pii} exceeds JSONB policy limit {}",
                    self.max_pii_fields
                ),
                policy: "MAX_PII_FIELDS",
            };
        }

        // Privacy — column minimization ratio
        if let (Some(req), Some(necessary)) = (ctx.requested_columns, ctx.task_necessary_columns)
            && necessary > 0
        {
            let ratio = req as f64 / necessary as f64;
            if ratio > self.max_requested_columns_ratio {
                return PolicyResult::Deny {
                    reason: format!(
                        "column ratio {ratio:.2} exceeds JSONB limit {:.2}",
                        self.max_requested_columns_ratio
                    ),
                    policy: "COLUMN_MINIMIZATION",
                };
            }
        }

        // Compliance — blocked jurisdictions
        if let Some(dest) = &ctx.destination_jurisdiction
            && self.blocked_jurisdictions.contains(&dest.to_uppercase())
        {
            return PolicyResult::Deny {
                reason: format!("destination jurisdiction '{dest}' is blocked by JSONB policy"),
                policy: "BLOCKED_JURISDICTION",
            };
        }

        // Operational — CPU / memory
        if let Some(cpu) = ctx.cpu_percent
            && cpu > self.max_cpu_percent
        {
            return PolicyResult::Deny {
                reason: format!(
                    "CPU {cpu:.1}% exceeds JSONB policy limit {:.1}%",
                    self.max_cpu_percent
                ),
                policy: "CPU_THRESHOLD",
            };
        }
        if let Some(mem) = ctx.memory_percent
            && mem > self.max_memory_percent
        {
            return PolicyResult::Deny {
                reason: format!(
                    "memory {mem:.1}% exceeds JSONB policy limit {:.1}%",
                    self.max_memory_percent
                ),
                policy: "MEMORY_THRESHOLD",
            };
        }
        if let Some(depth) = ctx.dependency_cascade_depth
            && depth > self.max_dependency_cascade_depth
        {
            return PolicyResult::Deny {
                reason: format!(
                    "dependency cascade depth {depth} exceeds JSONB policy limit {}",
                    self.max_dependency_cascade_depth
                ),
                policy: "MAX_DEPENDENCY_CASCADE_DEPTH",
            };
        }

        PolicyResult::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_default() -> ActionContext {
        ActionContext {
            agent_id: "test-agent".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_jsonb_defaults_pass_empty_context() {
        let policy = JsonbPolicy::from_jsonb(&json!({}));
        assert_eq!(policy.evaluate(&ctx_default()), PolicyResult::Pass);
    }

    #[test]
    fn test_jsonb_transfer_deny() {
        let policy = JsonbPolicy::from_jsonb(&json!({ "max_transfer_usd": 100.0 }));
        let mut ctx = ctx_default();
        ctx.transfer_amount_usd = Some(200.0);
        assert!(matches!(
            policy.evaluate(&ctx),
            PolicyResult::Deny {
                policy: "MAX_TRANSFER_USD",
                ..
            }
        ));
    }

    #[test]
    fn test_jsonb_transfer_pass_at_limit() {
        let policy = JsonbPolicy::from_jsonb(&json!({ "max_transfer_usd": 100.0 }));
        let mut ctx = ctx_default();
        ctx.transfer_amount_usd = Some(100.0);
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    #[test]
    fn test_jsonb_blocked_jurisdiction_deny() {
        let policy = JsonbPolicy::from_jsonb(&json!({
            "blocked_jurisdictions": ["CN", "RU"]
        }));
        let mut ctx = ctx_default();
        ctx.destination_jurisdiction = Some("cn".to_string()); // lowercase normalised
        assert!(matches!(
            policy.evaluate(&ctx),
            PolicyResult::Deny {
                policy: "BLOCKED_JURISDICTION",
                ..
            }
        ));
    }

    #[test]
    fn test_jsonb_allowed_jurisdiction_pass() {
        let policy = JsonbPolicy::from_jsonb(&json!({
            "blocked_jurisdictions": ["CN", "RU"]
        }));
        let mut ctx = ctx_default();
        ctx.destination_jurisdiction = Some("DE".to_string());
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
    }

    #[test]
    fn test_jsonb_cpu_threshold_deny() {
        let policy = JsonbPolicy::from_jsonb(&json!({ "max_cpu_percent": 70.0 }));
        let mut ctx = ctx_default();
        ctx.cpu_percent = Some(85.0);
        assert!(matches!(
            policy.evaluate(&ctx),
            PolicyResult::Deny {
                policy: "CPU_THRESHOLD",
                ..
            }
        ));
    }

    #[test]
    fn test_jsonb_missing_fields_use_defaults() {
        let policy = JsonbPolicy::from_jsonb(&json!({}));
        // Default max_transfer_usd is 1000.0 (from crate::MAX_TRANSFER_USD)
        let mut ctx = ctx_default();
        ctx.transfer_amount_usd = Some(500.0);
        assert_eq!(policy.evaluate(&ctx), PolicyResult::Pass);
        ctx.transfer_amount_usd = Some(1001.0);
        assert!(matches!(policy.evaluate(&ctx), PolicyResult::Deny { .. }));
    }
}
