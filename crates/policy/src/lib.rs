pub const MAX_TRANSFER_USD: f64 = 1_000.0; //max transfer
pub const MAX_ACTIONS_PER_MINUTE: usize = 10; //max action
pub const CIRCUIT_BREAK_SECS: u64 = 300; //hold time

// ─── Core decision type

/// Outcome of a single policy check.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyResult {
    Pass,
    Deny {
        reason: String,
        /// Machine-readable policy identifier returned to the caller.
        policy: &'static str,
    },
}

// ─── Breaker trait

/// A self-contained circuit breaker for one domain.
///
/// Implementations must be stateless and pure — all mutable state lives in the
/// caller's context object.  This makes breakers trivially composable and
/// testable in isolation.
pub trait CircuitBreaker: Send + Sync {
    /// Domain label used in logs and API responses (e.g. `"financial"`).
    fn domain(&self) -> &'static str;
    /// Evaluate the action context.  Returns `Pass` or `Deny`.
    fn evaluate(&self, ctx: &ActionContext) -> PolicyResult;
}

// ─── Action context

/// Unified context passed to every circuit breaker.
///
/// Fields are `Option` so callers only populate what is relevant for their
/// domain; breakers skip checks when their required fields are absent.
#[derive(Debug, Default, Clone)]
pub struct ActionContext {
    pub agent_id: String,
    // Financial
    pub transfer_amount_usd: Option<f64>,
    pub actions_per_minute: Option<usize>,
    // Privacy
    pub pii_field_count: Option<usize>,
    pub requested_columns: Option<usize>,
    pub task_necessary_columns: Option<usize>,
    pub cross_border_restricted: Option<bool>,
    // Security
    pub declared_scopes: Option<Vec<String>>,
    pub requested_scopes: Option<Vec<String>>,
    pub accessing_undeclared_service: Option<bool>,
    // Operational
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    pub dependency_cascade_depth: Option<usize>,
    // Compliance
    /// ISO-3166-1 alpha-2 country of the data destination (e.g. "CN", "RU").
    pub destination_jurisdiction: Option<String>,
    /// Agent's registered data schema fields (what it declared it would touch).
    pub registered_schema_fields: Option<Vec<String>>,
    /// Actual fields present in the outbound payload.
    pub payload_fields: Option<Vec<String>>,
    pub payload_contains_pii: Option<bool>,
    pub gdpr_deletion_requested: Option<bool>,
    pub retention_days_requested: Option<u32>,
    // Resource
    pub tokens_per_minute: Option<f64>,
    pub compute_seconds_per_hour: Option<f64>,
    pub max_tokens_per_minute: Option<f64>,
    pub max_compute_seconds_per_hour: Option<f64>,
    pub api_rate_limit_pct: Option<f64>,
}

// ─── Domain modules

pub mod aggregate;
pub mod compliance;
pub mod financial;
pub mod operational;
pub mod privacy;
pub mod resource;
pub mod security;
// Re-export all domain types for backward compatibility.
pub use aggregate::{AggregateBreaker, AggregateMode, PolicyEngine};
pub use compliance::ComplianceBreaker;
pub use financial::FinancialBreaker;
pub use operational::OperationalBreaker;
pub use privacy::PrivacyBreaker;
pub use resource::ResourceBreaker;
pub use security::SecurityBreaker;

#[cfg(test)]
mod tests {
    use super::*;
    // ── Legacy PolicyEngine
    #[test]
    fn allow_under_limit() {
        assert_eq!(PolicyEngine.check_transfer(999.99), PolicyResult::Pass);
    }

    #[test]
    fn allow_at_limit() {
        assert_eq!(PolicyEngine.check_transfer(1_000.0), PolicyResult::Pass);
    }

    #[test]
    fn deny_over_limit() {
        assert!(matches!(
            PolicyEngine.check_transfer(1_000.01),
            PolicyResult::Deny {
                policy: "MAX_TRANSFER_USD",
                ..
            }
        ));
    }
    // ── FinancialBreaker
    #[test]
    fn financial_pass() {
        let b = FinancialBreaker::default();
        assert_eq!(
            b.evaluate(&ActionContext {
                transfer_amount_usd: Some(50.0),
                ..Default::default()
            }),
            PolicyResult::Pass
        );
    }

    #[test]
    fn financial_velocity() {
        let b = FinancialBreaker::default();
        let r = b.evaluate(&ActionContext {
            actions_per_minute: Some(11),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "MAX_ACTIONS_PER_MINUTE",
                ..
            }
        ));
    }
    // ── PrivacyBreaker
    #[test]
    fn privacy_pii_over_limit() {
        let b = PrivacyBreaker::default();
        let r = b.evaluate(&ActionContext {
            pii_field_count: Some(11),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "PII_CONCENTRATION",
                ..
            }
        ));
    }

    #[test]
    fn privacy_over_collection() {
        let b = PrivacyBreaker::default();
        let r = b.evaluate(&ActionContext {
            requested_columns: Some(21),
            task_necessary_columns: Some(10),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "DATA_MINIMISATION",
                ..
            }
        ));
    }

    #[test]
    fn privacy_cross_border() {
        let b = PrivacyBreaker::default();
        let r = b.evaluate(&ActionContext {
            cross_border_restricted: Some(true),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "CROSS_BORDER_TRANSFER",
                ..
            }
        ));
    }

    // SecurityBreaker

    #[test]
    fn security_scope_creep() {
        let b = SecurityBreaker;
        let r = b.evaluate(&ActionContext {
            declared_scopes: Some(vec!["read:users".into()]),
            requested_scopes: Some(vec!["read:users".into(), "write:admin".into()]),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "SCOPE_CREEP",
                ..
            }
        ));
    }

    #[test]
    fn security_lateral_movement() {
        let r = SecurityBreaker.evaluate(&ActionContext {
            accessing_undeclared_service: Some(true),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "LATERAL_MOVEMENT",
                ..
            }
        ));
    }

    //OperationalBreaker

    #[test]
    fn operational_cpu() {
        let r = OperationalBreaker::default().evaluate(&ActionContext {
            cpu_percent: Some(95.0),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "CPU_EXHAUSTION",
                ..
            }
        ));
    }

    #[test]
    fn operational_cascade() {
        let r = OperationalBreaker::default().evaluate(&ActionContext {
            dependency_cascade_depth: Some(6),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "DEPENDENCY_CASCADE",
                ..
            }
        ));
    }

    // ── AggregateBreaker ─────────────────────────────────────────────────────

    #[test]
    fn aggregate_stops_at_first_deny() {
        let agg = AggregateBreaker::default_any();
        // Financial triggers first
        let r = agg.evaluate(&ActionContext {
            transfer_amount_usd: Some(5_000.0),
            pii_field_count: Some(20), // would also deny, but financial wins
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "MAX_TRANSFER_USD",
                ..
            }
        ));
    }

    #[test]
    fn aggregate_all_pass() {
        let agg = AggregateBreaker::default_any();
        assert_eq!(
            agg.evaluate(&ActionContext {
                agent_id: "bot".into(),
                ..Default::default()
            }),
            PolicyResult::Pass
        );
    }

    #[test]
    fn aggregate_or_mode_denies_on_any_breaker() {
        let agg = AggregateBreaker::default_any();
        assert_eq!(agg.mode(), AggregateMode::Any);
        let r = agg.evaluate(&ActionContext {
            transfer_amount_usd: Some(2_000.0),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "MAX_TRANSFER_USD",
                ..
            }
        ));
    }

    #[test]
    fn aggregate_and_mode_requires_all_breakers_to_deny() {
        let agg = AggregateBreaker::with_mode(
            vec![
                Box::new(FinancialBreaker::default()),
                Box::new(PrivacyBreaker::default()),
            ],
            AggregateMode::All,
        );

        let only_financial_denies = ActionContext {
            transfer_amount_usd: Some(2_000.0),
            pii_field_count: Some(1),
            ..Default::default()
        };
        assert_eq!(agg.evaluate(&only_financial_denies), PolicyResult::Pass);

        let both_deny = ActionContext {
            transfer_amount_usd: Some(2_000.0),
            pii_field_count: Some(99),
            ..Default::default()
        };
        assert!(matches!(
            agg.evaluate(&both_deny),
            PolicyResult::Deny { .. }
        ));
    }

    // ── ComplianceBreaker ────────────────────────────────────────────────────

    #[test]
    fn compliance_blocked_jurisdiction() {
        let b = ComplianceBreaker {
            allowed_jurisdictions: vec!["US".into(), "DE".into()],
            max_retention_days: 365,
        };
        let r = b.evaluate(&ActionContext {
            destination_jurisdiction: Some("CN".into()),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "JURISDICTION_NOT_ALLOWED",
                ..
            }
        ));
    }

    #[test]
    fn compliance_allowed_jurisdiction() {
        let b = ComplianceBreaker {
            allowed_jurisdictions: vec!["US".into(), "DE".into()],
            max_retention_days: 365,
        };
        assert_eq!(
            b.evaluate(&ActionContext {
                destination_jurisdiction: Some("US".into()),
                ..Default::default()
            }),
            PolicyResult::Pass
        );
    }

    #[test]
    fn compliance_schema_pii_violation() {
        let r = ComplianceBreaker::default().evaluate(&ActionContext {
            payload_contains_pii: Some(true),
            registered_schema_fields: Some(vec!["name".into(), "email".into()]),
            payload_fields: Some(vec!["name".into(), "email".into(), "ssn".into()]),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "SCHEMA_PII_VIOLATION",
                ..
            }
        ));
    }

    #[test]
    fn compliance_gdpr_deletion_block() {
        let r = ComplianceBreaker::default().evaluate(&ActionContext {
            gdpr_deletion_requested: Some(true),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "GDPR_DELETION_BLOCK",
                ..
            }
        ));
    }

    #[test]
    fn compliance_retention_violation() {
        let b = ComplianceBreaker {
            allowed_jurisdictions: vec![],
            max_retention_days: 90,
        };
        let r = b.evaluate(&ActionContext {
            retention_days_requested: Some(91),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "RETENTION_VIOLATION",
                ..
            }
        ));
    }

    // ── ResourceBreaker ──────────────────────────────────────────────────────

    #[test]
    fn resource_token_rate_exceeded() {
        let r = ResourceBreaker::default().evaluate(&ActionContext {
            tokens_per_minute: Some(150_000.0),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "TOKEN_RATE_EXCEEDED",
                ..
            }
        ));
    }

    #[test]
    fn resource_compute_exceeded() {
        let r = ResourceBreaker::default().evaluate(&ActionContext {
            compute_seconds_per_hour: Some(4_000.0),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "COMPUTE_EXCEEDED",
                ..
            }
        ));
    }

    #[test]
    fn resource_api_rate_limit() {
        let r = ResourceBreaker::default().evaluate(&ActionContext {
            api_rate_limit_pct: Some(95.0),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "API_RATE_LIMIT",
                ..
            }
        ));
    }

    #[test]
    fn resource_context_supplied_limit_overrides_default() {
        // Agent declares a custom 1000 TPM limit; at 1500 it should deny.
        let r = ResourceBreaker::default().evaluate(&ActionContext {
            tokens_per_minute: Some(1_500.0),
            max_tokens_per_minute: Some(1_000.0),
            ..Default::default()
        });
        assert!(matches!(
            r,
            PolicyResult::Deny {
                policy: "TOKEN_RATE_EXCEEDED",
                ..
            }
        ));
    }
}
