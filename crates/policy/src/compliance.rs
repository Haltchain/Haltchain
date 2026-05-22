use crate::{ActionContext, CircuitBreaker, PolicyResult};

pub struct ComplianceBreaker {
    /// Jurisdictions where data may be sent. Empty = all allowed.
    pub allowed_jurisdictions: Vec<String>,
    /// Maximum data retention the agent may request (days).
    pub max_retention_days: u32,
}

impl Default for ComplianceBreaker {
    fn default() -> Self {
        Self {
            allowed_jurisdictions: Vec::new(),
            max_retention_days: 2555,
        } // 7 years
    }
}

impl CircuitBreaker for ComplianceBreaker {
    fn domain(&self) -> &'static str {
        "compliance"
    }

    fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        if let Some(ref dest) = ctx.destination_jurisdiction
            && !self.allowed_jurisdictions.is_empty()
            && !self.allowed_jurisdictions.iter().any(|j| j == dest)
        {
            return PolicyResult::Deny {
                reason: format!("Destination jurisdiction '{dest}' is not in the allow-list"),
                policy: "JURISDICTION_NOT_ALLOWED",
            };
        }
        // Schema violation with PII in payload
        if ctx.payload_contains_pii == Some(true)
            && let (Some(registered), Some(payload)) =
                (&ctx.registered_schema_fields, &ctx.payload_fields)
        {
            let extras: Vec<_> = payload.iter().filter(|f| !registered.contains(f)).collect();
            if !extras.is_empty() {
                return PolicyResult::Deny {
                    reason: format!("Schema violation with PII: undeclared fields {:?}", extras),
                    policy: "SCHEMA_PII_VIOLATION",
                };
            }
        }
        if ctx.gdpr_deletion_requested == Some(true) {
            return PolicyResult::Deny {
                reason: "Agent attempted action on data subject to a GDPR deletion request"
                    .to_string(),
                policy: "GDPR_DELETION_BLOCK",
            };
        }
        if let Some(days) = ctx.retention_days_requested
            && days > self.max_retention_days
        {
            return PolicyResult::Deny {
                reason: format!(
                    "Retention of {days} days exceeds policy maximum of {}",
                    self.max_retention_days
                ),
                policy: "RETENTION_VIOLATION",
            };
        }
        PolicyResult::Pass
    }
}
