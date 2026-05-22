use crate::{ActionContext, CircuitBreaker, PolicyResult};

pub struct PrivacyBreaker {
    pub max_pii_fields: usize,
    /// Ratio of requested to task-necessary columns that triggers denial.
    pub over_collection_ratio: f64,
}

impl Default for PrivacyBreaker {
    fn default() -> Self {
        Self {
            max_pii_fields: 10,
            over_collection_ratio: 2.0,
        }
    }
}

impl CircuitBreaker for PrivacyBreaker {
    fn domain(&self) -> &'static str {
        "privacy"
    }

    fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        if let Some(pii) = ctx.pii_field_count
            && pii > self.max_pii_fields
        {
            return PolicyResult::Deny {
                reason: format!("High PII density: {pii} fields detected"),
                policy: "PII_CONCENTRATION",
            };
        }
        if let (Some(req), Some(needed)) = (ctx.requested_columns, ctx.task_necessary_columns) {
            let needed_f = needed.max(1) as f64;
            if req as f64 > needed_f * self.over_collection_ratio {
                return PolicyResult::Deny {
                    reason: "Over-collection violates data minimisation principle".to_string(),
                    policy: "DATA_MINIMISATION",
                };
            }
        }
        if ctx.cross_border_restricted == Some(true) {
            return PolicyResult::Deny {
                reason: "Cross-border transfer requires GDPR Article 44 mechanism".to_string(),
                policy: "CROSS_BORDER_TRANSFER",
            };
        }
        PolicyResult::Pass
    }
}
