use crate::{ActionContext, CircuitBreaker, PolicyResult};

/// Default maximum egress: 50 MB per minute per agent.
const DEFAULT_MAX_EGRESS_BYTES_PER_MINUTE: u64 = 50 * 1024 * 1024;

/// Circuit breaker that monitors outbound data volume per agent.
///
/// When an agent's cumulative egress in the current window exceeds the
/// configured threshold, the request is denied to prevent data exfiltration.
pub struct EgressBreaker {
    pub max_bytes_per_minute: u64,
}

impl Default for EgressBreaker {
    fn default() -> Self {
        Self {
            max_bytes_per_minute: DEFAULT_MAX_EGRESS_BYTES_PER_MINUTE,
        }
    }
}

impl CircuitBreaker for EgressBreaker {
    fn domain(&self) -> &'static str {
        "egress"
    }

    fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        let limit = ctx
            .max_egress_bytes_per_minute
            .unwrap_or(self.max_bytes_per_minute);

        if let Some(bytes) = ctx.egress_bytes
            && bytes > limit
        {
            return PolicyResult::Deny {
                reason: format!(
                    "Egress volume {} bytes exceeds limit {} bytes/min",
                    bytes, limit
                ),
                policy: "EGRESS_VOLUME_EXCEEDED",
            };
        }
        PolicyResult::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_under_limit_passes() {
        let breaker = EgressBreaker::default();
        let ctx = ActionContext {
            egress_bytes: Some(1_000),
            ..Default::default()
        };
        assert_eq!(breaker.evaluate(&ctx), PolicyResult::Pass);
    }

    #[test]
    fn egress_over_limit_denied() {
        let breaker = EgressBreaker {
            max_bytes_per_minute: 1_000,
        };
        let ctx = ActionContext {
            egress_bytes: Some(2_000),
            ..Default::default()
        };
        assert!(matches!(
            breaker.evaluate(&ctx),
            PolicyResult::Deny {
                policy: "EGRESS_VOLUME_EXCEEDED",
                ..
            }
        ));
    }

    #[test]
    fn no_egress_data_passes() {
        let breaker = EgressBreaker::default();
        let ctx = ActionContext::default();
        assert_eq!(breaker.evaluate(&ctx), PolicyResult::Pass);
    }

    #[test]
    fn context_override_limit() {
        let breaker = EgressBreaker::default();
        let ctx = ActionContext {
            egress_bytes: Some(500),
            max_egress_bytes_per_minute: Some(400),
            ..Default::default()
        };
        assert!(matches!(
            breaker.evaluate(&ctx),
            PolicyResult::Deny {
                policy: "EGRESS_VOLUME_EXCEEDED",
                ..
            }
        ));
    }
}
