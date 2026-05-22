use crate::{ActionContext, CircuitBreaker, PolicyResult};

pub struct ResourceBreaker {
    pub max_tokens_per_minute: f64,
    pub max_compute_seconds_per_hour: f64,
    /// API rate limit threshold — deny when usage exceeds this % of limit.
    pub api_rate_limit_warn_pct: f64,
}

impl Default for ResourceBreaker {
    fn default() -> Self {
        Self {
            max_tokens_per_minute: 100_000.0,
            max_compute_seconds_per_hour: 3_600.0,
            api_rate_limit_warn_pct: 90.0,
        }
    }
}

impl CircuitBreaker for ResourceBreaker {
    fn domain(&self) -> &'static str {
        "resource"
    }

    fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        // Use context-supplied limits if present, fall back to struct defaults.
        let max_tpm = ctx
            .max_tokens_per_minute
            .unwrap_or(self.max_tokens_per_minute);
        if let Some(tpm) = ctx.tokens_per_minute
            && tpm > max_tpm
        {
            return PolicyResult::Deny {
                reason: format!("Token rate {tpm:.0} TPM exceeds limit {max_tpm:.0}"),
                policy: "TOKEN_RATE_EXCEEDED",
            };
        }
        let max_cs = ctx
            .max_compute_seconds_per_hour
            .unwrap_or(self.max_compute_seconds_per_hour);
        if let Some(cs) = ctx.compute_seconds_per_hour
            && cs > max_cs
        {
            return PolicyResult::Deny {
                reason: format!("Compute {cs:.1}s/hr exceeds limit {max_cs:.1}s/hr"),
                policy: "COMPUTE_EXCEEDED",
            };
        }
        if let Some(pct) = ctx.api_rate_limit_pct
            && pct > self.api_rate_limit_warn_pct
        {
            return PolicyResult::Deny {
                reason: format!("API rate limit at {pct:.1}% — throttling to protect quota"),
                policy: "API_RATE_LIMIT",
            };
        }
        PolicyResult::Pass
    }
}
