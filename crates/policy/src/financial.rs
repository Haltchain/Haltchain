use crate::{
    ActionContext, CircuitBreaker, MAX_ACTIONS_PER_MINUTE, MAX_TRANSFER_USD, PolicyResult,
};

pub struct FinancialBreaker {
    pub max_transfer_usd: f64,
    pub max_actions_per_minute: usize,
}

impl Default for FinancialBreaker {
    fn default() -> Self {
        Self {
            max_transfer_usd: MAX_TRANSFER_USD,
            max_actions_per_minute: MAX_ACTIONS_PER_MINUTE,
        }
    }
}

impl CircuitBreaker for FinancialBreaker {
    fn domain(&self) -> &'static str {
        "financial"
    }

    fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        if let Some(amt) = ctx.transfer_amount_usd
            && amt > self.max_transfer_usd
        {
            return PolicyResult::Deny {
                reason: format!(
                    "Transfer ${:.2} exceeds ${:.2} per-transaction limit",
                    amt, self.max_transfer_usd
                ),
                policy: "MAX_TRANSFER_USD",
            };
        }
        if let Some(apm) = ctx.actions_per_minute
            && apm > self.max_actions_per_minute
        {
            return PolicyResult::Deny {
                reason: format!(
                    "{apm} actions/min exceeds limit of {}",
                    self.max_actions_per_minute
                ),
                policy: "MAX_ACTIONS_PER_MINUTE",
            };
        }
        PolicyResult::Pass
    }
}
