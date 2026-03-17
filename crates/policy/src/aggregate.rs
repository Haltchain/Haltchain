use crate::{
    ActionContext, CircuitBreaker, ComplianceBreaker, FinancialBreaker, OperationalBreaker,
    PolicyResult, PrivacyBreaker, ResourceBreaker, SecurityBreaker,
};

/// Logical composition mode for sub-breakers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateMode {
    /// AND over breaker trips: deny only when every sub-breaker denies.
    All,
    /// OR over breaker trips: deny when any sub-breaker denies.
    Any,
}

/// Runs registered breakers with configurable composition semantics.
pub struct AggregateBreaker {
    breakers: Vec<Box<dyn CircuitBreaker>>,
    mode: AggregateMode,
}

impl AggregateBreaker {
    pub fn new(breakers: Vec<Box<dyn CircuitBreaker>>) -> Self {
        Self {
            breakers,
            mode: AggregateMode::Any,
        }
    }

    pub fn with_mode(breakers: Vec<Box<dyn CircuitBreaker>>, mode: AggregateMode) -> Self {
        Self { breakers, mode }
    }

    pub fn mode(&self) -> AggregateMode {
        self.mode
    }

    /// Convenience constructor — returns the default 6-domain aggregate in AND mode.
    pub fn default_all() -> Self {
        Self::with_mode(
            vec![
                Box::new(FinancialBreaker::default()),
                Box::new(PrivacyBreaker::default()),
                Box::new(SecurityBreaker),
                Box::new(OperationalBreaker::default()),
                Box::new(ComplianceBreaker::default()),
                Box::new(ResourceBreaker::default()),
            ],
            AggregateMode::All,
        )
    }

    /// Same defaults as [`default_all`], but configured for OR mode.
    pub fn default_any() -> Self {
        Self::with_mode(
            vec![
                Box::new(FinancialBreaker::default()),
                Box::new(PrivacyBreaker::default()),
                Box::new(SecurityBreaker),
                Box::new(OperationalBreaker::default()),
                Box::new(ComplianceBreaker::default()),
                Box::new(ResourceBreaker::default()),
            ],
            AggregateMode::Any,
        )
    }

    pub fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        match self.mode {
            AggregateMode::Any => {
                for b in &self.breakers {
                    let r = b.evaluate(ctx);
                    if r != PolicyResult::Pass {
                        return r;
                    }
                }
                PolicyResult::Pass
            }
            AggregateMode::All => {
                let mut first_deny: Option<PolicyResult> = None;
                for b in &self.breakers {
                    let r = b.evaluate(ctx);
                    if r == PolicyResult::Pass {
                        return PolicyResult::Pass;
                    }
                    if first_deny.is_none() {
                        first_deny = Some(r);
                    }
                }
                first_deny.unwrap_or(PolicyResult::Pass)
            }
        }
    }
}

/// Stateless policy evaluator — kept for backwards compatibility.
/// New code should prefer [`AggregateBreaker`] with an [`ActionContext`].
#[derive(Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn check_transfer(&self, amount: f64) -> PolicyResult {
        FinancialBreaker::default().evaluate(&ActionContext {
            transfer_amount_usd: Some(amount),
            ..Default::default()
        })
    }
}
