pub const MAX_TRANSFER_USD: f64 = 1_000.0; //max transfer
pub const MAX_ACTIONS_PER_MINUTE: usize = 10; //max action
pub const CIRCUIT_BREAK_SECS: u64 = 300; //hold time

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

/// Stateless policy evaluator.
#[derive(Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {//pass or deny with limits
    pub fn check_transfer(&self, amount: f64) -> PolicyResult {
        if amount > MAX_TRANSFER_USD {
            PolicyResult::Deny {
                reason: format!(
                    "Transfer ${:.2} exceeds the ${:.2} per-transaction limit",
                    amount, MAX_TRANSFER_USD
                ),
                policy: "MAX_TRANSFER_USD",
            }
        } else {
            PolicyResult::Pass
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_under_limit() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.check_transfer(999.99), PolicyResult::Pass);
    }

    #[test]
    fn allow_at_limit() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.check_transfer(1_000.0), PolicyResult::Pass);
    }

    #[test]
    fn deny_over_limit() {
        let engine = PolicyEngine::default();
        assert!(matches!(
            engine.check_transfer(1_000.01),
            PolicyResult::Deny { policy: "MAX_TRANSFER_USD", .. }
        ));
    }
}
