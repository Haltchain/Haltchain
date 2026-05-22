use crate::{ActionContext, CircuitBreaker, PolicyResult};

pub struct SecurityBreaker;

impl CircuitBreaker for SecurityBreaker {
    fn domain(&self) -> &'static str {
        "security"
    }

    fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        if let (Some(declared), Some(requested)) = (&ctx.declared_scopes, &ctx.requested_scopes) {
            let scope_creep: Vec<_> = requested.iter().filter(|s| !declared.contains(s)).collect();
            if !scope_creep.is_empty() {
                return PolicyResult::Deny {
                    reason: format!("Undeclared OAuth scopes requested: {:?}", scope_creep),
                    policy: "SCOPE_CREEP",
                };
            }
        }
        if ctx.accessing_undeclared_service == Some(true) {
            return PolicyResult::Deny {
                reason: "Lateral access to service outside declared dependency graph".to_string(),
                policy: "LATERAL_MOVEMENT",
            };
        }
        PolicyResult::Pass
    }
}
