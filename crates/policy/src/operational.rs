use crate::{ActionContext, CircuitBreaker, PolicyResult};

pub struct OperationalBreaker {
    pub max_cpu_percent: f64,
    pub max_memory_percent: f64,
    pub max_cascade_depth: usize,
}

impl Default for OperationalBreaker {
    fn default() -> Self {
        Self {
            max_cpu_percent: 90.0,
            max_memory_percent: 85.0,
            max_cascade_depth: 5,
        }
    }
}

impl CircuitBreaker for OperationalBreaker {
    fn domain(&self) -> &'static str {
        "operational"
    }

    fn evaluate(&self, ctx: &ActionContext) -> PolicyResult {
        if let Some(cpu) = ctx.cpu_percent
            && cpu > self.max_cpu_percent
        {
            return PolicyResult::Deny {
                reason: format!("CPU at {cpu:.1}% — resource exhaustion risk"),
                policy: "CPU_EXHAUSTION",
            };
        }
        if let Some(mem) = ctx.memory_percent
            && mem > self.max_memory_percent
        {
            return PolicyResult::Deny {
                reason: format!("Memory at {mem:.1}% — resource exhaustion risk"),
                policy: "MEMORY_EXHAUSTION",
            };
        }
        if let Some(depth) = ctx.dependency_cascade_depth
            && depth > self.max_cascade_depth
        {
            return PolicyResult::Deny {
                reason: format!("Dependency cascade depth {depth} exceeds limit"),
                policy: "DEPENDENCY_CASCADE",
            };
        }
        PolicyResult::Pass
    }
}
