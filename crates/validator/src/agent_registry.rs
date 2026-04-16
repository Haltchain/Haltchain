use dashmap::DashSet;
use std::sync::OnceLock;
use tracing::warn;

/// In-memory registry of known agent IDs.
///
/// Agents can be pre-registered via the `HALTCHAIN_REGISTERED_AGENTS` env var
/// (comma-separated) or dynamically via `register()`.
///
/// When enforcement is enabled (`HALTCHAIN_ENFORCE_REGISTRY=true`), any
/// `agent_id` that appears in `/validate` but is not registered will be denied.
pub struct AgentRegistry {
    agents: DashSet<String>,
    enforce: bool,
}

static INSTANCE: OnceLock<AgentRegistry> = OnceLock::new();

impl AgentRegistry {
    fn from_env() -> Self {
        let agents = DashSet::new();
        if let Ok(raw) = std::env::var("HALTCHAIN_REGISTERED_AGENTS") {
            for id in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                agents.insert(id.to_string());
            }
        }
        let enforce = std::env::var("HALTCHAIN_ENFORCE_REGISTRY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        Self { agents, enforce }
    }

    /// Global singleton, initialised from env on first access.
    pub fn global() -> &'static Self {
        INSTANCE.get_or_init(Self::from_env)
    }

    /// Dynamically register an agent (e.g. via an admin endpoint).
    pub fn register(&self, agent_id: &str) {
        self.agents.insert(agent_id.to_string());
    }

    /// Remove an agent from the registry.
    pub fn unregister(&self, agent_id: &str) {
        self.agents.remove(agent_id);
    }

    /// Returns true if the agent is known (registered).
    pub fn is_registered(&self, agent_id: &str) -> bool {
        self.agents.contains(agent_id)
    }

    /// Check whether the agent should be allowed to proceed.
    ///
    /// Returns `Ok(())` if the registry is not enforced or the agent is registered.
    /// Returns `Err(reason)` if the agent is unknown and enforcement is on.
    pub fn check(&self, agent_id: &str) -> Result<(), String> {
        if !self.enforce {
            return Ok(());
        }
        if self.agents.contains(agent_id) {
            return Ok(());
        }
        warn!(agent_id = %agent_id, "unregistered agent attempted validation — denied");
        Err(format!(
            "agent '{agent_id}' is not in the registered agent inventory"
        ))
    }

    /// Number of registered agents.
    pub fn count(&self) -> usize {
        self.agents.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_registry(enforce: bool) -> AgentRegistry {
        AgentRegistry {
            agents: DashSet::new(),
            enforce,
        }
    }

    #[test]
    fn unregistered_agent_denied_when_enforced() {
        let reg = fresh_registry(true);
        reg.register("agent-a");
        assert!(reg.check("agent-a").is_ok());
        assert!(reg.check("agent-b").is_err());
    }

    #[test]
    fn unregistered_agent_allowed_when_not_enforced() {
        let reg = fresh_registry(false);
        assert!(reg.check("any-agent").is_ok());
    }

    #[test]
    fn register_and_unregister() {
        let reg = fresh_registry(true);
        reg.register("agent-x");
        assert!(reg.is_registered("agent-x"));
        reg.unregister("agent-x");
        assert!(!reg.is_registered("agent-x"));
        assert!(reg.check("agent-x").is_err());
    }
}
