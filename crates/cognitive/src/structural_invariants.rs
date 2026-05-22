//! Structural invariants — hardcoded safety rules that are **not** ML-derived.
//!
//! Inspired by IronCurtain's approach: "The agent is untrusted.  Security does
//! not depend on the model being good."
//!
//! These invariants enforce a default-deny posture for dangerous operations.
//! Evaluation order is security-critical and must not be reordered:
//!   1. Protected resource deny  (absolute block list)
//!   2. Sandbox containment      (no escaping execution boundary)
//!   3. Replication gate          (no self-spawning without approval)
//!   4. Unknown tool denial       (default-deny for unrecognised actions)

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Result of structural invariant evaluation — checked **before** any ML scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuralVerdict {
    /// Action is structurally safe; proceed to ML-based cognitive analysis.
    Allow,
    /// Action violates a hardcoded invariant — blocked unconditionally.
    Deny {
        invariant: InvariantClass,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InvariantClass {
    ProtectedResource,
    SandboxContainment,
    ReplicationGate,
    UnknownToolDenial,
}

/// Lightweight description of an agent action that can be evaluated
/// structurally before we do any expensive ML work.
#[derive(Debug, Clone)]
pub struct ActionDescriptor {
    /// Tool or syscall name the agent wants to invoke.
    pub tool_name: String,
    /// Paths the action would read from.
    pub read_paths: Vec<String>,
    /// Paths the action would write to.
    pub write_paths: Vec<String>,
    /// Network targets (host:port or URL) the action would contact.
    pub network_targets: Vec<String>,
    /// Whether this action spawns a sub-agent or child process.
    pub spawns_subprocess: bool,
}

/// Whitelist of tools recognised by the system.
/// Any tool not on this list is denied by default.
const KNOWN_TOOLS: &[&str] = &[
    "read_file",
    "write_file",
    "list_directory",
    "http_get",
    "http_post",
    "query_database",
    "insert_record",
    "update_record",
    "send_email",
    "send_notification",
    "calculate",
    "summarize",
    "translate",
    "search",
    "embed_text",
];

/// Paths that must never be written to by any agent action.
const PROTECTED_WRITE_PATHS: &[&str] = &[
    "/etc/",
    "/var/spool/cron",
    "/usr/lib/systemd",
    "/proc/",
    "/sys/",
    "~/.ssh/",
    "~/.config/systemd",
    ".git/hooks",
    "Dockerfile",
    "docker-compose",
    "Cargo.toml",
    ".env",
];

/// Paths that must never be read by an agent action.
const PROTECTED_READ_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "~/.ssh/id_",
    "~/.aws/credentials",
    "~/.config/gcloud",
    ".env",
];

/// Network targets that are blocked (metadata services, internal nets).
const BLOCKED_NETWORK_TARGETS: &[&str] = &[
    "169.254.169.254", // AWS/GCP metadata
    "metadata.google",
    "100.100.100.200", // Alibaba metadata
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
];

// ─────────────────────────────────────────────────────────────────────────────
// Evaluation — order is security-critical
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluate an action against all structural invariants.
///
/// Returns `Deny` on the **first** violated invariant (fail-fast).
/// Evaluation order must not be reordered.
pub fn evaluate(action: &ActionDescriptor) -> StructuralVerdict {
    // 1. Protected resource deny
    if let Some(v) = check_protected_resources(action) {
        return v;
    }
    // 2. Sandbox containment
    if let Some(v) = check_sandbox_containment(action) {
        return v;
    }
    // 3. Replication gate
    if let Some(v) = check_replication_gate(action) {
        return v;
    }
    // 4. Unknown tool denial (default-deny)
    if let Some(v) = check_unknown_tool(action) {
        return v;
    }
    StructuralVerdict::Allow
}

fn check_protected_resources(action: &ActionDescriptor) -> Option<StructuralVerdict> {
    for path in &action.write_paths {
        let normalised = path.to_lowercase();
        for &protected in PROTECTED_WRITE_PATHS {
            if normalised.contains(&protected.to_lowercase()) {
                return Some(StructuralVerdict::Deny {
                    invariant: InvariantClass::ProtectedResource,
                    reason: format!("Write to protected path denied: {}", path),
                });
            }
        }
    }
    for path in &action.read_paths {
        let normalised = path.to_lowercase();
        for &protected in PROTECTED_READ_PATHS {
            if normalised.contains(&protected.to_lowercase()) {
                return Some(StructuralVerdict::Deny {
                    invariant: InvariantClass::ProtectedResource,
                    reason: format!("Read from protected path denied: {}", path),
                });
            }
        }
    }
    None
}

fn check_sandbox_containment(action: &ActionDescriptor) -> Option<StructuralVerdict> {
    for target in &action.network_targets {
        let lower = target.to_lowercase();
        for &blocked in BLOCKED_NETWORK_TARGETS {
            if lower.contains(blocked) {
                return Some(StructuralVerdict::Deny {
                    invariant: InvariantClass::SandboxContainment,
                    reason: format!("Network access to blocked target denied: {}", target),
                });
            }
        }
    }
    None
}

fn check_replication_gate(action: &ActionDescriptor) -> Option<StructuralVerdict> {
    if action.spawns_subprocess {
        return Some(StructuralVerdict::Deny {
            invariant: InvariantClass::ReplicationGate,
            reason: "Sub-process / sub-agent spawn requires explicit human approval".into(),
        });
    }
    None
}

fn check_unknown_tool(action: &ActionDescriptor) -> Option<StructuralVerdict> {
    let lower = action.tool_name.to_lowercase();
    let known = KNOWN_TOOLS.iter().any(|t| lower == *t);
    if !known {
        return Some(StructuralVerdict::Deny {
            invariant: InvariantClass::UnknownToolDenial,
            reason: format!(
                "Unknown tool '{}' denied by default-deny policy",
                action.tool_name
            ),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_action(tool: &str) -> ActionDescriptor {
        ActionDescriptor {
            tool_name: tool.into(),
            read_paths: vec![],
            write_paths: vec![],
            network_targets: vec![],
            spawns_subprocess: false,
        }
    }

    #[test]
    fn known_tool_allowed() {
        let action = allow_action("read_file");
        assert_eq!(evaluate(&action), StructuralVerdict::Allow);
    }

    #[test]
    fn unknown_tool_denied() {
        let action = allow_action("exec_arbitrary_code");
        assert!(matches!(
            evaluate(&action),
            StructuralVerdict::Deny {
                invariant: InvariantClass::UnknownToolDenial,
                ..
            }
        ));
    }

    #[test]
    fn protected_write_denied() {
        let mut action = allow_action("write_file");
        action.write_paths.push("/etc/crontab".into());
        assert!(matches!(
            evaluate(&action),
            StructuralVerdict::Deny {
                invariant: InvariantClass::ProtectedResource,
                ..
            }
        ));
    }

    #[test]
    fn protected_read_denied() {
        let mut action = allow_action("read_file");
        action.read_paths.push("/etc/shadow".into());
        assert!(matches!(
            evaluate(&action),
            StructuralVerdict::Deny {
                invariant: InvariantClass::ProtectedResource,
                ..
            }
        ));
    }

    #[test]
    fn metadata_service_blocked() {
        let mut action = allow_action("http_get");
        action
            .network_targets
            .push("http://169.254.169.254/latest/meta-data/".into());
        assert!(matches!(
            evaluate(&action),
            StructuralVerdict::Deny {
                invariant: InvariantClass::SandboxContainment,
                ..
            }
        ));
    }

    #[test]
    fn subprocess_spawn_denied() {
        let mut action = allow_action("calculate");
        action.spawns_subprocess = true;
        assert!(matches!(
            evaluate(&action),
            StructuralVerdict::Deny {
                invariant: InvariantClass::ReplicationGate,
                ..
            }
        ));
    }

    #[test]
    fn evaluation_order_protected_before_unknown() {
        // Even if tool is unknown, protected resource check fires first
        let action = ActionDescriptor {
            tool_name: "evil_tool".into(),
            read_paths: vec![],
            write_paths: vec!["/etc/passwd".into()],
            network_targets: vec![],
            spawns_subprocess: false,
        };
        assert!(matches!(
            evaluate(&action),
            StructuralVerdict::Deny {
                invariant: InvariantClass::ProtectedResource,
                ..
            }
        ));
    }

    #[test]
    fn safe_action_passes_all_gates() {
        let action = ActionDescriptor {
            tool_name: "query_database".into(),
            read_paths: vec!["/app/data/users.json".into()],
            write_paths: vec!["/tmp/output.csv".into()],
            network_targets: vec!["https://api.example.com".into()],
            spawns_subprocess: false,
        };
        assert_eq!(evaluate(&action), StructuralVerdict::Allow);
    }
}
