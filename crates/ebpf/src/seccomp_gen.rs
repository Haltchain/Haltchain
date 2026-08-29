//! Phase 2: Dynamic Seccomp-BPF profile generation.
//!
//! Generates seccomp profiles from observed syscall patterns (captured via eBPF kprobes).
//! Profiles are stored in PostgreSQL `seccomp_profiles` table (migration 015).
//!
//! Current state: ONNX worker uses static profile from deploy/seccomp-profile.json.
//! This module extends that with per-workload dynamic profile generation.

use serde::{Deserialize, Serialize};

/// A generated seccomp profile in libseccomp JSON format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfile {
    pub workload: String,
    pub version: u32,
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<SeccompSyscallRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompSyscallRule {
    pub names: Vec<String>,
    pub action: String,
}

impl SeccompProfile {
    /// Build a minimal allow-list profile from a set of observed syscalls.
    /// Everything not in the allow list gets `SCMP_ACT_KILL_PROCESS`.
    pub fn from_observed(workload: &str, observed_syscalls: &[String]) -> Self {
        let mut allowed = observed_syscalls.to_vec();
        // Always allow basic runtime necessities
        for s in ["exit", "exit_group", "sigreturn", "rt_sigreturn"] {
            if !allowed.contains(&s.to_string()) {
                allowed.push(s.to_string());
            }
        }
        Self {
            workload: workload.to_string(),
            version: 1,
            default_action: "SCMP_ACT_KILL_PROCESS".to_string(),
            architectures: vec![
                "SCMP_ARCH_X86_64".to_string(),
                "SCMP_ARCH_AARCH64".to_string(),
            ],
            syscalls: vec![SeccompSyscallRule {
                names: allowed,
                action: "SCMP_ACT_ALLOW".to_string(),
            }],
        }
    }

    /// Returns the profile as a JSON value for storage in `seccomp_profiles.profile`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// The static ONNX worker profile baseline (matches deploy/seccomp-profile.json).
    pub fn onnx_worker_baseline() -> Self {
        Self::from_observed(
            "onnx_worker",
            &[
                "read".into(),
                "write".into(),
                "open".into(),
                "openat".into(),
                "close".into(),
                "fstat".into(),
                "mmap".into(),
                "mprotect".into(),
                "munmap".into(),
                "brk".into(),
                "pread64".into(),
                "access".into(),
                "mmap2".into(),
                "lseek".into(),
                "futex".into(),
                "clone".into(),
                "wait4".into(),
                "prctl".into(),
                "arch_prctl".into(),
                "set_tid_address".into(),
                "set_robust_list".into(),
                "prlimit64".into(),
                "getrandom".into(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onnx_baseline_deny_network() {
        let profile = SeccompProfile::onnx_worker_baseline();
        assert_eq!(profile.default_action, "SCMP_ACT_KILL_PROCESS");
        let allowed: Vec<_> = profile.syscalls[0]
            .names
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert!(
            !allowed.contains(&"connect"),
            "connect syscall should NOT be in ONNX baseline"
        );
        assert!(allowed.contains(&"read"), "read must be in baseline");
    }

    #[test]
    fn from_observed_always_has_exit() {
        let profile = SeccompProfile::from_observed("test", &["read".into(), "write".into()]);
        let allowed: Vec<_> = profile.syscalls[0]
            .names
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert!(allowed.contains(&"exit_group"));
    }
}
