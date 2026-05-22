//! eBPF probe lifecycle management.
//!
//! When the `kernel` feature is enabled, this module uses aya to load and attach
//! kprobe programs. Without the feature, all methods are no-ops that log a warning.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProbeError {
    #[error("kernel feature not enabled; rebuild with --features kernel")]
    KernelFeatureDisabled,
    #[cfg(all(feature = "kernel", target_os = "linux"))]
    #[error("aya error: {0}")]
    Aya(#[from] aya::BpfError),
    #[cfg(all(feature = "kernel", not(target_os = "linux")))]
    #[error("kernel feature is only supported on Linux targets")]
    UnsupportedPlatform,
    #[error("probe load error: {0}")]
    Load(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    pub target_syscalls: Vec<String>,
    pub ring_buf_capacity: usize,
    pub enforce_deny: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            target_syscalls: vec![
                "execve".into(),
                "connect".into(),
                "openat".into(),
            ],
            ring_buf_capacity: 65536,
            enforce_deny: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeEvent {
    pub syscall: String,
    pub pid: u32,
    pub comm: String,
    pub decision: String, // ALLOW | DENY
    pub ts_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttachedTarget {
    syscall: String,
    attached: bool,
    symbol: Option<String>,
    error: Option<String>,
}

pub struct ProbeManager {
    config: ProbeConfig,
    running: bool,
    attached_targets: Vec<AttachedTarget>,
    object_path: Option<String>,
    event_queue: Mutex<VecDeque<ProbeEvent>>,
    #[cfg(all(feature = "kernel", target_os = "linux"))]
    bpf: Option<aya::Ebpf>,
}

impl ProbeManager {
    pub fn new(config: ProbeConfig) -> Self {
        Self {
            config,
            running: false,
            attached_targets: Vec::new(),
            object_path: None,
            event_queue: Mutex::new(VecDeque::new()),
            #[cfg(all(feature = "kernel", target_os = "linux"))]
            bpf: None,
        }
    }

    fn now_ts_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)
    }

    fn push_event<S1: Into<String>, S2: Into<String>>(&self, syscall: S1, decision: S2) {
        let event = ProbeEvent {
            syscall: syscall.into(),
            pid: 0,
            comm: "probe_manager".to_string(),
            decision: decision.into(),
            ts_ns: Self::now_ts_ns(),
        };
        if let Ok(mut queue) = self.event_queue.lock() {
            queue.push_back(event);
        }
    }

    #[cfg(any(all(feature = "kernel", target_os = "linux"), test))]
    fn symbol_candidates(syscall: &str) -> [String; 3] {
        [
            format!("__x64_sys_{syscall}"),
            format!("__arm64_sys_{syscall}"),
            format!("sys_{syscall}"),
        ]
    }

    pub async fn start(&mut self) -> Result<(), ProbeError> {
        #[cfg(all(feature = "kernel", target_os = "linux"))]
        {
            if self.running {
                self.push_event("probe_manager", "START_SKIPPED_ALREADY_RUNNING");
                return Ok(());
            }

            const DEFAULT_OBJECT_PATH: &str = "/opt/haltchain/ebpf/haltchain.o";
            let object_path = std::env::var("HALTCHAIN_EBPF_OBJECT")
                .unwrap_or_else(|_| DEFAULT_OBJECT_PATH.to_string());
            self.object_path = Some(object_path.clone());
            self.attached_targets.clear();

            tracing::info!(
                object_path = %object_path,
                syscalls = ?self.config.target_syscalls,
                "eBPF probe manager starting (kernel feature enabled)"
            );

            let mut bpf = match aya::Ebpf::load_file(&object_path) {
                Ok(bpf) => bpf,
                Err(err) => {
                    self.push_event("probe_manager", format!("START_FAIL_LOAD_OBJECT:{err}"));
                    return Err(ProbeError::Aya(err));
                }
            };

            let target_syscalls = self.config.target_syscalls.clone();
            for syscall in target_syscalls {
                let mut target = AttachedTarget {
                    syscall: syscall.clone(),
                    attached: false,
                    symbol: None,
                    error: None,
                };

                let program = match bpf.program_mut(&syscall) {
                    Some(program) => program,
                    None => {
                        let msg = format!("missing eBPF program for syscall '{syscall}'");
                        self.push_event(&syscall, format!("ATTACH_FAIL:{msg}"));
                        target.error = Some(msg);
                        self.attached_targets.push(target);
                        continue;
                    }
                };

                let kprobe: &mut aya::programs::KProbe = match program.try_into() {
                    Ok(kprobe) => kprobe,
                    Err(err) => {
                        let msg = format!("program '{syscall}' is not a kprobe: {err}");
                        self.push_event(&syscall, format!("ATTACH_FAIL:{msg}"));
                        target.error = Some(msg);
                        self.attached_targets.push(target);
                        continue;
                    }
                };

                if let Err(err) = kprobe.load() {
                    let msg = format!("failed to load kprobe program '{syscall}': {err}");
                    self.push_event(&syscall, format!("ATTACH_FAIL:{msg}"));
                    target.error = Some(msg);
                    self.attached_targets.push(target);
                    continue;
                }

                let mut last_err = None;
                for symbol in Self::symbol_candidates(&syscall) {
                    match kprobe.attach(&symbol, 0) {
                        Ok(_) => {
                            target.attached = true;
                            target.symbol = Some(symbol.clone());
                            self.push_event(&syscall, format!("ATTACH_OK:{symbol}"));
                            break;
                        }
                        Err(err) => {
                            last_err = Some(format!("{symbol}: {err}"));
                        }
                    }
                }

                if !target.attached {
                    let msg = last_err.unwrap_or_else(|| "no symbol candidates succeeded".into());
                    self.push_event(&syscall, format!("ATTACH_FAIL:{msg}"));
                    target.error = Some(msg);
                }

                self.attached_targets.push(target);
            }

            let attached_count = self.attached_targets.iter().filter(|t| t.attached).count();
            if attached_count == 0 {
                self.push_event("probe_manager", "START_FAIL_NO_ATTACHMENTS");
                self.running = false;
                return Err(ProbeError::Load(
                    "failed to attach any configured syscall probes".to_string(),
                ));
            }

            self.bpf = Some(bpf);
            self.running = true;
            self.push_event(
                "probe_manager",
                format!("START_OK:{attached_count}_attached"),
            );
            Ok(())
        }
        #[cfg(all(feature = "kernel", not(target_os = "linux")))]
        {
            self.push_event("probe_manager", "START_FAIL_UNSUPPORTED_PLATFORM");
            tracing::warn!(
                "eBPF probe start requested with kernel feature enabled, but this target is not Linux."
            );
            Err(ProbeError::UnsupportedPlatform)
        }
        #[cfg(not(feature = "kernel"))]
        {
            self.push_event("probe_manager", "START_FAIL_KERNEL_FEATURE_DISABLED");
            tracing::warn!(
                "eBPF probe start requested but kernel feature is disabled. \
                 Rebuild with --features kernel on Linux 5.8+ to enable syscall interception."
            );
            Err(ProbeError::KernelFeatureDisabled)
        }
    }

    pub fn status(&self) -> serde_json::Value {
        serde_json::json!({
            "running": self.running,
            "kernel_feature": cfg!(feature = "kernel"),
            "kernel_runtime_supported": cfg!(target_os = "linux"),
            "target_syscalls": self.config.target_syscalls,
            "attached_targets": self.attached_targets,
            "object_path": self.object_path,
            "phase": "phase2",
        })
    }

    // read and drain lifecycle telemetry events
    pub async fn poll_events(&self) -> Vec<ProbeEvent> {
        match self.event_queue.lock() {
            Ok(mut queue) => queue.drain(..).collect(),
            Err(poisoned) => poisoned.into_inner().drain(..).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn poll_events_drains_queue() {
        let manager = ProbeManager::new(ProbeConfig::default());
        manager.push_event("probe_manager", "TEST_EVENT_1");
        manager.push_event("probe_manager", "TEST_EVENT_2");

        let events = manager.poll_events().await;
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e.decision == "TEST_EVENT_1"));
        assert!(events.iter().any(|e| e.decision == "TEST_EVENT_2"));

        let drained = manager.poll_events().await;
        assert!(drained.is_empty());
    }

    #[test]
    fn symbol_candidates_include_arch_fallbacks() {
        let candidates = ProbeManager::symbol_candidates("execve");
        assert_eq!(candidates[0], "__x64_sys_execve");
        assert_eq!(candidates[1], "__arm64_sys_execve");
        assert_eq!(candidates[2], "sys_execve");
    }
}
