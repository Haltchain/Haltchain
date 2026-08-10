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
            target_syscalls: vec!["execve".into(), "connect".into(), "openat".into()],
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

    // Drain lifecycle telemetry events (probe attach/detach, errors).
    pub async fn poll_events(&self) -> Vec<ProbeEvent> {
        match self.event_queue.lock() {
            Ok(mut queue) => queue.drain(..).collect(),
            Err(poisoned) => poisoned.into_inner().drain(..).collect(),
        }
    }

    /// Drain actual BPF ring-buffer events produced by the eBPF kprobes.
    /// Only available when the `kernel` feature is enabled and the manager is running.
    /// In non-kernel builds this returns an empty vec (observability mode).
    #[cfg(all(feature = "kernel", target_os = "linux"))]
    pub fn drain_ringbuf_events(&mut self) -> Vec<ProbeEvent> {
        use aya::maps::RingBuf;
        let bpf = match self.bpf.as_mut() {
            Some(b) => b,
            None => return vec![],
        };
        let ring: RingBuf<_> = match bpf.map_mut("events") {
            Ok(m) => match m.try_into() {
                Ok(rb) => rb,
                Err(_) => return vec![],
            },
            Err(_) => return vec![],
        };
        let mut out = Vec::new();
        // aya RingBuf implements Iterator over items; each item is a raw byte slice
        // matching SyscallEvent layout.
        for item in ring {
            let item = match item {
                Ok(i) => i,
                Err(_) => continue,
            };
            let bytes: &[u8] = &item;
            if bytes.len() < core::mem::size_of::<RawSyscallEvent>() {
                continue;
            }
            let raw = unsafe { &*(bytes.as_ptr() as *const RawSyscallEvent) };
            out.push(ProbeEvent {
                pid: raw.pid,
                syscall: bytes_to_str(&raw.syscall),
                comm: bytes_to_str(&raw.comm),
                decision: bytes_to_str(&raw.decision),
                ts_ns: raw.ts_ns,
            });
        }
        out
    }

    #[cfg(not(all(feature = "kernel", target_os = "linux")))]
    pub fn drain_ringbuf_events(&mut self) -> Vec<ProbeEvent> {
        vec![]
    }

    /// Insert a comm name into the BLOCKED_COMMS policy map so the eBPF
    /// kprobe will deny syscalls from that process. No-op without kernel feature.
    #[cfg(all(feature = "kernel", target_os = "linux"))]
    pub fn block_comm(&mut self, comm: &str) -> Result<(), ProbeError> {
        use aya::maps::HashMap;
        let bpf = self.bpf.as_mut().ok_or_else(|| ProbeError::Load("probe not loaded".into()))?;
        let mut map: HashMap<_, [u8; 16], u8> = bpf
            .map_mut("blocked_comms")
            .map_err(|e| ProbeError::Load(format!("blocked_comms map: {e}")))?
            .try_into()
            .map_err(|e| ProbeError::Load(format!("blocked_comms cast: {e}")))?;
        let mut key = [0u8; 16];
        let bytes = comm.as_bytes();
        let len = bytes.len().min(16);
        key[..len].copy_from_slice(&bytes[..len]);
        map.insert(key, 1u8, 0)
            .map_err(|e| ProbeError::Load(format!("map insert: {e}")))?;
        self.push_event("probe_manager", format!("BLOCK_COMM:{comm}"));
        Ok(())
    }

    #[cfg(not(all(feature = "kernel", target_os = "linux")))]
    pub fn block_comm(&mut self, _comm: &str) -> Result<(), ProbeError> {
        Err(ProbeError::KernelFeatureDisabled)
    }
}

/// Mirror of the SyscallEvent C struct from the BPF program.
#[repr(C)]
struct RawSyscallEvent {
    pid: u32,
    syscall: [u8; 16],
    comm: [u8; 16],
    decision: [u8; 16],
    ts_ns: u64,
}

fn bytes_to_str(b: &[u8; 16]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(16);
    String::from_utf8_lossy(&b[..end]).to_string()
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
