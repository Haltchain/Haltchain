//! Phase 2: eBPF syscall interception via aya-rs.
//!
//! Status: runtime-gated — kernel feature requires Linux 5.8+ and the `kernel` cargo feature.
//!
//! Architecture:
//!   - kprobes on `execve`/`connect`/`openat` to intercept agent tool calls before userspace
//!   - BPF maps for zero-copy data transfer to the Rust sidecar
//!   - Perf events / ring buffers for low-overhead decision feed-back
//!
//! Build for production:
//!   cargo build -p haltchain-ebpf --features kernel --target x86_64-unknown-linux-gnu
//!
//! Phase 2 milestones (from Final_roadmap.md lines 590-594):
//!   - [x] Crate skeleton + feature gating
//!   - [ ] kprobe on execve — block agent spawning new processes when drift detected
//!   - [ ] kprobe on connect — intercept outbound network calls, validate against policy
//!   - [ ] io_uring hot path migration (see io_uring module)
//!   - [ ] Seccomp-BPF dynamic profile generation from observed syscall set

pub mod io_uring;
pub mod probe_manager;
pub mod seccomp_gen;

pub use probe_manager::{ProbeConfig, ProbeEvent, ProbeManager};

/// Build info string for health/status endpoints.
pub fn build_info() -> String {
    format!(
        "haltchain-ebpf/{} phase=phase2 kernel_feature={}",
        env!("CARGO_PKG_VERSION"),
        if cfg!(feature = "kernel") {
            "enabled"
        } else {
            "disabled"
        }
    )
}
