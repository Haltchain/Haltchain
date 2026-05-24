#![no_std]
#![no_main]

use aya_ebpf::macros::{kprobe, map};
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::ProbeContext;

#[repr(C)]
pub struct SyscallEvent {
    pub pid: u32,
    pub syscall: [u8; 16],
    pub comm: [u8; 16],
    pub decision: [u8; 16],
    pub ts_ns: u64,
}

#[map(name = "events")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

const ALLOW: [u8; 16] = *b"ALLOW\0\0\0\0\0\0\0\0\0\0\0";
const DENY: [u8; 16] = *b"DENY\0\0\0\0\0\0\0\0\0\0\0\0";

fn copy_into(dst: &mut [u8], src: &[u8]) {
    let len = core::cmp::min(dst.len(), src.len());
    dst[..len].copy_from_slice(&src[..len]);
}

// observability-only stub until map-driven policy is wired from userspace
fn check_policy(_pid: u32, _comm: &[u8; 16]) -> bool {
    true
}

fn emit_event(syscall_name: &[u8], pid: u32, comm: [u8; 16], decision: [u8; 16]) {
    let event = SyscallEvent {
        pid,
        syscall: {
            let mut buf = [0u8; 16];
            copy_into(&mut buf, syscall_name);
            buf
        },
        comm,
        decision,
        ts_ns: aya_ebpf::helpers::bpf_get_current_pid_tgid(),
    };
    let _ = unsafe { EVENTS.output(&event, 0) };
}

#[kprobe(function = "execve")]
pub fn execve(_ctx: ProbeContext) -> u32 {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);
    let decision = if check_policy(pid, &comm) {
        ALLOW
    } else {
        DENY
    };
    emit_event(b"execve", pid, comm, decision);
    0
}

#[kprobe(function = "connect")]
pub fn connect(_ctx: ProbeContext) -> u32 {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);
    let decision = if check_policy(pid, &comm) {
        ALLOW
    } else {
        DENY
    };
    emit_event(b"connect", pid, comm, decision);
    0
}

#[kprobe(function = "openat")]
pub fn openat(_ctx: ProbeContext) -> u32 {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]);
    let decision = if check_policy(pid, &comm) {
        ALLOW
    } else {
        DENY
    };
    emit_event(b"openat", pid, comm, decision);
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
