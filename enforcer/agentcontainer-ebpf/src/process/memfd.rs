//! sys_enter_memfd_create tracepoint for fileless execution detection.
//!
//! Detects attempts to create anonymous memory-backed file descriptors via
//! memfd_create(2), which is a common technique for fileless malware execution.
//! The actual blocking happens at the bprm_check LSM hook when the agent tries
//! to exec the memfd's anonymous inode — this tracepoint provides detection and
//! logging so the enforcer can report the attempt.

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
};
use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use agentcontainer_common::events::COMM_MAX;

use crate::maps::MEMFD_EVENTS;

// --- Event type constant ---

/// Event type for memfd_create detection (matches EventType::MemfdBlocked in userspace).
const EVENT_MEMFD_BLOCKED: u32 = 9;

// --- Event struct ---

/// Event emitted when memfd_create is called within an enforced cgroup.
#[repr(C)]
struct MemfdEvent {
    timestamp_ns: u64,
    pid: u32,
    uid: u32,
    event_type: u32,
    verdict: u32,
    comm: [u8; COMM_MAX],
}

// --- Inline helpers ---

/// Check if the current cgroup is enforced.
#[inline(always)]
fn in_enforced_cgroup() -> bool {
    crate::maps::enforced_cgroup_for_current().is_some()
}

/// Emit a memfd block event to the MEMFD_EVENTS ring buffer.
#[inline(always)]
fn emit_memfd_event() {
    if let Some(mut buf) = MEMFD_EVENTS.reserve::<MemfdEvent>(0) {
        let ev = unsafe { &mut *buf.as_mut_ptr() };
        ev.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
        ev.pid = (pid_tgid >> 32) as u32;

        let uid_gid = unsafe { bpf_get_current_uid_gid() };
        ev.uid = uid_gid as u32;

        ev.event_type = EVENT_MEMFD_BLOCKED;
        ev.verdict = 1; // Block

        ev.comm = match unsafe { bpf_get_current_comm() } {
            Ok(c) => c,
            Err(_) => [0u8; COMM_MAX],
        };

        buf.submit(0);
    }
}

// ---------------------------------------------------------------------------
// syscalls/sys_enter_memfd_create -- detects fileless execution attempts.
// ---------------------------------------------------------------------------

#[tracepoint(category = "syscalls", name = "sys_enter_memfd_create")]
pub fn ac_memfd_create(_ctx: TracePointContext) -> u32 {
    match try_memfd_create() {
        Ok(ret) => ret,
        Err(_) => 0, // fail-open on BPF errors
    }
}

fn try_memfd_create() -> Result<u32, i64> {
    // 1. Cgroup scoping: only detect memfd_create in enforced containers.
    if !in_enforced_cgroup() {
        return Ok(0);
    }

    // 2. Emit detection event — the tracepoint cannot block the syscall,
    //    but bprm_check will deny exec of the resulting anonymous inode.
    emit_memfd_event();

    Ok(0)
}
