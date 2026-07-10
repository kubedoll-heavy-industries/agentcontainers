//! sched_process_exit tracepoint for PROC_DENY_SETS cleanup.
//!
//! When a process in an enforced cgroup exits, its entry is removed from
//! PROC_DENY_SETS. This prevents map exhaustion from dead PIDs accumulating
//! over time.

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use crate::maps::PROC_DENY_SETS;

/// Check if the current cgroup is enforced.
#[inline(always)]
fn in_enforced_cgroup() -> bool {
    crate::maps::enforced_cgroup_for_current().is_some()
}

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn ac_sched_exit(_ctx: TracePointContext) -> u32 {
    match try_sched_exit() {
        Ok(ret) => ret,
        Err(_) => 0, // Fail-open on BPF errors
    }
}

fn try_sched_exit() -> Result<u32, i64> {
    // 0. Cgroup scoping: only clean up for enforced containers.
    if !in_enforced_cgroup() {
        return Ok(0);
    }

    // 1. Get the exiting PID (tgid).
    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;

    // 2. Remove the PID from PROC_DENY_SETS to prevent map exhaustion.
    let _ = unsafe { PROC_DENY_SETS.remove(&pid) };

    Ok(0)
}
