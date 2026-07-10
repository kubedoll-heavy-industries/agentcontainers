//! sched_process_exit tracepoint for process-tree map cleanup.
//!
//! Removes the exiting PID from `PROC_ENFORCED` and `PROC_DENY_SETS` so maps
//! do not fill with dead PIDs. Cleanup runs whenever the PID has sticky
//! membership — not only when the current cgroup still looks enforced — so a
//! process that migrated to a sibling cgroup still gets cleaned up.

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use crate::maps::{PROC_DENY_SETS, PROC_ENFORCED};

#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn ac_sched_exit(_ctx: TracePointContext) -> u32 {
    match try_sched_exit() {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sched_exit() -> Result<u32, i64> {
    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;

    // Always attempt removal: entries are sparse; remove is a no-op if absent.
    // Do not gate on cgroup membership — sticky PIDs may have left the
    // registered cgroup tree.
    let _ = unsafe { PROC_ENFORCED.remove(&pid) };
    let _ = unsafe { PROC_DENY_SETS.remove(&pid) };

    Ok(0)
}
