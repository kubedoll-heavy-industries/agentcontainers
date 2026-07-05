//! sched_process_fork tracepoint for deny-set inheritance.
//!
//! When a process in an enforced cgroup forks, the child inherits the parent's
//! deny_set_id from PROC_DENY_SETS. This ensures that security policy follows
//! process lineage — a restricted process cannot escape its deny-set by forking.
//!
//! Tracepoint fields (from /sys/kernel/debug/tracing/events/sched/sched_process_fork/format):
//!   offset 24: parent_pid (u32)
//!   offset 44: child_pid  (u32)

use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use crate::maps::PROC_DENY_SETS;

/// Check if the current cgroup is enforced.
#[inline(always)]
fn in_enforced_cgroup() -> bool {
    crate::maps::enforced_cgroup_for_current().is_some()
}

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn ac_sched_fork(ctx: TracePointContext) -> u32 {
    match try_sched_fork(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Fail-open on BPF errors
    }
}

fn try_sched_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    // 0. Cgroup scoping: only propagate deny-sets for enforced containers.
    if !in_enforced_cgroup() {
        return Ok(0);
    }

    // 1. Read parent_pid (offset 24) and child_pid (offset 44) from tracepoint args.
    let parent_pid: u32 = unsafe { ctx.read_at(24)? };
    let child_pid: u32 = unsafe { ctx.read_at(44)? };

    // 2. Look up the parent's deny_set_id.
    if let Some(deny_set_id) = unsafe { PROC_DENY_SETS.get(&parent_pid) } {
        // 3. Inherit: insert child_pid with the same deny_set_id.
        let _ = unsafe { PROC_DENY_SETS.insert(&child_pid, deny_set_id, 0) };
    }

    Ok(0)
}
