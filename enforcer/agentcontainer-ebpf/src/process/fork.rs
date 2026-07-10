//! sched_process_fork tracepoint for process-tree policy inheritance.
//!
//! When a process under enforcement forks:
//! 1. Child inherits `PROC_ENFORCED` (governing cgroup_id) so sibling / non-
//!    ancestor cgroup migrations cannot drop the child out of the subject set.
//! 2. Child inherits `PROC_DENY_SETS` deny_set_id when the parent has one.
//!
//! Tracepoint fields (from sched_process_fork format):
//!   offset 24: parent_pid (u32)
//!   offset 44: child_pid  (u32)

use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use crate::maps::{governing_cgroup_for_pid, PROC_DENY_SETS, PROC_ENFORCED};

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn ac_sched_fork(ctx: TracePointContext) -> u32 {
    match try_sched_fork(&ctx) {
        Ok(ret) => ret,
        // Fork inheritance failures must not silently drop the child out of
        // the process-tree subject set when the parent is known-enforced —
        // but we cannot block fork from a tracepoint. Best effort only.
        Err(_) => 0,
    }
}

fn try_sched_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    let parent_pid: u32 = unsafe { ctx.read_at(24)? };
    let child_pid: u32 = unsafe { ctx.read_at(44)? };

    // 1. Sticky subject: if parent is under enforcement (cgroup subtree OR
    //    already sticky), stamp the child with the same governing cgroup.
    if let Some(gov) = governing_cgroup_for_pid(parent_pid) {
        let _ = unsafe { PROC_ENFORCED.insert(&child_pid, &gov, 0) };
    }

    // 2. Deny-set inheritance (existing Layer-2 process-tree policy).
    if let Some(deny_set_id) = unsafe { PROC_DENY_SETS.get(&parent_pid) } {
        let _ = unsafe { PROC_DENY_SETS.insert(&child_pid, deny_set_id, 0) };
    }

    Ok(0)
}
