//! LSM bprm_check_security hook for process execution enforcement.
//!
//! Intercepts execve() and enforces two stacked layers:
//!
//! Layer 1 (binary identity — this module owns it):
//!   0. Cgroup scoping + opt-in: skip cgroups that are not exec-enforced.
//!   1. Read the executable's inode from linux_binprm->file->…->d_inode.
//!   2. Allow only if (device, inode, cgroup) is present in ALLOWED_EXECS.
//!   3. Otherwise deny (-EACCES). Once a process is confirmed to belong to an
//!      exec-enforced cgroup, any failure to read or look up its executable
//!      identity is a denial (fail-CLOSED), never an allow.
//!
//! Layer 2 (deny-set process-tree policy — runs UNDER Layer 1, after the
//!   binary is authorized and before the final allow): if the current PID is
//!   tracked in PROC_DENY_SETS, the (deny_set_id, inode, dev) must be present
//!   in DENY_SET_POLICY, and any matching DENY_SET_TRANSITIONS re-tags the PID.
//!
//! Layer 1 authorizes *which binary* may run; it does not inspect command
//! arguments — that is the guard layer's responsibility.

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_probe_read_kernel,
};
use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;

use agentcontainer_common::events::{
    DenySetEvent, ExecEvent, STAT_DENYSET_ALLOWED, STAT_DENYSET_BLOCKED, STAT_PROC_ALLOWED,
    STAT_PROC_BLOCKED,
};
use agentcontainer_common::maps::{
    DenySetKey, FsInodeKey, CGROUP_FLAG_EXEC_ENFORCED, LSM_ALLOW, LSM_DENY,
};

use crate::maps::{
    bump_cgroup_stat, ALLOWED_EXECS, CGROUP_STAT_DENYSET_ALLOWED, CGROUP_STAT_DENYSET_BLOCKED,
    CGROUP_STAT_PROC_ALLOWED, CGROUP_STAT_PROC_BLOCKED, DENY_SET_POLICY, DENY_SET_TRANSITIONS,
    KERNEL_OFFSETS, PROC_DENY_SETS, PROC_EVENTS, PROC_STATS,
};

// ---------------------------------------------------------------------------
// Kernel struct fields are read at BTF-resolved byte offsets (KERNEL_OFFSETS),
// not via hardcoded `#[repr(C)]` mirrors: the Rust eBPF toolchain emits no CO-RE
// relocations, so fixed offsets break across kernel versions (6.x reorders
// `linux_binprm`/`file`). The executable inode comes from `file->f_inode`
// (stable since v3.9), avoiding the f_path/dentry walk entirely.
// ---------------------------------------------------------------------------

/// Read a `T` from `base + off` in kernel memory. `off` is a BTF-resolved byte
/// offset from KERNEL_OFFSETS.
#[inline(always)]
unsafe fn read_at<T>(base: *const u8, off: u32) -> Result<T, i64> {
    bpf_probe_read_kernel(base.add(off as usize) as *const T)
}

// ---------------------------------------------------------------------------
// Inline helpers
// ---------------------------------------------------------------------------

/// Bump a per-CPU stats counter by index.
#[inline(always)]
fn bump_stat(idx: u32) {
    unsafe {
        if let Some(val) = PROC_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

/// Bump a per-CPU deny-set stats counter by index.
#[inline(always)]
fn bump_denyset_stat(idx: u32) {
    unsafe {
        if let Some(val) = PROC_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

/// Emit a process execution event to the PROC_EVENTS ring buffer.
/// `verdict` follows `events::Verdict`: 0 = allow, 1 = block.
#[inline(always)]
fn emit_exec_event(cgroup_id: u64, ino: u64, verdict: u32) {
    if let Some(mut entry) = PROC_EVENTS.reserve::<ExecEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;

            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;

            (*ev).event_type = 4; // EventType::ProcessExec
            (*ev).verdict = verdict;
            (*ev).cgroup_id = cgroup_id;

            (*ev).inode = ino;

            // Zero out variable-length fields before populating.
            (*ev).binary = [0u8; 256];

            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; 16],
            };
        }
        entry.submit(0);
    }
}

/// Record a denied execution: bump block stats, audit it, and return LSM_DENY.
/// `ino` is 0 when the inode could not be read (the identity is unverifiable,
/// which is itself a denial).
#[inline(always)]
fn deny_exec(cgroup_id: u64, ino: u64) -> i32 {
    bump_stat(STAT_PROC_BLOCKED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_BLOCKED);
    emit_exec_event(cgroup_id, ino, 1 /* Verdict::Block */);
    LSM_DENY
}

/// Emit a block event for a deny-set policy violation to the PROC_EVENTS ring buffer.
#[inline(always)]
fn emit_denyset_block_event(deny_set_id: u32, child_ino: u64) {
    if let Some(mut entry) = PROC_EVENTS.reserve::<DenySetEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;

            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;

            (*ev).event_type = 6; // EventType::DenySetViolation
            (*ev).verdict = 1; // Verdict::Block

            (*ev).deny_set_id = deny_set_id;
            (*ev).parent_inode = 0; // Not available in bprm_check context.
            (*ev).child_inode = child_ino;

            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; 16],
            };
        }
        entry.submit(0);
    }
}

// ---------------------------------------------------------------------------
// lsm/bprm_check_security -- intercepts process execution (execve).
// ---------------------------------------------------------------------------

#[lsm(hook = "bprm_check_security")]
pub fn ac_bprm_check(ctx: LsmContext) -> i32 {
    match try_bprm_check(&ctx) {
        Ok(ret) => ret,
        // Fail closed: try_bprm_check only returns Err after the process is
        // confirmed to belong to an exec-enforced cgroup, so a read failure is
        // an unverifiable execution and must be denied, not allowed.
        Err(_) => LSM_DENY,
    }
}

fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i64> {
    // 0. Cgroup scoping: only enforce for processes in target containers.
    //    LSM hooks are system-wide; skip all non-container processes.
    // Subtree match: a task moved into a descendant of an enforced cgroup stays
    // governed by that ancestor's flags/policy, closing the child-cgroup escape.
    let (cgroup_id, flags) = match crate::maps::enforced_cgroup_flags_for_current() {
        Some(x) => x,
        None => return Ok(LSM_ALLOW),
    };

    // 1. Exec-allowlist enforcement is OPT-IN: only cgroups that had a non-empty
    //    exec allowlist applied (the EXEC_ENFORCED flag) are gated here. Tool-runner
    //    backends — e.g. the SIFT gateway, which must spawn its own MCP sub-servers
    //    and forensic binaries — receive no allowlist and run execs freely; their
    //    network/filesystem/readonly-rootfs/cap-drop confinement still applies.
    if flags & CGROUP_FLAG_EXEC_ENFORCED == 0 {
        return Ok(LSM_ALLOW);
    }

    // 2. BTF-resolved field offsets. Absent (userspace failed to populate) means
    //    we cannot verify the executable identity — fail closed.
    let offs = match KERNEL_OFFSETS.get(0) {
        Some(o) => o,
        None => return Ok(deny_exec(cgroup_id, 0)),
    };

    // Read the linux_binprm pointer from the LSM hook's first argument, then
    // walk linux_binprm* → file* → inode* (via file->f_inode, stable since
    // v3.9) → (i_ino, i_sb->s_dev). A missing file/inode/superblock means the
    // executable identity cannot be verified; for an enforced process that is a
    // denial, not an allowance (fail-CLOSED).
    let bprm_ptr: *const u8 = unsafe { ctx.arg(0) };

    let file_ptr: *const u8 = unsafe { read_at(bprm_ptr, offs.binprm_file)? };
    if file_ptr.is_null() {
        return Ok(deny_exec(cgroup_id, 0));
    }

    let inode_ptr: *const u8 = unsafe { read_at(file_ptr, offs.file_f_inode)? };
    if inode_ptr.is_null() {
        return Ok(deny_exec(cgroup_id, 0));
    }

    let ino: u64 = unsafe { read_at(inode_ptr, offs.inode_i_ino)? };

    let sb_ptr: *const u8 = unsafe { read_at(inode_ptr, offs.inode_i_sb)? };
    if sb_ptr.is_null() {
        return Ok(deny_exec(cgroup_id, ino));
    }

    let s_dev: u32 = unsafe { read_at(sb_ptr, offs.sb_s_dev)? };

    // Build lookup key with device major/minor numbers, scoped to this cgroup.
    // Linux dev_t: MAJOR = (dev >> 20) & 0xfff, MINOR = dev & 0xfffff.
    let key = FsInodeKey {
        inode: ino,
        dev_major: (s_dev >> 20) & 0xfff,
        dev_minor: s_dev & 0xfffff,
        cgroup_id,
    };

    // 3. Allowlist enforcement (Layer 1): an execution is permitted only when
    //    its (device, inode, cgroup) identity is present in ALLOWED_EXECS.
    //    Anything else (including an empty allowlist) is denied, fail-CLOSED.
    if unsafe { ALLOWED_EXECS.get(&key) }.is_none() {
        return Ok(deny_exec(cgroup_id, ino));
    }

    // Binary passed the Layer-1 allowlist. Count it as allowed at the binary
    // layer; the deny-set (Layer 2) may still block the exec below.
    bump_stat(STAT_PROC_ALLOWED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_ALLOWED);

    // 4. Deny-set policy (Layer 2): look up current PID in PROC_DENY_SETS.
    //    If the process is not under process-tree enforcement, skip.
    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
    if let Some(deny_set_id_ptr) = unsafe { PROC_DENY_SETS.get(&pid) } {
        let deny_set_id = *deny_set_id_ptr;

        // Build deny-set lookup key: (deny_set_id, inode, dev).
        let ds_key = DenySetKey {
            deny_set_id,
            _pad: 0,
            inode: ino,
            dev_major: key.dev_major,
            dev_minor: key.dev_minor,
        };

        // Presence in DENY_SET_POLICY means the exec is allowed for this deny-set.
        if unsafe { DENY_SET_POLICY.get(&ds_key) }.is_none() {
            // Not in deny-set policy -- block.
            bump_denyset_stat(STAT_DENYSET_BLOCKED);
            bump_cgroup_stat(cgroup_id, CGROUP_STAT_DENYSET_BLOCKED);
            emit_denyset_block_event(deny_set_id, ino);
            return Ok(LSM_DENY);
        }

        // Allowed by deny-set policy. Check for deny-set transition.
        bump_denyset_stat(STAT_DENYSET_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_DENYSET_ALLOWED);

        // If a transition exists, update the PID's deny_set_id.
        if let Some(new_id_ptr) = unsafe { DENY_SET_TRANSITIONS.get(&ds_key) } {
            let new_id = *new_id_ptr;
            let _ = PROC_DENY_SETS.insert(&pid, &new_id, 0);
        }
    }

    // 5. Both layers passed -- allow and audit the exec.
    emit_exec_event(cgroup_id, ino, 0 /* Verdict::Allow */);
    Ok(LSM_ALLOW)
}
