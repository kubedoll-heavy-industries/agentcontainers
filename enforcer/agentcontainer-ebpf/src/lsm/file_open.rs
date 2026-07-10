//! LSM file_open hook for filesystem enforcement.
//!
//! Intercepts file open operations and enforces inode-based access policy:
//! 0. Check cgroup scoping -- skip non-enforced cgroups.
//! 1. Check procfs environ -- always block /proc/*/environ.
//! 2a. Check SECRET_ACLS -- per-cgroup credential gating (TTL + write checks).
//! 2. Check denied inodes -- always block.
//! 3. Check allowed inodes -- allow with permission check.
//! 4. Default deny.
//!
//! On BLOCK, emits an FsEvent to the ring buffer for audit logging.
//! Increments per-CPU stats on every decision.

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    bpf_probe_read_kernel,
};
use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;

use agentcontainer_common::events::{
    CredEvent, EventType, FsEvent, Verdict, COMM_MAX, CRED_REASON_TTL_EXPIRED,
    CRED_REASON_WRITE_DENIED, EVENT_CRED_OPEN,
};
use agentcontainer_common::maps::{
    KernelOffsets, ScopedFsInodeKey, SecretAclKey, DENTRY_NAME_LEN, FS_PERM_WRITE, LSM_ALLOW,
    LSM_DENY, PROC_SUPER_MAGIC,
};

use crate::maps::{
    bump_cgroup_stat, ALLOWED_INODES, CGROUP_STAT_CRED_ALLOWED, CGROUP_STAT_CRED_BLOCKED,
    CGROUP_STAT_FS_ALLOWED, CGROUP_STAT_FS_BLOCKED, CRED_EVENTS, CRED_STATS, DENIED_INODES,
    FS_EVENTS, FS_STATS, KERNEL_OFFSETS, SECRET_ACLS,
};

// ---------------------------------------------------------------------------
// Kernel struct fields are read at BTF-resolved byte offsets (KERNEL_OFFSETS),
// not hardcoded `#[repr(C)]` mirrors — the Rust eBPF toolchain emits no CO-RE
// relocations, so fixed offsets break across kernel versions. The inode comes
// from `file->f_inode` (stable since v3.9); the dentry (for the /proc/*/environ
// name check) still comes via `file->f_path.dentry`.
// ---------------------------------------------------------------------------

/// Read a `T` from `base + off` in kernel memory. `off` is a BTF-resolved byte
/// offset from KERNEL_OFFSETS.
#[inline(always)]
unsafe fn read_at<T>(base: *const u8, off: u32) -> Result<T, i64> {
    bpf_probe_read_kernel(base.add(off as usize) as *const T)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Bump a per-CPU stat counter at the given index.
#[inline(always)]
fn bump_fs_stat(idx: u32) {
    unsafe {
        if let Some(val) = FS_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

/// Emit a filesystem block event to the ring buffer.
#[inline(always)]
fn emit_fs_block_event(inode_nr: u64, flags: u32) {
    if let Some(mut buf) = FS_EVENTS.reserve::<FsEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            (*event).pid = (pid_tgid >> 32) as u32;

            let uid_gid = bpf_get_current_uid_gid();
            (*event).uid = uid_gid as u32;

            (*event).event_type = EventType::FsOpen as u32;
            (*event).verdict = Verdict::Block as u32;
            (*event).inode = inode_nr;
            (*event).flags = flags;
            (*event)._pad = 0;

            // Fill comm from current task name.
            (*event).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; COMM_MAX],
            };
        }
        buf.submit(0);
    }
}

/// Bump a per-CPU credential stat counter at the given index.
#[inline(always)]
fn bump_cred_stat(idx: u32) {
    unsafe {
        if let Some(val) = CRED_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

/// Emit a credential block event to the ring buffer.
#[inline(always)]
fn emit_cred_block_event(inode_nr: u64, cgid: u64, reason: u32) {
    if let Some(mut buf) = CRED_EVENTS.reserve::<CredEvent>(0) {
        let event = buf.as_mut_ptr();
        unsafe {
            (*event).timestamp_ns = bpf_ktime_get_ns();
            let pid_tgid = bpf_get_current_pid_tgid();
            (*event).pid = (pid_tgid >> 32) as u32;
            let uid_gid = bpf_get_current_uid_gid();
            (*event).uid = uid_gid as u32;
            (*event).event_type = EVENT_CRED_OPEN;
            (*event).verdict = Verdict::Block as u32;
            (*event).inode = inode_nr;
            (*event).cgroup_id = cgid;
            (*event).reason = reason;
            (*event)._pad = 0;
            (*event).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; COMM_MAX],
            };
        }
        buf.submit(0);
    }
}

/// Detect /proc/*/environ by checking the dentry name on a procfs filesystem.
///
/// This handles the CRED-1 finding: procfs inodes are dynamic, so inode-based
/// deny lists do not work. Instead we check:
///   1. The filesystem is procfs (s_magic == PROC_SUPER_MAGIC).
///   2. The dentry name matches "environ".
///
/// HIGH-2 limitation: Bypassable via symlinks pointing to /proc/*/environ.
/// Mitigated by read-only rootfs and process enforcer restrictions.
#[inline(always)]
unsafe fn is_proc_environ(file_ptr: *const u8, offs: &KernelOffsets) -> bool {
    // Inode via file->f_inode → i_sb → s_magic; only procfs proceeds.
    let inode_ptr: *const u8 = match read_at(file_ptr, offs.file_f_inode) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if inode_ptr.is_null() {
        return false;
    }

    // Read the superblock pointer from inode->i_sb.
    let sb_ptr: *const u8 = match read_at(inode_ptr, offs.inode_i_sb) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if sb_ptr.is_null() {
        return false;
    }

    // Check filesystem magic -- only proceed if this is procfs.
    let s_magic: u64 = match read_at(sb_ptr, offs.sb_s_magic) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if s_magic != PROC_SUPER_MAGIC {
        return false;
    }

    // Dentry name via file->f_path.dentry->d_name.name (d_name is an embedded
    // qstr, so its `name` pointer is at d_name + qstr.name).
    let dentry_ptr: *const u8 = match read_at(file_ptr, offs.file_f_path + offs.path_dentry) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if dentry_ptr.is_null() {
        return false;
    }
    let name_ptr: *const u8 = match read_at(dentry_ptr, offs.dentry_d_name + offs.qstr_name) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if name_ptr.is_null() {
        return false;
    }

    // Read the dentry name into a local buffer.
    let mut name_buf = [0u8; DENTRY_NAME_LEN];
    if bpf_probe_read_kernel_buf(name_ptr, &mut name_buf[..DENTRY_NAME_LEN - 1]).is_err() {
        return false;
    }

    // Compare against "environ" (7 chars + null terminator).
    const ENVIRON: &[u8] = b"environ\0";
    name_buf[0] == ENVIRON[0]
        && name_buf[1] == ENVIRON[1]
        && name_buf[2] == ENVIRON[2]
        && name_buf[3] == ENVIRON[3]
        && name_buf[4] == ENVIRON[4]
        && name_buf[5] == ENVIRON[5]
        && name_buf[6] == ENVIRON[6]
        && name_buf[7] == 0
}

/// Read a byte buffer from kernel memory. Wraps bpf_probe_read_kernel for
/// copying into a mutable slice.
#[inline(always)]
unsafe fn bpf_probe_read_kernel_buf(src: *const u8, dst: &mut [u8]) -> Result<(), i64> {
    // aya_ebpf::helpers::bpf_probe_read_kernel reads a single T.
    // For a buffer, we use the raw BPF helper directly.
    let ret = aya_ebpf::helpers::gen::bpf_probe_read_kernel(
        dst.as_mut_ptr() as *mut core::ffi::c_void,
        dst.len() as u32,
        src as *const core::ffi::c_void,
    );
    if ret < 0 {
        Err(ret)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LSM file_open hook
// ---------------------------------------------------------------------------

#[lsm(hook = "file_open")]
pub fn ac_file_open(ctx: LsmContext) -> i32 {
    match try_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => LSM_ALLOW, // On error, fail open (same as C implementation)
    }
}

#[inline(always)]
fn try_file_open(ctx: &LsmContext) -> Result<i32, i64> {
    // 0. Cgroup scoping: only enforce for processes in target containers.
    //    LSM hooks are system-wide; skip all non-container processes.
    // Subtree match: a task moved into a descendant of an enforced cgroup stays
    // governed by that ancestor (its inode maps/stats), closing the child-cgroup
    // escape. `cgid` is the enforced ancestor's id.
    let cgid = match crate::maps::enforced_cgroup_for_current() {
        Some(id) => id,
        None => return Ok(LSM_ALLOW),
    };

    // BTF-resolved field offsets. Absent means userspace failed to populate them;
    // file_open's error policy is fail-open (matches the `Err` arm below).
    let offs = match KERNEL_OFFSETS.get(0) {
        Some(o) => o,
        None => return Ok(LSM_ALLOW),
    };

    // Get the file pointer from the LSM hook argument.
    let file_ptr: *const u8 = unsafe { ctx.arg::<*const u8>(0) };
    if file_ptr.is_null() {
        return Ok(LSM_ALLOW);
    }

    // 1. Check for /proc/*/environ -- always block to protect credentials.
    //    Procfs inodes are dynamic and cannot be predicted at attach time,
    //    so we use dentry name matching on procfs filesystems (CRED-1 fix).
    if unsafe { is_proc_environ(file_ptr, offs) } {
        bump_fs_stat(agentcontainer_common::events::STAT_FS_BLOCKED);
        bump_cgroup_stat(cgid, CGROUP_STAT_FS_BLOCKED);
        emit_fs_block_event(0, 0);
        return Ok(LSM_DENY);
    }

    // Read the inode via file->f_inode (stable since v3.9 — no dentry walk).
    let inode_ptr: *const u8 = unsafe { read_at(file_ptr, offs.file_f_inode)? };
    if inode_ptr.is_null() {
        bump_fs_stat(agentcontainer_common::events::STAT_FS_ALLOWED);
        bump_cgroup_stat(cgid, CGROUP_STAT_FS_ALLOWED);
        return Ok(LSM_ALLOW);
    }

    // Read inode number.
    let ino: u64 = unsafe { read_at(inode_ptr, offs.inode_i_ino)? };

    // Read file flags (file.f_flags) at its BTF-resolved offset.
    let flags: u32 = unsafe { read_at(file_ptr, offs.file_f_flags)? };

    // Read the superblock to get the device number.
    let sb_ptr: *const u8 = unsafe { read_at(inode_ptr, offs.inode_i_sb)? };
    if sb_ptr.is_null() {
        bump_fs_stat(agentcontainer_common::events::STAT_FS_ALLOWED);
        bump_cgroup_stat(cgid, CGROUP_STAT_FS_ALLOWED);
        return Ok(LSM_ALLOW);
    }

    let s_dev: u32 = unsafe { read_at(sb_ptr, offs.sb_s_dev)? };

    // Build lookup key with actual device numbers.
    // Linux dev_t: MAJOR(dev) = (dev >> 20) & 0xfff, MINOR(dev) = dev & 0xfffff
    let key = ScopedFsInodeKey {
        inode: ino,
        dev_major: (s_dev >> 20) & 0xfff,
        dev_minor: s_dev & 0xfffff,
        // ScopedFsInodeKey is now cgroup-scoped; use this hook's own exact-match cgid.
        cgroup_id: cgid,
    };

    // 2a. Credential enforcement: check SECRET_ACLS for per-cgroup secret access.
    let cred_key = SecretAclKey {
        inode: ino,
        dev_major: (s_dev >> 20) & 0xfff,
        dev_minor: s_dev & 0xfffff,
        cgroup_id: cgid,
    };

    if let Some(acl) = unsafe { SECRET_ACLS.get(&cred_key) } {
        // ACL entry exists — this is a secret file for this cgroup.
        let now_ns = unsafe { bpf_ktime_get_ns() };
        if acl.expires_at_ns > 0 && now_ns > acl.expires_at_ns {
            // Expired — deny.
            bump_cred_stat(agentcontainer_common::events::STAT_CRED_BLOCKED);
            bump_cgroup_stat(cgid, CGROUP_STAT_CRED_BLOCKED);
            emit_cred_block_event(ino, cgid, CRED_REASON_TTL_EXPIRED);
            return Ok(LSM_DENY);
        }

        // Check write permission.
        // O_WRONLY=0x01, O_RDWR=0x02, O_TRUNC=0o1000, O_APPEND=0o2000
        // Note: O_CREAT is intentionally excluded — in the LSM file_open hook the
        // file already exists, and O_CREAT alone (with O_RDONLY) does not imply
        // write intent.
        let write_access = (flags & 0x01) != 0    // O_WRONLY
            || (flags & 0x02) != 0                 // O_RDWR
            || (flags & 0o1000) != 0              // O_TRUNC
            || (flags & 0o2000) != 0; // O_APPEND

        if write_access && (acl.allowed_ops & FS_PERM_WRITE) == 0 {
            bump_cred_stat(agentcontainer_common::events::STAT_CRED_BLOCKED);
            bump_cgroup_stat(cgid, CGROUP_STAT_CRED_BLOCKED);
            emit_cred_block_event(ino, cgid, CRED_REASON_WRITE_DENIED);
            return Ok(LSM_DENY);
        }

        // Allowed — this cgroup may read this secret.
        bump_cred_stat(agentcontainer_common::events::STAT_CRED_ALLOWED);
        bump_cgroup_stat(cgid, CGROUP_STAT_CRED_ALLOWED);
        return Ok(LSM_ALLOW);
    }
    // No ACL entry — fall through to general FS enforcement.

    // 2. Check denied inodes (deny list takes priority).
    let denied = unsafe { DENIED_INODES.get(&key) };
    if denied.is_some() {
        bump_fs_stat(agentcontainer_common::events::STAT_FS_BLOCKED);
        bump_cgroup_stat(cgid, CGROUP_STAT_FS_BLOCKED);
        emit_fs_block_event(ino, flags);
        return Ok(LSM_DENY);
    }

    // 3. Check allowed inodes.
    if let Some(perm) = unsafe { ALLOWED_INODES.get(&key) } {
        // Check write permission if file is opened for writing.
        // O_WRONLY=0x01, O_RDWR=0x02, O_CREAT=0o100, O_TRUNC=0o1000, O_APPEND=0o2000
        let write_access = (flags & 0x01) != 0
            || (flags & 0x02) != 0
            || (flags & 0o100) != 0
            || (flags & 0o1000) != 0
            || (flags & 0o2000) != 0;

        if write_access && (*perm & FS_PERM_WRITE) == 0 {
            bump_fs_stat(agentcontainer_common::events::STAT_FS_BLOCKED);
            bump_cgroup_stat(cgid, CGROUP_STAT_FS_BLOCKED);
            emit_fs_block_event(ino, flags);
            return Ok(LSM_DENY);
        }

        bump_fs_stat(agentcontainer_common::events::STAT_FS_ALLOWED);
        bump_cgroup_stat(cgid, CGROUP_STAT_FS_ALLOWED);
        return Ok(LSM_ALLOW);
    }

    // 4. Default deny.
    bump_fs_stat(agentcontainer_common::events::STAT_FS_BLOCKED);
    bump_cgroup_stat(cgid, CGROUP_STAT_FS_BLOCKED);
    emit_fs_block_event(ino, flags);
    Ok(LSM_DENY)
}
