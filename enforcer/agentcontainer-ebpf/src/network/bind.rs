//! cgroup_sock_addr bind4/6 hooks for listening socket enforcement.
//!
//! Intercepts bind() syscalls and default-denies listening sockets in enforced
//! cgroups unless the port+protocol tuple is in the ALLOWED_BINDS map.
//!
//! **bind4 (IPv4) / bind6 (IPv6):**
//!   1. Check cgroup scoping -- skip if not in ENFORCED_CGROUPS.
//!   2. Allow ephemeral binds (port == 0, used for outbound connections).
//!   3. Look up (port, protocol) in ALLOWED_BINDS.
//!   4. If found, allow + bump stats.
//!   5. If not found, emit BindEvent + bump stats + block.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid, bpf_ktime_get_ns,
};
use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::programs::SockAddrContext;

use agentcontainer_common::events::{BindEvent, COMM_MAX, STAT_BIND_ALLOWED, STAT_BIND_BLOCKED};
use agentcontainer_common::maps::{ScopedBindKey, VERDICT_ALLOW, VERDICT_BLOCK};

use crate::maps::{
    bump_cgroup_stat, ALLOWED_BINDS, BIND_EVENTS, CGROUP_STAT_BIND_ALLOWED,
    CGROUP_STAT_BIND_BLOCKED, ENFORCED_CGROUPS, NET_STATS,
};

// --- Event type constant ---

/// Event type for bind hooks (matches EventType::Bind in userspace).
const EVENT_BIND: u32 = 5;

// --- Inline helpers ---

/// Bump a per-CPU stats counter by index.
#[inline(always)]
fn bump_stat(idx: u32) {
    unsafe {
        if let Some(val) = NET_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

/// Check if the current cgroup is enforced. Returns Some(cgroup_id) if enforcement applies.
#[inline(always)]
fn get_enforced_cgroup() -> Option<u64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_some() {
        Some(cgroup_id)
    } else {
        None
    }
}

/// Emit a bind block event to the BIND_EVENTS ring buffer.
#[inline(always)]
fn emit_bind_event(port: u16, protocol: u8) {
    if let Some(mut buf) = BIND_EVENTS.reserve::<BindEvent>(0) {
        let ev = unsafe { &mut *buf.as_mut_ptr() };
        ev.timestamp_ns = unsafe { bpf_ktime_get_ns() };

        let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
        ev.pid = (pid_tgid >> 32) as u32;

        let uid_gid = unsafe { bpf_get_current_uid_gid() };
        ev.uid = uid_gid as u32;

        ev.event_type = EVENT_BIND;
        ev.verdict = 1; // Block

        ev.port = port;
        ev.protocol = protocol;
        ev._pad = 0;

        ev.comm = match unsafe { bpf_get_current_comm() } {
            Ok(c) => c,
            Err(_) => [0u8; COMM_MAX],
        };

        buf.submit(0);
    }
}

// --- Shared bind logic ---

/// Core bind enforcement logic shared by bind4 and bind6.
///
/// Reads the port from the sock_addr context and checks the ALLOWED_BINDS map.
/// Ephemeral binds (port 0) are always allowed since they are used for outbound
/// connections, not listening sockets.
#[inline(always)]
fn try_bind(ctx: &SockAddrContext) -> Result<i32, i64> {
    // 1. Check cgroup scoping -- skip enforcement for non-registered cgroups.
    let cgroup_id = match get_enforced_cgroup() {
        Some(id) => id,
        None => return Ok(VERDICT_ALLOW),
    };

    let sock_addr = unsafe { &*ctx.sock_addr };

    // 2. Read port -- user_port is in network byte order (big-endian).
    let port = u16::from_be(sock_addr.user_port as u16);

    // 3. Allow ephemeral port binds (port == 0 means kernel picks a port).
    if port == 0 {
        bump_stat(STAT_BIND_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_BIND_ALLOWED);
        return Ok(VERDICT_ALLOW);
    }

    // 4. Check ALLOWED_BINDS map for this cgroup and (port, protocol).
    let protocol = sock_addr.protocol as u8;
    let key = ScopedBindKey {
        cgroup_id,
        port,
        protocol,
        _pad: 0,
    };
    if unsafe { ALLOWED_BINDS.get(&key) }.is_some() {
        bump_stat(STAT_BIND_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_BIND_ALLOWED);
        return Ok(VERDICT_ALLOW);
    }

    // 5. Default deny -- emit event and block.
    bump_stat(STAT_BIND_BLOCKED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_BIND_BLOCKED);
    emit_bind_event(port, protocol);
    Ok(VERDICT_BLOCK)
}

// ---------------------------------------------------------------------------
// cgroup/bind4 -- intercepts IPv4 bind() syscalls.
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(bind4)]
pub fn ac_bind4(ctx: SockAddrContext) -> i32 {
    match try_bind(&ctx) {
        Ok(ret) => ret,
        Err(_) => VERDICT_BLOCK, // Block on BPF errors.
    }
}

// ---------------------------------------------------------------------------
// cgroup/bind6 -- intercepts IPv6 bind() syscalls.
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(bind6)]
pub fn ac_bind6(ctx: SockAddrContext) -> i32 {
    match try_bind(&ctx) {
        Ok(ret) => ret,
        Err(_) => VERDICT_BLOCK, // Block on BPF errors.
    }
}
