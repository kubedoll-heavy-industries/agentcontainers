//! cgroup_sock_addr connect4/6 hooks for network egress enforcement.
//!
//! Intercepts outbound TCP/UDP connect() calls and enforces CIDR-based policy:
//!
//! **connect4 (IPv4):**
//!   1. Always allow loopback (127.0.0.0/8).
//!   2. Check cgroup scoping -- skip if not in ENFORCED_CGROUPS.
//!   3. Block explicitly denied CIDRs (BLOCKED_CIDRS_V4 LPM trie).
//!   4. Allow specific port rules (ALLOWED_PORTS hash map).
//!   5. Allow matching CIDRs (ALLOWED_V4 LPM trie).
//!   6. Default deny -- emit event.
//!
//! **connect6 (IPv6):**
//!   1. Always allow loopback (::1).
//!   2. Check cgroup scoping.
//!   3. Handle IPv4-mapped IPv6 (::ffff:x.x.x.x) -- check v4 rules too.
//!   4. Block denied IPv6 CIDRs (BLOCKED_CIDRS_V6).
//!   5. Allow matching IPv6 CIDRs (ALLOWED_V6).
//!   6. Default deny.
//!
//! On BLOCK, emits a NetworkEvent to NET_EVENTS ring buffer for audit logging.
//! Increments per-CPU stats on every decision.

use aya_ebpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
};
use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::SockAddrContext;

use agentcontainer_common::events::{NetworkEvent, STAT_NET_ALLOWED, STAT_NET_BLOCKED};
use agentcontainer_common::helpers::{
    extract_v4_from_mapped, is_loopback_v4, is_loopback_v6, is_v4_mapped_v6,
};
use agentcontainer_common::maps::{ScopedLpmKeyV4, ScopedLpmKeyV6, ScopedPortKeyV4};

use crate::maps::{
    bump_cgroup_stat, ALLOWED_PORTS, ALLOWED_V4, ALLOWED_V6, BLOCKED_CIDRS_V4, BLOCKED_CIDRS_V6,
    CGROUP_STAT_NET_ALLOWED, CGROUP_STAT_NET_BLOCKED, NET_EVENTS, NET_STATS,
};

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

/// Emit a block event for an IPv4 connection to the NET_EVENTS ring buffer.
#[inline(always)]
fn emit_block_event_v4(dst_ip: u32, dst_port: u16, proto: u8, event_type: u32) {
    if let Some(mut entry) = NET_EVENTS.reserve::<NetworkEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;

            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;

            (*ev).event_type = event_type;
            (*ev).verdict = 1; // Block

            (*ev).dst_ip4 = dst_ip;
            (*ev).dst_ip6 = [0, 0, 0, 0];
            (*ev).dst_port = dst_port;
            (*ev).protocol = proto;
            (*ev).ip_version = 4;

            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; 16],
            };
        }
        entry.submit(0);
    }
}

/// Emit a block event for an IPv6 connection to the NET_EVENTS ring buffer.
#[inline(always)]
fn emit_block_event_v6(dst_ip6: [u32; 4], dst_port: u16, proto: u8, event_type: u32) {
    if let Some(mut entry) = NET_EVENTS.reserve::<NetworkEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;

            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;

            (*ev).event_type = event_type;
            (*ev).verdict = 1; // Block

            (*ev).dst_ip4 = 0;
            (*ev).dst_ip6 = dst_ip6;
            (*ev).dst_port = dst_port;
            (*ev).protocol = proto;
            (*ev).ip_version = 6;

            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; 16],
            };
        }
        entry.submit(0);
    }
}

/// Check if the current cgroup is enforced. Returns Some(cgroup_id) if enforcement applies.
#[inline(always)]
fn get_enforced_cgroup() -> Option<u64> {
    crate::maps::enforced_cgroup_for_current()
}

// --- Event type constant ---

const EVENT_NET_CONNECT: u32 = 1; // EventType::NetworkConnect

const CGROUP_PREFIX_BITS: u32 = 64;
const IPV4_PREFIX_BITS: u32 = CGROUP_PREFIX_BITS + 32;
const IPV6_PREFIX_BITS: u32 = CGROUP_PREFIX_BITS + 128;

#[inline(always)]
fn scoped_lpm_v4(cgroup_id: u64, addr: u32) -> Key<ScopedLpmKeyV4> {
    Key::new(
        IPV4_PREFIX_BITS,
        ScopedLpmKeyV4 {
            cgroup_id,
            addr,
            _pad: 0,
        },
    )
}

#[inline(always)]
fn scoped_lpm_v6(cgroup_id: u64, addr: [u32; 4]) -> Key<ScopedLpmKeyV6> {
    Key::new(IPV6_PREFIX_BITS, ScopedLpmKeyV6 { cgroup_id, addr })
}

// ---------------------------------------------------------------------------
// cgroup/connect4 -- intercepts IPv4 connect() syscalls.
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect4)]
pub fn ac_connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Block on BPF errors; cgroup_sock_addr uses 1=allow, 0=deny.
    }
}

fn try_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    let dst: u32 = unsafe { (*ctx.sock_addr).user_ip4 };
    let port: u16 = (u32::from_be(unsafe { (*ctx.sock_addr).user_port }) >> 16) as u16;
    let proto: u8 = unsafe { (*ctx.sock_addr).protocol } as u8;

    // 1. Always allow loopback (127.0.0.0/8).
    if is_loopback_v4(dst) {
        bump_stat(STAT_NET_ALLOWED);
        return Ok(1);
    }

    // 2. Check cgroup scoping -- skip enforcement for non-registered cgroups.
    let cgroup_id = match get_enforced_cgroup() {
        Some(id) => id,
        None => return Ok(1),
    };

    // 3. Check blocked CIDRs (deny list takes priority).
    let lpm = Key::new(32, dst);
    if unsafe { BLOCKED_CIDRS_V4.get(&lpm) }.is_some() {
        bump_stat(STAT_NET_BLOCKED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
        emit_block_event_v4(dst, port, proto, EVENT_NET_CONNECT);
        return Ok(0);
    }

    // 4. Check allowed ports (specific IP+port+protocol tuples).
    let pk = ScopedPortKeyV4 {
        cgroup_id,
        ip: dst,
        port,
        protocol: proto,
        _pad: 0,
    };
    if unsafe { ALLOWED_PORTS.get(&pk) }.is_some() {
        bump_stat(STAT_NET_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_ALLOWED);
        return Ok(1);
    }

    // 5. Check allowed CIDRs (LPM trie longest prefix match).
    let scoped_lpm = scoped_lpm_v4(cgroup_id, dst);
    if unsafe { ALLOWED_V4.get(&scoped_lpm) }.is_some() {
        bump_stat(STAT_NET_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_ALLOWED);
        return Ok(1);
    }

    // 6. Default deny.
    bump_stat(STAT_NET_BLOCKED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
    emit_block_event_v4(dst, port, proto, EVENT_NET_CONNECT);
    Ok(0)
}

// ---------------------------------------------------------------------------
// cgroup/connect6 -- intercepts IPv6 connect() syscalls.
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect6)]
pub fn ac_connect6(ctx: SockAddrContext) -> i32 {
    match try_connect6(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Block on BPF errors; cgroup_sock_addr uses 1=allow, 0=deny.
    }
}

fn try_connect6(ctx: &SockAddrContext) -> Result<i32, i64> {
    let dst6: [u32; 4] = unsafe {
        [
            (*ctx.sock_addr).user_ip6[0],
            (*ctx.sock_addr).user_ip6[1],
            (*ctx.sock_addr).user_ip6[2],
            (*ctx.sock_addr).user_ip6[3],
        ]
    };
    let port: u16 = (u32::from_be(unsafe { (*ctx.sock_addr).user_port }) >> 16) as u16;
    let proto: u8 = unsafe { (*ctx.sock_addr).protocol } as u8;

    // 1. Always allow loopback (::1).
    if is_loopback_v6(&dst6) {
        bump_stat(STAT_NET_ALLOWED);
        return Ok(1);
    }

    // 2. Check cgroup scoping -- skip enforcement for non-registered cgroups.
    let cgroup_id = match get_enforced_cgroup() {
        Some(id) => id,
        None => return Ok(1),
    };

    // 3. Check for IPv4-mapped IPv6 (::ffff:x.x.x.x) -- also enforce
    //    IPv4 blocked/allowed rules to prevent bypass via dual-stack (RT-C3).
    if is_v4_mapped_v6(&dst6) {
        let v4addr = extract_v4_from_mapped(&dst6);
        let lpm4 = Key::new(32, v4addr);

        // Check IPv4 blocked CIDRs (metadata endpoint, etc.).
        if unsafe { BLOCKED_CIDRS_V4.get(&lpm4) }.is_some() {
            bump_stat(STAT_NET_BLOCKED);
            bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
            emit_block_event_v6(dst6, port, proto, EVENT_NET_CONNECT);
            return Ok(0);
        }

        // Check IPv4 allowed ports.
        let pk = ScopedPortKeyV4 {
            cgroup_id,
            ip: v4addr,
            port,
            protocol: proto,
            _pad: 0,
        };
        if unsafe { ALLOWED_PORTS.get(&pk) }.is_some() {
            bump_stat(STAT_NET_ALLOWED);
            bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_ALLOWED);
            return Ok(1);
        }

        // Check IPv4 allowed CIDRs.
        let scoped_lpm4 = scoped_lpm_v4(cgroup_id, v4addr);
        if unsafe { ALLOWED_V4.get(&scoped_lpm4) }.is_some() {
            bump_stat(STAT_NET_ALLOWED);
            bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_ALLOWED);
            return Ok(1);
        }

        // Fall through to IPv6 checks -- the IPv6 blocked/allowed maps
        // also have ::ffff-mapped entries for defense-in-depth.
    }

    // 4. Check IPv6 blocked CIDRs.
    let lpm6 = Key::new(128, dst6);
    if unsafe { BLOCKED_CIDRS_V6.get(&lpm6) }.is_some() {
        bump_stat(STAT_NET_BLOCKED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
        emit_block_event_v6(dst6, port, proto, EVENT_NET_CONNECT);
        return Ok(0);
    }

    // 5. Check IPv6 allowed CIDRs.
    let scoped_lpm6 = scoped_lpm_v6(cgroup_id, dst6);
    if unsafe { ALLOWED_V6.get(&scoped_lpm6) }.is_some() {
        bump_stat(STAT_NET_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_ALLOWED);
        return Ok(1);
    }

    // 6. Default deny.
    bump_stat(STAT_NET_BLOCKED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
    emit_block_event_v6(dst6, port, proto, EVENT_NET_CONNECT);
    Ok(0)
}
