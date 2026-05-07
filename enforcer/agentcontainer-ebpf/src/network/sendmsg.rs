//! cgroup_sock_addr sendmsg4/6 hooks for UDP egress enforcement.
//!
//! These hooks intercept outbound UDP sendto()/sendmsg() calls that bypass
//! connect(). This closes the critical UDP bypass (security review finding C2).
//!
//! Policy check order (identical to connect4/6):
//!   1. Always allow loopback.
//!   2. Check cgroup scoping -- skip enforcement for non-registered cgroups.
//!   3. Block explicitly denied CIDRs.
//!   4. Allow if destination matches an allowed port rule.
//!   5. Allow if destination matches an allowed CIDR (LPM trie).
//!   6. Default deny.
//!
//! For sendmsg6, IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are handled
//! by checking the embedded IPv4 address against IPv4 policy maps (RT-C3).

use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::SockAddrContext;

use agentcontainer_common::events::{
    NetworkEvent, Verdict, COMM_MAX, STAT_NET_ALLOWED, STAT_NET_BLOCKED,
};
use agentcontainer_common::helpers::{
    extract_v4_from_mapped, is_loopback_v4, is_loopback_v6, is_v4_mapped_v6, ntohl,
};
use agentcontainer_common::maps::{
    ScopedLpmKeyV4, ScopedLpmKeyV6, ScopedPortKeyV4, VERDICT_ALLOW, VERDICT_BLOCK,
};

use crate::maps::{
    bump_cgroup_stat, ALLOWED_PORTS, ALLOWED_V4, ALLOWED_V6, BLOCKED_CIDRS_V4, BLOCKED_CIDRS_V6,
    CGROUP_STAT_NET_ALLOWED, CGROUP_STAT_NET_BLOCKED, ENFORCED_CGROUPS, NET_EVENTS, NET_STATS,
};

use aya_ebpf::helpers::bpf_get_current_cgroup_id;

/// Event type for sendmsg hooks (matches C AC_EVENT_NET_SENDMSG = 2).
const EVENT_NET_SENDMSG: u32 = 2;

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

/// Get the cgroup_id if the current cgroup is enforced, or None.
#[inline(always)]
fn get_enforced_cgroup() -> Option<u64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_some() {
        Some(cgroup_id)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Stats helper
// ---------------------------------------------------------------------------

#[inline(always)]
fn bump_stat(idx: u32) {
    unsafe {
        if let Some(val) = NET_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Event emission helpers
// ---------------------------------------------------------------------------

#[inline(always)]
fn emit_block_event_v4(dst_ip: u32, dst_port: u16, proto: u8) {
    if let Some(mut buf) = NET_EVENTS.reserve::<NetworkEvent>(0) {
        let ev = unsafe { &mut *buf.as_mut_ptr() };
        ev.timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

        let pid_tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
        ev.pid = (pid_tgid >> 32) as u32;

        let uid_gid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() };
        ev.uid = uid_gid as u32;

        ev.event_type = EVENT_NET_SENDMSG;
        ev.verdict = Verdict::Block as u32;

        ev.dst_ip4 = dst_ip;
        ev.dst_ip6 = [0, 0, 0, 0];
        ev.dst_port = dst_port;
        ev.protocol = proto;
        ev.ip_version = 4;

        ev.comm = match unsafe { aya_ebpf::helpers::bpf_get_current_comm() } {
            Ok(c) => c,
            Err(_) => [0u8; COMM_MAX],
        };

        buf.submit(0);
    }
}

#[inline(always)]
fn emit_block_event_v6(dst_ip6: &[u32; 4], dst_port: u16, proto: u8) {
    if let Some(mut buf) = NET_EVENTS.reserve::<NetworkEvent>(0) {
        let ev = unsafe { &mut *buf.as_mut_ptr() };
        ev.timestamp_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

        let pid_tgid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() };
        ev.pid = (pid_tgid >> 32) as u32;

        let uid_gid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() };
        ev.uid = uid_gid as u32;

        ev.event_type = EVENT_NET_SENDMSG;
        ev.verdict = Verdict::Block as u32;

        ev.dst_ip4 = 0;
        ev.dst_ip6 = *dst_ip6;
        ev.dst_port = dst_port;
        ev.protocol = proto;
        ev.ip_version = 6;

        ev.comm = match unsafe { aya_ebpf::helpers::bpf_get_current_comm() } {
            Ok(c) => c,
            Err(_) => [0u8; COMM_MAX],
        };

        buf.submit(0);
    }
}

// ---------------------------------------------------------------------------
// cgroup/sendmsg4 -- intercepts IPv4 UDP sendto()/sendmsg().
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(sendmsg4)]
pub fn ac_sendmsg4(ctx: SockAddrContext) -> i32 {
    match try_sendmsg4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Block on BPF errors; cgroup_sock_addr uses 1=allow, 0=deny.
    }
}

#[inline(always)]
fn try_sendmsg4(ctx: &SockAddrContext) -> Result<i32, i64> {
    let sock_addr = unsafe { &*ctx.sock_addr };
    let dst = sock_addr.user_ip4;
    let port = (ntohl(sock_addr.user_port) >> 16) as u16;
    let proto = sock_addr.protocol as u8;

    // 1. Always allow loopback (127.0.0.0/8).
    if is_loopback_v4(dst) {
        bump_stat(STAT_NET_ALLOWED);
        return Ok(VERDICT_ALLOW);
    }

    // 2. Check cgroup scoping -- skip enforcement for non-registered cgroups.
    let cgroup_id = match get_enforced_cgroup() {
        Some(id) => id,
        None => return Ok(VERDICT_ALLOW),
    };

    // 3. Check blocked CIDRs (deny list takes priority).
    let lpm = Key::new(32, dst);
    if unsafe { BLOCKED_CIDRS_V4.get(&lpm) }.is_some() {
        bump_stat(STAT_NET_BLOCKED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
        emit_block_event_v4(dst, port, proto);
        return Ok(VERDICT_BLOCK);
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
        return Ok(VERDICT_ALLOW);
    }

    // 5. Check allowed CIDRs (LPM trie longest prefix match).
    let scoped_lpm = scoped_lpm_v4(cgroup_id, dst);
    if unsafe { ALLOWED_V4.get(&scoped_lpm) }.is_some() {
        bump_stat(STAT_NET_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_ALLOWED);
        return Ok(VERDICT_ALLOW);
    }

    // 6. Default deny.
    bump_stat(STAT_NET_BLOCKED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
    emit_block_event_v4(dst, port, proto);
    Ok(VERDICT_BLOCK)
}

// ---------------------------------------------------------------------------
// cgroup/sendmsg6 -- intercepts IPv6 UDP sendto()/sendmsg().
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(sendmsg6)]
pub fn ac_sendmsg6(ctx: SockAddrContext) -> i32 {
    match try_sendmsg6(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Block on BPF errors; cgroup_sock_addr uses 1=allow, 0=deny.
    }
}

#[inline(always)]
fn try_sendmsg6(ctx: &SockAddrContext) -> Result<i32, i64> {
    let sock_addr = unsafe { &*ctx.sock_addr };
    let dst6: [u32; 4] = [
        sock_addr.user_ip6[0],
        sock_addr.user_ip6[1],
        sock_addr.user_ip6[2],
        sock_addr.user_ip6[3],
    ];
    let port = (ntohl(sock_addr.user_port) >> 16) as u16;
    let proto = sock_addr.protocol as u8;

    // 1. Always allow loopback (::1).
    if is_loopback_v6(&dst6) {
        bump_stat(STAT_NET_ALLOWED);
        return Ok(VERDICT_ALLOW);
    }

    // 2. Check cgroup scoping -- skip enforcement for non-registered cgroups.
    let cgroup_id = match get_enforced_cgroup() {
        Some(id) => id,
        None => return Ok(VERDICT_ALLOW),
    };

    // 3. Check for IPv4-mapped IPv6 -- enforce IPv4 rules too (RT-C3).
    if is_v4_mapped_v6(&dst6) {
        let v4addr = extract_v4_from_mapped(&dst6);
        let lpm4 = Key::new(32, v4addr);

        // 3a. Block if IPv4 address is in blocked CIDRs.
        if unsafe { BLOCKED_CIDRS_V4.get(&lpm4) }.is_some() {
            bump_stat(STAT_NET_BLOCKED);
            bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
            emit_block_event_v6(&dst6, port, proto);
            return Ok(VERDICT_BLOCK);
        }

        // 3b. Allow if IPv4 address matches an allowed port rule.
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
            return Ok(VERDICT_ALLOW);
        }

        // 3c. Allow if IPv4 address matches an allowed CIDR.
        let scoped_lpm4 = scoped_lpm_v4(cgroup_id, v4addr);
        if unsafe { ALLOWED_V4.get(&scoped_lpm4) }.is_some() {
            bump_stat(STAT_NET_ALLOWED);
            bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_ALLOWED);
            return Ok(VERDICT_ALLOW);
        }
    }

    // 4. Check IPv6 blocked CIDRs.
    let lpm = Key::new(128, dst6);
    if unsafe { BLOCKED_CIDRS_V6.get(&lpm) }.is_some() {
        bump_stat(STAT_NET_BLOCKED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
        emit_block_event_v6(&dst6, port, proto);
        return Ok(VERDICT_BLOCK);
    }

    // 5. Check IPv6 allowed CIDRs.
    let scoped_lpm = scoped_lpm_v6(cgroup_id, dst6);
    if unsafe { ALLOWED_V6.get(&scoped_lpm) }.is_some() {
        bump_stat(STAT_NET_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_ALLOWED);
        return Ok(VERDICT_ALLOW);
    }

    // 6. Default deny.
    bump_stat(STAT_NET_BLOCKED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_NET_BLOCKED);
    emit_block_event_v6(&dst6, port, proto);
    Ok(VERDICT_BLOCK)
}
