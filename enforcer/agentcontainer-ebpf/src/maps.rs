//! BPF map definitions shared across all programs.
//!
//! Maps are the communication channel between userspace and BPF programs.
//! Userspace populates policy maps; BPF programs read them on each hook.
//! Event ring buffers flow in the opposite direction.
//!
//! Map layout must match the C definitions in internal/ebpf/bpf/headers/.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LpmTrie, PerCpuArray, PerCpuHashMap, RingBuf};

use agentcontainer_common::maps::{
    CgroupStats, DenySetKey, ScopedBindKey, ScopedFsInodeKey, ScopedLpmKeyV4, ScopedLpmKeyV6,
    ScopedPortKeyV4, SecretAclKey, SecretAclValue,
};
use agentcontainer_common::siphash::SipHashKey;

// --- Cgroup scoping ---

/// Cgroup IDs that should have enforcement applied.
/// All BPF programs check this map first and skip non-registered cgroups.
#[map]
pub static ENFORCED_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

/// Ancestor-walk depth bound. The kernel cgroup tree is shallow in practice; the
/// bound keeps the walk verifier-friendly.
pub const MAX_CGROUP_DEPTH: i32 = 16;

/// The enforced cgroup (id + its policy flags) governing the current task: its
/// own cgroup if directly registered, otherwise the nearest ancestor present in
/// `ENFORCED_CGROUPS` (SUBTREE match). Returning the registered ancestor means a
/// task moved into a descendant cgroup — `mkdir <enforced>/x; echo $$ >
/// x/cgroup.procs`, the Escape-the-Box T11 vector — stays governed by that
/// ancestor's policy/stats/inode maps instead of escaping enforcement. `None`
/// when neither the task nor any ancestor is enforced.
///
/// Perf: the fast path is one lookup for a directly-registered cgroup (the
/// normal container case). Only tasks NOT directly enforced pay the bounded
/// ancestor walk — including unenforced host processes on the system-wide LSM
/// hooks.
#[inline(always)]
pub fn enforced_cgroup_flags_for_current() -> Option<(u64, u8)> {
    let cgid = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    if let Some(&flags) = unsafe { ENFORCED_CGROUPS.get(&cgid) } {
        return Some((cgid, flags));
    }
    // Subtree walk: root (level 0) → self. `bpf_get_current_ancestor_cgroup_id`
    // returns 0 past the task's own depth, so break there.
    for level in 0..MAX_CGROUP_DEPTH {
        let id = unsafe { aya_ebpf::helpers::gen::bpf_get_current_ancestor_cgroup_id(level) };
        if id == 0 {
            break;
        }
        if let Some(&flags) = unsafe { ENFORCED_CGROUPS.get(&id) } {
            return Some((id, flags));
        }
    }
    None
}

/// Id-only [`enforced_cgroup_flags_for_current`] for callers that don't read the
/// per-cgroup policy flags (the egress, bind, process, and file hooks).
#[inline(always)]
pub fn enforced_cgroup_for_current() -> Option<u64> {
    enforced_cgroup_flags_for_current().map(|(id, _)| id)
}

// --- Network maps ---

/// Per-cgroup IPv4 CIDRs that are permitted (LPM trie longest prefix match).
/// Prefix length includes the 64-bit cgroup ID plus IPv4 prefix bits.
#[map]
pub static ALLOWED_V4: LpmTrie<ScopedLpmKeyV4, u8> = LpmTrie::with_max_entries(4096, 0);

/// Per-cgroup IPv6 CIDRs that are permitted.
/// Prefix length includes the 64-bit cgroup ID plus IPv6 prefix bits.
#[map]
pub static ALLOWED_V6: LpmTrie<ScopedLpmKeyV6, u8> = LpmTrie::with_max_entries(4096, 0);

/// IPv4 CIDRs that are always denied (e.g., cloud metadata endpoints).
/// Checked BEFORE the allow lists.
#[map]
pub static BLOCKED_CIDRS_V4: LpmTrie<u32, u8> = LpmTrie::with_max_entries(256, 0);

/// IPv6 CIDRs that are always denied.
#[map]
pub static BLOCKED_CIDRS_V6: LpmTrie<[u32; 4], u8> = LpmTrie::with_max_entries(256, 0);

/// Per-cgroup IPv4 IP+port+protocol tuples that are explicitly permitted.
/// Checked after blocked CIDRs but before broad allowed CIDRs.
#[map]
pub static ALLOWED_PORTS: HashMap<ScopedPortKeyV4, u8> = HashMap::with_max_entries(1024, 0);

/// Ring buffer for network enforcement events.
#[map]
pub static NET_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU stats counters for network enforcement.
#[map]
pub static NET_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

// --- DNS maps ---

/// SipHash-2-4 key shared between BPF and userspace.
/// Single entry (index 0). Userspace writes the key at enforcer startup;
/// BPF programs read it to hash domain names identically.
#[map]
pub static SIPHASH_KEY: Array<SipHashKey> = Array::with_max_entries(1, 0);

/// Set of tracked domain hashes. Userspace inserts SipHash-128 digests of
/// domains it cares about (from the network policy allowed_hosts list).
/// BPF DNS parser hashes each response domain and only emits a ring buffer
/// event if the hash is found in this map — unrelated DNS traffic is dropped
/// silently, reducing ring buffer bandwidth.
#[map]
pub static TRACKED_DOMAINS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(4096, 0);

/// Ring buffer for DNS response events.
#[map]
pub static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// --- Filesystem maps ---

/// Allowed inodes with permission bits (read/write).
#[map]
pub static ALLOWED_INODES: HashMap<ScopedFsInodeKey, u8> = HashMap::with_max_entries(4096, 0);

/// Denied inodes (always blocked).
#[map]
pub static DENIED_INODES: HashMap<ScopedFsInodeKey, u8> = HashMap::with_max_entries(4096, 0);

/// Ring buffer for filesystem enforcement events.
#[map]
pub static FS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU stats counters for filesystem enforcement.
#[map]
pub static FS_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

// --- Process maps ---

/// Allowed executable inodes (binary allowlist).
/// Uses ScopedFsInodeKey since exec inodes have the same layout.
#[map]
pub static ALLOWED_EXECS: HashMap<ScopedFsInodeKey, u8> = HashMap::with_max_entries(4096, 0);

/// Ring buffer for process enforcement events.
#[map]
pub static PROC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU stats counters for process enforcement.
#[map]
pub static PROC_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

// --- Credential maps ---

/// Per-cgroup secret file ACLs for credential enforcement.
/// Key includes (inode, dev, cgroup_id) so ACLs are scoped per-container.
#[map]
pub static SECRET_ACLS: HashMap<SecretAclKey, SecretAclValue> = HashMap::with_max_entries(1024, 0);

/// Ring buffer for credential enforcement events.
#[map]
pub static CRED_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Per-CPU stats counters for credential enforcement.
#[map]
pub static CRED_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

// --- Process deny-set maps ---

/// Per-process deny-set membership (pid → deny_set_id).
#[map]
pub static PROC_DENY_SETS: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

/// Deny-set policy: (deny_set_id, inode, dev) → blocked.
#[map]
pub static DENY_SET_POLICY: HashMap<DenySetKey, u8> = HashMap::with_max_entries(16384, 0);

/// Deny-set transitions: (deny_set_id, inode, dev) → new deny_set_id.
#[map]
pub static DENY_SET_TRANSITIONS: HashMap<DenySetKey, u32> = HashMap::with_max_entries(4096, 0);

// --- Bind maps ---

/// Allowed bind ports (port + protocol).
#[map]
pub static ALLOWED_BINDS: HashMap<ScopedBindKey, u8> = HashMap::with_max_entries(256, 0);

/// Ring buffer for bind enforcement events.
#[map]
pub static BIND_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// --- Reverse shell detection ---

/// Mode flag for reverse shell detection (index 0: 0=disabled, 1=enabled).
#[map]
pub static REVERSE_SHELL_MODE: Array<u8> = Array::with_max_entries(1, 0);

/// Ring buffer for reverse shell detection events.
#[map]
pub static REVERSE_SHELL_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// --- Memfd blocking ---

/// Ring buffer for memfd blocking events.
#[map]
pub static MEMFD_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// --- Per-cgroup statistics ---

/// Per-cgroup enforcement statistics (per-CPU hash map keyed by cgroup_id).
/// BPF programs increment the relevant counter in the current CPU's entry.
/// Userspace sums across CPUs to get per-container totals.
#[map]
pub static CGROUP_STATS: PerCpuHashMap<u64, CgroupStats> = PerCpuHashMap::with_max_entries(256, 0);

// --- Per-cgroup stats helpers ---

/// Offsets into CgroupStats fields (in units of u64).
pub const CGROUP_STAT_NET_ALLOWED: usize = 0;
pub const CGROUP_STAT_NET_BLOCKED: usize = 1;
pub const CGROUP_STAT_FS_ALLOWED: usize = 2;
pub const CGROUP_STAT_FS_BLOCKED: usize = 3;
pub const CGROUP_STAT_PROC_ALLOWED: usize = 4;
pub const CGROUP_STAT_PROC_BLOCKED: usize = 5;
pub const CGROUP_STAT_CRED_ALLOWED: usize = 6;
pub const CGROUP_STAT_CRED_BLOCKED: usize = 7;
pub const CGROUP_STAT_BIND_ALLOWED: usize = 8;
pub const CGROUP_STAT_BIND_BLOCKED: usize = 9;
pub const CGROUP_STAT_DENYSET_ALLOWED: usize = 10;
pub const CGROUP_STAT_DENYSET_BLOCKED: usize = 11;

/// Increment a specific counter in the per-cgroup stats map for the given cgroup_id.
///
/// `field_offset` is the byte offset of the u64 counter within `CgroupStats`.
/// If the cgroup doesn't have an entry yet, one is created with zeroed counters.
#[inline(always)]
pub fn bump_cgroup_stat(cgroup_id: u64, field_offset: usize) {
    unsafe {
        // Try to get existing entry first.
        if let Some(stats) = CGROUP_STATS.get_ptr_mut(&cgroup_id) {
            let base = stats as *mut u8;
            let counter = base.add(field_offset * 8) as *mut u64;
            *counter += 1;
        } else {
            // No entry yet — insert a new one with this counter set to 1.
            let mut stats = CgroupStats {
                network_allowed: 0,
                network_blocked: 0,
                filesystem_allowed: 0,
                filesystem_blocked: 0,
                process_allowed: 0,
                process_blocked: 0,
                credential_allowed: 0,
                credential_blocked: 0,
                bind_allowed: 0,
                bind_blocked: 0,
                denyset_allowed: 0,
                denyset_blocked: 0,
            };
            let base = &mut stats as *mut CgroupStats as *mut u8;
            let counter = base.add(field_offset * 8) as *mut u64;
            *counter = 1;
            let _ = CGROUP_STATS.insert(&cgroup_id, &stats, 0);
        }
    }
}
