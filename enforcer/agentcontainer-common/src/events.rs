//! Event types emitted by BPF programs to userspace via ring buffers.

/// Maximum length of a binary path in exec events.
pub const PATH_MAX: usize = 256;

/// Maximum length of a comm (command name) field.
pub const COMM_MAX: usize = 16;

/// Event types emitted by BPF programs.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    NetworkConnect = 1,
    DnsResponse = 2,
    FsOpen = 3,
    ProcessExec = 4,
    CredentialAccess = 5,
    DenySetViolation = 6,
    BindBlocked = 7,
    ReverseShellDetected = 8,
    MemfdBlocked = 9,
}

/// Verdict for an enforcement decision.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow = 0,
    Block = 1,
}

/// Event emitted by network enforcement BPF programs (connect/sendmsg hooks).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub dst_ip4: u32,
    pub dst_ip6: [u32; 4],
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_version: u8,
    pub comm: [u8; COMM_MAX],
}

/// Event emitted by the DNS ingress parser.
///
/// Contains a keyed SipHash-2-4 128-bit digest of the normalized domain name.
/// Userspace pre-computes hashes of tracked domains using the same key (from
/// the SIPHASH_KEY BPF map) and matches on `domain_hash`.
///
/// This replaces the previous 256-byte domain copy approach. With 128-bit
/// keyed hashes, birthday collision probability is ~2^-64 — negligible.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub ttl: u32,
    /// SipHash-2-4 128-bit digest of the lowercased, dot-separated domain name.
    /// Stored as [u8; 16] (native-endian) to avoid u128 alignment padding in repr(C).
    pub domain_hash: [u8; 16],
    /// Resolved IPv4 address (if A record). Zero if not applicable.
    pub addr_v4: [u8; 4],
    /// Resolved IPv6 address (if AAAA record). Zero if not applicable.
    pub addr_v6: [u8; 16],
    /// DNS record type (1 = A, 28 = AAAA).
    pub record_type: u8,
    pub _pad: [u8; 3],
}

/// Event emitted by filesystem enforcement.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub inode: u64,
    pub flags: u32,
    pub _pad: u32,
    pub comm: [u8; COMM_MAX],
}

/// Event emitted by process enforcement.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    /// Cgroup (container) the exec was authorized in — scopes the audit trail.
    pub cgroup_id: u64,
    pub inode: u64,
    pub comm: [u8; COMM_MAX],
    pub binary: [u8; PATH_MAX],
}

/// Credential enforcement event emitted when a secret file access is blocked.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CredEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub inode: u64,
    pub cgroup_id: u64,
    /// Reason for the block: 0 = no ACL entry, 1 = TTL expired, 2 = write denied.
    pub reason: u32,
    pub _pad: u32,
    pub comm: [u8; COMM_MAX],
}

/// Event emitted when a deny-set policy blocks an exec.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DenySetEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub deny_set_id: u32,
    pub parent_inode: u64,
    pub child_inode: u64,
    pub comm: [u8; COMM_MAX],
}

/// Event emitted when a bind is blocked.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BindEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
    pub comm: [u8; COMM_MAX],
}

/// Event emitted when a reverse shell is detected.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReverseShellEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub oldfd: u32,
    pub newfd: u32,
    pub comm: [u8; COMM_MAX],
}

/// Credential block reason constants.
pub const CRED_REASON_NO_ACL: u32 = 0;
pub const CRED_REASON_TTL_EXPIRED: u32 = 1;
pub const CRED_REASON_WRITE_DENIED: u32 = 2;

// --- Stats keys (per-CPU array indices) ---

pub const STAT_NET_ALLOWED: u32 = 0;
pub const STAT_NET_BLOCKED: u32 = 1;
pub const STAT_FS_ALLOWED: u32 = 2;
pub const STAT_FS_BLOCKED: u32 = 3;
pub const STAT_PROC_ALLOWED: u32 = 4;
pub const STAT_PROC_BLOCKED: u32 = 5;
pub const STAT_CRED_ALLOWED: u32 = 6;
pub const STAT_CRED_BLOCKED: u32 = 7;
pub const STAT_BIND_ALLOWED: u32 = 8;
pub const STAT_BIND_BLOCKED: u32 = 9;
pub const STAT_DENYSET_ALLOWED: u32 = 10;
pub const STAT_DENYSET_BLOCKED: u32 = 11;

// --- Event type constants ---

pub const EVENT_CRED_OPEN: u32 = 5; // Must match EventType::CredentialAccess

// --- DNS constants ---

pub const DNS_PORT: u16 = 53;
pub const DNS_HEADER_SIZE: usize = 12;
pub const DNS_MAX_LABELS: usize = 8;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_FLAG_QR: u16 = 0x8000;

/// Maximum compression pointer jumps before aborting DNS parsing (fixes H1).
pub const MAX_COMPRESSION_JUMPS: u32 = 8;
