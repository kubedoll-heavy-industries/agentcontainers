//! Event pipeline: broadcast bus between BPF ring buffers and gRPC StreamEvents.
//!
//! [`EventBus`] receives raw enforcement events from ring buffer readers, translates
//! them into [`EnforcementEvent`]s, and fans them out to per-container gRPC subscribers
//! via a tokio broadcast channel.
//!
//! [`ContainerRegistry`] maps BPF cgroup IDs to container ID strings so ring buffer
//! readers can resolve the container for each raw event.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, warn};

use crate::policy::{EnforcementEvent, EventDomain, EventVerdict};
use agentcontainer_common::events::{self as bpf};

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

/// Capacity of the broadcast channel backing the event bus.
const BROADCAST_CAPACITY: usize = 4096;

/// Fan-out event bus backed by a tokio broadcast channel.
///
/// Publishers call [`EventBus::publish`] to send an event to every subscriber.
/// Subscribers call [`EventBus::subscribe`] with an optional container filter
/// and receive events on an mpsc channel.
#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<EnforcementEvent>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// Create a new event bus with the default broadcast capacity (4096).
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self { tx }
    }

    /// Publish an event to all subscribers. Logs a warning if there are no
    /// active receivers (rather than failing).
    pub fn publish(&self, event: EnforcementEvent) {
        match self.tx.send(event) {
            Ok(_) => {}
            Err(_) => {
                // No active receivers — this is normal during startup/shutdown.
                debug!("event bus: no active receivers, event dropped");
            }
        }
    }

    /// Subscribe to events, optionally filtered by `container_id`.
    ///
    /// If `container_id` is empty, the subscriber receives all events.
    /// Returns an mpsc receiver; the filtering task runs in the background
    /// and stops when the receiver is dropped.
    pub fn subscribe(&self, container_id: &str) -> mpsc::Receiver<EnforcementEvent> {
        let mut rx = self.tx.subscribe();
        let (tx, out) = mpsc::channel::<EnforcementEvent>(256);
        let filter = container_id.to_string();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if (filter.is_empty() || event.container_id == filter)
                            && tx.send(event).await.is_err()
                        {
                            // mpsc receiver dropped — subscriber gone.
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(lagged = n, "event subscriber lagged, {} events dropped", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        out
    }
}

// ---------------------------------------------------------------------------
// ContainerRegistry
// ---------------------------------------------------------------------------

/// Maps BPF cgroup IDs (u64) to container ID strings.
///
/// Thread-safe via `RwLock`; reads vastly outnumber writes so the lock is
/// not contended on the hot path.
#[derive(Clone, Default)]
pub struct ContainerRegistry {
    inner: Arc<RwLock<HashMap<u64, String>>>,
}

impl ContainerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a cgroup → container mapping.
    pub async fn register_container(&self, cgroup_id: u64, container_id: String) {
        self.inner.write().await.insert(cgroup_id, container_id);
    }

    /// Remove a cgroup → container mapping. Returns the container ID if it existed.
    pub async fn unregister_container(&self, cgroup_id: u64) -> Option<String> {
        self.inner.write().await.remove(&cgroup_id)
    }

    /// Look up the container ID for a cgroup ID.
    pub async fn lookup(&self, cgroup_id: u64) -> Option<String> {
        self.inner.read().await.get(&cgroup_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Event parsing — raw BPF structs → EnforcementEvent
// ---------------------------------------------------------------------------

/// Extract a null-terminated UTF-8 (or lossy) string from a fixed-size byte buffer.
fn bytes_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Parse a raw BPF [`bpf::NetworkEvent`] into an [`EnforcementEvent`].
pub fn parse_network_event(raw: &bpf::NetworkEvent, container_id: &str) -> EnforcementEvent {
    let verdict = match raw.verdict {
        1 => EventVerdict::Block,
        _ => EventVerdict::Allow,
    };

    let mut details = HashMap::new();
    details.insert("protocol".into(), format!("{}", raw.protocol));
    details.insert("dst_port".into(), format!("{}", raw.dst_port));

    if raw.ip_version == 4 {
        // BPF stores IPv4 as network-order (big-endian) bytes in a u32.
        let ip = std::net::Ipv4Addr::from(raw.dst_ip4.to_be_bytes());
        details.insert("dst_ip".into(), ip.to_string());
    } else if raw.ip_version == 6 {
        // BPF stores IPv6 as 16 network-order bytes cast to [u32; 4].
        let mut octets = [0u8; 16];
        for (i, word) in raw.dst_ip6.iter().enumerate() {
            let bytes = word.to_be_bytes();
            octets[i * 4..i * 4 + 4].copy_from_slice(&bytes);
        }
        let ip = std::net::Ipv6Addr::from(octets);
        details.insert("dst_ip".into(), ip.to_string());
    }

    EnforcementEvent {
        timestamp_ns: raw.timestamp_ns,
        container_id: container_id.to_string(),
        domain: EventDomain::Network,
        verdict,
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        details,
    }
}

/// Parse a raw BPF [`bpf::FsEvent`] into an [`EnforcementEvent`].
pub fn parse_fs_event(raw: &bpf::FsEvent, container_id: &str) -> EnforcementEvent {
    let verdict = match raw.verdict {
        1 => EventVerdict::Block,
        _ => EventVerdict::Allow,
    };

    let mut details = HashMap::new();
    details.insert("inode".into(), format!("{}", raw.inode));
    details.insert("flags".into(), format!("{:#x}", raw.flags));

    EnforcementEvent {
        timestamp_ns: raw.timestamp_ns,
        container_id: container_id.to_string(),
        domain: EventDomain::Filesystem,
        verdict,
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        details,
    }
}

/// Parse a raw BPF [`bpf::ExecEvent`] into an [`EnforcementEvent`].
pub fn parse_exec_event(raw: &bpf::ExecEvent, container_id: &str) -> EnforcementEvent {
    let verdict = match raw.verdict {
        1 => EventVerdict::Block,
        _ => EventVerdict::Allow,
    };

    let binary = bytes_to_string(&raw.binary);
    let mut details = HashMap::new();
    details.insert("inode".into(), format!("{}", raw.inode));
    details.insert("binary".into(), binary);

    EnforcementEvent {
        timestamp_ns: raw.timestamp_ns,
        container_id: container_id.to_string(),
        domain: EventDomain::Process,
        verdict,
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        details,
    }
}

/// Parse a raw BPF [`bpf::CredEvent`] into an [`EnforcementEvent`].
///
/// Credential events are emitted when a secret file access is evaluated by the
/// LSM `file_open` hook. The reason field encodes why access was blocked
/// (no ACL entry, TTL expired, or write denied).
pub fn parse_cred_event(raw: &bpf::CredEvent, container_id: &str) -> EnforcementEvent {
    let verdict = match raw.verdict {
        1 => EventVerdict::Block,
        _ => EventVerdict::Allow,
    };

    let reason_str = match raw.reason {
        bpf::CRED_REASON_TTL_EXPIRED => "ttl_expired",
        bpf::CRED_REASON_WRITE_DENIED => "write_denied",
        _ => "no_acl",
    };

    let mut details = HashMap::new();
    details.insert("inode".into(), format!("{}", raw.inode));
    details.insert("cgroup_id".into(), format!("{}", raw.cgroup_id));
    details.insert("reason".into(), reason_str.into());

    EnforcementEvent {
        timestamp_ns: raw.timestamp_ns,
        container_id: container_id.to_string(),
        domain: EventDomain::Credential,
        verdict,
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        details,
    }
}

/// Parse a raw BPF [`bpf::BindEvent`] into an [`EnforcementEvent`].
pub fn parse_bind_event(raw: &bpf::BindEvent, container_id: &str) -> EnforcementEvent {
    let verdict = match raw.verdict {
        1 => EventVerdict::Block,
        _ => EventVerdict::Allow,
    };

    let proto_str = match raw.protocol {
        6 => "tcp",
        17 => "udp",
        _ => "unknown",
    };

    let mut details = HashMap::new();
    details.insert("port".into(), format!("{}", raw.port));
    details.insert("protocol".into(), proto_str.into());

    EnforcementEvent {
        timestamp_ns: raw.timestamp_ns,
        container_id: container_id.to_string(),
        domain: EventDomain::Bind,
        verdict,
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        details,
    }
}

/// Parse a raw BPF [`bpf::ReverseShellEvent`] into an [`EnforcementEvent`].
pub fn parse_reverse_shell_event(
    raw: &bpf::ReverseShellEvent,
    container_id: &str,
) -> EnforcementEvent {
    let verdict = match raw.verdict {
        1 => EventVerdict::Block,
        _ => EventVerdict::Allow,
    };

    let mut details = HashMap::new();
    details.insert("oldfd".into(), format!("{}", raw.oldfd));
    details.insert("newfd".into(), format!("{}", raw.newfd));

    EnforcementEvent {
        timestamp_ns: raw.timestamp_ns,
        container_id: container_id.to_string(),
        domain: EventDomain::ReverseShell,
        verdict,
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        details,
    }
}

/// Local mirror of the BPF-side MemfdEvent struct.
///
/// This struct is defined locally in the BPF program (`agentcontainer-ebpf`)
/// rather than in `agentcontainer-common` because it is a detection-only event
/// with no shared map key/value usage. We duplicate the layout here so the
/// ring buffer reader can deserialize it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemfdEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub comm: [u8; bpf::COMM_MAX],
}

/// Parse a raw [`MemfdEvent`] into an [`EnforcementEvent`].
pub fn parse_memfd_event(raw: &MemfdEvent, container_id: &str) -> EnforcementEvent {
    let verdict = match raw.verdict {
        1 => EventVerdict::Block,
        _ => EventVerdict::Allow,
    };

    EnforcementEvent {
        timestamp_ns: raw.timestamp_ns,
        container_id: container_id.to_string(),
        domain: EventDomain::Memfd,
        verdict,
        pid: raw.pid,
        comm: bytes_to_string(&raw.comm),
        details: HashMap::new(),
    }
}

/// Parse a raw BPF [`bpf::DnsEvent`] into an [`EnforcementEvent`].
///
/// DNS events are observation-only (always Allow). The domain name is
/// represented by its 128-bit SipHash digest; userspace correlates with
/// pre-computed hashes of tracked domains.
pub fn parse_dns_event(raw: &bpf::DnsEvent, container_id: &str) -> EnforcementEvent {
    let mut details = HashMap::new();

    // Domain hash as hex string.
    let hash_hex: String = raw.domain_hash.iter().map(|b| format!("{b:02x}")).collect();
    details.insert("domain_hash".into(), hash_hex);

    // Record type.
    let record_type = match raw.record_type {
        28 => "AAAA",
        _ => "A",
    };
    details.insert("record_type".into(), record_type.into());

    // TTL.
    details.insert("ttl".into(), format!("{}", raw.ttl));

    // Resolved IP (if non-zero).
    if raw.addr_v4 != [0; 4] {
        let ip = std::net::Ipv4Addr::from(raw.addr_v4);
        details.insert("resolved_ip".into(), ip.to_string());
    }
    if raw.addr_v6 != [0; 16] {
        let ip = std::net::Ipv6Addr::from(raw.addr_v6);
        details.insert("resolved_ip".into(), ip.to_string());
    }

    EnforcementEvent {
        timestamp_ns: raw.timestamp_ns,
        container_id: container_id.to_string(),
        domain: EventDomain::Network,
        verdict: EventVerdict::Allow,
        pid: raw.pid,
        comm: String::new(),
        details,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use agentcontainer_common::events::{COMM_MAX, PATH_MAX};

    /// Helper: create a zeroed NetworkEvent and set common fields.
    fn sample_network_event() -> bpf::NetworkEvent {
        let mut comm = [0u8; COMM_MAX];
        comm[..4].copy_from_slice(b"curl");

        bpf::NetworkEvent {
            timestamp_ns: 1_000_000,
            pid: 42,
            uid: 1000,
            event_type: bpf::EventType::NetworkConnect as u32,
            verdict: bpf::Verdict::Block as u32,
            // BPF stores 10.0.0.1 in network byte order (big-endian).
            dst_ip4: 0x0a000001,
            dst_ip6: [0; 4],
            dst_port: 443,
            protocol: 6, // TCP
            ip_version: 4,
            comm,
        }
    }

    fn sample_fs_event() -> bpf::FsEvent {
        let mut comm = [0u8; COMM_MAX];
        comm[..3].copy_from_slice(b"cat");

        bpf::FsEvent {
            timestamp_ns: 2_000_000,
            pid: 100,
            uid: 1000,
            event_type: bpf::EventType::FsOpen as u32,
            verdict: bpf::Verdict::Allow as u32,
            inode: 12345,
            flags: 0x0002,
            _pad: 0,
            comm,
        }
    }

    fn sample_exec_event() -> bpf::ExecEvent {
        let mut comm = [0u8; COMM_MAX];
        comm[..4].copy_from_slice(b"bash");
        let mut binary = [0u8; PATH_MAX];
        binary[..9].copy_from_slice(b"/bin/bash");

        bpf::ExecEvent {
            timestamp_ns: 3_000_000,
            pid: 200,
            uid: 0,
            event_type: bpf::EventType::ProcessExec as u32,
            verdict: bpf::Verdict::Block as u32,
            cgroup_id: 0,
            inode: 99999,
            comm,
            binary,
        }
    }

    // --- Parse tests ---

    #[test]
    fn test_parse_network_event_ipv4() {
        let raw = sample_network_event();
        let ev = parse_network_event(&raw, "ctr-abc");

        assert_eq!(ev.container_id, "ctr-abc");
        assert_eq!(ev.domain, EventDomain::Network);
        assert_eq!(ev.verdict, EventVerdict::Block);
        assert_eq!(ev.pid, 42);
        assert_eq!(ev.comm, "curl");
        assert_eq!(ev.timestamp_ns, 1_000_000);

        assert_eq!(ev.details.get("dst_ip").unwrap(), "10.0.0.1");
        assert_eq!(ev.details.get("dst_port").unwrap(), "443");
    }

    #[test]
    fn test_parse_network_event_ipv6() {
        let mut raw = sample_network_event();
        raw.ip_version = 6;
        // ::1 — 15 zero bytes then 0x01, stored as big-endian u32 words.
        raw.dst_ip6 = [0, 0, 0, 0x00000001];

        let ev = parse_network_event(&raw, "ctr-v6");
        assert_eq!(ev.details.get("dst_ip").unwrap(), "::1");
    }

    #[test]
    fn test_parse_fs_event() {
        let raw = sample_fs_event();
        let ev = parse_fs_event(&raw, "ctr-fs");

        assert_eq!(ev.domain, EventDomain::Filesystem);
        assert_eq!(ev.verdict, EventVerdict::Allow);
        assert_eq!(ev.pid, 100);
        assert_eq!(ev.comm, "cat");

        assert_eq!(ev.details.get("inode").unwrap(), "12345");
    }

    #[test]
    fn test_parse_exec_event() {
        let raw = sample_exec_event();
        let ev = parse_exec_event(&raw, "ctr-exec");

        assert_eq!(ev.domain, EventDomain::Process);
        assert_eq!(ev.verdict, EventVerdict::Block);
        assert_eq!(ev.pid, 200);
        assert_eq!(ev.comm, "bash");

        assert_eq!(ev.details.get("binary").unwrap(), "/bin/bash");
    }

    #[test]
    fn test_parse_dns_event() {
        let raw = bpf::DnsEvent {
            timestamp_ns: 5_000_000,
            pid: 300,
            uid: 1000,
            event_type: bpf::EventType::DnsResponse as u32,
            ttl: 3600,
            domain_hash: [
                0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ],
            addr_v4: [93, 184, 216, 34], // 93.184.216.34
            addr_v6: [0; 16],
            record_type: 1, // A
            _pad: [0; 3],
        };

        let ev = parse_dns_event(&raw, "ctr-dns");

        assert_eq!(ev.container_id, "ctr-dns");
        assert_eq!(ev.domain, EventDomain::Network);
        assert_eq!(ev.verdict, EventVerdict::Allow);
        assert_eq!(ev.pid, 300);
        assert_eq!(ev.timestamp_ns, 5_000_000);

        assert_eq!(
            ev.details.get("domain_hash").unwrap(),
            "abcdef0123456789fedcba9876543210"
        );
        assert_eq!(ev.details.get("record_type").unwrap(), "A");
        assert_eq!(ev.details.get("ttl").unwrap(), "3600");
        assert_eq!(ev.details.get("resolved_ip").unwrap(), "93.184.216.34");
    }

    fn sample_cred_event() -> bpf::CredEvent {
        let mut comm = [0u8; COMM_MAX];
        comm[..6].copy_from_slice(b"python");

        bpf::CredEvent {
            timestamp_ns: 4_000_000,
            pid: 150,
            uid: 1000,
            event_type: bpf::EventType::CredentialAccess as u32,
            verdict: bpf::Verdict::Block as u32,
            inode: 55555,
            cgroup_id: 99999,
            reason: bpf::CRED_REASON_TTL_EXPIRED,
            _pad: 0,
            comm,
        }
    }

    #[test]
    fn test_parse_cred_event_blocked_ttl_expired() {
        let raw = sample_cred_event();
        let ev = parse_cred_event(&raw, "ctr-cred");

        assert_eq!(ev.container_id, "ctr-cred");
        assert_eq!(ev.domain, EventDomain::Credential);
        assert_eq!(ev.verdict, EventVerdict::Block);
        assert_eq!(ev.pid, 150);
        assert_eq!(ev.comm, "python");
        assert_eq!(ev.timestamp_ns, 4_000_000);

        assert_eq!(ev.details.get("inode").unwrap(), "55555");
        assert_eq!(ev.details.get("cgroup_id").unwrap(), "99999");
        assert_eq!(ev.details.get("reason").unwrap(), "ttl_expired");
    }

    #[test]
    fn test_parse_cred_event_blocked_no_acl() {
        let mut raw = sample_cred_event();
        raw.reason = bpf::CRED_REASON_NO_ACL;
        raw.verdict = bpf::Verdict::Block as u32;

        let ev = parse_cred_event(&raw, "ctr-cred2");
        assert_eq!(ev.verdict, EventVerdict::Block);
        assert_eq!(ev.details.get("reason").unwrap(), "no_acl");
    }

    #[test]
    fn test_parse_cred_event_blocked_write_denied() {
        let mut raw = sample_cred_event();
        raw.reason = bpf::CRED_REASON_WRITE_DENIED;
        raw.verdict = bpf::Verdict::Block as u32;

        let ev = parse_cred_event(&raw, "ctr-cred3");
        assert_eq!(ev.verdict, EventVerdict::Block);
        assert_eq!(ev.details.get("reason").unwrap(), "write_denied");
    }

    #[test]
    fn test_parse_cred_event_allowed() {
        let mut raw = sample_cred_event();
        raw.verdict = bpf::Verdict::Allow as u32;

        let ev = parse_cred_event(&raw, "ctr-cred4");
        assert_eq!(ev.verdict, EventVerdict::Allow);
        assert_eq!(ev.domain, EventDomain::Credential);
    }

    // --- EventBus tests ---

    #[tokio::test]
    async fn test_event_bus_publish_subscribe_roundtrip() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe("");

        let event = EnforcementEvent {
            timestamp_ns: 42,
            container_id: "ctr-1".into(),
            domain: EventDomain::Network,
            verdict: EventVerdict::Allow,
            pid: 1,
            comm: "test".into(),
            details: HashMap::new(),
        };

        bus.publish(event.clone());

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out")
            .expect("channel closed");

        assert_eq!(received.container_id, "ctr-1");
        assert_eq!(received.timestamp_ns, 42);
    }

    #[tokio::test]
    async fn test_event_bus_filtered_subscribe() {
        let bus = EventBus::new();
        let mut rx_a = bus.subscribe("ctr-a");
        let mut rx_b = bus.subscribe("ctr-b");
        let mut rx_all = bus.subscribe("");

        let make_event = |cid: &str, ts: u64| EnforcementEvent {
            timestamp_ns: ts,
            container_id: cid.into(),
            domain: EventDomain::Filesystem,
            verdict: EventVerdict::Block,
            pid: 1,
            comm: "x".into(),
            details: HashMap::new(),
        };

        bus.publish(make_event("ctr-a", 1));
        bus.publish(make_event("ctr-b", 2));
        bus.publish(make_event("ctr-a", 3));

        let timeout = std::time::Duration::from_secs(1);

        // rx_a should get events 1 and 3 (ctr-a only).
        let e1 = tokio::time::timeout(timeout, rx_a.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e1.timestamp_ns, 1);
        let e3 = tokio::time::timeout(timeout, rx_a.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e3.timestamp_ns, 3);

        // rx_b should get event 2 only.
        let e2 = tokio::time::timeout(timeout, rx_b.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(e2.timestamp_ns, 2);

        // rx_all gets all three.
        let ea = tokio::time::timeout(timeout, rx_all.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ea.timestamp_ns, 1);
        let eb = tokio::time::timeout(timeout, rx_all.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(eb.timestamp_ns, 2);
        let ec = tokio::time::timeout(timeout, rx_all.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ec.timestamp_ns, 3);
    }

    #[tokio::test]
    async fn test_event_bus_no_receivers_does_not_panic() {
        let bus = EventBus::new();
        // Publishing with no subscribers should not panic.
        bus.publish(EnforcementEvent {
            timestamp_ns: 0,
            container_id: String::new(),
            domain: EventDomain::Network,
            verdict: EventVerdict::Allow,
            pid: 0,
            comm: String::new(),
            details: HashMap::new(),
        });
    }

    // --- ContainerRegistry tests ---

    #[tokio::test]
    async fn test_container_registry_register_lookup() {
        let reg = ContainerRegistry::new();
        assert!(reg.lookup(100).await.is_none());

        reg.register_container(100, "ctr-abc".into()).await;
        assert_eq!(reg.lookup(100).await.unwrap(), "ctr-abc");
    }

    #[tokio::test]
    async fn test_container_registry_unregister() {
        let reg = ContainerRegistry::new();
        reg.register_container(42, "ctr-x".into()).await;

        let removed = reg.unregister_container(42).await;
        assert_eq!(removed, Some("ctr-x".into()));
        assert!(reg.lookup(42).await.is_none());

        // Double unregister returns None.
        assert!(reg.unregister_container(42).await.is_none());
    }

    // --- bytes_to_string tests ---

    #[test]
    fn test_bytes_to_string_null_terminated() {
        let mut buf = [0u8; 16];
        buf[..5].copy_from_slice(b"hello");
        assert_eq!(bytes_to_string(&buf), "hello");
    }

    #[test]
    fn test_bytes_to_string_full_buffer() {
        let buf = [b'A'; 16];
        assert_eq!(bytes_to_string(&buf), "AAAAAAAAAAAAAAAA");
    }
}
