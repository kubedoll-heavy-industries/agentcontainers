use agentcontainer_common::events::*;

#[test]
fn test_event_type_values() {
    assert_eq!(EventType::NetworkConnect as u32, 1);
    assert_eq!(EventType::DnsResponse as u32, 2);
    assert_eq!(EventType::FsOpen as u32, 3);
    assert_eq!(EventType::ProcessExec as u32, 4);
    assert_eq!(EventType::CredentialAccess as u32, 5);
}

#[test]
fn test_verdict_values() {
    assert_eq!(Verdict::Allow as u32, 0);
    assert_eq!(Verdict::Block as u32, 1);
}

#[test]
fn test_dns_event_has_domain_hash() {
    let hash_bytes = 0xDEADBEEF_CAFEBABE_12345678_9ABCDEF0u128.to_ne_bytes();
    let evt = DnsEvent {
        timestamp_ns: 0,
        pid: 0,
        uid: 0,
        event_type: EventType::DnsResponse as u32,
        ttl: 300,
        domain_hash: hash_bytes,
        addr_v4: [0u8; 4],
        addr_v6: [0u8; 16],
        record_type: 1,
        _pad: [0u8; 3],
    };
    assert_eq!(evt.ttl, 300);
    assert_eq!(evt.domain_hash, hash_bytes);
}

#[test]
fn test_dns_event_size_reduced() {
    // DnsEvent with [u8; 16] hash: 8+4+4+4+4+16+4+16+1+3 = 64 bytes.
    // Much smaller than old 304-byte version with [u8; 256] domain.
    let size = core::mem::size_of::<DnsEvent>();
    assert_eq!(
        size, 64,
        "DnsEvent should be exactly 64 bytes, got {}",
        size
    );
}

#[test]
fn test_exec_event_has_binary_path() {
    assert_eq!(PATH_MAX, 256);
    let evt = ExecEvent {
        timestamp_ns: 0,
        pid: 0,
        uid: 0,
        event_type: EventType::ProcessExec as u32,
        verdict: Verdict::Block as u32,
        cgroup_id: 0,
        inode: 42,
        comm: [0u8; COMM_MAX],
        binary: [0u8; PATH_MAX],
    };
    assert_eq!(evt.inode, 42);
}

#[test]
fn test_stat_key_values() {
    assert_eq!(STAT_NET_ALLOWED, 0);
    assert_eq!(STAT_NET_BLOCKED, 1);
    assert_eq!(STAT_FS_ALLOWED, 2);
    assert_eq!(STAT_FS_BLOCKED, 3);
    assert_eq!(STAT_PROC_ALLOWED, 4);
    assert_eq!(STAT_PROC_BLOCKED, 5);
}

#[test]
fn test_dns_constants() {
    assert_eq!(DNS_PORT, 53);
    assert_eq!(DNS_HEADER_SIZE, 12);
    assert_eq!(DNS_TYPE_A, 1);
    assert_eq!(DNS_TYPE_AAAA, 28);
    assert_eq!(DNS_CLASS_IN, 1);
    assert_eq!(DNS_FLAG_QR, 0x8000);
    assert_eq!(MAX_COMPRESSION_JUMPS, 8);
}
