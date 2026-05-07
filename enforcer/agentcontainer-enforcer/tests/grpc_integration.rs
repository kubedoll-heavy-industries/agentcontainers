//! End-to-end gRPC integration tests for the agentcontainer-enforcer.
//!
//! These tests build and run the production Docker image, then exercise every
//! gRPC RPC from the host against real BPF enforcement inside the container.
//!
//! Unlike `bpf_integration.rs` (which requires `#[cfg(target_os = "linux")]`),
//! these tests run from any platform with Docker available (macOS via Docker
//! Desktop, Linux CI). BPF runs inside the container, not the test process.
//!
//! Requirements:
//! - Docker daemon running
//! - Ability to run privileged containers (Docker Desktop or Linux with perms)
//!
//! Run:
//!   cargo test --test grpc_integration -- --nocapture
//!   cargo test --test grpc_integration test_health -- --nocapture  # smoke test

use std::sync::Once;
use std::time::Duration;

use serial_test::serial;
use testcontainers::core::{IntoContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

use agentcontainer_enforcer::grpc::proto::enforcer_client::EnforcerClient;
use agentcontainer_enforcer::grpc::proto::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build the enforcer Docker image once per test run.
static BUILD_IMAGE: Once = Once::new();

fn ensure_image_built() {
    BUILD_IMAGE.call_once(|| {
        let context = format!("{}/..", env!("CARGO_MANIFEST_DIR"));
        let status = std::process::Command::new("docker")
            .args([
                "build",
                "-t",
                "agentcontainer-enforcer-test:latest",
                "-f",
                "Dockerfile",
                ".",
            ])
            .current_dir(&context)
            .status()
            .expect("docker build command failed to execute");
        assert!(
            status.success(),
            "docker build failed with status: {status}"
        );
    });
}

/// Start a fresh enforcer container and return the container + gRPC URI.
async fn start_enforcer() -> (testcontainers::ContainerAsync<GenericImage>, String) {
    ensure_image_built();

    let container = GenericImage::new("agentcontainer-enforcer-test", "latest")
        .with_exposed_port(50051.tcp())
        .with_wait_for(WaitFor::message_on_stdout("starting gRPC TCP server"))
        .with_privileged(true)
        .with_mount(Mount::bind_mount("/sys/fs/cgroup", "/sys/fs/cgroup"))
        .with_mount(Mount::bind_mount("/sys/fs/bpf", "/sys/fs/bpf"))
        .with_mount(Mount::bind_mount("/sys/kernel/btf", "/sys/kernel/btf"))
        .start()
        .await
        .expect("failed to start enforcer container");

    let port = container
        .get_host_port_ipv4(50051)
        .await
        .expect("failed to get mapped port");
    let uri = format!("http://127.0.0.1:{port}");

    (container, uri)
}

/// Connect to the enforcer gRPC server with retries.
async fn connect_with_retry(uri: &str) -> EnforcerClient<tonic::transport::Channel> {
    let mut last_err = None;
    for _ in 0..20 {
        match EnforcerClient::connect(uri.to_string()).await {
            Ok(client) => return client,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    panic!(
        "failed to connect to enforcer at {uri} after retries: {}",
        last_err.unwrap()
    );
}

/// A cgroup path guaranteed to exist inside the container.
const CONTAINER_CGROUP_PATH: &str = "/sys/fs/cgroup";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn test_health_check_serving() {
    let (_container, uri) = start_enforcer().await;

    let channel = tonic::transport::Channel::from_shared(uri)
        .expect("invalid URI")
        .connect()
        .await
        .expect("channel connect failed");

    let mut client = tonic_health::pb::health_client::HealthClient::new(channel);

    let resp = client
        .check(tonic_health::pb::HealthCheckRequest {
            service: "agentcontainers.enforcer.v1.Enforcer".into(),
        })
        .await
        .expect("health check failed")
        .into_inner();

    assert_eq!(
        resp.status,
        tonic_health::pb::health_check_response::ServingStatus::Serving as i32,
        "enforcer service should be SERVING"
    );
}

#[tokio::test]
#[serial]
async fn test_register_container() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    let resp = client
        .register_container(RegisterContainerRequest {
            container_id: "test-ctr-1".into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register_container failed")
        .into_inner();

    assert!(
        resp.cgroup_id > 0,
        "cgroup_id should be non-zero for a real cgroup, got: {}",
        resp.cgroup_id
    );
}

#[tokio::test]
#[serial]
async fn test_register_unregister_roundtrip() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    // Register.
    let resp = client
        .register_container(RegisterContainerRequest {
            container_id: "test-roundtrip".into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register failed")
        .into_inner();
    assert!(resp.cgroup_id > 0);

    // Unregister.
    client
        .unregister_container(UnregisterContainerRequest {
            container_id: "test-roundtrip".into(),
        })
        .await
        .expect("unregister failed");

    // Idempotent unregister — should not error.
    client
        .unregister_container(UnregisterContainerRequest {
            container_id: "test-roundtrip".into(),
        })
        .await
        .expect("idempotent unregister should succeed");
}

#[tokio::test]
#[serial]
async fn test_apply_network_policy() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    // Register first.
    client
        .register_container(RegisterContainerRequest {
            container_id: "test-net".into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register failed");

    let resp = client
        .apply_network_policy(NetworkPolicyRequest {
            container_id: "test-net".into(),
            allowed_hosts: vec!["api.example.com".into(), "cdn.example.com".into()],
            egress_rules: vec![EgressRule {
                host: "db.internal".into(),
                port: 5432,
                protocol: "tcp".into(),
            }],
            dns_servers: vec!["8.8.8.8".into()],
        })
        .await
        .expect("apply_network_policy failed")
        .into_inner();

    assert!(
        resp.success,
        "network policy should succeed: {}",
        resp.error
    );
}

#[tokio::test]
#[serial]
async fn test_apply_filesystem_policy() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    client
        .register_container(RegisterContainerRequest {
            container_id: "test-fs".into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register failed");

    let resp = client
        .apply_filesystem_policy(FilesystemPolicyRequest {
            container_id: "test-fs".into(),
            read_paths: vec!["/etc".into(), "/usr/lib".into()],
            write_paths: vec!["/tmp".into(), "/workspace".into()],
            deny_paths: vec!["/etc/shadow".into(), "/root".into()],
        })
        .await
        .expect("apply_filesystem_policy failed")
        .into_inner();

    assert!(
        resp.success,
        "filesystem policy should succeed: {}",
        resp.error
    );
}

#[tokio::test]
#[serial]
async fn test_apply_process_policy() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    client
        .register_container(RegisterContainerRequest {
            container_id: "test-proc".into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register failed");

    let resp = client
        .apply_process_policy(ProcessPolicyRequest {
            container_id: "test-proc".into(),
            allowed_binaries: vec!["/bin/sh".into(), "/usr/bin/node".into()],
        })
        .await
        .expect("apply_process_policy failed")
        .into_inner();

    assert!(
        resp.success,
        "process policy should succeed: {}",
        resp.error
    );
}

#[tokio::test]
#[serial]
async fn test_apply_credential_policy() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    client
        .register_container(RegisterContainerRequest {
            container_id: "test-cred".into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register failed");

    let resp = client
        .apply_credential_policy(CredentialPolicyRequest {
            container_id: "test-cred".into(),
            secret_acls: vec![SecretAcl {
                path: "/run/secrets/api_key".into(),
                allowed_tools: vec!["mcp-github".into()],
                ttl_seconds: 3600,
            }],
        })
        .await
        .expect("apply_credential_policy failed")
        .into_inner();

    assert!(
        resp.success,
        "credential policy should succeed: {}",
        resp.error
    );
}

#[tokio::test]
#[serial]
async fn test_get_stats() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    client
        .register_container(RegisterContainerRequest {
            container_id: "test-stats".into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register failed");

    let resp = client
        .get_stats(GetStatsRequest {
            container_id: "test-stats".into(),
        })
        .await
        .expect("get_stats failed")
        .into_inner();

    // Fresh container should have zeroed counters.
    assert_eq!(resp.network_allowed, 0);
    assert_eq!(resp.network_blocked, 0);
    assert_eq!(resp.filesystem_allowed, 0);
    assert_eq!(resp.filesystem_blocked, 0);
    assert_eq!(resp.process_allowed, 0);
    assert_eq!(resp.process_blocked, 0);
}

#[tokio::test]
#[serial]
async fn test_stream_events_connects() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    client
        .register_container(RegisterContainerRequest {
            container_id: "test-events".into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register failed");

    // Open the streaming RPC — should connect without error.
    let resp = client
        .stream_events(StreamEventsRequest {
            container_id: "test-events".into(),
        })
        .await;

    assert!(
        resp.is_ok(),
        "stream_events should connect: {:?}",
        resp.err()
    );

    // We don't expect events without triggering enforcement, so just verify
    // the stream is established and a short read times out (no events yet).
    let mut stream = resp.unwrap().into_inner();
    let next = tokio::time::timeout(Duration::from_millis(500), stream.message()).await;

    match next {
        Ok(Ok(None)) => {}    // Stream ended cleanly.
        Err(_) => {}          // Timeout — no events, which is expected.
        Ok(Ok(Some(_))) => {} // Got an event — fine, BPF may emit on attach.
        Ok(Err(e)) => panic!("stream error: {e}"),
    }
}

#[tokio::test]
#[serial]
async fn test_apply_unregistered_fails() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    // Apply network policy to a container that was never registered.
    let resp = client
        .apply_network_policy(NetworkPolicyRequest {
            container_id: "never-registered".into(),
            allowed_hosts: vec!["example.com".into()],
            egress_rules: vec![],
            dns_servers: vec![],
        })
        .await
        .expect("RPC should return a response, not a transport error")
        .into_inner();

    assert!(!resp.success, "apply to unregistered container should fail");
    assert!(
        resp.error.contains("not registered"),
        "error should mention 'not registered', got: {}",
        resp.error
    );
}

#[tokio::test]
#[serial]
async fn test_invalid_cgroup_fails() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    // Register with a cgroup path that doesn't exist inside the container.
    let result = client
        .register_container(RegisterContainerRequest {
            container_id: "test-bad-cgroup".into(),
            cgroup_path: "/sys/fs/cgroup/this/path/does/not/exist".into(),
            init_pid: 1,
        })
        .await;

    // The server should return a gRPC error (Internal) because stat() fails.
    assert!(result.is_err(), "register with invalid cgroup should fail");
}

#[tokio::test]
#[serial]
async fn test_port_out_of_range() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    let resp = client
        .apply_network_policy(NetworkPolicyRequest {
            container_id: "test-port-range".into(),
            allowed_hosts: vec![],
            egress_rules: vec![EgressRule {
                host: "example.com".into(),
                port: 70000, // exceeds u16 max
                protocol: "tcp".into(),
            }],
            dns_servers: vec![],
        })
        .await
        .expect("RPC should return a response")
        .into_inner();

    assert!(!resp.success, "port out of range should fail");
    assert!(
        resp.error.contains("port out of range"),
        "error should mention 'port out of range', got: {}",
        resp.error
    );
}

#[tokio::test]
#[serial]
async fn test_full_lifecycle() {
    let (_container, uri) = start_enforcer().await;
    let mut client = connect_with_retry(&uri).await;

    let container_id = "test-lifecycle";

    // 1. Register.
    let reg = client
        .register_container(RegisterContainerRequest {
            container_id: container_id.into(),
            cgroup_path: CONTAINER_CGROUP_PATH.into(),
            init_pid: 1,
        })
        .await
        .expect("register failed")
        .into_inner();
    assert!(reg.cgroup_id > 0, "cgroup_id should be non-zero");

    // 2. Apply all policy types.
    let net_resp = client
        .apply_network_policy(NetworkPolicyRequest {
            container_id: container_id.into(),
            allowed_hosts: vec!["api.example.com".into()],
            egress_rules: vec![EgressRule {
                host: "db.internal".into(),
                port: 5432,
                protocol: "tcp".into(),
            }],
            dns_servers: vec!["8.8.8.8".into()],
        })
        .await
        .expect("network policy failed")
        .into_inner();
    assert!(net_resp.success, "network: {}", net_resp.error);

    let fs_resp = client
        .apply_filesystem_policy(FilesystemPolicyRequest {
            container_id: container_id.into(),
            read_paths: vec!["/etc".into()],
            write_paths: vec!["/tmp".into()],
            deny_paths: vec!["/etc/shadow".into()],
        })
        .await
        .expect("filesystem policy failed")
        .into_inner();
    assert!(fs_resp.success, "filesystem: {}", fs_resp.error);

    let proc_resp = client
        .apply_process_policy(ProcessPolicyRequest {
            container_id: container_id.into(),
            allowed_binaries: vec!["/bin/sh".into()],
        })
        .await
        .expect("process policy failed")
        .into_inner();
    assert!(proc_resp.success, "process: {}", proc_resp.error);

    let cred_resp = client
        .apply_credential_policy(CredentialPolicyRequest {
            container_id: container_id.into(),
            secret_acls: vec![SecretAcl {
                path: "/run/secrets/token".into(),
                allowed_tools: vec!["curl".into()],
                ttl_seconds: 300,
            }],
        })
        .await
        .expect("credential policy failed")
        .into_inner();
    assert!(cred_resp.success, "credential: {}", cred_resp.error);

    // 3. Get stats.
    let stats = client
        .get_stats(GetStatsRequest {
            container_id: container_id.into(),
        })
        .await
        .expect("get_stats failed")
        .into_inner();
    // Counters should be zero (no real traffic in this test).
    assert_eq!(stats.network_allowed, 0);
    assert_eq!(stats.network_blocked, 0);

    // 4. Open event stream (just verify it connects).
    let stream_resp = client
        .stream_events(StreamEventsRequest {
            container_id: container_id.into(),
        })
        .await;
    assert!(stream_resp.is_ok(), "stream_events should connect");
    drop(stream_resp);

    // 5. Unregister.
    client
        .unregister_container(UnregisterContainerRequest {
            container_id: container_id.into(),
        })
        .await
        .expect("unregister failed");

    // 6. Verify cleanup: applying policy to unregistered container fails.
    let after_unreg = client
        .apply_network_policy(NetworkPolicyRequest {
            container_id: container_id.into(),
            allowed_hosts: vec!["should.fail".into()],
            egress_rules: vec![],
            dns_servers: vec![],
        })
        .await
        .expect("RPC should return a response")
        .into_inner();

    assert!(!after_unreg.success, "policy after unregister should fail");
    assert!(
        after_unreg.error.contains("not registered"),
        "error should mention 'not registered', got: {}",
        after_unreg.error
    );
}
