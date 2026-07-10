//! Policy manager trait — the contract between the gRPC service and BPF enforcement.
//!
//! On Linux, this is implemented by [`BpfPolicyManager`] which translates high-level
//! policy requests into BPF map operations via aya. On other platforms (and in tests),
//! a [`StubPolicyManager`] returns success without doing anything.
//!
//! Policy data types (NetworkPolicy, EgressRule, etc.) are defined in `agentcontainer-common`
//! and re-exported here to avoid duplication.

use std::collections::HashMap;

use tonic::async_trait;

// Re-export policy data types from agentcontainer-common (the single source of truth).
pub use agentcontainer_common::policy::{
    BindPolicy, BindRule, CredentialPolicy, DenySetPolicy, EgressRule, FilesystemPolicy,
    NetworkPolicy, ProcessPolicy, ResolvedDenySetEntry, ResolvedDenySetTransition,
    ReverseShellConfig, SecretAcl,
};

/// Per-container enforcement context returned by [`PolicyManager::register`].
#[derive(Debug, Clone)]
pub struct ContainerHandle {
    pub container_id: String,
    pub cgroup_id: u64,
}

/// Enforcement statistics for a container.
#[derive(Debug, Clone, Default)]
pub struct EnforcementStats {
    pub network_allowed: u64,
    pub network_blocked: u64,
    pub filesystem_allowed: u64,
    pub filesystem_blocked: u64,
    pub process_allowed: u64,
    pub process_blocked: u64,
    pub credential_allowed: u64,
    pub credential_blocked: u64,
}

/// Enforcement event emitted from BPF ring buffers.
#[derive(Debug, Clone)]
pub struct EnforcementEvent {
    pub timestamp_ns: u64,
    pub container_id: String,
    pub domain: EventDomain,
    pub verdict: EventVerdict,
    pub pid: u32,
    pub comm: String,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDomain {
    Network,
    Filesystem,
    Process,
    Credential,
    Bind,
    ReverseShell,
    Memfd,
}

impl EventDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Filesystem => "filesystem",
            Self::Process => "process",
            Self::Credential => "credential",
            Self::Bind => "bind",
            Self::ReverseShell => "reverse_shell",
            Self::Memfd => "memfd",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventVerdict {
    Allow,
    Block,
}

impl EventVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

/// The core abstraction between the gRPC service and BPF enforcement.
///
/// All methods are async and fallible. On Linux, the real implementation
/// translates these calls into BPF map operations. On macOS/tests, the
/// stub returns success.
#[async_trait]
pub trait PolicyManager: Send + Sync + 'static {
    /// Register a container for enforcement. Resolves the cgroup path to an ID
    /// and inserts it into the ENFORCED_CGROUPS map.
    async fn register(
        &self,
        container_id: &str,
        cgroup_path: &str,
    ) -> anyhow::Result<ContainerHandle>;

    /// Unregister a container. Removes all map entries for this cgroup.
    async fn unregister(&self, container_id: &str) -> anyhow::Result<()>;

    /// Apply network enforcement policy for a container.
    async fn apply_network(&self, container_id: &str, policy: &NetworkPolicy)
        -> anyhow::Result<()>;

    /// Apply filesystem enforcement policy for a container.
    async fn apply_filesystem(
        &self,
        container_id: &str,
        policy: &FilesystemPolicy,
    ) -> anyhow::Result<()>;

    /// Apply process enforcement policy for a container.
    async fn apply_process(&self, container_id: &str, policy: &ProcessPolicy)
        -> anyhow::Result<()>;

    /// Apply credential enforcement policy (Phase 6).
    async fn apply_credential(
        &self,
        container_id: &str,
        policy: &CredentialPolicy,
    ) -> anyhow::Result<()>;

    /// Apply deny-set process-tree policy for a container.
    async fn apply_deny_set(
        &self,
        container_id: &str,
        policy: &DenySetPolicy,
    ) -> anyhow::Result<()>;

    /// Update a single deny-set entry (add one binary to an existing set).
    async fn update_deny_set(
        &self,
        container_id: &str,
        entry: &ResolvedDenySetEntry,
    ) -> anyhow::Result<()>;

    /// Apply bind (listen) policy for a container.
    async fn apply_bind(&self, container_id: &str, policy: &BindPolicy) -> anyhow::Result<()>;

    /// Configure reverse shell detection mode for a container.
    async fn configure_reverse_shell(
        &self,
        container_id: &str,
        config: &ReverseShellConfig,
    ) -> anyhow::Result<()>;

    /// Get enforcement stats for a container (empty string = aggregate).
    async fn get_stats(&self, container_id: &str) -> anyhow::Result<EnforcementStats>;

    /// Subscribe to enforcement events. Returns a receiver that yields events
    /// for the given container (empty string = all containers).
    async fn subscribe_events(
        &self,
        container_id: &str,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<EnforcementEvent>>;
}

/// Stub policy manager for macOS and tests. All operations succeed as no-ops.
pub struct StubPolicyManager;

#[async_trait]
impl PolicyManager for StubPolicyManager {
    async fn register(
        &self,
        container_id: &str,
        _cgroup_path: &str,
    ) -> anyhow::Result<ContainerHandle> {
        tracing::warn!("stub policy manager: register is a no-op");
        Ok(ContainerHandle {
            container_id: container_id.to_string(),
            cgroup_id: 0,
        })
    }

    async fn unregister(&self, _container_id: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_network(
        &self,
        _container_id: &str,
        _policy: &NetworkPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_filesystem(
        &self,
        _container_id: &str,
        _policy: &FilesystemPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_process(
        &self,
        _container_id: &str,
        _policy: &ProcessPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_credential(
        &self,
        _container_id: &str,
        _policy: &CredentialPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_deny_set(
        &self,
        _container_id: &str,
        _policy: &DenySetPolicy,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn update_deny_set(
        &self,
        _container_id: &str,
        _entry: &ResolvedDenySetEntry,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn apply_bind(&self, _container_id: &str, _policy: &BindPolicy) -> anyhow::Result<()> {
        Ok(())
    }

    async fn configure_reverse_shell(
        &self,
        _container_id: &str,
        _config: &ReverseShellConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn get_stats(&self, _container_id: &str) -> anyhow::Result<EnforcementStats> {
        Ok(EnforcementStats::default())
    }

    /// Returns a receiver whose sender is immediately dropped, causing the stream to
    /// end immediately. This is intentional for the stub — no events are ever produced.
    /// A real implementation would hold the sender and feed events from BPF ring buffers.
    async fn subscribe_events(
        &self,
        _container_id: &str,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<EnforcementEvent>> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(rx)
    }
}
