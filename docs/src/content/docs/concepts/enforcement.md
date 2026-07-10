---
title: Enforcement
description: Defense-in-depth security model with BPF LSM hooks, network enforcement, and credential gating.
---

agentcontainers uses a defense-in-depth approach with multiple enforcement layers. In the current alpha, some layers are fully wired into `agentcontainer run` and others are implemented in the enforcer/runtime but still being integrated across every backend. Treat the enforcer as a fail-closed guardrail when `agent.enforcer.required` is enabled, not as a finished production sandbox.

## Enforcement layers

### Layer 1: Container isolation

Standard OCI container hardening:
- Dropped Linux capabilities (only declared caps retained)
- seccomp syscall filtering
- Read-only root filesystem
- No access to host credential stores

### Layer 2: Network enforcement

BPF cgroup hooks gate network egress at the kernel level when the Rust enforcer sidecar is running:

| Hook | Protocol | Purpose |
|---|---|---|
| `connect4` | TCP (IPv4) | Gate outbound TCP connections |
| `connect6` | TCP (IPv6) | Gate outbound TCP connections |
| `sendmsg4` | UDP (IPv4) | Gate UDP datagram sends |
| `sendmsg6` | UDP (IPv6) | Gate UDP datagram sends |

The alpha enforcer has TCP and UDP hook coverage for IPv4 and IPv6. Docker Sandbox mode also has proxy-based egress enforcement; the BPF path is still being hardened across host and VM backends.

Allowed endpoints are declared in `agent.capabilities.network`:

```jsonc
{
  "agent": {
    "capabilities": {
      "network": {
        "egress": [
          { "host": "api.github.com", "port": 443 },
          { "host": "registry.npmjs.org", "port": 443 }
        ]
      }
    }
  }
}
```

### Layer 3: Filesystem enforcement

The BPF LSM `file_open` hook contains inode-level access-control support:

- **DENIED_INODES**: Explicitly blocked files (e.g., host credential stores)
- **ALLOWED_INODES**: Explicitly permitted files
- **Default deny**: Anything not in the allow list is intended to be blocked when filesystem enforcement is active

Filesystem capabilities are declared in `agent.capabilities.filesystem`:

```jsonc
{
  "agent": {
    "capabilities": {
      "filesystem": {
        "read": ["/workspace/**", "/usr/**"],
        "write": ["/workspace/**", "/tmp/**"],
        "deny": ["/etc/shadow", "/root/.ssh/**"]
      }
    }
  }
}
```

Alpha note: the kernel maps support explicit denied inodes, but the Go policy translator does not yet populate every `filesystem.deny` path into BPF deny maps. Some deny behavior is still enforced by mount filtering and policy resolution before the container starts.

### Layer 4: Process enforcement

The BPF LSM `bprm_check_security` hook validates binary execution against declared shell capabilities when process enforcement is active:

```jsonc
{
  "agent": {
    "capabilities": {
      "shell": {
        "commands": [
          "git",
          "npm",
          "node",
          {
            "binary": "python3",
            "denyArgs": ["-c", "-e"]
          }
        ]
      }
    }
  }
}
```

Interpreter argument controls such as denying `-c` or `-e` are part of the process policy model. Coverage is alpha-quality and should be tested for the specific interpreters you allow.

Alpha note: the current BPF deny-set extension denies whole executable basenames. Argument-level and subcommand-level deny rules remain policy-model features until the enforcer translator and kernel hook are made argv-aware.

### Layer 5: Credential enforcement (CREDLSM)

The BPF LSM `file_open` hook includes a `SECRET_ACLS` map designed to gate per-cgroup access to secret files:

- Each secret file's inode is registered with `(inode, device, cgroup_id)` as the key
- The ACL value includes TTL expiry (`expires_at_ns`) and permission flags
- If a cgroup has no ACL entry for a secret file, access is denied
- If the TTL has expired, access is denied
- Write access to secrets is always denied unless explicitly permitted

Block reasons are tracked:
- **No ACL entry**: The cgroup is not authorized for this secret
- **TTL expired**: The credential has expired and needs rotation
- **Write denied**: Write access to credential files is blocked

Credential events are emitted to a dedicated `CRED_EVENTS` ring buffer when credential enforcement is active.

### Layer 6: Approval broker

The approval broker wraps the container runtime (decorator pattern) and intercepts capability changes. When an agent requests a capability not declared in the original config, the broker:

1. Pauses the request
2. Shows the user a diff of what changed
3. Waits for explicit approval
4. Only then applies the capability change

This is the human-in-the-loop layer for runtime escalation.

## Enforcement strategy

The enforcer uses a **gRPC sidecar** architecture:

```
agentcontainer runtime ──gRPC──► agentcontainer-enforcer sidecar ──BPF──► kernel
```

- The Go runtime sends policy via gRPC to the Rust enforcer sidecar
- The enforcer attaches Aya BPF programs to the container's cgroup
- Enforcer-backed decisions happen at the kernel level; runtime checks and Docker Sandbox proxy enforcement cover the remaining alpha paths
- The enforcer is fail-closed for startup and policy-apply failures when required

There is no in-process BPF and no iptables/nftables. The sidecar model ensures:
- The BPF programs run with the minimum required privileges
- The agent container has no access to the enforcement mechanism
- Policy updates are applied atomically via gRPC `Apply` calls

### Sidecar transport

The runtime can talk to the sidecar over TCP or a Unix domain socket:

- Linux hosts prefer `unix:///...` when the sidecar is started by the runtime. The socket directory is bind-mounted into the sidecar, TCP is not published to the host, and health checks use the Unix socket.
- Docker Desktop on macOS cannot expose a container-created Unix socket back to the host through a bind mount. In that environment, the runtime uses a Docker-assigned random host TCP port rather than the fixed default `50051`.
- Explicit `agent.enforcer.addr` / `AC_ENFORCER_ADDR` values are still honored. They may be TCP addresses such as `127.0.0.1:50051` or Unix socket targets such as `unix:///run/agentcontainer-enforcer/agentcontainer-enforcer.sock`.

Current alpha runtimes apply BPF policy after the target container or VM has a cgroup to attach to. That means a short startup window remains before policy application completes; if application fails while the enforcer is required, the runtime tears the container down.

## Alpha enforcement matrix

| Backend / feature | Current alpha status | Caveats |
|---|---|---|
| Docker + gRPC enforcer | Supported and fail-closed when enabled. `agentcontainer run` discovers or starts `agentcontainer-enforcer`, then registers the started container and applies network, filesystem, process, credential, deny-set, bind, and reverse-shell policy. | Policy is applied after container start because cgroups exist only after start, so a short pre-apply startup window remains. If apply fails while the enforcer is required, Docker stops and removes the container. |
| Sandbox + proxy | Supported. Sandbox pushes proxy configuration before in-VM BPF policy. | Proxy configuration failure is non-fatal and logs a warning. The proxy is HTTP/HTTPS-oriented; UDP and raw socket coverage depend on in-VM BPF. |
| Sandbox + in-VM gRPC enforcer | Supported and required by default. The VM starts `agentcontainer-enforcer`, connects over the VM network, and applies core plus extension policy. | Policy is applied after the VM/container context exists, so a short pre-apply startup window remains. `agent.enforcer.required: false` downgrades startup and apply failures to warnings. Sandbox currently passes `initPID=0` to `Apply`, so secret injection is not identical to the Docker host path. |
| Compose | gRPC enforcement is explicitly unsupported for alpha. | Compose passes policy-derived environment to Compose files, but does not post-modify containers for full BPF hardening. |
| Required / optional enforcer | Required by default for Docker and Sandbox. Optional only with `agent.enforcer.required: false`. | If optional and no sidecar starts, the runtime proceeds without BPF enforcement. A configured but unreachable `agent.enforcer.addr` is still an error. |
| Event streaming | gRPC streaming and Rust ring-buffer readers are implemented for cgroup-scoped BPF events. | Streaming depends on events carrying `cgroup_id`; mixed old eBPF and new userspace builds will misparse raw events. Go stream startup is non-fatal and local event channels may drop when full. |
| DNS | DNS ingress BPF parser exists but is not attached in the alpha enforcer image because the current parser exceeds verifier complexity limits on supported kernels. | DNS is allowed. Egress allowlist DNS resolution happens in userspace at apply time. Kernel DNS observation will return after the parser is reduced or split. |
| Network egress | BPF attaches `connect4/6`, `sendmsg4/6`, `bind4/6`, DNS ingress, and LSM hooks. | Host and port rules are resolved to IPs at apply time. IPv6 hook coverage exists, but policy population still has alpha gaps. |
| Filesystem deny-set | Kernel hook supports allowed and denied inode maps. | Current Go translation mostly sends read/write allow paths; explicit deny paths are not fully wired from every config path. |
| Shell deny-set | Extension RPC and BPF map exist for denied executable basenames. | Inline `denyArgs`, subcommands, and process policy argument matching are not emitted to the enforcer yet. Kernel deny-set treats entries as whole executable basename denies. |
| Reverse-shell detection | Extension RPC is supported for Docker and Sandbox and defaults to enforce when shell capabilities are present. | Detection is heuristic: BPF blocks outbound connects from shell-like command names. It is not full TTY/session or argv-aware reverse-shell analysis. |
| Non-Linux enforcer | The gRPC server can run for development. | The BPF policy manager is a no-op stub on non-Linux, so policy RPCs can succeed without kernel enforcement. |

## Stats and audit

The enforcer tracks per-cgroup statistics:

| Counter | Description |
|---|---|
| `network_allowed` | Network connections permitted |
| `network_blocked` | Network connections denied |
| `filesystem_allowed` | File opens permitted |
| `filesystem_blocked` | File opens denied |
| `process_allowed` | Process executions permitted |
| `process_blocked` | Process executions denied |
| `credential_allowed` | Secret file reads permitted |
| `credential_blocked` | Secret file reads denied |

Events are emitted to per-domain ring buffers (`NET_EVENTS`, `FS_EVENTS`, `PROC_EVENTS`, `CRED_EVENTS`, `DNS_EVENTS`) and fanned out over gRPC streams when the Linux BPF enforcer is active.

View enforcement stats:

```bash
agentcontainer enforcer status
agentcontainer enforcer diagnose
agentcontainer audit events
agentcontainer audit summary
```

## Enforcement in Sandbox mode

When using Docker Sandbox (microVM), two enforcement layers are attempted:

1. **Docker's proxy enforcement** (gVisor netstack `ProxyEnforcingDialer`) provides coarse-grained network control
2. **BPF enforcer inside the VM** provides cgroup-scoped kernel enforcement

The BPF enforcer runs inside the Sandbox VM, not on the host. It is required by default; setting `agent.enforcer.required: false` makes startup and policy failures warnings instead of session failures. Proxy enforcement is active when proxy configuration succeeds, while UDP/raw network behavior depends on the in-VM BPF path.
