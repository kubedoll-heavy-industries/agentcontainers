---
title: Threat Model
description: The threat model for agentcontainers and the attacks it defends against.
---

agentcontainers assumes the agent process is untrusted. Prompt injection, malicious repository content, poisoned tool output, and compromised MCP servers can all steer the agent toward hostile behavior. The job of the runtime is to keep that behavior inside declared policy.

## Trust Boundary

```
Host OS and user session
`-- agentcontainer CLI, policy engine, approval broker, and enforcer sidecar
    `-- OCI container or Sandbox VM
        `-- Agent process, tools, MCP servers, package managers, and repo content
```

The host, CLI, signed policy material, and enforcer sidecar are trusted computing base. The agent container is not trusted, even when it is running a familiar model or official tool.

## Assets

| Asset | Security goal |
|---|---|
| Host filesystem | The agent cannot read or write outside declared mounts and capabilities. |
| Host runtime control plane | Docker, containerd, CRI-O, Podman, kubelet, and Kubernetes API credentials are not exposed to the agent by default. |
| Secrets | Credentials are not placed in ambient environment variables and are only exposed through declared secret mechanisms. |
| Network boundary | The agent can reach only declared egress destinations needed for the task. |
| Policy state | Runtime escalation requires explicit approval and auditability. |
| Supply chain | Images, components, skills, and policy bundles can be pinned, verified, and audited. |

## In Scope

agentcontainers is designed to reduce damage from these cases:

- A prompt-injected agent tries to exfiltrate files, env vars, credentials, or canary tokens.
- Repository code asks the agent to execute a malicious shell command, package script, or interpreter payload.
- A tool or MCP server attempts undeclared network access or file access.
- A dependency install, build step, or test runner spawns unexpected child processes.
- A malicious image probes runtime sockets, Kubernetes tokens, cloud metadata, procfs/sysfs, cgroups, devices, and mount metadata.
- The agent requests a new capability after startup and needs human approval before it is granted.

## Out of Scope

These require separate controls outside agentcontainers:

- A compromised host OS, Docker daemon, hypervisor, or kernel.
- Hardware side channels and timing covert channels.
- Attacks on third-party model providers or package registries.
- Bugs in Docker, containerd, runc, Kubernetes, or the Linux kernel, except where agentcontainers can add compensating checks.
- Workspaces where the user intentionally bind-mounts sensitive host directories or runtime sockets into the agent container.

## Control Map

| Threat | Primary controls | Current alpha gaps |
|---|---|---|
| Undeclared network egress | BPF cgroup network hooks, Sandbox proxy enforcement, static egress policy | DNS observation is not fully attached in the alpha enforcer. Runtime DNS resolution is userspace-driven. |
| Host filesystem reads | Read-only root filesystem, explicit mounts, policy resolver, LSM file hooks | Explicit deny paths are not fully wired from every config path into BPF maps. |
| Secret theft | Tmpfs secret injection, credential ACL maps, TTL-aware secret policy, no env-based default | Process memory, inherited file descriptors, already-read secrets, PID 1 environment, and same-user agent-local auth/session files remain application-level risks. |
| Unapproved binaries | Approval broker, shell capability allowlist, BPF process hooks | Argument-level matching is not fully argv-aware in the kernel path. |
| Runtime socket takeover | Default mount denylist, adversarial canary checks | Users can still opt into dangerous mounts; docs and approval flows must make that explicit. |
| Ambient root escalation | Non-root red-team image, capability drop, no-new-privileges, seccomp, read-only rootfs | User namespace behavior depends on host runtime support and must be tested per backend. |
| eBPF abuse | Agent container has no BPF-related capabilities; enforcer runs out-of-band | The enforcer sidecar is privileged enough to load policy and must remain minimal and isolated. |
| Capability drift | Lockfiles, provenance, org policy, approval diff, audit log | Trust-store rotation and revocation are still early. |

## Agent-Specific Assumption

The model is allowed to be curious and adversarial inside the harness. A successful safety result is not that the model refuses to try. A successful result is that the host canary, secret canary, runtime sockets, Kubernetes tokens, and metadata endpoints remain unavailable even when the model tries within the authorized test scope.
