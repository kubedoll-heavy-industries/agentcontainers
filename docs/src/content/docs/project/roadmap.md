---
title: Roadmap
description: Release plan and milestone status.
---

## Milestones

| Milestone | Name | Status |
|---|---|---|
| M0 | Foundation | Shipped |
| M1 | Verify | Shipped |
| M2 | Sandbox | Shipped |
| M3 | Attest | Shipped |
| M4 | Enterprise | Mostly Complete |
| M5 | Alpha Hardening | In Progress |
| M6 | Ecosystem | Planning |

### M0: Foundation

CLI scaffolding, container lifecycle, config schema, runtime backends (Docker, Compose, Sandbox).

### M1: Verify

Lockfile generation, `ac lock` / `ac verify`, OCI resolver, signature verification.

### M2: Sandbox

Docker Sandbox VM backend, in-VM enforcement, compose-in-sandbox, multi-arch enforcer image.

### M3: Attest

SLSA provenance attestations, SBOM generation, Sigstore signing, drift detection.

### M4: Enterprise

BPF enforcer sidecar, network/filesystem/process enforcement, approval broker, secrets manager with OIDC/env/Vault/1Password/Infisical providers.

Three parallel workstreams:

- **M4-POLICY**: Organization policy engine -- OCI-distributed policy artifacts, MCP image allowlisting, policy staleness checking, `ac policy` CLI commands
- **M4-SECRETS**: On-demand secrets resolution with URI scheme detection (`op://`, `vault://`, `infisical://`, `env://`, `oidc://`)
- **M4-CREDLSM**: BPF LSM credential enforcement -- `SECRET_ACLS` map in `file_open` hook for per-cgroup, TTL-aware credential gating at the kernel level

### M5: Alpha Hardening (current)

Hardening the runtime against contemporary container escape classes and making dogfood/adversarial testing repeatable:

- **M5-DOJO**: `agentcontainer dojo` profiles for Codex red-team sessions and automated canary sweeps
- **M5-RUNTIME**: regression profiles for runc procfs/sysfs/cgroup classes, runtime sockets, user namespaces, rootless hosts, and Docker Desktop behavior
- **M5-NETWORK**: canary-based egress tests for model APIs, metadata endpoints, DNS, and denied webhook destinations
- **M5-EBPF**: enforcer privilege minimization, BPF/perf denial from the agent container, and sidecar TCB review
- **M5-DOCS**: publish the threat model, research baseline, known limitations, and tested runtime matrix

See [Container Security Research](/project/container-security-research/) for the threat taxonomy, [Runtime Matrix](/project/runtime-matrix/) for backend/profile comparison, and [Long-Range Roadmap](/project/long-range-roadmap/) for unexercised surfaces and future tracks.

### M6: Ecosystem

VS Code extension, Firecracker backend, Linux Kubernetes integration, MCP registry integration, and external runtime matrix support across Talos, Sysbox, gVisor, Kata/Firecracker, Docker, and containerd environments.
