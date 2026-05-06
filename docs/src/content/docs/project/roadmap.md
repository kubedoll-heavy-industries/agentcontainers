---
title: Roadmap
description: Release plan and milestone status.
---

## Milestones

| Milestone | Name | Status |
|---|---|---|
| M0 | Foundation | Complete |
| M1 | Verify | Complete |
| M2 | Attest | Complete |
| M3 | Enforce | Complete |
| M4 | Enterprise | In Progress |

### M0: Foundation

CLI scaffolding, container lifecycle, config schema, runtime backends (Docker, Compose, Sandbox).

### M1: Verify

Lockfile generation, `ac lock` / `ac verify`, OCI resolver, signature verification.

### M2: Attest

SLSA provenance attestations, SBOM generation, Sigstore signing, drift detection.

### M3: Enforce

BPF enforcer sidecar, network/filesystem/process enforcement, approval broker, secrets manager with OIDC/env/Vault/1Password/Infisical providers.

### M4: Enterprise (current)

Three parallel workstreams:

- **M4-POLICY**: Organization policy engine -- OCI-distributed policy artifacts, MCP image allowlisting, policy staleness checking, `ac policy` CLI commands
- **M4-SECRETS**: On-demand secrets resolution with URI scheme detection (`op://`, `vault://`, `infisical://`, `env://`, `oidc://`)
- **M4-CREDLSM**: BPF LSM credential enforcement -- `SECRET_ACLS` map in `file_open` hook for per-cgroup, TTL-aware credential gating at the kernel level

See the [full roadmap](https://github.com/Kubedoll-Heavy-Industries/agentcontainers/blob/main/ROADMAP.md) for details.
