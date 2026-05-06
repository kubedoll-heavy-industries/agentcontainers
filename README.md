# agentcontainers

**Immutable, reproducible, least-privilege runtime environments for AI agents.**

`agentcontainers` accepts common [devcontainer.json](https://containers.dev/) fields and adds security policy, supply chain verification, and human-in-the-loop permission approval for persistent AI agents (Claude Code, Codex CLI, Copilot Workspace, and similar tools).

> "AI agents are threatening to break the blood-brain barrier between the application layer and the OS layer."
> — Meredith Whittaker, President of Signal, SXSW 2025

---

## Why

Persistent AI agents require broad, long-lived system permissions. They read and write files, execute shell commands, make network requests, and consume credentials — often with the same ambient authority as the user who launched them. This is the equivalent of running every application as root on a shared machine with no network policy and no syscall filtering.

`agentcontainers` applies the lessons of a decade of container security to the agent problem:

| Threat | Mechanism |
|--------|-----------|
| Unapproved binary execution | Default-deny approval broker + eBPF enforcer |
| Argument injection / subshell escapes | Approval broker blocks known interpreter escape patterns; generated seccomp and eBPF sidecar layers add runtime checks |
| File access outside declared paths | Read-only root FS, explicit bind mounts |
| Network exfiltration | cgroup-scoped BPF connect4/sendmsg hooks |
| Credential theft | Secrets injected via tmpfs at `/run/secrets`; never in env vars |
| Supply chain attacks on tools/skills | OCI-packaged, Sigstore-signed, digest-pinned |
| Capability escalation without approval | Human-in-the-loop approval gating |

---

## Status

**Pre-Alpha.** M0-M4 are mostly shipped; M5 alpha hardening is in progress. The build and tests pass. The API and schema are not yet stable.

| Milestone | Status | What shipped |
|-----------|--------|-------------|
| M0: Foundation | Shipped | `agentcontainer init/run/exec/ps/stop/logs/save/audit`, schema, Docker runtime, approval broker, Rust eBPF enforcer |
| M1: Verify | Shipped | `agentcontainer lock/verify/shim/sbom/component`, lockfile, OCI digest pinning, WASM tool hosting |
| M2: Sandbox | Shipped | Docker Sandbox VM backend, in-VM enforcement, compose-in-sandbox, multi-arch enforcer image |
| M3: Attest | Shipped | `agentcontainer sign`, Sigstore integration, SLSA provenance, drift threshold enforcement, offline verification |
| M4: Enterprise | Mostly complete | Org policy as OCI layer, secrets (Vault/Infisical/1Password/OIDC), per-cgroup LSM credential enforcement |
| M5: Alpha Hardening | In progress | `agentcontainer dojo`, adversarial canary profiles, contemporary container escape regression sweeps |
| M6: Ecosystem | Planning | VS Code extension, Firecracker backend, Linux K8s, MCP registry integration |

---

## Quick Start

### Prerequisites

- Go 1.26+
- Docker Desktop (macOS) or Docker Engine (Linux)
- [mise](https://mise.jdx.dev/) for task running
- `cosign` (optional, for signature verification)

### Install

```bash
git clone https://github.com/Kubedoll-Heavy-Industries/agentcontainers
cd agentcontainers
mise install
mise run build       # builds to tmp/agentcontainer
```

Or install directly:

```bash
go install github.com/Kubedoll-Heavy-Industries/agentcontainers/cmd/agentcontainer@latest
```

### Initialize an agent container

```bash
# In your project directory
agentcontainer init

# This generates agentcontainer.json. If a devcontainer.json already exists,
# it is used as the base and extended with agent-specific defaults.
```

### Pin dependencies

```bash
agentcontainer lock    # resolves OCI image, feature, MCP, and skill references to digests
agentcontainer verify  # verifies lockfile coverage and optional signature/provenance checks
```

### Run an agent

```bash
agentcontainer run     # starts the container + enforcer sidecar
agentcontainer exec -- claude   # executes inside the container with approval gating
```

---

## agentcontainer.json

`agentcontainer.json` supports common devcontainer fields such as `image`, `build`, `features`, and `mounts`. Broader devcontainer compatibility is still alpha. The `agent` key adds capabilities, policy, secrets, and provenance configuration:

```jsonc
{
  "image": "ghcr.io/my-org/my-agent:latest",
  "agent": {
    "capabilities": {
      "network": {
        "egress": [
          { "host": "api.github.com", "port": 443 },
          { "host": "registry.npmjs.org", "port": 443 }
        ]
      },
      "filesystem": {
        "read": ["/workspace/**"],
        "write": ["/workspace/.cache/**"]
      },
      "shell": {
        "commands": ["git", "npm", "node"]
      }
    },
    "policy": {
      "escalation": "prompt",
      "auditLog": true
    },
    "secrets": {
      "GITHUB_TOKEN": {
        "provider": "vault://secret/data/github#token"
      },
      "NPM_TOKEN": {
        "provider": "op://Engineering/npm/token"
      }
    }
  }
}
```

Full schema reference: see the type definitions in [`internal/config/config.go`](./internal/config/config.go)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Host (trusted)                                     │
│                                                     │
│  agentcontainer CLI ─────────────────────────────  │
│     │                                               │
│     ▼                                               │
│  Agentcontainer Runtime                             │
│     ├── Policy engine (config → ContainerPolicy)    │
│     ├── Approval broker (human-in-the-loop gating)  │
│     ├── Secrets manager (OIDC / Vault / 1Password)  │
│     └── OCI verifier (Sigstore / lockfile)          │
│     │                                               │
│     ▼           gRPC                                │
│  ┌──────────────────────────────────────────────┐  │
│  │  Isolated OCI Container (UNTRUSTED)          │  │
│  │    └── Agent process (Claude Code, etc.)     │  │◄──── Developer / IDE
│  └──────────────────────────────────────────────┘  │
│     │                                               │
│     ▼           gRPC                                │
│  agentcontainer-enforcer sidecar (Rust + Aya eBPF)             │
│     ├── cgroup/connect4/sendmsg BPF hooks           │
│     ├── LSM file_open hook (credential gating)      │
│     └── WASM Component tool host                   │
└─────────────────────────────────────────────────────┘
```

Enforcement is **fail-closed** for sidecar startup and policy-apply failures when the enforcer is required. In the current alpha, BPF policy is applied after the target cgroup exists, so a short startup window remains before policy application completes.

For the security model and threat analysis: [SECURITY.md](./SECURITY.md)

---

## Development

```bash
mise run build          # build binary to tmp/agentcontainer
mise run test           # go test -race ./...
mise run test:dogfood   # adversarial canary + Docker dogfood probes
mise run test:integration:ts # TypeScript testcontainers integration suite
mise run redteam:codex                # disposable locked-down manual escape-test container
tmp/agentcontainer dojo               # start the default Codex red-team harness
tmp/agentcontainer dojo procfs-runc   # focus on procfs/sysfs/cgroup runtime setup probes
tmp/agentcontainer dojo runtime-sockets # focus on runtime sockets, K8s tokens, and metadata
mise run test:cover     # tests with coverage report
mise run lint           # golangci-lint
mise run dev            # live reload with air

# Before declaring work complete:
go build ./... && go vet ./... && go test -race ./...
```

Repository layout:

| Path | What's there |
|------|-------------|
| `cmd/agentcontainer/` | Binary entry point |
| `internal/cli/` | Cobra command definitions, one file per command |
| `internal/config/` | Schema types, JSONC parser, validator |
| `internal/container/` | Runtime backends (Docker, Compose, Sandbox) |
| `internal/enforcement/` | gRPC strategy, policy translation |
| `internal/signing/` | Sigstore/cosign integration, SLSA provenance |
| `internal/oci/` | OCI Distribution Spec client, push/pull |
| `internal/orgpolicy/` | Org policy extraction, merge, comparison |
| `internal/secrets/` | Secret provider implementations |
| `enforcer/` | Rust: agentcontainer-ebpf (Aya BPF), agentcontainer-enforcer (Tokio gRPC) |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

See [SECURITY.md](./SECURITY.md) for the vulnerability reporting policy and threat model.

## License

Apache 2.0. See [LICENSE](./LICENSE).
