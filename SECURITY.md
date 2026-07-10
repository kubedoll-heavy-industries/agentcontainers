# Security Policy

## Reporting a Vulnerability

Report security vulnerabilities through **GitHub Security Advisories** — do not open a public issue.

1. Go to the [Security Advisories](https://github.com/Kubedoll-Heavy-Industries/agentcontainers/security/advisories/new) page
2. Click **"Report a vulnerability"**
3. Include: affected component, reproduction steps, impact assessment, and your suggested severity

**Response timeline:**

| Stage | Target |
|-------|--------|
| Acknowledgment | 72 hours |
| Initial triage | 1 week |
| Fix (Critical/High) | 2 weeks |
| Fix (Medium/Low) | Next release cycle |

We credit reporters in the advisory and release notes unless you prefer anonymity.

No bug bounty program at this time (pre-alpha).

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch | Yes |
| Released tags | Yes |
| Pre-release / RC | Best effort |

## Scope

**In scope:**

- `agentcontainer` CLI and Rust enforcer sidecar (`enforcer/`)
- `agentcontainer.json` schema and policy engine
- Approval broker and capability matching logic
- OCI provenance and attestation pipeline
- Published container images (`ghcr.io/kubedoll-heavy-industries/agentcontainers`)
- CI/CD workflows that affect release integrity

**Out of scope:**

- Third-party dependencies — report upstream
- Docker Engine, Docker Desktop, or Docker Sandbox vulnerabilities
- Issues in the devcontainer specification itself
- Kernel vulnerabilities (report to kernel.org)

## Security Model

### Trust Boundary

```
Host OS (trusted)
└── agentcontainer runtime + enforcer sidecar (Trusted Computing Base)
    └── Agent container (UNTRUSTED — treat as adversarial)
        └── Agent process, MCP servers, skills
```

The agent running inside the container is **untrusted by design**. The enforcer sidecar is the TCB. The host is assumed trusted.

### What We Defend Against

| Threat | Mechanism |
|--------|-----------|
| Agent executing unapproved binaries | Approval broker + eBPF enforcer (deny-by-default) |
| Argument injection / subshell escapes | Approval broker blocks known interpreter escape patterns (`-c`, `-e` flags) |
| File access outside declared paths | Read-only root FS, explicit bind mounts |
| Network exfiltration to undeclared hosts | cgroup-scoped BPF connect4/sendmsg4/sendmsg6 hooks |
| Credential theft | Secrets injected via tmpfs at `/run/secrets`; never in env vars |
| Supply chain attacks on tools/skills | OCI-packaged, Sigstore-signed, digest-pinned |
| Capability escalation without approval | Human-in-the-loop approval gating |

### What Is Out of Scope for M0–M3 (Known Limitations)

These are architectural limitations, not bugs. We document them so defenders can layer compensating controls:

- **Timing covert channels** — a compromised agent can encode data in timing patterns of allowed syscalls. Mitigation requires hardware-level isolation (M3+ microVMs).
- **DNS exfiltration when DNS is allowed** — if DNS egress is permitted, an agent can exfiltrate data by encoding it in DNS query hostnames. Mitigate by running a filtering resolver or disabling DNS in high-sensitivity environments.
- **Child process execution tracing** — binaries like `npm test` may spawn child processes that inherit the approved capability set. The enforcer tracks the cgroup but does not intercept interpreter-spawned children for all runtimes.
- **WASM tool sandboxing** — WASM component tools run inside the enforcer process. A memory-safety bug in the Wasm runtime could affect the enforcer itself. WASM execution is sandboxed but not isolated to a separate process.
- **No seccomp or AppArmor integration** — enforcement relies on the eBPF cgroup hooks and approval broker. seccomp USER_NOTIF and AppArmor/SELinux profile generation are not yet implemented.

## Known Limitations

These are pre-alpha implementation gaps, not design flaws. They are documented so defenders can layer compensating controls and researchers know what attack surface exists today.

### F8: Secret ACL re-derivation is a stub

The enforcer accepts `LoadPolicyBundle` and stores a SipHash-2-4 128-bit digest of the policy bundle, but does not re-derive `SECRET_ACLS` from the signed policy on the Rust side. The Go `agentcontainer` binary installs ACLs directly. A compromised `agentcontainer` binary can install permissive ACLs as long as it provides a matching hash. Full Rust-side re-derivation of `SECRET_ACLS` from the signed org policy is planned; until then the enforcer trusts the caller's ACL table.

### CREDLSM coverage gaps

The `security_file_open` LSM hook catches direct `open(2)` calls on credential paths. It does not catch:

- `/proc/<pid>/mem` reads (direct memory access bypasses the file hook)
- `mmap()` of credential files (mapped before the hook sees it as a file access)
- In-process caching of secrets that were already read before the hook was installed
- File descriptor passing via `SCM_RIGHTS` over Unix sockets

The container boundary is the primary isolation mechanism for these cases. The LSM hook is a defense-in-depth layer, not a complete credential isolation boundary.

### Trust store has no key rotation or revocation

`~/.agentcontainers/trusted-org-keys.json` is a flat file of Ed25519 public keys. There is no TUF repository, no key rotation protocol, and no revocation mechanism. If a signing key is compromised, the operator must manually edit or replace the trust store file and re-provision affected hosts. Automated rotation and revocation are planned for a future milestone.

### No reproducible builds

Binary verification currently requires trusting the GitHub Actions build infrastructure. The released `agentcontainer` binaries are not reproducibly buildable from source in a way that allows independent hash verification. SLSA Level 3 provenance is generated (see release workflow), but reproducible builds are a separate follow-up.

## Security Architecture Summary

Full security model: see [§Security Model](#security-model) above

**Implemented defense layers:**

| Layer | Mechanism | What it blocks |
|-------|-----------|----------------|
| L1 | Approval broker (interpreter flag blocking) | Known escape patterns (`-c`, `-e` flags on interpreters) |
| L2 | gRPC enforcer — structured capability matching | Binary allowlist, subcommand allowlist |
| L3 | eBPF cgroup hooks (connect4/sendmsg4/sendmsg6) | Network access to undeclared hosts |
| L4 | LSM file_open hook (credential gating) | Unauthorized access to secret files |
| L5 | Container isolation (read-only rootfs, namespaces) | File system and process isolation |

**Not yet implemented:** seccomp profile generation from declared capabilities, `memfd_create` hook (fileless execution), reverse shell detection (`dup2`/`dup3`), `security_capable` hook (privilege escalation detection). These are planned for future milestones.
