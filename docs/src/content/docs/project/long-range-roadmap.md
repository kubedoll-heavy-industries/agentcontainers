---
title: Long-Range Roadmap
description: Unexercised surfaces, known gaps, and long-term project tracks.
---

Last reviewed: May 4, 2026.

This page tracks what has not yet been run through its paces and what has been identified during dogfood work but needs a durable owner. It complements the milestone [Roadmap](/project/roadmap/), [Container Security Research](/project/container-security-research/), [Runtime Matrix](/project/runtime-matrix/), and [Agent Ecosystem Spikes](/project/agent-ecosystem-spikes/).

## Current State

What has been exercised recently:

- The default `codex-redteam` dojo harness starts a locked-down Codex container with host/workspace canaries.
- The red-team image runs as non-root, strips SUID/SGID files, keeps `/home/node` on tmpfs, and disables Codex's inner sandbox so the container boundary is the system under test.
- Manual dogfood found no host canary, runtime socket, Kubernetes token, or metadata access in the tested Docker Desktop profile.
- `procfs-runc` and `runtime-sockets` exist as manual dojo profiles.
- `mise run test` / `go test -race ./...` passed on the PR branch.

What has not been exercised enough:

- Privileged BPF/enforcer integration tests in a real Linux environment.
- Runtime matrix rows beyond the default Docker Desktop path.
- Kubernetes, Talos, Sysbox, gVisor, Kata/Firecracker, rootless, and userns-remap profiles.
- GPU/CDI/device exposure.
- Deterministic network-deny behavior for metadata and denied callback canaries.
- Docs build as a release gate.
- Real multi-agent workloads beyond Codex.
- VCS/GitHub publish authority as a first-class policy surface.
- OpenTelemetry/OpenInference-compatible agent telemetry.
- Agent Skills packaging, locking, provenance, and capability enforcement.

## M5 Exit Criteria

M5 should not exit until the project can say:

- Manual dojo results can be reproduced by deterministic regression profiles.
- Every profile reports the same verdict schema: host canary, workspace canary, runtime sockets, service-account token, metadata endpoint, UID/GID map, capabilities, seccomp, `/proc`, `/sys`, cgroup, mountinfo, `/dev`, enforcer mode, and agent-local sensitive state.
- Privileged enforcer tests run in CI or in a documented maintainer workflow.
- Docs build with pinned dependencies and fail the PR if broken.
- The default published examples do not require ambient host credentials, host runtime sockets, or privileged containers.
- Known metadata leaks are classified as accepted, mitigated, or assigned.

## Long-Range Tracks

| Track | Goal | Not yet exercised / written down |
|---|---|---|
| Adversarial regression | Convert manual escape audits into repeatable tests. | `network-canary`, `metadata-min`, `vcs-publish`, `userns-matrix`, `device-cdi`, `k8s-kind`, `talos-k8s`, `sysbox`, `gvisor`, `kata-firecracker`. |
| Runtime matrix | Prove behavior across named host/runtime/orchestrator/workload tuples. | Docker Desktop ECI, Docker userns-remap, Docker rootless, containerd rootless, Talos, Sysbox, gVisor, Kata/Firecracker, CDI/GPU. |
| Enforcer TCB | Minimize and verify the trusted sidecar. | Privileged BPF CI, verifier-friendly DNS parser, IPv6 policy population, full deny-path map wiring, startup race reduction, sidecar capability minimization. |
| Process policy | Make shell capabilities enforceable beyond binary allowlists. | `denyArgs`, `denyEnv`, script validation, child process inheritance, helper binary denial assertions, interpreter-specific escape suites. |
| Network policy | Make egress denial deterministic and observable. | Fast metadata denial, DNS exfil profile, denied callback canaries, proxy/BPF parity, UDP/raw socket behavior, runtime-specific DNS resolution behavior. |
| Filesystem and metadata | Reduce host/path disclosure and make remaining leaks explicit. | Mountinfo leakage, hostname/container ID exposure, `/proc/1/environ`, namespace metadata, denied inode population, read/write path regression tests. |
| Credential isolation | Keep secrets out of ambient agent state. | Rust-side `SECRET_ACLS` re-derivation from signed policy, PID 1 env audit, Codex auth/session broker, file descriptor passing, mmap, `/proc/<pid>/mem`, already-read secret caching. |
| VCS and publish authority | Gate repository mutation independently from shell/network access. | Discussion [#24](https://github.com/kubedoll-heavy-industries/agentcontainers/discussions/24): GitHub CLI auth, credential helpers, SSH agent sockets, `git push`, `gh api`, releases, workflows, packages. |
| Supply chain | Make agent environments reproducible and revocable. | TUF key rotation/revocation, reproducible builds, component introspection, OCI org policy lock redesign, release provenance verification in CI. |
| Telemetry | Make agent and enforcer telemetry useful without leaking prompts, secrets, or canaries. | OpenTelemetry GenAI, OpenInference, OpenAI Agents SDK tracing, OTLP exporters, redaction defaults, telemetry egress policy. |
| Skills packaging | Treat Agent Skills as signed, policy-bearing supply chain components. | Skill manifests, OCI packing/referrers, SBOM/provenance, capability manifests, skill lockfile entries, MCP registry linkage. |
| WASM/MCP tool host | Treat tools as untrusted supply chain components. | WASM memory/time limits, async WASI support, process isolation for WASM execution, MCP registry trust model, signed tool manifests, capability manifests. |
| Kubernetes production | Make cluster deployments first-class. | RuntimeClass profiles, Pod Security, service-account automount policy, hostPath denial, node OS differences, Talos system extensions, enforcer DaemonSet/sidecar model. |
| Developer ecosystem | Make common agent workflows ergonomic without weakening policy. | Claude Code, Aider, Goose, OpenCode, Codex variants, nested Docker/buildkit, devcontainer compatibility, VS Code extension. |
| High isolation | Offer a credible path for untrusted or high-risk agents. | Firecracker/Kata backend, in-guest enforcer, workspace sharing model, cold-start cost, attestation, metadata service mediation. |

## Backlog By Horizon

### Alpha

- Automate `codex-redteam`, `procfs-runc`, and `runtime-sockets` into deterministic testcontainers or Go integration tests.
- Add `network-canary` with a local callback sink and a fake metadata endpoint.
- Add `metadata-min` to inventory mountinfo, `/proc`, `/sys`, cgroups, hostname, env, namespace links, and agent-local auth/session files.
- Add `vcs-publish` to prove authenticated GitHub/credential-helper publish paths are denied without explicit approval.
- Add telemetry spike outputs: proposed `agent.telemetry` schema, OTLP collector fixture, and redaction defaults.
- Add skills spike outputs: skill compatibility table and draft skill package/lockfile manifest.
- Run privileged enforcer tests in a documented Linux environment and publish the exact kernel/runtime versions tested.
- Pin docs dependencies and add docs build verification.

### Beta

- Implement user namespace and rootless runtime profiles.
- Add Kubernetes/kind with Pod Security, service-account token controls, hostPath denial, RuntimeClass scaffolding, and enforcer deployment notes.
- Add custom seccomp profile generation from declared capabilities.
- Implement process-policy features currently rejected as not implemented: `denyEnv`, script validation, and argument-aware interpreter controls.
- Complete deny-path propagation into BPF maps and add filesystem regression tests for deny precedence.
- Add TUF key rotation/revocation workflow and org-policy lockfile redesign.
- Add skill and MCP registry entries to lockfile/provenance verification.
- Export enforcer/audit events as OTel-compatible spans or events with redacted attributes.

### Production

- Add Talos, Sysbox, gVisor, Kata/Firecracker, and device/CDI profiles to the published runtime matrix.
- Provide a high-isolation backend for untrusted agents with microVM isolation and clear performance/compatibility tradeoffs.
- Move agent auth/session handling toward brokered credentials instead of long-lived same-user files.
- Make release artifacts reproducible or independently verifiable from source.
- Publish a signed skill/MCP packaging profile with SBOMs, provenance, and capability manifests.
- Publish a conformance suite for agent-safe container behavior.
- Establish an external security review and red-team process once regressions are reproducible.

## Items Identified But Easy To Lose

These came from scans, dogfood notes, and discussions and should either become issues or roadmap checkboxes:

- Compose explicitly does not support gRPC enforcement in alpha.
- DNS ingress parser exists but is not attached because of verifier complexity.
- IPv6 hook coverage exists, but policy population still has alpha gaps.
- Explicit filesystem deny paths are not fully wired from every config path into BPF maps.
- `LoadPolicyBundle` stores a digest but the Rust side does not re-derive `SECRET_ACLS` from signed policy.
- Trust store has no key rotation or revocation.
- Builds are not reproducible.
- WASM `memory_bytes` and `timeout_ms` limits are not enforced yet.
- WASI async types are not supported.
- `component` introspection is not available yet.
- OTel GenAI conventions are still development-status; telemetry support must tolerate schema churn.
- Agent Skills are portable filesystem packages, but they do not solve signing, trust, or runtime enforcement by themselves.
- MCP Registry is preview metadata, not a package registry or scanner; package code still lives in npm/PyPI/NuGet/OCI/etc.
- Org policy locking needs redesign.
- JSONC comment preservation during `update` is still a known limitation.
- `scriptValidation` and `denyEnv` are schema-visible but not implemented.
- Agent-local auth/session/history/log files are same-user readable and should be treated as sensitive state.
- `/proc/1/environ` may be same-user readable; secrets must not be placed in PID 1 env.
- `ptrace(PTRACE_TRACEME)` can succeed; same-UID ptrace policy needs explicit seccomp or profile decisions.
- SSH denial is not enough to prevent repository writes if `gh` or credential helpers have publish credentials.

## Decision Rule

New features should land with one of three labels:

- **verified**: covered by an automated profile or CI test.
- **dogfooded**: manually tested in `agentcontainer dojo` with a saved report.
- **documented gap**: known behavior or missing coverage with an owner.

If a feature does not fit one of those labels, it is not ready to be treated as part of the security story.
