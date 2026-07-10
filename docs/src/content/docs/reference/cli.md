---
title: CLI Reference
description: All agentcontainer commands and their usage.
---

## Core commands

| Command | Description |
|---|---|
| `agentcontainer init` | Initialize an `agentcontainer.json` in the current workspace |
| `agentcontainer run` | Build/pull image and start the agent container |
| `agentcontainer exec <name> -- <cmd>` | Execute a command in a running container |
| `agentcontainer stop <name>` | Stop a running container |
| `agentcontainer build` | Build the container image |
| `agentcontainer ps` | List running agent containers |
| `agentcontainer logs <name>` | View container logs |
| `agentcontainer gc` | Garbage collect stopped containers and dangling images |
| `agentcontainer dojo [profile]` | Start a disposable adversarial harness and drop into chat |

Available dojo profiles:

| Profile | Focus |
|---|---|
| `codex-redteam` | Default canary-backed escape-test prompt |
| `procfs-runc` | Procfs, sysfs, cgroup, mount metadata, and runtime setup confusion sweep |
| `runtime-sockets` | Docker/containerd/CRI-O/Podman sockets, Kubernetes tokens, cloud metadata, and env exposure |

## Supply chain commands

| Command | Description |
|---|---|
| `agentcontainer lock` | Generate a lockfile pinning image digests, MCP servers, and org policy |
| `agentcontainer verify` | Verify the lockfile against the registry (signatures, SBOM, staleness) |
| `agentcontainer sign` | Sign OCI artifacts with Sigstore |
| `agentcontainer attest` | Create SLSA provenance attestations |
| `agentcontainer sbom` | Generate SBOM for the container image |
| `agentcontainer drift` | Check for semantic drift between locked and current state |

## Enforcement commands

| Command | Description |
|---|---|
| `agentcontainer enforcer start` | Start the BPF enforcer sidecar |
| `agentcontainer enforcer stop` | Stop the enforcer sidecar |
| `agentcontainer enforcer status` | Show enforcer status and enforcement stats |
| `agentcontainer enforcer diagnose` | Run diagnostics on enforcer connectivity and BPF programs |

## Audit commands

| Command | Description |
|---|---|
| `agentcontainer audit events` | Stream enforcement events in real time |
| `agentcontainer audit summary` | Show aggregated enforcement statistics |

## Policy commands

| Command | Description |
|---|---|
| `agentcontainer policy pull <ref>` | Fetch an org policy from an OCI registry |
| `agentcontainer policy push <file> <ref>` | Push a local policy file to an OCI registry |
| `agentcontainer policy validate <file>` | Validate a policy file for internal consistency |
| `agentcontainer policy diff <old> <new>` | Show differences between two policy files |

## Global flags

| Flag | Description |
|---|---|
| `--runtime <type>` | Container runtime: `auto`, `docker`, `compose`, `sandbox` |
| `--config <path>` | Path to `agentcontainer.json` |
| `--org-policy <ref>` | OCI reference for org policy overlay |
| `--verbose` / `-v` | Increase log verbosity |
| `--version` | Print version information |
