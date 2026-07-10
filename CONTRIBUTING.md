# Contributing to agentcontainers

Thank you for your interest in contributing. This document covers how to get set up, how the codebase is organized, and the conventions we follow.

## Before You Start

- Check the [issue tracker](https://github.com/Kubedoll-Heavy-Industries/agentcontainers/issues) to see if your change is already being worked on.
- For significant changes, open an issue first to discuss the approach before writing code. This avoids wasted effort on work that may need to go in a different direction.
- Security vulnerabilities: do **not** open a public issue. See [SECURITY.md](./SECURITY.md).

## Development Setup

**Requirements:**

- Go 1.26+
- [mise](https://mise.jdx.dev/) — task runner and toolchain manager
- Docker Desktop (macOS) or Docker Engine (Linux)
- Rust toolchain (only needed if changing the enforcer in `enforcer/`)

If you are making a Go, docs, config, example, or CLI change, you do not need
the Rust/eBPF toolchain for the first local pass.

```bash
git clone https://github.com/Kubedoll-Heavy-Industries/agentcontainers
cd agentcontainers
mise install        # installs Go, golangci-lint, air, and other toolchain deps
mise run build      # builds the agentcontainer binary to tmp/agentcontainer
mise run test       # go test -race ./...
tmp/agentcontainer version
```

Expected result: `mise run build` creates `tmp/agentcontainer`, `mise run test`
finishes without failures, and `tmp/agentcontainer version` prints the local
binary version/build metadata.

**Before every pull request:**

```bash
go build ./... && go vet ./... && go test -race ./...
```

All three must pass with no errors or warnings.

### Fifteen-Minute Contributor Check

Use this when you are setting up the project for the first time:

```bash
mise install
mise run build
mise run test
tmp/agentcontainer version
```

That path exercises the Go CLI and unit test suite without requiring Docker,
privileged eBPF loading, a running agent, cloud credentials, or a secrets
backend. Docker-backed, Sandbox-backed, TypeScript testcontainers, and
Rust/eBPF checks are separate tiers.

If this quick check fails, open a bug report with the command output, OS,
Docker version if installed, and `go version`.

### Test Tiers

| Command | Requires | Use when |
|---------|----------|----------|
| `mise run test` | Go toolchain | Default check for Go, CLI, config, policy, docs-adjacent changes |
| `go build ./... && go vet ./... && go test -race ./...` | Go toolchain | Required before PRs that change Go behavior |
| `mise run test:dogfood` | Docker | Adversarial canary and Docker dogfood changes |
| `mise run test:integration:ts` | Docker, Node/npm | TypeScript testcontainers harness changes |
| `mise run enforcer:test` | Docker with privileged test container support | Rust/eBPF enforcer changes |
| `cd enforcer && cargo check && cargo test` | Rust toolchain | Rust-only compile/unit checks that do not need privileged BPF loading |

## Repository Layout

| Path | What's there |
|------|-------------|
| `cmd/agentcontainer/` | Binary entry point. Build info injected via ldflags. |
| `internal/cli/` | Cobra command definitions. One file per command: `newXxxCmd()` + `runXxx()`. |
| `internal/config/` | Schema types, JSONC parser, validator, lockfile. |
| `internal/container/` | Runtime interface (`Runtime`) and backends: Docker, Compose, Sandbox. |
| `internal/enforcement/` | gRPC enforcement strategy, policy translation, event streaming. |
| `internal/signing/` | Sigstore/cosign integration, SLSA provenance generation and verification. |
| `internal/oci/` | OCI Distribution Spec client, push/pull, referrers, Sigstore bundle fetch. |
| `internal/orgpolicy/` | Org policy extraction, merge, comparison. |
| `internal/secrets/` | Secret URI parsing and provider implementations (Vault, 1Password, Infisical, OIDC, env). |
| `internal/approval/` | Human-in-the-loop capability approval broker. |
| `enforcer/` | Rust workspace: `agentcontainer-ebpf` (Aya BPF programs), `agentcontainer-enforcer` (Tokio gRPC server), `agentcontainer-common`. |

## Where To Start

Good first contributions usually live in areas that have fast tests and low
blast radius:

- `internal/config/`: schema parsing, validation, and JSONC fixtures.
- `internal/policy/`: capability-to-policy translation tests.
- `internal/cli/`: focused command behavior and help text tests.
- `internal/dojo/` and `test/adversarial/`: adversarial profile fixtures and
  canary-harness coverage.
- `examples/` and `docs/src/content/docs/`: runnable examples and user-facing
  docs.

Coordinate with maintainers before taking on these areas:

- `enforcer/`: Rust, Aya eBPF, kernel hooks, privileged integration tests.
- `internal/container/runtime.go`: shared runtime interfaces.
- `internal/config/config.go`: schema shape used by every layer.
- OCI policy channel, signing, and secrets-provider behavior.

## Code Conventions

### Go

- CLI: Cobra with subcommands. Each command: `newXxxCmd()` constructor returns `*cobra.Command`; `runXxx()` contains the logic.
- Logging: `zap` for structured logging.
- Error wrapping: `fmt.Errorf("context: %w", err)`.
- Validation errors: collect into `[]error`, return with `errors.Join(errs...)`.
- Constructor pattern: `NewXxx(opts ...XxxOption)` with functional options.
- Table-driven tests using `t.Run()` subtests.
- Build tags for test tiers: default (unit), `//go:build integration`, `//go:build e2e`.
- Config is JSONC (JSON with comments) via `github.com/tailscale/hujson`.
- Octal literals: use `0o644` not `0644`.

### Docker SDK

Use `github.com/moby/moby`, **not** `github.com/docker/docker`. The old import paths will fail at `go mod tidy`.

### Testing

- Every new exported function gets a test.
- Unit tests go in `*_test.go` alongside the implementation.
- Tests that require a running Docker daemon go in `*_integration_test.go` with `//go:build integration`.
- The race detector is non-negotiable: `go test -race ./...`.
- Do not mock the Docker daemon in unit tests — use the integration build tag instead.

### Shared Contracts

These interfaces are shared across packages. Changing them affects everyone:

- `internal/container/runtime.go` — the `Runtime` interface and `Session`, `StartOptions`, `ExecResult` types.
- `internal/config/config.go` — the `AgentContainer` struct hierarchy. Adding fields is safe; removing or changing existing fields requires a migration path.
- `cmd/agentcontainer/main.go` — entry point (rarely needs changes).

Coordinate with maintainers before modifying these.

## Adding a New CLI Command

1. Create `internal/cli/<command>.go` with `newXxxCmd()` and `runXxx()`.
2. Register it in `internal/cli/root.go` with `cmd.AddCommand(newXxxCmd())`.
3. Create `internal/cli/<command>_test.go` with at least one test per subcommand.

## Pull Request Guidelines

- **One concern per PR.** Bug fixes, feature additions, and refactors should be separate PRs unless they are genuinely inseparable.
- **Write a clear description.** Explain what the change does, why it's needed, and how you tested it.
- **Reference issues.** Use `Fixes #123` or `Closes #123` in the PR body when applicable.
- **Keep diffs readable.** Avoid mixing formatting changes with functional changes. If you need to reformat, do it in a separate commit.
- **Tests required.** New functionality without tests will not be merged.
- **Schema consistency.** Changes to schema or policy behavior must be consistent with the type definitions in `internal/config/config.go`. If you need to change the schema, document the rationale in the PR.

## Rust / Enforcer

If you are changing the Rust enforcer (`enforcer/`):

- Install the Rust toolchain via `rustup` — the toolchain version is pinned in `enforcer/rust-toolchain.toml`.
- BPF programs in `enforcer/agentcontainer-ebpf/` are compiled with `cargo xtask build-ebpf` and embedded into the enforcer binary at compile time.
- Run `cargo test` in the `enforcer/` directory before submitting.
- The enforcer communicates with the Go CLI via gRPC. Proto definitions are in `enforcer/agentcontainer-enforcer/proto/`. Regenerate Go bindings with `make proto` if you change the proto files.

## Dependency Management

- Do not run `go get` directly if multiple agents or contributors may be working concurrently. Add your imports in Go source files and let `go mod tidy` resolve them.
- Note new third-party dependencies clearly in your PR description.
- For the Rust side, update `enforcer/Cargo.lock` alongside any `Cargo.toml` changes.

## License Compliance

This project is licensed under **Apache-2.0**. All dependencies must be compatible with Apache-2.0 distribution.

**Permitted dependency licenses:** Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, Unicode-DFS-2016, CC0-1.0.

**Prohibited licenses:** GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, LGPL (any version), EUPL, and any other copyleft license that would require source disclosure of the combined work.

**Verification:**

Go dependencies (94 modules as of 2026-04-10): all verified Apache-2.0, MIT, or BSD. No GPL/AGPL/SSPL present.

Rust dependencies (469 crates as of 2026-04-10): all verified Apache-2.0, MIT, or BSD. No GPL/AGPL/SSPL present. Verified by scanning `enforcer/Cargo.lock` for `license =` fields.

When adding a new dependency, check its license before opening a PR. If a dependency does not declare a license, treat it as UNKNOWN and do not merge until the license is confirmed compatible.
