# Organization Policy

Demonstrates the org policy overlay system. A `policy.json` is published as an OCI artifact and referenced from workspace configs via the `orgPolicy` field. The org policy sets organization-wide constraints that all agent environments must comply with.

## Prerequisites

- `ac` CLI
- Access to an OCI registry (e.g., `ghcr.io`)

## Quick Start

```bash
# 1. Validate the policy locally
ac policy validate policy.json

# 2. Push the policy to your OCI registry
ac policy push policy.json ghcr.io/your-org/agent-policy:latest

# 3. In any workspace, reference the policy
#    (already configured in agentcontainer.json via the orgPolicy field)

# 4. Verify workspace compliance
ac verify --org-policy ghcr.io/your-org/agent-policy:latest

# 5. Run the agent — policy is merged at startup
ac run --config agentcontainer.json .
```

## Policy Constraints in This Example

| Constraint | Value | Effect |
|-----------|-------|--------|
| `requireSignatures` | `true` | All OCI images must be signed |
| `requireSBOM` | `true` | All artifacts must have an attached SBOM |
| `minSLSALevel` | `2` | Minimum SLSA provenance level 2 |
| `trustedRegistries` | `ghcr.io/your-org/*`, `mcr.microsoft.com/devcontainers/*` | Only these registries are allowed |
| `bannedPackages` | `event-stream@3.3.6`, `ua-parser-js@0.7.29` | Known-malicious packages rejected |
| `allowedMCPImages` | `ghcr.io/your-org/mcp-tools/`, `ghcr.io/modelcontextprotocol/servers/` | Only approved MCP server images |

## How It Works

1. Security team authors `policy.json` and publishes it with `agentcontainer policy push`
2. Each workspace's `agentcontainer.json` references the policy via `orgPolicy`
3. `agentcontainer lock` pins the policy by digest in `agentcontainer.lock`
4. `agentcontainer run` fetches the policy, merges it with workspace config (deny wins)
5. `agentcontainer verify` checks that all workspace artifacts comply with the policy
6. Expired or replaced mutable policy-channel bundles fail verification until the lockfile is refreshed

## Policy Merge Rules

The org policy is **strictly additive constraints** — it can only restrict, never loosen:

- `trustedRegistries`: workspace images must match at least one pattern
- `allowedMCPImages`: MCP server images must match (exact pin or namespace prefix)
- `deniedCapabilities`: always wins over `allowedCapabilities`
- `bannedPackages`: merged with workspace-level bans
- `minSLSALevel`: the higher value wins (org or workspace)

## Workflow: Updating the Policy

```bash
# Edit policy.json
vim policy.json

# Validate changes
ac policy validate policy.json

# Preview the diff against the currently published version
ac policy diff policy.json ghcr.io/your-org/agent-policy:latest

# Push the update (creates a new OCI tag)
ac policy push policy.json ghcr.io/your-org/agent-policy:latest

# All workspaces pick up the new policy on next `agentcontainer lock` or `agentcontainer run`
```

## Production Notes

- Pin the `orgPolicy` reference by digest for reproducibility: `ghcr.io/your-org/agent-policy@sha256:abc...`
- Use short policy-channel expirations to force teams to refresh stale policies
- The `bannedPackages` field uses Package URL (purl) format
- Audit compliance across all repos with `agentcontainer audit --org your-org`
