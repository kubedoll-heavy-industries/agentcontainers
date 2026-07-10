---
title: Organization Policy
description: Create, distribute, and enforce enterprise-wide security policies as OCI artifacts.
---

Organization policies define security constraints that all agent environments in your organization must satisfy. Policies are stored as OCI artifacts in any compatible registry and enforced at runtime.

## Overview

An org policy is a JSON document that specifies:
- Required image signatures and SLSA provenance levels
- Trusted registries and MCP image allowlists
- Banned packages for SBOM enforcement
- Allowed and denied agent capabilities
- Policy staleness thresholds

When a workspace launches with `ac run`, the org policy merges with the workspace's `agentcontainer.json`. **Deny always wins** -- the org policy can only restrict, never expand, workspace permissions.

## Creating a policy

Create a JSON file with your organizational constraints:

```json
{
  "requireSignatures": true,
  "minSLSALevel": 2,
  "trustedRegistries": [
    "ghcr.io/myorg/*",
    "docker.io/library/*"
  ],
  "bannedPackages": [
    "log4j-core@<2.17.1",
    "lodash@<4.17.21"
  ],
  "requireSBOM": true,
  "allowedCapabilities": [
    "network",
    "filesystem",
    "git"
  ],
  "deniedCapabilities": [
    "shell:sudo",
    "shell:curl"
  ],
  "allowedMCPImages": [
    "ghcr.io/myorg/approved-tools/",
    "ghcr.io/myorg/github-mcp:v2.1.0@sha256:abc123..."
  ],
  "maxDriftThreshold": 0.15
}
```

### Field reference

| Field | Type | Description |
|---|---|---|
| `requireSignatures` | bool | Mandate Sigstore signatures on all OCI images |
| `minSLSALevel` | int (0-4) | Minimum SLSA provenance level |
| `trustedRegistries` | string[] | Allowlist of registries (supports glob patterns) |
| `bannedPackages` | string[] | Packages that must not appear in any SBOM |
| `requireSBOM` | bool | Require SBOM attached to all artifacts |
| `maxDriftThreshold` | float | Maximum semantic drift distance (0.0-1.0) |
| `allowedCapabilities` | string[] | Only these capabilities are permitted |
| `deniedCapabilities` | string[] | These capabilities are explicitly blocked |
| `allowedMCPImages` | string[] | Allowlist of MCP server images |

### MCP image allowlist matching

The `allowedMCPImages` field supports two matching modes:

1. **Exact pin**: Match a specific image reference with tag or digest.
   ```
   "ghcr.io/myorg/github-mcp:v2.1.0"
   "ghcr.io/myorg/github-mcp@sha256:abc123..."
   ```

2. **Namespace prefix**: A trailing slash matches any image directly in that namespace (no deeper nesting).
   ```
   "ghcr.io/myorg/approved-tools/"  // matches ghcr.io/myorg/approved-tools/any-tool:v1
   ```

The `oci://` prefix is stripped before matching. An empty list means all MCP images are allowed (backward-compatible).

## CLI commands

### Push a policy to a registry

```bash
ac policy push myorg-policy.json ghcr.io/myorg/policy:latest
```

This packages the policy JSON as an OCI artifact and pushes it to the registry.

### Pull a policy from a registry

```bash
ac policy pull ghcr.io/myorg/policy:latest
```

Fetches and prints the policy as JSON. Useful for inspecting remote policies.

### Validate a policy

```bash
ac policy validate myorg-policy.json
```

Checks the policy for internal consistency: valid SLSA levels, supported fields, and well-formed allowlist patterns.

### Diff two policies

```bash
ac policy diff old-policy.json new-policy.json
```

Shows what changed between two policy versions.

## Using policies with `ac run`

### Via `agentcontainer.json`

Set the `agent.orgPolicy` field to an OCI reference:

```jsonc
{
  "image": "node:22",
  "agent": {
    "orgPolicy": "ghcr.io/myorg/policy:latest",
    "capabilities": {
      "network": {
        "allow": ["api.github.com:443"]
      }
    }
  }
}
```

### Via CLI flag

Override or supplement with `--org-policy`:

```bash
ac run --org-policy ghcr.io/myorg/policy:latest
```

The CLI flag takes precedence over the config file.

## Policy merge behavior

When an org policy is present, the runtime merges it with the workspace config:

1. **Deny wins.** If the org policy denies a capability, the workspace cannot re-enable it.
2. **Allowlists intersect.** If both the org policy and workspace define `trustedRegistries`, only registries in both lists are permitted.
3. **Requirements escalate.** If the org requires `minSLSALevel: 2`, a workspace requesting level 1 is rejected.
4. **MCP images are gated.** If `allowedMCPImages` is non-empty, any MCP server image not matching the allowlist is blocked at session start.

## Locking and staleness

When you run `ac lock`, the org policy digest is pinned alongside image digests:

```bash
ac lock
# Pins: image digests, MCP server digests, org policy digest + timestamp
```

When you run `ac verify`, mutable org policy channels are re-resolved from the
registry unless `--registry=false` is set. The lockfile pins the signed policy
bundle manifest digest, epoch, and expiration time, so verification can detect
stale or replaced policy bundles before an agent session starts:

```bash
ac verify
# Fails if the policy digest changed, rolled back, expired, or rejects an artifact
# Re-run "ac lock" after approving a legitimate policy update
```

Strict offline verification still checks the locked policy expiration timestamp.
This ensures teams cannot run with stale policies indefinitely even when registry
access is disabled.

## Example: enterprise deployment

```json
{
  "requireSignatures": true,
  "minSLSALevel": 3,
  "trustedRegistries": [
    "ghcr.io/acme-corp/*",
    "acme-corp.azurecr.io/*"
  ],
  "bannedPackages": [
    "log4j-core@<2.17.1"
  ],
  "requireSBOM": true,
  "allowedCapabilities": [
    "network",
    "filesystem",
    "git"
  ],
  "deniedCapabilities": [
    "shell:sudo",
    "shell:rm -rf"
  ],
  "allowedMCPImages": [
    "ghcr.io/acme-corp/approved-mcp/"
  ],
  "maxDriftThreshold": 0.1
}
```

Push it:

```bash
ac policy push acme-policy.json ghcr.io/acme-corp/policy:2026-q1
ac policy push acme-policy.json ghcr.io/acme-corp/policy:latest
```

Teams reference it in their workspace configs, and the policy is enforced automatically at every `ac run`.
