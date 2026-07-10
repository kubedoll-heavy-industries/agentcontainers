# Claude Code Agent Example

Run [Claude Code](https://claude.ai/code) inside an agentcontainer with network egress restricted to the Anthropic API.

## Prerequisites

- Docker Desktop or Docker Engine
- `agentcontainer` binary ([install](../../README.md#install))
- An Anthropic API key (set `ANTHROPIC_API_KEY` in your shell)

## Usage

```bash
cd examples/claude-code

# Start the container
agentcontainer run

# In another terminal, run a prompt
agentcontainer exec <container-id> -- claude -p "what is 2+2"
```

## What this demonstrates

- **Network policy**: only Anthropic API and npm registry are reachable
- **Secret injection**: `ANTHROPIC_API_KEY` is injected via tmpfs at `/run/secrets/`, never in env vars
- **Tool allowlist**: only `claude`, `node`, `npm`, and `git` are permitted
- **Read-only rootfs**: the container filesystem is immutable except for `/workspace`
