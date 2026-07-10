# OpenCode Agent Example

Run [OpenCode](https://opencode.ai) inside an agentcontainer using GitHub Copilot's free tier — no API key required.

## Prerequisites

- Docker Desktop or Docker Engine
- `agentcontainer` binary ([install](../../README.md#install))
- GitHub Copilot auth (one of):
  - VS Code with the Copilot extension signed in
  - `gh auth login` via the GitHub CLI
  - GitHub Copilot Free tier (available to all GitHub users)

## Usage

```bash
cd examples/opencode

# Build the image
docker build -t opencode-agent .

# Start the container
agentcontainer run

# In another terminal, run a prompt
agentcontainer exec <container-id> -- opencode run "what is 2+2"
```

## What this demonstrates

- **Zero API key**: uses GitHub Copilot free tier, auth token auto-detected
- **Network policy**: only GitHub API and Copilot endpoints are reachable
- **Tool allowlist**: only `opencode` and `git` are permitted
- **Read-only rootfs**: the container filesystem is immutable except for `/workspace`

## Using a different provider

To use Anthropic instead of Copilot, add a secret and adjust egress:

```jsonc
{
  "agent": {
    "capabilities": {
      "network": {
        "egress": [{ "host": "api.anthropic.com", "port": 443 }]
      }
    },
    "secrets": {
      "ANTHROPIC_API_KEY": { "provider": "env://ANTHROPIC_API_KEY" }
    }
  }
}
```
