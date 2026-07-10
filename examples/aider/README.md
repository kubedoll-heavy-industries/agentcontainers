# Aider Agent Example

Run [Aider](https://aider.chat) inside an agentcontainer with network egress restricted to the Anthropic API.

## Prerequisites

- Docker Desktop or Docker Engine
- `agentcontainer` binary ([install](../../README.md#install))
- An Anthropic API key (set `ANTHROPIC_API_KEY` in your shell)

## Usage

```bash
cd examples/aider

# Start the container
agentcontainer run

# In another terminal, run a prompt
agentcontainer exec <container-id> -- aider --message "what is 2+2" --yes --no-auto-commits
```

## Adapting for OpenAI

```jsonc
"egress": [{ "host": "api.openai.com", "port": 443 }],
"secrets": {
  "OPENAI_API_KEY": { "provider": "env://OPENAI_API_KEY" }
}
```
