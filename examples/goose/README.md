# Goose Agent Example

Run [Goose](https://github.com/block/goose) (by Block) inside an agentcontainer with network egress restricted to the Anthropic API.

## Prerequisites

- Docker Desktop or Docker Engine
- `agentcontainer` binary ([install](../../README.md#install))
- An Anthropic API key (set `ANTHROPIC_API_KEY` in your shell)

## Usage

```bash
cd examples/goose

# Start the container
agentcontainer run

# In another terminal, run a prompt
agentcontainer exec <container-id> -- goose run "what is 2+2"
```

## Adapting for OpenAI

```jsonc
"egress": [{ "host": "api.openai.com", "port": 443 }],
"secrets": {
  "OPENAI_API_KEY": { "provider": "env://OPENAI_API_KEY" }
}
```
