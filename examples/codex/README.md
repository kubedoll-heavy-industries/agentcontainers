# Codex CLI Agent Example

Run [OpenAI Codex CLI](https://github.com/openai/codex) inside an agentcontainer with network egress restricted to the OpenAI API.

## Prerequisites

- Docker Desktop or Docker Engine
- `agentcontainer` binary ([install](../../README.md#install))
- An OpenAI API key (set `OPENAI_API_KEY` in your shell)

## Usage

```bash
cd examples/codex

# Start the container
agentcontainer run

# In another terminal, run a prompt
agentcontainer exec <container-id> -- codex "what is 2+2"
```
