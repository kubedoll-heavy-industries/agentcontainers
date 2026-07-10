FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl ca-certificates git nodejs npm \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

WORKDIR /workspace
ENTRYPOINT ["claude"]
