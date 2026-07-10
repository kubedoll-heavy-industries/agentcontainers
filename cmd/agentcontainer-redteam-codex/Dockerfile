FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash \
       ca-certificates \
       curl \
       gawk \
       git \
       less \
       procps \
       python3 \
       ripgrep \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @openai/codex \
    && codex_path="$(command -v codex)" \
    && codex_native="$(find /usr/local/lib/node_modules/@openai/codex -type f -path '*/vendor/*/codex/codex' | head -1)" \
    && mv "${codex_path}" /usr/local/bin/codex-real \
    && ln "${codex_native}" /usr/local/bin/codex-native \
    && printf '%s\n' \
       '#!/bin/sh' \
       'if [ -z "${OPENAI_API_KEY:-}" ] && [ -r /run/secrets/OPENAI_API_KEY ]; then' \
       '  export OPENAI_API_KEY="$(cat /run/secrets/OPENAI_API_KEY)"' \
       'fi' \
       'if [ "${AGENTCONTAINERS_CODEX_INNER_SANDBOX:-0}" != "1" ]; then' \
       '  case "${1:-}" in' \
       '    completion|debug|features|login|logout|mcp|mcp-server|plugin|sandbox|update|-h|--help|-V|--version)' \
       '      exec /usr/local/bin/codex-real "$@"' \
       '      ;;' \
       '  esac' \
       '  exec /usr/local/bin/codex-real --dangerously-bypass-approvals-and-sandbox "$@"' \
       'fi' \
       'exec /usr/local/bin/codex-real "$@"' \
       > /usr/local/bin/codex \
    && chmod 0755 /usr/local/bin/codex

RUN find /usr /bin /sbin -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} +

RUN mkdir -p /workspace \
    && chown node:node /workspace

USER node
ENV HOME=/home/node
WORKDIR /workspace
