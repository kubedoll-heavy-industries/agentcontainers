FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3 python3-pip python3-venv git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --break-system-packages aider-chat

WORKDIR /workspace
ENTRYPOINT ["aider"]
