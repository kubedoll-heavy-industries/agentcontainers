FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/block/goose/releases/latest/download/install.sh | bash

WORKDIR /workspace
ENTRYPOINT ["goose"]
