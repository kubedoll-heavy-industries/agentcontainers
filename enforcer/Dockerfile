# Example docker-compose sidecar usage:
# services:
#   agentcontainer-enforcer:
#     build:
#       context: ./enforcer
#       dockerfile: Dockerfile
#     image: agentcontainer-enforcer:latest
#     cap_add:
#       - BPF
#       - NET_ADMIN
#       - SYS_ADMIN
#     pid: host
#     volumes:
#       - /sys/fs/bpf:/sys/fs/bpf
#       - /sys/fs/cgroup:/sys/fs/cgroup:ro
#     ports:
#       - "50051:50051"
#     healthcheck:
#       test: ["CMD", "/bin/grpc_health_probe", "-addr=localhost:50051", "-service=agentcontainers.enforcer.v1.Enforcer"]
#       interval: 10s
#       timeout: 5s
#       retries: 3

# ========================================================================
# Chef Stage: Prepare cargo-chef recipe for dependency caching
# ========================================================================
# All build stages pin to BUILDPLATFORM so Rust compiles natively on the
# host CPU. Cross-compilation to other architectures (e.g. arm64) is
# handled by cargo-zigbuild + Zig — no QEMU emulation needed.
FROM --platform=$BUILDPLATFORM rust:1.93-bookworm AS chef

RUN cargo install cargo-chef
WORKDIR /build

# ========================================================================
# Planner Stage: Compute dependency recipe from source
# ========================================================================
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ========================================================================
# Build Stage: Cross-compile Rust workspace and BPF programs
# ========================================================================
FROM chef AS builder

ARG TARGETARCH

# Map Docker's TARGETARCH to the Rust target triple.
RUN case "$TARGETARCH" in \
      amd64) echo "x86_64-unknown-linux-gnu" ;; \
      arm64) echo "aarch64-unknown-linux-gnu" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2 && exit 1 ;; \
    esac > /tmp/rust-target

# Install build dependencies:
# - clang, llvm: BPF compilation toolchain (arch-independent bpfel target)
# - libelf-dev: eBPF library support (build-time linking)
# - linux-headers-generic: kernel headers for BPF type definitions
# - protobuf-compiler: tonic-build proto code generation
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-generic \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.15.2 (C cross-compiler used by cargo-zigbuild).
# Zig bundles libc for many targets, enabling cross-compilation without
# platform-specific GCC toolchains or QEMU emulation.
ARG ZIG_VERSION=0.15.2
RUN ARCH=$(uname -m) && \
    zig_archive="/tmp/zig-${ARCH}-linux-${ZIG_VERSION}.tar.xz" && \
    curl --retry 5 --retry-delay 2 --retry-all-errors --connect-timeout 20 -fL \
        "https://ziglang.org/download/${ZIG_VERSION}/zig-${ARCH}-linux-${ZIG_VERSION}.tar.xz" \
        -o "${zig_archive}" && \
    tar -tJf "${zig_archive}" >/dev/null && \
    tar -xJf "${zig_archive}" -C /usr/local && \
    rm -f "${zig_archive}" && \
    ln -s "/usr/local/zig-${ARCH}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

# Install cargo-zigbuild: uses Zig as the C linker for cross-compilation.
RUN cargo install --locked cargo-zigbuild

# Install nightly toolchain with rust-src (required by aya-build for BPF compilation).
# agentcontainer-ebpf targets bpfel-unknown-none and uses -Z build-std=core, which needs rust-src.
RUN rustup toolchain install nightly --component rust-src

# Install bpf-linker (required to link BPF programs for the bpfel-unknown-none target).
# bpf-linker v0.10+ requires edition2024, so install via nightly cargo.
RUN rustup run nightly cargo install bpf-linker

# Cook dependencies from recipe (cached unless Cargo.toml/Cargo.lock change).
# Installs cross target here (not earlier) to avoid BuildKit GHA cache sharing
# the layer with the native-only build variant and losing the cross target.
COPY --from=planner /build/recipe.json recipe.json
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    rustup target add "$RUST_TARGET" && \
    cargo chef cook --release --target "$RUST_TARGET" \
      --recipe-path recipe.json -p agentcontainer-enforcer 2>&1 \
    || echo "cargo-chef cook failed (expected for cross targets without system linker); continuing"

# Copy the entire workspace (includes agentcontainer-common, agentcontainer-enforcer, agentcontainer-ebpf, xtask)
COPY . .

# Cross-compile the agentcontainer-enforcer binary in release mode.
# cargo-zigbuild uses Zig as the C linker — compiles natively on the host CPU.
# build.rs runs on the host and invokes aya-build for BPF programs (arch-independent).
# rustup target add is repeated here to ensure the target is present even if the
# chef cook layer above was cached from a build with a different target.
RUN RUST_TARGET=$(cat /tmp/rust-target) && \
    rustup target add "$RUST_TARGET" && \
    cargo zigbuild --release --target "$RUST_TARGET" -p agentcontainer-enforcer

# Verify and copy artifacts to /build/output/ (not /build/agentcontainer-enforcer which
# collides with the agentcontainer-enforcer/ source directory from COPY . .).
RUN mkdir -p /build/output && \
    RUST_TARGET=$(cat /tmp/rust-target) && \
    test -f "/build/target/${RUST_TARGET}/release/agentcontainer-enforcer" && \
    cp "/build/target/${RUST_TARGET}/release/agentcontainer-enforcer" /build/output/agentcontainer-enforcer

# Copy BPF ELF from aya-build output to a well-known location.
# aya-build places it in OUT_DIR (target/<triple>/release/build/agentcontainer-enforcer-*/out/).
# BPF bytecode is architecture-independent (bpfel VM).
RUN find /build/target -name 'agentcontainer-ebpf-progs' -path '*/out/*' \
    | head -1 | xargs -I{} cp {} /build/output/agentcontainer-ebpf-progs.elf \
    && test -f /build/output/agentcontainer-ebpf-progs.elf

# ========================================================================
# Health Probe Stage: Download grpc_health_probe for the target platform
# ========================================================================
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS healthprobe

ARG TARGETARCH
ARG GRPC_HEALTH_PROBE_VERSION=v0.4.35

RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates \
    && wget -qO /bin/grpc_health_probe \
       "https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-${TARGETARCH}" \
    && chmod +x /bin/grpc_health_probe \
    && rm -rf /var/lib/apt/lists/*

# ========================================================================
# Runtime Stage: Minimal Debian with runtime dependencies only
# ========================================================================
FROM debian:bookworm-slim

# Install runtime dependencies:
# - libelf1: Required by aya for BPF program loading at runtime
RUN apt-get update && apt-get install -y \
    libelf1 \
    && rm -rf /var/lib/apt/lists/*

# BPF enforcement requires root capabilities (CAP_BPF, CAP_SYS_ADMIN, CAP_NET_ADMIN).
# The container must be run with --privileged or --cap-add flags (see compose example above).
# Running as root is required because BPF map creation and program loading are
# root-only kernel operations. The security boundary is container isolation, not UID.

# Copy grpc_health_probe from the healthprobe stage
COPY --from=healthprobe /bin/grpc_health_probe /bin/grpc_health_probe

# Copy the compiled binary from builder stage
COPY --from=builder /build/output/agentcontainer-enforcer /usr/local/bin/agentcontainer-enforcer

# Copy the BPF ELF to the well-known path the binary searches at runtime
COPY --from=builder /build/output/agentcontainer-ebpf-progs.elf /usr/lib/agentcontainer-enforcer/agentcontainer-ebpf-progs

# Make binaries executable
RUN chmod 755 /usr/local/bin/agentcontainer-enforcer \
    && chmod 644 /usr/lib/agentcontainer-enforcer/agentcontainer-ebpf-progs

# Expose gRPC port
EXPOSE 50051

# OCI labels
LABEL org.opencontainers.image.title="agentcontainer-enforcer"
LABEL org.opencontainers.image.description="BPF enforcement daemon for agentcontainers"
LABEL org.opencontainers.image.source="https://github.com/Kubedoll-Heavy-Industries/agentcontainers"

# Health check using gRPC health checking protocol (tonic-health)
HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD ["/bin/grpc_health_probe", "-addr=localhost:50051", "-service=agentcontainers.enforcer.v1.Enforcer"]

# Entrypoint: the agentcontainer-enforcer binary
ENTRYPOINT ["/usr/local/bin/agentcontainer-enforcer"]

# Default arguments: bind to all interfaces on port 50051
# Override with docker run args if needed (e.g., --listen 127.0.0.1:50051)
CMD ["--listen", "0.0.0.0:50051"]
