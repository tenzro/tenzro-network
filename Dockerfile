# Stage 1: Build
# Ubuntu 24.04 (glibc 2.39) is the floor of the release binaries: the prebuilt
# ONNX Runtime static library that ort-sys downloads is built against glibc
# 2.38 or newer and a current libstdc++, and does not link on Debian bookworm.
FROM docker.io/library/ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    cmake \
    protobuf-compiler \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Rust toolchain (the workspace rust-toolchain.toml selects the channel;
# rustup syncs it on the first cargo invocation)
# rustup-init is a fixed release, checked against its published sha256; any
# other file fails the build.
ARG RUSTUP_VERSION=1.29.1
RUN set -eux; \
    case "$(uname -m)" in \
      x86_64) t=x86_64-unknown-linux-gnu; sum=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71 ;; \
      aarch64) t=aarch64-unknown-linux-gnu; sum=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433 ;; \
      *) echo "no pinned rustup-init for $(uname -m)"; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL -o /tmp/rustup-init \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${t}/rustup-init"; \
    echo "${sum}  /tmp/rustup-init" | sha256sum -c -; \
    chmod +x /tmp/rustup-init; \
    /tmp/rustup-init -y --default-toolchain 1.99.1 --profile minimal; \
    rm /tmp/rustup-init
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /build
# The commit time (build-linux.sh passes it), for every tool that stamps a date.
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# Force clang as the C/C++ compiler (required by llama-cpp-sys-2 which uses clang-specific flags)
ENV CC=clang
ENV CXX=clang++

# ggml defaults to -march=native, which would pin the binary to whatever CPU
# the build host happens to have. The fleet is heterogeneous, so build for the
# baseline instruction set instead.
ENV CMAKE_ARGS="-DGGML_NATIVE=OFF"

# Copy workspace files
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY tools/ tools/
COPY sdk/tenzro-ts-sdk/native/ sdk/tenzro-ts-sdk/native/
COPY sdk/tenzro-py/native/ sdk/tenzro-py/native/
# vendor/* subtrees (erc8004-evm, erc8004-solana, erc8004-atom)
# are source artifacts for regenerate.sh, not build-time
# dependencies — they're copied here because COPY vendor/ is a single layer
# and the cost is negligible vs. surgical sub-copies.
COPY vendor/ vendor/

# Build tenzro-node and tenzro-cli. NODE_BUILD=edge builds the node as the
# light build for the edge tier (no model engines, the edge profile, see
# scripts/build-tier.sh) and puts it where the runtime stage copies from.
ARG NODE_BUILD=standard
RUN if [ "$NODE_BUILD" = edge ]; then \
        cargo build --locked --profile edge --no-default-features -p tenzro-node \
        && cargo build --release --locked -p tenzro-cli \
        && install -D -m 0755 target/edge/tenzro-node target/release/tenzro-node; \
    else \
        cargo build --release --locked -p tenzro-node -p tenzro-cli; \
    fi


# Stage 2: Runtime
FROM docker.io/library/ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852 AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3t64 \
    curl \
    libstdc++6 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r tenzro && useradd -r -g tenzro -m -d /home/tenzro tenzro

# Copy binaries from builder
COPY --from=builder /build/target/release/tenzro-node /usr/local/bin/tenzro-node
COPY --from=builder /build/target/release/tenzro /usr/local/bin/tenzro-cli

# Create data directories
# One root for everything on the persistent volume. `TENZRO_HOME` moves the
# shared model store, the HuggingFace cache, and any per-instance data dir
# onto /data/tenzro, which is the mounted volume. Keeping weights off the
# container's ephemeral layer means a restart does not re-download them.
#
# `--data-dir /data/tenzro` stays pinned in CMD below. That is the documented
# escape hatch, and it is used here deliberately: the chain database lives at
# /data/tenzro/db rather than under /data/tenzro/instances/default.
ENV TENZRO_HOME=/data/tenzro
RUN mkdir -p /data/tenzro/models /data/tenzro/hf /config && chown -R tenzro:tenzro /data /config

USER tenzro
WORKDIR /home/tenzro

# Expose ports
# P2P, JSON-RPC, Web API, Metrics, MCP, A2A
EXPOSE 9000 8545 8080 9090 3001 3002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/verify/health || exit 1

# Default entrypoint
ENTRYPOINT ["tenzro-node"]

# Default args (override with docker run args)
CMD ["--data-dir", "/data/tenzro", "--log-level", "info"]
