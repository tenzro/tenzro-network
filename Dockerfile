# Stage 1: Build
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    cmake \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Force clang as the C/C++ compiler (required by llama-cpp-sys-2 which uses clang-specific flags)
ENV CC=clang
ENV CXX=clang++

# Copy workspace files
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
COPY sdk/ sdk/
COPY tools/ tools/
# vendor/* subtrees (erc8004-evm, erc8004-solana, erc8004-daml, erc8004-atom)
# are source artifacts for regenerate.sh / DAML compilation, not build-time
# dependencies — they're copied here because COPY vendor/ is a single layer
# and the cost is negligible vs. surgical sub-copies.
COPY vendor/ vendor/

# Create minimal stub for desktop app workspace member (not built, but cargo needs it to resolve workspace)
# The real Cargo.toml is excluded by .gcloudignore (apps/), so we generate a stub inline
# NOTE: Cannot use shell heredocs here — Docker's classic parser interprets each line as a
# Dockerfile instruction, so [package] would be parsed as unknown instruction [PACKAGE].
RUN mkdir -p apps/tenzro-desktop/src-tauri/src && \
    echo "fn main() {}" > apps/tenzro-desktop/src-tauri/src/main.rs && \
    echo "fn main() {}" > apps/tenzro-desktop/src-tauri/build.rs && \
    printf '%s\n' \
      '[package]' \
      'name = "tenzro-desktop"' \
      'version = "0.1.0"' \
      'edition = "2021"' \
      '' \
      '[build-dependencies]' \
      'tauri-build = { version = "2", features = [] }' \
      '' \
      '[dependencies]' \
      'tauri = { version = "2", features = ["tray-icon"] }' \
      'tauri-plugin-shell = "2"' \
      'serde = { version = "1", features = ["derive"] }' \
      'serde_json = "1"' \
      'tokio = { version = "1", features = ["full"] }' \
      'reqwest = { version = "0.12", features = ["json", "stream"] }' \
      'futures-util = "0.3"' \
      'thiserror = "2"' \
      'tracing = "0.1"' \
      'uuid = { version = "1", features = ["v4"] }' \
      'hex = "0.4"' \
      'dirs = "5"' \
      'sysinfo = "0.31"' \
      'sha2 = "0.10"' \
      'aes-gcm = "0.10"' \
      'rand = "0.8"' \
      'hostname = "0.4"' \
      'tenzro-model = { path = "../../../crates/tenzro-model" }' \
      'tenzro-zk = { path = "../../../crates/tenzro-zk" }' \
      '' \
      '[features]' \
      'default = ["custom-protocol"]' \
      'custom-protocol = ["tauri/custom-protocol"]' \
      > apps/tenzro-desktop/src-tauri/Cargo.toml

# Build tenzro-node and tenzro-cli (excludes desktop app)
RUN cargo build --release -p tenzro-node -p tenzro-cli

# The `rpc` feature (on by default via cluster-serving) builds the standalone
# ggml `rpc-server` binary into llama-cpp-sys-2's cargo OUT_DIR. That path does
# not survive into the runtime stage, so stage it at a fixed location for COPY.
# The final ldd guard fails the build if rpc-server links a ggml/llama shared
# object: the slim runtime only carries libstdc++/libgomp/libssl, so a shared
# ggml link would ENOENT at exec on the fleet. Default build is static; this
# guards against a future dynamic-link regression.
RUN set -eux; \
    src="$(find target/release/build -type f -name rpc-server -perm -u+x 2>/dev/null | head -n1)"; \
    test -n "$src"; \
    cp "$src" /build/rpc-server; \
    ldd /build/rpc-server || true; \
    ! ldd /build/rpc-server | grep -qiE 'libggml|libllama|not found'

# Stage 2: Runtime
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    libstdc++6 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r tenzro && useradd -r -g tenzro -m -d /home/tenzro tenzro

# Copy binaries from builder
COPY --from=builder /build/target/release/tenzro-node /usr/local/bin/tenzro-node
COPY --from=builder /build/target/release/tenzro /usr/local/bin/tenzro-cli
# ggml rpc-server sidecar for LAN cluster serving; the node resolves it via
# TENZRO_RPC_SERVER_BIN (overrides the compile-time OUT_DIR path that the
# multi-stage build discards).
COPY --from=builder /build/rpc-server /usr/local/bin/rpc-server
ENV TENZRO_RPC_SERVER_BIN=/usr/local/bin/rpc-server

# Create data directories
RUN mkdir -p /data/tenzro /config /home/tenzro/.tenzro/models && chown -R tenzro:tenzro /data /config /home/tenzro/.tenzro

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
