# Container image of a tenzro-node release archive. Nothing is compiled here:
# the image carries the binaries of the archive it was built from, unchanged,
# so the image and the archive have the same digest-checked contents.
#
# Built by scripts/release/build-image.sh, which passes the base image (pinned
# by digest) and the runtime packages for the flavour:
#   cpu     Ubuntu 24.04
#   vulkan  Ubuntu 24.04, the Vulkan loader and the Mesa Vulkan drivers
#           (AMD and Intel GPUs through /dev/dri; NVIDIA through the NVIDIA
#           container toolkit, which mounts the driver's own Vulkan support)
#   cuda    NVIDIA CUDA runtime with cuDNN (Ubuntu 24.04), and the ONNX Runtime
#           libraries from the archive's lib/
ARG BASE
FROM ${BASE}

ARG PACKAGES
ARG FLAVOUR
ARG COMMIT
ARG VERSION=launch

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates ${PACKAGES} \
    && rm -rf /var/lib/apt/lists/*

# A fixed, unprivileged user, so an operator can match its uid on the host
# (data volume ownership, the credential directory).
RUN groupadd --system --gid 10001 tenzro \
    && useradd --system --uid 10001 --gid 10001 --home-dir /home/tenzro --create-home tenzro

COPY archive/bin/tenzro-node /usr/local/bin/tenzro-node
COPY archive/bin/tenzro /usr/local/bin/tenzro
# The CUDA build resolves ONNX Runtime through its $ORIGIN/../lib run path;
# other builds have no lib/ and this copies nothing.
COPY archive/lib/ /usr/local/lib/
COPY entrypoint.sh /usr/local/bin/tenzro-entrypoint

# Everything the node keeps lives on one volume: chain state, models, and the
# wrapped TPM key blobs (ciphertext under this machine's TPM, useless elsewhere).
ENV TENZRO_HOME=/data/tenzro \
    TENZRO_DATA_DIR=/data/tenzro \
    TENZRO_DEVICE_KEY_DIR=/data/tenzro/device-keys
RUN mkdir -p /data/tenzro \
    && chown -R tenzro:tenzro /data \
    && chmod 0700 /data/tenzro
VOLUME ["/data/tenzro"]

LABEL org.opencontainers.image.title="tenzro-node" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="https://github.com/tenzro/tenzro-network" \
      com.tenzro.flavour="${FLAVOUR}"

USER tenzro
WORKDIR /home/tenzro

# The node's own health endpoint on its web API (loopback, port 8080), read
# without an HTTP client in the image.
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD ["/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /health HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && head -n1 <&3 | grep -q ' 200 '"]

ENTRYPOINT ["/usr/local/bin/tenzro-entrypoint"]
CMD ["--log-level", "info"]
