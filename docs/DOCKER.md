# Run a node in Docker

Every release publishes container images of `tenzro-node` next to the release
archives. The tags carry the release line the build script names
(`launch` today), whichever phase the network is in. Each image carries the binaries of the matching archive,
unchanged, on a minimal base image.

| Tag | Platforms | Base | Serves models on |
|---|---|---|---|
| `tenzro-node:launch-cpu` | linux/amd64, linux/arm64 | Ubuntu 24.04 | the CPU (CPU-tier models) |
| `tenzro-node:launch-cuda` | linux/amd64, linux/arm64 | NVIDIA CUDA runtime, Ubuntu 24.04 | NVIDIA GPUs (llama.cpp and ONNX models) |
| `tenzro-node:launch-vulkan` | linux/amd64, linux/arm64 | Ubuntu 24.04, Vulkan loader, Mesa Vulkan drivers | AMD, Intel and NVIDIA GPUs through Vulkan (llama.cpp models) |

Each tag also exists pinned to the release commit:
`tenzro-node:launch-<commit>-<flavour>`. Use the pinned tag in anything you
deploy, so a host always runs the build you checked.

The Vulkan image serves llama.cpp models on the GPU. ONNX Runtime has no Vulkan
provider, so on an NVIDIA or AMD GPU it refuses ONNX models (embeddings,
vision, audio and the other ONNX runtimes) and names the CUDA or ROCm build
that serves them. A GPU image never falls back to the CPU: on a host where it
finds no usable GPU it stops at startup and names the CPU image.

## What the host needs

- Linux with a TPM 2.0 at `/dev/tpmrm0`. The node's identity and keys live in
  the TPM. The container refuses to start without it; it never generates a
  software key instead.
- The node's persistent TPM keys, made once with `tpm provision` (below). The
  attestation key among them authorises the node's key derivation root: every
  use carries its fresh signature, made in the TPM, and the host's secure-boot
  state (PCR 7) must be the one the root was made in. No secret is stored. A
  change of secure-boot state makes the root unusable: the node's derived keys
  are then replaced, as on a new machine.
- For `cuda`: the NVIDIA driver and the NVIDIA Container Toolkit.
- For `vulkan`: on AMD and Intel, the kernel GPU driver (`/dev/dri`); the image
  brings the Mesa Vulkan drivers. On NVIDIA, the NVIDIA driver and the NVIDIA
  Container Toolkit, which mounts the driver's Vulkan support.

## Ports and volumes

The image runs as the unprivileged user `tenzro` (uid 10001, gid 10001).

| What | Where | Notes |
|---|---|---|
| Data volume | `/data/tenzro` | Chain state, models and the wrapped TPM key blobs (ciphertext under this host's TPM, useless anywhere else). Mount a named volume or a directory owned by uid 10001. |
| P2P | UDP `9001` | Outbound is enough; inbound is optional. See [Node networking](NODE-NETWORKING.md). |
| JSON-RPC | TCP `8545`, loopback | Never open it to the network; put your own reverse proxy in front. |
| Web API and health | TCP `8080`, loopback | `GET /health` answers 200 while the node is up. |
| MCP | TCP `3001`, loopback | |
| A2A | TCP `3002`, loopback | |

The node binds its APIs to loopback only. Run the container with
`--network host` so they are on the host's loopback, where your reverse proxy
reaches them, and the P2P endpoint uses the host's UDP port directly.

The image's health check calls the node's own `/health` endpoint on port 8080
every 30 seconds; `docker ps` shows the result.

## One-time setup

Create a host user with the image's uid that may use Docker and the TPM. The
TPM is the boundary of the node's keys: give `/dev/tpmrm0` to this user alone.

```bash
sudo useradd --system --uid 10001 --user-group --create-home tenzro
sudo usermod -aG docker,"$(stat -c %G /dev/tpmrm0)" tenzro
sudo install -d -o 10001 -g 10001 -m 0700 /srv/tenzro
```

## The service

In a unit file `$$` passes a `$` to the shell. Save this as
`/etc/systemd/system/tenzro-node.service`, choosing the image line for your
hardware:

```ini
[Unit]
Description=Tenzro node
After=docker.service
Requires=docker.service

[Service]
User=tenzro
Environment=IMAGE=tenzro-node:launch-<commit>-cpu
# The group id of /dev/tpmrm0 (stat -c %g /dev/tpmrm0)
Environment=TPM_GID=<gid>
# NVIDIA:            Environment=GPU=--gpus all
# AMD or Intel:      Environment=GPU=--device /dev/dri --group-add <gid of /dev/dri/renderD128>
# Vulkan on NVIDIA:  Environment=GPU=--gpus all -e NVIDIA_DRIVER_CAPABILITIES=compute,utility,graphics
Environment=GPU=
ExecStartPre=-/usr/bin/docker rm -f tenzro-node
ExecStart=/bin/sh -c 'exec /usr/bin/docker run --name tenzro-node --rm --network host \
    --device /dev/tpmrm0 --group-add $$TPM_GID $$GPU \
    -v /srv/tenzro:/data/tenzro \
    "$$IMAGE" --roles validator,storage'
ExecStop=/usr/bin/docker stop tenzro-node
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Create the node's TPM keys once, with the same mounts, before the first start.
Provisioning makes the storage root, the attestation key and the node identity
key at free persistent handles and never evicts or overwrites a handle that is
already in use:

```bash
sudo -u tenzro docker run --rm --network none \
    --device /dev/tpmrm0 --group-add "$(stat -c %g /dev/tpmrm0)" \
    -v /srv/tenzro:/data/tenzro \
    tenzro-node:launch-<commit>-cpu tpm provision
sudo systemctl daemon-reload
sudo systemctl enable --now tenzro-node
```

## Check the hardware first

`hardware` needs no TPM. It prints the build, the GPUs it can drive, the ONNX
Runtime providers it will use, and whether the node would start:

```bash
docker run --rm tenzro-node:launch-cpu hardware
docker run --rm --gpus all tenzro-node:launch-cuda hardware
docker run --rm --device /dev/dri tenzro-node:launch-vulkan hardware
```

A Vulkan image on a host with a GPU prints `build: Vulkan`, `gpus: 1` (or
more) and `startup: ok`. Set `GGML_VK_VISIBLE_DEVICES` to a comma-separated
list of device indices to choose GPUs; an empty value hides every GPU.

## When the container stops at once

| Message | Fix |
|---|---|
| `no TPM: /dev/tpmrm0 is not in this container` | Add `--device /dev/tpmrm0`. |
| `the TPM at /dev/tpmrm0 is not readable and writable` | Add `--group-add "$(stat -c %g /dev/tpmrm0)"`. |
| `the root's authorising key 0x81018001 cannot be read` | Run `tpm provision` once (above). |
| `is not certified by this TPM's endorsement key` | `[tpm] root_authorization_handle` names a key that is not this TPM's endorsement-hierarchy attestation key; use the one `tpm provision` made. |
| `this is the Vulkan build of tenzro-node, but no usable Vulkan GPU or driver was found` | Pass the GPU (`--device /dev/dri`, or `--gpus all` on NVIDIA), or run the CPU image. |
| `this is the CUDA build of tenzro-node, but no usable CUDA GPU or driver was found` | Add `--gpus all` and install the NVIDIA Container Toolkit, or run the CPU image. |
