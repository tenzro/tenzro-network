#!/usr/bin/env bash
# Reference operator launcher for the Tenzro rental enclave.
#
# `KataConfinement` (crates/tenzro-node/src/remote_access_session.rs) does not
# know how to start a VM — by design. It runs THIS script, hands it the lease's
# AccessScope as JSON on stdin, and treats our stdin/stdout as the renter's PTY.
# Everything host-specific (which VMM, how VFIO binds, whether the GPU can cross
# the VM boundary on this exact part) lives here, where the operator owns it.
#
# All tooling is open-source and free:
#   - Kata Containers (Apache-2.0)      — the microVM sandbox + agent
#   - cloud-hypervisor (Apache-2.0)     — the VMM (a good aarch64 choice); QEMU
#                                         (GPL-2.0) works too, set VMM=qemu.
#   - jq (MIT)                          — parse the scope JSON
# Nothing here requires a licence, a subscription, or the NVIDIA GPU Operator.
#
# The scope JSON (see AccessScope): workspace, devices[], network, confinement,
# max_session_secs, max_memory_bytes, ... DeviceGrant is an externally-tagged
# snake_case enum, e.g.:
#   {"cpu":{"cores":8}} {"memory":{"mib":40000}} {"storage":{"mib":200000}}
#   {"accelerator":{"index":0}} {"accelerator_memory":{"index":0,"mib":40000}}
#
# Contract with the seam:
#   - stdin/stdout are the PTY. Do NOT print launcher chatter to stdout — it
#     would land in the renter's terminal. Diagnostics go to stderr.
#   - Exit non-zero with a one-line stderr reason if the session cannot start;
#     the node turns that into a clean lease failure and a receipt.

set -euo pipefail

log() { printf 'enclave-launcher: %s\n' "$*" >&2; }
die() { log "$*"; exit 1; }

command -v jq >/dev/null || die "jq not found (apt-get install jq)"

# Per-host helpers (VFIO/IOMMU knowledge, GB10 detection, capped volumes).
# shellcheck source=scripts/enclave-host-lib.sh
source "$(dirname "$(readlink -f "$0")")/enclave-host-lib.sh"

SCOPE="$(cat)"                       # the whole AccessScope, as JSON, on stdin
[ -n "$SCOPE" ] || die "empty scope on stdin"

VMM="${TENZRO_ENCLAVE_VMM:-cloud-hypervisor}"   # or 'qemu'
KATA_CONFIG="${TENZRO_KATA_CONFIG:-/etc/kata-containers/configuration.toml}"

# ---- resource grants ------------------------------------------------------
cpus="$(jq -r '[.devices[] | select(has("cpu")) | .cpu.cores] | add // 1'  <<<"$SCOPE")"
mem_mib="$(jq -r '[.devices[] | select(has("memory")) | .memory.mib] | add // 0' <<<"$SCOPE")"
# max_memory_bytes is the hard ceiling on a coherent-memory part; prefer it.
mem_bytes="$(jq -r '.max_memory_bytes // 0' <<<"$SCOPE")"
if [ "$mem_bytes" != "0" ]; then mem_mib=$(( mem_bytes / 1024 / 1024 )); fi
[ "$mem_mib" -gt 0 ] || mem_mib=2048
storage_mib="$(jq -r '[.devices[] | select(has("storage")) | .storage.mib] | add // 10240' <<<"$SCOPE")"
workspace="$(jq -r '.workspace' <<<"$SCOPE")"
max_secs="$(jq -r '.max_session_secs // 3600' <<<"$SCOPE")"
egress="$(jq -r 'if .network=="egress_only" then "on" else "off" end' <<<"$SCOPE")"

log "lease: ${cpus} vCPU, ${mem_mib} MiB RAM, ${storage_mib} MiB disk, egress=${egress}, ttl=${max_secs}s"

# ---- GPU grants: attempt VFIO, degrade cleanly on this host ----------------
# On a unified-memory part prefer AcceleratorMemory (a slice) over a whole
# Accelerator: handing over the whole device hands over the pool the node runs
# from. See remote_access.rs::DeviceGrant.
gpu_indices="$(jq -r '[.devices[] | (.accelerator.index // .accelerator_memory.index) | select(.!=null)] | unique | join(" ")' <<<"$SCOPE")"
vfio_args=()
if [ -n "$gpu_indices" ]; then
  # gpu_passthrough_supported() returns 0 only when VFIO can actually bind this
  # host's accelerator into a guest. On DGX Spark / GB10 the platform firmware
  # requires a 1:1 IOMMU mapping and the Grace-Blackwell KVM/nvgrace-gpu path is
  # still landing upstream (NVIDIA/OpenShell#1780), so passthrough fails at
  # VFIO_MAP_DMA. Refuse the GPU-bearing lease with a precise reason rather than
  # boot a VM that cannot see the accelerator — a renter paying for a GPU must
  # not get a silent CPU-only box.
  if ! gpu_passthrough_supported; then
    die "GPU passthrough is not available on this host yet: the accelerator \
requires a 1:1 IOMMU mapping and the vfio nvgrace-gpu / KVM support for this \
Grace-Blackwell part is not present. CPU/memory/storage leases work; GPU leases \
will once the upstream kernel/VMM support is installed. (tracking: OpenShell#1780)"
  fi
  for idx in $gpu_indices; do
    bdf="$(gpu_bdf_for_index "$idx")" || die "no PCI device for accelerator index $idx"
    bind_vfio "$bdf"
    vfio_args+=(--device "path=/sys/bus/pci/devices/${bdf}")
  done
  log "GPU passthrough armed for indices: ${gpu_indices}"
fi

# ---- storage: a size-capped subvolume the renter cannot exceed ------------
enclave_root="$(mk_capped_volume "$storage_mib")"    # returns a mounted, quota'd dir
trap 'cleanup_volume "$enclave_root"' EXIT

# ---- ssh key injection: ONLY the renter's key, nobody else's --------------
authorized_key="$(jq -r '.ssh_pubkey // empty' <<<"$SCOPE")"
[ -n "$authorized_key" ] || die "no ssh_pubkey in scope — cannot admit the renter"
inject_authorized_key "$enclave_root" "$authorized_key"

# ---- boot the Kata microVM, pinned to the slice, PTY on our stdio ---------
# Kata gives a real kernel boundary (not a shared-kernel container): the renter
# lands INSIDE the VM, never on the host, never near the node's sealed keys.
exec kata-runtime \
  --config "$KATA_CONFIG" \
  run \
    --cpus "$cpus" \
    --memory "${mem_mib}M" \
    --rootfs "$enclave_root" \
    --egress "$egress" \
    --timeout "$max_secs" \
    --vmm "$VMM" \
    "${vfio_args[@]}" \
    -- /bin/login -f renter

# NOTE: gpu_passthrough_supported / gpu_bdf_for_index / bind_vfio /
# mk_capped_volume / cleanup_volume / inject_authorized_key are host helpers the
# operator provides in scripts/enclave-host-lib.sh (sourced above in a real
# install). They are the per-host seam the module docs describe; this file is
# the reference orchestration around them.
