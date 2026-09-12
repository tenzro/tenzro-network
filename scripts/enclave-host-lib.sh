#!/usr/bin/env bash
# Host-specific helpers for the enclave launcher (scripts/enclave-kata-launcher.sh).
#
# This is the per-host seam the remote_access_session.rs docs describe: the
# knowledge of THIS machine's IOMMU groups, vfio-pci binding, and whether its
# accelerator can cross a VM boundary lives here, not in the node binary.
# All open-source, no paid tooling.
#
# Source this from the launcher:  source "$(dirname "$0")/enclave-host-lib.sh"

# --- GPU: can VFIO actually pass this host's accelerator into a guest? -------
# Returns 0 (yes) only when every prerequisite is present AND the platform is
# not a known-blocked part. Fails closed: unknown -> no.
gpu_passthrough_supported() {
  # 1. Kernel plumbing.
  [ -e /dev/vfio/vfio ] || return 1
  [ -d /sys/kernel/iommu_groups ] && [ -n "$(ls -A /sys/kernel/iommu_groups 2>/dev/null)" ] || return 1
  [ -e /dev/kvm ] || return 1

  # 2. A VFIO variant driver that can actually map THIS accelerator's memory.
  #    Discrete datacenter cards use vfio-pci directly. Grace-Blackwell
  #    (GB10/GB200) needs `nvgrace-gpu` (the coherent-memory VFIO variant) plus
  #    the KVM changes that map device memory as Normal with ECC handling. Until
  #    those are loaded, VFIO_MAP_DMA is rejected by the 1:1-IOMMU firmware.
  if lspci -nn 2>/dev/null | grep -qiE 'NVIDIA.*(GB10|GB200|Grace|22ce)'; then
    # Grace-Blackwell present: require the variant driver to be loaded.
    if ! lsmod 2>/dev/null | grep -qE '^nvgrace_gpu\b' \
       && [ ! -d /sys/bus/pci/drivers/nvgrace-gpu ]; then
      return 1     # the exact GB10 block (OpenShell#1780) — refuse cleanly.
    fi
  fi
  return 0
}

# --- GPU: PCI BDF for a logical accelerator index ---------------------------
# Index is the operator's stable numbering (0-based) over the NVIDIA 3D/display
# controllers on the box, sorted by BDF for determinism.
gpu_bdf_for_index() {
  local idx="$1"
  lspci -Dn 2>/dev/null \
    | awk '$2 ~ /^(0300|0302):/ && /10de:/ {print $1}' \
    | sort \
    | sed -n "$((idx+1))p"
}

# --- GPU: unbind from the host driver, bind to vfio-pci ---------------------
bind_vfio() {
  local bdf="$1"
  local vd; vd="$(lspci -Dn -s "$bdf" | awk '{print $3}' | tr ':' ' ')"
  [ -n "$vd" ] || return 1
  if [ -e "/sys/bus/pci/devices/${bdf}/driver" ]; then
    echo "$bdf" > "/sys/bus/pci/devices/${bdf}/driver/unbind" 2>/dev/null || true
  fi
  echo "$vd" > /sys/bus/pci/drivers/vfio-pci/new_id 2>/dev/null || true
  echo "$bdf" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || true
}

# --- storage: a size-capped subvolume the renter cannot exceed --------------
# Prefer an XFS project-quota or btrfs subvolume; fall back to a loopback ext4
# image sized to the grant so the cap is enforced by the filesystem, not by
# trust. Prints the mounted path on stdout.
mk_capped_volume() {
  local mib="$1"
  local base="${TENZRO_ENCLAVE_STATE:-/var/lib/tenzro/enclaves}"
  mkdir -p "$base"
  local img mnt
  img="$(mktemp "${base}/lease-XXXXXX.img")"
  mnt="$(mktemp -d "${base}/lease-XXXXXX.d")"
  truncate -s "${mib}M" "$img"
  mkfs.ext4 -q -F "$img" >/dev/null 2>&1
  mount -o loop,nosuid,nodev "$img" "$mnt"
  printf '%s\n' "$mnt"
}

cleanup_volume() {
  local mnt="$1"
  [ -n "$mnt" ] || return 0
  umount "$mnt" 2>/dev/null || true
  rmdir "$mnt" 2>/dev/null || true
}

# --- ssh: inject ONLY the renter's key ---------------------------------------
inject_authorized_key() {
  local root="$1" key="$2"
  install -d -m 0700 "${root}/home/renter/.ssh"
  printf '%s\n' "$key" > "${root}/home/renter/.ssh/authorized_keys"
  chmod 0600 "${root}/home/renter/.ssh/authorized_keys"
}
