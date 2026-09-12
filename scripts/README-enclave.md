# Rental enclave — operator launcher

The node's `KataConfinement` (`crates/tenzro-node/src/remote_access_session.rs`)
does not start VMs itself: it runs an **operator-supplied launcher**, hands it
the lease's `AccessScope` as JSON on stdin, and relays the renter's PTY. This
directory is the reference launcher.

- `enclave-kata-launcher.sh` — the launcher the node runs. Parses the scope,
  applies CPU/memory/storage limits, injects **only** the renter's SSH key, and
  boots a Kata microVM (a real kernel boundary — the renter never lands on the
  host). GPU grants attempt VFIO passthrough and **refuse cleanly** when the
  host can't do it (see below).
- `enclave-host-lib.sh` — the per-host seam: this machine's VFIO/IOMMU binding,
  its accelerator numbering, its capped-volume mechanism. The knowledge that is
  specific to one box lives here, never in the node binary.

Everything is **open-source and free**: Kata Containers (Apache-2.0),
cloud-hypervisor (Apache-2.0) or QEMU (GPL-2.0), jq (MIT). No NVIDIA GPU
Operator, no Kubernetes, no subscription.

## Install (Ubuntu, one box)

```sh
# Kata + a VMM (cloud-hypervisor is a good aarch64 default; QEMU also works)
sudo apt-get install -y kata-runtime jq
# cloud-hypervisor: from the project's release tarball (Apache-2.0), placed on PATH
# then point the node at the launcher:
sudo install -m0755 scripts/enclave-kata-launcher.sh scripts/enclave-host-lib.sh /usr/local/lib/tenzro/
# tell the node where the launcher is — it reads this env var and enables
# Kata confinement when set (unset = interactive sessions are refused, the safe
# default):
#   TENZRO_CONFINEMENT_LAUNCHER=/usr/local/lib/tenzro/enclave-kata-launcher.sh
```

## GPU passthrough status per host

`gpu_passthrough_supported()` gates GPU-bearing leases. It requires
`/dev/vfio`, IOMMU groups, `/dev/kvm`, and — critically — a VFIO variant driver
that can map **this** accelerator's memory into a guest.

- **Discrete datacenter GPUs** (vfio-pci binds directly): GPU leases work once
  Kata + a VMM are installed.
- **Grace-Blackwell (GB10 / DGX Spark, GB200)**: passthrough is **blocked today**.
  The platform firmware requires a 1:1 IOMMU mapping and the coherent-memory
  VFIO path (`nvgrace-gpu`) plus the KVM changes that map device memory as
  Normal-with-ECC are still landing upstream (tracking: NVIDIA/OpenShell#1780;
  QEMU 9.0 added the Grace generic-initiator change; the KVM/`nvgrace-gpu` bits
  follow). Until `nvgrace-gpu` is loaded, the launcher **refuses** a GPU lease
  with a precise reason rather than boot a VM that cannot see the accelerator.
  CPU / memory / storage leases work now. GPU leases start working the moment
  the driver is present — **no code change**, the gate flips on its own.

So this ships **real microVM isolation for CPU/memory/storage rentals today**,
and GPU rentals light up automatically when the GB10's upstream kernel support
arrives.
