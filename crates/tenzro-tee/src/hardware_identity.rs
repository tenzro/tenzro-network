//! Stable hardware identifiers folded into a machine-identity root.
//!
//! # What this is for
//!
//! A node's descriptive hardware profile — CPU model, core count, RAM, GPU
//! names — describes a *class* of machine, not a machine. Two nodes rented
//! from the same cloud SKU produce byte-identical descriptions. Anything that
//! wants to say "this is the same physical box that registered last week"
//! needs identifiers that are unique per unit and survive a reboot, an OS
//! reinstall, and a software upgrade.
//!
//! Three such identifiers are read here:
//!
//! - **SMBIOS/DMI system UUID** (`/sys/class/dmi/id/product_uuid`) — assigned
//!   per system by the manufacturer or, on a VM, by the hypervisor. Readable
//!   only by root on Linux (mode 0400), because it is a machine-unique value.
//! - **SMBIOS/DMI baseboard serial** (`/sys/class/dmi/id/board_serial`) — the
//!   motherboard's serial number, same permission posture.
//! - **NVIDIA GPU UUIDs** — `nvmlDeviceGetUUID` returns a per-board
//!   `GPU-xxxxxxxx-...` string burned in at manufacture. Collected for every
//!   visible device and sorted, so PCIe enumeration order does not perturb the
//!   result.
//!
//! # Privacy posture
//!
//! Raw serials never leave this module. They are folded into a SHA-256 root
//! and only the root is exposed, so a published fingerprint cannot be reversed
//! into a manufacturer's serial number. [`HardwareIdentity`] carries a manual
//! `Debug` for the same reason — deriving it would leak the inputs into any
//! log line that formats a profile.
//!
//! # Partial and absent sources
//!
//! Every source is optional. A container without `/sys/class/dmi` mounted, an
//! unprivileged process, a CPU-only host, a machine whose manufacturer left
//! the SMBIOS fields as placeholder text — all of these yield fewer sources,
//! not an error. [`HardwareIdentity::is_rooted`] reports whether *any* source
//! was found; callers decide what to do with an unrooted machine rather than
//! having a hard failure imposed on them here.
//!
//! Because the fold is order-fixed and length-prefixed, a host that gains a
//! source later (a GPU is installed, the node is granted root) produces a
//! different root. That is the correct behaviour: the identity claim being
//! made is over the identifiers actually observed, so it must change when the
//! evidence does.

use sha2::{Digest, Sha256};

/// Domain separation tag for the identity fold.
const ROOT_DOMAIN: &[u8] = b"tenzro/hardware-identity";

/// Directory holding the kernel's decoded SMBIOS/DMI table on Linux.
const DMI_DIR: &str = "/sys/class/dmi/id";

/// Placeholder strings manufacturers leave in unpopulated SMBIOS fields.
///
/// These are matched case-insensitively. A board that reports one of them is
/// telling us the field was never programmed, which is not an identifier —
/// treating it as one would make every unit from that vendor look like the
/// same machine.
const DMI_PLACEHOLDERS: &[&str] = &[
    "",
    "0",
    "none",
    "null",
    "unknown",
    "default string",
    "not specified",
    "not available",
    "not applicable",
    "to be filled by o.e.m.",
    "system serial number",
    "base board serial number",
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
];

/// A machine-identity root derived from per-unit hardware identifiers.
#[derive(Clone)]
pub struct HardwareIdentity {
    /// Labels of the sources that contributed, in fold order. Safe to log —
    /// these name the *kind* of identifier, never its value.
    sources: Vec<String>,
    root: [u8; 32],
}

impl HardwareIdentity {
    /// Reads every available identifier and folds them into the root.
    ///
    /// Performs blocking filesystem reads and, on Linux with the
    /// `nvidia-gpu` feature, a `dlopen` of `libnvidia-ml.so.1`. Call it from
    /// `spawn_blocking` on an async executor.
    pub fn collect() -> Self {
        let mut sources = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(ROOT_DOMAIN);

        let mut fold = |label: &str, value: &str| {
            sources.push(label.to_string());
            hasher.update((label.len() as u32).to_le_bytes());
            hasher.update(label.as_bytes());
            hasher.update((value.len() as u32).to_le_bytes());
            hasher.update(value.as_bytes());
        };

        if let Some(v) = read_dmi_field("product_uuid") {
            fold("dmi:product_uuid", &v);
        }
        if let Some(v) = read_dmi_field("board_serial") {
            fold("dmi:board_serial", &v);
        }
        for uuid in collect_gpu_uuids() {
            fold("gpu:uuid", &uuid);
        }

        Self {
            sources,
            root: hasher.finalize().into(),
        }
    }

    /// The 32-byte root over every identifier that was found.
    ///
    /// On a host with no identifiers this is the hash of the domain tag alone
    /// — identical across every such host — so check [`is_rooted`] before
    /// treating it as a machine-unique value.
    ///
    /// [`is_rooted`]: Self::is_rooted
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Lowercase hex of [`root`](Self::root).
    pub fn root_hex(&self) -> String {
        hex::encode(self.root)
    }

    /// Labels of the identifier sources that contributed, in fold order.
    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// Whether at least one per-unit identifier was found.
    ///
    /// False on macOS, in containers without `/sys/class/dmi` mounted, and in
    /// unprivileged processes on hosts with no NVIDIA GPU.
    pub fn is_rooted(&self) -> bool {
        !self.sources.is_empty()
    }
}

impl std::fmt::Debug for HardwareIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareIdentity")
            .field("sources", &self.sources)
            .field("root", &self.root_hex())
            .finish()
    }
}

/// Reads one DMI field, rejecting placeholder values.
///
/// Returns `None` for an absent file (no SMBIOS, container without `/sys`),
/// a permission error (the machine-unique fields are 0400 root-only), or a
/// value the manufacturer never programmed.
fn read_dmi_field(name: &str) -> Option<String> {
    let raw = std::fs::read_to_string(format!("{}/{}", DMI_DIR, name)).ok()?;
    let value = raw.trim();
    let lowered = value.to_ascii_lowercase();
    if DMI_PLACEHOLDERS.contains(&lowered.as_str()) {
        return None;
    }
    Some(value.to_string())
}

/// Reads the UUID of every visible NVIDIA device, sorted.
///
/// NVML has no device-count entry point bound here, so enumeration walks
/// indices until the driver refuses one — the documented termination
/// condition for `nvmlDeviceGetHandleByIndex`.
#[cfg(all(target_os = "linux", feature = "nvidia-gpu"))]
fn collect_gpu_uuids() -> Vec<String> {
    let Ok(nvml) = crate::nvml::Nvml::open() else {
        return Vec::new();
    };
    let mut uuids = Vec::new();
    for index in 0u32.. {
        let Ok(device) = nvml.device_by_index(index) else {
            break;
        };
        match nvml.device_uuid(device) {
            Ok(uuid) => uuids.push(uuid),
            Err(_) => break,
        }
    }
    uuids.sort();
    uuids
}

#[cfg(not(all(target_os = "linux", feature = "nvidia-gpu")))]
fn collect_gpu_uuids() -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_is_deterministic() {
        // The whole premise of a machine-identity root is that it reproduces.
        // Two reads of the same host must agree.
        let a = HardwareIdentity::collect();
        let b = HardwareIdentity::collect();
        assert_eq!(a.root(), b.root());
        assert_eq!(a.sources(), b.sources());
    }

    #[test]
    fn unrooted_host_is_reported_as_such() {
        let id = HardwareIdentity::collect();
        // On a dev machine (macOS, or Linux without root and without a GPU)
        // no source is available and the root is the bare domain hash.
        if !id.is_rooted() {
            let expected: [u8; 32] = Sha256::digest(ROOT_DOMAIN).into();
            assert_eq!(id.root(), expected);
        } else {
            assert!(!id.sources().is_empty());
        }
    }

    #[test]
    fn placeholder_serials_are_rejected() {
        // Every placeholder is matched case-insensitively after trimming, so
        // a board reporting "To Be Filled By O.E.M." contributes nothing.
        for raw in [
            "  To Be Filled By O.E.M. \n",
            "Default String",
            "00000000-0000-0000-0000-000000000000",
            "\n",
        ] {
            let lowered = raw.trim().to_ascii_lowercase();
            assert!(
                DMI_PLACEHOLDERS.contains(&lowered.as_str()),
                "{:?} should be treated as a placeholder",
                raw
            );
        }
    }

    #[test]
    fn debug_does_not_leak_identifier_values() {
        let id = HardwareIdentity::collect();
        let rendered = format!("{:?}", id);
        assert!(rendered.contains("root"));
        // Only labels and the digest appear; source labels are namespaced
        // kinds, never values.
        for source in id.sources() {
            assert!(source.starts_with("dmi:") || source.starts_with("gpu:"));
        }
    }

    #[test]
    fn sources_are_folded_with_length_prefixes() {
        // Length prefixing is what stops two different splits of the same
        // concatenation from colliding. Reproduce the fold by hand for a
        // known pair and confirm a shifted split differs.
        let fold = |pairs: &[(&str, &str)]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(ROOT_DOMAIN);
            for (label, value) in pairs {
                h.update((label.len() as u32).to_le_bytes());
                h.update(label.as_bytes());
                h.update((value.len() as u32).to_le_bytes());
                h.update(value.as_bytes());
            }
            h.finalize().into()
        };
        assert_ne!(
            fold(&[("dmi:product_uuid", "ab"), ("dmi:board_serial", "c")]),
            fold(&[("dmi:product_uuid", "a"), ("dmi:board_serial", "bc")]),
        );
    }
}
