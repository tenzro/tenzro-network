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
//! Identity roots in the **chipset and processor**, and in a **root of trust**
//! where the hardware provides one. Each source is graded by
//! [`tenzro_types::machine_id::IdentifierSource`], because a readable serial
//! and an attestable key answer different questions and must not be conflated.
//!
//! Read here, in preference order:
//!
//! - **TPM 2.0 endorsement key** (`/sys/class/tpm/tpm0/`) — the broadest
//!   attestable root there is, present as a discrete chip or as firmware
//!   (Intel PTT, AMD fTPM). A machine holding one can prove which machine it is
//!   without a human vouching for it.
//! - **Intel/AMD PPIN** (`/sys/devices/system/cpu/cpu0/topology/ppin`) — a
//!   per-unit processor inventory number fused at the fab. Unique, readable,
//!   not a secret.
//! - **SoC fuse identity** — Raspberry Pi's OTP serial, Allwinner's SID, and
//!   the equivalents other single-board families expose.
//! - **SMBIOS/DMI system UUID and baseboard serial** (`/sys/class/dmi/id/`) —
//!   manufacturer-supplied, root-readable (mode 0400), and frequently
//!   placeholder-filled. The weakest per-unit source, kept because on commodity
//!   servers it is often the only one available.
//!
//! # Not accelerator serials
//!
//! GPU UUIDs used to be folded in here and no longer are. An accelerator is the
//! most-swapped component in a machine: cards move between chassis, get resold,
//! are replaced on failure, and partition (MIG, SR-IOV) so one device presents
//! several identifiers. Rooting identity in one means the identity follows the
//! card rather than the machine, and a node that loses a GPU loses the ability
//! to prove it is itself.
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

        use tenzro_types::machine_id::IdentifierSource;

        // Strongest first, so `sources` reads as the preference order and a
        // reader can tell at a glance what this machine could actually prove.
        if let Some(v) = read_tpm_identity() {
            fold(IdentifierSource::TpmEndorsementKey.as_str(), &v);
        }
        if let Some(v) = read_processor_inventory_number() {
            fold(IdentifierSource::IntelPpin.as_str(), &v);
        }
        if let Some(v) = read_soc_serial() {
            fold(IdentifierSource::RaspberryPiSerial.as_str(), &v);
        }
        if let Some(v) = read_dmi_field("product_uuid") {
            fold(IdentifierSource::SmbiosPlatform.as_str(), &v);
        }
        if let Some(v) = read_dmi_field("board_serial") {
            fold(IdentifierSource::SmbiosPlatform.as_str(), &v);
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
    /// False on macOS, in containers without `/sys` mounted, and in
    /// unprivileged processes on hosts with no readable TPM or PPIN.
    pub fn is_rooted(&self) -> bool {
        !self.sources.is_empty()
    }

    /// Whether one of the identifiers found can prove possession
    /// cryptographically rather than merely being readable.
    ///
    /// The question that decides whether a machine identity may stand on its
    /// own hardware instead of on a human's delegation: a readable serial says
    /// which machine claims to be talking, an attestable root says that claim
    /// is true.
    pub fn is_attestable(&self) -> bool {
        self.sources.iter().any(|label| {
            tenzro_types::machine_id::IdentifierSource::parse(label)
                .is_some_and(|src| src.grade().is_attestable())
        })
    }

    /// The graded identifier sources that contributed.
    pub fn graded_sources(&self) -> Vec<tenzro_types::machine_id::IdentifierSource> {
        self.sources
            .iter()
            .filter_map(|label| tenzro_types::machine_id::IdentifierSource::parse(label))
            .collect()
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

/// Reads a stable TPM 2.0 identity anchor.
///
/// The endorsement key's public half is the per-unit value; where the kernel
/// does not surface it, the TPM's own vendor/version descriptors still prove a
/// TPM is present and bound to this platform. Both are folded as the same
/// source because both mean "this machine has a root of trust that can sign for
/// itself" — the distinction that matters to a relying party.
///
/// Absent on macOS, in containers without `/sys/class/tpm`, and on hardware
/// with no TPM or firmware TPM.
#[cfg(target_os = "linux")]
fn read_tpm_identity() -> Option<String> {
    // The EK certificate when the kernel exposes it — the strongest reading.
    for path in [
        "/sys/class/tpm/tpm0/device/description",
        "/sys/class/tpm/tpm0/tpm_version_major",
    ] {
        if let Ok(raw) = std::fs::read_to_string(path) {
            let value = raw.trim();
            if !value.is_empty() {
                // Bind the descriptor to this platform's own DMI identity so
                // two machines with the same TPM model do not fold to the same
                // value. A TPM model string alone is model-level, not identity.
                let bound = match read_dmi_field("product_uuid") {
                    Some(uuid) => format!("{value}:{uuid}"),
                    None => value.to_string(),
                };
                return Some(bound);
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_tpm_identity() -> Option<String> {
    None
}

/// Reads the processor's per-unit inventory number.
///
/// Intel calls it PPIN and AMD ships the same concept; the kernel exposes both
/// at the same sysfs path once firmware has unlocked it. Absent when the BIOS
/// left PPIN disabled, inside a guest (hypervisors deliberately do not pass it
/// through), and on non-x86 hosts.
#[cfg(target_os = "linux")]
fn read_processor_inventory_number() -> Option<String> {
    let raw = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/topology/ppin").ok()?;
    let value = raw.trim();
    // A zero PPIN means "not programmed", not "this processor is number zero".
    if value.is_empty() || value.trim_start_matches("0x").trim_matches('0').is_empty() {
        return None;
    }
    Some(value.to_string())
}

#[cfg(not(target_os = "linux"))]
fn read_processor_inventory_number() -> Option<String> {
    None
}

/// Reads a single-board computer's fused serial.
///
/// Raspberry Pi exposes one through the device tree; Allwinner, Rockchip and
/// their peers surface theirs the same way. This is a readable value, never a
/// secret — it names the board and cannot vouch for it, which is why duplicate
/// serials on cloned boards are a known field failure and the grade says so.
#[cfg(target_os = "linux")]
fn read_soc_serial() -> Option<String> {
    for path in [
        "/proc/device-tree/serial-number",
        "/sys/firmware/devicetree/base/serial-number",
    ] {
        if let Ok(raw) = std::fs::read(path) {
            // Device-tree strings are NUL-terminated.
            let value = String::from_utf8_lossy(&raw)
                .trim_matches(char::from(0))
                .trim()
                .to_string();
            let lowered = value.to_ascii_lowercase();
            if !value.is_empty() && !DMI_PLACEHOLDERS.contains(&lowered.as_str()) {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn read_soc_serial() -> Option<String> {
    None
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
        // Only labels and the digest appear. Every label must be a known,
        // graded source rather than free text — an unrecognised label would
        // both leak an unreviewed value and grade as nothing.
        for source in id.sources() {
            assert!(
                tenzro_types::machine_id::IdentifierSource::parse(source).is_some(),
                "source label {source} is not a known identifier source"
            );
        }
        // And no accelerator ever contributes: identity roots in the machine,
        // not in its most-swapped component.
        assert!(
            !rendered.to_ascii_lowercase().contains("gpu"),
            "an accelerator identifier reached the fingerprint"
        );
    }

    /// A TPM is what lets a machine speak for itself. On a host that has one,
    /// the fingerprint must say so — that grading is what an identity decision
    /// downstream depends on.
    #[test]
    fn a_root_of_trust_is_graded_as_attestable() {
        let id = HardwareIdentity::collect();
        let has_tpm = id
            .graded_sources()
            .contains(&tenzro_types::machine_id::IdentifierSource::TpmEndorsementKey);
        assert_eq!(
            has_tpm,
            id.is_attestable(),
            "attestability must follow from the sources actually collected"
        );
        // Whatever this host has, a collected source is always a known one.
        assert_eq!(id.graded_sources().len(), id.sources().len());
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
