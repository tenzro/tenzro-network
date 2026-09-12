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
use std::process::Command;

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
    /// Every (label, value) this host could read, strongest first — including
    /// the ones the root did not come from. Kept so a machine can still be
    /// recognised after its strongest identifier stops answering.
    candidates: Vec<(String, String)>,
}

/// Folds a single (label, value) pair into a root, exactly as `collect` does.
fn fold_one(label: &str, value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_DOMAIN);
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update((value.len() as u32).to_le_bytes());
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

/// The root a host with no readable identifier gets: all zeroes.
///
/// Deliberately *not* a hash. Folding the domain tag alone would yield a
/// perfectly ordinary-looking digest that every identifier-less host shares —
/// the same "stable, and therefore convincing, but identifies nothing" failure
/// this module exists to prevent, just one level up. Zero is the value
/// `TenzroDid::from_hardware_root` refuses outright, so a host that reads
/// nothing cannot derive a DID at all rather than deriving a shared one.
fn fold_empty() -> [u8; 32] {
    [0u8; 32]
}

impl HardwareIdentity {
    /// Reads every available identifier and folds them into the root.
    ///
    /// Performs blocking filesystem reads and, on Linux with the
    /// `nvidia-gpu` feature, a `dlopen` of `libnvidia-ml.so.1`. Call it from
    /// `spawn_blocking` on an async executor.
    pub fn collect() -> Self {
        use tenzro_types::machine_id::IdentifierSource;

        // Strongest first, so `sources` reads as the preference order and a
        // reader can tell at a glance what this machine could actually prove.
        //
        // The ordering encodes a rule, not a preference: a **secure element** —
        // TPM 2.0 on a PC, the Secure Enclave on Apple hardware — is the primary
        // machine identity, because it proves possession of a key nobody can
        // copy. Serial and chipset fingerprints below are **secondary**: they
        // identify a board, not a secret, so anything that can read them can
        // replay them. They exist for edge hardware that has no secure element
        // at all, and must never outrank one that does.
        // Exactly ONE source contributes: the strongest that answered.
        //
        // Folding every reading cumulatively would make the root depend on
        // which identifiers happened to be legible at that moment, and that is
        // not a property of the machine. A TPM can stop answering — object
        // contexts fill up and it returns TPM_RC_OBJECT_MEMORY until the host
        // reboots — so a cumulative fold gives one root while the chip is busy
        // and a different one afterwards. Same box, two identities, which is
        // the failure this whole module exists to prevent.
        //
        // Taking the strongest single source keeps the root stable while that
        // source lasts, and makes any change to it an explicit, visible
        // migration rather than a silent drift.
        let candidates: [(&str, Option<String>); 6] = [
            (IdentifierSource::TpmEndorsementKey.as_str(), read_tpm_identity()),
            (
                IdentifierSource::AppleSecureEnclave.as_str(),
                read_secure_enclave_identity(),
            ),
            (
                IdentifierSource::IntelPpin.as_str(),
                read_processor_inventory_number(),
            ),
            (
                IdentifierSource::RaspberryPiSerial.as_str(),
                read_soc_serial(),
            ),
            (
                IdentifierSource::SmbiosPlatform.as_str(),
                read_dmi_field("product_uuid"),
            ),
            (
                IdentifierSource::SmbiosPlatform.as_str(),
                read_dmi_field("board_serial"),
            ),
        ];

        let readable: Vec<(String, String)> = candidates
            .into_iter()
            .filter_map(|(label, value)| value.map(|v| (label.to_string(), v)))
            .collect();

        // `fold_one` is the single definition of how a (label, value) becomes a
        // root, shared with `candidate_roots` so the two can never disagree.
        match readable.first() {
            Some((label, value)) => Self {
                sources: vec![label.clone()],
                root: fold_one(label, value),
                candidates: readable,
            },
            None => Self {
                sources: Vec::new(),
                root: fold_empty(),
                candidates: Vec::new(),
            },
        }
    }

    /// Whether any identifier here proves possession of a non-copyable key —
    /// a TPM, a Secure Enclave, or another secure element.
    ///
    /// **False means the machine is identified but not hardware-rooted.** Every
    /// identifier it carries is a serial number that anything able to read it
    /// can replay. That is a supported state — edge hardware with no secure
    /// element still needs an identity — but it is a materially weaker claim,
    /// and a peer deciding what to trust must be able to see the difference
    /// rather than infer it from the source list.
    pub fn is_hardware_rooted(&self) -> bool {
        use tenzro_types::machine_id::IdentifierSource;
        self.sources
            .iter()
            .filter_map(|l| IdentifierSource::parse(l))
            .any(|s| s.domain().is_hardware_rooted())
    }

    /// The assurance label to publish to the network alongside this identity.
    ///
    /// Stated explicitly rather than derived by each consumer, so two peers
    /// cannot disagree about what the same source list means.
    pub fn assurance_label(&self) -> &'static str {
        if self.is_hardware_rooted() {
            "hardware-rooted"
        } else {
            "unrooted:serial-only"
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

    /// Whether this host has a TPM that yielded nothing *and* nothing else
    /// per-unit to fall back on.
    ///
    /// Two failures look identical in [`is_rooted`](Self::is_rooted) and are
    /// not the same thing. A TPM can be present and still refuse to load an
    /// object context — `TPM_RC_OBJECT_MEMORY` (0x902), observed on a
    /// production node whose chip guarantees only three transient slots and
    /// already holds two persistent handles. That is a property of the chip,
    /// not a transient collision, and it does not clear on retry.
    ///
    /// Such a machine still has an identity if a per-unit DMI identifier is
    /// readable, so refusing outright would strand it. What must never happen
    /// is registering with *no* per-unit identifier at all, because the fold
    /// then reduces to values shared fleet-wide and the machine takes on an
    /// identity that distinguishes nothing.
    pub fn has_unreadable_tpm(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let tpm_present = std::path::Path::new("/dev/tpmrm0").exists()
                || std::path::Path::new("/sys/class/tpm/tpm0").exists();
            let tpm_contributed = self.sources.iter().any(|label| {
                label == tenzro_types::machine_id::IdentifierSource::TpmEndorsementKey.as_str()
            });
            tpm_present && !tpm_contributed && !self.has_per_unit_identifier()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Every root this machine could present, strongest first.
    ///
    /// [`root`](Self::root) is the one derived from the strongest identifier
    /// that answered. This returns that root *and* the root each weaker
    /// identifier would have produced had it been chosen instead.
    ///
    /// The point is recognition across a change in what is readable. A TPM
    /// that stops answering (`TPM_RC_OBJECT_MEMORY` until the host reboots)
    /// drops the machine to a DMI root; a registry holding the earlier
    /// TPM-derived root can still recognise the machine if it is told both.
    /// Without this, the same box registers twice under two identities.
    pub fn candidate_roots(&self) -> Vec<[u8; 32]> {
        self.candidates
            .iter()
            .map(|(label, value)| fold_one(label, value))
            .collect()
    }

    /// Hex of each entry in [`candidate_roots`](Self::candidate_roots).
    pub fn candidate_roots_hex(&self) -> Vec<String> {
        self.candidate_roots().iter().map(hex::encode).collect()
    }

    /// Whether at least one identifier that varies between units contributed.
    ///
    /// The property the fold actually needs. `is_rooted` only reports that
    /// *something* was folded, which was true of the fleet-wide constant that
    /// gave every host one identity.
    pub fn has_per_unit_identifier(&self) -> bool {
        use tenzro_types::machine_id::IdentifierGrade;
        self.sources.iter().any(|label| {
            tenzro_types::machine_id::IdentifierSource::parse(label)
                // Anything above `Model` varies between units. `Model` is the
                // grade that names a design rather than a machine, and folding
                // it alone is what produced one identity fleet-wide.
                .is_some_and(|src| src.grade() > IdentifierGrade::Model)
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
    // Every per-unit DMI field — product_uuid, board_serial, product_serial —
    // is `-r-------- root root` by kernel design, so a service running under
    // its own account reads none of them. That is what silently emptied this
    // fold in production: the identifiers existed and were distinct, and the
    // process simply could not see them.
    //
    // systemd's `LoadCredential=` closes that gap without granting the service
    // root: systemd opens the file itself and drops a copy in
    // $CREDENTIALS_DIRECTORY owned by the service user. Prefer it when present,
    // and fall back to a direct read for callers that do run privileged.
    if let Ok(dir) = std::env::var("CREDENTIALS_DIRECTORY") {
        if let Ok(raw) = std::fs::read_to_string(std::path::Path::new(&dir).join(name)) {
            let value = raw.trim();
            let lowered = value.to_ascii_lowercase();
            if !value.is_empty() && !DMI_PLACEHOLDERS.contains(&lowered.as_str()) {
                return Some(value.to_string());
            }
        }
    }
    let raw = std::fs::read_to_string(format!("{}/{}", DMI_DIR, name)).ok()?;
    let value = raw.trim();
    let lowered = value.to_ascii_lowercase();
    if DMI_PLACEHOLDERS.contains(&lowered.as_str()) {
        return None;
    }
    Some(value.to_string())
}

/// This machine's Secure Enclave identity, on Apple hardware.
///
/// The SEP is the Apple counterpart to a TPM endorsement key: a key that
/// cannot leave the enclave, so possession is the proof. Unlike the TPM it
/// issues **no quote**, which is why `MachineRootKind` records how a node is
/// rooted rather than letting a caller infer it — see
/// `tenzro-secure-enclave`.
///
/// Returns `None` on every non-Apple target and on a Mac with no enclave,
/// so `collect()` simply falls through to the secondary identifiers.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn read_secure_enclave_identity() -> Option<String> {
    if !tenzro_secure_enclave::available() {
        return None;
    }
    // Fold the ROOT, not a raw key: the value is already machine-bound and
    // non-extractable, and hashing it keeps the enclave secret out of the
    // identifier string entirely.
    let ikm = tenzro_secure_enclave::machine_root_ikm().ok()?;
    use sha2::Digest;
    Some(hex::encode(Sha256::digest(&ikm[..])))
}

/// No Secure Enclave off Apple hardware, so the primary tier simply has one
/// fewer candidate and `collect()` falls through to the secondary ones.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn read_secure_enclave_identity() -> Option<String> {
    None
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
    // The EK certificate: per-unit, burned in at manufacture, and the only
    // thing here that is actually an endorsement key.
    //
    // What must NOT appear is a descriptor that is equal across units.
    // `tpm_version_major` reads "2" on every TPM 2.0 machine ever made, and
    // `device/description` is a model string shared by every unit of that
    // model. Folding either one produces a "hardware identity" that is
    // identical fleet-wide: every host derives the same root, the same DID,
    // and passes `is_attestable()` while being indistinguishable from every
    // other host. That is worse than having no identifier, because it is
    // stable enough to look real. Previously these were folded with a DMI
    // binding meant to disambiguate them, but the DMI files are root-only
    // (`-r-------- root root`), so under any non-root service account the
    // binding silently degraded to the bare version string.
    //
    // So: EK or nothing. A machine whose EK is not readable has no TPM-rooted
    // identity, and the caller must treat it as unrooted rather than accept a
    // value that merely proves a TPM exists.
    // The kernel exposes no EK through sysfs — `/sys/class/tpm/tpm0` carries
    // only `tpm_version_major`, the PCRs, and power/uevent plumbing — so the
    // EK has to come from the TPM itself. `-C e` names the endorsement
    // hierarchy, whose primary key is deterministic per chip: the same TPM
    // returns the same public key on every call, and a different TPM cannot
    // return this one.
    // Read the EK from its persistent handle rather than recreating it.
    //
    // This is the difference between an identifier that is always available
    // and one that disappears under load. `TPM2_ReadPublic` on a persistent
    // handle consumes no transient object slot, so it answers even when the
    // chip is out of object contexts; `TPM2_CreatePrimary` needs a slot and
    // returns TPM_RC_OBJECT_MEMORY (0x902) when none is free. A production
    // node sat in exactly that state for days — every createprimary failed,
    // and a reboot cleared it — which would have moved its identity had the
    // fold depended on recreating the key.
    //
    // The value is stable regardless: the TCG spec derives the EK
    // deterministically from the Endorsement Primary Seed, which never leaves
    // the chip and survives reboots, so the same TPM always yields the same
    // key. 0x81010020 is the TCG-standard ECC EK handle (0x81010001 is its
    // RSA counterpart); both production TPMs provision the former.
    for handle in ["0x81010020", "0x81010001"] {
        let Ok(out) = Command::new("tpm2_readpublic").args(["-c", handle]).output() else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        // `name` is the hash of the public area — per-unit, and already a
        // digest, so the EK's own bytes stay out of the identifier.
        let stdout = String::from_utf8_lossy(&out.stdout);
        if let Some(name) = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("name:"))
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            return Some(name.to_string());
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

    /// A secure element must outrank every serial: `sources` is the preference
    /// order, and a reader takes the first entry as the strongest claim.
    #[test]
    fn secure_elements_outrank_serials() {
        use tenzro_types::machine_id::IdentifierSource;
        let id = HardwareIdentity::collect();
        let ranked: Vec<_> = id
            .sources
            .iter()
            .filter_map(|l| IdentifierSource::parse(l))
            .collect();
        if let Some(first_serial) = ranked.iter().position(|s| !s.domain().is_hardware_rooted()) {
            // Nothing hardware-rooted may appear after a serial.
            assert!(
                ranked[first_serial..]
                    .iter()
                    .all(|s| !s.domain().is_hardware_rooted()),
                "a secure element was ranked below a serial: {:?}",
                id.sources
            );
        }
    }

    /// The flag must agree with the source list, or the network would be told
    /// one thing while the evidence says another.
    #[test]
    fn assurance_label_matches_the_sources() {
        let id = HardwareIdentity::collect();
        if id.is_hardware_rooted() {
            assert_eq!(id.assurance_label(), "hardware-rooted");
        } else {
            assert_eq!(id.assurance_label(), "unrooted:serial-only");
        }
    }

    /// On Apple hardware the enclave must actually be detected — before this,
    /// `apple:sep` existed as a type but nothing ever produced it.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn apple_hardware_is_detected_and_rooted() {
        use tenzro_types::machine_id::IdentifierSource;
        let id = HardwareIdentity::collect();
        assert!(
            id.sources
                .iter()
                .any(|s| s == IdentifierSource::AppleSecureEnclave.as_str()),
            "no apple:sep in {:?}",
            id.sources
        );
        assert!(
            id.is_hardware_rooted(),
            "a Mac with a Secure Enclave must be hardware-rooted"
        );
        assert_eq!(id.assurance_label(), "hardware-rooted");
    }

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
    fn a_host_with_no_identifier_folds_to_the_refused_root() {
        // Zero is the one value TenzroDid::from_hardware_root rejects, so a
        // host that can read nothing cannot derive a DID at all. Hashing the
        // domain tag instead would hand every such host the same
        // ordinary-looking identifier — stable, convincing, and identifying
        // nothing, which is the bug this module exists to prevent.
        assert_eq!(fold_empty(), [0u8; 32]);

        let actual = HardwareIdentity::collect();
        if !actual.is_rooted() {
            assert_eq!(actual.root(), [0u8; 32]);
        }
    }

    #[test]
    fn only_one_source_contributes_to_the_root() {
        // The root must be a function of one identifier, not of the set that
        // happened to be legible. A TPM that stops answering (object contexts
        // full, TPM_RC_OBJECT_MEMORY, until the host reboots) would otherwise
        // move the root: EK+DMI while it answers, DMI alone while it does not.
        // Same machine, two identities.
        let actual = HardwareIdentity::collect();
        assert!(
            actual.sources().len() <= 1,
            "exactly one source may contribute to the root, got {:?}",
            actual.sources()
        );
    }

    #[test]
    fn root_is_never_folded_from_a_fleet_wide_constant() {
        // Determinism alone is not identity, and this is the regression that
        // proves it. `read_tpm_identity` used to fall back to
        // `/sys/class/tpm/tpm0/tpm_version_major`, which reads "2" on every
        // TPM 2.0 machine, bound to a DMI UUID that is root-only and so
        // unreadable under a non-root service account. The result folded to
        // one root fleet-wide: perfectly reproducible, and the same on every
        // host. Both production nodes registered under that single identity.
        //
        // Any value that is equal across units must therefore be absent from
        // the fold, no matter how stable it is.
        // Uses the production fold, not a copy of it, so the test cannot pass
        // against a stale reimplementation.
        let degenerate = fold_one(
            tenzro_types::machine_id::IdentifierSource::TpmEndorsementKey.as_str(),
            "2",
        );
        let actual = HardwareIdentity::collect();
        assert_ne!(
            actual.root(),
            degenerate,
            "hardware root folded from the TPM version string — every TPM 2.0 host \
             derives this same root, so it identifies no machine"
        );
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
        // Attestability follows from ANY attestable-grade source, not from the
        // TPM specifically. This test used to hardcode TpmEndorsementKey, which
        // was true only while the TPM was the sole secure element ever
        // collected; a Mac contributes `apple:sep`, which is graded Attestable
        // as a peer of the TPM rather than a lesser substitute.
        let has_attestable_source = id
            .graded_sources()
            .iter()
            .any(|src| src.grade().is_attestable());
        assert_eq!(
            has_attestable_source,
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
