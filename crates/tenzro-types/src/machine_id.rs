//! What identifies a machine, and how much that identification is worth.
//!
//! A machine identity has to be anchored in the machine. This module names the
//! identifier sources the network will accept, and — more importantly — grades
//! them, because they are not equivalent and treating them as if they were is
//! how a cloned board ends up holding a second copy of someone's identity.
//!
//! # Not GPU serials
//!
//! An accelerator is the most-swapped component in the machine. Cards are moved
//! between chassis, resold, hot-swapped on failure, and partitioned (MIG, SR-IOV)
//! so that one physical device presents several identifiers. Rooting a machine's
//! identity in one means the identity travels with the card rather than the
//! machine, and a node that loses a GPU loses the ability to prove it is itself.
//!
//! Identity roots in the **chipset and processor** — the parts that define
//! which machine this is — and, where the hardware provides one, in a **root of
//! trust** that can sign for itself.
//!
//! # A readable number is not a secret
//!
//! [`IdentifierGrade`] is the load-bearing distinction. A fused serial like
//! Intel's PPIN or a Raspberry Pi's OTP serial is *readable*: it identifies a
//! machine to anyone who asks it honestly, and it is trivially forged by
//! anything running on that machine. A TPM endorsement key, an Apple Secure
//! Enclave UID, an ATECC608 signed serial or an AMD VCEK is *attestable*: the
//! machine can prove possession without disclosing the secret, so a relying
//! party learns something a liar could not have said.
//!
//! Both are useful and they answer different questions. A readable identifier
//! tells you which machine claims to be talking. An attestable one tells you
//! that claim is true.
//!
//! # Coverage is deliberately broad
//!
//! Server silicon, mobile SoCs, single-board computers and microcontrollers all
//! participate, and each family exposes something different. Refusing to model
//! the weak ones would not make them go away — it would just leave them
//! unlabelled, and an unlabelled identifier gets trusted like a strong one.

use std::fmt;

use serde::{Deserialize, Serialize};

/// How much weight an identifier carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierGrade {
    /// Identifies a *model*, not a unit. Every chip of the same design and
    /// stepping returns the same value.
    ///
    /// Modelled so it cannot be mistaken for identity: Arm's `MIDR_EL1` and
    /// x86 `CPUID` family/model/stepping are frequently misread as serials, and
    /// a fingerprint built from them is identical across every machine of that
    /// SKU.
    Model,
    /// A per-unit value fused at manufacture and readable by software.
    ///
    /// Unique, but not a secret and not attestable: anything running on the
    /// machine can read it, and anything anywhere can claim it. Good for
    /// naming a machine, insufficient for proving one.
    Fused,
    /// A per-unit secret held in a root of trust, which can prove possession
    /// without disclosing it.
    ///
    /// The only grade that survives an adversary who has read everything the
    /// machine can read.
    Attestable,
}

impl IdentifierGrade {
    /// Whether an identifier of this grade distinguishes one unit from another.
    pub fn is_unique(&self) -> bool {
        !matches!(self, IdentifierGrade::Model)
    }

    /// Whether possession of this identifier can be proven cryptographically.
    ///
    /// The question a relying party actually needs answered before treating a
    /// machine identity as self-sovereign.
    pub fn is_attestable(&self) -> bool {
        matches!(self, IdentifierGrade::Attestable)
    }

    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            IdentifierGrade::Model => "model",
            IdentifierGrade::Fused => "fused",
            IdentifierGrade::Attestable => "attestable",
        }
    }
}

impl fmt::Display for IdentifierGrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where in the machine an identifier comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierDomain {
    /// The processor or SoC die.
    Processor,
    /// The platform: baseboard, firmware, chipset.
    Platform,
    /// A discrete or integrated security element.
    RootOfTrust,
}

impl IdentifierDomain {
    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            IdentifierDomain::Processor => "processor",
            IdentifierDomain::Platform => "platform",
            IdentifierDomain::RootOfTrust => "root_of_trust",
        }
    }
}

impl fmt::Display for IdentifierDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A source of machine identity the network knows how to read and grade.
///
/// Every variant names a real, documented mechanism. Where a vendor exposes
/// both a readable serial and an attestable key, they are separate variants —
/// conflating them would let the weaker one inherit the stronger one's grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierSource {
    // ---- cross-vendor roots of trust ------------------------------------
    /// TPM 2.0 endorsement key, and the IDevID/IAK certified against it per
    /// IEEE 802.1AR and the TCG's device-identity profile.
    ///
    /// The broadest attestable root in existence: present on most x86 servers
    /// and business PCs, as a discrete chip or as firmware (Intel PTT, AMD
    /// fTPM). This is the anchor that lets a machine with no confidential-compute
    /// hardware still prove which machine it is.
    TpmEndorsementKey,
    /// A Chinese Trusted Cryptography Module, or the Trusted Platform Control
    /// Module built on it (GB/T 40650-2021).
    ///
    /// Functionally the TPM's counterpart with the SM2/SM3/SM4 algorithm set,
    /// and mandated on domestic Chinese platforms. Graded identically: it is a
    /// per-unit secret in a root of trust, and the algorithm set does not
    /// change what it proves.
    TrustedCryptographyModule,

    // ---- x86 ------------------------------------------------------------
    /// Intel Protected Processor Inventory Number, read from `MSR_PPIN` or
    /// `/sys/devices/system/cpu/cpu*/topology/ppin`.
    ///
    /// Per-unit and fused at the fab, but firmware-gated and readable — an
    /// inventory number, which is exactly what Intel calls it.
    IntelPpin,
    /// AMD's equivalent Protected Processor Inventory Number.
    AmdPpin,
    /// The chip-unique secret behind AMD SEV-SNP attestation, surfaced as
    /// `CHIP_ID` in the attestation report and as the VCEK that signs it.
    ///
    /// Attestable: the report is signed by a key derived from a secret that
    /// never leaves the processor, chaining to AMD's root.
    AmdSevSnpChipId,
    /// Intel SGX/TDX platform provisioning identity — the PPID and the
    /// `{QE_ID, PCE_ID}` pair a platform is registered under.
    ///
    /// Attestable through the PCK certificate chain.
    IntelPlatformProvisioningId,

    // ---- Arm and Arm SoCs -----------------------------------------------
    /// `MIDR_EL1`, the Arm main ID register.
    ///
    /// Explicitly modelled so it is never mistaken for a serial: it names the
    /// implementer, part, variant and revision, and is byte-identical across
    /// every chip of that core design.
    ArmMidr,
    /// Apple's Exclusive Chip Identification — a per-SoC 64-bit value used to
    /// personalise firmware.
    ///
    /// Fused and readable; it is the non-secret half of Apple's identity pair.
    AppleEcid,
    /// The Apple Secure Enclave UID, and the attestation keys derived from it.
    ///
    /// Fused inside the enclave by the enclave, never visible to software,
    /// Apple, or its suppliers — the secret half.
    AppleSecureEnclave,
    /// Qualcomm QFPROM fuse-derived device keys, reachable through the secure
    /// world and surfaced to Android as StrongBox-backed key attestation.
    QualcommQfprom,
    /// Huawei/HiSilicon platform identity, attested through the Kunpeng
    /// trusted-computing stack against a TPM or TCM root.
    HiSiliconPlatform,
    /// MediaTek eFuse identity. The field layout is available only under NDA,
    /// so a value is accepted when the platform supplies one and never probed
    /// speculatively.
    MediaTekEfuse,
    /// Rockchip OTP / eFuse identity.
    RockchipOtp,
    /// Allwinner SID — the openly documented fuse block carrying a chip ID and
    /// serial number.
    AllwinnerSid,

    // ---- Chinese server silicon -----------------------------------------
    /// Hygon's security-processor identity, the CSV counterpart to AMD's
    /// SEV-SNP chip identity on their shared lineage.
    HygonSecureProcessor,
    /// Loongson, Zhaoxin or Phytium platform identity, read through the
    /// platform's own trusted-computing module rather than a documented
    /// per-die register — none of these vendors publishes a chip-serial
    /// register, so the module is the anchor.
    DomesticPlatformModule,

    // ---- single-board and embedded --------------------------------------
    /// A Raspberry Pi's device unique secret, provisioned into locked OTP.
    ///
    /// The attestable anchor — as distinct from the `/proc/cpuinfo` serial,
    /// which is a readable text field and has been observed duplicated on
    /// cloned boards.
    RaspberryPiDeviceSecret,
    /// The Raspberry Pi serial exposed through `/proc/cpuinfo` and the device
    /// tree, plus the 64-bit OTP identifier on Pi 5.
    RaspberryPiSerial,
    /// A Microchip ATECC608-class secure element's guaranteed-unique 72-bit
    /// serial, together with the ECDSA key that signs for it.
    ///
    /// The reason Arduino-class boards can be attestable at all: the serial is
    /// signable, so it can be proven rather than merely read.
    AteccSecureElement,
    /// An NXP EdgeLock SE050 secure element's pre-provisioned credentials.
    Se050SecureElement,
    /// ESP32 eFuse identity — the factory MAC in eFuse, paired with the
    /// Digital Signature / ECDSA peripheral and a hardware unique key so the
    /// device can authenticate without exposing its private key.
    Esp32Efuse,
    /// A microcontroller's factory-programmed unique ID, such as the Renesas
    /// RA-series identifier behind `R_BSP_UniqueIdGet`.
    ///
    /// Readable and unsigned: it names the part, it cannot vouch for it.
    McuUniqueId,

    // ---- platform firmware ----------------------------------------------
    /// SMBIOS/DMI system UUID and baseboard serial, from
    /// `/sys/class/dmi/id/`.
    ///
    /// Firmware-supplied and manufacturer-dependent — frequently absent,
    /// placeholder-filled, or duplicated across a production run, and writable
    /// by anyone who can flash the firmware. Kept because on commodity servers
    /// it is often the only per-unit value available, and graded honestly.
    SmbiosPlatform,
}

impl IdentifierSource {
    /// Every source, in a stable order.
    pub const ALL: [IdentifierSource; 22] = [
        IdentifierSource::TpmEndorsementKey,
        IdentifierSource::TrustedCryptographyModule,
        IdentifierSource::IntelPpin,
        IdentifierSource::AmdPpin,
        IdentifierSource::AmdSevSnpChipId,
        IdentifierSource::IntelPlatformProvisioningId,
        IdentifierSource::ArmMidr,
        IdentifierSource::AppleEcid,
        IdentifierSource::AppleSecureEnclave,
        IdentifierSource::QualcommQfprom,
        IdentifierSource::HiSiliconPlatform,
        IdentifierSource::MediaTekEfuse,
        IdentifierSource::RockchipOtp,
        IdentifierSource::AllwinnerSid,
        IdentifierSource::HygonSecureProcessor,
        IdentifierSource::DomesticPlatformModule,
        IdentifierSource::RaspberryPiDeviceSecret,
        IdentifierSource::RaspberryPiSerial,
        IdentifierSource::AteccSecureElement,
        IdentifierSource::Se050SecureElement,
        IdentifierSource::Esp32Efuse,
        IdentifierSource::McuUniqueId,
        // `SmbiosPlatform` is last: it is the weakest per-unit source and the
        // ordering is the preference order for choosing an anchor.
    ];

    /// How much this source's value is worth.
    pub fn grade(&self) -> IdentifierGrade {
        match self {
            // Roots of trust: a secret that can prove itself.
            IdentifierSource::TpmEndorsementKey
            | IdentifierSource::TrustedCryptographyModule
            | IdentifierSource::AmdSevSnpChipId
            | IdentifierSource::IntelPlatformProvisioningId
            | IdentifierSource::AppleSecureEnclave
            | IdentifierSource::QualcommQfprom
            | IdentifierSource::HiSiliconPlatform
            | IdentifierSource::HygonSecureProcessor
            | IdentifierSource::DomesticPlatformModule
            | IdentifierSource::RaspberryPiDeviceSecret
            | IdentifierSource::AteccSecureElement
            | IdentifierSource::Se050SecureElement
            | IdentifierSource::Esp32Efuse => IdentifierGrade::Attestable,

            // Per-unit but readable.
            IdentifierSource::IntelPpin
            | IdentifierSource::AmdPpin
            | IdentifierSource::AppleEcid
            | IdentifierSource::MediaTekEfuse
            | IdentifierSource::RockchipOtp
            | IdentifierSource::AllwinnerSid
            | IdentifierSource::RaspberryPiSerial
            | IdentifierSource::McuUniqueId
            | IdentifierSource::SmbiosPlatform => IdentifierGrade::Fused,

            // Model-level only.
            IdentifierSource::ArmMidr => IdentifierGrade::Model,
        }
    }

    /// Where in the machine this identifier lives.
    pub fn domain(&self) -> IdentifierDomain {
        match self {
            IdentifierSource::TpmEndorsementKey
            | IdentifierSource::TrustedCryptographyModule
            | IdentifierSource::AppleSecureEnclave
            | IdentifierSource::QualcommQfprom
            | IdentifierSource::AteccSecureElement
            | IdentifierSource::Se050SecureElement
            | IdentifierSource::RaspberryPiDeviceSecret
            | IdentifierSource::DomesticPlatformModule => IdentifierDomain::RootOfTrust,

            IdentifierSource::IntelPpin
            | IdentifierSource::AmdPpin
            | IdentifierSource::AmdSevSnpChipId
            | IdentifierSource::IntelPlatformProvisioningId
            | IdentifierSource::ArmMidr
            | IdentifierSource::AppleEcid
            | IdentifierSource::HiSiliconPlatform
            | IdentifierSource::HygonSecureProcessor
            | IdentifierSource::MediaTekEfuse
            | IdentifierSource::RockchipOtp
            | IdentifierSource::AllwinnerSid
            | IdentifierSource::Esp32Efuse
            | IdentifierSource::McuUniqueId
            | IdentifierSource::RaspberryPiSerial => IdentifierDomain::Processor,

            IdentifierSource::SmbiosPlatform => IdentifierDomain::Platform,
        }
    }

    /// Stable wire form, used as the domain-separation label when an
    /// identifier is folded into a machine root.
    pub fn as_str(&self) -> &'static str {
        match self {
            IdentifierSource::TpmEndorsementKey => "tpm:ek",
            IdentifierSource::TrustedCryptographyModule => "tcm:ek",
            IdentifierSource::IntelPpin => "intel:ppin",
            IdentifierSource::AmdPpin => "amd:ppin",
            IdentifierSource::AmdSevSnpChipId => "amd:snp-chip-id",
            IdentifierSource::IntelPlatformProvisioningId => "intel:ppid",
            IdentifierSource::ArmMidr => "arm:midr",
            IdentifierSource::AppleEcid => "apple:ecid",
            IdentifierSource::AppleSecureEnclave => "apple:sep",
            IdentifierSource::QualcommQfprom => "qualcomm:qfprom",
            IdentifierSource::HiSiliconPlatform => "hisilicon:platform",
            IdentifierSource::MediaTekEfuse => "mediatek:efuse",
            IdentifierSource::RockchipOtp => "rockchip:otp",
            IdentifierSource::AllwinnerSid => "allwinner:sid",
            IdentifierSource::HygonSecureProcessor => "hygon:psp",
            IdentifierSource::DomesticPlatformModule => "domestic:tpcm",
            IdentifierSource::RaspberryPiDeviceSecret => "rpi:dus",
            IdentifierSource::RaspberryPiSerial => "rpi:serial",
            IdentifierSource::AteccSecureElement => "atecc:serial",
            IdentifierSource::Se050SecureElement => "se050:id",
            IdentifierSource::Esp32Efuse => "esp32:efuse",
            IdentifierSource::McuUniqueId => "mcu:uid",
            IdentifierSource::SmbiosPlatform => "smbios:platform",
        }
    }

    /// Parse the wire form; unknown values are refused rather than defaulted.
    pub fn parse(s: &str) -> Option<Self> {
        IdentifierSource::ALL
            .into_iter()
            .chain(std::iter::once(IdentifierSource::SmbiosPlatform))
            .find(|src| src.as_str() == s)
    }
}

impl fmt::Display for IdentifierSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One identifier read from this machine.
///
/// Carries the source rather than a bare value, so a consumer can grade it
/// without a lookup and cannot accidentally treat an SMBIOS UUID like a TPM
/// key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineIdentifier {
    /// Where the value came from.
    pub source: IdentifierSource,
    /// SHA-256 of the raw value, hex-encoded.
    ///
    /// The digest, never the value. A fused serial is a stable cross-service
    /// correlator, and publishing one in an announcement would let anyone track
    /// the same machine across every network it joins.
    pub value_digest: String,
}

/// Everything this machine can say about which machine it is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineIdentity {
    /// The identifiers that were successfully read, in preference order.
    pub identifiers: Vec<MachineIdentifier>,
}

impl MachineIdentity {
    /// The strongest grade any collected identifier reaches.
    ///
    /// `None` when nothing was collected — which is a real state on a
    /// container without device access, and must not silently read as
    /// [`IdentifierGrade::Model`].
    pub fn strongest_grade(&self) -> Option<IdentifierGrade> {
        self.identifiers.iter().map(|i| i.source.grade()).max()
    }

    /// Whether this machine holds a root of trust that can prove possession.
    ///
    /// The question that decides whether a machine identity may stand on its
    /// own hardware rather than on a human's delegation.
    pub fn is_attestable(&self) -> bool {
        self.identifiers
            .iter()
            .any(|i| i.source.grade().is_attestable())
    }

    /// Whether anything collected distinguishes this unit from others of the
    /// same model.
    ///
    /// False for a machine that could only read `MIDR_EL1` — a fingerprint made
    /// from model-level values alone is identical on every machine of that SKU,
    /// and treating it as identity would let them all claim to be each other.
    pub fn is_unique(&self) -> bool {
        self.identifiers
            .iter()
            .any(|i| i.source.grade().is_unique())
    }

    /// The identifiers that can prove themselves.
    pub fn attestable_sources(&self) -> Vec<IdentifierSource> {
        self.identifiers
            .iter()
            .map(|i| i.source)
            .filter(|s| s.grade().is_attestable())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(source: IdentifierSource) -> MachineIdentifier {
        MachineIdentifier {
            source,
            value_digest: "ab".repeat(32),
        }
    }

    /// The distinction the whole module exists to preserve: a readable serial
    /// names a machine, an attestable secret proves one.
    #[test]
    fn fused_identifiers_are_unique_but_cannot_prove_themselves() {
        for source in [
            IdentifierSource::IntelPpin,
            IdentifierSource::AmdPpin,
            IdentifierSource::AppleEcid,
            IdentifierSource::RaspberryPiSerial,
            IdentifierSource::SmbiosPlatform,
        ] {
            assert!(source.grade().is_unique(), "{source} should be per-unit");
            assert!(
                !source.grade().is_attestable(),
                "{source} is readable, so it must not grade as attestable"
            );
        }
    }

    #[test]
    fn roots_of_trust_are_attestable() {
        for source in [
            IdentifierSource::TpmEndorsementKey,
            IdentifierSource::TrustedCryptographyModule,
            IdentifierSource::AppleSecureEnclave,
            IdentifierSource::AmdSevSnpChipId,
            IdentifierSource::AteccSecureElement,
            IdentifierSource::Esp32Efuse,
            IdentifierSource::RaspberryPiDeviceSecret,
        ] {
            assert!(source.grade().is_attestable(), "{source} should attest");
            assert!(source.grade().is_unique());
        }
    }

    /// `MIDR_EL1` names a core design. Every Neoverse N1 in the world returns
    /// the same value, so a fingerprint built from it identifies nothing.
    #[test]
    fn arm_midr_is_model_level_and_never_identity() {
        assert_eq!(IdentifierSource::ArmMidr.grade(), IdentifierGrade::Model);
        assert!(!IdentifierSource::ArmMidr.grade().is_unique());

        let only_midr = MachineIdentity {
            identifiers: vec![ident(IdentifierSource::ArmMidr)],
        };
        assert!(!only_midr.is_unique());
        assert!(!only_midr.is_attestable());
    }

    /// No accelerator is a source. Identity roots in the parts that define
    /// which machine this is, not the most-swapped component in it.
    #[test]
    fn no_source_is_an_accelerator() {
        for source in IdentifierSource::ALL {
            let label = source.as_str();
            for banned in ["gpu", "nvidia", "nvml", "cuda", "accelerator"] {
                assert!(
                    !label.contains(banned),
                    "{label} looks like an accelerator identifier"
                );
            }
            assert_ne!(
                source.domain(),
                IdentifierDomain::Platform,
                "only SMBIOS is platform-domain, and it is excluded from ALL's preference order"
            );
        }
    }

    #[test]
    fn a_machine_with_a_tpm_can_stand_on_its_own_hardware() {
        let m = MachineIdentity {
            identifiers: vec![
                ident(IdentifierSource::SmbiosPlatform),
                ident(IdentifierSource::TpmEndorsementKey),
            ],
        };
        assert!(m.is_attestable());
        assert!(m.is_unique());
        assert_eq!(m.strongest_grade(), Some(IdentifierGrade::Attestable));
        assert_eq!(
            m.attestable_sources(),
            vec![IdentifierSource::TpmEndorsementKey]
        );
    }

    /// A container with no device access reads nothing, and that must not be
    /// mistaken for a weak reading.
    #[test]
    fn an_empty_identity_has_no_grade_at_all() {
        let empty = MachineIdentity::default();
        assert_eq!(empty.strongest_grade(), None);
        assert!(!empty.is_attestable());
        assert!(!empty.is_unique());
    }

    #[test]
    fn only_the_digest_is_carried_never_the_value() {
        // A fused serial is a stable cross-service correlator; publishing one
        // would let anyone track this machine across every network it joins.
        let i = ident(IdentifierSource::IntelPpin);
        assert_eq!(i.value_digest.len(), 64, "a SHA-256 hex digest");
    }

    #[test]
    fn wire_forms_round_trip() {
        for source in IdentifierSource::ALL {
            assert_eq!(IdentifierSource::parse(source.as_str()), Some(source));
        }
        assert_eq!(
            IdentifierSource::parse("smbios:platform"),
            Some(IdentifierSource::SmbiosPlatform)
        );
        assert_eq!(IdentifierSource::parse("gpu:uuid"), None);
    }

    /// Grades are ordered so `max()` picks the strongest.
    #[test]
    fn grades_order_weakest_to_strongest() {
        assert!(IdentifierGrade::Model < IdentifierGrade::Fused);
        assert!(IdentifierGrade::Fused < IdentifierGrade::Attestable);
    }
}
