//! Hardware security levels: what a participant's hardware is proven to be.
//!
//! A level is never declared. The chain derives it from attestation evidence
//! already in consensus state (see `tenzro_vm::native::hardware_level`), and
//! any copy of it elsewhere (a quote, a delivery receipt, a listing) must
//! equal what the chain derives. A level adds a small, capped reward bonus;
//! it never admits or excludes anyone. Not [`crate::hardware`], which
//! describes the capacity a node advertises.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How strongly a participant's key is proven to live in hardware.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum HardwareLevel {
    /// The controller holds its key; nothing proves where. Passkeys,
    /// software keys, Secure Enclave keys and uncertified TPMs.
    #[default]
    L0,
    /// A manufacturer-certified TPM holds the attestation key the identity
    /// derives from, and no other live identity holds that TPM.
    L1,
    /// L1, plus a hardware-held ML-DSA key proven on chain.
    L2,
    /// A hardware post-quantum attestation key, or a second independent
    /// hardware scheme, proven on chain.
    L3,
}

impl HardwareLevel {
    /// The level as an index, 0 to 3.
    pub fn index(self) -> u8 {
        self as u8
    }

    /// Stable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        }
    }
}

/// What kind of hardware the attestation proved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareKind {
    /// No hardware is proven: a passkey or software key, or a key whose
    /// hardware gives no verifiable attestation.
    #[default]
    Software,
    /// A TPM 2.0 whose endorsement key chains to a manufacturer root.
    Tpm2,
}

impl HardwareKind {
    /// Stable label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Tpm2 => "tpm2",
        }
    }
}

/// The level and hardware type of a participant, as derived from verified
/// attestation. Quotes and delivery receipts carry a copy, which must equal
/// the chain's derivation for the payee.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HardwareStamp {
    /// The level.
    pub level: HardwareLevel,
    /// The kind of hardware.
    pub kind: HardwareKind,
    /// The TPM manufacturer from the endorsement certificate (TCG
    /// `tpmManufacturer`, for example `id:494E5443`); empty when unknown.
    #[serde(default)]
    pub vendor: String,
    /// The TPM specification from the endorsement certificate
    /// (`family/level/revision`); empty when the certificate names none.
    #[serde(default)]
    pub spec: String,
    /// The attestation signature scheme (`ecdsa-p256` for a TPM attestation
    /// key, `p256` for a passkey or software key), with `+ml-dsa-65` when the
    /// identity has enrolled one.
    #[serde(default)]
    pub scheme: String,
}

impl HardwareStamp {
    /// Feeds the stamp into a digest, every string length-prefixed.
    pub fn digest_into(&self, h: &mut Sha256) {
        h.update([self.level.index()]);
        for s in [self.kind.as_str(), &self.vendor, &self.spec, &self.scheme] {
            h.update((s.len() as u32).to_le_bytes());
            h.update(s.as_bytes());
        }
    }
}

/// The chain's record of a participant's level at an epoch close.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareLevelRecord {
    /// The identity the level was derived for; empty when the address has
    /// none.
    pub did: String,
    /// Level and hardware type.
    pub stamp: HardwareStamp,
    /// The reward epoch whose close derived it.
    pub epoch: u64,
    /// SHA-256 of the TPM endorsement key's public area, hex; empty when no
    /// TPM is proven. One endorsement key backs at most one live identity.
    #[serde(default)]
    pub device_id: String,
    /// SHA-256 of the possession quote the level rests on, hex: the TPM's
    /// answer to this epoch's challenge. Empty at level 0.
    #[serde(default)]
    pub possession: String,
    /// The GPUs counted for the identity at this close, each the SHA-256 of
    /// its device identity key, hex. Each one is a second hardware scheme
    /// beside the TPM and is rewarded on its own.
    #[serde(default)]
    pub gpus: Vec<String>,
}

/// SHA-256 of a TPM endorsement key's public area, hex: the device
/// identifier one-device-one-attestation counts.
pub fn device_id(ek_public: &[u8]) -> String {
    hex::encode(Sha256::digest(ek_public))
}

const POSSESSION_DOMAIN: &[u8] = b"tenzro/hardware-possession/v1\0";
const ML_DSA_DOMAIN: &[u8] = b"tenzro/hardware-ml-dsa/v1\0";
const GPU_DOMAIN: &[u8] = b"tenzro/hardware-gpu/v1\0";
const FLEET_DOMAIN: &[u8] = b"tenzro/fleet-binding/v1\0";

/// The statement a host's TPM quotes to join the fleet of `operator`: the
/// operator's identity and the host's, so a quote made for one operator or
/// host binds no other.
pub fn fleet_binding(operator: &str, host: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FLEET_DOMAIN);
    for s in [operator, host] {
        h.update((s.len() as u32).to_le_bytes());
        h.update(s.as_bytes());
    }
    h.finalize().into()
}

/// The nonce a GPU signs to prove in an epoch that the machine still holds
/// it: the machine's [`possession_challenge`] of the epoch, kept apart from
/// the TPM's answer by its own domain.
pub fn gpu_challenge(possession: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(GPU_DOMAIN)
        .chain_update(possession)
        .finalize()
        .into()
}

/// The statement a machine's TPM certifies its ML-DSA key over: the
/// identity and the key, so a certification made for one identity or key
/// proves nothing for another.
pub fn ml_dsa_binding(did: &str, ml_dsa_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ML_DSA_DOMAIN);
    h.update((did.len() as u32).to_le_bytes());
    h.update(did.as_bytes());
    h.update(Sha256::digest(ml_dsa_key));
    h.finalize().into()
}

/// The challenge a machine answers in reward epoch `epoch` to show it still
/// holds the hardware its level rests on: bound to its identity, the epoch,
/// and the first value the randomness beacon took in the epoch (`round`,
/// `mix`). Nobody knows the beacon value before the epoch begins, so no
/// answer can be prepared in advance and replayed after the hardware is gone.
pub fn possession_challenge(did: &str, epoch: u64, round: u64, mix: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POSSESSION_DOMAIN);
    h.update((did.len() as u32).to_le_bytes());
    h.update(did.as_bytes());
    h.update(epoch.to_be_bytes());
    h.update(round.to_be_bytes());
    h.update(mix);
    h.finalize().into()
}

/// A proof about a participant's hardware, sent in a `HardwareProof`
/// transaction from the wallet of the identity it is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareProofOp {
    /// A quote over [`possession_challenge`] of `epoch` by the TPM
    /// attestation key the machine was admitted with.
    Possession {
        /// The reward epoch the quote answers; the current one.
        epoch: u64,
        /// `TPMS_ATTEST` of the quote.
        #[serde(with = "hex::serde")]
        quote: Vec<u8>,
        /// Raw `r || s` ECDSA P-256 signature over SHA-256 of `quote`.
        #[serde(with = "hex::serde")]
        signature: Vec<u8>,
    },
    /// `TPM2_Certify` of the identity's ML-DSA key by the machine's admitted
    /// attestation key over [`ml_dsa_binding`]: the key is a TPM 2.0
    /// library v1.85 ML-DSA object held in the same TPM.
    MlDsaKey {
        /// `TPMT_PUBLIC` of the ML-DSA key.
        #[serde(with = "hex::serde")]
        key_public: Vec<u8>,
        /// `TPMS_ATTEST` of the certification.
        #[serde(with = "hex::serde")]
        attest: Vec<u8>,
        /// Raw `r || s` ECDSA P-256 signature over SHA-256 of `attest`.
        #[serde(with = "hex::serde")]
        signature: Vec<u8>,
    },
    /// An NVIDIA GPU's SPDM measurement report over [`gpu_challenge`] of
    /// `epoch`, with its per-device certificate chain: a second hardware
    /// scheme, independent of the TPM.
    GpuDevice {
        /// The reward epoch the report answers; the current one.
        epoch: u64,
        /// The SPDM `GET_MEASUREMENTS` request and signed response.
        #[serde(with = "hex::serde")]
        report: Vec<u8>,
        /// The device's certificate chain, DER, alias certificate first.
        #[serde(with = "hex::serde")]
        chain: Vec<u8>,
    },
    /// The hosts of one operator's fleet, each with its own TPM identity,
    /// proving possession and their GPUs for the epoch in one transaction
    /// from the operator's wallet. Each host and each rack is accepted or
    /// refused on its own: a host whose evidence fails is refused and the
    /// rest are accepted.
    Fleet {
        /// DER certificates every GPU chain in the proof shares above its
        /// device certificate (NVIDIA's device identity CA and root),
        /// appended to each GPU's chain; empty when each chain is whole.
        #[serde(with = "hex::serde")]
        issuers: Vec<u8>,
        /// The hosts and racks.
        units: Vec<FleetUnit>,
    },
}

/// A TPM quote by a host's admitted attestation key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmQuote {
    /// `TPMS_ATTEST` of the quote.
    #[serde(with = "hex::serde")]
    pub quote: Vec<u8>,
    /// Raw `r || s` ECDSA P-256 signature over SHA-256 of `quote`.
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
}

/// One GPU's answer to its host's GPU challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuEvidence {
    /// The SPDM `GET_MEASUREMENTS` request and signed response.
    #[serde(with = "hex::serde")]
    pub report: Vec<u8>,
    /// The device's own certificates, DER, alias certificate first; the
    /// proof's shared issuers follow them.
    #[serde(with = "hex::serde")]
    pub chain: Vec<u8>,
}

/// One host of a fleet: a machine identity admitted with its own TPM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetHost {
    /// The host's machine identity.
    pub did: String,
    /// A quote over [`fleet_binding`] of the operator and the host, when
    /// the host joins the operator's fleet; none once it has.
    #[serde(default)]
    pub binding: Option<TpmQuote>,
    /// The reward epoch the possession quote answers; the current one.
    pub epoch: u64,
    /// A quote over the host's [`possession_challenge`] of `epoch`.
    pub possession: TpmQuote,
    /// Its GPUs, each answering [`gpu_challenge`] of that challenge.
    #[serde(default)]
    pub gpus: Vec<GpuEvidence>,
}

/// A unit of a fleet proof, accepted or refused whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FleetUnit {
    /// One TPM host with up to [`MAX_GPUS_PER_HOST`] GPUs.
    Host(FleetHost),
    /// A rack-scale system attested as one unit (an NVL72 rack: 18 compute
    /// trays of 4 GPUs): every host and GPU in it verifies, or none counts.
    Rack {
        /// The operator's name for the rack, unique among its racks.
        label: String,
        /// The rack's hosts.
        hosts: Vec<FleetHost>,
    },
}

impl FleetUnit {
    /// The unit's hosts.
    pub fn hosts(&self) -> &[FleetHost] {
        match self {
            Self::Host(h) => std::slice::from_ref(h),
            Self::Rack { hosts, .. } => hosts,
        }
    }
}

/// Most GPUs one TPM host proves.
pub const MAX_GPUS_PER_HOST: usize = 8;

/// Most hosts a rack unit holds: an NVL72 rack's 18 compute trays.
pub const MAX_RACK_HOSTS: usize = 18;

/// Most GPUs a rack unit holds: an NVL72 rack's 72.
pub const MAX_RACK_GPUS: usize = 72;

/// Most bytes a rack label may carry.
pub const MAX_RACK_LABEL_BYTES: usize = 64;

/// Most hosts one fleet proof carries, a rack's hosts included.
pub const MAX_FLEET_HOSTS: usize = 64;

/// Most GPUs one fleet proof carries.
pub const MAX_FLEET_GPUS: usize = 128;

/// Most evidence bytes one fleet proof carries, so that its hex encoding
/// stays inside one gossip message (1 MiB). An NVL72 rack's 72 NVIDIA
/// reports and device certificates with its 18 hosts' quotes fit.
pub const MAX_FLEET_EVIDENCE_BYTES: usize = 480 * 1024;

fn quote_fits(q: &TpmQuote) -> bool {
    !q.quote.is_empty() && q.quote.len() <= MAX_ATTEST_BYTES && q.signature.len() == 64
}

fn validate_fleet(issuers: &[u8], units: &[FleetUnit]) -> Result<(), &'static str> {
    if units.is_empty() {
        return Err("a fleet proof carries at least one host");
    }
    if issuers.len() > MAX_GPU_EVIDENCE_BYTES {
        return Err("a fleet proof's shared GPU issuers are at most 8192 bytes");
    }
    let mut hosts = 0usize;
    let mut gpus = 0usize;
    let mut bytes = issuers.len();
    for unit in units {
        if let FleetUnit::Rack { label, hosts: rack } = unit {
            if label.is_empty() || label.len() > MAX_RACK_LABEL_BYTES {
                return Err("a rack label is 1 to 64 bytes");
            }
            if rack.is_empty() || rack.len() > MAX_RACK_HOSTS {
                return Err("a rack holds 1 to 18 hosts");
            }
            if rack.iter().map(|h| h.gpus.len()).sum::<usize>() > MAX_RACK_GPUS {
                return Err("a rack holds at most 72 GPUs");
            }
        }
        for host in unit.hosts() {
            hosts += 1;
            if host.did.is_empty() || host.did.len() > 256 {
                return Err("a fleet host names its machine identity in at most 256 bytes");
            }
            if let Some(b) = &host.binding {
                if !quote_fits(b) {
                    return Err(
                        "a fleet binding is a TPM quote of at most 1024 bytes with a 64-byte \
                         P-256 signature",
                    );
                }
                bytes += b.quote.len() + b.signature.len();
            }
            if !quote_fits(&host.possession) {
                return Err(
                    "a possession proof is a TPM quote of at most 1024 bytes with a 64-byte \
                     P-256 signature",
                );
            }
            bytes += host.possession.quote.len() + host.possession.signature.len();
            if host.gpus.len() > MAX_GPUS_PER_HOST {
                return Err("a TPM host proves at most 8 GPUs");
            }
            gpus += host.gpus.len();
            for gpu in &host.gpus {
                if gpu.report.is_empty() || gpu.report.len() > MAX_GPU_EVIDENCE_BYTES {
                    return Err("a GPU report is at most 8192 bytes");
                }
                if gpu.chain.is_empty() || gpu.chain.len() > MAX_GPU_EVIDENCE_BYTES {
                    return Err("a GPU certificate chain is at most 8192 bytes");
                }
                bytes += gpu.report.len() + gpu.chain.len();
            }
        }
    }
    if hosts > MAX_FLEET_HOSTS {
        return Err("a fleet proof carries at most 64 hosts");
    }
    if gpus > MAX_FLEET_GPUS {
        return Err("a fleet proof carries at most 128 GPUs");
    }
    if bytes > MAX_FLEET_EVIDENCE_BYTES {
        return Err("a fleet proof carries at most 480 KiB of evidence");
    }
    Ok(())
}

/// NVIDIA's reference values for one GPU measurement index: the values its
/// reference integrity manifests list for a genuine firmware or driver, any
/// of which is accepted there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuReferenceValue {
    /// The SPDM measurement index.
    pub index: u8,
    /// The accepted values, hex.
    pub values: Vec<String>,
}

/// Most measurement indices a reference record may list.
pub const MAX_GPU_REFERENCE_INDICES: usize = 128;

/// Most values one index may accept.
pub const MAX_GPU_REFERENCE_VALUES: usize = 16;

/// `references` as `(index, accepted values)`, refused when an index repeats
/// or accepts nothing, or a value is not 1 to 64 bytes of hex.
pub fn decode_gpu_references(
    references: &[GpuReferenceValue],
) -> Result<Vec<(u8, Vec<Vec<u8>>)>, String> {
    if references.len() > MAX_GPU_REFERENCE_INDICES {
        return Err(format!(
            "at most {MAX_GPU_REFERENCE_INDICES} measurement indices"
        ));
    }
    let mut decoded: Vec<(u8, Vec<Vec<u8>>)> = Vec::with_capacity(references.len());
    for r in references {
        if decoded.iter().any(|(i, _)| *i == r.index) {
            return Err(format!("measurement {} is listed twice", r.index));
        }
        if r.values.is_empty() || r.values.len() > MAX_GPU_REFERENCE_VALUES {
            return Err(format!(
                "measurement {} accepts 1 to {MAX_GPU_REFERENCE_VALUES} values",
                r.index
            ));
        }
        let values = r
            .values
            .iter()
            .map(|v| match hex::decode(v) {
                Ok(b) if !b.is_empty() && b.len() <= 64 => Ok(b),
                _ => Err(format!(
                    "a value of measurement {} is not 1 to 64 bytes of hex",
                    r.index
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        decoded.push((r.index, values));
    }
    Ok(decoded)
}

/// Most bytes a GPU report or certificate chain may carry.
pub const MAX_GPU_EVIDENCE_BYTES: usize = 0x2000;

/// Most bytes an ML-DSA public area may carry here: ML-DSA-87 with room for
/// its header.
pub const MAX_ML_DSA_PUBLIC_BYTES: usize = 4096;

/// Most bytes a `TPMS_ATTEST` may carry here.
pub const MAX_ATTEST_BYTES: usize = 1024;

impl HardwareProofOp {
    /// Shape checks made at admission.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Possession {
                quote, signature, ..
            } => {
                if quote.is_empty() || quote.len() > MAX_ATTEST_BYTES {
                    return Err("a possession proof carries a TPM quote of at most 1024 bytes");
                }
                if signature.len() != 64 {
                    return Err("a possession quote is signed with a 64-byte P-256 signature");
                }
            }
            Self::MlDsaKey {
                key_public,
                attest,
                signature,
            } => {
                if key_public.is_empty() || key_public.len() > MAX_ML_DSA_PUBLIC_BYTES {
                    return Err("an ML-DSA public area is at most 4096 bytes");
                }
                if attest.is_empty() || attest.len() > MAX_ATTEST_BYTES {
                    return Err("a certification carries a TPMS_ATTEST of at most 1024 bytes");
                }
                if signature.len() != 64 {
                    return Err("a certification is signed with a 64-byte P-256 signature");
                }
            }
            Self::GpuDevice { report, chain, .. } => {
                if report.is_empty() || report.len() > MAX_GPU_EVIDENCE_BYTES {
                    return Err("a GPU report is at most 8192 bytes");
                }
                if chain.is_empty() || chain.len() > MAX_GPU_EVIDENCE_BYTES {
                    return Err("a GPU certificate chain is at most 8192 bytes");
                }
            }
            Self::Fleet { issuers, units } => validate_fleet(issuers, units)?,
        }
        Ok(())
    }
}
