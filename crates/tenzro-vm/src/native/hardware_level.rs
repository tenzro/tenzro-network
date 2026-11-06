//! Hardware security levels in consensus state.
//!
//! A participant's level is derived, never declared, from evidence chain
//! state already holds (see [`tenzro_types::hardware_level`]):
//!
//! - L1: the wallet's identity is a machine admitted with a TPM quote that
//!   binds it ([`super::funding::machine_attestation`]); its endorsement
//!   certificate chains to a manufacturer root governance recognises at the
//!   time asked ([`super::funding::machine_endorsed`]); the identity is not
//!   revoked; no other live identity holds the same endorsement key; and the
//!   machine has shown it still holds the TPM in the epoch (below).
//! - L2: L1, and the same TPM holds the identity's enrolled ML-DSA key: the
//!   admitted attestation key certified it (`TPM2_Certify`) as a TPM 2.0
//!   library v1.85 ML-DSA object, generated in the TPM and unable to leave
//!   it, over a statement binding the identity and the key
//!   ([`tenzro_tee::tpm_attest::verify_ml_dsa_certification`]).
//! - L3: L2 where that ML-DSA key is restricted, a hardware post-quantum
//!   attestation key chaining through the attestation key and the
//!   endorsement key to the manufacturer root; or L1 with a second,
//!   independent hardware scheme in the same epoch: an NVIDIA GPU whose
//!   per-device certificate chain ends at a GPU root governance recognises
//!   signs the epoch's GPU challenge
//!   ([`tenzro_tee::nvidia_device::verify_device_report`]). One GPU counts
//!   for one live identity.
//! - L0: everything else (passkeys, software keys, Secure Enclave keys,
//!   uncertified TPMs, revoked identities).
//!
//! The Secure Enclave reaches no level above 0, by design. Every
//! statement that a key lives in an Apple Secure Enclave (App Attest,
//! DeviceCheck, managed device attestation, the `apple` WebAuthn format)
//! is made by Apple and verifies only against an Apple root, used under
//! Apple's licence terms; the enclave has no endorsement key or
//! certificate of its own that anyone can check without Apple. Admitting
//! it would put Apple's root, and its licence, in the trust root. An
//! enclave key earns the full base reward at level 0.
//!
//! Possession is proven per reward epoch. The challenge is drawn from the
//! first value the randomness beacon takes in the epoch
//! ([`super::beacon::first_at_or_after`] the epoch's first block), so it
//! cannot be known before the epoch begins
//! ([`tenzro_types::hardware_level::possession_challenge`]). The machine's
//! admitted attestation key quotes it in a `HardwareProof` transaction
//! ([`prove`]). Admission evidence alone shows the TPM existed once; the
//! quote shows the same chip answered this epoch. An epoch's close counts
//! only a quote for that epoch, so a machine that misses one, or whose quote
//! is refused, is level 0 at that close.
//!
//! Each reward epoch's close derives the level of every address with
//! provider work in it, writes [`HardwareLevelRecord`], and pays the
//! provider bucket's bonus from those levels
//! ([`tenzro_token::rewards::LevelBonus`]). Nothing carries over: a revoked
//! identity, a removed manufacturer root or an expired certificate shows at
//! the next close. A quote or delivery receipt that carries a level must
//! carry exactly the derived one ([`check_stamp`]).

use super::funding::{read_json, refuse, write_json};
use super::*;
use sha2::{Digest, Sha256};
use tenzro_types::hardware_level::{
    FleetHost, FleetUnit, HardwareKind, HardwareLevel, HardwareLevelRecord, HardwareProofOp,
    HardwareStamp, device_id, fleet_binding, gpu_challenge, ml_dsa_binding, possession_challenge,
};

/// Gas for one hardware proof: a P-256 verification and two records.
pub const GAS_HARDWARE_PROOF: u64 = 150_000;
/// Topic of the log a hardware proof emits.
pub const HARDWARE_PROOF_TOPIC: &[u8] = b"HardwareProof";

/// Governed key: bonus of level 1, bps of the base provider share.
pub const LEVEL1_BONUS_PARAM: &str = "hardware.level1_bonus_bps";
/// Governed key: bonus of level 2, bps.
pub const LEVEL2_BONUS_PARAM: &str = "hardware.level2_bonus_bps";
/// Governed key: bonus of level 3, bps.
pub const LEVEL3_BONUS_PARAM: &str = "hardware.level3_bonus_bps";
/// Governed key: most bonus any level earns, bps; 0 turns the bonus off.
pub const LEVEL_BONUS_CAP_PARAM: &str = "hardware.level_bonus_cap_bps";
/// Genesis bonus of level 1: 1%.
pub const DEFAULT_LEVEL1_BONUS_BPS: u64 = 100;
/// Genesis bonus of level 2: 2%.
pub const DEFAULT_LEVEL2_BONUS_BPS: u64 = 200;
/// Genesis bonus of level 3: 3%.
pub const DEFAULT_LEVEL3_BONUS_BPS: u64 = 300;
/// Genesis cap: 3%. Kept low while most participants run older hardware.
pub const DEFAULT_LEVEL_BONUS_CAP_BPS: u64 = 300;
/// Most any level parameter may be set to: 10%.
pub const MAX_LEVEL_BONUS_BPS: u64 = 1_000;
/// Most a settlement's rewards may add up to with the hardware bonus at its
/// cap, bps of its fee: below the whole fee, so the bonus never makes trading
/// with oneself pay.
pub const MAX_REWARD_WITH_LEVEL_BONUS_BPS: u64 = 9_500;

fn record_key(address: &[u8]) -> String {
    format!("hardware_level:{}", hex::encode(address))
}

fn device_key(device: &str) -> String {
    format!("hardware_device:{device}")
}

fn possession_key(did: &str) -> String {
    format!("hardware_possession:{did}")
}

fn ml_dsa_key(did: &str) -> String {
    format!("hardware_ml_dsa:{did}")
}

fn gpu_key(did: &str) -> String {
    format!("hardware_gpu:{did}")
}

fn gpu_device_key(device: &str) -> String {
    format!("hardware_gpu_device:{device}")
}

fn host_gpus_key(did: &str) -> String {
    format!("hardware_host_gpus:{did}")
}

fn fleet_host_key(did: &str) -> String {
    format!("fleet_host:{did}")
}

fn rack_key(id: &str) -> String {
    format!("fleet_rack:{id}")
}

/// Key of the GPU device identity roots governance recognises.
pub const GPU_ROOTS_KEY: &str = "gpu_device_roots";

/// The GPU device identity roots (PEM) governance recognises; none until a
/// `GpuDeviceRootsSet` names them.
pub fn read_gpu_roots(state: &dyn VmState) -> Vec<String> {
    read_json(state, GPU_ROOTS_KEY).unwrap_or_default()
}

/// Replace the recognised GPU device roots, refused when one does not parse.
pub(super) fn set_gpu_roots(
    state: &mut dyn VmState,
    roots_pem: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    for pem in roots_pem {
        tenzro_tee::x509::parse_pem_chain(pem)
            .map_err(|e| refuse(format!("a GPU device root does not parse: {e}")))?;
    }
    write_json(state, GPU_ROOTS_KEY, &roots_pem.to_vec(), changes)?;
    Ok(())
}

/// Key of NVIDIA's GPU reference values governance recognises.
pub const GPU_REFERENCES_KEY: &str = "gpu_reference_values";

/// NVIDIA's GPU reference values governance recognises; none until a
/// `GpuReferenceValuesSet` names them.
pub fn read_gpu_references(
    state: &dyn VmState,
) -> Vec<tenzro_types::hardware_level::GpuReferenceValue> {
    read_json(state, GPU_REFERENCES_KEY).unwrap_or_default()
}

/// Replace the recognised GPU reference values, refused when one is malformed.
pub(super) fn set_gpu_references(
    state: &mut dyn VmState,
    references: &[tenzro_types::hardware_level::GpuReferenceValue],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    tenzro_types::hardware_level::decode_gpu_references(references)
        .map_err(|e| refuse(format!("GPU reference values: {e}")))?;
    write_json(state, GPU_REFERENCES_KEY, &references.to_vec(), changes)?;
    Ok(())
}

/// A machine's latest proof that it holds a GPU.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeldGpu {
    /// The reward epoch the report answered.
    pub epoch: u64,
    /// SHA-256 of the GPU's device identity key, hex.
    pub device: String,
    /// SHA-256 of the report, hex.
    pub report: String,
}

/// `did`'s latest proof that it holds a GPU.
pub fn read_gpu(state: &dyn VmState, did: &str) -> Option<HeldGpu> {
    read_json(state, &gpu_key(did))
}

/// The identity holding GPU `device`, when one claimed it.
pub fn gpu_holder(state: &dyn VmState, device: &str) -> Option<String> {
    read_json(state, &gpu_device_key(device))
}

/// The GPUs a host proved together in one epoch through a fleet proof.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostGpus {
    /// The reward epoch the reports answered.
    pub epoch: u64,
    /// Each GPU, in the order the proof listed them.
    pub gpus: Vec<HeldGpu>,
}

/// The GPUs `did` last proved through a fleet proof.
pub fn read_host_gpus(state: &dyn VmState, did: &str) -> Option<HostGpus> {
    read_json(state, &host_gpus_key(did))
}

/// `did`'s GPU proofs for epochs `counts` admits, each GPU once, leaving out
/// any GPU another live identity holds.
pub fn counted_gpus(state: &dyn VmState, did: &str, counts: impl Fn(u64) -> bool) -> Vec<HeldGpu> {
    let mut gpus: Vec<HeldGpu> = Vec::new();
    let proven = read_gpu(state, did).into_iter().chain(
        read_host_gpus(state, did)
            .into_iter()
            .flat_map(|h| h.gpus.into_iter()),
    );
    for gpu in proven {
        if counts(gpu.epoch)
            && !gpus.iter().any(|g| g.device == gpu.device)
            && !gpu_holder(state, &gpu.device)
                .is_some_and(|holder| holder != did && !is_identity_revoked(state, &holder))
        {
            gpus.push(gpu);
        }
    }
    gpus
}

/// The GPUs counted for `did` between closes: proven in the current reward
/// epoch or the one before.
pub fn current_gpus(state: &dyn VmState, did: &str) -> Vec<HeldGpu> {
    let current = epoch_start(state).map(|s| s.epoch);
    counted_gpus(state, did, |proven| {
        current.is_some_and(|c| proven == c || proven.saturating_add(1) == c)
    })
}

/// The fleet a host belongs to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FleetMembership {
    /// The operator's identity.
    pub operator: String,
    /// The reward epoch the host joined in.
    pub since_epoch: u64,
    /// The rack it was last proven in, when it is part of one.
    #[serde(default)]
    pub rack: Option<String>,
}

/// The fleet `did` belongs to.
pub fn fleet_of(state: &dyn VmState, did: &str) -> Option<FleetMembership> {
    read_json(state, &fleet_host_key(did))
}

/// A rack-scale system an operator proved as one unit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RackRecord {
    /// The operator's identity.
    pub operator: String,
    /// The operator's name for the rack.
    pub label: String,
    /// The reward epoch it was last proven in.
    pub epoch: u64,
    /// Its hosts' identities.
    pub hosts: Vec<String>,
    /// Its GPUs, each the SHA-256 of the device identity key, hex.
    pub gpus: Vec<String>,
}

/// The identifier of `operator`'s rack `label`: SHA-256, hex.
pub fn rack_id(operator: &str, label: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"tenzro/fleet-rack/v1\0");
    for s in [operator, label] {
        h.update((s.len() as u32).to_le_bytes());
        h.update(s.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Rack `id`, as last proven.
pub fn read_rack(state: &dyn VmState, id: &str) -> Option<RackRecord> {
    read_json(state, &rack_key(id))
}

/// A machine's proof that its TPM holds its identity's ML-DSA key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeldMlDsaKey {
    /// SHA-256 of the ML-DSA public key, hex.
    pub key: String,
    /// Whether the key is restricted: a TPM ML-DSA attestation key.
    pub attestation_key: bool,
    /// SHA-256 of the certification's `TPMS_ATTEST`, hex.
    pub certification: String,
}

/// `did`'s proof that its TPM holds an ML-DSA key.
pub fn read_ml_dsa(state: &dyn VmState, did: &str) -> Option<HeldMlDsaKey> {
    read_json(state, &ml_dsa_key(did))
}

const EPOCH_START_KEY: &str = "hardware_level:epoch_start";

/// When the current reward epoch began: the block time of its first block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochStart {
    /// The reward epoch.
    pub epoch: u64,
    /// Block time of its first block, ms.
    pub at_ms: i64,
}

/// A machine's latest proof that it holds its TPM.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Possession {
    /// The reward epoch the quote answered.
    pub epoch: u64,
    /// The beacon round the challenge was drawn from.
    pub beacon_round: u64,
    /// SHA-256 of the quote, hex.
    pub quote: String,
}

/// When the current reward epoch began.
pub fn epoch_start(state: &dyn VmState) -> Option<EpochStart> {
    read_json(state, EPOCH_START_KEY)
}

/// Records when reward epoch `epoch` began, at its first block.
pub(super) fn note_epoch_start(
    state: &mut dyn VmState,
    epoch: u64,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if epoch_start(state).is_some_and(|s| s.epoch >= epoch) {
        return Ok(());
    }
    write_json(
        state,
        EPOCH_START_KEY,
        &EpochStart {
            epoch,
            at_ms: now_ms,
        },
        changes,
    )?;
    Ok(())
}

/// `did`'s latest proof that it holds its TPM.
pub fn read_possession(state: &dyn VmState, did: &str) -> Option<Possession> {
    read_json(state, &possession_key(did))
}

/// The challenge `did` answers in the current reward epoch, with that epoch
/// and the beacon round it is drawn from; `None` until the beacon has taken
/// a value since the epoch began.
pub fn current_challenge(state: &dyn VmState, did: &str) -> Option<(u64, u64, [u8; 32])> {
    let start = epoch_start(state)?;
    let entry = super::beacon::first_at_or_after(state, start.at_ms)?;
    let mix = super::beacon::entry_mix(&entry)?;
    Some((
        start.epoch,
        entry.round,
        possession_challenge(did, start.epoch, entry.round, &mix),
    ))
}

/// Applies a `HardwareProof` sent from `from`.
pub(super) fn prove(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let op: HardwareProofOp = serde_json::from_slice(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("Invalid hardware proof: {e}")))?;
    op.validate().map_err(refuse)?;
    if let HardwareProofOp::Fleet { issuers, units } = op {
        return prove_fleet(state, from, now_ms, &issuers, &units);
    }
    let did = identity_of_wallet(state, from).ok_or_else(|| {
        refuse(format!(
            "{} has no registered identity to prove hardware for",
            hex::encode(from)
        ))
    })?;
    if is_identity_revoked(state, &did) {
        return Err(refuse(format!("{did} is revoked")));
    }
    let admitted = super::funding::machine_attestation(state, &did).map_err(|e| {
        refuse(format!(
            "a hardware proof needs a TPM-attested machine: {e}"
        ))
    })?;
    let mut changes = Vec::new();
    let (epoch, quote, signature) = match op {
        HardwareProofOp::Possession {
            epoch,
            quote,
            signature,
        } => (epoch, quote, signature),
        HardwareProofOp::MlDsaKey {
            key_public,
            attest,
            signature,
        } => {
            let identity = super::funding::identity_record(state, &did)
                .ok_or_else(|| refuse(format!("{did} is not registered")))?;
            if identity.pq_verifying_key.is_empty() {
                return Err(refuse(format!(
                    "{did} has enrolled no ML-DSA key for its TPM to hold"
                )));
            }
            let certified = tenzro_tee::tpm_attest::verify_ml_dsa_certification(
                &admitted.evidence,
                &key_public,
                &attest,
                &signature,
                &identity.pq_verifying_key,
                &ml_dsa_binding(&did, &identity.pq_verifying_key),
            )
            .map_err(|e| refuse(format!("ML-DSA key certification refused: {e}")))?;
            let record = HeldMlDsaKey {
                key: hex::encode(Sha256::digest(&identity.pq_verifying_key)),
                attestation_key: certified.attestation_key,
                certification: hex::encode(Sha256::digest(&attest)),
            };
            write_json(state, &ml_dsa_key(&did), &record, &mut changes)?;
            let log = Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![HARDWARE_PROOF_TOPIC.to_vec(), b"ml_dsa_key".to_vec()],
                serde_json::to_vec(&serde_json::json!({ "did": did, "ml_dsa_key": record }))
                    .map_err(|e| VmError::Internal(format!("encode hardware proof log: {e}")))?,
            );
            return Ok((changes, vec![log]));
        }
        HardwareProofOp::GpuDevice {
            epoch,
            report,
            chain,
        } => {
            let (current, _, possession) = current_challenge(state, &did).ok_or_else(|| {
                refuse(
                    "the randomness beacon has taken no value in this reward epoch yet; the \
                     GPU challenge is drawn from its first one",
                )
            })?;
            if epoch != current {
                return Err(refuse(format!(
                    "the reward epoch is {current}, not {epoch}"
                )));
            }
            if read_gpu(state, &did).is_some_and(|g| g.epoch == current) {
                return Err(refuse(format!(
                    "{did} has already proven its GPU in epoch {current}"
                )));
            }
            let roots = read_gpu_roots(state)
                .iter()
                .map(|pem| tenzro_tee::x509::parse_pem_chain(pem))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| refuse(e.to_string()))?
                .concat();
            let certs = tenzro_tee::nvidia_device::parse_chain(&chain)
                .map_err(|e| refuse(format!("GPU certificate chain: {e}")))?;
            let verified = tenzro_tee::nvidia_device::verify_device_report(
                &report,
                &certs,
                &roots,
                (now_ms.max(0) / 1000) as u64,
                &tenzro_types::hardware_level::gpu_challenge(&possession),
            )
            .map_err(|e| refuse(format!("GPU report refused: {e}")))?;
            let references =
                tenzro_types::hardware_level::decode_gpu_references(&read_gpu_references(state))
                    .map_err(refuse)?;
            tenzro_tee::nvidia_device::check_reference_values(&report, &references)
                .map_err(|e| refuse(format!("GPU measurements refused: {e}")))?;
            let record = HeldGpu {
                epoch: current,
                device: verified.device_id,
                report: hex::encode(Sha256::digest(&report)),
            };
            write_json(state, &gpu_key(&did), &record, &mut changes)?;
            let log = Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![HARDWARE_PROOF_TOPIC.to_vec(), b"gpu_device".to_vec()],
                serde_json::to_vec(&serde_json::json!({ "did": did, "gpu": record }))
                    .map_err(|e| VmError::Internal(format!("encode hardware proof log: {e}")))?,
            );
            return Ok((changes, vec![log]));
        }
        HardwareProofOp::Fleet { .. } => unreachable!("a fleet proof returned above"),
    };
    let (current, round, challenge) = current_challenge(state, &did).ok_or_else(|| {
        refuse(
            "the randomness beacon has taken no value in this reward epoch yet; the \
             possession challenge is drawn from its first one",
        )
    })?;
    if epoch != current {
        return Err(refuse(format!(
            "the reward epoch is {current}, not {epoch}"
        )));
    }
    if read_possession(state, &did).is_some_and(|p| p.epoch == current) {
        return Err(refuse(format!(
            "{did} has already proven possession in epoch {current}"
        )));
    }
    // The admitted endorsement and attestation keys, with the new quote: a
    // quote by any other key does not verify.
    let mut evidence = admitted.evidence;
    evidence.quote = quote;
    evidence.quote_signature = signature;
    tenzro_tee::tpm_attest::verify_quote(&evidence, &challenge)
        .map_err(|e| refuse(format!("possession quote refused: {e}")))?;
    let record = Possession {
        epoch: current,
        beacon_round: round,
        quote: hex::encode(Sha256::digest(&evidence.quote)),
    };
    write_json(state, &possession_key(&did), &record, &mut changes)?;
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![HARDWARE_PROOF_TOPIC.to_vec(), b"possession".to_vec()],
        serde_json::to_vec(&serde_json::json!({ "did": did, "possession": record }))
            .map_err(|e| VmError::Internal(format!("encode hardware proof log: {e}")))?,
    );
    Ok((changes, vec![log]))
}

/// The level recorded for `address` at the last epoch close it earned
/// provider work in.
pub fn read_record(state: &dyn VmState, address: &[u8]) -> Option<HardwareLevelRecord> {
    read_json(state, &record_key(address))
}

/// The identity holding TPM `device`, when one claimed it.
pub fn device_holder(state: &dyn VmState, device: &str) -> Option<String> {
    read_json(state, &device_key(device))
}

/// The level and hardware type of `address` at `now_ms`, from verified
/// evidence only, with the identity it was derived for and the TPM device
/// that backs it (empty when none). Between closes a possession quote for
/// the current epoch or the one before counts, so a machine that proves
/// itself every epoch keeps its level while it answers the new challenge.
pub fn derive(state: &dyn VmState, address: &[u8], now_ms: i64) -> (HardwareStamp, String, String) {
    let current = epoch_start(state).map(|s| s.epoch);
    derive_in(state, address, now_ms, |proven| {
        current.is_some_and(|c| proven == c || proven.saturating_add(1) == c)
    })
}

/// [`derive`], counting a possession quote only for the epochs `counts`
/// admits.
fn derive_in(
    state: &dyn VmState,
    address: &[u8],
    now_ms: i64,
    counts: impl Fn(u64) -> bool + Copy,
) -> (HardwareStamp, String, String) {
    let Some(did) = identity_of_wallet(state, address) else {
        return (HardwareStamp::default(), String::new(), String::new());
    };
    let Some(record) = super::funding::identity_record(state, &did) else {
        return (HardwareStamp::default(), did, String::new());
    };
    let pq = if record.pq_verifying_key.is_empty() {
        ""
    } else {
        "+ml-dsa-65"
    };
    let software = HardwareStamp {
        level: HardwareLevel::L0,
        kind: HardwareKind::Software,
        vendor: String::new(),
        spec: String::new(),
        scheme: format!("p256{pq}"),
    };
    if is_identity_revoked(state, &did) {
        return (software, did, String::new());
    }
    let Ok(att) = super::funding::machine_attestation(state, &did) else {
        return (software, did, String::new());
    };
    if super::funding::machine_endorsed(state, &did, now_ms).is_err() {
        return (software, did, String::new());
    }
    if !read_possession(state, &did).is_some_and(|p| counts(p.epoch)) {
        return (software, did, String::new());
    }
    let (vendor, spec) =
        tenzro_tee::tpm_attest::ek_certificate_profile(&att.evidence.ek_certificate);
    let device = device_id(&att.evidence.ek_public);
    let held_by_another = device_holder(state, &device)
        .is_some_and(|holder| holder != did && !is_identity_revoked(state, &holder));
    // The TPM holds the identity's own ML-DSA key: level 2; as a restricted
    // ML-DSA attestation key: level 3. A later enrolment of another key
    // matches no certification.
    let held_ml_dsa = read_ml_dsa(state, &did).filter(|held| {
        !record.pq_verifying_key.is_empty()
            && held.key == hex::encode(Sha256::digest(&record.pq_verifying_key))
    });
    // A GPU proven in the epoch is a second, independent hardware scheme.
    let gpu = !counted_gpus(state, &did, counts).is_empty();
    let level = match held_ml_dsa {
        _ if held_by_another => HardwareLevel::L0,
        Some(held) if held.attestation_key => HardwareLevel::L3,
        _ if gpu => HardwareLevel::L3,
        Some(_) => HardwareLevel::L2,
        None => HardwareLevel::L1,
    };
    let second = if gpu && level > HardwareLevel::L0 {
        "+nvidia-device"
    } else {
        ""
    };
    let stamp = HardwareStamp {
        level,
        kind: HardwareKind::Tpm2,
        vendor,
        spec,
        scheme: format!("ecdsa-p256{pq}{second}"),
    };
    (stamp, did, device)
}

/// Refuses a quote's or receipt's hardware stamp for `payee` unless it is
/// exactly what the chain derives at `now_ms`. A level or type claimed
/// without the attestation behind it is refused, never trusted.
pub fn check_stamp(
    state: &dyn VmState,
    payee: &[u8],
    stamp: &HardwareStamp,
    now_ms: i64,
) -> Result<()> {
    let (derived, _, _) = derive(state, payee, now_ms);
    if &derived != stamp {
        return Err(refuse(format!(
            "hardware stamp {} {} does not match the attested record of {} ({} {})",
            stamp.level.as_str(),
            stamp.kind.as_str(),
            hex::encode(payee),
            derived.level.as_str(),
            derived.kind.as_str(),
        )));
    }
    Ok(())
}

/// The governed bonus band, without levels.
pub fn bonus_band(state: &dyn VmState) -> tenzro_token::rewards::LevelBonus {
    tenzro_token::rewards::LevelBonus {
        levels: Default::default(),
        level_bps: [
            0,
            network_param(state, LEVEL1_BONUS_PARAM),
            network_param(state, LEVEL2_BONUS_PARAM),
            network_param(state, LEVEL3_BONUS_PARAM),
        ],
        cap_bps: network_param(state, LEVEL_BONUS_CAP_PARAM),
    }
}

/// Derives and records the level of each of `addresses` at an epoch's
/// close, claiming each L1 device for its identity, and returns the bonus
/// band with the levels above 0. Addresses are taken in byte order, so when
/// two identities present one TPM the same one keeps it on every node.
pub(super) fn record_epoch(
    state: &mut dyn VmState,
    epoch: u64,
    addresses: &std::collections::BTreeSet<[u8; 32]>,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<tenzro_token::rewards::LevelBonus> {
    let mut band = bonus_band(state);
    for address in addresses {
        let (stamp, did, device) = derive_in(state, address, now_ms, |proven| proven == epoch);
        if did.is_empty() {
            continue;
        }
        if stamp.level >= HardwareLevel::L1 && device_holder(state, &device).as_ref() != Some(&did)
        {
            write_json(state, &device_key(&device), &did, changes)?;
        }
        let mut gpus = Vec::new();
        if stamp.level >= HardwareLevel::L1 {
            for gpu in counted_gpus(state, &did, |proven| proven == epoch) {
                if gpu_holder(state, &gpu.device).as_ref() != Some(&did) {
                    write_json(state, &gpu_device_key(&gpu.device), &did, changes)?;
                }
                gpus.push(gpu.device);
            }
        }
        if stamp.level > HardwareLevel::L0 {
            band.levels.insert(*address, stamp.level.index());
        }
        let above = stamp.level > HardwareLevel::L0;
        let record = HardwareLevelRecord {
            gpus,
            possession: if above {
                read_possession(state, &did)
                    .map(|p| p.quote)
                    .unwrap_or_default()
            } else {
                String::new()
            },
            did,
            device_id: if above { device } else { String::new() },
            stamp,
            epoch,
        };
        write_json(state, &record_key(address), &record, changes)?;
    }
    Ok(band)
}

/// Gas a fleet proof adds for each TPM quote it carries.
pub const GAS_FLEET_QUOTE: u64 = 40_000;
/// Gas a fleet proof adds for each GPU report it carries.
pub const GAS_FLEET_GPU: u64 = 60_000;

/// Gas for the hardware proof `payload`: [`GAS_HARDWARE_PROOF`], and for a
/// fleet proof as much again for each quote and GPU report it carries.
pub fn proof_gas(payload: &[u8]) -> u64 {
    match serde_json::from_slice::<HardwareProofOp>(payload) {
        Ok(HardwareProofOp::Fleet { units, .. }) => {
            let (quotes, gpus) =
                units
                    .iter()
                    .flat_map(|u| u.hosts())
                    .fold((0u64, 0u64), |(q, g), h| {
                        (
                            q + 1 + u64::from(h.binding.is_some()),
                            g + h.gpus.len() as u64,
                        )
                    });
            GAS_HARDWARE_PROOF
                .saturating_add(quotes.saturating_mul(GAS_FLEET_QUOTE))
                .saturating_add(gpus.saturating_mul(GAS_FLEET_GPU))
        }
        _ => GAS_HARDWARE_PROOF,
    }
}

/// A fleet host whose evidence verified, with what it writes.
struct AcceptedHost {
    did: String,
    epoch: u64,
    possession: Possession,
    gpus: Vec<HeldGpu>,
}

/// What the GPU checks of a fleet proof share: the governed roots and
/// reference values, the block time, and the proof's shared issuers.
struct GpuRules<'a> {
    roots: Vec<tenzro_tee::x509::Cert>,
    references: Vec<(u8, Vec<Vec<u8>>)>,
    now_s: u64,
    issuers: &'a [u8],
}

/// Checks one fleet host of `operator` without writing anything: its
/// identity, its binding to the operator, its possession quote for the
/// current epoch and each of its GPUs. `taken` names GPUs other hosts of
/// the proof already present.
fn check_fleet_host(
    state: &dyn VmState,
    operator: &str,
    host: &FleetHost,
    rules: &GpuRules<'_>,
    taken: &dyn Fn(&str) -> bool,
) -> std::result::Result<AcceptedHost, String> {
    let did = host.did.as_str();
    if is_identity_revoked(state, did) {
        return Err(format!("{did} is revoked"));
    }
    let admitted = super::funding::machine_attestation(state, did)?;
    let quoted = |q: &tenzro_types::hardware_level::TpmQuote, statement: &[u8; 32]| {
        let mut evidence = admitted.evidence.clone();
        evidence.quote = q.quote.clone();
        evidence.quote_signature = q.signature.clone();
        tenzro_tee::tpm_attest::verify_quote(&evidence, statement).map_err(|e| e.to_string())
    };
    match &host.binding {
        Some(binding) => {
            quoted(binding, &fleet_binding(operator, did))
                .map_err(|e| format!("{did}: fleet binding quote refused: {e}"))?;
        }
        None if fleet_of(state, did).is_some_and(|m| m.operator == operator) => {}
        None => {
            return Err(format!(
                "{did} has not joined the fleet of {operator}; its first proof carries a \
                 binding quote"
            ));
        }
    }
    let (current, round, challenge) = current_challenge(state, did).ok_or_else(|| {
        "the randomness beacon has taken no value in this reward epoch yet; the possession \
         challenge is drawn from its first one"
            .to_string()
    })?;
    if host.epoch != current {
        return Err(format!(
            "{did}: the reward epoch is {current}, not {}",
            host.epoch
        ));
    }
    if read_possession(state, did).is_some_and(|p| p.epoch == current) {
        return Err(format!(
            "{did} has already proven possession in epoch {current}"
        ));
    }
    quoted(&host.possession, &challenge)
        .map_err(|e| format!("{did}: possession quote refused: {e}"))?;
    if !host.gpus.is_empty()
        && (read_host_gpus(state, did).is_some_and(|h| h.epoch == current)
            || read_gpu(state, did).is_some_and(|g| g.epoch == current))
    {
        return Err(format!(
            "{did} has already proven its GPUs in epoch {current}"
        ));
    }
    let nonce = gpu_challenge(&challenge);
    let mut gpus: Vec<HeldGpu> = Vec::with_capacity(host.gpus.len());
    for (i, gpu) in host.gpus.iter().enumerate() {
        let chain = [gpu.chain.as_slice(), rules.issuers].concat();
        let certs = tenzro_tee::nvidia_device::parse_chain(&chain)
            .map_err(|e| format!("{did} GPU {i}: certificate chain: {e}"))?;
        let verified = tenzro_tee::nvidia_device::verify_device_report(
            &gpu.report,
            &certs,
            &rules.roots,
            rules.now_s,
            &nonce,
        )
        .map_err(|e| format!("{did} GPU {i}: report refused: {e}"))?;
        tenzro_tee::nvidia_device::check_reference_values(&gpu.report, &rules.references)
            .map_err(|e| format!("{did} GPU {i}: measurements refused: {e}"))?;
        let device = verified.device_id;
        if taken(&device) || gpus.iter().any(|g| g.device == device) {
            return Err(format!(
                "{did} GPU {i}: GPU {device} appears twice in the proof"
            ));
        }
        if let Some(holder) = gpu_holder(state, &device)
            && holder != did
            && !is_identity_revoked(state, &holder)
        {
            return Err(format!("{did} GPU {i}: GPU {device} is held by {holder}"));
        }
        gpus.push(HeldGpu {
            epoch: current,
            device,
            report: hex::encode(Sha256::digest(&gpu.report)),
        });
    }
    Ok(AcceptedHost {
        did: did.to_string(),
        epoch: current,
        possession: Possession {
            epoch: current,
            beacon_round: round,
            quote: hex::encode(Sha256::digest(&host.possession.quote)),
        },
        gpus,
    })
}

/// Applies a fleet proof sent from the operator's wallet `from`. Each host
/// stands alone and each rack stands as one: one whose evidence fails is
/// refused, named in the log with the reason, and the rest are written.
/// Refused whole only when nothing in it is accepted.
fn prove_fleet(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    issuers: &[u8],
    units: &[FleetUnit],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let operator = identity_of_wallet(state, from).ok_or_else(|| {
        refuse(format!(
            "{} has no registered identity to operate a fleet",
            hex::encode(from)
        ))
    })?;
    if is_identity_revoked(state, &operator) {
        return Err(refuse(format!("{operator} is revoked")));
    }
    let rules = GpuRules {
        roots: read_gpu_roots(state)
            .iter()
            .map(|pem| tenzro_tee::x509::parse_pem_chain(pem))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| refuse(e.to_string()))?
            .concat(),
        references: tenzro_types::hardware_level::decode_gpu_references(&read_gpu_references(
            state,
        ))
        .map_err(refuse)?,
        now_s: (now_ms.max(0) / 1000) as u64,
        issuers,
    };
    let mut hosts_taken = std::collections::BTreeSet::<String>::new();
    let mut gpus_taken = std::collections::BTreeSet::<String>::new();
    let mut accepted: Vec<(AcceptedHost, Option<String>)> = Vec::new();
    let mut racks: Vec<(String, RackRecord)> = Vec::new();
    let mut refused: Vec<serde_json::Value> = Vec::new();
    for unit in units {
        let rack = match unit {
            FleetUnit::Rack { label, .. } => Some((label.clone(), rack_id(&operator, label))),
            FleetUnit::Host(_) => None,
        };
        if let Some((label, id)) = &rack
            && racks.iter().any(|(r, _)| r == id)
        {
            refused.push(serde_json::json!({
                "rack": label,
                "reason": format!("rack {label} appears twice in the proof"),
            }));
            continue;
        }
        let mut unit_ok: Vec<AcceptedHost> = Vec::new();
        let mut failure = None;
        for host in unit.hosts() {
            let checked =
                if hosts_taken.contains(&host.did) || unit_ok.iter().any(|a| a.did == host.did) {
                    Err(format!("{} appears twice in the proof", host.did))
                } else {
                    let taken = |d: &str| {
                        gpus_taken.contains(d)
                            || unit_ok.iter().any(|a| a.gpus.iter().any(|g| g.device == d))
                    };
                    check_fleet_host(state, &operator, host, &rules, &taken)
                };
            match checked {
                Ok(a) => unit_ok.push(a),
                Err(reason) if rack.is_some() => {
                    failure = Some(reason);
                    break;
                }
                Err(reason) => {
                    refused.push(serde_json::json!({ "host": host.did, "reason": reason }));
                }
            }
        }
        if let Some((label, id)) = &rack {
            if let Some(reason) = failure {
                refused.push(serde_json::json!({ "rack": label, "reason": reason }));
                continue;
            }
            racks.push((
                id.clone(),
                RackRecord {
                    operator: operator.clone(),
                    label: label.clone(),
                    epoch: unit_ok.first().map_or(0, |a| a.epoch),
                    hosts: unit_ok.iter().map(|a| a.did.clone()).collect(),
                    gpus: unit_ok
                        .iter()
                        .flat_map(|a| a.gpus.iter().map(|g| g.device.clone()))
                        .collect(),
                },
            ));
        }
        for a in unit_ok {
            hosts_taken.insert(a.did.clone());
            gpus_taken.extend(a.gpus.iter().map(|g| g.device.clone()));
            accepted.push((a, rack.as_ref().map(|(_, id)| id.clone())));
        }
    }
    if accepted.is_empty() {
        let reasons: Vec<String> = refused
            .iter()
            .filter_map(|r| r["reason"].as_str().map(str::to_string))
            .collect();
        return Err(refuse(format!(
            "no host of the fleet proof was accepted: {}",
            reasons.join("; ")
        )));
    }
    let mut changes = Vec::new();
    let mut summary = Vec::with_capacity(accepted.len());
    for (a, rack) in accepted {
        let since_epoch = fleet_of(state, &a.did)
            .filter(|m| m.operator == operator)
            .map_or(a.epoch, |m| m.since_epoch);
        let membership = FleetMembership {
            operator: operator.clone(),
            since_epoch,
            rack: rack.clone(),
        };
        if fleet_of(state, &a.did).as_ref() != Some(&membership) {
            write_json(state, &fleet_host_key(&a.did), &membership, &mut changes)?;
        }
        write_json(state, &possession_key(&a.did), &a.possession, &mut changes)?;
        if !a.gpus.is_empty() {
            write_json(
                state,
                &host_gpus_key(&a.did),
                &HostGpus {
                    epoch: a.epoch,
                    gpus: a.gpus.clone(),
                },
                &mut changes,
            )?;
        }
        summary.push(serde_json::json!({
            "host": a.did,
            "gpus": a.gpus.iter().map(|g| g.device.clone()).collect::<Vec<_>>(),
            "rack": rack,
        }));
    }
    for (id, record) in &racks {
        write_json(state, &rack_key(id), record, &mut changes)?;
    }
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![HARDWARE_PROOF_TOPIC.to_vec(), b"fleet".to_vec()],
        serde_json::to_vec(&serde_json::json!({
            "operator": operator,
            "accepted": summary,
            "refused": refused,
        }))
        .map_err(|e| VmError::Internal(format!("encode hardware proof log: {e}")))?,
    );
    Ok((changes, vec![log]))
}
