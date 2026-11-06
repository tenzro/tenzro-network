//! Inference faults in consensus state.
//!
//! A requester whose optimistic-level answer was not reproduced by another
//! provider serving the same model files a fault: the disputed receipt's
//! signed preimage and session signature, the provider's machine DID (its
//! compute bond), who paid and how much, when the receipt was signed, and the
//! dispute itself (the receipt, the request and the output) for validators to
//! re-execute. Filing is open to anyone within the challenge window after the
//! receipt was signed, and only when the receipt names the bonded machine,
//! was signed when the fault says, and carries a session signature the
//! hardware identity key registered on chain for that machine certified.
//!
//! Bonded validators then attest a verdict after re-executing the request on
//! providers other than the accused. Once attesters hold two thirds of bonded
//! stake the verdict freezes. Upheld, the provider's bond vault refunds the
//! requester (capped by the bond) and pays the insurance pool a penalty
//! scaled to what the requester paid, at least a USD floor; the bond marker records the slash and a
//! `ComputeBondSlashed` log lets every node mirror it. A fault with no quorum
//! within the window after filing expires undecided and slashes nothing.

use super::*;
use tenzro_types::inference_verification::{
    CatalogFaultEvidence, InferenceFaultEvidence, InferenceFaultOp, MAX_FAULT_DISPUTE_BYTES,
    catalog_fault_id,
};
use tenzro_types::network::NetworkRole;

/// Governed: share of a publisher's catalog publisher stake an upheld catalog
/// fault takes into the insurance pool, bps.
pub const CATALOG_FAULT_SLASH_BPS_PARAM: &str = "catalog.fault_slash_bps";
/// Genesis value of [`CATALOG_FAULT_SLASH_BPS_PARAM`].
pub const DEFAULT_CATALOG_FAULT_SLASH_BPS: u64 = 1_000;

/// A catalog fault as filed: the evidence, and what the chain established
/// from it when it was filed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CatalogFault {
    pub evidence: CatalogFaultEvidence,
    /// The publisher DID the document's signature names.
    pub publisher: String,
    /// Hex account holding the publisher's catalog publisher stake.
    pub account: String,
    /// The model the entry describes.
    pub model: String,
    /// The disputed component as the entry pins it (repo, path, source,
    /// size, sha256).
    pub pinned: serde_json::Value,
    /// Hex digest of the signed entry document, as its catalog record names it.
    pub digest: String,
}

fn faulted_entry_key(digest: &str) -> String {
    format!("catalog_entry_faulted:{}", digest.to_ascii_lowercase())
}

/// Whether the catalog entry whose signed document has `digest` was found to
/// pin bytes its source does not hold. Nodes leave such an entry out.
pub fn catalog_entry_faulted(state: &dyn VmState, digest: &str) -> bool {
    state
        .get_storage(&SYSTEM_ADDRESS, faulted_entry_key(digest).as_bytes())
        .is_some_and(|b| !b.is_empty())
}

/// What a fault accuses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultEvidence {
    /// An optimistic-level inference answer another provider did not
    /// reproduce.
    Inference(InferenceFaultEvidence),
    /// A catalog entry pinning bytes its source does not hold.
    Catalog(CatalogFault),
}

/// Selector for every inference-fault operation; the payload names which.
pub const SELECTOR_INFERENCE_FAULT: [u8; 4] = [0x01, 0x00, 0x00, 0x76];

/// Gas for one fault operation, plus per byte of dispute filed.
pub const GAS_INFERENCE_FAULT: u64 = 60_000;
pub const GAS_INFERENCE_FAULT_BYTE: u64 = 16;

/// Log topics for a filed and a decided fault.
pub const INFERENCE_FAULT_FILED_TOPIC: &[u8] = b"InferenceFaultFiled";
pub const INFERENCE_FAULT_DECIDED_TOPIC: &[u8] = b"InferenceFaultDecided";
/// Log topic of a compute-bond slash, mirrored by nodes into their bond view.
pub const COMPUTE_BOND_SLASHED_TOPIC: &[u8] = b"ComputeBondSlashed";
/// Op tag of a slash in a compute-bond lifecycle log.
pub const COMPUTE_BOND_SLASHED_OP: u8 = 4;

/// Governed: least share (bps) of optimistic answers re-executed, whatever
/// they cost. Never zero.
pub const SAMPLE_BPS_PARAM: &str = "inference.optimistic.sample_bps";
pub const DEFAULT_SAMPLE_BPS: u64 = 500;
/// Governed: the payment, gwei, for each multiple of which an answer's
/// re-execution share rises by [`SAMPLE_STEP_BPS_PARAM`].
pub const SAMPLE_ESCROW_STEP_GWEI_PARAM: &str = "inference.optimistic.sample_escrow_step_gwei";
/// Genesis value of [`SAMPLE_ESCROW_STEP_GWEI_PARAM`]: one TNZO.
pub const DEFAULT_SAMPLE_ESCROW_STEP_GWEI: u64 = 1_000_000_000;
/// Governed: bps added to the re-execution share per escrow step.
pub const SAMPLE_STEP_BPS_PARAM: &str = "inference.optimistic.sample_step_bps";
pub const DEFAULT_SAMPLE_STEP_BPS: u64 = 1_000;

/// Share (bps) of optimistic answers paid `escrow` (wei) that are
/// re-executed: the governed floor, plus the governed step for each full
/// escrow step the payment holds, at most every answer. A dearer answer is
/// checked more often, so the expected cost of a substituted answer grows
/// with what it earns.
pub fn sample_bps_for(state: &dyn VmState, escrow: u128) -> u64 {
    sample_bps_with(
        network_param(state, SAMPLE_BPS_PARAM),
        network_param(state, SAMPLE_ESCROW_STEP_GWEI_PARAM),
        network_param(state, SAMPLE_STEP_BPS_PARAM),
        escrow,
    )
}

/// [`sample_bps_for`] from explicit parameter values.
pub fn sample_bps_with(floor_bps: u64, step_gwei: u64, step_bps: u64, escrow: u128) -> u64 {
    let step_wei = u128::from(step_gwei.max(1)).saturating_mul(GWEI);
    let steps = escrow / step_wei;
    let rise = steps.saturating_mul(u128::from(step_bps));
    u128::from(floor_bps.max(1))
        .saturating_add(rise)
        .min(10_000) as u64
}
/// Governed: the challenge window, ms.
pub const WINDOW_MS_PARAM: &str = "inference.optimistic.window_ms";
pub const DEFAULT_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
/// Governed: least penalty an upheld fault pays the insurance pool,
/// micro-USD, converted at the rate in force.
pub const PENALTY_FLOOR_PARAM: &str = "inference.optimistic.penalty_floor_micro_usd";
/// Genesis value of [`PENALTY_FLOOR_PARAM`]: ten cents.
pub const DEFAULT_PENALTY_FLOOR_MICRO_USD: u64 = 100_000;
/// Governed: penalty an upheld fault pays the insurance pool, bps of what
/// the requester paid for the answer, when that is above the floor. Held at
/// or above the inverse of the least sampling share, so a substituted
/// answer, whatever it saves, loses more in expectation than it gains.
pub const PENALTY_PAYMENT_PARAM: &str = "inference.optimistic.penalty_payment_bps";
/// Genesis value of [`PENALTY_PAYMENT_PARAM`]: twenty times the payment, the
/// inverse of the 5% genesis sampling share.
pub const DEFAULT_PENALTY_PAYMENT_BPS: u64 = 200_000;

/// The penalty, wei, an upheld fault on an answer paid `payment` wei owes
/// the insurance pool: the governed share of the payment, and at least the
/// governed USD floor at the rate in force.
pub fn penalty_due(state: &dyn VmState, payment: u128) -> u128 {
    let floor = super::economy::usd_to_wei(
        state,
        u128::from(network_param(state, PENALTY_FLOOR_PARAM)).saturating_mul(1_000_000_000_000),
    );
    let bps = u128::from(network_param(state, PENALTY_PAYMENT_PARAM));
    let scaled = (payment / 10_000)
        .saturating_mul(bps)
        .saturating_add(payment % 10_000 * bps / 10_000);
    floor.max(scaled)
}
/// Governed: largest refund one fault may claim, gwei.
pub const MAX_REFUND_GWEI_PARAM: &str = "inference.optimistic.max_refund_gwei";
pub const DEFAULT_MAX_REFUND_GWEI: u64 = 100_000_000_000;

/// Governed: surcharge, in bps of the base price, a requester pays for an
/// answer at each verification level.
pub const RECEIPT_SURCHARGE_PARAM: &str = "inference.verification.receipt_bps";
pub const DEFAULT_RECEIPT_SURCHARGE_BPS: u64 = 0;
pub const OPTIMISTIC_SURCHARGE_PARAM: &str = "inference.verification.optimistic_bps";
pub const DEFAULT_OPTIMISTIC_SURCHARGE_BPS: u64 = 1_000;
pub const TEE_SURCHARGE_PARAM: &str = "inference.verification.tee_bps";
pub const DEFAULT_TEE_SURCHARGE_BPS: u64 = 2_000;

/// Most faults awaiting a verdict at once.
pub const MAX_PENDING_FAULTS: usize = 256;

const GWEI: u128 = 1_000_000_000;
const PENDING_KEY: &str = "inference_fault_pending";

/// One validator's verdict on a fault.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FaultAttestation {
    pub validator: String,
    pub upheld: bool,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub stake: u128,
}

/// A fault as consensus state holds it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FaultRecord {
    pub fault_id: String,
    pub evidence: FaultEvidence,
    pub filed_at_ms: i64,
    pub attestations: Vec<FaultAttestation>,
    /// `Some(true)` upheld, `Some(false)` dismissed, `None` undecided.
    pub upheld: Option<bool>,
    /// What the bond paid on an upheld fault: refund, then penalty.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub refunded: u128,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub penalty: u128,
}

fn fault_key(fault_id: &str) -> String {
    format!("inference_fault:{}", fault_id)
}

/// The fault `fault_id`, if one was filed.
pub fn read_fault(state: &dyn VmState, fault_id: &str) -> Option<FaultRecord> {
    state
        .get_storage(&SYSTEM_ADDRESS, fault_key(fault_id).as_bytes())
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// Ids of the faults awaiting a verdict, oldest first.
pub fn pending_faults(state: &dyn VmState) -> Vec<String> {
    state
        .get_storage(&SYSTEM_ADDRESS, PENDING_KEY.as_bytes())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(msg.into())
}

fn put(state: &mut dyn VmState, key: &str, blob: Vec<u8>, changes: &mut Vec<StateChange>) {
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        prior,
        Some(blob),
    ));
}

fn write_fault(
    state: &mut dyn VmState,
    record: &FaultRecord,
    changes: &mut Vec<StateChange>,
) -> Result<Vec<u8>> {
    let blob = serde_json::to_vec(record)
        .map_err(|e| VmError::Internal(format!("encode fault: {}", e)))?;
    put(state, &fault_key(&record.fault_id), blob.clone(), changes);
    Ok(blob)
}

fn write_pending(
    state: &mut dyn VmState,
    ids: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let blob = serde_json::to_vec(ids)
        .map_err(|e| VmError::Internal(format!("encode pending faults: {}", e)))?;
    put(state, PENDING_KEY, blob, changes);
    Ok(())
}

/// The pending list without faults decided or past their window.
fn live_pending(state: &dyn VmState, now: i64, window: i64) -> Vec<String> {
    pending_faults(state)
        .into_iter()
        .filter(|id| {
            read_fault(state, id)
                .is_some_and(|f| f.upheld.is_none() && now <= f.filed_at_ms.saturating_add(window))
        })
        .collect()
}

fn is_hex32(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Check that the bonded machine signed the disputed receipt: the preimage
/// hashes to the receipt digest, names `provider_did` as the serving machine
/// and ends with `served_at_ms` and the identity key registered on chain for
/// that DID, and that the hardware batch carried in `batched` is signed by
/// that key.
fn verify_receipt_signature(
    state: &dyn VmState,
    evidence: &InferenceFaultEvidence,
    now_ms: u64,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use tenzro_types::inference_verification::{receipt_preimage_machine, receipt_preimage_tail};

    let preimage = hex::decode(&evidence.receipt_preimage)
        .map_err(|_| refuse("receipt_preimage is not hex"))?;
    if hex::encode(Sha256::digest(&preimage)) != evidence.receipt_digest.to_ascii_lowercase() {
        return Err(refuse(
            "receipt_digest is not the digest of receipt_preimage",
        ));
    }
    if receipt_preimage_machine(&preimage) != Some(evidence.provider_did.as_str()) {
        return Err(refuse("the receipt does not name the bonded machine"));
    }
    let key = super::registered_identity_key(state, &evidence.provider_did)?;
    if !preimage.ends_with(&receipt_preimage_tail(
        evidence.served_at_ms,
        &key.p256,
        key.pq.as_deref(),
    )) {
        return Err(refuse(
            "the receipt was not signed at served_at_ms by the machine's registered identity key",
        ));
    }
    {
        let batched = evidence.batched.as_str();
        let sig: tenzro_crypto::batch::BatchedSignature = hex::decode(batched)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| refuse("batched is not the hex of a batched signature"))?;
        sig.verify_for_record_at_block(
            &key,
            &preimage,
            evidence.served_at_ms,
            now_ms,
            tenzro_crypto::batch::batch_skew_ms(),
            // A fault is filed up to the challenge window after the
            // receipt, so the age bound is never shorter than that.
            network_param(state, crate::governance::MAX_RECORD_AGE_PARAM)
                .max(network_param(state, WINDOW_MS_PARAM)),
            network_param(state, crate::governance::PQ_LEG_REQUIRED_FROM_PARAM),
        )
        .map_err(|_| refuse("the receipt is not signed by the machine's registered identity key"))
    }
}

impl NativeExecutor {
    pub(super) async fn execute_inference_fault(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let op: InferenceFaultOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid InferenceFault payload: {}", e)))?;
        let gas = GAS_INFERENCE_FAULT + GAS_INFERENCE_FAULT_BYTE * (tx.data.len() as u64);
        gas_meter.consume(gas)?;
        let gas_cost = tx.gas_price.saturating_mul(gas as u128);
        let payer = state.get_balance(&tx.from);
        if payer < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: payer,
            });
        }

        let now = deterministic_now_ms(tx);
        let window = network_param(state, WINDOW_MS_PARAM) as i64;
        let mut changes = Vec::new();
        let mut logs = Vec::new();

        match op {
            InferenceFaultOp::File { evidence } => {
                let fault_id = evidence.fault_id();
                if read_fault(state, &fault_id).is_some() {
                    return Err(refuse("this fault was already filed"));
                }
                if !is_hex32(&evidence.receipt_digest) {
                    return Err(refuse("receipt_digest is 32-byte hex"));
                }
                if evidence.dispute.len() > MAX_FAULT_DISPUTE_BYTES {
                    return Err(refuse(format!(
                        "a dispute carries at most {} bytes",
                        MAX_FAULT_DISPUTE_BYTES
                    )));
                }
                hex::decode(evidence.requester.trim_start_matches("0x"))
                    .ok()
                    .filter(|a| !a.is_empty())
                    .ok_or_else(|| refuse("requester must be a hex address"))?;
                let served = evidence.served_at_ms as i64;
                if served > now || now > served.saturating_add(window) {
                    return Err(refuse(
                        "a fault is filed within the challenge window after the receipt was signed",
                    ));
                }
                let max_refund = network_param(state, MAX_REFUND_GWEI_PARAM) as u128 * GWEI;
                if evidence.refund > max_refund {
                    return Err(refuse(format!(
                        "a fault refunds at most {} wei",
                        max_refund
                    )));
                }
                if state
                    .get_storage(
                        &SYSTEM_ADDRESS,
                        compute_bond_storage_key(&evidence.provider_did).as_bytes(),
                    )
                    .is_none()
                {
                    return Err(refuse(format!(
                        "no compute bond for '{}'",
                        evidence.provider_did
                    )));
                }
                verify_receipt_signature(state, &evidence, now.max(0) as u64)?;
                let mut pending = live_pending(state, now, window);
                if pending.len() >= MAX_PENDING_FAULTS {
                    return Err(refuse("too many faults await a verdict; file again later"));
                }
                pending.push(fault_id.clone());
                write_pending(state, &pending, &mut changes)?;
                let record = FaultRecord {
                    fault_id,
                    evidence: FaultEvidence::Inference(evidence),
                    filed_at_ms: now,
                    attestations: Vec::new(),
                    upheld: None,
                    refunded: 0,
                    penalty: 0,
                };
                let blob = write_fault(state, &record, &mut changes)?;
                logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![INFERENCE_FAULT_FILED_TOPIC.to_vec()],
                    blob,
                ));
            }
            InferenceFaultOp::FileCatalog { evidence } => {
                if evidence.document.len() > MAX_FAULT_DISPUTE_BYTES {
                    return Err(refuse(format!(
                        "a catalog entry document is at most {MAX_FAULT_DISPUTE_BYTES} bytes"
                    )));
                }
                let document: serde_json::Value = serde_json::from_str(&evidence.document)
                    .map_err(|e| refuse(format!("the catalog entry document is not JSON: {e}")))?;
                let record = tenzro_trust::catalog::CatalogRecord::parse(&document)
                    .map_err(|e| refuse(format!("not a signed catalog entry: {e}")))?;
                let entry = record
                    .entry
                    .as_ref()
                    .ok_or_else(|| refuse("a withdrawn entry pins no bytes"))?;
                let pinned = entry
                    .get("components")
                    .and_then(|c| c.as_array())
                    .and_then(|c| c.get(evidence.component as usize))
                    .cloned()
                    .ok_or_else(|| {
                        refuse(format!("the entry has no component {}", evidence.component))
                    })?;
                // The bond that answers for the entry is the one held by the
                // account of the key that signed it.
                let account = record
                    .signer_account()
                    .filter(|a| role_bonded(state, a, NetworkRole::CatalogPublisher))
                    .ok_or_else(|| {
                        refuse(format!(
                            "the key that signed {}'s entry holds no catalog publisher bond",
                            record.publisher
                        ))
                    })?;
                let fault_id = catalog_fault_id(&record.digest, evidence.component);
                if read_fault(state, &fault_id).is_some() {
                    return Err(refuse("this fault was already filed"));
                }
                let mut pending = live_pending(state, now, window);
                if pending.len() >= MAX_PENDING_FAULTS {
                    return Err(refuse("too many faults await a verdict; file again later"));
                }
                pending.push(fault_id.clone());
                write_pending(state, &pending, &mut changes)?;
                let fault = FaultRecord {
                    fault_id,
                    evidence: FaultEvidence::Catalog(CatalogFault {
                        evidence,
                        publisher: record.publisher.clone(),
                        account: hex::encode(account),
                        model: record.model.clone(),
                        pinned,
                        digest: record.digest.clone(),
                    }),
                    filed_at_ms: now,
                    attestations: Vec::new(),
                    upheld: None,
                    refunded: 0,
                    penalty: 0,
                };
                let blob = write_fault(state, &fault, &mut changes)?;
                logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![INFERENCE_FAULT_FILED_TOPIC.to_vec()],
                    blob,
                ));
            }
            InferenceFaultOp::Attest { fault_id, upheld } => {
                let stake = bonded_stake_of(state, &tx.from);
                if stake == 0 {
                    return Err(refuse(
                        "only accounts with bonded stake may attest inference faults",
                    ));
                }
                let mut record = read_fault(state, &fault_id)
                    .ok_or_else(|| refuse(format!("no inference fault '{}'", fault_id)))?;
                if record.upheld.is_some() {
                    return Err(refuse("this fault is already decided"));
                }
                if now > record.filed_at_ms.saturating_add(window) {
                    return Err(refuse("this fault's challenge window has closed"));
                }
                let me = hex::encode(&tx.from);
                if record.attestations.iter().any(|a| a.validator == me) {
                    return Err(refuse("this validator already attested the fault"));
                }
                record.attestations.push(FaultAttestation {
                    validator: me,
                    upheld,
                    stake,
                });
                let (up, down) = record
                    .attestations
                    .iter()
                    .fold((0u128, 0u128), |(u, d), a| {
                        if a.upheld {
                            (u.saturating_add(a.stake), d)
                        } else {
                            (u, d.saturating_add(a.stake))
                        }
                    });
                let total = total_bonded_stake(state);
                if total > 0 && up.saturating_add(down).saturating_mul(3) >= total.saturating_mul(2)
                {
                    let verdict = up > down;
                    record.upheld = Some(verdict);
                    if verdict {
                        match &record.evidence {
                            FaultEvidence::Inference(evidence) => {
                                let (refunded, penalty, bond_log) =
                                    slash_for_fault(state, evidence, &mut changes)?;
                                record.refunded = refunded;
                                record.penalty = penalty;
                                logs.extend(bond_log);
                            }
                            FaultEvidence::Catalog(fault) => {
                                record.penalty = slash_publisher(state, fault, &mut changes)?;
                                // The entry stays out of every node's catalog.
                                super::funding::write_json(
                                    state,
                                    &faulted_entry_key(&fault.digest),
                                    &record.fault_id,
                                    &mut changes,
                                )?;
                            }
                        }
                    }
                    let pending: Vec<String> = live_pending(state, now, window)
                        .into_iter()
                        .filter(|id| *id != record.fault_id)
                        .collect();
                    write_pending(state, &pending, &mut changes)?;
                    let blob = write_fault(state, &record, &mut changes)?;
                    logs.push(Log::new(
                        SYSTEM_ADDRESS.to_vec(),
                        vec![INFERENCE_FAULT_DECIDED_TOPIC.to_vec()],
                        blob,
                    ));
                } else {
                    write_fault(state, &record, &mut changes)?;
                }
            }
        }

        state.set_balance(
            &tx.from,
            state.get_balance(&tx.from).saturating_sub(gas_cost),
        );
        changes.insert(
            0,
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(payer.to_le_bytes().to_vec()),
                Some(state.get_balance(&tx.from).to_le_bytes().to_vec()),
            ),
        );
        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            Vec::new(),
            logs,
            changes,
        ))
    }
}

/// Take the governed share of an upheld catalog fault's publisher's model
/// provider stake into the insurance pool. Returns the amount taken.
fn slash_publisher(
    state: &mut dyn VmState,
    fault: &CatalogFault,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let account = hex::decode(&fault.account)
        .map_err(|e| VmError::Internal(format!("publisher account: {e}")))?;
    let bps = network_param(state, CATALOG_FAULT_SLASH_BPS_PARAM).min(10_000) as u16;
    let taken =
        role_stake::take_role_stake(state, &account, NetworkRole::CatalogPublisher, bps, changes)?;
    let pool = derive_insurance_pool_address().as_bytes().to_vec();
    let before = state.get_balance(&pool);
    let after = before.saturating_add(taken);
    state.set_balance(&pool, after);
    changes.push(StateChange::new(
        pool,
        b"balance".to_vec(),
        Some(before.to_le_bytes().to_vec()),
        Some(after.to_le_bytes().to_vec()),
    ));
    insurance::note_credit(state, taken, insurance::PoolSource::Slash, changes)?;
    Ok(taken)
}

/// Pay an upheld fault out of the provider's bond vault: the refund to the
/// requester first, then the penalty on what it paid to the insurance pool.
fn slash_for_fault(
    state: &mut dyn VmState,
    evidence: &InferenceFaultEvidence,
    changes: &mut Vec<StateChange>,
) -> Result<(u128, u128, Option<Log>)> {
    let requester = hex::decode(evidence.requester.trim_start_matches("0x"))
        .map_err(|e| VmError::Internal(format!("fault requester: {}", e)))?;
    let penalty = penalty_due(state, evidence.refund);
    slash_compute_bond(
        state,
        &evidence.provider_did,
        Some((requester, evidence.refund)),
        penalty,
        changes,
    )
}

/// The one slash of a compute bond. Pays `refund` (account, amount) out of the
/// bond vault first, then up to `penalty_due` into the insurance pool, both
/// capped by what the vault holds. The bond marker's amount falls by the
/// total; a bond emptied this way is marked `Slashed`. A bond that does not
/// exist slashes nothing. Returns (refunded, penalty, the `ComputeBondSlashed`
/// log the node mirrors into its bond index).
pub(crate) fn slash_compute_bond(
    state: &mut dyn VmState,
    provider_did: &str,
    refund: Option<(Vec<u8>, u128)>,
    penalty_due: u128,
    changes: &mut Vec<StateChange>,
) -> Result<(u128, u128, Option<Log>)> {
    let key = compute_bond_storage_key(provider_did);
    let Some(marker_blob) = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()) else {
        return Ok((0, 0, None));
    };
    let mut marker: serde_json::Value = serde_json::from_slice(&marker_blob)
        .map_err(|e| VmError::Internal(format!("decode compute bond marker: {}", e)))?;
    let vault = derive_compute_bond_vault_address(provider_did);
    let vault_bytes = vault.as_bytes().to_vec();
    let vault_before = state.get_balance(&vault_bytes);
    let (refund_to, refund_due) = refund.unwrap_or_default();
    let refunded = refund_due.min(vault_before);
    let penalty = penalty_due.min(vault_before - refunded);

    let pool = derive_insurance_pool_address().as_bytes().to_vec();
    for (to, amount) in [(refund_to, refunded), (pool, penalty)] {
        if amount == 0 {
            continue;
        }
        let before = state.get_balance(&to);
        let after = before
            .checked_add(amount)
            .ok_or_else(|| VmError::Internal("balance overflow".to_string()))?;
        state.set_balance(&to, after);
        changes.push(StateChange::new(
            to,
            b"balance".to_vec(),
            Some(before.to_le_bytes().to_vec()),
            Some(after.to_le_bytes().to_vec()),
        ));
    }
    super::insurance::note_credit(state, penalty, super::insurance::PoolSource::Slash, changes)?;
    let vault_after = vault_before - refunded - penalty;
    state.set_balance(&vault_bytes, vault_after);
    changes.push(StateChange::new(
        vault_bytes,
        b"balance".to_vec(),
        Some(vault_before.to_le_bytes().to_vec()),
        Some(vault_after.to_le_bytes().to_vec()),
    ));

    let slashed = refunded + penalty;
    if slashed == 0 {
        return Ok((0, 0, None));
    }
    let amount: u128 = marker
        .get("amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let remaining = amount.saturating_sub(slashed);
    marker["amount"] = serde_json::Value::String(remaining.to_string());
    if remaining == 0 {
        marker["op"] = serde_json::Value::String("Slashed".to_string());
    }
    let blob = serde_json::to_vec(&marker)
        .map_err(|e| VmError::Internal(format!("encode compute bond marker: {}", e)))?;
    put(state, &key, blob, changes);

    let provider_address = marker
        .get("provider_address")
        .and_then(|v| v.as_str())
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default();
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![COMPUTE_BOND_SLASHED_TOPIC.to_vec()],
        encode_compute_bond_log_data(
            provider_did,
            &provider_address,
            slashed,
            COMPUTE_BOND_SLASHED_OP,
            0,
        ),
    );
    Ok((refunded, penalty, Some(log)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    const DID: &str = "did:tenzro:machine:provider";

    fn bond_validator(state: &mut StateAdapter, who: &[u8], stake: u128) {
        staking::add_bond(state, who, stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
        let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        state.set_balance(&STAKING_VAULT_ADDRESS, vault + stake);
        state.set_balance(who, 10_000_000_000_000_000_000);
    }

    /// The hardware identity (hybrid, so both legs are checked) of the
    /// machine with `seed`; the provider is seed 3.
    fn identity_of(seed: u8) -> tenzro_crypto::CompositePublicKey {
        tenzro_crypto::composite::HybridSigner::public_key(
            &tenzro_crypto::testing::TestHybridSigner::hybrid(seed),
        )
        .clone()
    }

    /// Register `did` on chain with `key` as its hardware identity.
    fn register(state: &mut StateAdapter, did: &str, key: &tenzro_crypto::CompositePublicKey) {
        let record = tenzro_types::identity::RegisterIdentityPayload {
            did: did.into(),
            identity_type: "machine".into(),
            display_name: String::new(),
            controller_pubkey: key.p256.clone(),
            key_type: "p256".into(),
            wallet_id: String::new(),
            wallet_address: tenzro_types::primitives::Address::new([5; 32]),
            pq_verifying_key: key.pq.clone().unwrap_or_default(),
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            &super::super::identity_storage_key(did),
            serde_json::to_vec(&record).unwrap(),
        );
    }

    fn bond(state: &mut StateAdapter, amount: u128) {
        register(state, DID, &identity_of(3));
        let marker = serde_json::json!({
            "provider_did": DID,
            "provider_address": hex::encode([5u8; 20]),
            "amount": amount.to_string(),
            "op": "Posted",
        });
        state.set_storage(
            &SYSTEM_ADDRESS,
            compute_bond_storage_key(DID).as_bytes(),
            serde_json::to_vec(&marker).unwrap(),
        );
        state.set_balance(derive_compute_bond_vault_address(DID).as_bytes(), amount);
    }

    fn evidence(served_at_ms: u64, refund: u128) -> InferenceFaultEvidence {
        signed_evidence(3, DID, DID, served_at_ms, refund)
    }

    /// A receipt naming machine `named`, signed at `served_at_ms` in a
    /// hardware batch by the identity of seed `seed`, filed against the bond
    /// of `bonded`.
    fn signed_evidence(
        seed: u8,
        named: &str,
        bonded: &str,
        served_at_ms: u64,
        refund: u128,
    ) -> InferenceFaultEvidence {
        use sha2::{Digest, Sha256};
        use tenzro_crypto::batch::{BatchParams, BatchService};
        use tenzro_types::inference_verification::{
            INFERENCE_RECEIPT_DOMAIN, put_receipt_field, receipt_preimage_tail,
        };
        let key = identity_of(seed);
        let mut preimage = INFERENCE_RECEIPT_DOMAIN.to_vec();
        for field in ["m", "model-hash", "engine", named, "nonce"] {
            put_receipt_field(&mut preimage, field.as_bytes());
        }
        preimage.extend_from_slice(&receipt_preimage_tail(
            served_at_ms,
            &key.p256,
            key.pq.as_deref(),
        ));
        let svc = BatchService::new(
            std::sync::Arc::new(tenzro_crypto::testing::TestHybridSigner::hybrid(seed)),
            BatchParams {
                max_batch: 8,
                flush_interval_ms: 1_000,
            },
            0,
        )
        .unwrap();
        let sig = svc.sign_now(preimage.clone(), served_at_ms).unwrap();
        InferenceFaultEvidence {
            receipt_digest: hex::encode(Sha256::digest(&preimage)),
            provider_did: bonded.to_string(),
            receipt_preimage: hex::encode(&preimage),
            batched: hex::encode(serde_json::to_vec(&sig).unwrap()),
            requester: hex::encode([7u8; 20]),
            refund,
            served_at_ms,
            dispute: "{}".to_string(),
        }
    }

    fn fault_tx(from: &[u8], op: &InferenceFaultOp, now_ms: i64) -> VmTransaction {
        let mut data = SELECTOR_INFERENCE_FAULT.to_vec();
        data.extend_from_slice(&serde_json::to_vec(op).unwrap());
        let mut tx = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            10_000_000,
            0,
            0,
            VmType::Tenzro,
            1337,
        );
        tx.block_timestamp_ms = Some(now_ms);
        tx
    }

    fn attest(fault_id: &str, upheld: bool) -> InferenceFaultOp {
        InferenceFaultOp::Attest {
            fault_id: fault_id.to_string(),
            upheld,
        }
    }

    #[test]
    fn the_sample_share_never_falls_to_zero_and_rises_with_the_payment() {
        const TNZO: u128 = 1_000_000_000 * GWEI;
        let state = StateAdapter::new();
        assert_eq!(sample_bps_for(&state, 0), DEFAULT_SAMPLE_BPS);
        assert_eq!(sample_bps_for(&state, TNZO - 1), DEFAULT_SAMPLE_BPS);
        assert_eq!(
            sample_bps_for(&state, 2 * TNZO),
            DEFAULT_SAMPLE_BPS + 2 * DEFAULT_SAMPLE_STEP_BPS
        );
        assert_eq!(sample_bps_for(&state, 1_000 * TNZO), 10_000);
        assert_eq!(sample_bps_for(&state, u128::MAX), 10_000);
        // A zero floor or a zero step read from state still samples.
        assert_eq!(sample_bps_with(0, 0, 0, 0), 1);
        assert_eq!(sample_bps_with(0, 0, 1, u128::MAX), 10_000);
    }

    #[test]
    fn the_sample_floor_cannot_be_governed_to_zero() {
        let p = crate::governance::governed_param(SAMPLE_BPS_PARAM).unwrap();
        assert!(p.min >= 1);
    }

    #[tokio::test]
    async fn an_upheld_fault_refunds_the_requester_and_slashes_the_bond_once() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (a, b, c) = (vec![1u8; 20], vec![2u8; 20], vec![3u8; 20]);
        bond_validator(&mut state, &a, 100);
        bond_validator(&mut state, &b, 100);
        bond_validator(&mut state, &c, 100);
        let bonded = 3 * 1_000_000_000 * GWEI;
        bond(&mut state, bonded);
        let now = 1_000_000;
        let ev = evidence(now as u64 - 10, 7 * GWEI);
        let id = ev.fault_id();
        let filer = vec![9u8; 20];
        state.set_balance(&filer, 1);
        executor
            .execute_transaction(
                &fault_tx(
                    &filer,
                    &InferenceFaultOp::File {
                        evidence: ev.clone(),
                    },
                    now,
                ),
                &mut state,
            )
            .await
            .unwrap();
        assert_eq!(pending_faults(&state), vec![id.clone()]);
        // Filed once.
        assert!(
            executor
                .execute_transaction(
                    &fault_tx(
                        &filer,
                        &InferenceFaultOp::File {
                            evidence: ev.clone()
                        },
                        now
                    ),
                    &mut state
                )
                .await
                .is_err()
        );
        // Only bonded stake attests.
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &attest(&id, true), now), &mut state)
                .await
                .is_err()
        );

        executor
            .execute_transaction(&fault_tx(&a, &attest(&id, true), now), &mut state)
            .await
            .unwrap();
        assert!(
            executor
                .execute_transaction(&fault_tx(&a, &attest(&id, true), now), &mut state)
                .await
                .is_err()
        );
        assert_eq!(
            read_fault(&state, &id).unwrap().upheld,
            None,
            "a third of the stake decides nothing"
        );
        let r = executor
            .execute_transaction(&fault_tx(&b, &attest(&id, true), now), &mut state)
            .await
            .unwrap();
        assert!(
            r.logs
                .iter()
                .any(|l| l.topics[0] == COMPUTE_BOND_SLASHED_TOPIC.to_vec())
        );

        let f = read_fault(&state, &id).unwrap();
        assert_eq!(f.upheld, Some(true));
        assert_eq!(f.refunded, 7 * GWEI);
        // A small payment pays the USD floor: ten cents, one TNZO at the
        // genesis rate.
        assert_eq!(f.penalty, 1_000_000_000 * GWEI);
        assert_eq!(f.penalty, penalty_due(&state, 7 * GWEI));
        assert_eq!(state.get_balance(&[7u8; 20]), 7 * GWEI);
        assert_eq!(
            state.get_balance(derive_compute_bond_vault_address(DID).as_bytes()),
            bonded - f.refunded - f.penalty
        );
        assert!(pending_faults(&state).is_empty());
        // Decided: a late attestation moves nothing.
        assert!(
            executor
                .execute_transaction(&fault_tx(&c, &attest(&id, false), now), &mut state)
                .await
                .is_err()
        );
    }

    /// The penalty is the governed multiple of the payment, at least a USD
    /// floor converted at the rate in force: a fall in the TNZO price raises
    /// it in TNZO, and the multiple is held at or above the inverse of the
    /// least sampling share, so a substituted answer never pays in
    /// expectation whatever it saves.
    #[test]
    fn the_penalty_scales_with_the_payment_and_holds_its_usd_floor() {
        const TNZO: u128 = 1_000_000_000 * GWEI;
        let set = |state: &mut StateAdapter, key: &str, value: u64| {
            state.set_storage(
                &SYSTEM_ADDRESS,
                governed_param_key(key).as_bytes(),
                value.to_le_bytes().to_vec(),
            );
        };
        let mut state = StateAdapter::new();
        assert_eq!(penalty_due(&state, 0), TNZO);
        assert_eq!(penalty_due(&state, TNZO / 100), TNZO);
        assert_eq!(penalty_due(&state, 100 * TNZO), 2_000 * TNZO);
        // TNZO falls 90%: the floor is ten cents still, ten TNZO now.
        set(
            &mut state,
            crate::native::economy::GOVERNANCE_RATE_PARAM,
            10_000_000,
        );
        assert_eq!(penalty_due(&state, 0), 10 * TNZO);
        assert_eq!(penalty_due(&state, 100 * TNZO), 2_000 * TNZO);
        assert_eq!(penalty_due(&state, u128::MAX), u128::MAX);
        // Expected loss at the least sampling share covers the whole payment.
        for payment in [1u128, 10_001, TNZO, 1_000 * TNZO] {
            let p = u128::from(sample_bps_for(&state, payment));
            assert!(p * (payment + penalty_due(&state, payment)) >= 10_000 * payment);
        }
    }

    #[tokio::test]
    async fn the_payout_never_exceeds_the_bond_and_an_emptied_bond_is_slashed() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (a, b) = (vec![1u8; 20], vec![2u8; 20]);
        bond_validator(&mut state, &a, 100);
        bond_validator(&mut state, &b, 100);
        bond(&mut state, 50 * GWEI);
        let now = 1_000_000;
        let ev = evidence(now as u64, 30 * GWEI);
        let id = ev.fault_id();
        executor
            .execute_transaction(
                &fault_tx(&a, &InferenceFaultOp::File { evidence: ev }, now),
                &mut state,
            )
            .await
            .unwrap();
        executor
            .execute_transaction(&fault_tx(&a, &attest(&id, true), now), &mut state)
            .await
            .unwrap();
        executor
            .execute_transaction(&fault_tx(&b, &attest(&id, true), now), &mut state)
            .await
            .unwrap();
        let f = read_fault(&state, &id).unwrap();
        // The refund comes first, the penalty takes what is left.
        assert_eq!((f.refunded, f.penalty), (30 * GWEI, 20 * GWEI));
        assert_eq!(
            state.get_balance(derive_compute_bond_vault_address(DID).as_bytes()),
            0
        );
        let marker: serde_json::Value = serde_json::from_slice(
            &state
                .get_storage(&SYSTEM_ADDRESS, compute_bond_storage_key(DID).as_bytes())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (marker["op"].as_str(), marker["amount"].as_str()),
            (Some("Slashed"), Some("0"))
        );
    }

    /// A catalog entry for `model` with one hub component, signed by the
    /// P-256 key from `seed`; returns the document and the key's account.
    fn signed_entry(seed: u8, model: &str) -> (serde_json::Value, [u8; 32]) {
        use tenzro_crypto::p256::{P256KeyPair, P256Signer};
        use tenzro_trust::proof::{
            ProofRequest, attach_hardware, machine_did, options, signing_digest,
        };
        let key = P256Signer::from_keypair(&P256KeyPair::from_secret_bytes(&[seed; 32]).unwrap());
        let sec1 = key.public_key_sec1();
        let did = machine_did(&sec1);
        let entry = serde_json::json!({
            "model": { "spec": { "id": model } },
            "components": [{
                "repo": "o/m", "path": "m.gguf", "revision": "c".repeat(40),
                "size": 4, "sha256": "ab".repeat(32),
            }],
        });
        let doc = tenzro_trust::catalog::CatalogRecord::unsigned(&did, model, 1, Some(&entry));
        let opts = options(&ProofRequest {
            signer_did: did,
            public_key_sec1: sec1,
            purpose: "assertionMethod".into(),
            created: "2026-10-05T00:00:00Z".into(),
            rp_id: None,
        });
        let sig: [u8; 64] = key
            .sign_prehash(&signing_digest(&doc, &opts))
            .as_bytes()
            .try_into()
            .unwrap();
        (
            attach_hardware(doc, opts, &sig),
            tenzro_crypto::composite::account_slot(&sec1[1..]),
        )
    }

    #[tokio::test]
    async fn an_upheld_catalog_fault_slashes_the_publishers_bond_and_an_unbonded_signer_is_refused()
    {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (a, b) = (vec![1u8; 20], vec![2u8; 20]);
        bond_validator(&mut state, &a, 100);
        bond_validator(&mut state, &b, 100);
        let now = 1_000_000;

        let (unbonded_doc, _) = signed_entry(8, "m-other");
        let refused = executor
            .execute_transaction(
                &fault_tx(
                    &a,
                    &InferenceFaultOp::FileCatalog {
                        evidence: CatalogFaultEvidence {
                            document: unbonded_doc.to_string(),
                            component: 0,
                        },
                    },
                    now,
                ),
                &mut state,
            )
            .await;
        assert!(
            refused.is_err(),
            "an entry nobody bonded for slashes nothing"
        );

        let (doc, account) = signed_entry(7, "m-seed");
        let stake = tenzro_types::constants::MIN_CATALOG_PUBLISHER_STAKE;
        role_stake::bond_role_for_test(&mut state, &account, NetworkRole::CatalogPublisher, stake);
        let evidence = CatalogFaultEvidence {
            document: doc.to_string(),
            component: 0,
        };
        let digest = tenzro_trust::catalog::CatalogRecord::parse(&doc)
            .unwrap()
            .digest;
        let id = catalog_fault_id(&digest, 0);
        assert!(
            executor
                .execute_transaction(
                    &fault_tx(
                        &a,
                        &InferenceFaultOp::FileCatalog {
                            evidence: CatalogFaultEvidence {
                                document: doc.to_string(),
                                component: 3
                            },
                        },
                        now
                    ),
                    &mut state,
                )
                .await
                .is_err(),
            "the entry has one component"
        );
        executor
            .execute_transaction(
                &fault_tx(&a, &InferenceFaultOp::FileCatalog { evidence }, now),
                &mut state,
            )
            .await
            .unwrap();
        executor
            .execute_transaction(&fault_tx(&a, &attest(&id, true), now), &mut state)
            .await
            .unwrap();
        executor
            .execute_transaction(&fault_tx(&b, &attest(&id, true), now), &mut state)
            .await
            .unwrap();
        let record = read_fault(&state, &id).unwrap();
        assert_eq!(record.upheld, Some(true));
        let taken = stake * DEFAULT_CATALOG_FAULT_SLASH_BPS as u128 / 10_000;
        assert_eq!(record.penalty, taken);
        assert!(
            catalog_entry_faulted(&state, &digest),
            "an upheld entry is never served again"
        );
        assert_eq!(
            role_stake::read_role_stake(&state, &account, NetworkRole::CatalogPublisher)
                .unwrap()
                .bonded,
            stake - taken
        );
    }

    #[tokio::test]
    async fn a_dismissed_fault_slashes_nothing() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (a, b) = (vec![1u8; 20], vec![2u8; 20]);
        bond_validator(&mut state, &a, 100);
        bond_validator(&mut state, &b, 100);
        bond(&mut state, 5_000 * GWEI);
        let now = 1_000_000;
        let ev = evidence(now as u64, GWEI);
        let id = ev.fault_id();
        executor
            .execute_transaction(
                &fault_tx(&a, &InferenceFaultOp::File { evidence: ev }, now),
                &mut state,
            )
            .await
            .unwrap();
        executor
            .execute_transaction(&fault_tx(&a, &attest(&id, false), now), &mut state)
            .await
            .unwrap();
        executor
            .execute_transaction(&fault_tx(&b, &attest(&id, false), now), &mut state)
            .await
            .unwrap();
        assert_eq!(read_fault(&state, &id).unwrap().upheld, Some(false));
        assert_eq!(
            state.get_balance(derive_compute_bond_vault_address(DID).as_bytes()),
            5_000 * GWEI
        );
    }

    #[tokio::test]
    async fn a_fault_outside_the_window_or_against_another_key_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        bond(&mut state, 5_000 * GWEI);
        let filer = vec![9u8; 20];
        let now = (DEFAULT_WINDOW_MS as i64) * 3;
        let file = |ev| InferenceFaultOp::File { evidence: ev };
        // Too late.
        let stale = evidence((now - DEFAULT_WINDOW_MS as i64 - 1) as u64, GWEI);
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(stale), now), &mut state)
                .await
                .is_err()
        );
        // Not yet served.
        let future = evidence((now + 1) as u64, GWEI);
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(future), now), &mut state)
                .await
                .is_err()
        );
        // A receipt signed by any identity other than the one registered for
        // the bonded machine, even one naming that machine.
        let forged = signed_evidence(4, DID, DID, now as u64, GWEI);
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(forged), now), &mut state)
                .await
                .is_err()
        );
        // A receipt naming another machine, filed against this bond.
        let elsewhere = signed_evidence(3, "did:tenzro:machine:other", DID, now as u64, GWEI);
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(elsewhere), now), &mut state)
                .await
                .is_err()
        );
        // A serving time the receipt does not state.
        let mut moved = evidence(now as u64 - 5, GWEI);
        moved.served_at_ms = now as u64;
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(moved), now), &mut state)
                .await
                .is_err()
        );
        // A digest that is not the preimage's.
        let mut digest = evidence(now as u64, GWEI);
        digest.receipt_digest = "cd".repeat(32);
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(digest), now), &mut state)
                .await
                .is_err()
        );
        // A filing with no batched signature is refused.
        let mut unsigned = evidence(now as u64, GWEI);
        unsigned.batched = String::new();
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(unsigned), now), &mut state)
                .await
                .is_err()
        );
        // The honest receipt is accepted.
        executor
            .execute_transaction(
                &fault_tx(&filer, &file(evidence(now as u64, GWEI)), now),
                &mut state,
            )
            .await
            .unwrap();
        // A refund above the governed cap.
        let greedy = evidence(now as u64, DEFAULT_MAX_REFUND_GWEI as u128 * GWEI + 1);
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(greedy), now), &mut state)
                .await
                .is_err()
        );
        // An unbonded provider.
        let mut unbonded = evidence(now as u64, GWEI);
        unbonded.provider_did = "did:tenzro:machine:none".to_string();
        assert!(
            executor
                .execute_transaction(&fault_tx(&filer, &file(unbonded), now), &mut state)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_undecided_fault_expires_with_its_window() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let (a, b) = (vec![1u8; 20], vec![2u8; 20]);
        bond_validator(&mut state, &a, 100);
        bond_validator(&mut state, &b, 300);
        bond(&mut state, 5_000 * GWEI);
        let now = 1_000_000;
        let ev = evidence(now as u64, GWEI);
        let id = ev.fault_id();
        executor
            .execute_transaction(
                &fault_tx(&a, &InferenceFaultOp::File { evidence: ev }, now),
                &mut state,
            )
            .await
            .unwrap();
        executor
            .execute_transaction(&fault_tx(&a, &attest(&id, true), now), &mut state)
            .await
            .unwrap();
        let late = now + DEFAULT_WINDOW_MS as i64 + 1;
        assert!(
            executor
                .execute_transaction(&fault_tx(&b, &attest(&id, true), late), &mut state)
                .await
                .is_err()
        );
        assert_eq!(
            state.get_balance(derive_compute_bond_vault_address(DID).as_bytes()),
            5_000 * GWEI
        );
    }
}
