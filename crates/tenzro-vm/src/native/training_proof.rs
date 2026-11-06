//! Training receipts and spot re-execution challenges in consensus state.
//!
//! A trainer machine commits one signed receipt per round
//! ([`TrainingReceipt`]): the checkpoint it started from, the shard, the
//! hyperparameters, the step count, the checkpoint it ended at and the step
//! log root, signed through a session key its registered hardware identity
//! certified, and bound to the escrow that pays for the round. The escrow
//! must pay the machine's bonded account and name this module's executor
//! ([`training_executor`]) as the only party besides the payer that may
//! release it, so the milestone moves only through here.
//!
//! Anyone may challenge a committed round within its challenge window,
//! posting the governed challenge bond. The challenge fixes a sampling seed
//! from the randomness beacon and records the governed sample count and
//! tolerance; bonded validators replay the sampled steps
//! ([`tenzro_types::training_verification::check_challenge`]) and attest.
//! Once attesters hold two thirds of bonded stake the verdict freezes.
//! Upheld, the trainer's compute bond is slashed through the one compute-bond
//! slash (a reward to the challenger, the penalty to the insurance pool), the
//! escrow returns to its payer, and the challenger's bond comes back less the
//! fee. Dismissed, the bond less the fee compensates the trainer. A challenge
//! with no quorum within the decision window expires and its bond comes back
//! less the fee. The fee goes to the insurance pool.
//!
//! A round whose receipt carries a confidential-compute attestation binding
//! the receipt digest gets the shorter governed TEE challenge window. The
//! milestone is released to the trainer only after the window has closed
//! with no challenge pending and none upheld.

use super::*;
use tenzro_types::training_verification::{
    MAX_KERNEL_CLASS_LEN, SignedTrainingReceipt, TrainingProofOp, TrainingReceipt, challenge_seed,
};

/// Selector for every training proof operation; the payload names which.
pub const SELECTOR_TRAINING_PROOF: [u8; 4] = [0x01, 0x00, 0x00, 0x77];

/// Gas for one operation, plus per byte of payload (a receipt may carry an
/// attestation report).
pub const GAS_TRAINING_PROOF: u64 = 80_000;
pub const GAS_TRAINING_PROOF_BYTE: u64 = 16;

/// Log topics.
pub const TRAINING_COMMITTED_TOPIC: &[u8] = b"TrainingReceiptCommitted";
pub const TRAINING_CHALLENGED_TOPIC: &[u8] = b"TrainingChallenged";
pub const TRAINING_DECIDED_TOPIC: &[u8] = b"TrainingChallengeDecided";
pub const TRAINING_SETTLED_TOPIC: &[u8] = b"TrainingRoundSettled";

/// How far a receipt may be signed ahead of the block that commits it, ms.
/// A block carries the time its slot opened, and the trainer's clock may run
/// ahead of the validators' within the network's 60 s tolerance, so a receipt
/// signed just before it is sent is a little ahead of that block.
pub const MAX_SIGNED_AHEAD_MS: i64 = 60_000;

/// Governed: challenge window after a receipt is committed, ms.
pub const WINDOW_MS_PARAM: &str = "training.challenge_window_ms";
pub const DEFAULT_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
/// Governed: challenge window of a round run in an attested TEE, ms.
pub const TEE_WINDOW_MS_PARAM: &str = "training.tee_challenge_window_ms";
pub const DEFAULT_TEE_WINDOW_MS: u64 = 60 * 60 * 1000;
/// Governed: how long validators have to decide a challenge after it was
/// filed, ms.
pub const DECIDE_WINDOW_MS_PARAM: &str = "training.decide_window_ms";
pub const DEFAULT_DECIDE_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
/// Governed: bond a challenger posts, gwei.
pub const CHALLENGE_BOND_GWEI_PARAM: &str = "training.challenge_bond_gwei";
pub const DEFAULT_CHALLENGE_BOND_GWEI: u64 = 10_000_000_000;
/// Governed: share of a challenge bond kept as the fee, bps.
pub const CHALLENGE_FEE_BPS_PARAM: &str = "training.challenge_fee_bps";
pub const DEFAULT_CHALLENGE_FEE_BPS: u64 = 500;
/// Governed: reward an upheld challenge pays its challenger out of the
/// trainer's bond, gwei.
pub const CHALLENGER_REWARD_GWEI_PARAM: &str = "training.challenger_reward_gwei";
pub const DEFAULT_CHALLENGER_REWARD_GWEI: u64 = 5_000_000_000;
/// Governed: penalty an upheld challenge pays the insurance pool out of the
/// trainer's bond, gwei.
pub const PENALTY_GWEI_PARAM: &str = "training.penalty_gwei";
pub const DEFAULT_PENALTY_GWEI: u64 = 10_000_000_000;
/// Governed: steps a verifier replays per challenge.
pub const SAMPLE_STEPS_PARAM: &str = "training.sample_steps";
pub const DEFAULT_SAMPLE_STEPS: u64 = 32;
/// Governed: largest distance (ppm) between a replayed and a claimed state
/// that still counts as reproduced.
pub const TOLERANCE_PPM_PARAM: &str = "training.tolerance_ppm";
pub const DEFAULT_TOLERANCE_PPM: u64 = 100;
/// Governed: most challenges one round may carry.
pub const MAX_CHALLENGES_PARAM: &str = "training.max_challenges";
pub const DEFAULT_MAX_CHALLENGES: u64 = 4;

const GWEI: u128 = 1_000_000_000;
const EXECUTOR_DOMAIN: &[u8] = b"tenzro/training/executor";
const BOND_VAULT_DOMAIN: &[u8] = b"tenzro/training/challenge-vault";

/// The executor a training milestone escrow names. It has no key; only this
/// module releases as it.
pub fn training_executor() -> Address {
    Address::new(Sha256::digest(EXECUTOR_DOMAIN).into())
}

/// The keyless vault holding posted challenge bonds.
pub fn challenge_vault() -> Address {
    Address::new(Sha256::digest(BOND_VAULT_DOMAIN).into())
}

/// How a challenge ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeOutcome {
    Upheld,
    Dismissed,
    /// No quorum within the decision window, or the round was voided by
    /// another challenge first.
    Expired,
}

/// Where a challenge bond goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondSplit {
    pub to_challenger: u128,
    pub to_trainer: u128,
    pub to_pool: u128,
}

/// Split a challenge bond of `bond` with a fee of `fee_bps`: the fee to the
/// insurance pool, the rest back to the challenger unless the challenge was
/// dismissed, when it compensates the trainer. The parts sum to `bond`.
pub fn split_challenge_bond(bond: u128, fee_bps: u64, outcome: ChallengeOutcome) -> BondSplit {
    let fee = staking::bps_share(bond, u128::from(fee_bps));
    let rest = bond - fee;
    match outcome {
        ChallengeOutcome::Dismissed => BondSplit {
            to_challenger: 0,
            to_trainer: rest,
            to_pool: fee,
        },
        ChallengeOutcome::Upheld | ChallengeOutcome::Expired => BondSplit {
            to_challenger: rest,
            to_trainer: 0,
            to_pool: fee,
        },
    }
}

/// One challenge of a round.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrainingChallenge {
    /// Hex account that posted the bond.
    pub challenger: String,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub bond: u128,
    pub filed_at_ms: i64,
    /// Hex seed the sampled steps are drawn from.
    pub seed: String,
    /// Steps a verifier replays and the tolerance (ppm) it compares within,
    /// as governed when the challenge was filed.
    pub samples: u64,
    pub tolerance_ppm: u64,
    pub attestations: Vec<inference_fault::FaultAttestation>,
    /// `None` while undecided.
    pub outcome: Option<ChallengeOutcome>,
}

/// How a round's milestone was settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundSettlement {
    /// Paid to the trainer after the window closed without a valid fault.
    Released,
    /// Returned to the payer after an upheld challenge.
    Voided,
}

/// A committed round as consensus state holds it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrainingRecord {
    pub receipt: TrainingReceipt,
    pub committed_at_ms: i64,
    /// The challenge window this round got, ms.
    pub window_ms: u64,
    /// Whether the receipt carried an accepted TEE attestation.
    pub tee: bool,
    /// Hex account the trainer's compute bond pays out to.
    pub trainer_account: String,
    pub challenges: Vec<TrainingChallenge>,
    pub settled: Option<RoundSettlement>,
}

impl TrainingRecord {
    /// When the challenge window closes, ms.
    pub fn window_end_ms(&self) -> i64 {
        self.committed_at_ms.saturating_add(self.window_ms as i64)
    }
}

fn record_key(receipt_id: &str) -> String {
    tenzro_types::training_verification::training_receipt_slot(receipt_id)
}

fn escrow_round_key(escrow_id: &str) -> String {
    format!("training_escrow:{}", escrow_id.to_ascii_lowercase())
}

/// The committed round `receipt_id`, if any.
pub fn read_training_record(state: &dyn VmState, receipt_id: &str) -> Option<TrainingRecord> {
    funding::read_json(state, &record_key(receipt_id))
}

/// The receipt committed against escrow `escrow_id`, if any.
pub fn round_of_escrow(state: &dyn VmState, escrow_id: &str) -> Option<String> {
    funding::read_json(state, &escrow_round_key(escrow_id))
}

fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(msg.into())
}

fn gwei_param(state: &dyn VmState, key: &str) -> u128 {
    u128::from(network_param(state, key)).saturating_mul(GWEI)
}

/// Move `amount` of TNZO between accounts, recording both balances.
fn pay(
    state: &mut dyn VmState,
    from: &[u8],
    to: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if amount == 0 || from == to {
        return Ok(());
    }
    let from_before = state.get_balance(from);
    let from_after = from_before
        .checked_sub(amount)
        .ok_or_else(|| VmError::Internal("training vault underfunded".to_string()))?;
    state.set_balance(from, from_after);
    changes.push(StateChange::new(
        from.to_vec(),
        b"balance".to_vec(),
        Some(from_before.to_le_bytes().to_vec()),
        Some(from_after.to_le_bytes().to_vec()),
    ));
    let to_before = state.get_balance(to);
    let to_after = to_before
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("balance overflow".to_string()))?;
    state.set_balance(to, to_after);
    changes.push(StateChange::new(
        to.to_vec(),
        b"balance".to_vec(),
        Some(to_before.to_le_bytes().to_vec()),
        Some(to_after.to_le_bytes().to_vec()),
    ));
    Ok(())
}

/// Pay out a closed challenge's bond from the vault.
fn close_challenge(
    state: &mut dyn VmState,
    record: &TrainingRecord,
    challenge: &mut TrainingChallenge,
    outcome: ChallengeOutcome,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    challenge.outcome = Some(outcome);
    let split = split_challenge_bond(
        challenge.bond,
        network_param(state, CHALLENGE_FEE_BPS_PARAM),
        outcome,
    );
    let vault = challenge_vault().as_bytes().to_vec();
    let challenger = hex::decode(&challenge.challenger)
        .map_err(|e| VmError::Internal(format!("challenger account: {e}")))?;
    let trainer = hex::decode(&record.trainer_account)
        .map_err(|e| VmError::Internal(format!("trainer account: {e}")))?;
    let pool = derive_insurance_pool_address().as_bytes().to_vec();
    pay(state, &vault, &challenger, split.to_challenger, changes)?;
    pay(state, &vault, &trainer, split.to_trainer, changes)?;
    pay(state, &vault, &pool, split.to_pool, changes)?;
    insurance::note_credit(state, split.to_pool, insurance::PoolSource::Fees, changes)
}

/// Expire every undecided challenge of `record` whose decision window ended
/// before `now`, or every undecided one when `all`.
fn expire_challenges(
    state: &mut dyn VmState,
    record: &mut TrainingRecord,
    now: i64,
    all: bool,
    changes: &mut Vec<StateChange>,
) -> Result<bool> {
    let decide = network_param(state, DECIDE_WINDOW_MS_PARAM) as i64;
    let mut challenges = std::mem::take(&mut record.challenges);
    let mut any = false;
    for c in challenges.iter_mut() {
        if c.outcome.is_none() && (all || now > c.filed_at_ms.saturating_add(decide)) {
            close_challenge(state, record, c, ChallengeOutcome::Expired, changes)?;
            any = true;
        }
    }
    record.challenges = challenges;
    Ok(any)
}

/// Return what remains of a voided round's escrow to its payer.
fn void_escrow(
    state: &mut dyn VmState,
    escrow_id: &[u8; 32],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let (storage_key, blob, mut escrow) = read_escrow_record(state, escrow_id)?;
    if escrow.status != EscrowStatus::Funded {
        return Ok(());
    }
    let remaining = escrow.amount - escrow.claimed;
    let payer = escrow.payer.as_bytes().to_vec();
    release_from_vault(
        state, escrow_id, &escrow, &payer, remaining, now_ms, changes,
    )?;
    escrow.status = EscrowStatus::Refunded;
    changes.push(write_escrow_record(
        state,
        &storage_key,
        Some(blob),
        &escrow,
    )?);
    Ok(())
}

/// Check the batched signature over the receipt digest: the trainer's
/// registered hardware identity signed the batch holding it.
fn verify_receipt_signature(
    state: &dyn VmState,
    signed: &SignedTrainingReceipt,
    now_ms: u64,
) -> Result<()> {
    let key = super::registered_identity_key(state, &signed.receipt.trainer_did)?;
    {
        let batched = signed.batched.as_str();
        let sig: tenzro_crypto::batch::BatchedSignature = hex::decode(batched)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .ok_or_else(|| refuse("batched is not the hex of a batched signature"))?;
        sig.verify_for_record_at_block(
            &key,
            &signed.receipt.digest(),
            signed.receipt.signed_at_ms,
            now_ms,
            tenzro_crypto::batch::batch_skew_ms(),
            network_param(state, crate::governance::MAX_RECORD_AGE_PARAM),
            network_param(state, crate::governance::PQ_LEG_REQUIRED_FROM_PARAM),
        )
        .map_err(|_| refuse("the receipt is not signed by the trainer's registered identity key"))
    }
}

/// The account a machine's compute bond belongs to, and what its vault holds.
fn trainer_bond(state: &dyn VmState, did: &str) -> Result<(Vec<u8>, u128)> {
    let marker: serde_json::Value = state
        .get_storage(&SYSTEM_ADDRESS, compute_bond_storage_key(did).as_bytes())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| refuse(format!("no compute bond for '{did}'")))?;
    if marker.get("op").and_then(|v| v.as_str()) == Some("Slashed") {
        return Err(refuse(format!("the compute bond of '{did}' was slashed")));
    }
    let account = marker
        .get("provider_address")
        .and_then(|v| v.as_str())
        .and_then(|s| hex::decode(s).ok())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| refuse(format!("the compute bond of '{did}' names no account")))?;
    let held = state.get_balance(derive_compute_bond_vault_address(did).as_bytes());
    Ok((account, held))
}

impl NativeExecutor {
    pub(super) async fn execute_training_proof(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let op: TrainingProofOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid TrainingProof payload: {e}")))?;
        let gas = GAS_TRAINING_PROOF + GAS_TRAINING_PROOF_BYTE * (tx.data.len() as u64);
        gas_meter.consume(gas)?;
        let gas_cost = tx.gas_price.saturating_mul(gas as u128);
        require_balance(state, &tx.from, gas_cost)?;

        let now = deterministic_now_ms(tx);
        let mut changes = Vec::new();
        let mut logs = Vec::new();
        // TNZO a settled round's release burned, declared with the result.
        let mut released_burn: u128 = 0;
        let topic: &[u8];
        let record = match op {
            TrainingProofOp::Commit { receipt } => {
                topic = TRAINING_COMMITTED_TOPIC;
                self.commit(state, receipt, now, &mut changes)?
            }
            TrainingProofOp::Challenge { receipt_id } => {
                topic = TRAINING_CHALLENGED_TOPIC;
                let mut record = read_training_record(state, &receipt_id)
                    .ok_or_else(|| refuse(format!("no training receipt '{receipt_id}'")))?;
                if record.settled.is_some() {
                    return Err(refuse("this round is already settled"));
                }
                if now > record.window_end_ms() {
                    return Err(refuse("this round's challenge window has closed"));
                }
                let max = network_param(state, MAX_CHALLENGES_PARAM) as usize;
                if record.challenges.len() >= max {
                    return Err(refuse(format!("a round carries at most {max} challenges")));
                }
                let bond = gwei_param(state, CHALLENGE_BOND_GWEI_PARAM);
                require_balance(state, &tx.from, bond.saturating_add(gas_cost))?;
                pay(
                    state,
                    &tx.from,
                    challenge_vault().as_bytes(),
                    bond,
                    &mut changes,
                )?;
                let index = record.challenges.len() as u32;
                let mix = beacon::read_head(state).mix;
                let seed = challenge_seed(
                    &record.receipt.receipt_id(),
                    index,
                    &hex::decode(&mix).unwrap_or_default(),
                );
                record.challenges.push(TrainingChallenge {
                    challenger: hex::encode(&tx.from),
                    bond,
                    filed_at_ms: now,
                    seed: hex::encode(seed),
                    samples: network_param(state, SAMPLE_STEPS_PARAM),
                    tolerance_ppm: network_param(state, TOLERANCE_PPM_PARAM),
                    attestations: Vec::new(),
                    outcome: None,
                });
                record
            }
            TrainingProofOp::Attest {
                receipt_id,
                challenge,
                upheld,
            } => {
                topic = TRAINING_DECIDED_TOPIC;
                self.attest(
                    state,
                    tx,
                    &receipt_id,
                    challenge,
                    upheld,
                    now,
                    &mut changes,
                    &mut logs,
                )?
            }
            TrainingProofOp::Settle { receipt_id } => {
                topic = TRAINING_SETTLED_TOPIC;
                let mut record = read_training_record(state, &receipt_id)
                    .ok_or_else(|| refuse(format!("no training receipt '{receipt_id}'")))?;
                let expired = expire_challenges(state, &mut record, now, false, &mut changes)?;
                let pending = record.challenges.iter().any(|c| c.outcome.is_none());
                let releasable =
                    record.settled.is_none() && !pending && now > record.window_end_ms();
                if releasable {
                    let escrow_id = record.receipt.digests().map_err(refuse)?.escrow_id;
                    let (_, _, escrow) = read_escrow_record(state, &escrow_id)?;
                    if escrow.status == EscrowStatus::Funded {
                        let proof = ServiceProof::new(
                            tenzro_types::settlement::ProofType::Cryptographic,
                            record.receipt.digest().to_vec(),
                        );
                        let (release_changes, log, b) = release_escrow(
                            state,
                            &escrow_id,
                            &proof,
                            training_executor().as_bytes(),
                            now,
                        )?;
                        changes.extend(release_changes);
                        logs.push(log);
                        released_burn = b;
                    }
                    record.settled = Some(RoundSettlement::Released);
                } else if !expired {
                    return Err(refuse(if pending {
                        "a challenge of this round is still being decided"
                    } else if record.settled.is_some() {
                        "this round is already settled"
                    } else {
                        "this round's challenge window is still open"
                    }));
                }
                record
            }
        };
        let blob = serde_json::to_vec(&record)
            .map_err(|e| VmError::Internal(format!("encode training record: {e}")))?;
        funding::write_json(
            state,
            &record_key(&record.receipt.receipt_id()),
            &record,
            &mut changes,
        )?;
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![topic.to_vec()],
            blob,
        ));
        changes.extend(charge_and_advance(tx, state, gas_cost));
        Ok(
            ExecutionResult::success(gas_meter.final_used(), Vec::new(), logs, changes)
                .with_burn(released_burn),
        )
    }

    fn commit(
        &self,
        state: &mut dyn VmState,
        signed: SignedTrainingReceipt,
        now: i64,
        changes: &mut Vec<StateChange>,
    ) -> Result<TrainingRecord> {
        let receipt = &signed.receipt;
        let digests = receipt.digests().map_err(refuse)?;
        if receipt.steps == 0 {
            return Err(refuse("a round takes at least one step"));
        }
        if receipt.kernel_class.is_empty() || receipt.kernel_class.len() > MAX_KERNEL_CLASS_LEN {
            return Err(refuse(format!(
                "kernel_class is 1..={MAX_KERNEL_CLASS_LEN} bytes"
            )));
        }
        if receipt.signed_at_ms as i64 > now.saturating_add(MAX_SIGNED_AHEAD_MS) {
            return Err(refuse("the receipt is signed in the future"));
        }
        let receipt_id = receipt.receipt_id();
        if read_training_record(state, &receipt_id).is_some() {
            return Err(refuse("this receipt was already committed"));
        }
        if round_of_escrow(state, &receipt.escrow_id).is_some() {
            return Err(refuse("this escrow already settles another round"));
        }
        let (trainer_account, bond_held) = trainer_bond(state, &receipt.trainer_did)?;
        let at_stake = gwei_param(state, PENALTY_GWEI_PARAM)
            .saturating_add(gwei_param(state, CHALLENGER_REWARD_GWEI_PARAM));
        if bond_held < at_stake {
            return Err(refuse(format!(
                "the trainer's compute bond holds {bond_held} wei; a round needs {at_stake}"
            )));
        }
        verify_receipt_signature(state, &signed, now.max(0) as u64)?;

        let tee = match &signed.tee {
            None => false,
            Some(report) => {
                if !crate::precompiles::tee_report_acceptable(
                    report,
                    &receipt.digest(),
                    (now.max(0) / 1000) as u64,
                ) {
                    return Err(refuse(
                        "the TEE attestation does not verify or does not bind this receipt",
                    ));
                }
                true
            }
        };
        let window_ms = network_param(
            state,
            if tee {
                TEE_WINDOW_MS_PARAM
            } else {
                WINDOW_MS_PARAM
            },
        );

        let (_, _, escrow) = read_escrow_record(state, &digests.escrow_id)?;
        if escrow.status != EscrowStatus::Funded {
            return Err(refuse("the milestone escrow is not funded"));
        }
        if escrow.payee != Address::new(pad_address_32(&trainer_account)?) {
            return Err(refuse(
                "the milestone escrow does not pay the trainer's bonded account",
            ));
        }
        if escrow.release_conditions
            != (ReleaseConditions::Executor {
                executor: training_executor(),
            })
        {
            return Err(refuse(
                "the milestone escrow must name the training executor as its releaser",
            ));
        }
        let decide = network_param(state, DECIDE_WINDOW_MS_PARAM) as i64;
        let settle_by = now.saturating_add(window_ms as i64).saturating_add(decide);
        if escrow.expires_at.0 <= settle_by {
            return Err(refuse(
                "the milestone escrow expires before the round's challenges can be settled",
            ));
        }
        funding::write_json(
            state,
            &escrow_round_key(&receipt.escrow_id),
            &receipt_id,
            changes,
        )?;
        Ok(TrainingRecord {
            receipt: signed.receipt,
            committed_at_ms: now,
            window_ms,
            tee,
            trainer_account: hex::encode(trainer_account),
            challenges: Vec::new(),
            settled: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn attest(
        &self,
        state: &mut dyn VmState,
        tx: &VmTransaction,
        receipt_id: &str,
        index: u32,
        upheld: bool,
        now: i64,
        changes: &mut Vec<StateChange>,
        logs: &mut Vec<Log>,
    ) -> Result<TrainingRecord> {
        let stake = bonded_stake_of(state, &tx.from);
        if stake == 0 {
            return Err(refuse(
                "only accounts with bonded stake may attest training challenges",
            ));
        }
        let mut record = read_training_record(state, receipt_id)
            .ok_or_else(|| refuse(format!("no training receipt '{receipt_id}'")))?;
        let decide = network_param(state, DECIDE_WINDOW_MS_PARAM) as i64;
        let mut challenge = record
            .challenges
            .get(index as usize)
            .cloned()
            .ok_or_else(|| refuse(format!("this round has no challenge {index}")))?;
        if challenge.outcome.is_some() {
            return Err(refuse("this challenge is already decided"));
        }
        if now > challenge.filed_at_ms.saturating_add(decide) {
            return Err(refuse("this challenge's decision window has closed"));
        }
        let me = hex::encode(&tx.from);
        if challenge.attestations.iter().any(|a| a.validator == me) {
            return Err(refuse("this validator already attested the challenge"));
        }
        challenge
            .attestations
            .push(inference_fault::FaultAttestation {
                validator: me,
                upheld,
                stake,
            });
        let (up, down) = challenge
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
        let quorum =
            total > 0 && up.saturating_add(down).saturating_mul(3) >= total.saturating_mul(2);
        if !quorum {
            record.challenges[index as usize] = challenge;
            return Ok(record);
        }
        if up > down {
            close_challenge(
                state,
                &record,
                &mut challenge,
                ChallengeOutcome::Upheld,
                changes,
            )?;
            record.challenges[index as usize] = challenge.clone();
            let challenger = hex::decode(&challenge.challenger)
                .map_err(|e| VmError::Internal(format!("challenger account: {e}")))?;
            let reward = gwei_param(state, CHALLENGER_REWARD_GWEI_PARAM);
            let penalty = gwei_param(state, PENALTY_GWEI_PARAM);
            let (_, _, bond_log) = inference_fault::slash_compute_bond(
                state,
                &record.receipt.trainer_did,
                Some((challenger, reward)),
                penalty,
                changes,
            )?;
            logs.extend(bond_log);
            let escrow_id = record.receipt.digests().map_err(refuse)?.escrow_id;
            void_escrow(state, &escrow_id, now, changes)?;
            record.settled = Some(RoundSettlement::Voided);
            // The round is decided; the other challenges get their bonds back.
            expire_challenges(state, &mut record, now, true, changes)?;
        } else {
            close_challenge(
                state,
                &record,
                &mut challenge,
                ChallengeOutcome::Dismissed,
                changes,
            )?;
            record.challenges[index as usize] = challenge;
        }
        Ok(record)
    }
}

#[cfg(test)]
#[path = "training_proof_tests.rs"]
mod tests;
