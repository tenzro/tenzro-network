//! Verifiable training work: the receipt a trainer signs for each round, the
//! operations that commit, challenge and settle it, and the engine-neutral
//! spot re-execution a verifier runs before attesting a challenge.
//!
//! A round's receipt commits the checkpoint it started from, the shard it
//! trained on, the hyperparameters, the step count, the checkpoint it ended at
//! and the step log: a Merkle root over one leaf per step, each leaf binding
//! the step index, the digest of the batch that step consumed and the digest
//! of the state after it. The state before step `k` is the state after step
//! `k - 1`, or the starting checkpoint for step 0, so a step can only be
//! replayed from what the log itself committed. The shard commitment is a
//! Merkle root over one leaf per step's batch.
//!
//! A challenge samples steps from a seed the chain fixes; the first and the
//! last step are always among them, so a receipt whose checkpoints are not
//! the ends of its own log is always caught. For every sampled step the
//! trainer opens both log leaves, the batch and the two states; the verifier
//! checks every opening against the receipt, replays the step on its own
//! backend and compares the result with the claimed state within the
//! governed tolerance. Anything the trainer cannot open counts as a fault.
//!
//! A trainer that fabricates a share `f` of its steps escapes `s` sampled
//! steps with probability at most `(1 - f)^s`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::merkle::{Node, PathStep, merkle_root, root_from_path};

/// Domain of [`TrainingReceipt::digest`].
pub const TRAINING_RECEIPT_DOMAIN: &[u8] = b"tenzro/training/receipt/v1";
/// Domain of [`step_leaf`].
pub const TRAINING_STEP_DOMAIN: &[u8] = b"tenzro/training/step/v1";
/// Domain of [`batch_leaf`].
pub const TRAINING_BATCH_DOMAIN: &[u8] = b"tenzro/training/batch/v1";
/// Domain of [`sample_steps`].
pub const TRAINING_SAMPLE_DOMAIN: &[u8] = b"tenzro/training/sample/v1";

/// Longest kernel class name a receipt carries.
pub const MAX_KERNEL_CLASS_LEN: usize = 64;

/// What a trainer signs for one round, bound to the escrow that pays for it.
/// Every digest is 32 bytes of hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainingReceipt {
    /// The escrow paying for this round: the milestone it settles.
    pub escrow_id: String,
    /// The trainer machine's DID; its compute bond answers for the round.
    pub trainer_did: String,
    /// Round number within the job.
    pub round: u64,
    /// Digest of the state the round started from.
    pub start_checkpoint: String,
    /// Merkle root over the batches, one per step ([`batch_leaf`]).
    pub shard_commitment: String,
    /// Digest of the hyperparameters, as the backend encodes them.
    pub hyperparameters: String,
    /// Steps taken.
    pub steps: u64,
    /// Digest of the state the round ended at.
    pub end_checkpoint: String,
    /// Merkle root over the step log ([`step_leaf`]).
    pub step_root: String,
    /// Kernel class the steps ran on; a verifier replays on the same class.
    pub kernel_class: String,
    /// When the trainer signed the receipt, ms since the Unix epoch.
    pub signed_at_ms: u64,
}

fn put_field(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u32).to_le_bytes());
    h.update(field);
}

impl TrainingReceipt {
    /// What the trainer's identity signs and a TEE attestation binds:
    /// SHA-256 over every field, length-prefixed.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(TRAINING_RECEIPT_DOMAIN);
        for field in [
            self.escrow_id.to_ascii_lowercase().as_bytes(),
            self.trainer_did.as_bytes(),
            &self.round.to_le_bytes(),
            self.start_checkpoint.to_ascii_lowercase().as_bytes(),
            self.shard_commitment.to_ascii_lowercase().as_bytes(),
            self.hyperparameters.to_ascii_lowercase().as_bytes(),
            &self.steps.to_le_bytes(),
            self.end_checkpoint.to_ascii_lowercase().as_bytes(),
            self.step_root.to_ascii_lowercase().as_bytes(),
            self.kernel_class.as_bytes(),
            &self.signed_at_ms.to_le_bytes(),
        ] {
            put_field(&mut h, field);
        }
        h.finalize().into()
    }

    /// The receipt's id on chain: hex of [`TrainingReceipt::digest`].
    pub fn receipt_id(&self) -> String {
        hex::encode(self.digest())
    }

    /// Every digest field decoded, or which one is not 32 bytes of hex.
    pub fn digests(&self) -> Result<ReceiptDigests, String> {
        let get =
            |name: &str, v: &str| hex32(v).ok_or_else(|| format!("{name} is not 32 bytes of hex"));
        Ok(ReceiptDigests {
            escrow_id: get("escrow_id", &self.escrow_id)?,
            start_checkpoint: get("start_checkpoint", &self.start_checkpoint)?,
            shard_commitment: get("shard_commitment", &self.shard_commitment)?,
            hyperparameters: get("hyperparameters", &self.hyperparameters)?,
            end_checkpoint: get("end_checkpoint", &self.end_checkpoint)?,
            step_root: get("step_root", &self.step_root)?,
        })
    }
}

/// A receipt's digests, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptDigests {
    pub escrow_id: [u8; 32],
    pub start_checkpoint: [u8; 32],
    pub shard_commitment: [u8; 32],
    pub hyperparameters: [u8; 32],
    pub end_checkpoint: [u8; 32],
    pub step_root: [u8; 32],
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
}

/// A round's receipt signed in a hardware batch (`tenzro_crypto::batch`): the
/// trainer identity's hardware signed the Merkle root of a batch that holds
/// the receipt digest. Optionally a confidential compute attestation whose
/// report data binds [`TrainingReceipt::digest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTrainingReceipt {
    pub receipt: TrainingReceipt,
    /// Hex of the JSON of the batched signature over the receipt digest.
    pub batched: String,
    /// Attestation of the enclave the round ran in, if it ran in one.
    #[serde(default)]
    pub tee: Option<crate::tee::AttestationReport>,
}

/// Operations of the training proof module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingProofOp {
    /// Commit a signed receipt against its escrow; opens the challenge
    /// window.
    Commit { receipt: SignedTrainingReceipt },
    /// Challenge a committed round, posting the governed challenge bond.
    Challenge { receipt_id: String },
    /// A bonded validator's verdict on a challenge after it replayed the
    /// sampled steps: `upheld` when a step did not reproduce or could not be
    /// opened.
    Attest {
        receipt_id: String,
        challenge: u32,
        upheld: bool,
    },
    /// Close what time has decided: expire challenges past their decision
    /// window and, once the challenge window has closed with no upheld
    /// challenge and none pending, release the milestone to the trainer.
    Settle { receipt_id: String },
}

/// The system storage slot of a committed round's record.
pub fn training_receipt_slot(receipt_id: &str) -> String {
    format!("training_receipt:{}", receipt_id.to_ascii_lowercase())
}

/// Leaf of the step log for step `step`: the batch it consumed and the state
/// after it.
pub fn step_leaf(step: u64, batch_digest: &[u8; 32], state_after: &[u8; 32]) -> Node {
    Sha256::new()
        .chain_update(TRAINING_STEP_DOMAIN)
        .chain_update(step.to_le_bytes())
        .chain_update(batch_digest)
        .chain_update(state_after)
        .finalize()
        .into()
}

/// Leaf of the shard commitment for the batch step `step` consumes.
pub fn batch_leaf(step: u64, batch_digest: &[u8; 32]) -> Node {
    Sha256::new()
        .chain_update(TRAINING_BATCH_DOMAIN)
        .chain_update(step.to_le_bytes())
        .chain_update(batch_digest)
        .finalize()
        .into()
}

/// Shard commitment over the batches of a round, in step order.
pub fn shard_commitment(batch_digests: &[[u8; 32]]) -> Node {
    let leaves: Vec<Node> = batch_digests
        .iter()
        .enumerate()
        .map(|(k, b)| batch_leaf(k as u64, b))
        .collect();
    merkle_root(&leaves)
}

/// Step log root over `(batch digest, state after)` per step, in step order.
pub fn step_root(steps: &[([u8; 32], [u8; 32])]) -> Node {
    let leaves: Vec<Node> = steps
        .iter()
        .enumerate()
        .map(|(k, (b, s))| step_leaf(k as u64, b, s))
        .collect();
    merkle_root(&leaves)
}

/// The steps a challenge samples: the first and the last step, and up to
/// `count - 2` more drawn from `seed`, distinct and in order. Every step when
/// `count` covers the round.
pub fn sample_steps(seed: &[u8; 32], steps: u64, count: u64) -> Vec<u64> {
    if steps == 0 {
        return Vec::new();
    }
    if count >= steps {
        return (0..steps).collect();
    }
    let mut picked = std::collections::BTreeSet::from([0, steps - 1]);
    let want = count.max(2).min(steps) as usize;
    let mut i: u64 = 0;
    while picked.len() < want {
        let d: [u8; 32] = Sha256::new()
            .chain_update(TRAINING_SAMPLE_DOMAIN)
            .chain_update(seed)
            .chain_update(i.to_le_bytes())
            .finalize()
            .into();
        let mut w = [0u8; 8];
        w.copy_from_slice(&d[..8]);
        picked.insert(u64::from_le_bytes(w) % steps);
        i += 1;
    }
    picked.into_iter().collect()
}

/// Seed a challenge samples from: the receipt, the challenge's index and the
/// randomness beacon's mix when the challenge was filed, so neither the
/// challenger nor the trainer picks the steps.
pub fn challenge_seed(receipt_id: &str, challenge: u32, beacon_mix: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(TRAINING_SAMPLE_DOMAIN)
        .chain_update(receipt_id.to_ascii_lowercase().as_bytes())
        .chain_update(challenge.to_le_bytes())
        .chain_update(beacon_mix)
        .finalize()
        .into()
}

/// One step's log leaf as the trainer opens it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafOpening {
    pub batch_digest: [u8; 32],
    pub state_after: [u8; 32],
    /// Inclusion path into the step root.
    pub path: Vec<PathStep>,
}

/// Everything a trainer opens for one sampled step `step`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepOpening {
    pub step: u64,
    /// The leaf of step `step - 1`; `None` for step 0, whose state before is
    /// the starting checkpoint.
    pub previous: Option<LeafOpening>,
    /// The leaf of step `step`.
    pub leaf: LeafOpening,
    /// The batch the step consumed, and its path into the shard commitment.
    pub batch: Vec<u8>,
    pub batch_path: Vec<PathStep>,
    /// The state before and after the step, as the backend encodes them.
    pub state_before: Vec<u8>,
    pub state_after: Vec<u8>,
}

/// A training engine, as the verifier drives it. Each engine adapter
/// implements this once; nothing else in verification knows the engine.
pub trait TrainingBackend {
    /// The kernel class this backend replays on.
    fn kernel_class(&self) -> &str;
    /// Digest of an encoded state, as a receipt commits it.
    fn state_digest(&self, state: &[u8]) -> [u8; 32] {
        Sha256::digest(state).into()
    }
    /// Digest of an encoded batch, as a shard commitment commits it.
    fn batch_digest(&self, batch: &[u8]) -> [u8; 32] {
        Sha256::digest(batch).into()
    }
    /// Run step `step` from `state` over `batch` with `hyperparameters`,
    /// returning the encoded state after it.
    fn step(
        &self,
        state: &[u8],
        batch: &[u8],
        hyperparameters: &[u8],
        step: u64,
    ) -> Result<Vec<u8>, String>;
    /// Distance between two encoded states in parts per million, or `None`
    /// when they cannot be compared (different shapes, not decodable).
    fn distance_ppm(&self, a: &[u8], b: &[u8]) -> Option<u64>;
}

/// Why a sampled step convicts a round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepFault {
    /// The trainer did not open the step.
    Unopened,
    /// A leaf or its predecessor is not in the step log.
    NotInLog,
    /// The batch is not the one the shard commitment holds for this step.
    WrongBatch,
    /// A state does not have the digest the log commits.
    WrongState,
    /// The step's ends are not the receipt's checkpoints.
    WrongCheckpoint,
    /// Replaying the step on the verifier's backend failed.
    ReplayFailed(String),
    /// The replay ended this far (ppm) from the claimed state, beyond the
    /// tolerance; `None` when the states could not be compared at all.
    Mismatch(Option<u64>),
}

/// What a verifier concludes about a challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrainingVerdict {
    /// Every sampled step reproduced within the tolerance.
    Reproduced,
    /// The receipt itself is malformed or names another kernel class.
    BadReceipt(String),
    /// The first sampled step that did not reproduce, and why.
    Fault { step: u64, fault: StepFault },
}

impl TrainingVerdict {
    /// Whether a validator attests the challenge upheld.
    pub fn upheld(&self) -> bool {
        !matches!(self, Self::Reproduced)
    }
}

/// Check one challenge: replay every step sampled from `seed` (`count` of
/// them) on `backend`, with `open` returning the trainer's opening of a step
/// and `hyperparameters` the encoding the receipt's digest commits.
pub fn check_challenge(
    backend: &dyn TrainingBackend,
    receipt: &TrainingReceipt,
    hyperparameters: &[u8],
    seed: &[u8; 32],
    count: u64,
    tolerance_ppm: u64,
    open: &dyn Fn(u64) -> Option<StepOpening>,
) -> TrainingVerdict {
    let d = match receipt.digests() {
        Ok(d) => d,
        Err(e) => return TrainingVerdict::BadReceipt(e),
    };
    if receipt.kernel_class != backend.kernel_class() {
        return TrainingVerdict::BadReceipt(format!(
            "the round ran on kernel class {}, this verifier replays {}",
            receipt.kernel_class,
            backend.kernel_class()
        ));
    }
    if <[u8; 32]>::from(Sha256::digest(hyperparameters)) != d.hyperparameters {
        return TrainingVerdict::BadReceipt(
            "the hyperparameters do not match the receipt".to_string(),
        );
    }
    if receipt.steps == 0 {
        return TrainingVerdict::BadReceipt("a round takes at least one step".to_string());
    }
    for step in sample_steps(seed, receipt.steps, count) {
        let fault = match open(step) {
            None => Some(StepFault::Unopened),
            Some(o) if o.step != step => Some(StepFault::Unopened),
            Some(o) => check_step(backend, receipt, &d, hyperparameters, tolerance_ppm, &o).err(),
        };
        if let Some(fault) = fault {
            return TrainingVerdict::Fault { step, fault };
        }
    }
    TrainingVerdict::Reproduced
}

fn check_step(
    backend: &dyn TrainingBackend,
    receipt: &TrainingReceipt,
    d: &ReceiptDigests,
    hyperparameters: &[u8],
    tolerance_ppm: u64,
    o: &StepOpening,
) -> Result<(), StepFault> {
    let in_log = |k: u64, l: &LeafOpening| {
        root_from_path(&step_leaf(k, &l.batch_digest, &l.state_after), &l.path) == d.step_root
    };
    if !in_log(o.step, &o.leaf) {
        return Err(StepFault::NotInLog);
    }
    let before = match (o.step, &o.previous) {
        (0, _) => d.start_checkpoint,
        (k, Some(prev)) if in_log(k - 1, prev) => prev.state_after,
        _ => return Err(StepFault::NotInLog),
    };
    if o.step + 1 == receipt.steps && o.leaf.state_after != d.end_checkpoint {
        return Err(StepFault::WrongCheckpoint);
    }
    let batch_digest = backend.batch_digest(&o.batch);
    if batch_digest != o.leaf.batch_digest
        || root_from_path(&batch_leaf(o.step, &batch_digest), &o.batch_path) != d.shard_commitment
    {
        return Err(StepFault::WrongBatch);
    }
    if backend.state_digest(&o.state_before) != before
        || backend.state_digest(&o.state_after) != o.leaf.state_after
    {
        return Err(StepFault::WrongState);
    }
    let replayed = backend
        .step(&o.state_before, &o.batch, hyperparameters, o.step)
        .map_err(StepFault::ReplayFailed)?;
    match backend.distance_ppm(&replayed, &o.state_after) {
        Some(ppm) if ppm <= tolerance_ppm => Ok(()),
        other => Err(StepFault::Mismatch(other)),
    }
}

/// Least chance (ppm) that `samples` sampled steps catch a round in which a
/// share `fake_ppm` of the steps was fabricated: `1 - (1 - f)^s`, rounded
/// down.
pub fn catch_chance_ppm(fake_ppm: u64, samples: u64) -> u64 {
    let f = (fake_ppm.min(1_000_000) as f64) / 1_000_000.0;
    let miss = (1.0 - f).powi(samples.min(i32::MAX as u64) as i32);
    ((1.0 - miss) * 1_000_000.0).floor() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_always_include_both_ends_and_stay_in_range() {
        for steps in 1..40u64 {
            for count in 0..6u64 {
                let s = sample_steps(&[7; 32], steps, count);
                assert_eq!(s[0], 0);
                assert_eq!(*s.last().unwrap(), steps - 1);
                assert!(s.windows(2).all(|w| w[0] < w[1]));
                assert!(s.len() as u64 <= count.max(2).min(steps));
                assert!(s.len() as u64 >= count.max(2).min(steps).min(2));
            }
        }
        assert_eq!(sample_steps(&[1; 32], 5, 9), vec![0, 1, 2, 3, 4]);
        assert!(sample_steps(&[1; 32], 0, 9).is_empty());
        assert_ne!(
            sample_steps(&[1; 32], 1_000, 8),
            sample_steps(&[2; 32], 1_000, 8)
        );
    }

    #[test]
    fn the_receipt_digest_binds_every_field() {
        let r = TrainingReceipt {
            escrow_id: "00".repeat(32),
            trainer_did: "did:tenzro:machine:t".into(),
            round: 1,
            start_checkpoint: "11".repeat(32),
            shard_commitment: "22".repeat(32),
            hyperparameters: "33".repeat(32),
            steps: 10,
            end_checkpoint: "44".repeat(32),
            step_root: "55".repeat(32),
            kernel_class: "k".into(),
            signed_at_ms: 9,
        };
        let base = r.digest();
        let variants = [
            TrainingReceipt {
                round: 2,
                ..r.clone()
            },
            TrainingReceipt {
                steps: 11,
                ..r.clone()
            },
            TrainingReceipt {
                shard_commitment: "23".repeat(32),
                ..r.clone()
            },
            TrainingReceipt {
                end_checkpoint: "45".repeat(32),
                ..r.clone()
            },
            TrainingReceipt {
                signed_at_ms: 10,
                ..r.clone()
            },
        ];
        for v in variants {
            assert_ne!(v.digest(), base);
        }
        // Hex case does not change the receipt.
        let upper = TrainingReceipt {
            step_root: "AA".repeat(32),
            ..r.clone()
        };
        let lower = TrainingReceipt {
            step_root: "aa".repeat(32),
            ..r
        };
        assert_eq!(upper.digest(), lower.digest());
    }

    #[test]
    fn the_catch_chance_grows_with_samples_and_fakes() {
        assert_eq!(catch_chance_ppm(0, 100), 0);
        assert_eq!(catch_chance_ppm(1_000_000, 1), 1_000_000);
        assert!(catch_chance_ppm(100_000, 16) > catch_chance_ppm(100_000, 8));
        assert!(catch_chance_ppm(200_000, 8) > catch_chance_ppm(100_000, 8));
        // A tenth of the steps faked, 32 samples: caught over 96% of the time.
        assert!(catch_chance_ppm(100_000, 32) > 960_000);
    }
}
