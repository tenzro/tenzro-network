//! Where a trained model came from: the receipt a trainer signs for the
//! weights a training job produced, and the pack that lets anyone check it
//! offline.
//!
//! A job trains in rounds; each round's receipt
//! ([`crate::training_verification::TrainingReceipt`]) is committed on chain
//! against the milestone escrow that pays for it, may be challenged, and is
//! released only once its challenge window closes with no upheld fault. The
//! trained-model receipt names the rounds, in order, and binds them to the
//! base weights the job started from and the weights it produced (the
//! SHA-256 of the exported file), signed by the trainer machine's
//! registered hardware identity.
//!
//! The provenance pack carries that receipt and, under a certified state
//! root, every round's record and the trainer's identity registration. The
//! verifier needs only the chain's genesis anchor: it checks the signature
//! against the registered key, that the rounds chain from one end state to
//! the next and end where the receipt says, that each round's milestone was
//! released (no upheld challenge), and reports each round's dataset
//! commitment and whether it ran in an attested environment.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::evidence_pack::ProvenRecord;

/// Domain of [`TrainedModelReceipt::digest`].
pub const TRAINED_MODEL_DOMAIN: &[u8] = b"tenzro/training/model/v1";

/// Kind of a round's record in a provenance pack.
pub const ROUND_KIND: &str = "training_round";
/// Kind of the trainer's identity record in a provenance pack.
pub const TRAINER_KIND: &str = "trainer_identity";

/// What a trainer signs for the weights a job produced. Digests are 32 bytes
/// of hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrainedModelReceipt {
    /// The catalog model the job trained from.
    pub model_id: String,
    /// SHA-256 of the base weights file.
    pub base_sha256: String,
    /// SHA-256 of the weights file the job produced.
    pub output_sha256: String,
    /// The trainer machine's DID.
    pub trainer_did: String,
    /// Receipt ids of the job's committed rounds, first to last.
    pub rounds: Vec<String>,
    /// The state the last round ended at; the produced weights are its
    /// export.
    pub end_checkpoint: String,
    /// When the trainer signed, ms since the Unix epoch.
    pub signed_at_ms: u64,
}

fn put(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u32).to_le_bytes());
    h.update(field);
}

impl TrainedModelReceipt {
    /// What the trainer signs: SHA-256 over every field, length-prefixed.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(TRAINED_MODEL_DOMAIN);
        put(&mut h, self.model_id.as_bytes());
        put(&mut h, self.base_sha256.to_ascii_lowercase().as_bytes());
        put(&mut h, self.output_sha256.to_ascii_lowercase().as_bytes());
        put(&mut h, self.trainer_did.as_bytes());
        h.update((self.rounds.len() as u32).to_le_bytes());
        for r in &self.rounds {
            put(&mut h, r.to_ascii_lowercase().as_bytes());
        }
        put(&mut h, self.end_checkpoint.to_ascii_lowercase().as_bytes());
        h.update(self.signed_at_ms.to_le_bytes());
        h.finalize().into()
    }

    /// Structural checks: the digests are 32 bytes of hex and there is at
    /// least one round.
    pub fn validate(&self) -> Result<(), String> {
        for (name, v) in [
            ("base_sha256", &self.base_sha256),
            ("output_sha256", &self.output_sha256),
            ("end_checkpoint", &self.end_checkpoint),
        ] {
            if hex::decode(v.trim_start_matches("0x")).map(|b| b.len()) != Ok(32) {
                return Err(format!("{name} is not 32 bytes of hex"));
            }
        }
        if self.rounds.is_empty() {
            return Err("a trained model names at least one round".into());
        }
        Ok(())
    }
}

/// A receipt with the trainer's session signature over its digest, encoded
/// as JSON: a session key its registered hardware identity certified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTrainedModelReceipt {
    pub receipt: TrainedModelReceipt,
    #[serde(with = "crate::agent_audit::hex_bytes")]
    pub signature: Vec<u8>,
}

/// Everything needed to check a trained model's origin offline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingProvenancePack {
    pub receipt: SignedTrainedModelReceipt,
    /// Height of the certified state the records are proven under.
    pub state_height: u64,
    /// That state root, hex.
    pub state_root: String,
    /// The node hash of the state trie at `state_height`.
    #[serde(default)]
    pub state_trie_hash: crate::hash_scheme::HashScheme,
    /// Proof from genesis that the checkpoint committing `state_root` is
    /// certified.
    pub checkpoint: serde_json::Value,
    /// Each round's record ([`ROUND_KIND`], subject the receipt id) and the
    /// trainer's identity ([`TRAINER_KIND`], subject the DID).
    pub records: Vec<ProvenRecord>,
}
