//! On-chain commitments for Tenzro Train rounds and runs.
//!
//! - `state_root` is committed each round and binds {accepted outer gradients,
//!   post-step parameter hashes} for every fragment.
//! - `run_root` is the final Merkle commitment over all per-round state roots
//!   and is bound into the [`TrainingReceipt`](tenzro_types::training::TrainingReceipt).

use sha2::{Digest, Sha256};
use tenzro_types::primitives::Hash;
use tenzro_types::training::{FragmentQuorumStatus, OuterGradient, SyncRound};

/// Compute the per-round state root.
///
/// Layout (deterministic, BE-encoded):
///   sha256(
///     "tenzro/train/state-root"
///     || task_id_bytes
///     || round_be_u32
///     || for each fragment in sorted-by-id order:
///         fragment_be_u32
///         || accepted_be_u32
///         || quorum_met_u8
///         || for each accepted_hash in order: hash_bytes
///         || post_step_hash_bytes
///   )
pub fn compute_state_root(task_id: &str, round: u32, fragments: &[FragmentQuorumStatus]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro/train/state-root");
    hasher.update(task_id.as_bytes());
    hasher.update(round.to_be_bytes());
    let mut sorted: Vec<&FragmentQuorumStatus> = fragments.iter().collect();
    sorted.sort_by_key(|f| f.fragment);
    for f in sorted {
        hasher.update(f.fragment.to_be_bytes());
        hasher.update(f.accepted.to_be_bytes());
        hasher.update([if f.quorum_met { 1u8 } else { 0u8 }]);
        for h in &f.accepted_hashes {
            hasher.update(h.as_bytes());
        }
        hasher.update(f.post_step_hash.as_bytes());
    }
    let digest = hasher.finalize();
    Hash::from_bytes(&digest).expect("sha256 digest is 32 bytes")
}

/// Compute the run root from a sequence of per-round state roots.
///
/// Uses a SHA-256 Merkle tree (duplicate-last for unbalanced layers, like
/// Bitcoin). For length 1, returns the leaf directly. For length 0,
/// returns `Hash::zero()`.
pub fn compute_run_root(round_state_roots: &[Hash]) -> Hash {
    if round_state_roots.is_empty() {
        return Hash::zero();
    }
    let mut layer: Vec<[u8; 32]> = round_state_roots
        .iter()
        .map(|h| {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(h.as_bytes());
            buf
        })
        .collect();
    while layer.len() > 1 {
        if !layer.len().is_multiple_of(2) {
            let last = *layer.last().unwrap();
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(b"tenzro/train/run-root");
            hasher.update(chunk[0]);
            hasher.update(chunk[1]);
            let digest = hasher.finalize();
            let mut node = [0u8; 32];
            node.copy_from_slice(&digest);
            next.push(node);
        }
        layer = next;
    }
    Hash::from_bytes(&layer[0]).expect("32 bytes")
}

/// Canonical preimage the syncer signs to attest a [`SyncRound`].
pub fn sync_round_signing_bytes(round: &SyncRound) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64 + round.task_id.len());
    buf.extend_from_slice(b"tenzro/train/sync-round");
    buf.extend_from_slice(round.task_id.as_bytes());
    buf.extend_from_slice(&round.round.to_be_bytes());
    buf.extend_from_slice(round.state_root.as_bytes());
    buf.extend_from_slice(&round.published_at.as_millis().to_be_bytes());
    buf
}

/// Canonical preimage the trainer signs over an [`OuterGradient`].
///
/// Byte-identical to the Python reference trainer's `gradient_signing_bytes`
/// (`integrations/trainer/tenzro_trainer/gradient.py`): domain tag, then the
/// gradient fields in struct order (minus the signature), big-endian encoded.
/// The quantization is bound as its canonical display label
/// (`none` / `int8/N` / `int4/N`). `submitted_at` is the two's-complement i64
/// milliseconds, matching Python's `to_bytes(8, "big", signed=True)`.
/// The activation commitment is bound as a presence byte (`0x01`/`0x00`)
/// followed, when present, by its 32-byte
/// [`commitment_hash`](tenzro_types::training::ActivationCommitment::commitment_hash) —
/// so a trainer cannot swap the commitment after signing.
pub fn outer_gradient_signing_bytes(grad: &OuterGradient) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128 + grad.task_id.len() + grad.trainer_did.len());
    buf.extend_from_slice(b"tenzro/train/outer-gradient");
    buf.extend_from_slice(grad.task_id.as_bytes());
    buf.extend_from_slice(&grad.round.to_be_bytes());
    buf.extend_from_slice(&grad.fragment.to_be_bytes());
    buf.extend_from_slice(grad.trainer_did.as_bytes());
    buf.extend_from_slice(grad.safetensors_hash.as_bytes());
    buf.extend_from_slice(&grad.payload_bytes.to_be_bytes());
    buf.extend_from_slice(grad.quantization.to_string().as_bytes());
    buf.extend_from_slice(&grad.inner_step_count.to_be_bytes());
    buf.extend_from_slice(&grad.submitted_at.as_millis().to_be_bytes());
    match &grad.commitment {
        Some(commitment) => {
            buf.push(1u8);
            buf.extend_from_slice(&commitment.commitment_hash());
        }
        None => buf.push(0u8),
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        Hash::from_bytes(&[byte; 32]).unwrap()
    }

    #[test]
    fn run_root_empty_is_zero() {
        assert_eq!(compute_run_root(&[]), Hash::zero());
    }

    #[test]
    fn run_root_single_round_is_leaf() {
        let leaf = h(7);
        assert_eq!(compute_run_root(&[leaf]), leaf);
    }

    #[test]
    fn run_root_is_deterministic() {
        let roots = vec![h(1), h(2), h(3), h(4)];
        let a = compute_run_root(&roots);
        let b = compute_run_root(&roots);
        assert_eq!(a, b);
    }

    #[test]
    fn state_root_changes_when_fragment_count_changes() {
        let f1 = FragmentQuorumStatus {
            fragment: 0,
            accepted: 3,
            accepted_hashes: vec![h(1), h(2), h(3)],
            quorum_met: true,
            post_step_hash: h(9),
        };
        let f2 = FragmentQuorumStatus {
            fragment: 1,
            accepted: 3,
            accepted_hashes: vec![h(4), h(5), h(6)],
            quorum_met: true,
            post_step_hash: h(10),
        };
        let one = compute_state_root("task-A", 0, std::slice::from_ref(&f1));
        let two = compute_state_root("task-A", 0, &[f1, f2]);
        assert_ne!(one, two);
    }

    #[test]
    fn state_root_independent_of_fragment_input_order() {
        let f1 = FragmentQuorumStatus {
            fragment: 0,
            accepted: 2,
            accepted_hashes: vec![h(1), h(2)],
            quorum_met: true,
            post_step_hash: h(9),
        };
        let f2 = FragmentQuorumStatus {
            fragment: 1,
            accepted: 2,
            accepted_hashes: vec![h(3), h(4)],
            quorum_met: true,
            post_step_hash: h(10),
        };
        let r1 = compute_state_root("task-A", 0, &[f1.clone(), f2.clone()]);
        let r2 = compute_state_root("task-A", 0, &[f2, f1]);
        assert_eq!(r1, r2);
    }
}
