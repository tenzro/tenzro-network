//! MoE expert-execution receipts — activation commitments + holder signatures.
//!
//! Every remote expert execution returns, alongside the output rows, a
//! signed [`ExpertExecutionReceipt`] binding:
//!
//! - the **input carrier hash** — SHA-256 over the exact wire bytes of the
//!   hidden states the holder received (the Q8_0 blocks when the batch was
//!   compressed, the raw f32 LE bytes otherwise), so router and holder hash
//!   identical bytes despite wire quantization;
//! - the **activation commitment** — a compact per-token top-k feature
//!   sketch of the expert's output rows ([`ExpertActivationCommitment`]),
//!   hashed with a domain-tagged canonical encoding;
//! - the holder's provider address + Ed25519 signature over the canonical
//!   receipt payload.
//!
//! The router verifies the receipt inline (recompute the commitment from the
//! returned outputs, check the signature, check the provider binding) before
//! accepting the batch into the combine — an invalid receipt is treated as a
//! holder failure and the batch fails over to the next holder.
//!
//! Receipts sampled for retention keep the full feature rows so a disputer
//! can later re-execute the batch on an independent holder and fuzzy-compare
//! per-row features, the same re-execution discipline as the token-level
//! commitment pipeline in [`crate::toploc`]. Tolerances are looser than the
//! logit path because the wire carrier is Q8_0-quantized (~0.4% relative
//! error) and expert kernels differ across backends.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::keys::PublicKey;
use tenzro_crypto::signatures::{verify, Signature, Signer};
use tenzro_types::Address;

use crate::error::{ModelError, Result};
use crate::toploc::top_k_from_logits;

/// Domain tag for the activation-commitment canonical encoding.
pub const ACTIVATION_COMMITMENT_DOMAIN: &[u8] = b"tenzro/moe/activation";

/// Domain tag for the receipt signing payload.
pub const MOE_RECEIPT_DOMAIN: &[u8] = b"tenzro/moe/receipt";

/// Default number of features committed per output row.
pub const DEFAULT_ACTIVATION_K: u8 = 8;

/// Upper bound on per-row committed features.
pub const MAX_ACTIVATION_K: u8 = 32;

/// Minimum fraction of committed feature indices that must reappear in the
/// re-executed row's top-k for the row to pass.
pub const MIN_ROW_INDEX_OVERLAP: f32 = 0.75;

/// Maximum mean absolute feature delta, relative to the mean absolute
/// committed feature magnitude, for a row to pass. Covers Q8_0 wire error
/// plus cross-backend kernel variance.
pub const MAX_ACTIVATION_RELATIVE_DELTA: f32 = 0.05;

/// Minimum fraction of rows that must pass for the commitment to verify.
pub const MIN_ROW_PASS_FRACTION: f32 = 0.9;

/// One committed output feature: position in the row and its signed value.
/// Features are selected by descending absolute value (ties broken by
/// ascending index) so the sketch captures the row's dominant activations.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ActivationFeature {
    pub index: u32,
    pub value: f32,
}

/// Committed feature sketch for one output row (one token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationRow {
    /// Token index within the forward this row belongs to.
    pub token_index: u32,
    /// Top-k features by absolute value, descending (ties ascending index).
    pub features: Vec<ActivationFeature>,
}

/// Activation commitment for one expert-execute batch: one feature row per
/// token, in the batch's token order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertActivationCommitment {
    /// Number of features committed per row.
    pub k: u8,
    pub rows: Vec<ActivationRow>,
}

/// Select the top-k features of one output row by absolute value,
/// descending, ties broken by ascending index.
pub fn top_features(row: &[f32], k: usize) -> Vec<ActivationFeature> {
    let abs: Vec<f32> = row.iter().map(|v| v.abs()).collect();
    top_k_from_logits(&abs, k)
        .into_iter()
        .map(|e| ActivationFeature {
            index: e.token_id,
            value: row[e.token_id as usize],
        })
        .collect()
}

impl ExpertActivationCommitment {
    /// Build the commitment from a batch's flat output buffer
    /// (`token_indices.len() * d_model` values, row-major).
    pub fn from_outputs(
        token_indices: &[u32],
        outputs: &[f32],
        d_model: usize,
        k: u8,
    ) -> Result<Self> {
        let k = k.clamp(1, MAX_ACTIVATION_K);
        if d_model == 0 {
            return Err(ModelError::Other(
                "activation commitment: d_model must be non-zero".to_string(),
            ));
        }
        if outputs.len() != token_indices.len() * d_model {
            return Err(ModelError::Other(format!(
                "activation commitment: output length {} != {} tokens x d_model {}",
                outputs.len(),
                token_indices.len(),
                d_model
            )));
        }
        let rows = token_indices
            .iter()
            .zip(outputs.chunks_exact(d_model))
            .map(|(&token_index, row)| ActivationRow {
                token_index,
                features: top_features(row, k as usize),
            })
            .collect();
        Ok(Self { k, rows })
    }

    /// Deterministic byte encoding hashed into the commitment.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ACTIVATION_COMMITMENT_DOMAIN.len() + 5 + self.rows.len() * (5 + self.k as usize * 8),
        );
        out.extend_from_slice(ACTIVATION_COMMITMENT_DOMAIN);
        out.push(self.k);
        out.extend_from_slice(&(self.rows.len() as u32).to_le_bytes());
        for row in &self.rows {
            out.extend_from_slice(&row.token_index.to_le_bytes());
            out.push(row.features.len() as u8);
            for feature in &row.features {
                out.extend_from_slice(&feature.index.to_le_bytes());
                out.extend_from_slice(&feature.value.to_le_bytes());
            }
        }
        out
    }

    /// SHA-256 of the canonical encoding.
    pub fn commitment_hash(&self) -> [u8; 32] {
        let digest = Sha256::digest(self.canonical_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        hash
    }
}

/// Per-row comparison between a committed sketch and a re-executed row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowComparison {
    /// Fraction of committed indices present in the re-executed top-k.
    pub index_overlap: f32,
    /// Mean absolute feature delta over shared indices, relative to the
    /// mean absolute committed magnitude.
    pub relative_delta: f32,
    pub pass: bool,
}

/// Outcome of verifying a full activation commitment against re-executed
/// output rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationVerification {
    pub rows_total: usize,
    pub rows_passed: usize,
    /// Indices of failing rows (capped at 32 for reporting).
    pub failing_rows: Vec<usize>,
    pub pass: bool,
}

/// Compare one committed row against its re-executed counterpart.
pub fn compare_row(committed: &ActivationRow, reexecuted_row: &[f32], k: u8) -> RowComparison {
    if committed.features.is_empty() {
        return RowComparison {
            index_overlap: 0.0,
            relative_delta: f32::INFINITY,
            pass: false,
        };
    }
    let recomputed = top_features(reexecuted_row, k as usize);
    let mut shared = 0usize;
    let mut delta_sum = 0f64;
    let mut magnitude_sum = 0f64;
    for feature in &committed.features {
        magnitude_sum += feature.value.abs() as f64;
        if recomputed.iter().any(|r| r.index == feature.index) {
            shared += 1;
            let re = reexecuted_row
                .get(feature.index as usize)
                .copied()
                .unwrap_or(0.0);
            delta_sum += (feature.value - re).abs() as f64;
        }
    }
    let index_overlap = shared as f32 / committed.features.len() as f32;
    let mean_magnitude = magnitude_sum / committed.features.len() as f64;
    let relative_delta = if shared == 0 {
        f32::INFINITY
    } else if mean_magnitude > 0.0 {
        ((delta_sum / shared as f64) / mean_magnitude) as f32
    } else {
        0.0
    };
    let pass =
        index_overlap >= MIN_ROW_INDEX_OVERLAP && relative_delta <= MAX_ACTIVATION_RELATIVE_DELTA;
    RowComparison {
        index_overlap,
        relative_delta,
        pass,
    }
}

/// Verify a commitment against re-executed outputs for the same batch
/// (`rows.len() * d_model` values, row-major, same token order).
pub fn verify_activation_commitment(
    commitment: &ExpertActivationCommitment,
    reexecuted_outputs: &[f32],
    d_model: usize,
) -> Result<ActivationVerification> {
    if d_model == 0 || reexecuted_outputs.len() != commitment.rows.len() * d_model {
        return Err(ModelError::Other(format!(
            "activation verify: output length {} != {} rows x d_model {}",
            reexecuted_outputs.len(),
            commitment.rows.len(),
            d_model
        )));
    }
    let mut rows_passed = 0usize;
    let mut failing_rows = Vec::new();
    for (i, (row, re)) in commitment
        .rows
        .iter()
        .zip(reexecuted_outputs.chunks_exact(d_model))
        .enumerate()
    {
        if compare_row(row, re, commitment.k).pass {
            rows_passed += 1;
        } else if failing_rows.len() < 32 {
            failing_rows.push(i);
        }
    }
    let rows_total = commitment.rows.len();
    let pass = rows_total > 0
        && (rows_passed as f32 / rows_total as f32) >= MIN_ROW_PASS_FRACTION;
    Ok(ActivationVerification {
        rows_total,
        rows_passed,
        failing_rows,
        pass,
    })
}

/// Signed receipt for one expert-execute batch. The signing key is the
/// holder's announce key — the same identity that signs its provider
/// gossip announcements — so the receipt binds the execution to the
/// on-network provider record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpertExecutionReceipt {
    /// Holder's provider address.
    pub provider: Address,
    /// SHA-256 over the wire carrier bytes of the input hidden states.
    pub input_hash: [u8; 32],
    /// [`ExpertActivationCommitment::commitment_hash`] of the outputs.
    pub commitment: [u8; 32],
    /// Holder's Ed25519 signature over
    /// [`expert_receipt_signing_payload`].
    pub signature: Signature,
    /// Holder's Ed25519 public key. Used to verify `signature`.
    pub public_key: PublicKey,
}

/// Canonical receipt signing payload:
/// `MOE_RECEIPT_DOMAIN || model_id_len_le || model_id || layer_le ||
///  expert_le || n_tokens_le || token_index_le* || input_hash || commitment`.
pub fn expert_receipt_signing_payload(
    model_id: &str,
    layer: u32,
    expert: u32,
    token_indices: &[u32],
    input_hash: &[u8; 32],
    commitment: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        MOE_RECEIPT_DOMAIN.len() + 4 + model_id.len() + 12 + token_indices.len() * 4 + 64,
    );
    out.extend_from_slice(MOE_RECEIPT_DOMAIN);
    out.extend_from_slice(&(model_id.len() as u32).to_le_bytes());
    out.extend_from_slice(model_id.as_bytes());
    out.extend_from_slice(&layer.to_le_bytes());
    out.extend_from_slice(&expert.to_le_bytes());
    out.extend_from_slice(&(token_indices.len() as u32).to_le_bytes());
    for &idx in token_indices {
        out.extend_from_slice(&idx.to_le_bytes());
    }
    out.extend_from_slice(input_hash);
    out.extend_from_slice(commitment);
    out
}

/// Build a signed receipt on the holder side.
#[allow(clippy::too_many_arguments)]
pub fn build_expert_receipt<S: Signer + ?Sized>(
    model_id: &str,
    layer: u32,
    expert: u32,
    token_indices: &[u32],
    input_hash: [u8; 32],
    commitment: [u8; 32],
    provider: Address,
    signer: &S,
    public_key: PublicKey,
) -> Result<ExpertExecutionReceipt> {
    let payload = expert_receipt_signing_payload(
        model_id,
        layer,
        expert,
        token_indices,
        &input_hash,
        &commitment,
    );
    let signature = signer
        .sign(&payload)
        .map_err(|e| ModelError::Other(format!("expert receipt sign failed: {e}")))?;
    Ok(ExpertExecutionReceipt {
        provider,
        input_hash,
        commitment,
        signature,
        public_key,
    })
}

/// Verify a receipt on the router side. `expected_commitment` is recomputed
/// by the router from the returned output rows; `expected_input_hash` is the
/// carrier hash of the request the router sent.
pub fn verify_expert_receipt(
    receipt: &ExpertExecutionReceipt,
    model_id: &str,
    layer: u32,
    expert: u32,
    token_indices: &[u32],
    expected_input_hash: &[u8; 32],
    expected_commitment: &[u8; 32],
) -> Result<()> {
    if &receipt.input_hash != expected_input_hash {
        return Err(ModelError::Other(
            "expert receipt: input hash mismatch".to_string(),
        ));
    }
    if &receipt.commitment != expected_commitment {
        return Err(ModelError::Other(
            "expert receipt: activation commitment mismatch".to_string(),
        ));
    }
    let payload = expert_receipt_signing_payload(
        model_id,
        layer,
        expert,
        token_indices,
        &receipt.input_hash,
        &receipt.commitment,
    );
    verify(&receipt.public_key, &payload, &receipt.signature)
        .map_err(|e| ModelError::Other(format!("expert receipt: bad signature: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::Ed25519SignerImpl;

    fn sample_outputs(n_tokens: usize, d_model: usize) -> (Vec<u32>, Vec<f32>) {
        let token_indices: Vec<u32> = (0..n_tokens as u32).collect();
        let outputs: Vec<f32> = (0..n_tokens * d_model)
            .map(|i| ((i * 31 % 97) as f32 - 48.0) / 10.0)
            .collect();
        (token_indices, outputs)
    }

    #[test]
    fn commitment_is_deterministic() {
        let (tokens, outputs) = sample_outputs(4, 64);
        let a = ExpertActivationCommitment::from_outputs(&tokens, &outputs, 64, 8).unwrap();
        let b = ExpertActivationCommitment::from_outputs(&tokens, &outputs, 64, 8).unwrap();
        assert_eq!(a.commitment_hash(), b.commitment_hash());
        assert_eq!(a.rows.len(), 4);
        assert_eq!(a.rows[0].features.len(), 8);
    }

    #[test]
    fn commitment_changes_with_outputs() {
        let (tokens, mut outputs) = sample_outputs(4, 64);
        let a = ExpertActivationCommitment::from_outputs(&tokens, &outputs, 64, 8).unwrap();
        outputs[3] += 100.0;
        let b = ExpertActivationCommitment::from_outputs(&tokens, &outputs, 64, 8).unwrap();
        assert_ne!(a.commitment_hash(), b.commitment_hash());
    }

    #[test]
    fn top_features_ranked_by_magnitude() {
        let row = [0.1f32, -5.0, 2.0, -0.5, 3.0];
        let feats = top_features(&row, 3);
        assert_eq!(feats[0].index, 1);
        assert_eq!(feats[0].value, -5.0);
        assert_eq!(feats[1].index, 4);
        assert_eq!(feats[2].index, 2);
    }

    #[test]
    fn length_mismatch_rejected() {
        let tokens = vec![0u32, 1];
        let outputs = vec![0.0f32; 63];
        assert!(ExpertActivationCommitment::from_outputs(&tokens, &outputs, 64, 8).is_err());
    }

    #[test]
    fn verify_passes_on_near_identical_reexecution() {
        let (tokens, outputs) = sample_outputs(8, 64);
        let commitment =
            ExpertActivationCommitment::from_outputs(&tokens, &outputs, 64, 8).unwrap();
        // Simulate Q8_0-scale wire error: 0.3% relative perturbation.
        let perturbed: Vec<f32> = outputs.iter().map(|v| v * 1.003).collect();
        let outcome = verify_activation_commitment(&commitment, &perturbed, 64).unwrap();
        assert!(outcome.pass, "outcome: {outcome:?}");
        assert_eq!(outcome.rows_total, 8);
    }

    #[test]
    fn verify_fails_on_fabricated_outputs() {
        let (tokens, outputs) = sample_outputs(8, 64);
        let commitment =
            ExpertActivationCommitment::from_outputs(&tokens, &outputs, 64, 8).unwrap();
        let fabricated: Vec<f32> = outputs.iter().rev().copied().collect();
        let outcome = verify_activation_commitment(&commitment, &fabricated, 64).unwrap();
        assert!(!outcome.pass);
    }

    #[test]
    fn receipt_signs_and_verifies() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let public_key = keypair.public_key().clone();
        let provider =
            Address::from_bytes(tenzro_crypto::sha256(public_key.as_bytes()).as_bytes()).unwrap();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();

        let (tokens, outputs) = sample_outputs(4, 64);
        let commitment = ExpertActivationCommitment::from_outputs(&tokens, &outputs, 64, 8)
            .unwrap()
            .commitment_hash();
        let input_hash = [7u8; 32];
        let receipt = build_expert_receipt(
            "qwen3.5-397b-a17b",
            3,
            42,
            &tokens,
            input_hash,
            commitment,
            provider,
            &signer,
            public_key,
        )
        .unwrap();

        verify_expert_receipt(
            &receipt,
            "qwen3.5-397b-a17b",
            3,
            42,
            &tokens,
            &input_hash,
            &commitment,
        )
        .unwrap();

        // Tampered layer fails the signature check.
        assert!(verify_expert_receipt(
            &receipt,
            "qwen3.5-397b-a17b",
            4,
            42,
            &tokens,
            &input_hash,
            &commitment,
        )
        .is_err());

        // Mismatched commitment fails before signature.
        assert!(verify_expert_receipt(
            &receipt,
            "qwen3.5-397b-a17b",
            3,
            42,
            &tokens,
            &input_hash,
            &[0u8; 32],
        )
        .is_err());
    }
}
