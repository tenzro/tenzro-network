//! Cortex receipt construction and signing.

use sha2::{Digest, Sha256};
use tenzro_crypto::signatures::Signer;
use tenzro_types::{
    cortex::{CortexReceipt, CortexRequest},
    primitives::{Address, Hash, Signature, Timestamp},
};

use crate::error::{CortexError, Result};

/// Canonical serialization of a Cortex request for the input commitment.
///
/// Only the fields that materially affect the output are included —
/// transport-level identifiers like `request_id` and `timestamp` are
/// deliberately excluded so identical inputs produce identical commitments.
pub fn canonicalize_input(req: &CortexRequest) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Canonical<'a> {
        model_id: &'a str,
        input: &'a [u8],
        min_loops: u32,
        max_loops: u32,
        params: &'a std::collections::HashMap<String, String>,
    }
    let c = Canonical {
        model_id: &req.model_id,
        input: &req.input,
        min_loops: req.budget.min_loops,
        max_loops: req.budget.max_loops,
        params: &req.params,
    };
    serde_json::to_vec(&c).unwrap_or_default()
}

/// Canonical serialization of a raw output payload for the output commitment.
pub fn canonicalize_output(output: &[u8]) -> Vec<u8> {
    output.to_vec()
}

/// SHA-256 commitment over bytes.
pub fn hash_commitment(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&digest);
    Hash::new(buf)
}

/// Build and sign a [`CortexReceipt`].
#[allow(clippy::too_many_arguments)]
pub fn sign_receipt(
    signer: &dyn Signer,
    model_id: &str,
    weights_hash: Hash,
    runtime_hash: Hash,
    loops_requested: u32,
    loops_used: u32,
    input_commitment: Hash,
    output_commitment: Hash,
    worker_did: &str,
    worker_address: Address,
    tee_quote: Option<Vec<u8>>,
    zk_proof: Option<Vec<u8>>,
    tokens_in: u32,
    tokens_out: u32,
    price_wei: u128,
) -> Result<CortexReceipt> {
    let timestamp: Timestamp = Timestamp::now();

    // Temporary unsigned receipt used only to produce the signing preimage.
    let unsigned = CortexReceipt {
        model_id: model_id.to_string(),
        weights_hash,
        runtime_hash,
        loops_requested,
        loops_used,
        input_commitment,
        output_commitment,
        worker_did: worker_did.to_string(),
        worker_address,
        tee_quote: tee_quote.clone(),
        zk_proof: zk_proof.clone(),
        tokens_in,
        tokens_out,
        price_wei,
        timestamp,
        signature: Signature::default(),
    };
    let preimage = unsigned.signing_preimage();

    let crypto_sig = signer
        .sign(&preimage)
        .map_err(|e| CortexError::Crypto(e.to_string()))?;
    let signature = Signature::new(
        crypto_sig.as_bytes().to_vec(),
        signer.public_key().as_bytes().to_vec(),
    );

    Ok(CortexReceipt {
        signature,
        ..unsigned
    })
}

/// Verify the signature on a [`CortexReceipt`] against the provided
/// `tenzro-crypto` verifier. Returns `Ok(())` on success.
pub fn verify_receipt(receipt: &CortexReceipt) -> Result<()> {
    use tenzro_crypto::keys::{KeyType, PublicKey};
    use tenzro_crypto::signatures::{Signature as CryptoSignature, verify};

    let preimage = receipt.signing_preimage();

    // Crypto-layer Signature requires a KeyType. Receipts are signed with
    // Ed25519 by default; this is consistent with the rest of the Tenzro
    // stack (validator and worker keys are Ed25519).
    let public_key = PublicKey::new(KeyType::Ed25519, receipt.signature.public_key.clone());
    let sig = CryptoSignature::new(KeyType::Ed25519, receipt.signature.bytes.clone());

    verify(&public_key, &preimage, &sig).map_err(|e| CortexError::InvalidReceipt(e.to_string()))
}
