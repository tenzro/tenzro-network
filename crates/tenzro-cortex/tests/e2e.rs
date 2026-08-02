//! Full-lifecycle integration tests for Tenzro Cortex.
//!
//! Covers the full lifecycle a network operator walks through when standing
//! up a Cortex worker:
//!
//! 1. REGISTER — worker signs a [`CortexAdvertisement`], a peer node
//!    ingests it into a [`RemoteWorkerRegistry`] (the same path used by
//!    gossipsub discovery).
//! 2. INFER — client dispatches a [`CortexRequest`] to
//!    [`CortexWorker::execute`]; mock backend echoes the payload and
//!    reports loops_used; worker recomputes price and re-signs the
//!    receipt.
//! 3. VERIFY — [`verify_receipt`] checks Ed25519 signature against the
//!    canonical preimage; receipt must bind (model_id, weights_hash,
//!    runtime_hash, loops_used, worker_did, worker_address, commitments,
//!    price).
//! 4. SETTLE — final price_wei must equal [`CortexPricing::compute`]
//!    over the reported tokens/loops/attestation requirement, and must
//!    fall within the caller's [`ReasoningBudget::max_cost_wei`].
//!
//! The mock backend is deterministic so these assertions are exact, not
//! probabilistic. For sidecar-backed coverage, run the reference Python
//! FastAPI sidecar under `sidecar/reference_python/` and drive
//! [`SidecarModel`] directly — the receipt-signing path is identical,
//! because the worker discards the sidecar's placeholder signature and
//! re-signs with its own key.

use std::sync::Arc;

use tenzro_cortex::{
    CortexWorker, MockCortexModel,
    advertisement::{CortexAdvertisement, RemoteWorkerRegistry},
    verify_receipt,
};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_types::{
    cortex::{
        AttestationRequirement, CortexModelFamily, CortexPricing, CortexRequest, ReasoningBudget,
        ReasoningTier,
    },
    primitives::{Address, Timestamp},
};

const WORKER_DID: &str = "did:tenzro:machine:e2e-worker-1";
const MODEL_ID: &str = "mythos-3b";
const SIDECAR_ENDPOINT: &str = "http://127.0.0.1:8088";

struct WorkerCtx {
    worker: CortexWorker,
    signer: Arc<dyn Signer + Send + Sync>,
    address: Address,
    family: CortexModelFamily,
    pricing: CortexPricing,
}

fn build_worker() -> WorkerCtx {
    let signer: Arc<dyn Signer + Send + Sync> =
        Arc::new(Ed25519SignerImpl::generate().expect("generate ed25519 signer"));
    let address = Address::default();
    let family = CortexModelFamily {
        arch: "rdt-moe".into(),
        max_loops: 32,
        moe_experts: 64,
        experts_per_token: 2,
        attn_type: "mla".into(),
        supported_tiers: vec![
            ReasoningTier::Fast,
            ReasoningTier::Standard,
            ReasoningTier::Deep,
        ],
    };
    let pricing = CortexPricing::default();
    let backend = Arc::new(MockCortexModel::new(
        MODEL_ID,
        family.clone(),
        WORKER_DID,
        address,
        signer.clone(),
    ));
    let worker = CortexWorker::new(backend, pricing, signer.clone(), WORKER_DID, address);
    WorkerCtx {
        worker,
        signer,
        address,
        family,
        pricing,
    }
}

fn standard_request(request_id: &str, input: Vec<u8>) -> CortexRequest {
    CortexRequest {
        request_id: request_id.to_string(),
        model_id: MODEL_ID.to_string(),
        requester: Address::default(),
        input,
        budget: ReasoningBudget {
            max_cost_wei: 10_000_000_000,
            ..ReasoningBudget::for_tier(ReasoningTier::Standard)
        },
        params: Default::default(),
        timestamp: Timestamp::default(),
    }
}

#[tokio::test]
async fn e2e_register_infer_verify_settle() {
    let ctx = build_worker();

    // --- 1. REGISTER -----------------------------------------------------
    // Worker broadcasts a signed advertisement; a peer node ingests it.
    let ad = CortexAdvertisement::sign(
        &*ctx.signer,
        WORKER_DID,
        ctx.address,
        MODEL_ID,
        ctx.family.clone(),
        ctx.pricing,
        Some(SIDECAR_ENDPOINT.to_string()),
        60,
    )
    .expect("advertisement signs");

    ad.verify().expect("advertisement Ed25519-valid");
    assert!(!ad.is_expired(), "fresh advertisement must not be expired");

    let registry = RemoteWorkerRegistry::new();
    registry
        .ingest(ad.clone())
        .expect("registry ingests valid advertisement");
    let live = registry.snapshot();
    assert_eq!(live.len(), 1, "registry surfaces one live entry");
    assert_eq!(live[0].worker_did, WORKER_DID);
    assert_eq!(live[0].model_id, MODEL_ID);
    assert_eq!(live[0].endpoint.as_deref(), Some(SIDECAR_ENDPOINT));

    // --- 2. INFER --------------------------------------------------------
    let input = b"settle this: 42".to_vec();
    let input_len = input.len();
    let req = standard_request("req-e2e-1", input.clone());

    let resp = ctx.worker.execute(&req).await.expect("worker executes");

    // Standard tier is min=max=8 loops; mock picks budget.max_loops, so the
    // worker's budget check accepts the reported loops_used exactly.
    assert_eq!(resp.metadata.loops_used, 8, "loops_used == Standard tier");
    assert_eq!(resp.receipt.loops_used, 8);
    assert_eq!(resp.receipt.loops_requested, 8);

    // Echo backend: output bytes are the input bytes verbatim.
    assert_eq!(resp.output, input, "MockCortexModel echoes input");
    assert_eq!(resp.request_id, req.request_id);
    assert_eq!(resp.model_id, MODEL_ID);
    assert_eq!(resp.worker, ctx.address);

    // Tokens mirror mock backend's `max(1, len/4)` heuristic.
    let expected_tokens = (input_len / 4).max(1) as u32;
    assert_eq!(resp.receipt.tokens_in, expected_tokens);
    assert_eq!(resp.receipt.tokens_out, expected_tokens);

    // Receipt binds to the worker identity.
    assert_eq!(resp.receipt.worker_did, WORKER_DID);
    assert_eq!(resp.receipt.worker_address, ctx.address);
    assert_eq!(resp.receipt.model_id, MODEL_ID);

    // --- 3. VERIFY -------------------------------------------------------
    // Worker re-signed the receipt after recomputing the price — so the
    // signature must verify over the finalized preimage (15 fields in
    // declaration order, signature excluded).
    verify_receipt(&resp.receipt).expect("receipt Ed25519-valid");

    // --- 4. SETTLE -------------------------------------------------------
    // Final price must equal CortexPricing::compute() exactly. The caller's
    // budget used AttestationRequirement::default() (via for_tier); Standard
    // tier defaults to None, so no TEE/ZK premium applies.
    let expected_price = ctx.pricing.compute(
        resp.receipt.tokens_in,
        resp.receipt.tokens_out,
        resp.receipt.loops_used,
        AttestationRequirement::None,
    );
    assert_eq!(
        resp.price_wei, expected_price,
        "response price matches pricing formula"
    );
    assert_eq!(
        resp.receipt.price_wei, expected_price,
        "receipt price matches pricing formula"
    );
    assert!(
        resp.price_wei > 0,
        "standard-tier inference must be metered with non-zero cost"
    );
    assert!(
        resp.price_wei <= req.budget.max_cost_wei,
        "settled price must be within requested budget ceiling"
    );
}

/// Mutating any field of a signed receipt must invalidate the signature.
/// This guards against a malicious settlement service rewriting
/// loops_used / price_wei / tokens_* after the worker releases the receipt.
#[tokio::test]
async fn tampered_receipt_fails_verify() {
    let ctx = build_worker();
    let req = standard_request("req-tamper", b"evidence".to_vec());
    let mut resp = ctx.worker.execute(&req).await.expect("worker executes");

    // Baseline: the untampered receipt verifies.
    verify_receipt(&resp.receipt).expect("original receipt verifies");

    // Mutate loops_used — preimage changes, Ed25519 verify must fail.
    resp.receipt.loops_used = resp.receipt.loops_used.saturating_add(1);
    assert!(
        verify_receipt(&resp.receipt).is_err(),
        "tampered loops_used must fail verification"
    );
}

/// Worker must reject a request whose budget exceeds the model family's
/// advertised `max_loops` before invoking the backend. Catches two classes
/// of bug: (a) over-budget settlement (caller charged for more loops than
/// the weights can physically support), (b) silent sidecar clamping with
/// stale advertisement pricing.
#[tokio::test]
async fn out_of_family_budget_rejected() {
    let ctx = build_worker();
    let req = CortexRequest {
        request_id: "req-overflow".into(),
        model_id: MODEL_ID.into(),
        requester: Address::default(),
        input: b"x".to_vec(),
        budget: ReasoningBudget {
            // family.max_loops == 32; this budget is strictly out of range.
            min_loops: 50,
            max_loops: 100,
            tier: ReasoningTier::Deep,
            max_cost_wei: 10_000_000_000,
            attestation: AttestationRequirement::None,
            deadline_ms: None,
        },
        params: Default::default(),
        timestamp: Timestamp::default(),
    };

    let result = ctx.worker.execute(&req).await;
    assert!(
        result.is_err(),
        "out-of-family budget must be rejected pre-inference, got Ok"
    );
}

/// Swapping in a foreign public key (as a rogue settlement service might do)
/// must fail verification even if every other field is unchanged. This is
/// a stronger property than generic tampering because it targets the
/// key-binding assumption of the receipt.
#[tokio::test]
async fn foreign_signature_fails_verify() {
    let ctx = build_worker();
    let req = standard_request("req-swap", b"honest prompt".to_vec());
    let mut resp = ctx.worker.execute(&req).await.expect("worker executes");
    verify_receipt(&resp.receipt).expect("original receipt verifies");

    // Sign the same preimage with a DIFFERENT key, but keep the worker's
    // ORIGINAL public key in the receipt — this models the stronger attack:
    // the attacker has a signature they made with their own key, but they
    // need the receipt to *claim* the worker's key so downstream consumers
    // route payment to the right worker. Ed25519 verification of the forged
    // signature bytes against the worker's public key must fail.
    let worker_pubkey = resp.receipt.signature.public_key.clone();
    let foreign_signer = Ed25519SignerImpl::generate().expect("generate foreign signer");
    let preimage = resp.receipt.signing_preimage();
    let forged = foreign_signer
        .sign(&preimage)
        .expect("foreign signer signs preimage");
    resp.receipt.signature =
        tenzro_types::primitives::Signature::new(forged.as_bytes().to_vec(), worker_pubkey);
    assert!(
        verify_receipt(&resp.receipt).is_err(),
        "receipt signed by the wrong key must fail verification"
    );
}
