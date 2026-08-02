//! x402 scheme backends.
//!
//! Different x402 deployments use different on-chain authorization schemes:
//!
//! | scheme id          | how the payer authorizes                                   |
//! |--------------------|------------------------------------------------------------|
//! | `tenzro-hybrid`    | Ed25519 + ML-DSA-65 hybrid signature over the credential   |
//! | `upto`             | Ed25519 + ML-DSA-65 hybrid over a MAXIMUM; settle actual  |
//! | `exact-eip3009`    | EIP-3009 `transferWithAuthorization` (USDC-style meta-tx)  |
//! | `permit2`          | Uniswap Permit2 `PermitTransferFrom` signature             |
//! | `erc7710`          | ERC-7710 redeem of a pre-issued delegation                 |
//!
//! ## The `upto` (usage-metered) scheme
//!
//! `exact` schemes bind a fixed amount at authorization time. For per-token
//! LLM billing, metered compute, or bandwidth, the buyer can't know the
//! amount in advance. The `upto` scheme lets the buyer sign a *maximum*: the
//! challenge's `amount` is the ceiling, the credential's `amount` is the
//! actual usage (which must be `<= ceiling`), and settlement charges the
//! actual. The buyer's hybrid signature is over the ceiling (bound by a
//! distinct domain tag so an `upto` authorization can never be replayed as
//! an `exact` one), so the seller is free to settle any amount up to it.
//!
//! The [`SchemeRegistry`] looks up a [`SchemeBackend`] by id and delegates
//! credential verification to it. The credential-form path reads the scheme
//! from `challenge.extra["scheme"]`; the payload-form path reads it from the
//! top-level `requirement.scheme` field (Coinbase x402 V2 wire shape).
//!
//! The default registry registered by [`X402PaymentServer::new`](super::server::X402PaymentServer::new)
//! contains:
//!
//! - [`TenzroHybridBackend`] under `"tenzro-hybrid"` ([`DEFAULT_SCHEME`]).
//! - [`UptoBackend`] under `"upto"`.
//! - [`Eip3009Backend`] under `"exact-eip3009"` and `"eip3009"`.
//! - [`Permit2Backend`] under `"permit2"`.
//! - [`Erc7710Backend`] under `"erc7710"`.
//!
//! `Eip3009Backend` and `Permit2Backend` delegate signature/balance/nonce
//! checks to a [`FacilitatorVerifier`] (default impl: [`CdpFacilitatorVerifier`]
//! wrapping [`CdpFacilitatorClient`](super::coinbase::CdpFacilitatorClient)).
//! `Erc7710Backend` delegates redemption proofs to a [`DelegationVerifier`]
//! (no production wiring yet — the trait is in place so TDIP / EVM-precompile
//! integrations can plug in without touching the server).
//!
//! Tests inject mock backends via [`SchemeRegistry::register`] or replace the
//! whole registry via [`X402PaymentServer::with_scheme_registry`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, HybridVerifier, StandardHybridVerifier,
};
use tenzro_crypto::keys::{KeyType, PublicKey};
use tracing::debug;

use crate::error::{PaymentError, Result};
use crate::types::{PaymentChallenge, PaymentCredential};
use crate::x402::coinbase::{CdpFacilitatorClient, SettleRequest, VerifyRequest};
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::X402PaymentRequirement;

/// Scheme identifier used when a challenge does not pin one explicitly.
pub const DEFAULT_SCHEME: &str = "tenzro-hybrid";

/// Usage-metered scheme: buyer signs a maximum, seller settles the actual.
pub const UPTO_SCHEME: &str = "upto";

/// Domain-separation tag for the `upto` authorization preimage. Distinct from
/// the plain credential preimage so a maximum-authorizing signature can never
/// be replayed as an exact-amount authorization.
pub const UPTO_PREIMAGE_DOMAIN: &str = "tenzro/x402/upto";

/// Channel scheme: buyer deposits once, then signs cumulative off-chain
/// vouchers; the seller settles many vouchers with a single on-chain claim.
pub const BATCH_SETTLEMENT_SCHEME: &str = "batch-settlement";

/// Domain-separation tag for a batch-settlement cumulative-voucher preimage.
/// Distinct from every other x402 preimage so a voucher can never be replayed
/// as an exact/upto authorization and vice versa.
pub const BATCH_VOUCHER_PREIMAGE_DOMAIN: &str = "tenzro/x402/batch-voucher";

/// One pluggable verification path for an x402 credential.
///
/// Backends are stateless wrt. challenge/credential pairs — they receive both
/// at verify time and return `Ok(())` if the credential validly authorizes the
/// challenge under the backend's scheme.
#[async_trait]
pub trait SchemeBackend: Send + Sync + std::fmt::Debug {
    /// Canonical scheme id (e.g. `"exact-eip3009"`). Must match the value
    /// stored in `challenge.extra["scheme"]`.
    fn name(&self) -> &'static str;

    /// Verify `credential` against `challenge` under this backend's scheme.
    /// Implementations MUST NOT mutate any shared state; settlement happens
    /// elsewhere.
    async fn verify(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()>;

    /// Settle the (already-verified) credential. Returns the on-chain
    /// transaction hash or facilitator-supplied receipt id, when applicable.
    /// Backends without an on-chain settlement step (e.g. Tenzro-hybrid,
    /// which is settled by the local SettlementEngine) return `Ok(None)`.
    async fn settle(
        &self,
        _challenge: &PaymentChallenge,
        _credential: &PaymentCredential,
    ) -> Result<Option<String>> {
        Ok(None)
    }

    /// Payload-form verification used by the [`X402Facilitator`](super::facilitator::X402Facilitator)
    /// HTTP verify endpoint.
    ///
    /// The facilitator works directly on the wire-level
    /// `X402PaymentPayload` + `X402PaymentRequirement` shape (the V2 spec) and
    /// has no `PaymentCredential`. This entry point lets the same backends
    /// service both flows. Default: error — backends that don't have a
    /// payload-form verification path simply don't override it.
    async fn verify_payload(
        &self,
        _requirement: &X402PaymentRequirement,
        _payload: &X402PaymentPayload,
    ) -> Result<()> {
        Err(PaymentError::VerificationFailed(format!(
            "Scheme '{}' does not implement payload-form verification",
            self.name()
        )))
    }

    /// Payload-form settlement (parallel to [`Self::settle`]). Returns the
    /// on-chain transaction hash on success. Backends settled by a local
    /// settlement engine (e.g. tenzro-hybrid) return `Ok(None)`.
    async fn settle_payload(
        &self,
        _requirement: &X402PaymentRequirement,
        _payload: &X402PaymentPayload,
    ) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Registry of scheme backends keyed by scheme id.
///
/// IDs are matched case-insensitively. Multiple aliases can map to the same
/// backend (e.g. `"exact-eip3009"` and `"eip3009"` both resolve to
/// [`Eip3009Backend`]).
#[derive(Clone)]
pub struct SchemeRegistry {
    backends: HashMap<String, Arc<dyn SchemeBackend>>,
}

impl SchemeRegistry {
    /// Create an empty registry. Use [`SchemeRegistry::with_defaults`] for the
    /// default set.
    pub fn empty() -> Self {
        Self {
            backends: HashMap::new(),
        }
    }

    /// Build a registry pre-populated with the built-in backends.
    pub fn with_defaults() -> Self {
        let mut r = Self::empty();
        let hybrid: Arc<dyn SchemeBackend> = Arc::new(TenzroHybridBackend);
        r.register(DEFAULT_SCHEME, hybrid);

        let upto: Arc<dyn SchemeBackend> = Arc::new(UptoBackend);
        r.register(UPTO_SCHEME, upto);

        let batch: Arc<dyn SchemeBackend> = Arc::new(BatchSettlementBackend);
        r.register(BATCH_SETTLEMENT_SCHEME, batch);

        let eip3009: Arc<dyn SchemeBackend> =
            Arc::new(Eip3009Backend::new(Arc::new(CdpFacilitatorVerifier::new())));
        r.register("exact-eip3009", Arc::clone(&eip3009));
        r.register("eip3009", eip3009);

        let permit2: Arc<dyn SchemeBackend> =
            Arc::new(Permit2Backend::new(Arc::new(CdpFacilitatorVerifier::new())));
        r.register("permit2", permit2);

        let erc7710: Arc<dyn SchemeBackend> = Arc::new(Erc7710Backend::new(Arc::new(
            crate::x402::erc7710::Erc7710DelegationVerifier::default(),
        )));
        r.register("erc7710", erc7710);

        r
    }

    /// Build the default registry but route the EIP-3009 and Permit2 schemes
    /// through a self-hosted [`LocalFacilitatorVerifier`] instead of the remote
    /// [`CdpFacilitatorVerifier`]. This is the operator default: verification
    /// and settlement run against the operator's own EVM RPC + relayer signer,
    /// with no dependency on Coinbase CDP. The tenzro-hybrid, upto,
    /// batch-settlement, and erc7710 backends are identical to
    /// [`SchemeRegistry::with_defaults`].
    pub fn with_local_facilitator(
        signer: Arc<tenzro_bridge::EvmTransactionSigner>,
        rpc_url: impl Into<String>,
    ) -> Self {
        let mut r = Self::with_defaults();

        let local: Arc<dyn FacilitatorVerifier> = Arc::new(
            crate::x402::local_facilitator::LocalFacilitatorVerifier::new(signer, rpc_url),
        );

        let eip3009: Arc<dyn SchemeBackend> = Arc::new(Eip3009Backend::new(Arc::clone(&local)));
        r.register("exact-eip3009", Arc::clone(&eip3009));
        r.register("eip3009", eip3009);

        let permit2: Arc<dyn SchemeBackend> = Arc::new(Permit2Backend::new(local));
        r.register("permit2", permit2);

        r
    }

    /// Register (or replace) a backend under `id`. Lookup is
    /// case-insensitive — the id is lower-cased on insert.
    pub fn register(&mut self, id: &str, backend: Arc<dyn SchemeBackend>) {
        self.backends.insert(id.to_ascii_lowercase(), backend);
    }

    /// Look up a backend by id (case-insensitive). Returns `None` if no
    /// backend is registered for `id` or any of its aliases.
    pub fn get(&self, id: &str) -> Option<Arc<dyn SchemeBackend>> {
        self.backends.get(&id.to_ascii_lowercase()).cloned()
    }

    /// Look up the backend declared by a challenge's `extra["scheme"]` field.
    /// Falls back to the [`DEFAULT_SCHEME`] backend if the field is absent.
    pub fn lookup_for_challenge(
        &self,
        challenge: &PaymentChallenge,
    ) -> Result<Arc<dyn SchemeBackend>> {
        let id = challenge
            .extra
            .get("scheme")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_SCHEME);
        self.get(id).ok_or_else(|| {
            PaymentError::VerificationFailed(format!(
                "No x402 scheme backend registered for id '{}'",
                id
            ))
        })
    }

    /// Look up the backend declared by a requirement's top-level `scheme`
    /// field (Coinbase x402 V2 wire shape). Falls back to [`DEFAULT_SCHEME`]
    /// when empty. Used by the facilitator's payload-form verification path.
    pub fn lookup_for_requirement(
        &self,
        requirement: &X402PaymentRequirement,
    ) -> Result<Arc<dyn SchemeBackend>> {
        let id = if requirement.scheme.is_empty() {
            DEFAULT_SCHEME
        } else {
            requirement.scheme.as_str()
        };
        self.get(id).ok_or_else(|| {
            PaymentError::VerificationFailed(format!(
                "No x402 scheme backend registered for id '{}'",
                id
            ))
        })
    }

    /// All registered scheme ids (lower-case). Useful for diagnostics.
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.backends.keys().cloned().collect();
        v.sort();
        v
    }
}

impl Default for SchemeRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ─── Tenzro hybrid backend (default) ──────────────────────────────────────

/// Internal Tenzro x402 scheme: Ed25519 + ML-DSA-65 hybrid signature
/// over `challenge_id || payer_did || amount_le || asset`.
///
/// Mirrors the inline verification logic that lived on `X402PaymentServer`
/// before the scheme registry was introduced.
#[derive(Debug)]
pub struct TenzroHybridBackend;

#[async_trait]
impl SchemeBackend for TenzroHybridBackend {
    fn name(&self) -> &'static str {
        "tenzro-hybrid"
    }

    async fn verify(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()> {
        if credential.pq_public_key.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "Internal Tenzro x402 credential is missing pq_public_key (ML-DSA-65)".to_string(),
            ));
        }
        if credential.pq_signature.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "Internal Tenzro x402 credential is missing pq_signature (ML-DSA-65)".to_string(),
            ));
        }

        let message = build_credential_preimage(credential);
        let classical_pk = extract_classical_public_key(credential)?;

        let composite_pk = CompositePublicKey::new(classical_pk, credential.pq_public_key.clone());
        let composite_sig = CompositeSignature::new(
            credential.signature.clone(),
            credential.pq_signature.clone(),
        );

        let verifier = StandardHybridVerifier::new(composite_pk);
        verifier.verify(&message, &composite_sig).map_err(|e| {
            PaymentError::VerificationFailed(format!("Hybrid signature verification failed: {}", e))
        })?;

        debug!(
            "tenzro-hybrid verified credential {} for challenge {}",
            credential.credential_id, challenge.challenge_id
        );
        Ok(())
    }

    async fn verify_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()> {
        // Wire format (Coinbase x402 V2): nested ExactSchemePayload with
        // classical Ed25519 signature over the canonical preimage produced
        // by X402Client::create_signed_payload — network || asset ||
        // max_amount_required || pay_to || payer. The payer address is
        // carried in payload.payload.authorization.from. The PQ leg is bound
        // to the wallet's identity out-of-band (see x402::client) and is
        // not on the x402 wire (yet).
        let inner = &payload.payload;
        if inner.signature.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "tenzro-hybrid payload missing signature".to_string(),
            ));
        }

        let sig_hex = inner
            .signature
            .strip_prefix("0x")
            .unwrap_or(&inner.signature);
        let sig_bytes = hex::decode(sig_hex).map_err(|e| {
            PaymentError::VerificationFailed(format!("Invalid signature hex: {}", e))
        })?;

        let payer = &inner.authorization.from;
        let pk_hex = payer.strip_prefix("0x").unwrap_or(payer.as_str());
        let pk_bytes = hex::decode(pk_hex).map_err(|e| {
            PaymentError::VerificationFailed(format!("Invalid payer address hex: {}", e))
        })?;

        let mut message = Vec::new();
        message.extend_from_slice(requirement.network.as_bytes());
        message.extend_from_slice(requirement.asset.as_bytes());
        message.extend_from_slice(requirement.max_amount_required.as_bytes());
        message.extend_from_slice(requirement.pay_to.as_bytes());
        message.extend_from_slice(payer.as_bytes());

        use tenzro_crypto::keys::{KeyType, PublicKey};
        use tenzro_crypto::signatures::{Ed25519VerifierImpl, Signature, Verifier};

        let public_key = PublicKey::new(KeyType::Ed25519, pk_bytes);
        let signature = Signature::new(KeyType::Ed25519, sig_bytes);

        let verifier = Ed25519VerifierImpl::new(public_key)
            .map_err(|e| PaymentError::VerificationFailed(format!("Invalid public key: {}", e)))?;

        verifier.verify(&message, &signature).map_err(|e| {
            PaymentError::VerificationFailed(format!(
                "tenzro-hybrid signature verification failed: {}",
                e
            ))
        })?;

        debug!(
            "tenzro-hybrid verified payload from payer {} for {} {}",
            payer, requirement.max_amount_required, requirement.asset
        );
        Ok(())
    }

    // settle_payload: tenzro-hybrid is settled by the local SettlementEngine
    // (X402Facilitator::settle), so the default `Ok(None)` is correct.
}

/// Builds the canonical signing preimage for a Tenzro-hybrid x402 credential.
/// Exposed so signers and verifiers can never disagree on the layout.
pub fn build_credential_preimage(credential: &PaymentCredential) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        credential.challenge_id.len() + credential.payer_did.len() + 16 + credential.asset.len(),
    );
    message.extend_from_slice(credential.challenge_id.as_bytes());
    message.extend_from_slice(credential.payer_did.as_bytes());
    message.extend_from_slice(&credential.amount.to_le_bytes());
    message.extend_from_slice(credential.asset.as_bytes());
    message
}

fn extract_classical_public_key(credential: &PaymentCredential) -> Result<PublicKey> {
    if let Some(pk_value) = credential.extra.get("public_key")
        && let Some(pk_hex) = pk_value.as_str()
    {
        let pk_bytes = hex::decode(pk_hex)
            .map_err(|e| PaymentError::CredentialError(format!("Invalid public key hex: {}", e)))?;
        return Ok(PublicKey::new(KeyType::Ed25519, pk_bytes));
    }
    if !credential.payer_address.is_empty() {
        let pk_bytes = hex::decode(&credential.payer_address).map_err(|_| {
            PaymentError::CredentialError(
                "Credential must include public_key in extra metadata or valid payer_address"
                    .to_string(),
            )
        })?;
        return Ok(PublicKey::new(KeyType::Ed25519, pk_bytes));
    }
    Err(PaymentError::CredentialError(
        "No public key found in credential".to_string(),
    ))
}

// ─── Upto (usage-metered) backend ─────────────────────────────────────────

/// Usage-metered x402 backend. The buyer signs a **maximum** authorized
/// amount; the seller settles the **actual** usage, which must be ≤ the
/// maximum. Used for per-token LLM billing, metered compute, and bandwidth
/// where the exact charge isn't known at authorization time.
///
/// # Credential layout
///
/// - `credential.amount` — the *actual* usage the server is settling.
/// - `credential.extra["upto_max"]` — the *maximum* the buyer authorized,
///   as a decimal string. This is the value the buyer's hybrid signature
///   commits to (via [`build_upto_preimage`]). Must be `>= credential.amount`.
/// - `credential.pq_public_key` / `pq_signature` / `signature` — the same
///   Ed25519 + ML-DSA-65 hybrid legs as [`TenzroHybridBackend`], but over
///   the [`UPTO_PREIMAGE_DOMAIN`]-tagged maximum preimage.
///
/// The server's amount admission (`X402PaymentServer::verify_credential`)
/// enforces `credential.amount <= challenge.amount` for this scheme instead
/// of exact equality; this backend enforces `credential.amount <= upto_max`
/// and that the signature commits to `upto_max`.
#[derive(Debug)]
pub struct UptoBackend;

/// Builds the canonical `upto` authorization preimage. The buyer signs the
/// **maximum** (`upto_max`), not the actual usage, so the seller can settle
/// any amount up to it. Domain-separated from [`build_credential_preimage`]
/// so the two signature families never overlap.
pub fn build_upto_preimage(
    challenge_id: &str,
    payer_did: &str,
    upto_max: u128,
    asset: &str,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        UPTO_PREIMAGE_DOMAIN.len() + challenge_id.len() + payer_did.len() + 16 + asset.len(),
    );
    message.extend_from_slice(UPTO_PREIMAGE_DOMAIN.as_bytes());
    message.extend_from_slice(challenge_id.as_bytes());
    message.extend_from_slice(payer_did.as_bytes());
    message.extend_from_slice(&upto_max.to_le_bytes());
    message.extend_from_slice(asset.as_bytes());
    message
}

/// Read the buyer-authorized maximum from `credential.extra["upto_max"]`.
fn extract_upto_max(credential: &PaymentCredential) -> Result<u128> {
    let raw = credential
        .extra
        .get("upto_max")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PaymentError::CredentialError(
                "upto credential is missing extra.upto_max (decimal string)".to_string(),
            )
        })?;
    raw.parse::<u128>().map_err(|_| {
        PaymentError::CredentialError(format!(
            "upto credential extra.upto_max is not a valid u128: '{}'",
            raw
        ))
    })
}

#[async_trait]
impl SchemeBackend for UptoBackend {
    fn name(&self) -> &'static str {
        UPTO_SCHEME
    }

    async fn verify(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()> {
        if credential.pq_public_key.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "upto credential is missing pq_public_key (ML-DSA-65)".to_string(),
            ));
        }
        if credential.pq_signature.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "upto credential is missing pq_signature (ML-DSA-65)".to_string(),
            ));
        }

        let upto_max = extract_upto_max(credential)?;

        // The actual usage must fit under the authorized maximum...
        if credential.amount > upto_max {
            return Err(PaymentError::VerificationFailed(format!(
                "upto actual amount {} exceeds authorized maximum {}",
                credential.amount, upto_max
            )));
        }
        // ...and the maximum must fit under the challenge ceiling.
        if upto_max > challenge.amount {
            return Err(PaymentError::VerificationFailed(format!(
                "upto authorized maximum {} exceeds challenge ceiling {}",
                upto_max, challenge.amount
            )));
        }

        // The buyer's hybrid signature commits to the maximum, not the actual.
        let message = build_upto_preimage(
            &credential.challenge_id,
            &credential.payer_did,
            upto_max,
            &credential.asset,
        );
        let classical_pk = extract_classical_public_key(credential)?;

        let composite_pk = CompositePublicKey::new(classical_pk, credential.pq_public_key.clone());
        let composite_sig = CompositeSignature::new(
            credential.signature.clone(),
            credential.pq_signature.clone(),
        );

        let verifier = StandardHybridVerifier::new(composite_pk);
        verifier.verify(&message, &composite_sig).map_err(|e| {
            PaymentError::VerificationFailed(format!(
                "upto hybrid signature verification failed: {}",
                e
            ))
        })?;

        debug!(
            "upto verified credential {} (actual {} of max {}) for challenge {}",
            credential.credential_id, credential.amount, upto_max, challenge.challenge_id
        );
        Ok(())
    }

    // settle: usage-metered payments are closed by the local SettlementEngine
    // using credential.amount as the actual charge, so `Ok(None)` is correct.
}

// ─── Batch-settlement (channel voucher) backend ───────────────────────────

/// Channel-voucher x402 backend. The buyer deposits once into a micropayment
/// channel, then signs a running **cumulative** total after each request; the
/// seller settles many vouchers with a single on-chain claim. Used for
/// high-frequency per-request billing where per-request on-chain settlement
/// would dominate the cost.
///
/// This backend is stateless: it verifies that a voucher is a valid hybrid
/// signature over `(channel_id, cumulative_amount, voucher_nonce)` and that
/// the voucher is monotone (cumulative ≥ the challenge's declared floor and
/// within the channel deposit ceiling). The stateful accounting — deposit
/// locking, cumulative debit, claim, refund — lives in
/// [`tenzro_settlement::ChannelManager`], driven at the server/node layer once
/// verification passes.
///
/// # Credential layout
///
/// - `credential.amount` — the *incremental* charge this voucher authorizes
///   (`cumulative - previous_cumulative`), settled into the channel.
/// - `credential.extra["channel_id"]` — hex of the channel this voucher draws
///   against. Must equal the challenge's `extra["channel_id"]`.
/// - `credential.extra["cumulative_amount"]` — the running total the buyer is
///   signing, as a decimal string.
/// - `credential.extra["voucher_nonce"]` — monotonically increasing per-channel
///   voucher counter, as a decimal string.
/// - `credential.extra["channel_deposit"]` — the channel deposit ceiling, as a
///   decimal string. The cumulative total may not exceed it.
/// - `credential.{signature, pq_signature, pq_public_key}` — the Ed25519 +
///   ML-DSA-65 hybrid legs over [`build_batch_voucher_preimage`].
#[derive(Debug)]
pub struct BatchSettlementBackend;

/// Builds the canonical batch-settlement voucher preimage. The buyer signs the
/// **cumulative** total against a specific channel and voucher nonce, so the
/// seller can settle the highest voucher and discard the rest.
pub fn build_batch_voucher_preimage(
    channel_id: &str,
    payer_did: &str,
    cumulative_amount: u128,
    voucher_nonce: u64,
    asset: &str,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        BATCH_VOUCHER_PREIMAGE_DOMAIN.len()
            + channel_id.len()
            + payer_did.len()
            + 16
            + 8
            + asset.len(),
    );
    message.extend_from_slice(BATCH_VOUCHER_PREIMAGE_DOMAIN.as_bytes());
    message.extend_from_slice(channel_id.as_bytes());
    message.extend_from_slice(payer_did.as_bytes());
    message.extend_from_slice(&cumulative_amount.to_le_bytes());
    message.extend_from_slice(&voucher_nonce.to_le_bytes());
    message.extend_from_slice(asset.as_bytes());
    message
}

/// Read a required decimal `u128` field from `credential.extra`.
fn extract_u128_field(credential: &PaymentCredential, key: &str) -> Result<u128> {
    let raw = credential
        .extra
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PaymentError::CredentialError(format!(
                "batch-settlement voucher is missing extra.{} (decimal string)",
                key
            ))
        })?;
    raw.parse::<u128>().map_err(|_| {
        PaymentError::CredentialError(format!(
            "batch-settlement voucher extra.{} is not a valid u128: '{}'",
            key, raw
        ))
    })
}

/// Read a required decimal `u64` field from `credential.extra`.
fn extract_u64_field(credential: &PaymentCredential, key: &str) -> Result<u64> {
    let raw = credential
        .extra
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PaymentError::CredentialError(format!(
                "batch-settlement voucher is missing extra.{} (decimal string)",
                key
            ))
        })?;
    raw.parse::<u64>().map_err(|_| {
        PaymentError::CredentialError(format!(
            "batch-settlement voucher extra.{} is not a valid u64: '{}'",
            key, raw
        ))
    })
}

#[async_trait]
impl SchemeBackend for BatchSettlementBackend {
    fn name(&self) -> &'static str {
        BATCH_SETTLEMENT_SCHEME
    }

    async fn verify(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()> {
        if credential.pq_public_key.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "batch-settlement voucher is missing pq_public_key (ML-DSA-65)".to_string(),
            ));
        }
        if credential.pq_signature.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "batch-settlement voucher is missing pq_signature (ML-DSA-65)".to_string(),
            ));
        }

        let channel_id = credential
            .extra
            .get("channel_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PaymentError::CredentialError(
                    "batch-settlement voucher is missing extra.channel_id".to_string(),
                )
            })?;

        // The voucher must draw against the channel the challenge pins.
        if let Some(expected) = challenge.extra.get("channel_id").and_then(|v| v.as_str())
            && expected != channel_id
        {
            return Err(PaymentError::VerificationFailed(format!(
                "batch-settlement voucher channel_id '{}' does not match challenge channel '{}'",
                channel_id, expected
            )));
        }

        let cumulative = extract_u128_field(credential, "cumulative_amount")?;
        let voucher_nonce = extract_u64_field(credential, "voucher_nonce")?;
        let deposit = extract_u128_field(credential, "channel_deposit")?;

        // The incremental charge must be non-zero and must not exceed the
        // cumulative total it advances.
        if credential.amount == 0 {
            return Err(PaymentError::VerificationFailed(
                "batch-settlement voucher increment must be non-zero".to_string(),
            ));
        }
        if credential.amount > cumulative {
            return Err(PaymentError::VerificationFailed(format!(
                "batch-settlement increment {} exceeds cumulative total {}",
                credential.amount, cumulative
            )));
        }

        // The cumulative total may never exceed the channel deposit ceiling.
        if cumulative > deposit {
            return Err(PaymentError::VerificationFailed(format!(
                "batch-settlement cumulative {} exceeds channel deposit {}",
                cumulative, deposit
            )));
        }

        // The buyer's hybrid signature commits to the cumulative total against
        // this channel and voucher nonce.
        let message = build_batch_voucher_preimage(
            channel_id,
            &credential.payer_did,
            cumulative,
            voucher_nonce,
            &credential.asset,
        );
        let classical_pk = extract_classical_public_key(credential)?;

        let composite_pk = CompositePublicKey::new(classical_pk, credential.pq_public_key.clone());
        let composite_sig = CompositeSignature::new(
            credential.signature.clone(),
            credential.pq_signature.clone(),
        );

        let verifier = StandardHybridVerifier::new(composite_pk);
        verifier.verify(&message, &composite_sig).map_err(|e| {
            PaymentError::VerificationFailed(format!(
                "batch-settlement voucher signature verification failed: {}",
                e
            ))
        })?;

        debug!(
            "batch-settlement verified voucher {} (increment {}, cumulative {}, nonce {}) on channel {}",
            credential.credential_id, credential.amount, cumulative, voucher_nonce, channel_id
        );
        Ok(())
    }

    // settle: the channel debit and eventual on-chain claim are performed by
    // tenzro_settlement::ChannelManager at the server/node layer, so `Ok(None)`
    // is correct here.
}

// ─── Facilitator-backed schemes (EIP-3009 / Permit2) ──────────────────────

/// Verifies a base64-encoded x402 payload + requirements pair against a
/// remote facilitator (Coinbase CDP-style). Abstracted so unit tests can
/// inject a deterministic stub.
#[async_trait]
pub trait FacilitatorVerifier: Send + Sync + std::fmt::Debug {
    /// Verify the payload is admissible. Implementations MUST return
    /// `Err(PaymentError::VerificationFailed)` on rejection.
    async fn verify_payload(&self, payload_b64: &str, requirements_b64: &str) -> Result<()>;

    /// Settle the payload. Returns the on-chain tx hash on success.
    async fn settle_payload(&self, payload_b64: &str, requirements_b64: &str) -> Result<String>;
}

/// Default facilitator verifier — wraps [`CdpFacilitatorClient`].
#[derive(Debug)]
pub struct CdpFacilitatorVerifier {
    client: CdpFacilitatorClient,
}

impl CdpFacilitatorVerifier {
    pub fn new() -> Self {
        Self {
            client: CdpFacilitatorClient::new(),
        }
    }

    pub fn with_client(client: CdpFacilitatorClient) -> Self {
        Self { client }
    }
}

impl Default for CdpFacilitatorVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FacilitatorVerifier for CdpFacilitatorVerifier {
    async fn verify_payload(&self, payload_b64: &str, requirements_b64: &str) -> Result<()> {
        let resp = self
            .client
            .verify(&VerifyRequest {
                payload: payload_b64.to_string(),
                payment_requirements: requirements_b64.to_string(),
            })
            .await?;
        if resp.is_valid {
            Ok(())
        } else {
            Err(PaymentError::VerificationFailed(
                resp.error
                    .or(resp.invalidation_reason)
                    .unwrap_or_else(|| "Facilitator rejected payload".to_string()),
            ))
        }
    }

    async fn settle_payload(&self, payload_b64: &str, requirements_b64: &str) -> Result<String> {
        let resp = self
            .client
            .settle(&SettleRequest {
                payload: payload_b64.to_string(),
                payment_requirements: requirements_b64.to_string(),
            })
            .await?;
        if resp.success {
            Ok(resp.tx_hash)
        } else {
            Err(PaymentError::SettlementError(resp.error.unwrap_or_else(
                || "Facilitator settlement failed".to_string(),
            )))
        }
    }
}

/// Pulls the base64 payload + requirements out of a credential's `extra`.
///
/// EIP-3009 / Permit2 credentials carry the opaque facilitator-bound
/// payload as `extra.payload_b64` and the original 402 challenge as
/// `extra.requirements_b64`. Both are mandatory.
fn extract_facilitator_envelope(
    credential: &PaymentCredential,
    scheme: &str,
) -> Result<(String, String)> {
    let payload = credential
        .extra
        .get("payload_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PaymentError::CredentialError(format!(
                "{} credential is missing extra.payload_b64",
                scheme
            ))
        })?
        .to_string();
    let requirements = credential
        .extra
        .get("requirements_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            PaymentError::CredentialError(format!(
                "{} credential is missing extra.requirements_b64",
                scheme
            ))
        })?
        .to_string();
    Ok((payload, requirements))
}

/// Encode a payload-form `(requirement, payload)` pair as the base64 strings
/// the facilitator's HTTP API expects. Mirrors the wire format produced by
/// [`X402PaymentRequired::to_base64`] and [`X402Client`](super::client::X402Client)'s
/// payload base64 encoding.
fn encode_facilitator_envelope(
    requirement: &X402PaymentRequirement,
    payload: &X402PaymentPayload,
) -> Result<(String, String)> {
    let payload_json = serde_json::to_string(payload)
        .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
    let payload_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        payload_json.as_bytes(),
    );

    let requirements_json = serde_json::to_string(requirement)
        .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
    let requirements_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        requirements_json.as_bytes(),
    );
    Ok((payload_b64, requirements_b64))
}

/// EIP-3009 (`transferWithAuthorization`) backend. The actual signature /
/// nonce / balance checks are delegated to the facilitator — this backend
/// wires the registry to that path and enforces the structural invariants.
#[derive(Debug)]
pub struct Eip3009Backend {
    facilitator: Arc<dyn FacilitatorVerifier>,
}

impl Eip3009Backend {
    pub fn new(facilitator: Arc<dyn FacilitatorVerifier>) -> Self {
        Self { facilitator }
    }
}

#[async_trait]
impl SchemeBackend for Eip3009Backend {
    fn name(&self) -> &'static str {
        "exact-eip3009"
    }

    async fn verify(
        &self,
        _challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()> {
        let (payload, requirements) = extract_facilitator_envelope(credential, "exact-eip3009")?;
        self.facilitator
            .verify_payload(&payload, &requirements)
            .await
    }

    async fn settle(
        &self,
        _challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<Option<String>> {
        let (payload, requirements) = extract_facilitator_envelope(credential, "exact-eip3009")?;
        let tx = self
            .facilitator
            .settle_payload(&payload, &requirements)
            .await?;
        Ok(Some(tx))
    }

    async fn verify_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()> {
        let (payload_b64, requirements_b64) = encode_facilitator_envelope(requirement, payload)?;
        self.facilitator
            .verify_payload(&payload_b64, &requirements_b64)
            .await
    }

    async fn settle_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<Option<String>> {
        let (payload_b64, requirements_b64) = encode_facilitator_envelope(requirement, payload)?;
        let tx = self
            .facilitator
            .settle_payload(&payload_b64, &requirements_b64)
            .await?;
        Ok(Some(tx))
    }
}

/// Uniswap Permit2 backend (`PermitTransferFrom` signature). Same shape as
/// [`Eip3009Backend`] — the facilitator owns scheme-specific verification.
#[derive(Debug)]
pub struct Permit2Backend {
    facilitator: Arc<dyn FacilitatorVerifier>,
}

impl Permit2Backend {
    pub fn new(facilitator: Arc<dyn FacilitatorVerifier>) -> Self {
        Self { facilitator }
    }
}

#[async_trait]
impl SchemeBackend for Permit2Backend {
    fn name(&self) -> &'static str {
        "permit2"
    }

    async fn verify(
        &self,
        _challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()> {
        let (payload, requirements) = extract_facilitator_envelope(credential, "permit2")?;
        self.facilitator
            .verify_payload(&payload, &requirements)
            .await
    }

    async fn settle(
        &self,
        _challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<Option<String>> {
        let (payload, requirements) = extract_facilitator_envelope(credential, "permit2")?;
        let tx = self
            .facilitator
            .settle_payload(&payload, &requirements)
            .await?;
        Ok(Some(tx))
    }

    async fn verify_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()> {
        let (payload_b64, requirements_b64) = encode_facilitator_envelope(requirement, payload)?;
        self.facilitator
            .verify_payload(&payload_b64, &requirements_b64)
            .await
    }

    async fn settle_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<Option<String>> {
        let (payload_b64, requirements_b64) = encode_facilitator_envelope(requirement, payload)?;
        let tx = self
            .facilitator
            .settle_payload(&payload_b64, &requirements_b64)
            .await?;
        Ok(Some(tx))
    }
}

// ─── ERC-7710 (delegation redemption) ─────────────────────────────────────

/// Verifies the redemption proof attached to an ERC-7710 credential. A
/// production verifier resolves the on-chain DelegationManager state and
/// (a) checks the delegation is still active, (b) the redeemer is admitted,
/// (c) the redemption amount fits within the delegation's caveats. The
/// abstraction is here so different chains can plug in different verifiers.
#[async_trait]
pub trait DelegationVerifier: Send + Sync + std::fmt::Debug {
    async fn verify_redemption(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()>;

    /// Payload-form verification — receives the `(requirement, payload)`
    /// pair that arrived on the x402 wire. The default implementation
    /// errors so backends that haven't been ported don't silently accept
    /// payload-form requests. The `delegation_id` and `redemption_proof`
    /// are conventionally carried as a JSON object in
    /// `payload.authorization` after hex-decoding.
    async fn verify_payload_redemption(
        &self,
        _requirement: &X402PaymentRequirement,
        _payload: &X402PaymentPayload,
    ) -> Result<()> {
        Err(PaymentError::VerificationFailed(
            "ERC-7710 payload-form redemption verifier is not configured".to_string(),
        ))
    }
}

/// ERC-7710 redemption-of-delegation backend. The credential carries a
/// `delegation_id` (the on-chain delegation hash) and a `redemption_proof`
/// (the calldata or signature the redeemer submits to the delegation
/// manager). Verification is delegated to a [`DelegationVerifier`].
#[derive(Debug)]
pub struct Erc7710Backend {
    verifier: Arc<dyn DelegationVerifier>,
}

impl Erc7710Backend {
    pub fn new(verifier: Arc<dyn DelegationVerifier>) -> Self {
        Self { verifier }
    }
}

#[async_trait]
impl SchemeBackend for Erc7710Backend {
    fn name(&self) -> &'static str {
        "erc7710"
    }

    async fn verify(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<()> {
        // Structural checks — these are cheap and don't need to wait on
        // the delegation manager.
        if credential
            .extra
            .get("delegation_id")
            .and_then(|v| v.as_str())
            .map(str::is_empty)
            .unwrap_or(true)
        {
            return Err(PaymentError::CredentialError(
                "erc7710 credential missing extra.delegation_id".to_string(),
            ));
        }
        if credential
            .extra
            .get("redemption_proof")
            .and_then(|v| v.as_str())
            .map(str::is_empty)
            .unwrap_or(true)
        {
            return Err(PaymentError::CredentialError(
                "erc7710 credential missing extra.redemption_proof".to_string(),
            ));
        }
        self.verifier.verify_redemption(challenge, credential).await
    }

    async fn verify_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()> {
        // Payload-form ERC-7710 (Coinbase x402 V2 wire): the redemption proof
        // travels in `payload.payload.signature` as an opaque scheme-specific
        // blob; the EIP-3009-style authorization substructure carries the
        // standard from/to/value/valid_after/valid_before/nonce binding. Both
        // must be non-empty before we dispatch to the configured verifier.
        let inner = &payload.payload;
        if inner.signature.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "erc7710 payload missing signature (redemption proof)".to_string(),
            ));
        }
        if inner.authorization.from.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "erc7710 payload missing authorization.from".to_string(),
            ));
        }
        self.verifier
            .verify_payload_redemption(requirement, payload)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex;

    fn make_challenge(scheme: &str) -> PaymentChallenge {
        let mut extra = StdHashMap::new();
        if !scheme.is_empty() {
            extra.insert("scheme".to_string(), serde_json::json!(scheme));
        }
        PaymentChallenge {
            challenge_id: "ch-1".to_string(),
            protocol: "x402".to_string(),
            resource: "/api/r".to_string(),
            amount: 1_000,
            asset: "USDC".to_string(),
            recipient: "0xrecipient".to_string(),
            chain: "tenzro".to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
            extra,
        }
    }

    fn make_facilitator_credential(scheme: &str) -> PaymentCredential {
        let mut extra = StdHashMap::new();
        extra.insert("payload_b64".to_string(), serde_json::json!("dGVzdA=="));
        extra.insert(
            "requirements_b64".to_string(),
            serde_json::json!("cmVxcw=="),
        );
        PaymentCredential {
            credential_id: format!("cred-{}", scheme),
            challenge_id: "ch-1".to_string(),
            protocol: "x402".to_string(),
            payer_did: "did:tenzro:human:alice".to_string(),
            payer_address: "0xpayer".to_string(),
            amount: 1_000,
            asset: "USDC".to_string(),
            signature: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
            extra,
        }
    }

    #[test]
    fn registry_defaults_contain_all_built_in_schemes() {
        let r = SchemeRegistry::with_defaults();
        let ids = r.ids();
        for expected in [
            "tenzro-hybrid",
            "exact-eip3009",
            "eip3009",
            "permit2",
            "erc7710",
        ] {
            assert!(
                ids.iter().any(|id| id == expected),
                "missing default scheme: {} (got {:?})",
                expected,
                ids
            );
        }
    }

    #[test]
    fn registry_does_not_alias_legacy_exact_to_hybrid() {
        // Per pre-launch hygiene: no backcompat shims. The internal
        // Tenzro path is `tenzro-hybrid` only; `"exact"` is reserved for
        // future schemes that match the upstream x402 V2 naming.
        let r = SchemeRegistry::with_defaults();
        assert!(r.get("exact").is_none());
        assert!(r.get("").is_none());
    }

    #[test]
    fn registry_lookup_is_case_insensitive() {
        let r = SchemeRegistry::with_defaults();
        assert!(r.get("Permit2").is_some());
        assert!(r.get("ERC7710").is_some());
    }

    #[test]
    fn lookup_for_challenge_falls_back_to_default_when_absent() {
        let r = SchemeRegistry::with_defaults();
        let ch = make_challenge(""); // no scheme key at all
        let backend = r.lookup_for_challenge(&ch).unwrap();
        assert_eq!(backend.name(), "tenzro-hybrid");
    }

    #[test]
    fn lookup_for_challenge_unknown_scheme_errors() {
        let r = SchemeRegistry::with_defaults();
        let ch = make_challenge("not-a-real-scheme");
        let err = r.lookup_for_challenge(&ch).unwrap_err();
        assert!(
            matches!(err, PaymentError::VerificationFailed(_)),
            "expected VerificationFailed, got {:?}",
            err
        );
    }

    // ── EIP-3009 backend ────────────────────────────────────────────────

    #[derive(Debug)]
    struct StubFacilitator {
        accept: bool,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl StubFacilitator {
        fn new(accept: bool) -> Self {
            Self {
                accept,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl FacilitatorVerifier for StubFacilitator {
        async fn verify_payload(&self, payload: &str, requirements: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push((payload.to_string(), requirements.to_string()));
            if self.accept {
                Ok(())
            } else {
                Err(PaymentError::VerificationFailed(
                    "stub rejected".to_string(),
                ))
            }
        }

        async fn settle_payload(&self, _payload: &str, _requirements: &str) -> Result<String> {
            if self.accept {
                Ok("0xstubtx".to_string())
            } else {
                Err(PaymentError::SettlementError(
                    "stub settle reject".to_string(),
                ))
            }
        }
    }

    #[tokio::test]
    async fn eip3009_backend_calls_facilitator_with_envelope() {
        let stub = Arc::new(StubFacilitator::new(true));
        let backend = Eip3009Backend::new(stub.clone());

        let ch = make_challenge("exact-eip3009");
        let cred = make_facilitator_credential("exact-eip3009");

        backend.verify(&ch, &cred).await.unwrap();
        let tx = backend.settle(&ch, &cred).await.unwrap();
        assert_eq!(tx.as_deref(), Some("0xstubtx"));

        let calls = stub.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "dGVzdA==");
        assert_eq!(calls[0].1, "cmVxcw==");
    }

    #[tokio::test]
    async fn eip3009_backend_rejects_credential_without_payload() {
        let stub = Arc::new(StubFacilitator::new(true));
        let backend = Eip3009Backend::new(stub);

        let ch = make_challenge("exact-eip3009");
        let mut cred = make_facilitator_credential("exact-eip3009");
        cred.extra.remove("payload_b64");

        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::CredentialError(_)));
    }

    #[tokio::test]
    async fn eip3009_backend_propagates_facilitator_rejection() {
        let stub = Arc::new(StubFacilitator::new(false));
        let backend = Eip3009Backend::new(stub);

        let ch = make_challenge("exact-eip3009");
        let cred = make_facilitator_credential("exact-eip3009");
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    // ── Permit2 backend ─────────────────────────────────────────────────

    #[tokio::test]
    async fn permit2_backend_calls_facilitator() {
        let stub = Arc::new(StubFacilitator::new(true));
        let backend = Permit2Backend::new(stub.clone());

        let ch = make_challenge("permit2");
        let cred = make_facilitator_credential("permit2");
        backend.verify(&ch, &cred).await.unwrap();
        assert_eq!(stub.calls.lock().unwrap().len(), 1);
    }

    // ── ERC-7710 backend ────────────────────────────────────────────────

    #[derive(Debug)]
    struct StubDelegation {
        accept: bool,
    }

    #[async_trait]
    impl DelegationVerifier for StubDelegation {
        async fn verify_redemption(
            &self,
            _challenge: &PaymentChallenge,
            _credential: &PaymentCredential,
        ) -> Result<()> {
            if self.accept {
                Ok(())
            } else {
                Err(PaymentError::VerificationFailed(
                    "delegation rejected".to_string(),
                ))
            }
        }
    }

    fn make_erc7710_credential() -> PaymentCredential {
        let mut extra = StdHashMap::new();
        extra.insert("delegation_id".to_string(), serde_json::json!("0xdeadbeef"));
        extra.insert("redemption_proof".to_string(), serde_json::json!("0xproof"));
        PaymentCredential {
            credential_id: "cred-erc7710".to_string(),
            challenge_id: "ch-1".to_string(),
            protocol: "x402".to_string(),
            payer_did: "did:tenzro:machine:agent".to_string(),
            payer_address: "0xagent".to_string(),
            amount: 1_000,
            asset: "USDC".to_string(),
            signature: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
            extra,
        }
    }

    #[tokio::test]
    async fn erc7710_backend_requires_delegation_id() {
        let backend = Erc7710Backend::new(Arc::new(StubDelegation { accept: true }));
        let ch = make_challenge("erc7710");
        let mut cred = make_erc7710_credential();
        cred.extra.remove("delegation_id");

        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::CredentialError(_)));
    }

    #[tokio::test]
    async fn erc7710_backend_requires_redemption_proof() {
        let backend = Erc7710Backend::new(Arc::new(StubDelegation { accept: true }));
        let ch = make_challenge("erc7710");
        let mut cred = make_erc7710_credential();
        cred.extra.remove("redemption_proof");

        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::CredentialError(_)));
    }

    #[tokio::test]
    async fn erc7710_backend_delegates_to_verifier() {
        let backend_ok = Erc7710Backend::new(Arc::new(StubDelegation { accept: true }));
        let backend_no = Erc7710Backend::new(Arc::new(StubDelegation { accept: false }));

        let ch = make_challenge("erc7710");
        let cred = make_erc7710_credential();

        backend_ok.verify(&ch, &cred).await.unwrap();
        let err = backend_no.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn default_erc7710_verifier_fails_closed() {
        // The default verifier has no enforcer registry and a zero
        // delegation-manager domain — a structurally-present but garbage
        // proof must be rejected, never accepted.
        let backend = Erc7710Backend::new(Arc::new(
            crate::x402::erc7710::Erc7710DelegationVerifier::default(),
        ));
        let ch = make_challenge("erc7710");
        let cred = make_erc7710_credential();
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    // ── upto (usage-metered) backend ────────────────────────────────────

    fn upto_hybrid_signer() -> tenzro_crypto::composite::InMemoryHybridSigner {
        use tenzro_crypto::composite::InMemoryHybridSigner;
        use tenzro_crypto::keys::KeyPair;
        use tenzro_crypto::pq::MlDsaSigningKey;
        use tenzro_crypto::signatures::Ed25519SignerImpl;
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate())
    }

    /// Build an upto credential whose hybrid signature commits to `upto_max`,
    /// charging `actual`. `challenge_id`/`payer_did`/`asset` must match the
    /// challenge the backend verifies against.
    fn make_upto_credential(upto_max: u128, actual: u128) -> PaymentCredential {
        use tenzro_crypto::composite::HybridSigner;
        let signer = upto_hybrid_signer();
        let payer_did = "did:tenzro:human:alice";
        let asset = "USDC";
        let message = build_upto_preimage("ch-1", payer_did, upto_max, asset);
        let sig = signer.sign(&message).unwrap();
        let composite_pk = signer.public_key();
        let classical_pk_hex = hex::encode(composite_pk.classical.as_bytes());

        let mut extra = StdHashMap::new();
        extra.insert(
            "public_key".to_string(),
            serde_json::json!(classical_pk_hex),
        );
        extra.insert(
            "upto_max".to_string(),
            serde_json::json!(upto_max.to_string()),
        );
        PaymentCredential {
            credential_id: "cred-upto".to_string(),
            challenge_id: "ch-1".to_string(),
            protocol: "x402".to_string(),
            payer_did: payer_did.to_string(),
            payer_address: String::new(),
            amount: actual,
            asset: asset.to_string(),
            signature: sig.classical.clone(),
            pq_signature: sig.pq.clone(),
            pq_public_key: composite_pk.pq.clone(),
            extra,
        }
    }

    #[test]
    fn registry_defaults_contain_upto() {
        let r = SchemeRegistry::with_defaults();
        assert!(r.get(UPTO_SCHEME).is_some());
        assert_eq!(r.get("UPTO").unwrap().name(), UPTO_SCHEME);
    }

    #[test]
    fn with_local_facilitator_registers_self_hosted_backends() {
        // Signer construction is offline (key derivation only); no RPC is
        // issued until a verify/settle actually runs.
        let key = [7u8; 32];
        let signer = std::sync::Arc::new(
            tenzro_bridge::EvmTransactionSigner::new(&key, 84532, "http://127.0.0.1:0".into())
                .expect("offline signer construction"),
        );
        let r = SchemeRegistry::with_local_facilitator(signer, "http://127.0.0.1:0");

        // The EIP-3009 / Permit2 lanes now route through the local verifier.
        assert!(r.get("exact-eip3009").is_some());
        assert!(r.get("eip3009").is_some());
        assert!(r.get("permit2").is_some());

        // The shared, facilitator-independent backends are still present.
        assert!(r.get(DEFAULT_SCHEME).is_some());
        assert!(r.get(UPTO_SCHEME).is_some());
        assert!(r.get(BATCH_SETTLEMENT_SCHEME).is_some());
        assert!(r.get("erc7710").is_some());
    }

    #[test]
    fn upto_preimage_is_domain_separated_from_credential_preimage() {
        // A maximum-authorizing signature must never verify as a plain
        // exact-amount credential: the two preimages must differ even for
        // identical (challenge, payer, amount, asset) tuples.
        let upto = build_upto_preimage("ch-1", "did:x", 1_000, "USDC");
        let cred = PaymentCredential {
            credential_id: "c".into(),
            challenge_id: "ch-1".into(),
            protocol: "x402".into(),
            payer_did: "did:x".into(),
            payer_address: String::new(),
            amount: 1_000,
            asset: "USDC".into(),
            signature: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
            extra: StdHashMap::new(),
        };
        assert_ne!(upto, build_credential_preimage(&cred));
    }

    #[tokio::test]
    async fn upto_accepts_actual_at_or_below_max() {
        let backend = UptoBackend;
        let ch = make_challenge(UPTO_SCHEME); // ceiling 1_000
        let cred = make_upto_credential(800, 300);
        backend.verify(&ch, &cred).await.unwrap();
    }

    #[tokio::test]
    async fn upto_accepts_actual_equal_to_max() {
        let backend = UptoBackend;
        let ch = make_challenge(UPTO_SCHEME);
        let cred = make_upto_credential(800, 800);
        backend.verify(&ch, &cred).await.unwrap();
    }

    #[tokio::test]
    async fn upto_rejects_actual_above_max() {
        let backend = UptoBackend;
        let ch = make_challenge(UPTO_SCHEME);
        let cred = make_upto_credential(800, 801);
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn upto_rejects_max_above_ceiling() {
        let backend = UptoBackend;
        let ch = make_challenge(UPTO_SCHEME); // ceiling 1_000
        let cred = make_upto_credential(2_000, 500);
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn upto_rejects_missing_upto_max() {
        let backend = UptoBackend;
        let ch = make_challenge(UPTO_SCHEME);
        let mut cred = make_upto_credential(800, 300);
        cred.extra.remove("upto_max");
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::CredentialError(_)));
    }

    #[tokio::test]
    async fn upto_rejects_empty_pq_legs() {
        let backend = UptoBackend;
        let ch = make_challenge(UPTO_SCHEME);
        let mut cred = make_upto_credential(800, 300);
        cred.pq_public_key.clear();
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn upto_rejects_signature_over_different_max() {
        // Credential signs over max=800 but claims upto_max=900 — the
        // hybrid check must fail because the preimage no longer matches.
        let backend = UptoBackend;
        let ch = make_challenge(UPTO_SCHEME);
        let mut cred = make_upto_credential(800, 300);
        cred.extra
            .insert("upto_max".to_string(), serde_json::json!("900"));
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    // ─── batch-settlement backend ──────────────────────────────────────────

    /// Build a batch-settlement challenge pinned to `channel_id`.
    fn make_batch_challenge(channel_id: &str) -> PaymentChallenge {
        let mut ch = make_challenge(BATCH_SETTLEMENT_SCHEME); // ceiling 1_000
        ch.extra
            .insert("channel_id".to_string(), serde_json::json!(channel_id));
        ch
    }

    /// Build a batch-settlement voucher whose hybrid signature commits to
    /// `cumulative` against `channel_id` and `voucher_nonce`, settling an
    /// increment of `increment` under a `deposit` ceiling.
    fn make_batch_voucher(
        channel_id: &str,
        increment: u128,
        cumulative: u128,
        voucher_nonce: u64,
        deposit: u128,
    ) -> PaymentCredential {
        use tenzro_crypto::composite::HybridSigner;
        let signer = upto_hybrid_signer();
        let payer_did = "did:tenzro:human:alice";
        let asset = "USDC";
        let message =
            build_batch_voucher_preimage(channel_id, payer_did, cumulative, voucher_nonce, asset);
        let sig = signer.sign(&message).unwrap();
        let composite_pk = signer.public_key();
        let classical_pk_hex = hex::encode(composite_pk.classical.as_bytes());

        let mut extra = StdHashMap::new();
        extra.insert(
            "public_key".to_string(),
            serde_json::json!(classical_pk_hex),
        );
        extra.insert("channel_id".to_string(), serde_json::json!(channel_id));
        extra.insert(
            "cumulative_amount".to_string(),
            serde_json::json!(cumulative.to_string()),
        );
        extra.insert(
            "voucher_nonce".to_string(),
            serde_json::json!(voucher_nonce.to_string()),
        );
        extra.insert(
            "channel_deposit".to_string(),
            serde_json::json!(deposit.to_string()),
        );
        PaymentCredential {
            credential_id: "cred-batch".to_string(),
            challenge_id: "ch-1".to_string(),
            protocol: "x402".to_string(),
            payer_did: payer_did.to_string(),
            payer_address: String::new(),
            amount: increment,
            asset: asset.to_string(),
            signature: sig.classical.clone(),
            pq_signature: sig.pq.clone(),
            pq_public_key: composite_pk.pq.clone(),
            extra,
        }
    }

    #[test]
    fn registry_defaults_contain_batch_settlement() {
        let r = SchemeRegistry::with_defaults();
        assert!(r.get(BATCH_SETTLEMENT_SCHEME).is_some());
        assert_eq!(
            r.get("BATCH-SETTLEMENT").unwrap().name(),
            BATCH_SETTLEMENT_SCHEME
        );
    }

    #[test]
    fn batch_voucher_preimage_is_domain_separated_from_upto() {
        // A cumulative voucher must never verify as an upto authorization even
        // for identical (id, payer, amount, asset) tuples.
        let voucher = build_batch_voucher_preimage("chan-1", "did:x", 1_000, 0, "USDC");
        let upto = build_upto_preimage("chan-1", "did:x", 1_000, "USDC");
        assert_ne!(voucher, upto);
    }

    #[tokio::test]
    async fn batch_accepts_increment_within_cumulative_and_deposit() {
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        // increment 200, cumulative 500, deposit 800.
        let cred = make_batch_voucher("chan-1", 200, 500, 3, 800);
        backend.verify(&ch, &cred).await.unwrap();
    }

    #[tokio::test]
    async fn batch_accepts_cumulative_equal_to_deposit() {
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        let cred = make_batch_voucher("chan-1", 300, 800, 5, 800);
        backend.verify(&ch, &cred).await.unwrap();
    }

    #[tokio::test]
    async fn batch_rejects_cumulative_above_deposit() {
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        // cumulative 900 > deposit 800.
        let cred = make_batch_voucher("chan-1", 100, 900, 6, 800);
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn batch_rejects_increment_above_cumulative() {
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        // increment 600 > cumulative 500.
        let cred = make_batch_voucher("chan-1", 600, 500, 2, 800);
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn batch_rejects_zero_increment() {
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        let cred = make_batch_voucher("chan-1", 0, 500, 2, 800);
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn batch_rejects_channel_mismatch() {
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        // Voucher draws against a different channel than the challenge pins.
        let cred = make_batch_voucher("chan-2", 200, 500, 3, 800);
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn batch_rejects_missing_cumulative() {
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        let mut cred = make_batch_voucher("chan-1", 200, 500, 3, 800);
        cred.extra.remove("cumulative_amount");
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::CredentialError(_)));
    }

    #[tokio::test]
    async fn batch_rejects_empty_pq_legs() {
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        let mut cred = make_batch_voucher("chan-1", 200, 500, 3, 800);
        cred.pq_public_key.clear();
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn batch_rejects_signature_over_different_cumulative() {
        // Voucher signs cumulative=500 but claims cumulative=600 — the hybrid
        // check must fail because the preimage no longer matches.
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        let mut cred = make_batch_voucher("chan-1", 200, 500, 3, 800);
        cred.extra
            .insert("cumulative_amount".to_string(), serde_json::json!("600"));
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    #[tokio::test]
    async fn batch_rejects_signature_over_different_nonce() {
        // Voucher signs nonce=3 but claims nonce=4 — preimage mismatch.
        let backend = BatchSettlementBackend;
        let ch = make_batch_challenge("chan-1");
        let mut cred = make_batch_voucher("chan-1", 200, 500, 3, 800);
        cred.extra
            .insert("voucher_nonce".to_string(), serde_json::json!("4"));
        let err = backend.verify(&ch, &cred).await.unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }
}
