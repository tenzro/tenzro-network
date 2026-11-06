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
//! actual. The buyer's signature covers the ceiling. When the seller named a
//! meter key on the challenge, the charge must also carry a usage record
//! that meter signed ([`crate::metering`]), so the charge is exactly what the
//! seller's meter attests; without one, the seller may charge up to the
//! ceiling.
//!
//! The [`SchemeRegistry`] looks up a [`SchemeBackend`] by id and delegates
//! credential verification to it. A credential names its scheme through the
//! challenge's `extra["scheme"]`; a facilitator payload through its
//! requirement's `scheme`.
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
//! `Erc7710Backend` delegates redemption proofs to a [`DelegationVerifier`];
//! it has no settlement leg, so a node cannot serve a resource against it.
//!
//! Tests inject mock backends via [`SchemeRegistry::register`] or replace the
//! whole registry via [`X402PaymentServer::with_scheme_registry`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use crate::error::{PaymentError, Result};
use crate::payer_auth::{EnrolledKeys, verify_payer};
use crate::types::{PaymentChallenge, PaymentCredential, SettlementLeg};
use crate::x402::coinbase::{CdpFacilitatorClient, FacilitatorRequest};
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::X402PaymentRequirement;
use crate::x402::wire;

/// Scheme identifier used when a challenge does not pin one explicitly.
pub const DEFAULT_SCHEME: &str = "tenzro-hybrid";

/// Usage-metered scheme: buyer signs a maximum, seller settles the actual.
pub const UPTO_SCHEME: &str = "upto";

/// Channel scheme: buyer deposits once, then signs cumulative off-chain
/// vouchers; the seller settles many vouchers with a single on-chain claim.
pub const BATCH_SETTLEMENT_SCHEME: &str = "batch-settlement";

/// One x402 scheme: how a payment under it is verified and, for a scheme
/// that settles on another chain, settled.
#[async_trait]
pub trait SchemeBackend: Send + Sync + std::fmt::Debug {
    /// Scheme id, as carried in `challenge.extra["scheme"]` and in the
    /// requirement's `scheme`.
    fn name(&self) -> &'static str;

    /// Verify `credential` against the challenge it answers, returning how
    /// the payment moves value. A refusal is an `Err`.
    async fn verify(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<SettlementLeg>;

    /// Settle a verified credential whose leg is
    /// [`SettlementLeg::Foreign`], returning its transaction on that chain.
    /// Tenzro schemes settle on a gateway rail instead and return `None`.
    async fn settle(
        &self,
        _challenge: &PaymentChallenge,
        _credential: &PaymentCredential,
    ) -> Result<Option<String>> {
        Ok(None)
    }

    /// Verify a wire payload against a requirement, for the facilitator's
    /// `POST /verify`. Tenzro schemes are verified by the facilitator itself,
    /// so the default refuses.
    async fn verify_payload(
        &self,
        _requirement: &X402PaymentRequirement,
        _payload: &X402PaymentPayload,
    ) -> Result<()> {
        Err(PaymentError::VerificationFailed(format!(
            "scheme '{}' has no payload verification",
            self.name()
        )))
    }

    /// Settle a wire payload on its chain, for the facilitator's
    /// `POST /settle`. The default refuses.
    async fn settle_payload(
        &self,
        _requirement: &X402PaymentRequirement,
        _payload: &X402PaymentPayload,
    ) -> Result<String> {
        Err(PaymentError::SettlementError(format!(
            "scheme '{}' has no payload settlement",
            self.name()
        )))
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

    /// Build a registry pre-populated with the built-in backends that need
    /// nothing outside Tenzro. EIP-3009 and Permit2 are added only by
    /// [`Self::with_local_facilitator`] and [`Self::with_local_relayer`], over
    /// the operator's own EVM RPC: no hosted facilitator is consulted.
    pub fn with_defaults(keys: Arc<dyn EnrolledKeys>) -> Self {
        let mut r = Self::empty();
        let hybrid: Arc<dyn SchemeBackend> = Arc::new(TenzroHybridBackend::new(keys.clone()));
        r.register(DEFAULT_SCHEME, hybrid);

        let upto: Arc<dyn SchemeBackend> = Arc::new(UptoBackend::new(keys.clone()));
        r.register(UPTO_SCHEME, upto);

        let batch: Arc<dyn SchemeBackend> = Arc::new(BatchSettlementBackend::new(keys));
        r.register(BATCH_SETTLEMENT_SCHEME, batch);

        let erc7710: Arc<dyn SchemeBackend> = Arc::new(Erc7710Backend::new(Arc::new(
            crate::x402::erc7710::Erc7710DelegationVerifier::default(),
        )));
        r.register("erc7710", erc7710);

        r
    }

    /// Build the default registry but verify the EIP-3009 and Permit2 schemes
    /// locally with a [`LocalFacilitatorVerifier`] over the operator's own
    /// EVM RPC. Settlement broadcasts through the facilitator at
    /// `settlement_facilitator_url` and is confirmed on `rpc_url`.
    ///
    /// [`LocalFacilitatorVerifier`]: crate::x402::local_facilitator::LocalFacilitatorVerifier
    pub fn with_local_facilitator(
        keys: Arc<dyn EnrolledKeys>,
        rpc_url: impl Into<String>,
        settlement_facilitator_url: impl Into<String>,
    ) -> Self {
        let settle_via: Arc<dyn FacilitatorVerifier> =
            Arc::new(CdpFacilitatorVerifier::with_client(
                CdpFacilitatorClient::new(settlement_facilitator_url),
            ));
        Self::with_local_verifier(
            keys,
            Arc::new(
                crate::x402::local_facilitator::LocalFacilitatorVerifier::new(rpc_url, settle_via),
            ),
        )
    }

    /// Like [`Self::with_local_facilitator`], but the operator's relayer,
    /// whose key is on a hardware signing device, broadcasts settlements.
    pub fn with_local_relayer(
        keys: Arc<dyn EnrolledKeys>,
        relayer: Arc<tenzro_bridge::EvmTransactionSigner>,
        rpc_url: impl Into<String>,
    ) -> Self {
        Self::with_local_verifier(
            keys,
            Arc::new(
                crate::x402::local_facilitator::LocalFacilitatorVerifier::with_relayer(
                    rpc_url, relayer,
                ),
            ),
        )
    }

    fn with_local_verifier(
        keys: Arc<dyn EnrolledKeys>,
        local: Arc<dyn FacilitatorVerifier>,
    ) -> Self {
        let mut r = Self::with_defaults(keys);
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
    /// The backend for the scheme `credential` was signed under: the one it
    /// names, when the challenge offered it, or else the challenge's own.
    pub fn lookup_for_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &crate::types::PaymentCredential,
    ) -> Result<Arc<dyn SchemeBackend>> {
        let chosen = credential.extra.get("scheme").and_then(|v| v.as_str());
        match chosen {
            Some(s)
                if crate::x402::wire::offered_schemes(challenge)
                    .iter()
                    .any(|o| o == s) =>
            {
                self.get(s).ok_or_else(|| {
                    PaymentError::VerificationFailed(format!(
                        "No x402 scheme backend registered for id '{s}'"
                    ))
                })
            }
            Some(s) => Err(PaymentError::VerificationFailed(format!(
                "the credential answers under '{s}', which challenge {} does not offer",
                challenge.challenge_id
            ))),
            None => self.lookup_for_challenge(challenge),
        }
    }

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

// ─── Tenzro hybrid backend (default) ──────────────────────────────────────

/// Internal Tenzro x402 scheme: Ed25519 + ML-DSA-65 hybrid signature over the
/// canonical payment authorization
/// ([`tenzro_types::payment_authorization::payment_authorization_preimage`]),
/// which binds chain, challenge, payer, payee, amount and asset. The payer is
/// the account the signing key controls.
pub struct TenzroHybridBackend {
    keys: Arc<dyn EnrolledKeys>,
}

impl TenzroHybridBackend {
    /// A backend verifying payers against the keys their accounts enrolled.
    pub fn new(keys: Arc<dyn EnrolledKeys>) -> Self {
        Self { keys }
    }
}

impl std::fmt::Debug for TenzroHybridBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenzroHybridBackend")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SchemeBackend for TenzroHybridBackend {
    fn name(&self) -> &'static str {
        "tenzro-hybrid"
    }

    async fn verify(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<SettlementLeg> {
        if credential
            .extra
            .contains_key(crate::payer_auth::UPTO_MAX_KEY)
        {
            return Err(PaymentError::VerificationFailed(
                "an exact-amount scheme does not accept a metered ceiling".to_string(),
            ));
        }
        if credential.amount != challenge.amount {
            return Err(PaymentError::VerificationFailed(format!(
                "Amount mismatch: expected {}, got {}",
                challenge.amount, credential.amount
            )));
        }
        let payer = verify_payer(self.keys.as_ref(), challenge, credential)?;
        debug!(
            "tenzro-hybrid verified credential {} for challenge {}",
            credential.credential_id, challenge.challenge_id
        );
        Ok(SettlementLeg::Payer(payer))
    }
}

// ─── Upto (usage-metered) backend ─────────────────────────────────────────

/// Usage-metered x402 backend. The buyer signs a **maximum** (`upto_max`) in
/// the same canonical payment authorization; the charge is chosen at capture
/// time and must not exceed it. A metered credential carries the ceiling
/// under `extra["upto_max"]`, and `credential.amount` is the charge.
pub struct UptoBackend {
    keys: Arc<dyn EnrolledKeys>,
}

impl UptoBackend {
    /// A backend verifying payers against the keys their accounts enrolled.
    pub fn new(keys: Arc<dyn EnrolledKeys>) -> Self {
        Self { keys }
    }
}

impl std::fmt::Debug for UptoBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UptoBackend").finish_non_exhaustive()
    }
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
    ) -> Result<SettlementLeg> {
        if !credential
            .extra
            .contains_key(crate::payer_auth::UPTO_MAX_KEY)
        {
            return Err(PaymentError::CredentialError(
                "upto credential is missing extra.upto_max (decimal string)".to_string(),
            ));
        }
        let payer = verify_payer(self.keys.as_ref(), challenge, credential)?;
        // A seller that named a meter key at mint time charges only what its
        // meter signed for.
        if challenge.extra.contains_key(crate::metering::METER_KEY) {
            use crate::metering::MeterRecord as _;
            let record = crate::metering::usage_record(credential)?.ok_or_else(|| {
                PaymentError::VerificationFailed(
                    "this metered challenge charges only against a signed usage record".to_string(),
                )
            })?;
            record.verify(
                self.keys.as_ref(),
                challenge,
                &hex::encode(&payer.address.as_bytes()[..20]),
                payer.authorization.max_amount,
                credential.amount,
            )?;
        }
        debug!(
            "upto verified credential {} (charge {} of ceiling {}) for challenge {}",
            credential.credential_id,
            credential.amount,
            payer.authorization.max_amount,
            challenge.challenge_id
        );
        Ok(SettlementLeg::Payer(payer))
    }
}

// ─── Batch-settlement (escrow voucher) backend ────────────────────────────

/// Escrow-voucher x402 backend. The buyer funds an escrow on the Tenzro
/// Ledger once (a `CreateEscrow` transaction it signs), then pays each request
/// with a cumulative voucher against it; the seller claims the highest
/// voucher on-chain whenever it chooses. Used for high-frequency per-request
/// billing where a settlement per request would dominate the cost.
///
/// # Credential layout
///
/// - `credential.amount` — this request's charge (the voucher's advance).
/// - `credential.extra["escrow_id"]` — hex of the escrow the voucher draws on.
///   Must equal the challenge's `extra["escrow_id"]` when the challenge pins one.
/// - `credential.extra["cumulative_amount"]` — the running total, decimal.
/// - `credential.extra["public_key"]` — the payer's Ed25519 key.
/// - `credential.signature` — Ed25519 over
///   [`tenzro_types::payment_authorization::escrow_voucher_preimage`].
pub struct BatchSettlementBackend {
    keys: Arc<dyn EnrolledKeys>,
}

impl BatchSettlementBackend {
    /// A backend verifying payers against the keys their accounts enrolled.
    pub fn new(keys: Arc<dyn EnrolledKeys>) -> Self {
        Self { keys }
    }
}

impl std::fmt::Debug for BatchSettlementBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchSettlementBackend")
            .finish_non_exhaustive()
    }
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
    ) -> Result<SettlementLeg> {
        let voucher =
            crate::payer_auth::verify_escrow_voucher(self.keys.as_ref(), challenge, credential)?;
        if let Some(expected) = challenge.extra.get("escrow_id").and_then(|v| v.as_str())
            && expected.trim_start_matches("0x") != hex::encode(voucher.escrow_id)
        {
            return Err(PaymentError::VerificationFailed(format!(
                "voucher draws on escrow {} but the challenge pins {}",
                hex::encode(voucher.escrow_id),
                expected
            )));
        }
        debug!(
            "batch-settlement verified voucher {} (charge {}, cumulative {}) on escrow {}",
            credential.credential_id,
            credential.amount,
            voucher.cumulative_amount,
            hex::encode(voucher.escrow_id)
        );
        Ok(SettlementLeg::Voucher(voucher))
    }
}

// ─── Facilitator-backed schemes (EIP-3009 / Permit2) ──────────────────────

/// Verifies and settles an EVM payment payload: a remote x402 facilitator,
/// or [`LocalFacilitatorVerifier`](super::local_facilitator::LocalFacilitatorVerifier)
/// over the operator's own EVM RPC.
#[async_trait]
pub trait FacilitatorVerifier: Send + Sync + std::fmt::Debug {
    /// Accept or refuse `payload` against `requirement`. A refusal is an
    /// `Err(PaymentError::VerificationFailed)`.
    async fn verify(
        &self,
        payload: &X402PaymentPayload,
        requirement: &X402PaymentRequirement,
    ) -> Result<()>;

    /// Settle `payload`; returns the transaction hash on its chain.
    async fn settle(
        &self,
        payload: &X402PaymentPayload,
        requirement: &X402PaymentRequirement,
    ) -> Result<String>;
}

/// A facilitator reached over its HTTP API.
#[derive(Debug)]
pub struct CdpFacilitatorVerifier {
    client: CdpFacilitatorClient,
}

impl CdpFacilitatorVerifier {
    /// A facilitator the operator chose, reached through `client`.
    pub fn with_client(client: CdpFacilitatorClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl FacilitatorVerifier for CdpFacilitatorVerifier {
    async fn verify(
        &self,
        payload: &X402PaymentPayload,
        requirement: &X402PaymentRequirement,
    ) -> Result<()> {
        let resp = self
            .client
            .verify(&FacilitatorRequest::new(payload, requirement))
            .await?;
        if resp.is_valid {
            Ok(())
        } else {
            Err(PaymentError::VerificationFailed(
                resp.invalid_reason
                    .unwrap_or_else(|| "facilitator refused the payload".to_string()),
            ))
        }
    }

    async fn settle(
        &self,
        payload: &X402PaymentPayload,
        requirement: &X402PaymentRequirement,
    ) -> Result<String> {
        let resp = self
            .client
            .settle(&FacilitatorRequest::new(payload, requirement))
            .await?;
        if resp.success && !resp.transaction.is_empty() {
            Ok(resp.transaction)
        } else {
            Err(PaymentError::SettlementError(
                resp.error_reason
                    .unwrap_or_else(|| "facilitator did not settle the payload".to_string()),
            ))
        }
    }
}

/// Verify an EVM credential: its payload, against the requirement rebuilt
/// from the challenge.
async fn verify_evm_credential(
    facilitator: &dyn FacilitatorVerifier,
    challenge: &PaymentChallenge,
    credential: &PaymentCredential,
) -> Result<X402PaymentPayload> {
    let payload = wire::credential_payload(credential)?;
    let offered = wire::requirement_for(challenge);
    wire::check_accepted_matches(&payload, &offered)?;
    facilitator.verify(&payload, &offered).await?;
    Ok(payload)
}

/// EIP-3009 (`transferWithAuthorization`) backend. Signature, nonce and
/// balance checks belong to the facilitator.
#[derive(Debug)]
pub struct Eip3009Backend {
    facilitator: Arc<dyn FacilitatorVerifier>,
}

impl Eip3009Backend {
    /// A backend verifying through `facilitator`.
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
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<SettlementLeg> {
        verify_evm_credential(self.facilitator.as_ref(), challenge, credential).await?;
        Ok(SettlementLeg::Foreign)
    }

    async fn settle(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<Option<String>> {
        let payload = wire::credential_payload(credential)?;
        let tx = self
            .facilitator
            .settle(&payload, &wire::requirement_for(challenge))
            .await?;
        Ok(Some(tx))
    }

    async fn verify_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()> {
        self.facilitator.verify(payload, requirement).await
    }

    async fn settle_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<String> {
        self.facilitator.settle(payload, requirement).await
    }
}

/// Uniswap Permit2 backend (`PermitTransferFrom` signature). The facilitator
/// owns scheme-specific verification.
#[derive(Debug)]
pub struct Permit2Backend {
    facilitator: Arc<dyn FacilitatorVerifier>,
}

impl Permit2Backend {
    /// A backend verifying through `facilitator`.
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
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<SettlementLeg> {
        verify_evm_credential(self.facilitator.as_ref(), challenge, credential).await?;
        Ok(SettlementLeg::Foreign)
    }

    async fn settle(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<Option<String>> {
        let payload = wire::credential_payload(credential)?;
        let tx = self
            .facilitator
            .settle(&payload, &wire::requirement_for(challenge))
            .await?;
        Ok(Some(tx))
    }

    async fn verify_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()> {
        self.facilitator.verify(payload, requirement).await
    }

    async fn settle_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<String> {
        self.facilitator.settle(payload, requirement).await
    }
}

// ─── ERC-7710 (delegation redemption) ─────────────────────────────────────

/// Verifies the redemption proof of an ERC-7710 payment. A verifier resolves
/// the delegation chain and checks that the delegation authorizes this
/// redemption: the redeemer is admitted and the amount fits its caveats.
#[async_trait]
pub trait DelegationVerifier: Send + Sync + std::fmt::Debug {
    /// Verify a wire payload whose signature is the encoded redemption proof,
    /// bound to its authorization nonce.
    async fn verify_payload_redemption(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()>;
}

/// ERC-7710 redemption-of-delegation backend. Verification is delegated to a
/// [`DelegationVerifier`]; redemption happens on the delegator's chain, so
/// this backend has no settlement leg and a node cannot serve a resource
/// against it until one is attached.
#[derive(Debug)]
pub struct Erc7710Backend {
    verifier: Arc<dyn DelegationVerifier>,
}

impl Erc7710Backend {
    /// A backend verifying through `verifier`.
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
    ) -> Result<SettlementLeg> {
        let payload = wire::credential_payload(credential)?;
        let offered = wire::requirement_for(challenge);
        wire::check_accepted_matches(&payload, &offered)?;
        self.verify_payload(&offered, &payload).await?;
        Ok(SettlementLeg::Foreign)
    }

    async fn verify_payload(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> Result<()> {
        let exact = payload.exact_payload()?;
        if exact.signature.is_empty() {
            return Err(PaymentError::VerificationFailed(
                "erc7710 payload missing signature (redemption proof)".to_string(),
            ));
        }
        if exact.authorization.from.is_empty() {
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

    fn evm_challenge(scheme: &str) -> PaymentChallenge {
        let mut ch = make_challenge(scheme);
        ch.extra
            .insert("network".to_string(), serde_json::json!("eip155:8453"));
        ch
    }

    fn evm_payload(ch: &PaymentChallenge) -> X402PaymentPayload {
        use crate::x402::payment_payload::{ExactAuthorization, ExactSchemePayload};
        X402PaymentPayload::exact(
            wire::requirement_for(ch),
            &ExactSchemePayload {
                signature: "0x00".to_string(),
                authorization: ExactAuthorization {
                    from: "0xpayer".to_string(),
                    to: "0xrecipient".to_string(),
                    value: "1000".to_string(),
                    valid_after: 0,
                    valid_before: u64::MAX,
                    nonce: "0x01".to_string(),
                },
            },
        )
        .unwrap()
    }

    fn make_facilitator_credential(ch: &PaymentChallenge) -> PaymentCredential {
        wire::credential_from_payload(&evm_payload(ch)).unwrap()
    }

    #[test]
    fn registry_defaults_contain_all_built_in_schemes() {
        let r = SchemeRegistry::with_defaults(Arc::new(crate::test_support::SeedKeys));
        let ids = r.ids();
        for expected in ["tenzro-hybrid", "erc7710"] {
            assert!(
                ids.iter().any(|id| id == expected),
                "missing default scheme: {} (got {:?})",
                expected,
                ids
            );
        }
    }

    #[test]
    fn registry_does_not_alias_exact_to_hybrid() {
        // The internal Tenzro path is `tenzro-hybrid` only; `"exact"` is reserved for
        // future schemes that match the upstream x402 V2 naming.
        let r = SchemeRegistry::with_defaults(Arc::new(crate::test_support::SeedKeys));
        assert!(r.get("exact").is_none());
        assert!(r.get("").is_none());
    }

    #[test]
    fn registry_lookup_is_case_insensitive() {
        let r = SchemeRegistry::with_defaults(Arc::new(crate::test_support::SeedKeys));
        assert!(r.get("ERC7710").is_some());
        assert!(
            r.get("Permit2").is_none(),
            "EVM schemes need the operator's own EVM RPC"
        );
    }

    #[test]
    fn lookup_for_challenge_falls_back_to_default_when_absent() {
        let r = SchemeRegistry::with_defaults(Arc::new(crate::test_support::SeedKeys));
        let ch = make_challenge(""); // no scheme key at all
        let backend = r.lookup_for_challenge(&ch).unwrap();
        assert_eq!(backend.name(), "tenzro-hybrid");
    }

    #[test]
    fn lookup_for_challenge_unknown_scheme_errors() {
        let r = SchemeRegistry::with_defaults(Arc::new(crate::test_support::SeedKeys));
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
        calls: Mutex<Vec<X402PaymentRequirement>>,
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
        async fn verify(
            &self,
            _payload: &X402PaymentPayload,
            requirement: &X402PaymentRequirement,
        ) -> Result<()> {
            self.calls.lock().unwrap().push(requirement.clone());
            if self.accept {
                Ok(())
            } else {
                Err(PaymentError::VerificationFailed(
                    "stub rejected".to_string(),
                ))
            }
        }

        async fn settle(
            &self,
            _payload: &X402PaymentPayload,
            _requirement: &X402PaymentRequirement,
        ) -> Result<String> {
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
    async fn eip3009_verifies_against_the_challenge_not_the_echoed_option() {
        let stub = Arc::new(StubFacilitator::new(true));
        let backend = Eip3009Backend::new(stub.clone());
        let ch = evm_challenge("exact-eip3009");

        // The buyer rewrites the option it echoes: a lower price and itself
        // as payee. The facilitator is still asked about the challenge's.
        let mut payload = evm_payload(&ch);
        payload.accepted.amount = "1".to_string();
        payload.accepted.pay_to = "0xpayer".to_string();
        let cred = wire::credential_from_payload(&payload).unwrap();
        backend.verify(&ch, &cred).await.unwrap();
        let seen = stub.calls.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].amount, "1000");
        assert_eq!(seen[0].pay_to, "0xrecipient");

        let tx = backend.settle(&ch, &cred).await.unwrap();
        assert_eq!(tx.as_deref(), Some("0xstubtx"));
    }

    #[tokio::test]
    async fn eip3009_refuses_another_network_or_a_missing_payload() {
        let backend = Eip3009Backend::new(Arc::new(StubFacilitator::new(true)));
        let ch = evm_challenge("exact-eip3009");
        let mut payload = evm_payload(&ch);
        payload.accepted.network = "eip155:1".to_string();
        let cred = wire::credential_from_payload(&payload).unwrap();
        assert!(matches!(
            backend.verify(&ch, &cred).await.unwrap_err(),
            PaymentError::VerificationFailed(_)
        ));

        let mut cred = make_facilitator_credential(&ch);
        cred.extra.remove(wire::X402_PAYLOAD_KEY);
        assert!(matches!(
            backend.verify(&ch, &cred).await.unwrap_err(),
            PaymentError::CredentialError(_)
        ));
    }

    #[tokio::test]
    async fn eip3009_backend_propagates_facilitator_rejection() {
        let backend = Eip3009Backend::new(Arc::new(StubFacilitator::new(false)));
        let ch = evm_challenge("exact-eip3009");
        let err = backend
            .verify(&ch, &make_facilitator_credential(&ch))
            .await
            .unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    // ── Permit2 backend ─────────────────────────────────────────────────

    #[tokio::test]
    async fn permit2_backend_calls_facilitator() {
        let stub = Arc::new(StubFacilitator::new(true));
        let backend = Permit2Backend::new(stub.clone());
        let ch = evm_challenge("permit2");
        backend
            .verify(&ch, &make_facilitator_credential(&ch))
            .await
            .unwrap();
        assert_eq!(stub.calls.lock().unwrap().len(), 1);
    }

    // ── ERC-7710 backend ────────────────────────────────────────────────

    #[derive(Debug)]
    struct StubDelegation {
        accept: bool,
    }

    #[async_trait]
    impl DelegationVerifier for StubDelegation {
        async fn verify_payload_redemption(
            &self,
            _requirement: &X402PaymentRequirement,
            _payload: &X402PaymentPayload,
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

    #[tokio::test]
    async fn erc7710_backend_verifies_the_wire_payload_against_the_challenge() {
        let backend_ok = Erc7710Backend::new(Arc::new(StubDelegation { accept: true }));
        let backend_no = Erc7710Backend::new(Arc::new(StubDelegation { accept: false }));
        let ch = evm_challenge("erc7710");
        let cred = make_facilitator_credential(&ch);
        backend_ok.verify(&ch, &cred).await.unwrap();
        assert!(matches!(
            backend_no.verify(&ch, &cred).await.unwrap_err(),
            PaymentError::VerificationFailed(_)
        ));

        // No payload, or a payload for another network, is refused.
        let mut bare = cred.clone();
        bare.extra.remove(wire::X402_PAYLOAD_KEY);
        assert!(backend_ok.verify(&ch, &bare).await.is_err());
        let mut payload = evm_payload(&ch);
        payload.accepted.network = "eip155:1".to_string();
        let other = wire::credential_from_payload(&payload).unwrap();
        assert!(backend_ok.verify(&ch, &other).await.is_err());
    }

    #[tokio::test]
    async fn default_erc7710_verifier_fails_closed() {
        // The default verifier has no enforcer registry and a zero
        // delegation-manager domain: a garbage proof is refused.
        let backend = Erc7710Backend::new(Arc::new(
            crate::x402::erc7710::Erc7710DelegationVerifier::default(),
        ));
        let ch = evm_challenge("erc7710");
        let err = backend
            .verify(&ch, &make_facilitator_credential(&ch))
            .await
            .unwrap_err();
        assert!(matches!(err, PaymentError::VerificationFailed(_)));
    }

    // ── Tenzro-native backends ─────────────────────────────────────────

    fn hybrid_signer() -> tenzro_crypto::composite::testing::TestHybridSigner {
        static SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
        tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
            SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    fn tenzro_challenge(scheme: &str, amount: u128) -> PaymentChallenge {
        let mut ch = make_challenge(scheme);
        ch.amount = amount;
        ch.asset = "TNZO".to_string();
        ch.recipient = hex::encode([9u8; 20]);
        ch.extra.insert(
            crate::payer_auth::CHAIN_ID_KEY.to_string(),
            serde_json::json!(1337u64),
        );
        ch
    }

    #[test]
    fn registry_defaults_contain_upto_and_batch() {
        let r = SchemeRegistry::with_defaults(Arc::new(crate::test_support::SeedKeys));
        assert!(r.get(UPTO_SCHEME).is_some());
        assert_eq!(r.get("UPTO").unwrap().name(), UPTO_SCHEME);
    }

    #[tokio::test]
    async fn with_local_relayer_registers_self_hosted_backends() {
        // Signer construction is offline (the device reports its public key);
        // no RPC is issued until a verify/settle actually runs. The device is
        // a test stand-in for a hardware signer.
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let sk = k256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let pk = sk.verifying_key().to_sec1_point(true).as_bytes().to_vec();
        let device = std::sync::Arc::new(tenzro_wallet::pluggable_signer::GenericSigner::new(
            pk,
            move |hash| {
                let (sig, rec): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = sk
                    .sign_prehash(hash)
                    .map_err(|e| tenzro_wallet::WalletError::SignatureFailed(e.to_string()))?;
                let mut out = sig.to_bytes().to_vec();
                out.push(rec.to_byte());
                Ok(out)
            },
        ));
        let signer = std::sync::Arc::new(
            tenzro_bridge::EvmTransactionSigner::from_hardware(
                device,
                84532,
                "http://127.0.0.1:0".into(),
            )
            .await
            .expect("offline signer construction"),
        );
        let r = SchemeRegistry::with_local_relayer(
            Arc::new(crate::test_support::SeedKeys),
            signer,
            "http://127.0.0.1:0",
        );

        // The EIP-3009 / Permit2 lanes now route through the local verifier.
        assert!(r.get("exact-eip3009").is_some());
        assert!(r.get("eip3009").is_some());
        assert!(r.get("permit2").is_some());

        // The shared, facilitator-independent backends are still present.
        assert!(r.get(DEFAULT_SCHEME).is_some());
        assert!(r.get(UPTO_SCHEME).is_some());
        assert!(r.get(BATCH_SETTLEMENT_SCHEME).is_some());
    }

    #[tokio::test]
    async fn hybrid_accepts_an_exact_signed_payment_and_names_the_payer() {
        let s = hybrid_signer();
        let ch = tenzro_challenge("tenzro-hybrid", 1_000);
        let cred = crate::payer_auth::sign_credential(&ch, "x402", "", &s, 1_000, 1_000).unwrap();
        match TenzroHybridBackend::new(Arc::new(crate::test_support::SeedKeys))
            .verify(&ch, &cred)
            .await
            .unwrap()
        {
            SettlementLeg::Payer(p) => assert_eq!(p.authorization.max_amount, 1_000),
            other => panic!("expected a payer leg, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hybrid_refuses_a_metered_ceiling_and_a_short_amount() {
        let s = hybrid_signer();
        let ch = tenzro_challenge("tenzro-hybrid", 1_000);
        let metered = crate::payer_auth::sign_credential(&ch, "x402", "", &s, 10, 1_000).unwrap();
        assert!(
            TenzroHybridBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &metered)
                .await
                .is_err()
        );
        let short = crate::payer_auth::sign_credential(&ch, "x402", "", &s, 999, 999).unwrap();
        assert!(
            TenzroHybridBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &short)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn upto_accepts_a_charge_under_the_signed_ceiling() {
        let s = hybrid_signer();
        let ch = tenzro_challenge(UPTO_SCHEME, 1_000);
        let cred = crate::payer_auth::sign_credential(&ch, "x402", "", &s, 250, 800).unwrap();
        assert!(
            UptoBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &cred)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn upto_refuses_a_charge_raised_after_signing() {
        let s = hybrid_signer();
        let ch = tenzro_challenge(UPTO_SCHEME, 1_000);
        let mut cred = crate::payer_auth::sign_credential(&ch, "x402", "", &s, 250, 800).unwrap();
        cred.amount = 801;
        assert!(
            UptoBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &cred)
                .await
                .is_err()
        );
        // Raising the ceiling itself breaks the signature.
        let mut cred = crate::payer_auth::sign_credential(&ch, "x402", "", &s, 250, 800).unwrap();
        cred.extra.insert(
            crate::payer_auth::UPTO_MAX_KEY.to_string(),
            serde_json::json!("900"),
        );
        assert!(
            UptoBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &cred)
                .await
                .is_err()
        );
    }

    #[test]
    fn the_local_facilitator_registry_verifies_evm_schemes_itself() {
        let r = SchemeRegistry::with_local_facilitator(
            Arc::new(crate::test_support::SeedKeys),
            "http://127.0.0.1:0",
            "http://127.0.0.1:0",
        );
        for id in [
            "exact-eip3009",
            "eip3009",
            "permit2",
            "tenzro-hybrid",
            "upto",
        ] {
            assert!(r.get(id).is_some(), "missing {id}");
        }
    }

    #[tokio::test]
    async fn a_metered_upto_charge_needs_the_meters_signed_record() {
        use crate::metering::{METER_KEY, MeterRecord as _, UsageLine, UsageRecord, attach};
        let buyer = hybrid_signer();
        let meter = hybrid_signer();
        let mut ch = tenzro_challenge(UPTO_SCHEME, 1_000);
        ch.extra.insert(
            METER_KEY.to_string(),
            serde_json::json!(hex::encode(
                &tenzro_crypto::composite::HybridSigner::public_key(&meter).p256
            )),
        );
        let cred = crate::payer_auth::sign_credential(&ch, "x402", "", &buyer, 1, 1_000).unwrap();
        // No record: refused, whatever the charge.
        assert!(
            UptoBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &cred)
                .await
                .is_err()
        );

        let payer = tenzro_types::Address::new(
            tenzro_crypto::composite::HybridSigner::public_key(&buyer).account_slot(),
        );
        let lines = vec![UsageLine {
            unit: "output_tokens".into(),
            quantity: 30,
            unit_price: 11,
        }];
        let record = UsageRecord::sign(
            &ch,
            &hex::encode(&payer.as_bytes()[..20]),
            1_000,
            lines,
            &meter,
        )
        .unwrap();
        let mut metered = cred.clone();
        attach(&mut metered, &record).unwrap();
        assert_eq!(metered.amount, 330);
        assert!(
            UptoBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &metered)
                .await
                .is_ok()
        );

        // Charging more than the record says is refused.
        let mut inflated = metered.clone();
        inflated.amount = 900;
        assert!(
            UptoBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &inflated)
                .await
                .is_err()
        );
    }

    fn voucher_credential(
        ch: &PaymentChallenge,
        escrow: [u8; 32],
        cumulative: u128,
        charge: u128,
    ) -> PaymentCredential {
        use tenzro_crypto::composite::HybridSigner;
        let signer = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(0x77);
        let pk = signer.public_key().p256.clone();
        let msg = tenzro_types::payment_authorization::escrow_voucher_preimage(
            1337, &escrow, cumulative, &[0u8; 32],
        );
        let sig = signer
            .sign(
                tenzro_crypto::composite::SignatureContext::EscrowVoucher,
                &msg,
            )
            .unwrap();
        let mut extra = StdHashMap::new();
        extra.insert(
            "escrow_id".to_string(),
            serde_json::json!(hex::encode(escrow)),
        );
        extra.insert(
            "cumulative_amount".to_string(),
            serde_json::json!(cumulative.to_string()),
        );
        extra.insert(
            "public_key".to_string(),
            serde_json::json!(hex::encode(&pk)),
        );
        PaymentCredential {
            credential_id: "v".to_string(),
            challenge_id: ch.challenge_id.clone(),
            protocol: "x402".to_string(),
            payer_did: String::new(),
            payer_address: String::new(),
            amount: charge,
            asset: ch.asset.clone(),
            signature: Some(sig),
            extra,
        }
    }

    #[tokio::test]
    async fn batch_accepts_a_signed_voucher_as_a_voucher_leg() {
        let ch = tenzro_challenge(BATCH_SETTLEMENT_SCHEME, 100);
        let cred = voucher_credential(&ch, [3u8; 32], 500, 100);
        match BatchSettlementBackend::new(Arc::new(crate::test_support::SeedKeys))
            .verify(&ch, &cred)
            .await
            .unwrap()
        {
            SettlementLeg::Voucher(v) => {
                assert_eq!(v.escrow_id, [3u8; 32]);
                assert_eq!(v.cumulative_amount, 500);
            }
            other => panic!("expected a voucher leg, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn batch_refuses_a_tampered_cumulative_or_the_wrong_escrow() {
        let mut ch = tenzro_challenge(BATCH_SETTLEMENT_SCHEME, 100);
        let mut cred = voucher_credential(&ch, [3u8; 32], 500, 100);
        cred.extra
            .insert("cumulative_amount".to_string(), serde_json::json!("5000"));
        assert!(
            BatchSettlementBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &cred)
                .await
                .is_err()
        );

        let cred = voucher_credential(&ch, [3u8; 32], 500, 100);
        ch.extra.insert(
            "escrow_id".to_string(),
            serde_json::json!(hex::encode([4u8; 32])),
        );
        assert!(
            BatchSettlementBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &cred)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn batch_refuses_a_charge_above_the_cumulative_total() {
        let ch = tenzro_challenge(BATCH_SETTLEMENT_SCHEME, 1_000);
        let cred = voucher_credential(&ch, [3u8; 32], 50, 100);
        assert!(
            BatchSettlementBackend::new(Arc::new(crate::test_support::SeedKeys))
                .verify(&ch, &cred)
                .await
                .is_err()
        );
    }
}
