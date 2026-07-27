//! AP2 — Agent Payments Protocol
//!
//! Implements the [AP2 Mandate model](https://github.com/google/ap2) for
//! agentic commerce: a two-tier verifiable-credential (VDC) scheme that
//! lets a human (or a principal agent) delegate bounded purchasing
//! authority to an agent, and lets the agent commit to a specific basket
//! that the principal can finally approve.
//!
//! AP2 is being converged on by Google, Stripe, and Mastercard as a
//! cross-vendor replacement for ad-hoc "agent shops on my card" flows.
//! This implementation targets the v0.2 protocol shape:
//!
//! - **`CheckoutMandate`** — the principal's *pre-authorization*. It says
//!   "agent X may spend up to Y on resources matching Z before T". It is
//!   the AP2 analogue of a [`tenzro_identity::DelegationScope`] and is
//!   cross-validated against one when the payer DID is a TDIP identity.
//! - **`PaymentMandate`** — the agent's *final-offer bundle*: a specific
//!   cart of line items, a total, and a merchant. The agent signs it to
//!   commit, and the principal countersigns to authorize settlement.
//! - **`Vdc`** — a generic Verifiable Digital Credential wrapper over any
//!   mandate, carrying an Ed25519 signature plus a JCS-style canonical
//!   preimage so verification is deterministic.
//! - **`MandateValidator`** — composes checkout → payment verification,
//!   including scope checks, expiry, merchant whitelisting, and optional
//!   TDIP delegation-scope enforcement.
//!
//! Positioning: **TDIP identifies. AP2 authorizes. Tenzro settles.**
//!
//! This module is gated behind the `ap2` cargo feature.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tenzro_crypto::{
    keys::{KeyType, PublicKey},
    signatures::{verify, Signature as CryptoSignature, Signer},
};
use tenzro_identity::IdentityRegistry;

use crate::error::{PaymentError, Result};

/// AP2 protocol version advertised in mandate envelopes.
pub const AP2_VERSION: &str = "0.2";

/// Kinds of mandate a VDC can wrap.
///
/// AP2 v0.2 uses **Checkout Mandate** and **Payment Mandate** (not the
/// older "Intent"/"Cart" naming). Each carries a `vct` (Verifiable
/// Credential Type) suffix per AP2 v0.2 §SD-JWT-VC:
///
/// - `mandate.checkout.1` / `mandate.checkout.open.1` — pre-authorization
///   bundle: principal-signed declaration of what the agent may purchase.
/// - `mandate.payment.1` / `mandate.payment.open.1` — final-offer bundle:
///   a specific cart of line items, total, merchant, bound to a Checkout
///   Mandate via `checkout_hash` (SHA-256 of the Checkout JWT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateKind {
    Checkout,
    Payment,
}

impl MandateKind {
    /// Returns the AP2 v0.2 `vct` claim string for this mandate kind.
    ///
    /// `open: false` → `mandate.{checkout|payment}.1`
    /// `open: true`  → `mandate.{checkout|payment}.open.1` (autonomous flow)
    pub fn vct(self, open: bool) -> &'static str {
        match (self, open) {
            (MandateKind::Checkout, false) => "mandate.checkout.1",
            (MandateKind::Checkout, true) => "mandate.checkout.open.1",
            (MandateKind::Payment, false) => "mandate.payment.1",
            (MandateKind::Payment, true) => "mandate.payment.open.1",
        }
    }
}

/// Presence semantics for the principal — AP2 distinguishes between
/// *human-present* flows (principal approves cart in real time) and
/// *human-not-present* flows (principal pre-delegated via CheckoutMandate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceMode {
    /// Principal is online and confirming the cart interactively.
    #[default]
    HumanPresent,
    /// Principal pre-delegated; agent commits unilaterally within scope.
    HumanNotPresent,
}

/// AP2 CheckoutMandate — the principal's pre-authorization envelope.
///
/// The agent cannot spend outside of the limits expressed here, and the
/// `MandateValidator` enforces those limits when it later sees a
/// `PaymentMandate` signed by the same agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutMandate {
    /// Unique mandate ID (opaque to the protocol).
    pub mandate_id: String,
    /// Principal's DID (`did:tenzro:human:<uuid>` or
    /// `did:tenzro:machine:<uuid>` — TDIP-compatible, but any string DID
    /// works).
    pub principal_did: String,
    /// DID of the agent being delegated to.
    pub agent_did: String,
    /// Human-readable intent ("book flights to NYC under $600").
    pub description: String,
    /// Upper bound on total authorized spend, in the smallest unit of
    /// `asset`.
    pub max_amount: u128,
    /// Asset / currency (e.g. `"USD"`, `"USDC"`, `"TNZO"`).
    pub asset: String,
    /// Optional whitelist of merchant IDs / DIDs the agent may pay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_merchants: Vec<String>,
    /// Optional allow-list of resource categories (merchant-defined tags).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_categories: Vec<String>,
    /// Optional whitelist of settlement chains (rail identifiers, e.g.
    /// `"tenzro"`, `"tempo"`, `"base"`, `"ethereum"`). Empty = any chain
    /// admitted; non-empty = the child PaymentMandate's `chain` must be a
    /// member. Lets the principal pre-authorize a cart only on rails they
    /// trust (e.g. opt out of L2s with no fraud-proof window, opt in to
    /// Tempo for stablecoin settlement).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_chains: Vec<String>,
    /// Maximum number of charges this mandate may cover. `None` = single
    /// charge only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// Issuance timestamp (UTC).
    pub issued_at: DateTime<Utc>,
    /// Hard expiry (UTC). After this, the mandate must be refused.
    pub expires_at: DateTime<Utc>,
    /// Presence semantics (human-present vs human-not-present).
    #[serde(default)]
    pub presence: PresenceMode,
    /// AP2 v0.2 SD-JWT VC `cnf` (confirmation) claim — key binding.
    /// Carries either a JWK (`{"jwk": {...}}`) per RFC 7800 or a Tenzro
    /// extension `{"did": "did:tenzro:machine:..."}` whose DID Document
    /// holds the public key. When present, the verifier resolves `cnf`
    /// to the binding key and checks the mandate signature against it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<MandateCnf>,
    /// Tenzro extension — on-chain escrow ID (selector `0x01000010`
    /// `CreateEscrow`) that pre-locks `max_amount` of `asset` for the
    /// agent. When present, settlement of any child PaymentMandate flows
    /// through `ReleaseEscrow` against this ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow_id: Option<String>,
    /// Tenzro extension — AgentBond ID covering the agent. Mandate
    /// violations (overspend, merchant whitelist breach, etc.) trigger
    /// `slash_bond` against this ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_bond_id: Option<String>,
    /// Tenzro extension — Stripe SharedPaymentToken granted-token ID
    /// (`spt_grant_...`) the agent is authorized to confirm against.
    /// When present, the AP2 validator additionally consults the
    /// configured `SptCeilingResolver` so the payment is bounded by the
    /// SPT's `usage_limits.max_amount` and currency. The child
    /// PaymentMandate must reference the same `spt_grant_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spt_grant_id: Option<String>,
    /// Free-form metadata (merchant hints, session ID, refund policy …).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

/// AP2 v0.2 SD-JWT VC `cnf` (confirmation) claim — RFC 7800.
///
/// Carries the public key bound to a mandate. AP2 v0.2 §SD-JWT-VC mandates
/// a `cnf` claim on every mandate VDC so the holder of the binding key can
/// be authenticated independently of the issuer.
///
/// The Tenzro extension form (`{"did": "..."}`) lets the binding key live
/// in a Tenzro DID Document — verification = DID resolution + signature
/// check, with the resolved key replacing the inline JWK.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateCnf {
    /// Inline JWK per RFC 7517 — `{"cnf": {"jwk": {...}}}`.
    Jwk(serde_json::Value),
    /// Tenzro extension — DID whose DID Document holds the binding key.
    Did(String),
}

impl CheckoutMandate {
    /// Basic constructor with sensible AP2 defaults.
    pub fn new(
        principal_did: impl Into<String>,
        agent_did: impl Into<String>,
        description: impl Into<String>,
        max_amount: u128,
        asset: impl Into<String>,
        ttl_secs: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            mandate_id: uuid::Uuid::new_v4().to_string(),
            principal_did: principal_did.into(),
            agent_did: agent_did.into(),
            description: description.into(),
            max_amount,
            asset: asset.into(),
            allowed_merchants: Vec::new(),
            allowed_categories: Vec::new(),
            accepted_chains: Vec::new(),
            max_uses: Some(1),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            presence: PresenceMode::default(),
            cnf: None,
            escrow_id: None,
            agent_bond_id: None,
            spt_grant_id: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_allowed_merchants(mut self, merchants: Vec<String>) -> Self {
        self.allowed_merchants = merchants;
        self
    }

    pub fn with_allowed_categories(mut self, categories: Vec<String>) -> Self {
        self.allowed_categories = categories;
        self
    }

    /// Restrict settlement to a specific set of chains / rails. Empty (the
    /// default) admits any chain; non-empty makes the child PaymentMandate's
    /// `chain` membership a hard precondition of `validate()`.
    pub fn with_accepted_chains(mut self, chains: Vec<String>) -> Self {
        self.accepted_chains = chains;
        self
    }

    pub fn with_max_uses(mut self, uses: Option<u32>) -> Self {
        self.max_uses = uses;
        self
    }

    pub fn with_presence(mut self, presence: PresenceMode) -> Self {
        self.presence = presence;
        self
    }

    /// Bind a `cnf` (confirmation) claim — AP2 v0.2 SD-JWT VC requirement.
    pub fn with_cnf(mut self, cnf: MandateCnf) -> Self {
        self.cnf = Some(cnf);
        self
    }

    /// Bind a Tenzro on-chain escrow that pre-locks `max_amount`.
    pub fn with_escrow(mut self, escrow_id: impl Into<String>) -> Self {
        self.escrow_id = Some(escrow_id.into());
        self
    }

    /// Bind a Tenzro AgentBond covering the agent.
    pub fn with_agent_bond(mut self, bond_id: impl Into<String>) -> Self {
        self.agent_bond_id = Some(bond_id.into());
        self
    }

    /// Bind a Stripe SPT granted-token ID. When present, the validator's
    /// SPT ceiling check (`validate_with_delegation_policy_escrow_and_spt`)
    /// resolves the snapshot and verifies `usage_limits.max_amount ≥
    /// payment.total_amount` plus currency match against the resolver.
    pub fn with_spt_grant(mut self, granted_token_id: impl Into<String>) -> Self {
        self.spt_grant_id = Some(granted_token_id.into());
        self
    }

    /// AP2 v0.2 `vct` claim string for this CheckoutMandate.
    ///
    /// `presence == HumanNotPresent` selects the open variant
    /// (`mandate.checkout.open.1`), reflecting AP2 v0.2's distinction
    /// between principal-confirmed and pre-delegated flows.
    pub fn vct(&self) -> &'static str {
        MandateKind::Checkout.vct(self.presence == PresenceMode::HumanNotPresent)
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// A single line item in a PaymentMandate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartItem {
    pub sku: String,
    pub description: String,
    pub quantity: u32,
    pub unit_price: u128,
    pub total: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

/// AP2 PaymentMandate — the agent's committed purchase bundle.
///
/// Signed by the agent; optionally countersigned by the principal in
/// human-present flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMandate {
    /// Unique payment mandate ID.
    pub mandate_id: String,
    /// ID of the parent [`CheckoutMandate`]. Must exist and be non-expired
    /// when the payment mandate is validated.
    pub checkout_mandate_id: String,
    /// Agent committing to this payment mandate.
    pub agent_did: String,
    /// Merchant receiving the payment.
    pub merchant_did: String,
    /// Line items.
    pub items: Vec<CartItem>,
    /// Total (should equal the sum of line `total`s).
    pub total_amount: u128,
    /// Asset (must match the parent CheckoutMandate).
    pub asset: String,
    /// Chain / settlement rail.
    pub chain: String,
    /// When the agent committed to this payment mandate.
    pub committed_at: DateTime<Utc>,
    /// Expiry of the offer.
    pub expires_at: DateTime<Utc>,
    /// AP2 v0.2 §6.2.3 — SHA-256 hash of the parent CheckoutMandate VDC
    /// (lowercase hex). Cryptographically binds the PaymentMandate to a
    /// specific CheckoutMandate, preventing cross-mandate reuse. When
    /// `Some`, validators MUST verify it against the resolved parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkout_hash: Option<String>,
    /// AP2 v0.2 SD-JWT VC `cnf` (confirmation) claim — see [`MandateCnf`].
    /// Carries the agent's binding key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<MandateCnf>,
    /// Tenzro extension — settlement on-chain escrow ID. When the parent
    /// CheckoutMandate also carries an `escrow_id`, the two MUST match;
    /// release flows through `ReleaseEscrow` (selector `0x01000011`)
    /// against this ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow_id: Option<String>,
    /// Tenzro extension — Stripe SharedPaymentToken granted-token ID
    /// (`spt_grant_...`). When the parent CheckoutMandate also carries a
    /// `spt_grant_id`, the two MUST match. The validator's SPT ceiling
    /// check resolves this ID against the configured
    /// `SptCeilingResolver` and verifies `usage_limits.max_amount ≥
    /// payment.total_amount` plus currency match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spt_grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl PaymentMandate {
    pub fn new(
        checkout_mandate_id: impl Into<String>,
        agent_did: impl Into<String>,
        merchant_did: impl Into<String>,
        items: Vec<CartItem>,
        asset: impl Into<String>,
        chain: impl Into<String>,
        ttl_secs: i64,
    ) -> Self {
        let now = Utc::now();
        let total: u128 = items.iter().map(|i| i.total).sum();
        Self {
            mandate_id: uuid::Uuid::new_v4().to_string(),
            checkout_mandate_id: checkout_mandate_id.into(),
            agent_did: agent_did.into(),
            merchant_did: merchant_did.into(),
            items,
            total_amount: total,
            asset: asset.into(),
            chain: chain.into(),
            committed_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            checkout_hash: None,
            cnf: None,
            escrow_id: None,
            spt_grant_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Bind this PaymentMandate to its parent CheckoutMandate VDC by hash.
    ///
    /// AP2 v0.2 §6.2.3: the PaymentMandate carries `checkout_hash =
    /// sha256(parent_checkout_vdc_bytes)` so settlement infrastructure can
    /// verify the payment mandate commits to a specific authorization without having
    /// to re-resolve the parent VDC by `checkout_mandate_id`.
    pub fn with_checkout_hash(mut self, hash: impl Into<String>) -> Self {
        self.checkout_hash = Some(hash.into());
        self
    }

    /// Bind a `cnf` (confirmation) claim — AP2 v0.2 SD-JWT VC requirement.
    pub fn with_cnf(mut self, cnf: MandateCnf) -> Self {
        self.cnf = Some(cnf);
        self
    }

    /// Bind a Tenzro on-chain settlement escrow ID. Must match the parent
    /// CheckoutMandate's `escrow_id` when both are present.
    pub fn with_escrow(mut self, escrow_id: impl Into<String>) -> Self {
        self.escrow_id = Some(escrow_id.into());
        self
    }

    /// Bind a Stripe SPT granted-token ID. Must match the parent
    /// CheckoutMandate's `spt_grant_id` when both are present.
    pub fn with_spt_grant(mut self, granted_token_id: impl Into<String>) -> Self {
        self.spt_grant_id = Some(granted_token_id.into());
        self
    }

    /// AP2 v0.2 `vct` claim string for this PaymentMandate.
    ///
    /// The `open` variant is selected when the parent CheckoutMandate was
    /// `HumanNotPresent`; in v0.2 there is no per-PaymentMandate flag, so
    /// callers wanting `mandate.payment.open.1` must select it via the
    /// dispatcher (`MandateKind::Payment.vct(true)`).
    pub fn vct(&self) -> &'static str {
        MandateKind::Payment.vct(false)
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Recomputes the total from line items. Returns `Err` if the stored
    /// total disagrees with the recomputed total.
    pub fn check_total(&self) -> Result<()> {
        let computed: u128 = self
            .items
            .iter()
            .map(|i| i.total)
            .try_fold(0u128, |acc, t| acc.checked_add(t))
            .ok_or_else(|| {
                PaymentError::CredentialError("cart total overflow".into())
            })?;
        if computed != self.total_amount {
            return Err(PaymentError::CredentialError(format!(
                "cart total mismatch: claimed={}, computed={}",
                self.total_amount, computed
            )));
        }
        Ok(())
    }
}

/// Payload of a VDC — exactly one of the mandate kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MandatePayload {
    Checkout(CheckoutMandate),
    Payment(PaymentMandate),
}

impl MandatePayload {
    pub fn kind(&self) -> MandateKind {
        match self {
            MandatePayload::Checkout(_) => MandateKind::Checkout,
            MandatePayload::Payment(_) => MandateKind::Payment,
        }
    }

    pub fn mandate_id(&self) -> &str {
        match self {
            MandatePayload::Checkout(m) => &m.mandate_id,
            MandatePayload::Payment(m) => &m.mandate_id,
        }
    }
}

/// A Verifiable Digital Credential wrapping an AP2 mandate.
///
/// Canonicalization strategy: the signing preimage is the JSON
/// serialization of the inner mandate + version + a fixed `"ap2"` tag.
/// We avoid a full JCS dependency by always going through `serde_json`
/// with the same struct layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vdc {
    /// Protocol version (currently `"0.2"`).
    pub version: String,
    /// Mandate kind (redundant with payload, but useful for filtering).
    pub kind: MandateKind,
    /// The mandate itself.
    pub payload: MandatePayload,
    /// DID of the signer (principal for checkout, agent for payment).
    pub signer_did: String,
    /// Signer's Ed25519 public key (32 bytes).
    pub signer_public_key: Vec<u8>,
    /// Signature over the canonical preimage.
    pub signature: Vec<u8>,
    /// Algorithm identifier (`"ed25519"` today).
    pub alg: String,
}

/// Canonical preimage for signing/verifying a VDC.
#[derive(Serialize)]
struct VdcPreimage<'a> {
    tag: &'static str,
    version: &'a str,
    kind: MandateKind,
    payload: &'a MandatePayload,
    signer_did: &'a str,
    signer_public_key: &'a [u8],
}

impl Vdc {
    /// Sign a mandate, producing a VDC.
    pub fn sign(
        signer: &dyn Signer,
        signer_did: impl Into<String>,
        payload: MandatePayload,
    ) -> Result<Self> {
        let signer_did = signer_did.into();
        let signer_public_key = signer.public_key().as_bytes().to_vec();
        let preimage = Self::canonical_preimage(&payload, &signer_did, &signer_public_key)?;
        let sig = signer
            .sign(&preimage)
            .map_err(|e| PaymentError::CryptoError(e.to_string()))?;
        Self::assemble(payload, signer_did, signer_public_key, sig.as_bytes().to_vec())
    }

    /// Canonical preimage bytes for a mandate + signer pair.
    ///
    /// External signing flows (e.g. the JSON-RPC handler that signs through
    /// `WalletService`) need to produce the exact bytes that `Vdc::sign`
    /// would feed into `Signer::sign`. Exposing this helper keeps the
    /// canonicalization owned by the AP2 module — out-of-process signers
    /// must never roll their own preimage.
    pub fn canonical_preimage(
        payload: &MandatePayload,
        signer_did: &str,
        signer_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        serde_json::to_vec(&VdcPreimage {
            tag: "ap2",
            version: AP2_VERSION,
            kind: payload.kind(),
            payload,
            signer_did,
            signer_public_key,
        })
        .map_err(|e| PaymentError::SerializationError(format!("vdc preimage: {e}")))
    }

    /// Assemble a VDC from an externally-produced Ed25519 signature.
    ///
    /// `signature_bytes` MUST be the output of signing
    /// `Vdc::canonical_preimage(&payload, signer_did, signer_public_key)`
    /// with the Ed25519 private key matching `signer_public_key`. The
    /// result is then `verify()`-ed before being returned, so a wrong
    /// signature surfaces here rather than at the relying party.
    pub fn assemble(
        payload: MandatePayload,
        signer_did: impl Into<String>,
        signer_public_key: Vec<u8>,
        signature_bytes: Vec<u8>,
    ) -> Result<Self> {
        let kind = payload.kind();
        let vdc = Self {
            version: AP2_VERSION.to_string(),
            kind,
            payload,
            signer_did: signer_did.into(),
            signer_public_key,
            signature: signature_bytes,
            alg: "ed25519".to_string(),
        };
        vdc.verify()?;
        Ok(vdc)
    }

    /// Verify the VDC's signature against its embedded public key.
    pub fn verify(&self) -> Result<()> {
        if self.alg != "ed25519" {
            return Err(PaymentError::VerificationFailed(format!(
                "unsupported VDC alg: {}",
                self.alg
            )));
        }
        if self.version != AP2_VERSION {
            return Err(PaymentError::VerificationFailed(format!(
                "unsupported AP2 version: {}",
                self.version
            )));
        }

        let preimage = serde_json::to_vec(&VdcPreimage {
            tag: "ap2",
            version: &self.version,
            kind: self.kind,
            payload: &self.payload,
            signer_did: &self.signer_did,
            signer_public_key: &self.signer_public_key,
        })
        .map_err(|e| PaymentError::SerializationError(format!("vdc preimage: {e}")))?;

        let pk = PublicKey::new(KeyType::Ed25519, self.signer_public_key.clone());
        let sig = CryptoSignature::new(KeyType::Ed25519, self.signature.clone());
        verify(&pk, &preimage, &sig)
            .map_err(|e| PaymentError::VerificationFailed(e.to_string()))
    }

    /// Verify like [`Self::verify`] *and* enforce the `cnf` (key-binding)
    /// claim against an `IdentityRegistry`.
    ///
    /// AP2 v0.2 §SD-JWT-VC requires every mandate to carry a `cnf`
    /// (RFC 7800) claim naming the holder's binding key. When `cnf` is
    /// `MandateCnf::Did`, the binding key lives in the DID Document of
    /// `cnf.did`; the verifier MUST resolve that DID and check that the
    /// public key actually used to sign the VDC is one of the keys
    /// registered under it.
    ///
    /// **Tenzro extension** — this is the wire-up that turns AP2's bare
    /// JWK-binding into a DID-anchored binding via TDIP. A revoked or
    /// missing identity fails closed.
    ///
    /// Resolution rules:
    ///
    /// - `cnf == None` → falls back to plain [`Self::verify`].
    /// - `cnf == Some(MandateCnf::Jwk(_))` → enforced lexically: the JWK
    ///   `x` parameter (decoded base64url) MUST equal `signer_public_key`.
    ///   Mismatch is a hard fail. (Inline JWK lives in the VDC itself, so
    ///   no registry lookup is needed.)
    /// - `cnf == Some(MandateCnf::Did(did))` → the registry is queried for
    ///   `did`; the VDC's `signer_public_key` MUST appear among the
    ///   resolved identity's `public_keys`. The VDC's `signer_did` MUST
    ///   also equal the bound DID — otherwise an attacker could sign with
    ///   one DID's key while claiming binding to another.
    ///
    /// On `cnf == None`, this method behaves identically to `verify()`.
    /// Code paths that want strict enforcement should reject mandates that
    /// omit `cnf` *before* calling this function.
    pub fn verify_with_registry(&self, registry: &IdentityRegistry) -> Result<()> {
        self.verify()?;

        let cnf = match &self.payload {
            MandatePayload::Checkout(m) => m.cnf.as_ref(),
            MandatePayload::Payment(m) => m.cnf.as_ref(),
        };
        let Some(cnf) = cnf else {
            return Ok(());
        };

        match cnf {
            MandateCnf::Jwk(jwk) => {
                // The JWK is inline; we only need it to agree with the
                // signing key the VDC already verified against. RFC 7517
                // OKP keys (Ed25519) carry the raw public key in `x` as
                // base64url-no-pad.
                let x_str = jwk
                    .get("x")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        PaymentError::VerificationFailed(
                            "cnf.jwk missing 'x' parameter (Ed25519 OKP)".into(),
                        )
                    })?;
                use base64::{engine::general_purpose, Engine as _};
                let x_bytes =
                    general_purpose::URL_SAFE_NO_PAD.decode(x_str).map_err(|e| {
                        PaymentError::VerificationFailed(format!(
                            "cnf.jwk.x is not base64url-no-pad: {e}"
                        ))
                    })?;
                if x_bytes != self.signer_public_key {
                    return Err(PaymentError::VerificationFailed(
                        "cnf.jwk.x does not match VDC signer_public_key".into(),
                    ));
                }
                Ok(())
            }
            MandateCnf::Did(cnf_did) => {
                if cnf_did != &self.signer_did {
                    return Err(PaymentError::VerificationFailed(format!(
                        "cnf.did {} does not match VDC signer_did {}",
                        cnf_did, self.signer_did
                    )));
                }
                let identity = registry.resolve(cnf_did).map_err(|e| {
                    PaymentError::VerificationFailed(format!(
                        "cnf.did {} does not resolve: {e}",
                        cnf_did
                    ))
                })?;
                if !identity
                    .public_keys
                    .iter()
                    .any(|k| k.public_key == self.signer_public_key)
                {
                    return Err(PaymentError::VerificationFailed(format!(
                        "cnf.did {} does not list VDC signer_public_key",
                        cnf_did
                    )));
                }
                Ok(())
            }
        }
    }

    pub fn mandate_id(&self) -> &str {
        self.payload.mandate_id()
    }

    pub fn as_checkout(&self) -> Option<&CheckoutMandate> {
        match &self.payload {
            MandatePayload::Checkout(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_payment(&self) -> Option<&PaymentMandate> {
        match &self.payload {
            MandatePayload::Payment(m) => Some(m),
            _ => None,
        }
    }

    /// AP2 v0.2 §6.2.3 — SHA-256 of this VDC's canonical preimage,
    /// lowercase hex.
    ///
    /// Used as the `checkout_hash` claim on a child PaymentMandate to
    /// cryptographically bind it to a specific parent CheckoutMandate.
    /// The hash covers the full preimage (`tag="ap2"`, version, kind,
    /// payload, signer_did, signer_public_key) so any mutation of the
    /// parent invalidates the binding.
    pub fn checkout_hash(&self) -> Result<String> {
        let preimage = Self::canonical_preimage(
            &self.payload,
            &self.signer_did,
            &self.signer_public_key,
        )?;
        let digest = tenzro_crypto::hash::sha256(&preimage);
        Ok(hex::encode(digest.as_bytes()))
    }
}

/// Composite validator enforcing checkout → payment constraints.
///
/// Typical flow:
///
/// 1. Merchant receives a signed `Vdc` wrapping a `PaymentMandate` from
///    the agent.
/// 2. Merchant also holds the signed `Vdc` wrapping the parent
///    `CheckoutMandate` (provided by the principal out-of-band or
///    attached to the payment envelope).
/// 3. Merchant calls [`MandateValidator::validate`] passing both.
/// 4. On success, the merchant submits the cart total on-chain.
#[derive(Default)]
pub struct MandateValidator;

impl MandateValidator {
    pub fn new() -> Self {
        Self
    }

    /// Validate a `PaymentMandate` against a parent `CheckoutMandate`.
    ///
    /// Both VDCs must pass signature verification independently first.
    pub fn validate(&self, checkout_vdc: &Vdc, payment_vdc: &Vdc) -> Result<()> {
        checkout_vdc.verify()?;
        payment_vdc.verify()?;

        let checkout = checkout_vdc.as_checkout().ok_or_else(|| {
            PaymentError::CredentialError("parent VDC is not a CheckoutMandate".into())
        })?;
        let payment = payment_vdc.as_payment().ok_or_else(|| {
            PaymentError::CredentialError("child VDC is not a PaymentMandate".into())
        })?;

        if checkout.is_expired() {
            return Err(PaymentError::VerificationFailed(
                "CheckoutMandate expired".into(),
            ));
        }
        if payment.is_expired() {
            return Err(PaymentError::VerificationFailed(
                "PaymentMandate expired".into(),
            ));
        }

        if payment.checkout_mandate_id != checkout.mandate_id {
            return Err(PaymentError::VerificationFailed(format!(
                "payment.checkout_mandate_id {} does not match checkout.mandate_id {}",
                payment.checkout_mandate_id, checkout.mandate_id
            )));
        }

        // AP2 v0.2 §6.2.3 — when the PaymentMandate carries a
        // `checkout_hash`, it MUST match SHA-256 of the parent
        // CheckoutMandate VDC's canonical preimage. The hash is the
        // cryptographic binding that prevents a malicious agent from
        // pairing a PaymentMandate with a different (looser)
        // CheckoutMandate that happens to share the same `mandate_id`.
        if let Some(claimed_hash) = payment.checkout_hash.as_ref() {
            let actual_hash = checkout_vdc.checkout_hash()?;
            if !claimed_hash.eq_ignore_ascii_case(&actual_hash) {
                return Err(PaymentError::VerificationFailed(format!(
                    "payment.checkout_hash {} does not match parent VDC hash {}",
                    claimed_hash, actual_hash
                )));
            }
        }

        // Tenzro extension — when both mandates carry an `escrow_id`,
        // they must reference the same on-chain escrow. The principal
        // funds the escrow at CheckoutMandate-issue time; the agent
        // releases it at PaymentMandate-settle time.
        match (checkout.escrow_id.as_ref(), payment.escrow_id.as_ref()) {
            (Some(c), Some(p)) if c != p => {
                return Err(PaymentError::VerificationFailed(format!(
                    "escrow_id mismatch: checkout={}, payment={}",
                    c, p
                )));
            }
            _ => {}
        }

        // Tenzro extension — when both mandates carry a `spt_grant_id`,
        // they must reference the same Stripe SharedPaymentToken. The
        // principal binds the SPT at CheckoutMandate-issue time; the
        // agent settles against it at PaymentMandate-confirm time.
        match (checkout.spt_grant_id.as_ref(), payment.spt_grant_id.as_ref()) {
            (Some(c), Some(p)) if c != p => {
                return Err(PaymentError::VerificationFailed(format!(
                    "spt_grant_id mismatch: checkout={}, payment={}",
                    c, p
                )));
            }
            _ => {}
        }

        // The CheckoutMandate VDC must have been signed by the principal;
        // the PaymentMandate VDC by the delegated agent.
        if checkout_vdc.signer_did != checkout.principal_did {
            return Err(PaymentError::VerificationFailed(format!(
                "checkout signer {} != principal {}",
                checkout_vdc.signer_did, checkout.principal_did
            )));
        }
        if payment_vdc.signer_did != payment.agent_did {
            return Err(PaymentError::VerificationFailed(format!(
                "payment signer {} != agent {}",
                payment_vdc.signer_did, payment.agent_did
            )));
        }
        if checkout.agent_did != payment.agent_did {
            return Err(PaymentError::VerificationFailed(format!(
                "checkout delegates to agent {} but payment was signed by {}",
                checkout.agent_did, payment.agent_did
            )));
        }

        if checkout.asset != payment.asset {
            return Err(PaymentError::VerificationFailed(format!(
                "asset mismatch: checkout={}, payment={}",
                checkout.asset, payment.asset
            )));
        }

        payment.check_total()?;

        if payment.total_amount > checkout.max_amount {
            return Err(PaymentError::VerificationFailed(format!(
                "payment total {} exceeds checkout ceiling {}",
                payment.total_amount, checkout.max_amount
            )));
        }

        if !checkout.allowed_merchants.is_empty()
            && !checkout.allowed_merchants.contains(&payment.merchant_did)
        {
            return Err(PaymentError::VerificationFailed(format!(
                "merchant {} not in checkout allow-list",
                payment.merchant_did
            )));
        }

        if !checkout.allowed_categories.is_empty() {
            for item in &payment.items {
                let Some(cat) = item.category.as_ref() else {
                    return Err(PaymentError::VerificationFailed(format!(
                        "payment item {} missing category (checkout restricts categories)",
                        item.sku
                    )));
                };
                if !checkout.allowed_categories.contains(cat) {
                    return Err(PaymentError::VerificationFailed(format!(
                        "category {} not in checkout allow-list",
                        cat
                    )));
                }
            }
        }

        // Settlement rail whitelist (Tenzro extension). When the principal
        // pins `accepted_chains`, the agent's chosen rail must be a member;
        // empty list = any chain admitted.
        if !checkout.accepted_chains.is_empty()
            && !checkout.accepted_chains.contains(&payment.chain)
        {
            return Err(PaymentError::VerificationFailed(format!(
                "chain {} not in checkout accepted_chains list",
                payment.chain
            )));
        }

        Ok(())
    }

    /// Like [`Self::validate`], but additionally cross-checks the agent's
    /// TDIP delegation scope.
    ///
    /// AP2's CheckoutMandate is the *principal-facing* delegation envelope; the
    /// TDIP DelegationScope is the *protocol-facing* one. Both must allow the
    /// purchase: the CheckoutMandate caps the spend (`max_amount`,
    /// `allowed_merchants`, `allowed_categories`, expiry) and the TDIP scope
    /// caps the agent's broader operating envelope (`max_transaction_value`,
    /// `allowed_operations`, reputation floor, controller liveness).
    ///
    /// Returns `Ok(())` only when both layers admit the payment. Failures from
    /// the TDIP layer are wrapped as [`PaymentError::VerificationFailed`] so
    /// the caller does not need to bridge two error types.
    ///
    /// The operation name passed to TDIP enforcement is `"payment"`. Callers
    /// that want a finer-grained name (e.g. `"payment.ap2"`) should call
    /// [`IdentityRegistry::enforce_operation`] directly *in addition* to
    /// [`Self::validate`].
    pub fn validate_with_delegation(
        &self,
        checkout_vdc: &Vdc,
        payment_vdc: &Vdc,
        identity_registry: &IdentityRegistry,
    ) -> Result<()> {
        self.validate_with_delegation_and_policy(
            checkout_vdc,
            payment_vdc,
            identity_registry,
            None,
        )
    }

    /// Like [`Self::validate_with_delegation`], but additionally consults a
    /// runtime [`SpendingPolicyResolver`] so the payment mandate is rejected
    /// if the agent's *runtime* per-transaction or per-day ceiling would be
    /// exceeded.
    ///
    /// This variant applies three nested ceilings, all of which must admit
    /// the payment total:
    ///
    /// 1. **AP2 CheckoutMandate** — the principal-signed declaration of intent
    ///    (caps `max_amount`, `allowed_merchants`, `allowed_categories`).
    ///    Enforced by [`Self::validate`].
    /// 2. **TDIP DelegationScope** — the protocol-facing structural ceiling
    ///    on the agent's machine identity. Enforced by
    ///    `IdentityRegistry::enforce_operation`.
    /// 3. **Runtime SpendingPolicy** — the execution-facing ceiling that
    ///    tracks current daily spend and the configured per-transaction
    ///    bound. Enforced here when `policy_resolver` is `Some`.
    ///
    /// `policy_resolver` returning `Ok(None)` for the agent DID is treated as
    /// "no runtime ceiling configured" and falls back to (1) + (2) only.
    pub fn validate_with_delegation_and_policy(
        &self,
        checkout_vdc: &Vdc,
        payment_vdc: &Vdc,
        identity_registry: &IdentityRegistry,
        policy_resolver: Option<&dyn crate::identity_binding::SpendingPolicyResolver>,
    ) -> Result<()> {
        self.validate_with_delegation_policy_and_escrow(
            checkout_vdc,
            payment_vdc,
            identity_registry,
            policy_resolver,
            None,
        )
    }

    /// Like [`Self::validate_with_delegation_and_policy`], but additionally
    /// consults a [`EscrowResolver`](crate::identity_binding::EscrowResolver)
    /// so the payment is rejected if the on-chain escrow referenced by the
    /// mandate pair does not exist, has already been settled, has expired,
    /// has insufficient balance, or is bound to the wrong principal /
    /// agent.
    ///
    /// AP2 carries **four** nested ceilings on the Tenzro deployment, all
    /// of which must admit the payment:
    ///
    /// 1. **AP2 CheckoutMandate** — principal-signed declaration of intent
    ///    (caps `max_amount`, `allowed_merchants`, `allowed_categories`).
    /// 2. **TDIP DelegationScope** — protocol-facing structural ceiling on
    ///    the agent's machine identity.
    /// 3. **Runtime SpendingPolicy** — execution-facing ceiling tracking
    ///    current daily spend and per-transaction bound.
    /// 4. **On-chain Escrow** — pre-funded `CreateEscrow` (selector
    ///    `0x01000010`) account; the payment is bounded by `escrow.amount`,
    ///    `escrow.releasable`, `escrow.payer == principal`,
    ///    `escrow.payee == agent`. Enforced here when both the mandate
    ///    pair carries an `escrow_id` and `escrow_resolver` is `Some`.
    ///
    /// `escrow_resolver` returning `Ok(None)` for an `escrow_id` is a hard
    /// failure — the mandate explicitly committed to that escrow and the
    /// escrow MUST resolve. Mandates that carry no `escrow_id` skip the
    /// fourth ceiling entirely (off-chain settlement path; e.g. Stripe
    /// transferWithAuthorization or Visa TAP card-present).
    pub fn validate_with_delegation_policy_and_escrow(
        &self,
        checkout_vdc: &Vdc,
        payment_vdc: &Vdc,
        identity_registry: &IdentityRegistry,
        policy_resolver: Option<&dyn crate::identity_binding::SpendingPolicyResolver>,
        escrow_resolver: Option<&dyn crate::identity_binding::EscrowResolver>,
    ) -> Result<()> {
        // Enforce cnf binding via registry resolution before applying the
        // checkout → payment structural checks. A VDC whose cnf binding
        // doesn't resolve must never reach the spend-ceiling stage.
        checkout_vdc.verify_with_registry(identity_registry)?;
        payment_vdc.verify_with_registry(identity_registry)?;
        self.validate(checkout_vdc, payment_vdc)?;

        // Safe — `validate()` proved the payloads have the correct kinds.
        let checkout = checkout_vdc
            .as_checkout()
            .expect("validate() established checkout payload");
        let payment = payment_vdc
            .as_payment()
            .expect("validate() established payment payload");

        identity_registry
            .enforce_operation(&payment.agent_did, "payment", Some(payment.total_amount))
            .map_err(|e| {
                PaymentError::VerificationFailed(format!(
                    "TDIP delegation rejected AP2 payment mandate for agent {}: {}",
                    payment.agent_did, e
                ))
            })?;

        if let Some(resolver) = policy_resolver
            && let Some(snap) = resolver.resolve(&payment.agent_did)?
        {
            snap.check(payment.total_amount).map_err(|e| {
                PaymentError::VerificationFailed(format!(
                    "runtime SpendingPolicy rejected AP2 payment mandate for agent {}: {}",
                    payment.agent_did, e
                ))
            })?;
        }

        // Fourth ceiling — on-chain escrow. Only checked when the mandate
        // pair commits to an escrow_id. Both mandates must agree on the
        // ID; `validate()` already enforced that invariant.
        let escrow_id = payment
            .escrow_id
            .as_deref()
            .or(checkout.escrow_id.as_deref());
        if let Some(escrow_id) = escrow_id {
            let resolver = escrow_resolver.ok_or_else(|| {
                PaymentError::VerificationFailed(format!(
                    "AP2 mandate pair references escrow {} but no EscrowResolver is wired",
                    escrow_id
                ))
            })?;
            let snapshot = resolver.resolve(escrow_id)?.ok_or_else(|| {
                PaymentError::VerificationFailed(format!(
                    "AP2 mandate pair references escrow {} which does not resolve on-chain",
                    escrow_id
                ))
            })?;
            snapshot.check(
                &checkout.principal_did,
                &payment.agent_did,
                payment.total_amount,
            )?;
        }

        Ok(())
    }

    /// Like [`Self::validate_with_delegation_policy_and_escrow`], but
    /// additionally consults a [`SptCeilingResolver`] so the payment is
    /// rejected if the Stripe SharedPaymentToken referenced by the
    /// mandate pair is not `Active`, has expired, or has a
    /// `usage_limits.max_amount` below `payment.total_amount`. The
    /// resolver also enforces a currency match: `usage_limits.currency`
    /// must equal `payment.asset` (case-insensitive).
    ///
    /// AP2 carries **five** nested ceilings on the Tenzro deployment, all
    /// of which must admit the payment:
    ///
    /// 1. **AP2 CheckoutMandate** — principal-signed declaration of intent.
    /// 2. **TDIP DelegationScope** — protocol-facing structural ceiling.
    /// 3. **Runtime SpendingPolicy** — execution-facing daily/per-tx ceiling.
    /// 4. **On-chain Escrow** — pre-funded `CreateEscrow` account.
    /// 5. **Stripe SPT `usage_limits`** — issuer-side per-token cap.
    ///    Enforced here when the mandate pair carries a `spt_grant_id`
    ///    and `spt_resolver` is `Some`.
    ///
    /// `spt_resolver` returning `Ok(None)` for a `spt_grant_id` is a
    /// hard failure — the mandate explicitly committed to that SPT and
    /// the resolver MUST resolve it. Mandates that carry no
    /// `spt_grant_id` skip the fifth ceiling entirely (off-Stripe
    /// settlement path; e.g. on-chain escrow only, x402, MPP).
    ///
    /// `payment.total_amount` is `u128` (smallest-unit of the AP2 asset);
    /// SPT's `usage_limits.max_amount` is `u64` (smallest-unit of the
    /// Stripe currency). The conversion saturates at `u64::MAX` — a
    /// payment total exceeding that bound is, by construction, also above
    /// any plausible SPT cap, so saturation is a conservative fail.
    pub fn validate_with_delegation_policy_escrow_and_spt(
        &self,
        checkout_vdc: &Vdc,
        payment_vdc: &Vdc,
        identity_registry: &IdentityRegistry,
        policy_resolver: Option<&dyn crate::identity_binding::SpendingPolicyResolver>,
        escrow_resolver: Option<&dyn crate::identity_binding::EscrowResolver>,
        spt_resolver: Option<&dyn crate::mpp::stripe_spt::SptCeilingResolver>,
    ) -> Result<()> {
        self.validate_with_delegation_policy_and_escrow(
            checkout_vdc,
            payment_vdc,
            identity_registry,
            policy_resolver,
            escrow_resolver,
        )?;

        // Fifth ceiling — Stripe SPT `usage_limits`. Only checked when the
        // mandate pair commits to a `spt_grant_id`. `validate()` already
        // enforced that the two mandates agree on the value when both
        // carry one.
        let payment = payment_vdc
            .as_payment()
            .expect("validate_with_delegation_policy_and_escrow established payment payload");
        let checkout = checkout_vdc
            .as_checkout()
            .expect("validate_with_delegation_policy_and_escrow established checkout payload");
        let spt_grant_id = payment
            .spt_grant_id
            .as_deref()
            .or(checkout.spt_grant_id.as_deref());
        if let Some(spt_grant_id) = spt_grant_id {
            let resolver = spt_resolver.ok_or_else(|| {
                PaymentError::VerificationFailed(format!(
                    "AP2 mandate pair references SPT {} but no SptCeilingResolver is wired",
                    spt_grant_id
                ))
            })?;
            let snapshot = resolver.resolve(spt_grant_id)?.ok_or_else(|| {
                PaymentError::VerificationFailed(format!(
                    "AP2 mandate pair references SPT {} which does not resolve at the Stripe gate",
                    spt_grant_id
                ))
            })?;
            // u128 → u64 saturation: payment totals above u64::MAX cannot
            // possibly fit any SPT `usage_limits.max_amount` (also u64),
            // so saturating to u64::MAX preserves the rejection
            // semantics. `SptCeilingSnapshot::check` will then fail on
            // amount > max_amount.
            let payment_total_u64 = u64::try_from(payment.total_amount).unwrap_or(u64::MAX);
            snapshot
                .check(payment_total_u64, &payment.asset)
                .map_err(|e| {
                    PaymentError::VerificationFailed(format!(
                        "Stripe SPT {} rejected AP2 payment mandate for agent {}: {}",
                        spt_grant_id, payment.agent_did, e
                    ))
                })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::signatures::Ed25519SignerImpl;

    fn principal_signer() -> Ed25519SignerImpl {
        Ed25519SignerImpl::generate().unwrap()
    }

    fn make_checkout(agent_did: &str, max: u128) -> CheckoutMandate {
        CheckoutMandate::new(
            "did:tenzro:human:principal",
            agent_did,
            "test checkout",
            max,
            "USDC",
            3600,
        )
    }

    fn make_payment(checkout_id: &str, agent_did: &str, total: u128) -> PaymentMandate {
        PaymentMandate::new(
            checkout_id,
            agent_did,
            "did:tenzro:merchant:acme",
            vec![CartItem {
                sku: "sku-1".into(),
                description: "widget".into(),
                quantity: 1,
                unit_price: total,
                total,
                category: Some("widgets".into()),
            }],
            "USDC",
            "tenzro",
            300,
        )
    }

    #[test]
    fn vdc_signs_and_verifies_checkout() {
        let signer = principal_signer();
        let checkout = make_checkout("did:tenzro:machine:shopper", 1_000);
        let vdc = Vdc::sign(
            &signer,
            "did:tenzro:human:principal",
            MandatePayload::Checkout(checkout),
        )
        .unwrap();
        vdc.verify().unwrap();
        assert_eq!(vdc.kind, MandateKind::Checkout);
    }

    #[test]
    fn tampered_vdc_fails_verify() {
        let signer = principal_signer();
        let checkout = make_checkout("did:tenzro:machine:shopper", 1_000);
        let mut vdc = Vdc::sign(
            &signer,
            "did:tenzro:human:principal",
            MandatePayload::Checkout(checkout),
        )
        .unwrap();
        // Bump max_amount post-signing.
        if let MandatePayload::Checkout(m) = &mut vdc.payload {
            m.max_amount = 1_000_000;
        }
        assert!(vdc.verify().is_err());
    }

    #[test]
    fn validator_accepts_payment_within_checkout() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let agent_did = "did:tenzro:machine:shopper";

        let checkout = make_checkout(agent_did, 10_000);
        let checkout_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        let payment = make_payment(&checkout.mandate_id, agent_did, 5_000);
        let payment_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Payment(payment)).unwrap();

        MandateValidator::new()
            .validate(&checkout_vdc, &payment_vdc)
            .unwrap();
    }

    #[test]
    fn validator_rejects_payment_over_ceiling() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let agent_did = "did:tenzro:machine:shopper";

        let checkout = make_checkout(agent_did, 1_000);
        let checkout_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        let payment = make_payment(&checkout.mandate_id, agent_did, 5_000);
        let payment_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Payment(payment)).unwrap();

        let err = MandateValidator::new()
            .validate(&checkout_vdc, &payment_vdc)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds checkout ceiling"));
    }

    #[test]
    fn validator_rejects_wrong_agent() {
        let principal = principal_signer();
        let agent_a = Ed25519SignerImpl::generate().unwrap();
        let agent_b = Ed25519SignerImpl::generate().unwrap();

        let checkout = make_checkout("did:tenzro:machine:agent-a", 10_000);
        let checkout_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        // Payment claims agent-b signed, and actually is signed by agent-b
        // — but the checkout delegates to agent-a.
        let payment = make_payment(&checkout.mandate_id, "did:tenzro:machine:agent-b", 100);
        let payment_vdc = Vdc::sign(
            &agent_b,
            "did:tenzro:machine:agent-b",
            MandatePayload::Payment(payment),
        )
        .unwrap();

        let err = MandateValidator::new()
            .validate(&checkout_vdc, &payment_vdc)
            .unwrap_err();
        assert!(err.to_string().contains("delegates to agent"));
        // Compile-check: unused signer does not leak across tests.
        let _ = agent_a.public_key();
    }

    #[test]
    fn payment_total_mismatch_fails() {
        let mut payment = make_payment("checkout-1", "did:tenzro:machine:shopper", 100);
        payment.total_amount = 999; // tamper
        assert!(payment.check_total().is_err());
    }

    #[test]
    fn validator_rejects_chain_not_in_accepted_list() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let agent_did = "did:tenzro:machine:shopper";

        // Principal pins the settlement rail whitelist to {tenzro, tempo}.
        let checkout = make_checkout(agent_did, 10_000)
            .with_accepted_chains(vec!["tenzro".into(), "tempo".into()]);
        let checkout_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        // Agent picks "ethereum" — not on the whitelist.
        let mut payment = make_payment(&checkout.mandate_id, agent_did, 5_000);
        payment.chain = "ethereum".into();
        let payment_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Payment(payment)).unwrap();

        let err = MandateValidator::new()
            .validate(&checkout_vdc, &payment_vdc)
            .unwrap_err();
        assert!(
            err.to_string().contains("accepted_chains"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validator_accepts_when_chain_in_accepted_list() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let agent_did = "did:tenzro:machine:shopper";

        // Whitelist includes the chain the agent ends up picking.
        let checkout = make_checkout(agent_did, 10_000)
            .with_accepted_chains(vec!["tenzro".into(), "tempo".into()]);
        let checkout_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        // `make_payment` defaults `chain = "tenzro"`.
        let payment = make_payment(&checkout.mandate_id, agent_did, 5_000);
        let payment_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Payment(payment)).unwrap();

        MandateValidator::new()
            .validate(&checkout_vdc, &payment_vdc)
            .unwrap();
    }

    #[test]
    fn validator_accepts_when_accepted_chains_empty() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let agent_did = "did:tenzro:machine:shopper";

        // Empty whitelist = any chain admitted.
        let checkout = make_checkout(agent_did, 10_000);
        assert!(checkout.accepted_chains.is_empty());
        let checkout_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        let mut payment = make_payment(&checkout.mandate_id, agent_did, 5_000);
        payment.chain = "ethereum".into(); // exotic rail, but whitelist is open
        let payment_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Payment(payment)).unwrap();

        MandateValidator::new()
            .validate(&checkout_vdc, &payment_vdc)
            .unwrap();
    }

    // -----------------------------------------------------------------
    // validate_with_delegation — AP2 + TDIP cross-validation
    // -----------------------------------------------------------------

    use tenzro_identity::delegation::DelegationScope;
    use tenzro_identity::IdentityRegistry;
    use tenzro_types::identity::KycTier;

    /// Build a registry containing a human controller and a machine agent
    /// with the given delegation scope. Returns `(human_did, machine_did)`.
    async fn registry_with_human_and_machine(
        scope: DelegationScope,
    ) -> (IdentityRegistry, String, String) {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(vec![1; 32], "Alice".into(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity;
        let machine = registry
            .register_machine_with_fee(&human.did_string(), vec![2; 32], vec![], scope)
            .await
            .unwrap()
            .identity;
        (registry, human.did_string(), machine.did_string())
    }

    fn signed_checkout_and_payment(
        principal_did: &str,
        agent_did: &str,
        checkout_max: u128,
        payment_total: u128,
    ) -> (Vdc, Vdc) {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();

        let mut checkout = make_checkout(agent_did, checkout_max);
        checkout.principal_did = principal_did.to_string();

        let checkout_vdc = Vdc::sign(
            &principal,
            principal_did,
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();
        let payment = make_payment(&checkout.mandate_id, agent_did, payment_total);
        let payment_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Payment(payment)).unwrap();
        (checkout_vdc, payment_vdc)
    }

    #[tokio::test]
    async fn validate_with_delegation_accepts_when_tdip_admits_payment() {
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, &machine_did, 10_000, 5_000);

        MandateValidator::new()
            .validate_with_delegation(&checkout_vdc, &payment_vdc, &registry)
            .unwrap();
    }

    #[tokio::test]
    async fn validate_with_delegation_rejects_when_payment_op_missing() {
        // Scope allows "inference" but not "payment".
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["inference".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, &machine_did, 10_000, 5_000);

        let err = MandateValidator::new()
            .validate_with_delegation(&checkout_vdc, &payment_vdc, &registry)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TDIP delegation rejected"),
            "expected TDIP rejection prefix, got: {msg}"
        );
    }

    #[tokio::test]
    async fn validate_with_delegation_rejects_when_payment_exceeds_tdip_cap() {
        // AP2 intent allows up to 10_000, but TDIP scope caps at 1_000.
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(1_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, &machine_did, 10_000, 5_000);

        let err = MandateValidator::new()
            .validate_with_delegation(&checkout_vdc, &payment_vdc, &registry)
            .unwrap_err();
        assert!(
            err.to_string().contains("TDIP delegation rejected"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn validate_with_delegation_rejects_unknown_agent_did() {
        // Registry has a different machine; the AP2 payment mandate references one
        // that was never registered.
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, _machine_did) =
            registry_with_human_and_machine(scope).await;

        let bogus_agent = "did:tenzro:machine:not-registered";
        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, bogus_agent, 10_000, 5_000);

        let err = MandateValidator::new()
            .validate_with_delegation(&checkout_vdc, &payment_vdc, &registry)
            .unwrap_err();
        assert!(
            err.to_string().contains("TDIP delegation rejected"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn validate_with_delegation_rejects_when_ap2_validation_fails() {
        // AP2 layer should fail first (payment total > checkout ceiling) — the
        // method must short-circuit before touching the registry.
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(u128::MAX);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, &machine_did, 1_000, 5_000);

        let err = MandateValidator::new()
            .validate_with_delegation(&checkout_vdc, &payment_vdc, &registry)
            .unwrap_err();
        // "exceeds checkout ceiling" comes from the AP2 layer, NOT the
        // TDIP-rejection wrapper — proves AP2 ran first.
        assert!(
            err.to_string().contains("exceeds checkout ceiling"),
            "expected AP2 ceiling error, got: {err}"
        );
    }

    // ----- Phase C: SpendingPolicy gate via validate_with_delegation_and_policy

    /// Test resolver — returns a fixed snapshot regardless of DID.
    struct StaticPolicyResolver(crate::identity_binding::SpendingPolicySnapshot);

    impl crate::identity_binding::SpendingPolicyResolver for StaticPolicyResolver {
        fn resolve(
            &self,
            _payer_did: &str,
        ) -> crate::Result<Option<crate::identity_binding::SpendingPolicySnapshot>> {
            Ok(Some(self.0))
        }
    }

    #[tokio::test]
    async fn validate_with_policy_rejects_when_runtime_per_tx_cap_exceeded() {
        // AP2 intent + TDIP scope both allow up to 10_000, but the runtime
        // SpendingPolicy says max_per_transaction = 2_000.
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, &machine_did, 10_000, 5_000);

        let resolver = StaticPolicyResolver(
            crate::identity_binding::SpendingPolicySnapshot {
                max_per_transaction: 2_000,
                max_daily_spend: 100_000,
                current_daily_spend: 0,
                enabled: true,
            },
        );

        let err = MandateValidator::new()
            .validate_with_delegation_and_policy(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                Some(&resolver),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("runtime SpendingPolicy rejected"),
            "expected runtime policy error, got: {err}"
        );
    }

    #[tokio::test]
    async fn validate_with_policy_rejects_when_daily_spend_exceeded() {
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(u128::MAX);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, &machine_did, 10_000, 5_000);

        // Per-tx OK, but already 8_000 spent today against a 10_000 cap →
        // 8_000 + 5_000 > 10_000.
        let resolver = StaticPolicyResolver(
            crate::identity_binding::SpendingPolicySnapshot {
                max_per_transaction: 1_000_000,
                max_daily_spend: 10_000,
                current_daily_spend: 8_000,
                enabled: true,
            },
        );

        let err = MandateValidator::new()
            .validate_with_delegation_and_policy(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                Some(&resolver),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("runtime SpendingPolicy rejected"),
            "expected runtime policy error, got: {err}"
        );
    }

    #[tokio::test]
    async fn validate_with_policy_passes_when_within_limits() {
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, &machine_did, 10_000, 5_000);

        let resolver = StaticPolicyResolver(
            crate::identity_binding::SpendingPolicySnapshot {
                max_per_transaction: 10_000,
                max_daily_spend: 100_000,
                current_daily_spend: 0,
                enabled: true,
            },
        );

        MandateValidator::new()
            .validate_with_delegation_and_policy(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                Some(&resolver),
            )
            .expect("all three layers should admit the payment");
    }

    #[tokio::test]
    async fn validate_with_policy_disabled_passes_through() {
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (checkout_vdc, payment_vdc) =
            signed_checkout_and_payment(&human_did, &machine_did, 10_000, 5_000);

        // Tight ceilings that *would* reject — but `enabled: false` flips
        // the policy off entirely, so the payment goes through.
        let resolver = StaticPolicyResolver(
            crate::identity_binding::SpendingPolicySnapshot {
                max_per_transaction: 1,
                max_daily_spend: 1,
                current_daily_spend: 0,
                enabled: false,
            },
        );

        MandateValidator::new()
            .validate_with_delegation_and_policy(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                Some(&resolver),
            )
            .expect("disabled policy must not reject");
    }

    // ----- Phase D: AP2 v0.2 cnf (RFC 7800) key-binding via TDIP DID

    /// Like [`registry_with_human_and_machine`], but registers each identity
    /// using the actual Ed25519 public key that signs the corresponding VDC.
    /// Without this, `verify_with_registry` rejects the cnf=did binding
    /// because the registry's stored key doesn't match the signer's key.
    async fn registry_bound_to_signers(
        scope: DelegationScope,
        principal_pk: Vec<u8>,
        agent_pk: Vec<u8>,
    ) -> (IdentityRegistry, String, String) {
        let registry = IdentityRegistry::new();
        let human = registry
            .register_human_with_fee(principal_pk, "Alice".into(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity;
        let machine = registry
            .register_machine_with_fee(&human.did_string(), agent_pk, vec![], scope)
            .await
            .unwrap()
            .identity;
        (registry, human.did_string(), machine.did_string())
    }

    /// Sign a checkout/payment VDC pair AND attach `cnf=did` claims that
    /// point back at the principal/agent DIDs. Used to drive
    /// `verify_with_registry` through its full check sequence.
    fn signed_checkout_and_payment_with_cnf(
        principal_signer: &Ed25519SignerImpl,
        agent_signer: &Ed25519SignerImpl,
        principal_did: &str,
        agent_did: &str,
        checkout_max: u128,
        payment_total: u128,
    ) -> (Vdc, Vdc) {
        let mut checkout = make_checkout(agent_did, checkout_max);
        checkout.principal_did = principal_did.to_string();
        checkout = checkout.with_cnf(MandateCnf::Did(principal_did.to_string()));

        let checkout_vdc = Vdc::sign(
            principal_signer,
            principal_did,
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        let payment = make_payment(&checkout.mandate_id, agent_did, payment_total)
            .with_cnf(MandateCnf::Did(agent_did.to_string()));
        let payment_vdc = Vdc::sign(
            agent_signer,
            agent_did,
            MandatePayload::Payment(payment),
        )
        .unwrap();
        (checkout_vdc, payment_vdc)
    }

    #[tokio::test]
    async fn verify_with_registry_passes_when_cnf_did_resolves_to_signer_key() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let principal_pk = principal.public_key().as_bytes().to_vec();
        let agent_pk = agent.public_key().as_bytes().to_vec();

        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) =
            registry_bound_to_signers(scope, principal_pk, agent_pk).await;

        let (checkout_vdc, payment_vdc) = signed_checkout_and_payment_with_cnf(
            &principal,
            &agent,
            &human_did,
            &machine_did,
            10_000,
            5_000,
        );

        checkout_vdc.verify_with_registry(&registry).unwrap();
        payment_vdc.verify_with_registry(&registry).unwrap();
    }

    #[tokio::test]
    async fn verify_with_registry_rejects_when_cnf_did_unregistered() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        // Registry knows about the human, but not this fake machine DID.
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, _real_machine_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let bogus_agent_did = "did:tenzro:machine:fake:0000-0000-0000";
        let (_checkout_vdc, payment_vdc) = signed_checkout_and_payment_with_cnf(
            &principal,
            &agent,
            &human_did,
            bogus_agent_did,
            10_000,
            5_000,
        );

        let err = payment_vdc.verify_with_registry(&registry).unwrap_err();
        assert!(
            err.to_string().contains("does not resolve"),
            "expected resolution failure, got: {err}"
        );
    }

    #[tokio::test]
    async fn verify_with_registry_rejects_when_cnf_did_disagrees_with_signer_did() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        // Build a payment whose cnf.did names the human DID, but signed
        // by the agent's key — a confusion attack. The verifier MUST
        // reject before resolving.
        let mut payment = make_payment("checkout-id", &machine_did, 5_000);
        payment = payment.with_cnf(MandateCnf::Did(human_did.clone()));
        let payment_vdc =
            Vdc::sign(&agent, &machine_did, MandatePayload::Payment(payment)).unwrap();

        let err = payment_vdc.verify_with_registry(&registry).unwrap_err();
        assert!(
            err.to_string().contains("does not match VDC signer_did"),
            "expected cnf↔signer_did mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn verify_with_registry_rejects_when_signer_key_not_listed_under_cnf_did() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let other_agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        // The registry binds machine_did to `agent`'s public key, but we
        // sign the payment with `other_agent` — same DID, wrong key.
        let (registry, _human_did, machine_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let mut payment = make_payment("checkout-id", &machine_did, 5_000);
        payment = payment.with_cnf(MandateCnf::Did(machine_did.clone()));
        let payment_vdc = Vdc::sign(
            &other_agent,
            &machine_did,
            MandatePayload::Payment(payment),
        )
        .unwrap();

        let err = payment_vdc.verify_with_registry(&registry).unwrap_err();
        assert!(
            err.to_string()
                .contains("does not list VDC signer_public_key"),
            "expected signer-key not-listed error, got: {err}"
        );
    }

    #[tokio::test]
    async fn verify_with_registry_passes_through_when_cnf_absent() {
        // No cnf set → registry is irrelevant, falls back to plain verify().
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let registry = IdentityRegistry::new();

        let (checkout_vdc, payment_vdc) = signed_checkout_and_payment(
            "did:tenzro:human:p",
            "did:tenzro:machine:a:1",
            10_000,
            5_000,
        );
        // Use locally-bound signers above so the helper actually exercises
        // signing — but we discard them; signed_checkout_and_payment
        // generates its own. The registry stays empty.
        let _ = (principal, agent);

        checkout_vdc.verify_with_registry(&registry).unwrap();
        payment_vdc.verify_with_registry(&registry).unwrap();
    }

    #[tokio::test]
    async fn verify_with_registry_jwk_must_match_signer_key() {
        use base64::{engine::general_purpose, Engine as _};
        let agent = Ed25519SignerImpl::generate().unwrap();
        let agent_pk_bytes = agent.public_key().as_bytes().to_vec();

        // Inline JWK whose `x` agrees with the signer key — must pass.
        let good_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": general_purpose::URL_SAFE_NO_PAD.encode(&agent_pk_bytes),
        });
        let mut payment = make_payment("checkout-id", "did:tenzro:machine:a:1", 5_000);
        payment = payment.with_cnf(MandateCnf::Jwk(good_jwk));
        let payment_vdc = Vdc::sign(
            &agent,
            "did:tenzro:machine:a:1",
            MandatePayload::Payment(payment),
        )
        .unwrap();

        let registry = IdentityRegistry::new();
        payment_vdc.verify_with_registry(&registry).unwrap();

        // Inline JWK whose `x` disagrees — must fail.
        let bad_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]),
        });
        let mut bad_payment =
            make_payment("checkout-id", "did:tenzro:machine:a:1", 5_000);
        bad_payment = bad_payment.with_cnf(MandateCnf::Jwk(bad_jwk));
        let bad_vdc = Vdc::sign(
            &agent,
            "did:tenzro:machine:a:1",
            MandatePayload::Payment(bad_payment),
        )
        .unwrap();
        let err = bad_vdc.verify_with_registry(&registry).unwrap_err();
        assert!(
            err.to_string()
                .contains("cnf.jwk.x does not match VDC signer_public_key"),
            "expected jwk mismatch, got: {err}"
        );
    }

    // ─── EscrowResolver wiring (#365 escrow binding) ──────────────────

    use crate::identity_binding::{EscrowResolver, EscrowSnapshot};

    /// In-memory `EscrowResolver` for tests. Returns whatever the test
    /// configured for a given `escrow_id`.
    struct StubEscrowResolver {
        snapshots: std::collections::HashMap<String, EscrowSnapshot>,
    }

    impl StubEscrowResolver {
        fn new() -> Self {
            Self {
                snapshots: std::collections::HashMap::new(),
            }
        }

        fn insert(&mut self, snap: EscrowSnapshot) {
            self.snapshots.insert(snap.escrow_id.clone(), snap);
        }
    }

    impl EscrowResolver for StubEscrowResolver {
        fn resolve(&self, escrow_id: &str) -> Result<Option<EscrowSnapshot>> {
            Ok(self.snapshots.get(escrow_id).cloned())
        }
    }

    /// Build a (checkout, payment) VDC pair both bound to `escrow_id` via
    /// `with_escrow`, plus matching `cnf=did` claims so the registry path
    /// passes.
    #[allow(clippy::too_many_arguments)]
    fn signed_pair_with_escrow(
        principal_signer: &Ed25519SignerImpl,
        agent_signer: &Ed25519SignerImpl,
        principal_did: &str,
        agent_did: &str,
        checkout_max: u128,
        payment_total: u128,
        escrow_id: &str,
    ) -> (Vdc, Vdc) {
        let mut checkout = make_checkout(agent_did, checkout_max);
        checkout.principal_did = principal_did.to_string();
        checkout = checkout
            .with_cnf(MandateCnf::Did(principal_did.to_string()))
            .with_escrow(escrow_id);

        let checkout_vdc = Vdc::sign(
            principal_signer,
            principal_did,
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        let payment = make_payment(&checkout.mandate_id, agent_did, payment_total)
            .with_cnf(MandateCnf::Did(agent_did.to_string()))
            .with_escrow(escrow_id);
        let payment_vdc = Vdc::sign(
            agent_signer,
            agent_did,
            MandatePayload::Payment(payment),
        )
        .unwrap();
        (checkout_vdc, payment_vdc)
    }

    #[tokio::test]
    async fn escrow_path_admits_when_snapshot_matches_mandate_pair() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let escrow_id = "escrow-happy";
        let (checkout_vdc, payment_vdc) = signed_pair_with_escrow(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            escrow_id,
        );

        let mut resolver = StubEscrowResolver::new();
        resolver.insert(EscrowSnapshot {
            escrow_id: escrow_id.to_string(),
            payer_did: Some(principal_did.clone()),
            payee_did: Some(agent_did.clone()),
            amount: 10_000,
            asset: "USDC".into(),
            releasable: true,
        });

        let validator = MandateValidator::new();
        validator
            .validate_with_delegation_policy_and_escrow(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                Some(&resolver),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn escrow_path_rejects_when_id_does_not_resolve() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let (checkout_vdc, payment_vdc) = signed_pair_with_escrow(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            "escrow-missing",
        );

        let resolver = StubEscrowResolver::new(); // empty
        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_and_escrow(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                Some(&resolver),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("does not resolve on-chain"),
            "expected on-chain miss, got: {err}"
        );
    }

    #[tokio::test]
    async fn escrow_path_rejects_when_resolver_is_absent_but_id_is_set() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let (checkout_vdc, payment_vdc) = signed_pair_with_escrow(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            "escrow-orphan",
        );

        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_and_escrow(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("no EscrowResolver is wired"),
            "expected wiring error, got: {err}"
        );
    }

    #[tokio::test]
    async fn escrow_path_rejects_when_total_exceeds_locked_amount() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let escrow_id = "escrow-underfunded";
        let (checkout_vdc, payment_vdc) = signed_pair_with_escrow(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            escrow_id,
        );

        let mut resolver = StubEscrowResolver::new();
        resolver.insert(EscrowSnapshot {
            escrow_id: escrow_id.to_string(),
            payer_did: Some(principal_did.clone()),
            payee_did: Some(agent_did.clone()),
            amount: 1_000, // less than payment_total = 5_000
            asset: "USDC".into(),
            releasable: true,
        });

        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_and_escrow(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                Some(&resolver),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeds escrow"),
            "expected underfunding rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn escrow_path_rejects_when_not_releasable() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let escrow_id = "escrow-already-released";
        let (checkout_vdc, payment_vdc) = signed_pair_with_escrow(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            escrow_id,
        );

        let mut resolver = StubEscrowResolver::new();
        resolver.insert(EscrowSnapshot {
            escrow_id: escrow_id.to_string(),
            payer_did: Some(principal_did.clone()),
            payee_did: Some(agent_did.clone()),
            amount: 10_000,
            asset: "USDC".into(),
            releasable: false,
        });

        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_and_escrow(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                Some(&resolver),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("not releasable"),
            "expected releasability rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn escrow_path_rejects_when_principal_did_mismatch() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let escrow_id = "escrow-wrong-payer";
        let (checkout_vdc, payment_vdc) = signed_pair_with_escrow(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            escrow_id,
        );

        let mut resolver = StubEscrowResolver::new();
        resolver.insert(EscrowSnapshot {
            escrow_id: escrow_id.to_string(),
            // Someone ELSE funded an escrow by this name. Refuse to settle.
            payer_did: Some("did:tenzro:human:other".into()),
            payee_did: Some(agent_did.clone()),
            amount: 10_000,
            asset: "USDC".into(),
            releasable: true,
        });

        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_and_escrow(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                Some(&resolver),
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match CheckoutMandate principal"),
            "expected payer mismatch rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn escrow_path_skipped_when_no_escrow_id_on_pair() {
        // Mandate pair carries no escrow_id at all → off-chain rail.
        // EscrowResolver presence is irrelevant; should pass.
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let principal_pk = principal.public_key().as_bytes().to_vec();
        let agent_pk = agent.public_key().as_bytes().to_vec();

        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) =
            registry_bound_to_signers(scope, principal_pk, agent_pk).await;

        let (checkout_vdc, payment_vdc) = signed_checkout_and_payment_with_cnf(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
        );

        let resolver = StubEscrowResolver::new();
        let validator = MandateValidator::new();
        validator
            .validate_with_delegation_policy_and_escrow(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                Some(&resolver),
            )
            .unwrap();
    }

    // ─── SptCeilingResolver wiring (#383 SPT payment-mandate ceiling) ────

    use crate::mpp::stripe_spt::{
        SptCeilingResolver, SptCeilingSnapshot, SptStatus, UsageLimits,
    };

    /// In-memory `SptCeilingResolver` for tests. Returns whatever the
    /// test configured for a given `granted_token_id`.
    struct StubSptResolver {
        snapshots: std::collections::HashMap<String, SptCeilingSnapshot>,
    }

    impl StubSptResolver {
        fn new() -> Self {
            Self {
                snapshots: std::collections::HashMap::new(),
            }
        }

        fn insert(&mut self, snap: SptCeilingSnapshot) {
            self.snapshots.insert(snap.granted_token_id.clone(), snap);
        }
    }

    impl SptCeilingResolver for StubSptResolver {
        fn resolve(&self, granted_token_id: &str) -> Result<Option<SptCeilingSnapshot>> {
            Ok(self.snapshots.get(granted_token_id).cloned())
        }
    }

    /// Build a (checkout, payment) VDC pair both bound to `spt_grant_id`
    /// via `with_spt_grant`, plus matching `cnf=did` claims so the
    /// registry path passes.
    #[allow(clippy::too_many_arguments)]
    fn signed_pair_with_spt_grant(
        principal_signer: &Ed25519SignerImpl,
        agent_signer: &Ed25519SignerImpl,
        principal_did: &str,
        agent_did: &str,
        checkout_max: u128,
        payment_total: u128,
        spt_grant_id: &str,
        asset: &str,
    ) -> (Vdc, Vdc) {
        let mut checkout = CheckoutMandate::new(
            principal_did,
            agent_did,
            "test checkout",
            checkout_max,
            asset,
            3600,
        );
        checkout = checkout
            .with_cnf(MandateCnf::Did(principal_did.to_string()))
            .with_spt_grant(spt_grant_id);
        let checkout_vdc = Vdc::sign(
            principal_signer,
            principal_did,
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        let payment = PaymentMandate::new(
            &checkout.mandate_id,
            agent_did,
            "did:tenzro:merchant:acme",
            vec![CartItem {
                sku: "sku-1".into(),
                description: "widget".into(),
                quantity: 1,
                unit_price: payment_total,
                total: payment_total,
                category: Some("widgets".into()),
            }],
            asset,
            "tenzro",
            300,
        )
        .with_cnf(MandateCnf::Did(agent_did.to_string()))
        .with_spt_grant(spt_grant_id);
        let payment_vdc =
            Vdc::sign(agent_signer, agent_did, MandatePayload::Payment(payment))
                .unwrap();
        (checkout_vdc, payment_vdc)
    }

    fn active_snapshot(grant_id: &str, max_amount: u64, currency: &str) -> SptCeilingSnapshot {
        SptCeilingSnapshot {
            granted_token_id: grant_id.to_string(),
            issued_token_id: Some("spt_iss_test".to_string()),
            status: SptStatus::Active,
            usage_limits: UsageLimits {
                currency: currency.to_string(),
                max_amount,
                // 1 hour from now
                expires_at: chrono::Utc::now().timestamp() + 3600,
            },
        }
    }

    #[tokio::test]
    async fn spt_path_admits_when_snapshot_covers_payment_total() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let grant_id = "spt_grant_happy";
        let (checkout_vdc, payment_vdc) = signed_pair_with_spt_grant(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            grant_id,
            "USD",
        );

        let mut spt = StubSptResolver::new();
        spt.insert(active_snapshot(grant_id, 10_000, "USD"));

        let validator = MandateValidator::new();
        validator
            .validate_with_delegation_policy_escrow_and_spt(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                None,
                Some(&spt),
            )
            .unwrap();
    }

    #[tokio::test]
    async fn spt_path_rejects_when_payment_exceeds_max_amount() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let grant_id = "spt_grant_overdraw";
        // checkout_max=10_000 admits payment 8_000, but the SPT cap is 5_000.
        let (checkout_vdc, payment_vdc) = signed_pair_with_spt_grant(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            8_000,
            grant_id,
            "USD",
        );

        let mut spt = StubSptResolver::new();
        spt.insert(active_snapshot(grant_id, 5_000, "USD"));

        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_escrow_and_spt(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                None,
                Some(&spt),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("exceeds max_amount"),
            "expected SPT max_amount rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn spt_path_rejects_when_currency_does_not_match_asset() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let grant_id = "spt_grant_currency_mismatch";
        // Cart in USDC; SPT in USD. Hard fail.
        let (checkout_vdc, payment_vdc) = signed_pair_with_spt_grant(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            grant_id,
            "USDC",
        );

        let mut spt = StubSptResolver::new();
        spt.insert(active_snapshot(grant_id, 10_000, "USD"));

        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_escrow_and_spt(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                None,
                Some(&spt),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("currency mismatch"),
            "expected SPT currency mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn spt_path_rejects_when_id_does_not_resolve() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let grant_id = "spt_grant_unknown";
        let (checkout_vdc, payment_vdc) = signed_pair_with_spt_grant(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            grant_id,
            "USD",
        );

        // Resolver knows nothing about this grant_id — must hard-fail
        // since the mandate explicitly committed to it.
        let spt = StubSptResolver::new();

        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_escrow_and_spt(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                None,
                Some(&spt),
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("does not resolve"),
            "expected SPT does-not-resolve rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn spt_path_rejects_when_resolver_unwired_but_mandate_carries_grant_id() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let (checkout_vdc, payment_vdc) = signed_pair_with_spt_grant(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
            "spt_grant_resolver_missing",
            "USD",
        );

        // No resolver wired but mandate carries a grant_id → hard fail.
        let validator = MandateValidator::new();
        let err = validator
            .validate_with_delegation_policy_escrow_and_spt(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("no SptCeilingResolver is wired"),
            "expected unwired-resolver rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn spt_path_skipped_when_no_grant_id_on_pair() {
        // Mandate pair carries no spt_grant_id at all → SPT ceiling is
        // skipped, even with no resolver. This is the off-Stripe rail.
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, principal_did, agent_did) = registry_bound_to_signers(
            scope,
            principal.public_key().as_bytes().to_vec(),
            agent.public_key().as_bytes().to_vec(),
        )
        .await;

        let (checkout_vdc, payment_vdc) = signed_checkout_and_payment_with_cnf(
            &principal,
            &agent,
            &principal_did,
            &agent_did,
            10_000,
            5_000,
        );

        let validator = MandateValidator::new();
        validator
            .validate_with_delegation_policy_escrow_and_spt(
                &checkout_vdc,
                &payment_vdc,
                &registry,
                None,
                None,
                None,
            )
            .unwrap();
    }

    #[test]
    fn validate_rejects_spt_grant_id_mismatch_between_mandates() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let principal_did = "did:tenzro:human:principal";
        let agent_did = "did:tenzro:machine:agent:1";

        // Checkout binds spt_grant_A; payment binds spt_grant_B —
        // mismatch must be rejected even with no resolver wired.
        let checkout = make_checkout(agent_did, 10_000).with_spt_grant("spt_grant_A");
        let checkout_vdc = Vdc::sign(
            &principal,
            principal_did,
            MandatePayload::Checkout(checkout.clone()),
        )
        .unwrap();

        let payment = make_payment(&checkout.mandate_id, agent_did, 5_000)
            .with_spt_grant("spt_grant_B");
        let payment_vdc = Vdc::sign(
            &agent,
            agent_did,
            MandatePayload::Payment(payment),
        )
        .unwrap();

        let validator = MandateValidator::new();
        let err = validator.validate(&checkout_vdc, &payment_vdc).unwrap_err();
        assert!(
            err.to_string().contains("spt_grant_id mismatch"),
            "expected spt_grant_id mismatch rejection, got: {err}"
        );
    }
}
