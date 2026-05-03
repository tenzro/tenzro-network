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
//! - **`IntentMandate`** — the principal's *pre-authorization*. It says
//!   "agent X may spend up to Y on resources matching Z before T". It is
//!   the AP2 analogue of a [`tenzro_identity::DelegationScope`] and is
//!   cross-validated against one when the payer DID is a TDIP identity.
//! - **`CartMandate`** — the agent's *final-offer bundle*: a specific
//!   cart of line items, a total, and a merchant. The agent signs it to
//!   commit, and the principal countersigns to authorize settlement.
//! - **`Vdc`** — a generic Verifiable Digital Credential wrapper over any
//!   mandate, carrying an Ed25519 signature plus a JCS-style canonical
//!   preimage so verification is deterministic.
//! - **`MandateValidator`** — composes intent → cart verification,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateKind {
    Intent,
    Cart,
}

/// Presence semantics for the principal — AP2 distinguishes between
/// *human-present* flows (principal approves cart in real time) and
/// *human-not-present* flows (principal pre-delegated via IntentMandate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceMode {
    /// Principal is online and confirming the cart interactively.
    #[default]
    HumanPresent,
    /// Principal pre-delegated; agent commits unilaterally within scope.
    HumanNotPresent,
}

/// AP2 IntentMandate — the principal's pre-authorization envelope.
///
/// The agent cannot spend outside of the limits expressed here, and the
/// `MandateValidator` enforces those limits when it later sees a
/// `CartMandate` signed by the same agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentMandate {
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
    /// Free-form metadata (merchant hints, session ID, refund policy …).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl IntentMandate {
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
            max_uses: Some(1),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            presence: PresenceMode::default(),
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

    pub fn with_max_uses(mut self, uses: Option<u32>) -> Self {
        self.max_uses = uses;
        self
    }

    pub fn with_presence(mut self, presence: PresenceMode) -> Self {
        self.presence = presence;
        self
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// A single line item in a CartMandate.
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

/// AP2 CartMandate — the agent's committed purchase bundle.
///
/// Signed by the agent; optionally countersigned by the principal in
/// human-present flows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CartMandate {
    /// Unique cart mandate ID.
    pub mandate_id: String,
    /// ID of the parent [`IntentMandate`]. Must exist and be non-expired
    /// when the cart is validated.
    pub intent_mandate_id: String,
    /// Agent committing to this cart.
    pub agent_did: String,
    /// Merchant receiving the payment.
    pub merchant_did: String,
    /// Line items.
    pub items: Vec<CartItem>,
    /// Total (should equal the sum of line `total`s).
    pub total_amount: u128,
    /// Asset (must match the parent intent).
    pub asset: String,
    /// Chain / settlement rail.
    pub chain: String,
    /// When the agent committed to this cart.
    pub committed_at: DateTime<Utc>,
    /// Expiry of the cart offer.
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl CartMandate {
    pub fn new(
        intent_mandate_id: impl Into<String>,
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
            intent_mandate_id: intent_mandate_id.into(),
            agent_did: agent_did.into(),
            merchant_did: merchant_did.into(),
            items,
            total_amount: total,
            asset: asset.into(),
            chain: chain.into(),
            committed_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            metadata: HashMap::new(),
        }
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
    Intent(IntentMandate),
    Cart(CartMandate),
}

impl MandatePayload {
    pub fn kind(&self) -> MandateKind {
        match self {
            MandatePayload::Intent(_) => MandateKind::Intent,
            MandatePayload::Cart(_) => MandateKind::Cart,
        }
    }

    pub fn mandate_id(&self) -> &str {
        match self {
            MandatePayload::Intent(m) => &m.mandate_id,
            MandatePayload::Cart(m) => &m.mandate_id,
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
    /// DID of the signer (principal for intent, agent for cart).
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
        let kind = payload.kind();

        let preimage = serde_json::to_vec(&VdcPreimage {
            tag: "ap2",
            version: AP2_VERSION,
            kind,
            payload: &payload,
            signer_did: &signer_did,
            signer_public_key: &signer_public_key,
        })
        .map_err(|e| PaymentError::SerializationError(format!("vdc preimage: {e}")))?;

        let sig = signer
            .sign(&preimage)
            .map_err(|e| PaymentError::CryptoError(e.to_string()))?;

        Ok(Self {
            version: AP2_VERSION.to_string(),
            kind,
            payload,
            signer_did,
            signer_public_key,
            signature: sig.as_bytes().to_vec(),
            alg: "ed25519".to_string(),
        })
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

    pub fn mandate_id(&self) -> &str {
        self.payload.mandate_id()
    }

    pub fn as_intent(&self) -> Option<&IntentMandate> {
        match &self.payload {
            MandatePayload::Intent(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_cart(&self) -> Option<&CartMandate> {
        match &self.payload {
            MandatePayload::Cart(m) => Some(m),
            _ => None,
        }
    }
}

/// Composite validator enforcing intent → cart constraints.
///
/// Typical flow:
///
/// 1. Merchant receives a signed `Vdc` wrapping a `CartMandate` from
///    the agent.
/// 2. Merchant also holds the signed `Vdc` wrapping the parent
///    `IntentMandate` (provided by the principal out-of-band or
///    attached to the cart envelope).
/// 3. Merchant calls [`MandateValidator::validate`] passing both.
/// 4. On success, the merchant submits the cart total on-chain.
#[derive(Default)]
pub struct MandateValidator;

impl MandateValidator {
    pub fn new() -> Self {
        Self
    }

    /// Validate a `CartMandate` against a parent `IntentMandate`.
    ///
    /// Both VDCs must pass signature verification independently first.
    pub fn validate(&self, intent_vdc: &Vdc, cart_vdc: &Vdc) -> Result<()> {
        intent_vdc.verify()?;
        cart_vdc.verify()?;

        let intent = intent_vdc.as_intent().ok_or_else(|| {
            PaymentError::CredentialError("parent VDC is not an IntentMandate".into())
        })?;
        let cart = cart_vdc.as_cart().ok_or_else(|| {
            PaymentError::CredentialError("child VDC is not a CartMandate".into())
        })?;

        if intent.is_expired() {
            return Err(PaymentError::VerificationFailed(
                "IntentMandate expired".into(),
            ));
        }
        if cart.is_expired() {
            return Err(PaymentError::VerificationFailed(
                "CartMandate expired".into(),
            ));
        }

        if cart.intent_mandate_id != intent.mandate_id {
            return Err(PaymentError::VerificationFailed(format!(
                "cart.intent_mandate_id {} does not match intent.mandate_id {}",
                cart.intent_mandate_id, intent.mandate_id
            )));
        }

        // The intent VDC must have been signed by the principal; the
        // cart VDC by the delegated agent.
        if intent_vdc.signer_did != intent.principal_did {
            return Err(PaymentError::VerificationFailed(format!(
                "intent signer {} != principal {}",
                intent_vdc.signer_did, intent.principal_did
            )));
        }
        if cart_vdc.signer_did != cart.agent_did {
            return Err(PaymentError::VerificationFailed(format!(
                "cart signer {} != agent {}",
                cart_vdc.signer_did, cart.agent_did
            )));
        }
        if intent.agent_did != cart.agent_did {
            return Err(PaymentError::VerificationFailed(format!(
                "intent delegates to agent {} but cart was signed by {}",
                intent.agent_did, cart.agent_did
            )));
        }

        if intent.asset != cart.asset {
            return Err(PaymentError::VerificationFailed(format!(
                "asset mismatch: intent={}, cart={}",
                intent.asset, cart.asset
            )));
        }

        cart.check_total()?;

        if cart.total_amount > intent.max_amount {
            return Err(PaymentError::VerificationFailed(format!(
                "cart total {} exceeds intent ceiling {}",
                cart.total_amount, intent.max_amount
            )));
        }

        if !intent.allowed_merchants.is_empty()
            && !intent.allowed_merchants.contains(&cart.merchant_did)
        {
            return Err(PaymentError::VerificationFailed(format!(
                "merchant {} not in intent allow-list",
                cart.merchant_did
            )));
        }

        if !intent.allowed_categories.is_empty() {
            for item in &cart.items {
                let Some(cat) = item.category.as_ref() else {
                    return Err(PaymentError::VerificationFailed(format!(
                        "cart item {} missing category (intent restricts categories)",
                        item.sku
                    )));
                };
                if !intent.allowed_categories.contains(cat) {
                    return Err(PaymentError::VerificationFailed(format!(
                        "category {} not in intent allow-list",
                        cat
                    )));
                }
            }
        }

        Ok(())
    }

    /// Like [`Self::validate`], but additionally cross-checks the agent's
    /// TDIP delegation scope.
    ///
    /// AP2's IntentMandate is the *principal-facing* delegation envelope; the
    /// TDIP DelegationScope is the *protocol-facing* one. Both must allow the
    /// purchase: the IntentMandate caps the spend (`max_amount`,
    /// `allowed_merchants`, `allowed_categories`, expiry) and the TDIP scope
    /// caps the agent's broader operating envelope (`max_transaction_value`,
    /// `allowed_operations`, reputation floor, controller liveness).
    ///
    /// Returns `Ok(())` only when both layers admit the cart. Failures from
    /// the TDIP layer are wrapped as [`PaymentError::VerificationFailed`] so
    /// the caller does not need to bridge two error types.
    ///
    /// The operation name passed to TDIP enforcement is `"payment"`. Callers
    /// that want a finer-grained name (e.g. `"payment.ap2"`) should call
    /// [`IdentityRegistry::enforce_operation`] directly *in addition* to
    /// [`Self::validate`].
    pub fn validate_with_delegation(
        &self,
        intent_vdc: &Vdc,
        cart_vdc: &Vdc,
        identity_registry: &IdentityRegistry,
    ) -> Result<()> {
        self.validate_with_delegation_and_policy(
            intent_vdc,
            cart_vdc,
            identity_registry,
            None,
        )
    }

    /// Like [`Self::validate_with_delegation`], but additionally consults a
    /// runtime [`SpendingPolicyResolver`] so the cart is rejected if the
    /// agent's *runtime* per-transaction or per-day ceiling would be
    /// exceeded.
    ///
    /// AP2 carries three nested ceilings, all of which must admit the cart:
    ///
    /// 1. **AP2 IntentMandate** — the principal-signed declaration of intent
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
        intent_vdc: &Vdc,
        cart_vdc: &Vdc,
        identity_registry: &IdentityRegistry,
        policy_resolver: Option<&dyn crate::identity_binding::SpendingPolicyResolver>,
    ) -> Result<()> {
        self.validate(intent_vdc, cart_vdc)?;

        // Safe — `validate()` proved the cart is a CartMandate.
        let cart = cart_vdc
            .as_cart()
            .expect("validate() established cart payload");

        identity_registry
            .enforce_operation(&cart.agent_did, "payment", Some(cart.total_amount))
            .map_err(|e| {
                PaymentError::VerificationFailed(format!(
                    "TDIP delegation rejected AP2 cart for agent {}: {}",
                    cart.agent_did, e
                ))
            })?;

        if let Some(resolver) = policy_resolver {
            if let Some(snap) = resolver.resolve(&cart.agent_did)? {
                snap.check(cart.total_amount).map_err(|e| {
                    PaymentError::VerificationFailed(format!(
                        "runtime SpendingPolicy rejected AP2 cart for agent {}: {}",
                        cart.agent_did, e
                    ))
                })?;
            }
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

    fn make_intent(agent_did: &str, max: u128) -> IntentMandate {
        IntentMandate::new(
            "did:tenzro:human:principal",
            agent_did,
            "test intent",
            max,
            "USDC",
            3600,
        )
    }

    fn make_cart(intent_id: &str, agent_did: &str, total: u128) -> CartMandate {
        CartMandate::new(
            intent_id,
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
    fn vdc_signs_and_verifies_intent() {
        let signer = principal_signer();
        let intent = make_intent("did:tenzro:machine:shopper", 1_000);
        let vdc = Vdc::sign(
            &signer,
            "did:tenzro:human:principal",
            MandatePayload::Intent(intent),
        )
        .unwrap();
        vdc.verify().unwrap();
        assert_eq!(vdc.kind, MandateKind::Intent);
    }

    #[test]
    fn tampered_vdc_fails_verify() {
        let signer = principal_signer();
        let intent = make_intent("did:tenzro:machine:shopper", 1_000);
        let mut vdc = Vdc::sign(
            &signer,
            "did:tenzro:human:principal",
            MandatePayload::Intent(intent),
        )
        .unwrap();
        // Bump max_amount post-signing.
        if let MandatePayload::Intent(m) = &mut vdc.payload {
            m.max_amount = 1_000_000;
        }
        assert!(vdc.verify().is_err());
    }

    #[test]
    fn validator_accepts_cart_within_intent() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let agent_did = "did:tenzro:machine:shopper";

        let intent = make_intent(agent_did, 10_000);
        let intent_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Intent(intent.clone()),
        )
        .unwrap();

        let cart = make_cart(&intent.mandate_id, agent_did, 5_000);
        let cart_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Cart(cart)).unwrap();

        MandateValidator::new()
            .validate(&intent_vdc, &cart_vdc)
            .unwrap();
    }

    #[test]
    fn validator_rejects_cart_over_ceiling() {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();
        let agent_did = "did:tenzro:machine:shopper";

        let intent = make_intent(agent_did, 1_000);
        let intent_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Intent(intent.clone()),
        )
        .unwrap();

        let cart = make_cart(&intent.mandate_id, agent_did, 5_000);
        let cart_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Cart(cart)).unwrap();

        let err = MandateValidator::new()
            .validate(&intent_vdc, &cart_vdc)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exceeds intent ceiling"));
    }

    #[test]
    fn validator_rejects_wrong_agent() {
        let principal = principal_signer();
        let agent_a = Ed25519SignerImpl::generate().unwrap();
        let agent_b = Ed25519SignerImpl::generate().unwrap();

        let intent = make_intent("did:tenzro:machine:agent-a", 10_000);
        let intent_vdc = Vdc::sign(
            &principal,
            "did:tenzro:human:principal",
            MandatePayload::Intent(intent.clone()),
        )
        .unwrap();

        // Cart claims agent-b signed, and actually is signed by agent-b
        // — but the intent delegates to agent-a.
        let cart = make_cart(&intent.mandate_id, "did:tenzro:machine:agent-b", 100);
        let cart_vdc = Vdc::sign(
            &agent_b,
            "did:tenzro:machine:agent-b",
            MandatePayload::Cart(cart),
        )
        .unwrap();

        let err = MandateValidator::new()
            .validate(&intent_vdc, &cart_vdc)
            .unwrap_err();
        assert!(err.to_string().contains("delegates to agent"));
        // Compile-check: unused signer does not leak across tests.
        let _ = agent_a.public_key();
    }

    #[test]
    fn cart_total_mismatch_fails() {
        let mut cart = make_cart("intent-1", "did:tenzro:machine:shopper", 100);
        cart.total_amount = 999; // tamper
        assert!(cart.check_total().is_err());
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

    fn signed_intent_and_cart(
        principal_did: &str,
        agent_did: &str,
        intent_max: u128,
        cart_total: u128,
    ) -> (Vdc, Vdc) {
        let principal = principal_signer();
        let agent = Ed25519SignerImpl::generate().unwrap();

        let mut intent = make_intent(agent_did, intent_max);
        intent.principal_did = principal_did.to_string();

        let intent_vdc = Vdc::sign(
            &principal,
            principal_did,
            MandatePayload::Intent(intent.clone()),
        )
        .unwrap();
        let cart = make_cart(&intent.mandate_id, agent_did, cart_total);
        let cart_vdc =
            Vdc::sign(&agent, agent_did, MandatePayload::Cart(cart)).unwrap();
        (intent_vdc, cart_vdc)
    }

    #[tokio::test]
    async fn validate_with_delegation_accepts_when_tdip_admits_payment() {
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, &machine_did, 10_000, 5_000);

        MandateValidator::new()
            .validate_with_delegation(&intent_vdc, &cart_vdc, &registry)
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

        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, &machine_did, 10_000, 5_000);

        let err = MandateValidator::new()
            .validate_with_delegation(&intent_vdc, &cart_vdc, &registry)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("TDIP delegation rejected"),
            "expected TDIP rejection prefix, got: {msg}"
        );
    }

    #[tokio::test]
    async fn validate_with_delegation_rejects_when_cart_exceeds_tdip_cap() {
        // AP2 intent allows up to 10_000, but TDIP scope caps at 1_000.
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(1_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, &machine_did, 10_000, 5_000);

        let err = MandateValidator::new()
            .validate_with_delegation(&intent_vdc, &cart_vdc, &registry)
            .unwrap_err();
        assert!(
            err.to_string().contains("TDIP delegation rejected"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn validate_with_delegation_rejects_unknown_agent_did() {
        // Registry has a different machine; the AP2 cart references one
        // that was never registered.
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, _machine_did) =
            registry_with_human_and_machine(scope).await;

        let bogus_agent = "did:tenzro:machine:not-registered";
        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, bogus_agent, 10_000, 5_000);

        let err = MandateValidator::new()
            .validate_with_delegation(&intent_vdc, &cart_vdc, &registry)
            .unwrap_err();
        assert!(
            err.to_string().contains("TDIP delegation rejected"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn validate_with_delegation_rejects_when_ap2_validation_fails() {
        // AP2 layer should fail first (cart total > intent ceiling) — the
        // method must short-circuit before touching the registry.
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(u128::MAX);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, &machine_did, 1_000, 5_000);

        let err = MandateValidator::new()
            .validate_with_delegation(&intent_vdc, &cart_vdc, &registry)
            .unwrap_err();
        // "exceeds intent ceiling" comes from the AP2 layer, NOT the
        // TDIP-rejection wrapper — proves AP2 ran first.
        assert!(
            err.to_string().contains("exceeds intent ceiling"),
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

        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, &machine_did, 10_000, 5_000);

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
                &intent_vdc,
                &cart_vdc,
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

        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, &machine_did, 10_000, 5_000);

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
                &intent_vdc,
                &cart_vdc,
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

        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, &machine_did, 10_000, 5_000);

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
                &intent_vdc,
                &cart_vdc,
                &registry,
                Some(&resolver),
            )
            .expect("all three layers should admit the cart");
    }

    #[tokio::test]
    async fn validate_with_policy_disabled_passes_through() {
        let scope = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["payment".into()])
            .with_max_transaction_value(10_000);
        let (registry, human_did, machine_did) =
            registry_with_human_and_machine(scope).await;

        let (intent_vdc, cart_vdc) =
            signed_intent_and_cart(&human_did, &machine_did, 10_000, 5_000);

        // Tight ceilings that *would* reject — but `enabled: false` flips
        // the policy off entirely, so the cart goes through.
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
                &intent_vdc,
                &cart_vdc,
                &registry,
                Some(&resolver),
            )
            .expect("disabled policy must not reject");
    }
}
