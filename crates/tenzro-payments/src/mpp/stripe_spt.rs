//! Stripe Shared Payment Token (SPT) — agentic payment primitive.
//!
//! Stripe's Shared Payment Token is the Issuing-layer credential that lets an
//! agent spend a customer's PaymentMethod under cryptographically-scoped caps
//! without ever holding the underlying card data. Two resources, two halves of
//! the same token:
//!
//! - [`SharedPaymentIssuedToken`] — created by the agent (the AI platform / SA
//!   in AP2 terms) via the agent's Stripe secret key. Carries the underlying
//!   PaymentMethod reference and `usage_limits`.
//! - [`SharedPaymentGrantedToken`] — what the seller (merchant / CP) receives.
//!   Carries `usage_limits`, last-four, brand. Confirmed via PaymentIntent
//!   with `payment_method_data[shared_payment_granted_token]=spt_…`.
//!
//! `usage_limits` is the field that carries the spend ceiling: `{ currency,
//! max_amount, expires_at }`. Stripe enforces its copy at PaymentIntent confirm time;
//! Tenzro's [`SptCeilingResolver`] enforces a TDIP-rooted copy alongside
//! [`DelegationScope`] and [`SpendingPolicy`] — **whichever is stricter wins**.
//!
//! # Lifecycle
//!
//! `requires_action` → `active` → `used` / `deactivated`.
//!
//! - Issued in `requires_action` if the customer needs to authenticate
//!   (3DS / SCA).
//! - Becomes `active` when authentication clears.
//! - `used` after the seller's PaymentIntent confirms.
//! - `deactivated` on revoke (`POST /v1/shared_payment/issued_tokens/{id}/revoke`)
//!   or expiry.
//!
//! Webhook event family: `shared_payment.issued_token.*` (created / activated
//! / used) and `shared_payment.granted_token.deactivated`. Revoke events
//! trigger TDIP `apply_remote_revocation()` cascade in the surrounding gateway.
//!
//! # Tenzro extensions
//!
//! - **DID-anchored issuance.** TDIP DID Document carries
//!   `service[].type = "StripeSPT"` (see
//!   [`tenzro_identity::SERVICE_TYPE_STRIPE_SPT`]).
//! - **DelegationScope ↔ `usage_limits` mapping.**
//!   `DelegationScope.max_transaction_value` projects to
//!   `usage_limits.max_amount`; `time_bound.expires_at` projects to
//!   `usage_limits.expires_at`.
//! - **Four-ceiling enforcement.** [`SptCeilingResolver`] sits alongside
//!   [`SpendingPolicyResolver`] in [`IdentityPaymentBinder`]. The four
//!   ceilings are: `DelegationScope` (structural), runtime `SpendingPolicy`
//!   (daily window), Stripe SPT `usage_limits` (per-token cap), and the AP2
//!   payment mandate's `total_amount`.
//! - **ERC-8004 reputation cross-write.** SPT outcomes —
//!   [`SptOutcome::Succeeded`] / [`SptOutcome::Disputed`] /
//!   [`SptOutcome::ChargebackWon`] / [`SptOutcome::ChargebackLost`] — fan
//!   out to `ReputationRegistry.submitFeedback` at precompile `0x101b`.

use crate::error::{PaymentError, Result};
use crate::mpp::stripe::StripeClient;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Stripe API version header value.
///
/// Kept in sync with [`crate::mpp::stripe`] so SPT and PaymentIntent calls
/// pin the same Stripe API release.
const STRIPE_API_VERSION: &str = "2025-12-18.acacia";

/// Stripe SharedPaymentToken lifecycle status.
///
/// State machine: `RequiresAction → Active → Used | Deactivated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SptStatus {
    /// Token is awaiting customer authentication (3DS / SCA).
    RequiresAction,
    /// Token is authorized and ready for the seller to confirm a PaymentIntent.
    Active,
    /// Seller has confirmed the PaymentIntent against this token.
    Used,
    /// Token was revoked by the agent or expired.
    Deactivated,
}

impl SptStatus {
    /// True when the token can be used to confirm a fresh PaymentIntent.
    pub fn is_confirmable(&self) -> bool {
        matches!(self, SptStatus::Active)
    }

    /// Static label used in error messages and JSON envelopes.
    pub fn as_str(&self) -> &'static str {
        match self {
            SptStatus::RequiresAction => "requires_action",
            SptStatus::Active => "active",
            SptStatus::Used => "used",
            SptStatus::Deactivated => "deactivated",
        }
    }
}

/// Per-token usage caps, enforced by Stripe at PaymentIntent confirm time and
/// mirrored into Tenzro's [`SptCeilingResolver`] gate.
///
/// `max_amount` is in the smallest currency unit (e.g., cents for USD) for
/// fiat currencies, matching Stripe's PaymentIntent convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageLimits {
    /// Three-letter ISO currency code (e.g., "usd").
    pub currency: String,
    /// Maximum amount the seller can charge against this token, smallest
    /// currency unit.
    pub max_amount: u64,
    /// Token expiry (Unix epoch seconds). After this, Stripe rejects
    /// confirms regardless of `max_amount`.
    pub expires_at: i64,
}

impl UsageLimits {
    /// Returns `Ok(())` if a PaymentIntent of `amount` in `currency` would
    /// be admitted by these limits. Pure check — does not record the
    /// drawdown.
    pub fn check(&self, amount: u64, currency: &str) -> Result<()> {
        if !currency.eq_ignore_ascii_case(&self.currency) {
            return Err(PaymentError::VerificationFailed(format!(
                "SPT usage_limits currency mismatch: token={}, request={}",
                self.currency, currency
            )));
        }
        if amount > self.max_amount {
            return Err(PaymentError::VerificationFailed(format!(
                "SPT usage_limits amount {} exceeds max_amount {}",
                amount, self.max_amount
            )));
        }
        let now = Utc::now().timestamp();
        if now >= self.expires_at {
            return Err(PaymentError::VerificationFailed(format!(
                "SPT usage_limits expired at {} (now={})",
                self.expires_at, now
            )));
        }
        Ok(())
    }
}

/// `SharedPaymentIssuedToken` — agent-side resource.
///
/// Created by the agent via `POST /v1/shared_payment/issued_tokens` with a
/// `secret key`. The agent receives this back; the seller never sees it.
/// Sharing with a seller produces a sibling [`SharedPaymentGrantedToken`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPaymentIssuedToken {
    /// Token ID (`spt_iss_...`).
    pub id: String,
    /// Object type (always "shared_payment.issued_token").
    pub object: String,
    /// Lifecycle status.
    pub status: SptStatus,
    /// PaymentMethod this token references (`pm_...`).
    pub payment_method: String,
    /// Stripe Customer this token is bound to (`cus_...`), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<String>,
    /// Per-token usage caps.
    pub usage_limits: UsageLimits,
    /// Created timestamp (Unix epoch seconds).
    #[serde(default)]
    pub created: i64,
    /// Stripe-assigned metadata.
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// `SharedPaymentGrantedToken` — seller-side resource.
///
/// What the merchant receives. Carries `usage_limits` plus card-display
/// metadata (last-four, brand). Confirmed via PaymentIntent with
/// `payment_method_data[shared_payment_granted_token]=spt_grant_...`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPaymentGrantedToken {
    /// Token ID (`spt_grant_...`).
    pub id: String,
    /// Object type (always "shared_payment.granted_token").
    pub object: String,
    /// Lifecycle status.
    pub status: SptStatus,
    /// Per-token usage caps. Identical to the parent issued-token's limits.
    pub usage_limits: UsageLimits,
    /// Last 4 digits of the underlying card.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last4: Option<String>,
    /// Card brand ("visa", "mastercard", "amex", etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    /// Created timestamp (Unix epoch seconds).
    #[serde(default)]
    pub created: i64,
    /// Stripe-assigned metadata.
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// SPT settlement outcome — feeds the ERC-8004 `ReputationRegistry`
/// cross-write at precompile `0x101b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SptOutcome {
    /// PaymentIntent confirmed and settled cleanly.
    Succeeded,
    /// Cardholder filed a dispute; chargeback unresolved.
    Disputed,
    /// Chargeback resolved in the seller's favor.
    ChargebackWon,
    /// Chargeback resolved against the seller.
    ChargebackLost,
}

impl SptOutcome {
    /// Static label used in webhook bodies and reputation feedback rows.
    pub fn as_str(&self) -> &'static str {
        match self {
            SptOutcome::Succeeded => "succeeded",
            SptOutcome::Disputed => "disputed",
            SptOutcome::ChargebackWon => "chargeback_won",
            SptOutcome::ChargebackLost => "chargeback_lost",
        }
    }

    /// ERC-8004 feedback score on a 0..=100 scale. Mirrors the convention
    /// used by [`tenzro_identity::erc8004::FeedbackKind`]: success → 100,
    /// dispute → 50, chargeback won → 75, chargeback lost → 0.
    pub fn reputation_score(&self) -> u8 {
        match self {
            SptOutcome::Succeeded => 100,
            SptOutcome::ChargebackWon => 75,
            SptOutcome::Disputed => 50,
            SptOutcome::ChargebackLost => 0,
        }
    }
}

/// Stripe SPT-specific webhook event types.
///
/// The `shared_payment.*` event family is documented upstream; specific
/// suffixes track Stripe's spec. This enum covers the four lifecycle states plus
/// the four downstream PaymentIntent / Charge settlement-outcome events
/// that feed the ERC-8004 [`ReputationRegistry`] cross-write at precompile
/// `0x101b`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SptWebhookEvent {
    // -- SPT lifecycle events --
    /// `shared_payment.issued_token.created` — token issued, may be
    /// `requires_action` until the customer authenticates.
    IssuedTokenCreated,
    /// `shared_payment.issued_token.activated` — customer authentication
    /// cleared; token is now confirmable.
    IssuedTokenActivated,
    /// `shared_payment.issued_token.used` — seller successfully confirmed
    /// a PaymentIntent against this token.
    IssuedTokenUsed,
    /// `shared_payment.granted_token.deactivated` — seller-side token
    /// has been revoked or has expired. Triggers TDIP cascade.
    GrantedTokenDeactivated,

    // -- PaymentIntent / Charge settlement-outcome events --
    /// `payment_intent.succeeded` — PaymentIntent confirmed and captured
    /// cleanly. Cross-writes [`SptOutcome::Succeeded`] to ERC-8004.
    PaymentIntentSucceeded,
    /// `payment_intent.payment_failed` — PaymentIntent confirm failed
    /// (issuer decline, fraud screen, etc.). Cross-writes
    /// [`SptOutcome::ChargebackLost`] to ERC-8004.
    PaymentIntentFailed,
    /// `charge.dispute.created` — cardholder filed a dispute against an
    /// SPT-authorized charge. Cross-writes [`SptOutcome::Disputed`] to
    /// ERC-8004 immediately; the dispute may later be won or lost and
    /// will surface a fresh feedback row when `charge.dispute.closed`
    /// arrives.
    ChargeDisputeCreated,
    /// `charge.dispute.closed` — dispute resolved. The Stripe payload
    /// carries `status = "won"` (chargeback won, seller keeps funds) or
    /// `status = "lost"` (chargeback lost, funds clawed back). The
    /// dispatcher inspects the body to map onto
    /// [`SptOutcome::ChargebackWon`] / [`SptOutcome::ChargebackLost`].
    ChargeDisputeClosed,

    /// Unrecognized event type.
    Unknown(String),
}

impl SptWebhookEvent {
    /// Parses a Stripe webhook event-type string.
    pub fn from_type(event_type: &str) -> Self {
        match event_type {
            // SPT lifecycle
            "shared_payment.issued_token.created" => Self::IssuedTokenCreated,
            "shared_payment.issued_token.activated" => Self::IssuedTokenActivated,
            "shared_payment.issued_token.used" => Self::IssuedTokenUsed,
            "shared_payment.granted_token.deactivated" => Self::GrantedTokenDeactivated,
            // PaymentIntent / Charge settlement outcomes
            "payment_intent.succeeded" => Self::PaymentIntentSucceeded,
            "payment_intent.payment_failed" => Self::PaymentIntentFailed,
            "charge.dispute.created" => Self::ChargeDisputeCreated,
            "charge.dispute.closed" => Self::ChargeDisputeClosed,
            other if other.starts_with("shared_payment.") => Self::Unknown(other.to_string()),
            other => Self::Unknown(other.to_string()),
        }
    }

    /// True when this event indicates the token can no longer settle —
    /// either it was used or it was deactivated. Triggers TDIP
    /// `apply_remote_revocation()` cascade for the granted-token path.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SptWebhookEvent::IssuedTokenUsed | SptWebhookEvent::GrantedTokenDeactivated
        )
    }

    /// True when this event carries a settlement outcome that should be
    /// cross-written to the ERC-8004 [`ReputationRegistry`] precompile at
    /// `0x101b`. The mapping from event → [`SptOutcome`] for unambiguous
    /// events is provided by [`Self::settlement_outcome`]; ambiguous
    /// events ([`Self::ChargeDisputeClosed`]) require the dispatcher to
    /// inspect the body for `status = "won" | "lost"`.
    pub fn is_settlement_outcome(&self) -> bool {
        matches!(
            self,
            SptWebhookEvent::PaymentIntentSucceeded
                | SptWebhookEvent::PaymentIntentFailed
                | SptWebhookEvent::ChargeDisputeCreated
                | SptWebhookEvent::ChargeDisputeClosed
        )
    }

    /// Maps an unambiguous settlement-outcome event onto its
    /// [`SptOutcome`]. Returns `None` for events that either are not
    /// settlement-outcome events or whose outcome depends on payload
    /// inspection (e.g. `charge.dispute.closed` which can be won or lost).
    pub fn settlement_outcome(&self) -> Option<SptOutcome> {
        match self {
            SptWebhookEvent::PaymentIntentSucceeded => Some(SptOutcome::Succeeded),
            SptWebhookEvent::PaymentIntentFailed => Some(SptOutcome::ChargebackLost),
            SptWebhookEvent::ChargeDisputeCreated => Some(SptOutcome::Disputed),
            // ChargeDisputeClosed needs the dispatcher to inspect
            // `status` in the payload to pick won vs. lost.
            SptWebhookEvent::ChargeDisputeClosed => None,
            _ => None,
        }
    }
}

/// Snapshot of an active Stripe SPT, projected into the payment-gate view.
///
/// `tenzro-payments` does not depend on Stripe's wire types in its trait
/// surface — the resolver implementor (typically `tenzro-node`) projects
/// [`SharedPaymentGrantedToken`] into this struct. `granted_token_id` is
/// the credential the gate is checking against; `issued_token_id` is the
/// agent-side parent (used by the revoke path on cascade).
#[derive(Debug, Clone)]
pub struct SptCeilingSnapshot {
    /// Granted-token ID (`spt_grant_...`) the merchant presented.
    pub granted_token_id: String,
    /// Parent issued-token ID (`spt_iss_...`) for revoke cascade.
    pub issued_token_id: Option<String>,
    /// Lifecycle status — only `Active` admits a fresh confirm.
    pub status: SptStatus,
    /// Per-token caps.
    pub usage_limits: UsageLimits,
}

impl SptCeilingSnapshot {
    /// Returns `Ok(())` if a PaymentIntent of `amount` in `currency` would
    /// be admitted by this snapshot. Pure check.
    pub fn check(&self, amount: u64, currency: &str) -> Result<()> {
        if !self.status.is_confirmable() {
            return Err(PaymentError::VerificationFailed(format!(
                "SPT {} is {} (not confirmable)",
                self.granted_token_id,
                self.status.as_str()
            )));
        }
        self.usage_limits.check(amount, currency)
    }
}

/// Resolves the Stripe SPT ceiling for a granted-token reference.
///
/// Implemented by `tenzro-node` to bridge a Stripe API call (or a cached
/// snapshot) into the payment gate. Returning `Ok(None)` means the
/// credential under inspection does not carry a granted-token reference —
/// the gate then falls back to the [`DelegationScope`] +
/// [`SpendingPolicy`] enforcement only.
///
/// [`DelegationScope`]: tenzro_identity::DelegationScope
/// [`SpendingPolicy`]: crate::SpendingPolicySnapshot
pub trait SptCeilingResolver: Send + Sync {
    /// Resolves the SPT snapshot for `granted_token_id`. Returns
    /// `Ok(None)` when the token is unknown to the resolver (caller
    /// should treat this as a *missing* credential, not a *valid*
    /// credential — same as the `SpendingPolicyResolver` pattern).
    fn resolve(&self, granted_token_id: &str) -> Result<Option<SptCeilingSnapshot>>;
}

impl StripeClient {
    /// Creates a `SharedPaymentIssuedToken` via
    /// `POST /v1/shared_payment/issued_tokens`.
    ///
    /// The agent supplies a customer-bound PaymentMethod and the per-token
    /// usage caps the seller is permitted to draw against. Returned token
    /// is `requires_action` if the customer must complete 3DS / SCA;
    /// otherwise immediately `active`.
    ///
    /// # Arguments
    /// - `payment_method`: Stripe PaymentMethod ID (`pm_...`)
    /// - `customer`: Optional Stripe Customer ID (`cus_...`)
    /// - `limits`: per-token usage caps
    /// - `metadata`: free-form metadata (e.g., `{"agent_did": "did:tenzro:machine:..."}`)
    pub async fn create_issued_token(
        &self,
        payment_method: &str,
        customer: Option<&str>,
        limits: &UsageLimits,
        metadata: &[(&str, &str)],
    ) -> Result<SharedPaymentIssuedToken> {
        info!(
            "Creating Stripe SharedPaymentIssuedToken: pm={} currency={} max_amount={}",
            payment_method, limits.currency, limits.max_amount
        );

        let mut form: Vec<(String, String)> = vec![
            ("payment_method".into(), payment_method.to_string()),
            ("usage_limits[currency]".into(), limits.currency.clone()),
            (
                "usage_limits[max_amount]".into(),
                limits.max_amount.to_string(),
            ),
            (
                "usage_limits[expires_at]".into(),
                limits.expires_at.to_string(),
            ),
        ];
        if let Some(cust) = customer {
            form.push(("customer".into(), cust.to_string()));
        }
        for (k, v) in metadata {
            form.push((format!("metadata[{}]", k), (*v).to_string()));
        }

        let body = self
            .post_form(
                "/v1/shared_payment/issued_tokens",
                form,
                Some(uuid::Uuid::new_v4().to_string()),
            )
            .await?;

        let token: SharedPaymentIssuedToken = serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse SharedPaymentIssuedToken: {}",
                e
            ))
        })?;

        debug!(
            "Created SharedPaymentIssuedToken: id={} status={:?}",
            token.id, token.status
        );
        Ok(token)
    }

    /// Retrieves a `SharedPaymentGrantedToken` via
    /// `GET /v1/shared_payment/granted_tokens/:id`.
    ///
    /// Used by the seller-side gate to re-fetch an SPT before confirming a
    /// PaymentIntent against it (e.g., to verify the token is still
    /// `active` and the limits haven't tightened).
    pub async fn retrieve_granted_token(
        &self,
        granted_token_id: &str,
    ) -> Result<SharedPaymentGrantedToken> {
        debug!(
            "Retrieving Stripe SharedPaymentGrantedToken: {}",
            granted_token_id
        );

        let body = self
            .get(&format!(
                "/v1/shared_payment/granted_tokens/{}",
                granted_token_id
            ))
            .await?;

        serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse SharedPaymentGrantedToken: {}",
                e
            ))
        })
    }

    /// Revokes an issued token via
    /// `POST /v1/shared_payment/issued_tokens/:id/revoke`.
    ///
    /// Agent-side kill switch. After revoke, both the issued token and any
    /// granted tokens derived from it move to `deactivated`. Stripe emits a
    /// `shared_payment.granted_token.deactivated` webhook for each affected
    /// granted token.
    pub async fn revoke_issued_token(
        &self,
        issued_token_id: &str,
    ) -> Result<SharedPaymentIssuedToken> {
        info!("Revoking Stripe SharedPaymentIssuedToken: {}", issued_token_id);

        let body = self
            .post_form(
                &format!(
                    "/v1/shared_payment/issued_tokens/{}/revoke",
                    issued_token_id
                ),
                Vec::new(),
                None,
            )
            .await?;

        serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse revoked SharedPaymentIssuedToken: {}",
                e
            ))
        })
    }

    /// Confirms a PaymentIntent against a granted-token reference via
    /// `POST /v1/payment_intents/:id/confirm` with
    /// `payment_method_data[shared_payment_granted_token]=...`.
    ///
    /// The intent's `amount` and `currency` MUST be `<=` the granted
    /// token's `usage_limits.max_amount` and match its currency, otherwise
    /// Stripe rejects the confirm. The caller is expected to validate
    /// against the local [`SptCeilingSnapshot`] *before* calling this — to
    /// fail fast and avoid the round trip — but Stripe is the authoritative
    /// gate.
    pub async fn confirm_intent_with_spt(
        &self,
        payment_intent_id: &str,
        granted_token_id: &str,
    ) -> Result<crate::mpp::stripe::PaymentIntent> {
        info!(
            "Confirming PaymentIntent {} with SPT granted_token={}",
            payment_intent_id, granted_token_id
        );

        let form = vec![(
            "payment_method_data[shared_payment_granted_token]".to_string(),
            granted_token_id.to_string(),
        )];

        let body = self
            .post_form(
                &format!("/v1/payment_intents/{}/confirm", payment_intent_id),
                form,
                None,
            )
            .await?;

        serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!(
                "Failed to parse confirmed PaymentIntent: {}",
                e
            ))
        })
    }
}

/// `WebhookEvent` typed dispatcher for the SPT family.
///
/// Mirrors the existing `MppWebhookEvent` pattern: parse the raw event,
/// classify it into an [`SptWebhookEvent`] variant, and surface the
/// embedded resource (issued or granted token) for the caller to act on.
pub fn classify_spt_webhook(
    event: &crate::mpp::stripe::WebhookEvent,
) -> SptWebhookEvent {
    SptWebhookEvent::from_type(&event.event_type)
}

/// Extracts a `SharedPaymentIssuedToken` from an SPT webhook event.
///
/// Returns `Err` if the event's `data.object` is not a parseable issued
/// token (e.g., the event is actually a granted-token event).
pub fn extract_issued_token(
    event: &crate::mpp::stripe::WebhookEvent,
) -> Result<SharedPaymentIssuedToken> {
    serde_json::from_value(event.data.object.clone()).map_err(|e| {
        PaymentError::SerializationError(format!(
            "Failed to parse SharedPaymentIssuedToken from webhook: {}",
            e
        ))
    })
}

/// Extracts a `SharedPaymentGrantedToken` from an SPT webhook event.
pub fn extract_granted_token(
    event: &crate::mpp::stripe::WebhookEvent,
) -> Result<SharedPaymentGrantedToken> {
    serde_json::from_value(event.data.object.clone()).map_err(|e| {
        PaymentError::SerializationError(format!(
            "Failed to parse SharedPaymentGrantedToken from webhook: {}",
            e
        ))
    })
}

// ---------------------------------------------------------------------------
// HTTP helpers — kept private inside the SPT module so they reuse the same
// auth + version pinning the PaymentIntent path uses, without leaking
// internal client state.
// ---------------------------------------------------------------------------

#[doc(hidden)]
impl StripeClient {
    /// Internal: authenticated GET against the Stripe API.
    pub(crate) async fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.api_base(), path);
        let response = self
            .http()
            .get(&url)
            .basic_auth(self.api_key(), Option::<&str>::None)
            .header("Stripe-Version", STRIPE_API_VERSION)
            .send()
            .await
            .map_err(|e| {
                PaymentError::NetworkError(format!("Stripe GET {} failed: {}", path, e))
            })?;
        let status = response.status();
        let body = response.text().await.map_err(|e| {
            PaymentError::NetworkError(format!("Failed to read Stripe response: {}", e))
        })?;
        if !status.is_success() {
            warn!(
                "Stripe API GET {} returned {}: {}",
                path,
                status,
                body.chars().take(200).collect::<String>()
            );
            return Err(PaymentError::SettlementError(format!(
                "Stripe API error ({}): {}",
                status,
                body.chars().take(200).collect::<String>()
            )));
        }
        Ok(body)
    }

    /// Internal: authenticated POST with form-encoded body. `idempotency_key`
    /// is set as the `Idempotency-Key` header when supplied.
    pub(crate) async fn post_form(
        &self,
        path: &str,
        form: Vec<(String, String)>,
        idempotency_key: Option<String>,
    ) -> Result<String> {
        let url = format!("{}{}", self.api_base(), path);
        let mut req = self
            .http()
            .post(&url)
            .basic_auth(self.api_key(), Option::<&str>::None)
            .header("Stripe-Version", STRIPE_API_VERSION);
        if let Some(key) = idempotency_key {
            req = req.header("Idempotency-Key", key);
        }
        let response = req.form(&form).send().await.map_err(|e| {
            PaymentError::NetworkError(format!("Stripe POST {} failed: {}", path, e))
        })?;
        let status = response.status();
        let body = response.text().await.map_err(|e| {
            PaymentError::NetworkError(format!("Failed to read Stripe response: {}", e))
        })?;
        if !status.is_success() {
            warn!(
                "Stripe API POST {} returned {}: {}",
                path,
                status,
                body.chars().take(200).collect::<String>()
            );
            return Err(PaymentError::SettlementError(format!(
                "Stripe API error ({}): {}",
                status,
                body.chars().take(200).collect::<String>()
            )));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spt_status_confirmable() {
        assert!(SptStatus::Active.is_confirmable());
        assert!(!SptStatus::RequiresAction.is_confirmable());
        assert!(!SptStatus::Used.is_confirmable());
        assert!(!SptStatus::Deactivated.is_confirmable());
    }

    #[test]
    fn usage_limits_check_passes_within_caps() {
        let limits = UsageLimits {
            currency: "usd".to_string(),
            max_amount: 5000,
            expires_at: Utc::now().timestamp() + 3600,
        };
        assert!(limits.check(1000, "usd").is_ok());
        assert!(limits.check(5000, "USD").is_ok()); // case-insensitive
    }

    #[test]
    fn usage_limits_rejects_overdraw() {
        let limits = UsageLimits {
            currency: "usd".to_string(),
            max_amount: 5000,
            expires_at: Utc::now().timestamp() + 3600,
        };
        let err = limits.check(5001, "usd").unwrap_err();
        assert!(err.to_string().contains("max_amount"));
    }

    #[test]
    fn usage_limits_rejects_currency_mismatch() {
        let limits = UsageLimits {
            currency: "usd".to_string(),
            max_amount: 5000,
            expires_at: Utc::now().timestamp() + 3600,
        };
        let err = limits.check(100, "eur").unwrap_err();
        assert!(err.to_string().contains("currency mismatch"));
    }

    #[test]
    fn usage_limits_rejects_expired() {
        let limits = UsageLimits {
            currency: "usd".to_string(),
            max_amount: 5000,
            expires_at: Utc::now().timestamp() - 1,
        };
        let err = limits.check(100, "usd").unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn ceiling_snapshot_blocks_non_active_status() {
        let snap = SptCeilingSnapshot {
            granted_token_id: "spt_grant_test".to_string(),
            issued_token_id: None,
            status: SptStatus::Used,
            usage_limits: UsageLimits {
                currency: "usd".to_string(),
                max_amount: 5000,
                expires_at: Utc::now().timestamp() + 3600,
            },
        };
        let err = snap.check(100, "usd").unwrap_err();
        assert!(err.to_string().contains("not confirmable"));
    }

    #[test]
    fn ceiling_snapshot_passes_when_active_and_within_limits() {
        let snap = SptCeilingSnapshot {
            granted_token_id: "spt_grant_test".to_string(),
            issued_token_id: Some("spt_iss_test".to_string()),
            status: SptStatus::Active,
            usage_limits: UsageLimits {
                currency: "usd".to_string(),
                max_amount: 5000,
                expires_at: Utc::now().timestamp() + 3600,
            },
        };
        assert!(snap.check(2500, "usd").is_ok());
    }

    #[test]
    fn outcome_reputation_score_ordering() {
        assert!(
            SptOutcome::Succeeded.reputation_score()
                > SptOutcome::ChargebackWon.reputation_score()
        );
        assert!(
            SptOutcome::ChargebackWon.reputation_score()
                > SptOutcome::Disputed.reputation_score()
        );
        assert!(
            SptOutcome::Disputed.reputation_score() > SptOutcome::ChargebackLost.reputation_score()
        );
    }

    #[test]
    fn webhook_event_classification() {
        assert_eq!(
            SptWebhookEvent::from_type("shared_payment.issued_token.created"),
            SptWebhookEvent::IssuedTokenCreated
        );
        assert_eq!(
            SptWebhookEvent::from_type("shared_payment.issued_token.activated"),
            SptWebhookEvent::IssuedTokenActivated
        );
        assert_eq!(
            SptWebhookEvent::from_type("shared_payment.issued_token.used"),
            SptWebhookEvent::IssuedTokenUsed
        );
        assert_eq!(
            SptWebhookEvent::from_type("shared_payment.granted_token.deactivated"),
            SptWebhookEvent::GrantedTokenDeactivated
        );
        match SptWebhookEvent::from_type("shared_payment.something.new") {
            SptWebhookEvent::Unknown(s) => assert_eq!(s, "shared_payment.something.new"),
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn webhook_terminal_classification() {
        assert!(SptWebhookEvent::IssuedTokenUsed.is_terminal());
        assert!(SptWebhookEvent::GrantedTokenDeactivated.is_terminal());
        assert!(!SptWebhookEvent::IssuedTokenCreated.is_terminal());
        assert!(!SptWebhookEvent::IssuedTokenActivated.is_terminal());
    }

    #[test]
    fn settlement_outcome_event_classification() {
        assert_eq!(
            SptWebhookEvent::from_type("payment_intent.succeeded"),
            SptWebhookEvent::PaymentIntentSucceeded
        );
        assert_eq!(
            SptWebhookEvent::from_type("payment_intent.payment_failed"),
            SptWebhookEvent::PaymentIntentFailed
        );
        assert_eq!(
            SptWebhookEvent::from_type("charge.dispute.created"),
            SptWebhookEvent::ChargeDisputeCreated
        );
        assert_eq!(
            SptWebhookEvent::from_type("charge.dispute.closed"),
            SptWebhookEvent::ChargeDisputeClosed
        );
    }

    #[test]
    fn settlement_outcome_predicate_is_disjoint_from_lifecycle() {
        // Lifecycle events are NOT settlement outcomes.
        assert!(!SptWebhookEvent::IssuedTokenCreated.is_settlement_outcome());
        assert!(!SptWebhookEvent::IssuedTokenActivated.is_settlement_outcome());
        assert!(!SptWebhookEvent::IssuedTokenUsed.is_settlement_outcome());
        assert!(!SptWebhookEvent::GrantedTokenDeactivated.is_settlement_outcome());
        // Settlement-outcome events ARE.
        assert!(SptWebhookEvent::PaymentIntentSucceeded.is_settlement_outcome());
        assert!(SptWebhookEvent::PaymentIntentFailed.is_settlement_outcome());
        assert!(SptWebhookEvent::ChargeDisputeCreated.is_settlement_outcome());
        assert!(SptWebhookEvent::ChargeDisputeClosed.is_settlement_outcome());
    }

    #[test]
    fn settlement_outcome_mapping_for_unambiguous_events() {
        assert_eq!(
            SptWebhookEvent::PaymentIntentSucceeded.settlement_outcome(),
            Some(SptOutcome::Succeeded)
        );
        assert_eq!(
            SptWebhookEvent::PaymentIntentFailed.settlement_outcome(),
            Some(SptOutcome::ChargebackLost)
        );
        assert_eq!(
            SptWebhookEvent::ChargeDisputeCreated.settlement_outcome(),
            Some(SptOutcome::Disputed)
        );
        // Closed dispute is ambiguous — caller must inspect payload.
        assert_eq!(SptWebhookEvent::ChargeDisputeClosed.settlement_outcome(), None);
        // Lifecycle events have no settlement outcome.
        assert_eq!(SptWebhookEvent::IssuedTokenCreated.settlement_outcome(), None);
        assert_eq!(SptWebhookEvent::GrantedTokenDeactivated.settlement_outcome(), None);
    }

    #[test]
    fn issued_token_deserializes_with_status_and_limits() {
        let json = r#"{
            "id": "spt_iss_test",
            "object": "shared_payment.issued_token",
            "status": "active",
            "payment_method": "pm_test",
            "customer": "cus_test",
            "usage_limits": {
                "currency": "usd",
                "max_amount": 5000,
                "expires_at": 9999999999
            },
            "created": 1700000000,
            "metadata": {"agent_did": "did:tenzro:machine:abc"}
        }"#;
        let token: SharedPaymentIssuedToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.id, "spt_iss_test");
        assert_eq!(token.status, SptStatus::Active);
        assert_eq!(token.usage_limits.max_amount, 5000);
        assert_eq!(
            token.metadata.get("agent_did").map(String::as_str),
            Some("did:tenzro:machine:abc")
        );
    }

    #[test]
    fn granted_token_deserializes_with_card_metadata() {
        let json = r#"{
            "id": "spt_grant_test",
            "object": "shared_payment.granted_token",
            "status": "active",
            "usage_limits": {
                "currency": "usd",
                "max_amount": 5000,
                "expires_at": 9999999999
            },
            "last4": "4242",
            "brand": "visa",
            "created": 1700000000,
            "metadata": {}
        }"#;
        let token: SharedPaymentGrantedToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.id, "spt_grant_test");
        assert_eq!(token.last4.as_deref(), Some("4242"));
        assert_eq!(token.brand.as_deref(), Some("visa"));
    }
}
