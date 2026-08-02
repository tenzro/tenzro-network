//! A2A x402 Extension — payment-required tasks via `Message.metadata`
//!
//! This module implements the x402-over-A2A wire format. An A2A server
//! that wants to charge for a task emits `state = input-required` plus a
//! `x402.payment.required` metadata entry; the client replies with a
//! signed `x402.payment.payload`; the server verifies, settles, and
//! emits `x402.payment.receipts` and `x402.payment.status =
//! payment-completed` before delivering the task result.
//!
//! ## Wire keys (all live in `Message.metadata`)
//!
//! | Direction | Key                       | Payload                           |
//! |-----------|---------------------------|-----------------------------------|
//! | server→client | `x402.payment.required` | [`PaymentRequirements`] + `accepts` array |
//! | client→server | `x402.payment.payload`  | signed [`PaymentPayload`] + taskId |
//! | server→client | `x402.payment.receipts` | array of [`PaymentReceipt`]      |
//! | both directions | `x402.payment.status` | string [`PaymentStatus`]         |
//!
//! ## States (`x402.payment.status`)
//!
//! - `payment-required` — server is asking for payment
//! - `payment-submitted` — client has posted a payload, server is verifying
//! - `payment-rejected` — payload failed verification
//! - `payment-verified` — payload accepted, settlement in flight
//! - `payment-completed` — settled on-chain, receipts ready
//! - `payment-failed` — settlement reverted or expired
//!
//! ## No version field
//!
//! Tenzro-owned wire shapes carry no version number. The metadata keys are
//! content-addressed by purpose
//! (`required`/`payload`/`receipts`/`status`); the schemes inside
//! [`PaymentRequirement`] are content-addressed by name
//! (`exact-eip3009`, `exact-permit2`, `exact-erc7710`). When the wire
//! shape changes, every speaker switches in the same change — flag-day
//! cutover, no coexistence.
//!
//! ## Hold-and-resume dispatcher contract
//!
//! The A2A server checks, on every inbound message:
//!
//! 1. If the task is `state = input-required` AND has
//!    `metadata.x402.payment.required`, the dispatcher does NOT route
//!    the message to the normal handler. Instead it expects the inbound
//!    message to carry `metadata.x402.payment.payload` and routes to
//!    [`handle_payment_payload`].
//! 2. On verification + settlement success the task is updated to
//!    `metadata.x402.payment.status = payment-completed` and
//!    `metadata.x402.payment.receipts = [...]`, and only then resumes
//!    to `state = working` and runs the original handler.
//! 3. On verification or settlement failure the task transitions to
//!    `state = failed` with `metadata.x402.payment.status =
//!    payment-rejected` (verify failure) or `payment-failed`
//!    (settlement failure), and the failure reason is surfaced as an
//!    agent-role text message.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────
// Metadata key constants — these are stable identifiers, not versioned
// ─────────────────────────────────────────────────────────────────────

/// Server→client: structured [`PaymentRequirements`].
pub const KEY_PAYMENT_REQUIRED: &str = "x402.payment.required";
/// Client→server: signed [`PaymentPayload`] + taskId.
pub const KEY_PAYMENT_PAYLOAD: &str = "x402.payment.payload";
/// Server→client: array of [`PaymentReceipt`] after settlement.
pub const KEY_PAYMENT_RECEIPTS: &str = "x402.payment.receipts";
/// Both directions: string [`PaymentStatus`].
pub const KEY_PAYMENT_STATUS: &str = "x402.payment.status";

// ─────────────────────────────────────────────────────────────────────
// Status enum
// ─────────────────────────────────────────────────────────────────────

/// One of six payment-protocol states. Serializes/deserializes as a
/// kebab-case string (e.g. `"payment-required"`). The variant names
/// share the `Payment` prefix to match the kebab-case wire form
/// (`payment-required`, `payment-completed`, …); the enum's name
/// already disambiguates, so suppress the lint asking for shorter
/// variant names.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentStatus {
    /// Server has emitted requirements; client must submit a payload.
    PaymentRequired,
    /// Client has submitted; server is verifying signature + amount.
    PaymentSubmitted,
    /// Payload failed signature, amount, or expiry checks.
    PaymentRejected,
    /// Payload accepted; settlement is in flight on-chain.
    PaymentVerified,
    /// Settlement confirmed; receipts written; original task can run.
    PaymentCompleted,
    /// Settlement reverted or expired; task is failed.
    PaymentFailed,
}

// ─────────────────────────────────────────────────────────────────────
// PaymentRequirements (server→client)
// ─────────────────────────────────────────────────────────────────────

/// What the server is willing to accept. The client picks one entry
/// from `accepts` and produces a [`PaymentPayload`] against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// One or more acceptable payment options. The client MAY pick any
    /// entry; the server MUST accept any of them.
    pub accepts: Vec<PaymentRequirement>,
    /// Optional human-readable reason this task requires payment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A single acceptable payment option.
///
/// `scheme` is content-addressed by name (`exact-eip3009`,
/// `exact-permit2`, `exact-erc7710`); the matching `extra` shape is
/// scheme-specific and lives under the scheme's own module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirement {
    /// Settlement scheme — `exact-eip3009`, `exact-permit2`, or
    /// `exact-erc7710`. New schemes are added here as named constants;
    /// no version field on the wire.
    pub scheme: String,
    /// CAIP-2 chain identifier (e.g. `"eip155:1"`, `"eip155:8453"`,
    /// `"tenzro:testnet"`).
    pub network: String,
    /// Amount in the asset's smallest unit, as a decimal string for
    /// arbitrary-precision support.
    pub amount: String,
    /// Asset identifier — for EVM, the ERC-20 contract address as
    /// `0x…`; for native TNZO, the literal string `"native"`.
    pub asset: String,
    /// Address that receives the funds.
    pub pay_to: String,
    /// Maximum seconds the client has to submit a payload before the
    /// requirement expires.
    pub max_timeout_seconds: u32,
    /// Scheme-specific parameters (Permit2 witness, EIP-3009 nonce
    /// pre-binding, etc.). Free-form JSON; structure validated by the
    /// scheme module, not by this extension.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────
// PaymentPayload (client→server)
// ─────────────────────────────────────────────────────────────────────

/// What the client posts back. Identifies which task and which scheme
/// it picked, and carries the scheme-specific signed bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    /// The A2A task ID this payment is for. The server cross-checks
    /// this against the task it's holding so a payload can't be lifted
    /// from one task and replayed on another.
    pub task_id: String,
    /// Which scheme the client chose from `accepts[]`. Must match one
    /// of the requirement entries the server emitted.
    pub scheme: String,
    /// CAIP-2 chain identifier — must match the chosen requirement.
    pub network: String,
    /// Scheme-specific signed payload — for EIP-3009, the
    /// `transferWithAuthorization` calldata + sig; for Permit2, the
    /// witness + sig; for ERC-7710, the delegation + sig. Validated
    /// by the scheme module.
    pub authorization: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────
// PaymentReceipt (server→client, after settlement)
// ─────────────────────────────────────────────────────────────────────

/// One settlement receipt. A single payment can produce multiple
/// receipts (e.g. on-chain tx hash + facilitator confirmation).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentReceipt {
    /// CAIP-2 chain identifier where settlement landed.
    pub network: String,
    /// On-chain transaction hash (or facilitator settlement ID for
    /// off-chain schemes), as `0x…` hex.
    pub transaction: String,
    /// Block number / timestamp / facilitator ack — scheme-specific.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub extra: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────
// MessageMetadataExt — typed accessors over Message.metadata
// ─────────────────────────────────────────────────────────────────────

/// Typed read/write helpers over an A2A `Message.metadata` map.
///
/// The map itself is `HashMap<String, serde_json::Value>` so a single
/// key can hold a structured object. This trait provides round-tripping
/// helpers so callers don't need to remember the magic strings or do
/// manual `serde_json::from_value` decoding at each site.
///
/// Implemented for `HashMap<String, serde_json::Value>`. Both the A2A
/// server's `TaskMessageInput` and the `A2aTask::metadata` fields use
/// this same map shape, so a single trait covers all read/write sites.
pub trait MessageMetadataExt {
    fn get_payment_required(&self) -> Option<PaymentRequirements>;
    fn get_payment_payload(&self) -> Option<PaymentPayload>;

    /// Set `x402.payment.payload` to the given payload, and set
    /// `x402.payment.status` to [`PaymentStatus::PaymentSubmitted`].
    /// Convenience for the client side.
    fn submit_x402(&mut self, payload: PaymentPayload);

    /// Set `x402.payment.receipts` to the given receipts, and set
    /// `x402.payment.status` to [`PaymentStatus::PaymentCompleted`].
    /// Convenience for the server side after settlement clears.
    fn complete_x402(&mut self, receipts: Vec<PaymentReceipt>);

    /// Mark the task as having failed payment with the given status
    /// (must be one of the failure terminals — `PaymentRejected` or
    /// `PaymentFailed`). Panics with debug-only assertion if a
    /// non-failure status is passed.
    fn fail_x402(&mut self, status: PaymentStatus);
}

impl MessageMetadataExt for HashMap<String, serde_json::Value> {
    fn get_payment_required(&self) -> Option<PaymentRequirements> {
        self.get(KEY_PAYMENT_REQUIRED)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    fn get_payment_payload(&self) -> Option<PaymentPayload> {
        self.get(KEY_PAYMENT_PAYLOAD)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    fn submit_x402(&mut self, payload: PaymentPayload) {
        if let Ok(v) = serde_json::to_value(&payload) {
            self.insert(KEY_PAYMENT_PAYLOAD.to_string(), v);
        }
        set_status(self, PaymentStatus::PaymentSubmitted);
    }

    fn complete_x402(&mut self, receipts: Vec<PaymentReceipt>) {
        if let Ok(v) = serde_json::to_value(&receipts) {
            self.insert(KEY_PAYMENT_RECEIPTS.to_string(), v);
        }
        set_status(self, PaymentStatus::PaymentCompleted);
    }

    fn fail_x402(&mut self, status: PaymentStatus) {
        debug_assert!(
            matches!(
                status,
                PaymentStatus::PaymentRejected | PaymentStatus::PaymentFailed
            ),
            "fail_x402 must be called with a failure terminal status"
        );
        set_status(self, status);
    }
}

fn set_status(md: &mut HashMap<String, serde_json::Value>, status: PaymentStatus) {
    if let Ok(v) = serde_json::to_value(status) {
        md.insert(KEY_PAYMENT_STATUS.to_string(), v);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Verifier trait — concrete scheme implementations live elsewhere
// ─────────────────────────────────────────────────────────────────────

/// Reasons a payment payload can fail. Slice (a) defines only the three
/// dispatcher-level failure modes — task-id replay, scheme-not-offered,
/// and scheme-not-implemented. Slice (c) extends this enum with
/// scheme-internal failures (`InvalidAuthorization`, `SettlementFailed`)
/// when the concrete `exact-eip3009` / `exact-permit2` / `exact-erc7710`
/// backends are implemented.
#[derive(Debug, Clone)]
pub enum VerifyFailure {
    /// The payload's `taskId` doesn't match the task it was posted against —
    /// a payload can't be lifted from one task and replayed on another.
    TaskIdMismatch { expected: String, got: String },
    /// The payload's `scheme`/`network` pair doesn't match any entry in the
    /// requirements the server advertised.
    SchemeNotOffered { scheme: String, network: String },
    /// The scheme is offered, but no implementation is registered for it on
    /// this node — slice-c work brings in the concrete verifiers
    /// (`exact-eip3009`, `exact-permit2`, `exact-erc7710`).
    SchemeNotImplemented { scheme: String },
}

impl VerifyFailure {
    /// Map to the terminal status the server should record. All slice-(a)
    /// failures are pre-settlement and map to `payment-rejected`; slice
    /// (c) will add the `SettlementFailed` arm that maps to
    /// `payment-failed`.
    pub fn terminal_status(&self) -> PaymentStatus {
        PaymentStatus::PaymentRejected
    }

    /// Human-readable summary suitable for inclusion in an agent-role
    /// failure message.
    pub fn message(&self) -> String {
        match self {
            Self::TaskIdMismatch { expected, got } => {
                format!(
                    "payment payload taskId {} does not match task {}",
                    got, expected
                )
            }
            Self::SchemeNotOffered { scheme, network } => {
                format!(
                    "scheme {}/{} is not in the offered requirements",
                    scheme, network
                )
            }
            Self::SchemeNotImplemented { scheme } => {
                format!("scheme {} is not implemented on this node", scheme)
            }
        }
    }
}

/// Verifies and settles a [`PaymentPayload`] against advertised
/// [`PaymentRequirements`]. Slice (c) of the agentic 2026 upgrade rewrites
/// this trait's blanket implementation to dispatch into the concrete
/// `exact-eip3009` / `exact-permit2` / `exact-erc7710` schemes; until then
/// the only impl is [`UnimplementedSchemeVerifier`], which exercises the
/// dispatcher's task-id-replay and scheme-not-offered checks and then
/// reports `SchemeNotImplemented`.
pub trait PaymentVerifier: Send + Sync {
    /// Verify the payload against the requirements. On success returns the
    /// receipts to write back to the task metadata.
    fn verify_and_settle(
        &self,
        task_id: &str,
        requirements: &PaymentRequirements,
        payload: &PaymentPayload,
    ) -> Result<Vec<PaymentReceipt>, VerifyFailure>;
}

/// Slice-(a) verifier: runs the dispatcher-level checks (task-id match,
/// scheme-offered) and then reports `SchemeNotImplemented`. Slice (c)
/// replaces this with a verifier that dispatches into the real scheme
/// backends.
#[derive(Default)]
pub struct UnimplementedSchemeVerifier;

impl UnimplementedSchemeVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl PaymentVerifier for UnimplementedSchemeVerifier {
    fn verify_and_settle(
        &self,
        task_id: &str,
        requirements: &PaymentRequirements,
        payload: &PaymentPayload,
    ) -> Result<Vec<PaymentReceipt>, VerifyFailure> {
        // Prevent payload-replay across tasks.
        if payload.task_id != task_id {
            return Err(VerifyFailure::TaskIdMismatch {
                expected: task_id.to_string(),
                got: payload.task_id.clone(),
            });
        }
        // The scheme/network pair must match one of the offered
        // requirements — surface a precise error before reporting that
        // no backend is registered.
        if !requirements
            .accepts
            .iter()
            .any(|r| r.scheme == payload.scheme && r.network == payload.network)
        {
            return Err(VerifyFailure::SchemeNotOffered {
                scheme: payload.scheme.clone(),
                network: payload.network.clone(),
            });
        }
        Err(VerifyFailure::SchemeNotImplemented {
            scheme: payload.scheme.clone(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_requirements() -> PaymentRequirements {
        PaymentRequirements {
            accepts: vec![PaymentRequirement {
                scheme: "exact-eip3009".to_string(),
                network: "eip155:8453".to_string(),
                amount: "1000000".to_string(),
                asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string(),
                pay_to: "0x000000000000000000000000000000000000dEaD".to_string(),
                max_timeout_seconds: 60,
                extra: serde_json::json!({}),
            }],
            reason: Some("Inference fee".to_string()),
        }
    }

    fn sample_payload() -> PaymentPayload {
        PaymentPayload {
            task_id: "task-abc".to_string(),
            scheme: "exact-eip3009".to_string(),
            network: "eip155:8453".to_string(),
            authorization: serde_json::json!({"sig": "0xdeadbeef"}),
        }
    }

    #[test]
    fn status_kebab_case_round_trip() {
        for s in [
            PaymentStatus::PaymentRequired,
            PaymentStatus::PaymentSubmitted,
            PaymentStatus::PaymentRejected,
            PaymentStatus::PaymentVerified,
            PaymentStatus::PaymentCompleted,
            PaymentStatus::PaymentFailed,
        ] {
            let v = serde_json::to_value(s).unwrap();
            assert!(v.is_string(), "status must serialize as a string");
            let s2: PaymentStatus = serde_json::from_value(v).unwrap();
            assert_eq!(s, s2);
        }
    }

    #[test]
    fn status_strings_match_spec() {
        assert_eq!(
            serde_json::to_string(&PaymentStatus::PaymentRequired).unwrap(),
            "\"payment-required\""
        );
        assert_eq!(
            serde_json::to_string(&PaymentStatus::PaymentSubmitted).unwrap(),
            "\"payment-submitted\""
        );
        assert_eq!(
            serde_json::to_string(&PaymentStatus::PaymentRejected).unwrap(),
            "\"payment-rejected\""
        );
        assert_eq!(
            serde_json::to_string(&PaymentStatus::PaymentVerified).unwrap(),
            "\"payment-verified\""
        );
        assert_eq!(
            serde_json::to_string(&PaymentStatus::PaymentCompleted).unwrap(),
            "\"payment-completed\""
        );
        assert_eq!(
            serde_json::to_string(&PaymentStatus::PaymentFailed).unwrap(),
            "\"payment-failed\""
        );
    }

    /// Lookup `x402.payment.status` raw without going through a
    /// trait method — this lets us assert that helper methods write
    /// the right status without exposing a public getter that no
    /// production caller needs.
    fn read_status(md: &HashMap<String, serde_json::Value>) -> Option<PaymentStatus> {
        md.get(KEY_PAYMENT_STATUS)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Lookup `x402.payment.receipts` raw — same rationale as
    /// [`read_status`].
    fn read_receipts(md: &HashMap<String, serde_json::Value>) -> Option<Vec<PaymentReceipt>> {
        md.get(KEY_PAYMENT_RECEIPTS)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    #[test]
    fn submit_then_get_round_trip() {
        let mut md: HashMap<String, serde_json::Value> = HashMap::new();
        let pl = sample_payload();
        md.submit_x402(pl.clone());
        assert_eq!(read_status(&md), Some(PaymentStatus::PaymentSubmitted));
        let got = md.get_payment_payload().expect("payload present");
        assert_eq!(got.task_id, pl.task_id);
        assert_eq!(got.scheme, pl.scheme);
    }

    #[test]
    fn complete_carries_receipts_and_status() {
        let mut md: HashMap<String, serde_json::Value> = HashMap::new();
        let receipts = vec![PaymentReceipt {
            network: "eip155:8453".to_string(),
            transaction: "0xabc123".to_string(),
            extra: serde_json::json!({"block": 12345}),
        }];
        md.complete_x402(receipts.clone());
        assert_eq!(read_status(&md), Some(PaymentStatus::PaymentCompleted));
        let got = read_receipts(&md).expect("receipts present");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].transaction, "0xabc123");
    }

    #[test]
    fn fail_x402_records_terminal_status() {
        let mut md: HashMap<String, serde_json::Value> = HashMap::new();
        md.fail_x402(PaymentStatus::PaymentRejected);
        assert_eq!(read_status(&md), Some(PaymentStatus::PaymentRejected));

        let mut md2: HashMap<String, serde_json::Value> = HashMap::new();
        md2.fail_x402(PaymentStatus::PaymentFailed);
        assert_eq!(read_status(&md2), Some(PaymentStatus::PaymentFailed));
    }

    #[test]
    fn empty_metadata_returns_none_for_payment_keys() {
        let md: HashMap<String, serde_json::Value> = HashMap::new();
        assert!(md.get_payment_required().is_none());
        assert!(md.get_payment_payload().is_none());
    }

    #[test]
    fn malformed_value_decodes_to_none_not_panic() {
        let mut md: HashMap<String, serde_json::Value> = HashMap::new();
        md.insert(KEY_PAYMENT_REQUIRED.to_string(), serde_json::json!(42));
        md.insert(
            KEY_PAYMENT_PAYLOAD.to_string(),
            serde_json::json!("not-an-object"),
        );
        assert!(md.get_payment_required().is_none());
        assert!(md.get_payment_payload().is_none());
    }

    // ─────────────────────────────────────────────────────────────────
    // UnimplementedSchemeVerifier — slice-(a) dispatcher checks
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn verifier_rejects_task_id_replay() {
        let v = UnimplementedSchemeVerifier::new();
        let req = sample_requirements();
        let mut payload = sample_payload();
        payload.task_id = "different-task".to_string();
        match v.verify_and_settle("task-abc", &req, &payload) {
            Err(VerifyFailure::TaskIdMismatch { expected, got }) => {
                assert_eq!(expected, "task-abc");
                assert_eq!(got, "different-task");
            }
            other => panic!("expected TaskIdMismatch, got {:?}", other),
        }
    }

    #[test]
    fn verifier_rejects_scheme_not_offered() {
        let v = UnimplementedSchemeVerifier::new();
        let req = sample_requirements();
        let mut payload = sample_payload();
        payload.scheme = "exact-permit2".to_string();
        match v.verify_and_settle("task-abc", &req, &payload) {
            Err(VerifyFailure::SchemeNotOffered { scheme, network }) => {
                assert_eq!(scheme, "exact-permit2");
                assert_eq!(network, "eip155:8453");
            }
            other => panic!("expected SchemeNotOffered, got {:?}", other),
        }
    }

    #[test]
    fn verifier_rejects_network_mismatch() {
        let v = UnimplementedSchemeVerifier::new();
        let req = sample_requirements();
        let mut payload = sample_payload();
        payload.network = "eip155:1".to_string();
        match v.verify_and_settle("task-abc", &req, &payload) {
            Err(VerifyFailure::SchemeNotOffered { scheme, network }) => {
                assert_eq!(scheme, "exact-eip3009");
                assert_eq!(network, "eip155:1");
            }
            other => panic!("expected SchemeNotOffered, got {:?}", other),
        }
    }

    #[test]
    fn verifier_passes_dispatch_then_reports_unimplemented() {
        // task_id matches and scheme/network is in `accepts` — slice-(a)
        // should now report `SchemeNotImplemented`. Slice (c) replaces
        // this with real settlement.
        let v = UnimplementedSchemeVerifier::new();
        let req = sample_requirements();
        let payload = sample_payload();
        match v.verify_and_settle("task-abc", &req, &payload) {
            Err(VerifyFailure::SchemeNotImplemented { scheme }) => {
                assert_eq!(scheme, "exact-eip3009");
            }
            other => panic!("expected SchemeNotImplemented, got {:?}", other),
        }
    }

    #[test]
    fn verify_failure_terminal_status_is_rejected() {
        // All slice-(a) failure modes are pre-settlement; they all map
        // to `payment-rejected`. Slice (c) adds `SettlementFailed` mapping
        // to `payment-failed`.
        let cases = [
            VerifyFailure::TaskIdMismatch {
                expected: "a".to_string(),
                got: "b".to_string(),
            },
            VerifyFailure::SchemeNotOffered {
                scheme: "x".to_string(),
                network: "y".to_string(),
            },
            VerifyFailure::SchemeNotImplemented {
                scheme: "x".to_string(),
            },
        ];
        for f in cases {
            assert_eq!(f.terminal_status(), PaymentStatus::PaymentRejected);
            // Message is non-empty.
            assert!(!f.message().is_empty());
        }
    }

    #[test]
    fn keys_are_stable_strings() {
        // These constants are wire-visible. If they ever change, every
        // speaker must change in the same flag-day cutover. Pin them
        // here so an accidental edit breaks this test.
        assert_eq!(KEY_PAYMENT_REQUIRED, "x402.payment.required");
        assert_eq!(KEY_PAYMENT_PAYLOAD, "x402.payment.payload");
        assert_eq!(KEY_PAYMENT_RECEIPTS, "x402.payment.receipts");
        assert_eq!(KEY_PAYMENT_STATUS, "x402.payment.status");
    }

    #[test]
    fn no_version_field_in_serialized_requirements() {
        // No version field on Tenzro-owned wire shapes. Pin this here so a
        // re-introduction of `version`/`x402Version` breaks the test.
        let json = serde_json::to_value(sample_requirements()).unwrap();
        let obj = json.as_object().expect("requirements serialize as object");
        assert!(!obj.contains_key("version"));
        assert!(!obj.contains_key("x402Version"));
    }

    #[test]
    fn no_version_field_in_serialized_payload() {
        let json = serde_json::to_value(sample_payload()).unwrap();
        let obj = json.as_object().expect("payload serializes as object");
        assert!(!obj.contains_key("version"));
        assert!(!obj.contains_key("x402Version"));
    }
}
