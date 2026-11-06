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
//! each [`X402PaymentRequirement`] are x402 schemes, verified and settled
//! by the facilitator the operator names (`payments.facilitator_url`). When the wire
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
//!    message to carry `metadata.x402.payment.payload` and settles it
//!    through [`verify_and_settle`].
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
use tenzro_payments::x402::{
    CdpFacilitatorClient, FacilitatorRequest, X402PaymentPayload, X402PaymentRequirement,
    X402SettlementResponse,
};

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
    pub accepts: Vec<X402PaymentRequirement>,
    /// Optional human-readable reason this task requires payment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────
// PaymentPayload (client→server)
// ─────────────────────────────────────────────────────────────────────

/// What the client posts back: the task it pays for and the x402 payment
/// payload, whose `accepted` names the requirement it answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    /// The A2A task ID this payment is for. The server cross-checks
    /// this against the task it's holding so a payload can't be lifted
    /// from one task and replayed on another.
    pub task_id: String,
    /// The x402 payment payload, verified and settled by the node's x402
    /// facilitator exactly as an HTTP payment is.
    pub payment: X402PaymentPayload,
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

/// Reasons a payment payload can fail.
#[derive(Debug, Clone)]
pub enum VerifyFailure {
    /// The payload's `taskId` doesn't match the task it was posted against;
    /// a payload can't be lifted from one task and replayed on another.
    TaskIdMismatch { expected: String, got: String },
    /// The payload's `scheme`/`network` pair doesn't match any entry in the
    /// requirements the server advertised.
    SchemeNotOffered { scheme: String, network: String },
    /// Neither the operator's facilitator nor this node's own is
    /// available, so no payment can be settled.
    NoFacilitator,
    /// The facilitator refused the payload before moving value (bad or
    /// forged authorization, insufficient funds, an unproven or spent
    /// payment, a payment outside the payer's Terms).
    Refused { reason: String },
    /// The payload verified but settlement did not complete.
    SettlementFailed { reason: String },
}

impl VerifyFailure {
    /// The terminal status the server records: `payment-failed` once
    /// settlement was attempted, `payment-rejected` before that.
    pub fn terminal_status(&self) -> PaymentStatus {
        match self {
            Self::SettlementFailed { .. } => PaymentStatus::PaymentFailed,
            _ => PaymentStatus::PaymentRejected,
        }
    }

    /// Human-readable summary suitable for inclusion in an agent-role
    /// failure message.
    pub fn message(&self) -> String {
        match self {
            Self::TaskIdMismatch { expected, got } => {
                format!("payment payload taskId {got} does not match task {expected}")
            }
            Self::SchemeNotOffered { scheme, network } => {
                format!("scheme {scheme}/{network} is not in the offered requirements")
            }
            Self::NoFacilitator => "this node settles no x402 payments".to_string(),
            Self::Refused { reason } => format!("payment refused: {reason}"),
            Self::SettlementFailed { reason } => format!("settlement failed: {reason}"),
        }
    }
}

/// Facilitator refusal reasons that mean the payload never moved value.
const PRE_SETTLEMENT_REASONS: &[&str] = &[
    "invalid_payload",
    "insufficient_funds",
    "settlement_pending",
    "unsupported_scheme",
];

/// Settles an x402 payment: a facilitator the operator runs outside the node.
#[async_trait::async_trait]
pub trait X402Settler: Send + Sync {
    /// Verify and settle `payload` against `requirement`; a refusal is a
    /// failed response carrying its reason.
    async fn settle_payment(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> X402SettlementResponse;
}

#[async_trait::async_trait]
impl X402Settler for CdpFacilitatorClient {
    async fn settle_payment(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> X402SettlementResponse {
        match self
            .settle(&FacilitatorRequest::new(payload, requirement))
            .await
        {
            Ok(response) => response,
            Err(_) => X402SettlementResponse::failed(
                requirement.network.clone(),
                "unexpected_settle_error",
            ),
        }
    }
}

#[async_trait::async_trait]
impl X402Settler for tenzro_payments::x402::X402Facilitator {
    async fn settle_payment(
        &self,
        requirement: &X402PaymentRequirement,
        payload: &X402PaymentPayload,
    ) -> X402SettlementResponse {
        self.settle(requirement, payload).await
    }
}

/// Verify and settle `payload` for the task `task_id` against the
/// requirements the task advertised, through the operator's x402 facilitator.
/// The payload must name this task and answer one of the offered
/// requirements; the facilitator checks it against that requirement as the
/// server stated it, never as the payer restated it.
pub async fn verify_and_settle(
    facilitator: Option<&dyn X402Settler>,
    task_id: &str,
    requirements: &PaymentRequirements,
    payload: &PaymentPayload,
) -> Result<Vec<PaymentReceipt>, VerifyFailure> {
    if payload.task_id != task_id {
        return Err(VerifyFailure::TaskIdMismatch {
            expected: task_id.to_string(),
            got: payload.task_id.clone(),
        });
    }
    let accepted = &payload.payment.accepted;
    let requirement = requirements
        .accepts
        .iter()
        .find(|r| r.scheme == accepted.scheme && r.network == accepted.network)
        .ok_or_else(|| VerifyFailure::SchemeNotOffered {
            scheme: accepted.scheme.clone(),
            network: accepted.network.clone(),
        })?;
    let facilitator = facilitator.ok_or(VerifyFailure::NoFacilitator)?;
    let settled = facilitator
        .settle_payment(requirement, &payload.payment)
        .await;
    if !settled.success {
        let reason = settled
            .error_reason
            .unwrap_or_else(|| "unexpected_settle_error".to_string());
        return Err(if PRE_SETTLEMENT_REASONS.contains(&reason.as_str()) {
            VerifyFailure::Refused { reason }
        } else {
            VerifyFailure::SettlementFailed { reason }
        });
    }
    Ok(vec![PaymentReceipt {
        network: settled.network,
        transaction: settled.transaction,
        extra: serde_json::json!({
            "scheme": requirement.scheme,
            "payer": settled.payer,
            "amount": settled.amount,
        }),
    }])
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_requirement() -> X402PaymentRequirement {
        X402PaymentRequirement::new(
            "exact-eip3009",
            "eip155:8453",
            "1000000",
            "0x000000000000000000000000000000000000dEaD",
            "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            60,
        )
    }

    fn sample_requirements() -> PaymentRequirements {
        PaymentRequirements {
            accepts: vec![sample_requirement()],
            reason: Some("Inference fee".to_string()),
        }
    }

    fn sample_payload() -> PaymentPayload {
        PaymentPayload {
            task_id: "task-abc".to_string(),
            payment: X402PaymentPayload::new(
                sample_requirement(),
                serde_json::json!({"sig": "0xdeadbeef"}),
            ),
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
        assert_eq!(got.payment.accepted.scheme, pl.payment.accepted.scheme);
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
    // verify_and_settle: dispatch into the node's x402 facilitator
    // ─────────────────────────────────────────────────────────────────

    mod settle {
        use super::*;
        use parking_lot::Mutex;

        /// A facilitator that answers as told and records what it was asked.
        #[derive(Default)]
        struct Fake {
            answer: Mutex<Option<X402SettlementResponse>>,
            asked: Mutex<Vec<(X402PaymentRequirement, X402PaymentPayload)>>,
        }

        #[async_trait::async_trait]
        impl X402Settler for Fake {
            async fn settle_payment(
                &self,
                requirement: &X402PaymentRequirement,
                payload: &X402PaymentPayload,
            ) -> X402SettlementResponse {
                self.asked
                    .lock()
                    .push((requirement.clone(), payload.clone()));
                self.answer.lock().clone().expect("an answer")
            }
        }

        fn answering(r: X402SettlementResponse) -> Fake {
            let f = Fake::default();
            *f.answer.lock() = Some(r);
            f
        }

        fn settled() -> X402SettlementResponse {
            X402SettlementResponse {
                success: true,
                error_reason: None,
                payer: Some("0xabc".to_string()),
                transaction: "0x77".to_string(),
                network: "eip155:8453".to_string(),
                amount: Some("1000000".to_string()),
                usage_record: None,
                plan: None,
            }
        }

        #[tokio::test]
        async fn a_settled_payment_resumes_the_task_against_the_requirement_as_offered() {
            let f = answering(settled());
            let reqs = sample_requirements();
            let mut payload = sample_payload();
            // The payer restates the amount; the facilitator is asked about
            // the requirement the task offered.
            payload.payment.accepted.amount = "1".to_string();
            let receipts = verify_and_settle(Some(&f), "task-abc", &reqs, &payload)
                .await
                .expect("a paid task is accepted");
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].transaction, "0x77");
            let asked = f.asked.lock();
            assert_eq!(asked.len(), 1);
            assert_eq!(asked[0].0, reqs.accepts[0]);
        }

        #[tokio::test]
        async fn a_refusal_rejects_and_a_failed_settlement_fails() {
            let reqs = sample_requirements();
            let payload = sample_payload();
            let refused = answering(X402SettlementResponse::failed(
                "eip155:8453".to_string(),
                "invalid_payload",
            ));
            assert!(matches!(
                verify_and_settle(Some(&refused), "task-abc", &reqs, &payload).await,
                Err(VerifyFailure::Refused { .. })
            ));
            let failed = answering(X402SettlementResponse::failed(
                "eip155:8453".to_string(),
                "transaction_reverted",
            ));
            assert!(matches!(
                verify_and_settle(Some(&failed), "task-abc", &reqs, &payload).await,
                Err(VerifyFailure::SettlementFailed { .. })
            ));
        }

        #[tokio::test]
        async fn dispatcher_checks_run_before_the_facilitator() {
            let f = answering(settled());
            let reqs = sample_requirements();
            let mut payload = sample_payload();
            payload.task_id = "different-task".to_string();
            match verify_and_settle(Some(&f), "task-abc", &reqs, &payload).await {
                Err(VerifyFailure::TaskIdMismatch { expected, got }) => {
                    assert_eq!(
                        (expected.as_str(), got.as_str()),
                        ("task-abc", "different-task")
                    );
                }
                other => panic!("expected TaskIdMismatch, got {other:?}"),
            }

            let mut payload = sample_payload();
            payload.payment.accepted.network = "eip155:1".to_string();
            assert!(matches!(
                verify_and_settle(Some(&f), "task-abc", &reqs, &payload).await,
                Err(VerifyFailure::SchemeNotOffered { .. })
            ));

            let payload = sample_payload();
            assert!(matches!(
                verify_and_settle(None, "task-abc", &reqs, &payload).await,
                Err(VerifyFailure::NoFacilitator)
            ));
        }

        #[test]
        fn only_a_failed_settlement_is_payment_failed() {
            let failed = VerifyFailure::SettlementFailed { reason: "x".into() };
            assert_eq!(failed.terminal_status(), PaymentStatus::PaymentFailed);
            for f in [
                VerifyFailure::TaskIdMismatch {
                    expected: "a".into(),
                    got: "b".into(),
                },
                VerifyFailure::SchemeNotOffered {
                    scheme: "x".into(),
                    network: "y".into(),
                },
                VerifyFailure::NoFacilitator,
                VerifyFailure::Refused {
                    reason: "invalid_payload".into(),
                },
            ] {
                assert_eq!(f.terminal_status(), PaymentStatus::PaymentRejected);
                assert!(!f.message().is_empty());
            }
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
