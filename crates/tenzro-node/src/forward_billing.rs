//! Billing and credentials for inference this node forwards to a provider.
//!
//! When a model is served by another provider, this node pays that provider
//! for the leg out of the operator's payee and collects from its own caller.
//! Two things on that leg are decided here.
//!
//! **What is billed.** A provider reports its own usage. Billed as reported,
//! a provider could claim any count up to `u32::MAX` of every dimension. So:
//!
//! * a provider this node learned from a signed gossip announcement must return
//!   an [`InferenceReceipt`] signed by that announced key, binding the units to
//!   this request's nonce and to the output actually received. Without one,
//!   the leg is billed the offer's per-request floor and nothing more;
//! * whatever is billed is then capped against the request itself by
//!   [`cap_units`]: output tokens by the requested maximum and by the bytes
//!   that came back, prompt-side counts by the bytes that were sent, and every
//!   media dimension by what the request could have carried.
//!
//! **Which credential travels.** A caller's access token for this node was
//! issued by *this* node and is bound to its DPoP key for this node's URLs;
//! it is never forwarded. A caller who holds an access token the serving
//! provider issued (for a gated or private model) addresses it, with a DPoP
//! proof for the provider's `tenzro/infer` ALPN, explicitly with
//! [`ProviderCredential`]'s headers, and only that credential travels.

use serde_json::Value;
use tenzro_types::model::BillableUnits;

use crate::inference_receipt::{InferenceReceipt, expected_identity, output_hash};
use crate::openai_tools::OpenAIToolCall;

/// Header naming an access token the serving provider issued to the caller.
pub const PROVIDER_ACCESS_TOKEN_HEADER: &str = "x-tenzro-provider-access-token";
/// Header carrying the caller's DPoP proof for the provider's `tenzro/infer`
/// ALPN (`htm` `POST`, `htu` `tenzro-iroh://tenzro/infer`).
pub const PROVIDER_DPOP_HEADER: &str = "x-tenzro-provider-dpop";

/// A credential the caller addressed to the serving provider, and only that.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderCredential {
    pub access_token: Option<String>,
    pub dpop: Option<String>,
}

impl ProviderCredential {
    /// Read from the provider-addressed headers. The caller's own
    /// `Authorization` and `DPoP` headers are deliberately not read: they
    /// authenticate the caller to this node.
    pub fn from_headers(headers: &axum::http::HeaderMap) -> Self {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        Self {
            access_token: get(PROVIDER_ACCESS_TOKEN_HEADER),
            dpop: get(PROVIDER_DPOP_HEADER),
        }
    }

    /// Read from JSON-RPC params, where the same credential is named
    /// `provider_access_token` / `provider_dpop`.
    pub fn from_params(params: &Value) -> Self {
        let get = |name: &str| {
            params
                .get(name)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        Self {
            access_token: get("provider_access_token"),
            dpop: get("provider_dpop"),
        }
    }
}

/// What a forwarded request could legitimately have consumed.
#[derive(Debug, Clone, Copy, Default)]
pub struct UsageBound {
    /// The output-token ceiling the request carried, when it carried one.
    pub max_output_tokens: Option<u32>,
    /// Bytes of the request body this node sent.
    pub request_bytes: u64,
    /// Bytes of the response body this node received.
    pub response_bytes: u64,
    /// Generative media work the request asked for. Zero for a chat.
    pub pixel_steps: u128,
}

/// Cap reported units against the request that produced them.
///
/// Every token of text is at least one byte, so a count of prompt-side tokens
/// larger than the bytes sent, or of output tokens larger than the bytes
/// received, is a count the provider did not serve. Media durations are
/// bounded by the bytes that could have carried them at one byte per
/// millisecond, below any real codec's bitrate. Each unit is capped across
/// all its tiers. A unit with no request-derived bound passes as the signed
/// receipt reports it.
pub fn cap_units(reported: &BillableUnits, bound: &UsageBound) -> BillableUnits {
    use tenzro_types::meter::{parse_key, unit};
    let out_cap = bound.max_output_tokens.map_or(bound.response_bytes, |m| {
        (m as u64).min(bound.response_bytes)
    }) as u128;
    let request = bound.request_bytes as u128;
    let response = bound.response_bytes as u128;
    let media = request.saturating_add(response);
    // Prompt-side counts share the bytes sent: fresh input first, then cache
    // reads, then cache writes.
    let mut prompt_budget = request;
    let mut out = BillableUnits::new();
    let mut remaining: std::collections::BTreeMap<&str, u128> = std::collections::BTreeMap::new();
    for prompt_unit in [
        unit::INPUT_TOKENS,
        unit::CACHED_READ_TOKENS,
        unit::CACHED_WRITE_TOKENS,
    ] {
        for (k, v) in reported.iter() {
            if parse_key(k).map(|(u, _)| u) == Ok(prompt_unit) {
                let t = v.min(prompt_budget);
                prompt_budget -= t;
                let _ = out.set(k, t);
            }
        }
    }
    for (k, v) in reported.iter() {
        let Ok((u, _)) = parse_key(k) else { continue };
        let cap = match u {
            unit::INPUT_TOKENS | unit::CACHED_READ_TOKENS | unit::CACHED_WRITE_TOKENS => continue,
            unit::OUTPUT_TOKENS | unit::REASONING_TOKENS | unit::REASONING_LOOPS => out_cap,
            unit::IMAGE_TOKENS
            | unit::CHARACTERS
            | unit::RERANK_PAIRS
            | unit::DECISION_QUESTIONS
            | unit::TRAINED_TOKENS => request,
            unit::FORECAST_POINTS => response,
            unit::AUDIO_MS
            | unit::VIDEO_MS
            | unit::FRAMES
            | unit::AUDIO_OUT_MS
            | unit::SIMULATED_MS
            | unit::SESSION_HOLD_MS => media,
            unit::PIXEL_STEPS => bound.pixel_steps,
            _ => u128::MAX,
        };
        // A unit's cap is shared across its tiers.
        let left = remaining.entry(u).or_insert(cap);
        let t = v.min(*left);
        *left -= t;
        let _ = out.set(k, t);
    }
    out
}

/// How the billed units were established, reported in logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BillingBasis {
    /// Units bound by a receipt from the provider's announced key, then capped.
    SignedReceipt,
    /// An operator-registered endpoint with no announced key: the operator
    /// chose to trust its reports, which are still capped.
    OperatorRegistered,
    /// No acceptable receipt from an announced provider: the per-request floor.
    Floor,
}

/// The receipt-checking inputs for one forwarded leg.
pub struct ForwardLeg<'a> {
    pub model_id: &'a str,
    pub nonce: &'a str,
    /// The hardware identity key registered for the provider's machine DID,
    /// when the provider was learned from gossip; its receipts must be
    /// certified by that key.
    pub pinned_key: Option<&'a tenzro_crypto::composite::CompositePublicKey>,
    pub bound: UsageBound,
}

impl ForwardLeg<'_> {
    /// Decide the units to bill for a leg whose provider reported `reported`
    /// and attached `receipt` over an output hashing to `received_output`.
    pub fn billable(
        &self,
        reported: Option<BillableUnits>,
        receipt: Option<&Value>,
        received_output: &str,
    ) -> (BillableUnits, BillingBasis) {
        let reported = reported.unwrap_or_default();
        let Some(pinned) = self.pinned_key else {
            return (
                cap_units(&reported, &self.bound),
                BillingBasis::OperatorRegistered,
            );
        };
        let Some(identity) = expected_identity(self.model_id) else {
            tracing::warn!(model = %self.model_id,
                "No catalog identity for the routed model; billing the per-request floor");
            return (BillableUnits::default(), BillingBasis::Floor);
        };
        let verified = receipt
            .filter(|v| !v.is_null())
            .and_then(|v| serde_json::from_value::<InferenceReceipt>(v.clone()).ok())
            .map(|r| {
                r.verify_for_forward(
                    pinned,
                    self.model_id,
                    &identity,
                    self.nonce,
                    received_output,
                    &reported,
                )
            });
        match verified {
            Some(Ok(())) => (
                cap_units(&reported, &self.bound),
                BillingBasis::SignedReceipt,
            ),
            Some(Err(e)) => {
                tracing::warn!(model = %self.model_id, error = %e,
                    "Provider receipt refused; billing the per-request floor");
                (BillableUnits::default(), BillingBasis::Floor)
            }
            None => (BillableUnits::default(), BillingBasis::Floor),
        }
    }
}

/// The output hash of a non-streaming OpenAI completion body, computed the
/// same way the provider computed it when it signed.
pub fn completion_output_hash(body: &Value) -> String {
    let message = body
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"));
    let text = message
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let reasoning = message
        .and_then(|m| m.get("reasoning_content"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let calls: Vec<OpenAIToolCall> = message
        .and_then(|m| m.get("tool_calls"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    output_hash(text, reasoning, &tool_calls_json(&calls))
}

/// The output hash of a rich-shape reply, from its content blocks: text blocks
/// as the text, thinking blocks as the reasoning, `tool_use` blocks as tool
/// calls. Provider and gateway both derive it from the serialized blocks.
pub fn rich_output_hash(content: Option<&Value>) -> String {
    let (text, reasoning, calls) = rich_output_parts(content);
    output_hash(&text, &reasoning, &calls)
}

/// The text, the reasoning and the canonical tool-call string of a
/// rich-shape reply's content blocks: the three parts its output hash covers.
pub fn rich_output_parts(content: Option<&Value>) -> (String, String, String) {
    let blocks = content
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut text = String::new();
    let mut reasoning = String::new();
    let mut calls = Vec::new();
    for b in &blocks {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => text.push_str(b.get("text").and_then(Value::as_str).unwrap_or("")),
            Some("thinking") => {
                reasoning.push_str(b.get("thinking").and_then(Value::as_str).unwrap_or(""))
            }
            Some("tool_use") => calls.push(OpenAIToolCall {
                id: b
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                kind: "function".to_string(),
                function: crate::openai_tools::OpenAIFunctionCall {
                    name: b
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    arguments: serde_json::to_string(b.get("input").unwrap_or(&Value::Null))
                        .unwrap_or_default(),
                },
            }),
            _ => {}
        }
    }
    (text, reasoning, tool_calls_json(&calls))
}

/// The canonical string the output hash takes for a set of tool calls.
pub fn tool_calls_json(calls: &[OpenAIToolCall]) -> String {
    if calls.is_empty() {
        String::new()
    } else {
        serde_json::to_string(calls).unwrap_or_default()
    }
}

/// Reassembles what a streamed completion delivered, delta by delta, so its
/// output hash can be checked against the provider's receipt.
#[derive(Debug, Default)]
pub struct StreamedOutput {
    text: String,
    reasoning: String,
    calls: Vec<OpenAIToolCall>,
    /// The receipt, from whichever frame carried one (the finish frame).
    pub receipt: Option<Value>,
}

impl StreamedOutput {
    /// Fold one SSE payload in.
    pub fn absorb(&mut self, payload: &str) {
        let Ok(v) = serde_json::from_str::<Value>(payload.trim()) else {
            return;
        };
        if let Some(r) = v.get("tenzro_receipt").filter(|r| !r.is_null()) {
            self.receipt = Some(r.clone());
        }
        let Some(delta) = v
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("delta"))
        else {
            return;
        };
        if let Some(s) = delta.get("content").and_then(Value::as_str) {
            self.text.push_str(s);
        }
        if let Some(s) = delta.get("reasoning_content").and_then(Value::as_str) {
            self.reasoning.push_str(s);
        }
        for d in delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = d.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            if index > self.calls.len() {
                // A gap in the indices is not a stream any client assembles.
                continue;
            }
            if index == self.calls.len() {
                self.calls.push(OpenAIToolCall {
                    id: String::new(),
                    kind: "function".to_string(),
                    function: crate::openai_tools::OpenAIFunctionCall {
                        name: String::new(),
                        arguments: String::new(),
                    },
                });
            }
            let call = &mut self.calls[index];
            if let Some(id) = d.get("id").and_then(Value::as_str) {
                call.id = id.to_string();
            }
            if let Some(f) = d.get("function") {
                if let Some(n) = f.get("name").and_then(Value::as_str) {
                    call.function.name.push_str(n);
                }
                if let Some(a) = f.get("arguments").and_then(Value::as_str) {
                    call.function.arguments.push_str(a);
                }
            }
        }
    }

    /// The output hash of everything absorbed so far.
    pub fn output_hash(&self) -> String {
        output_hash(&self.text, &self.reasoning, &tool_calls_json(&self.calls))
    }

    /// Everything absorbed so far, in the three parts the output hash covers.
    pub fn output(&self) -> crate::optimistic::Output {
        crate::optimistic::Output {
            text: self.text.clone(),
            reasoning: self.reasoning.clone(),
            tool_calls: tool_calls_json(&self.calls),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference_receipt::{
        InferenceReceipt, ModelIdentity, ReceiptClaims, SamplingParams, catalog_identity,
        upstream_identity,
    };
    use serde_json::json;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::batch::ImmediateRecordSigner;

    fn session() -> ImmediateRecordSigner {
        tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(TestHybridSigner::random()))
    }

    fn bound() -> UsageBound {
        UsageBound {
            max_output_tokens: Some(100),
            request_bytes: 1_000,
            response_bytes: 2_000,
            pixel_steps: 0,
        }
    }

    #[test]
    fn forecast_points_cannot_exceed_the_bytes_that_carried_them() {
        let reported = BillableUnits::default().with_forecast_points(u32::MAX);
        assert_eq!(cap_units(&reported, &bound()).forecast_points(), 2_000);
        let honest = BillableUnits::default().with_forecast_points(96);
        assert_eq!(cap_units(&honest, &bound()).forecast_points(), 96);
    }

    #[test]
    fn inflated_output_is_capped_by_the_requested_maximum() {
        let capped = cap_units(&BillableUnits::tokens(10, u32::MAX), &bound());
        assert_eq!(capped.output_tokens(), 100);
        assert_eq!(capped.input_tokens(), 10);
    }

    #[test]
    fn without_a_maximum_output_is_capped_by_bytes_received() {
        let mut b = bound();
        b.max_output_tokens = None;
        assert_eq!(
            cap_units(&BillableUnits::tokens(0, 1_000_000), &b).output_tokens(),
            2_000
        );
    }

    #[test]
    fn a_unit_is_capped_across_its_tiers_and_an_unbounded_unit_passes() {
        let mut reported = BillableUnits::new();
        reported.set("output_tokens", 80).unwrap();
        reported.set("output_tokens@priority", 80).unwrap();
        reported.set("action_chunks", 7).unwrap();
        let capped = cap_units(&reported, &bound());
        assert_eq!(capped.unit_total("output_tokens"), 100);
        assert_eq!(capped.get("action_chunks"), 7);
    }

    #[test]
    fn prompt_side_counts_share_the_bytes_sent() {
        let reported = BillableUnits::tokens(900, 1).with_cache(900, 900);
        let capped = cap_units(&reported, &bound());
        assert_eq!(
            capped.input_tokens() + capped.cached_read_tokens() + capped.cached_write_tokens(),
            1_000
        );
    }

    #[test]
    fn media_dimensions_a_chat_cannot_consume_are_capped() {
        let reported = BillableUnits::new()
            .with_pixel_steps(u128::MAX)
            .with_audio_ms(u64::MAX)
            .with_video_ms(u64::MAX)
            .with_frames(u32::MAX)
            .with_image_tokens(u32::MAX)
            .with_reasoning_loops(u32::MAX);
        let capped = cap_units(&reported, &bound());
        assert_eq!(capped.pixel_steps(), 0);
        assert_eq!(capped.audio_ms(), 3_000);
        assert_eq!(capped.video_ms(), 3_000);
        assert_eq!(capped.frames(), 3_000);
        assert_eq!(capped.image_tokens(), 1_000);
        assert_eq!(capped.reasoning_loops(), 100);
    }

    /// A model the seed catalog lists.
    const MODEL: &str = "qwen3-0.6b";

    fn receipt_for(
        signer: &ImmediateRecordSigner,
        nonce: &str,
        body_hash: String,
        units: BillableUnits,
    ) -> Value {
        receipt_with_identity(signer, nonce, body_hash, units, None)
    }

    fn receipt_with_identity(
        signer: &ImmediateRecordSigner,
        nonce: &str,
        body_hash: String,
        units: BillableUnits,
        identity: Option<ModelIdentity>,
    ) -> Value {
        tenzro_catalog::install_test_seed();
        let identity = identity.unwrap_or_else(|| catalog_identity(MODEL).unwrap());
        receipt_naming(signer, MODEL, identity, nonce, body_hash, units)
    }

    fn receipt_naming(
        signer: &ImmediateRecordSigner,
        model_id: &str,
        identity: ModelIdentity,
        nonce: &str,
        body_hash: String,
        units: BillableUnits,
    ) -> Value {
        serde_json::to_value(
            InferenceReceipt::sign(
                signer,
                ReceiptClaims {
                    decode: Default::default(),
                    model_id: model_id.to_string(),
                    identity,
                    machine_did: "did:tenzro:machine:test".to_string(),
                    nonce: nonce.to_string(),
                    input_commitment: "11".repeat(32),
                    output_hash: body_hash,
                    units,
                    priced: None,
                    provenance: Vec::new(),
                    sampling: SamplingParams {
                        seed: 1,
                        temperature: 0.0,
                        top_p: 1.0,
                        top_k: None,
                        min_p: None,
                        max_output_tokens: 100,
                        keyed_sampler: false,
                    },
                    commitment_hash: None,
                    tee: None,
                    activation_fingerprint: None,
                },
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn a_receipt_for_other_weights_than_the_catalog_states_gets_the_floor() {
        let signer = session();
        let pk = signer.identity().clone();
        let out = output_hash("hi", "", "");
        let reported = BillableUnits::tokens(10, 50);
        let leg = ForwardLeg {
            model_id: MODEL,
            nonce: "n1",
            pinned_key: Some(&pk),
            bound: bound(),
        };
        let swapped = receipt_with_identity(
            &signer,
            "n1",
            out.clone(),
            reported.clone(),
            Some(ModelIdentity {
                model_hash: "00".repeat(32),
                engine: "gguf".to_string(),
            }),
        );
        assert_eq!(
            leg.billable(Some(reported.clone()), Some(&swapped), &out).1,
            BillingBasis::Floor
        );
        let honest = receipt_for(&signer, "n1", out.clone(), reported.clone());
        assert_eq!(
            leg.billable(Some(reported), Some(&honest), &out).1,
            BillingBasis::SignedReceipt
        );
    }

    /// A model the catalog does not list is served from an operator's own
    /// endpoint, and its receipt names the upstream identity: billed from the
    /// receipt like any other. A catalog model's receipt that names the
    /// upstream identity instead of the weights gets the floor.
    #[test]
    fn a_model_outside_the_catalog_is_billed_on_its_upstream_identity() {
        tenzro_catalog::install_test_seed();
        const UPSTREAM: &str = "operator/served-upstream";
        assert!(tenzro_model::catalog::entry(UPSTREAM).is_none());
        let signer = session();
        let pk = signer.identity().clone();
        let out = output_hash("hi", "", "");
        let reported = BillableUnits::tokens(12, 40);
        let leg = ForwardLeg {
            model_id: UPSTREAM,
            nonce: "n1",
            pinned_key: Some(&pk),
            bound: bound(),
        };
        let receipt = receipt_naming(
            &signer,
            UPSTREAM,
            upstream_identity(UPSTREAM),
            "n1",
            out.clone(),
            reported.clone(),
        );
        assert_eq!(
            leg.billable(Some(reported.clone()), Some(&receipt), &out),
            (reported.clone(), BillingBasis::SignedReceipt)
        );
        // The identity is bound to the id: another model's does not pass.
        let other = receipt_naming(
            &signer,
            UPSTREAM,
            upstream_identity("operator/other"),
            "n1",
            out.clone(),
            reported.clone(),
        );
        assert_eq!(
            leg.billable(Some(reported.clone()), Some(&other), &out).1,
            BillingBasis::Floor
        );
        let catalog_leg = ForwardLeg {
            model_id: MODEL,
            ..leg
        };
        let claimed = receipt_naming(
            &signer,
            MODEL,
            upstream_identity(MODEL),
            "n1",
            out.clone(),
            reported.clone(),
        );
        assert_eq!(
            catalog_leg.billable(Some(reported), Some(&claimed), &out).1,
            BillingBasis::Floor
        );
    }

    #[test]
    fn an_announced_provider_is_billed_from_its_receipt_and_capped() {
        let signer = session();
        let pk = signer.identity().clone();
        let out = output_hash("hi", "", "");
        let reported = BillableUnits::tokens(10, 500);
        let receipt = receipt_for(&signer, "n1", out.clone(), reported.clone());
        let leg = ForwardLeg {
            model_id: MODEL,
            nonce: "n1",
            pinned_key: Some(&pk),
            bound: bound(),
        };
        let (units, basis) = leg.billable(Some(reported.clone()), Some(&receipt), &out);
        assert_eq!(basis, BillingBasis::SignedReceipt);
        // Signed or not, a count above the requested maximum is not billed.
        assert_eq!(units.output_tokens(), 100);
    }

    #[test]
    fn an_announced_provider_without_a_valid_receipt_gets_the_floor() {
        let signer = session();
        let pk = signer.identity().clone();
        let out = output_hash("hi", "", "");
        let leg = ForwardLeg {
            model_id: MODEL,
            nonce: "n1",
            pinned_key: Some(&pk),
            bound: bound(),
        };
        let reported = BillableUnits::tokens(10, 50);
        // No receipt at all.
        assert_eq!(
            leg.billable(Some(reported.clone()), None, &out),
            (BillableUnits::default(), BillingBasis::Floor)
        );
        // A receipt replayed from another request.
        let replayed = receipt_for(&signer, "n0", out.clone(), reported.clone());
        assert_eq!(
            leg.billable(Some(reported.clone()), Some(&replayed), &out)
                .1,
            BillingBasis::Floor
        );
        // A receipt whose units are lower than the usage block claims.
        let under = receipt_for(&signer, "n1", out.clone(), BillableUnits::tokens(10, 5));
        assert_eq!(
            leg.billable(Some(reported.clone()), Some(&under), &out).1,
            BillingBasis::Floor
        );
        // A receipt from a key other than the announced one.
        let other = session();
        let forged = receipt_for(&other, "n1", out.clone(), reported.clone());
        assert_eq!(
            leg.billable(Some(reported.clone()), Some(&forged), &out).1,
            BillingBasis::Floor
        );
    }

    #[test]
    fn an_operator_registered_endpoint_is_capped_without_a_receipt() {
        let leg = ForwardLeg {
            model_id: MODEL,
            nonce: "n1",
            pinned_key: None,
            bound: bound(),
        };
        let (units, basis) = leg.billable(Some(BillableUnits::tokens(10, 9_999)), None, "");
        assert_eq!(basis, BillingBasis::OperatorRegistered);
        assert_eq!(units.output_tokens(), 100);
    }

    #[test]
    fn a_streamed_output_hashes_like_the_buffered_one() {
        let calls = vec![OpenAIToolCall {
            id: "call_1".into(),
            kind: "function".into(),
            function: crate::openai_tools::OpenAIFunctionCall {
                name: "f".into(),
                arguments: "{\"a\":1}".into(),
            },
        }];
        let body = json!({"choices": [{"message": {
            "content": "hello world", "reasoning_content": "think",
            "tool_calls": calls,
        }}]});
        let mut s = StreamedOutput::default();
        for frame in [
            json!({"choices": [{"delta": {"role": "assistant", "content": ""}}]}),
            json!({"choices": [{"delta": {"content": "hello "}}]}),
            json!({"choices": [{"delta": {"content": "world"}}]}),
            json!({"choices": [{"delta": {"reasoning_content": "think",
                "tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                "function": {"name": "f", "arguments": "{\"a\":"}}]}}]}),
            json!({"choices": [{"delta": {"tool_calls": [{"index": 0,
                "function": {"arguments": "1}"}}]}}], "tenzro_receipt": {"x": 1}}),
        ] {
            s.absorb(&frame.to_string());
        }
        assert_eq!(s.output_hash(), completion_output_hash(&body));
        assert_eq!(s.receipt, Some(json!({"x": 1})));
        // The reassembled stream is the answer re-execution compares: the
        // same three parts a whole answer's message parses to.
        let streamed = s.output();
        assert_eq!(streamed.hash(), s.output_hash());
        let mut whole = body.clone();
        whole["tenzro_receipt"] = json!(null);
        let message = &whole["choices"][0]["message"];
        assert_eq!(streamed.text, message["content"].as_str().unwrap());
        assert_eq!(
            streamed.reasoning,
            message["reasoning_content"].as_str().unwrap()
        );
        assert!(crate::optimistic::outputs_agree(
            "gguf", &streamed, &streamed
        ));
    }

    #[test]
    fn provider_credentials_come_only_from_provider_headers() {
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", "DPoP gateway-token".parse().unwrap());
        h.insert("dpop", "gateway-proof".parse().unwrap());
        assert_eq!(
            ProviderCredential::from_headers(&h),
            ProviderCredential::default()
        );
        h.insert(
            PROVIDER_ACCESS_TOKEN_HEADER,
            "provider-token".parse().unwrap(),
        );
        assert_eq!(
            ProviderCredential::from_headers(&h).access_token.as_deref(),
            Some("provider-token")
        );
        let p = json!({"access_token": "gateway-token", "provider_dpop": "proof"});
        let c = ProviderCredential::from_params(&p);
        assert_eq!(c.access_token, None);
        assert_eq!(c.dpop.as_deref(), Some("proof"));
    }
}
