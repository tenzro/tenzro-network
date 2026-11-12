//! Optimistic verification: sampled re-execution and inference faults.
//!
//! An answer served at [`VerificationLevel::Optimistic`] is decoded greedily
//! (temperature 0), so any provider serving the same weights computes the same
//! output up to the engine's numeric tolerance ([`outputs_agree`]). The node
//! that forwarded it re-executes a governed share of such answers
//! ([`SAMPLE_BPS_PARAM`]) on another provider announcing the same model, and
//! checks the second receipt names the same model hash, engine, input
//! commitment and sampling. When the outputs disagree it files an inference
//! fault on chain within the challenge window, carrying the dispute (the
//! receipt, the request and the output) for validators to re-execute. Parts
//! of the request or output too large to carry inline (an image, a mask, a
//! long conversation) travel by BLAKE3 content hash: a modality receipt
//! commits to its output in that form ([`content_committed`]), the filing node
//! keeps the parts in its content store, and a validator fetches and checks
//! them against their hashes before re-executing.
//!
//! Every validator reviews pending faults ([`spawn_reviewer`]): it checks the
//! disputed receipt against its own catalog and the claimed digest and key,
//! re-executes the request on two distinct providers other than the accused,
//! and attests its verdict: upheld only when both witnesses reproduce an
//! answer that differs from the accused one, so no single witness can frame a
//! provider ([`verdict_of`]). Two thirds of bonded stake decides; an upheld fault refunds
//! the requester from the provider's bond and pays a penalty to the insurance
//! pool (see `tenzro_vm::native::inference_fault`).
//!
//! [`VerificationLevel::Optimistic`]: tenzro_types::inference_verification::VerificationLevel::Optimistic

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenzro_types::inference_verification::{
    InferenceFaultEvidence, InferenceFaultOp, MAX_FAULT_DISPUTE_BYTES,
};
use tenzro_vm::native::inference_fault::{
    FaultEvidence, SAMPLE_BPS_PARAM, SAMPLE_ESCROW_STEP_GWEI_PARAM, SAMPLE_STEP_BPS_PARAM,
    WINDOW_MS_PARAM, pending_faults, read_fault, sample_bps_with,
};
use tracing::{debug, info, warn};

use crate::forward_billing::{ProviderCredential, tool_calls_json};
use crate::inference_receipt::{InferenceReceipt, fresh_nonce, output_hash, task_commitment};
use crate::node::TenzroNode;

/// How many leading words of a generated answer must match for two greedy
/// decodes of the same weights to agree, for engines whose kernels may round
/// differently across hardware.
const GREEDY_PREFIX_WORDS: usize = 32;

/// How often a validator looks for faults to review.
const REVIEW_INTERVAL: Duration = Duration::from_secs(60);

/// What a completion returned, in the three parts its output hash covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    pub text: String,
    pub reasoning: String,
    pub tool_calls: String,
}

impl Output {
    pub fn hash(&self) -> String {
        output_hash(&self.text, &self.reasoning, &self.tool_calls)
    }
}

/// What an answer returned: a completion's output, or the result a modality
/// call committed to (its answer without the receipt and the delivery fields,
/// see [`committed_task_output`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Answer {
    Chat(Output),
    Task { task: String, out: Value },
}

impl Answer {
    /// The output hash a receipt over this answer carries.
    pub fn hash(&self) -> String {
        match self {
            Answer::Chat(o) => o.hash(),
            Answer::Task { task, out } => task_commitment(
                task,
                &crate::verifiable_inference::canonical_json(&content_committed(out).0),
            ),
        }
    }
}

/// Fields a modality answer carries beside what its receipt commits to: the
/// receipt itself, the billing a serving node adds after signing, the audio a
/// speech answer delivers under the hash it committed to, and where a render
/// left the output it committed to.
const TASK_DELIVERY_FIELDS: &[&str] = &[
    "tenzro_receipt",
    "units",
    "cost_wei",
    "settlement",
    "audio_base64",
    "output_blake3",
];

/// Fields that report how long the work took. They are part of what a
/// provider commits to but differ on every run, so two answers are compared
/// without them.
const TASK_TIMING_FIELDS: &[&str] = &[
    "generation_time_ms",
    "generation_ms",
    "latency_ms",
    "total_latency_ms",
    "response_time_ms",
    "tokens_per_second",
];

/// A modality answer as its receipt committed to it: the JSON-RPC result
/// without [`TASK_DELIVERY_FIELDS`].
pub fn committed_task_output(result: &Value) -> Value {
    let mut out = result.clone();
    if let Some(obj) = out.as_object_mut() {
        for f in TASK_DELIVERY_FIELDS {
            obj.remove(*f);
        }
    }
    out
}

/// The most canonical-JSON bytes a part of a committed answer or a dispute
/// holds inline; a larger part is held by its content hash
/// ([`content_committed`]).
pub const INLINE_COMMIT_BYTES: usize = 4096;

/// The form a value is committed and disputed in: every part whose canonical
/// JSON is longer than [`INLINE_COMMIT_BYTES`] is replaced by
/// `{"blake3": <hex BLAKE3 of that canonical JSON>, "bytes": <its length>}`,
/// opening objects first so that only their large members are replaced.
/// Committing a committed form changes nothing, so a receipt binds the same
/// output hash whether it was computed over the answer or over its form, and
/// the form of any value is at most a few kilobytes. Returns the form and
/// the canonical JSON of each replaced part, which its reference names.
pub fn content_committed(v: &Value) -> (Value, Vec<Vec<u8>>) {
    let mut parts = Vec::new();
    let form = commit_part(v, &mut parts);
    (form, parts)
}

fn commit_part(v: &Value, parts: &mut Vec<Vec<u8>>) -> Value {
    let bytes = crate::verifiable_inference::canonical_json(v);
    if bytes.len() <= INLINE_COMMIT_BYTES {
        return v.clone();
    }
    if let Value::Object(members) = v {
        let mark = parts.len();
        let opened = Value::Object(
            members
                .iter()
                .map(|(k, m)| (k.clone(), commit_part(m, parts)))
                .collect(),
        );
        if crate::verifiable_inference::canonical_json(&opened).len() <= INLINE_COMMIT_BYTES {
            return opened;
        }
        parts.truncate(mark);
    }
    let reference = serde_json::json!({ "blake3": blake3::hash(&bytes).to_hex().to_string(), "bytes": bytes.len() });
    parts.push(bytes);
    reference
}

/// The BLAKE3 hash and length a content reference names.
fn content_reference(v: &Value) -> Option<(&str, usize)> {
    let o = v.as_object().filter(|o| o.len() == 2)?;
    Some((
        o.get("blake3")?.as_str()?,
        usize::try_from(o.get("bytes")?.as_u64()?).ok()?,
    ))
}

fn references<'a>(v: &'a Value, out: &mut Vec<(&'a str, usize)>) {
    if let Some(r) = content_reference(v) {
        out.push(r);
        return;
    }
    match v {
        Value::Object(m) => m.values().for_each(|x| references(x, out)),
        Value::Array(a) => a.iter().for_each(|x| references(x, out)),
        _ => {}
    }
}

/// `form` with each content reference replaced by the part it names, taken
/// from `parts` (keyed by hash). A part that is missing, of another length
/// or hash, or not JSON is an error.
pub fn content_restored(
    form: &Value,
    parts: &std::collections::HashMap<String, Vec<u8>>,
) -> Result<Value, String> {
    if let Some((hash, len)) = content_reference(form) {
        let bytes = parts
            .get(hash)
            .ok_or_else(|| format!("content part {hash} is missing"))?;
        if bytes.len() != len || blake3::hash(bytes).to_hex().as_str() != hash {
            return Err(format!("content part {hash} does not match its reference"));
        }
        return serde_json::from_slice(bytes).map_err(|e| format!("content part {hash}: {e}"));
    }
    Ok(match form {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| Ok((k.clone(), content_restored(x, parts)?)))
                .collect::<Result<_, String>>()?,
        ),
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|x| content_restored(x, parts))
                .collect::<Result<_, String>>()?,
        ),
        other => other.clone(),
    })
}

/// Read the receipt and the committed result from a provider's answer to a
/// modality call (a JSON-RPC response or its bare result).
pub fn parse_task_answer(task: &str, body: &Value) -> Option<(InferenceReceipt, Answer)> {
    if body.get("error").is_some() {
        return None;
    }
    let result = body.get("result").unwrap_or(body);
    let receipt = serde_json::from_value(result.get("tenzro_receipt")?.clone()).ok()?;
    Some((
        receipt,
        Answer::Task {
            task: task.to_string(),
            out: committed_task_output(result),
        },
    ))
}

/// How far apart two numeric vectors from the same weights may be, as the
/// L2 norm of their difference over the larger norm. Different weights land
/// far outside it.
const VECTOR_TOLERANCE: f64 = 5e-2;

/// How far apart two scalars from the same weights may be, relative to the
/// larger magnitude, with an absolute floor for values near zero.
const SCALAR_TOLERANCE: f64 = 1e-2;
const SCALAR_FLOOR: f64 = 1e-4;

/// Leading windows of a speech envelope that must agree, and how far each
/// may differ (relative to the louder window, with a floor in sample units).
/// Like a greedy text decode, synthesis on other hardware may drift late in
/// a long clip; different weights diverge from the first windows.
const SPEECH_PREFIX_WINDOWS: usize = 50;
const SPEECH_WINDOW_TOLERANCE: f64 = 0.1;
const SPEECH_WINDOW_FLOOR: f64 = 64.0;

/// Whether two answers to the same request agree; see [`outputs_agree`] for
/// completions and [`task_outputs_agree`] for modality calls.
pub fn answers_agree(engine: &str, a: &Answer, b: &Answer) -> bool {
    match (a, b) {
        (Answer::Chat(a), Answer::Chat(b)) => outputs_agree(engine, a, b),
        (Answer::Task { task: ta, out: a }, Answer::Task { task: tb, out: b }) => {
            ta == tb && task_outputs_agree(ta, a, b)
        }
        _ => false,
    }
}

/// Whether two committed results of the same modality call agree: the same
/// fields, timing aside; strings by the greedy word-prefix rule; integers
/// exactly; other numbers within [`SCALAR_TOLERANCE`]; numeric arrays within
/// [`VECTOR_TOLERANCE`]. Speech compares the loudness envelope it commits
/// to, over its first [`SPEECH_PREFIX_WINDOWS`] windows, instead of the
/// audio hash and length. A media render compares its perceptual fingerprint
/// within the tolerance both receipts commit to
/// ([`crate::media_verify::renders_agree`]).
pub fn task_outputs_agree(task: &str, a: &Value, b: &Value) -> bool {
    match task {
        "speech" => speech_agrees(a, b),
        "media" => crate::media_verify::renders_agree(a, b),
        _ => values_agree(a, b),
    }
}

fn speech_agrees(a: &Value, b: &Value) -> bool {
    let envelope = |v: &Value| -> Option<Vec<f64>> {
        v.get("envelope")?
            .as_array()?
            .iter()
            .map(Value::as_f64)
            .collect()
    };
    let (Some(ea), Some(eb)) = (envelope(a), envelope(b)) else {
        return false;
    };
    let n = SPEECH_PREFIX_WINDOWS.min(ea.len()).min(eb.len());
    let prefix_agrees = n > 0
        && ea[..n].iter().zip(&eb[..n]).all(|(x, y)| {
            (x - y).abs() <= SPEECH_WINDOW_TOLERANCE * x.abs().max(y.abs()) + SPEECH_WINDOW_FLOOR
        });
    let mut rest_a = a.clone();
    let mut rest_b = b.clone();
    for v in [&mut rest_a, &mut rest_b] {
        if let Some(obj) = v.as_object_mut() {
            for f in ["envelope", "audio_sha256", "duration_ms", "frames"] {
                obj.remove(f);
            }
        }
    }
    prefix_agrees
        && (ea.len() >= SPEECH_PREFIX_WINDOWS) == (eb.len() >= SPEECH_PREFIX_WINDOWS)
        && values_agree(&rest_a, &rest_b)
}

fn values_agree(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys = |m: &serde_json::Map<String, Value>| -> Vec<String> {
                let mut k: Vec<String> = m
                    .keys()
                    .filter(|k| !TASK_TIMING_FIELDS.contains(&k.as_str()))
                    .cloned()
                    .collect();
                k.sort();
                k
            };
            let kx = keys(x);
            kx == keys(y) && kx.iter().all(|k| values_agree(&x[k], &y[k]))
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                return false;
            }
            let nums = |v: &[Value]| -> Option<Vec<f64>> { v.iter().map(Value::as_f64).collect() };
            match (nums(x), nums(y)) {
                (Some(nx), Some(ny)) if !nx.is_empty() => vectors_agree(&nx, &ny),
                _ => x.iter().zip(y).all(|(p, q)| values_agree(p, q)),
            }
        }
        (Value::Number(x), Value::Number(y)) => {
            if (x.is_i64() || x.is_u64()) && (y.is_i64() || y.is_u64()) {
                return x == y;
            }
            match (x.as_f64(), y.as_f64()) {
                (Some(p), Some(q)) => {
                    (p - q).abs() <= SCALAR_TOLERANCE * p.abs().max(q.abs()) + SCALAR_FLOOR
                }
                _ => false,
            }
        }
        (Value::String(x), Value::String(y)) => text_agrees(x, y),
        _ => a == b,
    }
}

fn vectors_agree(a: &[f64], b: &[f64]) -> bool {
    let norm = |v: &[f64]| v.iter().map(|x| x * x).sum::<f64>().sqrt();
    let diff: f64 = a
        .iter()
        .zip(b)
        .map(|(x, y)| (x - y) * (x - y))
        .sum::<f64>()
        .sqrt();
    let scale = norm(a).max(norm(b));
    if !diff.is_finite() || !scale.is_finite() {
        return false;
    }
    diff <= VECTOR_TOLERANCE * scale + SCALAR_FLOOR
}

/// The greedy word-prefix rule of [`outputs_agree`] for one string: equal, or
/// the same first [`GREEDY_PREFIX_WORDS`] words (all of them, if shorter).
fn text_agrees(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let wa: Vec<&str> = a.split_whitespace().collect();
    let wb: Vec<&str> = b.split_whitespace().collect();
    let n = GREEDY_PREFIX_WORDS.min(wa.len()).min(wb.len());
    n > 0
        && wa[..n] == wb[..n]
        && (wa.len() >= GREEDY_PREFIX_WORDS) == (wb.len() >= GREEDY_PREFIX_WORDS)
}

/// Read the receipt and the output from a provider's answer, in either the
/// OpenAI completion shape or the `tenzro_chat` JSON-RPC shape.
pub fn parse_answer(body: &Value) -> Option<(InferenceReceipt, Output)> {
    if let Some(message) = body
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
    {
        let receipt = serde_json::from_value(body.get("tenzro_receipt")?.clone()).ok()?;
        let calls: Vec<crate::openai_tools::OpenAIToolCall> = message
            .get("tool_calls")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let output = Output {
            text: message
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            reasoning: message
                .get("reasoning_content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            tool_calls: tool_calls_json(&calls),
        };
        return Some((receipt, output));
    }
    let result = body.get("result").unwrap_or(body);
    let receipt = serde_json::from_value(result.get("tenzro_receipt")?.clone()).ok()?;
    if let Some(content) = result.get("content").filter(|c| c.is_array()) {
        let (text, reasoning, tool_calls) =
            crate::forward_billing::rich_output_parts(Some(content));
        return Some((
            receipt,
            Output {
                text,
                reasoning,
                tool_calls,
            },
        ));
    }
    let output = Output {
        text: result
            .get("output")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        reasoning: result
            .get("thinking")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        tool_calls: String::new(),
    };
    Some((receipt, output))
}

/// Whether two answers to the same greedy request agree. Identical outputs
/// always do. A `gguf` decode may round differently on other hardware, so two
/// answers also agree when their tool calls match and the first
/// [`GREEDY_PREFIX_WORDS`] words of their text (all of it, if shorter) are the
/// same; a different model diverges far sooner. Every other engine's output
/// must match exactly.
pub fn outputs_agree(engine: &str, a: &Output, b: &Output) -> bool {
    if a == b {
        return true;
    }
    engine == "gguf" && a.tool_calls == b.tool_calls && text_agrees(&a.text, &b.text)
}

/// The receipt was decoded greedily, so re-execution is comparable.
pub fn is_greedy(receipt: &InferenceReceipt) -> bool {
    receipt.sampling.temperature == 0.0
}

/// A governed parameter, from this node's view of chain state.
fn governed(node: &TenzroNode, key: &str) -> u64 {
    crate::rpc::chain_state_of(node)
        .map(|chain| tenzro_vm::native::network_param(&chain, key))
        .unwrap_or_else(|| tenzro_vm::governance::genesis_param(key))
}

/// Draw whether an answer paid `escrow` is re-executed, at the governed rate
/// for that payment ([`sample_bps_with`]). The provider cannot predict the
/// draw: it is made by the requester's node after the answer arrives.
pub fn draw_sample(node: &TenzroNode, escrow: u128) -> bool {
    let bps = sample_bps_with(
        governed(node, SAMPLE_BPS_PARAM),
        governed(node, SAMPLE_ESCROW_STEP_GWEI_PARAM),
        governed(node, SAMPLE_STEP_BPS_PARAM),
        escrow,
    );
    rand::random::<u64>() % 10_000 < bps
}

/// Everything needed to re-execute an answer: the provider's receipt, the
/// request it was given, and what it returned.
#[derive(Debug, Clone)]
pub struct ServedAnswer {
    pub receipt: InferenceReceipt,
    pub request: Value,
    pub output: Answer,
}

/// A dispute as a fault carries it: the receipt, and the request and the
/// answer in their committed form ([`content_committed`]), so it fits a
/// fault whatever the size of the request or the output. The parts the form
/// references by hash are in the content store of the node that filed it,
/// `parts_at`, and anyone holding them can serve them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiledAnswer {
    pub receipt: InferenceReceipt,
    pub request: Value,
    pub output: Value,
    pub parts_at: Option<String>,
}

impl ServedAnswer {
    /// The dispute over this answer, and the parts its form references.
    pub fn dispute(&self, parts_at: Option<String>) -> Result<(FiledAnswer, Vec<Vec<u8>>), String> {
        let (request, mut parts) = content_committed(&self.request);
        let (output, output_parts) =
            content_committed(&serde_json::to_value(&self.output).map_err(|e| e.to_string())?);
        parts.extend(output_parts);
        Ok((
            FiledAnswer {
                receipt: self.receipt.clone(),
                request,
                output,
                parts_at: if parts.is_empty() { None } else { parts_at },
            },
            parts,
        ))
    }
}

impl FiledAnswer {
    /// The answer this dispute is over, given the parts its form references.
    pub fn served(
        &self,
        parts: &std::collections::HashMap<String, Vec<u8>>,
    ) -> Result<ServedAnswer, String> {
        Ok(ServedAnswer {
            receipt: self.receipt.clone(),
            request: content_restored(&self.request, parts)?,
            output: serde_json::from_value(content_restored(&self.output, parts)?)
                .map_err(|e| e.to_string())?,
        })
    }

    /// Fetch the parts the form references: from this node's content store,
    /// from `parts_at`, or from any node announcing them.
    async fn fetch_parts(
        &self,
        node: &TenzroNode,
    ) -> Result<std::collections::HashMap<String, Vec<u8>>, String> {
        use tenzro_iroh::IrohResolver as _;
        let mut wanted = Vec::new();
        references(&self.request, &mut wanted);
        references(&self.output, &mut wanted);
        let mut parts = std::collections::HashMap::new();
        if wanted.is_empty() {
            return Ok(parts);
        }
        let resolver = node
            .iroh_resolver
            .as_ref()
            .ok_or("this node has no content store to fetch the dispute's parts")?;
        for (hash, _) in wanted {
            let uri = tenzro_types::tenzro_uri::TenzroUri::Blob {
                hash: hash.to_string(),
                provider_hint: self.parts_at.clone(),
            };
            let bytes = resolver
                .fetch_bytes(&uri)
                .await
                .map_err(|e| format!("content part {hash}: {e}"))?;
            parts.insert(hash.to_string(), bytes.to_vec());
        }
        Ok(parts)
    }
}

/// The result of re-executing a dispute on another provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reexecution {
    /// The other provider's answer agrees.
    Agrees,
    /// It does not.
    Differs,
    /// No other provider can answer for the same weights right now.
    NoWitness,
}

/// Providers other than the one that signed `original` announcing the same
/// model, one registration per machine.
fn witnesses_for(
    node: &TenzroNode,
    original: &InferenceReceipt,
) -> Vec<tenzro_network::ModelRegistrationMessage> {
    let own = node
        .iroh_resolver
        .as_ref()
        .map(|r| r.endpoint_id().to_string());
    let mut witnesses: Vec<tenzro_network::ModelRegistrationMessage> = Vec::new();
    for r in node
        .network_models_snapshot()
        .into_iter()
        .map(|e| e.registration)
    {
        if r.model_id == original.model_id
            && !r.iroh_endpoint_id.is_empty()
            && own.as_deref() != Some(r.iroh_endpoint_id.as_str())
            && r.machine_did != original.machine_did
            && !witnesses.iter().any(|w| w.machine_did == r.machine_did)
        {
            witnesses.push(r);
        }
    }
    witnesses
}

/// Take one witness at random out of `witnesses`.
fn draw_witness(
    witnesses: &mut Vec<tenzro_network::ModelRegistrationMessage>,
) -> Option<tenzro_network::ModelRegistrationMessage> {
    if witnesses.is_empty() {
        return None;
    }
    let pick = rand::random::<u64>() as usize % witnesses.len();
    Some(witnesses.swap_remove(pick))
}

/// Re-execute `dispute.request` on a provider other than the one that signed
/// the receipt, among those announcing the same model; see [`witness_answer`].
pub async fn reexecute(node: &TenzroNode, dispute: &ServedAnswer) -> Result<Reexecution, String> {
    let Some(witness) = draw_witness(&mut witnesses_for(node, &dispute.receipt)) else {
        return Ok(Reexecution::NoWitness);
    };
    let output = witness_answer(node, dispute, &witness).await?;
    Ok(
        if answers_agree(&dispute.receipt.engine, &dispute.output, &output) {
            Reexecution::Agrees
        } else {
            Reexecution::Differs
        },
    )
}

/// Re-execute `dispute.request` on `witness`. The witness must return a
/// receipt for the same model hash, engine, input commitment and sampling,
/// signed by the key it announced and binding the output it sent.
async fn witness_answer(
    node: &TenzroNode,
    dispute: &ServedAnswer,
    witness: &tenzro_network::ModelRegistrationMessage,
) -> Result<Answer, String> {
    let original = &dispute.receipt;
    let witness_key = crate::identity_bootstrap::registered_identity_key(
        &node.identity_registry_slot(),
        &witness.machine_did,
    )
    .ok_or_else(|| format!("{} has no registered identity key", witness.machine_did))?;

    let nonce = fresh_nonce();
    let mut request = dispute.request.clone();
    let target = match request.get_mut("params") {
        Some(p) => p,
        None => &mut request,
    };
    if let Some(obj) = target.as_object_mut() {
        obj.insert("receipt_nonce".to_string(), Value::String(nonce.clone()));
        if matches!(dispute.output, Answer::Chat(_)) {
            obj.insert("stream".to_string(), Value::Bool(false));
        }
    }
    let bytes = crate::infer::call_provider(
        node,
        &witness.iroh_endpoint_id,
        &request,
        &ProviderCredential::default(),
    )
    .await?;
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("witness answer does not parse: {e}"))?;
    let (receipt, output) = match &dispute.output {
        Answer::Chat(_) => parse_answer(&body).map(|(r, o)| (r, Answer::Chat(o))),
        Answer::Task { task, .. } => parse_task_answer(task, &body),
    }
    .ok_or("the witness returned no receipt")?;
    receipt
        .verify_signature(&witness_key)
        .map_err(|e| format!("witness receipt: {e}"))?;
    if receipt.nonce != nonce || receipt.output_hash != output.hash() {
        return Err("the witness receipt does not bind this request and its output".to_string());
    }
    if receipt.model_hash != original.model_hash
        || receipt.engine != original.engine
        || receipt.input_commitment != original.input_commitment
        || receipt.sampling != original.sampling
    {
        return Err("the witness served other weights, input or sampling".to_string());
    }
    Ok(output)
}

/// After an optimistic-level answer this node forwarded, for which
/// `requester` paid `refund`: draw the sample, and if drawn, re-execute it in
/// the background and file a fault when the witness disagrees.
pub fn spawn_check(
    node: Arc<TenzroNode>,
    dispute: ServedAnswer,
    requester: tenzro_types::primitives::Address,
    refund: u128,
) {
    if draw_sample(&node, refund) {
        spawn_reexecution(node, dispute, requester, refund);
    }
}

/// Re-execute a drawn answer in the background and file a fault when the
/// witness disagrees; [`spawn_check`] after its draw.
pub fn spawn_reexecution(
    node: Arc<TenzroNode>,
    dispute: ServedAnswer,
    requester: tenzro_types::primitives::Address,
    refund: u128,
) {
    tokio::spawn(async move {
        match reexecute(&node, &dispute).await {
            Ok(Reexecution::Agrees) => {
                debug!(model = %dispute.receipt.model_id, "sampled answer re-executed and agrees")
            }
            Ok(Reexecution::NoWitness) => {
                debug!(model = %dispute.receipt.model_id, "no other provider to re-execute the sampled answer")
            }
            Ok(Reexecution::Differs) => {
                if let Err(e) = file_fault(&node, &dispute, requester, refund).await {
                    warn!(model = %dispute.receipt.model_id, error = %e, "could not file inference fault");
                }
            }
            Err(e) => debug!(model = %dispute.receipt.model_id, error = %e, "re-execution failed"),
        }
    });
}

/// The compute bond of the machine that signed `receipt`: held for the
/// receipt's machine DID, whose registered identity key signed it.
fn bond_of(node: &TenzroNode, receipt: &InferenceReceipt) -> Option<String> {
    tenzro_vm::native::compute_bond(&node.chain_state()?, &receipt.machine_did)?;
    let key = crate::identity_bootstrap::registered_identity_key(
        &node.identity_registry_slot(),
        &receipt.machine_did,
    )?;
    (key == receipt.public_key).then(|| receipt.machine_did.clone())
}

/// The evidence for a fault over `dispute`, refunding `refund` to `requester`.
pub fn evidence_for(
    dispute: &FiledAnswer,
    provider_did: String,
    requester: String,
    refund: u128,
) -> Result<tenzro_types::inference_verification::InferenceFaultEvidence, String> {
    let blob = serde_json::to_string(dispute).map_err(|e| e.to_string())?;
    if blob.len() > MAX_FAULT_DISPUTE_BYTES {
        return Err(format!(
            "the dispute is larger than {MAX_FAULT_DISPUTE_BYTES} bytes"
        ));
    }
    let receipt = &dispute.receipt;
    Ok(
        tenzro_types::inference_verification::InferenceFaultEvidence {
            receipt_digest: receipt.digest(),
            provider_did,
            receipt_preimage: hex::encode(receipt.preimage()),
            batched: hex::encode(
                serde_json::to_vec(&receipt.signature.batched).map_err(|e| e.to_string())?,
            ),
            requester,
            refund,
            served_at_ms: receipt.signed_at_ms,
            dispute: blob,
        },
    )
}

/// The filing operation for a fault over `dispute`.
pub fn fault_op_for(
    dispute: &FiledAnswer,
    provider_did: String,
    requester: String,
    refund: u128,
) -> Result<InferenceFaultOp, String> {
    Ok(InferenceFaultOp::File {
        evidence: evidence_for(dispute, provider_did, requester, refund)?,
    })
}

/// The fault id an operation files under.
pub fn fault_id_of(op: &InferenceFaultOp) -> Option<String> {
    match op {
        InferenceFaultOp::File { evidence } => Some(evidence.fault_id()),
        _ => None,
    }
}

/// File a fault for `dispute` on chain, refunding `requester`, who paid the
/// provider. Validators, this node among them when it holds bonded stake,
/// then review it.
async fn file_fault(
    node: &Arc<TenzroNode>,
    dispute: &ServedAnswer,
    requester: tenzro_types::primitives::Address,
    refund: u128,
) -> Result<(), String> {
    use tenzro_iroh::IrohResolver as _;
    let provider_did =
        bond_of(node, &dispute.receipt).ok_or("the provider serves under no compute bond")?;
    let resolver = node.iroh_resolver.as_ref();
    let (filed, parts) = dispute.dispute(resolver.map(|r| r.endpoint_id().to_string()))?;
    if !parts.is_empty() {
        let resolver =
            resolver.ok_or("this node has no content store to hold the dispute's parts")?;
        for part in parts {
            resolver
                .publish_bytes(part.into())
                .await
                .map_err(|e| format!("could not store a dispute part: {e}"))?;
        }
    }
    let op = fault_op_for(
        &filed,
        provider_did,
        hex::encode(requester.as_bytes()),
        refund,
    )?;
    let fault_id = fault_id_of(&op).ok_or("not a filing")?;
    let gas = filing_gas(&op);
    crate::rpc::submit_as_validator(
        node,
        tenzro_types::TransactionType::InferenceFault { op },
        gas,
    )
    .await
    .map_err(|e| e.message)?;
    info!(fault = %fault_id, model = %dispute.receipt.model_id, "filed inference fault");
    Ok(())
}

/// The gas limit a fault filing carries: the base cost of a transaction, then
/// what the fault handler meters per byte of its data, the selector and the op
/// JSON, in which the dispute is an escaped string next to the receipt's
/// preimage, certificate and signature.
fn filing_gas(op: &InferenceFaultOp) -> u64 {
    let data = tenzro_vm::native::SELECTOR_INFERENCE_FAULT.len()
        + serde_json::to_vec(op).map_or(MAX_FAULT_DISPUTE_BYTES * 2, |v| v.len());
    tenzro_vm::gas::evm_gas_costs::TRANSACTION
        + tenzro_vm::native::GAS_INFERENCE_FAULT
        + tenzro_vm::native::GAS_INFERENCE_FAULT_BYTE * data as u64
}

/// Judge one filed fault: the dispute must be the receipt the fault names,
/// from the machine it names, for the weights this node's catalog states and
/// within the window; then re-execute it. Consensus already checked that the
/// machine's registered identity key signed it. The parts the dispute holds by
/// content hash are fetched first. `None` when this node cannot judge (yet).
async fn judge(node: &TenzroNode, evidence: &InferenceFaultEvidence) -> Option<bool> {
    let filed: FiledAnswer = serde_json::from_str(&evidence.dispute).ok()?;
    let parts = match filed.fetch_parts(node).await {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "dispute parts not available yet");
            return None;
        }
    };
    let Ok(dispute) = filed.served(&parts) else {
        // Parts that verify against their hashes but do not restore the
        // answer: the dispute does not hold together.
        return Some(false);
    };
    let receipt = &dispute.receipt;
    let consistent = receipt.digest() == evidence.receipt_digest
        && receipt.machine_did == evidence.provider_did
        && receipt.signed_at_ms == evidence.served_at_ms
        && receipt.output_hash == dispute.output.hash()
        && is_greedy(receipt);
    if !consistent {
        // A dispute that does not hold together accuses no one.
        return Some(false);
    }
    if receipt.verify_against_catalog().is_err() {
        return Some(false);
    }
    corroborated(node, &dispute).await
}

/// Distinct witnesses a validator hears before it attests a verdict.
const VERDICT_WITNESSES: usize = 2;

/// Re-execute a filed dispute on [`VERDICT_WITNESSES`] distinct witnesses
/// drawn at random and judge it by [`verdict_of`]. `None` while too few
/// witnesses answer.
async fn corroborated(node: &TenzroNode, dispute: &ServedAnswer) -> Option<bool> {
    let mut witnesses = witnesses_for(node, &dispute.receipt);
    let mut answers = Vec::with_capacity(VERDICT_WITNESSES);
    while answers.len() < VERDICT_WITNESSES {
        let witness = draw_witness(&mut witnesses)?;
        match witness_answer(node, dispute, &witness).await {
            Ok(answer) => answers.push(answer),
            Err(e) => {
                debug!(witness = %witness.machine_did, error = %e, "witness did not re-execute the dispute")
            }
        }
    }
    verdict_of(&dispute.receipt.engine, &dispute.output, &answers)
}

/// The verdict on an accused answer from what distinct witnesses returned
/// when they re-executed it. Upheld only when every witness differs from it
/// and they agree with one another, so a slash rests on an answer more than
/// one machine reproduced and signed, never on one witness's word; dismissed
/// when every witness agrees with it; `None` (no attestation) when they split
/// or fewer than [`VERDICT_WITNESSES`] answered.
fn verdict_of(engine: &str, accused: &Answer, witnessed: &[Answer]) -> Option<bool> {
    if witnessed.len() < VERDICT_WITNESSES {
        return None;
    }
    if witnessed.iter().all(|w| answers_agree(engine, accused, w)) {
        return Some(false);
    }
    let reproduced = witnessed
        .iter()
        .all(|w| !answers_agree(engine, accused, w) && answers_agree(engine, &witnessed[0], w));
    reproduced.then_some(true)
}

/// On a validator, review pending inference faults and attest a verdict on
/// each this validator has not yet judged.
pub fn spawn_reviewer(node: Arc<TenzroNode>) {
    let Some(me) = node
        .ledger_submitter()
        .map(|s| hex::encode(s.address().as_bytes()))
    else {
        return;
    };
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REVIEW_INTERVAL).await;
            let Some(chain) = crate::rpc::chain_state_of(&node) else {
                continue;
            };
            if tenzro_vm::native::bonded_stake_of(&chain, &hex::decode(&me).unwrap_or_default())
                == 0
            {
                continue;
            }
            let window = tenzro_vm::native::network_param(&chain, WINDOW_MS_PARAM);
            let now = tenzro_crypto::session::now_ms() as i64;
            for id in pending_faults(&chain) {
                let Some(fault) = read_fault(&chain, &id) else {
                    continue;
                };
                if fault.upheld.is_some()
                    || now > fault.filed_at_ms.saturating_add(window as i64)
                    || fault.attestations.iter().any(|a| a.validator == me)
                {
                    continue;
                }
                let verdict = match &fault.evidence {
                    FaultEvidence::Inference(evidence) => judge(&node, evidence).await,
                    FaultEvidence::Catalog(fault) => {
                        crate::catalog_fault::judge(&node, fault).await
                    }
                };
                let Some(upheld) = verdict else {
                    continue;
                };
                let tx = tenzro_types::TransactionType::InferenceFault {
                    op: InferenceFaultOp::Attest {
                        fault_id: id.clone(),
                        upheld,
                    },
                };
                match crate::rpc::submit_as_validator(
                    &node,
                    tx,
                    tenzro_vm::native::GAS_INFERENCE_FAULT * 2,
                )
                .await
                {
                    Ok(_) => info!(fault = %id, upheld, "attested inference fault"),
                    Err(e) => {
                        warn!(fault = %id, error = %e.message, "could not attest inference fault")
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(text: &str) -> Output {
        Output {
            text: text.to_string(),
            reasoning: String::new(),
            tool_calls: String::new(),
        }
    }

    fn words(n: usize, tail: &str) -> String {
        let mut s: Vec<String> = (0..n).map(|i| format!("w{i}")).collect();
        s.push(tail.to_string());
        s.join(" ")
    }

    #[test]
    fn greedy_gguf_answers_agree_on_their_leading_words() {
        let a = out(&words(GREEDY_PREFIX_WORDS, "end."));
        let b = out(&words(GREEDY_PREFIX_WORDS, "finish."));
        assert!(outputs_agree("gguf", &a, &b));
        // Another model diverges early.
        let c = out(&format!("x {}", words(GREEDY_PREFIX_WORDS, "end.")));
        assert!(!outputs_agree("gguf", &a, &c));
        // A truncated answer is not the same answer.
        assert!(!outputs_agree("gguf", &a, &out("w0 w1")));
        // Other engines compare exactly.
        assert!(!outputs_agree("onnx-text-embedding", &a, &b));
        assert!(outputs_agree("onnx-text-embedding", &a, &a.clone()));
    }

    #[test]
    fn one_lying_witness_cannot_frame_an_honest_provider() {
        let honest = Answer::Chat(out(&words(GREEDY_PREFIX_WORDS, "end.")));
        let forged = Answer::Chat(out("a substituted answer"));
        let other = Answer::Chat(out("another substituted answer"));
        // A malicious witness alone: the fault is not upheld.
        assert_eq!(
            verdict_of("gguf", &honest, std::slice::from_ref(&forged)),
            None
        );
        // Beside an honest witness, in either order: still not upheld.
        assert_eq!(
            verdict_of("gguf", &honest, &[forged.clone(), honest.clone()]),
            None
        );
        assert_eq!(
            verdict_of("gguf", &honest, &[honest.clone(), forged.clone()]),
            None
        );
        // Witnesses that also disagree with each other prove nothing.
        assert_eq!(
            verdict_of("gguf", &honest, &[forged.clone(), other.clone()]),
            None
        );
        // Honest witnesses dismiss it.
        assert_eq!(
            verdict_of("gguf", &honest, &[honest.clone(), honest.clone()]),
            Some(false)
        );
        // A substituted answer two witnesses reproduce otherwise is upheld.
        assert_eq!(
            verdict_of("gguf", &forged, &[honest.clone(), honest.clone()]),
            Some(true)
        );
    }

    #[test]
    fn different_tool_calls_never_agree() {
        let mut a = out("same");
        let mut b = out("same");
        a.tool_calls = "[1]".into();
        b.tool_calls = "[2]".into();
        assert!(!outputs_agree("gguf", &a, &b));
    }

    fn signed(text: &str) -> InferenceReceipt {
        use crate::inference_receipt::{ModelIdentity, ReceiptClaims, SamplingParams};
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(Arc::new(
            tenzro_crypto::composite::testing::TestHybridSigner::random(),
        ));
        InferenceReceipt::sign(
            &signer,
            ReceiptClaims {
                decode: Default::default(),
                model_id: "m".into(),
                identity: ModelIdentity {
                    model_hash: "ab".repeat(32),
                    engine: "gguf".into(),
                },
                machine_did: "did:tenzro:machine:p".into(),
                nonce: "n".into(),
                input_commitment: "cd".repeat(32),
                output_hash: out(text).hash(),
                units: tenzro_types::model::BillableUnits::tokens(1, 1),
                priced: None,
                provenance: Vec::new(),
                sampling: SamplingParams {
                    seed: 0,
                    temperature: 0.0,
                    top_p: 1.0,
                    top_k: None,
                    min_p: None,
                    max_output_tokens: 16,
                    keyed_sampler: false,
                },
                commitment_hash: None,
                tee: None,
                activation_fingerprint: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn a_filing_carries_the_gas_its_transaction_spends() {
        let receipt = signed(&"a \"quoted\" answer ".repeat(64));
        let served = ServedAnswer {
            receipt,
            request: serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "say \"hi\""}]}),
            output: Answer::Chat(out(&"a \"quoted\" answer ".repeat(64))),
        };
        let (filed, _) = served.dispute(Some("holder".into())).unwrap();
        let evidence =
            evidence_for(&filed, "did:tenzro:machine:p".into(), "ee".repeat(20), 9).unwrap();
        let op = InferenceFaultOp::File { evidence };
        // What the transaction spends: the base cost of a transaction, then
        // what the fault handler meters over the selector and the op JSON,
        // in which the dispute is an escaped string.
        let data = tenzro_vm::native::SELECTOR_INFERENCE_FAULT.len()
            + serde_json::to_vec(&op).unwrap().len();
        let spent = tenzro_vm::gas::evm_gas_costs::TRANSACTION
            + tenzro_vm::native::GAS_INFERENCE_FAULT
            + tenzro_vm::native::GAS_INFERENCE_FAULT_BYTE * data as u64;
        assert!(filing_gas(&op) >= spent, "{} < {spent}", filing_gas(&op));
    }

    #[test]
    fn a_dispute_round_trips_from_an_answer_into_fault_evidence() {
        let receipt = signed("hello there");
        let body = serde_json::json!({
            "choices": [{"message": {"content": "hello there"}}],
            "tenzro_receipt": receipt,
        });
        let (parsed, output) = parse_answer(&body).unwrap();
        assert_eq!(parsed, receipt);
        assert_eq!(output.hash(), receipt.output_hash);
        assert!(is_greedy(&receipt));

        let dispute = ServedAnswer {
            receipt: receipt.clone(),
            request: serde_json::json!({"model": "m", "messages": []}),
            output: Answer::Chat(output),
        };
        let (filed, parts) = dispute.dispute(Some("holder".into())).unwrap();
        assert!(
            parts.is_empty() && filed.parts_at.is_none(),
            "a small dispute is carried whole"
        );
        let e = evidence_for(&filed, "did:tenzro:machine:p".into(), "ee".repeat(20), 9).unwrap();
        assert_eq!(e.receipt_digest, receipt.digest());
        assert_eq!(e.receipt_preimage, hex::encode(receipt.preimage()));
        // The evidence carries exactly what consensus checks before a fault
        // links to the bond: the preimage names the machine and ends with the
        // serving time and the signer's identity key, and the batch
        // signature it carries verifies against that key at that time.
        let preimage = receipt.preimage();
        assert_eq!(
            tenzro_types::inference_verification::receipt_preimage_machine(&preimage),
            Some(receipt.machine_did.as_str())
        );
        assert!(preimage.ends_with(
            &tenzro_types::inference_verification::receipt_preimage_tail(
                e.served_at_ms,
                &receipt.public_key.p256,
                receipt.public_key.pq.as_deref(),
            )
        ));
        let sig: tenzro_crypto::batch::BatchedSignature =
            serde_json::from_slice(&hex::decode(&e.batched).unwrap()).unwrap();
        tenzro_crypto::batch::RecordSignature::batched(sig)
            .verify_record_at(
                &receipt.public_key,
                &hex::decode(&e.receipt_preimage).unwrap(),
                e.served_at_ms,
            )
            .unwrap();
        assert_eq!(e.served_at_ms, receipt.signed_at_ms);
        let back: FiledAnswer = serde_json::from_str(&e.dispute).unwrap();
        assert_eq!(back.receipt.digest(), e.receipt_digest);
        assert_eq!(
            back.served(&Default::default()).unwrap().output.hash(),
            receipt.output_hash
        );

        // A conversation larger than a fault holds is carried by hash.
        let huge = ServedAnswer {
            request: serde_json::json!({"messages": "x".repeat(MAX_FAULT_DISPUTE_BYTES)}),
            ..dispute
        };
        let (filed, parts) = huge.dispute(Some("holder".into())).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(filed.parts_at.as_deref(), Some("holder"));
        let e = evidence_for(&filed, "d".into(), "ee".repeat(20), 9).unwrap();
        assert!(e.dispute.len() < 2 * INLINE_COMMIT_BYTES);
        let back: FiledAnswer = serde_json::from_str(&e.dispute).unwrap();
        assert!(
            back.served(&Default::default()).is_err(),
            "the parts are needed to restore it"
        );
        let held = parts
            .iter()
            .map(|p| (blake3::hash(p).to_hex().to_string(), p.clone()))
            .collect();
        assert_eq!(back.served(&held).unwrap().request, huge.request);
    }

    /// A segmentation answer far larger than a fault: the receipt commits to
    /// the masks by content hash, the dispute fits, and a validator holding
    /// the parts restores exactly the answer the receipt bound.
    #[test]
    fn large_task_outputs_are_disputed_by_content_hash() {
        let mask: Vec<u8> = (0..300_000u32).map(|i| u8::from(i % 7 == 0)).collect();
        let out = serde_json::json!({
            "masks": [{ "width": 600, "height": 500, "score": 0.93, "mask": mask }],
            "generation_time_ms": 12,
        });
        assert!(crate::verifiable_inference::canonical_json(&out).len() > MAX_FAULT_DISPUTE_BYTES);
        let answer = Answer::Task {
            task: "segment".into(),
            out: out.clone(),
        };

        // The committed form keeps the small members and names the masks by hash.
        let (form, parts) = content_committed(&out);
        assert_eq!(form["generation_time_ms"], serde_json::json!(12));
        let (hash, len) =
            content_reference(&form["masks"]).expect("the masks are a content reference");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].len(), len);
        assert_eq!(blake3::hash(&parts[0]).to_hex().as_str(), hash);
        assert_eq!(
            content_committed(&form).0,
            form,
            "committing a committed form changes nothing"
        );
        assert_eq!(
            answer.hash(),
            Answer::Task {
                task: "segment".into(),
                out: form.clone()
            }
            .hash()
        );

        // One pixel more is another commitment.
        let mut other = out.clone();
        other["masks"][0]["mask"][1] = serde_json::json!(1);
        assert_ne!(
            answer.hash(),
            Answer::Task {
                task: "segment".into(),
                out: other
            }
            .hash()
        );

        let mut receipt = signed("x");
        receipt.output_hash = answer.hash();
        let served = ServedAnswer {
            receipt,
            request: serde_json::json!({ "method": "tenzro_segment", "params": { "image_base64": "A".repeat(200_000) } }),
            output: answer.clone(),
        };
        let (filed, parts) = served.dispute(Some("holder".into())).unwrap();
        assert_eq!(parts.len(), 2, "the image and the masks");
        let e = evidence_for(&filed, "d".into(), "ee".repeat(20), 9).unwrap();
        assert!(e.dispute.len() <= MAX_FAULT_DISPUTE_BYTES);

        let back: FiledAnswer = serde_json::from_str(&e.dispute).unwrap();
        let held: std::collections::HashMap<String, Vec<u8>> = parts
            .iter()
            .map(|p| (blake3::hash(p).to_hex().to_string(), p.clone()))
            .collect();
        let restored = back.served(&held).unwrap();
        assert_eq!(restored.output, answer);
        assert_eq!(restored.request, served.request);
        assert_eq!(restored.output.hash(), back.receipt.output_hash);

        // A part that is not the one the reference names restores nothing.
        let mut forged = held.clone();
        let masks = forged.values_mut().find(|v| v.len() > 250_000).unwrap();
        masks[10] ^= 1;
        assert!(back.served(&forged).is_err());
    }

    #[test]
    fn task_answers_agree_within_numeric_tolerance() {
        let a = serde_json::json!({"model_id": "e", "embeddings": [[0.5, -0.25, 0.125]], "dim": 3, "generation_time_ms": 10});
        let near = serde_json::json!({"model_id": "e", "embeddings": [[0.5004, -0.2502, 0.1249]], "dim": 3, "generation_time_ms": 99});
        let far = serde_json::json!({"model_id": "e", "embeddings": [[-0.1, 0.4, 0.3]], "dim": 3, "generation_time_ms": 10});
        assert!(
            task_outputs_agree("text_embed", &a, &near),
            "timing aside, rounding agrees"
        );
        assert!(!task_outputs_agree("text_embed", &a, &far));
        let other_dim =
            serde_json::json!({"model_id": "e", "embeddings": [[0.5, -0.25, 0.125]], "dim": 4});
        assert!(
            !task_outputs_agree("text_embed", &a, &other_dim),
            "integers compare exactly"
        );
        let t = |s: &str| serde_json::json!({"text": s, "audio_ms": 1000});
        assert!(task_outputs_agree(
            "transcribe",
            &t("hello there"),
            &t("hello there")
        ));
        assert!(!task_outputs_agree(
            "transcribe",
            &t("hello there"),
            &t("goodbye there")
        ));
        let extra = serde_json::json!({"text": "hello there", "audio_ms": 1000, "x": 1});
        assert!(!task_outputs_agree("transcribe", &t("hello there"), &extra));
    }

    #[test]
    fn speech_answers_agree_on_their_envelope_prefix() {
        let s = |env: Vec<u64>, sha: &str, ms: u64| serde_json::json!({"model_id": "s", "format": "wav", "seed": 7, "audio_sha256": sha, "duration_ms": ms, "envelope": env});
        let base: Vec<u64> = (0..60).map(|i| 1000 + 10 * i).collect();
        let mut drift = base.clone();
        drift[55] = 9; // past the prefix
        drift.push(5);
        let jitter: Vec<u64> = base.iter().map(|v| v + 30).collect();
        assert!(task_outputs_agree(
            "speech",
            &s(base.clone(), "aa", 1200),
            &s(jitter, "bb", 1200)
        ));
        assert!(task_outputs_agree(
            "speech",
            &s(base.clone(), "aa", 1200),
            &s(drift, "cc", 1220)
        ));
        let other: Vec<u64> = base.iter().map(|v| v * 3).collect();
        assert!(!task_outputs_agree(
            "speech",
            &s(base.clone(), "aa", 1200),
            &s(other, "aa", 1200)
        ));
        let mut reseeded = s(base.clone(), "aa", 1200);
        reseeded["seed"] = serde_json::json!(8);
        assert!(!task_outputs_agree(
            "speech",
            &s(base, "aa", 1200),
            &reseeded
        ));
    }

    #[test]
    fn task_answers_commit_without_delivery_fields() {
        let result = serde_json::json!({
            "model_id": "r", "results": [{"index": 0, "relevance_score": 0.9}],
            "tenzro_receipt": {"x": 1}, "units": {}, "cost_wei": "5", "settlement": {}, "audio_base64": "AA=="
        });
        let committed = committed_task_output(&result);
        assert_eq!(
            committed,
            serde_json::json!({"model_id": "r", "results": [{"index": 0, "relevance_score": 0.9}]})
        );
        let answer = Answer::Task {
            task: "rerank".into(),
            out: committed.clone(),
        };
        assert_eq!(
            answer.hash(),
            task_commitment(
                "rerank",
                &crate::verifiable_inference::canonical_json(&committed)
            )
        );
        assert_ne!(
            answer.hash(),
            Answer::Task {
                task: "segment".into(),
                out: committed
            }
            .hash()
        );
        let back: Answer = serde_json::from_str(&serde_json::to_string(&answer).unwrap()).unwrap();
        assert_eq!(back, answer);
        assert!(!answers_agree("onnx", &answer, &Answer::Chat(out("hi"))));
        assert!(parse_task_answer("rerank", &serde_json::json!({"error": {"code": 1}})).is_none());
    }

    #[test]
    fn answers_parse_in_both_shapes() {
        let r = signed("hi");
        let (_, o) =
            parse_answer(&serde_json::json!({"result": {"output": "hi", "tenzro_receipt": r}}))
                .unwrap();
        assert_eq!(o.hash(), r.output_hash);
        let receipt = serde_json::json!(null);
        // No receipt, no answer.
        assert!(parse_answer(&serde_json::json!({"choices": [{"message": {"content": "hi"}}], "tenzro_receipt": receipt})).is_none());
        assert!(parse_answer(&serde_json::json!({"result": {"output": "hi"}})).is_none());
    }
}
