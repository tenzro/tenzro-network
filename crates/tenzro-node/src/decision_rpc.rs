//! Decision models: `tenzro_loadDecisionModel`, `tenzro_unloadDecisionModel`,
//! `tenzro_listDecisionCatalog` and `tenzro_decide` (also `POST /tenzro/decide`;
//! no OpenAI contract exists for typed decisions).
//!
//! A decision call is billed per question answered, and answered with a signed
//! receipt over the request and the answers at the verification level the
//! caller asked for. Answering draws nothing, so any node holding the same
//! weights recomputes the same probabilities.
//!
//! The request carries a `state` (text, or any JSON value) and `questions`.
//! Each question has an `id`, a `type` (`choice`, `score` or `noul`), its
//! `instructions` (text or JSON) and its `criteria`:
//!
//! * `choice`: the options, as an array of `{ key, description? }` in the
//!   order the prompt lists them, or an object of key to description (listed
//!   in the order given);
//! * `score`: an array of 2 to 10 level descriptions, level 0 first;
//! * `noul` (yes or no): optionally `{ "false": ..., "true": ... }`
//!   describing the two answers.
//!
//! `questions` is an array of questions, or an object of id to question (the
//! shape the llama.cpp decision route takes), listed in the order given.

use std::sync::Arc;

#[cfg(feature = "inference")]
use serde_json::Map;
use serde_json::{Value, json};
#[cfg(feature = "inference")]
use tenzro_types::model::BillableUnits;

use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, missing_param};
#[cfg(feature = "inference")]
use crate::rpc::{
    bill_local_units, catalog_load_params, fetch_catalog_bundle, forecast_err, not_in_catalog,
    record_multimodal_visibility, units_to_json,
};
#[cfg(feature = "inference")]
use crate::verifiable_inference::{attach_task_receipt, task_level};

#[cfg(feature = "inference")]
fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

/// `tenzro_loadDecisionModel`: fetch and load a catalog decision model.
/// Params: `{ model_id, visibility? }`.
#[cfg(feature = "inference")]
pub(crate) async fn handle_load(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = catalog_load_params(&p)?;
    let entry = tenzro_model::get_decision_model_by_id(&model_id)
        .ok_or_else(|| not_in_catalog("decision", &model_id))?;
    let (bundle_dir, provenance) = fetch_catalog_bundle(
        node,
        &model_id,
        &entry.hf_repo,
        vec![entry.hf_filename.clone()],
        entry.size_bytes,
    )
    .await?;
    let gguf = bundle_dir.join(&entry.hf_filename);
    let rt = node.decision_runtime.clone();
    let id = model_id.clone();
    let n_ctx = entry.context_length;
    tokio::task::spawn_blocking(move || rt.load(&id, &gguf, n_ctx))
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("decision load task: {e}"),
            data: None,
        })?
        .map_err(forecast_err)?;
    record_multimodal_visibility(node, "tenzro_loadDecisionModel", &p, &model_id)?;
    Ok(json!({
        "model_id": model_id,
        "bundle_dir": bundle_dir.display().to_string(),
        "loaded": true,
        "provenance": provenance.to_json(),
    }))
}

/// `tenzro_unloadDecisionModel`. Params: `{ model_id }`.
#[cfg(feature = "inference")]
pub(crate) async fn handle_unload(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?;
    let removed = node.decision_runtime.unload(model_id);
    crate::rpc::forget_multimodal_model(node, model_id);
    Ok(json!({ "model_id": model_id, "removed": removed }))
}

/// `tenzro_listDecisionCatalog`.
pub(crate) async fn handle_catalog() -> Result<Value, JsonRpcError> {
    Ok(json!({
        "models": crate::catalog_rpc::with_licence(&tenzro_model::get_decision_catalog()),
    }))
}

#[cfg(feature = "inference")]
fn text_or_json(v: Option<&Value>) -> Value {
    v.cloned().unwrap_or(Value::Null)
}

#[cfg(feature = "inference")]
/// The options of a choice question.
fn choice_options(
    id: &str,
    criteria: Option<&Value>,
) -> Result<Vec<tenzro_model::decision_runtime::DecisionOption>, JsonRpcError> {
    use tenzro_model::decision_runtime::DecisionOption;
    let bad = |m: &str| invalid(format!("question {id}: {m}"));
    match criteria {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(key) => Ok(DecisionOption {
                    key: key.clone(),
                    description: Value::Null,
                }),
                Value::Object(o) => Ok(DecisionOption {
                    key: o
                        .get("key")
                        .and_then(Value::as_str)
                        .ok_or_else(|| bad("an option needs a text `key`"))?
                        .to_string(),
                    description: text_or_json(o.get("description")),
                }),
                _ => Err(bad("an option is a key or { key, description }")),
            })
            .collect(),
        Some(Value::Object(o)) if !o.is_empty() => Ok(o
            .iter()
            .map(|(key, description)| DecisionOption {
                key: key.clone(),
                description: description.clone(),
            })
            .collect()),
        _ => Err(bad("`criteria` of a choice is a non-empty array or object")),
    }
}

#[cfg(feature = "inference")]
/// One question from its JSON form.
fn parse_question(
    id: &str,
    q: &Value,
) -> Result<tenzro_model::decision_runtime::Question, JsonRpcError> {
    use tenzro_model::decision_runtime::Question;
    let bad = |m: &str| invalid(format!("question {id}: {m}"));
    let obj = q.as_object().ok_or_else(|| bad("must be an object"))?;
    let instructions = obj
        .get("instructions")
        .filter(|v| !v.is_null())
        .cloned()
        .ok_or_else(|| bad("`instructions` must be provided"))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("`type` must be one of: choice, score, noul"))?;
    let criteria = obj.get("criteria").filter(|v| !v.is_null());
    match kind {
        "choice" => Ok(Question::choice(
            id,
            instructions,
            choice_options(id, criteria)?,
        )),
        "score" => {
            let levels = criteria
                .and_then(Value::as_array)
                .ok_or_else(|| bad("`criteria` of a score is an array of level descriptions"))?;
            Ok(Question::score(id, instructions, levels.clone()))
        }
        "noul" => {
            let (f, t) = match criteria {
                None => (Value::Null, Value::Null),
                Some(Value::Object(o)) => {
                    for k in o.keys() {
                        if k != "false" && k != "true" {
                            return Err(bad(
                                "`criteria` of a yes/no describes \"false\" and \"true\"",
                            ));
                        }
                    }
                    (text_or_json(o.get("false")), text_or_json(o.get("true")))
                }
                Some(_) => return Err(bad("`criteria` of a yes/no is an object")),
            };
            Ok(Question::noul(id, instructions, f, t))
        }
        _ => Err(bad("`type` must be one of: choice, score, noul")),
    }
}

#[cfg(feature = "inference")]
/// The questions of a request, from an array of questions (each with an
/// `id`) or an object of id to question.
pub(crate) fn parse_questions(
    raw: &Value,
) -> Result<Vec<tenzro_model::decision_runtime::Question>, JsonRpcError> {
    match raw {
        Value::Array(items) if !items.is_empty() => items
            .iter()
            .enumerate()
            .map(|(i, q)| {
                let id = q
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid(format!("question {i}: an `id` is required")))?;
                parse_question(id, q)
            })
            .collect(),
        Value::Object(map) if !map.is_empty() => {
            map.iter().map(|(id, q)| parse_question(id, q)).collect()
        }
        _ => Err(invalid(
            "'questions' is a non-empty array of questions or object of id to question",
        )),
    }
}

#[cfg(feature = "inference")]
/// One answer as the wire carries it.
pub(crate) fn answer_json(a: &tenzro_model::decision_runtime::DecisionAnswer) -> Value {
    let mut o = Map::new();
    o.insert("id".into(), json!(a.id));
    o.insert("type".into(), json!(a.kind.name()));
    if let Some(c) = &a.choice {
        o.insert("choice".into(), json!(c));
    }
    if let Some(s) = a.score {
        o.insert("score".into(), json!(s));
    }
    if let Some(n) = a.noul {
        o.insert("noul".into(), json!(n));
    }
    if !a.probabilities.is_empty() {
        let p: Map<String, Value> = a
            .probabilities
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        o.insert("probabilities".into(), Value::Object(p));
    }
    if let Some(c) = a.confidence {
        o.insert("confidence".into(), json!(c));
    }
    if !a.legend.is_empty() {
        let l: Map<String, Value> = a.legend.iter().cloned().collect();
        o.insert("legend".into(), Value::Object(l));
    }
    Value::Object(o)
}

/// `tenzro_decide`: answer typed questions about a state.
///
/// Params: `{ model_id, state, questions, verification?, receipt_nonce?,
/// payment?, channel_voucher? }`. Returns `answers` (one per question, in
/// request order) with the units billed, the cost, the settlement and the
/// signed receipt.
pub(crate) async fn handle_decide(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    if let Some(model_id) = p.get("model_id").and_then(Value::as_str)
        && let Some(answer) =
            crate::task_route::forward(node, "tenzro_decide", "decide", &p, model_id).await?
    {
        return Ok(answer);
    }
    decide_here(node, p).await
}

/// `tenzro_decide` on this node's own decision model.
#[cfg(feature = "inference")]
async fn decide_here(node: &Arc<TenzroNode>, p: Value) -> Result<Value, JsonRpcError> {
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?;
    let state = p
        .get("state")
        .cloned()
        .ok_or_else(|| missing_param("state"))?;
    let questions = parse_questions(
        p.get("questions")
            .ok_or_else(|| missing_param("questions"))?,
    )?;
    let level = task_level(node, &p, model_id)?;

    let bytes_in = serde_json::to_vec(&state).map(|b| b.len()).unwrap_or(0) as u64
        + serde_json::to_vec(p.get("questions").unwrap_or(&Value::Null))
            .map(|b| b.len())
            .unwrap_or(0) as u64;
    let n_questions = questions.len();
    let started = std::time::Instant::now();
    let decided = node
        .decision_runtime
        .decide(model_id, state, questions)
        .await
        .map_err(forecast_err)?;
    let latency_ms = started.elapsed().as_millis() as u64;

    // A decision model bills per question answered; the tokens the prompts
    // took are the provider's cost, not a second charge to the caller.
    let units = BillableUnits::default()
        .with_decision_questions(u32::try_from(n_questions).unwrap_or(u32::MAX));
    let bytes_out = (n_questions * std::mem::size_of::<f64>()) as u64;
    let (cost_wei, settlement) = bill_local_units(
        node,
        &p,
        model_id,
        units.clone(),
        bytes_in,
        bytes_out,
        latency_ms,
    )
    .await?;

    let answers: Vec<Value> = decided.answers.iter().map(answer_json).collect();
    let mut out = json!({
        "model_id": model_id,
        "answers": answers,
        "usage": { "questions": n_questions, "input_tokens": decided.tokens },
    });
    attach_task_receipt(node, &p, model_id, "decide", level, units.clone(), &mut out).await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("units".to_string(), units_to_json(&units));
        obj.insert("cost_wei".to_string(), json!(cost_wei.to_string()));
        obj.insert("settlement".to_string(), settlement.to_json());
    }
    Ok(out)
}

/// The light build runs no decision model: a call no provider offers is refused.
#[cfg(not(feature = "inference"))]
async fn decide_here(_node: &Arc<TenzroNode>, _p: Value) -> Result<Value, JsonRpcError> {
    Err(crate::rpc::not_offered("tenzro_decide"))
}

/// `POST /tenzro/decide`: the body is the `tenzro_decide` params with the
/// model named `model`; the answer is the same.
pub(crate) async fn handle_http(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::Json(mut body): axum::Json<Value>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    if let Some(obj) = body.as_object_mut()
        && let Some(model) = obj.remove("model")
    {
        obj.insert("model_id".to_string(), model);
    }
    match handle_decide(&node, Some(body)).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => {
            let status = if e.code == -32602 {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            crate::rpc::json_error_response(
                status,
                &e.message,
                "invalid_request_error",
                &e.code.to_string(),
            )
        }
    }
}

#[cfg(all(test, feature = "inference"))]
mod tests {
    use super::*;
    use tenzro_model::decision_runtime::QuestionKind;

    #[test]
    fn questions_parse_from_an_array_or_an_object() {
        let arr = json!([
            {"id": "spam", "type": "noul", "instructions": "Is it spam?"},
            {"id": "kind", "type": "choice", "instructions": "Which?",
             "criteria": [{"key": "a", "description": "first"}, "b"]},
            {"id": "tone", "type": "score", "instructions": {"rate": "tone"},
             "criteria": ["bad", "ok", "good"]},
        ]);
        let qs = parse_questions(&arr).unwrap();
        assert_eq!(qs.len(), 3);
        assert_eq!(qs[0].kind, QuestionKind::Noul);
        assert_eq!(qs[0].options.len(), 2);
        assert_eq!(qs[1].options[0].key, "a");
        assert_eq!(qs[1].options[1].key, "b");
        assert_eq!(qs[2].options.len(), 3);
        // the llama.cpp object form: listed in the order given
        let obj = json!({
            "z": {"type": "noul", "instructions": "q?"},
            "a": {"type": "choice", "instructions": "q?", "criteria": {"y": "why", "x": null}},
        });
        let qs = parse_questions(&obj).unwrap();
        assert_eq!(qs[0].id, "z");
        assert_eq!(qs[1].id, "a");
        assert_eq!(qs[1].options[0].key, "y");
        assert_eq!(qs[1].options[1].key, "x");
    }

    #[test]
    fn a_malformed_question_is_a_parameter_error_naming_it() {
        for bad in [
            json!([]),
            json!("text"),
            json!([{"type": "noul", "instructions": "q"}]),
            json!([{"id": "q", "instructions": "q"}]),
            json!([{"id": "q", "type": "maybe", "instructions": "q"}]),
            json!([{"id": "q", "type": "noul"}]),
            json!([{"id": "q", "type": "choice", "instructions": "q"}]),
            json!([{"id": "q", "type": "score", "instructions": "q", "criteria": {"a": 1}}]),
            json!([{"id": "q", "type": "noul", "instructions": "q", "criteria": {"maybe": "x"}}]),
        ] {
            let err = parse_questions(&bad).unwrap_err();
            assert_eq!(err.code, -32602, "{bad}");
        }
    }

    #[test]
    fn answers_carry_only_the_fields_of_their_kind() {
        use tenzro_model::decision_runtime::DecisionAnswer;
        let a = DecisionAnswer {
            id: "k".into(),
            kind: QuestionKind::Choice,
            choice: Some("a".into()),
            score: None,
            noul: None,
            probabilities: vec![("a".into(), 0.75), ("b".into(), 0.25)],
            confidence: Some(0.5),
            legend: vec![],
            tokens: 12,
        };
        let v = answer_json(&a);
        assert_eq!(v["type"], "choice");
        assert_eq!(v["choice"], "a");
        assert_eq!(v["probabilities"]["b"], 0.25);
        assert!(v.get("score").is_none() && v.get("noul").is_none() && v.get("legend").is_none());
    }
}
