//! Speech synthesis: `tenzro_loadSpeechModel`, `tenzro_unloadSpeechModel`,
//! `tenzro_speak`, and `POST /v1/audio/speech` (the OpenAI contract, WAV out).
//!
//! Speech runs on the Praecise engine in the node process. A call bills per
//! character spoken and per second of audio produced, and answers with a
//! signed receipt over the request and a hash of the audio at the
//! verification level the caller asked for. With the same seed, text, voice
//! and weights the same samples come out.
//!
//! Reference audio means voice cloning, which carries consent and
//! impersonation consequences a built-in voice does not: it is refused unless
//! the checkpoint supports it and the operator turned it on
//! (`TENZRO_ALLOW_VOICE_CLONING=1`). Choosing a model that can clone is not
//! the same act as offering cloning.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(feature = "inference")]
use tenzro_model::speech_runtime::{Speech, SpeechInput};
use tenzro_types::model::BillableUnits;

use crate::node::TenzroNode;
use crate::rpc::{
    JsonRpcError, bill_local_units, catalog_load_params, fetch_catalog_bundle, forecast_err,
    missing_param, not_in_catalog, record_multimodal_visibility, units_to_json,
};
use crate::verifiable_inference::{attach_task_receipt, task_level};

/// Frames a request may ask for at most.
const MAX_FRAMES: usize = 4096;

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn cloning_enabled() -> bool {
    std::env::var("TENZRO_ALLOW_VOICE_CLONING").as_deref() == Ok("1")
}

/// `tenzro_loadSpeechModel`: fetch and load a catalog speech model (backbone
/// and audio projector), or an omni model (thinker and talker, served on the
/// realtime transport by [`crate::voice_rpc`]). Params: `{ model_id,
/// visibility? }`.
#[cfg(feature = "inference")]
pub(crate) async fn handle_load(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = catalog_load_params(&p)?;
    if let Some(omni) = tenzro_model::get_omni_model_by_id(&model_id) {
        return load_omni(node, &p, model_id, omni).await;
    }
    let entry = tenzro_model::get_tts_model_by_id(&model_id)
        .ok_or_else(|| not_in_catalog("speech", &model_id))?;
    let (bundle_dir, provenance) = fetch_catalog_bundle(
        node,
        &model_id,
        &entry.hf_repo,
        vec![entry.hf_filename.clone(), entry.mmproj_filename.clone()],
        entry.size_bytes,
    )
    .await?;
    let gguf = bundle_dir.join(&entry.hf_filename);
    let mmproj = bundle_dir.join(&entry.mmproj_filename);
    let rt = node.speech_runtime.clone();
    let id = model_id.clone();
    tokio::task::spawn_blocking(move || rt.load(&id, &gguf, &mmproj))
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("speech load task: {e}"),
            data: None,
        })?
        .map_err(forecast_err)?;
    record_multimodal_visibility(node, "tenzro_loadSpeechModel", &p, &model_id)?;
    Ok(json!({
        "model_id": model_id,
        "bundle_dir": bundle_dir.display().to_string(),
        "loaded": true,
        "provenance": provenance.to_json(),
        "sample_rate": entry.sample_rate,
    }))
}

/// An omni model: thinker and talker, four files from one repository.
#[cfg(feature = "inference")]
async fn load_omni(
    node: &Arc<TenzroNode>,
    p: &Value,
    model_id: String,
    entry: tenzro_model::OmniModelEntry,
) -> Result<Value, JsonRpcError> {
    let files = vec![
        entry.hf_filename.clone(),
        entry.mmproj_filename.clone(),
        entry.talker_filename.clone(),
        entry.talker_mmproj_filename.clone(),
    ];
    let (bundle_dir, provenance) =
        fetch_catalog_bundle(node, &model_id, &entry.hf_repo, files, entry.size_bytes).await?;
    let path = |f: &str| bundle_dir.join(f);
    let (thinker, thinker_mmproj, talker, talker_mmproj) = (
        path(&entry.hf_filename),
        path(&entry.mmproj_filename),
        path(&entry.talker_filename),
        path(&entry.talker_mmproj_filename),
    );
    let rt = node.omni_runtime.clone();
    let id = model_id.clone();
    tokio::task::spawn_blocking(move || {
        rt.load(&id, &thinker, &thinker_mmproj, &talker, &talker_mmproj)
    })
    .await
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("omni load task: {e}"),
        data: None,
    })?
    .map_err(forecast_err)?;
    record_multimodal_visibility(node, "tenzro_loadSpeechModel", p, &model_id)?;
    Ok(json!({
        "model_id": model_id,
        "bundle_dir": bundle_dir.display().to_string(),
        "loaded": true,
        "provenance": provenance.to_json(),
        "sample_rate": entry.sample_rate,
        "voices": entry.voices,
    }))
}

/// `tenzro_unloadSpeechModel`. Params: `{ model_id }`.
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
    let removed = node.speech_runtime.unload(model_id) | node.omni_runtime.unload(model_id);
    crate::rpc::forget_multimodal_model(node, model_id);
    Ok(json!({ "model_id": model_id, "removed": removed }))
}

/// One synthesis as every surface serves it (`tenzro_speak`,
/// `POST /v1/audio/speech`, the speech leg of a realtime turn): the WAV and
/// the answer's JSON (everything but the audio itself). A model this node
/// does not serve, or a call pinned to another provider, is spoken by that
/// provider ([`crate::task_route::forward`]), whose delivered audio was
/// checked against its receipt and reaches `on_chunk` as one run.
/// `on_chunk` receives each run of samples as it is decoded.
pub(crate) async fn speak(
    node: &Arc<TenzroNode>,
    p: &Value,
    mut on_chunk: impl FnMut(u32, &[f32]) + Send + 'static,
) -> Result<(Vec<u8>, Value), JsonRpcError> {
    if let Some(model_id) = p.get("model_id").and_then(Value::as_str)
        && let Some(mut answer) =
            crate::task_route::forward(node, "tenzro_speak", "speech", p, model_id).await?
    {
        let wav = answer
            .as_object_mut()
            .and_then(|o| o.remove("audio_base64"))
            .and_then(|a| {
                a.as_str()
                    .and_then(|a| base64::engine::general_purpose::STANDARD.decode(a).ok())
            })
            .ok_or_else(|| JsonRpcError {
                code: -32000,
                message: "the provider delivered no audio".to_string(),
                data: None,
            })?;
        if let Some((rate, samples)) = crate::task_route::wav_first_channel(&wav) {
            let samples: Vec<f32> = samples.iter().map(|&s| f32::from(s) / 32768.0).collect();
            on_chunk(rate, &samples);
        }
        return Ok((wav, answer));
    }
    #[cfg(feature = "inference")]
    {
        let (speech, out) = speak_here(node, p, on_chunk).await?;
        Ok((speech.wav, out))
    }
    // The light build runs no speech model: a call no provider offers is
    // refused.
    #[cfg(not(feature = "inference"))]
    {
        let _ = on_chunk;
        Err(crate::rpc::not_offered("tenzro_speak"))
    }
}

/// [`speak`] on this node's own speech runtime.
#[cfg(feature = "inference")]
async fn speak_here(
    node: &Arc<TenzroNode>,
    p: &Value,
    on_chunk: impl FnMut(u32, &[f32]) + Send + 'static,
) -> Result<(Speech, Value), JsonRpcError> {
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?;
    let text = p
        .get("input")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("input"))?
        .to_string();
    let entry = tenzro_model::get_tts_model_by_id(model_id)
        .ok_or_else(|| not_in_catalog("speech", model_id))?;
    let speaker_reference = match p.get("ref_audio").and_then(Value::as_str) {
        None => None,
        Some(b64) => {
            if !entry.supports_voice_cloning {
                return Err(invalid(format!("{model_id} has no voice-cloning path")));
            }
            if !cloning_enabled() {
                return Err(JsonRpcError {
                    code: -32010,
                    message: "voice cloning is not enabled on this node; the operator must opt in before reference audio is accepted".into(),
                    data: None,
                });
            }
            Some(
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| invalid("ref_audio is base64 audio (wav, mp3 or flac)"))?,
            )
        }
    };
    let language = p
        .get("language")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(l) = &language
        && !entry.languages.iter().any(|x| x == l)
    {
        return Err(invalid(format!(
            "{model_id} speaks {}; not {l}",
            entry.languages.join(", ")
        )));
    }
    let seed = match p.get("seed") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .and_then(|s| u32::try_from(s).ok())
            .ok_or_else(|| invalid("seed is a u32"))?,
    };
    let max_frames = match p.get("max_frames") {
        None | Some(Value::Null) => MAX_FRAMES,
        Some(v) => v
            .as_u64()
            .filter(|n| *n > 0 && *n as usize <= MAX_FRAMES)
            .ok_or_else(|| invalid(format!("max_frames is 1 to {MAX_FRAMES}")))?
            as usize,
    };
    let level = task_level(node, p, model_id)?;

    let started = std::time::Instant::now();
    let characters = text.chars().count();
    let bytes_in = text.len() as u64;
    let speech = node
        .speech_runtime
        .synthesize(
            model_id,
            SpeechInput {
                text,
                language,
                speaker_reference,
                seed,
                max_frames,
            },
            on_chunk,
        )
        .await
        .map_err(forecast_err)?;
    let latency_ms = started.elapsed().as_millis() as u64;

    let units = BillableUnits::default()
        .with_characters(u32::try_from(characters).unwrap_or(u32::MAX))
        .with_audio_out_ms(speech.duration_ms);
    let (cost_wei, settlement) = bill_local_units(
        node,
        p,
        model_id,
        units.clone(),
        bytes_in,
        speech.wav.len() as u64,
        latency_ms,
    )
    .await?;
    let envelope = crate::task_route::speech_envelope(&speech.wav).ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "the speech runtime returned audio that is not 16-bit PCM WAV".to_string(),
        data: None,
    })?;
    let mut out = json!({
        "model_id": model_id,
        "format": "wav",
        "audio_sha256": hex::encode(Sha256::digest(&speech.wav)),
        "envelope": envelope,
        "sample_rate": speech.sample_rate,
        "duration_ms": speech.duration_ms,
        "frames": speech.frames,
        "seed": seed,
    });
    attach_task_receipt(node, p, model_id, "speech", level, units.clone(), &mut out).await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("units".to_string(), units_to_json(&units));
        obj.insert("cost_wei".to_string(), json!(cost_wei.to_string()));
        obj.insert("settlement".to_string(), settlement.to_json());
    }
    Ok((speech, out))
}

/// `tenzro_speak`: speak text. Params: `{ model_id, input, language?,
/// ref_audio? (base64), seed?, max_frames?, verification?, receipt_nonce?,
/// payment?, channel_voucher? }`. Returns the WAV base64-encoded beside its
/// hash, length, units, cost, settlement and signed receipt.
pub(crate) async fn handle_speak(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let (wav, mut out) = speak(node, &p, |_, _| {}).await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "audio_base64".to_string(),
            json!(base64::engine::general_purpose::STANDARD.encode(&wav)),
        );
    }
    Ok(out)
}

/// `POST /v1/audio/speech`: the OpenAI body (`model`, `input`, optional
/// `response_format` of `wav`, `speed` of 1), plus Tenzro's `language`,
/// `ref_audio`, `seed`, `verification` and `receipt_nonce`. Answers WAV; the
/// cost and the signed receipt (base64 JSON) ride in headers.
pub(crate) async fn handle_http(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::Json(mut body): axum::Json<Value>,
) -> axum::response::Response {
    use axum::http::{HeaderName, StatusCode, header};
    use axum::response::IntoResponse;
    let refuse = |status: StatusCode, message: &str, code: &str| {
        crate::rpc::json_error_response(status, message, "invalid_request_error", code)
    };
    if body
        .get("response_format")
        .and_then(Value::as_str)
        .is_some_and(|f| f != "wav")
    {
        return refuse(
            StatusCode::BAD_REQUEST,
            "this node answers speech as wav",
            "unsupported_format",
        );
    }
    if body
        .get("speed")
        .and_then(Value::as_f64)
        .is_some_and(|s| (s - 1.0).abs() > f64::EPSILON)
    {
        return refuse(StatusCode::BAD_REQUEST, "speed must be 1", "invalid_speed");
    }
    if let Some(obj) = body.as_object_mut() {
        for f in ["response_format", "speed", "voice"] {
            obj.remove(f);
        }
        if let Some(model) = obj.remove("model") {
            obj.insert("model_id".to_string(), model);
        }
    }
    match speak(&node, &body, |_, _| {}).await {
        Ok((wav, out)) => {
            let receipt = base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&out["tenzro_receipt"]).unwrap_or_default());
            let cost = out["cost_wei"].as_str().unwrap_or("0").to_string();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "audio/wav".to_string()),
                    (HeaderName::from_static("x-tenzro-cost-wei"), cost),
                    (HeaderName::from_static("x-tenzro-receipt"), receipt),
                ],
                wav,
            )
                .into_response()
        }
        Err(e) => {
            let status = match e.code {
                -32602 => StatusCode::BAD_REQUEST,
                -32010 => StatusCode::FORBIDDEN,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            refuse(status, &e.message, &e.code.to_string())
        }
    }
}
