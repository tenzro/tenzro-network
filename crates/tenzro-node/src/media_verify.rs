//! Optimistic verification of media generation.
//!
//! A render is seeded, so another provider holding the same weights renders
//! the same output up to its hardware's numeric drift. Every render commits,
//! under a signed inference receipt for the task `media`, to the output's
//! type, SHA-256 and length, its perceptual fingerprint
//! ([`tenzro_model::media_fingerprint`]) and the tolerance two renders of it
//! must agree within ([`committed`]).
//!
//! `tenzro_mediaGen_render` renders one output synchronously, here or on a
//! provider serving the model. Anyone holding a render's receipt can
//! re-execute it on another provider through the same method
//! ([`crate::optimistic`]) and file an inference fault, refunding the caller
//! from the provider's bond, when the fingerprints disagree.

use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_model::media_fingerprint::{MediaFingerprint, agree};
#[cfg(feature = "inference")]
use tenzro_model::{Output, RenderJob};
use tenzro_types::media_gen::{MediaGenInputRole, MediaGenKind, MediaGenParams};

use crate::node::TenzroNode;
use crate::rpc::{JsonRpcError, missing_param};

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn failed(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: message.into(),
        data: None,
    }
}

/// What a render's receipt commits to: the output's media type, SHA-256 and
/// length, its fingerprint, and the tolerance in basis points a re-render
/// must agree within.
pub(crate) fn committed(mime: &str, bytes: &[u8]) -> Result<Value, String> {
    let fingerprint = tenzro_model::media_fingerprint::of(mime, bytes).ok_or_else(|| {
        format!(
            "a {mime} output has no perceptual fingerprint, so it cannot be checked by re-execution"
        )
    })?;
    Ok(json!({
        "mime": mime,
        "output_sha256": hex::encode(Sha256::digest(bytes)),
        "output_bytes": bytes.len(),
        "tolerance_bps": fingerprint.tolerance_bps(),
        "fingerprint": fingerprint,
    }))
}

/// Whether two committed renders are of the same output: the same media
/// type, and fingerprints within the smaller tolerance either committed to.
/// Their hashes and lengths differ from device to device and are not
/// compared.
pub(crate) fn renders_agree(a: &Value, b: &Value) -> bool {
    let fingerprint = |v: &Value| -> Option<MediaFingerprint> {
        serde_json::from_value(v.get("fingerprint")?.clone()).ok()
    };
    let tolerance = |v: &Value| {
        v.get("tolerance_bps")
            .and_then(Value::as_u64)
            .and_then(|t| u32::try_from(t).ok())
    };
    match (fingerprint(a), fingerprint(b), tolerance(a), tolerance(b)) {
        (Some(fa), Some(fb), Some(ta), Some(tb)) => {
            a.get("mime") == b.get("mime") && agree(&fa, &fb, ta.min(tb))
        }
        _ => false,
    }
}

/// A forwarded render delivers, at `output_blake3` on the provider, the
/// output its receipt committed to: the same SHA-256 and fingerprint,
/// recomputed from the bytes.
pub(crate) async fn check_delivered(
    node: &TenzroNode,
    result: &Value,
    committed: &Value,
    provider_endpoint: &str,
) -> Result<(), String> {
    use tenzro_iroh::IrohResolver as _;
    let hash = result
        .get("output_blake3")
        .and_then(Value::as_str)
        .ok_or("the provider delivered no output")?;
    let resolver = node
        .iroh_resolver
        .as_ref()
        .ok_or("this node has no content store to fetch the output")?;
    let uri = tenzro_types::tenzro_uri::TenzroUri::Blob {
        hash: hash.to_string(),
        provider_hint: Some(provider_endpoint.to_string()),
    };
    let bytes = resolver
        .fetch_bytes(&uri)
        .await
        .map_err(|e| format!("the delivered output could not be fetched: {e}"))?;
    let mime = committed
        .get("mime")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match self::committed(mime, &bytes) {
        Ok(ours) if ours == *committed => Ok(()),
        _ => Err("the delivered output does not match what the receipt commits to".to_string()),
    }
}

/// The bytes of `params.inputs` from `inputs_base64`, each checked against
/// the SHA-256 its entry names, paired with its role.
fn decode_inputs(
    p: &Value,
    params: &MediaGenParams,
) -> Result<Vec<(MediaGenInputRole, Vec<u8>)>, JsonRpcError> {
    let data = match p.get("inputs_base64") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => v
            .as_array()
            .ok_or_else(|| invalid("'inputs_base64' is a list of base64 strings"))?
            .clone(),
    };
    if data.len() != params.inputs.len() {
        return Err(invalid(format!(
            "'inputs_base64' carries {} inputs for the {} that params.inputs names",
            data.len(),
            params.inputs.len()
        )));
    }
    params
        .inputs
        .iter()
        .zip(&data)
        .enumerate()
        .map(|(i, (named, d))| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(d.as_str().unwrap_or_default())
                .map_err(|e| invalid(format!("inputs_base64[{i}]: {e}")))?;
            if Sha256::digest(&bytes).as_slice() != named.hash.as_bytes() {
                return Err(invalid(format!(
                    "inputs_base64[{i}] is not the input params.inputs[{i}] names"
                )));
            }
            Ok((named.role, bytes))
        })
        .collect()
}

/// `tenzro_mediaGen_render`: render one output, on this node or on a
/// provider serving the model, and answer with what its receipt commits to
/// ([`committed`]), the receipt, the price, and `output_blake3`, under which
/// the output can be fetched (`tenzro_iroh_fetchBlob`).
///
/// Params: `{ model_id, kind, params, inputs_base64?: [base64, ...],
/// verification?, provider?, receipt_nonce?, payment?, channel_voucher? }`.
/// `params` is the media market's job parameters and must carry the seed;
/// `inputs_base64` carries the bytes of the inputs `params.inputs` names by
/// SHA-256, in their order. A model whose schedule splits across two experts
/// renders on the market.
pub(crate) async fn handle_render(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?;
    if let Some(answer) =
        crate::task_route::forward(node, "tenzro_mediaGen_render", "media", &p, model_id).await?
    {
        return Ok(answer);
    }
    if let Some(upstream) = node.upstream_model(model_id).cloned() {
        return crate::connector::serve_render(node, &upstream, &p).await;
    }
    render_here(node, &p, model_id).await
}

/// `tenzro_mediaGen_render` on this node's own media models.
#[cfg(feature = "inference")]
async fn render_here(
    node: &Arc<TenzroNode>,
    p: &Value,
    model_id: &str,
) -> Result<Value, JsonRpcError> {
    let level = crate::verifiable_inference::task_level(node, p, model_id)?;
    let kind: MediaGenKind = serde_json::from_value(
        p.get("kind")
            .cloned()
            .ok_or_else(|| missing_param("kind"))?,
    )
    .map_err(|e| invalid(format!("'kind': {e}")))?;
    let media: MediaGenParams = serde_json::from_value(
        p.get("params")
            .cloned()
            .ok_or_else(|| missing_param("params"))?,
    )
    .map_err(|e| invalid(format!("'params': {e}")))?;
    media
        .validate_for(kind)
        .map_err(|e| invalid(e.to_string()))?;
    let seed = media
        .seed
        .ok_or_else(|| invalid("a render is seeded: set params.seed"))?;
    if tenzro_model::media_gen_model_splits(model_id) {
        return Err(invalid(format!(
            "{model_id} renders across two experts and is not served as one render"
        )));
    }
    let inputs = decode_inputs(p, &media)?;
    tenzro_model::access::check(model_id).map_err(|e| JsonRpcError {
        code: -32010,
        message: e.to_string(),
        data: None,
    })?;

    let started = Instant::now();
    let job = RenderJob {
        job_id: format!("render-{}", crate::inference_receipt::fresh_nonce()),
        kind,
        params: media.clone(),
        seed,
        requester: [0; 32],
        inputs,
        role: None,
        inbound_latent: None,
    };
    let output = tenzro_model::access::as_caller(
        tenzro_model::access::Caller::Node,
        node.media_models.runtime().render(model_id, job),
    )
    .await
    .map_err(crate::rpc::forecast_err)?;
    let Output::Media(rendered) = output else {
        return Err(failed("the render stopped at a hand-over latent"));
    };
    let out_bytes = rendered.bytes.len() as u64;
    let mut out = committed(&rendered.mime, &rendered.bytes).map_err(invalid)?;
    let units = crate::rpc::media_gen_units(kind, &media);
    crate::verifiable_inference::attach_task_receipt(
        node,
        p,
        model_id,
        "media",
        level,
        units.clone(),
        &mut out,
    )
    .await?;

    let blake3 = {
        use tenzro_iroh::IrohResolver as _;
        let resolver = node
            .iroh_resolver
            .as_ref()
            .ok_or_else(|| failed("this node has no content store to hold the output"))?;
        match resolver
            .publish_bytes(rendered.bytes.into())
            .await
            .map_err(|e| failed(format!("storing the output: {e}")))?
        {
            tenzro_types::tenzro_uri::TenzroUri::Blob { hash, .. } => hash,
            other => return Err(failed(format!("the content store answered {other:?}"))),
        }
    };
    let (cost_wei, settlement) = crate::rpc::bill_local_units(
        node,
        p,
        model_id,
        units.clone(),
        0,
        out_bytes,
        started.elapsed().as_millis() as u64,
    )
    .await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("output_blake3".into(), json!(blake3));
        obj.insert("units".into(), crate::rpc::units_to_json(&units));
        obj.insert("cost_wei".into(), json!(cost_wei.to_string()));
        obj.insert("settlement".into(), settlement.to_json());
    }
    Ok(out)
}

/// The light build runs no media model: a render no provider on the network
/// offers is refused.
#[cfg(not(feature = "inference"))]
async fn render_here(
    _node: &Arc<TenzroNode>,
    _p: &Value,
    _model_id: &str,
) -> Result<Value, JsonRpcError> {
    Err(crate::rpc::not_offered("tenzro_mediaGen_render"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimistic::Answer;

    /// Two seconds of 8 kHz mono sound whose level follows `level(i)`.
    fn wav(level: impl Fn(usize) -> f32) -> Vec<u8> {
        let data: Vec<u8> = (0..16_000usize)
            .flat_map(|i| ((((i as f32) * 0.37).sin() * level(i)) as i16).to_le_bytes())
            .collect();
        let mut w = b"RIFF".to_vec();
        w.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&8000u32.to_le_bytes());
        w.extend_from_slice(&16000u32.to_le_bytes());
        w.extend_from_slice(&2u16.to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&(data.len() as u32).to_le_bytes());
        w.extend_from_slice(&data);
        w
    }

    #[test]
    fn renders_agree_on_their_fingerprint_not_their_bytes() {
        let a = committed("audio/wav", &wav(|i| 2000.0 + i as f32 / 4.0)).unwrap();
        let drifted = committed("audio/wav", &wav(|i| 2010.0 + i as f32 / 4.0)).unwrap();
        // The same opening, then quiet: a track that stops early.
        let other = committed(
            "audio/wav",
            &wav(|i| {
                if i < 4000 {
                    2000.0 + i as f32 / 4.0
                } else {
                    50.0
                }
            }),
        )
        .unwrap();
        assert_ne!(a["output_sha256"], drifted["output_sha256"]);
        assert!(renders_agree(&a, &drifted));
        assert!(!renders_agree(&a, &other));

        // A wider committed tolerance does not loosen the comparison past
        // the other side's, nor past the protocol's cap.
        let mut loose = other.clone();
        loose["tolerance_bps"] = json!(u32::MAX);
        assert!(!renders_agree(&a, &loose));
        // Another media type is another output.
        let mut relabelled = drifted.clone();
        relabelled["mime"] = json!("audio/flac");
        assert!(!renders_agree(&a, &relabelled));
        assert!(!renders_agree(&a, &json!({})));
        assert!(committed("application/json", b"{}").is_err());
    }

    #[test]
    fn a_media_answer_is_compared_and_hashed_as_committed() {
        let a = committed("audio/wav", &wav(|_| 3000.0)).unwrap();
        let answer = Answer::Task {
            task: "media".into(),
            out: a.clone(),
        };
        let mut delivered = a.clone();
        delivered["output_blake3"] = json!("ab".repeat(32));
        delivered["cost_wei"] = json!("7");
        assert_eq!(
            crate::optimistic::committed_task_output(&delivered),
            a,
            "delivery fields are not committed"
        );
        let witness = committed("audio/wav", &wav(|_| 3020.0)).unwrap();
        assert!(crate::optimistic::answers_agree(
            "praecise",
            &answer,
            &Answer::Task {
                task: "media".into(),
                out: witness
            }
        ));
    }

    #[test]
    fn a_render_reads_exactly_the_inputs_its_params_name() {
        let input = vec![1u8, 2, 3];
        let params: MediaGenParams = serde_json::from_value(json!({
            "prompt": "a lighthouse", "negative_prompt": null, "width": 64, "height": 64,
            "num_frames": null, "fps": null, "steps": 4, "guidance_scale": 1.0, "seed": 9,
            "inputs": [{ "role": "reference", "hash": tenzro_types::primitives::Hash::new(Sha256::digest(&input).into()) }],
        }))
        .unwrap();
        let p = json!({ "model_id": "m", "kind": "image2image", "params": params, "inputs_base64": ["AQID"] });
        assert_eq!(
            decode_inputs(&p, &params).unwrap(),
            vec![(MediaGenInputRole::Reference, input)]
        );
        // Bytes other than the input the params name, or a missing one, are refused.
        assert!(decode_inputs(&json!({ "inputs_base64": ["AQIE"] }), &params).is_err());
        assert!(decode_inputs(&json!({}), &params).is_err());
    }
}
