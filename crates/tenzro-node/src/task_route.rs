//! Modality calls served by another provider.
//!
//! A modality call (embedding, rerank, segmentation, detection, forecast,
//! transcription, video embedding, speech, media render) for a model this node does not
//! serve, or pinned to another provider's offer, is forwarded the way a chat
//! completion is: the provider is picked by [`crate::rpc::network_offer`],
//! dialled on the `tenzro/infer` ALPN with a fresh receipt nonce, its signed
//! task receipt is checked against the key its machine registered, the units
//! the receipt binds are billed at the price its announcement stated, and an
//! `optimistic` answer is drawn for re-execution on another provider
//! ([`crate::optimistic::spawn_check`]) exactly as a completion is.

use std::sync::Arc;

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_types::inference_verification::VerificationLevel;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Request fields that address this node or its payment rather than the
/// provider's work; never forwarded.
const LOCAL_FIELDS: &[&str] = &[
    "payment",
    "channel_voucher",
    "provider",
    "provider_access_token",
    "provider_dpop",
    "caller_address",
    "access_token",
    "dpop",
];

fn refused(code: i32, message: String) -> JsonRpcError {
    JsonRpcError {
        code,
        message,
        data: None,
    }
}

/// Serve `method` (whose receipts name `task`) on another provider when this
/// node should not answer it itself. `Ok(None)` means the call is this
/// node's to serve.
pub(crate) async fn forward(
    node: &Arc<TenzroNode>,
    method: &str,
    task: &str,
    params: &Value,
    model_id: &str,
) -> Result<Option<Value>, JsonRpcError> {
    let level = crate::verifiable_inference::level_param(params.get("verification"))?;
    let pinned = match params.get("provider").and_then(Value::as_str) {
        Some(hex) => Some(
            tenzro_types::primitives::Address::from_hex(hex)
                .map_err(|e| refused(-32602, format!("'provider': {e}")))?,
        ),
        None => None,
    };
    let pinned_elsewhere = pinned.is_some_and(|pin| node.operator_payee() != Some(pin));
    let served_here = node.served_models.contains_key(model_id);
    if served_here && !pinned_elsewhere {
        return Ok(None);
    }
    let Some(svc) = crate::rpc::network_offer(node, model_id, pinned, level) else {
        if let Some(pin) = pinned.filter(|_| pinned_elsewhere && !served_here) {
            return Err(refused(
                -32004,
                format!(
                    "Provider 0x{} is no longer offering model '{model_id}'. Route again to pick a live offer.",
                    hex::encode(pin.as_bytes())
                ),
            ));
        }
        // Nobody else offers it: this node answers, or says it cannot.
        return Ok(None);
    };

    let nonce = crate::inference_receipt::fresh_nonce();
    let mut forward_params = params.clone();
    if let Some(obj) = forward_params.as_object_mut() {
        for f in LOCAL_FIELDS {
            obj.remove(*f);
        }
        obj.insert("model_id".to_string(), json!(svc.model_id));
        obj.insert("verification".to_string(), json!(level));
        obj.insert("receipt_nonce".to_string(), json!(nonce));
    }
    let forward_body =
        json!({ "jsonrpc": "2.0", "method": method, "params": forward_params, "id": 1 });
    let request_bytes = serde_json::to_vec(&forward_body)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);

    let bytes = crate::infer::call_provider(
        node,
        &svc.iroh_endpoint_id,
        &forward_body,
        &crate::forward_billing::ProviderCredential::from_params(params),
    )
    .await
    .map_err(|e| {
        refused(
            -32000,
            format!("Failed to reach provider {}: {e}", svc.provider_name),
        )
    })?;
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|e| refused(-32000, format!("Failed to parse provider response: {e}")))?;
    if let Some(err) = body.get("error") {
        return Err(refused(
            err.get("code")
                .and_then(Value::as_i64)
                .and_then(|c| i32::try_from(c).ok())
                .unwrap_or(-32000),
            format!(
                "provider {}: {}",
                svc.provider_name,
                err.get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("error")
            ),
        ));
    }
    let result = body.get("result").cloned().unwrap_or(Value::Null);
    let committed = crate::optimistic::committed_task_output(&result);
    if task == "speech" {
        check_delivered_speech(&result, &committed).map_err(|e| {
            crate::verifiable_inference::answer_refused(&svc.provider_name, level, e)
        })?;
    }
    if task == "media" {
        crate::media_verify::check_delivered(node, &result, &committed, &svc.iroh_endpoint_id)
            .await
            .map_err(|e| {
                crate::verifiable_inference::answer_refused(&svc.provider_name, level, e)
            })?;
    }
    let answer = crate::optimistic::Answer::Task {
        task: task.to_string(),
        out: committed,
    };
    let output_hash = answer.hash();

    let pinned_key = crate::rpc::pinned_identity_key(node, model_id, &svc.provider_name);
    crate::verifiable_inference::check_answer(
        node,
        level,
        model_id,
        &nonce,
        pinned_key.as_ref(),
        result.get("tenzro_receipt"),
        &output_hash,
    )
    .map_err(|e| crate::verifiable_inference::answer_refused(&svc.provider_name, level, e))?;
    let (units, _) = crate::forward_billing::ForwardLeg {
        model_id,
        nonce: &nonce,
        pinned_key: pinned_key.as_ref(),
        bound: crate::forward_billing::UsageBound {
            max_output_tokens: None,
            request_bytes: request_bytes as u64,
            response_bytes: bytes.len() as u64,
            pixel_steps: 0,
        },
    }
    .billable(
        result.get("units").map(crate::rpc::units_from_json),
        result.get("tenzro_receipt"),
        &output_hash,
    );
    node.metrics().record_inference();

    let cost_wei = crate::verifiable_inference::priced(
        crate::inference_pricing::charge_wei(node, &svc.pricing, &units).map_err(|e| {
            crate::rpc::JsonRpcError {
                code: -32023,
                message: format!("the provider's card cannot price this call: {e}"),
                data: None,
            }
        })?,
        crate::verifiable_inference::surcharge_bps(node, level),
    );
    let settlement = crate::rpc::settle_inference_cost(
        node,
        params.get("payment"),
        params.get("channel_voucher"),
        Some(svc.provider_address),
        model_id,
        &units,
        cost_wei,
    )
    .await?;
    if level == VerificationLevel::Optimistic
        && let Some(receipt) = result.get("tenzro_receipt").and_then(|r| {
            serde_json::from_value::<crate::inference_receipt::InferenceReceipt>(r.clone()).ok()
        })
        && let Some(caller) = params
            .get("caller_address")
            .and_then(Value::as_str)
            .and_then(|s| tenzro_types::primitives::Address::from_hex(s).ok())
    {
        crate::optimistic::spawn_check(
            node.clone(),
            crate::optimistic::ServedAnswer {
                receipt,
                request: forward_body,
                output: answer,
            },
            caller,
            cost_wei,
        );
    }

    let mut out = result;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("units".to_string(), crate::rpc::units_to_json(&units));
        obj.insert("cost_wei".to_string(), json!(cost_wei.to_string()));
        obj.insert("settlement".to_string(), settlement.to_json());
        obj.insert("location".to_string(), json!("network"));
        obj.insert("provider".to_string(), json!(svc.provider_name));
    }
    Ok(Some(out))
}

/// A forwarded speech answer delivers the audio its receipt committed to by
/// hash and by loudness envelope; both are recomputed from the bytes.
fn check_delivered_speech(result: &Value, committed: &Value) -> Result<(), String> {
    let audio = result
        .get("audio_base64")
        .and_then(Value::as_str)
        .ok_or("the provider delivered no audio")?;
    let wav = base64::engine::general_purpose::STANDARD
        .decode(audio)
        .map_err(|e| format!("the delivered audio is not base64: {e}"))?;
    if committed.get("audio_sha256").and_then(Value::as_str)
        != Some(hex::encode(Sha256::digest(&wav)).as_str())
    {
        return Err(
            "the delivered audio does not match the hash the receipt commits to".to_string(),
        );
    }
    let envelope = speech_envelope(&wav).ok_or("the delivered audio is not 16-bit PCM WAV")?;
    if committed.get("envelope") != Some(&json!(envelope)) {
        return Err(
            "the delivered audio does not match the envelope the receipt commits to".to_string(),
        );
    }
    Ok(())
}

/// Windows per second of a speech envelope.
const ENVELOPE_WINDOWS_PER_SEC: u32 = 50;

/// The loudness envelope of a 16-bit PCM WAV: the RMS sample value of each
/// 20 ms window (the last one possibly shorter), in integer arithmetic so
/// every party computes the same numbers from the same bytes. A speech
/// receipt commits to it, and re-executions compare it.
pub fn speech_envelope(wav: &[u8]) -> Option<Vec<u16>> {
    let (rate, channels, pcm) = wav_pcm16(wav)?;
    let samples: Vec<i16> = pcm
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect();
    Some(rms_windows(
        &samples,
        envelope_window(rate) * channels as usize,
    ))
}

/// Samples per envelope window at `rate` (one channel).
pub fn envelope_window(rate: u32) -> usize {
    (rate / ENVELOPE_WINDOWS_PER_SEC).max(1) as usize
}

/// The RMS sample value of each `window` samples (the last one possibly
/// shorter), in integer arithmetic.
pub fn rms_windows(samples: &[i16], window: usize) -> Vec<u16> {
    samples
        .chunks(window.max(1))
        .map(|w| {
            let sum: u64 = w.iter().map(|&x| (x as i64 * x as i64) as u64).sum();
            (sum / w.len() as u64).isqrt() as u16
        })
        .collect()
}

/// Sample rate and first-channel samples of a 16-bit PCM WAV.
pub fn wav_first_channel(wav: &[u8]) -> Option<(u32, Vec<i16>)> {
    let (rate, channels, pcm) = wav_pcm16(wav)?;
    let frame = 2 * channels as usize;
    Some((
        rate,
        pcm.chunks_exact(frame)
            .map(|f| i16::from_le_bytes([f[0], f[1]]))
            .collect(),
    ))
}

/// Sample rate, channel count and the PCM bytes of a 16-bit PCM WAV.
fn wav_pcm16(wav: &[u8]) -> Option<(u32, u16, &[u8])> {
    if wav.len() < 12 || &wav[0..4] != b"RIFF" || &wav[8..12] != b"WAVE" {
        return None;
    }
    let mut at = 12;
    let mut format = None;
    while at + 8 <= wav.len() {
        let id = &wav[at..at + 4];
        let len = u32::from_le_bytes(wav[at + 4..at + 8].try_into().ok()?) as usize;
        let body = wav.get(at + 8..(at + 8).checked_add(len)?.min(wav.len()))?;
        match id {
            b"fmt " if body.len() >= 16 => {
                let tag = u16::from_le_bytes([body[0], body[1]]);
                let channels = u16::from_le_bytes([body[2], body[3]]);
                let rate = u32::from_le_bytes(body[4..8].try_into().ok()?);
                let bits = u16::from_le_bytes([body[14], body[15]]);
                if tag != 1 || bits != 16 || channels == 0 || rate == 0 {
                    return None;
                }
                format = Some((rate, channels));
            }
            b"data" => {
                let (rate, channels) = format?;
                return Some((rate, channels, body));
            }
            _ => {}
        }
        at += 8 + len + (len & 1);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wav(rate: u32, samples: &[i16]) -> Vec<u8> {
        let data: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
        let mut w = Vec::new();
        w.extend_from_slice(b"RIFF");
        w.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        w.extend_from_slice(b"WAVEfmt ");
        w.extend_from_slice(&16u32.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&1u16.to_le_bytes());
        w.extend_from_slice(&rate.to_le_bytes());
        w.extend_from_slice(&(rate * 2).to_le_bytes());
        w.extend_from_slice(&2u16.to_le_bytes());
        w.extend_from_slice(&16u16.to_le_bytes());
        w.extend_from_slice(b"data");
        w.extend_from_slice(&(data.len() as u32).to_le_bytes());
        w.extend_from_slice(&data);
        w
    }

    #[test]
    fn envelope_is_the_rms_of_each_window() {
        // 1000 Hz rate: 20 samples per window; a constant 300 then silence.
        let mut s = vec![300i16; 20];
        s.extend(vec![-300i16; 20]);
        s.extend(vec![0i16; 10]);
        assert_eq!(speech_envelope(&wav(1000, &s)).unwrap(), vec![300, 300, 0]);
        assert!(speech_envelope(b"not a wav").is_none());
    }

    #[test]
    fn delivered_speech_must_match_its_commitment() {
        let w = wav(1000, &[100; 40]);
        let committed = json!({
            "audio_sha256": hex::encode(Sha256::digest(&w)),
            "envelope": speech_envelope(&w).unwrap(),
        });
        let mut result = committed.clone();
        result["audio_base64"] = json!(base64::engine::general_purpose::STANDARD.encode(&w));
        assert!(check_delivered_speech(&result, &committed).is_ok());

        let other = wav(1000, &[101; 40]);
        result["audio_base64"] = json!(base64::engine::general_purpose::STANDARD.encode(&other));
        assert!(check_delivered_speech(&result, &committed).is_err());

        let mut lying = committed.clone();
        lying["envelope"] = json!([1, 1]);
        result["audio_base64"] = json!(base64::engine::general_purpose::STANDARD.encode(&w));
        assert!(check_delivered_speech(&result, &lying).is_err());
    }

    #[test]
    fn local_fields_never_reach_the_provider() {
        for f in [
            "payment",
            "channel_voucher",
            "provider_access_token",
            "caller_address",
        ] {
            assert!(LOCAL_FIELDS.contains(&f));
        }
    }
}
