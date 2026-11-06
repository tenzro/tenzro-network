//! `POST /v1/videos` and `GET /v1/videos/{id}/content`: the OpenAI video
//! request, rendered by `tenzro_mediaGen_render` on this node or on a provider
//! serving the model. The render completes before the answer, so the video
//! object comes back `completed`; its id is the content hash the output is
//! stored under, and the content route serves it from the content store.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::images_http::{Refusal, fetch_blob, passthrough, render_status};
use crate::node::TenzroNode;

fn bad(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        status: StatusCode::BAD_REQUEST,
        code,
        message: message.into(),
    }
}

/// A catalog entry's video defaults: width, height, steps, guidance, frame
/// count and frames per second.
pub(crate) type VideoDefaults = (u32, u32, u32, f32, u32, u32);

fn catalog_defaults(model: &str) -> Option<VideoDefaults> {
    let m = tenzro_model::get_media_gen_model_by_id(model)?;
    Some((
        m.default_width,
        m.default_height,
        m.default_steps,
        m.default_guidance_scale,
        m.default_num_frames?,
        m.default_fps?,
    ))
}

/// The `tenzro_mediaGen_render` params for an OpenAI video request. `seconds`
/// sets the frame count at the model's frame rate; Tenzro's `num_frames`,
/// `fps`, `steps` and `guidance_scale` set them exactly. A field left out
/// takes the model's catalog default; the seed is drawn by `seed` when the
/// caller sends none.
pub(crate) fn render_params(
    body: &Value,
    defaults: Option<VideoDefaults>,
    seed: impl FnOnce() -> u64,
) -> Result<Value, Refusal> {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .ok_or_else(|| bad("missing_model", "'model' is required"))?;
    let prompt = body
        .get("prompt")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| bad("missing_prompt", "'prompt' is required"))?;
    let need = |what: &str| {
        bad(
            "missing_default",
            format!("{model} has no default {what}: set it"),
        )
    };
    let whole = |key: &'static str| -> Result<Option<u32>, Refusal> {
        match body.get(key) {
            None => Ok(None),
            Some(v) => v
                .as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                .and_then(|n| u32::try_from(n).ok())
                .map(Some)
                .ok_or_else(|| bad("invalid_number", format!("'{key}' is a whole number"))),
        }
    };
    let (width, height) = match body.get("size").and_then(Value::as_str) {
        Some(size) => size
            .split_once('x')
            .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?)))
            .ok_or_else(|| bad("invalid_size", "'size' is WIDTHxHEIGHT, e.g. 832x480"))?,
        None => defaults.map(|d| (d.0, d.1)).ok_or_else(|| need("size"))?,
    };
    let steps = match whole("steps")? {
        Some(s) => s,
        None => defaults.map(|d| d.2).ok_or_else(|| need("steps"))?,
    };
    let guidance = match body.get("guidance_scale") {
        Some(v) => v
            .as_f64()
            .ok_or_else(|| bad("invalid_guidance_scale", "'guidance_scale' is a number"))?,
        None => defaults
            .map(|d| f64::from(d.3))
            .ok_or_else(|| need("guidance"))?,
    };
    let fps = match whole("fps")? {
        Some(f) => f,
        None => defaults.map(|d| d.5).ok_or_else(|| need("fps"))?,
    };
    let frames = match (whole("num_frames")?, whole("seconds")?) {
        (Some(n), _) => n,
        (None, Some(secs)) => secs.saturating_mul(fps),
        (None, None) => defaults.map(|d| d.4).ok_or_else(|| need("length"))?,
    };
    let seed = match body.get("seed") {
        Some(v) => v
            .as_u64()
            .ok_or_else(|| bad("invalid_seed", "'seed' is a whole number"))?,
        None => seed(),
    };
    let mut params = json!({
        "model_id": model,
        "kind": "text2video",
        "params": {
            "prompt": prompt,
            "negative_prompt": body.get("negative_prompt").and_then(Value::as_str),
            "width": width,
            "height": height,
            "num_frames": frames,
            "fps": fps,
            "steps": steps,
            "guidance_scale": guidance,
            "seed": seed,
        },
    });
    passthrough(body, &mut params);
    Ok(params)
}

/// The OpenAI video object for a completed render `out`.
pub(crate) fn video_object(out: &Value, model: &str, params: &Value, created: u64) -> Value {
    let p = &params["params"];
    let seconds = match (p["num_frames"].as_u64(), p["fps"].as_u64()) {
        (Some(n), Some(f)) if f > 0 => json!(format!("{}", n / f)),
        _ => Value::Null,
    };
    json!({
        "id": out.get("output_blake3"),
        "object": "video",
        "model": model,
        "status": "completed",
        "progress": 100,
        "created_at": created,
        "completed_at": created,
        "size": format!("{}x{}", p["width"], p["height"]),
        "seconds": seconds,
        "tenzro": {
            "mime": out.get("mime"),
            "output_sha256": out.get("output_sha256"),
            "output_blake3": out.get("output_blake3"),
            "cost_wei": out.get("cost_wei"),
            "settlement": out.get("settlement"),
            "receipt": out.get("tenzro_receipt"),
        },
    })
}

/// The media type of stored video bytes, from their container signature.
pub(crate) fn sniff(bytes: &[u8]) -> &'static str {
    if bytes.len() > 8 && &bytes[4..8] == b"ftyp" {
        "video/mp4"
    } else if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        "video/webm"
    } else if bytes.starts_with(b"GIF8") {
        "image/gif"
    } else {
        "application/octet-stream"
    }
}

/// `POST /v1/videos`.
pub(crate) async fn create(
    State(node): State<Arc<TenzroNode>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let refuse = |status: StatusCode, message: &str, code: &str| {
        crate::rpc::json_error_response(status, message, "invalid_request_error", code)
    };
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let params = match render_params(&body, catalog_defaults(&model), rand::random) {
        Ok(p) => p,
        Err(r) => return refuse(r.status, &r.message, r.code),
    };
    let out = match crate::media_verify::handle_render(&node, Some(params.clone())).await {
        Ok(out) => out,
        Err(e) => return refuse(render_status(e.code), &e.message, &e.code.to_string()),
    };
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let receipt = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        serde_json::to_vec(&out["tenzro_receipt"]).unwrap_or_default(),
    );
    let cost = out["cost_wei"].as_str().unwrap_or("0").to_string();
    (
        StatusCode::OK,
        [
            (HeaderName::from_static("x-tenzro-cost-wei"), cost),
            (HeaderName::from_static("x-tenzro-receipt"), receipt),
        ],
        axum::Json(video_object(&out, &model, &params, created)),
    )
        .into_response()
}

/// `GET /v1/videos/{id}/content`: the stored output under content hash `id`.
pub(crate) async fn content(
    State(node): State<Arc<TenzroNode>>,
    Path(id): Path<String>,
) -> Response {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return crate::rpc::json_error_response(
            StatusCode::BAD_REQUEST,
            "a video id is the 64-hex content hash its render returned",
            "invalid_request_error",
            "invalid_video_id",
        );
    }
    match fetch_blob(&node, &id).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, sniff(&bytes))],
            bytes,
        )
            .into_response(),
        Err(why) => crate::rpc::json_error_response(
            StatusCode::NOT_FOUND,
            &why,
            "invalid_request_error",
            "video_not_found",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COSMOS: VideoDefaults = (832, 480, 50, 5.0, 121, 24);

    #[test]
    fn an_openai_video_request_becomes_a_seeded_text2video_render() {
        let p = render_params(
            &json!({"model": "cosmos3-edge", "prompt": "waves", "seconds": "4"}),
            Some(COSMOS),
            || 3,
        )
        .unwrap();
        assert_eq!(p["kind"], "text2video");
        assert_eq!(p["params"]["num_frames"], 96);
        assert_eq!(p["params"]["fps"], 24);
        assert_eq!(p["params"]["width"], 832);
        assert_eq!(p["params"]["seed"], 3);
        let parsed: tenzro_types::MediaGenParams =
            serde_json::from_value(p["params"].clone()).unwrap();
        assert!(
            parsed
                .validate_for(tenzro_types::MediaGenKind::Text2Video)
                .is_ok()
        );
        let exact = render_params(
            &json!({"model": "m", "prompt": "x", "size": "320x192", "num_frames": 9,
                    "fps": 8, "steps": 4, "guidance_scale": 1.0, "seed": 1}),
            None,
            || unreachable!(),
        )
        .unwrap();
        assert_eq!(exact["params"]["num_frames"], 9);
        assert!(render_params(&json!({"model": "m", "prompt": "x"}), None, || 1).is_err());
    }

    #[test]
    fn the_video_object_is_completed_and_names_its_content_hash() {
        let out = json!({"output_blake3": "ab".repeat(32), "mime": "video/mp4",
                         "tenzro_receipt": {"model_id": "m"}, "cost_wei": "5"});
        let params = json!({"params": {"width": 832, "height": 480, "num_frames": 96, "fps": 24}});
        let v = video_object(&out, "cosmos3-edge", &params, 9);
        assert_eq!(v["status"], "completed");
        assert_eq!(v["id"], "ab".repeat(32));
        assert_eq!(v["size"], "832x480");
        assert_eq!(v["seconds"], "4");
        assert_eq!(v["tenzro"]["receipt"]["model_id"], "m");
        assert_eq!(sniff(b"\0\0\0\x18ftypisom"), "video/mp4");
    }
}
