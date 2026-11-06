//! `POST /v1/images/generations`: the OpenAI image request, rendered by
//! `tenzro_mediaGen_render` on this node or on a provider serving the model,
//! answered with the image inline and the render's receipt and settlement.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::{Value, json};

use crate::node::TenzroNode;

/// Fields passed through to the render unchanged.
const PASSED: &[&str] = &[
    "verification",
    "provider",
    "payment",
    "channel_voucher",
    "receipt_nonce",
];

/// Why a request is refused before anything renders.
#[derive(Debug, PartialEq)]
pub(crate) struct Refusal {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

fn bad(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        status: StatusCode::BAD_REQUEST,
        code,
        message: message.into(),
    }
}

/// The defaults a catalog entry gives a render: width, height, steps and
/// guidance.
pub(crate) type Defaults = (u32, u32, u32, f32);

fn catalog_defaults(model: &str) -> Option<Defaults> {
    tenzro_model::get_media_gen_model_by_id(model).map(|m| {
        (
            m.default_width,
            m.default_height,
            m.default_steps,
            m.default_guidance_scale,
        )
    })
}

/// The `tenzro_mediaGen_render` params for an OpenAI image request. A field
/// the caller leaves out takes the model's catalog default; a model the
/// catalog does not describe needs `size`, `steps` and `guidance_scale`. The
/// seed is drawn by `seed` when the caller sends none.
pub(crate) fn render_params(
    body: &Value,
    defaults: Option<Defaults>,
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
    if body.get("n").is_some_and(|n| n.as_u64() != Some(1)) {
        return Err(bad(
            "invalid_n",
            "this node renders one image per request: n must be 1",
        ));
    }
    if body
        .get("response_format")
        .and_then(Value::as_str)
        .is_some_and(|f| f != "b64_json")
    {
        return Err(bad(
            "unsupported_format",
            "this node answers the image inline: response_format must be b64_json",
        ));
    }
    let (width, height) = match body.get("size").and_then(Value::as_str) {
        Some(size) => {
            let (w, h) = size
                .split_once('x')
                .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?)))
                .ok_or_else(|| bad("invalid_size", "'size' is WIDTHxHEIGHT, e.g. 1024x1024"))?;
            (w, h)
        }
        None => defaults.map(|d| (d.0, d.1)).ok_or_else(|| {
            bad(
                "missing_size",
                format!("{model} has no default size: set 'size'"),
            )
        })?,
    };
    let steps = match body.get("steps") {
        Some(v) => v
            .as_u64()
            .and_then(|s| u32::try_from(s).ok())
            .ok_or_else(|| bad("invalid_steps", "'steps' is a whole number"))?,
        None => defaults.map(|d| d.2).ok_or_else(|| {
            bad(
                "missing_steps",
                format!("{model} has no default steps: set 'steps'"),
            )
        })?,
    };
    let guidance = match body.get("guidance_scale") {
        Some(v) => v
            .as_f64()
            .ok_or_else(|| bad("invalid_guidance_scale", "'guidance_scale' is a number"))?,
        None => defaults.map(|d| f64::from(d.3)).ok_or_else(|| {
            bad(
                "missing_guidance_scale",
                format!("{model} has no default guidance: set 'guidance_scale'"),
            )
        })?,
    };
    let seed = match body.get("seed") {
        Some(v) => v
            .as_u64()
            .ok_or_else(|| bad("invalid_seed", "'seed' is a whole number"))?,
        None => seed(),
    };
    let mut params = json!({
        "model_id": model,
        "kind": "text2image",
        "params": {
            "prompt": prompt,
            "negative_prompt": body.get("negative_prompt").and_then(Value::as_str),
            "width": width,
            "height": height,
            "num_frames": null,
            "fps": null,
            "steps": steps,
            "guidance_scale": guidance,
            "seed": seed,
        },
    });
    passthrough(body, &mut params);
    Ok(params)
}

/// Copies the fields a render takes unchanged from `body` into `params`.
pub(crate) fn passthrough(body: &Value, params: &mut Value) {
    for f in PASSED {
        if let Some(v) = body.get(*f) {
            params[*f] = v.clone();
        }
    }
}

/// The HTTP status for a render refused with JSON-RPC `code`.
pub(crate) fn render_status(code: i32) -> StatusCode {
    match code {
        -32602 => StatusCode::BAD_REQUEST,
        -32010 | -32001 => StatusCode::FORBIDDEN,
        -32004 => StatusCode::NOT_FOUND,
        -32023..=-32021 => StatusCode::PAYMENT_REQUIRED,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The OpenAI response for a render `out` whose image is `image`.
pub(crate) fn image_response(out: &Value, image: &[u8], created: u64) -> Value {
    json!({
        "created": created,
        "data": [{ "b64_json": base64::engine::general_purpose::STANDARD.encode(image) }],
        "tenzro": {
            "mime": out.get("mime"),
            "output_sha256": out.get("output_sha256"),
            "output_blake3": out.get("output_blake3"),
            "seed": out.get("seed"),
            "cost_wei": out.get("cost_wei"),
            "settlement": out.get("settlement"),
            "receipt": out.get("tenzro_receipt"),
        },
    })
}

/// `POST /v1/images/generations`. The cost and the signed receipt (base64
/// JSON) also ride in headers, as on the speech route.
pub(crate) async fn generations(
    State(node): State<Arc<TenzroNode>>,
    axum::Json(body): axum::Json<Value>,
) -> Response {
    let refuse = |status: StatusCode, message: &str, code: &str| {
        crate::rpc::json_error_response(status, message, "invalid_request_error", code)
    };
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = match render_params(&body, catalog_defaults(model), rand::random) {
        Ok(p) => p,
        Err(r) => return refuse(r.status, &r.message, r.code),
    };
    let out = match crate::media_verify::handle_render(&node, Some(params)).await {
        Ok(out) => out,
        Err(e) => return refuse(render_status(e.code), &e.message, &e.code.to_string()),
    };
    let image = match fetch_output(&node, &out).await {
        Ok(bytes) => bytes,
        Err(why) => return refuse(StatusCode::BAD_GATEWAY, &why, "output_unavailable"),
    };
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let receipt = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&out["tenzro_receipt"]).unwrap_or_default());
    let cost = out["cost_wei"].as_str().unwrap_or("0").to_string();
    (
        StatusCode::OK,
        [
            (HeaderName::from_static("x-tenzro-cost-wei"), cost),
            (HeaderName::from_static("x-tenzro-receipt"), receipt),
        ],
        axum::Json(image_response(&out, &image, created)),
    )
        .into_response()
}

/// The rendered bytes, from the content store under the hash the render
/// committed to.
async fn fetch_output(node: &Arc<TenzroNode>, out: &Value) -> Result<Vec<u8>, String> {
    let hash = out
        .get("output_blake3")
        .and_then(Value::as_str)
        .ok_or("the render named no output")?;
    fetch_blob(node, hash).await
}

/// The bytes stored under content hash `hash`.
pub(crate) async fn fetch_blob(node: &Arc<TenzroNode>, hash: &str) -> Result<Vec<u8>, String> {
    use tenzro_iroh::IrohResolver as _;
    let resolver = node
        .iroh_resolver
        .as_ref()
        .ok_or("this node has no content store to fetch the output")?;
    let uri = tenzro_types::tenzro_uri::TenzroUri::Blob {
        hash: hash.to_string(),
        provider_hint: None,
    };
    resolver
        .fetch_bytes(&uri)
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("the rendered output could not be fetched: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const QWEN: Defaults = (1328, 1328, 50, 4.0);

    #[test]
    fn an_openai_request_becomes_a_seeded_text2image_render_with_the_model_defaults() {
        let body = json!({"model": "qwen-image", "prompt": "a lighthouse", "n": 1,
                          "response_format": "b64_json", "verification": "receipt"});
        let p = render_params(&body, Some(QWEN), || 7).unwrap();
        assert_eq!(p["model_id"], "qwen-image");
        assert_eq!(p["kind"], "text2image");
        assert_eq!(p["params"]["width"], 1328);
        assert_eq!(p["params"]["steps"], 50);
        assert_eq!(p["params"]["guidance_scale"], 4.0);
        assert_eq!(p["params"]["seed"], 7);
        assert_eq!(p["verification"], "receipt");
        let parsed: tenzro_types::MediaGenParams =
            serde_json::from_value(p["params"].clone()).unwrap();
        assert!(
            parsed
                .validate_for(tenzro_types::MediaGenKind::Text2Image)
                .is_ok()
        );

        let sized = render_params(
            &json!({"model": "m", "prompt": "x", "size": "512x768", "steps": 4,
                    "guidance_scale": 0.0, "seed": 9}),
            None,
            || unreachable!(),
        )
        .unwrap();
        assert_eq!(
            (
                sized["params"]["width"].clone(),
                sized["params"]["height"].clone()
            ),
            (json!(512), json!(768))
        );
        assert_eq!(sized["params"]["seed"], 9);
    }

    #[test]
    fn what_this_node_cannot_answer_is_refused_by_name() {
        for (body, code) in [
            (json!({"prompt": "x"}), "missing_model"),
            (json!({"model": "m"}), "missing_prompt"),
            (json!({"model": "m", "prompt": "x", "n": 2}), "invalid_n"),
            (
                json!({"model": "m", "prompt": "x", "response_format": "url"}),
                "unsupported_format",
            ),
            (
                json!({"model": "m", "prompt": "x", "size": "big"}),
                "invalid_size",
            ),
            (json!({"model": "m", "prompt": "x"}), "missing_size"),
        ] {
            assert_eq!(
                render_params(&body, None, || 1).unwrap_err().code,
                code,
                "{body}"
            );
        }
    }

    #[test]
    fn the_response_carries_the_image_inline_with_its_receipt_and_settlement() {
        let out = json!({"mime": "image/png", "output_sha256": "ab", "output_blake3": "cd",
                         "cost_wei": "12", "settlement": {"status": "settled"},
                         "tenzro_receipt": {"model_id": "m"}});
        let r = image_response(&out, b"png", 5);
        assert_eq!(r["data"][0]["b64_json"], "cG5n");
        assert_eq!(r["tenzro"]["receipt"]["model_id"], "m");
        assert_eq!(r["tenzro"]["settlement"]["status"], "settled");
        assert_eq!(r["tenzro"]["cost_wei"], "12");
    }
}
