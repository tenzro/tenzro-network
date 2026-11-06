//! Janus-Pro and TRELLIS.2 render through the node's media runtime on their
//! real weights: an image from image tokens, and a GLB from a reference image,
//! each with the fingerprint its receipt commits to.
//!
//! The weights are not committed, so both tests are ignored by default. Run
//! with `--ignored` and:
//!
//! - `TENZRO_MEDIA_JANUS_CHECKPOINT`: the `deepseek-community/Janus-Pro-1B`
//!   files the catalog pins (`config.json`, `generation_config.json`,
//!   `model.safetensors`);
//! - `TENZRO_MEDIA_JANUS_GGUF_DIR`: the directory holding the backbone GGUF
//!   the catalog entry names;
//! - `TENZRO_MEDIA_TRELLIS_CHECKPOINT`: the assembled TRELLIS.2 checkpoint
//!   (`pipeline.json`, `ckpts/`, and the structure decoder and image encoder
//!   at the paths `pipeline.json` names);
//! - `TENZRO_MEDIA_REFERENCE`: an RGBA PNG of an object on a transparent
//!   background;
//! - optionally `TENZRO_MEDIA_OUT`, a directory the outputs are written to.

use std::collections::HashMap;
use std::path::PathBuf;

use tenzro_model::media_fingerprint::{self, GEOMETRY_GRID, MediaFingerprint};
use tenzro_model::{MediaPrecision, MediaRuntime, Output, RenderJob, Rendered};
use tenzro_types::{MediaGenInputRole, MediaGenKind, MediaGenParams};

fn env_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set")))
}

fn params(
    prompt: &str,
    width: u32,
    height: u32,
    steps: u32,
    guidance_scale: f32,
) -> MediaGenParams {
    MediaGenParams {
        prompt: prompt.into(),
        negative_prompt: None,
        width,
        height,
        num_frames: None,
        fps: None,
        steps,
        guidance_scale,
        voxel_resolution: None,
        audio_duration_secs: None,
        action_chunks: None,
        session_hold_secs: None,
        seed: Some(7),
        inputs: Vec::new(),
        metadata: HashMap::new(),
    }
}

async fn render(
    rt: &MediaRuntime,
    model_id: &str,
    kind: MediaGenKind,
    params: MediaGenParams,
    inputs: Vec<(MediaGenInputRole, Vec<u8>)>,
) -> Rendered {
    let job = RenderJob {
        job_id: format!("{model_id}-real"),
        kind,
        params,
        seed: 7,
        requester: [0; 32],
        inputs,
        role: None,
        inbound_latent: None,
    };
    match rt.render(model_id, job).await.expect("render") {
        Output::Media(r) => r,
        Output::Latent(_) => panic!("{model_id} handed over a latent"),
    }
}

fn keep(name: &str, r: &Rendered) -> MediaFingerprint {
    if let Ok(dir) = std::env::var("TENZRO_MEDIA_OUT") {
        std::fs::write(PathBuf::from(dir).join(name), &r.bytes).expect("write output");
    }
    let fp = media_fingerprint::of(&r.mime, &r.bytes).expect("a fingerprint");
    eprintln!(
        "{name}: {} bytes of {} in {} ms, tolerance {} bps",
        r.bytes.len(),
        r.mime,
        r.generation_ms,
        fp.tolerance_bps()
    );
    fp
}

#[tokio::test]
#[ignore = "needs the Janus-Pro weights: TENZRO_MEDIA_JANUS_CHECKPOINT and TENZRO_MEDIA_JANUS_GGUF_DIR"]
async fn janus_renders_an_image_from_image_tokens() {
    let rt = MediaRuntime::default();
    let dirs = [
        env_path("TENZRO_MEDIA_JANUS_CHECKPOINT"),
        env_path("TENZRO_MEDIA_JANUS_GGUF_DIR"),
    ];
    let info = rt
        .load(
            "janus-pro-1b",
            "JanusProPipeline",
            &dirs,
            1,
            MediaPrecision::Bf16,
        )
        .expect("load");
    eprintln!(
        "janus-pro-1b on {} ({} resident bytes)",
        info.device, info.resident_bytes
    );
    let prompt = "A red fox sitting in fresh snow, watercolor.";
    let r = render(
        &rt,
        "janus-pro-1b",
        MediaGenKind::Text2Image,
        params(prompt, 384, 384, 576, 5.0),
        Vec::new(),
    )
    .await;
    assert_eq!(r.mime, "image/png");
    let img = image::load_from_memory(&r.bytes).expect("a PNG").to_rgb8();
    assert_eq!(img.dimensions(), (384, 384));
    let fp = keep("janus.png", &r);
    let spread = fp.luma.iter().max().unwrap() - fp.luma.iter().min().unwrap();
    assert!(
        spread > 20,
        "a picture, not a flat field: luma spread {spread}"
    );

    // The same seed renders the same picture.
    let again = render(
        &rt,
        "janus-pro-1b",
        MediaGenKind::Text2Image,
        params(prompt, 384, 384, 576, 5.0),
        Vec::new(),
    )
    .await;
    let fp2 = keep("janus-again.png", &again);
    assert!(media_fingerprint::agree(&fp, &fp2, fp.tolerance_bps()));
    assert!(rt.unload("janus-pro-1b"));
}

#[tokio::test]
#[ignore = "needs the TRELLIS.2 weights: TENZRO_MEDIA_TRELLIS_CHECKPOINT and TENZRO_MEDIA_REFERENCE"]
async fn trellis_renders_a_glb_from_a_reference_image() {
    let rt = MediaRuntime::default();
    let dirs = [env_path("TENZRO_MEDIA_TRELLIS_CHECKPOINT")];
    let info = rt
        .load(
            "trellis2-4b",
            "Trellis2ImageTo3DPipeline",
            &dirs,
            1,
            MediaPrecision::Bf16,
        )
        .expect("load");
    eprintln!(
        "trellis2-4b on {} ({} resident bytes)",
        info.device, info.resident_bytes
    );
    let reference = std::fs::read(env_path("TENZRO_MEDIA_REFERENCE")).expect("reference image");
    let (w, h) = image::load_from_memory(&reference)
        .expect("an image")
        .into_rgba8()
        .dimensions();
    let mut p = params("", w, h, 12, 7.5);
    p.voxel_resolution = Some(512);
    let r = render(
        &rt,
        "trellis2-4b",
        MediaGenKind::Image23d,
        p,
        vec![(MediaGenInputRole::Reference, reference)],
    )
    .await;
    assert_eq!(r.mime, tenzro_model::media_runtime::GLB_MIME);
    assert_eq!(&r.bytes[..4], b"glTF");
    let fp = keep("trellis.glb", &r);
    assert_eq!(fp.geometry.len(), GEOMETRY_GRID.pow(3));
    let occupied = fp.geometry.iter().filter(|&&v| v > 0).count();
    assert!(occupied > 8, "a surface, not a speck: {occupied} cells");
    assert!(rt.unload("trellis2-4b"));
}
