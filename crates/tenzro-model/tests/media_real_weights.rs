//! Janus-Pro renders through the node's media runtime on its real weights:
//! an image from image tokens, with the fingerprint its receipt commits to.
//!
//! The weights are not committed, so the test is ignored by default;
//! scripts/media-weight-tests.sh fetches them and runs it. Run by hand with
//! `--ignored` and:
//!
//! - `TENZRO_MEDIA_JANUS_CHECKPOINT`: the `deepseek-community/Janus-Pro-1B`
//!   files the catalog pins (`config.json`, `generation_config.json`,
//!   `model.safetensors`);
//! - `TENZRO_MEDIA_JANUS_GGUF_DIR`: the directory holding the backbone GGUF
//!   the catalog entry names;
//! - optionally `TENZRO_MEDIA_OUT`, a directory the outputs are written to.

use std::collections::HashMap;
use std::path::PathBuf;

use tenzro_model::media_fingerprint::{self, MediaFingerprint};
use tenzro_model::{
    Catalog, CatalogCell, MediaPrecision, MediaRuntime, Output, RenderJob, Rendered,
};
use tenzro_types::{MediaGenKind, MediaGenParams};

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
) -> Rendered {
    let job = RenderJob {
        job_id: format!("{model_id}-real"),
        kind,
        params,
        seed: 7,
        requester: [0; 32],
        inputs: Vec::new(),
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
#[ignore = "needs the Janus-Pro weights; scripts/media-weight-tests.sh fetches them and runs it"]
async fn janus_renders_an_image_from_image_tokens() {
    let rt = MediaRuntime::with_host(Default::default(), CatalogCell::new(Catalog::test_seed()));
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
    )
    .await;
    let fp2 = keep("janus-again.png", &again);
    assert!(media_fingerprint::agree(&fp, &fp2, fp.tolerance_bps()));
    assert!(rt.unload("janus-pro-1b"));
}

/// FLUX 3 Image Klein on the release's own files: text-to-image, the same seed
/// again, and an edit from the first picture, through the node's media runtime.
///
/// `TENZRO_MEDIA_FLUX3_KLEIN_CHECKPOINT` names the directory the catalog entry
/// `flux-3-image-klein` pins (`model.safetensors`, `ae.safetensors`,
/// `config.json`, `modular_model_index.json`, `text_encoder/`); optionally
/// `TENZRO_MEDIA_OUT`. The weights are gated, so the files are fetched by hand.
#[tokio::test]
#[ignore = "needs the gated FLUX 3 Image Klein release files"]
async fn flux3_image_klein_renders_and_edits() {
    use tenzro_types::MediaGenInputRole;

    let rt = MediaRuntime::with_host(Default::default(), CatalogCell::new(Catalog::test_seed()));
    let dirs = [env_path("TENZRO_MEDIA_FLUX3_KLEIN_CHECKPOINT")];
    let info = rt
        .load(
            "flux-3-image-klein",
            "Flux3DistilledModularPipeline",
            &dirs,
            1,
            MediaPrecision::Bf16,
        )
        .expect("load");
    eprintln!(
        "flux-3-image-klein on {} ({} resident bytes)",
        info.device, info.resident_bytes
    );
    let prompt = "A red bicycle leaning against a white wall in soft morning light, sharp photograph, shallow depth of field";
    let r = render(
        &rt,
        "flux-3-image-klein",
        MediaGenKind::Text2Image,
        params(prompt, 1024, 1024, 16, 1.0),
    )
    .await;
    let img = image::load_from_memory(&r.bytes).expect("a PNG").to_rgb8();
    assert_eq!(img.dimensions(), (1024, 1024));
    let fp = keep("flux3-klein.png", &r);
    let spread = fp.luma.iter().max().unwrap() - fp.luma.iter().min().unwrap();
    assert!(
        spread > 20,
        "a picture, not a flat field: luma spread {spread}"
    );

    let again = render(
        &rt,
        "flux-3-image-klein",
        MediaGenKind::Text2Image,
        params(prompt, 1024, 1024, 16, 1.0),
    )
    .await;
    let fp2 = keep("flux3-klein-again.png", &again);
    assert!(media_fingerprint::agree(&fp, &fp2, fp.tolerance_bps()));

    // An edit from that picture: one reference, kept whole, at its own size.
    let job = RenderJob {
        job_id: "flux-3-image-klein-edit".into(),
        kind: MediaGenKind::Image2Image,
        params: params("Make the bicycle blue", 1024, 1024, 16, 1.0),
        seed: 7,
        requester: [0; 32],
        inputs: vec![(MediaGenInputRole::EditSource, r.bytes.clone())],
        role: None,
        inbound_latent: None,
    };
    let edited = match rt.render("flux-3-image-klein", job).await.expect("edit") {
        Output::Media(e) => e,
        Output::Latent(_) => panic!("handed over a latent"),
    };
    let out = image::load_from_memory(&edited.bytes)
        .expect("a PNG")
        .to_rgb8();
    assert_eq!(out.dimensions(), (1024, 1024));
    keep("flux3-klein-edit.png", &edited);
    assert!(rt.unload("flux-3-image-klein"));
}
