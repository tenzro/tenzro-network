//! The seed catalog: the entries in `seed/`, the catalog's first published
//! content. Every test here reads the catalog through the same accessors a
//! node uses, after installing the seed in this process.

use std::sync::Once;

use tenzro_catalog::*;

fn seeded() {
    static SEED: Once = Once::new();
    SEED.call_once(|| {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seed");
        let entries = read_entries(&dir).expect("the seed parses");
        let (catalog, errors) = Catalog::build(entries);
        assert!(errors.is_empty(), "seed entries refused: {errors:?}");
        store::install(catalog);
    });
}

/// Each accessor the tests call installs the seed first.
macro_rules! seeded {
    ($($name:ident($($arg:ident: $ty:ty),*) -> $ret:ty;)*) => {
        $(
            fn $name($($arg: $ty),*) -> $ret {
                seeded();
                tenzro_catalog::$name($($arg),*)
            }
        )*
    };
}

seeded! {
    get_model_catalog() -> Vec<HfModelEntry>;
    get_model_by_id(id: &str) -> Option<HfModelEntry>;
    get_model_families() -> Vec<String>;
    get_vision_catalog() -> Vec<OnnxVisionEntry>;
    get_vision_model_by_id(id: &str) -> Option<OnnxVisionEntry>;
    get_forecast_catalog() -> Vec<OnnxForecastEntry>;
    get_forecast_model_by_id(id: &str) -> Option<OnnxForecastEntry>;
    get_text_embedding_catalog() -> Vec<OnnxTextEmbeddingEntry>;
    get_text_embedding_model_by_id(id: &str) -> Option<OnnxTextEmbeddingEntry>;
    get_embed_catalog() -> Vec<EmbedModelEntry>;
    get_embed_model_by_id(id: &str) -> Option<EmbedModelEntry>;
    get_segmentation_catalog() -> Vec<OnnxSegmentationEntry>;
    get_segmentation_model_by_id(id: &str) -> Option<OnnxSegmentationEntry>;
    get_detection_catalog() -> Vec<OnnxDetectionEntry>;
    get_detection_model_by_id(id: &str) -> Option<OnnxDetectionEntry>;
    get_audio_catalog() -> Vec<OnnxAudioEntry>;
    get_decision_catalog() -> Vec<HfModelEntry>;
    get_decision_model_by_id(id: &str) -> Option<HfModelEntry>;
    get_rerank_catalog() -> Vec<HfModelEntry>;
    get_rerank_model_by_id(id: &str) -> Option<HfModelEntry>;
    get_tts_catalog() -> Vec<TtsModelEntry>;
    get_tts_model_by_id(id: &str) -> Option<TtsModelEntry>;
    get_video_catalog() -> Vec<OnnxVideoEntry>;
    get_video_model_by_id(id: &str) -> Option<OnnxVideoEntry>;
    get_media_gen_catalog() -> Vec<MediaGenModelEntry>;
    get_media_gen_model_by_id(id: &str) -> Option<MediaGenModelEntry>;
    get_media_gen_models_for_kind(kind: tenzro_types::MediaGenKind) -> Vec<MediaGenModelEntry>;
    runnable_media_gen_model(model_id: &str) -> Result<MediaGenModelEntry, String>;
    resolve_reasoning_effort(id: &str, effort: Option<&str>) -> Option<(String, String)>;
    resolve_enable_thinking(id: &str, budget: Option<u32>) -> bool;
    entry(id: &str) -> Option<CatalogEntry>;
    moe_source(id: &str) -> Option<SourceCheckpoint>;
    permits_paid_use(id: &str) -> bool;
    license_tier_of(id: &str) -> Option<LicenseTier>;
}

#[test]
fn paid_use_follows_the_licence_across_every_model_type() {
    assert!(permits_paid_use("flux2-klein-4b"));
    assert!(
        !permits_paid_use("flux2-klein-9b"),
        "FLUX.2 non-commercial licence"
    );
    assert!(!permits_paid_use("hunyuan3d-2.1"));
    assert!(!permits_paid_use("qwen-image-2.1"), "Qwen Research License");
    let pinned = entry("qwen-image-2.1").expect("catalogued");
    assert!(
        !pinned.components.is_empty(),
        "qwen-image-2.1 pins no files"
    );
    assert_eq!(pinned.licence.id.as_deref(), Some("qwen-research"));
    assert!(
        pinned
            .licence
            .conditions
            .as_deref()
            .is_some_and(|c| c.contains("Built with Qwen")),
        "the notice obligations travel with the entry"
    );
    assert!(permits_paid_use("not-in-any-catalog"));
    assert_eq!(
        license_tier_of("flux2-dev"),
        Some(LicenseTier::NonCommercial)
    );
}

/// A licence that restricts paid serving keeps its models off the paid path,
/// whatever engine family they are in: the tier says so, and the predicate
/// pricing and admission read agrees for every entry.
#[test]
fn a_licence_that_restricts_paid_serving_is_never_listed_for_paid_serving() {
    seeded();
    let catalog = store::current();
    // Licences verified from their licence files to forbid serving for pay
    // without a separate grant (non-commercial, research-only, or a separate
    // licence for any Model-as-a-Service use with no revenue floor).
    let restricts_paid = |name: &str, id: Option<&str>| {
        let name = name.to_ascii_lowercase();
        name.contains("non-commercial")
            || name.contains("noncommercial")
            || name.contains("research")
            || matches!(id, Some("qwen-community-1.0" | "bfl-flux2"))
    };
    let mut restricted = 0;
    for e in catalog.entries() {
        let id = e.id();
        let tier = e.licence.effective_tier();
        // Weights under several licences are bound by every one: the
        // effective tier is at least each licence's, and a part that
        // restricts paid serving restricts the whole model.
        for part in e.licence.parts() {
            assert!(
                tier >= part.tier,
                "{id}: {} is more restrictive than the effective tier",
                part.name
            );
            if restricts_paid(part.name, part.id) {
                restricted += 1;
                assert_eq!(
                    tier,
                    LicenseTier::NonCommercial,
                    "{id}: {} restricts paid serving",
                    part.name
                );
            }
        }
        assert_eq!(
            permits_paid_use(id),
            tier.permits_paid_use(),
            "{id}: paid use disagrees with its licence tier"
        );
        if tier == LicenseTier::NonCommercial {
            assert!(
                !permits_paid_use(id),
                "{id} is non-commercial but listed for paid serving"
            );
        }
    }
    assert!(restricted > 0);
    for id in [
        "qwen3.8-flash-next",
        "qwen3.8-flash-next-mtp-draft",
        "minimax-m2.7",
    ] {
        assert!(!permits_paid_use(id), "{id}");
    }
}

/// A licence whose commercial use is conditional records its conditions, and
/// a territorial licence is enforced through its territorial grant.
#[test]
fn conditional_licences_record_their_conditions() {
    for id in [
        "qwen3.8-2.4t-a95b",
        "kimi-k3",
        "minimax-m3",
        "minimax-h3",
        "kimi-k2-instruct",
        "kimi-k2.5",
        "kimi-k2.6",
        "kimi-k2.7-code",
    ] {
        let e = entry(id).expect("catalogued");
        assert_eq!(e.licence.tier, LicenseTier::CommercialCustom, "{id}");
        assert!(e.licence.id.is_some(), "{id}: no licence id to accept");
        assert!(
            e.licence.conditions.is_some(),
            "{id}: conditions not recorded"
        );
    }
    // The Kimi K2 releases are under a modified MIT licence: each names the
    // model to display above the usage threshold.
    for (id, shown) in [
        ("kimi-k2-instruct", "\"Kimi K2\""),
        ("kimi-k2.5", "\"Kimi K2.5\""),
        ("kimi-k2.6", "\"Kimi K2.6\""),
        ("kimi-k2.7-code", "\"Kimi K2.7 Code\""),
    ] {
        let e = entry(id).expect("catalogued");
        assert_eq!(
            (e.licence.name.as_str(), e.licence.id.as_deref()),
            ("Modified MIT License", Some("kimi-k2-modified-mit")),
            "{id}"
        );
        assert!(
            e.licence.conditions.as_deref().unwrap().starts_with(shown),
            "{id}"
        );
    }
    let h3 = entry("minimax-h3").expect("catalogued");
    let grant = license_territory(h3.licence.id.as_deref().unwrap()).expect("territorial grant");
    for t in ["EU", "GB", "KR", "US"] {
        assert!(grant.excluded.iter().any(|x| x == t), "{t}");
    }
    // Hunyuan3D 2.1: §1.l excludes the EU, the UK and South Korea, not the
    // US, and §5.c reaches outputs, so every request is checked.
    let hy3d = entry("hunyuan3d-2.1").expect("catalogued");
    let grant = license_territory(hy3d.licence.id.as_deref().unwrap()).expect("territorial grant");
    for t in ["EU", "GB", "KR"] {
        assert!(grant.excluded.iter().any(|x| x == t), "{t}");
    }
    assert!(
        !grant.excluded.iter().any(|x| x == "US"),
        "US is in the Territory"
    );
    assert_eq!(
        grant.scope,
        tenzro_types::model::TerritorialScope::WeightsAndOutputs
    );
    assert!(grant.is_per_request());
    let m27 = entry("minimax-m2.7").expect("catalogued");
    assert!(
        m27.licence
            .id
            .as_deref()
            .is_none_or(|l| license_territory(l).is_none()),
        "M2.7 is not under the H3 territory"
    );
    for id in ["gemma4-31b", "gemma4-e2b", "gemma4-26b-a4b-mtp-draft"] {
        assert_eq!(
            license_tier_of(id),
            Some(LicenseTier::Permissive),
            "{id}: Gemma 4 is Apache-2.0"
        );
    }
}

/// MiniMax-H3 pins its diffusers checkpoint (transformer, both autoencoders,
/// the Qwen3-VL encoder, tokenizer and both schedulers) at one commit; the
/// quantised and image-conditioned variants pin only their own files and take
/// the rest from it: the reference entry pins the official reference
/// transformer, the 8-bit entry quantises the base weights at load. All six
/// stay planned until their real checks pass.
#[test]
fn minimax_h3_pins_its_checkpoint_and_stays_planned() {
    let base = entry("minimax-h3").expect("catalogued");
    let files = base.checkpoint("MiniMaxAI/MiniMax-H3");
    assert_eq!(files.len(), base.components.len());
    for path in [
        "model_index.json",
        "transformer/config.json",
        "vae/config.json",
        "audio_vae/config.json",
        "audio_vae/diffusion_pytorch_model.safetensors",
        "text_encoder/config.json",
        "tokenizer/tokenizer.json",
        "scheduler/scheduler_config.json",
        "audio_scheduler/scheduler_config.json",
    ] {
        assert!(files.iter().any(|c| c.path == path), "{path} not pinned");
    }
    let shards = |dir: &str| {
        files
            .iter()
            .filter(|c| c.path.starts_with(dir) && c.path.ends_with(".safetensors"))
            .count()
    };
    assert_eq!(
        (
            shards("transformer/"),
            shards("vae/"),
            shards("text_encoder/")
        ),
        (14, 3, 14)
    );
    assert!(
        files
            .iter()
            .all(|c| !c.path.starts_with("transformer_ref/") && !c.path.starts_with("FL2VA/"))
    );
    let reference = entry("minimax-h3-ref2va").expect("catalogued");
    assert!(
        reference
            .components
            .iter()
            .all(|c| c.path.starts_with("transformer_ref/"))
    );
    assert_eq!(
        reference
            .components
            .iter()
            .filter(|c| c.path.ends_with(".safetensors"))
            .count(),
        14
    );
    let int8 = get_media_gen_model_by_id("minimax-h3-int8").expect("media entry");
    assert!(
        int8.load_int8
            && entry("minimax-h3-int8")
                .expect("catalogued")
                .components
                .is_empty()
    );
    assert!(
        !get_media_gen_model_by_id("minimax-h3")
            .expect("media entry")
            .load_int8
    );
    for id in [
        "minimax-h3",
        "minimax-h3-int8",
        "minimax-h3-ref2va",
        "minimax-h3-ref2va-fp8",
        "minimax-h3-fl2va-gguf",
        "minimax-h3-ref2va-gguf",
    ] {
        let e = entry(id).expect("catalogued");
        let m = get_media_gen_model_by_id(id).expect("media entry");
        assert_eq!(m.pipeline_class, "MiniMaxH3ModularPipeline", "{id}");
        assert!(runnable_media_gen_model(id).is_err(), "{id} is planned");
        assert_eq!(
            e.licence.id.as_deref(),
            Some("minimax-h3-community"),
            "{id}"
        );
        for c in &e.components {
            assert!(
                c.sha256.len() == 64 && c.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "{id}: {}",
                c.path
            );
            assert!(
                c.revision().is_some_and(|r| r.len() == 40),
                "{id}: {} not pinned to a commit",
                c.path
            );
            // Pickled checkpoints execute code on load; only safetensors and GGUF.
            assert!(
                !c.path.ends_with(".pt") && !c.path.ends_with(".pth") && !c.path.ends_with(".bin"),
                "{id}: {}",
                c.path
            );
        }
        let own: u64 = e.components.iter().map(|c| c.size).sum();
        let deps: Vec<_> = e
            .requires
            .iter()
            .map(|d| entry(&d.entry).expect("required entry"))
            .collect();
        let required: u64 = if id == "minimax-h3" {
            0
        } else {
            assert_eq!(e.requires[0].entry, "minimax-h3", "{id}");
            assert!(
                e.requires
                    .iter()
                    .all(|d| d.entry == "minimax-h3" || d.entry == "minimax-h3-ref2va"),
                "{id}"
            );
            assert!(
                e.components
                    .iter()
                    .all(|c| base.components.iter().all(|b| b.path != c.view_path())),
                "{id}: no copied base files"
            );
            deps.iter()
                .flat_map(|d| e.required_components(d))
                .map(|c| c.size)
                .sum()
        };
        assert_eq!(own + required, m.size_bytes, "{id}");
        // The pipeline reads one directory: the view the node assembles holds
        // the denoiser's config beside its weights, every autoencoder and the
        // prompt encoder's config beside theirs, the tokenizer and both
        // schedulers.
        let view = e.checkpoint_view(&deps).unwrap_or_else(|m| panic!("{m}"));
        let dir = if e
            .components
            .iter()
            .any(|c| c.view_path().starts_with("transformer_ref/"))
        {
            "transformer_ref"
        } else {
            "transformer"
        };
        let has = |p: &str| view.iter().any(|f| f.at == p);
        let weights_in = |d: &str| {
            view.iter().any(|f| {
                f.at.starts_with(&format!("{d}/"))
                    && (f.at.ends_with(".safetensors") || f.at.ends_with(".gguf"))
            })
        };
        for d in [dir, "text_encoder", "vae", "audio_vae"] {
            assert!(
                has(&format!("{d}/config.json")) && weights_in(d),
                "{id}: {d}/ incomplete"
            );
        }
        for p in [
            "tokenizer/tokenizer.json",
            "scheduler/scheduler_config.json",
            "audio_scheduler/scheduler_config.json",
        ] {
            assert!(has(p), "{id}: {p} missing");
        }
        // One weight format per directory, so the loader never mixes two
        // copies of one part.
        for d in [dir, "text_encoder", "vae", "audio_vae"] {
            let formats: std::collections::BTreeSet<_> = view
                .iter()
                .filter(|f| {
                    f.at.starts_with(&format!("{d}/"))
                        && (f.at.ends_with(".safetensors") || f.at.ends_with(".gguf"))
                })
                .map(|f| f.entry)
                .collect();
            assert_eq!(
                formats.len(),
                1,
                "{id}: {d}/ holds weights from {formats:?}"
            );
        }
    }
}

/// Every native media entry names the engine revision it runs on, and that is
/// the revision the workspace builds.
#[test]
fn native_media_entries_pin_the_engine_revision_the_workspace_builds() {
    let manifest = include_str!("../../../Cargo.toml");
    let line = manifest
        .lines()
        .find(|l| l.starts_with("praecise-diffusion"))
        .expect("praecise-diffusion is a workspace dependency");
    let rev = line
        .split("rev = \"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("pinned by rev");
    let native: Vec<_> = get_media_gen_catalog()
        .into_iter()
        .filter(|e| e.status == MediaGenStatus::Native)
        .collect();
    for id in [
        "flux2-klein-4b",
        "z-image-turbo",
        "acestep-v15-xl-turbo",
        "acestep-v15-xl-sft",
        "acestep-v15-xl-base",
        "cosmos3-edge",
        "cosmos3-edge-policy-droid",
        "ltx-2.3-22b-dev",
        "ltx-2.3-22b-distilled-gguf",
        "flux-3-action-so101",
        "flux-3-action-droid",
        "qwen-image-edit",
        "qwen-image-2.1",
        "wan2.2-ti2v-5b",
        "janus-pro-1b",
        "trellis2-4b",
    ] {
        assert!(native.iter().any(|e| e.id == id), "{id} is not native");
    }
    for e in native {
        assert_eq!(
            e.engine_rev.as_deref(),
            Some(rev),
            "{}: engine revision drifted from the workspace pin",
            e.id
        );
    }
}

/// Qwen-Image-Edit runs natively from one pinned checkpoint directory: the
/// files the engine reads (transformer, autoencoder, Qwen2.5-VL encoder,
/// tokenizer, scheduler), hashed, and nothing else. It edits images only and
/// is Apache-2.0, so it may be served for pay.
#[test]
fn qwen_image_edit_runs_from_one_pinned_checkpoint() {
    let m = get_media_gen_model_by_id("qwen-image-edit").expect("catalogued");
    assert_eq!(m.status, MediaGenStatus::Native);
    assert_eq!(m.pipeline_class, "QwenImageEditPlusPipeline");
    assert_eq!(m.kinds, vec![tenzro_types::MediaGenKind::Image2Image]);
    assert!(permits_paid_use("qwen-image-edit"));
    let e = entry("qwen-image-edit").expect("catalogued");
    assert_eq!(
        e.sources("Qwen/Qwen-Image-Edit-2511"),
        vec!["Qwen/Qwen-Image-Edit-2511"]
    );
    let files = e.checkpoint("Qwen/Qwen-Image-Edit-2511");
    assert_eq!(files.len(), e.components.len());
    for path in [
        "model_index.json",
        "processor/tokenizer.json",
        "scheduler/scheduler_config.json",
        "text_encoder/config.json",
        "transformer/config.json",
        "vae/config.json",
        "vae/diffusion_pytorch_model.safetensors",
    ] {
        assert!(files.iter().any(|c| c.path == path), "{path} not pinned");
    }
    let shards = |dir: &str| {
        files
            .iter()
            .filter(|c| c.path.starts_with(dir) && c.path.ends_with(".safetensors"))
            .count()
    };
    assert_eq!((shards("transformer/"), shards("text_encoder/")), (5, 4));
    for c in &files {
        assert!(
            c.sha256.len() == 64 && c.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}",
            c.path
        );
    }
    assert_eq!(files.iter().map(|c| c.size).sum::<u64>(), m.size_bytes);
}

/// The FLUX 3 action policies are under the FLUX Kommunity License: gated at
/// their origin, served once the operator accepts `flux-kommunity-1.0`. The
/// Cosmos policy is permissive. The Cosmos policy and the FLUX 3 embodiment
/// policies run on the native engine; the FLUX 3 base has no embodiment head
/// and stays planned.
#[test]
fn action_policies_carry_their_licence_and_embodiment() {
    let policies = get_media_gen_models_for_kind(tenzro_types::MediaGenKind::ActionPolicy);
    let ids: Vec<_> = policies.iter().map(|m| m.id.as_str()).collect();
    for id in [
        "flux-3-action-base",
        "flux-3-action-so101",
        "flux-3-action-droid",
    ] {
        assert!(ids.contains(&id), "{id} missing");
        let e = entry(id).expect("catalogued");
        assert!(e.gated, "{id}: gated at its origin");
        assert_eq!(e.gating_licence(), Some("flux-kommunity-1.0"), "{id}");
        assert_eq!(
            license_tier_of(id),
            Some(LicenseTier::CommercialCustom),
            "{id}"
        );
    }
    assert!(permits_paid_use("cosmos3-edge-policy-droid"));
    for m in &policies {
        assert_eq!(
            m.kinds,
            vec![tenzro_types::MediaGenKind::ActionPolicy],
            "{}",
            m.id
        );
        let native = m.id != "flux-3-action-base";
        let status = if native {
            tenzro_catalog::MediaGenStatus::Native
        } else {
            tenzro_catalog::MediaGenStatus::Planned
        };
        assert_eq!(m.status, status, "{}", m.id);
        assert_eq!(runnable_media_gen_model(&m.id).is_ok(), native, "{}", m.id);
    }
    let cosmos = get_media_gen_model_by_id("cosmos3-edge-policy-droid")
        .and_then(|m| m.action)
        .expect("embodiment");
    assert_eq!(
        (
            cosmos.embodiment.as_str(),
            cosmos.action_dim,
            cosmos.chunk_len
        ),
        ("droid_lerobot", 10, 32)
    );
    let droid = get_media_gen_model_by_id("flux-3-action-droid")
        .and_then(|m| m.action)
        .expect("embodiment");
    assert_eq!(
        (droid.embodiment.as_str(), droid.action_dim, droid.chunk_len),
        ("droid", 8, 32)
    );
}

/// FLUX 3 Image Klein is listed with every file pinned at one commit and
/// stays planned until a native port runs it. The FP8 and NVFP4 entries pin
/// their own transformer and load the bfloat16 entry's text encoder and
/// autoencoder. All are gated by the FLUX Kommunity License, whose
/// commercial terms travel with the entry. The prompt upsampler the model
/// card recommends is its own language model, never chained by the node.
#[test]
fn flux3_image_klein_is_pinned_gated_and_planned() {
    let klein = entry("flux-3-image-klein").expect("catalogued");
    for id in [
        "flux-3-image-klein",
        "flux-3-image-klein-fp8",
        "flux-3-image-klein-nvfp4",
        "flux-3-image-klein-base",
    ] {
        let e = entry(id).expect("catalogued");
        let m = get_media_gen_model_by_id(id).expect("media entry");
        assert_eq!(m.status, MediaGenStatus::Planned, "{id}");
        assert!(m.engine_rev.is_none(), "{id}");
        assert!(runnable_media_gen_model(id).is_err(), "{id}");
        assert_eq!(
            m.kinds,
            [
                tenzro_types::MediaGenKind::Text2Image,
                tenzro_types::MediaGenKind::Image2Image
            ],
            "{id}"
        );
        assert!(e.gated, "{id}");
        assert_eq!(e.gating_licence(), Some("flux-kommunity-1.0"), "{id}");
        assert_eq!(e.licence.tier, LicenseTier::CommercialCustom, "{id}");
        let conditions = e.licence.all_conditions().expect("conditions recorded");
        assert!(
            conditions.contains("US$5,000,000") && conditions.contains("LICENSE.md"),
            "{id}: {conditions}"
        );
        assert!(!e.components.is_empty(), "{id} pins no files");
        let revisions: std::collections::HashSet<_> =
            e.components.iter().map(|c| c.revision()).collect();
        assert_eq!(revisions.len(), 1, "{id}: one commit");
        assert!(m.min_vram_gb >= 25, "{id}: vendor peak memory");
        assert!(e.requires.iter().all(|d| d.entry == "flux-3-image-klein"));
        let view = e
            .checkpoint_view(std::slice::from_ref(&klein))
            .expect("checkpoint view");
        for part in [
            "modular_model_index.json",
            "text_encoder/config.json",
            "vae/config.json",
        ] {
            assert!(
                view.iter().any(|f| f.at == part),
                "{id}: {part} not in view"
            );
        }
    }
    for (id, file) in [
        ("flux-3-image-klein-fp8", "variants/fp8r/model.safetensors"),
        (
            "flux-3-image-klein-nvfp4",
            "variants/nvfp4/model.safetensors",
        ),
    ] {
        let e = entry(id).expect("catalogued");
        assert!(
            e.component("black-forest-labs/flux-3-image-klein", file)
                .is_some(),
            "{id}"
        );
        assert!(
            e.components.iter().all(|c| c.path.starts_with("variants/")),
            "{id}: shares the bfloat16 entry's text encoder and autoencoder"
        );
    }
    let pup = get_model_by_id("flux-3-image-klein-pup").expect("upsampler listed");
    assert!(pup.mmproj.is_some(), "reads reference images");
    assert_eq!(
        license_tier_of("flux-3-image-klein-pup"),
        Some(LicenseTier::Permissive)
    );
    assert!(
        klein.requires.is_empty(),
        "the node never chains the upsampler"
    );
}

/// The world models are permissive and planned until their real checks pass.
/// Matrix-Game loads the Wan 2.2 TI2V 5B text encoder, tokenizer, autoencoder
/// and scheduler as a dependency on that entry, never as copies of its files.
#[test]
fn world_models_are_permissive_and_matrix_game_requires_wan() {
    let worlds = get_media_gen_models_for_kind(tenzro_types::MediaGenKind::WorldModel);
    let ids: Vec<_> = worlds.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids.len(), 2, "{ids:?}");
    for id in ["wan2.2-ti2v-5b", "matrix-game-3"] {
        assert!(ids.contains(&id), "{id} missing");
        assert_eq!(license_tier_of(id), Some(LicenseTier::Permissive), "{id}");
        assert!(permits_paid_use(id), "{id}");
    }
    assert!(
        runnable_media_gen_model("wan2.2-ti2v-5b").is_ok(),
        "wan2.2-ti2v-5b is native"
    );
    assert!(
        runnable_media_gen_model("matrix-game-3").is_err(),
        "matrix-game-3 is planned"
    );
    let mg = entry("matrix-game-3").expect("catalogued");
    assert_eq!(mg.requires.len(), 1);
    assert_eq!(mg.requires[0].entry, "wan2.2-ti2v-5b");
    let wan = entry("wan2.2-ti2v-5b").expect("catalogued");
    let parts: Vec<&str> = mg
        .required_components(&wan)
        .iter()
        .map(|c| c.path.as_str())
        .collect();
    for need in [
        "text_encoder/config.json",
        "tokenizer/tokenizer.json",
        "vae/config.json",
        "scheduler/scheduler_config.json",
    ] {
        assert!(parts.contains(&need), "{need} not required");
    }
    assert!(
        parts.iter().all(|p| !p.starts_with("transformer/")),
        "{parts:?}"
    );
    assert!(
        mg.components
            .iter()
            .all(|c| c.repo == "Skywork/Matrix-Game-3.0"),
        "no copied Wan files"
    );
    let files: Vec<&str> = mg
        .checkpoint("Skywork/Matrix-Game-3.0")
        .iter()
        .map(|c| c.path.as_str())
        .collect();
    for need in [
        "model_index.json",
        "base_distilled_model/config.json",
        "base_distilled_model/diffusion_pytorch_model.safetensors",
    ] {
        assert!(files.contains(&need), "{need} not pinned");
    }
}

/// A media entry the node runs in process is fetched as the directory of its
/// components, so they must cover every part it loads, at one commit.
#[test]
fn every_in_process_media_entry_pins_its_checkpoint() {
    let native: Vec<_> = get_media_gen_catalog()
        .into_iter()
        .filter(|e| e.status == MediaGenStatus::Native)
        .collect();
    assert!(!native.is_empty());
    for e in native {
        let full = entry(&e.id).expect("catalogued");
        // Every source repository is fetched at one commit.
        for repo in full.sources(&e.hf_repo) {
            let revisions: std::collections::HashSet<_> =
                full.checkpoint(repo).iter().map(|c| c.revision()).collect();
            assert_eq!(
                revisions.len(),
                1,
                "{}: {repo} pinned at {} commits",
                e.id,
                revisions.len()
            );
        }
        if e.pipeline_class == "MatrixGame3I2VPipeline" {
            // The world transformer is its own source; the rest of the stack
            // is a dependency on the Wan 2.2 entry.
            assert_eq!(full.sources(&e.hf_repo).len(), 1, "{}: one source", e.id);
            let files: Vec<&str> = full
                .checkpoint(&e.hf_repo)
                .iter()
                .map(|c| c.path.as_str())
                .collect();
            for need in ["model_index.json", "base_distilled_model/config.json"] {
                assert!(files.contains(&need), "{}: {need} not pinned", e.id);
            }
            assert_eq!(
                full.requires.len(),
                1,
                "{}: requires the Wan 2.2 stack",
                e.id
            );
            continue;
        }
        if e.pipeline_class == "LTX2Pipeline" {
            // Exactly one source holds the text encoder and its tokenizer;
            // every other source holds checkpoint files (the single file or
            // its split sections, and an optional latent upsampler) at its
            // root or in subdirectories other than text_encoder/.
            let sources = full.sources(&e.hf_repo);
            let is_text = |repo: &str| {
                full.checkpoint(repo)
                    .iter()
                    .any(|c| c.path.starts_with("text_encoder/"))
            };
            let text_sources: Vec<_> = sources.iter().filter(|r| is_text(r)).collect();
            assert_eq!(text_sources.len(), 1, "{}: sources {sources:?}", e.id);
            let text: Vec<&str> = full
                .checkpoint(text_sources[0])
                .iter()
                .map(|c| c.path.as_str())
                .collect();
            for need in ["text_encoder/config.json", "tokenizer/tokenizer.json"] {
                assert!(text.contains(&need), "{}: {need} not pinned", e.id);
            }
            assert!(
                text.iter()
                    .any(|f| f.starts_with("text_encoder/") && f.ends_with(".safetensors")),
                "{}: no text encoder weights",
                e.id
            );
            for repo in sources.iter().filter(|r| !is_text(r)) {
                let files: Vec<&str> = full
                    .checkpoint(repo)
                    .iter()
                    .map(|c| c.path.as_str())
                    .collect();
                assert!(
                    !files.is_empty()
                        && files
                            .iter()
                            .all(|f| f.ends_with(".safetensors") || f.ends_with(".gguf")),
                    "{}: {files:?}",
                    e.id
                );
            }
            continue;
        }
        if e.pipeline_class == "JanusProPipeline" {
            // The checkpoint (image head, decoder, token ids), then the
            // language backbone's GGUF the entry names.
            let sources = full.sources(&e.hf_repo);
            assert_eq!(sources.len(), 2, "{}: sources {sources:?}", e.id);
            let paths = |repo: &str| -> Vec<String> {
                full.checkpoint(repo)
                    .iter()
                    .map(|c| c.path.clone())
                    .collect()
            };
            assert_eq!(
                paths(sources[0]),
                ["config.json", "generation_config.json", "model.safetensors"],
                "{}",
                e.id
            );
            assert_eq!(e.gguf_repo.as_deref(), Some(sources[1]), "{}", e.id);
            assert_eq!(
                paths(sources[1]),
                [e.gguf_file.clone().expect("a backbone GGUF")],
                "{}",
                e.id
            );
            continue;
        }
        if e.pipeline_class == "Trellis2ImageTo3DPipeline" {
            // One checkpoint directory: the pipeline's own models, the
            // structure decoder it names in another repository and the image
            // encoder, each at the path pipeline.json names it by.
            let view = full.checkpoint_view(&[]).expect("no dependencies");
            let at: Vec<&str> = view.iter().map(|f| f.at).collect();
            for need in [
                "pipeline.json",
                "ckpts/ss_flow_img_dit_1_3B_64_bf16.safetensors",
                "ckpts/slat_flow_img2shape_dit_1_3B_512_bf16.safetensors",
                "ckpts/slat_flow_imgshape2tex_dit_1_3B_512_bf16.safetensors",
                "ckpts/shape_dec_next_dc_f16c32_fp16.safetensors",
                "ckpts/tex_dec_next_dc_f16c32_fp16.safetensors",
                "microsoft/TRELLIS-image-large/ckpts/ss_dec_conv3d_16l8_fp16.json",
                "microsoft/TRELLIS-image-large/ckpts/ss_dec_conv3d_16l8_fp16.safetensors",
                "facebook/dinov3-vitl16-pretrain-lvd1689m/config.json",
                "facebook/dinov3-vitl16-pretrain-lvd1689m/model.safetensors",
            ] {
                assert!(at.contains(&need), "{}: {need} not in the view", e.id);
            }
            // Only the 512 path is served, so the larger paths are not fetched.
            assert!(!at.iter().any(|p| p.contains("_1024_")), "{}", e.id);
            continue;
        }
        if e.pipeline_class == "Flux3ActionPipeline" {
            // A released policy (its settings and transformer), then the
            // autoencoder and text encoder of the base it names.
            let sources = full.sources(&e.hf_repo);
            assert_eq!(sources.len(), 2, "{}: sources {sources:?}", e.id);
            let policy: Vec<&str> = full
                .checkpoint(sources[0])
                .iter()
                .map(|c| c.path.as_str())
                .collect();
            for need in ["config.json", "model.safetensors"] {
                assert!(policy.contains(&need), "{}: {need} not pinned", e.id);
            }
            let base: Vec<&str> = full
                .checkpoint(sources[1])
                .iter()
                .map(|c| c.path.as_str())
                .collect();
            for need in [
                "video_vae.safetensors",
                "text_encoder/config.json",
                "text_encoder/tokenizer.json",
                "text_encoder/tokenizer_config.json",
            ] {
                assert!(base.contains(&need), "{}: base {need} not pinned", e.id);
            }
            assert!(
                base.iter()
                    .any(|f| f.starts_with("text_encoder/") && f.ends_with(".safetensors")),
                "{}: no text encoder weights",
                e.id
            );
            continue;
        }
        assert_eq!(full.sources(&e.hf_repo).len(), 1, "{}: one source", e.id);
        let files: Vec<&str> = full
            .checkpoint(&e.hf_repo)
            .iter()
            .map(|c| c.path.as_str())
            .collect();
        // The parts each native pipeline loads, as its loader reads them.
        let (configs, weights): (&[&str], &[&str]) = match e.pipeline_class.as_str() {
            "Flux2KleinPipeline" | "ZImagePipeline" => (
                &["tokenizer/tokenizer.json", "text_encoder/config.json"],
                &["transformer", "text_encoder", "vae"],
            ),
            "AceStepPipeline" => (
                &[
                    "tokenizer/tokenizer.json",
                    "text_encoder/config.json",
                    "condition_encoder/config.json",
                ],
                &["transformer", "condition_encoder", "text_encoder", "vae"],
            ),
            "Cosmos3OmniPipeline" => (&["text_tokenizer/tokenizer.json"], &["transformer", "vae"]),
            "QwenImageEditPlusPipeline" | "QwenImage21Pipeline" => (
                &["processor/tokenizer.json", "text_encoder/config.json"],
                &["transformer", "text_encoder", "vae"],
            ),
            "WanPipeline" => (
                &["tokenizer/tokenizer.json", "text_encoder/config.json"],
                &["transformer", "text_encoder", "vae"],
            ),
            other => panic!("{}: no loader layout for {other}", e.id),
        };
        for need in [
            "model_index.json",
            "scheduler/scheduler_config.json",
            "transformer/config.json",
            "vae/config.json",
        ]
        .iter()
        .chain(configs)
        {
            assert!(files.contains(need), "{}: {need} not pinned", e.id);
        }
        for dir in weights {
            assert!(
                files
                    .iter()
                    .any(|f| f.starts_with(&format!("{dir}/")) && f.ends_with(".safetensors")),
                "{}: no pinned {dir} weights",
                e.id
            );
        }
    }
}

#[test]
fn every_speech_model_pins_its_checkpoint() {
    let tts = get_tts_catalog();
    assert!(!tts.is_empty());
    for e in tts {
        let full = entry(&e.id).expect("catalogued");
        let files: Vec<&str> = full
            .checkpoint(&e.hf_repo)
            .iter()
            .map(|c| c.path.as_str())
            .collect();
        for need in [e.hf_filename.as_str(), e.mmproj_filename.as_str()] {
            assert!(files.contains(&need), "{}: {need} not pinned", e.id);
        }
        let revisions: std::collections::HashSet<_> = full
            .checkpoint(&e.hf_repo)
            .iter()
            .map(|c| c.revision())
            .collect();
        assert_eq!(
            revisions.len(),
            1,
            "{}: files pinned at more than one commit",
            e.id
        );
    }
}

/// Every seed entry is well formed, and every file an entry downloads has
/// the hash its bytes must have: a file without one cannot be downloaded at
/// all, so publishing it would ship a model nobody can fetch.
#[test]
fn every_seed_entry_is_valid_and_hashes_its_downloads() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seed");
    let entries = read_entries(&dir).expect("the seed parses");
    assert!(
        entries.len() > 150,
        "the seed lost entries: {}",
        entries.len()
    );
    for e in &entries {
        e.validate().unwrap_or_else(|err| panic!("{err}"));
        for (repo, path) in e.downloads() {
            assert!(
                e.component(&repo, &path).is_some(),
                "{}: {repo}/{path} has no hash",
                e.id()
            );
        }
    }
    let (catalog, errors) = Catalog::build(entries);
    assert!(errors.is_empty(), "{errors:?}");
    assert!(catalog.len() > 150);
}

/// The registry row of a GGUF entry.
fn model_info(id: &str, provider: tenzro_types::Address) -> tenzro_types::ModelInfo {
    entry(id)
        .unwrap_or_else(|| panic!("{id} missing from catalog"))
        .model_info(provider)
        .expect("a GGUF entry")
}

/// The licence of a model, from its entry.
fn licence(id: &str) -> Licence {
    entry(id).unwrap_or_else(|| panic!("{id} missing")).licence
}

/// The two served families disagree on the template variable name, so a
/// resolver that returned only a value would set the wrong kwarg on one of
/// them and be silently ignored.
#[test]
fn effort_kwarg_name_is_per_family() {
    let qwen = EffortPolicy::for_family("qwen3.8-flash-next");
    assert_eq!(qwen.kwarg, "reasoning_effort");
    let muse = EffortPolicy::for_family("muse-glimmer");
    assert_eq!(muse.kwarg, "reasoning_strength");
}

/// A family with no declared policy must drop the value entirely — the
/// safe direction, since guessing a kwarg name can only mislead a template.
#[test]
fn family_without_effort_control_drops_the_value() {
    let none = EffortPolicy::for_family("gemma4");
    assert!(none.kwarg.is_empty());
    assert_eq!(resolve_reasoning_effort("gemma4-12b", Some("low")), None);
}

/// End-to-end through the catalog: the *model id* must map to its family's
/// policy. This is the step that would silently disable the feature if a
/// family string were mistyped, since the fallback is "no effort control".
#[test]
fn resolve_maps_model_id_to_family_policy() {
    assert_eq!(
        resolve_reasoning_effort("qwen3.8-flash-next", Some("high")),
        Some(("reasoning_effort".to_string(), "xhigh".to_string())),
    );
    assert_eq!(
        resolve_reasoning_effort("muse-glimmer-30b", Some("low")),
        Some(("reasoning_strength".to_string(), "low".to_string())),
    );
}

/// An unknown model has no family, so there is nothing to validate against.
#[test]
fn unknown_model_resolves_to_none() {
    assert_eq!(resolve_reasoning_effort("no-such-model", Some("low")), None);
}

#[test]
fn test_catalog_not_empty() {
    let catalog = get_model_catalog();
    assert!(!catalog.is_empty());
    assert!(
        catalog.len() >= 20,
        "Expected at least 20 models in catalog"
    );
}

/// The router tiers on `parameter_count`. Leaving it unset is what made
/// `quality_floor=strong` unsatisfiable for every locally-served model.
///
/// The only entries without a size are MTP draft heads, which are loaded
/// alongside a target model and never routed to on their own — `None` is
/// the honest answer for those, and keeps them out of the strong tier.
#[test]
fn a_served_catalog_model_carries_its_size_into_the_registry() {
    let provider = tenzro_types::Address::new([7; 32]);
    let mut sized = 0usize;
    for entry in get_model_catalog() {
        let count = model_info(&entry.id, provider).parameters.parameter_count;
        // Digit-leading, or Gemma's `E2B` effective-parameter form.
        let declares_size = entry
            .parameters
            .trim_start_matches(['E', 'e'])
            .starts_with(|c: char| c.is_ascii_digit());
        if declares_size {
            assert!(
                count.is_some(),
                "{} declares parameters {:?} but no count reached ModelInfo",
                entry.id,
                entry.parameters
            );
            sized += 1;
        } else {
            assert_eq!(
                entry.mtp_kind,
                MtpKind::None,
                "{} has no declared size but is not a draft head: {:?}",
                entry.id,
                entry.parameters
            );
            assert!(count.is_none());
        }
    }
    assert!(sized > 20, "expected most of the catalog to declare a size");
}

/// The two models this machine serves must land on opposite sides of the
/// strong-tier floor, or the ladder has nothing to choose between.
#[test]
fn the_served_pair_straddles_the_strong_tier_floor() {
    let provider = tenzro_types::Address::new([7; 32]);
    let count = |id: &str| model_info(id, provider).parameters.parameter_count;
    assert_eq!(count("qwen3.5-0.8b"), Some(800_000_000));
    assert_eq!(count("qwen3.6-35b-a3b-mtp"), Some(35_000_000_000));
}

/// The reported regression: qwen3.5-0.8b (the ladder's fast L0 rung)
/// must render thinking-OFF and answer directly, while the strong
/// reasoners keep thinking. The gate keys on TOTAL params, so the 35B-A3B
/// MoE (3B active) is NOT caught by the 4B small-series floor.
#[test]
fn thinking_off_for_small_qwen_but_on_for_capable_reasoners() {
    assert!(!resolve_enable_thinking("qwen3.5-0.8b", None));
    assert!(!resolve_enable_thinking("qwen3.5-2b", None));
    assert!(resolve_enable_thinking("qwen3.6-35b-a3b-mtp", None));
    assert!(resolve_enable_thinking("qwen3.6-35b-a3b", None));
    // muse-glimmer reasons via harmony channels, not the template toggle:
    // supports_thinking=false -> leave the flag at its default (true).
    assert!(resolve_enable_thinking("muse-glimmer-30b", None));
    // Unknown id -> unchanged default.
    assert!(resolve_enable_thinking("does-not-exist", None));
}

/// Gemma 4 has a genuine `enable_thinking` template toggle, OFF by
/// default per Google's docs. Before the `"gemma4"` arm existed, the
/// family fell through to `Self::default()` and was misread the same
/// way muse-glimmer's channel-format reasoning is (`supports_thinking:
/// false` -> "no toggle, leave the flag at true") — forcing thinking on
/// for every request and, on the 12B+ variants, skipping the template's
/// own empty-thought-channel stabilization stub.
#[test]
fn gemma4_thinking_off_by_default() {
    assert!(!resolve_enable_thinking("gemma4-12b-qat", None));
    assert!(!resolve_enable_thinking("gemma4-12b-qat", Some(50)));
    assert!(!resolve_enable_thinking("gemma4-12b-qat", Some(32_768)));
}

/// Serialises env-var access across the two tests that mutate
/// `TENZRO_NOTHINK_MODELS`, so a set in one can't leak into the other's
/// observation (Rust runs tests in the same process on many threads).
static NOTHINK_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The operator escape hatch: `TENZRO_NOTHINK_MODELS` forces a normally
/// thinking-on model onto the non-thinking path with no rebuild, and the
/// override wins before any policy lookup.
#[test]
fn env_override_forces_thinking_off() {
    let _guard = NOTHINK_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Baseline: this MoE reasons by default.
    assert!(resolve_enable_thinking("qwen3.6-35b-a3b", None));
    // SAFETY: single-threaded within the lock; no other test reads/writes
    // this var without holding the same lock.
    unsafe {
        std::env::set_var("TENZRO_NOTHINK_MODELS", " other-id , qwen3.6-35b-a3b ,");
    }
    // Trimmed, non-empty match -> forced off even for a large reasoner.
    assert!(!resolve_enable_thinking("qwen3.6-35b-a3b", None));
    // A model not on the list is unaffected by the override.
    assert!(resolve_enable_thinking("muse-glimmer-30b", None));
    unsafe {
        std::env::remove_var("TENZRO_NOTHINK_MODELS");
    }
    // Cleared -> back to the policy default.
    assert!(resolve_enable_thinking("qwen3.6-35b-a3b", None));
}

/// The budget half of the Auto gate: a capable reasoner given too small a
/// `max_tokens` to both think and answer renders thinking-OFF, while a
/// generous budget keeps it on. qwen3.6 carries `thinking_min_budget_tokens
/// == 16_384`.
#[test]
fn budget_gate_forces_thinking_off_when_tiny() {
    let _guard = NOTHINK_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Make sure a leaked override from another test can't confound this.
    unsafe {
        std::env::remove_var("TENZRO_NOTHINK_MODELS");
    }
    // Tiny budget (< 16_384) -> off despite the model being big enough.
    assert!(!resolve_enable_thinking("qwen3.6-35b-a3b", Some(512)));
    // Generous budget (>= 16_384) -> on.
    assert!(resolve_enable_thinking("qwen3.6-35b-a3b", Some(32_768)));
    // Exactly at the floor -> on (the gate is `>=`).
    assert!(resolve_enable_thinking("qwen3.6-35b-a3b", Some(16_384)));
    // muse-glimmer is supports_thinking=false, so the budget never applies.
    assert!(resolve_enable_thinking("muse-glimmer-30b", Some(1)));
}

#[test]
fn test_all_entries_have_required_fields() {
    for entry in get_model_catalog() {
        assert!(!entry.id.is_empty(), "Model ID empty");
        assert!(!entry.name.is_empty(), "Model name empty for {}", entry.id);
        assert!(!entry.hf_repo.is_empty(), "HF repo empty for {}", entry.id);
        // Extraction-only MoE entries carry no whole-model GGUF
        // serving artifact yet: hf_filename is empty, size/RAM are
        // unset, and the entry is not promotable. They must instead
        // map to a safetensors checkpoint source for per-expert
        // extraction.
        let extraction_only = entry.hf_filename.is_empty();
        if extraction_only {
            assert!(
                !entry.promotable,
                "{} has no serving artifact but is promotable",
                entry.id
            );
            assert!(
                entry.moe.is_some(),
                "{} has no serving artifact and no MoE shape",
                entry.id
            );
            assert!(
                moe_source(&entry.id).is_some(),
                "{} has no serving artifact and no safetensors source",
                entry.id
            );
        } else {
            assert!(entry.size_bytes > 0, "Size is 0 for {}", entry.id);
            assert!(entry.min_ram_gb > 0, "Min RAM is 0 for {}", entry.id);
        }
        assert!(
            entry.context_length > 0,
            "Context length is 0 for {}",
            entry.id
        );
        // Sampler values must be plausible.
        assert!(
            entry.serving.temperature >= 0.0 && entry.serving.temperature <= 2.0,
            "implausible temperature {} for {}",
            entry.serving.temperature,
            entry.id
        );
        assert!(
            entry.serving.top_p > 0.0 && entry.serving.top_p <= 1.0,
            "implausible top_p {} for {}",
            entry.serving.top_p,
            entry.id
        );
    }
}

/// Each entry carries its family's serving profile, not the neutral
/// `ServingProfile::default()`. Spot-check a few families whose profiles
/// differ from the default.
#[test]
fn test_serving_profiles_stamped_by_family() {
    let by = |id: &str| get_model_by_id(id).expect(id).serving;
    // Gemma uses temp 1.0 / top_k 64 — distinct from the 0.7/20 default.
    let g = by("gemma3-4b");
    assert_eq!(g.temperature, 1.0, "gemma3 temperature");
    assert_eq!(g.top_k, 64, "gemma3 top_k");
    // Mistral uses low-temp instruct 0.15.
    if let Some(m) = get_model_by_id("mistral-nemo-12b") {
        assert_eq!(m.serving.temperature, 0.15, "mistral temperature");
    }
    // Every entry must have jinja required (all are chat models).
    for entry in get_model_catalog() {
        assert!(
            entry.serving.jinja_required,
            "{} should require jinja",
            entry.id
        );
    }
}

#[test]
fn test_mmproj_stamped_on_gemma4_multimodal() {
    // Every Gemma 4 language model carries the projector; the tiny
    // speculative drafters do not.
    for entry in get_model_catalog() {
        if entry.architecture == ModelArchitecture::Gemma4 {
            if entry.id.ends_with("-mtp-draft") {
                assert!(
                    entry.mmproj.is_none(),
                    "{} is a draft model and must not carry mmproj",
                    entry.id
                );
            } else if entry.id == "nemotron-3.5-bolt-e4b-4gb" {
                // The vendor's own release is text in, text out and ships no
                // projector; the multimodal builds are the unsloth entries.
                assert!(entry.mmproj.is_none(), "{}", entry.id);
            } else {
                let mm = entry
                    .mmproj
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} should carry mmproj", entry.id));
                assert_eq!(mm.filename, "mmproj-F16.gguf", "{}", entry.id);
            }
        }
    }
    // Text-only families never carry a projector.
    let q = get_model_by_id("qwen3-4b").expect("qwen3-4b");
    assert!(q.mmproj.is_none(), "text-only model should have no mmproj");
}

#[test]
fn test_get_model_by_id() {
    assert!(get_model_by_id("qwen3-0.6b").is_some());
    assert!(get_model_by_id("gemma3-4b").is_some());
    assert!(get_model_by_id("nonexistent").is_none());
}

/// Every `drafter_id` in the catalog must resolve to another catalog
/// entry. A dangling reference would break speculative-decoding load.
#[test]
fn test_drafter_ids_resolve() {
    let catalog = get_model_catalog();
    for entry in &catalog {
        if let Some(drafter) = entry.drafter_id.as_ref() {
            assert!(
                get_model_by_id(drafter).is_some(),
                "model `{}` references unknown drafter `{}`",
                entry.id,
                drafter,
            );
            // A drafter must not itself nest a drafter.
            let drafter_entry = get_model_by_id(drafter).unwrap();
            assert!(
                drafter_entry.drafter_id.is_none(),
                "drafter `{}` itself has a drafter_id — nesting not supported",
                drafter,
            );
            // Drafter must be smaller than target — sanity check, not a hard
            // requirement of llama.cpp but a precondition for net-positive
            // speculative decoding throughput.
            assert!(
                drafter_entry.size_bytes < entry.size_bytes,
                "drafter `{}` ({} bytes) is not smaller than target `{}` ({} bytes)",
                drafter,
                drafter_entry.size_bytes,
                entry.id,
                entry.size_bytes,
            );
        }
    }
}

/// The four target/drafter pairings we explicitly ship as of 2026-05-06.
/// If any of these stop being wired, speculative decoding regresses for
/// the corresponding family.
#[test]
fn test_known_drafter_pairings() {
    let pairs = [
        ("qwen3-32b", "qwen3-0.6b"),
        ("qwen3.6-27b", "qwen3.5-0.8b"),
        ("mistral-small-3.1-24b", "mistral-small-3.1-draft-0.5b"),
        ("mistral-small-3.2-24b", "mistral-small-3.1-draft-0.5b"),
        // Gemma 4 drafter pairings switched to Unsloth's MTP heads
        // (`mtp-gemma-4-*-it.gguf` shipped as siblings of the
        // target GGUFs). MtpKind::DraftMtp + draft_n=2 are the
        // production defaults; older `*-it-assistant` references
        // were community-converted safetensors and are no longer
        // in the catalog.
        ("gemma4-e2b", "gemma4-e2b-mtp-draft"),
        ("gemma4-e4b", "gemma4-e4b-mtp-draft"),
        ("gemma4-12b", "gemma4-12b-mtp-draft"),
        ("gemma4-26b-a4b", "gemma4-26b-a4b-mtp-draft"),
        ("gemma4-31b", "gemma4-31b-mtp-draft"),
    ];
    for (target, expected_drafter) in pairs {
        let entry =
            get_model_by_id(target).unwrap_or_else(|| panic!("missing target `{}`", target));
        assert_eq!(
            entry.drafter_id.as_deref(),
            Some(expected_drafter),
            "target `{}` should pair with drafter `{}`",
            target,
            expected_drafter,
        );
    }
}

#[test]
fn test_model_families() {
    let families = get_model_families();
    assert!(families.contains(&"qwen3".to_string()));
    assert!(families.contains(&"qwen3.6".to_string()));
    assert!(families.contains(&"gemma3".to_string()));
    assert!(families.contains(&"gemma4".to_string()));
    assert!(families.contains(&"mistral".to_string()));
    assert!(families.contains(&"nemotron".to_string()));
    assert!(families.contains(&"glm".to_string()));
    assert!(families.contains(&"kimi".to_string()));
    assert!(families.contains(&"minimax".to_string()));
    assert!(families.contains(&"deepseek".to_string()));
    assert!(families.contains(&"gpt-oss".to_string()));
    assert!(families.contains(&"granite".to_string()));
}

#[test]
fn test_2026_additions_present() {
    assert!(get_model_by_id("qwen3.6-27b").is_some());
    assert!(get_model_by_id("qwen3.6-35b-a3b").is_some());
    assert!(get_model_by_id("mistral-small-3.1-24b").is_some());
    assert!(get_model_by_id("mistral-small-3.2-24b").is_some());
    assert!(get_model_by_id("gpt-oss-20b").is_some());
    assert!(get_model_by_id("gpt-oss-120b").is_some());
    assert!(get_model_by_id("granite4-350m").is_some());
    assert!(get_model_by_id("granite4-1b").is_some());
    assert!(get_model_by_id("granite4-h-tiny").is_some());
    assert!(get_model_by_id("granite4-h-small").is_some());
}

#[test]
fn test_unique_ids() {
    let catalog = get_model_catalog();
    let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
    ids.sort();
    let len_before = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), len_before, "Duplicate model IDs found");
}

#[test]
fn test_vision_catalog_not_empty() {
    let catalog = get_vision_catalog();
    assert!(!catalog.is_empty());
    assert!(catalog.len() >= 7, "Expected at least 7 vision encoders");
}

#[test]
fn test_vision_entries_have_required_fields() {
    for e in get_vision_catalog() {
        assert!(!e.id.is_empty(), "vision id empty");
        assert!(!e.name.is_empty(), "vision name empty for {}", e.id);
        assert!(!e.hf_repo.is_empty(), "vision repo empty for {}", e.id);
        assert!(
            e.hf_filename.ends_with(".onnx"),
            "vision filename not .onnx for {}: {}",
            e.id,
            e.hf_filename
        );
        assert!(e.input_size > 0, "input_size 0 for {}", e.id);
        assert!(e.embedding_dim > 0, "embedding_dim 0 for {}", e.id);
        assert!(e.size_bytes > 0, "size 0 for {}", e.id);
        assert!(e.min_ram_gb > 0, "min ram 0 for {}", e.id);
        assert!(
            matches!(e.normalization.as_str(), "clip" | "imagenet" | "siglip"),
            "unknown normalization '{}' for {}",
            e.normalization,
            e.id
        );
    }
}

#[test]
fn test_vision_get_by_id() {
    assert!(get_vision_model_by_id("clip-vit-b32").is_some());
    assert!(get_vision_model_by_id("siglip2-base-224").is_some());
    assert!(get_vision_model_by_id("dinov3-vitl16").is_some());
    assert!(get_vision_model_by_id("nonexistent").is_none());
}

#[test]
fn test_vision_unique_ids() {
    let catalog = get_vision_catalog();
    let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
    ids.sort();
    let len_before = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), len_before, "Duplicate vision model IDs");
}

#[test]
fn test_vision_families_present() {
    let catalog = get_vision_catalog();
    let families: std::collections::HashSet<&str> =
        catalog.iter().map(|m| m.family.as_str()).collect();
    assert!(families.contains("clip"));
    assert!(families.contains("siglip"));
    assert!(families.contains("siglip2"));
    assert!(families.contains("dinov3"));
}

#[test]
fn test_forecast_catalog_not_empty() {
    let catalog = get_forecast_catalog();
    assert!(!catalog.is_empty());
}

#[test]
fn test_forecast_entries_have_required_fields() {
    for e in get_forecast_catalog() {
        assert!(!e.id.is_empty(), "forecast id empty");
        assert!(!e.name.is_empty(), "forecast name empty for {}", e.id);
        assert!(!e.hf_repo.is_empty(), "forecast repo empty for {}", e.id);
        assert!(
            e.hf_filename.ends_with(".onnx"),
            "forecast filename not .onnx for {}: {}",
            e.id,
            e.hf_filename
        );
        assert!(e.context_length > 0, "context_length 0 for {}", e.id);
        assert!(e.max_horizon > 0, "max_horizon 0 for {}", e.id);
        assert!(e.size_bytes > 0, "size 0 for {}", e.id);
        assert!(e.min_ram_gb > 0, "min ram 0 for {}", e.id);
        assert!(!e.parameters.is_empty(), "parameters empty for {}", e.id);
        assert!(
            !licence(&e.id).name.is_empty(),
            "license empty for {}",
            e.id
        );
        assert!(
            e.batch_size > 0,
            "batch_size 0 for {} — the runtime tiles input to this width",
            e.id
        );
        if let Some(name) = &e.output_name {
            assert!(!name.is_empty(), "empty output_name for {}", e.id);
        }
    }
}

#[test]
fn test_single_input_quantile_forecasters_are_built_files() {
    // TiRex-2 and Toto 2.0 are exported in-tree to one input `context
    // [1, ctx]` and one output `quantiles [1, H, 9]`; GenericForecast reads
    // the median at index q / 2 = 4 (level 0.5). Both are network files
    // rebuilt by the recipe from the pinned upstream checkpoint.
    for (id, ctx, horizon) in [
        ("tirex-2", 2048, 320),
        ("toto-2.0-22m", 2048, 768),
        ("toto-2.0-313m", 2048, 768),
    ] {
        let e = get_forecast_model_by_id(id).unwrap();
        assert_eq!(e.context_length, ctx, "{id}");
        assert_eq!(e.max_horizon, horizon, "{id}");
        assert_eq!(e.n_quantiles, 9, "{id}");
        assert_eq!(e.batch_size, 1, "{id}");
        assert_eq!(e.output_name.as_deref(), Some("quantiles"), "{id}");
        assert!(
            matches!(licence(&e.id).tier, LicenseTier::Permissive),
            "{id}"
        );
    }
    assert!(get_forecast_model_by_id("tirex-35m").is_none());
}

#[test]
fn test_timesfm_graph_quirks_are_recorded() {
    // Both quirks are properties of the published graph, not caller
    // choices: the decoder averages across the batch axis for flip
    // invariance, and the first output is a hidden state.
    let t = get_forecast_model_by_id("timesfm-2.5-200m").unwrap();
    assert_eq!(t.batch_size, 2);
    assert_eq!(t.output_name.as_deref(), Some("full_predictions"));
}

#[test]
fn test_forecast_get_by_id() {
    assert!(get_forecast_model_by_id("timesfm-2.5-200m").is_some());
    assert!(get_forecast_model_by_id("nonexistent").is_none());
}

#[test]
fn test_forecast_unique_ids() {
    let catalog = get_forecast_catalog();
    let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
    ids.sort();
    let len_before = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), len_before, "Duplicate forecast model IDs");
}

#[test]
fn test_forecast_families_present() {
    let catalog = get_forecast_catalog();
    let families: std::collections::HashSet<&str> =
        catalog.iter().map(|m| m.family.as_str()).collect();
    assert!(families.contains("timesfm"));
}

#[test]
fn test_forecast_quantile_shape_invariant() {
    // n_quantiles > 0 → quantile head; TimesFM 2.5 ships 10 bands.
    let timesfm = get_forecast_model_by_id("timesfm-2.5-200m").unwrap();
    assert_eq!(timesfm.n_quantiles, 10);
}

// ── Vision catalog (DINOv3 + SigLIP2 large/so400m) ──────────────

#[test]
fn test_vision_dinov3_entries_present() {
    for id in &["dinov3-vits16", "dinov3-vitb16", "dinov3-vitl16"] {
        let e = get_vision_model_by_id(id).unwrap_or_else(|| panic!("missing dinov3 entry {}", id));
        assert_eq!(e.family, "dinov3");
        assert_eq!(licence(&e.id).tier, LicenseTier::CommercialCustom);
    }
}

#[test]
fn test_vision_siglip2_large_so400m_present() {
    for id in &["siglip2-large-256", "siglip2-so400m-384"] {
        let e =
            get_vision_model_by_id(id).unwrap_or_else(|| panic!("missing siglip2 entry {}", id));
        assert_eq!(e.family, "siglip2");
        assert_eq!(licence(&e.id).tier, LicenseTier::Permissive);
    }
}

// ── Text embedding catalog ─────────────────────────────────────

#[test]
fn test_text_embedding_catalog_not_empty() {
    let catalog = get_text_embedding_catalog();
    assert!(
        catalog.len() >= 5,
        "expected at least 5 text-embedding models"
    );
}

#[test]
fn test_text_embedding_required_fields() {
    for e in get_text_embedding_catalog() {
        assert!(!e.id.is_empty());
        assert!(!e.hf_repo.is_empty());
        assert!(e.hf_filename.ends_with(".onnx"), "{} not .onnx", e.id);
        assert!(e.tokenizer_filename.ends_with(".json"));
        assert!(e.max_sequence_length > 0);
        assert!(e.embedding_dim > 0);
        assert!(e.size_bytes > 0);
        assert!(e.min_ram_gb > 0);
    }
}

#[test]
fn test_text_embedding_qwen3_family() {
    for id in &[
        "qwen3-embedding-0.6b",
        "qwen3-embedding-4b",
        "qwen3-embedding-8b",
    ] {
        let e = get_text_embedding_model_by_id(id)
            .unwrap_or_else(|| panic!("missing qwen3-embedding {}", id));
        assert_eq!(e.family, "qwen3-embedding");
        assert_eq!(licence(&e.id).tier, LicenseTier::Permissive);
    }
}

#[test]
fn test_qwen3_vl_embedding_is_a_network_gguf() {
    let e = get_embed_model_by_id("qwen3-vl-embedding-2b").expect("qwen3-vl-embedding-2b");
    assert_eq!(e.family, "qwen3-vl-embedding");
    assert_eq!(e.embedding_dim, 2048);
    assert!(matches!(
        e.embedding_template,
        EmbeddingTemplate::ChatInstruct { .. }
    ));
    assert_eq!(e.hf_filename, "qwen3-vl-embedding-2b-f16.gguf");
    assert_eq!(
        e.mmproj.as_ref().map(|m| m.filename.as_str()),
        Some("qwen3-vl-embedding-2b-mmproj-f16.gguf")
    );
    assert_eq!(licence(&e.id).tier, LicenseTier::Permissive);
    // the projector comes with the pipeline's own picture and frame sizing
    let v = e
        .vision_input
        .as_ref()
        .expect("a vision-language embedder takes pictures");
    assert_eq!(
        (v.patch_size, v.merge_size, v.temporal_patch_size),
        (16, 2, 2)
    );
    assert_eq!((v.image_min_pixels, v.image_max_pixels), (4096, 1_843_200));
    assert_eq!(v.video_frames, 64);
    // served on the Praecise engine only: no ONNX export of it is listed
    assert!(get_text_embedding_model_by_id(&e.id).is_none());
    assert!(
        get_embed_catalog()
            .iter()
            .all(|m| m.mmproj.is_some() == m.vision_input.is_some())
    );
}

#[test]
fn test_qwen3_vl_reranker_is_a_network_gguf() {
    let e = get_rerank_model_by_id("qwen3-vl-reranker-2b").expect("qwen3-vl-reranker-2b");
    let full = entry(&e.id).expect("catalogued");
    assert!(
        full.checkpoint(&e.hf_repo)
            .iter()
            .any(|c| c.path == e.hf_filename && c.network_blake3().is_some())
    );
    // The projector is a network file from the same converter, fetched with the model.
    let mmproj = &e.mmproj.as_ref().expect("projector").filename;
    assert!(
        full.checkpoint(&e.hf_repo)
            .iter()
            .any(|c| &c.path == mmproj && c.network_blake3().is_some())
    );
    assert!(full.downloads().iter().any(|(_, p)| p == mmproj));
    let input = e.vision_input.as_ref().expect("picture sizing");
    assert_eq!(
        (
            input.patch_size,
            input.merge_size,
            input.temporal_patch_size
        ),
        (16, 2, 2)
    );
    assert_eq!(
        (input.image_min_pixels, input.image_max_pixels),
        (4096, 1_310_720)
    );
    assert_eq!(input.video_total_pixels, 10_485_760);
    assert_eq!(licence(&e.id).tier, LicenseTier::Permissive);
}

#[test]
fn test_nemotron_embed_is_a_network_export() {
    let e = get_text_embedding_model_by_id("nemotron-3-embed-1b").expect("nemotron-3-embed-1b");
    assert_eq!(e.family, "nemotron-embed");
    assert_eq!(e.embedding_dim, 2048);
    assert_eq!(e.embedding_template, EmbeddingTemplate::QueryPassagePrefix);
    assert_eq!(
        e.external_data_filenames,
        vec!["model.onnx_data".to_string()]
    );
    assert_eq!(licence(&e.id).tier, LicenseTier::Permissive);
}

#[test]
fn test_embeddinggemma_matryoshka() {
    let e = get_text_embedding_model_by_id("embeddinggemma-300m").unwrap();
    assert_eq!(e.embedding_dim, 768);
    assert_eq!(e.matryoshka_dims, vec![512, 256, 128]);
    assert!(!e.supports_fp16, "EmbeddingGemma is fp32-only");
    assert_eq!(licence(&e.id).tier, LicenseTier::CommercialCustom);
}

#[test]
fn test_modernbert_embed_variants() {
    let base = get_text_embedding_model_by_id("modernbert-embed-base").unwrap();
    assert_eq!(base.family, "modernbert");
    assert_eq!(base.embedding_dim, 768);
    assert_eq!(base.max_sequence_length, 8192);
    assert_eq!(base.matryoshka_dims, vec![256]);
    assert_eq!(licence(&base.id).tier, LicenseTier::Permissive);

    let large = get_text_embedding_model_by_id("modernbert-embed-large").unwrap();
    assert_eq!(large.family, "modernbert");
    assert_eq!(large.embedding_dim, 1024);
    assert_eq!(large.max_sequence_length, 8192);
    assert_eq!(licence(&large.id).tier, LicenseTier::Permissive);
}

#[test]
fn test_text_embedding_unique_ids() {
    let ids: Vec<_> = get_text_embedding_catalog()
        .into_iter()
        .map(|m| m.id)
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    let len_before = sorted.len();
    sorted.dedup();
    assert_eq!(sorted.len(), len_before, "duplicate text-embedding IDs");
}

// ── Segmentation catalog ───────────────────────────────────────

#[test]
fn test_segmentation_catalog_not_empty() {
    let catalog = get_segmentation_catalog();
    // SAM 2 base + large, EdgeSAM, MobileSAM. SAM 3 is deferred to a
    // future text-promptable runtime — see comment in
    // `get_segmentation_catalog`.
    assert_eq!(catalog.len(), 4, "expected 4 segmentation models");
}

#[test]
fn test_segmentation_sam2_permissive() {
    for id in &["sam2-base", "sam2-large"] {
        let e = get_segmentation_model_by_id(id).unwrap_or_else(|| panic!("missing {}", id));
        assert_eq!(licence(&e.id).tier, LicenseTier::Permissive);
    }
}

#[test]
fn test_segmentation_edge_tier() {
    // EdgeSAM is research-only (NTU S-Lab 1.0 = NonCommercial); MobileSAM
    // is Apache 2.0. Both are <50 MB.
    let edgesam = get_segmentation_model_by_id("edgesam").expect("missing edgesam");
    assert_eq!(licence(&edgesam.id).tier, LicenseTier::NonCommercial);
    assert!(edgesam.size_bytes < 50_000_000);

    let mobilesam = get_segmentation_model_by_id("mobilesam").expect("missing mobilesam");
    assert_eq!(licence(&mobilesam.id).tier, LicenseTier::Permissive);
    assert!(mobilesam.size_bytes < 50_000_000);
}

#[test]
fn test_segmentation_required_fields() {
    for e in get_segmentation_catalog() {
        assert!(!e.id.is_empty());
        assert!(e.encoder_filename.ends_with(".onnx"));
        assert!(e.decoder_filename.ends_with(".onnx"));
        assert!(e.input_size > 0);
        assert!(e.size_bytes > 0);
    }
}

// ── Detection catalog ──────────────────────────────────────────

#[test]
fn test_detection_catalog_not_empty() {
    let catalog = get_detection_catalog();
    assert!(catalog.len() >= 9, "expected ≥9 detection models");
}

#[test]
fn test_detection_rf_detr_six_tiers() {
    for id in &[
        "rf-detr-nano",
        "rf-detr-small",
        "rf-detr-medium",
        "rf-detr-base",
        "rf-detr-large",
        "rf-detr-2xl",
    ] {
        let e =
            get_detection_model_by_id(id).unwrap_or_else(|| panic!("missing rf-detr tier {}", id));
        assert_eq!(e.family, "rf-detr");
        assert_eq!(licence(&e.id).tier, LicenseTier::Permissive);
    }
}

#[test]
fn test_detection_required_fields() {
    for e in get_detection_catalog() {
        assert!(!e.id.is_empty());
        assert!(e.hf_filename.ends_with(".onnx"));
        assert!(e.input_size > 0);
        assert!(e.num_classes > 0);
        assert!(e.size_bytes > 0);
    }
}

// ── Audio catalog ──────────────────────────────────────────────

#[test]
fn test_audio_catalog_not_empty() {
    let catalog = get_audio_catalog();
    assert!(catalog.len() >= 5, "expected ≥5 audio models");
}

#[test]
fn test_audio_required_fields() {
    for e in get_audio_catalog() {
        assert!(!e.id.is_empty());
        assert!(e.encoder_filename.ends_with(".onnx"));
        assert_eq!(e.sample_rate, 16000);
        assert!(e.max_audio_seconds > 0);
        assert!(!e.languages.is_empty(), "{} has no languages", e.id);
    }
}

// ── Video catalog ──────────────────────────────────────────────

#[test]
fn the_video_catalog_is_empty_until_a_real_onnx_export_exists() {
    // Guards against re-adding entries the node cannot load. V-JEPA 2 sat
    // here for a while, but `facebook/vjepa2-*` ships safetensors only and
    // `handle_load_video_model` never consults this catalog — it wires the
    // frame-pooled vision encoder from a `vision_model_id` instead. An entry
    // here is therefore unreachable by construction, and advertising an
    // unreachable model is worse than advertising none: callers only find
    // out after trying.
    //
    // When a permissive encoder-only video model ships a genuine ONNX
    // export, add it here AND give it a loader path in the same change.
    assert!(
        get_video_catalog().is_empty(),
        "video entries need a loader path before they are listed"
    );
    assert!(get_video_model_by_id("vjepa2-vitl-256").is_none());
}

// ── Speech synthesis catalog ─────────────────────────────────────

#[test]
fn every_tts_entry_is_permissive_and_complete() {
    let catalog = get_tts_catalog();
    assert!(!catalog.is_empty());
    for e in &catalog {
        assert_eq!(licence(&e.id).name, "Apache-2.0", "{}", e.id);
        assert!(matches!(licence(&e.id).tier, LicenseTier::Permissive));
        assert!(
            e.hf_filename.ends_with(".gguf") && e.mmproj_filename.ends_with(".gguf"),
            "{}",
            e.id
        );
        assert!(e.size_bytes > 0 && e.min_ram_gb > 0 && e.sample_rate > 0);
        assert!(e.languages.iter().any(|l| l == "en"));
        assert_eq!(
            get_tts_model_by_id(&e.id).as_ref().map(|x| &x.id),
            Some(&e.id),
            "{} must round-trip through lookup",
            e.id
        );
    }
}

#[test]
fn voice_cloning_capability_is_recorded_per_checkpoint() {
    // An operator has to be able to see which checkpoints carry cloning
    // before turning it on, rather than finding out from a request.
    let by_id: std::collections::HashMap<String, TtsModelEntry> = get_tts_catalog()
        .into_iter()
        .map(|e| (e.id.clone(), e))
        .collect();
    assert!(by_id["qwen3-tts-1.7b"].supports_voice_cloning);
}

#[test]
fn every_reranker_pins_its_gguf_and_is_no_chat_model() {
    let catalog = get_rerank_catalog();
    assert!(!catalog.is_empty());
    for e in &catalog {
        let full = entry(&e.id).expect("catalogued");
        assert!(
            full.checkpoint(&e.hf_repo)
                .iter()
                .any(|c| c.path == e.hf_filename),
            "{}",
            e.id
        );
        assert!(
            get_model_by_id(&e.id).is_none(),
            "{} is served as a reranker only",
            e.id
        );
        assert_eq!(
            get_rerank_model_by_id(&e.id).map(|x| x.id),
            Some(e.id.clone())
        );
    }
}

#[test]
fn an_unknown_tts_model_resolves_to_none() {
    assert!(get_tts_model_by_id("kokoro-82m").is_none());
}

// ── Generative-media catalog ─────────────────────────────────────

/// Every media-gen entry must still satisfy the catalog's own admission
/// rules on the real hub.
///
/// The rules: gated on the Hub exactly when the entry says so, and published
/// as a pipeline repo (a `model_index.json` naming its pipeline).
/// Both are properties of the upstream repo, not of this file, so they
/// can stop being true without anything here changing — a repo gets
/// gated, renamed, or re-uploaded at a different size.
///
/// `size_bytes` is checked to within 10%: it feeds the memory budget and
/// the on-demand tier ceiling, so a stale figure means the node admits a
/// pipeline against the wrong footprint.
///
/// Ignored by default — it hits the network, and CI stays hermetic.
#[tokio::test]
#[ignore = "hits the HuggingFace API; run with --run-ignored"]
async fn media_gen_entries_still_satisfy_their_admission_rules() {
    #[derive(serde::Deserialize)]
    struct Sibling {
        rfilename: String,
        #[serde(default)]
        size: Option<u64>,
    }
    #[derive(serde::Deserialize)]
    struct RepoInfo {
        #[serde(default)]
        gated: serde_json::Value,
        #[serde(default)]
        siblings: Vec<Sibling>,
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("client");

    let mut problems = Vec::new();
    for entry in get_media_gen_catalog() {
        let url = format!(
            "https://huggingface.co/api/models/{}?blobs=true",
            entry.hf_repo
        );
        let response = client.get(&url).send().await.expect("HF reachable");
        if !response.status().is_success() {
            problems.push(format!(
                "{}: HF returned {} for {}",
                entry.id,
                response.status(),
                entry.hf_repo
            ));
            continue;
        }
        let info: RepoInfo = response.json().await.expect("HF response parses");

        // `gated` is `false` when open, or a string like "auto"/"manual".
        let hub_gated = info.gated != serde_json::Value::Bool(false);
        if hub_gated != tenzro_catalog::entry(&entry.id).is_some_and(|e| e.gated) {
            problems.push(format!(
                "{}: the Hub reports gated = {}",
                entry.id, info.gated
            ));
        }
        if !info
            .siblings
            .iter()
            .any(|s| s.rfilename == "model_index.json")
        {
            problems.push(format!(
                "{}: no model_index.json — not a pipeline repo",
                entry.id
            ));
        }

        let actual: u64 = info.siblings.iter().filter_map(|s| s.size).sum();
        if actual > 0 && entry.size_bytes > 0 {
            let drift =
                (actual as f64 - entry.size_bytes as f64).abs() / entry.size_bytes as f64 * 100.0;
            if drift > 10.0 {
                problems.push(format!(
                    "{}: size drifted {drift:.0}% (catalog {:.1} GB, actual {:.1} GB) — the \
                     memory budget would admit it against the wrong footprint",
                    entry.id,
                    entry.size_bytes as f64 / 1e9,
                    actual as f64 / 1e9
                ));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "catalog drift:\n  {}",
        problems.join("\n  ")
    );
}

/// A model id belongs to exactly one family, and a family's ids share it.
///
/// The adapter is looked up by family and the entry by id, so an id filed
/// under the wrong family silently gets another family's hooks — the
/// quietest way to render on the wrong recipe.
#[test]
fn every_media_gen_id_is_unique_and_its_family_is_consistent() {
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for entry in get_media_gen_catalog() {
        if let Some(previous) = seen.insert(entry.id.clone(), entry.family.clone()) {
            panic!(
                "{} appears twice, as family {previous:?} and {:?}",
                entry.id, entry.family
            );
        }
    }

    // An id's prefix is not required to match its family — `z-image-turbo`
    // is family `z-image`, `wan2.2-t2v-a14b` is `wan2.2` — but where a
    // family name IS the prefix of an id, that id must be in it. This is
    // what catches `acestep-v15-xl-turbo` being filed under `ltx2`.
    let families: std::collections::HashSet<String> = get_media_gen_catalog()
        .iter()
        .map(|e| e.family.clone())
        .collect();
    for entry in get_media_gen_catalog() {
        for family in &families {
            if entry.id.starts_with(&format!("{family}-")) && &entry.family != family {
                panic!(
                    "{} is named for family {family:?} but is filed under {:?}; it \
                     would be given the wrong family's hooks",
                    entry.id, entry.family
                );
            }
        }
    }
}

/// Every kind a row serves must round-trip through the wire spelling.
///
/// The kind is written as a string into a job, a receipt and a quote, and
/// parsed back on the other side. A variant that does not survive that
/// trip is a job nobody can route.
#[test]
fn every_kind_a_row_serves_round_trips_through_its_label() {
    for entry in get_media_gen_catalog() {
        for kind in &entry.kinds {
            let label = kind.to_string();
            assert_eq!(
                tenzro_types::MediaGenKind::from_str_lossy(&label),
                Some(*kind),
                "{}: kind {label} does not parse back to itself",
                entry.id
            );
        }
    }
}

/// An audio row carries no meaningful pixel dimensions, and must not
/// pretend to. The convention is the struct's minimum, so anything
/// pricing or scheduling on width or height is obviously wrong rather
/// than quietly wrong.
#[test]
fn audio_rows_do_not_carry_plausible_looking_pixel_dimensions() {
    for entry in get_media_gen_catalog() {
        let audio_only = !entry.kinds.is_empty()
            && entry
                .kinds
                .iter()
                .all(|k| matches!(k, tenzro_types::MediaGenKind::Text2Audio));
        if audio_only {
            assert_eq!(
                (
                    entry.default_width,
                    entry.default_height,
                    entry.max_resolution
                ),
                (1, 1, 1),
                "{}: an audio row carrying pixel dimensions invites something to \
                 price on them",
                entry.id
            );
            assert!(
                entry.default_num_frames.is_none() && entry.default_fps.is_none(),
                "{}: an audio row carrying frames or fps invites the video path",
                entry.id
            );
        }
    }
}

#[test]
fn test_media_gen_catalog_membership() {
    let catalog = get_media_gen_catalog();
    let mut ids: Vec<&str> = catalog.iter().map(|e| e.id.as_str()).collect();
    ids.sort();
    assert_eq!(
        ids,
        vec![
            "acestep-v15-xl-base",
            "acestep-v15-xl-sft",
            "acestep-v15-xl-turbo",
            "cosmos3-edge",
            "cosmos3-edge-policy-droid",
            "flux-3-action-base",
            "flux-3-action-droid",
            "flux-3-action-so101",
            "flux-3-image-klein",
            "flux-3-image-klein-base",
            "flux-3-image-klein-fp8",
            "flux-3-image-klein-nvfp4",
            "flux2-dev",
            "flux2-klein-4b",
            "flux2-klein-9b",
            "flux2-klein-9b-gguf-q4",
            "flux2-klein-9b-gguf-q8",
            "flux2-klein-9b-kv",
            "flux2-klein-base-4b",
            "flux2-klein-base-9b",
            "hunyuan-image-3.0",
            "hunyuan3d-2.1",
            "janus-pro-1b",
            "ltx-2.3-22b-dev",
            "ltx-2.3-22b-distilled-gguf",
            "ltx-2.5-22b-dev",
            "ltx-2.5-22b-dev-int8",
            "ltx-2.5-22b-distilled",
            "ltx-2.5-22b-distilled-nvfp4",
            "matrix-game-3",
            "minimax-h3",
            "minimax-h3-fl2va-gguf",
            "minimax-h3-int8",
            "minimax-h3-ref2va",
            "minimax-h3-ref2va-fp8",
            "minimax-h3-ref2va-gguf",
            "minimax-music3",
            "qwen-image",
            "qwen-image-2.1",
            "qwen-image-edit",
            "qwen-image-flash",
            "qwen-image-gguf",
            "trellis2-4b",
            "wan2.1-flf2v-14b",
            "wan2.2-i2v-a14b",
            "wan2.2-t2v-a14b",
            "wan2.2-ti2v-5b",
            "z-image-turbo",
        ],
        "media-gen membership changed: list the entry here, native or planned"
    );
    for e in &catalog {
        // Membership is about *gating on HuggingFace* — whether a fresh
        // node can fetch the weights without an account. Licence tier is a
        // separate axis, enforced at enrollment by
        // `TenzroNode::check_model_license`.
        //
        // This used to reject every NonCommercial entry outright, on the
        // reasoning that "nothing gated survives membership, so no entry is
        // NonCommercial". That inference is false: Hunyuan3D 2.1 is
        // ungated on the Hub and carries a non-commercial community
        // licence, so the two properties are simply independent. The rule
        // that matters is that a restrictive tier must be *acceptable* —
        // there has to be a way for an operator to opt in — otherwise the
        // entry is unservable by anyone and should not be listed.
        let l = licence(&e.id);
        match l.tier {
            LicenseTier::Permissive | LicenseTier::Attribution => {}
            LicenseTier::CommercialCustom => assert!(
                l.id.is_some(),
                "{} is CommercialCustom but its license '{}' has no \
                 acceptance id, so --accept-license could never admit it",
                e.id,
                l.name
            ),
            // Admissible, and opted into with `--accept-non-commercial`.
            // The flag is global rather than per-id, so unlike
            // CommercialCustom there is no acceptance id to map — the
            // requirement is only that the tier is labelled honestly, so
            // an operator is told what they are agreeing to.
            LicenseTier::NonCommercial => assert!(
                !l.name.is_empty(),
                "{} is NonCommercial but names no licence, so an operator \
                 accepting it would not know what they accepted",
                e.id
            ),
        }
        assert!(!e.kinds.is_empty(), "{} serves no MediaGenKind", e.id);
        assert!(e.pipeline_class.ends_with("Pipeline"), "{}", e.id);
        assert!(e.max_resolution >= e.default_width.max(e.default_height));
        let looked_up = get_media_gen_model_by_id(&e.id)
            .unwrap_or_else(|| panic!("{} missing from catalog lookup", e.id));
        assert_eq!(looked_up.hf_repo, e.hf_repo);
    }
    assert!(get_media_gen_model_by_id("not-a-real-id").is_none());
}

#[test]
fn test_media_gen_expert_pairs_are_the_two_a14b_entries() {
    let catalog = get_media_gen_catalog();
    let mut split: Vec<&str> = catalog
        .iter()
        .filter(|e| e.expert_pair.is_some())
        .map(|e| e.id.as_str())
        .collect();
    split.sort();
    assert_eq!(
        split,
        vec!["wan2.2-i2v-a14b", "wan2.2-t2v-a14b"],
        "only the Wan 2.2 A14B checkpoints ship two denoising experts"
    );
    for e in &catalog {
        let Some(ref pair) = e.expert_pair else {
            continue;
        };
        assert_ne!(pair.high_noise_component, pair.low_noise_component);
        assert!(
            pair.boundary_ratio > 0.0 && pair.boundary_ratio < 1.0,
            "{}: boundary must split the schedule",
            e.id
        );
        assert!(
            pair.min_vram_gb_per_expert < e.min_vram_gb,
            "{}: holding one expert must cost less than holding both",
            e.id
        );
    }
}

#[test]
fn test_media_gen_frame_grid_snaps_up_and_defaults_are_on_grid() {
    let ltx = get_media_gen_model_by_id("ltx-2.3-22b-distilled-gguf").expect("ltx entry");
    assert_eq!(ltx.temporal_stride(), 8);
    // 2s at 24fps is the case that shipped 41 frames against a 48-frame
    // bill before this snapped.
    assert_eq!(ltx.snap_num_frames(48), 49);
    assert_eq!(ltx.snap_num_frames(49), 49, "already on grid, unchanged");
    assert_eq!(ltx.snap_num_frames(50), 57);
    assert_eq!(ltx.snap_num_frames(1), 1);

    // An image entry has no temporal grid, so every count passes through.
    let img = get_media_gen_model_by_id("qwen-image-gguf").expect("image entry");
    assert_eq!(img.temporal_stride(), 1);
    assert_eq!(img.snap_num_frames(48), 48);

    // A default the catalog hands out must itself be representable, or the
    // no-`seconds` path reintroduces exactly the mismatch snapping fixes.
    for e in get_media_gen_catalog() {
        if let Some(frames) = e.default_num_frames {
            assert_eq!(
                e.snap_num_frames(frames),
                frames,
                "{}: default_num_frames {} is off its {}-frame grid",
                e.id,
                frames,
                e.temporal_stride()
            );
        }
    }
}

#[test]
fn test_media_gen_video_entries_carry_frame_defaults() {
    for e in get_media_gen_catalog() {
        let serves_video = e.kinds.iter().any(|k| k.is_video());
        assert_eq!(
            serves_video,
            e.default_num_frames.is_some() && e.default_fps.is_some(),
            "{}: frame/fps defaults must be present iff it serves a \
             video kind",
            e.id
        );
    }
}

#[test]
fn test_media_gen_kind_filter() {
    use tenzro_types::MediaGenKind;
    let t2v = get_media_gen_models_for_kind(MediaGenKind::Text2Video);
    assert!(
        t2v.iter()
            .all(|e| e.kinds.contains(&MediaGenKind::Text2Video))
    );
    assert!(t2v.iter().any(|e| e.id == "wan2.2-t2v-a14b"));
    // TI2V-5B is the one entry serving both video kinds.
    assert!(t2v.iter().any(|e| e.id == "wan2.2-ti2v-5b"));
    let i2v = get_media_gen_models_for_kind(MediaGenKind::Image2Video);
    assert!(i2v.iter().any(|e| e.id == "wan2.2-ti2v-5b"));
    let t2i = get_media_gen_models_for_kind(MediaGenKind::Text2Image);
    assert!(t2i.iter().any(|e| e.id == "qwen-image"));
    assert!(t2i.iter().all(|e| !e.kinds.iter().any(|k| k.is_video())));
}

// ── GGUF promotability / HF-resolvability verification ───────────
//
// The catalog is the single source of truth for which models we
// promote to users. Two failure modes have historically slipped in:
//   1. an entry points at a `hf_repo`/`hf_filename` that doesn't
//      exist on HuggingFace (sharded-path typos, dot-vs-dash quant
//      suffixes, renamed MTP drafts) — the user clicks download and
//      gets a 404.
//   2. an entry is left `promotable` even though its GGUF is gated
//      (HTTP 401) or simply not published yet.
//
// `test_promotable_entries_have_plausible_gguf_paths` runs offline
// on every `cargo test` and catches structural mistakes. The
// network-gated `verify_promotable_entries_resolve_on_hf` (marked
// `#[ignore]`) hits the HF API for every promotable entry and is the
// CI-able regression guard — run with
// `cargo test -p tenzro-model -- --ignored verify_promotable`.

/// Returns true if `name` looks like the first shard of a
/// gguf-split set (`...-00001-of-000NN.gguf`).
fn is_first_shard(name: &str) -> bool {
    name.contains("-00001-of-")
}

#[test]
fn test_promotable_entries_have_plausible_gguf_paths() {
    for entry in get_model_catalog() {
        // GGUF entries only (skip ONNX vision/audio/embedding).
        if !entry.hf_filename.ends_with(".gguf") {
            continue;
        }
        assert!(
            !entry.hf_repo.is_empty() && !entry.hf_filename.is_empty(),
            "{}: empty repo/filename",
            entry.id
        );
        // A filename that mentions a multi-part split MUST be the
        // first shard — llama.cpp only auto-continues from -00001-.
        if entry.hf_filename.contains("-of-") {
            assert!(
                is_first_shard(&entry.hf_filename),
                "{}: sharded filename must point at the first shard \
                 (-00001-of-...), got `{}`",
                entry.id,
                entry.hf_filename
            );
        }
        // No accidental leading slash / windows separators.
        assert!(
            !entry.hf_filename.starts_with('/') && !entry.hf_filename.contains('\\'),
            "{}: malformed hf_filename `{}`",
            entry.id,
            entry.hf_filename
        );
    }
}

#[test]
fn test_parse_params_active_b_prefers_active_over_total() {
    // MoE forms must yield the active path width, not the total.
    assert_eq!(parse_params_active_b("1T (MoE, 32B active)"), 32.0);
    assert_eq!(
        parse_params_active_b("2.8T total / 104B active (MoE)"),
        104.0
    );
    assert_eq!(parse_params_active_b("35B (MoE, 3B active)"), 3.0);
    assert_eq!(parse_params_active_b("397B (MoE, 17B active)"), 17.0);
    assert_eq!(parse_params_active_b("975B (MoE, 41B active)"), 41.0);
    assert_eq!(parse_params_active_b("118B (MoE, 8B active)"), 8.0);
    // Hyphenated MoE form.
    assert_eq!(parse_params_active_b("30B-A3B"), 3.0);
    // Dense.
    assert_eq!(parse_params_active_b("27B"), 27.0);
    assert_eq!(parse_params_active_b("0.8B"), 0.8);
}

#[test]
fn test_moe_entries_report_active_not_total_params() {
    for entry in get_model_catalog() {
        let Some(moe) = entry.moe.as_ref() else {
            continue;
        };
        let Some(per_expert_x10) = moe.params_per_expert_x10 else {
            continue;
        };
        let parsed = parse_params_active_b(&entry.parameters);
        if parsed == 0.0 {
            continue;
        }
        // Routed + shared experts alone are a lower bound on the
        // active path; attention and embeddings add to it. A parsed
        // figure below that bound means we read the total by mistake
        // or the shape is wrong.
        let expert_active_b = (per_expert_x10 as f32 / 10.0)
            * (moe.experts_per_token as f32 + moe.shared_experts as f32);
        assert!(
            parsed >= expert_active_b * 0.9,
            "{}: parsed active {}B is below the expert-only floor {}B \
             derived from its MoE shape",
            entry.id,
            parsed,
            expert_active_b
        );
    }
}

#[test]
fn test_gated_entries_are_explicitly_known() {
    // Keep the set of gated-out entries visible and intentional. If
    // a new entry is gated, add it here on purpose; if a gated entry
    // becomes downloadable, flip `promotable` and drop it here.
    let gated: Vec<String> = get_model_catalog()
        .into_iter()
        .filter(|e| !e.promotable)
        .map(|e| e.id)
        .collect();
    let mut gated_sorted = gated.clone();
    gated_sorted.sort();
    // embeddinggemma-2-gguf-f16: the model card says float16 gives NaN, so
    // that build is published for completeness and not promoted.
    let expected = vec![
        "deepseek-v4-pro".to_string(),
        "embeddinggemma-2-gguf-f16".to_string(),
    ];
    assert_eq!(
        gated_sorted, expected,
        "Gated-out set changed unexpectedly. Current gated: {:?}. \
         If intentional, update this test.",
        gated
    );
}

/// Network-gated: verifies every promotable GGUF entry resolves on
/// HuggingFace (repo exists AND the exact `hf_filename` is present).
/// Ignored by default so offline/`cargo test` stays hermetic; run in
/// CI with `--ignored`.
#[tokio::test]
#[ignore = "network: hits huggingface.co — run with --ignored in CI"]
async fn verify_promotable_entries_resolve_on_hf() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("tenzro-model-catalog-verify")
        .build()
        .expect("build http client");

    // Cache repo file-listings so we hit each repo once.
    let mut repo_files: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut failures: Vec<String> = Vec::new();

    for entry in get_model_catalog() {
        if !entry.promotable || !entry.hf_filename.ends_with(".gguf") {
            continue;
        }
        let files = if let Some(f) = repo_files.get(&entry.hf_repo) {
            f.clone()
        } else {
            let url = format!(
                "https://huggingface.co/api/models/{}?blobs=true",
                entry.hf_repo
            );
            let resp = client.get(&url).send().await;
            let files = match resp {
                Ok(r) if r.status().is_success() => {
                    let v: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
                    v.get("siblings")
                        .and_then(|s| s.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|s| {
                                    s.get("rfilename")
                                        .and_then(|n| n.as_str())
                                        .map(String::from)
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                }
                Ok(r) => {
                    failures.push(format!(
                        "{}: repo `{}` returned HTTP {}",
                        entry.id,
                        entry.hf_repo,
                        r.status()
                    ));
                    Vec::new()
                }
                Err(e) => {
                    failures.push(format!(
                        "{}: repo `{}` request error: {}",
                        entry.id, entry.hf_repo, e
                    ));
                    Vec::new()
                }
            };
            repo_files.insert(entry.hf_repo.clone(), files.clone());
            files
        };

        if !files.is_empty() && !files.iter().any(|f| f == &entry.hf_filename) {
            failures.push(format!(
                "{}: file `{}` not found in repo `{}`",
                entry.id, entry.hf_filename, entry.hf_repo
            ));
        }

        // Vision-capable entries must have their projector present too,
        // or image input silently degrades to text-only.
        if let Some(mmproj) = entry.mmproj.as_ref()
            && !files.is_empty()
            && !files.iter().any(|f| f == &mmproj.filename)
        {
            failures.push(format!(
                "{}: mmproj `{}` not found in repo `{}`",
                entry.id, mmproj.filename, entry.hf_repo
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} promotable catalog entries failed HF verification:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The GGUF verifier above covered only `get_model_catalog`, which is why
/// three D-FINE detection entries sat pointing at `.onnx` files that never
/// existed in `Peterande/D-FINE` (that repo publishes PyTorch `.pth`
/// only). The ONNX catalogs need the same check or the same drift recurs.
///
/// Network-gated for the same reason as its GGUF sibling.
#[tokio::test]
#[ignore = "network: hits huggingface.co — run with --ignored in CI"]
async fn verify_onnx_catalog_entries_resolve_on_hf() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("tenzro-model-catalog-verify")
        .build()
        .expect("build http client");

    // (catalog label, id, repo, filename) flattened across every ONNX
    // catalog, so adding a modality without adding it here is visible as
    // a missing label rather than as silent non-coverage.
    let mut entries: Vec<(&str, String, String, String)> = Vec::new();
    for e in get_detection_catalog() {
        entries.push(("detection", e.id, e.hf_repo, e.hf_filename));
    }
    for e in get_segmentation_catalog() {
        // Both halves: a missing decoder breaks segmentation exactly as
        // thoroughly as a missing encoder.
        entries.push((
            "segmentation-encoder",
            e.id.clone(),
            e.hf_repo.clone(),
            e.encoder_filename,
        ));
        entries.push(("segmentation-decoder", e.id, e.hf_repo, e.decoder_filename));
    }
    for e in get_vision_catalog() {
        entries.push(("vision", e.id, e.hf_repo, e.hf_filename));
    }
    for e in get_text_embedding_catalog() {
        entries.push(("text-embedding", e.id, e.hf_repo, e.hf_filename));
    }
    for e in get_forecast_catalog() {
        entries.push(("forecast", e.id, e.hf_repo, e.hf_filename));
    }

    let mut repo_files: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut failures: Vec<String> = Vec::new();

    for (kind, id, repo, filename) in entries {
        if filename.is_empty() {
            continue;
        }
        let files = if let Some(f) = repo_files.get(&repo) {
            f.clone()
        } else {
            let url = format!("https://huggingface.co/api/models/{repo}");
            let files = match client.get(&url).send().await {
                Ok(r) if r.status().is_success() => {
                    let v: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
                    v.get("siblings")
                        .and_then(|s| s.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|s| {
                                    s.get("rfilename")
                                        .and_then(|n| n.as_str())
                                        .map(String::from)
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                }
                Ok(r) => {
                    failures.push(format!(
                        "{kind}/{id}: repo `{repo}` returned HTTP {}",
                        r.status()
                    ));
                    Vec::new()
                }
                Err(e) => {
                    failures.push(format!("{kind}/{id}: repo `{repo}` request error: {e}"));
                    Vec::new()
                }
            };
            repo_files.insert(repo.clone(), files.clone());
            files
        };

        if !files.is_empty() && !files.iter().any(|f| f == &filename) {
            failures.push(format!(
                "{kind}/{id}: file `{filename}` not found in repo `{repo}`"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "ONNX catalog entries that do not resolve on HuggingFace:\n  {}",
        failures.join("\n  ")
    );
}

/// Janus-Pro writes images as tokens of its backbone: native, one step per
/// token of its 24x24 grid, under the DeepSeek model licence. TRELLIS.2 is
/// native on its 512 path and gated by the licence of its image encoder,
/// stricter than the MIT of its own weights. HunyuanImage 3.0 is listed for
/// a large host only and stays planned.
#[test]
fn unified_image_and_3d_entries_record_how_they_are_served() {
    let janus = get_media_gen_model_by_id("janus-pro-1b").expect("catalogued");
    assert!(runnable_media_gen_model("janus-pro-1b").is_ok());
    assert_eq!(janus.default_steps, 24 * 24);
    assert_eq!((janus.default_width, janus.default_height), (384, 384));
    assert_eq!(
        licence("janus-pro-1b").id.as_deref(),
        Some("deepseek-model")
    );

    let trellis = get_media_gen_model_by_id("trellis2-4b").expect("catalogued");
    assert!(runnable_media_gen_model("trellis2-4b").is_ok());
    assert_eq!(trellis.kinds, [tenzro_types::MediaGenKind::Image23d]);
    assert_eq!(trellis.default_voxel_resolution, Some(512));
    let e = entry("trellis2-4b").expect("catalogued");
    assert!(e.gated);
    assert_eq!(e.licence.tier, LicenseTier::Permissive);
    assert_eq!(e.licence.effective_tier(), LicenseTier::CommercialCustom);
    assert_eq!(e.gating_licence(), Some("dinov3"));

    let hy3 = get_media_gen_model_by_id("hunyuan-image-3.0").expect("catalogued");
    assert!(runnable_media_gen_model("hunyuan-image-3.0").is_err());
    assert!(hy3.min_vram_gb > 80, "not servable from one consumer GPU");
    assert!(
        hy3.description.contains("large host"),
        "{}",
        hy3.description
    );
    let grant = license_territory(licence("hunyuan-image-3.0").id.as_deref().unwrap())
        .expect("territorial grant");
    for t in ["EU", "GB", "KR"] {
        assert!(grant.excluded.iter().any(|x| x == t), "{t}");
    }
}

/// A planned media model stays listed and every use of it is refused.
#[test]
fn planned_media_models_are_listed_and_refused() {
    let planned: Vec<_> = get_media_gen_catalog()
        .into_iter()
        .filter(|e| e.status == MediaGenStatus::Planned)
        .collect();
    assert!(!planned.is_empty());
    for e in &planned {
        let err = runnable_media_gen_model(&e.id).expect_err("a planned model is refused");
        assert!(err.ends_with(MEDIA_PLANNED_REFUSAL), "{err}");
    }
    assert!(runnable_media_gen_model("flux2-klein-4b").is_ok());
}

#[test]
fn every_entry_names_the_units_it_is_billed_on() {
    seeded();
    let registered: std::collections::BTreeMap<String, bool> = tenzro_types::meter::genesis_units()
        .into_iter()
        .map(|u| (u.id, u.billable))
        .collect();
    for entry in store::current().entries() {
        let billed = entry.model.billed_on();
        assert!(!billed.is_empty(), "{} names no billable unit", entry.id());
        for unit in billed {
            assert_eq!(
                registered.get(*unit),
                Some(&true),
                "{}: {unit} is not a registered billable unit",
                entry.id()
            );
        }
        let expected: Option<&[&str]> = match entry.model.engine() {
            "onnx-forecast" => Some(&["forecast_points"]),
            "rerank" => Some(&["rerank_pairs"]),
            "decision" => Some(&["decision_questions"]),
            "onnx-text-embedding" | "embed" => Some(&["input_tokens"]),
            _ => None,
        };
        if let Some(expected) = expected {
            assert_eq!(billed, expected, "{}", entry.id());
        }
    }
}

/// A model whose parts are under different licences takes the most
/// restrictive tier of them, and lists every licence's conditions.
#[test]
fn component_licences_bind_the_whole_model() {
    let ltx = entry("ltx-2.3-22b-dev").expect("catalogued");
    let parts = ltx.licence.parts();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].id, Some("ltx-open-weights"));
    assert_eq!(
        (parts[1].covers, parts[1].id),
        (Some("text encoder (Gemma 3)"), Some("gemma"))
    );
    assert_eq!(ltx.licence.effective_tier(), LicenseTier::CommercialCustom);
    assert!(permits_paid_use("ltx-2.3-22b-dev"));
    let conditions = ltx.licence.all_conditions().expect("conditions recorded");
    assert!(
        conditions.contains("USD 10,000,000") && conditions.contains("Gemma Prohibited Use Policy"),
        "{conditions}"
    );

    // A non-commercial part makes the whole model non-commercial.
    let mut mixed = ltx.licence.clone();
    mixed.components.push(tenzro_catalog::ComponentLicence {
        covers: "vae".into(),
        name: "Research Only".into(),
        id: None,
        tier: LicenseTier::NonCommercial,
        conditions: None,
    });
    assert_eq!(mixed.effective_tier(), LicenseTier::NonCommercial);
    assert_eq!(mixed.governing().covers, Some("vae"));
    assert!(!mixed.effective_tier().permits_paid_use());
}

// ---------------------------------------------------------------------------
// Nemotron hybrid line, Nemotron 3.5 Bolt, EmbeddingGemma 2
// ---------------------------------------------------------------------------

fn nemotron_h_entries() -> Vec<HfModelEntry> {
    get_model_catalog()
        .into_iter()
        .filter(|e| e.architecture == ModelArchitecture::NemotronH)
        .collect()
}

/// Every Nemotron-H GGUF (Nano, Super, Ultra, Cascade, Lightning, Omni, Bolt)
/// carries the hybrid label: the Mamba-2 plus MoE plus attention layer mix is
/// one architecture to the planner, whatever the size.
#[test]
fn the_hybrid_nemotron_models_share_one_architecture_label() {
    let ids: Vec<String> = nemotron_h_entries().into_iter().map(|e| e.id).collect();
    for id in [
        "nemotron-nano-4b",
        "nemotron-nano-30b-a3b",
        "nemotron-3.5-lightning-30b-a3b",
        "nemotron-3-super-120b-a12b",
        "nemotron-cascade-2-30b-a3b",
        "nemotron-3-nano-omni-30b-a3b",
        "nemotron-3-ultra-550b-a55b",
        "nemotron-3.5-bolt-74b-a9b",
    ] {
        assert!(
            ids.iter().any(|i| i == id),
            "{id} must be labelled nemotronh"
        );
    }
    assert_eq!(
        ModelArchitecture::NemotronH.engine_architectures().unwrap(),
        &["nemotron_h", "nemotron_h_moe"]
    );
    // No second label names the same GGUF architecture.
    assert!(
        !ModelArchitecture::Llama
            .engine_architectures()
            .unwrap()
            .contains(&"nemotron_h_moe")
    );
}

/// Nemotron 3 Ultra: every quantisation the registry repository publishes is
/// an entry, each pinned to all of its shards, under the licence the model
/// card names, with the card's sampling and no draft head (the GGUF carries
/// no multi-token-prediction tensors).
#[test]
fn nemotron_3_ultra_covers_every_published_quantisation() {
    let base = get_model_by_id("nemotron-3-ultra-550b-a55b").expect("base");
    assert_eq!(base.context_length, 1_048_576);
    assert_eq!(base.quantization, "UD-Q4_K_XL");
    assert_eq!(base.drafter_id, None);
    assert_eq!(base.mtp_kind, MtpKind::None);
    assert_eq!(base.serving.temperature, 1.0);
    assert!((base.serving.top_p - 0.95).abs() < 1e-6);
    let moe = base.moe.expect("routed experts are declared");
    assert_eq!((moe.num_experts, moe.experts_per_token), (512, 22));
    assert_eq!(
        license_tier_of("nemotron-3-ultra-550b-a55b"),
        Some(LicenseTier::Permissive)
    );
    let quants = [
        "BF16",
        "Q8_0",
        "UD-Q8_K_XL",
        "UD-Q6_K_XL",
        "UD-Q6_K",
        "UD-Q5_K_XL",
        "UD-Q5_K_M",
        "UD-Q5_K_S",
        "MXFP4_MOE",
        "UD-Q4_K_XL",
        "UD-Q4_K_M",
        "UD-Q4_K_S",
        "UD-IQ4_NL",
        "UD-IQ4_XS",
        "UD-Q3_K_XL",
        "UD-Q3_K_M",
        "UD-IQ3_S",
        "UD-IQ3_XXS",
        "UD-Q2_K_XL",
        "UD-IQ2_M",
        "UD-IQ2_XXS",
        "UD-IQ1_M",
    ];
    let all: Vec<HfModelEntry> = get_model_catalog()
        .into_iter()
        .filter(|e| e.id.starts_with("nemotron-3-ultra-550b-a55b"))
        .collect();
    assert_eq!(all.len(), quants.len());
    for q in quants {
        let e = all
            .iter()
            .find(|e| e.quantization == q)
            .unwrap_or_else(|| panic!("no Ultra entry at {q}"));
        // The entry file is the first shard and the shard set is complete.
        let en = entry(&e.id).expect("entry");
        let of = e.hf_filename.rsplit("-of-").next().unwrap();
        let total: usize = of.trim_end_matches(".gguf").parse().unwrap();
        assert_eq!(en.components.len(), total, "{} shards", e.id);
        assert!(e.hf_filename.contains("-00001-of-"), "{}", e.id);
        assert_eq!(
            e.size_bytes,
            en.components.iter().map(|c| c.size).sum::<u64>(),
            "{} size is the sum of its shards",
            e.id
        );
        assert!(!e.hardware_tiers.is_empty(), "{} has placement tiers", e.id);
    }
    // The smallest build (1-bit class, about 188 GB) needs no single node of
    // 128 GB: its tiers say two nodes of 128 GB, which is metadata, not a gate.
    let smallest = get_model_by_id("nemotron-3-ultra-550b-a55b-ud-iq1-m").unwrap();
    assert!(smallest.size_bytes > 180_000_000_000 && smallest.size_bytes < 200_000_000_000);
    assert!(
        smallest
            .hardware_tiers
            .iter()
            .any(|t| t.nodes == 2 && t.memory_gb_per_node == 128)
    );
    assert!(smallest.promotable);
}

/// Nemotron 3.5 Bolt E4B (Gemma 4 architecture) and 74B-A9B (hybrid MoE):
/// the facts NVIDIA's cards give, the vision projector, and the draft models
/// they pair with.
#[test]
fn nemotron_bolt_models_are_wired_with_their_projectors_and_drafters() {
    let e4b = get_model_by_id("nemotron-3.5-bolt-e4b").expect("e4b");
    assert_eq!(e4b.architecture, ModelArchitecture::Gemma4);
    assert_eq!(e4b.context_length, 65_536);
    assert!(e4b.mmproj.is_some());
    assert_eq!(
        e4b.drafter_id.as_deref(),
        Some("nemotron-3.5-bolt-e4b-dflash")
    );
    assert_eq!(e4b.mtp_kind, MtpKind::DraftDflash);
    assert!((e4b.serving.top_p - 0.95).abs() < 1e-6);
    let big = get_model_by_id("nemotron-3.5-bolt-74b-a9b").expect("74b");
    assert_eq!(big.architecture, ModelArchitecture::NemotronH);
    assert_eq!(big.context_length, 262_144);
    assert!(big.mmproj.is_some());
    assert_eq!(
        big.drafter_id.as_deref(),
        Some("nemotron-3.5-bolt-74b-a9b-lilicorr")
    );
    let moe = big.moe.expect("moe");
    assert_eq!((moe.num_experts, moe.experts_per_token), (496, 9));
    // The 24 GB build the vendor ships is about 22 GB of weights.
    assert!(big.size_bytes > 22_000_000_000 && big.size_bytes < 25_000_000_000);
    // Every quantisation variant keeps the same drafter and projector wiring.
    let variants: Vec<HfModelEntry> = get_model_catalog()
        .into_iter()
        .filter(|e| e.id.starts_with("nemotron-3.5-bolt-74b-a9b-") && !e.id.ends_with("lilicorr"))
        .collect();
    assert!(variants.len() >= 13);
    for v in variants {
        assert!(v.mmproj.is_some() && v.drafter_id.is_some(), "{}", v.id);
        assert_eq!(v.context_length, 262_144);
    }
    // The drafters are models the target loads beside itself, not standalone.
    for d in [
        "nemotron-3.5-bolt-e4b-dflash",
        "nemotron-3.5-bolt-74b-a9b-lilicorr",
    ] {
        let e = get_model_by_id(d).expect(d);
        assert_eq!(e.drafter_id, None);
        assert!(e.size_bytes < 1_000_000_000);
    }
}

/// The reasoning-effort switches the model cards document.
#[test]
fn nemotron_and_mistral_large_effort_switches_resolve() {
    assert_eq!(
        resolve_reasoning_effort("nemotron-3-ultra-550b-a55b", Some("medium")),
        Some(("medium_effort".to_string(), "medium".to_string()))
    );
    // `high` is the template default for Nemotron: nothing is set.
    assert_eq!(
        resolve_reasoning_effort("nemotron-3-ultra-550b-a55b", Some("high")),
        None
    );
    assert_eq!(
        EffortPolicy::for_family("mistral-large").levels,
        vec!["low", "medium", "high"]
    );
}

/// EmbeddingGemma 2: text embeddings at 768 truncated to 512/256/128, 8,192
/// tokens, Apache 2.0, Gemma task prompts; the GGUF builds are pinned by
/// quantisation and the half-precision one is not promoted (NaN).
#[test]
fn embeddinggemma_2_is_registered_as_onnx_and_gguf() {
    let o = get_text_embedding_model_by_id("embeddinggemma-2").expect("onnx entry");
    assert_eq!(o.embedding_dim, 768);
    assert_eq!(o.matryoshka_dims, vec![512, 256, 128]);
    assert_eq!(o.max_sequence_length, 8192);
    assert!(!o.supports_fp16);
    assert_eq!(
        license_tier_of("embeddinggemma-2"),
        Some(LicenseTier::Permissive)
    );
    let g = get_model_by_id("embeddinggemma-2-gguf").expect("gguf entry");
    assert_eq!(g.architecture, ModelArchitecture::GemmaEmbedding2);
    assert_eq!(g.quantization, "UD-Q4_K_XL");
    assert!(g.size_bytes < 250_000_000);
    let f16 = get_model_by_id("embeddinggemma-2-gguf-f16").expect("f16");
    assert!(!f16.promotable, "float16 gives NaN on this model");
    assert!(
        get_model_by_id("embeddinggemma-2-gguf-bf16")
            .unwrap()
            .promotable
    );
}

/// Mistral Large 4: every published quantisation, loadable by the engine,
/// served free of charge only (the licence makes serving third parties a
/// Model-as-a-Service business that needs a separate Mistral licence).
#[test]
fn mistral_large_4_is_published_and_licence_restricted() {
    assert_eq!(
        ModelArchitecture::MistralLarge4
            .engine_architectures()
            .unwrap(),
        &["mistral-large4"]
    );
    let base = get_model_by_id("mistral-large-4").expect("base");
    assert_eq!(base.context_length, 1_048_576);
    assert_eq!(base.quantization, "UD-Q4_K_XL");
    assert!(base.mmproj.is_some());
    let moe = base.moe.expect("moe");
    assert_eq!((moe.num_experts, moe.experts_per_token), (128, 4));
    assert!((base.serving.top_p - 0.95).abs() < 1e-6);
    assert_eq!(
        license_tier_of("mistral-large-4"),
        Some(LicenseTier::NonCommercial)
    );
    assert!(!permits_paid_use("mistral-large-4"));
    let all: Vec<HfModelEntry> = get_model_catalog()
        .into_iter()
        .filter(|e| e.id.starts_with("mistral-large-4") && !e.id.contains("dspark"))
        .collect();
    assert_eq!(all.len(), 11);
    for e in &all {
        assert_eq!(
            e.drafter_id.as_deref(),
            Some("mistral-large-4-dspark"),
            "{}",
            e.id
        );
        assert_eq!(e.mtp_default_draft_n, Some(3), "{}", e.id);
    }
    for q in [
        "BF16",
        "Q8_0",
        "UD-Q6_K_XL",
        "UD-Q5_K_XL",
        "UD-Q4_K_XL",
        "UD-Q3_K_XL",
        "UD-IQ3_XXS",
        "UD-Q2_K_XL",
        "UD-IQ2_XXS",
        "UD-IQ1_M",
        "UD-IQ1_S",
    ] {
        let e = all
            .iter()
            .find(|e| e.quantization == q)
            .unwrap_or_else(|| panic!("{q}"));
        assert!(e.promotable, "{}", e.id);
        assert!(
            e.hardware_tiers.iter().any(|t| t.nodes > 1),
            "{} is a cluster-tier model",
            e.id
        );
    }
    // The smallest build is the 233 GB one named in the registry repository.
    let smallest = get_model_by_id("mistral-large-4-ud-iq1-s").unwrap();
    assert!(smallest.size_bytes > 230_000_000_000 && smallest.size_bytes < 245_000_000_000);
    assert_eq!(
        resolve_reasoning_effort("mistral-large-4", Some("medium")),
        Some(("reasoning_effort".to_string(), "medium".to_string()))
    );
}

/// The DSpark drafters of Mistral Large 4: small files that keep the dspark
/// prefix the runtime keys the algorithm on, inheriting the target's licence.
#[test]
fn mistral_large_4_dspark_drafters_are_registered() {
    for (id, quant) in [
        ("mistral-large-4-dspark", "Q8_0"),
        ("mistral-large-4-dspark-bf16", "BF16"),
    ] {
        let e = get_model_by_id(id).unwrap_or_else(|| panic!("{id}"));
        assert_eq!(e.quantization, quant);
        assert!(
            e.hf_filename
                .rsplit('/')
                .next()
                .unwrap()
                .starts_with("dspark-"),
            "the runtime picks DSpark from the file name: {}",
            e.hf_filename
        );
        assert!(e.size_bytes > 2_000_000_000 && e.size_bytes < 5_000_000_000);
        assert_eq!(license_tier_of(id), Some(LicenseTier::NonCommercial));
    }
}

/// NVIDIA's own Q4_K_M release of Bolt E4B is its own entry beside the
/// unsloth builds, with the vendor's DFlash drafter.
#[test]
fn nemotron_bolt_e4b_4gb_vendor_build_is_registered() {
    let e = get_model_by_id("nemotron-3.5-bolt-e4b-4gb").expect("entry");
    assert_eq!(e.hf_repo, "nvidia/NVIDIA-Nemotron-3.5-Bolt-E4B-4GB");
    assert_eq!(e.hf_filename, "Nemotron-3.5-Bolt-E4B-Q4_K_M.gguf");
    assert_eq!(e.quantization, "Q4_K_M");
    assert_eq!(e.size_bytes, 6_180_446_208);
    assert_eq!(e.context_length, 65_536);
    assert!(
        e.mmproj.is_none(),
        "the vendor repository ships no projector"
    );
    assert_eq!(
        e.drafter_id.as_deref(),
        Some("nemotron-3.5-bolt-e4b-dflash")
    );
    assert_eq!(license_tier_of(&e.id), Some(LicenseTier::Permissive));
}

/// A third-party fine-tune: Apache 2.0 in the author's repository, GGUF and
/// projector pinned by SHA-256 at the upstream revision, code capability.
#[test]
fn qwen35_3d_coder_third_party_fine_tune_is_registered() {
    for (id, quant) in [
        ("qwen3.5-4b-3d-coder", "Q4_K_M"),
        ("qwen3.5-4b-3d-coder-q8-0", "Q8_0"),
    ] {
        let e = get_model_by_id(id).unwrap_or_else(|| panic!("{id}"));
        assert_eq!(e.hf_repo, "ccore/Qwen3.5-4B-3D-Coder");
        assert_eq!(e.quantization, quant);
        assert_eq!(e.architecture, ModelArchitecture::Qwen35);
        assert_eq!(
            e.mmproj.as_ref().unwrap().filename,
            "mmproj-Qwen3.5-4B-BF16.gguf"
        );
        assert_eq!(license_tier_of(id), Some(LicenseTier::Permissive));
    }
    let entry = read_entries(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seed"))
        .unwrap()
        .into_iter()
        .find(|e| e.id() == "qwen3.5-4b-3d-coder")
        .unwrap();
    assert!(entry.capabilities.iter().any(|c| c == "code"));
    assert_eq!(entry.components.len(), 2);
    for c in &entry.components {
        assert_eq!(
            c.revision(),
            Some("196c03ff49d8d99f49235ad19c7d48f940bc7523")
        );
    }
}

/// The November 2026 leaderboard additions: each is pinned at the upstream
/// GGUF revision, carries its licence tier, and names an architecture the
/// engine loads.
#[test]
fn november_2026_survey_models_are_registered() {
    for (id, repo, arch, tier) in [
        (
            "glm-5.3",
            "unsloth/GLM-5.3-GGUF",
            ModelArchitecture::Glm,
            LicenseTier::CommercialCustom,
        ),
        (
            "glm-5.3-flash",
            "unsloth/GLM-5.3-Flash-GGUF",
            ModelArchitecture::Glm,
            LicenseTier::Permissive,
        ),
        (
            "deepseek-v4.1-flash-1017",
            "unsloth/DeepSeek-V4.1-Flash-1017-GGUF",
            ModelArchitecture::DeepSeekV3,
            LicenseTier::Permissive,
        ),
        (
            "minimax-m3.1-flash",
            "unsloth/MiniMax-M3.1-Flash-GGUF",
            ModelArchitecture::MiniMax,
            LicenseTier::CommercialCustom,
        ),
        (
            "beam-1.0",
            "unsloth/Beam-1.0-501B-A23B-GGUF",
            ModelArchitecture::Beam,
            LicenseTier::Permissive,
        ),
        (
            "glm-ocr",
            "ggml-org/GLM-OCR-GGUF",
            ModelArchitecture::Glm,
            LicenseTier::Permissive,
        ),
        (
            "flint",
            "unsloth/flint-GGUF",
            ModelArchitecture::Flint,
            LicenseTier::Permissive,
        ),
        (
            "spark-x2.6-4b",
            "XHToken/Spark-X2.6-4B-GGUF",
            ModelArchitecture::Spark25,
            LicenseTier::Permissive,
        ),
        (
            "sage-a1.5",
            "InternScience/Sage-A1.5-Q4_K_M-GGUF",
            ModelArchitecture::Qwen35Moe,
            LicenseTier::Permissive,
        ),
    ] {
        let e = get_model_by_id(id).unwrap_or_else(|| panic!("{id}"));
        assert_eq!(e.hf_repo, repo, "{id}");
        assert_eq!(e.architecture, arch, "{id}");
        assert_eq!(license_tier_of(id), Some(tier), "{id}");
        assert!(e.promotable, "{id}");
    }
    assert_eq!(
        ModelArchitecture::Beam.engine_architectures().unwrap(),
        &["beam"]
    );
    assert!(
        ModelArchitecture::Glm
            .engine_architectures()
            .unwrap()
            .contains(&"glm5-next")
    );
    assert!(
        ModelArchitecture::DeepSeekV3
            .engine_architectures()
            .unwrap()
            .contains(&"deepseek41")
    );
    // Every ladder build ends in a named quantisation and DSpark drafters keep their prefix.
    for id in [
        "deepseek-v4.1-flash-1017-dspark",
        "minimax-m3.1-flash-dspark",
    ] {
        let e = get_model_by_id(id).unwrap_or_else(|| panic!("{id}"));
        assert!(e.hf_filename.starts_with("dspark-"), "{id}");
    }
    assert!(
        get_model_by_id("spark-x2.6-4b-dspark")
            .unwrap()
            .hf_filename
            .contains("DSpark")
    );
    assert_eq!(get_model_by_id("flint").unwrap().quantization, "UD-Q4_K_XL");
    assert!(get_model_by_id("sage-a1.5").unwrap().mmproj.is_some());
    assert_eq!(
        get_model_by_id("deepseek-v4.1-flash-1017")
            .unwrap()
            .drafter_id
            .as_deref(),
        Some("deepseek-v4.1-flash-1017-dspark")
    );
    let glm: Vec<_> = get_model_catalog()
        .into_iter()
        .filter(|e| e.id.starts_with("glm-5.3-flash"))
        .collect();
    assert_eq!(glm.len(), 12);
}

/// Laya, ConvAI Innovations' decision models: Apache 2.0, served only as
/// decision models. The English checkpoint is the Hub file the registry hashes;
/// the multilingual and typed-decisions checkpoints have no engine-layout GGUF on
/// the Hub, so they are network files rebuilt from the upstream checkpoint by
/// the in-tree recipe and pinned by SHA-256 and BLAKE3.
#[test]
fn laya_is_pinned_as_decision_models() {
    let catalog = get_decision_catalog();
    assert_eq!(catalog.len(), 4);
    for e in &catalog {
        assert_eq!(e.architecture, ModelArchitecture::ModernBert);
        assert_eq!(e.family, "laya");
        assert!(
            get_model_by_id(&e.id).is_none(),
            "{} is no chat model",
            e.id
        );
        assert_eq!(license_tier_of(&e.id), Some(LicenseTier::Permissive));
        let en = entry(&e.id).unwrap();
        assert_eq!(en.model.engine(), "decision");
        assert_eq!(en.model.billed_on(), &["decision_questions"]);
        assert_eq!(en.components.len(), 1);
        assert_eq!(en.components[0].size, e.size_bytes);
    }
    for id in ["laya", "laya-bf16"] {
        let e = get_decision_model_by_id(id).unwrap();
        assert_eq!(e.context_length, 512);
        assert!(e.hf_repo.starts_with("ggml-org/"));
    }
    for id in ["laya-multilingual", "laya-typed-decisions"] {
        let e = get_decision_model_by_id(id).unwrap();
        assert_eq!(e.context_length, 1024);
        // The multilingual model ships in BF16: its 8-bit build moved a near-tie
        // answer by 0.13 against the reference implementation.
        assert_eq!(
            e.quantization,
            if id == "laya-multilingual" {
                "BF16"
            } else {
                "Q8_0"
            }
        );
        assert!(
            e.description.contains("tools/gguf-export/convert.sh"),
            "{id}"
        );
        assert!(e.description.contains("Apache-2.0"), "{id}");
        let c = &entry(id).unwrap().components[0];
        match &c.source {
            Source::Network {
                blake3,
                built_from,
                recipe,
            } => {
                assert_eq!(blake3.len(), 64, "{id}");
                assert_eq!(built_from.revision.len(), 40, "{id}");
                assert!(
                    built_from.repo.starts_with("convaiinnovations/laya"),
                    "{id}"
                );
                assert_eq!(recipe, "tools/gguf-export/convert.sh");
            }
            other => panic!("{id}: {other:?} is not a rebuilt network file"),
        }
    }
    assert_eq!(
        get_decision_model_by_id("laya").unwrap().quantization,
        "Q8_0"
    );
    assert_eq!(
        ModelArchitecture::ModernBert
            .engine_architectures()
            .unwrap(),
        &["modern-bert"]
    );
}
