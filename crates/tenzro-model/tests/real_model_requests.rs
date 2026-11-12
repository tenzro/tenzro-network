//! Real weights through the node's own request path.
//!
//! `#[ignore]`-style: nothing runs unless a scenario is named, because every
//! scenario fetches a registry model through the node's downloader
//! (`HfDownloader`, which writes only the files the catalog hashes) and runs
//! it on the CPU. This binary is also the model parser's confinement
//! launcher (a model file is parsed in a child process first), so it has its
//! own `main`.
//!
//!   TENZRO_MODELS_DIR=/path/to/models TENZRO_REAL_SCENARIOS=long,audio,video,decision \
//!     cargo test --release -p tenzro-model --test real_model_requests
//!
//! Scenarios:
//! * `long`: a 32K-token prompt with a fact placed early and another in the
//!   middle on `nemotron-3.5-bolt-e4b`; both must be retrieved (the model
//!   keeps a 64K window; the hybrid and sliding-window layers must hold it);
//! * `audio`: a recorded tone through the projector's audio tower on
//!   `nemotron-3.5-bolt-e4b`; the request must be served and the attachment
//!   must cost prompt tokens;
//! * `video`: four consecutive frames of a moving square as a video on
//!   `nemotron-3.5-bolt-74b-a9b`; same checks;
//! * `video-engine`: the same video request on a model above the CPU tier
//!   (the node's runtime refuses a GPU-tier model on a CPU build, as it
//!   should), served by the batch engine the runtime drives, with the
//!   projector, on the CPU;
//! * `latent`: one Latent MoE layer of the real Nemotron 3.5 Bolt 74B-A9B
//!   checkpoint (router, latent projections, shared expert and the experts
//!   its tokens select, read from the safetensors by ranged requests) run
//!   through the expert runtime the way `tenzro_moeForward` runs it, and
//!   compared with the layer function;
//! * `fetch`: only fetch the registry models named in `TENZRO_FETCH_IDS`
//!   (comma separated) through the downloader, so a long download can run
//!   before the build that uses the model;
//! * `decision-file`: a decision model file named by `LAYA_GGUF` (context
//!   `LAYA_CTX`) answers the questions of `LAYA_CASES` through the decision
//!   runtime and writes them to `LAYA_OUT`, to be compared with the
//!   reference implementation's answers to the same cases;
//! * `decision`: Laya answers a yes/no, a choice and a score through the
//!   decision runtime.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use tenzro_model::{
    ChatMessage, DownloadProgress, DownloadState, GenerationConfig, HfDownloader, ModelRuntime,
    SourcePolicy, get_decision_model_by_id, get_model_by_id,
};

fn main() {
    tenzro_model::parse_jail::enter_if_requested();
    let Ok(wanted) = std::env::var("TENZRO_REAL_SCENARIOS") else {
        println!(
            "real_model_requests: skipped (set TENZRO_REAL_SCENARIOS=long,audio,video,decision)"
        );
        return;
    };
    let models = std::env::var("TENZRO_MODELS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
                .join(".tenzro/models")
        });
    std::fs::create_dir_all(&models).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut failed = 0;
    for name in wanted.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let started = Instant::now();
        let outcome = rt.block_on(tenzro_model::access::as_node(async {
            match name {
                "long" => long_context(&models).await,
                "audio" => audio(&models).await,
                "video" => video(&models).await,
                "video-engine" => video_engine(&models).await,
                "latent" => latent_real().await,
                "fetch" => fetch_all(&models).await,
                "decision-file" => decision_file().await,
                "decision" => decision(&models).await,
                other => Err(format!("unknown scenario {other}")),
            }
        }));
        match outcome {
            Ok(note) => println!(
                "PASS {name} ({:.0} s): {note}",
                started.elapsed().as_secs_f64()
            ),
            Err(why) => {
                failed += 1;
                println!("FAIL {name}: {why}");
            }
        }
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

/// Fetch a registry model (and its projector) through the node's downloader.
async fn fetch(dir: &Path, id: &str) -> Result<PathBuf, String> {
    tenzro_catalog::install_test_seed();
    let entry = get_model_by_id(id)
        .or_else(|| get_decision_model_by_id(id))
        .ok_or_else(|| format!("{id} is not in the catalog"))?;
    let downloader = HfDownloader::new(dir.to_path_buf());
    if downloader.is_downloaded(id)
        && (entry.mmproj.is_none() || downloader.mmproj_path(id).exists())
    {
        return Ok(downloader.model_path(id));
    }
    let (tx, _rx) = tokio::sync::watch::channel(DownloadProgress {
        model_id: id.to_string(),
        status: DownloadState::Pending,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: entry.size_bytes,
    });
    downloader
        .download_model(&entry, None, SourcePolicy::HuggingFace, tx)
        .await
        .map_err(|e| format!("download {id}: {e}"))
}

fn greedy(max_tokens: u32) -> GenerationConfig {
    GenerationConfig {
        temperature: 0.0,
        top_k: Some(1),
        repeat_penalty: 1.0,
        repeat_last_n: 0,
        max_tokens,
        seed: 7,
        enable_thinking: Some(false),
        ..Default::default()
    }
}

fn user(text: &str) -> ChatMessage {
    ChatMessage {
        role: "user".into(),
        content: text.into(),
        ..Default::default()
    }
}

/// A prompt of about `target_tokens` tokens of varied sentences with two facts
/// in it: one near the start, one in the middle.
fn needle_prompt(target_tokens: usize) -> String {
    let mut s = String::from(
        "Read the following notes carefully; questions about them follow at the end.\n\
         Note 0: the access phrase for the east vault is OLIVE-TRUMPET-7413.\n",
    );
    let mut i = 1;
    let mut tokens = 30;
    while tokens < target_tokens {
        s.push_str(&format!(
            "Note {i}: the delivery on route {} carried {} crates of item {} to depot {}.\n",
            (i * 37) % 211,
            (i * 13) % 97 + 3,
            (i * 53) % 1009,
            (i * 29) % 61
        ));
        tokens += 30;
        if tokens >= target_tokens / 2 && !s.contains("MARBLE-HARBOR") {
            s.push_str(&format!(
                "Note {i}b: the access phrase for the west vault is MARBLE-HARBOR-2958.\n"
            ));
            tokens += 25;
        }
        i += 1;
    }
    s.push_str(
        "\nQuestion: what are the access phrases for the east vault and the west vault? \
         Answer with the two phrases only.",
    );
    s
}

async fn long_context(dir: &Path) -> Result<String, String> {
    const ID: &str = "nemotron-3.5-bolt-e4b";
    let path = fetch(dir, ID).await?;
    let rt = Arc::new(ModelRuntime::new().map_err(|e| e.to_string())?);
    rt.load_model_with_context(ID, &path, Some(40_960))
        .await
        .map_err(|e| format!("load: {e}"))?;
    let prompt = needle_prompt(31_000);
    let r = rt
        .generate_chat(ID, &[user(&prompt)], &greedy(40))
        .await
        .map_err(|e| format!("generate: {e}"))?;
    if r.input_tokens < 24_000 {
        return Err(format!("the prompt was only {} tokens", r.input_tokens));
    }
    let answer = r.text.to_ascii_uppercase();
    if !answer.contains("OLIVE-TRUMPET-7413") || !answer.contains("MARBLE-HARBOR-2958") {
        return Err(format!(
            "the facts were not retrieved from {} tokens of context: {:?}",
            r.input_tokens, r.text
        ));
    }
    Ok(format!(
        "{} prompt tokens, both facts retrieved ({:.1} tok/s decode): {:?}",
        r.input_tokens, r.tokens_per_second, r.text
    ))
}

/// 16 kHz mono 16-bit WAV of `secs` seconds of a tone that steps up in pitch.
fn tone_wav(secs: u32) -> Vec<u8> {
    let rate = 16_000u32;
    let n = rate * secs;
    let mut pcm = Vec::with_capacity(n as usize * 2);
    for i in 0..n {
        let t = i as f32 / rate as f32;
        let f = if t < secs as f32 / 2.0 { 440.0 } else { 880.0 };
        let v = (f32::sin(2.0 * std::f32::consts::PI * f * t) * 0.4 * i16::MAX as f32) as i16;
        pcm.extend_from_slice(&v.to_le_bytes());
    }
    let mut wav = Vec::new();
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + pcm.len() as u32).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes());
    wav.extend_from_slice(&rate.to_le_bytes());
    wav.extend_from_slice(&(rate * 2).to_le_bytes());
    wav.extend_from_slice(&2u16.to_le_bytes());
    wav.extend_from_slice(&16u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
    wav.extend_from_slice(&pcm);
    wav
}

/// PNG frame `index` of `count`: a red square moving left to right on white.
fn frame_png(index: u32, count: u32) -> Vec<u8> {
    let size = 224u32;
    let side = 48u32;
    let x0 = 8 + index * (size - side - 16) / (count - 1).max(1);
    let img = image::RgbImage::from_fn(size, size, |x, y| {
        if x >= x0 && x < x0 + side && y >= 88 && y < 88 + side {
            image::Rgb([220, 20, 20])
        } else {
            image::Rgb([255, 255, 255])
        }
    });
    let mut out = Vec::new();
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

async fn media_request(
    dir: &Path,
    id: &str,
    question: &str,
    media: Vec<Vec<u8>>,
    kind: &str,
) -> Result<String, String> {
    let path = fetch(dir, id).await?;
    let rt = Arc::new(ModelRuntime::new().map_err(|e| e.to_string())?);
    rt.load_model_with_context(id, &path, Some(8192))
        .await
        .map_err(|e| format!("load: {e}"))?;
    if !rt.supports_media(id) {
        return Err(format!("{id} loaded without its projector"));
    }
    let plain = rt
        .generate_chat_multimodal(id, &[user(question)], &[], &[], &greedy(8))
        .await
        .map_err(|e| format!("text-only request: {e}"))?;
    let with = rt
        .generate_chat_multimodal(id, &[user(question)], &media, &[], &greedy(48))
        .await
        .map_err(|e| format!("{kind} request: {e}"))?;
    if with.text.trim().is_empty() {
        return Err(format!("the {kind} request came back empty"));
    }
    if with.input_tokens < plain.input_tokens + 40 {
        return Err(format!(
            "the {kind} cost no prompt tokens ({} with, {} without): the tower did not run",
            with.input_tokens, plain.input_tokens
        ));
    }
    Ok(format!(
        "{} prompt tokens with the {kind}, {} without; reply: {:?}",
        with.input_tokens, plain.input_tokens, with.text
    ))
}

async fn audio(dir: &Path) -> Result<String, String> {
    media_request(
        dir,
        "nemotron-3.5-bolt-e4b",
        "Describe the sound you hear in one short sentence.",
        vec![tone_wav(4)],
        "audio clip",
    )
    .await
}

async fn video(dir: &Path) -> Result<String, String> {
    let frames: Vec<Vec<u8>> = (0..4).map(|i| frame_png(i, 4)).collect();
    media_request(
        dir,
        "nemotron-3.5-bolt-74b-a9b",
        "These are four consecutive frames of a short video. In one sentence, what moves and in which direction?",
        frames,
        "video",
    )
    .await
}

async fn decision(dir: &Path) -> Result<String, String> {
    use serde_json::{Value, json};
    use tenzro_model::decision_runtime::{DecisionOption, DecisionRuntime, Question};
    const ID: &str = "laya";
    let path = fetch(dir, ID).await?;
    let rt = Arc::new(DecisionRuntime::default());
    let (rt2, p2) = (rt.clone(), path.clone());
    tokio::task::spawn_blocking(move || rt2.load(ID, &p2, 512))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("load: {e}"))?;
    let option = |k: &str, d: Value| DecisionOption {
        key: k.into(),
        description: d,
    };
    let questions = vec![
        Question::noul("spam", "Is this message spam?", Value::Null, Value::Null),
        Question::choice(
            "category",
            "Which kind of message is this?",
            vec![
                option("promotion", json!("an advertisement or prize offer")),
                option("support", json!("a customer asking for help")),
                option("personal", Value::Null),
            ],
        ),
        Question::score(
            "urgency",
            "How urgent does the message sound?",
            vec![
                json!("not urgent"),
                json!("somewhat urgent"),
                json!("very urgent"),
            ],
        ),
    ];
    let r = rt
        .decide(
            ID,
            json!(
                "WIN A FREE IPHONE now!!! Click the link below to claim your prize before midnight"
            ),
            questions,
        )
        .await
        .map_err(|e| format!("decide: {e}"))?;
    let spam = r.answers[0].noul.ok_or("no yes/no answer")?;
    if spam < 0.9 || r.answers[1].choice.as_deref() != Some("promotion") {
        return Err(format!("wrong answers: {:?}", r.answers));
    }
    Ok(format!(
        "spam {spam:.4}, category promotion, urgency {:.2}, {} prompt tokens",
        r.answers[2].score.unwrap_or(f64::NAN),
        r.tokens
    ))
}

/// The video request on a model the runtime keeps for GPU nodes, through the
/// batch engine and projector the runtime itself builds, on the CPU.
async fn video_engine(dir: &Path) -> Result<String, String> {
    use llama_cpp_2::llama_backend::LlamaBackend;
    use llama_cpp_2::model::params::LlamaModelParams;
    use praecise_runtime::{BatchEngine, BatchPrompt, BatchRequest};

    const ID: &str = "nemotron-3.5-bolt-74b-a9b";
    let path = fetch(dir, ID).await?;
    let mmproj = HfDownloader::new(dir.to_path_buf()).mmproj_path(ID);
    let backend = Arc::new(LlamaBackend::init().map_err(|e| e.to_string())?);
    let model = tenzro_model::parse_jail::load_llama(&backend, &path, &LlamaModelParams::default())
        .map_err(|e| format!("load: {e}"))?;
    // SAFETY: the engine drops the projector before the model it moves onto its thread.
    let projector = unsafe {
        llama_cpp_2::mtmd::MtmdContext::init_from_file(
            mmproj.to_str().unwrap(),
            &model,
            &llama_cpp_2::mtmd::MtmdContextParams::default(),
        )
    }
    .map_err(|e| format!("projector: {e}"))?;
    let engine = BatchEngine::spawn_with_projector(
        ID.to_string(),
        model,
        backend.clone(),
        8192,
        false,
        Some(projector),
    )
    .map_err(|e| format!("engine: {e}"))?;
    let marker = tenzro_model::chat::media_marker();
    let question = "These are four consecutive frames of a short video. In one sentence, what moves and in which direction?";
    let run = |text: String, media: Vec<Vec<u8>>, max_tokens: u32| {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sent = engine.submit(BatchRequest {
            prompt: BatchPrompt::Chat(vec![praecise_runtime::ChatMessage {
                role: "user".into(),
                content: text,
                ..Default::default()
            }]),
            config: greedy(max_tokens),
            token_tx: None,
            result_tx: tx,
            media,
        });
        async move {
            sent.map_err(|e| format!("submit: {e}"))?;
            rx.await
                .map_err(|_| "the engine dropped the request".to_string())?
                .map_err(|e| format!("generate: {e}"))
        }
    };
    let plain = run(question.to_string(), Vec::new(), 4).await?;
    let frames: Vec<Vec<u8>> = (0..4).map(|i| frame_png(i, 4)).collect();
    let text = format!("{}{question}", marker.repeat(4));
    let with = run(text, frames, 48).await?;
    if with.text.trim().is_empty() {
        return Err("the video request came back empty".into());
    }
    if with.input_tokens < plain.input_tokens + 40 {
        return Err(format!(
            "the frames cost no prompt tokens ({} with, {} without)",
            with.input_tokens, plain.input_tokens
        ));
    }
    Ok(format!(
        "{} prompt tokens with four frames, {} without; reply: {:?}",
        with.input_tokens, plain.input_tokens, with.text
    ))
}

/// One Latent MoE layer of the real checkpoint through the serving path.
async fn latent_real() -> Result<String, String> {
    use std::collections::{BTreeSet, HashMap};
    use tenzro_model::{
        ExpertExecuteRequest, ExpertFfn, GatingNetwork, LatentProjection, MoeCombiner,
        MoeExpertRuntime, MoeExtractor, MoeTensorNaming, latent_moe_forward,
    };
    tenzro_catalog::install_test_seed();
    const REPO: &str = "nvidia/NVIDIA-Nemotron-3.5-Bolt-74B-A9B-BF16";
    let revision = get_model_by_id("nemotron-3.5-bolt-74b-a9b")
        .and(tenzro_catalog::moe_source("nemotron-3.5-bolt-74b-a9b"))
        .map(|s| s.revision)
        .ok_or("the 74B entry carries no MoE checkpoint source")?;
    let layer = 1u32; // the first MoE layer: mamba, moe, mamba, moe, ...
    let mut ex = MoeExtractor::open(REPO, revision, MoeTensorNaming::NemotronH)
        .await
        .map_err(|e| format!("open: {e}"))?;
    let gate_blob = ex
        .gate_blob(layer)
        .await
        .map_err(|e| format!("gate: {e}"))?;
    let gate = GatingNetwork::from_safetensors(&gate_blob).map_err(|e| e.to_string())?;
    let latent = LatentProjection::from_safetensors(&gate_blob).map_err(|e| e.to_string())?;
    let (d_model, d_latent, n_experts) = (gate.d_model(), latent.d_latent(), gate.num_experts());
    let top_k = 9usize;
    // Tokens: post-norm hidden states have unit RMS; use fixed pseudo-random ones.
    let n_tokens = 4usize;
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut hidden = Vec::with_capacity(n_tokens * d_model);
    for _ in 0..n_tokens * d_model {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        hidden.push(((seed >> 11) as f32 / (1u64 << 53) as f32 - 0.5) * 3.4641);
    }
    let rt = MoeExpertRuntime::new();
    rt.load_gate("bolt", layer, &gate_blob)
        .map_err(|e| e.to_string())?;
    let routed = rt
        .route("bolt", layer, d_model, &hidden, top_k)
        .map_err(|e| e.to_string())?;
    let wanted: BTreeSet<u32> = routed
        .iter()
        .flat_map(|t| t.slots.iter().map(|s| s.expert.expert))
        .collect();
    if routed.iter().any(|t| t.slots.len() != top_k) {
        return Err("the router did not pick top-k experts per token".into());
    }
    let mut experts = HashMap::new();
    for e in &wanted {
        let blob = ex
            .expert_blob(layer, *e)
            .await
            .map_err(|er| format!("expert {e}: {er}"))?;
        rt.load_expert("bolt", layer, *e, &blob, None)
            .map_err(|er| er.to_string())?;
        experts.insert(
            *e,
            ExpertFfn::from_safetensors(&blob).map_err(|er| er.to_string())?,
        );
    }
    let shared_blob = ex
        .shared_expert_blob(layer)
        .await
        .map_err(|e| format!("shared: {e}"))?;
    rt.load_expert("bolt", layer, n_experts as u32, &shared_blob, None)
        .map_err(|e| e.to_string())?;
    let shared = ExpertFfn::from_safetensors(&shared_blob).map_err(|e| e.to_string())?;

    // The serving path.
    let (z, dl) = rt
        .latent_down("bolt", layer, d_model, &hidden)
        .map_err(|e| e.to_string())?
        .ok_or("the router blob carried no latent projections")?;
    if dl != d_latent {
        return Err(format!("latent width {dl} != {d_latent}"));
    }
    let mut combiner = MoeCombiner::new(d_latent, &routed).map_err(|e| e.to_string())?;
    let mut by_expert: HashMap<u32, Vec<u32>> = HashMap::new();
    for t in &routed {
        for s in &t.slots {
            by_expert
                .entry(s.expert.expert)
                .or_default()
                .push(t.token_index);
        }
    }
    for (expert, tokens) in by_expert {
        let rows: Vec<f32> = tokens
            .iter()
            .flat_map(|t| z[*t as usize * d_latent..(*t as usize + 1) * d_latent].to_vec())
            .collect();
        let req = ExpertExecuteRequest::compressed(
            "bolt".into(),
            layer,
            expert,
            tokens,
            d_latent as u32,
            rows,
        );
        combiner
            .accumulate(&rt.execute(&req).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    }
    let mixed = combiner.finish().map_err(|e| e.to_string())?;
    let served = rt
        .latent_finish("bolt", layer, &mixed, &hidden)
        .map_err(|e| e.to_string())?;

    // The layer function on the same weights.
    let cpu = tenzro_model::CpuCompute::detect();
    let x = ndarray::Array2::from_shape_vec((n_tokens, d_model), hidden.clone()).unwrap();
    let want = latent_moe_forward(
        x.view(),
        &gate,
        top_k,
        &latent,
        &experts,
        Some(&shared),
        &cpu,
    )
    .map_err(|e| e.to_string())?;
    let mut worst = 0f32;
    let mut energy = 0f64;
    for (a, b) in served.iter().zip(want.iter()) {
        if !a.is_finite() {
            return Err("the layer output has a non-finite value".into());
        }
        worst = worst.max((a - b).abs() / (1.0 + b.abs()));
        energy += f64::from(*a) * f64::from(*a);
    }
    // The hidden rows travel to the experts as Q8_0 blocks (the wire format of
    // every expert request when the width is a multiple of 32), so the serving
    // path differs from the full-precision layer function by the rounding of
    // that format, about half a percent; a wrong projection or a missing
    // shared expert would be an order of magnitude more.
    let backend = rt.compute_backend();
    if worst > 2e-2 {
        return Err(format!(
            "serving path ({backend}) differs from the layer function by {worst}"
        ));
    }
    let rms = (energy / served.len() as f64).sqrt();
    if rms < 1e-4 {
        return Err("the layer output is all zeros".into());
    }
    Ok(format!(
        "layer {layer}: {n_experts} experts, latent {d_latent} of {d_model}, {n_tokens} tokens over {} distinct experts, backend {backend}, output rms {rms:.4}, max relative difference {worst:.2e}",
        wanted.len()
    ))
}

/// Answers to a file of cases, for comparison with the reference implementation.
async fn decision_file() -> Result<String, String> {
    use serde_json::{Value, json};
    use tenzro_model::decision_runtime::{DecisionOption, DecisionRuntime, Question, QuestionKind};
    let var = |k: &str| std::env::var(k).map_err(|_| format!("{k} is not set"));
    let gguf = PathBuf::from(var("LAYA_GGUF")?);
    let n_ctx: u32 = var("LAYA_CTX")?
        .parse()
        .map_err(|_| "LAYA_CTX is a number")?;
    let cases: Value =
        serde_json::from_slice(&std::fs::read(var("LAYA_CASES")?).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let rt = Arc::new(DecisionRuntime::default());
    let (rt2, g2) = (rt.clone(), gguf.clone());
    tokio::task::spawn_blocking(move || rt2.load("laya-file", &g2, n_ctx))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("load: {e}"))?;
    let questions = |v: &Value| -> Vec<Question> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|q| {
                let id = q["id"].as_str().unwrap();
                let ins = q["instructions"].clone();
                match q["type"].as_str().unwrap() {
                    "choice" => Question::choice(
                        id,
                        ins,
                        q["criteria"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|o| DecisionOption {
                                key: o["key"].as_str().unwrap().into(),
                                description: o["description"].clone(),
                            })
                            .collect(),
                    ),
                    "score" => Question::score(id, ins, q["criteria"].as_array().unwrap().clone()),
                    _ => Question::noul(id, ins, Value::Null, Value::Null),
                }
            })
            .collect()
    };
    let mut out = serde_json::Map::new();
    let mut tokens = 0;
    for (name, state) in cases["states"].as_object().unwrap() {
        let r = rt
            .decide("laya-file", state.clone(), questions(&cases["questions"]))
            .await
            .map_err(|e| format!("{name}: {e}"))?;
        tokens += r.tokens;
        let mut answers = serde_json::Map::new();
        for a in &r.answers {
            let mut o = serde_json::Map::new();
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
                o.insert(
                    "probabilities".into(),
                    a.probabilities
                        .iter()
                        .map(|(k, v)| (k.clone(), json!(v)))
                        .collect::<serde_json::Map<_, _>>()
                        .into(),
                );
            }
            if let Some(c) = a.confidence {
                o.insert("confidence".into(), json!(c));
            }
            let _ = QuestionKind::Noul;
            answers.insert(a.id.clone(), Value::Object(o));
        }
        out.insert(name.clone(), Value::Object(answers));
    }
    std::fs::write(var("LAYA_OUT")?, serde_json::to_vec_pretty(&out).unwrap())
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{} states answered, {tokens} prompt tokens",
        out.len()
    ))
}

async fn fetch_all(dir: &Path) -> Result<String, String> {
    let ids = std::env::var("TENZRO_FETCH_IDS").map_err(|_| "TENZRO_FETCH_IDS is not set")?;
    let mut done = Vec::new();
    for id in ids.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        fetch(dir, id).await?;
        done.push(id.to_string());
    }
    Ok(format!("fetched {}", done.join(", ")))
}
