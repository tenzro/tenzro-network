//! Prefix reuse in the batch engine, measured on a small real model of every
//! memory architecture the engine serves.
//!
//! `#[ignore]`d by default: it downloads the models through the node's own
//! downloader (`HfDownloader`, the path `tenzro model download` drives) and
//! runs them on the CPU. Run explicitly with:
//!
//!   BATCH_MAX_SLOTS=4 TENZRO_PREFIX_MODELS_DIR=/path/to/models \
//!     cargo test -p tenzro-model --test prefix_reuse_architectures -- --ignored --nocapture
//!
//! `TENZRO_PREFIX_CLASSES` (comma separated) runs a subset. Every scenario is
//! checked against the same prompt run on a second engine that has never seen
//! it, so a reuse that changed the answer fails the test rather than looking
//! like a speedup.
//!
//! For each class it records, and asserts:
//! (a) an exact extension of the cached conversation reuses all of it,
//! (b) a request that diverges at a turn boundary reuses up to that turn,
//! (c) an identical re-send prefills a single token,
//! (d) two conversations served together answer exactly as each does alone,
//!     and one namespace never reuses another's cache,
//! (e) the prompt tokens each request did not have to prefill.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};
use llama_cpp_2::openai::OpenAIChatTemplateParams;
use praecise_runtime::{
    BatchEngine, BatchPrompt, BatchRequest, ChatMessage, GenerationConfig, InferenceResult,
};
use tenzro_model::{
    DownloadProgress, DownloadState, HfDownloader, HfModelEntry, SourcePolicy, get_model_by_id,
};

/// One architecture class and the model that stands for it.
struct Class {
    name: &'static str,
    entry: HfModelEntry,
    /// The class is served by the batch engine at all. An embedding model is
    /// refused by the engine and an encoder-decoder model by the node, and
    /// that refusal is what is tested for them.
    generates: bool,
    multimodal: bool,
}

/// The encoder-decoder class. The batch engine cannot build its context for
/// one (it aborts instead of returning an error), so the node refuses to
/// serve it there, and the refusal must say why.
const ENCODER_DECODER: &str = "encoder-decoder";

fn catalog(id: &str) -> HfModelEntry {
    tenzro_catalog::install_test_seed();
    get_model_by_id(id).unwrap_or_else(|| panic!("{id} must be in the catalog"))
}

/// One pinned catalog entry per class, fetched through the node's downloader.
fn classes() -> Vec<Class> {
    let class = |name: &'static str, id: &str, multimodal: bool| Class {
        name,
        entry: catalog(id),
        generates: true,
        multimodal,
    };
    vec![
        class("dense", "qwen3-0.6b", false),
        class("swa", "gemma3-270m", false),
        class("hybrid", "qwen3.5-0.8b", false),
        class("ssm", "mamba-130m", false),
        class("rwkv", "rwkv7-0.1b", false),
        class("moe", "granite-3.1-1b-a400m", false),
        class("multimodal", "smolvlm-256m", true),
        class("hybrid-multimodal", "qwen3.5-0.8b-vl", true),
        Class {
            name: ENCODER_DECODER,
            entry: catalog("flan-t5-small"),
            generates: false,
            multimodal: false,
        },
        Class {
            name: "embedding",
            entry: catalog("embeddinggemma-300m-gguf"),
            generates: false,
            multimodal: false,
        },
    ]
}

async fn fetch(dir: &Path, e: &HfModelEntry) -> (PathBuf, Option<PathBuf>) {
    let downloader = HfDownloader::new(dir.to_path_buf());
    let (tx, _rx) = tokio::sync::watch::channel(DownloadProgress {
        model_id: e.id.clone(),
        status: DownloadState::Pending,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: e.size_bytes,
    });
    let path = if downloader.is_downloaded(&e.id)
        && (e.mmproj.is_none() || downloader.mmproj_path(&e.id).exists())
    {
        downloader.model_path(&e.id)
    } else {
        downloader
            .download_model(e, None, SourcePolicy::HuggingFace, tx)
            .await
            .unwrap_or_else(|err| panic!("download {}: {err}", e.id))
    };
    let mmproj = e.mmproj.as_ref().map(|_| downloader.mmproj_path(&e.id));
    (path, mmproj)
}

/// Render a conversation the way the engine renders a chat request, with
/// thinking off, so the test knows every prompt token by token.
fn render(model: &LlamaModel, messages: &[ChatMessage], generation_prompt: bool) -> String {
    // No template (the recurrent base models), or one that does not carry the
    // whole conversation: a plain transcript.
    let transcript = || {
        let mut s = String::new();
        for m in messages {
            s.push_str(&format!("{}: {}\n", m.role, m.content));
        }
        if generation_prompt {
            s.push_str("assistant:");
        }
        s
    };
    let Ok(tmpl) = model.chat_template(None) else {
        return transcript();
    };
    let messages_json = serde_json::to_string(messages).unwrap();
    let params = OpenAIChatTemplateParams {
        messages_json: &messages_json,
        tools_json: None,
        tool_choice: None,
        json_schema: None,
        grammar: None,
        reasoning_format: None,
        chat_template_kwargs: None,
        add_generation_prompt: generation_prompt,
        use_jinja: true,
        parallel_tool_calls: false,
        enable_thinking: false,
        add_bos: false,
        add_eos: false,
        parse_tool_calls: false,
        force_pure_content: false,
    };
    match model.apply_chat_template_oaicompat(&tmpl, &params) {
        Ok(r) if messages.iter().all(|m| r.prompt.contains(m.content.trim())) => r.prompt,
        _ => transcript(),
    }
}

/// How a warm engine's answer compares with a cold engine's, read off both
/// commitments (the top-8 logits of every generated token).
enum Agreement {
    Same,
    /// The first differing token was a near tie on the cold engine: the warm
    /// engine's token is among the cold engine's top 8, within [`TIE`] of its
    /// top logit.
    Tie {
        step: usize,
        gap: f32,
    },
    Differs {
        step: usize,
        gap: f32,
    },
}

/// Logit distance under which two greedy runs of the same prompt may pick
/// different tokens from float rounding alone. The KV layout and the batch
/// shape change the order of the reductions: two runs of an identical prompt
/// with nothing reused (the "other namespace" rows) move the top logit by up
/// to about 1.1 on these models.
const TIE: f32 = 1.0;

fn agreement(warm: &InferenceResult, cold: &InferenceResult) -> Agreement {
    let (Some(w), Some(c)) = (warm.commitment.as_ref(), cold.commitment.as_ref()) else {
        return if warm.text == cold.text {
            Agreement::Same
        } else {
            Agreement::Differs {
                step: 0,
                gap: f32::NAN,
            }
        };
    };
    for (step, (ws, cs)) in w.steps.iter().zip(&c.steps).enumerate() {
        if ws.token_id == cs.token_id {
            continue;
        }
        let top = cs.top_k.first().map_or(f32::NAN, |e| e.logit);
        return match cs.top_k.iter().find(|e| e.token_id == ws.token_id) {
            Some(e) if top - e.logit < TIE => Agreement::Tie {
                step,
                gap: top - e.logit,
            },
            Some(e) => Agreement::Differs {
                step,
                gap: top - e.logit,
            },
            None => Agreement::Differs {
                step,
                gap: f32::INFINITY,
            },
        };
    }
    if w.steps.len() == c.steps.len() {
        Agreement::Same
    } else {
        Agreement::Differs {
            step: w.steps.len().min(c.steps.len()),
            gap: f32::NAN,
        }
    }
}

/// Top-1 logit difference between two answers on their first generated token:
/// what a cache that reused the wrong state would move first.
fn first_logit_delta(warm: &InferenceResult, cold: &InferenceResult) -> f32 {
    let top = |r: &InferenceResult| {
        r.commitment
            .as_ref()
            .and_then(|c| c.steps.first())
            .and_then(|s| s.top_k.first())
            .map(|e| e.logit)
    };
    match (top(warm), top(cold)) {
        (Some(a), Some(b)) => (a - b).abs(),
        _ => f32::NAN,
    }
}

/// Identity positions before the first media chunk of `prompt`, as the
/// projector tokenizes it: a request with a different attachment there can
/// reuse at most this much.
fn media_start(model: &LlamaModel, mmproj: &Path, prompt: &str, media: &[u8]) -> usize {
    use llama_cpp_2::mtmd::{
        MtmdBitmap, MtmdContext, MtmdContextParams, MtmdInputChunkType, MtmdInputText,
    };
    // SAFETY: the projector is a local of this function and dropped before
    // `model`, which the caller keeps alive.
    let ctx = unsafe {
        MtmdContext::init_from_file(
            mmproj.to_str().unwrap(),
            model,
            &MtmdContextParams::default(),
        )
    }
    .expect("load projector");
    let bitmap = MtmdBitmap::from_buffer(&ctx, media, false).expect("decode image");
    let chunks = ctx
        .tokenize(
            MtmdInputText {
                text: prompt.to_string(),
                add_special: true,
                parse_special: true,
            },
            &[&bitmap],
        )
        .expect("tokenize");
    let mut at = 0;
    for i in 0..chunks.len() {
        let chunk = chunks.get(i).expect("chunk");
        if chunk.chunk_type() != MtmdInputChunkType::Text {
            break;
        }
        at += chunk.n_tokens();
    }
    at
}

fn tokens(model: &LlamaModel, s: &str) -> usize {
    model
        .str_to_token(s, AddBos::Always)
        .expect("tokenize")
        .len()
}

fn config(salt: Option<&str>) -> GenerationConfig {
    GenerationConfig {
        temperature: 0.0,
        top_k: Some(1),
        repeat_penalty: 1.0,
        max_tokens: 12,
        seed: 7,
        enable_thinking: Some(false),
        cache_salt: salt.map(str::to_string),
        // The top logits of every token, to tell a changed answer from a
        // near tie resolved the other way.
        commitment_k: Some(8),
        ..Default::default()
    }
}

async fn ask(
    engine: &BatchEngine,
    prompt: &str,
    salt: Option<&str>,
    media: Vec<Vec<u8>>,
) -> (InferenceResult, u128) {
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let started = Instant::now();
    engine
        .submit(BatchRequest {
            prompt: BatchPrompt::Raw(prompt.to_string()),
            config: config(salt),
            token_tx: None,
            result_tx,
            media,
        })
        .expect("submit");
    let r = result_rx
        .await
        .expect("engine answered")
        .expect("generation");
    (r, started.elapsed().as_millis())
}

/// Spawn a batch engine the way the node does: a model the node refuses to
/// batch is refused here with the node's reason, before the engine sees it.
fn spawn(
    backend: &Arc<LlamaBackend>,
    id: &str,
    path: &Path,
    mmproj: Option<&Path>,
) -> Result<BatchEngine, String> {
    let model = LlamaModel::load_from_file(backend, path, &LlamaModelParams::default())
        .expect("load model");
    if let Some(reason) = tenzro_model::runtime::batch_engine_refusal(&model) {
        return Err(reason);
    }
    let projector = mmproj.map(|p| {
        // SAFETY: the engine drops the projector before the model it moves
        // onto its thread.
        unsafe {
            llama_cpp_2::mtmd::MtmdContext::init_from_file(
                p.to_str().unwrap(),
                &model,
                &llama_cpp_2::mtmd::MtmdContextParams::default(),
            )
        }
        .expect("load projector")
    });
    BatchEngine::spawn_with_projector(
        id.to_string(),
        model,
        backend.clone(),
        4096,
        false,
        projector,
    )
    .map_err(|e| e.to_string())
}

/// A 32x32 24-bit BMP of one colour: every image decoder mtmd uses reads it.
fn bmp(rgb: [u8; 3]) -> Vec<u8> {
    let (w, h) = (32u32, 32u32);
    let row = (w * 3).div_ceil(4) * 4;
    let size = 54 + row * h;
    let mut b = Vec::with_capacity(size as usize);
    b.extend_from_slice(b"BM");
    b.extend_from_slice(&size.to_le_bytes());
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(&54u32.to_le_bytes());
    b.extend_from_slice(&40u32.to_le_bytes());
    b.extend_from_slice(&w.to_le_bytes());
    b.extend_from_slice(&h.to_le_bytes());
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&24u16.to_le_bytes());
    b.extend_from_slice(&[0; 24]);
    for _ in 0..h {
        for x in 0..row {
            b.push(if x < w * 3 {
                rgb[2 - (x % 3) as usize]
            } else {
                0
            });
        }
    }
    b
}

struct Row {
    scenario: &'static str,
    prompt_tokens: u32,
    cached: u32,
    expected_at_least: usize,
    ms: u128,
    cold_ms: u128,
    agreement: Agreement,
    first_logit_delta: f32,
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn prefix_reuse_on_every_architecture() {
    let dir =
        PathBuf::from(std::env::var("TENZRO_PREFIX_MODELS_DIR").expect("TENZRO_PREFIX_MODELS_DIR"));
    let only: Option<Vec<String>> = std::env::var("TENZRO_PREFIX_CLASSES")
        .ok()
        .map(|v| v.split(',').map(str::to_string).collect());
    let backend = Arc::new(LlamaBackend::init().expect("backend"));
    let mut failures = Vec::new();

    for class in classes() {
        if only
            .as_ref()
            .is_some_and(|o| !o.iter().any(|c| c == class.name))
        {
            continue;
        }
        let (path, mmproj) = fetch(&dir, &class.entry).await;
        println!("\n=== {} ({}) ===", class.name, class.entry.id);

        if !class.generates {
            match spawn(&backend, &class.entry.id, &path, None) {
                Ok(_) => failures.push(format!(
                    "{}: {} was accepted by the batch engine",
                    class.name, class.entry.id
                )),
                Err(e) if class.name == ENCODER_DECODER && !e.contains("encoder-decoder") => {
                    failures.push(format!(
                        "{}: refused without naming the encoder-decoder reason: {e}",
                        class.name
                    ))
                }
                Err(e) => println!("refused as expected: {e}"),
            }
            continue;
        }

        let engine =
            spawn(&backend, &class.entry.id, &path, mmproj.as_deref()).expect("spawn engine");
        let cold = spawn(
            &backend,
            &format!("{}-cold", class.entry.id),
            &path,
            mmproj.as_deref(),
        )
        .expect("spawn cold engine");
        let model = LlamaModel::load_from_file(&backend, &path, &LlamaModelParams::default())
            .expect("load model");
        let marker = llama_cpp_2::mtmd::mtmd_default_marker();

        // A conversation long enough that reuse is worth measuring.
        let system = "You are a careful assistant. ".repeat(24);
        let user1 = if class.multimodal {
            format!("{marker}\nWhat colour is this picture? Answer in one word.")
        } else {
            "Name three rivers in Europe, one per line.".to_string()
        };
        let media1 = if class.multimodal {
            vec![bmp([200, 30, 30])]
        } else {
            Vec::new()
        };
        let turn1 = vec![
            ChatMessage::new("system", &system),
            ChatMessage::new("user", &user1),
        ];
        let p1 = render(&model, &turn1, true);
        // Where the reply to turn 1 starts: every later turn re-renders it,
        // and this is the turn boundary a divergence falls on.
        let reply_start = tokens(&model, &render(&model, &turn1, false));

        let mut rows: Vec<Row> = Vec::new();
        let mut check = |scenario: &'static str,
                         prompt_tokens: u32,
                         r: &InferenceResult,
                         ms: u128,
                         c: &(InferenceResult, u128),
                         at_least: usize| {
            rows.push(Row {
                scenario,
                prompt_tokens,
                cached: r.cached_tokens,
                expected_at_least: at_least,
                ms,
                cold_ms: c.1,
                agreement: agreement(r, &c.0),
                first_logit_delta: first_logit_delta(r, &c.0),
            });
        };

        // Turn 1, cold.
        let (r1, ms1) = ask(&engine, &p1, Some("tenant-a"), media1.clone()).await;
        let c1 = ask(&cold, &p1, Some("cold-1"), media1.clone()).await;
        check("cold", r1.input_tokens, &r1, ms1, &c1, 0);

        // (c) Identical re-send.
        let (rc, msc) = ask(&engine, &p1, Some("tenant-a"), media1.clone()).await;
        let resend_floor = rc.input_tokens as usize - 1;
        check(
            "(c) identical re-send",
            rc.input_tokens,
            &rc,
            msc,
            &c1,
            resend_floor,
        );

        // (a) Exact extension: the cache holds turn 1's prompt and reply; the
        // next request carries both verbatim and continues.
        let pa = format!("{p1}{}\n\nAnd one more.", rc.text);
        let (ra, msa) = ask(&engine, &pa, Some("tenant-a"), media1.clone()).await;
        let ca = ask(&cold, &pa, Some("cold-a"), media1.clone()).await;
        check(
            "(a) exact extension",
            ra.input_tokens,
            &ra,
            msa,
            &ca,
            rc.input_tokens as usize - 1,
        );

        // (b) Divergence at a turn boundary: the reply comes back different
        // (edited, or stripped of reasoning), then a new question.
        let turn2 = vec![
            ChatMessage::new("system", &system),
            ChatMessage::new("user", &user1),
            ChatMessage::new("assistant", "I would rather not say."),
            ChatMessage::new("user", "Then name one."),
        ];
        let pb = render(&model, &turn2, true);
        let (rb, msb) = ask(&engine, &pb, Some("tenant-a"), media1.clone()).await;
        let cb = ask(&cold, &pb, Some("cold-b"), media1.clone()).await;
        check(
            "(b) turn-boundary divergence",
            rb.input_tokens,
            &rb,
            msb,
            &cb,
            reply_start.saturating_sub(4),
        );

        // A different image in the same place: nothing from the image on may
        // be reused.
        if class.multimodal {
            let other = vec![bmp([30, 30, 200])];
            let (rm, msm) = ask(&engine, &p1, Some("tenant-a"), other.clone()).await;
            let cm = ask(&cold, &p1, Some("cold-m"), other).await;
            let before_image = media_start(
                &model,
                mmproj.as_deref().expect("projector"),
                &p1,
                &media1[0],
            );
            if rm.cached_tokens as usize > before_image {
                failures.push(format!(
                    "{}: a different image reused {} tokens, past the {} before it",
                    class.name, rm.cached_tokens, before_image
                ));
            }
            check(
                "different image, same text",
                rm.input_tokens,
                &rm,
                msm,
                &cm,
                0,
            );
        }

        // (d) Another namespace sending exactly the cached prompt reuses
        // nothing of it.
        let (rx, msx) = ask(&engine, &p1, Some("tenant-b"), media1.clone()).await;
        if rx.cached_tokens != 0 {
            failures.push(format!(
                "{}: tenant-b reused {} tokens of tenant-a's cache",
                class.name, rx.cached_tokens
            ));
        }
        check(
            "(d) other tenant, same prompt",
            rx.input_tokens,
            &rx,
            msx,
            &c1,
            0,
        );

        // (d) Two conversations at once answer exactly as each does alone.
        let q = vec![
            ChatMessage::new("system", "You answer in French. ".repeat(20)),
            ChatMessage::new("user", "Count from one to five."),
        ];
        let pq = render(&model, &q, true);
        let alone_q = ask(&cold, &pq, Some("cold-q"), Vec::new()).await;
        let (both_p, both_q) = tokio::join!(
            ask(&engine, &pa, Some("tenant-a"), media1.clone()),
            ask(&engine, &pq, Some("tenant-c"), Vec::new()),
        );
        check(
            "(d) concurrent, conversation 1",
            both_p.0.input_tokens,
            &both_p.0,
            both_p.1,
            &ca,
            0,
        );
        check(
            "(d) concurrent, conversation 2",
            both_q.0.input_tokens,
            &both_q.0,
            both_q.1,
            &alone_q,
            0,
        );

        println!(
            "{:<32} {:>7} {:>7} {:>9} {:>8} {:>8} {:>9} {:<22}",
            "scenario", "prompt", "cached", "expected", "ms", "cold_ms", "dlogit0", "vs cold"
        );
        for r in &rows {
            let vs_cold = match r.agreement {
                Agreement::Same => "same".to_string(),
                Agreement::Tie { step, gap } => format!("tie at token {step} ({gap:.3})"),
                Agreement::Differs { step, gap } => format!("DIFFERS at token {step} ({gap:.3})"),
            };
            println!(
                "{:<32} {:>7} {:>7} {:>9} {:>8} {:>8} {:>9.4} {:<22}",
                r.scenario,
                r.prompt_tokens,
                r.cached,
                format!(">={}", r.expected_at_least),
                r.ms,
                r.cold_ms,
                r.first_logit_delta,
                vs_cold
            );
            if (r.cached as usize) < r.expected_at_least {
                failures.push(format!(
                    "{}: {} reused {} tokens, expected at least {}",
                    class.name, r.scenario, r.cached, r.expected_at_least
                ));
            }
            if matches!(r.agreement, Agreement::Differs { .. }) {
                failures.push(format!(
                    "{}: {} answered differently from a cold engine: {vs_cold}",
                    class.name, r.scenario
                ));
            }
        }
        let saved: u32 = rows.iter().map(|r| r.cached).sum();
        let total: u32 = rows.iter().map(|r| r.prompt_tokens).sum();
        println!("prefill tokens saved: {saved} of {total}");
        engine.shutdown();
        cold.shutdown();
    }
    assert!(failures.is_empty(), "failures:\n{}", failures.join("\n"));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn reasoning_streams_on_its_own_channel_as_it_is_produced() {
    let dir =
        PathBuf::from(std::env::var("TENZRO_PREFIX_MODELS_DIR").expect("TENZRO_PREFIX_MODELS_DIR"));
    let e = catalog("qwen3-0.6b");
    let (path, _) = fetch(&dir, &e).await;
    let backend = Arc::new(LlamaBackend::init().expect("backend"));
    let engine = spawn(&backend, &e.id, &path, None).expect("spawn");
    let (token_tx, mut token_rx) = tokio::sync::mpsc::channel::<String>(1024);
    let (reasoning_tx, mut reasoning_rx) = tokio::sync::mpsc::channel::<String>(1024);
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let mut cfg = config(Some("think"));
    cfg.enable_thinking = Some(true);
    cfg.max_tokens = 96;
    cfg.reasoning_budget = Some(48);
    cfg.reasoning_tx = Some(reasoning_tx);
    engine
        .submit(BatchRequest {
            prompt: BatchPrompt::Chat(vec![ChatMessage::new(
                "user",
                "Is 17 prime? Answer yes or no.",
            )]),
            config: cfg,
            token_tx: Some(token_tx),
            result_tx,
            media: Vec::new(),
        })
        .unwrap();
    // The first reasoning delta arrives before any answer text does.
    let first = tokio::time::timeout(std::time::Duration::from_secs(120), reasoning_rx.recv())
        .await
        .expect("reasoning arrived while generating")
        .expect("a reasoning delta");
    assert!(
        token_rx.try_recv().is_err(),
        "no answer text before the first reasoning delta"
    );
    let mut reasoning = first;
    let r = result_rx.await.unwrap().unwrap();
    while let Some(c) = reasoning_rx.recv().await {
        reasoning.push_str(&c);
    }
    let mut answer = String::new();
    while let Some(c) = token_rx.recv().await {
        answer.push_str(&c);
    }
    println!(
        "reasoning {} bytes streamed, answer {:?}, {} output tokens",
        reasoning.len(),
        answer.trim(),
        r.output_tokens
    );
    assert_eq!(
        Some(reasoning.trim().to_string()),
        r.thinking,
        "the streamed reasoning is the reasoning returned"
    );
    assert!(!answer.contains("<think>") && !answer.contains("</think>"));
    assert_eq!(answer, r.text, "the answer stream carries only the answer");
    // The budget closed the block by forcing its close marker: those tokens
    // are in the commitment (they are in the output) but not billed.
    let steps = r.commitment.as_ref().map_or(0, |c| c.steps.len() as u32);
    println!(
        "commitment steps {steps}, billed output tokens {}",
        r.output_tokens
    );
    assert!(
        steps > r.output_tokens,
        "forced close tokens are recorded but not counted as generated"
    );
    engine.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_full_request_queue_refuses_instead_of_growing() {
    let dir =
        PathBuf::from(std::env::var("TENZRO_PREFIX_MODELS_DIR").expect("TENZRO_PREFIX_MODELS_DIR"));
    let e = catalog("qwen3-0.6b");
    let (path, _) = fetch(&dir, &e).await;
    let backend = Arc::new(LlamaBackend::init().expect("backend"));
    let engine = spawn(&backend, &e.id, &path, None).expect("spawn");

    // Three times the slots, submitted at once: the slots and the queue behind
    // them take at most twice the slots, and the rest are refused up front
    // instead of held in memory.
    let slots = praecise_runtime::max_slots();
    let mut accepted = Vec::new();
    let mut refused = 0;
    for i in 0..3 * slots {
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let submitted = engine.submit(BatchRequest {
            prompt: BatchPrompt::Raw(format!("Count to {i}.")),
            config: config(Some("flood")),
            token_tx: None,
            result_tx,
            media: Vec::new(),
        });
        match submitted {
            Ok(()) => accepted.push(result_rx),
            Err(praecise_runtime::Error::QueueFull { .. }) => refused += 1,
            Err(other) => panic!("unexpected submit error: {other}"),
        }
    }
    println!(
        "{} accepted, {refused} refused with {slots} slots",
        accepted.len()
    );
    assert!(
        refused >= slots,
        "at least the requests past slots + queue are refused"
    );
    assert!(accepted.len() <= 2 * slots);
    for rx in accepted {
        rx.await
            .expect("engine answered")
            .expect("an accepted request completes");
    }
    engine.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_client_that_stops_reading_its_stream_holds_back_no_one_else() {
    let dir =
        PathBuf::from(std::env::var("TENZRO_PREFIX_MODELS_DIR").expect("TENZRO_PREFIX_MODELS_DIR"));
    let e = catalog("qwen3-0.6b");
    let (path, _) = fetch(&dir, &e).await;
    let backend = Arc::new(LlamaBackend::init().expect("backend"));
    let engine = spawn(&backend, &e.id, &path, None).expect("spawn");

    // A streaming client with room for one chunk that never reads it.
    let (token_tx, mut token_rx) = tokio::sync::mpsc::channel::<String>(1);
    let (slow_tx, slow_rx) = tokio::sync::oneshot::channel();
    let mut slow_config = config(Some("slow"));
    slow_config.max_tokens = 64;
    engine
        .submit(BatchRequest {
            prompt: BatchPrompt::Raw("Write a long story about a lighthouse.".into()),
            config: slow_config,
            token_tx: Some(token_tx),
            result_tx: slow_tx,
            media: Vec::new(),
        })
        .unwrap();

    // Another request completes while that client is not reading.
    let started = Instant::now();
    let (other, _) = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        ask(&engine, "Say hello.", Some("fast"), Vec::new()),
    )
    .await
    .expect("the other request completed while the slow client was stalled");
    println!(
        "other request done in {} ms with {} tokens",
        started.elapsed().as_millis(),
        other.output_tokens
    );

    // The slow client then reads everything, and gets its whole answer.
    let mut streamed = String::new();
    while let Some(chunk) = token_rx.recv().await {
        streamed.push_str(&chunk);
    }
    let slow = slow_rx.await.unwrap().unwrap();
    assert_eq!(
        streamed, slow.text,
        "every chunk arrived once the client read them"
    );
    engine.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn the_batched_engine_commits_to_what_it_generated() {
    let dir =
        PathBuf::from(std::env::var("TENZRO_PREFIX_MODELS_DIR").expect("TENZRO_PREFIX_MODELS_DIR"));
    let e = catalog("qwen3-0.6b");
    let (path, _) = fetch(&dir, &e).await;
    let backend = Arc::new(LlamaBackend::init().expect("backend"));
    let engine = spawn(&backend, &e.id, &path, None).expect("spawn");
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let mut cfg = config(None);
    cfg.commitment_k = Some(8);
    engine
        .submit(BatchRequest {
            prompt: BatchPrompt::Raw("The capital of France is".into()),
            config: cfg,
            token_tx: None,
            result_tx,
            media: Vec::new(),
        })
        .unwrap();
    let r = result_rx.await.unwrap().unwrap();
    let c = r
        .commitment
        .expect("a verifiable request gets a commitment on the batched path");
    assert_eq!(c.k, 8);
    assert_eq!(
        c.steps.len() as u32,
        r.output_tokens,
        "one record per generated token"
    );
    assert_eq!(c.prompt_tokens, r.input_tokens);
    for step in &c.steps {
        assert_eq!(step.top_k.len(), 8);
        assert_eq!(
            step.top_k[0].token_id, step.token_id,
            "greedy sampling picked the top logit"
        );
    }
    println!("commitment {} over {} steps", c.hash_hex(), c.steps.len());
    engine.shutdown();
}
