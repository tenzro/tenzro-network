//! A continuity session on a batched model moves to another node's engine.
//!
//! One test per architecture class, each on a small model of that class:
//!
//! | test | model | class | download |
//! |---|---|---|---|
//! | `attention_only` | `qwen3-0.6b` | attention layers only | 397 MB |
//! | `attention_with_recurrent_layers` | `qwen3.5-0.8b` | attention plus recurrent layers | 533 MB |
//! | `mixture_of_experts` | `granite-3.1-1b-a400m` | attention with routed experts | 850 MB |
//! | `state_space_only_serves_no_session` | `mamba-130m` | selective state space, no attention | 90 MB |
//! | `recurrent_only_serves_no_session` | `rwkv7-0.1b` | recurrent network, no attention | 133 MB |
//!
//! A session is a chat session. The catalog's state-space and recurrent-only
//! models are not chat models: one carries no chat template and the other
//! only names one. Their two tests hold that such a model is refused a
//! session turn with that reason, rather than being served a prompt that is
//! not the conversation.
//!
//! `#[ignore]`d by default: each fetches its model through the node's own
//! downloader (about 2.0 GB for all five) and runs it on the CPU. Run
//! explicitly, all or one, with:
//!
//!   TENZRO_TEST_MODELS_DIR=/path/to/models \
//!     cargo test -p tenzro-model --test batch_session_migration -- --ignored --nocapture --test-threads 1
//!
//! Engine A serves a turn and checkpoints it from the turn's own sequence:
//! the conversation through that turn's prompt. Engine B, a separate runtime
//! of the same weights, rebuilds the session from that checkpoint alone and
//! serves the next turn. B must answer exactly as A does when A serves that
//! turn itself, and must prefill only what came after the checkpointed
//! prompt, the reply and the next message, not the history.
//!
//! A template may render the end of a prompt differently from the same turn
//! in the next history. An attention cache is cut back to where they part; a
//! cache with recurrent state cannot be, so a model with recurrent layers
//! then has no checkpoint, and its turn must say so with that reason.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tenzro_model::{Catalog, CatalogCell};
use tenzro_model::{
    ChatMessage, DownloadProgress, DownloadState, GenerationConfig, HfDownloader, ModelRuntime,
    SequenceEngine, SessionTurn, SourcePolicy, TurnCheckpoint,
};

/// Loading a model starts this executable again as the model parser. This
/// initialiser runs before the test harness and turns that child into the
/// parser, so the harness never starts in it.
#[cfg(target_os = "linux")]
#[used]
#[unsafe(link_section = ".init_array")]
static ENTER_PARSE_JAIL_CHILD: extern "C" fn() = enter_parse_jail_child;

#[cfg(target_os = "linux")]
extern "C" fn enter_parse_jail_child() {
    tenzro_model::parse_jail::enter_if_requested();
}

const SESSION: &str = "session-under-test";

/// Most positions at the end of a turn's prompt that the next turn's history
/// may render differently (a generation prompt's own opening), plus the one
/// token a successor feeds after the chain.
const PROMPT_END_ALLOWANCE: u32 = 16;

async fn fetch(model: &str, dir: &Path) -> PathBuf {
    let catalog = Catalog::test_seed();
    let entry = catalog
        .get_model_by_id(model)
        .unwrap_or_else(|| panic!("{model} must be in the catalog"));
    let downloader = HfDownloader::new(dir.to_path_buf(), CatalogCell::new(catalog));
    if downloader.is_downloaded(&entry.id) {
        return downloader.model_path(&entry.id);
    }
    let (tx, _rx) = tokio::sync::watch::channel(DownloadProgress {
        model_id: entry.id.clone(),
        status: DownloadState::Pending,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: entry.size_bytes,
    });
    downloader
        .download_model(&entry, None, SourcePolicy::HuggingFace, tx)
        .await
        .unwrap_or_else(|e| panic!("download {model}: {e}"))
}

async fn runtime(model: &str, path: &Path) -> Arc<ModelRuntime> {
    let rt = Arc::new(ModelRuntime::new(CatalogCell::new(Catalog::test_seed())).expect("runtime"));
    rt.load_model_with_context(model, path, Some(4096))
        .await
        .expect("load");
    rt
}

fn greedy(max_tokens: u32) -> GenerationConfig {
    GenerationConfig {
        temperature: 0.0,
        top_k: Some(1),
        repeat_penalty: 1.0,
        repeat_last_n: 0,
        max_tokens,
        enable_thinking: Some(false),
        ..GenerationConfig::default()
    }
}

async fn turn(rt: &Arc<ModelRuntime>, model: &str, messages: Vec<ChatMessage>) -> SessionTurn {
    let (rt, model) = (rt.clone(), model.to_string());
    tokio::task::spawn_blocking(move || rt.turn(&model, SESSION, &messages, &greedy(24)))
        .await
        .unwrap()
        .expect("turn")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "loads real weights; scripts/model-weight-tests.sh runs it"]
async fn attention_only() {
    a_session_checkpointed_on_one_engine_continues_on_another("qwen3-0.6b").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "loads real weights; scripts/model-weight-tests.sh runs it"]
async fn attention_with_recurrent_layers() {
    a_session_checkpointed_on_one_engine_continues_on_another("qwen3.5-0.8b").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "loads real weights; scripts/model-weight-tests.sh runs it"]
async fn mixture_of_experts() {
    a_session_checkpointed_on_one_engine_continues_on_another("granite-3.1-1b-a400m").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "loads real weights; scripts/model-weight-tests.sh runs it"]
async fn state_space_only_serves_no_session() {
    a_model_with_no_chat_template_is_refused_a_session_turn(
        "mamba-130m",
        "carries no chat template",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "loads real weights; scripts/model-weight-tests.sh runs it"]
async fn recurrent_only_serves_no_session() {
    a_model_with_no_chat_template_is_refused_a_session_turn(
        "rwkv7-0.1b",
        "names the chat template `rwkv-world`",
    )
    .await;
}

async fn a_model_with_no_chat_template_is_refused_a_session_turn(model: &str, reason: &str) {
    let dir =
        PathBuf::from(std::env::var("TENZRO_TEST_MODELS_DIR").expect("TENZRO_TEST_MODELS_DIR"));
    let path = fetch(model, &dir).await;
    let rt = runtime(model, &path).await;
    let messages = vec![ChatMessage::new(
        "user",
        "Name a river that flows through Europe.",
    )];
    let refused = {
        let (rt, model) = (rt.clone(), model.to_string());
        tokio::task::spawn_blocking(move || rt.turn(&model, SESSION, &messages, &greedy(24)))
            .await
            .unwrap()
    };
    let why = refused.expect_err("a turn was served").to_string();
    assert!(why.contains(reason), "{model}: {why}");
    println!("refused ({model}): {why}");
}

async fn a_session_checkpointed_on_one_engine_continues_on_another(model: &str) {
    let dir =
        PathBuf::from(std::env::var("TENZRO_TEST_MODELS_DIR").expect("TENZRO_TEST_MODELS_DIR"));
    let path = fetch(model, &dir).await;

    let system = "You are a concise assistant. Answer in one short sentence. ".repeat(8);
    let first = vec![
        ChatMessage::new("system", &system),
        ChatMessage::new("user", "Name a river that flows through Europe."),
    ];

    // Engine A serves the first turn and checkpoints it.
    let a = runtime(model, &path).await;
    let t1 = turn(&a, model, first.clone()).await;
    assert!(t1.completion_tokens > 0, "the first turn answered");
    if let TurnCheckpoint::Unavailable(why) = &t1.checkpoint {
        // The one reason a turn that answered may have none: recurrent state
        // behind a prompt the next history renders differently.
        assert!(
            why.contains("recurrent state cannot be cut back"),
            "{model}: {why}"
        );
        let exported = {
            let a = a.clone();
            tokio::task::spawn_blocking(move || a.export_delta(SESSION))
                .await
                .unwrap()
                .expect("export")
        };
        assert!(
            exported.is_none(),
            "a turn with no checkpoint exports nothing"
        );
        println!("no checkpoint ({model}): {why}");
        return;
    }
    assert_eq!(
        t1.checkpoint,
        TurnCheckpoint::Ready,
        "the first turn left a checkpoint ({model})"
    );
    let delta = {
        let a = a.clone();
        tokio::task::spawn_blocking(move || a.export_delta(SESSION))
            .await
            .unwrap()
            .expect("export")
            .expect("the first turn was checkpointed")
    };
    let blob = tenzro_model::KvBlob::decode(&delta.blob).expect("blob");
    let carried = blob.tokens.len() as u32;
    assert_eq!(blob.base_pos, 0, "a batched checkpoint is a whole chain");
    // The conversation through the first turn's prompt, and what of its
    // reply was decoded when the cache was copied.
    assert!(
        carried >= t1.prompt_tokens,
        "{carried} positions for a prompt of {}",
        t1.prompt_tokens
    );
    println!(
        "checkpoint: {carried} positions, {} bytes ({model})",
        delta.blob.len()
    );
    // Nothing new to send until another turn is checkpointed.
    let again = {
        let a = a.clone();
        tokio::task::spawn_blocking(move || a.export_delta(SESSION))
            .await
            .unwrap()
            .expect("export")
    };
    assert!(again.is_none(), "a checkpoint is exported once");

    let mut second = first.clone();
    second.push(ChatMessage::new("assistant", &t1.text));
    second.push(ChatMessage::new("user", "Which sea does it flow into?"));

    // Engine B holds only the checkpoint.
    let b = runtime(model, &path).await;
    let rebuilt = {
        let (b, chain, model) = (b.clone(), vec![delta.blob.clone()], model.to_string());
        tokio::task::spawn_blocking(move || b.import_chain(&model, SESSION, &chain))
            .await
            .unwrap()
            .expect("import")
    };
    assert_eq!(rebuilt, carried);
    assert!(b.has_session(SESSION));
    let on_b = turn(&b, model, second.clone()).await;

    // The same turn served by A, where the session ran all along.
    let on_a = turn(&a, model, second.clone()).await;
    println!(
        "turn 2: A reused {}/{} prompt tokens, B reused {}/{} ({model})",
        on_a.reused_tokens, on_a.prompt_tokens, on_b.reused_tokens, on_b.prompt_tokens
    );
    assert_eq!(on_b.prompt_tokens, on_a.prompt_tokens);
    // B prefills what the conversation added after the first turn's prompt,
    // the reply and the next message, and not the history before it. The
    // allowance covers the end of that prompt where the next history renders
    // it differently, and the token fed after the chain.
    let added = on_b.prompt_tokens - t1.prompt_tokens;
    let prefilled = on_b.prompt_tokens - on_b.reused_tokens;
    assert!(
        prefilled <= added + PROMPT_END_ALLOWANCE,
        "B read the history again: prefilled {prefilled} of {}, {added} of them new",
        on_b.prompt_tokens
    );
    assert!(
        on_b.reused_tokens + PROMPT_END_ALLOWANCE >= t1.prompt_tokens,
        "B reused {} positions of a first prompt of {}",
        on_b.reused_tokens,
        t1.prompt_tokens
    );
    assert_eq!(
        on_b.text, on_a.text,
        "B continues the session exactly as A does"
    );
    assert_eq!(on_b.completion_tokens, on_a.completion_tokens);

    // A checkpoint of other weights is refused before anything is installed.
    let mut forged = blob.clone();
    forged.model = tenzro_model::ModelFingerprint::of_bytes(b"other weights");
    let refused = {
        let (b, chain, model) = (b.clone(), vec![forged.encode()], model.to_string());
        tokio::task::spawn_blocking(move || b.import_chain(&model, "other-session", &chain))
            .await
            .unwrap()
    };
    assert!(refused.is_err(), "a chain of other weights is refused");
    assert!(!b.has_session("other-session"));
}
