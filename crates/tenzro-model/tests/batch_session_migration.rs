//! A continuity session on a batched model moves to another node's engine.
//!
//! `#[ignore]`d by default: it fetches `qwen3.5-0.8b` (attention plus
//! recurrent layers) through the node's own downloader and runs it on the CPU.
//! Run explicitly with:
//!
//!   TENZRO_TEST_MODELS_DIR=/path/to/models \
//!     cargo test -p tenzro-model --test batch_session_migration -- --ignored --nocapture
//!
//! Engine A serves a turn and checkpoints it through its reply. Engine B, a
//! separate runtime of the same weights, rebuilds the session from that
//! checkpoint alone and serves the next turn. B must answer exactly as A does
//! when A serves that turn itself, and must not prefill again what the
//! checkpoint carried: neither the history nor the reply.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tenzro_model::{
    ChatMessage, DownloadProgress, DownloadState, GenerationConfig, HfDownloader, ModelRuntime,
    SequenceEngine, SessionTurn, SourcePolicy, get_model_by_id,
};

const MODEL: &str = "qwen3.5-0.8b";
const SESSION: &str = "session-under-test";

async fn fetch(dir: &Path) -> PathBuf {
    tenzro_catalog::install_test_seed();
    let entry = get_model_by_id(MODEL).unwrap_or_else(|| panic!("{MODEL} must be in the catalog"));
    let downloader = HfDownloader::new(dir.to_path_buf());
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
        .unwrap_or_else(|e| panic!("download {MODEL}: {e}"))
}

async fn runtime(path: &Path) -> Arc<ModelRuntime> {
    let rt = Arc::new(ModelRuntime::new().expect("runtime"));
    rt.load_model_with_context(MODEL, path, Some(4096))
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

async fn turn(rt: &Arc<ModelRuntime>, messages: Vec<ChatMessage>) -> SessionTurn {
    let rt = rt.clone();
    tokio::task::spawn_blocking(move || rt.turn(MODEL, SESSION, &messages, &greedy(24)))
        .await
        .unwrap()
        .expect("turn")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_batched_session_checkpointed_on_one_engine_continues_on_another() {
    let dir =
        PathBuf::from(std::env::var("TENZRO_TEST_MODELS_DIR").expect("TENZRO_TEST_MODELS_DIR"));
    let path = fetch(&dir).await;

    let system = "You are a concise assistant. Answer in one short sentence. ".repeat(8);
    let first = vec![
        ChatMessage::new("system", &system),
        ChatMessage::new("user", "Name a river that flows through Europe."),
    ];

    // Engine A serves the first turn and checkpoints it.
    let a = runtime(&path).await;
    let t1 = turn(&a, first.clone()).await;
    assert!(t1.completion_tokens > 0, "the first turn answered");
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
    // The conversation through the first turn's reply, as the next turn's
    // history renders it: longer than the first prompt by the reply.
    assert!(
        carried > t1.prompt_tokens,
        "{carried} positions for a prompt of {}",
        t1.prompt_tokens
    );
    println!(
        "checkpoint: {carried} positions, {} bytes",
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
    let b = runtime(&path).await;
    let rebuilt = {
        let (b, chain) = (b.clone(), vec![delta.blob.clone()]);
        tokio::task::spawn_blocking(move || b.import_chain(MODEL, SESSION, &chain))
            .await
            .unwrap()
            .expect("import")
    };
    assert_eq!(rebuilt, carried);
    assert!(b.has_session(SESSION));
    let on_b = turn(&b, second.clone()).await;

    // The same turn served by A, where the session ran all along.
    let on_a = turn(&a, second.clone()).await;
    println!(
        "turn 2: A reused {}/{} prompt tokens, B reused {}/{}",
        on_a.reused_tokens, on_a.prompt_tokens, on_b.reused_tokens, on_b.prompt_tokens
    );
    assert_eq!(on_b.prompt_tokens, on_a.prompt_tokens);
    // At most the two positions around the end of the checkpoint are decoded
    // again: the token fed after it, and a cache restored to one position
    // before the end of the next history. The reply is among what is reused.
    assert!(
        on_b.reused_tokens + 2 >= carried,
        "B prefilled again what the checkpoint carried: reused {} of {carried}",
        on_b.reused_tokens
    );
    assert!(
        on_b.prompt_tokens - on_b.reused_tokens <= on_b.prompt_tokens - carried + 2,
        "B re-read the last reply: prefilled {} of {}",
        on_b.prompt_tokens - on_b.reused_tokens,
        on_b.prompt_tokens
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
        let (b, chain) = (b.clone(), vec![forged.encode()]);
        tokio::task::spawn_blocking(move || b.import_chain(MODEL, "other-session", &chain))
            .await
            .unwrap()
    };
    assert!(refused.is_err(), "a chain of other weights is refused");
    assert!(!b.has_session("other-session"));
}
