//! The registry loader gate: every catalog entry the Praecise engine serves
//! has a loader for its architecture, and a small model of each architecture
//! loads and decodes.
//!
//! `#[ignore]`d by default; the scheduled suite runs it (stage
//! `model-loaders`, scripts/testnet/stages.sh):
//!
//!   TENZRO_LOADER_ARCH_SRC=<engine checkout>/llama-cpp-sys-2/llama.cpp/src/llama-arch.cpp \
//!   TENZRO_LOADER_MODELS_DIR=/path/to/models TENZRO_LOADER_OUT=/path/to/out \
//!     cargo test --release -p tenzro-model --test registry_loaders -- --ignored --nocapture
//!
//! For every engine entry it checks, in order:
//! 1. each GGUF architecture the entry's label allows is one the pinned
//!    engine knows (parsed from the engine's own architecture table);
//! 2. the `general.architecture` in the header of the entry's file, read
//!    from its pinned Hub revision (the first 256 KiB only), is one the label
//!    allows. Gated and network-built files are not read from the Hub;
//! 3. for each GGUF architecture, the smallest entry no larger than
//!    `TENZRO_LOADER_MAX_BYTES` (default 1 GB) that runs on its own is
//!    fetched through the node's downloader, loaded on the CPU and asked for
//!    a few tokens through the batch engine.
//!
//! `TENZRO_LOADER_IDS` (comma separated catalog ids) restricts step 3 to those
//! entries and lifts the size cap for them, to prove a specific registry
//! entry (a larger quantisation, a new model) through the real download path.
//! An architecture with no entry small enough, or with only draft entries,
//! is written to `engine-only.txt` in `TENZRO_LOADER_OUT`; the stage runs the
//! engine's tiny random-weight model of it instead. Every line of the report
//! starts with PASS, FAIL, SKIP or ENGINE-ONLY; the test fails on any FAIL.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::model::params::LlamaModelParams;
use praecise_runtime::{BatchEngine, BatchPrompt, BatchRequest, GenerationConfig};
use tenzro_catalog::{CatalogEntry, Loader, ModelSpec, Source, read_entries};
use tenzro_model::{DownloadProgress, DownloadState, HfDownloader, HfModelEntry, SourcePolicy};

const HEADER_BYTES: u64 = 256 * 1024;

/// Draft heads: they decode only beside the model they draft for, so they
/// are never run on their own here.
const DRAFT_ARCHITECTURES: &[&str] = &["dflash", "eagle3", "gemma4-assistant"];

/// The architecture names of the pinned engine: `{ LLM_ARCH_X, "name" },`.
fn engine_architectures(src: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("{ LLM_ARCH_")?;
            let (_, quoted) = rest.split_once('"')?;
            let (name, _) = quoted.split_once('"')?;
            (name != "(unknown)").then(|| name.to_string())
        })
        .collect()
}

/// `general.architecture` from the start of a GGUF file.
fn header_architecture(b: &[u8]) -> Result<String, String> {
    let mut o = 0usize;
    let take = |o: &mut usize, n: usize| -> Result<&[u8], String> {
        let s = b.get(*o..*o + n).ok_or("header ends early")?;
        *o += n;
        Ok(s)
    };
    let u32_at = |o: &mut usize| -> Result<u32, String> {
        Ok(u32::from_le_bytes(take(o, 4)?.try_into().unwrap()))
    };
    let u64_at = |o: &mut usize| -> Result<u64, String> {
        Ok(u64::from_le_bytes(take(o, 8)?.try_into().unwrap()))
    };
    if take(&mut o, 4)? != b"GGUF" {
        return Err("not a GGUF file".into());
    }
    let _version = u32_at(&mut o)?;
    let _tensors = u64_at(&mut o)?;
    let kvs = u64_at(&mut o)?;
    for _ in 0..kvs {
        let n = u64_at(&mut o)? as usize;
        let key = String::from_utf8_lossy(take(&mut o, n)?).into_owned();
        let ty = u32_at(&mut o)?;
        match ty {
            8 => {
                let n = u64_at(&mut o)? as usize;
                let v = String::from_utf8_lossy(take(&mut o, n)?).into_owned();
                if key == "general.architecture" {
                    return Ok(v);
                }
            }
            0 | 1 | 7 => o += 1,
            2 | 3 => o += 2,
            4..=6 => o += 4,
            10..=12 => o += 8,
            _ => {
                return Err(format!(
                    "general.architecture is not before array key {key}"
                ));
            }
        }
    }
    Err("no general.architecture".into())
}

/// An error with every cause under it, so a refused handshake or a DNS
/// failure is named rather than reported as a failed send.
fn with_causes(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cause = c.source();
    }
    s
}

async fn read_header(
    http: &reqwest::Client,
    repo: &str,
    revision: &str,
    path: &str,
) -> Result<String, String> {
    let url = format!("https://huggingface.co/{repo}/resolve/{revision}/{path}");
    let r = http
        .get(&url)
        .header("Range", format!("bytes=0-{}", HEADER_BYTES - 1))
        .send()
        .await
        .map_err(|e| format!("{url}: {}", with_causes(&e)))?;
    if !r.status().is_success() {
        return Err(format!("{url}: HTTP {}", r.status()));
    }
    let b = r
        .bytes()
        .await
        .map_err(|e| format!("{url}: {}", with_causes(&e)))?;
    header_architecture(&b)
}

/// The engine-served spec of an entry, when it is a chat or reranker GGUF.
fn gguf_spec(e: &CatalogEntry) -> Option<&HfModelEntry> {
    match &e.model {
        ModelSpec::Gguf(m) | ModelSpec::Rerank(m) => Some(m),
        _ => None,
    }
}

async fn fetch(dir: &Path, e: &HfModelEntry) -> Result<(PathBuf, Option<PathBuf>), String> {
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
            .map_err(|err| format!("download: {err}"))?
    };
    Ok((
        path,
        e.mmproj.as_ref().map(|_| downloader.mmproj_path(&e.id)),
    ))
}

/// Load the model (and its projector) on the CPU and decode a few tokens.
async fn run(
    backend: &Arc<LlamaBackend>,
    id: &str,
    path: &Path,
    mmproj: Option<&Path>,
    generates: bool,
) -> Result<String, String> {
    let started = Instant::now();
    let model = LlamaModel::load_from_file(backend, path, &LlamaModelParams::default())
        .map_err(|e| format!("load: {e}"))?;
    let projector = match mmproj {
        Some(p) => Some(
            // SAFETY: the engine drops the projector before the model it moves
            // onto its thread.
            unsafe {
                llama_cpp_2::mtmd::MtmdContext::init_from_file(
                    p.to_str().unwrap(),
                    &model,
                    &llama_cpp_2::mtmd::MtmdContextParams::default(),
                )
            }
            .map_err(|e| format!("projector: {e}"))?,
        ),
        None => None,
    };
    let engine = BatchEngine::spawn_with_projector(
        id.to_string(),
        model,
        backend.clone(),
        2048,
        false,
        projector,
    );
    if !generates {
        return match engine {
            Err(e) => Ok(format!("loaded, generation refused as expected ({e})")),
            Ok(_) => Err("an embedding model was accepted for generation".into()),
        };
    }
    let engine = engine.map_err(|e| format!("engine: {e}"))?;
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    engine
        .submit(BatchRequest {
            prompt: BatchPrompt::Raw("The capital of France is".to_string()),
            config: GenerationConfig {
                temperature: 0.0,
                top_k: Some(1),
                max_tokens: 4,
                seed: 7,
                enable_thinking: Some(false),
                ..Default::default()
            },
            token_tx: None,
            result_tx,
            media: Vec::new(),
        })
        .map_err(|e| format!("submit: {e}"))?;
    let r = result_rx
        .await
        .map_err(|_| "the engine dropped the request".to_string())?
        .map_err(|e| format!("generate: {e}"))?;
    if r.output_tokens == 0 {
        return Err("no tokens generated".into());
    }
    Ok(format!(
        "{} tokens in {} ms",
        r.output_tokens,
        started.elapsed().as_millis()
    ))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn every_registry_architecture_loads_and_decodes() {
    let arch_src =
        PathBuf::from(std::env::var("TENZRO_LOADER_ARCH_SRC").expect("TENZRO_LOADER_ARCH_SRC"));
    let models =
        PathBuf::from(std::env::var("TENZRO_LOADER_MODELS_DIR").expect("TENZRO_LOADER_MODELS_DIR"));
    let out = PathBuf::from(std::env::var("TENZRO_LOADER_OUT").expect("TENZRO_LOADER_OUT"));
    let only_ids: Vec<String> = std::env::var("TENZRO_LOADER_IDS")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let max_bytes: u64 = std::env::var("TENZRO_LOADER_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000_000);
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&models).unwrap();
    let mut report = std::fs::File::create(out.join("report.txt")).unwrap();
    let mut line = |s: String| {
        println!("{s}");
        writeln!(report, "{s}").unwrap();
    };

    // The downloader fetches only files the installed catalog hashes.
    tenzro_catalog::install_test_seed();
    let known = engine_architectures(&arch_src);
    assert!(
        known.len() > 50,
        "only {} engine architectures parsed from {}",
        known.len(),
        arch_src.display()
    );
    let seed = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tenzro-catalog/seed");
    let entries = read_entries(&seed).expect("the seed parses");
    let http = reqwest::Client::new();

    // Header architecture -> runnable candidates (size, entry).
    let mut by_arch: BTreeMap<String, Vec<(u64, HfModelEntry)>> = BTreeMap::new();
    let mut engine_only: BTreeSet<String> = BTreeSet::new();
    for e in &entries {
        let archs = match e.model.loader() {
            Loader::Engine(a) => a,
            Loader::Missing(why) => {
                line(format!("FAIL {}: no loader: {why}", e.id()));
                continue;
            }
            Loader::Media | Loader::Onnx | Loader::Planned => continue,
        };
        let unknown: Vec<&str> = archs
            .iter()
            .copied()
            .filter(|a| !known.contains(*a))
            .collect();
        if !unknown.is_empty() {
            line(format!(
                "FAIL {}: the engine has no {} architecture",
                e.id(),
                unknown.join(", ")
            ));
            continue;
        }
        let file = e
            .components
            .iter()
            .find(|c| c.path.ends_with(".gguf") && !c.path.to_ascii_lowercase().contains("mmproj"));
        let Some(file) = file else {
            line(format!(
                "FAIL {}: no GGUF file among its components",
                e.id()
            ));
            continue;
        };
        let revision = match &file.source {
            Source::Hub { revision } => revision.as_str(),
            Source::Network { .. } => {
                line(format!(
                    "SKIP {}: network-built file, header not read from the Hub",
                    e.id()
                ));
                continue;
            }
        };
        if e.gated {
            line(format!(
                "SKIP {}: gated, header not read from the Hub",
                e.id()
            ));
            continue;
        }
        let arch = match read_header(&http, &file.repo, revision, &file.path).await {
            Ok(a) => a,
            Err(why) => {
                line(format!("FAIL {}: header unreadable: {why}", e.id()));
                continue;
            }
        };
        if !archs.contains(&arch.as_str()) {
            line(format!(
                "FAIL {}: file architecture {arch} is not one its label allows ({})",
                e.id(),
                archs.join(", ")
            ));
            continue;
        }
        let candidates = by_arch.entry(arch.clone()).or_default();
        match gguf_spec(e) {
            Some(m)
                if !DRAFT_ARCHITECTURES.contains(&arch.as_str())
                    && if only_ids.is_empty() {
                        m.size_bytes <= max_bytes
                    } else {
                        only_ids.contains(&m.id)
                    } =>
            {
                candidates.push((m.size_bytes, m.clone()))
            }
            _ => {}
        }
    }

    let backend = Arc::new(LlamaBackend::init().expect("backend"));
    for (arch, mut candidates) in by_arch {
        candidates.sort_by_key(|(size, _)| *size);
        let Some((size, m)) = candidates.into_iter().next() else {
            line(format!(
                "ENGINE-ONLY {arch}: no runnable entry under {max_bytes} bytes"
            ));
            engine_only.insert(arch);
            continue;
        };
        let generates = !matches!(arch.as_str(), "gemma-embedding" | "gemma-embedding2");
        let result = match fetch(&models, &m).await {
            Ok((path, mmproj)) => run(&backend, &m.id, &path, mmproj.as_deref(), generates).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(how) => line(format!(
                "PASS {arch}: {} ({:.2} GB) {how}",
                m.id,
                size as f64 / 1e9
            )),
            Err(why) => line(format!(
                "FAIL {arch}: {} ({:.2} GB) {why}",
                m.id,
                size as f64 / 1e9
            )),
        }
    }
    // Speech and embedder architectures run outside the batch engine.
    for e in &entries {
        if let (ModelSpec::Tts(_) | ModelSpec::Embed(_), Loader::Engine(archs)) =
            (&e.model, e.model.loader())
        {
            for a in archs {
                if known.contains(*a) && engine_only.insert(a.to_string()) {
                    line(format!(
                        "ENGINE-ONLY {a}: {} is not served by the batch engine",
                        e.id()
                    ));
                }
            }
        }
    }
    std::fs::write(
        out.join("engine-only.txt"),
        engine_only
            .iter()
            .map(|a| format!("{a}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let text = std::fs::read_to_string(out.join("report.txt")).unwrap();
    let failed: Vec<&str> = text.lines().filter(|l| l.starts_with("FAIL")).collect();
    assert!(
        failed.is_empty(),
        "{} loader failure(s):\n{}",
        failed.len(),
        failed.join("\n")
    );
}
