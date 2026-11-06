//! Media models the node serves in process.
//!
//! A media model the node loads runs in the node's process on the Praecise
//! diffusion engine. `tenzro_mediaGen_render` renders with it
//! ([`crate::media_verify`]); loading fetches the pinned checkpoint, checks
//! every file against its catalog hash and hands it to the engine.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use tenzro_model::{
    ArtifactSpec, DownloadProgress, DownloadState, MediaModelInfo, MediaPrecision, MediaRuntime,
};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// The node's media runtime: the media models it has loaded.
#[derive(Debug)]
pub struct MediaModels {
    runtime: Arc<MediaRuntime>,
}

impl MediaModels {
    /// No models loaded yet, loading through the node's `host`.
    pub fn with_host(host: Arc<tenzro_model::ModelHost>) -> Self {
        Self {
            runtime: Arc::new(MediaRuntime::with_host(host)),
        }
    }

    /// The loaded media models.
    pub fn runtime(&self) -> &Arc<MediaRuntime> {
        &self.runtime
    }
}

fn rpc_err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

/// Fetch every pinned file of `repo` into `dir_name` under the node's models
/// directory.
pub(crate) async fn fetch_pinned(
    node: &Arc<TenzroNode>,
    model_id: &str,
    repo: &str,
    files: Vec<String>,
    dir_name: String,
    total_bytes: u64,
) -> Result<PathBuf, JsonRpcError> {
    if files.is_empty() {
        return Err(rpc_err(
            -32010,
            format!("{model_id}: {repo} has no pinned files; it cannot be fetched"),
        ));
    }
    let models_dir = node.config().effective_models_dir();
    std::fs::create_dir_all(&models_dir)
        .map_err(|e| rpc_err(-32603, format!("models dir: {e}")))?;
    // Peers holding verified copies are asked first; weights gated behind a
    // licence come from them alone.
    let peer_hints = crate::trust_hooks::peer_hints(node, repo, &files);
    let spec = ArtifactSpec::Bundle {
        files,
        dir_name,
        peer_hints,
    };
    let (tx, _rx) = tokio::sync::watch::channel(DownloadProgress {
        model_id: model_id.to_string(),
        status: DownloadState::Pending,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes,
    });
    crate::rpc::artifact_downloader(node, models_dir)
        .download(model_id, repo, &spec, tenzro_model::SourcePolicy::Auto, tx)
        .await
        .map_err(|e| rpc_err(-32603, format!("fetch {model_id}: {e}")))
}

/// One repository a checkpoint is fetched from: its pinned files in path
/// order, their bytes, and the directory (under the node's models
/// directory) they land in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckpointSource {
    pub repo: String,
    pub files: Vec<String>,
    pub bytes: u64,
    pub dir_name: String,
}

/// Every source the catalog entry for `model_id` pins, `primary` first: the
/// directories a checkpoint loaded as directories is fetched into, one per
/// repository, so no two sources ever share a directory. The parts of each
/// entry it requires follow, one source per repository of that entry,
/// fetched into the required entry's own directory so both models read one
/// copy.
pub(crate) fn checkpoint_sources(model_id: &str, primary: &str) -> Vec<CheckpointSource> {
    let Some(e) = tenzro_model::catalog::entry(model_id) else {
        return vec![CheckpointSource {
            repo: primary.to_string(),
            files: Vec::new(),
            bytes: 0,
            dir_name: source_dir(model_id, primary),
        }];
    };
    let mut out: Vec<CheckpointSource> = e
        .sources(primary)
        .into_iter()
        .map(|repo| {
            let files = e.checkpoint(repo);
            CheckpointSource {
                repo: repo.to_string(),
                bytes: files.iter().map(|c| c.size).sum(),
                files: files.into_iter().map(|c| c.path.clone()).collect(),
                dir_name: source_dir(model_id, repo),
            }
        })
        // An entry made only of another entry's parts pins nothing of its own.
        .filter(|s| !s.files.is_empty())
        .collect();
    for dep in required_entries(&e) {
        let files = e.required_components(&dep);
        let mut repos: Vec<&str> = files.iter().map(|c| c.repo.as_str()).collect();
        repos.dedup();
        for repo in repos {
            let from: Vec<_> = files.iter().filter(|c| c.repo == repo).collect();
            out.push(CheckpointSource {
                repo: repo.to_string(),
                bytes: from.iter().map(|c| c.size).sum(),
                files: from.iter().map(|c| c.path.clone()).collect(),
                dir_name: source_dir(dep.id(), repo),
            });
        }
    }
    out
}

/// The catalog entries `e` requires, in the order it lists them.
fn required_entries(
    e: &tenzro_model::catalog::CatalogEntry,
) -> Vec<tenzro_model::catalog::CatalogEntry> {
    e.requires
        .iter()
        .filter_map(|d| tenzro_model::catalog::entry(&d.entry))
        .collect()
}

/// Whether `model_id` loads from an assembled checkpoint directory rather
/// than its fetched sources: its pipeline reads one directory, and the
/// entry's files come from entries it requires or are placed apart from
/// their repository paths.
fn needs_view(model_id: &str, pipeline_class: &str) -> bool {
    tenzro_model::media_runtime::source_directories(pipeline_class) == 1
        && tenzro_model::catalog::entry(model_id)
            .is_some_and(|e| !e.requires.is_empty() || e.components.iter().any(|c| c.at.is_some()))
}

/// Assemble the one checkpoint directory entry `e` (requiring `deps`) loads:
/// `media/<model>/checkpoint` under `models_dir`, each file of the entry's
/// checkpoint view a hard link to its fetched copy (`fetched` maps a
/// source's directory name to where it was fetched), linked only after the
/// copy's SHA-256 matches its pin. A link already in place is kept while it
/// still is the fetched copy (same length and modification time, which hard
/// links share); anything else in the directory is removed, so no stray
/// weight file is ever loaded.
pub(crate) fn assemble_view(
    models_dir: &Path,
    e: &tenzro_model::catalog::CatalogEntry,
    deps: &[tenzro_model::catalog::CatalogEntry],
    fetched: &HashMap<String, PathBuf>,
) -> Result<PathBuf, String> {
    let model_id = e.id();
    let view = e.checkpoint_view(deps)?;
    let root = models_dir.join("media").join(model_id).join("checkpoint");
    let mut placed = std::collections::HashSet::new();
    for f in &view {
        let dir_name = source_dir(f.entry, &f.component.repo);
        let src = fetched
            .get(&dir_name)
            .ok_or_else(|| format!("{model_id}: {dir_name} was not fetched"))?
            .join(&f.component.path);
        let dst = root.join(f.at);
        placed.insert(dst.clone());
        if same_copy(&src, &dst) {
            continue;
        }
        let actual = sha256_file(&src)?;
        if actual != f.component.sha256 {
            return Err(format!(
                "{}: SHA-256 {actual} is not the pinned {}",
                src.display(),
                f.component.sha256
            ));
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        if dst.symlink_metadata().is_ok() {
            std::fs::remove_file(&dst).map_err(|e| format!("{}: {e}", dst.display()))?;
        }
        std::fs::hard_link(&src, &dst)
            .map_err(|e| format!("link {} -> {}: {e}", dst.display(), src.display()))?;
    }
    prune(&root, &placed)?;
    Ok(root)
}

/// Whether `dst` is still the hard link to `src` made earlier.
fn same_copy(src: &Path, dst: &Path) -> bool {
    match (std::fs::metadata(src), std::fs::symlink_metadata(dst)) {
        (Ok(a), Ok(b)) => {
            b.is_file()
                && a.len() == b.len()
                && a.modified()
                    .ok()
                    .is_some_and(|m| b.modified().ok() == Some(m))
        }
        _ => false,
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Remove every file and directory under `dir` that is not one of `keep` or
/// an ancestor of one.
fn prune(dir: &Path, keep: &std::collections::HashSet<PathBuf>) -> Result<(), String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        if is_dir && keep.iter().any(|k| k.starts_with(&p)) {
            prune(&p, keep)?;
        } else if !keep.contains(&p) {
            let r = if is_dir {
                std::fs::remove_dir_all(&p)
            } else {
                std::fs::remove_file(&p)
            };
            r.map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    Ok(())
}

/// The directory a source of `model_id` is fetched into: `media/<model>/<owner>--<name>`.
fn source_dir(model_id: &str, repo: &str) -> String {
    format!("media/{model_id}/{}", repo.replace('/', "--"))
}

/// Bytes of weights the catalog entry for `model_id` pins, across every
/// repository it fetches: what its load reserves in the node's memory ledger.
/// Falls back to the entry's declared size.
pub(crate) fn checkpoint_bytes(model_id: &str, declared: u64) -> u64 {
    let pinned: u64 = tenzro_model::catalog::entry(model_id)
        .map(|e| {
            let own: u64 = e.components.iter().map(|c| c.size).sum();
            let required: u64 = required_entries(&e)
                .iter()
                .flat_map(|d| e.required_components(d))
                .map(|c| c.size)
                .sum();
            own + required
        })
        .unwrap_or(0);
    if pinned > 0 { pinned } else { declared }
}

/// Fetch the pinned checkpoint for `model_id` and load it on its engine.
pub(crate) async fn load(
    node: &Arc<TenzroNode>,
    model_id: &str,
    precision: MediaPrecision,
) -> Result<MediaModelInfo, JsonRpcError> {
    let entry = tenzro_model::catalog::runnable_media_gen_model(model_id)
        .map_err(|m| rpc_err(-32010, m))?;
    node.check_model_license(model_id)
        .map_err(|m| rpc_err(-32010, m))?;
    // The weights of every entry it requires are loaded too, under their own licences.
    for dep in tenzro_model::catalog::entry(model_id)
        .map(|e| e.requires)
        .unwrap_or_default()
    {
        node.check_model_license(&dep.entry)
            .map_err(|m| rpc_err(-32010, m))?;
    }
    let mut dirs = Vec::new();
    let mut fetched = HashMap::new();
    for source in checkpoint_sources(model_id, &entry.hf_repo) {
        let total = if source.bytes > 0 {
            source.bytes
        } else {
            entry.size_bytes
        };
        let dir = fetch_pinned(
            node,
            model_id,
            &source.repo,
            source.files,
            source.dir_name.clone(),
            total,
        )
        .await?;
        fetched.insert(source.dir_name, dir.clone());
        dirs.push(dir);
    }
    // A pipeline that reads one directory gets the entry's files assembled
    // into one, hash-checked.
    if needs_view(model_id, &entry.pipeline_class) {
        let models_dir = node.config().effective_models_dir();
        let e = tenzro_model::catalog::entry(model_id)
            .ok_or_else(|| rpc_err(-32010, format!("{model_id} is not in the catalog")))?;
        let view = tokio::task::spawn_blocking(move || {
            assemble_view(&models_dir, &e, &required_entries(&e), &fetched)
        })
        .await
        .map_err(|e| rpc_err(-32603, format!("assemble task: {e}")))?
        .map_err(|m| rpc_err(-32010, m))?;
        dirs = vec![view];
    }

    let runtime = node.media_models.runtime().clone();
    let id = model_id.to_string();
    let bytes = checkpoint_bytes(model_id, entry.size_bytes);
    let pipeline_class = entry.pipeline_class.clone();
    let precision = if entry.load_int8 {
        MediaPrecision::Q8_0
    } else {
        precision
    };
    let info = tokio::task::spawn_blocking(move || {
        runtime.load(&id, &pipeline_class, &dirs, bytes, precision)
    })
    .await
    .map_err(|e| rpc_err(-32603, format!("load task: {e}")))?
    .map_err(|e| rpc_err(-32603, e.to_string()))?;
    Ok(info)
}

/// `tenzro_loadMediaModel`: load a catalog media model into the node.
///
/// Params: `{ model_id, visibility? }`. Weights load at bf16, the only format
/// that passed the quality check against the reference, except for an entry
/// marked `load_int8`, which quantises its bf16 weights to 8 bits at load.
pub(crate) async fn handle_load(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| rpc_err(-32602, "missing params"))?;
    let model_id = crate::rpc::catalog_load_params(&p)?;
    let info = load(node, &model_id, MediaPrecision::Bf16).await?;
    crate::rpc::record_multimodal_visibility(node, "tenzro_loadMediaModel", &p, &model_id)?;
    serde_json::to_value(&info).map_err(|e| rpc_err(-32603, e.to_string()))
}

/// `tenzro_unloadMediaModel`: release a loaded media model.
///
/// Params: `{ model_id }`
pub(crate) async fn handle_unload(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| rpc_err(-32602, "missing params"))?;
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_err(-32602, "missing model_id"))?;
    let removed = unload(node, model_id).await?;
    crate::rpc::forget_multimodal_model(node, model_id);
    Ok(serde_json::json!({ "model_id": model_id, "removed": removed }))
}

/// Stop serving `model_id` and release it.
pub(crate) async fn unload(node: &Arc<TenzroNode>, model_id: &str) -> Result<bool, JsonRpcError> {
    Ok(node.media_models.runtime().unload(model_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_checkpoint_from_several_repositories_fetches_each_into_its_own_directory() {
        tenzro_catalog::install_test_seed();
        let one = checkpoint_sources("z-image-turbo", "Tongyi-MAI/Z-Image-Turbo");
        assert_eq!(one.len(), 1);
        assert_eq!(
            one[0].dir_name,
            "media/z-image-turbo/Tongyi-MAI--Z-Image-Turbo"
        );
        assert!(one[0].files.contains(&"model_index.json".to_string()));

        let ltx = checkpoint_sources("ltx-2.3-22b-dev", "Lightricks/LTX-2.3");
        let repos: Vec<_> = ltx.iter().map(|s| s.repo.as_str()).collect();
        assert_eq!(repos, ["Lightricks/LTX-2.3", "Lightricks/LTX-2"]);
        assert_eq!(ltx[0].files, ["ltx-2.3-22b-dev.safetensors"]);
        assert!(
            ltx[1]
                .files
                .contains(&"tokenizer/tokenizer.json".to_string())
        );
        assert!(
            ltx[1]
                .files
                .iter()
                .all(|f| f.starts_with("text_encoder/") || f.starts_with("tokenizer/"))
        );
        assert_ne!(ltx[0].dir_name, ltx[1].dir_name);
        assert!(ltx.iter().all(|s| s.bytes > 0));
        let pinned: u64 = ltx.iter().map(|s| s.bytes).sum();
        assert_eq!(pinned, checkpoint_bytes("ltx-2.3-22b-dev", 0));

        // The quantised distilled build: split checkpoint, upsampler and
        // prompt encoder each come from their own repository.
        let q5 = checkpoint_sources("ltx-2.3-22b-distilled-gguf", "Lightricks/LTX-2.3");
        let repos: Vec<_> = q5.iter().map(|s| s.repo.as_str()).collect();
        assert_eq!(
            repos,
            [
                "Lightricks/LTX-2.3",
                "unsloth/LTX-2.3-GGUF",
                "Lightricks/LTX-2"
            ]
        );
        assert_eq!(q5[0].files, ["ltx-2.3-spatial-upscaler-x2-1.1.safetensors"]);
        assert!(
            q5[1]
                .files
                .contains(&"distilled-1.1/ltx-2.3-22b-distilled-1.1-UD-Q5_K_M.gguf".to_string())
        );
        assert_eq!(q5[1].files.len(), 4);
        assert_eq!(
            q5.iter().map(|s| s.bytes).sum::<u64>(),
            checkpoint_bytes("ltx-2.3-22b-distilled-gguf", 0)
        );
    }

    #[test]
    fn a_single_directory_pipeline_loads_a_hash_checked_view_of_its_sources() {
        use sha2::{Digest, Sha256};
        tenzro_catalog::install_test_seed();
        let mut e = tenzro_model::catalog::entry("minimax-h3-fl2va-gguf").expect("catalogued");
        let mut deps = required_entries(&e);
        assert!(needs_view(
            "minimax-h3-fl2va-gguf",
            "MiniMaxH3ModularPipeline"
        ));
        assert!(!needs_view("z-image-turbo", "ZImagePipeline"));
        assert!(
            !needs_view("ltx-2.3-22b-distilled-gguf", "LTX2Pipeline"),
            "a two-directory pipeline reads its sources"
        );

        // Stand-in bytes for every pinned file, fetched where the node fetches them.
        let models = std::env::temp_dir().join(format!("tz-view-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&models);
        let mut fetched = HashMap::new();
        let mut write = |entry: &str, c: &mut tenzro_model::catalog::Component| {
            let dir_name = source_dir(entry, &c.repo);
            let dir = models.join(&dir_name);
            let bytes = format!("{}:{}", c.repo, c.path).into_bytes();
            let path = dir.join(&c.path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            c.sha256 = hex::encode(Sha256::digest(&bytes));
            fetched.insert(dir_name, dir);
        };
        let id = e.id().to_string();
        for c in &mut e.components {
            write(&id, c);
        }
        for d in &mut deps {
            let did = d.id().to_string();
            for c in &mut d.components {
                write(&did, c);
            }
        }
        let root = assemble_view(&models, &e, &deps, &fetched).unwrap();
        assert_eq!(root, models.join("media/minimax-h3-fl2va-gguf/checkpoint"));
        let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap();
        assert_eq!(
            read("transformer/minimax_h3_fl2va_pruned-Q4_K.gguf"),
            "unsloth/MiniMax-H3-GGUF:minimax_h3_fl2va_pruned-Q4_K.gguf"
        );
        assert_eq!(
            read("transformer/config.json"),
            "MiniMaxAI/MiniMax-H3:transformer/config.json"
        );
        assert_eq!(
            read("audio_vae/minimax_h3_audio_vae_fp32.safetensors"),
            "unsloth/MiniMax-H3-GGUF:vae/minimax_h3_audio_vae_fp32.safetensors"
        );
        assert!(
            root.join("tokenizer/tokenizer.json").is_file()
                && !root
                    .join("text_encoder/model.safetensors.index.json")
                    .exists()
        );

        // A stray weight file is removed; a kept link is not re-hashed.
        std::fs::write(root.join("transformer/stray.gguf"), b"x").unwrap();
        assemble_view(&models, &e, &deps, &fetched).unwrap();
        assert!(!root.join("transformer/stray.gguf").exists());

        // Bytes that no longer match their pin are refused, not linked.
        let src = models
            .join(source_dir(&id, "unsloth/MiniMax-H3-GGUF"))
            .join("qwen3vl_32b_minimax_h3-Q4_K_M.gguf");
        std::fs::remove_file(root.join("text_encoder/qwen3vl_32b_minimax_h3-Q4_K_M.gguf")).unwrap();
        std::fs::write(&src, b"tampered").unwrap();
        let err = assemble_view(&models, &e, &deps, &fetched).unwrap_err();
        assert!(err.contains("is not the pinned"), "{err}");
        let _ = std::fs::remove_dir_all(&models);
    }
}
