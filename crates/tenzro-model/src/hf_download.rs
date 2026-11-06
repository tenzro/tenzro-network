//! HuggingFace Hub download integration with optional peer-fetch over the
//! `tenzro://blob/<blake3>` / `tenzro://model/<id>@<blake3>` URI scheme.
//!
//! Downloads model artifacts from HuggingFace Hub via direct HTTPS to the
//! HF CDN, with progress tracking and local file management. Supports two
//! artifact shapes:
//!
//! - [`ArtifactSpec::SingleFile`]: a single file at
//!   `https://huggingface.co/<repo>/resolve/main/<filename>`. Used by GGUF
//!   LLMs and single-file ONNX models (vision encoders, Moonshine).
//! - [`ArtifactSpec::Bundle`]: a directory of files (encoder + decoder +
//!   tokenizer, etc.). Used by multi-file ONNX models like Whisper /
//!   Distil-Whisper / Parakeet RNN-T.
//!
//! `HfDownloader` is the GGUF-oriented downloader used by LLM callers
//! (CLI, RPC handlers). It exposes GGUF-specific helpers (`model_path`,
//! `is_downloaded`, `downloaded_size`, `verify_download` with size
//! tolerance). New modality runtimes use [`HfArtifactDownloader::download`]
//! directly to access the full single-file / bundle artifact shape.
//!
//! # Peer fetch over `tenzro://`
//!
//! When a [`BlobFetcher`] is wired via
//! [`HfArtifactDownloader::with_blob_fetcher`] (typically
//! `tenzro_iroh::IrohBackedResolver` adapted on the node side) and an
//! [`ArtifactSpec`] carries a `tenzro_uri` peer hint, the downloader tries
//! the peer fetch *first* and falls back to the HF CDN on any error
//! (missing blob, BLAKE3 mismatch, transport failure). Optional
//! `sha256_hex` is checked against the fetched bytes as a
//! defense-in-depth layer on top of iroh-blobs' own BLAKE3 verification.
//!
//! When a download completes via the HF CDN path *and* a fetcher is
//! wired, the downloader opportunistically publishes the bytes via
//! [`BlobFetcher::publish_file`] so neighbour nodes can subsequently fetch by
//! content hash without re-pulling from HF, the same pattern training
//! blobs follow.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use tenzro_types::tenzro_uri::TenzroUri;

use crate::catalog::HfModelEntry;
use crate::error::{ModelError, Result};

/// Maximum allowable size deviation (5%) before flagging a download as corrupt.
/// GGUF files vary slightly across quantization rebuilds, so we allow some tolerance.
const SIZE_TOLERANCE_PERCENT: f64 = 5.0;

/// Download progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadProgress {
    pub model_id: String,
    pub status: DownloadState,
    pub progress_percent: f64,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
}

/// State of a model download
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadState {
    Pending,
    Downloading,
    Completed,
    Failed,
}

impl std::fmt::Display for DownloadState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Downloading => write!(f, "downloading"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Per-file peer-fetch hint for the `tenzro://` distribution path.
///
/// When [`HfArtifactDownloader`] is wired with a [`BlobFetcher`], any file
/// that carries a `PeerHint` is fetched from peers via the URI first; the
/// HF CDN is only contacted if the peer fetch fails (missing blob, hash
/// mismatch, transport error). The optional `sha256_hex` is verified
/// against the fetched bytes as a defense-in-depth check on
/// top of iroh-blobs' own BLAKE3 transport verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHint {
    /// `tenzro://` URI naming the blob. Typically a `tenzro://blob/<blake3>`
    /// or `tenzro://model/<id>@<blake3>` form. The transport layer maps
    /// this to its content-addressed locator (BLAKE3 for iroh-blobs).
    pub tenzro_uri: TenzroUri,
    /// Optional canonical SHA-256 of the file bytes. When present, the
    /// downloader verifies it against the fetched payload regardless of
    /// transport (peer-fetch *or* HF CDN). Mismatch on the peer path
    /// triggers fallback to HF; mismatch on HF surfaces as
    /// [`ModelError::ChecksumMismatch`].
    pub sha256_hex: Option<String>,
}

/// Where a download is allowed to source its bytes from.
///
/// The network offers two source classes: the centralized HuggingFace Hub,
/// and the set of verified network providers that hold the blob at its
/// content hash (BLAKE3, checked over the whole transfer, plus the canonical
/// SHA-256 as defense-in-depth). A caller picks the policy that fits their
/// trust and reachability constraints — a node in a jurisdiction where the
/// HF CDN is blocked selects [`Network`], which never contacts HF.
///
/// [`Network`]: SourcePolicy::Network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SourcePolicy {
    /// Network-first, HuggingFace fallback. Tries verified providers over
    /// `tenzro://` first; on any peer-side failure (or absent hint / fetcher)
    /// streams from the HF CDN. The default — maximizes availability.
    #[default]
    Auto,
    /// Verified network providers only. Fetches the content-addressed blob
    /// from a verified holder and never contacts the HF CDN. Fails if no
    /// verified provider currently holds the blob. Use this to stay
    /// independent of HuggingFace (blocked, rate-limited, or by preference).
    Network,
    /// Centralized HuggingFace Hub only. Skips the peer path and streams
    /// directly from the HF CDN.
    HuggingFace,
}

impl SourcePolicy {
    /// Whether this policy permits fetching from verified network providers.
    pub fn allows_network(self) -> bool {
        matches!(self, Self::Auto | Self::Network)
    }

    /// Whether this policy permits falling back to the HuggingFace CDN.
    pub fn allows_huggingface(self) -> bool {
        matches!(self, Self::Auto | Self::HuggingFace)
    }
}

/// Specification of an artifact to download from HuggingFace Hub.
///
/// `SingleFile` is a single file (GGUF, single-file ONNX) saved as
/// `<storage_path>/<model_id>.<extension>`. `Bundle` is a directory of
/// related files (encoder + decoder + tokenizer for ASR / multi-file
/// ONNX) saved under `<storage_path>/<dir_name>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactSpec {
    /// Single file artifact — `<storage_path>/<model_id>.<extension>`.
    SingleFile {
        /// Filename inside the HF repo (e.g., `"qwen3-8b-q4_k_m.gguf"`).
        filename: String,
        /// File extension to use locally (no leading dot). The download
        /// destination is `<storage_path>/<model_id>.<extension>`.
        extension: String,
        /// Optional `tenzro://` peer-fetch hint. When wired with a
        /// [`BlobFetcher`], the downloader prefers this over HF CDN.
        peer_hint: Option<PeerHint>,
    },
    /// Multi-file bundle — `<storage_path>/<dir_name>/<file1>`, …
    /// All files are downloaded into the same local directory, named
    /// `dir_name`. The directory is created atomically via tmp-dir-rename:
    /// downloads land in `<dir_name>.tmp/` and the dir is renamed once
    /// every file completes successfully.
    Bundle {
        /// Filenames inside the HF repo (e.g.,
        /// `["encoder_model.onnx", "decoder_model.onnx", "tokenizer.json"]`).
        files: Vec<String>,
        /// Local directory name (relative to storage_path).
        dir_name: String,
        /// Per-file peer-fetch hints. When present, the entry for
        /// `files[i]` is `peer_hints[i]`. Length-equal-to-`files` when
        /// non-empty (caller's contract); shorter / mismatched lengths
        /// are tolerated as "no hint for that file".
        peer_hints: Vec<Option<PeerHint>>,
    },
}

/// Transport-agnostic interface for fetching and publishing bytes by
/// `tenzro://` URI. Implemented by `tenzro_iroh::IrohBackedResolver` on the
/// node side — kept as a trait here so `tenzro-model` stays free of any
/// `tenzro-iroh` (or iroh) runtime dependency.
///
/// `fetch` returns the raw blob bytes. `publish` ingests bytes and
/// returns the resulting `tenzro://blob/<hash>` URI so neighbours can
/// re-fetch the same payload by content hash.
///
/// Errors are surfaced as plain `String` to keep the trait
/// cross-crate-friendly without forcing a shared error type — the caller
/// logs the message and falls back to the HF CDN on any error.
#[async_trait]
pub trait BlobFetcher: Send + Sync {
    /// Fetch the bytes named by `uri` from a peer.
    async fn fetch(&self, uri: &TenzroUri) -> std::result::Result<Bytes, String>;
    /// Publish `bytes` to the blob store, returning a content-addressed
    /// `tenzro://blob/<hash>` URI.
    async fn publish(&self, bytes: Bytes) -> std::result::Result<TenzroUri, String>;
    /// Publish a file already on disk without reading it into memory or
    /// copying its bytes. Model artifacts are multi-gigabyte, so this is the
    /// path every download-side publish takes; `publish` remains for callers
    /// that only hold bytes.
    async fn publish_file(&self, path: &Path) -> std::result::Result<TenzroUri, String>;
    /// Bind the blob `uri` names to the model licence `licence` before its
    /// bytes enter the store, so they are served only to nodes whose
    /// operator accepted it. A fetcher that cannot bind refuses, and the
    /// weights are not fetched.
    async fn bind_licence(
        &self,
        uri: &TenzroUri,
        licence: &str,
    ) -> std::result::Result<(), String> {
        Err(format!(
            "this blob fetcher cannot bind {uri} to the licence {licence}"
        ))
    }
}

/// Generic artifact downloader for HuggingFace Hub.
///
/// Wraps the same storage path as [`HfDownloader`] but accepts an
/// [`ArtifactSpec`] so callers can request single-file (GGUF, single-file
/// ONNX) or multi-file (Whisper-style ONNX bundle) artifacts through a
/// single API.
///
/// When wired with [`HfArtifactDownloader::with_blob_fetcher`], any
/// artifact whose spec carries a [`PeerHint`] is fetched over
/// `tenzro://` first and only falls back to the HF CDN on failure.
/// Successful HF downloads are opportunistically published via
/// [`BlobFetcher::publish_file`] so neighbours can avoid re-pulling.
pub struct HfArtifactDownloader {
    storage_path: PathBuf,
    blob_fetcher: Option<Arc<dyn BlobFetcher>>,
    accepted_licences: Vec<String>,
}

/// Manages downloading GGUF models from HuggingFace Hub.
///
/// Used by LLM callers (CLI, RPC handlers). Exposes GGUF-specific
/// helpers (`model_path`, `is_downloaded`, `downloaded_size`,
/// `verify_download` with size tolerance). For multi-file ONNX bundles
/// or single-file ONNX, use [`HfArtifactDownloader::download`] directly.
///
/// When wired with [`HfDownloader::with_blob_fetcher`], a runtime-supplied
/// [`PeerHint`] is tried before the HF CDN (same pattern as
/// [`HfArtifactDownloader`]). Successful HF downloads are opportunistically
/// published so neighbours can fetch by content hash next time.
pub struct HfDownloader {
    storage_path: PathBuf,
    blob_fetcher: Option<Arc<dyn BlobFetcher>>,
    accepted_licences: Vec<String>,
}

impl HfDownloader {
    /// Create a new downloader that stores models at the given path.
    pub fn new(storage_path: PathBuf) -> Self {
        Self {
            storage_path,
            blob_fetcher: None,
            accepted_licences: Vec::new(),
        }
    }

    /// Attach a [`BlobFetcher`] so the downloader can fetch and publish
    /// over `tenzro://` URIs. Returns `self` for builder-style chaining.
    pub fn with_blob_fetcher(mut self, fetcher: Arc<dyn BlobFetcher>) -> Self {
        self.blob_fetcher = Some(fetcher);
        self
    }

    /// The ids of the model licences the operator accepted
    /// (`--accept-license`). Weights their origin gates behind a licence are
    /// fetched only when it is among them.
    pub fn with_accepted_licences(mut self, ids: Vec<String>) -> Self {
        self.accepted_licences = ids;
        self
    }

    /// Returns true if a [`BlobFetcher`] is wired.
    pub fn has_blob_fetcher(&self) -> bool {
        self.blob_fetcher.is_some()
    }

    /// Get the local file path for a model.
    ///
    /// Single-file GGUFs live at `<storage>/<id>.gguf`. Sharded
    /// (gguf-split) GGUFs live at `<storage>/<id>/<...-00001-of-000NN.gguf>`
    /// — when that directory exists, return its first shard so callers
    /// (sidecar, loaders) get the path llama.cpp auto-continues from.
    pub fn model_path(&self, model_id: &str) -> PathBuf {
        if let Some(first_shard) = self.sharded_first_shard(model_id) {
            return first_shard;
        }
        self.storage_path.join(format!("{}.gguf", model_id))
    }

    /// Local path for a model's multimodal projector (mmproj). Stored flat
    /// as `<storage>/<id>.mmproj.gguf` regardless of whether the language
    /// model is single-file or sharded, so the sidecar can resolve it from
    /// the model id alone. Only present for vision-capable entries whose
    /// catalog `mmproj` is `Some`.
    pub fn mmproj_path(&self, model_id: &str) -> PathBuf {
        self.storage_path.join(format!("{}.mmproj.gguf", model_id))
    }

    /// If `model_id` was downloaded as a shard set, return the path to its
    /// first shard inside `<storage>/<id>/`. Returns `None` for single-file
    /// or absent models.
    fn sharded_first_shard(&self, model_id: &str) -> Option<PathBuf> {
        let dir = self.storage_path.join(model_id);
        if !dir.is_dir() {
            return None;
        }
        std::fs::read_dir(&dir)
            .ok()?
            .filter_map(|e| e.ok())
            .find_map(|e| {
                let name = e.file_name();
                let name = name.to_str()?;
                (name.contains("-00001-of-") && name.ends_with(".gguf")).then(|| e.path())
            })
    }

    /// Resolve the on-disk GGUF for `model_id`, whatever layout it landed in.
    ///
    /// Three layouts exist because three writers produced them: a shard set
    /// under `<storage>/<id>/` with the `-00001-of-` naming, a flat
    /// `<storage>/<id>.gguf`, and a single unshard-named `.gguf` sitting alone
    /// inside `<storage>/<id>/`.
    ///
    /// This is the one place that knows the rule. It used to be four places —
    /// three of them hand-rolled `$HOME/.tenzro/models` probes inside
    /// `tenzro-node`, written because the CLI and the node resolved their
    /// model directories differently and each had to go looking in the other's.
    /// They now share one directory, so the probes are gone and the layout
    /// question is answered by the crate that owns the layout.
    ///
    /// Returns `None` when nothing matching is on disk.
    pub fn resolve_local_gguf(&self, model_id: &str) -> Option<PathBuf> {
        if let Some(shard) = self.sharded_first_shard(model_id) {
            return Some(shard);
        }
        let flat = self.storage_path.join(format!("{}.gguf", model_id));
        if flat.exists() {
            return Some(flat);
        }
        let dir = self.storage_path.join(model_id);
        if !dir.is_dir() {
            return None;
        }
        std::fs::read_dir(&dir)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|ext| ext == "gguf"))
    }

    /// Check if a model is already downloaded locally.
    ///
    /// Also cleans up broken symlinks left over from previous versions that
    /// symlinked to the ephemeral HF cache inside the container.
    pub fn is_downloaded(&self, model_id: &str) -> bool {
        if self.sharded_first_shard(model_id).is_some() {
            return true;
        }
        let path = self.storage_path.join(format!("{}.gguf", model_id));
        // Clean up broken symlinks (target gone after container restart)
        #[cfg(unix)]
        {
            if path.is_symlink() && !path.exists() {
                info!("Cleaning up broken symlink: {}", path.display());
                let _ = std::fs::remove_file(&path);
                return false;
            }
        }
        path.exists()
    }

    /// Get the file size of a downloaded model, if present. For sharded
    /// models this sums every shard so callers see the full on-disk size.
    pub fn downloaded_size(&self, model_id: &str) -> Option<u64> {
        if self.sharded_first_shard(model_id).is_some() {
            let dir = self.storage_path.join(model_id);
            let total: u64 = std::fs::read_dir(&dir)
                .ok()?
                .filter_map(|e| e.ok())
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum();
            return Some(total);
        }
        let path = self.storage_path.join(format!("{}.gguf", model_id));
        std::fs::metadata(&path).ok().map(|m| m.len())
    }

    /// Fetch a file the network publishes with no hub copy, by its BLAKE3
    /// content address alone, from the storage providers that hold it, to
    /// `<storage>/<model_id>.gguf`. The bytes are kept only if they are
    /// `size` bytes with that BLAKE3 and SHA-256 `sha256_hex`; anything else
    /// is refused and nothing is written.
    pub async fn fetch_network_file(
        &self,
        model_id: &str,
        blake3_hex: &str,
        sha256_hex: &str,
        size: u64,
    ) -> Result<PathBuf> {
        let fetcher = self.blob_fetcher.as_ref().ok_or_else(|| {
            ModelError::DownloadError(format!(
                "{model_id}: this node has no peer network to fetch it from"
            ))
        })?;
        let hint = PeerHint {
            tenzro_uri: TenzroUri::Blob {
                hash: blake3_hex.to_ascii_lowercase(),
                provider_hint: None,
            },
            sha256_hex: Some(sha256_hex.to_string()),
        };
        let dest_path = self.model_path(model_id);
        let tmp_path = dest_path.with_extension("gguf.tmp");
        let (progress_tx, _rx) = watch::channel(DownloadProgress {
            model_id: model_id.to_string(),
            status: DownloadState::Downloading,
            progress_percent: 0.0,
            downloaded_bytes: 0,
            total_bytes: size,
        });
        fetch_from_provider(
            model_id,
            &hint,
            size,
            sha256_hex,
            fetcher,
            &dest_path,
            &tmp_path,
            &progress_tx,
        )
        .await?
        .map_err(|reason| ModelError::DownloadError(format!("{model_id}: {reason}")))?;
        Ok(dest_path)
    }

    /// Download a model from HuggingFace Hub.
    ///
    /// When `peer_hint` is `Some` and a [`BlobFetcher`] is wired, the
    /// downloader first tries to pull the GGUF over `tenzro://` from a
    /// peer. On any peer-side failure (or absent hint / fetcher) it
    /// falls back to streaming the GGUF file from the HF CDN to
    /// `<storage_path>/<model_id>.gguf` via a tmp-rename for atomicity.
    /// On successful HF-CDN downloads, the bytes are opportunistically
    /// published via the wired [`BlobFetcher`] so neighbours can fetch
    /// from us next time.
    ///
    /// Progress updates are sent via `progress_tx`.
    pub async fn download_model(
        &self,
        entry: &HfModelEntry,
        peer_hint: Option<&PeerHint>,
        policy: SourcePolicy,
        progress_tx: watch::Sender<DownloadProgress>,
    ) -> Result<PathBuf> {
        // Sharded (gguf-split) GGUFs: the catalog `hf_filename` points at
        // the first shard (`...-00001-of-000NN.gguf`). llama.cpp only
        // auto-continues a split set when every shard sits in the same
        // directory under its original name, so we can't flatten to
        // `<id>.gguf` like a single-file model. Download all NN shards
        // into `<storage>/<id>/` and return the first-shard path.
        if let Some((prefix, total, ext_suffix)) = crate::catalog::shard_spec(&entry.hf_filename) {
            return self
                .download_sharded(entry, &prefix, total, &ext_suffix, policy, progress_tx)
                .await;
        }

        let dest_path = self.model_path(&entry.id);
        let tmp_path = dest_path.with_extension("gguf.tmp");
        // Whatever the source, the bytes must be the ones the catalog pins.
        let pin = require_pin(&entry.hf_repo, &entry.hf_filename, &self.accepted_licences)?;
        let source = fetch_pinned(
            &entry.id,
            &pin,
            peer_hint,
            self.blob_fetcher.as_ref(),
            policy,
            &dest_path,
            &tmp_path,
            &progress_tx,
        )
        .await?;

        if source == Fetched::Hub {
            /*
             * Advisory only, and deliberately so.
             *
             * This compares the file against the catalog's hand-maintained `size_bytes`, which is not
             * authoritative: the `gemma4-e2b-mtp-draft` entry claimed 200 MB for a file the server
             * serves as 97,817,664 bytes, so a correct download reported a "mismatch" on every run.
             * Failing closed here would have made a good model unusable.
             *
             * Truncation is caught in `download_one_file` against the server's Content-Length, which is
             * the check that can actually be trusted. This one only flags that the catalog and reality
             * disagree -- worth knowing, never worth refusing a download over.
             */
            if let Err(e) = self.verify_download(&entry.id, entry.size_bytes) {
                warn!(
                    "{}: on-disk size disagrees with the catalog ({}). The download itself was verified \
                     against the server's Content-Length; this points at a stale catalog entry, not a \
                     corrupt file.",
                    entry.id, e
                );
            }

            // Opportunistic publish so neighbours can fetch from us next time.
        }

        self.download_mmproj(entry, policy, &progress_tx).await?;

        Ok(dest_path)
    }

    /// Download a vision-capable model's multimodal projector (mmproj)
    /// from the model's own repo into `<storage>/<id>.mmproj.gguf`. No-op
    /// when the entry has no `mmproj`. A projector failure is logged but
    /// NOT fatal — the language model still serves text-only, which is
    /// strictly better than failing the whole download.
    async fn download_mmproj(
        &self,
        entry: &HfModelEntry,
        policy: SourcePolicy,
        progress_tx: &watch::Sender<DownloadProgress>,
    ) -> Result<()> {
        let Some(mmproj) = entry.mmproj.as_ref() else {
            return Ok(());
        };
        let dest_path = self.mmproj_path(&entry.id);
        if dest_path.exists() {
            return Ok(());
        }
        let tmp_path = dest_path.with_extension("gguf.tmp");

        let fetched = match require_pin(&entry.hf_repo, &mmproj.filename, &self.accepted_licences) {
            Ok(pin) => fetch_pinned(
                &format!("{}/mmproj", entry.id),
                &pin,
                None,
                self.blob_fetcher.as_ref(),
                policy,
                &dest_path,
                &tmp_path,
                progress_tx,
            )
            .await
            .map(|_| ()),
            Err(e) => Err(e),
        };
        if let Err(e) = fetched {
            warn!(
                "{}: mmproj projector download failed ({}); model will serve text-only",
                entry.id, e
            );
        }
        Ok(())
    }

    /// Download a gguf-split shard set into `<storage>/<id>/`, preserving
    /// the original shard filenames so llama.cpp auto-continues from the
    /// first shard. `prefix`/`total`/`ext_suffix` come from
    /// [`crate::catalog::shard_spec`] on the first-shard `hf_filename`. The remote
    /// path may carry a subdir (e.g. `Q4_K_M/Model-...-00001-of-000NN.gguf`)
    /// but every shard lands flat in the model dir under its bare name.
    /// Returns the path to the first shard.
    async fn download_sharded(
        &self,
        entry: &HfModelEntry,
        prefix: &str,
        total: u32,
        ext_suffix: &str,
        policy: SourcePolicy,
        progress_tx: watch::Sender<DownloadProgress>,
    ) -> Result<PathBuf> {
        // Remote dir prefix (everything before the bare shard filename),
        // kept so we can rebuild each shard's remote path.
        let remote_dir = entry
            .hf_filename
            .rsplit_once('/')
            .map(|(d, _)| format!("{}/", d))
            .unwrap_or_default();

        let dest_dir = self.storage_path.join(&entry.id);
        let tmp_dir = self.storage_path.join(format!("{}.tmp", entry.id));

        // A tmp dir an interrupted attempt left is kept: each shard in it that
        // still hashes to its pin is not fetched again. It is never served from.
        std::fs::create_dir_all(&tmp_dir).map_err(|e| {
            ModelError::DownloadError(format!(
                "Failed to create shard tmp dir {}: {}",
                tmp_dir.display(),
                e
            ))
        })?;

        for idx in 1..=total {
            let shard_name = format!("{}-{:05}-of-{:05}{}", prefix, idx, total, ext_suffix);
            let remote_filename = format!("{}{}", remote_dir, shard_name);
            let shard_dest = tmp_dir.join(&shard_name);
            let shard_tmp = tmp_dir.join(format!("{}.tmp", shard_name));

            let fetched =
                match require_pin(&entry.hf_repo, &remote_filename, &self.accepted_licences) {
                    Ok(pin) => fetch_pinned(
                        &format!("{}/{}", entry.id, shard_name),
                        &pin,
                        None,
                        self.blob_fetcher.as_ref(),
                        policy,
                        &shard_dest,
                        &shard_tmp,
                        &progress_tx,
                    )
                    .await
                    .map(|_| ()),
                    Err(e) => Err(e),
                };
            fetched.inspect_err(|_| {
                // Only the shard that failed is dropped; the set is renamed
                // into place only once every shard is there.
                let _ = std::fs::remove_file(&shard_tmp);
            })?;
        }

        if dest_dir.exists() {
            std::fs::remove_dir_all(&dest_dir).map_err(|e| {
                ModelError::DownloadError(format!(
                    "Failed to clear existing shard dir {}: {}",
                    dest_dir.display(),
                    e
                ))
            })?;
        }
        std::fs::rename(&tmp_dir, &dest_dir).map_err(|e| {
            ModelError::DownloadError(format!(
                "Failed to finalize shard dir {} -> {}: {}",
                tmp_dir.display(),
                dest_dir.display(),
                e
            ))
        })?;

        let first_shard =
            dest_dir.join(format!("{}-{:05}-of-{:05}{}", prefix, 1, total, ext_suffix));

        let _ = progress_tx.send(DownloadProgress {
            model_id: entry.id.clone(),
            status: DownloadState::Completed,
            progress_percent: 100.0,
            downloaded_bytes: entry.size_bytes,
            total_bytes: entry.size_bytes,
        });

        info!(
            "Sharded download completed: {} ({} shards in {})",
            entry.id,
            total,
            dest_dir.display()
        );

        self.download_mmproj(entry, policy, &progress_tx).await?;

        Ok(first_shard)
    }

    /// Verify a downloaded model file against expected metadata.
    ///
    /// Checks that the file exists and its size is within
    /// [`SIZE_TOLERANCE_PERCENT`] of `expected_size_bytes`. GGUF files
    /// from HuggingFace can vary slightly across re-quantizations, so a
    /// strict byte-equal check would cause false negatives.
    ///
    /// If the file is missing or the size deviates beyond the tolerance,
    /// returns an error describing the mismatch.
    pub fn verify_download(&self, model_id: &str, expected_size_bytes: u64) -> Result<()> {
        let path = self.model_path(model_id);

        if !path.exists() {
            return Err(ModelError::DownloadError(format!(
                "Downloaded file not found: {}",
                path.display()
            )));
        }

        let actual_size = std::fs::metadata(&path)
            .map_err(|e| ModelError::DownloadError(format!("Cannot stat file: {}", e)))?
            .len();

        if actual_size == 0 {
            return Err(ModelError::DownloadError(format!(
                "Downloaded file is empty: {}",
                path.display()
            )));
        }

        // Check size deviation
        if expected_size_bytes > 0 {
            let deviation = if actual_size > expected_size_bytes {
                (actual_size - expected_size_bytes) as f64 / expected_size_bytes as f64 * 100.0
            } else {
                (expected_size_bytes - actual_size) as f64 / expected_size_bytes as f64 * 100.0
            };

            if deviation > SIZE_TOLERANCE_PERCENT {
                return Err(ModelError::ChecksumMismatch {
                    expected: format!("{} bytes", expected_size_bytes),
                    actual: format!("{} bytes ({:.1}% deviation)", actual_size, deviation),
                });
            }

            info!(
                "Download verified: {} ({} bytes, {:.1}% deviation from catalog)",
                model_id, actual_size, deviation
            );
        }

        Ok(())
    }

    /// Delete a downloaded model from local storage.
    ///
    /// Removes the GGUF file from the persistent models directory and any
    /// partial `.tmp` download files.
    pub fn delete_model(&self, model_id: &str) -> Result<()> {
        // Sharded models live in a per-id directory — remove the whole set
        // (shards + any leftover .tmp) in one shot.
        let shard_dir = self.storage_path.join(model_id);
        if shard_dir.is_dir() {
            std::fs::remove_dir_all(&shard_dir).map_err(|e| {
                ModelError::DownloadError(format!("Failed to delete shard dir: {}", e))
            })?;
            info!("Deleted sharded model dir: {}", shard_dir.display());
        }
        let shard_tmp_dir = self.storage_path.join(format!("{}.tmp", model_id));
        if shard_tmp_dir.is_dir() {
            let _ = std::fs::remove_dir_all(&shard_tmp_dir);
        }

        // Multimodal projector, if any.
        let mmproj = self.mmproj_path(model_id);
        if mmproj.exists() {
            let _ = std::fs::remove_file(&mmproj);
            info!("Deleted mmproj projector: {}", mmproj.display());
        }

        let path = self.storage_path.join(format!("{}.gguf", model_id));

        // Clean up any .tmp partial download files
        let tmp_path = self.storage_path.join(format!("{}.gguf.tmp", model_id));
        if tmp_path.exists() {
            let _ = std::fs::remove_file(&tmp_path);
            info!("Deleted partial download: {}", tmp_path.display());
        }

        // Clean up broken symlinks left over from older versions
        #[cfg(unix)]
        {
            if path.is_symlink() && !path.exists() {
                let _ = std::fs::remove_file(&path);
                info!("Cleaned up broken symlink: {}", path.display());
                return Ok(());
            }
        }

        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                ModelError::DownloadError(format!("Failed to delete model file: {}", e))
            })?;
            info!("Deleted model file: {}", path.display());
        }
        Ok(())
    }

    /// List all downloaded model files.
    pub fn list_downloaded(&self) -> Vec<String> {
        let mut models = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.storage_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(ext) = path.extension()
                    && ext == "gguf"
                    && let Some(stem) = path.file_stem()
                {
                    models.push(stem.to_string_lossy().to_string());
                }
            }
        }
        models
    }

    /// Get the storage path.
    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }
}

impl HfArtifactDownloader {
    /// Create a new artifact downloader rooted at `storage_path`.
    pub fn new(storage_path: PathBuf) -> Self {
        Self {
            storage_path,
            blob_fetcher: None,
            accepted_licences: Vec::new(),
        }
    }

    /// Attach a [`BlobFetcher`] so the downloader can fetch and publish
    /// over `tenzro://` URIs. Returns `self` for builder-style chaining.
    pub fn with_blob_fetcher(mut self, fetcher: Arc<dyn BlobFetcher>) -> Self {
        self.blob_fetcher = Some(fetcher);
        self
    }

    /// The ids of the model licences the operator accepted
    /// (`--accept-license`). Weights their origin gates behind a licence are
    /// fetched only when it is among them.
    pub fn with_accepted_licences(mut self, ids: Vec<String>) -> Self {
        self.accepted_licences = ids;
        self
    }

    /// Returns true if a [`BlobFetcher`] is wired.
    pub fn has_blob_fetcher(&self) -> bool {
        self.blob_fetcher.is_some()
    }

    /// Get the storage root.
    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }

    /// Compute the local destination path for an artifact.
    ///
    /// - `SingleFile { extension }` → `<storage>/<model_id>.<extension>`
    /// - `Bundle { dir_name }` → `<storage>/<dir_name>/`
    pub fn artifact_path(&self, model_id: &str, spec: &ArtifactSpec) -> PathBuf {
        match spec {
            ArtifactSpec::SingleFile { extension, .. } => self
                .storage_path
                .join(format!("{}.{}", model_id, extension)),
            ArtifactSpec::Bundle { dir_name, .. } => self.storage_path.join(dir_name),
        }
    }

    /// Returns true if the artifact is already present locally.
    pub fn is_downloaded(&self, model_id: &str, spec: &ArtifactSpec) -> bool {
        let path = self.artifact_path(model_id, spec);
        match spec {
            ArtifactSpec::SingleFile { .. } => path.exists() && path.is_file(),
            ArtifactSpec::Bundle { files, .. } => {
                if !path.is_dir() {
                    return false;
                }
                files.iter().all(|f| path.join(f).is_file())
            }
        }
    }

    /// Download an artifact from `repo` according to `spec`.
    ///
    /// For `SingleFile`, returns the path to the downloaded file. For
    /// `Bundle`, returns the path to the downloaded directory containing
    /// every requested file. Bundles are downloaded into a tmp directory
    /// and renamed atomically once every file completes — partial bundles
    /// never appear in the final location.
    ///
    /// Every file must be pinned in the catalog (see [`require_pin`]); its
    /// pinned size drives progress when the CDN sends no Content-Length.
    ///
    /// `policy` selects which source classes are allowed. [`SourcePolicy::Auto`]
    /// (the default) tries verified network providers first and falls back to
    /// the HF CDN; [`SourcePolicy::Network`] refuses HF entirely and fails if no
    /// verified provider holds the blob; [`SourcePolicy::HuggingFace`] goes
    /// straight to the HF CDN.
    pub async fn download(
        &self,
        model_id: &str,
        repo: &str,
        spec: &ArtifactSpec,
        policy: SourcePolicy,
        progress_tx: watch::Sender<DownloadProgress>,
    ) -> Result<PathBuf> {
        // Ensure storage root exists
        std::fs::create_dir_all(&self.storage_path).map_err(|e| {
            ModelError::DownloadError(format!("Failed to create storage dir: {}", e))
        })?;

        match spec {
            ArtifactSpec::SingleFile {
                filename,
                extension,
                peer_hint,
            } => {
                let dest_path = self
                    .storage_path
                    .join(format!("{}.{}", model_id, extension));
                let tmp_path = dest_path.with_extension(format!("{}.tmp", extension));
                self.fetch_one_file(
                    model_id,
                    repo,
                    filename,
                    peer_hint.as_ref(),
                    &dest_path,
                    &tmp_path,
                    policy,
                    &progress_tx,
                )
                .await?;
                Ok(dest_path)
            }
            ArtifactSpec::Bundle {
                files,
                dir_name,
                peer_hints,
            } => {
                let dest_dir = self.storage_path.join(dir_name);

                // Already complete on disk: nothing to fetch. Every catalog
                // load of an ONNX model came through here, so re-serving one to
                // change its visibility, or restoring it at boot, fetched the
                // whole bundle again — 2.4 GB for a 0.6B embedding model, and a
                // multi-minute window with the old copy still serving. The test
                // is the one `is_downloaded` uses, so the two cannot disagree.
                if dest_dir.is_dir() && files.iter().all(|f| dest_dir.join(f).is_file()) {
                    return Ok(dest_dir);
                }

                let tmp_dir = self.storage_path.join(format!("{}.tmp", dir_name));

                // A tmp dir an interrupted attempt left is kept: each file in it
                // that still hashes to its pin is not fetched again.
                std::fs::create_dir_all(&tmp_dir).map_err(|e| {
                    ModelError::DownloadError(format!(
                        "Failed to create bundle tmp dir {}: {}",
                        tmp_dir.display(),
                        e
                    ))
                })?;

                for (idx, filename) in files.iter().enumerate() {
                    let file_dest = tmp_dir.join(filename);
                    if let Some(parent) = file_dest.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            ModelError::DownloadError(format!(
                                "Failed to create subdir {}: {}",
                                parent.display(),
                                e
                            ))
                        })?;
                    }
                    let file_tmp = file_dest.with_extension({
                        let cur = file_dest
                            .extension()
                            .map(|e| e.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if cur.is_empty() {
                            "tmp".to_string()
                        } else {
                            format!("{}.tmp", cur)
                        }
                    });
                    let file_hint = peer_hints.get(idx).and_then(|h| h.as_ref());
                    self.fetch_one_file(
                        &format!("{}/{}", model_id, filename),
                        repo,
                        filename,
                        file_hint,
                        &file_dest,
                        &file_tmp,
                        policy,
                        &progress_tx,
                    )
                    .await
                    .inspect_err(|_e| {
                        // Only the file that failed is dropped; the bundle is
                        // renamed into place only once every file is there.
                        let _ = std::fs::remove_file(&file_tmp);
                    })?;
                }

                // Atomic rename of the whole bundle directory.
                if dest_dir.exists() {
                    std::fs::remove_dir_all(&dest_dir).map_err(|e| {
                        ModelError::DownloadError(format!(
                            "Failed to clear existing bundle dir {}: {}",
                            dest_dir.display(),
                            e
                        ))
                    })?;
                }
                std::fs::rename(&tmp_dir, &dest_dir).map_err(|e| {
                    ModelError::DownloadError(format!(
                        "Failed to finalize bundle dir {} -> {}: {}",
                        tmp_dir.display(),
                        dest_dir.display(),
                        e
                    ))
                })?;

                info!(
                    "Bundle download completed: {} ({} files in {})",
                    model_id,
                    files.len(),
                    dest_dir.display()
                );

                Ok(dest_dir)
            }
        }
    }

    /// Fetch a single file from a peer first (when a hint is present and
    /// a [`BlobFetcher`] is wired), falling back to the HF CDN on any
    /// peer-side failure. On HF success, the bytes are opportunistically
    /// published so neighbours can fetch by content hash next time.
    ///
    /// Whichever path serves them, the bytes must match the SHA-256 the
    /// catalog pins for this file; an unpinned file is refused outright.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_one_file(
        &self,
        progress_label: &str,
        hf_repo: &str,
        hf_filename: &str,
        peer_hint: Option<&PeerHint>,
        dest_path: &Path,
        tmp_path: &Path,
        policy: SourcePolicy,
        progress_tx: &watch::Sender<DownloadProgress>,
    ) -> Result<()> {
        let pin = require_pin(hf_repo, hf_filename, &self.accepted_licences)?;
        fetch_pinned(
            progress_label,
            &pin,
            peer_hint,
            self.blob_fetcher.as_ref(),
            policy,
            dest_path,
            tmp_path,
            progress_tx,
        )
        .await
        .map(|_| ())
    }
}

/// Which source served a pinned file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fetched {
    Network,
    Hub,
    /// Already at the destination with the pinned hash, from an earlier attempt.
    Kept,
}

/// Whether `path` holds bytes that hash to `sha256`.
async fn holds_pinned(path: &Path, sha256: &str) -> bool {
    if !path.is_file() {
        return false;
    }
    let (path, want) = (path.to_path_buf(), sha256.to_string());
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let Ok(mut f) = std::fs::File::open(&path) else {
            return false;
        };
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            match f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => h.update(&buf[..n]),
                Err(_) => return false,
            }
        }
        hex::encode(h.finalize()) == want
    })
    .await
    .unwrap_or(false)
}

/// Fetch one pinned file to `dest_path` from the sources `policy` allows.
///
/// A file the catalog publishes only to the network is fetched from storage
/// providers at its pinned BLAKE3 address and nowhere else: the hub has no
/// copy, so no policy sends it there. A hub file is tried at `peer_hint` first
/// (when the policy allows the network and a fetcher is wired), then read from
/// the hub at its pinned commit and offered to peers. Whatever the source,
/// bytes that are not the pinned size and SHA-256 are never kept.
#[allow(clippy::too_many_arguments)]
async fn fetch_pinned(
    progress_label: &str,
    pin: &Pin,
    peer_hint: Option<&PeerHint>,
    fetcher: Option<&Arc<dyn BlobFetcher>>,
    policy: SourcePolicy,
    dest_path: &Path,
    tmp_path: &Path,
    progress_tx: &watch::Sender<DownloadProgress>,
) -> Result<Fetched> {
    // A file an earlier attempt finished stays: an interrupted bundle carries
    // on from the file it stopped in instead of from its first byte.
    if holds_pinned(dest_path, &pin.file.sha256).await {
        info!("{progress_label}: already held with the pinned hash; not fetched again");
        return Ok(Fetched::Kept);
    }
    let pinned_address = pin.network_hint();
    if pinned_address.is_some() && !policy.allows_network() {
        return Err(ModelError::DownloadError(format!(
            "{progress_label} is fetched only from the network, and the source policy forbids network fetches"
        )));
    }
    let hint = pinned_address.as_ref().or(peer_hint);

    // Gated weights come from network providers holding them, bound to their
    // licence in this node's store before the first byte arrives so they are
    // passed on only to nodes whose operator accepted it. Failing that, an
    // operator who set their own credential for the origin fetches them from
    // the origin with it; such a copy is never offered to peers.
    if let Some(licence) = &pin.licence {
        let mut why = "no network provider is known to hold it".to_string();
        if policy.allows_network()
            && let (Some(fetcher), Some(hint)) = (fetcher, hint)
        {
            fetcher
                .bind_licence(&hint.tenzro_uri, licence)
                .await
                .map_err(|e| ModelError::DownloadError(format!("{progress_label}: {e}")))?;
            match fetch_from_provider(
                progress_label,
                hint,
                pin.file.size,
                &pin.file.sha256,
                fetcher,
                dest_path,
                tmp_path,
                progress_tx,
            )
            .await?
            {
                Ok(()) => return Ok(Fetched::Network),
                Err(reason) => why = reason,
            }
        } else if !policy.allows_network() {
            why = "the source policy forbids network fetches".to_string();
        }
        let revision = pin.file.revision().filter(|_| policy.allows_huggingface());
        return match (crate::origin_credential::current(), revision) {
            (Some(credential), Some(revision)) => {
                info!(
                    "{progress_label}: gated behind {licence}; fetching from its origin with the \
                     operator's own credential ({why})"
                );
                download_one_file(
                    progress_label,
                    pin,
                    revision,
                    dest_path,
                    tmp_path,
                    progress_tx,
                    Some(&credential),
                )
                .await?;
                Ok(Fetched::Hub)
            }
            _ => Err(ModelError::NoNetworkSource(format!(
                "{progress_label} (gated behind {licence}: {why}; {})",
                crate::origin_credential::HOW_TO_SET
            ))),
        };
    }

    if policy.allows_network()
        && let (Some(fetcher), Some(hint)) = (fetcher, hint)
    {
        debug!(
            target: "tenzro_model::peer_fetch",
            "{}: trying verified-provider fetch via {}",
            progress_label, hint.tenzro_uri
        );
        match fetch_from_provider(
            progress_label,
            hint,
            pin.file.size,
            &pin.file.sha256,
            fetcher,
            dest_path,
            tmp_path,
            progress_tx,
        )
        .await?
        {
            Ok(()) => return Ok(Fetched::Network),
            Err(reason) => {
                warn!(target: "tenzro_model::peer_fetch", "{}: {}", progress_label, reason)
            }
        }
    }

    // A network-only file has no other source, and the `Network` policy never
    // contacts the hub: either way no verified provider served the file.
    let Some(revision) = pin.file.revision().filter(|_| policy.allows_huggingface()) else {
        return Err(ModelError::NoNetworkSource(progress_label.to_string()));
    };

    download_one_file(
        progress_label,
        pin,
        revision,
        dest_path,
        tmp_path,
        progress_tx,
        None,
    )
    .await?;

    // Opportunistic publish so neighbours can fetch from us next time.
    if let Some(fetcher) = fetcher {
        match fetcher.publish_file(dest_path).await {
            Ok(uri) => debug!(
                target: "tenzro_model::peer_fetch",
                "{}: published to peer store as {}",
                progress_label, uri
            ),
            Err(e) => debug!(
                target: "tenzro_model::peer_fetch",
                "{}: opportunistic publish failed ({}), not fatal",
                progress_label, e
            ),
        }
    }
    Ok(Fetched::Hub)
}

/// Fetch one file from a verified storage provider at `hint` and keep it at
/// `dest_path` only if it is `size` bytes, hashes to the BLAKE3 the hint
/// addresses (when it addresses one) and to `sha256`. The outer error is a
/// local write failure; the inner one says why no provider served the bytes.
#[allow(clippy::too_many_arguments)]
async fn fetch_from_provider(
    progress_label: &str,
    hint: &PeerHint,
    size: u64,
    sha256: &str,
    fetcher: &Arc<dyn BlobFetcher>,
    dest_path: &Path,
    tmp_path: &Path,
    progress_tx: &watch::Sender<DownloadProgress>,
) -> Result<std::result::Result<(), String>> {
    let bytes = match fetcher.fetch(&hint.tenzro_uri).await {
        Ok(bytes) => bytes,
        Err(e) => return Ok(Err(format!("verified-provider fetch failed ({e})"))),
    };
    if bytes.len() as u64 != size {
        return Ok(Err(format!(
            "provider served {} bytes but {} are pinned",
            bytes.len(),
            size
        )));
    }
    let addressed = match &hint.tenzro_uri {
        TenzroUri::Blob { hash, .. } | TenzroUri::Model { hash, .. } => Some(hash.as_str()),
        _ => None,
    };
    if let Some(expected) = addressed {
        let actual = blake3::hash(&bytes).to_hex();
        if !actual.as_str().eq_ignore_ascii_case(expected) {
            return Ok(Err(format!(
                "provider-served bytes have BLAKE3 {actual} but the address is {expected}"
            )));
        }
    }
    if let Err(actual) = verify_sha256(&bytes, sha256) {
        return Ok(Err(format!(
            "provider-served bytes hash to {actual} but {sha256} is pinned"
        )));
    }
    write_bytes_atomic(progress_label, &bytes, dest_path, tmp_path, progress_tx).await?;
    info!(
        "{}: served from verified provider ({} bytes via {})",
        progress_label,
        bytes.len(),
        hint.tenzro_uri
    );
    Ok(Ok(()))
}

/// Verify that `bytes` hash to `expected_hex` under SHA-256. Returns the
/// actual hex on mismatch.
fn verify_sha256(bytes: &[u8], expected_hex: &str) -> std::result::Result<(), String> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let actual = hex::encode(hasher.finalize());
    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(actual)
    }
}

/// Write `bytes` to `dest_path` via a tmp-rename, emitting two progress
/// frames (0% → 100%). Used by the peer-fetch path which delivers the
/// payload as a single in-memory buffer.
async fn write_bytes_atomic(
    progress_label: &str,
    bytes: &[u8],
    dest_path: &Path,
    tmp_path: &Path,
    progress_tx: &watch::Sender<DownloadProgress>,
) -> Result<()> {
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ModelError::DownloadError(format!(
                "Failed to create dest parent {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    let total = bytes.len() as u64;
    let _ = progress_tx.send(DownloadProgress {
        model_id: progress_label.to_string(),
        status: DownloadState::Downloading,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: total,
    });

    tokio::fs::write(tmp_path, bytes).await.map_err(|e| {
        ModelError::DownloadError(format!(
            "Failed to write peer payload to {}: {}",
            tmp_path.display(),
            e
        ))
    })?;

    std::fs::rename(tmp_path, dest_path).map_err(|e| {
        ModelError::DownloadError(format!(
            "Failed to rename {} -> {}: {}",
            tmp_path.display(),
            dest_path.display(),
            e
        ))
    })?;

    let _ = progress_tx.send(DownloadProgress {
        model_id: progress_label.to_string(),
        status: DownloadState::Completed,
        progress_percent: 100.0,
        downloaded_bytes: total,
        total_bytes: total,
    });

    Ok(())
}

/// The origin's base URL. Tests point it at a local server.
fn hub_base() -> String {
    #[cfg(test)]
    if let Some(base) = tests::HUB_BASE.lock().unwrap().clone() {
        return base;
    }
    "https://huggingface.co".to_string()
}

/// Turn an origin HTTP failure into something that names the actual problem.
fn explain_hf_status(status: reqwest::StatusCode, repo: &str) -> String {
    match status.as_u16() {
        401 | 403 => format!(
            "the origin returned {status} for {repo}: the repository is gated or private; the node \
             fetches it from the origin only with the operator's own credential, and the origin \
             refused it or none was sent"
        ),
        404 => format!(
            "the origin returned 404 for {repo}. Either the repository or the file within it \
             does not exist; check the catalog entry against the origin."
        ),
        _ => format!("HTTP {status} from the origin for {repo}"),
    }
}

/// A catalog file cleared for download.
#[derive(Debug, Clone)]
pub struct Pin {
    /// Where it is fetched from and the SHA-256 its bytes must have.
    pub file: crate::catalog::Component,
    /// The licence the file's origin gates it behind, which the operator
    /// accepted. A gated file is fetched only from network providers.
    pub licence: Option<String>,
}

impl Pin {
    /// The provider address of a file the catalog publishes only to the
    /// network: its pinned BLAKE3, checked against its pinned SHA-256.
    pub fn network_hint(&self) -> Option<PeerHint> {
        let hash = self.file.network_blake3()?.to_string();
        Some(PeerHint {
            tenzro_uri: TenzroUri::Blob {
                hash,
                provider_hint: None,
            },
            sha256_hex: Some(self.file.sha256.clone()),
        })
    }
}

/// The pin for `repo`/`path`, or a refusal. A file no catalog entry hashes is
/// never downloaded: whatever the Hub served would otherwise become the model
/// this node runs. A file its origin gates behind a licence is cleared only
/// when the operator accepted that licence (`accepted`, from
/// `--accept-license`); it is then fetched from network providers alone.
pub fn require_pin(repo: &str, path: &str, accepted: &[String]) -> Result<Pin> {
    let (entry, file) = crate::catalog::file(repo, path).ok_or_else(|| {
        ModelError::DownloadError(format!(
            "{repo}/{path} is hashed by no entry in this node's catalog; refusing to download it"
        ))
    })?;
    let licence = accepted_gate(entry.id(), entry.gating_licence(), accepted)?;
    Ok(Pin { file, licence })
}

/// The licence `model_id`'s origin gates it behind, once the operator has
/// accepted it; a refusal naming the flag when not.
fn accepted_gate(
    model_id: &str,
    licence: Option<&str>,
    accepted: &[String],
) -> Result<Option<String>> {
    match licence {
        None => Ok(None),
        Some(id) if accepted.iter().any(|a| a == id) => Ok(Some(id.to_string())),
        Some(id) => Err(ModelError::AccessDenied(format!(
            "{model_id} is gated by its origin behind the licence {id}; read it and accept it with \
             --accept-license {id} before this node fetches the weights"
        ))),
    }
}

async fn download_one_file(
    progress_label: &str,
    pin: &Pin,
    revision: &str,
    dest_path: &Path,
    tmp_path: &Path,
    progress_tx: &watch::Sender<DownloadProgress>,
    credential: Option<&crate::origin_credential::OriginCredential>,
) -> Result<()> {
    let (hf_repo, hf_filename, total_bytes_hint) = (
        pin.file.repo.as_str(),
        pin.file.path.as_str(),
        pin.file.size,
    );
    info!(
        "Starting download: {} from {}/{} at {}",
        progress_label, hf_repo, hf_filename, revision
    );

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ModelError::DownloadError(format!(
                "Failed to create dest parent {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    let _ = progress_tx.send(DownloadProgress {
        model_id: progress_label.to_string(),
        status: DownloadState::Downloading,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: total_bytes_hint,
    });

    // Direct HTTPS to HF CDN — bypasses hf-hub crate due to chunked-transfer
    // issues with HF's xethub CDN in containerized environments. Fetched at
    // the pinned commit, never at a moving branch.
    let download_url = format!(
        "{}/{}/resolve/{}/{}",
        hub_base(),
        hf_repo,
        revision,
        hf_filename
    );
    info!("Downloading from: {}", download_url);

    // `timeout()` bounds the *whole* request, response body included, so any
    // ceiling here is a ceiling on model size: a 22 GB GGUF cannot finish in
    // 600 s below a sustained 37 MB/s, and the stream is cut mid-body with
    // "error decoding response body" no matter how healthy the transfer is.
    // What actually needs bounding is a stalled connection, so bound the
    // connect and the gap between reads instead and let a slow-but-advancing
    // download run as long as it keeps advancing.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .connect_timeout(std::time::Duration::from_secs(30))
        .read_timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| ModelError::DownloadError(format!("Failed to create HTTP client: {}", e)))?;

    // Only a gated file carries the operator's credential, and the client
    // drops it on any redirect off the origin's host.
    let mut request = client.get(&download_url);
    if let Some(credential) = credential {
        let value = credential.header_value().ok_or_else(|| {
            ModelError::DownloadError("the operator's credential is not a valid header".into())
        })?;
        request = request.header(reqwest::header::AUTHORIZATION, value);
    }

    let response = request.send().await.map_err(|e| {
        error!("HTTP download request failed for {}: {}", progress_label, e);
        ModelError::DownloadError(format!("HTTP request failed: {}", e))
    })?;

    if !response.status().is_success() {
        return Err(ModelError::DownloadError(explain_hf_status(
            response.status(),
            hf_repo,
        )));
    }

    // The server's own length, when it sent one. A chunked response sends
    // none, and "unknown" is not "mismatched": the progress bar falls back to
    // the pinned size, the truncation check below does not run, and the hash
    // check still does.
    let advertised_length = response.content_length();
    let content_length = advertised_length.unwrap_or(total_bytes_hint);

    {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::create(tmp_path)
            .await
            .map_err(|e| ModelError::DownloadError(format!("Failed to create temp file: {}", e)))?;

        let mut downloaded: u64 = 0;
        let mut hasher = Sha256::new();
        let mut stream = response.bytes_stream();
        use futures::StreamExt;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| ModelError::DownloadError(format!("Download stream error: {}", e)))?;

            file.write_all(&chunk)
                .await
                .map_err(|e| ModelError::DownloadError(format!("Write error: {}", e)))?;
            hasher.update(&chunk);

            downloaded += chunk.len() as u64;
            let pct = if content_length > 0 {
                (downloaded as f64 / content_length as f64) * 100.0
            } else {
                0.0
            };

            let _ = progress_tx.send(DownloadProgress {
                model_id: progress_label.to_string(),
                status: DownloadState::Downloading,
                progress_percent: pct,
                downloaded_bytes: downloaded,
                total_bytes: content_length,
            });
        }

        file.flush()
            .await
            .map_err(|e| ModelError::DownloadError(format!("Flush error: {}", e)))?;

        /*
         * A short transfer is a corrupt file, and until now it was accepted silently.
         *
         * `content_length` was read from the response and used only to drive the progress bar; nothing
         * compared it against what actually landed on disk. A connection dropped at 90% produced a
         * truncated GGUF that got renamed into place and loaded, and the only signal was a progress bar
         * that never reached 100%.
         *
         * This gates on the SERVER's own Content-Length, not on the catalog's `size_bytes`. The
         * distinction matters: the catalog figure is hand-maintained and demonstrably wrong for at least
         * one entry, so gating on it would reject good downloads. What the server said it was sending is
         * authoritative for whether we received all of it.
         *
         * Only checked when the server advertised a length -- chunked responses omit it, and "unknown"
         * is not "mismatched". The temp file is removed so a retry starts clean rather than resuming
         * onto a truncated prefix.
         */
        if let Some(advertised) = advertised_length
            && downloaded != advertised
        {
            let _ = std::fs::remove_file(tmp_path);
            return Err(ModelError::DownloadError(format!(
                "Truncated download for {}: received {} of {} bytes the server advertised",
                progress_label, downloaded, advertised
            )));
        }

        // The bytes must be the pinned bytes. Checked before the rename, so a
        // file that fails never sits at the path a loader reads from.
        let actual = hex::encode(hasher.finalize());
        if actual != pin.file.sha256 {
            let _ = std::fs::remove_file(tmp_path);
            return Err(ModelError::DownloadError(format!(
                "{}/{} at {} hashed to {} but the catalog pins {}; refusing it",
                hf_repo, hf_filename, revision, actual, pin.file.sha256
            )));
        }
    }

    std::fs::rename(tmp_path, dest_path).map_err(|e| {
        ModelError::DownloadError(format!(
            "Failed to rename {} -> {}: {}",
            tmp_path.display(),
            dest_path.display(),
            e
        ))
    })?;

    let actual_size = std::fs::metadata(dest_path)
        .map(|m| m.len())
        .unwrap_or(total_bytes_hint);

    let _ = progress_tx.send(DownloadProgress {
        model_id: progress_label.to_string(),
        status: DownloadState::Completed,
        progress_percent: 100.0,
        downloaded_bytes: actual_size,
        total_bytes: actual_size,
    });

    info!(
        "Download completed: {} ({} bytes) -> {}",
        progress_label,
        actual_size,
        dest_path.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_path() {
        let dl = HfDownloader::new(PathBuf::from("/tmp/models"));
        assert_eq!(
            dl.model_path("qwen3-4b"),
            PathBuf::from("/tmp/models/qwen3-4b.gguf")
        );
    }

    #[test]
    fn test_download_state_display() {
        assert_eq!(DownloadState::Downloading.to_string(), "downloading");
        assert_eq!(DownloadState::Completed.to_string(), "completed");
    }

    #[test]
    fn parse_shard_spec_first_shard_with_subdir() {
        let (prefix, total, ext) =
            crate::catalog::shard_spec("Q4_K_M/Kimi-K2-Instruct-Q4_K_M-00001-of-00013.gguf")
                .expect("should parse first shard");
        assert_eq!(prefix, "Kimi-K2-Instruct-Q4_K_M");
        assert_eq!(total, 13);
        assert_eq!(ext, ".gguf");
    }

    #[test]
    fn parse_shard_spec_bare_first_shard() {
        let (prefix, total, ext) =
            crate::catalog::shard_spec("DeepSeek-V3-0324-Q4_K_M-00001-of-00009.gguf")
                .expect("should parse bare first shard");
        assert_eq!(prefix, "DeepSeek-V3-0324-Q4_K_M");
        assert_eq!(total, 9);
        assert_eq!(ext, ".gguf");
    }

    #[test]
    fn parse_shard_spec_rejects_single_file() {
        assert!(crate::catalog::shard_spec("Qwen3.5-4B-Q4_K_M.gguf").is_none());
    }

    #[test]
    fn parse_shard_spec_rejects_non_first_shard() {
        // Only the first shard is a valid catalog entry point.
        assert!(crate::catalog::shard_spec("Q4_K_M/Model-00002-of-00009.gguf").is_none());
    }

    #[test]
    fn sharded_model_path_prefers_first_shard() {
        let tmp = std::env::temp_dir().join(format!("tenzro-shard-test-{}", std::process::id()));
        let dir = tmp.join("kimi-k2");
        std::fs::create_dir_all(&dir).unwrap();
        // Write shards out of order to confirm we pick shard 1.
        std::fs::write(dir.join("Kimi-K2-00002-of-00003.gguf"), b"x").unwrap();
        std::fs::write(dir.join("Kimi-K2-00001-of-00003.gguf"), b"x").unwrap();
        std::fs::write(dir.join("Kimi-K2-00003-of-00003.gguf"), b"x").unwrap();

        let dl = HfDownloader::new(tmp.clone());
        assert_eq!(
            dl.model_path("kimi-k2"),
            dir.join("Kimi-K2-00001-of-00003.gguf")
        );
        assert!(dl.is_downloaded("kimi-k2"));
        assert_eq!(dl.downloaded_size("kimi-k2"), Some(3));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn artifact_path_single_file() {
        let dl = HfArtifactDownloader::new(PathBuf::from("/tmp/models"));
        let spec = ArtifactSpec::SingleFile {
            filename: "model.onnx".to_string(),
            extension: "onnx".to_string(),
            peer_hint: None,
        };
        assert_eq!(
            dl.artifact_path("dinov3-base", &spec),
            PathBuf::from("/tmp/models/dinov3-base.onnx")
        );
    }

    #[test]
    fn artifact_path_bundle() {
        let dl = HfArtifactDownloader::new(PathBuf::from("/tmp/models"));
        let spec = ArtifactSpec::Bundle {
            files: vec!["encoder.onnx".to_string(), "decoder.onnx".to_string()],
            dir_name: "whisper-large-v3-turbo".to_string(),
            peer_hints: Vec::new(),
        };
        assert_eq!(
            dl.artifact_path("whisper-large-v3-turbo", &spec),
            PathBuf::from("/tmp/models/whisper-large-v3-turbo")
        );
    }

    #[test]
    fn is_downloaded_bundle_requires_all_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dl = HfArtifactDownloader::new(tmp.path().to_path_buf());
        let spec = ArtifactSpec::Bundle {
            files: vec!["a.onnx".to_string(), "b.onnx".to_string()],
            dir_name: "bundle".to_string(),
            peer_hints: Vec::new(),
        };
        assert!(!dl.is_downloaded("bundle", &spec));

        let dir = tmp.path().join("bundle");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.onnx"), b"a").unwrap();
        // Only one of two files present — not "downloaded".
        assert!(!dl.is_downloaded("bundle", &spec));

        std::fs::write(dir.join("b.onnx"), b"b").unwrap();
        assert!(dl.is_downloaded("bundle", &spec));
    }

    #[test]
    fn verify_sha256_roundtrip_and_mismatch() {
        let bytes = b"hello world";
        let mut h = Sha256::new();
        h.update(bytes);
        let expected = hex::encode(h.finalize());
        assert!(verify_sha256(bytes, &expected).is_ok());

        let wrong = "0".repeat(64);
        let err = verify_sha256(bytes, &wrong).unwrap_err();
        assert_eq!(err.len(), 64);
        assert_ne!(err, wrong);
    }

    #[test]
    fn artifact_spec_carries_peer_hint() {
        let hint = PeerHint {
            tenzro_uri: TenzroUri::Blob {
                hash: "a".repeat(64),
                provider_hint: None,
            },
            sha256_hex: Some("b".repeat(64)),
        };
        let spec = ArtifactSpec::SingleFile {
            filename: "model.onnx".to_string(),
            extension: "onnx".to_string(),
            peer_hint: Some(hint.clone()),
        };
        match spec {
            ArtifactSpec::SingleFile { peer_hint, .. } => assert_eq!(peer_hint, Some(hint)),
            _ => panic!("wrong variant"),
        }
    }

    /// A blob store that serves fixed bytes and records what was asked of it.
    struct Store {
        bytes: Option<Bytes>,
        asked: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl BlobFetcher for Store {
        async fn fetch(&self, uri: &TenzroUri) -> std::result::Result<Bytes, String> {
            self.asked.lock().unwrap().push(uri.to_string());
            self.bytes
                .clone()
                .ok_or_else(|| "no provider holds it".to_string())
        }
        async fn publish(&self, _bytes: Bytes) -> std::result::Result<TenzroUri, String> {
            Err("read-only".into())
        }
        async fn publish_file(&self, _path: &Path) -> std::result::Result<TenzroUri, String> {
            Err("read-only".into())
        }
    }

    fn store(bytes: Option<&'static [u8]>) -> Arc<dyn BlobFetcher> {
        Arc::new(Store {
            bytes: bytes.map(Bytes::from_static),
            asked: Default::default(),
        })
    }

    /// A pin for `bytes` published only to the network.
    fn network_pin(bytes: &[u8]) -> Pin {
        Pin {
            file: crate::catalog::Component {
                repo: "tenzro/built".into(),
                path: "m.gguf".into(),
                source: crate::catalog::Source::Network {
                    blake3: blake3::hash(bytes).to_hex().to_string(),
                    built_from: crate::catalog::SourceCheckpoint {
                        repo: "o/r".into(),
                        revision: "c".repeat(40),
                    },
                    recipe: "tools/build.sh".into(),
                },
                size: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(bytes)),
                at: None,
            },
            licence: None,
        }
    }

    /// A pin for `bytes` read from the Hub at a commit, gated by its origin
    /// behind `licence`, which the operator accepted.
    fn gated_pin(bytes: &[u8], licence: &str) -> Pin {
        Pin {
            file: crate::catalog::Component {
                repo: "o/gated".into(),
                path: "model.safetensors".into(),
                source: crate::catalog::Source::Hub {
                    revision: "c".repeat(40),
                },
                size: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(bytes)),
                at: None,
            },
            licence: Some(licence.into()),
        }
    }

    /// A provider holding `bytes` that records each licence binding it is
    /// asked for.
    struct GatedStore {
        bytes: Option<Bytes>,
        bound: std::sync::Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl BlobFetcher for GatedStore {
        async fn fetch(&self, uri: &TenzroUri) -> std::result::Result<Bytes, String> {
            assert!(
                self.bound
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|(u, _)| *u == uri.to_string()),
                "fetched before it was bound to its licence"
            );
            self.bytes
                .clone()
                .ok_or_else(|| "no provider holds it".to_string())
        }
        async fn publish(&self, _bytes: Bytes) -> std::result::Result<TenzroUri, String> {
            Err("read-only".into())
        }
        async fn publish_file(&self, _path: &Path) -> std::result::Result<TenzroUri, String> {
            Err("read-only".into())
        }
        async fn bind_licence(
            &self,
            uri: &TenzroUri,
            licence: &str,
        ) -> std::result::Result<(), String> {
            self.bound
                .lock()
                .unwrap()
                .push((uri.to_string(), licence.to_string()));
            Ok(())
        }
    }

    #[test]
    fn a_gated_file_is_cleared_only_once_its_licence_is_accepted() {
        assert_eq!(accepted_gate("m", None, &[]).unwrap(), None);
        let err = accepted_gate("m", Some("custom-terms"), &["other".into()]).unwrap_err();
        assert!(
            matches!(err, ModelError::AccessDenied(ref m) if m.contains("--accept-license custom-terms")),
            "{err}"
        );
        assert_eq!(
            accepted_gate("m", Some("custom-terms"), &["custom-terms".into()])
                .unwrap()
                .as_deref(),
            Some("custom-terms")
        );
    }

    #[tokio::test]
    async fn a_gated_file_is_bound_to_its_licence_then_fetched_by_content_hash() {
        const BYTES: &[u8] = b"gated weights";
        let pin = gated_pin(BYTES, "custom-terms");
        let hint = PeerHint {
            tenzro_uri: TenzroUri::Blob {
                hash: blake3::hash(BYTES).to_hex().to_string(),
                provider_hint: None,
            },
            sha256_hex: Some(pin.file.sha256.clone()),
        };
        let gated = Arc::new(GatedStore {
            bytes: Some(Bytes::from_static(BYTES)),
            bound: Default::default(),
        });
        let fetcher: Arc<dyn BlobFetcher> = gated.clone();
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("m");
        let (tx, _rx) = watch::channel(DownloadProgress {
            model_id: "m".into(),
            status: DownloadState::Downloading,
            progress_percent: 0.0,
            downloaded_bytes: 0,
            total_bytes: 0,
        });
        let r = fetch_pinned(
            "m",
            &pin,
            Some(&hint),
            Some(&fetcher),
            SourcePolicy::Auto,
            &dest,
            &dir.path().join("m.tmp"),
            &tx,
        )
        .await;
        assert_eq!(r.unwrap(), Fetched::Network);
        assert_eq!(std::fs::read(&dest).unwrap(), BYTES);
        assert_eq!(
            *gated.bound.lock().unwrap(),
            vec![(hint.tenzro_uri.to_string(), "custom-terms".to_string())]
        );
    }

    #[tokio::test]
    async fn a_gated_file_never_comes_from_the_hub_without_the_operators_credential() {
        let _origin = ORIGIN.lock().await;
        crate::origin_credential::install(None);
        let pin = gated_pin(b"bytes", "custom-terms");
        // No provider known: refused, with no fall back to the origin.
        let (r, dest, _dir) = fetch(&pin, Some(&store(Some(b"bytes"))), SourcePolicy::Auto).await;
        assert!(matches!(r, Err(ModelError::NoNetworkSource(_))), "{r:?}");
        assert!(!dest.exists());
        let (r, _, _dir) = fetch(&pin, None, SourcePolicy::Auto).await;
        assert!(matches!(r, Err(ModelError::NoNetworkSource(_))), "{r:?}");
        // A policy that forbids the network forbids the file.
        let (r, _, _dir) = fetch(
            &pin,
            Some(&store(Some(b"bytes"))),
            SourcePolicy::HuggingFace,
        )
        .await;
        assert!(
            matches!(r, Err(ModelError::NoNetworkSource(ref m)) if m.contains("credentials set huggingface")),
            "{r:?}"
        );
    }

    /// Serialises the tests that set the process's origin and credential.
    static ORIGIN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    pub(super) static HUB_BASE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

    /// A local origin serving `bytes` for any path. It answers 401 unless
    /// the request carries `Bearer <want>` (or always 200 when `want` is
    /// `None`), and records each request's Authorization header.
    async fn mock_origin(
        bytes: &'static [u8],
        want: Option<&'static str>,
    ) -> Arc<std::sync::Mutex<Vec<Option<String>>>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        *HUB_BASE.lock().unwrap() = Some(format!("http://{}", listener.local_addr().unwrap()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let auth = head
                    .lines()
                    .find_map(|l| {
                        l.strip_prefix("authorization: ")
                            .or_else(|| l.strip_prefix("Authorization: "))
                    })
                    .map(str::to_string);
                let ok = match want {
                    None => true,
                    Some(t) => auth.as_deref() == Some(format!("Bearer {t}").as_str()),
                };
                log.lock().unwrap().push(auth);
                let reply = if ok {
                    let mut r = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        bytes.len()
                    )
                    .into_bytes();
                    r.extend_from_slice(bytes);
                    r
                } else {
                    b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        .to_vec()
                };
                let _ = sock.write_all(&reply).await;
            }
        });
        seen
    }

    #[tokio::test]
    async fn a_gated_file_comes_from_its_origin_only_with_the_operators_credential() {
        const BYTES: &[u8] = b"gated weights from the origin";
        let _origin = ORIGIN.lock().await;
        let seen = mock_origin(BYTES, Some("operator-own-token-1")).await;
        let pin = gated_pin(BYTES, "custom-terms");

        // Without a credential the origin is never asked.
        crate::origin_credential::install(None);
        let (r, dest, _dir) = fetch(&pin, None, SourcePolicy::Auto).await;
        assert!(matches!(r, Err(ModelError::NoNetworkSource(_))), "{r:?}");
        assert!(!dest.exists());
        assert!(seen.lock().unwrap().is_empty());

        // A credential the origin refuses: refused, and the error names no part of it.
        crate::origin_credential::install(Some(
            crate::origin_credential::OriginCredential::new("operator-wrong-token-9").unwrap(),
        ));
        let (r, dest, _dir) = fetch(&pin, None, SourcePolicy::Auto).await;
        let msg = format!("{r:?}");
        assert!(
            r.is_err() && !msg.contains("operator-wrong-token-9"),
            "{msg}"
        );
        assert!(!dest.exists());

        // The operator's own credential: fetched from the origin, sent only as the bearer header.
        crate::origin_credential::install(Some(
            crate::origin_credential::OriginCredential::new("operator-own-token-1").unwrap(),
        ));
        let (r, dest, _dir) = fetch(&pin, None, SourcePolicy::Auto).await;
        assert!(matches!(r, Ok(Fetched::Hub)), "{r:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), BYTES);
        assert_eq!(
            seen.lock().unwrap().last().cloned().flatten().as_deref(),
            Some("Bearer operator-own-token-1")
        );
        crate::origin_credential::install(None);
        *HUB_BASE.lock().unwrap() = None;
    }

    #[tokio::test]
    async fn a_file_an_earlier_attempt_finished_is_not_fetched_again() {
        const BYTES: &[u8] = b"weights finished before the interruption";
        let _origin = ORIGIN.lock().await;
        let seen = mock_origin(BYTES, None).await;
        let mut pin = gated_pin(BYTES, "unused");
        pin.licence = None;
        let dir = tempfile::tempdir().unwrap();
        let (dest, tmp) = (dir.path().join("m.gguf"), dir.path().join("m.tmp"));
        let (tx, _rx) = watch::channel(DownloadProgress {
            model_id: "m".into(),
            status: DownloadState::Downloading,
            progress_percent: 0.0,
            downloaded_bytes: 0,
            total_bytes: 0,
        });
        let go = || {
            fetch_pinned(
                "m",
                &pin,
                None,
                None,
                SourcePolicy::HuggingFace,
                &dest,
                &tmp,
                &tx,
            )
        };
        assert!(matches!(go().await, Ok(Fetched::Hub)));
        assert!(matches!(go().await, Ok(Fetched::Kept)));
        assert_eq!(seen.lock().unwrap().len(), 1);
        // Bytes that are not the pinned ones are fetched again.
        std::fs::write(&dest, b"not the pinned weights").unwrap();
        let r = go().await;
        *HUB_BASE.lock().unwrap() = None;
        assert!(matches!(r, Ok(Fetched::Hub)), "{r:?}");
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert_eq!(std::fs::read(&dest).unwrap(), BYTES);
    }

    #[tokio::test]
    async fn an_open_file_never_carries_the_operators_credential() {
        const BYTES: &[u8] = b"open weights";
        let _origin = ORIGIN.lock().await;
        let seen = mock_origin(BYTES, None).await;
        let mut pin = gated_pin(BYTES, "unused");
        pin.licence = None;
        crate::origin_credential::install(Some(
            crate::origin_credential::OriginCredential::new("operator-own-token-2").unwrap(),
        ));
        let (r, dest, _dir) = fetch(&pin, None, SourcePolicy::HuggingFace).await;
        crate::origin_credential::install(None);
        *HUB_BASE.lock().unwrap() = None;
        assert!(matches!(r, Ok(Fetched::Hub)), "{r:?}");
        assert_eq!(std::fs::read(&dest).unwrap(), BYTES);
        assert_eq!(seen.lock().unwrap().as_slice(), &[None]);
    }

    #[tokio::test]
    async fn a_gated_file_is_not_fetched_by_a_fetcher_that_cannot_bind_it() {
        const BYTES: &[u8] = b"gated weights";
        let pin = gated_pin(BYTES, "custom-terms");
        let hint = PeerHint {
            tenzro_uri: TenzroUri::Blob {
                hash: blake3::hash(BYTES).to_hex().to_string(),
                provider_hint: None,
            },
            sha256_hex: None,
        };
        let fetcher = store(Some(BYTES));
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("m");
        let (tx, _rx) = watch::channel(DownloadProgress {
            model_id: "m".into(),
            status: DownloadState::Downloading,
            progress_percent: 0.0,
            downloaded_bytes: 0,
            total_bytes: 0,
        });
        let r = fetch_pinned(
            "m",
            &pin,
            Some(&hint),
            Some(&fetcher),
            SourcePolicy::Network,
            &dest,
            &dir.path().join("m.tmp"),
            &tx,
        )
        .await;
        assert!(
            matches!(r, Err(ModelError::DownloadError(ref m)) if m.contains("cannot bind")),
            "{r:?}"
        );
        assert!(!dest.exists());
    }

    async fn fetch(
        pin: &Pin,
        fetcher: Option<&Arc<dyn BlobFetcher>>,
        policy: SourcePolicy,
    ) -> (Result<Fetched>, PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("m.gguf");
        let (tx, _rx) = watch::channel(DownloadProgress {
            model_id: "m".into(),
            status: DownloadState::Downloading,
            progress_percent: 0.0,
            downloaded_bytes: 0,
            total_bytes: 0,
        });
        let r = fetch_pinned(
            "m",
            pin,
            None,
            fetcher,
            policy,
            &dest,
            &dir.path().join("m.tmp"),
            &tx,
        )
        .await;
        (r, dest, dir)
    }

    #[tokio::test]
    async fn a_network_file_is_fetched_by_its_pinned_content_address() {
        const BYTES: &[u8] = b"weights built by the recipe";
        let pin = network_pin(BYTES);
        let hint = pin.network_hint().unwrap();
        assert_eq!(
            hint.tenzro_uri.to_string(),
            format!("tenzro://blob/{}", blake3::hash(BYTES).to_hex())
        );
        for policy in [SourcePolicy::Auto, SourcePolicy::Network] {
            let fetcher = store(Some(BYTES));
            let (r, dest, _dir) = fetch(&pin, Some(&fetcher), policy).await;
            assert_eq!(r.unwrap(), Fetched::Network);
            assert_eq!(std::fs::read(&dest).unwrap(), BYTES);
        }
    }

    fn hashes(bytes: &[u8]) -> (String, String) {
        (
            blake3::hash(bytes).to_hex().to_string(),
            hex::encode(Sha256::digest(bytes)),
        )
    }

    #[tokio::test]
    async fn a_network_file_is_fetched_by_its_content_hash() {
        const BYTES: &[u8] = b"trained adapter";
        let (b3, sha) = hashes(BYTES);
        let dir = tempfile::tempdir().unwrap();
        let dl = HfDownloader::new(dir.path().to_path_buf()).with_blob_fetcher(store(Some(BYTES)));
        let path = dl
            .fetch_network_file("trained-ab", &b3, &sha, BYTES.len() as u64)
            .await
            .unwrap();
        assert_eq!(path, dir.path().join("trained-ab.gguf"));
        assert_eq!(std::fs::read(&path).unwrap(), BYTES);
        assert_eq!(dl.resolve_local_gguf("trained-ab"), Some(path));
    }

    #[tokio::test]
    async fn a_network_file_with_other_bytes_is_refused() {
        const BYTES: &[u8] = b"trained adapter";
        let (b3, sha) = hashes(BYTES);
        let dir = tempfile::tempdir().unwrap();
        // Same length, different bytes: the content address does not match.
        let dl = HfDownloader::new(dir.path().to_path_buf())
            .with_blob_fetcher(store(Some(b"trained adaptex")));
        let err = dl
            .fetch_network_file("trained-ab", &b3, &sha, BYTES.len() as u64)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("BLAKE3"), "{err}");
        assert!(!dir.path().join("trained-ab.gguf").exists());
        // The served bytes are the addressed ones, but the pinned SHA-256 is not theirs.
        let dl = HfDownloader::new(dir.path().to_path_buf()).with_blob_fetcher(store(Some(BYTES)));
        let err = dl
            .fetch_network_file("trained-ab", &b3, &"0".repeat(64), BYTES.len() as u64)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("pinned"), "{err}");
        assert!(!dir.path().join("trained-ab.gguf").exists());
    }

    #[tokio::test]
    async fn a_network_file_no_provider_holds_errors() {
        let (b3, sha) = hashes(b"x");
        let dir = tempfile::tempdir().unwrap();
        let dl = HfDownloader::new(dir.path().to_path_buf()).with_blob_fetcher(store(None));
        let err = dl
            .fetch_network_file("trained-ab", &b3, &sha, 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no provider holds it"), "{err}");
        let dl = HfDownloader::new(dir.path().to_path_buf());
        let err = dl
            .fetch_network_file("trained-ab", &b3, &sha, 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no peer network"), "{err}");
        assert!(!dir.path().join("trained-ab.gguf").exists());
    }

    #[tokio::test]
    async fn a_network_file_is_never_kept_unless_it_is_the_pinned_bytes() {
        let pin = network_pin(b"the pinned bytes");
        let fetcher = store(Some(b"other bytes"));
        let (r, dest, _dir) = fetch(&pin, Some(&fetcher), SourcePolicy::Auto).await;
        assert!(matches!(r, Err(ModelError::NoNetworkSource(_))), "{r:?}");
        assert!(!dest.exists());
        let fetcher = store(Some(b"the pinned byteZ"));
        let (r, dest, _dir) = fetch(&pin, Some(&fetcher), SourcePolicy::Auto).await;
        assert!(matches!(r, Err(ModelError::NoNetworkSource(_))), "{r:?}");
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn a_network_file_has_no_hub_fallback() {
        let pin = network_pin(b"bytes");
        let (r, _, _dir) = fetch(&pin, Some(&store(None)), SourcePolicy::Auto).await;
        assert!(matches!(r, Err(ModelError::NoNetworkSource(_))), "{r:?}");
        let (r, _, _dir) = fetch(&pin, None, SourcePolicy::Auto).await;
        assert!(matches!(r, Err(ModelError::NoNetworkSource(_))), "{r:?}");
        let fetcher = store(Some(b"bytes"));
        let (r, dest, _dir) = fetch(&pin, Some(&fetcher), SourcePolicy::HuggingFace).await;
        assert!(matches!(r, Err(ModelError::DownloadError(_))), "{r:?}");
        assert!(!dest.exists());
    }
}
