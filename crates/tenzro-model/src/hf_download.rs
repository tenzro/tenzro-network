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
//! # Peer fetch over `tenzro://` (Phase B3, #218)
//!
//! When a [`BlobFetcher`] is wired via
//! [`HfArtifactDownloader::with_blob_fetcher`] (typically
//! `tenzro_iroh::IrohBackedResolver` adapted on the node side) and an
//! [`ArtifactSpec`] carries a `tenzro_uri` peer hint, the downloader tries
//! the peer fetch *first* and falls back to the HF CDN on any error
//! (missing blob, BLAKE3 mismatch, transport failure). Optional
//! `sha256_hex` is checked against the fetched bytes as a
//! defense-in-depth layer on top of iroh-blobs' own BLAKE3 verification
//! — same belt-and-braces discipline as
//! [`crate::payload_store::verify_payload`] in `tenzro-training` and
//! [`tenzro_training::verify_shard_ciphertext`] in `tenzro-iroh`'s sealed
//! shard store.
//!
//! When a download completes via the HF CDN path *and* a fetcher is
//! wired, the downloader opportunistically publishes the bytes via
//! [`BlobFetcher::publish`] so neighbour nodes can subsequently fetch by
//! content hash without re-pulling from HF — Phase B1's
//! `IrohGradientStore` and Phase B2's `IrohSealedShardStore` follow the
//! same pattern for gradients and sealed shards respectively.

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
/// [`BlobFetcher::publish`] so neighbours can avoid re-pulling.
pub struct HfArtifactDownloader {
    storage_path: PathBuf,
    blob_fetcher: Option<Arc<dyn BlobFetcher>>,
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
}

impl HfDownloader {
    /// Create a new downloader that stores models at the given path.
    pub fn new(storage_path: PathBuf) -> Self {
        Self {
            storage_path,
            blob_fetcher: None,
        }
    }

    /// Attach a [`BlobFetcher`] so the downloader can fetch and publish
    /// over `tenzro://` URIs. Returns `self` for builder-style chaining.
    pub fn with_blob_fetcher(mut self, fetcher: Arc<dyn BlobFetcher>) -> Self {
        self.blob_fetcher = Some(fetcher);
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
        std::fs::read_dir(&dir).ok()?.filter_map(|e| e.ok()).find_map(|e| {
            let name = e.file_name();
            let name = name.to_str()?;
            (name.contains("-00001-of-") && name.ends_with(".gguf")).then(|| e.path())
        })
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
        if let Some((prefix, total, ext_suffix)) = parse_shard_spec(&entry.hf_filename) {
            return self
                .download_sharded(entry, &prefix, total, &ext_suffix, policy, progress_tx)
                .await;
        }

        let dest_path = self.model_path(&entry.id);
        let tmp_path = dest_path.with_extension("gguf.tmp");

        // Verified-network path — only when the policy permits it AND a
        // fetcher AND a hint are all present.
        if policy.allows_network()
            && let (Some(fetcher), Some(hint)) = (self.blob_fetcher.as_ref(), peer_hint)
        {
            debug!(
                target: "tenzro_model::peer_fetch",
                "{}: trying verified-provider fetch via {}",
                entry.id, hint.tenzro_uri
            );
            match fetcher.fetch(&hint.tenzro_uri).await {
                Ok(bytes) => {
                    // Defense-in-depth SHA-256 check on top of the
                    // transport's own BLAKE3 verification.
                    let sha_ok = match hint.sha256_hex.as_deref() {
                        Some(expected) => match verify_sha256(&bytes, expected) {
                            Ok(()) => true,
                            Err(actual) => {
                                warn!(
                                    target: "tenzro_model::peer_fetch",
                                    "{}: verified-provider fetch SHA-256 mismatch (got {})",
                                    entry.id, actual
                                );
                                false
                            }
                        },
                        None => true,
                    };

                    if sha_ok {
                        write_bytes_atomic(
                            &entry.id,
                            &bytes,
                            &dest_path,
                            &tmp_path,
                            &progress_tx,
                        )
                        .await?;
                        info!(
                            "{}: served from verified provider ({} bytes via {})",
                            entry.id,
                            bytes.len(),
                            hint.tenzro_uri
                        );
                        // Vision projector still comes from the model repo;
                        // honor the same policy for it.
                        self.download_mmproj(entry, policy, &progress_tx).await?;
                        return Ok(dest_path);
                    }
                }
                Err(e) => {
                    warn!(
                        target: "tenzro_model::peer_fetch",
                        "{}: verified-provider fetch failed ({})",
                        entry.id, e
                    );
                }
            }
        }

        // The `Network` policy never contacts the HF CDN. If we reach here
        // under it, no verified provider served the blob — terminal.
        if !policy.allows_huggingface() {
            return Err(ModelError::NoNetworkSource(entry.id.clone()));
        }

        download_one_file(
            &entry.id,
            &entry.hf_repo,
            &entry.hf_filename,
            entry.size_bytes,
            &dest_path,
            &tmp_path,
            &progress_tx,
        )
        .await?;

        // Verify download integrity (file size check)
        if let Err(e) = self.verify_download(&entry.id, entry.size_bytes) {
            // Log but don't delete — the file may still be usable if the catalog
            // size is slightly off. Callers can decide whether to retry.
            warn!("Download verification warning for {}: {}", entry.id, e);
        }

        // Opportunistic publish so neighbours can fetch from us next time.
        if let Some(fetcher) = self.blob_fetcher.as_ref() {
            match tokio::fs::read(&dest_path).await {
                Ok(bytes) => {
                    let bytes = Bytes::from(bytes);
                    match fetcher.publish(bytes).await {
                        Ok(uri) => debug!(
                            target: "tenzro_model::peer_fetch",
                            "{}: published to peer store as {}",
                            entry.id, uri
                        ),
                        Err(e) => debug!(
                            target: "tenzro_model::peer_fetch",
                            "{}: opportunistic publish failed ({}), not fatal",
                            entry.id, e
                        ),
                    }
                }
                Err(e) => debug!(
                    target: "tenzro_model::peer_fetch",
                    "{}: skipped publish (read failed: {})",
                    entry.id, e
                ),
            }
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
        // The projector is fetched from the model repo on the HF CDN. Under a
        // policy that forbids HF, skip it — the model still serves text-only,
        // exactly as it would on an HF projector failure.
        if !policy.allows_huggingface() {
            debug!(
                "{}: skipping mmproj projector (source policy forbids HuggingFace); model serves text-only",
                entry.id
            );
            return Ok(());
        }
        let dest_path = self.mmproj_path(&entry.id);
        if dest_path.exists() {
            return Ok(());
        }
        let tmp_path = dest_path.with_extension("gguf.tmp");

        if let Err(e) = download_one_file(
            &format!("{}/mmproj", entry.id),
            &entry.hf_repo,
            &mmproj.filename,
            0,
            &dest_path,
            &tmp_path,
            progress_tx,
        )
        .await
        {
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
    /// [`parse_shard_spec`] on the first-shard `hf_filename`. The remote
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
        // Shard sets are fetched per-shard from the HF CDN — the catalog
        // carries a single canonical hash for the model, not per-shard peer
        // hints, so there is no verified-provider path for split GGUFs yet.
        // A policy that forbids HF therefore has no source: fail terminally.
        if !policy.allows_huggingface() {
            return Err(ModelError::NoNetworkSource(entry.id.clone()));
        }

        // Remote dir prefix (everything before the bare shard filename),
        // kept so we can rebuild each shard's remote path.
        let remote_dir = entry
            .hf_filename
            .rsplit_once('/')
            .map(|(d, _)| format!("{}/", d))
            .unwrap_or_default();

        let dest_dir = self.storage_path.join(&entry.id);
        let tmp_dir = self.storage_path.join(format!("{}.tmp", entry.id));

        if tmp_dir.exists() {
            let _ = std::fs::remove_dir_all(&tmp_dir);
        }
        std::fs::create_dir_all(&tmp_dir).map_err(|e| {
            ModelError::DownloadError(format!(
                "Failed to create shard tmp dir {}: {}",
                tmp_dir.display(),
                e
            ))
        })?;

        let per_shard_hint = if total > 0 {
            entry.size_bytes / total as u64
        } else {
            0
        };

        for idx in 1..=total {
            let shard_name = format!("{}-{:05}-of-{:05}{}", prefix, idx, total, ext_suffix);
            let remote_filename = format!("{}{}", remote_dir, shard_name);
            let shard_dest = tmp_dir.join(&shard_name);
            let shard_tmp = tmp_dir.join(format!("{}.tmp", shard_name));

            download_one_file(
                &format!("{}/{}", entry.id, shard_name),
                &entry.hf_repo,
                &remote_filename,
                per_shard_hint,
                &shard_dest,
                &shard_tmp,
                &progress_tx,
            )
            .await
            .inspect_err(|_| {
                // Tear down the partial set — never expose a split GGUF
                // missing shards (llama.cpp would fail to load it).
                let _ = std::fs::remove_dir_all(&tmp_dir);
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
        }
    }

    /// Attach a [`BlobFetcher`] so the downloader can fetch and publish
    /// over `tenzro://` URIs. Returns `self` for builder-style chaining.
    pub fn with_blob_fetcher(mut self, fetcher: Arc<dyn BlobFetcher>) -> Self {
        self.blob_fetcher = Some(fetcher);
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
            ArtifactSpec::SingleFile { extension, .. } => {
                self.storage_path.join(format!("{}.{}", model_id, extension))
            }
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
    /// `total_size_hint` is used only for progress UI when the HF CDN
    /// doesn't return Content-Length; it does not gate the download.
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
        total_size_hint: u64,
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
                    total_size_hint,
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
                let tmp_dir = self
                    .storage_path
                    .join(format!("{}.tmp", dir_name));

                // Clean any stale tmp dir from a previous failed attempt.
                if tmp_dir.exists() {
                    let _ = std::fs::remove_dir_all(&tmp_dir);
                }
                std::fs::create_dir_all(&tmp_dir).map_err(|e| {
                    ModelError::DownloadError(format!(
                        "Failed to create bundle tmp dir {}: {}",
                        tmp_dir.display(),
                        e
                    ))
                })?;

                // Per-file size hint = total / N, used only for progress UI
                // when Content-Length is missing.
                let n = files.len() as u64;
                let per_file_hint = total_size_hint.checked_div(n).unwrap_or(0);

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
                        per_file_hint,
                        &file_dest,
                        &file_tmp,
                        policy,
                        &progress_tx,
                    )
                    .await
                    .inspect_err(|_e| {
                        // Tear down the partial bundle on first failure —
                        // we never expose half-downloaded multi-file ONNX.
                        let _ = std::fs::remove_dir_all(&tmp_dir);
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
    /// `sha256_hex` (when present in the hint) is verified against the
    /// fetched bytes regardless of which path served them — the HF CDN
    /// itself doesn't carry a SHA-256 commitment, so this is the only
    /// way to detect corruption on the HF path.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_one_file(
        &self,
        progress_label: &str,
        hf_repo: &str,
        hf_filename: &str,
        peer_hint: Option<&PeerHint>,
        total_bytes_hint: u64,
        dest_path: &Path,
        tmp_path: &Path,
        policy: SourcePolicy,
        progress_tx: &watch::Sender<DownloadProgress>,
    ) -> Result<()> {
        // Verified-network path — only when the policy permits it AND a
        // fetcher AND a hint are all present.
        if policy.allows_network()
            && let (Some(fetcher), Some(hint)) = (self.blob_fetcher.as_ref(), peer_hint)
        {
            debug!(
                target: "tenzro_model::peer_fetch",
                "{}: trying verified-provider fetch via {}",
                progress_label, hint.tenzro_uri
            );
            match fetcher.fetch(&hint.tenzro_uri).await {
                Ok(bytes) => {
                    // Defense-in-depth SHA-256 check on top of the
                    // transport's own BLAKE3 verification.
                    if let Some(expected_sha) = hint.sha256_hex.as_deref()
                        && let Err(e) = verify_sha256(&bytes, expected_sha)
                    {
                        warn!(
                            target: "tenzro_model::peer_fetch",
                            "{}: verified-provider fetch SHA-256 mismatch ({})",
                            progress_label, e
                        );
                    } else {
                        // Write peer bytes to disk and return early.
                        write_bytes_atomic(
                            progress_label,
                            &bytes,
                            dest_path,
                            tmp_path,
                            progress_tx,
                        )
                        .await?;
                        info!(
                            "{}: served from verified provider ({} bytes via {})",
                            progress_label,
                            bytes.len(),
                            hint.tenzro_uri
                        );
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!(
                        target: "tenzro_model::peer_fetch",
                        "{}: verified-provider fetch failed ({})",
                        progress_label, e
                    );
                }
            }
        }

        // The `Network` policy never contacts the HF CDN. If we reach here
        // under it, no verified provider served the blob — terminal.
        if !policy.allows_huggingface() {
            return Err(ModelError::NoNetworkSource(progress_label.to_string()));
        }

        // HF CDN path (fallback under `Auto`, primary under `HuggingFace`).
        download_one_file(
            progress_label,
            hf_repo,
            hf_filename,
            total_bytes_hint,
            dest_path,
            tmp_path,
            progress_tx,
        )
        .await?;

        // SHA-256 verification on the HF path (only when the spec
        // committed a hash up front).
        if let Some(expected_sha) = peer_hint.and_then(|h| h.sha256_hex.as_deref()) {
            match tokio::fs::read(dest_path).await {
                Ok(bytes) => {
                    if let Err(e) = verify_sha256(&bytes, expected_sha) {
                        error!(
                            "{}: HF CDN download failed SHA-256 verification ({})",
                            progress_label, e
                        );
                        let _ = std::fs::remove_file(dest_path);
                        return Err(ModelError::ChecksumMismatch {
                            expected: expected_sha.to_string(),
                            actual: e,
                        });
                    }
                }
                Err(e) => {
                    return Err(ModelError::DownloadError(format!(
                        "Failed to re-read {} for SHA-256 check: {}",
                        dest_path.display(),
                        e
                    )));
                }
            }
        }

        // Opportunistic publish so neighbours can fetch from us next time.
        if let Some(fetcher) = self.blob_fetcher.as_ref() {
            match tokio::fs::read(dest_path).await {
                Ok(bytes) => {
                    let bytes = Bytes::from(bytes);
                    match fetcher.publish(bytes.clone()).await {
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
                Err(e) => debug!(
                    target: "tenzro_model::peer_fetch",
                    "{}: skipped publish (read failed: {})",
                    progress_label, e
                ),
            }
        }

        Ok(())
    }
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

/// Stream a single HF Hub file to disk via a tmp-rename. Shared between
/// the [`HfDownloader::download_model`] path and the
/// [`HfArtifactDownloader::download`] path.
/// Parse a gguf-split first-shard filename into its `(prefix, total, ext)`
/// parts. Accepts the bare name or a subdir-prefixed remote path; the
/// returned `prefix` is the model stem WITHOUT the `-00001-of-000NN`
/// segment and WITHOUT any leading directory, and `ext` is everything
/// after the shard segment (normally `.gguf`).
///
/// Returns `None` for non-sharded names or any shard other than the
/// first — only the first shard is a valid catalog entry point.
///
/// `Q4_K_M/Kimi-K2-Instruct-Q4_K_M-00001-of-00013.gguf`
///   → `("Kimi-K2-Instruct-Q4_K_M", 13, ".gguf")`
fn parse_shard_spec(hf_filename: &str) -> Option<(String, u32, String)> {
    let bare = hf_filename.rsplit('/').next().unwrap_or(hf_filename);
    let marker = bare.find("-00001-of-")?;
    let prefix = bare[..marker].to_string();
    // After the marker: "-00001-of-" then NNNNN then the extension.
    let rest = &bare[marker + "-00001-of-".len()..];
    let digits_end = rest.find(|c: char| !c.is_ascii_digit())?;
    let total: u32 = rest[..digits_end].parse().ok()?;
    if total == 0 {
        return None;
    }
    let ext_suffix = rest[digits_end..].to_string();
    Some((prefix, total, ext_suffix))
}

async fn download_one_file(
    progress_label: &str,
    hf_repo: &str,
    hf_filename: &str,
    total_bytes_hint: u64,
    dest_path: &Path,
    tmp_path: &Path,
    progress_tx: &watch::Sender<DownloadProgress>,
) -> Result<()> {
    info!(
        "Starting download: {} from {}/{}",
        progress_label, hf_repo, hf_filename
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
    // issues with HF's xethub CDN in containerized environments.
    let download_url = format!(
        "https://huggingface.co/{}/resolve/main/{}",
        hf_repo, hf_filename
    );
    info!("Downloading from: {}", download_url);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .map_err(|e| ModelError::DownloadError(format!("Failed to create HTTP client: {}", e)))?;

    let response = client.get(&download_url).send().await.map_err(|e| {
        error!("HTTP download request failed for {}: {}", progress_label, e);
        ModelError::DownloadError(format!("HTTP request failed: {}", e))
    })?;

    if !response.status().is_success() {
        return Err(ModelError::DownloadError(format!(
            "HTTP {} from HuggingFace for {}",
            response.status(),
            progress_label
        )));
    }

    let content_length = response.content_length().unwrap_or(total_bytes_hint);

    {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::create(tmp_path).await.map_err(|e| {
            ModelError::DownloadError(format!("Failed to create temp file: {}", e))
        })?;

        let mut downloaded: u64 = 0;
        let mut stream = response.bytes_stream();
        use futures::StreamExt;

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.map_err(|e| {
                ModelError::DownloadError(format!("Download stream error: {}", e))
            })?;

            file.write_all(&chunk)
                .await
                .map_err(|e| ModelError::DownloadError(format!("Write error: {}", e)))?;

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
            parse_shard_spec("Q4_K_M/Kimi-K2-Instruct-Q4_K_M-00001-of-00013.gguf")
                .expect("should parse first shard");
        assert_eq!(prefix, "Kimi-K2-Instruct-Q4_K_M");
        assert_eq!(total, 13);
        assert_eq!(ext, ".gguf");
    }

    #[test]
    fn parse_shard_spec_bare_first_shard() {
        let (prefix, total, ext) =
            parse_shard_spec("DeepSeek-V3-0324-Q4_K_M-00001-of-00009.gguf")
                .expect("should parse bare first shard");
        assert_eq!(prefix, "DeepSeek-V3-0324-Q4_K_M");
        assert_eq!(total, 9);
        assert_eq!(ext, ".gguf");
    }

    #[test]
    fn parse_shard_spec_rejects_single_file() {
        assert!(parse_shard_spec("Qwen3.5-4B-Q4_K_M.gguf").is_none());
    }

    #[test]
    fn parse_shard_spec_rejects_non_first_shard() {
        // Only the first shard is a valid catalog entry point.
        assert!(parse_shard_spec("Q4_K_M/Model-00002-of-00009.gguf").is_none());
    }

    #[test]
    fn sharded_model_path_prefers_first_shard() {
        let tmp = std::env::temp_dir().join(format!(
            "ipnops-shard-test-{}",
            std::process::id()
        ));
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
}
