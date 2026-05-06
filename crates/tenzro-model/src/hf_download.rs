//! HuggingFace Hub download integration.
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

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn, error};

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
    },
}

/// Generic artifact downloader for HuggingFace Hub.
///
/// Wraps the same storage path as [`HfDownloader`] but accepts an
/// [`ArtifactSpec`] so callers can request single-file (GGUF, single-file
/// ONNX) or multi-file (Whisper-style ONNX bundle) artifacts through a
/// single API.
pub struct HfArtifactDownloader {
    storage_path: PathBuf,
}

/// Manages downloading GGUF models from HuggingFace Hub.
///
/// Used by LLM callers (CLI, RPC handlers). Exposes GGUF-specific
/// helpers (`model_path`, `is_downloaded`, `downloaded_size`,
/// `verify_download` with size tolerance). For multi-file ONNX bundles
/// or single-file ONNX, use [`HfArtifactDownloader::download`] directly.
pub struct HfDownloader {
    storage_path: PathBuf,
}

impl HfDownloader {
    /// Create a new downloader that stores models at the given path.
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path }
    }

    /// Get the local file path for a model.
    pub fn model_path(&self, model_id: &str) -> PathBuf {
        // Store as <storage_path>/<model_id>.gguf
        self.storage_path.join(format!("{}.gguf", model_id))
    }

    /// Check if a model is already downloaded locally.
    ///
    /// Also cleans up broken symlinks left over from previous versions that
    /// symlinked to the ephemeral HF cache inside the container.
    pub fn is_downloaded(&self, model_id: &str) -> bool {
        let path = self.model_path(model_id);
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

    /// Get the file size of a downloaded model, if present.
    pub fn downloaded_size(&self, model_id: &str) -> Option<u64> {
        let path = self.model_path(model_id);
        std::fs::metadata(&path).ok().map(|m| m.len())
    }

    /// Download a model from HuggingFace Hub.
    ///
    /// Streams the GGUF file from the HF CDN to
    /// `<storage_path>/<model_id>.gguf` via a tmp-rename for atomicity.
    /// Progress updates are sent via `progress_tx`.
    pub async fn download_model(
        &self,
        entry: &HfModelEntry,
        progress_tx: watch::Sender<DownloadProgress>,
    ) -> Result<PathBuf> {
        let dest_path = self.model_path(&entry.id);
        let tmp_path = dest_path.with_extension("gguf.tmp");

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

        Ok(dest_path)
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
        let path = self.model_path(model_id);

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
        Self { storage_path }
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
    pub async fn download(
        &self,
        model_id: &str,
        repo: &str,
        spec: &ArtifactSpec,
        total_size_hint: u64,
        progress_tx: watch::Sender<DownloadProgress>,
    ) -> Result<PathBuf> {
        // Ensure storage root exists
        std::fs::create_dir_all(&self.storage_path).map_err(|e| {
            ModelError::DownloadError(format!("Failed to create storage dir: {}", e))
        })?;

        match spec {
            ArtifactSpec::SingleFile { filename, extension } => {
                let dest_path = self
                    .storage_path
                    .join(format!("{}.{}", model_id, extension));
                let tmp_path = dest_path.with_extension(format!("{}.tmp", extension));
                download_one_file(
                    model_id,
                    repo,
                    filename,
                    total_size_hint,
                    &dest_path,
                    &tmp_path,
                    &progress_tx,
                )
                .await?;
                Ok(dest_path)
            }
            ArtifactSpec::Bundle { files, dir_name } => {
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
                let per_file_hint = if n > 0 { total_size_hint / n } else { 0 };

                for filename in files {
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
                    download_one_file(
                        &format!("{}/{}", model_id, filename),
                        repo,
                        filename,
                        per_file_hint,
                        &file_dest,
                        &file_tmp,
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
}

/// Stream a single HF Hub file to disk via a tmp-rename. Shared between
/// the [`HfDownloader::download_model`] path and the
/// [`HfArtifactDownloader::download`] path.
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
    fn artifact_path_single_file() {
        let dl = HfArtifactDownloader::new(PathBuf::from("/tmp/models"));
        let spec = ArtifactSpec::SingleFile {
            filename: "model.onnx".to_string(),
            extension: "onnx".to_string(),
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
}
