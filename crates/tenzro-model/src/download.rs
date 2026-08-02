//! Model download management module
//!
//! This module handles downloading AI models for serving on inference providers,
//! including progress tracking, checksum verification, and concurrent downloads.

use crate::error::{ModelError, Result};
use crate::registry::ModelRegistry;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

/// Status of a download task
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DownloadStatus {
    /// Download is pending
    Pending,
    /// Download is in progress
    Downloading,
    /// Download is paused
    Paused,
    /// Download completed successfully
    Completed,
    /// Download failed
    Failed,
    /// Download was cancelled
    Cancelled,
}

/// A download task for a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadTask {
    /// Model ID being downloaded
    pub model_id: String,
    /// Download URL
    pub url: String,
    /// Current download progress (0.0 - 1.0)
    pub progress: f64,
    /// Current status
    pub status: DownloadStatus,
    /// Number of bytes downloaded
    pub downloaded_bytes: u64,
    /// Total number of bytes to download
    pub total_bytes: u64,
    /// Local file path where model will be saved
    pub file_path: PathBuf,
    /// Expected checksum (SHA-256 hex)
    pub expected_checksum: Option<String>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Download start time
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Download completion time
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl DownloadTask {
    /// Creates a new download task
    pub fn new(
        model_id: String,
        url: String,
        total_bytes: u64,
        file_path: PathBuf,
        expected_checksum: Option<String>,
    ) -> Self {
        Self {
            model_id,
            url,
            progress: 0.0,
            status: DownloadStatus::Pending,
            downloaded_bytes: 0,
            total_bytes,
            file_path,
            expected_checksum,
            error_message: None,
            started_at: None,
            completed_at: None,
        }
    }

    /// Updates download progress
    pub fn update_progress(&mut self, downloaded_bytes: u64) {
        self.downloaded_bytes = downloaded_bytes;
        if self.total_bytes > 0 {
            self.progress = downloaded_bytes as f64 / self.total_bytes as f64;
        }
    }

    /// Marks download as started
    pub fn mark_started(&mut self) {
        self.status = DownloadStatus::Downloading;
        self.started_at = Some(chrono::Utc::now());
    }

    /// Marks download as completed
    pub fn mark_completed(&mut self) {
        self.status = DownloadStatus::Completed;
        self.progress = 1.0;
        self.completed_at = Some(chrono::Utc::now());
    }

    /// Marks download as failed
    pub fn mark_failed(&mut self, error: String) {
        self.status = DownloadStatus::Failed;
        self.error_message = Some(error);
    }

    /// Calculates download speed in bytes per second
    pub fn download_speed(&self) -> Option<f64> {
        if let Some(started_at) = self.started_at {
            let elapsed = chrono::Utc::now()
                .signed_duration_since(started_at)
                .num_seconds();
            if elapsed > 0 {
                return Some(self.downloaded_bytes as f64 / elapsed as f64);
            }
        }
        None
    }

    /// Estimates time remaining in seconds
    pub fn estimated_time_remaining(&self) -> Option<u64> {
        if let Some(speed) = self.download_speed()
            && speed > 0.0
        {
            let remaining_bytes = self.total_bytes.saturating_sub(self.downloaded_bytes);
            return Some((remaining_bytes as f64 / speed) as u64);
        }
        None
    }
}

/// Manager for model downloads
#[derive(Debug, Clone)]
pub struct DownloadManager {
    /// Active download tasks
    tasks: Arc<DashMap<String, DownloadTask>>,
    /// Base directory for storing downloaded models
    storage_path: PathBuf,
    /// Maximum concurrent downloads
    max_concurrent_downloads: usize,
    /// Optional model registry for integrity verification
    registry: Option<ModelRegistry>,
}

impl DownloadManager {
    /// Creates a new download manager
    pub fn new(storage_path: PathBuf) -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
            storage_path,
            max_concurrent_downloads: 3,
            registry: None,
        }
    }

    /// Creates a new download manager with custom concurrent download limit
    pub fn with_max_concurrent(storage_path: PathBuf, max_concurrent: usize) -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
            storage_path,
            max_concurrent_downloads: max_concurrent,
            registry: None,
        }
    }

    /// Sets the model registry for integrity verification
    pub fn with_registry(mut self, registry: ModelRegistry) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Starts a new download
    ///
    /// # Errors
    ///
    /// Returns `ModelError::DownloadError` if the download cannot be started.
    pub async fn start_download(
        &self,
        model_id: String,
        url: String,
        total_bytes: u64,
        expected_checksum: Option<String>,
    ) -> Result<()> {
        // Enforce checksum requirement for model integrity verification
        if expected_checksum.is_none() {
            return Err(ModelError::DownloadError(
                "SHA-256 checksum is required for model integrity verification".to_string(),
            ));
        }

        // Check concurrent download limit
        let active_count = self
            .tasks
            .iter()
            .filter(|entry| entry.value().status == DownloadStatus::Downloading)
            .count();

        if active_count >= self.max_concurrent_downloads {
            return Err(ModelError::DownloadError(
                "Maximum concurrent downloads reached".to_string(),
            ));
        }

        // Create storage directory if it doesn't exist
        fs::create_dir_all(&self.storage_path).await?;

        // Determine file path
        let file_name = format!("{}.model", model_id);
        let file_path = self.storage_path.join(file_name);

        // Create download task
        let mut task = DownloadTask::new(
            model_id.clone(),
            url.clone(),
            total_bytes,
            file_path.clone(),
            expected_checksum.clone(),
        );

        task.mark_started();
        self.tasks.insert(model_id.clone(), task);

        info!("Started download for model: {} from {}", model_id, url);

        // Spawn download task in background
        let tasks = self.tasks.clone();
        let registry = self.registry.clone();
        let model_id_clone = model_id.clone();
        tokio::spawn(async move {
            if let Err(e) = Self::perform_download(
                &tasks,
                &model_id_clone,
                &url,
                &file_path,
                expected_checksum.as_deref(),
                registry.as_ref(),
            )
            .await
            {
                warn!("Download failed for {}: {}", model_id_clone, e);
                if let Some(mut entry) = tasks.get_mut(&model_id_clone) {
                    entry.mark_failed(e.to_string());
                }
            }
        });

        Ok(())
    }

    /// Performs the actual HTTP download with streaming and progress tracking
    async fn perform_download(
        tasks: &Arc<DashMap<String, DownloadTask>>,
        model_id: &str,
        url: &str,
        file_path: &Path,
        expected_checksum: Option<&str>,
        registry: Option<&ModelRegistry>,
    ) -> Result<()> {
        // Check if we can resume from a partial download
        let (starting_byte, file) = if file_path.exists() {
            let metadata = fs::metadata(file_path).await?;
            let existing_size = metadata.len();

            // Update task with existing progress
            if let Some(mut entry) = tasks.get_mut(model_id) {
                entry.update_progress(existing_size);
            }

            info!(
                "Resuming download for {} from byte {}",
                model_id, existing_size
            );
            (
                existing_size,
                fs::OpenOptions::new()
                    .write(true)
                    .append(true)
                    .open(file_path)
                    .await?,
            )
        } else {
            (0, fs::File::create(file_path).await?)
        };

        // Build HTTP client
        let client = reqwest::Client::new();

        // Build request with Range header for resumption support
        let mut request = client.get(url);
        if starting_byte > 0 {
            request = request.header("Range", format!("bytes={}-", starting_byte));
        }

        // Send request
        let response = request
            .send()
            .await
            .map_err(|e| ModelError::DownloadError(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(ModelError::DownloadError(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        // Download bytes
        // Note: This loads the entire response into memory. For production,
        // enable reqwest's "stream" feature and use bytes_stream() for
        // chunk-by-chunk streaming with progress updates.
        let bytes = response
            .bytes()
            .await
            .map_err(|e| ModelError::DownloadError(format!("Failed to download bytes: {}", e)))?;

        let mut file = file;
        let mut downloaded_bytes = starting_byte;

        // Write all bytes to file
        file.write_all(&bytes).await?;
        downloaded_bytes += bytes.len() as u64;

        // Update progress
        if let Some(mut entry) = tasks.get_mut(model_id) {
            entry.update_progress(downloaded_bytes);

            // Check if download was cancelled
            if entry.status == DownloadStatus::Cancelled {
                debug!("Download cancelled for {}", model_id);
                return Ok(());
            }
        }

        // Ensure all data is written
        file.flush().await?;
        drop(file);

        info!("Download completed for {}, verifying checksum...", model_id);

        // Verify checksum
        if let Some(expected) = expected_checksum {
            let actual = Self::calculate_file_checksum(file_path).await?;
            if actual != expected {
                return Err(ModelError::ChecksumMismatch {
                    expected: expected.to_string(),
                    actual,
                });
            }
            info!("Checksum verified for {}", model_id);
        }

        // Verify model integrity against registry if available
        if let Some(reg) = registry {
            info!(
                "Verifying model integrity against registry for {}",
                model_id
            );
            let model_data = fs::read(file_path).await?;
            reg.verify_model_integrity(model_id, &model_data)?;
            info!("Registry integrity verification passed for {}", model_id);
        }

        // Mark as completed
        if let Some(mut entry) = tasks.get_mut(model_id) {
            entry.mark_completed();
        }

        info!("Model {} downloaded and verified successfully", model_id);
        Ok(())
    }

    /// Calculates SHA-256 checksum of a file
    async fn calculate_file_checksum(file_path: &Path) -> Result<String> {
        use sha2::{Digest, Sha256};

        let contents = fs::read(file_path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&contents);
        let result = hasher.finalize();

        Ok(hex::encode(result))
    }

    /// Pauses an active download
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ModelNotFound` if the download doesn't exist.
    pub fn pause_download(&self, model_id: &str) -> Result<()> {
        if let Some(mut entry) = self.tasks.get_mut(model_id) {
            if entry.status == DownloadStatus::Downloading {
                entry.status = DownloadStatus::Paused;
                debug!("Paused download for model: {}", model_id);
                Ok(())
            } else {
                Err(ModelError::DownloadError(format!(
                    "Download for {} is not in progress",
                    model_id
                )))
            }
        } else {
            Err(ModelError::ModelNotFound(model_id.to_string()))
        }
    }

    /// Resumes a paused download
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ModelNotFound` if the download doesn't exist.
    pub fn resume_download(&self, model_id: &str) -> Result<()> {
        if let Some(mut entry) = self.tasks.get_mut(model_id) {
            if entry.status == DownloadStatus::Paused {
                entry.status = DownloadStatus::Downloading;
                info!("Resumed download for model: {}", model_id);
                Ok(())
            } else {
                Err(ModelError::DownloadError(format!(
                    "Download for {} is not paused",
                    model_id
                )))
            }
        } else {
            Err(ModelError::ModelNotFound(model_id.to_string()))
        }
    }

    /// Cancels a download
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ModelNotFound` if the download doesn't exist.
    pub async fn cancel_download(&self, model_id: &str) -> Result<()> {
        if let Some(mut entry) = self.tasks.get_mut(model_id) {
            entry.status = DownloadStatus::Cancelled;
            let file_path = entry.file_path.clone();
            drop(entry);

            // Remove partial download file
            if file_path.exists() {
                fs::remove_file(&file_path).await?;
            }

            warn!("Cancelled download for model: {}", model_id);
            Ok(())
        } else {
            Err(ModelError::ModelNotFound(model_id.to_string()))
        }
    }

    /// Gets the status of a download
    pub fn get_download_status(&self, model_id: &str) -> Option<DownloadTask> {
        self.tasks.get(model_id).map(|entry| entry.value().clone())
    }

    /// Lists all download tasks
    pub fn list_downloads(&self) -> Vec<DownloadTask> {
        self.tasks
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Lists active downloads
    pub fn list_active_downloads(&self) -> Vec<DownloadTask> {
        self.tasks
            .iter()
            .filter(|entry| entry.value().status == DownloadStatus::Downloading)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Verifies the checksum of a downloaded file
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ChecksumMismatch` if checksums don't match.
    /// Returns `ModelError::ModelNotFound` if the download doesn't exist.
    pub async fn verify_checksum(&self, model_id: &str) -> Result<bool> {
        let task = self
            .get_download_status(model_id)
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;

        if task.status != DownloadStatus::Completed {
            return Err(ModelError::DownloadError(
                "Download not completed".to_string(),
            ));
        }

        let expected_checksum = task.expected_checksum.as_ref().ok_or_else(|| {
            ModelError::DownloadError(
                "No checksum recorded for model — integrity cannot be verified".to_string(),
            )
        })?;

        let actual_checksum = Self::calculate_file_checksum(&task.file_path).await?;

        if &actual_checksum != expected_checksum {
            return Err(ModelError::ChecksumMismatch {
                expected: expected_checksum.clone(),
                actual: actual_checksum,
            });
        }

        info!("Checksum verified for model: {}", model_id);
        Ok(true)
    }

    /// Updates download progress for a task
    pub fn update_progress(&self, model_id: &str, downloaded_bytes: u64) -> Result<()> {
        if let Some(mut entry) = self.tasks.get_mut(model_id) {
            entry.update_progress(downloaded_bytes);
            Ok(())
        } else {
            Err(ModelError::ModelNotFound(model_id.to_string()))
        }
    }

    /// Marks a download as completed
    pub fn mark_completed(&self, model_id: &str) -> Result<()> {
        if let Some(mut entry) = self.tasks.get_mut(model_id) {
            entry.mark_completed();
            info!("Download completed for model: {}", model_id);
            Ok(())
        } else {
            Err(ModelError::ModelNotFound(model_id.to_string()))
        }
    }

    /// Marks a download as failed
    pub fn mark_failed(&self, model_id: &str, error: String) -> Result<()> {
        if let Some(mut entry) = self.tasks.get_mut(model_id) {
            entry.mark_failed(error.clone());
            warn!("Download failed for model {}: {}", model_id, error);
            Ok(())
        } else {
            Err(ModelError::ModelNotFound(model_id.to_string()))
        }
    }

    /// Gets the storage path for a model
    pub fn get_model_path(&self, model_id: &str) -> PathBuf {
        let file_name = format!("{}.model", model_id);
        self.storage_path.join(file_name)
    }

    /// Checks if a model is already downloaded
    pub fn is_downloaded(&self, model_id: &str) -> bool {
        let path = self.get_model_path(model_id);
        path.exists()
    }

    /// Removes a downloaded model file
    pub async fn remove_model(&self, model_id: &str) -> Result<()> {
        let path = self.get_model_path(model_id);
        if path.exists() {
            fs::remove_file(&path).await?;
            info!("Removed model file: {}", model_id);
        }

        // Also remove task if exists
        self.tasks.remove(model_id);

        Ok(())
    }

    /// Gets the count of active downloads
    pub fn active_download_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|entry| entry.value().status == DownloadStatus::Downloading)
            .count()
    }

    /// Gets the total download progress across all active downloads
    pub fn total_progress(&self) -> f64 {
        let downloads: Vec<_> = self.list_active_downloads();
        if downloads.is_empty() {
            return 0.0;
        }

        let total_progress: f64 = downloads.iter().map(|d| d.progress).sum();
        total_progress / downloads.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_download_task() {
        let task = DownloadTask::new(
            "model-1".to_string(),
            "https://example.com/model.bin".to_string(),
            1000,
            PathBuf::from("/tmp/model-1.model"),
            Some("abc123".to_string()),
        );

        assert_eq!(task.model_id, "model-1");
        assert_eq!(task.status, DownloadStatus::Pending);
        assert_eq!(task.progress, 0.0);
    }

    #[tokio::test]
    async fn test_update_progress() {
        let mut task = DownloadTask::new(
            "model-1".to_string(),
            "https://example.com/model.bin".to_string(),
            1000,
            PathBuf::from("/tmp/model-1.model"),
            None,
        );

        task.update_progress(500);
        assert_eq!(task.downloaded_bytes, 500);
        assert_eq!(task.progress, 0.5);

        task.update_progress(1000);
        assert_eq!(task.progress, 1.0);
    }

    #[tokio::test]
    async fn test_download_manager() {
        let temp_dir = std::env::temp_dir().join("tenzro-test-downloads");
        let _manager = DownloadManager::new(temp_dir.clone());

        // Clean up after test
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn test_download_requires_checksum() {
        let temp_dir = std::env::temp_dir().join("tenzro-test-checksum");
        let manager = DownloadManager::new(temp_dir.clone());

        // Download without checksum should fail
        let result = manager
            .start_download(
                "model-no-checksum".to_string(),
                "https://example.com/model.bin".to_string(),
                1000,
                None,
            )
            .await;
        assert!(result.is_err());

        // Download with checksum should succeed
        let result = manager
            .start_download(
                "model-with-checksum".to_string(),
                "https://example.com/model.bin".to_string(),
                1000,
                Some("abc123def456".to_string()),
            )
            .await;
        assert!(result.is_ok());

        // Clean up
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn test_download_status() {
        let mut task = DownloadTask::new(
            "model-1".to_string(),
            "https://example.com/model.bin".to_string(),
            1000,
            PathBuf::from("/tmp/model-1.model"),
            None,
        );

        assert_eq!(task.status, DownloadStatus::Pending);

        task.mark_started();
        assert_eq!(task.status, DownloadStatus::Downloading);

        task.mark_completed();
        assert_eq!(task.status, DownloadStatus::Completed);
        assert_eq!(task.progress, 1.0);
    }

    #[tokio::test]
    async fn test_download_manager_with_registry() {
        use crate::registry::ModelRegistry;

        let temp_dir = std::env::temp_dir().join("tenzro-test-with-registry");
        let registry = ModelRegistry::new();
        let manager = DownloadManager::new(temp_dir.clone()).with_registry(registry);

        // Verify manager was created successfully
        assert_eq!(manager.active_download_count(), 0);

        // Clean up
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
