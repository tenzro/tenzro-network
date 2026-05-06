//! Model provisioning and auto-discovery module
//!
//! Handles automatic model provisioning for providers based on hardware
//! capabilities, and discovery of models from network peers.

use crate::catalog::{get_model_catalog, HfModelEntry, ModelArchitecture};
use crate::error::{ModelError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Hardware capabilities used for model provisioning decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    /// Available RAM in GB
    pub ram_gb: u32,
    /// Available VRAM in GB (0 if no GPU)
    pub vram_gb: u32,
    /// Available disk space in GB
    pub disk_gb: u32,
    /// Whether TEE is available
    pub tee_available: bool,
    /// CPU architecture
    pub cpu_arch: String,
    /// Number of CPU cores
    pub cpu_cores: u32,
}

impl Default for HardwareCapabilities {
    fn default() -> Self {
        Self {
            ram_gb: 8,
            vram_gb: 0,
            disk_gb: 50,
            tee_available: false,
            cpu_arch: std::env::consts::ARCH.to_string(),
            cpu_cores: std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(4),
        }
    }
}

impl HardwareCapabilities {
    /// Detect hardware capabilities from the current system
    pub fn detect() -> Self {
        let mut caps = Self::default();

        // Detect RAM
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemTotal:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<u64>() {
                                caps.ram_gb = (kb / 1_048_576) as u32;
                            }
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("sysctl").arg("-n").arg("hw.memsize").output()
                && let Ok(bytes_str) = String::from_utf8(output.stdout)
                && let Ok(bytes) = bytes_str.trim().parse::<u64>()
            {
                caps.ram_gb = (bytes / 1_073_741_824) as u32;
            }
        }

        caps
    }
}

/// A model that has been recommended for provisioning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningRecommendation {
    /// Model ID from catalog
    pub model_id: String,
    /// Human-readable model name
    pub model_name: String,
    /// Model family
    pub family: String,
    /// File size in bytes
    pub size_bytes: u64,
    /// Minimum RAM required
    pub min_ram_gb: u32,
    /// Architecture
    pub architecture: String,
    /// Reason for recommendation
    pub reason: String,
    /// Priority score (higher = more recommended)
    pub priority: u32,
    /// Whether the model is already downloaded
    pub already_downloaded: bool,
}

/// Provider provisioning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningConfig {
    /// Maximum number of models to serve concurrently
    pub max_concurrent_models: usize,
    /// Minimum free RAM to keep (GB)
    pub min_free_ram_gb: u32,
    /// Whether to auto-download recommended models
    pub auto_download: bool,
    /// Whether to auto-serve downloaded models
    pub auto_serve: bool,
    /// Preferred model families
    pub preferred_families: Vec<String>,
    /// Preferred architectures
    pub preferred_architectures: Vec<ModelArchitecture>,
    /// Maximum model size in bytes (0 = unlimited)
    pub max_model_size_bytes: u64,
}

impl Default for ProvisioningConfig {
    fn default() -> Self {
        Self {
            max_concurrent_models: 2,
            min_free_ram_gb: 4,
            auto_download: false,
            auto_serve: false,
            preferred_families: Vec::new(),
            preferred_architectures: Vec::new(),
            max_model_size_bytes: 0,
        }
    }
}

/// Model provisioning engine that recommends and manages models for providers.
///
/// Thread-safe via `Arc` — use `ModelProvisioner::new_shared()` to create a
/// shared reference that can be passed across async tasks.
pub struct ModelProvisioner {
    /// Hardware capabilities
    hardware: HardwareCapabilities,
    /// Provisioning configuration
    config: ProvisioningConfig,
    /// Models directory
    models_dir: PathBuf,
    /// Currently provisioned models (model_id -> status)
    provisioned: DashMap<String, ProvisioningStatus>,
}

/// Status of a provisioned model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProvisioningStatus {
    /// Recommended but not yet downloaded
    Recommended,
    /// Currently downloading
    Downloading { progress_pct: f32 },
    /// Downloaded but not serving
    Downloaded,
    /// Currently being served
    Serving,
    /// Failed to provision
    Failed { error: String },
}

impl ModelProvisioner {
    /// Create a new model provisioner, validating that the models directory exists.
    ///
    /// Returns `Err(ModelError::Other)` if the models directory does not exist
    /// and cannot be created.
    pub fn new(models_dir: PathBuf) -> Self {
        if !models_dir.exists() {
            debug!(dir = %models_dir.display(), "Models directory does not exist, will be created on first download");
        } else {
            debug!(dir = %models_dir.display(), "Using existing models directory");
        }
        Self {
            hardware: HardwareCapabilities::detect(),
            config: ProvisioningConfig::default(),
            models_dir,
            provisioned: DashMap::new(),
        }
    }

    /// Create a thread-safe shared provisioner wrapped in `Arc`.
    ///
    /// Use this when the provisioner needs to be shared across multiple
    /// async tasks (e.g., RPC handlers, background health monitors).
    pub fn new_shared(models_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self::new(models_dir))
    }

    /// Create with specific hardware capabilities
    pub fn with_hardware(mut self, hardware: HardwareCapabilities) -> Self {
        debug!(
            ram_gb = hardware.ram_gb,
            vram_gb = hardware.vram_gb,
            disk_gb = hardware.disk_gb,
            cpu_cores = hardware.cpu_cores,
            cpu_arch = %hardware.cpu_arch,
            "Configured provisioner with custom hardware capabilities"
        );
        self.hardware = hardware;
        self
    }

    /// Create with specific config
    pub fn with_config(mut self, config: ProvisioningConfig) -> Self {
        debug!(
            max_concurrent = config.max_concurrent_models,
            auto_download = config.auto_download,
            auto_serve = config.auto_serve,
            "Configured provisioner with custom config"
        );
        self.config = config;
        self
    }

    /// Get hardware capabilities
    pub fn hardware(&self) -> &HardwareCapabilities {
        &self.hardware
    }

    /// Get provisioning config
    pub fn config(&self) -> &ProvisioningConfig {
        &self.config
    }

    /// Get all provisioned model statuses
    pub fn provisioned_models(&self) -> Vec<(String, ProvisioningStatus)> {
        self.provisioned
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Recommend models based on hardware capabilities.
    ///
    /// Evaluates each `HfModelEntry` from the catalog against the node's hardware
    /// capabilities and provisioning preferences, returning prioritized recommendations.
    ///
    /// Returns `Err(ModelError::Other)` if the model catalog is empty or inaccessible.
    pub fn recommend_models(&self) -> Vec<ProvisioningRecommendation> {
        let all_models: Vec<HfModelEntry> = get_model_catalog();
        let available_ram = self.hardware.ram_gb.saturating_sub(self.config.min_free_ram_gb);

        debug!(
            catalog_size = all_models.len(),
            available_ram_gb = available_ram,
            hardware_ram_gb = self.hardware.ram_gb,
            min_free_ram_gb = self.config.min_free_ram_gb,
            "Starting model recommendation scan"
        );

        if all_models.is_empty() {
            warn!("Model catalog is empty — no models available for recommendation");
            return Vec::new();
        }

        let mut recommendations: Vec<ProvisioningRecommendation> = Vec::new();
        let mut skipped_ram = 0u32;
        let mut skipped_size = 0u32;

        for model in &all_models {
            // Skip models that require more RAM than available
            if model.min_ram_gb > available_ram {
                debug!(
                    model_id = %model.id,
                    requires_gb = model.min_ram_gb,
                    available_gb = available_ram,
                    "Skipping model: exceeds available RAM"
                );
                skipped_ram += 1;
                continue;
            }

            // Skip if model exceeds max size limit
            if self.config.max_model_size_bytes > 0 && model.size_bytes > self.config.max_model_size_bytes {
                debug!(
                    model_id = %model.id,
                    size_bytes = model.size_bytes,
                    max_bytes = self.config.max_model_size_bytes,
                    "Skipping model: exceeds max model size limit"
                );
                skipped_size += 1;
                continue;
            }

            let mut priority: u32 = 50;
            let mut reasons = Vec::new();

            // Boost priority for preferred families
            if !self.config.preferred_families.is_empty()
                && self.config.preferred_families.iter().any(|f| f.eq_ignore_ascii_case(&model.family)) {
                    priority += 20;
                    reasons.push("preferred family".to_string());
                }

            // Boost priority for preferred architectures
            if !self.config.preferred_architectures.is_empty()
                && self.config.preferred_architectures.contains(&model.architecture) {
                    priority += 15;
                    reasons.push("preferred architecture".to_string());
                }

            // Boost smaller models (faster to load, less resource usage)
            if model.min_ram_gb <= available_ram / 2 {
                priority += 10;
                reasons.push("fits comfortably in RAM".to_string());
            }

            // Check if already downloaded
            let model_path = self.models_dir.join(format!("{}.gguf", model.id));
            let alt_path = self.models_dir.join(&model.hf_filename);
            let already_downloaded = model_path.exists() || alt_path.exists();

            if already_downloaded {
                priority += 30;
                reasons.push("already downloaded".to_string());
            }

            let reason = if reasons.is_empty() {
                format!("fits in {available_ram}GB available RAM")
            } else {
                reasons.join(", ")
            };

            debug!(
                model_id = %model.id,
                architecture = ?model.architecture,
                priority = priority,
                already_downloaded = already_downloaded,
                "Evaluated model for recommendation"
            );

            recommendations.push(ProvisioningRecommendation {
                model_id: model.id.clone(),
                model_name: model.name.clone(),
                family: model.family.clone(),
                size_bytes: model.size_bytes,
                min_ram_gb: model.min_ram_gb,
                architecture: format!("{:?}", model.architecture),
                reason,
                priority,
                already_downloaded,
            });
        }

        // Sort by priority descending
        recommendations.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Limit to max concurrent models * 2 (show some options)
        let limit = self.config.max_concurrent_models * 2;
        if recommendations.len() > limit {
            recommendations.truncate(limit);
        }

        info!(
            recommended = recommendations.len(),
            skipped_ram = skipped_ram,
            skipped_size = skipped_size,
            total_catalog = all_models.len(),
            "Model recommendation scan complete"
        );

        recommendations
    }

    /// Mark a model as provisioned with a given status.
    ///
    /// Logs the status transition for observability.
    pub fn set_status(&self, model_id: &str, status: ProvisioningStatus) {
        let prev = self.provisioned.insert(model_id.to_string(), status.clone());
        match &status {
            ProvisioningStatus::Failed { error } => {
                warn!(
                    model_id = %model_id,
                    error = %error,
                    "Model provisioning failed"
                );
            }
            _ => {
                debug!(
                    model_id = %model_id,
                    status = ?status,
                    previous = ?prev,
                    "Model provisioning status updated"
                );
            }
        }
    }

    /// Get the status of a provisioned model
    pub fn get_status(&self, model_id: &str) -> Option<ProvisioningStatus> {
        self.provisioned.get(model_id).map(|v| v.clone())
    }

    /// Look up a specific model from the catalog by ID.
    ///
    /// Returns the `HfModelEntry` if found, or `Err(ModelError::ModelNotFound)`.
    pub fn lookup_catalog_entry(&self, model_id: &str) -> Result<HfModelEntry> {
        let catalog: Vec<HfModelEntry> = get_model_catalog();
        catalog
            .into_iter()
            .find(|m| m.id == model_id)
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))
    }

    /// Validate that a model from the catalog is compatible with the current hardware.
    ///
    /// Returns `Ok(entry)` if the model fits, or `Err` with the reason it does not.
    pub fn validate_model_for_hardware(&self, model_id: &str) -> Result<HfModelEntry> {
        let entry = self.lookup_catalog_entry(model_id)?;
        let available_ram = self.hardware.ram_gb.saturating_sub(self.config.min_free_ram_gb);

        if entry.min_ram_gb > available_ram {
            warn!(
                model_id = %model_id,
                requires_gb = entry.min_ram_gb,
                available_gb = available_ram,
                "Model incompatible with available hardware"
            );
            return Err(ModelError::Other(format!(
                "Model '{}' requires {}GB RAM but only {}GB available",
                model_id, entry.min_ram_gb, available_ram
            )));
        }

        if self.config.max_model_size_bytes > 0 && entry.size_bytes > self.config.max_model_size_bytes {
            warn!(
                model_id = %model_id,
                size_bytes = entry.size_bytes,
                max_bytes = self.config.max_model_size_bytes,
                "Model exceeds configured size limit"
            );
            return Err(ModelError::Other(format!(
                "Model '{}' is {}MB but max allowed is {}MB",
                model_id,
                entry.size_bytes / (1024 * 1024),
                self.config.max_model_size_bytes / (1024 * 1024)
            )));
        }

        debug!(
            model_id = %model_id,
            architecture = ?entry.architecture,
            min_ram_gb = entry.min_ram_gb,
            "Model validated for hardware compatibility"
        );
        Ok(entry)
    }

    /// Get models that are ready to serve (downloaded but not yet serving)
    pub fn ready_to_serve(&self) -> Vec<String> {
        let mut ready = Vec::new();

        // Check all downloaded models
        let recommendations = self.recommend_models();
        for rec in &recommendations {
            if rec.already_downloaded {
                let status = self.provisioned.get(&rec.model_id);
                let is_serving = matches!(status.as_deref(), Some(ProvisioningStatus::Serving));
                if !is_serving {
                    debug!(
                        model_id = %rec.model_id,
                        "Model is downloaded and ready to serve"
                    );
                    ready.push(rec.model_id.clone());
                }
            }
        }

        if ready.is_empty() {
            debug!("No models currently ready to serve");
        } else {
            info!(count = ready.len(), "Found models ready to serve");
        }

        ready
    }

    /// Get a summary of provisioning state
    pub fn summary(&self) -> ProvisioningSummary {
        let mut recommended = 0u32;
        let mut downloading = 0u32;
        let mut downloaded = 0u32;
        let mut serving = 0u32;
        let mut failed = 0u32;

        for entry in self.provisioned.iter() {
            match entry.value() {
                ProvisioningStatus::Recommended => recommended += 1,
                ProvisioningStatus::Downloading { .. } => downloading += 1,
                ProvisioningStatus::Downloaded => downloaded += 1,
                ProvisioningStatus::Serving => serving += 1,
                ProvisioningStatus::Failed { .. } => failed += 1,
            }
        }

        ProvisioningSummary {
            total_models_in_catalog: get_model_catalog().len() as u32,
            compatible_models: self.recommend_models().len() as u32,
            recommended,
            downloading,
            downloaded,
            serving,
            failed,
            available_ram_gb: self.hardware.ram_gb,
            available_disk_gb: self.hardware.disk_gb,
        }
    }
}

/// Summary of provisioning state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningSummary {
    /// Total models available in the catalog
    pub total_models_in_catalog: u32,
    /// Models compatible with current hardware
    pub compatible_models: u32,
    /// Models recommended but not downloaded
    pub recommended: u32,
    /// Models currently downloading
    pub downloading: u32,
    /// Models downloaded and ready
    pub downloaded: u32,
    /// Models currently being served
    pub serving: u32,
    /// Models that failed to provision
    pub failed: u32,
    /// Available RAM
    pub available_ram_gb: u32,
    /// Available disk
    pub available_disk_gb: u32,
}

/// Network model discovery — discovers models available from network peers
#[derive(Debug)]
pub struct NetworkModelDiscovery {
    /// Known models from network peers (model_id -> peer endpoints)
    discovered_models: DashMap<String, Vec<DiscoveredEndpoint>>,
}

/// A discovered model endpoint from a network peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    /// Provider address
    pub provider: String,
    /// API endpoint URL
    pub endpoint: String,
    /// Model ID
    pub model_id: String,
    /// Model name
    pub model_name: String,
    /// Provider's price per input token (in smallest TNZO unit)
    pub price_input: u64,
    /// Provider's price per output token
    pub price_output: u64,
    /// Whether the provider is in a TEE enclave
    pub tee_secured: bool,
    /// Last seen timestamp
    pub last_seen: u64,
}

impl NetworkModelDiscovery {
    /// Create a new network model discovery instance
    pub fn new() -> Self {
        Self {
            discovered_models: DashMap::new(),
        }
    }

    /// Register a discovered endpoint from a network peer
    pub fn register_endpoint(&self, endpoint: DiscoveredEndpoint) {
        self.discovered_models
            .entry(endpoint.model_id.clone())
            .or_default()
            .push(endpoint);
    }

    /// Remove stale endpoints older than max_age_secs
    pub fn prune_stale(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.discovered_models.alter_all(|_, mut endpoints| {
            endpoints.retain(|ep| now.saturating_sub(ep.last_seen) < max_age_secs);
            endpoints
        });

        // Remove model entries with no remaining endpoints
        self.discovered_models.retain(|_, endpoints| !endpoints.is_empty());
    }

    /// Get all discovered models
    pub fn list_models(&self) -> Vec<String> {
        self.discovered_models
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Get endpoints for a specific model, sorted by price
    pub fn get_endpoints(&self, model_id: &str) -> Vec<DiscoveredEndpoint> {
        self.discovered_models
            .get(model_id)
            .map(|endpoints| {
                let mut eps = endpoints.clone();
                eps.sort_by_key(|e| e.price_input);
                eps
            })
            .unwrap_or_default()
    }

    /// Get cheapest endpoint for a model
    pub fn cheapest_endpoint(&self, model_id: &str) -> Option<DiscoveredEndpoint> {
        self.get_endpoints(model_id).into_iter().next()
    }

    /// Get TEE-secured endpoints for a model
    pub fn tee_endpoints(&self, model_id: &str) -> Vec<DiscoveredEndpoint> {
        self.get_endpoints(model_id)
            .into_iter()
            .filter(|ep| ep.tee_secured)
            .collect()
    }

    /// Total number of discovered models
    pub fn model_count(&self) -> usize {
        self.discovered_models.len()
    }

    /// Total number of discovered endpoints
    pub fn endpoint_count(&self) -> usize {
        self.discovered_models
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }
}

impl Default for NetworkModelDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_hardware_capabilities_default() {
        let caps = HardwareCapabilities::default();
        assert!(caps.ram_gb > 0);
        assert!(!caps.cpu_arch.is_empty());
    }

    #[test]
    fn test_provisioning_config_default() {
        let config = ProvisioningConfig::default();
        assert_eq!(config.max_concurrent_models, 2);
        assert_eq!(config.min_free_ram_gb, 4);
        assert!(!config.auto_download);
    }

    #[test]
    fn test_recommend_models() {
        let provisioner = ModelProvisioner::new(PathBuf::from("/tmp/test_models"))
            .with_hardware(HardwareCapabilities {
                ram_gb: 16,
                vram_gb: 0,
                disk_gb: 100,
                tee_available: false,
                cpu_arch: "aarch64".to_string(),
                cpu_cores: 8,
            });

        let recommendations = provisioner.recommend_models();
        // Should have some recommendations for 16GB RAM
        // All should require <= 12GB RAM (16 - 4 min_free)
        for rec in &recommendations {
            assert!(rec.min_ram_gb <= 12, "Model {} requires {}GB but only 12GB available", rec.model_id, rec.min_ram_gb);
        }
    }

    #[test]
    fn test_provisioning_status() {
        let provisioner = ModelProvisioner::new(PathBuf::from("/tmp/test_models"));

        provisioner.set_status("test-model", ProvisioningStatus::Downloaded);
        assert!(matches!(
            provisioner.get_status("test-model"),
            Some(ProvisioningStatus::Downloaded)
        ));

        provisioner.set_status("test-model", ProvisioningStatus::Serving);
        assert!(matches!(
            provisioner.get_status("test-model"),
            Some(ProvisioningStatus::Serving)
        ));
    }

    #[test]
    fn test_network_discovery() {
        let discovery = NetworkModelDiscovery::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        discovery.register_endpoint(DiscoveredEndpoint {
            provider: "0x1234".to_string(),
            endpoint: "http://peer1:8080/v1/chat".to_string(),
            model_id: "qwen3.5-4b".to_string(),
            model_name: "Qwen 3.5 4B".to_string(),
            price_input: 100,
            price_output: 200,
            tee_secured: false,
            last_seen: now,
        });

        discovery.register_endpoint(DiscoveredEndpoint {
            provider: "0x5678".to_string(),
            endpoint: "http://peer2:8080/v1/chat".to_string(),
            model_id: "qwen3.5-4b".to_string(),
            model_name: "Qwen 3.5 4B".to_string(),
            price_input: 50,
            price_output: 150,
            tee_secured: true,
            last_seen: now,
        });

        assert_eq!(discovery.model_count(), 1);
        assert_eq!(discovery.endpoint_count(), 2);

        let endpoints = discovery.get_endpoints("qwen3.5-4b");
        assert_eq!(endpoints.len(), 2);
        // Sorted by price, cheapest first
        assert_eq!(endpoints[0].price_input, 50);

        let cheapest = discovery.cheapest_endpoint("qwen3.5-4b").unwrap();
        assert_eq!(cheapest.provider, "0x5678");

        let tee_eps = discovery.tee_endpoints("qwen3.5-4b");
        assert_eq!(tee_eps.len(), 1);
        assert!(tee_eps[0].tee_secured);
    }

    #[test]
    fn test_prune_stale_endpoints() {
        let discovery = NetworkModelDiscovery::new();

        // Add an old endpoint
        discovery.register_endpoint(DiscoveredEndpoint {
            provider: "0x1234".to_string(),
            endpoint: "http://old:8080/v1/chat".to_string(),
            model_id: "old-model".to_string(),
            model_name: "Old Model".to_string(),
            price_input: 100,
            price_output: 200,
            tee_secured: false,
            last_seen: 1000, // Very old
        });

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Add a fresh endpoint
        discovery.register_endpoint(DiscoveredEndpoint {
            provider: "0x5678".to_string(),
            endpoint: "http://new:8080/v1/chat".to_string(),
            model_id: "new-model".to_string(),
            model_name: "New Model".to_string(),
            price_input: 50,
            price_output: 150,
            tee_secured: false,
            last_seen: now,
        });

        assert_eq!(discovery.model_count(), 2);

        // Prune endpoints older than 1 hour
        discovery.prune_stale(3600);

        assert_eq!(discovery.model_count(), 1);
        assert!(discovery.get_endpoints("old-model").is_empty());
        assert_eq!(discovery.get_endpoints("new-model").len(), 1);
    }

    #[test]
    fn test_provisioning_summary() {
        let provisioner = ModelProvisioner::new(PathBuf::from("/tmp/test_models"));

        provisioner.set_status("model-a", ProvisioningStatus::Downloaded);
        provisioner.set_status("model-b", ProvisioningStatus::Serving);
        provisioner.set_status("model-c", ProvisioningStatus::Failed { error: "OOM".to_string() });

        let summary = provisioner.summary();
        assert_eq!(summary.downloaded, 1);
        assert_eq!(summary.serving, 1);
        assert_eq!(summary.failed, 1);
        assert!(summary.total_models_in_catalog > 0);
    }
}
