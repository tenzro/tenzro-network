//! Model registry module
//!
//! This module provides a central catalog of all AI models available on Tenzro Network.
//! It handles model registration, updates, search, and verification.

use crate::error::{ModelError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_storage::kv::{CF_MODELS, KvStore};
use tenzro_types::{
    model::{AcceptancePolicy, ModelInfo, ModelModality, ModelStatus},
    primitives::{Address, Hash, Timestamp},
};
use tracing::{debug, info, warn};

/// Storage key prefix for `ModelInfo` catalog records in `CF_MODELS`.
///
/// Node-level served-model markers are written to `CF_MODELS` under the raw
/// `model_id` key by `tenzro-node`. To avoid collision, the `ModelRegistry`
/// catalog uses an explicit `info:` prefix so the two can coexist in the
/// same column family.
const MODEL_INFO_KEY_PREFIX: &[u8] = b"info:";

/// Re-derive catalog-owned fields on a record loaded from storage.
///
/// A persisted `ModelInfo` mixes two kinds of field: facts about *this*
/// deployment (artifact hash, provider, status, endpoint) and facts about the
/// model itself (size, context window, license), which the built-in catalog
/// owns. Only the first kind belongs in storage. When the second kind is
/// persisted too, a record written by an older build shadows the catalog
/// forever, and no amount of re-serving fixes it — the row is loaded before
/// anything would rewrite it.
///
/// That is not hypothetical: `parameter_count` was never populated, so every
/// stored model hydrated size-less, the router tiered them all `Cheap`, and
/// `quality_floor=strong` was unsatisfiable on a node serving a 35B. Filling
/// the field in at its source fixed new registrations and did nothing for the
/// rows already on disk.
///
/// Deployment facts are left exactly as stored.
fn refresh_catalog_fields(mut model: ModelInfo) -> ModelInfo {
    let Some(entry) = crate::catalog::get_model_catalog()
        .into_iter()
        .find(|e| e.id == model.model_id)
    else {
        // Not a catalog model (a peer's offer, a cortex worker, an operator's
        // own GGUF): nothing to re-derive, and its stored metadata is the only
        // description that exists.
        return model;
    };
    let fresh = entry.to_model_info(model.provider);
    model.parameters.parameter_count = fresh.parameters.parameter_count;
    model.parameters.context_window = fresh.parameters.context_window;
    model
}

/// Filter criteria for searching models
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelFilter {
    /// Filter by modality
    pub modality: Option<ModelModality>,
    /// Minimum context window size
    pub min_context_window: Option<u32>,
    /// Maximum price per token (in smallest TNZO unit)
    pub max_price: Option<u64>,
    /// Filter by status
    pub status: Option<ModelStatus>,
    /// Search by name substring
    pub name_contains: Option<String>,
    /// Filter by provider
    pub provider: Option<Address>,
}

impl ModelFilter {
    /// Creates a new empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets modality filter
    pub fn with_modality(mut self, modality: ModelModality) -> Self {
        self.modality = Some(modality);
        self
    }

    /// Sets minimum context window filter
    pub fn with_min_context_window(mut self, size: u32) -> Self {
        self.min_context_window = Some(size);
        self
    }

    /// Sets maximum price filter
    pub fn with_max_price(mut self, price: u64) -> Self {
        self.max_price = Some(price);
        self
    }

    /// Sets status filter
    pub fn with_status(mut self, status: ModelStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Checks if a model matches this filter
    pub fn matches(&self, model: &ModelInfo) -> bool {
        if let Some(modality) = self.modality
            && !model.modality.supports(modality)
        {
            return false;
        }

        if let Some(min_ctx) = self.min_context_window
            && model.parameters.context_window < min_ctx
        {
            return false;
        }

        if let Some(max_price) = self.max_price {
            let model_price = model
                .pricing
                .price_per_input_token
                .max(model.pricing.price_per_output_token);
            if model_price > max_price {
                return false;
            }
        }

        if let Some(status) = self.status
            && model.status != status
        {
            return false;
        }

        if let Some(ref name_filter) = self.name_contains
            && !model
                .name
                .to_lowercase()
                .contains(&name_filter.to_lowercase())
        {
            return false;
        }

        if let Some(provider) = self.provider
            && model.provider != provider
        {
            return false;
        }

        true
    }
}

/// Events emitted by the model registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryEvent {
    /// A new model was registered
    ModelRegistered {
        model_id: String,
        provider: Address,
        timestamp: Timestamp,
    },
    /// A model was updated
    ModelUpdated {
        model_id: String,
        timestamp: Timestamp,
    },
    /// A model was deactivated
    ModelDeactivated {
        model_id: String,
        timestamp: Timestamp,
    },
}

/// Central registry for AI models on Tenzro Network
#[derive(Clone)]
pub struct ModelRegistry {
    /// Map of model_id to ModelInfo
    models: Arc<DashMap<String, ModelInfo>>,
    /// Optional persistent storage backend. When set, all registry mutations
    /// are written through to `CF_MODELS` under the `info:<model_id>` key.
    storage: Option<Arc<dyn KvStore>>,
    /// Operator license-acceptance policy. `register_model` refuses any model
    /// whose `license_tier` is not admitted by this policy: NonCommercial
    /// requires `accept_non_commercial`, CommercialCustom requires the
    /// model's `license_id` to be in `accepted_license_ids`.
    acceptance: AcceptancePolicy,
}

impl std::fmt::Debug for ModelRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelRegistry")
            .field("models", &self.models.len())
            .field("storage", &self.storage.is_some())
            .finish()
    }
}

impl ModelRegistry {
    /// Creates a new in-memory-only model registry.
    ///
    /// Use [`ModelRegistry::with_storage`] for a persistent registry that
    /// survives node restarts.
    pub fn new() -> Self {
        Self {
            models: Arc::new(DashMap::new()),
            storage: None,
            acceptance: AcceptancePolicy::default(),
        }
    }

    /// Creates a new model registry backed by persistent RocksDB storage.
    ///
    /// Hydrates the in-memory catalog from `CF_MODELS` on construction by
    /// scanning keys with the `info:` prefix. Subsequent calls to
    /// `register_model`, `update_model`, and `deactivate_model` write
    /// through to storage so the catalog survives restarts.
    ///
    /// Catalog-derived fields are re-read from the built-in catalog as each
    /// record loads — see [`refresh_catalog_fields`].
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let models: Arc<DashMap<String, ModelInfo>> = Arc::new(DashMap::new());

        // Hydrate from storage: scan CF_MODELS for `info:<model_id>` records.
        match storage.get_keys_with_prefix(CF_MODELS, MODEL_INFO_KEY_PREFIX) {
            Ok(keys) => {
                let mut hydrated = 0usize;
                for key_bytes in &keys {
                    match storage.get(CF_MODELS, key_bytes) {
                        Ok(Some(data)) => match serde_json::from_slice::<ModelInfo>(&data) {
                            Ok(model) => {
                                let model_id = model.model_id.clone();
                                models.insert(model_id, refresh_catalog_fields(model));
                                hydrated += 1;
                            }
                            Err(e) => {
                                let key_str = std::str::from_utf8(key_bytes).unwrap_or("<binary>");
                                warn!("Failed to deserialize model at key {}: {}", key_str, e);
                            }
                        },
                        Ok(None) => {}
                        Err(e) => {
                            warn!("Storage read failure during ModelRegistry hydration: {}", e);
                        }
                    }
                }
                if hydrated > 0 {
                    info!("Hydrated {} model(s) from RocksDB CF_MODELS", hydrated);
                }
            }
            Err(e) => {
                warn!(
                    "Failed to scan CF_MODELS during ModelRegistry hydration: {}",
                    e
                );
            }
        }

        Self {
            models,
            storage: Some(storage),
            acceptance: AcceptancePolicy::default(),
        }
    }

    /// Sets the operator license-acceptance policy consulted by
    /// [`ModelRegistry::register_model`]. Wired from the node's CLI flags
    /// (`--accept-non-commercial`, `--accept-license <id>`).
    pub fn with_acceptance_policy(mut self, acceptance: AcceptancePolicy) -> Self {
        self.acceptance = acceptance;
        self
    }

    /// Computes the storage key for a model catalog record.
    fn storage_key(model_id: &str) -> Vec<u8> {
        [MODEL_INFO_KEY_PREFIX, model_id.as_bytes()].concat()
    }

    /// Persists a single model record to storage, if a backend is configured.
    fn persist_model(&self, model: &ModelInfo) {
        if let Some(ref storage) = self.storage {
            match serde_json::to_vec(model) {
                Ok(data) => {
                    let key = Self::storage_key(&model.model_id);
                    if let Err(e) = storage.put(CF_MODELS, &key, &data) {
                        warn!(
                            "Failed to persist model {} to CF_MODELS: {}",
                            model.model_id, e
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to serialize model {}: {}", model.model_id, e);
                }
            }
        }
    }

    /// Removes a model record from storage, if a backend is configured.
    fn remove_from_storage(&self, model_id: &str) {
        if let Some(ref storage) = self.storage {
            let key = Self::storage_key(model_id);
            if let Err(e) = storage.delete(CF_MODELS, &key) {
                warn!("Failed to remove model {} from CF_MODELS: {}", model_id, e);
            }
        }
    }

    /// Registers a new model in the registry
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ModelAlreadyExists` if a model with the same ID already exists.
    /// Returns `ModelError::InvalidModel` if the model configuration is invalid.
    pub fn register_model(&self, model: ModelInfo) -> Result<RegistryEvent> {
        // Validate model
        self.validate_model(&model)?;

        let model_id = model.model_id.clone();
        let provider = model.provider;

        // Check if model already exists
        if self.models.contains_key(&model_id) {
            return Err(ModelError::ModelAlreadyExists(model_id));
        }

        // Verify model hash is not zero (requires proper hash)
        if model.model_hash == Hash::zero() {
            return Err(ModelError::InvalidModel(
                "Model hash cannot be zero - SHA-256 hash required for integrity verification"
                    .to_string(),
            ));
        }

        // License gate: refuse models whose tier the operator has not accepted.
        if !self
            .acceptance
            .admits(model.license_tier, model.license_id.as_deref())
        {
            return Err(ModelError::LicenseNotAccepted {
                model_id,
                tier: model.license_tier,
                license_id: model.license_id.clone(),
            });
        }

        // Persist first so a restart never surfaces a model that wasn't durable.
        self.persist_model(&model);

        // Insert model
        self.models.insert(model_id.clone(), model);

        info!("Registered new model: {} with hash verification", model_id);

        Ok(RegistryEvent::ModelRegistered {
            model_id,
            provider,
            timestamp: Timestamp::now(),
        })
    }

    /// Retrieves a model by ID
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ModelNotFound` if the model doesn't exist.
    pub fn get_model(&self, model_id: &str) -> Result<ModelInfo> {
        self.models
            .get(model_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))
    }

    /// Updates an existing model
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ModelNotFound` if the model doesn't exist.
    /// Returns `ModelError::InvalidModel` if the updated configuration is invalid.
    pub fn update_model(&self, model: ModelInfo) -> Result<RegistryEvent> {
        // Validate model
        self.validate_model(&model)?;

        let model_id = model.model_id.clone();

        // Check if model exists
        if !self.models.contains_key(&model_id) {
            return Err(ModelError::ModelNotFound(model_id));
        }

        // Write-through to storage before updating the in-memory copy.
        self.persist_model(&model);

        // Update model
        self.models.insert(model_id.clone(), model);

        debug!("Updated model: {}", model_id);

        Ok(RegistryEvent::ModelUpdated {
            model_id,
            timestamp: Timestamp::now(),
        })
    }

    /// Deactivates a model (sets status to Inactive)
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ModelNotFound` if the model doesn't exist.
    pub fn deactivate_model(&self, model_id: &str) -> Result<RegistryEvent> {
        let mut model = self.get_model(model_id)?;
        model.status = ModelStatus::Inactive;
        // Persist the status change so a restart reflects the deactivation.
        self.persist_model(&model);
        self.models.insert(model_id.to_string(), model);

        warn!("Deactivated model: {}", model_id);

        Ok(RegistryEvent::ModelDeactivated {
            model_id: model_id.to_string(),
            timestamp: Timestamp::now(),
        })
    }

    /// Permanently removes a model from the registry (both memory and storage).
    ///
    /// Unlike `deactivate_model`, this deletes the catalog record. Use with
    /// care — provider deregistration typically only needs `deactivate_model`.
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ModelNotFound` if the model doesn't exist.
    pub fn remove_model(&self, model_id: &str) -> Result<()> {
        if !self.models.contains_key(model_id) {
            return Err(ModelError::ModelNotFound(model_id.to_string()));
        }
        self.models.remove(model_id);
        self.remove_from_storage(model_id);
        info!("Removed model from registry: {}", model_id);
        Ok(())
    }

    /// Lists all models in the registry
    pub fn list_models(&self) -> Vec<ModelInfo> {
        self.models
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Searches for models matching the given filter
    pub fn search_models(&self, filter: &ModelFilter) -> Vec<ModelInfo> {
        self.models
            .iter()
            .filter(|entry| filter.matches(entry.value()))
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Convenience helper: returns every model whose modality supports the
    /// requested one. Equivalent to `search_models(&ModelFilter::new()
    /// .with_modality(modality))` but reads more naturally at call sites
    /// that just want a per-modality slice of the catalog.
    pub fn get_models_by_modality(&self, modality: ModelModality) -> Vec<ModelInfo> {
        self.search_models(&ModelFilter::new().with_modality(modality))
    }

    /// Verifies a model's hash matches the expected hash
    pub fn verify_model_hash(&self, model_id: &str, expected_hash: &Hash) -> Result<bool> {
        let model = self.get_model(model_id)?;
        Ok(&model.model_hash == expected_hash)
    }

    /// Verifies model integrity by computing SHA-256 hash of model data
    ///
    /// # Arguments
    ///
    /// * `model_id` - The model identifier
    /// * `model_data` - The raw model file bytes
    ///
    /// # Errors
    ///
    /// Returns `ModelError::ChecksumMismatch` if the computed hash doesn't match the registered hash.
    pub fn verify_model_integrity(&self, model_id: &str, model_data: &[u8]) -> Result<bool> {
        let model = self.get_model(model_id)?;

        // Compute SHA-256 hash of model data
        let computed_hash = self.compute_model_hash(model_data);

        // Compare with stored hash
        if computed_hash != model.model_hash {
            return Err(ModelError::ChecksumMismatch {
                expected: hex::encode(model.model_hash.as_bytes()),
                actual: hex::encode(computed_hash.as_bytes()),
            });
        }

        info!("Model integrity verified for: {}", model_id);
        Ok(true)
    }

    /// Computes SHA-256 hash of model data
    ///
    /// # Arguments
    ///
    /// * `data` - The raw bytes to hash
    ///
    /// # Returns
    ///
    /// A Hash containing the SHA-256 digest
    pub fn compute_model_hash(&self, data: &[u8]) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        Hash::from_bytes(&result).expect("SHA-256 always produces 32 bytes")
    }

    /// Gets the count of models in the registry
    pub fn count(&self) -> usize {
        self.models.len()
    }

    /// Validates a model configuration
    fn validate_model(&self, model: &ModelInfo) -> Result<()> {
        // Validate model ID is not empty
        if model.model_id.is_empty() {
            return Err(ModelError::InvalidModel(
                "Model ID cannot be empty".to_string(),
            ));
        }

        // Validate name is not empty
        if model.name.is_empty() {
            return Err(ModelError::InvalidModel(
                "Model name cannot be empty".to_string(),
            ));
        }

        // Validate version is not empty
        if model.version.is_empty() {
            return Err(ModelError::InvalidModel(
                "Model version cannot be empty".to_string(),
            ));
        }

        // Validate context window is reasonable
        if model.parameters.context_window == 0 {
            return Err(ModelError::InvalidModel(
                "Context window must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::model::{
        LicenseTier, ModelModality, ModelParameters, ModelVisibility, PricingConfig,
    };

    #[test]
    fn test_register_and_get_model() {
        let registry = ModelRegistry::new();
        let model = create_test_model("test-model-1");

        registry.register_model(model.clone()).unwrap();
        let retrieved = registry.get_model("test-model-1").unwrap();

        assert_eq!(retrieved.model_id, "test-model-1");
        assert_eq!(retrieved.name, model.name);
    }

    #[test]
    fn test_duplicate_registration() {
        let registry = ModelRegistry::new();
        let model = create_test_model("test-model-1");

        registry.register_model(model.clone()).unwrap();
        let result = registry.register_model(model);

        assert!(matches!(result, Err(ModelError::ModelAlreadyExists(_))));
    }

    #[test]
    fn test_update_model() {
        let registry = ModelRegistry::new();
        let mut model = create_test_model("test-model-1");

        registry.register_model(model.clone()).unwrap();

        model.description = "Updated description".to_string();
        registry.update_model(model.clone()).unwrap();

        let retrieved = registry.get_model("test-model-1").unwrap();
        assert_eq!(retrieved.description, "Updated description");
    }

    #[test]
    fn test_deactivate_model() {
        let registry = ModelRegistry::new();
        let model = create_test_model("test-model-1");

        registry.register_model(model).unwrap();
        registry.deactivate_model("test-model-1").unwrap();

        let retrieved = registry.get_model("test-model-1").unwrap();
        assert_eq!(retrieved.status, ModelStatus::Inactive);
    }

    #[test]
    fn test_search_models() {
        let registry = ModelRegistry::new();

        let mut model1 = create_test_model("text-model");
        model1.modality = ModelModality::Text;

        let mut model2 = create_test_model("image-model");
        model2.modality = ModelModality::Image;

        registry.register_model(model1).unwrap();
        registry.register_model(model2).unwrap();

        let filter = ModelFilter::new().with_modality(ModelModality::Text);
        let results = registry.search_models(&filter);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].model_id, "text-model");
    }

    #[test]
    fn test_modality_supports_exact_match() {
        assert!(ModelModality::Text.supports(ModelModality::Text));
        assert!(ModelModality::Image.supports(ModelModality::Image));
        assert!(ModelModality::Audio.supports(ModelModality::Audio));
        assert!(ModelModality::Video.supports(ModelModality::Video));
        assert!(ModelModality::TextImage.supports(ModelModality::TextImage));
        assert!(ModelModality::Multimodal.supports(ModelModality::Multimodal));
    }

    #[test]
    fn test_modality_supports_compound() {
        // TextImage supports both Text and Image
        assert!(ModelModality::TextImage.supports(ModelModality::Text));
        assert!(ModelModality::TextImage.supports(ModelModality::Image));
        assert!(!ModelModality::TextImage.supports(ModelModality::Audio));

        // TextAudio supports both Text and Audio
        assert!(ModelModality::TextAudio.supports(ModelModality::Text));
        assert!(ModelModality::TextAudio.supports(ModelModality::Audio));
        assert!(!ModelModality::TextAudio.supports(ModelModality::Image));

        // Multimodal supports everything
        assert!(ModelModality::Multimodal.supports(ModelModality::Text));
        assert!(ModelModality::Multimodal.supports(ModelModality::Image));
        assert!(ModelModality::Multimodal.supports(ModelModality::Audio));
        assert!(ModelModality::Multimodal.supports(ModelModality::Video));

        // Single modalities don't support other singles
        assert!(!ModelModality::Text.supports(ModelModality::Image));
        assert!(!ModelModality::Image.supports(ModelModality::Text));
        assert!(!ModelModality::Audio.supports(ModelModality::Video));
    }

    #[test]
    fn test_search_models_inclusive_modality() {
        let registry = ModelRegistry::new();

        let mut text_model = create_test_model("text-only");
        text_model.modality = ModelModality::Text;

        let mut text_image_model = create_test_model("text-image");
        text_image_model.modality = ModelModality::TextImage;

        let mut multi_model = create_test_model("multimodal");
        multi_model.modality = ModelModality::Multimodal;

        let mut image_model = create_test_model("image-only");
        image_model.modality = ModelModality::Image;

        registry.register_model(text_model).unwrap();
        registry.register_model(text_image_model).unwrap();
        registry.register_model(multi_model).unwrap();
        registry.register_model(image_model).unwrap();

        // Searching for Text returns text-only + text-image + multimodal
        let filter = ModelFilter::new().with_modality(ModelModality::Text);
        let results = registry.search_models(&filter);
        assert_eq!(results.len(), 3);

        // Searching for Image returns image-only + text-image + multimodal
        let filter = ModelFilter::new().with_modality(ModelModality::Image);
        let results = registry.search_models(&filter);
        assert_eq!(results.len(), 3);

        // Searching for Video returns only multimodal
        let filter = ModelFilter::new().with_modality(ModelModality::Video);
        let results = registry.search_models(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].model_id, "multimodal");
    }

    /// A row written by an older build must not pin stale catalog metadata.
    /// `parameter_count` hydrating as `None` is what made every stored model
    /// tier `Cheap`, so `quality_floor=strong` could not be satisfied.
    #[test]
    fn hydration_re_reads_catalog_owned_fields() {
        let mut stale = create_test_model("qwen3.6-35b-a3b-mtp");
        stale.parameters.parameter_count = None;
        stale.parameters.context_window = 1;
        // A deployment fact, which must survive untouched.
        stale.status = tenzro_types::model::ModelStatus::Active;
        let stored_hash = stale.model_hash;

        let fresh = refresh_catalog_fields(stale);
        assert_eq!(
            fresh.parameters.parameter_count,
            Some(35_000_000_000),
            "the catalog owns size; storage must not pin it"
        );
        assert!(fresh.parameters.context_window > 1);
        assert_eq!(
            fresh.model_hash, stored_hash,
            "artifact hash is deployment state"
        );
        assert_eq!(fresh.status, tenzro_types::model::ModelStatus::Active);
    }

    /// A model the catalog has never heard of — a peer's offer, an operator's
    /// own GGUF — keeps exactly what was stored.
    #[test]
    fn hydration_leaves_non_catalog_models_alone() {
        let mut stored = create_test_model("someones-private-finetune");
        stored.parameters.parameter_count = Some(123);
        stored.parameters.context_window = 4096;

        let after = refresh_catalog_fields(stored);
        assert_eq!(after.parameters.parameter_count, Some(123));
        assert_eq!(after.parameters.context_window, 4096);
    }

    fn create_test_model(id: &str) -> ModelInfo {
        // Create a non-zero hash for testing (using SHA-256 of model ID)
        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        let result = hasher.finalize();
        let model_hash = Hash::from_bytes(&result).expect("SHA-256 produces 32 bytes");

        ModelInfo {
            model_id: id.to_string(),
            name: format!("Test Model {}", id),
            version: "1.0.0".to_string(),
            description: "Test model".to_string(),
            modality: ModelModality::Text,
            architecture: "transformer".to_string(),
            provider: Address::zero(),
            model_hash,
            parameters: ModelParameters::default(),
            pricing: PricingConfig::default(),
            status: ModelStatus::Active,
            metadata: Default::default(),
            size_bytes: 0,
            moe: None,
            timeseries: None,
            vision: None,
            audio: None,
            video: None,
            license_tier: LicenseTier::Permissive,
            license: String::new(),
            license_id: None,
            visibility: ModelVisibility::Network,
            blake3_hash: None,
            tenzro_uri: None,
            peer_hints: Vec::new(),
        }
    }
}
