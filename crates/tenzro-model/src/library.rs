//! Model library module
//!
//! This module provides a curated library of AI models that users can browse,
//! search, and download for use on Tenzro Network.

use crate::error::{ModelError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::model::{ModelInfo, ModelModality, ModelStatus};

/// Category for organizing models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCategory {
    /// Category name
    pub name: String,
    /// Category description
    pub description: String,
    /// Number of models in this category
    pub model_count: usize,
    /// Category type
    pub category_type: CategoryType,
}

impl ModelCategory {
    /// Creates a new model category
    pub fn new(name: String, description: String, category_type: CategoryType) -> Self {
        Self {
            name,
            description,
            model_count: 0,
            category_type,
        }
    }
}

/// Type of model category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CategoryType {
    /// Text generation models
    TextGeneration,
    /// Vision/image models
    Vision,
    /// Audio/speech models
    Audio,
    /// Timeseries forecasting models
    Timeseries,
    /// Embedding models
    Embedding,
    /// Multimodal models
    Multimodal,
    /// Code generation models
    Code,
    /// Translation models
    Translation,
    /// Summarization models
    Summarization,
    /// Question answering models
    QuestionAnswering,
    /// Other/custom category
    Other,
}

impl CategoryType {
    /// Returns the default description for this category type
    pub fn default_description(&self) -> &str {
        match self {
            CategoryType::TextGeneration => "Models for generating and completing text",
            CategoryType::Vision => "Models for image understanding and generation",
            CategoryType::Audio => "Models for audio processing and speech",
            CategoryType::Timeseries => "Models for time-series forecasting",
            CategoryType::Embedding => "Models for creating vector embeddings",
            CategoryType::Multimodal => "Models supporting multiple input/output modalities",
            CategoryType::Code => "Models specialized for code generation and understanding",
            CategoryType::Translation => "Models for translating between languages",
            CategoryType::Summarization => "Models for summarizing text",
            CategoryType::QuestionAnswering => "Models for answering questions",
            CategoryType::Other => "Other specialized models",
        }
    }

    /// Returns all category types
    pub fn all() -> Vec<CategoryType> {
        vec![
            CategoryType::TextGeneration,
            CategoryType::Vision,
            CategoryType::Audio,
            CategoryType::Timeseries,
            CategoryType::Embedding,
            CategoryType::Multimodal,
            CategoryType::Code,
            CategoryType::Translation,
            CategoryType::Summarization,
            CategoryType::QuestionAnswering,
            CategoryType::Other,
        ]
    }

    /// Suggests a category type based on model modality
    pub fn from_modality(modality: ModelModality) -> Self {
        match modality {
            ModelModality::Text => CategoryType::TextGeneration,
            ModelModality::Image => CategoryType::Vision,
            ModelModality::Audio => CategoryType::Audio,
            ModelModality::Timeseries => CategoryType::Timeseries,
            ModelModality::Video => CategoryType::Vision,
            ModelModality::TextImage | ModelModality::TextAudio | ModelModality::Multimodal => {
                CategoryType::Multimodal
            }
        }
    }
}

/// Featured or trending status for models
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelHighlight {
    /// Featured model
    Featured,
    /// Trending model
    Trending,
    /// New model
    New,
    /// Popular model
    Popular,
}

/// Extended model information for library
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryModelInfo {
    /// Base model information
    pub model: ModelInfo,
    /// Category this model belongs to
    pub category: CategoryType,
    /// Optional highlight status
    pub highlight: Option<ModelHighlight>,
    /// Download count
    pub download_count: u64,
    /// Average rating (0.0 - 5.0)
    pub rating: f64,
    /// Number of ratings
    pub rating_count: u32,
    /// Tags for searching
    pub tags: Vec<String>,
}

impl LibraryModelInfo {
    /// Creates new library model info
    pub fn new(model: ModelInfo, category: CategoryType) -> Self {
        Self {
            model,
            category,
            highlight: None,
            download_count: 0,
            rating: 0.0,
            rating_count: 0,
            tags: Vec::new(),
        }
    }

    /// Sets highlight status
    pub fn with_highlight(mut self, highlight: ModelHighlight) -> Self {
        self.highlight = Some(highlight);
        self
    }

    /// Adds tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Increments download count
    pub fn increment_downloads(&mut self) {
        self.download_count += 1;
    }

    /// Adds a rating
    pub fn add_rating(&mut self, rating: f64) {
        let total = self.rating * self.rating_count as f64 + rating;
        self.rating_count += 1;
        self.rating = total / self.rating_count as f64;
    }
}

/// Compatibility requirements for running a model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityRequirements {
    /// Minimum VRAM in GB
    pub min_vram_gb: u32,
    /// Minimum RAM in GB
    pub min_ram_gb: u32,
    /// Required GPU types
    pub gpu_types: Vec<String>,
    /// Minimum compute capability
    pub min_compute_capability: Option<String>,
}

impl CompatibilityRequirements {
    /// Creates basic compatibility requirements
    pub fn new(min_vram_gb: u32, min_ram_gb: u32) -> Self {
        Self {
            min_vram_gb,
            min_ram_gb,
            gpu_types: Vec::new(),
            min_compute_capability: None,
        }
    }

    /// Checks if given specs meet requirements
    pub fn is_compatible(&self, vram_gb: u32, ram_gb: u32) -> bool {
        vram_gb >= self.min_vram_gb && ram_gb >= self.min_ram_gb
    }
}

/// Model library for browsing and discovering models
#[derive(Debug, Clone)]
pub struct ModelLibrary {
    /// Models in the library
    models: Arc<DashMap<String, LibraryModelInfo>>,
    /// Compatibility requirements by model ID
    requirements: Arc<DashMap<String, CompatibilityRequirements>>,
}

impl ModelLibrary {
    /// Creates a new model library
    pub fn new() -> Self {
        Self {
            models: Arc::new(DashMap::new()),
            requirements: Arc::new(DashMap::new()),
        }
    }

    /// Adds a model to the library
    pub fn add_to_library(&self, model_info: LibraryModelInfo) -> Result<()> {
        let model_id = model_info.model.model_id.clone();
        self.models.insert(model_id, model_info);
        Ok(())
    }

    /// Removes a model from the library
    pub fn remove_from_library(&self, model_id: &str) -> Result<()> {
        self.models
            .remove(model_id)
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))?;
        self.requirements.remove(model_id);
        Ok(())
    }

    /// Sets compatibility requirements for a model
    pub fn set_requirements(
        &self,
        model_id: &str,
        requirements: CompatibilityRequirements,
    ) -> Result<()> {
        if !self.models.contains_key(model_id) {
            return Err(ModelError::ModelNotFound(model_id.to_string()));
        }
        self.requirements.insert(model_id.to_string(), requirements);
        Ok(())
    }

    /// Gets compatibility requirements for a model
    pub fn get_requirements(&self, model_id: &str) -> Option<CompatibilityRequirements> {
        self.requirements.get(model_id).map(|r| r.value().clone())
    }

    /// Lists all available models in the library
    pub fn list_available_models(&self) -> Vec<LibraryModelInfo> {
        self.models
            .iter()
            .filter(|entry| entry.value().model.status == ModelStatus::Active)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Gets detailed information about a model
    pub fn get_model_details(&self, model_id: &str) -> Result<LibraryModelInfo> {
        self.models
            .get(model_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| ModelError::ModelNotFound(model_id.to_string()))
    }

    /// Gets all categories with model counts
    pub fn get_categories(&self) -> Vec<ModelCategory> {
        let mut categories = std::collections::HashMap::new();

        for entry in self.models.iter() {
            let category_type = entry.value().category;
            *categories.entry(category_type).or_insert(0) += 1;
        }

        CategoryType::all()
            .into_iter()
            .map(|cat_type| {
                let count = categories.get(&cat_type).copied().unwrap_or(0);
                ModelCategory {
                    name: format!("{:?}", cat_type),
                    description: cat_type.default_description().to_string(),
                    model_count: count,
                    category_type: cat_type,
                }
            })
            .filter(|cat| cat.model_count > 0)
            .collect()
    }

    /// Gets models by category
    pub fn get_models_by_category(&self, category: CategoryType) -> Vec<LibraryModelInfo> {
        self.models
            .iter()
            .filter(|entry| entry.value().category == category)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Gets featured models
    pub fn get_featured_models(&self) -> Vec<LibraryModelInfo> {
        self.models
            .iter()
            .filter(|entry| entry.value().highlight == Some(ModelHighlight::Featured))
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Gets trending models
    pub fn get_trending_models(&self) -> Vec<LibraryModelInfo> {
        let mut models: Vec<LibraryModelInfo> = self
            .models
            .iter()
            .filter(|entry| entry.value().model.status == ModelStatus::Active)
            .map(|entry| entry.value().clone())
            .collect();

        // Sort by download count
        models.sort_by_key(|b| std::cmp::Reverse(b.download_count));

        models.into_iter().take(10).collect()
    }

    /// Gets new models (recently added)
    pub fn get_new_models(&self, limit: usize) -> Vec<LibraryModelInfo> {
        let mut models: Vec<LibraryModelInfo> = self
            .models
            .iter()
            .filter(|entry| entry.value().highlight == Some(ModelHighlight::New))
            .map(|entry| entry.value().clone())
            .collect();

        models.truncate(limit);
        models
    }

    /// Searches models by tag
    pub fn search_by_tag(&self, tag: &str) -> Vec<LibraryModelInfo> {
        self.models
            .iter()
            .filter(|entry| {
                entry
                    .value()
                    .tags
                    .iter()
                    .any(|t| t.to_lowercase().contains(&tag.to_lowercase()))
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Searches models by name or description
    pub fn search(&self, query: &str) -> Vec<LibraryModelInfo> {
        let query_lower = query.to_lowercase();
        self.models
            .iter()
            .filter(|entry| {
                let model_info = entry.value();
                model_info.model.name.to_lowercase().contains(&query_lower)
                    || model_info
                        .model
                        .description
                        .to_lowercase()
                        .contains(&query_lower)
                    || model_info
                        .tags
                        .iter()
                        .any(|t| t.to_lowercase().contains(&query_lower))
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Records a model download
    pub fn record_download(&self, model_id: &str) -> Result<()> {
        if let Some(mut entry) = self.models.get_mut(model_id) {
            entry.increment_downloads();
            Ok(())
        } else {
            Err(ModelError::ModelNotFound(model_id.to_string()))
        }
    }

    /// Checks if provider meets model compatibility requirements
    pub fn check_compatibility(
        &self,
        model_id: &str,
        vram_gb: u32,
        ram_gb: u32,
    ) -> Result<bool> {
        if let Some(requirements) = self.get_requirements(model_id) {
            Ok(requirements.is_compatible(vram_gb, ram_gb))
        } else {
            // No requirements means compatible
            Ok(true)
        }
    }

    /// Gets the count of models in the library
    pub fn count(&self) -> usize {
        self.models.len()
    }
}

impl Default for ModelLibrary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::model::ModelModality;
    use tenzro_types::primitives::Address;

    #[test]
    fn test_add_and_get_model() {
        let library = ModelLibrary::new();
        let model_info = create_test_library_model("test-model");

        library.add_to_library(model_info.clone()).unwrap();
        let retrieved = library.get_model_details("test-model").unwrap();

        assert_eq!(retrieved.model.model_id, "test-model");
    }

    #[test]
    fn test_get_categories() {
        let library = ModelLibrary::new();

        let mut model1 = create_test_library_model("text-model");
        model1.category = CategoryType::TextGeneration;

        let mut model2 = create_test_library_model("vision-model");
        model2.category = CategoryType::Vision;

        library.add_to_library(model1).unwrap();
        library.add_to_library(model2).unwrap();

        let categories = library.get_categories();
        assert_eq!(categories.len(), 2);
    }

    #[test]
    fn test_search() {
        let library = ModelLibrary::new();
        let mut model = create_test_library_model("gpt-test");
        model.model.name = "GPT Test Model".to_string();

        library.add_to_library(model).unwrap();

        let results = library.search("gpt");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].model.model_id, "gpt-test");
    }

    #[test]
    fn test_compatibility_check() {
        let library = ModelLibrary::new();
        let model = create_test_library_model("large-model");
        library.add_to_library(model).unwrap();

        let requirements = CompatibilityRequirements::new(16, 32);
        library
            .set_requirements("large-model", requirements)
            .unwrap();

        assert!(library.check_compatibility("large-model", 24, 64).unwrap());
        assert!(!library.check_compatibility("large-model", 8, 16).unwrap());
    }

    fn create_test_library_model(id: &str) -> LibraryModelInfo {
        let model = ModelInfo::new(
            id.to_string(),
            format!("Model {}", id),
            "1.0.0".to_string(),
            ModelModality::Text,
            Address::zero(),
        );

        LibraryModelInfo::new(model, CategoryType::TextGeneration)
    }
}
