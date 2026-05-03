//! Pricing engine module
//!
//! This module handles cost calculation, price estimation, and dynamic pricing
//! for inference requests on Tenzro Network.

use crate::error::{ModelError, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tenzro_types::{
    asset::AssetId,
    model::{InferenceMetadata, PricingConfig, PricingModel},
    primitives::Timestamp,
};
use parking_lot::RwLock;

/// Price estimate for an inference request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceEstimate {
    /// Minimum price across all providers
    pub min_price: u64,
    /// Maximum price across all providers
    pub max_price: u64,
    /// Estimated price based on average
    pub estimated_price: u64,
    /// Currency/asset ID
    pub currency: AssetId,
    /// Number of providers considered
    pub provider_count: usize,
}

impl PriceEstimate {
    /// Creates a new price estimate
    pub fn new(
        min_price: u64,
        max_price: u64,
        estimated_price: u64,
        currency: AssetId,
        provider_count: usize,
    ) -> Self {
        Self {
            min_price,
            max_price,
            estimated_price,
            currency,
            provider_count,
        }
    }
}

/// Historical price data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceDataPoint {
    /// Price in smallest unit
    pub price: u64,
    /// Timestamp of the transaction
    pub timestamp: Timestamp,
    /// Model ID
    pub model_id: String,
}

/// Market data for dynamic pricing
#[derive(Debug, Clone)]
struct MarketData {
    /// Recent price history (limited size)
    price_history: VecDeque<PriceDataPoint>,
    /// Maximum history size
    max_history_size: usize,
    /// Moving average window size
    moving_average_window: usize,
}

impl MarketData {
    fn new(max_history_size: usize, moving_average_window: usize) -> Self {
        Self {
            price_history: VecDeque::with_capacity(max_history_size),
            max_history_size,
            moving_average_window,
        }
    }

    fn add_price(&mut self, data_point: PriceDataPoint) {
        if self.price_history.len() >= self.max_history_size {
            self.price_history.pop_front();
        }
        self.price_history.push_back(data_point);
    }

    fn calculate_moving_average(&self) -> Option<u64> {
        if self.price_history.is_empty() {
            return None;
        }

        let window_size = self.moving_average_window.min(self.price_history.len());
        let recent_prices: Vec<u64> = self
            .price_history
            .iter()
            .rev()
            .take(window_size)
            .map(|p| p.price)
            .collect();

        let sum: u64 = recent_prices.iter().sum();
        Some(sum / window_size as u64)
    }

    fn get_price_range(&self) -> Option<(u64, u64)> {
        if self.price_history.is_empty() {
            return None;
        }

        let prices: Vec<u64> = self.price_history.iter().map(|p| p.price).collect();
        let min = *prices.iter().min()?;
        let max = *prices.iter().max()?;
        Some((min, max))
    }
}

/// Pricing engine for inference services
pub struct PricingEngine {
    /// Market data by model ID
    market_data: Arc<RwLock<dashmap::DashMap<String, MarketData>>>,
    /// Default currency for pricing
    default_currency: AssetId,
}

impl PricingEngine {
    /// Creates a new pricing engine
    pub fn new() -> Self {
        Self {
            market_data: Arc::new(RwLock::new(dashmap::DashMap::new())),
            default_currency: AssetId::tnzo(),
        }
    }

    /// Creates a new pricing engine with custom currency
    pub fn with_currency(currency: AssetId) -> Self {
        Self {
            market_data: Arc::new(RwLock::new(dashmap::DashMap::new())),
            default_currency: currency,
        }
    }

    /// Calculates the cost for an inference request
    ///
    /// # Arguments
    ///
    /// * `pricing` - The pricing configuration
    /// * `metadata` - Inference metadata containing token counts
    ///
    /// # Returns
    ///
    /// The calculated cost in smallest currency unit
    pub fn calculate_cost(
        &self,
        pricing: &PricingConfig,
        metadata: &InferenceMetadata,
    ) -> Result<u64> {
        let cost = match pricing.pricing_model {
            PricingModel::PerToken => {
                let input_cost = pricing.price_per_input_token * metadata.input_tokens as u64;
                let output_cost = pricing.price_per_output_token * metadata.output_tokens as u64;
                input_cost + output_cost
            }
            PricingModel::PerRequest => pricing.minimum_price,
            PricingModel::PerComputeTime => {
                // Price per millisecond of compute time
                // Using minimum_price as the per-ms rate
                let ms_rate = pricing.minimum_price;
                ms_rate * metadata.latency_ms
            }
            PricingModel::Dynamic => {
                // Use market average if available, otherwise use configured price
                
                pricing.price_per_input_token * metadata.input_tokens as u64
                    + pricing.price_per_output_token * metadata.output_tokens as u64
            }
        };

        // Ensure minimum price is met
        Ok(cost.max(pricing.minimum_price))
    }

    /// Estimates the cost for an inference request
    ///
    /// # Arguments
    ///
    /// * `pricing` - The pricing configuration
    /// * `estimated_input_tokens` - Estimated number of input tokens
    /// * `estimated_output_tokens` - Estimated number of output tokens
    ///
    /// # Returns
    ///
    /// The estimated cost in smallest currency unit
    pub fn estimate_cost(
        &self,
        pricing: &PricingConfig,
        estimated_input_tokens: u32,
        estimated_output_tokens: u32,
    ) -> Result<u64> {
        let metadata = InferenceMetadata {
            input_tokens: estimated_input_tokens,
            output_tokens: estimated_output_tokens,
            latency_ms: 1000, // Assume 1 second for estimation
            model_version: None,
            finish_reason: None,
        };

        self.calculate_cost(pricing, &metadata)
    }

    /// Validates that a price is acceptable
    ///
    /// # Arguments
    ///
    /// * `price` - The price to validate
    /// * `max_price` - Maximum acceptable price
    ///
    /// # Errors
    ///
    /// Returns `ModelError::PricingError` if price exceeds maximum.
    pub fn validate_price(&self, price: u64, max_price: u64) -> Result<()> {
        if price > max_price {
            Err(ModelError::PricingError(format!(
                "Price {} exceeds maximum {}",
                price, max_price
            )))
        } else {
            Ok(())
        }
    }

    /// Updates market price history with a new transaction
    pub fn update_market_price(&self, model_id: String, price: u64) {
        let data_point = PriceDataPoint {
            price,
            timestamp: Timestamp::now(),
            model_id: model_id.clone(),
        };

        let market_data = self.market_data.read();
        market_data
            .entry(model_id)
            .or_insert_with(|| MarketData::new(1000, 100))
            .add_price(data_point);
    }

    /// Gets price estimates from multiple providers
    pub fn estimate_from_providers(
        &self,
        pricing_configs: Vec<PricingConfig>,
        estimated_input_tokens: u32,
        estimated_output_tokens: u32,
    ) -> Result<PriceEstimate> {
        if pricing_configs.is_empty() {
            return Err(ModelError::PricingError(
                "No pricing configurations provided".to_string(),
            ));
        }

        let mut prices = Vec::new();
        for config in &pricing_configs {
            let price = self.estimate_cost(config, estimated_input_tokens, estimated_output_tokens)?;
            prices.push(price);
        }

        let min_price = *prices.iter().min().unwrap();
        let max_price = *prices.iter().max().unwrap();
        let estimated_price = prices.iter().sum::<u64>() / prices.len() as u64;

        Ok(PriceEstimate::new(
            min_price,
            max_price,
            estimated_price,
            self.default_currency.clone(),
            pricing_configs.len(),
        ))
    }

    /// Gets the moving average price for a model
    pub fn get_market_average(&self, model_id: &str) -> Option<u64> {
        let market_data = self.market_data.read();
        market_data
            .get(model_id)
            .and_then(|data| data.calculate_moving_average())
    }

    /// Gets the price range for a model from market data
    pub fn get_market_price_range(&self, model_id: &str) -> Option<(u64, u64)> {
        let market_data = self.market_data.read();
        market_data
            .get(model_id)
            .and_then(|data| data.get_price_range())
    }

    /// Calculates dynamic price based on demand/supply
    pub fn calculate_dynamic_price(
        &self,
        base_pricing: &PricingConfig,
        model_id: &str,
        demand_multiplier: f64,
    ) -> u64 {
        // Get market average if available
        let base_price = self
            .get_market_average(model_id)
            .unwrap_or(base_pricing.minimum_price);

        // Apply demand multiplier (e.g., 1.5 = 50% price increase)
        let dynamic_price = (base_price as f64 * demand_multiplier) as u64;

        // Ensure minimum price
        dynamic_price.max(base_pricing.minimum_price)
    }

    /// Calculates price for a specific model and provider based on dynamic factors
    ///
    /// # Arguments
    ///
    /// * `model_id` - The model identifier
    /// * `provider_id` - The provider identifier
    /// * `base_pricing` - Base pricing configuration
    /// * `model_complexity` - Model complexity metric (e.g., parameter count in billions)
    /// * `provider_load` - Provider utilization percentage (0.0 - 1.0)
    ///
    /// # Returns
    ///
    /// The calculated dynamic price in smallest currency unit (TNZO)
    pub fn calculate_price(
        &self,
        model_id: &str,
        _provider_id: &str,
        base_pricing: &PricingConfig,
        model_complexity: f64,
        provider_load: f64,
    ) -> u64 {
        // 1. Start with base price from configuration
        let mut price = base_pricing.minimum_price as f64;

        // 2. Apply model complexity multiplier
        // Complexity factor: 1.0 + (complexity / 100.0)
        // Example: 7B model (7.0) -> 1.07x, 70B model (70.0) -> 1.70x
        let complexity_multiplier = 1.0 + (model_complexity / 100.0);
        price *= complexity_multiplier;

        // 3. Apply provider load multiplier
        // Load factor increases price when provider is busy
        // load=0.0 -> 1.0x, load=0.5 -> 1.25x, load=0.8 -> 1.6x, load=1.0 -> 2.0x
        let load_multiplier = 1.0 + provider_load;
        price *= load_multiplier;

        // 4. Apply historical price adjustments using moving average
        if let Some(market_avg) = self.get_market_average(model_id) {
            // Blend market average with calculated price (70% market, 30% calculated)
            price = (market_avg as f64 * 0.7) + (price * 0.3);
        }

        // 5. Apply market volatility bounds to prevent extreme swings
        // Cap price increase to 3x base price
        let max_price = base_pricing.minimum_price as f64 * 3.0;
        price = price.min(max_price);

        // Ensure minimum price is respected
        let final_price = price as u64;
        final_price.max(base_pricing.minimum_price)
    }

    /// Estimates price based on model size (parameter count)
    ///
    /// # Arguments
    ///
    /// * `parameter_count` - Number of model parameters (in billions)
    /// * `base_price_per_billion` - Base price per billion parameters
    ///
    /// # Returns
    ///
    /// Estimated price in TNZO
    pub fn estimate_price_by_model_size(
        &self,
        parameter_count: f64,
        base_price_per_billion: u64,
    ) -> u64 {
        // Linear scaling with parameter count
        // e.g., 7B model @ 100 TNZO/B = 700 TNZO
        // e.g., 70B model @ 100 TNZO/B = 7000 TNZO
        let estimated_price = (parameter_count * base_price_per_billion as f64) as u64;

        // Apply diminishing returns for very large models
        // This prevents exponential pricing for huge models
        if parameter_count > 100.0 {
            // Apply 20% discount for models over 100B parameters
            (estimated_price as f64 * 0.8) as u64
        } else {
            estimated_price
        }
    }

    /// Calculates surge pricing based on network congestion
    ///
    /// # Arguments
    ///
    /// * `base_price` - Base price for the service
    /// * `active_requests` - Current number of active inference requests
    /// * `total_capacity` - Total network capacity for inference requests
    ///
    /// # Returns
    ///
    /// Adjusted price with surge multiplier applied
    pub fn calculate_surge_price(
        &self,
        base_price: u64,
        active_requests: u64,
        total_capacity: u64,
    ) -> u64 {
        if total_capacity == 0 {
            return base_price;
        }

        // Calculate utilization ratio
        let utilization = active_requests as f64 / total_capacity as f64;

        // Apply surge multiplier based on utilization
        // 0-50% utilization: 1.0x (no surge)
        // 50-75% utilization: 1.0x - 1.5x
        // 75-90% utilization: 1.5x - 2.0x
        // 90-100% utilization: 2.0x - 3.0x
        let surge_multiplier = if utilization <= 0.5 {
            1.0
        } else if utilization <= 0.75 {
            1.0 + (utilization - 0.5) * 2.0 // Linear from 1.0 to 1.5
        } else if utilization <= 0.9 {
            1.5 + (utilization - 0.75) * 3.33 // Linear from 1.5 to 2.0
        } else {
            2.0 + (utilization - 0.9) * 10.0 // Linear from 2.0 to 3.0
        };

        (base_price as f64 * surge_multiplier) as u64
    }

    /// Gets pricing recommendation for a provider based on current market conditions
    ///
    /// # Arguments
    ///
    /// * `model_id` - The model identifier
    /// * `current_utilization` - Provider's current utilization (0.0 - 1.0)
    ///
    /// # Returns
    ///
    /// Recommended price per token in TNZO
    pub fn get_pricing_recommendation(
        &self,
        model_id: &str,
        current_utilization: f64,
    ) -> Option<u64> {
        // Get market average as baseline
        let market_avg = self.get_market_average(model_id)?;

        // Adjust based on utilization
        // Low utilization (< 30%): reduce price to attract customers
        // Medium utilization (30-70%): keep market price
        // High utilization (> 70%): increase price due to scarcity
        let recommended_price = if current_utilization < 0.3 {
            // Offer 10% discount to increase demand
            (market_avg as f64 * 0.9) as u64
        } else if current_utilization > 0.7 {
            // Add 20% premium due to high demand
            (market_avg as f64 * 1.2) as u64
        } else {
            // Keep market price
            market_avg
        };

        Some(recommended_price)
    }
}

impl Default for PricingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::model::{PricingConfig, PricingModel};

    #[test]
    fn test_calculate_cost_per_token() {
        let engine = PricingEngine::new();
        let pricing = PricingConfig {
            price_per_input_token: 10,
            price_per_output_token: 20,
            minimum_price: 100,
            pricing_model: PricingModel::PerToken,
        };

        let metadata = InferenceMetadata {
            input_tokens: 100,
            output_tokens: 50,
            latency_ms: 1000,
            model_version: None,
            finish_reason: None,
        };

        let cost = engine.calculate_cost(&pricing, &metadata).unwrap();
        assert_eq!(cost, 2000); // 100*10 + 50*20 = 2000
    }

    #[test]
    fn test_calculate_cost_minimum() {
        let engine = PricingEngine::new();
        let pricing = PricingConfig {
            price_per_input_token: 1,
            price_per_output_token: 1,
            minimum_price: 1000,
            pricing_model: PricingModel::PerToken,
        };

        let metadata = InferenceMetadata {
            input_tokens: 10,
            output_tokens: 10,
            latency_ms: 1000,
            model_version: None,
            finish_reason: None,
        };

        let cost = engine.calculate_cost(&pricing, &metadata).unwrap();
        assert_eq!(cost, 1000); // Should use minimum price
    }

    #[test]
    fn test_estimate_from_providers() {
        let engine = PricingEngine::new();
        let pricing1 = PricingConfig {
            price_per_input_token: 10,
            price_per_output_token: 20,
            minimum_price: 100,
            pricing_model: PricingModel::PerToken,
        };

        let pricing2 = PricingConfig {
            price_per_input_token: 15,
            price_per_output_token: 25,
            minimum_price: 100,
            pricing_model: PricingModel::PerToken,
        };

        let estimate = engine
            .estimate_from_providers(vec![pricing1, pricing2], 100, 50)
            .unwrap();

        assert!(estimate.min_price <= estimate.max_price);
        assert_eq!(estimate.provider_count, 2);
    }

    #[test]
    fn test_market_price_tracking() {
        let engine = PricingEngine::new();

        engine.update_market_price("model-1".to_string(), 1000);
        engine.update_market_price("model-1".to_string(), 1200);
        engine.update_market_price("model-1".to_string(), 1100);

        let avg = engine.get_market_average("model-1");
        assert!(avg.is_some());
        assert_eq!(avg.unwrap(), 1100); // (1000 + 1200 + 1100) / 3
    }

    #[test]
    fn test_validate_price() {
        let engine = PricingEngine::new();

        assert!(engine.validate_price(100, 200).is_ok());
        assert!(engine.validate_price(300, 200).is_err());
    }

    #[test]
    fn test_dynamic_pricing_with_complexity() {
        let engine = PricingEngine::new();
        let base_pricing = PricingConfig {
            price_per_input_token: 10,
            price_per_output_token: 20,
            minimum_price: 1000,
            pricing_model: PricingModel::PerToken,
        };

        // Test with small model (7B parameters)
        let price_7b = engine.calculate_price("model-1", "provider-1", &base_pricing, 7.0, 0.5);

        // Test with large model (70B parameters)
        let price_70b = engine.calculate_price("model-1", "provider-1", &base_pricing, 70.0, 0.5);

        // Larger model should cost more
        assert!(price_70b > price_7b);

        // Both should be at least minimum price
        assert!(price_7b >= base_pricing.minimum_price);
        assert!(price_70b >= base_pricing.minimum_price);
    }

    #[test]
    fn test_dynamic_pricing_with_load() {
        let engine = PricingEngine::new();
        let base_pricing = PricingConfig {
            price_per_input_token: 10,
            price_per_output_token: 20,
            minimum_price: 1000,
            pricing_model: PricingModel::PerToken,
        };

        // Low load
        let price_low_load = engine.calculate_price("model-1", "provider-1", &base_pricing, 10.0, 0.2);

        // High load
        let price_high_load = engine.calculate_price("model-1", "provider-1", &base_pricing, 10.0, 0.9);

        // Higher load should result in higher price
        assert!(price_high_load > price_low_load);
    }

    #[test]
    fn test_estimate_price_by_model_size() {
        let engine = PricingEngine::new();

        let price_7b = engine.estimate_price_by_model_size(7.0, 100);
        assert_eq!(price_7b, 700);

        let price_70b = engine.estimate_price_by_model_size(70.0, 100);
        assert_eq!(price_70b, 7000);

        // Very large model should have diminishing returns
        let price_200b = engine.estimate_price_by_model_size(200.0, 100);
        assert_eq!(price_200b, 16000); // 200 * 100 * 0.8 = 16000
    }

    #[test]
    fn test_surge_pricing() {
        let engine = PricingEngine::new();
        let base_price = 1000;

        // Low utilization - no surge
        let price_low = engine.calculate_surge_price(base_price, 25, 100);
        assert_eq!(price_low, base_price);

        // Medium utilization - moderate surge
        let price_med = engine.calculate_surge_price(base_price, 60, 100);
        assert!(price_med > base_price);
        assert!(price_med < base_price * 2);

        // High utilization - significant surge
        let price_high = engine.calculate_surge_price(base_price, 95, 100);
        assert!(price_high > price_med);
        assert!(price_high <= base_price * 3);
    }

    #[test]
    fn test_pricing_recommendation() {
        let engine = PricingEngine::new();

        // Add market data
        engine.update_market_price("model-1".to_string(), 1000);
        engine.update_market_price("model-1".to_string(), 1200);
        engine.update_market_price("model-1".to_string(), 1100);

        let market_avg = engine.get_market_average("model-1").unwrap();
        assert_eq!(market_avg, 1100);

        // Low utilization - should recommend discount
        let low_util_price = engine.get_pricing_recommendation("model-1", 0.2).unwrap();
        assert!(low_util_price < market_avg);

        // High utilization - should recommend premium
        let high_util_price = engine.get_pricing_recommendation("model-1", 0.8).unwrap();
        assert!(high_util_price > market_avg);

        // Medium utilization - should recommend market price
        let med_util_price = engine.get_pricing_recommendation("model-1", 0.5).unwrap();
        assert_eq!(med_util_price, market_avg);
    }
}
