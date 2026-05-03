//! TEE provider registry for Tenzro Network.
//!
//! This module maintains a registry of all TEE providers participating in the
//! Tenzro Network, tracking their attestations, availability, and capacity.

use chrono::Duration;
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

use tenzro_types::tee::{TeeProviderInfo, TeeProviderStatus, TeeVendor, TeeCapacity, AttestationReport, TeeProviderPricing, AttestationResult};
use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;

/// Registry for tracking TEE providers on the Tenzro Network.
///
/// The registry maintains:
/// - Provider information and attestations
/// - Health status and heartbeats
/// - Capacity metrics
/// - Attestation verification state
#[derive(Debug, Clone)]
pub struct TeeRegistry {
    /// Map of provider ID to provider info
    providers: Arc<DashMap<Uuid, TeeProviderInfo>>,
    /// Heartbeat timeout duration
    heartbeat_timeout: Duration,
}

impl TeeRegistry {
    /// Creates a new TEE provider registry.
    ///
    /// # Arguments
    /// - `heartbeat_timeout_secs`: Seconds before a provider is considered offline
    pub fn new(heartbeat_timeout_secs: i64) -> Self {
        Self {
            providers: Arc::new(DashMap::new()),
            heartbeat_timeout: Duration::seconds(heartbeat_timeout_secs),
        }
    }

    /// Registers a new TEE provider.
    ///
    /// # Arguments
    /// - `address`: Network address of the provider
    /// - `public_key`: Provider's public key
    /// - `attestation`: Initial attestation report
    /// - `capacity`: Provider's capacity metrics
    ///
    /// # Returns
    /// The provider ID
    pub fn register_provider(
        &self,
        address: String,
        public_key: Vec<u8>,
        attestation: AttestationReport,
        capacity: TeeCapacity,
    ) -> Result<Uuid> {
        let provider_id = Uuid::new_v4();
        let now = tenzro_types::Timestamp::now();

        let info = TeeProviderInfo {
            id: provider_id,
            vendor: attestation.vendor,
            address,
            public_key,
            attestation,
            registered_at: now,
            last_heartbeat: now,
            capacity,
            status: TeeProviderStatus::Active,
            attestation_result: None,
            pricing: TeeProviderPricing::default(),
            reputation: 0,
            total_jobs_completed: 0,
            last_attestation_update: now,
        };

        let vendor = info.vendor;
        self.providers.insert(provider_id, info);

        tracing::info!(
            "Registered TEE provider: {} (vendor: {:?})",
            provider_id,
            vendor
        );

        Ok(provider_id)
    }

    /// Unregisters a TEE provider.
    ///
    /// # Arguments
    /// - `provider_id`: The provider to unregister
    pub fn unregister_provider(&self, provider_id: &Uuid) -> Result<()> {
        self.providers
            .remove(provider_id)
            .ok_or_else(|| TeeError::ProviderNotFound(provider_id.to_string()))?;

        tracing::info!("Unregistered TEE provider: {}", provider_id);
        Ok(())
    }

    /// Updates a provider's attestation.
    ///
    /// # Arguments
    /// - `provider_id`: The provider to update
    /// - `attestation`: New attestation report
    pub fn update_attestation(
        &self,
        provider_id: &Uuid,
        attestation: AttestationReport,
    ) -> Result<()> {
        let mut provider = self
            .providers
            .get_mut(provider_id)
            .ok_or_else(|| TeeError::ProviderNotFound(provider_id.to_string()))?;

        provider.attestation = attestation;
        provider.last_heartbeat = tenzro_types::Timestamp::now();

        tracing::debug!("Updated attestation for provider: {}", provider_id);
        Ok(())
    }

    /// Records a heartbeat from a provider.
    ///
    /// # Arguments
    /// - `provider_id`: The provider sending the heartbeat
    /// - `capacity`: Updated capacity metrics
    pub fn heartbeat(&self, provider_id: &Uuid, capacity: TeeCapacity) -> Result<()> {
        let mut provider = self
            .providers
            .get_mut(provider_id)
            .ok_or_else(|| TeeError::ProviderNotFound(provider_id.to_string()))?;

        provider.last_heartbeat = tenzro_types::Timestamp::now();
        provider.capacity = capacity;

        // If provider was offline, mark it active
        if provider.status == TeeProviderStatus::Offline {
            provider.status = TeeProviderStatus::Active;
            tracing::info!("Provider {} is back online", provider_id);
        }

        Ok(())
    }

    /// Updates a provider's status.
    ///
    /// # Arguments
    /// - `provider_id`: The provider to update
    /// - `status`: New status
    pub fn update_status(&self, provider_id: &Uuid, status: TeeProviderStatus) -> Result<()> {
        let mut provider = self
            .providers
            .get_mut(provider_id)
            .ok_or_else(|| TeeError::ProviderNotFound(provider_id.to_string()))?;

        provider.status = status;

        tracing::info!("Provider {} status changed to: {:?}", provider_id, status);
        Ok(())
    }

    /// Gets information about a provider.
    pub fn get_provider(&self, provider_id: &Uuid) -> Option<TeeProviderInfo> {
        self.providers.get(provider_id).map(|p| p.clone())
    }

    /// Gets all registered providers.
    pub fn get_all_providers(&self) -> Vec<TeeProviderInfo> {
        self.providers.iter().map(|entry| entry.value().clone()).collect()
    }

    /// Gets all providers of a specific vendor.
    pub fn get_providers_by_vendor(&self, vendor: TeeVendor) -> Vec<TeeProviderInfo> {
        self.providers
            .iter()
            .filter(|entry| entry.value().vendor == vendor)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Gets all active providers (accepting requests).
    pub fn get_active_providers(&self) -> Vec<TeeProviderInfo> {
        self.providers
            .iter()
            .filter(|entry| entry.value().status == TeeProviderStatus::Active)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Gets providers with available capacity.
    ///
    /// # Arguments
    /// - `min_available_operations`: Minimum available operation slots required
    pub fn get_available_providers(&self, min_available_operations: u32) -> Vec<TeeProviderInfo> {
        self.providers
            .iter()
            .filter(|entry| {
                let info = entry.value();
                info.status == TeeProviderStatus::Active
                    && info.capacity.max_operations - info.capacity.current_operations
                        >= min_available_operations
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Checks and updates status of providers based on heartbeat timeouts.
    ///
    /// Providers that haven't sent a heartbeat within the timeout period
    /// are marked as offline.
    ///
    /// # Returns
    /// Number of providers marked offline
    pub fn check_heartbeats(&self) -> usize {
        let now = tenzro_types::Timestamp::now();
        let timeout_millis = self.heartbeat_timeout.num_milliseconds();
        let timeout_threshold = tenzro_types::Timestamp::new(now.as_millis() - timeout_millis);
        let mut offline_count = 0;

        for mut entry in self.providers.iter_mut() {
            let provider = entry.value_mut();
            if provider.last_heartbeat < timeout_threshold
                && provider.status == TeeProviderStatus::Active
            {
                provider.status = TeeProviderStatus::Offline;
                offline_count += 1;
                tracing::warn!("Provider {} marked offline (no heartbeat)", provider.id);
            }
        }

        offline_count
    }

    /// Verifies a provider's attestation using the given verifier.
    ///
    /// If verification fails, marks the provider as untrusted.
    pub async fn verify_provider_attestation(
        &self,
        provider_id: &Uuid,
        verifier: &dyn TeeProvider,
    ) -> Result<AttestationResult> {
        let provider = self
            .providers
            .get(provider_id)
            .ok_or_else(|| TeeError::ProviderNotFound(provider_id.to_string()))?;

        let attestation = provider.attestation.clone();
        drop(provider); // Release the lock

        let result = verifier.verify_attestation(&attestation).await?;

        if !result.valid {
            self.update_status(provider_id, TeeProviderStatus::Untrusted)?;
            tracing::warn!("Provider {} failed attestation verification", provider_id);
        }

        Ok(result)
    }

    /// Returns statistics about the registry.
    pub fn stats(&self) -> RegistryStats {
        let mut stats = RegistryStats {
            total_providers: 0,
            active_providers: 0,
            draining_providers: 0,
            offline_providers: 0,
            untrusted_providers: 0,
            providers_by_vendor: std::collections::HashMap::new(),
        };

        for entry in self.providers.iter() {
            let provider = entry.value();
            stats.total_providers += 1;

            match provider.status {
                TeeProviderStatus::Active => stats.active_providers += 1,
                TeeProviderStatus::Draining => stats.draining_providers += 1,
                TeeProviderStatus::Offline => stats.offline_providers += 1,
                TeeProviderStatus::Untrusted => stats.untrusted_providers += 1,
                TeeProviderStatus::Pending
                | TeeProviderStatus::Inactive
                | TeeProviderStatus::Suspended
                | TeeProviderStatus::AttestationExpired => {
                    // These statuses are not tracked separately in stats
                }
            }

            *stats.providers_by_vendor.entry(provider.vendor).or_insert(0) += 1;
        }

        stats
    }
}

impl Default for TeeRegistry {
    fn default() -> Self {
        Self::new(300) // 5 minute default timeout
    }
}

/// Statistics about the TEE provider registry.
#[derive(Debug, Clone)]
pub struct RegistryStats {
    pub total_providers: usize,
    pub active_providers: usize,
    pub draining_providers: usize,
    pub offline_providers: usize,
    pub untrusted_providers: usize,
    pub providers_by_vendor: std::collections::HashMap<TeeVendor, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_attestation(vendor: TeeVendor) -> AttestationReport {
        AttestationReport {
            id: Uuid::new_v4(),
            vendor,
            user_data: vec![],
            attestation_data: vec![],
            certificates: vec![],
            timestamp: tenzro_types::Timestamp::now(),
            metadata: std::collections::HashMap::new(),
            quote: vec![0x01; 32],
            measurement: vec![0x02; 32],
            signature: vec![0x03; 64],
            vendor_data: vec![],
        }
    }

    fn create_test_capacity() -> TeeCapacity {
        TeeCapacity {
            max_concurrent_jobs: 10,
            active_jobs: 2,
            max_operations: 100,
            current_operations: 10,
            total_memory: 2 * 1024 * 1024 * 1024,
            available_memory: 1024 * 1024 * 1024,
            total_cpu_cores: 8,
            available_cpu_cores: 6,
            supported_vendors: vec![TeeVendor::IntelTdx],
        }
    }

    #[test]
    fn test_register_provider() {
        let registry = TeeRegistry::default();

        let id = registry
            .register_provider(
                "127.0.0.1:8080".to_string(),
                vec![0x01; 32],
                create_test_attestation(TeeVendor::IntelTdx),
                create_test_capacity(),
            )
            .unwrap();

        assert!(registry.get_provider(&id).is_some());
    }

    #[test]
    fn test_unregister_provider() {
        let registry = TeeRegistry::default();

        let id = registry
            .register_provider(
                "127.0.0.1:8080".to_string(),
                vec![0x01; 32],
                create_test_attestation(TeeVendor::IntelTdx),
                create_test_capacity(),
            )
            .unwrap();

        registry.unregister_provider(&id).unwrap();
        assert!(registry.get_provider(&id).is_none());
    }

    #[test]
    fn test_heartbeat() {
        let registry = TeeRegistry::default();

        let id = registry
            .register_provider(
                "127.0.0.1:8080".to_string(),
                vec![0x01; 32],
                create_test_attestation(TeeVendor::IntelTdx),
                create_test_capacity(),
            )
            .unwrap();

        let new_capacity = TeeCapacity {
            max_concurrent_jobs: 10,
            active_jobs: 5,
            max_operations: 100,
            current_operations: 50,
            total_memory: 2 * 1024 * 1024 * 1024,
            available_memory: 512 * 1024 * 1024,
            total_cpu_cores: 8,
            available_cpu_cores: 3,
            supported_vendors: vec![TeeVendor::IntelTdx],
        };

        registry.heartbeat(&id, new_capacity).unwrap();

        let provider = registry.get_provider(&id).unwrap();
        assert_eq!(provider.capacity.current_operations, 50);
    }

    #[test]
    fn test_get_active_providers() {
        let registry = TeeRegistry::default();

        let id1 = registry
            .register_provider(
                "127.0.0.1:8080".to_string(),
                vec![0x01; 32],
                create_test_attestation(TeeVendor::IntelTdx),
                create_test_capacity(),
            )
            .unwrap();

        let id2 = registry
            .register_provider(
                "127.0.0.1:8081".to_string(),
                vec![0x02; 32],
                create_test_attestation(TeeVendor::AmdSevSnp),
                create_test_capacity(),
            )
            .unwrap();

        registry.update_status(&id2, TeeProviderStatus::Offline).unwrap();

        let active = registry.get_active_providers();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, id1);
    }

    #[test]
    fn test_stats() {
        let registry = TeeRegistry::default();

        registry
            .register_provider(
                "127.0.0.1:8080".to_string(),
                vec![0x01; 32],
                create_test_attestation(TeeVendor::IntelTdx),
                create_test_capacity(),
            )
            .unwrap();

        registry
            .register_provider(
                "127.0.0.1:8081".to_string(),
                vec![0x02; 32],
                create_test_attestation(TeeVendor::AmdSevSnp),
                create_test_capacity(),
            )
            .unwrap();

        let stats = registry.stats();
        assert_eq!(stats.total_providers, 2);
        assert_eq!(stats.active_providers, 2);
    }
}
