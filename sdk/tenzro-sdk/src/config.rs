//! SDK configuration types
//!
//! This module provides configuration options for the Tenzro SDK client.

use crate::access::AccessCredential;
use crate::error::{SdkError, SdkResult};

/// SDK configuration
///
/// Use the builder pattern to configure the SDK client.
///
/// # Example
///
/// ```no_run
/// use tenzro_sdk::config::SdkConfig;
///
/// let config = SdkConfig::builder()
///     .endpoint("https://node.example")
///     .timeout(10000)
///     .max_retries(5)
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct SdkConfig {
    /// RPC endpoint URL
    pub endpoint: String,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// The access token and DPoP key to sign requests with, if signed in
    pub access: Option<AccessCredential>,
    /// Chain ID
    pub chain_id: u64,
}

impl SdkConfig {
    /// Creates a new configuration builder
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tenzro_sdk::config::SdkConfig;
    ///
    /// let config = SdkConfig::builder()
    ///     .endpoint("https://node.example")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn builder() -> SdkConfigBuilder {
        SdkConfigBuilder::default()
    }

    /// Creates a configuration for the preview network
    ///
    /// Connects to [`PREVIEW_NETWORK`](crate::network::PREVIEW_NETWORK)'s
    /// public RPC endpoint with its chain id. To move between the staked RPC
    /// operators instead of one endpoint, use
    /// [`connect_to_network`](crate::network::connect_to_network).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tenzro_sdk::config::SdkConfig;
    ///
    /// let config = SdkConfig::preview();
    /// ```
    pub fn preview() -> Self {
        let network = crate::network::PREVIEW_NETWORK;
        Self {
            endpoint: network.rpc.to_string(),
            timeout_ms: 30000,
            max_retries: 3,
            access: None,
            chain_id: network.chain_id,
        }
    }

    /// Creates a local development configuration
    ///
    /// Connects to a local Tenzro node at `http://localhost:8545`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tenzro_sdk::config::SdkConfig;
    ///
    /// let config = SdkConfig::local();
    /// ```
    pub fn local() -> Self {
        Self {
            endpoint: "http://localhost:8545".to_string(),
            timeout_ms: 10000,
            max_retries: 1,
            access: None,
            chain_id: 1337,
        }
    }
}

/// Builder for SDK configuration
#[derive(Debug, Default)]
pub struct SdkConfigBuilder {
    endpoint: Option<String>,
    timeout_ms: Option<u64>,
    max_retries: Option<u32>,
    access: Option<AccessCredential>,
    chain_id: Option<u64>,
}

impl SdkConfigBuilder {
    /// Sets the RPC endpoint
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Sets the request timeout in milliseconds
    pub fn timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Sets the maximum number of retry attempts
    pub fn max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = Some(max_retries);
        self
    }

    /// Signs every call with this access token and DPoP key. Unset,
    /// `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` are forwarded when set.
    pub fn access(mut self, credential: AccessCredential) -> Self {
        self.access = Some(credential);
        self
    }

    /// Sets the chain ID. Unset, the preview network's
    /// ([`NETWORK_CHAIN_ID`](crate::network::NETWORK_CHAIN_ID)).
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Builds the SDK configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the endpoint is not set.
    pub fn build(self) -> SdkResult<SdkConfig> {
        let endpoint = self
            .endpoint
            .ok_or_else(|| SdkError::InvalidConfiguration("endpoint is required".to_string()))?;

        Ok(SdkConfig {
            endpoint,
            timeout_ms: self.timeout_ms.unwrap_or(30000),
            max_retries: self.max_retries.unwrap_or(3),
            access: self.access,
            chain_id: self.chain_id.unwrap_or(crate::network::NETWORK_CHAIN_ID),
        })
    }
}
