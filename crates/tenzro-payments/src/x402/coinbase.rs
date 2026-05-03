//! Coinbase CDP (Coinbase Developer Platform) facilitator API client for x402
//!
//! The x402 protocol uses an off-chain facilitator to verify and settle payments.
//! Coinbase provides a CDP facilitator service with two key endpoints:
//!
//! - `POST /verify` — Verify a payment payload before releasing the resource
//! - `POST /settle` — Execute on-chain settlement after resource delivery
//!
//! # x402 Payment Flow
//!
//! ```text
//! Client                    Resource Server              CDP Facilitator
//!   |-- GET /resource ------->|                                |
//!   |<-- 402 + requirements --|                                |
//!   |                         |                                |
//!   | (sign EIP-3009 or       |                                |
//!   |  Permit2 authorization) |                                |
//!   |                         |                                |
//!   |-- GET + X-PAYMENT ----->|                                |
//!   |                         |-- POST /verify (payload) ----->|
//!   |                         |<-- { valid: true } ------------|
//!   |                         |                                |
//!   |<-- 200 (resource) ------|                                |
//!   |                         |-- POST /settle (payload) ----->|
//!   |                         |<-- { tx_hash: "0x..." } -------|
//! ```
//!
//! # Authorization Schemes
//!
//! - **EIP-3009**: `transferWithAuthorization()` — gasless USDC transfers via meta-tx
//! - **Permit2**: Uniswap's universal token approval + transfer in one signature
//! - **EIP-2612**: Standard permit for ERC-20 tokens
//!
//! # Supported Networks (CAIP-2)
//!
//! - `eip155:8453` — Base Mainnet
//! - `eip155:84532` — Base Sepolia (testnet)
//! - `eip155:1` — Ethereum Mainnet
//! - `eip155:11155111` — Ethereum Sepolia
//!
//! # Usage
//!
//! ```no_run
//! use tenzro_payments::x402::coinbase::{CdpFacilitatorClient, VerifyRequest, SettleRequest};
//!
//! # async fn example() -> tenzro_payments::Result<()> {
//! let client = CdpFacilitatorClient::new();
//!
//! // Verify a payment before releasing the resource
//! let verified = client.verify(&VerifyRequest {
//!     payload: "base64-encoded-payment-payload".to_string(),
//!     payment_requirements: "base64-encoded-requirements".to_string(),
//! }).await?;
//!
//! if verified.is_valid {
//!     // Release the resource, then settle
//!     let settled = client.settle(&SettleRequest {
//!         payload: "base64-encoded-payment-payload".to_string(),
//!         payment_requirements: "base64-encoded-requirements".to_string(),
//!     }).await?;
//!     println!("Settlement tx: {}", settled.tx_hash);
//! }
//! # Ok(())
//! # }
//! ```

use crate::error::{PaymentError, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Default CDP facilitator base URL
const CDP_FACILITATOR_BASE: &str = "https://x402.org/facilitator";

/// CAIP-2 chain identifiers supported by x402
pub mod chains {
    /// Base Mainnet
    pub const BASE_MAINNET: &str = "eip155:8453";
    /// Base Sepolia (testnet)
    pub const BASE_SEPOLIA: &str = "eip155:84532";
    /// Ethereum Mainnet
    pub const ETHEREUM_MAINNET: &str = "eip155:1";
    /// Ethereum Sepolia (testnet)
    pub const ETHEREUM_SEPOLIA: &str = "eip155:11155111";
    /// Tenzro L1
    pub const TENZRO: &str = "eip155:1337";
    /// Tempo Network
    pub const TEMPO_TESTNET: &str = "eip155:325000";
}

/// Authorization scheme used for the payment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationScheme {
    /// EIP-3009 transferWithAuthorization (USDC-native gasless transfers)
    Eip3009,
    /// Uniswap Permit2 (universal token approvals)
    Permit2,
    /// EIP-2612 permit (standard ERC-20 permit)
    Eip2612,
    /// Direct transfer (pre-signed transaction)
    Exact,
}

impl AuthorizationScheme {
    /// Returns the scheme identifier string used in x402 payment requirements
    pub fn as_str(&self) -> &str {
        match self {
            Self::Eip3009 => "eip3009",
            Self::Permit2 => "permit2",
            Self::Eip2612 => "eip2612",
            Self::Exact => "exact",
        }
    }

    /// Parses a scheme string from x402 payment requirements
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "eip3009" | "eip-3009" => Self::Eip3009,
            "permit2" => Self::Permit2,
            "eip2612" | "eip-2612" => Self::Eip2612,
            "exact" | "direct" => Self::Exact,
            _ => Self::Exact,
        }
    }
}

/// Request to verify a payment payload via CDP facilitator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    /// Base64-encoded payment payload (from X-PAYMENT header)
    pub payload: String,
    /// Base64-encoded payment requirements (original 402 response)
    pub payment_requirements: String,
}

/// Response from CDP facilitator verify endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    /// Whether the payment payload is valid
    pub is_valid: bool,
    /// Error message if not valid
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Invalidation reason details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalidation_reason: Option<String>,
}

/// Request to settle a payment via CDP facilitator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleRequest {
    /// Base64-encoded payment payload (same as verify)
    pub payload: String,
    /// Base64-encoded payment requirements (same as verify)
    pub payment_requirements: String,
}

/// Response from CDP facilitator settle endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponse {
    /// Whether settlement was successful
    pub success: bool,
    /// On-chain transaction hash (e.g., "0xabc...")
    #[serde(default)]
    pub tx_hash: String,
    /// Network the settlement was executed on (CAIP-2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Error message if settlement failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// CDP Facilitator API client for x402 payment verification and settlement
#[derive(Debug)]
pub struct CdpFacilitatorClient {
    /// HTTP client
    http_client: reqwest::Client,
    /// Facilitator base URL
    base_url: String,
    /// Optional API key for authenticated requests
    api_key: Option<String>,
}

impl CdpFacilitatorClient {
    /// Creates a new CDP facilitator client with the default URL
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::new(),
            base_url: CDP_FACILITATOR_BASE.to_string(),
            api_key: None,
        }
    }

    /// Creates a new client with a custom facilitator URL
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Sets the CDP API key for authenticated requests
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Verifies a payment payload via `POST /verify`
    ///
    /// This should be called before releasing the protected resource.
    /// The facilitator checks:
    /// 1. The authorization signature is valid (EIP-3009, Permit2, etc.)
    /// 2. The amount matches or exceeds the requirement
    /// 3. The authorization hasn't been used (nonce check)
    /// 4. The payer has sufficient token balance
    pub async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse> {
        info!("Verifying x402 payment via CDP facilitator");

        let mut req_builder = self
            .http_client
            .post(format!("{}/verify", self.base_url))
            .json(request);

        if let Some(ref key) = self.api_key {
            req_builder = req_builder.bearer_auth(key);
        }

        let response = req_builder
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("CDP facilitator verify failed: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Failed to read CDP response: {}", e)))?;

        if !status.is_success() {
            return Err(PaymentError::VerificationFailed(format!(
                "CDP facilitator returned {}: {}",
                status,
                body.chars().take(200).collect::<String>()
            )));
        }

        let verify_response: VerifyResponse = serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!("Failed to parse verify response: {}", e))
        })?;

        if verify_response.is_valid {
            debug!("CDP facilitator: payment verified successfully");
        } else {
            warn!(
                "CDP facilitator: payment invalid — {}",
                verify_response
                    .error
                    .as_deref()
                    .or(verify_response.invalidation_reason.as_deref())
                    .unwrap_or("unknown reason")
            );
        }

        Ok(verify_response)
    }

    /// Settles a payment via `POST /settle`
    ///
    /// This should be called after the protected resource has been delivered.
    /// The facilitator executes the on-chain transfer using the pre-signed authorization.
    ///
    /// For EIP-3009: calls `transferWithAuthorization()` on the token contract
    /// For Permit2: calls `permit()` then `transferFrom()` via the Permit2 contract
    pub async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse> {
        info!("Settling x402 payment via CDP facilitator");

        let mut req_builder = self
            .http_client
            .post(format!("{}/settle", self.base_url))
            .json(request);

        if let Some(ref key) = self.api_key {
            req_builder = req_builder.bearer_auth(key);
        }

        let response = req_builder
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("CDP facilitator settle failed: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Failed to read CDP response: {}", e)))?;

        if !status.is_success() {
            return Err(PaymentError::SettlementError(format!(
                "CDP facilitator settlement failed ({}): {}",
                status,
                body.chars().take(200).collect::<String>()
            )));
        }

        let settle_response: SettleResponse = serde_json::from_str(&body).map_err(|e| {
            PaymentError::SerializationError(format!("Failed to parse settle response: {}", e))
        })?;

        if settle_response.success {
            info!(
                "x402 settlement successful: tx={}",
                settle_response.tx_hash
            );
        } else {
            warn!(
                "x402 settlement failed: {}",
                settle_response.error.as_deref().unwrap_or("unknown error")
            );
        }

        Ok(settle_response)
    }

    /// Combined verify-and-settle flow
    ///
    /// 1. Verify the payment payload
    /// 2. If valid, execute settlement
    /// 3. Return the settlement transaction hash
    pub async fn verify_and_settle(
        &self,
        payload: &str,
        payment_requirements: &str,
    ) -> Result<SettleResponse> {
        let verify_req = VerifyRequest {
            payload: payload.to_string(),
            payment_requirements: payment_requirements.to_string(),
        };

        let verify_result = self.verify(&verify_req).await?;

        if !verify_result.is_valid {
            return Err(PaymentError::VerificationFailed(format!(
                "x402 payment verification failed: {}",
                verify_result
                    .error
                    .or(verify_result.invalidation_reason)
                    .unwrap_or_else(|| "unknown reason".to_string())
            )));
        }

        let settle_req = SettleRequest {
            payload: payload.to_string(),
            payment_requirements: payment_requirements.to_string(),
        };

        self.settle(&settle_req).await
    }
}

impl Default for CdpFacilitatorClient {
    fn default() -> Self {
        Self::new()
    }
}

/// EIP-712 typed data domain for x402 payment authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Domain {
    /// Domain name
    pub name: String,
    /// Domain version
    pub version: String,
    /// Chain ID (numeric)
    pub chain_id: u64,
    /// Verifying contract address
    pub verifying_contract: String,
}

/// EIP-3009 TransferWithAuthorization parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferWithAuthorization {
    /// Token holder (from)
    pub from: String,
    /// Recipient (to)
    pub to: String,
    /// Transfer amount (wei string)
    pub value: String,
    /// Valid after timestamp
    pub valid_after: u64,
    /// Valid before timestamp
    pub valid_before: u64,
    /// Unique nonce (bytes32 hex)
    pub nonce: String,
}

impl TransferWithAuthorization {
    /// Returns the EIP-712 type hash for TransferWithAuthorization
    pub fn type_hash() -> &'static str {
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    }

    /// Encodes the parameters as ABI-encoded bytes for the smart contract call
    ///
    /// Function selector: `transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)`
    pub fn encode_calldata(&self, v: u8, r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        // Function selector: keccak256("transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)")
        // = 0xe3ee160e
        let selector: [u8; 4] = [0xe3, 0xee, 0x16, 0x0e];

        let mut calldata = Vec::with_capacity(4 + 9 * 32);
        calldata.extend_from_slice(&selector);

        // from (address, left-padded to 32 bytes)
        calldata.extend_from_slice(&abi_encode_address(&self.from));
        // to (address)
        calldata.extend_from_slice(&abi_encode_address(&self.to));
        // value (uint256)
        calldata.extend_from_slice(&abi_encode_uint256(&self.value));
        // validAfter (uint256)
        calldata.extend_from_slice(&abi_encode_u64(self.valid_after));
        // validBefore (uint256)
        calldata.extend_from_slice(&abi_encode_u64(self.valid_before));
        // nonce (bytes32)
        calldata.extend_from_slice(&abi_encode_bytes32(&self.nonce));
        // v (uint8 as uint256)
        calldata.extend_from_slice(&abi_encode_u8(v));
        // r (bytes32)
        calldata.extend_from_slice(r);
        // s (bytes32)
        calldata.extend_from_slice(s);

        calldata
    }
}

/// Well-known token contract addresses for x402
pub mod tokens {
    /// USDC on Base Mainnet
    pub const USDC_BASE: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    /// USDC on Base Sepolia
    pub const USDC_BASE_SEPOLIA: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
    /// USDC on Ethereum Mainnet
    pub const USDC_ETHEREUM: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    /// USDC on Ethereum Sepolia
    pub const USDC_ETHEREUM_SEPOLIA: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
}

/// ABI-encode an address (left-padded to 32 bytes)
fn abi_encode_address(addr: &str) -> [u8; 32] {
    let clean = addr.strip_prefix("0x").unwrap_or(addr);
    let bytes = hex::decode(clean).unwrap_or_default();
    let mut padded = [0u8; 32];
    let len = bytes.len().min(20);
    padded[32 - len..].copy_from_slice(&bytes[..len]);
    padded
}

/// ABI-encode a uint256 from a decimal string
fn abi_encode_uint256(value: &str) -> [u8; 32] {
    let val: u128 = value.parse().unwrap_or(0);
    let mut padded = [0u8; 32];
    padded[16..].copy_from_slice(&val.to_be_bytes());
    padded
}

/// ABI-encode a u64 as uint256
fn abi_encode_u64(value: u64) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[24..].copy_from_slice(&value.to_be_bytes());
    padded
}

/// ABI-encode a u8 as uint256
fn abi_encode_u8(value: u8) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[31] = value;
    padded
}

/// ABI-encode a bytes32 from hex string
fn abi_encode_bytes32(hex_str: &str) -> [u8; 32] {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(clean).unwrap_or_default();
    let mut padded = [0u8; 32];
    let len = bytes.len().min(32);
    padded[..len].copy_from_slice(&bytes[..len]);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_scheme_roundtrip() {
        let schemes = vec![
            ("eip3009", AuthorizationScheme::Eip3009),
            ("permit2", AuthorizationScheme::Permit2),
            ("eip2612", AuthorizationScheme::Eip2612),
            ("exact", AuthorizationScheme::Exact),
        ];

        for (s, expected) in &schemes {
            let parsed = AuthorizationScheme::from_str(s);
            assert_eq!(&parsed, expected, "Failed for scheme: {}", s);
            assert_eq!(parsed.as_str(), *s);
        }
    }

    #[test]
    fn test_authorization_scheme_case_insensitive() {
        assert_eq!(
            AuthorizationScheme::from_str("EIP3009"),
            AuthorizationScheme::Eip3009
        );
        assert_eq!(
            AuthorizationScheme::from_str("Permit2"),
            AuthorizationScheme::Permit2
        );
    }

    #[test]
    fn test_verify_request_serialization() {
        let req = VerifyRequest {
            payload: "dGVzdA==".to_string(),
            payment_requirements: "cmVxcw==".to_string(),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"payload\""));
        assert!(json.contains("\"paymentRequirements\""));

        let parsed: VerifyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.payload, "dGVzdA==");
    }

    #[test]
    fn test_verify_response_valid() {
        let json = r#"{"isValid": true}"#;
        let resp: VerifyResponse = serde_json::from_str(json).unwrap();
        assert!(resp.is_valid);
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_verify_response_invalid() {
        let json = r#"{"isValid": false, "error": "insufficient_balance", "invalidationReason": "Payer balance too low"}"#;
        let resp: VerifyResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.is_valid);
        assert_eq!(resp.error.unwrap(), "insufficient_balance");
        assert!(resp.invalidation_reason.unwrap().contains("balance"));
    }

    #[test]
    fn test_settle_response_success() {
        let json = r#"{"success": true, "txHash": "0xabc123", "network": "eip155:8453"}"#;
        let resp: SettleResponse = serde_json::from_str(json).unwrap();
        assert!(resp.success);
        assert_eq!(resp.tx_hash, "0xabc123");
        assert_eq!(resp.network.unwrap(), "eip155:8453");
    }

    #[test]
    fn test_settle_response_failure() {
        let json = r#"{"success": false, "txHash": "", "error": "nonce_already_used"}"#;
        let resp: SettleResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.success);
        assert_eq!(resp.error.unwrap(), "nonce_already_used");
    }

    #[test]
    fn test_abi_encode_address() {
        let addr = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let encoded = abi_encode_address(addr);
        // First 12 bytes should be zero (left-padded)
        assert_eq!(&encoded[..12], &[0u8; 12]);
        // Last 20 bytes should be the address
        assert_eq!(encoded[12], 0xA0);
        assert_eq!(encoded[31], 0x48);
    }

    #[test]
    fn test_abi_encode_uint256() {
        let encoded = abi_encode_uint256("1000000");
        // Should be big-endian in the last 16 bytes
        let value = u128::from_be_bytes(encoded[16..].try_into().unwrap());
        assert_eq!(value, 1_000_000);
    }

    #[test]
    fn test_abi_encode_u64() {
        let encoded = abi_encode_u64(1234567890);
        assert_eq!(&encoded[..24], &[0u8; 24]);
        let value = u64::from_be_bytes(encoded[24..].try_into().unwrap());
        assert_eq!(value, 1234567890);
    }

    #[test]
    fn test_abi_encode_u8() {
        let encoded = abi_encode_u8(27);
        assert_eq!(&encoded[..31], &[0u8; 31]);
        assert_eq!(encoded[31], 27);
    }

    #[test]
    fn test_abi_encode_bytes32() {
        let nonce = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let encoded = abi_encode_bytes32(nonce);
        assert_eq!(encoded[0], 0xab);
        assert_eq!(encoded[1], 0xcd);
        assert_eq!(encoded[31], 0x89);
    }

    #[test]
    fn test_transfer_with_authorization_type_hash() {
        let hash = TransferWithAuthorization::type_hash();
        assert!(hash.starts_with("TransferWithAuthorization("));
        assert!(hash.contains("address from"));
        assert!(hash.contains("bytes32 nonce"));
    }

    #[test]
    fn test_transfer_with_authorization_calldata() {
        let auth = TransferWithAuthorization {
            from: "0x1111111111111111111111111111111111111111".to_string(),
            to: "0x2222222222222222222222222222222222222222".to_string(),
            value: "1000000".to_string(),
            valid_after: 0,
            valid_before: u64::MAX,
            nonce: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
        };

        let r = [1u8; 32];
        let s = [2u8; 32];
        let calldata = auth.encode_calldata(27, &r, &s);

        // Function selector (4 bytes) + 9 params * 32 bytes = 292 bytes
        assert_eq!(calldata.len(), 4 + 9 * 32);
        // Check function selector
        assert_eq!(&calldata[..4], &[0xe3, 0xee, 0x16, 0x0e]);
    }

    #[test]
    fn test_well_known_token_addresses() {
        // USDC has 6 decimals and these are the canonical addresses
        assert!(tokens::USDC_BASE.starts_with("0x"));
        assert!(tokens::USDC_ETHEREUM.starts_with("0x"));
        assert_eq!(tokens::USDC_BASE.len(), 42); // 0x + 40 hex chars
        assert_eq!(tokens::USDC_ETHEREUM.len(), 42);
    }

    #[test]
    fn test_chain_constants() {
        assert_eq!(chains::BASE_MAINNET, "eip155:8453");
        assert_eq!(chains::BASE_SEPOLIA, "eip155:84532");
        assert_eq!(chains::ETHEREUM_MAINNET, "eip155:1");
        assert_eq!(chains::TENZRO, "eip155:1337");
    }

    #[test]
    fn test_eip712_domain_serialization() {
        let domain = Eip712Domain {
            name: "USD Coin".to_string(),
            version: "2".to_string(),
            chain_id: 8453,
            verifying_contract: tokens::USDC_BASE.to_string(),
        };

        let json = serde_json::to_string(&domain).unwrap();
        assert!(json.contains("\"name\":\"USD Coin\""));
        assert!(json.contains("\"chainId\":8453"));

        let parsed: Eip712Domain = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, 8453);
    }

    #[test]
    fn test_cdp_client_default() {
        let client = CdpFacilitatorClient::default();
        assert_eq!(client.base_url, CDP_FACILITATOR_BASE);
        assert!(client.api_key.is_none());
    }

    #[test]
    fn test_cdp_client_with_config() {
        let client = CdpFacilitatorClient::new()
            .with_base_url("https://custom.facilitator.com")
            .with_api_key("cdp-api-key-123");
        assert_eq!(client.base_url, "https://custom.facilitator.com");
        assert_eq!(client.api_key.as_deref(), Some("cdp-api-key-123"));
    }
}
