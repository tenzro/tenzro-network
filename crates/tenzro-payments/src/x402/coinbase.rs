//! Client for an x402 facilitator's HTTP API.
//!
//! A facilitator verifies and settles EVM payment payloads for a resource
//! server: `POST /verify` and `POST /settle`, each with the body
//! `{x402Version, paymentPayload, paymentRequirements}`. `/verify` answers
//! `{isValid, invalidReason?, payer?}`; `/settle` answers the settlement
//! response `{success, errorReason?, payer?, transaction, network}`.

use crate::error::{PaymentError, Result};
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::{X402_WIRE_VERSION, X402PaymentRequirement};
use crate::x402::receipt::X402SettlementResponse;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Body of `POST /verify` and `POST /settle`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FacilitatorRequest {
    /// Protocol version.
    pub x402_version: u32,
    /// The buyer's payload.
    pub payment_payload: X402PaymentPayload,
    /// The requirement the payload must satisfy, as the resource server
    /// offered it.
    pub payment_requirements: X402PaymentRequirement,
}

impl FacilitatorRequest {
    /// A request for `payload` against `requirement`.
    pub fn new(payload: &X402PaymentPayload, requirement: &X402PaymentRequirement) -> Self {
        Self {
            x402_version: X402_WIRE_VERSION,
            payment_payload: payload.clone(),
            payment_requirements: requirement.clone(),
        }
    }
}

/// Body of the `POST /verify` answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    /// Whether the payload is valid.
    pub is_valid: bool,
    /// Why it is not, as an x402 error code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    /// The paying address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

/// A facilitator reached over HTTP.
#[derive(Debug)]
pub struct CdpFacilitatorClient {
    http_client: reqwest::Client,
    base_url: String,
    /// Bearer token for a facilitator that requires one.
    api_key: Option<String>,
}

impl CdpFacilitatorClient {
    /// A client for the facilitator at `base_url`, which the operator chose.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            base_url: base_url.into(),
            api_key: None,
        }
    }

    /// Authenticate with a bearer token.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        request: &FacilitatorRequest,
    ) -> Result<T> {
        let mut req = self
            .http_client
            .post(format!("{}{}", self.base_url, path))
            .json(request);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let response = req
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("facilitator {path}: {e}")))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("facilitator {path}: {e}")))?;
        if !status.is_success() {
            return Err(PaymentError::VerificationFailed(format!(
                "facilitator {path} returned {status}: {}",
                body.chars().take(200).collect::<String>()
            )));
        }
        serde_json::from_str(&body)
            .map_err(|e| PaymentError::SerializationError(format!("facilitator {path}: {e}")))
    }

    /// `POST /verify`.
    pub async fn verify(&self, request: &FacilitatorRequest) -> Result<VerifyResponse> {
        let resp: VerifyResponse = self.post("/verify", request).await?;
        if !resp.is_valid {
            warn!(
                "facilitator refused payload: {}",
                resp.invalid_reason.as_deref().unwrap_or("no reason given")
            );
        }
        Ok(resp)
    }

    /// `POST /settle`.
    pub async fn settle(&self, request: &FacilitatorRequest) -> Result<X402SettlementResponse> {
        let resp: X402SettlementResponse = self.post("/settle", request).await?;
        debug!(
            "facilitator settle: success={} transaction={}",
            resp.success, resp.transaction
        );
        Ok(resp)
    }
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
    fn facilitator_bodies_use_the_protocol_field_names() {
        let req =
            X402PaymentRequirement::new("exact-eip3009", "eip155:8453", "1", "0xto", "0xusdc", 60);
        let payload = X402PaymentPayload::new(req.clone(), serde_json::json!({}));
        let json = serde_json::to_value(FacilitatorRequest::new(&payload, &req)).unwrap();
        assert_eq!(json["x402Version"], 2);
        assert_eq!(json["paymentRequirements"]["payTo"], "0xto");
        assert_eq!(
            json["paymentPayload"]["accepted"]["scheme"],
            "exact-eip3009"
        );

        let resp: VerifyResponse =
            serde_json::from_str(r#"{"isValid":false,"invalidReason":"insufficient_funds"}"#)
                .unwrap();
        assert_eq!(resp.invalid_reason.as_deref(), Some("insufficient_funds"));
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
            nonce: "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
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
    fn test_cdp_client_with_config() {
        let client = CdpFacilitatorClient::new("https://custom.facilitator.com")
            .with_api_key("cdp-api-key-123");
        assert_eq!(client.base_url, "https://custom.facilitator.com");
        assert_eq!(client.api_key.as_deref(), Some("cdp-api-key-123"));
    }
}
