//! Visa TAP issuer API client
//!
//! Agent-side client for the issuer surface of the Trusted Agent Protocol:
//! payment-instruction lifecycle, agent token provisioning, and credential
//! verification. Every request carries an RFC 9421 HTTP Message Signature
//! (via the crate's `rfc9421` signer) plus the issuer API key, so the issuer
//! can attribute the call to a registered agent key.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::error::{PaymentError, Result};
use crate::rfc9421::{
    RequestParts, SignatureAlgorithm, SignatureInput, SignatureParams, create_http_signature,
};
use crate::visa_tap::types::{AgentTag, ConsumerRecognition, PaymentContainer};

/// Default issuer API base (Visa Developer Platform TAP surface).
pub const DEFAULT_ISSUER_API_BASE: &str = "https://api.visa.com/tap";

const SIGNATURE_LABEL: &str = "sig1";
const COVERED_COMPONENTS: [&str; 4] = ["@method", "@authority", "@path", "content-type"];

/// Lifecycle status of an issuer payment instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentInstructionStatus {
    Created,
    Authorized,
    Captured,
    Declined,
    Expired,
    Reversed,
}

/// Request to create a payment instruction with the issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePaymentInstructionRequest {
    /// DID of the agent initiating the payment.
    pub agent_did: String,
    /// Merchant identifier the instruction settles to.
    pub merchant_id: String,
    /// Payment container (method, amount, asset, recipient, chain).
    pub container: PaymentContainer,
    /// Consumer recognition binding the instruction to a human principal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<ConsumerRecognition>,
    /// Caller-supplied correlation reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// A payment instruction as returned by the issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInstruction {
    pub instruction_id: String,
    pub status: PaymentInstructionStatus,
    pub agent_did: String,
    pub merchant_id: String,
    pub container: PaymentContainer,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Issuer-side network reference (authorization / settlement id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_reason: Option<String>,
}

/// Request to provision an issuer payment token bound to an agent credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionAgentTokenRequest {
    pub agent_did: String,
    /// Tenzro payment-credential id the token is bound to.
    pub credential_id: String,
    /// Hex-encoded public key the issuer pins for this token.
    pub public_key: String,
    /// Interaction class the token is provisioned for.
    pub tag: AgentTag,
}

/// Status of a provisioned agent token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTokenStatus {
    Active,
    Suspended,
    Revoked,
}

/// A provisioned issuer token for an agent credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentToken {
    pub token_id: String,
    pub agent_did: String,
    /// Hash of the tokenized instrument — matches
    /// [`crate::visa_tap::types::PaymentMethod::CardToken::token_hash`].
    pub token_hash: String,
    pub status: AgentTokenStatus,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to verify a TAP payment credential against the issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCredentialRequest {
    pub credential_id: String,
    pub agent_did: String,
    /// Base64 signature bytes presented with the credential.
    pub signature: String,
    /// Raw `Signature-Input` header value the signature was created under.
    pub signature_input: String,
    pub tag: AgentTag,
}

/// Issuer verdict on a presented credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialVerification {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IssuerErrorEnvelope {
    error: IssuerApiError,
}

/// Structured issuer API error body: `{"error": {"code": ..., "message": ...}}`.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuerApiError {
    pub code: String,
    pub message: String,
}

/// Client for the Visa TAP issuer API.
///
/// Mirrors the [`crate::mpp::stripe::StripeClient`] shape: reqwest transport,
/// bearer API key, `with_*()` builders, typed request/response structs. The
/// TAP-specific addition is RFC 9421 request signing — the issuer identifies
/// the calling agent by `key_id` and verifies the covered components.
#[derive(Debug)]
pub struct VisaTapIssuerClient {
    http_client: reqwest::Client,
    base_url: String,
    api_key: String,
    /// RFC 9421 `keyid` — the issuer-registered identifier for `signing_key`.
    key_id: String,
    /// Private key bytes in the format expected by
    /// [`crate::rfc9421::create_http_signature`] for `algorithm`.
    signing_key: Vec<u8>,
    algorithm: SignatureAlgorithm,
}

impl VisaTapIssuerClient {
    /// Creates an issuer client signing with Ed25519 by default.
    pub fn new(
        api_key: impl Into<String>,
        key_id: impl Into<String>,
        signing_key: Vec<u8>,
    ) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            base_url: DEFAULT_ISSUER_API_BASE.to_string(),
            api_key: api_key.into(),
            key_id: key_id.into(),
            signing_key,
            algorithm: SignatureAlgorithm::Ed25519,
        }
    }

    /// Overrides the issuer API base URL (sandbox / regional endpoints).
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Overrides the RFC 9421 signature algorithm (the key bytes must match).
    pub fn with_algorithm(mut self, algorithm: SignatureAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Creates a payment instruction with the issuer.
    pub async fn create_payment_instruction(
        &self,
        request: &CreatePaymentInstructionRequest,
    ) -> Result<PaymentInstruction> {
        info!(
            "Creating TAP payment instruction for agent {} → merchant {}",
            request.agent_did, request.merchant_id
        );
        self.post_signed("/payment-instructions", request, AgentTag::PayerAuth)
            .await
    }

    /// Retrieves the current status of a payment instruction.
    pub async fn get_payment_instruction(
        &self,
        instruction_id: &str,
    ) -> Result<PaymentInstruction> {
        debug!("Fetching TAP payment instruction {}", instruction_id);
        self.get_signed(
            &format!("/payment-instructions/{}", instruction_id),
            AgentTag::BrowserAuth,
        )
        .await
    }

    /// Provisions an issuer payment token bound to an agent credential.
    pub async fn provision_agent_token(
        &self,
        request: &ProvisionAgentTokenRequest,
    ) -> Result<AgentToken> {
        info!(
            "Provisioning TAP agent token for {} (credential {})",
            request.agent_did, request.credential_id
        );
        self.post_signed("/agent-tokens", request, request.tag)
            .await
    }

    /// Verifies a TAP payment credential against the issuer.
    pub async fn verify_payment_credential(
        &self,
        request: &VerifyCredentialRequest,
    ) -> Result<CredentialVerification> {
        debug!(
            "Verifying TAP credential {} for agent {}",
            request.credential_id, request.agent_did
        );
        self.post_signed("/credentials/verify", request, request.tag)
            .await
    }

    async fn post_signed<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: &B,
        tag: AgentTag,
    ) -> Result<T> {
        let url = self.endpoint_url(endpoint);
        let (signature_input, signature) = self.signed_headers("POST", &url, tag)?;

        let response = self
            .http_client
            .post(&url)
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .header("Signature-Input", signature_input)
            .header("Signature", signature)
            .json(body)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Issuer request failed: {}", e)))?;

        Self::parse_response(response).await
    }

    async fn get_signed<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        tag: AgentTag,
    ) -> Result<T> {
        let url = self.endpoint_url(endpoint);
        let (signature_input, signature) = self.signed_headers("GET", &url, tag)?;

        let response = self
            .http_client
            .get(&url)
            .bearer_auth(&self.api_key)
            .header("Content-Type", "application/json")
            .header("Signature-Input", signature_input)
            .header("Signature", signature)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Issuer request failed: {}", e)))?;

        Self::parse_response(response).await
    }

    fn endpoint_url(&self, endpoint: &str) -> String {
        format!("{}{}", self.base_url.trim_end_matches('/'), endpoint)
    }

    /// Builds the RFC 9421 `Signature-Input` + `Signature` header pair for a
    /// request to `url`. The param serialization order (created, nonce,
    /// keyid, alg, tag) matches `build_signature_base` so verifiers derive
    /// the identical signature base from the header.
    fn signed_headers(&self, method: &str, url: &str, tag: AgentTag) -> Result<(String, String)> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| PaymentError::VisaTapError(format!("Invalid issuer URL: {}", e)))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| PaymentError::VisaTapError("Issuer URL has no host".to_string()))?;
        let authority = match parsed.port() {
            Some(port) => format!("{}:{}", host, port),
            None => host.to_string(),
        };
        let path = parsed.path().to_string();

        let created = Utc::now().timestamp() as u64;
        let nonce = uuid::Uuid::new_v4().to_string();

        let parts = RequestParts::for_request(method, authority.clone(), path.clone())
            .with_header("content-type", "application/json");
        let input = SignatureInput {
            label: SIGNATURE_LABEL.to_string(),
            covered_components: COVERED_COMPONENTS.iter().map(|c| c.to_string()).collect(),
            params: SignatureParams {
                label: SIGNATURE_LABEL.to_string(),
                created: Some(created),
                expires: None,
                nonce: Some(nonce.clone()),
                keyid: self.key_id.clone(),
                alg: self.algorithm,
                tag: Some(tag.as_str().to_string()),
            },
        };

        let signature_bytes =
            create_http_signature(&parts, &input, &self.signing_key, &self.algorithm)?;

        let components: Vec<String> = COVERED_COMPONENTS
            .iter()
            .map(|c| format!("\"{}\"", c))
            .collect();
        let signature_input_header = format!(
            "{}=({});created={};nonce=\"{}\";keyid=\"{}\";alg=\"{}\";tag=\"{}\"",
            SIGNATURE_LABEL,
            components.join(" "),
            created,
            nonce,
            self.key_id,
            self.algorithm.as_str(),
            tag.as_str(),
        );
        let signature_header = format!("{}=:{}:", SIGNATURE_LABEL, BASE64.encode(&signature_bytes));

        Ok((signature_input_header, signature_header))
    }

    async fn parse_response<T: for<'de> Deserialize<'de>>(
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| PaymentError::NetworkError(format!("Issuer response read: {}", e)))?;

        if !status.is_success() {
            if let Ok(envelope) = serde_json::from_str::<IssuerErrorEnvelope>(&body) {
                return Err(PaymentError::VisaTapError(format!(
                    "Issuer API error {} ({}): {}",
                    status, envelope.error.code, envelope.error.message
                )));
            }
            return Err(PaymentError::VisaTapError(format!(
                "Issuer API error {}: {}",
                status, body
            )));
        }

        serde_json::from_str(&body)
            .map_err(|e| PaymentError::SerializationError(format!("Issuer response parse: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc9421::SignedHeaders;
    use crate::rfc9421::signature::parse_signature_input;
    use crate::rfc9421::verify_http_signature;
    use crate::visa_tap::types::PaymentMethod;
    use tenzro_crypto::keys::{KeyPair, KeyType};

    fn test_client() -> (VisaTapIssuerClient, Vec<u8>) {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let public = keypair.public_key().to_bytes();
        let client = VisaTapIssuerClient::new("vk_test_123", "agent-key-1", keypair.to_bytes());
        (client, public)
    }

    #[test]
    fn client_defaults() {
        let (client, _) = test_client();
        assert_eq!(client.base_url, DEFAULT_ISSUER_API_BASE);
        assert_eq!(client.algorithm, SignatureAlgorithm::Ed25519);

        let client = client.with_base_url("https://sandbox.api.visa.com/tap/");
        assert_eq!(
            client.endpoint_url("/agent-tokens"),
            "https://sandbox.api.visa.com/tap/agent-tokens"
        );
    }

    #[test]
    fn signed_headers_verify_against_public_key() {
        let (client, public_key) = test_client();
        let url = format!("{}/payment-instructions", DEFAULT_ISSUER_API_BASE);
        let (signature_input_raw, signature_header) = client
            .signed_headers("POST", &url, AgentTag::PayerAuth)
            .unwrap();

        assert!(signature_input_raw.starts_with("sig1=(\"@method\""));
        assert!(signature_input_raw.contains("keyid=\"agent-key-1\""));
        assert!(signature_input_raw.contains("alg=\"ed25519\""));
        assert!(signature_input_raw.contains("tag=\"agent-payer-auth\""));
        assert!(signature_header.starts_with("sig1=:"));
        assert!(signature_header.ends_with(':'));

        // Round-trip: parse the emitted header and verify the signature the
        // way an issuer-side RFC 9421 verifier would.
        let parsed = parse_signature_input(&signature_input_raw).unwrap();
        let sig_b64 = signature_header
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();
        let signed = SignedHeaders {
            signature_input_raw: signature_input_raw.clone(),
            signature_bytes: BASE64.decode(sig_b64).unwrap(),
            parsed,
        };
        let parts = RequestParts::for_request("POST", "api.visa.com", "/tap/payment-instructions")
            .with_header("content-type", "application/json");
        verify_http_signature(&parts, &signed, &public_key, &SignatureAlgorithm::Ed25519).unwrap();
    }

    #[test]
    fn signed_headers_reject_bad_key_material() {
        let client = VisaTapIssuerClient::new("vk_test_123", "agent-key-1", vec![1, 2, 3]);
        let url = format!("{}/agent-tokens", DEFAULT_ISSUER_API_BASE);
        let err = client
            .signed_headers("POST", &url, AgentTag::PayerAuth)
            .unwrap_err();
        assert!(matches!(err, PaymentError::Rfc9421Error(_)));
    }

    #[test]
    fn create_instruction_request_serializes_camel_case() {
        let request = CreatePaymentInstructionRequest {
            agent_did: "did:tenzro:machine:agent".to_string(),
            merchant_id: "merchant-42".to_string(),
            container: PaymentContainer {
                payment_method: PaymentMethod::CardToken {
                    token_hash: "abc123".to_string(),
                },
                amount: 25_000,
                asset: "USDC".to_string(),
                recipient: "0xmerchant".to_string(),
                chain: "tenzro-mainnet".to_string(),
            },
            consumer: None,
            reference: Some("order-7".to_string()),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"agentDid\":\"did:tenzro:machine:agent\""));
        assert!(json.contains("\"merchantId\":\"merchant-42\""));
        assert!(json.contains("\"reference\":\"order-7\""));
        assert!(!json.contains("consumer"));
    }

    #[test]
    fn payment_instruction_deserializes_issuer_shape() {
        let body = r#"{
            "instructionId": "pi_001",
            "status": "authorized",
            "agentDid": "did:tenzro:machine:agent",
            "merchantId": "merchant-42",
            "container": {
                "payment_method": {"type": "card_token", "token_hash": "abc123"},
                "amount": 25000,
                "asset": "USDC",
                "recipient": "0xmerchant",
                "chain": "tenzro-mainnet"
            },
            "createdAt": "2026-07-12T00:00:00Z",
            "networkReference": "auth-9001"
        }"#;

        let instruction: PaymentInstruction = serde_json::from_str(body).unwrap();
        assert_eq!(instruction.instruction_id, "pi_001");
        assert_eq!(instruction.status, PaymentInstructionStatus::Authorized);
        assert_eq!(instruction.network_reference.as_deref(), Some("auth-9001"));
        assert!(instruction.expires_at.is_none());
    }

    #[test]
    fn credential_verification_deserializes() {
        let verification: CredentialVerification =
            serde_json::from_str(r#"{"valid": false, "reason": "token_revoked"}"#).unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.reason.as_deref(), Some("token_revoked"));

        let token: AgentToken = serde_json::from_str(
            r#"{
                "tokenId": "tok_1",
                "agentDid": "did:tenzro:machine:agent",
                "tokenHash": "abc",
                "status": "active",
                "createdAt": "2026-07-12T00:00:00Z"
            }"#,
        )
        .unwrap();
        assert_eq!(token.status, AgentTokenStatus::Active);
    }
}
