//! x402 HTTP client for automatic 402 payment handling
//!
//! Implements the x402 V2 client flow:
//! 1. Make initial request
//! 2. If 402, parse PAYMENT-REQUIRED header (base64-encoded PaymentRequirements)
//! 3. Select matching requirement, create signed PaymentPayload
//! 4. Retry with PAYMENT-SIGNATURE header (base64-encoded PaymentPayload)
//! 5. Parse PAYMENT-RESPONSE header from success response

use crate::error::{PaymentError, Result};
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::X402PaymentRequired;
use std::sync::Arc;
use tenzro_wallet::wallet::WalletId;
use tenzro_wallet::WalletService;
use tracing::{debug, info};

/// x402-aware HTTP client that automatically handles 402 Payment Required responses
pub struct X402Client {
    http_client: reqwest::Client,
    payer_address: String,
    wallet_service: Option<Arc<dyn WalletService>>,
    wallet_id: Option<WalletId>,
    supported_chains: Vec<String>,
}

impl X402Client {
    /// Creates a new x402 client
    pub fn new(payer_address: impl Into<String>) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            payer_address: payer_address.into(),
            wallet_service: None,
            wallet_id: None,
            supported_chains: vec!["tenzro".to_string(), "tempo".to_string()],
        }
    }

    /// Sets the wallet service for signing payments
    pub fn with_wallet(
        mut self,
        wallet_service: Arc<dyn WalletService>,
        wallet_id: impl Into<String>,
    ) -> Self {
        self.wallet_service = Some(wallet_service);
        self.wallet_id = Some(WalletId(wallet_id.into()));
        self
    }

    /// Sets the supported chains
    pub fn with_supported_chains(mut self, chains: Vec<String>) -> Self {
        self.supported_chains = chains;
        self
    }

    /// Makes an HTTP request, automatically handling x402 402 responses
    pub async fn get(&self, url: &str) -> Result<reqwest::Response> {
        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(e.to_string()))?;

        if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            debug!("Received x402 402 from {}", url);
            return self.handle_payment_required(url, response).await;
        }

        Ok(response)
    }

    /// Handles a 402 Payment Required response
    async fn handle_payment_required(
        &self,
        url: &str,
        response: reqwest::Response,
    ) -> Result<reqwest::Response> {
        // Try to get payment requirements from header first (V2), then body (V1)
        let requirements = if let Some(header) = response.headers().get("payment-required") {
            let header_str = header.to_str().map_err(|_| {
                PaymentError::ChallengeError("Invalid PAYMENT-REQUIRED header".to_string())
            })?;
            X402PaymentRequired::from_base64(header_str)?
        } else {
            // Fall back to body parsing (V1)
            let body = response
                .text()
                .await
                .map_err(|e| PaymentError::NetworkError(e.to_string()))?;
            serde_json::from_str(&body).map_err(|e| {
                PaymentError::ChallengeError(format!("Failed to parse payment requirements: {}", e))
            })?
        };

        info!(
            "Received {} payment requirement(s) from {}",
            requirements.accepts.len(),
            url
        );

        // Find a matching requirement for a chain we support
        let requirement = requirements
            .accepts
            .iter()
            .find(|r| self.supported_chains.contains(&r.chain))
            .ok_or_else(|| {
                PaymentError::ChallengeError(format!(
                    "No supported chain found in requirements. Server offers: {:?}, we support: {:?}",
                    requirements.accepts.iter().map(|r| &r.chain).collect::<Vec<_>>(),
                    self.supported_chains
                ))
            })?;

        // Create and sign the payment payload
        let payload = self.create_signed_payload(requirement).await?;

        // Encode payload as base64 for the header
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
        let payload_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload_json.as_bytes(),
        );

        // Retry the request with the payment header
        info!("Retrying {} with x402 payment header", url);
        let retry_response = self
            .http_client
            .get(url)
            .header("PAYMENT-SIGNATURE", &payload_b64)
            .send()
            .await
            .map_err(|e| PaymentError::NetworkError(e.to_string()))?;

        if retry_response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            return Err(PaymentError::SettlementError(
                "Payment rejected after retry — server refused payment payload".to_string(),
            ));
        }

        Ok(retry_response)
    }

    /// Creates a signed payment payload for a requirement
    async fn create_signed_payload(
        &self,
        requirement: &crate::x402::payment_required::X402PaymentRequirement,
    ) -> Result<X402PaymentPayload> {
        let mut payload = X402PaymentPayload::new(
            &requirement.chain,
            &requirement.asset,
            &requirement.amount,
            &self.payer_address,
            "", // authorization will be the signed message
        );

        // Sign the payload if we have a wallet
        if let (Some(wallet_service), Some(wallet_id)) = (&self.wallet_service, &self.wallet_id) {
            // Construct the message to sign
            let mut message = Vec::new();
            message.extend_from_slice(requirement.chain.as_bytes());
            message.extend_from_slice(requirement.asset.as_bytes());
            message.extend_from_slice(requirement.amount.as_bytes());
            message.extend_from_slice(requirement.recipient.as_bytes());
            message.extend_from_slice(self.payer_address.as_bytes());

            // Wave 3d: wallet now produces a hybrid signature. The x402 wire
            // format is fixed by Coinbase and only carries a single signature
            // string, so we emit the classical leg here. The ML-DSA-65 leg is
            // still computed and bound to the wallet's identity for internal
            // audit; an x402 extension may surface it once standardised.
            let hybrid_sig = wallet_service
                .sign_data(wallet_id, &message)
                .await
                .map_err(|e| {
                    PaymentError::CredentialError(format!("Failed to sign payment: {}", e))
                })?;

            payload.signature = hex::encode(&hybrid_sig.classical);
            payload.authorization = hex::encode(&message);
        } else {
            return Err(PaymentError::CredentialError(
                "Wallet service required for x402 payments — call with_wallet() first".to_string(),
            ));
        }

        Ok(payload)
    }

    /// Returns the payer address
    pub fn payer_address(&self) -> &str {
        &self.payer_address
    }
}
