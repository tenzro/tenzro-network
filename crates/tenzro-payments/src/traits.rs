//! Core payment protocol traits

use crate::error::Result;
use crate::types::{PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification};
use async_trait::async_trait;

/// Core trait that all payment protocols must implement
///
/// Covers both server-side (challenge/verify/settle) and client-side
/// (create credential) flows.
#[async_trait]
pub trait PaymentProtocol: Send + Sync {
    /// Returns the protocol name (e.g., "mpp", "x402")
    fn protocol_name(&self) -> &str;

    /// Server-side: creates a payment challenge for a resource
    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge>;

    /// Server-side: verifies a payment credential against a challenge
    async fn verify_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<PaymentVerification>;

    /// Server-side: settles a verified payment
    async fn settle(&self, verification: &PaymentVerification) -> Result<PaymentReceipt>;

    /// Client-side: creates a payment credential to satisfy a challenge
    async fn create_credential(
        &self,
        challenge: &PaymentChallenge,
        payer_did: &str,
        wallet_id: &str,
    ) -> Result<PaymentCredential>;
}

/// Unified payment gateway that routes across multiple protocols
#[async_trait]
pub trait PaymentGateway: Send + Sync {
    /// Returns the list of supported protocol names
    fn supported_protocols(&self) -> Vec<String>;

    /// Creates a challenge using the specified protocol
    async fn create_challenge(
        &self,
        protocol: &str,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge>;

    /// Verifies a credential (auto-detects protocol from the credential)
    async fn verify_and_settle(
        &self,
        credential: &PaymentCredential,
    ) -> Result<PaymentReceipt>;
}
