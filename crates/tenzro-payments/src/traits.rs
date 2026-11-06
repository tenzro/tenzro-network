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

    /// Whether verifying a credential consumes replay state (a nonce), so a
    /// credential can be verified only once. Such protocols cannot be
    /// checked ahead of payment without spending the credential.
    fn verification_consumes_nonce(&self) -> bool {
        false
    }

    /// Server-side: builds the receipt for a verified payment and performs any
    /// settlement the scheme owns on another chain. Ledger settlement of a
    /// payer-authorized payment is the gateway's, after this returns.
    async fn settle(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
        verification: &PaymentVerification,
    ) -> Result<PaymentReceipt>;

    /// Client-side: creates a payment credential to satisfy a challenge,
    /// signed by the payer's own hybrid key.
    async fn create_credential(
        &self,
        challenge: &PaymentChallenge,
        payer_did: &str,
        signer: &dyn tenzro_crypto::composite::HybridSigner,
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

    /// Verifies a credential against what the caller expects it to pay for,
    /// settles it, and returns the receipt once the funds moved.
    async fn verify_and_settle(
        &self,
        credential: &PaymentCredential,
        expect: crate::gateway::PaymentExpectation<'_>,
    ) -> Result<PaymentReceipt>;

    /// Checks a metered (`upto`) credential before the work it pays for
    /// runs, and returns its challenge: the challenge is live and is what the
    /// caller expects, the payer signed a ceiling within it, and the payer's
    /// identity, delegation and spending policy admit that ceiling. Nothing is
    /// claimed or settled; the charge is settled afterwards, with its usage
    /// record, through [`PaymentGateway::verify_and_settle`].
    async fn verify_metered(
        &self,
        credential: &PaymentCredential,
        expect: crate::gateway::PaymentExpectation<'_>,
    ) -> Result<PaymentChallenge>;
}
