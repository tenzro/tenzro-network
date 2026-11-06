//! Fixtures shared by this crate's tests.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use chrono::Utc;
use tenzro_identity::{IdentityRegistry, WalletBinder};

use crate::error::Result;
use crate::gateway::{RailOutcome, SettlementInstruction, SettlementRail};
use crate::payer_auth::{EnrolledKeys, sign_credential, verify_payer};
use crate::traits::PaymentProtocol;
use crate::types::{
    PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification, SettlementLeg,
};

/// An [`IdentityRegistry`] that can actually provision a wallet.
///
/// `IdentityRegistry::new()` wires a binder for itself under `#[cfg(test)]`,
/// and `cfg(test)` is not transitive: it holds while tenzro-identity compiles
/// its OWN tests and is false when tenzro-identity is built as a dependency of
/// this crate's tests. So every fixture here got `wallet_binder: None`, and
/// registration refuses without one — "Refusing rather than assigning a
/// placeholder address no key can sign for", which is correct behaviour and
/// left thirty tests in this crate red against it.
///
/// Asking for the binder explicitly is what a test that needs a signable wallet
/// should do anyway; it does not depend on how a dependency happens to be
/// compiled.
/// Enrolled keys for test signers: a `TestHybridSigner::hybrid` account has
/// enrolled its ML-DSA-65 key, any other account none.
pub struct SeedKeys;

impl EnrolledKeys for SeedKeys {
    fn enrolled_pq_key(&self, p256_xy: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(tenzro_crypto::composite::testing::TestHybridSigner::hybrid_pq_key(p256_xy))
    }
}

pub fn registry_with_binder() -> IdentityRegistry {
    let binder = WalletBinder::new().expect("test wallet binder");
    IdentityRegistry::with_wallet_binder(Arc::new(binder))
}

/// Protocol that verifies with the shared payer authorization.
pub struct TestProtocol;

#[async_trait]
impl PaymentProtocol for TestProtocol {
    fn protocol_name(&self) -> &str {
        "test"
    }

    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        Ok(PaymentChallenge {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            protocol: "test".to_string(),
            resource: resource.to_string(),
            amount,
            asset: asset.to_string(),
            recipient: recipient.to_string(),
            chain: "tenzro".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            extra: HashMap::new(),
        })
    }

    async fn verify_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<PaymentVerification> {
        let payer = verify_payer(&SeedKeys, challenge, credential)?;
        Ok(PaymentVerification {
            credential_id: credential.credential_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: credential.payer_did.clone(),
            verified_at: Utc::now(),
            amount: credential.amount,
            leg: SettlementLeg::Payer(payer),
            detail: None,
        })
    }

    async fn settle(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
        verification: &PaymentVerification,
    ) -> Result<PaymentReceipt> {
        Ok(PaymentReceipt {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            protocol: "test".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            credential_id: credential.credential_id.clone(),
            amount: verification.amount,
            asset: challenge.asset.clone(),
            settlement_tx: None,
            chain: challenge.chain.clone(),
            settled_at: Utc::now(),
            principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                verification.payer_did.clone(),
                tenzro_types::primitives::BlockHeight::new(0),
            ),
            extra: HashMap::new(),
        })
    }

    async fn create_credential(
        &self,
        challenge: &PaymentChallenge,
        payer_did: &str,
        signer: &dyn tenzro_crypto::composite::HybridSigner,
    ) -> Result<PaymentCredential> {
        sign_credential(
            challenge,
            "test",
            payer_did,
            signer,
            challenge.amount,
            challenge.amount,
        )
    }
}

/// Rail that records what it was asked to move and answers as told.
pub struct RecordingRail {
    pub seen: Mutex<Vec<SettlementInstruction>>,
    pub answer: Mutex<RailOutcome>,
    pub calls: AtomicUsize,
    pub delay_ms: u64,
}

impl RecordingRail {
    pub fn new(answer: RailOutcome) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(Vec::new()),
            answer: Mutex::new(answer),
            calls: AtomicUsize::new(0),
            delay_ms: 0,
        })
    }
}

#[async_trait]
impl SettlementRail for RecordingRail {
    fn name(&self) -> &'static str {
        "recording"
    }
    fn carries(&self, asset: &str) -> bool {
        asset.eq_ignore_ascii_case("TNZO")
    }
    async fn settle(&self, i: &SettlementInstruction) -> Result<RailOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
        }
        self.seen.lock().unwrap().push(i.clone());
        Ok(self.answer.lock().unwrap().clone())
    }
    async fn status(&self, _payment_id: &str) -> Result<RailOutcome> {
        Ok(self.answer.lock().unwrap().clone())
    }
}

pub fn signer() -> tenzro_crypto::composite::testing::TestHybridSigner {
    static SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
    tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
        SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}
