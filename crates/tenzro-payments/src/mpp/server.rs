//! MPP server-side payment protocol implementation
//!
//! Two intents are served:
//!
//! - **charge**: a one-shot payment. The payer signs the canonical payment
//!   authorization for exactly the challenge amount, and the gateway settles
//!   it on the rail that carries the asset.
//! - **session**: a capped streaming session. The payer's on-chain escrow
//!   deposit is the cap; each request is paid with a cumulative voucher
//!   against it, and the payee claims the highest voucher from the escrow.
//!   The challenge `amount` is the price of one request.

use crate::challenge_store::ChallengeStore;
use crate::error::{PaymentError, Result};
use crate::mpp::challenge::MppChallenge;
use crate::payer_auth::{EnrolledKeys, verify_escrow_voucher, verify_payer};
use crate::traits::PaymentProtocol;
use crate::types::{
    PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification, SettlementLeg,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tracing::{debug, info};

/// Key in `challenge.extra` naming the MPP intent.
pub const MPP_INTENT_KEY: &str = "intent";

/// The one-shot intent.
pub const MPP_INTENT_CHARGE: &str = "charge";

/// The capped streaming-session intent.
pub const MPP_INTENT_SESSION: &str = "session";

/// MPP server-side payment handler
pub struct MppPaymentServer {
    /// Default chain
    default_chain: String,
    /// Intent this server issues challenges under.
    intent: &'static str,
    /// Challenge store for looking up challenges during settlement
    challenge_store: ChallengeStore,
    /// The keys payers' accounts enrolled, which their signatures verify against.
    keys: std::sync::Arc<dyn EnrolledKeys>,
}

impl MppPaymentServer {
    /// Creates a new MPP payment server issuing `charge` challenges.
    pub fn new(keys: std::sync::Arc<dyn EnrolledKeys>) -> Self {
        Self {
            default_chain: "tenzro".to_string(),
            intent: MPP_INTENT_CHARGE,
            challenge_store: ChallengeStore::new(),
            keys,
        }
    }

    /// Issue `session` challenges: each request is paid by a voucher
    /// against the payer's on-chain escrow.
    pub fn with_session_intent(mut self) -> Self {
        self.intent = MPP_INTENT_SESSION;
        self
    }

    /// Sets the default chain
    pub fn with_default_chain(mut self, chain: impl Into<String>) -> Self {
        self.default_chain = chain.into();
        self
    }

    /// Sets a shared challenge store (e.g., shared with gateway)
    pub fn with_challenge_store(mut self, store: ChallengeStore) -> Self {
        self.challenge_store = store;
        self
    }

    /// Returns a reference to the challenge store
    pub fn challenge_store(&self) -> &ChallengeStore {
        &self.challenge_store
    }
}

fn challenge_intent(challenge: &PaymentChallenge) -> &str {
    challenge
        .extra
        .get(MPP_INTENT_KEY)
        .and_then(|v| v.as_str())
        .unwrap_or(MPP_INTENT_CHARGE)
}

#[async_trait]
impl PaymentProtocol for MppPaymentServer {
    fn protocol_name(&self) -> &str {
        "mpp"
    }

    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        let mpp_challenge =
            MppChallenge::new(resource, amount, asset, recipient).with_chain(&self.default_chain);

        info!(
            "Created MPP {} challenge {} for resource {} amount={}",
            self.intent, mpp_challenge.challenge_id, resource, amount
        );

        let mut extra = HashMap::new();
        extra.insert(MPP_INTENT_KEY.to_string(), serde_json::json!(self.intent));
        let challenge = PaymentChallenge {
            challenge_id: mpp_challenge.challenge_id,
            protocol: "mpp".to_string(),
            resource: mpp_challenge.resource,
            amount: mpp_challenge.amount,
            asset: mpp_challenge.asset,
            recipient: mpp_challenge.recipient,
            chain: mpp_challenge.chain,
            expires_at: mpp_challenge.expires_at,
            extra,
        };

        self.challenge_store.store(&challenge)?;
        Ok(challenge)
    }

    async fn verify_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<PaymentVerification> {
        info!(
            "Verifying MPP credential {} for challenge {}",
            credential.credential_id, challenge.challenge_id
        );

        if Utc::now() > challenge.expires_at {
            return Err(PaymentError::VerificationFailed(
                "Challenge has expired".to_string(),
            ));
        }

        let leg = match challenge_intent(challenge) {
            MPP_INTENT_CHARGE => {
                if credential.amount != challenge.amount
                    || credential
                        .extra
                        .contains_key(crate::payer_auth::UPTO_MAX_KEY)
                {
                    return Err(PaymentError::VerificationFailed(format!(
                        "charge intent pays exactly {}, got {}",
                        challenge.amount, credential.amount
                    )));
                }
                SettlementLeg::Payer(verify_payer(self.keys.as_ref(), challenge, credential)?)
            }
            MPP_INTENT_SESSION => {
                if credential.amount != challenge.amount {
                    return Err(PaymentError::VerificationFailed(format!(
                        "session request costs {}, voucher advances {}",
                        challenge.amount, credential.amount
                    )));
                }
                SettlementLeg::Voucher(verify_escrow_voucher(
                    self.keys.as_ref(),
                    challenge,
                    credential,
                )?)
            }
            other => {
                return Err(PaymentError::VerificationFailed(format!(
                    "unknown MPP intent '{other}'"
                )));
            }
        };

        debug!("MPP credential {} verified", credential.credential_id);

        Ok(PaymentVerification {
            credential_id: credential.credential_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            payer_did: credential.payer_did.clone(),
            verified_at: Utc::now(),
            amount: credential.amount,
            leg,
            detail: None,
        })
    }

    async fn settle(
        &self,
        challenge: &PaymentChallenge,
        _credential: &PaymentCredential,
        verification: &PaymentVerification,
    ) -> Result<PaymentReceipt> {
        let mut extra = HashMap::new();
        extra.insert(
            MPP_INTENT_KEY.to_string(),
            serde_json::json!(challenge_intent(challenge)),
        );
        Ok(PaymentReceipt {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            protocol: "mpp".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            credential_id: verification.credential_id.clone(),
            amount: verification.amount,
            asset: challenge.asset.clone(),
            settlement_tx: None,
            chain: challenge.chain.clone(),
            settled_at: Utc::now(),
            principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                verification.payer_did.clone(),
                tenzro_types::primitives::BlockHeight::new(0),
            ),
            extra,
        })
    }

    async fn create_credential(
        &self,
        challenge: &PaymentChallenge,
        payer_did: &str,
        signer: &dyn tenzro_crypto::composite::HybridSigner,
    ) -> Result<PaymentCredential> {
        if challenge_intent(challenge) != MPP_INTENT_CHARGE {
            return Err(PaymentError::CredentialError(
                "a session is paid with an escrow voucher, not a signed charge".to_string(),
            ));
        }
        crate::payer_auth::sign_credential(
            challenge,
            "mpp",
            payer_did,
            signer,
            challenge.amount,
            challenge.amount,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYEE: &str = "0909090909090909090909090909090909090909";

    fn signer() -> tenzro_crypto::composite::testing::TestHybridSigner {
        static SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
        tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
            SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        )
    }

    async fn stamped(server: &MppPaymentServer) -> PaymentChallenge {
        let mut ch = server
            .create_challenge("/api/test", 5000, "TNZO", PAYEE)
            .await
            .unwrap();
        ch.extra.insert(
            crate::payer_auth::CHAIN_ID_KEY.to_string(),
            serde_json::json!(1337u64),
        );
        ch
    }

    #[tokio::test]
    async fn a_charge_verifies_to_a_payer_leg_for_the_exact_amount() {
        let server = MppPaymentServer::new(std::sync::Arc::new(crate::test_support::SeedKeys));
        let ch = stamped(&server).await;
        let cred = server.create_credential(&ch, "", &signer()).await.unwrap();
        let v = server.verify_credential(&ch, &cred).await.unwrap();
        assert!(matches!(v.leg, SettlementLeg::Payer(_)));
        assert_eq!(v.amount, 5000);
    }

    #[tokio::test]
    async fn a_charge_signed_with_one_key_cannot_debit_another_account() {
        let server = MppPaymentServer::new(std::sync::Arc::new(crate::test_support::SeedKeys));
        let ch = stamped(&server).await;
        let mut cred = server.create_credential(&ch, "", &signer()).await.unwrap();
        cred.payer_address = hex::encode([0x77u8; 20]);
        assert!(server.verify_credential(&ch, &cred).await.is_err());
    }

    #[tokio::test]
    async fn a_session_challenge_refuses_a_signed_charge() {
        let server = MppPaymentServer::new(std::sync::Arc::new(crate::test_support::SeedKeys))
            .with_session_intent();
        let ch = stamped(&server).await;
        assert!(server.create_credential(&ch, "", &signer()).await.is_err());
        let charge_server =
            MppPaymentServer::new(std::sync::Arc::new(crate::test_support::SeedKeys));
        let mut charge = stamped(&charge_server).await;
        charge.challenge_id = ch.challenge_id.clone();
        let cred = charge_server
            .create_credential(&charge, "", &signer())
            .await
            .unwrap();
        // A charge credential carries no voucher fields.
        assert!(server.verify_credential(&ch, &cred).await.is_err());
    }
}
