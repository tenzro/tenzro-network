//! x402 server-side payment protocol implementation

use crate::challenge_store::ChallengeStore;
use crate::error::{PaymentError, Result};
use crate::traits::PaymentProtocol;
use crate::types::{
    PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification, SettlementLeg,
};
use crate::x402::scheme::SchemeRegistry;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// x402 server-side payment handler.
///
/// Credentials are verified via a [`SchemeRegistry`] that maps the scheme id
/// from `challenge.extra["scheme"]` (e.g. `"exact-eip3009"`, `"permit2"`,
/// `"erc7710"`, or the internal `"tenzro-hybrid"` default) to a
/// [`crate::x402::scheme::SchemeBackend`]. Use
/// [`X402PaymentServer::with_scheme_registry`] to inject custom backends.
///
/// The server verifies and builds receipts. Settlement of a Tenzro-native
/// payment happens in the gateway, on the rail that carries its asset; a
/// scheme that settles on another chain (EIP-3009, Permit2) settles in
/// [`PaymentProtocol::settle`] through its facilitator.
pub struct X402PaymentServer {
    /// Supported chains
    supported_chains: Vec<String>,
    /// Chain id of the Tenzro network this server issues challenges for.
    chain_id: u64,
    /// Challenge store for looking up challenges during settlement
    challenge_store: ChallengeStore,
    /// Registry of credential-verification backends, dispatched per
    /// `challenge.extra["scheme"]`.
    scheme_registry: SchemeRegistry,
    /// Optional server key that signs the offer commitment on the 402 body so
    /// a buyer can prove which price it agreed to.
    offer_signer: Option<Arc<dyn tenzro_crypto::composite::HybridSigner>>,
    /// The meter that signs usage records for `upto` challenges. When set,
    /// every `upto` challenge names its key and charges only against a
    /// record it signed.
    meter_signer: Option<Arc<dyn tenzro_crypto::composite::HybridSigner>>,
    /// The scheme this server pins on the challenges it issues.
    ///
    /// Configuration rather than a literal, because the choice is an economic
    /// one the operator makes, not a property of the protocol. A resource whose
    /// price is known up front issues `exact`-family challenges; a **metered**
    /// resource — inference, media generation, anything billed by consumption —
    /// issues [`crate::x402::UPTO_SCHEME`], where `amount` is the ceiling the
    /// buyer authorizes and the seller settles the actual usage beneath it.
    scheme: String,
    /// Schemes offered beside `scheme` on every challenge, each as its own
    /// option in `PAYMENT-REQUIRED`: a payer answers with whichever it can
    /// sign. A metered resource offers `batch-settlement` too, so a payer that
    /// holds no key of its own (a delegated agent, paying with vouchers its
    /// serving node signs on a channel it funded) can pay it.
    also_offered: Vec<String>,
}

impl X402PaymentServer {
    /// Offers `scheme` beside the pinned one on every challenge.
    pub fn with_also_offered(mut self, scheme: impl Into<String>) -> Self {
        let scheme = scheme.into();
        if scheme != self.scheme && !self.also_offered.contains(&scheme) {
            self.also_offered.push(scheme);
        }
        self
    }

    /// Pins the scheme this server issues challenges under.
    ///
    /// Set [`crate::x402::UPTO_SCHEME`] on a node serving **metered** resources
    /// — inference, media generation, anything priced by consumption. Under it
    /// the challenge `amount` is the ceiling the buyer authorizes rather than a
    /// fixed price, and the seller settles the metered actual beneath it.
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = scheme.into();
        self
    }

    /// Creates a new x402 payment server with the default scheme registry
    /// ([`SchemeRegistry::with_defaults`]).
    pub fn new(
        chain_id: u64,
        supported_chains: Vec<String>,
        keys: std::sync::Arc<dyn crate::payer_auth::EnrolledKeys>,
    ) -> Self {
        Self {
            supported_chains,
            chain_id,
            challenge_store: ChallengeStore::new(),
            scheme_registry: SchemeRegistry::with_defaults(keys),
            offer_signer: None,
            meter_signer: None,
            scheme: crate::x402::DEFAULT_SCHEME.to_string(),
            also_offered: Vec::new(),
        }
    }

    /// Sets a shared challenge store
    pub fn with_challenge_store(mut self, store: ChallengeStore) -> Self {
        self.challenge_store = store;
        self
    }

    /// Replace the scheme registry. Use this to register additional backends
    /// or to swap the default verifiers (e.g. point a custom facilitator at
    /// the EIP-3009 backend).
    pub fn with_scheme_registry(mut self, registry: SchemeRegistry) -> Self {
        self.scheme_registry = registry;
        self
    }

    /// Attach the node's signer, whose Ed25519 leg signs the offer on each
    /// challenge so a buyer can verify the price before paying.
    pub fn with_offer_signer(
        mut self,
        signer: Arc<dyn tenzro_crypto::composite::HybridSigner>,
    ) -> Self {
        self.offer_signer = Some(signer);
        self
    }

    /// Attach the meter whose signed usage records back `upto` charges.
    pub fn with_meter_signer(
        mut self,
        signer: Arc<dyn tenzro_crypto::composite::HybridSigner>,
    ) -> Self {
        self.meter_signer = Some(signer);
        self
    }

    /// Charge an `upto` credential for what was served: sign a usage record
    /// for `lines` with the meter and set the credential's charge to it.
    pub fn meter(
        &self,
        challenge: &PaymentChallenge,
        credential: &mut PaymentCredential,
        lines: Vec<crate::metering::UsageLine>,
    ) -> Result<crate::metering::UsageRecord> {
        let signer = self
            .meter_signer
            .as_ref()
            .ok_or_else(|| PaymentError::ConfigError("this server has no meter".to_string()))?;
        let pk = hex::decode(
            credential
                .extra
                .get(crate::payer_auth::PUBLIC_KEY_KEY)
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
        )
        .map_err(|_| PaymentError::CredentialError("public_key is not hex".to_string()))?;
        let payer = crate::payer_auth::payer_account(&pk);
        let ceiling = crate::payer_auth::authorized_ceiling(credential)?;
        use crate::metering::MeterRecord as _;
        let record = crate::metering::UsageRecord::sign(
            challenge,
            &hex::encode(&payer.as_bytes()[..20]),
            ceiling,
            lines,
            signer.as_ref(),
        )?;
        crate::metering::attach(credential, &record)?;
        Ok(record)
    }

    /// Returns a reference to the challenge store
    pub fn challenge_store(&self) -> &ChallengeStore {
        &self.challenge_store
    }

    /// Returns a reference to the configured scheme registry.
    pub fn scheme_registry(&self) -> &SchemeRegistry {
        &self.scheme_registry
    }

    /// The CAIP-2 network a challenge on `chain` settles on.
    fn network_for(&self, chain: &str) -> String {
        tenzro_types::settlement_network::caip2_for_chain_name(chain, self.chain_id)
            .map(|c| c.into_owned())
            .unwrap_or_else(|| chain.to_string())
    }
}

impl crate::middleware::UsageMeter for X402PaymentServer {
    fn meter(
        &self,
        challenge: &PaymentChallenge,
        credential: &mut PaymentCredential,
        lines: Vec<crate::metering::UsageLine>,
    ) -> Result<crate::metering::UsageRecord> {
        X402PaymentServer::meter(self, challenge, credential, lines)
    }
}

#[async_trait]
impl PaymentProtocol for X402PaymentServer {
    fn protocol_name(&self) -> &str {
        "x402"
    }

    async fn create_challenge(
        &self,
        resource: &str,
        amount: u128,
        asset: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        info!("Creating x402 challenge for resource {}", resource);

        let chain = self
            .supported_chains
            .first()
            .cloned()
            .unwrap_or_else(|| "tenzro".to_string());
        let scheme = self.scheme.clone();
        let network = self.network_for(&chain);

        let mut extra = HashMap::new();
        extra.insert("scheme".to_string(), serde_json::json!(scheme));
        extra.insert("network".to_string(), serde_json::json!(network));
        if !self.also_offered.is_empty() {
            let mut offered = vec![scheme.clone()];
            offered.extend(self.also_offered.iter().cloned());
            extra.insert(
                crate::x402::wire::OFFERED_SCHEMES_KEY.to_string(),
                serde_json::json!(offered),
            );
        }
        if scheme == crate::x402::UPTO_SCHEME
            && let Some(meter) = &self.meter_signer
        {
            extra.insert(
                crate::metering::METER_KEY.to_string(),
                serde_json::json!(hex::encode(&meter.public_key().p256)),
            );
        }

        let mut challenge = PaymentChallenge {
            challenge_id: uuid::Uuid::new_v4().to_string(),
            protocol: "x402".to_string(),
            resource: resource.to_string(),
            amount,
            asset: asset.to_string(),
            recipient: recipient.to_string(),
            chain,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            extra,
        };

        // With an offer signer configured, the node signs the option it
        // offers so a buyer can verify the price against the node's key.
        if let Some(signer) = &self.offer_signer {
            let requirement = crate::x402::wire::requirement_for(&challenge);
            let offer =
                crate::x402::offer::SignedOffer::sign(resource, &requirement, signer.as_ref())?;
            for (key, value) in [
                (
                    crate::x402::offer::OFFER_COMMITMENT_KEY,
                    offer.offer_commitment,
                ),
                (crate::x402::offer::OFFER_SIG_KEY, offer.offer_sig),
                (crate::x402::offer::OFFER_SIGNER_KEY, offer.offer_signer),
            ] {
                challenge
                    .extra
                    .insert(key.to_string(), serde_json::json!(value));
            }
        }

        self.challenge_store.store(&challenge)?;
        Ok(challenge)
    }

    async fn verify_credential(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<PaymentVerification> {
        info!(
            "Verifying x402 credential {} for challenge {}",
            credential.credential_id, challenge.challenge_id
        );

        if credential.challenge_id != challenge.challenge_id {
            return Err(PaymentError::VerificationFailed(
                "Credential challenge_id does not match".to_string(),
            ));
        }
        if Utc::now() > challenge.expires_at {
            return Err(PaymentError::VerificationFailed(
                "Challenge has expired".to_string(),
            ));
        }
        if !self.supported_chains.contains(&challenge.chain) && !self.supported_chains.is_empty() {
            return Err(PaymentError::VerificationFailed(format!(
                "Unsupported chain: {}",
                challenge.chain
            )));
        }

        // The scheme the challenge was minted under decides which backend
        // verifies, and each backend enforces its own amount rule: exact
        // schemes charge the challenge amount, `upto` charges at most the
        // signed ceiling, `batch-settlement` charges a voucher's advance.
        let backend = self
            .scheme_registry
            .lookup_for_credential(challenge, credential)?;
        let leg = backend.verify(challenge, credential).await?;
        if credential.amount > challenge.amount {
            return Err(PaymentError::VerificationFailed(format!(
                "charge {} exceeds the challenge amount {}",
                credential.amount, challenge.amount
            )));
        }
        debug!(
            "x402 credential {} verified under scheme '{}'",
            credential.credential_id,
            backend.name()
        );

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
        credential: &PaymentCredential,
        verification: &PaymentVerification,
    ) -> Result<PaymentReceipt> {
        let scheme_id = challenge
            .extra
            .get("scheme")
            .and_then(|v| v.as_str())
            .unwrap_or(crate::x402::DEFAULT_SCHEME)
            .to_string();

        // A scheme that settles on another chain settles here, through its
        // facilitator; its transaction is the receipt's settlement reference.
        let settlement_tx = match verification.leg {
            SettlementLeg::Foreign => {
                let backend = self
                    .scheme_registry
                    .lookup_for_credential(challenge, credential)?;
                Some(
                    backend
                        .settle(challenge, credential)
                        .await?
                        .ok_or_else(|| {
                            PaymentError::SettlementError(format!(
                                "scheme {scheme_id} has no settlement leg on its chain"
                            ))
                        })?,
                )
            }
            SettlementLeg::Payer(_) | SettlementLeg::Voucher(_) => None,
        };

        let mut extra: HashMap<String, serde_json::Value> = HashMap::new();
        extra.insert(
            "network".to_string(),
            serde_json::json!(crate::x402::wire::challenge_network(challenge)),
        );
        if matches!(verification.leg, SettlementLeg::Foreign) {
            extra.insert(
                "payer".to_string(),
                serde_json::json!(credential.payer_address),
            );
        }
        extra.insert("scheme".to_string(), serde_json::json!(scheme_id));

        Ok(PaymentReceipt {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            protocol: "x402".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            credential_id: verification.credential_id.clone(),
            amount: verification.amount,
            asset: challenge.asset.clone(),
            settlement_tx,
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
        crate::payer_auth::sign_credential(
            challenge,
            "x402",
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

    async fn stamped(server: &X402PaymentServer, amount: u128) -> PaymentChallenge {
        let mut ch = server
            .create_challenge("/api/resource", amount, "TNZO", PAYEE)
            .await
            .unwrap();
        ch.extra.insert(
            crate::payer_auth::CHAIN_ID_KEY.to_string(),
            serde_json::json!(1337u64),
        );
        ch
    }

    #[tokio::test]
    async fn challenges_name_the_tenzro_network_by_chain_id() {
        let server = X402PaymentServer::new(
            4242,
            vec!["tenzro".to_string()],
            std::sync::Arc::new(crate::test_support::SeedKeys),
        );
        let ch = server
            .create_challenge("/api/resource", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        assert_eq!(ch.extra.get("network").unwrap(), "tenzro:4242");
        assert_eq!(ch.extra.get("scheme").unwrap(), crate::x402::DEFAULT_SCHEME);
    }

    #[tokio::test]
    async fn a_signed_credential_verifies_to_a_payer_leg() {
        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            std::sync::Arc::new(crate::test_support::SeedKeys),
        );
        let ch = stamped(&server, 1234).await;
        let cred = server.create_credential(&ch, "", &signer()).await.unwrap();
        let v = server.verify_credential(&ch, &cred).await.unwrap();
        assert!(matches!(v.leg, SettlementLeg::Payer(_)));
        assert_eq!(v.amount, 1234);
    }

    #[tokio::test]
    async fn a_credential_for_another_challenge_is_refused() {
        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            std::sync::Arc::new(crate::test_support::SeedKeys),
        );
        let a = stamped(&server, 10).await;
        let b = stamped(&server, 10).await;
        let cred = server.create_credential(&a, "", &signer()).await.unwrap();
        assert!(server.verify_credential(&b, &cred).await.is_err());
    }

    #[tokio::test]
    async fn an_unknown_scheme_is_refused() {
        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            std::sync::Arc::new(crate::test_support::SeedKeys),
        );
        let mut ch = stamped(&server, 10).await;
        ch.extra.insert(
            "scheme".to_string(),
            serde_json::json!("definitely-not-real"),
        );
        let cred = server.create_credential(&ch, "", &signer()).await.unwrap();
        assert!(matches!(
            server.verify_credential(&ch, &cred).await,
            Err(PaymentError::VerificationFailed(_))
        ));
    }

    #[tokio::test]
    async fn a_ledger_payment_receipt_carries_no_settlement_until_the_gateway_settles() {
        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            std::sync::Arc::new(crate::test_support::SeedKeys),
        );
        let ch = stamped(&server, 55).await;
        let cred = server.create_credential(&ch, "", &signer()).await.unwrap();
        let v = server.verify_credential(&ch, &cred).await.unwrap();
        let receipt = server.settle(&ch, &cred, &v).await.unwrap();
        assert_eq!(receipt.amount, 55);
        assert!(receipt.settlement_tx.is_none());
    }

    #[tokio::test]
    async fn a_metered_server_charges_what_its_meter_signed() {
        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            std::sync::Arc::new(crate::test_support::SeedKeys),
        )
        .with_scheme(crate::x402::UPTO_SCHEME)
        .with_meter_signer(Arc::new(signer()));
        let ch = stamped(&server, 5_000).await;
        assert!(ch.extra.contains_key(crate::metering::METER_KEY));
        let mut cred =
            crate::payer_auth::sign_credential(&ch, "x402", "", &signer(), 1, 5_000).unwrap();
        // Unmetered, nothing can be charged.
        assert!(server.verify_credential(&ch, &cred).await.is_err());
        server
            .meter(
                &ch,
                &mut cred,
                vec![crate::metering::UsageLine {
                    unit: "output_tokens".into(),
                    quantity: 7,
                    unit_price: 100,
                }],
            )
            .unwrap();
        let v = server.verify_credential(&ch, &cred).await.unwrap();
        assert_eq!(v.amount, 700);
    }

    #[tokio::test]
    async fn signed_offers_ride_on_the_challenge() {
        let server = X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            std::sync::Arc::new(crate::test_support::SeedKeys),
        )
        .with_offer_signer(Arc::new(signer()));
        let ch = server
            .create_challenge("/api/paid", 1000, "TNZO", PAYEE)
            .await
            .unwrap();
        for key in [
            crate::x402::offer::OFFER_COMMITMENT_KEY,
            crate::x402::offer::OFFER_SIG_KEY,
            crate::x402::offer::OFFER_SIGNER_KEY,
        ] {
            assert!(ch.extra.contains_key(key), "missing {key}");
        }
    }
}
