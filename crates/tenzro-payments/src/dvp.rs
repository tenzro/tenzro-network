//! Delivery versus payment for HTTP-402 responses.
//!
//! The seller encrypts the response under a fresh content key and hands the
//! buyer the ciphertext with the SHA-256 of the key, signed together with the
//! resource and price as a [`SealedDelivery`]. The buyer funds two escrows
//! locked by that hash
//! ([`ReleaseConditions::HashLock`](tenzro_types::settlement::ReleaseConditions::HashLock)):
//! one to the seller for the price less the network share, and one to the
//! network treasury for the share, as every HTTP-402 payment carries it. The
//! seller is paid only by submitting `ClaimEscrowPreimage` with the key,
//! which publishes it on the ledger, so payment and the buyer's ability to
//! decrypt are one event; the published key then opens the treasury's escrow
//! too. If the seller never claims, the buyer refunds both escrows after they
//! expire.
//!
//! The seller's signature over the ciphertext hash is its statement of what
//! it delivered: a buyer who decrypts something other than what was offered
//! holds a signed record of it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::batch::{RecordSignature, RecordSigner};
use tenzro_crypto::composite::{CompositePublicKey, SignatureContext, message_representative};
use tenzro_crypto::encryption::SymmetricKey;

use crate::error::{PaymentError, Result};

/// Domain tag of a delivery statement.
pub const DELIVERY_DOMAIN: &str = "tenzro/dvp/delivery";

/// An encrypted response and the seller's statement of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDelivery {
    /// The resource delivered.
    pub resource: String,
    /// AES-256-GCM ciphertext of the response (hex, nonce first).
    pub ciphertext: String,
    /// SHA-256 of the ciphertext (hex).
    pub content_hash: String,
    /// SHA-256 of the content key (hex): the escrow's lock.
    pub key_hash: String,
    /// Price, in the asset's smallest unit.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub price: u128,
    /// Asset.
    pub asset: String,
    /// The seller's account, the escrow's payee (hex).
    pub payee: String,
    /// The part of the price that is the network's share, paid by a second
    /// escrow under the same lock.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub network_share: u128,
    /// The network treasury, that escrow's payee (hex).
    pub network_payee: String,
    /// The seller's hardware identity key.
    pub seller_key: CompositePublicKey,
    /// Signature over [`SealedDelivery::statement`] (in the `DvpDelivery`
    /// context) by a session key that `seller_key` certified.
    pub signature: RecordSignature,
}

fn refuse(why: impl Into<String>) -> PaymentError {
    PaymentError::VerificationFailed(format!("delivery: {}", why.into()))
}

/// The domain tag followed by each field, length-prefixed.
fn statement(fields: &[&[u8]]) -> Vec<u8> {
    let mut m = DELIVERY_DOMAIN.as_bytes().to_vec();
    for f in fields {
        m.extend_from_slice(&(f.len() as u32).to_le_bytes());
        m.extend_from_slice(f);
    }
    m
}

/// What the session key signs: the statement's representative in the
/// delivery context, so the signature cannot be read under another context.
fn representative(statement: &[u8]) -> Vec<u8> {
    message_representative(SignatureContext::DvpDelivery, statement)
}

impl SealedDelivery {
    /// The bytes the seller signs.
    pub fn statement(&self) -> Vec<u8> {
        statement(&[
            self.resource.as_bytes(),
            self.content_hash.as_bytes(),
            self.key_hash.as_bytes(),
            &self.price.to_le_bytes(),
            self.asset.as_bytes(),
            self.payee.as_bytes(),
            &self.network_share.to_le_bytes(),
            self.network_payee.as_bytes(),
            &self.seller_key.p256,
            self.seller_key.pq.as_deref().unwrap_or_default(),
        ])
    }

    /// Encrypt `body` for sale at `price` of `asset` to be paid to `payee`,
    /// signing the statement with the seller's session signer. Returns the
    /// delivery and the content key the seller claims the escrow with.
    pub fn seal(
        resource: &str,
        body: &[u8],
        price: u128,
        asset: &str,
        payee: &str,
        network_share_bps: u64,
        signer: &dyn RecordSigner,
    ) -> Result<(Self, [u8; 32])> {
        let key = SymmetricKey::generate();
        let ciphertext = key
            .encrypt(body)
            .map_err(|e| PaymentError::CryptoError(format!("sealing: {e}")))?;
        let content_hash = hex::encode(Sha256::digest(&ciphertext));
        let key_hash = hex::encode(Sha256::digest(key.as_bytes()));
        let network_share = Self::share_of(price, network_share_bps);
        let network_payee = hex::encode(tenzro_types::network_treasury_address().as_bytes());
        let seller_key = signer.identity().clone();
        let statement = statement(&[
            resource.as_bytes(),
            content_hash.as_bytes(),
            key_hash.as_bytes(),
            &price.to_le_bytes(),
            asset.as_bytes(),
            payee.as_bytes(),
            &network_share.to_le_bytes(),
            network_payee.as_bytes(),
            &seller_key.p256,
            seller_key.pq.as_deref().unwrap_or_default(),
        ]);
        let signature = signer
            .sign_record(&representative(&statement))
            .map_err(|e| PaymentError::CryptoError(format!("delivery signing: {e}")))?;
        let delivery = Self {
            resource: resource.to_string(),
            content_hash,
            ciphertext: hex::encode(&ciphertext),
            key_hash,
            price,
            asset: asset.to_string(),
            payee: payee.to_string(),
            network_share,
            network_payee,
            seller_key,
            signature,
        };
        Ok((delivery, key.to_bytes()))
    }

    /// Check the seller's signature and that the ciphertext is the one it
    /// signed for.
    pub fn verify(&self) -> Result<()> {
        let ciphertext =
            hex::decode(&self.ciphertext).map_err(|_| refuse("ciphertext is not hex"))?;
        if hex::encode(Sha256::digest(&ciphertext)) != self.content_hash {
            return Err(refuse("the ciphertext is not the one signed for"));
        }
        self.signature
            .verify_now(&self.seller_key, &representative(&self.statement()))
            .map_err(|_| refuse("the seller's signature does not verify"))
    }

    /// The network's share of `price` at the governed `network_share_bps`.
    pub fn share_of(price: u128, network_share_bps: u64) -> u128 {
        price.saturating_mul(u128::from(network_share_bps.min(10_000))) / 10_000
    }

    /// What the seller's escrow must hold: the price less the network share.
    pub fn seller_amount(&self) -> u128 {
        self.price.saturating_sub(self.network_share)
    }

    /// The escrow lock a buyer funds against.
    pub fn lock(&self) -> Result<[u8; 32]> {
        let bytes = hex::decode(&self.key_hash).map_err(|_| refuse("key hash is not hex"))?;
        bytes
            .try_into()
            .map_err(|_| refuse("key hash is not 32 bytes"))
    }

    /// Check that `seller` and, when the network is owed a share, `network`
    /// are funded escrows locked by this delivery's key hash that pay
    /// `payee` the price less the share and the treasury the share, and
    /// outlive `now_ms` by `margin_ms`. Returns the lock.
    pub fn check_locked(
        &self,
        payee: &tenzro_types::Address,
        seller: &crate::mpp::EscrowView,
        network: Option<&crate::mpp::EscrowView>,
        now_ms: i64,
        margin_ms: i64,
    ) -> std::result::Result<[u8; 32], String> {
        let lock = self.lock().map_err(|e| e.to_string())?;
        if seller.hash_lock() != Some(lock) {
            return Err(
                "the seller's escrow is not locked by this delivery's key hash".to_string(),
            );
        }
        seller
            .pays(payee, self.seller_amount(), now_ms, margin_ms)
            .map_err(|e| format!("the seller's escrow {e}"))?;
        if self.network_share > 0 {
            let network =
                network.ok_or("the network's share needs its own escrow under the same lock")?;
            if network.hash_lock() != Some(lock) {
                return Err("the network's escrow is locked by another hash".to_string());
            }
            network
                .pays(
                    &tenzro_types::network_treasury_address(),
                    self.network_share,
                    now_ms,
                    margin_ms,
                )
                .map_err(|e| format!("the network's escrow {e}"))?;
        }
        Ok(lock)
    }

    /// Decrypt with the key the seller's claim published.
    pub fn open(&self, key: &[u8]) -> Result<Vec<u8>> {
        if hex::encode(Sha256::digest(key)) != self.key_hash {
            return Err(refuse("the key does not open this delivery's lock"));
        }
        let key = SymmetricKey::from_bytes(key).map_err(|e| refuse(e.to_string()))?;
        let ciphertext =
            hex::decode(&self.ciphertext).map_err(|_| refuse("ciphertext is not hex"))?;
        key.decrypt(&ciphertext)
            .map_err(|_| refuse("the ciphertext does not decrypt under the published key"))
    }
}

/// The content key revealed by an `EscrowPreimageRevealed` log
/// (`escrow_id(32) ‖ payee(32) ‖ payout(16) ‖ preimage`).
pub fn revealed_key(log_data: &[u8]) -> Option<&[u8]> {
    log_data.get(80..).filter(|k| !k.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> tenzro_crypto::batch::ImmediateRecordSigner {
        tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::random()))
    }

    #[test]
    fn the_buyer_reads_the_response_only_with_the_locked_key() {
        let seller = signer();
        let (d, key) =
            SealedDelivery::seal("/paid", b"the answer", 700, "TNZO", "0909", 1_000, &seller)
                .unwrap();
        d.verify().unwrap();
        assert_eq!(d.lock().unwrap(), <[u8; 32]>::from(Sha256::digest(key)));
        assert_eq!(d.open(&key).unwrap(), b"the answer");
        assert!(d.open(&[7u8; 32]).is_err());
    }

    #[test]
    fn a_tampered_delivery_fails_its_statement() {
        let seller = signer();
        let (mut d, _) =
            SealedDelivery::seal("/paid", b"x", 1, "TNZO", "0909", 1_000, &seller).unwrap();
        d.price = 2;
        assert!(d.verify().is_err());
        let (mut d, _) =
            SealedDelivery::seal("/paid", b"x", 1_000, "TNZO", "0909", 1_000, &seller).unwrap();
        assert_eq!(d.network_share, 100);
        assert_eq!(d.seller_amount(), 900);
        d.network_share = 0;
        assert!(d.verify().is_err());
        let (mut d, _) =
            SealedDelivery::seal("/paid", b"x", 1, "TNZO", "0909", 1_000, &seller).unwrap();
        d.ciphertext = hex::encode([0u8; 40]);
        assert!(d.verify().is_err());
        // A delivery naming a seller key that did not certify the session key.
        let (mut d, _) =
            SealedDelivery::seal("/paid", b"x", 1, "TNZO", "0909", 1_000, &seller).unwrap();
        d.seller_key = signer().identity().clone();
        assert!(d.verify().is_err());
    }

    #[test]
    fn the_key_is_read_from_the_claim_log() {
        let mut log = vec![0u8; 80];
        log.extend_from_slice(&[9u8; 32]);
        assert_eq!(revealed_key(&log), Some(&[9u8; 32][..]));
        assert_eq!(revealed_key(&[0u8; 80]), None);
    }

    #[test]
    fn a_delivery_signed_in_a_hardware_batch_verifies_and_an_old_reader_refuses_it() {
        use tenzro_crypto::batch::{BatchParams, BatchRecordSigner, BatchService};
        let id: std::sync::Arc<dyn tenzro_crypto::composite::HybridSigner> = std::sync::Arc::new(
            tenzro_crypto::composite::testing::TestHybridSigner::hybrid(21),
        );
        let service = std::sync::Arc::new(
            BatchService::new(
                id,
                BatchParams {
                    max_batch: 1,
                    flush_interval_ms: 1_000,
                },
                0,
            )
            .unwrap(),
        );
        let seller = BatchRecordSigner::new(service, std::time::Duration::from_millis(200));
        let (d, key) =
            SealedDelivery::seal("/paid", b"the answer", 700, "TNZO", "0909", 1_000, &seller)
                .unwrap();
        d.verify().unwrap();
        assert_eq!(d.open(&key).unwrap(), b"the answer");
        let json = serde_json::to_vec(&d).unwrap();
        let again: SealedDelivery = serde_json::from_slice(&json).unwrap();
        again.verify().unwrap();
        let mut tampered = again.clone();
        tampered.price = 1;
        assert!(tampered.verify().is_err());
    }
}
