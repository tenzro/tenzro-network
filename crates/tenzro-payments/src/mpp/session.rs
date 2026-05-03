//! MPP Session management for streaming micropayments
//!
//! Sessions wrap the existing MicropaymentChannel infrastructure from
//! tenzro-settlement, providing MPP-compatible session semantics.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::kv::{KvStore, CF_CHANNELS};
use tracing::{debug, info, warn};

/// A signed voucher for incremental payment within an MPP session
///
/// Wave 3d hybrid signing: every voucher carries BOTH classical (Ed25519)
/// and post-quantum (ML-DSA-65) signatures, plus the corresponding public
/// keys. Verification fails closed if either leg is missing or invalid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppVoucher {
    /// Session ID this voucher belongs to
    pub session_id: String,
    /// Cumulative amount spent (not incremental)
    pub cumulative_amount: u128,
    /// Monotonic nonce to prevent replay
    pub nonce: u64,
    /// Classical Ed25519 signature over `message_bytes()` by the payer
    pub signature: Vec<u8>,
    /// Payer's classical Ed25519 public key (32 bytes)
    pub public_key: Vec<u8>,
    /// Post-quantum ML-DSA-65 signature over `message_bytes()` (3309 bytes)
    pub pq_signature: Vec<u8>,
    /// Payer's ML-DSA-65 verifying key (1952 bytes)
    pub pq_public_key: Vec<u8>,
}

impl MppVoucher {
    /// Constructs the message bytes that should be signed
    pub fn message_bytes(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.session_id.as_bytes());
        msg.extend_from_slice(&self.cumulative_amount.to_le_bytes());
        msg.extend_from_slice(&self.nonce.to_le_bytes());
        msg
    }

    /// Verifies the voucher signature (hybrid: both classical and PQ legs
    /// must validate over the same canonical message).
    pub fn verify(&self) -> bool {
        let message = self.message_bytes();
        let composite_pk = tenzro_crypto::composite::CompositePublicKey::new(
            tenzro_crypto::keys::PublicKey::new(
                tenzro_crypto::keys::KeyType::Ed25519,
                self.public_key.clone(),
            ),
            Some(self.pq_public_key.clone()),
        );
        let composite_sig = tenzro_crypto::composite::CompositeSignature::new(
            self.signature.clone(),
            Some(self.pq_signature.clone()),
        );
        let verifier = tenzro_crypto::composite::StandardHybridVerifier::new(composite_pk);
        use tenzro_crypto::composite::HybridVerifier;
        verifier.verify(&message, &composite_sig).is_ok()
    }
}

/// An MPP session for streaming micropayments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppSession {
    /// Session ID
    pub session_id: String,
    /// Payer DID
    pub payer_did: String,
    /// Recipient address
    pub recipient: String,
    /// Total deposited into session
    pub total_deposit: u128,
    /// Total spent so far
    pub total_spent: u128,
    /// Asset
    pub asset: String,
    /// Session state
    pub state: MppSessionState,
    /// Last voucher nonce for replay protection (must be monotonically increasing)
    pub last_voucher_nonce: u64,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Last activity
    pub last_activity: DateTime<Utc>,
}

/// State of an MPP session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MppSessionState {
    /// Session is open and accepting vouchers
    Open,
    /// Session is closing (final settlement in progress)
    Closing,
    /// Session is closed
    Closed,
}

/// Key prefix for MPP sessions in CF_CHANNELS
const SESSION_KEY_PREFIX: &str = "mpp-session:";

/// Manager for MPP sessions with optional RocksDB persistence (MEDIUM #127)
pub struct MppSessionManager {
    sessions: DashMap<String, MppSession>,
    /// Optional persistent storage — when set, every mutation is written through
    storage: Option<Arc<dyn KvStore>>,
}

impl MppSessionManager {
    /// Creates a new session manager (in-memory only)
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            storage: None,
        }
    }

    /// Creates a session manager backed by persistent storage.
    ///
    /// On construction, hydrates all existing sessions from `CF_CHANNELS`
    /// using the `mpp-session:` key prefix. Every subsequent mutation
    /// (open, voucher, close) is written through to storage.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let sessions = DashMap::new();

        // Hydrate sessions from persistent storage
        match storage.get_keys_with_prefix(CF_CHANNELS, SESSION_KEY_PREFIX.as_bytes()) {
            Ok(keys) => {
                let mut loaded = 0usize;
                for key in &keys {
                    if let Ok(Some(bytes)) = storage.get(CF_CHANNELS, key) {
                        match serde_json::from_slice::<MppSession>(&bytes) {
                            Ok(session) => {
                                sessions.insert(session.session_id.clone(), session);
                                loaded += 1;
                            }
                            Err(e) => {
                                warn!("Failed to deserialize MPP session from storage: {}", e);
                            }
                        }
                    }
                }
                if loaded > 0 {
                    info!("Loaded {} MPP sessions from storage", loaded);
                }
            }
            Err(e) => {
                warn!("Failed to load MPP sessions from storage: {}", e);
            }
        }

        Self {
            sessions,
            storage: Some(storage),
        }
    }

    /// Persists a session to storage (write-through)
    fn persist_session(&self, session: &MppSession) {
        if let Some(ref store) = self.storage {
            let key = format!("{}{}", SESSION_KEY_PREFIX, session.session_id);
            match serde_json::to_vec(session) {
                Ok(bytes) => {
                    if let Err(e) = store.put(CF_CHANNELS, key.as_bytes(), &bytes) {
                        warn!("Failed to persist MPP session {}: {}", session.session_id, e);
                    }
                }
                Err(e) => {
                    warn!("Failed to serialize MPP session {}: {}", session.session_id, e);
                }
            }
        }
    }

    /// Opens a new MPP session
    pub fn open_session(
        &self,
        payer_did: impl Into<String>,
        recipient: impl Into<String>,
        deposit: u128,
        asset: impl Into<String>,
    ) -> MppSession {
        let session = MppSession {
            session_id: uuid::Uuid::new_v4().to_string(),
            payer_did: payer_did.into(),
            recipient: recipient.into(),
            total_deposit: deposit,
            total_spent: 0,
            asset: asset.into(),
            state: MppSessionState::Open,
            last_voucher_nonce: 0,
            created_at: Utc::now(),
            last_activity: Utc::now(),
        };

        info!("Opened MPP session: {}", session.session_id);
        self.persist_session(&session);
        self.sessions
            .insert(session.session_id.clone(), session.clone());
        session
    }

    /// Processes a signed voucher with full cryptographic verification
    ///
    /// Verifies:
    /// 1. Session exists and is open
    /// 2. Voucher signature is valid
    /// 3. Voucher session_id matches
    /// 4. Nonce is strictly greater than last seen nonce (replay protection)
    /// 5. Cumulative amount does not exceed deposit
    /// 6. Cumulative amount is monotonically non-decreasing
    pub fn process_voucher_verified(
        &self,
        voucher: &MppVoucher,
    ) -> crate::error::Result<u128> {
        // 1. Verify signature first (before any state changes)
        if !voucher.verify() {
            return Err(crate::error::PaymentError::VerificationFailed("voucher signature verification failed".to_string()));
        }

        let mut session = self
            .sessions
            .get_mut(&voucher.session_id)
            .ok_or_else(|| crate::error::PaymentError::SessionError(format!("session not found: {}", voucher.session_id)))?;

        // 2. Check session is open
        if session.state != MppSessionState::Open {
            return Err(crate::error::PaymentError::SessionError("session is not open".to_string()));
        }

        // 3. Check nonce is strictly monotonically increasing (replay protection)
        if voucher.nonce <= session.last_voucher_nonce {
            return Err(crate::error::PaymentError::ReplayDetected(format!(
                "voucher nonce {} is not greater than last seen nonce {}",
                voucher.nonce, session.last_voucher_nonce
            )));
        }

        // 4. Cumulative amount must be >= current total (no rollback)
        if voucher.cumulative_amount < session.total_spent {
            return Err(crate::error::PaymentError::SessionError(format!(
                "cumulative amount {} is less than current total {}",
                voucher.cumulative_amount, session.total_spent
            )));
        }

        // 5. Check cumulative amount doesn't exceed deposit
        if voucher.cumulative_amount > session.total_deposit {
            return Err(crate::error::PaymentError::InsufficientFunds("voucher cumulative amount exceeds session deposit".to_string()));
        }

        debug!(
            "Verified voucher for session {}: cumulative={}, nonce={}",
            voucher.session_id, voucher.cumulative_amount, voucher.nonce
        );

        session.total_spent = voucher.cumulative_amount;
        session.last_voucher_nonce = voucher.nonce;
        session.last_activity = Utc::now();
        let total = session.total_spent;
        self.persist_session(&session);
        Ok(total)
    }

    /// Closes a session and returns the final balance
    pub fn close_session(&self, session_id: &str) -> crate::error::Result<MppSession> {
        let mut session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| crate::error::PaymentError::SessionError(format!("session not found: {}", session_id)))?;

        session.state = MppSessionState::Closed;
        session.last_activity = Utc::now();
        info!(
            "Closed MPP session: {} (spent: {}/{})",
            session_id, session.total_spent, session.total_deposit
        );
        let closed = session.clone();
        self.persist_session(&closed);
        Ok(closed)
    }

    /// Gets a session by ID
    pub fn get_session(&self, session_id: &str) -> Option<MppSession> {
        self.sessions.get(session_id).map(|s| s.clone())
    }
}

impl Default for MppSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::Ed25519SignerImpl;

    /// Helper bundle holding both signing legs for the hybrid voucher path.
    struct TestVoucherKeys {
        priv_bytes: Vec<u8>,
        pub_bytes: Vec<u8>,
        pq_seed: Vec<u8>,
        pq_pub_bytes: Vec<u8>,
    }

    /// Helper to build a hybrid-signed voucher for tests.
    fn signed_voucher(
        keys: &TestVoucherKeys,
        session_id: &str,
        cumulative_amount: u128,
        nonce: u64,
    ) -> MppVoucher {
        let mut msg = Vec::new();
        msg.extend_from_slice(session_id.as_bytes());
        msg.extend_from_slice(&cumulative_amount.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());

        let kp =
            KeyPair::from_bytes(KeyType::Ed25519, &keys.priv_bytes).expect("from_bytes");
        let classical = Ed25519SignerImpl::new(kp).expect("signer");
        let pq = MlDsaSigningKey::from_seed(&keys.pq_seed).expect("pq from_seed");
        let hybrid = InMemoryHybridSigner::new(Box::new(classical), pq);
        let composite = hybrid.sign(&msg).expect("hybrid sign");

        MppVoucher {
            session_id: session_id.to_string(),
            cumulative_amount,
            nonce,
            signature: composite.classical,
            public_key: keys.pub_bytes.clone(),
            pq_signature: composite.pq.unwrap_or_default(),
            pq_public_key: keys.pq_pub_bytes.clone(),
        }
    }

    fn test_keys() -> TestVoucherKeys {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let priv_bytes = kp.to_bytes();
        let pub_bytes = kp.public_key().to_bytes();
        let pq = MlDsaSigningKey::generate();
        let pq_seed = pq.seed_bytes().to_vec();
        let pq_pub_bytes = pq.verifying_key_bytes().to_vec();
        TestVoucherKeys {
            priv_bytes,
            pub_bytes,
            pq_seed,
            pq_pub_bytes,
        }
    }

    #[test]
    fn test_session_lifecycle() {
        let manager = MppSessionManager::new();
        let keys = test_keys();

        let session = manager.open_session("did:tenzro:human:alice", "0xrecipient", 1000, "USDC");
        assert_eq!(session.state, MppSessionState::Open);

        let v1 = signed_voucher(&keys, &session.session_id, 100, 1);
        let total = manager.process_voucher_verified(&v1).unwrap();
        assert_eq!(total, 100);

        let v2 = signed_voucher(&keys, &session.session_id, 300, 2);
        let total = manager.process_voucher_verified(&v2).unwrap();
        assert_eq!(total, 300);

        let closed = manager.close_session(&session.session_id).unwrap();
        assert_eq!(closed.state, MppSessionState::Closed);
        assert_eq!(closed.total_spent, 300);
    }

    #[test]
    fn test_voucher_exceeds_deposit() {
        let manager = MppSessionManager::new();
        let keys = test_keys();
        let session = manager.open_session("payer", "recipient", 100, "USDC");

        let v = signed_voucher(&keys, &session.session_id, 150, 1);
        let result = manager.process_voucher_verified(&v);
        assert!(matches!(
            result,
            Err(crate::error::PaymentError::InsufficientFunds(_))
        ));
    }

    #[test]
    fn test_verified_voucher_nonce_replay_rejected() {
        let manager = MppSessionManager::new();
        let keys = test_keys();
        let session = manager.open_session("payer", "recipient", 1000, "USDC");

        // First voucher at nonce=1 succeeds.
        let v1 = signed_voucher(&keys, &session.session_id, 100, 1);
        manager.process_voucher_verified(&v1).unwrap();

        let s = manager.get_session(&session.session_id).unwrap();
        assert_eq!(s.last_voucher_nonce, 1);
        assert_eq!(s.total_spent, 100);

        // Replay of nonce=1 must be rejected.
        let v1_replay = signed_voucher(&keys, &session.session_id, 200, 1);
        let result = manager.process_voucher_verified(&v1_replay);
        assert!(matches!(
            result,
            Err(crate::error::PaymentError::ReplayDetected(_))
        ));

        // Lower nonce (0) must also be rejected.
        let v0 = signed_voucher(&keys, &session.session_id, 200, 0);
        let result = manager.process_voucher_verified(&v0);
        assert!(matches!(
            result,
            Err(crate::error::PaymentError::ReplayDetected(_))
        ));
    }

    #[test]
    fn test_voucher_message_bytes() {
        let voucher = MppVoucher {
            session_id: "test-session".to_string(),
            cumulative_amount: 500,
            nonce: 3,
            signature: vec![],
            public_key: vec![],
            pq_signature: vec![],
            pq_public_key: vec![],
        };

        let msg = voucher.message_bytes();
        // session_id bytes + 16 bytes (u128) + 8 bytes (u64)
        assert_eq!(msg.len(), "test-session".len() + 16 + 8);
    }
}
