//! Cortex worker gossipsub advertisement.
//!
//! Workers periodically publish a signed [`CortexAdvertisement`] on the
//! `tenzro/cortex` topic so that other nodes can discover remote
//! Cortex workers without needing to register them via RPC.
//!
//! The broadcasting transport is plugable via [`CortexGossipPublisher`];
//! `tenzro-node` provides an adapter that wraps the existing libp2p
//! gossipsub `NetworkService`.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_crypto::{
    keys::{KeyType, PublicKey},
    signatures::{verify, Signature as CryptoSignature, Signer},
};
use tenzro_types::{
    cortex::{CortexModelFamily, CortexPricing},
    primitives::Address,
};

use crate::error::{CortexError, Result};

/// Gossipsub topic used for Cortex worker advertisements.
pub const CORTEX_TOPIC: &str = "tenzro/cortex";

/// Default lifetime for an advertisement, in seconds.
pub const DEFAULT_ADVERT_TTL_SECS: u64 = 90;

/// Default interval between re-broadcasts, in seconds.
pub const DEFAULT_ADVERT_INTERVAL_SECS: u64 = 30;

/// Signed advertisement announcing a Cortex worker's capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CortexAdvertisement {
    /// Stable worker DID (`did:tenzro:machine:<id>`).
    pub worker_did: String,
    /// On-chain settlement address for the worker.
    pub worker_address: Address,
    /// Model identifier this worker serves.
    pub model_id: String,
    /// Family / capability metadata (MoE, attention, max loops).
    pub family: CortexModelFamily,
    /// Pricing schedule applied by this worker.
    pub pricing: CortexPricing,
    /// Public HTTP / JSON-RPC endpoint for clients to hit
    /// (e.g. `https://worker.example:8545`). Optional.
    pub endpoint: Option<String>,
    /// UNIX seconds timestamp at which this advertisement was signed.
    pub issued_at: u64,
    /// UNIX seconds timestamp after which this advertisement is stale.
    pub expires_at: u64,
    /// Worker's Ed25519 public key bytes (32B).
    pub public_key: Vec<u8>,
    /// Ed25519 signature over the canonical preimage
    /// (everything above this field, serialized in declaration order).
    pub signature: Vec<u8>,
}

/// Canonical preimage for signing / verifying an advertisement.
#[derive(Serialize)]
struct AdvertPreimage<'a> {
    worker_did: &'a str,
    worker_address: &'a Address,
    model_id: &'a str,
    family: &'a CortexModelFamily,
    pricing: &'a CortexPricing,
    endpoint: Option<&'a str>,
    issued_at: u64,
    expires_at: u64,
    public_key: &'a [u8],
}

impl CortexAdvertisement {
    /// Build and sign an advertisement.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        signer: &dyn Signer,
        worker_did: impl Into<String>,
        worker_address: Address,
        model_id: impl Into<String>,
        family: CortexModelFamily,
        pricing: CortexPricing,
        endpoint: Option<String>,
        ttl_secs: u64,
    ) -> Result<Self> {
        let now = now_secs();
        let expires_at = now.saturating_add(ttl_secs);
        let public_key = signer.public_key().as_bytes().to_vec();
        let worker_did: String = worker_did.into();
        let model_id: String = model_id.into();

        let preimage = serde_json::to_vec(&AdvertPreimage {
            worker_did: &worker_did,
            worker_address: &worker_address,
            model_id: &model_id,
            family: &family,
            pricing: &pricing,
            endpoint: endpoint.as_deref(),
            issued_at: now,
            expires_at,
            public_key: &public_key,
        })
        .map_err(CortexError::Serde)?;

        let sig = signer
            .sign(&preimage)
            .map_err(|e| CortexError::Crypto(e.to_string()))?;

        Ok(Self {
            worker_did,
            worker_address,
            model_id,
            family,
            pricing,
            endpoint,
            issued_at: now,
            expires_at,
            public_key,
            signature: sig.as_bytes().to_vec(),
        })
    }

    /// Verify the signature against the embedded public key.
    pub fn verify(&self) -> Result<()> {
        let preimage = serde_json::to_vec(&AdvertPreimage {
            worker_did: &self.worker_did,
            worker_address: &self.worker_address,
            model_id: &self.model_id,
            family: &self.family,
            pricing: &self.pricing,
            endpoint: self.endpoint.as_deref(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            public_key: &self.public_key,
        })
        .map_err(CortexError::Serde)?;

        let pk = PublicKey::new(KeyType::Ed25519, self.public_key.clone());
        let sig = CryptoSignature::new(KeyType::Ed25519, self.signature.clone());

        verify(&pk, &preimage, &sig).map_err(|e| CortexError::InvalidReceipt(e.to_string()))
    }

    /// Returns true if this advertisement has expired relative to the
    /// current wall clock.
    pub fn is_expired(&self) -> bool {
        now_secs() > self.expires_at
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Transport abstraction over gossipsub publishing.
///
/// `tenzro-node` provides a wrapper around its libp2p `NetworkService`;
/// tests can pass a no-op or a spy.
#[async_trait]
pub trait CortexGossipPublisher: Send + Sync {
    async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<()>;
}

/// In-memory registry of remote Cortex workers discovered via gossipsub.
///
/// Nodes keep a live view of peer workers here so routing/RPC can
/// surface them via `tenzro_listRemoteCortexWorkers`. Expired entries
/// are evicted lazily on read.
#[derive(Default)]
pub struct RemoteWorkerRegistry {
    inner: DashMap<String, CortexAdvertisement>,
}

impl RemoteWorkerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest an advertisement received from a peer. Verifies the
    /// signature and upserts the entry keyed by `worker_did::model_id`.
    pub fn ingest(&self, ad: CortexAdvertisement) -> Result<()> {
        ad.verify()?;
        if ad.is_expired() {
            return Err(CortexError::WorkerRejected(
                "advertisement expired".into(),
            ));
        }
        let key = format!("{}::{}", ad.worker_did, ad.model_id);
        self.inner.insert(key, ad);
        Ok(())
    }

    /// Snapshot of all currently-live advertisements (expired entries
    /// are pruned here).
    pub fn snapshot(&self) -> Vec<CortexAdvertisement> {
        let now = now_secs();
        let expired: Vec<String> = self
            .inner
            .iter()
            .filter(|e| e.value().expires_at < now)
            .map(|e| e.key().clone())
            .collect();
        for k in expired {
            self.inner.remove(&k);
        }
        self.inner.iter().map(|e| e.value().clone()).collect()
    }

    /// Number of currently-tracked advertisements (includes stale;
    /// callers should snapshot for clean data).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Helper bundling a signer + publisher so the node can spawn a loop
/// that periodically broadcasts advertisements.
pub struct AdvertisementBroadcaster {
    pub publisher: Arc<dyn CortexGossipPublisher>,
    pub signer: Arc<dyn Signer + Send + Sync>,
    pub worker_did: String,
    pub worker_address: Address,
    pub model_id: String,
    pub family: CortexModelFamily,
    pub pricing: CortexPricing,
    pub endpoint: Option<String>,
    pub ttl_secs: u64,
}

impl AdvertisementBroadcaster {
    /// Build, sign, and publish one advertisement.
    pub async fn broadcast_once(&self) -> Result<()> {
        let ad = CortexAdvertisement::sign(
            &*self.signer,
            self.worker_did.clone(),
            self.worker_address,
            self.model_id.clone(),
            self.family.clone(),
            self.pricing,
            self.endpoint.clone(),
            self.ttl_secs,
        )?;
        let bytes = serde_json::to_vec(&ad).map_err(CortexError::Serde)?;
        self.publisher.publish(CORTEX_TOPIC, bytes).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::signatures::Ed25519SignerImpl;

    fn test_signer() -> Ed25519SignerImpl {
        Ed25519SignerImpl::generate().unwrap()
    }

    #[test]
    fn advertisement_signs_and_verifies() {
        let signer = test_signer();
        let ad = CortexAdvertisement::sign(
            &signer,
            "did:tenzro:machine:test",
            Address::default(),
            "mythos-3b",
            CortexModelFamily::default(),
            CortexPricing::default(),
            Some("https://worker.example:8545".into()),
            60,
        )
        .unwrap();
        ad.verify().unwrap();
        assert!(!ad.is_expired());
    }

    #[test]
    fn tampered_advertisement_fails_verify() {
        let signer = test_signer();
        let mut ad = CortexAdvertisement::sign(
            &signer,
            "did:tenzro:machine:test",
            Address::default(),
            "mythos-3b",
            CortexModelFamily::default(),
            CortexPricing::default(),
            None,
            60,
        )
        .unwrap();
        // Tamper with price.
        ad.pricing.price_per_loop_wei = 999_999;
        assert!(ad.verify().is_err());
    }

    #[test]
    fn registry_ingests_and_snapshots() {
        let signer = test_signer();
        let ad = CortexAdvertisement::sign(
            &signer,
            "did:tenzro:machine:test",
            Address::default(),
            "mythos-3b",
            CortexModelFamily::default(),
            CortexPricing::default(),
            None,
            60,
        )
        .unwrap();
        let reg = RemoteWorkerRegistry::new();
        reg.ingest(ad.clone()).unwrap();
        assert_eq!(reg.len(), 1);
        let snap = reg.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].worker_did, ad.worker_did);
    }
}
