//! Data availability primitives for receipt offload (Spec 7).
//!
//! High-volume receipts (inference, agent message, channel updates) ship a
//! commitment + pointer instead of the full payload — the bulk lives in an
//! external DA layer (EigenDA / Celestia / Avail). Sensitive low-volume
//! receipts (kill-switch, governance, escrow) stay inline.
//!
//! This module ships only the protocol-side primitives: the `ReceiptEnvelope`
//! container, the `DaBackend` trait, and an `InlineFallbackBackend` that
//! refuses to offload (the safe default until external backends are wired).
//! External backend impls are gated behind feature flags that land alongside
//! their respective bridge work.

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_types::primitives::{Hash, Timestamp};
use tenzro_types::principal_chain::PrincipalChainSummary;

use crate::error::{Result, StorageError};

pub mod redstuff;

#[cfg(feature = "celestia")]
pub mod celestia;

#[cfg(feature = "celestia")]
pub use celestia::CelestiaBackend;

#[cfg(feature = "eigenda")]
pub mod eigenda;

#[cfg(feature = "eigenda")]
pub use eigenda::EigenDaBackend;

#[cfg(feature = "avail")]
pub mod avail;

#[cfg(feature = "avail")]
pub use avail::AvailBackend;

/// Storage mode for a receipt — whether the full payload lives on-chain or in
/// an external DA layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptStorageMode {
    /// Full payload embedded in the chain envelope. Audit-critical or
    /// low-volume receipts use this mode.
    Inline,
    /// Only commitment + pointer + summary are on-chain; the payload lives in
    /// the named DA backend.
    OffloadedDA,
}

/// Logical kind of receipt — drives the per-kind default storage mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptKind {
    /// Escrow create/release/refund. Default: Inline (audit-critical).
    SettlementEscrow,
    /// Off-chain channel update. Default: OffloadedDA (high volume).
    SettlementChannel,
    /// Inference request/response pair. Default: OffloadedDA.
    Inference,
    /// Agent-to-agent message receipt. Default: OffloadedDA.
    AgentMessage,
    /// Pause/Quarantine/Terminate event. Default: Inline (audit-critical).
    KillSwitch,
    /// Identity register / agent spawn. Default: Inline.
    Lifecycle,
    /// Governance proposal or vote. Default: Inline.
    Governance,
}

impl ReceiptKind {
    /// Default storage mode for this kind. See `da-offload.md` §"Per-receipt-kind defaults".
    pub fn default_mode(&self) -> ReceiptStorageMode {
        match self {
            ReceiptKind::SettlementChannel
            | ReceiptKind::Inference
            | ReceiptKind::AgentMessage => ReceiptStorageMode::OffloadedDA,
            ReceiptKind::SettlementEscrow
            | ReceiptKind::KillSwitch
            | ReceiptKind::Lifecycle
            | ReceiptKind::Governance => ReceiptStorageMode::Inline,
        }
    }
}

/// Identifier for a DA backend implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DaBackendId {
    /// Inline fallback — refuses offload, used when no external backend is
    /// configured or as a safe default.
    InlineFallback,
    /// EigenDA via disperser RPC + attestation service.
    EigenDA,
    /// Celestia + Matcha namespace data.
    Celestia,
    /// Avail node + KZG opening proofs.
    Avail,
    /// iroh-blobs content-addressed transport (Phase A2, #214).
    /// Locator is the 32-byte BLAKE3 hash; backend commitment_kzg is `None`
    /// because iroh-blobs verifies the BLAKE3 hash over every transferred
    /// chunk itself.
    IrohBlobs,
    /// Committee-resident Red Stuff store. Two-dimensional Reed-Solomon slivers
    /// distributed to the validator committee, with a `2f+1`-signed availability
    /// certificate carried in `DaPointer::attestation_root`. Locator is the
    /// 32-byte blob commitment; reconstruction needs `2f+1` slivers and each
    /// sliver binds to the commitment via a Merkle proof.
    TenzroCommittee,
}

impl DaBackendId {
    pub fn as_str(&self) -> &'static str {
        match self {
            DaBackendId::InlineFallback => "inline_fallback",
            DaBackendId::EigenDA => "eigenda",
            DaBackendId::Celestia => "celestia",
            DaBackendId::Avail => "avail",
            DaBackendId::IrohBlobs => "iroh_blobs",
            DaBackendId::TenzroCommittee => "tenzro_committee",
        }
    }
}

/// Typed pointer to a payload in an external DA layer.
///
/// `commitment_kzg` is backend-attested (KZG for Avail, BN254 for EigenDA's
/// restaking attestation, namespace-Merkle for Celestia). The chain-of-custody
/// commitment in `ReceiptEnvelope::commitment` is always SHA-256 over the
/// canonical payload bytes — verifiers check both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaPointer {
    pub backend: DaBackendId,
    /// Backend namespace (Celestia namespace bytes, EigenDA quorum id, …).
    pub namespace: Vec<u8>,
    /// Backend-specific locator (batch_id+chunk for Celestia, blob_id for
    /// Avail, etc.). Opaque to consensus; only the configured backend can
    /// dereference.
    pub locator: Vec<u8>,
    /// Backend-attested commitment. May differ from
    /// `ReceiptEnvelope::commitment` (KZG vs SHA-256). `None` for backends
    /// that do not produce one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_kzg: Option<Vec<u8>>,
    /// EigenDA attestation service root (or analogous backend root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_root: Option<Hash>,
}

/// Minimal triage fields surfaced to indexes regardless of storage mode.
/// Always present in `ReceiptEnvelope::inline_summary`. Index-style RPCs (list
/// by controller, summarize controller) work against summaries alone — the
/// full payload is fetched only when explicitly requested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSummary {
    pub receipt_id: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_wei: Option<u128>,
    pub timestamp: Timestamp,
    /// Compact view of the principal chain (Spec 5) when applicable. Full
    /// chain (delegation_scope_ids etc.) lives in the offloaded payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_chain_summary: Option<PrincipalChainSummary>,
}

/// Reference to a signed off-chain mandate that authorized the receipt.
///
/// Settlements that flow from an AP2 checkout mandate, an x402 challenge,
/// an MPP session, or a Stripe SPT carry a `MandateRef` so the on-chain
/// receipt is cryptographically tied back to the user's signed intent.
/// The mandate body itself stays off-chain (or in DA); the chain stores
/// only the hash, the protocol identifier, and the issuer DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateRef {
    /// Wire protocol identifier. Canonical values:
    /// `"ap2-checkout"`, `"ap2-payment"`, `"x402"`, `"mpp"`,
    /// `"stripe-spt"`, `"visa-tap"`, `"mastercard-agent-pay"`,
    /// `"capital-intent"`, `"workflow-step"`.
    pub protocol: String,
    /// `keccak256(canonical_mandate_bytes)` or SHA-256, per the protocol
    /// — the hash agreed between issuer and verifier.
    pub mandate_hash: Hash,
    /// DID of the principal (user / agent / institution) who signed the
    /// mandate.
    pub issuer_did: String,
    /// Optional mandate body URI (e.g. `https://`, `tenzro://`,
    /// `eigenda://`). When absent the verifier is expected to resolve
    /// the body out of band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate_uri: Option<String>,
    /// Mandate expiry (unix seconds). `0` = no expiry.
    #[serde(default)]
    pub expires_at: u64,
}

impl MandateRef {
    /// Construct an AP2 checkout-mandate reference.
    pub fn ap2_checkout(mandate_hash: Hash, issuer_did: impl Into<String>) -> Self {
        Self {
            protocol: "ap2-checkout".into(),
            mandate_hash,
            issuer_did: issuer_did.into(),
            mandate_uri: None,
            expires_at: 0,
        }
    }

    /// Construct an x402-challenge reference.
    pub fn x402(mandate_hash: Hash, issuer_did: impl Into<String>) -> Self {
        Self {
            protocol: "x402".into(),
            mandate_hash,
            issuer_did: issuer_did.into(),
            mandate_uri: None,
            expires_at: 0,
        }
    }
}

/// Receipt as recorded on-chain. Either embeds the full payload (Inline) or
/// records a commitment + DA pointer (OffloadedDA). The chain's only guarantee
/// is `commitment = SHA-256(canonical_payload)` — same model L2s use against
/// EigenDA / Celestia / Avail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptEnvelope {
    pub kind: ReceiptKind,
    pub storage_mode: ReceiptStorageMode,
    pub inline_summary: ReceiptSummary,
    /// Present iff `storage_mode == Inline`. Canonical-encoded payload bytes
    /// (the encoding is the receipt-kind's responsibility — bincode for
    /// settlement, JSON for inference, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline_payload: Option<Vec<u8>>,
    /// Present iff `storage_mode == OffloadedDA`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub da_pointer: Option<DaPointer>,
    /// SHA-256 over the canonical payload bytes — the chain-of-custody
    /// commitment, regardless of storage mode.
    pub commitment: Hash,
    /// Optional reference to a signed off-chain mandate authorizing this
    /// receipt. Present for settlements, inferences, and agent actions
    /// that flow from a signed user intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate_ref: Option<MandateRef>,
}

impl ReceiptEnvelope {
    /// Build an inline envelope from a payload. `commitment` is computed as
    /// `SHA-256(payload)`.
    pub fn inline(kind: ReceiptKind, summary: ReceiptSummary, payload: Vec<u8>) -> Self {
        let commitment = compute_commitment(&payload);
        Self {
            kind,
            storage_mode: ReceiptStorageMode::Inline,
            inline_summary: summary,
            inline_payload: Some(payload),
            da_pointer: None,
            commitment,
            mandate_ref: None,
        }
    }

    /// Build an offloaded envelope. `commitment` must be computed by the
    /// caller over the original payload before submission.
    pub fn offloaded(
        kind: ReceiptKind,
        summary: ReceiptSummary,
        pointer: DaPointer,
        commitment: Hash,
    ) -> Self {
        Self {
            kind,
            storage_mode: ReceiptStorageMode::OffloadedDA,
            inline_summary: summary,
            inline_payload: None,
            da_pointer: Some(pointer),
            commitment,
            mandate_ref: None,
        }
    }

    /// Attach a signed off-chain mandate reference to this envelope. Used
    /// for settlements that flow from an AP2 checkout mandate, x402 challenge,
    /// MPP session, Stripe SPT, or another signed user intent.
    pub fn with_mandate(mut self, mandate_ref: MandateRef) -> Self {
        self.mandate_ref = Some(mandate_ref);
        self
    }

    /// Validate the envelope's internal shape — fields match the declared
    /// storage mode, inline payload (if present) matches commitment.
    pub fn validate(&self) -> Result<()> {
        match self.storage_mode {
            ReceiptStorageMode::Inline => {
                let payload = self.inline_payload.as_ref().ok_or_else(|| {
                    StorageError::InvalidValue(
                        "Inline receipt envelope missing inline_payload".into(),
                    )
                })?;
                if self.da_pointer.is_some() {
                    return Err(StorageError::InvalidValue(
                        "Inline receipt envelope must not carry da_pointer".into(),
                    ));
                }
                let actual = compute_commitment(payload);
                if actual != self.commitment {
                    return Err(StorageError::InvalidValue(format!(
                        "Receipt commitment mismatch: declared {}, computed {}",
                        self.commitment, actual,
                    )));
                }
                Ok(())
            }
            ReceiptStorageMode::OffloadedDA => {
                if self.da_pointer.is_none() {
                    return Err(StorageError::InvalidValue(
                        "Offloaded receipt envelope missing da_pointer".into(),
                    ));
                }
                if self.inline_payload.is_some() {
                    return Err(StorageError::InvalidValue(
                        "Offloaded receipt envelope must not carry inline_payload".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Compute the chain-of-custody commitment over a canonical payload.
/// SHA-256 — matches the rest of Tenzro's hash usage.
pub fn compute_commitment(payload: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::new(bytes)
}

/// Status snapshot for a configured DA backend, surfaced to operators via
/// `tenzro_getDaBackends`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaBackendStatus {
    pub backend: DaBackendId,
    pub healthy: bool,
    /// Last successful submission, ms-since-epoch. `None` if never submitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_submission_ms: Option<i64>,
    /// Last successful fetch, ms-since-epoch. `None` if never fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_fetch_ms: Option<i64>,
    /// Recent error rate in basis points (0-10000). 0 = fully healthy.
    pub error_rate_bps: u16,
}

/// External data availability backend.
///
/// `submit` writes a payload to the backend and returns a typed pointer.
/// `fetch` resolves a pointer back to the payload (commitment verification is
/// the caller's responsibility — fetched bytes must hash to the envelope's
/// `commitment` before being trusted). `verify_availability` is a cheap "is
/// this pointer dereferenceable right now" probe that does not transfer the
/// payload.
#[async_trait]
pub trait DaBackend: Send + Sync {
    fn id(&self) -> DaBackendId;

    fn status(&self) -> DaBackendStatus;

    async fn submit(&self, namespace: &[u8], payload: &[u8]) -> Result<DaPointer>;

    async fn fetch(&self, pointer: &DaPointer) -> Result<Vec<u8>>;

    async fn verify_availability(&self, pointer: &DaPointer) -> Result<()>;
}

/// Default backend used when no external DA layer (EigenDA / Celestia / Avail)
/// is configured. Stores submitted payloads in an in-memory `DashMap` keyed by
/// a synthetic locator `fallback:<sha256_hex>` and round-trips them through
/// `fetch`. This keeps the receipt-offload path functional pre-mainnet so the
/// rest of the system (commitments, indices, RPC) can be exercised in full
/// without standing up an external DA layer.
///
/// Optionally takes a [`crate::kv::KvStore`] handle (`with_storage`) so the
/// fallback DashMap is backed by `CF_METADATA` under the `da_fallback:`
/// prefix. Without storage the cache is in-process only and submissions do
/// not survive a restart — fine for tests and unit work, **not fine** for
/// any persisted receipt that needs to round-trip through `fetch` after a
/// process restart. Node startup and `RocksDbChannelStorage` wire in the
/// shared `RocksDbStore` so consensus-relevant offloaded payloads survive
/// restarts even before EigenDA / Celestia / Avail land.
///
/// Operators see `inline_fallback` in `tenzro_getDaBackends` and know external
/// availability is not guaranteed (no signed attestations, no cross-node
/// replication). Production deployments swap this out for a real backend
/// behind the matching feature flag.
pub struct InlineFallbackBackend {
    /// Synthetic-locator keyed payload store. Locator is
    /// `fallback:<sha256_hex>` of the payload, so the same payload submitted
    /// twice deduplicates to the same entry.
    store: DashMap<Vec<u8>, Vec<u8>>,
    /// Optional KvStore for cross-restart durability. When `Some`, every
    /// `submit_sync` mirror-writes the payload under `da_fallback:<locator>`
    /// in `CF_METADATA`, and `fetch_sync` falls back to the store on a
    /// DashMap miss (re-populating the cache).
    storage: Option<Arc<dyn crate::kv::KvStore>>,
    /// Last-submission / last-fetch timestamps (ms-since-epoch) for the
    /// status snapshot.
    last_submission_ms: Mutex<Option<i64>>,
    last_fetch_ms: Mutex<Option<i64>>,
}

impl InlineFallbackBackend {
    /// Storage prefix used when `with_storage` is wired. Lives in
    /// `CF_METADATA` to avoid colliding with any column-family-specific
    /// receipt index.
    const STORAGE_PREFIX: &'static [u8] = b"da_fallback:";

    pub fn new() -> Self {
        Self {
            store: DashMap::new(),
            storage: None,
            last_submission_ms: Mutex::new(None),
            last_fetch_ms: Mutex::new(None),
        }
    }

    /// Wire a durable `KvStore` so submitted payloads survive process
    /// restarts under `CF_METADATA` / `da_fallback:<locator>`.
    pub fn with_storage(mut self, storage: Arc<dyn crate::kv::KvStore>) -> Self {
        self.storage = Some(storage);
        self
    }

    pub fn arc() -> Arc<dyn DaBackend> {
        Arc::new(Self::new())
    }

    fn storage_key(locator: &[u8]) -> Vec<u8> {
        [Self::STORAGE_PREFIX, locator].concat()
    }

    /// Locator format: `fallback:<sha256_hex>` over the payload. Stable across
    /// duplicate submissions.
    fn make_locator(payload: &[u8]) -> Vec<u8> {
        let commitment = compute_commitment(payload);
        format!("fallback:{}", hex::encode(commitment.as_bytes())).into_bytes()
    }

    fn now_ms() -> i64 {
        Timestamp::now().0
    }

    /// Synchronous submit helper for callers in non-async contexts.
    ///
    /// Mirrors [`DaBackend::submit`] but without the async wrapper — the
    /// inline fallback does pure in-memory work, so there is nothing to
    /// suspend on. Used by sync persistence paths (channel storage, etc.)
    /// that wrap their payloads in a `ReceiptEnvelope` without taking a
    /// `&dyn DaBackend` dependency.
    ///
    /// When backed by a [`crate::kv::KvStore`] (via `with_storage`) the
    /// payload is also mirror-written under `CF_METADATA` /
    /// `da_fallback:<locator>` for cross-restart durability. Storage write
    /// failures are downgraded to a `tracing::warn` — the in-memory cache
    /// is still populated, so the same-process round-trip stays
    /// functional.
    pub fn submit_sync(&self, namespace: &[u8], payload: &[u8]) -> DaPointer {
        let locator = Self::make_locator(payload);
        self.store.insert(locator.clone(), payload.to_vec());
        if let Some(storage) = &self.storage
            && let Err(e) = storage.put(crate::kv::CF_METADATA, &Self::storage_key(&locator), payload) {
                tracing::warn!(
                    "InlineFallbackBackend: failed to mirror-write payload to storage: {}",
                    e
                );
            }
        *self.last_submission_ms.lock() = Some(Self::now_ms());
        DaPointer {
            backend: DaBackendId::InlineFallback,
            namespace: namespace.to_vec(),
            locator,
            commitment_kzg: None,
            attestation_root: None,
        }
    }

    /// Synchronous fetch helper. See [`Self::submit_sync`].
    ///
    /// Looks up the in-memory cache first; on miss, falls back to the
    /// configured `KvStore` (re-populating the cache on hit) so submissions
    /// from a previous process incarnation are still resolvable.
    pub fn fetch_sync(&self, pointer: &DaPointer) -> Result<Vec<u8>> {
        if pointer.backend != DaBackendId::InlineFallback {
            return Err(StorageError::Generic(format!(
                "InlineFallbackBackend cannot fetch pointer with backend {:?}",
                pointer.backend
            )));
        }
        if let Some(entry) = self.store.get(&pointer.locator) {
            *self.last_fetch_ms.lock() = Some(Self::now_ms());
            return Ok(entry.value().clone());
        }
        if let Some(storage) = &self.storage
            && let Some(bytes) = storage
                .get(crate::kv::CF_METADATA, &Self::storage_key(&pointer.locator))
                .map_err(|e| StorageError::Generic(format!("storage read: {}", e)))?
            {
                self.store.insert(pointer.locator.clone(), bytes.clone());
                *self.last_fetch_ms.lock() = Some(Self::now_ms());
                return Ok(bytes);
            }
        Err(StorageError::KeyNotFound(format!(
            "InlineFallbackBackend has no payload for locator {}",
            String::from_utf8_lossy(&pointer.locator)
        )))
    }
}

impl std::fmt::Debug for InlineFallbackBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InlineFallbackBackend")
            .field("entries", &self.store.len())
            .finish()
    }
}

impl Default for InlineFallbackBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DaBackend for InlineFallbackBackend {
    fn id(&self) -> DaBackendId {
        DaBackendId::InlineFallback
    }

    fn status(&self) -> DaBackendStatus {
        DaBackendStatus {
            backend: DaBackendId::InlineFallback,
            healthy: true,
            last_submission_ms: *self.last_submission_ms.lock(),
            last_fetch_ms: *self.last_fetch_ms.lock(),
            error_rate_bps: 0,
        }
    }

    async fn submit(&self, namespace: &[u8], payload: &[u8]) -> Result<DaPointer> {
        Ok(self.submit_sync(namespace, payload))
    }

    async fn fetch(&self, pointer: &DaPointer) -> Result<Vec<u8>> {
        self.fetch_sync(pointer)
    }

    async fn verify_availability(&self, pointer: &DaPointer) -> Result<()> {
        if pointer.backend != DaBackendId::InlineFallback {
            return Err(StorageError::Generic(format!(
                "InlineFallbackBackend cannot verify pointer with backend {:?}",
                pointer.backend
            )));
        }
        if self.store.contains_key(&pointer.locator) {
            return Ok(());
        }
        if let Some(storage) = &self.storage
            && storage
                .get(crate::kv::CF_METADATA, &Self::storage_key(&pointer.locator))
                .map_err(|e| StorageError::Generic(format!("storage read: {}", e)))?
                .is_some()
            {
                return Ok(());
            }
        Err(StorageError::KeyNotFound(format!(
            "InlineFallbackBackend has no payload for locator {}",
            String::from_utf8_lossy(&pointer.locator)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_summary() -> ReceiptSummary {
        ReceiptSummary {
            receipt_id: Hash::new([7u8; 32]),
            payer: Some("did:tenzro:human:alice".into()),
            payee: Some("did:tenzro:machine:bob".into()),
            amount_wei: Some(123_456_789),
            timestamp: Timestamp::new(1_700_000_000_000),
            principal_chain_summary: None,
        }
    }

    #[test]
    fn default_mode_per_kind_matches_spec() {
        assert_eq!(
            ReceiptKind::SettlementEscrow.default_mode(),
            ReceiptStorageMode::Inline
        );
        assert_eq!(
            ReceiptKind::SettlementChannel.default_mode(),
            ReceiptStorageMode::OffloadedDA
        );
        assert_eq!(
            ReceiptKind::Inference.default_mode(),
            ReceiptStorageMode::OffloadedDA
        );
        assert_eq!(
            ReceiptKind::AgentMessage.default_mode(),
            ReceiptStorageMode::OffloadedDA
        );
        assert_eq!(
            ReceiptKind::KillSwitch.default_mode(),
            ReceiptStorageMode::Inline
        );
        assert_eq!(
            ReceiptKind::Lifecycle.default_mode(),
            ReceiptStorageMode::Inline
        );
        assert_eq!(
            ReceiptKind::Governance.default_mode(),
            ReceiptStorageMode::Inline
        );
    }

    #[test]
    fn compute_commitment_is_sha256() {
        let h = compute_commitment(b"hello");
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            hex::encode(h.as_bytes()),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn inline_envelope_validates() {
        let env = ReceiptEnvelope::inline(
            ReceiptKind::SettlementEscrow,
            sample_summary(),
            b"escrow-payload".to_vec(),
        );
        env.validate().unwrap();
        assert_eq!(env.storage_mode, ReceiptStorageMode::Inline);
        assert!(env.da_pointer.is_none());
        assert!(env.inline_payload.is_some());
    }

    #[test]
    fn inline_envelope_with_tampered_commitment_rejected() {
        let mut env = ReceiptEnvelope::inline(
            ReceiptKind::Inference,
            sample_summary(),
            b"payload".to_vec(),
        );
        env.commitment = Hash::new([0u8; 32]);
        let err = env.validate().unwrap_err();
        match err {
            StorageError::InvalidValue(msg) => assert!(msg.contains("commitment mismatch")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn offloaded_envelope_validates() {
        let payload = b"large-inference-blob".to_vec();
        let commitment = compute_commitment(&payload);
        let pointer = DaPointer {
            backend: DaBackendId::EigenDA,
            namespace: b"tenzro/inference".to_vec(),
            locator: b"blob-42".to_vec(),
            commitment_kzg: Some(vec![0xab; 48]),
            attestation_root: Some(Hash::new([3u8; 32])),
        };
        let env =
            ReceiptEnvelope::offloaded(ReceiptKind::Inference, sample_summary(), pointer, commitment);
        env.validate().unwrap();
        assert_eq!(env.storage_mode, ReceiptStorageMode::OffloadedDA);
        assert!(env.inline_payload.is_none());
        assert!(env.da_pointer.is_some());
    }

    #[test]
    fn offloaded_envelope_without_pointer_rejected() {
        let env = ReceiptEnvelope {
            kind: ReceiptKind::Inference,
            storage_mode: ReceiptStorageMode::OffloadedDA,
            inline_summary: sample_summary(),
            inline_payload: None,
            da_pointer: None,
            commitment: Hash::new([1u8; 32]),
            mandate_ref: None,
        };
        let err = env.validate().unwrap_err();
        match err {
            StorageError::InvalidValue(msg) => assert!(msg.contains("missing da_pointer")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn inline_envelope_with_pointer_rejected() {
        let payload = b"x".to_vec();
        let env = ReceiptEnvelope {
            kind: ReceiptKind::SettlementEscrow,
            storage_mode: ReceiptStorageMode::Inline,
            inline_summary: sample_summary(),
            inline_payload: Some(payload.clone()),
            da_pointer: Some(DaPointer {
                backend: DaBackendId::EigenDA,
                namespace: vec![],
                locator: vec![],
                commitment_kzg: None,
                attestation_root: None,
            }),
            commitment: compute_commitment(&payload),
            mandate_ref: None,
        };
        let err = env.validate().unwrap_err();
        match err {
            StorageError::InvalidValue(msg) => assert!(msg.contains("must not carry da_pointer")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn inline_fallback_round_trips_payload() {
        let backend = InlineFallbackBackend::new();
        assert_eq!(backend.id(), DaBackendId::InlineFallback);
        assert!(backend.status().healthy);

        let payload = b"large-inference-blob".to_vec();
        let pointer = backend.submit(b"tenzro/inference", &payload).await.unwrap();
        assert_eq!(pointer.backend, DaBackendId::InlineFallback);
        assert_eq!(pointer.namespace, b"tenzro/inference".to_vec());
        // Locator is `fallback:<sha256_hex>` of the payload.
        let expected_locator = format!(
            "fallback:{}",
            hex::encode(compute_commitment(&payload).as_bytes())
        );
        assert_eq!(pointer.locator, expected_locator.as_bytes());

        backend.verify_availability(&pointer).await.unwrap();
        let fetched = backend.fetch(&pointer).await.unwrap();
        assert_eq!(fetched, payload);

        // Status reflects the submission/fetch.
        let status = backend.status();
        assert!(status.last_submission_ms.is_some());
        assert!(status.last_fetch_ms.is_some());

        // Submitting the same payload again is idempotent — same locator.
        let pointer2 = backend.submit(b"tenzro/inference", &payload).await.unwrap();
        assert_eq!(pointer2.locator, pointer.locator);
    }

    #[tokio::test]
    async fn inline_fallback_rejects_foreign_pointer() {
        let backend = InlineFallbackBackend::new();
        let foreign = DaPointer {
            backend: DaBackendId::EigenDA,
            namespace: vec![],
            locator: b"blob-1".to_vec(),
            commitment_kzg: None,
            attestation_root: None,
        };
        assert!(backend.fetch(&foreign).await.is_err());
        assert!(backend.verify_availability(&foreign).await.is_err());
    }

    #[tokio::test]
    async fn inline_fallback_missing_locator_is_key_not_found() {
        let backend = InlineFallbackBackend::new();
        let pointer = DaPointer {
            backend: DaBackendId::InlineFallback,
            namespace: vec![],
            locator: b"fallback:deadbeef".to_vec(),
            commitment_kzg: None,
            attestation_root: None,
        };
        let err = backend.fetch(&pointer).await.unwrap_err();
        assert!(matches!(err, StorageError::KeyNotFound(_)));
    }

    #[test]
    fn da_backend_id_str() {
        assert_eq!(DaBackendId::InlineFallback.as_str(), "inline_fallback");
        assert_eq!(DaBackendId::EigenDA.as_str(), "eigenda");
        assert_eq!(DaBackendId::Celestia.as_str(), "celestia");
        assert_eq!(DaBackendId::Avail.as_str(), "avail");
        assert_eq!(DaBackendId::IrohBlobs.as_str(), "iroh_blobs");
        assert_eq!(DaBackendId::TenzroCommittee.as_str(), "tenzro_committee");
    }
}
