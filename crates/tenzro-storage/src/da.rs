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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_types::primitives::{Hash, Timestamp};
use tenzro_types::principal_chain::PrincipalChainSummary;

use crate::error::{Result, StorageError};

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
}

impl DaBackendId {
    pub fn as_str(&self) -> &'static str {
        match self {
            DaBackendId::InlineFallback => "inline_fallback",
            DaBackendId::EigenDA => "eigenda",
            DaBackendId::Celestia => "celestia",
            DaBackendId::Avail => "avail",
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
        }
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

/// Default backend used when no external DA layer is configured. Refuses to
/// offload (so the writer is forced to use Inline mode); fetch is a pure
/// echo for already-inline payloads handed to it directly.
///
/// Used as a placeholder in node startup until EigenDA / Celestia / Avail
/// adapters are wired in their respective feature flags. Operators see
/// `inline_fallback` in `tenzro_getDaBackends` and know offload is disabled.
pub struct InlineFallbackBackend;

impl InlineFallbackBackend {
    pub fn new() -> Self {
        Self
    }

    pub fn arc() -> Arc<dyn DaBackend> {
        Arc::new(Self::new())
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
            last_submission_ms: None,
            last_fetch_ms: None,
            error_rate_bps: 0,
        }
    }

    async fn submit(&self, _namespace: &[u8], _payload: &[u8]) -> Result<DaPointer> {
        Err(StorageError::Generic(
            "InlineFallbackBackend does not support offload — receipt must use storage_mode=Inline"
                .into(),
        ))
    }

    async fn fetch(&self, _pointer: &DaPointer) -> Result<Vec<u8>> {
        Err(StorageError::Generic(
            "InlineFallbackBackend cannot fetch — payload should be inline on the envelope".into(),
        ))
    }

    async fn verify_availability(&self, _pointer: &DaPointer) -> Result<()> {
        Err(StorageError::Generic(
            "InlineFallbackBackend cannot verify external pointers".into(),
        ))
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
        };
        let err = env.validate().unwrap_err();
        match err {
            StorageError::InvalidValue(msg) => assert!(msg.contains("must not carry da_pointer")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn inline_fallback_refuses_offload() {
        let backend = InlineFallbackBackend::new();
        assert_eq!(backend.id(), DaBackendId::InlineFallback);
        assert!(backend.status().healthy);

        let err = backend.submit(b"ns", b"payload").await.unwrap_err();
        match err {
            StorageError::Generic(msg) => assert!(msg.contains("does not support offload")),
            other => panic!("unexpected error: {:?}", other),
        }

        let pointer = DaPointer {
            backend: DaBackendId::EigenDA,
            namespace: vec![],
            locator: vec![],
            commitment_kzg: None,
            attestation_root: None,
        };
        assert!(backend.fetch(&pointer).await.is_err());
        assert!(backend.verify_availability(&pointer).await.is_err());
    }

    #[test]
    fn da_backend_id_str() {
        assert_eq!(DaBackendId::InlineFallback.as_str(), "inline_fallback");
        assert_eq!(DaBackendId::EigenDA.as_str(), "eigenda");
        assert_eq!(DaBackendId::Celestia.as_str(), "celestia");
        assert_eq!(DaBackendId::Avail.as_str(), "avail");
    }
}
