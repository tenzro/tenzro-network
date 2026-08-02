//! Attestation hooks for Cortex receipts.
//!
//! The [`AttestationRequirement`] enum on `CortexRequest` says *what* kind
//! of proof the caller wants (none / tee / zk / tee+zk), but the worker
//! needs a concrete way to produce those proofs. We can't hard-pin the
//! worker to `tenzro-tee` or `tenzro-zk` (that would invert the dep graph
//! — the node's `init_cortex_workers` already pulls both crates in), so
//! we define two small provider traits here and let the node wire real
//! implementations at startup.
//!
//! The provider traits take the canonical preimage bytes that the receipt
//! signer will sign, and return opaque `Vec<u8>` blobs that callers can
//! later verify against their respective verification paths (AttestationVerifier
//! in tenzro-tee, Plonky3 STARKs over KoalaBear in tenzro-zk).

use async_trait::async_trait;
use std::sync::Arc;

use crate::error::Result;

/// Produces a TEE attestation quote binding the given preimage.
///
/// Wired in tenzro-node via a wrapper over `TeeRegistry::get_active()`
/// which in turn calls the appropriate provider
/// (Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA GPU).
#[async_trait]
pub trait TeeAttestationProvider: Send + Sync {
    /// Generate a serialized TEE quote covering `preimage`.
    async fn attest(&self, preimage: &[u8]) -> Result<Vec<u8>>;
}

/// Produces a ZK proof binding the given preimage.
///
/// Wired in tenzro-node via a wrapper over tenzro-zk's Plonky3 STARK prover
/// and the `InferenceAir` inference-verification circuit.
#[async_trait]
pub trait ZkProofProvider: Send + Sync {
    /// Generate a serialized ZK proof covering `preimage`.
    async fn prove(&self, preimage: &[u8]) -> Result<Vec<u8>>;
}

/// Bundle of optional attestation providers injected into a worker.
///
/// If a provider is `None`, requests that require that class of proof
/// will fail with [`crate::error::CortexError::WorkerRejected`] at the
/// worker level. Nodes that want to serve only cheap `None` requests
/// can leave both fields empty.
#[derive(Clone, Default)]
pub struct AttestationSuite {
    pub tee: Option<Arc<dyn TeeAttestationProvider>>,
    pub zk: Option<Arc<dyn ZkProofProvider>>,
}

impl AttestationSuite {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tee(mut self, p: Arc<dyn TeeAttestationProvider>) -> Self {
        self.tee = Some(p);
        self
    }

    pub fn with_zk(mut self, p: Arc<dyn ZkProofProvider>) -> Self {
        self.zk = Some(p);
        self
    }

    pub fn has_tee(&self) -> bool {
        self.tee.is_some()
    }

    pub fn has_zk(&self) -> bool {
        self.zk.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTee;
    #[async_trait]
    impl TeeAttestationProvider for MockTee {
        async fn attest(&self, preimage: &[u8]) -> Result<Vec<u8>> {
            let mut out = b"mock-tee:".to_vec();
            out.extend_from_slice(preimage);
            Ok(out)
        }
    }

    #[tokio::test]
    async fn suite_wires_providers() {
        let suite = AttestationSuite::new().with_tee(Arc::new(MockTee));
        assert!(suite.has_tee());
        assert!(!suite.has_zk());
        let quote = suite.tee.unwrap().attest(b"preimage").await.unwrap();
        assert!(quote.starts_with(b"mock-tee:"));
    }
}
