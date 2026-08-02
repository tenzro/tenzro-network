//! x402 Facilitator — verification and settlement service
//!
//! The facilitator is a trusted intermediary that verifies payment
//! payloads and settles them on-chain. In the x402 V2 spec, the
//! facilitator runs as an HTTP service with POST /verify and POST /settle.
//!
//! Verification is dispatched through the [`SchemeRegistry`] just like
//! [`X402PaymentServer`](super::server::X402PaymentServer) — every payload
//! resolves to a `SchemeBackend` via `requirement.extra["scheme"]` (default:
//! `tenzro-hybrid`). This is the payload-form path
//! ([`SchemeBackend::verify_payload`] /
//! [`SchemeBackend::settle_payload`]) parallel to the credential-form path
//! used by the in-process server.

use crate::error::{PaymentError, Result};
use crate::x402::payment_payload::X402PaymentPayload;
use crate::x402::payment_required::X402PaymentRequired;
use crate::x402::scheme::SchemeRegistry;
use std::sync::Arc;
use tenzro_settlement::engine::SettlementEngine;
use tenzro_types::Address;
use tenzro_types::settlement::{ProofType, ServiceProof, ServiceType};
use tracing::{debug, info};

/// x402 facilitator for payment verification and settlement
pub struct X402Facilitator {
    /// Supported chains for payment
    supported_chains: Vec<String>,
    /// Settlement engine for executing on-chain settlements (Tenzro-native path)
    settlement_engine: Option<Arc<SettlementEngine>>,
    /// Scheme registry — dispatches verification/settlement by
    /// `requirement.extra["scheme"]` (defaults: `tenzro-hybrid`,
    /// `exact-eip3009`, `permit2`, `erc7710`).
    scheme_registry: SchemeRegistry,
}

impl X402Facilitator {
    /// Creates a new x402 facilitator
    pub fn new(supported_chains: Vec<String>) -> Self {
        Self {
            supported_chains,
            settlement_engine: None,
            scheme_registry: SchemeRegistry::with_defaults(),
        }
    }

    /// Sets the settlement engine
    pub fn with_settlement_engine(mut self, engine: Arc<SettlementEngine>) -> Self {
        self.settlement_engine = Some(engine);
        self
    }

    /// Replaces the scheme registry — primarily used by tests and by
    /// operators wiring custom backends (e.g. a real on-chain
    /// `DelegationVerifier` for ERC-7710).
    pub fn with_scheme_registry(mut self, registry: SchemeRegistry) -> Self {
        self.scheme_registry = registry;
        self
    }

    /// Borrow the underlying scheme registry. Useful for diagnostics
    /// (`scheme_registry().ids()` exposes the set of registered ids).
    pub fn scheme_registry(&self) -> &SchemeRegistry {
        &self.scheme_registry
    }

    /// CAIP-2 networks this facilitator accepts payloads on.
    pub fn supported_chains(&self) -> &[String] {
        &self.supported_chains
    }

    /// Verifies a payment payload against requirements.
    ///
    /// Pipeline (Coinbase x402 V2 wire):
    /// 1. Network is supported by this facilitator (payload.network).
    /// 2. A requirement in `requirements.accepts` matches the payload's
    ///    `(network, scheme)` pair.
    /// 3. The paid amount (`payload.payload.authorization.value`) is `>=`
    ///    `requirement.max_amount_required`.
    /// 4. The requirement has not expired.
    /// 5. The configured [`SchemeBackend`] (selected from
    ///    `requirement.scheme`) accepts the payload.
    ///
    /// Returns `Ok(true)` only if all five checks pass. Scheme-specific
    /// failures bubble up as `Ok(false)` rather than `Err` so the
    /// facilitator can return a structured 402 response — explicit error
    /// returns are reserved for misconfiguration (unknown scheme).
    pub async fn verify(
        &self,
        requirements: &X402PaymentRequired,
        payload: &X402PaymentPayload,
    ) -> Result<bool> {
        let payer = &payload.payload.authorization.from;
        info!("Verifying x402 payment from {}", payer);

        // 1. Check network is supported
        if !self.supported_chains.contains(&payload.network) {
            debug!("Unsupported network: {}", payload.network);
            return Ok(false);
        }

        // 2. Find matching requirement on (network, scheme).
        let requirement = requirements
            .accepts
            .iter()
            .find(|r| r.network == payload.network && r.scheme == payload.scheme);

        let requirement = match requirement {
            Some(r) => r,
            None => {
                debug!(
                    "No matching requirement for network={} scheme={}",
                    payload.network, payload.scheme
                );
                return Ok(false);
            }
        };

        // 3. Verify amount matches
        let required_amount: u128 = requirement.max_amount_required.parse().unwrap_or(0);
        let payload_amount: u128 = payload.payload.authorization.value.parse().unwrap_or(0);

        if payload_amount < required_amount {
            debug!(
                "Insufficient payment: required={}, got={}",
                required_amount, payload_amount
            );
            return Ok(false);
        }

        // 4. Check requirement expiration
        if chrono::Utc::now() > requirement.expires_at {
            debug!("Requirement has expired");
            return Ok(false);
        }

        // 5. Dispatch scheme-specific verification through the registry.
        let backend = self.scheme_registry.lookup_for_requirement(requirement)?;
        match backend.verify_payload(requirement, payload).await {
            Ok(()) => {
                info!(
                    "x402 payment verified from {} under scheme '{}'",
                    payer,
                    backend.name()
                );
                Ok(true)
            }
            Err(e) => {
                debug!(
                    "Scheme '{}' rejected payload from {}: {}",
                    backend.name(),
                    payer,
                    e
                );
                Ok(false)
            }
        }
    }

    /// Settles a verified payment.
    ///
    /// Two paths:
    /// 1. **Facilitator-routed schemes** (EIP-3009, Permit2, ERC-7710): the
    ///    backend's [`SchemeBackend::settle_payload`] returns the on-chain
    ///    tx hash from the remote facilitator (Coinbase CDP, etc.). Use
    ///    that.
    /// 2. **Tenzro-native schemes** (`tenzro-hybrid`): backend returns
    ///    `Ok(None)`. Settle locally via the configured `SettlementEngine`.
    ///
    /// `requirements` lets the facilitator pick the right scheme — without
    /// it we can't tell which path applies, so callers must pass the
    /// originating requirements (the same ones that produced the payload).
    pub async fn settle(
        &self,
        requirements: &X402PaymentRequired,
        payload: &X402PaymentPayload,
    ) -> Result<String> {
        let payer = &payload.payload.authorization.from;
        info!("Settling x402 payment on network {}", payload.network);

        let requirement = requirements
            .accepts
            .iter()
            .find(|r| r.network == payload.network && r.scheme == payload.scheme)
            .ok_or_else(|| {
                PaymentError::SettlementError(format!(
                    "No matching requirement for settlement: network={} scheme={}",
                    payload.network, payload.scheme
                ))
            })?;

        // 1. Try scheme-specific settlement (facilitator-routed schemes
        //    return Some(tx_hash); Tenzro-native schemes return None).
        let backend = self.scheme_registry.lookup_for_requirement(requirement)?;
        if let Some(tx_hash) = backend.settle_payload(requirement, payload).await? {
            debug!(
                "Scheme '{}' settled payload from {} as tx {}",
                backend.name(),
                payer,
                tx_hash
            );
            return Ok(tx_hash);
        }

        // 2. Tenzro-native path: route through the local SettlementEngine.
        if let Some(engine) = &self.settlement_engine {
            let amount: u128 = payload.payload.authorization.value.parse().unwrap_or(0);
            let amount_u64 = u64::try_from(amount).map_err(|_| {
                PaymentError::SettlementError("Amount exceeds u64 range".to_string())
            })?;

            let payer_hex = payer.strip_prefix("0x").unwrap_or(payer.as_str());
            let payer_bytes = hex::decode(payer_hex).unwrap_or_default();
            let mut payer_arr = [0u8; 32];
            let len = payer_bytes.len().min(32);
            payer_arr[32 - len..].copy_from_slice(&payer_bytes[..len]);

            // Bind the canonical EIP-3009 authorization tuple as the proof
            // body — the facilitator-side opaque blob.
            let auth_proof = serde_json::to_vec(&payload.payload.authorization)
                .map_err(|e| PaymentError::SerializationError(e.to_string()))?;

            let request = tenzro_types::settlement::SettlementRequest::new(
                Address::new([0u8; 32]), // Provider (facilitator) address
                Address::new(payer_arr),
                ServiceType::HttpPayment {
                    protocol: "x402".to_string(),
                    resource: "facilitator-settlement".to_string(),
                },
                amount_u64,
                ServiceProof {
                    proof_type: ProofType::Cryptographic,
                    proof_data: auth_proof,
                    signatures: vec![],
                    attestation: None,
                },
            );

            let receipt = engine
                .settle(request)
                .await
                .map_err(|e| PaymentError::SettlementError(e.to_string()))?;

            return Ok(hex::encode(receipt.transaction_hash.as_bytes()));
        }

        // No engine and no scheme tx — return a reference ID
        Ok(format!("x402-settlement-{}", uuid::Uuid::new_v4()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PaymentChallenge, PaymentCredential};
    use crate::x402::payment_payload::{ExactAuthorization, ExactSchemePayload};
    use crate::x402::payment_required::X402PaymentRequirement;
    use crate::x402::scheme::SchemeBackend;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

    fn empty_payload(scheme: &str, network: &str, value: &str, payer: &str) -> X402PaymentPayload {
        X402PaymentPayload::new(
            scheme,
            network,
            ExactSchemePayload::new(ExactAuthorization {
                from: payer.to_string(),
                to: "0xrecipient".to_string(),
                value: value.to_string(),
                valid_after: 0,
                valid_before: u64::MAX,
                nonce: "0x".to_string() + &hex::encode([0u8; 32]),
            }),
        )
    }

    /// Sign a payload under the canonical tenzro-hybrid V2 preimage:
    /// `network || asset || max_amount_required || pay_to || payer_hex`.
    /// Consumes `kp` because `Ed25519SignerImpl::new` takes a `KeyPair` by
    /// value.
    fn sign_tenzro_hybrid_payload(
        requirement: &X402PaymentRequirement,
        value: &str,
        kp: KeyPair,
    ) -> X402PaymentPayload {
        let payer_hex = hex::encode(kp.public_key().as_bytes());

        let mut msg = Vec::new();
        msg.extend_from_slice(requirement.network.as_bytes());
        msg.extend_from_slice(requirement.asset.as_bytes());
        msg.extend_from_slice(requirement.max_amount_required.as_bytes());
        msg.extend_from_slice(requirement.pay_to.as_bytes());
        msg.extend_from_slice(payer_hex.as_bytes());

        let signer = Ed25519SignerImpl::new(kp).unwrap();
        let sig = signer.sign(&msg).unwrap();

        let authorization = ExactAuthorization {
            from: payer_hex,
            to: requirement.pay_to.clone(),
            value: value.to_string(),
            valid_after: 0,
            valid_before: u64::MAX,
            nonce: "0x".to_string() + &hex::encode([0u8; 32]),
        };

        X402PaymentPayload::new(
            &requirement.scheme,
            &requirement.network,
            ExactSchemePayload {
                signature: hex::encode(sig.as_bytes()),
                authorization,
            },
        )
    }

    fn tenzro_hybrid_requirement(amount: &str) -> X402PaymentRequirement {
        X402PaymentRequirement::new(
            "tenzro-hybrid",
            "tenzro",
            amount,
            "0xrecipient",
            "USDC",
            "https://api.tenzro.xyz/paid/resource",
            "Test resource",
            "application/json",
            300,
        )
    }

    #[tokio::test]
    async fn test_facilitator_rejects_unsupported_chain() {
        let facilitator = X402Facilitator::new(vec!["tenzro".to_string()]);
        let requirements = X402PaymentRequired::new(vec![tenzro_hybrid_requirement("1000")]);
        let payload = empty_payload("tenzro-hybrid", "ethereum", "1000", "0xpayer");

        let result = facilitator.verify(&requirements, &payload).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_facilitator_rejects_insufficient_amount() {
        let facilitator = X402Facilitator::new(vec!["tenzro".to_string()]);
        let requirements = X402PaymentRequired::new(vec![tenzro_hybrid_requirement("1000")]);
        let payload = empty_payload("tenzro-hybrid", "tenzro", "500", "0xpayer");

        let result = facilitator.verify(&requirements, &payload).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_facilitator_accepts_signed_tenzro_hybrid_payload() {
        let facilitator = X402Facilitator::new(vec!["tenzro".to_string()]);
        let requirement = tenzro_hybrid_requirement("1000");
        let requirements = X402PaymentRequired::new(vec![requirement.clone()]);

        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let payload = sign_tenzro_hybrid_payload(&requirement, "1000", kp);

        let result = facilitator.verify(&requirements, &payload).await.unwrap();
        assert!(result, "Ed25519-signed tenzro-hybrid payload must verify");
    }

    #[tokio::test]
    async fn test_facilitator_rejects_unsigned_tenzro_hybrid_payload() {
        let facilitator = X402Facilitator::new(vec!["tenzro".to_string()]);
        let requirements = X402PaymentRequired::new(vec![tenzro_hybrid_requirement("1000")]);

        // No signature populated — under the new scheme-dispatch contract
        // tenzro-hybrid rejects this.
        let payload = empty_payload("tenzro-hybrid", "tenzro", "1000", "0xpayer");
        let result = facilitator.verify(&requirements, &payload).await.unwrap();
        assert!(!result, "unsigned tenzro-hybrid payload must be rejected");
    }

    #[tokio::test]
    async fn test_facilitator_rejects_tampered_signature() {
        let facilitator = X402Facilitator::new(vec!["tenzro".to_string()]);
        let requirement = tenzro_hybrid_requirement("1000");
        let requirements = X402PaymentRequired::new(vec![requirement.clone()]);

        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let mut payload = sign_tenzro_hybrid_payload(&requirement, "1000", kp);
        // Flip a byte in the signature.
        let mut sig_bytes = hex::decode(&payload.payload.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        payload.payload.signature = hex::encode(&sig_bytes);

        let result = facilitator.verify(&requirements, &payload).await.unwrap();
        assert!(!result, "tampered signature must be rejected");
    }

    /// Stub backend used to assert that the facilitator routes through the
    /// registry. Records every payload-form invocation it sees.
    #[derive(Debug)]
    struct CountingBackend {
        verify_calls: AtomicUsize,
        settle_calls: AtomicUsize,
        accept: AtomicBool,
    }

    impl CountingBackend {
        fn new(accept: bool) -> Arc<Self> {
            Arc::new(Self {
                verify_calls: AtomicUsize::new(0),
                settle_calls: AtomicUsize::new(0),
                accept: AtomicBool::new(accept),
            })
        }
    }

    #[async_trait]
    impl SchemeBackend for CountingBackend {
        fn name(&self) -> &'static str {
            "counting"
        }

        async fn verify(
            &self,
            _challenge: &PaymentChallenge,
            _credential: &PaymentCredential,
        ) -> Result<()> {
            Ok(())
        }

        async fn verify_payload(
            &self,
            _requirement: &X402PaymentRequirement,
            _payload: &X402PaymentPayload,
        ) -> Result<()> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            if self.accept.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(PaymentError::VerificationFailed("counting reject".into()))
            }
        }

        async fn settle_payload(
            &self,
            _requirement: &X402PaymentRequirement,
            _payload: &X402PaymentPayload,
        ) -> Result<Option<String>> {
            self.settle_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Some("0xcounting-tx".to_string()))
        }
    }

    #[tokio::test]
    async fn test_facilitator_dispatches_through_registry() {
        let backend = CountingBackend::new(true);

        let mut registry = crate::x402::scheme::SchemeRegistry::with_defaults();
        registry.register("counting", backend.clone());

        let facilitator =
            X402Facilitator::new(vec!["tenzro".to_string()]).with_scheme_registry(registry);

        let requirement = X402PaymentRequirement::new(
            "counting",
            "tenzro",
            "1000",
            "0xrecipient",
            "USDC",
            "https://api.tenzro.xyz/paid/resource",
            "Counting backend test",
            "application/json",
            300,
        );
        let requirements = X402PaymentRequired::new(vec![requirement]);
        let payload = empty_payload("counting", "tenzro", "1000", "0xpayer");

        let accepted = facilitator.verify(&requirements, &payload).await.unwrap();
        assert!(accepted, "counting backend was set to accept");
        assert_eq!(backend.verify_calls.load(Ordering::SeqCst), 1);

        let tx = facilitator.settle(&requirements, &payload).await.unwrap();
        assert_eq!(tx, "0xcounting-tx");
        assert_eq!(backend.settle_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_facilitator_rejects_unknown_scheme() {
        let facilitator = X402Facilitator::new(vec!["tenzro".to_string()]);
        let requirement = X402PaymentRequirement::new(
            "not-a-real-scheme",
            "tenzro",
            "1000",
            "0xrecipient",
            "USDC",
            "https://api.tenzro.xyz/paid/resource",
            "Unknown scheme test",
            "application/json",
            300,
        );
        let requirements = X402PaymentRequired::new(vec![requirement]);
        let payload = empty_payload("not-a-real-scheme", "tenzro", "1000", "0xpayer");

        let err = facilitator
            .verify(&requirements, &payload)
            .await
            .unwrap_err();
        assert!(
            matches!(err, PaymentError::VerificationFailed(_)),
            "expected VerificationFailed, got {:?}",
            err
        );
    }
}
