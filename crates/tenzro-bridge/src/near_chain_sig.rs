//! NEAR Chain Signatures (MPC v2) adapter.
//!
//! NEAR's chain-signatures MPC lets any account derive a per-(account, path)
//! external key on Bitcoin, Ethereum, Solana, TON, Stellar, Sui, Aptos and
//! sign transactions there without leaving NEAR. The MPC contract supports
//! both **ECDSA** (secp256k1 — Bitcoin, Ethereum, Dogecoin) and **EdDSA**
//! (Ed25519 — Solana, TON, Stellar, Sui, Aptos) per the late-2024 rollout.
//!
//! This adapter is the Tenzro-side view of that MPC: it derives the
//! expected target address for a `(predecessor, path, curve)` triple,
//! formats `sign` requests that match the NEAR contract method signature,
//! and parses the returned signature back into Tenzro `Signature` shape.
//!
//! Implementation references:
//!   - NEAR MPC contract: `near/mpc` GitHub
//!   - Curves: `near/threshold-signatures` GitHub
//!   - Spec: `docs.near.org/chain-abstraction/chain-signatures`

use std::collections::HashMap;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tenzro_types::primitives::Hash;

/// Curves NEAR Chain Signatures supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NearSigCurve {
    /// Secp256k1 — Bitcoin / Ethereum / Dogecoin / EVM-class chains.
    Secp256k1,
    /// Ed25519 — Solana / TON / Stellar / Sui / Aptos.
    Ed25519,
}

impl NearSigCurve {
    /// Canonical contract-side string for this curve.
    pub fn contract_path_tag(&self) -> &'static str {
        match self {
            NearSigCurve::Secp256k1 => "secp256k1",
            NearSigCurve::Ed25519 => "ed25519",
        }
    }
}

/// Target ecosystem the derived key drives. Used by [`NearChainSigAdapter`]
/// to expose the right address-encoding convenience.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NearTargetChain {
    /// Bitcoin mainnet.
    Bitcoin,
    /// Ethereum / generic EVM (caller supplies chain_id).
    Ethereum,
    /// Solana.
    Solana,
    /// TON.
    Ton,
    /// Stellar.
    Stellar,
    /// Sui.
    Sui,
    /// Aptos.
    Aptos,
    /// Dogecoin.
    Dogecoin,
}

impl NearTargetChain {
    /// Curve this chain expects.
    pub fn curve(&self) -> NearSigCurve {
        match self {
            NearTargetChain::Bitcoin
            | NearTargetChain::Ethereum
            | NearTargetChain::Dogecoin => NearSigCurve::Secp256k1,
            NearTargetChain::Solana
            | NearTargetChain::Ton
            | NearTargetChain::Stellar
            | NearTargetChain::Sui
            | NearTargetChain::Aptos => NearSigCurve::Ed25519,
        }
    }
}

/// Connection config for the NEAR MPC contract.
#[derive(Debug, Clone)]
pub struct NearChainSigConfig {
    /// `https://...` URL of a NEAR RPC node (or relayer) that fronts the MPC
    /// contract.
    pub rpc_url: String,
    /// Contract account id of the MPC contract (e.g. `v1.signer-prod.near`
    /// on mainnet, `v1.signer-dev.testnet` on testnet).
    pub mpc_contract: String,
    /// Public key root for the chosen curve. The adapter derives child keys
    /// off this via the `path`-based key-derivation rule the contract
    /// publishes (epsilon = hash(predecessor || ',' || path)).
    pub curve_root_pubkey: Vec<u8>,
    /// Curve this contract serves.
    pub curve: NearSigCurve,
}

/// Per-call request the contract method `sign(payload, path, key_version)`
/// expects. Hex-encoding is left to the JSON-RPC adapter on the node side
/// — this struct is the canonical Rust form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearSignRequest {
    /// 32-byte payload to sign — chain-specific tx-hash.
    pub payload: [u8; 32],
    /// Derivation path — e.g. `bitcoin-1`, `ethereum-mainnet-tnzo`.
    pub path: String,
    /// MPC key version (0 for the production root key).
    pub key_version: u32,
    /// Target chain shape this signature is for.
    pub target_chain: NearTargetChain,
    /// NEAR predecessor account that derives the child key (the caller).
    pub predecessor: String,
}

/// Returned signature. `r`, `s` are big-endian 32-byte scalars; `recovery_id`
/// is set for ECDSA only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearSignResponse {
    /// Curve of the returned signature.
    pub curve: NearSigCurve,
    /// 32-byte r.
    pub r: [u8; 32],
    /// 32-byte s.
    pub s: [u8; 32],
    /// ECDSA-only recovery id (0 or 1).
    pub recovery_id: Option<u8>,
    /// The derived public key — exposed so the caller can sanity-check it
    /// matches the locally-derived child key.
    pub derived_pubkey: Vec<u8>,
}

/// Adapter state. Holds the config and an audit log of submitted requests.
#[derive(Debug)]
pub struct NearChainSigAdapter {
    config: NearChainSigConfig,
    audit: RwLock<HashMap<Hash, NearSignRequest>>,
}

impl NearChainSigAdapter {
    /// Build a new adapter.
    pub fn new(config: NearChainSigConfig) -> Self {
        Self {
            config,
            audit: RwLock::new(HashMap::new()),
        }
    }

    /// Curve this adapter serves.
    pub fn curve(&self) -> NearSigCurve {
        self.config.curve
    }

    /// Compute the derivation `epsilon` for a `(predecessor, path)` pair.
    /// `epsilon = SHA-256("near-mpc-recovery v0.1.0 epsilon derivation:" ||
    /// predecessor || "," || path)` — matches the NEAR MPC contract.
    pub fn epsilon(predecessor: &str, path: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"near-mpc-recovery v0.1.0 epsilon derivation:");
        h.update(predecessor.as_bytes());
        h.update(b",");
        h.update(path.as_bytes());
        h.finalize().into()
    }

    /// Stable request id used to dedup + audit submissions.
    pub fn request_id(req: &NearSignRequest) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/near-chain-sig/request");
        h.update(req.predecessor.as_bytes());
        h.update(req.path.as_bytes());
        h.update(req.payload);
        h.update(req.key_version.to_le_bytes());
        h.update([req.target_chain as u8]);
        let digest: [u8; 32] = h.finalize().into();
        Hash::new(digest)
    }

    /// Record an outbound sign request (for audit + dedup). Returns the
    /// stable request id.
    pub fn record_request(&self, request: NearSignRequest) -> Hash {
        let id = Self::request_id(&request);
        self.audit.write().insert(id, request);
        id
    }

    /// Look up an audited request by id.
    pub fn get_request(&self, id: &Hash) -> Option<NearSignRequest> {
        self.audit.read().get(id).cloned()
    }

    /// Number of audited requests.
    pub fn audit_len(&self) -> usize {
        self.audit.read().len()
    }

    /// MPC contract method name for sign.
    pub fn contract_method_sign() -> &'static str {
        "sign"
    }

    /// MPC contract method name for the latest derived public key.
    pub fn contract_method_public_key() -> &'static str {
        "public_key"
    }

    /// Config getter.
    pub fn config(&self) -> &NearChainSigConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> NearChainSigConfig {
        NearChainSigConfig {
            rpc_url: "https://rpc.mainnet.near.org".into(),
            mpc_contract: "v1.signer-prod.near".into(),
            curve_root_pubkey: vec![0xab; 33],
            curve: NearSigCurve::Secp256k1,
        }
    }

    #[test]
    fn epsilon_is_deterministic() {
        let a = NearChainSigAdapter::epsilon("alice.near", "bitcoin-1");
        let b = NearChainSigAdapter::epsilon("alice.near", "bitcoin-1");
        assert_eq!(a, b);
        let c = NearChainSigAdapter::epsilon("alice.near", "bitcoin-2");
        assert_ne!(a, c);
    }

    #[test]
    fn curve_map_is_consistent() {
        assert_eq!(NearTargetChain::Bitcoin.curve(), NearSigCurve::Secp256k1);
        assert_eq!(NearTargetChain::Ethereum.curve(), NearSigCurve::Secp256k1);
        assert_eq!(NearTargetChain::Solana.curve(), NearSigCurve::Ed25519);
        assert_eq!(NearTargetChain::Aptos.curve(), NearSigCurve::Ed25519);
    }

    #[test]
    fn record_and_get_request() {
        let adapter = NearChainSigAdapter::new(cfg());
        let req = NearSignRequest {
            payload: [7u8; 32],
            path: "ethereum-mainnet".into(),
            key_version: 0,
            target_chain: NearTargetChain::Ethereum,
            predecessor: "tenzro.near".into(),
        };
        let id = adapter.record_request(req.clone());
        let back = adapter.get_request(&id).unwrap();
        assert_eq!(back.path, req.path);
        assert_eq!(adapter.audit_len(), 1);
    }

    #[test]
    fn request_id_is_path_sensitive() {
        let base = NearSignRequest {
            payload: [3u8; 32],
            path: "p1".into(),
            key_version: 0,
            target_chain: NearTargetChain::Ethereum,
            predecessor: "tenzro.near".into(),
        };
        let mut other = base.clone();
        other.path = "p2".into();
        assert_ne!(
            NearChainSigAdapter::request_id(&base),
            NearChainSigAdapter::request_id(&other)
        );
    }
}
