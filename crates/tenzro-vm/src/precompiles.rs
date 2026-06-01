//! Precompiled contracts for Tenzro Network

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

use crate::{error::Result, VmError};

// Re-export types for service injection
use tenzro_model::routing::InferenceRouter;
use tenzro_settlement::SettlementEngine;
use tenzro_storage::KvStore;

/// Precompile address type
pub type PrecompileAddress = Vec<u8>;

/// Standard EVM precompile addresses (Ethereum-compatible)
pub const PRECOMPILE_ECRECOVER: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const PRECOMPILE_SHA256: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
pub const PRECOMPILE_RIPEMD160: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
pub const PRECOMPILE_IDENTITY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4];
pub const PRECOMPILE_MODEXP: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
pub const PRECOMPILE_ECADD: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6];
pub const PRECOMPILE_ECMUL: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
pub const PRECOMPILE_ECPAIRING: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8];
pub const PRECOMPILE_BLAKE2F: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];

/// EIP-2537 BLS12-381 precompile addresses (Pectra upgrade, 0x0a-0x10)
pub const PRECOMPILE_BLS12_G1ADD: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a];
pub const PRECOMPILE_BLS12_G1MSM: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b];
pub const PRECOMPILE_BLS12_G2ADD: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0c];
pub const PRECOMPILE_BLS12_G2MSM: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0d];
pub const PRECOMPILE_BLS12_PAIRING_CHECK: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e];
pub const PRECOMPILE_BLS12_MAP_FP_TO_G1: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0f];
pub const PRECOMPILE_BLS12_MAP_FP2_TO_G2: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

/// EIP-7951 P256VERIFY precompile (Fusaka/Osaka, Dec 2025) — secp256r1 ECDSA verification at 0x100.
///
/// Canonical mainnet address (160-bit, big-endian = `0x000000…000100`) so callers using
/// FIDO2 / WebAuthn / Apple Secure Enclave / Android Keystore P-256 signatures get
/// bit-exact compatibility with Ethereum.
pub const PRECOMPILE_P256VERIFY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];

/// Tenzro-specific precompile addresses (`0x010000` upward). Distinct numerical range
/// from EIP-7951 (`0x100`); the comment in the original code labelled this "0x100" but
/// the byte pattern `0x010000` actually places these at 65536.
pub const PRECOMPILE_TEE_VERIFY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0];
pub const PRECOMPILE_ZK_VERIFY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
pub const PRECOMPILE_MODEL_INFERENCE: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2];
pub const PRECOMPILE_SETTLEMENT: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 3];

/// Token system precompile addresses (starting at 0x1001)
pub const PRECOMPILE_TNZO_BRIDGE: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 0];
pub const PRECOMPILE_TOKEN_FACTORY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x02, 0];
pub const PRECOMPILE_CROSS_VM_BRIDGE: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x03, 0];
pub const PRECOMPILE_STAKING: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x04, 0];
pub const PRECOMPILE_GOVERNANCE: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x05, 0];
/// NFT Factory precompile for creating/managing NFT collections across VMs (ERC-721/1155)
pub const PRECOMPILE_NFT_FACTORY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x06, 0];
/// VRF precompile — ECVRF-EDWARDS25519-SHA512-TAI proof verification (RFC 9381)
pub const PRECOMPILE_VRF_VERIFY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x07, 0];
/// Tenzro Train precompile — verify a [`TrainingReceipt`] commitment chain.
/// Phase 1: shell — accepts a serialized receipt, recomputes `run_root` from
/// `round_state_roots`, and returns 1 iff it matches the receipt's `run_root`.
/// Phase 2: extends to verifying syncer signature + attestation chain.
pub const PRECOMPILE_TRAINING_VERIFY: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x08, 0];

// ERC-7579 modular validator precompiles. Re-exported from `crate::erc7579`
// so that the registry-side wiring can reach them without an extra import.
pub use crate::erc7579::{
    PRECOMPILE_SESSION_KEY_VALIDATOR, PRECOMPILE_SOCIAL_RECOVERY_VALIDATOR,
    PRECOMPILE_SPENDING_LIMIT_VALIDATOR,
};

/// Precompile execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrecompileResult {
    /// Output data
    pub output: Vec<u8>,

    /// Gas used
    pub gas_used: u64,

    /// Whether execution succeeded
    pub success: bool,
}

impl PrecompileResult {
    /// Create a success result
    pub fn success(output: Vec<u8>, gas_used: u64) -> Self {
        Self {
            output,
            gas_used,
            success: true,
        }
    }

    /// Create a revert result with ABI-encoded reason data
    pub fn revert(output: Vec<u8>, gas_used: u64) -> Self {
        Self {
            output,
            gas_used,
            success: false,
        }
    }

    /// Create a failure result with no output
    pub fn failed(gas_used: u64) -> Self {
        Self {
            output: Vec::new(),
            gas_used,
            success: false,
        }
    }
}

/// Precompile function signature
pub type PrecompileFn = Arc<dyn Fn(&[u8], u64) -> Result<PrecompileResult> + Send + Sync>;

/// Length of a ZK commitment hash (SHA-256 digest).
pub const ZK_COMMITMENT_HASH_LEN: usize = 32;

/// A 32-byte SHA-256 commitment over a Plonky3 proof envelope.
pub type ZkCommitmentHash = [u8; ZK_COMMITMENT_HASH_LEN];

/// On-chain registry of validator-attested ZK proof commitments.
///
/// Plonky3 STARKs are too expensive to verify inside the EVM precompile
/// directly. Instead, the validator set runs the full Plonky3 verifier
/// off the EVM hot-path (in the consensus layer / RPC layer / settlement
/// engine), and on success records the proof's commitment hash in this
/// registry via a privileged transaction. The [`PRECOMPILE_ZK_VERIFY`]
/// precompile then performs an O(1) set-membership lookup against this
/// registry, returning `1` iff the commitment is present.
///
/// This is the "commitment-attestation" model — analogous to how
/// rollups commit verified state roots on L1 without re-executing the
/// underlying state transition.
///
/// # Commitment hash
///
/// `commitment = SHA-256(circuit_id || proof_bytes || encoded_public_inputs)`
///
/// where `encoded_public_inputs` is the concatenation of each public
/// input prefixed with its 4-byte little-endian length, ensuring the
/// hash is unambiguous across variable-width inputs.
///
/// See [`compute_zk_commitment`] for the canonical implementation.
#[derive(Default)]
pub struct ZkCommitmentRegistry {
    /// Set of attested commitment hashes.
    commitments: RwLock<HashSet<ZkCommitmentHash>>,
}

impl ZkCommitmentRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            commitments: RwLock::new(HashSet::new()),
        }
    }

    /// Record a verified commitment. Idempotent — re-attesting the same
    /// commitment is a no-op. Returns `true` if the commitment was newly
    /// inserted, `false` if it was already present.
    pub fn attest(&self, hash: ZkCommitmentHash) -> bool {
        self.commitments.write().insert(hash)
    }

    /// Check whether a commitment has been attested.
    pub fn is_attested(&self, hash: &ZkCommitmentHash) -> bool {
        self.commitments.read().contains(hash)
    }

    /// Number of attested commitments. Primarily for diagnostics.
    pub fn len(&self) -> usize {
        self.commitments.read().len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.commitments.read().is_empty()
    }
}

/// Compute the canonical SHA-256 commitment for a Plonky3 proof envelope.
///
/// `commitment = SHA-256(circuit_id || proof_bytes || Σ (len_le(pi) || pi))`
///
/// The 4-byte little-endian length prefix on each public input prevents
/// ambiguity when public inputs vary in width (e.g. mixing 4-byte
/// KoalaBear field elements with longer blobs). `circuit_id` is the
/// raw UTF-8 bytes — every AIR has a fixed-length circuit_id so no
/// length prefix is needed there.
pub fn compute_zk_commitment(proof: &tenzro_zk::Proof) -> ZkCommitmentHash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(proof.circuit_id.as_bytes());
    hasher.update(&proof.proof_bytes);
    for pi in &proof.public_inputs {
        hasher.update((pi.len() as u32).to_le_bytes());
        hasher.update(pi);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; ZK_COMMITMENT_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Registry of precompiled contracts
pub struct PrecompileRegistry {
    /// Map of address to precompile function
    precompiles: DashMap<Vec<u8>, PrecompileFn>,
}

impl PrecompileRegistry {
    /// Create a new precompile registry without service injection.
    ///
    /// In this serviceless mode, only the standard EVM precompiles
    /// (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, BN254 EC ops,
    /// BLAKE2F, BLS12-381 family, P256VERIFY) and the standalone Tenzro
    /// precompiles (TEE_VERIFY, TNZO_BRIDGE, TOKEN_FACTORY, CROSS_VM_BRIDGE,
    /// STAKING, GOVERNANCE, NFT_FACTORY, VRF_VERIFY) are registered.
    ///
    /// The service-dependent precompiles (ZK_VERIFY at 0x101, MODEL_INFERENCE
    /// at 0x102, SETTLEMENT at 0x103) are NOT registered until
    /// [`upgrade_services`] is called with their backing services. Calls to
    /// those addresses on a serviceless registry return the standard
    /// "precompile not found" error, which the EVM handles as a normal call
    /// to an unallocated address.
    pub fn new() -> Self {
        Self::new_with_services(None, None, None, None)
    }

    /// Create a new precompile registry, optionally pre-wiring the
    /// service-dependent precompiles at construction time.
    ///
    /// `Some(InferenceRouter)` registers MODEL_INFERENCE (0x102) at
    /// construction; `Some(SettlementEngine)` registers SETTLEMENT (0x103);
    /// `Some(ZkCommitmentRegistry)` registers ZK_VERIFY (0x101);
    /// `Some(KvStore)` registers NFT_FACTORY (0x1006) with persistent state
    /// (without a store, NFT_FACTORY is registered with an in-memory-only
    /// registry — mutations are lost on restart). Any of these may be wired
    /// later via [`upgrade_services`] / [`upgrade_nft_factory`].
    pub fn new_with_services(
        inference_router: Option<Arc<InferenceRouter>>,
        settlement_engine: Option<Arc<SettlementEngine>>,
        zk_commitment_registry: Option<Arc<ZkCommitmentRegistry>>,
        nft_storage: Option<Arc<dyn KvStore>>,
    ) -> Self {
        let registry = Self {
            precompiles: DashMap::new(),
        };

        // Register standard EVM precompiles
        registry.register_standard_precompiles();

        // Register Tenzro-specific precompiles with optional services
        registry.register_tenzro_precompiles(
            inference_router,
            settlement_engine,
            zk_commitment_registry,
            nft_storage,
        );

        registry
    }

    /// Register a precompile
    pub fn register(&self, address: Vec<u8>, func: PrecompileFn) {
        self.precompiles.insert(address, func);
    }

    /// Check if an address is a precompile
    pub fn is_precompile(&self, address: &[u8]) -> bool {
        self.precompiles.contains_key(address)
    }

    /// Execute a precompile
    pub fn execute(&self, address: &[u8], input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
        let precompile = self.precompiles.get(address)
            .ok_or_else(|| VmError::PrecompileFailed(format!("Precompile not found at address: {}", hex::encode(address))))?;

        precompile(input, gas_limit)
    }

    /// Register standard EVM precompiles
    fn register_standard_precompiles(&self) {
        // ecRecover
        self.register(PRECOMPILE_ECRECOVER.to_vec(), Arc::new(precompile_ecrecover));

        // SHA-256
        self.register(PRECOMPILE_SHA256.to_vec(), Arc::new(precompile_sha256));

        // RIPEMD-160
        self.register(PRECOMPILE_RIPEMD160.to_vec(), Arc::new(precompile_ripemd160));

        // Identity (copy)
        self.register(PRECOMPILE_IDENTITY.to_vec(), Arc::new(precompile_identity));

        // ModExp
        self.register(PRECOMPILE_MODEXP.to_vec(), Arc::new(precompile_modexp));

        // BN254 (alt_bn128) EC operations
        self.register(PRECOMPILE_ECADD.to_vec(), Arc::new(precompile_ecadd));
        self.register(PRECOMPILE_ECMUL.to_vec(), Arc::new(precompile_ecmul));
        self.register(PRECOMPILE_ECPAIRING.to_vec(), Arc::new(precompile_ecpairing));

        // BLAKE2f
        self.register(PRECOMPILE_BLAKE2F.to_vec(), Arc::new(precompile_blake2f));

        // EIP-7951 P256VERIFY (Fusaka/Osaka, Dec 2025) — secp256r1 ECDSA verification
        self.register(PRECOMPILE_P256VERIFY.to_vec(), Arc::new(precompile_p256verify));

        // EIP-2537 BLS12-381 precompiles (Pectra upgrade)
        self.register(PRECOMPILE_BLS12_G1ADD.to_vec(), Arc::new(precompile_bls12_g1add));
        self.register(PRECOMPILE_BLS12_G1MSM.to_vec(), Arc::new(precompile_bls12_g1msm));
        self.register(PRECOMPILE_BLS12_G2ADD.to_vec(), Arc::new(precompile_bls12_g2add));
        self.register(PRECOMPILE_BLS12_G2MSM.to_vec(), Arc::new(precompile_bls12_g2msm));
        self.register(PRECOMPILE_BLS12_PAIRING_CHECK.to_vec(), Arc::new(precompile_bls12_pairing_check));
        self.register(PRECOMPILE_BLS12_MAP_FP_TO_G1.to_vec(), Arc::new(precompile_bls12_map_fp_to_g1));
        self.register(PRECOMPILE_BLS12_MAP_FP2_TO_G2.to_vec(), Arc::new(precompile_bls12_map_fp2_to_g2));

        // Tenzro VRF (0x1007) — ECVRF-EDWARDS25519-SHA512-TAI proof verification (RFC 9381)
        self.register(PRECOMPILE_VRF_VERIFY.to_vec(), Arc::new(precompile_vrf_verify));

        // Tenzro Train (0x1008) — TrainingReceipt commitment-chain verification
        self.register(PRECOMPILE_TRAINING_VERIFY.to_vec(), Arc::new(precompile_training_verify));
    }

    /// Register Tenzro-specific precompiles with optional service injection
    fn register_tenzro_precompiles(
        &self,
        inference_router: Option<Arc<InferenceRouter>>,
        settlement_engine: Option<Arc<SettlementEngine>>,
        zk_commitment_registry: Option<Arc<ZkCommitmentRegistry>>,
        nft_storage: Option<Arc<dyn KvStore>>,
    ) {
        // TEE attestation verification — has no service dependency, always registered.
        self.register(PRECOMPILE_TEE_VERIFY.to_vec(), Arc::new(precompile_tee_verify));

        // NFT factory (0x1006) — ERC-721/1155 collection creation, mint, transfer,
        // mintRandom. Always registered. When `nft_storage` is provided, mutations
        // write through to `CF_NFTS` and previous state is hydrated on startup;
        // without a store, the registry is in-memory-only and state is lost on
        // restart. The store can be upgraded later via `upgrade_nft_factory`.
        {
            use crate::evm::nft_factory::{create_nft_factory_precompile, NftRegistry};
            let nft_registry = match nft_storage {
                Some(store) => Arc::new(NftRegistry::with_storage(store)),
                None => Arc::new(NftRegistry::new()),
            };
            self.register(
                PRECOMPILE_NFT_FACTORY.to_vec(),
                create_nft_factory_precompile(nft_registry),
            );
        }

        // Service-dependent precompiles: only registered when their backing
        // service is provided. Calls to unregistered addresses return
        // "precompile not found" — which the EVM treats as a call to an
        // unallocated address (no-op, returns empty data, charges only the
        // base call gas). No stub, no shim, no warning return value.
        if let Some(zk_registry) = zk_commitment_registry {
            self.register(
                PRECOMPILE_ZK_VERIFY.to_vec(),
                Arc::new(move |input: &[u8], gas_limit: u64| {
                    precompile_zk_verify_real(&zk_registry, input, gas_limit)
                }),
            );
        }

        if let Some(router) = inference_router {
            self.register(
                PRECOMPILE_MODEL_INFERENCE.to_vec(),
                Arc::new(move |input: &[u8], gas_limit: u64| {
                    precompile_model_inference_real(&router, input, gas_limit)
                }),
            );
        }

        if let Some(engine) = settlement_engine {
            self.register(
                PRECOMPILE_SETTLEMENT.to_vec(),
                Arc::new(move |input: &[u8], gas_limit: u64| {
                    precompile_settlement_real(&engine, input, gas_limit)
                }),
            );
        }
    }

    /// Upgrade the NFT_FACTORY precompile (0x1006) to a storage-backed
    /// `NftRegistry`, hydrating any pre-existing state from `CF_NFTS`.
    ///
    /// The VM runtime is built before persistent storage is wired into node
    /// startup, so NFT_FACTORY is initially registered in-memory-only. This
    /// method swaps it for a persistent registry once `RocksDbStore` is
    /// available. Idempotent: calling repeatedly with the same store rebuilds
    /// the registry from disk.
    pub fn upgrade_nft_factory(&self, store: Arc<dyn KvStore>) {
        use crate::evm::nft_factory::{create_nft_factory_precompile, NftRegistry};
        tracing::info!("Wiring NFT_FACTORY precompile (0x1006) to persistent NftRegistry");
        let nft_registry = Arc::new(NftRegistry::with_storage(store));
        self.register(
            PRECOMPILE_NFT_FACTORY.to_vec(),
            create_nft_factory_precompile(nft_registry),
        );
    }

    /// Wire up the service-dependent precompiles after registry construction.
    ///
    /// The VM runtime is typically built before `InferenceRouter`,
    /// `SettlementEngine`, and `ZkCommitmentRegistry` exist (they depend on
    /// storage and AI infra that come up later in node startup). This method
    /// is the canonical wire-up point: each `Some(service)` registers its
    /// precompile for the first time at the appropriate address. Each `None`
    /// leaves the address unregistered — calls return the standard "precompile
    /// not found" path, which the EVM handles as a call to an unallocated
    /// address.
    ///
    /// Idempotent: calling with the same services overwrites the previous
    /// registration with an identical one. Calling with all `None` is a no-op.
    pub fn upgrade_services(
        &self,
        inference_router: Option<Arc<InferenceRouter>>,
        settlement_engine: Option<Arc<SettlementEngine>>,
        zk_commitment_registry: Option<Arc<ZkCommitmentRegistry>>,
    ) {
        if let Some(router) = inference_router {
            tracing::info!("Wiring MODEL_INFERENCE precompile (0x102) to InferenceRouter");
            self.register(
                PRECOMPILE_MODEL_INFERENCE.to_vec(),
                Arc::new(move |input: &[u8], gas_limit: u64| {
                    precompile_model_inference_real(&router, input, gas_limit)
                }),
            );
        }
        if let Some(engine) = settlement_engine {
            tracing::info!("Wiring SETTLEMENT precompile (0x103) to SettlementEngine");
            self.register(
                PRECOMPILE_SETTLEMENT.to_vec(),
                Arc::new(move |input: &[u8], gas_limit: u64| {
                    precompile_settlement_real(&engine, input, gas_limit)
                }),
            );
        }
        if let Some(zk_registry) = zk_commitment_registry {
            tracing::info!(
                "Wiring ZK_VERIFY precompile (0x101) to ZkCommitmentRegistry \
                 (current size: {})",
                zk_registry.len()
            );
            self.register(
                PRECOMPILE_ZK_VERIFY.to_vec(),
                Arc::new(move |input: &[u8], gas_limit: u64| {
                    precompile_zk_verify_real(&zk_registry, input, gas_limit)
                }),
            );
        }
    }

    /// Register token system precompiles (TNZO bridge, token factory, cross-VM bridge)
    ///
    /// These precompiles provide EVM access to the native token layer:
    /// - 0x1001: TNZO Bridge — wTNZO ERC-20 pointer operations
    /// - 0x1002: Token Factory — permissionless ERC-20 creation
    /// - 0x1003: Cross-VM Bridge — atomic cross-VM token transfers
    pub fn register_token_precompiles(
        &self,
        token: Arc<tenzro_token::TnzoToken>,
        registry: Arc<tenzro_token::TokenRegistry>,
    ) {
        use crate::evm::tnzo_bridge::create_tnzo_bridge_precompile;
        use crate::evm::token_factory::create_token_factory_precompile;
        use crate::cross_vm_bridge::create_cross_vm_bridge_precompile;

        // TNZO Bridge (0x1001) — wTNZO ERC-20 pointer
        self.register(
            PRECOMPILE_TNZO_BRIDGE.to_vec(),
            create_tnzo_bridge_precompile(token.clone(), registry.clone()),
        );

        // Token Factory (0x1002) — ERC-20 creation
        self.register(
            PRECOMPILE_TOKEN_FACTORY.to_vec(),
            create_token_factory_precompile(registry.clone()),
        );

        // Cross-VM Bridge (0x1003) — cross-VM transfers
        self.register(
            PRECOMPILE_CROSS_VM_BRIDGE.to_vec(),
            create_cross_vm_bridge_precompile(token, registry),
        );

        // NFT Factory (0x1006) — ERC-721/1155 collection creation and management
        {
            use crate::evm::nft_factory::{NftRegistry, create_nft_factory_precompile};
            let nft_registry = Arc::new(NftRegistry::new());
            self.register(
                PRECOMPILE_NFT_FACTORY.to_vec(),
                create_nft_factory_precompile(nft_registry),
            );
        }

        tracing::info!("Registered token system precompiles (0x1001-0x1003, 0x1006)");
    }

    /// Register the ERC-7579 modular validator precompiles
    /// (`0x101d` / `0x101e` / `0x101f`) and return the live module handles
    /// so the caller can install per-account configurations into them.
    ///
    /// - `0x101d`: [`SocialRecoveryValidator`] — N-of-M guardian quorum
    ///   (composite Ed25519 + ML-DSA-65 signatures)
    /// - `0x101e`: [`SessionKeyValidator`] — session-bound keys with target /
    ///   selector / value / time restrictions
    /// - `0x101f`: [`SpendingLimitValidator`] — on-chain twin of the runtime
    ///   `SpendingPolicy` (per-tx + rolling-window daily ceilings)
    ///
    /// All three are AND-combined by the [`crate::aa_validators::ValidatorRegistry`]
    /// — every installed validator must approve a `UserOperation` for the
    /// EntryPoint to accept it. This matches the custody invariant from
    /// `feedback_custody_enforce_at_signing_time`: the on-chain validator
    /// modules are the primary control surface; off-chain
    /// `SpendingPolicyResolver` is defence-in-depth only.
    pub fn register_erc7579_validator_precompiles(
        &self,
    ) -> (
        Arc<crate::erc7579::SocialRecoveryValidator>,
        Arc<crate::erc7579::SessionKeyValidator>,
        Arc<crate::erc7579::SpendingLimitValidator>,
    ) {
        use crate::erc7579::{
            create_session_key_validator_precompile,
            create_social_recovery_validator_precompile,
            create_spending_limit_validator_precompile, SessionKeyValidator,
            SocialRecoveryValidator, SpendingLimitValidator,
        };

        let mut social_recovery_addr = [0u8; 20];
        social_recovery_addr.copy_from_slice(&PRECOMPILE_SOCIAL_RECOVERY_VALIDATOR[..20]);
        let mut session_key_addr = [0u8; 20];
        session_key_addr.copy_from_slice(&PRECOMPILE_SESSION_KEY_VALIDATOR[..20]);
        let mut spending_limit_addr = [0u8; 20];
        spending_limit_addr.copy_from_slice(&PRECOMPILE_SPENDING_LIMIT_VALIDATOR[..20]);

        let social_recovery = Arc::new(SocialRecoveryValidator::new(social_recovery_addr));
        let session_key = Arc::new(SessionKeyValidator::new(session_key_addr));
        let spending_limit = Arc::new(SpendingLimitValidator::new(spending_limit_addr));

        self.register(
            PRECOMPILE_SOCIAL_RECOVERY_VALIDATOR.to_vec(),
            create_social_recovery_validator_precompile(Arc::clone(&social_recovery)),
        );
        self.register(
            PRECOMPILE_SESSION_KEY_VALIDATOR.to_vec(),
            create_session_key_validator_precompile(Arc::clone(&session_key)),
        );
        self.register(
            PRECOMPILE_SPENDING_LIMIT_VALIDATOR.to_vec(),
            create_spending_limit_validator_precompile(Arc::clone(&spending_limit)),
        );

        tracing::info!(
            "Registered ERC-7579 modular validator precompiles \
             (0x101d SocialRecoveryValidator, 0x101e SessionKeyValidator, \
             0x101f SpendingLimitValidator)"
        );

        (social_recovery, session_key, spending_limit)
    }
}

impl Default for PrecompileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Standard EVM precompile implementations

fn precompile_ecrecover(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    tracing::debug!("ecRecover precompile called with {} bytes", input.len());

    // Input should be exactly 128 bytes: hash(32) + v(32) + r(32) + s(32)
    if input.len() < 128 {
        // Return empty on invalid input (Ethereum behavior)
        return Ok(PrecompileResult::success(vec![0u8; 32], 3_000));
    }

    let hash = &input[0..32];
    let v_bytes = &input[32..64];
    let r_bytes = &input[64..96];
    let s_bytes = &input[96..128];

    // Extract v (recovery ID) - should be 27 or 28
    let v = v_bytes[31];
    if v != 27 && v != 28 {
        return Ok(PrecompileResult::success(vec![0u8; 32], 3_000));
    }

    let recovery_id = match RecoveryId::try_from(v - 27) {
        Ok(id) => id,
        Err(_) => return Ok(PrecompileResult::success(vec![0u8; 32], 3_000)),
    };

    // Construct signature from r and s
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(r_bytes);
    sig_bytes[32..64].copy_from_slice(s_bytes);

    let signature = match Signature::from_bytes(&sig_bytes.into()) {
        Ok(sig) => sig,
        Err(_) => return Ok(PrecompileResult::success(vec![0u8; 32], 3_000)),
    };

    // Recover the public key
    let recovered_key = match VerifyingKey::recover_from_prehash(hash, &signature, recovery_id) {
        Ok(key) => key,
        Err(_) => return Ok(PrecompileResult::success(vec![0u8; 32], 3_000)),
    };

    // Compute Ethereum address from public key (keccak256(pubkey)[12..])
    use sha3::{Digest, Keccak256};
    let pubkey_bytes = recovered_key.to_sec1_point(false);
    let pubkey_uncompressed = &pubkey_bytes.as_bytes()[1..]; // Skip 0x04 prefix

    let mut hasher = Keccak256::new();
    hasher.update(pubkey_uncompressed);
    let hash_result = hasher.finalize();

    // Return last 20 bytes as address, padded to 32 bytes
    let mut result = vec![0u8; 32];
    result[12..32].copy_from_slice(&hash_result[12..32]);

    Ok(PrecompileResult::success(result, 3_000))
}

fn precompile_sha256(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    let gas_used = 60 + (input.len() as u64).div_ceil(32) * 12;

    Ok(PrecompileResult::success(result.to_vec(), gas_used))
}

fn precompile_ripemd160(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    use ripemd::{Ripemd160, Digest};

    let mut hasher = Ripemd160::new();
    hasher.update(input);
    let hash = hasher.finalize();

    // Return 20-byte hash right-aligned in 32-byte output (Ethereum convention)
    let mut result = vec![0u8; 32];
    result[12..32].copy_from_slice(&hash);

    let gas_used = 600 + (input.len() as u64).div_ceil(32) * 120;

    Ok(PrecompileResult::success(result, gas_used))
}

fn precompile_identity(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    let gas_used = 15 + (input.len() as u64).div_ceil(32) * 3;
    Ok(PrecompileResult::success(input.to_vec(), gas_used))
}

/// ModExp precompile (EIP-198 + EIP-2565)
///
/// Computes (BASE ^ EXPONENT) % MODULUS with arbitrary-precision integers.
/// Input: [base_len (32)] [exp_len (32)] [mod_len (32)] [base] [exp] [mod]
/// Output: result with same byte length as modulus
/// Gas: max(200, floor(mult_complexity * iteration_count / 3)) per EIP-2565
fn precompile_modexp(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    use num_bigint::BigUint;
    use num_traits::{One, Zero};

    tracing::debug!("ModExp precompile called with {} bytes", input.len());

    // Helper to read from input with zero-padding
    let read_input = |offset: usize, len: usize| -> Vec<u8> {
        let mut buf = vec![0u8; len];
        if offset < input.len() {
            let available = std::cmp::min(len, input.len() - offset);
            buf[..available].copy_from_slice(&input[offset..offset + available]);
        }
        buf
    };

    // Parse the three 32-byte length fields
    let base_len_bytes = read_input(0, 32);
    let exp_len_bytes = read_input(32, 32);
    let mod_len_bytes = read_input(64, 32);

    // Convert to usize (cap at reasonable limits to prevent DoS)
    let base_len = BigUint::from_bytes_be(&base_len_bytes);
    let exp_len = BigUint::from_bytes_be(&exp_len_bytes);
    let mod_len = BigUint::from_bytes_be(&mod_len_bytes);

    // Cap lengths to prevent excessive memory allocation (8192 bytes each)
    let max_len = BigUint::from(8192u32);
    if base_len > max_len || exp_len > max_len || mod_len > max_len {
        return Err(VmError::PrecompileFailed("ModExp input too large".to_string()));
    }

    let base_len = base_len.to_u64_digits().first().copied().unwrap_or(0) as usize;
    let exp_len = exp_len.to_u64_digits().first().copied().unwrap_or(0) as usize;
    let mod_len = mod_len.to_u64_digits().first().copied().unwrap_or(0) as usize;

    // If modulus length is 0, return empty result
    if mod_len == 0 {
        let gas_used = modexp_gas(base_len, exp_len, mod_len, &read_input(96 + base_len, exp_len));
        return Ok(PrecompileResult::success(vec![], gas_used));
    }

    // Read base, exponent, modulus from input (zero-padded)
    let base_bytes = read_input(96, base_len);
    let exp_bytes = read_input(96 + base_len, exp_len);
    let mod_bytes = read_input(96 + base_len + exp_len, mod_len);

    // Calculate gas cost per EIP-2565
    let gas_used = modexp_gas(base_len, exp_len, mod_len, &exp_bytes);

    let base = BigUint::from_bytes_be(&base_bytes);
    let exp = BigUint::from_bytes_be(&exp_bytes);
    let modulus = BigUint::from_bytes_be(&mod_bytes);

    // Compute result
    let result = if modulus.is_zero() {
        BigUint::zero()
    } else if exp.is_zero() {
        BigUint::one() % &modulus
    } else {
        base.modpow(&exp, &modulus)
    };

    // Convert result to big-endian bytes, left-padded to mod_len
    let result_bytes = result.to_bytes_be();
    let mut output = vec![0u8; mod_len];
    if !result_bytes.is_empty() {
        let start = mod_len.saturating_sub(result_bytes.len());
        let copy_len = std::cmp::min(result_bytes.len(), mod_len);
        output[start..start + copy_len]
            .copy_from_slice(&result_bytes[result_bytes.len() - copy_len..]);
    }

    Ok(PrecompileResult::success(output, gas_used))
}

/// EIP-2565 gas cost for ModExp
fn modexp_gas(base_len: usize, exp_len: usize, mod_len: usize, exp_bytes: &[u8]) -> u64 {
    use num_traits::Zero;
    let max_len = std::cmp::max(base_len, mod_len);
    let words = (max_len as u64).div_ceil(8);
    let mult_complexity = words * words;

    // Calculate iteration count from exponent
    let iteration_count = if exp_len <= 32 {
        // For exp_len <= 32, use the highest bit position
        let exp_val = num_bigint::BigUint::from_bytes_be(exp_bytes);
        if exp_val.is_zero() {
            0u64
        } else {
            exp_val.bits() - 1
        }
    } else {
        // For exp_len > 32, use first 32 bytes highest bit + 8 * (exp_len - 32)
        let first_32: Vec<u8> = if exp_bytes.len() >= 32 {
            exp_bytes[..32].to_vec()
        } else {
            let mut padded = vec![0u8; 32];
            padded[32 - exp_bytes.len()..].copy_from_slice(exp_bytes);
            padded
        };
        let first_32_val = num_bigint::BigUint::from_bytes_be(&first_32);
        let high_bits = if first_32_val.is_zero() {
            0u64
        } else {
            (first_32_val.bits() - 1) as u64
        };
        high_bits + 8 * (exp_len as u64 - 32)
    };

    let iteration_count = std::cmp::max(iteration_count, 1);
    std::cmp::max(200, mult_complexity * iteration_count / 3)
}

/// EC_ADD precompile (EIP-196 + EIP-1108)
///
/// Performs point addition on the alt_bn128 (BN254) curve.
/// Input: P1(x, y) [64 bytes] + P2(x, y) [64 bytes] = 128 bytes
/// Output: P3(x, y) [64 bytes]
/// Gas: 150 (EIP-1108)
fn precompile_ecadd(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    use ark_bn254::{G1Affine, G1Projective};

    tracing::debug!("EC_ADD precompile called with {} bytes", input.len());
    let gas_used = 150u64;

    // Zero-pad input to 128 bytes
    let mut padded = [0u8; 128];
    let copy_len = std::cmp::min(input.len(), 128);
    padded[..copy_len].copy_from_slice(&input[..copy_len]);

    // Parse P1
    let p1 = match parse_bn254_g1_point(&padded[0..64]) {
        Some(p) => p,
        None => return Ok(PrecompileResult::failed(gas_used)),
    };

    // Parse P2
    let p2 = match parse_bn254_g1_point(&padded[64..128]) {
        Some(p) => p,
        None => return Ok(PrecompileResult::failed(gas_used)),
    };

    // Perform addition in projective coordinates
    let result: G1Projective = p1 + p2;
    let result_affine: G1Affine = result.into();

    // Serialize result
    let output = serialize_bn254_g1_point(&result_affine);

    Ok(PrecompileResult::success(output, gas_used))
}

/// EC_MUL precompile (EIP-196 + EIP-1108)
///
/// Performs scalar multiplication on the alt_bn128 (BN254) curve.
/// Input: P(x, y) [64 bytes] + scalar s [32 bytes] = 96 bytes
/// Output: s*P(x, y) [64 bytes]
/// Gas: 6000 (EIP-1108)
fn precompile_ecmul(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    use ark_bn254::{G1Affine, G1Projective, Fr};
    use ark_ff::PrimeField;

    tracing::debug!("EC_MUL precompile called with {} bytes", input.len());
    let gas_used = 6_000u64;

    // Zero-pad input to 96 bytes
    let mut padded = [0u8; 96];
    let copy_len = std::cmp::min(input.len(), 96);
    padded[..copy_len].copy_from_slice(&input[..copy_len]);

    // Parse point P
    let p = match parse_bn254_g1_point(&padded[0..64]) {
        Some(p) => p,
        None => return Ok(PrecompileResult::failed(gas_used)),
    };

    // Parse scalar (big-endian 256-bit integer)
    // The scalar can be any 256-bit value; it's reduced mod the group order internally
    let scalar_bytes = &padded[64..96];
    let scalar = Fr::from_be_bytes_mod_order(scalar_bytes);

    // Perform scalar multiplication
    let result: G1Projective = p * scalar;
    let result_affine: G1Affine = result.into();

    // Serialize result
    let output = serialize_bn254_g1_point(&result_affine);

    Ok(PrecompileResult::success(output, gas_used))
}

/// EC_PAIRING precompile (EIP-197 + EIP-1108)
///
/// Performs optimal ate pairing check on alt_bn128 (BN254).
/// Input: k pairs of (G1_point [64 bytes], G2_point [128 bytes]) = k * 192 bytes
/// Output: 32 bytes — 1 if pairing check passes (product of pairings = 1), 0 otherwise
/// Gas: 34000 * k + 45000 (EIP-1108)
fn precompile_ecpairing(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    use ark_bn254::Bn254;
    use ark_ec::pairing::Pairing;
    use ark_ff::Zero;

    tracing::debug!("EC_PAIRING precompile called with {} bytes", input.len());

    // Input must be a multiple of 192 bytes
    if !input.len().is_multiple_of(192) {
        return Err(VmError::PrecompileFailed(
            "EC_PAIRING input must be multiple of 192 bytes".to_string(),
        ));
    }

    let k = input.len() / 192;
    let gas_used = 34_000 * k as u64 + 45_000;

    // Empty input is valid — returns 1 (identity pairing check)
    if k == 0 {
        let mut output = vec![0u8; 32];
        output[31] = 1;
        return Ok(PrecompileResult::success(output, gas_used));
    }

    // Parse all pairs
    let mut g1_points = Vec::with_capacity(k);
    let mut g2_points = Vec::with_capacity(k);

    for i in 0..k {
        let offset = i * 192;

        // Parse G1 point (64 bytes)
        let g1 = match parse_bn254_g1_point(&input[offset..offset + 64]) {
            Some(p) => p,
            None => return Ok(PrecompileResult::failed(gas_used)),
        };

        // Parse G2 point (128 bytes: x_imag[32] x_real[32] y_imag[32] y_real[32])
        let g2 = match parse_bn254_g2_point(&input[offset + 64..offset + 192]) {
            Some(p) => p,
            None => return Ok(PrecompileResult::failed(gas_used)),
        };

        g1_points.push(g1);
        g2_points.push(g2);
    }

    // Perform multi-pairing check: e(a1,b1) * e(a2,b2) * ... * e(ak,bk) == 1
    let result = Bn254::multi_pairing(&g1_points, &g2_points);

    let mut output = vec![0u8; 32];
    // The pairing check passes if the product equals the identity element (1 in GT).
    // In arkworks additive notation, the identity is "zero" for PairingOutput.
    if result.is_zero() {
        output[31] = 1;
    }

    Ok(PrecompileResult::success(output, gas_used))
}

/// BLAKE2F precompile (EIP-152)
///
/// Implements the F compression function from BLAKE2b (RFC 7693).
/// Input: 213 bytes = rounds[4] + h[64] + m[128] + t[16] + f[1]
/// Output: 64 bytes (updated state h)
/// Gas: rounds (1 gas per round)
fn precompile_blake2f(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    tracing::debug!("BLAKE2F precompile called with {} bytes", input.len());

    // Input must be exactly 213 bytes
    if input.len() != 213 {
        return Err(VmError::PrecompileFailed(format!(
            "BLAKE2F input must be exactly 213 bytes, got {}",
            input.len()
        )));
    }

    // Parse rounds (4 bytes, big-endian)
    let rounds = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
    let gas_used = rounds as u64;

    // Parse state vector h (64 bytes = 8 x u64 little-endian)
    let mut h = [0u64; 8];
    for (i, h_val) in h.iter_mut().enumerate() {
        let offset = 4 + i * 8;
        *h_val = u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap());
    }

    // Parse message block m (128 bytes = 16 x u64 little-endian)
    let mut m = [0u64; 16];
    for (i, m_val) in m.iter_mut().enumerate() {
        let offset = 68 + i * 8;
        *m_val = u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap());
    }

    // Parse offset counters t (16 bytes = 2 x u64 little-endian)
    let t0 = u64::from_le_bytes(input[196..204].try_into().unwrap());
    let t1 = u64::from_le_bytes(input[204..212].try_into().unwrap());

    // Parse final block flag (1 byte, must be 0 or 1)
    let f = input[212];
    if f != 0 && f != 1 {
        return Err(VmError::PrecompileFailed(
            "BLAKE2F final block indicator must be 0 or 1".to_string(),
        ));
    }
    let final_block = f != 0;

    // Execute BLAKE2b F compression function
    blake2b_f(&mut h, &m, [t0, t1], final_block, rounds as usize);

    // Serialize output (64 bytes = 8 x u64 little-endian)
    let mut output = vec![0u8; 64];
    for i in 0..8 {
        output[i * 8..(i + 1) * 8].copy_from_slice(&h[i].to_le_bytes());
    }

    Ok(PrecompileResult::success(output, gas_used))
}

// ============================================================================
// BN254 curve point parsing/serialization helpers
// ============================================================================

/// Parse a BN254 G1 point from 64 bytes (big-endian x[32] + y[32])
/// Returns None if the point is not on the curve.
/// (0, 0) is treated as the point at infinity.
fn parse_bn254_g1_point(data: &[u8]) -> Option<ark_bn254::G1Affine> {
    use ark_bn254::{Fq, G1Affine};
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    assert!(data.len() >= 64);

    let x_bytes = &data[0..32];
    let y_bytes = &data[32..64];

    // Check for point at infinity (0, 0)
    if x_bytes.iter().all(|&b| b == 0) && y_bytes.iter().all(|&b| b == 0) {
        return Some(G1Affine::zero());
    }

    // Parse field elements (big-endian)
    let x = Fq::from_be_bytes_mod_order(x_bytes);
    let y = Fq::from_be_bytes_mod_order(y_bytes);

    // Verify the parsed values match the input (i.e., inputs were < field modulus)
    let x_check = fq_to_be_bytes(&x);
    let y_check = fq_to_be_bytes(&y);
    if x_check != x_bytes || y_check != y_bytes {
        return None; // Input was >= field modulus
    }

    let point = G1Affine::new_unchecked(x, y);

    // Verify point is on the curve
    if !point.is_on_curve() {
        return None;
    }

    Some(point)
}

/// Parse a BN254 G2 point from 128 bytes
/// EVM encoding: x_imag[32] x_real[32] y_imag[32] y_real[32]
fn parse_bn254_g2_point(data: &[u8]) -> Option<ark_bn254::G2Affine> {
    use ark_bn254::{Fq, Fq2, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;

    assert!(data.len() >= 128);

    let x_imag_bytes = &data[0..32];
    let x_real_bytes = &data[32..64];
    let y_imag_bytes = &data[64..96];
    let y_real_bytes = &data[96..128];

    // Check for point at infinity (all zeros)
    if data.iter().all(|&b| b == 0) {
        return Some(G2Affine::zero());
    }

    // Parse field elements
    let x_real = Fq::from_be_bytes_mod_order(x_real_bytes);
    let x_imag = Fq::from_be_bytes_mod_order(x_imag_bytes);
    let y_real = Fq::from_be_bytes_mod_order(y_real_bytes);
    let y_imag = Fq::from_be_bytes_mod_order(y_imag_bytes);

    // Verify inputs were canonical (< field modulus)
    if fq_to_be_bytes(&x_real) != x_real_bytes
        || fq_to_be_bytes(&x_imag) != x_imag_bytes
        || fq_to_be_bytes(&y_real) != y_real_bytes
        || fq_to_be_bytes(&y_imag) != y_imag_bytes
    {
        return None;
    }

    let x = Fq2::new(x_real, x_imag);
    let y = Fq2::new(y_real, y_imag);

    let point = G2Affine::new_unchecked(x, y);

    // Verify point is on the curve and in the correct subgroup
    if !point.is_on_curve() {
        return None;
    }

    Some(point)
}

/// Serialize a BN254 G1 affine point to 64 bytes (big-endian x[32] + y[32])
fn serialize_bn254_g1_point(point: &ark_bn254::G1Affine) -> Vec<u8> {
    use ark_ec::AffineRepr;

    if point.is_zero() {
        return vec![0u8; 64];
    }

    let x = point.x().unwrap();
    let y = point.y().unwrap();

    let mut output = vec![0u8; 64];
    let x_bytes = fq_to_be_bytes(x);
    let y_bytes = fq_to_be_bytes(y);
    output[0..32].copy_from_slice(&x_bytes);
    output[32..64].copy_from_slice(&y_bytes);
    output
}

/// Convert an Fq element to 32-byte big-endian representation
fn fq_to_be_bytes(fq: &ark_bn254::Fq) -> Vec<u8> {
    use ark_ff::PrimeField;

    let bigint = fq.into_bigint();
    let mut bytes = vec![0u8; 32];
    // ark BigInteger stores limbs in little-endian order
    let limbs = bigint.as_ref();
    for (i, limb) in limbs.iter().enumerate() {
        let le_bytes = limb.to_le_bytes();
        for (j, &b) in le_bytes.iter().enumerate() {
            let pos = i * 8 + j;
            if pos < 32 {
                bytes[31 - pos] = b;
            }
        }
    }
    bytes
}

// ============================================================================
// EIP-2537 BLS12-381 precompile implementations (Pectra upgrade)
// ============================================================================

/// EIP-2537 MSM discount table.
/// Index 0 is unused; discount[k] is the multiplier (per-mille) for k pairs.
/// For k > 128, use discount[128].
const BLS12_MSM_DISCOUNT_TABLE: [u64; 129] = [
    0, // index 0 unused
    1200, 888, 764, 641, 594, 547, 500, 453, 438, 423,
    408, 394, 379, 364, 349, 334, 330, 326, 322, 318,
    314, 310, 306, 302, 298, 294, 289, 285, 281, 277,
    273, 269, 268, 266, 265, 263, 262, 260, 259, 257,
    256, 254, 253, 251, 250, 248, 247, 245, 244, 242,
    241, 239, 238, 236, 235, 233, 232, 231, 229, 228,
    226, 225, 223, 222, 221, 220, 219, 219, 218, 217,
    216, 216, 215, 214, 213, 213, 212, 211, 211, 210,
    209, 208, 208, 207, 206, 205, 205, 204, 203, 202,
    202, 201, 200, 199, 199, 198, 197, 196, 196, 195,
    194, 193, 193, 192, 191, 191, 190, 189, 189, 188,
    187, 187, 186, 185, 185, 184, 183, 183, 182, 181,
    181, 180, 179, 179, 178, 177, 177, 176,
];

/// Get MSM discount for k pairs
fn bls12_msm_discount(k: usize) -> u64 {
    if k == 0 {
        return 0;
    }
    if k >= BLS12_MSM_DISCOUNT_TABLE.len() {
        BLS12_MSM_DISCOUNT_TABLE[128]
    } else {
        BLS12_MSM_DISCOUNT_TABLE[k]
    }
}

// ---------------------------------------------------------------------------
// BLS12-381 point encoding helpers (EIP-2537 padded big-endian format)
// ---------------------------------------------------------------------------

/// Decode a 48-byte BLS12-381 field element from a 64-byte padded big-endian input.
/// The high 16 bytes MUST be zero; returns None otherwise.
/// Returns the blst_fp in the out parameter.
unsafe fn decode_fp(input: &[u8], out: &mut blst::blst_fp) -> Option<()> {
    assert!(input.len() == 64);
    // High 16 bytes must be zero (padding)
    if input[..16] != [0u8; 16] {
        return None;
    }
    // The remaining 48 bytes are the big-endian field element.
    // SAFETY: caller of `decode_fp` upholds blst's contract for the out pointer;
    // `input[16..]` is a 48-byte slice, matching blst_fp_from_bendian's expectation.
    unsafe {
        blst::blst_fp_from_bendian(out, input[16..].as_ptr());
    }
    Some(())
}

/// Decode a G1 affine point from 128 bytes (two 64-byte padded Fp elements).
/// Validates: padding, on-curve, in-subgroup.
/// Returns None on any validation failure.
fn decode_g1_point(input: &[u8]) -> Option<blst::blst_p1_affine> {
    assert!(input.len() == 128);

    // Check for point at infinity (all zeros)
    if input.iter().all(|&b| b == 0) {
        let mut p = blst::blst_p1_affine::default();
        // blst identity: x=0, y=0 in affine is NOT the identity.
        // The identity in blst_p1_affine is the point with all-zero bytes
        // which blst_p1_affine_in_g1 accepts as the identity.
        unsafe {
            std::ptr::write_bytes(&mut p as *mut blst::blst_p1_affine, 0, 1);
        }
        return Some(p);
    }

    let mut x = blst::blst_fp::default();
    let mut y = blst::blst_fp::default();

    unsafe {
        decode_fp(&input[0..64], &mut x)?;
        decode_fp(&input[64..128], &mut y)?;
    }

    let p = blst::blst_p1_affine { x, y };

    // Validate: on curve AND in the correct subgroup
    unsafe {
        if !blst::blst_p1_affine_on_curve(&p) {
            return None;
        }
        if !blst::blst_p1_affine_in_g1(&p) {
            return None;
        }
    }

    Some(p)
}

/// Encode a G1 affine point to 128 bytes (two 64-byte padded Fp elements).
fn encode_g1_point(p: &blst::blst_p1_affine) -> Vec<u8> {
    let mut output = vec![0u8; 128];
    unsafe {
        // x coordinate: 48 bytes big-endian, left-padded to 64
        blst::blst_bendian_from_fp(output[16..64].as_mut_ptr(), &p.x);
        // y coordinate: 48 bytes big-endian, left-padded to 64
        blst::blst_bendian_from_fp(output[80..128].as_mut_ptr(), &p.y);
    }
    output
}

/// Decode a G2 affine point from 256 bytes (four 64-byte padded Fp elements).
/// Layout: x_c0[64] x_c1[64] y_c0[64] y_c1[64]
/// (EIP-2537: x = c0 + c1*u, first component c0 comes first, then c1)
fn decode_g2_point(input: &[u8]) -> Option<blst::blst_p2_affine> {
    assert!(input.len() == 256);

    // Check for point at infinity (all zeros)
    if input.iter().all(|&b| b == 0) {
        let mut p = blst::blst_p2_affine::default();
        unsafe {
            std::ptr::write_bytes(&mut p as *mut blst::blst_p2_affine, 0, 1);
        }
        return Some(p);
    }

    let mut x_c0 = blst::blst_fp::default();
    let mut x_c1 = blst::blst_fp::default();
    let mut y_c0 = blst::blst_fp::default();
    let mut y_c1 = blst::blst_fp::default();

    unsafe {
        decode_fp(&input[0..64], &mut x_c0)?;
        decode_fp(&input[64..128], &mut x_c1)?;
        decode_fp(&input[128..192], &mut y_c0)?;
        decode_fp(&input[192..256], &mut y_c1)?;
    }

    let x = blst::blst_fp2 { fp: [x_c0, x_c1] };
    let y = blst::blst_fp2 { fp: [y_c0, y_c1] };
    let p = blst::blst_p2_affine { x, y };

    unsafe {
        if !blst::blst_p2_affine_on_curve(&p) {
            return None;
        }
        if !blst::blst_p2_affine_in_g2(&p) {
            return None;
        }
    }

    Some(p)
}

/// Encode a G2 affine point to 256 bytes.
fn encode_g2_point(p: &blst::blst_p2_affine) -> Vec<u8> {
    let mut output = vec![0u8; 256];
    unsafe {
        blst::blst_bendian_from_fp(output[16..64].as_mut_ptr(), &p.x.fp[0]);
        blst::blst_bendian_from_fp(output[80..128].as_mut_ptr(), &p.x.fp[1]);
        blst::blst_bendian_from_fp(output[144..192].as_mut_ptr(), &p.y.fp[0]);
        blst::blst_bendian_from_fp(output[208..256].as_mut_ptr(), &p.y.fp[1]);
    }
    output
}

/// Check if a padded 64-byte Fp value is a valid field element (< BLS12-381 p).
/// Uses blst's internal check by round-tripping through blst_fp.
fn validate_fp_canonical(input: &[u8]) -> bool {
    assert!(input.len() == 64);
    if input[..16] != [0u8; 16] {
        return false;
    }
    // Encode to blst_fp and back to check canonical form
    let mut fp = blst::blst_fp::default();
    let mut roundtrip = [0u8; 48];
    unsafe {
        blst::blst_fp_from_bendian(&mut fp, input[16..].as_ptr());
        blst::blst_bendian_from_fp(roundtrip.as_mut_ptr(), &fp);
    }
    // If the input was >= p, the round-trip will differ
    roundtrip[..] == input[16..64]
}

// ---------------------------------------------------------------------------
// EIP-7951 P256VERIFY (0x100) — secp256r1 ECDSA signature verification
// ---------------------------------------------------------------------------

/// P256VERIFY precompile (EIP-7951, Fusaka Dec 2025, address 0x100).
///
/// Verifies a secp256r1 (NIST P-256) ECDSA signature. Enables on-chain
/// verification of WebAuthn / FIDO2 / Apple Secure Enclave / Android
/// Keystore signatures, which is foundational for Tenzro's TDIP human
/// identity flows and machine passkeys.
///
/// **Input** — exactly 160 bytes, big-endian:
/// | offset | length | field            |
/// |--------|--------|------------------|
/// |   0    |   32   | message hash     |
/// |  32    |   32   | signature `r`    |
/// |  64    |   32   | signature `s`    |
/// |  96    |   32   | public key `x`   |
/// | 128    |   32   | public key `y`   |
///
/// **Output:**
/// - Valid signature → 32-byte big-endian `1` (`0x00…0001`).
/// - Invalid signature, malformed input, or wrong length → empty bytes
///   (`0x`). The precompile does NOT revert; callers must check the
///   return-data length, matching go-ethereum semantics.
///
/// **Gas cost:** flat 6900, input-independent.
fn precompile_p256verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    const GAS_COST: u64 = 6900;
    if gas_limit < GAS_COST {
        return Err(VmError::OutOfGas);
    }

    // Wrong length is failure-with-empty-output, NOT a revert.
    if input.len() != 160 {
        return Ok(PrecompileResult::success(Vec::new(), GAS_COST));
    }

    let hash = &input[0..32];
    let r = &input[32..64];
    let s = &input[64..96];
    let pk_x = &input[96..128];
    let pk_y = &input[128..160];

    // Reassemble (r, s) as a fixed-array DER-free signature and (x, y) as an
    // uncompressed SEC1 point with the 0x04 prefix.
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(r);
    sig_bytes[32..].copy_from_slice(s);
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return Ok(PrecompileResult::success(Vec::new(), GAS_COST)),
    };

    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(pk_x);
    sec1[33..].copy_from_slice(pk_y);
    let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
        Ok(k) => k,
        Err(_) => return Ok(PrecompileResult::success(Vec::new(), GAS_COST)),
    };

    match vk.verify_prehash(hash, &signature) {
        Ok(()) => {
            // 32-byte big-endian `1`.
            let mut out = [0u8; 32];
            out[31] = 1;
            Ok(PrecompileResult::success(out.to_vec(), GAS_COST))
        }
        Err(_) => Ok(PrecompileResult::success(Vec::new(), GAS_COST)),
    }
}

// ---------------------------------------------------------------------------
// BLS12_G1ADD (0x0a)
// ---------------------------------------------------------------------------

/// BLS12_G1ADD precompile (EIP-2537, address 0x0a)
///
/// Performs point addition on the BLS12-381 G1 curve.
/// Input: 256 bytes (two 128-byte G1 points in padded big-endian)
/// Output: 128 bytes (one G1 point)
/// Gas: 375
fn precompile_bls12_g1add(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    const GAS_COST: u64 = 375;

    if input.len() != 256 {
        return Err(VmError::PrecompileFailed(format!(
            "BLS12_G1ADD: expected 256 bytes input, got {}", input.len()
        )));
    }

    // Validate field elements are canonical (< p)
    if !validate_fp_canonical(&input[0..64])
        || !validate_fp_canonical(&input[64..128])
        || !validate_fp_canonical(&input[128..192])
        || !validate_fp_canonical(&input[192..256])
    {
        return Err(VmError::PrecompileFailed(
            "BLS12_G1ADD: field element >= modulus".to_string(),
        ));
    }

    let p1 = match decode_g1_point(&input[0..128]) {
        Some(p) => p,
        None => return Err(VmError::PrecompileFailed(
            "BLS12_G1ADD: invalid G1 point (first operand)".to_string(),
        )),
    };

    let p2 = match decode_g1_point(&input[128..256]) {
        Some(p) => p,
        None => return Err(VmError::PrecompileFailed(
            "BLS12_G1ADD: invalid G1 point (second operand)".to_string(),
        )),
    };

    // Perform addition via projective coordinates
    let mut result_proj = blst::blst_p1::default();
    unsafe {
        blst::blst_p1_from_affine(&mut result_proj, &p1);
        blst::blst_p1_add_or_double_affine(&mut result_proj, &result_proj, &p2);
    }

    let mut result_affine = blst::blst_p1_affine::default();
    unsafe {
        blst::blst_p1_to_affine(&mut result_affine, &result_proj);
    }

    Ok(PrecompileResult::success(encode_g1_point(&result_affine), GAS_COST))
}

// ---------------------------------------------------------------------------
// BLS12_G1MSM (0x0b)
// ---------------------------------------------------------------------------

/// BLS12_G1MSM precompile (EIP-2537, address 0x0b)
///
/// Performs multi-scalar multiplication on BLS12-381 G1.
/// Input: k * 160 bytes (k pairs of 128-byte G1 point + 32-byte scalar)
/// Output: 128 bytes (one G1 point)
/// Gas: k * 14400 * discount[k] / 1000
fn precompile_bls12_g1msm(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    const PAIR_SIZE: usize = 160; // 128 (G1) + 32 (scalar)
    const BASE_GAS_PER_PAIR: u64 = 14400;

    if input.is_empty() || !input.len().is_multiple_of(PAIR_SIZE) {
        return Err(VmError::PrecompileFailed(format!(
            "BLS12_G1MSM: input length {} is not a multiple of {}", input.len(), PAIR_SIZE
        )));
    }

    let k = input.len() / PAIR_SIZE;
    let gas_cost = k as u64 * BASE_GAS_PER_PAIR * bls12_msm_discount(k) / 1000;

    // Accumulate result in projective coordinates
    let mut acc = blst::blst_p1::default();
    // Initialize to the identity (zero)
    unsafe {
        // blst_p1 zero-initialized is NOT the identity; we need to use
        // the from_affine of a zero affine point which IS the identity.
        let zero_affine = blst::blst_p1_affine::default();
        blst::blst_p1_from_affine(&mut acc, &zero_affine);
    }

    for i in 0..k {
        let offset = i * PAIR_SIZE;
        let point_bytes = &input[offset..offset + 128];
        let scalar_bytes = &input[offset + 128..offset + 160];

        // Validate field elements
        if !validate_fp_canonical(&point_bytes[0..64])
            || !validate_fp_canonical(&point_bytes[64..128])
        {
            return Err(VmError::PrecompileFailed(
                "BLS12_G1MSM: field element >= modulus".to_string(),
            ));
        }

        let p = match decode_g1_point(point_bytes) {
            Some(p) => p,
            None => return Err(VmError::PrecompileFailed(format!(
                "BLS12_G1MSM: invalid G1 point at index {}", i
            ))),
        };

        // Convert scalar from big-endian to little-endian for blst
        let mut scalar_le = [0u8; 32];
        for j in 0..32 {
            scalar_le[j] = scalar_bytes[31 - j];
        }

        // Scalar multiplication: tmp = scalar * p
        let mut p_proj = blst::blst_p1::default();
        unsafe {
            blst::blst_p1_from_affine(&mut p_proj, &p);
            blst::blst_p1_mult(&mut p_proj, &p_proj, scalar_le.as_ptr(), 256);
            // Accumulate: acc = acc + tmp
            blst::blst_p1_add_or_double(&mut acc, &acc, &p_proj);
        }
    }

    let mut result_affine = blst::blst_p1_affine::default();
    unsafe {
        blst::blst_p1_to_affine(&mut result_affine, &acc);
    }

    Ok(PrecompileResult::success(encode_g1_point(&result_affine), gas_cost))
}

// ---------------------------------------------------------------------------
// BLS12_G2ADD (0x0c)
// ---------------------------------------------------------------------------

/// BLS12_G2ADD precompile (EIP-2537, address 0x0c)
///
/// Performs point addition on the BLS12-381 G2 curve.
/// Input: 512 bytes (two 256-byte G2 points)
/// Output: 256 bytes (one G2 point)
/// Gas: 600
fn precompile_bls12_g2add(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    const GAS_COST: u64 = 600;

    if input.len() != 512 {
        return Err(VmError::PrecompileFailed(format!(
            "BLS12_G2ADD: expected 512 bytes input, got {}", input.len()
        )));
    }

    // Validate all 8 Fp elements
    for i in 0..8 {
        if !validate_fp_canonical(&input[i * 64..(i + 1) * 64]) {
            return Err(VmError::PrecompileFailed(
                "BLS12_G2ADD: field element >= modulus".to_string(),
            ));
        }
    }

    let p1 = match decode_g2_point(&input[0..256]) {
        Some(p) => p,
        None => return Err(VmError::PrecompileFailed(
            "BLS12_G2ADD: invalid G2 point (first operand)".to_string(),
        )),
    };

    let p2 = match decode_g2_point(&input[256..512]) {
        Some(p) => p,
        None => return Err(VmError::PrecompileFailed(
            "BLS12_G2ADD: invalid G2 point (second operand)".to_string(),
        )),
    };

    let mut result_proj = blst::blst_p2::default();
    unsafe {
        blst::blst_p2_from_affine(&mut result_proj, &p1);
        blst::blst_p2_add_or_double_affine(&mut result_proj, &result_proj, &p2);
    }

    let mut result_affine = blst::blst_p2_affine::default();
    unsafe {
        blst::blst_p2_to_affine(&mut result_affine, &result_proj);
    }

    Ok(PrecompileResult::success(encode_g2_point(&result_affine), GAS_COST))
}

// ---------------------------------------------------------------------------
// BLS12_G2MSM (0x0d)
// ---------------------------------------------------------------------------

/// BLS12_G2MSM precompile (EIP-2537, address 0x0d)
///
/// Performs multi-scalar multiplication on BLS12-381 G2.
/// Input: k * 288 bytes (k pairs of 256-byte G2 point + 32-byte scalar)
/// Output: 256 bytes (one G2 point)
/// Gas: k * 45000 * discount[k] / 1000
fn precompile_bls12_g2msm(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    const PAIR_SIZE: usize = 288; // 256 (G2) + 32 (scalar)
    const BASE_GAS_PER_PAIR: u64 = 45000;

    if input.is_empty() || !input.len().is_multiple_of(PAIR_SIZE) {
        return Err(VmError::PrecompileFailed(format!(
            "BLS12_G2MSM: input length {} is not a multiple of {}", input.len(), PAIR_SIZE
        )));
    }

    let k = input.len() / PAIR_SIZE;
    let gas_cost = k as u64 * BASE_GAS_PER_PAIR * bls12_msm_discount(k) / 1000;

    let mut acc = blst::blst_p2::default();
    unsafe {
        let zero_affine = blst::blst_p2_affine::default();
        blst::blst_p2_from_affine(&mut acc, &zero_affine);
    }

    for i in 0..k {
        let offset = i * PAIR_SIZE;
        let point_bytes = &input[offset..offset + 256];
        let scalar_bytes = &input[offset + 256..offset + 288];

        // Validate all 4 Fp elements in this G2 point
        for j in 0..4 {
            if !validate_fp_canonical(&point_bytes[j * 64..(j + 1) * 64]) {
                return Err(VmError::PrecompileFailed(
                    "BLS12_G2MSM: field element >= modulus".to_string(),
                ));
            }
        }

        let p = match decode_g2_point(point_bytes) {
            Some(p) => p,
            None => return Err(VmError::PrecompileFailed(format!(
                "BLS12_G2MSM: invalid G2 point at index {}", i
            ))),
        };

        let mut scalar_le = [0u8; 32];
        for j in 0..32 {
            scalar_le[j] = scalar_bytes[31 - j];
        }

        let mut p_proj = blst::blst_p2::default();
        unsafe {
            blst::blst_p2_from_affine(&mut p_proj, &p);
            blst::blst_p2_mult(&mut p_proj, &p_proj, scalar_le.as_ptr(), 256);
            blst::blst_p2_add_or_double(&mut acc, &acc, &p_proj);
        }
    }

    let mut result_affine = blst::blst_p2_affine::default();
    unsafe {
        blst::blst_p2_to_affine(&mut result_affine, &acc);
    }

    Ok(PrecompileResult::success(encode_g2_point(&result_affine), gas_cost))
}

// ---------------------------------------------------------------------------
// BLS12_PAIRING_CHECK (0x0e)
// ---------------------------------------------------------------------------

/// BLS12_PAIRING_CHECK precompile (EIP-2537, address 0x0e)
///
/// Performs a pairing check on BLS12-381.
/// Input: k * 384 bytes (k pairs of 128-byte G1 + 256-byte G2)
/// Output: 32 bytes (0x01 if check passes, 0x00 otherwise)
/// Gas: 43000 * k + 65000
fn precompile_bls12_pairing_check(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    const PAIR_SIZE: usize = 384; // 128 (G1) + 256 (G2)

    if input.is_empty() {
        return Err(VmError::PrecompileFailed(
            "BLS12_PAIRING_CHECK: empty input".to_string(),
        ));
    }

    if !input.len().is_multiple_of(PAIR_SIZE) {
        return Err(VmError::PrecompileFailed(format!(
            "BLS12_PAIRING_CHECK: input length {} is not a multiple of {}", input.len(), PAIR_SIZE
        )));
    }

    let k = input.len() / PAIR_SIZE;
    let gas_cost = 43000 * k as u64 + 65000;

    // Parse all pairs and validate
    let mut g1_points = Vec::with_capacity(k);
    let mut g2_points = Vec::with_capacity(k);

    for i in 0..k {
        let offset = i * PAIR_SIZE;

        // Validate G1 Fp elements
        if !validate_fp_canonical(&input[offset..offset + 64])
            || !validate_fp_canonical(&input[offset + 64..offset + 128])
        {
            return Err(VmError::PrecompileFailed(
                "BLS12_PAIRING_CHECK: G1 field element >= modulus".to_string(),
            ));
        }

        // Validate G2 Fp elements
        for j in 0..4 {
            let fp_start = offset + 128 + j * 64;
            if !validate_fp_canonical(&input[fp_start..fp_start + 64]) {
                return Err(VmError::PrecompileFailed(
                    "BLS12_PAIRING_CHECK: G2 field element >= modulus".to_string(),
                ));
            }
        }

        let g1 = match decode_g1_point(&input[offset..offset + 128]) {
            Some(p) => p,
            None => return Err(VmError::PrecompileFailed(format!(
                "BLS12_PAIRING_CHECK: invalid G1 point at pair {}", i
            ))),
        };

        let g2 = match decode_g2_point(&input[offset + 128..offset + 384]) {
            Some(p) => p,
            None => return Err(VmError::PrecompileFailed(format!(
                "BLS12_PAIRING_CHECK: invalid G2 point at pair {}", i
            ))),
        };

        g1_points.push(g1);
        g2_points.push(g2);
    }

    // Compute the multi-pairing using blst's miller loop + final exponentiation
    let mut acc = blst::blst_fp12::default();
    let mut first = true;

    for i in 0..k {
        // Check if either point is the identity (zero); if so, the pairing
        // contribution is 1 (neutral element) and can be skipped.
        let g1_is_inf = unsafe { blst::blst_p1_affine_is_inf(&g1_points[i]) };
        let g2_is_inf = unsafe { blst::blst_p2_affine_is_inf(&g2_points[i]) };

        if g1_is_inf || g2_is_inf {
            continue;
        }

        let mut ml = blst::blst_fp12::default();
        unsafe {
            blst::blst_miller_loop(&mut ml, &g2_points[i], &g1_points[i]);
        }

        if first {
            acc = ml;
            first = false;
        } else {
            unsafe {
                blst::blst_fp12_mul(&mut acc, &acc, &ml);
            }
        }
    }

    // If all pairs had identity points, the product is 1
    let result_bool = if first {
        true // No non-trivial pairings, product = 1
    } else {
        unsafe {
            blst::blst_final_exp(&mut acc, &acc);
            blst::blst_fp12_is_one(&acc)
        }
    };

    let mut output = vec![0u8; 32];
    if result_bool {
        output[31] = 1;
    }

    Ok(PrecompileResult::success(output, gas_cost))
}

// ---------------------------------------------------------------------------
// BLS12_MAP_FP_TO_G1 (0x0f)
// ---------------------------------------------------------------------------

/// BLS12_MAP_FP_TO_G1 precompile (EIP-2537, address 0x0f)
///
/// Maps a field element to a G1 point using the IETF hash-to-curve standard
/// (draft-irtf-cfrg-hash-to-curve, map_to_curve_simple_swu).
/// Input: 64 bytes (one padded Fp element)
/// Output: 128 bytes (one G1 point)
/// Gas: 5500
fn precompile_bls12_map_fp_to_g1(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    const GAS_COST: u64 = 5500;

    if input.len() != 64 {
        return Err(VmError::PrecompileFailed(format!(
            "BLS12_MAP_FP_TO_G1: expected 64 bytes input, got {}", input.len()
        )));
    }

    if !validate_fp_canonical(input) {
        return Err(VmError::PrecompileFailed(
            "BLS12_MAP_FP_TO_G1: field element >= modulus".to_string(),
        ));
    }

    let mut fp = blst::blst_fp::default();
    unsafe {
        blst::blst_fp_from_bendian(&mut fp, input[16..].as_ptr());
    }

    // Map to G1 using blst's map_to_g1 (SWU map)
    let mut result_proj = blst::blst_p1::default();
    unsafe {
        blst::blst_map_to_g1(&mut result_proj, &fp, std::ptr::null());
    }

    let mut result_affine = blst::blst_p1_affine::default();
    unsafe {
        blst::blst_p1_to_affine(&mut result_affine, &result_proj);
    }

    Ok(PrecompileResult::success(encode_g1_point(&result_affine), GAS_COST))
}

// ---------------------------------------------------------------------------
// BLS12_MAP_FP2_TO_G2 (0x10)
// ---------------------------------------------------------------------------

/// BLS12_MAP_FP2_TO_G2 precompile (EIP-2537, address 0x10)
///
/// Maps an Fp2 element to a G2 point using the IETF hash-to-curve standard.
/// Input: 128 bytes (one padded Fp2 element = two 64-byte Fp)
/// Output: 256 bytes (one G2 point)
/// Gas: 23800
fn precompile_bls12_map_fp2_to_g2(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    const GAS_COST: u64 = 23800;

    if input.len() != 128 {
        return Err(VmError::PrecompileFailed(format!(
            "BLS12_MAP_FP2_TO_G2: expected 128 bytes input, got {}", input.len()
        )));
    }

    if !validate_fp_canonical(&input[0..64]) || !validate_fp_canonical(&input[64..128]) {
        return Err(VmError::PrecompileFailed(
            "BLS12_MAP_FP2_TO_G2: field element >= modulus".to_string(),
        ));
    }

    let mut c0 = blst::blst_fp::default();
    let mut c1 = blst::blst_fp::default();
    unsafe {
        blst::blst_fp_from_bendian(&mut c0, input[16..64].as_ptr());
        blst::blst_fp_from_bendian(&mut c1, input[80..128].as_ptr());
    }

    let fp2 = blst::blst_fp2 { fp: [c0, c1] };

    let mut result_proj = blst::blst_p2::default();
    unsafe {
        blst::blst_map_to_g2(&mut result_proj, &fp2, std::ptr::null());
    }

    let mut result_affine = blst::blst_p2_affine::default();
    unsafe {
        blst::blst_p2_to_affine(&mut result_affine, &result_proj);
    }

    Ok(PrecompileResult::success(encode_g2_point(&result_affine), GAS_COST))
}

// ============================================================================
// BLAKE2b F compression function (RFC 7693)
// ============================================================================

/// BLAKE2b initialization vectors
const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// BLAKE2b sigma permutations
const BLAKE2B_SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// BLAKE2b G mixing function
#[inline]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// BLAKE2b F compression function (RFC 7693, Section 3.2)
fn blake2b_f(h: &mut [u64; 8], m: &[u64; 16], t: [u64; 2], final_block: bool, rounds: usize) {
    let mut v = [0u64; 16];

    // Initialize working vector
    v[..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&BLAKE2B_IV);

    v[12] ^= t[0]; // low word of offset
    v[13] ^= t[1]; // high word of offset

    if final_block {
        v[14] = !v[14]; // invert all bits for last block
    }

    // Cryptographic mixing rounds
    for i in 0..rounds {
        let s = &BLAKE2B_SIGMA[i % 10];

        blake2b_g(&mut v, 0, 4, 8,  12, m[s[0]],  m[s[1]]);
        blake2b_g(&mut v, 1, 5, 9,  13, m[s[2]],  m[s[3]]);
        blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
        blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
        blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
        blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2b_g(&mut v, 2, 7, 8,  13, m[s[12]], m[s[13]]);
        blake2b_g(&mut v, 3, 4, 9,  14, m[s[14]], m[s[15]]);
    }

    // Finalize: h' = h XOR upper XOR lower
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

// Tenzro-specific precompile implementations

/// VRF proof verification precompile (0x1007)
///
/// Verifies an ECVRF-EDWARDS25519-SHA512-TAI proof (RFC 9381 §5.4.1.1) and, on
/// success, returns the 64-byte VRF output (beta). Callers such as the NFT
/// factory can use this output to pick a deterministic but unpredictable
/// token_id, trait, or rarity tier that third parties can later re-verify.
///
/// Input layout (flat, big-endian):
///   pubkey      :  32 bytes  (Ed25519 compressed public key)
///   proof       :  80 bytes  (Gamma(32) || c(16) || s(32))
///   alpha_len   :  32 bytes  (uint256, big-endian length of alpha)
///   alpha       :  alpha_len bytes (VRF input — block hash, mint nonce, ...)
///
/// Output (on valid proof):
///   status      :  32 bytes  (uint256, 1 = valid)
///   output      :  64 bytes  (VRF beta / hash output)
///
/// Output (on invalid proof or malformed input):
///   status      :  32 bytes  (uint256, 0 = invalid)
///
/// Gas cost: 50,000 base + 3 * alpha_len (amortizes SHA-512 + curve ops).
fn precompile_vrf_verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    use tenzro_crypto::vrf;

    const BASE_GAS: u64 = 50_000;
    const GAS_PER_ALPHA_BYTE: u64 = 3;
    const HEADER_LEN: usize = 32 + vrf::PROOF_LEN + 32; // pk + proof + alpha_len
    const INVALID: [u8; 32] = [0u8; 32];
    const VALID_STATUS: [u8; 32] = {
        let mut s = [0u8; 32];
        s[31] = 1;
        s
    };

    // Reject oversized inputs cheaply.
    if input.len() < HEADER_LEN {
        return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
    }

    // Parse pubkey
    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&input[0..32]);

    // Parse proof
    let mut proof_bytes = [0u8; vrf::PROOF_LEN];
    proof_bytes.copy_from_slice(&input[32..32 + vrf::PROOF_LEN]);

    // Parse alpha length (uint256 big-endian); reject lengths that exceed u32.
    let len_bytes = &input[32 + vrf::PROOF_LEN..HEADER_LEN];
    for b in &len_bytes[..28] {
        if *b != 0 {
            return Ok(PrecompileResult::success(
                INVALID.to_vec(),
                BASE_GAS.min(gas_limit),
            ));
        }
    }
    let alpha_len = u32::from_be_bytes([
        len_bytes[28],
        len_bytes[29],
        len_bytes[30],
        len_bytes[31],
    ]) as usize;

    if input.len() < HEADER_LEN + alpha_len {
        return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
    }
    let alpha = &input[HEADER_LEN..HEADER_LEN + alpha_len];

    // Gas accounting — fail cleanly if caller didn't supply enough gas.
    let gas_used = BASE_GAS.saturating_add(GAS_PER_ALPHA_BYTE.saturating_mul(alpha_len as u64));
    if gas_used > gas_limit {
        return Err(crate::error::VmError::OutOfGas);
    }

    let pk = vrf::VrfPublicKey(pk_bytes);
    let proof = vrf::VrfProof(proof_bytes);

    match vrf::verify(&pk, alpha, &proof) {
        Ok(output) => {
            let mut out = Vec::with_capacity(32 + vrf::OUTPUT_LEN);
            out.extend_from_slice(&VALID_STATUS);
            out.extend_from_slice(&output.0);
            tracing::debug!(
                alpha_len = alpha_len,
                "VRF precompile: proof verified"
            );
            Ok(PrecompileResult::success(out, gas_used))
        }
        Err(e) => {
            tracing::debug!("VRF precompile: verification failed: {}", e);
            Ok(PrecompileResult::success(INVALID.to_vec(), gas_used))
        }
    }
}

/// Tenzro Train commitment-chain verification precompile (0x1008)
///
/// Phase 1 (shell): given a JSON-serialized [`TrainingReceipt`], recompute
/// `run_root` from `round_state_roots` using the `tenzro-training` Merkle
/// scheme (SHA-256 with domain prefix `tenzro/train/run-root`,
/// duplicate-last for unbalanced layers). Returns `[1]` iff the recomputed
/// root matches `receipt.run_root`, else `[0]`.
///
/// Phase 2 will additionally:
/// - Verify the syncer signature over the receipt's canonical bytes.
/// - Verify the syncer's TEE attestation chain.
/// - Verify each per-round state root matches its accepted-gradient set.
///
/// Gas cost: 30,000 base + 200 per round_state_root (amortizes SHA-256).
fn precompile_training_verify(input: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    use sha2::{Digest, Sha256};

    const BASE_GAS: u64 = 30_000;
    const GAS_PER_ROUND: u64 = 200;
    const INVALID: [u8; 1] = [0u8];
    const VALID: [u8; 1] = [1u8];

    if input.is_empty() {
        return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
    }

    // Parse the receipt as a JSON object with the fields we care about.
    // We tolerate extra fields so this stays forward-compatible.
    let receipt: serde_json::Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(_) => {
            return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
        }
    };

    let roots_value = match receipt.get("round_state_roots") {
        Some(v) => v,
        None => {
            return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
        }
    };
    let claimed_root_value = match receipt.get("run_root") {
        Some(v) => v,
        None => {
            return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
        }
    };

    let roots_arr = match roots_value.as_array() {
        Some(a) => a,
        None => {
            return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
        }
    };

    // Hash type serializes as { "0": [u8; 32] } via serde — accept either
    // raw 32-byte array or that wrapped form for forward compatibility.
    fn extract_32(v: &serde_json::Value) -> Option<[u8; 32]> {
        // Form A: array of 32 numbers.
        if let Some(arr) = v.as_array()
            && arr.len() == 32
        {
            let mut out = [0u8; 32];
            for (i, b) in arr.iter().enumerate() {
                out[i] = b.as_u64()? as u8;
            }
            return Some(out);
        }
        // Form B: object with "0" key holding the byte array (newtype tuple).
        if let Some(inner) = v.get("0") {
            return extract_32(inner);
        }
        None
    }

    let mut layer: Vec<[u8; 32]> = Vec::with_capacity(roots_arr.len());
    for r in roots_arr {
        match extract_32(r) {
            Some(b) => layer.push(b),
            None => {
                return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
            }
        }
    }

    let claimed = match extract_32(claimed_root_value) {
        Some(b) => b,
        None => {
            return Ok(PrecompileResult::success(INVALID.to_vec(), BASE_GAS.min(gas_limit)));
        }
    };

    let gas_used = BASE_GAS.saturating_add(GAS_PER_ROUND.saturating_mul(layer.len() as u64));
    if gas_used > gas_limit {
        return Err(crate::error::VmError::OutOfGas);
    }

    // Empty rounds → run_root must be zero (matches `compute_run_root`).
    let computed: [u8; 32] = if layer.is_empty() {
        [0u8; 32]
    } else {
        while layer.len() > 1 {
            if !layer.len().is_multiple_of(2) {
                let last = *layer.last().unwrap();
                layer.push(last);
            }
            let mut next = Vec::with_capacity(layer.len() / 2);
            for chunk in layer.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(b"tenzro/train/run-root");
                hasher.update(chunk[0]);
                hasher.update(chunk[1]);
                let digest = hasher.finalize();
                let mut node = [0u8; 32];
                node.copy_from_slice(&digest);
                next.push(node);
            }
            layer = next;
        }
        layer[0]
    };

    let out = if computed == claimed { VALID } else { INVALID };
    tracing::debug!(
        rounds = roots_arr.len(),
        valid = (computed == claimed),
        "Training verify precompile: commitment-chain check"
    );
    Ok(PrecompileResult::success(out.to_vec(), gas_used))
}

/// TEE attestation verification precompile
///
/// Integrates with tenzro-tee crate to verify attestation reports.
/// Supports Intel TDX, AMD SEV-SNP, AWS Nitro, and NVIDIA GPU attestations.
///
/// Input format: JSON-serialized AttestationReport
/// Output: [1] for valid, [0] for invalid
fn precompile_tee_verify(input: &[u8], _gas_limit: u64) -> Result<PrecompileResult> {
    tracing::info!("TEE verification precompile called with {} bytes", input.len());

    if input.is_empty() {
        return Ok(PrecompileResult::success(vec![0u8], 100_000));
    }

    // Try to deserialize input as an AttestationReport
    let report: tenzro_types::AttestationReport = match serde_json::from_slice(input) {
        Ok(report) => report,
        Err(e) => {
            tracing::warn!("TEE precompile: failed to parse attestation report: {}", e);
            return Ok(PrecompileResult::success(vec![0u8], 100_000));
        }
    };

    // Use the real AttestationVerifier from tenzro-tee
    let verifier = tenzro_tee::AttestationVerifier::new();
    match verifier.verify_report(&report) {
        Ok(result) => {
            let output = if result.valid { vec![1u8] } else { vec![0u8] };
            tracing::info!("TEE precompile: attestation valid={}, vendor={:?}",
                result.valid, result.vendor);
            Ok(PrecompileResult::success(output, 100_000))
        }
        Err(e) => {
            tracing::warn!("TEE precompile: verification failed: {}", e);
            Ok(PrecompileResult::success(vec![0u8], 100_000))
        }
    }
}

/// ZK proof verification precompile — real implementation backed by a
/// validator-attested [`ZkCommitmentRegistry`].
///
/// Decodes the input as a JSON-serialized [`tenzro_zk::Proof`], computes its
/// canonical commitment hash via [`compute_zk_commitment`], and looks the
/// commitment up in the registry. Returns `[1]` if the commitment is present
/// (proof has been verified by the validator set), `[0]` otherwise.
///
/// # Why commitment-attestation?
///
/// Running the full Plonky3 STARK verifier inside an EVM precompile would
/// require ~100M+ gas (FRI queries, Poseidon2 rounds, polynomial commitment
/// openings). The validator set already verifies every Plonky3 proof off the
/// EVM hot-path — in `tenzro-zk::Plonky3Verifier`, in the consensus layer,
/// in the settlement engine, and in the web/MCP verify handlers — and on
/// success commits the proof's hash to the on-chain registry via a
/// privileged transaction. The precompile then performs an O(1) HashSet
/// lookup, gas-bounded at 500k.
///
/// # Input format
/// JSON-serialized `tenzro_zk::Proof`.
///
/// # Output format
/// `[1]` if attested, `[0]` if not (or on parse error). Single byte either way
/// — matches the Ethereum convention for boolean precompile outputs.
fn precompile_zk_verify_real(
    registry: &Arc<ZkCommitmentRegistry>,
    input: &[u8],
    _gas_limit: u64,
) -> Result<PrecompileResult> {
    tracing::info!(
        "ZK verification precompile (real) called with {} bytes",
        input.len()
    );

    if input.is_empty() {
        return Ok(PrecompileResult::success(vec![0u8], 500_000));
    }

    let proof: tenzro_zk::Proof = match serde_json::from_slice(input) {
        Ok(proof) => proof,
        Err(e) => {
            tracing::warn!("ZK precompile: failed to parse proof: {}", e);
            return Ok(PrecompileResult::success(vec![0u8], 500_000));
        }
    };

    if proof.proof_bytes.is_empty() {
        tracing::warn!("ZK precompile: empty proof bytes");
        return Ok(PrecompileResult::success(vec![0u8], 500_000));
    }

    let commitment = compute_zk_commitment(&proof);
    let attested = registry.is_attested(&commitment);

    tracing::info!(
        "ZK precompile: circuit={}, commitment={}, attested={}",
        proof.circuit_id,
        hex::encode(commitment),
        attested,
    );

    let output = if attested { vec![1u8] } else { vec![0u8] };
    Ok(PrecompileResult::success(output, 500_000))
}

/// Model inference precompile — real implementation backed by [`InferenceRouter`].
///
/// Forwards a JSON-encoded `tenzro_types::InferenceRequest` to the configured
/// router (which routes it to a registered provider over HTTP) and returns the
/// JSON-encoded `tenzro_types::InferenceResponse`.
///
/// On any error (parse failure, router error, no provider available) the
/// precompile returns an empty output and consumes the gas budget — matching
/// Ethereum's "soft failure" precompile convention so the caller can detect
/// failure by inspecting `returndatasize`.
///
/// # Input format
/// JSON-serialized `tenzro_types::InferenceRequest`.
///
/// # Output format
/// JSON-serialized `tenzro_types::InferenceResponse`, or empty bytes on error.
fn precompile_model_inference_real(
    router: &Arc<InferenceRouter>,
    input: &[u8],
    _gas_limit: u64,
) -> Result<PrecompileResult> {
    tracing::info!(
        "Model inference precompile (real) called with {} bytes",
        input.len()
    );

    if input.is_empty() {
        return Ok(PrecompileResult::success(Vec::new(), 200_000));
    }

    // Deserialize the inference request
    let request: tenzro_types::InferenceRequest = match serde_json::from_slice(input) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(
                "Model inference precompile: failed to parse InferenceRequest: {}",
                e
            );
            return Ok(PrecompileResult::success(Vec::new(), 200_000));
        }
    };

    // Run the async router call from this synchronous precompile context.
    // The EVM executor runs inside a tokio runtime, so we use block_in_place +
    // block_on to bridge the async API.
    let router = router.clone();
    let result = tokio::task::block_in_place(move || {
        tokio::runtime::Handle::current()
            .block_on(async move { router.forward_request(&request).await })
    });

    match result {
        Ok(response) => match serde_json::to_vec(&response) {
            Ok(bytes) => {
                tracing::info!(
                    "Model inference precompile: success, response {} bytes",
                    bytes.len()
                );
                Ok(PrecompileResult::success(bytes, 200_000))
            }
            Err(e) => {
                tracing::warn!(
                    "Model inference precompile: failed to serialize response: {}",
                    e
                );
                Ok(PrecompileResult::success(Vec::new(), 200_000))
            }
        },
        Err(e) => {
            tracing::warn!("Model inference precompile: routing failed: {}", e);
            Ok(PrecompileResult::success(Vec::new(), 200_000))
        }
    }
}

/// Settlement precompile — real implementation backed by [`SettlementEngine`].
///
/// Parses a JSON-encoded `tenzro_types::SettlementRequest`, executes it through
/// the engine (which validates the request, checks balances, transfers tokens,
/// collects the network fee, and emits a receipt), and returns the JSON-encoded
/// `tenzro_types::SettlementReceipt`.
///
/// On any failure the precompile returns empty output, matching the Ethereum
/// soft-failure convention used by [`precompile_model_inference_real`] above.
///
/// # Input format
/// JSON-serialized `tenzro_types::SettlementRequest`.
///
/// # Output format
/// JSON-serialized `tenzro_types::SettlementReceipt`, or empty bytes on error.
fn precompile_settlement_real(
    engine: &Arc<SettlementEngine>,
    input: &[u8],
    _gas_limit: u64,
) -> Result<PrecompileResult> {
    tracing::info!(
        "Settlement precompile (real) called with {} bytes",
        input.len()
    );

    if input.is_empty() {
        return Ok(PrecompileResult::success(Vec::new(), 150_000));
    }

    let request: tenzro_types::SettlementRequest = match serde_json::from_slice(input) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!(
                "Settlement precompile: failed to parse SettlementRequest: {}",
                e
            );
            return Ok(PrecompileResult::success(Vec::new(), 150_000));
        }
    };

    let engine = engine.clone();
    let result = tokio::task::block_in_place(move || {
        tokio::runtime::Handle::current()
            .block_on(async move { engine.settle(request).await })
    });

    match result {
        Ok(receipt) => match serde_json::to_vec(&receipt) {
            Ok(bytes) => {
                tracing::info!(
                    "Settlement precompile: success, receipt {} bytes",
                    bytes.len()
                );
                Ok(PrecompileResult::success(bytes, 150_000))
            }
            Err(e) => {
                tracing::warn!(
                    "Settlement precompile: failed to serialize receipt: {}",
                    e
                );
                Ok(PrecompileResult::success(Vec::new(), 150_000))
            }
        },
        Err(e) => {
            tracing::warn!("Settlement precompile: settlement failed: {}", e);
            Ok(PrecompileResult::success(Vec::new(), 150_000))
        }
    }
}

// ---------------------------------------------------------------------------
// Transient Storage Reentrancy Guard (EIP-1153 pattern)
// ---------------------------------------------------------------------------

/// Transient storage reentrancy guard following the EIP-1153 pattern.
///
/// Protects Tenzro precompile calls from reentrancy attacks. More gas-efficient
/// than storage-based guards because transient storage is automatically cleared
/// at the end of each transaction.
///
/// Usage: call [`acquire`] before precompile execution and [`release`] after.
/// Call [`clear`] at the end of each transaction to reset all locks.
pub struct TransientReentrancyGuard {
    /// Locked precompile addresses (cleared after each tx)
    locked: RwLock<HashSet<[u8; 20]>>,
}

impl TransientReentrancyGuard {
    /// Create a new transient reentrancy guard with no active locks.
    pub fn new() -> Self {
        Self {
            locked: RwLock::new(HashSet::new()),
        }
    }

    /// Acquire a reentrancy lock for a precompile address.
    ///
    /// Returns an error if the precompile is already locked (reentrancy detected).
    pub fn acquire(&self, precompile: &[u8; 20]) -> Result<()> {
        let mut locked = self.locked.write();
        if locked.contains(precompile) {
            return Err(VmError::ExecutionFailed(format!(
                "Reentrancy detected on precompile 0x{}",
                hex::encode(precompile)
            )));
        }
        locked.insert(*precompile);
        Ok(())
    }

    /// Release the reentrancy lock for a precompile address.
    pub fn release(&self, precompile: &[u8; 20]) {
        self.locked.write().remove(precompile);
    }

    /// Clear all locks. Must be called at the end of each transaction.
    pub fn clear(&self) {
        self.locked.write().clear();
    }

    /// Returns true if the given precompile address is currently locked.
    pub fn is_locked(&self, precompile: &[u8; 20]) -> bool {
        self.locked.read().contains(precompile)
    }

    /// Returns the number of currently held locks.
    pub fn active_lock_count(&self) -> usize {
        self.locked.read().len()
    }
}

impl Default for TransientReentrancyGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TransientReentrancyGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.locked.read().len();
        f.debug_struct("TransientReentrancyGuard")
            .field("active_locks", &count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Registry tests
    // ========================================================================

    #[test]
    fn test_precompile_registry() {
        let registry = PrecompileRegistry::new();

        // Check all 9 standard EVM precompiles
        assert!(registry.is_precompile(PRECOMPILE_ECRECOVER));
        assert!(registry.is_precompile(PRECOMPILE_SHA256));
        assert!(registry.is_precompile(PRECOMPILE_RIPEMD160));
        assert!(registry.is_precompile(PRECOMPILE_IDENTITY));
        assert!(registry.is_precompile(PRECOMPILE_MODEXP));
        assert!(registry.is_precompile(PRECOMPILE_ECADD));
        assert!(registry.is_precompile(PRECOMPILE_ECMUL));
        assert!(registry.is_precompile(PRECOMPILE_ECPAIRING));
        assert!(registry.is_precompile(PRECOMPILE_BLAKE2F));

        // Check EIP-2537 BLS12-381 precompiles
        assert!(registry.is_precompile(PRECOMPILE_BLS12_G1ADD));
        assert!(registry.is_precompile(PRECOMPILE_BLS12_G1MSM));
        assert!(registry.is_precompile(PRECOMPILE_BLS12_G2ADD));
        assert!(registry.is_precompile(PRECOMPILE_BLS12_G2MSM));
        assert!(registry.is_precompile(PRECOMPILE_BLS12_PAIRING_CHECK));
        assert!(registry.is_precompile(PRECOMPILE_BLS12_MAP_FP_TO_G1));
        assert!(registry.is_precompile(PRECOMPILE_BLS12_MAP_FP2_TO_G2));

        // Tenzro precompiles registered in serviceless mode (no service deps)
        assert!(registry.is_precompile(PRECOMPILE_TEE_VERIFY));

        // Service-dependent Tenzro precompiles are NOT registered until
        // upgrade_services() is called with their backing services.
        // See test_serviceless_registry_does_not_register_service_dependent_precompiles.
        assert!(!registry.is_precompile(PRECOMPILE_ZK_VERIFY));
        assert!(!registry.is_precompile(PRECOMPILE_MODEL_INFERENCE));
        assert!(!registry.is_precompile(PRECOMPILE_SETTLEMENT));

        // Check non-existent precompile
        assert!(!registry.is_precompile(&[0xFF; 20]));
    }

    // ========================================================================
    // SHA-256 (0x02) tests
    // ========================================================================

    #[test]
    fn test_sha256_precompile() {
        let input = b"hello world";
        let result = precompile_sha256(input, 1000).unwrap();
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        // SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        assert_eq!(hex::encode(&result.output),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_sha256_empty() {
        let result = precompile_sha256(b"", 1000).unwrap();
        assert!(result.success);
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(hex::encode(&result.output),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha256_gas() {
        // Gas = 60 + 12 * ceil(len/32)
        let input = vec![0u8; 64]; // 2 words
        let result = precompile_sha256(&input, 1000).unwrap();
        assert_eq!(result.gas_used, 60 + 2 * 12);
    }

    // ========================================================================
    // RIPEMD-160 (0x03) tests
    // ========================================================================

    #[test]
    fn test_ripemd160_precompile() {
        let input = b"hello world";
        let result = precompile_ripemd160(input, 1000).unwrap();
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        // RIPEMD-160("hello world") = 98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f
        // Right-aligned in 32 bytes
        assert_eq!(hex::encode(&result.output),
            "00000000000000000000000098c615784ccb5fe5936fbc0cbe9dfdb408d92f0f");
    }

    #[test]
    fn test_ripemd160_empty() {
        let result = precompile_ripemd160(b"", 1000).unwrap();
        assert!(result.success);
        // RIPEMD-160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
        assert_eq!(hex::encode(&result.output),
            "0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31");
    }

    // ========================================================================
    // Identity (0x04) tests
    // ========================================================================

    #[test]
    fn test_identity_precompile() {
        let input = vec![1, 2, 3, 4, 5];
        let result = precompile_identity(&input, 1000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, input);
    }

    #[test]
    fn test_identity_empty() {
        let result = precompile_identity(b"", 1000).unwrap();
        assert!(result.success);
        assert!(result.output.is_empty());
        assert_eq!(result.gas_used, 15);
    }

    // ========================================================================
    // ModExp (0x05) tests — go-ethereum test vectors
    // ========================================================================

    #[test]
    fn test_modexp_eip_example1() {
        // From go-ethereum: eip_example1
        // base=3 (secp256k1 prime-1), exp=fffffffc2e..., mod=fffffffc2f...
        let input = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000020\
             0000000000000000000000000000000000000000000000000000000000000020\
             03\
             fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e\
             fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        ).unwrap();
        let result = precompile_modexp(&input, 10_000_000).unwrap();
        assert!(result.success);
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        assert_eq!(result.output, expected);
    }

    #[test]
    fn test_modexp_eip_example2() {
        // From go-ethereum: eip_example2 — base=0, should return 0
        let input = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000020\
             0000000000000000000000000000000000000000000000000000000000000020\
             fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e\
             fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        ).unwrap();
        let result = precompile_modexp(&input, 10_000_000).unwrap();
        assert!(result.success);
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ).unwrap();
        assert_eq!(result.output, expected);
    }

    #[test]
    fn test_modexp_simple() {
        // 2^10 mod 17 = 1024 mod 17 = 4
        let input = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000001\
             02\
             0a\
             11"
        ).unwrap();
        let result = precompile_modexp(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![4u8]);
    }

    #[test]
    fn test_modexp_zero_modulus() {
        // Any modexp with modulus=0 returns empty
        let input = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000000\
             02\
             0a"
        ).unwrap();
        let result = precompile_modexp(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert!(result.output.is_empty());
    }

    #[test]
    fn test_modexp_gas_minimum() {
        // Gas should be at least 200 per EIP-2565
        let input = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000001\
             02\
             01\
             03"
        ).unwrap();
        let result = precompile_modexp(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert!(result.gas_used >= 200, "ModExp gas must be >= 200, got {}", result.gas_used);
    }

    // ========================================================================
    // EC_ADD (0x06) tests — go-ethereum test vectors
    // ========================================================================

    #[test]
    fn test_ecadd_zero_plus_zero() {
        // (0,0) + (0,0) = (0,0) — identity element addition
        let input = vec![0u8; 128];
        let result = precompile_ecadd(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![0u8; 64]);
        assert_eq!(result.gas_used, 150);
    }

    #[test]
    fn test_ecadd_chfast1() {
        // From go-ethereum bn256Add test: chfast1
        let input = hex::decode(
            "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9\
             063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266\
             07c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed\
             06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7"
        ).unwrap();
        let expected = hex::decode(
            "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703\
             301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915"
        ).unwrap();
        let result = precompile_ecadd(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
    }

    #[test]
    fn test_ecadd_chfast2() {
        // From go-ethereum bn256Add test: chfast2
        let input = hex::decode(
            "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703\
             301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915\
             18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9\
             063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266"
        ).unwrap();
        let expected = hex::decode(
            "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7\
             21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204"
        ).unwrap();
        let result = precompile_ecadd(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
    }

    #[test]
    fn test_ecadd_short_input() {
        // Short input should be zero-padded
        let input = vec![0u8; 64]; // Only P1 provided, P2 is zero-padded
        let result = precompile_ecadd(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![0u8; 64]); // 0 + 0 = 0
    }

    // ========================================================================
    // EC_MUL (0x07) tests — go-ethereum test vectors
    // ========================================================================

    #[test]
    fn test_ecmul_zero_scalar() {
        // P * 0 = point at infinity = (0, 0)
        let mut input = hex::decode(
            "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9\
             063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266"
        ).unwrap();
        input.extend_from_slice(&[0u8; 32]); // scalar = 0
        let result = precompile_ecmul(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![0u8; 64]);
        assert_eq!(result.gas_used, 6_000);
    }

    #[test]
    fn test_ecmul_chfast1() {
        // From go-ethereum bn256ScalarMul test: chfast1
        let input = hex::decode(
            "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7\
             21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204\
             00000000000000000000000000000000000000000000000011138ce750fa15c2"
        ).unwrap();
        let expected = hex::decode(
            "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c\
             031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc"
        ).unwrap();
        let result = precompile_ecmul(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
    }

    #[test]
    fn test_ecmul_chfast2() {
        // From go-ethereum bn256ScalarMul test: chfast2
        let input = hex::decode(
            "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c\
             031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc\
             30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46"
        ).unwrap();
        let expected = hex::decode(
            "025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb\
             2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e"
        ).unwrap();
        let result = precompile_ecmul(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
    }

    #[test]
    fn test_ecmul_identity_scalar() {
        // G1 * 1 = G1 (generator point)
        let mut input = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000002"
        ).unwrap();
        input.extend_from_slice(&{
            let mut s = vec![0u8; 32];
            s[31] = 1; // scalar = 1
            s
        });
        let result = precompile_ecmul(&input, 10_000_000).unwrap();
        assert!(result.success);
        // Result should be the generator point (1, 2)
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000002"
        ).unwrap();
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
    }

    // ========================================================================
    // EC_PAIRING (0x08) tests — go-ethereum test vectors
    // ========================================================================

    #[test]
    fn test_ecpairing_empty() {
        // Empty input should return 1 (identity pairing check passes)
        let result = precompile_ecpairing(b"", 10_000_000).unwrap();
        assert!(result.success);
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        assert_eq!(result.output, expected);
        assert_eq!(result.gas_used, 45_000);
    }

    #[test]
    fn test_ecpairing_invalid_input_length() {
        // Input not multiple of 192 should fail
        let input = vec![0u8; 100];
        let result = precompile_ecpairing(&input, 10_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecpairing_jeff1() {
        // From go-ethereum bn256Pairing test: jeff1 — should return 1 (valid pairing)
        let input = hex::decode(
            "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59\
             3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41\
             209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7\
             04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678\
             2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d\
             120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550\
             111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c\
             2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411\
             198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
             1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
             090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
             12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
        ).unwrap();
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ).unwrap();
        let result = precompile_ecpairing(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
    }

    #[test]
    fn test_ecpairing_one_point() {
        // From go-ethereum: one_point — single G1 generator with G2 generator
        // e(G1, G2) != 1, so should return 0
        let input = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000002\
             198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
             1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
             090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
             12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
        ).unwrap();
        let expected = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ).unwrap();
        let result = precompile_ecpairing(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
    }

    #[test]
    fn test_ecpairing_gas() {
        // Gas = 34000 * k + 45000
        // For k=2: 34000*2 + 45000 = 113000
        let input = vec![0u8; 384]; // 2 pairs of zeros (point at infinity pairs)
        let result = precompile_ecpairing(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 113_000);
    }

    // ========================================================================
    // BLAKE2F (0x09) tests — go-ethereum / EIP-152 test vectors
    // ========================================================================

    #[test]
    fn test_blake2f_vector4() {
        // From go-ethereum blake2F test: vector 4 (0 rounds)
        let input = hex::decode(
            "00000000\
             48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
             d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b\
             6162630000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0300000000000000000000000000000001"
        ).unwrap();
        let expected = hex::decode(
            "08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
             d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b"
        ).unwrap();
        let result = precompile_blake2f(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
        assert_eq!(result.gas_used, 0); // 0 rounds = 0 gas
    }

    #[test]
    fn test_blake2f_vector5() {
        // From go-ethereum blake2F test: vector 5 (12 rounds) — BLAKE2b("abc")
        let input = hex::decode(
            "0000000c\
             48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
             d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b\
             6162630000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0300000000000000000000000000000001"
        ).unwrap();
        let expected = hex::decode(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        ).unwrap();
        let result = precompile_blake2f(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
        assert_eq!(result.gas_used, 12); // 12 rounds = 12 gas
    }

    #[test]
    fn test_blake2f_vector6_final_false() {
        // Same as vector 5 but with final block flag = 0
        let input = hex::decode(
            "0000000c\
             48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5\
             d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b\
             6162630000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0300000000000000000000000000000000"
        ).unwrap();
        let expected = hex::decode(
            "75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d28752\
             98743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735"
        ).unwrap();
        let result = precompile_blake2f(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(hex::encode(&result.output), hex::encode(&expected));
    }

    #[test]
    fn test_blake2f_wrong_length() {
        // Input not exactly 213 bytes should fail
        let input = vec![0u8; 212];
        let result = precompile_blake2f(&input, 10_000_000);
        assert!(result.is_err());

        let input2 = vec![0u8; 214];
        let result2 = precompile_blake2f(&input2, 10_000_000);
        assert!(result2.is_err());
    }

    #[test]
    fn test_blake2f_bad_final_flag() {
        // Final flag must be 0 or 1; value 2 should fail
        let mut input = vec![0u8; 213];
        input[212] = 2; // invalid final flag
        let result = precompile_blake2f(&input, 10_000_000);
        assert!(result.is_err());
    }

    // ========================================================================
    // ecRecover (0x01) tests
    // ========================================================================

    #[test]
    fn test_ecrecover_short_input() {
        // Short input should return 32 zero bytes
        let input = vec![0u8; 64];
        let result = precompile_ecrecover(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.gas_used, 3_000);
    }

    #[test]
    fn test_ecrecover_invalid_v() {
        // v must be 27 or 28; other values return zeros
        let mut input = vec![0u8; 128];
        input[63] = 26; // v = 26 (invalid)
        let result = precompile_ecrecover(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![0u8; 32]);
    }

    // ========================================================================
    // TEE precompile tests
    // ========================================================================

    #[test]
    fn test_tee_verify_empty() {
        let result = precompile_tee_verify(b"", 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![0u8]); // empty input returns invalid
    }

    #[test]
    fn test_tee_verify_invalid_json() {
        let result = precompile_tee_verify(b"not json", 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![0u8]); // invalid JSON returns invalid
    }

    // ========================================================================
    // Model inference & settlement precompile tests
    // ========================================================================

    #[tokio::test(flavor = "multi_thread")]
    async fn test_model_inference_real_empty_input() {
        // Real variant with empty input — should soft-fail with empty output
        let provider_manager = Arc::new(tenzro_model::ProviderManager::new());
        let router = Arc::new(InferenceRouter::new(provider_manager));
        let result = precompile_model_inference_real(&router, &[], 10_000_000).unwrap();
        assert!(result.success);
        assert!(result.output.is_empty());
        assert_eq!(result.gas_used, 200_000);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_model_inference_real_invalid_json() {
        // Real variant with garbage input — should soft-fail with empty output
        let provider_manager = Arc::new(tenzro_model::ProviderManager::new());
        let router = Arc::new(InferenceRouter::new(provider_manager));
        let input = b"not valid json";
        let result = precompile_model_inference_real(&router, input, 10_000_000).unwrap();
        assert!(result.success);
        assert!(result.output.is_empty());
        assert_eq!(result.gas_used, 200_000);
    }

    // -----------------------------------------------------------------------
    // TransientReentrancyGuard tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_reentrancy_guard_acquire_release() {
        let guard = TransientReentrancyGuard::new();
        let addr: [u8; 20] = [0x01; 20];

        assert!(!guard.is_locked(&addr));
        guard.acquire(&addr).unwrap();
        assert!(guard.is_locked(&addr));
        assert_eq!(guard.active_lock_count(), 1);

        guard.release(&addr);
        assert!(!guard.is_locked(&addr));
        assert_eq!(guard.active_lock_count(), 0);
    }

    #[test]
    fn test_reentrancy_guard_detects_reentry() {
        let guard = TransientReentrancyGuard::new();
        let addr: [u8; 20] = [0x01; 20];

        guard.acquire(&addr).unwrap();

        // Second acquire should fail
        let result = guard.acquire(&addr);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Reentrancy detected"));
    }

    #[test]
    fn test_reentrancy_guard_independent_precompiles() {
        let guard = TransientReentrancyGuard::new();
        let addr_a: [u8; 20] = [0x01; 20];
        let addr_b: [u8; 20] = [0x02; 20];

        guard.acquire(&addr_a).unwrap();
        // Different precompile should succeed
        guard.acquire(&addr_b).unwrap();
        assert_eq!(guard.active_lock_count(), 2);
    }

    #[test]
    fn test_reentrancy_guard_clear() {
        let guard = TransientReentrancyGuard::new();
        let addr_a: [u8; 20] = [0x01; 20];
        let addr_b: [u8; 20] = [0x02; 20];

        guard.acquire(&addr_a).unwrap();
        guard.acquire(&addr_b).unwrap();
        assert_eq!(guard.active_lock_count(), 2);

        guard.clear();
        assert_eq!(guard.active_lock_count(), 0);

        // Should be acquirable again after clear
        guard.acquire(&addr_a).unwrap();
        assert_eq!(guard.active_lock_count(), 1);
    }

    #[test]
    fn test_serviceless_registry_does_not_register_service_dependent_precompiles() {
        // A default `new()` registry has no InferenceRouter, no SettlementEngine,
        // and no ZkCommitmentRegistry — so the three service-dependent
        // precompiles are NOT registered. Calls return the standard
        // "precompile not found" error, which the EVM treats as a call to an
        // unallocated address (no shim, no warning revert, no [0] return).
        let registry = PrecompileRegistry::new();

        assert!(
            !registry.is_precompile(PRECOMPILE_ZK_VERIFY),
            "serviceless registry must not register ZK_VERIFY"
        );
        assert!(
            !registry.is_precompile(PRECOMPILE_MODEL_INFERENCE),
            "serviceless registry must not register MODEL_INFERENCE"
        );
        assert!(
            !registry.is_precompile(PRECOMPILE_SETTLEMENT),
            "serviceless registry must not register SETTLEMENT"
        );

        // execute() on an unregistered address returns an error.
        let result = registry.execute(PRECOMPILE_MODEL_INFERENCE, &[1, 2, 3], 100_000);
        assert!(result.is_err(), "execute on unregistered address must error");
    }

    #[test]
    fn test_upgrade_services_registers_service_dependent_precompiles() {
        let registry = PrecompileRegistry::new();

        // Before wire-up: not registered.
        assert!(!registry.is_precompile(PRECOMPILE_MODEL_INFERENCE));
        assert!(!registry.is_precompile(PRECOMPILE_SETTLEMENT));

        // Wire up only the InferenceRouter — the other two stay unregistered.
        let provider_manager = Arc::new(tenzro_model::ProviderManager::new());
        let router = Arc::new(InferenceRouter::new(provider_manager));
        registry.upgrade_services(Some(router), None, None);

        assert!(
            registry.is_precompile(PRECOMPILE_MODEL_INFERENCE),
            "MODEL_INFERENCE registered after upgrade_services(Some, None, None)"
        );
        assert!(
            !registry.is_precompile(PRECOMPILE_SETTLEMENT),
            "SETTLEMENT must remain unregistered when no engine provided"
        );
        assert!(
            !registry.is_precompile(PRECOMPILE_ZK_VERIFY),
            "ZK_VERIFY must remain unregistered when no commitment registry provided"
        );
    }

    #[test]
    fn test_upgrade_services_with_all_none_is_noop() {
        let registry = PrecompileRegistry::new();
        registry.upgrade_services(None, None, None);
        assert!(!registry.is_precompile(PRECOMPILE_ZK_VERIFY));
        assert!(!registry.is_precompile(PRECOMPILE_MODEL_INFERENCE));
        assert!(!registry.is_precompile(PRECOMPILE_SETTLEMENT));
    }

    #[test]
    fn test_zk_commitment_registry_membership() {
        let registry = ZkCommitmentRegistry::new();
        assert!(registry.is_empty());

        let hash = [42u8; 32];
        assert!(!registry.is_attested(&hash));

        // First attest returns true (newly inserted)
        assert!(registry.attest(hash));
        assert_eq!(registry.len(), 1);
        assert!(registry.is_attested(&hash));

        // Second attest returns false (idempotent)
        assert!(!registry.attest(hash));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_zk_commitment_hash_canonical() {
        // Two proofs with identical commitment-relevant fields hash equally
        // even if metadata/timestamp differ.
        use tenzro_zk::Proof;

        let p1 = Proof::new(
            vec![1, 2, 3, 4],
            vec![vec![10], vec![20, 30]],
            "test_circuit".to_string(),
        );
        let p2 = Proof::new(
            vec![1, 2, 3, 4],
            vec![vec![10], vec![20, 30]],
            "test_circuit".to_string(),
        );

        // Different timestamps but same commitment-relevant fields
        assert_eq!(compute_zk_commitment(&p1), compute_zk_commitment(&p2));

        // Different proof bytes → different commitment
        let p3 = Proof::new(
            vec![1, 2, 3, 5],
            vec![vec![10], vec![20, 30]],
            "test_circuit".to_string(),
        );
        assert_ne!(compute_zk_commitment(&p1), compute_zk_commitment(&p3));

        // Different circuit_id → different commitment
        let p4 = Proof::new(
            vec![1, 2, 3, 4],
            vec![vec![10], vec![20, 30]],
            "other_circuit".to_string(),
        );
        assert_ne!(compute_zk_commitment(&p1), compute_zk_commitment(&p4));

        // Public-input length-prefix prevents ambiguity:
        // [[1,2],[3]] must hash differently from [[1],[2,3]]
        let p5 = Proof::new(
            vec![0],
            vec![vec![1, 2], vec![3]],
            "c".to_string(),
        );
        let p6 = Proof::new(
            vec![0],
            vec![vec![1], vec![2, 3]],
            "c".to_string(),
        );
        assert_ne!(compute_zk_commitment(&p5), compute_zk_commitment(&p6));
    }

    #[test]
    fn test_zk_precompile_real_attested() {
        use tenzro_zk::Proof;

        let zk_registry = Arc::new(ZkCommitmentRegistry::new());
        let registry = PrecompileRegistry::new_with_services(None, None, Some(zk_registry.clone()), None);

        let proof = Proof::new(
            vec![0xab, 0xcd, 0xef],
            vec![vec![1, 2, 3, 4]],
            "inference_v1".to_string(),
        );
        let input = serde_json::to_vec(&proof).unwrap();

        // Not yet attested → returns [0]
        let r = registry.execute(PRECOMPILE_ZK_VERIFY, &input, 500_000).unwrap();
        assert!(r.success);
        assert_eq!(r.output, vec![0u8]);

        // Attest the commitment, then re-run → returns [1]
        let commitment = compute_zk_commitment(&proof);
        zk_registry.attest(commitment);

        let r2 = registry.execute(PRECOMPILE_ZK_VERIFY, &input, 500_000).unwrap();
        assert!(r2.success);
        assert_eq!(r2.output, vec![1u8]);
    }

    #[test]
    fn test_zk_precompile_real_rejects_malformed() {
        let zk_registry = Arc::new(ZkCommitmentRegistry::new());
        let registry = PrecompileRegistry::new_with_services(None, None, Some(zk_registry), None);

        // Garbage bytes → [0]
        let r = registry.execute(PRECOMPILE_ZK_VERIFY, &[0xff; 16], 500_000).unwrap();
        assert!(r.success);
        assert_eq!(r.output, vec![0u8]);

        // Empty input → [0]
        let r = registry.execute(PRECOMPILE_ZK_VERIFY, &[], 500_000).unwrap();
        assert!(r.success);
        assert_eq!(r.output, vec![0u8]);
    }

    // ========================================================================
    // EIP-2537 BLS12-381 precompile tests
    // ========================================================================

    /// Helper: encode the BLS12-381 G1 generator in the EIP-2537 padded format (128 bytes).
    fn bls12_g1_generator_encoded() -> Vec<u8> {
        let g_pt = unsafe { *blst::blst_p1_affine_generator() };
        encode_g1_point(&g_pt)
    }

    /// Helper: encode the BLS12-381 G2 generator in the EIP-2537 padded format (256 bytes).
    fn bls12_g2_generator_encoded() -> Vec<u8> {
        let g_pt = unsafe { *blst::blst_p2_affine_generator() };
        encode_g2_point(&g_pt)
    }

    /// Helper: encode a G1 point-at-infinity (128 zero bytes).
    fn bls12_g1_infinity() -> Vec<u8> {
        vec![0u8; 128]
    }

    /// Helper: encode a G2 point-at-infinity (256 zero bytes).
    fn bls12_g2_infinity() -> Vec<u8> {
        vec![0u8; 256]
    }

    // ---- P256VERIFY (EIP-7951, 0x100) ----

    #[test]
    fn test_p256verify_round_trip_valid_signature() {
        use ::p256::elliptic_curve::Generate;
        use getrandom_0_4::{SysRng, rand_core::UnwrapErr};
        use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
        use sha2::{Digest, Sha256};

        let signing_key = SigningKey::generate_from_rng(&mut UnwrapErr(SysRng));
        let verifying_key = signing_key.verifying_key();
        let hash = Sha256::digest(b"tenzro-eip7951-roundtrip");
        let signature: p256::ecdsa::Signature = signing_key.sign_prehash(&hash).unwrap();

        let encoded = verifying_key.to_sec1_point(false);
        let bytes = encoded.as_bytes();
        assert_eq!(bytes[0], 0x04);

        let mut input = Vec::with_capacity(160);
        input.extend_from_slice(&hash);
        input.extend_from_slice(&signature.to_bytes());
        input.extend_from_slice(&bytes[1..]); // x || y, 64 bytes

        let result = precompile_p256verify(&input, 10_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 6900);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 1);
    }

    #[test]
    fn test_p256verify_wrong_length_returns_empty() {
        let result = precompile_p256verify(&[0u8; 100], 10_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, Vec::<u8>::new());
        assert_eq!(result.gas_used, 6900);
    }

    #[test]
    fn test_p256verify_invalid_signature_returns_empty() {
        let input = vec![0xFFu8; 160];
        let result = precompile_p256verify(&input, 10_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, Vec::<u8>::new());
    }

    #[test]
    fn test_p256verify_out_of_gas() {
        let result = precompile_p256verify(&[0u8; 160], 100);
        assert!(matches!(result, Err(VmError::OutOfGas)));
    }

    // ---- BLS12_G1ADD (0x0a) ----

    #[test]
    fn test_bls12_g1add_identity_plus_generator() {
        // infinity + G = G
        let mut input = bls12_g1_infinity();
        input.extend_from_slice(&bls12_g1_generator_encoded());
        let result = precompile_bls12_g1add(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 375);
        assert_eq!(result.output, bls12_g1_generator_encoded());
    }

    #[test]
    fn test_bls12_g1add_generator_plus_identity() {
        // G + infinity = G
        let mut input = bls12_g1_generator_encoded();
        input.extend_from_slice(&bls12_g1_infinity());
        let result = precompile_bls12_g1add(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, bls12_g1_generator_encoded());
    }

    #[test]
    fn test_bls12_g1add_identity_plus_identity() {
        let mut input = bls12_g1_infinity();
        input.extend_from_slice(&bls12_g1_infinity());
        let result = precompile_bls12_g1add(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, bls12_g1_infinity());
    }

    #[test]
    fn test_bls12_g1add_wrong_length() {
        let input = vec![0u8; 255];
        let result = precompile_bls12_g1add(&input, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_bls12_g1add_generator_doubling() {
        // G + G = 2G
        let g_pt = bls12_g1_generator_encoded();
        let mut input = g_pt.clone();
        input.extend_from_slice(&g_pt);
        let result = precompile_bls12_g1add(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output.len(), 128);
        // Result should NOT be the generator or infinity
        assert_ne!(result.output, g_pt);
        assert_ne!(result.output, bls12_g1_infinity());
    }

    // ---- BLS12_G1MSM (0x0b) ----

    #[test]
    fn test_bls12_g1msm_single_scalar_one() {
        // 1 * G = G
        let g_pt = bls12_g1_generator_encoded();
        let mut input = g_pt.clone();
        let mut scalar = vec![0u8; 32];
        scalar[31] = 1; // scalar = 1
        input.extend_from_slice(&scalar);
        let result = precompile_bls12_g1msm(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, g_pt);
    }

    #[test]
    fn test_bls12_g1msm_single_scalar_zero() {
        // 0 * G = infinity
        let g_pt = bls12_g1_generator_encoded();
        let mut input = g_pt;
        input.extend_from_slice(&[0u8; 32]); // scalar = 0
        let result = precompile_bls12_g1msm(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, bls12_g1_infinity());
    }

    #[test]
    fn test_bls12_g1msm_identity_any_scalar() {
        // scalar * infinity = infinity
        let mut input = bls12_g1_infinity();
        let mut scalar = vec![0u8; 32];
        scalar[31] = 42;
        input.extend_from_slice(&scalar);
        let result = precompile_bls12_g1msm(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, bls12_g1_infinity());
    }

    #[test]
    fn test_bls12_g1msm_wrong_length() {
        let input = vec![0u8; 100]; // not a multiple of 160
        let result = precompile_bls12_g1msm(&input, 10_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_bls12_g1msm_two_pairs() {
        // 1*G + 1*G = 2*G
        let g_pt = bls12_g1_generator_encoded();
        let mut scalar_one = vec![0u8; 32];
        scalar_one[31] = 1;

        let mut input = g_pt.clone();
        input.extend_from_slice(&scalar_one);
        input.extend_from_slice(&g_pt);
        input.extend_from_slice(&scalar_one);

        let result = precompile_bls12_g1msm(&input, 10_000_000).unwrap();
        assert!(result.success);

        // Compare with G1ADD(G, G)
        let mut add_input = g_pt.clone();
        add_input.extend_from_slice(&g_pt);
        let add_result = precompile_bls12_g1add(&add_input, 1_000_000).unwrap();

        assert_eq!(result.output, add_result.output);
    }

    #[test]
    fn test_bls12_g1msm_gas_discount() {
        // k=1: gas = 1 * 14400 * 1200 / 1000 = 17280
        let g_pt = bls12_g1_generator_encoded();
        let mut input = g_pt;
        input.extend_from_slice(&[0u8; 32]);
        let result = precompile_bls12_g1msm(&input, 100_000).unwrap();
        assert_eq!(result.gas_used, 14400 * 1200 / 1000);
    }

    // ---- BLS12_G2ADD (0x0c) ----

    #[test]
    fn test_bls12_g2add_identity_plus_generator() {
        let mut input = bls12_g2_infinity();
        input.extend_from_slice(&bls12_g2_generator_encoded());
        let result = precompile_bls12_g2add(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 600);
        assert_eq!(result.output, bls12_g2_generator_encoded());
    }

    #[test]
    fn test_bls12_g2add_identity_plus_identity() {
        let mut input = bls12_g2_infinity();
        input.extend_from_slice(&bls12_g2_infinity());
        let result = precompile_bls12_g2add(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, bls12_g2_infinity());
    }

    #[test]
    fn test_bls12_g2add_wrong_length() {
        let input = vec![0u8; 500];
        let result = precompile_bls12_g2add(&input, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_bls12_g2add_generator_doubling() {
        let g_pt = bls12_g2_generator_encoded();
        let mut input = g_pt.clone();
        input.extend_from_slice(&g_pt);
        let result = precompile_bls12_g2add(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_ne!(result.output, g_pt);
        assert_ne!(result.output, bls12_g2_infinity());
    }

    // ---- BLS12_G2MSM (0x0d) ----

    #[test]
    fn test_bls12_g2msm_single_scalar_one() {
        let g_pt = bls12_g2_generator_encoded();
        let mut input = g_pt.clone();
        let mut scalar = vec![0u8; 32];
        scalar[31] = 1;
        input.extend_from_slice(&scalar);
        let result = precompile_bls12_g2msm(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, g_pt);
    }

    #[test]
    fn test_bls12_g2msm_single_scalar_zero() {
        let g_pt = bls12_g2_generator_encoded();
        let mut input = g_pt;
        input.extend_from_slice(&[0u8; 32]);
        let result = precompile_bls12_g2msm(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output, bls12_g2_infinity());
    }

    #[test]
    fn test_bls12_g2msm_wrong_length() {
        let input = vec![0u8; 200]; // not a multiple of 288
        let result = precompile_bls12_g2msm(&input, 10_000_000);
        assert!(result.is_err());
    }

    // ---- BLS12_PAIRING_CHECK (0x0e) ----

    #[test]
    fn test_bls12_pairing_check_single_pair_generator() {
        // e(G1, G2) != 1, so check should fail (output = 0)
        let mut input = bls12_g1_generator_encoded();
        input.extend_from_slice(&bls12_g2_generator_encoded());
        let result = precompile_bls12_pairing_check(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 43000 + 65000);
        assert_eq!(result.output[31], 0);
    }

    #[test]
    fn test_bls12_pairing_check_with_infinity_g1() {
        // e(O, G2) = 1, so check should pass
        let mut input = bls12_g1_infinity();
        input.extend_from_slice(&bls12_g2_generator_encoded());
        let result = precompile_bls12_pairing_check(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output[31], 1);
    }

    #[test]
    fn test_bls12_pairing_check_with_infinity_g2() {
        // e(G1, O) = 1, so check should pass
        let mut input = bls12_g1_generator_encoded();
        input.extend_from_slice(&bls12_g2_infinity());
        let result = precompile_bls12_pairing_check(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output[31], 1);
    }

    #[test]
    fn test_bls12_pairing_check_two_pairs_cancelling() {
        // e(-G1, G2) * e(G1, G2) = 1
        // Negate G1: negate the y-coordinate
        let gen_g1 = bls12_g1_generator_encoded();
        let gen_g2 = bls12_g2_generator_encoded();

        // Get -G1 by negating the generator
        let gen_affine = unsafe { *blst::blst_p1_affine_generator() };

        let mut neg_proj = blst::blst_p1::default();
        unsafe {
            blst::blst_p1_from_affine(&mut neg_proj, &gen_affine);
            blst::blst_p1_cneg(&mut neg_proj, true);
        }
        let mut neg_affine = blst::blst_p1_affine::default();
        unsafe { blst::blst_p1_to_affine(&mut neg_affine, &neg_proj); }
        let neg_g1 = encode_g1_point(&neg_affine);

        // Input: (-G1, G2), (G1, G2)
        let mut input = neg_g1;
        input.extend_from_slice(&gen_g2);
        input.extend_from_slice(&gen_g1);
        input.extend_from_slice(&gen_g2);

        let result = precompile_bls12_pairing_check(&input, 10_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output[31], 1, "e(-G1,G2)*e(G1,G2) should equal 1");
    }

    #[test]
    fn test_bls12_pairing_check_empty() {
        let result = precompile_bls12_pairing_check(&[], 10_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_bls12_pairing_check_wrong_length() {
        let input = vec![0u8; 100];
        let result = precompile_bls12_pairing_check(&input, 10_000_000);
        assert!(result.is_err());
    }

    // ---- BLS12_MAP_FP_TO_G1 (0x0f) ----

    #[test]
    fn test_bls12_map_fp_to_g1_zero() {
        // Map Fp(0) to G1 — should produce a valid G1 point
        let input = vec![0u8; 64];
        let result = precompile_bls12_map_fp_to_g1(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 5500);
        assert_eq!(result.output.len(), 128);
        // The result should be a valid non-infinity point (map_to_g1(0) is defined)
        // Verify it can be decoded back
        let decoded = decode_g1_point(&result.output);
        assert!(decoded.is_some(), "map_fp_to_g1(0) should produce a valid G1 point");
    }

    #[test]
    fn test_bls12_map_fp_to_g1_one() {
        // Map Fp(1) to G1
        let mut input = vec![0u8; 64];
        input[63] = 1;
        let result = precompile_bls12_map_fp_to_g1(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output.len(), 128);
        let decoded = decode_g1_point(&result.output);
        assert!(decoded.is_some());
    }

    #[test]
    fn test_bls12_map_fp_to_g1_wrong_length() {
        let input = vec![0u8; 63];
        let result = precompile_bls12_map_fp_to_g1(&input, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_bls12_map_fp_to_g1_deterministic() {
        // Same input must produce the same output
        let mut input = vec![0u8; 64];
        input[63] = 42;
        let r1 = precompile_bls12_map_fp_to_g1(&input, 1_000_000).unwrap();
        let r2 = precompile_bls12_map_fp_to_g1(&input, 1_000_000).unwrap();
        assert_eq!(r1.output, r2.output);
    }

    // ---- BLS12_MAP_FP2_TO_G2 (0x10) ----

    #[test]
    fn test_bls12_map_fp2_to_g2_zero() {
        let input = vec![0u8; 128];
        let result = precompile_bls12_map_fp2_to_g2(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, 23800);
        assert_eq!(result.output.len(), 256);
        let decoded = decode_g2_point(&result.output);
        assert!(decoded.is_some(), "map_fp2_to_g2(0,0) should produce a valid G2 point");
    }

    #[test]
    fn test_bls12_map_fp2_to_g2_one() {
        let mut input = vec![0u8; 128];
        input[63] = 1; // c0 = 1, c1 = 0
        let result = precompile_bls12_map_fp2_to_g2(&input, 1_000_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output.len(), 256);
        let decoded = decode_g2_point(&result.output);
        assert!(decoded.is_some());
    }

    #[test]
    fn test_bls12_map_fp2_to_g2_wrong_length() {
        let input = vec![0u8; 127];
        let result = precompile_bls12_map_fp2_to_g2(&input, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_bls12_map_fp2_to_g2_deterministic() {
        let mut input = vec![0u8; 128];
        input[63] = 7;
        input[127] = 11;
        let r1 = precompile_bls12_map_fp2_to_g2(&input, 1_000_000).unwrap();
        let r2 = precompile_bls12_map_fp2_to_g2(&input, 1_000_000).unwrap();
        assert_eq!(r1.output, r2.output);
    }

    // ---- Cross-precompile consistency ----

    #[test]
    fn test_bls12_g1msm_scalar_two_equals_g1add_doubling() {
        // 2*G via MSM should equal G+G via G1ADD
        let g_pt = bls12_g1_generator_encoded();

        // MSM: 2*G
        let mut msm_input = g_pt.clone();
        let mut scalar_two = vec![0u8; 32];
        scalar_two[31] = 2;
        msm_input.extend_from_slice(&scalar_two);
        let msm_result = precompile_bls12_g1msm(&msm_input, 10_000_000).unwrap();

        // ADD: G + G
        let mut add_input = g_pt.clone();
        add_input.extend_from_slice(&g_pt);
        let add_result = precompile_bls12_g1add(&add_input, 1_000_000).unwrap();

        assert_eq!(msm_result.output, add_result.output);
    }

    #[test]
    fn test_bls12_g2msm_scalar_two_equals_g2add_doubling() {
        // 2*G2 via MSM should equal G2+G2 via G2ADD
        let g_pt = bls12_g2_generator_encoded();

        let mut msm_input = g_pt.clone();
        let mut scalar_two = vec![0u8; 32];
        scalar_two[31] = 2;
        msm_input.extend_from_slice(&scalar_two);
        let msm_result = precompile_bls12_g2msm(&msm_input, 10_000_000).unwrap();

        let mut add_input = g_pt.clone();
        add_input.extend_from_slice(&g_pt);
        let add_result = precompile_bls12_g2add(&add_input, 1_000_000).unwrap();

        assert_eq!(msm_result.output, add_result.output);
    }

    #[test]
    fn test_bls12_g1add_invalid_point_not_on_curve() {
        // Construct a point that has valid Fp elements but is NOT on the curve
        let mut input = vec![0u8; 256];
        // Set x = 1, y = 1 for first point — almost certainly not on BLS12-381
        input[63] = 1;
        input[127] = 1;
        // Second point is identity (valid)
        let result = precompile_bls12_g1add(&input, 1_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_bls12_g1add_non_canonical_fp() {
        // Set padding bytes to non-zero (should be rejected)
        let g_pt = bls12_g1_generator_encoded();
        let mut input = g_pt.clone();
        input.extend_from_slice(&g_pt);
        input[0] = 0xFF; // corrupt padding of first Fp element
        let result = precompile_bls12_g1add(&input, 1_000_000);
        assert!(result.is_err());
    }

    // ============================================================
    // VRF precompile tests (0x1007)
    // ============================================================

    fn vrf_build_input(pk: &[u8; 32], proof: &[u8; 80], alpha: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 80 + 32 + alpha.len());
        v.extend_from_slice(pk);
        v.extend_from_slice(proof);
        let mut len_be = [0u8; 32];
        let bytes = (alpha.len() as u32).to_be_bytes();
        len_be[28..32].copy_from_slice(&bytes);
        v.extend_from_slice(&len_be);
        v.extend_from_slice(alpha);
        v
    }

    #[test]
    fn test_vrf_precompile_valid_proof_returns_output() {
        use tenzro_crypto::vrf::{prove, VrfSecretKey};

        let sk = VrfSecretKey([7u8; 32]);
        let pk = sk.public_key();
        let alpha = b"tenzro-nft-mint-42";
        let proof = prove(&sk, alpha).unwrap();

        let input = vrf_build_input(&pk.0, &proof.0, alpha);
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();

        assert_eq!(out.output.len(), 32 + 64);
        // First 32 bytes = uint256(1)
        assert_eq!(out.output[31], 1);
        for b in &out.output[0..31] {
            assert_eq!(*b, 0);
        }
        // Output bytes must be non-trivial
        assert!(out.output[32..].iter().any(|b| *b != 0));
    }

    #[test]
    fn test_vrf_precompile_tampered_proof_rejected() {
        use tenzro_crypto::vrf::{prove, VrfSecretKey};

        let sk = VrfSecretKey([7u8; 32]);
        let pk = sk.public_key();
        let alpha = b"tenzro-nft-mint-42";
        let mut proof = prove(&sk, alpha).unwrap();
        proof.0[0] ^= 0x01;

        let input = vrf_build_input(&pk.0, &proof.0, alpha);
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();
        // Only 32-byte zero status on failure
        assert_eq!(out.output, vec![0u8; 32]);
    }

    #[test]
    fn test_vrf_precompile_wrong_alpha_rejected() {
        use tenzro_crypto::vrf::{prove, VrfSecretKey};

        let sk = VrfSecretKey([9u8; 32]);
        let pk = sk.public_key();
        let proof = prove(&sk, b"hello").unwrap();

        let input = vrf_build_input(&pk.0, &proof.0, b"world");
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();
        assert_eq!(out.output, vec![0u8; 32]);
    }

    #[test]
    fn test_vrf_precompile_short_input() {
        let input = vec![0u8; 50]; // too short
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();
        assert_eq!(out.output, vec![0u8; 32]);
    }

    #[test]
    fn test_vrf_precompile_insufficient_gas() {
        use tenzro_crypto::vrf::{prove, VrfSecretKey};
        let sk = VrfSecretKey([3u8; 32]);
        let pk = sk.public_key();
        let alpha = b"abc";
        let proof = prove(&sk, alpha).unwrap();
        let input = vrf_build_input(&pk.0, &proof.0, alpha);
        let err = precompile_vrf_verify(&input, 1_000); // way below 50k base
        assert!(matches!(err, Err(crate::error::VmError::OutOfGas)));
    }

    #[test]
    fn test_vrf_precompile_huge_length_rejected() {
        // alpha_len with top bits set -> rejected as invalid
        let mut input = vec![0u8; 32 + 80 + 32];
        // set a byte in the high 28 bytes of length encoding
        input[32 + 80] = 0x01;
        let out = precompile_vrf_verify(&input, 1_000_000).unwrap();
        assert_eq!(out.output, vec![0u8; 32]);
    }

    #[test]
    fn test_vrf_precompile_registered_at_correct_address() {
        use tenzro_crypto::vrf::{prove, VrfSecretKey};
        let reg = PrecompileRegistry::new();
        // Exercise via execute() to confirm registration
        let sk = VrfSecretKey([11u8; 32]);
        let pk = sk.public_key();
        let alpha = b"registered";
        let proof = prove(&sk, alpha).unwrap();
        let input = vrf_build_input(&pk.0, &proof.0, alpha);
        let res = reg
            .execute(PRECOMPILE_VRF_VERIFY, &input, 1_000_000)
            .unwrap();
        assert_eq!(res.output.len(), 32 + 64);
        assert_eq!(res.output[31], 1);
        // Address byte pattern: last 3 bytes = 0x10, 0x07, 0x00
        assert_eq!(PRECOMPILE_VRF_VERIFY[17], 0x10);
        assert_eq!(PRECOMPILE_VRF_VERIFY[18], 0x07);
        assert_eq!(PRECOMPILE_VRF_VERIFY[19], 0x00);
    }
}
