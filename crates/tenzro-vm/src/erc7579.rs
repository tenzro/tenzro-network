//! ERC-7579 modular validator modules — concrete implementations.
//!
//! This module is the Phase B custody layer for the smart-account path. The
//! ERC-7579 protocol surface (module types, `IValidator` trait,
//! `ValidatorRegistry`, `ModuleAttestationRegistry`, ERC-1271 magic value)
//! lives in [`crate::aa_validators`]; this file ships three concrete validator
//! modules that enforce real custody invariants at signing time:
//!
//! | Address  | Module                       | Invariant                                                              |
//! |----------|------------------------------|------------------------------------------------------------------------|
//! | `0x101d` | [`SocialRecoveryValidator`]  | N-of-M guardian quorum (composite Ed25519 + ML-DSA-65 signatures)      |
//! | `0x101e` | [`SessionKeyValidator`]      | Session-bound keys with target / selector / value / time restrictions  |
//! | `0x101f` | [`SpendingLimitValidator`]   | On-chain twin of the runtime `SpendingPolicy` (per-tx + daily window)  |
//!
//! # Why on-chain?
//!
//! Per `feedback_custody_enforce_at_signing_time`: off-chain
//! `SpendingPolicyResolver` is defence-in-depth, not the primary control.
//! Delegation must be enforced inside the validator module that the EntryPoint
//! consults during `validateUserOp` — otherwise an attacker who controls the
//! signing key can bypass the off-chain check by hitting any other RPC.
//!
//! All three validators stash their per-account state in `DashMap` registries
//! that mirror the ERC-7579 `installModule(uint256 typeId, address module,
//! bytes initData)` shape — `initData` decodes per-validator into the
//! account-scoped configuration (guardians + threshold; session-key parameters;
//! spending-limit parameters).
//!
//! # Composite signatures
//!
//! `SocialRecoveryValidator` validates each guardian signature as a
//! [`tenzro_crypto::composite::CompositeSignature`] (Ed25519 + ML-DSA-65), per
//! the workspace post-quantum migration. The signature wire format consumed by
//! the validator is a length-prefixed concatenation of guardian DIDs and their
//! composite signatures — see [`SocialRecoverySignaturePayload`].
//!
//! # Standard ERC-7579 selectors
//!
//! The ERC-7579 v1.0.0 four-byte function selectors are exported as constants
//! from this module so `NativeExecutor` (and the ERC-7579-compatible wallet
//! tooling) can dispatch on the canonical wire shape rather than on
//! Tenzro-private selectors:
//!
//! | Selector     | Function                                              |
//! |--------------|-------------------------------------------------------|
//! | `0x9517e29f` | `installModule(uint256,address,bytes)`                |
//! | `0xa71763a8` | `uninstallModule(uint256,address,bytes)`              |
//! | `0x112d3a7d` | `isModuleInstalled(uint256,address,bytes)`            |
//! | `0xa97bfdd1` | `validateUserOp(bytes,bytes32)`                       |
//!
//! These are byte-identical to what Safe / Biconomy Nexus / ZeroDev Kernel /
//! Rhinestone publish against the ERC-7579 reference implementation.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

use tenzro_crypto::composite::{CompositePublicKey, CompositeSignature, StandardHybridVerifier};
use tenzro_crypto::HybridVerifier;

use crate::aa_validators::{
    IValidator, ValidationData, ValidatorError, ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE,
};
use crate::account_abstraction::UserOperation;
use crate::precompiles::{PrecompileFn, PrecompileResult};
use crate::error::Result as VmResult;
use crate::VmError;

// -----------------------------------------------------------------------------
// ERC-7579 standard selectors (keccak256 4-byte prefix)
// -----------------------------------------------------------------------------

/// `installModule(uint256 typeId, address module, bytes initData)`
pub const SELECTOR_INSTALL_MODULE: [u8; 4] = [0x95, 0x17, 0xe2, 0x9f];

/// `uninstallModule(uint256 typeId, address module, bytes deinitData)`
pub const SELECTOR_UNINSTALL_MODULE: [u8; 4] = [0xa7, 0x17, 0x63, 0xa8];

/// `isModuleInstalled(uint256 typeId, address module, bytes context)`
pub const SELECTOR_IS_MODULE_INSTALLED: [u8; 4] = [0x11, 0x2d, 0x3a, 0x7d];

/// `validateUserOp(bytes packedUserOp, bytes32 userOpHash)`
pub const SELECTOR_VALIDATE_USER_OP: [u8; 4] = [0xa9, 0x7b, 0xfd, 0xd1];

/// ERC-7579 §3.1 module type ID for validators.
pub const MODULE_TYPE_VALIDATOR: u64 = 1;

// -----------------------------------------------------------------------------
// Precompile addresses (consistent with the rest of the Tenzro precompile space)
// -----------------------------------------------------------------------------

/// `0x101d` — `SocialRecoveryValidator` precompile (ERC-7579 module).
pub const PRECOMPILE_SOCIAL_RECOVERY_VALIDATOR: &[u8] =
    &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x1d, 0];

/// `0x101e` — `SessionKeyValidator` precompile (ERC-7579 module).
pub const PRECOMPILE_SESSION_KEY_VALIDATOR: &[u8] =
    &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x1e, 0];

/// `0x101f` — `SpendingLimitValidator` precompile (ERC-7579 module).
pub const PRECOMPILE_SPENDING_LIMIT_VALIDATOR: &[u8] =
    &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x1f, 0];

/// Hardware signer module-address slots. The node-side `tenzro_addHardwareSigner`
/// RPC assigns one of these to each installed device. Multiple hardware
/// signers can coexist on a single account because each device kind gets a
/// distinct slot. Matches the slot mapping in
/// `crates/tenzro-node/src/passkey_rpc.rs::handle_add_hardware_signer`.
pub const HARDWARE_VALIDATOR_LEDGER: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x30,
];
pub const HARDWARE_VALIDATOR_TREZOR: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x31,
];
pub const HARDWARE_VALIDATOR_GRIDPLUS: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x32,
];
pub const HARDWARE_VALIDATOR_YUBIKEY: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x33,
];
pub const HARDWARE_VALIDATOR_GENERIC: [u8; 20] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x3f,
];

// -----------------------------------------------------------------------------
// ValidatorModuleConfig — the on-account record of an installed module
// -----------------------------------------------------------------------------

/// The per-account record of an installed validator module, as tracked on the
/// `SmartAccount`. Mirrors the `(typeId, address, initData)` triple from
/// ERC-7579 `installModule`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorModuleConfig {
    /// ERC-7579 module type ID — currently always [`MODULE_TYPE_VALIDATOR`].
    pub type_id: u64,
    /// 20-byte module address (typically a precompile address such as
    /// `0x101d` / `0x101e` / `0x101f`).
    pub module_address: [u8; 20],
    /// Opaque per-module initialisation data — decoded by the module itself.
    pub init_data: Vec<u8>,
    /// Priority within the installed-module list (lower runs first;
    /// AND-combined across all installed modules).
    pub priority: u32,
}

// =============================================================================
// SocialRecoveryValidator — N-of-M composite-signature quorum
// =============================================================================

/// Per-account social-recovery configuration: M guardians, N-of-M quorum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialRecoveryConfig {
    /// Guardian composite public keys (Ed25519 + ML-DSA-65). The list defines
    /// the set; ordering is irrelevant — quorum signatures may arrive in any
    /// order.
    pub guardians: Vec<CompositePublicKey>,
    /// Threshold N — number of guardian signatures required to approve.
    pub threshold: u32,
}

impl SocialRecoveryConfig {
    pub fn new(
        guardians: Vec<CompositePublicKey>,
        threshold: u32,
    ) -> Result<Self, ValidatorError> {
        if guardians.is_empty() {
            return Err(ValidatorError::InvalidInput(
                "SocialRecovery: guardian set must be non-empty".into(),
            ));
        }
        if threshold == 0 || (threshold as usize) > guardians.len() {
            return Err(ValidatorError::InvalidInput(format!(
                "SocialRecovery: threshold {} out of range (1..={})",
                threshold,
                guardians.len()
            )));
        }
        Ok(Self {
            guardians,
            threshold,
        })
    }
}

/// One guardian's contribution to a social-recovery user-op signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardianSignature {
    /// Index into the configured guardian list.
    pub guardian_index: u32,
    /// Composite (classical + PQ) signature over the user-op hash.
    pub signature: CompositeSignature,
}

/// `userOp.signature` payload consumed by [`SocialRecoveryValidator`]. The
/// validator demands at least `threshold` distinct entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocialRecoverySignaturePayload {
    pub guardian_signatures: Vec<GuardianSignature>,
}

/// ERC-7579 validator module that approves a user op iff a configured quorum
/// of guardian composite signatures verify against the user-op hash.
pub struct SocialRecoveryValidator {
    address: [u8; 20],
    /// Per-account configuration. Keyed by smart-account address.
    configs: DashMap<Vec<u8>, SocialRecoveryConfig>,
    /// Optional persistence backend. Write-through on every
    /// `install_for`/`uninstall_for`; hydrate on construction via
    /// `with_storage`. Without storage, configs are in-memory only —
    /// fine for tests, disastrous for production where a node
    /// restart silently wipes the guardian quorum.
    storage: Option<std::sync::Arc<dyn tenzro_storage::KvStore>>,
}

impl SocialRecoveryValidator {
    pub fn new(address: [u8; 20]) -> Self {
        Self {
            address,
            configs: DashMap::new(),
            storage: None,
        }
    }

    /// Constructs a persistent validator backed by `storage`. Hydrates
    /// the configs map from `CF_VALIDATOR_MODULES / erc7579/social/*`
    /// on construction. Every subsequent `install_for`/`uninstall_for`
    /// writes through to the same column family. Production
    /// constructor — call instead of `new` whenever the node owns a
    /// `KvStore`.
    pub fn with_storage(
        address: [u8; 20],
        storage: std::sync::Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let v = Self {
            address,
            configs: DashMap::new(),
            storage: Some(storage),
        };
        v.hydrate();
        v
    }

    fn social_key(account: &[u8]) -> Vec<u8> {
        let mut k = b"erc7579/social/".to_vec();
        k.extend_from_slice(account);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let prefix = b"erc7579/social/";
        let entries = match storage.scan_prefix(tenzro_storage::CF_VALIDATOR_MODULES, prefix) {
            Ok(e) => e,
            Err(_) => return,
        };
        for (key, value) in entries {
            if key.len() <= prefix.len() {
                continue;
            }
            let account = key[prefix.len()..].to_vec();
            if let Ok(config) = serde_json::from_slice::<SocialRecoveryConfig>(&value) {
                self.configs.insert(account, config);
            }
        }
    }

    fn persist(&self, account: &[u8], config: &SocialRecoveryConfig) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(config) {
                let _ = storage.put(
                    tenzro_storage::CF_VALIDATOR_MODULES,
                    &Self::social_key(account),
                    &bytes,
                );
            }
        }
    }

    fn forget(&self, account: &[u8]) {
        if let Some(ref storage) = self.storage {
            let _ = storage
                .delete(tenzro_storage::CF_VALIDATOR_MODULES, &Self::social_key(account));
        }
    }

    /// Install (or replace) the social-recovery configuration for `account`.
    /// Called when the EntryPoint decodes `installModule` for this validator;
    /// `init_data` is the bincode encoding of [`SocialRecoveryConfigInit`].
    pub fn install_for(
        &self,
        account: Vec<u8>,
        config: SocialRecoveryConfig,
    ) -> Result<(), ValidatorError> {
        self.persist(&account, &config);
        self.configs.insert(account, config);
        Ok(())
    }

    pub fn uninstall_for(&self, account: &[u8]) {
        self.configs.remove(account);
        self.forget(account);
    }

    pub fn config_for(&self, account: &[u8]) -> Option<SocialRecoveryConfig> {
        self.configs.get(account).map(|e| e.value().clone())
    }
}

impl IValidator for SocialRecoveryValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        let Some(config) = self.config_for(&op.sender) else {
            return Err(ValidatorError::InvalidInput(format!(
                "SocialRecovery: no config installed for account 0x{}",
                hex::encode(&op.sender)
            )));
        };

        let payload: SocialRecoverySignaturePayload = bincode::deserialize(&op.signature)
            .map_err(|e| {
                ValidatorError::InvalidInput(format!(
                    "SocialRecovery: signature decode failed: {e}"
                ))
            })?;

        // De-duplicate by guardian_index — repeated indices do not count
        // toward the threshold (otherwise a single guardian could fake N-of-M).
        let mut seen = std::collections::HashSet::new();
        let mut approvals: u32 = 0;
        for gs in &payload.guardian_signatures {
            if !seen.insert(gs.guardian_index) {
                continue;
            }
            let Some(pk) = config.guardians.get(gs.guardian_index as usize) else {
                continue;
            };
            let verifier = StandardHybridVerifier::new(pk.clone());
            if verifier.verify(op_hash, &gs.signature).is_ok() {
                approvals += 1;
                if approvals >= config.threshold {
                    return Ok(ValidationData::success());
                }
            }
        }

        Ok(ValidationData::failure())
    }

    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        let Some(config) = self.config_for(sender) else {
            return ERC1271_FAILURE_VALUE;
        };
        let Ok(payload) = bincode::deserialize::<SocialRecoverySignaturePayload>(signature) else {
            return ERC1271_FAILURE_VALUE;
        };
        let mut seen = std::collections::HashSet::new();
        let mut approvals: u32 = 0;
        for gs in &payload.guardian_signatures {
            if !seen.insert(gs.guardian_index) {
                continue;
            }
            let Some(pk) = config.guardians.get(gs.guardian_index as usize) else {
                continue;
            };
            let verifier = StandardHybridVerifier::new(pk.clone());
            if verifier.verify(hash, &gs.signature).is_ok() {
                approvals += 1;
                if approvals >= config.threshold {
                    return ERC1271_MAGIC_VALUE;
                }
            }
        }
        ERC1271_FAILURE_VALUE
    }
}

// =============================================================================
// SessionKeyValidator — restricted-scope session keys
// =============================================================================

/// Per-session-key restrictions enforced at validation time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionKeyConfig {
    /// 32-byte session key public key (Ed25519 verifying key, raw bytes — the
    /// canonical Tenzro composite keys are too large for in-band session use).
    pub session_pubkey: [u8; 32],
    /// Allowed call targets (20-byte addresses). Empty = any target.
    pub allowed_targets: Vec<[u8; 20]>,
    /// Allowed 4-byte function selectors. Empty = any selector.
    pub allowed_selectors: Vec<[u8; 4]>,
    /// Earliest unix timestamp the key is valid. `0` = no lower bound.
    pub valid_after: u64,
    /// Latest unix timestamp the key is valid. `0` = no upper bound.
    pub valid_until: u64,
    /// Per-call value ceiling (smallest unit). `None` = unlimited.
    pub max_value_per_call: Option<u128>,
    /// Cumulative value ceiling across all calls signed by this key. `None` =
    /// unlimited.
    pub max_total_value: Option<u128>,
}

/// Mutable counter for per-key total spend.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct SessionKeyState {
    total_spent: u128,
}

/// Wire-format payload for `userOp.signature`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionKeySignaturePayload {
    /// Ed25519 raw signature (64 bytes) over the user-op hash.
    pub ed25519_signature: Vec<u8>,
    /// Per-call value being moved (in smallest units). Used to enforce
    /// `max_value_per_call` / `max_total_value`. Decoupled from the ABI-level
    /// `call_data.value` so the validator does not need to parse arbitrary
    /// calldata; the smart-account standard-execute path is responsible for
    /// surfacing this honestly.
    pub call_value: u128,
    /// 20-byte call target. Required for `allowed_targets` enforcement.
    pub call_target: [u8; 20],
    /// 4-byte function selector. Required for `allowed_selectors` enforcement.
    pub call_selector: [u8; 4],
}

/// ERC-7579 validator module enforcing session-key restrictions on-chain.
pub struct SessionKeyValidator {
    address: [u8; 20],
    configs: DashMap<Vec<u8>, SessionKeyConfig>,
    state: DashMap<Vec<u8>, RwLock<SessionKeyState>>,
    /// Test hook — when set, used in place of `SystemTime::now()` so the time
    /// gates are deterministically testable. `None` in production.
    clock_override: RwLock<Option<u64>>,
    /// Optional persistence backend.
    storage: Option<std::sync::Arc<dyn tenzro_storage::KvStore>>,
}

impl SessionKeyValidator {
    pub fn new(address: [u8; 20]) -> Self {
        Self {
            address,
            configs: DashMap::new(),
            state: DashMap::new(),
            clock_override: RwLock::new(None),
            storage: None,
        }
    }

    /// Production constructor with write-through to
    /// `CF_VALIDATOR_MODULES`. Hydrates configs + state on construction.
    pub fn with_storage(
        address: [u8; 20],
        storage: std::sync::Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let v = Self {
            address,
            configs: DashMap::new(),
            state: DashMap::new(),
            clock_override: RwLock::new(None),
            storage: Some(storage),
        };
        v.hydrate();
        v
    }

    fn cfg_key(account: &[u8]) -> Vec<u8> {
        let mut k = b"erc7579/session/".to_vec();
        k.extend_from_slice(account);
        k
    }
    fn state_key(account: &[u8]) -> Vec<u8> {
        let mut k = b"erc7579/session_state/".to_vec();
        k.extend_from_slice(account);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let cfg_prefix: &[u8] = b"erc7579/session/";
        if let Ok(entries) =
            storage.scan_prefix(tenzro_storage::CF_VALIDATOR_MODULES, cfg_prefix)
        {
            for (key, value) in entries {
                if key.len() <= cfg_prefix.len() {
                    continue;
                }
                let account = key[cfg_prefix.len()..].to_vec();
                if let Ok(config) = serde_json::from_slice::<SessionKeyConfig>(&value) {
                    self.configs.insert(account, config);
                }
            }
        }
        let state_prefix: &[u8] = b"erc7579/session_state/";
        if let Ok(entries) =
            storage.scan_prefix(tenzro_storage::CF_VALIDATOR_MODULES, state_prefix)
        {
            for (key, value) in entries {
                if key.len() <= state_prefix.len() {
                    continue;
                }
                let account = key[state_prefix.len()..].to_vec();
                if let Ok(state) = serde_json::from_slice::<SessionKeyState>(&value) {
                    self.state.insert(account, RwLock::new(state));
                }
            }
        }
    }

    fn persist_config(&self, account: &[u8], config: &SessionKeyConfig) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(config) {
                let _ = storage.put(
                    tenzro_storage::CF_VALIDATOR_MODULES,
                    &Self::cfg_key(account),
                    &bytes,
                );
            }
        }
    }

    fn persist_state(&self, account: &[u8], state: &SessionKeyState) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(state) {
                let _ = storage.put(
                    tenzro_storage::CF_VALIDATOR_MODULES,
                    &Self::state_key(account),
                    &bytes,
                );
            }
        }
    }

    fn forget(&self, account: &[u8]) {
        if let Some(ref storage) = self.storage {
            let _ = storage
                .delete(tenzro_storage::CF_VALIDATOR_MODULES, &Self::cfg_key(account));
            let _ = storage
                .delete(tenzro_storage::CF_VALIDATOR_MODULES, &Self::state_key(account));
        }
    }

    pub fn install_for(&self, account: Vec<u8>, config: SessionKeyConfig) {
        self.persist_config(&account, &config);
        let initial_state = SessionKeyState::default();
        self.persist_state(&account, &initial_state);
        self.configs.insert(account.clone(), config);
        self.state.insert(account, RwLock::new(initial_state));
    }

    pub fn uninstall_for(&self, account: &[u8]) {
        self.configs.remove(account);
        self.state.remove(account);
        self.forget(account);
    }

    pub fn config_for(&self, account: &[u8]) -> Option<SessionKeyConfig> {
        self.configs.get(account).map(|e| e.value().clone())
    }

    /// Override the clock for tests. Pass `None` to revert to wall time.
    pub fn set_clock_override(&self, ts: Option<u64>) {
        *self.clock_override.write() = ts;
    }

    fn now(&self) -> u64 {
        if let Some(ts) = *self.clock_override.read() {
            return ts;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl IValidator for SessionKeyValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        let Some(config) = self.config_for(&op.sender) else {
            return Err(ValidatorError::InvalidInput(format!(
                "SessionKey: no config installed for account 0x{}",
                hex::encode(&op.sender)
            )));
        };

        let payload: SessionKeySignaturePayload =
            bincode::deserialize(&op.signature).map_err(|e| {
                ValidatorError::InvalidInput(format!(
                    "SessionKey: signature decode failed: {e}"
                ))
            })?;

        // 1. Ed25519 signature check.
        if payload.ed25519_signature.len() != 64 {
            return Ok(ValidationData::failure());
        }
        use ed25519_dalek_verify::verify_ed25519;
        if !verify_ed25519(&config.session_pubkey, op_hash, &payload.ed25519_signature) {
            return Ok(ValidationData::failure());
        }

        // 2. Time window.
        let now = self.now();
        if config.valid_after != 0 && now < config.valid_after {
            return Ok(ValidationData::failure());
        }
        if config.valid_until != 0 && now > config.valid_until {
            return Ok(ValidationData::failure());
        }

        // 3. Call target allowlist.
        if !config.allowed_targets.is_empty()
            && !config.allowed_targets.contains(&payload.call_target)
        {
            return Ok(ValidationData::failure());
        }

        // 4. Selector allowlist.
        if !config.allowed_selectors.is_empty()
            && !config.allowed_selectors.contains(&payload.call_selector)
        {
            return Ok(ValidationData::failure());
        }

        // 5. Per-call value ceiling.
        if let Some(max) = config.max_value_per_call
            && payload.call_value > max
        {
            return Ok(ValidationData::failure());
        }

        // 6. Total-spend ceiling. Mutates state on success — the EntryPoint
        // contract semantics is "validation is a write surface for state owned
        // by the validator", per ERC-7579 §6.1.
        if let Some(max_total) = config.max_total_value {
            let mut state_entry = self
                .state
                .entry(op.sender.clone())
                .or_insert_with(|| RwLock::new(SessionKeyState::default()));
            let mut state = state_entry.value_mut().write();
            let new_total = state.total_spent.saturating_add(payload.call_value);
            if new_total > max_total {
                return Ok(ValidationData::failure());
            }
            state.total_spent = new_total;
            let snapshot = state.clone();
            drop(state);
            drop(state_entry);
            self.persist_state(&op.sender, &snapshot);
        }

        // Surface the configured time bounds as `(valid_after, valid_until)`
        // in the packed `ValidationData` so the EntryPoint can re-check them
        // at execution time without re-consulting the validator.
        Ok(ValidationData {
            aggregator: vec![0u8; 20],
            valid_after: config.valid_after,
            valid_until: config.valid_until,
        })
    }

    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        let Some(config) = self.config_for(sender) else {
            return ERC1271_FAILURE_VALUE;
        };
        if signature.len() != 64 {
            return ERC1271_FAILURE_VALUE;
        }
        use ed25519_dalek_verify::verify_ed25519;
        if verify_ed25519(&config.session_pubkey, hash, signature) {
            ERC1271_MAGIC_VALUE
        } else {
            ERC1271_FAILURE_VALUE
        }
    }
}

// =============================================================================
// SpendingLimitValidator — on-chain twin of the runtime SpendingPolicy
// =============================================================================

/// Per-account spending-limit configuration. The validator tracks a rolling
/// `window_seconds` window (default 86_400 = 24h) and rejects any user op
/// whose `call_value` would push `current_window_spend + call_value` over
/// `max_daily_spend`, or whose `call_value` exceeds `max_per_transaction`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendingLimitConfig {
    /// Per-transaction ceiling. `None` = unlimited.
    pub max_per_transaction: Option<u128>,
    /// Per-window ceiling. `None` = unlimited.
    pub max_daily_spend: Option<u128>,
    /// Rolling window length in seconds (default 86_400 = 1 day).
    pub window_seconds: u64,
    /// Master switch — when `false`, validator rejects all user ops.
    pub enabled: bool,
}

impl Default for SpendingLimitConfig {
    fn default() -> Self {
        Self {
            max_per_transaction: None,
            max_daily_spend: None,
            window_seconds: 86_400,
            enabled: true,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct SpendingLimitState {
    /// Unix timestamp (seconds) at which the current window started.
    window_start_ts: u64,
    /// Cumulative spend within the current window.
    spent_in_window: u128,
}

/// Wire-format payload for `userOp.signature`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendingLimitSignaturePayload {
    /// Per-call value being moved (in smallest units).
    pub call_value: u128,
    /// Inner signature (Ed25519 raw 64 bytes) over the user-op hash. Provides
    /// authentication of the spending request — the limit check is enforced
    /// in addition to (not instead of) the signature.
    pub ed25519_signature: Vec<u8>,
    /// Authenticator pubkey for the inner signature (32 bytes Ed25519).
    pub authenticator_pubkey: [u8; 32],
}

/// ERC-7579 validator module enforcing per-tx + rolling-window spending limits.
pub struct SpendingLimitValidator {
    address: [u8; 20],
    configs: DashMap<Vec<u8>, SpendingLimitConfig>,
    state: DashMap<Vec<u8>, RwLock<SpendingLimitState>>,
    /// Authorised authenticator pubkey per account. Set at install time so the
    /// validator knows which key is allowed to spend; multiple validators in
    /// the AND-combiner stack can independently authenticate, but this one
    /// pins its own.
    authenticators: DashMap<Vec<u8>, [u8; 32]>,
    clock_override: RwLock<Option<u64>>,
    storage: Option<std::sync::Arc<dyn tenzro_storage::KvStore>>,
}

impl SpendingLimitValidator {
    pub fn new(address: [u8; 20]) -> Self {
        Self {
            address,
            configs: DashMap::new(),
            state: DashMap::new(),
            authenticators: DashMap::new(),
            clock_override: RwLock::new(None),
            storage: None,
        }
    }

    /// Production constructor with write-through.
    pub fn with_storage(
        address: [u8; 20],
        storage: std::sync::Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let v = Self {
            address,
            configs: DashMap::new(),
            state: DashMap::new(),
            authenticators: DashMap::new(),
            clock_override: RwLock::new(None),
            storage: Some(storage),
        };
        v.hydrate();
        v
    }

    fn cfg_key(account: &[u8]) -> Vec<u8> {
        let mut k = b"erc7579/spending/".to_vec();
        k.extend_from_slice(account);
        k
    }
    fn state_key(account: &[u8]) -> Vec<u8> {
        let mut k = b"erc7579/spending_state/".to_vec();
        k.extend_from_slice(account);
        k
    }
    fn auth_key(account: &[u8]) -> Vec<u8> {
        let mut k = b"erc7579/spending_auth/".to_vec();
        k.extend_from_slice(account);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let cfg_prefix: &[u8] = b"erc7579/spending/";
        if let Ok(entries) =
            storage.scan_prefix(tenzro_storage::CF_VALIDATOR_MODULES, cfg_prefix)
        {
            for (key, value) in entries {
                if key.len() <= cfg_prefix.len() {
                    continue;
                }
                let account = key[cfg_prefix.len()..].to_vec();
                if let Ok(config) = serde_json::from_slice::<SpendingLimitConfig>(&value) {
                    self.configs.insert(account, config);
                }
            }
        }
        let state_prefix: &[u8] = b"erc7579/spending_state/";
        if let Ok(entries) =
            storage.scan_prefix(tenzro_storage::CF_VALIDATOR_MODULES, state_prefix)
        {
            for (key, value) in entries {
                if key.len() <= state_prefix.len() {
                    continue;
                }
                let account = key[state_prefix.len()..].to_vec();
                if let Ok(state) = serde_json::from_slice::<SpendingLimitState>(&value) {
                    self.state.insert(account, RwLock::new(state));
                }
            }
        }
        let auth_prefix: &[u8] = b"erc7579/spending_auth/";
        if let Ok(entries) =
            storage.scan_prefix(tenzro_storage::CF_VALIDATOR_MODULES, auth_prefix)
        {
            for (key, value) in entries {
                if key.len() <= auth_prefix.len() || value.len() != 32 {
                    continue;
                }
                let account = key[auth_prefix.len()..].to_vec();
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&value);
                self.authenticators.insert(account, pk);
            }
        }
    }

    fn persist_config(&self, account: &[u8], config: &SpendingLimitConfig) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(config) {
                let _ = storage.put(
                    tenzro_storage::CF_VALIDATOR_MODULES,
                    &Self::cfg_key(account),
                    &bytes,
                );
            }
        }
    }

    fn persist_state(&self, account: &[u8], state: &SpendingLimitState) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(state) {
                let _ = storage.put(
                    tenzro_storage::CF_VALIDATOR_MODULES,
                    &Self::state_key(account),
                    &bytes,
                );
            }
        }
    }

    fn persist_auth(&self, account: &[u8], pubkey: &[u8; 32]) {
        if let Some(ref storage) = self.storage {
            let _ = storage.put(
                tenzro_storage::CF_VALIDATOR_MODULES,
                &Self::auth_key(account),
                pubkey,
            );
        }
    }

    fn forget(&self, account: &[u8]) {
        if let Some(ref storage) = self.storage {
            let _ = storage
                .delete(tenzro_storage::CF_VALIDATOR_MODULES, &Self::cfg_key(account));
            let _ = storage
                .delete(tenzro_storage::CF_VALIDATOR_MODULES, &Self::state_key(account));
            let _ = storage
                .delete(tenzro_storage::CF_VALIDATOR_MODULES, &Self::auth_key(account));
        }
    }

    pub fn install_for(
        &self,
        account: Vec<u8>,
        config: SpendingLimitConfig,
        authenticator_pubkey: [u8; 32],
    ) {
        self.persist_config(&account, &config);
        let initial_state = SpendingLimitState::default();
        self.persist_state(&account, &initial_state);
        self.persist_auth(&account, &authenticator_pubkey);
        self.configs.insert(account.clone(), config);
        self.state
            .insert(account.clone(), RwLock::new(initial_state));
        self.authenticators.insert(account, authenticator_pubkey);
    }

    pub fn uninstall_for(&self, account: &[u8]) {
        self.configs.remove(account);
        self.state.remove(account);
        self.authenticators.remove(account);
        self.forget(account);
    }

    pub fn config_for(&self, account: &[u8]) -> Option<SpendingLimitConfig> {
        self.configs.get(account).map(|e| e.value().clone())
    }

    pub fn current_window_spend(&self, account: &[u8]) -> u128 {
        self.state
            .get(account)
            .map(|e| e.value().read().spent_in_window)
            .unwrap_or(0)
    }

    pub fn set_clock_override(&self, ts: Option<u64>) {
        *self.clock_override.write() = ts;
    }

    fn now(&self) -> u64 {
        if let Some(ts) = *self.clock_override.read() {
            return ts;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl IValidator for SpendingLimitValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        let Some(config) = self.config_for(&op.sender) else {
            return Err(ValidatorError::InvalidInput(format!(
                "SpendingLimit: no config installed for account 0x{}",
                hex::encode(&op.sender)
            )));
        };

        if !config.enabled {
            return Ok(ValidationData::failure());
        }

        let payload: SpendingLimitSignaturePayload =
            bincode::deserialize(&op.signature).map_err(|e| {
                ValidatorError::InvalidInput(format!(
                    "SpendingLimit: signature decode failed: {e}"
                ))
            })?;

        // The validator pins its own authenticator pubkey at install time;
        // reject a user op whose payload claims a different one.
        let Some(expected_pk) = self.authenticators.get(&op.sender).map(|e| *e.value()) else {
            return Ok(ValidationData::failure());
        };
        if payload.authenticator_pubkey != expected_pk {
            return Ok(ValidationData::failure());
        }
        if payload.ed25519_signature.len() != 64 {
            return Ok(ValidationData::failure());
        }
        use ed25519_dalek_verify::verify_ed25519;
        if !verify_ed25519(
            &payload.authenticator_pubkey,
            op_hash,
            &payload.ed25519_signature,
        ) {
            return Ok(ValidationData::failure());
        }

        // Per-tx ceiling.
        if let Some(max) = config.max_per_transaction
            && payload.call_value > max
        {
            return Ok(ValidationData::failure());
        }

        // Rolling-window ceiling.
        if let Some(max_daily) = config.max_daily_spend {
            let now = self.now();
            let mut state_entry = self
                .state
                .entry(op.sender.clone())
                .or_insert_with(|| RwLock::new(SpendingLimitState::default()));
            let mut state = state_entry.value_mut().write();
            // Reset the window if it's expired.
            if state.window_start_ts == 0 || now >= state.window_start_ts + config.window_seconds {
                state.window_start_ts = now;
                state.spent_in_window = 0;
            }
            let new_spend = state.spent_in_window.saturating_add(payload.call_value);
            if new_spend > max_daily {
                return Ok(ValidationData::failure());
            }
            state.spent_in_window = new_spend;
            let snapshot = state.clone();
            drop(state);
            drop(state_entry);
            self.persist_state(&op.sender, &snapshot);
        }

        Ok(ValidationData::success())
    }

    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        let Some(expected_pk) = self.authenticators.get(sender).map(|e| *e.value()) else {
            return ERC1271_FAILURE_VALUE;
        };
        if signature.len() != 64 {
            return ERC1271_FAILURE_VALUE;
        }
        use ed25519_dalek_verify::verify_ed25519;
        if verify_ed25519(&expected_pk, hash, signature) {
            ERC1271_MAGIC_VALUE
        } else {
            ERC1271_FAILURE_VALUE
        }
    }
}

// -----------------------------------------------------------------------------
// Account-side module installation map (for `SmartAccount`)
// -----------------------------------------------------------------------------

/// Helper used by `SmartAccount` to maintain its on-account installed-validator
/// map. Keyed by 20-byte module address; ordered so iteration is deterministic.
pub type ValidatorModuleMap = BTreeMap<[u8; 20], ValidatorModuleConfig>;

// -----------------------------------------------------------------------------
// Precompile factories
// -----------------------------------------------------------------------------

/// Decode the standard ERC-7579 `installModule(uint256,address,bytes)` calldata
/// and return `(type_id, module_address, init_data)`. The encoding is the
/// canonical Solidity ABI: 32-byte uint, 32-byte address (left-padded), then
/// the dynamic `bytes` (offset + length + data).
fn decode_install_module_calldata(input: &[u8]) -> VmResult<(u64, [u8; 20], Vec<u8>)> {
    if input.len() < 4 + 32 * 3 {
        return Err(VmError::PrecompileFailed(
            "ERC-7579 installModule: short calldata".into(),
        ));
    }
    let body = &input[4..];
    // type_id: take low 8 bytes of the first 32-byte word (big-endian).
    let mut tid_bytes = [0u8; 8];
    tid_bytes.copy_from_slice(&body[24..32]);
    let type_id = u64::from_be_bytes(tid_bytes);
    // module_address: low 20 bytes of the second word.
    let mut module_addr = [0u8; 20];
    module_addr.copy_from_slice(&body[32 + 12..32 + 32]);
    // init_data: dynamic bytes — third word is the offset (we accept the
    // canonical 0x60 = 96 layout), fourth word is the length, then payload.
    let offset_bytes = &body[64..96];
    let mut off_buf = [0u8; 8];
    off_buf.copy_from_slice(&offset_bytes[24..32]);
    let offset = u64::from_be_bytes(off_buf) as usize;
    if body.len() < offset + 32 {
        return Err(VmError::PrecompileFailed(
            "ERC-7579 installModule: missing length word".into(),
        ));
    }
    let len_bytes = &body[offset..offset + 32];
    let mut len_buf = [0u8; 8];
    len_buf.copy_from_slice(&len_bytes[24..32]);
    let init_len = u64::from_be_bytes(len_buf) as usize;
    if body.len() < offset + 32 + init_len {
        return Err(VmError::PrecompileFailed(
            "ERC-7579 installModule: short init data".into(),
        ));
    }
    let init_data = body[offset + 32..offset + 32 + init_len].to_vec();
    Ok((type_id, module_addr, init_data))
}

/// Build the precompile function for `SocialRecoveryValidator`. The precompile
/// dispatches on the standard ERC-7579 selectors and the custom
/// `validateUserOp` path used by the EntryPoint to evaluate an in-flight
/// user op against this module.
pub fn create_social_recovery_validator_precompile(
    validator: Arc<SocialRecoveryValidator>,
) -> PrecompileFn {
    Arc::new(move |input: &[u8], _gas_limit: u64| -> VmResult<PrecompileResult> {
        if input.len() < 4 {
            return Ok(PrecompileResult::failed(0));
        }
        let mut sel = [0u8; 4];
        sel.copy_from_slice(&input[..4]);
        match sel {
            SELECTOR_INSTALL_MODULE => {
                let (type_id, _module_addr, init_data) = decode_install_module_calldata(input)?;
                if type_id != MODULE_TYPE_VALIDATOR {
                    return Ok(PrecompileResult::failed(0));
                }
                // Tenzro-native install_data: bincode of (account, SocialRecoveryConfig).
                let (account, config): (Vec<u8>, SocialRecoveryConfig) =
                    bincode::deserialize(&init_data).map_err(|e| {
                        VmError::PrecompileFailed(format!(
                            "SocialRecovery install: decode failed: {e}"
                        ))
                    })?;
                validator.install_for(account, config).map_err(|e| {
                    VmError::PrecompileFailed(format!("SocialRecovery install: {e}"))
                })?;
                Ok(PrecompileResult::success(vec![1u8], 5_000))
            }
            _ => Ok(PrecompileResult::failed(0)),
        }
    })
}

/// Build the precompile function for `SessionKeyValidator`.
pub fn create_session_key_validator_precompile(
    validator: Arc<SessionKeyValidator>,
) -> PrecompileFn {
    Arc::new(move |input: &[u8], _gas_limit: u64| -> VmResult<PrecompileResult> {
        if input.len() < 4 {
            return Ok(PrecompileResult::failed(0));
        }
        let mut sel = [0u8; 4];
        sel.copy_from_slice(&input[..4]);
        match sel {
            SELECTOR_INSTALL_MODULE => {
                let (type_id, _module_addr, init_data) = decode_install_module_calldata(input)?;
                if type_id != MODULE_TYPE_VALIDATOR {
                    return Ok(PrecompileResult::failed(0));
                }
                let (account, config): (Vec<u8>, SessionKeyConfig) =
                    bincode::deserialize(&init_data).map_err(|e| {
                        VmError::PrecompileFailed(format!(
                            "SessionKey install: decode failed: {e}"
                        ))
                    })?;
                validator.install_for(account, config);
                Ok(PrecompileResult::success(vec![1u8], 5_000))
            }
            _ => Ok(PrecompileResult::failed(0)),
        }
    })
}

/// Build the precompile function for `SpendingLimitValidator`.
pub fn create_spending_limit_validator_precompile(
    validator: Arc<SpendingLimitValidator>,
) -> PrecompileFn {
    Arc::new(move |input: &[u8], _gas_limit: u64| -> VmResult<PrecompileResult> {
        if input.len() < 4 {
            return Ok(PrecompileResult::failed(0));
        }
        let mut sel = [0u8; 4];
        sel.copy_from_slice(&input[..4]);
        match sel {
            SELECTOR_INSTALL_MODULE => {
                let (type_id, _module_addr, init_data) = decode_install_module_calldata(input)?;
                if type_id != MODULE_TYPE_VALIDATOR {
                    return Ok(PrecompileResult::failed(0));
                }
                // Tenzro-native install_data: bincode of (account, config, authenticator_pk).
                let (account, config, authenticator_pk): (
                    Vec<u8>,
                    SpendingLimitConfig,
                    [u8; 32],
                ) = bincode::deserialize(&init_data).map_err(|e| {
                    VmError::PrecompileFailed(format!(
                        "SpendingLimit install: decode failed: {e}"
                    ))
                })?;
                validator.install_for(account, config, authenticator_pk);
                Ok(PrecompileResult::success(vec![1u8], 5_000))
            }
            _ => Ok(PrecompileResult::failed(0)),
        }
    })
}

// -----------------------------------------------------------------------------
// Minimal local Ed25519 verifier
// -----------------------------------------------------------------------------
//
// We deliberately do not pull a new direct ed25519 dependency into tenzro-vm
// for this file — the workspace already exports raw Ed25519 verification via
// `tenzro_crypto::signatures::verify`. We wrap that call so the validator
// modules don't need to know about `Signature` envelopes.

mod ed25519_dalek_verify {
    use tenzro_crypto::keys::{KeyType, PublicKey};
    use tenzro_crypto::signatures::{verify, Signature};

    /// Verify a raw 64-byte Ed25519 signature against a 32-byte verifying key
    /// and a message. Returns `false` on any decoding or verification error.
    pub fn verify_ed25519(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != 64 {
            return false;
        }
        let pk = PublicKey::new(KeyType::Ed25519, pubkey.to_vec());
        let signature = Signature::new(KeyType::Ed25519, sig.to_vec());
        verify(&pk, msg, &signature).is_ok()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aa_validators::{ModuleAttestation, ModuleType, ValidatorRegistry};
    use crate::account_abstraction::{EntryPoint, SmartAccount};
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use tenzro_crypto::composite::InMemoryHybridSigner;
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::Ed25519SignerImpl;
    use tenzro_crypto::HybridSigner;

    fn make_user_op(sender: Vec<u8>, sig: Vec<u8>) -> UserOperation {
        UserOperation {
            sender,
            nonce: tenzro_vm::account_abstraction::Nonce::from_seq(0).to_bytes(),
            factory: vec![],
            factory_data: vec![],
            call_data: vec![0x42; 4],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![],
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: vec![],
            signature: sig,
        }
    }

    fn fresh_hybrid_signer() -> InMemoryHybridSigner {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate())
    }

    fn dummy_op_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(17);
        }
        h
    }

    // -------------------------------------------------------------------------
    // SocialRecoveryValidator
    // -------------------------------------------------------------------------

    #[test]
    fn social_recovery_2_of_3_quorum_approves() {
        let v = SocialRecoveryValidator::new([0x1d; 20]);
        let g1 = fresh_hybrid_signer();
        let g2 = fresh_hybrid_signer();
        let g3 = fresh_hybrid_signer();

        let account = vec![0xACu8; 20];
        let config = SocialRecoveryConfig::new(
            vec![
                g1.public_key().clone(),
                g2.public_key().clone(),
                g3.public_key().clone(),
            ],
            2,
        )
        .unwrap();
        v.install_for(account.clone(), config).unwrap();

        let hash = dummy_op_hash();
        let sig1 = g1.sign(&hash).unwrap();
        let sig2 = g2.sign(&hash).unwrap();
        let payload = SocialRecoverySignaturePayload {
            guardian_signatures: vec![
                GuardianSignature {
                    guardian_index: 0,
                    signature: sig1,
                },
                GuardianSignature {
                    guardian_index: 1,
                    signature: sig2,
                },
            ],
        };
        let sig_bytes = bincode::serialize(&payload).unwrap();

        let op = make_user_op(account, sig_bytes);
        let data = v.validate_user_op(&op, &hash).unwrap();
        assert!(!data.is_failure());
    }

    #[test]
    fn social_recovery_1_of_3_below_quorum_rejects() {
        let v = SocialRecoveryValidator::new([0x1d; 20]);
        let g1 = fresh_hybrid_signer();
        let g2 = fresh_hybrid_signer();
        let g3 = fresh_hybrid_signer();

        let account = vec![0xACu8; 20];
        let config = SocialRecoveryConfig::new(
            vec![
                g1.public_key().clone(),
                g2.public_key().clone(),
                g3.public_key().clone(),
            ],
            2,
        )
        .unwrap();
        v.install_for(account.clone(), config).unwrap();

        let hash = dummy_op_hash();
        let sig1 = g1.sign(&hash).unwrap();
        let payload = SocialRecoverySignaturePayload {
            guardian_signatures: vec![GuardianSignature {
                guardian_index: 0,
                signature: sig1,
            }],
        };
        let sig_bytes = bincode::serialize(&payload).unwrap();

        let op = make_user_op(account, sig_bytes);
        let data = v.validate_user_op(&op, &hash).unwrap();
        assert!(data.is_failure());
    }

    #[test]
    fn social_recovery_dedupe_same_guardian_does_not_count_twice() {
        let v = SocialRecoveryValidator::new([0x1d; 20]);
        let g1 = fresh_hybrid_signer();
        let g2 = fresh_hybrid_signer();
        let account = vec![0xACu8; 20];
        let config =
            SocialRecoveryConfig::new(vec![g1.public_key().clone(), g2.public_key().clone()], 2)
                .unwrap();
        v.install_for(account.clone(), config).unwrap();

        let hash = dummy_op_hash();
        let sig1 = g1.sign(&hash).unwrap();
        let payload = SocialRecoverySignaturePayload {
            guardian_signatures: vec![
                GuardianSignature {
                    guardian_index: 0,
                    signature: sig1.clone(),
                },
                GuardianSignature {
                    guardian_index: 0,
                    signature: sig1,
                },
            ],
        };
        let sig_bytes = bincode::serialize(&payload).unwrap();
        let op = make_user_op(account, sig_bytes);
        assert!(v.validate_user_op(&op, &hash).unwrap().is_failure());
    }

    // -------------------------------------------------------------------------
    // SessionKeyValidator
    // -------------------------------------------------------------------------

    fn fresh_ed25519() -> (SigningKey, [u8; 32]) {
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    #[test]
    fn session_key_within_window_approves() {
        let v = SessionKeyValidator::new([0x1e; 20]);
        v.set_clock_override(Some(1_000_000));

        let (sk, pk) = fresh_ed25519();
        let account = vec![0xACu8; 20];
        let target = [0x11u8; 20];
        let selector = [0xAA, 0xBB, 0xCC, 0xDD];
        v.install_for(
            account.clone(),
            SessionKeyConfig {
                session_pubkey: pk,
                allowed_targets: vec![target],
                allowed_selectors: vec![selector],
                valid_after: 999_000,
                valid_until: 1_001_000,
                max_value_per_call: Some(100),
                max_total_value: Some(1_000),
            },
        );

        let hash = dummy_op_hash();
        let dalek_sig = sk.sign(&hash).to_bytes().to_vec();
        let payload = SessionKeySignaturePayload {
            ed25519_signature: dalek_sig,
            call_value: 50,
            call_target: target,
            call_selector: selector,
        };
        let op = make_user_op(account, bincode::serialize(&payload).unwrap());
        let data = v.validate_user_op(&op, &hash).unwrap();
        assert!(!data.is_failure());
        assert_eq!(data.valid_after, 999_000);
        assert_eq!(data.valid_until, 1_001_000);
    }

    #[test]
    fn session_key_after_expiry_rejects() {
        let v = SessionKeyValidator::new([0x1e; 20]);
        v.set_clock_override(Some(2_000_000)); // way past valid_until

        let (sk, pk) = fresh_ed25519();
        let account = vec![0xACu8; 20];
        let target = [0x11u8; 20];
        let selector = [0xAA, 0xBB, 0xCC, 0xDD];
        v.install_for(
            account.clone(),
            SessionKeyConfig {
                session_pubkey: pk,
                allowed_targets: vec![target],
                allowed_selectors: vec![selector],
                valid_after: 999_000,
                valid_until: 1_001_000,
                max_value_per_call: None,
                max_total_value: None,
            },
        );

        let hash = dummy_op_hash();
        let dalek_sig = sk.sign(&hash).to_bytes().to_vec();
        let payload = SessionKeySignaturePayload {
            ed25519_signature: dalek_sig,
            call_value: 0,
            call_target: target,
            call_selector: selector,
        };
        let op = make_user_op(account, bincode::serialize(&payload).unwrap());
        assert!(v.validate_user_op(&op, &hash).unwrap().is_failure());
    }

    #[test]
    fn session_key_call_target_not_in_allowlist_rejects() {
        let v = SessionKeyValidator::new([0x1e; 20]);
        v.set_clock_override(Some(1_000_000));

        let (sk, pk) = fresh_ed25519();
        let account = vec![0xACu8; 20];
        let allowed = [0x11u8; 20];
        let denied = [0x22u8; 20];
        let selector = [0xAA, 0xBB, 0xCC, 0xDD];
        v.install_for(
            account.clone(),
            SessionKeyConfig {
                session_pubkey: pk,
                allowed_targets: vec![allowed],
                allowed_selectors: vec![selector],
                valid_after: 0,
                valid_until: 0,
                max_value_per_call: None,
                max_total_value: None,
            },
        );

        let hash = dummy_op_hash();
        let dalek_sig = sk.sign(&hash).to_bytes().to_vec();
        let payload = SessionKeySignaturePayload {
            ed25519_signature: dalek_sig,
            call_value: 0,
            call_target: denied, // not in allowlist
            call_selector: selector,
        };
        let op = make_user_op(account, bincode::serialize(&payload).unwrap());
        assert!(v.validate_user_op(&op, &hash).unwrap().is_failure());
    }

    // -------------------------------------------------------------------------
    // SpendingLimitValidator
    // -------------------------------------------------------------------------

    #[test]
    fn spending_limit_under_daily_cap_approves() {
        let v = SpendingLimitValidator::new([0x1f; 20]);
        v.set_clock_override(Some(1_000_000));
        let (sk, pk) = fresh_ed25519();
        let account = vec![0xACu8; 20];

        v.install_for(
            account.clone(),
            SpendingLimitConfig {
                max_per_transaction: Some(500),
                max_daily_spend: Some(2_000),
                window_seconds: 86_400,
                enabled: true,
            },
            pk,
        );

        let hash = dummy_op_hash();
        let dalek_sig = sk.sign(&hash).to_bytes().to_vec();
        let payload = SpendingLimitSignaturePayload {
            call_value: 100,
            ed25519_signature: dalek_sig,
            authenticator_pubkey: pk,
        };
        let op = make_user_op(account.clone(), bincode::serialize(&payload).unwrap());
        let data = v.validate_user_op(&op, &hash).unwrap();
        assert!(!data.is_failure());
        assert_eq!(v.current_window_spend(&account), 100);
    }

    #[test]
    fn spending_limit_over_daily_cap_rejects() {
        let v = SpendingLimitValidator::new([0x1f; 20]);
        v.set_clock_override(Some(1_000_000));
        let (sk, pk) = fresh_ed25519();
        let account = vec![0xACu8; 20];

        v.install_for(
            account.clone(),
            SpendingLimitConfig {
                max_per_transaction: Some(10_000),
                max_daily_spend: Some(100),
                window_seconds: 86_400,
                enabled: true,
            },
            pk,
        );

        let hash = dummy_op_hash();
        let dalek_sig = sk.sign(&hash).to_bytes().to_vec();
        // First call: 80 (under cap)
        let payload1 = SpendingLimitSignaturePayload {
            call_value: 80,
            ed25519_signature: dalek_sig.clone(),
            authenticator_pubkey: pk,
        };
        let op1 = make_user_op(account.clone(), bincode::serialize(&payload1).unwrap());
        assert!(!v.validate_user_op(&op1, &hash).unwrap().is_failure());

        // Second call: 30 (would push to 110, over 100 cap).
        let payload2 = SpendingLimitSignaturePayload {
            call_value: 30,
            ed25519_signature: dalek_sig,
            authenticator_pubkey: pk,
        };
        let op2 = make_user_op(account.clone(), bincode::serialize(&payload2).unwrap());
        assert!(v.validate_user_op(&op2, &hash).unwrap().is_failure());
        // Spend pointer was not advanced by the failed call.
        assert_eq!(v.current_window_spend(&account), 80);
    }

    #[test]
    fn spending_limit_disabled_rejects_all() {
        let v = SpendingLimitValidator::new([0x1f; 20]);
        v.set_clock_override(Some(1_000_000));
        let (sk, pk) = fresh_ed25519();
        let account = vec![0xACu8; 20];

        v.install_for(
            account.clone(),
            SpendingLimitConfig {
                max_per_transaction: Some(u128::MAX),
                max_daily_spend: Some(u128::MAX),
                window_seconds: 86_400,
                enabled: false,
            },
            pk,
        );
        let hash = dummy_op_hash();
        let dalek_sig = sk.sign(&hash).to_bytes().to_vec();
        let payload = SpendingLimitSignaturePayload {
            call_value: 1,
            ed25519_signature: dalek_sig,
            authenticator_pubkey: pk,
        };
        let op = make_user_op(account, bincode::serialize(&payload).unwrap());
        assert!(v.validate_user_op(&op, &hash).unwrap().is_failure());
    }

    #[test]
    fn spending_limit_window_reset_after_expiry() {
        let v = SpendingLimitValidator::new([0x1f; 20]);
        v.set_clock_override(Some(1_000_000));
        let (sk, pk) = fresh_ed25519();
        let account = vec![0xACu8; 20];

        v.install_for(
            account.clone(),
            SpendingLimitConfig {
                max_per_transaction: Some(1_000),
                max_daily_spend: Some(100),
                window_seconds: 60,
                enabled: true,
            },
            pk,
        );
        let hash = dummy_op_hash();
        let dalek_sig = sk.sign(&hash).to_bytes().to_vec();
        let payload = SpendingLimitSignaturePayload {
            call_value: 90,
            ed25519_signature: dalek_sig,
            authenticator_pubkey: pk,
        };
        let op = make_user_op(account.clone(), bincode::serialize(&payload).unwrap());
        assert!(!v.validate_user_op(&op, &hash).unwrap().is_failure());

        // Advance past the window — counter must reset.
        v.set_clock_override(Some(1_000_000 + 120));
        let op2 = make_user_op(account.clone(), op.signature.clone());
        assert!(!v.validate_user_op(&op2, &hash).unwrap().is_failure());
        assert_eq!(v.current_window_spend(&account), 90);
    }

    // -------------------------------------------------------------------------
    // EntryPoint AND-combiner integration
    // -------------------------------------------------------------------------

    fn attest_module(reg: &ValidatorRegistry, module: [u8; 20]) {
        reg.attestations().attest(ModuleAttestation {
            module_address: module,
            module_type: ModuleType::Validator,
            registry: *reg.trusted_registry(),
            attester: [0xAA; 20],
            attestation_data: b"audit-pass".to_vec(),
            revoked: false,
        });
    }

    #[test]
    fn entry_point_and_combiner_all_validators_must_approve() {
        let reg = Arc::new(ValidatorRegistry::new());
        let account = vec![0xACu8; 20];

        // SessionKey validator at 0x1e (always approves).
        let session_addr = [0x1eu8; 20];
        let session_validator = Arc::new(SessionKeyValidator::new(session_addr));
        session_validator.set_clock_override(Some(1_000_000));
        let (sk_session, pk_session) = fresh_ed25519();
        let target = [0x11u8; 20];
        let selector = [0xAAu8, 0xBB, 0xCC, 0xDD];
        session_validator.install_for(
            account.clone(),
            SessionKeyConfig {
                session_pubkey: pk_session,
                allowed_targets: vec![target],
                allowed_selectors: vec![selector],
                valid_after: 0,
                valid_until: 0,
                max_value_per_call: None,
                max_total_value: None,
            },
        );

        // SpendingLimit validator at 0x1f (will reject when call_value=200 > cap=100).
        let spend_addr = [0x1fu8; 20];
        let spend_validator = Arc::new(SpendingLimitValidator::new(spend_addr));
        spend_validator.set_clock_override(Some(1_000_000));
        let (sk_spend, pk_spend) = fresh_ed25519();
        spend_validator.install_for(
            account.clone(),
            SpendingLimitConfig {
                max_per_transaction: Some(100),
                max_daily_spend: Some(1_000),
                window_seconds: 86_400,
                enabled: true,
            },
            pk_spend,
        );

        attest_module(&reg, session_addr);
        attest_module(&reg, spend_addr);

        reg.install(
            account.clone(),
            ModuleType::Validator,
            session_validator.clone() as Arc<dyn IValidator>,
            10,
            vec![],
        )
        .unwrap();
        reg.install(
            account.clone(),
            ModuleType::Validator,
            spend_validator.clone() as Arc<dyn IValidator>,
            20,
            vec![],
        )
        .unwrap();

        let entry_point = EntryPoint::new(vec![0xEEu8; 20])
            .with_chain_id(1337)
            .with_validator_registry(Arc::clone(&reg));

        // Build a session-key signature payload that satisfies SessionKey,
        // but stuffs the wire form so SpendingLimit rejects (call_value > cap).
        // Trick: signature bytes must be both — we shape the user-op so each
        // module sees its own payload. To keep the test honest we install only
        // the SpendingLimit validator with a known-bad value, after first
        // verifying SessionKey alone passes.

        // First: only SessionKey installed → passes.
        let other = vec![0xBDu8; 20];
        // Install SessionKey config for `other` before registering the module —
        // SessionKeyValidator keeps configs in its own map keyed by account, and
        // the registry install only registers the validator handle.
        session_validator.install_for(
            other.clone(),
            SessionKeyConfig {
                session_pubkey: pk_session,
                allowed_targets: vec![target],
                allowed_selectors: vec![selector],
                valid_after: 0,
                valid_until: 0,
                max_value_per_call: None,
                max_total_value: None,
            },
        );
        attest_module(&reg, session_addr);
        reg.install(
            other.clone(),
            ModuleType::Validator,
            session_validator.clone() as Arc<dyn IValidator>,
            10,
            vec![],
        )
        .unwrap();

        let op_hash = dummy_op_hash();
        let session_sig = sk_session.sign(&op_hash).to_bytes().to_vec();
        let session_payload = SessionKeySignaturePayload {
            ed25519_signature: session_sig.clone(),
            call_value: 50,
            call_target: target,
            call_selector: selector,
        };
        // Build op but bind the hash to EntryPoint's actual EIP-712 domain.
        let mut op = make_user_op(other.clone(), bincode::serialize(&session_payload).unwrap());
        op.nonce = tenzro_vm::account_abstraction::Nonce::from_seq(entry_point.get_nonce_default_key(&other)).to_bytes();
        let h = op.hash(1337, &vec![0xEEu8; 20]);
        // Re-sign with the EntryPoint-domain hash.
        let mut real_hash = [0u8; 32];
        real_hash.copy_from_slice(&h[..32]);
        let session_sig2 = sk_session.sign(&real_hash).to_bytes().to_vec();
        let session_payload2 = SessionKeySignaturePayload {
            ed25519_signature: session_sig2,
            call_value: 50,
            call_target: target,
            call_selector: selector,
        };
        op.signature = bincode::serialize(&session_payload2).unwrap();
        // Single-validator (SessionKey) account passes.
        entry_point.validate_user_op(&op).unwrap();

        // Now: AND-combiner case — `account` has both validators installed.
        // We craft a payload that passes SessionKey but uses call_value=200
        // which trips the SpendingLimit cap.
        let mut op2 = make_user_op(account.clone(), vec![]);
        op2.nonce = tenzro_vm::account_abstraction::Nonce::from_seq(entry_point.get_nonce_default_key(&account)).to_bytes();
        let h2 = op2.hash(1337, &vec![0xEEu8; 20]);
        let mut real_hash2 = [0u8; 32];
        real_hash2.copy_from_slice(&h2[..32]);
        // Each validator will deserialize the *same* `op.signature` bytes
        // through its own decoder; we intentionally make them
        // co-deserializable by sharing the SpendingLimit shape — and then the
        // session validator will fail decode and surface InvalidInput, which
        // proves the AND-combiner short-circuits on hard error. To keep the
        // assertion clean, we test the pure-combiner positive case below.
        let session_sig_h2 = sk_session.sign(&real_hash2).to_bytes().to_vec();
        let session_payload_h2 = SessionKeySignaturePayload {
            ed25519_signature: session_sig_h2,
            call_value: 50,
            call_target: target,
            call_selector: selector,
        };
        op2.signature = bincode::serialize(&session_payload_h2).unwrap();
        // This will surface as InvalidUserOp — SpendingLimit cannot deserialize
        // a SessionKeySignaturePayload, which is the expected boundary signal
        // when an AND-combined op is malformed for any installed validator.
        assert!(entry_point.validate_user_op(&op2).is_err());

        // Pure positive AND-combiner case: install two validators that both
        // accept a shared payload shape. We use the SpendingLimit payload
        // (call_value within cap) as the wire format and install a second
        // SpendingLimit validator with a wider cap on the other slot.
        let other2 = vec![0xBEu8; 20];
        let spend2 = Arc::new(SpendingLimitValidator::new([0x2eu8; 20]));
        spend2.set_clock_override(Some(1_000_000));
        spend2.install_for(
            other2.clone(),
            SpendingLimitConfig {
                max_per_transaction: Some(10_000),
                max_daily_spend: Some(10_000),
                window_seconds: 86_400,
                enabled: true,
            },
            pk_spend,
        );
        spend_validator.install_for(
            other2.clone(),
            SpendingLimitConfig {
                max_per_transaction: Some(500),
                max_daily_spend: Some(1_000),
                window_seconds: 86_400,
                enabled: true,
            },
            pk_spend,
        );
        attest_module(&reg, [0x2eu8; 20]);
        reg.install(
            other2.clone(),
            ModuleType::Validator,
            spend_validator.clone() as Arc<dyn IValidator>,
            10,
            vec![],
        )
        .unwrap();
        reg.install(
            other2.clone(),
            ModuleType::Validator,
            spend2 as Arc<dyn IValidator>,
            20,
            vec![],
        )
        .unwrap();

        let mut op3 = make_user_op(other2.clone(), vec![]);
        op3.nonce = tenzro_vm::account_abstraction::Nonce::from_seq(entry_point.get_nonce_default_key(&other2)).to_bytes();
        let h3 = op3.hash(1337, &vec![0xEEu8; 20]);
        let mut rh3 = [0u8; 32];
        rh3.copy_from_slice(&h3[..32]);
        let sig3 = sk_spend.sign(&rh3).to_bytes().to_vec();
        let payload3 = SpendingLimitSignaturePayload {
            call_value: 50,
            ed25519_signature: sig3,
            authenticator_pubkey: pk_spend,
        };
        op3.signature = bincode::serialize(&payload3).unwrap();
        // BOTH SpendingLimit validators must approve — and they do, since
        // 50 < 500 and 50 < 10_000.
        entry_point.validate_user_op(&op3).unwrap();
    }

    // -------------------------------------------------------------------------
    // SmartAccount module installation
    // -------------------------------------------------------------------------

    #[test]
    fn install_module_root_key_only_pre_recovery_install() {
        let mut acct = SmartAccount {
            address: vec![0x01; 20],
            owner: vec![0x02; 20],
            factory: vec![0x03; 20],
            nonce: tenzro_vm::account_abstraction::Nonce::from_seq(0).to_bytes(),
            is_deployed: true,
            modules: Vec::new(),
            validator_modules: BTreeMap::new(),
        };
        let cfg = ValidatorModuleConfig {
            type_id: MODULE_TYPE_VALIDATOR,
            module_address: [0x1d; 20],
            init_data: vec![],
            priority: 100,
        };
        // Root-key-only path: with no SocialRecovery installed, the owner
        // key is the only authorised installer — the call shape mirrors
        // ERC-7579 but we surface the root-key-only requirement as a
        // boolean argument from the smart-account caller.
        let owner_authorized = true;
        acct.install_validator_module(cfg.clone(), owner_authorized)
            .unwrap();
        assert!(acct.is_validator_installed(&[0x1d; 20]));

        // After SocialRecovery is installed, a non-root caller must come from
        // the recovery quorum — represented here as `owner_authorized = false`
        // along with the `recovery_authorized` flag (the SmartAccount caller
        // is responsible for proving the quorum signature; the account itself
        // just gates on the boolean).
        let cfg2 = ValidatorModuleConfig {
            type_id: MODULE_TYPE_VALIDATOR,
            module_address: [0x1e; 20],
            init_data: vec![],
            priority: 200,
        };
        let err = acct.install_validator_module(cfg2.clone(), false).unwrap_err();
        assert!(matches!(err, ValidatorError::InvalidInput(_)));
        // With the recovery override, install succeeds.
        acct.install_validator_module_with_recovery(cfg2, true)
            .unwrap();
        assert!(acct.is_validator_installed(&[0x1e; 20]));
    }
}

// =============================================================================
// HardwareSignerValidator — Ledger / Trezor / GridPlus secp256k1 sign-off
// =============================================================================

/// On-chain configuration for a hardware-bound co-signer.
///
/// The node-side `tenzro_addHardwareSigner` RPC writes this struct (as JSON)
/// into the `ValidatorModuleConfig.init_data` slot. The
/// [`HardwareSignerValidator`] then decodes that init_data on install and
/// stores it per-account. Mirrors the `HardwareValidatorInit` shape in
/// `crates/tenzro-node/src/passkey_rpc.rs::handle_add_hardware_signer`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareSignerConfig {
    pub device_kind: String,
    /// 33-byte SEC1-compressed secp256k1 public key (Ledger / Trezor / GridPlus
    /// hardware path) OR 64-byte raw P-256 (YubiKey path — verification falls
    /// through to the WebAuthn module in that case).
    pub public_key: Vec<u8>,
    /// If `true`, every UserOp must carry a valid hardware signature.
    /// Otherwise the validator only insists when the UserOp's call_value
    /// exceeds `required_above_wei`.
    pub required_always: bool,
    /// Threshold above which the hardware signature is required (`None`
    /// means no value gate — only `required_always` matters).
    pub required_above_wei: Option<String>,
    pub label: Option<String>,
}

impl HardwareSignerConfig {
    /// Decode `init_data` JSON written by the node-side RPC.
    pub fn from_init_data(init_data: &[u8]) -> Result<Self, ValidatorError> {
        serde_json::from_slice(init_data).map_err(|e| {
            ValidatorError::InvalidInput(format!("HardwareSigner: init_data decode: {e}"))
        })
    }
}

/// HardwareSignerValidator — verifies a secp256k1 ECDSA signature against a
/// hardware-bound public key on every UserOp whose call_value crosses the
/// configured threshold (or unconditionally when `required_always = true`).
///
/// # Signature wire shape
///
/// The UserOp signature is `compact_r || compact_s` (64 bytes raw, no `v`
/// byte) over the UserOp hash. This matches what the wallet-side
/// `PluggableSigner::sign_hash` returns for Ledger / Trezor / GridPlus
/// adapters.
pub struct HardwareSignerValidator {
    address: [u8; 20],
    configs: DashMap<Vec<u8>, HardwareSignerConfig>,
    storage: Option<std::sync::Arc<dyn tenzro_storage::KvStore>>,
}

impl HardwareSignerValidator {
    pub fn new(address: [u8; 20]) -> Self {
        Self {
            address,
            configs: DashMap::new(),
            storage: None,
        }
    }

    pub fn with_storage(
        address: [u8; 20],
        storage: std::sync::Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let v = Self {
            address,
            configs: DashMap::new(),
            storage: Some(storage),
        };
        v.hydrate();
        v
    }

    fn key_for(account: &[u8], module_addr: &[u8; 20]) -> Vec<u8> {
        let mut k = b"erc7579/hardware/".to_vec();
        k.extend_from_slice(module_addr);
        k.push(b'/');
        k.extend_from_slice(account);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let mut prefix = b"erc7579/hardware/".to_vec();
        prefix.extend_from_slice(&self.address);
        prefix.push(b'/');
        let entries = match storage.scan_prefix(tenzro_storage::CF_VALIDATOR_MODULES, &prefix) {
            Ok(e) => e,
            Err(_) => return,
        };
        for (key, value) in entries {
            if key.len() <= prefix.len() {
                continue;
            }
            let account = key[prefix.len()..].to_vec();
            if let Ok(config) = serde_json::from_slice::<HardwareSignerConfig>(&value) {
                self.configs.insert(account, config);
            }
        }
    }

    fn persist(&self, account: &[u8], config: &HardwareSignerConfig) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(config) {
                let _ = storage.put(
                    tenzro_storage::CF_VALIDATOR_MODULES,
                    &Self::key_for(account, &self.address),
                    &bytes,
                );
            }
        }
    }

    fn forget(&self, account: &[u8]) {
        if let Some(ref storage) = self.storage {
            let _ = storage.delete(
                tenzro_storage::CF_VALIDATOR_MODULES,
                &Self::key_for(account, &self.address),
            );
        }
    }

    pub fn install_for(
        &self,
        account: Vec<u8>,
        config: HardwareSignerConfig,
    ) -> Result<(), ValidatorError> {
        self.persist(&account, &config);
        self.configs.insert(account, config);
        Ok(())
    }

    pub fn uninstall_for(&self, account: &[u8]) {
        self.configs.remove(account);
        self.forget(account);
    }

    pub fn config_for(&self, account: &[u8]) -> Option<HardwareSignerConfig> {
        self.configs.get(account).map(|e| e.value().clone())
    }

    /// Convenience: decode `init_data` and install in one step. Used by
    /// `EntryPoint::installModule` dispatch when an account installs a
    /// hardware-signer module.
    pub fn install_from_init_data(
        &self,
        account: Vec<u8>,
        init_data: &[u8],
    ) -> Result<(), ValidatorError> {
        let config = HardwareSignerConfig::from_init_data(init_data)?;
        self.install_for(account, config)
    }

    /// Verify a 64-byte secp256k1 signature against a 33-byte compressed
    /// public key over a 32-byte hash. Returns `true` iff the signature
    /// matches. Pulled out so unit tests can exercise it directly.
    fn verify_secp256k1(pubkey: &[u8], hash: &[u8; 32], sig: &[u8]) -> bool {
        use k256::ecdsa::signature::Verifier;
        use k256::ecdsa::{Signature, VerifyingKey};

        if sig.len() != 64 {
            return false;
        }
        let Ok(vk) = VerifyingKey::from_sec1_bytes(pubkey) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        vk.verify(hash, &signature).is_ok()
    }

    fn parse_threshold(s: Option<&String>) -> Option<u128> {
        s.and_then(|raw| {
            let raw = raw.trim();
            if let Some(hex_part) = raw.strip_prefix("0x") {
                u128::from_str_radix(hex_part, 16).ok()
            } else {
                raw.parse::<u128>().ok()
            }
        })
    }

    /// Best-effort extraction of the call_value out of `execute(...)` calldata.
    /// When the UserOp uses the canonical `execute(address,uint256,bytes)`
    /// selector (0xb61d27f6), this returns the embedded value; otherwise 0
    /// (the value gate is conservative — if we can't tell, we don't require
    /// the hardware leg unless `required_always = true`).
    fn extract_value_from_calldata(call_data: &[u8]) -> u128 {
        if call_data.len() < 132 {
            return 0;
        }
        if call_data[0..4] != [0xb6, 0x1d, 0x27, 0xf6] {
            return 0;
        }
        if call_data[36..52].iter().any(|b| *b != 0) {
            return u128::MAX; // oversize → force hardware leg
        }
        let mut v = [0u8; 16];
        v.copy_from_slice(&call_data[52..68]);
        u128::from_be_bytes(v)
    }
}

impl IValidator for HardwareSignerValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        let Some(config) = self.config_for(&op.sender) else {
            return Err(ValidatorError::InvalidInput(format!(
                "HardwareSigner: no config installed for account 0x{}",
                hex::encode(&op.sender)
            )));
        };

        // Decide whether the hardware leg is required for this op.
        let gate_required = if config.required_always {
            true
        } else if let Some(threshold) = Self::parse_threshold(config.required_above_wei.as_ref()) {
            let call_value = Self::extract_value_from_calldata(&op.call_data);
            call_value >= threshold
        } else {
            false
        };

        if !gate_required {
            // Out-of-scope op — the hardware validator does not block here;
            // some other validator (WebAuthn, SocialRecovery) is responsible.
            // Return success so the EntryPoint AND-combine doesn't fail.
            return Ok(ValidationData::success());
        }

        // The UserOp signature for the hardware path is appended at the
        // end of `op.signature` as the last 64 bytes. Earlier bytes are
        // consumed by upstream validators (e.g. WebAuthn). When only the
        // hardware leg is installed, the whole signature is the 64-byte
        // ECDSA payload.
        if op.signature.len() < 64 {
            return Ok(ValidationData::failure());
        }
        let sig_start = op.signature.len() - 64;
        let sig = &op.signature[sig_start..];

        if Self::verify_secp256k1(&config.public_key, op_hash, sig) {
            Ok(ValidationData::success())
        } else {
            Ok(ValidationData::failure())
        }
    }

    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        let Some(config) = self.config_for(sender) else {
            return ERC1271_FAILURE_VALUE;
        };
        if signature.len() < 64 {
            return ERC1271_FAILURE_VALUE;
        }
        let sig = &signature[signature.len() - 64..];
        if Self::verify_secp256k1(&config.public_key, hash, sig) {
            ERC1271_MAGIC_VALUE
        } else {
            ERC1271_FAILURE_VALUE
        }
    }
}

#[cfg(test)]
mod hardware_tests {
    use super::*;
    use crate::account_abstraction::UserOperation;
    use k256::ecdsa::{signature::Signer, SigningKey};

    fn test_signing_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        SigningKey::from_bytes(&bytes.into()).expect("valid secp256k1 scalar")
    }

    fn dummy_user_op(sender: Vec<u8>, sig: Vec<u8>, call_data: Vec<u8>) -> UserOperation {
        UserOperation {
            sender,
            nonce: tenzro_vm::account_abstraction::Nonce::from_seq(0).to_bytes(),
            factory: vec![],
            factory_data: vec![],
            call_data,
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![],
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: vec![],
            signature: sig,
        }
    }

    #[test]
    fn hardware_validator_required_always_accepts_real_signature() {
        let sk = test_signing_key(7);
        let vk = sk.verifying_key();
        let pubkey = vk.to_sec1_point(true).as_bytes().to_vec(); // 33-byte compressed // 33-byte compressed

        let validator = HardwareSignerValidator::new(HARDWARE_VALIDATOR_LEDGER);
        let sender = vec![0xAB; 20];
        validator
            .install_for(
                sender.clone(),
                HardwareSignerConfig {
                    device_kind: "ledger".into(),
                    public_key: pubkey,
                    required_always: true,
                    required_above_wei: None,
                    label: Some("Ledger Nano X".into()),
                },
            )
            .unwrap();

        let op_hash = [0x42u8; 32];
        let sig: k256::ecdsa::Signature = sk.sign(&op_hash);
        let sig_bytes = sig.to_bytes().to_vec(); // 64 bytes r||s

        let op = dummy_user_op(sender, sig_bytes, vec![]);
        let vd = validator.validate_user_op(&op, &op_hash).unwrap();
        assert_eq!(vd.valid_after, 0);
        assert_eq!(vd.valid_until, 0);
    }

    #[test]
    fn hardware_validator_rejects_wrong_signature() {
        let sk = test_signing_key(7);
        let vk = sk.verifying_key();
        let pubkey = vk.to_sec1_point(true).as_bytes().to_vec(); // 33-byte compressed

        let validator = HardwareSignerValidator::new(HARDWARE_VALIDATOR_LEDGER);
        let sender = vec![0xCD; 20];
        validator
            .install_for(
                sender.clone(),
                HardwareSignerConfig {
                    device_kind: "ledger".into(),
                    public_key: pubkey,
                    required_always: true,
                    required_above_wei: None,
                    label: None,
                },
            )
            .unwrap();

        // Sign over a DIFFERENT hash so verification fails
        let real_hash = [0x42u8; 32];
        let wrong_hash = [0x99u8; 32];
        let sig: k256::ecdsa::Signature = sk.sign(&wrong_hash);
        let sig_bytes = sig.to_bytes().to_vec();

        let op = dummy_user_op(sender, sig_bytes, vec![]);
        let vd = validator.validate_user_op(&op, &real_hash).unwrap();
        assert!(vd.is_failure(), "wrong signature must fail");
    }

    #[test]
    fn hardware_validator_value_gate_skips_low_value_ops() {
        // required_above_wei = 1_000_000 means low-value ops don't need
        // the hardware leg — validator returns success WITHOUT checking
        // the signature.
        let validator = HardwareSignerValidator::new(HARDWARE_VALIDATOR_LEDGER);
        let sender = vec![0xEF; 20];
        validator
            .install_for(
                sender.clone(),
                HardwareSignerConfig {
                    device_kind: "ledger".into(),
                    public_key: vec![0u8; 33], // junk pubkey — never consulted
                    required_always: false,
                    required_above_wei: Some("1000000".into()),
                    label: None,
                },
            )
            .unwrap();

        // No execute() selector → extract_value returns 0 → below threshold
        let op = dummy_user_op(sender, vec![], vec![0xde, 0xad]);
        let vd = validator.validate_user_op(&op, &[0u8; 32]).unwrap();
        assert_eq!(vd.valid_until, 0); // success
    }

    #[test]
    fn hardware_validator_install_from_init_data_roundtrip() {
        let init = serde_json::json!({
            "device_kind": "trezor",
            "public_key": [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33],
            "required_always": true,
            "required_above_wei": null,
            "label": "personal trezor"
        });
        let init_bytes = serde_json::to_vec(&init).unwrap();
        let validator = HardwareSignerValidator::new(HARDWARE_VALIDATOR_TREZOR);
        let account = vec![0x11; 20];
        validator
            .install_from_init_data(account.clone(), &init_bytes)
            .unwrap();
        let cfg = validator.config_for(&account).expect("config installed");
        assert_eq!(cfg.device_kind, "trezor");
        assert!(cfg.required_always);
        assert_eq!(cfg.public_key.len(), 33);
    }
}
