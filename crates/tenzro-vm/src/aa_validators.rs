//! ERC-7579 Modular Smart Account Validators
//!
//! This module implements the ERC-7579 modular-account interface for Tenzro
//! Network's account-abstraction stack. ERC-7579 standardises the wire shape
//! by which a smart account delegates `validateUserOp` to a pluggable
//! validator module — the same module shape used by Safe, Biconomy Nexus,
//! ZeroDev Kernel, Rhinestone, and the broader EIP-4337 ecosystem in 2026.
//!
//! # Module Types
//!
//! Per ERC-7579 §3.1:
//!
//! | Type | Name | Role |
//! |------|------|------|
//! |  1   | Validator | Authorises a UserOperation (signature scheme, scope check, …) |
//! |  2   | Executor  | Mutating call invoked by the account |
//! |  3   | Fallback  | Default handler for unknown selectors |
//! |  4   | Hook      | Pre/post-execution hook |
//!
//! Tenzro currently registers Validator modules; Executor / Fallback / Hook
//! types are encoded for forward compatibility but rejected at install time
//! until their dispatch sites land.
//!
//! # The IValidator Interface
//!
//! ```text
//! validateUserOp(UserOp op, bytes32 hash) -> uint256 validationData
//! isValidSignatureWithSender(address sender, bytes32 hash, bytes sig) -> bytes4
//! ```
//!
//! `validationData` is packed per ERC-4337 §6.1:
//! `[aggregator (160) | validUntil (48) | validAfter (48)]`. A value of `0`
//! means "valid signature, no aggregator, no time bounds". A value of `1`
//! means "invalid signature".
//!
//! `isValidSignatureWithSender` follows ERC-1271: returns the magic
//! `0x1626ba7e` on success, anything else on failure.
//!
//! # ERC-7484 Module Registry Attestation Gate
//!
//! Per ERC-7484, an account SHOULD only install modules attested by a
//! trusted registry. Tenzro pins the canonical Rhinestone singleton at
//! `0x000000000069E2a187AEFFb852bF3cCdC95151B2` (the same address shipped on
//! Ethereum mainnet, Optimism, Arbitrum, Base, Polygon, etc. in 2026), but
//! the registry is pluggable per-account.
//!
//! # Native Selectors
//!
//! Selectors `0x01000060..=0x01000063` are reserved for module-management
//! operations. They are dispatched by `NativeExecutor` exactly the same way
//! as the escrow / kill-switch / workflow selector families.
//!
//! ```text
//! 0x01000060 - installValidator(account, module, init_data)
//! 0x01000061 - uninstallValidator(account, module)
//! 0x01000062 - attestModule(module, attestation_data)
//! ```
//!
//! `isValidatorInstalled` is a view operation (no selector — read directly
//! from the in-memory `ValidatorRegistry` via the dedicated query method).

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

use crate::account_abstraction::UserOperation;

// -----------------------------------------------------------------------------
// Selectors (4-byte function discriminators on the Native VM)
// -----------------------------------------------------------------------------

/// Selector: `installValidator(account, module, init_data)`
pub const SELECTOR_INSTALL_VALIDATOR: [u8; 4] = [0x01, 0x00, 0x00, 0x60];

/// Selector: `uninstallValidator(account, module)`
pub const SELECTOR_UNINSTALL_VALIDATOR: [u8; 4] = [0x01, 0x00, 0x00, 0x61];

/// Selector: `attestModule(module, attestation_data)`
pub const SELECTOR_ATTEST_MODULE: [u8; 4] = [0x01, 0x00, 0x00, 0x62];

// -----------------------------------------------------------------------------
// ERC-7484 canonical registry
// -----------------------------------------------------------------------------

/// Rhinestone Module Registry singleton — same 20-byte address on every
/// EVM-compatible chain (Ethereum, Optimism, Arbitrum, Base, Polygon, …)
/// per ERC-7484 §4.
pub const ERC7484_REGISTRY_ADDRESS: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x69, 0xE2, 0xa1, 0x87, 0xAE,
    0xFF, 0xb8, 0x52, 0xbF, 0x3c, 0xCd, 0xC9, 0x51, 0x51, 0xB2,
];

// -----------------------------------------------------------------------------
// ERC-1271 magic value
// -----------------------------------------------------------------------------

/// ERC-1271 magic value returned by `isValidSignatureWithSender` on success:
/// `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
pub const ERC1271_MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

/// ERC-1271 failure value (any non-magic value works; we pin the canonical
/// `0xffffffff` per Safe / Biconomy convention).
pub const ERC1271_FAILURE_VALUE: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

// -----------------------------------------------------------------------------
// Module type
// -----------------------------------------------------------------------------

/// ERC-7579 §3.1 module types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ModuleType {
    Validator = 1,
    Executor = 2,
    Fallback = 3,
    Hook = 4,
}

impl ModuleType {
    pub fn from_u8(v: u8) -> Result<Self, ValidatorError> {
        match v {
            1 => Ok(Self::Validator),
            2 => Ok(Self::Executor),
            3 => Ok(Self::Fallback),
            4 => Ok(Self::Hook),
            _ => Err(ValidatorError::InvalidModuleType(v)),
        }
    }
}

// -----------------------------------------------------------------------------
// ValidationData (packed per ERC-4337 §6.1)
// -----------------------------------------------------------------------------

/// Result of `IValidator::validate_user_op`.
///
/// Packed wire format: `[aggregator (160 bits) | validUntil (48) | validAfter (48)]`.
/// This high-level struct keeps the fields unpacked; the on-chain `validateUserOp`
/// returns the packed `u256`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationData {
    /// Aggregator address (`Vec<u8>` of length 20, all-zero = no aggregator,
    /// all-one = signature failed).
    pub aggregator: Vec<u8>,
    /// Earliest timestamp the signature is valid (0 = no lower bound).
    pub valid_after: u64,
    /// Latest timestamp the signature is valid (0 = no upper bound).
    pub valid_until: u64,
}

impl ValidationData {
    /// `Ok(())` shorthand: signature valid, no aggregator, no time bounds.
    pub fn success() -> Self {
        Self {
            aggregator: vec![0u8; 20],
            valid_after: 0,
            valid_until: 0,
        }
    }

    /// `Err` shorthand: signature failed.
    pub fn failure() -> Self {
        Self {
            aggregator: vec![0xffu8; 20],
            valid_after: 0,
            valid_until: 0,
        }
    }

    /// `true` if the validator rejected the signature.
    pub fn is_failure(&self) -> bool {
        self.aggregator == vec![0xffu8; 20]
    }

    /// Pack to the ERC-4337 §6.1 256-bit wire form.
    /// Layout (high → low): aggregator (160) | validUntil (48) | validAfter (48).
    pub fn pack(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // 20 bytes aggregator at offset 0..20 (high 160 bits)
        let agg_len = self.aggregator.len().min(20);
        out[0..agg_len].copy_from_slice(&self.aggregator[..agg_len]);
        // validUntil at offset 20..26 (48 bits, big-endian, take low 6 bytes)
        let until = self.valid_until.to_be_bytes(); // 8 bytes
        out[20..26].copy_from_slice(&until[2..8]);
        // validAfter at offset 26..32
        let after = self.valid_after.to_be_bytes();
        out[26..32].copy_from_slice(&after[2..8]);
        out
    }
}

// -----------------------------------------------------------------------------
// IValidator trait
// -----------------------------------------------------------------------------

/// ERC-7579 validator-module interface.
///
/// Implementors are the cryptographic validation policies an account opts
/// into: WebAuthn assertion, delegation-scope check, TEE-bound attestation,
/// FROST threshold signature, etc.
pub trait IValidator: Send + Sync {
    /// Stable identifier of the module — typically the on-chain address of
    /// the validator contract. Used as the registry key.
    fn module_address(&self) -> [u8; 20];

    /// Validate an in-flight `UserOperation`. Implementations consume the
    /// `op.signature` field (or any module-specific encoding within it)
    /// against `op_hash`.
    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError>;

    /// ERC-1271 signature check on behalf of the account. Returns the
    /// 4-byte magic on success; any other 4-byte value (we use the canonical
    /// `0xffffffff`) on failure.
    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4];
}

// -----------------------------------------------------------------------------
// InstalledModule (priority-ordered)
// -----------------------------------------------------------------------------

/// A module installed on a specific account. Priority controls the order in
/// which the registry walks installed validators on `validate_user_op` —
/// lower numbers run first. **All installed validators must approve**
/// (AND-combiner); priority only governs evaluation order so cheap checks
/// short-circuit on failure before expensive ones run.
pub struct InstalledModule {
    pub account: Vec<u8>,
    pub module_type: ModuleType,
    pub module: Arc<dyn IValidator>,
    pub priority: u32,
    pub init_data: Vec<u8>,
}

impl std::fmt::Debug for InstalledModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstalledModule")
            .field("account", &hex::encode(&self.account))
            .field("module_type", &self.module_type)
            .field("module_address", &hex::encode(self.module.module_address()))
            .field("priority", &self.priority)
            .field("init_data_len", &self.init_data.len())
            .finish()
    }
}

// -----------------------------------------------------------------------------
// ModuleAttestationRegistry (ERC-7484 gate)
// -----------------------------------------------------------------------------

/// Per-module attestation record from an ERC-7484 registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleAttestation {
    pub module_address: [u8; 20],
    pub module_type: ModuleType,
    /// Attestation registry that issued the record.
    pub registry: [u8; 20],
    /// Attester address (signer of the attestation).
    pub attester: [u8; 20],
    /// Opaque attestation payload (audit hash, schema id, etc.).
    pub attestation_data: Vec<u8>,
    pub revoked: bool,
}

impl ModuleAttestation {
    pub fn is_active(&self) -> bool {
        !self.revoked
    }
}

/// In-memory mirror of an ERC-7484 module registry. Attestations are written
/// by the `attestModule` selector and consulted at install time.
#[derive(Debug, Default)]
pub struct ModuleAttestationRegistry {
    /// Keyed by (registry_address, module_address).
    attestations: DashMap<([u8; 20], [u8; 20]), ModuleAttestation>,
}

impl ModuleAttestationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attestation. Per ERC-7484, only the `attester` field of the
    /// registry would normally be authorised to call this — authorisation is
    /// enforced at the `attestModule` selector dispatch site.
    pub fn attest(&self, attestation: ModuleAttestation) {
        let key = (attestation.registry, attestation.module_address);
        self.attestations.insert(key, attestation);
    }

    pub fn revoke(&self, registry: &[u8; 20], module: &[u8; 20]) -> bool {
        if let Some(mut entry) = self.attestations.get_mut(&(*registry, *module)) {
            entry.revoked = true;
            true
        } else {
            false
        }
    }

    pub fn get(&self, registry: &[u8; 20], module: &[u8; 20]) -> Option<ModuleAttestation> {
        self.attestations
            .get(&(*registry, *module))
            .map(|e| e.value().clone())
    }

    /// `true` if `module` carries an active attestation from `registry`.
    pub fn is_attested(&self, registry: &[u8; 20], module: &[u8; 20]) -> bool {
        self.attestations
            .get(&(*registry, *module))
            .map(|e| e.is_active())
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.attestations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }
}

// -----------------------------------------------------------------------------
// ValidatorRegistry — installed-module index keyed by (account, module)
// -----------------------------------------------------------------------------

/// Per-account validator registry. Keyed by (account_address, module_address);
/// this lets the same module instance serve many accounts without contention.
#[derive(Debug)]
pub struct ValidatorRegistry {
    /// installed[(account, module_addr)] = InstalledModule
    installed: DashMap<(Vec<u8>, [u8; 20]), Arc<InstalledModule>>,
    /// account_index[account] = ordered list of module addresses (sorted by priority asc)
    account_index: DashMap<Vec<u8>, Vec<[u8; 20]>>,
    /// Trusted ERC-7484 registry that gates installs. Defaults to the Rhinestone singleton.
    trusted_registry: [u8; 20],
    /// Attestation table.
    attestations: Arc<ModuleAttestationRegistry>,
}

impl ValidatorRegistry {
    /// Construct a registry pinned to the canonical Rhinestone singleton
    /// (`0x000000000069E2a187AEFFb852bF3cCdC95151B2`).
    pub fn new() -> Self {
        Self::with_trusted_registry(ERC7484_REGISTRY_ADDRESS)
    }

    /// Construct a registry pinned to a non-default trusted ERC-7484 registry.
    pub fn with_trusted_registry(trusted_registry: [u8; 20]) -> Self {
        Self {
            installed: DashMap::new(),
            account_index: DashMap::new(),
            trusted_registry,
            attestations: Arc::new(ModuleAttestationRegistry::new()),
        }
    }

    /// Construct a registry sharing an existing attestation table — useful
    /// when the node-side attestation cache is built from on-chain logs and
    /// shared across many accounts' validator sets.
    pub fn with_attestations(
        trusted_registry: [u8; 20],
        attestations: Arc<ModuleAttestationRegistry>,
    ) -> Self {
        Self {
            installed: DashMap::new(),
            account_index: DashMap::new(),
            trusted_registry,
            attestations,
        }
    }

    pub fn trusted_registry(&self) -> &[u8; 20] {
        &self.trusted_registry
    }

    pub fn attestations(&self) -> Arc<ModuleAttestationRegistry> {
        Arc::clone(&self.attestations)
    }

    /// Install a validator on `account`. Per ERC-7484, the module must be
    /// attested in the trusted registry, otherwise the call is rejected with
    /// `ValidatorError::ModuleNotAttested`.
    ///
    /// `priority` controls the run order on `validate_user_op` (lower runs
    /// first). `init_data` is opaque per-module setup state.
    pub fn install(
        &self,
        account: Vec<u8>,
        module_type: ModuleType,
        module: Arc<dyn IValidator>,
        priority: u32,
        init_data: Vec<u8>,
    ) -> Result<(), ValidatorError> {
        // Phase 1 only handles Validator modules.
        if module_type != ModuleType::Validator {
            return Err(ValidatorError::UnsupportedModuleType(module_type));
        }

        let module_addr = module.module_address();

        // ERC-7484 attestation gate.
        if !self.attestations.is_attested(&self.trusted_registry, &module_addr) {
            return Err(ValidatorError::ModuleNotAttested {
                module: module_addr,
                registry: self.trusted_registry,
            });
        }

        let key = (account.clone(), module_addr);
        if self.installed.contains_key(&key) {
            return Err(ValidatorError::ModuleAlreadyInstalled {
                account: account.clone(),
                module: module_addr,
            });
        }

        let installed = Arc::new(InstalledModule {
            account: account.clone(),
            module_type,
            module,
            priority,
            init_data,
        });
        self.installed.insert(key, installed);

        // Maintain per-account priority-sorted index. Snapshot the addresses
        // first, sort outside the DashMap guard (so we never hold a RefMut on
        // `account_index` while reading `installed` — deadlock risk per the
        // workspace DashMap rule), then write the sorted list back.
        let mut addrs: Vec<[u8; 20]> = self
            .account_index
            .get(&account)
            .map(|e| e.value().clone())
            .unwrap_or_default();
        if !addrs.contains(&module_addr) {
            addrs.push(module_addr);
        }
        addrs.sort_by_key(|addr| {
            self.installed
                .get(&(account.clone(), *addr))
                .map(|m| m.priority)
                .unwrap_or(u32::MAX)
        });
        self.account_index.insert(account, addrs);

        Ok(())
    }

    /// Uninstall a validator from `account`. No-op (and `Ok(false)`) if the
    /// module wasn't installed.
    pub fn uninstall(
        &self,
        account: &[u8],
        module: &[u8; 20],
    ) -> Result<bool, ValidatorError> {
        let key = (account.to_vec(), *module);
        let removed = self.installed.remove(&key).is_some();
        if removed
            && let Some(mut idx) = self.account_index.get_mut(account)
        {
            idx.retain(|a| a != module);
        }
        Ok(removed)
    }

    /// `true` if `module` is installed on `account`.
    pub fn is_installed(&self, account: &[u8], module: &[u8; 20]) -> bool {
        self.installed.contains_key(&(account.to_vec(), *module))
    }

    /// Validators installed on `account`, in priority order (low first).
    pub fn list_for_account(&self, account: &[u8]) -> Vec<Arc<InstalledModule>> {
        let Some(idx) = self.account_index.get(account) else {
            return Vec::new();
        };
        idx.iter()
            .filter_map(|module_addr| {
                self.installed
                    .get(&(account.to_vec(), *module_addr))
                    .map(|e| Arc::clone(e.value()))
            })
            .collect()
    }

    /// Walk installed validators in priority order. **All installed validators
    /// must approve** for the user op to be considered valid (AND-combiner). If
    /// any validator returns `ValidationData::failure()`, the combined result
    /// is failure. If all approve, the returned `ValidationData` is the
    /// **intersection** of their `(valid_after, valid_until)` time windows —
    /// `valid_after` = max of all module's `valid_after`, `valid_until` =
    /// min of all module's non-zero `valid_until`. The aggregator field is
    /// kept from the highest-priority module.
    ///
    /// AND semantics are mandatory: each validator encodes a distinct security
    /// invariant (signature scheme, scope check, spending limit, …) and they
    /// must all hold simultaneously. OR semantics would let an attacker who
    /// controls only one validator's signing path bypass the others.
    ///
    /// If the account has no validators installed, returns
    /// `Err(ValidatorError::NoValidatorInstalled)`.
    ///
    /// This is the routing entry point invoked by `EntryPoint::validate_user_op`.
    pub fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        let validators = self.list_for_account(&op.sender);
        if validators.is_empty() {
            return Err(ValidatorError::NoValidatorInstalled {
                account: op.sender.clone(),
            });
        }

        let mut combined_aggregator: Option<Vec<u8>> = None;
        let mut combined_valid_after: u64 = 0;
        let mut combined_valid_until: u64 = 0; // 0 = no upper bound
        for v in validators {
            let data = v.module.validate_user_op(op, op_hash)?;
            if data.is_failure() {
                return Ok(ValidationData::failure());
            }
            if combined_aggregator.is_none() {
                combined_aggregator = Some(data.aggregator.clone());
            }
            // valid_after: latest of all
            if data.valid_after > combined_valid_after {
                combined_valid_after = data.valid_after;
            }
            // valid_until: earliest non-zero of all
            if data.valid_until != 0
                && (combined_valid_until == 0 || data.valid_until < combined_valid_until)
            {
                combined_valid_until = data.valid_until;
            }
        }

        Ok(ValidationData {
            aggregator: combined_aggregator.unwrap_or_else(|| vec![0u8; 20]),
            valid_after: combined_valid_after,
            valid_until: combined_valid_until,
        })
    }
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ValidatorError {
    #[error("invalid module type byte: {0}")]
    InvalidModuleType(u8),

    #[error("module type {0:?} is not yet supported (Phase 1 supports Validator only)")]
    UnsupportedModuleType(ModuleType),

    #[error("module 0x{} is not attested in registry 0x{}", hex::encode(module), hex::encode(registry))]
    ModuleNotAttested {
        module: [u8; 20],
        registry: [u8; 20],
    },

    #[error("module 0x{} already installed on account 0x{}", hex::encode(module), hex::encode(account))]
    ModuleAlreadyInstalled {
        account: Vec<u8>,
        module: [u8; 20],
    },

    #[error("account 0x{} has no validator installed", hex::encode(account))]
    NoValidatorInstalled { account: Vec<u8> },

    #[error("validator rejected the user op: {0}")]
    ValidationFailed(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

// -----------------------------------------------------------------------------
// NoOpValidator — reference module used by tests + as a wiring sanity-check
// -----------------------------------------------------------------------------

/// A trivial validator that accepts any non-empty signature. Useful as a
/// reference impl + as the default module installed by the no-op factory in
/// tests; **not** intended for production use.
pub struct NoOpValidator {
    address: [u8; 20],
}

impl NoOpValidator {
    pub fn new(address: [u8; 20]) -> Self {
        Self { address }
    }
}

impl IValidator for NoOpValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        _op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        if op.signature.is_empty() {
            return Ok(ValidationData::failure());
        }
        Ok(ValidationData::success())
    }

    fn is_valid_signature_with_sender(
        &self,
        _sender: &[u8],
        _hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        if signature.is_empty() {
            ERC1271_FAILURE_VALUE
        } else {
            ERC1271_MAGIC_VALUE
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_abstraction::UserOperation;

    fn dummy_user_op(sender: Vec<u8>, sig: Vec<u8>) -> UserOperation {
        UserOperation {
            sender,
            nonce: 0,
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
    fn module_type_round_trip() {
        for t in [
            ModuleType::Validator,
            ModuleType::Executor,
            ModuleType::Fallback,
            ModuleType::Hook,
        ] {
            assert_eq!(ModuleType::from_u8(t as u8).unwrap(), t);
        }
        assert!(ModuleType::from_u8(0).is_err());
        assert!(ModuleType::from_u8(5).is_err());
    }

    #[test]
    fn validation_data_pack_layout() {
        let data = ValidationData {
            aggregator: vec![0u8; 20],
            valid_after: 0x0102_0304_0506,
            valid_until: 0x0a0b_0c0d_0e0f,
        };
        let packed = data.pack();
        // First 20 bytes = aggregator
        assert_eq!(&packed[..20], &[0u8; 20]);
        // Next 6 bytes = validUntil (low 48 bits, big-endian)
        assert_eq!(&packed[20..26], &[0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        // Last 6 bytes = validAfter (low 48 bits, big-endian)
        assert_eq!(&packed[26..32], &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn validation_data_failure_marker() {
        let f = ValidationData::failure();
        assert!(f.is_failure());
        let s = ValidationData::success();
        assert!(!s.is_failure());
    }

    #[test]
    fn install_requires_attestation() {
        let reg = ValidatorRegistry::new();
        let module_addr = [0x42u8; 20];
        let module = Arc::new(NoOpValidator::new(module_addr));
        let account = vec![0x01; 20];

        // Without an attestation, install must fail.
        let err = reg
            .install(
                account.clone(),
                ModuleType::Validator,
                module.clone(),
                100,
                vec![],
            )
            .unwrap_err();
        assert!(matches!(err, ValidatorError::ModuleNotAttested { .. }));
        assert!(!reg.is_installed(&account, &module_addr));

        // After attestation, install succeeds.
        attest_module(&reg, module_addr);
        reg.install(
            account.clone(),
            ModuleType::Validator,
            module.clone(),
            100,
            vec![],
        )
        .unwrap();
        assert!(reg.is_installed(&account, &module_addr));
    }

    #[test]
    fn install_rejects_non_validator_types() {
        let reg = ValidatorRegistry::new();
        let module_addr = [0x42u8; 20];
        let module = Arc::new(NoOpValidator::new(module_addr));
        attest_module(&reg, module_addr);
        let account = vec![0x01; 20];

        for t in [ModuleType::Executor, ModuleType::Fallback, ModuleType::Hook] {
            let err = reg
                .install(account.clone(), t, module.clone(), 100, vec![])
                .unwrap_err();
            assert!(matches!(err, ValidatorError::UnsupportedModuleType(_)));
        }
    }

    #[test]
    fn install_rejects_duplicate() {
        let reg = ValidatorRegistry::new();
        let module_addr = [0x42u8; 20];
        let module = Arc::new(NoOpValidator::new(module_addr));
        attest_module(&reg, module_addr);
        let account = vec![0x01; 20];

        reg.install(
            account.clone(),
            ModuleType::Validator,
            module.clone(),
            100,
            vec![],
        )
        .unwrap();
        let err = reg
            .install(
                account.clone(),
                ModuleType::Validator,
                module.clone(),
                200,
                vec![],
            )
            .unwrap_err();
        assert!(matches!(err, ValidatorError::ModuleAlreadyInstalled { .. }));
    }

    #[test]
    fn uninstall_round_trip() {
        let reg = ValidatorRegistry::new();
        let module_addr = [0x42u8; 20];
        let module = Arc::new(NoOpValidator::new(module_addr));
        attest_module(&reg, module_addr);
        let account = vec![0x01; 20];

        reg.install(
            account.clone(),
            ModuleType::Validator,
            module.clone(),
            100,
            vec![],
        )
        .unwrap();
        assert!(reg.is_installed(&account, &module_addr));

        let removed = reg.uninstall(&account, &module_addr).unwrap();
        assert!(removed);
        assert!(!reg.is_installed(&account, &module_addr));

        // Second uninstall is a no-op.
        let removed2 = reg.uninstall(&account, &module_addr).unwrap();
        assert!(!removed2);
    }

    #[test]
    fn validate_routes_to_installed_validator() {
        let reg = ValidatorRegistry::new();
        let module_addr = [0x42u8; 20];
        let module = Arc::new(NoOpValidator::new(module_addr));
        attest_module(&reg, module_addr);
        let account = vec![0x01; 20];

        reg.install(
            account.clone(),
            ModuleType::Validator,
            module.clone(),
            100,
            vec![],
        )
        .unwrap();

        let op = dummy_user_op(account.clone(), vec![0xAA; 65]);
        let hash = [0u8; 32];
        let data = reg.validate_user_op(&op, &hash).unwrap();
        assert!(!data.is_failure());

        // Empty signature → NoOpValidator returns failure.
        let bad = dummy_user_op(account.clone(), vec![]);
        let data = reg.validate_user_op(&bad, &hash).unwrap();
        assert!(data.is_failure());
    }

    #[test]
    fn validate_errors_with_no_validator_installed() {
        let reg = ValidatorRegistry::new();
        let account = vec![0x01; 20];
        let op = dummy_user_op(account, vec![0xAA; 65]);
        let hash = [0u8; 32];
        let err = reg.validate_user_op(&op, &hash).unwrap_err();
        assert!(matches!(err, ValidatorError::NoValidatorInstalled { .. }));
    }

    #[test]
    fn validate_and_combiner_all_accept_succeeds() {
        let reg = ValidatorRegistry::new();
        let account = vec![0x01; 20];

        // Module A: address 0xAA, priority 50, accepts any non-empty sig.
        let mod_a_addr = [0xAAu8; 20];
        let mod_a: Arc<dyn IValidator> = Arc::new(NoOpValidator::new(mod_a_addr));
        attest_module(&reg, mod_a_addr);
        reg.install(account.clone(), ModuleType::Validator, mod_a, 50, vec![])
            .unwrap();

        // Module B: address 0xBB, priority 100, also accepts.
        let mod_b_addr = [0xBBu8; 20];
        let mod_b: Arc<dyn IValidator> = Arc::new(NoOpValidator::new(mod_b_addr));
        attest_module(&reg, mod_b_addr);
        reg.install(account.clone(), ModuleType::Validator, mod_b, 100, vec![])
            .unwrap();

        let op = dummy_user_op(account.clone(), vec![0x42; 32]);
        let hash = [0u8; 32];
        // Both accept; AND-combiner returns success.
        let data = reg.validate_user_op(&op, &hash).unwrap();
        assert!(!data.is_failure());

        // Priority order is preserved in the listing (cheap checks first).
        let listed = reg.list_for_account(&account);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].module.module_address(), mod_a_addr);
        assert_eq!(listed[1].module.module_address(), mod_b_addr);
    }

    #[test]
    fn attestation_revocation_blocks_future_installs() {
        let reg = ValidatorRegistry::new();
        let module_addr = [0x42u8; 20];
        attest_module(&reg, module_addr);
        assert!(reg
            .attestations()
            .is_attested(reg.trusted_registry(), &module_addr));

        reg.attestations()
            .revoke(reg.trusted_registry(), &module_addr);
        assert!(!reg
            .attestations()
            .is_attested(reg.trusted_registry(), &module_addr));

        let module = Arc::new(NoOpValidator::new(module_addr));
        let err = reg
            .install(
                vec![0x01; 20],
                ModuleType::Validator,
                module,
                100,
                vec![],
            )
            .unwrap_err();
        assert!(matches!(err, ValidatorError::ModuleNotAttested { .. }));
    }

    #[test]
    fn no_op_validator_erc1271_magic() {
        let v = NoOpValidator::new([0x42; 20]);
        assert_eq!(
            v.is_valid_signature_with_sender(&[], &[0u8; 32], &[0xAA]),
            ERC1271_MAGIC_VALUE
        );
        assert_eq!(
            v.is_valid_signature_with_sender(&[], &[0u8; 32], &[]),
            ERC1271_FAILURE_VALUE
        );
    }

    #[test]
    fn entry_point_routes_signature_check_to_validator_registry() {
        use crate::account_abstraction::{AccountAbstractionError, EntryPoint};

        // Build a registry with a no-op validator installed for `account`.
        let reg = Arc::new(ValidatorRegistry::new());
        let module_addr = [0x42u8; 20];
        let module = Arc::new(NoOpValidator::new(module_addr));
        attest_module(&reg, module_addr);
        let account = vec![0x01; 20];
        reg.install(
            account.clone(),
            ModuleType::Validator,
            module.clone(),
            100,
            vec![],
        )
        .unwrap();

        // Attach the registry to a fresh EntryPoint. Balance is no longer
        // tracked at the EntryPoint level — execution-time VmState owns it.
        let entry_point = EntryPoint::new(vec![0xEE; 20])
            .with_chain_id(1337)
            .with_validator_registry(Arc::clone(&reg));

        // (a) Non-empty sig: NoOp accepts → EntryPoint validate succeeds.
        let mut op = dummy_user_op(account.clone(), vec![0xAA; 65]);
        op.nonce = entry_point.get_nonce(&account);
        entry_point.validate_user_op(&op).unwrap();

        // (b) Empty sig: NoOp returns failure → EntryPoint surfaces InvalidSignature.
        let bad = dummy_user_op(account.clone(), vec![]);
        let err = entry_point.validate_user_op(&bad).unwrap_err();
        assert!(matches!(err, AccountAbstractionError::InvalidSignature));

        // (c) For an account with NO installed validator, EntryPoint falls
        // back to the legacy length check (non-empty sig is enough).
        let other = vec![0x02; 20];
        let op2 = dummy_user_op(other, vec![0xBB; 65]);
        entry_point.validate_user_op(&op2).unwrap();
    }

    #[test]
    fn registry_address_is_canonical_singleton() {
        // Pinned Rhinestone ERC-7484 singleton — same 20-byte address on
        // every EVM chain. Stored without the "0x" prefix.
        assert_eq!(
            hex::encode(ERC7484_REGISTRY_ADDRESS),
            "000000000069e2a187aeffb852bf3ccdc95151b2"
        );
    }
}
