//! DelegationScope validator (ERC-7579 module) — cryptographic scope enforcement.
//!
//! This validator is the **primary** custody control for delegated machine
//! identities. It composes an inner `IValidator` (which authenticates the
//! signer — e.g. a [`crate::aa_webauthn_validator::WebAuthnValidator`] or a
//! plain Ed25519 validator) with a `ScopeOracle` lookup that enforces the
//! TDIP `DelegationScope` and the runtime `SpendingPolicy` cryptographically
//! at AA validation time.
//!
//! # Why a wrapper?
//!
//! ERC-7579 §6.1 (`IValidator.validateUserOp`) is the *only* place where the
//! EntryPoint asks "is this UserOp authorised for this account?". Anything
//! that is not enforced here is purely defence-in-depth and can be bypassed
//! by an attacker who controls only the signer (cf. the Grok / Bankr drain
//! incidents in May 2026 — the fix was to force the validator to evaluate
//! the spending scope before returning success). So the canonical pattern is:
//!
//! ```text
//! DelegationScopeValidator {
//!     inner:  Arc<dyn IValidator>,   // signature / auth check
//!     oracle: Arc<dyn ScopeOracle>,  // identity + runtime policy lookup
//! }
//! ```
//!
//! Validation succeeds only when both legs pass.
//!
//! # Layer split
//!
//! `tenzro-vm` cannot depend on `tenzro-identity` or `tenzro-payments`
//! (the dep graph runs the other way). So this module defines a
//! `ScopeOracle` trait whose concrete impl lives at the node layer (alongside
//! `AgentRuntimeSpendingPolicyResolver` in `crates/tenzro-node/src/`). The
//! oracle returns an `EnforcedScope` snapshot — a flat, self-contained value
//! that encodes everything the validator needs:
//!
//! - per-tx ceiling and per-day ceiling (intersection of `DelegationScope` and
//!   runtime `SpendingPolicy`),
//! - allowed call targets (`allowed_contracts`),
//! - allowed selectors (`allowed_operations` — represented as 4-byte function
//!   selectors so we don't have to parse the call_data heuristically),
//! - allowed chains and payment protocols (advisory, surfaced for the
//!   payments/bridge layers downstream),
//! - validity window (`not_before`, `not_after`),
//! - daily-spend window state (`window_start_ts`, `spent_in_window`).
//!
//! The validator then takes the userOp's `(value, callTarget, selector)`
//! triple and checks each axis. Failure on any axis returns
//! `ValidationData::failure()`.
//!
//! # Time encoding in ValidationData
//!
//! ERC-4337 §6.1 packs `(aggregator, validUntil, validAfter)` into a single
//! 256-bit return word. We surface the scope's `(not_before, not_after)`
//! through this packing so the EntryPoint enforces the time bound on-chain
//! without needing the off-chain oracle to be re-consulted at execution time.

use dashmap::DashMap;
use std::sync::Arc;

use crate::aa_validators::{IValidator, ValidationData, ValidatorError};
use crate::account_abstraction::UserOperation;

// -----------------------------------------------------------------------------
// EnforcedScope — flat, self-contained snapshot returned by the oracle
// -----------------------------------------------------------------------------

/// Self-contained scope snapshot returned by [`ScopeOracle::lookup`].
///
/// Encodes the **intersection** of TDIP `DelegationScope` (the protocol
/// ceiling) and the runtime `SpendingPolicy` (the execution ceiling). The
/// validator does not see either source type — only this projected snapshot.
#[derive(Debug, Clone)]
pub struct EnforcedScope {
    /// Per-transaction ceiling (smallest unit, e.g. wei). `None` = unlimited.
    pub max_per_tx: Option<u128>,
    /// Per-day ceiling (smallest unit). `None` = unlimited.
    pub max_per_day: Option<u128>,
    /// 4-byte selectors the validator may invoke. Empty = any selector
    /// (operation-allowlist disabled).
    pub allowed_selectors: Vec<[u8; 4]>,
    /// 20-byte call targets the validator may invoke. Empty = any target
    /// (target-allowlist disabled).
    pub allowed_targets: Vec<[u8; 20]>,
    /// Validity window — Unix seconds. `valid_after` is the not-before; ops
    /// arriving before this time fail. `valid_until == 0` means no upper
    /// bound (per ERC-4337 §6.1 packing convention).
    pub valid_after: u64,
    pub valid_until: u64,
    /// Tracking state for the per-day ceiling: when did the current
    /// 24h window start, and how much has already been spent. Both are
    /// authoritative on the oracle side; the validator uses them only to
    /// reject a tx that would push the new total past `max_per_day`.
    pub window_start_ts: u64,
    pub spent_in_window: u128,
    /// Now timestamp for window-rollover detection. The oracle injects
    /// monotonic time so the validator never reads a clock directly.
    pub now_ts: u64,
}

impl EnforcedScope {
    /// Convenience constructor for "no restrictions" scopes — used by the
    /// node oracle for human identities (humans bypass delegation per
    /// `IdentityRegistry::enforce_operation`) and for tests.
    pub fn unrestricted(now_ts: u64) -> Self {
        Self {
            max_per_tx: None,
            max_per_day: None,
            allowed_selectors: Vec::new(),
            allowed_targets: Vec::new(),
            valid_after: 0,
            valid_until: 0,
            window_start_ts: now_ts,
            spent_in_window: 0,
            now_ts,
        }
    }

    /// Effective remaining daily allowance, accounting for window rollover.
    ///
    /// If the 24h window starting at `window_start_ts` has elapsed, the
    /// counter resets to zero (the oracle is responsible for persisting this
    /// reset; the validator only computes the in-memory view). Returns
    /// `None` if `max_per_day` is unlimited.
    pub fn remaining_today(&self) -> Option<u128> {
        let max = self.max_per_day?;
        let window_elapsed = self.now_ts.saturating_sub(self.window_start_ts);
        if window_elapsed >= ONE_DAY_SECS {
            // Window has rolled over; the full ceiling is available.
            return Some(max);
        }
        Some(max.saturating_sub(self.spent_in_window))
    }
}

const ONE_DAY_SECS: u64 = 24 * 60 * 60;

// -----------------------------------------------------------------------------
// CallIntent — what the validator extracts from a UserOperation
// -----------------------------------------------------------------------------

/// The `(target, selector, value)` the validator pulls out of the UserOp's
/// `call_data` to evaluate against the enforced scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallIntent {
    /// The contract being called. For ERC-4337 this is parsed from the
    /// `execute(address,uint256,bytes)` calldata or batched equivalent.
    pub target: [u8; 20],
    /// First 4 bytes of the inner calldata. `None` if the inner call is
    /// pure value-transfer (zero-length data).
    pub selector: Option<[u8; 4]>,
    /// Native value forwarded to the target (smallest unit).
    pub value: u128,
}

// -----------------------------------------------------------------------------
// CallIntentDecoder — pluggable extractor
//
// ERC-7579 `Execution::execute(address target, uint256 value, bytes data)`
// selector: `keccak256("execute(address,uint256,bytes)")[..4]`.
//
// We don't hard-code one canonical selector here because ERC-7579's IExecutor
// surface is open-ended. Instead, the validator accepts any call_data shape
// via the CallIntentDecoder trait — the default is StandardExecuteDecoder
// which understands the canonical `execute(address,uint256,bytes)` ABI
// encoding.
// -----------------------------------------------------------------------------

/// Pluggable strategy for extracting a [`CallIntent`] from a UserOp's
/// `call_data`. The default impl handles the canonical
/// `execute(address,uint256,bytes)` envelope.
pub trait CallIntentDecoder: Send + Sync {
    fn decode(&self, call_data: &[u8]) -> Result<CallIntent, ValidatorError>;
}

/// Decodes the canonical ERC-7579 / Safe / Kernel
/// `execute(address target, uint256 value, bytes data)` envelope.
///
/// Layout (ABI-encoded): `selector(4) ‖ pad(12) ‖ target(20) ‖ value(32) ‖
/// offset(32) ‖ length(32) ‖ data_padded`.
pub struct StandardExecuteDecoder;

impl CallIntentDecoder for StandardExecuteDecoder {
    fn decode(&self, call_data: &[u8]) -> Result<CallIntent, ValidatorError> {
        // Minimum: 4 (outer selector) + 32 (target word) + 32 (value) + 32 (data offset) + 32 (data length) = 132.
        if call_data.len() < 132 {
            return Err(ValidatorError::InvalidInput(format!(
                "execute() call_data too short: {} bytes (need ≥132)",
                call_data.len()
            )));
        }
        // target is right-aligned in the second 32-byte word.
        let mut target = [0u8; 20];
        target.copy_from_slice(&call_data[4 + 12..4 + 32]);

        // value is the next 32 bytes, big-endian. Right-align u128 from the
        // low 16 bytes; reject any non-zero high 16 bytes (preventing silent
        // truncation of values > u128::MAX).
        let value_word = &call_data[4 + 32..4 + 64];
        if value_word[..16].iter().any(|&b| b != 0) {
            return Err(ValidatorError::InvalidInput(
                "execute() value > u128::MAX".to_string(),
            ));
        }
        let mut value_bytes = [0u8; 16];
        value_bytes.copy_from_slice(&value_word[16..]);
        let value = u128::from_be_bytes(value_bytes);

        // Inner data offset (always 0x60 for this ABI shape, but we read it
        // anyway in case of non-canonical encodings).
        let mut offset_bytes = [0u8; 32];
        offset_bytes.copy_from_slice(&call_data[4 + 64..4 + 96]);
        // Treat the offset as u64 — anything larger than the call_data is
        // malformed.
        let offset = u64::from_be_bytes(offset_bytes[24..].try_into().unwrap()) as usize;
        let data_start = 4 + offset;
        if data_start + 32 > call_data.len() {
            return Err(ValidatorError::InvalidInput(
                "execute() inner data offset out of range".to_string(),
            ));
        }
        let mut len_bytes = [0u8; 32];
        len_bytes.copy_from_slice(&call_data[data_start..data_start + 32]);
        let inner_len = u64::from_be_bytes(len_bytes[24..].try_into().unwrap()) as usize;
        let inner_start = data_start + 32;
        if inner_start + inner_len > call_data.len() {
            return Err(ValidatorError::InvalidInput(
                "execute() inner data length out of range".to_string(),
            ));
        }

        let selector = if inner_len >= 4 {
            let mut s = [0u8; 4];
            s.copy_from_slice(&call_data[inner_start..inner_start + 4]);
            Some(s)
        } else {
            None
        };

        Ok(CallIntent {
            target,
            selector,
            value,
        })
    }
}

// -----------------------------------------------------------------------------
// ScopeOracle — node-side bridge to identity + spending-policy registries
// -----------------------------------------------------------------------------

/// Node-side bridge that projects the union of TDIP `DelegationScope` and
/// runtime `SpendingPolicy` into the flat [`EnforcedScope`] snapshot the
/// validator consumes.
///
/// The concrete impl lives in `tenzro-node` (alongside the existing
/// `AgentRuntimeSpendingPolicyResolver`) and is wired in at node startup.
/// During unit tests we use [`InMemoryScopeOracle`].
pub trait ScopeOracle: Send + Sync {
    /// Look up the effective scope for `account`. Returns `None` if the
    /// account is not bound to any identity (and therefore the validator
    /// should fail closed rather than fall through).
    fn lookup(&self, account: &[u8]) -> Option<EnforcedScope>;
}

/// Test/default oracle that holds scopes in-memory keyed by account.
#[derive(Debug, Default)]
pub struct InMemoryScopeOracle {
    scopes: DashMap<Vec<u8>, EnforcedScope>,
}

impl InMemoryScopeOracle {
    pub fn new() -> Self {
        Self {
            scopes: DashMap::new(),
        }
    }

    pub fn set(&self, account: Vec<u8>, scope: EnforcedScope) {
        self.scopes.insert(account, scope);
    }

    pub fn remove(&self, account: &[u8]) -> bool {
        self.scopes.remove(account).is_some()
    }
}

impl ScopeOracle for InMemoryScopeOracle {
    fn lookup(&self, account: &[u8]) -> Option<EnforcedScope> {
        self.scopes.get(account).map(|e| e.value().clone())
    }
}

// -----------------------------------------------------------------------------
// DelegationScopeValidator
// -----------------------------------------------------------------------------

/// ERC-7579 validator that wraps an `inner` authenticator with a
/// scope-enforcement layer.
///
/// Validation order:
/// 1. Inner validator (signature check). Failure short-circuits.
/// 2. Decode `op.call_data` into a [`CallIntent`].
/// 3. Look up the [`EnforcedScope`] for `op.sender` via the oracle.
///    Unbound accounts fail closed.
/// 4. Check selector / target / per-tx value / per-day cumulative value.
///    Time bounds are surfaced through the returned `ValidationData`.
pub struct DelegationScopeValidator {
    address: [u8; 20],
    inner: Arc<dyn IValidator>,
    oracle: Arc<dyn ScopeOracle>,
    decoder: Arc<dyn CallIntentDecoder>,
}

impl DelegationScopeValidator {
    /// Construct a new scope validator. The default decoder handles
    /// `execute(address,uint256,bytes)`.
    pub fn new(
        address: [u8; 20],
        inner: Arc<dyn IValidator>,
        oracle: Arc<dyn ScopeOracle>,
    ) -> Self {
        Self {
            address,
            inner,
            oracle,
            decoder: Arc::new(StandardExecuteDecoder),
        }
    }

    /// Override the call-intent decoder (for non-standard execution envelopes
    /// like Safe's `execTransaction` or Kernel's batched executor).
    pub fn with_decoder(mut self, decoder: Arc<dyn CallIntentDecoder>) -> Self {
        self.decoder = decoder;
        self
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Apply the scope check against a decoded intent. Returns the merged
    /// `ValidationData` (success with time bound, or failure). Public so
    /// upstream simulators (RPC `tenzro_estimateUserOp`) can reuse the same
    /// pure check.
    pub fn enforce(intent: &CallIntent, scope: &EnforcedScope) -> ValidationData {
        // 1. Time-window guard. valid_after / valid_until are surfaced through
        // ValidationData; failures here come only from a hard miss (now > until).
        if scope.valid_until != 0 && scope.now_ts > scope.valid_until {
            return ValidationData::failure();
        }
        if scope.now_ts < scope.valid_after {
            return ValidationData::failure();
        }

        // 2. Per-tx ceiling.
        if let Some(max_tx) = scope.max_per_tx
            && intent.value > max_tx
        {
            return ValidationData::failure();
        }

        // 3. Per-day ceiling (with rollover).
        if let Some(max_day) = scope.max_per_day {
            let remaining = scope.remaining_today().unwrap_or(max_day);
            if intent.value > remaining {
                return ValidationData::failure();
            }
        }

        // 4. Target allow-list.
        if !scope.allowed_targets.is_empty() && !scope.allowed_targets.contains(&intent.target) {
            return ValidationData::failure();
        }

        // 5. Selector allow-list. Pure value-transfer (no selector) is
        // allowed only if either the allow-list is empty OR the zero
        // selector is explicitly listed.
        if !scope.allowed_selectors.is_empty() {
            match intent.selector {
                Some(sel) => {
                    if !scope.allowed_selectors.contains(&sel) {
                        return ValidationData::failure();
                    }
                }
                None => {
                    if !scope.allowed_selectors.contains(&[0u8; 4]) {
                        return ValidationData::failure();
                    }
                }
            }
        }

        // Surface the time bound through ValidationData so the EntryPoint
        // re-checks it on-chain at execute() time. valid_until=0 means
        // "no upper bound" in ERC-4337 §6.1 packing.
        ValidationData {
            aggregator: vec![0u8; 20],
            valid_after: scope.valid_after,
            valid_until: scope.valid_until,
        }
    }
}

impl IValidator for DelegationScopeValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        // 1. Authenticate via the inner validator. If it fails, the wrapper
        // fails — no point evaluating the scope on a forged signature.
        let inner_result = self.inner.validate_user_op(op, op_hash)?;
        if inner_result.is_failure() {
            return Ok(ValidationData::failure());
        }

        // 2. Decode the intent. Malformed call_data fails closed: an
        // attacker cannot bypass scope checks by passing garbage that
        // skips decoding.
        let intent = match self.decoder.decode(&op.call_data) {
            Ok(i) => i,
            Err(_) => return Ok(ValidationData::failure()),
        };

        // 3. Look up the scope. Unbound accounts fail closed.
        let Some(scope) = self.oracle.lookup(&op.sender) else {
            return Ok(ValidationData::failure());
        };

        // 4. Apply the scope check; intersect time bounds with the inner
        // validator's bounds (take the tighter window).
        let scope_result = Self::enforce(&intent, &scope);
        if scope_result.is_failure() {
            return Ok(ValidationData::failure());
        }

        Ok(merge_time_bounds(inner_result, scope_result))
    }

    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        // ERC-1271 has no notion of "intent" — there's no call_data to
        // decode. Delegate to the inner authenticator only. Scope is
        // enforced at validate_user_op time, which is the only path that
        // actually moves funds.
        self.inner
            .is_valid_signature_with_sender(sender, hash, signature)
    }
}

/// Intersect two `ValidationData` time windows: take the latest `valid_after`
/// and the earliest non-zero `valid_until`. Aggregator from `a` wins (the
/// inner validator owns the aggregator slot).
fn merge_time_bounds(a: ValidationData, b: ValidationData) -> ValidationData {
    let valid_after = a.valid_after.max(b.valid_after);
    let valid_until = match (a.valid_until, b.valid_until) {
        (0, x) => x,
        (x, 0) => x,
        (x, y) => x.min(y),
    };
    ValidationData {
        aggregator: a.aggregator,
        valid_after,
        valid_until,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aa_validators::{ERC1271_FAILURE_VALUE, NoOpValidator};
    use crate::account_abstraction::UserOperation;

    /// A test inner validator that fails iff `signature` is empty.
    struct LengthValidator(pub [u8; 20]);
    impl IValidator for LengthValidator {
        fn module_address(&self) -> [u8; 20] {
            self.0
        }
        fn validate_user_op(
            &self,
            op: &UserOperation,
            _hash: &[u8; 32],
        ) -> Result<ValidationData, ValidatorError> {
            if op.signature.is_empty() {
                Ok(ValidationData::failure())
            } else {
                Ok(ValidationData::success())
            }
        }
        fn is_valid_signature_with_sender(&self, _s: &[u8], _h: &[u8; 32], sig: &[u8]) -> [u8; 4] {
            if sig.is_empty() {
                ERC1271_FAILURE_VALUE
            } else {
                crate::aa_validators::ERC1271_MAGIC_VALUE
            }
        }
    }

    /// Build an ABI-encoded `execute(address,uint256,bytes)` call_data with
    /// the given target / value / inner_data.
    fn encode_execute(target: [u8; 20], value: u128, inner_data: &[u8]) -> Vec<u8> {
        // execute(address,uint256,bytes) selector: 0xb61d27f6
        let mut out = vec![0xb6, 0x1d, 0x27, 0xf6];
        // target — left-pad to 32 bytes.
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&target);
        // value — left-pad u128 to 32 bytes.
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&value.to_be_bytes());
        // bytes offset = 0x60 (= 96).
        let mut off = [0u8; 32];
        off[31] = 0x60;
        out.extend_from_slice(&off);
        // inner length.
        let mut len = [0u8; 32];
        let l = inner_data.len() as u64;
        len[24..].copy_from_slice(&l.to_be_bytes());
        out.extend_from_slice(&len);
        // inner data — pad to 32-byte multiple.
        out.extend_from_slice(inner_data);
        let pad = (32 - (inner_data.len() % 32)) % 32;
        out.extend_from_slice(&vec![0u8; pad]);
        out
    }

    fn dummy_user_op(sender: Vec<u8>, call_data: Vec<u8>, sig: Vec<u8>) -> UserOperation {
        UserOperation {
            sender,
            nonce: crate::account_abstraction::Nonce::from_seq(0).to_bytes(),
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

    const NOW: u64 = 2_000_000_000;
    const ACCOUNT: [u8; 20] = [0xAB; 20];
    const TARGET_OK: [u8; 20] = [0x01; 20];
    const TARGET_BAD: [u8; 20] = [0x02; 20];
    const SEL_OK: [u8; 4] = [0xA9, 0x05, 0x9C, 0xBB]; // transfer(address,uint256)
    const SEL_BAD: [u8; 4] = [0x42, 0x84, 0x2E, 0x0E]; // safeTransferFrom

    fn account() -> Vec<u8> {
        ACCOUNT.to_vec()
    }

    #[test]
    fn standard_execute_decoder_round_trip() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3], 0xDE, 0xAD];
        let cd = encode_execute(TARGET_OK, 12345u128, &inner);
        let intent = StandardExecuteDecoder.decode(&cd).unwrap();
        assert_eq!(intent.target, TARGET_OK);
        assert_eq!(intent.value, 12345u128);
        assert_eq!(intent.selector, Some(SEL_OK));
    }

    #[test]
    fn standard_execute_decoder_handles_pure_value_transfer() {
        let cd = encode_execute(TARGET_OK, 555u128, &[]);
        let intent = StandardExecuteDecoder.decode(&cd).unwrap();
        assert_eq!(intent.selector, None);
        assert_eq!(intent.value, 555);
    }

    #[test]
    fn standard_execute_decoder_rejects_short_data() {
        let r = StandardExecuteDecoder.decode(&[0u8; 50]);
        assert!(r.is_err());
    }

    #[test]
    fn standard_execute_decoder_rejects_value_above_u128() {
        let mut cd = encode_execute(TARGET_OK, 0u128, &[]);
        // poison the high byte of the value word.
        cd[4 + 32] = 0xFF;
        let r = StandardExecuteDecoder.decode(&cd);
        assert!(r.is_err());
    }

    fn build_validator(
        scope: EnforcedScope,
    ) -> (DelegationScopeValidator, Arc<InMemoryScopeOracle>) {
        let oracle = Arc::new(InMemoryScopeOracle::new());
        oracle.set(ACCOUNT.to_vec(), scope);
        let inner = Arc::new(LengthValidator([0xEE; 20]));
        let validator = DelegationScopeValidator::new([0x77; 20], inner, oracle.clone());
        (validator, oracle)
    }

    fn unrestricted_scope() -> EnforcedScope {
        let mut s = EnforcedScope::unrestricted(NOW);
        s.allowed_targets = vec![TARGET_OK];
        s.allowed_selectors = vec![SEL_OK];
        s
    }

    #[test]
    fn validate_succeeds_when_inner_passes_and_intent_in_scope() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3], 0xDE, 0xAD];
        let cd = encode_execute(TARGET_OK, 100u128, &inner);
        let (v, _) = build_validator(unrestricted_scope());
        let op = dummy_user_op(account(), cd, vec![1, 2, 3]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(!r.is_failure());
    }

    #[test]
    fn validate_fails_when_inner_signature_check_fails() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_OK, 100u128, &inner);
        let (v, _) = build_validator(unrestricted_scope());
        let op = dummy_user_op(account(), cd, vec![]); // empty sig → inner fails
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(r.is_failure());
    }

    #[test]
    fn validate_fails_when_target_not_allowed() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_BAD, 100u128, &inner);
        let (v, _) = build_validator(unrestricted_scope());
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(r.is_failure(), "disallowed target must fail");
    }

    #[test]
    fn validate_fails_when_selector_not_allowed() {
        let inner = vec![SEL_BAD[0], SEL_BAD[1], SEL_BAD[2], SEL_BAD[3]];
        let cd = encode_execute(TARGET_OK, 100u128, &inner);
        let (v, _) = build_validator(unrestricted_scope());
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(r.is_failure(), "disallowed selector must fail");
    }

    #[test]
    fn validate_fails_when_value_exceeds_per_tx() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_OK, 1_001u128, &inner);
        let mut s = unrestricted_scope();
        s.max_per_tx = Some(1_000);
        let (v, _) = build_validator(s);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(r.is_failure(), "over per-tx ceiling must fail");
    }

    #[test]
    fn validate_fails_when_value_exceeds_remaining_daily_budget() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_OK, 600u128, &inner);
        let mut s = unrestricted_scope();
        s.max_per_day = Some(1_000);
        s.window_start_ts = NOW - 3600; // 1h into window
        s.spent_in_window = 500;
        let (v, _) = build_validator(s);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(
            r.is_failure(),
            "spend that exceeds remaining day budget must fail"
        );
    }

    #[test]
    fn validate_succeeds_when_window_has_rolled_over() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_OK, 900u128, &inner);
        let mut s = unrestricted_scope();
        s.max_per_day = Some(1_000);
        // window started >24h ago — counter should reset
        s.window_start_ts = NOW - (ONE_DAY_SECS + 60);
        s.spent_in_window = 999; // would exceed if we hadn't rolled
        let (v, _) = build_validator(s);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(!r.is_failure(), "window rollover must restore the budget");
    }

    #[test]
    fn validate_fails_before_valid_after() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_OK, 100u128, &inner);
        let mut s = unrestricted_scope();
        s.valid_after = NOW + 60; // not yet valid
        let (v, _) = build_validator(s);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(r.is_failure());
    }

    #[test]
    fn validate_fails_after_valid_until() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_OK, 100u128, &inner);
        let mut s = unrestricted_scope();
        s.valid_until = NOW - 1; // expired
        let (v, _) = build_validator(s);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(r.is_failure());
    }

    #[test]
    fn validate_passes_through_valid_until_in_validation_data() {
        let inner = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_OK, 100u128, &inner);
        let mut s = unrestricted_scope();
        s.valid_after = NOW - 100;
        s.valid_until = NOW + 3600;
        let (v, _) = build_validator(s);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(!r.is_failure());
        assert_eq!(r.valid_after, NOW - 100);
        assert_eq!(r.valid_until, NOW + 3600);
    }

    #[test]
    fn validate_fails_when_oracle_has_no_binding() {
        let inner_data = vec![SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]];
        let cd = encode_execute(TARGET_OK, 100u128, &inner_data);
        // Oracle is empty.
        let oracle = Arc::new(InMemoryScopeOracle::new());
        let inner = Arc::new(LengthValidator([0xEE; 20]));
        let v = DelegationScopeValidator::new([0x77; 20], inner, oracle);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(r.is_failure(), "unbound account must fail closed");
    }

    #[test]
    fn validate_fails_on_malformed_call_data() {
        let (v, _) = build_validator(unrestricted_scope());
        let op = dummy_user_op(account(), vec![0xAA; 8], vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(r.is_failure(), "malformed call_data must fail closed");
    }

    #[test]
    fn pure_value_transfer_blocked_when_zero_selector_not_listed() {
        let cd = encode_execute(TARGET_OK, 100u128, &[]);
        let s = unrestricted_scope(); // selectors = [SEL_OK], no zero selector
        let (v, _) = build_validator(s);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(
            r.is_failure(),
            "pure value transfer blocked when zero selector not in allow-list"
        );
    }

    #[test]
    fn pure_value_transfer_allowed_when_zero_selector_listed() {
        let cd = encode_execute(TARGET_OK, 100u128, &[]);
        let mut s = unrestricted_scope();
        s.allowed_selectors.push([0u8; 4]);
        let (v, _) = build_validator(s);
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(
            !r.is_failure(),
            "pure value transfer allowed when zero selector listed"
        );
    }

    #[test]
    fn erc1271_passthrough_to_inner_validator() {
        let (v, _) = build_validator(unrestricted_scope());
        let magic = v.is_valid_signature_with_sender(&account(), &[0; 32], &[1, 2, 3]);
        assert_eq!(magic, crate::aa_validators::ERC1271_MAGIC_VALUE);
        let fail = v.is_valid_signature_with_sender(&account(), &[0; 32], &[]);
        assert_eq!(fail, ERC1271_FAILURE_VALUE);
    }

    #[test]
    fn merge_time_bounds_takes_tighter_window() {
        let a = ValidationData {
            aggregator: vec![0u8; 20],
            valid_after: 100,
            valid_until: 1000,
        };
        let b = ValidationData {
            aggregator: vec![0u8; 20],
            valid_after: 200,
            valid_until: 800,
        };
        let merged = merge_time_bounds(a, b);
        assert_eq!(merged.valid_after, 200);
        assert_eq!(merged.valid_until, 800);
    }

    #[test]
    fn merge_time_bounds_treats_zero_until_as_unbounded() {
        let a = ValidationData {
            aggregator: vec![0u8; 20],
            valid_after: 0,
            valid_until: 0,
        };
        let b = ValidationData {
            aggregator: vec![0u8; 20],
            valid_after: 0,
            valid_until: 500,
        };
        let merged = merge_time_bounds(a, b);
        assert_eq!(merged.valid_until, 500);
    }

    #[test]
    fn unrestricted_scope_admits_anything_within_allowlists() {
        let s = EnforcedScope::unrestricted(NOW);
        assert!(s.max_per_tx.is_none());
        assert!(s.max_per_day.is_none());
        assert_eq!(s.allowed_targets.len(), 0);
        assert_eq!(s.allowed_selectors.len(), 0);
    }

    #[test]
    fn no_op_validator_composes_with_scope_validator() {
        // Sanity: composing the no-op auth + a tight scope still enforces scope.
        let inner = Arc::new(NoOpValidator::new([0x11; 20]));
        let oracle = Arc::new(InMemoryScopeOracle::new());
        oracle.set(ACCOUNT.to_vec(), unrestricted_scope());
        let v = DelegationScopeValidator::new([0x77; 20], inner, oracle);
        let cd = encode_execute(
            TARGET_BAD,
            100u128,
            &[SEL_OK[0], SEL_OK[1], SEL_OK[2], SEL_OK[3]],
        );
        let op = dummy_user_op(account(), cd, vec![1]);
        let r = v.validate_user_op(&op, &[0; 32]).unwrap();
        assert!(
            r.is_failure(),
            "scope check applies even when inner is no-op"
        );
    }
}
