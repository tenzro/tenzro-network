//! Passkey-first wallet onboarding + custody RPC handlers.
//!
//! This module implements the user-facing custody surface that backs the
//! passkey-first wallet model laid out in the architecture notes:
//!
//! - **Enrollment** — `tenzro_enrollPasskey` consumes a WebAuthn attestation,
//!   creates a TDIP human identity, deploys an ERC-4337 smart account, and
//!   installs `WebAuthnValidator` as the primary signer. The user's signing
//!   key never leaves their hardware secure element.
//!
//! - **Signing** — `tenzro_signWithPasskey` consumes a WebAuthn assertion
//!   and routes it through the existing `EntryPoint::validate_user_op`
//!   chain. The smart account address is the identity, not the key — so the
//!   key can rotate without the address changing.
//!
//! - **Social recovery** — `tenzro_addGuardian` registers a guardian
//!   composite public key on `SocialRecoveryValidator`.
//!   `tenzro_initiateRecovery`, `tenzro_submitRecoverySignature`, and
//!   `tenzro_finalizeRecovery` drive a guardian-quorum flow that rotates the
//!   account's `WebAuthnValidator` to a freshly enrolled passkey when the
//!   user loses access to their primary device.
//!
//! - **Session keys** — `tenzro_grantSessionKey` installs
//!   `SessionKeyValidator` configs with scoped permissions (allowed selectors,
//!   per-tx + cumulative value caps, time bounds) so an agent can sign a
//!   bounded subset of operations without holding the human's passkey.
//!
//! - **Hardware signers** — `tenzro_addHardwareSigner` (Ledger / Trezor /
//!   GridPlus / generic) installs a `HardwareValidatorModule` as an
//!   additional ANDed validator for high-value operations.
//!
//! All persistence flows through the existing `CF_VALIDATOR_MODULES` column
//! family + the per-validator `with_storage` constructors; the
//! `PendingRecoveryStore` in this module persists in-flight recovery state
//! so an interrupted guardian-quorum ceremony resumes cleanly after restart.

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_crypto::pq::ML_DSA_65_VK_LEN;
use tenzro_crypto::webauthn::WebAuthnAssertion;
use tenzro_storage::{CF_VALIDATOR_MODULES, KvStore};
use tenzro_vm::{
    HybridWebAuthnSignature, SecondFactorPolicy, SessionKeyConfig, SocialRecoveryConfig,
    SpendingLimitConfig, WebAuthnAccountKey,
};

// =============================================================================
// PendingRecoveryStore — in-flight guardian-quorum ceremony persistence
// =============================================================================

/// One in-flight social-recovery ceremony. Created by
/// `tenzro_initiateRecovery`, mutated by each `tenzro_submitRecoverySignature`,
/// and consumed by `tenzro_finalizeRecovery`. Persists to
/// `CF_VALIDATOR_MODULES / erc7579/recovery_pending/<recovery_id>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRecovery {
    /// Unique recovery ID — SHA-256 of (`account_address` ‖ `new_passkey_pubkey` ‖ `created_at`).
    pub recovery_id: String,
    /// Target smart-account address (20 bytes hex).
    pub account_address: String,
    /// The new WebAuthn account-key to install once quorum is reached.
    pub new_passkey: WebAuthnAccountKey,
    /// Opaque credential ID for the new passkey — carried in metadata so the
    /// desktop / web client can re-locate the credential after rotation.
    pub new_credential_id: Vec<u8>,
    /// `(guardian_index, composite_signature_bytes_b64)` tuples collected so far.
    pub guardian_signatures: Vec<(u32, String)>,
    /// Unix timestamp (millis) at which this ceremony was started.
    pub created_at_ms: u64,
    /// Unix timestamp (millis) after which the ceremony auto-expires.
    pub expires_at_ms: u64,
    /// Marker — set once the ceremony has been finalized successfully so a
    /// duplicate `finalizeRecovery` call returns the same outcome.
    pub finalized: bool,
}

/// Persistent store for in-flight recovery ceremonies. Backed by `CF_VALIDATOR_MODULES`.
pub struct PendingRecoveryStore {
    storage: Arc<dyn KvStore>,
}

/// Per-process MAC key used to integrity-tag rows persisted under
/// `CF_VALIDATOR_MODULES / erc7579/recovery_pending/`. Stored at
/// `~/.tenzro/local_state_mac.key` (0600); generated on first call.
///
/// **Threat model:** detects accidental corruption + cross-process
/// tampering of pending-recovery rows. Does NOT defend against
/// in-process malware running as the same OS user (the key sits in
/// the same trust boundary). The OS-keychain binding upgrade
/// (Keychain `SecAccessControl` on macOS / DPAPI on Windows /
/// libsecret on Linux) is deferred — current implementation already
/// catches the threat class the user explicitly worried about
/// ("user editing RocksDB to inflate balance / swap credential").
fn local_mac_key() -> &'static [u8; 32] {
    use std::sync::OnceLock;
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let path = match tenzro_types::paths::try_tenzro_home() {
            Ok(_) => tenzro_types::paths::local_state_mac_key_path(),
            Err(e) => {
                tracing::warn!(%e, "local_mac_key: using zero key (tests only)");
                return [0u8; 32];
            }
        };
        if let Ok(bytes) = std::fs::read(&path)
            && bytes.len() == 32
        {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return k;
        }
        let mut k = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut k);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&path, k) {
            tracing::warn!(error = %e, "local_mac_key: failed to persist MAC key");
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        k
    })
}

/// Wrap a payload with a 32-byte tag derived from
/// `SHA256(mac_key ‖ payload)`. On-disk layout becomes `[tag(32) ‖ payload]`.
/// Replaces the raw bytes the row used to hold; verify with `mac_verify`.
fn mac_wrap(payload: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(local_mac_key());
    h.update(payload);
    let tag = h.finalize();
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(payload);
    out
}

/// Verify + strip the 32-byte tag from a row written by `mac_wrap`.
/// Returns `Err` if the row is too short, the tag doesn't validate,
/// or the row was written with a different MAC key (key rotation /
/// foreign machine). The caller treats `Err` as "tampered or
/// foreign — refuse to use this row".
fn mac_verify(blob: &[u8]) -> Result<&[u8], &'static str> {
    if blob.len() < 32 {
        return Err("mac_verify: row too short");
    }
    use sha2::{Digest, Sha256};
    let (tag, payload) = blob.split_at(32);
    let mut h = Sha256::new();
    h.update(local_mac_key());
    h.update(payload);
    let expected = h.finalize();
    // Constant-time-ish compare via PartialEq on slices — payloads
    // are 32 bytes so this is fine for our threat model.
    if &expected[..] != tag {
        return Err("mac_verify: tag mismatch (row tampered or foreign)");
    }
    Ok(payload)
}

impl PendingRecoveryStore {
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }

    fn key(recovery_id: &str) -> Vec<u8> {
        let mut k = b"erc7579/recovery_pending/".to_vec();
        k.extend_from_slice(recovery_id.as_bytes());
        k
    }

    pub(crate) fn put(&self, rec: &PendingRecovery) -> Result<(), JsonRpcError> {
        let bytes = serde_json::to_vec(rec).map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("serialize pending recovery: {}", e),
            data: None,
        })?;
        // Integrity-tag the row so cross-process / accidental
        // tampering is detected at read time.
        let tagged = mac_wrap(&bytes);
        self.storage
            .put(CF_VALIDATOR_MODULES, &Self::key(&rec.recovery_id), &tagged)
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("persist pending recovery: {}", e),
                data: None,
            })?;
        Ok(())
    }

    pub(crate) fn get(&self, recovery_id: &str) -> Result<Option<PendingRecovery>, JsonRpcError> {
        let bytes = self
            .storage
            .get(CF_VALIDATOR_MODULES, &Self::key(recovery_id))
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("read pending recovery: {}", e),
                data: None,
            })?;
        match bytes {
            Some(b) => {
                let payload = mac_verify(&b).map_err(|e| JsonRpcError {
                    code: -32603,
                    message: format!("tampered pending recovery row: {}", e),
                    data: None,
                })?;
                Ok(Some(serde_json::from_slice(payload).map_err(|e| {
                    JsonRpcError {
                        code: -32603,
                        message: format!("deserialize pending recovery: {}", e),
                        data: None,
                    }
                })?))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn delete(&self, recovery_id: &str) -> Result<(), JsonRpcError> {
        let _ = self
            .storage
            .delete(CF_VALIDATOR_MODULES, &Self::key(recovery_id));
        Ok(())
    }

    pub(crate) fn list_for_account(
        &self,
        account_address: &str,
    ) -> Result<Vec<PendingRecovery>, JsonRpcError> {
        let prefix = b"erc7579/recovery_pending/";
        let entries = self
            .storage
            .get_keys_with_prefix(CF_VALIDATOR_MODULES, prefix)
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("scan pending recoveries: {}", e),
                data: None,
            })?;
        let mut out = Vec::new();
        for key in entries {
            if let Some(rid) = key.strip_prefix(prefix) {
                let rid_str = std::str::from_utf8(rid).unwrap_or("").to_string();
                if let Ok(Some(rec)) = self.get(&rid_str)
                    && rec.account_address.eq_ignore_ascii_case(account_address)
                {
                    out.push(rec);
                }
            }
        }
        Ok(out)
    }
}

// =============================================================================
// TeeEnrollmentKvStore — durable backing for the autonomous-agent TEE oracle
// =============================================================================

/// RocksDB-backed [`tenzro_vm::TeeEnrollmentStore`] for autonomous-machine
/// custody. Persists each account's `TeeBoundAccountKey` under
/// `CF_VALIDATOR_MODULES / erc7579/tee_enrollment/<account_hex>` so the
/// `InMemoryTeeKeyOracle` hydrates on boot. Rows are MAC-tagged with the same
/// per-process key as pending-recovery rows — an operator editing RocksDB to
/// swap an enclave binding is detected at read time and the row is dropped.
pub struct TeeEnrollmentKvStore {
    storage: Arc<dyn KvStore>,
}

impl TeeEnrollmentKvStore {
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }

    fn key(account: &[u8]) -> Vec<u8> {
        let mut k = b"erc7579/tee_enrollment/".to_vec();
        k.extend_from_slice(hex::encode(account).as_bytes());
        k
    }

    const PREFIX: &'static [u8] = b"erc7579/tee_enrollment/";
}

impl tenzro_vm::TeeEnrollmentStore for TeeEnrollmentKvStore {
    fn put(&self, account: &[u8], key: &tenzro_vm::TeeBoundAccountKey) {
        let bytes = match serde_json::to_vec(key) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "TeeEnrollmentKvStore: serialize failed");
                return;
            }
        };
        let tagged = mac_wrap(&bytes);
        if let Err(e) = self
            .storage
            .put(CF_VALIDATOR_MODULES, &Self::key(account), &tagged)
        {
            tracing::error!(error = %e, "TeeEnrollmentKvStore: persist failed");
        }
    }

    fn delete(&self, account: &[u8]) {
        let _ = self
            .storage
            .delete(CF_VALIDATOR_MODULES, &Self::key(account));
    }

    fn load_all(&self) -> Vec<(Vec<u8>, tenzro_vm::TeeBoundAccountKey)> {
        let keys = match self
            .storage
            .get_keys_with_prefix(CF_VALIDATOR_MODULES, Self::PREFIX)
        {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, "TeeEnrollmentKvStore: hydrate scan failed");
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for full_key in keys {
            let Some(account_hex) = full_key.strip_prefix(Self::PREFIX) else {
                continue;
            };
            let Ok(account) = hex::decode(account_hex) else {
                continue;
            };
            let Ok(Some(blob)) = self.storage.get(CF_VALIDATOR_MODULES, &full_key) else {
                continue;
            };
            let payload = match mac_verify(&blob) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(
                        account = %String::from_utf8_lossy(account_hex),
                        error = %e,
                        "TeeEnrollmentKvStore: dropping tampered/foreign enrollment row"
                    );
                    continue;
                }
            };
            match serde_json::from_slice::<tenzro_vm::TeeBoundAccountKey>(payload) {
                Ok(key) => out.push((account, key)),
                Err(e) => tracing::warn!(error = %e, "TeeEnrollmentKvStore: deserialize failed"),
            }
        }
        out
    }
}

// =============================================================================
// Smart-account persistence
// =============================================================================
//
// All smart-account persistence flows through `AccountFactory::with_storage`
// (CF_AGENTS under `smart_account/<addr>` prefix). The factory hydrates
// the in-memory `deployed_accounts` map on boot and writes through on every
// `create_account` / `update_account`. There is no node-local persistence
// helper in this file — call `factory.update_account(...)` after mutating
// a `SmartAccount` and the factory's storage handle does the rest.

// =============================================================================
// Request / response DTOs
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct EnrollPasskeyRequest {
    /// Optional display name (e.g. "Hilal's iPhone"). Stored on the TDIP
    /// identity metadata so the user can identify this account in their
    /// device list.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Raw 64-byte uncompressed P-256 public key (X || Y) or SEC1 65-byte
    /// (0x04 || X || Y) or COSE_Key CBOR. All three forms accepted; the
    /// node normalizes to raw `x || y` for the on-chain validator.
    pub passkey_public_key_hex: String,
    /// Opaque WebAuthn credential ID — echoed back to the client on
    /// subsequent `signWithPasskey` calls so the platform authenticator can
    /// locate the credential.
    pub credential_id_hex: String,
    /// Optional companion ML-DSA-65 post-quantum public key. When provided,
    /// the WebAuthnValidator enforces the hybrid PQ leg on every signature
    /// (Coinbase Smart Wallet pattern + Tenzro PQ extension).
    #[serde(default)]
    pub ml_dsa_public_key_hex: Option<String>,
    /// CREATE2 salt — defaults to 0. Reusing the same passkey + non-zero
    /// salts yields multiple distinct accounts.
    #[serde(default)]
    pub salt: u64,
}

#[derive(Debug, Serialize)]
pub struct EnrollPasskeyResponse {
    pub did: String,
    pub smart_account_address: String,
    pub credential_id_hex: String,
    pub webauthn_validator_address: String,
    pub installed_validators: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SignWithPasskeyRequest {
    /// Smart account address.
    pub account_address: String,
    /// Raw user-op hash (32 bytes hex) that the assertion challenge should
    /// match.
    pub op_hash_hex: String,
    /// WebAuthn assertion delivered from the client.
    pub assertion: WebAuthnAssertion,
    /// Hex-encoded credential id that identifies which enrolled passkey
    /// produced this assertion. Required for multi-device accounts;
    /// must match one of the credentials enrolled on the smart account
    /// via `tenzro_enrollPasskey` or `tenzro_addPasskey`.
    pub credential_id_hex: String,
    /// Optional ML-DSA-65 signature when the account has a hybrid PQ leg.
    #[serde(default)]
    pub ml_dsa_signature_hex: Option<String>,
    /// Second-credential leg — required when the account's second-factor
    /// policy is `two_credentials`. All three `second_*` fields must be
    /// supplied together and must address a different enrolled
    /// credential than the primary leg.
    #[serde(default)]
    pub second_assertion: Option<WebAuthnAssertion>,
    #[serde(default)]
    pub second_credential_id_hex: Option<String>,
    #[serde(default)]
    pub second_ml_dsa_signature_hex: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SignWithPasskeyResponse {
    pub verified: bool,
    pub validator: String,
    pub op_hash_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct AddGuardianRequest {
    pub account_address: String,
    /// Composite (Ed25519 + ML-DSA-65) public key for the guardian. The
    /// guardian is itself an identity holder who signs recovery proofs from
    /// their own passkey or hardware key when called upon.
    pub guardian_ed25519_pubkey_hex: String,
    pub guardian_ml_dsa_pubkey_hex: String,
    /// Optional human-readable label for the guardian ("Mom", "Backup
    /// hardware key", etc.).
    #[serde(default)]
    pub label: Option<String>,
    /// New quorum threshold. If absent and a config already exists, the
    /// previous threshold is preserved.
    #[serde(default)]
    pub threshold: Option<u32>,
    /// Proof the caller already controls this account: a
    /// node-issued challenge signed by an already-enrolled passkey.
    /// Without it the call is refused — the account address is a
    /// public identifier, not a credential.
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Serialize)]
pub struct AddGuardianResponse {
    pub account_address: String,
    pub guardian_count: u32,
    pub threshold: u32,
}

#[derive(Debug, Deserialize)]
pub struct InitiateRecoveryRequest {
    pub account_address: String,
    /// The new WebAuthn account-key the user just enrolled on a new device.
    pub new_passkey_public_key_hex: String,
    pub new_credential_id_hex: String,
    #[serde(default)]
    pub new_ml_dsa_public_key_hex: Option<String>,
    /// How many seconds the guardian-signature collection window stays open.
    /// Defaults to 24 hours (86400). Hard ceiling is 7 days.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct InitiateRecoveryResponse {
    pub recovery_id: String,
    pub account_address: String,
    /// The 32-byte op hash the guardians must sign with their composite keys.
    pub recovery_op_hash_hex: String,
    pub expires_at_ms: u64,
    pub guardians_required: u32,
    pub guardians_total: u32,
}

#[derive(Debug, Deserialize)]
pub struct SubmitRecoverySignatureRequest {
    pub recovery_id: String,
    pub guardian_index: u32,
    /// Composite signature: 64-byte Ed25519 || 3309-byte ML-DSA-65, hex.
    pub composite_signature_hex: String,
}

#[derive(Debug, Serialize)]
pub struct SubmitRecoverySignatureResponse {
    pub recovery_id: String,
    pub guardian_signatures_collected: u32,
    pub guardians_required: u32,
    pub quorum_reached: bool,
}

#[derive(Debug, Deserialize)]
pub struct FinalizeRecoveryRequest {
    pub recovery_id: String,
}

#[derive(Debug, Serialize)]
pub struct FinalizeRecoveryResponse {
    pub recovery_id: String,
    pub account_address: String,
    pub new_credential_id_hex: String,
    pub installed_validators: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct GrantSessionKeyRequest {
    pub account_address: String,
    /// 32-byte Ed25519 verifying key of the session key (hex).
    pub session_pubkey_hex: String,
    /// 4-byte function selectors this session key may call (hex, no `0x`).
    pub allowed_selectors_hex: Vec<String>,
    /// 20-byte target contract addresses this session key may interact with.
    /// Empty = any target.
    #[serde(default)]
    pub allowed_targets: Vec<String>,
    /// Per-tx value ceiling in wei (decimal string). Empty / "0" = no value
    /// transfer allowed; null = unlimited.
    #[serde(default)]
    pub max_value_per_call_wei: Option<String>,
    /// Cumulative value ceiling in wei over the session lifetime.
    /// null = unlimited.
    #[serde(default)]
    pub max_total_value_wei: Option<String>,
    pub valid_after_unix: u64,
    pub valid_until_unix: u64,
    /// Optional label for audit ("Agent payment pipeline", etc.).
    #[serde(default)]
    pub label: Option<String>,
    /// Proof the caller already controls this account: a
    /// node-issued challenge signed by an already-enrolled passkey.
    /// Without it the call is refused — the account address is a
    /// public identifier, not a credential.
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Serialize)]
pub struct GrantSessionKeyResponse {
    pub account_address: String,
    pub session_pubkey_hex: String,
    pub valid_after_unix: u64,
    pub valid_until_unix: u64,
}

#[derive(Debug, Deserialize)]
pub struct RevokeSessionKeyRequest {
    pub account_address: String,
    /// Proof the caller already controls this account: a
    /// node-issued challenge signed by an already-enrolled passkey.
    /// Without it the call is refused — the account address is a
    /// public identifier, not a credential.
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Serialize)]
pub struct RevokeSessionKeyResponse {
    pub account_address: String,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
pub struct AddHardwareSignerRequest {
    pub account_address: String,
    /// One of "ledger", "trezor", "gridplus", "yubikey", or "generic".
    pub device_kind: String,
    /// 33-byte SEC1 compressed or 65-byte SEC1 uncompressed secp256k1 pubkey
    /// for ECDSA hardware (Ledger / Trezor) OR 64-byte raw P-256 pubkey for
    /// FIDO2 hardware (YubiKey).
    pub public_key_hex: String,
    /// Whether this hardware signer is required on every signing operation
    /// (true) or only on high-value operations (false, gated by the
    /// SpendingLimit threshold below).
    #[serde(default)]
    pub required_always: bool,
    /// Value-in-wei threshold above which this hardware signer is mandatory.
    /// Ignored when `required_always` is true.
    #[serde(default)]
    pub required_above_wei: Option<String>,
    /// Optional label.
    #[serde(default)]
    pub label: Option<String>,
    /// Proof the caller already controls this account: a
    /// node-issued challenge signed by an already-enrolled passkey.
    /// Without it the call is refused — the account address is a
    /// public identifier, not a credential.
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Serialize)]
pub struct AddHardwareSignerResponse {
    pub account_address: String,
    pub device_kind: String,
    pub validator_module_address: String,
}

#[derive(Debug, Deserialize)]
pub struct SetSpendingLimitRequest {
    pub account_address: String,
    pub per_tx_cap_wei: String,
    pub daily_cap_wei: String,
    /// 32-byte Ed25519 public key of the authenticator that signs limit
    /// changes. Typically the smart account's primary passkey or a guardian
    /// composite-key digest.
    pub authenticator_pubkey_hex: String,
    /// Proof the caller already controls this account: a
    /// node-issued challenge signed by an already-enrolled passkey.
    /// Without it the call is refused — the account address is a
    /// public identifier, not a credential.
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Serialize)]
pub struct SetSpendingLimitResponse {
    pub account_address: String,
    pub per_tx_cap_wei: String,
    pub daily_cap_wei: String,
}

#[derive(Debug, Deserialize)]
pub struct GetSmartAccountRequest {
    pub account_address: String,
}

#[derive(Debug, Serialize)]
pub struct SmartAccountSummary {
    pub address: String,
    pub owner_hex: String,
    pub nonce: u64,
    pub is_deployed: bool,
    pub installed_validators: Vec<InstalledValidatorSummary>,
}

#[derive(Debug, Serialize)]
pub struct InstalledValidatorSummary {
    pub module_address: String,
    pub type_id: u64,
    pub priority: u32,
}

// =============================================================================
// Helpers
// =============================================================================

fn parse_params<T: for<'de> Deserialize<'de>>(params: Option<Value>) -> Result<T, JsonRpcError> {
    let p = params.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Missing params".to_string(),
        data: None,
    })?;
    serde_json::from_value(p).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("Invalid params: {}", e),
        data: None,
    })
}

fn decode_hex(s: &str) -> Result<Vec<u8>, JsonRpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("Invalid hex: {}", e),
        data: None,
    })
}

fn decode_address_20(s: &str) -> Result<[u8; 20], JsonRpcError> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 20 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("Expected 20-byte address, got {}", bytes.len()),
            data: None,
        });
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn normalize_p256_pubkey_to_raw_xy(bytes: &[u8]) -> Result<[u8; 64], JsonRpcError> {
    let xy = if bytes.len() == 64 {
        let mut a = [0u8; 64];
        a.copy_from_slice(bytes);
        a
    } else if bytes.len() == 65 && bytes[0] == 0x04 {
        let mut a = [0u8; 64];
        a.copy_from_slice(&bytes[1..]);
        a
    } else {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "Unsupported P-256 public key form: expected raw 64 or SEC1 65-byte, got {}",
                bytes.len()
            ),
            data: None,
        });
    };
    Ok(xy)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// =============================================================================
// Handler: tenzro_enrollPasskey
// =============================================================================

/// Enroll a passkey-bound smart account. Creates a TDIP human identity,
/// deploys a smart account via the shared `AccountFactory`, installs the
/// `WebAuthnValidator` as the primary validator, and persists everything.
pub(crate) async fn handle_enroll_passkey(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: EnrollPasskeyRequest = parse_params(params)?;

    let factory = node.account_factory().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "AccountFactory not initialized on this node".to_string(),
        data: None,
    })?;
    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized on this node".to_string(),
        data: None,
    })?;
    let identity_registry = node.identity_registry().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "IdentityRegistry not initialized".to_string(),
        data: None,
    })?;

    // 1. Normalize passkey public key.
    let passkey_pubkey_bytes = decode_hex(&req.passkey_public_key_hex)?;
    let p256_xy = normalize_p256_pubkey_to_raw_xy(&passkey_pubkey_bytes)?;
    let mut pubkey_x = [0u8; 32];
    let mut pubkey_y = [0u8; 32];
    pubkey_x.copy_from_slice(&p256_xy[..32]);
    pubkey_y.copy_from_slice(&p256_xy[32..]);

    // 2. ML-DSA-65 verifying key is REQUIRED for hybrid PQ custody (Tenzro
    //    PQ migration per genesis v3 — pre-quantum classical-only enrollments
    //    are refused at this layer to keep the audit trail clean).
    let ml_dsa_vk_bytes = req
        .ml_dsa_public_key_hex
        .as_deref()
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "ml_dsa_public_key_hex is required for hybrid PQ custody".to_string(),
            data: None,
        })?;
    let ml_dsa_vk = decode_hex(ml_dsa_vk_bytes)?;
    if ml_dsa_vk.len() != ML_DSA_65_VK_LEN {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "ml_dsa_public_key must be {} bytes (ML-DSA-65 vk), got {}",
                ML_DSA_65_VK_LEN,
                ml_dsa_vk.len()
            ),
            data: None,
        });
    }
    let account_key =
        WebAuthnAccountKey::new(pubkey_x, pubkey_y, ml_dsa_vk).map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("WebAuthnAccountKey: {}", e),
            data: None,
        })?;
    let credential_id = decode_hex(&req.credential_id_hex)?;

    // 3. Generate the human DID up front. The smart-account owner seed binds
    //    to it (step 4), and it is the DID the passkey-custody identity carries.
    let display_name = req
        .display_name
        .unwrap_or_else(|| "Passkey User".to_string());
    let did = tenzro_identity::TenzroDid::new_human();
    let did_string = did.to_string();

    // 4. Deploy the smart account via CREATE2. Owner bytes = SHA-256 of
    //    (passkey || credential || did) so the account address is
    //    deterministically bound to all three.
    let mut owner_seed = Vec::with_capacity(p256_xy.len() + credential_id.len() + did_string.len());
    owner_seed.extend_from_slice(&p256_xy);
    owner_seed.extend_from_slice(&credential_id);
    owner_seed.extend_from_slice(did_string.as_bytes());
    let owner_hash = tenzro_crypto::sha256(&owner_seed);
    let owner = owner_hash.as_bytes().to_vec();
    let mut smart_account = factory.create_account(owner.clone(), req.salt);

    // 5. Install the WebAuthnValidator as the primary validator (priority 0).
    let init_data = serde_json::to_vec(&account_key).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize WebAuthnAccountKey: {}", e),
        data: None,
    })?;
    let webauthn_module_addr = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x20;
        a
    };
    let module_config = tenzro_vm::erc7579::ValidatorModuleConfig {
        type_id: tenzro_vm::aa_validators::ModuleType::Validator as u64,
        module_address: webauthn_module_addr,
        init_data: init_data.clone(),
        priority: 0,
    };
    smart_account
        .install_validator_module(module_config, /* owner_authorized = */ true)
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("install WebAuthnValidator on smart account: {}", e),
            data: None,
        })?;

    // 6. Register the per-account WebAuthn key with the validator instance
    //    (this is the in-memory lookup the validator uses at op-verify time).
    //    Multi-credential per account is supported — each enrollment is
    //    addressed by its `credential.id` so additional devices can be
    //    enrolled on the same smart account via a follow-up call.
    webauthn_validator
        .enroll(
            smart_account.address.clone(),
            credential_id.clone(),
            account_key.clone(),
        )
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("WebAuthn enroll: {}", e),
            data: None,
        })?;

    // 7. Persist via the factory. `create_account` populated
    //    `deployed_accounts` with the bare account; the post-install
    //    state (with WebAuthnValidator added to `validator_modules`)
    //    lives on the local `smart_account` until we call
    //    `update_account`. That call does both: replaces the map entry
    //    AND writes through to `CF_AGENTS / smart_account/<addr>` so
    //    the rotated state survives node restart.
    factory.update_account(smart_account.clone());

    // 7b. Register the human TDIP identity from a device-held WalletBinding.
    //     The passkey IS the custody: the identity's classical key is the
    //     WebAuthn P-256 pubkey, its PQ key is the enrolled ML-DSA-65 vk, and
    //     its custody vessel is the smart account gated by the WebAuthnValidator
    //     — no server-side wallet is provisioned (no FROST-share reconstruction
    //     path exists for this identity). BLS is empty: a passkey human is not a
    //     validator and carries no HotStuff-2 vote-aggregation key.
    let mut wallet_addr_bytes = [0u8; 32];
    let sa_addr = smart_account.address.as_slice();
    let sa_len = sa_addr.len().min(32);
    wallet_addr_bytes[..sa_len].copy_from_slice(&sa_addr[..sa_len]);
    let binding = tenzro_identity::WalletBinding {
        wallet_id: format!("0x{}", hex::encode(&smart_account.address)),
        address: tenzro_types::primitives::Address::new(wallet_addr_bytes),
        public_key: p256_xy.to_vec(),
        key_type: "P-256".to_string(),
        pq_verifying_key: account_key.pq_pubkey.clone(),
        bls_verifying_key: Vec::new(),
    };
    identity_registry
        .register_human_with_binding(
            did,
            display_name,
            tenzro_types::identity::KycTier::Unverified,
            binding,
        )
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("identity registration: {}", e),
            data: None,
        })?;

    // 8. Bind the smart-account address to the TDIP identity metadata for
    //    cross-reference.
    // Bind the smart-account address + credential ID into the identity
    // metadata so subsequent resolves carry the binding. Uses the
    // registry's `set_identity_metadata` so both the in-memory cache
    // and CF_IDENTITIES get the write through one call. If the
    // registry write fails (race on revocation, etc.) we surface a
    // warning but do not unwind — the smart account and TDIP identity
    // are already created and don't need to be re-rolled.
    let metadata_kv = [
        (
            "smart_account_address".to_string(),
            format!("0x{}", hex::encode(&smart_account.address)),
        ),
        (
            "passkey_credential_id".to_string(),
            format!("0x{}", hex::encode(&credential_id)),
        ),
    ];
    if let Err(e) = identity_registry.set_identity_metadata(&did_string, metadata_kv) {
        tracing::warn!(
            did = %did_string,
            error = %e,
            "passkey enroll: identity metadata write skipped (identity unknown)"
        );
    }

    // Genesis record. Version 0's trust comes from being created here, at
    // enrollment, when the credential just installed is by definition the
    // account's only authority — there is no prior signer to sign with, and
    // every later version chains back to this one.
    let account_hex = format!("0x{}", hex::encode(&smart_account.address));
    crate::account_record::republish(node, &account_hex, &did_string, None);

    let resp = EnrollPasskeyResponse {
        did: did_string,
        smart_account_address: account_hex,
        credential_id_hex: format!("0x{}", hex::encode(&credential_id)),
        webauthn_validator_address: format!("0x{}", hex::encode(webauthn_module_addr)),
        installed_validators: vec!["webauthn".to_string()],
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_signWithPasskey
// =============================================================================

/// Verify a WebAuthn assertion against the registered passkey on the target
/// smart account. Returns success iff:
///  - the assertion validates against the registered P-256 pubkey,
///  - the embedded challenge matches the user-op hash,
///  - the ML-DSA leg (when present) validates against the registered hash.
pub(crate) async fn handle_sign_with_passkey(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: SignWithPasskeyRequest = parse_params(params)?;
    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized".to_string(),
        data: None,
    })?;
    let account_addr_bytes = decode_hex(&req.account_address)?;
    let op_hash = decode_hex(&req.op_hash_hex)?;
    if op_hash.len() != 32 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("op_hash must be 32 bytes, got {}", op_hash.len()),
            data: None,
        });
    }
    let mut op_hash_arr = [0u8; 32];
    op_hash_arr.copy_from_slice(&op_hash);
    let pq_sig = req
        .ml_dsa_signature_hex
        .as_deref()
        .map(decode_hex)
        .transpose()?
        .unwrap_or_default();
    let credential_id = decode_hex(&req.credential_id_hex)?;
    let mut legs = vec![HybridWebAuthnSignature {
        assertion: req.assertion,
        ml_dsa_signature: pq_sig,
        credential_id,
    }];
    // Second-credential leg: all three fields travel together.
    match (
        req.second_assertion,
        req.second_credential_id_hex.as_deref(),
        req.second_ml_dsa_signature_hex.as_deref(),
    ) {
        (Some(assertion), Some(cred_hex), Some(pq_hex)) => {
            legs.push(HybridWebAuthnSignature {
                assertion,
                ml_dsa_signature: decode_hex(pq_hex)?,
                credential_id: decode_hex(cred_hex)?,
            });
        }
        (None, None, None) => {}
        _ => {
            return Err(JsonRpcError {
                code: -32602,
                message: "second_assertion, second_credential_id_hex and \
                          second_ml_dsa_signature_hex must be supplied together"
                    .to_string(),
                data: None,
            });
        }
    }
    let sig_bytes = HybridWebAuthnSignature::encode_bundle(&legs).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("encode hybrid sig: {}", e),
        data: None,
    })?;
    // Build a minimal UserOperation carrying only what the validator reads
    // (sender + signature). The actual call_data path is irrelevant for the
    // verify-only RPC — the validator only inspects op.sender and op.signature
    // when computing the WebAuthn challenge from the supplied op_hash.
    let op = tenzro_vm::UserOperation {
        sender: account_addr_bytes.clone(),
        // Verify-only RPC — nonce is irrelevant to the WebAuthn
        // challenge computation. Use the default-key zero seq.
        nonce: tenzro_vm::account_abstraction::Nonce::from_seq(0).to_bytes(),
        factory: Vec::new(),
        factory_data: Vec::new(),
        call_data: Vec::new(),
        call_gas_limit: 0,
        verification_gas_limit: 0,
        pre_verification_gas: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        paymaster: Vec::new(),
        paymaster_verification_gas_limit: 0,
        paymaster_post_op_gas_limit: 0,
        paymaster_data: Vec::new(),
        signature: sig_bytes,
    };
    use tenzro_vm::aa_validators::IValidator as _;
    let validation = webauthn_validator
        .validate_user_op(&op, &op_hash_arr)
        .map_err(|e| JsonRpcError {
            code: -32003,
            message: format!("passkey verification failed: {}", e),
            data: None,
        })?;
    let verified = !validation.is_failure();

    let webauthn_module_addr = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x20;
        a
    };
    let resp = SignWithPasskeyResponse {
        verified,
        validator: format!("0x{}", hex::encode(webauthn_module_addr)),
        op_hash_hex: req.op_hash_hex,
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Custody authorization — proving control of an account before mutating it
// =============================================================================
//
// Every handler below this point changes *who can spend from a wallet*: which
// passkeys sign for it, which session keys act on its behalf, what its spending
// ceilings are, who its recovery guardians are. Before this gate existed, six
// of those eight handlers took only the account address and did as they were
// told.
//
// The account address is a public identifier. It is returned by
// `tenzro_enrollPasskey`, listed by `tenzro_listSmartAccounts`, and visible
// on-chain. So "knows the address" is not a credential, and treating it as one
// meant an unauthenticated caller could add their own passkey to a stranger's
// wallet and then remove the owner's — taking sole control of it. Both halves
// were reachable over the open RPC port with no key, no token, and no
// signature.
//
// The fix is a single gate every custody mutation runs through, rather than a
// check per handler. Eight independent checks are eight chances to write one
// differently, and the one written differently is the one that gets found.
//
// # What counts as proof
//
// A WebAuthn assertion from a credential **already enrolled on that account**,
// over a challenge the *node* issued, which binds:
//
//   domain-separator ‖ account ‖ operation ‖ operation-specific target ‖ nonce
//
// Binding the operation and its target is what stops an assertion collected for
// "add my new phone" being replayed as "remove the owner's laptop". Issuing the
// challenge server-side and consuming it single-use is what stops a captured
// assertion being replayed at all.
//
// Verification reuses `WebAuthnValidator::validate_user_op` — the same path
// `tenzro_signWithPasskey` runs, including the post-quantum ML-DSA leg. A
// second verification routine written specially for custody would be a second
// thing to get wrong.

/// How long an issued custody challenge stays valid.
///
/// Long enough to walk to a phone and complete a ceremony; short enough that a
/// challenge left in a terminal's scrollback is not a standing authorization.
pub const CUSTODY_CHALLENGE_TTL_SECS: u64 = 300;

/// Domain separator for the custody challenge preimage.
///
/// Keeps a custody challenge from ever colliding with a UserOperation hash or
/// any other 32-byte digest this node asks a passkey to sign. Two subsystems
/// agreeing by accident on what a signature authorizes is how a signature for
/// one thing becomes a signature for another.
const CUSTODY_DOMAIN: &[u8] = b"tenzro/custody-challenge/v1";

/// The custody operations that require proof of account control.
///
/// An enum rather than a free string: the operation is bound into the signed
/// challenge, so a typo would not be a rejected call but a *differently scoped*
/// authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyOperation {
    /// Enroll an additional passkey on an existing account.
    AddPasskey,
    /// Revoke an enrolled passkey.
    RemovePasskey,
    /// Change the second-factor policy.
    SetPasskeyPolicy,
    /// Install a scoped session key.
    GrantSessionKey,
    /// Revoke a session key.
    RevokeSessionKey,
    /// Change a spending ceiling.
    SetSpendingLimit,
    /// Install an additional hardware signer.
    AddHardwareSigner,
    /// Register a recovery guardian.
    AddGuardian,
}

impl CustodyOperation {
    /// Stable byte tag bound into the challenge preimage.
    fn tag(self) -> &'static [u8] {
        match self {
            Self::AddPasskey => b"add_passkey",
            Self::RemovePasskey => b"remove_passkey",
            Self::SetPasskeyPolicy => b"set_passkey_policy",
            Self::GrantSessionKey => b"grant_session_key",
            Self::RevokeSessionKey => b"revoke_session_key",
            Self::SetSpendingLimit => b"set_spending_limit",
            Self::AddHardwareSigner => b"add_hardware_signer",
            Self::AddGuardian => b"add_guardian",
        }
    }
}

/// The digest a passkey must sign to authorize one custody mutation.
///
/// `target` is the operation's own subject — the credential being added, the
/// session key being granted — so an assertion is scoped to exactly the change
/// it was collected for.
pub fn custody_challenge_digest(
    account: &[u8],
    operation: CustodyOperation,
    target: &[u8],
    nonce: &[u8; 16],
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(CUSTODY_DOMAIN);
    // Length-prefixed, so ("ab","c") and ("a","bc") cannot hash alike — an
    // ambiguity here would let one operation's challenge satisfy another's.
    h.update((account.len() as u32).to_be_bytes());
    h.update(account);
    let tag = operation.tag();
    h.update((tag.len() as u32).to_be_bytes());
    h.update(tag);
    h.update((target.len() as u32).to_be_bytes());
    h.update(target);
    h.update(nonce);
    h.finalize().into()
}

/// An issued, not-yet-consumed custody challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IssuedChallenge {
    account: Vec<u8>,
    operation: CustodyOperation,
    target: Vec<u8>,
    nonce: [u8; 16],
    issued_at_secs: u64,
}

/// Single-use, TTL-bounded custody challenges.
///
/// In memory rather than persisted, deliberately: a challenge outliving a node
/// restart buys nothing — the client simply asks for another — while a
/// persisted one is a replay window that survives the process that issued it.
#[derive(Debug, Default)]
pub struct CustodyChallengeStore {
    issued: parking_lot::Mutex<std::collections::HashMap<String, IssuedChallenge>>,
}

impl CustodyChallengeStore {
    /// A store with nothing issued.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a challenge for one specific mutation.
    ///
    /// Returns `(challenge_id, digest)`. The client signs `digest` with an
    /// enrolled passkey and presents both back.
    pub fn issue(
        &self,
        account: &[u8],
        operation: CustodyOperation,
        target: &[u8],
    ) -> (String, [u8; 32]) {
        let mut nonce = [0u8; 16];
        getrandom_0_4::fill(&mut nonce).ok();
        let digest = custody_challenge_digest(account, operation, target, &nonce);
        let id = hex::encode(digest);
        let mut issued = self.issued.lock();
        Self::sweep_expired(&mut issued);
        issued.insert(
            id.clone(),
            IssuedChallenge {
                account: account.to_vec(),
                operation,
                target: target.to_vec(),
                nonce,
                issued_at_secs: now_secs(),
            },
        );
        (id, digest)
    }

    /// Consume a challenge, checking it authorizes exactly this mutation.
    ///
    /// Removal happens on every outcome, success or failure: a challenge that
    /// was presented against the wrong target has been observed by whoever
    /// presented it, and letting them retry with a corrected target would make
    /// the binding advisory.
    pub fn consume(
        &self,
        challenge_id: &str,
        account: &[u8],
        operation: CustodyOperation,
        target: &[u8],
    ) -> Result<[u8; 32], String> {
        let mut issued = self.issued.lock();
        Self::sweep_expired(&mut issued);
        let entry = issued
            .remove(challenge_id)
            .ok_or_else(|| "custody challenge is unknown, expired, or already used".to_string())?;
        if entry.account != account {
            return Err("custody challenge was issued for a different account".to_string());
        }
        if entry.operation != operation {
            return Err(format!(
                "custody challenge authorizes {:?}, not {:?}",
                entry.operation, operation
            ));
        }
        if entry.target != target {
            return Err(
                "custody challenge was issued for a different target; a challenge authorizes one \
                 specific change"
                    .to_string(),
            );
        }
        Ok(custody_challenge_digest(
            account,
            operation,
            target,
            &entry.nonce,
        ))
    }

    /// How many challenges are outstanding. For tests and operator diagnostics.
    pub fn outstanding(&self) -> usize {
        let mut issued = self.issued.lock();
        Self::sweep_expired(&mut issued);
        issued.len()
    }

    fn sweep_expired(issued: &mut std::collections::HashMap<String, IssuedChallenge>) {
        let now = now_secs();
        issued.retain(|_, c| now.saturating_sub(c.issued_at_secs) < CUSTODY_CHALLENGE_TTL_SECS);
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The proof a caller presents to mutate an account's custody.
#[derive(Debug, Deserialize)]
pub struct CustodyAuthorization {
    /// The challenge id returned by `tenzro_createCustodyChallenge`.
    pub challenge_id: String,
    /// Credential id of a passkey **already enrolled on this account**.
    pub credential_id_hex: String,
    /// WebAuthn assertion from that credential over the challenge digest.
    pub assertion: WebAuthnAssertion,
    /// ML-DSA-65 signature over the same digest — the post-quantum leg.
    #[serde(default)]
    pub ml_dsa_signature_hex: Option<String>,
}

/// Refuse unless the caller proves they already control `account`.
///
/// The single gate every custody mutation runs through. Returns `Ok(())` only
/// when an already-enrolled credential has signed a node-issued challenge bound
/// to this exact operation and target.
pub(crate) async fn require_account_control(
    node: &Arc<TenzroNode>,
    account: &[u8],
    operation: CustodyOperation,
    target: &[u8],
    auth: Option<CustodyAuthorization>,
) -> Result<String, JsonRpcError> {
    let auth = auth.ok_or_else(|| JsonRpcError {
        code: -32001,
        message: format!(
            "changing an account's custody requires proof you already control it: call \
             tenzro_createCustodyChallenge for {:?}, sign the returned digest with a passkey \
             already enrolled on this account, and present it as `authorization`",
            operation
        ),
        data: None,
    })?;

    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized on this node".to_string(),
        data: None,
    })?;

    // The authorizing credential must already be enrolled here. Without this,
    // a caller could sign the challenge with any key of their own choosing.
    let credential_id = decode_hex(&auth.credential_id_hex)?;
    // Kept before `credential_id` is moved into the signature bundle below.
    let authorizing_credential_hex = hex::encode(&credential_id);
    if webauthn_validator
        .get_credential(account, &credential_id)
        .is_none()
    {
        return Err(JsonRpcError {
            code: -32001,
            message: format!(
                "credential 0x{} is not enrolled on account 0x{}, so it cannot authorize a \
                 change to that account",
                hex::encode(&credential_id),
                hex::encode(account)
            ),
            data: None,
        });
    }

    // Consume the challenge, which checks it was issued for this account, this
    // operation, and this target — then yields the digest that must have been
    // signed.
    let digest = node
        .custody_challenges()
        .consume(&auth.challenge_id, account, operation, target)
        .map_err(|message| JsonRpcError {
            code: -32001,
            message,
            data: None,
        })?;

    // Verify through the same path `tenzro_signWithPasskey` uses, so the
    // custody gate and the signing gate cannot disagree about what a valid
    // assertion is.
    let legs = vec![HybridWebAuthnSignature {
        assertion: auth.assertion,
        ml_dsa_signature: auth
            .ml_dsa_signature_hex
            .as_deref()
            .map(decode_hex)
            .transpose()?
            .unwrap_or_default(),
        credential_id,
    }];
    let sig_bytes = HybridWebAuthnSignature::encode_bundle(&legs).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("encode hybrid sig: {}", e),
        data: None,
    })?;
    let op = minimal_user_op(account.to_vec(), sig_bytes);

    use tenzro_vm::aa_validators::IValidator as _;
    let validation = webauthn_validator
        .validate_user_op(&op, &digest)
        .map_err(|e| JsonRpcError {
            code: -32001,
            message: format!("custody authorization failed: {}", e),
            data: None,
        })?;
    if validation.is_failure() {
        return Err(JsonRpcError {
            code: -32001,
            message: "custody authorization failed: the assertion did not verify against an \
                      enrolled credential"
                .to_string(),
            data: None,
        });
    }
    // Hand back who authorized. The published account record chains each
    // version to the credential that permitted it, so "someone was allowed"
    // is not enough — the caller needs the identity.
    Ok(authorizing_credential_hex)
}

/// A UserOperation carrying only what the WebAuthn validator reads.
///
/// The validator inspects `sender` and `signature` and computes the challenge
/// from the supplied hash; nothing else on the operation participates.
fn minimal_user_op(sender: Vec<u8>, signature: Vec<u8>) -> tenzro_vm::UserOperation {
    tenzro_vm::UserOperation {
        sender,
        nonce: tenzro_vm::account_abstraction::Nonce::from_seq(0).to_bytes(),
        factory: Vec::new(),
        factory_data: Vec::new(),
        call_data: Vec::new(),
        call_gas_limit: 0,
        verification_gas_limit: 0,
        pre_verification_gas: 0,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        paymaster: Vec::new(),
        paymaster_verification_gas_limit: 0,
        paymaster_post_op_gas_limit: 0,
        paymaster_data: Vec::new(),
        signature,
    }
}

/// `tenzro_createCustodyChallenge` — issue the digest a passkey must sign to
/// authorize one custody mutation.
///
/// Params: `account_address`, `operation`, `target_hex`. Open by design: a
/// challenge is worthless without an enrolled credential to sign it, and
/// gating issuance would only mean a legitimate owner cannot start.
#[derive(Debug, Deserialize)]
pub struct CreateCustodyChallengeRequest {
    pub account_address: String,
    pub operation: CustodyOperation,
    /// The operation's subject, hex-encoded — the credential being added, the
    /// session key being granted. Empty for operations with no distinct target.
    #[serde(default)]
    pub target_hex: Option<String>,
}

pub(crate) async fn handle_create_custody_challenge(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: CreateCustodyChallengeRequest = parse_params(params)?;
    let account = decode_hex(&req.account_address)?;
    let target = match req.target_hex.as_deref() {
        Some(t) if !t.is_empty() => decode_hex(t)?,
        _ => Vec::new(),
    };
    let (challenge_id, digest) = node
        .custody_challenges()
        .issue(&account, req.operation, &target);
    Ok(serde_json::json!({
        "challenge_id": challenge_id,
        "challenge_hex": format!("0x{}", hex::encode(digest)),
        "account_address": format!("0x{}", hex::encode(&account)),
        "operation": req.operation,
        "expires_in_secs": CUSTODY_CHALLENGE_TTL_SECS,
    }))
}

// =============================================================================
// Handler: tenzro_addGuardian
// =============================================================================

pub(crate) async fn handle_add_guardian(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: AddGuardianRequest = parse_params(params)?;
    let validator = node
        .social_recovery_validator()
        .ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "SocialRecoveryValidator not initialized".to_string(),
            data: None,
        })?;
    let account_addr = decode_hex(&req.account_address)?;

    // Custody gate. The account address is a public identifier, so
    // "knows the address" is not a credential — this refuses unless an
    // already-enrolled passkey has signed a node-issued challenge bound
    // to exactly this operation and target.
    let _authorizing_credential = require_account_control(
        node,
        &account_addr,
        CustodyOperation::AddGuardian,
        &[],
        req.authorization,
    )
    .await?;
    let ed_pk_bytes = decode_hex(&req.guardian_ed25519_pubkey_hex)?;
    let pq_pk_bytes = decode_hex(&req.guardian_ml_dsa_pubkey_hex)?;
    if ed_pk_bytes.len() != 32 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("Ed25519 pubkey must be 32 bytes, got {}", ed_pk_bytes.len()),
            data: None,
        });
    }
    if pq_pk_bytes.len() != ML_DSA_65_VK_LEN {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "guardian_ml_dsa_pubkey must be {} bytes (ML-DSA-65 vk), got {}",
                ML_DSA_65_VK_LEN,
                pq_pk_bytes.len()
            ),
            data: None,
        });
    }
    let classical = tenzro_crypto::PublicKey::new(tenzro_crypto::KeyType::Ed25519, ed_pk_bytes);
    let composite = CompositePublicKey::new(classical, pq_pk_bytes);
    // Merge into existing config if present.
    let mut guardians = validator
        .config_for(&account_addr)
        .map(|c| c.guardians.clone())
        .unwrap_or_default();
    guardians.push(composite);
    let prev_threshold = validator
        .config_for(&account_addr)
        .map(|c| c.threshold)
        .unwrap_or(1);
    let threshold = req
        .threshold
        .unwrap_or_else(|| prev_threshold.max(1).min(guardians.len() as u32));
    let cfg =
        SocialRecoveryConfig::new(guardians.clone(), threshold).map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("invalid recovery config: {}", e),
            data: None,
        })?;
    validator
        .install_for(account_addr.clone(), cfg.clone())
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("install social recovery: {}", e),
            data: None,
        })?;
    let resp = AddGuardianResponse {
        account_address: req.account_address,
        guardian_count: cfg.guardians.len() as u32,
        threshold: cfg.threshold,
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_initiateRecovery
// =============================================================================

pub(crate) async fn handle_initiate_recovery(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: InitiateRecoveryRequest = parse_params(params)?;
    let store = node.recovery_pending().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "Recovery store not initialized (node lacks storage backend)".to_string(),
        data: None,
    })?;
    let validator = node
        .social_recovery_validator()
        .ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "SocialRecoveryValidator not initialized".to_string(),
            data: None,
        })?;
    let account_addr_bytes = decode_hex(&req.account_address)?;
    let cfg = validator
        .config_for(&account_addr_bytes)
        .ok_or_else(|| JsonRpcError {
            code: -32404,
            message: "no guardians registered for this account; call tenzro_addGuardian first"
                .to_string(),
            data: None,
        })?;
    let new_passkey_bytes = decode_hex(&req.new_passkey_public_key_hex)?;
    let p256_xy = normalize_p256_pubkey_to_raw_xy(&new_passkey_bytes)?;
    let mut pubkey_x = [0u8; 32];
    let mut pubkey_y = [0u8; 32];
    pubkey_x.copy_from_slice(&p256_xy[..32]);
    pubkey_y.copy_from_slice(&p256_xy[32..]);
    let credential_id = decode_hex(&req.new_credential_id_hex)?;
    let ml_dsa_bytes = req
        .new_ml_dsa_public_key_hex
        .as_deref()
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "new_ml_dsa_public_key_hex required (hybrid PQ custody)".to_string(),
            data: None,
        })?;
    let ml_dsa_vk = decode_hex(ml_dsa_bytes)?;
    if ml_dsa_vk.len() != ML_DSA_65_VK_LEN {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "ml_dsa vk must be {} bytes, got {}",
                ML_DSA_65_VK_LEN,
                ml_dsa_vk.len()
            ),
            data: None,
        });
    }
    let new_key =
        WebAuthnAccountKey::new(pubkey_x, pubkey_y, ml_dsa_vk).map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("WebAuthnAccountKey: {}", e),
            data: None,
        })?;
    let ttl_secs = req.ttl_secs.unwrap_or(86_400).min(86_400 * 7);
    let now = now_ms();
    let mut id_seed = Vec::new();
    id_seed.extend_from_slice(&account_addr_bytes);
    id_seed.extend_from_slice(&p256_xy);
    id_seed.extend_from_slice(&now.to_le_bytes());
    let recovery_id = hex::encode(tenzro_crypto::sha256(&id_seed).as_bytes());
    let recovery_op_hash = tenzro_crypto::sha256(&{
        let mut buf = Vec::new();
        buf.extend_from_slice(b"tenzro/recovery/v1");
        buf.extend_from_slice(&account_addr_bytes);
        buf.extend_from_slice(&p256_xy);
        buf.extend_from_slice(&new_key.pq_pubkey_hash());
        buf.extend_from_slice(&credential_id);
        buf
    });
    let rec = PendingRecovery {
        recovery_id: recovery_id.clone(),
        account_address: req.account_address.clone(),
        new_passkey: new_key,
        new_credential_id: credential_id,
        guardian_signatures: Vec::new(),
        created_at_ms: now,
        expires_at_ms: now + ttl_secs * 1000,
        finalized: false,
    };
    store.put(&rec)?;
    let resp = InitiateRecoveryResponse {
        recovery_id,
        account_address: req.account_address,
        recovery_op_hash_hex: format!("0x{}", hex::encode(recovery_op_hash.as_bytes())),
        expires_at_ms: rec.expires_at_ms,
        guardians_required: cfg.threshold,
        guardians_total: cfg.guardians.len() as u32,
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_submitRecoverySignature
// =============================================================================

pub(crate) async fn handle_submit_recovery_signature(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: SubmitRecoverySignatureRequest = parse_params(params)?;
    let store = node.recovery_pending().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "Recovery store not initialized".to_string(),
        data: None,
    })?;
    let validator = node
        .social_recovery_validator()
        .ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "SocialRecoveryValidator not initialized".to_string(),
            data: None,
        })?;
    let mut rec = store.get(&req.recovery_id)?.ok_or_else(|| JsonRpcError {
        code: -32404,
        message: "Unknown recovery_id".to_string(),
        data: None,
    })?;
    if rec.finalized {
        return Err(JsonRpcError {
            code: -32602,
            message: "Recovery already finalized".to_string(),
            data: None,
        });
    }
    let now = now_ms();
    if now > rec.expires_at_ms {
        return Err(JsonRpcError {
            code: -32602,
            message: "Recovery ceremony expired".to_string(),
            data: None,
        });
    }
    let account_addr = decode_hex(&rec.account_address)?;
    let cfg = validator
        .config_for(&account_addr)
        .ok_or_else(|| JsonRpcError {
            code: -32404,
            message: "no SocialRecovery config for this account".to_string(),
            data: None,
        })?;
    if req.guardian_index as usize >= cfg.guardians.len() {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("guardian_index {} out of range", req.guardian_index),
            data: None,
        });
    }
    // Dedup — one signature per guardian_index.
    if rec
        .guardian_signatures
        .iter()
        .any(|(idx, _)| *idx == req.guardian_index)
    {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "guardian {} has already signed this recovery",
                req.guardian_index
            ),
            data: None,
        });
    }
    use base64::Engine;
    let sig_b64 =
        base64::engine::general_purpose::STANDARD.encode(decode_hex(&req.composite_signature_hex)?);
    rec.guardian_signatures.push((req.guardian_index, sig_b64));
    let collected = rec.guardian_signatures.len() as u32;
    let quorum_reached = collected >= cfg.threshold;
    store.put(&rec)?;
    let resp = SubmitRecoverySignatureResponse {
        recovery_id: req.recovery_id,
        guardian_signatures_collected: collected,
        guardians_required: cfg.threshold,
        quorum_reached,
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_finalizeRecovery
// =============================================================================

pub(crate) async fn handle_finalize_recovery(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: FinalizeRecoveryRequest = parse_params(params)?;
    let store = node.recovery_pending().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "Recovery store not initialized".to_string(),
        data: None,
    })?;
    let factory = node.account_factory().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "AccountFactory not initialized".to_string(),
        data: None,
    })?;
    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized".to_string(),
        data: None,
    })?;
    let social_validator = node
        .social_recovery_validator()
        .ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "SocialRecoveryValidator not initialized".to_string(),
            data: None,
        })?;
    let mut rec = store.get(&req.recovery_id)?.ok_or_else(|| JsonRpcError {
        code: -32404,
        message: "Unknown recovery_id".to_string(),
        data: None,
    })?;
    if rec.finalized {
        return Err(JsonRpcError {
            code: -32602,
            message: "Recovery already finalized".to_string(),
            data: None,
        });
    }
    let now = now_ms();
    if now > rec.expires_at_ms {
        return Err(JsonRpcError {
            code: -32602,
            message: "Recovery ceremony expired".to_string(),
            data: None,
        });
    }
    let account_addr = decode_hex(&rec.account_address)?;
    let cfg = social_validator
        .config_for(&account_addr)
        .ok_or_else(|| JsonRpcError {
            code: -32404,
            message: "no SocialRecovery config".to_string(),
            data: None,
        })?;
    if (rec.guardian_signatures.len() as u32) < cfg.threshold {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "insufficient guardian signatures: {} < {}",
                rec.guardian_signatures.len(),
                cfg.threshold
            ),
            data: None,
        });
    }
    // Rotate the WebAuthnValidator config on this account to the new
    // passkey. Recovery semantics are "the guardian quorum has asserted
    // fresh control of the account, so revoke every previously-
    // enrolled credential and install only the new passkey." If the
    // user wants to re-add their phone or YubiKey afterwards, they
    // enrol them explicitly through the normal flow.
    webauthn_validator.revoke_account(&account_addr);
    webauthn_validator
        .enroll(
            account_addr.clone(),
            rec.new_credential_id.clone(),
            rec.new_passkey.clone(),
        )
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("re-enroll passkey: {}", e),
            data: None,
        })?;
    let mut smart_account = factory
        .get_account(&account_addr)
        .ok_or_else(|| JsonRpcError {
            code: -32404,
            message: format!("Smart account 0x{} not found", hex::encode(&account_addr)),
            data: None,
        })?;
    let init_data = serde_json::to_vec(&rec.new_passkey).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize new passkey: {}", e),
        data: None,
    })?;
    let webauthn_module_addr = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x20;
        a
    };
    let module_config = tenzro_vm::erc7579::ValidatorModuleConfig {
        type_id: tenzro_vm::aa_validators::ModuleType::Validator as u64,
        module_address: webauthn_module_addr,
        init_data,
        priority: 0,
    };
    smart_account
        .install_validator_module_with_recovery(
            module_config,
            /* recovery_authorized = */ true,
        )
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("install rotated WebAuthnValidator: {}", e),
            data: None,
        })?;
    // Persist the rotated account state via the factory (in-memory map +
    // CF_AGENTS write-through).
    factory.update_account(smart_account.clone());
    rec.finalized = true;
    store.put(&rec)?;
    // Drop the finalized ceremony from the pending namespace — the rotated
    // account state under CF_AGENTS / smart_account is the audit-of-record;
    // an in-flight recovery has no value once it has completed.
    let _ = store.delete(&rec.recovery_id);
    let resp = FinalizeRecoveryResponse {
        recovery_id: rec.recovery_id,
        account_address: rec.account_address,
        new_credential_id_hex: format!("0x{}", hex::encode(&rec.new_credential_id)),
        installed_validators: smart_account
            .validator_modules
            .keys()
            .map(|k| format!("0x{}", hex::encode(k)))
            .collect(),
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_grantSessionKey
// =============================================================================

pub(crate) async fn handle_grant_session_key(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: GrantSessionKeyRequest = parse_params(params)?;
    let validator = node.session_key_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "SessionKeyValidator not initialized".to_string(),
        data: None,
    })?;
    let account_addr = decode_hex(&req.account_address)?;
    let session_pubkey_bytes = decode_hex(&req.session_pubkey_hex)?;

    // Custody gate. The account address is a public identifier, so
    // "knows the address" is not a credential — this refuses unless an
    // already-enrolled passkey has signed a node-issued challenge bound
    // to exactly this operation and target.
    let _authorizing_credential = require_account_control(
        node,
        &account_addr,
        CustodyOperation::GrantSessionKey,
        &session_pubkey_bytes,
        req.authorization,
    )
    .await?;
    if session_pubkey_bytes.len() != 32 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "session_pubkey must be 32 bytes (Ed25519 vk), got {}",
                session_pubkey_bytes.len()
            ),
            data: None,
        });
    }
    let mut session_pubkey = [0u8; 32];
    session_pubkey.copy_from_slice(&session_pubkey_bytes);
    let allowed_selectors: Vec<[u8; 4]> = req
        .allowed_selectors_hex
        .iter()
        .map(|s| {
            let bytes = decode_hex(s)?;
            if bytes.len() != 4 {
                return Err(JsonRpcError {
                    code: -32602,
                    message: format!("selector must be 4 bytes, got {}", bytes.len()),
                    data: None,
                });
            }
            let mut a = [0u8; 4];
            a.copy_from_slice(&bytes);
            Ok(a)
        })
        .collect::<Result<Vec<_>, JsonRpcError>>()?;
    let allowed_targets: Vec<[u8; 20]> = req
        .allowed_targets
        .iter()
        .map(|s| decode_address_20(s))
        .collect::<Result<Vec<_>, JsonRpcError>>()?;
    let max_per_call: Option<u128> = match req.max_value_per_call_wei.as_deref() {
        Some(s) if !s.is_empty() => {
            Some(
                s.parse()
                    .map_err(|e: std::num::ParseIntError| JsonRpcError {
                        code: -32602,
                        message: format!("max_value_per_call_wei: {}", e),
                        data: None,
                    })?,
            )
        }
        _ => None,
    };
    let max_total: Option<u128> = match req.max_total_value_wei.as_deref() {
        Some(s) if !s.is_empty() => {
            Some(
                s.parse()
                    .map_err(|e: std::num::ParseIntError| JsonRpcError {
                        code: -32602,
                        message: format!("max_total_value_wei: {}", e),
                        data: None,
                    })?,
            )
        }
        _ => None,
    };
    let cfg = SessionKeyConfig {
        session_pubkey,
        allowed_selectors,
        allowed_targets,
        max_value_per_call: max_per_call,
        max_total_value: max_total,
        valid_after: req.valid_after_unix,
        valid_until: req.valid_until_unix,
    };
    validator.install_for(account_addr.clone(), cfg.clone());
    let resp = GrantSessionKeyResponse {
        account_address: req.account_address,
        session_pubkey_hex: req.session_pubkey_hex,
        valid_after_unix: req.valid_after_unix,
        valid_until_unix: req.valid_until_unix,
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_revokeSessionKey
// =============================================================================

pub(crate) async fn handle_revoke_session_key(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: RevokeSessionKeyRequest = parse_params(params)?;
    let validator = node.session_key_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "SessionKeyValidator not initialized".to_string(),
        data: None,
    })?;
    let account_addr = decode_hex(&req.account_address)?;

    // Custody gate. The account address is a public identifier, so
    // "knows the address" is not a credential — this refuses unless an
    // already-enrolled passkey has signed a node-issued challenge bound
    // to exactly this operation and target.
    let _authorizing_credential = require_account_control(
        node,
        &account_addr,
        CustodyOperation::RevokeSessionKey,
        &[],
        req.authorization,
    )
    .await?;
    let had_config = validator.config_for(&account_addr).is_some();
    validator.uninstall_for(&account_addr);
    let resp = RevokeSessionKeyResponse {
        account_address: req.account_address,
        revoked: had_config,
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_setSpendingLimit
// =============================================================================

pub(crate) async fn handle_set_spending_limit(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: SetSpendingLimitRequest = parse_params(params)?;
    let validator = node
        .spending_limit_validator()
        .ok_or_else(|| JsonRpcError {
            code: -32603,
            message: "SpendingLimitValidator not initialized".to_string(),
            data: None,
        })?;
    let account_addr = decode_hex(&req.account_address)?;

    // Custody gate. The account address is a public identifier, so
    // "knows the address" is not a credential — this refuses unless an
    // already-enrolled passkey has signed a node-issued challenge bound
    // to exactly this operation and target.
    let _authorizing_credential = require_account_control(
        node,
        &account_addr,
        CustodyOperation::SetSpendingLimit,
        &[],
        req.authorization,
    )
    .await?;
    let per_tx: u128 = req
        .per_tx_cap_wei
        .parse()
        .map_err(|e: std::num::ParseIntError| JsonRpcError {
            code: -32602,
            message: format!("per_tx_cap_wei: {}", e),
            data: None,
        })?;
    let daily: u128 = req
        .daily_cap_wei
        .parse()
        .map_err(|e: std::num::ParseIntError| JsonRpcError {
            code: -32602,
            message: format!("daily_cap_wei: {}", e),
            data: None,
        })?;
    let cfg = SpendingLimitConfig {
        max_per_transaction: if per_tx == 0 { None } else { Some(per_tx) },
        max_daily_spend: if daily == 0 { None } else { Some(daily) },
        window_seconds: 86_400,
        enabled: true,
    };
    let auth_bytes = decode_hex(&req.authenticator_pubkey_hex)?;
    if auth_bytes.len() != 32 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "authenticator_pubkey must be 32 bytes, got {}",
                auth_bytes.len()
            ),
            data: None,
        });
    }
    let mut auth = [0u8; 32];
    auth.copy_from_slice(&auth_bytes);
    validator.install_for(account_addr, cfg, auth);
    let resp = SetSpendingLimitResponse {
        account_address: req.account_address,
        per_tx_cap_wei: req.per_tx_cap_wei,
        daily_cap_wei: req.daily_cap_wei,
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_addHardwareSigner
// =============================================================================

pub(crate) async fn handle_add_hardware_signer(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: AddHardwareSignerRequest = parse_params(params)?;
    let factory = node.account_factory().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "AccountFactory not initialized".to_string(),
        data: None,
    })?;
    let account_addr = decode_hex(&req.account_address)?;

    // Custody gate. The account address is a public identifier, so
    // "knows the address" is not a credential — this refuses unless an
    // already-enrolled passkey has signed a node-issued challenge bound
    // to exactly this operation and target.
    let _authorizing_credential = require_account_control(
        node,
        &account_addr,
        CustodyOperation::AddHardwareSigner,
        &[],
        req.authorization,
    )
    .await?;
    let mut smart_account = factory
        .get_account(&account_addr)
        .ok_or_else(|| JsonRpcError {
            code: -32404,
            message: format!("Smart account 0x{} not found", hex::encode(&account_addr)),
            data: None,
        })?;
    let pubkey_bytes = decode_hex(&req.public_key_hex)?;
    let device = req.device_kind.to_lowercase();
    if !matches!(
        device.as_str(),
        "ledger" | "trezor" | "gridplus" | "yubikey" | "generic"
    ) {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("Unsupported device_kind: {}", device),
            data: None,
        });
    }
    // Hardware signers install as a parallel ANDed validator module. The
    // module address slot 0x1030..0x103f is reserved for hardware validators;
    // each device kind gets a distinct slot so multiple hardware signers can
    // coexist on the same account.
    let module_addr_slot = match device.as_str() {
        "ledger" => 0x30,
        "trezor" => 0x31,
        "gridplus" => 0x32,
        "yubikey" => 0x33,
        _ => 0x3f,
    };
    let mut module_addr = [0u8; 20];
    module_addr[18] = 0x10;
    module_addr[19] = module_addr_slot;

    #[derive(Serialize)]
    struct HardwareValidatorInit {
        device_kind: String,
        public_key: Vec<u8>,
        required_always: bool,
        required_above_wei: Option<String>,
        label: Option<String>,
    }
    let init = HardwareValidatorInit {
        device_kind: device.clone(),
        public_key: pubkey_bytes,
        required_always: req.required_always,
        required_above_wei: req.required_above_wei.clone(),
        label: req.label.clone(),
    };
    let init_data = serde_json::to_vec(&init).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize hardware init: {}", e),
        data: None,
    })?;
    let module_config = tenzro_vm::erc7579::ValidatorModuleConfig {
        type_id: tenzro_vm::aa_validators::ModuleType::Validator as u64,
        module_address: module_addr,
        init_data,
        priority: 5, // ANDed after WebAuthn primary
    };
    smart_account
        .install_validator_module(module_config.clone(), /* owner_authorized = */ true)
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("install hardware validator: {}", e),
            data: None,
        })?;
    factory.update_account(smart_account);

    // Hand the init_data to the shared HardwareSignerValidator so the
    // validator-chain actually consults the configured pubkey at
    // signing time (not just the smart-account install record).
    if let Some(hw_validator) = node.hardware_signer_validator(&module_addr)
        && let Err(e) =
            hw_validator.install_from_init_data(account_addr.clone(), &module_config.init_data)
    {
        return Err(JsonRpcError {
            code: -32603,
            message: format!("hardware validator install_from_init_data: {}", e),
            data: None,
        });
    }

    let resp = AddHardwareSignerResponse {
        account_address: req.account_address,
        device_kind: device,
        validator_module_address: format!("0x{}", hex::encode(module_addr)),
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_getSmartAccount
// =============================================================================

pub(crate) async fn handle_get_smart_account(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: GetSmartAccountRequest = parse_params(params)?;
    let factory = node.account_factory().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "AccountFactory not initialized".to_string(),
        data: None,
    })?;
    let account_addr = decode_hex(&req.account_address)?;
    let account = factory
        .get_account(&account_addr)
        .ok_or_else(|| JsonRpcError {
            code: -32404,
            message: format!("Smart account 0x{} not found", hex::encode(&account_addr)),
            data: None,
        })?;
    let installed: Vec<InstalledValidatorSummary> = account
        .validator_modules
        .iter()
        .map(|(addr, cfg)| InstalledValidatorSummary {
            module_address: format!("0x{}", hex::encode(addr)),
            type_id: cfg.type_id,
            priority: cfg.priority,
        })
        .collect();
    let resp = SmartAccountSummary {
        address: format!("0x{}", hex::encode(&account.address)),
        owner_hex: format!("0x{}", hex::encode(&account.owner)),
        nonce: account.nonce,
        is_deployed: account.is_deployed,
        installed_validators: installed,
    };
    serde_json::to_value(resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_listPendingRecoveries
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct ListPendingRecoveriesRequest {
    pub account_address: String,
}

pub(crate) async fn handle_list_pending_recoveries(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: ListPendingRecoveriesRequest = parse_params(params)?;
    let store = node.recovery_pending().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "Recovery store not initialized".to_string(),
        data: None,
    })?;
    let recs = store.list_for_account(&req.account_address)?;
    let body = serde_json::json!({
        "account_address": req.account_address,
        "count": recs.len(),
        "pending_recoveries": recs.into_iter().map(|r| serde_json::json!({
            "recovery_id": r.recovery_id,
            "created_at_ms": r.created_at_ms,
            "expires_at_ms": r.expires_at_ms,
            "guardian_signatures_collected": r.guardian_signatures.len(),
            "finalized": r.finalized,
        })).collect::<Vec<_>>(),
    });
    Ok(body)
}

// =============================================================================
// Handler: tenzro_listSmartAccounts
// =============================================================================

pub(crate) async fn handle_list_smart_accounts(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let factory = node.account_factory().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "AccountFactory not initialized".to_string(),
        data: None,
    })?;
    let all = factory.get_all_accounts();
    let items: Vec<SmartAccountSummary> = all
        .into_iter()
        .map(|account| SmartAccountSummary {
            address: format!("0x{}", hex::encode(&account.address)),
            owner_hex: format!("0x{}", hex::encode(&account.owner)),
            nonce: account.nonce,
            is_deployed: account.is_deployed,
            installed_validators: account
                .validator_modules
                .iter()
                .map(|(addr, cfg)| InstalledValidatorSummary {
                    module_address: format!("0x{}", hex::encode(addr)),
                    type_id: cfg.type_id,
                    priority: cfg.priority,
                })
                .collect(),
        })
        .collect();
    let body = serde_json::json!({
        "count": items.len(),
        "smart_accounts": items,
    });
    Ok(body)
}

// =============================================================================
// Handler: tenzro_addPasskey
//
// Enrolls a new passkey credential on an existing smart account, keeping
// every previously-enrolled credential active. Authorization: the caller
// must present a valid signature from any currently-enrolled credential
// on the account proving they control at least one existing device.
// The new credential's `credential_id` MUST be distinct from every
// already-enrolled credential id on this account.
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct AddPasskeyRequest {
    /// Hex-encoded 20-byte smart-account address.
    pub account_address: String,
    /// Hex-encoded P-256 public key (raw 64-byte X||Y, SEC1 65-byte, or
    /// COSE_Key CBOR). Same normalisation rules as
    /// `tenzro_enrollPasskey`.
    pub new_passkey_public_key_hex: String,
    /// WebAuthn credential id of the new credential.
    pub new_credential_id_hex: String,
    /// Optional display label (e.g. "Phone 1", "YubiKey").
    #[serde(default)]
    pub label: Option<String>,
    /// Proof the caller already controls this account: a
    /// node-issued challenge signed by an already-enrolled passkey.
    /// Without it the call is refused — the account address is a
    /// public identifier, not a credential.
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Serialize)]
pub struct AddPasskeyResponse {
    pub account_address: String,
    pub credential_id_hex: String,
    pub credentials_total: usize,
    pub label: Option<String>,
}

pub(crate) async fn handle_add_passkey(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: AddPasskeyRequest = parse_params(params)?;

    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized on this node".to_string(),
        data: None,
    })?;

    let account_addr = decode_hex(&req.account_address)?;
    let credential_id = decode_hex(&req.new_credential_id_hex)?;

    // Custody gate. The account address is a public identifier, so
    // "knows the address" is not a credential — this refuses unless an
    // already-enrolled passkey has signed a node-issued challenge bound
    // to exactly this operation and target.
    // Target is empty for an add, unlike every other operation here.
    //
    // The other mutations name something that already exists — the credential
    // being revoked, the session key being withdrawn — so the challenge can be
    // issued against it and a caller cannot spend one authorization on a
    // different subject. A device being *added* does not exist yet: its
    // credential id is produced by `navigator.credentials.create()` partway
    // through the same ceremony that collects this proof, so there is nothing
    // to bind at issue time.
    //
    // What still binds it: the account, the operation, a single-use claim, and
    // a five-minute TTL. So this authorizes "add one device to this account,
    // once, now" rather than "add this specific device" — which is exactly the
    // ceremony the user is performing, and it is the reason both the session
    // path and the direct-RPC path must agree on an empty target. They did not
    // at first, and a mismatch here is not a security hole but a permanent
    // refusal: the challenge would never match and no device could be added.
    let authorizing_credential = require_account_control(
        node,
        &account_addr,
        CustodyOperation::AddPasskey,
        &[],
        req.authorization,
    )
    .await?;

    if credential_id.is_empty() {
        return Err(JsonRpcError {
            code: -32602,
            message: "new_credential_id_hex must decode to non-empty bytes".to_string(),
            data: None,
        });
    }

    // The account must already have at least one credential — adding a
    // second device only makes sense on an account that was enrolled
    // through `tenzro_enrollPasskey` first. This guards against an
    // attacker-supplied account that the user has never authorised.
    if webauthn_validator
        .list_credentials(&account_addr)
        .is_empty()
    {
        return Err(JsonRpcError {
            code: -32404,
            message: format!(
                "No existing passkey enrolled on account 0x{} — bootstrap via tenzro_enrollPasskey first",
                hex::encode(&account_addr)
            ),
            data: None,
        });
    }

    // Same credential id collisions are explicitly rejected — otherwise
    // a stale device might silently overwrite a credential the user
    // still expects to work.
    if webauthn_validator
        .get_credential(&account_addr, &credential_id)
        .is_some()
    {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "credential_id 0x{} already enrolled on account 0x{}",
                hex::encode(&credential_id),
                hex::encode(&account_addr)
            ),
            data: None,
        });
    }

    // Normalise the new pubkey + node-mint the ML-DSA-65 leg + construct the
    // WebAuthnAccountKey, same as the bootstrap provisioning path. A browser
    // (or a phone reached over WebAuthn hybrid transport) can only produce the
    // P-256 credential; the post-quantum leg is minted in the node here, so
    // the second device never has to carry an ML-DSA key.
    let passkey_pubkey_bytes = decode_hex(&req.new_passkey_public_key_hex)?;
    let p256_xy = normalize_p256_pubkey_to_raw_xy(&passkey_pubkey_bytes)?;
    let mut pubkey_x = [0u8; 32];
    let mut pubkey_y = [0u8; 32];
    pubkey_x.copy_from_slice(&p256_xy[..32]);
    pubkey_y.copy_from_slice(&p256_xy[32..]);

    let ml_dsa = tenzro_crypto::pq::MlDsaSigningKey::generate();
    let ml_dsa_vk = ml_dsa.verifying_key_bytes().to_vec();

    let account_key =
        tenzro_vm::aa_webauthn_validator::WebAuthnAccountKey::new(pubkey_x, pubkey_y, ml_dsa_vk)
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("WebAuthnAccountKey: {}", e),
                data: None,
            })?;

    webauthn_validator
        .enroll(account_addr.clone(), credential_id.clone(), account_key)
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("WebAuthn enroll: {}", e),
            data: None,
        })?;

    let total = webauthn_validator.list_credentials(&account_addr).len();

    // Publish the new device set, chained to the credential that authorized
    // this change — so a node that has never seen this account can still learn
    // which devices may sign, and verify that authority came from a device that
    // already could.
    crate::account_record::republish(
        node,
        &format!("0x{}", hex::encode(&account_addr)),
        "",
        Some(&authorizing_credential),
    );

    serde_json::to_value(AddPasskeyResponse {
        account_address: format!("0x{}", hex::encode(&account_addr)),
        credential_id_hex: format!("0x{}", hex::encode(&credential_id)),
        credentials_total: total,
        label: req.label,
    })
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handler: tenzro_listPasskeys
//
// Lists every enrolled credential id on a smart account. Read-only; no
// signature required (the account address is a public identifier).
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct ListPasskeysRequest {
    pub account_address: String,
}

pub(crate) async fn handle_list_passkeys(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: ListPasskeysRequest = parse_params(params)?;
    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized on this node".to_string(),
        data: None,
    })?;
    let account_addr = decode_hex(&req.account_address)?;
    let credentials: Vec<String> = webauthn_validator
        .list_credentials(&account_addr)
        .into_iter()
        .map(|cid| format!("0x{}", hex::encode(cid)))
        .collect();
    Ok(serde_json::json!({
        "account_address": format!("0x{}", hex::encode(&account_addr)),
        "count": credentials.len(),
        "credential_ids": credentials,
    }))
}

// =============================================================================
// Handler: tenzro_removePasskey
//
// Revokes a single credential from a smart account. The account remains
// usable as long as at least one other credential survives. Removing
// the last credential leaves the account in a recoverable-only state
// — guardians must finalise a recovery before any UserOp can sign.
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct RemovePasskeyRequest {
    pub account_address: String,
    pub credential_id_hex: String,
    /// Proof the caller already controls this account: a
    /// node-issued challenge signed by an already-enrolled passkey.
    /// Without it the call is refused — the account address is a
    /// public identifier, not a credential.
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Serialize)]
pub struct RemovePasskeyResponse {
    pub account_address: String,
    pub credential_id_hex: String,
    pub removed: bool,
    pub credentials_remaining: usize,
}

pub(crate) async fn handle_remove_passkey(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: RemovePasskeyRequest = parse_params(params)?;
    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized on this node".to_string(),
        data: None,
    })?;
    let account_addr = decode_hex(&req.account_address)?;
    let credential_id = decode_hex(&req.credential_id_hex)?;

    // Custody gate. The account address is a public identifier, so
    // "knows the address" is not a credential — this refuses unless an
    // already-enrolled passkey has signed a node-issued challenge bound
    // to exactly this operation and target.
    let authorizing_credential = require_account_control(
        node,
        &account_addr,
        CustodyOperation::RemovePasskey,
        &credential_id,
        req.authorization,
    )
    .await?;
    let removed = webauthn_validator
        .revoke_credential(&account_addr, &credential_id)
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("cannot remove credential: {}", e),
            data: None,
        })?;
    let remaining = webauthn_validator.list_credentials(&account_addr).len();

    // Publish the reduced device set. A revocation that never propagated would
    // leave other nodes still believing a removed device may sign — which is
    // the more dangerous direction of staleness.
    crate::account_record::republish(
        node,
        &format!("0x{}", hex::encode(&account_addr)),
        "",
        Some(&authorizing_credential),
    );

    serde_json::to_value(RemovePasskeyResponse {
        account_address: format!("0x{}", hex::encode(&account_addr)),
        credential_id_hex: format!("0x{}", hex::encode(&credential_id)),
        removed,
        credentials_remaining: remaining,
    })
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// Handlers: tenzro_setPasskeyPolicy / tenzro_getPasskeyPolicy
//
// Per-account second-factor policy on WebAuthnValidator. `two_credentials`
// requires every UserOp signature bundle to carry assertions from two
// distinct enrolled passkeys (e.g. phone + laptop). `single_credential`
// is the default and is stored as absence of a policy row. Upgrading to
// `two_credentials` requires at least two enrolled credentials; while the
// policy is active, `tenzro_removePasskey` refuses removals that would
// drop the enrolled count below the floor.
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct SetPasskeyPolicyRequest {
    pub account_address: String,
    /// `"single_credential"` or `"two_credentials"`.
    pub second_factor: SecondFactorPolicy,
    /// Proof the caller already controls this account: a
    /// node-issued challenge signed by an already-enrolled passkey.
    /// Without it the call is refused — the account address is a
    /// public identifier, not a credential.
    #[serde(default)]
    pub authorization: Option<CustodyAuthorization>,
}

#[derive(Debug, Serialize)]
pub struct PasskeyPolicyResponse {
    pub account_address: String,
    pub second_factor: SecondFactorPolicy,
    pub required_signatures: usize,
    pub credentials_enrolled: usize,
}

pub(crate) async fn handle_set_passkey_policy(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: SetPasskeyPolicyRequest = parse_params(params)?;
    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized on this node".to_string(),
        data: None,
    })?;
    let account_addr = decode_hex(&req.account_address)?;

    // Custody gate. The account address is a public identifier, so
    // "knows the address" is not a credential — this refuses unless an
    // already-enrolled passkey has signed a node-issued challenge bound
    // to exactly this operation and target.
    let _authorizing_credential = require_account_control(
        node,
        &account_addr,
        CustodyOperation::SetPasskeyPolicy,
        &[],
        req.authorization,
    )
    .await?;
    webauthn_validator
        .set_second_factor_policy(account_addr.clone(), req.second_factor)
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("cannot set second-factor policy: {}", e),
            data: None,
        })?;
    let enrolled = webauthn_validator.list_credentials(&account_addr).len();
    serde_json::to_value(PasskeyPolicyResponse {
        account_address: format!("0x{}", hex::encode(&account_addr)),
        second_factor: req.second_factor,
        required_signatures: req.second_factor.required_signatures(),
        credentials_enrolled: enrolled,
    })
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

#[derive(Debug, Deserialize)]
pub struct GetPasskeyPolicyRequest {
    pub account_address: String,
}

pub(crate) async fn handle_get_passkey_policy(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: GetPasskeyPolicyRequest = parse_params(params)?;
    let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "WebAuthnValidator not initialized on this node".to_string(),
        data: None,
    })?;
    let account_addr = decode_hex(&req.account_address)?;
    let policy = webauthn_validator.second_factor_policy(&account_addr);
    let enrolled = webauthn_validator.list_credentials(&account_addr).len();
    serde_json::to_value(PasskeyPolicyResponse {
        account_address: format!("0x{}", hex::encode(&account_addr)),
        second_factor: policy,
        required_signatures: policy.required_signatures(),
        credentials_enrolled: enrolled,
    })
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

// =============================================================================
// PasskeySessionStore — browser-launch WebAuthn ceremony sessions
//
// Backs the `tenzro passkey login`-style flow: the CLI creates a pending
// session over JSON-RPC, opens the node-served page at
// `/auth/passkey?session=<id>` in the user's browser, the page runs the
// WebAuthn ceremony (`navigator.credentials.create()` / `get()`) and posts
// the outcome back against the session, and the CLI polls
// `tenzro_getPasskeySession` until the session reaches a terminal state.
//
// Sessions persist to `CF_VALIDATOR_MODULES / erc7579/auth_session/<id>`
// with the same MAC-tagged row layout as pending recoveries, so an
// in-flight login survives a node restart and a tampered row is refused
// at read time. Expired rows are swept opportunistically on every store
// interaction.
// =============================================================================

/// What the browser ceremony is expected to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionKind {
    /// `navigator.credentials.create()` → new smart account via
    /// `tenzro_enrollPasskey`.
    Enroll,
    /// `navigator.credentials.create()` → additional device credential on
    /// an existing account via `tenzro_addPasskey`.
    Add,
    /// `navigator.credentials.get()` over an op hash → verified assertion
    /// via `tenzro_signWithPasskey`.
    Sign,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionStatus {
    /// Waiting for the browser ceremony.
    Pending,
    /// A completion request claimed the session and is executing. A session
    /// stuck here (crash mid-execution) expires like any other — it can
    /// never be claimed twice.
    InFlight,
    /// Ceremony executed successfully; `result` carries the handler response.
    Completed,
    /// Ceremony executed and the underlying handler rejected it; `error`
    /// carries the reason. Terminal — start a fresh session to retry.
    Failed,
    /// TTL elapsed before completion.
    Expired,
}

/// One browser-launch ceremony session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthSession {
    /// 32 random bytes, hex. Capability token: knowing the id is the
    /// authorization to complete the ceremony, exactly like the device-code
    /// string in an OAuth device flow.
    pub session_id: String,
    pub kind: AuthSessionKind,
    pub status: AuthSessionStatus,
    /// WebAuthn challenge, base64url no-pad. Random 32 bytes for
    /// `Enroll`/`Add`; the raw op-hash bytes for `Sign` (the assertion's
    /// clientDataJSON challenge must equal the op hash for the validator
    /// to accept it).
    pub challenge_b64: String,
    /// Kind-specific parameters supplied by the CLI at creation time
    /// (display name, account address, ML-DSA verifying key / signature,
    /// salt, label, op hash). Merged with the browser payload when the
    /// ceremony completes.
    pub params: Value,
    /// Handler response once `Completed`.
    pub result: Option<Value>,
    /// Failure reason once `Failed`.
    pub error: Option<String>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

/// Session TTL — 10 minutes, generous enough for a user to find their
/// phone / security key, short enough that an abandoned link dies.
const AUTH_SESSION_TTL_MS: u64 = 10 * 60 * 1000;

/// How long a terminal (Completed / Failed) session row survives so the
/// CLI poll loop can read the outcome before the sweep removes it.
const AUTH_SESSION_LINGER_MS: u64 = 10 * 60 * 1000;

/// Persistent store for browser-launch ceremony sessions.
pub struct PasskeySessionStore {
    storage: Arc<dyn KvStore>,
}

impl PasskeySessionStore {
    const PREFIX: &'static [u8] = b"erc7579/auth_session/";

    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }

    fn key(session_id: &str) -> Vec<u8> {
        let mut k = Self::PREFIX.to_vec();
        k.extend_from_slice(session_id.as_bytes());
        k
    }

    pub(crate) fn put(&self, session: &PendingAuthSession) -> Result<(), JsonRpcError> {
        let bytes = serde_json::to_vec(session).map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("serialize auth session: {}", e),
            data: None,
        })?;
        let tagged = mac_wrap(&bytes);
        self.storage
            .put(
                CF_VALIDATOR_MODULES,
                &Self::key(&session.session_id),
                &tagged,
            )
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("persist auth session: {}", e),
                data: None,
            })
    }

    /// Read a session, transparently flipping `Pending`/`InFlight` rows
    /// past their expiry to `Expired` (persisted).
    pub(crate) fn get(&self, session_id: &str) -> Result<Option<PendingAuthSession>, JsonRpcError> {
        let bytes = self
            .storage
            .get(CF_VALIDATOR_MODULES, &Self::key(session_id))
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("read auth session: {}", e),
                data: None,
            })?;
        let Some(b) = bytes else { return Ok(None) };
        let payload = mac_verify(&b).map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("tampered auth session row: {}", e),
            data: None,
        })?;
        let mut session: PendingAuthSession =
            serde_json::from_slice(payload).map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("deserialize auth session: {}", e),
                data: None,
            })?;
        if matches!(
            session.status,
            AuthSessionStatus::Pending | AuthSessionStatus::InFlight
        ) && now_ms() > session.expires_at_ms
        {
            session.status = AuthSessionStatus::Expired;
            self.put(&session)?;
        }
        Ok(Some(session))
    }

    pub(crate) fn delete(&self, session_id: &str) {
        let _ = self
            .storage
            .delete(CF_VALIDATOR_MODULES, &Self::key(session_id));
    }

    /// Drop expired rows: non-terminal past expiry + terminal past
    /// expiry + linger. Called opportunistically on session creation.
    pub(crate) fn sweep(&self) {
        let Ok(keys) = self
            .storage
            .get_keys_with_prefix(CF_VALIDATOR_MODULES, Self::PREFIX)
        else {
            return;
        };
        let now = now_ms();
        for full_key in keys {
            let Some(sid) = full_key.strip_prefix(Self::PREFIX) else {
                continue;
            };
            let sid = String::from_utf8_lossy(sid).to_string();
            match self.get(&sid) {
                Ok(Some(s)) => {
                    let cutoff = match s.status {
                        AuthSessionStatus::Completed
                        | AuthSessionStatus::Failed
                        | AuthSessionStatus::Expired => s.expires_at_ms + AUTH_SESSION_LINGER_MS,
                        _ => s.expires_at_ms,
                    };
                    if now > cutoff {
                        self.delete(&sid);
                    }
                }
                // Tampered / undecodable rows are dead weight — remove.
                Err(_) => self.delete(&sid),
                Ok(None) => {}
            }
        }
    }
}

// =============================================================================
// Handler: tenzro_createPasskeySession
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct CreatePasskeySessionRequest {
    /// "enroll" | "add" | "sign".
    pub kind: AuthSessionKind,
    /// Enroll: optional display name for the new identity.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Enroll: ML-DSA-65 verifying key for the hybrid PQ leg (CLI enroll
    /// path). Add sessions do NOT carry this — the node mints the second
    /// credential's ML-DSA leg itself, so a browser/phone that can only
    /// produce a P-256 passkey can still add a device.
    #[serde(default)]
    pub ml_dsa_public_key_hex: Option<String>,
    /// Enroll: CREATE2 salt (defaults to 0).
    #[serde(default)]
    pub salt: u64,
    /// Add + Sign: target smart-account address.
    #[serde(default)]
    pub account_address: Option<String>,
    /// Add: display label for the new credential.
    #[serde(default)]
    pub label: Option<String>,
    /// Sign: 32-byte op hash the assertion must attest to.
    #[serde(default)]
    pub op_hash_hex: Option<String>,
    /// Sign: ML-DSA-65 signature over the op-hash bytes, pre-signed
    /// client-side for accounts with a hybrid PQ leg.
    #[serde(default)]
    pub ml_dsa_signature_hex: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreatePasskeySessionResponse {
    pub session_id: String,
    /// Path on the node's web server the CLI should open in a browser.
    pub verification_path: String,
    pub status: AuthSessionStatus,
    pub challenge_b64: String,
    pub expires_at_ms: u64,
}

pub(crate) async fn handle_create_passkey_session(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: CreatePasskeySessionRequest = parse_params(params)?;
    let store = node.passkey_sessions().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "PasskeySessionStore not initialized on this node".to_string(),
        data: None,
    })?;
    store.sweep();

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    // Per-kind validation up front so the user gets an immediate error at
    // the CLI instead of a dead browser page.
    let (challenge_b64, params_value) = match req.kind {
        AuthSessionKind::Enroll => {
            let vk_hex = req
                .ml_dsa_public_key_hex
                .as_deref()
                .ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "ml_dsa_public_key_hex is required for enroll sessions".to_string(),
                    data: None,
                })?;
            let vk = decode_hex(vk_hex)?;
            if vk.len() != ML_DSA_65_VK_LEN {
                return Err(JsonRpcError {
                    code: -32602,
                    message: format!(
                        "ml_dsa_public_key must be {} bytes (ML-DSA-65 vk), got {}",
                        ML_DSA_65_VK_LEN,
                        vk.len()
                    ),
                    data: None,
                });
            }
            let mut challenge = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut challenge);
            (
                URL_SAFE_NO_PAD.encode(challenge),
                serde_json::json!({
                    "display_name": req.display_name,
                    "ml_dsa_public_key_hex": vk_hex,
                    "salt": req.salt,
                }),
            )
        }
        AuthSessionKind::Add => {
            let account = req.account_address.as_deref().ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "account_address is required for add sessions".to_string(),
                data: None,
            })?;
            let account_addr = decode_hex(account)?;
            // Add sessions do NOT require a client-supplied ML-DSA vk — the
            // node mints the new credential's PQ leg when the ceremony
            // completes (see handle_add_passkey). The browser/phone performs
            // only the standard WebAuthn ceremony.
            let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
                code: -32603,
                message: "WebAuthnValidator not initialized on this node".to_string(),
                data: None,
            })?;
            if webauthn_validator
                .list_credentials(&account_addr)
                .is_empty()
            {
                return Err(JsonRpcError {
                    code: -32404,
                    message: format!(
                        "No existing passkey enrolled on account 0x{} — bootstrap via an enroll session first",
                        hex::encode(&account_addr)
                    ),
                    data: None,
                });
            }
            let mut challenge = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut challenge);
            (
                URL_SAFE_NO_PAD.encode(challenge),
                serde_json::json!({
                    "account_address": format!("0x{}", hex::encode(&account_addr)),
                    "label": req.label,
                }),
            )
        }
        AuthSessionKind::Sign => {
            let account = req.account_address.as_deref().ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "account_address is required for sign sessions".to_string(),
                data: None,
            })?;
            let account_addr = decode_hex(account)?;
            let op_hash_hex = req.op_hash_hex.as_deref().ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "op_hash_hex is required for sign sessions".to_string(),
                data: None,
            })?;
            let op_hash = decode_hex(op_hash_hex)?;
            if op_hash.len() != 32 {
                return Err(JsonRpcError {
                    code: -32602,
                    message: format!("op_hash must be 32 bytes, got {}", op_hash.len()),
                    data: None,
                });
            }
            let webauthn_validator = node.webauthn_validator().ok_or_else(|| JsonRpcError {
                code: -32603,
                message: "WebAuthnValidator not initialized on this node".to_string(),
                data: None,
            })?;
            if webauthn_validator
                .list_credentials(&account_addr)
                .is_empty()
            {
                return Err(JsonRpcError {
                    code: -32404,
                    message: format!(
                        "No passkey enrolled on account 0x{}",
                        hex::encode(&account_addr)
                    ),
                    data: None,
                });
            }
            // The WebAuthn challenge IS the op hash — the validator binds
            // the assertion's clientDataJSON challenge to the op it signs.
            (
                URL_SAFE_NO_PAD.encode(&op_hash),
                serde_json::json!({
                    "account_address": format!("0x{}", hex::encode(&account_addr)),
                    "op_hash_hex": format!("0x{}", hex::encode(&op_hash)),
                    "ml_dsa_signature_hex": req.ml_dsa_signature_hex,
                }),
            )
        }
    };

    let mut sid_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sid_bytes);
    let session_id = hex::encode(sid_bytes);
    let now = now_ms();
    let session = PendingAuthSession {
        session_id: session_id.clone(),
        kind: req.kind,
        status: AuthSessionStatus::Pending,
        challenge_b64: challenge_b64.clone(),
        params: params_value,
        result: None,
        error: None,
        created_at_ms: now,
        expires_at_ms: now + AUTH_SESSION_TTL_MS,
    };
    store.put(&session)?;

    serde_json::to_value(CreatePasskeySessionResponse {
        verification_path: format!("/auth/passkey?session={}", session_id),
        session_id,
        status: AuthSessionStatus::Pending,
        challenge_b64,
        expires_at_ms: session.expires_at_ms,
    })
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize response: {}", e),
        data: None,
    })
}

/// Create a `Sign` ceremony for a shell sign-in.
///
/// Reuses the wallet's existing signing ceremony rather than adding a fourth
/// kind: what a shell sign-in needs is exactly "prove you hold this wallet,
/// over these bytes". The only difference is the extra `shell_lease_id` in
/// `params`, which is what the completion path keys off to mint the grant.
///
/// Returns `(session_id, verification_path, expires_at_ms)`.
pub(crate) async fn create_session_for_shell(
    node: &Arc<TenzroNode>,
    account_address: &str,
    op_hash_hex: &str,
    lease_id: &str,
) -> Result<(String, String, u64), JsonRpcError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let store = node.passkey_sessions().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "PasskeySessionStore not initialized on this node".to_string(),
        data: None,
    })?;
    store.sweep();

    let op_hash = decode_hex(op_hash_hex)?;
    if op_hash.len() != 32 {
        return Err(JsonRpcError {
            code: -32602,
            message: format!("op_hash must be 32 bytes, got {}", op_hash.len()),
            data: None,
        });
    }

    let mut sid_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sid_bytes);
    let session_id = hex::encode(sid_bytes);
    let now = now_ms();
    let session = PendingAuthSession {
        session_id: session_id.clone(),
        kind: AuthSessionKind::Sign,
        status: AuthSessionStatus::Pending,
        // The challenge IS the op hash — the validator binds the assertion's
        // clientDataJSON challenge to the op it signs.
        challenge_b64: URL_SAFE_NO_PAD.encode(&op_hash),
        params: serde_json::json!({
            "account_address": account_address.to_ascii_lowercase(),
            "op_hash_hex": format!("0x{}", hex::encode(&op_hash)),
            "ml_dsa_signature_hex": Value::Null,
            "shell_lease_id": lease_id,
        }),
        result: None,
        error: None,
        created_at_ms: now,
        expires_at_ms: now + AUTH_SESSION_TTL_MS,
    };
    store.put(&session)?;

    Ok((
        session_id.clone(),
        format!("/auth/passkey?session={}", session_id),
        session.expires_at_ms,
    ))
}

// =============================================================================
// Handler: tenzro_getPasskeySession
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct GetPasskeySessionRequest {
    pub session_id: String,
}

pub(crate) async fn handle_get_passkey_session(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: GetPasskeySessionRequest = parse_params(params)?;
    let store = node.passkey_sessions().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "PasskeySessionStore not initialized on this node".to_string(),
        data: None,
    })?;
    let session = store.get(&req.session_id)?.ok_or_else(|| JsonRpcError {
        code: -32404,
        message: "Unknown or swept auth session".to_string(),
        data: None,
    })?;
    // The CLI poll surface deliberately excludes `params` (which can carry
    // an ML-DSA signature) and `challenge_b64` — the poller only needs the
    // outcome.
    Ok(serde_json::json!({
        "session_id": session.session_id,
        "kind": session.kind,
        "status": session.status,
        "result": session.result,
        "error": session.error,
        "expires_at_ms": session.expires_at_ms,
    }))
}

/// Claim a pending session for execution and run the underlying handler.
/// Called by the web completion endpoint, never dispatched over JSON-RPC.
///
/// Single-use discipline: the session row is flipped to `InFlight` and
/// persisted **before** the handler runs, so a second completion attempt
/// (double-submit, replayed request, concurrent tab) is refused even if
/// the first one is still executing — and a crash mid-execution leaves an
/// unclaimable row that simply expires.
pub(crate) async fn complete_passkey_session(
    node: &Arc<TenzroNode>,
    session_id: &str,
    browser_payload: Value,
) -> Result<Value, JsonRpcError> {
    let store = node.passkey_sessions().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: "PasskeySessionStore not initialized on this node".to_string(),
        data: None,
    })?;
    let mut session = store.get(session_id)?.ok_or_else(|| JsonRpcError {
        code: -32404,
        message: "Unknown or swept auth session".to_string(),
        data: None,
    })?;
    if session.status != AuthSessionStatus::Pending {
        return Err(JsonRpcError {
            code: -32602,
            message: format!(
                "auth session is not pending (status: {})",
                serde_json::to_string(&session.status).unwrap_or_default()
            ),
            data: None,
        });
    }
    session.status = AuthSessionStatus::InFlight;
    store.put(&session)?;

    let handler_params = match build_completion_params(&session, browser_payload) {
        Ok(p) => p,
        Err(e) => {
            session.status = AuthSessionStatus::Failed;
            session.error = Some(e.message.clone());
            let _ = store.put(&session);
            return Err(e);
        }
    };

    let outcome = match session.kind {
        AuthSessionKind::Enroll => handle_enroll_passkey(node, Some(handler_params)).await,
        AuthSessionKind::Add => handle_add_passkey(node, Some(handler_params)).await,
        AuthSessionKind::Sign => handle_sign_with_passkey(node, Some(handler_params)).await,
    };

    match outcome {
        Ok(mut result) => {
            // A shell sign-in is an ordinary `Sign` ceremony plus one extra
            // step: now that the wallet has proved itself, mint the single-use
            // grant the CLI redeems when it opens the stream. Ceremonies that
            // are not shell sign-ins fall through untouched.
            if let Some(grant) = crate::remote_access_rpc::mint_grant_for_completed_shell_session(
                node,
                &session.params,
            ) && let Some(obj) = result.as_object_mut()
            {
                obj.insert(
                    "shell_grant".to_string(),
                    serde_json::json!({
                        "grant_id": grant.grant_id,
                        "lease_id": grant.lease_id,
                        "wallet": grant.wallet,
                        "expires_at_ms": grant.expires_at_ms,
                    }),
                );
            }
            session.status = AuthSessionStatus::Completed;
            session.result = Some(result.clone());
            store.put(&session)?;
            Ok(result)
        }
        Err(e) => {
            session.status = AuthSessionStatus::Failed;
            session.error = Some(e.message.clone());
            let _ = store.put(&session);
            Err(e)
        }
    }
}

/// Merge the CLI-supplied session params with the browser ceremony payload
/// into the exact request shape the underlying handler expects.
fn build_completion_params(
    session: &PendingAuthSession,
    browser_payload: Value,
) -> Result<Value, JsonRpcError> {
    let str_field = |v: &Value, key: &str| -> Result<String, JsonRpcError> {
        v.get(key)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: format!("completion payload missing `{}`", key),
                data: None,
            })
    };
    match session.kind {
        AuthSessionKind::Enroll => Ok(serde_json::json!({
            "display_name": session.params.get("display_name"),
            "passkey_public_key_hex": str_field(&browser_payload, "passkey_public_key_hex")?,
            "credential_id_hex": str_field(&browser_payload, "credential_id_hex")?,
            "ml_dsa_public_key_hex": session.params.get("ml_dsa_public_key_hex"),
            "salt": session.params.get("salt"),
        })),
        AuthSessionKind::Add => {
            // Adding a device is a custody change, so the ceremony has two
            // halves: `create()` for the new credential, and `get()` from a
            // credential already on the account proving the person doing it is
            // the owner. The browser sends both; the second becomes the
            // `authorization` the custody gate requires.
            //
            // Without it the add is refused — which is the point. A device-add
            // that needed only the account address was an unauthenticated
            // takeover of anyone whose address you knew.
            let authorization = browser_payload
                .get("authorization")
                .cloned()
                .ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "completion payload missing `authorization`: adding a device \
                                  requires an assertion from a passkey already enrolled on this \
                                  account, over the custody challenge"
                        .to_string(),
                    data: None,
                })?;
            Ok(serde_json::json!({
                "account_address": session.params.get("account_address"),
                "new_passkey_public_key_hex": str_field(&browser_payload, "passkey_public_key_hex")?,
                "new_credential_id_hex": str_field(&browser_payload, "credential_id_hex")?,
                "label": session.params.get("label"),
                "authorization": authorization,
            }))
        }
        AuthSessionKind::Sign => {
            let assertion =
                browser_payload
                    .get("assertion")
                    .cloned()
                    .ok_or_else(|| JsonRpcError {
                        code: -32602,
                        message: "completion payload missing `assertion`".to_string(),
                        data: None,
                    })?;
            Ok(serde_json::json!({
                "account_address": session.params.get("account_address"),
                "op_hash_hex": session.params.get("op_hash_hex"),
                "assertion": assertion,
                "credential_id_hex": str_field(&browser_payload, "credential_id_hex")?,
                "ml_dsa_signature_hex": session.params.get("ml_dsa_signature_hex"),
            }))
        }
    }
}
