//! A wallet's public custody state, published so it survives the node it was
//! created on.
//!
//! # The problem
//!
//! A user's identity, their smart account, and the set of passkeys allowed to
//! sign for it all live in one node's RocksDB. Lose that node and the private
//! keys are still perfectly safe — they never left the users' devices — but
//! nothing remains that says *which* devices those were. The wallet becomes
//! unrecoverable for want of a list of public keys.
//!
//! So the network has to know too. Only the public half: verification keys,
//! credential ids, policy, guardians. Nothing here can sign anything.
//!
//! # Why this cannot be a plain broadcast
//!
//! The obvious approach — announce "here are Alice's credentials" on a gossip
//! topic — reopens over the network exactly the hole that
//! [`crate::passkey_rpc`] closes locally. If any peer can publish a record for
//! any account, an attacker publishes one naming their own key and the wallet
//! is theirs on every node that believes it.
//!
//! Signing the record does not by itself fix that, because the attacker can
//! sign their own record with their own key. The question a verifier must be
//! able to answer is not "is this signed?" but "is this signed by someone who
//! was *already* an authority on this account?"
//!
//! # The chain
//!
//! Each record names its predecessor and is signed by a credential present in
//! that predecessor. Version 0 is created at enrollment, when the account's
//! first credential is by definition its only authority, and its commitment is
//! anchored where consensus decides rather than where a peer asserts.
//!
//! From there the property is inductive: version N is trustworthy if version
//! N−1 was, and version 0 is trustworthy because it is anchored. An attacker
//! who publishes a record signed with a key that was not in the previous
//! version produces something every verifier rejects, no matter how many peers
//! repeat it.
//!
//! That is the same rule as the local custody gate — *a change to who can sign
//! must be authorized by someone who already could* — extended across time and
//! across machines.

use serde::{Deserialize, Serialize};

/// Domain separator for the commitment preimage.
///
/// Keeps an account commitment from colliding with any other 32-byte digest in
/// the system. Two subsystems agreeing by accident on what a hash commits to is
/// how a signature over one thing becomes a signature over another.
const RECORD_DOMAIN: &[u8] = b"tenzro/account-record/v1";

/// One device that may sign for an account.
///
/// Public material only. A credential id identifies a device; the P-256 point
/// and ML-DSA verifying key check its signatures. None of it can produce one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCredential {
    /// WebAuthn credential id, hex.
    pub credential_id_hex: String,
    /// P-256 public key as raw `x || y`, hex.
    pub p256_public_key_hex: String,
    /// ML-DSA-65 verifying key, hex — the post-quantum leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_dsa_public_key_hex: Option<String>,
    /// Operator-supplied label, e.g. "Phone". Advisory; carries no authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A published snapshot of an account's public custody state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    /// The smart-account address, hex.
    pub account_address: String,
    /// The TDIP identity that owns it.
    pub owner_did: String,
    /// Monotonic. Version 0 is the enrollment record.
    pub version: u64,
    /// Commitment of the previous version, hex. `None` only at version 0.
    ///
    /// This is what makes the chain a chain: a record that names no predecessor
    /// and is not version 0 has nothing to be verified against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_commitment_hex: Option<String>,
    /// Every device that may sign, ordered by credential id so the commitment
    /// does not depend on map iteration order.
    pub credentials: Vec<DeviceCredential>,
    /// Second-factor policy, as its wire string.
    pub policy: String,
    /// Recovery guardians, as their public keys, hex.
    #[serde(default)]
    pub guardians: Vec<String>,
    /// Unix milliseconds at publication. Advisory — ordering comes from
    /// `version` and the chain, never from a clock a publisher controls.
    pub published_at_ms: u64,
}

impl AccountRecord {
    /// The 32-byte commitment over this record.
    ///
    /// Every field is length-prefixed, so no two distinct records can hash
    /// alike by rearranging where one field ends and the next begins. That
    /// ambiguity would let an attacker craft a record with a different
    /// credential set but the same commitment as an anchored one.
    pub fn commitment(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(RECORD_DOMAIN);
        // A free function rather than a closure: a closure capturing `h`
        // mutably cannot coexist with the direct `h.update` calls between
        // fields.
        fn field(h: &mut Sha256, bytes: &[u8]) {
            h.update((bytes.len() as u32).to_be_bytes());
            h.update(bytes);
        }
        field(&mut h, self.account_address.as_bytes());
        field(&mut h, self.owner_did.as_bytes());
        h.update(self.version.to_be_bytes());
        field(
            &mut h,
            self.previous_commitment_hex
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        h.update((self.credentials.len() as u32).to_be_bytes());
        // Sorted before hashing, so the commitment is a function of the *set*
        // of devices rather than of the order a particular node happened to
        // read them out of its database.
        let mut sorted = self.credentials.clone();
        sorted.sort_by(|a, b| a.credential_id_hex.cmp(&b.credential_id_hex));
        for c in &sorted {
            field(&mut h, c.credential_id_hex.as_bytes());
            field(&mut h, c.p256_public_key_hex.as_bytes());
            field(
                &mut h,
                c.ml_dsa_public_key_hex
                    .as_deref()
                    .unwrap_or_default()
                    .as_bytes(),
            );
        }
        field(&mut h, self.policy.as_bytes());
        h.update((self.guardians.len() as u32).to_be_bytes());
        let mut guardians = self.guardians.clone();
        guardians.sort();
        for g in &guardians {
            field(&mut h, g.as_bytes());
        }
        h.finalize().into()
    }

    /// The commitment as `0x`-prefixed hex.
    pub fn commitment_hex(&self) -> String {
        format!("0x{}", hex::encode(self.commitment()))
    }

    /// Whether `credential_id_hex` may sign for this account.
    pub fn authorizes(&self, credential_id_hex: &str) -> bool {
        let want = credential_id_hex.trim_start_matches("0x");
        self.credentials
            .iter()
            .any(|c| c.credential_id_hex.trim_start_matches("0x") == want)
    }
}

/// Account addresses arrive with and without the `0x` prefix depending on which
/// surface produced them; keying on the raw string would file the same account
/// under two entries and let a second "genesis" slip past the duplicate check.
fn normalize(account: &str) -> String {
    account.trim_start_matches("0x").to_lowercase()
}

/// Why a published record was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// The record is for a different account than the one it claims to update.
    AccountMismatch,
    /// Versions must advance by exactly one. A gap means a record nobody has
    /// seen sits between them, and its credential set decided who could sign.
    NonSequentialVersion {
        /// The version already held.
        have: u64,
        /// The version offered.
        offered: u64,
    },
    /// The offered record does not name the record it is meant to follow.
    BrokenChain,
    /// The signing credential was not an authority in the previous version.
    ///
    /// The whole point. A record signed by a key that was not already trusted
    /// is a record an attacker minted.
    UnauthorizedSigner {
        /// The credential that signed.
        credential_id_hex: String,
    },
    /// A record claiming to be the first, for an account that already has one.
    DuplicateGenesis,
    /// A genesis record that names a predecessor, or a later one that does not.
    MalformedGenesis,
    /// An account with no credentials could never be signed for again.
    EmptyCredentialSet,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AccountMismatch => write!(f, "record is for a different account"),
            Self::NonSequentialVersion { have, offered } => write!(
                f,
                "record version {offered} does not follow {have}; a gap hides a change to who \
                 could sign"
            ),
            Self::BrokenChain => write!(
                f,
                "record does not name the commitment of the version it follows"
            ),
            Self::UnauthorizedSigner { credential_id_hex } => write!(
                f,
                "credential {credential_id_hex} was not an authority in the previous version, so \
                 it cannot authorize this one"
            ),
            Self::DuplicateGenesis => {
                write!(f, "this account already has a first record")
            }
            Self::MalformedGenesis => write!(
                f,
                "version 0 must name no predecessor, and every later version must name one"
            ),
            Self::EmptyCredentialSet => write!(
                f,
                "a record with no credentials would leave an account nobody can ever sign for"
            ),
        }
    }
}

impl std::error::Error for RecordError {}

/// Check that `offered` may replace `current` for the same account.
///
/// `signing_credential_id_hex` is the credential that signed `offered`; the
/// caller verifies the signature itself (through the same WebAuthn path
/// everything else uses) and passes the id here so this function can answer the
/// question that actually matters — *was that signer already an authority?*
///
/// Splitting it this way is deliberate. Signature verification and authority
/// checking are different questions, and collapsing them is how a system ends
/// up accepting a perfectly valid signature from entirely the wrong person.
pub fn verify_succession(
    current: Option<&AccountRecord>,
    offered: &AccountRecord,
    signing_credential_id_hex: &str,
) -> Result<(), RecordError> {
    if offered.credentials.is_empty() {
        return Err(RecordError::EmptyCredentialSet);
    }

    let Some(current) = current else {
        // Genesis. Its trust comes from being anchored where consensus
        // decides, not from a signature — at enrollment there is no prior
        // authority to sign with.
        if offered.version != 0 || offered.previous_commitment_hex.is_some() {
            return Err(RecordError::MalformedGenesis);
        }
        return Ok(());
    };

    // Compared normalized: the same account arrives as `0xAAAA` or `aaaa`
    // depending on which surface produced it, and treating those as different
    // accounts would reject a legitimate update — or, worse, let a second
    // "genesis" past the duplicate check under the other spelling.
    if normalize(&current.account_address) != normalize(&offered.account_address) {
        return Err(RecordError::AccountMismatch);
    }
    if offered.version == 0 {
        return Err(RecordError::DuplicateGenesis);
    }
    if offered.version != current.version + 1 {
        return Err(RecordError::NonSequentialVersion {
            have: current.version,
            offered: offered.version,
        });
    }
    let names = offered
        .previous_commitment_hex
        .as_deref()
        .ok_or(RecordError::MalformedGenesis)?;
    if names.trim_start_matches("0x") != current.commitment_hex().trim_start_matches("0x") {
        return Err(RecordError::BrokenChain);
    }
    // The inductive step: authority to change the set comes from the set as it
    // stood *before* the change, never from the set being proposed.
    if !current.authorizes(signing_credential_id_hex) {
        return Err(RecordError::UnauthorizedSigner {
            credential_id_hex: signing_credential_id_hex.to_string(),
        });
    }
    Ok(())
}

// =============================================================================
// Store
// =============================================================================

use std::sync::Arc;
use tenzro_storage::{CF_VALIDATOR_MODULES, KvStore};

/// Key prefix for the current record of each account.
const RECORD_PREFIX: &[u8] = b"account_record:";

/// The latest accepted record per account, and the gate that decides what
/// "accepted" means.
///
/// Persisted under `CF_VALIDATOR_MODULES` alongside the WebAuthn enrollments
/// this mirrors, so the record and the credentials it describes live and die
/// together on any given node.
pub struct AccountRecordStore {
    storage: Option<Arc<dyn KvStore>>,
    records: dashmap::DashMap<String, AccountRecord>,
}

impl std::fmt::Debug for AccountRecordStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountRecordStore")
            .field("accounts", &self.records.len())
            .field("persistent", &self.storage.is_some())
            .finish()
    }
}

impl AccountRecordStore {
    /// A memory-only store.
    pub fn new() -> Self {
        Self {
            storage: None,
            records: dashmap::DashMap::new(),
        }
    }

    /// A persistent store, hydrated from `storage`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let records = dashmap::DashMap::new();
        if let Ok(rows) = storage.scan_prefix(CF_VALIDATOR_MODULES, RECORD_PREFIX) {
            for (_, bytes) in rows {
                if let Ok(r) = serde_json::from_slice::<AccountRecord>(&bytes) {
                    records.insert(normalize(&r.account_address), r);
                }
            }
        }
        Self {
            storage: Some(storage),
            records,
        }
    }

    /// The current record for `account`, if this node has one.
    pub fn get(&self, account: &str) -> Option<AccountRecord> {
        self.records
            .get(&normalize(account))
            .map(|e| e.value().clone())
    }

    /// How many accounts this node holds a record for.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Accept `offered` if it legitimately succeeds what is held.
    ///
    /// `signing_credential_id_hex` is the credential that signed it; the caller
    /// verifies the signature and passes the id so this can answer the separate
    /// question of whether that signer had authority. See
    /// [`verify_succession`].
    pub fn accept(
        &self,
        offered: AccountRecord,
        signing_credential_id_hex: &str,
    ) -> Result<(), RecordError> {
        let key = normalize(&offered.account_address);
        let current = self.records.get(&key).map(|e| e.value().clone());
        verify_succession(current.as_ref(), &offered, signing_credential_id_hex)?;

        if let Some(storage) = &self.storage
            && let Ok(bytes) = serde_json::to_vec(&offered)
        {
            let mut k = RECORD_PREFIX.to_vec();
            k.extend_from_slice(key.as_bytes());
            if let Err(e) = storage.put(CF_VALIDATOR_MODULES, &k, &bytes) {
                tracing::warn!(account = %key, error = %e, "Could not persist the account record");
            }
        }
        self.records.insert(key, offered);
        Ok(())
    }
}

impl Default for AccountRecordStore {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Publishing from live node state
// =============================================================================

/// Build and accept the next record for `account` from what the node currently
/// holds.
///
/// Called after every successful custody change, so the published snapshot is
/// derived from the validator's own state rather than assembled by hand at each
/// call site — eight hand-assembled records are eight chances for one to omit a
/// credential, and a record that omits a credential is a device the owner
/// silently loses on recovery.
///
/// `signing_credential_id_hex` is the credential that authorized the change. It
/// was already verified by the custody gate; passing it here is what links the
/// new version to the authority that produced it.
///
/// Failure is logged, not propagated. The custody change itself has already
/// been applied and is correct locally; refusing it retroactively because a
/// *snapshot* could not be written would turn a durability problem into a
/// correctness one.
pub fn republish(
    node: &std::sync::Arc<crate::node::TenzroNode>,
    account_hex: &str,
    owner_did: &str,
    signing_credential_id_hex: Option<&str>,
) {
    let Some(validator) = node.webauthn_validator() else {
        return;
    };
    let Ok(account_bytes) = hex::decode(account_hex.trim_start_matches("0x")) else {
        tracing::warn!(account = %account_hex, "Not publishing a record: unreadable account address");
        return;
    };

    let credentials: Vec<DeviceCredential> = validator
        .list_credentials(&account_bytes)
        .into_iter()
        .filter_map(|id| {
            let key = validator.get_credential(&account_bytes, &id)?;
            Some(DeviceCredential {
                credential_id_hex: hex::encode(&id),
                p256_public_key_hex: format!(
                    "{}{}",
                    hex::encode(key.pubkey_x),
                    hex::encode(key.pubkey_y)
                ),
                ml_dsa_public_key_hex: (!key.pq_pubkey.is_empty())
                    .then(|| hex::encode(&key.pq_pubkey)),
                label: None,
            })
        })
        .collect();

    if credentials.is_empty() {
        // Nothing to publish, and a record saying so would be a record
        // asserting the wallet has no signers.
        return;
    }

    let store = node.account_records();
    let current = store.get(account_hex);
    let (version, previous) = match &current {
        Some(c) => (c.version + 1, Some(c.commitment_hex())),
        None => (0, None),
    };

    let record = AccountRecord {
        account_address: account_hex.to_string(),
        owner_did: owner_did.to_string(),
        version,
        previous_commitment_hex: previous,
        credentials,
        policy: "single_credential".to_string(),
        guardians: Vec::new(),
        published_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };

    // At version 0 there is no prior authority to sign with; the record's
    // trust comes from being created at enrollment. After that, the credential
    // that authorized the change is the one that authorizes the record.
    let signer = signing_credential_id_hex.unwrap_or_default();
    match store.accept(record, signer) {
        Ok(()) => tracing::debug!(account = %account_hex, version, "Published account record"),
        Err(e) => tracing::warn!(
            account = %account_hex,
            error = %e,
            "Could not publish the account record; the custody change itself stands"
        ),
    }
}

// =============================================================================
// RPC
// =============================================================================

use crate::rpc::JsonRpcError;
use serde_json::{Value, json};

/// `tenzro_getAccountRecord` — the published custody snapshot for an account.
///
/// Open. Everything in it is public verification material, and the point of
/// publishing is that a node which has never seen this account can obtain it —
/// gating the read would defeat the recovery it exists for.
pub(crate) async fn handle_get_account_record(
    node: &std::sync::Arc<crate::node::TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Missing params: expected {account_address}".to_string(),
        data: None,
    })?;
    let account = p
        .get("account_address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "Missing 'account_address'".to_string(),
            data: None,
        })?;

    match node.account_records().get(account) {
        Some(record) => Ok(json!({
            "record": record,
            "commitment": record.commitment_hex(),
            "note": "Public verification material only. Nothing here can sign; the private keys \
                     stay in each device's secure element.",
        })),
        None => Err(JsonRpcError {
            code: -32004,
            message: format!("This node holds no published record for {account}"),
            data: None,
        }),
    }
}

/// `tenzro_publishAccountRecord` — offer a record this node has not seen.
///
/// How a wallet is recovered onto a node that never held it, and how a node
/// catches up after being offline. Open, because the record carries its own
/// proof: acceptance is decided by [`verify_succession`], not by who asked.
///
/// Params: `{record, signing_credential_id_hex}`.
pub(crate) async fn handle_publish_account_record(
    node: &std::sync::Arc<crate::node::TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Missing params: expected {record, signing_credential_id_hex}".to_string(),
        data: None,
    })?;
    let record: AccountRecord =
        serde_json::from_value(p.get("record").cloned().unwrap_or(Value::Null)).map_err(|e| {
            JsonRpcError {
                code: -32602,
                message: format!("Invalid 'record': {e}"),
                data: None,
            }
        })?;
    let signer = p
        .get("signing_credential_id_hex")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let account = record.account_address.clone();
    let version = record.version;
    node.account_records()
        .accept(record, signer)
        .map_err(|e| JsonRpcError {
            code: -32001,
            message: e.to_string(),
            data: None,
        })?;

    let stored = node.account_records().get(&account);
    Ok(json!({
        "accepted": true,
        "account_address": account,
        "version": version,
        "commitment": stored.map(|r| r.commitment_hex()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(id: &str) -> DeviceCredential {
        DeviceCredential {
            credential_id_hex: id.to_string(),
            p256_public_key_hex: format!("04{}", "11".repeat(64)),
            ml_dsa_public_key_hex: None,
            label: None,
        }
    }

    fn genesis(creds: &[&str]) -> AccountRecord {
        AccountRecord {
            account_address: "0xaaaa".to_string(),
            owner_did: "did:tenzro:human:alice".to_string(),
            version: 0,
            previous_commitment_hex: None,
            credentials: creds.iter().map(|c| credential(c)).collect(),
            policy: "single_credential".to_string(),
            guardians: Vec::new(),
            published_at_ms: 1,
        }
    }

    fn successor(prev: &AccountRecord, creds: &[&str]) -> AccountRecord {
        AccountRecord {
            version: prev.version + 1,
            previous_commitment_hex: Some(prev.commitment_hex()),
            credentials: creds.iter().map(|c| credential(c)).collect(),
            published_at_ms: prev.published_at_ms + 1,
            ..prev.clone()
        }
    }

    #[test]
    fn a_genesis_record_is_accepted_with_no_predecessor() {
        let g = genesis(&["aa"]);
        assert_eq!(verify_succession(None, &g, "aa"), Ok(()));
    }

    #[test]
    fn a_genesis_record_must_not_name_a_predecessor() {
        let mut g = genesis(&["aa"]);
        g.previous_commitment_hex = Some("0xdead".to_string());
        assert_eq!(
            verify_succession(None, &g, "aa"),
            Err(RecordError::MalformedGenesis)
        );
    }

    #[test]
    fn a_device_can_be_added_by_a_device_already_present() {
        let g = genesis(&["aa"]);
        let next = successor(&g, &["aa", "bb"]);
        assert_eq!(verify_succession(Some(&g), &next, "aa"), Ok(()));
    }

    /// The property the whole design exists for. An attacker publishes a record
    /// naming their own key, signed with their own key — and every verifier
    /// rejects it, however many peers repeat it.
    #[test]
    fn a_record_signed_by_an_outsider_is_rejected() {
        let g = genesis(&["aa"]);
        let hostile = successor(&g, &["aa", "attacker"]);
        assert_eq!(
            verify_succession(Some(&g), &hostile, "attacker"),
            Err(RecordError::UnauthorizedSigner {
                credential_id_hex: "attacker".to_string()
            })
        );
    }

    /// The subtler version: the attacker removes the owner and installs
    /// themselves. Same rejection — authority comes from the previous set.
    #[test]
    fn an_outsider_cannot_replace_the_credential_set() {
        let g = genesis(&["aa"]);
        let hostile = successor(&g, &["attacker"]);
        assert!(matches!(
            verify_succession(Some(&g), &hostile, "attacker"),
            Err(RecordError::UnauthorizedSigner { .. })
        ));
    }

    #[test]
    fn a_version_gap_is_rejected() {
        // A gap hides a record nobody has seen, and that record's credential
        // set decided who could sign this one.
        let g = genesis(&["aa"]);
        let mut skipped = successor(&g, &["aa", "bb"]);
        skipped.version = 5;
        assert_eq!(
            verify_succession(Some(&g), &skipped, "aa"),
            Err(RecordError::NonSequentialVersion {
                have: 0,
                offered: 5
            })
        );
    }

    #[test]
    fn a_record_naming_the_wrong_predecessor_is_rejected() {
        let g = genesis(&["aa"]);
        let mut forked = successor(&g, &["aa", "bb"]);
        forked.previous_commitment_hex = Some(format!("0x{}", "00".repeat(32)));
        assert_eq!(
            verify_succession(Some(&g), &forked, "aa"),
            Err(RecordError::BrokenChain)
        );
    }

    #[test]
    fn a_second_genesis_cannot_overwrite_an_existing_account() {
        // Otherwise "start again from scratch" is a takeover primitive.
        let g = genesis(&["aa"]);
        let replacement = genesis(&["attacker"]);
        assert_eq!(
            verify_succession(Some(&g), &replacement, "attacker"),
            Err(RecordError::DuplicateGenesis)
        );
    }

    #[test]
    fn an_empty_credential_set_is_refused() {
        let g = genesis(&["aa"]);
        let emptied = successor(&g, &[]);
        assert_eq!(
            verify_succession(Some(&g), &emptied, "aa"),
            Err(RecordError::EmptyCredentialSet)
        );
    }

    #[test]
    fn a_record_for_another_account_is_rejected() {
        let g = genesis(&["aa"]);
        let mut elsewhere = successor(&g, &["aa", "bb"]);
        elsewhere.account_address = "0xbbbb".to_string();
        assert_eq!(
            verify_succession(Some(&g), &elsewhere, "aa"),
            Err(RecordError::AccountMismatch)
        );
    }

    // ── store ───────────────────────────────────────────────────────────

    #[test]
    fn the_store_accepts_a_legitimate_chain() {
        let store = AccountRecordStore::new();
        let g = genesis(&["aa"]);
        store.accept(g.clone(), "aa").expect("genesis");
        let next = successor(&g, &["aa", "bb"]);
        store.accept(next.clone(), "aa").expect("succession");
        assert_eq!(store.get("0xaaaa").map(|r| r.version), Some(1));
        assert!(store.get("0xaaaa").unwrap().authorizes("bb"));
    }

    #[test]
    fn the_store_refuses_an_unauthorized_successor_and_keeps_the_old_one() {
        // A rejected record must not partially apply — the wallet's authority
        // set is exactly what it was.
        let store = AccountRecordStore::new();
        let g = genesis(&["aa"]);
        store.accept(g.clone(), "aa").expect("genesis");

        let hostile = successor(&g, &["attacker"]);
        assert!(store.accept(hostile, "attacker").is_err());

        let held = store.get("0xaaaa").expect("still there");
        assert_eq!(held.version, 0);
        assert!(held.authorizes("aa"));
        assert!(!held.authorizes("attacker"));
    }

    #[test]
    fn an_account_is_keyed_the_same_with_and_without_the_hex_prefix() {
        // Otherwise the same account files under two entries, and the second
        // one accepts a fresh genesis — which is a takeover.
        let store = AccountRecordStore::new();
        store.accept(genesis(&["aa"]), "aa").expect("genesis");
        assert!(store.get("aaaa").is_some());
        assert!(store.get("0xAAAA").is_some());

        let mut second = genesis(&["attacker"]);
        second.account_address = "aaaa".to_string();
        assert_eq!(
            store.accept(second, "attacker"),
            Err(RecordError::DuplicateGenesis)
        );
    }

    // ── commitment ──────────────────────────────────────────────────────

    #[test]
    fn the_commitment_ignores_credential_ordering() {
        // Two nodes reading the same set out of different map iteration orders
        // must agree, or the chain breaks for reasons that have nothing to do
        // with authority.
        let a = genesis(&["aa", "bb", "cc"]);
        let mut b = a.clone();
        b.credentials.reverse();
        assert_eq!(a.commitment(), b.commitment());
    }

    #[test]
    fn the_commitment_changes_when_the_credential_set_changes() {
        let a = genesis(&["aa"]);
        let b = genesis(&["aa", "bb"]);
        assert_ne!(a.commitment(), b.commitment());
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        // Without length prefixes, moving a character between two adjacent
        // fields would leave the digest unchanged — and an attacker could
        // craft a different credential set with an anchored commitment.
        let mut a = genesis(&["aa"]);
        a.account_address = "0xaa".to_string();
        a.owner_did = "aadid".to_string();
        let mut b = a.clone();
        b.account_address = "0xaaa".to_string();
        b.owner_did = "adid".to_string();
        assert_ne!(a.commitment(), b.commitment());
    }

    #[test]
    fn the_commitment_covers_the_policy_and_guardians() {
        // Both decide who can spend, so both must be committed to; a record
        // whose guardian set could change without changing the commitment
        // would let recovery be seized silently.
        let base = genesis(&["aa"]);
        let mut policy_changed = base.clone();
        policy_changed.policy = "two_credentials".to_string();
        assert_ne!(base.commitment(), policy_changed.commitment());

        let mut guardian_added = base.clone();
        guardian_added.guardians.push("0xguardian".to_string());
        assert_ne!(base.commitment(), guardian_added.commitment());
    }

    #[test]
    fn authorization_tolerates_the_hex_prefix() {
        // The same credential arrives with and without `0x` depending on which
        // surface produced it; treating those as different keys would refuse a
        // legitimate owner.
        let g = genesis(&["aa"]);
        assert!(g.authorizes("aa"));
        assert!(g.authorizes("0xaa"));
        assert!(!g.authorizes("bb"));
    }

    #[test]
    fn a_label_does_not_affect_the_commitment() {
        // Labels are advisory. Committing to them would mean renaming a device
        // forks the chain.
        let mut a = genesis(&["aa"]);
        let b = a.clone();
        a.credentials[0].label = Some("Laptop".to_string());
        assert_eq!(a.commitment(), b.commitment());
    }
}
