//! Passkey account keystores in consensus state (see
//! [`tenzro_types::keystore`]): the record of each account, the indexes that
//! find an account from any of its passkeys, the rules a
//! [`KeystoreUpdate`] passes, and the one check that lets a passkey act for
//! the account it is linked to.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use tenzro_crypto::composite::{
    ClassicalProof, CompositePublicKey, CompositeSignature, PqPolicy, SignatureContext,
    VerifiedLegs, verify_classical_component_for, verify_composite, verify_composite_for,
};

/// Verify `signature` by `key`, its passkey leg checked against `rp_id`, the
/// relying party a keystore records the passkey under; `None` for a passkey
/// no record pins (a key that is its own account, or the passkey an identity
/// derives from), checked against the relying party its assertion names. No
/// relying party is fixed for the network.
pub fn verify_for_relying_party(
    rp_id: Option<&str>,
    key: &CompositePublicKey,
    context: SignatureContext,
    message: &[u8],
    signature: &CompositeSignature,
    policy: PqPolicy,
) -> tenzro_crypto::Result<VerifiedLegs> {
    match rp_id {
        Some(rp_id) => verify_composite_for(rp_id, key, context, message, signature, policy),
        None => verify_composite(key, context, message, signature, policy),
    }
}
use tenzro_types::device_binding::independent_roots;
use tenzro_types::keystore::{
    KeystoreCredential, KeystoreOp, KeystoreRecord, KeystoreUpdate, MAX_CREDENTIALS,
    PendingRecovery, RecoveryCode, RecoverySigner, RecoveryWait, SPEND_MIN_INDEPENDENT_ROOTS,
    SecondFactorPolicy, credential_index_key, recovery_code_claim, recovery_code_commitment,
    recovery_wait,
};

use crate::error::{Result, VmError};
use crate::native::SYSTEM_ADDRESS;
use crate::traits::VmState;
use crate::types::{Log, StateChange, VmTransaction};

/// Selector of `KeystoreUpdate`.
pub const SELECTOR_KEYSTORE_UPDATE: [u8; 4] = [0x01, 0x00, 0x00, 0xD4];
/// Gas for a keystore change: up to a few P-256 and ML-DSA-65 verifications.
pub const GAS_KEYSTORE_UPDATE: u64 = 120_000;
/// Topic of the log a keystore change emits.
pub const KEYSTORE_UPDATED_TOPIC: &[u8] = b"KeystoreUpdated";

const AD_FLAG_BE: u8 = 0x08;
const AD_FLAG_BS: u8 = 0x10;

/// Refuse unless governance has the recovery factor's status lever enabled.
fn factor_enabled(state: &dyn VmState, key: &str, factor: &str) -> Result<()> {
    crate::native::require_lever_enabled(state, key, factor)
}

fn factor_open(state: &dyn VmState, role: tenzro_types::keystore::RecoveryRole) -> bool {
    crate::native::lever_status(state, crate::governance::recovery_factor_status_key(role))
        == crate::governance::LeverStatus::Enabled
}

fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(msg.into())
}

/// The 20-byte account a ledger address names: a 20-byte address, or a
/// 32-byte account slot whose last 12 bytes are zero.
pub fn account20(address: &[u8]) -> Option<[u8; 20]> {
    let mut out = [0u8; 20];
    match address.len() {
        20 => out.copy_from_slice(address),
        32 if address[20..].iter().all(|b| *b == 0) => out.copy_from_slice(&address[..20]),
        _ => return None,
    }
    Some(out)
}

fn record_key(account: &[u8]) -> Vec<u8> {
    format!("keystore:record:{}", hex::encode(account)).into_bytes()
}

fn credential_key(rp_id: &str, credential_id: &[u8]) -> Vec<u8> {
    format!(
        "keystore:credential:{}",
        hex::encode(credential_index_key(rp_id, credential_id))
    )
    .into_bytes()
}

fn public_key_key(public_key: &[u8]) -> Vec<u8> {
    format!("keystore:key:{}", hex::encode(Sha256::digest(public_key))).into_bytes()
}

/// The governed wait a recovery approved by signers in `roles` serves.
fn governed_recovery_wait(
    state: &dyn VmState,
    roles: &[tenzro_types::keystore::RecoveryRole],
) -> u64 {
    use crate::governance as g;
    let key = match recovery_wait(roles) {
        RecoveryWait::KeyAndEmail => g::KEYSTORE_RECOVERY_WAIT_KEY_AND_EMAIL_PARAM,
        RecoveryWait::Key => g::KEYSTORE_RECOVERY_WAIT_KEY_PARAM,
        RecoveryWait::Other => g::KEYSTORE_RECOVERY_WAIT_OTHER_PARAM,
    };
    crate::native::network_param(state, key)
}

fn claim_key(account: &[u8], claim: &[u8]) -> Vec<u8> {
    format!(
        "keystore:code-claim:{}:{}",
        hex::encode(account),
        hex::encode(claim)
    )
    .into_bytes()
}

fn did_key(did: &str) -> Vec<u8> {
    format!("keystore:did:{did}").into_bytes()
}

fn read_accounts(state: &dyn VmState, key: &[u8]) -> Vec<String> {
    state
        .get_storage(&SYSTEM_ADDRESS, key)
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn put(state: &mut dyn VmState, key: Vec<u8>, value: Vec<u8>, changes: &mut Vec<StateChange>) {
    let old = state.get_storage(&SYSTEM_ADDRESS, &key);
    state.set_storage(&SYSTEM_ADDRESS, &key, value.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key,
        old,
        Some(value),
    ));
}

fn edit_accounts(
    state: &mut dyn VmState,
    key: Vec<u8>,
    account: &str,
    add: bool,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut accounts = read_accounts(state, &key);
    let had = accounts.iter().any(|a| a == account);
    match (add, had) {
        (true, false) => accounts.push(account.to_string()),
        (false, true) => accounts.retain(|a| a != account),
        _ => return Ok(()),
    }
    accounts.sort();
    let value = if accounts.is_empty() {
        Vec::new()
    } else {
        serde_json::to_vec(&accounts)
            .map_err(|e| VmError::Internal(format!("encode keystore index: {e}")))?
    };
    put(state, key, value, changes);
    Ok(())
}

/// The keystore of `account` (20 bytes) as chain state holds it. `None`
/// before the account's first change: its record is then the genesis
/// record of its first passkey.
pub fn read_record(state: &dyn VmState, account: &[u8]) -> Option<KeystoreRecord> {
    state
        .get_storage(&SYSTEM_ADDRESS, &record_key(account))
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// The accounts (20-byte hex) the passkey with credential id
/// `credential_id`, registered on the relying party `rp_id`, is linked to.
pub fn resolve_credential(state: &dyn VmState, rp_id: &str, credential_id: &[u8]) -> Vec<String> {
    read_accounts(state, &credential_key(rp_id, credential_id))
}

/// The accounts (20-byte hex) the passkey with P-256 key `public_key` is
/// linked to.
pub fn accounts_of_key(state: &dyn VmState, public_key: &[u8]) -> Vec<String> {
    read_accounts(state, &public_key_key(public_key))
}

/// The accounts (20-byte hex) owned by `did` that have a keystore on chain.
pub fn accounts_of_did(state: &dyn VmState, did: &str) -> Vec<String> {
    read_accounts(state, &did_key(did))
}

/// Store `next` as the keystore of its account, replacing `previous`, and
/// keep the indexes in step.
pub fn write_record(
    state: &mut dyn VmState,
    previous: Option<&KeystoreRecord>,
    next: &KeystoreRecord,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let account = hex::encode(&next.account);
    let body =
        serde_json::to_vec(next).map_err(|e| VmError::Internal(format!("encode keystore: {e}")))?;
    put(state, record_key(&next.account), body, changes);
    let before: Vec<&KeystoreCredential> = previous
        .map(|p| p.credentials.iter().collect())
        .unwrap_or_default();
    for gone in before
        .iter()
        .filter(|c| next.credential_by_id(&c.credential_id).is_none())
    {
        edit_accounts(
            state,
            credential_key(&gone.rp_id, &gone.credential_id),
            &account,
            false,
            changes,
        )?;
        edit_accounts(
            state,
            public_key_key(&gone.public_key),
            &account,
            false,
            changes,
        )?;
    }
    for c in &next.credentials {
        edit_accounts(
            state,
            credential_key(&c.rp_id, &c.credential_id),
            &account,
            true,
            changes,
        )?;
        edit_accounts(
            state,
            public_key_key(&c.public_key),
            &account,
            true,
            changes,
        )?;
    }
    edit_accounts(state, did_key(&next.owner_did), &account, true, changes)
}

/// Whether `signature` is a user-verified WebAuthn assertion, made for the
/// relying party `rp_id`, by the passkey `public_key` over `digest` for
/// `context`, with its ML-DSA-65 leg once one is enrolled for that key, or
/// always under [`PqPolicy::Required`] (an account that requires the leg).
pub fn passkey_signed(
    state: &dyn VmState,
    rp_id: &str,
    public_key: &[u8],
    context: SignatureContext,
    digest: &[u8],
    signature: &CompositeSignature,
    policy: PqPolicy,
) -> bool {
    if !matches!(signature.classical, ClassicalProof::WebAuthn { .. }) {
        return false;
    }
    let Ok(key) = CompositePublicKey::new(
        public_key.to_vec(),
        crate::account_keys::enrolled_pq_key(state, public_key),
    ) else {
        return false;
    };
    verify_composite_for(rp_id, &key, context, digest, signature, policy).is_ok()
}

/// Whether `signature` is the recovery signer's approval of `digest`. A
/// signer recorded as device-bound may not present an assertion whose BE
/// flag is set: it would then be reachable through a sync provider.
fn recovery_signed(
    state: &dyn VmState,
    signer: &RecoverySigner,
    digest: &[u8],
    signature: &CompositeSignature,
    policy: PqPolicy,
) -> bool {
    let Ok(key) = CompositePublicKey::new(
        signer.public_key.clone(),
        crate::account_keys::enrolled_pq_key(state, &signer.public_key),
    ) else {
        return false;
    };
    match &signature.classical {
        ClassicalProof::WebAuthn {
            authenticator_data, ..
        } => {
            if signer.rp_id.is_empty()
                || (!signer.backup_eligible
                    && authenticator_data
                        .get(32)
                        .is_none_or(|f| f & AD_FLAG_BE != 0))
            {
                return false;
            }
            verify_composite_for(
                &signer.rp_id,
                &key,
                SignatureContext::RecoveryApproval,
                digest,
                signature,
                policy,
            )
            .is_ok()
        }
        ClassicalProof::Raw { .. } => verify_composite(
            &key,
            SignatureContext::RecoveryApproval,
            digest,
            signature,
            policy,
        )
        .is_ok(),
    }
}

/// Refuse a change made for another chain: its approvals sign its chain id,
/// so one approved on one chain cannot be replayed on another.
fn check_chain(update: &KeystoreUpdate, chain_id: u64) -> Result<()> {
    if update.chain_id != chain_id {
        return Err(refuse(format!(
            "the keystore change is for chain {}, not this chain {chain_id}",
            update.chain_id
        )));
    }
    Ok(())
}

fn keystore_update_of(tx: &VmTransaction) -> Option<KeystoreUpdate> {
    if tx.data.len() < 4 || tx.data[..4] != SELECTOR_KEYSTORE_UPDATE {
        return None;
    }
    serde_json::from_slice(&tx.data[4..]).ok()
}

/// The record a change to `account` starts from: the one on chain, or for
/// an account with none, the genesis record of the update's anchor, which
/// must derive the account.
fn current_record(
    state: &dyn VmState,
    account: &[u8],
    update: Option<&KeystoreUpdate>,
) -> Result<KeystoreRecord> {
    if let Some(record) = read_record(state, account) {
        if update.is_some_and(|u| u.anchor.is_some()) {
            return Err(refuse(
                "the account already has a keystore on chain; only its first change names an anchor",
            ));
        }
        return Ok(record);
    }
    let anchor = update.and_then(|u| u.anchor.as_ref()).ok_or_else(|| {
        refuse("the account has no keystore on chain; its first change names its first passkey")
    })?;
    let genesis = KeystoreRecord::genesis(anchor);
    if genesis.account != account {
        return Err(refuse("the anchor's passkey does not derive the account"));
    }
    Ok(genesis)
}

/// Check that the passkey `public_key` may act alone for `record`'s account
/// at `now_ms`: it is linked, the account lets one passkey act, and the
/// account holds [`SPEND_MIN_INDEPENDENT_ROOTS`] independent roots.
fn check_acting_passkey<'a>(
    record: &'a KeystoreRecord,
    public_key: &[u8],
    now_ms: u64,
) -> Result<&'a KeystoreCredential> {
    let Some(credential) = record.credential_by_key(public_key) else {
        return Err(refuse("the signing key is not a passkey of the account"));
    };
    if record.policy == SecondFactorPolicy::TwoCredentials {
        return Err(refuse(
            "the account needs two passkeys to act; one passkey alone cannot act for it",
        ));
    }
    if !record.may_spend(now_ms) {
        return Err(refuse(format!(
            "the account must hold {SPEND_MIN_INDEPENDENT_ROOTS} independent passkeys before they can spend from it \
             (it holds {}); link a device from another provider or a security key",
            record.independent_roots_at(now_ms)
        )));
    }
    Ok(credential)
}

/// The keys `public_key` signs with for `account` at `now_ms`, and the
/// relying party a passkey assertion by it must be for: none fixed for the
/// account its P-256 key names (see [`verify_for_relying_party`]), or, for a
/// passkey account whose
/// keystore links it and lets it act (see [`check_acting_passkey`]; the
/// relying party the keystore records for it). The ML-DSA-65 key is the one
/// enrolled for that P-256 key.
pub fn account_signing_key(
    state: &dyn VmState,
    public_key: &[u8],
    account: &[u8],
    now_ms: u64,
) -> Result<(CompositePublicKey, Option<String>)> {
    let rp_id = if tenzro_crypto::controls_account(public_key, account) {
        None
    } else {
        let account =
            account20(account).ok_or_else(|| refuse("the key does not name the account"))?;
        let record = read_record(state, &account).ok_or_else(|| {
            refuse("the key does not name the account, and no keystore on chain links it")
        })?;
        Some(
            check_acting_passkey(&record, public_key, now_ms)?
                .rp_id
                .clone(),
        )
    };
    let key = CompositePublicKey::new(
        public_key.to_vec(),
        crate::account_keys::enrolled_pq_key(state, public_key),
    )
    .map_err(|e| refuse(format!("account key: {e}")))?;
    // Once the account requires the ML-DSA-65 leg, a key without one acts
    // for nothing; a key with one is held to it by its enrollment.
    if key.pq.is_none() && crate::account_keys::pq_required(state, account) {
        return Err(refuse(
            "the account requires the ML-DSA-65 leg, and the key has no ML-DSA-65 key enrolled",
        ));
    }
    Ok((key, rp_id))
}

/// Authorize a transaction whose signing key does not name its sender: the
/// key must be a passkey of the sender's keystore that may act alone (see
/// [`check_acting_passkey`]). A keystore change of the account itself is
/// judged by its own rules instead: any of its passkeys may send it, and so
/// may the passkey a recovery is adding, so a recovery is paid from the
/// account's own balance.
pub fn authorize_sender(state: &dyn VmState, tx: &VmTransaction, now_ms: u64) -> Result<()> {
    authorize_signer(
        state,
        &tx.from,
        tx.public_key.as_deref().unwrap_or_default(),
        tx.signature.as_ref(),
        tx.signing_digest.as_deref().unwrap_or_default(),
        keystore_update_of(tx).as_ref(),
        tx.chain_id,
        now_ms,
    )
}

/// [`authorize_sender`] from a transaction's parts: its sender, signing key,
/// signature and the digest it signs, the keystore change it carries, if it
/// is one, and the chain it is sent on. The passkey's assertion is verified
/// here, for the relying party the keystore records for it.
#[allow(clippy::too_many_arguments)]
pub fn authorize_signer(
    state: &dyn VmState,
    from: &[u8],
    public_key: &[u8],
    signature: Option<&CompositeSignature>,
    digest: &[u8],
    update: Option<&KeystoreUpdate>,
    chain_id: u64,
    now_ms: u64,
) -> Result<()> {
    let account = account20(from)
        .ok_or_else(|| refuse("the signing key does not name the sender account"))?;
    let update = update.filter(|u| u.account == account);
    if let Some(update) = update {
        check_chain(update, chain_id)?;
    }
    let record = current_record(state, &account, update).map_err(|_| {
        refuse("the signing key does not name the sender account, and no keystore links it")
    })?;
    let Some(signature) =
        signature.filter(|s| matches!(s.classical, ClassicalProof::WebAuthn { .. }))
    else {
        return Err(refuse(
            "a passkey account's transactions carry the passkey's WebAuthn assertion",
        ));
    };
    let credential = if let Some(update) = update {
        // A recovery is sent by the account itself, paid from its own
        // balance, signed by the passkey that is joining it: an account that
        // lost every passkey needs no other account to recover.
        let joining = match &update.op {
            KeystoreOp::StartRecovery { credential } => Some(credential),
            KeystoreOp::FinishRecovery => record.pending_recovery.as_ref().map(|p| &p.credential),
            KeystoreOp::RecoverWithCode { credential, .. } => Some(credential),
            _ => None,
        };
        match record.credential_by_key(public_key) {
            Some(credential) => credential,
            None => {
                let credential =
                    joining
                        .filter(|c| c.public_key == public_key)
                        .ok_or_else(|| {
                            refuse("the signing key is not a passkey of the sender account")
                        })?;
                // The account pays for its recovery, so only a recovery
                // that carries its authority may charge it: otherwise anyone
                // could name a passkey of their own and spend the account's
                // balance and nonces on refused recoveries.
                recovery_carries_authority(state, &record, update, now_ms)?;
                credential
            }
        }
    } else {
        check_acting_passkey(&record, public_key, now_ms)?
    };
    verify_classical_component_for(
        &credential.rp_id,
        public_key,
        SignatureContext::Transaction,
        digest,
        &signature.classical,
    )
    .map_err(|e| refuse(format!("the passkey's signature does not verify: {e}")))
}

/// Whether a recovery the joining passkey sends from the account carries
/// the authority to start or finish: for a start, at least one recovery
/// signer's approval that verifies; for a reveal, the account's code and a
/// claim binding it to that passkey that is old enough and not expired; for
/// a finish, a pending recovery whose wait has passed.
fn recovery_carries_authority(
    state: &dyn VmState,
    record: &KeystoreRecord,
    update: &KeystoreUpdate,
    now_ms: u64,
) -> Result<()> {
    let digest = update.digest();
    match &update.op {
        KeystoreOp::StartRecovery { .. } => {
            let approved = update.approvals.iter().any(|a| {
                record
                    .recovery_signers
                    .iter()
                    .find(|s| s.public_key == a.public_key)
                    .is_some_and(|s| {
                        recovery_signed(
                            state,
                            s,
                            &digest,
                            &a.signature,
                            crate::account_keys::account_pq_policy(state, &update.account),
                        )
                    })
            });
            if record.pending_recovery.is_some() || !approved {
                return Err(refuse(
                    "a recovery sent by its joining passkey needs a recovery signer's approval",
                ));
            }
        }
        KeystoreOp::RecoverWithCode { code, credential } => {
            let matches = record.recovery_code.as_ref().is_some_and(|held| {
                held.commitment.as_slice()
                    == recovery_code_commitment(update.chain_id, &update.account, code)
            });
            let claimed_at = state
                .get_storage(
                    &SYSTEM_ADDRESS,
                    &claim_key(
                        &update.account,
                        &recovery_code_claim(update.chain_id, &update.account, code, credential),
                    ),
                )
                .filter(|v| v.len() == 8)
                .map(|v| u64::from_be_bytes(v.as_slice().try_into().expect("8 bytes")));
            let param = |k: &str| crate::native::network_param(state, k);
            let ripe = claimed_at.is_some_and(|at| {
                let age = now_ms.saturating_sub(at);
                age >= param(crate::governance::KEYSTORE_RECOVERY_CODE_REVEAL_DELAY_PARAM)
                    && age <= param(crate::governance::KEYSTORE_RECOVERY_CODE_CLAIM_TTL_PARAM)
            });
            if record.pending_recovery.is_some() || !matches || !ripe {
                return Err(refuse(
                    "a recovery code reveal needs the account's code and a ripe claim for this passkey",
                ));
            }
        }
        KeystoreOp::FinishRecovery => {
            if !record
                .pending_recovery
                .as_ref()
                .is_some_and(|p| now_ms >= p.ready_at_ms)
            {
                return Err(refuse("no recovery is ready to complete"));
            }
        }
        _ => {
            return Err(refuse(
                "the signing key is not a passkey of the sender account",
            ));
        }
    }
    Ok(())
}

/// Check that the passkey `public_key` may approve as the human root
/// `controller_did`, and return the relying party its assertion must be for.
/// Before the identity has a keystore on chain, only the passkey its DID
/// derives from may, on whichever relying party it was registered on
/// (`None`); afterwards, any passkey
/// linked to one of its wallets, on the relying party the keystore records
/// for it, as long as that wallet lets one passkey act alone and the passkey
/// counts as a root at `now_ms` (a passkey inside its add-device wait
/// approves nothing).
pub fn check_passkey_root(
    state: &dyn VmState,
    controller_did: &str,
    public_key: &[u8],
    now_ms: u64,
) -> std::result::Result<Option<String>, String> {
    let wallets = accounts_of_did(state, controller_did);
    if wallets.is_empty() {
        return if tenzro_types::did_derivation::did_derives_from_key(controller_did, public_key) {
            Ok(None)
        } else {
            Err(
                "the approval must come from the passkey the controller's identity derives from"
                    .to_string(),
            )
        };
    }
    let mut two_passkey_wallet = false;
    let mut waiting = false;
    for account in accounts_of_key(state, public_key) {
        if !wallets.contains(&account) {
            continue;
        }
        let Some(record) = hex::decode(&account)
            .ok()
            .and_then(|a| read_record(state, &a))
        else {
            continue;
        };
        if record.owner_did != controller_did {
            continue;
        }
        let Some(credential) = record.credential_by_key(public_key) else {
            continue;
        };
        if !credential.counts_at(now_ms) {
            waiting = true;
            continue;
        }
        if record.policy == SecondFactorPolicy::TwoCredentials {
            two_passkey_wallet = true;
            continue;
        }
        return Ok(Some(credential.rp_id.clone()));
    }
    Err(if waiting {
        "the passkey is still inside its add-device wait and approves nothing yet".to_string()
    } else if two_passkey_wallet {
        "the controller's wallet needs two passkeys to act; one passkey alone cannot approve"
            .to_string()
    } else {
        "the approval must come from a passkey linked to the controller's wallet".to_string()
    })
}

/// Apply a [`KeystoreUpdate`] sent in `tx` at block time `now_ms`.
pub fn apply(
    state: &mut dyn VmState,
    tx: &VmTransaction,
    update: &KeystoreUpdate,
    now_ms: u64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    update.validate().map_err(refuse)?;
    check_chain(update, tx.chain_id)?;
    let on_chain = read_record(state, &update.account);
    let current = current_record(state, &update.account, Some(update))?;
    if update.previous_commitment != current.commitment() {
        return Err(refuse(
            "the change names another version of the account's keystore",
        ));
    }
    let digest = update.digest();

    // A claim on the recovery code is kept apart from the record, so it
    // never moves the record's commitment under approvals in flight. It is
    // paid by another account: the locked account pays nothing for claims
    // nobody proved a right to make.
    if let KeystoreOp::ClaimRecoveryCode { claim } = &update.op {
        if account20(&tx.from).is_some_and(|a| a.as_slice() == update.account.as_slice()) {
            return Err(refuse(
                "a recovery code claim is sent and paid by another account",
            ));
        }
        if current.recovery_code.is_none() {
            return Err(refuse("the account has no recovery code"));
        }
        factor_enabled(
            &*state,
            crate::governance::RECOVERY_CODE_STATUS,
            "recovery by code",
        )?;
        let key = claim_key(&update.account, claim);
        if state
            .get_storage(&SYSTEM_ADDRESS, &key)
            .is_some_and(|v| !v.is_empty())
        {
            return Err(refuse("that claim is already made"));
        }
        let mut changes = Vec::new();
        put(state, key, now_ms.to_be_bytes().to_vec(), &mut changes);
        return Ok((changes, Vec::new()));
    }

    // Passkeys of the account that approved: each approval, and the
    // transaction's own signer when the account sends it. A passkey still
    // inside its add-device wait approves nothing: until it counts, the
    // passkeys that do count can remove it, and it cannot remove them first
    // or change the account's recovery.
    let mut signers: BTreeSet<Vec<u8>> = BTreeSet::new();
    let counting = |key: &[u8]| {
        current
            .credential_by_key(key)
            .filter(|c| c.counts_at(now_ms))
    };
    if tx.signing_digest.is_some()
        && account20(&tx.from).is_some_and(|a| a.as_slice() == update.account.as_slice())
        && let Some(key) = tx.public_key.as_deref()
        && counting(key).is_some()
    {
        signers.insert(key.to_vec());
    }
    for a in &update.approvals {
        if let Some(credential) = counting(&a.public_key)
            && passkey_signed(
                state,
                &credential.rp_id,
                &a.public_key,
                SignatureContext::AccountOwner,
                &digest,
                &a.signature,
                crate::account_keys::account_pq_policy(&*state, &update.account),
            )
        {
            signers.insert(a.public_key.clone());
        }
    }
    let required = current.policy.required_signatures();
    let need = |n: usize, what: &str| -> Result<()> {
        if signers.len() >= n {
            Ok(())
        } else {
            Err(refuse(format!(
                "{what} needs the approval of {n} of the account's passkeys"
            )))
        }
    };

    if let Some(new) = update.op.new_credential() {
        if current.credential_by_id(&new.credential_id).is_some()
            || current.credential_by_key(&new.public_key).is_some()
        {
            return Err(refuse("that passkey is already linked to the account"));
        }
        let possession = update
            .possession
            .as_ref()
            .ok_or_else(|| refuse("adding a passkey needs its proof of possession"))?;
        let ClassicalProof::WebAuthn {
            authenticator_data, ..
        } = &possession.classical
        else {
            return Err(refuse(
                "the new passkey proves possession with a WebAuthn assertion",
            ));
        };
        let flags = *authenticator_data
            .get(32)
            .ok_or_else(|| refuse("the assertion carries no flags"))?;
        if (flags & AD_FLAG_BE != 0) != new.backup_eligible
            || (flags & AD_FLAG_BS != 0) != new.backup_state
        {
            return Err(refuse(
                "the new passkey's signed assertion disagrees with its backup flags",
            ));
        }
        if !passkey_signed(
            state,
            &new.rp_id,
            &new.public_key,
            SignatureContext::AccountOwner,
            &digest,
            possession,
            crate::account_keys::account_pq_policy(&*state, &update.account),
        ) {
            return Err(refuse(
                "the new passkey's proof of possession does not verify",
            ));
        }
    }

    let mut next = current.clone();
    next.version = current.version + 1;
    match &update.op {
        KeystoreOp::AddCredential { credential } => {
            need(required, "linking a passkey")?;
            if current.credentials.len() >= MAX_CREDENTIALS {
                return Err(refuse(format!(
                    "an account links at most {MAX_CREDENTIALS} passkeys"
                )));
            }
            let mut added = credential.clone();
            added.added_at_ms = now_ms;
            added.counts_as_root_from_ms =
                if current.independent_roots_at(now_ms) >= SPEND_MIN_INDEPENDENT_ROOTS {
                    0
                } else {
                    now_ms.saturating_add(crate::native::network_param(
                        &*state,
                        crate::governance::KEYSTORE_ADD_DEVICE_WAIT_PARAM,
                    ))
                };
            next.credentials.push(added);
        }
        KeystoreOp::RemoveCredential { credential_id } => {
            let target = current
                .credential_by_id(credential_id)
                .ok_or_else(|| refuse("that passkey is not linked to the account"))?;
            // A passkey still waiting to count is cancelled by any one other.
            let waiting = !target.counts_at(now_ms);
            need(if waiting { 1 } else { required }, "unlinking a passkey")?;
            if current.credentials.len() == 1 {
                return Err(refuse("the account's last passkey cannot be unlinked"));
            }
            next.credentials
                .retain(|c| c.credential_id != *credential_id);
            if next.credentials.len() < next.policy.required_signatures() {
                next.policy = SecondFactorPolicy::SingleCredential;
            }
        }
        KeystoreOp::SetPolicy { policy } => {
            need(
                required.max(policy.required_signatures()),
                "changing the policy",
            )?;
            if current.credentials.len() < policy.required_signatures() {
                return Err(refuse("the two-passkey policy needs two linked passkeys"));
            }
            next.policy = *policy;
        }
        KeystoreOp::SetRecovery {
            signers: members,
            threshold,
        } => {
            need(required, "changing the recovery signers")?;
            for m in members {
                if !factor_open(&*state, m.role) {
                    factor_enabled(
                        &*state,
                        crate::governance::recovery_factor_status_key(m.role),
                        "this kind of recovery signer",
                    )?;
                }
            }
            let keys: BTreeSet<&Vec<u8>> = members.iter().map(|m| &m.public_key).collect();
            if keys.len() != members.len() {
                return Err(refuse("the same key cannot be two recovery signers"));
            }
            let roots = independent_roots(members);
            if *threshold as usize > roots {
                return Err(refuse(format!(
                    "a threshold of {threshold} needs that many independent recovery signers; these are {roots}"
                )));
            }
            next.recovery_signers = members.clone();
            next.recovery_threshold = *threshold;
        }
        KeystoreOp::StartRecovery { credential } => {
            if current.recovery_threshold == 0 {
                return Err(refuse("the account has no recovery signers"));
            }
            if current.pending_recovery.is_some() {
                return Err(refuse(
                    "a recovery is already pending; cancel or complete it first",
                ));
            }
            let mut approvers: BTreeSet<u32> = BTreeSet::new();
            for a in &update.approvals {
                if let Some((i, signer)) = current
                    .recovery_signers
                    .iter()
                    .enumerate()
                    .find(|(_, s)| s.public_key == a.public_key)
                    && factor_open(&*state, signer.role)
                    && recovery_signed(
                        state,
                        signer,
                        &digest,
                        &a.signature,
                        crate::account_keys::account_pq_policy(&*state, &update.account),
                    )
                {
                    approvers.insert(i as u32);
                }
            }
            let approving: Vec<&RecoverySigner> = approvers
                .iter()
                .map(|i| &current.recovery_signers[*i as usize])
                .collect();
            let roots = independent_roots(&approving);
            if roots < current.recovery_threshold as usize {
                return Err(refuse(format!(
                    "recovery needs {} independent recovery signers; {roots} approved",
                    current.recovery_threshold
                )));
            }
            let roles: Vec<_> = approving.iter().map(|s| s.role).collect();
            let mut joining = credential.clone();
            joining.counts_as_root_from_ms = 0;
            joining.added_at_ms = 0;
            next.pending_recovery = Some(PendingRecovery {
                credential: joining,
                approvers: approvers.into_iter().collect(),
                started_at_ms: now_ms,
                ready_at_ms: now_ms.saturating_add(governed_recovery_wait(&*state, &roles)),
            });
        }
        KeystoreOp::SetRecoveryCode { commitment } => {
            need(required, "setting the recovery code")?;
            if commitment.is_some() {
                factor_enabled(
                    &*state,
                    crate::governance::RECOVERY_CODE_STATUS,
                    "recovery by code",
                )?;
            }
            next.recovery_code = commitment.as_ref().map(|c| RecoveryCode {
                commitment: c.0.clone(),
            });
        }
        KeystoreOp::ClaimRecoveryCode { .. } => unreachable!("handled above"),
        KeystoreOp::RecoverWithCode { code, credential } => {
            factor_enabled(
                &*state,
                crate::governance::RECOVERY_CODE_STATUS,
                "recovery by code",
            )?;
            let held = current
                .recovery_code
                .as_ref()
                .ok_or_else(|| refuse("the account has no recovery code"))?;
            if held.commitment.as_slice()
                != recovery_code_commitment(update.chain_id, &update.account, code)
            {
                return Err(refuse("the recovery code does not match"));
            }
            if current.pending_recovery.is_some() {
                return Err(refuse(
                    "a recovery is already pending; cancel or complete it first",
                ));
            }
            let key = claim_key(
                &update.account,
                &recovery_code_claim(update.chain_id, &update.account, code, credential),
            );
            let claimed_at = state
                .get_storage(&SYSTEM_ADDRESS, &key)
                .filter(|v| v.len() == 8)
                .map(|v| u64::from_be_bytes(v.as_slice().try_into().expect("8 bytes")))
                .ok_or_else(|| refuse("no claim binds this code to this passkey"))?;
            let param = |k: &str| crate::native::network_param(&*state, k);
            let age = now_ms.saturating_sub(claimed_at);
            if age < param(crate::governance::KEYSTORE_RECOVERY_CODE_REVEAL_DELAY_PARAM) {
                return Err(refuse("the claim is too recent to reveal its code"));
            }
            if age > param(crate::governance::KEYSTORE_RECOVERY_CODE_CLAIM_TTL_PARAM) {
                return Err(refuse("the claim has expired; claim again"));
            }
            let wait = param(crate::governance::KEYSTORE_RECOVERY_CODE_WAIT_PARAM);
            let mut joining = credential.clone();
            joining.counts_as_root_from_ms = 0;
            joining.added_at_ms = 0;
            next.pending_recovery = Some(PendingRecovery {
                credential: joining,
                approvers: Vec::new(),
                started_at_ms: now_ms,
                ready_at_ms: now_ms.saturating_add(wait),
            });
            // The code works once; the account sets a new one.
            next.recovery_code = None;
        }
        KeystoreOp::CancelRecovery => {
            need(1, "cancelling a recovery")?;
            if current.pending_recovery.is_none() {
                return Err(refuse("no recovery is pending"));
            }
            next.pending_recovery = None;
        }
        KeystoreOp::FinishRecovery => {
            let pending = current
                .pending_recovery
                .as_ref()
                .ok_or_else(|| refuse("no recovery is pending"))?;
            // A factor governance paused after the recovery started holds it:
            // the pause answers a fault in that factor, and a recovery it
            // approved is what the fault would let through.
            if pending.approvers.is_empty() {
                factor_enabled(
                    &*state,
                    crate::governance::RECOVERY_CODE_STATUS,
                    "recovery by code",
                )?;
            }
            for i in &pending.approvers {
                if let Some(signer) = current.recovery_signers.get(*i as usize)
                    && !factor_open(&*state, signer.role)
                {
                    factor_enabled(
                        &*state,
                        crate::governance::recovery_factor_status_key(signer.role),
                        "a recovery signer that approved this recovery",
                    )?;
                }
            }
            if now_ms < pending.ready_at_ms {
                return Err(refuse(format!(
                    "the recovery completes from {} (block time, ms); any passkey of the account can cancel it until then",
                    pending.ready_at_ms
                )));
            }
            if current
                .credential_by_id(&pending.credential.credential_id)
                .is_none()
                && current
                    .credential_by_key(&pending.credential.public_key)
                    .is_none()
            {
                if current.credentials.len() >= MAX_CREDENTIALS {
                    return Err(refuse(format!(
                        "an account links at most {MAX_CREDENTIALS} passkeys"
                    )));
                }
                let mut joined = pending.credential.clone();
                joined.added_at_ms = now_ms;
                next.credentials.push(joined);
            }
            next.pending_recovery = None;
        }
    }
    // The passkey an account derives from joins the chain with its first change.
    if current.version == 0 {
        for c in next.credentials.iter_mut().filter(|c| c.added_at_ms == 0) {
            c.added_at_ms = now_ms;
        }
    }
    next.credentials
        .sort_by(|a, b| a.credential_id.cmp(&b.credential_id));

    let mut changes = Vec::new();
    write_record(state, on_chain.as_ref(), &next, &mut changes)?;
    let data = serde_json::to_vec(&serde_json::json!({
        "account": hex::encode(&next.account),
        "version": next.version,
        "commitment": hex::encode(next.commitment()),
    }))
    .map_err(|e| VmError::Internal(format!("encode keystore log: {e}")))?;
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![KEYSTORE_UPDATED_TOPIC.to_vec(), next.account.clone()],
        data,
    );
    Ok((changes, vec![log]))
}
