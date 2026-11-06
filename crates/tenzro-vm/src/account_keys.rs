//! The keys an account signs with: the P-256 key that names it and the
//! ML-DSA-65 key it has enrolled in chain state.
//!
//! Every verifier in the VM takes the ML-DSA-65 key from state through this
//! module, never from the record it verifies. Once an account has one
//! enrolled, its signatures must carry the ML-DSA-65 leg, so the P-256 key
//! alone cannot spend it.

use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, PqPolicy, SignatureContext, VerifiedLegs, account_slot,
    controls_account, verify_composite, verify_pq_component,
};
use tenzro_types::account_signature::{
    AccountKeysOp, enrolled_pq_key_storage_key, pq_enrollment_message, pq_required_storage_key,
    retired_p256_storage_key,
};

use crate::error::{Result, VmError};
use crate::native::SYSTEM_ADDRESS;
use crate::traits::VmState;
use crate::types::{Log, StateChange, VmTransaction};

/// Governed lever: while enabled, an account that enrolls an ML-DSA-65 key
/// requires from then on the ML-DSA-65 leg of every key acting for it, as
/// [`AccountKeysOp::RequirePqLeg`] does: 0 enabled, 1 paused, 2 retired.
pub const PQ_LEG_ON_ENROLMENT_STATUS: &str = "accounts.ml_dsa_leg_on_enrolment.status";

/// Whether the account named by `p256_xy` has retired its P-256 leg.
pub fn p256_retired(state: &dyn VmState, p256_xy: &[u8]) -> bool {
    let key = retired_p256_storage_key(&account_slot(p256_xy));
    state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .is_some_and(|v| !v.is_empty())
}

/// Record that the account named by `p256_xy` has retired its P-256 leg.
pub fn retire_p256(state: &mut dyn VmState, p256_xy: &[u8], changes: &mut Vec<StateChange>) {
    let key = retired_p256_storage_key(&account_slot(p256_xy));
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), vec![1]);
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(vec![1]),
    ));
}

/// The ML-DSA-65 key the account named by `p256_xy` has enrolled.
pub fn enrolled_pq_key(state: &dyn VmState, p256_xy: &[u8]) -> Option<Vec<u8>> {
    let key = enrolled_pq_key_storage_key(&account_slot(p256_xy));
    state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .filter(|k| !k.is_empty())
}

/// The keys of `account`: `p256_xy` must name it, and the ML-DSA-65 key is
/// the one enrolled in state.
pub fn account_key(
    state: &dyn VmState,
    p256_xy: &[u8],
    account: &[u8],
) -> Result<CompositePublicKey> {
    if !controls_account(p256_xy, account) {
        return Err(VmError::InvalidTransaction(
            "the P-256 key does not name the account".to_string(),
        ));
    }
    CompositePublicKey::new(p256_xy.to_vec(), enrolled_pq_key(state, p256_xy))
        .map_err(|e| VmError::InvalidTransaction(format!("account key: {e}")))
}

/// Verify `sig` by `account` over `message` for `context` against the keys
/// the account has in state.
pub fn verify_account_signature(
    state: &dyn VmState,
    p256_xy: &[u8],
    account: &[u8],
    context: SignatureContext,
    message: &[u8],
    sig: &CompositeSignature,
    policy: PqPolicy,
) -> Result<VerifiedLegs> {
    let key = account_key(state, p256_xy, account)?;
    verify_composite(&key, context, message, sig, policy)
        .map_err(|e| VmError::InvalidTransaction(format!("signature does not verify: {e}")))
}

/// Record `pq_key` as the ML-DSA-65 key of the account named by `p256_xy`.
pub fn set_enrolled_pq_key(
    state: &mut dyn VmState,
    p256_xy: &[u8],
    pq_key: Vec<u8>,
    changes: &mut Vec<StateChange>,
) {
    let key = enrolled_pq_key_storage_key(&account_slot(p256_xy));
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), pq_key.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(pq_key),
    ));
}

/// Selector of `AccountKeys`.
pub const SELECTOR_ACCOUNT_KEYS: [u8; 4] = [0x01, 0x00, 0x00, 0xD3];
/// Gas for an account keys operation: two ML-DSA-65 verifications.
pub const GAS_ACCOUNT_KEYS: u64 = 80_000;
/// Topic of the log a P-256 retirement emits.
pub const P256_RETIRED_TOPIC: &[u8] = b"P256Retired";
/// Topic of the log an enrollment emits.
pub const PQ_KEY_ENROLLED_TOPIC: &[u8] = b"PqKeyEnrolled";
/// Topic of the log requiring the ML-DSA-65 leg emits.
pub const PQ_LEG_REQUIRED_TOPIC: &[u8] = b"PqLegRequired";
/// Topic of the log requiring an agent's serving nodes' ML-DSA leg emits.
pub const AGENT_PQ_LEG_REQUIRED_TOPIC: &[u8] = b"AgentPqLegRequired";

/// Refuse unless the transaction's signing key acts for the sender, has an
/// ML-DSA-65 key enrolled, and signed with both legs.
fn check_both_legs(
    state: &dyn VmState,
    tx: &VmTransaction,
    p256_xy: &[u8],
    sig: &CompositeSignature,
    digest: &[u8],
) -> Result<()> {
    let now_ms = crate::native::deterministic_now_ms(tx).max(0) as u64;
    crate::keystore::account_signing_key(state, p256_xy, &tx.from, now_ms)?;
    let Some(enrolled) = enrolled_pq_key(state, p256_xy) else {
        return Err(VmError::InvalidTransaction(
            "requiring the ML-DSA-65 leg needs an ML-DSA-65 key enrolled for the signing key"
                .to_string(),
        ));
    };
    if !sig.has_classical_leg() {
        return Err(VmError::InvalidTransaction(
            "requiring the ML-DSA-65 leg is signed with both legs".to_string(),
        ));
    }
    verify_pq_component(
        Some(enrolled.as_slice()),
        SignatureContext::Transaction,
        digest,
        sig.pq.as_deref(),
        PqPolicy::Required,
    )
    .map(|_| ())
    .map_err(|e| VmError::InvalidTransaction(format!("signature does not verify: {e}")))
}

fn payload_op(tx: &VmTransaction) -> Option<AccountKeysOp> {
    if tx.data.len() < 4 || tx.data[..4] != SELECTOR_ACCOUNT_KEYS {
        return None;
    }
    serde_json::from_slice(&tx.data[4..]).ok()
}

/// The ML-DSA-65 key the transaction's ML-DSA-65 leg must verify against,
/// and how strictly: the enrolled key; or, for an enrollment by an account
/// with none enrolled yet, the key being enrolled, whose leg is then
/// required.
pub fn tx_pq_key(
    state: &dyn VmState,
    tx: &VmTransaction,
    p256_xy: &[u8],
) -> (Option<Vec<u8>>, PqPolicy) {
    let op = payload_op(tx);
    pq_key_for(state, p256_xy, op.as_ref())
}

/// [`tx_pq_key`] for a transaction whose account keys operation, if it is
/// one, is `op`.
pub fn pq_key_for(
    state: &dyn VmState,
    p256_xy: &[u8],
    op: Option<&AccountKeysOp>,
) -> (Option<Vec<u8>>, PqPolicy) {
    if let Some(enrolled) = enrolled_pq_key(state, p256_xy) {
        return (Some(enrolled), PqPolicy::default());
    }
    match op {
        Some(AccountKeysOp::EnrollPqKey {
            ml_dsa_public_key, ..
        }) => (Some(ml_dsa_public_key.clone()), PqPolicy::default()),
        // No key enrolled: every other operation is refused until the
        // account enrolls one, because the leg is required.
        _ => (None, PqPolicy::default()),
    }
}

/// Apply an [`AccountKeysOp`] sent by `tx.from`.
///
/// An enrollment is signed with both hardware legs: the P-256 key that names
/// the account, and the ML-DSA-65 key that is enrolled, or the one being
/// enrolled when there is none, so replacing a key needs the old one. The new
/// key also proves possession over the account slot. There is no operation
/// that removes a key.
pub fn apply(
    state: &mut dyn VmState,
    tx: &VmTransaction,
    op: &AccountKeysOp,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    op.validate()
        .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
    let (Some(sig), Some(p256_xy), Some(digest)) = (
        tx.signature.as_ref(),
        tx.public_key.as_ref(),
        tx.signing_digest.as_ref(),
    ) else {
        return Err(VmError::InvalidTransaction(
            "an account keys operation must be hardware-signed".to_string(),
        ));
    };
    if !controls_account(p256_xy, &tx.from)
        && !matches!(
            op,
            AccountKeysOp::RequirePqLeg {} | AccountKeysOp::RequireAgentPqLeg { .. }
        )
    {
        return Err(VmError::InvalidTransaction(
            "the P-256 key does not name the account".to_string(),
        ));
    }
    match op {
        AccountKeysOp::EnrollPqKey {
            ml_dsa_public_key,
            possession,
        } => {
            let slot = account_slot(p256_xy);
            verify_pq_component(
                Some(ml_dsa_public_key),
                SignatureContext::PqKeyEnrollment,
                &pq_enrollment_message(&slot, ml_dsa_public_key),
                Some(possession),
                PqPolicy::Required,
            )
            .map_err(|e| VmError::InvalidTransaction(format!("proof of possession: {e}")))?;
            let (expected, _) = tx_pq_key(state, tx, p256_xy);
            verify_pq_component(
                expected.as_deref(),
                SignatureContext::Transaction,
                digest,
                sig.pq.as_deref(),
                PqPolicy::Required,
            )
            .map_err(|e| VmError::InvalidTransaction(format!("signature does not verify: {e}")))?;
            let mut changes = Vec::new();
            set_enrolled_pq_key(state, p256_xy, ml_dsa_public_key.clone(), &mut changes);
            let mut logs = vec![Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![PQ_KEY_ENROLLED_TOPIC.to_vec(), slot.to_vec()],
                ml_dsa_public_key.clone(),
            )];
            if crate::native::lever_status(state, PQ_LEG_ON_ENROLMENT_STATUS)
                == crate::governance::LeverStatus::Enabled
            {
                let account = crate::keystore::account20(&tx.from).ok_or_else(|| {
                    VmError::InvalidTransaction("the sender is not a 20-byte account".to_string())
                })?;
                set_pq_required(state, &account, &mut changes);
                logs.push(Log::new(
                    SYSTEM_ADDRESS.to_vec(),
                    vec![PQ_LEG_REQUIRED_TOPIC.to_vec(), account.to_vec()],
                    Vec::new(),
                ));
            }
            Ok((changes, logs))
        }
        AccountKeysOp::RetireP256 {} => {
            let Some(enrolled) = enrolled_pq_key(state, p256_xy) else {
                return Err(VmError::InvalidTransaction(
                    "retiring the P-256 leg needs an enrolled ML-DSA-65 key".to_string(),
                ));
            };
            if !sig.has_classical_leg() {
                return Err(VmError::InvalidTransaction(
                    "retiring the P-256 leg is signed with both legs".to_string(),
                ));
            }
            verify_pq_component(
                Some(enrolled.as_slice()),
                SignatureContext::Transaction,
                digest,
                sig.pq.as_deref(),
                PqPolicy::Required,
            )
            .map_err(|e| VmError::InvalidTransaction(format!("signature does not verify: {e}")))?;
            let mut changes = Vec::new();
            retire_p256(state, p256_xy, &mut changes);
            let log = Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![P256_RETIRED_TOPIC.to_vec(), account_slot(p256_xy).to_vec()],
                Vec::new(),
            );
            Ok((changes, vec![log]))
        }
        AccountKeysOp::RequireAgentPqLeg { agent_did, nodes } => {
            check_both_legs(state, tx, p256_xy, sig, digest)?;
            crate::native::authorize_agent_controller(state, &tx.from, agent_did)?;
            let terms = crate::native::agent_terms::read_agent_terms(state, agent_did)
                .ok_or_else(|| {
                    VmError::InvalidTransaction(format!("{agent_did} has no terms on chain"))
                })?
                .terms;
            let named: std::collections::BTreeSet<&str> =
                nodes.iter().map(|n| n.machine_did.as_str()).collect();
            if terms
                .serving_nodes
                .iter()
                .any(|s| !named.contains(s.machine_did.as_str()))
                || nodes
                    .iter()
                    .any(|n| terms.serving_node(&n.machine_did).is_none())
            {
                return Err(VmError::InvalidTransaction(
                    "the ML-DSA keys must name exactly the serving nodes of the agent's terms"
                        .to_string(),
                ));
            }
            for n in nodes {
                tenzro_crypto::pq::ml_dsa_verify(
                    &n.ml_dsa_public_key,
                    tenzro_types::account_signature::AGENT_NODE_PQ_POSSESSION_CONTEXT,
                    &tenzro_types::account_signature::agent_node_pq_possession_message(
                        agent_did,
                        &n.machine_did,
                        &n.ml_dsa_public_key,
                    ),
                    &n.possession,
                )
                .map_err(|_| {
                    VmError::InvalidTransaction(format!(
                        "{}'s proof of its ML-DSA key does not verify",
                        n.machine_did
                    ))
                })?;
            }
            let keys: Vec<(String, Vec<u8>)> = nodes
                .iter()
                .map(|n| (n.machine_did.clone(), n.ml_dsa_public_key.clone()))
                .collect();
            let mut changes = Vec::new();
            crate::native::agent_terms::require_agent_node_pq_keys(
                state,
                agent_did,
                &keys,
                &mut changes,
            );
            let log = Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![
                    AGENT_PQ_LEG_REQUIRED_TOPIC.to_vec(),
                    agent_did.as_bytes().to_vec(),
                ],
                Vec::new(),
            );
            Ok((changes, vec![log]))
        }
        AccountKeysOp::RequirePqLeg {} => {
            // The signing key names the account, or is a passkey its
            // keystore lets act for it.
            let now_ms = crate::native::deterministic_now_ms(tx).max(0) as u64;
            crate::keystore::account_signing_key(state, p256_xy, &tx.from, now_ms)?;
            let Some(enrolled) = enrolled_pq_key(state, p256_xy) else {
                return Err(VmError::InvalidTransaction(
                    "requiring the ML-DSA-65 leg needs an ML-DSA-65 key enrolled for the signing key"
                        .to_string(),
                ));
            };
            if !sig.has_classical_leg() {
                return Err(VmError::InvalidTransaction(
                    "requiring the ML-DSA-65 leg is signed with both legs".to_string(),
                ));
            }
            verify_pq_component(
                Some(enrolled.as_slice()),
                SignatureContext::Transaction,
                digest,
                sig.pq.as_deref(),
                PqPolicy::Required,
            )
            .map_err(|e| VmError::InvalidTransaction(format!("signature does not verify: {e}")))?;
            let account = crate::keystore::account20(&tx.from).ok_or_else(|| {
                VmError::InvalidTransaction("the sender is not a 20-byte account".to_string())
            })?;
            let mut changes = Vec::new();
            set_pq_required(state, &account, &mut changes);
            let log = Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![PQ_LEG_REQUIRED_TOPIC.to_vec(), account.to_vec()],
                Vec::new(),
            );
            Ok((changes, vec![log]))
        }
    }
}

/// Record that `account` requires the ML-DSA-65 leg of every key acting
/// for it.
pub fn set_pq_required(
    state: &mut dyn VmState,
    account: &[u8; 20],
    changes: &mut Vec<StateChange>,
) {
    let key = pq_required_storage_key(account);
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), vec![1]);
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(vec![1]),
    ));
}

/// Whether `account` requires the ML-DSA-65 leg of every key acting for it
/// (see [`AccountKeysOp::RequirePqLeg`]).
pub fn pq_required(state: &dyn VmState, account: &[u8]) -> bool {
    crate::keystore::account20(account).is_some_and(|a| {
        state
            .get_storage(&SYSTEM_ADDRESS, pq_required_storage_key(&a).as_bytes())
            .is_some_and(|v| !v.is_empty())
    })
}

/// How strictly a signature acting for `account` is held to the ML-DSA-65
/// leg: always [`PqPolicy::Required`]. An account that has not enrolled an
/// ML-DSA-65 key signs nothing until it does, so the first transaction of a
/// new account is its enrolment ([`AccountKeysOp::EnrollPqKey`]).
pub fn account_pq_policy(_state: &dyn VmState, _account: &[u8]) -> PqPolicy {
    PqPolicy::default()
}
