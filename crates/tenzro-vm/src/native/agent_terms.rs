//! Delegated agents' terms in chain state, and the check every agent action
//! passes at execution.
//!
//! `SetAgentTerms` records the terms a root approved; each validator
//! re-verifies the root's signature (a human's passkey or a machine's TPM or
//! Secure Enclave key) over the custody challenge for exactly those terms. `AgentAct` is one action, signed by a serving
//! node's hardware key for the agent; it executes only when the signing node
//! is assigned in the current terms and the action is within them. The
//! daily total is kept here, so every node sees the same running spend.

use serde::{Deserialize, Serialize};
use tenzro_types::agent_terms::{
    ActionHistory, AgentAction, AgentEscrow, AgentTerms, AgentTermsApproval, DAY_MS,
    OP_AGENT_STEP_UP, OP_DELEGATE_AGENT, OP_UPDATE_AGENT_TERMS, RootKind, agent_did, agent_wallet,
    check_action, check_trifecta, custody_challenge_digest,
};
use tenzro_types::transaction::VmCall;

use super::agent_audit::read_agent_quarantine;
use super::funding::{read_json, refuse, write_json};
use super::*;

/// Gas for recording terms.
pub const GAS_SET_AGENT_TERMS: u64 = 60_000;
/// Gas for one agent action.
pub const GAS_AGENT_ACT: u64 = 40_000;
/// Topic of the log recorded terms emit.
pub const AGENT_TERMS_TOPIC: &[u8] = b"AgentTermsSet";
/// Topic of the log an executed agent action emits.
pub const AGENT_ACT_TOPIC: &[u8] = b"AgentAct";

/// An agent's terms as chain state records them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAgentTerms {
    /// The approved terms.
    pub terms: AgentTerms,
    /// What the controller's authority is rooted in.
    pub root: RootKind,
    /// Increments with every approved change.
    pub version: u64,
    /// Digest of the custody challenge the controller approved, hex.
    pub approval_digest: String,
    /// Block time of the change, ms.
    pub updated_at_ms: i64,
    /// Block time the root last approved the terms in full, ms. A scope
    /// change approved within pre-approved bounds keeps it.
    #[serde(default)]
    pub renewed_at_ms: Option<i64>,
}

impl StoredAgentTerms {
    /// When the root last approved the terms in full, ms.
    pub fn renewed_at(&self) -> i64 {
        self.renewed_at_ms.unwrap_or(self.updated_at_ms)
    }
}

/// Governed parameter: how long, in ms, an agent may act after its root last
/// approved its terms in full.
pub const PARAM_MAX_UNRENEWED_MS: &str = "agent.max_unrenewed_ms";
/// Genesis value of [`PARAM_MAX_UNRENEWED_MS`]: 90 days.
pub const DEFAULT_MAX_UNRENEWED_MS: u64 = 90 * DAY_MS;

/// Refuse an agent whose root has not approved its terms in full within
/// [`PARAM_MAX_UNRENEWED_MS`] of `at_ms`, so an agent cannot outlive the
/// root that answers for it.
pub fn check_renewed(
    state: &dyn VmState,
    agent_did: &str,
    stored: &StoredAgentTerms,
    at_ms: u64,
) -> std::result::Result<(), String> {
    let window = network_param(state, PARAM_MAX_UNRENEWED_MS);
    let lapses_at = stored
        .renewed_at()
        .saturating_add(i64::try_from(window).unwrap_or(i64::MAX));
    if i64::try_from(at_ms).unwrap_or(i64::MAX) >= lapses_at {
        return Err(format!(
            "renewal: {agent_did} lapsed at {lapses_at} ms; its root must approve its terms again"
        ));
    }
    Ok(())
}

/// System storage slot of an agent's terms.
pub fn terms_key(agent: &str) -> String {
    format!("agent_terms:{agent}")
}

/// Rolling window of what `agent` spent and did over the last 24 hours.
pub(super) fn spent_day_key(agent: &str) -> String {
    format!("agent_spent_24h:{agent}")
}

/// Marks a root approval of `agent`'s terms as spent.
fn approval_used_key(agent: &str, digest: &[u8; 32]) -> String {
    format!("agent_terms_approval_used:{agent}:{}", hex::encode(digest))
}

fn nonce_key(agent: &str) -> String {
    format!("agent_act_nonce:{agent}")
}

/// Rolling window of what `agent` spent and did over the last 60 minutes.
pub(super) fn spent_hour_key(agent: &str) -> String {
    format!("agent_spent_60m:{agent}")
}

/// Rolling window of what `agent` paid in `asset` over the last 24 hours.
fn asset_spent_key(agent: &str, asset: &str) -> String {
    format!(
        "agent_asset_spent_24h:{agent}:{}",
        asset.to_ascii_lowercase()
    )
}

fn paid_key(agent: &str, counterparty: &str) -> String {
    format!(
        "agent_paid:{agent}:{}",
        counterparty.trim_start_matches("0x").to_ascii_lowercase()
    )
}

/// What `agent_did` has done in the 24 hours and the 60 minutes up to
/// `at_ms` ([`super::rolling`]), and whether it has paid `counterparty`
/// before.
pub fn read_agent_history(
    state: &dyn VmState,
    agent_did: &str,
    counterparty: &str,
    at_ms: u64,
) -> ActionHistory {
    let day = rolling::totals(state, &spent_day_key(agent_did), rolling::DAY, at_ms);
    let hour = rolling::totals(state, &spent_hour_key(agent_did), rolling::HOUR, at_ms);
    ActionHistory {
        known_counterparty: !counterparty.is_empty()
            && read_json::<bool>(state, &paid_key(agent_did, counterparty)).unwrap_or(false),
        spent_today: day.amount,
        spent_this_hour: hour.amount,
        actions_today: day.actions,
        actions_this_hour: hour.actions,
        asset_spent_today: 0,
        ..Default::default()
    }
}

/// [`read_agent_history`] for `action`: with what the agent has paid in the
/// last 24 hours in the action's asset, when that is not TNZO.
fn history_of(state: &dyn VmState, action: &AgentAction, at_ms: u64) -> ActionHistory {
    let mut history = read_agent_history(state, &action.agent_did, &action.counterparty, at_ms);
    if let Some(asset) = &action.asset {
        history.asset_spent_today = read_agent_asset_spent(state, &action.agent_did, asset, at_ms);
    }
    history
}

/// The KYC tiers `action`'s counterparty holds under the registry the
/// terms name and under the asset the action moves, read from the claims
/// made under each token. A counterparty that is not an address holds none.
fn read_counterparty_kyc(
    state: &dyn VmState,
    terms: &tenzro_types::agent_terms::AgentTerms,
    action: &AgentAction,
    history: &mut ActionHistory,
    at_ms: u64,
) {
    let Ok(subject) = hex::decode(action.counterparty.trim_start_matches("0x")) else {
        return;
    };
    if subject.is_empty() {
        return;
    }
    let tier_under = |token: &str| -> u8 {
        let Some(id) = hex::decode(token.trim_start_matches("0x"))
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return 0;
        };
        let Some(record) = crate::token_ledger::read_token(state, &id) else {
            return 0;
        };
        let mut view = crate::token_ledger::StateView(state);
        crate::token_ledger::kyc_tier(&mut view, &id, &record, &subject, at_ms as i64).unwrap_or(0)
    };
    let scope = &terms.delegation_scope;
    if let Some(k) = &scope.counterparty_kyc {
        history.counterparty_kyc_tier = tier_under(&k.registry);
    }
    if let Some(asset) = &action.asset
        && scope
            .asset_limit(asset)
            .is_some_and(|l| l.min_counterparty_kyc_tier != 0)
    {
        history.asset_kyc_tier = tier_under(asset);
    }
}

/// Micro-units of account `amount` of `asset` (TNZO when `None`) counts
/// as against the terms' spend limits, rounded up. TNZO counts at the rate
/// in force. A permitted settlement asset counts at its validator rate,
/// and is refused by name when it may not settle now (disabled, unpriced
/// or off its peg). Any other token counts at the price the action states.
/// A token never counts at less than the stated price, nor at less than its
/// share of the asset's daily limit applied to the terms' daily spend: the
/// price is the proposer's statement, the share the controller's, so a low
/// stated price cannot shrink what the limits count.
pub fn spend_units(
    state: &dyn VmState,
    terms: Option<&AgentTerms>,
    asset: Option<&str>,
    amount: u128,
    usd_e6: u64,
) -> std::result::Result<u128, String> {
    use super::settlement_asset::value_e6_up;
    if amount == 0 {
        return Ok(0);
    }
    let asset = asset.unwrap_or(tenzro_types::payment_authorization::TNZO_ASSET);
    let token = super::payment_settlement::asset_token(state, asset).map_err(|e| e.to_string())?;
    if token == crate::token_ledger::tnzo_id() {
        let rate = super::economy::read_fee_rate(state).rate_nano_usd;
        return Ok(value_e6_up(amount, rate, 18));
    }
    let valued = match super::settlement_asset::read_settlement_asset(state, &token) {
        Some(_) => {
            let p = super::settlement_asset::permitted(state, &token).map_err(|e| e.to_string())?;
            value_e6_up(amount, p.rate_nano_usd, p.asset.decimals)
        }
        None => 0,
    };
    let share = terms.map_or(0, |t| asset_share_of_daily_spend(t, asset, amount));
    Ok(valued.max(u128::from(usd_e6)).max(share))
}

/// The action as the terms' spend limits see it: its amount in micro-units
/// of account ([`spend_units`]).
fn unit_view(
    state: &dyn VmState,
    terms: &AgentTerms,
    action: &AgentAction,
) -> std::result::Result<AgentAction, String> {
    let mut view = action.clone();
    view.amount = spend_units(
        state,
        Some(terms),
        action.asset.as_deref(),
        action.amount,
        action.usd_e6,
    )?;
    Ok(view)
}

/// `amount` of `asset` as the share of the terms' daily spend it uses: the
/// fraction of the asset's daily limit it is, times the daily spend. Zero
/// when the terms set no daily spend or do not list the asset.
fn asset_share_of_daily_spend(terms: &AgentTerms, asset: &str, amount: u128) -> u128 {
    use tenzro_types::agent_terms::parse_amount;
    let s = &terms.delegation_scope;
    let Some(daily) = parse_amount(s.max_daily_spend.as_deref()).ok().flatten() else {
        return 0;
    };
    let Some(per_day) = s
        .asset_limit(asset)
        .and_then(|l| parse_amount(Some(&l.max_per_day)).ok().flatten())
        .filter(|v| *v > 0)
    else {
        return 0;
    };
    amount
        .checked_mul(daily)
        .map_or(u128::MAX, |p| p.div_ceil(per_day))
}

/// The terms chain state holds for `agent_did`.
pub fn read_agent_terms(state: &dyn VmState, agent_did: &str) -> Option<StoredAgentTerms> {
    read_json(state, &terms_key(agent_did))
}

/// What `agent_did` has spent in the 24 hours up to `at_ms`, wei.
pub fn read_agent_spent(state: &dyn VmState, agent_did: &str, at_ms: u64) -> u128 {
    rolling::totals(state, &spent_day_key(agent_did), rolling::DAY, at_ms).amount
}

/// What `agent_did` has paid in `asset` in the 24 hours up to `at_ms`, in
/// the asset's base units.
pub fn read_agent_asset_spent(
    state: &dyn VmState,
    agent_did: &str,
    asset: &str,
    at_ms: u64,
) -> u128 {
    rolling::totals(
        state,
        &asset_spent_key(agent_did, asset),
        rolling::DAY,
        at_ms,
    )
    .amount
}

/// The next action nonce `agent_did` must use.
pub fn read_agent_act_nonce(state: &dyn VmState, agent_did: &str) -> u64 {
    read_json(state, &nonce_key(agent_did)).unwrap_or(0)
}

/// Refuse an agent that chain state records as revoked or quarantined, or
/// that its controller has paused until after `now_ms`.
pub fn check_agent_status(
    state: &dyn VmState,
    agent_did: &str,
    now_ms: u64,
) -> std::result::Result<(), String> {
    match read_agent_quarantine(state, agent_did) {
        Some(q) if q.revoked => Err(format!("{agent_did} was revoked by its controller")),
        Some(_) => Err(format!("{agent_did} is quarantined")),
        None if super::agent_paused(state, agent_did, now_ms as i64) => {
            Err(format!("{agent_did} is paused by its controller"))
        }
        None => Ok(()),
    }
}

/// Verify the root's approval of `terms` (see [`verify_root_approval`]).
fn verify_approval(
    state: &dyn VmState,
    terms: &AgentTerms,
    rotate: Option<bool>,
    approval: &AgentTermsApproval,
    now_ms: u64,
) -> Result<[u8; 32]> {
    let op = if rotate.is_some() {
        OP_UPDATE_AGENT_TERMS
    } else {
        OP_DELEGATE_AGENT
    };
    verify_root_approval(
        state,
        &terms.controller_did,
        op,
        &terms.target(rotate),
        approval,
        now_ms,
    )
    .map_err(refuse)
}

/// The P-256 key (`x || y`) of the autonomous machine `machine_did` as its
/// on-chain registration binds it. The DID must derive from that key, be
/// registered as a machine and not be revoked.
pub fn machine_root_key(
    state: &dyn VmState,
    machine_did: &str,
) -> std::result::Result<Vec<u8>, String> {
    let record = super::funding::identity_record(state, machine_did)
        .filter(|r| r.identity_type == "machine")
        .ok_or_else(|| format!("{machine_did} is not a machine identity registered on chain"))?;
    if state
        .get_storage(
            &SYSTEM_ADDRESS,
            &super::identity_revocation_key(machine_did),
        )
        .is_some_and(|b| !b.is_empty())
    {
        return Err(format!("identity {machine_did} is revoked"));
    }
    if !tenzro_types::did_derivation::did_derives_from_key(machine_did, &record.controller_pubkey) {
        return Err(format!(
            "{machine_did} does not derive from its registered key"
        ));
    }
    match record.controller_pubkey.as_slice() {
        [0x04, xy @ ..] if xy.len() == 64 => Ok(xy.to_vec()),
        xy if xy.len() == 64 => Ok(xy.to_vec()),
        _ => Err(format!("{machine_did} is registered without a P-256 key")),
    }
}

/// Verify that the root `controller_did` approved the custody operation `op`
/// over `target`. Returns the challenge digest.
///
/// One check for every root. For a human, a passkey of the identity's
/// keystore on chain (any linked device; before the identity has a keystore,
/// the passkey its DID derives from); for an autonomous machine, the hardware
/// key its on-chain registration binds (registered, not revoked). The signature
/// is a composite over the custody challenge digest under the account-owner
/// context: a passkey signs it as a WebAuthn assertion with user
/// verification, a machine in raw form. The ML-DSA-65 key comes from chain
/// state, never from the approval, and once one is enrolled for the root's
/// key the hybrid is mandatory, so the P-256 leg alone cannot pass.
pub fn verify_root_approval(
    state: &dyn VmState,
    controller_did: &str,
    op: &[u8],
    target: &[u8],
    approval: &AgentTermsApproval,
    now_ms: u64,
) -> std::result::Result<[u8; 32], String> {
    use tenzro_crypto::composite::{
        ClassicalProof, CompositePublicKey, PqPolicy, SignatureContext,
    };
    let xy = approval.root_public_key.as_slice();
    let rp_id = match RootKind::of(controller_did) {
        Some(RootKind::Passkey) => {
            let rp_id = crate::keystore::check_passkey_root(state, controller_did, xy, now_ms)?;
            if !matches!(
                approval.signature.classical,
                ClassicalProof::WebAuthn { .. }
            ) {
                return Err("a human root approves with a passkey assertion".to_string());
            }
            rp_id
        }
        Some(RootKind::Machine) => {
            if machine_root_key(state, controller_did)? != xy {
                return Err(
                    "the approval must come from the hardware key the machine's identity is registered with"
                        .to_string(),
                );
            }
            if !matches!(approval.signature.classical, ClassicalProof::Raw { .. }) {
                return Err(
                    "a machine root approves with its TPM or Secure Enclave key".to_string()
                );
            }
            None
        }
        None => {
            return Err(format!(
                "{controller_did} cannot root an agent: a root is a human or an autonomous machine"
            ));
        }
    };
    let digest = custody_challenge_digest(
        super::network_chain_id(state),
        &approval.account,
        op,
        target,
        &approval.nonce,
    );
    let key = CompositePublicKey::new(xy.to_vec(), crate::account_keys::enrolled_pq_key(state, xy))
        .map_err(|e| format!("root key: {e}"))?;
    crate::keystore::verify_for_relying_party(
        rp_id.as_deref(),
        &key,
        SignatureContext::AccountOwner,
        &digest,
        &approval.signature,
        PqPolicy::Required,
    )
    .map_err(|e| format!("the root's approval does not verify: {e}"))?;
    Ok(digest)
}

/// Record approved terms.
pub(super) fn set_terms(
    state: &mut dyn VmState,
    terms: &AgentTerms,
    rotate: Option<bool>,
    approval: &AgentTermsApproval,
    at_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let root = RootKind::of(&terms.controller_did).ok_or_else(|| {
        refuse("the controller must be a human or an autonomous machine identity")
    })?;
    let agent = agent_did(&terms.controller_did, &terms.agent_name).ok_or_else(|| {
        refuse("the controller must be a human or an autonomous machine identity")
    })?;
    check_agent_status(state, &agent, at_ms.max(0) as u64).map_err(refuse)?;
    let existing = read_agent_terms(state, &agent);
    match (&existing, rotate) {
        (None, Some(_)) => return Err(refuse(format!("{agent} has no terms to change"))),
        (Some(_), None) => {
            return Err(refuse(format!(
                "{agent} already exists; change its terms with update_agent_terms"
            )));
        }
        (Some(e), Some(_)) if e.terms.controller_did != terms.controller_did => {
            return Err(refuse(format!("{agent} has another controller")));
        }
        _ => {}
    }
    check_trifecta(terms.exposure(), terms.trifecta_exception).map_err(refuse)?;
    let digest = verify_approval(state, terms, rotate, approval, at_ms.max(0) as u64)?;
    // A root's approval authorizes one change; replaying it must not restore older terms.
    let used = approval_used_key(&agent, &digest);
    if state
        .get_storage(&SYSTEM_ADDRESS, used.as_bytes())
        .is_some()
    {
        return Err(refuse(
            "this approval was already used; the root must approve the change again",
        ));
    }
    // The bond is posted before the terms it secures.
    super::economy::check_agent_bond(state, &agent, terms).map_err(refuse)?;
    let record = StoredAgentTerms {
        terms: terms.clone(),
        root,
        version: existing.as_ref().map(|e| e.version + 1).unwrap_or(1),
        approval_digest: hex::encode(digest),
        updated_at_ms: at_ms,
        renewed_at_ms: Some(at_ms),
    };
    // A renewal that changes nothing but a later expiry keeps the grants
    // issued under the terms it renews.
    let renewal_only = rotate != Some(true)
        && existing
            .as_ref()
            .is_some_and(|e| only_extends_expiry(&e.terms, terms));
    let mut changes = Vec::new();
    let replaced = record.version > 1;
    write_json(state, &terms_key(&agent), &record, &mut changes)?;
    write_json(state, &used, &record.version, &mut changes)?;
    if !replaced {
        super::identity_revocation::index_delegated_agent(
            state,
            &terms.controller_did,
            &agent,
            &mut changes,
        )?;
    }
    let log_data = serde_json::to_vec(&serde_json::json!({
        "agent_did": agent,
        "version": record.version,
        "approval_digest": record.approval_digest,
    }))
    .map_err(|e| VmError::Internal(format!("encode terms log: {e}")))?;
    let mut logs = vec![Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![AGENT_TERMS_TOPIC.to_vec()],
        log_data,
    )];
    // Grants on other chains were issued under the terms these replace.
    if replaced && !renewal_only {
        super::remote_grant::void_all(state, &agent, at_ms.max(0) as u64, &mut changes, &mut logs)?;
    }
    Ok((changes, logs))
}

/// Whether `new` differs from `old` in nothing but an expiry no earlier than
/// the old one (no expiry being the latest).
fn only_extends_expiry(old: &AgentTerms, new: &AgentTerms) -> bool {
    let later = match (old.expires_at_ms, new.expires_at_ms) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(o), Some(n)) => n >= o,
    };
    let mut same = old.clone();
    same.expires_at_ms = new.expires_at_ms;
    later && same == *new
}

/// Verify a serving node's signature over `action` against its key in the
/// agent's current terms.
pub fn verify_action_signature(
    terms: &AgentTerms,
    action: &AgentAction,
    signature: &[u8],
) -> std::result::Result<(), String> {
    verify_node_signature(terms, &action.machine_did, &action.digest(), signature)
}

/// Verify `signature` over `digest` by the key the agent's terms assign to
/// the serving node `machine_did`: the one key a node holds for the agent,
/// in its TPM, whether it signs an action or a voucher.
pub fn verify_node_signature(
    terms: &AgentTerms,
    machine_did: &str,
    digest: &[u8; 32],
    signature: &[u8],
) -> std::result::Result<(), String> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let node = terms
        .serving_node(machine_did)
        .ok_or("outside the agent's approved terms: serving node")?;
    let xy = hex::decode(&node.dpop_public_key).map_err(|_| "the node key is not hex")?;
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&xy);
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| "the node key is not a P-256 point")?;
    let sig =
        p256::ecdsa::Signature::from_slice(signature).map_err(|_| "the signature is malformed")?;
    key.verify_prehash(digest, &sig)
        .map_err(|_| "the signature is not by the serving node's key for this agent".to_string())
}

/// Records `keys` (machine DID, ML-DSA-65 key) as the serving nodes'
/// ML-DSA-65 keys for `agent_did` and marks its wallet as requiring the
/// ML-DSA leg (see `AccountKeysOp::RequireAgentPqLeg`).
pub(crate) fn require_agent_node_pq_keys(
    state: &mut dyn VmState,
    agent_did: &str,
    keys: &[(String, Vec<u8>)],
    changes: &mut Vec<StateChange>,
) {
    let Some(wallet) = crate::keystore::account20(&agent_wallet(agent_did)) else {
        return;
    };
    let map: std::collections::BTreeMap<String, String> = keys
        .iter()
        .map(|(did, key)| (did.clone(), hex::encode(key)))
        .collect();
    let value = serde_json::to_vec(&map).unwrap_or_default();
    let key = tenzro_types::account_signature::agent_pq_keys_storage_key(&wallet);
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), value.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(value),
    ));
    crate::account_keys::set_pq_required(state, &wallet, changes);
}

/// The ML-DSA-65 key `agent_did`'s requirement names for `machine_did`.
fn agent_node_pq_key(state: &dyn VmState, agent_did: &str, machine_did: &str) -> Option<Vec<u8>> {
    let wallet = crate::keystore::account20(&agent_wallet(agent_did))?;
    let key = tenzro_types::account_signature::agent_pq_keys_storage_key(&wallet);
    let raw = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes())?;
    let keys: std::collections::BTreeMap<String, String> = serde_json::from_slice(&raw).ok()?;
    hex::decode(keys.get(machine_did)?).ok()
}

/// A serving node's signature for an agent: the P-256 signature (64 bytes)
/// and, after it, the node's ML-DSA-65 signature when it carries one.
pub fn split_node_signature(signature: &[u8]) -> (&[u8], Option<&[u8]>) {
    if signature.len() > 64 {
        (&signature[..64], Some(&signature[64..]))
    } else {
        (signature, None)
    }
}

/// The ML-DSA leg of a serving node's signature over `digest` for
/// `agent_did`: required, by the key the agent's requirement names for
/// `machine_did`, once the agent's wallet requires it; not looked at
/// otherwise.
pub fn verify_node_pq_leg(
    state: &dyn VmState,
    agent_did: &str,
    machine_did: &str,
    digest: &[u8; 32],
    pq: Option<&[u8]>,
) -> std::result::Result<(), String> {
    if !crate::account_keys::pq_required(state, &agent_wallet(agent_did)) {
        return Ok(());
    }
    let key = agent_node_pq_key(state, agent_did, machine_did).ok_or(
        "the agent requires the ML-DSA leg, and the serving node has no ML-DSA key for it on chain",
    )?;
    let sig = pq.ok_or("the agent requires the serving node's ML-DSA-65 signature")?;
    tenzro_crypto::pq::ml_dsa_verify(
        &key,
        tenzro_types::account_signature::AGENT_NODE_PQ_CONTEXT,
        digest,
        sig,
    )
    .map_err(|_| "the serving node's ML-DSA-65 signature does not verify".to_string())
}

/// The full check an action passes: the agent is live, the action is the
/// next in sequence, signed by an assigned serving node, and within the
/// terms. The serving node runs this before signing; the VM runs it again
/// at execution.
pub fn check_agent_act(
    state: &dyn VmState,
    action: &AgentAction,
    signature: Option<&[u8]>,
    at_ms: u64,
) -> std::result::Result<StoredAgentTerms, String> {
    check_agent_status(state, &action.agent_did, at_ms)?;
    let stored = read_agent_terms(state, &action.agent_did)
        .ok_or_else(|| format!("{} has no approved terms on chain", action.agent_did))?;
    check_renewed(state, &action.agent_did, &stored, at_ms)?;
    if action.nonce != read_agent_act_nonce(state, &action.agent_did) {
        return Err("the action nonce is not the agent's next one".to_string());
    }
    // A bond withdrawn below what the terms require stops the agent.
    super::economy::check_agent_bond(state, &action.agent_did, &stored.terms)?;
    if let Some(sig) = signature {
        let (p256, pq) = split_node_signature(sig);
        verify_action_signature(&stored.terms, action, p256)?;
        verify_node_pq_leg(
            state,
            &action.agent_did,
            &action.machine_did,
            &action.digest(),
            pq,
        )?;
    }
    let stepped_up = match &action.step_up {
        Some(approval) => {
            verify_root_approval(
                state,
                &stored.terms.controller_did,
                OP_AGENT_STEP_UP,
                &action.digest(),
                approval,
                at_ms,
            )
            .map_err(|e| format!("step-up: {e}"))?;
            true
        }
        None => false,
    };
    let mut history = history_of(state, action, at_ms);
    read_counterparty_kyc(state, &stored.terms, action, &mut history, at_ms);
    check_action(
        &stored.terms,
        &unit_view(state, &stored.terms, action)?,
        &history,
        stepped_up,
        at_ms,
    )
    .map_err(|d| format!("outside the agent's approved terms: {d}"))?;
    tenzro_types::agent_terms::check_asset(&stored.terms, action, history.asset_spent_today)
        .map_err(|d| format!("outside the agent's approved terms: {d}"))?;
    if action.remote_grant.is_some() {
        super::remote_grant::check_issue(state, &stored, action, at_ms)?;
    }
    Ok(stored)
}

/// A payment `payer_did` proposes through a payment protocol (x402, MPP,
/// vouchers, card flows), held to chain state: a payer with no terms is
/// not a delegated agent and pays under its own key, except that an agent
/// DID with no terms has no authority at all; a delegated agent must be
/// live, bonded and within its terms, and an amount its terms hold for
/// step-up is refused here (the controller approves it as an `AgentAct`).
pub struct PaymentProposal<'a> {
    /// The paying DID.
    pub payer_did: &'a str,
    /// The operation, as the terms name it.
    pub operation: &'a str,
    /// Value moved, smallest unit.
    pub amount: u128,
    /// The payee, hex address or DID.
    pub counterparty: &'a str,
    /// The chain it settles on.
    pub chain: &'a str,
    /// The payment protocol.
    pub protocol: Option<&'a str>,
    /// Untrusted input reached the agent before it proposed the payment.
    pub tainted: bool,
}

/// Check a [`PaymentProposal`] against chain state at `at_ms`.
pub fn check_agent_payment(
    state: &dyn VmState,
    p: &PaymentProposal<'_>,
    at_ms: u64,
) -> std::result::Result<(), String> {
    let Some(stored) = read_agent_terms(state, p.payer_did) else {
        if p.payer_did.starts_with("did:tenzro:agent:") {
            return Err(format!("{} has no approved terms on chain", p.payer_did));
        }
        return Ok(());
    };
    check_agent_status(state, p.payer_did, at_ms)?;
    check_renewed(state, p.payer_did, &stored, at_ms)?;
    super::economy::check_agent_bond(state, p.payer_did, &stored.terms)?;
    let action = AgentAction {
        agent_did: p.payer_did.to_string(),
        machine_did: String::new(),
        operation: p.operation.to_string(),
        counterparty: p.counterparty.to_string(),
        amount: spend_units(state, Some(&stored.terms), None, p.amount, 0)?,
        asset: None,
        usd_e6: 0,
        payment: None,
        chain: p.chain.to_string(),
        payment_protocol: p.protocol.map(str::to_string),
        model: None,
        calls: Vec::new(),
        escrow: None,
        nonce: 0,
        tainted: p.tainted,
        step_up: None,
        remote_grant: None,
        ballot: None,
        veto_signal: None,
    };
    let mut history = read_agent_history(state, p.payer_did, p.counterparty, at_ms);
    read_counterparty_kyc(state, &stored.terms, &action, &mut history, at_ms);
    tenzro_types::agent_terms::check_limits(&stored.terms, &action, &history, false, at_ms)
        .map_err(|d| format!("outside the agent's approved terms: {d}"))
}

/// Held to an agent's standing and spend caps wherever its own account pays
/// — not only through `AgentAct`, but through any settlement path a signed
/// payment can reach (a generic `PayerSettle`, a channel voucher, and so
/// on). `check_agent_payment` above is the fuller gate `AgentAct` and
/// explicit agent payments take, including which operations, chains,
/// protocols and counterparties the terms allow; callers that cannot name an
/// operation for a generic settlement still owe the agent these three
/// things, which do not depend on one: it is not revoked, quarantined,
/// paused or lapsed, and this payment does not carry it past its
/// per-transaction, daily or hourly cap or its action-rate limit. Recorded
/// outflow compounds across calls in the same rolling windows `AgentAct`
/// spends from, so a tight loop of small payments cannot walk past a cap one
/// call at a time, and a call once revocation lands is refused like any
/// other action after it.
pub fn check_and_record_agent_spend(
    state: &mut dyn VmState,
    agent_did: &str,
    counterparty: &str,
    asset: Option<&str>,
    amount: u128,
    usd_e6: u64,
    at_ms: u64,
) -> std::result::Result<Vec<StateChange>, String> {
    let stored = read_agent_terms(state, agent_did)
        .ok_or_else(|| format!("{agent_did} has no approved terms on chain"))?;
    let amount = spend_units(state, Some(&stored.terms), asset, amount, usd_e6)?;
    check_agent_status(state, agent_did, at_ms)?;
    check_renewed(state, agent_did, &stored, at_ms)?;
    let history = read_agent_history(state, agent_did, counterparty, at_ms);
    let s = &stored.terms.delegation_scope;
    let per_tx = tenzro_types::agent_terms::parse_amount(s.max_transaction_value.as_deref())
        .map_err(|_| "per-transaction limit".to_string())?;
    if per_tx.is_some_and(|cap| amount > cap) {
        return Err("per-transaction limit".to_string());
    }
    let daily = tenzro_types::agent_terms::parse_amount(s.max_daily_spend.as_deref())
        .map_err(|_| "daily limit".to_string())?;
    if daily.is_some_and(|cap| history.spent_today.saturating_add(amount) > cap) {
        return Err("daily limit".to_string());
    }
    let hourly = tenzro_types::agent_terms::parse_amount(s.max_hourly_spend.as_deref())
        .map_err(|_| "hourly limit".to_string())?;
    if hourly.is_some_and(|cap| history.spent_this_hour.saturating_add(amount) > cap) {
        return Err("hourly limit".to_string());
    }
    if s.max_actions_per_hour
        .is_some_and(|cap| history.actions_this_hour >= cap)
    {
        return Err("actions per hour".to_string());
    }
    if s.max_actions_per_day
        .is_some_and(|cap| history.actions_today >= cap)
    {
        return Err("actions per day".to_string());
    }
    let mut changes = Vec::new();
    for (key, span) in [
        (spent_day_key(agent_did), rolling::DAY),
        (spent_hour_key(agent_did), rolling::HOUR),
    ] {
        rolling::add(state, &key, span, at_ms, amount, 1, &mut changes)
            .map_err(|e| e.to_string())?;
    }
    Ok(changes)
}

pub(crate) mod rolling {
    //! The rolling windows an agent's caps count over: the last 24 hours and the
    //! last 60 minutes, whatever the clock reads. A window is a short list of
    //! fixed sub-buckets (an hour each for the day, five minutes each for the
    //! hour). A bucket counts while any part of it lies inside the window, so a
    //! total never counts less than what moved in any rolling span, and a cap
    //! holds over every 24 hours and every 60 minutes. Buckets that leave the
    //! window are dropped on the next write, so a window holds at most 25 or 13
    //! entries.

    use serde::{Deserialize, Serialize};
    use tenzro_types::agent_terms::{DAY_MS, HOUR_MS};

    use super::super::funding::{read_json, write_json};
    use super::super::*;

    /// A rolling span and the size of the buckets it is counted in.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Span {
        /// Length of the window, ms.
        pub span_ms: u64,
        /// Length of one bucket, ms.
        pub bucket_ms: u64,
    }

    /// The last 24 hours, in hourly buckets.
    pub const DAY: Span = Span {
        span_ms: DAY_MS,
        bucket_ms: HOUR_MS,
    };

    /// The last 60 minutes, in five-minute buckets.
    pub const HOUR: Span = Span {
        span_ms: HOUR_MS,
        bucket_ms: 5 * 60 * 1000,
    };

    impl Span {
        /// Start of the oldest bucket that still overlaps the window ending at
        /// `now`.
        fn first(&self, now: u64) -> u64 {
            now.saturating_sub(self.span_ms) / self.bucket_ms * self.bucket_ms
        }

        /// Start of the bucket holding `at`.
        fn bucket_of(&self, at: u64) -> u64 {
            at / self.bucket_ms * self.bucket_ms
        }
    }

    /// What moved in one bucket.
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Bucket {
        /// Start of the bucket, ms.
        pub start_ms: u64,
        /// Value moved, smallest unit, decimal.
        pub amount: String,
        /// Actions taken.
        pub actions: u32,
    }

    impl Bucket {
        fn amount(&self) -> u128 {
            self.amount.parse().unwrap_or(0)
        }
    }

    /// What a window holds at a moment.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Totals {
        /// Value moved, smallest unit.
        pub amount: u128,
        /// Actions taken.
        pub actions: u32,
    }

    fn live(state: &dyn VmState, key: &str, span: Span, now: u64) -> Vec<Bucket> {
        let first = span.first(now);
        let mut buckets: Vec<Bucket> = read_json(state, key).unwrap_or_default();
        buckets.retain(|b| b.start_ms >= first);
        buckets
    }

    /// What the window at `key` holds for the span ending at `now`.
    pub fn totals(state: &dyn VmState, key: &str, span: Span, now: u64) -> Totals {
        live(state, key, span, now)
            .iter()
            .fold(Totals::default(), |t, b| Totals {
                amount: t.amount.saturating_add(b.amount()),
                actions: t.actions.saturating_add(b.actions),
            })
    }

    /// Add `amount` and `actions` at `now` to the window at `key`.
    pub(crate) fn add(
        state: &mut dyn VmState,
        key: &str,
        span: Span,
        now: u64,
        amount: u128,
        actions: u32,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let mut buckets = live(state, key, span, now);
        let start = span.bucket_of(now);
        match buckets.iter_mut().find(|b| b.start_ms == start) {
            Some(b) => {
                b.amount = b.amount().saturating_add(amount).to_string();
                b.actions = b.actions.saturating_add(actions);
            }
            None => buckets.push(Bucket {
                start_ms: start,
                amount: amount.to_string(),
                actions,
            }),
        }
        write_json(state, key, &buckets, changes).map(|_| ())
    }

    /// Take `amount` back from the bucket that counted a use made at `at`, when
    /// that bucket is still inside the window ending at `now`.
    pub(crate) fn credit(
        state: &mut dyn VmState,
        key: &str,
        span: Span,
        now: u64,
        at: u64,
        amount: u128,
        changes: &mut Vec<StateChange>,
    ) -> Result<()> {
        let mut buckets = live(state, key, span, now);
        let start = span.bucket_of(at);
        if let Some(b) = buckets.iter_mut().find(|b| b.start_ms == start) {
            b.amount = b.amount().saturating_sub(amount).to_string();
        }
        write_json(state, key, &buckets, changes).map(|_| ())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::state_adapter::StateAdapter;

        const KEY: &str = "window";

        #[test]
        fn a_use_counts_for_the_whole_span_and_then_leaves() {
            let mut state = StateAdapter::new();
            let t = 10 * DAY_MS + 23 * HOUR_MS + 59 * 60_000;
            add(&mut state, KEY, DAY, t, 100, 1, &mut Vec::new()).unwrap();
            // Two minutes later the UTC day has turned; the use still counts.
            assert_eq!(totals(&state, KEY, DAY, t + 2 * 60_000).amount, 100);
            assert_eq!(totals(&state, KEY, DAY, t + DAY_MS - 1).amount, 100);
            // Once its whole bucket has left the window, it no longer counts.
            assert_eq!(totals(&state, KEY, DAY, t + DAY_MS + HOUR_MS).amount, 0);
        }

        #[test]
        fn a_window_holds_a_bounded_number_of_buckets() {
            let mut state = StateAdapter::new();
            for i in 0..1_000u64 {
                add(&mut state, KEY, HOUR, i * 60_000, 1, 1, &mut Vec::new()).unwrap();
            }
            let buckets: Vec<Bucket> = read_json(&state, KEY).unwrap();
            assert!(buckets.len() <= 13, "{}", buckets.len());
            let t = totals(&state, KEY, HOUR, 999 * 60_000);
            assert!(t.actions >= 60 && t.actions <= 65, "{}", t.actions);
        }

        #[test]
        fn a_credit_returns_value_to_the_bucket_that_counted_it() {
            let mut state = StateAdapter::new();
            add(&mut state, KEY, DAY, HOUR_MS, 100, 1, &mut Vec::new()).unwrap();
            credit(
                &mut state,
                KEY,
                DAY,
                3 * HOUR_MS,
                HOUR_MS,
                40,
                &mut Vec::new(),
            )
            .unwrap();
            assert_eq!(totals(&state, KEY, DAY, 3 * HOUR_MS).amount, 60);
        }
    }
}

#[cfg(test)]
pub(crate) fn store_terms_unapproved(
    state: &mut dyn VmState,
    agent_did: &str,
    stored: &StoredAgentTerms,
) {
    let mut changes = Vec::new();
    write_json(state, &terms_key(agent_did), stored, &mut changes).unwrap();
}

/// Decode an `AgentAct` payload: the action and the serving node's
/// signature over it.
pub fn decode_act(payload: &[u8]) -> Result<(AgentAction, Vec<u8>)> {
    #[derive(Deserialize)]
    struct Payload {
        action: AgentAction,
        signature: Vec<u8>,
    }
    let p: Payload = serde_json::from_slice(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("Invalid AgentAct payload: {e}")))?;
    Ok((p.action, p.signature))
}

/// The terms' view of one call an action makes: the VM is its chain, the
/// code it calls its counterparty and `amount` the value it moves.
fn call_view(action: &AgentAction, call: &VmCall, amount: u128) -> AgentAction {
    AgentAction {
        agent_did: action.agent_did.clone(),
        machine_did: action.machine_did.clone(),
        operation: action.operation.clone(),
        counterparty: hex::encode(&call.to),
        amount,
        asset: None,
        usd_e6: 0,
        payment: None,
        chain: call.vm.name().to_string(),
        payment_protocol: None,
        model: None,
        calls: Vec::new(),
        escrow: None,
        remote_grant: None,
        ballot: None,
        veto_signal: None,
        nonce: action.nonce,
        tainted: action.tainted,
        step_up: None,
    }
}

/// The agent's history as a call of `action` sees it: the action itself is
/// already counted, and a call is part of it, not another action.
fn call_history(
    state: &dyn VmState,
    action: &AgentAction,
    call: &VmCall,
    at_ms: u64,
) -> ActionHistory {
    let mut history = read_agent_history(state, &action.agent_did, &hex::encode(&call.to), at_ms);
    history.actions_today = history.actions_today.saturating_sub(1);
    history.actions_this_hour = history.actions_this_hour.saturating_sub(1);
    history
}

/// Check a call before it runs: the agent's terms must allow its VM, the
/// code it calls and the value it carries, the same terms every VM's calls
/// are held to. A step-up the action carries covers its calls, since the
/// controller signed the digest that binds them.
pub fn check_agent_call(
    state: &dyn VmState,
    action: &AgentAction,
    call: &VmCall,
    at_ms: u64,
) -> std::result::Result<(), String> {
    let stored = read_agent_terms(state, &action.agent_did)
        .ok_or_else(|| format!("{} has no approved terms on chain", action.agent_did))?;
    check_renewed(state, &action.agent_did, &stored, at_ms)?;
    let mut history = call_history(state, action, call, at_ms);
    let view = call_view(
        action,
        call,
        spend_units(state, Some(&stored.terms), None, call.value, 0)?,
    );
    read_counterparty_kyc(state, &stored.terms, &view, &mut history, at_ms);
    check_action(
        &stored.terms,
        &view,
        &history,
        action.step_up.is_some(),
        at_ms,
    )
    .map_err(|d| format!("outside the agent's approved terms: {d}"))
}

/// Hold the TNZO a call moved out of the agent's wallet, fees aside, to the
/// terms' limits, and add it to the day's and the hour's totals.
pub fn record_agent_call_outflow(
    state: &mut dyn VmState,
    action: &AgentAction,
    call: &VmCall,
    outflow: u128,
    at_ms: u64,
) -> std::result::Result<Vec<StateChange>, String> {
    let stored = read_agent_terms(state, &action.agent_did)
        .ok_or_else(|| format!("{} has no approved terms on chain", action.agent_did))?;
    let history = call_history(state, action, call, at_ms);
    let outflow = spend_units(state, Some(&stored.terms), None, outflow, 0)?;
    check_action(
        &stored.terms,
        &call_view(action, call, outflow),
        &history,
        action.step_up.is_some(),
        at_ms,
    )
    .map_err(|d| format!("outside the agent's approved terms: {d}"))?;
    let mut changes = Vec::new();
    if outflow > 0 {
        for (key, span) in [
            (spent_day_key(&action.agent_did), rolling::DAY),
            (spent_hour_key(&action.agent_did), rolling::HOUR),
        ] {
            rolling::add(state, &key, span, at_ms, outflow, 0, &mut changes)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(changes)
}

/// Execute an agent action: check it, move its value from the agent's
/// wallet to the counterparty, and advance the day's total and the nonce.
/// A plan's action rides the plan that states it, never on its own.
pub(super) fn act(
    state: &mut dyn VmState,
    chain_id: u64,
    action: &AgentAction,
    signature: &[u8],
    at_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>, u128)> {
    if action.operation == tenzro_types::agent_terms::OP_SETTLEMENT_PLAN {
        return Err(refuse(
            "an agent opens a settlement plan in the plan's own operation",
        ));
    }
    let stored =
        check_agent_act(state, action, Some(signature), at_ms.max(0) as u64).map_err(refuse)?;
    act_checked(state, chain_id, action, stored, at_ms)
}

/// Check and record the action an agent's settlement plan carries: the
/// whole value counts against the terms and the day's totals here, and the
/// plan moves it.
pub(super) fn act_for_plan(
    state: &mut dyn VmState,
    chain_id: u64,
    action: &AgentAction,
    signature: &[u8],
    at_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    if action.operation != tenzro_types::agent_terms::OP_SETTLEMENT_PLAN {
        return Err(refuse(format!(
            "an agent's plan carries the operation {}",
            tenzro_types::agent_terms::OP_SETTLEMENT_PLAN
        )));
    }
    let stored =
        check_agent_act(state, action, Some(signature), at_ms.max(0) as u64).map_err(refuse)?;
    let (changes, logs, burned) = act_checked(state, chain_id, action, stored, at_ms)?;
    // A plan's authorization moves nothing itself; the plan settles and
    // declares what its settlements burn.
    if burned != 0 {
        return Err(VmError::Internal(
            "a plan's authorization burned value".to_string(),
        ));
    }
    Ok((changes, logs))
}

/// Record an action that has passed `check_agent_act`; only the two entry
/// points above reach it, each with the terms that check returned.
fn act_checked(
    state: &mut dyn VmState,
    chain_id: u64,
    action: &AgentAction,
    stored: StoredAgentTerms,
    at_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>, u128)> {
    let now = at_ms.max(0) as u64;
    // TNZO the action's settlements burn, for its transaction to declare.
    let mut burned: u128 = 0;
    let plan_op = action.operation == tenzro_types::agent_terms::OP_SETTLEMENT_PLAN;
    let history = history_of(state, action, now);
    // What the spend limits count: the amount in micro-units of account.
    let counted = unit_view(state, &stored.terms, action)
        .map_err(refuse)?
        .amount;
    let asset = action
        .asset
        .as_deref()
        .unwrap_or(tenzro_types::payment_authorization::TNZO_ASSET);
    let token = super::payment_settlement::asset_token(state, asset)?;
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    let wallet = agent_wallet(&action.agent_did);
    if let Some(escrow) = &action.escrow {
        // The agent's wallet is the escrow's payer; the terms bound the
        // amount it locks exactly as they bound a transfer.
        let (escrow_changes, log) = match escrow {
            AgentEscrow::Create {
                expires_at_ms,
                release_conditions,
                reference,
            } => {
                let payee = hex::decode(action.counterparty.trim_start_matches("0x"))
                    .ok()
                    .filter(|b| b.len() == 32)
                    .ok_or_else(|| refuse("an escrow names a 32-byte payee as its counterparty"))?;
                let payload = CreateEscrowPayload {
                    payee: Address::from_bytes(&payee)
                        .ok_or_else(|| refuse("an escrow names a 32-byte payee"))?,
                    amount: action.amount,
                    asset_id: tenzro_types::asset::AssetId::new(asset),
                    usd_e6: action.usd_e6,
                    expires_at: *expires_at_ms,
                    release_conditions: release_conditions.clone(),
                    reference: *reference,
                };
                let (_, c, log) = lock_escrow(state, &wallet, action.nonce, &payload, 0, at_ms)?;
                (c, log)
            }
            AgentEscrow::Release { escrow_id, proof } => {
                let (c, log, b) = release_escrow(state, escrow_id, proof, &wallet, at_ms)?;
                burned = burned.saturating_add(b);
                (c, log)
            }
            AgentEscrow::Refund { escrow_id } => {
                let (c, log, b) = refund_escrow(state, escrow_id, &wallet, at_ms)?;
                burned = burned.saturating_add(b);
                (c, log)
            }
        };
        changes.extend(escrow_changes);
        logs.push(log);
    }
    if action.remote_grant.is_some() {
        // The grant's budget is counted against the daily spend below, at
        // its equivalent; no value leaves the wallet here.
        super::remote_grant::issue(state, &stored, action, now, &mut changes, &mut logs)?;
    }
    if let Some(ballot) = &action.ballot {
        super::cast_agent_ballot(
            state,
            &stored.terms,
            action,
            ballot,
            at_ms,
            &mut changes,
            &mut logs,
        )?;
    }
    if let Some(proposal_id) = &action.veto_signal {
        super::veto_escrow::agent_signal(
            state,
            &stored.terms,
            action,
            &wallet,
            proposal_id,
            at_ms,
            &mut changes,
            &mut logs,
        )?;
    }
    if action.amount > 0
        && !plan_op
        && action.escrow.is_none()
        && action.remote_grant.is_none()
        && action.veto_signal.is_none()
    {
        let to = hex::decode(action.counterparty.trim_start_matches("0x"))
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or_else(|| refuse("a value-moving action names a 32-byte counterparty"))?;
        match &action.payment {
            // A payment settles like any other, from the agent's wallet,
            // and leaves its record naming the agent.
            Some(payment) => {
                let payer = Address::new(wallet);
                let payee = Address::from_bytes(&to)
                    .ok_or_else(|| refuse("a payment names a 32-byte payee"))?;
                let outcome = super::payment_settlement::settle_native(
                    state,
                    chain_id,
                    at_ms,
                    &super::payment_settlement::NativePayment {
                        payer: &payer,
                        payee: &payee,
                        asset,
                        amount: action.amount,
                        binding: tenzro_types::payment_authorization::PaymentBinding {
                            request_digest: payment.request_digest,
                            quote_digest: payment.quote_digest,
                            usd_e6: action.usd_e6,
                            app_margin: None,
                        },
                        nonce: &payment.payment_id,
                        agent_did: Some(&action.agent_did),
                        relayer: None,
                        resellers: &[],
                    },
                    &mut changes,
                )?;
                burned = burned.saturating_add(outcome.burned);
                logs.push(outcome.log);
            }
            None => super::payment_settlement::move_asset(
                state,
                &token,
                &wallet,
                &to,
                action.amount,
                at_ms,
                &mut changes,
            )?,
        }
    }
    // Every action counts toward the action caps; what it moves toward the
    // spend caps.
    let moved = if action.amount > 0 { counted } else { 0 };
    for (key, span) in [
        (spent_day_key(&action.agent_did), rolling::DAY),
        (spent_hour_key(&action.agent_did), rolling::HOUR),
    ] {
        rolling::add(state, &key, span, now, moved, 1, &mut changes)?;
    }
    if action.amount > 0 {
        if let Some(asset) = &action.asset {
            rolling::add(
                state,
                &asset_spent_key(&action.agent_did, asset),
                rolling::DAY,
                now,
                action.amount,
                0,
                &mut changes,
            )?;
        }
        if !history.known_counterparty
            && action.remote_grant.is_none()
            && !action.counterparty.is_empty()
        {
            write_json(
                state,
                &paid_key(&action.agent_did, &action.counterparty),
                &true,
                &mut changes,
            )?;
        }
    }
    write_json(
        state,
        &nonce_key(&action.agent_did),
        &(action.nonce + 1),
        &mut changes,
    )?;
    let log_data = serde_json::to_vec(&serde_json::json!({
        "agent_did": action.agent_did,
        "machine_did": action.machine_did,
        "operation": action.operation,
        "amount": action.amount.to_string(),
        "nonce": action.nonce,
    }))
    .map_err(|e| VmError::Internal(format!("encode act log: {e}")))?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![AGENT_ACT_TOPIC.to_vec()],
        log_data,
    ));
    Ok((changes, logs, burned))
}

#[cfg(test)]
mod escrow_tests {
    use super::*;
    use crate::state_adapter::StateAdapter;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_types::agent_terms::{ServingNode, TermsScope};

    const AGENT: &str = "did:tenzro:agent:escrow-buyer";
    const MACHINE: &str = "did:tenzro:machine:serving";

    fn setup() -> (StateAdapter, SigningKey) {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let terms = AgentTerms {
            controller_did: "did:tenzro:human:controller".into(),
            agent_name: "escrow-buyer".into(),
            delegation_scope: TermsScope {
                max_daily_spend: Some("1000".into()),
                allowed_operations: vec!["create_escrow".into(), "refund_escrow".into()],
                ..Default::default()
            },
            capabilities: vec![],
            serving_nodes: vec![ServingNode {
                machine_did: MACHINE.into(),
                operator_did: "did:tenzro:human:op".into(),
                dpop_public_key: hex::encode(&point.as_bytes()[1..]),
                ..Default::default()
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        };
        let mut state = StateAdapter::new();
        crate::native::economy::count_wei_as_units_for_tests(&mut state);
        let stored = StoredAgentTerms {
            terms,
            root: RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: 0,
            renewed_at_ms: None,
        };
        write_json(&mut state, &terms_key(AGENT), &stored, &mut Vec::new()).unwrap();
        state.set_balance(derive_bond_vault_address(AGENT).as_bytes(), 1_000_000);
        state.set_balance(&agent_wallet(AGENT), 1_000);
        (state, key)
    }

    fn signed(
        state: &StateAdapter,
        key: &SigningKey,
        amount: u128,
        payee: &str,
        escrow: AgentEscrow,
    ) -> (AgentAction, Vec<u8>) {
        let action = AgentAction {
            asset: None,
            usd_e6: 0,
            payment: None,
            agent_did: AGENT.into(),
            machine_did: MACHINE.into(),
            operation: escrow.operation().into(),
            counterparty: payee.into(),
            amount,
            chain: "tenzro".into(),
            payment_protocol: None,
            model: None,
            calls: Vec::new(),
            escrow: Some(escrow),
            remote_grant: None,
            ballot: None,
            veto_signal: None,
            nonce: read_agent_act_nonce(state, AGENT),
            tainted: false,
            step_up: None,
        };
        let sig: p256::ecdsa::Signature = key.sign_prehash(&action.digest()).unwrap();
        (action, sig.to_bytes().to_vec())
    }

    /// A paused agent pays nothing until its pause ends.
    #[test]
    fn a_paused_agent_pays_nothing_until_its_pause_ends() {
        let (mut state, key) = setup();
        let payee = hex::encode([9u8; 32]);
        let create = AgentEscrow::Create {
            expires_at_ms: 90_000,
            release_conditions: ReleaseConditions::ProviderSignature,
            reference: None,
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            super::super::agent_pause_key(AGENT).as_bytes(),
            5_000i64.to_le_bytes().to_vec(),
        );
        let (a, sig) = signed(&state, &key, 400, &payee, create.clone());
        let r = act(&mut state, 1, &a, &sig, 1_000);
        assert!(format!("{r:?}").contains("paused"), "{r:?}");
        assert_eq!(state.get_balance(&agent_wallet(AGENT)), 1_000);
        act(&mut state, 1, &a, &sig, 6_000).unwrap();
        assert_eq!(state.get_balance(&agent_wallet(AGENT)), 600);
    }

    #[test]
    fn an_agent_escrow_is_paid_from_its_wallet_within_its_terms() {
        let (mut state, key) = setup();
        let wallet = agent_wallet(AGENT);
        let payee = hex::encode([9u8; 32]);
        let create = AgentEscrow::Create {
            expires_at_ms: 5_000,
            release_conditions: ReleaseConditions::ProviderSignature,
            reference: None,
        };

        // Above the daily ceiling: refused, nothing moves.
        let (a, sig) = signed(&state, &key, 1_001, &payee, create.clone());
        assert!(act(&mut state, 1, &a, &sig, 1_000).is_err());
        assert_eq!(state.get_balance(&wallet), 1_000);

        let (a, sig) = signed(&state, &key, 400, &payee, create);
        act(&mut state, 1, &a, &sig, 1_000).unwrap();
        let escrow_id = derive_escrow_id(&Address::new(wallet), 0);
        let escrow = read_escrow(&state, &escrow_id).expect("escrow recorded");
        assert_eq!(escrow.payer, Address::new(wallet));
        assert_eq!(escrow.amount, 400);
        assert_eq!(state.get_balance(&wallet), 600);
        assert_eq!(
            state.get_balance(derive_vault_address(&escrow_id).as_bytes()),
            400
        );
        assert_eq!(read_agent_spent(&state, AGENT, 1_000), 400);

        // Refund waits for expiry, then returns the remainder to the wallet.
        let (a, sig) = signed(&state, &key, 0, "", AgentEscrow::Refund { escrow_id });
        assert!(act(&mut state, 1, &a, &sig, 2_000).is_err());
        act(&mut state, 1, &a, &sig, 6_000).unwrap();
        assert_eq!(state.get_balance(&wallet), 1_000);

        // Release is not in the terms.
        let (a, sig) = signed(
            &state,
            &key,
            0,
            "",
            AgentEscrow::Release {
                escrow_id,
                proof: ServiceProof::new(
                    tenzro_types::settlement::ProofType::Cryptographic,
                    vec![],
                ),
            },
        );
        assert!(act(&mut state, 1, &a, &sig, 3_000).is_err());
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_crypto::composite::HybridSigner as _;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_types::agent_terms::HOUR_MS;
    use tenzro_types::agent_terms::{ServingNode, TermsScope};

    const MACHINE: &str = "did:tenzro:machine:serving";

    /// The chain id the fixtures sign for. Test states record none, so the VM
    /// checks approvals against 0.
    pub(crate) const CHAIN_ID: u64 = 0;

    /// The controller's passkey: a P-256 key with an ML-DSA-65 key beside it.
    pub(crate) fn passkey() -> TestHybridSigner {
        TestHybridSigner::hybrid(9)
    }

    /// Records the ML-DSA-65 key of `signer` as the one enrolled for its P-256 key.
    pub(crate) fn enroll(state: &mut dyn crate::traits::VmState, signer: &TestHybridSigner) {
        let key = signer.public_key();
        crate::account_keys::set_enrolled_pq_key(
            state,
            &key.p256,
            key.pq.clone().expect("a hybrid signer"),
            &mut Vec::new(),
        );
    }

    /// The controller's passkey assertion over the step-up challenge for
    /// `action`.
    pub(crate) fn step_up(action: &AgentAction, signer: &TestHybridSigner) -> AgentTermsApproval {
        controller_approval(OP_AGENT_STEP_UP, &action.digest(), signer)
    }

    /// The controller's passkey assertion over the custody challenge for
    /// `op` over `target`.
    pub(crate) fn controller_approval(
        op: &[u8],
        target: &[u8],
        signer: &TestHybridSigner,
    ) -> AgentTermsApproval {
        use tenzro_crypto::composite::SignatureContext;
        let nonce = [3u8; 16];
        let account = vec![1u8; 32];
        let digest = custody_challenge_digest(CHAIN_ID, &account, op, target, &nonce);
        AgentTermsApproval {
            account,
            nonce,
            root_public_key: signer.public_key().p256.clone(),
            signature: signer.sign_passkey_composite(0x05, SignatureContext::AccountOwner, &digest),
        }
    }

    /// A machine root's TPM or Secure Enclave signature over the custody
    /// challenge for `op` over `target`.
    pub(crate) fn machine_approval(
        op: &[u8],
        target: &[u8],
        signer: &tenzro_crypto::composite::testing::TestHybridSigner,
    ) -> AgentTermsApproval {
        use tenzro_crypto::composite::{HybridSigner, SignatureContext};
        let nonce = [4u8; 16];
        let account = signer.address().as_bytes().to_vec();
        let digest = custody_challenge_digest(CHAIN_ID, &account, op, target, &nonce);
        AgentTermsApproval {
            account,
            nonce,
            root_public_key: signer.public_key().p256.clone(),
            signature: signer
                .sign(SignatureContext::AccountOwner, &digest)
                .unwrap(),
        }
    }

    pub(crate) struct Agent {
        pub state: crate::StateAdapter,
        pub did: String,
        pub key: SigningKey,
    }

    impl Agent {
        /// The serving node's hardware key for the agent.
        pub fn node_key() -> SigningKey {
            SigningKey::from_slice(&[7u8; 32]).unwrap()
        }

        /// Terms under `controller` for an agent served by MACHINE.
        pub fn terms(controller: String, scope: TermsScope) -> AgentTerms {
            let point = Self::node_key().verifying_key().to_sec1_point(false);
            AgentTerms {
                controller_did: controller,
                agent_name: "buyer".into(),
                delegation_scope: scope,
                capabilities: vec![],
                serving_nodes: vec![ServingNode {
                    machine_did: MACHINE.into(),
                    operator_did: "did:tenzro:human:op".into(),
                    dpop_public_key: hex::encode(&point.as_bytes()[1..]),
                    ..Default::default()
                }],
                min_distinct_operators: 1,
                expires_at_ms: None,
                trifecta_exception: false,
                auto_approve: None,
                credentials: Vec::new(),
            }
        }

        pub fn new(scope: TermsScope) -> Self {
            let key = Self::node_key();
            let controller = format!(
                "did:tenzro:human:{}",
                tenzro_types::did_derivation::human_id(&passkey().public_key().p256)
            );
            let terms = Self::terms(controller, scope);
            let did = agent_did(&terms.controller_did, &terms.agent_name).unwrap();
            let mut state = crate::StateAdapter::new();
            enroll(&mut state, &passkey());
            crate::native::economy::count_wei_as_units_for_tests(&mut state);
            let record = StoredAgentTerms {
                terms,
                root: RootKind::Passkey,
                version: 1,
                approval_digest: String::new(),
                updated_at_ms: 0,
                // Renewed beyond every clock the tests that use this fixture
                // run at; renewal itself is tested through set_terms.
                renewed_at_ms: Some(i64::MAX / 2),
            };
            write_json(&mut state, &terms_key(&did), &record, &mut Vec::new()).unwrap();
            state.set_balance(derive_bond_vault_address(&did).as_bytes(), u128::MAX / 2);
            state.set_balance(&agent_wallet(&did), 1_000_000);
            Self { state, did, key }
        }

        pub fn action(&self, amount: u128) -> AgentAction {
            AgentAction {
                asset: None,
                usd_e6: 0,
                payment: None,
                agent_did: self.did.clone(),
                machine_did: MACHINE.into(),
                operation: "transfer".into(),
                counterparty: "11".repeat(32),
                amount,
                chain: "tenzro".into(),
                payment_protocol: None,
                model: None,
                calls: Vec::new(),
                escrow: None,
                remote_grant: None,
                ballot: None,
                veto_signal: None,
                nonce: read_agent_act_nonce(&self.state, &self.did),
                tainted: false,
                step_up: None,
            }
        }

        pub fn act(&mut self, action: &AgentAction, at_ms: u64) -> std::result::Result<(), String> {
            let sig: p256::ecdsa::Signature = self.key.sign_prehash(&action.digest()).unwrap();
            act(&mut self.state, 1, action, &sig.to_bytes(), at_ms as i64)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    }

    /// Terms that require a KYC tier of every counterparty: the VM reads
    /// the tier from the live `kyc` claims under the registry token the
    /// terms name, and a step-up does not lift the requirement.
    #[test]
    fn a_payment_needs_the_counterpartys_kyc_tier_under_the_terms_registry() {
        use tenzro_types::token_policy::Rule;
        let issuer = "did:tenzro:human:kyc-attestor";
        let mut a = Agent::new(TermsScope::default());
        let registry = crate::token_ledger::test_token(
            &mut a.state,
            vec![Rule::RequireClaim {
                kind: "kyc".into(),
                issuers: vec![issuer.into()],
            }],
        );
        let mut stored = read_agent_terms(&a.state, &a.did).unwrap();
        stored.terms.delegation_scope = TermsScope {
            allowed_operations: vec!["transfer".into()],
            max_daily_spend: Some("1000".into()),
            counterparty_kyc: Some(tenzro_types::agent_terms::KycRequirement {
                min_tier: 2,
                registry: format!("0x{}", hex::encode(registry)),
            }),
            ..Default::default()
        };
        write_json(&mut a.state, &terms_key(&a.did), &stored, &mut Vec::new()).unwrap();
        let grade = |state: &mut crate::StateAdapter, value: &str| {
            let claim = crate::token_ledger::Claim {
                value: value.into(),
                expires_ms: i64::MAX,
            };
            crate::evm::precompile_host::state_write_blob(
                state,
                &crate::precompiles::PRECOMPILE_TOKEN_FACTORY,
                crate::evm::token_factory::claim_slot(&registry, &[0x11u8; 32], "kyc", issuer),
                &serde_json::to_vec(&claim).unwrap(),
            );
        };
        let unverified = a.act(&a.action(10), HOUR_MS).unwrap_err();
        assert!(unverified.contains("counterparty kyc tier"), "{unverified}");
        grade(&mut a.state, "basic");
        let mut stepped = a.action(10);
        stepped.step_up = Some(step_up(&stepped, &passkey()));
        let basic = a.act(&stepped, HOUR_MS).unwrap_err();
        assert!(basic.contains("counterparty kyc tier"), "{basic}");
        // Moving nothing pays no one.
        a.act(&a.action(0), HOUR_MS).unwrap();
        grade(&mut a.state, "enhanced");
        a.act(&a.action(10), HOUR_MS).unwrap();
    }

    #[test]
    fn rolling_caps_hold_across_the_utc_day_boundary() {
        let mut a = Agent::new(TermsScope {
            max_daily_spend: Some("100".into()),
            allowed_operations: vec!["transfer".into()],
            ..Default::default()
        });
        a.act(&a.action(100), 5 * DAY_MS - 60_000).unwrap();
        let over = a.act(&a.action(100), 5 * DAY_MS + 60_000).unwrap_err();
        assert!(over.contains("daily limit"), "{over}");
        // A full day after the spend, the cap is free again.
        a.act(&a.action(100), 6 * DAY_MS + HOUR_MS).unwrap();
    }

    #[test]
    fn rolling_caps_hold_across_the_top_of_the_hour() {
        let mut a = Agent::new(TermsScope {
            max_daily_spend: Some("1000".into()),
            max_hourly_spend: Some("20".into()),
            max_actions_per_hour: Some(2),
            allowed_operations: vec!["transfer".into()],
            ..Default::default()
        });
        let top = 30 * HOUR_MS;
        a.act(&a.action(20), top - 60_000).unwrap();
        let over = a.act(&a.action(20), top + 60_000).unwrap_err();
        assert!(over.contains("hourly limit"), "{over}");
        a.act(&a.action(0), top + 60_000).unwrap();
        let busy = a.act(&a.action(0), top + 120_000).unwrap_err();
        assert!(busy.contains("actions per hour"), "{busy}");
    }

    #[test]
    fn the_vm_keeps_hourly_and_daily_counts() {
        let mut a = Agent::new(TermsScope {
            max_daily_spend: Some("1000".into()),
            max_hourly_spend: Some("100".into()),
            max_actions_per_hour: Some(2),
            max_actions_per_day: Some(3),
            allowed_operations: vec!["transfer".into()],
            ..Default::default()
        });
        let t0 = 10 * HOUR_MS;
        a.act(&a.action(60), t0).unwrap();
        let over = a.act(&a.action(60), t0 + 1).unwrap_err();
        assert!(over.contains("hourly limit"), "{over}");
        a.act(&a.action(40), t0 + 2).unwrap();
        let busy = a.act(&a.action(0), t0 + 3).unwrap_err();
        assert!(busy.contains("actions per hour"), "{busy}");
        // The first spend's five-minute bucket has left the rolling hour.
        a.act(&a.action(60), t0 + HOUR_MS + 5 * 60_000).unwrap();
        let day = a.act(&a.action(0), t0 + 2 * HOUR_MS).unwrap_err();
        assert!(day.contains("actions per day"), "{day}");
        assert_eq!(
            read_agent_history(&a.state, &a.did, "", t0).spent_today,
            160
        );
    }

    #[test]
    fn trifecta_terms_need_the_controllers_explicit_exception() {
        let a = Agent::new(TermsScope::default());
        let mut terms = read_agent_terms(&a.state, &a.did).unwrap().terms;
        terms.agent_name = "reader".into();
        terms.delegation_scope.allowed_operations = vec!["files".into(), "fetch".into()];
        let approval = step_up(&a.action(0), &passkey());
        let mut state = crate::StateAdapter::new();
        let refused = set_terms(&mut state, &terms, None, &approval, 0)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("trifecta_exception"), "{refused}");
        terms.delegation_scope.allowed_operations = vec!["files".into(), "inference".into()];
        let other = set_terms(&mut state, &terms, None, &approval, 0)
            .unwrap_err()
            .to_string();
        assert!(!other.contains("trifecta"), "two legs are allowed: {other}");
        terms.delegation_scope.allowed_operations = vec!["files".into(), "fetch".into()];
        terms.trifecta_exception = true;
        let other = set_terms(&mut state, &terms, None, &approval, 0)
            .unwrap_err()
            .to_string();
        assert!(other.contains("does not verify"), "{other}");
    }

    #[test]
    fn a_tainted_payment_runs_only_with_the_controllers_step_up() {
        let mut a = Agent::new(TermsScope {
            max_daily_spend: Some("1000".into()),
            allowed_operations: vec!["transfer".into()],
            ..Default::default()
        });
        let mut tainted = a.action(10);
        tainted.tainted = true;
        let held = a.act(&tainted, 0).unwrap_err();
        assert!(held.contains("step-up required: untrusted input"), "{held}");
        tainted.step_up = Some(step_up(&tainted, &passkey()));
        a.act(&tainted, 0).unwrap();
        a.act(&a.action(10), 1).unwrap();
    }

    #[test]
    fn a_held_action_runs_only_with_the_controllers_step_up() {
        let mut a = Agent::new(TermsScope {
            max_daily_spend: Some("1000".into()),
            step_up_above: Some("100".into()),
            step_up_new_counterparty: true,
            allowed_operations: vec!["transfer".into()],
            ..Default::default()
        });
        let held = a.act(&a.action(10), 0).unwrap_err();
        assert!(
            held.contains("step-up required: new counterparty"),
            "{held}"
        );
        let mut stepped = a.action(10);
        stepped.step_up = Some(step_up(&stepped, &passkey()));
        a.act(&stepped, 0).unwrap();
        a.act(&a.action(10), 1).unwrap();
        let big = a.act(&a.action(101), 2).unwrap_err();
        assert!(big.contains("step-up required: amount"), "{big}");
        let stranger = TestHybridSigner::hybrid(4);
        let mut forged = a.action(101);
        forged.step_up = Some(step_up(&forged, &stranger));
        let refused = a.act(&forged, 2).unwrap_err();
        assert!(refused.contains("step-up"), "{refused}");
        let mut replayed = a.action(101);
        replayed.step_up = stepped.step_up.clone();
        assert!(
            a.act(&replayed, 2).is_err(),
            "an approval covers one action only"
        );
        let mut big = a.action(101);
        big.step_up = Some(step_up(&big, &passkey()));
        a.act(&big, 2).unwrap();
    }

    /// Root oversight has one path: terms that hold every action for the
    /// root refuse it until the root's step-up of that exact action arrives
    /// in the action itself; with no step-up (the root declined) or with a
    /// step-up whose action nonce has passed (expired), it stays refused.
    #[test]
    fn a_held_action_proceeds_on_the_roots_step_up_and_nothing_else() {
        let mut a = Agent::new(TermsScope {
            max_daily_spend: Some("1000".into()),
            step_up_above: Some("0".into()),
            allowed_operations: vec!["transfer".into()],
            ..Default::default()
        });
        let declined = a.act(&a.action(5), 0).unwrap_err();
        assert!(declined.contains("step-up required"), "{declined}");
        let mut first = a.action(5);
        first.step_up = Some(step_up(&first, &passkey()));
        let mut early = a.action(6);
        early.step_up = Some(step_up(&early, &passkey()));
        a.act(&first, 0).unwrap();
        let expired = a.act(&early, 1).unwrap_err();
        assert!(expired.contains("nonce"), "{expired}");
        let mut fresh = a.action(6);
        fresh.step_up = Some(step_up(&fresh, &passkey()));
        a.act(&fresh, 1).unwrap();
    }

    fn pay<'a>(did: &'a str, amount: u128) -> PaymentProposal<'a> {
        PaymentProposal {
            payer_did: did,
            operation: "payment",
            amount,
            counterparty: "22",
            chain: "tenzro",
            protocol: Some("x402"),
            tainted: false,
        }
    }

    #[test]
    fn a_payment_is_held_to_the_payers_terms() {
        let mut a = Agent::new(TermsScope {
            max_transaction_value: Some("100".into()),
            max_daily_spend: Some("150".into()),
            allowed_operations: vec!["payment".into(), "transfer".into()],
            allowed_payment_protocols: vec!["x402".into()],
            ..Default::default()
        });
        check_agent_payment(&a.state, &pay(&a.did, 100), 0).unwrap();
        let over = check_agent_payment(&a.state, &pay(&a.did, 101), 0).unwrap_err();
        assert!(over.contains("per-transaction limit"), "{over}");
        let mut other = pay(&a.did, 1);
        other.protocol = Some("mpp");
        let proto = check_agent_payment(&a.state, &other, 0).unwrap_err();
        assert!(proto.contains("payment protocol"), "{proto}");
        other.protocol = Some("x402");
        other.operation = "bridge";
        let op = check_agent_payment(&a.state, &other, 0).unwrap_err();
        assert!(op.contains("operation"), "{op}");
        // What the agent already spent through its actions counts.
        a.act(&a.action(100), 1).unwrap();
        let day = check_agent_payment(&a.state, &pay(&a.did, 60), 2).unwrap_err();
        assert!(day.contains("daily limit"), "{day}");
        check_agent_payment(&a.state, &pay(&a.did, 50), 2).unwrap();
    }

    #[test]
    fn an_agent_without_terms_has_no_authority_and_a_root_pays_with_its_own_key() {
        let state = crate::StateAdapter::new();
        let refused =
            check_agent_payment(&state, &pay("did:tenzro:agent:nobody", 1), 0).unwrap_err();
        assert!(refused.contains("no approved terms"), "{refused}");
        check_agent_payment(&state, &pay("did:tenzro:human:alice", 1), 0).unwrap();
    }

    mod governance_ballots {
        use super::*;
        use crate::governance::ProposalAction;
        use tenzro_types::agent_terms::{AgentBallot, GovernanceScope, OP_GOVERNANCE_VOTE};

        const STAKE: u128 = 1_000_000;
        const GAS: u128 = 10_000_000_000_000_000_000;

        fn scope(domains: &[&str]) -> TermsScope {
            TermsScope {
                allowed_operations: vec![OP_GOVERNANCE_VOTE.into()],
                max_daily_spend: Some("1000".into()),
                governance: (!domains.is_empty()).then(|| GovernanceScope {
                    domains: domains.iter().map(|d| d.to_string()).collect(),
                    may_vote: true,
                    max_weight_bps: 10_000,
                    ..Default::default()
                }),
                ..Default::default()
            }
        }

        fn bind(state: &mut crate::StateAdapter, addr: &[u8], did: &str) {
            state.set_storage(
                &SYSTEM_ADDRESS,
                identity_wallet_index_key(addr).as_bytes(),
                did.as_bytes().to_vec(),
            );
            state.set_balance(addr, GAS);
        }

        /// The principal's validator and its passkey account in the agent's
        /// world, and a network and a treasury proposal open at 0.
        async fn world(a: &mut Agent) -> (Vec<u8>, Vec<u8>, String, String) {
            let controller = read_agent_terms(&a.state, &a.did)
                .unwrap()
                .terms
                .controller_did;
            let id = controller
                .trim_start_matches("did:tenzro:human:")
                .to_string();
            let validator = vec![0x10u8; 32];
            let operator = vec![0x11u8; 32];
            staking::add_bond(
                &mut a.state,
                &validator,
                STAKE,
                -crate::governance::MIN_BOND_AGE_MS,
            )
            .unwrap();
            let vault = a.state.get_balance(&STAKING_VAULT_ADDRESS);
            a.state.set_balance(&STAKING_VAULT_ADDRESS, vault + STAKE);
            bind(
                &mut a.state,
                &validator,
                &format!("did:tenzro:machine:{id}:v1"),
            );
            bind(&mut a.state, &operator, &controller);
            let recipient = vec![0x12u8; 32];
            bind(&mut a.state, &recipient, "did:tenzro:human:recipient");
            crate::native::payout_gates::approve_grantee_for_test(
                &mut a.state,
                &recipient,
                crate::governance::GranteeClass::Developer,
            );
            let executor = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
            let open = |action: ProposalAction| {
                let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
                data.extend_from_slice(&serde_json::to_vec(&action).unwrap());
                let mut t = VmTransaction::new(
                    validator.clone(),
                    None,
                    0,
                    data,
                    200_000,
                    1_000_000_000,
                    0,
                    crate::VmType::Evm,
                    1337,
                );
                t.block_timestamp_ms = Some(0);
                t
            };
            let network = open(ProposalAction::ParameterChange {
                key: "agent.remote_grant_budget_divisor".into(),
                value: 4,
                memo: "m".into(),
            });
            let treasury = open(ProposalAction::TreasuryGrant {
                recipient: tenzro_types::primitives::Address::from_bytes(&recipient).unwrap(),
                amount: 1,
                memo: "g".into(),
                category: "development".into(),
                link: String::new(),
                tranches: Vec::new(),
                milestones: vec!["milestone".into()],
                vesting: crate::governance::GrantVesting::Liquid,
                asset: None,
                release: Default::default(),
            });
            let n = hex::encode(
                executor
                    .execute_transaction(&network, &mut a.state)
                    .await
                    .unwrap()
                    .output,
            );
            let t = hex::encode(
                executor
                    .execute_transaction(&treasury, &mut a.state)
                    .await
                    .unwrap()
                    .output,
            );
            (validator, operator, n, t)
        }

        fn ballot(a: &Agent, proposal: &str, validator: &[u8], in_favour: bool) -> AgentAction {
            let mut act = a.action(0);
            act.operation = OP_GOVERNANCE_VOTE.into();
            act.counterparty = String::new();
            act.chain = String::new();
            act.ballot = Some(AgentBallot {
                proposal_id: proposal.into(),
                in_favour,
                validator: hex::encode(validator),
            });
            act
        }

        #[tokio::test]
        async fn an_agent_ballot_is_capped_overridden_by_the_principal_and_stepped_up_for_treasury()
        {
            let mut a = Agent::new(scope(&["network", "treasury"]));
            let (validator, operator, network, treasury) = world(&mut a).await;

            // Over the governed per-ballot cap, the rest abstains.
            a.act(&ballot(&a, &network, &validator, true), 10).unwrap();
            let cap = STAKE * crate::governance::DEFAULT_AGENT_WEIGHT_MAX_BPS as u128 / 10_000;
            assert_eq!(load_tally(&a.state, &network).yes, cap);

            // The principal overrides before close, and its ballot stands.
            let executor = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
            let id = hex::decode(&network).unwrap();
            let mut t = VmTransaction::new(
                operator.clone(),
                None,
                0,
                test_vote_data(&id, false, &validator),
                200_000,
                1_000_000_000,
                0,
                crate::VmType::Evm,
                1337,
            );
            t.block_timestamp_ms = Some(20);
            executor
                .execute_transaction(&t, &mut a.state)
                .await
                .expect("principal ballot");
            let tally = load_tally(&a.state, &network);
            assert_eq!((tally.yes, tally.no), (0, STAKE));
            let err = a
                .act(&ballot(&a, &network, &validator, true), 30)
                .unwrap_err();
            assert!(err.contains("principal's own ballot stands"), "{err}");

            // A treasury ballot needs the principal's step-up.
            let err = a
                .act(&ballot(&a, &treasury, &validator, true), 40)
                .unwrap_err();
            assert!(err.contains("step-up"), "{err}");
            let mut stepped = ballot(&a, &treasury, &validator, true);
            stepped.step_up = Some(step_up(&stepped, &passkey()));
            a.act(&stepped, 40).unwrap();
            assert_eq!(load_tally(&a.state, &treasury).yes, cap);
        }

        #[tokio::test]
        async fn an_agent_without_a_governance_scope_or_outside_its_domains_is_refused() {
            let mut a = Agent::new(scope(&[]));
            let (validator, _, network, _) = world(&mut a).await;
            let err = a
                .act(&ballot(&a, &network, &validator, true), 10)
                .unwrap_err();
            assert!(err.contains("no vote"), "{err}");

            let mut b = Agent::new(scope(&["treasury"]));
            let (validator, _, network, _) = world(&mut b).await;
            let err = b
                .act(&ballot(&b, &network, &validator, true), 10)
                .unwrap_err();
            assert!(err.contains("network domain"), "{err}");
        }

        #[tokio::test]
        async fn an_agent_veto_signal_is_scoped_stepped_up_capped_and_paid_back_to_its_wallet() {
            use tenzro_types::agent_terms::OP_GOVERNANCE_VETO_SIGNAL;
            let mut veto_scope = scope(&["treasury"]);
            veto_scope.allowed_operations = vec![OP_GOVERNANCE_VETO_SIGNAL.into()];
            if let Some(g) = veto_scope.governance.as_mut() {
                g.may_vote = false;
                g.may_veto_signal = true;
            }
            let mut a = Agent::new(veto_scope);
            let (_, operator, network, treasury) = world(&mut a).await;
            a.state.record_supply_change(10_000, 0);
            let wallet = agent_wallet(&a.did);
            a.state.set_balance(&wallet, 1_000);
            let signal = |a: &Agent, proposal: &str, amount: u128| {
                let mut act = a.action(0);
                act.operation = OP_GOVERNANCE_VETO_SIGNAL.into();
                act.counterparty = String::new();
                act.chain = String::new();
                act.amount = amount;
                act.veto_signal = Some(proposal.into());
                act
            };

            let err = a.act(&signal(&a, &network, 100), 10).unwrap_err();
            assert!(err.contains("network domain"), "{err}");
            let err = a.act(&signal(&a, &treasury, 100), 10).unwrap_err();
            assert!(err.contains("step-up"), "{err}");

            // The governed agent share (5%) of a 10 000 supply is 500.
            let mut over = signal(&a, &treasury, 600);
            over.step_up = Some(step_up(&over, &passkey()));
            let err = a.act(&over, 10).unwrap_err();
            assert!(err.contains("at most 500"), "{err}");
            let mut ok = signal(&a, &treasury, 400);
            ok.step_up = Some(step_up(&ok, &passkey()));
            a.act(&ok, 10).unwrap();
            assert_eq!(a.state.get_balance(&wallet), 600);
            assert_eq!(
                super::super::veto_escrow::locked_by(&a.state, &treasury, &wallet),
                400
            );

            // No ballot: rejected at close, and anyone returns the lock to the wallet.
            let mut data = super::super::SELECTOR_GOVERNANCE_VETO_WITHDRAW.to_vec();
            data.extend_from_slice(&hex::decode(&treasury).unwrap());
            data.push(32);
            data.extend_from_slice(&wallet);
            let mut t = VmTransaction::new(
                operator,
                None,
                0,
                data,
                200_000,
                1_000_000_000,
                0,
                crate::VmType::Evm,
                1337,
            );
            t.block_timestamp_ms = Some(crate::governance::VOTING_PERIOD_MS);
            let executor = NativeExecutor::new(crate::config::VmConfig::default()).unwrap();
            executor
                .execute_transaction(&t, &mut a.state)
                .await
                .expect("withdraw to the wallet");
            assert_eq!(a.state.get_balance(&wallet), 1_000);
        }
    }
}

/// Agents rooted in a machine's TPM or Secure Enclave key: the same terms,
/// the same checks, the same single verification path as a passkey root.
#[cfg(test)]
mod machine_root_tests {
    use super::tests::{Agent, controller_approval, machine_approval, passkey};
    use super::*;
    use crate::account_keys::set_enrolled_pq_key;
    use tenzro_crypto::composite::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_types::agent_terms::TermsScope;

    fn scope() -> TermsScope {
        TermsScope {
            max_daily_spend: Some("100".into()),
            step_up_above: Some("50".into()),
            allowed_operations: vec!["transfer".into()],
            ..Default::default()
        }
    }

    /// Register `m` on chain as an autonomous machine, its ML-DSA-65 key
    /// enrolled when it has one. Returns its DID.
    fn register(state: &mut crate::StateAdapter, m: &TestHybridSigner) -> String {
        let xy = m.public_key().p256.clone();
        let sec1 = [&[0x04u8][..], &xy].concat();
        let did = tenzro_types::did_derivation::machine_did(&sec1);
        let record = tenzro_types::identity::RegisterIdentityPayload {
            did: did.clone(),
            identity_type: "machine".into(),
            display_name: "root".into(),
            controller_pubkey: sec1,
            key_type: "P-256".into(),
            wallet_id: "w".into(),
            wallet_address: m.address(),
            pq_verifying_key: m.public_key().pq.clone().unwrap_or_default(),
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            &super::super::identity_storage_key(&did),
            serde_json::to_vec(&record).unwrap(),
        );
        state.set_storage(
            &SYSTEM_ADDRESS,
            super::super::identity_wallet_index_key(m.address().as_bytes()).as_bytes(),
            did.clone().into_bytes(),
        );
        if let Some(pq) = m.public_key().pq.clone() {
            set_enrolled_pq_key(state, &xy, pq, &mut Vec::new());
        }
        did
    }

    /// A state where `root` is registered and `terms` under `controller` are
    /// bonded and funded, not yet recorded.
    fn world(root: &TestHybridSigner) -> (crate::StateAdapter, AgentTerms, String) {
        let mut state = crate::StateAdapter::new();
        crate::native::economy::count_wei_as_units_for_tests(&mut state);
        let controller = register(&mut state, root);
        let terms = Agent::terms(controller, scope());
        let did = agent_did(&terms.controller_did, &terms.agent_name).unwrap();
        state.set_balance(
            super::super::derive_bond_vault_address(&did).as_bytes(),
            u128::MAX / 2,
        );
        state.set_balance(&agent_wallet(&did), 1_000_000);
        (state, terms, did)
    }

    #[test]
    fn a_machine_rooted_agent_acts_within_its_terms_and_is_refused_beyond_them() {
        let root = TestHybridSigner::hybrid(21);
        let (mut state, terms, did) = world(&root);
        let approval = machine_approval(OP_DELEGATE_AGENT, &terms.target(None), &root);
        set_terms(&mut state, &terms, None, &approval, 0).unwrap();
        let stored = read_agent_terms(&state, &did).unwrap();
        assert_eq!(stored.root, RootKind::Machine);
        assert!(did.starts_with("did:tenzro:machine:"));

        let mut a = Agent {
            state,
            did,
            key: Agent::node_key(),
        };
        a.act(&a.action(10), 0).unwrap();
        let over = a.act(&a.action(500), 1).unwrap_err();
        assert!(over.contains("daily limit"), "{over}");
        let mut stepped_over = a.action(500);
        stepped_over.step_up = Some(machine_approval(
            OP_AGENT_STEP_UP,
            &stepped_over.digest(),
            &root,
        ));
        let over = a.act(&stepped_over, 1).unwrap_err();
        assert!(
            over.contains("daily limit"),
            "a step-up never lifts a cap: {over}"
        );

        // Held for step-up: the machine root's hardware approval lifts it,
        // a passkey's does not.
        let held = a.act(&a.action(60), 2).unwrap_err();
        assert!(held.contains("step-up required"), "{held}");
        let mut by_passkey = a.action(60);
        by_passkey.step_up = Some(controller_approval(
            OP_AGENT_STEP_UP,
            &by_passkey.digest(),
            &passkey(),
        ));
        assert!(a.act(&by_passkey, 2).is_err(), "only the root approves");
        let mut stepped = a.action(60);
        stepped.step_up = Some(machine_approval(OP_AGENT_STEP_UP, &stepped.digest(), &root));
        a.act(&stepped, 2).unwrap();

        // Tightened by the machine root: the old limit no longer holds.
        let mut tighter = read_agent_terms(&a.state, &a.did).unwrap().terms;
        tighter.delegation_scope.max_daily_spend = Some("75".into());
        let approval = machine_approval(OP_UPDATE_AGENT_TERMS, &tighter.target(Some(false)), &root);
        set_terms(&mut a.state, &tighter, Some(false), &approval, 3).unwrap();
        assert!(
            a.act(&a.action(10), 4).is_err(),
            "70 spent today, 10 more passes 75"
        );

        // Tightened again; replaying the earlier approval must not bring the looser terms back.
        let mut tightest = tighter.clone();
        tightest.delegation_scope.max_daily_spend = Some("50".into());
        let second = machine_approval(OP_UPDATE_AGENT_TERMS, &tightest.target(Some(false)), &root);
        set_terms(&mut a.state, &tightest, Some(false), &second, 5).unwrap();
        assert!(set_terms(&mut a.state, &tighter, Some(false), &approval, 6).is_err());
        assert!(set_terms(&mut a.state, &tightest, Some(false), &second, 7).is_err());
        let stored = read_agent_terms(&a.state, &a.did).unwrap();
        assert_eq!(
            stored.terms.delegation_scope.max_daily_spend.as_deref(),
            Some("50")
        );
    }

    /// The same single oversight path as a passkey root: an action the
    /// terms hold is refused until the machine root's step-up of that exact
    /// action arrives in it (held); with it, it runs (allowed); another key's
    /// step-up is refused; a step-up whose action nonce has passed (expired)
    /// is refused.
    #[test]
    fn a_held_action_proceeds_on_the_machine_roots_step_up_and_nothing_else() {
        let root = TestHybridSigner::hybrid(28);
        let (mut state, mut terms, did) = world(&root);
        terms.delegation_scope.step_up_above = Some("0".into());
        let approval = machine_approval(OP_DELEGATE_AGENT, &terms.target(None), &root);
        set_terms(&mut state, &terms, None, &approval, 0).unwrap();
        let mut a = Agent {
            state,
            did,
            key: Agent::node_key(),
        };

        let held = a.act(&a.action(5), 0).unwrap_err();
        assert!(held.contains("step-up required"), "{held}");

        let mut refused = a.action(5);
        refused.step_up = Some(machine_approval(
            OP_AGENT_STEP_UP,
            &refused.digest(),
            &TestHybridSigner::hybrid(29),
        ));
        assert!(a.act(&refused, 0).is_err(), "another machine's step-up");
        let mut stripped = a.action(5);
        let mut s = machine_approval(OP_AGENT_STEP_UP, &stripped.digest(), &root);
        s.signature.pq = None;
        stripped.step_up = Some(s);
        assert!(
            a.act(&stripped, 0).is_err(),
            "a step-up without the enrolled ML-DSA-65 leg"
        );

        let mut first = a.action(5);
        first.step_up = Some(machine_approval(OP_AGENT_STEP_UP, &first.digest(), &root));
        let mut early = a.action(6);
        early.step_up = Some(machine_approval(OP_AGENT_STEP_UP, &early.digest(), &root));
        a.act(&first, 0).unwrap();
        let expired = a.act(&early, 1).unwrap_err();
        assert!(expired.contains("nonce"), "{expired}");
        let mut fresh = a.action(6);
        fresh.step_up = Some(machine_approval(OP_AGENT_STEP_UP, &fresh.digest(), &root));
        a.act(&fresh, 1).unwrap();
    }

    #[test]
    fn the_ml_dsa_leg_cannot_be_stripped_from_a_machine_roots_approval() {
        let root = TestHybridSigner::hybrid(22);
        let (mut state, terms, _) = world(&root);
        let mut approval = machine_approval(OP_DELEGATE_AGENT, &terms.target(None), &root);
        approval.signature.pq = None;
        let refused = set_terms(&mut state, &terms, None, &approval, 0)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("ML-DSA-65"), "{refused}");
    }

    #[test]
    fn an_approval_signed_for_another_network_is_refused() {
        use tenzro_crypto::composite::SignatureContext;
        let root = TestHybridSigner::hybrid(24);
        let (mut state, terms, _) = world(&root);
        state.set_storage(
            &SYSTEM_ADDRESS,
            super::super::NETWORK_CHAIN_ID_KEY.as_bytes(),
            13380u64.to_le_bytes().to_vec(),
        );
        assert_eq!(super::super::network_chain_id(&state), 13380);
        let target = terms.target(None);
        let signed_for = |chain_id: u64| {
            let nonce = [6u8; 16];
            let account = root.address().as_bytes().to_vec();
            let digest =
                custody_challenge_digest(chain_id, &account, OP_DELEGATE_AGENT, &target, &nonce);
            AgentTermsApproval {
                account,
                nonce,
                root_public_key: root.public_key().p256.clone(),
                signature: root.sign(SignatureContext::AccountOwner, &digest).unwrap(),
            }
        };
        let foreign = signed_for(1337);
        let refused = verify_root_approval(
            &state,
            &terms.controller_did,
            OP_DELEGATE_AGENT,
            &target,
            &foreign,
            0,
        )
        .unwrap_err();
        assert!(refused.contains("does not verify"), "{refused}");
        let own = signed_for(13380);
        verify_root_approval(
            &state,
            &terms.controller_did,
            OP_DELEGATE_AGENT,
            &target,
            &own,
            0,
        )
        .unwrap();
        set_terms(&mut state, &terms, None, &own, 0).unwrap();
    }

    #[test]
    fn a_machine_root_revokes_its_agent_and_the_agent_halts() {
        let root = TestHybridSigner::hybrid(23);
        let (mut state, terms, did) = world(&root);
        let approval = machine_approval(OP_DELEGATE_AGENT, &terms.target(None), &root);
        set_terms(&mut state, &terms, None, &approval, 0).unwrap();
        let mut a = Agent {
            state,
            did: did.clone(),
            key: Agent::node_key(),
        };
        a.act(&a.action(10), 0).unwrap();

        let payload = serde_json::to_vec(&serde_json::json!({
            "agent_did": did,
            "controller_did": terms.controller_did,
            "approval_digest": hex::encode([1u8; 32]),
        }))
        .unwrap();
        // Another account cannot; the machine root's own account can.
        let stranger = TestHybridSigner::hybrid(24);
        assert!(
            super::super::agent_audit::revoke(
                &mut a.state,
                stranger.address().as_bytes(),
                &payload,
                1
            )
            .is_err()
        );
        super::super::agent_audit::revoke(&mut a.state, root.address().as_bytes(), &payload, 1)
            .unwrap();
        let halted = a.act(&a.action(10), 2).unwrap_err();
        assert!(halted.contains("revoked"), "{halted}");
    }

    #[test]
    fn a_machine_cannot_approve_terms_for_another_machines_agent() {
        let owner = TestHybridSigner::hybrid(25);
        let other = TestHybridSigner::hybrid(26);
        let (mut state, terms, _) = world(&owner);
        register(&mut state, &other);
        let target = terms.target(None);
        let forged = machine_approval(OP_DELEGATE_AGENT, &target, &other);
        let refused = set_terms(&mut state, &terms, None, &forged, 0)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("registered with"), "{refused}");

        // The other machine's key presented as the owner's still fails the
        // signature: the key comes from the owner's registration.
        let mut swapped = forged.clone();
        swapped.root_public_key = owner.public_key().p256.clone();
        assert!(set_terms(&mut state, &terms, None, &swapped, 0).is_err());

        // A passkey assertion cannot stand in for a machine root either.
        let mut as_passkey = controller_approval(OP_DELEGATE_AGENT, &target, &passkey());
        as_passkey.root_public_key = owner.public_key().p256.clone();
        assert!(set_terms(&mut state, &terms, None, &as_passkey, 0).is_err());

        // Unregistered or revoked machines root nothing.
        let stranger = TestHybridSigner::hybrid(27);
        let sec1 = [&[0x04u8][..], &stranger.public_key().p256].concat();
        let mut stray = Agent::terms(tenzro_types::did_derivation::machine_did(&sec1), scope());
        stray.agent_name = "stray".into();
        let approval = machine_approval(OP_DELEGATE_AGENT, &stray.target(None), &stranger);
        let refused = set_terms(&mut state, &stray, None, &approval, 0)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("not a machine identity registered"),
            "{refused}"
        );
        state.set_storage(
            &SYSTEM_ADDRESS,
            &super::super::identity_revocation_key(&terms.controller_did),
            vec![1],
        );
        let approval = machine_approval(OP_DELEGATE_AGENT, &target, &owner);
        let refused = set_terms(&mut state, &terms, None, &approval, 0)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("revoked"), "{refused}");

        // A delegated machine (an agent) cannot root another agent.
        assert_eq!(RootKind::of("did:tenzro:machine:aa:bb"), None);
    }

    /// A machine-rooted agent whose terms its root approved at 0.
    fn approved(seed: u8) -> (Agent, TestHybridSigner, AgentTerms) {
        let root = TestHybridSigner::hybrid(seed);
        let (mut state, terms, did) = world(&root);
        let approval = machine_approval(OP_DELEGATE_AGENT, &terms.target(None), &root);
        set_terms(&mut state, &terms, None, &approval, 0).unwrap();
        let a = Agent {
            state,
            did,
            key: Agent::node_key(),
        };
        (a, root, terms)
    }

    #[test]
    fn an_agent_lapses_when_its_root_has_not_renewed_within_the_window() {
        let (mut a, root, terms) = approved(31);
        a.act(&a.action(10), 89 * DAY_MS).unwrap();
        let lapsed = a.act(&a.action(10), 91 * DAY_MS).unwrap_err();
        assert!(lapsed.contains("renewal"), "{lapsed}");
        // The root approves the same terms again: the agent acts again.
        let approval = machine_approval(OP_UPDATE_AGENT_TERMS, &terms.target(Some(false)), &root);
        set_terms(
            &mut a.state,
            &terms,
            Some(false),
            &approval,
            (91 * DAY_MS) as i64,
        )
        .unwrap();
        a.act(&a.action(10), 91 * DAY_MS + 1).unwrap();
    }

    #[test]
    fn a_lapsed_agent_cannot_pay_through_a_payment_protocol() {
        let (a, _, _) = approved(33);
        let counterparty = "11".repeat(32);
        let pay = PaymentProposal {
            payer_did: &a.did,
            operation: "transfer",
            amount: 10,
            counterparty: &counterparty,
            chain: "tenzro",
            protocol: None,
            tainted: false,
        };
        check_agent_payment(&a.state, &pay, 89 * DAY_MS).unwrap();
        let lapsed = check_agent_payment(&a.state, &pay, 91 * DAY_MS).unwrap_err();
        assert!(lapsed.contains("renewal"), "{lapsed}");
    }

    #[test]
    fn the_renewal_window_follows_governance() {
        let (mut a, _, _) = approved(34);
        super::super::set_governed_param_for_test(&mut a.state, "agent.max_unrenewed_ms", DAY_MS);
        a.act(&a.action(10), DAY_MS - 1).unwrap();
        let lapsed = a.act(&a.action(10), DAY_MS).unwrap_err();
        assert!(lapsed.contains("renewal"), "{lapsed}");
    }
}
