//! Remote grants in chain state: an agent's authority on other chains.
//!
//! An agent action with operation `remote_grant` writes a [`RemoteGrant`] at
//! `agent_grant:{did}:{caip2}` once the terms allow it, and lists the chain
//! under `agent_grants:{did}`. The grant's budget uses the agent's daily
//! spend at the rate the controller's own limits set: a budget `b` of an
//! asset limited to `m` per day counts as `b * max_daily_spend / m`, so the
//! grants across every chain and asset never exceed the daily cap. Records,
//! under `SYSTEM_ADDRESS`:
//! - `agent_grant:{did}:{caip2}` — the grant, fixed layout (the bytes an
//!   account on that chain proves under a final state root).
//! - `agent_grants:{did}` — the chains with a grant.
//! - `agent_grant_issue:{did}:{caip2}:{seq}` — what an issue took from the
//!   period counters, so a proven close credits back the unspent part once.
//! - `agent_remote_spent:{did}:{caip19}:{day}` — the asset's daily use, by
//!   grants and by settlement legs on other chains.
//! - `agent_grant_relay:{did}:{caip2}` — the relay deposit and the open
//!   relay duty, if any.
//!
//! Revoking, pausing, quarantining or terminating the agent, or approving new
//! terms, voids every live grant: each is rewritten with `void = 1` and the
//! next `seq`, which any relayer may install on the other chain. Where the
//! chain proves its accounts' reports back through a route, a void opens a
//! relay duty paid from the deposit once the install is proven.

use serde::{Deserialize, Serialize};
use tenzro_types::agent_terms::{AgentAction, parse_amount};
use tenzro_types::omni_account::{AgentAccountChain, Family, omni_address};
use tenzro_types::remote_grant::{
    AccountReport, RemoteGrant, ReportKind, agent_hash, asset_hash, chain_hash, index_key,
    key_leaves, leaf_key, merkle_root,
};

use super::agent_terms::StoredAgentTerms;
use super::funding::{move_balance, read_json, refuse, write_json};
use super::*;

pub const REMOTE_GRANT_TOPIC: &[u8] = b"AgentRemoteGrant";
pub const REMOTE_GRANT_VOID_TOPIC: &[u8] = b"AgentRemoteGrantVoid";
pub const REMOTE_GRANT_SETTLE_TOPIC: &[u8] = b"AgentRemoteGrantSettle";

/// Governed: a grant's lifetime when the terms set none, ms.
pub const PARAM_DEFAULT_TTL: &str = "agent.remote_grant_ttl_ms";
/// Governed: a grant's budget is at most the asset's daily limit over this.
pub const PARAM_BUDGET_DIVISOR: &str = "agent.remote_grant_budget_divisor";
/// Governed: the relay deposit a grant on a chain of each family holds,
/// in micro-TNZO (10^12 wei).
pub const PARAM_RELAY_DEPOSIT_PREFIX: &str = "agent.relay_deposit_utnzo.";
/// The budget divisor when governance has set none: a grant holds at most
/// one hour's share of a day.
pub const DEFAULT_BUDGET_DIVISOR: u64 = 24;
/// The relay deposit when governance has set none, micro-TNZO.
pub const DEFAULT_RELAY_DEPOSIT_UTNZO: u64 = 1_000_000;
const MICRO_TNZO: u128 = 1_000_000_000_000;

fn family_name(f: Family) -> &'static str {
    match f {
        Family::Eip155 => "eip155",
        Family::Solana => "solana",
        Family::Sui => "sui",
        Family::Aptos => "aptos",
        Family::Stellar => "stellar",
        Family::Cosmos => "cosmos",
        Family::Tvm => "tvm",
    }
}

/// The relay deposit a grant on `family` holds, wei.
pub fn relay_deposit(state: &dyn VmState, family: Family) -> u128 {
    let key = format!("{PARAM_RELAY_DEPOSIT_PREFIX}{}", family_name(family));
    network_param(state, &key) as u128 * MICRO_TNZO
}

/// What an issue took from the period counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantIssue {
    pub caip19: String,
    pub budget: String,
    /// The share of the daily spend the grant used, wei.
    pub equivalent: String,
    /// Block time the grant was issued, ms: the rolling windows its use was
    /// counted in.
    pub issued_at_ms: u64,
    /// The targets the grant allows, for building their proofs.
    pub targets: Vec<tenzro_types::remote_grant::RemoteTarget>,
    /// A proven close was credited.
    pub settled: bool,
}

/// The relay deposit of an agent's grant on one chain, and the relay duty it
/// funds once the grant is voided.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRelay {
    /// Wei held in the grant's relay account.
    pub deposit: String,
    /// The void the open duty pays for: its grant seq and duty id.
    pub duty: Option<RelayDuty>,
}

/// The open relay duty of a voided grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDuty {
    /// The grant sequence the install must carry.
    pub seq: u64,
    /// The duty id, hex.
    pub duty_id: String,
}

/// What the issue of grant `seq` of `did` on `caip2` recorded.
pub fn read_grant_issue(
    state: &dyn VmState,
    did: &str,
    caip2: &str,
    seq: u64,
) -> Option<GrantIssue> {
    read_json(state, &issue_key(did, caip2, seq))
}

fn issue_key(did: &str, caip2: &str, seq: u64) -> String {
    format!("agent_grant_issue:{did}:{caip2}:{seq}")
}

/// Rolling window of what `did` used of `caip19` on other chains over the
/// last 24 hours.
fn asset_spent_key(did: &str, caip19: &str) -> String {
    format!("agent_remote_spent_24h:{did}:{caip19}")
}

fn remote_used(state: &dyn VmState, did: &str, caip19: &str, now: u64) -> u128 {
    super::agent_terms::rolling::totals(
        state,
        &asset_spent_key(did, caip19),
        super::agent_terms::rolling::DAY,
        now,
    )
    .amount
}

fn relay_key(did: &str, caip2: &str) -> String {
    format!("agent_grant_relay:{did}:{caip2}")
}

/// The keyless account holding the relay deposit of an agent's grant on a
/// chain.
pub fn relay_account(did: &str, caip2: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&tenzro_types::remote_grant::sha256(&[
        b"tenzro/agent-grant-relay",
        did.as_bytes(),
        b":",
        caip2.as_bytes(),
    ]));
    out
}

/// The grant of `did` on `caip2`, if one was issued.
pub fn read_grant(state: &dyn VmState, did: &str, caip2: &str) -> Option<RemoteGrant> {
    state
        .get_storage(&SYSTEM_ADDRESS, leaf_key(did, caip2).as_bytes())
        .and_then(|b| RemoteGrant::decode(&b).ok())
}

/// The chains `did` holds grants on.
pub fn read_grant_chains(state: &dyn VmState, did: &str) -> Vec<String> {
    read_json(state, &index_key(did)).unwrap_or_default()
}

/// The configuration of `caip2`, if governance installed one.
pub fn read_account_chain(state: &dyn VmState, caip2: &str) -> Option<AgentAccountChain> {
    read_json(state, &AgentAccountChain::storage_key(caip2))
}

pub fn read_grant_relay(state: &dyn VmState, did: &str, caip2: &str) -> GrantRelay {
    read_json(state, &relay_key(did, caip2)).unwrap_or_default()
}

fn write_raw(state: &mut dyn VmState, key: &str, value: Vec<u8>, changes: &mut Vec<StateChange>) {
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), value.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        prior,
        Some(value),
    ));
}

/// `value * num / den`, rounded up.
fn scale_up(value: u128, num: u128, den: u128) -> Option<u128> {
    if den == 0 {
        return None;
    }
    let p = value.checked_mul(num)?;
    Some(p.div_ceil(den))
}

/// The share of the daily spend a grant of `budget` uses, under `terms`:
/// the daily cap and the asset's daily limit set the rate.
pub fn grant_equivalent(
    stored: &StoredAgentTerms,
    caip19: &str,
    budget: u128,
) -> std::result::Result<u128, String> {
    let s = &stored.terms.delegation_scope;
    let limit = s
        .remote_limit(caip19)
        .ok_or("outside the agent's approved terms: asset")?;
    let per_day = parse_amount(Some(&limit.max_per_day))
        .ok()
        .flatten()
        .filter(|v| *v > 0)
        .ok_or("the asset's daily limit is malformed")?;
    let daily = parse_amount(s.max_daily_spend.as_deref())
        .ok()
        .flatten()
        .ok_or("remote grants need the terms' daily spend limit")?;
    scale_up(budget, daily, per_day).ok_or_else(|| "the grant's budget overflows".to_string())
}

/// What an agent's legs on other chains move, summed per CAIP-19 asset.
pub type RemoteUse = Vec<(String, u128)>;

/// Add `amount` of `caip19` to `uses`.
pub fn add_remote_use(
    uses: &mut RemoteUse,
    caip19: &str,
    amount: u128,
) -> std::result::Result<(), String> {
    match uses.iter_mut().find(|(c, _)| c == caip19) {
        Some((_, total)) => *total = total.checked_add(amount).ok_or("the legs overflow")?,
        None => uses.push((caip19.to_string(), amount)),
    }
    Ok(())
}

/// The agent's terms list every asset `uses` moves on another chain, and
/// each stays within the asset's daily limit beside what its grants and
/// legs have already used today.
pub fn check_remote_use(
    state: &dyn VmState,
    stored: &StoredAgentTerms,
    did: &str,
    uses: &RemoteUse,
    now: u64,
) -> std::result::Result<(), String> {
    let s = &stored.terms.delegation_scope;
    for (caip19, amount) in uses {
        let limit = s
            .remote_limit(caip19)
            .ok_or_else(|| format!("outside the agent's approved terms: asset {caip19}"))?;
        let per_day = parse_amount(Some(&limit.max_per_day))
            .ok()
            .flatten()
            .unwrap_or(0);
        let used = remote_used(state, did, caip19, now);
        if used.checked_add(*amount).is_none_or(|t| t > per_day) {
            return Err(format!(
                "outside the agent's approved terms: the daily limit on {caip19}"
            ));
        }
    }
    Ok(())
}

/// What the agent has used of `caip19` in the 24 hours up to `now`.
pub fn read_remote_spent(state: &dyn VmState, did: &str, caip19: &str, now: u64) -> u128 {
    remote_used(state, did, caip19, now)
}

/// Count checked `uses` against each asset's daily limit.
pub(super) fn record_remote_use(
    state: &mut dyn VmState,
    did: &str,
    uses: &RemoteUse,
    now: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    for (caip19, amount) in uses {
        super::agent_terms::rolling::add(
            state,
            &asset_spent_key(did, caip19),
            super::agent_terms::rolling::DAY,
            now,
            *amount,
            0,
            changes,
        )?;
    }
    Ok(())
}

/// Check a `remote_grant` action beyond what the terms check of every
/// action, and return the grant it writes. `now` is the block time.
pub fn check_issue(
    state: &dyn VmState,
    stored: &StoredAgentTerms,
    action: &AgentAction,
    now: u64,
) -> std::result::Result<RemoteGrant, String> {
    let req = action.remote_grant.as_ref().ok_or("not a remote grant")?;
    let caip2 = action.chain.as_str();
    let chain =
        read_account_chain(state, caip2).ok_or_else(|| format!("{caip2} has no agent accounts"))?;
    if !chain.open {
        return Err(format!("agent accounts on {caip2} are not open"));
    }
    let s = &stored.terms.delegation_scope;
    let limit = s
        .remote_limit(&req.caip19)
        .ok_or("outside the agent's approved terms: asset")?;
    let per_day = parse_amount(Some(&limit.max_per_day))
        .ok()
        .flatten()
        .unwrap_or(0);
    let divisor = network_param(state, PARAM_BUDGET_DIVISOR).max(1) as u128;
    if req.budget == 0 || req.budget > per_day / divisor {
        return Err(format!(
            "a grant's budget is 1 to the asset's daily limit over {divisor}"
        ));
    }
    if req.per_action_max == 0 || req.per_action_max > req.budget {
        return Err("a grant's per-action limit is 1 to its budget".into());
    }
    let ttl = s
        .remote_grant_ttl_ms
        .unwrap_or_else(|| network_param(state, PARAM_DEFAULT_TTL));
    if req.ttl_ms == 0 || req.ttl_ms > ttl {
        return Err(format!("a grant lives 1 to {ttl} ms under these terms"));
    }
    let family = Family::of(caip2).ok_or("an unsupported chain")?;
    if family == Family::Aptos && req.payload_hash.is_none() {
        return Err("grants on Aptos are exact: they name the one action they allow".into());
    }
    if req.payload_hash == Some([0u8; 32]) {
        return Err("an exact grant names a non-zero payload hash".into());
    }
    let equivalent = grant_equivalent(stored, &req.caip19, req.budget)?;
    if action.amount != equivalent {
        return Err(format!(
            "a grant of this budget uses {equivalent} of the daily spend, the action states {}",
            action.amount
        ));
    }
    let used = remote_used(state, &action.agent_did, &req.caip19, now);
    if used.saturating_add(req.budget) > per_day {
        return Err("outside the agent's approved terms: the asset's daily limit".into());
    }
    let leaves =
        key_leaves(&stored.terms.serving_nodes).ok_or("a serving node's key is malformed")?;
    let account =
        omni_address(&action.agent_did, caip2, &chain.deployment).map_err(|e| e.to_string())?;
    let daily = parse_amount(s.max_daily_spend.as_deref())
        .ok()
        .flatten()
        .unwrap_or(0);
    let cosign_above = match parse_amount(s.cosign_above.as_deref()).ok().flatten() {
        Some(wei) => wei
            .checked_mul(per_day)
            .map(|p| p / daily.max(1))
            .unwrap_or(u128::MAX),
        None => u128::MAX,
    };
    let seq = read_grant(state, &action.agent_did, caip2)
        .map(|g| g.seq + 1)
        .unwrap_or(1);
    Ok(RemoteGrant {
        chain: chain_hash(caip2),
        account: account.account_word(),
        agent: agent_hash(&action.agent_did),
        terms_version: stored.version,
        seq,
        not_before_ms: now,
        not_after_ms: now + req.ttl_ms,
        asset: asset_hash(&req.caip19),
        budget: req.budget,
        per_action_max: req.per_action_max,
        cosign_above,
        keys_root: merkle_root(&leaves),
        targets_root: req.targets_root(),
        payload_hash: req.payload_hash.unwrap_or([0u8; 32]),
        relay_fee_max: req.relay_fee_max,
        void: false,
    })
}

/// Write the grant a checked `remote_grant` action issues, take the relay
/// deposit, and count the budget against the asset's daily limit. The
/// caller has already counted the action's amount against the daily spend.
pub(super) fn issue(
    state: &mut dyn VmState,
    stored: &StoredAgentTerms,
    action: &AgentAction,
    now: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let grant = check_issue(state, stored, action, now).map_err(refuse)?;
    let req = action.remote_grant.as_ref().expect("checked");
    let did = action.agent_did.as_str();
    let caip2 = action.chain.as_str();
    write_raw(state, &leaf_key(did, caip2), grant.encode(), changes);
    let mut chains = read_grant_chains(state, did);
    if !chains.iter().any(|c| c == caip2) {
        chains.push(caip2.to_string());
        write_json(state, &index_key(did), &chains, changes)?;
    }
    super::agent_terms::rolling::add(
        state,
        &asset_spent_key(did, &req.caip19),
        super::agent_terms::rolling::DAY,
        now,
        req.budget,
        0,
        changes,
    )?;
    write_json(
        state,
        &issue_key(did, caip2, grant.seq),
        &GrantIssue {
            caip19: req.caip19.clone(),
            budget: req.budget.to_string(),
            equivalent: action.amount.to_string(),
            issued_at_ms: now,
            targets: req.targets.clone(),
            settled: false,
        },
        changes,
    )?;
    // The relay deposit is topped up to the governed amount, where the
    // chain proves its accounts' reports and a relay can be paid.
    let chain = read_account_chain(state, caip2).expect("checked");
    if chain.report_route.is_some() {
        let mut relay = read_grant_relay(state, did, caip2);
        let held: u128 = relay.deposit.parse().unwrap_or(0);
        let want = relay_deposit(state, Family::of(caip2).expect("checked"));
        if held < want {
            let wallet = tenzro_types::agent_terms::agent_wallet(did);
            move_balance(
                state,
                &wallet,
                &relay_account(did, caip2),
                want - held,
                changes,
            )?;
            relay.deposit = want.to_string();
            write_json(state, &relay_key(did, caip2), &relay, changes)?;
        }
    }
    let data = serde_json::to_vec(&serde_json::json!({
        "agent_did": did,
        "chain": caip2,
        "seq": grant.seq,
        "asset": req.caip19,
        "budget": req.budget.to_string(),
        "not_after_ms": grant.not_after_ms,
        "exact": grant.is_exact(),
    }))
    .map_err(|e| VmError::Internal(format!("encode grant log: {e}")))?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![REMOTE_GRANT_TOPIC.to_vec()],
        data,
    ));
    Ok(())
}

/// Void every live grant of `did`: each is rewritten with `void = 1` and the
/// next seq. Where the chain proves its accounts' reports, a relay duty paid
/// from the deposit is opened for installing the void there.
pub(super) fn void_all(
    state: &mut dyn VmState,
    did: &str,
    now: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    for caip2 in read_grant_chains(state, did) {
        let Some(mut grant) = read_grant(state, did, &caip2) else {
            continue;
        };
        if grant.void {
            continue;
        }
        grant.void = true;
        grant.seq += 1;
        write_raw(state, &leaf_key(did, &caip2), grant.encode(), changes);
        let relay_duty = match read_account_chain(state, &caip2) {
            Some(chain) if chain.report_route.is_some() => {
                let mut relay = read_grant_relay(state, did, &caip2);
                let deposit: u128 = relay.deposit.parse().unwrap_or(0);
                if deposit > 0 {
                    if let Some(old) = relay.duty.take()
                        && let Some(old) = hex::decode(&old.duty_id)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    {
                        super::duty::close(state, &old, changes)?;
                    }
                    let vault = relay_account(did, &caip2);
                    let kind = tenzro_types::duty::DutyKind::GrantRelay {
                        agent_did: did.to_string(),
                        chain: caip2.clone(),
                        seq: grant.seq,
                    };
                    let id = hex::encode(super::duty::open(
                        state, kind, vault, vault, deposit, now as i64, None, changes,
                    )?);
                    relay.duty = Some(RelayDuty {
                        seq: grant.seq,
                        duty_id: id.clone(),
                    });
                    write_json(state, &relay_key(did, &caip2), &relay, changes)?;
                    Some(id)
                } else {
                    None
                }
            }
            _ => None,
        };
        let data = serde_json::to_vec(&serde_json::json!({
            "agent_did": did,
            "chain": caip2,
            "seq": grant.seq,
            "relay_duty": relay_duty,
            "stops_by_ms": grant.not_after_ms,
        }))
        .map_err(|e| VmError::Internal(format!("encode void log: {e}")))?;
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![REMOTE_GRANT_VOID_TOPIC.to_vec()],
            data,
        ));
    }
    Ok(())
}

/// What a relayer submits to settle: a delivery on the chain's report route
/// carrying one account report.
#[derive(Debug, Clone, Deserialize)]
pub struct SettlePayload {
    pub agent_did: String,
    pub chain: String,
    #[serde(with = "tenzro_types::remote_grant::hex_bytes")]
    pub delivery: Vec<u8>,
}

/// Settle one account report proven through the chain's report route: a
/// close credits the unspent budget back to the period counters once, an
/// action is added to the agent's remote audit trail, and an installed void
/// pays the open relay duty.
pub(super) fn settle(
    state: &mut dyn VmState,
    chain_id: u64,
    now: i64,
    payload: &SettlePayload,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let mut changes = Vec::new();
    let did = payload.agent_did.as_str();
    let (report, _) = admit_report(
        state,
        chain_id,
        now,
        did,
        &payload.chain,
        &payload.delivery,
        &mut changes,
    )?;
    let what = match &report.kind {
        ReportKind::Closed { spent } => {
            let key = issue_key(did, &payload.chain, report.seq);
            let mut issue: GrantIssue =
                read_json(state, &key).ok_or_else(|| refuse("no such grant was issued"))?;
            if issue.settled {
                return Err(refuse("the grant's close was already settled"));
            }
            let budget: u128 = issue.budget.parse().unwrap_or(0);
            let equivalent: u128 = issue.equivalent.parse().unwrap_or(0);
            if *spent > budget {
                return Err(refuse("the report spends more than the grant's budget"));
            }
            let unspent = budget - spent;
            let unspent_equivalent = equivalent.saturating_mul(unspent) / budget.max(1);
            let credits = [
                (
                    super::agent_terms::spent_day_key(did),
                    super::agent_terms::rolling::DAY,
                    unspent_equivalent,
                ),
                (
                    super::agent_terms::spent_hour_key(did),
                    super::agent_terms::rolling::HOUR,
                    unspent_equivalent,
                ),
                (
                    asset_spent_key(did, &issue.caip19),
                    super::agent_terms::rolling::DAY,
                    unspent,
                ),
            ];
            let now_ms = now.max(0) as u64;
            for (k, span, credit) in credits {
                super::agent_terms::rolling::credit(
                    state,
                    &k,
                    span,
                    now_ms,
                    issue.issued_at_ms,
                    credit,
                    &mut changes,
                )?;
            }
            issue.settled = true;
            write_json(state, &key, &issue, &mut changes)?;
            serde_json::json!({"closed": report.seq, "unspent": unspent.to_string()})
        }
        ReportKind::Acted {
            nonce,
            digest,
            amount,
        } => {
            let key =
                super::agent_audit::remote_action_key(did, &payload.chain, report.seq, *nonce);
            let entry = super::agent_audit::RemoteActionEntry {
                digest: hex::encode(digest),
                amount: amount.to_string(),
                recorded_at_ms: now,
            };
            super::agent_audit::record_remote_action(state, &key, &entry, &mut changes)?;
            serde_json::json!({"acted": report.seq, "nonce": nonce})
        }
        ReportKind::Paid { .. } => {
            return Err(refuse("a payment report is recorded as a proven payment"));
        }
        ReportKind::Synced { void, payee } => {
            let mut relay = read_grant_relay(state, did, &payload.chain);
            let duty = relay
                .duty
                .clone()
                .filter(|t| *void && t.seq == report.seq)
                .ok_or_else(|| refuse("no relay duty waits for this install"))?;
            let id: [u8; 32] = hex::decode(&duty.duty_id)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| VmError::Internal("corrupt relay duty id".into()))?;
            if !super::duty::pay(state, &id, payee, &mut changes)? {
                return Err(refuse("the relay duty is no longer open"));
            }
            relay.duty = None;
            relay.deposit = "0".into();
            write_json(state, &relay_key(did, &payload.chain), &relay, &mut changes)?;
            serde_json::json!({"relayed_void": report.seq, "duty_id": duty.duty_id})
        }
    };
    let data = serde_json::to_vec(
        &serde_json::json!({"agent_did": did, "chain": payload.chain, "report": what}),
    )
    .map_err(|e| VmError::Internal(format!("encode settle log: {e}")))?;
    Ok((
        changes,
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![REMOTE_GRANT_SETTLE_TOPIC.to_vec()],
            data,
        )],
    ))
}

/// Admit one report of `did`'s account on `caip2` through the chain's
/// report route, checking it is of that agent, account and chain. Returns
/// the report and the chain's name on the route.
fn admit_report(
    state: &mut dyn VmState,
    chain_id: u64,
    now: i64,
    did: &str,
    caip2: &str,
    delivery: &[u8],
    changes: &mut Vec<StateChange>,
) -> Result<(AccountReport, String)> {
    let chain = read_account_chain(state, caip2)
        .ok_or_else(|| refuse(format!("{caip2} has no agent accounts")))?;
    let route = chain.report_route.clone().ok_or_else(|| {
        refuse(format!(
            "{caip2} proves no account reports; a grant there counts as spent"
        ))
    })?;
    let route_chain = route.source_chain.to_ascii_lowercase();
    let epoch = super::rewards::read_reward_state(state)?.current_epoch;
    let body = {
        let mut view = super::bridge::VmRouteState::new(state, chain_id, now, epoch);
        let (_, body) = super::bridge::route_framework()
            .admit_message(&mut view, route.adapter, &route_chain, delivery)
            .map_err(|e| refuse(format!("report delivery refused: {e}")))?;
        changes.extend(view.into_changes());
        body
    };
    let report = AccountReport::decode(&body)
        .ok_or_else(|| refuse("the delivery is not an account report"))?;
    let account = omni_address(did, caip2, &chain.deployment).map_err(|e| refuse(e.to_string()))?;
    if report.chain != chain_hash(caip2)
        || report.agent != agent_hash(did)
        || report.account != account.account_word()
    {
        return Err(refuse("the report is of another agent, account or chain"));
    }
    Ok((report, route_chain))
}

/// A payment an agent's account made on another chain, as its proven
/// report states it.
pub(crate) struct ProvenPayment {
    /// The paying account on the chain, CAIP-10.
    pub payer: String,
    /// The payee on Tenzro.
    pub payee: Address,
    /// What it paid for.
    pub binding: tenzro_types::payment_authorization::PaymentBinding,
    /// Amount, in the asset's smallest unit.
    pub amount: u128,
    /// The grant's asset, CAIP-19.
    pub asset: String,
    /// Unique per account: grant and action.
    pub nonce: String,
    /// The chain's name on its report route.
    pub route_chain: String,
}

/// Admit `did`'s account's `Paid` report on `caip2`: the account itself
/// reported the payment, under a grant this chain issued it, in that grant's
/// asset and within its budget.
pub(crate) fn proven_payment(
    state: &mut dyn VmState,
    chain_id: u64,
    now: i64,
    did: &str,
    caip2: &str,
    delivery: &[u8],
    changes: &mut Vec<StateChange>,
) -> Result<ProvenPayment> {
    let (report, route_chain) = admit_report(state, chain_id, now, did, caip2, delivery, changes)?;
    let ReportKind::Paid {
        nonce,
        payee,
        binding,
        amount,
    } = report.kind
    else {
        return Err(refuse("the report is not a payment"));
    };
    let issue: GrantIssue = read_json(state, &issue_key(did, caip2, report.seq))
        .ok_or_else(|| refuse("no such grant was issued"))?;
    if amount > issue.budget.parse::<u128>().unwrap_or(0) {
        return Err(refuse("the payment is more than its grant's budget"));
    }
    let chain = read_account_chain(state, caip2)
        .ok_or_else(|| refuse(format!("{caip2} has no agent accounts")))?;
    let account = omni_address(did, caip2, &chain.deployment).map_err(|e| refuse(e.to_string()))?;
    Ok(ProvenPayment {
        payer: account.caip10(),
        payee: Address::new(payee),
        binding,
        amount,
        asset: issue.caip19,
        nonce: format!("{}:{}:{nonce}", hex::encode(report.account), report.seq),
        route_chain,
    })
}

#[cfg(test)]
mod tests {
    use super::super::agent_terms::tests::{Agent, passkey, step_up};
    use super::*;
    use crate::VmConfig;
    use crate::VmType;
    use k256::ecdsa::signature::hazmat::PrehashSigner as _;
    use tenzro_bridge::route::attestation::{Delivery, MemberSignature, attestation_digest};
    use tenzro_types::agent_terms::{RemoteLimit, TermsScope};
    use tenzro_types::bridge_route::{
        BridgeRoute, BridgeRouteAdapter, ChainFamily, MintRateLimit, VerifierMember, VerifierQuorum,
    };
    use tenzro_types::omni_account::{AccountDeployment, ReportRoute};
    use tenzro_types::remote_grant::{RemoteGrantRequest, payload_hash};

    const BASE: &str = "eip155:8453";
    const ETH: &str = "eip155:1";
    const APTOS: &str = "aptos:1";
    const USDC_BASE: &str = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
    const USDC_ETH: &str = "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    const APT: &str = "aptos:1/coin:0x1::aptos_coin::AptosCoin";
    const T0: u64 = 1_800_000_000_000;
    const CHAIN_ID: u64 = 1337;

    fn evm() -> AccountDeployment {
        AccountDeployment::Eip155 {
            factory: [0x42; 20],
            init_code_hash: [0x24; 32],
        }
    }

    fn scope() -> TermsScope {
        let limit = |a: &str| RemoteLimit {
            caip19: a.into(),
            max_per_day: "2400".into(),
        };
        TermsScope {
            max_daily_spend: Some("2400".into()),
            allowed_operations: vec!["remote_grant".into()],
            allowed_chains: vec![BASE.into(), ETH.into(), APTOS.into()],
            remote_limits: vec![limit(USDC_BASE), limit(USDC_ETH), limit(APT)],
            ..Default::default()
        }
    }

    fn install(
        state: &mut dyn VmState,
        caip2: &str,
        deployment: AccountDeployment,
        report: Option<ReportRoute>,
    ) {
        let chain = AgentAccountChain {
            caip2: caip2.into(),
            deployment,
            open: true,
            report_route: report,
        };
        write_json(
            state,
            &AgentAccountChain::storage_key(caip2),
            &chain,
            &mut Vec::new(),
        )
        .unwrap();
    }

    fn agent(scope: TermsScope) -> Agent {
        let mut a = Agent::new(scope);
        install(&mut a.state, BASE, evm(), None);
        install(&mut a.state, ETH, evm(), None);
        install(
            &mut a.state,
            APTOS,
            AccountDeployment::Aptos {
                creator: [0x33; 32],
            },
            None,
        );
        a
    }

    fn request(asset: &str, budget: u128) -> RemoteGrantRequest {
        RemoteGrantRequest {
            caip19: asset.into(),
            budget,
            per_action_max: budget,
            ttl_ms: 600_000,
            targets: vec![],
            payload_hash: None,
            relay_fee_max: 5,
        }
    }

    fn grant_action(a: &Agent, chain: &str, req: RemoteGrantRequest) -> AgentAction {
        let stored = super::super::agent_terms::read_agent_terms(&a.state, &a.did).unwrap();
        let mut act = a.action(0);
        act.operation = "remote_grant".into();
        act.counterparty = String::new();
        act.chain = chain.into();
        act.amount = grant_equivalent(&stored, &req.caip19, req.budget).unwrap();
        act.remote_grant = Some(req);
        act
    }

    #[test]
    fn a_grant_is_written_where_accounts_prove_it_and_uses_the_daily_spend() {
        let mut a = agent(scope());
        let act = grant_action(&a, BASE, request(USDC_BASE, 100));
        assert_eq!(act.amount, 100);
        a.act(&act, T0).unwrap();
        let g = read_grant(&a.state, &a.did, BASE).unwrap();
        let account = omni_address(&a.did, BASE, &evm()).unwrap();
        assert_eq!(
            (g.seq, g.void, g.budget, g.not_after_ms),
            (1, false, 100, T0 + 600_000)
        );
        assert_eq!(g.account, account.account_word());
        assert_eq!(g.chain, chain_hash(BASE));
        assert_eq!(g.cosign_above, u128::MAX);
        let stored = super::super::agent_terms::read_agent_terms(&a.state, &a.did).unwrap();
        assert_eq!(
            g.keys_root,
            merkle_root(&key_leaves(&stored.terms.serving_nodes).unwrap())
        );
        assert_eq!(
            super::super::agent_terms::read_agent_spent(&a.state, &a.did, T0),
            100
        );
        assert_eq!(read_grant_chains(&a.state, &a.did), vec![BASE.to_string()]);
        // The bytes sit where the state tree keys the grant.
        let raw = a
            .state
            .get_storage(&SYSTEM_ADDRESS, leaf_key(&a.did, BASE).as_bytes())
            .unwrap();
        assert_eq!(RemoteGrant::decode(&raw).unwrap(), g);
    }

    #[test]
    fn a_budget_above_the_governed_share_of_the_day_is_refused() {
        let mut a = agent(scope());
        let act = grant_action(&a, BASE, request(USDC_BASE, 101));
        let e = a.act(&act, T0).unwrap_err();
        assert!(e.contains("daily limit over 24"), "{e}");
    }

    #[test]
    fn grants_on_two_chains_cannot_exceed_the_daily_cap() {
        let mut a = agent(scope());
        a.state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(PARAM_BUDGET_DIVISOR).as_bytes(),
            1u64.to_le_bytes().to_vec(),
        );
        a.act(&grant_action(&a, BASE, request(USDC_BASE, 2_000)), T0)
            .unwrap();
        let second = grant_action(&a, ETH, request(USDC_ETH, 401));
        let e = a.act(&second, T0).unwrap_err();
        assert!(e.contains("daily limit"), "{e}");
        a.act(&grant_action(&a, ETH, request(USDC_ETH, 400)), T0)
            .unwrap();
        assert_eq!(
            super::super::agent_terms::read_agent_spent(&a.state, &a.did, T0),
            2_400
        );
    }

    #[test]
    fn a_stated_share_that_is_not_the_budgets_is_refused() {
        let mut a = agent(scope());
        let mut act = grant_action(&a, BASE, request(USDC_BASE, 100));
        act.amount = 1;
        assert!(
            a.act(&act, T0)
                .unwrap_err()
                .contains("uses 100 of the daily spend")
        );
    }

    #[test]
    fn an_exact_grant_above_step_up_needs_the_controllers_assertion() {
        let mut s = scope();
        s.step_up_above = Some("50".into());
        let mut a = agent(s);
        let mut req = request(USDC_BASE, 100);
        req.payload_hash = Some([7; 32]);
        let mut act = grant_action(&a, BASE, req);
        let e = a.act(&act, T0).unwrap_err();
        assert!(e.contains("step-up"), "{e}");
        act.step_up = Some(step_up(&act, &passkey()));
        a.act(&act, T0).unwrap();
        assert!(read_grant(&a.state, &a.did, BASE).unwrap().is_exact());
    }

    #[test]
    fn aptos_takes_exact_grants_only() {
        let mut a = agent(scope());
        let e = a
            .act(&grant_action(&a, APTOS, request(APT, 100)), T0)
            .unwrap_err();
        assert!(e.contains("exact"), "{e}");
        let mut req = request(APT, 100);
        req.payload_hash = Some(payload_hash(&tenzro_types::remote_grant::RemoteAction {
            target: b"0x1::aptos_account".to_vec(),
            selector: b"transfer".to_vec(),
            amount: 100,
            relay_refund: 0,
            data: vec![],
        }));
        a.act(&grant_action(&a, APTOS, req), T0).unwrap();
    }

    #[test]
    fn a_chain_not_listed_in_the_terms_or_not_open_is_refused() {
        let mut s = scope();
        s.allowed_chains = vec![ETH.into()];
        let mut a = agent(s);
        assert!(
            a.act(&grant_action(&a, BASE, request(USDC_BASE, 100)), T0)
                .unwrap_err()
                .contains("remote grant")
        );
        let mut a = agent(scope());
        let chain = AgentAccountChain {
            caip2: BASE.into(),
            deployment: evm(),
            open: false,
            report_route: None,
        };
        write_json(
            &mut a.state,
            &AgentAccountChain::storage_key(BASE),
            &chain,
            &mut Vec::new(),
        )
        .unwrap();
        assert!(
            a.act(&grant_action(&a, BASE, request(USDC_BASE, 100)), T0)
                .unwrap_err()
                .contains("not open")
        );
    }

    #[test]
    fn the_sequence_rises_with_every_grant_and_every_void() {
        let mut a = agent(scope());
        a.act(&grant_action(&a, BASE, request(USDC_BASE, 50)), T0)
            .unwrap();
        a.act(&grant_action(&a, BASE, request(USDC_BASE, 50)), T0)
            .unwrap();
        assert_eq!(read_grant(&a.state, &a.did, BASE).unwrap().seq, 2);
        void_all(&mut a.state, &a.did, T0, &mut Vec::new(), &mut Vec::new()).unwrap();
        let g = read_grant(&a.state, &a.did, BASE).unwrap();
        assert_eq!((g.seq, g.void), (3, true));
        // A void grant stays void.
        void_all(&mut a.state, &a.did, T0, &mut Vec::new(), &mut Vec::new()).unwrap();
        assert_eq!(read_grant(&a.state, &a.did, BASE).unwrap().seq, 3);
    }

    fn granted() -> Agent {
        let mut a = agent(scope());
        a.act(&grant_action(&a, BASE, request(USDC_BASE, 50)), T0)
            .unwrap();
        a.act(&grant_action(&a, ETH, request(USDC_ETH, 50)), T0)
            .unwrap();
        a
    }

    fn all_void(a: &Agent) -> bool {
        [BASE, ETH].iter().all(|c| {
            let raw = a
                .state
                .get_storage(&SYSTEM_ADDRESS, leaf_key(&a.did, c).as_bytes())
                .unwrap();
            let g = RemoteGrant::decode(&raw).unwrap();
            g.void && g.seq == 2
        })
    }

    /// Runs a call from the controller's registered wallet.
    async fn run(a: &mut Agent, selector: [u8; 4], payload: serde_json::Value) {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let from = vec![0xAB; 32];
        let wallet = super::super::identity_wallet_index_key(&from);
        let controller_did = controller(a);
        a.state.set_storage(
            &SYSTEM_ADDRESS,
            wallet.as_bytes(),
            controller_did.into_bytes(),
        );
        a.state.set_balance(&from, 1_000_000_000_000_000_000_000);
        let mut data = selector.to_vec();
        data.extend(serde_json::to_vec(&payload).unwrap());
        let mut t = VmTransaction::new(
            from,
            None,
            0,
            data,
            5_000_000,
            0,
            0,
            VmType::Tenzro,
            CHAIN_ID,
        );
        t.block_timestamp_ms = Some(T0 as i64);
        let r = ex.execute_transaction(&t, &mut a.state).await.unwrap();
        assert!(r.success, "{:?}", r);
    }

    fn controller(a: &Agent) -> String {
        super::super::agent_terms::read_agent_terms(&a.state, &a.did)
            .unwrap()
            .terms
            .controller_did
    }

    #[tokio::test]
    async fn pausing_the_agent_voids_its_grants() {
        let mut a = granted();
        let p = serde_json::json!({"agent_did": a.did, "controller_did": controller(&a), "reason_code": 1});
        run(&mut a, SELECTOR_KILLSWITCH_PAUSE, p).await;
        assert!(all_void(&a));
    }

    #[tokio::test]
    async fn terminating_the_agent_voids_its_grants() {
        let mut a = granted();
        let p = serde_json::json!({"agent_did": a.did, "controller_did": controller(&a), "reason_code": 1, "slash_bps": 0});
        run(&mut a, SELECTOR_KILLSWITCH_TERMINATE, p).await;
        assert!(all_void(&a));
    }

    #[test]
    fn a_quarantine_voids_its_grants() {
        let mut a = granted();
        let q = super::super::agent_audit::AgentQuarantine {
            controller_did: controller(&a),
            by: "validators".into(),
            reason_code: 0,
            evidence_hash: None,
            at_ms: T0 as i64,
            revoked: false,
        };
        let did = a.did.clone();
        super::super::agent_audit::impose(&mut a.state, &did, &q, &mut Vec::new(), &mut Vec::new())
            .unwrap();
        assert!(all_void(&a));
    }

    #[test]
    fn revoking_the_agent_voids_its_grants() {
        let mut a = granted();
        let from = vec![0xCC; 32];
        a.state.set_storage(
            &SYSTEM_ADDRESS,
            format!("identity_wallet:{}", hex::encode(&from)).as_bytes(),
            controller(&a).into_bytes(),
        );
        let p = serde_json::json!({"agent_did": a.did, "controller_did": controller(&a), "approval_digest": hex::encode([1u8; 32])});
        let (_, logs) = super::super::agent_audit::revoke(
            &mut a.state,
            &from,
            &serde_json::to_vec(&p).unwrap(),
            T0 as i64,
        )
        .unwrap();
        assert!(all_void(&a));
        assert_eq!(
            logs.iter()
                .filter(|l| l.topics[0] == REMOTE_GRANT_VOID_TOPIC)
                .count(),
            2
        );
    }

    #[test]
    fn a_scope_change_on_renewal_voids_remote_grants() {
        let mut a = granted();
        let mut terms = super::super::agent_terms::read_agent_terms(&a.state, &a.did)
            .unwrap()
            .terms;
        terms.delegation_scope.max_daily_spend = Some("90".into());
        let approval = super::super::agent_terms::tests::controller_approval(
            tenzro_types::agent_terms::OP_UPDATE_AGENT_TERMS,
            &terms.target(Some(false)),
            &passkey(),
        );
        let (_, logs) = super::super::agent_terms::set_terms(
            &mut a.state,
            &terms,
            Some(false),
            &approval,
            T0 as i64,
        )
        .unwrap();
        assert!(all_void(&a));
        assert_eq!(
            logs.iter()
                .filter(|l| l.topics[0] == REMOTE_GRANT_VOID_TOPIC)
                .count(),
            2
        );
    }

    #[test]
    fn a_renewal_that_only_extends_expiry_keeps_remote_grants() {
        let mut a = granted();
        let terms = super::super::agent_terms::read_agent_terms(&a.state, &a.did)
            .unwrap()
            .terms;
        let approval = super::super::agent_terms::tests::controller_approval(
            tenzro_types::agent_terms::OP_UPDATE_AGENT_TERMS,
            &terms.target(Some(false)),
            &passkey(),
        );
        let (_, logs) = super::super::agent_terms::set_terms(
            &mut a.state,
            &terms,
            Some(false),
            &approval,
            T0 as i64,
        )
        .unwrap();
        assert!(logs.iter().all(|l| l.topics[0] != REMOTE_GRANT_VOID_TOPIC));
        for c in [BASE, ETH] {
            let raw = a
                .state
                .get_storage(&SYSTEM_ADDRESS, leaf_key(&a.did, c).as_bytes())
                .unwrap();
            assert!(!RemoteGrant::decode(&raw).unwrap().void);
        }
    }

    // Reports through a route: a committee-attested route stands in for the
    // chain's light client here.

    fn member(seed: u8) -> k256::ecdsa::SigningKey {
        k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn member_address(sk: &k256::ecdsa::SigningKey) -> [u8; 20] {
        let point = sk.verifying_key().to_sec1_point(false);
        let h = <sha3::Keccak256 as sha2::Digest>::digest(&point.as_bytes()[1..]);
        h[12..].try_into().unwrap()
    }

    fn quorum(seed: u8, label: &str) -> (Vec<k256::ecdsa::SigningKey>, VerifierQuorum) {
        let keys: Vec<_> = (0..5).map(|i| member(seed + i)).collect();
        let q = VerifierQuorum {
            set_index: 0,
            size: keys.len() as u32,
            members: keys
                .iter()
                .enumerate()
                .map(|(i, k)| VerifierMember {
                    address: member_address(k),
                    pq_public_key: tenzro_bridge::route::attestation::testing::pq_key(
                        &k.to_bytes(),
                    )
                    .verifying_key_bytes()
                    .to_vec(),
                    operator: format!("{label}-op-{i}"),
                    rpc_provider: format!("{label}-rpc-{i}"),
                })
                .collect(),
            threshold: 3,
        };
        (keys, q)
    }

    /// A CCIP route from Ethereum with a verifier and a blessing committee.
    fn report_route() -> (
        BridgeRoute,
        Vec<k256::ecdsa::SigningKey>,
        Vec<k256::ecdsa::SigningKey>,
    ) {
        let (verifiers, vq) = quorum(1, "verifier");
        let (blessing, bq) = quorum(40, "blessing");
        let ethereum = tenzro_bridge::route::evm::EVM_CHAINS
            .iter()
            .find(|c| c.name == "ethereum")
            .unwrap();
        let mut pad = [0u8; 32];
        pad[12..].copy_from_slice(&[0x52; 20]);
        let route = BridgeRoute {
            adapter: BridgeRouteAdapter::Ccip,
            family: ChainFamily::Evm,
            source_chain: "ethereum".into(),
            source_chain_id: ethereum.selector,
            local_selector: 7_777,
            peer: pad,
            ramp: pad,
            local_endpoint: [0xCD; 32],
            remote_token: pad,
            verifiers: vq,
            blessing: Some(bq),
            light_client: None,
            mint_limit: MintRateLimit {
                per_mint: 10_000,
                per_epoch: 10_000,
            },
            ibc: None,
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
            outflow: tenzro_types::bridge_route::LaneRateLimit {
                capacity: 10_000,
                rate: 100,
            },
            lane_limits: Some(tenzro_types::bridge_route::CcipLane {
                version: tenzro_types::bridge_route::CcipLaneVersion::V1_6,
                off_ramp: [0u8; 20],
                ccv_and_executor_hash: [0u8; 32],
                inbound: tenzro_types::bridge_route::LaneRateLimit {
                    capacity: 10_000,
                    rate: 100,
                },
            }),
        };
        route.validate().unwrap();
        (route, verifiers, blessing)
    }

    fn sign_all(
        keys: &[k256::ecdsa::SigningKey],
        digest: &[u8; 32],
        n: usize,
    ) -> Vec<MemberSignature> {
        keys.iter()
            .take(n)
            .map(|k| {
                let (sig, rec): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
                    k.sign_prehash(digest).unwrap();
                let mut out = [0u8; 65];
                out[..64].copy_from_slice(&sig.to_bytes());
                out[64] = rec.to_byte();
                (member_address(k), out) as MemberSignature
            })
            .collect()
    }

    type Committees = (
        BridgeRoute,
        Vec<k256::ecdsa::SigningKey>,
        Vec<k256::ecdsa::SigningKey>,
    );

    fn deliver_n(c: &Committees, nonce: u64, body: Vec<u8>, signers: usize) -> Vec<u8> {
        let mut d = Delivery {
            dest_chain_id: CHAIN_ID,
            nonce,
            expiry_ms: T0 as i64 + 60_000,
            body,
            proof: vec![],
            committee: vec![],
            committee_pq: vec![],
            blessing: vec![],
            blessing_pq: vec![],
        };
        let digest = attestation_digest(&c.0, &d);
        d.committee = sign_all(&c.1, &digest, signers);
        d.blessing = sign_all(&c.2, &digest, signers);
        let pq = |keys: &[k256::ecdsa::SigningKey]| {
            keys.iter()
                .take(signers)
                .map(|k| {
                    tenzro_bridge::route::attestation::testing::sign_leg(
                        &k.to_bytes(),
                        member_address(k),
                        &digest,
                    )
                })
                .collect::<Vec<_>>()
        };
        d.committee_pq = pq(&c.1);
        d.blessing_pq = pq(&c.2);
        d.encode()
    }

    fn deliver(c: &Committees, nonce: u64, body: Vec<u8>) -> Vec<u8> {
        deliver_n(c, nonce, body, 3)
    }

    const SUI: &str = ETH;
    const SUI_USDC: &str = USDC_ETH;

    fn reporting_agent() -> (Agent, Committees) {
        let mut a = agent(scope());
        let c = report_route();
        a.state.set_storage(
            &SYSTEM_ADDRESS,
            c.0.storage_key().as_bytes(),
            serde_json::to_vec(&c.0).unwrap(),
        );
        install(
            &mut a.state,
            ETH,
            evm(),
            Some(ReportRoute {
                adapter: BridgeRouteAdapter::Ccip,
                source_chain: "ethereum".into(),
            }),
        );
        let wallet = tenzro_types::agent_terms::agent_wallet(&a.did);
        a.state.set_balance(&wallet, 10_000_000_000_000_000_000);
        (a, c)
    }

    fn report(a: &Agent, seq: u64, kind: ReportKind) -> Vec<u8> {
        let account = omni_address(&a.did, SUI, &evm()).unwrap();
        AccountReport {
            chain: chain_hash(SUI),
            account: account.account_word(),
            agent: agent_hash(&a.did),
            seq,
            kind,
        }
        .encode()
    }

    fn settle_with(a: &mut Agent, delivery: Vec<u8>) -> std::result::Result<(), String> {
        let p = SettlePayload {
            agent_did: a.did.clone(),
            chain: SUI.into(),
            delivery,
        };
        settle(&mut a.state, CHAIN_ID, T0 as i64 + 1_000, &p)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn a_proven_close_credits_the_unspent_budget_once() {
        let (mut a, c) = reporting_agent();
        a.act(&grant_action(&a, SUI, request(SUI_USDC, 100)), T0)
            .unwrap();
        assert_eq!(
            super::super::agent_terms::read_agent_spent(&a.state, &a.did, T0),
            100
        );
        let body = report(&a, 1, ReportKind::Closed { spent: 30 });
        settle_with(&mut a, deliver(&c, 1, body.clone())).unwrap();
        assert_eq!(
            super::super::agent_terms::read_agent_spent(&a.state, &a.did, T0),
            30
        );
        let e = settle_with(&mut a, deliver(&c, 2, body)).unwrap_err();
        assert!(e.contains("already settled"), "{e}");
    }

    #[test]
    fn a_forged_or_misdirected_report_is_refused() {
        let (mut a, c) = reporting_agent();
        a.act(&grant_action(&a, SUI, request(SUI_USDC, 100)), T0)
            .unwrap();
        let body = report(&a, 1, ReportKind::Closed { spent: 0 });
        // Signed by one member only: below the committee's threshold.
        assert!(
            settle_with(&mut a, deliver_n(&c, 1, body.clone(), 1))
                .unwrap_err()
                .contains("refused")
        );
        // Of another account.
        let mut other = AccountReport::decode(&body).unwrap();
        other.account = [9; 32];
        assert!(
            settle_with(&mut a, deliver(&c, 2, other.encode()))
                .unwrap_err()
                .contains("another agent")
        );
        // Spending past the budget.
        let over = report(&a, 1, ReportKind::Closed { spent: 101 });
        assert!(
            settle_with(&mut a, deliver(&c, 3, over))
                .unwrap_err()
                .contains("more than")
        );
        // The same delivery twice: its nonce is spent.
        let ok = deliver(&c, 4, report(&a, 1, ReportKind::Closed { spent: 1 }));
        settle_with(&mut a, ok.clone()).unwrap();
        assert!(settle_with(&mut a, ok).is_err());
    }

    #[test]
    fn a_proven_action_joins_the_audit_trail_once() {
        let (mut a, c) = reporting_agent();
        a.act(&grant_action(&a, SUI, request(SUI_USDC, 100)), T0)
            .unwrap();
        let body = report(
            &a,
            1,
            ReportKind::Acted {
                nonce: 0,
                digest: [5; 32],
                amount: 10,
            },
        );
        settle_with(&mut a, deliver(&c, 1, body.clone())).unwrap();
        let key = super::super::agent_audit::remote_action_key(&a.did, SUI, 1, 0);
        let entry: super::super::agent_audit::RemoteActionEntry =
            read_json(&a.state, &key).unwrap();
        assert_eq!(entry.digest, hex::encode([5; 32]));
        assert!(
            settle_with(&mut a, deliver(&c, 2, body))
                .unwrap_err()
                .contains("already recorded")
        );
    }

    fn record_paid(
        a: &mut Agent,
        delivery: Vec<u8>,
    ) -> std::result::Result<tenzro_types::settlement::PaymentRecord, String> {
        let op = tenzro_types::settlement::PaymentOp::Proven {
            agent_did: a.did.clone(),
            chain: SUI.into(),
            delivery,
        };
        let mut changes = Vec::new();
        super::super::payment_settlement::apply_payment_op(
            &mut a.state,
            CHAIN_ID,
            T0 as i64 + 1_000,
            &[0x42; 32],
            &op,
            &mut changes,
        )
        .map_err(|e| e.to_string())?;
        let records: Vec<_> = changes
            .iter()
            .filter_map(|c| c.new_value.as_ref())
            .filter_map(|v| {
                serde_json::from_slice::<tenzro_types::settlement::PaymentRecord>(v).ok()
            })
            .collect();
        records
            .into_iter()
            .next()
            .ok_or_else(|| "no record written".to_string())
    }

    fn paid(nonce: u64, amount: u128) -> ReportKind {
        ReportKind::Paid {
            nonce,
            payee: [0x55; 32],
            binding: tenzro_types::payment_authorization::PaymentBinding {
                request_digest: [1; 32],
                quote_digest: [2; 32],
                usd_e6: 30,
                app_margin: None,
            },
            amount,
        }
    }

    #[test]
    fn an_accounts_proven_payment_is_recorded_once_as_the_agents() {
        let (mut a, c) = reporting_agent();
        a.act(&grant_action(&a, SUI, request(SUI_USDC, 100)), T0)
            .unwrap();
        let record = {
            let d = deliver(&c, 1, report(&a, 1, paid(0, 30)));
            record_paid(&mut a, d)
        }
        .unwrap();
        let account = omni_address(&a.did, SUI, &evm()).unwrap();
        assert_eq!(record.class, tenzro_types::settlement::RecordClass::Proven);
        assert_eq!(record.payer, account.caip10());
        assert_eq!(record.agent_did.as_deref(), Some(a.did.as_str()));
        assert_eq!(record.asset, SUI_USDC);
        assert_eq!(record.amount, 30);
        assert_eq!(record.payee, Address::new([0x55; 32]));
        assert_eq!(record.source.as_deref(), Some("ethereum"));
        // The receipt fields every class fills: no fee on Tenzro, valued at
        // the signed price, paid in its own asset.
        assert_eq!(record.fee, 0);
        assert_eq!(record.settled.fee_asset, SUI_USDC);
        assert_eq!(record.settled.fee_tnzo_eq, 0);
        assert_eq!(record.settled.burn_eq, 0);
        assert_eq!(record.settled.unit.basket, "USD");
        assert_eq!(record.settled.unit.version, 1);
        assert_eq!(record.settled.value_units, 30);
        assert_eq!(record.settled.payout_asset, SUI_USDC);

        // The same payment proven again under a fresh delivery nonce.
        let e = {
            let d = deliver(&c, 2, report(&a, 1, paid(0, 30)));
            record_paid(&mut a, d)
        }
        .unwrap_err();
        assert!(e.contains("already"), "{e}");
        // Another account's report, a payment above the grant's budget, a
        // grant never issued, or a report that is not a payment.
        let mut other = AccountReport::decode(&report(&a, 1, paid(1, 30))).unwrap();
        other.account = [9; 32];
        assert!(
            record_paid(&mut a, deliver(&c, 3, other.encode()))
                .unwrap_err()
                .contains("another agent")
        );
        assert!(
            {
                let d = deliver(&c, 4, report(&a, 1, paid(2, 101)));
                record_paid(&mut a, d)
            }
            .unwrap_err()
            .contains("budget")
        );
        assert!(
            {
                let d = deliver(&c, 5, report(&a, 9, paid(3, 1)));
                record_paid(&mut a, d)
            }
            .unwrap_err()
            .contains("no such grant")
        );
        let closed = report(&a, 1, ReportKind::Closed { spent: 1 });
        assert!(
            record_paid(&mut a, deliver(&c, 6, closed))
                .unwrap_err()
                .contains("not a payment")
        );
        // Settling a payment report as a grant report is refused.
        assert!(
            {
                let d = deliver(&c, 7, report(&a, 1, paid(4, 1)));
                settle_with(&mut a, d)
            }
            .is_err()
        );
    }

    #[test]
    fn a_void_opens_a_relay_duty_that_pays_only_on_a_proven_install() {
        let (mut a, c) = reporting_agent();
        a.act(&grant_action(&a, SUI, request(SUI_USDC, 100)), T0)
            .unwrap();
        let deposit = relay_deposit(&a.state, Family::Eip155);
        assert_eq!(a.state.get_balance(&relay_account(&a.did, SUI)), deposit);
        void_all(
            &mut a.state,
            &a.did.clone(),
            T0,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
        let relay = read_grant_relay(&a.state, &a.did, SUI);
        let duty = relay.duty.clone().unwrap();
        assert_eq!(duty.seq, 2);
        let id: [u8; 32] = hex::decode(&duty.duty_id).unwrap().try_into().unwrap();
        assert_eq!(
            super::super::duty::read_duty(&a.state, &id).unwrap().state,
            tenzro_types::duty::DutyState::Open
        );
        let payee = [0x77; 32];
        // An install of the old grant pays nothing.
        let stale = report(&a, 1, ReportKind::Synced { void: false, payee });
        assert!(settle_with(&mut a, deliver(&c, 1, stale)).is_err());
        assert_eq!(a.state.get_balance(&payee), 0);
        let proven = report(&a, 2, ReportKind::Synced { void: true, payee });
        settle_with(&mut a, deliver(&c, 2, proven.clone())).unwrap();
        assert_eq!(a.state.get_balance(&payee), deposit);
        assert_eq!(
            super::super::duty::read_duty(&a.state, &id).unwrap().state,
            tenzro_types::duty::DutyState::Paid
        );
        assert!(settle_with(&mut a, deliver(&c, 3, proven)).is_err());
    }

    #[test]
    fn a_chain_that_proves_no_reports_settles_nothing_and_opens_no_duty() {
        let mut a = granted();
        void_all(
            &mut a.state,
            &a.did.clone(),
            T0,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(read_grant_relay(&a.state, &a.did, BASE).duty.is_none());
        let p = SettlePayload {
            agent_did: a.did.clone(),
            chain: BASE.into(),
            delivery: vec![1],
        };
        let e = settle(&mut a.state, CHAIN_ID, T0 as i64, &p)
            .unwrap_err()
            .to_string();
        assert!(e.contains("counts as spent"), "{e}");
    }
}
