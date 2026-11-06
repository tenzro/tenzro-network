//! Opt-in outflow limits for an account, with a cancel window and a second
//! key as the step-up.
//!
//! Nothing here is forced on anyone and nothing is custodial: an account
//! sets a policy on itself, and the funds stay in the account. A stolen key
//! then drains at most the policy's cap per window, and anything larger goes
//! through a release the owner, or the guardian the owner named, can cancel
//! before it unlocks.
//!
//! - `Set` writes the policy: a cap per rolling window, a hold (the cancel
//!   window) and an optional guardian: a human identity whose passkey
//!   (WebAuthn assertion, plus the ML-DSA-65 leg once it enrolled one) is
//!   the step-up, verified as every other root approval is. A first policy, or any change that tightens it, takes effect
//!   at once. A change that loosens it (a higher rate, a shorter hold, a
//!   removed or replaced guardian, or `Remove`) is queued for the current
//!   hold, so a thief with the owner key cannot lift the cap faster than
//!   the owner or the guardian can cancel it (`CancelPending`).
//! - Outflow past the cap is refused. `RequestRelease` queues a payment of
//!   any size; it unlocks after the hold. The owner or the guardian cancels
//!   it (`CancelRelease`). The owner claims it after the hold
//!   (`ClaimRelease`); the guardian may claim it at once, which is the
//!   step-up for a payment the owner wants now.
//! - An account with a policy refuses new EIP-7702 delegations, which would
//!   let other code move its funds around the cap.
//!
//! The floor on the hold and the window, and how many releases may be open
//! at once, are governed parameters.

use serde::{Deserialize, Serialize};
use tenzro_types::agent_terms::AgentTermsApproval;

use crate::error::{Result, VmError};
use crate::native::SYSTEM_ADDRESS;
use crate::traits::VmState;
use crate::types::{Log, StateChange, VmTransaction};

/// Selector of an account's outflow-policy operations.
pub const SELECTOR_ACCOUNT_OUTFLOW: [u8; 4] = [0x01, 0x00, 0x00, 0xDC];

/// Gas of one operation.
pub const GAS_ACCOUNT_OUTFLOW: u64 = 40_000;

/// Governed: the shortest hold (cancel window) a policy may set, ms.
pub const MIN_HOLD_PARAM: &str = "accounts.outflow_min_hold_ms";

/// Genesis value of [`MIN_HOLD_PARAM`]: one hour.
pub const DEFAULT_MIN_HOLD_MS: u64 = 60 * 60 * 1000;

/// Governed: the shortest window a policy may count its cap over, ms.
pub const MIN_WINDOW_PARAM: &str = "accounts.outflow_min_window_ms";

/// Genesis value of [`MIN_WINDOW_PARAM`]: one hour.
pub const DEFAULT_MIN_WINDOW_MS: u64 = 60 * 60 * 1000;

/// Governed: the most releases one account may have open at once.
pub const MAX_RELEASES_PARAM: &str = "accounts.outflow_max_open_releases";

/// Genesis value of [`MAX_RELEASES_PARAM`].
pub const DEFAULT_MAX_RELEASES: u64 = 16;

/// Topic of the log every operation emits.
pub const OUTFLOW_TOPIC: &[u8] = b"AccountOutflow";

/// A change waiting out the hold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pending {
    /// Window of the queued policy, ms.
    pub window_ms: u64,
    /// Cap of the queued policy.
    #[serde(with = "dec")]
    pub cap: u128,
    /// Hold of the queued policy, ms.
    pub hold_ms: u64,
    /// Guardian of the queued policy.
    pub guardian: Option<String>,
    /// The queued change removes the policy.
    pub remove: bool,
    /// Block time it takes effect, ms.
    pub effective_ms: i64,
}

/// An account's outflow policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Window the cap counts over, ms.
    pub window_ms: u64,
    /// Most the account may send out per window.
    #[serde(with = "dec")]
    pub cap: u128,
    /// How long a release waits, ms.
    pub hold_ms: u64,
    /// The account that may cancel, and claim at once.
    #[serde(default)]
    pub guardian: Option<String>,
    /// A loosening queued for the end of the hold.
    #[serde(default)]
    pub pending: Option<Pending>,
}

/// A queued payment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Release {
    /// Recipient.
    pub to: Vec<u8>,
    /// Amount.
    #[serde(with = "dec")]
    pub amount: u128,
    /// Block time it unlocks, ms.
    pub unlock_ms: i64,
}

/// One operation. `account` is the account the policy belongs to; the
/// transaction's sender is the owner or, where said, the guardian.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Set or change the policy (owner).
    Set {
        /// The account.
        account: Vec<u8>,
        /// Window, ms.
        window_ms: u64,
        /// Cap per window.
        #[serde(with = "dec")]
        cap: u128,
        /// Hold, ms.
        hold_ms: u64,
        /// Guardian account.
        #[serde(default)]
        guardian: Option<String>,
    },
    /// Remove the policy after the hold (owner).
    Remove {
        /// The account.
        account: Vec<u8>,
    },
    /// Cancel a queued loosening (owner or guardian).
    CancelPending {
        /// The account.
        account: Vec<u8>,
        /// The guardian's passkey approval (required while a guardian is set).
        #[serde(default)]
        approval: Option<AgentTermsApproval>,
    },
    /// Queue a payment of any size (owner).
    RequestRelease {
        /// The account.
        account: Vec<u8>,
        /// Recipient.
        to: Vec<u8>,
        /// Amount.
        #[serde(with = "dec")]
        amount: u128,
    },
    /// Cancel a queued payment (owner or guardian).
    CancelRelease {
        /// The account.
        account: Vec<u8>,
        /// The release.
        id: u64,
        /// The guardian's passkey approval (required while a guardian is set).
        #[serde(default)]
        approval: Option<AgentTermsApproval>,
    },
    /// Pay a queued payment: the owner once it unlocked, the guardian any
    /// time.
    ClaimRelease {
        /// The account.
        account: Vec<u8>,
        /// The release.
        id: u64,
        /// The guardian's passkey approval, which pays at once.
        #[serde(default)]
        approval: Option<AgentTermsApproval>,
    },
}

/// Amounts travel as decimal strings: JSON numbers do not carry 128 bits.
mod dec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

fn refuse(msg: impl Into<String>) -> VmError {
    VmError::InvalidTransaction(format!("account outflow: {}", msg.into()))
}

fn policy_key(account: &[u8]) -> String {
    format!("acct_outflow:{}", hex::encode(account))
}

fn window_key(account: &[u8]) -> String {
    format!("acct_outflow_window:{}", hex::encode(account))
}

fn release_key(account: &[u8], id: u64) -> String {
    format!("acct_outflow_rel:{}:{id}", hex::encode(account))
}

fn meta_key(account: &[u8]) -> String {
    format!("acct_outflow_relmeta:{}", hex::encode(account))
}

fn read_json<T: for<'a> Deserialize<'a>>(state: &dyn VmState, key: &str) -> Option<T> {
    let raw = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes())?;
    if raw.is_empty() {
        return None;
    }
    serde_json::from_slice(&raw).ok()
}

fn write(
    state: &mut dyn VmState,
    key: &str,
    value: Option<Vec<u8>>,
    changes: &mut Vec<StateChange>,
) {
    let previous = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(
        &SYSTEM_ADDRESS,
        key.as_bytes(),
        value.clone().unwrap_or_default(),
    );
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.as_bytes().to_vec(),
        previous,
        value,
    ));
}

fn write_policy(
    state: &mut dyn VmState,
    account: &[u8],
    policy: Option<&Policy>,
    changes: &mut Vec<StateChange>,
) {
    write(
        state,
        &policy_key(account),
        policy.map(|p| serde_json::to_vec(p).expect("policy encodes")),
        changes,
    );
}

/// Whether the account has any policy record, queued changes included.
pub fn has_policy(state: &dyn VmState, account: &[u8]) -> bool {
    read_json::<Policy>(state, &policy_key(account)).is_some()
}

/// What a wallet shows about `account`: the policy in force and every open
/// queued payment, as JSON (amounts as decimal strings, addresses as hex).
pub fn view(state: &dyn VmState, account: &[u8], now_ms: i64) -> serde_json::Value {
    let policy = policy_in_force(state, account, now_ms).map(|p| {
        serde_json::json!({
            "window_ms": p.window_ms,
            "cap": p.cap.to_string(),
            "hold_ms": p.hold_ms,
            "guardian": p.guardian,
            "pending": p.pending.as_ref().map(|q| serde_json::json!({
                "window_ms": q.window_ms,
                "cap": q.cap.to_string(),
                "hold_ms": q.hold_ms,
                "guardian": q.guardian,
                "remove": q.remove,
                "effective_ms": q.effective_ms,
            })),
        })
    });
    let next = match state.get_storage(&SYSTEM_ADDRESS, meta_key(account).as_bytes()) {
        Some(r) if r.len() == 12 => u64::from_le_bytes(r[..8].try_into().expect("8 bytes")),
        _ => 0,
    };
    let releases: Vec<serde_json::Value> = (next.saturating_sub(256)..next)
        .filter_map(|id| {
            read_json::<Release>(state, &release_key(account, id)).map(|r| {
                serde_json::json!({
                    "id": id,
                    "to": hex::encode(&r.to),
                    "amount": r.amount.to_string(),
                    "unlock_ms": r.unlock_ms,
                })
            })
        })
        .collect();
    serde_json::json!({
        "now_ms": now_ms,
        "policy": policy,
        "releases": releases,
        "approval_step": read_step(state, account),
    })
}

/// The policy in force at `now_ms`: a queued change whose hold has run out
/// has taken effect.
pub fn policy_in_force(state: &dyn VmState, account: &[u8], now_ms: i64) -> Option<Policy> {
    let mut p: Policy = read_json(state, &policy_key(account))?;
    if let Some(q) = p.pending.clone()
        && now_ms >= q.effective_ms
    {
        if q.remove {
            return None;
        }
        p = Policy {
            window_ms: q.window_ms,
            cap: q.cap,
            hold_ms: q.hold_ms,
            guardian: q.guardian,
            pending: None,
        };
    }
    Some(p)
}

/// Counts `amount` leaving `account` against its cap. Refuses when the
/// window's total would pass the cap. An account with no policy in force
/// is not limited.
pub fn charge_outflow(
    state: &mut dyn VmState,
    account: &[u8],
    amount: u128,
    now_ms: i64,
) -> std::result::Result<(), String> {
    let Some(p) = policy_in_force(state, account, now_ms) else {
        return Ok(());
    };
    let key = window_key(account);
    let (mut start, mut spent) = match state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()) {
        Some(r) if r.len() == 24 => (
            i64::from_le_bytes(r[..8].try_into().unwrap()),
            u128::from_le_bytes(r[8..].try_into().unwrap()),
        ),
        _ => (now_ms, 0),
    };
    if now_ms < start || now_ms - start >= p.window_ms as i64 {
        start = now_ms;
        spent = 0;
    }
    let total = spent.saturating_add(amount);
    if total > p.cap {
        return Err(format!(
            "{amount} would take the window's outflow to {total}, past the account's cap of {}",
            p.cap
        ));
    }
    let mut blob = start.to_le_bytes().to_vec();
    blob.extend_from_slice(&total.to_le_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob);
    Ok(())
}

fn log(account: &[u8], what: &str, detail: Vec<u8>) -> Log {
    let mut data = what.as_bytes().to_vec();
    data.push(b':');
    data.extend_from_slice(&detail);
    Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![OUTFLOW_TOPIC.to_vec(), account.to_vec()],
        data,
    )
}

fn looser(cur: &Policy, new: &Policy) -> bool {
    new.cap.saturating_mul(cur.window_ms as u128) > cur.cap.saturating_mul(new.window_ms as u128)
        || new.hold_ms < cur.hold_ms
        || new.guardian != cur.guardian
}

/// Operation name a guardian's passkey approval is made under.
pub const OP_OUTFLOW_GUARDIAN: &[u8] = b"account_outflow_guardian";

fn step_key(account: &[u8]) -> String {
    format!("acct_outflow_step:{}", hex::encode(account))
}

fn read_step(state: &dyn VmState, account: &[u8]) -> u64 {
    state
        .get_storage(&SYSTEM_ADDRESS, step_key(account).as_bytes())
        .filter(|r| r.len() == 8)
        .map(|r| u64::from_le_bytes(r[..].try_into().unwrap()))
        .unwrap_or(0)
}

/// The bytes a guardian's passkey signs, bound to the account, the action,
/// the release and the account's approval counter: an approval made for one
/// action cannot be used for another, and once one has been used the counter
/// has moved, so it cannot be used again.
pub fn approval_target(account: &[u8], action: &str, id: u64, step: u64) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&(account.len() as u32).to_be_bytes());
    t.extend_from_slice(account);
    t.extend_from_slice(&(action.len() as u32).to_be_bytes());
    t.extend_from_slice(action.as_bytes());
    t.extend_from_slice(&id.to_be_bytes());
    t.extend_from_slice(&step.to_be_bytes());
    t
}

/// Verifies that the guardian's human identity approved `action` with a
/// passkey assertion (and the ML-DSA-65 leg once it enrolled one), and moves
/// the account's approval counter so the approval cannot be replayed.
fn verify_guardian(
    state: &mut dyn VmState,
    account: &[u8],
    guardian_did: &str,
    action: &str,
    id: u64,
    approval: Option<&AgentTermsApproval>,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let approval = approval
        .ok_or_else(|| refuse("the account's guardian must approve this with its passkey"))?;
    approval.check_bounds().map_err(refuse)?;
    if approval.account != account {
        return Err(refuse("the approval names another account"));
    }
    let step = read_step(state, account);
    crate::native::verify_root_approval(
        state,
        guardian_did,
        OP_OUTFLOW_GUARDIAN,
        &approval_target(account, action, id, step),
        approval,
        now_ms.max(0) as u64,
    )
    .map_err(|e| refuse(format!("the guardian's approval is refused: {e}")))?;
    write(
        state,
        &step_key(account),
        Some((step + 1).to_le_bytes().to_vec()),
        changes,
    );
    Ok(())
}

/// Applies one operation sent by `tx.from`.
pub fn apply(
    state: &mut dyn VmState,
    tx: &VmTransaction,
    op: &Op,
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    use crate::native::network_param;
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    let account = match op {
        Op::Set { account, .. }
        | Op::Remove { account }
        | Op::CancelPending { account, .. }
        | Op::RequestRelease { account, .. }
        | Op::CancelRelease { account, .. }
        | Op::ClaimRelease { account, .. } => account.clone(),
    };
    let owner = tx.from == account;
    let current = policy_in_force(state, &account, now_ms);
    let guardian = current.as_ref().and_then(|p| p.guardian.clone());
    match op {
        Op::Set {
            window_ms,
            cap,
            hold_ms,
            guardian: new_guardian,
            ..
        } => {
            if !owner {
                return Err(refuse("only the account sets its own policy"));
            }
            if *cap == 0 {
                return Err(refuse("a cap of zero would lock the account"));
            }
            if *window_ms < network_param(state, MIN_WINDOW_PARAM) {
                return Err(refuse("the window is shorter than the governed floor"));
            }
            if *hold_ms < network_param(state, MIN_HOLD_PARAM) {
                return Err(refuse("the hold is shorter than the governed floor"));
            }
            if let Some(g) = new_guardian
                && !g.starts_with(crate::governance::HUMAN_DID_PREFIX)
            {
                return Err(refuse(
                    "the guardian is a human identity (did:tenzro:human:...)",
                ));
            }
            let new = Policy {
                window_ms: *window_ms,
                cap: *cap,
                hold_ms: *hold_ms,
                guardian: new_guardian.clone(),
                pending: None,
            };
            match current {
                None => {
                    write_policy(state, &account, Some(&new), &mut changes);
                    logs.push(log(&account, "set", Vec::new()));
                }
                Some(cur) if looser(&cur, &new) => {
                    let mut cur = cur;
                    cur.pending = Some(Pending {
                        window_ms: new.window_ms,
                        cap: new.cap,
                        hold_ms: new.hold_ms,
                        guardian: new.guardian,
                        remove: false,
                        effective_ms: now_ms + cur.hold_ms as i64,
                    });
                    write_policy(state, &account, Some(&cur), &mut changes);
                    logs.push(log(&account, "loosening_queued", Vec::new()));
                }
                Some(_) => {
                    write_policy(state, &account, Some(&new), &mut changes);
                    logs.push(log(&account, "tightened", Vec::new()));
                }
            }
        }
        Op::Remove { .. } => {
            if !owner {
                return Err(refuse("only the account removes its own policy"));
            }
            let mut cur = current.ok_or_else(|| refuse("the account has no policy"))?;
            cur.pending = Some(Pending {
                window_ms: cur.window_ms,
                cap: cur.cap,
                hold_ms: cur.hold_ms,
                guardian: cur.guardian.clone(),
                remove: true,
                effective_ms: now_ms + cur.hold_ms as i64,
            });
            write_policy(state, &account, Some(&cur), &mut changes);
            logs.push(log(&account, "removal_queued", Vec::new()));
        }
        Op::CancelPending { approval, .. } => {
            let mut cur = current.ok_or_else(|| refuse("the account has no policy"))?;
            match &guardian {
                // With a guardian, a cancel is the guardian's passkey, from
                // whoever relays it; the owner's key alone does not cancel.
                Some(g) => verify_guardian(
                    state,
                    &account,
                    g,
                    "cancel_pending",
                    0,
                    approval.as_ref(),
                    now_ms,
                    &mut changes,
                )?,
                None if owner => {}
                None => return Err(refuse("only the account cancels")),
            }
            if cur.pending.take().is_none() {
                return Err(refuse("nothing is queued"));
            }
            write_policy(state, &account, Some(&cur), &mut changes);
            logs.push(log(&account, "pending_cancelled", Vec::new()));
        }
        Op::RequestRelease { to, amount, .. } => {
            if !owner {
                return Err(refuse("only the account requests a release"));
            }
            let cur = current.ok_or_else(|| refuse("the account has no policy"))?;
            if *amount == 0 || to.is_empty() {
                return Err(refuse("a release names a recipient and an amount"));
            }
            let (next, open) =
                match state.get_storage(&SYSTEM_ADDRESS, meta_key(&account).as_bytes()) {
                    Some(r) if r.len() == 12 => (
                        u64::from_le_bytes(r[..8].try_into().unwrap()),
                        u32::from_le_bytes(r[8..].try_into().unwrap()),
                    ),
                    _ => (0, 0),
                };
            if open as u64 >= network_param(state, MAX_RELEASES_PARAM) {
                return Err(refuse("too many releases are open"));
            }
            let release = Release {
                to: to.clone(),
                amount: *amount,
                unlock_ms: now_ms + cur.hold_ms as i64,
            };
            write(
                state,
                &release_key(&account, next),
                Some(serde_json::to_vec(&release).expect("release encodes")),
                &mut changes,
            );
            let mut meta = (next + 1).to_le_bytes().to_vec();
            meta.extend_from_slice(&(open + 1).to_le_bytes());
            write(state, &meta_key(&account), Some(meta), &mut changes);
            logs.push(log(
                &account,
                "release_requested",
                next.to_le_bytes().to_vec(),
            ));
        }
        Op::CancelRelease { id, approval, .. } | Op::ClaimRelease { id, approval, .. } => {
            let claim = matches!(op, Op::ClaimRelease { .. });
            let rel: Release = read_json(state, &release_key(&account, *id))
                .ok_or_else(|| refuse("no such release"))?;
            match &guardian {
                Some(g) => {
                    // The owner's key alone claims once the hold has run
                    // out. Anything else (a cancel, or a claim before the
                    // unlock) is the guardian's passkey.
                    let owner_claims_late =
                        claim && owner && approval.is_none() && now_ms >= rel.unlock_ms;
                    if !owner_claims_late {
                        verify_guardian(
                            state,
                            &account,
                            g,
                            if claim {
                                "claim_release"
                            } else {
                                "cancel_release"
                            },
                            *id,
                            approval.as_ref(),
                            now_ms,
                            &mut changes,
                        )?;
                    }
                }
                None => {
                    if !owner {
                        return Err(refuse("only the account acts on its release"));
                    }
                    if claim && now_ms < rel.unlock_ms {
                        return Err(refuse("the release has not unlocked"));
                    }
                }
            }
            if claim {
                let bal = state.get_balance(&account);
                if bal < rel.amount {
                    return Err(refuse("the account does not hold the amount"));
                }
                let to_bal = state.get_balance(&rel.to);
                state.set_balance(&account, bal - rel.amount);
                state.set_balance(&rel.to, to_bal + rel.amount);
                changes.push(StateChange::new(
                    account.clone(),
                    b"balance".to_vec(),
                    Some(bal.to_le_bytes().to_vec()),
                    Some((bal - rel.amount).to_le_bytes().to_vec()),
                ));
                changes.push(StateChange::new(
                    rel.to.clone(),
                    b"balance".to_vec(),
                    Some(to_bal.to_le_bytes().to_vec()),
                    Some((to_bal + rel.amount).to_le_bytes().to_vec()),
                ));
            }
            write(state, &release_key(&account, *id), None, &mut changes);
            if let Some(r) = state.get_storage(&SYSTEM_ADDRESS, meta_key(&account).as_bytes())
                && r.len() == 12
            {
                let open = u32::from_le_bytes(r[8..].try_into().unwrap()).saturating_sub(1);
                let mut meta = r[..8].to_vec();
                meta.extend_from_slice(&open.to_le_bytes());
                write(state, &meta_key(&account), Some(meta), &mut changes);
            }
            logs.push(log(
                &account,
                if claim {
                    "release_claimed"
                } else {
                    "release_cancelled"
                },
                id.to_le_bytes().to_vec(),
            ));
        }
    }
    Ok((changes, logs))
}

/// Whether `tx` is an outflow-policy operation, which moves funds by its own
/// rules and is not counted against the cap.
pub fn is_outflow_op(tx: &VmTransaction) -> bool {
    tx.vm_type == crate::VmType::Tenzro && tx.data.starts_with(&SELECTOR_ACCOUNT_OUTFLOW)
}
