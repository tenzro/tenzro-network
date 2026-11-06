//! Requests to an account's opt-in outflow policy (a cap per window, a hold and
//! an optional guardian), the policy as the node reports it
//! (`tenzro_getAccountOutflow`), and a plain-language preview of each request
//! to show before signing. The same wire form and wording as the node's
//! `tenzro_types::account_outflow_ui` and the TypeScript and Python SDKs; the
//! rules are the chain's, in its `account_outflow` module.
//!
//! Send a request with [`TypedTxClient`](crate::typed_tx::TypedTxClient) using
//! [`OutflowRequest::typed_transaction`]; a guardian sends from its own
//! account, naming the guarded account.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use crate::error::SdkResult;
use crate::rpc::RpcClient;
use crate::typed_tx::{TxKind, TypedTransaction};
use serde_json::{Value, json};

const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

/// A queued change, as `tenzro_getAccountOutflow` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingView {
    /// Queued window, ms.
    pub window_ms: u64,
    /// Queued cap, wei.
    pub cap: u128,
    /// Queued hold, ms.
    pub hold_ms: u64,
    /// Queued guardian, hex.
    pub guardian: Option<String>,
    /// The queued change removes the policy.
    pub remove: bool,
    /// Block time it takes effect, ms.
    pub effective_ms: i64,
}

/// An account's policy, as `tenzro_getAccountOutflow` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyView {
    /// Window the cap counts over, ms.
    pub window_ms: u64,
    /// Most the account may send per window, wei.
    pub cap: u128,
    /// How long a release waits, ms.
    pub hold_ms: u64,
    /// The guardian, hex.
    pub guardian: Option<String>,
    /// A loosening waiting out the hold.
    pub pending: Option<PendingView>,
}

/// One queued payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseView {
    /// Its number.
    pub id: u64,
    /// Recipient, hex.
    pub to: String,
    /// Amount, wei.
    pub amount: u128,
    /// Block time it unlocks, ms.
    pub unlock_ms: i64,
}

fn dec(v: &Value) -> Option<u128> {
    v.as_str().and_then(|s| s.parse().ok())
}

impl PolicyView {
    /// Read the `policy` object of the node's answer.
    pub fn from_rpc(v: &Value) -> Option<Self> {
        if v.is_null() {
            return None;
        }
        Some(Self {
            window_ms: v.get("window_ms")?.as_u64()?,
            cap: dec(v.get("cap")?)?,
            hold_ms: v.get("hold_ms")?.as_u64()?,
            guardian: v.get("guardian").and_then(|g| g.as_str()).map(str::to_string),
            pending: v.get("pending").filter(|p| !p.is_null()).and_then(|p| {
                Some(PendingView {
                    window_ms: p.get("window_ms")?.as_u64()?,
                    cap: dec(p.get("cap")?)?,
                    hold_ms: p.get("hold_ms")?.as_u64()?,
                    guardian: p.get("guardian").and_then(|g| g.as_str()).map(str::to_string),
                    remove: p.get("remove")?.as_bool()?,
                    effective_ms: p.get("effective_ms")?.as_i64()?,
                })
            }),
        })
    }
}

impl ReleaseView {
    /// Read one entry of the node's `releases` list.
    pub fn from_rpc(v: &Value) -> Option<Self> {
        Some(Self {
            id: v.get("id")?.as_u64()?,
            to: v.get("to")?.as_str()?.to_string(),
            amount: dec(v.get("amount")?)?,
            unlock_ms: v.get("unlock_ms")?.as_i64()?,
        })
    }
}

/// One request to the account's outflow policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutflowRequest {
    /// Set or change the policy.
    Set {
        /// Window, ms.
        window_ms: u64,
        /// Cap per window, wei.
        cap: u128,
        /// Hold, ms.
        hold_ms: u64,
        /// The guardian: a person's identity (DID) whose passkey approves a
        /// cancel or an early payment. None for no guardian.
        guardian: Option<String>,
    },
    /// Remove the policy after the hold.
    Remove,
    /// Cancel a queued loosening. `approval` is the guardian's passkey
    /// approval when the guardian cancels (the account itself needs none).
    CancelPending {
        /// The guardian's approval, as the chain's `AgentTermsApproval` JSON.
        approval: Option<Value>,
    },
    /// Queue a payment of any size.
    RequestRelease {
        /// Recipient.
        to: Vec<u8>,
        /// Amount, wei.
        amount: u128,
    },
    /// Cancel a queued payment.
    CancelRelease {
        /// Its number.
        id: u64,
        /// The guardian's approval when the guardian cancels.
        approval: Option<Value>,
    },
    /// Pay a queued payment (the owner once unlocked, the guardian at once).
    ClaimRelease {
        /// Its number.
        id: u64,
        /// The guardian's approval, required to pay before the hold ends.
        approval: Option<Value>,
    },
}

impl OutflowRequest {
    /// The operation as the VM reads it, for `account`.
    pub fn op_json(&self, account: &[u8]) -> Vec<u8> {
        // The chain's `Op` is externally tagged: `{"set": {..fields..}}`.
        let a: Vec<u32> = account.iter().map(|b| u32::from(*b)).collect();
        let v = match self {
            Self::Set { window_ms, cap, hold_ms, guardian } => json!({ "set": {
                "account": a, "window_ms": window_ms, "cap": cap.to_string(),
                "hold_ms": hold_ms, "guardian": guardian,
            }}),
            Self::Remove => json!({ "remove": { "account": a } }),
            Self::CancelPending { approval } => json!({ "cancel_pending": { "account": a, "approval": approval } }),
            Self::RequestRelease { to, amount } => json!({ "request_release": {
                "account": a, "to": to, "amount": amount.to_string(),
            }}),
            Self::CancelRelease { id, approval } => json!({ "cancel_release": { "account": a, "id": id, "approval": approval } }),
            Self::ClaimRelease { id, approval } => json!({ "claim_release": { "account": a, "id": id, "approval": approval } }),
        };
        serde_json::to_vec(&v).expect("an outflow request encodes")
    }

    /// The transaction carrying the request, ready for `TypedTxClient::send`.
    pub fn typed_transaction(&self, account: &[u8]) -> SdkResult<TypedTransaction> {
        let op: Vec<u32> = self.op_json(account).iter().map(|b| u32::from(*b)).collect();
        TypedTransaction::new(TxKind::AccountOutflow, json!({ "op": op }))
    }

    /// Plain-language lines to show before signing. `current` is the policy
    /// in force, `now_ms` the block time (for the times named).
    pub fn describe(&self, current: Option<&PolicyView>, now_ms: i64) -> Vec<String> {
        let mut out = Vec::new();
        match self {
            Self::Set { window_ms, cap, hold_ms, guardian } => {
                out.push(format!(
                    "Cap: this account can send at most {} per {}.",
                    tnzo(*cap),
                    span(*window_ms)
                ));
                out.push(format!(
                    "Hold: a larger payment is queued and waits {} before it can be paid. You{} can cancel it meanwhile.",
                    span(*hold_ms),
                    if guardian.is_some() { " or your guardian" } else { "" }
                ));
                match guardian {
                    Some(g) => out.push(format!(
                        "Guardian: {g} can cancel a queued payment and can approve one at once, each with their own passkey. Choose a person whose passkey is on different hardware from this account's.",
                    )),
                    None => out.push(
                        "No guardian: only this account can cancel or approve. A thief holding its key could also approve a queued payment once the hold ends, so the hold is your only protection."
                            .to_string(),
                    ),
                }
                match current {
                    None => out.push("A first policy takes effect at once.".to_string()),
                    Some(cur) => {
                        let new = PolicyView {
                            window_ms: *window_ms,
                            cap: *cap,
                            hold_ms: *hold_ms,
                            guardian: guardian.clone(),
                            pending: None,
                        };
                        if looser(cur, &new) {
                            out.push(format!(
                                "This loosens the policy, so it is queued for the current hold ({}) and takes effect at {}. You{} can cancel it until then.",
                                span(cur.hold_ms),
                                at(now_ms + cur.hold_ms as i64),
                                if cur.guardian.is_some() { " or your guardian" } else { "" }
                            ));
                        } else {
                            out.push("This tightens the policy, so it takes effect at once.".to_string());
                        }
                    }
                }
            }
            Self::Remove => {
                let hold = current.map_or(0, |c| c.hold_ms);
                out.push(format!(
                    "Remove the outflow policy. This is queued for the current hold ({}) and takes effect at {}; until then the cap still applies. You{} can cancel it.",
                    span(hold),
                    at(now_ms + hold as i64),
                    if current.is_some_and(|c| c.guardian.is_some()) { " or your guardian" } else { "" }
                ));
            }
            Self::CancelPending { .. } => {
                out.push("Cancel the queued change to this account's outflow policy. The policy stays as it is now.".to_string());
            }
            Self::RequestRelease { to, amount } => {
                out.push(format!("Queue a payment of {} to 0x{}.", tnzo(*amount), hex(to)));
                match current {
                    Some(c) => out.push(format!(
                        "It can be paid at {} (after the {} hold). You{} can cancel it until it is paid.",
                        at(now_ms + c.hold_ms as i64),
                        span(c.hold_ms),
                        if c.guardian.is_some() { " or your guardian" } else { "" }
                    )),
                    None => out.push("This account has no outflow policy, so a queued payment is refused.".to_string()),
                }
            }
            Self::CancelRelease { id, .. } => {
                out.push(format!("Cancel queued payment #{id}. Nothing is sent; it leaves the queue."));
            }
            Self::ClaimRelease { id, .. } => {
                out.push(format!(
                    "Pay queued payment #{id}. The account pays it once its hold has ended; its guardian may pay it at once, with their passkey approval."
                ));
            }
        }
        out
    }
}

/// The bytes a guardian's passkey signs for one action, bound to the account,
/// the action (`cancel_pending`, `cancel_release`, `claim_release`), the
/// release number (0 for `cancel_pending`) and the account's approval
/// counter (`approval_step` in the node's answer). Identical to the chain's
/// `account_outflow::approval_target`; a test in `tenzro-vm` keeps them equal.
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

/// What a wallet offers when it creates an account. Nothing is set unless the
/// holder chooses to; the offer is never a default that applies itself.
pub fn creation_offer() -> Vec<String> {
    vec![
        "Optional: protect this account with an outflow limit.".to_string(),
        "You choose a cap per window and a hold. A payment above the cap is queued and waits the hold, and you can cancel it meanwhile.".to_string(),
        "For the strongest protection name a guardian: a person whose passkey is on different hardware from this account's. The guardian can cancel, and can approve a payment at once.".to_string(),
        "Nothing is set unless you set it: tenzro wallet outflow set --cap <TNZO> --guardian <did>".to_string(),
    ]
}

/// Whether `new` loosens `cur` (the VM queues those for the hold).
pub fn looser(cur: &PolicyView, new: &PolicyView) -> bool {
    new.cap.saturating_mul(u128::from(cur.window_ms)) > cur.cap.saturating_mul(u128::from(new.window_ms))
        || new.hold_ms < cur.hold_ms
        || (cur.guardian.is_some() && new.guardian != cur.guardian)
}

/// Lines describing the account's policy and what is waiting.
pub fn describe_state(policy: Option<&PolicyView>, releases: &[ReleaseView], now_ms: i64) -> Vec<String> {
    let Some(p) = policy else {
        return vec!["No outflow policy: this account is not limited. (Opt in with `outflow set`.)".to_string()];
    };
    let mut out = vec![
        format!("Cap: {} per {}.", tnzo(p.cap), span(p.window_ms)),
        format!("Hold: {}.", span(p.hold_ms)),
        match &p.guardian {
            Some(g) => format!("Guardian: {g}."),
            None => "Guardian: none.".to_string(),
        },
    ];
    if let Some(q) = &p.pending {
        out.push(if q.remove {
            format!("Queued: removal of the policy at {}. You{} can cancel it.", at(q.effective_ms), if p.guardian.is_some() { " or your guardian" } else { "" })
        } else {
            format!(
                "Queued: a looser policy (cap {} per {}, hold {}) at {}. You{} can cancel it.",
                tnzo(q.cap), span(q.window_ms), span(q.hold_ms), at(q.effective_ms),
                if p.guardian.is_some() { " or your guardian" } else { "" }
            )
        });
    }
    for r in releases {
        out.push(format!(
            "Queued payment #{}: {} to 0x{}, {}.",
            r.id,
            tnzo(r.amount),
            r.to,
            if now_ms >= r.unlock_ms { "ready to be paid".to_string() } else { format!("unlocks at {}", at(r.unlock_ms)) }
        ));
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn tnzo(wei: u128) -> String {
    let whole = wei / ONE_TNZO;
    let frac = wei % ONE_TNZO;
    if frac == 0 {
        format!("{whole} TNZO")
    } else {
        let f = format!("{frac:018}");
        format!("{whole}.{} TNZO", f.trim_end_matches('0'))
    }
}

fn span(ms: u64) -> String {
    let m = ms / 60_000;
    if m >= 2 * 24 * 60 {
        format!("{} days", m / (24 * 60))
    } else if m >= 120 {
        format!("{} hours", m / 60)
    } else if m >= 1 {
        format!("{m} minutes")
    } else {
        "under a minute".to_string()
    }
}

fn at(ms: i64) -> String {
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rem / 3600, rem % 3600 / 60)
}

/// The node queries behind the outflow policy: an account's policy and its
/// queued changes and releases, and whether a delegate's code is on the
/// governed list.
#[derive(Clone)]
pub struct AccountOutflowClient {
    rpc: Arc<RpcClient>,
}

impl AccountOutflowClient {
    /// Creates a client over `rpc`.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// `tenzro_getAccountOutflow`: the policy of `account` (hex), its pending
    /// change and its releases. Read the policy with
    /// [`PolicyView::from_rpc`] and the releases with [`ReleaseView::from_rpc`].
    pub async fn get(&self, account: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getAccountOutflow",
                json!({ "account": account.trim_start_matches("0x") }),
            )
            .await
    }

    /// `tenzro_checkDelegateTarget`: whether the code at `address` is on the
    /// governed list of delegate code hashes.
    pub async fn check_delegate_target(&self, address: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_checkDelegateTarget", json!({ "address": address }))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u128 = ONE_TNZO;
    const DAY: u64 = 86_400_000;
    const HOUR: u64 = 3_600_000;

    fn policy() -> PolicyView {
        PolicyView { window_ms: DAY, cap: 10 * T, hold_ms: 24 * HOUR, guardian: Some("did:tenzro:human:g1".into()), pending: None }
    }

    #[test]
    fn a_first_policy_is_described_with_cap_hold_and_guardian() {
        let r = OutflowRequest::Set { window_ms: DAY, cap: 10 * T, hold_ms: 24 * HOUR, guardian: Some("did:tenzro:human:g1".into()) };
        let text = r.describe(None, 0).join(" ");
        assert!(text.contains("at most 10 TNZO per 24 hours"), "{text}");
        assert!(text.contains("waits 24 hours"));
        assert!(text.contains("your guardian"));
        assert!(text.contains("takes effect at once"));
    }

    #[test]
    fn no_guardian_is_called_out() {
        let r = OutflowRequest::Set { window_ms: DAY, cap: T, hold_ms: HOUR, guardian: None };
        assert!(r.describe(None, 0).join(" ").contains("No guardian"));
    }

    #[test]
    fn loosening_is_said_to_be_queued_and_tightening_is_immediate() {
        let cur = policy();
        let loose = OutflowRequest::Set { window_ms: DAY, cap: 100 * T, hold_ms: 24 * HOUR, guardian: cur.guardian.clone() };
        let t = loose.describe(Some(&cur), 0).join(" ");
        assert!(t.contains("loosens the policy") && t.contains("1970-01-02 00:00 UTC"), "{t}");
        let tight = OutflowRequest::Set { window_ms: DAY, cap: T, hold_ms: 48 * HOUR, guardian: Some("did:tenzro:human:g1".into()) };
        assert!(tight.describe(Some(&cur), 0).join(" ").contains("tightens the policy"));
        assert!(looser(&cur, &PolicyView { guardian: None, ..cur.clone() }));
    }

    #[test]
    fn release_and_removal_name_who_can_cancel_and_when() {
        let cur = policy();
        let rel = OutflowRequest::RequestRelease { to: vec![0xb1; 32], amount: 3 * T / 2 };
        let t = rel.describe(Some(&cur), 0).join(" ");
        assert!(t.contains("1.5 TNZO") && t.contains("You or your guardian can cancel"), "{t}");
        assert!(OutflowRequest::Remove.describe(Some(&cur), 0).join(" ").contains("queued for the current hold"));
        assert!(rel.describe(None, 0).join(" ").contains("no outflow policy"));
    }

    #[test]
    fn the_guardian_approval_target_is_length_prefixed_and_step_bound() {
        let a = approval_target(&[1, 2], "claim_release", 7, 3);
        assert_eq!(&a[..4], &2u32.to_be_bytes());
        assert_ne!(a, approval_target(&[1, 2], "claim_release", 7, 4));
        assert_ne!(a, approval_target(&[1, 2], "cancel_release", 7, 3));
    }

    #[test]
    fn the_wire_form_is_the_vm_op_shape() {
        let v: Value = serde_json::from_slice(&OutflowRequest::Set { window_ms: 5, cap: 7, hold_ms: 9, guardian: None }.op_json(&[1, 2])).unwrap();
        assert_eq!(v["set"]["cap"], "7");
        assert_eq!(v["set"]["account"], json!([1, 2]));
        assert!(v.get("op").is_none());
        let tx = OutflowRequest::CancelRelease { id: 3, approval: None }.typed_transaction(&[1]).unwrap();
        assert_eq!(tx.kind, TxKind::AccountOutflow);
        assert!(tx.fields["op"].is_array());
    }

    #[test]
    fn the_node_answer_is_read_back_and_summarised() {
        let v = json!({"window_ms": DAY, "cap": (10 * T).to_string(), "hold_ms": 24 * HOUR, "guardian": "did:tenzro:human:g1",
            "pending": {"window_ms": DAY, "cap": (50 * T).to_string(), "hold_ms": 24 * HOUR, "guardian": "did:tenzro:human:g1", "remove": false, "effective_ms": 86_400_000}});
        let p = PolicyView::from_rpc(&v).unwrap();
        let rel = ReleaseView::from_rpc(&json!({"id": 4, "to": "b1", "amount": T.to_string(), "unlock_ms": 100})).unwrap();
        let t = describe_state(Some(&p), &[rel], 0).join(" ");
        assert!(t.contains("Queued: a looser policy") && t.contains("Queued payment #4") && t.contains("unlocks at"), "{t}");
        assert!(describe_state(None, &[], 0)[0].contains("not limited"));
        assert!(PolicyView::from_rpc(&Value::Null).is_none());
    }
}
