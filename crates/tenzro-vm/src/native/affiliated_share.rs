//! The share of sponsorship and grants paid to founder-affiliated accounts.
//!
//! Governance marks an account as affiliated with the network's founders
//! ([`crate::governance::ProposalAction::SetAffiliation`]); the recipient
//! cannot mark or clear itself. Once [`GATE`] is in force, every
//! sponsorship or grant paid to a marked account is counted per calendar
//! year beside the year's total of all sponsorship and grants, in the unit
//! the year is counted in (TNZO or USD), and published with the payout
//! report.
//!
//! The cap binds: a payout to a marked account that would lift the year's
//! affiliated share above [`CAP_PARAM`] is refused, and the transaction or
//! enactment that carried it fails, leaving the grant or sponsorship unpaid.
//! Payouts to unmarked recipients always proceed, so the base an affiliated
//! payout is measured against widens only through payouts to others.
//!
//! Records, under `SYSTEM_ADDRESS`:
//! - `affiliated:{account}` — present while the account is marked.
//! - `affiliated_accounts` — the marked accounts, hex.
//! - `affiliated_paid:{unit prefix}:{year}` — paid to marked accounts.

use serde::{Deserialize, Serialize};

use super::funding::{delete_record, read_json, refuse, write_json};
use super::*;

/// Gate of marking and of the cap.
pub const GATE: &str = "feature.affiliated_share.activation_epoch";

/// Governed key: most of a year's sponsorship and grants marked accounts
/// may receive, bps of the year's total.
pub const CAP_PARAM: &str = "feature.affiliated_share.max_bps";

/// Topic of the log a marking emits.
pub const AFFILIATION_TOPIC: &[u8] = b"AffiliationSet";

const INDEX_KEY: &str = "affiliated_accounts";

fn mark_key(account: &[u8]) -> String {
    format!("affiliated:{}", hex::encode(account))
}

fn paid_key(unit_prefix: &str, year: i64) -> String {
    format!("affiliated_paid:{unit_prefix}:{year}")
}

/// Whether governance marked `account` as affiliated.
pub fn is_affiliated(state: &dyn VmState, account: &[u8]) -> bool {
    read_json::<bool>(state, &mark_key(account)).unwrap_or(false)
}

/// The marked accounts, hex.
pub fn affiliated_accounts(state: &dyn VmState) -> Vec<String> {
    read_json(state, INDEX_KEY).unwrap_or_default()
}

/// Paid to marked accounts in `year`, in the unit `unit_prefix` names.
pub fn affiliated_paid(state: &dyn VmState, unit_prefix: &str, year: i64) -> u128 {
    read_json::<String>(state, &paid_key(unit_prefix, year))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Mark or clear `account`, as an enacted proposal says.
pub(super) fn set(
    state: &mut dyn VmState,
    account: &Address,
    affiliated: bool,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let hex_account = hex::encode(account.as_bytes());
    let mut index = affiliated_accounts(state);
    index.retain(|a| *a != hex_account);
    if affiliated {
        write_json(state, &mark_key(account.as_bytes()), &true, changes)?;
        index.push(hex_account.clone());
        index.sort();
    } else {
        delete_record(state, &mark_key(account.as_bytes()), changes);
    }
    write_json(state, INDEX_KEY, &index, changes)?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![AFFILIATION_TOPIC.to_vec()],
        serde_json::to_vec(&serde_json::json!({
            "account": hex_account,
            "affiliated": affiliated,
        }))
        .map_err(|e| VmError::Internal(format!("encode affiliation log: {e}")))?,
    ));
    Ok(())
}

/// Count `counted` paid to `account` in `year` against the cap, where
/// `total` is what the year paid every recipient before it. Nothing while
/// the gate is dormant or the account is unmarked; a refusal when the
/// payment would lift the year's affiliated share above the cap.
pub(super) fn count_payout(
    state: &mut dyn VmState,
    unit_prefix: &str,
    year: i64,
    total: u128,
    account: &[u8],
    counted: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if !crate::feature_gate::is_live_now(state, GATE) || !is_affiliated(state, account) {
        return Ok(());
    }
    let paid = affiliated_paid(state, unit_prefix, year).saturating_add(counted);
    let after = total.saturating_add(counted);
    let cap = u128::from(network_param(state, CAP_PARAM).min(10_000));
    if paid.saturating_mul(10_000) > cap.saturating_mul(after) {
        return Err(refuse(format!(
            "{} is marked as affiliated with the founders, and this payout would lift their \
             share of the year's sponsorship and grants above {cap} bps; it waits until \
             payouts to others widen the year's total",
            hex::encode(account)
        )));
    }
    write_json(
        state,
        &paid_key(unit_prefix, year),
        &paid.to_string(),
        changes,
    )?;
    Ok(())
}

/// One unit's year of affiliated payouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AffiliatedYear {
    /// Paid to marked accounts.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub paid: u128,
    /// Paid to every recipient.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub total: u128,
    /// `paid` over `total`, bps; zero when nothing was paid.
    pub share_bps: u64,
}

impl AffiliatedYear {
    pub(super) fn new(paid: u128, total: u128) -> Self {
        let share_bps = paid
            .saturating_mul(10_000)
            .checked_div(total)
            .map_or(0, |share| u64::try_from(share).unwrap_or(u64::MAX));
        AffiliatedYear {
            paid,
            total,
            share_bps,
        }
    }
}
