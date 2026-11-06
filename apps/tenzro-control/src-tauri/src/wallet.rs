//! Operator account: custody, balance, and what that balance unlocks.
//!
//! Two things happen here that look like one thing. The account is the
//! ledger account of this machine's hardware key (TPM 2.0 or Secure
//! Enclave), read from the key's public half and fixed for the life of the
//! install. Reading the balance decides *which roles the operator may
//! offer*, because every role carries a stake minimum and a role card
//! that cannot be met should say so with a number rather than failing
//! later at role-set time.
//!
//! Balances are read back through the node's own `tenzro_getBalance`
//! rather than through `node.token().balance_of()` directly. That
//! matters: the workspace has two functions that
//! turn a hex string into an `Address` and they do not agree about
//! 20-byte inputs — one right-aligns into the 32-byte array, the other
//! left-aligns. A smart-account address is 20 bytes. Crediting through
//! one convention and reading through the other yields a balance of
//! zero on an account that holds funds. Going through the RPC means the
//! read uses literally the same parser as the credit, so the two cannot
//! drift apart.

use serde::Serialize;
use serde_json::json;

use tenzro_types::network::StakeLadder;

use crate::config::{self, Custody};
use crate::state::AppState;

const TNZO_DECIMALS: u32 = 18;

/// Wei to a human figure with four decimal places.
///
/// Four is enough to distinguish the amounts an operator deals in
/// without turning a dashboard into a wall of zeroes.
pub fn format_tnzo(wei: u128) -> String {
    let unit = 10u128.pow(TNZO_DECIMALS);
    let whole = wei / unit;
    let frac = (wei % unit) / 10u128.pow(TNZO_DECIMALS - 4);
    format!("{}.{:04}", whole, frac)
}

/// `0x1234…abcd` — long enough to recognise, short enough for a chip.
fn abbreviate(hex: &str) -> String {
    if hex.len() <= 14 {
        return hex.to_string();
    }
    format!("{}…{}", &hex[..6], &hex[hex.len() - 4..])
}

/// One role, and where this wallet stands against its minimum.
#[derive(Debug, Clone, Serialize)]
pub struct RoleStakeGate {
    /// Wire token, as stored in `ControlConfig::roles`.
    pub role: String,
    /// Operator-facing name.
    pub label: String,
    pub required_wei: String,
    pub required_display: String,
    /// The stake bonded for *this* role covers it.
    pub met: bool,
    /// Amount bonded for this role in chain state.
    pub staked_wei: String,
    pub staked_display: String,
    /// The balance covers the minimum, so a `Stake` bond for the role would
    /// go through right now.
    pub can_stake: bool,
    /// Zero when `met`. What the operator still has to acquire.
    pub shortfall_wei: String,
    pub shortfall_display: String,
}

/// Project balance and bonded stakes against every role minimum.
///
/// Two figures, because they answer different questions. `met` asks
/// whether the role's bond is already posted; `can_stake` asks whether
/// posting it would succeed. They are never both true. Each role is its
/// own stake in chain state, so a bond for one role never blocks another.
///
/// Storage and compute bonds rise with the capacity pledged; the floor is
/// the figure these gates report. The amounts are the governed ones in force
/// (`ladder`).
pub fn role_gates(balance_wei: u128, stakes: &[(&str, u128)], ladder: &StakeLadder) -> Vec<RoleStakeGate> {
    [
        ("validator", "Validator", ladder.validator),
        ("ai", "AI inference", ladder.model),
        ("storage", "Storage", ladder.storage_floor),
        ("compute", "Compute", ladder.compute_floor),
        ("tee", "Confidential compute", ladder.tee),
    ]
    .into_iter()
    .map(|(role, label, required)| {
        let mine = stakes.iter().find(|(r, _)| *r == role).map_or(0, |(_, a)| *a);
        let met = mine >= required;
        let can_stake = !met && balance_wei >= required;
        let shortfall = required.saturating_sub(mine.max(balance_wei));

        RoleStakeGate {
            role: role.to_string(),
            label: label.to_string(),
            required_wei: required.to_string(),
            required_display: format_tnzo(required),
            met,
            staked_wei: mine.to_string(),
            staked_display: format_tnzo(mine),
            can_stake,
            shortfall_wei: shortfall.to_string(),
            shortfall_display: format_tnzo(shortfall),
        }
    })
    .collect()
}

/// Everything the wallet screen and the dashboard chip need in one read.
#[derive(Debug, Clone, Serialize)]
pub struct WalletStatusView {
    /// An account has been provisioned.
    pub exists: bool,
    pub address: String,
    pub display_address: String,
    pub did: String,
    pub custody: Custody,
    /// Decimal string — u128 does not survive JSON.
    pub balance_wei: String,
    pub balance_display: String,
    /// Total bonded across roles, held in the role-stake vault.
    pub staked_wei: String,
    pub staked_display: String,
    /// Wire tokens of the roles with a bond, comma-separated, empty when
    /// nothing is staked.
    pub staked_role: String,
    /// When the earliest unbonding stake can be withdrawn.
    pub unbonding_at_ms: Option<i64>,
    /// Wire tokens of the roles with stake unbonding.
    pub unbonding_roles: Vec<String>,
    /// The account stakes are bonded from, signed by this machine's hardware
    /// or a passkey. Balance gates and stakes are this account's.
    pub stake_account: crate::native_tx::StakeAccount,
    pub stake_balance_wei: String,
    pub stake_balance_display: String,
    /// The node has finished starting. A false here means "ask again",
    /// not "something is wrong".
    pub node_ready: bool,
    pub gates: Vec<RoleStakeGate>,
}

impl WalletStatusView {
    fn empty(node_ready: bool) -> Self {
        Self {
            exists: false,
            address: String::new(),
            display_address: String::new(),
            did: String::new(),
            custody: Custody::None,
            balance_wei: "0".to_string(),
            balance_display: format_tnzo(0),
            staked_wei: "0".to_string(),
            staked_display: format_tnzo(0),
            staked_role: String::new(),
            unbonding_at_ms: None,
            unbonding_roles: Vec::new(),
            stake_account: Default::default(),
            stake_balance_wei: "0".to_string(),
            stake_balance_display: format_tnzo(0),
            node_ready,
            gates: role_gates(0, &[], &StakeLadder::genesis()),
        }
    }
}

/// The account's stakes per role, read from chain state.
#[derive(Debug, Clone, Default)]
struct StakeSnapshot {
    /// (role wire token, bonded wei)
    stakes: Vec<(&'static str, u128)>,
    release_at_ms: Option<i64>,
    unbonding: Vec<String>,
}

fn read_stake(node: &std::sync::Arc<tenzro_node::TenzroNode>, address: &str) -> StakeSnapshot {
    let Some(chain) = node.chain_state() else {
        return StakeSnapshot::default();
    };
    let Ok(account) = hex::decode(address.trim_start_matches("0x")) else {
        return StakeSnapshot::default();
    };
    let mut snapshot = StakeSnapshot::default();
    for (role, stake) in tenzro_vm::native::role_stakes_of(&chain, &account) {
        if stake.bonded > 0 {
            snapshot.stakes.push((role.as_str(), stake.bonded));
        }
        if stake.unbonding > 0 {
            snapshot.unbonding.push(role.as_str().to_string());
            snapshot.release_at_ms = Some(snapshot.release_at_ms.map_or(stake.release_at_ms, |t| t.min(stake.release_at_ms)));
        }
    }
    let validator = tenzro_vm::native::bonded_stake_of(&chain, &account);
    if validator > 0 {
        snapshot.stakes.push(("validator", validator));
    }
    snapshot
}

/// Current account state.
///
/// The persisted identity is the account. With none recorded there is no
/// account yet.
pub async fn status(state: &AppState) -> Result<WalletStatusView, String> {
    let node = {
        let guard = state.node.read().await;
        match guard.as_ref() {
            Some(h) => h.node(),
            None => return Ok(WalletStatusView::empty(false)),
        }
    };

    let identity = config::get().identity;

    if identity.address.is_empty() {
        return Ok(WalletStatusView::empty(true));
    }
    let (address, did, custody) = (identity.address, identity.did, identity.custody);

    let balance_wei = balance_of(&address, state).await.unwrap_or(0);


    let stake_account = tokio::task::spawn_blocking(crate::native_tx::stake_account)
        .await
        .map_err(|e| e.to_string())?;
    let (stake, stake_balance_wei) = if stake_account.address.is_empty() {
        (StakeSnapshot::default(), 0)
    } else {
        (
            read_stake(&node, &stake_account.address),
            balance_of(&stake_account.address, state).await.unwrap_or(0),
        )
    };
    let ladder = node
        .chain_state()
        .map(|chain| tenzro_vm::native::stake_ladder(&chain))
        .unwrap_or_else(StakeLadder::genesis);
    let gates = role_gates(stake_balance_wei, &stake.stakes, &ladder);
    let total: u128 = stake.stakes.iter().map(|(_, a)| *a).sum();
    let roles = stake.stakes.iter().map(|(r, _)| *r).collect::<Vec<_>>().join(",");

    Ok(WalletStatusView {
        exists: true,
        display_address: abbreviate(&address),
        address,
        did,
        custody,
        balance_wei: balance_wei.to_string(),
        balance_display: format_tnzo(balance_wei),
        staked_wei: total.to_string(),
        staked_display: format_tnzo(total),
        staked_role: roles,
        unbonding_at_ms: stake.release_at_ms,
        unbonding_roles: stake.unbonding,
        stake_account,
        stake_balance_wei: stake_balance_wei.to_string(),
        stake_balance_display: format_tnzo(stake_balance_wei),
        node_ready: true,
        gates,
    })
}

/// Balance in wei, through the node's own parser. See the module note.
pub(crate) async fn balance_of(address: &str, state: &AppState) -> Result<u128, String> {
    let value = crate::rpc::rpc_result("tenzro_getBalance", json!({ "address": address }), state)
        .await?;
    parse_balance(&value)
}

/// The wei amount a `tenzro_getBalance` answer carries (`0x`-prefixed hex).
fn parse_balance(value: &serde_json::Value) -> Result<u128, String> {
    let hex = value
        .as_str()
        .ok_or_else(|| "tenzro_getBalance did not return a string".to_string())?;
    let digits = hex.strip_prefix("0x").unwrap_or(hex);
    u128::from_str_radix(digits, 16).map_err(|e| format!("unparseable balance {}: {}", hex, e))
}

/// Set up the operator's wallet: the ledger account of this machine's
/// hardware key, the key the node's identity is held under. Nothing is
/// created here and no key leaves the hardware; the account and the DID
/// are read from the key's public half.
pub async fn use_hardware_key(state: &AppState, display_name: String) -> Result<WalletStatusView, String> {
    let signer = crate::native_tx::open_signer().await?;
    let identity = crate::machine_identity::identity_of(&signer)?;
    let address = signer.address();
    let name = display_name.trim().to_string();
    config::update(|c| {
        c.identity.did = identity.did.clone();
        c.identity.address = address.clone();
        c.identity.custody = Custody::Hardware;
        c.identity.display_name = name.clone();
    })?;
    status(state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g() -> StakeLadder {
        StakeLadder::genesis()
    }

    const ONE: u128 = 1_000_000_000_000_000_000;

    #[test]
    fn formats_to_four_places() {
        assert_eq!(format_tnzo(0), "0.0000");
        assert_eq!(format_tnzo(ONE), "1.0000");
        assert_eq!(format_tnzo(ONE * 10_000), "10000.0000");
        assert_eq!(format_tnzo(ONE / 2), "0.5000");
    }

    #[test]
    fn truncates_below_four_places_rather_than_rounding_up() {
        // A balance that reads as 1.0000 must actually be at least 1.
        assert_eq!(format_tnzo(ONE - 1), "0.9999");
    }

    #[test]
    fn abbreviation_keeps_both_ends() {
        let a = "0x1234567890abcdef1234567890abcdef12345678";
        assert_eq!(abbreviate(a), "0x1234…5678");
    }

    #[test]
    fn short_addresses_are_left_alone() {
        assert_eq!(abbreviate("0x1234"), "0x1234");
    }

    #[test]
    fn empty_wallet_meets_nothing_and_reports_the_full_gap() {
        let gates = role_gates(0, &[], &g());
        assert!(gates.iter().all(|g| !g.met));
        assert!(gates.iter().all(|g| !g.can_stake));
        let validator = gates.iter().find(|g| g.role == "validator").unwrap();
        assert_eq!(validator.shortfall_wei, g().validator.to_string());
    }

    #[test]
    fn cheaper_roles_open_before_validator() {
        let gates = role_gates(g().model, &[], &g());
        let ai = gates.iter().find(|g| g.role == "ai").unwrap();
        let validator = gates.iter().find(|g| g.role == "validator").unwrap();
        assert!(ai.can_stake);
        assert!(!validator.can_stake);
        assert_eq!(
            validator.shortfall_wei,
            (g().validator - g().model).to_string()
        );
    }

    #[test]
    fn a_balance_alone_never_counts_as_a_posted_bond() {
        let gates = role_gates(g().validator, &[], &g());
        assert!(gates.iter().all(|g| !g.met));
        assert!(gates.iter().all(|g| g.can_stake));
        assert!(gates.iter().all(|g| g.staked_wei == "0"));
    }

    #[test]
    fn each_role_is_its_own_bond() {
        let gates = role_gates(g().validator, &[("validator", g().validator)], &g());
        for gate in &gates {
            if gate.role == "validator" {
                assert!(gate.met);
                assert_eq!(gate.shortfall_wei, "0");
            } else {
                assert!(!gate.met);
                assert!(gate.can_stake, "{} stays open", gate.role);
            }
        }
    }

    #[test]
    fn an_underfunded_bond_still_reports_the_remaining_gap() {
        let short = g().validator - g().model;
        let gates = role_gates(0, &[("validator", short)], &g());
        let validator = gates.iter().find(|g| g.role == "validator").unwrap();
        assert!(!validator.met);
        assert_eq!(validator.shortfall_wei, g().model.to_string());
    }

    #[test]
    fn every_role_token_is_covered() {
        let gates = role_gates(0, &[], &g());
        let roles: Vec<&str> = gates.iter().map(|g| g.role.as_str()).collect();
        assert_eq!(roles, vec!["validator", "ai", "storage", "compute", "tee"]);
    }

    #[test]
    fn a_balance_answer_is_read_as_hex_wei() {
        assert_eq!(parse_balance(&json!("0x0")).unwrap(), 0);
        assert_eq!(parse_balance(&json!("0xde0b6b3a7640000")).unwrap(), 1_000_000_000_000_000_000);
        assert!(parse_balance(&json!(12)).is_err());
        assert!(parse_balance(&json!("0xnothex")).is_err());
    }
}
