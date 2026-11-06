//! The charter gate: every payout out of a network-held fund is tied to a
//! paid, verified unit of work, nothing is paid for holding, for time, for
//! volume or for signing up, and no path mints TNZO: its supply is fixed and
//! rewards are released from the pool funded at genesis.
//!
//! The paths are enumerated from the source: every function outside tests
//! that moves value out of the treasury, the rewards pool, the insurance
//! pool, the running-cost reserve or the validator cover reserve is listed
//! below with what ties it to paid work. A new path fails the inventory
//! until it is listed with its tie. The behavioural checks then run the
//! reward engine and the cover with consensus work but no paid settlement,
//! and require that nothing is paid.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::state_adapter::StateAdapter;
use crate::traits::VmState;
use tenzro_types::primitives::Address;

/// What ties a path's payout to paid, verified work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tie {
    /// Value flows into a network-held fund (fees, slashes): not a payout.
    Inflow,
    /// Pays for a unit of paid, verified work, named.
    PaidWork(&'static str),
    /// Exchanges value the payee was already paid for paid work, at most at
    /// par: no new value.
    Exchange,
    /// A payment a vote of bonded validators enacts, never automatic.
    Enacted(&'static str),
    /// Existing fund TNZO bonded on a validator's behalf by an enacted vote:
    /// it moves into the staking vault, is paid to nobody, earns nothing,
    /// and returns to the fund on recall or exit, less what a slash took.
    SponsoredBond(&'static str),
}

fn inventory() -> BTreeMap<(&'static str, &'static str), Tie> {
    BTreeMap::from([
        (("ledger.rs", "settle_block"), Tie::Inflow),
        (("native/bridge_committee.rs", "slash_member"), Tie::Inflow),
        (("native/economy.rs", "credit_fee"), Tie::Inflow),
        (("native/economy.rs", "record_fee_in"), Tie::Inflow),
        (("native/economy.rs", "slash_agent_bond"), Tie::Inflow),
        (
            ("native/inference_fault.rs", "slash_compute_bond"),
            Tie::Inflow,
        ),
        (
            ("native/inference_fault.rs", "slash_publisher"),
            Tie::Inflow,
        ),
        (("native/registry.rs", "governance_retire"), Tie::Inflow),
        (("native/staking.rs", "credit_pool"), Tie::Inflow),
        (
            ("native/availability_reward.rs", "pay_if_available"),
            Tie::PaidWork(
                "a verified-available SLA verdict: two thirds of bonded stake attested the \
                 subject answered unpredictable challenges, signed by its TPM-endorsed machine \
                 identity; an unavailable verdict slashes instead",
            ),
        ),
        (
            ("native/payment_settlement.rs", "reimburse_relayer"),
            Tie::PaidWork(
                "the gas a relayer fronted for a paid settlement, from that settlement's fee",
            ),
        ),
        (
            ("native/payment_settlement/recon.rs", "begin_block"),
            Tie::PaidWork("the reconciliation duty over paid settlements, per verified report"),
        ),
        (("native/payout_swap.rs", "fill_epoch"), Tie::Exchange),
        (("native/payout_swap.rs", "pay_out"), Tie::Exchange),
        (
            ("native/rewards.rs", "claim_rewards"),
            Tie::PaidWork(
                "coupons the reward engine issued for an epoch's recorded work, every bucket \
                 pegged to the reward ceilings of the paid settlements the epoch recorded",
            ),
        ),
        (
            ("native/treasury_reserve.rs", "begin_block"),
            Tie::PaidWork("enacted running costs, from a reserve filled only by fee revenue"),
        ),
        (
            ("native/validator_cover.rs", "cover_epoch"),
            Tie::PaidWork(
                "validators' running cost for an epoch of consensus work, from a reserve filled \
                 only by the stable fees paid settlements left the treasury",
            ),
        ),
        (
            ("native/funding.rs", "execute_funding"),
            Tie::Enacted("a treasury grant or tranche a vote of bonded validators enacts"),
        ),
        (
            ("native/funding.rs", "pay_grant"),
            Tie::Enacted("a treasury grant or tranche a vote of bonded validators enacts"),
        ),
        (
            ("native/payout_gates.rs", "sponsor_running_cost"),
            Tie::Enacted(
                "running cost an enacted proposal pays an approved operator out of the treasury, \
                 only against hours the challenge protocol judged it available, each hour once, \
                 within the yearly caps and the treasury outflow caps",
            ),
        ),
        (
            ("native/stable_payout.rs", "transfer_out"),
            Tie::Enacted(
                "a stable asset the treasury already holds, paid by an enacted proposal or a \
                 verified-milestone release to an approved operator or grantee only, valued in \
                 US dollars, within the USD yearly caps and the stable outflow limit; the asset \
                 moves between balances and none is issued",
            ),
        ),
        (
            ("native/sponsored_bond.rs", "sponsor_bond"),
            Tie::SponsoredBond(
                "existing treasury TNZO an enacted SponsorValidatorBond moves into the staking \
                 vault as part of a validator's bond: never issued, never paid to the validator, \
                 never a reward; recallable, slashable, returned to the treasury",
            ),
        ),
    ])
}

/// Accounts whose balance is network-held.
const FUNDS: [&str; 6] = [
    "derive_treasury_address()",
    "reserve_address()",
    "rewards_pool_address()",
    "derive_insurance_pool_address()",
    "insurance::pool_address()",
    "validator_cover::reserve_address()",
];

/// Calls that move value.
const MOVES: [&str; 5] = [
    "move_balance(",
    "move_asset(",
    "open_vesting(",
    "set_balance(",
    "token_ledger::transfer(",
];

/// Lending, borrowing, staking derivatives and TNZO issuance beyond the
/// fixed supply: the chain offers none of them.
const BANNED: [&str; 9] = [
    "fn borrow",
    "fn lend",
    "LiquidStaking",
    "fn mint_staked_derivative",
    "collateral_ratio",
    "fn liquidate_loan",
    "fn mint_tnzo",
    "fn mint_native",
    "fn inflate",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn fn_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    let starts = ["fn ", "pub ", "pub(", "async ", "const fn ", "unsafe "];
    if !starts.iter().any(|s| t.starts_with(s)) {
        return None;
    }
    let at = t.find("fn ")?;
    let name: String = t[at + 3..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Every (file, function) outside tests whose body names a network-held
/// fund and moves value, and every line that names a banned instrument.
fn scan() -> (BTreeMap<(String, String), ()>, Vec<String>) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut found = BTreeMap::new();
    let mut banned = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel.ends_with("tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut bodies: BTreeMap<String, String> = BTreeMap::new();
        let mut current = String::new();
        for (i, line) in lines.iter().enumerate() {
            if line.trim() == "#[cfg(test)]"
                && lines[i + 1..]
                    .iter()
                    .find(|l| !l.trim().is_empty())
                    .is_some_and(|l| {
                        let l = l.trim_start();
                        l.starts_with("mod ")
                            || l.starts_with("pub(super) mod ")
                            || l.starts_with("pub mod ")
                    })
            {
                break;
            }
            if let Some(name) = fn_name(line) {
                current = name;
            }
            let code = line.trim_start();
            if code.starts_with("//") || current.is_empty() {
                continue;
            }
            for b in BANNED {
                if code.contains(b) {
                    banned.push(format!("{rel}: {code}"));
                }
            }
            let body = bodies.entry(current.clone()).or_default();
            body.push_str(code);
            body.push('\n');
        }
        for (name, body) in bodies {
            if FUNDS.iter().any(|f| body.contains(f)) && MOVES.iter().any(|m| body.contains(m)) {
                found.insert((rel.clone(), name), ());
            }
        }
    }
    (found, banned)
}

#[test]
fn every_payout_path_is_listed_and_tied_to_paid_verified_work() {
    let (found, banned) = scan();
    let found: Vec<(String, String)> = found.into_keys().collect();
    let listed = inventory();
    let listed_keys: Vec<(String, String)> = listed
        .keys()
        .map(|(f, n)| (f.to_string(), n.to_string()))
        .collect();
    assert_eq!(
        found, listed_keys,
        "a path that moves value out of a network-held fund was added or removed: list it with what ties it to paid, verified work"
    );
    for (site, tie) in &listed {
        match tie {
            Tie::Inflow | Tie::Exchange => {}
            Tie::PaidWork(why) | Tie::Enacted(why) | Tie::SponsoredBond(why) => {
                assert!(!why.is_empty(), "{site:?} names no tie")
            }
        }
    }
    assert!(
        banned.is_empty(),
        "the chain offers no borrowing against TNZO and no staking derivative: {banned:?}"
    );
}

/// A governance-sponsored bond is existing treasury TNZO held in the staking
/// vault, never a payout: sponsoring, a week of consensus work by the
/// sponsored validator with no paid usage, a slash, a recall and the return
/// issue no coupon to anyone, pay the validator nothing, and leave the TNZO
/// in existence exactly what it was, the slashed part in the insurance pool.
#[test]
fn a_sponsored_bond_is_never_a_payout_or_a_reward_and_never_issues_tnzo() {
    use super::rewards;
    use super::staking;
    let mut state = StateAdapter::new();
    state.set_storage(
        &crate::native::SYSTEM_ADDRESS,
        rewards::REWARD_SCHEDULE_KEY.as_bytes(),
        rewards::genesis_reward_schedule(86_400_000).unwrap(),
    );
    let pool = tenzro_token::rewards::rewards_pool_address();
    state.set_balance(pool.as_bytes(), tenzro_token::rewards::NETWORK_REWARDS_POOL);
    super::economy::write_rate_for_tests(&mut state, 1, 100_000_000, 100_000_000);
    let one = tenzro_types::constants::ONE_TNZO;
    let treasury = crate::native::derive_treasury_address();
    state.set_balance(treasury.as_bytes(), 10_000_000 * one);
    let validator = Address::new([7; 32]);
    let v = validator.as_bytes().to_vec();
    state.set_storage(
        &crate::native::SYSTEM_ADDRESS,
        format!("validator_register:{}", hex::encode(&v)).as_bytes(),
        b"{}".to_vec(),
    );
    staking::add_bond(&mut state, &v, 1_000 * one, 0).unwrap();
    state.set_balance(&crate::native::STAKING_VAULT_ADDRESS, 1_000 * one);
    for (key, value) in [
        (super::sponsored_bond::MAX_PER_VALIDATOR_PARAM, 100_000u64),
        (super::sponsored_bond::MAX_TOTAL_PARAM, 100_000u64),
    ] {
        state.set_storage(
            &crate::native::SYSTEM_ADDRESS,
            crate::native::governed_param_key(key).as_bytes(),
            value.to_le_bytes().to_vec(),
        );
    }
    let validator_balance = state.get_balance(&v);
    let mut changes = Vec::new();
    let mut logs = Vec::new();

    super::payout_gates::approve_operator_for_test(
        &mut state,
        &v,
        crate::governance::OperatorClass::Validator,
    );
    assert!(state.begin_transaction());
    super::sponsored_bond::sponsor_bond(
        &mut state,
        "proposal",
        &v,
        50_000 * one,
        1,
        &mut changes,
        &mut logs,
    )
    .unwrap();
    for epoch in 0..8u64 {
        rewards::begin_block(&mut state, epoch, &validator, epoch as i64 * 86_400_000 + 2).unwrap();
    }
    staking::slash_to_insurance(
        &mut state,
        &v,
        staking::SlashedStake::Validator,
        1_000,
        &mut changes,
    )
    .unwrap();
    let left = staking::sponsored_bond_of(&state, &v);
    super::sponsored_bond::recall_bond(&mut state, &v, left, 8 * 86_400_000, &mut logs).unwrap();
    let matured =
        8 * 86_400_000 + crate::native::network_param(&state, staking::UNBONDING_PARAM) as i64;
    let returned = staking::release_recalled(&mut state, &v, matured).unwrap();
    let delta = state.journal_balance_delta();
    state.commit_transaction();

    assert_eq!(delta, Some(0), "a sponsored bond created or destroyed TNZO");
    assert_eq!(returned, left);
    assert_eq!(
        state.get_balance(&v),
        validator_balance,
        "the validator was paid"
    );
    for who in [validator, treasury] {
        assert!(
            rewards::read_coupons(&state, &who).unwrap().is_empty(),
            "{who:?} was issued a reward for a sponsored bond"
        );
    }
    assert_eq!(
        state.get_balance(pool.as_bytes()),
        tenzro_token::rewards::NETWORK_REWARDS_POOL,
        "the pool paid nothing"
    );
    assert_eq!(staking::total_sponsored_outstanding(&state), 0);
}

/// Seven validators propose and vote for a week of one-day epochs and
/// nobody pays for anything: no coupon is issued, no base and no cover is
/// paid. Consensus over an economy with no paid usage earns nothing.
#[test]
fn with_no_paid_work_no_reward_is_issued() {
    use super::rewards;
    let mut state = StateAdapter::new();
    state.set_storage(
        &crate::native::SYSTEM_ADDRESS,
        rewards::REWARD_SCHEDULE_KEY.as_bytes(),
        rewards::genesis_reward_schedule(86_400_000).unwrap(),
    );
    let pool = tenzro_token::rewards::rewards_pool_address();
    state.set_balance(pool.as_bytes(), tenzro_token::rewards::NETWORK_REWARDS_POOL);
    super::economy::write_rate_for_tests(&mut state, 1, 100_000_000, 100_000_000);
    let validators: Vec<Address> = (1..=7u8).map(|v| Address::new([v; 32])).collect();
    // TNZO's supply is fixed: no step of the reward engine credits TNZO it
    // did not debit somewhere.
    assert!(state.begin_transaction());
    for epoch in 0..8u64 {
        for (i, v) in validators.iter().enumerate() {
            rewards::begin_block(
                &mut state,
                epoch,
                v,
                epoch as i64 * 86_400_000 + i as i64 * 1_000 + 1,
            )
            .unwrap();
        }
    }
    let delta = state.journal_balance_delta();
    state.commit_transaction();
    assert!(
        delta.is_some_and(|d| d <= 0),
        "the reward engine created TNZO: balance delta {delta:?}"
    );
    for v in &validators {
        let coupons = rewards::read_coupons(&state, v).unwrap();
        assert!(
            coupons.is_empty(),
            "{v:?} was issued {} coupon(s) with no paid work: {:?}",
            coupons.len(),
            coupons
                .iter()
                .map(|c| (c.amount, c.base))
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(
        state.get_balance(pool.as_bytes()),
        tenzro_token::rewards::NETWORK_REWARDS_POOL,
        "the pool paid nothing"
    );
}

/// The source of the top-level function `name` in `rel`.
fn fn_source(rel: &str, name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut out = String::new();
    let mut inside = false;
    for line in text.lines() {
        if !inside && fn_name(line).as_deref() == Some(name) && !line.starts_with(' ') {
            inside = true;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
            if line == "}" {
                break;
            }
        }
    }
    assert!(!out.is_empty(), "{rel} has no top-level fn {name}");
    out
}

/// Every payout out of the treasury is either a governance action or a
/// release against verified work, and each counts against the treasury's
/// outflow period and a recipient gate. The unattended ones (the availability
/// reward and the reconciliation duty reward) carry no proposal, so the
/// outflow period is their cap; the enacted ones pass the approval, the
/// verified-work or milestone check and the yearly caps first.
#[test]
fn every_treasury_payout_counts_against_the_outflow_period_and_its_gate() {
    let must: &[(&str, &str, &[&str])] = &[
        (
            "native/availability_reward.rs",
            "pay_if_available",
            &["record_outflow(", "machine_endorsed("],
        ),
        (
            "native/payment_settlement/recon.rs",
            "begin_block",
            &["record_outflow("],
        ),
        (
            "native/funding.rs",
            "pay_grant",
            &["record_grant_payment(", "record_outflow("],
        ),
        (
            "native/sponsored_bond.rs",
            "sponsor_bond",
            &["record_bond_sponsorship(", "treasury_outflow("],
        ),
        (
            "native/payout_gates.rs",
            "sponsor_running_cost",
            &[
                "plan_running_cost(",
                "check_sponsorship_caps(",
                "treasury_outflow(",
            ],
        ),
        (
            "native/payout_gates.rs",
            "commit_reserve_payment",
            &[
                "plan_running_cost(",
                "check_sponsorship_caps(",
                "commit_outflow(",
            ],
        ),
        (
            "native/treasury_reserve.rs",
            "begin_block",
            &[
                "require_approved_operator(",
                "outflow_headroom(",
                "record_outflow(",
            ],
        ),
        (
            "native/stable_payout.rs",
            "sponsor_stable",
            &[
                "plan_hours(",
                "check_sponsorship_caps(",
                "commit_stable(",
                "record_stable(",
            ],
        ),
        (
            "native/stable_payout.rs",
            "pay_grant_stable",
            &[
                "require_approved_grantee(",
                "check_grant_caps(",
                "record_stable(",
            ],
        ),
        (
            "native/stable_payout.rs",
            "pay_remote",
            &[
                "plan_hours(",
                "check_sponsorship_caps(",
                "commit_stable(",
                "record_stable(",
            ],
        ),
        (
            "native/funding.rs",
            "release_milestone",
            &["check_next_tranche(", "verified_ms", "pay_grant("],
        ),
        (
            "native/funding.rs",
            "enact_grant",
            &[
                "require_approved_grantee(",
                "commit_outflow(",
                "commit_grant(",
            ],
        ),
    ];
    for (rel, name, calls) in must.iter().copied() {
        let body = fn_source(rel, name);
        for call in calls {
            assert!(
                body.contains(call),
                "{rel} {name} pays out of the treasury without {call}"
            );
        }
    }
    // The approval gate itself refuses an unapproved or revoked recipient.
    let gate = fn_source("native/payout_gates.rs", "record_grant_payment");
    assert!(gate.contains("require_approved_grantee("));
    let gate = fn_source("native/payout_gates.rs", "record_bond_sponsorship");
    assert!(gate.contains("require_approved_operator("));
    let gate = fn_source("native/payout_gates.rs", "plan_hours");
    assert!(gate.contains("require_approved_operator("));
    assert!(gate.contains("unused_verified_epochs("));
    // A stable asset pays only when the registry prices it on its USD peg.
    let gate = fn_source("native/stable_payout.rs", "price");
    assert!(gate.contains("permitted("));
    assert!(gate.contains("NUMERAIRE"));
}

/// Unowned funds return to the treasury and the treasury is never a source:
/// recovery is not a payout route.
#[test]
fn recovering_unowned_funds_cannot_pay_out_of_the_treasury() {
    let src = fn_source("native/mod.rs", "is_recoverable_source");
    assert!(
        !src.contains("derive_treasury_address"),
        "the treasury is not a recoverable source"
    );
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/native/mod.rs");
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains("unowned funds return to the treasury"));
}
