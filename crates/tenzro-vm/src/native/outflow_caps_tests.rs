//! Every path that pays TNZO out of network-held funds for an amount priced
//! in USD has a per-epoch ceiling in TNZO, so a chain rate that undervalues
//! TNZO cannot drain the treasury, the reward pool or the insurance pool.
//!
//! The paths are enumerated from the source: every conversion from a USD
//! amount to TNZO outside tests is listed below with what it is. A new
//! conversion fails the inventory until it is listed, and one that pays out
//! must name the governed TNZO ceilings that bound it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::state_adapter::StateAdapter;
use crate::traits::VmState;

/// What a USD-to-TNZO conversion is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    /// Someone pays it (a fee, a price, a bond or penalty owed by the
    /// party at fault): nothing leaves a network-held fund.
    Payer,
    /// A valuation or a requirement: nothing moves.
    Valuation,
    /// Paid out of a network-held fund, bounded per epoch by these governed
    /// whole-TNZO or TNZO-share ceilings.
    Outflow(&'static [&'static str]),
}

const PATTERNS: [&str; 4] = [
    "usd_to_wei(",
    "usd_e6_to_wei(",
    "amount_in_tnzo(",
    "amount_in_tnzo_at(",
];

fn inventory() -> BTreeMap<(&'static str, &'static str), Use> {
    use super::{insurance, rewards};
    BTreeMap::from([
        (("ledger.rs", "block_base_fee"), Use::Payer),
        (("ledger.rs", "resource_premium"), Use::Payer),
        // The USD demand target, converted only to compare paid demand
        // against it; it can lower the availability reward, never raise it.
        (
            ("native/availability_reward.rs", "demand_offset_bps"),
            Use::Valuation,
        ),
        (("native/economy.rs", "amount_in_tnzo"), Use::Valuation),
        (("native/economy.rs", "posted_fee"), Use::Payer),
        (("native/economy.rs", "fee_params"), Use::Payer),
        (("native/economy.rs", "check_agent_bond"), Use::Valuation),
        (("native/inference_fault.rs", "penalty_due"), Use::Payer),
        (
            ("native/payment_settlement.rs", "usd_e6_to_wei"),
            Use::Valuation,
        ),
        (
            ("native/payment_settlement.rs", "settle_native"),
            Use::Payer,
        ),
        (
            ("native/payment_settlement/plan.rs", "check_agent_plan"),
            Use::Payer,
        ),
        (
            ("native/payment_settlement/recon.rs", "apply"),
            Use::Outflow(&[
                insurance::MAX_CLAIM_TNZO_PARAM,
                insurance::MAX_PAID_EPOCH_PARAM,
            ]),
        ),
        (
            ("native/rewards.rs", "validator_base_rights"),
            Use::Outflow(&[
                rewards::VALIDATOR_BASE_CAP_PARAM,
                rewards::VALIDATOR_BURN_SHARE_PARAM,
            ]),
        ),
        (("native/security.rs", "unit_value_tnzo"), Use::Valuation),
        (("native/settlement_asset.rs", "quote_asset"), Use::Payer),
    ])
}

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

/// Every (file, enclosing function) outside tests that converts a USD amount
/// to TNZO.
fn conversion_sites() -> BTreeMap<(String, String), usize> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut found = BTreeMap::new();
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
        let mut current = String::new();
        for (i, line) in lines.iter().enumerate() {
            if line.trim() == "#[cfg(test)]"
                && lines[i + 1..]
                    .iter()
                    .find(|l| !l.trim().is_empty())
                    .is_some_and(|l| {
                        let l = l.trim_start();
                        ["mod ", "pub mod ", "pub(super) mod ", "pub(crate) mod "]
                            .iter()
                            .any(|p| l.starts_with(p))
                    })
            {
                break;
            }
            if let Some(name) = fn_name(line) {
                current = name;
            }
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for p in PATTERNS {
                if let Some(at) = code.find(p) {
                    // A definition, not a call.
                    if code[..at].ends_with("fn ") {
                        continue;
                    }
                    *found.entry((rel.clone(), current.clone())).or_insert(0) += 1;
                }
            }
        }
    }
    found
}

#[test]
fn every_usd_priced_tnzo_conversion_is_listed_and_every_outflow_names_its_ceilings() {
    let found = conversion_sites();
    let listed = inventory();
    let found_keys: Vec<(String, String)> = found.keys().cloned().collect();
    let listed_keys: Vec<(String, String)> = listed
        .keys()
        .map(|(f, n)| (f.to_string(), n.to_string()))
        .collect();
    assert_eq!(
        found_keys, listed_keys,
        "a USD-to-TNZO conversion was added or removed: list it with what it is, and give a payout its per-epoch TNZO ceiling"
    );
    for (site, use_) in listed {
        if let Use::Outflow(ceilings) = use_ {
            assert!(!ceilings.is_empty(), "{site:?} pays out with no ceiling");
            for key in ceilings {
                assert!(
                    crate::governance::governed_param(key).is_some(),
                    "{site:?}: ceiling {key} is not a governed parameter"
                );
            }
        }
    }
}

/// xorshift64*: deterministic per seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    /// Log-uniform in [lo, hi], scaled by 1e6.
    fn log_e6(&mut self, lo: f64, hi: f64) -> u128 {
        let u = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        ((lo.ln() + u * (hi.ln() - lo.ln())).exp() * 1e6) as u128
    }
}

const ONE: u128 = 1_000_000_000_000_000_000;

/// Over 10,000 seeds, with the chain rate anywhere from 0.05x to 20x the
/// market, the TNZO every listed outflow pays in one epoch stays within the
/// sum of its ceilings, however the USD amounts are priced.
#[test]
fn tnzo_paid_out_per_epoch_never_passes_the_sum_of_ceilings_over_10000_rate_gaps() {
    use super::{economy, insurance, rewards, set_governed_param_for_test};
    for seed in 0..10_000u64 {
        let mut r = Rng::new(seed);
        let mut state = StateAdapter::new();
        // Market $0.01..$10 a TNZO; the chain rate 0.05x..20x of it.
        let market = r.log_e6(0.01, 10.0) * 1_000;
        let gap_e6 = r.log_e6(0.05, 20.0);
        let chain = (market * gap_e6 / 1_000_000).max(1);
        economy::write_rate_for_tests(&mut state, 1, chain, chain);

        // Validator base rewards: USD running cost, TNZO cap, burn-funded.
        let burned = u128::from(r.below(1_000_000)) * ONE;
        economy::book_for_tests(&mut state, burned, 0);
        let share = r.below(10_001);
        set_governed_param_for_test(&mut state, rewards::VALIDATOR_BURN_SHARE_PARAM, share);
        set_governed_param_for_test(
            &mut state,
            rewards::VALIDATOR_BASE_COST_PARAM,
            r.below(100_000),
        );
        set_governed_param_for_test(
            &mut state,
            rewards::VALIDATOR_BASE_CAP_PARAM,
            r.below(1_000_000),
        );
        let active = 1 + r.below(300);
        let epoch = economy::read_current_epoch(&state);
        let base = rewards::validator_base_rights(&state, epoch, active, 8_760);
        let base_ceiling = burned * u128::from(share) / 10_000;

        // Insurance claims: losses priced in USD, converted at the chain
        // rate when the mismatch is recorded.
        let pool = insurance::pool_address();
        state.set_balance(pool.as_bytes(), u128::from(r.below(1_000_000_000)) * ONE);
        let epoch_cap = r.below(100_000);
        set_governed_param_for_test(&mut state, insurance::MAX_PAID_EPOCH_PARAM, epoch_cap);
        set_governed_param_for_test(
            &mut state,
            insurance::MAX_CLAIM_TNZO_PARAM,
            1 + r.below(100_000),
        );
        let mut claims = 0u128;
        for _ in 0..1 + r.below(20) {
            let loss = crate::native::usd_e6_to_wei(&state, r.below(1_000_000_000_000));
            let paid = insurance::payable(&state, loss);
            let held = state.get_balance(pool.as_bytes());
            assert!(paid <= held);
            state.set_balance(pool.as_bytes(), held - paid);
            insurance::book_paid(&mut state, paid, &mut Vec::new()).unwrap();
            claims += paid;
        }
        let claim_ceiling = u128::from(epoch_cap) * ONE;

        assert!(
            base <= base_ceiling,
            "seed {seed}: base {base} over {base_ceiling}"
        );
        assert!(
            claims <= claim_ceiling,
            "seed {seed}: claims {claims} over {claim_ceiling}"
        );
        assert!(base + claims <= base_ceiling + claim_ceiling, "seed {seed}");
    }
}
