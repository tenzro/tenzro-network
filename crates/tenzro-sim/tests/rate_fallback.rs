//! The TNZO/USD rate that prices fees fails safe: missing reports hold fees
//! at the last good rate and the read surface reports the hold once the
//! rate passes its governed maximum age; manipulated reports move the rate
//! by at most the per-epoch bound, or not at all.
//!
//! Twenty-one validators of equal stake report hourly, each report quoting
//! two sources.
//!
//! Run with `cargo test -p tenzro-sim --test rate_fallback`.

use std::collections::BTreeMap;

use tenzro_sim::ledger::{self, Envelope, Genesis, Ledger, SimTx};
use tenzro_vm::native as n;
use tenzro_vm::native::economy as e;

const HOUR_MS: u64 = 3_600_000;
const VALIDATORS: u32 = 21;
const START_NANO: u128 = 100_000_000;
const ONE_USD_ATTO: u128 = 1_000_000_000_000_000_000;

type Sealed = Option<(u64, Vec<(String, String, u128)>, [u8; 32])>;

fn report(v: u32, nonce: u64, sealed: &mut Sealed, closed: u64, rate: u128) -> SimTx {
    let quotes = vec![
        ("TNZO".to_string(), "venue-a".to_string(), rate),
        ("TNZO".to_string(), "venue-b".to_string(), rate),
    ];
    let mut salt = [0u8; 32];
    salt[..8].copy_from_slice(&closed.to_be_bytes());
    salt[8..12].copy_from_slice(&v.to_be_bytes());
    let commitment = tenzro_types::fee_rate_commitment(
        &ledger::account(v),
        closed,
        &salt,
        quotes.iter().map(|(a, b, x)| (a.as_str(), b.as_str(), *x)),
    );
    let reveal = sealed
        .take()
        .filter(|(e, _, _)| *e + 1 == closed)
        .map(|(_, q, salt)| {
            serde_json::json!({
                "quotes": q.iter().map(|(s, src, x)| serde_json::json!({
                    "symbol": s, "source": src, "rate_nano_usd": x.to_string(),
                })).collect::<Vec<_>>(),
                "salt": hex::encode(salt),
            })
        });
    *sealed = Some((closed, quotes, salt));
    let payload = serde_json::json!({
        "epoch": closed,
        "commitment": hex::encode(commitment),
        "reveal": reveal,
    });
    let mut data = n::SELECTOR_FEE_RATE_SUBMIT.to_vec();
    data.extend_from_slice(payload.to_string().as_bytes());
    SimTx::Call {
        from: v,
        to: None,
        value: 0,
        data,
        gas: 2_000_000,
        max_fee: None,
        nonce,
    }
}

/// What the chain shows at the end of one hour.
#[derive(Debug, Clone, Copy)]
struct Hour {
    hour: u64,
    rate: u128,
    wei_per_usd: u128,
    held: bool,
    governance: bool,
}

/// Runs `hours` hourly blocks. `rate_of(hour, validator, in_force)` is what
/// a validator reports for the epoch that just closed, or `None` to stay
/// silent.
fn run(hours: u64, rate_of: impl Fn(u64, u32, u128) -> Option<u128>) -> Vec<Hour> {
    let mut params = BTreeMap::new();
    params.insert("fees.usd_rate_mode".to_string(), 1);
    params.insert("fees.tnzo_usd_nano".to_string(), START_NANO as u64);
    let mut chain = Ledger::genesis(&Genesis {
        active: VALIDATORS,
        standby: 0,
        users: 0,
        bond_tnzo: 100_000,
        balance_tnzo: 1_000,
        calendar_scale: 1,
        epoch_ms: HOUR_MS,
        network_params: params,
        accounts: Vec::new(),
        strict_supply: false,
    });
    let mut sealed: Vec<Sealed> = vec![None; VALIDATORS as usize];
    let mut path = Vec::new();
    for hour in 2..=hours {
        let at = hour * HOUR_MS + HOUR_MS / 2;
        let closed = hour - 1;
        let in_force = n::read_fee_rate(chain.state()).rate_nano_usd;
        let mut txs = Vec::new();
        for v in 0..VALIDATORS {
            let Some(rate) = rate_of(hour, v, in_force) else {
                continue;
            };
            let nonce = chain.nonce(v);
            let tx = report(v, nonce, &mut sealed[v as usize], closed, rate);
            txs.push(Envelope {
                submitted_ms: at,
                tx,
            });
        }
        let h = chain.height() + 1;
        let mut content = [0u8; 32];
        content[..8].copy_from_slice(&h.to_be_bytes());
        chain.execute(h, content, content, 1, 0, hour, at, 0, txs);
        for r in std::mem::take(&mut chain.results) {
            assert!(r.applied, "hour {hour}: report refused: {}", r.error);
        }
        let state = chain.state();
        path.push(Hour {
            hour,
            rate: n::read_fee_rate(state).rate_nano_usd,
            wei_per_usd: n::usd_to_wei(state, ONE_USD_ATTO),
            held: e::rate_age(state, e::FEE_SYMBOL, at as i64).held,
            governance: n::read_fee_rate(state).mode == "governance",
        });
    }
    assert!(chain.conservation_failures.is_empty());
    path
}

fn at(path: &[Hour], hour: u64) -> Hour {
    *path.iter().find(|h| h.hour == hour).expect("hour")
}

/// A market sliding 0.5% an hour, inside the 1% hourly bound.
fn sliding(hour: u64) -> u128 {
    START_NANO * (1_000 - 5 * u128::from(hour)) / 1_000
}

#[test]
fn missing_reports_hold_fees_at_the_last_good_rate_and_the_hold_is_visible() {
    const LAST: u64 = 20;
    const RESUME: u64 = 61;
    let path = run(70, |hour, _, _| {
        (hour <= LAST || hour >= RESUME).then(|| sliding(hour.min(LAST) - 1))
    });
    // Reports through hour LAST open epoch LAST - 2: that median is the
    // last good rate.
    let good = at(&path, LAST);
    assert!(good.rate < START_NANO, "the rate followed the market");
    assert!(!good.held);
    let max_age = e::DEFAULT_RATE_MAX_AGE_EPOCHS;
    for h in LAST..RESUME {
        let now = at(&path, h);
        assert_eq!(now.rate, good.rate, "hour {h}: the rate moved");
        assert_eq!(now.wei_per_usd, good.wei_per_usd, "hour {h}: fees moved");
        assert!(now.wei_per_usd > 0);
        let age = h - (LAST - 2);
        assert_eq!(now.held, age > max_age, "hour {h}: age {age}");
    }
    // Once reports resume and one epoch opens, the hold clears.
    assert!(at(&path, RESUME).held);
    assert!(!at(&path, RESUME + 1).held);
}

#[test]
fn a_majority_withholding_never_moves_the_rate() {
    // Eleven of twenty-one stay silent while the market falls 20%: too
    // little stake opens to count, so the rate and fees stay exactly put.
    let path = run(40, |hour, v, _| {
        if hour < 10 {
            Some(START_NANO)
        } else if v < 11 {
            None
        } else {
            Some(START_NANO * 8 / 10)
        }
    });
    let before = at(&path, 10);
    for h in 10..=40 {
        let now = at(&path, h);
        assert_eq!(now.rate, before.rate, "hour {h}");
        assert_eq!(now.wei_per_usd, before.wei_per_usd, "hour {h}");
    }
}

#[test]
fn reports_under_a_third_of_stake_cannot_move_the_rate() {
    // Six of twenty-one report ten times the market every hour.
    let path = run(30, |_, v, _| {
        Some(if v < 6 { START_NANO * 10 } else { START_NANO })
    });
    assert!(path.iter().all(|h| h.rate == START_NANO), "{path:?}");
}

#[test]
fn even_unanimous_manipulation_never_moves_the_rate() {
    // Every validator reports ten times the market, far beyond the governed
    // gap from the governance rate: each epoch holds the rate, and after the
    // governed run of such epochs the governance rate is in force.
    let path = run(30, |_, _, _| Some(START_NANO * 10));
    assert!(path.iter().all(|h| h.rate == START_NANO), "{path:?}");
    assert!(at(&path, 30).governance, "the governance rate is in force");
}
