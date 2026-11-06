//! The TNZO/USD rate in force follows the market when a third of the
//! validators hold one edge of the reporting band or withhold their
//! reports, and when more than a third withhold so that the quorum is
//! missed.
//!
//! Twenty-one validators of equal stake report hourly. The market falls
//! 20% at once. Seven (a third) either report one clamp step below the
//! rate in force every epoch, aiming to hold the upper band edge, or report
//! nothing, leaving exactly two thirds to open; neither may slow the rate.
//! Eight withholding leave the quorum missed; the rate must then come
//! within the governed staleness gap (3%) of the market within the
//! staleness window plus the clamp's own pace.
//!
//! Run with `cargo test -p tenzro-sim --test rate_staleness`.

use std::collections::BTreeMap;

use tenzro_sim::ledger::{self, Envelope, Genesis, Ledger, SimTx};
use tenzro_vm::native as n;

const HOUR_MS: u64 = 3_600_000;
const VALIDATORS: u32 = 21;
const THIRD: u32 = 7;
const START_NANO: u128 = 100_000_000;
const DROP_HOUR: u64 = 10;

#[derive(Clone, Copy, PartialEq)]
enum Coalition {
    Honest,
    Walk(u32),
    Withhold(u32),
}

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

fn market(hour: u64) -> u128 {
    if hour < DROP_HOUR {
        START_NANO
    } else {
        START_NANO * 8 / 10
    }
}

/// Runs hourly reports to `hours` and returns the rate in force each hour.
fn run(coalition: Coalition, hours: u64) -> Vec<(u64, u128)> {
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
            let rate = match coalition {
                Coalition::Walk(c) if v < c => in_force * 9_900 / 10_000,
                Coalition::Withhold(c) if v < c => continue,
                _ => market(closed),
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
        path.push((hour, n::read_fee_rate(chain.state()).rate_nano_usd));
    }
    assert!(chain.conservation_failures.is_empty());
    path
}

fn gap_at(path: &[(u64, u128)], hour: u64) -> f64 {
    let (_, rate) = path.iter().find(|(h, _)| *h == hour).expect("hour");
    (*rate as f64 / market(hour) as f64 - 1.0).abs()
}

/// What honest reports alone achieve: the rate meets the market inside a
/// day of the fall.
#[test]
fn honest_reports_follow_a_fall_within_a_day() {
    let path = run(Coalition::Honest, DROP_HOUR + 36);
    assert!(gap_at(&path, DROP_HOUR + 30) < 0.01, "{path:?}");
}

#[test]
fn a_third_holding_the_band_edge_does_not_slow_the_rate() {
    let honest = run(Coalition::Honest, DROP_HOUR + 36);
    let walk = run(Coalition::Walk(THIRD), DROP_HOUR + 36);
    // The same path hour by hour: a third gains nothing.
    assert_eq!(walk, honest);
}

#[test]
fn a_third_withholding_its_reports_does_not_slow_the_rate() {
    let honest = run(Coalition::Honest, DROP_HOUR + 36);
    let held = run(Coalition::Withhold(THIRD), DROP_HOUR + 36);
    assert_eq!(held, honest);
}

#[test]
fn more_than_a_third_withholding_freezes_the_rate_only_for_the_window() {
    let honest = run(Coalition::Honest, DROP_HOUR + 40);
    let held = run(Coalition::Withhold(THIRD + 1), DROP_HOUR + 40);
    let h = gap_at(&honest, DROP_HOUR + 40);
    let w = gap_at(&held, DROP_HOUR + 40);
    assert!(w <= h + 0.03, "withheld {w:.4} vs honest {h:.4}: {held:?}");
}
