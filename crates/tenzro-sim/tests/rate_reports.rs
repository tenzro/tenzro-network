//! A validator whose sealed rate report did not land keeps reporting.
//!
//! Each hour a validator seals the closed epoch's rates and opens the rates
//! it sealed the hour before. When one hour's report is lost (it could not
//! pay, or it executed too late), the next report opens an epoch the
//! validator never sealed. That opening must not refuse the new seal, or
//! the validator never reports again and the network loses its quorum.
//!
//! Run with `cargo test -p tenzro-sim --test rate_reports`.

use std::collections::BTreeMap;

use tenzro_sim::ledger::{self, Envelope, Genesis, Ledger, SimTx};
use tenzro_vm::native as n;

const HOUR_MS: u64 = 3_600_000;
const VALIDATORS: u32 = 4;

struct Reporter {
    sealed: Option<(u64, Vec<(String, String, u128)>, [u8; 32])>,
}

fn report(v: u32, nonce: u64, r: &mut Reporter, closed: u64, volume: u128) -> SimTx {
    let sym = n::economy::VOLUME_SYMBOL.to_string();
    let quotes = vec![
        (sym.clone(), "venue-a".to_string(), volume),
        (sym, "venue-b".to_string(), volume),
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
    let reveal = r
        .sealed
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
    // The client keeps what it sealed whether or not the report lands, as
    // a node's reporter does.
    r.sealed = Some((closed, quotes, salt));
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

#[test]
fn a_lost_report_costs_one_hour_not_every_hour_after_it() {
    let mut chain = Ledger::genesis(&Genesis {
        active: VALIDATORS,
        standby: 0,
        users: 0,
        bond_tnzo: 100_000,
        balance_tnzo: 1_000,
        calendar_scale: 1,
        epoch_ms: HOUR_MS,
        network_params: BTreeMap::new(),
        accounts: Vec::new(),
        strict_supply: false,
    });
    let mut reporters: Vec<Reporter> = (0..VALIDATORS).map(|_| Reporter { sealed: None }).collect();
    // Three of four validators lose their report in hour 6: without them
    // the rest are under the quorum.
    let lost_hour = 6u64;
    let mut stuck = 0u32;
    for hour in 2..=30u64 {
        let at = hour * HOUR_MS + HOUR_MS / 2;
        let closed = hour - 1;
        let mut txs = Vec::new();
        for v in 0..VALIDATORS {
            let nonce = chain.nonce(v);
            let tx = report(
                v,
                nonce,
                &mut reporters[v as usize],
                closed,
                24_000_000_000_000,
            );
            if hour == lost_hour && v < 3 {
                continue;
            }
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
            if r.applied {
                continue;
            }
            if r.error.contains("sealed no rates") {
                stuck += 1;
            } else {
                panic!("hour {hour}: report refused: {}", r.error);
            }
        }
    }
    assert_eq!(stuck, 0, "reports refused for opening an unsealed epoch");
    // Every epoch from two hours after the lost one has a frozen volume.
    for e in lost_hour + 1..=26 {
        assert!(
            n::economy::read_committed_rate(chain.state(), n::economy::VOLUME_SYMBOL, e).is_some(),
            "no frozen volume for epoch {e}"
        );
    }
    assert!(chain.conservation_failures.is_empty());
}
