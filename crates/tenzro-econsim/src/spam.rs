//! Spam economics at real block time: what it costs to fill blocks and
//! how far that moves the fee an ordinary transfer pays.

use std::collections::BTreeMap;

use serde::Serialize;
use tenzro_sim::ledger::{self, USER_BASE};

use crate::chain::{Chain, Clock, GenesisPlan, tnzo};

/// One spam level's outcome.
#[derive(Debug, Clone, Serialize)]
pub struct SpamLevel {
    /// Spam gas per block as a multiple of the target.
    pub spam_of_target: f64,
    /// Blocks the spam lasted.
    pub blocks: u32,
    /// Seconds of real time the spam lasted.
    pub seconds: f64,
    /// What the spammer paid, TNZO.
    pub cost_tnzo: f64,
    /// What the spammer paid, USD at the genesis rate.
    pub cost_usd: f64,
    /// Base fee at the start and the end, TNZO per gas.
    pub base_fee_start: f64,
    /// Base fee at the end.
    pub base_fee_end: f64,
    /// Fee an ordinary transfer paid at the end, USD.
    pub transfer_fee_end_usd: f64,
    /// Fee an ordinary transfer paid at the start, USD.
    pub transfer_fee_start_usd: f64,
    /// Ordinary transfers left out of full blocks.
    pub honest_left_out: u64,
}

/// Runs spam at each level for `blocks` blocks beside a steady honest load
/// of `honest_per_block` transfers.
pub fn study(levels: &[f64], blocks: u32, honest_per_block: u32, price_usd: f64) -> Vec<SpamLevel> {
    let mut out = Vec::new();
    for &lvl in levels {
        let mut params = BTreeMap::new();
        params.insert("fees.tnzo_usd_nano".to_string(), (price_usd * 1e9) as u64);
        let plan = GenesisPlan {
            validators: 4,
            standby: 0,
            bond_tnzo: tenzro_vm::governance::genesis_param("stake.validator_tnzo").max(1),
            balance_tnzo: 100_000,
            users: 2_000,
            treasury_tnzo: 0,
            insurance_tnzo: 0,
            reserve_tnzo: 0,
            opening_accounts: Vec::new(),
            network_params: params,
        };
        let mut chain = Chain::new(&plan, Clock::REAL);
        let target = chain.param(tenzro_vm::ledger::COMPUTE_TARGET_PARAM);
        let spam_tx = ((target as f64 * lvl) / 21_000.0) as u64;
        let spammers: Vec<u32> = (USER_BASE..USER_BASE + 1_000).collect();
        let honest = USER_BASE + 1_000;
        let before: u128 = spammers.iter().map(|s| chain.ledger.balance(*s)).sum();
        let fee_start = chain.base_fee();
        let probe = |chain: &Chain| tnzo(chain.base_fee()) * 21_000.0 * price_usd;
        let transfer_start = probe(&chain);
        let mut left_out = 0u64;
        for b in 0..blocks {
            // Honest transfers go in first, then the spam fills the rest.
            for i in 0..honest_per_block {
                let from = honest + (i % 900);
                let to = honest + ((i + 1) % 900);
                if !chain.transfer(from, to, 1, None) {
                    left_out += 1;
                }
            }
            for i in 0..spam_tx {
                let from = spammers[((b as u64 * spam_tx + i) % spammers.len() as u64) as usize];
                let max = Some(chain.base_fee().saturating_mul(4).max(1));
                if !chain.transfer(from, from, 0, max) {
                    break;
                }
            }
            chain.produce();
        }
        let after: u128 = spammers.iter().map(|s| chain.ledger.balance(*s)).sum();
        let cost = tnzo(before.saturating_sub(after));
        out.push(SpamLevel {
            spam_of_target: lvl,
            blocks,
            seconds: blocks as f64 * Clock::REAL.block_ms as f64 / 1000.0,
            cost_tnzo: cost,
            cost_usd: cost * price_usd,
            base_fee_start: tnzo(fee_start),
            base_fee_end: tnzo(chain.base_fee()),
            transfer_fee_end_usd: probe(&chain),
            transfer_fee_start_usd: transfer_start,
            honest_left_out: left_out,
        });
        let _ = ledger::account(0);
    }
    out
}
