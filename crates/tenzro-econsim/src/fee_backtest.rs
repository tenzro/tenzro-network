//! The base-fee rule backtested on real block usage.
//!
//! A trace is one row per block: its number, the share of its gas limit it
//! used, and the base fee it charged (`block,gas_used_ratio,base_fee_wei`,
//! the fields `eth_feeHistory` returns). `data/eth-fee-history.csv` holds
//! 1,024 consecutive Ethereum mainnet blocks from 26,434,669, read with
//! `eth_feeHistory`.
//!
//! Two replays run on the trace's usage. Ethereum's own rule, from the first
//! recorded fee, must reproduce the recorded fees: that shows the trace is
//! read correctly. The ledger's rule ([`tenzro_vm::eip1559::next_base_fee`]
//! with the governed genesis target, step denominator, floor and ceiling)
//! then runs on the same usage, each block's share of its limit applied to
//! the ledger's block limit, from the governed floor. The report gives how
//! often the ledger's fee sits on its floor or ceiling, its largest one-block
//! steps, its largest swing over a window, and how many blocks of full use
//! take it from floor to ceiling.

use serde::Serialize;
use tenzro_vm::eip1559::{Eip1559Config, next_base_fee};
use tenzro_vm::governance::genesis_param;
use tenzro_vm::ledger as vl;

/// The Ethereum trace shipped with the crate.
pub const ETH_FEE_HISTORY: &str = include_str!("../data/eth-fee-history.csv");

/// Blocks in the swing window.
pub const SWING_BLOCKS: usize = 300;

/// One block of a trace.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Block {
    /// Block number.
    pub number: u64,
    /// Gas used over the gas limit.
    pub gas_used_ratio: f64,
    /// Base fee the block charged, wei.
    pub base_fee_wei: u128,
}

/// Reads a trace; the first line is the header.
pub fn parse(text: &str) -> Result<Vec<Block>, String> {
    text.lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .map(|(i, l)| {
            let f: Vec<&str> = l.split(',').map(str::trim).collect();
            let bad = |what: &str| format!("line {}: {what}: {l}", i + 2);
            if f.len() != 3 {
                return Err(bad("three fields expected"));
            }
            let gas_used_ratio: f64 = f[1].parse().map_err(|_| bad("gas_used_ratio"))?;
            if !(0.0..=1.0).contains(&gas_used_ratio) {
                return Err(bad("gas_used_ratio outside 0..=1"));
            }
            Ok(Block {
                number: f[0].parse().map_err(|_| bad("block"))?,
                gas_used_ratio,
                base_fee_wei: f[2].parse().map_err(|_| bad("base_fee_wei"))?,
            })
        })
        .collect()
}

/// The ledger's fee market at its governed genesis values.
pub fn genesis_config() -> Eip1559Config {
    let min_base_fee = u128::from(genesis_param(vl::MIN_BASE_FEE_PARAM));
    let target = genesis_param(vl::COMPUTE_TARGET_PARAM);
    let d = Eip1559Config::default();
    Eip1559Config {
        target_gas_per_block: target,
        max_gas_per_block: target.saturating_mul(d.elasticity_multiplier),
        base_fee_change_denominator: genesis_param(vl::BASE_FEE_CHANGE_DENOMINATOR_PARAM),
        min_base_fee,
        max_base_fee: u128::from(genesis_param(vl::MAX_BASE_FEE_PARAM)).max(min_base_fee),
        ..d
    }
}

/// Ethereum's rule (target half the limit, step 1/8, at least 1 wei up
/// above target) from the first recorded fee: the fee of each block after
/// the first.
pub fn ethereum_replay(blocks: &[Block]) -> Vec<f64> {
    let mut fee = blocks.first().map_or(0.0, |b| b.base_fee_wei as f64);
    blocks
        .iter()
        .take(blocks.len().saturating_sub(1))
        .map(|b| {
            let delta = fee * (2.0 * b.gas_used_ratio - 1.0) / 8.0;
            fee += if b.gas_used_ratio > 0.5 {
                delta.max(1.0)
            } else {
                delta
            };
            fee
        })
        .collect()
}

/// The ledger's rule on the trace's usage from the floor: the fee of every
/// block, the first at the floor.
pub fn ledger_replay(config: &Eip1559Config, blocks: &[Block]) -> Vec<u128> {
    let mut fee = config.min_base_fee;
    let mut out = Vec::with_capacity(blocks.len());
    for b in blocks {
        out.push(fee);
        let used = (b.gas_used_ratio * config.max_gas_per_block as f64) as u64;
        fee = next_base_fee(config, fee, used);
    }
    out
}

/// Blocks of full use that take the ledger's fee from its floor to its
/// ceiling, `None` beyond a million.
pub fn floor_to_ceiling_blocks(config: &Eip1559Config) -> Option<u64> {
    let mut fee = config.min_base_fee;
    for n in 1..=1_000_000u64 {
        fee = next_base_fee(config, fee, config.max_gas_per_block);
        if fee >= config.max_base_fee {
            return Some(n);
        }
    }
    None
}

/// What one backtest measured.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Blocks in the trace.
    pub blocks: usize,
    /// First and last block number.
    pub span: (u64, u64),
    /// Mean share of the gas limit used.
    pub mean_usage: f64,
    /// Largest relative error of Ethereum's rule against the recorded fees.
    pub ethereum_max_rel_error: f64,
    /// The ledger's fee market run.
    pub config: Eip1559Config,
    /// Share of blocks the ledger's fee sat on its floor.
    pub floor_share: f64,
    /// Share of blocks it sat on its ceiling.
    pub ceiling_share: f64,
    /// Largest one-block rise, relative.
    pub max_step_up: f64,
    /// Largest one-block fall, relative.
    pub max_step_down: f64,
    /// Largest high over low within any [`SWING_BLOCKS`] window.
    pub max_swing: f64,
    /// Ledger fee at the end over its floor.
    pub end_over_floor: f64,
    /// Blocks of full use from floor to ceiling.
    pub floor_to_ceiling_blocks: Option<u64>,
}

/// Backtests `config` on `blocks`.
pub fn backtest(config: &Eip1559Config, blocks: &[Block]) -> Report {
    let eth = ethereum_replay(blocks);
    let ethereum_max_rel_error = eth
        .iter()
        .zip(blocks.iter().skip(1))
        .map(|(p, b)| (p - b.base_fee_wei as f64).abs() / (b.base_fee_wei as f64).max(1.0))
        .fold(0.0, f64::max);
    let fees = ledger_replay(config, blocks);
    let n = fees.len().max(1) as f64;
    let steps: Vec<f64> = fees
        .windows(2)
        .map(|w| w[1] as f64 / w[0].max(1) as f64 - 1.0)
        .collect();
    let max_swing = fees
        .windows(SWING_BLOCKS.min(fees.len()).max(1))
        .map(|w| {
            let hi = *w.iter().max().unwrap_or(&1) as f64;
            let lo = *w.iter().min().unwrap_or(&1) as f64;
            hi / lo.max(1.0)
        })
        .fold(1.0, f64::max);
    Report {
        blocks: blocks.len(),
        span: (
            blocks.first().map_or(0, |b| b.number),
            blocks.last().map_or(0, |b| b.number),
        ),
        mean_usage: blocks.iter().map(|b| b.gas_used_ratio).sum::<f64>() / n,
        ethereum_max_rel_error,
        config: config.clone(),
        floor_share: fees.iter().filter(|&&f| f <= config.min_base_fee).count() as f64 / n,
        ceiling_share: fees.iter().filter(|&&f| f >= config.max_base_fee).count() as f64 / n,
        max_step_up: steps.iter().copied().fold(0.0, f64::max),
        max_step_down: -steps.iter().copied().fold(0.0, f64::min),
        max_swing,
        end_over_floor: fees
            .last()
            .map_or(1.0, |&f| f as f64 / config.min_base_fee.max(1) as f64),
        floor_to_ceiling_blocks: floor_to_ceiling_blocks(config),
    }
}

/// The report as a markdown table.
pub fn table(r: &Report) -> String {
    format!(
        "| measure | value |\n|---|---|\n\
         | blocks | {} ({}..={}) |\n\
         | mean share of the gas limit used | {:.3} |\n\
         | Ethereum's rule against the recorded fees, largest relative error | {:.2e} |\n\
         | ledger target gas, step denominator | {}, {} |\n\
         | ledger floor, ceiling (atto-USD per unit) | {}, {} |\n\
         | blocks on the floor | {:.1}% |\n\
         | blocks on the ceiling | {:.1}% |\n\
         | largest one-block rise, fall | {:.2}%, {:.2}% |\n\
         | largest high over low in {} blocks | {:.2} |\n\
         | fee at the end over the floor | {:.2} |\n\
         | blocks of full use from floor to ceiling | {} |\n",
        r.blocks,
        r.span.0,
        r.span.1,
        r.mean_usage,
        r.ethereum_max_rel_error,
        r.config.target_gas_per_block,
        r.config.base_fee_change_denominator,
        r.config.min_base_fee,
        r.config.max_base_fee,
        r.floor_share * 100.0,
        r.ceiling_share * 100.0,
        r.max_step_up * 100.0,
        r.max_step_down * 100.0,
        SWING_BLOCKS,
        r.max_swing,
        r.end_over_floor,
        r.floor_to_ceiling_blocks
            .map_or("over a million".into(), |b| b.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace() -> Vec<Block> {
        parse(ETH_FEE_HISTORY).expect("shipped trace parses")
    }

    #[test]
    fn the_shipped_trace_is_consecutive_blocks() {
        let t = trace();
        assert_eq!(t.len(), 1_024);
        assert!(t.windows(2).all(|w| w[1].number == w[0].number + 1));
    }

    #[test]
    fn ethereums_rule_reproduces_the_recorded_fees() {
        let r = backtest(&genesis_config(), &trace());
        assert!(
            r.ethereum_max_rel_error < 1e-4,
            "largest relative error {}",
            r.ethereum_max_rel_error
        );
    }

    #[test]
    fn the_ledger_rule_moves_at_most_one_step_a_block_within_its_bounds() {
        let c = genesis_config();
        let r = backtest(&c, &trace());
        let step = 1.0 / c.base_fee_change_denominator as f64;
        assert!(r.max_step_up <= step + 1e-9, "{}", r.max_step_up);
        assert!(r.max_step_down <= step + 1e-9, "{}", r.max_step_down);
        let fees = ledger_replay(&c, &trace());
        assert!(
            fees.iter()
                .all(|&f| (c.min_base_fee..=c.max_base_fee).contains(&f))
        );
        assert!(table(&r).contains("| blocks | 1024 "));
    }

    #[test]
    fn full_use_reaches_the_ceiling_and_an_idle_chain_stays_on_the_floor() {
        let c = genesis_config();
        assert!(floor_to_ceiling_blocks(&c).is_some());
        let idle: Vec<Block> = (0..100)
            .map(|i| Block {
                number: i,
                gas_used_ratio: 0.0,
                base_fee_wei: 1,
            })
            .collect();
        let r = backtest(&c, &idle);
        assert_eq!(r.floor_share, 1.0);
    }

    #[test]
    fn a_bad_row_is_refused_with_its_line() {
        let e = parse("block,gas_used_ratio,base_fee_wei\n1,1.5,7\n").unwrap_err();
        assert!(e.starts_with("line 2:"), "{e}");
    }
}
