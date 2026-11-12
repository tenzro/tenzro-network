//! One summary line for a run of finalized blocks.
//!
//! A validator finalizes a block every second or so; five log lines a block
//! is some 800 MB of journal a day. The per-block lines stay at debug, and at
//! the default level this module writes one line per [`SUMMARY_EVERY_BLOCKS`]
//! blocks (a count of blocks, not a time): the height reached, the blocks and
//! transactions since the last line, the failures and the gas.

use std::sync::Mutex;

use tracing::info;

/// Blocks between two summary lines.
pub const SUMMARY_EVERY_BLOCKS: u64 = 1_000;

/// What has been finalized since the last summary line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Height of the last block counted.
    pub height: u64,
    /// Blocks counted.
    pub blocks: u64,
    /// Transactions in them.
    pub transactions: u64,
    /// Transactions that failed.
    pub failed: u64,
    /// Gas they used.
    pub gas: u64,
}

/// The counter behind [`record`], separate so tests can run their own.
#[derive(Debug, Default)]
pub struct Counter {
    since: Summary,
    reported_first: bool,
}

impl Counter {
    /// Counts a block; returns the summary when the run is complete. The
    /// first block after a start is reported at once, so a restarted node
    /// says where it is.
    pub fn record(&mut self, height: u64, txs: u64, failed: u64, gas: u64) -> Option<Summary> {
        self.since.height = self.since.height.max(height);
        self.since.blocks += 1;
        self.since.transactions += txs;
        self.since.failed += failed;
        self.since.gas = self.since.gas.saturating_add(gas);
        if !self.reported_first || self.since.blocks >= SUMMARY_EVERY_BLOCKS {
            self.reported_first = true;
            return Some(std::mem::take(&mut self.since));
        }
        None
    }
}

static COUNTER: Mutex<Option<Counter>> = Mutex::new(None);

/// Counts a finalized block and writes the summary line when a run is done.
pub fn record(height: u64, txs: u64, failed: u64, gas: u64) {
    let summary = {
        let mut guard = COUNTER.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .get_or_insert_with(Counter::default)
            .record(height, txs, failed, gas)
    };
    if let Some(s) = summary {
        info!(
            height = s.height,
            blocks = s.blocks,
            transactions = s.transactions,
            failed = s.failed,
            gas = s.gas,
            "blocks finalized"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_thousand_blocks_make_one_line_and_the_first_block_is_reported() {
        let mut c = Counter::default();
        let first = c.record(10, 2, 1, 50).expect("the first block is reported");
        assert_eq!((first.blocks, first.transactions, first.failed), (1, 2, 1));
        let mut lines = 0;
        for h in 11..=2_010u64 {
            if c.record(h, 1, 0, 21_000).is_some() {
                lines += 1;
            }
        }
        assert_eq!(lines, 2, "2000 blocks write two summary lines");
        let mut c = Counter::default();
        c.record(1, 0, 0, 0);
        for h in 2..=1_000u64 {
            assert!(c.record(h, 0, 0, 0).is_none());
        }
        let s = c.record(1_001, 3, 0, 9).unwrap();
        assert_eq!((s.blocks, s.height, s.transactions), (1_000, 1_001, 3));
    }
}
