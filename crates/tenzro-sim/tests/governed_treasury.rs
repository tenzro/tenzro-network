//! The treasury's funding values change only by an enacted proposal, and
//! every node switches at the same epoch boundary.
//!
//! Three nodes each run their own state machine from the same genesis and
//! execute the same ordered blocks. A `parameter_change` on a treasury value
//! is proposed, voted, closed and enacted through the governance path; each
//! node must keep the old value through the last block of the epoch before
//! the change's activation epoch and read the new one from the first block
//! of that epoch, at the same height.
//!
//! Run with `cargo test --release -p tenzro-sim --test governed_treasury`.

use std::collections::BTreeMap;

use tenzro_sim::ledger::{self, Envelope, Genesis, Ledger, SimTx};
use tenzro_vm::governance::GovernanceRules;
use tenzro_vm::native::treasury_reserve as reserve;
use tenzro_vm::traits::VmState;

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 24 * HOUR_MS;
const VALIDATORS: u32 = 4;

fn genesis() -> Genesis {
    Genesis {
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
    }
}

struct Net {
    nodes: Vec<Ledger>,
    height: u64,
    nonces: Vec<u64>,
}

impl Net {
    fn new(n: usize) -> Self {
        let g = genesis();
        Self {
            nodes: (0..n).map(|_| Ledger::genesis(&g)).collect(),
            height: 0,
            nonces: vec![0; VALIDATORS as usize],
        }
    }

    fn nonce(&mut self, v: u32) -> u64 {
        let n = self.nonces[v as usize];
        self.nonces[v as usize] += 1;
        n
    }

    /// One block at `at_ms` on every node; returns node 0's results after
    /// checking every node reached the same outcome.
    fn block(&mut self, at_ms: u64, txs: Vec<SimTx>) -> Vec<ledger::TxResult> {
        self.height += 1;
        let h = self.height;
        let mut content = [0u8; 32];
        content[..8].copy_from_slice(&h.to_be_bytes());
        let mut outcomes = Vec::new();
        for node in &mut self.nodes {
            let env = txs
                .iter()
                .cloned()
                .map(|tx| Envelope {
                    submitted_ms: at_ms,
                    tx,
                })
                .collect();
            let e = node.execute(h, content, content, 1, 0, at_ms / HOUR_MS, at_ms, 0, env);
            let results = std::mem::take(&mut node.results);
            outcomes.push((e.root, results));
        }
        let (root, first) = outcomes.remove(0);
        for (r, res) in &outcomes {
            assert_eq!(*r, root, "nodes diverged at height {h}");
            let a: Vec<bool> = res.iter().map(|x| x.applied).collect();
            let b: Vec<bool> = first.iter().map(|x| x.applied).collect();
            assert_eq!(a, b, "nodes applied different transactions at height {h}");
        }
        first
    }

    fn param(&self, key: &str) -> Vec<u64> {
        self.nodes.iter().map(|n| n.param(key)).collect()
    }
}

#[test]
fn a_passed_proposal_changes_a_treasury_value_on_every_node_at_the_same_epoch() {
    let key = reserve::SALE_VOLUME_SHARE_PARAM;
    let old = tenzro_vm::governance::genesis_param(key);
    let new = old + 1_234;
    let mut net = Net::new(3);
    let rules = GovernanceRules::GENESIS;

    // Bonds must be older than the governed bond age when the vote opens.
    let mut t = rules.min_bond_age_ms as u64 + DAY_MS;
    net.block(HOUR_MS, Vec::new());
    let n = net.nonce(0);
    let out = net.block(
        t,
        vec![SimTx::Propose {
            from: 0,
            action: ledger::parameter_change(key, new),
            nonce: n,
        }],
    );
    assert!(out[0].applied, "proposal refused: {}", out[0].error);
    let id = out[0].output.clone();

    t += HOUR_MS;
    let votes = (0..VALIDATORS)
        .map(|v| SimTx::Vote {
            from: v,
            proposal: id.clone(),
            nonce: net.nonce(v),
        })
        .collect();
    let out = net.block(t, votes);
    assert!(out.iter().all(|r| r.applied), "a vote was refused: {out:?}");

    // Close the vote, then enact after the timelock.
    t += rules.voting_period_ms as u64 + rules.voting_period_ms as u64 / 10;
    let n = net.nonce(0);
    let out = net.block(
        t,
        vec![SimTx::Execute {
            from: 0,
            proposal: id.clone(),
            nonce: n,
        }],
    );
    assert!(out[0].applied, "close refused: {}", out[0].error);
    t += rules.timelock_ms as u64 + HOUR_MS;
    let n = net.nonce(0);
    let out = net.block(
        t,
        vec![SimTx::Execute {
            from: 0,
            proposal: id.clone(),
            nonce: n,
        }],
    );
    assert!(out[0].applied, "enactment refused: {}", out[0].error);

    // Enacted, not yet in force: every node still reads the old value and
    // holds the same waiting change.
    assert_eq!(net.param(key), vec![old; 3]);
    let pending: Vec<u64> = net
        .nodes
        .iter()
        .map(|n| {
            tenzro_vm::native::pending_param(n.state(), key)
                .expect("change waiting")
                .activates_epoch
        })
        .collect();
    assert!(pending.iter().all(|e| *e == pending[0]));
    let activates = pending[0];

    // Blocks through the rest of this epoch keep the old value; the first
    // block of the activation epoch carries the new one on every node.
    let enacted_epoch = t / HOUR_MS;
    assert!(activates > enacted_epoch);
    let mut at = t;
    while (at + HOUR_MS / 4) / HOUR_MS < activates {
        at += HOUR_MS / 4;
        net.block(at, Vec::new());
        assert_eq!(net.param(key), vec![old; 3], "applied early at {at}");
    }
    net.block(activates * HOUR_MS, Vec::new());
    assert_eq!(net.param(key), vec![new; 3]);
    for n in &net.nodes {
        assert_eq!(tenzro_vm::native::params_epoch(n.state()), activates);
        assert!(tenzro_vm::native::pending_param(n.state(), key).is_none());
        assert!(
            n.conservation_failures.is_empty(),
            "{:?}",
            n.conservation_failures
        );
    }
}

#[test]
fn a_zero_seed_network_runs_its_reserve_boundaries_on_every_node() {
    let mut net = Net::new(2);
    for hour in 1..=72u64 {
        net.block(hour * HOUR_MS, Vec::new());
    }
    for n in &net.nodes {
        let book = reserve::read_book(n.state());
        assert_eq!(book.epoch, Some(72));
        assert_eq!(book.total_paid, 0);
        assert_eq!(
            n.state().get_balance(reserve::reserve_address().as_bytes()),
            0
        );
        assert!(
            n.conservation_failures.is_empty(),
            "{:?}",
            n.conservation_failures
        );
        assert_eq!(n.stats.failed_duties, 0);
    }
}
