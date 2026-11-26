//! Keeps this node from carrying EVM transactions that end in an engine
//! error.
//!
//! A transaction that makes the EVM engine itself fail after it has run is
//! charged as a transaction that never ran, so its sender gets the work it
//! did before the failure for the base transaction gas. Until the rule that
//! prices it correctly is live on the chain, this guard is what an honest
//! node does about it with what it sees locally. It decides nothing about
//! block validity: every node still executes whatever a block carries.
//!
//! The guard acts only on what a block has already shown, so it gives no
//! work away at admission. It is the pool's own admission rule
//! ([`tenzro_consensus::PoolGuard`]), so a transaction meets it whichever
//! way it reaches the pool: from a peer or from this node's RPC. Its values
//! are the node's own ([`EvmPoolGuardConfig`], the `[evm_pool_guard]`
//! table):
//!
//! - A sender whose transaction ended in an engine error is held: this node
//!   admits nothing more from it for `hold_secs`, and the event loop takes
//!   what it still has pooled out of the pool.
//! - After `watch_faults` such transactions within `watch_secs`, from any
//!   senders, this node admits no EVM transaction with a gas limit above
//!   `watch_gas_limit` until the window has passed. That bounds what one
//!   more such transaction can take from this node's blocks while senders
//!   are being rotated.
//!
//! Holds and the window run from the time of the block that showed the
//! error, and never from later than this node's own clock: blocks replayed
//! or imported from the past set nothing that is still in force, and a block
//! dated in the future holds nobody longer than one dated now. Nothing is kept across a restart, and at most
//! `held_senders_max` senders are held at once, the oldest hold giving way.
//! The guard does not stop the first such transaction of a sender, the ones
//! a sender already has in flight, or a proposer that carries them on
//! purpose.
//!
//! Both rules can be turned against honest users, and an operator should
//! know how before tightening them:
//!
//! - `watch_faults` cheap engine-error transactions every `watch_secs` keep
//!   every EVM transaction above `watch_gas_limit`, large deployments among
//!   them, out of honest nodes for as long as someone pays for them.
//! - A contract that calls the failing address gets each of its callers
//!   held for `hold_secs`: the sender of the transaction is held, whoever
//!   wrote the contract.

use std::collections::{HashMap, VecDeque};

use parking_lot::Mutex;
use tenzro_types::{SignedTransaction, TransactionType};
use tenzro_vm::VmType;

use crate::config::EvmPoolGuardConfig;

/// What this node has seen of engine errors in executed blocks.
#[derive(Debug, Default)]
pub struct EvmPoolGuard {
    config: EvmPoolGuardConfig,
    seen: Mutex<Seen>,
}

#[derive(Debug, Default)]
struct Seen {
    /// Held senders and the time, Unix ms, each hold ends.
    held: HashMap<Vec<u8>, u64>,
    /// Block time, Unix ms, of each recent engine error, oldest first.
    faults: VecDeque<u64>,
}

/// What an engine error in an executed block set off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Noted {
    /// The sender's hold is still running now. It is not when the block is
    /// an old one, replayed or imported.
    pub in_force: bool,
    /// The gas limit ceiling started with this error and its window is
    /// still running now.
    pub watch_started: bool,
}

/// One account under one key: a 20-byte address and the 32-byte account
/// that is the same address followed by zeros are the same sender.
fn account_key(account: &[u8]) -> Vec<u8> {
    if account.len() == 32 && account[20..].iter().all(|b| *b == 0) {
        account[..20].to_vec()
    } else {
        account.to_vec()
    }
}

/// This node's clock, Unix ms.
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl EvmPoolGuard {
    /// A guard with the node's values.
    pub fn new(config: EvmPoolGuardConfig) -> Self {
        Self {
            config,
            seen: Mutex::default(),
        }
    }

    fn hold_ms(&self) -> u64 {
        self.config.hold_secs.saturating_mul(1000)
    }

    fn watch_ms(&self) -> u64 {
        self.config.watch_secs.saturating_mul(1000)
    }

    /// The gas limit ceiling while the window runs.
    pub fn watch_gas_limit(&self) -> u64 {
        self.config.watch_gas_limit
    }

    /// Whether the guard judges `tx`: the transactions the EVM runs, an
    /// external wallet transaction and a native one addressed to the EVM.
    pub fn judges(tx: &SignedTransaction) -> bool {
        match &tx.transaction.tx_type {
            TransactionType::ExternalEvm { .. } => true,
            TransactionType::ExternalSvm { .. } => false,
            _ => crate::event_loop::vm_transaction(tx).vm_type == VmType::Evm,
        }
    }

    /// Whether `a` and `b` name one account, in either of its forms.
    pub fn same_account(a: &[u8], b: &[u8]) -> bool {
        account_key(a) == account_key(b)
    }

    /// Records the failure `reason` of a transaction of `sender` executed in
    /// a block dated `block_ms`, at `now_ms` on this node's clock. `Some`
    /// when it was an engine error and the guard is on: the sender is held
    /// from the block's time, or from now when the block is dated later.
    pub fn note_executed(
        &self,
        sender: &[u8],
        reason: Option<&str>,
        block_ms: u64,
        now_ms: u64,
    ) -> Option<Noted> {
        if !self.config.enabled || !reason.is_some_and(tenzro_vm::evm::is_engine_fault) {
            return None;
        }
        let block_ms = block_ms.min(now_ms);
        let until = block_ms.saturating_add(self.hold_ms());
        // A block whose hold has already ended, replayed or imported from the
        // past, changes nothing: it neither holds its sender nor counts
        // toward the window, and evicts nobody.
        if until <= now_ms {
            return Some(Noted {
                in_force: false,
                watch_started: false,
            });
        }
        let mut seen = self.seen.lock();
        // Holds that have ended go first; past the cap, the hold that ends
        // soonest gives way.
        seen.held.retain(|_, held_until| *held_until > now_ms);
        if seen.held.len() >= self.config.held_senders_max
            && let Some(oldest) = seen
                .held
                .iter()
                .min_by_key(|(_, held_until)| **held_until)
                .map(|(sender, _)| sender.clone())
        {
            seen.held.remove(&oldest);
        }
        seen.held.insert(account_key(sender), until);
        // The window runs back from now; a fault older than it counts for
        // nothing, and the faults stay in time order, so the oldest is the
        // one that leaves when there are more than the threshold needs.
        let window = self.watch_ms();
        seen.faults
            .retain(|at| now_ms.saturating_sub(*at) <= window);
        let before = seen.faults.len();
        if now_ms.saturating_sub(block_ms) <= window {
            let at = seen.faults.partition_point(|t| *t <= block_ms);
            seen.faults.insert(at, block_ms);
        }
        while seen.faults.len() > self.config.watch_faults {
            seen.faults.pop_front();
        }
        Some(Noted {
            in_force: true,
            watch_started: before < self.config.watch_faults
                && seen.faults.len() == self.config.watch_faults,
        })
    }

    /// Why this node does not admit an EVM transaction of `sender` with
    /// `gas_limit` at `now_ms`, if it does not.
    pub fn refusal_at(&self, sender: &[u8], gas_limit: u64, now_ms: u64) -> Option<String> {
        if !self.config.enabled {
            return None;
        }
        let seen = self.seen.lock();
        if seen
            .held
            .get(&account_key(sender))
            .is_some_and(|until| now_ms < *until)
        {
            return Some(
                "a transaction of this sender ended in an EVM engine error; this node takes \
                 no more from it for now"
                    .to_string(),
            );
        }
        let window = self.watch_ms();
        let recent = seen
            .faults
            .iter()
            .filter(|at| now_ms.saturating_sub(**at) <= window)
            .count();
        (recent >= self.config.watch_faults && gas_limit > self.config.watch_gas_limit).then(|| {
            format!(
                "EVM engine errors are being used against the network; this node admits no \
                 EVM transaction above a gas limit of {} for now",
                self.config.watch_gas_limit
            )
        })
    }
}

impl tenzro_consensus::PoolGuard for EvmPoolGuard {
    /// Judges the transactions the EVM runs: an external wallet transaction
    /// and a native one addressed to the EVM. The sender and gas limit are
    /// the envelope's, which both ways into the pool have already checked
    /// against the signed wallet transaction inside it, so they are the
    /// ones the engine runs it with.
    fn refusal(&self, tx: &SignedTransaction) -> Option<String> {
        if !Self::judges(tx) {
            return None;
        }
        self.refusal_at(
            tx.transaction.from.as_bytes(),
            tx.transaction.gas_limit,
            unix_ms(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOLD_MS: u64 = 60 * 60 * 1000;
    const WATCH_MS: u64 = 10 * 60 * 1000;
    const WATCH_FAULTS: usize = 3;
    const WATCH_GAS_LIMIT: u64 = 1_000_000;
    const T0: u64 = 1_800_000_000_000;

    const FAULT: &str =
        "Execution failed: revm execution failed: Precompile(\"c-kzg feature is not enabled\")";

    #[test]
    fn a_sender_is_held_after_an_engine_error_and_released_when_the_hold_ends() {
        let guard = EvmPoolGuard::default();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(guard.refusal_at(&a, 30_000_000, T0).is_none());

        // An ordinary failure holds nobody.
        assert!(
            guard
                .note_executed(&a, Some("Execution reverted"), T0, T0)
                .is_none()
        );
        assert!(guard.note_executed(&a, None, T0, T0).is_none());
        assert!(guard.refusal_at(&a, 30_000_000, T0).is_none());

        assert_eq!(
            guard.note_executed(&a, Some(FAULT), T0, T0),
            Some(Noted {
                in_force: true,
                watch_started: false
            })
        );
        assert!(
            guard.refusal_at(&a, 21_000, T0).is_some(),
            "held at any gas limit"
        );
        assert!(
            guard.refusal_at(&b, 30_000_000, T0).is_none(),
            "others are not"
        );
        assert!(guard.refusal_at(&a, 21_000, T0 + HOLD_MS - 1).is_some());
        assert!(guard.refusal_at(&a, 21_000, T0 + HOLD_MS).is_none());
    }

    #[test]
    fn an_account_is_one_sender_in_its_short_and_its_padded_form() {
        let guard = EvmPoolGuard::default();
        let short = [7u8; 20];
        let mut padded = [0u8; 32];
        padded[..20].copy_from_slice(&short);
        guard.note_executed(&padded, Some(FAULT), T0, T0);
        assert!(guard.refusal_at(&short, 21_000, T0).is_some());
        assert!(guard.refusal_at(&padded, 21_000, T0).is_some());
    }

    #[test]
    fn an_engine_error_in_an_old_block_holds_nobody_now() {
        let guard = EvmPoolGuard::default();
        let sender = [3u8; 32];
        for i in 0..WATCH_FAULTS as u64 {
            guard.note_executed(&sender, Some(FAULT), T0 + i, T0 + i);
        }
        let now = T0 + HOLD_MS + WATCH_MS;
        assert!(guard.refusal_at(&sender, 30_000_000, now).is_none());
    }

    /// A block dated far in the future holds its sender no longer than a
    /// block dated now, and its fault leaves the window when one of now
    /// would; a block dated in the past sets a hold that is not in force.
    #[test]
    fn a_block_dated_in_the_future_counts_as_a_block_of_now() {
        let guard = EvmPoolGuard::default();
        let sender = [5u8; 32];
        let future = T0 + 10 * 24 * 60 * 60 * 1000;
        for _ in 0..WATCH_FAULTS {
            let noted = guard
                .note_executed(&sender, Some(FAULT), future, T0)
                .unwrap();
            assert!(noted.in_force);
        }
        assert!(
            guard.refusal_at(&[6u8; 32], 30_000_000, T0).is_some(),
            "the ceiling is on at T0"
        );
        assert!(
            guard
                .refusal_at(&sender, 21_000, T0 + HOLD_MS - 1)
                .is_some()
        );
        assert!(guard.refusal_at(&sender, 21_000, T0 + HOLD_MS).is_none());
        assert!(
            guard
                .refusal_at(&[6u8; 32], 30_000_000, T0 + WATCH_MS + 1)
                .is_none(),
            "the ceiling ends with the window from now"
        );

        let old = EvmPoolGuard::default();
        let noted = old
            .note_executed(&sender, Some(FAULT), T0, T0 + HOLD_MS)
            .unwrap();
        assert!(!noted.in_force, "an old block's hold has already ended");
    }

    /// Replaying an old block that carries an engine error, as sync does,
    /// changes nothing: the ceiling the recent faults started stays on, and
    /// a full set of holds keeps every hold that is still running.
    #[test]
    fn an_old_block_changes_nothing_in_the_guard() {
        let guard = EvmPoolGuard::new(EvmPoolGuardConfig {
            held_senders_max: WATCH_FAULTS,
            ..EvmPoolGuardConfig::default()
        });
        let now = T0 + 2 * HOLD_MS;
        for i in 0..WATCH_FAULTS as u8 {
            guard.note_executed(&[i; 32], Some(FAULT), now, now);
        }
        assert!(guard.refusal_at(&[9u8; 32], 30_000_000, now).is_some());

        let noted = guard
            .note_executed(&[42u8; 32], Some(FAULT), T0, now)
            .unwrap();
        assert!(!noted.in_force && !noted.watch_started);
        assert!(
            guard.refusal_at(&[9u8; 32], 30_000_000, now).is_some(),
            "the ceiling is still on"
        );
        for i in 0..WATCH_FAULTS as u8 {
            assert!(
                guard.refusal_at(&[i; 32], 21_000, now).is_some(),
                "hold {i} is still running"
            );
        }
        assert!(guard.refusal_at(&[42u8; 32], 21_000, now).is_none());
    }

    #[test]
    fn repeated_engine_errors_cap_the_gas_limit_for_the_window() {
        let guard = EvmPoolGuard::default();
        let bystander = [9u8; 32];
        for i in 0..WATCH_FAULTS {
            assert!(
                guard.refusal_at(&bystander, 30_000_000, T0).is_none(),
                "{i} engine errors do not start the watch"
            );
            let noted = guard
                .note_executed(&[i as u8; 32], Some(FAULT), T0, T0)
                .unwrap();
            assert_eq!(noted.watch_started, i + 1 == WATCH_FAULTS);
        }
        assert!(
            guard
                .refusal_at(&bystander, WATCH_GAS_LIMIT + 1, T0)
                .is_some()
        );
        assert!(
            guard.refusal_at(&bystander, WATCH_GAS_LIMIT, T0).is_none(),
            "a transaction within the ceiling is admitted"
        );
        // A tighter node: one engine error starts a lower ceiling.
        let tight = EvmPoolGuard::new(EvmPoolGuardConfig {
            watch_faults: 1,
            watch_gas_limit: 100_000,
            ..EvmPoolGuardConfig::default()
        });
        assert!(
            tight
                .note_executed(&[7u8; 32], Some(FAULT), T0, T0)
                .unwrap()
                .watch_started
        );
        assert!(tight.refusal_at(&bystander, 100_001, T0).is_some());
        assert!(tight.refusal_at(&bystander, 100_000, T0).is_none());

        assert!(
            guard
                .refusal_at(&bystander, 30_000_000, T0 + WATCH_MS + 1)
                .is_none(),
            "the watch ends with its window"
        );
    }

    #[test]
    fn the_held_senders_stay_under_their_cap_and_ended_holds_are_swept() {
        let guard = EvmPoolGuard::new(EvmPoolGuardConfig {
            held_senders_max: 2,
            ..EvmPoolGuardConfig::default()
        });
        let sender = |i: u8| [i; 32];
        guard.note_executed(&sender(1), Some(FAULT), T0, T0);
        guard.note_executed(&sender(2), Some(FAULT), T0 + 1, T0 + 1);
        guard.note_executed(&sender(3), Some(FAULT), T0 + 2, T0 + 2);
        assert_eq!(guard.seen.lock().held.len(), 2);
        assert!(
            guard.refusal_at(&sender(1), 21_000, T0 + 2).is_none(),
            "the oldest hold gave way"
        );
        assert!(guard.refusal_at(&sender(3), 21_000, T0 + 2).is_some());

        guard.note_executed(
            &sender(4),
            Some(FAULT),
            T0 + HOLD_MS + 10,
            T0 + HOLD_MS + 10,
        );
        assert_eq!(
            guard.seen.lock().held.len(),
            1,
            "holds that ended are gone when a block is noted"
        );
    }

    #[test]
    fn a_guard_turned_off_holds_and_refuses_nothing() {
        let guard = EvmPoolGuard::new(EvmPoolGuardConfig {
            enabled: false,
            ..EvmPoolGuardConfig::default()
        });
        assert!(
            guard
                .note_executed(&[1u8; 32], Some(FAULT), T0, T0)
                .is_none()
        );
        assert!(guard.refusal_at(&[1u8; 32], 30_000_000, T0).is_none());
    }
}
