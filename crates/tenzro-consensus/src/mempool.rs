//! Transaction mempool with priority ordering.
//!
//! ## Mempool ↔ proposer coupling
//!
//! `select_transactions` is **non-destructive**: it reads the priority queue
//! without removing anything. Removal happens only via [`Mempool::remove_transactions`],
//! which the consensus engine invokes on **finalization** of a block.
//!
//! This is the canonical production pattern — the same
//! reap-then-update split used by production BFT mempools, including the
//! pre-quorum-store design. It guarantees liveness across view changes:
//! transactions in an abandoned proposal stay selectable, so the next leader
//! picks them up. Across concurrent in-flight proposals the same tx may appear
//! in more than one — at most one block finalizes, the other proposal is
//! dropped wholesale, and the `contains_key` check on subsequent selections
//! filters out anything already finalized.
//!
//! The destructive-pop-with-explicit-reinjection pattern (the obvious
//! alternative) is **not** used by any major project in 2026: it requires
//! plumbing proposal lifecycle (timeout, abandon, commit) back into the
//! mempool, and any desync between the in-flight set and the abandonment
//! notification reproduces exactly the stranding bug this design avoids.
//!
//! Future direction: abandon priority-pull entirely in favor of a quorum store
//! or DAG-based mempool design, where data availability is
//! certified before consensus orders it. Until then, non-destructive read is
//! the right interim design.

use crate::admission::{AdmissionController, AdmissionDecision, Lane};
use crate::config::ConsensusConfig;
use crate::error::{ConsensusError, Result};
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tenzro_onboarding_types::onboarding::Standing;
use tenzro_types::primitives::{Address, Hash};
use tenzro_types::transaction::{SignedTransaction, TransactionType};

/// Read access to live account execution state for stateful admission.
///
/// Implemented by the node layer over the VM execution state (CF_STATE
/// `nonce:` / balance keys) and wired post-construction via
/// [`Mempool::set_state_reader`] — same lifecycle as the admission
/// controller. When unwired (tests, early bootstrap before storage is up),
/// the mempool skips nonce/balance validation and relies on execution-time
/// rejection alone.
pub trait AccountStateReader: Send + Sync {
    /// Current execution-state nonce for `address` (0 for unknown accounts).
    fn account_nonce(&self, address: &Address) -> u64;

    /// Current spendable balance for `address` (0 for unknown accounts).
    fn account_balance(&self, address: &Address) -> u128;

    /// Base fee the next block charges, per unit of gas. A transaction
    /// offering less is never executed, so it is not admitted either.
    fn block_base_fee(&self) -> u128;
}

/// What the identity registry says about the account that sends a
/// transaction, so the mempool admits only registered senders.
///
/// Implemented by the node over consensus chain state (the wallet-to-identity
/// index `RegisterIdentity` writes, and the revocation markers) and wired
/// post-construction with [`Mempool::set_sender_registry`]. Unwired, the
/// mempool admits any sender, as before.
pub trait SenderRegistry: Send + Sync {
    /// The standing of `sender`. The implementation decides the carve-outs
    /// that keep the chain live (an account already bonded as a validator).
    fn sender_standing(&self, sender: &Address) -> Standing;
}

/// Whether `tx` is part of getting registered, or a record the protocol
/// asks a validator to make, and so is admitted from an account that has no
/// registered identity yet. The VM still applies its own rules to each: the
/// registration is checked against the key it names, the record against the
/// sender's bond.
pub fn is_registration_path(tx: &TransactionType) -> bool {
    matches!(
        tx,
        TransactionType::RegisterIdentity { .. } | TransactionType::AccountKeys { .. }
    ) || tx.pays_no_fee()
}

/// Where a pooled transaction stands in selection order: the higher
/// priority first, and among equal priorities the one admitted first.
type OrderKey = (Reverse<u64>, u64);

/// What a selection does with a transaction it is shown in turn: every
/// transaction a sender has pooled is shown in nonce order from the
/// sender's executed nonce, and a later one only once the one before it was
/// taken or passed over as taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// Taken: the sender's next transaction may follow it.
    Take,
    /// Not taken here because it is already taken elsewhere (batched and
    /// not yet executed): the sender's next transaction may follow it.
    Taken,
    /// Not taken: the sender's later transactions wait with it.
    Wait,
    /// The selection ends here.
    Stop,
}

/// A pooled transaction, the size it was admitted at, its priority, its
/// admission sequence number (which, with the priority, is its place in
/// selection order) and when it was admitted.
#[derive(Clone)]
struct Pooled {
    tx: Arc<SignedTransaction>,
    size: usize,
    priority: u64,
    seq: u64,
    added_at: SystemTime,
}

/// The priority a transaction is ordered and kept by: its gas price, or the
/// highest for a record the protocol asks a validator to make, which pays no
/// fee (see [`TransactionType::pays_no_fee`]). Such a record is neither
/// ordered behind fee-paying transactions nor evicted for one.
fn priority(tx: &SignedTransaction, fee_free: bool) -> u64 {
    if fee_free {
        u64::MAX
    } else {
        tx.transaction.gas_price
    }
}

/// Transaction mempool with priority ordering
pub struct Mempool {
    /// Selection order of the pooled transactions. Only selection takes
    /// this lock: it walks the order from the front, as far as it takes
    /// transactions, and drops the entries of transactions no longer
    /// pooled as it passes them.
    order: Arc<Mutex<BTreeMap<OrderKey, Hash>>>,

    /// Transactions admitted since the last selection. Admission appends
    /// here, holding the lock for one push, and selection moves them into
    /// `order`, so admission never waits on a selection walking the pool.
    admitted: Arc<Mutex<Vec<(OrderKey, Hash)>>>,

    /// The next admission sequence number.
    next_seq: Arc<AtomicU64>,

    /// Transaction lookup by hash
    transactions: Arc<DashMap<Hash, Pooled>>,

    /// Configuration
    config: Arc<ConsensusConfig>,

    /// Total size in bytes
    total_size: Arc<RwLock<usize>>,

    /// Per-DID admission controller. When set, every
    /// `add_transaction` call first runs lane assignment + token-bucket
    /// rate limiting. When unset, the mempool applies size/count limits
    /// only — used by tests and very early
    /// bootstrap before identity is wired.
    ///
    /// Stored in a `OnceLock` so it can be wired in *after* `Mempool::new`
    /// (which happens inside `ConsensusHandle::new` before the node has
    /// `IdentityRegistry` handle), without forcing
    /// any `&mut self` on the hot path. Read on every `add_transaction`,
    /// written exactly once at node startup.
    admission: OnceLock<Arc<AdmissionController>>,

    /// Live account state reader for stateful admission (nonce ordering +
    /// balance coverage). Same wire-once lifecycle as `admission`; when
    /// unset, nonce/balance checks are skipped and only execution rejects
    /// invalid transactions.
    state_reader: OnceLock<Arc<dyn AccountStateReader>>,

    /// The identity registry as the mempool reads it. Wired once by the
    /// node when the identity gate is on; when unset, any sender is admitted.
    sender_registry: OnceLock<Arc<dyn SenderRegistry>>,

    /// Pending-transaction count per sender address. Enforces
    /// `ConsensusConfig::mempool_max_per_sender` so a single account cannot
    /// monopolize shared mempool capacity. Incremented on insert,
    /// decremented in `remove_transaction`, cleared in `clear`.
    sender_counts: Arc<DashMap<Address, usize>>,
}

impl Mempool {
    /// Creates a new mempool
    pub fn new(config: Arc<ConsensusConfig>) -> Self {
        Self {
            order: Arc::new(Mutex::new(BTreeMap::new())),
            admitted: Arc::new(Mutex::new(Vec::new())),
            next_seq: Arc::new(AtomicU64::new(0)),
            transactions: Arc::new(DashMap::new()),
            config,
            total_size: Arc::new(RwLock::new(0)),
            admission: OnceLock::new(),
            state_reader: OnceLock::new(),
            sender_registry: OnceLock::new(),
            sender_counts: Arc::new(DashMap::new()),
        }
    }

    /// Wire an account state reader into a live `Mempool` for stateful
    /// admission (nonce ordering + balance coverage). Same at-most-once
    /// contract as [`Self::set_admission`].
    pub fn set_state_reader(&self, reader: Arc<dyn AccountStateReader>) -> Result<()> {
        self.state_reader
            .set(reader)
            .map_err(|_| ConsensusError::AlreadyStarted)
    }

    /// Wire the identity registry into a live `Mempool`: from here only a
    /// registered sender's transaction is admitted (see
    /// [`is_registration_path`] for what is admitted from anyone). Same
    /// at-most-once contract as [`Self::set_admission`].
    pub fn set_sender_registry(&self, registry: Arc<dyn SenderRegistry>) -> Result<()> {
        self.sender_registry
            .set(registry)
            .map_err(|_| ConsensusError::AlreadyStarted)
    }

    /// Wire a admission controller into a live `Mempool`. The
    /// controller is shared (via `Arc`) so RPC handlers and the node tick
    /// loop can also read its bucket snapshots and stats. May be called
    /// at most once per `Mempool` instance — subsequent calls return
    /// `Err(ConsensusError::AlreadyStarted)` so a buggy second wiring
    /// can't silently desync the resolver from the engine.
    pub fn set_admission(&self, admission: Arc<AdmissionController>) -> Result<()> {
        self.admission
            .set(admission)
            .map_err(|_| ConsensusError::AlreadyStarted)
    }

    /// The nonce `sender`'s next transaction takes: `executed` (the account's
    /// nonce in execution state) advanced past every consecutive nonce the
    /// sender already has waiting here.
    ///
    /// The waiting transactions are read before `executed` is called. A
    /// transaction leaves the mempool only after the state its block wrote is
    /// committed, so one that is no longer here is already counted in the
    /// executed nonce read after it.
    pub fn next_nonce(&self, sender: &Address, executed: impl FnOnce() -> u64) -> u64 {
        let waiting: std::collections::HashSet<u64> =
            if self.sender_counts.get(sender).is_none_or(|c| *c == 0) {
                std::collections::HashSet::new()
            } else {
                self.transactions
                    .iter()
                    .filter(|e| &e.value().tx.transaction.from == sender)
                    .map(|e| e.value().tx.transaction.nonce.0)
                    .collect()
            };
        let mut next = executed();
        while waiting.contains(&next) {
            match next.checked_add(1) {
                Some(n) => next = n,
                None => break,
            }
        }
        next
    }

    /// Whether `sender` has a transaction waiting here for which `matches`
    /// holds.
    pub fn has_pending_from(
        &self,
        sender: &Address,
        matches: impl Fn(&SignedTransaction) -> bool,
    ) -> bool {
        if self.sender_counts.get(sender).is_none_or(|c| *c == 0) {
            return false;
        }
        self.transactions
            .iter()
            .any(|e| &e.value().tx.transaction.from == sender && matches(&e.value().tx))
    }

    /// The least gas price a transaction in `lane` is admitted at: the
    /// lane's multiple of the base fee the next block charges, never below
    /// that base fee.
    pub fn required_gas_price(&self, ctrl: &AdmissionController, lane: Lane) -> u64 {
        let base_fee = self.base_fee();
        let lane_floor = (base_fee as f64 * ctrl.fee_floor_mult(lane)).ceil();
        if lane_floor >= u64::MAX as f64 {
            u64::MAX
        } else {
            (lane_floor as u64).max(base_fee)
        }
    }

    /// The base fee the next block charges, 0 without a state reader.
    fn base_fee(&self) -> u64 {
        let base_fee = self.state_reader.get().map_or(0, |r| r.block_base_fee());
        u64::try_from(base_fee).unwrap_or(u64::MAX)
    }

    /// The least gas price this mempool admits a `lane` transaction at right
    /// now: [`Self::required_gas_price`] under admission control, else the
    /// base fee the next block charges. Transactions the node itself signs
    /// take their price from here at signing time, so they clear admission
    /// whatever the fee market is.
    pub fn current_min_gas_price(&self, lane: Lane) -> u64 {
        match self.admission.get() {
            Some(ctrl) => self.required_gas_price(ctrl, lane),
            None => self.base_fee(),
        }
    }

    /// Read access to the admission controller, if any. Used by RPC
    /// handlers (`tenzro_getMempoolLane`, `tenzro_getMempoolStats`) and
    /// metrics collection.
    pub fn admission(&self) -> Option<&Arc<AdmissionController>> {
        self.admission.get()
    }

    /// Adds a transaction to the mempool
    ///
    /// # Security (count and size limits)
    ///
    /// This method enforces strict mempool size limits to prevent resource exhaustion:
    /// - **Count limit**: Default 10,000 transactions (configurable via mempool_max_transactions)
    /// - **Size limit**: Default 100MB (configurable via mempool_size_limit)
    /// - **Eviction policy**: When full, evicts lowest-gas-price transactions to make room
    ///   for higher-priority transactions
    ///
    /// This prevents DoS attacks where an attacker floods the mempool with low-fee transactions.
    pub fn add_transaction(&self, mut transaction: SignedTransaction) -> Result<()> {
        let hash = transaction.hash();

        // Check if already in mempool
        if self.transactions.contains_key(&hash) {
            return Err(ConsensusError::Mempool(
                "Transaction already in mempool".to_string(),
            ));
        }

        // A transaction already past its valid_until can never execute;
        // block execution is what enforces the expiry, this only keeps it
        // out of the pool.
        if transaction.transaction.valid_until < tenzro_types::primitives::Timestamp::now() {
            return Err(ConsensusError::Mempool(
                "Transaction expired (valid_until has passed)".to_string(),
            ));
        }

        // The sender must have a registered identity, except for the
        // transactions that are how one is registered. Checked before any
        // lane, bucket or size work, so an unregistered sender spends none
        // of them. The refusal names its reason; nothing is charged.
        if let Some(registry) = self.sender_registry.get()
            && !is_registration_path(&transaction.transaction.tx_type)
        {
            let standing = registry.sender_standing(&transaction.transaction.from);
            if !standing.is_registered() {
                tracing::debug!(
                    target: "mempool::admission",
                    hash = %hash,
                    sender = %transaction.transaction.from,
                    reason = standing.refusal(),
                    "Rejected: sender has no registered identity"
                );
                return Err(ConsensusError::SenderNotRegistered {
                    sender: transaction.transaction.from.to_string(),
                    reason: standing.refusal(),
                });
            }
        }

        // per-DID admission lane + token bucket + fee floor.
        // Runs before any size/count work so rate-limited / under-priced
        // senders can't push out expensive eviction passes. Skipped when
        // the controller is unwired (early bootstrap, test harness).
        //
        // Order matters:
        //   1. assign_lane (cheap, no side effect)
        //   2. fee-floor check — reject without consuming a bucket token
        //   3. try_admit (consumes token; rejects if bucket empty)
        //
        // Doing fee-floor *before* try_admit ensures spam at zero gas
        // doesn't drain a controller's bucket — only well-formed
        // transactions burn admission rate.
        //
        // A record the protocol asks a validator to make pays no fee: it is
        // held to no fee floor and needs no balance. Under admission control
        // only a bonded validator's is admitted as one (the controller's
        // resolver checks the bond); the VM refuses one from any account
        // with no bond.
        let fee_free = transaction.transaction.tx_type.pays_no_fee()
            && self
                .admission
                .get()
                .is_none_or(|ctrl| ctrl.exempt_from_rate(&transaction));
        let admitted_lane = if let Some(ctrl) = self.admission.get() {
            let lane = ctrl.assign_lane(&transaction);

            // (2) Fee-floor check.
            let base_floor = self.base_fee();
            let required = self.required_gas_price(ctrl, lane);
            if required > 0 && !fee_free {
                let multiplier = ctrl.fee_floor_mult(lane);
                if transaction.transaction.gas_price < required {
                    ctrl.record_rejected_fee_floor(lane);
                    tracing::debug!(
                        target: "mempool::admission",
                        hash = %hash,
                        lane = %lane.as_str(),
                        gas_price = transaction.transaction.gas_price,
                        required,
                        base = base_floor,
                        multiplier,
                        "Rejected at fee-floor"
                    );
                    return Err(ConsensusError::FeeFloorTooLow {
                        lane: lane.as_str(),
                        gas_price: transaction.transaction.gas_price,
                        required,
                        base: base_floor,
                        multiplier,
                    });
                }
            }

            Some(lane)
        } else {
            None
        };

        // Per-sender pending cap. Runs regardless of whether a state reader
        // is wired — it is a pure mempool-shape invariant, not a state check.
        let sender = transaction.transaction.from;
        let per_sender_cap = self.config.mempool_max_per_sender;
        if per_sender_cap > 0 {
            let pending = self
                .sender_counts
                .get(&sender)
                .map(|c| *c.value())
                .unwrap_or(0);
            if pending >= per_sender_cap {
                return Err(ConsensusError::SenderCapExceeded {
                    sender: sender.to_string(),
                    pending,
                    cap: per_sender_cap,
                });
            }
        }

        // Stateful admission: nonce ordering + balance coverage against live
        // execution state. Skipped when no reader is wired (tests, early
        // bootstrap) — execution-time rejection is the backstop.
        if let Some(reader) = self.state_reader.get() {
            let account_nonce = reader.account_nonce(&sender);
            let tx_nonce = transaction.transaction.nonce.0;

            if tx_nonce < account_nonce {
                return Err(ConsensusError::NonceTooLow {
                    sender: sender.to_string(),
                    tx_nonce,
                    account_nonce,
                });
            }

            // Bound the future-nonce gap so unexecutable transactions can't
            // park in the mempool indefinitely. The per-sender cap doubles as
            // the look-ahead window.
            if per_sender_cap > 0 && tx_nonce > account_nonce.saturating_add(per_sender_cap as u64)
            {
                return Err(ConsensusError::NonceGapTooLarge {
                    sender: sender.to_string(),
                    tx_nonce,
                    account_nonce,
                    max_gap: per_sender_cap as u64,
                });
            }

            // Worst-case cost: gas_limit × gas_price + transferred value.
            let value: u128 = match &transaction.transaction.tx_type {
                TransactionType::Transfer { amount } => *amount,
                TransactionType::Stake {
                    op: tenzro_types::token::StakeOp::Bond { amount, .. },
                } => *amount,
                TransactionType::CreateEscrow { amount, .. } => *amount,
                _ => 0,
            };
            // The treasury pays a Funding transaction's gas, and a protocol
            // record pays none, so their senders may hold nothing.
            let gas_cost = if fee_free
                || matches!(
                    transaction.transaction.tx_type,
                    TransactionType::Funding { .. }
                ) {
                0
            } else {
                (transaction.transaction.gas_limit as u128)
                    .saturating_mul(transaction.transaction.gas_price as u128)
            };
            let required = gas_cost.saturating_add(value);
            let balance = reader.account_balance(&sender);
            if balance < required {
                return Err(ConsensusError::InsufficientBalance {
                    sender: sender.to_string(),
                    balance,
                    required,
                });
            }
        }

        // (3) Token bucket: consumed only by a transaction every other
        // check admits, so refused ones spend none of their sender's rate.
        let admitted_lane = match (self.admission.get(), admitted_lane) {
            (Some(ctrl), Some(lane)) if ctrl.exempt_from_rate(&transaction) => Some(lane),
            (Some(ctrl), Some(_)) => match ctrl.try_admit(&transaction) {
                AdmissionDecision::Admit { lane } => Some(lane),
                AdmissionDecision::RateLimited {
                    lane,
                    retry_after_ms,
                    burst_remaining,
                    current_rate,
                } => {
                    tracing::debug!(
                        target: "mempool::admission",
                        hash = %hash,
                        lane = %lane.as_str(),
                        retry_after_ms,
                        burst_remaining,
                        current_rate,
                        "Rate-limited at admission"
                    );
                    return Err(ConsensusError::RateLimited {
                        lane: lane.as_str(),
                        retry_after_ms,
                        burst_remaining,
                        current_rate,
                    });
                }
            },
            _ => None,
        };

        let tx_size = self.estimate_transaction_size(&transaction);
        let gas_price = priority(&transaction, fee_free);

        // SECURITY: Mempool count limit with eviction
        // Check count limit and evict if necessary
        if self.transactions.len() >= self.config.mempool_max_transactions {
            // Try to evict the lowest-gas-price transaction
            if !self.evict_lowest_gas_price_transaction(&transaction, gas_price)? {
                if let (Some(ctrl), Some(lane)) = (self.admission.get(), admitted_lane) {
                    ctrl.record_rejected_mempool_full(lane);
                }
                return Err(ConsensusError::Mempool(
                    "Mempool full and new transaction has lower gas price than all existing ones"
                        .to_string(),
                ));
            }
        }

        // SECURITY: Mempool size limit with eviction
        // Check size limit
        let current_size = *self.total_size.read();
        if current_size + tx_size > self.config.mempool_size_limit {
            // Try to evict transactions until we have space
            if !self.evict_for_size(&transaction, tx_size, gas_price)? {
                if let (Some(ctrl), Some(lane)) = (self.admission.get(), admitted_lane) {
                    ctrl.record_rejected_mempool_full(lane);
                }
                return Err(ConsensusError::Mempool(
                    "Mempool size limit exceeded and cannot evict enough transactions".to_string(),
                ));
            }
        }

        let seq = self.next_seq.fetch_add(1, AtomicOrdering::Relaxed);

        *self.total_size.write() += tx_size;
        *self.sender_counts.entry(sender).or_insert(0) += 1;
        match self.transactions.entry(hash) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                self.release(&sender, tx_size);
                return Err(ConsensusError::Mempool(
                    "Transaction already in mempool".to_string(),
                ));
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert(Pooled {
                    tx: Arc::new(transaction),
                    size: tx_size,
                    priority: gas_price,
                    seq,
                    added_at: SystemTime::now(),
                });
            }
        }
        self.admitted.lock().push(((Reverse(gas_price), seq), hash));

        tracing::debug!(
            hash = %hash,
            gas_price = gas_price,
            size = tx_size,
            total_size = *self.total_size.read(),
            count = self.transactions.len(),
            lane = ?admitted_lane.map(|l| l.as_str()),
            "Transaction added to mempool"
        );

        Ok(())
    }

    /// The pooled transactions that cannot run next: their sender's pooled
    /// nonces do not reach them without a gap from the account nonce. Also
    /// whether `newcomer` would be one of them. Without a state reader every
    /// transaction counts as executable.
    fn queued(&self, newcomer: &SignedTransaction) -> (std::collections::HashSet<Hash>, bool) {
        let mut queued = std::collections::HashSet::new();
        let Some(reader) = self.state_reader.get() else {
            return (queued, false);
        };
        let mut by_sender: HashMap<Address, Vec<(u64, Hash)>> = HashMap::new();
        for entry in self.transactions.iter() {
            let t = &entry.value().tx.transaction;
            by_sender
                .entry(t.from)
                .or_default()
                .push((t.nonce.0, *entry.key()));
        }
        let newcomer_from = newcomer.transaction.from;
        let mut newcomer_next = None;
        for (sender, mut txs) in by_sender {
            txs.sort_unstable_by_key(|(n, _)| *n);
            let start = reader.account_nonce(&sender);
            let mut next = start;
            for (n, h) in txs {
                if n == next {
                    next = next.saturating_add(1);
                } else if n < start || n > next {
                    queued.insert(h);
                }
            }
            if sender == newcomer_from {
                newcomer_next = Some(next);
            }
        }
        let next = newcomer_next.unwrap_or_else(|| reader.account_nonce(&newcomer_from));
        (queued, newcomer.transaction.nonce.0 > next)
    }

    /// Makes room for one transaction when the pool is full. An executable
    /// newcomer first displaces a transaction that cannot run next, whatever
    /// that one pays: it would never be charged for its place. Otherwise the
    /// cheapest transaction paying less than the newcomer goes, and a
    /// newcomer that cannot run next displaces only another such one.
    /// Returns true if eviction succeeded, false otherwise
    fn evict_lowest_gas_price_transaction(
        &self,
        newcomer: &SignedTransaction,
        new_gas_price: u64,
    ) -> Result<bool> {
        let (queued, newcomer_queued) = self.queued(newcomer);
        let mut victim: Option<(bool, u64, Hash)> = None;
        for entry in self.transactions.iter() {
            let hash = *entry.key();
            let price = entry.value().priority;
            let is_queued = queued.contains(&hash);
            let evictable = if newcomer_queued {
                is_queued && price < new_gas_price
            } else {
                is_queued || price < new_gas_price
            };
            if !evictable {
                continue;
            }
            // Queued ones first, then the cheapest.
            let key = (!is_queued, price, hash);
            if victim.is_none_or(|v| (key.0, key.1, key.2.as_bytes()) < (v.0, v.1, v.2.as_bytes()))
            {
                victim = Some(key);
            }
        }

        if let Some((_, evicted_gas_price, hash)) = victim {
            self.remove_transaction(&hash);
            tracing::debug!(
                evicted_hash = %hash,
                evicted_gas_price,
                new_gas_price = new_gas_price,
                "Evicted a transaction to make room"
            );
            return Ok(true);
        }

        Ok(false)
    }

    /// Makes room for `needed_size` bytes by evicting transactions that pay
    /// less than `new_gas_price`, cheapest first; an executable newcomer
    /// evicts transactions that cannot run next before any other, whatever
    /// they pay, and a newcomer that cannot run next evicts only such ones.
    /// Evicts nothing unless that frees enough: a newcomer that cannot fit
    /// leaves the pool as it was. Returns whether the room was made.
    fn evict_for_size(
        &self,
        newcomer: &SignedTransaction,
        needed_size: usize,
        new_gas_price: u64,
    ) -> Result<bool> {
        let current_size = *self.total_size.read();
        let available = self.config.mempool_size_limit.saturating_sub(current_size);

        if available >= needed_size {
            return Ok(true);
        }

        let mut to_evict = Vec::new();
        let mut freed_size = 0usize;
        let needed_to_free = needed_size - available;

        // Transactions that cannot run next first, then cheaper ones, by
        // their admitted sizes, lowest first.
        let (queued, newcomer_queued) = self.queued(newcomer);
        let mut txs: Vec<(bool, Hash, u64, usize)> = self
            .transactions
            .iter()
            .filter_map(|entry| {
                let p = entry.value();
                let price = p.priority;
                let is_queued = queued.contains(entry.key());
                let evictable = if newcomer_queued {
                    is_queued && price < new_gas_price
                } else {
                    is_queued || price < new_gas_price
                };
                evictable.then_some((!is_queued, *entry.key(), price, p.size))
            })
            .collect();

        txs.sort_by(|a, b| (a.0, a.2, a.1.as_bytes()).cmp(&(b.0, b.2, b.1.as_bytes())));

        for (_, hash, _, size) in txs {
            to_evict.push(hash);
            freed_size += size;

            if freed_size >= needed_to_free {
                break;
            }
        }
        if freed_size < needed_to_free {
            return Ok(false);
        }

        // Perform evictions
        for hash in &to_evict {
            self.remove_transaction(hash);
        }

        tracing::debug!(
            evicted_count = to_evict.len(),
            freed_size = freed_size,
            needed_size = needed_size,
            "Evicted transactions to free space"
        );

        Ok(freed_size >= needed_to_free)
    }

    /// Releases the size and the sender's count one pooled transaction
    /// took.
    fn release(&self, sender: &Address, size: usize) {
        {
            let mut total = self.total_size.write();
            *total = total.saturating_sub(size);
        }
        if let dashmap::mapref::entry::Entry::Occupied(mut count) =
            self.sender_counts.entry(*sender)
        {
            if *count.get() <= 1 {
                count.remove();
            } else {
                *count.get_mut() -= 1;
            }
        }
    }

    /// Whether any pooled transaction satisfies `pred`. Reads the pool as it
    /// stands and takes none of the locks ordering and admission use.
    pub fn any_transaction(&self, pred: impl Fn(&SignedTransaction) -> bool) -> bool {
        self.transactions.iter().any(|e| pred(&e.value().tx))
    }

    /// Removes a transaction from the mempool
    pub fn remove_transaction(&self, hash: &Hash) -> Option<SignedTransaction> {
        let (_, pooled) = self.transactions.remove(hash)?;
        self.release(&pooled.tx.transaction.from, pooled.size);
        // The selection order keeps its entry; selection drops it.
        Some(Arc::unwrap_or_clone(pooled.tx))
    }

    /// Whether the mempool holds `hash`.
    pub fn contains(&self, hash: &Hash) -> bool {
        self.transactions.contains_key(hash)
    }

    /// Gets a transaction from the mempool
    pub fn get_transaction(&self, hash: &Hash) -> Option<SignedTransaction> {
        self.transactions.get(hash).map(|p| (*p.tx).clone())
    }

    /// Selects transactions for block proposal.
    ///
    /// Selection takes nothing out of the pool: a selected transaction stays
    /// selectable until [`Self::remove_transactions`] takes it out on
    /// finalization. This is what guarantees liveness across view changes:
    /// if a proposal is abandoned (timeout, leader change), the transactions
    /// it carried are selected again by the next leader. Within one call a
    /// transaction is selected at most once.
    pub fn select_transactions(&self, max_count: usize, max_gas: u64) -> Vec<SignedTransaction> {
        let mut selected = Vec::new();
        let mut total_gas = 0u64;
        self.select_with(|_, tx| {
            if selected.len() >= max_count {
                return Pick::Stop;
            }
            let gas = tx.transaction.gas_limit;
            if total_gas.saturating_add(gas) > max_gas {
                return Pick::Wait;
            }
            total_gas += gas;
            selected.push(tx.clone());
            Pick::Take
        });
        tracing::debug!(
            count = selected.len(),
            total_gas = total_gas,
            "Selected transactions for block"
        );
        selected
    }

    /// Shows `pick` the pooled transactions in selection order, highest
    /// priority first, until it stops or the pool is passed, and nothing
    /// else: the walk ends where the caller has what it needs, not at the
    /// end of the pool.
    ///
    /// A sender's transactions execute in nonce order and only from its
    /// execution-state nonce on: one ahead of a nonce not yet shown would
    /// fail in execution and spend nothing, so it is shown only after the
    /// one before it was taken (or passed over as taken elsewhere). Without
    /// a state reader the mempool cannot know the next nonce, and every
    /// transaction is shown by priority alone.
    ///
    /// Admission never waits on this walk: it takes no lock the walk holds
    /// except, for a moment, the read of one transaction's entry.
    pub fn select_with(&self, mut pick: impl FnMut(&Hash, &SignedTransaction) -> Pick) {
        let mut order = self.order.lock();
        let admitted = std::mem::take(&mut *self.admitted.lock());
        order.extend(admitted);

        let reader = self.state_reader.get().cloned();
        let ttl = self.config.transaction_ttl();
        let now = SystemTime::now();
        // Each sender's next nonce to show, from its executed nonce on.
        let mut next_nonce: HashMap<Address, u64> = HashMap::new();
        // Transactions passed in the walk ahead of their sender's next
        // nonce, by sender and nonce.
        let mut held: HashMap<Address, BTreeMap<u64, Hash>> = HashMap::new();
        // Entries of transactions no longer pooled, or pooled again under
        // a later entry.
        let mut gone: Vec<OrderKey> = Vec::new();
        let mut expired: Vec<Hash> = Vec::new();

        // Shows `hash` to `pick` if it is still pooled, holding no lock of
        // the pool while `pick` looks at it; what `pick` made of it.
        let show = |hash: &Hash, pick: &mut dyn FnMut(&Hash, &SignedTransaction) -> Pick| {
            let tx = self.transactions.get(hash)?.tx.clone();
            Some(pick(hash, &tx))
        };

        'walk: for (key, hash) in order.iter() {
            let (sender, nonce) = {
                let Some(pooled) = self.transactions.get(hash) else {
                    gone.push(*key);
                    continue;
                };
                if pooled.seq != key.1 {
                    gone.push(*key);
                    continue;
                }
                if now
                    .duration_since(pooled.added_at)
                    .is_ok_and(|age| age > ttl)
                {
                    gone.push(*key);
                    expired.push(*hash);
                    continue;
                }
                let t = &pooled.tx.transaction;
                (t.from, t.nonce.0)
            };
            let Some(reader) = reader.as_ref() else {
                match show(hash, &mut pick) {
                    Some(Pick::Stop) => break 'walk,
                    _ => continue,
                }
            };
            let expected = *next_nonce
                .entry(sender)
                .or_insert_with(|| reader.account_nonce(&sender));
            if nonce != expected {
                // Ahead of the sender's next nonce: held until that one is
                // shown. Behind it: already executed or superseded.
                if nonce > expected {
                    held.entry(sender).or_default().insert(nonce, *hash);
                }
                continue;
            }
            let mut current = *hash;
            let mut next = nonce;
            loop {
                match show(&current, &mut pick) {
                    Some(Pick::Take) | Some(Pick::Taken) => next = next.saturating_add(1),
                    Some(Pick::Stop) => break 'walk,
                    Some(Pick::Wait) | None => break,
                }
                // The sender's held transactions that now follow in order.
                match held.get_mut(&sender).and_then(|w| w.remove(&next)) {
                    Some(h) => current = h,
                    None => break,
                }
            }
            if next != nonce {
                next_nonce.insert(sender, next);
            } else {
                // Not shown on: none of the sender's later ones may be.
                next_nonce.insert(sender, u64::MAX);
            }
        }
        for key in gone {
            order.remove(&key);
        }
        // A walk that stops early leaves the entries behind it; the order
        // is compacted once it holds far more entries than the pool does.
        if order.len() > 2 * self.transactions.len() + 1024 {
            order.retain(|key, hash| self.transactions.get(hash).is_some_and(|p| p.seq == key.1));
        }
        drop(order);
        for hash in expired {
            self.remove_transaction(&hash);
        }
    }

    /// Removes transactions that are included in a block
    pub fn remove_transactions(&self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove_transaction(hash);
        }
    }

    /// Cleans up expired transactions
    pub fn cleanup_expired(&self) {
        let mut expired = Vec::new();

        // Collect expired transactions
        for entry in self.transactions.iter() {
            let hash = *entry.key();
            let tx = &entry.value().tx;

            let tx_age = SystemTime::now()
                .duration_since(tx.transaction.timestamp.into())
                .unwrap_or(Duration::from_secs(0));

            if tx_age > self.config.transaction_ttl()
                || tx.transaction.valid_until < tenzro_types::primitives::Timestamp::now()
            {
                expired.push(hash);
            }
        }

        // Remove expired transactions
        for hash in expired {
            self.remove_transaction(&hash);
            tracing::debug!(hash = %hash, "Removed expired transaction");
        }
    }

    /// Returns the number of transactions in the mempool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Returns whether the mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Returns the total size in bytes
    pub fn size(&self) -> usize {
        *self.total_size.read()
    }

    /// Clears all transactions from the mempool
    pub fn clear(&self) {
        self.order.lock().clear();
        self.admitted.lock().clear();
        self.transactions.clear();
        self.sender_counts.clear();
        *self.total_size.write() = 0;
    }

    /// Returns current queue depth bucketed by admission lane.
    ///
    /// Returns `[verified_count, delegated_count, open_count]`; if no
    /// admission controller is wired (early bootstrap) all transactions
    /// are reported as Open. Walks the transaction map and re-resolves
    /// each tx's lane — O(n) in the mempool size. Suitable for periodic
    /// metrics scrapes (every 10–60s); not for the admission hot path.
    pub fn lane_depths(&self) -> [u64; 3] {
        let mut depths = [0u64; 3];
        match self.admission.get() {
            Some(ctrl) => {
                for entry in self.transactions.iter() {
                    let lane = ctrl.assign_lane(&entry.value().tx);
                    depths[lane as usize] = depths[lane as usize].saturating_add(1);
                }
            }
            None => {
                // No admission wired — everything is Open lane.
                depths[Lane::Open as usize] = self.transactions.len() as u64;
            }
        }
        depths
    }

    /// Estimates the size of a transaction in bytes
    fn estimate_transaction_size(&self, transaction: &SignedTransaction) -> usize {
        // Rough estimation based on serialized size
        serde_json::to_string(transaction)
            .map(|s| s.len())
            .unwrap_or(1024) // Default 1KB if serialization fails
    }
}

/// Mempool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolStats {
    /// Number of transactions
    pub transaction_count: usize,

    /// Total size in bytes
    pub total_size: usize,

    /// Average gas price
    pub avg_gas_price: u64,

    /// Size limit in bytes
    pub size_limit: usize,

    /// Maximum number of transactions
    pub max_transactions: usize,
}

impl Mempool {
    /// Returns mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let transaction_count = self.len();
        let total_size = self.size();

        let avg_gas_price = if transaction_count > 0 {
            let total_gas_price: u128 = self
                .transactions
                .iter()
                .map(|entry| u128::from(entry.value().tx.transaction.gas_price))
                .sum();
            u64::try_from(total_gas_price / transaction_count as u128).unwrap_or(u64::MAX)
        } else {
            0
        };

        MempoolStats {
            transaction_count,
            total_size,
            avg_gas_price,
            size_limit: self.config.mempool_size_limit,
            max_transactions: self.config.mempool_max_transactions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_types::primitives::{Address, ChainId, Nonce};

    fn sign_test(tx: Transaction) -> SignedTransaction {
        let signer = TestHybridSigner::p256_only(1);
        let signature = signer
            .sign(
                tenzro_crypto::SignatureContext::Transaction,
                tx.hash().as_bytes(),
            )
            .unwrap();
        SignedTransaction::new(tx, signer.public_key().p256.clone(), signature)
    }
    use tenzro_types::transaction::{Transaction, TransactionType};

    fn create_test_transaction(gas_price: u64, nonce: u64) -> SignedTransaction {
        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 1000 },
            21000,
            gas_price,
        );
        sign_test(tx)
    }

    #[test]
    fn test_mempool_add_transaction() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        let tx = create_test_transaction(100, 1);
        mempool.add_transaction(tx.clone()).unwrap();

        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_priority_ordering() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        // Add transactions with different gas prices
        let tx1 = create_test_transaction(100, 1);
        let tx2 = create_test_transaction(200, 2);
        let tx3 = create_test_transaction(150, 3);

        mempool.add_transaction(tx1).unwrap();
        mempool.add_transaction(tx2.clone()).unwrap();
        mempool.add_transaction(tx3).unwrap();

        // Select transactions - should be ordered by gas price
        let selected = mempool.select_transactions(10, 1_000_000);
        assert_eq!(selected.len(), 3);

        // First should be tx2 (highest gas price)
        assert_eq!(selected[0].transaction.gas_price, 200);
    }

    #[test]
    fn test_mempool_gas_limit() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        let tx1 = create_test_transaction(100, 1);
        let tx2 = create_test_transaction(200, 2);

        mempool.add_transaction(tx1).unwrap();
        mempool.add_transaction(tx2).unwrap();

        // Select with low gas limit - should only get one transaction
        let selected = mempool.select_transactions(10, 25000);
        assert_eq!(selected.len(), 1);
    }

    /// Regression: `select_transactions` must NOT remove selected txs from
    /// the mempool. They are only removed by `remove_transactions` on
    /// finalization. This is what guarantees liveness when a proposal is
    /// abandoned by a view change — the next leader's selection must still
    /// see them.
    #[test]
    fn test_select_is_non_destructive_across_view_changes() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        let tx1 = create_test_transaction(100, 1);
        let tx2 = create_test_transaction(200, 2);
        let tx3 = create_test_transaction(150, 3);

        mempool.add_transaction(tx1).unwrap();
        mempool.add_transaction(tx2).unwrap();
        mempool.add_transaction(tx3).unwrap();
        assert_eq!(mempool.len(), 3);

        // Leader 1 selects — proposal is built but never finalizes (e.g. view
        // change before commit QC). `remove_transactions` is NOT called.
        let leader1 = mempool.select_transactions(10, 1_000_000);
        assert_eq!(leader1.len(), 3);
        assert_eq!(mempool.len(), 3, "select must not shrink mempool");

        // Leader 2 selects on the next view. With the buggy
        // destructive-pop-no-reinsert design, this returned 0 — the selected
        // txs were stranded. With the fix, the same 3 txs are re-selected.
        let leader2 = mempool.select_transactions(10, 1_000_000);
        assert_eq!(
            leader2.len(),
            3,
            "after a view change, abandoned txs must be re-selectable"
        );

        // Order is preserved across selections (still gas-priority sorted).
        assert_eq!(leader2[0].transaction.gas_price, 200);

        // Only finalization removes them.
        let hashes: Vec<_> = leader2.iter().cloned().map(|mut t| t.hash()).collect();
        mempool.remove_transactions(&hashes);
        assert_eq!(mempool.len(), 0);

        let leader3 = mempool.select_transactions(10, 1_000_000);
        assert_eq!(leader3.len(), 0);
    }

    #[test]
    fn a_selection_walks_no_further_than_it_takes() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig {
            mempool_max_per_sender: 0,
            ..ConsensusConfig::default()
        }));
        for i in 0..2_000u64 {
            mempool
                .add_transaction(create_test_transaction(1_000 + i, i))
                .unwrap();
        }
        let mut shown = Vec::new();
        mempool.select_with(|_, tx| {
            shown.push(tx.transaction.gas_price);
            if shown.len() == 10 {
                Pick::Stop
            } else {
                Pick::Take
            }
        });
        assert_eq!(shown.len(), 10);
        assert_eq!(shown, (0..10u64).map(|i| 2_999 - i).collect::<Vec<_>>());
    }

    #[test]
    fn admission_never_waits_on_a_selection() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig {
            mempool_max_per_sender: 0,
            ..ConsensusConfig::default()
        }));
        for i in 0..100u64 {
            mempool
                .add_transaction(create_test_transaction(1_000 + i, i))
                .unwrap();
        }
        let mut admitted_meanwhile = None;
        std::thread::scope(|scope| {
            mempool.select_with(|_, _| {
                if admitted_meanwhile.is_none() {
                    let (done, finished) = std::sync::mpsc::channel();
                    let pool = &mempool;
                    scope.spawn(move || {
                        let _ =
                            done.send(pool.add_transaction(create_test_transaction(5_000, 100)));
                    });
                    admitted_meanwhile = Some(
                        finished
                            .recv_timeout(Duration::from_secs(10))
                            .expect("admission finished while the selection walked")
                            .is_ok(),
                    );
                }
                Pick::Take
            });
        });
        assert_eq!(admitted_meanwhile, Some(true));
        let next = mempool.select_transactions(1, u64::MAX);
        assert_eq!(
            next[0].transaction.gas_price, 5_000,
            "the next selection shows it"
        );
    }

    #[test]
    fn a_transaction_removed_and_offered_again_is_selected_once() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        let mut tx = create_test_transaction(100, 1);
        let hash = tx.hash();
        mempool.add_transaction(tx.clone()).unwrap();
        assert_eq!(mempool.select_transactions(10, u64::MAX).len(), 1);
        mempool.remove_transaction(&hash);
        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.select_transactions(10, u64::MAX).len(), 1);
        assert_eq!(mempool.select_transactions(10, u64::MAX).len(), 1);
    }

    /// A transaction that expires in the pool leaves it whole: its size and
    /// its sender's count go with it, so expired transactions never hold
    /// room in the pool.
    #[test]
    fn an_expired_transaction_leaves_no_size_or_sender_count_behind() {
        let config = ConsensusConfig {
            transaction_ttl_seconds: 0,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));
        let tx = create_test_transaction(100, 1);
        let sender = tx.transaction.from;
        mempool.add_transaction(tx).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(mempool.select_transactions(10, u64::MAX).is_empty());
        assert!(mempool.is_empty());
        assert_eq!(mempool.size(), 0);
        assert!(mempool.sender_counts.get(&sender).is_none());
    }

    /// Making room by size evicts only transactions paying less than the
    /// newcomer, and evicts nothing unless that makes enough room.
    #[test]
    fn size_eviction_never_trades_dearer_transactions_for_a_cheaper_one() {
        let one = Mempool::new(Arc::new(ConsensusConfig::default()))
            .estimate_transaction_size(&create_test_transaction(1000, 1));
        let config = ConsensusConfig {
            mempool_size_limit: 2 * one + one / 2,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));
        mempool
            .add_transaction(create_test_transaction(1000, 1))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(1000, 2))
            .unwrap();
        assert!(
            mempool
                .add_transaction(create_test_transaction(1, 3))
                .is_err()
        );
        assert_eq!(mempool.len(), 2);
        mempool
            .add_transaction(create_test_transaction(2000, 4))
            .unwrap();
        assert_eq!(mempool.len(), 2);
    }

    /// The same transaction offered from many threads at once enters the
    /// pool once: one entry, one size, one count, one selection.
    #[test]
    fn a_transaction_offered_concurrently_enters_the_pool_once() {
        for _ in 0..20 {
            let mempool = Arc::new(Mempool::new(Arc::new(ConsensusConfig::default())));
            let tx = create_test_transaction(100, 1);
            let sender = tx.transaction.from;
            let size = mempool.estimate_transaction_size(&tx);
            let barrier = Arc::new(std::sync::Barrier::new(8));
            let oks: usize = (0..8)
                .map(|_| {
                    let (m, t, b) = (mempool.clone(), tx.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        b.wait();
                        m.add_transaction(t).is_ok()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().unwrap() as usize)
                .sum();
            assert_eq!(oks, 1);
            assert_eq!(mempool.len(), 1);
            assert_eq!(mempool.size(), size);
            assert_eq!(*mempool.sender_counts.get(&sender).unwrap(), 1);
            assert_eq!(mempool.select_transactions(10, u64::MAX).len(), 1);
        }
    }

    /// Removing a transaction while another thread adds it never drives the
    /// pool's size below zero or leaves size behind.
    #[test]
    fn concurrent_add_and_remove_keep_the_size_exact() {
        for _ in 0..50 {
            let mempool = Arc::new(Mempool::new(Arc::new(ConsensusConfig::default())));
            let mut tx = create_test_transaction(100, 1);
            let hash = tx.hash();
            let remover = {
                let m = mempool.clone();
                std::thread::spawn(move || while m.remove_transaction(&hash).is_none() {})
            };
            mempool.add_transaction(tx).unwrap();
            remover.join().unwrap();
            assert_eq!(mempool.size(), 0);
            assert!(mempool.is_empty());
        }
    }

    /// A transaction refused for its nonce spends none of its sender's
    /// admission budget.
    #[test]
    fn a_refused_transaction_spends_no_admission_token() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver};
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 5,
                balance: u128::MAX,
                base_fee: 0,
            }))
            .unwrap();
        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission).unwrap();
        for _ in 0..100 {
            assert!(matches!(
                mempool.add_transaction(create_test_transaction(1_000_000_000, 3)),
                Err(ConsensusError::NonceTooLow { .. })
            ));
        }
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 5))
            .unwrap();
    }

    /// A validator duty the resolver exempts is admitted past its sender's
    /// token bucket; the same transactions from an ordinary sender are not.
    #[test]
    fn an_exempt_duty_is_not_held_by_the_token_bucket() {
        use crate::admission::{
            AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane, LaneResolver,
        };
        struct Duty;
        impl LaneResolver for Duty {
            fn assign_lane(&self, _tx: &SignedTransaction) -> Lane {
                Lane::Open
            }
            fn bucket_key(&self, tx: &SignedTransaction) -> Address {
                tx.transaction.from
            }
            fn exempt_from_rate(&self, _tx: &SignedTransaction) -> bool {
                true
            }
        }
        let fill = |resolver: Arc<dyn LaneResolver>| {
            let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
            mempool
                .set_state_reader(Arc::new(FixedStateReader {
                    nonce: 0,
                    balance: u128::MAX,
                    base_fee: 0,
                }))
                .unwrap();
            mempool
                .set_admission(Arc::new(AdmissionController::new(
                    AdmissionConfig::default(),
                    resolver,
                )))
                .unwrap();
            (0..64)
                .filter(|n| {
                    mempool
                        .add_transaction(create_test_transaction(1_000_000_000, *n))
                        .is_ok()
                })
                .count()
        };
        assert!(
            fill(Arc::new(DefaultLaneResolver)) < 64,
            "the bucket holds an ordinary sender"
        );
        assert_eq!(fill(Arc::new(Duty)), 64, "an exempt duty is not held");
    }

    #[test]
    fn test_mempool_remove_transaction() {
        let config = Arc::new(ConsensusConfig::default());
        let mempool = Mempool::new(config);

        let mut tx = create_test_transaction(100, 1);
        let hash = tx.hash();

        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.len(), 1);

        mempool.remove_transaction(&hash);
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_count_limit_eviction() {
        let config = ConsensusConfig {
            mempool_max_transactions: 3,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        // Add 3 transactions with different gas prices
        mempool
            .add_transaction(create_test_transaction(100, 1))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(200, 2))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(150, 3))
            .unwrap();
        assert_eq!(mempool.len(), 3);

        // Add a 4th transaction with higher gas price - should evict lowest (100)
        mempool
            .add_transaction(create_test_transaction(300, 4))
            .unwrap();
        assert_eq!(mempool.len(), 3);

        // The mempool should now have gas prices: 200, 150, 300
        let selected = mempool.select_transactions(10, 1_000_000);
        assert_eq!(selected.len(), 3);

        // Highest should be 300
        assert_eq!(selected[0].transaction.gas_price, 300);
    }

    #[test]
    fn test_mempool_eviction_rejects_lower_gas() {
        let config = ConsensusConfig {
            mempool_max_transactions: 2,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        // Add 2 transactions with higher gas prices
        mempool
            .add_transaction(create_test_transaction(200, 1))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(300, 2))
            .unwrap();
        assert_eq!(mempool.len(), 2);

        // Try to add transaction with lower gas price - should fail
        let result = mempool.add_transaction(create_test_transaction(50, 3));
        assert!(result.is_err());
        assert_eq!(mempool.len(), 2);
    }

    #[test]
    fn test_fee_floor_rejects_below_open_lane_multiplier() {
        // With admission wired and Open-lane multiplier 4.0× × base fee 1 Gwei = 4 Gwei,
        // a 100-wei tx must be rejected with FeeFloorTooLow.
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane};

        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(base_fee_reader(1_000_000_000))
            .unwrap();

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission.clone()).unwrap();

        let tx = create_test_transaction(100, 1); // way below 1 Gwei
        let result = mempool.add_transaction(tx);

        match result {
            Err(ConsensusError::FeeFloorTooLow {
                lane,
                gas_price,
                required,
                base,
                multiplier,
            }) => {
                assert_eq!(lane, Lane::Open.as_str());
                assert_eq!(gas_price, 100);
                assert_eq!(base, 1_000_000_000);
                assert!((multiplier - 4.0).abs() < 1e-9);
                assert_eq!(required, 4_000_000_000);
            }
            other => panic!("expected FeeFloorTooLow, got {:?}", other),
        }

        assert_eq!(mempool.len(), 0, "rejected tx must not enter mempool");
    }

    #[test]
    fn test_fee_floor_admits_at_or_above_open_lane_multiplier() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver};

        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(base_fee_reader(1_000_000_000))
            .unwrap();

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission).unwrap();

        // 4 Gwei = exactly the Open-lane floor — must be admitted.
        let tx = create_test_transaction(4_000_000_000, 1);
        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_fee_floor_disabled_when_base_is_zero() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver};

        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission).unwrap();

        // Even gas_price=0 should pass the floor check (then admission token bucket).
        let tx = create_test_transaction(0, 1);
        mempool.add_transaction(tx).unwrap();
        assert_eq!(mempool.len(), 1);
    }

    /// Admission metrics path: the per-lane queue-depth accessor reports
    /// the number of pending transactions in each admission lane.
    /// `DefaultLaneResolver` puts everything in Open, so all admitted
    /// txs land there.
    #[test]
    fn test_lane_depths_with_default_resolver() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane};

        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission).unwrap();

        // Empty mempool: all lanes are zero.
        let depths = mempool.lane_depths();
        assert_eq!(depths, [0, 0, 0]);

        // Admit two transactions — both land in Open via the default resolver.
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 1))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 2))
            .unwrap();

        let depths = mempool.lane_depths();
        assert_eq!(depths[Lane::Verified as usize], 0);
        assert_eq!(depths[Lane::Delegated as usize], 0);
        assert_eq!(depths[Lane::Open as usize], 2);
    }

    /// Without an admission controller wired, `lane_depths` falls back
    /// to attributing every tx to Open. This is the bootstrap path
    /// before identity/staking come online.
    #[test]
    fn test_lane_depths_without_admission_attributes_to_open() {
        use crate::admission::Lane;

        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));

        // No `set_admission` call. Insert 3 txs.
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 1))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 2))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 3))
            .unwrap();

        let depths = mempool.lane_depths();
        assert_eq!(depths[Lane::Verified as usize], 0);
        assert_eq!(depths[Lane::Delegated as usize], 0);
        assert_eq!(depths[Lane::Open as usize], 3);
    }

    /// A state reader whose next block charges `base_fee` per gas.
    fn base_fee_reader(base_fee: u128) -> Arc<FixedStateReader> {
        Arc::new(FixedStateReader {
            nonce: 0,
            balance: u128::MAX,
            base_fee,
        })
    }

    /// Mock state reader with fixed nonce/balance for every address.
    struct FixedStateReader {
        nonce: u64,
        balance: u128,
        base_fee: u128,
    }

    impl AccountStateReader for FixedStateReader {
        fn account_nonce(&self, _address: &Address) -> u64 {
            self.nonce
        }
        fn account_balance(&self, _address: &Address) -> u128 {
            self.balance
        }
        fn block_base_fee(&self) -> u128 {
            self.base_fee
        }
    }

    #[test]
    fn test_stateful_admission_rejects_stale_nonce() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 5,
                balance: u128::MAX,
                base_fee: 0,
            }))
            .unwrap();

        // tx nonce 1 < account nonce 5 — can never execute.
        let result = mempool.add_transaction(create_test_transaction(1_000_000_000, 1));
        match result {
            Err(ConsensusError::NonceTooLow {
                tx_nonce,
                account_nonce,
                ..
            }) => {
                assert_eq!(tx_nonce, 1);
                assert_eq!(account_nonce, 5);
            }
            other => panic!("expected NonceTooLow, got {:?}", other),
        }
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_stateful_admission_rejects_excessive_nonce_gap() {
        let config = ConsensusConfig {
            mempool_max_per_sender: 8,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 0,
                balance: u128::MAX,
                base_fee: 0,
            }))
            .unwrap();

        // nonce 9 > account nonce 0 + gap 8 — parked-forever spam.
        let result = mempool.add_transaction(create_test_transaction(1_000_000_000, 9));
        match result {
            Err(ConsensusError::NonceGapTooLarge {
                tx_nonce, max_gap, ..
            }) => {
                assert_eq!(tx_nonce, 9);
                assert_eq!(max_gap, 8);
            }
            other => panic!("expected NonceGapTooLarge, got {:?}", other),
        }

        // nonce 8 == account nonce 0 + gap 8 — at the boundary, admitted.
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 8))
            .unwrap();
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_stateful_admission_rejects_insufficient_balance() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        // Balance covers neither gas nor the 1000-unit transfer value.
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 0,
                balance: 10,
                base_fee: 0,
            }))
            .unwrap();

        let result = mempool.add_transaction(create_test_transaction(1_000_000_000, 0));
        match result {
            Err(ConsensusError::InsufficientBalance {
                balance, required, ..
            }) => {
                assert_eq!(balance, 10);
                // 21000 gas × 1 Gwei + 1000 transfer value
                assert_eq!(required, 21_000u128 * 1_000_000_000 + 1000);
            }
            other => panic!("expected InsufficientBalance, got {:?}", other),
        }
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn a_funding_transaction_is_admitted_from_a_zero_balance() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 0,
                balance: 0,
                base_fee: 0,
            }))
            .unwrap();
        let tx = Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(0),
            TransactionType::Funding { op: b"{}".to_vec() },
            80_000,
            1_000_000_000,
        );
        mempool
            .add_transaction(sign_test(tx))
            .expect("the treasury pays a funding transaction's gas");
        // Anything else from the same zero balance is still refused.
        assert!(matches!(
            mempool.add_transaction(create_test_transaction(1_000_000_000, 1)),
            Err(ConsensusError::InsufficientBalance { .. })
        ));
    }

    /// Nothing for the record's sender, plenty for everyone else.
    struct OnlyOthersFunded;

    impl AccountStateReader for OnlyOthersFunded {
        fn account_nonce(&self, _address: &Address) -> u64 {
            0
        }
        fn account_balance(&self, address: &Address) -> u128 {
            if *address == Address::default() {
                0
            } else {
                u128::MAX
            }
        }
        fn block_base_fee(&self) -> u128 {
            1_000_000_000
        }
    }

    /// A checkpoint-signers record from a bonded validator (one the resolver
    /// exempts) is admitted with no balance and no gas price, is selected
    /// ahead of fee-paying transactions and is never evicted for one. From
    /// an account the resolver does not exempt it is held to the fee floor.
    #[test]
    fn a_validators_protocol_record_needs_no_balance_and_no_fee() {
        use crate::admission::{
            AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane, LaneResolver,
        };
        struct Bonded;
        impl LaneResolver for Bonded {
            fn assign_lane(&self, _tx: &SignedTransaction) -> Lane {
                Lane::Open
            }
            fn bucket_key(&self, tx: &SignedTransaction) -> Address {
                tx.transaction.from
            }
            fn exempt_from_rate(&self, tx: &SignedTransaction) -> bool {
                tx.transaction.from == Address::default()
            }
        }
        let pool = |resolver: Arc<dyn LaneResolver>| {
            let mempool = Mempool::new(Arc::new(ConsensusConfig {
                mempool_max_transactions: 3,
                ..ConsensusConfig::default()
            }));
            mempool
                .set_state_reader(Arc::new(OnlyOthersFunded))
                .unwrap();
            mempool
                .set_admission(Arc::new(AdmissionController::new(
                    AdmissionConfig::default(),
                    resolver,
                )))
                .unwrap();
            mempool
        };
        let mut record = sign_test(Transaction::new(
            ChainId::from(1),
            Address::default(),
            Address::default(),
            Nonce::from(0),
            TransactionType::RecordCheckpointSigners {
                certificate: vec![1, 2, 3],
            },
            100_000,
            0,
        ));
        let paying = |nonce: u64, gas_price: u64| {
            sign_test(Transaction::new(
                ChainId::from(1),
                Address::new([7; 32]),
                Address::default(),
                Nonce::from(nonce),
                TransactionType::Transfer { amount: 1 },
                21_000,
                gas_price,
            ))
        };

        let mempool = pool(Arc::new(Bonded));
        mempool
            .add_transaction(record.clone())
            .expect("a bonded validator's record needs no balance and no gas price");
        for nonce in 0..3 {
            mempool
                .add_transaction(paying(nonce, 100_000_000_000 * (nonce + 1)))
                .unwrap();
        }
        assert_eq!(mempool.len(), 3);
        assert!(
            mempool.contains(&record.hash()),
            "a dearer transaction never evicts the record"
        );
        let mut selected = mempool.select_transactions(10, u64::MAX);
        assert_eq!(selected[0].hash(), record.hash(), "the record goes first");

        // The same record from an account the resolver does not exempt is
        // an ordinary transaction naming no gas price.
        assert!(matches!(
            pool(Arc::new(DefaultLaneResolver)).add_transaction(record),
            Err(ConsensusError::FeeFloorTooLow { .. })
        ));
    }

    #[test]
    fn test_stateful_admission_admits_when_balance_covers_cost() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 0,
                balance: 21_000u128 * 1_000_000_000 + 1000,
                base_fee: 0,
            }))
            .unwrap();

        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 0))
            .unwrap();
        assert_eq!(mempool.len(), 1);
    }

    fn mempool_at_nonce(nonce: u64) -> Mempool {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce,
                balance: u128::MAX / 4,
                base_fee: 0,
            }))
            .unwrap();
        mempool
    }

    /// What a sender has waiting is found by predicate, and only for that sender.
    #[test]
    fn pending_from_finds_a_waiting_transaction_of_the_sender_only() {
        let mempool = mempool_at_nonce(0);
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 0))
            .unwrap();
        let sender = Address::default();
        assert!(mempool.has_pending_from(&sender, |t| t.transaction.nonce.0 == 0));
        assert!(!mempool.has_pending_from(&sender, |t| t.transaction.nonce.0 == 7));
        assert!(!mempool.has_pending_from(&Address::new([9u8; 32]), |_| true));
    }

    fn nonces(selected: &[SignedTransaction]) -> Vec<u64> {
        selected.iter().map(|t| t.transaction.nonce.0).collect()
    }

    /// A sender's transactions are selected in nonce order from its state
    /// nonce on, whatever their priority: the higher-paying later nonce
    /// follows the one before it.
    #[test]
    fn selection_keeps_each_senders_nonce_order() {
        let mempool = mempool_at_nonce(0);
        mempool
            .add_transaction(create_test_transaction(9_000_000_000, 1))
            .unwrap();
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 0))
            .unwrap();
        assert_eq!(
            nonces(&mempool.select_transactions(10, u64::MAX)),
            vec![0, 1]
        );
    }

    /// A transaction whose predecessor this mempool does not hold is not
    /// selected (it would fail and spend nothing); it stays for a later
    /// block, and is selected once the gap is filled.
    #[test]
    fn a_transaction_ahead_of_a_missing_nonce_waits() {
        let mempool = mempool_at_nonce(4);
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 5))
            .unwrap();
        assert!(mempool.select_transactions(10, u64::MAX).is_empty());
        assert_eq!(mempool.len(), 1, "it stays in the mempool");
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 4))
            .unwrap();
        assert_eq!(
            nonces(&mempool.select_transactions(10, u64::MAX)),
            vec![4, 5]
        );
    }

    #[test]
    fn the_next_nonce_counts_the_senders_waiting_transactions() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        assert_eq!(mempool.next_nonce(&Address::default(), || 3), 3);
        for nonce in [3, 4, 6] {
            mempool
                .add_transaction(create_test_transaction(1_000_000_000 + nonce, nonce))
                .unwrap();
        }
        // 3 and 4 wait; 5 is the gap the next transaction fills.
        assert_eq!(mempool.next_nonce(&Address::default(), || 3), 5);
        assert_eq!(mempool.next_nonce(&Address::new([9u8; 32]), || 0), 0);
    }

    /// A transaction taken into a batch stays counted until its block
    /// executes: batching selects from the mempool without removing anything.
    #[test]
    fn a_batched_transaction_still_counts_toward_the_next_nonce() {
        let mempool = mempool_at_nonce(0);
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 0))
            .unwrap();
        assert_eq!(nonces(&mempool.select_transactions(10, u64::MAX)), vec![0]);
        assert_eq!(mempool.next_nonce(&Address::default(), || 0), 1);
    }

    #[test]
    fn an_open_lane_price_at_the_base_fee_but_below_its_multiple_is_refused() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver};

        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission.clone()).unwrap();
        mempool
            .set_state_reader(Arc::new(FixedStateReader {
                nonce: 0,
                balance: u128::MAX,
                base_fee: 10_000_000_000,
            }))
            .unwrap();

        // The 10 Gwei base fee clears a verified sender, not the open lane's
        // 4x multiple of it.
        assert_eq!(
            mempool.required_gas_price(&admission, Lane::Open),
            40_000_000_000
        );
        assert!(matches!(
            mempool.add_transaction(create_test_transaction(10_000_000_000, 0)),
            Err(ConsensusError::FeeFloorTooLow {
                required: 40_000_000_000,
                ..
            })
        ));
        mempool
            .add_transaction(create_test_transaction(40_000_000_000, 0))
            .unwrap();
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_per_sender_cap_enforced_and_released() {
        let config = ConsensusConfig {
            mempool_max_per_sender: 2,
            ..ConsensusConfig::default()
        };
        let mempool = Mempool::new(Arc::new(config));

        // All test txs share Address::default() as sender.
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 0))
            .unwrap();
        let mut second = create_test_transaction(1_000_000_001, 1);
        let second_hash = second.hash();
        mempool.add_transaction(second).unwrap();

        // Third pending tx from the same sender exceeds the cap.
        let result = mempool.add_transaction(create_test_transaction(1_000_000_002, 2));
        match result {
            Err(ConsensusError::SenderCapExceeded { pending, cap, .. }) => {
                assert_eq!(pending, 2);
                assert_eq!(cap, 2);
            }
            other => panic!("expected SenderCapExceeded, got {:?}", other),
        }

        // Removing one pending tx frees a slot.
        mempool.remove_transaction(&second_hash);
        mempool
            .add_transaction(create_test_transaction(1_000_000_002, 2))
            .unwrap();
        assert_eq!(mempool.len(), 2);
    }

    #[test]
    fn test_unwired_state_reader_skips_stateful_checks() {
        // No set_state_reader call: a stale-nonce, zero-balance-account tx
        // still enters the mempool (execution is the backstop).
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .add_transaction(create_test_transaction(1_000_000_000, 999))
            .unwrap();
        assert_eq!(mempool.len(), 1);
    }

    /// A fee-floor rejection bumps `rejected_fee_floor` (not the
    /// rate-limited or mempool-full counters) so /metrics can attribute
    /// the cause cleanly.
    #[test]
    fn test_fee_floor_rejection_bumps_correct_counter() {
        use crate::admission::{AdmissionConfig, AdmissionController, DefaultLaneResolver, Lane};

        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .set_state_reader(base_fee_reader(1_000_000_000))
            .unwrap();

        let admission = Arc::new(AdmissionController::new(
            AdmissionConfig::default(),
            Arc::new(DefaultLaneResolver),
        ));
        mempool.set_admission(admission.clone()).unwrap();

        // Below 4× × 1 Gwei Open-lane floor — rejected at fee-floor.
        let tx = create_test_transaction(100, 1);
        let _ = mempool.add_transaction(tx);

        let stats = admission.stats();
        assert_eq!(stats.rejected_fee_floor(Lane::Open), 1);
        assert_eq!(stats.rejected_rate_limited(Lane::Open), 0);
        assert_eq!(stats.rejected_mempool_full(Lane::Open), 0);
        // And the bucket token was *not* consumed — fee-floor runs
        // before try_admit. Subsequent admission attempts must succeed.
        let tx2 = create_test_transaction(4_000_000_000, 2);
        mempool.add_transaction(tx2).unwrap();
        let stats = admission.stats();
        assert_eq!(stats.admitted(Lane::Open), 1);
    }

    // ---- identity gate: only registered senders are pooled -------------

    struct Registry(HashMap<Address, Standing>);

    impl SenderRegistry for Registry {
        fn sender_standing(&self, sender: &Address) -> Standing {
            self.0
                .get(sender)
                .copied()
                .unwrap_or(Standing::Unregistered)
        }
    }

    fn from_sender(sender: u8, nonce: u64, tx_type: TransactionType) -> SignedTransaction {
        sign_test(Transaction::new(
            ChainId::from(1),
            Address::new([sender; 32]),
            Address::default(),
            Nonce::from(nonce),
            tx_type,
            21_000,
            1_000_000_000,
        ))
    }

    fn registration() -> TransactionType {
        use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
        use tenzro_types::identity::RegistrationProof;
        TransactionType::RegisterIdentity {
            did: "did:tenzro:machine:aa".into(),
            identity_type: "machine".into(),
            display_name: "machine root".into(),
            controller_pubkey: vec![4; 65],
            key_type: "P-256".into(),
            wallet_id: "0x00".into(),
            wallet_address: Address::new([9; 32]),
            pq_verifying_key: Vec::new(),
            metadata: Default::default(),
            proof: RegistrationProof::Hardware {
                signature: CompositeSignature::classical(ClassicalProof::Raw {
                    signature: Vec::new(),
                }),
            },
        }
    }

    fn gated_pool() -> Mempool {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        let mut standings = HashMap::new();
        standings.insert(Address::new([1; 32]), Standing::Registered);
        standings.insert(Address::new([3; 32]), Standing::Revoked);
        mempool
            .set_sender_registry(Arc::new(Registry(standings)))
            .unwrap();
        mempool
    }

    #[test]
    fn an_unwired_registry_admits_any_sender_as_before() {
        let mempool = Mempool::new(Arc::new(ConsensusConfig::default()));
        mempool
            .add_transaction(from_sender(2, 0, TransactionType::Transfer { amount: 1 }))
            .unwrap();
    }

    #[test]
    fn a_transaction_from_a_sender_with_no_registered_identity_is_refused_with_its_reason() {
        let mempool = gated_pool();
        let err = mempool
            .add_transaction(from_sender(2, 0, TransactionType::Transfer { amount: 1 }))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::SenderNotRegistered {
                    reason: "no registered identity",
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(mempool.len(), 0);
        mempool
            .add_transaction(from_sender(1, 0, TransactionType::Transfer { amount: 1 }))
            .expect("a registered sender is admitted");
    }

    #[test]
    fn every_kind_of_action_is_refused_for_an_unregistered_sender() {
        use tenzro_types::token::StakeOp;
        let mempool = gated_pool();
        let actions = [
            TransactionType::Transfer { amount: 1 },
            TransactionType::Stake {
                op: StakeOp::Bond {
                    role: tenzro_types::network::NetworkRole::ModelProvider,
                    amount: 1,
                    capacity: Default::default(),
                },
            },
            TransactionType::GovernanceVote {
                proposal_id: "p".into(),
                vote: true,
                validator: Address::new([2; 32]),
                root_approval: None,
            },
            TransactionType::Funding { op: vec![1] },
            TransactionType::ExitValidator,
        ];
        for (i, tx) in actions.into_iter().enumerate() {
            assert!(
                matches!(
                    mempool.add_transaction(from_sender(2, i as u64, tx)),
                    Err(ConsensusError::SenderNotRegistered { .. })
                ),
                "action {i} was admitted"
            );
        }
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn a_revoked_identity_is_refused_and_says_so() {
        let mempool = gated_pool();
        let err = mempool
            .add_transaction(from_sender(3, 0, TransactionType::Transfer { amount: 1 }))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConsensusError::SenderNotRegistered {
                    reason: "identity revoked",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn registering_an_identity_is_admitted_from_an_account_that_has_none() {
        let mempool = gated_pool();
        mempool
            .add_transaction(from_sender(2, 0, registration()))
            .expect("the way in must not need the thing it creates");
        assert!(is_registration_path(&registration()));
        assert!(!is_registration_path(&TransactionType::Transfer {
            amount: 1
        }));
    }
}

#[cfg(test)]
mod gapped_nonce_tests {
    use super::*;
    use tenzro_crypto::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};

    struct Reader;
    impl AccountStateReader for Reader {
        fn account_nonce(&self, _a: &Address) -> u64 {
            0
        }
        fn account_balance(&self, _a: &Address) -> u128 {
            1_000_000_000_000_000_000_000
        }
        fn block_base_fee(&self) -> u128 {
            0
        }
    }

    fn tx(from: u8, nonce: u64, gas_price: u64) -> SignedTransaction {
        let t = Transaction::new(
            ChainId::from(1),
            Address::new([from; 32]),
            Address::default(),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 1 },
            21000,
            gas_price,
        );
        let s = TestHybridSigner::p256_only(1);
        let sig = s
            .sign(
                tenzro_crypto::SignatureContext::Transaction,
                t.hash().as_bytes(),
            )
            .unwrap();
        SignedTransaction::new(t, s.public_key().p256.clone(), sig)
    }

    /// Transactions that can never execute (each sender skips its next nonce)
    /// fill the pool at a price they never pay, and an executable transfer is
    /// then refused.
    #[test]
    fn gapped_transactions_do_not_lock_out_executable_ones() {
        let cfg = ConsensusConfig {
            mempool_max_transactions: 10,
            ..ConsensusConfig::default()
        };
        let m = Mempool::new(Arc::new(cfg));
        m.set_state_reader(Arc::new(Reader)).unwrap();
        for s in 1..=10u8 {
            m.add_transaction(tx(s, 1, 1_000_000_000_000)).unwrap();
        }
        assert_eq!(
            m.select_transactions(100, u64::MAX).len(),
            0,
            "none of them can execute"
        );
        let r = m.add_transaction(tx(200, 0, 1_000_000_000));
        assert!(r.is_ok(), "executable transfer refused: {:?}", r);
    }

    /// A run of transactions past a gap is no better: none of it can run,
    /// so every one of them gives way to an executable transfer, and a
    /// transaction past a gap never displaces an executable one.
    #[test]
    fn a_run_past_a_gap_gives_way_and_never_displaces_an_executable_one() {
        let cfg = ConsensusConfig {
            mempool_max_transactions: 10,
            ..ConsensusConfig::default()
        };
        let m = Mempool::new(Arc::new(cfg));
        m.set_state_reader(Arc::new(Reader)).unwrap();
        for s in 1..=5u8 {
            m.add_transaction(tx(s, 1, 1_000_000_000_000)).unwrap();
            m.add_transaction(tx(s, 2, 1_000_000_000_000)).unwrap();
        }
        for s in 100..110u8 {
            let r = m.add_transaction(tx(s, 0, 1_000_000_000));
            assert!(r.is_ok(), "executable transfer refused: {:?}", r);
        }
        assert_eq!(m.select_transactions(100, u64::MAX).len(), 10);
        let r = m.add_transaction(tx(50, 3, u64::MAX / 100_000_000));
        assert!(
            r.is_err(),
            "a gapped transaction displaced an executable one"
        );
        assert_eq!(m.select_transactions(100, u64::MAX).len(), 10);
    }
}
