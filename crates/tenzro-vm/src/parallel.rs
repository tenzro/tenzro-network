//! Parallel block execution (Block-STM).
//!
//! A block's transactions are executed speculatively on worker threads, each
//! against a view of state that reflects the writes of the transactions
//! before it in block order as far as they are known. Every execution records
//! what it read; a transaction is re-executed when a read turns out to be
//! stale. When no transaction has anything left to execute or validate, each
//! one's last execution read exactly what it would have read had the block run
//! in order, so its effects are the ones sequential execution produces. Those
//! effects are then applied to the node's [`StateAdapter`] in block order.
//!
//! # Scheduling
//!
//! Workers share two cursors, one for executions and one for validations,
//! and always take the lower task first, so validation keeps up with
//! execution:
//!
//! - **Execution** runs one incarnation of a transaction. A read of a value
//!   whose writer is being re-executed (an estimate) stops the incarnation
//!   and parks the transaction until that writer finishes.
//! - **Validation** re-reads everything an incarnation read. If anything
//!   changed, the incarnation is aborted, its writes become estimates so
//!   later readers wait instead of reading them, and the transaction is
//!   executed again.
//! - A finished execution that wrote to a key its previous incarnation did not
//!   write sends the validation cursor back, because later transactions may
//!   have read that key before it was written.
//!
//! # What each execution is
//!
//! Each incarnation is a whole [`crate::ledger::execute_in_block`] call on a
//! speculative [`StateAdapter`]: the base-fee check, the executor, and the
//! value rules of [`crate::ledger::settle_transaction`]. What it writes is
//! therefore already the transaction's net effect, fee included, and a failed
//! transaction's writes are already undone. Applying those effects in order
//! gives the state, fees, supply change and outcome the sequential loop
//! gives.
//!
//! Two keys are handled as commutative totals rather than values, because
//! every transaction touches them and treating them as ordinary keys would
//! make every transaction depend on the one before it:
//!
//! - the fee pool balance: a speculative execution sees the pool as empty, so
//!   what it leaves there is exactly the fee it paid, which is added to the
//!   real pool when its effects are applied;
//! - total supply: each transaction records its own supply change, and a read
//!   of total supply sums the changes of every transaction before it.
//!
//! # What runs in parallel
//!
//! Native (`VmType::Tenzro`) transactions, whose executor reads and writes
//! nothing but the state it is handed. Any other transaction runs alone, in
//! its place in the block, on the node's adapter: the EVM executor needs the
//! node adapter itself.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::ledger::{
    BlockFees, FEE_POOL_ADDRESS, TxOutcome, execute_checked_in_block, execute_in_block,
};
use crate::runtime::{MultiVmRuntime, SignatureChecked};
use crate::state_adapter::{PrefetchKeys, StateAdapter};
use crate::traits::{VmState, VmType};
use crate::types::VmTransaction;

/// How a block is executed in parallel.
#[derive(Debug, Clone)]
pub struct BlockStmConfig {
    /// Worker threads. One means every transaction runs in order on the
    /// calling thread.
    pub workers: usize,
    /// Shortest run of parallel-eligible transactions worth spreading over
    /// workers; shorter runs execute in order.
    pub min_parallel_run: usize,
}

impl Default for BlockStmConfig {
    fn default() -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self {
            workers: cores.clamp(1, 8),
            min_parallel_run: 4,
        }
    }
}

/// One executed transaction of a block.
#[derive(Debug)]
pub struct BlockTx {
    /// What happened to it, exactly as sequential execution reports it.
    pub outcome: TxOutcome,
    /// How many times it was executed beyond the first, because something it
    /// read changed underneath it.
    pub reexecutions: u32,
}

/// Where a speculative [`StateAdapter`] reads anything it has not written.
pub(crate) trait SpeculativeReads: Send + Sync {
    fn balance(&self, address: &[u8]) -> u128;
    fn nonce(&self, address: &[u8]) -> u64;
    fn code(&self, address: &[u8]) -> Option<Vec<u8>>;
    fn storage(&self, address: &[u8], key: &[u8]) -> Option<Vec<u8>>;
    fn total_supply(&self) -> u128;
}

/// Final values a speculative execution wrote.
#[derive(Debug, Clone, Default)]
pub(crate) struct WriteSet {
    pub(crate) balances: Vec<(Vec<u8>, u128)>,
    pub(crate) nonces: Vec<(Vec<u8>, u64)>,
    pub(crate) code: Vec<(Vec<u8>, Vec<u8>)>,
    pub(crate) storage: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    pub(crate) supply_net: i128,
}

/// Executes a block's transactions and applies their effects to `state` in
/// block order, accumulating fees into `fees`.
///
/// The result is identical to running [`execute_in_block`] over the
/// transactions one after another: same state, same supply change, same fee
/// pool, same outcome for every transaction.
pub async fn execute_block(
    runtime: &MultiVmRuntime,
    state: &mut StateAdapter,
    txs: &[VmTransaction],
    base_fee: u128,
    fees: &mut BlockFees,
    config: &BlockStmConfig,
) -> Vec<BlockTx> {
    let mut out = Vec::with_capacity(txs.len());
    let mut i = 0;
    while i < txs.len() {
        let end = txs[i..]
            .iter()
            .position(|tx| !parallel_eligible(tx))
            .map(|p| i + p)
            .unwrap_or(txs.len());

        if end - i >= config.min_parallel_run.max(2) && config.workers > 1 {
            let segment = &txs[i..end];
            state.prefetch(&PrefetchKeys::from_transactions(segment));
            let executed = run_parallel(runtime, state, segment, base_fee, config.workers);
            for tx in executed {
                apply(state, &tx.writes, fees, &tx.fees);
                out.push(BlockTx {
                    outcome: tx.outcome,
                    reexecutions: tx.incarnation,
                });
            }
            i = end;
            continue;
        }

        // A run too short to be worth the threads, or a transaction that
        // must run alone: in order, on the node adapter.
        let stop = if end > i { end } else { i + 1 };
        for tx in &txs[i..stop] {
            let outcome = execute_in_block(runtime, state, tx, base_fee, fees).await;
            out.push(BlockTx {
                outcome,
                reexecutions: 0,
            });
        }
        i = stop;
    }
    out
}

fn parallel_eligible(tx: &VmTransaction) -> bool {
    tx.vm_type == VmType::Tenzro
}

/// Applies one transaction's effects to the node adapter.
fn apply(state: &mut StateAdapter, writes: &WriteSet, fees: &mut BlockFees, tx_fees: &BlockFees) {
    for (addr, value) in &writes.balances {
        if addr.as_slice() == FEE_POOL_ADDRESS {
            // The speculative pool started empty: what is there is this
            // transaction's fee.
            let pool = state.get_balance(addr);
            state.set_balance(addr, pool.saturating_add(*value));
        } else {
            state.set_balance(addr, *value);
        }
    }
    for (addr, nonce) in &writes.nonces {
        state.set_nonce(addr, *nonce);
    }
    for (addr, code) in &writes.code {
        state.set_code(addr, code.clone());
    }
    for (addr, key, value) in &writes.storage {
        state.set_storage(addr, key, value.clone());
    }
    if writes.supply_net > 0 {
        state.record_supply_change(writes.supply_net as u128, 0);
    } else if writes.supply_net < 0 {
        state.record_supply_change(0, writes.supply_net.unsigned_abs());
    }
    fees.merge(tx_fees);
}

/// Runs the scheduler to completion on `workers` threads and returns every
/// transaction's final execution, in block order.
fn run_parallel(
    runtime: &MultiVmRuntime,
    state: &StateAdapter,
    txs: &[VmTransaction],
    base_fee: u128,
    workers: usize,
) -> Vec<Executed> {
    let checked = check_signatures(runtime, txs, workers);
    let block = BlockRun {
        runtime,
        txs,
        checked,
        base_fee,
        base: Arc::new(state.shared_reader()),
        mvcc: Arc::new(Mvcc::default()),
        scheduler: Scheduler::new(txs.len()),
        slots: (0..txs.len()).map(|_| Mutex::new(None)).collect(),
    };

    let run = || {
        std::thread::scope(|s| {
            for _ in 0..workers.min(txs.len()) {
                s.spawn(|| block.worker());
            }
        })
    };
    // The workers are blocking threads; on a multi-threaded runtime the
    // calling task hands its worker thread back while it waits for them.
    match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(run),
        _ => run(),
    }

    block
        .slots
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .expect("every transaction has executed when the scheduler is done")
        })
        .collect()
}

/// Checks every transaction's signature across `workers` threads. The check
/// reads no state and is the most expensive part of executing a transfer, so
/// it runs once per transaction here rather than inside every speculative
/// execution. A transaction whose signature fails keeps `None` and executes
/// through the full path, which rejects it exactly as in-order execution does.
fn check_signatures(
    runtime: &MultiVmRuntime,
    txs: &[VmTransaction],
    workers: usize,
) -> Vec<Option<SignatureChecked>> {
    let chunk = txs.len().div_ceil(workers.max(1)).max(1);
    let mut checked: Vec<Option<SignatureChecked>> = vec![None; txs.len()];
    std::thread::scope(|s| {
        for (txs, out) in txs.chunks(chunk).zip(checked.chunks_mut(chunk)) {
            s.spawn(move || {
                for (tx, slot) in txs.iter().zip(out.iter_mut()) {
                    *slot = runtime.check_signature(tx).ok();
                }
            });
        }
    });
    checked
}

// ---------------------------------------------------------------------------
// Multi-version memory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Balance(Vec<u8>),
    Nonce(Vec<u8>),
    Code(Vec<u8>),
    Storage(Vec<u8>, Vec<u8>),
    /// Total supply. Entries hold each transaction's own supply change.
    Supply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Val {
    Balance(u128),
    Nonce(u64),
    Bytes(Option<Vec<u8>>),
    /// For [`Key::Supply`]: the sum of the supply changes before the reader.
    Supply(i128),
}

#[derive(Debug, Clone)]
enum Entry {
    Written(Val),
    /// Written by an incarnation that has been aborted; its next incarnation
    /// will probably write here again, so a reader waits for it.
    Estimate,
}

/// Every transaction's latest write to every key, by transaction index.
#[derive(Default)]
struct Mvcc {
    data: DashMap<Key, BTreeMap<usize, Entry>>,
}

impl Mvcc {
    /// The value transaction `idx` sees at `key` from the transactions before
    /// it: `Ok(None)` when none of them wrote it, `Err(j)` when the nearest
    /// writer `j` is being re-executed.
    fn read(&self, idx: usize, key: &Key) -> Result<Option<Val>, usize> {
        let Some(versions) = self.data.get(key) else {
            return Ok(None);
        };
        if *key == Key::Supply {
            let mut sum: i128 = 0;
            for (j, entry) in versions.range(..idx) {
                match entry {
                    Entry::Written(Val::Supply(d)) => sum = sum.saturating_add(*d),
                    Entry::Written(_) => {}
                    Entry::Estimate => return Err(*j),
                }
            }
            return Ok(Some(Val::Supply(sum)));
        }
        match versions.range(..idx).next_back() {
            None => Ok(None),
            Some((_, Entry::Written(v))) => Ok(Some(v.clone())),
            Some((j, Entry::Estimate)) => Err(*j),
        }
    }

    fn write(&self, idx: usize, key: Key, val: Val) {
        self.data
            .entry(key)
            .or_default()
            .insert(idx, Entry::Written(val));
    }

    fn remove(&self, idx: usize, key: &Key) {
        if let Some(mut versions) = self.data.get_mut(key) {
            versions.remove(&idx);
        }
    }

    fn mark_estimate(&self, idx: usize, key: &Key) {
        if let Some(mut versions) = self.data.get_mut(key) {
            versions.insert(idx, Entry::Estimate);
        }
    }
}

/// The keys and values a write set puts into multi-version memory. The fee
/// pool is left out: it is a total, not a value later transactions read.
fn mvcc_writes(writes: &WriteSet) -> Vec<(Key, Val)> {
    let mut out = Vec::with_capacity(
        writes.balances.len() + writes.nonces.len() + writes.code.len() + writes.storage.len() + 1,
    );
    for (a, v) in &writes.balances {
        if a.as_slice() != FEE_POOL_ADDRESS {
            out.push((Key::Balance(a.clone()), Val::Balance(*v)));
        }
    }
    for (a, n) in &writes.nonces {
        out.push((Key::Nonce(a.clone()), Val::Nonce(*n)));
    }
    for (a, c) in &writes.code {
        out.push((Key::Code(a.clone()), Val::Bytes(Some(c.clone()))));
    }
    for (a, k, v) in &writes.storage {
        out.push((
            Key::Storage(a.clone(), k.clone()),
            Val::Bytes(Some(v.clone())),
        ));
    }
    if writes.supply_net != 0 {
        out.push((Key::Supply, Val::Supply(writes.supply_net)));
    }
    out
}

/// Reads for one incarnation of transaction `idx`: multi-version memory
/// first, then the state the block started from. Records what it returned.
struct IncarnationReads {
    idx: usize,
    mvcc: Arc<Mvcc>,
    base: Arc<StateAdapter>,
    reads: Mutex<Vec<(Key, Val)>>,
    blocked_on: Mutex<Option<usize>>,
}

impl IncarnationReads {
    fn resolve(&self, key: Key) -> Option<Val> {
        match resolve(&self.mvcc, &self.base, self.idx, &key) {
            Ok(v) => {
                self.reads.lock().push((key, v.clone()));
                Some(v)
            }
            Err(j) => {
                self.blocked_on.lock().get_or_insert(j);
                None
            }
        }
    }
}

/// What transaction `idx` sees at `key`, or the transaction it must wait for.
fn resolve(mvcc: &Mvcc, base: &StateAdapter, idx: usize, key: &Key) -> Result<Val, usize> {
    if let Some(v) = mvcc.read(idx, key)? {
        return Ok(match (key, v) {
            (Key::Supply, Val::Supply(sum)) => {
                Val::Supply((base.total_supply() as i128).saturating_add(sum))
            }
            (_, v) => v,
        });
    }
    Ok(match key {
        Key::Balance(a) => Val::Balance(base.get_balance(a)),
        Key::Nonce(a) => Val::Nonce(base.get_nonce(a)),
        Key::Code(a) => Val::Bytes(base.get_code(a)),
        Key::Storage(a, k) => Val::Bytes(base.get_storage(a, k)),
        Key::Supply => Val::Supply(base.total_supply() as i128),
    })
}

impl SpeculativeReads for IncarnationReads {
    fn balance(&self, address: &[u8]) -> u128 {
        if address == FEE_POOL_ADDRESS {
            return 0;
        }
        match self.resolve(Key::Balance(address.to_vec())) {
            Some(Val::Balance(b)) => b,
            _ => 0,
        }
    }

    fn nonce(&self, address: &[u8]) -> u64 {
        match self.resolve(Key::Nonce(address.to_vec())) {
            Some(Val::Nonce(n)) => n,
            _ => 0,
        }
    }

    fn code(&self, address: &[u8]) -> Option<Vec<u8>> {
        match self.resolve(Key::Code(address.to_vec())) {
            Some(Val::Bytes(c)) => c,
            _ => None,
        }
    }

    fn storage(&self, address: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        match self.resolve(Key::Storage(address.to_vec(), key.to_vec())) {
            Some(Val::Bytes(v)) => v,
            _ => None,
        }
    }

    fn total_supply(&self) -> u128 {
        match self.resolve(Key::Supply) {
            Some(Val::Supply(s)) => s.max(0) as u128,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    ReadyToExecute,
    Executing,
    Executed,
    Aborting,
}

#[derive(Debug, Clone, Copy)]
enum Task {
    Execute(usize, u32),
    Validate(usize, u32),
}

/// Hands out execution and validation tasks so that every transaction ends
/// with an execution whose reads are current.
struct Scheduler {
    n: usize,
    execution_idx: AtomicUsize,
    validation_idx: AtomicUsize,
    decrease_cnt: AtomicUsize,
    num_active_tasks: AtomicUsize,
    done_marker: AtomicBool,
    status: Vec<Mutex<(u32, Status)>>,
    dependents: Vec<Mutex<Vec<usize>>>,
}

impl Scheduler {
    fn new(n: usize) -> Self {
        Self {
            n,
            execution_idx: AtomicUsize::new(0),
            validation_idx: AtomicUsize::new(0),
            decrease_cnt: AtomicUsize::new(0),
            num_active_tasks: AtomicUsize::new(0),
            done_marker: AtomicBool::new(false),
            status: (0..n)
                .map(|_| Mutex::new((0, Status::ReadyToExecute)))
                .collect(),
            dependents: (0..n).map(|_| Mutex::new(Vec::new())).collect(),
        }
    }

    fn done(&self) -> bool {
        self.done_marker.load(Ordering::Acquire)
    }

    fn decrease_execution_idx(&self, target: usize) {
        self.execution_idx.fetch_min(target, Ordering::SeqCst);
        self.decrease_cnt.fetch_add(1, Ordering::SeqCst);
    }

    fn decrease_validation_idx(&self, target: usize) {
        self.validation_idx.fetch_min(target, Ordering::SeqCst);
        self.decrease_cnt.fetch_add(1, Ordering::SeqCst);
    }

    fn check_done(&self) {
        let observed = self.decrease_cnt.load(Ordering::SeqCst);
        let exec = self.execution_idx.load(Ordering::SeqCst);
        let val = self.validation_idx.load(Ordering::SeqCst);
        if exec.min(val) >= self.n
            && self.num_active_tasks.load(Ordering::SeqCst) == 0
            && observed == self.decrease_cnt.load(Ordering::SeqCst)
        {
            self.done_marker.store(true, Ordering::Release);
        }
    }

    /// Claims transaction `idx` for execution if it is ready. Does not touch
    /// the active-task count; callers do.
    fn try_incarnate(&self, idx: usize) -> Option<(usize, u32)> {
        if idx >= self.n {
            return None;
        }
        let mut s = self.status[idx].lock();
        if s.1 == Status::ReadyToExecute {
            s.1 = Status::Executing;
            Some((idx, s.0))
        } else {
            None
        }
    }

    fn next_version_to_execute(&self) -> Option<(usize, u32)> {
        if self.execution_idx.load(Ordering::SeqCst) >= self.n {
            self.check_done();
            return None;
        }
        self.num_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx = self.execution_idx.fetch_add(1, Ordering::SeqCst);
        let claimed = self.try_incarnate(idx);
        if claimed.is_none() {
            self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        }
        claimed
    }

    fn next_version_to_validate(&self) -> Option<(usize, u32)> {
        if self.validation_idx.load(Ordering::SeqCst) >= self.n {
            self.check_done();
            return None;
        }
        self.num_active_tasks.fetch_add(1, Ordering::SeqCst);
        let idx = self.validation_idx.fetch_add(1, Ordering::SeqCst);
        if idx < self.n {
            let s = self.status[idx].lock();
            if s.1 == Status::Executed {
                return Some((idx, s.0));
            }
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn next_task(&self) -> Option<Task> {
        if self.validation_idx.load(Ordering::SeqCst) < self.execution_idx.load(Ordering::SeqCst) {
            self.next_version_to_validate()
                .map(|(i, inc)| Task::Validate(i, inc))
        } else {
            self.next_version_to_execute()
                .map(|(i, inc)| Task::Execute(i, inc))
        }
    }

    /// Parks `idx` until `blocking` finishes executing. Returns false when
    /// `blocking` already has, in which case `idx` should simply run again.
    fn add_dependency(&self, idx: usize, blocking: usize) -> bool {
        let mut deps = self.dependents[blocking].lock();
        if self.status[blocking].lock().1 == Status::Executed {
            return false;
        }
        self.status[idx].lock().1 = Status::Aborting;
        deps.push(idx);
        drop(deps);
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        true
    }

    fn set_ready_status(&self, idx: usize) {
        let mut s = self.status[idx].lock();
        *s = (s.0 + 1, Status::ReadyToExecute);
    }

    fn finish_execution(&self, idx: usize, incarnation: u32, wrote_new_key: bool) -> Option<Task> {
        *self.status[idx].lock() = (incarnation, Status::Executed);
        let deps = std::mem::take(&mut *self.dependents[idx].lock());
        if let Some(min) = deps.iter().copied().min() {
            for d in &deps {
                self.set_ready_status(*d);
            }
            self.decrease_execution_idx(min);
        }
        if self.validation_idx.load(Ordering::SeqCst) > idx {
            if wrote_new_key {
                self.decrease_validation_idx(idx);
            } else {
                return Some(Task::Validate(idx, incarnation));
            }
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }

    fn try_validation_abort(&self, idx: usize, incarnation: u32) -> bool {
        let mut s = self.status[idx].lock();
        if *s == (incarnation, Status::Executed) {
            s.1 = Status::Aborting;
            true
        } else {
            false
        }
    }

    fn finish_validation(&self, idx: usize, aborted: bool) -> Option<Task> {
        if aborted {
            self.set_ready_status(idx);
            self.decrease_validation_idx(idx + 1);
            if self.execution_idx.load(Ordering::SeqCst) > idx
                && let Some((i, inc)) = self.try_incarnate(idx)
            {
                return Some(Task::Execute(i, inc));
            }
        }
        self.num_active_tasks.fetch_sub(1, Ordering::SeqCst);
        None
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// A finished incarnation of one transaction.
struct Executed {
    incarnation: u32,
    reads: Vec<(Key, Val)>,
    written: HashSet<Key>,
    writes: WriteSet,
    fees: BlockFees,
    outcome: TxOutcome,
}

enum Attempt {
    Done(Executed),
    Blocked(usize),
}

struct BlockRun<'a> {
    runtime: &'a MultiVmRuntime,
    txs: &'a [VmTransaction],
    checked: Vec<Option<SignatureChecked>>,
    base_fee: u128,
    base: Arc<StateAdapter>,
    mvcc: Arc<Mvcc>,
    scheduler: Scheduler,
    slots: Vec<Mutex<Option<Executed>>>,
}

impl BlockRun<'_> {
    fn worker(&self) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a worker thread can build a current-thread runtime");
        let mut task: Option<Task> = None;
        while !self.scheduler.done() {
            task = match task.take() {
                Some(Task::Execute(i, inc)) => self.execute(&rt, i, inc),
                Some(Task::Validate(i, inc)) => self.validate(i, inc),
                None => {
                    let next = self.scheduler.next_task();
                    if next.is_none() {
                        std::thread::yield_now();
                    }
                    next
                }
            };
        }
    }

    fn attempt(&self, rt: &tokio::runtime::Runtime, idx: usize, incarnation: u32) -> Attempt {
        let reads = Arc::new(IncarnationReads {
            idx,
            mvcc: Arc::clone(&self.mvcc),
            base: Arc::clone(&self.base),
            reads: Mutex::new(Vec::new()),
            blocked_on: Mutex::new(None),
        });
        let mut spec = StateAdapter::speculative(reads.clone());
        let mut fees = BlockFees::default();
        let tx = &self.txs[idx];
        let outcome = rt.block_on(async {
            match self.checked[idx] {
                Some(checked) => {
                    execute_checked_in_block(
                        self.runtime,
                        &mut spec,
                        tx,
                        self.base_fee,
                        &mut fees,
                        checked,
                    )
                    .await
                }
                None => {
                    execute_in_block(self.runtime, &mut spec, tx, self.base_fee, &mut fees).await
                }
            }
        });
        if let Some(j) = *reads.blocked_on.lock() {
            return Attempt::Blocked(j);
        }
        let writes = spec.speculative_effects();
        let written = mvcc_writes(&writes).into_iter().map(|(k, _)| k).collect();
        Attempt::Done(Executed {
            incarnation,
            reads: std::mem::take(&mut *reads.reads.lock()),
            written,
            writes,
            fees,
            outcome,
        })
    }

    fn execute(&self, rt: &tokio::runtime::Runtime, idx: usize, incarnation: u32) -> Option<Task> {
        loop {
            match self.attempt(rt, idx, incarnation) {
                Attempt::Blocked(j) => {
                    if self.scheduler.add_dependency(idx, j) {
                        return None;
                    }
                }
                Attempt::Done(executed) => {
                    let wrote_new_key = self.record(idx, executed);
                    return self
                        .scheduler
                        .finish_execution(idx, incarnation, wrote_new_key);
                }
            }
        }
    }

    /// Publishes an incarnation's writes and drops the previous incarnation's
    /// writes to keys this one did not write. Returns whether it wrote a key
    /// the previous incarnation did not.
    fn record(&self, idx: usize, executed: Executed) -> bool {
        let mut slot = self.slots[idx].lock();
        let previous: HashSet<Key> = slot.as_ref().map(|e| e.written.clone()).unwrap_or_default();
        for (k, v) in mvcc_writes(&executed.writes) {
            self.mvcc.write(idx, k, v);
        }
        for k in previous.difference(&executed.written) {
            self.mvcc.remove(idx, k);
        }
        let wrote_new_key = !executed.written.is_subset(&previous);
        *slot = Some(executed);
        wrote_new_key
    }

    fn validate(&self, idx: usize, incarnation: u32) -> Option<Task> {
        let valid = {
            let slot = self.slots[idx].lock();
            let executed = slot.as_ref().expect("a validated transaction has executed");
            executed
                .reads
                .iter()
                .all(|(key, seen)| resolve(&self.mvcc, &self.base, idx, key).as_ref() == Ok(seen))
        };
        let aborted = !valid && self.scheduler.try_validation_abort(idx, incarnation);
        if aborted && let Some(executed) = self.slots[idx].lock().as_ref() {
            for k in &executed.written {
                self.mvcc.mark_estimate(idx, k);
            }
        }
        self.scheduler.finish_validation(idx, aborted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VmConfig;

    const BASE_FEE: u128 = 1_000_000_000;
    const ONE: u128 = 1_000_000_000_000_000_000;

    fn account(i: u8) -> Vec<u8> {
        let mut a = vec![0x11u8; 20];
        a[19] = i;
        a
    }

    fn transfer(from: u8, to: u8, value: u128, nonce: u64, gas_price: u128) -> VmTransaction {
        VmTransaction::new(
            account(from),
            Some(account(to)),
            value,
            vec![],
            21_000,
            gas_price,
            nonce,
            VmType::Tenzro,
            VmConfig::default().chain_id,
        )
    }

    fn funded(accounts: u8) -> StateAdapter {
        let mut s = StateAdapter::new();
        for i in 0..accounts {
            s.set_balance(&account(i), 100 * ONE);
        }
        // The funding is a mint in the same pending block, so the block's
        // conservation check sees it matched by supply.
        s.record_supply_change(accounts as u128 * 100 * ONE, 0);
        s
    }

    /// Small deterministic generator, so a failing block can be replayed.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// A block over `accounts` accounts with heavy overlap: most transfers
    /// touch the first two accounts, some reuse or skip nonces, some
    /// overdraw, some send to themselves, some offer less than the base fee.
    fn random_block(rng: &mut Rng, accounts: u8, n: usize) -> Vec<VmTransaction> {
        let mut nonces = vec![0u64; accounts as usize];
        (0..n)
            .map(|_| {
                let r = rng.next();
                let from = if r.is_multiple_of(3) {
                    (r >> 8) as u8 % 2
                } else {
                    (r >> 8) as u8 % accounts
                };
                let to = if r.is_multiple_of(4) {
                    from
                } else {
                    (r >> 16) as u8 % 2
                };
                let value = match (r >> 24) % 5 {
                    0 => 150 * ONE,
                    _ => ((r >> 32) % 20 + 1) as u128 * ONE,
                };
                let gas_price = if (r >> 40).is_multiple_of(11) {
                    BASE_FEE - 1
                } else {
                    BASE_FEE + (r >> 44) as u128 % 3
                };
                let nonce = match (r >> 48) % 13 {
                    0 => nonces[from as usize] + 1,
                    _ => nonces[from as usize],
                };
                nonces[from as usize] = nonces[from as usize].max(nonce) + 1;
                transfer(from, to, value, nonce, gas_price)
            })
            .collect()
    }

    fn describe(outcome: &TxOutcome) -> String {
        match outcome {
            TxOutcome::Applied { result, fee } => {
                format!(
                    "applied gas={} fee={} out={:?}",
                    result.gas_used, fee, result.output
                )
            }
            TxOutcome::Reverted {
                result,
                fee,
                reason,
            } => {
                format!("reverted gas={} fee={} {}", result.gas_used, fee, reason)
            }
            TxOutcome::Rejected(e) => format!("rejected {e}"),
        }
    }

    async fn sequential(
        runtime: &MultiVmRuntime,
        state: &mut StateAdapter,
        txs: &[VmTransaction],
        fees: &mut BlockFees,
    ) -> Vec<String> {
        let mut out = Vec::new();
        for tx in txs {
            out.push(describe(
                &execute_in_block(runtime, state, tx, BASE_FEE, fees).await,
            ));
        }
        out
    }

    fn snapshot(state: &StateAdapter, accounts: u8) -> Vec<(u128, u64)> {
        let mut v: Vec<(u128, u64)> = (0..accounts)
            .map(|i| (state.get_balance(&account(i)), state.get_nonce(&account(i))))
            .collect();
        v.push((state.get_balance(&FEE_POOL_ADDRESS), 0));
        v
    }

    /// Random conflicting blocks give exactly the sequential result: every
    /// balance and nonce, the fee pool, the supply change, the fees
    /// collected, and each transaction's outcome.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parallel_blocks_equal_sequential_blocks() {
        let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let accounts = 6u8;
        for seed in 1..=40u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
            let txs = random_block(&mut rng, accounts, 64);

            let mut seq_state = funded(accounts);
            let mut seq_fees = BlockFees::default();
            let seq_out = sequential(&runtime, &mut seq_state, &txs, &mut seq_fees).await;

            for workers in [2usize, 4, 8] {
                let mut par_state = funded(accounts);
                let mut par_fees = BlockFees::default();
                let config = BlockStmConfig {
                    workers,
                    min_parallel_run: 2,
                };
                let par = execute_block(
                    &runtime,
                    &mut par_state,
                    &txs,
                    BASE_FEE,
                    &mut par_fees,
                    &config,
                )
                .await;
                let par_out: Vec<String> = par.iter().map(|t| describe(&t.outcome)).collect();

                assert_eq!(
                    par_out, seq_out,
                    "outcomes differ, seed {seed} workers {workers}"
                );
                assert_eq!(
                    snapshot(&par_state, accounts),
                    snapshot(&seq_state, accounts),
                    "state differs, seed {seed} workers {workers}"
                );
                assert_eq!(par_fees, seq_fees, "fees differ, seed {seed}");
                assert_eq!(
                    par_state.pending_block_delta(),
                    seq_state.pending_block_delta(),
                    "value accounting differs, seed {seed}"
                );
                crate::ledger::verify_block(&par_state).unwrap();
            }
        }
    }

    /// The same equivalence on a runtime with a single thread, where the
    /// workers cannot hand the calling thread back.
    #[tokio::test]
    async fn parallel_equals_sequential_on_a_current_thread_runtime() {
        let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut rng = Rng(0xdead_beef);
        let txs = random_block(&mut rng, 4, 48);

        let mut seq_state = funded(4);
        let mut seq_fees = BlockFees::default();
        let seq_out = sequential(&runtime, &mut seq_state, &txs, &mut seq_fees).await;

        let mut par_state = funded(4);
        let mut par_fees = BlockFees::default();
        let config = BlockStmConfig {
            workers: 4,
            min_parallel_run: 2,
        };
        let par = execute_block(
            &runtime,
            &mut par_state,
            &txs,
            BASE_FEE,
            &mut par_fees,
            &config,
        )
        .await;
        let par_out: Vec<String> = par.iter().map(|t| describe(&t.outcome)).collect();
        assert_eq!(par_out, seq_out);
        assert_eq!(snapshot(&par_state, 4), snapshot(&seq_state, 4));
        assert_eq!(par_fees, seq_fees);
    }

    /// A read made before an earlier transaction wrote the same key fails
    /// validation, and succeeds once re-read.
    #[test]
    fn a_read_overtaken_by_an_earlier_write_fails_validation() {
        let mut base = StateAdapter::new();
        let hot = account(1);
        base.set_balance(&hot, 10);
        let base = Arc::new(base);
        let mvcc = Mvcc::default();

        // Transaction 1 reads the hot balance while nothing before it has
        // written it.
        let seen = resolve(&mvcc, &base, 1, &Key::Balance(hot.clone())).unwrap();
        assert_eq!(seen, Val::Balance(10));

        // Transaction 0 then writes it.
        mvcc.write(0, Key::Balance(hot.clone()), Val::Balance(7));
        let now = resolve(&mvcc, &base, 1, &Key::Balance(hot.clone())).unwrap();
        assert_ne!(now, seen, "the stale read must not validate");
        assert_eq!(now, Val::Balance(7));

        // A later transaction's write is invisible to transaction 1.
        mvcc.write(2, Key::Balance(hot.clone()), Val::Balance(99));
        assert_eq!(
            resolve(&mvcc, &base, 1, &Key::Balance(hot.clone())).unwrap(),
            Val::Balance(7)
        );

        // An aborted writer makes readers wait on it.
        mvcc.mark_estimate(0, &Key::Balance(hot.clone()));
        assert_eq!(resolve(&mvcc, &base, 1, &Key::Balance(hot)), Err(0));
    }

    /// Supply reads sum the changes of every earlier transaction.
    #[test]
    fn a_supply_read_sums_earlier_changes() {
        let base = StateAdapter::new();
        base.record_supply_change(1_000, 0);
        let base = Arc::new(base);
        let mvcc = Mvcc::default();
        mvcc.write(0, Key::Supply, Val::Supply(-30));
        mvcc.write(2, Key::Supply, Val::Supply(-5));
        mvcc.write(4, Key::Supply, Val::Supply(-7));
        assert_eq!(resolve(&mvcc, &base, 3, &Key::Supply), Ok(Val::Supply(965)));
    }

    /// Every transaction sends to one account and from a few shared senders,
    /// so speculative executions collide; the result still equals sequential
    /// and the collisions show up as re-executions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn conflicting_block_reexecutes_and_matches_sequential() {
        let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut nonces = [0u64; 4];
        let txs: Vec<VmTransaction> = (0..96)
            .map(|i| {
                let from = (i % 4) as u8;
                let tx = transfer(from, 5, ONE, nonces[from as usize], BASE_FEE);
                nonces[from as usize] += 1;
                tx
            })
            .collect();

        let mut seq_state = funded(6);
        let mut seq_fees = BlockFees::default();
        let seq_out = sequential(&runtime, &mut seq_state, &txs, &mut seq_fees).await;

        let mut par_state = funded(6);
        let mut par_fees = BlockFees::default();
        let config = BlockStmConfig {
            workers: 8,
            min_parallel_run: 2,
        };
        let par = execute_block(
            &runtime,
            &mut par_state,
            &txs,
            BASE_FEE,
            &mut par_fees,
            &config,
        )
        .await;
        let par_out: Vec<String> = par.iter().map(|t| describe(&t.outcome)).collect();

        assert_eq!(par_out, seq_out);
        assert_eq!(snapshot(&par_state, 6), snapshot(&seq_state, 6));
        assert_eq!(par_fees, seq_fees);
        assert!(
            par.iter()
                .all(|t| matches!(t.outcome, TxOutcome::Applied { .. }))
        );
        assert_eq!(par_state.get_balance(&account(5)), 196 * ONE);
    }

    /// Blocks of signed transactions, where the signature is checked once per
    /// transaction ahead of the speculative executions: a hot recipient forces
    /// re-executions, and a forged signature and a signature stripped of the
    /// enrolled ML-DSA-65 leg must be rejected exactly as in-order execution rejects them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::needless_range_loop)] // the loop index also derives the account address
    async fn signed_blocks_equal_sequential_blocks() {
        use tenzro_crypto::composite::testing::TestHybridSigner;
        use tenzro_crypto::composite::{HybridSigner, SignatureContext};

        let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let signers: Vec<TestHybridSigner> = (0..4)
            .map(|i| TestHybridSigner::hybrid(i as u8 + 1))
            .collect();
        let address = |i: usize| signers[i].address().as_bytes().to_vec();

        let mut nonces = [0u64; 4];
        let txs: Vec<VmTransaction> = (0..32)
            .map(|n| {
                let i = n % 4;
                let mut tx = transfer(0, 5, ONE, nonces[i], BASE_FEE);
                tx.from = address(i);
                let mut digest = [0u8; 32];
                digest[..8].copy_from_slice(&(n as u64).to_le_bytes());
                let mut sig = signers[i]
                    .sign(SignatureContext::Transaction, &digest)
                    .unwrap();
                if n == 21 {
                    // The P-256 leg alone, for an account with ML-DSA-65 enrolled.
                    sig.pq = None;
                }
                tx.signature = Some(sig);
                tx.public_key = Some(signers[i].public_key().p256.clone());
                tx.signing_digest = Some(digest.to_vec());
                if n == 13 {
                    tx.signing_digest = Some(vec![0xee; 32]);
                }
                if n != 13 && n != 21 {
                    nonces[i] += 1;
                }
                tx
            })
            .collect();

        let fund = || {
            let mut s = StateAdapter::new();
            for i in 0..4 {
                s.set_balance(&address(i), 100 * ONE);
                let pk = signers[i].public_key();
                crate::account_keys::set_enrolled_pq_key(
                    &mut s,
                    &pk.p256,
                    pk.pq.clone().unwrap(),
                    &mut Vec::new(),
                );
            }
            s.record_supply_change(400 * ONE, 0);
            s
        };

        let mut seq_state = fund();
        let mut seq_fees = BlockFees::default();
        let seq_out = sequential(&runtime, &mut seq_state, &txs, &mut seq_fees).await;
        assert!(seq_out[13].starts_with("rejected"), "{}", seq_out[13]);
        assert!(seq_out[21].starts_with("rejected"), "{}", seq_out[21]);

        let mut par_state = fund();
        let mut par_fees = BlockFees::default();
        let config = BlockStmConfig {
            workers: 8,
            min_parallel_run: 2,
        };
        let par = execute_block(
            &runtime,
            &mut par_state,
            &txs,
            BASE_FEE,
            &mut par_fees,
            &config,
        )
        .await;
        let par_out: Vec<String> = par.iter().map(|t| describe(&t.outcome)).collect();
        assert_eq!(par_out, seq_out);
        let balances = |s: &StateAdapter| -> Vec<(u128, u64)> {
            (0..4)
                .map(|i| (s.get_balance(&address(i)), s.get_nonce(&address(i))))
                .chain([
                    (s.get_balance(&account(5)), 0),
                    (s.get_balance(&FEE_POOL_ADDRESS), 0),
                ])
                .collect()
        };
        assert_eq!(balances(&par_state), balances(&seq_state));
        assert_eq!(par_fees, seq_fees);
        crate::ledger::verify_block(&par_state).unwrap();
    }
}
