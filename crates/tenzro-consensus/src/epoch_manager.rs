//! Epoch management for validator set transitions

use crate::error::{ConsensusError, Result};
use crate::validator::{ValidatorInfo, ValidatorSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::primitives::{Address, BlockHeight, Timestamp};

/// Persistence backend for epoch state.
///
/// Implemented by the node layer (over RocksDB CF_METADATA) and injected
/// into `EpochManager::with_store`. The trait is intentionally minimal —
/// it stores serialized `Epoch` records keyed by epoch number. We avoid a
/// hard dependency on `tenzro-storage` from `tenzro-consensus`, matching
/// the pattern used by `tenzro-vm::StateAdapter` and
/// `tenzro-token::RocksDbBackend`.
///
/// Implementations must be thread-safe (`Send + Sync`) — write-through
/// happens from inside `transition_epoch`'s critical section, and hydration
/// reads happen from `with_store`.
pub trait EpochStateStore: Send + Sync {
    /// Persists the bincode-serialized `Epoch` under `epoch_number`.
    ///
    /// Called once per epoch transition (write-through). Errors are logged
    /// but do not roll back the in-memory transition — durability is
    /// best-effort; the next leader's commit-QC will re-anchor the chain.
    fn put_epoch(&self, epoch_number: u64, bytes: Vec<u8>) -> Result<()>;

    /// Loads all persisted epochs in ascending order (epoch 0 first).
    ///
    /// Called once from `EpochManager::with_store` to hydrate
    /// `current_epoch` + `epoch_history`. Returns an empty vec for a
    /// fresh database.
    fn load_all_epochs(&self) -> Result<Vec<Vec<u8>>>;

    /// One persisted epoch by number, `None` when it is not stored.
    fn load_epoch(&self, epoch_number: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.load_all_epochs()?.into_iter().find(|bytes| {
            bincode::deserialize::<Epoch>(bytes).is_ok_and(|e| e.number == epoch_number)
        }))
    }

    /// Visits every persisted epoch in ascending order, one record at a
    /// time, so a caller after a few of them holds no more than those.
    fn for_each_epoch(&self, f: &mut dyn FnMut(&[u8])) -> Result<()> {
        for bytes in self.load_all_epochs()? {
            f(&bytes);
        }
        Ok(())
    }
}

/// Epochs read from the store at start: the current one and the in-memory
/// history before it.
const HYDRATED_EPOCHS: usize = 11;

/// Epoch information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Epoch {
    /// Epoch number
    pub number: u64,

    /// Start height of the epoch
    pub start_height: BlockHeight,

    /// End height of the epoch (exclusive)
    pub end_height: BlockHeight,

    /// Validator set for this epoch
    pub validator_set: ValidatorSet,

    /// Epoch start timestamp
    pub start_time: Timestamp,
}

impl Epoch {
    /// Creates a new epoch
    pub fn new(
        number: u64,
        start_height: BlockHeight,
        end_height: BlockHeight,
        validator_set: ValidatorSet,
    ) -> Self {
        Self {
            number,
            start_height,
            end_height,
            validator_set,
            start_time: Timestamp::now(),
        }
    }

    /// Checks if the given height is in this epoch
    pub fn contains(&self, height: BlockHeight) -> bool {
        height >= self.start_height && height < self.end_height
    }

    /// Returns the duration of the epoch in blocks
    pub fn duration(&self) -> u64 {
        self.end_height.as_u64() - self.start_height.as_u64()
    }
}

/// Longest an epoch may run in wall-clock terms before a transition is due,
/// measured between block timestamps.
///
/// The height schedule alone cannot bound an epoch on a chain that suppresses
/// empty blocks: height advances only when there is work, so a quiet network
/// sits inside one epoch indefinitely and its validator set can never rotate.
/// This is the second bound. Whichever comes first ends the epoch.
pub const MAX_EPOCH_DURATION_MS: u64 = 3_600_000;

/// Manages epoch transitions and validator set updates
///
/// # Atomicity Guarantees
///
/// - `current_epoch` is protected by RwLock, ensuring atomic reads and writes
/// - Epoch transitions use a write lock that prevents any concurrent access
/// - All state updates (history, pending validators, current epoch) happen
///   within the critical section to prevent split-brain scenarios
/// - The validator set change becomes visible atomically when the write lock
///   is released
pub struct EpochManager {
    /// Current epoch (protected by RwLock for atomic access)
    current_epoch: Arc<RwLock<Epoch>>,

    /// Epoch duration in blocks
    epoch_duration: u64,

    /// Pending validator additions/updates for next epoch.
    ///
    /// Each entry is upserted into the next epoch's validator set on
    /// transition: a matching address is replaced; new addresses are added.
    /// Any added voting power (entrants and stake increases) is subject to
    /// the per-transition churn budget — see `transition_epoch`. The part
    /// beyond the budget stays queued (FIFO) and applies at subsequent
    /// transitions.
    pending_validators: Arc<RwLock<Vec<ValidatorInfo>>>,

    /// Pending validator removals for next epoch (e.g. unstake or slashing).
    ///
    /// On transition, addresses in this list are dropped from the next
    /// epoch's validator set before pending_validators is upserted in,
    /// subject to the per-transition churn budget — see `transition_epoch`.
    /// Entries beyond the budget stay queued (FIFO) and apply at
    /// subsequent transitions.
    pending_removals: Arc<RwLock<Vec<tenzro_types::primitives::Address>>>,

    /// History of past epochs (protected by RwLock)
    epoch_history: Arc<RwLock<Vec<Epoch>>>,

    /// Maximum epochs to keep in-memory.
    ///
    /// Persistent store (if attached) retains all epochs unconditionally —
    /// in-memory trim is a working-set bound, not a retention policy. A node
    /// catching up across an epoch boundary outside the in-memory window
    /// falls back to the store via `get_epoch_for_height` / `get_epoch`.
    max_history: usize,

    /// Optional persistence backend.
    ///
    /// Set via `with_store` (wired in node startup). When present:
    /// - construction hydrates `current_epoch` + `epoch_history` from disk;
    /// - every `transition_epoch` writes the new epoch through.
    ///
    /// When absent (tests, ephemeral nodes), `EpochManager` behaves
    /// identically to the pre-persistence implementation.
    store: Option<Arc<dyn EpochStateStore>>,
}

impl EpochManager {
    /// Creates a new epoch manager (ephemeral — no persistence).
    ///
    /// Used by tests and ephemeral nodes. Production nodes should use
    /// `with_store` so that the validator-set history survives restarts —
    /// without that, a node catching up across an epoch boundary cannot
    /// verify historical commit-QCs and gets stuck in `InvalidHeight`
    /// rejection (a liveness stall).
    pub fn new(initial_validators: Vec<ValidatorInfo>, epoch_duration: u64) -> Result<Self> {
        let validator_set = ValidatorSet::new(0, initial_validators)?;

        let current_epoch = Epoch::new(
            0,
            BlockHeight::from(0),
            BlockHeight::from(epoch_duration),
            validator_set,
        );

        Ok(Self {
            current_epoch: Arc::new(RwLock::new(current_epoch)),
            epoch_duration,
            pending_validators: Arc::new(RwLock::new(Vec::new())),
            pending_removals: Arc::new(RwLock::new(Vec::new())),
            epoch_history: Arc::new(RwLock::new(Vec::new())),
            max_history: 10,
            store: None,
        })
    }

    /// Creates a new epoch manager backed by a persistent store.
    ///
    /// On construction, hydrates `current_epoch` and `epoch_history` from
    /// the store. If the store is empty (fresh node), bootstraps epoch 0
    /// from `initial_validators` and writes it through immediately so a
    /// crash before the first transition still leaves a recoverable record.
    ///
    /// Hydration order: the highest-numbered persisted epoch becomes
    /// `current_epoch`; everything below it (up to `max_history`) becomes
    /// `epoch_history`, oldest first.
    ///
    /// The store retains all epochs unconditionally; `max_history` only
    /// bounds the in-memory working set. Cross-epoch verification for an
    /// epoch outside the working set falls back to the store transparently
    /// via `get_epoch` / `get_epoch_for_height`.
    pub fn with_store(
        initial_validators: Vec<ValidatorInfo>,
        epoch_duration: u64,
        store: Arc<dyn EpochStateStore>,
    ) -> Result<Self> {
        // Only the newest epochs are needed here; the store is streamed, so a
        // node that has run for years does not decode every epoch it kept.
        let mut persisted_any = false;
        let mut newest: std::collections::BTreeMap<u64, Epoch> = std::collections::BTreeMap::new();
        store.for_each_epoch(&mut |bytes| {
            persisted_any = true;
            match bincode::deserialize::<Epoch>(bytes) {
                Ok(epoch) => {
                    newest.insert(epoch.number, epoch);
                    if newest.len() > HYDRATED_EPOCHS {
                        newest.pop_first();
                    }
                }
                // Records persisted under an older Epoch schema fail to
                // decode; the canonical-schedule walk in `transition_epoch`
                // re-derives the live epoch from observed heights, so losing
                // stale records only costs history depth.
                Err(e) => tracing::warn!(error = %e, "Dropping undecodable persisted epoch record (schema change); canonical walk will re-derive"),
            }
        })?;

        let (current_epoch, history) = if !persisted_any {
            // Fresh node: bootstrap epoch 0 and write it through.
            let validator_set = ValidatorSet::new(0, initial_validators)?;
            let epoch = Epoch::new(
                0,
                BlockHeight::from(0),
                BlockHeight::from(epoch_duration),
                validator_set,
            );
            let bytes = bincode::serialize(&epoch)
                .map_err(|e| ConsensusError::Internal(format!("bootstrap epoch 0 encode: {e}")))?;
            if let Err(e) = store.put_epoch(0, bytes) {
                tracing::warn!(error = %e, "Failed to persist bootstrap epoch 0; continuing in-memory");
            }
            (epoch, Vec::new())
        } else {
            // Ascending by epoch number, whatever order the store keeps.
            let mut decoded: Vec<Epoch> = newest.into_values().collect();

            let Some(current) = decoded.pop() else {
                // Every persisted record was undecodable — bootstrap fresh.
                let validator_set = ValidatorSet::new(0, initial_validators)?;
                let epoch = Epoch::new(
                    0,
                    BlockHeight::from(0),
                    BlockHeight::from(epoch_duration),
                    validator_set,
                );
                let bytes = bincode::serialize(&epoch).map_err(|e| {
                    ConsensusError::Internal(format!("bootstrap epoch 0 encode: {e}"))
                })?;
                if let Err(e) = store.put_epoch(0, bytes) {
                    tracing::warn!(error = %e, "Failed to persist bootstrap epoch 0; continuing in-memory");
                }
                return Ok(Self {
                    current_epoch: Arc::new(RwLock::new(epoch)),
                    epoch_duration,
                    pending_validators: Arc::new(RwLock::new(Vec::new())),
                    pending_removals: Arc::new(RwLock::new(Vec::new())),
                    epoch_history: Arc::new(RwLock::new(Vec::new())),
                    max_history: 10,
                    store: Some(store),
                });
            };

            // Tail is history; cap to max_history (oldest first).
            let max_history = 10usize;
            let history_start = decoded.len().saturating_sub(max_history);
            let history: Vec<Epoch> = decoded.into_iter().skip(history_start).collect();

            tracing::info!(
                current_epoch = current.number,
                history_len = history.len(),
                "Hydrated EpochManager from persistent store"
            );

            // Surface drifted records persisted by pre-canonical-schedule
            // builds. The walk in `transition_epoch` heals this as soon as
            // the node observes a height whose canonical epoch index is
            // ahead of the hydrated number.
            let canonical_start = current.number * epoch_duration;
            if current.start_height.as_u64() != canonical_start
                || current.end_height.as_u64() != canonical_start + epoch_duration
            {
                tracing::debug!(
                    epoch = current.number,
                    start_height = %current.start_height,
                    end_height = %current.end_height,
                    canonical_start,
                    canonical_end = canonical_start + epoch_duration,
                    "Hydrated epoch is off the canonical schedule; will re-anchor on next due transition"
                );
            }

            (current, history)
        };

        Ok(Self {
            current_epoch: Arc::new(RwLock::new(current_epoch)),
            epoch_duration,
            pending_validators: Arc::new(RwLock::new(Vec::new())),
            pending_removals: Arc::new(RwLock::new(Vec::new())),
            epoch_history: Arc::new(RwLock::new(history)),
            max_history: 10,
            store: Some(store),
        })
    }

    /// Returns the current epoch
    ///
    /// This is an atomic snapshot of the current epoch state.
    pub fn current_epoch(&self) -> Epoch {
        self.current_epoch.read().clone()
    }

    /// Returns the current validator set
    ///
    /// This is an atomic snapshot of the current validator set.
    /// During epoch transitions, this will either return the old or new set,
    /// never a partial/inconsistent state.
    pub fn current_validator_set(&self) -> ValidatorSet {
        self.current_epoch.read().validator_set.clone()
    }

    /// Checks if it's time to transition to the next epoch.
    ///
    /// The epoch schedule is canonical and derived purely from height:
    /// the epoch covering height `h` is `h / epoch_duration`. A transition
    /// is due whenever the canonical epoch index for `height` is ahead of
    /// the current epoch number — including when the current epoch carries
    /// drifted boundaries persisted by an earlier buggy transition (whose
    /// `end_height` could be arbitrarily far in the future). Deriving the
    /// due-check from the canonical schedule instead of `end_height` lets
    /// such a node walk back onto the fleet-wide schedule, which matters
    /// because the epoch number seeds reputation-based leader election —
    /// divergent epoch numbers mean divergent leaders per view.
    pub fn should_transition(&self, height: BlockHeight) -> bool {
        height.as_u64() / self.epoch_duration > self.current_epoch.read().number
    }

    /// Transitions to the next epoch
    ///
    /// This operation is atomic - the write lock on current_epoch ensures
    /// no other thread can read or modify the epoch during transition.
    /// History and pending validators are updated atomically within the same
    /// critical section to prevent split-brain scenarios.
    ///
    /// # Churn budget (set-continuity safety)
    ///
    /// BFT safety across epoch boundaries relies on set continuity: a
    /// client (or catching-up node) that trusts epoch N's validator set
    /// extends that trust to epoch N+1 only if a quorum of the stake it
    /// already holds accountable is still present in the new set. Unbounded
    /// churn lets a single transition replace the entire set, severing that
    /// chain of trust (long-range / posterior-corruption attacks). Each
    /// transition therefore bounds both directions:
    ///
    /// - **Removals**: at most 1/3 of the outgoing epoch's total stake may
    ///   leave per transition, so ≥ 2/3 of previously-accountable stake
    ///   remains in the new set.
    /// - **New voting power**: stake added by entrants and by stake increases
    ///   of continuing validators is capped, together, at half the
    ///   continuing stake, so continuing validators hold ≥ 2/3 of the NEW
    ///   set's total voting power and neither a fresh entrant nor a freshly
    ///   raised stake can immediately own a blocking minority.
    ///
    /// Upserts that add no voting power (key updates, stake decreases) apply
    /// in full. New voting power beyond the budget is phased in: a candidate
    /// is admitted, or grown, by the budget that remains and stays queued
    /// (FIFO) for the rest, which applies at subsequent transitions. So
    /// admission remains permissionless — large joins are spread across
    /// epochs, never censored, and never admitted past the budget.
    ///
    /// Removals keep one progress exception: the first queued removal
    /// applies even when it alone exceeds the removal budget, with a warning
    /// logged, because a slashed validator holding more than the budget must
    /// still be removable. A light client following the set across such a
    /// transition sees less than 2/3 continuity for that one epoch and must
    /// re-anchor through the removal's slashing evidence.
    ///
    /// Returns `Ok(None)` when the canonical epoch index for `height`
    /// (`height / epoch_duration`) is not ahead of the current epoch
    /// number — including the case where a concurrent caller won the
    /// race and already transitioned. The due-check runs under the same
    /// write lock as the transition itself, so two racing callers (the
    /// engine's finalize path and the node's follower path) resolve to
    /// exactly one transition.
    pub fn transition_epoch(&self, height: BlockHeight) -> Result<Option<ValidatorSet>> {
        self.transition_epoch_timed(height, None)
    }

    /// As [`Self::transition_epoch`], but `time_up` names an epoch whose time
    /// is up, which also authorises the transition out of it when the height
    /// schedule has not been reached.
    ///
    /// The caller decides that, because deciding it here would mean reading a
    /// clock, and the only clock every node agrees on is the one carried by
    /// the blocks themselves. See [`MAX_EPOCH_DURATION_MS`].
    pub fn transition_epoch_timed(
        &self,
        height: BlockHeight,
        time_up: Option<u64>,
    ) -> Result<Option<ValidatorSet>> {
        self.transition_epoch_checked(height, time_up, None)
    }

    /// As [`Self::transition_epoch_timed`], but the new validator set is
    /// first offered to `check`, and a set it rejects fails the transition
    /// before anything has changed: the epoch, the history and the pending
    /// queues stay as they were, so the caller can try again.
    pub fn transition_epoch_checked(
        &self,
        height: BlockHeight,
        time_up: Option<u64>,
        check: Option<&dyn Fn(&ValidatorSet) -> bool>,
    ) -> Result<Option<ValidatorSet>> {
        // Acquire write lock for atomic transition
        // This prevents any concurrent reads or writes to the current epoch
        let mut current = self.current_epoch.write();

        // Canonical due-check: derived from the height-based schedule, NOT
        // from `current.end_height`. A current epoch carrying drifted
        // boundaries (persisted by an earlier buggy transition) must not be
        // able to pin the node off-schedule — see `should_transition`.
        let height_due = height.as_u64() / self.epoch_duration > current.number;
        // A time-triggered transition is decided by its caller before the
        // lock is taken, for the epoch it saw running; one that finds that
        // epoch already closed lost a race with another caller. An epoch in
        // which no block was made still closes when its time is up.
        let time_due = time_up == Some(current.number);
        if !height_due && !time_due {
            return Ok(None);
        }

        let next_epoch_number = current.number + 1;

        // Compute next validator set as: current set, with churn-budgeted
        // pending_removals dropped, then pending_validators upserted
        // (matching address replaces; new address appends subject to the
        // entrant budget). Pending entries are deltas rather than a full
        // replacement, so a single stake event doesn't reset the set.
        // Both queues are taken in address order, so the set this builds
        // depends on what is queued and never on the order or the epochs it
        // was queued in: a node that restarted, and re-queued from the
        // registry, builds the same set as one that kept its queue.
        let mut pending_adds: Vec<ValidatorInfo> = self.pending_validators.read().clone();
        pending_adds.sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
        let mut pending_drops: Vec<Address> = self.pending_removals.read().clone();
        pending_drops.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let old_set = &current.validator_set;
        let old_total_stake = old_set.total_stake();

        // Step 1 — removals, FIFO, capped at 1/3 of outgoing stake so
        // ≥ 2/3 of previously-accountable stake persists into the new set.
        let removal_budget = old_total_stake / 3;
        let mut removed_stake: u128 = 0;
        let mut real_removals = 0usize;
        let mut applied_drops: Vec<Address> = Vec::new();
        let mut deferred_drop_count = 0usize;
        for addr in &pending_drops {
            let Some(member) = old_set.get_by_address(addr) else {
                // Address is not in the set — nothing to remove. Consume
                // the entry so it doesn't sit in the queue forever.
                applied_drops.push(*addr);
                continue;
            };
            let cumulative = removed_stake.saturating_add(member.stake);
            if cumulative <= removal_budget || real_removals == 0 {
                if cumulative > removal_budget {
                    tracing::warn!(
                        address = %addr,
                        stake = member.stake,
                        removal_budget,
                        "Validator removal exceeds the per-epoch churn budget on its own; applying for progress (slashing/unstake must not be censorable)"
                    );
                }
                removed_stake = cumulative;
                real_removals += 1;
                applied_drops.push(*addr);
            } else {
                deferred_drop_count += 1;
            }
        }

        // Step 2 — survivors, then upserts of continuing members that do not
        // add voting power (key or metadata updates, stake decreases). Those
        // apply in full.
        let mut next_validators: Vec<ValidatorInfo> = old_set
            .iter()
            .filter(|v| !applied_drops.iter().any(|a| a == &v.address))
            .cloned()
            .collect();

        let mut applied_add_addrs: Vec<Address> = Vec::new();
        let mut growth_candidates: Vec<ValidatorInfo> = Vec::new();
        for upsert in pending_adds {
            // An entry the next set cannot hold is consumed and refused on its
            // own, so it never fails the transition for every other change.
            if let Some(reason) = unseatable(&next_validators, &upsert) {
                tracing::warn!(
                    address = %upsert.address,
                    reason,
                    "Refusing a validator update the next set cannot hold"
                );
                applied_add_addrs.push(upsert.address);
                continue;
            }
            match next_validators
                .iter_mut()
                .find(|v| v.address == upsert.address)
            {
                Some(existing) if upsert.stake <= existing.stake => {
                    applied_add_addrs.push(upsert.address);
                    *existing = upsert;
                }
                _ => growth_candidates.push(upsert),
            }
        }

        // Step 3 — new voting power, FIFO: entrants and stake increases of
        // continuing members alike, capped in total at half the continuing
        // stake so continuing validators hold ≥ 2/3 of the new total. An
        // increase is new power exactly as an entrant is; exempting it would
        // let a small entrant grow to a majority one epoch after joining.
        //
        // A candidate that does not fit is admitted, or grown, by as much of
        // the remaining budget as there is, and stays queued for the rest, so
        // a large stake phases in over several epochs. Nothing is ever
        // admitted beyond the budget: admission stays permissionless, only
        // its speed is bounded.
        let continuing_stake: u128 = next_validators.iter().map(|v| v.stake).sum();
        let growth_budget = continuing_stake / 2;
        let mut granted: u128 = 0;
        let mut deferred_add_count = 0usize;
        for mut candidate in growth_candidates {
            if let Some(reason) = unseatable(&next_validators, &candidate) {
                tracing::warn!(
                    address = %candidate.address,
                    reason,
                    "Refusing a validator update the next set cannot hold"
                );
                applied_add_addrs.push(candidate.address);
                continue;
            }
            let current = next_validators
                .iter()
                .find(|v| v.address == candidate.address)
                .map(|v| v.stake)
                .unwrap_or(0);
            let wanted = candidate.stake.saturating_sub(current);
            let room = growth_budget.saturating_sub(granted);
            let grant = wanted.min(room);
            if grant < wanted {
                deferred_add_count += 1;
                if grant == 0 {
                    continue;
                }
                tracing::warn!(
                    address = %candidate.address,
                    requested_stake = candidate.stake,
                    admitted_stake = current + grant,
                    growth_budget,
                    "New voting power exceeds the per-epoch churn budget; phasing it in"
                );
            } else {
                applied_add_addrs.push(candidate.address);
            }
            granted = granted.saturating_add(grant);
            candidate.stake = current + grant;
            match next_validators
                .iter_mut()
                .find(|v| v.address == candidate.address)
            {
                Some(existing) => *existing = candidate,
                None => next_validators.push(candidate),
            }
        }

        // Create new validator set - this can fail, so we do it before modifying state
        let validator_set = ValidatorSet::new(next_epoch_number, next_validators)?;
        if let Some(check) = check
            && !check(&validator_set)
        {
            return Err(crate::error::ConsensusError::EpochTransition(format!(
                "the validator set derived for epoch {next_epoch_number} is not the one expected"
            )));
        }

        // Calculate next epoch boundaries canonically from the epoch number —
        // NOT from the height the caller happened to transition at, and NOT
        // from the outgoing epoch's end_height (which may carry persisted
        // drift). Epoch N covers exactly [N * duration, (N+1) * duration),
        // fleet-wide, unconditionally. A node that transitions late (after
        // catching up from a stall) or that hydrated a drifted epoch record
        // walks back onto the same schedule as everyone else.
        // A height-triggered epoch sits on the canonical schedule. A
        // time-triggered one has to begin where the chain actually is: the
        // range an epoch carries is what `get_epoch_for_height` answers
        // historical validator-set lookups from, and every commit-QC over
        // those heights is verified against that answer. Keeping the
        // canonical range here would file the epoch under heights it never
        // governed and leave the heights it did govern pointing at the
        // superseded set.
        let (start_height, end_height) = if height_due {
            let canonical = BlockHeight::from(next_epoch_number * self.epoch_duration);
            (canonical, canonical + self.epoch_duration)
        } else {
            (height, height + self.epoch_duration)
        };

        // Create new epoch
        let new_epoch = Epoch::new(
            next_epoch_number,
            start_height,
            end_height,
            validator_set.clone(),
        );

        // Now perform all state updates atomically within this critical section

        // Close the outgoing epoch where the new one starts. On the
        // canonical schedule the two already coincide; after a time-triggered
        // roll they do not, and an outgoing epoch still claiming its canonical
        // end would overlap the new one. `get_epoch_for_height` scans history
        // in order and would answer with the epoch that has been superseded.
        current.end_height = start_height;

        // 1. Store current epoch in history
        {
            let mut history = self.epoch_history.write();
            history.push(current.clone());

            // Trim history if needed
            if history.len() > self.max_history {
                history.remove(0);
            }
            // history lock is released here
        }

        // 2. Consume the applied pending deltas. Deferred entries (beyond
        //    this transition's churn budget) stay queued FIFO for the next
        //    epoch. Retain-by-applied (rather than overwrite) also preserves
        //    entries queued concurrently while this transition ran.
        {
            self.pending_validators
                .write()
                .retain(|v| !applied_add_addrs.iter().any(|a| a == &v.address));
            self.pending_removals
                .write()
                .retain(|addr| !applied_drops.iter().any(|a| a == addr));
            // pending_validators / pending_removals locks are released here
        }

        // 3. Update current epoch (this is the commit point)
        // Once this happens, all readers will see the new epoch
        *current = new_epoch.clone();

        // current lock is released here, making the transition visible
        drop(current);

        // 4. Write-through to persistent store (if attached).
        //
        // Best-effort: a write failure is logged but does not roll back the
        // in-memory transition. The next leader's commit-QC will re-anchor
        // the chain at the new epoch, and on the next clean restart we'll
        // hydrate from whatever did make it to disk plus replay from
        // genesis — never from a torn write.
        //
        // Note: we persist the OUTGOING epoch (its end_height is now
        // fixed) so history is complete, plus the NEW epoch so it survives
        // crash-before-first-block-of-epoch. Both writes are independent;
        // a partial failure still gives us a usable state on restart.
        if let Some(store) = self.store.as_ref() {
            // Persist the just-finalized outgoing epoch (history record).
            // The clone before the swap is captured in `history.push(current.clone())`
            // above; we re-derive its serialized form here.
            let outgoing_number = next_epoch_number - 1;
            if let Some(outgoing) = self.get_epoch(outgoing_number) {
                match bincode::serialize(&outgoing) {
                    Ok(bytes) => {
                        if let Err(e) = store.put_epoch(outgoing_number, bytes) {
                            tracing::warn!(
                                epoch = outgoing_number,
                                error = %e,
                                "Failed to persist outgoing epoch; chain will rebuild on next leader"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            epoch = outgoing_number,
                            error = %e,
                            "Failed to serialize outgoing epoch"
                        );
                    }
                }
            }

            // Persist the new current epoch.
            match bincode::serialize(&new_epoch) {
                Ok(bytes) => {
                    if let Err(e) = store.put_epoch(next_epoch_number, bytes) {
                        tracing::warn!(
                            epoch = next_epoch_number,
                            error = %e,
                            "Failed to persist new epoch; will retry on next transition"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        epoch = next_epoch_number,
                        error = %e,
                        "Failed to serialize new epoch"
                    );
                }
            }
        }

        tracing::info!(
            epoch = next_epoch_number,
            start_height = %start_height,
            end_height = %end_height,
            validator_count = validator_set.len(),
            deferred_adds = deferred_add_count,
            deferred_removals = deferred_drop_count,
            persisted = self.store.is_some(),
            "Epoch transition completed atomically"
        );

        Ok(Some(validator_set))
    }

    /// Starts epoch `from_epoch + 1` at `start_height` with exactly
    /// `validators`, closing `from_epoch` there. This is the one way a
    /// validator set is replaced without a certified block closing the
    /// epoch: a recovery manifest after a halt below quorum (see
    /// [`crate::recovery_manifest`]). Queued additions and removals belong
    /// to the set being replaced and are dropped.
    ///
    /// Applying it twice is a no-op. When the epoch manager already holds
    /// `from_epoch + 1` (the halted chain had closed `from_epoch` and derived
    /// its successor), that epoch is replaced. Any other current epoch is
    /// refused.
    pub fn install_recovery_epoch(
        &self,
        from_epoch: u64,
        start_height: BlockHeight,
        validators: Vec<ValidatorInfo>,
    ) -> Result<()> {
        let to_epoch = from_epoch + 1;
        let validator_set = ValidatorSet::new(to_epoch, validators)?;
        let new_epoch = Epoch::new(
            to_epoch,
            start_height,
            start_height + self.epoch_duration,
            validator_set,
        );
        let mut current = self.current_epoch.write();
        let replaced = current.number == to_epoch;
        if !replaced && current.number != from_epoch {
            return Err(ConsensusError::Internal(format!(
                "recovery from epoch {from_epoch} but the epoch manager is at epoch {}",
                current.number
            )));
        }
        if !replaced {
            current.end_height = start_height;
            let mut history = self.epoch_history.write();
            history.push(current.clone());
            if history.len() > self.max_history {
                history.remove(0);
            }
        }
        *current = new_epoch.clone();
        self.pending_validators.write().clear();
        self.pending_removals.write().clear();
        drop(current);
        let outgoing = self.get_epoch(from_epoch);

        if let Some(store) = self.store.as_ref() {
            let mut records = vec![(to_epoch, new_epoch)];
            records.extend(outgoing.map(|e| (from_epoch, e)));
            for (number, epoch) in records {
                let bytes = bincode::serialize(&epoch).map_err(|e| {
                    ConsensusError::Internal(format!("recovery epoch {number} encode: {e}"))
                })?;
                store.put_epoch(number, bytes)?;
            }
        }
        tracing::info!(
            epoch = to_epoch,
            start_height = %start_height,
            "Recovery epoch installed"
        );
        Ok(())
    }

    /// Queues a validator add/update for the next epoch. If `validator.address`
    /// is already present in the pending queue, the prior entry is replaced.
    /// Also clears any pending removal for the same address (an add wins over
    /// a prior queued remove within the same epoch window).
    pub fn add_pending_validator(&self, validator: ValidatorInfo) {
        let addr = validator.address;
        let stake = validator.stake;

        {
            let mut pending = self.pending_validators.write();
            if let Some(existing) = pending.iter_mut().find(|v| v.address == addr) {
                *existing = validator;
            } else {
                pending.push(validator);
            }
        }
        self.pending_removals.write().retain(|a| a != &addr);

        tracing::debug!(
            address = %addr,
            stake = stake,
            "Pending validator add/update queued for next epoch"
        );
    }

    /// Queues a validator removal for the next epoch. Idempotent: queueing the
    /// same address twice records one removal. Also drops any pending add for
    /// the same address (a remove wins over a prior queued add within the same
    /// epoch window).
    pub fn remove_pending_validator(&self, address: &tenzro_types::primitives::Address) {
        self.pending_validators
            .write()
            .retain(|v| &v.address != address);

        let mut removals = self.pending_removals.write();
        if !removals.iter().any(|a| a == address) {
            removals.push(*address);
        }

        tracing::debug!(address = %address, "Pending validator removal queued for next epoch");
    }

    /// Returns the pending validator additions/updates for the next epoch
    pub fn pending_validators(&self) -> Vec<ValidatorInfo> {
        self.pending_validators.read().clone()
    }

    /// Empties both queues. The node does this at the start of each
    /// boundary's staging and fills them again from the registry, so what is
    /// queued is a function of the registry, the seated set and the chain
    /// state alone, and never of what this process happened to keep.
    pub fn clear_pending(&self) {
        self.pending_validators.write().clear();
        self.pending_removals.write().clear();
    }

    /// Returns the pending validator removals for the next epoch
    pub fn pending_removals(&self) -> Vec<tenzro_types::primitives::Address> {
        self.pending_removals.read().clone()
    }

    /// Returns an epoch from history
    pub fn get_epoch(&self, epoch_number: u64) -> Option<Epoch> {
        {
            let current = self.current_epoch.read();
            if current.number == epoch_number {
                return Some(current.clone());
            }
        }

        if let Some(epoch) = self
            .epoch_history
            .read()
            .iter()
            .find(|e| e.number == epoch_number)
            .cloned()
        {
            return Some(epoch);
        }

        self.stored_epoch(epoch_number)
    }

    /// Returns the validator set for a specific epoch
    pub fn get_validator_set(&self, epoch_number: u64) -> Option<ValidatorSet> {
        self.get_epoch(epoch_number)
            .map(|epoch| epoch.validator_set)
    }

    /// Returns the epoch for a given block height
    pub fn get_epoch_for_height(&self, height: BlockHeight) -> Option<Epoch> {
        {
            let current = self.current_epoch.read();
            if current.contains(height) {
                return Some(current.clone());
            }
        }

        if let Some(epoch) = self
            .epoch_history
            .read()
            .iter()
            .find(|e| e.contains(height))
            .cloned()
        {
            return Some(epoch);
        }

        self.find_in_store(|e| e.contains(height))
    }

    /// One epoch read from the persistent store by its number: a lookup
    /// that misses the in-memory working set reads that record alone.
    fn stored_epoch(&self, epoch_number: u64) -> Option<Epoch> {
        let bytes = match self.store.as_ref()?.load_epoch(epoch_number) {
            Ok(bytes) => bytes?,
            Err(e) => {
                tracing::warn!(error = %e, epoch = epoch_number, "Epoch store read failed");
                return None;
            }
        };
        match bincode::deserialize::<Epoch>(&bytes) {
            Ok(epoch) if epoch.number == epoch_number => Some(epoch),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(error = %e, "Skipping undecodable epoch record in store");
                None
            }
        }
    }

    /// Streams the persistent store for the newest epoch matching `pred`.
    ///
    /// Fallback for height lookups that miss the in-memory working set
    /// (current + bounded history). One record is decoded at a time, so the
    /// scan holds no more than the match. Returns `None` when no store is
    /// attached or nothing matches.
    fn find_in_store(&self, pred: impl Fn(&Epoch) -> bool) -> Option<Epoch> {
        let store = self.store.as_ref()?;
        let mut found = None;
        let scanned =
            store.for_each_epoch(&mut |bytes| match bincode::deserialize::<Epoch>(bytes) {
                Ok(epoch) if pred(&epoch) => found = Some(epoch),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "Skipping undecodable epoch record in store"),
            });
        if let Err(e) = scanned {
            tracing::warn!(error = %e, "Epoch store scan failed");
            return None;
        }
        found
    }

    /// Returns epoch statistics
    pub fn stats(&self) -> EpochStats {
        let current = self.current_epoch.read();
        let pending_count = self.pending_validators.read().len();

        EpochStats {
            current_epoch: current.number,
            start_height: current.start_height,
            end_height: current.end_height,
            validator_count: current.validator_set.len(),
            pending_validator_changes: pending_count,
            epoch_duration: self.epoch_duration,
        }
    }
}

/// Epoch statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochStats {
    /// Current epoch number
    pub current_epoch: u64,

    /// Start height of current epoch
    pub start_height: BlockHeight,

    /// End height of current epoch
    pub end_height: BlockHeight,

    /// Number of validators in current epoch
    pub validator_count: usize,

    /// Number of pending validator changes
    pub pending_validator_changes: usize,

    /// Epoch duration in blocks
    pub epoch_duration: u64,
}

/// Why `update` cannot join `set`: a malformed key, or a key another
/// validator in the set already holds.
fn unseatable(set: &[ValidatorInfo], update: &ValidatorInfo) -> Option<&'static str> {
    if update.public_key.check_well_formed().is_err() {
        return Some("malformed consensus key");
    }
    let fingerprint = update.public_key.fingerprint();
    set.iter()
        .any(|v| v.address != update.address && v.public_key.fingerprint() == fingerprint)
        .then_some("consensus key held by another validator")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_key::ValidatorSigner;
    use crate::validator_key::test_signer::SoftwareTestSigner;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn create_test_validator(stake: u128) -> ValidatorInfo {
        static NEXT: AtomicU64 = AtomicU64::new(1_000);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..8].copy_from_slice(&n.to_be_bytes());
        let address = tenzro_types::primitives::Address::new(addr_bytes);
        ValidatorInfo::new(
            address,
            SoftwareTestSigner::from_seed(n).public_key().clone(),
            addr_bytes,
            stake,
        )
    }

    #[test]
    fn an_update_reusing_a_seated_key_is_refused_without_stalling_the_transition() {
        let a = create_test_validator(1000);
        let b = create_test_validator(1000);
        let manager = EpochManager::new(vec![a.clone(), b.clone()], 100).unwrap();

        let mut twin = create_test_validator(10);
        twin.public_key = a.public_key.clone();
        manager.add_pending_validator(twin.clone());
        let mut grown = b.clone();
        grown.stake = 1200;
        manager.add_pending_validator(grown);

        let set = manager
            .transition_epoch(BlockHeight::from(100))
            .expect("one unseatable update failed the whole transition")
            .expect("the transition was due");
        assert!(set.get_by_address(&twin.address).is_none());
        assert_eq!(set.get_by_address(&b.address).map(|v| v.stake), Some(1200));
        assert!(manager.pending_validators().is_empty());
    }

    #[test]
    fn test_epoch_creation() {
        let validators = vec![create_test_validator(1000), create_test_validator(2000)];

        let manager = EpochManager::new(validators, 100).unwrap();

        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 0);
        assert_eq!(epoch.start_height, BlockHeight::from(0));
        assert_eq!(epoch.end_height, BlockHeight::from(100));
    }

    /// A quiet chain must still be able to rotate its set.
    ///
    /// Height 30 is nowhere near the 100-block boundary, and on a chain that
    /// suppresses empty blocks it may not arrive for weeks. With the elapsed
    /// bound the epoch rolls anyway.
    #[test]
    fn an_epoch_can_roll_before_its_height_boundary() {
        let manager = EpochManager::new(vec![create_test_validator(1000)], 100).unwrap();

        // Not due by height, and not authorised by time either.
        assert!(!manager.should_transition(BlockHeight::from(30)));
        assert!(
            manager
                .transition_epoch(BlockHeight::from(30))
                .unwrap()
                .is_none(),
            "without the time authorisation this must stay a no-op"
        );

        assert!(
            manager
                .transition_epoch_timed(BlockHeight::from(30), Some(0))
                .unwrap()
                .is_some()
        );
        assert_eq!(manager.current_epoch().number, 1);
    }

    /// Two callers that both saw epoch 0's time run out make one
    /// transition: the second finds epoch 0 already closed and does nothing.
    #[test]
    fn a_time_triggered_transition_happens_once_per_epoch() {
        let manager = EpochManager::new(vec![create_test_validator(1000)], 100).unwrap();
        assert!(
            manager
                .transition_epoch_timed(BlockHeight::from(30), Some(0))
                .unwrap()
                .is_some()
        );
        assert!(
            manager
                .transition_epoch_timed(BlockHeight::from(30), Some(0))
                .unwrap()
                .is_none()
        );
        assert_eq!(manager.current_epoch().number, 1);
    }

    /// An epoch in which no block was made still closes when its time is up:
    /// an idle chain hands over at the height the previous epoch began at.
    #[test]
    fn an_epoch_without_a_block_closes_when_its_time_is_up() {
        let manager = EpochManager::new(vec![create_test_validator(1000)], 100).unwrap();
        for closing in 0..3 {
            assert!(
                manager
                    .transition_epoch_timed(BlockHeight::from(0), Some(closing))
                    .unwrap()
                    .is_some(),
                "epoch {closing} did not close"
            );
        }
        assert_eq!(manager.current_epoch().number, 3);
    }

    /// The range a time-triggered epoch carries must be the range it governs.
    ///
    /// `get_epoch_for_height` answers historical validator-set lookups by
    /// scanning ranges, and commit-QC verification is decided by what it
    /// returns. An epoch that rolled at height 30 while the canonical schedule
    /// put the boundary at 100 has to own [30, 130) — and its predecessor has
    /// to stop at 30, or both claim height 50 and the older one wins the scan.
    #[test]
    fn a_time_triggered_epoch_owns_the_heights_it_governs() {
        let manager = EpochManager::new(vec![create_test_validator(1000)], 100).unwrap();

        manager
            .transition_epoch_timed(BlockHeight::from(30), Some(0))
            .unwrap()
            .expect("time-authorised transition");

        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 1);
        assert_eq!(epoch.start_height, BlockHeight::from(30));
        assert_eq!(epoch.end_height, BlockHeight::from(130));

        // Heights before the roll still resolve to epoch 0, which no longer
        // claims to run to 100.
        let before = manager
            .get_epoch_for_height(BlockHeight::from(29))
            .expect("epoch 0 covers height 29");
        assert_eq!(before.number, 0);
        assert_eq!(before.end_height, BlockHeight::from(30));

        // And heights after it resolve to epoch 1, not to the epoch whose
        // canonical range still nominally contains them.
        for h in [30u64, 50, 129] {
            let at = manager
                .get_epoch_for_height(BlockHeight::from(h))
                .unwrap_or_else(|| panic!("no epoch resolves height {h}"));
            assert_eq!(at.number, 1, "height {h} resolved to the wrong epoch");
        }
    }

    /// Rolling early must not leave the node stuck off the height schedule:
    /// once height catches up past the new epoch's own end, the height rule
    /// takes over again.
    #[test]
    fn the_height_rule_still_applies_after_an_early_roll() {
        let manager = EpochManager::new(vec![create_test_validator(1000)], 100).unwrap();

        manager
            .transition_epoch_timed(BlockHeight::from(30), Some(0))
            .unwrap()
            .expect("time-authorised transition");

        // Epoch 1 now; the canonical rule is `height / 100 > 1`, so 200 is the
        // next height-triggered boundary and 150 is not one.
        assert!(!manager.should_transition(BlockHeight::from(150)));
        assert!(manager.should_transition(BlockHeight::from(200)));

        manager
            .transition_epoch(BlockHeight::from(200))
            .unwrap()
            .expect("height-triggered transition");
        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 2);
        assert_eq!(
            epoch.start_height,
            BlockHeight::from(200),
            "a height-triggered roll returns to the canonical schedule"
        );
    }

    #[test]
    fn test_epoch_transition() {
        let validators = vec![create_test_validator(1000)];
        let manager = EpochManager::new(validators, 100).unwrap();

        assert!(!manager.should_transition(BlockHeight::from(50)));
        assert!(manager.should_transition(BlockHeight::from(100)));

        // Not yet due → Ok(None), state unchanged
        assert!(
            manager
                .transition_epoch(BlockHeight::from(50))
                .unwrap()
                .is_none()
        );
        assert_eq!(manager.current_epoch().number, 0);

        // Transition to next epoch
        let new_validators = manager.transition_epoch(BlockHeight::from(100)).unwrap();
        assert!(new_validators.is_some());

        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 1);
        assert_eq!(epoch.start_height, BlockHeight::from(100));
        assert_eq!(epoch.end_height, BlockHeight::from(200));
    }

    #[test]
    fn test_late_epoch_transition_keeps_fleet_schedule() {
        // A node that transitions LATE (caught up after a stall) must land on
        // the same epoch boundaries as nodes that transitioned exactly at
        // end_height — boundaries anchor to the outgoing epoch's end_height,
        // not the height the caller happened to pass.
        let validators = vec![create_test_validator(1000)];
        let manager = EpochManager::new(validators, 100).unwrap();

        // Transition fires late, at height 789 instead of 100.
        let next = manager.transition_epoch(BlockHeight::from(789)).unwrap();
        assert!(next.is_some());

        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 1);
        assert_eq!(epoch.start_height, BlockHeight::from(100));
        assert_eq!(epoch.end_height, BlockHeight::from(200));

        // Walking forward (multi-epoch catch-up) keeps converging on the
        // canonical schedule.
        while manager.should_transition(BlockHeight::from(789)) {
            manager
                .transition_epoch(BlockHeight::from(789))
                .unwrap()
                .expect("due transition must produce a set");
        }
        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 7);
        assert_eq!(epoch.start_height, BlockHeight::from(700));
        assert_eq!(epoch.end_height, BlockHeight::from(800));
    }

    #[test]
    fn test_pending_validators_merge_add() {
        // 3 initial validators + 1 pending add → 4 in next epoch (merge, not replace)
        let v0 = create_test_validator(1000);
        let v1 = create_test_validator(2000);
        let v2 = create_test_validator(3000);
        let manager = EpochManager::new(vec![v0.clone(), v1.clone(), v2.clone()], 100).unwrap();

        // Within the growth budget (half the continuing 6000).
        let v3 = create_test_validator(3000);
        manager.add_pending_validator(v3.clone());
        assert_eq!(manager.pending_validators().len(), 1);

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");

        assert_eq!(next.len(), 4, "next epoch must MERGE pending into current");
        assert!(next.iter().any(|v| v.address == v0.address));
        assert!(next.iter().any(|v| v.address == v1.address));
        assert!(next.iter().any(|v| v.address == v2.address));
        assert!(next.iter().any(|v| v.address == v3.address));

        // Both queues cleared
        assert_eq!(manager.pending_validators().len(), 0);
        assert_eq!(manager.pending_removals().len(), 0);
    }

    #[test]
    fn test_pending_validators_remove() {
        // 3 initial - 1 pending removal → 2 in next epoch
        let v0 = create_test_validator(1000);
        let v1 = create_test_validator(2000);
        let v2 = create_test_validator(3000);
        let manager = EpochManager::new(vec![v0.clone(), v1.clone(), v2.clone()], 100).unwrap();

        manager.remove_pending_validator(&v1.address);
        assert_eq!(manager.pending_removals().len(), 1);

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");

        assert_eq!(next.len(), 2);
        assert!(next.iter().any(|v| v.address == v0.address));
        assert!(!next.iter().any(|v| v.address == v1.address));
        assert!(next.iter().any(|v| v.address == v2.address));

        assert_eq!(manager.pending_removals().len(), 0);
    }

    #[test]
    fn test_pending_validators_upsert_existing() {
        // Pending add for existing address replaces (stake updated)
        let v0 = create_test_validator(1000);
        let v0_addr = v0.address;
        let v0_pk = v0.public_key.clone();
        let manager = EpochManager::new(vec![v0.clone()], 100).unwrap();

        // Same address, larger stake
        // Same address, larger stake within the growth budget.
        let v0_updated = ValidatorInfo::new(v0_addr, v0_pk, v0.node_key, 1500);
        manager.add_pending_validator(v0_updated);

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");

        assert_eq!(next.len(), 1, "upsert must not duplicate");
        let only = next.get(0).unwrap();
        assert_eq!(only.address, v0_addr);
        assert_eq!(only.stake, 1500, "stake must be updated to new value");
    }

    #[test]
    fn test_pending_validators_add_then_remove_same_address() {
        // Conflict resolution: add then remove for same address → final state respects last op (remove)
        let v0 = create_test_validator(1000);
        let manager = EpochManager::new(vec![v0.clone()], 100).unwrap();

        let v_new = create_test_validator(2000);
        let v_new_addr = v_new.address;

        manager.add_pending_validator(v_new);
        manager.remove_pending_validator(&v_new_addr);

        // After remove, the add for the same address should have been dropped
        assert!(
            !manager
                .pending_validators()
                .iter()
                .any(|v| v.address == v_new_addr),
            "add must be dropped when subsequent remove targets same address"
        );

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");

        // Only original v0 remains; v_new was added then removed
        assert_eq!(next.len(), 1);
        assert_eq!(next.get(0).unwrap().address, v0.address);
    }

    #[test]
    fn test_pending_validators_remove_then_add_same_address() {
        // Inverse conflict: remove then add for same existing address → add wins (re-stake)
        let v0 = create_test_validator(1000);
        let v0_addr = v0.address;
        let v0_pk = v0.public_key.clone();
        let manager = EpochManager::new(vec![v0.clone()], 100).unwrap();

        manager.remove_pending_validator(&v0_addr);
        // Now re-stake same address with new amount
        let v0_restaked = ValidatorInfo::new(v0_addr, v0_pk, v0.node_key, 1400);
        manager.add_pending_validator(v0_restaked);

        // The add should clear the prior pending removal for the same address
        assert!(
            !manager
                .pending_removals()
                .iter()
                .any(|addr| addr == &v0_addr),
            "subsequent add for same address must clear pending removal"
        );

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 1);
        assert_eq!(next.get(0).unwrap().stake, 1400);
    }

    #[test]
    fn test_removal_churn_capped_and_deferred() {
        // 6 validators × 1000 stake (total 6000, removal budget 2000).
        // Queueing 4 removals must apply exactly 2 per transition and
        // defer the rest, so ≥ 2/3 of outgoing stake persists each epoch.
        let validators: Vec<ValidatorInfo> = (0..6).map(|_| create_test_validator(1000)).collect();
        let manager = EpochManager::new(validators.clone(), 100).unwrap();

        for v in validators.iter().take(4) {
            manager.remove_pending_validator(&v.address);
        }
        assert_eq!(manager.pending_removals().len(), 4);

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 4, "budget admits 2 removals of 1000 each");
        assert_eq!(
            manager.pending_removals().len(),
            2,
            "excess removals deferred"
        );

        // Next transition: total 4000, budget 1333 → exactly 1 more removal.
        let next = manager
            .transition_epoch(BlockHeight::from(200))
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 3);
        assert_eq!(manager.pending_removals().len(), 1);

        // Next: total 3000, budget 1000 → last removal applies, queue drains.
        let next = manager
            .transition_epoch(BlockHeight::from(300))
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 2);
        assert!(manager.pending_removals().is_empty());
    }

    #[test]
    fn test_oversized_removal_applies_for_progress() {
        // A validator holding more stake than the whole budget must still
        // be removable in one transition (slashing is not censorable).
        let whale = create_test_validator(5000);
        let small = create_test_validator(1000);
        let manager = EpochManager::new(vec![whale.clone(), small.clone()], 100).unwrap();

        manager.remove_pending_validator(&whale.address);

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 1);
        assert!(!next.is_validator(&whale.address));
        assert!(manager.pending_removals().is_empty());
    }

    #[test]
    fn test_entrant_churn_capped_and_deferred() {
        // 3 validators × 1000 (continuing 3000, entrant budget 1500).
        // First 1000-stake entrant fits; the second gets the remaining 500
        // and the rest of its stake waits for the next epoch.
        let validators: Vec<ValidatorInfo> = (0..3).map(|_| create_test_validator(1000)).collect();
        let manager = EpochManager::new(validators, 100).unwrap();

        let a = create_test_validator(1000);
        let b = create_test_validator(1000);
        manager.add_pending_validator(a.clone());
        manager.add_pending_validator(b.clone());

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 5);
        assert_eq!(next.get_by_address(&a.address).unwrap().stake, 1000);
        assert_eq!(next.get_by_address(&b.address).unwrap().stake, 500);
        assert_eq!(next.total_stake(), 4500, "exactly the budget was added");
        assert_eq!(
            manager.pending_validators().len(),
            1,
            "the rest of the second entrant stays queued"
        );

        // Next epoch: continuing 4500, budget 2250 → the rest fits.
        let next = manager
            .transition_epoch(BlockHeight::from(200))
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 5);
        assert_eq!(next.get_by_address(&b.address).unwrap().stake, 1000);
        assert!(manager.pending_validators().is_empty());
    }

    /// Long-range shape: a cohort with more stake than the whole set joins at
    /// once and tries to replace it. It cannot do so in one transition; every
    /// transition keeps two thirds of its power with stake the previous set
    /// held, and owning two thirds of the set takes several epochs, which is
    /// the time honest validators and light clients have to see it.
    #[test]
    fn a_cohort_with_unbounded_stake_needs_several_epochs_to_own_the_set() {
        let honest: Vec<ValidatorInfo> = (0..6).map(|_| create_test_validator(1000)).collect();
        let manager = EpochManager::new(honest, 100).unwrap();
        let cohort: Vec<ValidatorInfo> = (0..12).map(|_| create_test_validator(100_000)).collect();
        for c in &cohort {
            manager.add_pending_validator(c.clone());
        }
        let mut prev_total = 6000u128;
        let mut owns_two_thirds_at = None;
        for epoch in 1..=20u64 {
            let set = manager
                .transition_epoch(BlockHeight::from(epoch * 100))
                .unwrap()
                .expect("transition due");
            assert!(
                prev_total * 3 >= set.total_stake() * 2,
                "epoch {epoch}: continuing stake {prev_total} is under two thirds of {}",
                set.total_stake()
            );
            let theirs: u128 = cohort
                .iter()
                .filter_map(|c| set.get_by_address(&c.address))
                .map(|v| v.stake)
                .sum();
            if owns_two_thirds_at.is_none() && theirs * 3 > set.total_stake() * 2 {
                owns_two_thirds_at = Some(epoch);
            }
            prev_total = set.total_stake();
        }
        let at = owns_two_thirds_at.expect("the queue drains into the set over time");
        assert!(at >= 3, "two thirds of the set was taken in {at} epochs");
    }

    #[test]
    fn an_oversized_entrant_is_phased_in_not_admitted_whole() {
        // A single entrant staking 100x the set used to be admitted whole at
        // the first boundary, holding ~99% of voting power. It now enters at
        // the budget, holding a third, and grows by at most half of the
        // continuing stake per epoch, so every transition keeps two thirds
        // of the new set's power with stake the previous set already held.
        let genesis = create_test_validator(1000);
        let manager = EpochManager::new(vec![genesis], 100).unwrap();

        let whale = create_test_validator(100_000);
        manager.add_pending_validator(whale.clone());

        let first = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");
        let whale_stake = first.get_by_address(&whale.address).unwrap().stake;
        assert_eq!(whale_stake, 500, "admitted at the budget, not whole");
        assert_eq!(first.total_stake(), 1500);

        let mut prev_total = first.total_stake();
        let mut prev_stake = whale_stake;
        for epoch in 2..=8u64 {
            let next = manager
                .transition_epoch(BlockHeight::from(epoch * 100))
                .unwrap()
                .expect("transition due");
            let stake = next.get_by_address(&whale.address).unwrap().stake;
            assert!(stake > prev_stake, "the entrant keeps growing");
            assert!(
                prev_total * 3 >= next.total_stake() * 2,
                "epoch {epoch}: continuing stake {prev_total} is under two thirds of {}",
                next.total_stake()
            );
            prev_total = next.total_stake();
            prev_stake = stake;
        }
        assert!(
            !manager.pending_validators().is_empty(),
            "the remainder stays queued until it fits"
        );
    }

    #[test]
    fn a_stake_increase_draws_on_the_same_budget() {
        // Joining small and raising stake right after must not bypass the
        // budget: the increase is new voting power exactly as an entrant is.
        let v0 = create_test_validator(1000);
        let v1 = create_test_validator(1000);
        let manager = EpochManager::new(vec![v0.clone(), v1], 100).unwrap();

        let v0_restaked = ValidatorInfo::new(v0.address, v0.public_key.clone(), v0.node_key, 9000);
        manager.add_pending_validator(v0_restaked);
        let e1 = create_test_validator(3000);
        manager.add_pending_validator(e1.clone());

        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");
        // Continuing stake 2000, budget 1000, all of it taken by v0's raise.
        assert_eq!(next.get_by_address(&v0.address).unwrap().stake, 2000);
        assert!(!next.is_validator(&e1.address), "no budget left this epoch");
        assert_eq!(manager.pending_validators().len(), 2);
    }

    #[test]
    fn a_stake_decrease_applies_in_full() {
        let v0 = create_test_validator(5000);
        let v1 = create_test_validator(5000);
        let manager = EpochManager::new(vec![v0.clone(), v1], 100).unwrap();
        let lowered = ValidatorInfo::new(v0.address, v0.public_key.clone(), v0.node_key, 1000);
        manager.add_pending_validator(lowered);
        let next = manager
            .transition_epoch(BlockHeight::from(100))
            .unwrap()
            .expect("transition due");
        assert_eq!(next.get_by_address(&v0.address).unwrap().stake, 1000);
        assert!(manager.pending_validators().is_empty());
    }

    /// A node that kept many epochs reads only the newest at start, and a
    /// lookup by number outside the in-memory window reads that one record:
    /// nothing loads every epoch, however long the chain has run.
    #[test]
    fn epoch_lookups_read_only_what_they_need() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        #[derive(Default)]
        struct Counting {
            epochs: parking_lot::Mutex<std::collections::BTreeMap<u64, Vec<u8>>>,
            all: AtomicUsize,
            one: AtomicUsize,
        }
        impl EpochStateStore for Counting {
            fn put_epoch(&self, epoch_number: u64, bytes: Vec<u8>) -> Result<()> {
                self.epochs.lock().insert(epoch_number, bytes);
                Ok(())
            }
            fn load_all_epochs(&self) -> Result<Vec<Vec<u8>>> {
                self.all.fetch_add(1, Ordering::Relaxed);
                Ok(self.epochs.lock().values().cloned().collect())
            }
            fn load_epoch(&self, epoch_number: u64) -> Result<Option<Vec<u8>>> {
                self.one.fetch_add(1, Ordering::Relaxed);
                Ok(self.epochs.lock().get(&epoch_number).cloned())
            }
            fn for_each_epoch(&self, f: &mut dyn FnMut(&[u8])) -> Result<()> {
                let records: Vec<Vec<u8>> = self.epochs.lock().values().cloned().collect();
                for bytes in records {
                    f(&bytes);
                }
                Ok(())
            }
        }

        let validators = vec![create_test_validator(1000)];
        let store = Arc::new(Counting::default());
        for n in 0..1_000u64 {
            let epoch = Epoch::new(
                n,
                BlockHeight::from(n * 10_000),
                BlockHeight::from((n + 1) * 10_000),
                ValidatorSet::new(n, validators.clone()).unwrap(),
            );
            store
                .put_epoch(n, bincode::serialize(&epoch).unwrap())
                .unwrap();
        }

        let manager = EpochManager::with_store(validators, 10_000, store.clone()).unwrap();
        assert_eq!(manager.current_epoch().number, 999);
        assert!(manager.epoch_history.read().len() <= 10);
        assert_eq!(
            store.all.load(Ordering::Relaxed),
            0,
            "start loaded every epoch"
        );

        // Outside the in-memory window: one record read, nothing loaded whole.
        assert_eq!(manager.get_epoch(5).map(|e| e.number), Some(5));
        assert_eq!(manager.get_validator_set(17).map(|s| s.epoch), Some(17));
        assert_eq!(store.one.load(Ordering::Relaxed), 2);
        assert_eq!(
            store.all.load(Ordering::Relaxed),
            0,
            "a lookup loaded every epoch"
        );

        // By height, outside the window: streamed, never loaded whole.
        assert_eq!(
            manager
                .get_epoch_for_height(BlockHeight::from(42_500))
                .map(|e| e.number),
            Some(4)
        );
        assert_eq!(store.all.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_drifted_persisted_epoch_heals_onto_canonical_schedule() {
        // Fleet condition observed 2026-06-12: a node hydrates an epoch
        // record whose number AND boundaries drifted (pre-canonical builds
        // anchored boundaries to caller heights). Epoch number seeds
        // reputation-based leader election, so divergent numbers across
        // the fleet break leader agreement. The canonical due-check must
        // fire even though the drifted end_height is far in the future,
        // and walking must land exactly on the canonical schedule.
        struct MemStore(parking_lot::Mutex<std::collections::BTreeMap<u64, Vec<u8>>>);
        impl EpochStateStore for MemStore {
            fn put_epoch(&self, epoch_number: u64, bytes: Vec<u8>) -> Result<()> {
                self.0.lock().insert(epoch_number, bytes);
                Ok(())
            }
            fn load_all_epochs(&self) -> Result<Vec<Vec<u8>>> {
                Ok(self.0.lock().values().cloned().collect())
            }
        }

        let validators = vec![create_test_validator(1000)];
        let validator_set = ValidatorSet::new(3, validators.clone()).unwrap();

        // Drifted record: epoch 3 claiming to cover [95_000, 195_000) —
        // number says 3, canonical epoch 3 is [30_000, 40_000).
        let drifted = Epoch::new(
            3,
            BlockHeight::from(95_000),
            BlockHeight::from(195_000),
            validator_set,
        );
        let store = Arc::new(MemStore(parking_lot::Mutex::new(
            std::collections::BTreeMap::new(),
        )));
        store
            .put_epoch(3, bincode::serialize(&drifted).unwrap())
            .unwrap();

        let manager = EpochManager::with_store(validators, 10_000, store).unwrap();
        assert_eq!(manager.current_epoch().number, 3);

        // Chain tip at 106_000 → canonical epoch 10. The drifted
        // end_height (195_000) must NOT suppress the transition.
        let tip = BlockHeight::from(106_000);
        assert!(manager.should_transition(tip));

        while manager.should_transition(tip) {
            manager
                .transition_epoch(tip)
                .unwrap()
                .expect("due transition must produce a set");
        }

        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 10);
        assert_eq!(epoch.start_height, BlockHeight::from(100_000));
        assert_eq!(epoch.end_height, BlockHeight::from(110_000));

        // Every walked epoch landed canonically.
        for n in 4..=9u64 {
            let e = manager.get_epoch(n).expect("walked epoch persisted");
            assert_eq!(e.start_height.as_u64(), n * 10_000);
            assert_eq!(e.end_height.as_u64(), (n + 1) * 10_000);
        }

        // Heights inside the current canonical window must NOT be due.
        assert!(!manager.should_transition(BlockHeight::from(109_999)));
        assert!(manager.should_transition(BlockHeight::from(110_000)));
    }

    #[test]
    fn test_epoch_history() {
        let validators = vec![create_test_validator(1000)];
        let manager = EpochManager::new(validators, 100).unwrap();

        manager.transition_epoch(BlockHeight::from(100)).unwrap();
        manager.transition_epoch(BlockHeight::from(200)).unwrap();

        // Should have epoch 0 in history
        let epoch0 = manager.get_epoch(0);
        assert!(epoch0.is_some());
        assert_eq!(epoch0.unwrap().number, 0);

        // Current epoch should be 2
        assert_eq!(manager.current_epoch().number, 2);
    }

    #[test]
    fn test_get_epoch_for_height() {
        let validators = vec![create_test_validator(1000)];
        let manager = EpochManager::new(validators, 100).unwrap();

        manager.transition_epoch(BlockHeight::from(100)).unwrap();

        // Height 50 should be in epoch 0
        let epoch = manager.get_epoch_for_height(BlockHeight::from(50));
        assert!(epoch.is_some());
        assert_eq!(epoch.unwrap().number, 0);

        // Height 150 should be in epoch 1
        let epoch = manager.get_epoch_for_height(BlockHeight::from(150));
        assert!(epoch.is_some());
        assert_eq!(epoch.unwrap().number, 1);
    }

    #[test]
    fn a_recovery_epoch_replaces_the_set_once_and_is_idempotent() {
        let old: Vec<_> = (0..4).map(|_| create_test_validator(1000)).collect();
        let manager = EpochManager::new(old.clone(), 100).unwrap();
        manager.add_pending_validator(create_test_validator(5));
        let successor: Vec<_> = (0..4).map(|_| create_test_validator(1000)).collect();

        manager
            .install_recovery_epoch(0, BlockHeight::from(51), successor.clone())
            .unwrap();
        let now = manager.current_epoch();
        assert_eq!(now.number, 1);
        assert_eq!(now.start_height, BlockHeight::from(51));
        assert!(now.validator_set.get_by_address(&old[0].address).is_none());
        assert!(
            now.validator_set
                .get_by_address(&successor[0].address)
                .is_some()
        );
        assert!(manager.pending_validators().is_empty());
        assert_eq!(
            manager.get_epoch(0).unwrap().end_height,
            BlockHeight::from(51)
        );
        assert_eq!(
            manager
                .get_epoch_for_height(BlockHeight::from(51))
                .unwrap()
                .number,
            1
        );
        assert_eq!(
            manager
                .get_epoch_for_height(BlockHeight::from(50))
                .unwrap()
                .number,
            0
        );

        // Applied again, nothing changes and no history is added.
        manager
            .install_recovery_epoch(0, BlockHeight::from(51), successor)
            .unwrap();
        assert_eq!(manager.current_epoch().number, 1);
        assert_eq!(manager.get_epoch(0).unwrap().number, 0);

        // From an epoch the manager is not at: refused.
        assert!(
            manager
                .install_recovery_epoch(5, BlockHeight::from(60), vec![create_test_validator(1)])
                .is_err()
        );
    }

    #[test]
    fn a_transition_whose_set_fails_the_check_changes_nothing() {
        let a = create_test_validator(1000);
        let b = create_test_validator(1000);
        let manager = EpochManager::new(vec![a.clone(), b.clone()], 100).unwrap();
        let extra = create_test_validator(300);
        manager.add_pending_validator(extra.clone());

        let refused = manager.transition_epoch_checked(
            BlockHeight::from(100),
            None,
            Some(&|_: &ValidatorSet| false),
        );
        assert!(refused.is_err());
        assert_eq!(manager.current_epoch().number, 0, "the epoch did not move");
        assert_eq!(manager.pending_validators().len(), 1, "the queue is intact");

        let set = manager
            .transition_epoch_checked(BlockHeight::from(100), None, Some(&|_: &ValidatorSet| true))
            .unwrap()
            .expect("due");
        assert!(set.get_by_address(&extra.address).is_some());
        assert_eq!(manager.current_epoch().number, 1);
    }

    /// Whatever order and in whichever epochs the changes were queued, the
    /// next set is the same: queued entries are taken in address order.
    #[test]
    fn the_next_set_does_not_depend_on_the_order_changes_were_queued_in() {
        let base: Vec<_> = (0..3).map(|_| create_test_validator(1000)).collect();
        let adds: Vec<_> = (0..5).map(|_| create_test_validator(900)).collect();
        let drops = [base[0].address, base[1].address];
        let order = |perm: &[usize]| -> Vec<Address> {
            let manager = EpochManager::new(base.clone(), 100).unwrap();
            for i in perm {
                manager.add_pending_validator(adds[*i].clone());
            }
            let removals: Vec<Address> = if perm[0] % 2 == 0 {
                drops.to_vec()
            } else {
                drops.iter().rev().copied().collect()
            };
            for d in &removals {
                manager.remove_pending_validator(d);
            }
            manager
                .transition_epoch(BlockHeight::from(100))
                .unwrap()
                .unwrap()
                .iter()
                .map(|v| v.address)
                .collect()
        };
        let first = order(&[0, 1, 2, 3, 4]);
        for perm in [[4, 3, 2, 1, 0], [2, 0, 4, 1, 3], [1, 3, 0, 4, 2]] {
            assert_eq!(order(&perm), first);
        }
    }
}
