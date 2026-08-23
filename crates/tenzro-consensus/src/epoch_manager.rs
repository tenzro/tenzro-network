//! Epoch management for validator set transitions

use crate::error::{ConsensusError, Result};
use crate::validator::{ValidatorInfo, ValidatorSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::primitives::{Address, BlockHeight, Hash, Timestamp};

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
}

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

    /// Deterministic leader-election seed anchor for this epoch.
    ///
    /// Fixed at transition time to the finalized block hash at the
    /// canonical epoch boundary height (`number * epoch_duration`), so
    /// every node derives the identical reputation seed for every view in
    /// the epoch regardless of where its local finalized tip currently
    /// sits. Epoch 0 uses `Hash::default()` (genesis has no prior
    /// finalized block).
    pub seed_anchor: Hash,
}

impl Epoch {
    /// Creates a new epoch
    pub fn new(
        number: u64,
        start_height: BlockHeight,
        end_height: BlockHeight,
        validator_set: ValidatorSet,
        seed_anchor: Hash,
    ) -> Self {
        Self {
            number,
            start_height,
            end_height,
            validator_set,
            start_time: Timestamp::now(),
            seed_anchor,
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
    /// New entrants are subject to the per-transition churn budget — see
    /// `transition_epoch`. Entries beyond the budget stay queued (FIFO)
    /// and apply at subsequent transitions.
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
    /// rejection (the May 2026 testnet stall).
    pub fn new(initial_validators: Vec<ValidatorInfo>, epoch_duration: u64) -> Result<Self> {
        let validator_set = ValidatorSet::new(0, initial_validators)?;

        let current_epoch = Epoch::new(
            0,
            BlockHeight::from(0),
            BlockHeight::from(epoch_duration),
            validator_set,
            Hash::default(),
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
        let persisted = store.load_all_epochs()?;

        let (current_epoch, history) = if persisted.is_empty() {
            // Fresh node: bootstrap epoch 0 and write it through.
            let validator_set = ValidatorSet::new(0, initial_validators)?;
            let epoch = Epoch::new(
                0,
                BlockHeight::from(0),
                BlockHeight::from(epoch_duration),
                validator_set,
                Hash::default(),
            );
            let bytes = bincode::serialize(&epoch)
                .map_err(|e| ConsensusError::Internal(format!("bootstrap epoch 0 encode: {e}")))?;
            if let Err(e) = store.put_epoch(0, bytes) {
                tracing::warn!(error = %e, "Failed to persist bootstrap epoch 0; continuing in-memory");
            }
            (epoch, Vec::new())
        } else {
            // Decode all, sort by epoch number (defensive — store may not order).
            // Records persisted under an older Epoch schema fail to decode;
            // drop them (logged) — the canonical-schedule walk in
            // `transition_epoch` re-derives the live epoch from observed
            // heights, so losing stale records only costs history depth.
            let mut decoded: Vec<Epoch> = persisted
                .into_iter()
                .filter_map(|bytes| match bincode::deserialize::<Epoch>(&bytes) {
                    Ok(epoch) => Some(epoch),
                    Err(e) => {
                        tracing::warn!(error = %e, "Dropping undecodable persisted epoch record (schema change); canonical walk will re-derive");
                        None
                    }
                })
                .collect();
            decoded.sort_by_key(|e| e.number);

            let Some(current) = decoded.pop() else {
                // Every persisted record was undecodable — bootstrap fresh.
                let validator_set = ValidatorSet::new(0, initial_validators)?;
                let epoch = Epoch::new(
                    0,
                    BlockHeight::from(0),
                    BlockHeight::from(epoch_duration),
                    validator_set,
                    Hash::default(),
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
                tracing::warn!(
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
    /// - **Entrants**: newly-joining stake is capped at half the continuing
    ///   stake, so continuing validators hold ≥ 2/3 of the NEW set's total
    ///   voting power and a fresh entrant cannot immediately own a blocking
    ///   minority.
    ///
    /// Stake updates for continuing validators (upserts of addresses
    /// already in the set) are not churn and are never deferred. Entries
    /// beyond the budget stay queued (FIFO) and apply at subsequent
    /// transitions, so admission remains permissionless — large joins and
    /// exits are spread across epochs, never censored. Progress guarantee:
    /// the first queued removal and the first queued entrant always apply
    /// even when they alone exceed the budget (a slashed validator holding
    /// more than the budget must still be removable; a bootstrap-size set
    /// must still be joinable), with a warning logged.
    ///
    /// Returns `Ok(None)` when the canonical epoch index for `height`
    /// (`height / epoch_duration`) is not ahead of the current epoch
    /// number — including the case where a concurrent caller won the
    /// race and already transitioned. The due-check runs under the same
    /// write lock as the transition itself, so two racing callers (the
    /// engine's finalize path and the node's follower path) resolve to
    /// exactly one transition.
    ///
    /// `anchor_of` resolves the finalized block hash at the new epoch's
    /// canonical boundary height — it is invoked inside the critical
    /// section with the exact boundary of the epoch being created, so a
    /// caller racing another transition can never pair an anchor with the
    /// wrong epoch number. Returning `None` falls back to
    /// `Hash::default()` (logged), which only happens when neither the
    /// in-memory finality tracker nor durable block storage has the
    /// boundary block.
    pub fn transition_epoch<F>(
        &self,
        height: BlockHeight,
        anchor_of: F,
    ) -> Result<Option<ValidatorSet>>
    where
        F: FnOnce(BlockHeight) -> Option<Hash>,
    {
        self.transition_epoch_timed(height, false, anchor_of)
    }

    /// As [`Self::transition_epoch`], but `time_due` also authorises the
    /// transition when the height schedule has not been reached.
    ///
    /// The caller decides that, because deciding it here would mean reading a
    /// clock, and the only clock every node agrees on is the one carried by
    /// the blocks themselves. See [`MAX_EPOCH_DURATION_MS`].
    pub fn transition_epoch_timed<F>(
        &self,
        height: BlockHeight,
        time_due: bool,
        anchor_of: F,
    ) -> Result<Option<ValidatorSet>>
    where
        F: FnOnce(BlockHeight) -> Option<Hash>,
    {
        // Acquire write lock for atomic transition
        // This prevents any concurrent reads or writes to the current epoch
        let mut current = self.current_epoch.write();

        // Canonical due-check: derived from the height-based schedule, NOT
        // from `current.end_height`. A current epoch carrying drifted
        // boundaries (persisted by an earlier buggy transition) must not be
        // able to pin the node off-schedule — see `should_transition`.
        let height_due = height.as_u64() / self.epoch_duration > current.number;
        if !height_due && !time_due {
            return Ok(None);
        }

        let next_epoch_number = current.number + 1;

        // Compute next validator set as: current set, with churn-budgeted
        // pending_removals dropped, then pending_validators upserted
        // (matching address replaces; new address appends subject to the
        // entrant budget). Pending entries are deltas rather than a full
        // replacement, so a single stake event doesn't reset the set.
        let pending_adds: Vec<ValidatorInfo> = self.pending_validators.read().clone();
        let pending_drops: Vec<Address> = self.pending_removals.read().clone();

        let old_set = &current.validator_set;
        let old_total_stake = old_set.total_stake();

        // Phase 1 — removals, FIFO, capped at 1/3 of outgoing stake so
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

        // Phase 2 — survivors, then upserts of continuing members. Stake
        // updates for addresses already in the set are not churn.
        let mut next_validators: Vec<ValidatorInfo> = old_set
            .iter()
            .filter(|v| !applied_drops.iter().any(|a| a == &v.address))
            .cloned()
            .collect();

        let mut applied_add_addrs: Vec<Address> = Vec::new();
        let mut entrant_candidates: Vec<ValidatorInfo> = Vec::new();
        for upsert in pending_adds {
            if let Some(existing) = next_validators
                .iter_mut()
                .find(|v| v.address == upsert.address)
            {
                applied_add_addrs.push(upsert.address);
                *existing = upsert;
            } else {
                entrant_candidates.push(upsert);
            }
        }

        // Phase 3 — new entrants, FIFO, capped at half the continuing
        // stake so continuing validators hold ≥ 2/3 of the new total.
        let continuing_stake: u128 = next_validators.iter().map(|v| v.stake).sum();
        let entrant_budget = continuing_stake / 2;
        let mut entrant_stake: u128 = 0;
        let mut admitted_entrants = 0usize;
        let mut deferred_add_count = 0usize;
        for entrant in entrant_candidates {
            let cumulative = entrant_stake.saturating_add(entrant.stake);
            if cumulative <= entrant_budget || admitted_entrants == 0 {
                if cumulative > entrant_budget {
                    tracing::warn!(
                        address = %entrant.address,
                        stake = entrant.stake,
                        entrant_budget,
                        "Entrant stake exceeds the per-epoch churn budget on its own; admitting for progress (admission must not be censorable)"
                    );
                }
                entrant_stake = cumulative;
                admitted_entrants += 1;
                applied_add_addrs.push(entrant.address);
                next_validators.push(entrant);
            } else {
                deferred_add_count += 1;
            }
        }

        // Create new validator set - this can fail, so we do it before modifying state
        let validator_set = ValidatorSet::new(next_epoch_number, next_validators)?;

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

        // Resolve the deterministic leader-election seed anchor: the
        // finalized block hash at the canonical boundary. Every node
        // resolves the same hash for the same epoch, so reputation seeds
        // (and therefore elected leaders) are identical fleet-wide.
        let seed_anchor = anchor_of(start_height).unwrap_or_else(|| {
            tracing::warn!(
                epoch = next_epoch_number,
                boundary = %start_height,
                "Boundary block hash unavailable at epoch transition; using default seed anchor"
            );
            Hash::default()
        });

        // Create new epoch
        let new_epoch = Epoch::new(
            next_epoch_number,
            start_height,
            end_height,
            validator_set.clone(),
            seed_anchor,
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

        self.find_in_store(|e| e.number == epoch_number)
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

    /// Scans the persistent store for an epoch matching `pred`.
    ///
    /// Fallback for lookups that miss the in-memory working set (current +
    /// bounded history). Scans newest-first because callers overwhelmingly
    /// ask about recent heights (block-sync import across a boundary just
    /// outside the in-memory window). Returns `None` when no store is
    /// attached or nothing matches.
    fn find_in_store(&self, pred: impl Fn(&Epoch) -> bool) -> Option<Epoch> {
        let store = self.store.as_ref()?;
        let records = match store.load_all_epochs() {
            Ok(records) => records,
            Err(e) => {
                tracing::warn!(error = %e, "Epoch store scan failed");
                return None;
            }
        };

        records
            .iter()
            .rev()
            .find_map(|bytes| match bincode::deserialize::<Epoch>(bytes) {
                Ok(epoch) if pred(&epoch) => Some(epoch),
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!(error = %e, "Skipping undecodable epoch record in store");
                    None
                }
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::bls::BlsKeyPair;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::{KeyPair, KeyType};

    fn create_test_validator(stake: u128) -> ValidatorInfo {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = tenzro_types::primitives::Address::new(addr_bytes);
        let pq = MlDsaSigningKey::generate();
        let bls = BlsKeyPair::generate().unwrap();
        ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            bls.public_key().to_bytes().to_vec(),
            stake,
        )
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
                .transition_epoch(BlockHeight::from(30), |_| None)
                .unwrap()
                .is_none(),
            "without the time authorisation this must stay a no-op"
        );

        assert!(
            manager
                .transition_epoch_timed(BlockHeight::from(30), true, |_| None)
                .unwrap()
                .is_some()
        );
        assert_eq!(manager.current_epoch().number, 1);
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
            .transition_epoch_timed(BlockHeight::from(30), true, |_| None)
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
            .transition_epoch_timed(BlockHeight::from(30), true, |_| None)
            .unwrap()
            .expect("time-authorised transition");

        // Epoch 1 now; the canonical rule is `height / 100 > 1`, so 200 is the
        // next height-triggered boundary and 150 is not one.
        assert!(!manager.should_transition(BlockHeight::from(150)));
        assert!(manager.should_transition(BlockHeight::from(200)));

        manager
            .transition_epoch(BlockHeight::from(200), |_| None)
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
                .transition_epoch(BlockHeight::from(50), |_| None)
                .unwrap()
                .is_none()
        );
        assert_eq!(manager.current_epoch().number, 0);

        // Transition to next epoch
        let new_validators = manager
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap();
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
        let next = manager
            .transition_epoch(BlockHeight::from(789), |_| None)
            .unwrap();
        assert!(next.is_some());

        let epoch = manager.current_epoch();
        assert_eq!(epoch.number, 1);
        assert_eq!(epoch.start_height, BlockHeight::from(100));
        assert_eq!(epoch.end_height, BlockHeight::from(200));

        // Walking forward (multi-epoch catch-up) keeps converging on the
        // canonical schedule.
        while manager.should_transition(BlockHeight::from(789)) {
            manager
                .transition_epoch(BlockHeight::from(789), |_| None)
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

        let v3 = create_test_validator(4000);
        manager.add_pending_validator(v3.clone());
        assert_eq!(manager.pending_validators().len(), 1);

        let next = manager
            .transition_epoch(BlockHeight::from(100), |_| None)
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
            .transition_epoch(BlockHeight::from(100), |_| None)
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
        let v0_pq = v0.pq_public_key.clone();
        let v0_bls = v0.bls_public_key.clone();
        let manager = EpochManager::new(vec![v0.clone()], 100).unwrap();

        // Same address, larger stake
        let v0_updated = ValidatorInfo::new(v0_addr, v0_pk, v0_pq, v0_bls, 5000);
        manager.add_pending_validator(v0_updated);

        let next = manager
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap()
            .expect("transition due");

        assert_eq!(next.len(), 1, "upsert must not duplicate");
        let only = next.get(0).unwrap();
        assert_eq!(only.address, v0_addr);
        assert_eq!(only.stake, 5000, "stake must be updated to new value");
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
            .transition_epoch(BlockHeight::from(100), |_| None)
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
        let v0_pq = v0.pq_public_key.clone();
        let v0_bls = v0.bls_public_key.clone();
        let manager = EpochManager::new(vec![v0.clone()], 100).unwrap();

        manager.remove_pending_validator(&v0_addr);
        // Now re-stake same address with new amount
        let v0_restaked = ValidatorInfo::new(v0_addr, v0_pk, v0_pq, v0_bls, 7777);
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
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 1);
        assert_eq!(next.get(0).unwrap().stake, 7777);
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
            .transition_epoch(BlockHeight::from(100), |_| None)
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
            .transition_epoch(BlockHeight::from(200), |_| None)
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 3);
        assert_eq!(manager.pending_removals().len(), 1);

        // Next: total 3000, budget 1000 → last removal applies, queue drains.
        let next = manager
            .transition_epoch(BlockHeight::from(300), |_| None)
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
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 1);
        assert!(!next.is_validator(&whale.address));
        assert!(manager.pending_removals().is_empty());
    }

    #[test]
    fn test_entrant_churn_capped_and_deferred() {
        // 3 validators × 1000 (continuing 3000, entrant budget 1500).
        // First 1000-stake entrant fits; the second would push entrant
        // stake to 2000 > 1500 and is deferred to the next epoch.
        let validators: Vec<ValidatorInfo> = (0..3).map(|_| create_test_validator(1000)).collect();
        let manager = EpochManager::new(validators, 100).unwrap();

        let a = create_test_validator(1000);
        let b = create_test_validator(1000);
        manager.add_pending_validator(a.clone());
        manager.add_pending_validator(b.clone());

        let next = manager
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 4);
        assert!(next.is_validator(&a.address));
        assert!(!next.is_validator(&b.address));
        assert_eq!(
            manager.pending_validators().len(),
            1,
            "excess entrant deferred"
        );

        // Next epoch: continuing 4000, budget 2000 → deferred entrant joins.
        let next = manager
            .transition_epoch(BlockHeight::from(200), |_| None)
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 5);
        assert!(next.is_validator(&b.address));
        assert!(manager.pending_validators().is_empty());
    }

    #[test]
    fn test_oversized_entrant_admitted_for_progress() {
        // A bootstrap-size set must remain joinable: the first entrant is
        // admitted even when its stake alone exceeds the budget.
        let genesis = create_test_validator(1000);
        let manager = EpochManager::new(vec![genesis], 100).unwrap();

        let whale = create_test_validator(100_000);
        manager.add_pending_validator(whale.clone());

        let next = manager
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 2);
        assert!(next.is_validator(&whale.address));
        assert!(manager.pending_validators().is_empty());
    }

    #[test]
    fn test_upsert_does_not_consume_entrant_budget() {
        // A stake update for a continuing member is not churn: it applies
        // unconditionally and its raised stake widens the entrant budget.
        let v0 = create_test_validator(1000);
        let v1 = create_test_validator(1000);
        let manager = EpochManager::new(vec![v0.clone(), v1], 100).unwrap();

        let v0_restaked = ValidatorInfo::new(
            v0.address,
            v0.public_key.clone(),
            v0.pq_public_key.clone(),
            v0.bls_public_key.clone(),
            9000,
        );
        manager.add_pending_validator(v0_restaked);

        // Two entrants totalling 5000. Without the upsert, continuing
        // stake is 2000 (budget 1000): the first entrant would only get in
        // via the progress guarantee and the second would be deferred.
        // With the upsert applied first, continuing stake is 10000
        // (budget 5000) and BOTH entrants fit within the budget.
        let e1 = create_test_validator(3000);
        let e2 = create_test_validator(2000);
        manager.add_pending_validator(e1.clone());
        manager.add_pending_validator(e2.clone());

        let next = manager
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap()
            .expect("transition due");
        assert_eq!(next.len(), 4);
        assert_eq!(
            next.get_by_address(&v0.address).unwrap().stake,
            9000,
            "upsert applied"
        );
        assert!(next.is_validator(&e1.address));
        assert!(next.is_validator(&e2.address));
        assert!(manager.pending_validators().is_empty());
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
            Hash::default(),
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
                .transition_epoch(tip, |_| None)
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

        manager
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap();
        manager
            .transition_epoch(BlockHeight::from(200), |_| None)
            .unwrap();

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

        manager
            .transition_epoch(BlockHeight::from(100), |_| None)
            .unwrap();

        // Height 50 should be in epoch 0
        let epoch = manager.get_epoch_for_height(BlockHeight::from(50));
        assert!(epoch.is_some());
        assert_eq!(epoch.unwrap().number, 0);

        // Height 150 should be in epoch 1
        let epoch = manager.get_epoch_for_height(BlockHeight::from(150));
        assert!(epoch.is_some());
        assert_eq!(epoch.unwrap().number, 1);
    }
}
