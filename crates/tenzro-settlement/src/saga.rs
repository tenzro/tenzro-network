//! DvP (delivery-versus-payment) saga orchestrator.
//!
//! A [`DvpSaga`] bundles multiple settlement legs — native transfers, escrow
//! releases, channel updates, or external (bridge/Canton) movements — into an
//! all-or-compensate unit. The orchestrator drives legs strictly in order
//! through a venue-agnostic [`LegExecutor`] implemented by the node layer.
//! On any leg failure, already-executed legs are compensated in reverse order.
//!
//! # State machine
//!
//! ```text
//! Open ──▶ Executing ──▶ Verifying ──▶ Finalized
//!   │          │             │
//!   │          ├──▶ Compensating ──▶ Compensated
//!   │          │             └─────▶ Aborted
//!   │          └──▶ Expired   (via Compensating for executed legs)
//!   └──▶ Expired / Aborted
//! ```
//!
//! Terminal states: `Finalized`, `Compensated`, `Aborted`, `Expired`.
//! Re-driving a saga in a terminal state returns its record unchanged;
//! re-executing an already-executed leg is a no-op via `leg_results`.
//!
//! # Persistence
//!
//! When constructed via [`SagaOrchestrator::with_storage`], records persist
//! to `CF_SETTLEMENTS` and rehydrate on construction:
//!
//! | Prefix                | Value                            |
//! |-----------------------|----------------------------------|
//! | `saga:<id>`           | `DvpSaga` (JSON)                 |
//! | `saga_creator:<addr>` | `Vec<String>` of saga IDs (JSON) |

use crate::error::{Result, SettlementError};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::{CF_SETTLEMENTS, KvStore, WriteOp};
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{debug, info, warn};

/// Storage key prefix for `DvpSaga` records in `CF_SETTLEMENTS`.
const SAGA_KEY_PREFIX: &[u8] = b"saga:";
/// Storage key prefix for the per-creator index of saga IDs.
const SAGA_CREATOR_KEY_PREFIX: &[u8] = b"saga_creator:";
/// Domain tag for saga id derivation.
const SAGA_ID_DOMAIN: &[u8] = b"tenzro/settlement/saga";

/// Where a settlement leg executes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegVenue {
    /// Native TNZO ledger transfer.
    Native,
    /// Release of a pre-funded on-chain escrow.
    Escrow {
        /// Escrow identifier (hex, VM-derived).
        escrow_id: String,
    },
    /// Micropayment channel update.
    Channel {
        /// Channel identifier.
        channel_id: String,
    },
    /// Bridge / Canton / other externally-executed leg.
    External {
        /// Venue-specific reference resolved by the node-layer executor.
        reference: String,
    },
}

/// A single delivery or payment leg of a DvP saga.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaLeg {
    /// Unique (within the saga) leg identifier.
    pub leg_id: String,
    /// Party delivering the asset.
    pub payer: Address,
    /// Party receiving the asset.
    pub payee: Address,
    /// CAIP-19-style asset identifier.
    pub asset: String,
    /// Amount in the asset's base units.
    pub amount: u128,
    /// Execution venue.
    pub venue: LegVenue,
}

/// Saga lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaState {
    /// Created, not yet driven.
    Open,
    /// Legs executing in order; `current_leg` is the index being driven.
    Executing {
        /// Index of the leg currently being executed.
        current_leg: usize,
    },
    /// All legs executed; awaiting finalization.
    Verifying,
    /// All legs executed and finalized. Terminal.
    Finalized,
    /// A leg failed; executed legs are being compensated in reverse order.
    Compensating {
        /// Index of the leg whose failure triggered compensation.
        failed_leg: usize,
    },
    /// All executed legs compensated after a failure. Terminal.
    Compensated,
    /// Unrecoverable failure (e.g. compensation itself failed). Terminal.
    Aborted {
        /// Human-readable abort reason.
        reason: String,
    },
    /// Expired before completion; executed legs were compensated. Terminal.
    Expired,
}

impl SagaState {
    /// Whether the state is terminal (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SagaState::Finalized
                | SagaState::Compensated
                | SagaState::Aborted { .. }
                | SagaState::Expired
        )
    }

    /// Whether transitioning from `self` to `next` is legal.
    pub fn can_transition_to(&self, next: &SagaState) -> bool {
        use SagaState::*;
        matches!(
            (self, next),
            (Open, Executing { .. })
                | (Open, Aborted { .. })
                | (Open, Expired)
                | (Executing { .. }, Executing { .. })
                | (Executing { .. }, Verifying)
                | (Executing { .. }, Compensating { .. })
                | (Executing { .. }, Expired)
                | (Verifying, Finalized)
                | (Verifying, Compensating { .. })
                | (Compensating { .. }, Compensated)
                | (Compensating { .. }, Aborted { .. })
                | (Compensating { .. }, Expired)
        )
    }
}

impl std::fmt::Display for SagaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SagaState::Open => write!(f, "Open"),
            SagaState::Executing { current_leg } => write!(f, "Executing({current_leg})"),
            SagaState::Verifying => write!(f, "Verifying"),
            SagaState::Finalized => write!(f, "Finalized"),
            SagaState::Compensating { failed_leg } => write!(f, "Compensating({failed_leg})"),
            SagaState::Compensated => write!(f, "Compensated"),
            SagaState::Aborted { reason } => write!(f, "Aborted({reason})"),
            SagaState::Expired => write!(f, "Expired"),
        }
    }
}

/// Receipt produced by a [`LegExecutor`] for a successfully executed leg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegReceipt {
    /// Leg this receipt belongs to.
    pub leg_id: String,
    /// Venue-specific reference (tx hash, escrow id, channel nonce, ...).
    pub reference: String,
    /// Execution time.
    pub executed_at: Timestamp,
}

/// Outcome of driving one leg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LegOutcome {
    /// Leg executed; receipt recorded.
    Executed,
    /// Leg execution failed.
    Failed {
        /// Executor-reported failure reason.
        reason: String,
    },
    /// Previously-executed leg was compensated after a downstream failure.
    Compensated,
    /// Compensation of a previously-executed leg failed.
    CompensationFailed {
        /// Executor-reported failure reason.
        reason: String,
    },
}

/// Per-leg execution record on a saga.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegResult {
    /// Leg identifier.
    pub leg_id: String,
    /// Current outcome.
    pub outcome: LegOutcome,
    /// Receipt from execution, if the leg executed.
    pub receipt: Option<LegReceipt>,
}

/// A delivery-versus-payment saga.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DvpSaga {
    /// `hex(SHA-256("tenzro/settlement/saga" || creator || nonce_le))`.
    pub saga_id: String,
    /// Address that opened the saga.
    pub creator: Address,
    /// Ordered legs.
    pub legs: Vec<SagaLeg>,
    /// Lifecycle state.
    pub state: SagaState,
    /// Creation time.
    pub created_at: Timestamp,
    /// Expiry deadline; Open/Executing sagas past this compensate.
    pub expires_at: Timestamp,
    /// Per-leg execution records, in execution order.
    pub leg_results: Vec<LegResult>,
}

impl DvpSaga {
    /// Whether the saga is past its expiry deadline.
    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.expires_at
    }

    /// Applies a state transition, enforcing legality.
    fn transition(&mut self, next: SagaState) -> Result<()> {
        if !self.state.can_transition_to(&next) {
            return Err(SettlementError::IllegalSagaTransition {
                saga_id: self.saga_id.clone(),
                from: self.state.to_string(),
                to: next.to_string(),
            });
        }
        debug!(
            "Saga {} transition {} -> {}",
            self.saga_id, self.state, next
        );
        self.state = next;
        Ok(())
    }

    /// Executed-leg result lookup by leg id.
    fn executed_result(&self, leg_id: &str) -> Option<&LegResult> {
        self.leg_results
            .iter()
            .find(|r| r.leg_id == leg_id && r.outcome == LegOutcome::Executed)
    }
}

/// Computes a deterministic saga id from creator and nonce.
pub fn compute_saga_id(creator: &Address, nonce: u64) -> String {
    let mut preimage = Vec::with_capacity(SAGA_ID_DOMAIN.len() + 32 + 8);
    preimage.extend_from_slice(SAGA_ID_DOMAIN);
    preimage.extend_from_slice(creator.as_bytes());
    preimage.extend_from_slice(&nonce.to_le_bytes());
    hex::encode(tenzro_crypto::hash::sha256(&preimage).as_bytes())
}

/// Venue-agnostic leg executor implemented by the node layer against
/// escrow / channels / bridges / Canton.
#[async_trait]
pub trait LegExecutor: Send + Sync {
    /// Executes a leg, returning a venue-specific receipt.
    async fn execute(&self, leg: &SagaLeg) -> Result<LegReceipt>;
    /// Reverses a previously-executed leg using its receipt.
    async fn compensate(&self, leg: &SagaLeg, receipt: &LegReceipt) -> Result<()>;
}

/// RAII marker preventing concurrent drives of the same saga.
struct InFlightGuard<'a> {
    set: &'a DashMap<String, ()>,
    saga_id: String,
}

impl<'a> InFlightGuard<'a> {
    fn acquire(set: &'a DashMap<String, ()>, saga_id: &str) -> Result<Self> {
        if set.insert(saga_id.to_string(), ()).is_some() {
            return Err(SettlementError::SagaError(format!(
                "saga {saga_id} is already being driven"
            )));
        }
        Ok(Self {
            set,
            saga_id: saga_id.to_string(),
        })
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.set.remove(&self.saga_id);
    }
}

/// Orchestrator for DvP sagas.
pub struct SagaOrchestrator {
    /// Sagas by id.
    sagas: DashMap<String, DvpSaga>,
    /// Saga ids by creator.
    sagas_by_creator: DashMap<Address, Vec<String>>,
    /// Sagas currently being driven (concurrency guard).
    in_flight: DashMap<String, ()>,
    /// Optional persistent storage backend.
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for SagaOrchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SagaOrchestrator")
            .field("sagas", &self.sagas.len())
            .field("in_flight", &self.in_flight.len())
            .field(
                "storage",
                &self.storage.as_ref().map(|_| "Some(Arc<dyn KvStore>)"),
            )
            .finish()
    }
}

impl Default for SagaOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl SagaOrchestrator {
    /// Creates an in-memory orchestrator (no persistence).
    pub fn new() -> Self {
        Self {
            sagas: DashMap::new(),
            sagas_by_creator: DashMap::new(),
            in_flight: DashMap::new(),
            storage: None,
        }
    }

    /// Creates an orchestrator backed by RocksDB; rehydrates `saga:` records
    /// from `CF_SETTLEMENTS` on construction.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let orch = Self {
            sagas: DashMap::new(),
            sagas_by_creator: DashMap::new(),
            in_flight: DashMap::new(),
            storage: Some(storage),
        };
        orch.hydrate();
        orch
    }

    fn saga_storage_key(saga_id: &str) -> Vec<u8> {
        [SAGA_KEY_PREFIX, saga_id.as_bytes()].concat()
    }

    fn creator_index_key(addr: &Address) -> Vec<u8> {
        [
            SAGA_CREATOR_KEY_PREFIX,
            hex::encode(addr.as_bytes()).as_bytes(),
        ]
        .concat()
    }

    fn hydrate(&self) {
        let storage = match &self.storage {
            Some(s) => s,
            None => return,
        };
        let keys = match storage.get_keys_with_prefix(CF_SETTLEMENTS, SAGA_KEY_PREFIX) {
            Ok(keys) => keys,
            Err(e) => {
                warn!("Failed to scan CF_SETTLEMENTS for saga hydration: {}", e);
                return;
            }
        };

        let mut hydrated = 0usize;
        for key_bytes in &keys {
            match storage.get(CF_SETTLEMENTS, key_bytes) {
                Ok(Some(data)) => match serde_json::from_slice::<DvpSaga>(&data) {
                    Ok(saga) => {
                        self.sagas_by_creator
                            .entry(saga.creator)
                            .or_default()
                            .push(saga.saga_id.clone());
                        self.sagas.insert(saga.saga_id.clone(), saga);
                        hydrated += 1;
                    }
                    Err(e) => {
                        let key_str = std::str::from_utf8(key_bytes).unwrap_or("<binary>");
                        warn!("Failed to deserialize saga at key {}: {}", key_str, e);
                    }
                },
                Ok(None) => {}
                Err(e) => warn!("Storage read failure during saga hydration: {}", e),
            }
        }
        if hydrated > 0 {
            info!("Hydrated {} saga(s) from RocksDB CF_SETTLEMENTS", hydrated);
        }
    }

    /// Atomically persists a saga record and (optionally) its creator index.
    fn persist_saga_atomic(&self, saga: &DvpSaga, index_changed: bool) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };
        let saga_data = serde_json::to_vec(saga)
            .map_err(|e| SettlementError::StorageError(format!("serialize saga: {}", e)))?;
        let mut ops = vec![WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: Self::saga_storage_key(&saga.saga_id),
            value: saga_data,
        }];
        if index_changed {
            let ids: Vec<String> = self
                .sagas_by_creator
                .get(&saga.creator)
                .map(|v| v.value().clone())
                .unwrap_or_default();
            let index_data = serde_json::to_vec(&ids).map_err(|e| {
                SettlementError::StorageError(format!("serialize creator index: {}", e))
            })?;
            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: Self::creator_index_key(&saga.creator),
                value: index_data,
            });
        }
        storage
            .write_batch_sync(ops)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Writes the working copy back into the index and storage.
    fn checkpoint(&self, saga: &DvpSaga) -> Result<()> {
        self.sagas.insert(saga.saga_id.clone(), saga.clone());
        self.persist_saga_atomic(saga, false)
    }

    /// Opens a saga. Idempotent: reopening the same `(creator, nonce)`
    /// returns the existing record.
    pub fn open_saga(
        &self,
        creator: Address,
        nonce: u64,
        legs: Vec<SagaLeg>,
        expires_at: Timestamp,
    ) -> Result<DvpSaga> {
        let saga_id = compute_saga_id(&creator, nonce);
        if let Some(existing) = self.sagas.get(&saga_id) {
            return Ok(existing.value().clone());
        }

        if legs.is_empty() {
            return Err(SettlementError::SagaError(
                "saga must have at least one leg".to_string(),
            ));
        }
        if expires_at <= Timestamp::now() {
            return Err(SettlementError::SagaExpired(saga_id));
        }
        let mut seen = std::collections::HashSet::new();
        for leg in &legs {
            if leg.leg_id.is_empty() {
                return Err(SettlementError::SagaError("empty leg_id".to_string()));
            }
            if !seen.insert(leg.leg_id.as_str()) {
                return Err(SettlementError::SagaError(format!(
                    "duplicate leg_id: {}",
                    leg.leg_id
                )));
            }
            if leg.amount == 0 {
                return Err(SettlementError::InvalidAmount(format!(
                    "leg {} amount must be greater than zero",
                    leg.leg_id
                )));
            }
            if leg.payer == leg.payee {
                return Err(SettlementError::SagaError(format!(
                    "leg {} payer equals payee",
                    leg.leg_id
                )));
            }
        }

        let saga = DvpSaga {
            saga_id: saga_id.clone(),
            creator,
            legs,
            state: SagaState::Open,
            created_at: Timestamp::now(),
            expires_at,
            leg_results: Vec::new(),
        };

        self.sagas.insert(saga_id.clone(), saga.clone());
        self.sagas_by_creator
            .entry(creator)
            .or_default()
            .push(saga_id.clone());
        self.persist_saga_atomic(&saga, true)?;

        info!(
            "Opened DvP saga {} with {} leg(s) for creator {}",
            saga_id,
            saga.legs.len(),
            creator
        );
        Ok(saga)
    }

    /// Drives the saga through its legs in order. All-or-compensate: on any
    /// leg failure, already-executed legs are compensated in reverse order.
    ///
    /// Idempotent: a saga in a terminal state (or `Verifying`) returns its
    /// record; legs with an `Executed` result are skipped on resume.
    pub async fn execute(&self, saga_id: &str, executor: &dyn LegExecutor) -> Result<DvpSaga> {
        let _guard = InFlightGuard::acquire(&self.in_flight, saga_id)?;

        let mut saga = self
            .sagas
            .get(saga_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| SettlementError::SagaNotFound(saga_id.to_string()))?;

        if saga.state.is_terminal() || saga.state == SagaState::Verifying {
            return Ok(saga);
        }

        if saga.is_expired() {
            self.run_expiry(&mut saga, executor).await?;
            return Ok(saga);
        }

        for i in 0..saga.legs.len() {
            let leg = saga.legs[i].clone();
            if saga.executed_result(&leg.leg_id).is_some() {
                debug!(
                    "Saga {} leg {} already executed; skipping",
                    saga_id, leg.leg_id
                );
                continue;
            }

            saga.transition(SagaState::Executing { current_leg: i })?;
            self.checkpoint(&saga)?;

            match executor.execute(&leg).await {
                Ok(receipt) => {
                    saga.leg_results.push(LegResult {
                        leg_id: leg.leg_id.clone(),
                        outcome: LegOutcome::Executed,
                        receipt: Some(receipt),
                    });
                    self.checkpoint(&saga)?;
                }
                Err(e) => {
                    warn!("Saga {} leg {} failed: {}", saga_id, leg.leg_id, e);
                    saga.leg_results.push(LegResult {
                        leg_id: leg.leg_id.clone(),
                        outcome: LegOutcome::Failed {
                            reason: e.to_string(),
                        },
                        receipt: None,
                    });
                    saga.transition(SagaState::Compensating { failed_leg: i })?;
                    self.checkpoint(&saga)?;
                    self.compensate_executed(&mut saga, executor, None).await?;
                    return Ok(saga);
                }
            }
        }

        saga.transition(SagaState::Verifying)?;
        self.checkpoint(&saga)?;
        info!("Saga {} fully executed; awaiting finalization", saga_id);
        Ok(saga)
    }

    /// Compensates executed legs in reverse execution order, then moves the
    /// saga to `end_state` (default `Compensated`) or `Aborted` if any
    /// compensation fails. Assumes the saga is in `Compensating`.
    async fn compensate_executed(
        &self,
        saga: &mut DvpSaga,
        executor: &dyn LegExecutor,
        end_state: Option<SagaState>,
    ) -> Result<()> {
        let mut failure: Option<String> = None;

        // Reverse execution order over results with Executed outcome.
        let executed_indices: Vec<usize> = saga
            .leg_results
            .iter()
            .enumerate()
            .filter(|(_, r)| r.outcome == LegOutcome::Executed)
            .map(|(idx, _)| idx)
            .rev()
            .collect();

        for idx in executed_indices {
            let (leg_id, receipt) = {
                let result = &saga.leg_results[idx];
                (result.leg_id.clone(), result.receipt.clone())
            };
            let leg = match saga.legs.iter().find(|l| l.leg_id == leg_id) {
                Some(l) => l.clone(),
                None => {
                    failure = Some(format!("leg {leg_id} missing from saga definition"));
                    break;
                }
            };
            let receipt = match receipt {
                Some(r) => r,
                None => {
                    failure = Some(format!("executed leg {leg_id} has no receipt"));
                    break;
                }
            };
            match executor.compensate(&leg, &receipt).await {
                Ok(()) => {
                    saga.leg_results[idx].outcome = LegOutcome::Compensated;
                    self.checkpoint(saga)?;
                    debug!("Saga {} compensated leg {}", saga.saga_id, leg_id);
                }
                Err(e) => {
                    saga.leg_results[idx].outcome = LegOutcome::CompensationFailed {
                        reason: e.to_string(),
                    };
                    self.checkpoint(saga)?;
                    failure = Some(format!("compensation of leg {leg_id} failed: {e}"));
                    break;
                }
            }
        }

        match failure {
            Some(reason) => {
                warn!("Saga {} aborted: {}", saga.saga_id, reason);
                saga.transition(SagaState::Aborted { reason })?;
            }
            None => {
                let next = end_state.unwrap_or(SagaState::Compensated);
                info!("Saga {} compensated; -> {}", saga.saga_id, next);
                saga.transition(next)?;
            }
        }
        self.checkpoint(saga)?;
        Ok(())
    }

    /// Expiry path: compensates executed legs (if any) and marks `Expired`.
    async fn run_expiry(&self, saga: &mut DvpSaga, executor: &dyn LegExecutor) -> Result<()> {
        match saga.state.clone() {
            SagaState::Open => {
                saga.transition(SagaState::Expired)?;
                self.checkpoint(saga)?;
            }
            SagaState::Executing { current_leg } => {
                saga.transition(SagaState::Compensating {
                    failed_leg: current_leg,
                })?;
                self.checkpoint(saga)?;
                self.compensate_executed(saga, executor, Some(SagaState::Expired))
                    .await?;
            }
            other => {
                return Err(SettlementError::IllegalSagaTransition {
                    saga_id: saga.saga_id.clone(),
                    from: other.to_string(),
                    to: SagaState::Expired.to_string(),
                });
            }
        }
        info!("Saga {} expired", saga.saga_id);
        Ok(())
    }

    /// Finalizes a saga in `Verifying`. Idempotent for `Finalized`.
    pub fn finalize(&self, saga_id: &str) -> Result<DvpSaga> {
        let mut saga = self
            .sagas
            .get(saga_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| SettlementError::SagaNotFound(saga_id.to_string()))?;

        if saga.state == SagaState::Finalized {
            return Ok(saga);
        }
        saga.transition(SagaState::Finalized)?;
        self.checkpoint(&saga)?;
        info!("Saga {} finalized", saga_id);
        Ok(saga)
    }

    /// Compensates and expires every Open/Executing saga past its deadline.
    /// Returns the number of sagas expired.
    pub async fn expire_sweep(&self, executor: &dyn LegExecutor) -> usize {
        let expired_ids: Vec<String> = self
            .sagas
            .iter()
            .filter(|e| {
                let s = e.value();
                matches!(s.state, SagaState::Open | SagaState::Executing { .. }) && s.is_expired()
            })
            .map(|e| e.key().clone())
            .collect();

        let mut count = 0usize;
        for saga_id in expired_ids {
            let _guard = match InFlightGuard::acquire(&self.in_flight, &saga_id) {
                Ok(g) => g,
                Err(_) => continue,
            };
            let mut saga = match self.sagas.get(&saga_id).map(|e| e.value().clone()) {
                Some(s) => s,
                None => continue,
            };
            // Re-check under the guard.
            if !matches!(saga.state, SagaState::Open | SagaState::Executing { .. })
                || !saga.is_expired()
            {
                continue;
            }
            match self.run_expiry(&mut saga, executor).await {
                Ok(()) => count += 1,
                Err(e) => warn!("Failed to expire saga {}: {}", saga_id, e),
            }
        }
        if count > 0 {
            info!("Expired {} saga(s)", count);
        }
        count
    }

    /// Gets a saga by id.
    pub fn get_saga(&self, saga_id: &str) -> Result<DvpSaga> {
        self.sagas
            .get(saga_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| SettlementError::SagaNotFound(saga_id.to_string()))
    }

    /// Lists all sagas opened by a creator.
    pub fn get_sagas_by_creator(&self, creator: &Address) -> Vec<DvpSaga> {
        self.sagas_by_creator
            .get(creator)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.sagas.get(id).map(|e| e.value().clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use tenzro_storage::MemoryStore;

    fn addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    fn leg(id: &str, payer: u8, payee: u8, amount: u128) -> SagaLeg {
        SagaLeg {
            leg_id: id.to_string(),
            payer: addr(payer),
            payee: addr(payee),
            asset: "tenzro:1337/slip44:0".to_string(),
            amount,
            venue: LegVenue::Native,
        }
    }

    fn future_ts() -> Timestamp {
        Timestamp::new(Timestamp::now().as_millis() + 3_600_000)
    }

    #[derive(Default)]
    struct MockExecutor {
        fail_execute_on: Option<String>,
        fail_compensate_on: Option<String>,
        executed: Mutex<Vec<String>>,
        compensated: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl LegExecutor for MockExecutor {
        async fn execute(&self, leg: &SagaLeg) -> Result<LegReceipt> {
            if self.fail_execute_on.as_deref() == Some(leg.leg_id.as_str()) {
                return Err(SettlementError::PaymentFailed(format!(
                    "mock failure on {}",
                    leg.leg_id
                )));
            }
            self.executed.lock().push(leg.leg_id.clone());
            Ok(LegReceipt {
                leg_id: leg.leg_id.clone(),
                reference: format!("ref-{}", leg.leg_id),
                executed_at: Timestamp::now(),
            })
        }

        async fn compensate(&self, leg: &SagaLeg, receipt: &LegReceipt) -> Result<()> {
            assert_eq!(receipt.leg_id, leg.leg_id);
            if self.fail_compensate_on.as_deref() == Some(leg.leg_id.as_str()) {
                return Err(SettlementError::PaymentFailed(format!(
                    "mock compensation failure on {}",
                    leg.leg_id
                )));
            }
            self.compensated.lock().push(leg.leg_id.clone());
            Ok(())
        }
    }

    #[test]
    fn saga_id_is_deterministic() {
        let a = compute_saga_id(&addr(1), 7);
        let b = compute_saga_id(&addr(1), 7);
        let c = compute_saga_id(&addr(1), 8);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn state_machine_legality() {
        use SagaState::*;
        assert!(Open.can_transition_to(&Executing { current_leg: 0 }));
        assert!(Open.can_transition_to(&Expired));
        assert!(Executing { current_leg: 0 }.can_transition_to(&Executing { current_leg: 1 }));
        assert!(Executing { current_leg: 1 }.can_transition_to(&Verifying));
        assert!(Executing { current_leg: 1 }.can_transition_to(&Compensating { failed_leg: 1 }));
        assert!(Verifying.can_transition_to(&Finalized));
        assert!(Compensating { failed_leg: 0 }.can_transition_to(&Compensated));
        assert!(Compensating { failed_leg: 0 }.can_transition_to(&Expired));

        // Illegal.
        assert!(!Open.can_transition_to(&Finalized));
        assert!(!Open.can_transition_to(&Verifying));
        assert!(!Verifying.can_transition_to(&Executing { current_leg: 0 }));
        assert!(!Finalized.can_transition_to(&Open));
        assert!(!Compensated.can_transition_to(&Compensating { failed_leg: 0 }));
        assert!(!Expired.can_transition_to(&Executing { current_leg: 0 }));
        assert!(
            !Aborted {
                reason: "x".to_string()
            }
            .can_transition_to(&Compensated)
        );
    }

    #[test]
    fn open_saga_validation() {
        let orch = SagaOrchestrator::new();

        // Empty legs.
        let r = orch.open_saga(addr(1), 0, vec![], future_ts());
        assert!(matches!(r.unwrap_err(), SettlementError::SagaError(_)));

        // Past expiry.
        let r = orch.open_saga(
            addr(1),
            1,
            vec![leg("a", 1, 2, 10)],
            Timestamp::new(Timestamp::now().as_millis() - 1_000),
        );
        assert!(matches!(r.unwrap_err(), SettlementError::SagaExpired(_)));

        // Zero amount.
        let r = orch.open_saga(addr(1), 2, vec![leg("a", 1, 2, 0)], future_ts());
        assert!(matches!(r.unwrap_err(), SettlementError::InvalidAmount(_)));

        // Duplicate leg ids.
        let r = orch.open_saga(
            addr(1),
            3,
            vec![leg("a", 1, 2, 10), leg("a", 2, 3, 10)],
            future_ts(),
        );
        assert!(matches!(r.unwrap_err(), SettlementError::SagaError(_)));

        // Payer == payee.
        let r = orch.open_saga(addr(1), 4, vec![leg("a", 1, 1, 10)], future_ts());
        assert!(matches!(r.unwrap_err(), SettlementError::SagaError(_)));
    }

    #[test]
    fn open_saga_is_idempotent() {
        let orch = SagaOrchestrator::new();
        let s1 = orch
            .open_saga(addr(1), 5, vec![leg("a", 1, 2, 10)], future_ts())
            .unwrap();
        let s2 = orch
            .open_saga(addr(1), 5, vec![leg("b", 3, 4, 99)], future_ts())
            .unwrap();
        assert_eq!(s1.saga_id, s2.saga_id);
        assert_eq!(s2.legs[0].leg_id, "a");
        assert_eq!(orch.get_sagas_by_creator(&addr(1)).len(), 1);
    }

    #[tokio::test]
    async fn execute_happy_path_then_finalize() {
        let orch = SagaOrchestrator::new();
        let exec = MockExecutor::default();
        let saga = orch
            .open_saga(
                addr(1),
                0,
                vec![leg("pay", 1, 2, 100), leg("deliver", 2, 1, 1)],
                future_ts(),
            )
            .unwrap();

        let driven = orch.execute(&saga.saga_id, &exec).await.unwrap();
        assert_eq!(driven.state, SagaState::Verifying);
        assert_eq!(*exec.executed.lock(), vec!["pay", "deliver"]);
        assert_eq!(driven.leg_results.len(), 2);
        assert!(
            driven
                .leg_results
                .iter()
                .all(|r| r.outcome == LegOutcome::Executed && r.receipt.is_some())
        );

        let finalized = orch.finalize(&saga.saga_id).unwrap();
        assert_eq!(finalized.state, SagaState::Finalized);

        // Idempotent finalize + execute on terminal state.
        assert_eq!(
            orch.finalize(&saga.saga_id).unwrap().state,
            SagaState::Finalized
        );
        let again = orch.execute(&saga.saga_id, &exec).await.unwrap();
        assert_eq!(again.state, SagaState::Finalized);
        assert_eq!(exec.executed.lock().len(), 2);
    }

    #[tokio::test]
    async fn finalize_before_verifying_is_illegal() {
        let orch = SagaOrchestrator::new();
        let saga = orch
            .open_saga(addr(1), 0, vec![leg("a", 1, 2, 10)], future_ts())
            .unwrap();
        let r = orch.finalize(&saga.saga_id);
        assert!(matches!(
            r.unwrap_err(),
            SettlementError::IllegalSagaTransition { .. }
        ));
    }

    #[tokio::test]
    async fn leg_failure_compensates_in_reverse_order() {
        let orch = SagaOrchestrator::new();
        let exec = MockExecutor {
            fail_execute_on: Some("c".to_string()),
            ..Default::default()
        };
        let saga = orch
            .open_saga(
                addr(1),
                0,
                vec![leg("a", 1, 2, 10), leg("b", 2, 3, 20), leg("c", 3, 1, 30)],
                future_ts(),
            )
            .unwrap();

        let driven = orch.execute(&saga.saga_id, &exec).await.unwrap();
        assert_eq!(driven.state, SagaState::Compensated);
        assert_eq!(*exec.executed.lock(), vec!["a", "b"]);
        // Reverse order.
        assert_eq!(*exec.compensated.lock(), vec!["b", "a"]);

        let a = driven.leg_results.iter().find(|r| r.leg_id == "a").unwrap();
        let b = driven.leg_results.iter().find(|r| r.leg_id == "b").unwrap();
        let c = driven.leg_results.iter().find(|r| r.leg_id == "c").unwrap();
        assert_eq!(a.outcome, LegOutcome::Compensated);
        assert_eq!(b.outcome, LegOutcome::Compensated);
        assert!(matches!(c.outcome, LegOutcome::Failed { .. }));

        // Terminal: re-drive is a no-op.
        let again = orch.execute(&saga.saga_id, &exec).await.unwrap();
        assert_eq!(again.state, SagaState::Compensated);
        assert_eq!(exec.executed.lock().len(), 2);
    }

    #[tokio::test]
    async fn compensation_failure_aborts() {
        let orch = SagaOrchestrator::new();
        let exec = MockExecutor {
            fail_execute_on: Some("c".to_string()),
            fail_compensate_on: Some("a".to_string()),
            ..Default::default()
        };
        let saga = orch
            .open_saga(
                addr(1),
                0,
                vec![leg("a", 1, 2, 10), leg("b", 2, 3, 20), leg("c", 3, 1, 30)],
                future_ts(),
            )
            .unwrap();

        let driven = orch.execute(&saga.saga_id, &exec).await.unwrap();
        assert!(matches!(driven.state, SagaState::Aborted { .. }));
        // b compensated fine before a failed.
        assert_eq!(*exec.compensated.lock(), vec!["b"]);
        let a = driven.leg_results.iter().find(|r| r.leg_id == "a").unwrap();
        assert!(matches!(a.outcome, LegOutcome::CompensationFailed { .. }));
    }

    #[tokio::test]
    async fn resume_skips_executed_legs() {
        let orch = SagaOrchestrator::new();
        let exec = MockExecutor::default();
        let saga = orch
            .open_saga(
                addr(1),
                0,
                vec![leg("a", 1, 2, 10), leg("b", 2, 3, 20), leg("c", 3, 1, 30)],
                future_ts(),
            )
            .unwrap();

        orch.execute(&saga.saga_id, &exec).await.unwrap();
        assert_eq!(exec.executed.lock().len(), 3);

        // Simulate a crash mid-execute: state back to Executing(2) with the
        // third leg's result removed.
        {
            let mut entry = orch.sagas.get_mut(&saga.saga_id).unwrap();
            let s = entry.value_mut();
            s.state = SagaState::Executing { current_leg: 2 };
            s.leg_results.retain(|r| r.leg_id != "c");
        }

        let resumed = orch.execute(&saga.saga_id, &exec).await.unwrap();
        assert_eq!(resumed.state, SagaState::Verifying);
        // Only leg c re-driven.
        assert_eq!(*exec.executed.lock(), vec!["a", "b", "c", "c"]);
        assert_eq!(resumed.leg_results.len(), 3);
    }

    #[tokio::test]
    async fn expire_sweep_open_saga() {
        let orch = SagaOrchestrator::new();
        let exec = MockExecutor::default();
        let saga = orch
            .open_saga(
                addr(1),
                0,
                vec![leg("a", 1, 2, 10)],
                Timestamp::new(Timestamp::now().as_millis() + 30),
            )
            .unwrap();

        std::thread::sleep(std::time::Duration::from_millis(60));
        let count = orch.expire_sweep(&exec).await;
        assert_eq!(count, 1);
        let expired = orch.get_saga(&saga.saga_id).unwrap();
        assert_eq!(expired.state, SagaState::Expired);
        assert!(exec.compensated.lock().is_empty());

        // Second sweep is a no-op.
        assert_eq!(orch.expire_sweep(&exec).await, 0);
    }

    #[tokio::test]
    async fn expire_sweep_compensates_executing_saga() {
        let orch = SagaOrchestrator::new();
        let exec = MockExecutor::default();
        let saga = orch
            .open_saga(
                addr(1),
                0,
                vec![leg("a", 1, 2, 10), leg("b", 2, 3, 20)],
                future_ts(),
            )
            .unwrap();

        // Simulate a stalled saga: leg a executed, then the process died and
        // the deadline passed.
        {
            let mut entry = orch.sagas.get_mut(&saga.saga_id).unwrap();
            let s = entry.value_mut();
            s.state = SagaState::Executing { current_leg: 1 };
            s.leg_results.push(LegResult {
                leg_id: "a".to_string(),
                outcome: LegOutcome::Executed,
                receipt: Some(LegReceipt {
                    leg_id: "a".to_string(),
                    reference: "ref-a".to_string(),
                    executed_at: Timestamp::now(),
                }),
            });
            s.expires_at = Timestamp::new(Timestamp::now().as_millis() - 1_000);
        }

        let count = orch.expire_sweep(&exec).await;
        assert_eq!(count, 1);
        let expired = orch.get_saga(&saga.saga_id).unwrap();
        assert_eq!(expired.state, SagaState::Expired);
        assert_eq!(*exec.compensated.lock(), vec!["a"]);
        assert_eq!(expired.leg_results[0].outcome, LegOutcome::Compensated);
    }

    #[tokio::test]
    async fn execute_missing_saga_errors() {
        let orch = SagaOrchestrator::new();
        let exec = MockExecutor::default();
        let r = orch.execute("nope", &exec).await;
        assert!(matches!(r.unwrap_err(), SettlementError::SagaNotFound(_)));
        assert!(matches!(
            orch.get_saga("nope").unwrap_err(),
            SettlementError::SagaNotFound(_)
        ));
    }

    #[tokio::test]
    async fn persistence_and_hydration() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let exec = MockExecutor::default();

        let saga_id = {
            let orch = SagaOrchestrator::with_storage(storage.clone());
            let saga = orch
                .open_saga(
                    addr(9),
                    42,
                    vec![leg("a", 1, 2, 10), leg("b", 2, 3, 20)],
                    future_ts(),
                )
                .unwrap();
            orch.execute(&saga.saga_id, &exec).await.unwrap();
            saga.saga_id
        };

        let orch2 = SagaOrchestrator::with_storage(storage.clone());
        let restored = orch2.get_saga(&saga_id).unwrap();
        assert_eq!(restored.state, SagaState::Verifying);
        assert_eq!(restored.leg_results.len(), 2);
        let by_creator = orch2.get_sagas_by_creator(&addr(9));
        assert_eq!(by_creator.len(), 1);
        assert_eq!(by_creator[0].saga_id, saga_id);

        // Mutations after rehydration write through.
        orch2.finalize(&saga_id).unwrap();
        let orch3 = SagaOrchestrator::with_storage(storage);
        assert_eq!(
            orch3.get_saga(&saga_id).unwrap().state,
            SagaState::Finalized
        );
    }
}
