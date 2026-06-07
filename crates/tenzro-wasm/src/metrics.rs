//! Execution metrics — fuel reports and signed execution receipts.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Per-invocation fuel accounting summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuelReport {
    /// Fuel budget at the start of the invocation.
    pub budget: u64,

    /// Fuel consumed by the time the invocation returned (or trapped).
    pub consumed: u64,

    /// Fuel left in the budget when the invocation finished. Equals
    /// `budget - consumed` for a clean return; `0` for a trap on
    /// exhaustion.
    pub remaining: u64,

    /// Wall-clock execution time.
    pub elapsed: Duration,
}

impl FuelReport {
    /// Returns true if the invocation exhausted its fuel budget.
    pub fn exhausted(&self) -> bool {
        self.remaining == 0 && self.consumed >= self.budget
    }
}

/// A receipt emitted for each invocation. Suitable for chaining into
/// Tenzro `ReceiptEnvelope` records (see `tenzro-storage::da`) for
/// durable, auditable execution history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Component id from the manifest.
    pub component_id: String,

    /// SHA-256 content hash of the bytes the host actually executed,
    /// lowercase hex. The host re-hashes on every load so a manifest
    /// can never claim a hash it didn't ship.
    pub content_hash_hex: String,

    /// Exported function name the host invoked.
    pub function: String,

    /// SHA-256 of the canonical input bytes (lowercase hex). Lets the
    /// host bind a receipt to a specific request body without storing
    /// the full input.
    pub input_hash_hex: String,

    /// SHA-256 of the canonical output bytes (lowercase hex). Same
    /// reasoning as `input_hash_hex`. Empty string on a trap.
    pub output_hash_hex: String,

    /// Outcome.
    pub outcome: InvocationOutcome,

    /// Fuel accounting.
    pub fuel: FuelReport,

    /// Unix-millisecond timestamp from the host clock when the
    /// invocation completed.
    pub completed_at_ms: i64,
}

/// Coarse-grained outcome label for an invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InvocationOutcome {
    /// The component returned a value through its exported function.
    Success,

    /// The component trapped (panic, oversized memory, undefined
    /// behavior, ...).
    Trapped,

    /// The component exhausted its fuel budget.
    FuelExhausted,

    /// The component exceeded its wall-clock deadline.
    DeadlineExceeded,

    /// The component violated the host contract (wrong arg type,
    /// oversize argument, unauthorized capability use, ...).
    HostContractViolation,
}
