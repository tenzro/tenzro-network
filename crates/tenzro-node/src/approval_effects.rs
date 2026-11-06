//! What a transaction would do, derived by the node rather than drawn by
//! whichever front end asks for an approval.
//!
//! The node executes the unsigned transaction on a copy of its state at a
//! named block, under the block rules, and reports the outcome, every balance
//! it changes and the logs it emits. Nothing is committed. The report carries
//! a digest over all of it, the height and the block hash, so a wallet can
//! ask a second node, run by another operator, for the same block and show
//! the effects only when both digests agree.

use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tenzro_types::transaction::{SignedTransaction, Transaction};
use tenzro_vm::traits::VmState as _;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Domain of [`Effects::digest`].
const EFFECTS_DOMAIN: &[u8] = b"tenzro/approval-effects/v1";

/// One balance a transaction changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BalanceChange {
    pub account: String,
    pub before: String,
    pub after: String,
}

/// One log a transaction emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmittedLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

/// The effects of a transaction executed at `height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Effects {
    pub height: u64,
    pub block_hash: String,
    /// `applied`, `reverted` or `rejected`.
    pub outcome: &'static str,
    pub error: Option<String>,
    pub gas_used: u64,
    pub balance_changes: Vec<BalanceChange>,
    pub logs: Vec<EmittedLog>,
    /// [`effects_digest`] over everything above, hex.
    pub digest: String,
}

/// SHA-256 over the effects, each field length-prefixed in a fixed order.
pub fn effects_digest(
    height: u64,
    block_hash: &str,
    outcome: &str,
    error: Option<&str>,
    gas_used: u64,
    balance_changes: &[BalanceChange],
    logs: &[EmittedLog],
) -> String {
    fn put(h: &mut Sha256, b: &[u8]) {
        h.update((b.len() as u64).to_le_bytes());
        h.update(b);
    }
    let mut h = Sha256::new();
    h.update(EFFECTS_DOMAIN);
    h.update(height.to_le_bytes());
    put(&mut h, block_hash.as_bytes());
    put(&mut h, outcome.as_bytes());
    put(&mut h, error.unwrap_or("").as_bytes());
    h.update(gas_used.to_le_bytes());
    h.update((balance_changes.len() as u64).to_le_bytes());
    for c in balance_changes {
        put(&mut h, c.account.as_bytes());
        put(&mut h, c.before.as_bytes());
        put(&mut h, c.after.as_bytes());
    }
    h.update((logs.len() as u64).to_le_bytes());
    for l in logs {
        put(&mut h, l.address.as_bytes());
        h.update((l.topics.len() as u64).to_le_bytes());
        for t in &l.topics {
            put(&mut h, t.as_bytes());
        }
        put(&mut h, l.data.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Execute `tx`, unsigned, on a copy of the state after block `block` (the
/// head when absent) and report its effects.
pub(crate) async fn simulate(
    node: &Arc<TenzroNode>,
    tx: &Transaction,
    block: Option<&serde_json::Value>,
) -> Result<Effects, JsonRpcError> {
    let failed = |message: String| JsonRpcError {
        code: -32603,
        message,
        data: None,
    };
    let height = crate::eth_block_param::block_height(node, block).await?;
    let mut state = crate::eth_block_param::state_at(node, height)?;
    let before = state.fork();
    let header_block = crate::eth_block_param::block_at(node, height).await?;
    let block_hash = format!("0x{}", hex::encode(header_block.hash().as_bytes()));
    let block_timestamp_ms =
        tenzro_vm::native::calendar_ms(&state, header_block.header.timestamp.as_millis())
            .map_err(|e| failed(format!("calendar: {e}")))?;
    let base_fee = tenzro_vm::ledger::block_base_fee(&state);
    let mut vm_tx = crate::event_loop::vm_transaction(&SignedTransaction::external(tx.clone()))
        .with_block_timestamp_ms(block_timestamp_ms)
        .with_block_height(height);
    // No signature exists yet: this is what the signature would approve.
    vm_tx.signature = None;
    vm_tx.public_key = None;
    vm_tx.signing_digest = None;
    vm_tx.block_base_fee = Some(base_fee);
    let vm = node
        .vm_runtime()
        .ok_or_else(|| failed("VM runtime not initialized".to_string()))?;
    let mut fees = tenzro_vm::ledger::BlockFees::default();
    let outcome =
        tenzro_vm::ledger::execute_in_block(vm, &mut state, &vm_tx, base_fee, &mut fees).await;
    let (label, error, result) = match outcome {
        tenzro_vm::ledger::TxOutcome::Applied { result, .. } => ("applied", None, Some(result)),
        tenzro_vm::ledger::TxOutcome::Reverted { result, reason, .. } => {
            ("reverted", Some(reason), Some(result))
        }
        tenzro_vm::ledger::TxOutcome::Rejected(e) => ("rejected", Some(e.to_string()), None),
    };
    let balance_changes: Vec<BalanceChange> = state
        .written_balances()
        .into_iter()
        .filter_map(|account| {
            let was = before.get_balance(&account);
            let now = state.get_balance(&account);
            (was != now).then(|| BalanceChange {
                account: format!("0x{}", hex::encode(&account)),
                before: was.to_string(),
                after: now.to_string(),
            })
        })
        .collect();
    let (gas_used, logs) = result.map_or((0, Vec::new()), |r| {
        (
            r.gas_used,
            r.logs
                .iter()
                .map(|l| EmittedLog {
                    address: format!("0x{}", hex::encode(&l.address)),
                    topics: l
                        .topics
                        .iter()
                        .map(|t| format!("0x{}", hex::encode(t)))
                        .collect(),
                    data: format!("0x{}", hex::encode(&l.data)),
                })
                .collect(),
        )
    });
    let digest = effects_digest(
        height,
        &block_hash,
        label,
        error.as_deref(),
        gas_used,
        &balance_changes,
        &logs,
    );
    Ok(Effects {
        height,
        block_hash,
        outcome: label,
        error,
        gas_used,
        balance_changes,
        logs,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(account: &str, before: &str, after: &str) -> BalanceChange {
        BalanceChange {
            account: account.into(),
            before: before.into(),
            after: after.into(),
        }
    }

    #[test]
    fn the_digest_moves_with_every_effect() {
        let changes = vec![change("0x01", "10", "5"), change("0x02", "0", "5")];
        let base = effects_digest(7, "ab", "applied", None, 21_000, &changes, &[]);
        assert_eq!(
            base,
            effects_digest(7, "ab", "applied", None, 21_000, &changes, &[])
        );
        let mut other = changes.clone();
        other[1] = change("0x03", "0", "5");
        for d in [
            effects_digest(8, "ab", "applied", None, 21_000, &changes, &[]),
            effects_digest(7, "cd", "applied", None, 21_000, &changes, &[]),
            effects_digest(7, "ab", "reverted", Some("x"), 21_000, &changes, &[]),
            effects_digest(7, "ab", "applied", None, 21_001, &changes, &[]),
            effects_digest(7, "ab", "applied", None, 21_000, &other, &[]),
            effects_digest(
                7,
                "ab",
                "applied",
                None,
                21_000,
                &changes,
                &[EmittedLog {
                    address: "0x01".into(),
                    topics: vec![],
                    data: "0x".into(),
                }],
            ),
        ] {
            assert_ne!(d, base);
        }
    }
}
