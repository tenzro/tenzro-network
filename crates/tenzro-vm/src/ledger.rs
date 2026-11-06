//! Native TNZO value accounting for block execution.
//!
//! Every node applies the same three rules to every block it executes, so
//! the ledger they agree on is one in which value is only ever moved, and
//! destroyed only where a transaction says it is. TNZO supply is fixed at
//! genesis: nothing after genesis adds to it.
//!
//! 1. **Per transaction.** A successful transaction changes the balances it
//!    touched by exactly `supply_change - gas_price * gas_used`: it may move
//!    value, it pays its fee, and it burns only what its
//!    [`ExecutionResult::supply_change`] declares. A declared increase is
//!    refused. A transaction that does anything else is reverted and charged
//!    gas like any failed transaction.
//! 2. **Fees.** Every fee a transaction pays is credited to
//!    [`FEE_POOL_ADDRESS`] as it is paid. At the end of the block the pool is
//!    emptied: the governed share of the base-fee revenue is burned (total
//!    supply falls by that amount) and the rest is credited to the treasury.
//!    Both figures come from the fees the block actually collected, so they
//!    cannot drift from what payers were charged.
//! 3. **Per block.** Before the block's state is committed, the net change
//!    across every balance the block wrote must equal the net change it
//!    recorded to total supply, and that change may not be an increase
//!    ([`verify_executed_block`]). A block that fails this is not committed.
//!
//! The per-block rule is measured independently of the per-transaction
//! journal (see [`StateAdapter::pending_block_delta`]), so writes made with no
//! journal open, such as gas charged after a revert and the end-of-block fee
//! split, are held to it as well.
//!
//! Because the EVM and SVM executors both read and write the one native
//! balance through the same [`StateAdapter`], these rules are the cross-VM
//! invariant: however value moves between the VM views, their sum is the
//! native total supply.
//!
//! # One fee market per resource
//!
//! A transaction's gas covers four resources, each with its own market:
//! compute, state growth (entries created), bandwidth (bytes carried) and
//! proof verification. Each has a USD base fee in consensus state that moves
//! by the EIP-1559 rule against its own per-block target, priced in TNZO at
//! the rate in force. The executors charge every unit of gas at the
//! transaction's gas price, which is at least the compute base fee; a unit of
//! another resource whose own base fee is higher pays the difference on top,
//! so congestion in one resource prices that resource and leaves the others
//! alone. A resource never costs less than compute, because every unit is
//! also gas.

use crate::eip1559::{Eip1559Config, next_base_fee};
use crate::error::{Result, VmError};
use crate::native::{derive_treasury_address, network_param};
use crate::runtime::MultiVmRuntime;
use crate::state_adapter::StateAdapter;
use crate::traits::VmState;
use crate::types::{ExecutionResult, VmTransaction};

/// System account that collects the fees paid during a block. Emptied by
/// [`settle_block`] at the end of every block, so it holds nothing between
/// blocks.
pub const FEE_POOL_ADDRESS: [u8; 20] = [0xFD; 20];

/// Storage slot under [`FEE_POOL_ADDRESS`] holding the base fee of the next
/// block in atto-USD per unit of gas (16-byte little-endian). Fees are priced
/// in USD and paid in TNZO at the rate in force
/// ([`crate::native::read_fee_rate`]).
const BASE_FEE_SLOT: &[u8] = b"base_fee";

/// Burn share before governance has ever enacted a burn dial: the whole base
/// fee is burned.
pub const DEFAULT_BASE_FEE_BURN_BPS: u64 = 10_000;

/// Share of base-fee revenue burned, in basis points: the base-fee dial of
/// the last enacted `AdaptiveBurnConfigUpdate`. The burn dial moves only by a
/// governance vote on that policy (the node's proposal generator drafts it
/// from the supply metrics), and this is the one place block execution reads
/// it. The rest of the fees a block collects is credited to the treasury.
pub fn base_fee_burn_bps(state: &dyn VmState) -> u64 {
    match crate::native::read_policy(state, "adaptive_burn_config").map(|p| p.update) {
        Some(tenzro_types::token::PolicyUpdate::AdaptiveBurnConfigUpdate {
            base_fee_burn_bps,
            ..
        }) => u64::from(base_fee_burn_bps).min(10_000),
        _ => DEFAULT_BASE_FEE_BURN_BPS,
    }
}

/// USD base fee of the block being executed, atto-USD per unit of gas.
///
/// Read from consensus state; before the first block has settled it is the
/// fee market's configured initial base fee.
pub fn block_base_fee_usd(state: &dyn VmState) -> u128 {
    state
        .get_storage(&FEE_POOL_ADDRESS, BASE_FEE_SLOT)
        .filter(|b| b.len() == 16)
        .map(|b| {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b);
            u128::from_le_bytes(a)
        })
        .unwrap_or_else(|| Eip1559Config::default().initial_base_fee)
}

/// Base fee the block being executed charges at minimum, in TNZO base units
/// per unit of gas: the USD base fee at the TNZO/USD rate in force.
pub fn block_base_fee(state: &dyn VmState) -> u128 {
    crate::native::usd_to_wei(state, block_base_fee_usd(state))
}

/// A resource with a fee market of its own beside compute gas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    /// State entries a transaction creates.
    StateGrowth,
    /// Bytes a transaction carries.
    Bandwidth,
    /// Proof verification.
    Proof,
}

impl Resource {
    /// Every resource with its own market.
    pub const ALL: [Resource; 3] = [Resource::StateGrowth, Resource::Bandwidth, Resource::Proof];

    fn index(self) -> usize {
        match self {
            Resource::StateGrowth => 0,
            Resource::Bandwidth => 1,
            Resource::Proof => 2,
        }
    }

    /// Its name on the wire and in its governed parameter.
    pub fn name(self) -> &'static str {
        match self {
            Resource::StateGrowth => "state_growth",
            Resource::Bandwidth => "bandwidth",
            Resource::Proof => "proof",
        }
    }

    fn base_fee_slot(self) -> &'static [u8] {
        match self {
            Resource::StateGrowth => b"base_fee:state_growth",
            Resource::Bandwidth => b"base_fee:bandwidth",
            Resource::Proof => b"base_fee:proof",
        }
    }

    /// Governed key of the units of this resource a block targets.
    pub fn target_param(self) -> &'static str {
        match self {
            Resource::StateGrowth => "fees.state_growth_target_per_block",
            Resource::Bandwidth => "fees.bandwidth_target_per_block",
            Resource::Proof => "fees.proof_target_per_block",
        }
    }
}

/// Governed key: compute gas a block targets; the base fee rises above it
/// and falls below it.
pub const COMPUTE_TARGET_PARAM: &str = "fees.compute_target_gas_per_block";
/// Governed key: the base fee moves at most 1/this per block.
pub const BASE_FEE_CHANGE_DENOMINATOR_PARAM: &str = "fees.base_fee_change_denominator";
/// Governed key: lowest base fee, atto-USD per unit.
pub const MIN_BASE_FEE_PARAM: &str = "fees.min_base_fee";
/// Governed key: highest base fee, atto-USD per unit.
pub const MAX_BASE_FEE_PARAM: &str = "fees.max_base_fee";

/// The fee market the chain runs, from the governed parameters. A ceiling
/// governance set below the floor is read as the floor.
pub fn fee_market_config(state: &dyn VmState) -> Eip1559Config {
    let min_base_fee = u128::from(network_param(state, MIN_BASE_FEE_PARAM));
    Eip1559Config {
        target_gas_per_block: network_param(state, COMPUTE_TARGET_PARAM),
        base_fee_change_denominator: network_param(state, BASE_FEE_CHANGE_DENOMINATOR_PARAM),
        min_base_fee,
        max_base_fee: u128::from(network_param(state, MAX_BASE_FEE_PARAM)).max(min_base_fee),
        ..Eip1559Config::default()
    }
}

/// Genesis target of each non-compute resource per block: a sixth of the
/// 15M compute gas target, so a block that fills one resource to its target
/// leaves most of the block for compute.
pub const DEFAULT_RESOURCE_TARGET_PER_BLOCK: u64 = 15_000_000 / 6;

/// Gas for carrying `data`: the EVM's calldata rates.
pub(crate) fn bandwidth_gas(data: &[u8]) -> u64 {
    use crate::gas::evm_gas_costs::{TXDATA_NONZERO, TXDATA_ZERO};
    data.iter()
        .map(|b| if *b == 0 { TXDATA_ZERO } else { TXDATA_NONZERO })
        .sum()
}

/// Gas for the state entries `changes` created: each change from nothing (or
/// zero) to a non-zero value costs what a new EVM storage slot does. An
/// account's nonce is not an entry of its own.
pub(crate) fn state_growth_gas(changes: &[crate::types::StateChange]) -> u64 {
    let empty = |v: &Option<Vec<u8>>| v.as_ref().is_none_or(|b| b.iter().all(|x| *x == 0));
    let created = changes
        .iter()
        .filter(|c| c.key != b"nonce" && empty(&c.old_value) && !empty(&c.new_value))
        .count() as u64;
    created.saturating_mul(crate::gas::evm_gas_costs::SSTORE_SET)
}

/// The units of each resource with its own market that `tx` used, out of
/// its `result.gas_used`, indexed as [`Resource::ALL`].
pub fn resource_units(tx: &VmTransaction, result: &ExecutionResult) -> [u64; 3] {
    let mut left = result.gas_used;
    let mut take = |want: u64| {
        let got = want.min(left);
        left -= got;
        got
    };
    let proof = take(result.proof_gas);
    let bandwidth = take(bandwidth_gas(&tx.data));
    let state_growth = take(state_growth_gas(&result.state_changes));
    [state_growth, bandwidth, proof]
}

/// USD base fee of `resource` for the block being executed, atto-USD per
/// unit. Before its market first settles it is the compute market's initial
/// base fee.
pub fn resource_base_fee_usd(state: &dyn VmState, resource: Resource) -> u128 {
    state
        .get_storage(&FEE_POOL_ADDRESS, resource.base_fee_slot())
        .filter(|b| b.len() == 16)
        .map(|b| u128::from_le_bytes(b.try_into().expect("16 bytes")))
        .unwrap_or_else(|| Eip1559Config::default().initial_base_fee)
}

/// What a transaction pays on top of its gas for the resources whose own
/// base fee is above compute's, in TNZO base units.
pub fn resource_premium(state: &dyn VmState, units: &[u64; 3], compute_base_fee: u128) -> u128 {
    Resource::ALL.iter().fold(0u128, |acc, r| {
        let price = crate::native::usd_to_wei(state, resource_base_fee_usd(state, *r));
        acc.saturating_add(
            (units[r.index()] as u128).saturating_mul(price.saturating_sub(compute_base_fee)),
        )
    })
}

/// Fees collected so far in the block being executed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockFees {
    /// Everything payers were charged.
    pub collected: u128,
    /// The part of `collected` that is base fee (`min(gas_price, base_fee)`
    /// per unit of gas, and every resource premium). The burn share is taken
    /// from this.
    pub base_fee_revenue: u128,
    /// Gas used by every transaction that executed.
    pub gas_used: u64,
    /// Units of each resource with its own market used, indexed as
    /// [`Resource::ALL`].
    pub resource_units: [u64; 3],
}

impl BlockFees {
    /// Add another set of fees, as a transaction executed speculatively
    /// collected them.
    pub fn merge(&mut self, other: &BlockFees) {
        self.collected = self.collected.saturating_add(other.collected);
        self.base_fee_revenue = self.base_fee_revenue.saturating_add(other.base_fee_revenue);
        self.gas_used = self.gas_used.saturating_add(other.gas_used);
        for (a, b) in self.resource_units.iter_mut().zip(other.resource_units) {
            *a = a.saturating_add(b);
        }
    }

    fn add(&mut self, fee: u128, gas_used: u64, gas_price: u128, base_fee: u128) {
        self.collected = self.collected.saturating_add(fee);
        let base_part = gas_price
            .min(base_fee)
            .saturating_mul(gas_used as u128)
            .min(fee);
        self.base_fee_revenue = self.base_fee_revenue.saturating_add(base_part);
        self.gas_used = self.gas_used.saturating_add(gas_used);
    }
}

/// What happened to one transaction in a block.
#[derive(Debug)]
pub enum TxOutcome {
    /// Executed and kept. `fee` was paid into the fee pool.
    Applied { result: ExecutionResult, fee: u128 },
    /// Executed and failed, or broke the value rule. Its writes were undone
    /// and `fee` was charged. `reason` says why.
    Reverted {
        result: ExecutionResult,
        fee: u128,
        reason: String,
    },
    /// Never executed: no writes and no fee.
    Rejected(VmError),
}

/// Why a transaction's value accounting did not balance.
fn conservation_error(delta: i128, fee: u128, declared: i128) -> String {
    if declared > 0 {
        return format!(
            "value not conserved: declared a supply increase of {declared}; TNZO supply is \
             fixed at genesis"
        );
    }
    format!(
        "value not conserved: balances changed by {delta}, fee {fee}, declared supply change \
         {declared}"
    )
}

/// Checks one transaction's balance movement against the value rule.
///
/// `balance_delta` is the net change across every balance the transaction
/// wrote, `fee` what it owes for gas, `supply_change` what it declared it
/// burned (negative). TNZO supply is fixed at genesis, so a transaction that
/// declares an increase never conserves value, whatever its balances.
pub fn conserves_value(balance_delta: i128, fee: u128, supply_change: i128) -> bool {
    supply_change <= 0 && balance_delta.checked_add(fee as i128) == Some(supply_change)
}

/// Debits up to `fee` from `payer` and credits what was taken to the fee
/// pool. Returns the amount actually moved, which is less than `fee` only when
/// the payer cannot cover it.
fn collect_fee(state: &mut StateAdapter, payer: &[u8], fee: u128) -> u128 {
    if fee == 0 {
        return 0;
    }
    let balance = state.get_balance(payer);
    let taken = fee.min(balance);
    if taken == 0 {
        return 0;
    }
    state.set_balance(payer, balance - taken);
    let pool = state.get_balance(&FEE_POOL_ADDRESS);
    state.set_balance(&FEE_POOL_ADDRESS, pool.saturating_add(taken));
    taken
}

/// Runs the future of one transaction so that a panic inside it ends that
/// transaction and nothing else.
///
/// Every validator executes the same finalized block against the same state,
/// so a panic that a transaction can provoke happens on every validator at
/// the same block: the event loop dies everywhere, each restart replays the
/// block and dies again, and the chain stops for good. Turned into an
/// execution error the transaction is refused and undone like any other
/// failure, deterministically on every validator, and the block goes on. No
/// finalized block contains a transaction that panicked (the chain would not
/// have passed it), so the rule changes no past outcome.
async fn contain_panic<F>(fut: F) -> Result<ExecutionResult>
where
    F: std::future::Future<Output = Result<ExecutionResult>>,
{
    struct Contained<F>(std::pin::Pin<Box<F>>);
    impl<F: std::future::Future> std::future::Future for Contained<F> {
        type Output = std::thread::Result<F::Output>;
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            use std::task::Poll;
            let inner = self.0.as_mut();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.poll(cx))) {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(v)) => Poll::Ready(Ok(v)),
                Err(payload) => Poll::Ready(Err(payload)),
            }
        }
    }
    match Contained(Box::pin(fut)).await {
        Ok(outcome) => outcome,
        Err(payload) => {
            let what = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-text panic".to_string());
            tracing::error!(panic = %what, "a transaction panicked during execution; refused and undone");
            Err(VmError::ExecutionFailed(
                "the transaction panicked during execution".to_string(),
            ))
        }
    }
}

/// A transaction offering less than the block base fee is never executed.
/// A record that pays no fee ([`crate::native::pays_no_fee`]) is held to no
/// base fee.
fn below_base_fee(tx: &VmTransaction, base_fee: u128) -> Option<TxOutcome> {
    (tx.gas_price < base_fee && !crate::native::pays_no_fee(tx)).then(|| {
        TxOutcome::Rejected(VmError::InvalidTransaction(format!(
            "gas price {} is below the block base fee {}",
            tx.gas_price, base_fee
        )))
    })
}

/// Executes one transaction of a finalized block under the value rules.
///
/// Opens the transaction's undo log, runs it, and then either keeps its
/// writes (paying its fee into the pool and recording any declared supply
/// change) or undoes them and charges gas. The nonce advances whenever the
/// transaction executed, kept or not, because the journal does not cover it.
pub async fn execute_in_block(
    runtime: &MultiVmRuntime,
    state: &mut StateAdapter,
    tx: &VmTransaction,
    base_fee: u128,
    fees: &mut BlockFees,
) -> TxOutcome {
    if let Some(rejected) = below_base_fee(tx, base_fee) {
        return rejected;
    }

    state.begin_transaction();
    let outcome = contain_panic(runtime.execute_transaction(tx, state)).await;
    settle_transaction(state, tx, outcome, base_fee, fees)
}

/// [`execute_in_block`] for a transaction whose signature has already been
/// accepted by [`MultiVmRuntime::check_signature`]. The outcome is the one
/// [`execute_in_block`] gives, because the signature check reads no state.
pub(crate) async fn execute_checked_in_block(
    runtime: &MultiVmRuntime,
    state: &mut StateAdapter,
    tx: &VmTransaction,
    base_fee: u128,
    fees: &mut BlockFees,
    checked: crate::runtime::SignatureChecked,
) -> TxOutcome {
    if let Some(rejected) = below_base_fee(tx, base_fee) {
        return rejected;
    }

    state.begin_transaction();
    let outcome = contain_panic(runtime.execute_checked(tx, state, checked)).await;
    settle_transaction(state, tx, outcome, base_fee, fees)
}

/// EIP-7702 delegations stand even when the execution after them reverts
/// (the authorities' nonces, never journaled, already stand).
fn reapply_delegations(state: &mut StateAdapter, tx: &VmTransaction, result: &ExecutionResult) {
    let now = crate::native::deterministic_now_ms(tx);
    for (authority, code) in &result.delegations {
        state.set_code(authority, code.clone());
        // The change counts against the ceiling although the call reverted.
        crate::delegation_guard::bump(state, authority, now);
    }
}

/// Applies the value rules to a transaction that has just executed with its
/// undo log open. Closes the log.
pub fn settle_transaction(
    state: &mut StateAdapter,
    tx: &VmTransaction,
    outcome: Result<ExecutionResult>,
    base_fee: u128,
    fees: &mut BlockFees,
) -> TxOutcome {
    let result = match outcome {
        Err(e) => {
            state.revert_transaction();
            return TxOutcome::Rejected(e);
        }
        Ok(r) => r,
    };

    // A record that pays no fee owes nothing for its gas or its resources,
    // kept or refused.
    let fee_free = crate::native::pays_no_fee(tx);
    let owed = if fee_free {
        0
    } else {
        tx.gas_price.saturating_mul(result.gas_used as u128)
    };

    if !result.success {
        state.revert_transaction();
        reapply_delegations(state, tx, &result);
        let fee = collect_fee(state, &tx.from, owed);
        fees.add(fee, result.gas_used, tx.gas_price, base_fee);
        let reason = result
            .revert_reason
            .clone()
            .unwrap_or_else(|| "reverted".to_string());
        return TxOutcome::Reverted {
            result,
            fee,
            reason,
        };
    }

    let delta = state.journal_balance_delta().unwrap_or(0);
    if !conserves_value(delta, owed, result.supply_change) {
        let reason = conservation_error(delta, owed, result.supply_change);
        tracing::error!(
            from = %hex::encode(&tx.from),
            delta,
            fee = %owed,
            declared = result.supply_change,
            "Transaction reverted: value not conserved"
        );
        state.revert_transaction();
        reapply_delegations(state, tx, &result);
        let fee = collect_fee(state, &tx.from, owed);
        fees.add(fee, result.gas_used, tx.gas_price, base_fee);
        let mut failed = result;
        failed.success = false;
        failed.logs.clear();
        failed.state_changes.clear();
        failed.supply_change = 0;
        failed.revert_reason = Some(reason.clone());
        return TxOutcome::Reverted {
            result: failed,
            fee,
            reason,
        };
    }

    // The resources whose own market prices them above compute gas are
    // paid on top, from the sender, inside the transaction: a sender that
    // cannot pay them has its transaction undone like any failed one.
    let units = resource_units(tx, &result);
    let premium = if fee_free {
        0
    } else {
        resource_premium(state, &units, base_fee)
    };
    if premium > 0 {
        let balance = state.get_balance(&tx.from);
        if balance < premium {
            state.revert_transaction();
            reapply_delegations(state, tx, &result);
            let fee = collect_fee(state, &tx.from, owed);
            fees.add(fee, result.gas_used, tx.gas_price, base_fee);
            let reason = format!("cannot pay the resource fees of {premium} beyond gas");
            let mut failed = result;
            failed.success = false;
            failed.logs.clear();
            failed.state_changes.clear();
            failed.supply_change = 0;
            failed.revert_reason = Some(reason.clone());
            return TxOutcome::Reverted {
                result: failed,
                fee,
                reason,
            };
        }
        state.set_balance(&tx.from, balance - premium);
    }
    let owed = owed.saturating_add(premium);

    state.commit_transaction();
    // The executor already debited the gas from the sender, and the resource
    // premium was debited above; both land in the pool here, which is what
    // makes the transaction's net effect equal to its declared supply change.
    if owed > 0 {
        let pool = state.get_balance(&FEE_POOL_ADDRESS);
        state.set_balance(&FEE_POOL_ADDRESS, pool.saturating_add(owed));
    }
    // `conserves_value` admitted only a burn or no change.
    let change = result.supply_change;
    if change < 0 {
        state.record_supply_change(0, change.unsigned_abs());
    }
    fees.add(
        owed.saturating_sub(premium),
        result.gas_used,
        tx.gas_price,
        base_fee,
    );
    fees.collected = fees.collected.saturating_add(premium);
    fees.base_fee_revenue = fees.base_fee_revenue.saturating_add(premium);
    for (a, u) in fees.resource_units.iter_mut().zip(units) {
        *a = a.saturating_add(u);
    }
    TxOutcome::Applied { result, fee: owed }
}

/// How a block's fees were settled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockFeeSettlement {
    /// Fees the block collected.
    pub collected: u128,
    /// Burned: removed from the fee pool and from total supply.
    pub burned: u128,
    /// Credited to the treasury.
    pub to_treasury: u128,
    /// Credited to the insurance pool.
    pub to_insurance: u128,
    /// Base fee of the next block.
    pub next_base_fee: u128,
    /// Gas the block used.
    pub gas_used: u64,
}

/// Empties the fee pool at the end of a block and sets the next base fee.
///
/// The governed share of base-fee revenue is burned and everything else in
/// the pool goes to the treasury. The next USD base fee follows from this
/// block's USD base fee and gas used, and is stored in state so every node
/// prices the next block identically.
pub fn settle_block(state: &mut StateAdapter, fees: &BlockFees) -> BlockFeeSettlement {
    let pool = state.get_balance(&FEE_POOL_ADDRESS);
    let burn_bps = base_fee_burn_bps(state) as u128;
    let burned = (fees.base_fee_revenue.saturating_mul(burn_bps) / 10_000).min(pool);
    let to_treasury = pool - burned;

    // The insurance pool takes its governed share of what would go to the
    // treasury.
    let to_insurance = crate::native::insurance::fee_share(state, to_treasury);
    let to_treasury = to_treasury - to_insurance;
    if pool > 0 {
        state.set_balance(&FEE_POOL_ADDRESS, 0);
        for (account, amount) in [
            (derive_treasury_address(), to_treasury),
            (crate::native::insurance::pool_address(), to_insurance),
        ] {
            if amount > 0 {
                let balance = state.get_balance(account.as_bytes());
                state.set_balance(account.as_bytes(), balance.saturating_add(amount));
            }
        }
        if let Err(e) = crate::native::insurance::note_credit(
            state,
            to_insurance,
            crate::native::insurance::PoolSource::Fees,
            &mut Vec::new(),
        ) {
            tracing::warn!(error = %e, "could not record the block's insurance share");
        }
        if let Err(e) =
            crate::native::treasury_reserve::note_revenue(state, to_treasury, &mut Vec::new())
        {
            tracing::warn!(error = %e, "could not record the block's treasury revenue");
        }
        if burned > 0 {
            state.record_supply_change(0, burned);
            if let Err(e) = crate::native::economy::record_burn(state, burned) {
                tracing::warn!(error = %e, "could not add the block's burn to the epoch record");
            }
        }
    }

    let market = fee_market_config(state);
    let next_usd = next_base_fee(&market, block_base_fee_usd(state), fees.gas_used);
    state.set_storage(
        &FEE_POOL_ADDRESS,
        BASE_FEE_SLOT,
        next_usd.to_le_bytes().to_vec(),
    );
    // Every other resource moves against its own target, from its own use.
    for r in Resource::ALL {
        let target = network_param(state, r.target_param()).max(1);
        let config = Eip1559Config {
            target_gas_per_block: target,
            ..market.clone()
        };
        let next = next_base_fee(
            &config,
            resource_base_fee_usd(state, r),
            fees.resource_units[r.index()],
        );
        state.set_storage(
            &FEE_POOL_ADDRESS,
            r.base_fee_slot(),
            next.to_le_bytes().to_vec(),
        );
    }

    // Each guarded module's vault against what it owes; a module that is
    // short is frozen in this block.
    crate::invariant_monitor::check_block(state);

    BlockFeeSettlement {
        collected: fees.collected,
        burned,
        to_treasury,
        to_insurance,
        next_base_fee: block_base_fee(state),
        gas_used: fees.gas_used,
    }
}

/// The block-level value rule: refuses a pending block whose balance writes
/// do not net to the supply change it recorded.
pub fn verify_block(state: &StateAdapter) -> Result<()> {
    let (balances, supply) = state.pending_block_delta();
    if balances != supply {
        return Err(VmError::StateError(format!(
            "block does not conserve value: balances changed by {balances}, supply by {supply}"
        )));
    }
    Ok(())
}

/// The rule for every block after genesis: [`verify_block`], and no increase
/// in total supply. Fees and settlements may burn TNZO and rewards are paid
/// from the genesis-funded pool; nothing mints, so a block that recorded
/// added supply is refused. Genesis, which allocates the supply, is held to
/// [`verify_block`] alone.
pub fn verify_executed_block(state: &StateAdapter) -> Result<()> {
    verify_block(state)?;
    let (_, supply) = state.pending_block_delta();
    if supply > 0 {
        return Err(VmError::StateError(format!(
            "block adds {supply} to total supply; TNZO supply is fixed at genesis"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn a_panicking_transaction_is_refused_and_does_not_unwind_the_caller() {
        let out = contain_panic(async {
            if true {
                panic!("poison");
            }
            Err(VmError::OutOfGas)
        })
        .await;
        assert!(matches!(out, Err(VmError::ExecutionFailed(_))));
        // A panic after the future has yielded once is contained too.
        let out = contain_panic(async {
            tokio::task::yield_now().await;
            let v: Vec<u8> = Vec::new();
            let _ = v[3];
            Err(VmError::OutOfGas)
        })
        .await;
        assert!(matches!(out, Err(VmError::ExecutionFailed(_))));
        let err = contain_panic(async { Err(VmError::OutOfGas) }).await;
        assert!(matches!(err, Err(VmError::OutOfGas)));
    }
    use super::*;

    #[test]
    fn a_transfer_that_pays_its_fee_conserves_value() {
        assert!(conserves_value(-21_000, 21_000, 0));
    }

    #[test]
    fn a_self_transfer_that_keeps_its_value_does_not_conserve() {
        // Paid the fee and was also credited the transfer amount again.
        assert!(!conserves_value(1_000 - 21_000, 21_000, 0));
    }

    #[test]
    fn a_declared_burn_conserves_value() {
        assert!(conserves_value(-521_000, 21_000, -500_000));
        assert!(!conserves_value(-521_000, 21_000, 0));
    }

    /// TNZO supply is fixed at genesis: a transaction that declares it added
    /// supply is refused even when its balances match the declaration.
    #[test]
    fn a_declared_supply_increase_never_conserves_value() {
        assert!(!conserves_value(500_000 - 21_000, 21_000, 500_000));
        assert!(!conserves_value(1 - 21_000, 21_000, 1));
    }
}
