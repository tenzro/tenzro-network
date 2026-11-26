//! EVM (Ethereum Virtual Machine) executor module

pub mod executor;
pub mod gateway;
pub mod nft_factory;
mod osaka;
pub mod precompile_host;
pub mod revm_db;
pub mod tnzo_bridge;
pub mod token_factory;
pub mod wtnzo;

pub use executor::{EvmExecutor, is_engine_fault};

/// The gate of the rule that the EVM runs under Prague alone.
pub const PRAGUE_ONLY_KEY: &str = "feature.evm_prague_only.activation_epoch";

/// The gate of the rules that bring the EVM to the Prague rule set where the
/// engine as first built departed from it: the BLS12-381 precompiles
/// (`0x0b`-`0x11`), the KZG point evaluation precompile (`0x0a`), the
/// removal of an account that destroys itself in the transaction that
/// created it, an engine error charged at the whole gas limit, and a limit
/// on the gas a block's EVM and SVM transactions use
/// ([`BLOCK_GAS_LIMIT_PARAM`]).
pub const CONFORMANCE_KEY: &str = "feature.evm_conformance.activation_epoch";

/// The governed gas a block's EVM and SVM transactions may use before the
/// rest wait for the next block, once [`CONFORMANCE_KEY`] is live.
pub const BLOCK_GAS_LIMIT_PARAM: &str = "evm.block_gas_limit";

/// The gas the EVM and SVM transactions of the block being executed may use
/// before the rest are left for a later block: `None` until
/// [`CONFORMANCE_KEY`] is live.
pub fn block_gas_limit(state: &dyn crate::traits::VmState) -> Option<u64> {
    conformance_live(state).then(|| crate::native::network_param(state, BLOCK_GAS_LIMIT_PARAM))
}

/// Whether [`CONFORMANCE_KEY`] is live in the block being executed.
pub fn conformance_live(state: &dyn crate::traits::VmState) -> bool {
    crate::feature_gate::is_live_now(state, CONFORMANCE_KEY)
}

/// The Ethereum rule set of the block being executed: Prague once
/// [`PRAGUE_ONLY_KEY`] is live. Until then it is the engine's own default,
/// which adds the EOF container format to Prague. A container deployed
/// before the rule is live is legacy code once it is: it can no longer be
/// called.
pub fn rule_set(state: &dyn crate::traits::VmState) -> revm::primitives::SpecId {
    if crate::feature_gate::is_live_now(state, PRAGUE_ONLY_KEY) {
        revm::primitives::SpecId::PRAGUE
    } else {
        revm::primitives::SpecId::LATEST
    }
}

/// The gate of the Osaka rule set: from its epoch on a block's EVM
/// transactions run on the engine of that rule set (`osaka`), linked beside
/// the first one. It replaces the first engine whole, so [`PRAGUE_ONLY_KEY`]
/// no longer bears on a block once this is live.
pub const OSAKA_KEY: &str = "feature.evm_osaka.activation_epoch";

/// Whether [`OSAKA_KEY`] is live in the block being executed.
pub fn osaka_live(state: &dyn crate::traits::VmState) -> bool {
    crate::feature_gate::is_live_now(state, OSAKA_KEY)
}

/// The highest gas limit an EVM transaction may carry in the block being
/// executed: the Osaka rule set's cap (EIP-7825) once [`OSAKA_KEY`] is live,
/// none before. A block refuses a transaction above it, so a node's pool
/// does not admit one.
pub fn transaction_gas_cap(state: &dyn crate::traits::VmState) -> Option<u64> {
    osaka_live(state).then_some(osaka::TRANSACTION_GAS_CAP)
}
