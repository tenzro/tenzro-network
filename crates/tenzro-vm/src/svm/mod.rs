//! SVM (Solana Virtual Machine) executor module

pub mod cross_vm;
pub mod executor;
/// Real SBF execution via Anza's `solana-svm`. Declared here rather than
/// inside `executor.rs` because `full.rs` sits beside `executor.rs`, not
/// under it — a `mod full;` in `executor.rs` resolves to
/// `svm/executor/full.rs`, which does not exist.
#[cfg(feature = "svm-full")]
mod full;
pub mod spl_adapter;

pub use cross_vm::{
    BRIDGE_FROM_EVM_PAYLOAD_SIZE, BRIDGE_TO_EVM_PAYLOAD_SIZE, CrossVmDecodeError,
    CrossVmInstruction, PROGRAM_ID_DERIVATION_DOMAIN, REGISTER_TOKEN_POINTER_PAYLOAD_SIZE,
    TENZRO_CROSS_VM_PROGRAM_ID, TRANSFER_CROSS_VM_PAYLOAD_SIZE,
    discriminators as cross_vm_discriminators, vm_types as cross_vm_dest,
};
pub use executor::SvmExecutor;
pub use spl_adapter::SplTokenAdapter;
