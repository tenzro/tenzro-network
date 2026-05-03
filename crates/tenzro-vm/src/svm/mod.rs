//! SVM (Solana Virtual Machine) executor module

pub mod cross_vm;
pub mod executor;
pub mod spl_adapter;

pub use cross_vm::{
    discriminators as cross_vm_discriminators, vm_types as cross_vm_dest, CrossVmDecodeError,
    CrossVmInstruction, BRIDGE_FROM_EVM_PAYLOAD_SIZE, BRIDGE_TO_EVM_PAYLOAD_SIZE,
    PROGRAM_ID_DERIVATION_DOMAIN, REGISTER_TOKEN_POINTER_PAYLOAD_SIZE, TENZRO_CROSS_VM_PROGRAM_ID,
    TRANSFER_CROSS_VM_PAYLOAD_SIZE,
};
pub use executor::SvmExecutor;
pub use spl_adapter::SplTokenAdapter;
