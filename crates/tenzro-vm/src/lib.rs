//! Multi-VM runtime for Tenzro Network
//!
//! This crate provides the virtual machine execution layer for Tenzro Network,
//! supporting multiple VM backends:
//!
//! - **EVM**: Ethereum Virtual Machine for EVM-compatible smart contracts
//! - **SVM**: Solana Virtual Machine for high-performance BPF programs
//!
//! # Architecture
//!
//! The VM layer is designed with pluggable executors that implement a common
//! `VmExecutor` trait. This allows Tenzro Network to support multiple execution
//! environments while maintaining a unified interface.
//!
//! # Features
//!
//! - Dual VM support (EVM and SVM)
//! - Automatic routing based on address format
//! - Gas accounting and metering
//! - Custom precompiles for TEE, ZK, and AI model operations
//! - State adapter for storage layer integration
//!
//! # Example
//!
//! ```rust,no_run
//! use tenzro_vm::{
//!     MultiVmRuntime,
//!     VmTransaction,
//!     VmType,
//!     config::VmConfig,
//! };
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create VM configuration
//! let config = VmConfig::default();
//!
//! // Initialize multi-VM runtime
//! let runtime = MultiVmRuntime::new(config).await?;
//!
//! // Execute a transaction (automatically routed to correct VM)
//! // let result = runtime.execute_transaction(&tx, &mut state).await?;
//! # Ok(())
//! # }
//! ```

pub mod aa_execution;
pub mod aa_identity_key_validator;
pub mod aa_validators;
pub mod aa_webauthn_validator;
pub mod account_abstraction;
pub mod account_keys;
pub mod calls;
pub mod config;
pub mod eip1559;
pub mod eip7702;
pub mod erc7579;
pub mod error;
pub mod evm;
pub mod external_tx;
pub mod feature_gate;
pub mod funding;
pub mod gas;
pub mod governance;
pub mod hot_state;
pub mod invariant_monitor;
pub mod keystore;
pub mod ledger;
pub mod native;
pub mod parallel;
pub mod permit2;
pub mod precompiles;
pub mod runtime;
pub mod state_adapter;
pub mod svm;
pub mod token_ledger;

pub mod account_outflow;
pub mod delegation_guard;
/// Kani proof harnesses; see `proofs/mod.rs`.
#[cfg(all(kani, feature = "kani"))]
#[path = "../proofs/mod.rs"]
mod proofs;
pub mod traits;
pub mod tx_validity;
pub mod types;

// Re-export commonly used types
pub use aa_execution::{
    CALLTYPE_BATCH, CALLTYPE_SINGLE, EXECUTE_SELECTOR, Execution, ExecutionDecodeError,
    MAX_BATCH_CALLS, decode_execute, encode_batch, encode_single, total_value,
};
pub use aa_validators::{
    ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE, ERC7484_REGISTRY_ADDRESS, IValidator,
    InstalledModule, ModuleAttestation, ModuleAttestationRegistry, ModuleType, NoOpValidator,
    SELECTOR_ATTEST_MODULE, SELECTOR_INSTALL_VALIDATOR, SELECTOR_UNINSTALL_VALIDATOR,
    ValidationData, ValidatorError, ValidatorRegistry,
};
pub use aa_webauthn_validator::{
    KeystoreCredential, PasskeySignature, SecondFactorPolicy, WebAuthnValidator,
};
pub use account_abstraction::{
    AccountAbstractionError, EIP_7702_DESIGNATOR_LEN, EIP_7702_DESIGNATOR_PREFIX, EIP_7702_MAGIC,
    EIP_7702_TX_TYPE, ENTRY_POINT_V09, Eip7702Authorization, Nonce, PackedUserOperation,
    UserOperation, ValidityRange, build_7702_designator, parse_7702_designator,
};
pub use config::VmConfig;
pub use eip1559::{Eip1559Config, FeeMarket, FeeMarketStats, FeeUrgency};
pub use error::{Result, VmError};
pub use evm::EvmExecutor;
pub use gas::{GasEstimator, GasOracle, GasPrice, gas_normalizer};
pub use hot_state::{
    AccountSample, ContentionScore, HOT_STATE_MAX_MULTIPLIER, HOT_STATE_SCORE_FLOOR,
    HOT_STATE_WINDOW_BLOCKS, HOT_STATE_WRITE_FLOOR, HotStateMarket, local_multiplier_for_score,
};
pub use native::NativeExecutor;
pub use parallel::{BlockStmConfig, BlockTx};
pub use precompiles::{
    PRECOMPILE_NFT_FACTORY, PRECOMPILE_P256VERIFY, PRECOMPILE_RANDOMNESS_BEACON,
    PRECOMPILE_TEE_VERIFY, PRECOMPILE_TNZO_BRIDGE, PRECOMPILE_TOKEN_FACTORY, PRECOMPILE_VRF_VERIFY,
    PRECOMPILE_ZK_VERIFY, PrecompileAddress, PrecompileRegistry,
};
pub use runtime::MultiVmRuntime;
pub use state_adapter::{CacheStats, PersistentState, PrefetchKeys, StateAdapter};
pub use svm::SvmExecutor;
pub use traits::{VmExecutor, VmState, VmType};
pub use types::{
    CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, Log, StateChange,
    VmTransaction,
};

/// VM module version
pub const VM_VERSION: &str = "0.1.0";

/// Maximum gas limit for a single transaction
pub const MAX_GAS_LIMIT: u64 = 30_000_000;

/// Default gas limit for transactions
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;
