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

pub mod traits;
pub mod types;
pub mod error;
pub mod config;
pub mod runtime;
pub mod gas;
pub mod precompiles;
pub mod state_adapter;
pub mod evm;
pub mod svm;
pub mod daml;
pub mod native;
pub mod parallel;
pub mod eip1559;
pub mod account_abstraction;
pub mod cross_vm_bridge;

// Re-export commonly used types
pub use traits::{VmExecutor, VmState, VmType};
pub use types::{
    VmTransaction, ExecutionResult, ContractCall, CallResult,
    ContractDeployment, DeployResult, Log, StateChange,
};
pub use error::{VmError, Result};
pub use config::VmConfig;
pub use runtime::MultiVmRuntime;
pub use gas::{GasOracle, GasPrice, GasEstimator, gas_normalizer};
pub use precompiles::{
    PrecompileRegistry, PrecompileAddress, TransientReentrancyGuard,
    PRECOMPILE_TEE_VERIFY, PRECOMPILE_ZK_VERIFY, PRECOMPILE_MODEL_INFERENCE, PRECOMPILE_SETTLEMENT,
    PRECOMPILE_TNZO_BRIDGE, PRECOMPILE_TOKEN_FACTORY, PRECOMPILE_CROSS_VM_BRIDGE,
    PRECOMPILE_STAKING, PRECOMPILE_GOVERNANCE, PRECOMPILE_NFT_FACTORY,
    PRECOMPILE_ERC8004_IDENTITY, PRECOMPILE_ERC8004_REPUTATION, PRECOMPILE_ERC8004_VALIDATION,
};
pub use evm::erc8004::{
    AgentRecord as Erc8004AgentRecord, Erc8004IdentityRegistry, Erc8004ReputationRegistry,
    Erc8004ValidationRegistry, FeedbackEntry as Erc8004FeedbackEntry,
    ValidationEntry as Erc8004ValidationEntry, ValidationStatus as Erc8004ValidationStatus,
};
pub use state_adapter::{StateAdapter, PersistentState, CacheStats};
pub use evm::EvmExecutor;
pub use svm::SvmExecutor;
pub use daml::DamlExecutor;
pub use native::NativeExecutor;
pub use parallel::{BlockStmExecutor, BlockStmConfig, ParallelExecutionResult};
pub use eip1559::{FeeMarket, Eip1559Config, EffectiveGasPrice, FeeMarketStats, FeeUrgency};
pub use account_abstraction::{
    UserOperation, PackedUserOperation, EntryPoint, AccountFactory, SmartAccount, AccountModule,
    Paymaster, BundlerConfig, UserOpReceipt, SimulationResult, AccountAbstractionError,
    Eip7702Authorization, EIP_7702_TX_TYPE, EIP_7702_MAGIC,
    EIP_7702_DESIGNATOR_PREFIX, EIP_7702_DESIGNATOR_LEN,
    build_7702_designator, parse_7702_designator,
    process_7702_authorizations, cleanup_7702_authorizations,
};

/// VM module version
pub const VM_VERSION: &str = "0.1.0";

/// Maximum gas limit for a single transaction
pub const MAX_GAS_LIMIT: u64 = 30_000_000;

/// Default gas limit for transactions
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;
