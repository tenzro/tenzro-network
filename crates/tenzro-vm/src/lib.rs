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
pub mod hot_state;
pub mod account_abstraction;
pub mod aa_validators;
pub mod aa_webauthn_validator;
pub mod aa_delegation_validator;
pub mod aa_tee_bound_validator;
pub mod aa_bootstrap_paymaster;
pub mod erc7579;
pub mod erc7943;
pub mod eip7702;
pub mod permit2;
pub mod secure_mint;
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
};
pub use state_adapter::{StateAdapter, PersistentState, CacheStats};
pub use evm::EvmExecutor;
pub use svm::SvmExecutor;
pub use daml::DamlExecutor;
pub use native::NativeExecutor;
pub use parallel::{BlockStmExecutor, BlockStmConfig, ParallelExecutionResult};
pub use eip1559::{FeeMarket, Eip1559Config, EffectiveGasPrice, FeeMarketStats, FeeUrgency};
pub use hot_state::{
    AccountSample, ContentionScore, HotStateMarket, local_multiplier_for_score,
    HOT_STATE_MAX_MULTIPLIER, HOT_STATE_SCORE_FLOOR, HOT_STATE_WINDOW_BLOCKS,
    HOT_STATE_WRITE_FLOOR,
};
pub use account_abstraction::{
    UserOperation, PackedUserOperation, EntryPoint, AccountFactory, SmartAccount, AccountModule,
    Paymaster, BundlerConfig, UserOpReceipt, SimulationResult, AccountAbstractionError,
    Eip7702Authorization, EIP_7702_TX_TYPE, EIP_7702_MAGIC,
    EIP_7702_DESIGNATOR_PREFIX, EIP_7702_DESIGNATOR_LEN,
    build_7702_designator, parse_7702_designator,
    process_7702_authorizations,
};
pub use aa_validators::{
    IValidator, InstalledModule, ModuleAttestation, ModuleAttestationRegistry, ModuleType,
    NoOpValidator, ValidationData, ValidatorError, ValidatorRegistry,
    ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE, ERC7484_REGISTRY_ADDRESS,
    SELECTOR_ATTEST_MODULE, SELECTOR_INSTALL_VALIDATOR, SELECTOR_UNINSTALL_VALIDATOR,
};
pub use aa_webauthn_validator::{
    HybridWebAuthnSignature, WebAuthnAccountKey, WebAuthnValidator,
};
pub use aa_delegation_validator::{
    CallIntent, CallIntentDecoder, DelegationScopeValidator, EnforcedScope,
    InMemoryScopeOracle, ScopeOracle, StandardExecuteDecoder,
};
pub use aa_tee_bound_validator::{
    EnclaveSignedOp, InMemoryTeeKeyOracle, TeeBoundAccountKey, TeeBoundValidator, TeeKeyOracle,
    DEFAULT_MAX_ATTESTATION_AGE_SECS,
};
pub use aa_bootstrap_paymaster::{
    AgentRegistryLookup, BootstrapPaymasterError, TnzoBootstrapPaymaster,
};
pub use erc7579::{
    create_session_key_validator_precompile, create_social_recovery_validator_precompile,
    create_spending_limit_validator_precompile, GuardianSignature, SessionKeyConfig,
    SessionKeySignaturePayload, SessionKeyValidator, SocialRecoveryConfig,
    SocialRecoverySignaturePayload, SocialRecoveryValidator, SpendingLimitConfig,
    SpendingLimitSignaturePayload, SpendingLimitValidator, ValidatorModuleConfig,
    ValidatorModuleMap, MODULE_TYPE_VALIDATOR, PRECOMPILE_SESSION_KEY_VALIDATOR,
    PRECOMPILE_SOCIAL_RECOVERY_VALIDATOR, PRECOMPILE_SPENDING_LIMIT_VALIDATOR,
    SELECTOR_INSTALL_MODULE as ERC7579_SELECTOR_INSTALL_MODULE,
    SELECTOR_IS_MODULE_INSTALLED as ERC7579_SELECTOR_IS_MODULE_INSTALLED,
    SELECTOR_UNINSTALL_MODULE as ERC7579_SELECTOR_UNINSTALL_MODULE,
    SELECTOR_VALIDATE_USER_OP as ERC7579_SELECTOR_VALIDATE_USER_OP,
};

/// VM module version
pub const VM_VERSION: &str = "0.1.0";

/// Maximum gas limit for a single transaction
pub const MAX_GAS_LIMIT: u64 = 30_000_000;

/// Default gas limit for transactions
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;
