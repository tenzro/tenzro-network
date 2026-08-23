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

pub mod aa_bootstrap_paymaster;
pub mod aa_delegation_validator;
pub mod aa_identity_key_validator;
pub mod aa_tee_bound_validator;
pub mod aa_validators;
pub mod aa_webauthn_validator;
pub mod account_abstraction;
pub mod config;
pub mod corporate_actions;
pub mod cross_vm_bridge;
pub mod daml;
pub mod eip1559;
pub mod eip7702;
pub mod erc7579;
pub mod erc7943;
pub mod error;
pub mod evm;
pub mod gas;
pub mod global_supply;
pub mod governance;
pub mod hot_state;
pub mod native;
pub mod parallel;
pub mod permit2;
pub mod precompiles;
pub mod runtime;
pub mod secure_mint;
pub mod stable_asset_registry;
pub mod stable_controller;
pub mod stable_rate_oracle;
pub mod state_adapter;
pub mod svm;
pub mod traits;
pub mod types;

// Re-export commonly used types
pub use aa_bootstrap_paymaster::{
    AgentRegistryLookup, BootstrapPaymasterError, TnzoBootstrapPaymaster,
};
pub use aa_delegation_validator::{
    CallIntent, CallIntentDecoder, DelegationScopeValidator, EnforcedScope, InMemoryScopeOracle,
    ScopeOracle, StandardExecuteDecoder,
};
pub use aa_tee_bound_validator::{
    DEFAULT_MAX_ATTESTATION_AGE_SECS, EnclaveSignedOp, InMemoryTeeKeyOracle, TeeBoundAccountKey,
    TeeBoundValidator, TeeEnrollmentStore, TeeKeyOracle,
};
pub use aa_validators::{
    ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE, ERC7484_REGISTRY_ADDRESS, IValidator,
    InstalledModule, ModuleAttestation, ModuleAttestationRegistry, ModuleType, NoOpValidator,
    SELECTOR_ATTEST_MODULE, SELECTOR_INSTALL_VALIDATOR, SELECTOR_UNINSTALL_VALIDATOR,
    ValidationData, ValidatorError, ValidatorRegistry,
};
pub use aa_webauthn_validator::{
    HybridWebAuthnSignature, SecondFactorPolicy, WebAuthnAccountKey, WebAuthnValidator,
};
pub use account_abstraction::{
    AccountAbstractionError, AccountFactory, AccountModule, BundlerConfig, EIP_7702_DESIGNATOR_LEN,
    EIP_7702_DESIGNATOR_PREFIX, EIP_7702_MAGIC, EIP_7702_TX_TYPE, EXECUTE_SELECTOR,
    Eip7702Authorization, EntryPoint, Nonce, PackedUserOperation, Paymaster, SimulationResult,
    SmartAccount, UserOpReceipt, UserOperation, build_7702_designator, encode_execute_calldata,
    parse_7702_designator, process_7702_authorizations,
};
pub use config::VmConfig;
pub use daml::DamlExecutor;
pub use eip1559::{EffectiveGasPrice, Eip1559Config, FeeMarket, FeeMarketStats, FeeUrgency};
pub use erc7579::{
    GuardianSignature, MODULE_TYPE_VALIDATOR, PRECOMPILE_SESSION_KEY_VALIDATOR,
    PRECOMPILE_SOCIAL_RECOVERY_VALIDATOR, PRECOMPILE_SPENDING_LIMIT_VALIDATOR,
    SELECTOR_INSTALL_MODULE as ERC7579_SELECTOR_INSTALL_MODULE,
    SELECTOR_IS_MODULE_INSTALLED as ERC7579_SELECTOR_IS_MODULE_INSTALLED,
    SELECTOR_UNINSTALL_MODULE as ERC7579_SELECTOR_UNINSTALL_MODULE,
    SELECTOR_VALIDATE_USER_OP as ERC7579_SELECTOR_VALIDATE_USER_OP, SessionKeyConfig,
    SessionKeySignaturePayload, SessionKeyValidator, SocialRecoveryConfig,
    SocialRecoverySignaturePayload, SocialRecoveryValidator, SpendingLimitConfig,
    SpendingLimitSignaturePayload, SpendingLimitValidator, ValidatorModuleConfig,
    ValidatorModuleMap, create_session_key_validator_precompile,
    create_social_recovery_validator_precompile, create_spending_limit_validator_precompile,
};
pub use error::{Result, VmError};
pub use evm::EvmExecutor;
pub use gas::{GasEstimator, GasOracle, GasPrice, gas_normalizer};
pub use hot_state::{
    AccountSample, ContentionScore, HOT_STATE_MAX_MULTIPLIER, HOT_STATE_SCORE_FLOOR,
    HOT_STATE_WINDOW_BLOCKS, HOT_STATE_WRITE_FLOOR, HotStateMarket, local_multiplier_for_score,
};
pub use native::NativeExecutor;
pub use parallel::{
    BaseState, BlockStmConfig, BlockStmExecutor, ParallelExecutionResult, ReadWriteSet,
    ResolvedDeltas, TxExecutionStatus, ZeroBaseState,
};
pub use precompiles::{
    PRECOMPILE_CROSS_VM_BRIDGE, PRECOMPILE_GOVERNANCE, PRECOMPILE_MODEL_INFERENCE,
    PRECOMPILE_NFT_FACTORY, PRECOMPILE_SETTLEMENT, PRECOMPILE_STAKING, PRECOMPILE_TEE_VERIFY,
    PRECOMPILE_TNZO_BRIDGE, PRECOMPILE_TOKEN_FACTORY, PRECOMPILE_ZK_VERIFY, PrecompileAddress,
    PrecompileRegistry, TransientReentrancyGuard,
};
pub use runtime::MultiVmRuntime;
pub use state_adapter::{CacheStats, PersistentState, PrefetchKeys, StateAdapter};
pub use svm::SvmExecutor;
pub use traits::{VmExecutor, VmState, VmType};
pub use types::{
    CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, Log, StateChange,
    VmTransaction,
};

pub use corporate_actions::{
    CORPORATE_ACTION_DOMAIN, CorporateAction, CorporateActionEngine, CorporateActionError,
    CorporateActionRecord,
};
pub use erc7943::{KycGateRegistry, KycTierResolver};

pub use stable_asset_registry::{
    PaymentRail, ReserveSource, SharedStableAssetRegistry, StableAssetError, StableAssetPolicy,
    StableAssetRegistry,
};
pub use stable_controller::{
    BufferAction, RiskBand, StableController, StableControllerConfig, StableControllerOutput,
};
pub use stable_rate_oracle::{
    ChainlinkRateOracle, CrossRateFeed, GovernanceSetRateOracle, RateBacking, RateRow,
    StableRateError, StableRateOracle, StableRateQuote,
};

/// VM module version
pub const VM_VERSION: &str = "0.1.0";

/// Maximum gas limit for a single transaction
pub const MAX_GAS_LIMIT: u64 = 30_000_000;

/// Default gas limit for transactions
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;
