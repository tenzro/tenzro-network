//! ERC-7579 interface identifiers for EVM compatibility.
//!
//! A modular smart account deployed in the EVM (Safe with the 7579 adapter,
//! Kernel, Nexus and others) and its modules are ordinary contracts that run
//! in consensus. The node does not install modules or validate user
//! operations itself; these constants let tooling and tests build and
//! recognise the standard calls. The execution encoding (`execute(bytes32,
//! bytes)` and its mode word) lives in [`crate::aa_execution`].

/// Module type: validator.
pub const MODULE_TYPE_VALIDATOR: u64 = 1;
/// Module type: executor.
pub const MODULE_TYPE_EXECUTOR: u64 = 2;
/// Module type: fallback handler.
pub const MODULE_TYPE_FALLBACK: u64 = 3;
/// Module type: hook.
pub const MODULE_TYPE_HOOK: u64 = 4;

/// Account: `execute(bytes32 mode, bytes executionCalldata)`.
pub const SELECTOR_EXECUTE: [u8; 4] = [0xe9, 0xae, 0x5c, 0x53];
/// Account: `executeFromExecutor(bytes32 mode, bytes executionCalldata)`.
pub const SELECTOR_EXECUTE_FROM_EXECUTOR: [u8; 4] = [0xd6, 0x91, 0xc9, 0x64];
/// Account: `accountId()`.
pub const SELECTOR_ACCOUNT_ID: [u8; 4] = [0x9c, 0xfd, 0x7c, 0xff];
/// Account: `supportsExecutionMode(bytes32)`.
pub const SELECTOR_SUPPORTS_EXECUTION_MODE: [u8; 4] = [0xd0, 0x3c, 0x79, 0x14];
/// Account: `supportsModule(uint256)`.
pub const SELECTOR_SUPPORTS_MODULE: [u8; 4] = [0xf2, 0xdc, 0x69, 0x1d];
/// Account: `installModule(uint256 moduleTypeId, address module, bytes initData)`.
pub const SELECTOR_INSTALL_MODULE: [u8; 4] = [0x95, 0x17, 0xe2, 0x9f];
/// Account: `uninstallModule(uint256 moduleTypeId, address module, bytes deInitData)`.
pub const SELECTOR_UNINSTALL_MODULE: [u8; 4] = [0xa7, 0x17, 0x63, 0xa8];
/// Account: `isModuleInstalled(uint256 moduleTypeId, address module, bytes additionalContext)`.
pub const SELECTOR_IS_MODULE_INSTALLED: [u8; 4] = [0x11, 0x2d, 0x3a, 0x7d];

/// Module: `onInstall(bytes)`.
pub const SELECTOR_ON_INSTALL: [u8; 4] = [0x6d, 0x61, 0xfe, 0x70];
/// Module: `onUninstall(bytes)`.
pub const SELECTOR_ON_UNINSTALL: [u8; 4] = [0x8a, 0x91, 0xb0, 0xe3];
/// Module: `isModuleType(uint256)`.
pub const SELECTOR_IS_MODULE_TYPE: [u8; 4] = [0xec, 0xd0, 0x59, 0x61];
/// Module: `isInitialized(address)`.
pub const SELECTOR_IS_INITIALIZED: [u8; 4] = [0xd6, 0x0b, 0x34, 0x7f];

/// Validator: `validateUserOp(PackedUserOperation userOp, bytes32 userOpHash)`.
pub const SELECTOR_VALIDATE_USER_OP: [u8; 4] = [0x97, 0x00, 0x32, 0x03];
/// Validator: `isValidSignatureWithSender(address sender, bytes32 hash, bytes signature)`.
pub const SELECTOR_IS_VALID_SIGNATURE_WITH_SENDER: [u8; 4] = [0xf5, 0x51, 0xe2, 0xee];
