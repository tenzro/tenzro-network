//! ERC-20 Token Factory Precompile (0x1002)
//!
//! Provides permissionless ERC-20 token creation using ERC-1167 minimal proxy clones.
//! Each new token is deployed as a 45-byte minimal proxy pointing to a shared
//! ERC-20 implementation contract. Token metadata is registered in the unified
//! TokenRegistry for cross-VM discoverability.
//!
//! # Function Selectors
//!
//! | Selector   | Function                                          | Gas     |
//! |------------|---------------------------------------------------|---------|
//! | 0x5d3555bb | createToken(string,string,uint8,uint256,uint8)    | 150,000 |
//! | 0xb4a99a4e | predictAddress(bytes32)                           | 2,600   |
//! | 0x49a7a26d | getImplementation()                               | 2,600   |
//! | 0x8abf6077 | getTokenCount()                                   | 2,600   |

use crate::evm::wtnzo::abi;
use crate::precompiles::PrecompileResult;
use crate::error::Result;
use crate::VmError;
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use tenzro_token::{
    TokenRegistry, TokenDefinition, TokenId, TokenType,
    cross_vm::{VmAddresses, TokenPermissions, TokenMetadata},
};
use tracing::{debug, info};

/// Gas cost for token creation
const GAS_CREATE_TOKEN: u64 = 150_000;
/// Gas cost for read operations
const GAS_READ: u64 = 2_600;

/// Function selectors for the token factory precompile
pub mod selectors {
    /// createToken(string name, string symbol, uint8 decimals, uint256 initialSupply, uint8 flags)
    /// flags: bit 0 = mintable, bit 1 = burnable, bit 2 = pausable, bit 3 = freezable
    pub const CREATE_TOKEN: [u8; 4] = [0x5d, 0x35, 0x55, 0xbb];
    /// predictAddress(bytes32 salt) -> address
    pub const PREDICT_ADDRESS: [u8; 4] = [0xb4, 0xa9, 0x9a, 0x4e];
    /// getImplementation() -> address
    pub const GET_IMPLEMENTATION: [u8; 4] = [0x49, 0xa7, 0xa2, 0x6d];
    /// getTokenCount() -> uint256
    pub const GET_TOKEN_COUNT: [u8; 4] = [0x8a, 0xbf, 0x60, 0x77];
}

/// Well-known address of the ERC-20 implementation contract
/// All clones delegate to this implementation.
const ERC20_IMPLEMENTATION: [u8; 20] = [
    0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// ERC-1167 minimal proxy bytecode prefix
/// 3d602d80600a3d3981f3363d3d373d3d3d363d73
const CLONE_PREFIX: &[u8] = &[
    0x3d, 0x60, 0x2d, 0x80, 0x60, 0x0a, 0x3d, 0x39, 0x81, 0xf3,
    0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73,
];

/// ERC-1167 minimal proxy bytecode suffix
/// 5af43d82803e903d91602b57fd5bf3
const CLONE_SUFFIX: &[u8] = &[
    0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60,
    0x2b, 0x57, 0xfd, 0x5b, 0xf3,
];

/// Creates the token factory precompile function
pub fn create_token_factory_precompile(
    registry: Arc<TokenRegistry>,
) -> Arc<dyn Fn(&[u8], u64) -> Result<PrecompileResult> + Send + Sync> {
    Arc::new(move |input: &[u8], gas_limit: u64| {
        execute_token_factory(&registry, input, gas_limit)
    })
}

/// Main dispatch for the token factory precompile.
///
/// Frame contract when invoked via `PrecompileRegistry::execute`:
///
/// ```text
///   [0..4]    selector
///   [4..N]    caller-supplied calldata (any ABI shape)
///   [N..N+32] trusted msg.sender (32-byte left-padded) — REQUIRED for
///             write selectors (CREATE_TOKEN); read-only selectors
///             accept a missing slot.
/// ```
///
/// Authorization-sensitive selectors read the creator from `caller`,
/// never from caller-supplied calldata bytes.
fn execute_token_factory(
    registry: &TokenRegistry,
    input: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if input.len() < 4 {
        return Ok(PrecompileResult::failed(gas_limit));
    }

    let selector = &input[..4];
    let (caller_opt, calldata): (Option<[u8; 20]>, &[u8]) = if input.len() >= 4 + 32 {
        let split = input.len() - 32;
        let mut caller = [0u8; 20];
        caller.copy_from_slice(&input[split + 12..]);
        (Some(caller), &input[4..split])
    } else {
        (None, &input[4..])
    };

    match selector {
        s if s == selectors::CREATE_TOKEN => {
            let caller = caller_opt.ok_or_else(|| VmError::PrecompileFailed(
                "createToken requires trusted msg.sender; invoke precompile \
                 via PrecompileRegistry::execute (EVM runtime path).".to_string(),
            ))?;
            handle_create_token(registry, &caller, calldata, gas_limit)
        }
        s if s == selectors::PREDICT_ADDRESS => handle_predict_address(calldata, gas_limit),
        s if s == selectors::GET_IMPLEMENTATION => handle_get_implementation(gas_limit),
        s if s == selectors::GET_TOKEN_COUNT => handle_get_token_count(registry, gas_limit),
        _ => Ok(PrecompileResult::failed(gas_limit)),
    }
}

/// createToken(string name, string symbol, uint8 decimals, uint256 initialSupply, uint8 flags)
///
/// Creates a new ERC-20 token via ERC-1167 minimal proxy clone.
/// The creator is the trusted `msg.sender` supplied by the EVM runtime;
/// caller-supplied bytes in `calldata` are never used for authorization.
///
/// `calldata` is the original Solidity ABI payload (after the selector,
/// and with the runtime-appended trusted-caller slot stripped). Layout:
///   [0..32]   name_offset (dynamic)
///   [32..64]  symbol_offset (dynamic)
///   [64..96]  decimals (uint8)
///   [96..128] initial_supply (uint256)
///   [128..160] flags (uint8)
///   [160..]   dynamic name and symbol data
fn handle_create_token(
    registry: &TokenRegistry,
    caller: &[u8; 20],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_CREATE_TOKEN {
        return Err(VmError::OutOfGas);
    }

    // We need at least the five fixed-size head words.
    if calldata.len() < 160 {
        return Ok(PrecompileResult::failed(GAS_CREATE_TOKEN));
    }

    // Parse fixed parameters
    let decimals = calldata[95]; // Last byte of [64..96]
    let initial_supply = abi::decode_uint256_at(calldata, 96).unwrap_or(0);
    let flags = calldata[159]; // Last byte of [128..160]

    // Creator is the trusted caller from the EVM runtime.
    let mut creator = [0u8; 32];
    creator[12..32].copy_from_slice(caller);

    // Parse dynamic strings (simplified: read from offsets)
    let name = decode_dynamic_string(calldata, 0).unwrap_or_else(|| "Unnamed Token".to_string());
    let symbol = decode_dynamic_string(calldata, 32).unwrap_or_else(|| "???".to_string());

    // Parse flags
    let permissions = TokenPermissions {
        mintable: flags & 0x01 != 0,
        burnable: flags & 0x02 != 0,
        pausable: flags & 0x04 != 0,
        freezable: flags & 0x08 != 0,
        paused: false,
    };

    // Compute deterministic clone address via CREATE2
    let salt = compute_create2_salt(&creator, &name, &symbol);
    let clone_address = compute_clone_address(&salt);

    // Register the token
    let def = TokenDefinition {
        token_id: TokenId::compute(&creator, 0), // Will be reassigned by registry
        name: name.clone(),
        symbol: symbol.clone(),
        decimals,
        total_supply: initial_supply,
        max_supply: if permissions.mintable { None } else { Some(initial_supply) },
        creator,
        token_type: TokenType::Erc20,
        vm_addresses: VmAddresses {
            evm: Some(clone_address),
            ..Default::default()
        },
        permissions,
        created_at: 0, // Will be set by registry
        metadata: TokenMetadata::default(),
    };

    match registry.register_token(def) {
        Ok(token_id) => {
            info!(
                "Token factory: created {} ({}) at 0x{}, id={}",
                name,
                symbol,
                hex::encode(clone_address),
                token_id
            );

            // Return the clone address (left-padded to 32 bytes)
            let mut output = vec![0u8; 32];
            output[12..32].copy_from_slice(&clone_address);
            Ok(PrecompileResult::success(output, GAS_CREATE_TOKEN))
        }
        Err(e) => {
            debug!("Token factory: creation failed: {}", e);
            Ok(PrecompileResult::failed(GAS_CREATE_TOKEN))
        }
    }
}

/// predictAddress(bytes32 salt) -> address
fn handle_predict_address(calldata: &[u8], gas_limit: u64) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 32 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut salt = [0u8; 32];
    salt.copy_from_slice(&calldata[..32]);
    let address = compute_clone_address(&salt);

    let mut output = vec![0u8; 32];
    output[12..32].copy_from_slice(&address);
    Ok(PrecompileResult::success(output, GAS_READ))
}

/// getImplementation() -> address
fn handle_get_implementation(gas_limit: u64) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    let mut output = vec![0u8; 32];
    output[12..32].copy_from_slice(&ERC20_IMPLEMENTATION);
    Ok(PrecompileResult::success(output, GAS_READ))
}

/// getTokenCount() -> uint256
fn handle_get_token_count(registry: &TokenRegistry, gas_limit: u64) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    let count = registry.token_count() as u128;
    Ok(PrecompileResult::success(abi::encode_uint256(count), GAS_READ))
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Computes the CREATE2 salt for a token deployment
fn compute_create2_salt(creator: &[u8; 32], name: &str, symbol: &str) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"tenzro-token-factory:");
    hasher.update(creator);
    hasher.update(name.as_bytes());
    hasher.update(symbol.as_bytes());
    let result = hasher.finalize();
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&result);
    salt
}

/// Computes the CREATE2 clone address
///
/// address = keccak256(0xff ++ factory_address ++ salt ++ keccak256(clone_bytecode))[12:]
fn compute_clone_address(salt: &[u8; 32]) -> [u8; 20] {
    // Build clone initcode
    let mut initcode = Vec::with_capacity(CLONE_PREFIX.len() + 20 + CLONE_SUFFIX.len());
    initcode.extend_from_slice(CLONE_PREFIX);
    initcode.extend_from_slice(&ERC20_IMPLEMENTATION);
    initcode.extend_from_slice(CLONE_SUFFIX);

    // Hash initcode
    let mut hasher = Keccak256::new();
    hasher.update(&initcode);
    let initcode_hash = hasher.finalize();

    // Compute CREATE2 address
    let factory = crate::evm::wtnzo::TOKEN_FACTORY_ADDRESS;
    let mut hasher = Keccak256::new();
    hasher.update([0xff]);
    hasher.update(factory);
    hasher.update(salt);
    hasher.update(initcode_hash);
    let result = hasher.finalize();

    let mut address = [0u8; 20];
    address.copy_from_slice(&result[12..32]);
    address
}

/// Generates the ERC-1167 minimal proxy bytecode for a given implementation address
pub fn generate_clone_bytecode(implementation: &[u8; 20]) -> Vec<u8> {
    let mut bytecode = Vec::with_capacity(CLONE_PREFIX.len() + 20 + CLONE_SUFFIX.len());
    bytecode.extend_from_slice(CLONE_PREFIX);
    bytecode.extend_from_slice(implementation);
    bytecode.extend_from_slice(CLONE_SUFFIX);
    bytecode
}

/// Decodes a dynamic string from ABI-encoded calldata at a given offset slot
fn decode_dynamic_string(calldata: &[u8], offset_slot: usize) -> Option<String> {
    if calldata.len() < offset_slot + 32 {
        return None;
    }

    // Read the offset to the string data
    let offset = abi::decode_uint256_at(calldata, offset_slot)? as usize;

    if calldata.len() < offset + 32 {
        return None;
    }

    // Read string length
    let length = abi::decode_uint256_at(calldata, offset)? as usize;

    if length == 0 || calldata.len() < offset + 32 + length {
        return None;
    }

    // Read string bytes
    let string_bytes = &calldata[offset + 32..offset + 32 + length];
    String::from_utf8(string_bytes.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone_bytecode_length() {
        let bytecode = generate_clone_bytecode(&ERC20_IMPLEMENTATION);
        // ERC-1167: 10 (prefix-creation) + 10 (prefix-runtime) + 20 (address) + 15 (suffix) = 55
        assert_eq!(bytecode.len(), 55);
    }

    #[test]
    fn test_create2_salt_deterministic() {
        let creator = [1u8; 32];
        let salt1 = compute_create2_salt(&creator, "Token", "TKN");
        let salt2 = compute_create2_salt(&creator, "Token", "TKN");
        assert_eq!(salt1, salt2);
    }

    #[test]
    fn test_create2_salt_different_params() {
        let creator = [1u8; 32];
        let salt1 = compute_create2_salt(&creator, "Token1", "TK1");
        let salt2 = compute_create2_salt(&creator, "Token2", "TK2");
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_clone_address_deterministic() {
        let salt = [42u8; 32];
        let addr1 = compute_clone_address(&salt);
        let addr2 = compute_clone_address(&salt);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_get_implementation() {
        let registry = Arc::new(TokenRegistry::new());
        let input = selectors::GET_IMPLEMENTATION.to_vec();
        let result = execute_token_factory(&registry, &input, 100_000).unwrap();
        assert!(result.success);
        assert_eq!(&result.output[12..32], &ERC20_IMPLEMENTATION);
    }

    #[test]
    fn test_get_token_count() {
        let registry = Arc::new(TokenRegistry::new());
        let input = selectors::GET_TOKEN_COUNT.to_vec();
        let result = execute_token_factory(&registry, &input, 100_000).unwrap();
        assert!(result.success);
        let count = abi::decode_uint256(&result.output).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_predict_address() {
        let registry = Arc::new(TokenRegistry::new());
        let mut input = selectors::PREDICT_ADDRESS.to_vec();
        input.extend_from_slice(&[42u8; 32]);
        let result = execute_token_factory(&registry, &input, 100_000).unwrap();
        assert!(result.success);
        // Address should be non-zero
        assert!(!result.output[12..32].iter().all(|&b| b == 0));
    }
}
