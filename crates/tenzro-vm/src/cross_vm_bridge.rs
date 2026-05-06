//! Cross-VM Bridge Precompile (0x1003)
//!
//! Handles atomic cross-VM token transfers. When a token moves from one VM to another
//! (e.g., EVM -> SVM), the bridge burns the representation on the source VM and mints
//! on the destination VM. For TNZO (which uses the pointer model), cross-VM transfers
//! are simply balance transfers in the native TnzoToken layer.
//!
//! # Function Selectors
//!
//! | Selector   | Function                                    | Gas     |
//! |------------|---------------------------------------------|---------|
//! | 0x3eaaf86b | crossVmTransfer(bytes32,uint256,uint8,bytes) | 15,000  |
//! | 0xa3c573eb | getVmBalance(bytes32,address,uint8)          | 2,600   |
//! | 0x12065fe0 | getBalance()                                 | 2,600   |

use crate::evm::wtnzo::abi;
use crate::precompiles::PrecompileResult;
use crate::error::Result;
use crate::VmError;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tenzro_token::{TnzoToken, TokenRegistry, TokenId, TokenVmType, cross_vm};
use tenzro_types::primitives::Address;
use tracing::{info, warn};

/// Gas costs
const GAS_CROSS_VM_TRANSFER: u64 = 15_000;
const GAS_READ: u64 = 2_600;

/// VM type constants for ABI encoding
const VM_TYPE_NATIVE: u8 = 0;
const VM_TYPE_EVM: u8 = 1;
const VM_TYPE_SVM: u8 = 2;
const VM_TYPE_DAML: u8 = 3;
const VM_TYPE_TEMPO_TIP20: u8 = 4;

/// Function selectors
pub mod selectors {
    /// crossVmTransfer(bytes32 tokenId, uint256 amount, uint8 destVm, bytes destAddress)
    pub const CROSS_VM_TRANSFER: [u8; 4] = [0x3e, 0xaa, 0xf8, 0x6b];
    /// getVmBalance(bytes32 tokenId, address owner, uint8 vm)
    pub const GET_VM_BALANCE: [u8; 4] = [0xa3, 0xc5, 0x73, 0xeb];
    /// getSupportedVms() -> uint8[]
    pub const GET_SUPPORTED_VMS: [u8; 4] = [0x12, 0x06, 0x5f, 0xe0];
}

/// Creates the cross-VM bridge precompile function
pub fn create_cross_vm_bridge_precompile(
    token: Arc<TnzoToken>,
    registry: Arc<TokenRegistry>,
) -> Arc<dyn Fn(&[u8], u64) -> Result<PrecompileResult> + Send + Sync> {
    let nonce_counter = Arc::new(AtomicU64::new(1));
    Arc::new(move |input: &[u8], gas_limit: u64| {
        execute_cross_vm_bridge(&token, &registry, &nonce_counter, input, gas_limit)
    })
}

/// Main dispatch for the cross-VM bridge precompile
fn execute_cross_vm_bridge(
    token: &TnzoToken,
    registry: &TokenRegistry,
    nonce_counter: &AtomicU64,
    input: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if input.len() < 4 {
        return Ok(PrecompileResult::failed(gas_limit));
    }

    let selector = &input[..4];
    let calldata = &input[4..];

    match selector {
        s if s == selectors::CROSS_VM_TRANSFER => {
            handle_cross_vm_transfer(token, registry, nonce_counter, calldata, gas_limit)
        }
        s if s == selectors::GET_VM_BALANCE => {
            handle_get_vm_balance(token, registry, calldata, gas_limit)
        }
        s if s == selectors::GET_SUPPORTED_VMS => handle_get_supported_vms(gas_limit),
        _ => Ok(PrecompileResult::failed(gas_limit)),
    }
}

/// crossVmTransfer(bytes32 tokenId, uint256 amount, uint8 destVm, bytes destAddress)
///
/// Performs an atomic cross-VM token transfer.
///
/// For TNZO (pointer model): This is simply a native TnzoToken transfer since
/// all VM representations share the same underlying balance.
///
/// For user tokens: This would burn on the source VM and mint on the destination VM.
/// Currently, only TNZO is supported for cross-VM transfers.
///
/// Input layout (after selector):
///   [0..32]    tokenId (bytes32)
///   [32..64]   amount (uint256)
///   [64..96]   destVm (uint8, right-aligned)
///   [96..128]  destAddress offset (= 0xa0, points to length slot below)
///   [128..160] caller address (right-aligned 20 bytes — populated by the
///              transaction sender, not auto-injected by the runtime)
///   [160..192] destAddress length (uint256, big-endian)
///   [192..]    destAddress data (right-padded to 32-byte multiple)
fn handle_cross_vm_transfer(
    token: &TnzoToken,
    registry: &TokenRegistry,
    nonce_counter: &AtomicU64,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_CROSS_VM_TRANSFER {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 160 {
        return Ok(PrecompileResult::failed(GAS_CROSS_VM_TRANSFER));
    }

    // Parse token ID
    let mut token_id_bytes = [0u8; 32];
    token_id_bytes.copy_from_slice(&calldata[0..32]);
    let token_id = TokenId::new(token_id_bytes);

    // Parse amount
    let amount = abi::decode_uint256_at(calldata, 32).ok_or_else(|| {
        VmError::PrecompileFailed("crossVmTransfer: invalid amount".to_string())
    })?;

    // Parse destination VM type
    let dest_vm_byte = calldata[95]; // Last byte of [64..96]
    let dest_vm = byte_to_vm_type(dest_vm_byte).ok_or_else(|| {
        VmError::PrecompileFailed(format!("crossVmTransfer: invalid VM type {}", dest_vm_byte))
    })?;

    // Parse caller (sender) address
    let caller_20 = abi::decode_address_at(calldata, 128).unwrap_or([0u8; 20]);

    // Parse destination address from dynamic bytes
    let dest_address = decode_dynamic_bytes(calldata, 96).unwrap_or_default();

    // Validate the transfer
    let transfer = cross_vm::CrossVmTransfer {
        token_id,
        from_vm: TokenVmType::Evm, // Source is always EVM when called from EVM
        to_vm: dest_vm,
        from_address: caller_20.to_vec(),
        to_address: dest_address.clone(),
        amount,
        nonce: nonce_counter.fetch_add(1, Ordering::SeqCst),
    };

    registry
        .validate_cross_vm_transfer(&transfer)
        .map_err(|e| VmError::PrecompileFailed(format!("crossVmTransfer: validation failed: {}", e)))?;

    // Execute the transfer
    // For TNZO (pointer model): the balance is already unified across VMs,
    // so we just need to transfer in the native layer.
    if token_id == TokenId::tnzo() {
        let from_addr = evm_addr_to_tenzro(&caller_20);
        let to_addr = bytes_to_tenzro_address(&dest_address);

        match token.transfer(&from_addr, &to_addr, amount) {
            Ok(()) => {
                info!(
                    "Cross-VM transfer: TNZO {} from EVM 0x{} to {:?} {}",
                    amount,
                    hex::encode(caller_20),
                    dest_vm,
                    hex::encode(&dest_address),
                );
                Ok(PrecompileResult::success(abi::encode_bool(true), GAS_CROSS_VM_TRANSFER))
            }
            Err(e) => {
                warn!("Cross-VM transfer failed: {}", e);
                Ok(PrecompileResult::success(abi::encode_bool(false), GAS_CROSS_VM_TRANSFER))
            }
        }
    } else {
        // For non-TNZO tokens, cross-VM transfers require burn/mint mechanics
        // which depend on the specific VM adapters. For now, only TNZO is supported.
        warn!(
            "Cross-VM transfer: non-TNZO token {} not yet supported",
            token_id
        );
        Ok(PrecompileResult::success(abi::encode_bool(false), GAS_CROSS_VM_TRANSFER))
    }
}

/// getVmBalance(bytes32 tokenId, address owner, uint8 vm) -> uint256
///
/// Gets the balance of a token for a specific owner on a specific VM.
fn handle_get_vm_balance(
    token: &TnzoToken,
    _registry: &TokenRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    // Parse token ID
    let mut token_id_bytes = [0u8; 32];
    token_id_bytes.copy_from_slice(&calldata[0..32]);
    let token_id = TokenId::new(token_id_bytes);

    // Parse owner address
    let owner_20 = abi::decode_address_at(calldata, 32).unwrap_or([0u8; 20]);

    // Parse VM type
    let vm_byte = calldata[95]; // Last byte of [64..96]

    // For TNZO, all VMs share the same balance
    if token_id == TokenId::tnzo() {
        let addr = evm_addr_to_tenzro(&owner_20);
        let balance = token.balance_of(&addr);

        // If querying SVM balance, convert to 9-decimal
        if vm_byte == VM_TYPE_SVM {
            let spl_balance = cross_vm::native_to_spl(balance).unwrap_or(0);
            return Ok(PrecompileResult::success(
                abi::encode_uint256(spl_balance as u128),
                GAS_READ,
            ));
        }

        return Ok(PrecompileResult::success(
            abi::encode_uint256(balance),
            GAS_READ,
        ));
    }

    // For other tokens, balance lookup depends on the VM type
    // This would query the EVM state, SVM accounts, or DAML contracts
    Ok(PrecompileResult::success(abi::encode_uint256(0), GAS_READ))
}

/// getSupportedVms() -> uint8[]
fn handle_get_supported_vms(gas_limit: u64) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    // Return supported VM types as a dynamic array
    // [offset(32)] [length(32)] [vm0..vm4(32 each)]
    let mut output = Vec::with_capacity(224);
    output.extend_from_slice(&abi::encode_uint256(32)); // offset
    output.extend_from_slice(&abi::encode_uint256(5)); // length
    output.extend_from_slice(&abi::encode_uint256(VM_TYPE_NATIVE as u128));
    output.extend_from_slice(&abi::encode_uint256(VM_TYPE_EVM as u128));
    output.extend_from_slice(&abi::encode_uint256(VM_TYPE_SVM as u128));
    output.extend_from_slice(&abi::encode_uint256(VM_TYPE_DAML as u128));
    output.extend_from_slice(&abi::encode_uint256(VM_TYPE_TEMPO_TIP20 as u128));

    Ok(PrecompileResult::success(output, GAS_READ))
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Converts a u8 VM type to TokenVmType
fn byte_to_vm_type(byte: u8) -> Option<TokenVmType> {
    match byte {
        VM_TYPE_NATIVE => Some(TokenVmType::Native),
        VM_TYPE_EVM => Some(TokenVmType::Evm),
        VM_TYPE_SVM => Some(TokenVmType::Svm),
        VM_TYPE_DAML => Some(TokenVmType::Daml),
        VM_TYPE_TEMPO_TIP20 => Some(TokenVmType::TempoTip20),
        _ => None,
    }
}

/// Converts a 20-byte EVM address to a 32-byte Tenzro Address
fn evm_addr_to_tenzro(evm_addr: &[u8; 20]) -> Address {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(evm_addr);
    Address::new(bytes)
}

/// Converts arbitrary bytes to a Tenzro Address (padding or truncating to 32 bytes)
fn bytes_to_tenzro_address(bytes: &[u8]) -> Address {
    let mut addr = [0u8; 32];
    let copy_len = bytes.len().min(32);
    if bytes.len() <= 20 {
        // EVM-style: right-align in 32 bytes
        addr[32 - copy_len..32].copy_from_slice(&bytes[..copy_len]);
    } else {
        // SVM-style: left-align (already 32 bytes)
        addr[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }
    Address::new(addr)
}

/// Decodes dynamic bytes from ABI calldata at a given offset slot
fn decode_dynamic_bytes(calldata: &[u8], offset_slot: usize) -> Option<Vec<u8>> {
    if calldata.len() < offset_slot + 32 {
        return None;
    }
    let offset = abi::decode_uint256_at(calldata, offset_slot)? as usize;
    if calldata.len() < offset + 32 {
        return None;
    }
    let length = abi::decode_uint256_at(calldata, offset)? as usize;
    if length == 0 || calldata.len() < offset + 32 + length {
        return None;
    }
    Some(calldata[offset + 32..offset + 32 + length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Arc<TnzoToken>, Arc<TokenRegistry>) {
        let token = Arc::new(TnzoToken::new());
        let registry = Arc::new(TokenRegistry::new());

        let treasury = Address::new([0xFF; 32]);
        token.set_treasury_address(treasury);
        token
            .mint(
                &Address::new([0u8; 32]),
                1_000_000_000_000_000_000_000u128,
                &treasury,
            )
            .unwrap();

        registry
            .register_tnzo(Some([0x01; 20]), Some([0x02; 32]), None)
            .unwrap();

        (token, registry)
    }

    #[test]
    fn test_get_supported_vms() {
        let (token, registry) = setup();
        let nonce_counter = AtomicU64::new(1);
        let input = [&selectors::GET_SUPPORTED_VMS[..]].concat();
        let result = execute_cross_vm_bridge(&token, &registry, &nonce_counter, &input, 100_000).unwrap();
        assert!(result.success);
        // Should have 5 VM types: Native, Evm, Svm, Daml, TempoTip20
        let length = abi::decode_uint256_at(&result.output, 32).unwrap();
        assert_eq!(length, 5);
    }

    #[test]
    fn test_get_vm_balance() {
        let (token, registry) = setup();
        let nonce_counter = AtomicU64::new(1);

        // Build calldata: getVmBalance(tokenId, owner, vmType)
        let mut input = selectors::GET_VM_BALANCE.to_vec();
        input.extend_from_slice(&TokenId::tnzo().0); // token ID
        let owner_padded = vec![0u8; 32]; // owner address (zero = has balance)
        input.extend_from_slice(&owner_padded);
        input.extend_from_slice(&abi::encode_uint256(VM_TYPE_EVM as u128)); // VM type

        let result = execute_cross_vm_bridge(&token, &registry, &nonce_counter, &input, 100_000).unwrap();
        assert!(result.success);
        let balance = abi::decode_uint256(&result.output).unwrap();
        assert!(balance > 0);
    }

    #[test]
    fn test_byte_to_vm_type() {
        assert_eq!(byte_to_vm_type(0), Some(TokenVmType::Native));
        assert_eq!(byte_to_vm_type(1), Some(TokenVmType::Evm));
        assert_eq!(byte_to_vm_type(2), Some(TokenVmType::Svm));
        assert_eq!(byte_to_vm_type(3), Some(TokenVmType::Daml));
        assert_eq!(byte_to_vm_type(4), Some(TokenVmType::TempoTip20));
        assert_eq!(byte_to_vm_type(5), None);
    }

    #[test]
    fn test_evm_addr_to_tenzro() {
        let evm = [0xAB; 20];
        let addr = evm_addr_to_tenzro(&evm);
        assert_eq!(addr.as_bytes()[12..32], [0xAB; 20]);
        assert_eq!(addr.as_bytes()[0..12], [0u8; 12]);
    }
}
