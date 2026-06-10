//! TNZO Bridge Precompile (0x1001)
//!
//! The bridge precompile is the only code path that can modify native TNZO balances
//! from within the EVM. It acts as the intermediary between EVM contract calls and
//! the `TnzoToken` state, following the Sei V2 pointer contract model.
//!
//! # Function Selectors
//!
//! | Selector   | Function                           | Gas    |
//! |------------|------------------------------------|--------|
//! | 0x70a08231 | balanceOf(address)                 | 2,600  |
//! | 0xa9059cbb | transfer(address,uint256)           | 9,000  |
//! | 0x18160ddd | totalSupply()                       | 2,600  |
//! | 0xd0e30db0 | deposit()                           | 9,000  |
//! | 0x2e1a7d4d | withdraw(uint256)                   | 9,000  |
//! | 0x06fdde03 | name()                              | 2,600  |
//! | 0x95d89b41 | symbol()                            | 2,600  |
//! | 0x313ce567 | decimals()                          | 2,600  |
//! | 0x095ea7b3 | approve(address,uint256)             | 5,000  |
//! | 0xdd62ed3e | allowance(address,address)           | 2,600  |
//! | 0x23b872dd | transferFrom(address,address,uint256) | 12,000 |
//! | 0xec0ec5b3 | crosschainMint(address,uint256,bytes) | 15,000 | ERC-7802
//! | 0xcba5b0a7 | crosschainBurn(address,uint256,bytes) | 15,000 | ERC-7802

use crate::evm::wtnzo::{abi, selectors};
use crate::precompiles::PrecompileResult;
use crate::error::Result;
use crate::VmError;
use std::sync::Arc;
use tenzro_token::{TnzoToken, TokenRegistry, TokenId};
use tenzro_types::primitives::Address;
use tracing::{debug, info, warn};

/// Gas costs for TNZO bridge precompile operations
const GAS_READ: u64 = 2_600;
const GAS_TRANSFER: u64 = 9_000;
const GAS_APPROVE: u64 = 5_000;
const GAS_TRANSFER_FROM: u64 = 12_000;
/// Gas cost for ERC-7802 crosschain mint/burn operations
const GAS_CROSSCHAIN: u64 = 15_000;

/// Creates the TNZO bridge precompile function
///
/// The returned closure captures references to the TnzoToken and TokenRegistry,
/// routing all calls through the native token layer.
pub fn create_tnzo_bridge_precompile(
    token: Arc<TnzoToken>,
    registry: Arc<TokenRegistry>,
) -> Arc<dyn Fn(&[u8], u64) -> Result<PrecompileResult> + Send + Sync> {
    Arc::new(move |input: &[u8], gas_limit: u64| {
        execute_tnzo_bridge(&token, &registry, input, gas_limit)
    })
}

/// Main dispatch for the TNZO bridge precompile
fn execute_tnzo_bridge(
    token: &TnzoToken,
    registry: &TokenRegistry,
    input: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if input.len() < 4 {
        return Ok(PrecompileResult::failed(gas_limit));
    }

    let selector = &input[..4];

    // Frame contract (set by `PrecompileRegistry::execute`):
    //   [0..4]    selector
    //   [4..N]    caller-supplied calldata (any ABI shape)
    //   [N..N+32] trusted msg.sender (32-byte left-padded) — RUNTIME-SET
    //
    // Read-only selectors (NAME / SYMBOL / DECIMALS / TOTAL_SUPPLY /
    // BALANCE_OF / ALLOWANCE) don't depend on the trusted caller and
    // can be invoked with no trailing slot. Write selectors REQUIRE
    // the trailing 32 bytes.
    //
    // Stripping the trailing slot off `calldata` keeps callers' encoded
    // ABI offsets (which were computed against their original calldata
    // length) intact.
    let (caller_opt, calldata): (Option<[u8; 20]>, &[u8]) = if input.len() >= 4 + 32 {
        let split = input.len() - 32;
        let mut caller = [0u8; 20];
        caller.copy_from_slice(&input[split + 12..]);
        (Some(caller), &input[4..split])
    } else {
        (None, &input[4..])
    };

    let require_caller = |sel_name: &str| -> Result<[u8; 20]> {
        caller_opt.ok_or_else(|| VmError::PrecompileFailed(format!(
            "TNZO bridge: {sel_name} requires trusted msg.sender; invoke \
             precompile via PrecompileRegistry::execute (EVM runtime path)."
        )))
    };

    match selector {
        s if s == selectors::NAME => handle_name(gas_limit),
        s if s == selectors::SYMBOL => handle_symbol(gas_limit),
        s if s == selectors::DECIMALS => handle_decimals(gas_limit),
        s if s == selectors::TOTAL_SUPPLY => handle_total_supply(token, gas_limit),
        s if s == selectors::BALANCE_OF => handle_balance_of(token, calldata, gas_limit),
        s if s == selectors::TRANSFER => {
            let caller = require_caller("transfer")?;
            handle_transfer(token, &caller, calldata, gas_limit)
        }
        s if s == selectors::APPROVE => {
            let caller = require_caller("approve")?;
            handle_approve(registry, &caller, calldata, gas_limit)
        }
        s if s == selectors::ALLOWANCE => handle_allowance(registry, calldata, gas_limit),
        s if s == selectors::TRANSFER_FROM => {
            let caller = require_caller("transferFrom")?;
            handle_transfer_from(token, registry, &caller, calldata, gas_limit)
        }
        s if s == selectors::DEPOSIT => {
            let caller = require_caller("deposit")?;
            handle_deposit(token, &caller, calldata, gas_limit)
        }
        s if s == selectors::WITHDRAW => {
            let caller = require_caller("withdraw")?;
            handle_withdraw(token, &caller, calldata, gas_limit)
        }
        // ERC-7802 Cross-Chain Token Interface
        s if s == selectors::CROSSCHAIN_MINT => {
            let caller = require_caller("crosschainMint")?;
            handle_crosschain_mint(token, &caller, calldata, gas_limit)
        }
        s if s == selectors::CROSSCHAIN_BURN => {
            let caller = require_caller("crosschainBurn")?;
            handle_crosschain_burn(token, &caller, calldata, gas_limit)
        }
        _ => {
            warn!(
                "TNZO bridge: unknown selector 0x{}",
                hex::encode(selector)
            );
            Ok(PrecompileResult::failed(gas_limit))
        }
    }
}

/// name() -> string "Wrapped TNZO"
fn handle_name(gas_limit: u64) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_READ)?;
    Ok(PrecompileResult::success(
        abi::encode_string("Wrapped TNZO"),
        GAS_READ,
    ))
}

/// symbol() -> string "wTNZO"
fn handle_symbol(gas_limit: u64) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_READ)?;
    Ok(PrecompileResult::success(
        abi::encode_string("wTNZO"),
        GAS_READ,
    ))
}

/// decimals() -> uint8(18)
fn handle_decimals(gas_limit: u64) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_READ)?;
    Ok(PrecompileResult::success(
        abi::encode_uint8(18),
        GAS_READ,
    ))
}

/// totalSupply() -> uint256
fn handle_total_supply(token: &TnzoToken, gas_limit: u64) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_READ)?;
    let supply = token.total_supply();
    Ok(PrecompileResult::success(
        abi::encode_uint256(supply),
        GAS_READ,
    ))
}

/// balanceOf(address) -> uint256
fn handle_balance_of(
    token: &TnzoToken,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_READ)?;

    let addr_20 = abi::decode_address_20(calldata).ok_or_else(|| {
        VmError::PrecompileFailed("balanceOf: invalid address encoding".to_string())
    })?;

    let address = evm_addr_to_tenzro(&addr_20);
    let balance = token.balance_of(&address);

    debug!(
        "TNZO bridge balanceOf(0x{}) = {}",
        hex::encode(addr_20),
        balance
    );

    Ok(PrecompileResult::success(
        abi::encode_uint256(balance),
        GAS_READ,
    ))
}

/// transfer(address to, uint256 amount) -> bool
///
/// Transfers native TNZO from the trusted `msg.sender` to the
/// destination. The caller is supplied by the EVM runtime via
/// `PrecompileRegistry::execute`, not by caller-supplied
/// calldata — this is the only signal that prevents arbitrary
/// impersonation.
fn handle_transfer(
    token: &TnzoToken,
    caller: &[u8; 20],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_TRANSFER)?;

    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_TRANSFER));
    }

    let to_20 = abi::decode_address_at(calldata, 0).ok_or_else(|| {
        VmError::PrecompileFailed("transfer: invalid to address".to_string())
    })?;

    let amount = abi::decode_uint256_at(calldata, 32).ok_or_else(|| {
        VmError::PrecompileFailed("transfer: invalid amount".to_string())
    })?;

    if amount == 0 {
        return Ok(PrecompileResult::success(abi::encode_bool(true), GAS_TRANSFER));
    }

    let from_addr = evm_addr_to_tenzro(caller);
    let to_addr = evm_addr_to_tenzro(&to_20);

    match token.transfer(&from_addr, &to_addr, amount) {
        Ok(()) => {
            debug!(
                "TNZO bridge transfer: {} -> 0x{}, amount={}",
                from_addr,
                hex::encode(to_20),
                amount
            );
            Ok(PrecompileResult::success(abi::encode_bool(true), GAS_TRANSFER))
        }
        Err(e) => {
            warn!("TNZO bridge transfer failed: {}", e);
            Ok(PrecompileResult::success(abi::encode_bool(false), GAS_TRANSFER))
        }
    }
}

/// approve(address spender, uint256 amount) -> bool
///
/// Stores approval in the token registry (not in EVM storage).
/// Owner is the trusted `msg.sender` supplied by the EVM runtime.
fn handle_approve(
    registry: &TokenRegistry,
    caller: &[u8; 20],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_APPROVE)?;

    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_APPROVE));
    }

    let spender = abi::decode_address_at(calldata, 0).ok_or_else(|| {
        VmError::PrecompileFailed("approve: invalid spender address".to_string())
    })?;

    let amount = abi::decode_uint256_at(calldata, 32).ok_or_else(|| {
        VmError::PrecompileFailed("approve: invalid amount".to_string())
    })?;

    let owner = *caller;

    let token_id = TokenId::tnzo();
    registry
        .set_approval(&owner, &spender, &token_id, amount)
        .map_err(|e| VmError::PrecompileFailed(format!("approve failed: {}", e)))?;

    debug!(
        "TNZO bridge approve: owner=0x{} spender=0x{} amount={}",
        hex::encode(owner),
        hex::encode(spender),
        amount
    );

    Ok(PrecompileResult::success(abi::encode_bool(true), GAS_APPROVE))
}

/// allowance(address owner, address spender) -> uint256
fn handle_allowance(
    registry: &TokenRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_READ)?;

    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let owner = abi::decode_address_at(calldata, 0).ok_or_else(|| {
        VmError::PrecompileFailed("allowance: invalid owner address".to_string())
    })?;

    let spender = abi::decode_address_at(calldata, 32).ok_or_else(|| {
        VmError::PrecompileFailed("allowance: invalid spender address".to_string())
    })?;

    let token_id = TokenId::tnzo();
    let allowance = registry.get_approval(&owner, &spender, &token_id);

    Ok(PrecompileResult::success(
        abi::encode_uint256(allowance),
        GAS_READ,
    ))
}

/// transferFrom(address from, address to, uint256 amount) -> bool
///
/// Spends from approval then transfers native TNZO. The spender is the
/// trusted `msg.sender` from the EVM runtime, not caller-supplied bytes.
fn handle_transfer_from(
    token: &TnzoToken,
    registry: &TokenRegistry,
    caller: &[u8; 20],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_TRANSFER_FROM)?;

    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_TRANSFER_FROM));
    }

    let from_20 = abi::decode_address_at(calldata, 0).ok_or_else(|| {
        VmError::PrecompileFailed("transferFrom: invalid from address".to_string())
    })?;

    let to_20 = abi::decode_address_at(calldata, 32).ok_or_else(|| {
        VmError::PrecompileFailed("transferFrom: invalid to address".to_string())
    })?;

    let amount = abi::decode_uint256_at(calldata, 64).ok_or_else(|| {
        VmError::PrecompileFailed("transferFrom: invalid amount".to_string())
    })?;

    let spender = *caller;

    if amount == 0 {
        return Ok(PrecompileResult::success(abi::encode_bool(true), GAS_TRANSFER_FROM));
    }

    // Check and spend approval
    let token_id = TokenId::tnzo();
    if let Err(e) = registry.spend_approval(&from_20, &spender, &token_id, amount) {
        warn!("TNZO bridge transferFrom: approval check failed: {}", e);
        return Ok(PrecompileResult::success(abi::encode_bool(false), GAS_TRANSFER_FROM));
    }

    // Execute the transfer
    let from_addr = evm_addr_to_tenzro(&from_20);
    let to_addr = evm_addr_to_tenzro(&to_20);

    match token.transfer(&from_addr, &to_addr, amount) {
        Ok(()) => {
            debug!(
                "TNZO bridge transferFrom: 0x{} -> 0x{}, amount={}, spender=0x{}",
                hex::encode(from_20),
                hex::encode(to_20),
                amount,
                hex::encode(spender),
            );
            Ok(PrecompileResult::success(abi::encode_bool(true), GAS_TRANSFER_FROM))
        }
        Err(e) => {
            warn!("TNZO bridge transferFrom failed: {}", e);
            Ok(PrecompileResult::success(abi::encode_bool(false), GAS_TRANSFER_FROM))
        }
    }
}

/// deposit() — payable
///
/// Pointer model: balances are shared between native TNZO and wTNZO,
/// so deposit is a structural no-op. We still require a trusted caller
/// (rejected upstream) so a contract cannot pretend to credit a
/// third-party EVM balance via this path.
fn handle_deposit(
    _token: &TnzoToken,
    _caller: &[u8; 20],
    _calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_TRANSFER)?;
    debug!("TNZO bridge deposit: no-op in pointer model (balances are unified)");
    Ok(PrecompileResult::success(Vec::new(), GAS_TRANSFER))
}

/// withdraw(uint256 amount)
///
/// Same pointer-model no-op as `deposit`. Trusted caller required upstream.
fn handle_withdraw(
    _token: &TnzoToken,
    _caller: &[u8; 20],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_TRANSFER)?;

    let _amount = if calldata.len() >= 32 {
        abi::decode_uint256(calldata).unwrap_or(0)
    } else {
        0
    };

    debug!("TNZO bridge withdraw: no-op in pointer model (balances are unified)");
    Ok(PrecompileResult::success(Vec::new(), GAS_TRANSFER))
}

// -----------------------------------------------------------------------
// ERC-7802 Cross-Chain Token Interface
// -----------------------------------------------------------------------

/// crosschainMint(address to, uint256 amount, bytes data)
///
/// Mints TNZO to the specified address. Only callable by authorized bridge adapters.
/// The `data` parameter carries the source chain ID (first 32 bytes) and the
/// original message sender address (next 32 bytes) for verification.
///
/// Input layout (after selector):
///   [0..32]   to (address, left-padded)
///   [32..64]  amount (uint256)
///   [64..96]  data offset (pointer to dynamic bytes)
///   [96..128] caller address (appended by EVM runtime — must be authorized bridge)
///   [128..]   data (length-prefixed: source_chain_id(32) + msg_sender(32))
fn handle_crosschain_mint(
    token: &TnzoToken,
    caller: &[u8; 20],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_CROSSCHAIN)?;

    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_CROSSCHAIN));
    }

    // Parse `to` address
    let to_20 = abi::decode_address_at(calldata, 0).ok_or_else(|| {
        VmError::PrecompileFailed("crosschainMint: invalid to address".to_string())
    })?;

    // Parse amount
    let amount = abi::decode_uint256_at(calldata, 32).ok_or_else(|| {
        VmError::PrecompileFailed("crosschainMint: invalid amount".to_string())
    })?;

    if amount == 0 {
        return Ok(PrecompileResult::success(Vec::new(), GAS_CROSSCHAIN));
    }

    // Verify the TRUSTED runtime-supplied caller is an authorized bridge
    // adapter. Authorized callers: the cross-VM bridge precompile
    // (0x1003), or the treasury. Previously this read the caller from
    // calldata slot 96 (caller-supplied!), which let anyone impersonate
    // the bridge by writing the bridge address into their own calldata.
    if !is_authorized_bridge_caller(caller, token) {
        warn!(
            "crosschainMint: unauthorized caller 0x{}",
            hex::encode(caller)
        );
        return Err(VmError::PrecompileFailed(
            "crosschainMint: caller is not an authorized bridge adapter".to_string(),
        ));
    }

    // Parse optional data for source chain verification
    let data = decode_dynamic_bytes(calldata, 64);
    let source_chain_id = data.as_ref().and_then(|d| {
        if d.len() >= 32 {
            Some(u128::from_be_bytes(d[16..32].try_into().unwrap_or([0u8; 16])))
        } else {
            None
        }
    });

    // Execute the mint via treasury authorization
    let to_addr = evm_addr_to_tenzro(&to_20);
    let treasury = token.treasury_address_ref();

    match treasury {
        Some(treasury_addr) => {
            match token.mint(&to_addr, amount, &treasury_addr) {
                Ok(()) => {
                    info!(
                        "ERC-7802 crosschainMint: {} TNZO to 0x{} (source_chain: {:?})",
                        amount,
                        hex::encode(to_20),
                        source_chain_id,
                    );
                    Ok(PrecompileResult::success(Vec::new(), GAS_CROSSCHAIN))
                }
                Err(e) => {
                    warn!("crosschainMint failed: {}", e);
                    Err(VmError::PrecompileFailed(format!(
                        "crosschainMint: mint failed: {}",
                        e
                    )))
                }
            }
        }
        None => Err(VmError::PrecompileFailed(
            "crosschainMint: treasury not configured".to_string(),
        )),
    }
}

/// crosschainBurn(address from, uint256 amount, bytes data)
///
/// Burns TNZO from the specified address for cross-chain transfer out.
/// The `data` parameter carries the destination chain ID (first 32 bytes)
/// and the destination address (next 32 bytes).
///
/// Input layout (after selector):
///   [0..32]   from (address, left-padded)
///   [32..64]  amount (uint256)
///   [64..96]  data offset (pointer to dynamic bytes)
///   [96..128] caller address (appended by EVM runtime — must be authorized bridge)
///   [128..]   data (length-prefixed: dest_chain_id(32) + dest_address(32))
fn handle_crosschain_burn(
    token: &TnzoToken,
    caller: &[u8; 20],
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    check_gas(gas_limit, GAS_CROSSCHAIN)?;

    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_CROSSCHAIN));
    }

    // Parse `from` address
    let from_20 = abi::decode_address_at(calldata, 0).ok_or_else(|| {
        VmError::PrecompileFailed("crosschainBurn: invalid from address".to_string())
    })?;

    // Parse amount
    let amount = abi::decode_uint256_at(calldata, 32).ok_or_else(|| {
        VmError::PrecompileFailed("crosschainBurn: invalid amount".to_string())
    })?;

    if amount == 0 {
        return Ok(PrecompileResult::success(Vec::new(), GAS_CROSSCHAIN));
    }

    // Verify the TRUSTED runtime-supplied caller is an authorized bridge
    // adapter (see crosschainMint commentary).
    if !is_authorized_bridge_caller(caller, token) {
        warn!(
            "crosschainBurn: unauthorized caller 0x{}",
            hex::encode(caller)
        );
        return Err(VmError::PrecompileFailed(
            "crosschainBurn: caller is not an authorized bridge adapter".to_string(),
        ));
    }

    // Parse optional data for destination chain info
    let data = decode_dynamic_bytes(calldata, 64);
    let dest_chain_id = data.as_ref().and_then(|d| {
        if d.len() >= 32 {
            Some(u128::from_be_bytes(d[16..32].try_into().unwrap_or([0u8; 16])))
        } else {
            None
        }
    });

    // Execute the burn
    let from_addr = evm_addr_to_tenzro(&from_20);

    match token.burn(&from_addr, amount) {
        Ok(()) => {
            info!(
                "ERC-7802 crosschainBurn: {} TNZO from 0x{} (dest_chain: {:?})",
                amount,
                hex::encode(from_20),
                dest_chain_id,
            );
            Ok(PrecompileResult::success(Vec::new(), GAS_CROSSCHAIN))
        }
        Err(e) => {
            warn!("crosschainBurn failed: {}", e);
            Err(VmError::PrecompileFailed(format!(
                "crosschainBurn: burn failed: {}",
                e
            )))
        }
    }
}

/// Checks whether a 20-byte EVM caller is an authorized bridge adapter.
///
/// Authorized callers are:
/// - The cross-VM bridge precompile (0x1003)
/// - The treasury address
/// - Any address registered as a bridge adapter in the TNZO bridge's
///   authorized set (future: on-chain registry)
fn is_authorized_bridge_caller(caller: &[u8; 20], token: &TnzoToken) -> bool {
    use crate::evm::wtnzo::CROSS_VM_BRIDGE_ADDRESS;

    // Cross-VM bridge precompile is always authorized
    if caller == &CROSS_VM_BRIDGE_ADDRESS {
        return true;
    }

    // Treasury is always authorized
    if let Some(treasury) = token.treasury_address_ref() {
        let mut treasury_20 = [0u8; 20];
        treasury_20.copy_from_slice(&treasury.as_bytes()[12..32]);
        if caller == &treasury_20 {
            return true;
        }
    }

    false
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

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Converts a 20-byte EVM address to a 32-byte Tenzro Address
fn evm_addr_to_tenzro(evm_addr: &[u8; 20]) -> Address {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(evm_addr);
    Address::new(bytes)
}

/// Checks that sufficient gas is available
fn check_gas(gas_limit: u64, required: u64) -> Result<()> {
    if gas_limit < required {
        Err(VmError::OutOfGas)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Arc<TnzoToken>, Arc<TokenRegistry>) {
        let token = Arc::new(TnzoToken::new());
        let registry = Arc::new(TokenRegistry::new());

        // Setup treasury and mint some tokens
        let treasury = Address::new([0xFF; 32]);
        token.set_treasury_address(treasury);
        token
            .mint(&Address::new([0u8; 32]), 1_000_000_000_000_000_000_000u128, &treasury)
            .unwrap();

        (token, registry)
    }

    #[test]
    fn test_name() {
        let (token, registry) = setup();
        let input = selectors::NAME.to_vec();
        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, GAS_READ);
    }

    #[test]
    fn test_symbol() {
        let (token, registry) = setup();
        let input = selectors::SYMBOL.to_vec();
        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_decimals() {
        let (token, registry) = setup();
        let input = selectors::DECIMALS.to_vec();
        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);
        assert_eq!(result.output[31], 18);
    }

    #[test]
    fn test_total_supply() {
        let (token, registry) = setup();
        let input = selectors::TOTAL_SUPPLY.to_vec();
        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);
        let supply = abi::decode_uint256(&result.output).unwrap();
        assert!(supply > 0);
    }

    #[test]
    fn test_balance_of() {
        let (token, registry) = setup();
        let addr_20 = [0u8; 20]; // Corresponds to Address::new([0u8; 32])

        let mut input = selectors::BALANCE_OF.to_vec();
        let mut padded = vec![0u8; 32];
        padded[12..32].copy_from_slice(&addr_20);
        input.extend_from_slice(&padded);

        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);
        let balance = abi::decode_uint256(&result.output).unwrap();
        assert_eq!(balance, 1_000_000_000_000_000_000_000u128);
    }

    #[test]
    fn test_approve_and_allowance() {
        let (token, registry) = setup();

        let owner = [0x01u8; 20];
        let spender = [0x02u8; 20];
        let amount = 500u128;

        // Approve
        let mut input = selectors::APPROVE.to_vec();
        let mut spender_padded = vec![0u8; 32];
        spender_padded[12..32].copy_from_slice(&spender);
        input.extend_from_slice(&spender_padded);
        input.extend_from_slice(&abi::encode_uint256(amount));
        // Append owner context
        let mut owner_padded = vec![0u8; 32];
        owner_padded[12..32].copy_from_slice(&owner);
        input.extend_from_slice(&owner_padded);

        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);

        // Check allowance
        let mut input = selectors::ALLOWANCE.to_vec();
        input.extend_from_slice(&owner_padded);
        input.extend_from_slice(&spender_padded);

        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);
        let allowance = abi::decode_uint256(&result.output).unwrap();
        assert_eq!(allowance, 500);
    }

    #[test]
    fn test_insufficient_gas() {
        let (token, registry) = setup();
        let input = selectors::TOTAL_SUPPLY.to_vec();
        let result = execute_tnzo_bridge(&token, &registry, &input, 100); // Not enough gas
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_selector() {
        let (token, registry) = setup();
        let input = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_erc7802_selectors() {
        // Verify ERC-7802 selector computation matches Solidity ABI
        use sha3::{Digest, Keccak256};

        let mut hasher = Keccak256::new();
        hasher.update(b"crosschainMint(address,uint256,bytes)");
        let result = hasher.finalize();
        assert_eq!(&result[..4], &selectors::CROSSCHAIN_MINT);

        let mut hasher = Keccak256::new();
        hasher.update(b"crosschainBurn(address,uint256,bytes)");
        let result = hasher.finalize();
        assert_eq!(&result[..4], &selectors::CROSSCHAIN_BURN);
    }

    #[test]
    fn test_crosschain_mint_authorized() {
        let (token, registry) = setup();

        // Caller is the cross-VM bridge precompile (authorized)
        let cross_vm_addr = crate::evm::wtnzo::CROSS_VM_BRIDGE_ADDRESS;
        let to_addr = [0xAA; 20];

        let mut input = selectors::CROSSCHAIN_MINT.to_vec();
        // to address
        let mut to_padded = vec![0u8; 32];
        to_padded[12..32].copy_from_slice(&to_addr);
        input.extend_from_slice(&to_padded);
        // amount = 1000
        input.extend_from_slice(&abi::encode_uint256(1000));
        // data offset (points to byte 96 from start of calldata, but we put it at 128)
        input.extend_from_slice(&abi::encode_uint256(128));
        // caller (cross-VM bridge = authorized)
        let mut caller_padded = vec![0u8; 32];
        caller_padded[12..32].copy_from_slice(&cross_vm_addr);
        input.extend_from_slice(&caller_padded);
        // data: length=32, then source_chain_id=1
        input.extend_from_slice(&abi::encode_uint256(32)); // length
        input.extend_from_slice(&abi::encode_uint256(1)); // source chain id

        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_crosschain_mint_unauthorized() {
        let (token, registry) = setup();

        let unauthorized = [0xBB; 20];
        let to_addr = [0xAA; 20];

        let mut input = selectors::CROSSCHAIN_MINT.to_vec();
        let mut to_padded = vec![0u8; 32];
        to_padded[12..32].copy_from_slice(&to_addr);
        input.extend_from_slice(&to_padded);
        input.extend_from_slice(&abi::encode_uint256(1000));
        input.extend_from_slice(&abi::encode_uint256(128));
        // unauthorized caller
        let mut caller_padded = vec![0u8; 32];
        caller_padded[12..32].copy_from_slice(&unauthorized);
        input.extend_from_slice(&caller_padded);
        input.extend_from_slice(&abi::encode_uint256(0)); // empty data

        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_crosschain_burn() {
        let (token, registry) = setup();

        let cross_vm_addr = crate::evm::wtnzo::CROSS_VM_BRIDGE_ADDRESS;
        // Burn from the address that has tokens (Address::new([0u8; 32]))
        let from_addr = [0u8; 20];

        let mut input = selectors::CROSSCHAIN_BURN.to_vec();
        let mut from_padded = vec![0u8; 32];
        from_padded[12..32].copy_from_slice(&from_addr);
        input.extend_from_slice(&from_padded);
        input.extend_from_slice(&abi::encode_uint256(500));
        input.extend_from_slice(&abi::encode_uint256(128));
        let mut caller_padded = vec![0u8; 32];
        caller_padded[12..32].copy_from_slice(&cross_vm_addr);
        input.extend_from_slice(&caller_padded);
        input.extend_from_slice(&abi::encode_uint256(32));
        input.extend_from_slice(&abi::encode_uint256(42)); // dest chain id

        let result = execute_tnzo_bridge(&token, &registry, &input, 100_000).unwrap();
        assert!(result.success);
    }
}
