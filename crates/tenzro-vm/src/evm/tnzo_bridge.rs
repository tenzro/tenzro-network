//! wTNZO pointer precompile (`0x1001`).
//!
//! The ERC-20 interface over native TNZO. There is no wrapped balance: an
//! account's wTNZO balance is its native TNZO balance, `transfer` moves native
//! TNZO, and `totalSupply` is the native supply. Only allowances are kept,
//! in this precompile's own storage. Every operation acts for the calling
//! frame's `msg.sender`; nothing is taken from calldata for authorization.
//!
//! | Selector   | Function                                 |
//! |------------|------------------------------------------|
//! | 0x06fdde03 | name()                                   |
//! | 0x95d89b41 | symbol()                                 |
//! | 0x313ce567 | decimals()                               |
//! | 0x18160ddd | totalSupply()                            |
//! | 0x70a08231 | balanceOf(address)                       |
//! | 0xa9059cbb | transfer(address,uint256)                |
//! | 0x095ea7b3 | approve(address,uint256)                 |
//! | 0xdd62ed3e | allowance(address,address)               |
//! | 0x23b872dd | transferFrom(address,address,uint256)    |

use crate::error::Result;
use crate::evm::precompile_host::{PrecompileCall, abi_error_string, slot_key};
use crate::evm::wtnzo::{abi, events, selectors};
use crate::precompiles::PrecompileResult;

const GAS_BASE: u64 = 2_000;

fn revert(msg: &str) -> Result<PrecompileResult> {
    Ok(PrecompileResult::revert(abi_error_string(msg), 0))
}

fn allowance_slot(owner: &[u8; 20], spender: &[u8; 20]) -> [u8; 32] {
    slot_key(b"wtnzo/allowance", &[owner, spender])
}

fn addr_topic(a: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(a);
    t
}

/// Move native TNZO and emit `Transfer`. Reverts on insufficient balance.
fn move_native(
    call: &mut PrecompileCall<'_>,
    from: [u8; 20],
    to: [u8; 20],
    amount: u128,
) -> Result<Option<PrecompileResult>> {
    if !call.state.transfer(from, to, amount)? {
        return revert("wTNZO: insufficient balance").map(Some);
    }
    call.emit(
        vec![events::transfer_topic(), addr_topic(&from), addr_topic(&to)],
        abi::encode_uint256(amount),
    )?;
    Ok(None)
}

/// Entry point registered at [`crate::precompiles::PRECOMPILE_TNZO_BRIDGE`].
pub fn wtnzo_pointer_precompile(call: &mut PrecompileCall<'_>) -> Result<PrecompileResult> {
    call.charge(GAS_BASE)?;
    if call.env.value != 0 {
        return revert("wTNZO: native TNZO is already wTNZO; send no value");
    }
    if call.input.len() < 4 {
        return revert("wTNZO: missing selector");
    }
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&call.input[..4]);
    let args = &call.input[4..];
    let caller = call.env.caller;

    match sel {
        selectors::NAME => Ok(PrecompileResult::success(
            abi::encode_string("Wrapped TNZO"),
            0,
        )),
        selectors::SYMBOL => Ok(PrecompileResult::success(abi::encode_string("wTNZO"), 0)),
        selectors::DECIMALS => Ok(PrecompileResult::success(abi::encode_uint8(18), 0)),
        selectors::TOTAL_SUPPLY => {
            let supply = call.state.native_total_supply()?;
            Ok(PrecompileResult::success(abi::encode_uint256(supply), 0))
        }
        selectors::BALANCE_OF => {
            let Some(owner) = abi::decode_address_at(args, 0) else {
                return revert("wTNZO: bad address");
            };
            let b = call.state.balance(owner)?;
            Ok(PrecompileResult::success(abi::encode_uint256(b), 0))
        }
        selectors::ALLOWANCE => {
            let (Some(owner), Some(spender)) = (
                abi::decode_address_at(args, 0),
                abi::decode_address_at(args, 32),
            ) else {
                return revert("wTNZO: bad address");
            };
            let a = call.sload_u128(allowance_slot(&owner, &spender))?;
            Ok(PrecompileResult::success(abi::encode_uint256(a), 0))
        }
        selectors::TRANSFER => {
            call.require_write()?;
            let (Some(to), Some(amount)) = (
                abi::decode_address_at(args, 0),
                abi::decode_uint256_at(args, 32),
            ) else {
                return revert("wTNZO: bad arguments");
            };
            if let Some(r) = move_native(call, caller, to, amount)? {
                return Ok(r);
            }
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::APPROVE => {
            call.require_write()?;
            let (Some(spender), Some(amount)) = (
                abi::decode_address_at(args, 0),
                abi::decode_uint256_at(args, 32),
            ) else {
                return revert("wTNZO: bad arguments");
            };
            call.sstore_u128(allowance_slot(&caller, &spender), amount)?;
            call.emit(
                vec![
                    events::approval_topic(),
                    addr_topic(&caller),
                    addr_topic(&spender),
                ],
                abi::encode_uint256(amount),
            )?;
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::TRANSFER_FROM => {
            call.require_write()?;
            let (Some(from), Some(to), Some(amount)) = (
                abi::decode_address_at(args, 0),
                abi::decode_address_at(args, 32),
                abi::decode_uint256_at(args, 64),
            ) else {
                return revert("wTNZO: bad arguments");
            };
            let slot = allowance_slot(&from, &caller);
            let allowed = call.sload_u128(slot)?;
            if allowed < amount {
                return revert("wTNZO: allowance exceeded");
            }
            if allowed != u128::MAX {
                call.sstore_u128(slot, allowed - amount)?;
            }
            if let Some(r) = move_native(call, from, to, amount)? {
                return Ok(r);
            }
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        _ => revert("wTNZO: unknown selector"),
    }
}
