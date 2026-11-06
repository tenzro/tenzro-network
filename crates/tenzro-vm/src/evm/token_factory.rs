//! Token factory precompile (`0x1002`).
//!
//! Permissionless fungible tokens whose whole ledger (metadata, balances,
//! allowances) lives in this precompile's storage, so it is part of the
//! state root and journaled with the transaction that touches it. A token is
//! addressed by its 32-byte id, `keccak256(creator || creator_nonce)`, and
//! every write acts for the calling frame's `msg.sender`.
//!
//! These tokens are separate assets. They never touch native TNZO balances.
//! A token created here has a fixed supply and no issuer powers; a native
//! `Token` transaction creates tokens with a power manifest and an
//! eligibility policy. Every holder transfer here goes through the ledger's
//! one rule engine (`token_ledger::can_transfer`).
//!
//! | Selector   | Function                                             |
//! |------------|------------------------------------------------------|
//! | 0x210f5dda | createToken(string,string,uint8,uint256) -> bytes32  |
//! | 0x155bf4e2 | getToken(bytes32)                                    |
//! | 0x78a89567 | getTokenCount()                                      |
//! | 0xc2038236 | balanceOf(bytes32,address)                           |
//! | 0x3feb1bd8 | transfer(bytes32,address,uint256)                    |
//! | 0xbf1ed1eb | approve(bytes32,address,uint256)                     |
//! | 0xe88a3178 | allowance(bytes32,address,address)                   |
//! | 0x500d2f6d | transferFrom(bytes32,address,address,uint256)        |
//!
//! The ERC-7943 (uRWA) interface, keyed by token id, reads and writes the
//! same ledger through the same rule engine: `canTransact(bytes32,address)`,
//! `canTransfer(bytes32,address,address,uint256)`,
//! `getFrozenTokens(bytes32,address)`, `setFrozenTokens(bytes32,address,uint256)`,
//! `forcedTransfer(bytes32,address,address,uint256)`, plus
//! `facadeOf(bytes32) -> address` and `supportsInterface(bytes4)`.
//!
//! Every token also answers at its own facade address
//! ([`facade_address`]): the standard ERC-20 functions and the standard
//! ERC-7943 functions without a token-id argument, forwarded to this
//! precompile with the id filled in. A facade has no storage of its own.
//!
//! `setFrozenTokens` and `forcedTransfer` act only for an issuer that holds
//! the power alone under the token's manifest; a council-held power goes
//! through the native `Token` transaction. The action record they write
//! carries reason code [`ERC7943_REASON_CODE`] and the hash of the call as
//! its evidence.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::error::{Result, VmError};
use crate::evm::precompile_host::{PrecompileCall, abi_error_string, slot_key};
use crate::evm::wtnzo::{abi, events};
use crate::precompiles::PrecompileResult;

/// Function selectors
pub mod selectors {
    /// createToken(string name, string symbol, uint8 decimals, uint256 initialSupply)
    pub const CREATE_TOKEN: [u8; 4] = [0x21, 0x0f, 0x5d, 0xda];
    /// getToken(bytes32 token)
    pub const GET_TOKEN: [u8; 4] = [0x15, 0x5b, 0xf4, 0xe2];
    /// getTokenCount()
    pub const GET_TOKEN_COUNT: [u8; 4] = [0x78, 0xa8, 0x95, 0x67];
    /// balanceOf(bytes32 token, address owner)
    pub const BALANCE_OF: [u8; 4] = [0xc2, 0x03, 0x82, 0x36];
    /// transfer(bytes32 token, address to, uint256 amount)
    pub const TRANSFER: [u8; 4] = [0x3f, 0xeb, 0x1b, 0xd8];
    /// approve(bytes32 token, address spender, uint256 amount)
    pub const APPROVE: [u8; 4] = [0xbf, 0x1e, 0xd1, 0xeb];
    /// allowance(bytes32 token, address owner, address spender)
    pub const ALLOWANCE: [u8; 4] = [0xe8, 0x8a, 0x31, 0x78];
    /// transferFrom(bytes32 token, address from, address to, uint256 amount)
    pub const TRANSFER_FROM: [u8; 4] = [0x50, 0x0d, 0x2f, 0x6d];
}

/// The function selector of a Solidity signature.
pub fn selector(signature: &str) -> [u8; 4] {
    let d = Keccak256::digest(signature.as_bytes());
    [d[0], d[1], d[2], d[3]]
}

/// The standard ERC-7943 fungible functions (no token-id argument), whose
/// selectors XOR to the interface id.
pub const ERC7943_FUNCTIONS: [&str; 5] = [
    "forcedTransfer(address,address,uint256)",
    "setFrozenTokens(address,uint256)",
    "canTransact(address)",
    "getFrozenTokens(address)",
    "canTransfer(address,address,uint256)",
];

/// The standard ERC-20 functions a facade answers.
pub const ERC20_FUNCTIONS: [&str; 6] = [
    "totalSupply()",
    "balanceOf(address)",
    "transfer(address,uint256)",
    "allowance(address,address)",
    "approve(address,uint256)",
    "transferFrom(address,address,uint256)",
];

/// ERC-165 interface id of a set of functions: the XOR of their selectors.
pub fn interface_id(functions: &[&str]) -> [u8; 4] {
    functions.iter().fold([0u8; 4], |acc, f| {
        let s = selector(f);
        [acc[0] ^ s[0], acc[1] ^ s[1], acc[2] ^ s[2], acc[3] ^ s[3]]
    })
}

/// ERC-165's own interface id.
pub const ERC165_INTERFACE_ID: [u8; 4] = [0x01, 0xff, 0xc9, 0xa7];

/// Reason code an issuer action taken through the ERC-7943 interface
/// records: the call itself is the evidence, hashed.
pub const ERC7943_REASON_CODE: u16 = 0x7943;

/// Leading bytes of every per-token facade address. No precompile and no
/// account the factory creates starts with them.
pub const FACADE_PREFIX: [u8; 6] = [0, 0, 0, 0, 0x10, 0x02];

/// The facade address of token `id`.
pub fn facade_address(id: &[u8; 32]) -> [u8; 20] {
    let mut h = Keccak256::new();
    h.update(b"tenzro/token-factory/facade");
    h.update(id);
    let d = h.finalize();
    let mut a = [0u8; 20];
    a[..6].copy_from_slice(&FACADE_PREFIX);
    a[6..].copy_from_slice(&d[..14]);
    a
}

/// Whether `address` is shaped like a facade address.
pub fn is_facade_address(address: &[u8; 20]) -> bool {
    address[..6] == FACADE_PREFIX
}

/// Storage slot holding the token id behind facade `address`.
pub(crate) fn facade_slot(address: &[u8; 20]) -> [u8; 32] {
    slot_key(b"token/facade", &[address])
}

const GAS_BASE: u64 = 2_000;
const GAS_CREATE: u64 = 50_000;
const MAX_NAME_LEN: usize = 64;

/// A token's definition, as the factory stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRecord {
    /// Display name.
    pub name: String,
    /// Ticker symbol.
    pub symbol: String,
    /// Decimal places.
    pub decimals: u8,
    /// Units in existence.
    pub total_supply: u128,
    /// The issuer's ledger account (20 bytes for an EVM creator, 32 for a
    /// native one). It exercises every power the manifest gives the issuer.
    pub creator: Vec<u8>,
    /// Ceiling on `total_supply`, when the token has one.
    pub max_supply: Option<u128>,
    /// Who holds each issuer power. Only narrows.
    pub powers: tenzro_types::token_policy::PowerManifest,
    /// Who may hold the token.
    pub policy: tenzro_types::token_policy::TokenPolicy,
    /// Issuer council, for powers the manifest gives to one.
    pub council: Option<tenzro_types::token_policy::KeySet>,
    /// For a token backed one to one by reserves held elsewhere: the bonded
    /// attestor stake each mint's reserve attestations must hold.
    pub reserve_backing: Option<tenzro_types::token_policy::ReserveBacking>,
    /// A queued policy and reserve-backing change and when it may apply.
    pub pending: Option<PendingChange>,
}

/// A queued change to a token's policy and reserve backing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingChange {
    /// The policy that applies once executed.
    pub policy: tenzro_types::token_policy::TokenPolicy,
    /// The reserve backing that applies once executed.
    pub reserve_backing: Option<tenzro_types::token_policy::ReserveBacking>,
    /// Earliest block time it may be executed at.
    pub eta_ms: i64,
}

fn revert(msg: &str) -> Result<PrecompileResult> {
    Ok(PrecompileResult::revert(abi_error_string(msg), 0))
}

pub(crate) fn token_slot(id: &[u8; 32]) -> [u8; 32] {
    slot_key(b"token/record", &[id])
}

/// Storage slot of the amount of `owner`'s balance of `id` its issuer froze.
pub(crate) fn frozen_slot(id: &[u8; 32], owner: &[u8]) -> [u8; 32] {
    slot_key(
        b"token/frozen",
        &[id, crate::state_adapter::ledger_account(owner)],
    )
}

/// Storage slot holding 1 while the issuer has halted holder transfers of `id`.
pub(crate) fn halted_slot(id: &[u8; 32]) -> [u8; 32] {
    slot_key(b"token/halted", &[id])
}

/// The id of the token `creator` makes with its `nonce`-th creation.
pub(crate) fn token_id(creator: &[u8], nonce: u128) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"tenzro/token-factory/id");
    h.update(crate::state_adapter::ledger_account(creator));
    h.update(nonce.to_be_bytes());
    let mut id = [0u8; 32];
    id.copy_from_slice(&h.finalize());
    id
}
/// Storage slot of `owner`'s balance of token `id`. `owner` is any ledger
/// account: a 20-byte EVM address, or a 32-byte SVM key. A 32-byte
/// key that is a 20-byte address followed by twelve zero bytes names the
/// same balance as that address, as it does for native TNZO.
pub(crate) fn balance_slot(id: &[u8; 32], owner: &[u8]) -> [u8; 32] {
    slot_key(
        b"token/balance",
        &[id, crate::state_adapter::ledger_account(owner)],
    )
}

/// Decimals of token `id`, read from VM state, or `None` when no such token
/// exists.
pub(crate) fn token_decimals(state: &dyn crate::traits::VmState, id: &[u8; 32]) -> Option<u8> {
    let bytes = crate::evm::precompile_host::state_blob(
        state,
        &crate::precompiles::PRECOMPILE_TOKEN_FACTORY,
        token_slot(id),
    )?;
    serde_json::from_slice::<TokenRecord>(&bytes)
        .ok()
        .map(|r| r.decimals)
}
/// Storage slot of the claim `issuer_did` made about `subject` of `kind`
/// for token `id`.
pub(crate) fn claim_slot(id: &[u8; 32], subject: &[u8], kind: &str, issuer_did: &str) -> [u8; 32] {
    slot_key(
        b"token/claim",
        &[
            id,
            crate::state_adapter::ledger_account(subject),
            kind.as_bytes(),
            issuer_did.as_bytes(),
        ],
    )
}

/// Storage slot of the number of accounts holding a non-zero balance of `id`.
pub(crate) fn holders_slot(id: &[u8; 32]) -> [u8; 32] {
    slot_key(b"token/holders", &[id])
}

/// Storage slot of the council approvals recorded for one issuer operation.
pub(crate) fn approvals_slot(id: &[u8; 32], op_hash: &[u8; 32]) -> [u8; 32] {
    slot_key(b"token/approvals", &[id, op_hash])
}

fn allowance_slot(id: &[u8; 32], owner: &[u8; 20], spender: &[u8; 20]) -> [u8; 32] {
    slot_key(b"token/allowance", &[id, owner, spender])
}
pub(crate) fn nonce_slot(creator: &[u8]) -> [u8; 32] {
    slot_key(
        b"token/nonce",
        &[crate::state_adapter::ledger_account(creator)],
    )
}
pub(crate) fn count_slot() -> [u8; 32] {
    slot_key(b"token/count", &[])
}

fn load_token(call: &mut PrecompileCall<'_>, id: &[u8; 32]) -> Result<Option<TokenRecord>> {
    match call.read_blob(token_slot(id))? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| VmError::Internal(format!("corrupt token record: {e}"))),
        None => Ok(None),
    }
}

/// The issuer as an ABI word: an EVM creator as an address, a native
/// 32-byte account as itself.
fn creator_word(creator: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    match creator.len() {
        20 => w[12..].copy_from_slice(creator),
        32 => w.copy_from_slice(creator),
        _ => {}
    }
    w
}

fn addr_topic(a: &[u8; 20]) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[12..].copy_from_slice(a);
    t
}

/// Keep the holder count as one balance moves from `before` to `after`.
fn note_holder(
    call: &mut PrecompileCall<'_>,
    id: &[u8; 32],
    before: u128,
    after: u128,
) -> Result<()> {
    let holders = call.sload_u128(holders_slot(id))?;
    let next = crate::token_ledger::holders_after(holders, before, after);
    if next != holders {
        call.sstore_u128(holders_slot(id), next)?;
    }
    Ok(())
}

fn move_tokens(
    call: &mut PrecompileCall<'_>,
    id: &[u8; 32],
    from: [u8; 20],
    to: [u8; 20],
    amount: u128,
) -> Result<std::result::Result<(), String>> {
    let from_slot = balance_slot(id, &from);
    let from_bal = call.sload_u128(from_slot)?;
    if from_bal < amount {
        return Ok(Err("token factory: insufficient balance".to_string()));
    }
    let now_ms = (call.env.block_timestamp as i64).saturating_mul(1000);
    if let Err(refusal) = crate::token_ledger::can_transfer(call, id, &from, &to, amount, now_ms)? {
        return Ok(Err(format!("token factory: {refusal}")));
    }
    // Debit first and re-read the recipient afterwards, so a transfer to
    // oneself nets to zero.
    call.sstore_u128(from_slot, from_bal - amount)?;
    note_holder(call, id, from_bal, from_bal - amount)?;
    let to_slot = balance_slot(id, &to);
    let to_bal = call.sload_u128(to_slot)?;
    let Some(new_to) = to_bal.checked_add(amount) else {
        return Err(VmError::PrecompileFailed(
            "token balance overflow".to_string(),
        ));
    };
    call.sstore_u128(to_slot, new_to)?;
    note_holder(call, id, to_bal, new_to)?;
    let mut data = id.to_vec();
    data.extend_from_slice(&abi::encode_uint256(amount));
    call.emit(
        vec![events::transfer_topic(), addr_topic(&from), addr_topic(&to)],
        data,
    )?;
    Ok(Ok(()))
}

/// Entry point registered at [`crate::precompiles::PRECOMPILE_TOKEN_FACTORY`].
pub fn token_factory_precompile(call: &mut PrecompileCall<'_>) -> Result<PrecompileResult> {
    call.charge(GAS_BASE)?;
    if call.env.value != 0 {
        return revert("token factory: send no value");
    }
    if call.input.len() < 4 {
        return revert("token factory: missing selector");
    }
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&call.input[..4]);
    let args = call.input[4..].to_vec();
    let caller = call.env.caller;

    match sel {
        selectors::CREATE_TOKEN => {
            call.require_write()?;
            call.charge(GAS_CREATE)?;
            let (Some(name), Some(symbol), Some(decimals), Some(supply)) = (
                abi::decode_dynamic_string(&args, 0, 0),
                abi::decode_dynamic_string(&args, 0, 32),
                abi::decode_uint256_at(&args, 64),
                abi::decode_uint256_at(&args, 96),
            ) else {
                return revert("token factory: bad arguments");
            };
            if name.is_empty()
                || symbol.is_empty()
                || name.len() > MAX_NAME_LEN
                || symbol.len() > MAX_NAME_LEN
                || decimals > 36
            {
                return revert("token factory: invalid name, symbol or decimals");
            }
            let nonce = call.sload_u128(nonce_slot(&caller))?;
            call.sstore_u128(nonce_slot(&caller), nonce + 1)?;
            let id = token_id(&caller, nonce);
            let record = TokenRecord {
                name,
                symbol,
                decimals: decimals as u8,
                total_supply: supply,
                creator: caller.to_vec(),
                max_supply: Some(supply),
                powers: tenzro_types::token_policy::PowerManifest::NONE,
                policy: tenzro_types::token_policy::TokenPolicy::default(),
                council: None,
                reserve_backing: None,
                pending: None,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| VmError::Internal(format!("token record encode: {e}")))?;
            call.write_blob(token_slot(&id), &bytes)?;
            call.sstore(facade_slot(&facade_address(&id)), id)?;
            call.sstore_u128(balance_slot(&id, &caller), supply)?;
            note_holder(call, &id, 0, supply)?;
            call.emit(vec![crate::token_ledger::token_created_topic(), id], bytes)?;
            let count = call.sload_u128(count_slot())?;
            call.sstore_u128(count_slot(), count + 1)?;
            Ok(PrecompileResult::success(id.to_vec(), 0))
        }
        selectors::GET_TOKEN => {
            let Some(id) = abi::decode_bytes32_at(&args, 0) else {
                return revert("token factory: bad token id");
            };
            let Some(t) = load_token(call, &id)? else {
                return revert("token factory: unknown token");
            };
            // (string name, string symbol, uint8 decimals, uint256 totalSupply, address creator)
            let name = t.name.as_bytes();
            let symbol = t.symbol.as_bytes();
            let name_block = 32 + name.len().div_ceil(32) * 32;
            let mut out = Vec::new();
            out.extend_from_slice(&abi::encode_uint256(160));
            out.extend_from_slice(&abi::encode_uint256((160 + name_block) as u128));
            out.extend_from_slice(&abi::encode_uint8(t.decimals));
            out.extend_from_slice(&abi::encode_uint256(t.total_supply));
            out.extend_from_slice(&creator_word(&t.creator));
            for s in [name, symbol] {
                out.extend_from_slice(&abi::encode_uint256(s.len() as u128));
                let start = out.len();
                out.extend_from_slice(s);
                out.resize(start + s.len().div_ceil(32) * 32, 0);
            }
            Ok(PrecompileResult::success(out, 0))
        }
        selectors::GET_TOKEN_COUNT => {
            let c = call.sload_u128(count_slot())?;
            Ok(PrecompileResult::success(abi::encode_uint256(c), 0))
        }
        selectors::BALANCE_OF => {
            let (Some(id), Some(owner)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
            ) else {
                return revert("token factory: bad arguments");
            };
            let b = call.sload_u128(balance_slot(&id, &owner))?;
            Ok(PrecompileResult::success(abi::encode_uint256(b), 0))
        }
        selectors::ALLOWANCE => {
            let (Some(id), Some(owner), Some(spender)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_address_at(&args, 64),
            ) else {
                return revert("token factory: bad arguments");
            };
            let a = call.sload_u128(allowance_slot(&id, &owner, &spender))?;
            Ok(PrecompileResult::success(abi::encode_uint256(a), 0))
        }
        selectors::TRANSFER => {
            call.require_write()?;
            let (Some(id), Some(to), Some(amount)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_uint256_at(&args, 64),
            ) else {
                return revert("token factory: bad arguments");
            };
            if load_token(call, &id)?.is_none() {
                return revert("token factory: unknown token");
            }
            if let Err(reason) = move_tokens(call, &id, caller, to, amount)? {
                return revert(&reason);
            }
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::APPROVE => {
            call.require_write()?;
            let (Some(id), Some(spender), Some(amount)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_uint256_at(&args, 64),
            ) else {
                return revert("token factory: bad arguments");
            };
            call.sstore_u128(allowance_slot(&id, &caller, &spender), amount)?;
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::TRANSFER_FROM => {
            call.require_write()?;
            let (Some(id), Some(from), Some(to), Some(amount)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_address_at(&args, 64),
                abi::decode_uint256_at(&args, 96),
            ) else {
                return revert("token factory: bad arguments");
            };
            let slot = allowance_slot(&id, &from, &caller);
            let allowed = call.sload_u128(slot)?;
            if allowed < amount {
                return revert("token factory: allowance exceeded");
            }
            if allowed != u128::MAX {
                call.sstore_u128(slot, allowed - amount)?;
            }
            if let Err(reason) = move_tokens(call, &id, from, to, amount)? {
                return revert(&reason);
            }
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        _ => erc7943(call, sel, &args, caller),
    }
}

/// The ERC-7943 functions keyed by token id, `facadeOf` and
/// `supportsInterface`.
fn erc7943(
    call: &mut PrecompileCall<'_>,
    sel: [u8; 4],
    args: &[u8],
    caller: [u8; 20],
) -> Result<PrecompileResult> {
    let now_ms = (call.env.block_timestamp as i64).saturating_mul(1000);
    if sel == selector("supportsInterface(bytes4)") {
        let Some(word) = abi::word_at(args, 0) else {
            return revert("token factory: bad arguments");
        };
        let id = [word[0], word[1], word[2], word[3]];
        let yes = id == ERC165_INTERFACE_ID
            || id == interface_id(&ERC7943_FUNCTIONS)
            || id == interface_id(&ERC20_FUNCTIONS);
        return Ok(PrecompileResult::success(abi::encode_bool(yes), 0));
    }
    let Some(id) = abi::decode_bytes32_at(args, 0) else {
        return revert("token factory: unknown selector");
    };
    if sel == selector("facadeOf(bytes32)") {
        return Ok(PrecompileResult::success(
            abi::encode_address(&facade_address(&id)),
            0,
        ));
    }
    if sel == selector("canTransact(bytes32,address)") {
        let Some(account) = abi::decode_address_at(args, 32) else {
            return revert("token factory: bad arguments");
        };
        let ok = match crate::token_ledger::read_record(call, &id)? {
            Some(record) => {
                crate::token_ledger::can_receive(call, &id, &record, &account, 0, now_ms)?.is_ok()
            }
            None => false,
        };
        return Ok(PrecompileResult::success(abi::encode_bool(ok), 0));
    }
    if sel == selector("canTransfer(bytes32,address,address,uint256)") {
        let (Some(from), Some(to), Some(amount)) = (
            abi::decode_address_at(args, 32),
            abi::decode_address_at(args, 64),
            abi::decode_uint256_at(args, 96),
        ) else {
            return revert("token factory: bad arguments");
        };
        let ok = crate::token_ledger::can_transfer(call, &id, &from, &to, amount, now_ms)?.is_ok();
        return Ok(PrecompileResult::success(abi::encode_bool(ok), 0));
    }
    if sel == selector("getFrozenTokens(bytes32,address)") {
        let Some(account) = abi::decode_address_at(args, 32) else {
            return revert("token factory: bad arguments");
        };
        let f = call.sload_u128(frozen_slot(&id, &account))?;
        return Ok(PrecompileResult::success(abi::encode_uint256(f), 0));
    }
    if sel == selector("setFrozenTokens(bytes32,address,uint256)") {
        call.require_write()?;
        let (Some(account), Some(amount)) = (
            abi::decode_address_at(args, 32),
            abi::decode_uint256_at(args, 64),
        ) else {
            return revert("token factory: bad arguments");
        };
        if let Err(reason) = issuer_alone(
            call,
            &id,
            tenzro_types::token_policy::Power::Freeze,
            &caller,
        )? {
            return revert(&reason);
        }
        let held = call.sload_u128(balance_slot(&id, &account))?;
        let Some(amount) = crate::token_ledger::freeze_within(amount, held) else {
            return revert(&format!(
                "token factory: the holder has {held}, the freeze is {amount}"
            ));
        };
        call.sstore_u128(frozen_slot(&id, &account), amount)?;
        let mut data = id.to_vec();
        data.extend_from_slice(&abi::encode_uint256(amount));
        call.emit(vec![frozen_topic(), addr_topic(&account)], data)?;
        record_action(call, &id)?;
        return Ok(PrecompileResult::success(abi::encode_bool(true), 0));
    }
    if sel == selector("forcedTransfer(bytes32,address,address,uint256)") {
        call.require_write()?;
        let (Some(from), Some(to), Some(amount)) = (
            abi::decode_address_at(args, 32),
            abi::decode_address_at(args, 64),
            abi::decode_uint256_at(args, 96),
        ) else {
            return revert("token factory: bad arguments");
        };
        let record =
            match issuer_alone(call, &id, tenzro_types::token_policy::Power::Force, &caller)? {
                Ok(record) => record,
                Err(reason) => return revert(&reason),
            };
        // The same rule the native forced transfer applies: no halt, lockup
        // or frozen amount stops it, but the recipient must be eligible, and
        // the frozen amount drops to what the holder keeps.
        if let Err(refusal) =
            crate::token_ledger::can_receive(call, &id, &record, &to, amount, now_ms)?
        {
            return revert(&format!("token factory: {refusal}"));
        }
        let from_slot = balance_slot(&id, &from);
        let from_bal = call.sload_u128(from_slot)?;
        if from_bal < amount {
            return revert("token factory: the holder has less than the forced transfer");
        }
        call.sstore_u128(from_slot, from_bal - amount)?;
        note_holder(call, &id, from_bal, from_bal - amount)?;
        let to_slot = balance_slot(&id, &to);
        let to_bal = call.sload_u128(to_slot)?;
        let Some(new_to) = to_bal.checked_add(amount) else {
            return Err(VmError::PrecompileFailed(
                "token balance overflow".to_string(),
            ));
        };
        call.sstore_u128(to_slot, new_to)?;
        note_holder(call, &id, to_bal, new_to)?;
        // Read what is left after the credit, so a forced transfer to the
        // holder itself keeps its freeze.
        let left = call.sload_u128(from_slot)?;
        let frozen = call.sload_u128(frozen_slot(&id, &from))?;
        if crate::token_ledger::frozen_after(frozen, left) != frozen {
            call.sstore_u128(frozen_slot(&id, &from), left)?;
        }
        let mut data = id.to_vec();
        data.extend_from_slice(&abi::encode_uint256(amount));
        call.emit(
            vec![forced_transfer_topic(), addr_topic(&from), addr_topic(&to)],
            data,
        )?;
        record_action(call, &id)?;
        return Ok(PrecompileResult::success(abi::encode_bool(true), 0));
    }
    revert("token factory: unknown selector")
}

/// The token record when `caller` is its issuer and the manifest gives
/// `power` to the issuer alone; otherwise why not.
fn issuer_alone(
    call: &mut PrecompileCall<'_>,
    id: &[u8; 32],
    power: tenzro_types::token_policy::Power,
    caller: &[u8; 20],
) -> Result<std::result::Result<TokenRecord, String>> {
    use tenzro_types::token_policy::Authority;
    let Some(record) = load_token(call, id)? else {
        return Ok(Err("token factory: unknown token".to_string()));
    };
    Ok(match record.powers.get(power) {
        Authority::Issuer
            if record.creator.as_slice() == crate::state_adapter::ledger_account(caller) =>
        {
            Ok(record)
        }
        Authority::Issuer => Err("token factory: only the token's issuer may do this".to_string()),
        Authority::Disabled => Err(format!("token factory: the token has no {power:?} power")),
        Authority::IssuerCouncil { k } => Err(format!(
            "token factory: this power needs {k} issuer-council approvals through the Token transaction"
        )),
    })
}

/// Log the issuer action record for an ERC-7943 write: the reason code and
/// the hash of the call as evidence.
fn record_action(call: &mut PrecompileCall<'_>, id: &[u8; 32]) -> Result<()> {
    let evidence: [u8; 32] = Keccak256::digest(call.input).into();
    let mut data = abi::encode_uint256(u128::from(ERC7943_REASON_CODE));
    data.extend_from_slice(&evidence);
    call.emit(vec![issuer_action_topic(), *id], data)
}

/// `Frozen(address indexed account, uint256 amount)`, with the token id
/// leading the data.
pub fn frozen_topic() -> [u8; 32] {
    Keccak256::digest(b"Frozen(address,uint256)").into()
}

/// `ForcedTransfer(address indexed from, address indexed to, uint256 amount)`,
/// with the token id leading the data.
pub fn forced_transfer_topic() -> [u8; 32] {
    Keccak256::digest(b"ForcedTransfer(address,address,uint256)").into()
}

/// `IssuerAction(bytes32 indexed token, uint16 reasonCode, bytes32 evidenceHash)`.
pub fn issuer_action_topic() -> [u8; 32] {
    Keccak256::digest(b"IssuerAction(bytes32,uint16,bytes32)").into()
}

/// Entry point for every facade address: the standard ERC-20 and ERC-7943
/// functions of one token, forwarded to the factory with its id filled in.
/// Logs a standard ERC-20 `Transfer` or `Approval` from the facade address.
pub fn token_facade_precompile(call: &mut PrecompileCall<'_>) -> Result<PrecompileResult> {
    let facade = call.env.address;
    call.env.address = crate::precompiles::PRECOMPILE_TOKEN_FACTORY;
    call.charge(GAS_BASE)?;
    let id = call.sload(facade_slot(&facade))?;
    if id == [0u8; 32] {
        return revert("token facade: no token at this address");
    }
    if call.input.len() < 4 {
        return revert("token facade: missing selector");
    }
    let sel = [call.input[0], call.input[1], call.input[2], call.input[3]];
    let args = call.input[4..].to_vec();
    let record = load_token(call, &id)?
        .ok_or_else(|| VmError::Internal("facade names a missing token".into()))?;
    if sel == selector("name()") {
        return Ok(PrecompileResult::success(
            abi::encode_string(&record.name),
            0,
        ));
    }
    if sel == selector("symbol()") {
        return Ok(PrecompileResult::success(
            abi::encode_string(&record.symbol),
            0,
        ));
    }
    if sel == selector("decimals()") {
        return Ok(PrecompileResult::success(
            abi::encode_uint8(record.decimals),
            0,
        ));
    }
    if sel == selector("totalSupply()") {
        return Ok(PrecompileResult::success(
            abi::encode_uint256(record.total_supply),
            0,
        ));
    }
    if sel == selector("supportsInterface(bytes4)") {
        return forward(call, sel, None, &args);
    }
    let factory_sel = match sel {
        s if s == selector("balanceOf(address)") => selectors::BALANCE_OF,
        s if s == selector("allowance(address,address)") => selectors::ALLOWANCE,
        s if s == selector("transfer(address,uint256)") => selectors::TRANSFER,
        s if s == selector("approve(address,uint256)") => selectors::APPROVE,
        s if s == selector("transferFrom(address,address,uint256)") => selectors::TRANSFER_FROM,
        s if s == selector("canTransact(address)") => selector("canTransact(bytes32,address)"),
        s if s == selector("canTransfer(address,address,uint256)") => {
            selector("canTransfer(bytes32,address,address,uint256)")
        }
        s if s == selector("getFrozenTokens(address)") => {
            selector("getFrozenTokens(bytes32,address)")
        }
        s if s == selector("setFrozenTokens(address,uint256)") => {
            selector("setFrozenTokens(bytes32,address,uint256)")
        }
        s if s == selector("forcedTransfer(address,address,uint256)") => {
            selector("forcedTransfer(bytes32,address,address,uint256)")
        }
        _ => return revert("token facade: unknown selector"),
    };
    let out = forward(call, factory_sel, Some(id), &args)?;
    if !out.success {
        return Ok(out);
    }
    let caller = call.env.caller;
    let standard = match factory_sel {
        selectors::TRANSFER => Some((
            events::transfer_topic(),
            caller,
            abi::decode_address_at(&args, 0),
            abi::decode_uint256_at(&args, 32),
        )),
        selectors::TRANSFER_FROM => Some((
            events::transfer_topic(),
            abi::decode_address_at(&args, 0).unwrap_or_default(),
            abi::decode_address_at(&args, 32),
            abi::decode_uint256_at(&args, 64),
        )),
        selectors::APPROVE => Some((
            events::approval_topic(),
            caller,
            abi::decode_address_at(&args, 0),
            abi::decode_uint256_at(&args, 32),
        )),
        _ => None,
    };
    if let Some((topic, a, Some(b), Some(amount))) = standard {
        call.state.emit_log(
            facade,
            vec![topic, addr_topic(&a), addr_topic(&b)],
            abi::encode_uint256(amount),
        )?;
    }
    Ok(out)
}

/// Run the factory on `sel`, with `id` (when given) as the first argument.
fn forward(
    call: &mut PrecompileCall<'_>,
    sel: [u8; 4],
    id: Option<[u8; 32]>,
    args: &[u8],
) -> Result<PrecompileResult> {
    let mut input = sel.to_vec();
    if let Some(id) = id {
        input.extend_from_slice(&id);
    }
    input.extend_from_slice(args);
    let mut inner = PrecompileCall {
        input: &input,
        gas_limit: call.gas_limit,
        env: call.env,
        state: &mut *call.state,
    };
    token_factory_precompile(&mut inner)
}
