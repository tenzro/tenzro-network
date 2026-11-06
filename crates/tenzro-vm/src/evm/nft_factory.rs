//! NFT factory precompile (`0x1006`).
//!
//! Permissionless ERC-721 and ERC-1155 collections. Every record (collection
//! metadata, owners, balances, token URIs, cross-VM pointers, pending random
//! mints) lives in this precompile's storage, so it is part of the state root,
//! journaled with the transaction that writes it and identical on every
//! validator. Authorization comes only from the calling frame's `msg.sender`:
//! the creator of a collection is whoever created it, only the creator mints
//! into it or registers its pointers, and only an owner transfers a token.
//!
//! # Function selectors
//!
//! | Selector   | Function                                               |
//! |------------|--------------------------------------------------------|
//! | 0xe9c3ab8b | createCollection(string,string,uint8) -> bytes32       |
//! | 0xf5c1f76e | getCollection(bytes32)                                 |
//! | 0x40c10f19 | mint(bytes32,address,uint256,string)                   |
//! | 0xb48ab8b6 | mintBatch(bytes32,address,uint256[],string[])          |
//! | 0x26a75453 | transferNft(bytes32,address,uint256)                   |
//! | 0x6352211e | ownerOf(bytes32,uint256)                               |
//! | 0x00fdd58e | balanceOf(bytes32,address)                             |
//! | 0x0e89341c | tokenUri(bytes32,uint256)                              |
//! | 0x1a6d2e4f | registerEvmPointer(bytes32,address)                    |
//! | 0x2b7ce500 | registerSvmPointer(bytes32,bytes32)                    |
//! | 0x731133e9 | mintMulti(bytes32,address,uint256,uint256)             |
//! | 0x4e1273f4 | balanceOfMulti(bytes32,address,uint256)                |
//! | 0xd3622f7b | mintRandom(bytes32,address,uint256) -> bytes32         |
//! | 0xdd68a4e3 | fulfillRandom(bytes32) -> uint256                      |
//!
//! # Random mints
//!
//! `mintRandom` records a request in block N and returns its id. From block
//! N+2 on, anyone may call `fulfillRandom(id)`: the token id and rarity come
//! from `keccak256(domain || hash(block N+1) || request id)`. The requester
//! commits before block N+1 exists, so it cannot see or choose the outcome,
//! and neither the minter nor the fulfiller supplies any input to it.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::error::{Result, VmError};
use crate::evm::precompile_host::{PrecompileCall, abi_error_string, slot_key};
use crate::evm::wtnzo::abi;
use crate::precompiles::PrecompileResult;

const GAS_CREATE_COLLECTION: u64 = 50_000;
const GAS_MINT: u64 = 20_000;
const GAS_READ: u64 = 1_000;
/// Longest name, symbol or token URI accepted.
const MAX_TEXT_LEN: usize = 512;
/// Most tokens a single `mintBatch` may mint.
const MAX_BATCH: usize = 256;
/// Collisions probed by `fulfillRandom` before it gives up.
const RANDOM_PROBES: u64 = 16;

/// Function selectors for the NFT factory precompile
pub mod selectors {
    /// createCollection(string name, string symbol, uint8 standard)
    pub const CREATE_COLLECTION: [u8; 4] = [0xe9, 0xc3, 0xab, 0x8b];
    /// getCollection(bytes32 collectionId)
    pub const GET_COLLECTION: [u8; 4] = [0xf5, 0xc1, 0xf7, 0x6e];
    /// mint(bytes32 collectionId, address to, uint256 tokenId, string tokenUri)
    pub const MINT: [u8; 4] = [0x40, 0xc1, 0x0f, 0x19];
    /// mintBatch(bytes32 collectionId, address to, uint256[] tokenIds, string[] tokenUris)
    pub const MINT_BATCH: [u8; 4] = [0xb4, 0x8a, 0xb8, 0xb6];
    /// transferNft(bytes32 collectionId, address to, uint256 tokenId)
    pub const TRANSFER_NFT: [u8; 4] = [0x26, 0xa7, 0x54, 0x53];
    /// ownerOf(bytes32 collectionId, uint256 tokenId)
    pub const OWNER_OF: [u8; 4] = [0x63, 0x52, 0x21, 0x1e];
    /// balanceOf(bytes32 collectionId, address owner)
    pub const BALANCE_OF: [u8; 4] = [0x00, 0xfd, 0xd5, 0x8e];
    /// tokenUri(bytes32 collectionId, uint256 tokenId)
    pub const TOKEN_URI: [u8; 4] = [0x0e, 0x89, 0x34, 0x1c];
    /// registerEvmPointer(bytes32 collectionId, address evmContract)
    pub const REGISTER_EVM_POINTER: [u8; 4] = [0x1a, 0x6d, 0x2e, 0x4f];
    /// registerSvmPointer(bytes32 collectionId, bytes32 svmMint)
    pub const REGISTER_SVM_POINTER: [u8; 4] = [0x2b, 0x7c, 0xe5, 0x00];
    /// mintMulti(bytes32 collectionId, address to, uint256 tokenId, uint256 amount)
    pub const MINT_MULTI: [u8; 4] = [0x73, 0x11, 0x33, 0xe9];
    /// balanceOfMulti(bytes32 collectionId, address owner, uint256 tokenId)
    pub const BALANCE_OF_MULTI: [u8; 4] = [0x4e, 0x12, 0x73, 0xf4];
    /// mintRandom(bytes32 collectionId, address to, uint256 idSpace)
    pub const MINT_RANDOM: [u8; 4] = [0xd3, 0x62, 0x2f, 0x7b];
    /// fulfillRandom(bytes32 requestId)
    pub const FULFILL_RANDOM: [u8; 4] = [0xdd, 0x68, 0xa4, 0xe3];
}

/// Supported NFT standards
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NftStandard {
    /// ERC-721: unique, non-fungible tokens
    Erc721 = 0,
    /// ERC-1155: multi-token standard (fungible + non-fungible)
    Erc1155 = 1,
}

impl NftStandard {
    /// Parse from a u8 value
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Erc721),
            1 => Some(Self::Erc1155),
            _ => None,
        }
    }
}

/// Metadata for a single NFT collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftCollection {
    /// Human-readable name
    pub name: String,
    /// Short ticker symbol
    pub symbol: String,
    /// Creator address (the `msg.sender` that created it)
    pub creator: [u8; 20],
    /// Total minted supply
    pub total_supply: u128,
    /// NFT standard
    pub standard: NftStandard,
    /// Block height at creation
    pub created_at_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RandomRequest {
    collection: [u8; 32],
    to: [u8; 20],
    id_space: u128,
    block: u64,
}

fn collection_slot(id: &[u8; 32]) -> [u8; 32] {
    slot_key(b"nft/collection", &[id])
}
fn owner_slot(id: &[u8; 32], token: u128) -> [u8; 32] {
    slot_key(b"nft/owner", &[id, &token.to_be_bytes()])
}
fn uri_slot(id: &[u8; 32], token: u128) -> [u8; 32] {
    slot_key(b"nft/uri", &[id, &token.to_be_bytes()])
}
fn bal721_slot(id: &[u8; 32], owner: &[u8; 20]) -> [u8; 32] {
    slot_key(b"nft/bal721", &[id, owner])
}
fn bal1155_slot(id: &[u8; 32], owner: &[u8; 20], token: u128) -> [u8; 32] {
    slot_key(b"nft/bal1155", &[id, owner, &token.to_be_bytes()])
}
fn evm_ptr_slot(id: &[u8; 32]) -> [u8; 32] {
    slot_key(b"nft/evm_ptr", &[id])
}
fn svm_ptr_slot(id: &[u8; 32]) -> [u8; 32] {
    slot_key(b"nft/svm_ptr", &[id])
}
fn nonce_slot(creator: &[u8; 20]) -> [u8; 32] {
    slot_key(b"nft/nonce", &[creator])
}
fn request_slot(request_id: &[u8; 32]) -> [u8; 32] {
    slot_key(b"nft/random_request", &[request_id])
}
fn request_counter_slot(collection: &[u8; 32]) -> [u8; 32] {
    slot_key(b"nft/random_counter", &[collection])
}

/// `NftTransfer(bytes32 indexed collection, address indexed from, address indexed to, uint256 tokenId)`
fn nft_transfer_topic() -> [u8; 32] {
    let mut t = [0u8; 32];
    t.copy_from_slice(&Keccak256::digest(
        b"NftTransfer(bytes32,address,address,uint256)",
    ));
    t
}

fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn revert(msg: &str) -> Result<PrecompileResult> {
    Ok(PrecompileResult::revert(abi_error_string(msg), 0))
}

/// Deterministic collection id: `SHA-256(creator || nonce_le)`.
pub fn compute_collection_id(creator: &[u8; 20], nonce: u64) -> [u8; 32] {
    use sha2::Sha256;
    let mut h = Sha256::new();
    h.update(creator);
    h.update(nonce.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn load_collection(call: &mut PrecompileCall<'_>, id: &[u8; 32]) -> Result<Option<NftCollection>> {
    match call.read_blob(collection_slot(id))? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| VmError::Internal(format!("corrupt NFT collection record: {e}"))),
        None => Ok(None),
    }
}

fn store_collection(call: &mut PrecompileCall<'_>, id: &[u8; 32], c: &NftCollection) -> Result<()> {
    let bytes = serde_json::to_vec(c)
        .map_err(|e| VmError::Internal(format!("NFT collection encode: {e}")))?;
    call.write_blob(collection_slot(id), &bytes)
}

fn owner_of(call: &mut PrecompileCall<'_>, id: &[u8; 32], token: u128) -> Result<Option<[u8; 20]>> {
    let w = call.sload(owner_slot(id, token))?;
    if w.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&w[12..]);
    Ok(Some(a))
}

/// Load the collection and require the caller to be its creator.
fn creator_collection(
    call: &mut PrecompileCall<'_>,
    id: &[u8; 32],
) -> Result<std::result::Result<NftCollection, &'static str>> {
    let Some(c) = load_collection(call, id)? else {
        return Ok(Err("NFT factory: unknown collection"));
    };
    if c.creator != call.env.caller {
        return Ok(Err("NFT factory: only the collection creator may do this"));
    }
    Ok(Ok(c))
}

/// Mint one ERC-721 token. `Ok(false)` if the id is already taken.
fn mint_721(
    call: &mut PrecompileCall<'_>,
    id: &[u8; 32],
    collection: &mut NftCollection,
    to: [u8; 20],
    token: u128,
    uri: &str,
) -> Result<bool> {
    if owner_of(call, id, token)?.is_some() {
        return Ok(false);
    }
    call.charge(GAS_MINT)?;
    call.sstore(owner_slot(id, token), addr_word(&to))?;
    if !uri.is_empty() {
        call.write_blob(uri_slot(id, token), uri.as_bytes())?;
    }
    let bal = call.sload_u128(bal721_slot(id, &to))?;
    call.sstore_u128(bal721_slot(id, &to), bal + 1)?;
    collection.total_supply += 1;
    call.emit(
        vec![
            nft_transfer_topic(),
            *id,
            addr_word(&[0u8; 20]),
            addr_word(&to),
        ],
        abi::encode_uint256(token),
    )?;
    Ok(true)
}

/// Entry point registered at [`crate::precompiles::PRECOMPILE_NFT_FACTORY`].
pub fn nft_factory_precompile(call: &mut PrecompileCall<'_>) -> Result<PrecompileResult> {
    call.charge(GAS_READ)?;
    if call.env.value != 0 {
        return revert("NFT factory: send no value");
    }
    if call.input.len() < 4 {
        return revert("NFT factory: missing selector");
    }
    let mut sel = [0u8; 4];
    sel.copy_from_slice(&call.input[..4]);
    let args = call.input[4..].to_vec();
    let caller = call.env.caller;

    match sel {
        selectors::CREATE_COLLECTION => {
            call.require_write()?;
            call.charge(GAS_CREATE_COLLECTION)?;
            let (Some(name), Some(symbol), Some(standard)) = (
                abi::decode_dynamic_string(&args, 0, 0),
                abi::decode_dynamic_string(&args, 0, 32),
                abi::decode_uint256_at(&args, 64),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            let Some(standard) = u8::try_from(standard).ok().and_then(NftStandard::from_u8) else {
                return revert("NFT factory: unknown standard");
            };
            if name.is_empty() || name.len() > MAX_TEXT_LEN || symbol.len() > MAX_TEXT_LEN {
                return revert("NFT factory: invalid name or symbol");
            }
            let nonce = call.sload_u128(nonce_slot(&caller))?;
            call.sstore_u128(nonce_slot(&caller), nonce + 1)?;
            let id = compute_collection_id(&caller, nonce as u64);
            let collection = NftCollection {
                name,
                symbol,
                creator: caller,
                total_supply: 0,
                standard,
                created_at_block: call.env.block_number,
            };
            store_collection(call, &id, &collection)?;
            Ok(PrecompileResult::success(id.to_vec(), 0))
        }
        selectors::GET_COLLECTION => {
            let Some(id) = abi::decode_bytes32_at(&args, 0) else {
                return revert("NFT factory: bad collection id");
            };
            let Some(c) = load_collection(call, &id)? else {
                return revert("NFT factory: unknown collection");
            };
            // (string name, string symbol, address creator, uint256 totalSupply, uint8 standard)
            let name = c.name.as_bytes();
            let symbol = c.symbol.as_bytes();
            let name_block = 32 + name.len().div_ceil(32) * 32;
            let mut out = Vec::new();
            out.extend_from_slice(&abi::encode_uint256(160));
            out.extend_from_slice(&abi::encode_uint256((160 + name_block) as u128));
            out.extend_from_slice(&abi::encode_address(&c.creator));
            out.extend_from_slice(&abi::encode_uint256(c.total_supply));
            out.extend_from_slice(&abi::encode_uint8(c.standard as u8));
            for s in [name, symbol] {
                out.extend_from_slice(&abi::encode_uint256(s.len() as u128));
                let start = out.len();
                out.extend_from_slice(s);
                out.resize(start + s.len().div_ceil(32) * 32, 0);
            }
            Ok(PrecompileResult::success(out, 0))
        }
        selectors::MINT => {
            call.require_write()?;
            let (Some(id), Some(to), Some(token)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_uint256_at(&args, 64),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            let uri = abi::decode_dynamic_string(&args, 0, 96).unwrap_or_default();
            if uri.len() > MAX_TEXT_LEN || to == [0u8; 20] {
                return revert("NFT factory: invalid recipient or URI");
            }
            let mut c = match creator_collection(call, &id)? {
                Ok(c) => c,
                Err(m) => return revert(m),
            };
            if c.standard != NftStandard::Erc721 {
                return revert("NFT factory: collection is not ERC-721");
            }
            if !mint_721(call, &id, &mut c, to, token, &uri)? {
                return revert("NFT factory: token already minted");
            }
            store_collection(call, &id, &c)?;
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::MINT_BATCH => {
            call.require_write()?;
            let (Some(id), Some(to), Some(tokens)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_uint256_array(&args, 0, 64),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            let uris = abi::decode_string_array(&args, 0, 96).unwrap_or_default();
            if tokens.is_empty() || tokens.len() > MAX_BATCH || to == [0u8; 20] {
                return revert("NFT factory: batch must hold 1 to 256 tokens");
            }
            let mut c = match creator_collection(call, &id)? {
                Ok(c) => c,
                Err(m) => return revert(m),
            };
            if c.standard != NftStandard::Erc721 {
                return revert("NFT factory: collection is not ERC-721");
            }
            for (i, token) in tokens.iter().enumerate() {
                let uri = uris.get(i).map(String::as_str).unwrap_or("");
                if uri.len() > MAX_TEXT_LEN {
                    return revert("NFT factory: URI too long");
                }
                if !mint_721(call, &id, &mut c, to, *token, uri)? {
                    return revert("NFT factory: token already minted");
                }
            }
            store_collection(call, &id, &c)?;
            Ok(PrecompileResult::success(
                abi::encode_uint256(tokens.len() as u128),
                0,
            ))
        }
        selectors::TRANSFER_NFT => {
            call.require_write()?;
            let (Some(id), Some(to), Some(token)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_uint256_at(&args, 64),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            if to == [0u8; 20] {
                return revert("NFT factory: invalid recipient");
            }
            match owner_of(call, &id, token)? {
                Some(owner) if owner == caller => {}
                Some(_) => return revert("NFT factory: caller does not own the token"),
                None => return revert("NFT factory: token does not exist"),
            }
            if to != caller {
                call.sstore(owner_slot(&id, token), addr_word(&to))?;
                let from_bal = call.sload_u128(bal721_slot(&id, &caller))?;
                call.sstore_u128(bal721_slot(&id, &caller), from_bal.saturating_sub(1))?;
                let to_bal = call.sload_u128(bal721_slot(&id, &to))?;
                call.sstore_u128(bal721_slot(&id, &to), to_bal + 1)?;
            }
            call.emit(
                vec![nft_transfer_topic(), id, addr_word(&caller), addr_word(&to)],
                abi::encode_uint256(token),
            )?;
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::OWNER_OF => {
            let (Some(id), Some(token)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_uint256_at(&args, 32),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            match owner_of(call, &id, token)? {
                Some(o) => Ok(PrecompileResult::success(abi::encode_address(&o), 0)),
                None => revert("NFT factory: token does not exist"),
            }
        }
        selectors::BALANCE_OF => {
            let (Some(id), Some(owner)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            let b = call.sload_u128(bal721_slot(&id, &owner))?;
            Ok(PrecompileResult::success(abi::encode_uint256(b), 0))
        }
        selectors::TOKEN_URI => {
            let (Some(id), Some(token)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_uint256_at(&args, 32),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            let uri = call.read_blob(uri_slot(&id, token))?.unwrap_or_default();
            Ok(PrecompileResult::success(
                abi::encode_string(&String::from_utf8_lossy(&uri)),
                0,
            ))
        }
        selectors::REGISTER_EVM_POINTER => {
            call.require_write()?;
            let (Some(id), Some(ptr)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            if let Err(m) = creator_collection(call, &id)? {
                return revert(m);
            }
            call.sstore(evm_ptr_slot(&id), addr_word(&ptr))?;
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::REGISTER_SVM_POINTER => {
            call.require_write()?;
            let (Some(id), Some(mint)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_bytes32_at(&args, 32),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            if let Err(m) = creator_collection(call, &id)? {
                return revert(m);
            }
            call.sstore(svm_ptr_slot(&id), mint)?;
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::MINT_MULTI => {
            call.require_write()?;
            let (Some(id), Some(to), Some(token), Some(amount)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_uint256_at(&args, 64),
                abi::decode_uint256_at(&args, 96),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            if amount == 0 || to == [0u8; 20] {
                return revert("NFT factory: invalid amount or recipient");
            }
            let mut c = match creator_collection(call, &id)? {
                Ok(c) => c,
                Err(m) => return revert(m),
            };
            if c.standard != NftStandard::Erc1155 {
                return revert("NFT factory: collection is not ERC-1155");
            }
            call.charge(GAS_MINT)?;
            let slot = bal1155_slot(&id, &to, token);
            let bal = call.sload_u128(slot)?;
            let Some(new_bal) = bal.checked_add(amount) else {
                return revert("NFT factory: balance overflow");
            };
            let Some(new_supply) = c.total_supply.checked_add(amount) else {
                return revert("NFT factory: supply overflow");
            };
            call.sstore_u128(slot, new_bal)?;
            c.total_supply = new_supply;
            store_collection(call, &id, &c)?;
            Ok(PrecompileResult::success(abi::encode_bool(true), 0))
        }
        selectors::BALANCE_OF_MULTI => {
            let (Some(id), Some(owner), Some(token)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_uint256_at(&args, 64),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            let b = call.sload_u128(bal1155_slot(&id, &owner, token))?;
            Ok(PrecompileResult::success(abi::encode_uint256(b), 0))
        }
        selectors::MINT_RANDOM => {
            call.require_write()?;
            let (Some(id), Some(to), Some(id_space)) = (
                abi::decode_bytes32_at(&args, 0),
                abi::decode_address_at(&args, 32),
                abi::decode_uint256_at(&args, 64),
            ) else {
                return revert("NFT factory: bad arguments");
            };
            if id_space == 0 || to == [0u8; 20] {
                return revert("NFT factory: invalid id space or recipient");
            }
            let c = match creator_collection(call, &id)? {
                Ok(c) => c,
                Err(m) => return revert(m),
            };
            if c.standard != NftStandard::Erc721 {
                return revert("NFT factory: collection is not ERC-721");
            }
            let counter = call.sload_u128(request_counter_slot(&id))?;
            call.sstore_u128(request_counter_slot(&id), counter + 1)?;
            let block = call.env.block_number;
            let mut h = Keccak256::new();
            h.update(b"tenzro/nft/random-request");
            h.update(id);
            h.update(counter.to_be_bytes());
            let mut request_id = [0u8; 32];
            request_id.copy_from_slice(&h.finalize());
            let request = RandomRequest {
                collection: id,
                to,
                id_space,
                block,
            };
            let bytes = serde_json::to_vec(&request)
                .map_err(|e| VmError::Internal(format!("random request encode: {e}")))?;
            call.write_blob(request_slot(&request_id), &bytes)?;
            Ok(PrecompileResult::success(request_id.to_vec(), 0))
        }
        selectors::FULFILL_RANDOM => {
            call.require_write()?;
            let Some(request_id) = abi::decode_bytes32_at(&args, 0) else {
                return revert("NFT factory: bad request id");
            };
            let Some(bytes) = call.read_blob(request_slot(&request_id))? else {
                return revert("NFT factory: unknown or fulfilled request");
            };
            let request: RandomRequest = serde_json::from_slice(&bytes)
                .map_err(|e| VmError::Internal(format!("corrupt random request: {e}")))?;
            let Some(seed_block) = request.block.checked_add(1) else {
                return revert("NFT factory: request block overflow");
            };
            if call.env.block_number <= seed_block {
                return revert("NFT factory: randomness not yet available");
            }
            let seed = call.state.block_hash(seed_block)?;
            if seed == [0u8; 32] {
                return revert("NFT factory: seed block hash unavailable");
            }
            let mut h = Keccak256::new();
            h.update(b"tenzro/nft/random");
            h.update(seed);
            h.update(request_id);
            let out = h.finalize();
            let mut first = [0u8; 16];
            first.copy_from_slice(&out[..16]);
            let base = u128::from_be_bytes(first) % request.id_space;
            let rarity = out[31];

            let mut c = match load_collection(call, &request.collection)? {
                Some(c) => c,
                None => return revert("NFT factory: unknown collection"),
            };
            let uri = format!("rarity:{rarity}");
            let mut minted = None;
            for probe in 0..RANDOM_PROBES as u128 {
                let token = (base + probe) % request.id_space;
                if mint_721(call, &request.collection, &mut c, request.to, token, &uri)? {
                    minted = Some(token);
                    break;
                }
            }
            let Some(token) = minted else {
                return revert("NFT factory: id space exhausted near the drawn id");
            };
            store_collection(call, &request.collection, &c)?;
            call.write_blob(request_slot(&request_id), &[])?;
            call.sstore(request_slot(&request_id), [0u8; 32])?;
            Ok(PrecompileResult::success(abi::encode_uint256(token), 0))
        }
        _ => revert("NFT factory: unknown selector"),
    }
}
