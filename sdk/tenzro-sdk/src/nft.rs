//! NFTs: the network's NFT factory precompile at `0x…1006`, which keeps
//! ERC-721 and ERC-1155 collections in consensus state.
//!
//! Writes are EVM calls inside a `ContractCall` transaction signed by the
//! account that acts: the collection's creator creates, mints and registers
//! pointers, a token's owner transfers it, and anyone fulfils a random mint
//! two blocks after its request. [`nft_contract_call`] builds that
//! transaction's fields. Reads are `eth_call`s of the read calldata here.
//! Everything in this module is offline.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// The factory precompile's address.
pub const NFT_FACTORY_ADDRESS: [u8; 20] = {
    let mut a = [0u8; 20];
    a[18] = 0x10;
    a[19] = 0x06;
    a
};

/// The factory's function selectors (fixed values, not all the hash of their signature).
pub mod selectors {
    pub const CREATE_COLLECTION: [u8; 4] = [0xe9, 0xc3, 0xab, 0x8b];
    pub const GET_COLLECTION: [u8; 4] = [0xf5, 0xc1, 0xf7, 0x6e];
    pub const MINT: [u8; 4] = [0x40, 0xc1, 0x0f, 0x19];
    pub const MINT_BATCH: [u8; 4] = [0xb4, 0x8a, 0xb8, 0xb6];
    pub const TRANSFER_NFT: [u8; 4] = [0x26, 0xa7, 0x54, 0x53];
    pub const OWNER_OF: [u8; 4] = [0x63, 0x52, 0x21, 0x1e];
    pub const BALANCE_OF: [u8; 4] = [0x00, 0xfd, 0xd5, 0x8e];
    pub const TOKEN_URI: [u8; 4] = [0x0e, 0x89, 0x34, 0x1c];
    pub const REGISTER_EVM_POINTER: [u8; 4] = [0x1a, 0x6d, 0x2e, 0x4f];
    pub const REGISTER_SVM_POINTER: [u8; 4] = [0x2b, 0x7c, 0xe5, 0x00];
    pub const MINT_MULTI: [u8; 4] = [0x73, 0x11, 0x33, 0xe9];
    pub const BALANCE_OF_MULTI: [u8; 4] = [0x4e, 0x12, 0x73, 0xf4];
    pub const MINT_RANDOM: [u8; 4] = [0xd3, 0x62, 0x2f, 0x7b];
    pub const FULFILL_RANDOM: [u8; 4] = [0xdd, 0x68, 0xa4, 0xe3];
}

/// Longest name, symbol or token URI the factory accepts, in bytes.
pub const NFT_MAX_TEXT: usize = 512;
/// Most tokens one `mintBatch` mints.
pub const NFT_MAX_BATCH: usize = 256;

/// The two collection standards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftStandard {
    Erc721 = 0,
    Erc1155 = 1,
}

/// A request the factory would refuse, caught before signing, or return data that does not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct NftError(pub String);

fn err<T>(m: impl Into<String>) -> Result<T, NftError> {
    Err(NftError(m.into()))
}

/// topic 0 of `NftTransfer(bytes32 indexed collection, address indexed from, address indexed to, uint256 tokenId)`.
pub fn nft_transfer_topic() -> [u8; 32] {
    Keccak256::digest(b"NftTransfer(bytes32,address,address,uint256)").into()
}

/// The id `createCollection` gives the `nonce`-th collection of `creator`: SHA-256(creator ‖ nonce as 8 bytes little-endian).
pub fn nft_collection_id(creator: &[u8; 20], nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(creator);
    h.update(nonce.to_le_bytes());
    h.finalize().into()
}

fn word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}
fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}
fn dyn_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = word(b.len() as u128).to_vec();
    out.extend_from_slice(b);
    out.resize(32 + b.len().div_ceil(32) * 32, 0);
    out
}
fn text(s: &str, what: &str) -> Result<(), NftError> {
    if s.len() > NFT_MAX_TEXT {
        return err(format!("{what} is longer than {NFT_MAX_TEXT} bytes"));
    }
    Ok(())
}
fn recipient(a: &[u8; 20]) -> Result<(), NftError> {
    if a == &[0u8; 20] {
        return err("the recipient may not be the zero address");
    }
    Ok(())
}

/// Head words then tails, as the ABI lays out a call's arguments.
enum Arg<'a> {
    Word([u8; 32]),
    Dynamic(&'a [u8]),
    Owned(Vec<u8>),
}

fn call(sel: [u8; 4], args: &[Arg<'_>]) -> Vec<u8> {
    let mut head = sel.to_vec();
    let mut tail = Vec::new();
    let head_len = 32 * args.len();
    for a in args {
        match a {
            Arg::Word(w) => head.extend_from_slice(w),
            Arg::Dynamic(b) => {
                head.extend_from_slice(&word((head_len + tail.len()) as u128));
                tail.extend(dyn_bytes(b));
            }
            Arg::Owned(enc) => {
                head.extend_from_slice(&word((head_len + tail.len()) as u128));
                tail.extend_from_slice(enc);
            }
        }
    }
    head.extend(tail);
    head
}

fn uint_array(v: &[u128]) -> Vec<u8> {
    let mut out = word(v.len() as u128).to_vec();
    for x in v {
        out.extend_from_slice(&word(*x));
    }
    out
}

fn string_array(v: &[&str]) -> Vec<u8> {
    let mut out = word(v.len() as u128).to_vec();
    let mut tails = Vec::new();
    for s in v {
        out.extend_from_slice(&word((32 * v.len() + tails.len()) as u128));
        tails.extend(dyn_bytes(s.as_bytes()));
    }
    out.extend(tails);
    out
}

/// `createCollection(string,string,uint8)`.
pub fn create_collection(
    name: &str,
    symbol: &str,
    standard: NftStandard,
) -> Result<Vec<u8>, NftError> {
    if name.is_empty() {
        return err("a collection needs a name");
    }
    text(name, "name")?;
    text(symbol, "symbol")?;
    Ok(call(
        selectors::CREATE_COLLECTION,
        &[
            Arg::Dynamic(name.as_bytes()),
            Arg::Dynamic(symbol.as_bytes()),
            Arg::Word(word(standard as u128)),
        ],
    ))
}

/// `getCollection(bytes32)`.
pub fn get_collection(collection: &[u8; 32]) -> Vec<u8> {
    call(selectors::GET_COLLECTION, &[Arg::Word(*collection)])
}

/// `mint(bytes32,address,uint256,string)`.
pub fn mint(
    collection: &[u8; 32],
    to: &[u8; 20],
    token: u128,
    uri: &str,
) -> Result<Vec<u8>, NftError> {
    recipient(to)?;
    text(uri, "token URI")?;
    Ok(call(
        selectors::MINT,
        &[
            Arg::Word(*collection),
            Arg::Word(addr_word(to)),
            Arg::Word(word(token)),
            Arg::Dynamic(uri.as_bytes()),
        ],
    ))
}

/// `mintBatch(bytes32,address,uint256[],string[])`.
pub fn mint_batch(
    collection: &[u8; 32],
    to: &[u8; 20],
    tokens: &[u128],
    uris: &[&str],
) -> Result<Vec<u8>, NftError> {
    recipient(to)?;
    if tokens.is_empty() || tokens.len() > NFT_MAX_BATCH {
        return err(format!("a batch holds 1 to {NFT_MAX_BATCH} tokens"));
    }
    if uris.len() > tokens.len() {
        return err("more URIs than tokens");
    }
    for u in uris {
        text(u, "token URI")?;
    }
    Ok(call(
        selectors::MINT_BATCH,
        &[
            Arg::Word(*collection),
            Arg::Word(addr_word(to)),
            Arg::Owned(uint_array(tokens)),
            Arg::Owned(string_array(uris)),
        ],
    ))
}

/// `transferNft(bytes32,address,uint256)`.
pub fn transfer(collection: &[u8; 32], to: &[u8; 20], token: u128) -> Result<Vec<u8>, NftError> {
    recipient(to)?;
    Ok(call(
        selectors::TRANSFER_NFT,
        &[
            Arg::Word(*collection),
            Arg::Word(addr_word(to)),
            Arg::Word(word(token)),
        ],
    ))
}

/// `ownerOf(bytes32,uint256)`.
pub fn owner_of(collection: &[u8; 32], token: u128) -> Vec<u8> {
    call(
        selectors::OWNER_OF,
        &[Arg::Word(*collection), Arg::Word(word(token))],
    )
}

/// `balanceOf(bytes32,address)`.
pub fn balance_of(collection: &[u8; 32], owner: &[u8; 20]) -> Vec<u8> {
    call(
        selectors::BALANCE_OF,
        &[Arg::Word(*collection), Arg::Word(addr_word(owner))],
    )
}

/// `tokenUri(bytes32,uint256)`.
pub fn token_uri(collection: &[u8; 32], token: u128) -> Vec<u8> {
    call(
        selectors::TOKEN_URI,
        &[Arg::Word(*collection), Arg::Word(word(token))],
    )
}

/// `registerEvmPointer(bytes32,address)`.
pub fn register_evm_pointer(collection: &[u8; 32], evm_contract: &[u8; 20]) -> Vec<u8> {
    call(
        selectors::REGISTER_EVM_POINTER,
        &[Arg::Word(*collection), Arg::Word(addr_word(evm_contract))],
    )
}

/// `registerSvmPointer(bytes32,bytes32)`.
pub fn register_svm_pointer(collection: &[u8; 32], svm_mint: &[u8; 32]) -> Vec<u8> {
    call(
        selectors::REGISTER_SVM_POINTER,
        &[Arg::Word(*collection), Arg::Word(*svm_mint)],
    )
}

/// `mintMulti(bytes32,address,uint256,uint256)`.
pub fn mint_multi(
    collection: &[u8; 32],
    to: &[u8; 20],
    token: u128,
    amount: u128,
) -> Result<Vec<u8>, NftError> {
    recipient(to)?;
    if amount == 0 {
        return err("amount must be positive");
    }
    Ok(call(
        selectors::MINT_MULTI,
        &[
            Arg::Word(*collection),
            Arg::Word(addr_word(to)),
            Arg::Word(word(token)),
            Arg::Word(word(amount)),
        ],
    ))
}

/// `balanceOfMulti(bytes32,address,uint256)`.
pub fn balance_of_multi(collection: &[u8; 32], owner: &[u8; 20], token: u128) -> Vec<u8> {
    call(
        selectors::BALANCE_OF_MULTI,
        &[
            Arg::Word(*collection),
            Arg::Word(addr_word(owner)),
            Arg::Word(word(token)),
        ],
    )
}

/// `mintRandom(bytes32,address,uint256)`.
pub fn mint_random(
    collection: &[u8; 32],
    to: &[u8; 20],
    id_space: u128,
) -> Result<Vec<u8>, NftError> {
    recipient(to)?;
    if id_space == 0 {
        return err("id space must be positive");
    }
    Ok(call(
        selectors::MINT_RANDOM,
        &[
            Arg::Word(*collection),
            Arg::Word(addr_word(to)),
            Arg::Word(word(id_space)),
        ],
    ))
}

/// `fulfillRandom(bytes32)`.
pub fn fulfill_random(request: &[u8; 32]) -> Vec<u8> {
    call(selectors::FULFILL_RANDOM, &[Arg::Word(*request)])
}

/// A collection as `getCollection` returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftCollection {
    pub name: String,
    pub symbol: String,
    pub creator: [u8; 20],
    pub total_supply: u128,
    pub standard: NftStandard,
}

fn at(data: &[u8], offset: usize) -> Result<&[u8; 32], NftError> {
    data.get(offset..offset + 32)
        .map(|w| w.try_into().expect("32 bytes"))
        .ok_or_else(|| NftError("return data too short".into()))
}

/// A `uint256` return (`balanceOf`, `balanceOfMulti`, `mintBatch`, `fulfillRandom`); the factory's values fit 128 bits.
pub fn decode_uint(data: &[u8]) -> Result<u128, NftError> {
    let w = at(data, 0)?;
    if w[..16].iter().any(|b| *b != 0) {
        return err("value does not fit 128 bits");
    }
    Ok(u128::from_be_bytes(w[16..].try_into().unwrap()))
}

/// An `address` return (`ownerOf`).
pub fn decode_address(data: &[u8]) -> Result<[u8; 20], NftError> {
    let w = at(data, 0)?;
    if w[..12].iter().any(|b| *b != 0) {
        return err("address has non-zero high bytes");
    }
    Ok(w[12..].try_into().unwrap())
}

/// A `bool` return (`mint`, `transferNft`, `mintMulti`, the pointer registrations).
pub fn decode_bool(data: &[u8]) -> Result<bool, NftError> {
    match decode_uint(data)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => err("bool is neither 0 nor 1"),
    }
}

fn string_at(data: &[u8], head: usize) -> Result<String, NftError> {
    let off = usize::try_from(decode_uint(at(data, head)?)?)
        .map_err(|_| NftError("offset too large".into()))?;
    let len = usize::try_from(decode_uint(at(data, off)?)?)
        .map_err(|_| NftError("length too large".into()))?;
    let bytes = data
        .get(off + 32..off + 32 + len)
        .ok_or_else(|| NftError("string runs past the data".into()))?;
    String::from_utf8(bytes.to_vec()).map_err(|_| NftError("string is not UTF-8".into()))
}

/// A `string` return (`tokenUri`).
pub fn decode_string(data: &[u8]) -> Result<String, NftError> {
    string_at(data, 0)
}

/// The `getCollection` return.
pub fn decode_collection(data: &[u8]) -> Result<NftCollection, NftError> {
    let standard = match decode_uint(at(data, 128)?)? {
        0 => NftStandard::Erc721,
        1 => NftStandard::Erc1155,
        s => return err(format!("unknown NFT standard {s}")),
    };
    Ok(NftCollection {
        name: string_at(data, 0)?,
        symbol: string_at(data, 32)?,
        creator: decode_address(at(data, 64)?)?,
        total_supply: decode_uint(at(data, 96)?)?,
        standard,
    })
}

/// A minted or moved token, from an `NftTransfer` log (`from` is zero for a mint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftTransfer {
    pub collection: [u8; 32],
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub token_id: u128,
}

/// Decode an `NftTransfer` log; `None` for any other log.
pub fn decode_nft_transfer(topics: &[[u8; 32]], data: &[u8]) -> Option<NftTransfer> {
    if topics.len() != 4 || topics[0] != nft_transfer_topic() {
        return None;
    }
    Some(NftTransfer {
        collection: topics[1],
        from: decode_address(&topics[2]).ok()?,
        to: decode_address(&topics[3]).ok()?,
        token_id: decode_uint(data).ok()?,
    })
}

/// The fields of a `ContractCall` transaction running these factory calls in
/// order, all or nothing, for `TypedTxClient`. The signer's account is `msg.sender`.
pub fn nft_contract_call(calldata: &[Vec<u8>]) -> Value {
    let calls: Vec<Value> = calldata
        .iter()
        .map(|d| json!({ "vm": "evm", "to": NFT_FACTORY_ADDRESS.to_vec(), "value": 0, "data": d }))
        .collect();
    json!({ "calls": calls })
}
