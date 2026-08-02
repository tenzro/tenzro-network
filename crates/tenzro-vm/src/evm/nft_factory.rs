//! NFT Factory Precompile (0x1006)
//!
//! Provides permissionless NFT collection creation, minting, transfers, and queries.
//! Supports both ERC-721 (unique tokens) and ERC-1155 (multi-token) standards.
//! Cross-VM NFT pointers follow the Sei V2 model for unified ownership across
//! EVM, SVM, and Canton VMs.
//!
//! # Function Selectors
//!
//! | Selector   | Function                                                        | Gas     |
//! |------------|-----------------------------------------------------------------|---------|
//! | 0xa3d4926e | createCollection(string,string,address,uint8)                   | 150,000 |
//! | 0xf5c1f76e | getCollection(bytes32)                                          | 2,600   |
//! | 0x40c10f19 | mint(bytes32,address,uint256,string)                            | 80,000  |
//! | 0xb48ab8b6 | mintBatch(bytes32,address,uint256[],string[])                   | 200,000 |
//! | 0xc3b6e1ff | transferNft(bytes32,address,address,uint256)                    | 60,000  |
//! | 0x6352211e | ownerOf(bytes32,uint256)                                        | 2,600   |
//! | 0x00fdd58e | balanceOf(bytes32,address)                                      | 2,600   |
//! | 0x0e89341c | tokenUri(bytes32,uint256)                                       | 2,600   |
//! | 0x1a6d2e4f | registerEvmPointer(bytes32,address)                             | 50,000  |
//! | 0x2b7ce500 | registerSvmPointer(bytes32,bytes32)                             | 50,000  |
//! | 0x731133e9 | mintMulti(bytes32,address,uint256,uint256)                      | 80,000  |
//! | 0x4e1273f4 | balanceOfMulti(bytes32,address,uint256)                         | 2,600   |

use crate::VmError;
use crate::error::Result;
use crate::evm::wtnzo::abi;
use crate::precompiles::PrecompileResult;
use dashmap::DashMap;
use sha2::{Digest as Sha2Digest, Sha256};
use std::sync::Arc;
use tenzro_storage::{CF_NFTS, KvStore};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Gas constants
// ---------------------------------------------------------------------------

/// Gas cost for creating a new collection
const GAS_CREATE_COLLECTION: u64 = 150_000;
/// Gas cost for minting a single NFT
const GAS_MINT: u64 = 80_000;
/// Gas cost for minting a VRF-randomized NFT (mint + VRF verification overhead)
const GAS_MINT_RANDOM: u64 = 130_000;
/// Gas cost for batch minting
const GAS_MINT_BATCH: u64 = 200_000;
/// Gas cost for transferring an NFT
const GAS_TRANSFER: u64 = 60_000;
/// Gas cost for registering a cross-VM pointer
const GAS_REGISTER_POINTER: u64 = 50_000;
/// Gas cost for read-only queries
const GAS_READ: u64 = 2_600;

// ---------------------------------------------------------------------------
// Function selectors
// ---------------------------------------------------------------------------

/// Function selectors for the NFT factory precompile
pub mod selectors {
    /// createCollection(string name, string symbol, address creator, uint8 standard)
    pub const CREATE_COLLECTION: [u8; 4] = [0xa3, 0xd4, 0x92, 0x6e];
    /// getCollection(bytes32 collectionId)
    pub const GET_COLLECTION: [u8; 4] = [0xf5, 0xc1, 0xf7, 0x6e];
    /// mint(bytes32 collectionId, address to, uint256 tokenId, string tokenUri)
    pub const MINT: [u8; 4] = [0x40, 0xc1, 0x0f, 0x19];
    /// mintBatch(bytes32 collectionId, address to, uint256[] tokenIds, string[] tokenUris)
    pub const MINT_BATCH: [u8; 4] = [0xb4, 0x8a, 0xb8, 0xb6];
    /// transferNft(bytes32 collectionId, address from, address to, uint256 tokenId)
    pub const TRANSFER_NFT: [u8; 4] = [0xc3, 0xb6, 0xe1, 0xff];
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
    /// mintRandom(bytes32 collectionId, address to, uint256 idSpace, bytes32 vrfPubkey, bytes vrfProof, bytes alpha)
    ///
    /// Mints an ERC-721 NFT whose token_id and rarity tier are derived from a
    /// verified VRF output. The precompile calls into the VRF precompile (0x1007)
    /// at the `tenzro-crypto` level to verify the proof, then:
    ///   - token_id = vrf_u64(output) mod idSpace (retries on collision up to 4 times)
    ///   - rarity   = uint8(output[32]) (0..=255) stored via token_uri
    pub const MINT_RANDOM: [u8; 4] = [0x52, 0x51, 0x7e, 0x21];
}

// ---------------------------------------------------------------------------
// NFT standard enum
// ---------------------------------------------------------------------------

/// Supported NFT standards
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Convert to u8
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Metadata for a single NFT collection
#[derive(Debug, Clone)]
pub struct NftCollection {
    /// Unique 32-byte identifier (SHA-256 of creator + nonce)
    pub collection_id: [u8; 32],
    /// Human-readable name
    pub name: String,
    /// Short ticker symbol
    pub symbol: String,
    /// Creator address (20 bytes)
    pub creator: [u8; 20],
    /// Total minted supply
    pub total_supply: u128,
    /// NFT standard (ERC-721 or ERC-1155)
    pub standard: NftStandard,
    /// Block timestamp at creation
    pub created_at: u64,
}

/// Central NFT state registry shared across precompile invocations.
///
/// All state is held in-memory via `DashMap` for fast concurrent reads from the
/// EVM precompile. When constructed via [`NftRegistry::with_storage`] the
/// registry write-through-persists every mutation to RocksDB `CF_NFTS` and
/// hydrates from the same column family on startup, so collections / owners /
/// URIs / balances / pointers / nonces all survive node restarts. The
/// persistent JSON format is shared with the `tenzro-node` RPC handlers
/// (`handle_create_nft_collection`, `handle_mint_nft`, `handle_transfer_nft`,
/// …) — both layers read and write the same keys.
pub struct NftRegistry {
    /// Collections indexed by collection_id
    collections: DashMap<[u8; 32], NftCollection>,
    /// NFT ownership: (collection_id, token_id) -> owner address (ERC-721)
    nft_owners: DashMap<([u8; 32], u128), [u8; 20]>,
    /// Token URIs: (collection_id, token_id) -> uri string
    token_uris: DashMap<([u8; 32], u128), String>,
    /// ERC-721 balance tracking: (collection_id, owner) -> count
    erc721_balances: DashMap<([u8; 32], [u8; 20]), u128>,
    /// ERC-1155 balance tracking: (collection_id, owner, token_id) -> amount
    erc1155_balances: DashMap<([u8; 32], [u8; 20], u128), u128>,
    /// Cross-VM EVM pointer: collection_id -> EVM contract address
    evm_pointers: DashMap<[u8; 32], [u8; 20]>,
    /// Cross-VM SVM pointer: collection_id -> SVM mint address (32 bytes)
    svm_pointers: DashMap<[u8; 32], [u8; 32]>,
    /// Per-creator nonce for deterministic collection ID generation
    creator_nonces: DashMap<[u8; 20], u64>,
    /// Optional durable backing store. `None` for tests / ephemeral runs.
    storage: Option<Arc<dyn KvStore>>,
}

impl NftRegistry {
    /// Create a new empty in-memory NFT registry (no persistence).
    pub fn new() -> Self {
        Self {
            collections: DashMap::new(),
            nft_owners: DashMap::new(),
            token_uris: DashMap::new(),
            erc721_balances: DashMap::new(),
            erc1155_balances: DashMap::new(),
            evm_pointers: DashMap::new(),
            svm_pointers: DashMap::new(),
            creator_nonces: DashMap::new(),
            storage: None,
        }
    }

    /// Create a registry backed by `store`, hydrating existing state from
    /// `CF_NFTS` and write-through-persisting every subsequent mutation.
    pub fn with_storage(store: Arc<dyn KvStore>) -> Self {
        let registry = Self {
            collections: DashMap::new(),
            nft_owners: DashMap::new(),
            token_uris: DashMap::new(),
            erc721_balances: DashMap::new(),
            erc1155_balances: DashMap::new(),
            evm_pointers: DashMap::new(),
            svm_pointers: DashMap::new(),
            creator_nonces: DashMap::new(),
            storage: Some(store),
        };
        registry.hydrate_from_storage();
        registry
    }

    /// Returns the total number of registered collections
    pub fn collection_count(&self) -> usize {
        self.collections.len()
    }

    // -----------------------------------------------------------------
    // Persistence helpers
    // -----------------------------------------------------------------

    fn hex32(b: &[u8; 32]) -> String {
        hex::encode(b)
    }
    fn hex20(b: &[u8; 20]) -> String {
        hex::encode(b)
    }

    fn collection_key(id: &[u8; 32]) -> Vec<u8> {
        format!("collection:{}", Self::hex32(id)).into_bytes()
    }
    fn nft_key(coll: &[u8; 32], token_id: u128) -> Vec<u8> {
        format!("nft:{}:{}", Self::hex32(coll), token_id).into_bytes()
    }
    fn bal721_key(coll: &[u8; 32], owner: &[u8; 20]) -> Vec<u8> {
        format!("bal721:{}:{}", Self::hex32(coll), Self::hex20(owner)).into_bytes()
    }
    fn bal1155_key(coll: &[u8; 32], owner: &[u8; 20], token_id: u128) -> Vec<u8> {
        format!(
            "bal1155:{}:{}:{}",
            Self::hex32(coll),
            Self::hex20(owner),
            token_id
        )
        .into_bytes()
    }
    fn evm_ptr_key(coll: &[u8; 32]) -> Vec<u8> {
        format!("evm_ptr:{}", Self::hex32(coll)).into_bytes()
    }
    fn svm_ptr_key(coll: &[u8; 32]) -> Vec<u8> {
        format!("svm_ptr:{}", Self::hex32(coll)).into_bytes()
    }
    fn nonce_key(creator: &[u8; 20]) -> Vec<u8> {
        format!("nonce:{}", Self::hex20(creator)).into_bytes()
    }

    fn persist_collection(&self, c: &NftCollection) {
        let Some(store) = &self.storage else { return };
        let value = serde_json::json!({
            "collection_id": format!("0x{}", Self::hex32(&c.collection_id)),
            "name": c.name,
            "symbol": c.symbol,
            "creator": format!("0x{}", Self::hex20(&c.creator)),
            "total_supply": c.total_supply.to_string(),
            "standard": c.standard.as_u8(),
            "created_at": c.created_at,
        });
        match serde_json::to_vec(&value) {
            Ok(bytes) => {
                if let Err(e) = store.put(CF_NFTS, &Self::collection_key(&c.collection_id), &bytes)
                {
                    warn!(target: "nft_factory", error = %e, "persist_collection failed");
                }
            }
            Err(e) => warn!(target: "nft_factory", error = %e, "persist_collection serialize"),
        }
    }

    fn persist_nft(
        &self,
        coll: &[u8; 32],
        token_id: u128,
        owner: &[u8; 20],
        uri: &str,
        amount: u128,
    ) {
        let Some(store) = &self.storage else { return };
        let value = serde_json::json!({
            "collection_id": format!("0x{}", Self::hex32(coll)),
            "token_id": token_id.to_string(),
            "owner": format!("0x{}", Self::hex20(owner)),
            "uri": uri,
            "amount": amount.to_string(),
        });
        if let Ok(bytes) = serde_json::to_vec(&value)
            && let Err(e) = store.put(CF_NFTS, &Self::nft_key(coll, token_id), &bytes)
        {
            warn!(target: "nft_factory", error = %e, "persist_nft failed");
        }
    }

    fn persist_balance_721(&self, coll: &[u8; 32], owner: &[u8; 20], balance: u128) {
        let Some(store) = &self.storage else { return };
        if let Err(e) = store.put(
            CF_NFTS,
            &Self::bal721_key(coll, owner),
            &balance.to_le_bytes(),
        ) {
            warn!(target: "nft_factory", error = %e, "persist_balance_721 failed");
        }
    }

    fn persist_balance_1155(
        &self,
        coll: &[u8; 32],
        owner: &[u8; 20],
        token_id: u128,
        balance: u128,
    ) {
        let Some(store) = &self.storage else { return };
        if let Err(e) = store.put(
            CF_NFTS,
            &Self::bal1155_key(coll, owner, token_id),
            &balance.to_le_bytes(),
        ) {
            warn!(target: "nft_factory", error = %e, "persist_balance_1155 failed");
        }
    }

    fn persist_evm_pointer(&self, coll: &[u8; 32], evm_contract: &[u8; 20]) {
        let Some(store) = &self.storage else { return };
        if let Err(e) = store.put(CF_NFTS, &Self::evm_ptr_key(coll), evm_contract) {
            warn!(target: "nft_factory", error = %e, "persist_evm_pointer failed");
        }
    }

    fn persist_svm_pointer(&self, coll: &[u8; 32], svm_mint: &[u8; 32]) {
        let Some(store) = &self.storage else { return };
        if let Err(e) = store.put(CF_NFTS, &Self::svm_ptr_key(coll), svm_mint) {
            warn!(target: "nft_factory", error = %e, "persist_svm_pointer failed");
        }
    }

    fn persist_nonce(&self, creator: &[u8; 20], nonce: u64) {
        let Some(store) = &self.storage else { return };
        if let Err(e) = store.put(CF_NFTS, &Self::nonce_key(creator), &nonce.to_le_bytes()) {
            warn!(target: "nft_factory", error = %e, "persist_nonce failed");
        }
    }

    /// Walk every key in `CF_NFTS` and rebuild the in-memory maps. Called once
    /// from [`with_storage`].
    fn hydrate_from_storage(&self) {
        let Some(store) = &self.storage else { return };
        let mut collection_count = 0usize;
        let mut nft_count = 0usize;

        // Collections
        let coll_keys = match store.get_keys_with_prefix(CF_NFTS, b"collection:") {
            Ok(keys) => keys,
            Err(e) => {
                warn!(target: "nft_factory", error = %e, "hydrate: list collections");
                return;
            }
        };
        for key in coll_keys {
            let Ok(Some(bytes)) = store.get(CF_NFTS, &key) else {
                continue;
            };
            let Ok(v): serde_json::Result<serde_json::Value> = serde_json::from_slice(&bytes)
            else {
                continue;
            };
            let Some(id_hex) = v.get("collection_id").and_then(|x| x.as_str()) else {
                continue;
            };
            let id_hex = id_hex.strip_prefix("0x").unwrap_or(id_hex);
            let Ok(id_bytes) = hex::decode(id_hex) else {
                continue;
            };
            if id_bytes.len() != 32 {
                continue;
            }
            let mut collection_id = [0u8; 32];
            collection_id.copy_from_slice(&id_bytes);

            let name = v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let symbol = v
                .get("symbol")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let creator_hex = v
                .get("creator")
                .and_then(|x| x.as_str())
                .unwrap_or("0x0000000000000000000000000000000000000000");
            let creator_hex = creator_hex.strip_prefix("0x").unwrap_or(creator_hex);
            let mut creator = [0u8; 20];
            if let Ok(cb) = hex::decode(creator_hex)
                && cb.len() == 20
            {
                creator.copy_from_slice(&cb)
            }
            let total_supply = v
                .get("total_supply")
                .and_then(|x| {
                    x.as_str()
                        .and_then(|s| s.parse::<u128>().ok())
                        .or_else(|| x.as_u64().map(|n| n as u128))
                })
                .unwrap_or(0);
            let standard = v
                .get("standard")
                .and_then(|x| x.as_u64())
                .and_then(|n| NftStandard::from_u8(n as u8))
                .unwrap_or(NftStandard::Erc721);
            let created_at = v.get("created_at").and_then(|x| x.as_u64()).unwrap_or(0);

            self.collections.insert(
                collection_id,
                NftCollection {
                    collection_id,
                    name,
                    symbol,
                    creator,
                    total_supply,
                    standard,
                    created_at,
                },
            );
            collection_count += 1;
        }

        // NFTs (owners + URIs)
        if let Ok(nft_keys) = store.get_keys_with_prefix(CF_NFTS, b"nft:") {
            for key in nft_keys {
                let Ok(Some(bytes)) = store.get(CF_NFTS, &key) else {
                    continue;
                };
                let Ok(v): serde_json::Result<serde_json::Value> = serde_json::from_slice(&bytes)
                else {
                    continue;
                };
                let coll_hex = v
                    .get("collection_id")
                    .and_then(|x| x.as_str())
                    .map(|s| s.strip_prefix("0x").unwrap_or(s).to_string())
                    .unwrap_or_default();
                let token_id: u128 = v
                    .get("token_id")
                    .and_then(|x| {
                        x.as_str()
                            .and_then(|s| s.parse::<u128>().ok())
                            .or_else(|| x.as_u64().map(|n| n as u128))
                    })
                    .unwrap_or(0);
                let owner_hex = v
                    .get("owner")
                    .and_then(|x| x.as_str())
                    .map(|s| s.strip_prefix("0x").unwrap_or(s).to_string())
                    .unwrap_or_default();
                let uri = v
                    .get("uri")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let Ok(coll_b) = hex::decode(&coll_hex) else {
                    continue;
                };
                if coll_b.len() != 32 {
                    continue;
                }
                let mut coll = [0u8; 32];
                coll.copy_from_slice(&coll_b);
                let Ok(owner_b) = hex::decode(&owner_hex) else {
                    continue;
                };
                if owner_b.len() != 20 {
                    continue;
                }
                let mut owner = [0u8; 20];
                owner.copy_from_slice(&owner_b);
                self.nft_owners.insert((coll, token_id), owner);
                if !uri.is_empty() {
                    self.token_uris.insert((coll, token_id), uri);
                }
                nft_count += 1;
            }
        }

        // ERC-721 balances
        if let Ok(keys) = store.get_keys_with_prefix(CF_NFTS, b"bal721:") {
            for key in keys {
                let Ok(Some(bytes)) = store.get(CF_NFTS, &key) else {
                    continue;
                };
                if bytes.len() != 16 {
                    continue;
                }
                let s = match std::str::from_utf8(&key) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                // bal721:<coll_hex>:<owner_hex>
                let parts: Vec<&str> = s.splitn(3, ':').collect();
                if parts.len() != 3 {
                    continue;
                }
                let Ok(coll_b) = hex::decode(parts[1]) else {
                    continue;
                };
                let Ok(owner_b) = hex::decode(parts[2]) else {
                    continue;
                };
                if coll_b.len() != 32 || owner_b.len() != 20 {
                    continue;
                }
                let mut coll = [0u8; 32];
                coll.copy_from_slice(&coll_b);
                let mut owner = [0u8; 20];
                owner.copy_from_slice(&owner_b);
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&bytes);
                self.erc721_balances
                    .insert((coll, owner), u128::from_le_bytes(buf));
            }
        }

        // ERC-1155 balances
        if let Ok(keys) = store.get_keys_with_prefix(CF_NFTS, b"bal1155:") {
            for key in keys {
                let Ok(Some(bytes)) = store.get(CF_NFTS, &key) else {
                    continue;
                };
                if bytes.len() != 16 {
                    continue;
                }
                let s = match std::str::from_utf8(&key) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let parts: Vec<&str> = s.splitn(4, ':').collect();
                if parts.len() != 4 {
                    continue;
                }
                let Ok(coll_b) = hex::decode(parts[1]) else {
                    continue;
                };
                let Ok(owner_b) = hex::decode(parts[2]) else {
                    continue;
                };
                let Ok(token_id) = parts[3].parse::<u128>() else {
                    continue;
                };
                if coll_b.len() != 32 || owner_b.len() != 20 {
                    continue;
                }
                let mut coll = [0u8; 32];
                coll.copy_from_slice(&coll_b);
                let mut owner = [0u8; 20];
                owner.copy_from_slice(&owner_b);
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&bytes);
                self.erc1155_balances
                    .insert((coll, owner, token_id), u128::from_le_bytes(buf));
            }
        }

        // EVM pointers
        if let Ok(keys) = store.get_keys_with_prefix(CF_NFTS, b"evm_ptr:") {
            for key in keys {
                let Ok(Some(bytes)) = store.get(CF_NFTS, &key) else {
                    continue;
                };
                if bytes.len() != 20 {
                    continue;
                }
                let s = match std::str::from_utf8(&key) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let coll_hex = s.trim_start_matches("evm_ptr:");
                let Ok(coll_b) = hex::decode(coll_hex) else {
                    continue;
                };
                if coll_b.len() != 32 {
                    continue;
                }
                let mut coll = [0u8; 32];
                coll.copy_from_slice(&coll_b);
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&bytes);
                self.evm_pointers.insert(coll, addr);
            }
        }

        // SVM pointers
        if let Ok(keys) = store.get_keys_with_prefix(CF_NFTS, b"svm_ptr:") {
            for key in keys {
                let Ok(Some(bytes)) = store.get(CF_NFTS, &key) else {
                    continue;
                };
                if bytes.len() != 32 {
                    continue;
                }
                let s = match std::str::from_utf8(&key) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let coll_hex = s.trim_start_matches("svm_ptr:");
                let Ok(coll_b) = hex::decode(coll_hex) else {
                    continue;
                };
                if coll_b.len() != 32 {
                    continue;
                }
                let mut coll = [0u8; 32];
                coll.copy_from_slice(&coll_b);
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&bytes);
                self.svm_pointers.insert(coll, mint);
            }
        }

        // Per-creator nonces
        if let Ok(keys) = store.get_keys_with_prefix(CF_NFTS, b"nonce:") {
            for key in keys {
                let Ok(Some(bytes)) = store.get(CF_NFTS, &key) else {
                    continue;
                };
                if bytes.len() != 8 {
                    continue;
                }
                let s = match std::str::from_utf8(&key) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let creator_hex = s.trim_start_matches("nonce:");
                let Ok(b) = hex::decode(creator_hex) else {
                    continue;
                };
                if b.len() != 20 {
                    continue;
                }
                let mut creator = [0u8; 20];
                creator.copy_from_slice(&b);
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes);
                self.creator_nonces.insert(creator, u64::from_le_bytes(buf));
            }
        }

        info!(
            target: "nft_factory",
            collections = collection_count,
            nfts = nft_count,
            "NftRegistry hydrated from CF_NFTS"
        );
    }

    /// Compute a deterministic collection ID from creator address and nonce
    fn compute_collection_id(creator: &[u8; 20], nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"tenzro-nft-collection:");
        hasher.update(creator);
        hasher.update(nonce.to_be_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        id
    }

    /// Allocate the next nonce for a creator and return the new nonce value
    fn next_nonce(&self, creator: &[u8; 20]) -> u64 {
        let next_after_alloc = {
            let mut entry = self.creator_nonces.entry(*creator).or_insert(0);
            let nonce = *entry;
            *entry = nonce + 1;
            nonce
        };
        // Persist the *next* (post-increment) nonce so a restart resumes
        // allocating without colliding on the just-issued one. The map stores
        // post-increment too, so they stay in sync.
        self.persist_nonce(creator, next_after_alloc + 1);
        next_after_alloc
    }
}

impl Default for NftRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public constructor
// ---------------------------------------------------------------------------

/// Creates the NFT factory precompile closure
pub fn create_nft_factory_precompile(
    registry: Arc<NftRegistry>,
) -> Arc<dyn Fn(&[u8], u64) -> Result<PrecompileResult> + Send + Sync> {
    Arc::new(move |input: &[u8], gas_limit: u64| execute_nft_factory(&registry, input, gas_limit))
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Main dispatch for the NFT factory precompile
fn execute_nft_factory(
    registry: &NftRegistry,
    input: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if input.len() < 4 {
        return Ok(PrecompileResult::failed(gas_limit));
    }

    let selector = &input[..4];
    let calldata = &input[4..];

    match selector {
        s if s == selectors::CREATE_COLLECTION => {
            handle_create_collection(registry, calldata, gas_limit)
        }
        s if s == selectors::GET_COLLECTION => handle_get_collection(registry, calldata, gas_limit),
        s if s == selectors::MINT => handle_mint(registry, calldata, gas_limit),
        s if s == selectors::MINT_BATCH => handle_mint_batch(registry, calldata, gas_limit),
        s if s == selectors::TRANSFER_NFT => handle_transfer_nft(registry, calldata, gas_limit),
        s if s == selectors::OWNER_OF => handle_owner_of(registry, calldata, gas_limit),
        s if s == selectors::BALANCE_OF => handle_balance_of(registry, calldata, gas_limit),
        s if s == selectors::TOKEN_URI => handle_token_uri(registry, calldata, gas_limit),
        s if s == selectors::REGISTER_EVM_POINTER => {
            handle_register_evm_pointer(registry, calldata, gas_limit)
        }
        s if s == selectors::REGISTER_SVM_POINTER => {
            handle_register_svm_pointer(registry, calldata, gas_limit)
        }
        s if s == selectors::MINT_MULTI => handle_mint_multi(registry, calldata, gas_limit),
        s if s == selectors::BALANCE_OF_MULTI => {
            handle_balance_of_multi(registry, calldata, gas_limit)
        }
        s if s == selectors::MINT_RANDOM => handle_mint_random(registry, calldata, gas_limit),
        _ => Ok(PrecompileResult::failed(gas_limit)),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// createCollection(string name, string symbol, address creator, uint8 standard)
///
/// Input layout (after selector):
///   [0..32]    name_offset (dynamic)
///   [32..64]   symbol_offset (dynamic)
///   [64..96]   creator address
///   [96..128]  standard (uint8)
///   [128..]    dynamic name and symbol data
fn handle_create_collection(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_CREATE_COLLECTION {
        return Err(VmError::OutOfGas);
    }

    // Need at least the 4 fixed-size slots
    if calldata.len() < 128 {
        return Ok(PrecompileResult::failed(GAS_CREATE_COLLECTION));
    }

    // Parse creator address from slot 2
    let creator = abi::decode_address_at(calldata, 64).unwrap_or([0u8; 20]);

    // Parse standard from slot 3
    let standard_byte = calldata[127]; // last byte of [96..128]
    let standard = match NftStandard::from_u8(standard_byte) {
        Some(s) => s,
        None => return Ok(PrecompileResult::failed(GAS_CREATE_COLLECTION)),
    };

    // Parse dynamic strings
    let name =
        decode_dynamic_string(calldata, 0).unwrap_or_else(|| "Unnamed Collection".to_string());
    let symbol = decode_dynamic_string(calldata, 32).unwrap_or_else(|| "NFT".to_string());

    // Allocate nonce and compute collection ID
    let nonce = registry.next_nonce(&creator);
    let collection_id = NftRegistry::compute_collection_id(&creator, nonce);

    let collection = NftCollection {
        collection_id,
        name: name.clone(),
        symbol: symbol.clone(),
        creator,
        total_supply: 0,
        standard,
        created_at: 0, // Would be set by block context in production
    };

    registry
        .collections
        .insert(collection_id, collection.clone());
    registry.persist_collection(&collection);

    info!(
        "NFT factory: created collection {} ({}) id=0x{}, standard={:?}",
        name,
        symbol,
        hex::encode(collection_id),
        standard,
    );

    // Return the collection_id as bytes32
    Ok(PrecompileResult::success(
        collection_id.to_vec(),
        GAS_CREATE_COLLECTION,
    ))
}

/// getCollection(bytes32 collectionId)
///
/// Returns ABI-encoded: (string name, string symbol, address creator, uint256 totalSupply, uint8 standard)
///
/// Input layout (after selector):
///   [0..32]  collectionId
fn handle_get_collection(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 32 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let collection = match registry.collections.get(&collection_id) {
        Some(c) => c.clone(),
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    // Encode the response as a tuple of fixed-size fields followed by dynamic strings.
    // Layout:
    //   [0..32]    offset to name string data
    //   [32..64]   offset to symbol string data
    //   [64..96]   creator (address, left-padded)
    //   [96..128]  totalSupply (uint256)
    //   [128..160] standard (uint8)
    //   [160..]    dynamic name data, then dynamic symbol data

    // We know the fixed portion is 5 slots = 160 bytes.
    // name data starts at offset 160.
    let name_bytes = collection.name.as_bytes();
    let name_padded_len = name_bytes.len().div_ceil(32) * 32;
    // name dynamic block = 32 (length) + name_padded_len
    let name_block_len = 32 + name_padded_len;
    let symbol_offset = 160 + name_block_len;

    let symbol_bytes = collection.symbol.as_bytes();
    let symbol_padded_len = symbol_bytes.len().div_ceil(32) * 32;

    let total_len = symbol_offset + 32 + symbol_padded_len;
    let mut output = vec![0u8; total_len];

    // Slot 0: offset to name
    let name_offset_enc = abi::encode_uint256(160);
    output[..32].copy_from_slice(&name_offset_enc);

    // Slot 1: offset to symbol
    let symbol_offset_enc = abi::encode_uint256(symbol_offset as u128);
    output[32..64].copy_from_slice(&symbol_offset_enc);

    // Slot 2: creator address (left-padded to 32 bytes)
    output[76..96].copy_from_slice(&collection.creator);

    // Slot 3: totalSupply
    let supply_enc = abi::encode_uint256(collection.total_supply);
    output[96..128].copy_from_slice(&supply_enc);

    // Slot 4: standard
    output[159] = collection.standard.as_u8();

    // Dynamic name data at offset 160
    let name_len_enc = abi::encode_uint256(name_bytes.len() as u128);
    output[160..192].copy_from_slice(&name_len_enc);
    output[192..192 + name_bytes.len()].copy_from_slice(name_bytes);

    // Dynamic symbol data at symbol_offset
    let sym_len_enc = abi::encode_uint256(symbol_bytes.len() as u128);
    output[symbol_offset..symbol_offset + 32].copy_from_slice(&sym_len_enc);
    output[symbol_offset + 32..symbol_offset + 32 + symbol_bytes.len()]
        .copy_from_slice(symbol_bytes);

    Ok(PrecompileResult::success(output, GAS_READ))
}

/// mint(bytes32 collectionId, address to, uint256 tokenId, string tokenUri)
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   to (address)
///   [64..96]   tokenId (uint256)
///   [96..128]  tokenUri offset (dynamic)
///   [128..]    dynamic tokenUri data
fn handle_mint(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_MINT {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 128 {
        return Ok(PrecompileResult::failed(GAS_MINT));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let to = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_MINT)),
    };

    let token_id = match abi::decode_uint256_at(calldata, 64) {
        Some(v) => v,
        None => return Ok(PrecompileResult::failed(GAS_MINT)),
    };

    let token_uri = decode_dynamic_string(calldata, 96).unwrap_or_default();

    // Validate collection exists and is ERC-721
    let mut collection = match registry.collections.get_mut(&collection_id) {
        Some(c) => c,
        None => {
            debug!("NFT factory mint: collection not found");
            return Ok(PrecompileResult::failed(GAS_MINT));
        }
    };

    if collection.standard != NftStandard::Erc721 {
        debug!("NFT factory mint: collection is not ERC-721");
        return Ok(PrecompileResult::failed(GAS_MINT));
    }

    // Check that token_id is not already minted
    let owner_key = (collection_id, token_id);
    if registry.nft_owners.contains_key(&owner_key) {
        debug!("NFT factory mint: token_id {} already minted", token_id);
        return Ok(PrecompileResult::failed(GAS_MINT));
    }

    // Mint: set owner, increment balance, store URI, increment supply
    registry.nft_owners.insert(owner_key, to);
    if !token_uri.is_empty() {
        registry
            .token_uris
            .insert((collection_id, token_id), token_uri.clone());
    }

    let new_balance = {
        let balance_key = (collection_id, to);
        let mut balance = registry.erc721_balances.entry(balance_key).or_insert(0);
        *balance += 1;
        *balance
    };

    collection.total_supply += 1;
    let updated_collection = collection.clone();
    drop(collection); // release RefMut before persisting

    registry.persist_nft(&collection_id, token_id, &to, &token_uri, 1);
    registry.persist_balance_721(&collection_id, &to, new_balance);
    registry.persist_collection(&updated_collection);

    info!(
        "NFT factory: minted token {} in collection 0x{} to 0x{}",
        token_id,
        hex::encode(collection_id),
        hex::encode(to),
    );

    Ok(PrecompileResult::success(abi::encode_bool(true), GAS_MINT))
}

/// mintBatch(bytes32 collectionId, address to, uint256[] tokenIds, string[] tokenUris)
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   to (address)
///   [64..96]   tokenIds offset (dynamic)
///   [96..128]  tokenUris offset (dynamic)
///   [128..]    dynamic array data
fn handle_mint_batch(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_MINT_BATCH {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 128 {
        return Ok(PrecompileResult::failed(GAS_MINT_BATCH));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let to = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_MINT_BATCH)),
    };

    // Decode tokenIds array
    let token_ids_offset = match abi::decode_uint256_at(calldata, 64) {
        Some(v) => v as usize,
        None => return Ok(PrecompileResult::failed(GAS_MINT_BATCH)),
    };

    let token_ids = match decode_uint256_array(calldata, token_ids_offset) {
        Some(ids) => ids,
        None => return Ok(PrecompileResult::failed(GAS_MINT_BATCH)),
    };

    // Decode tokenUris array
    let token_uris_offset = match abi::decode_uint256_at(calldata, 96) {
        Some(v) => v as usize,
        None => return Ok(PrecompileResult::failed(GAS_MINT_BATCH)),
    };

    let token_uris = decode_string_array(calldata, token_uris_offset).unwrap_or_default();

    if token_ids.is_empty() {
        return Ok(PrecompileResult::failed(GAS_MINT_BATCH));
    }

    // Validate collection exists and is ERC-721
    let mut collection = match registry.collections.get_mut(&collection_id) {
        Some(c) => c,
        None => return Ok(PrecompileResult::failed(GAS_MINT_BATCH)),
    };

    if collection.standard != NftStandard::Erc721 {
        return Ok(PrecompileResult::failed(GAS_MINT_BATCH));
    }

    // Check none of the token IDs are already minted
    for &tid in &token_ids {
        if registry.nft_owners.contains_key(&(collection_id, tid)) {
            debug!("NFT factory mintBatch: token_id {} already minted", tid);
            return Ok(PrecompileResult::failed(GAS_MINT_BATCH));
        }
    }

    // Mint all tokens
    for (i, &tid) in token_ids.iter().enumerate() {
        registry.nft_owners.insert((collection_id, tid), to);
        let uri_str = token_uris.get(i).cloned().unwrap_or_default();
        if !uri_str.is_empty() {
            registry
                .token_uris
                .insert((collection_id, tid), uri_str.clone());
        }
        // Persist each token row with its URI (or empty string).
        registry.persist_nft(&collection_id, tid, &to, &uri_str, 1);
    }

    // Update balance and supply atomically
    let new_balance = {
        let balance_key = (collection_id, to);
        let mut balance = registry.erc721_balances.entry(balance_key).or_insert(0);
        *balance += token_ids.len() as u128;
        *balance
    };
    collection.total_supply += token_ids.len() as u128;
    let updated_collection = collection.clone();
    drop(collection);

    registry.persist_balance_721(&collection_id, &to, new_balance);
    registry.persist_collection(&updated_collection);

    info!(
        "NFT factory: batch minted {} tokens in collection 0x{} to 0x{}",
        token_ids.len(),
        hex::encode(collection_id),
        hex::encode(to),
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(true),
        GAS_MINT_BATCH,
    ))
}

/// transferNft(bytes32 collectionId, address from, address to, uint256 tokenId)
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   from (address)
///   [64..96]   to (address)
///   [96..128]  tokenId (uint256)
fn handle_transfer_nft(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_TRANSFER {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 128 {
        return Ok(PrecompileResult::failed(GAS_TRANSFER));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let from = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_TRANSFER)),
    };

    let to = match abi::decode_address_at(calldata, 64) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_TRANSFER)),
    };

    let token_id = match abi::decode_uint256_at(calldata, 96) {
        Some(v) => v,
        None => return Ok(PrecompileResult::failed(GAS_TRANSFER)),
    };

    // Validate collection exists
    if !registry.collections.contains_key(&collection_id) {
        return Ok(PrecompileResult::failed(GAS_TRANSFER));
    }

    // Verify current owner
    let owner_key = (collection_id, token_id);
    {
        let current_owner = match registry.nft_owners.get(&owner_key) {
            Some(o) => *o,
            None => {
                debug!("NFT factory transfer: token not found");
                return Ok(PrecompileResult::failed(GAS_TRANSFER));
            }
        };

        if current_owner != from {
            debug!("NFT factory transfer: caller is not the owner");
            return Ok(PrecompileResult::failed(GAS_TRANSFER));
        }
    }

    // Transfer ownership
    registry.nft_owners.insert(owner_key, to);

    // Capture URI for persistence (so the persisted owner row stays consistent with the in-memory owner row)
    let uri_str = registry
        .token_uris
        .get(&owner_key)
        .map(|u| u.clone())
        .unwrap_or_default();

    // Update balances: decrement `from`, increment `to`
    let new_from_balance = {
        let from_key = (collection_id, from);
        if let Some(mut balance) = registry.erc721_balances.get_mut(&from_key) {
            *balance = balance.saturating_sub(1);
            *balance
        } else {
            0
        }
    };
    let new_to_balance = {
        let to_key = (collection_id, to);
        let mut balance = registry.erc721_balances.entry(to_key).or_insert(0);
        *balance += 1;
        *balance
    };

    // Persist updated owner row + both balance rows
    registry.persist_nft(&collection_id, token_id, &to, &uri_str, 1);
    registry.persist_balance_721(&collection_id, &from, new_from_balance);
    registry.persist_balance_721(&collection_id, &to, new_to_balance);

    info!(
        "NFT factory: transferred token {} in 0x{} from 0x{} to 0x{}",
        token_id,
        hex::encode(collection_id),
        hex::encode(from),
        hex::encode(to),
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(true),
        GAS_TRANSFER,
    ))
}

/// ownerOf(bytes32 collectionId, uint256 tokenId)
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   tokenId (uint256)
fn handle_owner_of(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let token_id = match abi::decode_uint256_at(calldata, 32) {
        Some(v) => v,
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    let owner = match registry.nft_owners.get(&(collection_id, token_id)) {
        Some(o) => *o,
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    // Return address left-padded to 32 bytes
    let mut output = vec![0u8; 32];
    output[12..32].copy_from_slice(&owner);
    Ok(PrecompileResult::success(output, GAS_READ))
}

/// balanceOf(bytes32 collectionId, address owner)
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   owner (address)
fn handle_balance_of(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let owner = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    let balance = registry
        .erc721_balances
        .get(&(collection_id, owner))
        .map(|v| *v)
        .unwrap_or(0);

    Ok(PrecompileResult::success(
        abi::encode_uint256(balance),
        GAS_READ,
    ))
}

/// tokenUri(bytes32 collectionId, uint256 tokenId)
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   tokenId (uint256)
fn handle_token_uri(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let token_id = match abi::decode_uint256_at(calldata, 32) {
        Some(v) => v,
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    let uri = match registry.token_uris.get(&(collection_id, token_id)) {
        Some(u) => u.clone(),
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    Ok(PrecompileResult::success(
        abi::encode_string(&uri),
        GAS_READ,
    ))
}

/// registerEvmPointer(bytes32 collectionId, address evmContract)
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   evmContract (address)
fn handle_register_evm_pointer(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_REGISTER_POINTER {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_REGISTER_POINTER));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let evm_contract = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_REGISTER_POINTER)),
    };

    // Validate collection exists
    if !registry.collections.contains_key(&collection_id) {
        return Ok(PrecompileResult::failed(GAS_REGISTER_POINTER));
    }

    registry.evm_pointers.insert(collection_id, evm_contract);
    registry.persist_evm_pointer(&collection_id, &evm_contract);

    info!(
        "NFT factory: registered EVM pointer 0x{} for collection 0x{}",
        hex::encode(evm_contract),
        hex::encode(collection_id),
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(true),
        GAS_REGISTER_POINTER,
    ))
}

/// registerSvmPointer(bytes32 collectionId, bytes32 svmMint)
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   svmMint (bytes32)
fn handle_register_svm_pointer(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_REGISTER_POINTER {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_REGISTER_POINTER));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let mut svm_mint = [0u8; 32];
    svm_mint.copy_from_slice(&calldata[32..64]);

    // Validate collection exists
    if !registry.collections.contains_key(&collection_id) {
        return Ok(PrecompileResult::failed(GAS_REGISTER_POINTER));
    }

    registry.svm_pointers.insert(collection_id, svm_mint);
    registry.persist_svm_pointer(&collection_id, &svm_mint);

    info!(
        "NFT factory: registered SVM pointer 0x{} for collection 0x{}",
        hex::encode(svm_mint),
        hex::encode(collection_id),
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(true),
        GAS_REGISTER_POINTER,
    ))
}

/// mintMulti(bytes32 collectionId, address to, uint256 tokenId, uint256 amount)
///
/// ERC-1155 multi-token mint: mints `amount` copies of `tokenId` to `to`.
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   to (address)
///   [64..96]   tokenId (uint256)
///   [96..128]  amount (uint256)
fn handle_mint_multi(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_MINT {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 128 {
        return Ok(PrecompileResult::failed(GAS_MINT));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let to = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_MINT)),
    };

    let token_id = match abi::decode_uint256_at(calldata, 64) {
        Some(v) => v,
        None => return Ok(PrecompileResult::failed(GAS_MINT)),
    };

    let amount = match abi::decode_uint256_at(calldata, 96) {
        Some(v) => v,
        None => return Ok(PrecompileResult::failed(GAS_MINT)),
    };

    if amount == 0 {
        return Ok(PrecompileResult::failed(GAS_MINT));
    }

    // Validate collection exists and is ERC-1155
    let mut collection = match registry.collections.get_mut(&collection_id) {
        Some(c) => c,
        None => return Ok(PrecompileResult::failed(GAS_MINT)),
    };

    if collection.standard != NftStandard::Erc1155 {
        debug!("NFT factory mintMulti: collection is not ERC-1155");
        return Ok(PrecompileResult::failed(GAS_MINT));
    }

    // Increment the ERC-1155 balance
    let new_balance = {
        let key = (collection_id, to, token_id);
        let mut balance = registry.erc1155_balances.entry(key).or_insert(0);
        *balance = balance.saturating_add(amount);
        *balance
    };

    collection.total_supply = collection.total_supply.saturating_add(amount);
    let updated_collection = collection.clone();
    drop(collection);

    registry.persist_balance_1155(&collection_id, &to, token_id, new_balance);
    registry.persist_collection(&updated_collection);

    info!(
        "NFT factory: minted {} copies of token {} in ERC-1155 collection 0x{} to 0x{}",
        amount,
        token_id,
        hex::encode(collection_id),
        hex::encode(to),
    );

    Ok(PrecompileResult::success(abi::encode_bool(true), GAS_MINT))
}

/// balanceOfMulti(bytes32 collectionId, address owner, uint256 tokenId)
///
/// ERC-1155 balance query for a specific token ID.
///
/// Input layout (after selector):
///   [0..32]    collectionId
///   [32..64]   owner (address)
///   [64..96]   tokenId (uint256)
fn handle_balance_of_multi(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let owner = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    let token_id = match abi::decode_uint256_at(calldata, 64) {
        Some(v) => v,
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    let balance = registry
        .erc1155_balances
        .get(&(collection_id, owner, token_id))
        .map(|v| *v)
        .unwrap_or(0);

    Ok(PrecompileResult::success(
        abi::encode_uint256(balance),
        GAS_READ,
    ))
}

/// mintRandom(bytes32 collectionId, address to, uint256 idSpace,
///            bytes32 vrfPubkey, bytes vrfProof, bytes alpha)
///
/// Verifies an ECVRF proof (RFC 9381, `tenzro_crypto::vrf`), derives a
/// deterministic random token_id in `[0, idSpace)`, assigns a rarity tier
/// from byte[32] of the VRF output, and mints the resulting ERC-721 NFT.
///
/// Because the VRF output is fully determined by (vrfPubkey, alpha) and
/// can be independently re-verified by third parties via precompile 0x1007,
/// the randomness is unbiased and auditable (Chainlink-VRF-style guarantee).
///
/// Input layout (after selector):
///   [0..32]    collectionId (bytes32)
///   [32..64]   to (address, right-padded)
///   [64..96]   idSpace (uint256; must be > 0)
///   [96..128]  vrfPubkey (bytes32, raw Ed25519 compressed pk)
///   [128..160] offset to vrfProof (dynamic, must decode to 80 bytes)
///   [160..192] offset to alpha (dynamic)
///   [192..]    dynamic segments: proof, alpha
///
/// Output:
///   [0..32]    minted token_id (uint256)
///   [32..64]   rarity tier (uint256, 0..=255)
fn handle_mint_random(
    registry: &NftRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    use tenzro_crypto::vrf;

    if gas_limit < GAS_MINT_RANDOM {
        return Err(VmError::OutOfGas);
    }

    if calldata.len() < 192 {
        return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
    }

    let mut collection_id = [0u8; 32];
    collection_id.copy_from_slice(&calldata[..32]);

    let to = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_MINT_RANDOM)),
    };

    let id_space = match abi::decode_uint256_at(calldata, 64) {
        Some(v) if v > 0 => v,
        _ => return Ok(PrecompileResult::failed(GAS_MINT_RANDOM)),
    };

    let mut pk_bytes = [0u8; 32];
    pk_bytes.copy_from_slice(&calldata[96..128]);

    // Decode proof (dynamic bytes, must be exactly 80 bytes)
    let proof_offset = match abi::decode_uint256_at(calldata, 128) {
        Some(o) => o as usize,
        None => return Ok(PrecompileResult::failed(GAS_MINT_RANDOM)),
    };
    if calldata.len() < proof_offset + 32 {
        return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
    }
    let proof_len = match abi::decode_uint256_at(calldata, proof_offset) {
        Some(l) => l as usize,
        None => return Ok(PrecompileResult::failed(GAS_MINT_RANDOM)),
    };
    if proof_len != vrf::PROOF_LEN || calldata.len() < proof_offset + 32 + vrf::PROOF_LEN {
        return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
    }
    let mut proof_bytes = [0u8; vrf::PROOF_LEN];
    proof_bytes.copy_from_slice(&calldata[proof_offset + 32..proof_offset + 32 + vrf::PROOF_LEN]);

    // Decode alpha (dynamic bytes, any length up to remaining calldata)
    let alpha_offset = match abi::decode_uint256_at(calldata, 160) {
        Some(o) => o as usize,
        None => return Ok(PrecompileResult::failed(GAS_MINT_RANDOM)),
    };
    if calldata.len() < alpha_offset + 32 {
        return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
    }
    let alpha_len = match abi::decode_uint256_at(calldata, alpha_offset) {
        Some(l) => l as usize,
        None => return Ok(PrecompileResult::failed(GAS_MINT_RANDOM)),
    };
    if calldata.len() < alpha_offset + 32 + alpha_len {
        return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
    }
    let alpha = &calldata[alpha_offset + 32..alpha_offset + 32 + alpha_len];

    // Verify VRF proof
    let pk = vrf::VrfPublicKey(pk_bytes);
    let proof = vrf::VrfProof(proof_bytes);
    let vrf_output = match vrf::verify(&pk, alpha, &proof) {
        Ok(o) => o,
        Err(e) => {
            debug!("NFT factory mintRandom: VRF verification failed: {}", e);
            return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
        }
    };

    // Validate collection exists and is ERC-721 before touching state
    let mut collection = match registry.collections.get_mut(&collection_id) {
        Some(c) => c,
        None => {
            debug!("NFT factory mintRandom: collection not found");
            return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
        }
    };

    if collection.standard != NftStandard::Erc721 {
        debug!("NFT factory mintRandom: collection is not ERC-721");
        return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
    }

    // Derive a random token_id from VRF output, with up to 4 collision retries
    // using rotating 8-byte windows of the 64-byte output.
    let output_bytes = &vrf_output.0;
    let mut token_id: u128 = 0;
    let mut assigned = false;
    for window in 0..4 {
        let base = window * 8;
        if base + 8 > output_bytes.len() {
            break;
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&output_bytes[base..base + 8]);
        let candidate = (u64::from_be_bytes(buf) as u128) % id_space;
        let owner_key = (collection_id, candidate);
        if !registry.nft_owners.contains_key(&owner_key) {
            token_id = candidate;
            assigned = true;
            break;
        }
    }

    if !assigned {
        debug!("NFT factory mintRandom: id_space too crowded (4 collisions)");
        return Ok(PrecompileResult::failed(GAS_MINT_RANDOM));
    }

    // Rarity tier from byte 32 (first byte of second half of output)
    let rarity = output_bytes[32] as u128;

    // Commit state
    let owner_key = (collection_id, token_id);
    registry.nft_owners.insert(owner_key, to);
    let uri_str = format!(
        "tenzro-vrf://rarity/{}?alpha={}",
        rarity,
        hex::encode(alpha)
    );
    registry
        .token_uris
        .insert((collection_id, token_id), uri_str.clone());
    let new_balance = {
        let balance_key = (collection_id, to);
        let mut balance = registry.erc721_balances.entry(balance_key).or_insert(0);
        *balance += 1;
        *balance
    };
    collection.total_supply += 1;
    let updated_collection = collection.clone();
    drop(collection);

    registry.persist_nft(&collection_id, token_id, &to, &uri_str, 1);
    registry.persist_balance_721(&collection_id, &to, new_balance);
    registry.persist_collection(&updated_collection);

    info!(
        "NFT factory: VRF-minted token {} (rarity={}) in collection 0x{} to 0x{}",
        token_id,
        rarity,
        hex::encode(collection_id),
        hex::encode(to),
    );

    // Return (token_id, rarity) as 2x uint256
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&abi::encode_uint256(token_id));
    out.extend_from_slice(&abi::encode_uint256(rarity));
    Ok(PrecompileResult::success(out, GAS_MINT_RANDOM))
}

// ---------------------------------------------------------------------------
// ABI decoding helpers
// ---------------------------------------------------------------------------

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

/// Decodes an ABI-encoded uint256[] array from calldata at a given byte offset
fn decode_uint256_array(calldata: &[u8], offset: usize) -> Option<Vec<u128>> {
    if calldata.len() < offset + 32 {
        return None;
    }

    // Read array length
    let length = abi::decode_uint256_at(calldata, offset)? as usize;

    if length == 0 {
        return Some(Vec::new());
    }

    if calldata.len() < offset + 32 + length * 32 {
        return None;
    }

    let mut result = Vec::with_capacity(length);
    for i in 0..length {
        let value = abi::decode_uint256_at(calldata, offset + 32 + i * 32)?;
        result.push(value);
    }
    Some(result)
}

/// Decodes an ABI-encoded string[] array from calldata at a given byte offset
fn decode_string_array(calldata: &[u8], offset: usize) -> Option<Vec<String>> {
    if calldata.len() < offset + 32 {
        return None;
    }

    // Read array length
    let length = abi::decode_uint256_at(calldata, offset)? as usize;

    if length == 0 {
        return Some(Vec::new());
    }

    // Each element is an offset (relative to the start of the array data area)
    if calldata.len() < offset + 32 + length * 32 {
        return None;
    }

    let mut result = Vec::with_capacity(length);
    for i in 0..length {
        let str_offset = abi::decode_uint256_at(calldata, offset + 32 + i * 32)? as usize;
        // str_offset is relative to offset + 32 (start of data area)
        let abs_offset = offset + 32 + str_offset;
        if calldata.len() < abs_offset + 32 {
            result.push(String::new());
            continue;
        }
        let str_len = abi::decode_uint256_at(calldata, abs_offset)? as usize;
        if str_len == 0 || calldata.len() < abs_offset + 32 + str_len {
            result.push(String::new());
            continue;
        }
        let s = String::from_utf8(calldata[abs_offset + 32..abs_offset + 32 + str_len].to_vec())
            .unwrap_or_default();
        result.push(s);
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode a uint256 into a 32-byte ABI slot
    fn enc_u256(v: u128) -> Vec<u8> {
        abi::encode_uint256(v)
    }

    /// Helper: encode an address into a 32-byte ABI slot (left-padded)
    fn enc_addr(addr: &[u8; 20]) -> Vec<u8> {
        let mut slot = vec![0u8; 32];
        slot[12..32].copy_from_slice(addr);
        slot
    }

    /// Helper: encode a dynamic string for ABI calldata.
    /// Returns (offset_value, data_bytes) where data_bytes = length_slot + padded_content.
    fn enc_string_data(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        let padded_len = bytes.len().div_ceil(32) * 32;
        let mut data = Vec::with_capacity(32 + padded_len);
        data.extend_from_slice(&enc_u256(bytes.len() as u128)); // length
        data.extend_from_slice(bytes);
        data.resize(32 + padded_len, 0); // pad
        data
    }

    /// Helper: build createCollection calldata
    fn build_create_collection(
        name: &str,
        symbol: &str,
        creator: &[u8; 20],
        standard: u8,
    ) -> Vec<u8> {
        // Fixed slots: name_offset(0), symbol_offset(32), creator(64), standard(96)
        // Dynamic data starts at offset 128
        let name_data = enc_string_data(name);
        let symbol_data = enc_string_data(symbol);

        let name_offset = 128u128; // dynamic data starts right after 4 fixed slots
        let symbol_offset = name_offset + name_data.len() as u128;

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&enc_u256(name_offset)); // slot 0: name offset
        calldata.extend_from_slice(&enc_u256(symbol_offset)); // slot 1: symbol offset
        calldata.extend_from_slice(&enc_addr(creator)); // slot 2: creator
        calldata.extend_from_slice(&enc_u256(standard as u128)); // slot 3: standard
        calldata.extend_from_slice(&name_data);
        calldata.extend_from_slice(&symbol_data);
        calldata
    }

    /// Helper: build mint calldata
    fn build_mint(collection_id: &[u8; 32], to: &[u8; 20], token_id: u128, uri: &str) -> Vec<u8> {
        let uri_data = enc_string_data(uri);
        let uri_offset = 128u128; // dynamic data starts after 4 fixed slots

        let mut calldata = Vec::new();
        calldata.extend_from_slice(collection_id); // slot 0
        calldata.extend_from_slice(&enc_addr(to)); // slot 1
        calldata.extend_from_slice(&enc_u256(token_id)); // slot 2
        calldata.extend_from_slice(&enc_u256(uri_offset)); // slot 3: uri offset
        calldata.extend_from_slice(&uri_data);
        calldata
    }

    /// Helper: build full input with selector prefix
    fn with_selector(selector: &[u8; 4], calldata: &[u8]) -> Vec<u8> {
        let mut input = Vec::with_capacity(4 + calldata.len());
        input.extend_from_slice(selector);
        input.extend_from_slice(calldata);
        input
    }

    fn test_creator() -> [u8; 20] {
        [0xAA; 20]
    }

    fn test_recipient() -> [u8; 20] {
        [0xBB; 20]
    }

    #[test]
    fn test_create_collection_and_get_collection() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();

        // Create an ERC-721 collection
        let calldata = build_create_collection("CryptoApes", "APES", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();

        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.gas_used, GAS_CREATE_COLLECTION);

        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        // Verify collection count
        assert_eq!(registry.collection_count(), 1);

        // Get the collection back
        let mut get_calldata = Vec::new();
        get_calldata.extend_from_slice(&collection_id);
        let get_input = with_selector(&selectors::GET_COLLECTION, &get_calldata);
        let get_result = execute_nft_factory(&registry, &get_input, 10_000).unwrap();

        assert!(get_result.success);
        assert_eq!(get_result.gas_used, GAS_READ);

        // Verify creator address in output (slot 2, offset 64..96)
        let mut returned_creator = [0u8; 20];
        returned_creator.copy_from_slice(&get_result.output[76..96]);
        assert_eq!(returned_creator, creator);

        // Verify total supply is 0 (slot 3, offset 96..128)
        let total_supply = abi::decode_uint256_at(&get_result.output, 96).unwrap();
        assert_eq!(total_supply, 0);

        // Verify standard is ERC-721 (slot 4, offset 128..160)
        assert_eq!(get_result.output[159], 0);
    }

    #[test]
    fn test_mint_and_owner_of_and_balance_of() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();
        let recipient = test_recipient();

        // Create collection
        let calldata = build_create_collection("TestNFT", "TNFT", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        assert!(result.success);
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        // Mint token 1
        let mint_calldata = build_mint(&collection_id, &recipient, 1, "https://example.com/1");
        let mint_input = with_selector(&selectors::MINT, &mint_calldata);
        let mint_result = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(mint_result.success);
        assert_eq!(mint_result.gas_used, GAS_MINT);

        // Check ownerOf
        let mut owner_calldata = Vec::new();
        owner_calldata.extend_from_slice(&collection_id);
        owner_calldata.extend_from_slice(&enc_u256(1));
        let owner_input = with_selector(&selectors::OWNER_OF, &owner_calldata);
        let owner_result = execute_nft_factory(&registry, &owner_input, 10_000).unwrap();
        assert!(owner_result.success);
        let mut returned_owner = [0u8; 20];
        returned_owner.copy_from_slice(&owner_result.output[12..32]);
        assert_eq!(returned_owner, recipient);

        // Check balanceOf
        let mut bal_calldata = Vec::new();
        bal_calldata.extend_from_slice(&collection_id);
        bal_calldata.extend_from_slice(&enc_addr(&recipient));
        let bal_input = with_selector(&selectors::BALANCE_OF, &bal_calldata);
        let bal_result = execute_nft_factory(&registry, &bal_input, 10_000).unwrap();
        assert!(bal_result.success);
        let balance = abi::decode_uint256(&bal_result.output).unwrap();
        assert_eq!(balance, 1);

        // Verify total supply incremented
        let collection = registry.collections.get(&collection_id).unwrap();
        assert_eq!(collection.total_supply, 1);
    }

    #[test]
    fn test_transfer_nft_and_owner_check() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();
        let alice = [0x11; 20];
        let bob = [0x22; 20];

        // Create collection and mint to alice
        let calldata = build_create_collection("TransferTest", "TT", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        let mint_calldata = build_mint(&collection_id, &alice, 42, "");
        let mint_input = with_selector(&selectors::MINT, &mint_calldata);
        let mint_result = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(mint_result.success);

        // Transfer from alice to bob
        let mut xfer_calldata = Vec::new();
        xfer_calldata.extend_from_slice(&collection_id);
        xfer_calldata.extend_from_slice(&enc_addr(&alice));
        xfer_calldata.extend_from_slice(&enc_addr(&bob));
        xfer_calldata.extend_from_slice(&enc_u256(42));
        let xfer_input = with_selector(&selectors::TRANSFER_NFT, &xfer_calldata);
        let xfer_result = execute_nft_factory(&registry, &xfer_input, 100_000).unwrap();
        assert!(xfer_result.success);
        assert_eq!(xfer_result.gas_used, GAS_TRANSFER);

        // Verify bob is now the owner
        let mut owner_calldata = Vec::new();
        owner_calldata.extend_from_slice(&collection_id);
        owner_calldata.extend_from_slice(&enc_u256(42));
        let owner_input = with_selector(&selectors::OWNER_OF, &owner_calldata);
        let owner_result = execute_nft_factory(&registry, &owner_input, 10_000).unwrap();
        assert!(owner_result.success);
        let mut new_owner = [0u8; 20];
        new_owner.copy_from_slice(&owner_result.output[12..32]);
        assert_eq!(new_owner, bob);

        // Verify alice balance is 0, bob balance is 1
        let alice_bal = registry
            .erc721_balances
            .get(&(collection_id, alice))
            .map(|v| *v)
            .unwrap_or(0);
        assert_eq!(alice_bal, 0);
        let bob_bal = registry
            .erc721_balances
            .get(&(collection_id, bob))
            .map(|v| *v)
            .unwrap_or(0);
        assert_eq!(bob_bal, 1);
    }

    #[test]
    fn test_transfer_nft_wrong_owner_fails() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();
        let alice = [0x11; 20];
        let bob = [0x22; 20];
        let eve = [0x33; 20];

        // Create and mint to alice
        let calldata = build_create_collection("OwnerCheck", "OC", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        let mint_calldata = build_mint(&collection_id, &alice, 1, "");
        execute_nft_factory(
            &registry,
            &with_selector(&selectors::MINT, &mint_calldata),
            100_000,
        )
        .unwrap();

        // Eve tries to transfer alice's token
        let mut xfer_calldata = Vec::new();
        xfer_calldata.extend_from_slice(&collection_id);
        xfer_calldata.extend_from_slice(&enc_addr(&eve)); // from=eve (not owner)
        xfer_calldata.extend_from_slice(&enc_addr(&bob));
        xfer_calldata.extend_from_slice(&enc_u256(1));
        let xfer_input = with_selector(&selectors::TRANSFER_NFT, &xfer_calldata);
        let xfer_result = execute_nft_factory(&registry, &xfer_input, 100_000).unwrap();
        assert!(!xfer_result.success);
    }

    #[test]
    fn test_token_uri_setting_and_retrieval() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();
        let recipient = test_recipient();

        // Create collection
        let calldata = build_create_collection("UriTest", "URI", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        // Mint with URI
        let uri = "ipfs://QmTest123456789";
        let mint_calldata = build_mint(&collection_id, &recipient, 7, uri);
        let mint_input = with_selector(&selectors::MINT, &mint_calldata);
        let mint_result = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(mint_result.success);

        // Query tokenUri
        let mut uri_calldata = Vec::new();
        uri_calldata.extend_from_slice(&collection_id);
        uri_calldata.extend_from_slice(&enc_u256(7));
        let uri_input = with_selector(&selectors::TOKEN_URI, &uri_calldata);
        let uri_result = execute_nft_factory(&registry, &uri_input, 10_000).unwrap();
        assert!(uri_result.success);

        // The output is ABI-encoded string: offset(32) + length(32) + padded_data
        // Offset should be 32 (pointing to length)
        let offset = abi::decode_uint256(&uri_result.output[..32]).unwrap() as usize;
        assert_eq!(offset, 32);
        let length = abi::decode_uint256(&uri_result.output[32..64]).unwrap() as usize;
        assert_eq!(length, uri.len());
        let returned_uri = String::from_utf8(uri_result.output[64..64 + length].to_vec()).unwrap();
        assert_eq!(returned_uri, uri);
    }

    #[test]
    fn test_cross_vm_evm_pointer() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();

        // Create collection
        let calldata = build_create_collection("Pointer", "PTR", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        // Register EVM pointer
        let evm_contract = [0xCC; 20];
        let mut ptr_calldata = Vec::new();
        ptr_calldata.extend_from_slice(&collection_id);
        ptr_calldata.extend_from_slice(&enc_addr(&evm_contract));
        let ptr_input = with_selector(&selectors::REGISTER_EVM_POINTER, &ptr_calldata);
        let ptr_result = execute_nft_factory(&registry, &ptr_input, 100_000).unwrap();
        assert!(ptr_result.success);
        assert_eq!(ptr_result.gas_used, GAS_REGISTER_POINTER);

        // Verify pointer stored
        let stored = registry.evm_pointers.get(&collection_id).unwrap();
        assert_eq!(*stored, evm_contract);
    }

    #[test]
    fn test_cross_vm_svm_pointer() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();

        // Create collection
        let calldata = build_create_collection("SvmPtr", "SP", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        // Register SVM pointer
        let svm_mint = [0xDD; 32];
        let mut ptr_calldata = Vec::new();
        ptr_calldata.extend_from_slice(&collection_id);
        ptr_calldata.extend_from_slice(&svm_mint);
        let ptr_input = with_selector(&selectors::REGISTER_SVM_POINTER, &ptr_calldata);
        let ptr_result = execute_nft_factory(&registry, &ptr_input, 100_000).unwrap();
        assert!(ptr_result.success);

        // Verify pointer stored
        let stored = registry.svm_pointers.get(&collection_id).unwrap();
        assert_eq!(*stored, svm_mint);
    }

    #[test]
    fn test_erc1155_mint_multi_and_balance_of_multi() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();
        let recipient = test_recipient();

        // Create an ERC-1155 collection
        let calldata = build_create_collection("MultiToken", "MT", &creator, 1);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        assert!(result.success);
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        // Mint 100 copies of token 5
        let mut mint_calldata = Vec::new();
        mint_calldata.extend_from_slice(&collection_id);
        mint_calldata.extend_from_slice(&enc_addr(&recipient));
        mint_calldata.extend_from_slice(&enc_u256(5)); // tokenId
        mint_calldata.extend_from_slice(&enc_u256(100)); // amount
        let mint_input = with_selector(&selectors::MINT_MULTI, &mint_calldata);
        let mint_result = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(mint_result.success);

        // Query balance
        let mut bal_calldata = Vec::new();
        bal_calldata.extend_from_slice(&collection_id);
        bal_calldata.extend_from_slice(&enc_addr(&recipient));
        bal_calldata.extend_from_slice(&enc_u256(5));
        let bal_input = with_selector(&selectors::BALANCE_OF_MULTI, &bal_calldata);
        let bal_result = execute_nft_factory(&registry, &bal_input, 10_000).unwrap();
        assert!(bal_result.success);
        let balance = abi::decode_uint256(&bal_result.output).unwrap();
        assert_eq!(balance, 100);

        // Mint 50 more copies of token 5
        let mint_result2 = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(mint_result2.success);

        // Balance should now be 200 (the same calldata mints another 100)
        let bal_result2 = execute_nft_factory(&registry, &bal_input, 10_000).unwrap();
        let balance2 = abi::decode_uint256(&bal_result2.output).unwrap();
        assert_eq!(balance2, 200);

        // Verify total supply
        let collection = registry.collections.get(&collection_id).unwrap();
        assert_eq!(collection.total_supply, 200);
    }

    #[test]
    fn test_erc1155_mint_rejects_erc721_collection() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();
        let recipient = test_recipient();

        // Create ERC-721 collection
        let calldata = build_create_collection("Only721", "721", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        // Try to mintMulti on an ERC-721 collection (should fail)
        let mut mint_calldata = Vec::new();
        mint_calldata.extend_from_slice(&collection_id);
        mint_calldata.extend_from_slice(&enc_addr(&recipient));
        mint_calldata.extend_from_slice(&enc_u256(1));
        mint_calldata.extend_from_slice(&enc_u256(10));
        let mint_input = with_selector(&selectors::MINT_MULTI, &mint_calldata);
        let mint_result = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(!mint_result.success);
    }

    #[test]
    fn test_unknown_selector_returns_failed() {
        let registry = Arc::new(NftRegistry::new());
        let input = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let result = execute_nft_factory(&registry, &input, 100_000).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_insufficient_gas_returns_error() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();

        let calldata = build_create_collection("NoGas", "NG", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);

        // Provide less gas than required
        let result = execute_nft_factory(&registry, &input, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_insufficient_gas_for_read() {
        let registry = Arc::new(NftRegistry::new());
        let calldata = vec![0u8; 32]; // dummy collectionId
        let input = with_selector(&selectors::GET_COLLECTION, &calldata);

        let result = execute_nft_factory(&registry, &input, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_input_too_short_returns_failed() {
        let registry = Arc::new(NftRegistry::new());
        // Less than 4 bytes => failed
        let result = execute_nft_factory(&registry, &[0x00, 0x01], 100_000).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_mint_duplicate_token_id_fails() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();
        let recipient = test_recipient();

        // Create collection
        let calldata = build_create_collection("DupTest", "DUP", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        let mut collection_id = [0u8; 32];
        collection_id.copy_from_slice(&result.output);

        // Mint token 1
        let mint_calldata = build_mint(&collection_id, &recipient, 1, "");
        let mint_input = with_selector(&selectors::MINT, &mint_calldata);
        let first = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(first.success);

        // Mint token 1 again (should fail)
        let second = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(!second.success);
    }

    #[test]
    fn test_collection_id_deterministic() {
        let creator = test_creator();
        let id1 = NftRegistry::compute_collection_id(&creator, 0);
        let id2 = NftRegistry::compute_collection_id(&creator, 0);
        assert_eq!(id1, id2);

        // Different nonce => different ID
        let id3 = NftRegistry::compute_collection_id(&creator, 1);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_register_pointer_nonexistent_collection_fails() {
        let registry = Arc::new(NftRegistry::new());
        let fake_id = [0xFF; 32];
        let evm_contract = [0xCC; 20];

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&fake_id);
        calldata.extend_from_slice(&enc_addr(&evm_contract));
        let input = with_selector(&selectors::REGISTER_EVM_POINTER, &calldata);
        let result = execute_nft_factory(&registry, &input, 100_000).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_owner_of_nonexistent_token_fails() {
        let registry = Arc::new(NftRegistry::new());
        let fake_id = [0xFF; 32];

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&fake_id);
        calldata.extend_from_slice(&enc_u256(999));
        let input = with_selector(&selectors::OWNER_OF, &calldata);
        let result = execute_nft_factory(&registry, &input, 10_000).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_balance_of_multi_zero_for_unknown() {
        let registry = Arc::new(NftRegistry::new());
        let owner = test_recipient();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&[0u8; 32]); // fake collection
        calldata.extend_from_slice(&enc_addr(&owner));
        calldata.extend_from_slice(&enc_u256(1));
        let input = with_selector(&selectors::BALANCE_OF_MULTI, &calldata);
        let result = execute_nft_factory(&registry, &input, 10_000).unwrap();
        assert!(result.success);
        let balance = abi::decode_uint256(&result.output).unwrap();
        assert_eq!(balance, 0);
    }

    #[test]
    fn test_mint_on_nonexistent_collection_fails() {
        let registry = Arc::new(NftRegistry::new());
        let fake_id = [0xFF; 32];
        let recipient = test_recipient();

        let mint_calldata = build_mint(&fake_id, &recipient, 1, "");
        let mint_input = with_selector(&selectors::MINT, &mint_calldata);
        let result = execute_nft_factory(&registry, &mint_input, 100_000).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_invalid_standard_fails() {
        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();

        // Standard = 99 (invalid)
        let calldata = build_create_collection("Bad", "BAD", &creator, 99);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        assert!(!result.success);
    }

    // ------------------------------------------------------------------
    // VRF-backed random mint tests (mintRandom, selector 0x52517e21)
    // ------------------------------------------------------------------

    /// Build mintRandom calldata with a real VRF proof.
    fn build_mint_random(
        collection_id: &[u8; 32],
        to: &[u8; 20],
        id_space: u128,
        pk: &[u8; 32],
        proof: &[u8; 80],
        alpha: &[u8],
    ) -> Vec<u8> {
        // Static part: [0..192] — 6 slots
        // Proof dynamic segment: 32-byte length + 80-byte proof + 16 padding = 128 bytes
        // Alpha offset = proof_offset + 128
        let proof_offset: u128 = 192;
        let proof_segment_len: u128 = 32 + 96; // 32 length + 80 data padded to 96
        let alpha_offset: u128 = proof_offset + proof_segment_len;

        let mut cd = Vec::new();
        cd.extend_from_slice(collection_id);
        cd.extend_from_slice(&enc_addr(to));
        cd.extend_from_slice(&enc_u256(id_space));
        cd.extend_from_slice(pk);
        cd.extend_from_slice(&enc_u256(proof_offset));
        cd.extend_from_slice(&enc_u256(alpha_offset));

        // Proof segment: length(32) + proof(80) + pad(16)
        cd.extend_from_slice(&enc_u256(80));
        cd.extend_from_slice(proof);
        cd.extend_from_slice(&[0u8; 16]);

        // Alpha segment: length(32) + alpha + pad
        cd.extend_from_slice(&enc_u256(alpha.len() as u128));
        cd.extend_from_slice(alpha);
        let alpha_pad = (32 - (alpha.len() % 32)) % 32;
        cd.extend_from_slice(&vec![0u8; alpha_pad]);

        cd
    }

    fn setup_erc721_collection(registry: &NftRegistry) -> [u8; 32] {
        let creator = test_creator();
        let calldata = build_create_collection("VRF Art", "VART", &creator, 0);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let result = execute_nft_factory(registry, &input, 200_000).unwrap();
        assert!(result.success);
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&result.output[..32]);
        cid
    }

    #[test]
    fn test_mint_random_valid_proof_succeeds() {
        use tenzro_crypto::vrf::{VrfSecretKey, prove};

        let registry = Arc::new(NftRegistry::new());
        let cid = setup_erc721_collection(&registry);
        let recipient = test_recipient();

        let sk = VrfSecretKey([42u8; 32]);
        let pk = sk.public_key();
        let alpha = b"mint-round-1";
        let proof = prove(&sk, alpha).unwrap();

        let cd = build_mint_random(&cid, &recipient, 10_000, &pk.0, &proof.0, alpha);
        let input = with_selector(&selectors::MINT_RANDOM, &cd);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        assert!(result.success, "mintRandom should succeed with valid proof");
        assert_eq!(result.output.len(), 64);

        let token_id = abi::decode_uint256_at(&result.output, 0).unwrap();
        assert!(token_id < 10_000);

        let owner = registry.nft_owners.get(&(cid, token_id)).unwrap();
        assert_eq!(*owner, recipient);
    }

    #[test]
    fn test_mint_random_determinism() {
        // Same (pk, alpha) must yield the same token_id+rarity in fresh collections.
        use tenzro_crypto::vrf::{VrfSecretKey, prove};

        let sk = VrfSecretKey([7u8; 32]);
        let pk = sk.public_key();
        let alpha = b"determinism-check";
        let proof = prove(&sk, alpha).unwrap();
        let recipient = test_recipient();

        let r1 = {
            let reg = Arc::new(NftRegistry::new());
            let cid = setup_erc721_collection(&reg);
            let cd = build_mint_random(&cid, &recipient, 1_000_000, &pk.0, &proof.0, alpha);
            execute_nft_factory(&reg, &with_selector(&selectors::MINT_RANDOM, &cd), 200_000)
                .unwrap()
        };

        let r2 = {
            let reg = Arc::new(NftRegistry::new());
            let cid = setup_erc721_collection(&reg);
            let cd = build_mint_random(&cid, &recipient, 1_000_000, &pk.0, &proof.0, alpha);
            execute_nft_factory(&reg, &with_selector(&selectors::MINT_RANDOM, &cd), 200_000)
                .unwrap()
        };

        assert_eq!(
            r1.output, r2.output,
            "same VRF input => same token_id+rarity"
        );
    }

    #[test]
    fn test_mint_random_invalid_proof_rejected() {
        use tenzro_crypto::vrf::{VrfSecretKey, prove};

        let registry = Arc::new(NftRegistry::new());
        let cid = setup_erc721_collection(&registry);
        let recipient = test_recipient();

        let sk = VrfSecretKey([5u8; 32]);
        let pk = sk.public_key();
        let alpha = b"abc";
        let mut proof = prove(&sk, alpha).unwrap();
        proof.0[10] ^= 0xFF;

        let cd = build_mint_random(&cid, &recipient, 1000, &pk.0, &proof.0, alpha);
        let input = with_selector(&selectors::MINT_RANDOM, &cd);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        assert!(!result.success, "tampered proof must be rejected");
    }

    #[test]
    fn test_mint_random_zero_id_space_rejected() {
        use tenzro_crypto::vrf::{VrfSecretKey, prove};

        let registry = Arc::new(NftRegistry::new());
        let cid = setup_erc721_collection(&registry);
        let recipient = test_recipient();

        let sk = VrfSecretKey([6u8; 32]);
        let pk = sk.public_key();
        let alpha = b"zero-space";
        let proof = prove(&sk, alpha).unwrap();

        let cd = build_mint_random(&cid, &recipient, 0, &pk.0, &proof.0, alpha);
        let input = with_selector(&selectors::MINT_RANDOM, &cd);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        assert!(!result.success);
    }

    #[test]
    fn test_mint_random_non_erc721_collection_rejected() {
        use tenzro_crypto::vrf::{VrfSecretKey, prove};

        let registry = Arc::new(NftRegistry::new());
        let creator = test_creator();
        let calldata = build_create_collection("Multi", "MULT", &creator, 1);
        let input = with_selector(&selectors::CREATE_COLLECTION, &calldata);
        let r = execute_nft_factory(&registry, &input, 200_000).unwrap();
        assert!(r.success);
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&r.output[..32]);

        let sk = VrfSecretKey([8u8; 32]);
        let pk = sk.public_key();
        let alpha = b"wrong-standard";
        let proof = prove(&sk, alpha).unwrap();
        let recipient = test_recipient();

        let cd = build_mint_random(&cid, &recipient, 100, &pk.0, &proof.0, alpha);
        let input = with_selector(&selectors::MINT_RANDOM, &cd);
        let result = execute_nft_factory(&registry, &input, 200_000).unwrap();
        assert!(!result.success, "mintRandom only supports ERC-721");
    }
}
