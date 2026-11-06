//! Token metadata index over consensus state.
//!
//! Every token's balances and supply live in chain state, in the token
//! ledger: native TNZO in the native balance map, every other token in the
//! token factory's storage. This index answers metadata lookups (by id,
//! symbol, EVM address, SVM mint, Tempo address, issuer) without scanning
//! state. Its entries are of two kinds:
//!
//! - definitions the protocol or the node's configuration fixes: TNZO and its
//!   VM addresses, the Tempo TIP-20 stablecoins the catalog routes to;
//! - tokens created on chain, indexed from the `TokenCreated` log the token
//!   ledger emits as each block executes.
//!
//! It holds no balances and moves no value. Entries persist to `CF_TOKENS` so
//! the index survives a restart without replaying history.

use crate::cross_vm::{
    TokenDefinition, TokenId, TokenMetadata, TokenPermissions, TokenType, TokenVmType, VmAddresses,
};
use crate::error::{Result, TokenError};
use dashmap::DashMap;
use std::sync::Arc;
use tenzro_storage::kv::{CF_TOKENS, KvStore};
use tracing::{debug, info, warn};

/// Token metadata index.
pub struct TokenRegistry {
    /// Token definitions indexed by TokenId
    tokens: DashMap<TokenId, TokenDefinition>,
    /// EVM address -> TokenId index
    by_evm_address: DashMap<[u8; 20], TokenId>,
    /// SVM mint -> TokenId index
    by_svm_mint: DashMap<[u8; 32], TokenId>,
    /// Tempo L1 TIP-20 address -> TokenId index
    by_tempo_address: DashMap<[u8; 20], TokenId>,
    /// Symbol (uppercase) -> the first TokenId indexed under it
    by_symbol: DashMap<String, TokenId>,
    /// Issuer -> list of TokenIds
    by_creator: DashMap<[u8; 32], Vec<TokenId>>,
    /// Persistence for the index
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for TokenRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRegistry")
            .field("token_count", &self.tokens.len())
            .field("evm_index_count", &self.by_evm_address.len())
            .field("svm_index_count", &self.by_svm_mint.len())
            .field("tempo_index_count", &self.by_tempo_address.len())
            .finish()
    }
}

impl Default for TokenRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenRegistry {
    /// An empty in-memory index.
    pub fn new() -> Self {
        Self {
            tokens: DashMap::new(),
            by_evm_address: DashMap::new(),
            by_svm_mint: DashMap::new(),
            by_tempo_address: DashMap::new(),
            by_symbol: DashMap::new(),
            by_creator: DashMap::new(),
            storage: None,
        }
    }

    /// An index persisted to `storage`, loaded from it.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let registry = Self {
            storage: Some(storage.clone()),
            ..Self::new()
        };
        for (key, value) in storage.scan_prefix(CF_TOKENS, b"token:")? {
            match bincode::deserialize::<TokenDefinition>(&value) {
                Ok(def) => registry.insert(def),
                Err(e) => warn!(
                    "Failed to deserialize token from key {}: {}",
                    hex::encode(&key),
                    e
                ),
            }
        }
        info!("Loaded token index: {} tokens", registry.tokens.len());
        Ok(registry)
    }

    fn insert(&self, def: TokenDefinition) {
        if let Some(evm_addr) = def.vm_addresses.evm {
            self.by_evm_address.insert(evm_addr, def.token_id);
        }
        if let Some(svm_mint) = def.vm_addresses.svm {
            self.by_svm_mint.insert(svm_mint, def.token_id);
        }
        if let Some(tempo_addr) = def.vm_addresses.tempo {
            self.by_tempo_address.insert(tempo_addr, def.token_id);
        }
        self.by_symbol
            .entry(def.symbol.to_uppercase())
            .or_insert(def.token_id);
        let mut issued = self.by_creator.entry(def.creator).or_default();
        if !issued.contains(&def.token_id) {
            issued.push(def.token_id);
        }
        drop(issued);
        self.tokens.insert(def.token_id, def);
    }

    fn persist(&self, def: &TokenDefinition) -> Result<()> {
        if let Some(storage) = &self.storage {
            let mut key = b"token:".to_vec();
            key.extend_from_slice(&def.token_id.0);
            let value =
                bincode::serialize(def).map_err(|e| TokenError::StorageError(e.to_string()))?;
            storage.put(CF_TOKENS, &key, &value)?;
        }
        Ok(())
    }

    fn define(&self, def: TokenDefinition) -> Result<()> {
        self.persist(&def)?;
        self.insert(def);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Definitions
    // -----------------------------------------------------------------------

    /// Define native TNZO with its addresses in each VM.
    pub fn define_tnzo(
        &self,
        evm_address: Option<[u8; 20]>,
        svm_mint: Option<[u8; 32]>,
    ) -> Result<()> {
        self.define(TokenDefinition {
            token_id: TokenId::tnzo(),
            name: "Tenzro Network Token".to_string(),
            symbol: "TNZO".to_string(),
            decimals: 18,
            total_supply: crate::tnzo::MAX_SUPPLY,
            max_supply: Some(crate::tnzo::MAX_SUPPLY),
            creator: [0u8; 32],
            token_type: TokenType::CrossVm,
            vm_addresses: VmAddresses {
                evm: evm_address,
                svm: svm_mint,
                native: Some([0u8; 32]),
                tempo: None,
            },
            permissions: TokenPermissions {
                mintable: false,
                burnable: false,
                pausable: false,
                freezable: false,
                paused: false,
            },
            created_at: 0,
            metadata: TokenMetadata {
                description: Some(
                    "Governance and utility token for the Tenzro Network".to_string(),
                ),
                ..Default::default()
            },
        })?;
        info!("Defined TNZO in the token index");
        Ok(())
    }

    /// Define a Tempo L1 TIP-20 stablecoin the catalog routes to. Its supply
    /// and issuance are on Tempo; the entry is metadata for routing.
    pub fn define_tip20(
        &self,
        symbol: &str,
        name: &str,
        decimals: u8,
        tempo_address: [u8; 20],
    ) -> Result<TokenId> {
        if symbol.is_empty() || symbol.len() > 12 {
            return Err(TokenError::InvalidAmount(
                "Token symbol must be 1-12 characters".to_string(),
            ));
        }
        if name.is_empty() || name.len() > 64 {
            return Err(TokenError::InvalidAmount(
                "Token name must be 1-64 characters".to_string(),
            ));
        }
        if decimals > 18 {
            return Err(TokenError::InvalidAmount(
                "Decimals must be 0-18".to_string(),
            ));
        }
        if self.by_symbol.contains_key(&symbol.to_uppercase()) {
            return Err(TokenError::InvalidAmount(format!(
                "Token symbol '{symbol}' already indexed"
            )));
        }
        // Deterministic id: SHA-256("tenzro/tip20" || tempo_address)
        use sha2::Digest;
        let token_id = TokenId(
            sha2::Sha256::new()
                .chain_update(b"tenzro/tip20")
                .chain_update(tempo_address)
                .finalize()
                .into(),
        );
        self.define(TokenDefinition {
            token_id,
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            total_supply: 0,
            max_supply: None,
            creator: [0u8; 32],
            token_type: TokenType::CrossVm,
            vm_addresses: VmAddresses {
                evm: None,
                svm: None,
                native: None,
                tempo: Some(tempo_address),
            },
            permissions: TokenPermissions {
                mintable: false,
                burnable: false,
                pausable: false,
                freezable: false,
                paused: false,
            },
            created_at: 0,
            metadata: TokenMetadata {
                description: Some(format!(
                    "Tempo L1 TIP-20 stablecoin ({symbol}) at chain_id 42431"
                )),
                ..Default::default()
            },
        })?;
        info!("Defined Tempo TIP-20 token {} in the token index", symbol);
        Ok(token_id)
    }

    /// Index a token created on chain, from its `TokenCreated` log. The
    /// ledger record holds its supply; the entry is its metadata.
    pub fn index_created(
        &self,
        token_id: [u8; 32],
        name: &str,
        symbol: &str,
        decimals: u8,
        issuer: &[u8],
    ) -> Result<()> {
        let mut creator = [0u8; 32];
        let n = issuer.len().min(32);
        creator[..n].copy_from_slice(&issuer[..n]);
        self.define(TokenDefinition {
            token_id: TokenId(token_id),
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            total_supply: 0,
            max_supply: None,
            creator,
            token_type: TokenType::Erc20,
            vm_addresses: VmAddresses::default(),
            permissions: TokenPermissions::default(),
            created_at: 0,
            metadata: TokenMetadata::default(),
        })?;
        debug!("Indexed token {} ({})", hex::encode(token_id), symbol);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Lookups
    // -----------------------------------------------------------------------

    /// Gets a token definition by ID
    pub fn get(&self, token_id: &TokenId) -> Option<TokenDefinition> {
        self.tokens.get(token_id).map(|r| r.clone())
    }

    /// Gets a token by EVM contract address
    pub fn get_by_evm_address(&self, address: &[u8; 20]) -> Option<TokenDefinition> {
        self.by_evm_address
            .get(address)
            .and_then(|id| self.tokens.get(&id).map(|r| r.clone()))
    }

    /// Gets a token by SVM mint address
    pub fn get_by_svm_mint(&self, mint: &[u8; 32]) -> Option<TokenDefinition> {
        self.by_svm_mint
            .get(mint)
            .and_then(|id| self.tokens.get(&id).map(|r| r.clone()))
    }

    /// Gets a token by Tempo L1 TIP-20 contract address
    pub fn get_by_tempo_address(&self, address: &[u8; 20]) -> Option<TokenDefinition> {
        self.by_tempo_address
            .get(address)
            .and_then(|id| self.tokens.get(&id).map(|r| r.clone()))
    }

    /// Gets a token by symbol (case-insensitive)
    pub fn get_by_symbol(&self, symbol: &str) -> Option<TokenDefinition> {
        self.by_symbol
            .get(&symbol.to_uppercase())
            .and_then(|id| self.tokens.get(&id).map(|r| r.clone()))
    }

    /// Lists indexed tokens, optionally filtered by VM and issuer.
    pub fn list_tokens(
        &self,
        vm_filter: Option<TokenVmType>,
        creator_filter: Option<&[u8; 32]>,
        limit: usize,
    ) -> Vec<TokenDefinition> {
        let keep = |def: &TokenDefinition| {
            vm_filter
                .map(|vm| def.vm_addresses.has_vm(vm))
                .unwrap_or(true)
        };
        match creator_filter {
            Some(creator) => self
                .by_creator
                .get(creator)
                .map(|ids| {
                    ids.iter()
                        .filter_map(|id| self.tokens.get(id).map(|d| d.clone()))
                        .filter(keep)
                        .take(limit)
                        .collect()
                })
                .unwrap_or_default(),
            None => self
                .tokens
                .iter()
                .map(|e| e.value().clone())
                .filter(keep)
                .take(limit)
                .collect(),
        }
    }

    /// Number of indexed tokens.
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_indexed_creation_is_found_by_id_symbol_and_issuer() {
        let registry = TokenRegistry::new();
        let issuer = [5u8; 20];
        registry
            .index_created([9; 32], "Gold", "GLD", 6, &issuer)
            .unwrap();
        let def = registry.get(&TokenId([9; 32])).unwrap();
        assert_eq!(def.symbol, "GLD");
        assert_eq!(
            registry.get_by_symbol("gld").unwrap().token_id,
            TokenId([9; 32])
        );
        let mut creator = [0u8; 32];
        creator[..20].copy_from_slice(&issuer);
        assert_eq!(registry.list_tokens(None, Some(&creator), 10).len(), 1);
    }

    #[test]
    fn the_first_token_under_a_symbol_keeps_it() {
        let registry = TokenRegistry::new();
        registry
            .index_created([1; 32], "Gold", "GLD", 6, &[1; 20])
            .unwrap();
        registry
            .index_created([2; 32], "Gilded", "GLD", 6, &[2; 20])
            .unwrap();
        assert_eq!(
            registry.get_by_symbol("GLD").unwrap().token_id,
            TokenId([1; 32])
        );
        assert_eq!(registry.token_count(), 2);
    }

    #[test]
    fn tnzo_and_tip20_definitions_resolve_by_their_addresses() {
        let registry = TokenRegistry::new();
        registry.define_tnzo(Some([7; 20]), Some([8; 32])).unwrap();
        assert_eq!(
            registry.get_by_evm_address(&[7; 20]).unwrap().symbol,
            "TNZO"
        );
        assert_eq!(registry.get_by_svm_mint(&[8; 32]).unwrap().symbol, "TNZO");
        let id = registry
            .define_tip20("USDC", "USD Coin", 6, [3; 20])
            .unwrap();
        assert_eq!(
            registry.get_by_tempo_address(&[3; 20]).unwrap().token_id,
            id
        );
        assert!(registry.define_tip20("usdc", "Again", 6, [4; 20]).is_err());
    }
}
