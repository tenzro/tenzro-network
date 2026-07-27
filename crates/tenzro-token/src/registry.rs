//! Unified Token Registry for cross-VM token management
//!
//! The registry is the canonical source of truth for all token metadata and
//! cross-VM address mappings. It stores token definitions in RocksDB (CF_TOKENS)
//! and maintains in-memory indices for fast lookups by EVM address, SVM mint,
//! symbol, and creator.

use crate::cross_vm::{
    CrossVmTransfer, TokenDefinition, TokenId, TokenMetadata, TokenPermissions, TokenType,
    TokenVmType, VmAddresses,
};
use crate::error::{Result, TokenError};
use crate::tnzo::TnzoToken;
use dashmap::DashMap;
use std::sync::Arc;
use tenzro_storage::kv::{KvStore, CF_TOKENS};
use tracing::{debug, info, warn};

/// Unified Token Registry
///
/// Manages all tokens across all VMs. Each token has a canonical `TokenDefinition`
/// and optional cross-VM address mappings. The TNZO native token is registered at
/// startup with `TokenId::tnzo()`.
pub struct TokenRegistry {
    /// Token definitions indexed by TokenId
    tokens: DashMap<TokenId, TokenDefinition>,
    /// EVM address -> TokenId index
    by_evm_address: DashMap<[u8; 20], TokenId>,
    /// SVM mint -> TokenId index
    by_svm_mint: DashMap<[u8; 32], TokenId>,
    /// Tempo L1 TIP-20 address -> TokenId index
    by_tempo_address: DashMap<[u8; 20], TokenId>,
    /// Symbol (uppercase) -> TokenId index
    by_symbol: DashMap<String, TokenId>,
    /// Creator -> list of TokenIds
    by_creator: DashMap<[u8; 32], Vec<TokenId>>,
    /// ERC-20 approvals (only for wTNZO pointer contract; user ERC-20s store approvals in EVM state)
    approvals: DashMap<([u8; 20], [u8; 20], TokenId), u128>,
    /// Token creation nonce per creator (for deterministic TokenId computation)
    creator_nonces: DashMap<[u8; 32], u64>,
    /// User token balances: (owner_address, token_id) -> balance
    token_balances: DashMap<([u8; 32], TokenId), u128>,
    /// Reference to native TNZO token for pointer operations
    tnzo_token: Option<Arc<TnzoToken>>,
    /// RocksDB storage backend
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

impl TokenRegistry {
    /// Creates a new empty token registry (in-memory only)
    pub fn new() -> Self {
        Self {
            tokens: DashMap::new(),
            by_evm_address: DashMap::new(),
            by_svm_mint: DashMap::new(),
            by_tempo_address: DashMap::new(),
            by_symbol: DashMap::new(),
            by_creator: DashMap::new(),
            approvals: DashMap::new(),
            creator_nonces: DashMap::new(),
            token_balances: DashMap::new(),
            tnzo_token: None,
            storage: None,
        }
    }

    /// Creates a token registry with RocksDB persistence
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let registry = Self {
            tokens: DashMap::new(),
            by_evm_address: DashMap::new(),
            by_svm_mint: DashMap::new(),
            by_tempo_address: DashMap::new(),
            by_symbol: DashMap::new(),
            by_creator: DashMap::new(),
            approvals: DashMap::new(),
            creator_nonces: DashMap::new(),
            token_balances: DashMap::new(),
            tnzo_token: None,
            storage: Some(storage.clone()),
        };

        // Load existing tokens from storage
        registry.hydrate_from_storage()?;

        Ok(registry)
    }

    /// Sets the native TNZO token reference for pointer contract operations
    pub fn with_tnzo_token(mut self, token: Arc<TnzoToken>) -> Self {
        self.tnzo_token = Some(token);
        self
    }

    /// Hydrate in-memory caches from RocksDB on startup
    fn hydrate_from_storage(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        let prefix = b"token:";
        let entries = storage.scan_prefix(CF_TOKENS, prefix)?;

        for (key, value) in entries {
            match bincode::deserialize::<TokenDefinition>(&value) {
                Ok(def) => {
                    self.index_token(&def);
                    self.tokens.insert(def.token_id, def);
                }
                Err(e) => {
                    warn!(
                        "Failed to deserialize token from key {}: {}",
                        hex::encode(&key),
                        e
                    );
                }
            }
        }

        // Load nonces
        let nonce_prefix = b"nonce:";
        let nonce_entries = storage.scan_prefix(CF_TOKENS, nonce_prefix)?;
        for (key, value) in nonce_entries {
            if key.len() >= nonce_prefix.len() + 32 && value.len() == 8 {
                let mut creator = [0u8; 32];
                creator.copy_from_slice(&key[nonce_prefix.len()..nonce_prefix.len() + 32]);
                let nonce = u64::from_le_bytes(value.try_into().unwrap());
                self.creator_nonces.insert(creator, nonce);
            }
        }

        // Load approvals
        let approval_prefix = b"approval:";
        let approval_entries = storage.scan_prefix(CF_TOKENS, approval_prefix)?;
        for (_key, value) in approval_entries {
            if value.len() >= 72 {
                // 20 + 20 + 32 = 72 bytes for key parts, then amount
                let mut owner = [0u8; 20];
                let mut spender = [0u8; 20];
                let mut token_bytes = [0u8; 32];
                owner.copy_from_slice(&value[..20]);
                spender.copy_from_slice(&value[20..40]);
                token_bytes.copy_from_slice(&value[40..72]);
                if value.len() >= 88 {
                    let mut amount_bytes = [0u8; 16];
                    amount_bytes.copy_from_slice(&value[72..88]);
                    let amount = u128::from_le_bytes(amount_bytes);
                    let token_id = TokenId::new(token_bytes);
                    self.approvals
                        .insert((owner, spender, token_id), amount);
                }
            }
        }

        // Load token balances
        let balance_prefix = b"token_balance:";
        let balance_entries = storage.scan_prefix(CF_TOKENS, balance_prefix)?;
        for (key, value) in balance_entries {
            // Key format: "token_balance:" + 64 hex chars (owner) + ":" + 64 hex chars (token_id)
            if let Ok(key_str) = std::str::from_utf8(&key)
                && let Some(rest) = key_str.strip_prefix("token_balance:")
            {
                let parts: Vec<&str> = rest.splitn(2, ':').collect();
                if parts.len() == 2
                    && value.len() == 16
                    && let (Ok(owner_bytes), Ok(token_bytes)) =
                        (hex::decode(parts[0]), hex::decode(parts[1]))
                    && owner_bytes.len() == 32
                    && token_bytes.len() == 32
                {
                    let mut owner = [0u8; 32];
                    let mut token = [0u8; 32];
                    owner.copy_from_slice(&owner_bytes);
                    token.copy_from_slice(&token_bytes);
                    let mut amount_bytes = [0u8; 16];
                    amount_bytes.copy_from_slice(&value);
                    let amount = u128::from_le_bytes(amount_bytes);
                    self.token_balances
                        .insert((owner, TokenId::new(token)), amount);
                }
            }
        }

        info!(
            "Hydrated token registry: {} tokens, {} balances loaded",
            self.tokens.len(),
            self.token_balances.len()
        );
        Ok(())
    }

    /// Adds index entries for a token
    fn index_token(&self, def: &TokenDefinition) {
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
            .insert(def.symbol.to_uppercase(), def.token_id);

        self.by_creator
            .entry(def.creator)
            .or_default()
            .push(def.token_id);
    }

    /// Removes index entries for a token
    fn unindex_token(&self, def: &TokenDefinition) {
        if let Some(evm_addr) = def.vm_addresses.evm {
            self.by_evm_address.remove(&evm_addr);
        }
        if let Some(svm_mint) = def.vm_addresses.svm {
            self.by_svm_mint.remove(&svm_mint);
        }
        if let Some(tempo_addr) = def.vm_addresses.tempo {
            self.by_tempo_address.remove(&tempo_addr);
        }
        self.by_symbol.remove(&def.symbol.to_uppercase());
    }

    /// Persists a token definition to RocksDB
    fn persist_token(&self, def: &TokenDefinition) -> Result<()> {
        if let Some(storage) = &self.storage {
            let key = Self::token_key(&def.token_id);
            let value =
                bincode::serialize(def).map_err(|e| TokenError::StorageError(e.to_string()))?;
            storage.put(CF_TOKENS, &key, &value)?;
        }
        Ok(())
    }

    /// Persists a creator nonce
    fn persist_nonce(&self, creator: &[u8; 32], nonce: u64) -> Result<()> {
        if let Some(storage) = &self.storage {
            let mut key = b"nonce:".to_vec();
            key.extend_from_slice(creator);
            storage.put(CF_TOKENS, &key, &nonce.to_le_bytes())?;
        }
        Ok(())
    }

    /// Persists an approval
    fn persist_approval(
        &self,
        owner: &[u8; 20],
        spender: &[u8; 20],
        token_id: &TokenId,
        amount: u128,
    ) -> Result<()> {
        if let Some(storage) = &self.storage {
            let mut key = b"approval:".to_vec();
            key.extend_from_slice(owner);
            key.extend_from_slice(spender);
            key.extend_from_slice(&token_id.0);

            let mut value = Vec::with_capacity(88);
            value.extend_from_slice(owner);
            value.extend_from_slice(spender);
            value.extend_from_slice(&token_id.0);
            value.extend_from_slice(&amount.to_le_bytes());

            storage.put(CF_TOKENS, &key, &value)?;
        }
        Ok(())
    }

    /// Persists a token balance to RocksDB
    fn persist_token_balance(
        &self,
        owner: &[u8; 32],
        token_id: &TokenId,
        balance: u128,
    ) -> Result<()> {
        if let Some(storage) = &self.storage {
            let key = format!("token_balance:{}:{}", hex::encode(owner), hex::encode(token_id.0));
            storage.put(CF_TOKENS, key.as_bytes(), &balance.to_le_bytes())?;
        }
        Ok(())
    }

    /// Storage key for a token definition
    fn token_key(token_id: &TokenId) -> Vec<u8> {
        let mut key = b"token:".to_vec();
        key.extend_from_slice(&token_id.0);
        key
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Registers the native TNZO token definition at startup
    pub fn register_tnzo(
        &self,
        evm_address: Option<[u8; 20]>,
        svm_mint: Option<[u8; 32]>,
        daml_template: Option<String>,
    ) -> Result<()> {
        let token_id = TokenId::tnzo();

        let def = TokenDefinition {
            token_id,
            name: "Tenzro Network Token".to_string(),
            symbol: "TNZO".to_string(),
            decimals: 18,
            total_supply: crate::tnzo::MAX_SUPPLY,
            max_supply: Some(crate::tnzo::MAX_SUPPLY),
            creator: [0u8; 32], // System
            token_type: TokenType::CrossVm,
            vm_addresses: VmAddresses {
                evm: evm_address,
                svm: svm_mint,
                daml_template_id: daml_template,
                native: Some([0u8; 32]), // Sentinel for native
                tempo: None,
            },
            permissions: TokenPermissions {
                mintable: true, // Treasury can mint
                burnable: true,
                pausable: false,
                freezable: false,
                paused: false,
            },
            created_at: 0, // Genesis
            metadata: TokenMetadata {
                description: Some(
                    "Governance and utility token for the Tenzro Network".to_string(),
                ),
                ..Default::default()
            },
        };

        self.index_token(&def);
        self.persist_token(&def)?;
        self.tokens.insert(token_id, def);

        info!("Registered TNZO token in unified registry");
        Ok(())
    }

    /// Registers a Tempo L1 TIP-20 stablecoin in the catalog.
    ///
    /// Tempo (chain_id 42431, EIP-155 EVM, Stripe + Paradigm) hosts the canonical
    /// USDC/PYUSD/USDT issuances under TIP-20. Registering them here lets the rest
    /// of the workspace route to Tempo as a settlement venue on the same footing
    /// as EVM/SVM/DAML.
    pub fn register_tip20(
        &self,
        symbol: &str,
        name: &str,
        decimals: u8,
        tempo_address: [u8; 20],
        max_supply: Option<u128>,
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
                "Token symbol '{}' already registered",
                symbol
            )));
        }

        // Deterministic id: SHA-256("tenzro/tip20" || tempo_address)
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"tenzro/tip20");
        hasher.update(tempo_address);
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&hasher.finalize());
        let token_id = TokenId(id_bytes);

        let def = TokenDefinition {
            token_id,
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            total_supply: 0, // Tracked on Tempo, mirrored opportunistically
            max_supply,
            creator: [0u8; 32], // System catalog entry
            token_type: TokenType::CrossVm,
            vm_addresses: VmAddresses {
                evm: None,
                svm: None,
                daml_template_id: None,
                native: None,
                tempo: Some(tempo_address),
            },
            permissions: TokenPermissions {
                mintable: false, // Issuer-controlled on Tempo, not from Tenzro
                burnable: false,
                pausable: false,
                freezable: false,
                paused: false,
            },
            created_at: 0,
            metadata: TokenMetadata {
                description: Some(format!(
                    "Tempo L1 TIP-20 stablecoin ({}) at chain_id 42431",
                    symbol
                )),
                ..Default::default()
            },
        };

        self.index_token(&def);
        self.persist_token(&def)?;
        self.tokens.insert(token_id, def);

        info!("Registered Tempo TIP-20 token {} in unified registry", symbol);
        Ok(token_id)
    }

    /// Registers a new user-created token
    pub fn register_token(&self, mut def: TokenDefinition) -> Result<TokenId> {
        // Validate
        if def.name.is_empty() || def.name.len() > 64 {
            return Err(TokenError::InvalidAmount(
                "Token name must be 1-64 characters".to_string(),
            ));
        }
        if def.symbol.is_empty() || def.symbol.len() > 12 {
            return Err(TokenError::InvalidAmount(
                "Token symbol must be 1-12 characters".to_string(),
            ));
        }
        if def.decimals > 18 {
            return Err(TokenError::InvalidAmount(
                "Decimals must be 0-18".to_string(),
            ));
        }

        // Check symbol uniqueness
        if self.by_symbol.contains_key(&def.symbol.to_uppercase()) {
            return Err(TokenError::InvalidAmount(format!(
                "Token symbol '{}' already registered",
                def.symbol
            )));
        }

        // Assign token ID using creator nonce
        let mut nonce = self
            .creator_nonces
            .entry(def.creator)
            .or_insert(0);
        let token_id = TokenId::compute(&def.creator, *nonce);
        *nonce += 1;
        let new_nonce = *nonce;
        drop(nonce);

        def.token_id = token_id;
        def.created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let creator = def.creator;
        let supply = def.total_supply;

        self.index_token(&def);
        self.persist_token(&def)?;
        self.persist_nonce(&creator, new_nonce)?;
        self.tokens.insert(token_id, def);

        // Credit initial supply to creator
        if supply > 0 {
            self.token_balances.insert((creator, token_id), supply);
            self.persist_token_balance(&creator, &token_id, supply)?;
            info!(
                "Credited {} initial supply of token {} to creator {}",
                supply,
                token_id,
                hex::encode(creator)
            );
        }

        info!("Registered token {} in unified registry", token_id);
        Ok(token_id)
    }

    /// Updates VM addresses for an existing token (e.g., after deploying ERC-20 wrapper)
    pub fn update_vm_addresses(
        &self,
        token_id: &TokenId,
        addresses: VmAddresses,
    ) -> Result<()> {
        let mut def = self
            .tokens
            .get_mut(token_id)
            .ok_or_else(|| TokenError::AssetNotFound {
                asset_id: token_id.to_hex(),
            })?;

        // Remove old indices
        self.unindex_token(&def);

        // Update addresses
        def.vm_addresses = addresses;

        // Re-index
        self.index_token(&def);
        self.persist_token(&def)?;

        debug!("Updated VM addresses for token {}", token_id);
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

    /// Lists all tokens, optionally filtered
    pub fn list_tokens(
        &self,
        vm_filter: Option<TokenVmType>,
        creator_filter: Option<&[u8; 32]>,
        limit: usize,
    ) -> Vec<TokenDefinition> {
        let mut results = Vec::new();

        if let Some(creator) = creator_filter {
            // Use creator index
            if let Some(ids) = self.by_creator.get(creator) {
                for id in ids.iter().take(limit) {
                    if let Some(def) = self.tokens.get(id)
                        && vm_filter
                            .map(|vm| def.vm_addresses.has_vm(vm))
                            .unwrap_or(true)
                    {
                        results.push(def.clone());
                    }
                }
            }
        } else {
            for entry in self.tokens.iter() {
                if results.len() >= limit {
                    break;
                }
                let def = entry.value();
                if vm_filter
                    .map(|vm| def.vm_addresses.has_vm(vm))
                    .unwrap_or(true)
                {
                    results.push(def.clone());
                }
            }
        }

        results
    }

    /// Returns total number of registered tokens
    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    // -----------------------------------------------------------------------
    // User Token Balances
    // -----------------------------------------------------------------------

    /// Get balance of a user token for an address
    pub fn token_balance(&self, owner: &[u8; 32], token_id: &TokenId) -> u128 {
        self.token_balances
            .get(&(*owner, *token_id))
            .map(|v| *v)
            .unwrap_or(0)
    }

    /// Transfer user tokens between addresses
    pub fn transfer_token(
        &self,
        token_id: &TokenId,
        from: &[u8; 32],
        to: &[u8; 32],
        amount: u128,
    ) -> Result<()> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount(
                "Amount must be greater than zero".to_string(),
            ));
        }
        // Verify token exists
        if !self.tokens.contains_key(token_id) {
            return Err(TokenError::InvalidAmount(format!(
                "Token {} not found",
                token_id
            )));
        }
        let from_balance = self.token_balance(from, token_id);
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance {
                required: amount,
                available: from_balance,
            });
        }
        let new_from = from_balance.checked_sub(amount).ok_or_else(|| {
            TokenError::ArithmeticOverflow {
                operation: "transfer subtraction".to_string(),
            }
        })?;
        let to_balance = self.token_balance(to, token_id);
        let new_to = to_balance.checked_add(amount).ok_or_else(|| {
            TokenError::ArithmeticOverflow {
                operation: "transfer addition".to_string(),
            }
        })?;
        self.token_balances.insert((*from, *token_id), new_from);
        self.token_balances.insert((*to, *token_id), new_to);
        self.persist_token_balance(from, token_id, new_from)?;
        self.persist_token_balance(to, token_id, new_to)?;
        Ok(())
    }

    /// Mint additional tokens (only if token is mintable, caller must be creator)
    pub fn mint_token(
        &self,
        token_id: &TokenId,
        to: &[u8; 32],
        amount: u128,
        caller: &[u8; 32],
    ) -> Result<()> {
        let mut def = self.tokens.get_mut(token_id).ok_or_else(|| {
            TokenError::InvalidAmount(format!("Token {} not found", token_id))
        })?;
        if !def.permissions.mintable {
            return Err(TokenError::Unauthorized {
                reason: "Token is not mintable".to_string(),
            });
        }
        if &def.creator != caller {
            return Err(TokenError::Unauthorized {
                reason: "Only token creator can mint".to_string(),
            });
        }
        if let Some(max) = def.max_supply
            && def.total_supply.saturating_add(amount) > max
        {
            return Err(TokenError::InvalidAmount(
                "Minting would exceed max supply".to_string(),
            ));
        }
        def.total_supply = def.total_supply.checked_add(amount).ok_or_else(|| {
            TokenError::ArithmeticOverflow {
                operation: "mint supply increase".to_string(),
            }
        })?;
        let balance = self.token_balance(to, token_id);
        let new_balance = balance.checked_add(amount).ok_or_else(|| {
            TokenError::ArithmeticOverflow {
                operation: "mint balance increase".to_string(),
            }
        })?;
        self.token_balances.insert((*to, *token_id), new_balance);
        self.persist_token(def.value())?;
        self.persist_token_balance(to, token_id, new_balance)?;
        Ok(())
    }

    /// Burn tokens (only if token is burnable)
    pub fn burn_token(
        &self,
        token_id: &TokenId,
        from: &[u8; 32],
        amount: u128,
    ) -> Result<()> {
        let mut def = self.tokens.get_mut(token_id).ok_or_else(|| {
            TokenError::InvalidAmount(format!("Token {} not found", token_id))
        })?;
        if !def.permissions.burnable {
            return Err(TokenError::Unauthorized {
                reason: "Token is not burnable".to_string(),
            });
        }
        let balance = self.token_balance(from, token_id);
        if balance < amount {
            return Err(TokenError::InsufficientBalance {
                required: amount,
                available: balance,
            });
        }
        let new_balance = balance.checked_sub(amount).unwrap();
        def.total_supply = def.total_supply.saturating_sub(amount);
        self.token_balances.insert((*from, *token_id), new_balance);
        self.persist_token(def.value())?;
        self.persist_token_balance(from, token_id, new_balance)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // ERC-20 Approvals (for wTNZO pointer contract only)
    // -----------------------------------------------------------------------

    /// Sets ERC-20 approval for a token
    pub fn set_approval(
        &self,
        owner: &[u8; 20],
        spender: &[u8; 20],
        token_id: &TokenId,
        amount: u128,
    ) -> Result<()> {
        self.approvals
            .insert((*owner, *spender, *token_id), amount);
        self.persist_approval(owner, spender, token_id, amount)?;
        debug!(
            "Set approval: owner={} spender={} token={} amount={}",
            hex::encode(owner),
            hex::encode(spender),
            token_id,
            amount
        );
        Ok(())
    }

    /// Gets ERC-20 approval for a token
    pub fn get_approval(
        &self,
        owner: &[u8; 20],
        spender: &[u8; 20],
        token_id: &TokenId,
    ) -> u128 {
        self.approvals
            .get(&(*owner, *spender, *token_id))
            .map(|r| *r)
            .unwrap_or(0)
    }

    /// Spends from an approval (used by transferFrom)
    pub fn spend_approval(
        &self,
        owner: &[u8; 20],
        spender: &[u8; 20],
        token_id: &TokenId,
        amount: u128,
    ) -> Result<()> {
        let current = self.get_approval(owner, spender, token_id);

        // u128::MAX means unlimited approval
        if current == u128::MAX {
            return Ok(());
        }

        if current < amount {
            return Err(TokenError::InsufficientBalance {
                required: amount,
                available: current,
            });
        }

        let new_amount = current - amount;
        self.set_approval(owner, spender, token_id, new_amount)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Cross-VM Transfers
    // -----------------------------------------------------------------------

    /// Validates a cross-VM transfer request
    pub fn validate_cross_vm_transfer(&self, transfer: &CrossVmTransfer) -> Result<()> {
        // Token must exist
        let def = self
            .tokens
            .get(&transfer.token_id)
            .ok_or_else(|| TokenError::AssetNotFound {
                asset_id: transfer.token_id.to_hex(),
            })?;

        // Token must exist on both VMs (or be CrossVm/Native type)
        if transfer.from_vm != TokenVmType::Native && !def.vm_addresses.has_vm(transfer.from_vm) {
            return Err(TokenError::InvalidAmount(format!(
                "Token {} not available on source VM {:?}",
                def.symbol, transfer.from_vm
            )));
        }
        if transfer.to_vm != TokenVmType::Native && !def.vm_addresses.has_vm(transfer.to_vm) {
            return Err(TokenError::InvalidAmount(format!(
                "Token {} not available on destination VM {:?}",
                def.symbol, transfer.to_vm
            )));
        }

        // Amount must be > 0
        if transfer.amount == 0 {
            return Err(TokenError::InvalidAmount(
                "Transfer amount must be > 0".to_string(),
            ));
        }

        // Token must not be paused
        if def.permissions.paused {
            return Err(TokenError::Unauthorized {
                reason: format!("Token {} is paused", def.symbol),
            });
        }

        Ok(())
    }

    /// Returns the TNZO token reference
    pub fn tnzo_token(&self) -> Option<&Arc<TnzoToken>> {
        self.tnzo_token.as_ref()
    }
}

impl Default for TokenRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token_def(name: &str, symbol: &str, creator: [u8; 32]) -> TokenDefinition {
        TokenDefinition {
            token_id: TokenId::compute(&creator, 0),
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals: 18,
            total_supply: 1_000_000_000_000_000_000_000_000,
            max_supply: None,
            creator,
            token_type: TokenType::Erc20,
            vm_addresses: VmAddresses {
                evm: Some([0xAB; 20]),
                ..Default::default()
            },
            permissions: TokenPermissions::default(),
            created_at: 0,
            metadata: TokenMetadata::default(),
        }
    }

    #[test]
    fn test_register_and_lookup() {
        let registry = TokenRegistry::new();
        let creator = [1u8; 32];
        let def = make_token_def("TestToken", "TST", creator);

        let token_id = registry.register_token(def).unwrap();

        // Lookup by ID
        let found = registry.get(&token_id).unwrap();
        assert_eq!(found.name, "TestToken");
        assert_eq!(found.symbol, "TST");

        // Lookup by symbol
        let found = registry.get_by_symbol("tst").unwrap();
        assert_eq!(found.token_id, token_id);

        // Lookup by EVM address
        let found = registry.get_by_evm_address(&[0xAB; 20]).unwrap();
        assert_eq!(found.token_id, token_id);
    }

    #[test]
    fn test_register_tnzo() {
        let registry = TokenRegistry::new();
        registry
            .register_tnzo(Some([0x01; 20]), None, None)
            .unwrap();

        let tnzo = registry.get(&TokenId::tnzo()).unwrap();
        assert_eq!(tnzo.symbol, "TNZO");
        assert_eq!(tnzo.decimals, 18);
        assert!(tnzo.vm_addresses.evm.is_some());

        // Lookup by symbol
        let found = registry.get_by_symbol("TNZO").unwrap();
        assert_eq!(found.token_id, TokenId::tnzo());
    }

    #[test]
    fn test_duplicate_symbol_rejected() {
        let registry = TokenRegistry::new();
        let creator = [1u8; 32];

        let def1 = make_token_def("Token1", "DUP", creator);
        registry.register_token(def1).unwrap();

        let def2 = make_token_def("Token2", "DUP", [2u8; 32]);
        let result = registry.register_token(def2);
        assert!(result.is_err());
    }

    #[test]
    fn test_approval_lifecycle() {
        let registry = TokenRegistry::new();
        let owner = [0x01; 20];
        let spender = [0x02; 20];
        let token_id = TokenId::tnzo();

        // Set approval
        registry
            .set_approval(&owner, &spender, &token_id, 1000)
            .unwrap();
        assert_eq!(registry.get_approval(&owner, &spender, &token_id), 1000);

        // Spend from approval
        registry
            .spend_approval(&owner, &spender, &token_id, 400)
            .unwrap();
        assert_eq!(registry.get_approval(&owner, &spender, &token_id), 600);

        // Over-spend fails
        let result = registry.spend_approval(&owner, &spender, &token_id, 700);
        assert!(result.is_err());
    }

    #[test]
    fn test_unlimited_approval() {
        let registry = TokenRegistry::new();
        let owner = [0x01; 20];
        let spender = [0x02; 20];
        let token_id = TokenId::tnzo();

        registry
            .set_approval(&owner, &spender, &token_id, u128::MAX)
            .unwrap();

        // Spending does not reduce unlimited approval
        registry
            .spend_approval(&owner, &spender, &token_id, 999_999)
            .unwrap();
        assert_eq!(
            registry.get_approval(&owner, &spender, &token_id),
            u128::MAX
        );
    }

    #[test]
    fn test_list_tokens_with_filter() {
        let registry = TokenRegistry::new();
        let creator = [1u8; 32];

        let mut def1 = make_token_def("EvmToken", "EVT", creator);
        def1.vm_addresses.evm = Some([0x01; 20]);
        def1.vm_addresses.svm = None;
        registry.register_token(def1).unwrap();

        let mut def2 = make_token_def("SvmToken", "SVT", [2u8; 32]);
        def2.vm_addresses.evm = None;
        def2.vm_addresses.svm = Some([0x02; 32]);
        registry.register_token(def2).unwrap();

        // Filter by EVM
        let evm_tokens = registry.list_tokens(Some(TokenVmType::Evm), None, 100);
        assert_eq!(evm_tokens.len(), 1);
        assert_eq!(evm_tokens[0].symbol, "EVT");

        // Filter by SVM
        let svm_tokens = registry.list_tokens(Some(TokenVmType::Svm), None, 100);
        assert_eq!(svm_tokens.len(), 1);
        assert_eq!(svm_tokens[0].symbol, "SVT");

        // No filter
        let all_tokens = registry.list_tokens(None, None, 100);
        assert_eq!(all_tokens.len(), 2);
    }

    #[test]
    fn test_nonce_increments_per_creator() {
        let registry = TokenRegistry::new();
        let creator = [1u8; 32];

        let def1 = make_token_def("Token1", "T1", creator);
        let id1 = registry.register_token(def1).unwrap();

        let def2 = make_token_def("Token2", "T2", creator);
        let id2 = registry.register_token(def2).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(*registry.creator_nonces.get(&creator).unwrap(), 2);
    }

    #[test]
    fn test_validate_cross_vm_transfer() {
        let registry = TokenRegistry::new();
        registry
            .register_tnzo(Some([0x01; 20]), Some([0x02; 32]), None)
            .unwrap();

        // Valid transfer
        let transfer = CrossVmTransfer {
            token_id: TokenId::tnzo(),
            from_vm: TokenVmType::Evm,
            to_vm: TokenVmType::Svm,
            from_address: vec![0x01; 20],
            to_address: vec![0x02; 32],
            amount: 1_000_000,
            nonce: 0,
        };
        assert!(registry.validate_cross_vm_transfer(&transfer).is_ok());

        // Zero amount
        let bad_transfer = CrossVmTransfer {
            amount: 0,
            ..transfer.clone()
        };
        assert!(registry.validate_cross_vm_transfer(&bad_transfer).is_err());

        // Non-existent token
        let bad_transfer = CrossVmTransfer {
            token_id: TokenId::new([0xFF; 32]),
            ..transfer
        };
        assert!(registry.validate_cross_vm_transfer(&bad_transfer).is_err());
    }
}
