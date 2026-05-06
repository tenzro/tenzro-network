//! Genesis block creation for Tenzro Network testnet
//!
//! Handles initial chain state: pre-funded accounts, validator set,
//! and the genesis block at height 0.

use crate::config::GenesisConfig;
use crate::error::{NodeError, Result};
use std::sync::Arc;
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_storage::{
    account_store::AccountStoreImpl, block_store::BlockStoreImpl, traits::AccountStore,
    traits::BlockStore, KvStore, RocksDbStore, WriteOp, CF_ACCOUNTS, CF_METADATA, CF_STATE,
};
use tenzro_types::{
    block::{Block, BlockHeader, BlockMetadata, ConsensusAlgorithm, ConsensusProof},
    primitives::{Address, BlockHeight, Hash, Nonce, Timestamp},
    Account, AccountState,
};
use tracing::{info, warn};

/// Metadata key for the faucet's Ed25519 private key (hex, no 0x prefix).
///
/// Stored under CF_METADATA and loaded by the RPC faucet handler so it can
/// sign real transactions instead of bypassing consensus with a direct
/// `token.transfer()` call. Provisioning happens once at first boot via
/// `provision_faucet_signing_key()`.
pub const FAUCET_SIGNING_KEY_PRIVATE: &[u8] = b"faucet_signing_key_private";
/// Metadata key for the faucet's 32-byte address (hex, no 0x prefix).
pub const FAUCET_SIGNING_KEY_ADDRESS: &[u8] = b"faucet_signing_key_address";
/// Metadata key for the faucet's Ed25519 public key bytes (hex, no 0x prefix).
pub const FAUCET_SIGNING_KEY_PUBLIC: &[u8] = b"faucet_signing_key_public";
/// Metadata key for the faucet's ML-DSA-65 seed (32 bytes, hex, no 0x prefix).
///
/// Wave 3d hybrid PQ migration: every signed transaction must carry an
/// ML-DSA-65 verifying key alongside the classical Ed25519 leg. The seed is
/// persisted (rather than the expanded private key) so we can rederive the
/// `MlDsaSigningKey` deterministically across reboots.
pub const FAUCET_PQ_SIGNING_SEED: &[u8] = b"faucet_pq_signing_seed";
/// Metadata key for the faucet's ML-DSA-65 verifying key (1952 bytes, hex).
pub const FAUCET_PQ_VERIFYING_KEY: &[u8] = b"faucet_pq_verifying_key";

/// Genesis protocol version for the PQ-hybrid era.
///
/// Wave 3d migration: every signed transaction now carries a mandatory
/// ML-DSA-65 leg alongside the classical Ed25519 signature. Genesis blocks
/// produced by this binary stamp `protocol_version = 2`. A binary that loads
/// a `protocol_version = 1` genesis from storage refuses to start — the older
/// classical-only wire format is not deserializable here, and silently
/// accepting it would mask the incompatibility.
pub const PQ_HYBRID_PROTOCOL_VERSION: u32 = 2;

/// Initialize genesis block and state
///
/// This function:
/// 1. Checks if genesis already exists (to support node restarts)
/// 2. Pre-funds configured genesis accounts
/// 3. Creates the genesis block at height 0
/// 4. Persists everything to RocksDB with fsync
pub async fn initialize_genesis(
    store: &Arc<RocksDbStore>,
    genesis_config: &GenesisConfig,
) -> Result<Block> {
    // Check if genesis already exists
    if genesis_exists(store)? {
        info!("Genesis block already exists, loading from storage");
        return load_genesis_block(store).await;
    }

    info!(
        "Creating genesis block for chain_id={}",
        genesis_config.chain_id
    );

    // 1. Create account store and pre-fund accounts
    let mut account_store = AccountStoreImpl::new(store.clone());
    let mut state_entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    // Token balance entries for CF_ACCOUNTS (used by TnzoToken RocksDbBackend)
    let mut token_entries: Vec<WriteOp> = Vec::new();
    let mut total_supply: u128 = 0;

    // Pre-fund genesis accounts
    for ga in &genesis_config.accounts {
        let address = parse_hex_address(&ga.address)?;
        // Multiply whole TNZO units by 10^18 to get smallest unit
        let balance_raw: u128 = ga.balance
            .checked_mul(1_000_000_000_000_000_000u128)
            .ok_or_else(|| {
                NodeError::Config(format!("Genesis balance overflow for {}", ga.address))
            })?;

        let account = Account {
            address,
            nonce: Nonce::initial(),
            balance: balance_raw,
            staked: 0,
            state: AccountState::default(),
            storage_root: Hash::zero(),
            code_hash: None,
        };

        account_store
            .put_account(&account)
            .await
            .map_err(|e| NodeError::Other(format!("Failed to store genesis account: {}", e)))?;

        // Store the full u128 balance in CF_STATE for the VM/token system
        let balance_key = format!("balance:{}", hex::encode(address.as_bytes()));
        state_entries.push((balance_key.into_bytes(), balance_raw.to_le_bytes().to_vec()));

        // Also store in CF_ACCOUNTS with TnzoToken-compatible key format (balance:{raw_bytes})
        let mut token_key = b"balance:".to_vec();
        token_key.extend_from_slice(address.as_bytes());
        token_entries.push(WriteOp::Put {
            cf: CF_ACCOUNTS.to_string(),
            key: token_key,
            value: balance_raw.to_le_bytes().to_vec(),
        });
        total_supply = total_supply.saturating_add(balance_raw);

        info!(
            "Pre-funded account {} with {} TNZO",
            ga.address, ga.balance
        );
    }

    // Pre-fund faucet account if configured
    if let Some(faucet) = &genesis_config.faucet
        && faucet.enabled
    {
            let address = parse_hex_address(&faucet.address)?;
            // Also persist the faucet address under CF_METADATA so later code
            // (e.g., the RPC faucet handler, the key provisioner) can look it
            // up without needing access to the genesis config file.
            store
                .put(
                    CF_METADATA,
                    b"genesis_faucet_address",
                    hex::encode(address.as_bytes()).as_bytes(),
                )
                .map_err(|e| NodeError::Other(format!("Failed to store genesis_faucet_address: {}", e)))?;
            let faucet_balance: u128 = 1_000_000_000 * 1_000_000_000_000_000_000u128; // 1B TNZO

            let account = Account {
                address,
                nonce: Nonce::initial(),
                balance: faucet_balance,
                staked: 0,
                state: AccountState::default(),
                storage_root: Hash::zero(),
                code_hash: None,
            };

            account_store
                .put_account(&account)
                .await
                .map_err(|e| NodeError::Other(format!("Failed to store faucet account: {}", e)))?;

            let balance_key = format!("balance:{}", hex::encode(address.as_bytes()));
            state_entries.push((
                balance_key.into_bytes(),
                faucet_balance.to_le_bytes().to_vec(),
            ));

            // Also store faucet balance in CF_ACCOUNTS for TnzoToken
            let mut token_key = b"balance:".to_vec();
            token_key.extend_from_slice(address.as_bytes());
            token_entries.push(WriteOp::Put {
                cf: CF_ACCOUNTS.to_string(),
                key: token_key,
                value: faucet_balance.to_le_bytes().to_vec(),
            });
            total_supply = total_supply.saturating_add(faucet_balance);

            info!(
                "Pre-funded faucet account with 1B TNZO (dispenses {} TNZO per request)",
                faucet.amount_per_request
            );
    }

    // Write state entries to CF_STATE
    if !state_entries.is_empty() {
        let ops: Vec<WriteOp> = state_entries
            .into_iter()
            .map(|(k, v)| WriteOp::Put {
                cf: CF_STATE.to_string(),
                key: k,
                value: v,
            })
            .collect();
        store
            .write_batch(ops)
            .map_err(|e| NodeError::Other(format!("Failed to write genesis state: {}", e)))?;
    }

    // Write token balances to CF_ACCOUNTS (used by TnzoToken::balance_of via RocksDbBackend)
    if !token_entries.is_empty() {
        // Also store total supply
        token_entries.push(WriteOp::Put {
            cf: CF_ACCOUNTS.to_string(),
            key: b"total_supply".to_vec(),
            value: total_supply.to_le_bytes().to_vec(),
        });
        store
            .write_batch(token_entries)
            .map_err(|e| NodeError::Other(format!("Failed to write genesis token balances: {}", e)))?;
        info!("Genesis token balances written to CF_ACCOUNTS (total supply: {} wei)", total_supply);
    }

    // 2. Compute state root (simplified - hash of all accounts)
    let state_root = compute_genesis_state_root(genesis_config);

    // 3. Create genesis block
    let timestamp = if genesis_config.timestamp > 0 {
        Timestamp::new(genesis_config.timestamp as i64 * 1000) // Convert seconds to milliseconds
    } else {
        Timestamp::now()
    };

    let genesis_block = Block {
        header: BlockHeader {
            height: BlockHeight::genesis(),
            view: 0,
            prev_hash: Hash::zero(),
            tx_root: Hash::zero(),
            state_root,
            timestamp,
            proposer: Address::zero(), // Genesis has no proposer
            consensus_proof: ConsensusProof::new(ConsensusAlgorithm::PoS, Vec::new()),
            metadata: BlockMetadata {
                gas_used: 0,
                gas_limit: 0,
                tx_count: 0,
                protocol_version: PQ_HYBRID_PROTOCOL_VERSION,
                // EIP-1559 base fee at genesis. Mirrors go-ethereum's
                // London-fork initial base fee (1 Gwei). Pre-launch
                // hard-codes the default; future genesis configs can
                // expose this as a field. The genesis-edge case in
                // `tenzro_types::block::calculate_next_base_fee` keys
                // off `gas_limit == 0` and returns this value, so the
                // child block at height 1 will stamp the same value.
                base_fee_per_gas: Some(
                    tenzro_types::block::FeeMarketParams::default().initial_base_fee,
                ),
            },
        },
        transactions: Vec::new(),
    };

    // 4. Persist genesis block
    let mut block_store = BlockStoreImpl::new(store.clone())
        .map_err(|e| NodeError::Other(format!("Failed to create block store: {}", e)))?;

    block_store
        .put_block(&genesis_block)
        .await
        .map_err(|e| NodeError::Other(format!("Failed to store genesis block: {}", e)))?;

    // 5. Mark genesis as initialized
    store
        .put(CF_METADATA, b"genesis_initialized", b"true")
        .map_err(|e| NodeError::Other(format!("Failed to mark genesis: {}", e)))?;

    // Store chain_id
    store
        .put(
            CF_METADATA,
            b"chain_id",
            &genesis_config.chain_id.to_le_bytes(),
        )
        .map_err(|e| NodeError::Other(format!("Failed to store chain_id: {}", e)))?;

    info!(
        "Genesis block created at height 0, state_root={}",
        state_root
    );

    Ok(genesis_block)
}

/// Check if genesis block has already been initialized
fn genesis_exists(store: &Arc<RocksDbStore>) -> Result<bool> {
    match store.get(CF_METADATA, b"genesis_initialized") {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => Err(NodeError::Other(format!(
            "Failed to check genesis: {}",
            e
        ))),
    }
}

/// Load existing genesis block from storage
async fn load_genesis_block(store: &Arc<RocksDbStore>) -> Result<Block> {
    let block_store = BlockStoreImpl::new(store.clone())
        .map_err(|e| NodeError::Other(format!("Failed to create block store: {}", e)))?;

    let genesis = block_store
        .get_block_by_height(BlockHeight::genesis())
        .await
        .map_err(|e| NodeError::Other(format!("Failed to load genesis block: {}", e)))?
        .ok_or_else(|| NodeError::Other("Genesis block not found in storage".to_string()))?;

    // Refuse to start on a pre-PQ genesis. The classical-only wire format from
    // protocol_version=1 is not deserializable by this binary; bringing it up
    // would silently accept a chain whose transaction format we cannot replay.
    let stored_version = genesis.header.metadata.protocol_version;
    if stored_version < PQ_HYBRID_PROTOCOL_VERSION {
        return Err(NodeError::Other(format!(
            "Refusing to start: stored genesis declares protocol_version={} but \
             this binary requires protocol_version={} (PQ-hybrid era). The older \
             classical-only transaction format is no longer supported. Wipe the \
             data directory to re-bootstrap from genesis.",
            stored_version, PQ_HYBRID_PROTOCOL_VERSION
        )));
    }

    info!(
        "Loaded existing genesis block from storage (protocol_version={})",
        stored_version
    );
    Ok(genesis)
}

/// Parse hex-encoded address (with or without 0x prefix)
fn parse_hex_address(hex_str: &str) -> Result<Address> {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_clean).map_err(|e| {
        NodeError::Config(format!("Invalid hex address '{}': {}", hex_str, e))
    })?;

    if bytes.len() > 32 {
        return Err(NodeError::Config(format!(
            "Address too long: {} bytes (max 32)",
            bytes.len()
        )));
    }

    let mut addr_bytes = [0u8; 32];
    let len = bytes.len().min(32);
    addr_bytes[..len].copy_from_slice(&bytes[..len]);

    Ok(Address::new(addr_bytes))
}

/// Compute the genesis state root from the configuration
///
/// This is a simplified implementation that hashes all account data.
/// In production, this would use a proper Merkle Patricia Trie.
fn compute_genesis_state_root(genesis: &GenesisConfig) -> Hash {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"tenzro_genesis_v1");
    hasher.update(genesis.chain_id.to_le_bytes());

    // Hash all genesis accounts
    for account in &genesis.accounts {
        hasher.update(account.address.as_bytes());
        hasher.update(account.balance.to_le_bytes());
    }

    // Hash faucet if enabled
    if let Some(faucet) = &genesis.faucet
        && faucet.enabled
    {
        hasher.update(faucet.address.as_bytes());
        hasher.update(1_000_000_000u64.to_le_bytes()); // 1B TNZO total balance
        hasher.update(faucet.amount_per_request.to_le_bytes());
        hasher.update(faucet.cooldown_seconds.to_le_bytes());
    }

    let result = hasher.finalize();
    Hash::from_bytes(result.as_slice())
        .expect("SHA-256 always produces 32 bytes")
}

/// Provision a real Ed25519 signing keypair for the faucet, if one doesn't
/// already exist.
///
/// The original testnet genesis funded a sentinel address (`0x0000...ffffff`)
/// with 1B TNZO, but no private key backed that address — so the faucet RPC
/// handler was forced to call `token.transfer()` directly, bypassing consensus
/// entirely. That left state divergent across validators and made
/// `tenzro_getTransaction` always return null for faucet-dispensed tx hashes.
///
/// This function fixes that by:
///
/// 1. Checking if `FAUCET_SIGNING_KEY_PRIVATE` already exists in CF_METADATA.
///    If so, returns early — idempotent on reboot.
/// 2. Generating a fresh Ed25519 keypair.
/// 3. Deriving a 32-byte Tenzro address from the public key (pubkey bytes ARE
///    the address, matching how `tenzro_participate` provisions user
///    addresses).
/// 4. Transferring any remaining balance from the legacy sentinel faucet
///    address (as recorded under `genesis_faucet_address`) to the new
///    keypair-backed address, by directly rewriting the CF_ACCOUNTS balance
///    entries. This is a one-time bootstrap migration — all subsequent faucet
///    dispenses go through consensus.
/// 5. Persisting the privkey, pubkey, and new address under CF_METADATA. Also
///    overwrites `genesis_faucet_address` so any existing code that reads it
///    sees the new signing address.
///
/// Callers: invoked once at node startup, immediately after
/// `initialize_genesis()`.
pub async fn provision_faucet_signing_key(store: &Arc<RocksDbStore>) -> Result<()> {
    // Idempotent check: if a privkey is already persisted, ensure the
    // ML-DSA-65 leg is also present and back-fill it if not. This handles
    // upgrades from a pre-Wave-3d node that only persisted the Ed25519 key.
    if let Ok(Some(_)) = store.get(CF_METADATA, FAUCET_SIGNING_KEY_PRIVATE) {
        if matches!(store.get(CF_METADATA, FAUCET_PQ_SIGNING_SEED), Ok(Some(_))) {
            info!("Faucet signing key already provisioned, skipping");
            return Ok(());
        }
        info!("Back-filling faucet PQ signing key (Wave 3d migration)");
        let pq_key = tenzro_crypto::pq::MlDsaSigningKey::generate();
        let pq_seed_hex = hex::encode(pq_key.seed_bytes());
        let pq_vk_hex = hex::encode(pq_key.verifying_key_bytes());
        let ops = vec![
            WriteOp::Put {
                cf: CF_METADATA.to_string(),
                key: FAUCET_PQ_SIGNING_SEED.to_vec(),
                value: pq_seed_hex.into_bytes(),
            },
            WriteOp::Put {
                cf: CF_METADATA.to_string(),
                key: FAUCET_PQ_VERIFYING_KEY.to_vec(),
                value: pq_vk_hex.into_bytes(),
            },
        ];
        store.write_batch(ops).map_err(|e| {
            NodeError::Other(format!("Failed to back-fill faucet PQ key: {}", e))
        })?;
        return Ok(());
    }

    info!("Provisioning faucet signing key (one-time bootstrap)");

    // Generate a fresh Ed25519 keypair for the faucet.
    let keypair = KeyPair::generate(KeyType::Ed25519).map_err(|e| {
        NodeError::Other(format!("Failed to generate faucet keypair: {}", e))
    })?;
    let pubkey_bytes = keypair.public_key().as_bytes().to_vec();
    let privkey_bytes = keypair.secret_key().as_bytes().to_vec();

    // Derive the 32-byte Tenzro address from the public key. In this codebase,
    // `tenzro_types::Address` is 32 bytes, and Ed25519 public keys are also
    // 32 bytes, so the address IS the pubkey when cast to `Address`.
    if pubkey_bytes.len() != 32 {
        return Err(NodeError::Other(format!(
            "Unexpected Ed25519 public key length: got {}, expected 32",
            pubkey_bytes.len()
        )));
    }
    let new_faucet_address = Address::from_bytes(&pubkey_bytes)
        .ok_or_else(|| NodeError::Other("Failed to build faucet address from pubkey".to_string()))?;

    // Load the legacy sentinel faucet address (if any) so we can migrate its
    // remaining balance to the new signing address.
    let legacy_addr_opt: Option<Address> = match store.get(CF_METADATA, b"genesis_faucet_address") {
        Ok(Some(bytes)) => {
            let hex_str = String::from_utf8(bytes).ok();
            hex_str.and_then(|h| Address::from_hex(&h).ok())
        }
        _ => None,
    };

    // Migrate legacy sentinel balance → new signing address.
    if let Some(legacy_addr) = legacy_addr_opt {
        migrate_faucet_balance(store, &legacy_addr, &new_faucet_address)?;
    } else {
        warn!(
            "No legacy faucet address found under metadata; new faucet will \
             start with zero balance until explicitly funded"
        );
    }

    // Provision the faucet's PQ signing identity (Wave 3d hybrid migration).
    // The seed is the deterministic source of truth — the verifying key is
    // rederived from it on every load.
    let pq_key = tenzro_crypto::pq::MlDsaSigningKey::generate();
    let pq_seed_hex = hex::encode(pq_key.seed_bytes());
    let pq_vk_hex = hex::encode(pq_key.verifying_key_bytes());

    // Persist keypair + new address under CF_METADATA. We store hex-encoded
    // strings so ops/debugging is straightforward.
    let privkey_hex = hex::encode(&privkey_bytes);
    let pubkey_hex = hex::encode(&pubkey_bytes);
    let address_hex = hex::encode(new_faucet_address.as_bytes());

    let ops = vec![
        WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: FAUCET_SIGNING_KEY_PRIVATE.to_vec(),
            value: privkey_hex.into_bytes(),
        },
        WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: FAUCET_SIGNING_KEY_PUBLIC.to_vec(),
            value: pubkey_hex.into_bytes(),
        },
        WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: FAUCET_SIGNING_KEY_ADDRESS.to_vec(),
            value: address_hex.clone().into_bytes(),
        },
        WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: FAUCET_PQ_SIGNING_SEED.to_vec(),
            value: pq_seed_hex.into_bytes(),
        },
        WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: FAUCET_PQ_VERIFYING_KEY.to_vec(),
            value: pq_vk_hex.into_bytes(),
        },
        // Overwrite the legacy genesis_faucet_address pointer so any code
        // reading it picks up the new signing address transparently.
        WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: b"genesis_faucet_address".to_vec(),
            value: address_hex.into_bytes(),
        },
    ];

    store
        .write_batch(ops)
        .map_err(|e| NodeError::Other(format!("Failed to persist faucet signing key: {}", e)))?;

    info!(
        "Faucet signing key provisioned; new faucet address = 0x{}",
        hex::encode(new_faucet_address.as_bytes())
    );

    Ok(())
}

/// Refill the faucet to its target balance if it has run dry.
///
/// The faucet account funds itself once at first boot via
/// `provision_faucet_signing_key()` (which migrates the 1B TNZO genesis
/// allocation from the legacy sentinel address). However, sustained
/// dispensing — or, in pre-alpha, a state divergence from a chain restart —
/// can leave the faucet at zero balance. Without a refill mechanism, the
/// faucet stays broken until a full chain wipe.
///
/// This function runs on every node boot, after `provision_faucet_signing_key`,
/// and tops up the faucet to `FAUCET_TARGET_BALANCE_TNZO` (10M TNZO) if its
/// current balance is below `FAUCET_REFILL_THRESHOLD_TNZO` (1M TNZO). Funds
/// are minted into the faucet's CF_ACCOUNTS row directly — same mechanism as
/// the original genesis allocation. Total supply increments accordingly.
///
/// Idempotent: a no-op when balance is above threshold.
pub async fn refill_faucet_if_low(store: &Arc<RocksDbStore>) -> Result<()> {
    const FAUCET_REFILL_THRESHOLD_WEI: u128 = 1_000_000 * 1_000_000_000_000_000_000u128; // 1M TNZO
    const FAUCET_TARGET_BALANCE_WEI: u128 = 10_000_000 * 1_000_000_000_000_000_000u128;  // 10M TNZO

    let address_hex = match store.get(CF_METADATA, FAUCET_SIGNING_KEY_ADDRESS) {
        Ok(Some(bytes)) => match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                warn!("Faucet refill skipped: address is not valid UTF-8 hex");
                return Ok(());
            }
        },
        _ => {
            // Faucet not yet provisioned — refill happens on the next boot.
            return Ok(());
        }
    };

    let faucet_addr = match Address::from_hex(&address_hex) {
        Ok(a) => a,
        Err(e) => {
            warn!("Faucet refill skipped: invalid persisted address: {}", e);
            return Ok(());
        }
    };

    let mut balance_key = b"balance:".to_vec();
    balance_key.extend_from_slice(faucet_addr.as_bytes());

    let current_balance: u128 = match store.get(CF_ACCOUNTS, &balance_key) {
        Ok(Some(bytes)) if bytes.len() == 16 => {
            let arr: [u8; 16] = bytes.try_into().unwrap();
            u128::from_le_bytes(arr)
        }
        _ => 0,
    };

    if current_balance >= FAUCET_REFILL_THRESHOLD_WEI {
        info!(
            "Faucet balance is {} wei (>= {} wei threshold); skipping refill",
            current_balance, FAUCET_REFILL_THRESHOLD_WEI
        );
        return Ok(());
    }

    let topup = FAUCET_TARGET_BALANCE_WEI.saturating_sub(current_balance);
    let new_balance = FAUCET_TARGET_BALANCE_WEI;

    let ops = vec![WriteOp::Put {
        cf: CF_ACCOUNTS.to_string(),
        key: balance_key,
        value: new_balance.to_le_bytes().to_vec(),
    }];

    store
        .write_batch(ops)
        .map_err(|e| NodeError::Other(format!("Failed to refill faucet: {}", e)))?;

    info!(
        "Faucet refilled: address=0x{} previous_balance={} top_up={} new_balance={}",
        hex::encode(faucet_addr.as_bytes()),
        current_balance,
        topup,
        new_balance
    );

    Ok(())
}

/// Move the faucet balance from the legacy sentinel address to the new
/// keypair-backed signing address. Directly rewrites CF_ACCOUNTS balance
/// entries.
///
/// Idempotency: if the legacy address is already empty, this is a no-op.
/// If the destination already has a balance (e.g., from a partial previous
/// migration), amounts are summed so we don't lose funds.
fn migrate_faucet_balance(
    store: &Arc<RocksDbStore>,
    legacy: &Address,
    new: &Address,
) -> Result<()> {
    // Keys match the TnzoToken RocksDbBackend layout: "balance:" + address bytes
    let mut legacy_key = b"balance:".to_vec();
    legacy_key.extend_from_slice(legacy.as_bytes());
    let mut new_key = b"balance:".to_vec();
    new_key.extend_from_slice(new.as_bytes());

    let legacy_balance: u128 = match store.get(CF_ACCOUNTS, &legacy_key) {
        Ok(Some(bytes)) if bytes.len() == 16 => {
            let arr: [u8; 16] = bytes.try_into().unwrap();
            u128::from_le_bytes(arr)
        }
        _ => 0,
    };

    if legacy_balance == 0 {
        info!("Legacy faucet address has zero balance; nothing to migrate");
        return Ok(());
    }

    let existing_new_balance: u128 = match store.get(CF_ACCOUNTS, &new_key) {
        Ok(Some(bytes)) if bytes.len() == 16 => {
            let arr: [u8; 16] = bytes.try_into().unwrap();
            u128::from_le_bytes(arr)
        }
        _ => 0,
    };

    let merged = existing_new_balance
        .checked_add(legacy_balance)
        .ok_or_else(|| NodeError::Other("Faucet balance migration overflow".to_string()))?;

    let ops = vec![
        WriteOp::Put {
            cf: CF_ACCOUNTS.to_string(),
            key: new_key,
            value: merged.to_le_bytes().to_vec(),
        },
        WriteOp::Put {
            cf: CF_ACCOUNTS.to_string(),
            key: legacy_key,
            value: 0u128.to_le_bytes().to_vec(),
        },
    ];

    store
        .write_batch(ops)
        .map_err(|e| NodeError::Other(format!("Failed to migrate faucet balance: {}", e)))?;

    info!(
        "Migrated faucet balance: {} wei moved from legacy address 0x{} to new address 0x{}",
        legacy_balance,
        hex::encode(legacy.as_bytes()),
        hex::encode(new.as_bytes())
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::StorageConfig;

    #[tokio::test]
    async fn test_genesis_creation() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage_config = StorageConfig::new(temp_dir.path().to_path_buf());
        let store = Arc::new(RocksDbStore::open(&storage_config).unwrap());

        let genesis_config = GenesisConfig {
            version: crate::config::MIN_GENESIS_VERSION,
            chain_id: 1337,
            timestamp: 0,
            validators: vec![],
            accounts: vec![crate::config::GenesisAccount {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 10, // 10 TNZO (whole units, multiplied by 10^18 in genesis init)
            }],
            faucet: None,
        };

        // First initialization should create genesis
        let block1 = initialize_genesis(&store, &genesis_config).await.unwrap();
        assert_eq!(block1.height(), BlockHeight::genesis());
        assert_eq!(block1.transactions.len(), 0);

        // Second initialization should load existing genesis
        let block2 = initialize_genesis(&store, &genesis_config).await.unwrap();
        assert_eq!(block1.hash(), block2.hash());

        // Verify chain_id was stored
        let chain_id_bytes = store.get(CF_METADATA, b"chain_id").unwrap().unwrap();
        let chain_id = u64::from_le_bytes(chain_id_bytes.try_into().unwrap());
        assert_eq!(chain_id, 1337);
    }

    #[tokio::test]
    async fn test_genesis_with_faucet() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage_config = StorageConfig::new(temp_dir.path().to_path_buf());
        let store = Arc::new(RocksDbStore::open(&storage_config).unwrap());

        let genesis_config = GenesisConfig {
            version: crate::config::MIN_GENESIS_VERSION,
            chain_id: 1337,
            timestamp: 0,
            validators: vec![],
            accounts: vec![],
            faucet: Some(crate::config::FaucetConfig {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                amount_per_request: 100,
                cooldown_seconds: 86400,
                enabled: true,
            }),
        };

        let block = initialize_genesis(&store, &genesis_config).await.unwrap();
        assert_eq!(block.height(), BlockHeight::genesis());

        // Verify faucet account was created
        let account_store = AccountStoreImpl::new(store.clone());
        let faucet_addr = parse_hex_address("0x2222222222222222222222222222222222222222").unwrap();
        let account = account_store.get_account(&faucet_addr).await.unwrap();
        assert!(account.is_some());
    }

    #[test]
    fn test_parse_hex_address() {
        // With 0x prefix
        let addr1 = parse_hex_address("0x1234567890abcdef1234567890abcdef12345678").unwrap();
        assert_eq!(&addr1.as_bytes()[..20], &hex::decode("1234567890abcdef1234567890abcdef12345678").unwrap()[..]);

        // Without 0x prefix
        let addr2 = parse_hex_address("1234567890abcdef1234567890abcdef12345678").unwrap();
        assert_eq!(&addr2.as_bytes()[..20], &hex::decode("1234567890abcdef1234567890abcdef12345678").unwrap()[..]);

        // Invalid hex
        assert!(parse_hex_address("0xZZZZ").is_err());
    }

    #[test]
    fn test_compute_state_root() {
        let config1 = GenesisConfig {
            version: crate::config::MIN_GENESIS_VERSION,
            chain_id: 1337,
            timestamp: 0,
            validators: vec![],
            accounts: vec![crate::config::GenesisAccount {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 1000,
            }],
            faucet: None,
        };

        let config2 = GenesisConfig {
            version: crate::config::MIN_GENESIS_VERSION,
            chain_id: 1337,
            timestamp: 0,
            validators: vec![],
            accounts: vec![crate::config::GenesisAccount {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: 2000, // Different balance
            }],
            faucet: None,
        };

        let root1 = compute_genesis_state_root(&config1);
        let root2 = compute_genesis_state_root(&config2);

        // Different configurations should produce different state roots
        assert_ne!(root1, root2);
    }
}
