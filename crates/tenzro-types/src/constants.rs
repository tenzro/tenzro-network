//! Chain constants and parameters for Tenzro Network
//!
//! This module defines immutable constants that govern the behavior
//! of the Tenzro Network blockchain.

/// The native token symbol
pub const TOKEN_SYMBOL: &str = "TNZO";

/// The native token name
pub const TOKEN_NAME: &str = "Tenzro Network Token";

/// Number of decimal places for TNZO token
pub const TOKEN_DECIMALS: u8 = 18;

/// Total supply of TNZO tokens (1 billion with 18 decimals)
pub const TOKEN_TOTAL_SUPPLY: u128 = 1_000_000_000 * 10u128.pow(TOKEN_DECIMALS as u32);

/// Mainnet chain ID
pub const MAINNET_CHAIN_ID: u64 = 1;

/// Testnet chain ID
pub const TESTNET_CHAIN_ID: u64 = 1337;

/// Maximum block size in bytes (1 MB)
pub const MAX_BLOCK_SIZE: u64 = 1024 * 1024;

/// Target block time in milliseconds (2 seconds)
pub const BLOCK_TIME_MS: u64 = 2000;

/// Maximum transactions per block
pub const MAX_TRANSACTIONS_PER_BLOCK: u32 = 1000;

/// Minimum gas price in smallest TNZO unit
pub const MIN_GAS_PRICE: u64 = 1;

/// Maximum gas per block
pub const MAX_GAS_PER_BLOCK: u64 = 30_000_000;

/// Maximum gas per transaction
pub const MAX_GAS_PER_TRANSACTION: u64 = 10_000_000;

/// Base transaction gas cost
pub const BASE_TRANSACTION_GAS: u64 = 21_000;

/// Gas cost per byte of transaction data
pub const GAS_PER_BYTE: u64 = 68;

/// One whole TNZO in the smallest unit.
pub const ONE_TNZO: u128 = 10u128.pow(TOKEN_DECIMALS as u32);

// ---------------------------------------------------------------------------
// Provider bonds
//
// Two shapes live here. Roles that grant a *protocol privilege* — producing
// blocks, serving RPC to tenants, attesting inside an enclave — carry a flat
// bond, because the thing being collateralised is the privilege itself and it
// does not come in units. Roles that sell *capacity* — accelerators, disk,
// hosted services — scale with the capacity actually pledged, so a laptop
// pledging one integrated GPU is not asked for the same bond as a rack of
// datacentre cards.
//
// The absolute numbers are calibrated against comparable networks as a
// fraction of total supply rather than in nominal tokens, since nominal
// amounts say nothing across chains with different supplies. A flat bond at
// 0.001% of supply sits between Polkadot's validator self-stake and NEAR's
// floor; the per-accelerator base sits in the same band as Phala's per-GPU
// bond and a small multiple of io.net's per-chip entry.
// ---------------------------------------------------------------------------

/// Validator bond (10,000 TNZO, 0.001% of supply).
pub const MIN_VALIDATOR_STAKE: u128 = 10_000 * ONE_TNZO;

/// RPC operator bond (100,000 TNZO, 0.01% of supply).
///
/// Ten times the validator bond, and the highest rung on the ladder, because
/// this bond is not only collateral: it is routing weight and it is the right
/// to mint tenant API keys against the operator's own credentials. An operator
/// that carries other people's traffic and issues their access has more to
/// answer for than one that only signs blocks.
pub const MIN_RPC_OPERATOR_STAKE: u128 = 100_000 * ONE_TNZO;

/// Edge operator bond (10,000 TNZO, as a validator's). An edge operator
/// serves the relay every node may connect through, published at the URL
/// its bond names; the bond is what keeps relay supply from being free to
/// flood with relays that answer nothing.
pub const MIN_EDGE_OPERATOR_STAKE: u128 = 10_000 * ONE_TNZO;

/// Minimum bond of a rail attestor, which confirms that a settlement plan's
/// bank, card or ISO 20022 leg was paid. It vouches for value it moved off
/// any chain, so it carries the same bond as an RPC operator.
pub const MIN_ATTESTOR_STAKE: u128 = 100_000 * ONE_TNZO;

/// Minimum bond of a wallet provider. It backs the provider's claim to serve
/// passkey wallets on the domain it declared; it moves no one's value, so it
/// sits with the model provider rather than the RPC operator.
pub const MIN_WALLET_PROVIDER_STAKE: u128 = 1_000 * ONE_TNZO;

/// Minimum bond of a catalog publisher. It answers for every catalog entry
/// the publisher signs; an upheld catalog fault takes a share of it.
pub const MIN_CATALOG_PUBLISHER_STAKE: u128 = 1_000 * ONE_TNZO;

/// Confidential compute bond (10,000 TNZO, 0.001% of supply).
///
/// Priced level with the validator bond rather than with the other capacity
/// roles: a TEE provider's output is an attestation that relying parties act
/// on without being able to re-derive it, so the bond stands behind a claim
/// nobody else can check independently.
pub const MIN_TEE_PROVIDER_STAKE: u128 = 10_000 * ONE_TNZO;

/// Model provider bond (1,000 TNZO, 0.0001% of supply).
///
/// Flat rather than per-model: serving weights is bounded by the memory the
/// machine already has, and the budget screen already stops an operator
/// pledging more models than fit.
pub const MIN_MODEL_PROVIDER_STAKE: u128 = 1_000 * ONE_TNZO;

/// Bond per pledged accelerator at consumer-discrete class, before the class
/// multiplier (1,000 TNZO).
pub const COMPUTE_STAKE_PER_ACCELERATOR: u128 = 1_000 * ONE_TNZO;

/// Floor for a compute-rental bond (500 TNZO) — one integrated accelerator.
pub const MIN_COMPUTE_PROVIDER_STAKE: u128 = 500 * ONE_TNZO;

/// Bond per whole terabyte pledged (100 TNZO).
///
/// At ten terabytes this reaches 1,000 TNZO, which is where a flat storage
/// bond would otherwise have sat. Below that it decays to something a laptop
/// operator with spare disk can actually post.
pub const STORAGE_STAKE_PER_TB: u128 = 100 * ONE_TNZO;

/// Floor for a storage bond (100 TNZO) — any pledge under one terabyte.
pub const MIN_STORAGE_PROVIDER_STAKE: u128 = 100 * ONE_TNZO;

/// Refundable deposit posted with a marketplace bid or quote (5 TNZO).
///
/// Sybil resistance on order flow belongs here rather than in the role bond.
/// Pricing spam into the bond would raise the cost of honest onboarding to
/// solve a problem that only appears at bid time; a deposit that comes back on
/// settlement costs an honest bidder nothing.
pub const MARKETPLACE_BID_DEPOSIT: u128 = 5 * ONE_TNZO;

/// Maximum validators in the active set
pub const MAX_VALIDATORS: u32 = 100;

/// Address length in bytes
pub const ADDRESS_LENGTH: usize = 32;

/// Hash length in bytes
pub const HASH_LENGTH: usize = 32;

/// Maximum memo size in bytes
pub const MAX_MEMO_SIZE: usize = 256;

/// Maximum contract code size in bytes (1 MB)
pub const MAX_CONTRACT_CODE_SIZE: usize = 1024 * 1024;

/// Maximum storage size per account (100 MB)
pub const MAX_STORAGE_SIZE_PER_ACCOUNT: u64 = 100 * 1024 * 1024;

/// Bridge minimum transfer amount (10 TNZO)
pub const BRIDGE_MIN_TRANSFER: u128 = 10 * 10u128.pow(TOKEN_DECIMALS as u32);

/// Bridge confirmation blocks required
pub const BRIDGE_CONFIRMATION_BLOCKS: u32 = 12;

/// Maximum agent execution time in milliseconds (60 seconds)
pub const MAX_AGENT_EXECUTION_TIME_MS: u64 = 60_000;

/// Maximum agent memory in bytes (1 GB)
pub const MAX_AGENT_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;

/// Maximum agent API calls per execution
pub const MAX_AGENT_API_CALLS: u32 = 100;

/// Maximum model context window (tokens)
pub const MAX_MODEL_CONTEXT_WINDOW: u32 = 128_000;

/// Maximum model output tokens
pub const MAX_MODEL_OUTPUT_TOKENS: u32 = 4_096;

/// Default model inference timeout in milliseconds (5 minutes)
pub const DEFAULT_INFERENCE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

/// TEE attestation validity period in milliseconds (30 days)
pub const TEE_ATTESTATION_VALIDITY_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Settlement timeout in milliseconds (1 hour)
pub const SETTLEMENT_TIMEOUT_MS: i64 = 60 * 60 * 1000;

/// Maximum peer connections
pub const MAX_PEER_CONNECTIONS: u32 = 75;

/// Peer reputation decay interval in milliseconds (1 day)
pub const PEER_REPUTATION_DECAY_INTERVAL_MS: i64 = 24 * 60 * 60 * 1000;

/// Protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Network magic bytes for mainnet
pub const MAINNET_MAGIC: [u8; 4] = [0x54, 0x4E, 0x5A, 0x4F]; // "TNZO"

/// Network magic bytes for testnet
pub const TESTNET_MAGIC: [u8; 4] = [0x54, 0x54, 0x5A, 0x4F]; // "TTZO"

/// Genesis block timestamp (placeholder - should be set to actual launch)
pub const GENESIS_TIMESTAMP: i64 = 1700000000000; // Nov 14, 2023 22:13:20 GMT

// ---------------------------------------------------------------------------
// Deserialization bounds (for HIGH #69 — protect against OOM via untrusted
// vectors received over RPC, P2P, or storage formats)
// ---------------------------------------------------------------------------

/// Maximum number of transactions accepted in a single deserialized block
pub const MAX_DESERIALIZED_TX_COUNT: usize = MAX_TRANSACTIONS_PER_BLOCK as usize;

/// Maximum length of a deserialized signature byte vector
pub const MAX_SIGNATURE_BYTES: usize = 256;

/// Maximum length of a deserialized public key byte vector
pub const MAX_PUBLIC_KEY_BYTES: usize = 256;

/// Maximum number of validator entries in a deserialized validator set
pub const MAX_DESERIALIZED_VALIDATOR_COUNT: usize = MAX_VALIDATORS as usize * 4;

/// Maximum number of peers in a deserialized peer list
pub const MAX_DESERIALIZED_PEER_COUNT: usize = MAX_PEER_CONNECTIONS as usize * 4;

/// Maximum number of bytes in a single deserialized vector field of unknown content
pub const MAX_DESERIALIZED_BYTES: usize = 16 * 1024 * 1024; // 16 MB

/// Maximum length of a deserialized free-form string (URLs, names, descriptions)
pub const MAX_DESERIALIZED_STRING_LEN: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Chain ID validation
// ---------------------------------------------------------------------------

/// Minimum allowed chain ID (0 is reserved/invalid)
pub const CHAIN_ID_MIN: u64 = 1;

/// Maximum allowed chain ID — matches EIP-2294 recommendation
/// (`floor(MAX_UINT64 / 2) - 36`) to avoid overflow when combined with EIP-155.
pub const CHAIN_ID_MAX: u64 = (u64::MAX / 2) - 36;

/// Genesis file schema version.
///
/// A genesis whose `version` is not exactly this is refused rather than
/// migrated: a node that read an older genesis leniently would build a
/// different chain from one that refused it, and the two would only find out
/// at the first block they disagreed on.
///
/// Here rather than in the node's config because the CLI writes genesis files
/// and the node reads them, and a constant that means "these two agree" cannot
/// live inside one of them.
pub const GENESIS_SCHEMA_VERSION: u32 = 1;

/// Gas the VM charges for bond transactions.
///
/// The VM charges these and the CLI sends them as gas limits, so they live
/// here where both read them. When each kept its own copy they drifted: the
/// CLI sent withdrawals and finalizations short of what the VM charged, and
/// every one of them failed.
pub mod bond_gas {
    /// `PostAgentBond`: writes the bond record and emits a log.
    pub const AGENT_BOND_POST: u64 = 80_000;
    /// `IncreaseAgentBond`.
    pub const AGENT_BOND_INCREASE: u64 = 50_000;
    /// `WithdrawAgentBond`.
    pub const AGENT_BOND_WITHDRAW: u64 = 60_000;
    /// `PostComputeBond`: same shape and state footprint as an agent bond.
    pub const COMPUTE_BOND_POST: u64 = 80_000;
    /// `IncreaseComputeBond`.
    pub const COMPUTE_BOND_INCREASE: u64 = 50_000;
    /// `WithdrawComputeBond`.
    pub const COMPUTE_BOND_WITHDRAW: u64 = 60_000;
    /// `FinalizeComputeBondWithdrawal`: one balance write more than a
    /// withdrawal, moving the vault back to the provider.
    pub const COMPUTE_BOND_FINALIZE: u64 = 70_000;
}
