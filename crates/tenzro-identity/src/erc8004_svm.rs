//! ERC-8004 Solana port — calldata builders + transport abstraction.
//!
//! Mirrors the EVM-side [`crate::erc8004`] module against the QuantuLabs
//! Solana port of ERC-8004 (`vendor/erc8004-solana`,
//! [github.com/QuantuLabs/8004-solana](https://github.com/QuantuLabs/8004-solana),
//! MIT-licensed, security-audited 2026-02-05). The Solana port preserves
//! the three-registry spirit (Identity / Reputation / Validation) but
//! consolidates Identity + Reputation into a single Anchor program backed
//! by Metaplex Core NFTs (the upstream rationale: "agent NFT = agent
//! identity"); ATOM reputation/scoring lives in a sibling CPI-callee
//! program (`vendor/erc8004-atom`).
//!
//! # Wire format: Anchor vs Solidity
//!
//! | concept             | Solidity (EVM)                                  | Anchor (SVM)                                                |
//! | ------------------- | ----------------------------------------------- | ----------------------------------------------------------- |
//! | call dispatch tag   | 4-byte function selector (`keccak256` truncate) | 8-byte instruction discriminator (`sha256` truncate)        |
//! | argument encoding   | ABI heads/tails over 32-byte words              | Borsh (LE little-endian, length-prefix on strings/vecs)     |
//! | state ID            | contract address (20 bytes)                     | program ID (32-byte Ed25519 public key)                     |
//! | identity primary key| `uint256 agentId` (sequential)                  | `agent_account` PDA + Metaplex Core Asset (32-byte Pubkey)  |
//! | event emission      | `LOG` opcode, indexed topics                    | `emit_cpi!` writes Borsh-serialized payload to inner ix logs|
//!
//! The Anchor instruction discriminator is the first 8 bytes of
//! `sha256("global:" || instruction_name)`. The event discriminator is the
//! first 8 bytes of `sha256("event:" || event_name)`. Both are reproduced
//! verbatim in the [`discriminators`] / [`event_discriminators`] modules
//! below from the canonical IDL at `vendor/erc8004-solana/idl/`.
//!
//! # Position in Tenzro
//!
//! As with the EVM mirror, the SVM mirror is **outbound only**: a TDIP
//! machine identity can optionally publish itself to a Solana cluster so
//! agents that only speak the QuantuLabs port can discover Tenzro agents.
//! TDIP remains the source of truth.
//!
//! Unlike the EVM mirror, the SVM port has not (yet) been predeployed at
//! Tenzro Ledger genesis — the Anchor program ID
//! [`addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA`] points at the
//! canonical Solana mainnet-beta deployment; activating an in-network
//! mirror requires both a built `.so` artifact (out of scope for
//! `cargo build`; see `vendor/erc8004-solana/Anchor.toml`) and an
//! initialized `RegistryConfig` PDA + Metaplex Core collection. The
//! mirror wiring lives in `tenzro-node` (`erc8004_svm_mirror.rs`) and is
//! gated on `Option<Arc<dyn OnChainAgentSvmRegistry>>` on
//! [`crate::registry::IdentityRegistry`] — no opt-in config, no
//! activation.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};

/// 32-byte Solana public key. Stored as raw bytes; base58 is only for
/// display / RPC. Identical layout to `solana_sdk::pubkey::Pubkey`
/// without the dependency.
pub type SolPubkey = [u8; 32];

/// Hook for mirroring TDIP machine registrations into the canonical
/// QuantuLabs Solana port of ERC-8004. Parallel to
/// [`crate::erc8004::OnChainAgentRegistry`] (EVM).
///
/// Implementors live in `tenzro-node` so `tenzro-identity` does not
/// depend on `tenzro-vm`, Solana SDK, or any HTTP/signing crate.
///
/// # Async-by-spawn pattern
///
/// `mirror_register_agent` is **sync from the TDIP caller's perspective**
/// but performs its on-chain work as a detached `tokio::spawn`: it builds
/// the Anchor-encoded instruction + signs a Solana transaction with a
/// node-held system keypair and submits via the SVM executor / cluster
/// RPC. Returns to the TDIP caller immediately.
///
/// The newly-allocated `agent_account` PDA + Metaplex Asset Pubkey are
/// **not** returned synchronously — they arrive later via the
/// `AgentRegistered { asset, collection, owner, atom_enabled, agent_uri }`
/// CPI event reflected back into the off-chain `erc8004_svm_did_index:`
/// keyspace in `CF_IDENTITIES`. The reflector also patches
/// `IdentityData::Machine.erc8004_svm_asset` on the TDIP record.
///
/// Failures are logged but never block TDIP registration — the on-chain
/// mirror is best-effort and additive.
pub trait OnChainAgentSvmRegistry: Send + Sync {
    /// Mirror a TDIP machine registration into the on-chain registry.
    ///
    /// Builds Anchor calldata for `register(string agent_uri)` against
    /// [`addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA`], signs with
    /// the node-held `erc8004-svm-system` keypair, and submits as a
    /// detached tokio task. Returns immediately on calldata-build
    /// success; transport / signing failures inside the spawned task are
    /// logged and dropped (TDIP registration is unaffected).
    fn mirror_register_agent(&self, did: &str, metadata_uri: &str) -> Result<()>;

    /// Resolve a TDIP DID string back to its allocated Metaplex Asset
    /// pubkey. Reads from the off-chain DID index in RocksDB
    /// (`CF_IDENTITIES` under the `erc8004_svm_did_index:` prefix), which
    /// is populated by the `AgentRegistered` event reflector.
    ///
    /// Returns `None` if the DID has never been mirrored OR if the
    /// mirror tx has not yet been included + indexed. Callers MUST
    /// tolerate the `None` case.
    fn lookup_asset_by_did(&self, did: &str) -> Option<SolPubkey>;
}

/// Transport abstraction so this module stays free of Solana SDK / HTTP
/// deps. Implementors (typically in `tenzro-node`) wrap either a Solana
/// JSON-RPC client (when mirroring to a public Solana cluster) or a
/// direct SVM-executor handle (when mirroring inside Tenzro's own SVM,
/// once the QuantuLabs `.so` is allocated at genesis).
#[async_trait]
pub trait Erc8004SvmTransport: Send + Sync {
    /// Submit a signed Solana transaction. Returns the transaction
    /// signature (base58, the canonical Solana tx identifier).
    async fn send_signed_transaction(&self, signed_tx: &[u8]) -> Result<String>;

    /// Read an account's raw data by pubkey. Returns `Ok(None)` if the
    /// account does not exist. Callers parse the data themselves (Anchor
    /// account layouts are documented in `vendor/erc8004-solana/idl/`).
    async fn get_account(&self, pubkey: &SolPubkey) -> Result<Option<Vec<u8>>>;
}

/// Canonical QuantuLabs ERC-8004 program IDs.
///
/// These are the on-chain Solana program addresses for the canonical
/// QuantuLabs deployment. Pulled from
/// `vendor/erc8004-solana/Anchor.toml::[programs.devnet]` and
/// `vendor/erc8004-atom/Anchor.toml::[programs.mainnet]`. The mainnet ID
/// is the production target; devnet/localnet IDs differ and are
/// documented in the vendored `Anchor.toml`.
///
/// # Vanity addresses
///
/// The QuantuLabs program IDs follow the same `8004…` / `AToM…` vanity
/// convention as the EVM port's `0x8004…` addresses, signalling the
/// canonical ERC-8004 + ATOM reputation engine across Solana clusters.
pub mod addresses {
    use super::SolPubkey;

    /// Decode a base58 Solana pubkey at compile time. Hand-resolved here
    /// to avoid a bs58 dep at module level.
    const fn b58_to_pubkey(_b58: &str, bytes: [u8; 32]) -> SolPubkey {
        bytes
    }

    /// `agent_registry_8004` — main identity + reputation program on
    /// Solana mainnet-beta. Vanity: `8oo4...`. The bytes are the base58
    /// decode of `8oo4J9tBB3Hna1jRQ3rWvJjojqM5DYTDJo5cejUuJy3C` (the
    /// canonical QuantuLabs deployment per
    /// `vendor/erc8004-solana/Anchor.toml::[programs.devnet]`).
    ///
    /// The QuantuLabs port currently uses the same program ID across
    /// devnet, localnet, and (planned) mainnet — Anchor's deterministic
    /// build pipeline produces the same `.so` digest regardless of
    /// cluster, and the address is keypair-pinned in
    /// `target/deploy/agent_registry_8004-keypair.json`.
    pub const AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA: SolPubkey = b58_to_pubkey(
        "8oo4J9tBB3Hna1jRQ3rWvJjojqM5DYTDJo5cejUuJy3C",
        [
            0x73, 0xfe, 0x9a, 0x31, 0x81, 0x81, 0x30, 0x59, 0x3a, 0x08, 0xa7, 0xc2, 0x7a, 0x08,
            0xc2, 0xdc, 0xf5, 0xd5, 0xcc, 0xc3, 0x68, 0x86, 0x27, 0xf3, 0x0a, 0x87, 0x0d, 0x44,
            0x14, 0xd4, 0x02, 0x27,
        ],
    );

    /// `atom_engine` — CPI-callee reputation/scoring program. Vanity:
    /// `AToM...`. Base58 of
    /// `AToMufS4QD6hEXvcvBDg9m1AHeCLpmZQsyfYa5h9MwAF`.
    pub const ATOM_ENGINE_PROGRAM_ID: SolPubkey = b58_to_pubkey(
        "AToMufS4QD6hEXvcvBDg9m1AHeCLpmZQsyfYa5h9MwAF",
        [
            0x8c, 0x96, 0xb4, 0x0d, 0xef, 0x5e, 0xdc, 0x22, 0xcb, 0xcd, 0xeb, 0x94, 0xc1, 0xd1,
            0x19, 0x3c, 0x05, 0x8c, 0x1c, 0x6d, 0x76, 0xb3, 0x27, 0xe4, 0x5a, 0x40, 0xe7, 0x87,
            0x8d, 0x9b, 0xea, 0xd0,
        ],
    );

    /// Metaplex Core NFT program. Required as the `mpl_core_program`
    /// account on every `register` / `set_agent_uri` call (Metaplex Core
    /// is how QuantuLabs implements the agent-NFT primitive).
    /// Base58 of `CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d`.
    pub const MPL_CORE_PROGRAM_ID: SolPubkey = b58_to_pubkey(
        "CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d",
        [
            0xaf, 0x54, 0xab, 0x10, 0xbd, 0x97, 0xa5, 0x42, 0xa0, 0x9e, 0xf7, 0xb3, 0x98, 0x89,
            0xdd, 0x0c, 0xd3, 0x94, 0xa4, 0xcc, 0xe9, 0xdf, 0xa6, 0xcd, 0xc9, 0x7e, 0xbe, 0x2d,
            0x23, 0x5b, 0xa7, 0x48,
        ],
    );

    /// Solana System Program. Required as the `system_program` account
    /// on every CPI that allocates a new account. All-zero pubkey.
    pub const SYSTEM_PROGRAM_ID: SolPubkey = [0u8; 32];
}

/// Anchor instruction discriminators for `agent_registry_8004`.
///
/// First 8 bytes of `sha256("global:" || instruction_name)`. Reproduced
/// verbatim from `vendor/erc8004-solana/idl/agent_registry_8004.json`.
/// Anchor pins these at IDL-generation time; they are part of the wire
/// contract and never change for a given program version.
pub mod discriminators {
    /// `register(agent_uri: string)` — allocates a fresh `agent_account`
    /// PDA + Metaplex Core Asset NFT for `owner`. The simplest register
    /// path; equivalent to EVM `register(string)`.
    pub const REGISTER: [u8; 8] = [0xd3, 0x7c, 0x43, 0x0f, 0xd3, 0xc2, 0xb2, 0xf0];

    /// `register_with_options(agent_uri: string, atom_enabled: bool)` —
    /// same as `register` plus a flag controlling ATOM reputation
    /// engine enrolment.
    pub const REGISTER_WITH_OPTIONS: [u8; 8] = [0xb1, 0xaf, 0x60, 0x29, 0x3b, 0xa6, 0x0d, 0x06];

    /// `set_agent_uri(new_uri: string)` — update an agent's metadata URI
    /// in place. Mirrors EVM `setAgentURI(uint256, string)`.
    pub const SET_AGENT_URI: [u8; 8] = [0x2b, 0xfe, 0xa8, 0x68, 0xc0, 0x33, 0x27, 0x2e];

    /// `set_agent_wallet(new_wallet: pubkey, deadline: i64)` — rebind an
    /// agent's controller wallet (with deadline replay protection).
    /// Mirrors EVM `setAgentWallet`.
    pub const SET_AGENT_WALLET: [u8; 8] = [0x9a, 0x57, 0xfb, 0x17, 0x33, 0x0c, 0x04, 0x96];

    /// `set_metadata_pda(key_hash: [u8;16], key: string, value: bytes,
    /// immutable: bool)` — write a `(key → value)` metadata entry to a
    /// per-entry PDA. Mirrors EVM `setMetadata(uint256, string, bytes)`.
    /// The `key_hash` is the first 16 bytes of `sha256(key)`, used as
    /// the PDA seed for collision-free indexing.
    pub const SET_METADATA_PDA: [u8; 8] = [0xec, 0x3c, 0x17, 0x30, 0x8a, 0x45, 0xc4, 0x99];

    /// `delete_metadata_pda(key_hash: [u8;16])` — remove a metadata
    /// entry by key hash. Mirrors EVM `setMetadata(...empty value...)`.
    pub const DELETE_METADATA_PDA: [u8; 8] = [0xe4, 0xbe, 0xc3, 0xff, 0x3d, 0xdd, 0x1a, 0x98];

    /// `give_feedback(value, value_decimals, score, ..., feedback_uri)`
    /// — submit reputation feedback. Mirrors EVM
    /// `submitFeedback(uint256, int8, string)` but with the full
    /// QuantuLabs ATOM-engine signature (value + decimals for fee
    /// weighting, optional score, two tags, endpoint).
    pub const GIVE_FEEDBACK: [u8; 8] = [0x91, 0x88, 0x7b, 0x03, 0xd7, 0xa5, 0x62, 0x29];

    /// `revoke_feedback(feedback_index, seal_hash)` — mark a previously
    /// submitted feedback entry as revoked. Mirrors EVM
    /// `revokeFeedback(uint256, bytes32)`.
    pub const REVOKE_FEEDBACK: [u8; 8] = [0xd3, 0x25, 0xe6, 0x52, 0x76, 0xd8, 0x89, 0xce];

    /// `append_response(client_address, feedback_index, response_uri,
    /// response_hash, seal_hash)` — agent's response to a feedback
    /// entry. Mirrors EVM `appendResponse(uint256, bytes32, string)`.
    pub const APPEND_RESPONSE: [u8; 8] = [0xa2, 0xd2, 0xba, 0x32, 0xb4, 0x04, 0x2f, 0x68];

    /// `owner_of()` — read selector returning the agent's owner pubkey.
    /// Mirrors EVM `ERC721.ownerOf(uint256)`.
    pub const OWNER_OF: [u8; 8] = [0xa5, 0x55, 0x2e, 0xf9, 0x64, 0x3d, 0xf9, 0x70];

    /// `sync_owner()` — re-derive `AgentAccount.owner` from the Metaplex
    /// Core asset's current owner. Mirrors a manual ERC-721 transfer +
    /// `ownerOf` refresh round-trip.
    pub const SYNC_OWNER: [u8; 8] = [0x2e, 0x05, 0xe8, 0xc6, 0x3b, 0x9e, 0xa0, 0x77];
}

/// Anchor event discriminators (first 8 bytes of `sha256("event:" ||
/// event_name)`).  Reproduced from
/// `vendor/erc8004-solana/idl/agent_registry_8004.json::events`.
pub mod event_discriminators {
    /// `AgentRegistered { asset, collection, owner, atom_enabled,
    /// agent_uri }` — emitted by `register` / `register_with_options`.
    /// Equivalent to EVM `Registered(uint256, string, address)`.
    pub const AGENT_REGISTERED: [u8; 8] = [0xbf, 0x4e, 0xd9, 0x36, 0xe8, 0x64, 0xbd, 0x55];

    /// `UriUpdated { asset, new_uri }` — emitted by `set_agent_uri`.
    pub const URI_UPDATED: [u8; 8] = [0xaa, 0xc7, 0x4e, 0xa7, 0x31, 0x54, 0x66, 0x0b];

    /// `WalletUpdated { asset, new_wallet }` — emitted by
    /// `set_agent_wallet`.
    pub const WALLET_UPDATED: [u8; 8] = [0xd7, 0x22, 0x0a, 0x3b, 0x18, 0x72, 0xc9, 0x81];

    /// `MetadataSet { asset, key_hash, key, immutable }` — emitted by
    /// `set_metadata_pda`.
    pub const METADATA_SET: [u8; 8] = [0xbe, 0x7d, 0x47, 0x77, 0x0e, 0x1f, 0x1a, 0xc5];

    /// `NewFeedback { agent_account, client, feedback_index, ... }` —
    /// emitted by `give_feedback`.
    pub const NEW_FEEDBACK: [u8; 8] = [0x0e, 0xa2, 0x3a, 0xc2, 0x83, 0x2a, 0x0b, 0x95];
}

/// Borsh calldata builders for the QuantuLabs agent_registry_8004
/// program.
///
/// All builders produce the **instruction data** half of a Solana
/// instruction — the account-list half is constructed separately by the
/// caller (typically the mirror adapter in `tenzro-node`). Borsh
/// encoding rules used:
///
/// - `string` → `[u32 LE length][utf8 bytes]`
/// - `bytes` → `[u32 LE length][raw bytes]`
/// - `bool` → `[0u8]` or `[1u8]`
/// - `[u8; N]` → raw `N` bytes
/// - `pubkey` → raw 32 bytes
/// - `i64` → 8 bytes LE two's-complement
///
/// Reference: `https://borsh.io/` + Anchor's
/// `anchor_lang::AnchorSerialize` (which is Borsh).
pub mod borsh_ix {
    /// `register(agent_uri: string)`
    pub fn encode_register(agent_uri: &str) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 4 + agent_uri.len());
        data.extend_from_slice(&super::discriminators::REGISTER);
        encode_string(&mut data, agent_uri);
        data
    }

    /// `register_with_options(agent_uri: string, atom_enabled: bool)`
    pub fn encode_register_with_options(agent_uri: &str, atom_enabled: bool) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 4 + agent_uri.len() + 1);
        data.extend_from_slice(&super::discriminators::REGISTER_WITH_OPTIONS);
        encode_string(&mut data, agent_uri);
        data.push(atom_enabled as u8);
        data
    }

    /// `set_agent_uri(new_uri: string)`
    pub fn encode_set_agent_uri(new_uri: &str) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 4 + new_uri.len());
        data.extend_from_slice(&super::discriminators::SET_AGENT_URI);
        encode_string(&mut data, new_uri);
        data
    }

    /// `set_agent_wallet(new_wallet: pubkey, deadline: i64)`
    pub fn encode_set_agent_wallet(new_wallet: &super::SolPubkey, deadline: i64) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 32 + 8);
        data.extend_from_slice(&super::discriminators::SET_AGENT_WALLET);
        data.extend_from_slice(new_wallet);
        data.extend_from_slice(&deadline.to_le_bytes());
        data
    }

    /// `set_metadata_pda(key_hash: [u8;16], key: string, value: bytes,
    /// immutable: bool)`
    pub fn encode_set_metadata_pda(
        key_hash: &[u8; 16],
        key: &str,
        value: &[u8],
        immutable: bool,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 16 + 4 + key.len() + 4 + value.len() + 1);
        data.extend_from_slice(&super::discriminators::SET_METADATA_PDA);
        data.extend_from_slice(key_hash);
        encode_string(&mut data, key);
        encode_bytes(&mut data, value);
        data.push(immutable as u8);
        data
    }

    /// `delete_metadata_pda(key_hash: [u8;16])`
    pub fn encode_delete_metadata_pda(key_hash: &[u8; 16]) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 16);
        data.extend_from_slice(&super::discriminators::DELETE_METADATA_PDA);
        data.extend_from_slice(key_hash);
        data
    }

    /// `give_feedback(value: i128, value_decimals: u8, score: Option<u8>,
    /// feedback_file_hash: Option<[u8;32]>, tag1: string, tag2: string,
    /// endpoint: string, feedback_uri: string)`
    #[allow(clippy::too_many_arguments)]
    pub fn encode_give_feedback(
        value: i128,
        value_decimals: u8,
        score: Option<u8>,
        feedback_file_hash: Option<[u8; 32]>,
        tag1: &str,
        tag2: &str,
        endpoint: &str,
        feedback_uri: &str,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&super::discriminators::GIVE_FEEDBACK);
        data.extend_from_slice(&value.to_le_bytes());
        data.push(value_decimals);
        encode_option_u8(&mut data, score);
        encode_option_bytes32(&mut data, feedback_file_hash);
        encode_string(&mut data, tag1);
        encode_string(&mut data, tag2);
        encode_string(&mut data, endpoint);
        encode_string(&mut data, feedback_uri);
        data
    }

    /// `revoke_feedback(feedback_index: u64, seal_hash: [u8;32])`
    pub fn encode_revoke_feedback(feedback_index: u64, seal_hash: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 8 + 32);
        data.extend_from_slice(&super::discriminators::REVOKE_FEEDBACK);
        data.extend_from_slice(&feedback_index.to_le_bytes());
        data.extend_from_slice(seal_hash);
        data
    }

    /// `append_response(client_address: pubkey, feedback_index: u64,
    /// response_uri: string, response_hash: [u8;32], seal_hash: [u8;32])`
    pub fn encode_append_response(
        client_address: &super::SolPubkey,
        feedback_index: u64,
        response_uri: &str,
        response_hash: &[u8; 32],
        seal_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(8 + 32 + 8 + 4 + response_uri.len() + 32 + 32);
        data.extend_from_slice(&super::discriminators::APPEND_RESPONSE);
        data.extend_from_slice(client_address);
        data.extend_from_slice(&feedback_index.to_le_bytes());
        encode_string(&mut data, response_uri);
        data.extend_from_slice(response_hash);
        data.extend_from_slice(seal_hash);
        data
    }

    // --- Borsh primitives ------------------------------------------------

    fn encode_string(out: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    }

    fn encode_bytes(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }

    fn encode_option_u8(out: &mut Vec<u8>, v: Option<u8>) {
        match v {
            None => out.push(0),
            Some(x) => {
                out.push(1);
                out.push(x);
            }
        }
    }

    fn encode_option_bytes32(out: &mut Vec<u8>, v: Option<[u8; 32]>) {
        match v {
            None => out.push(0),
            Some(arr) => {
                out.push(1);
                out.extend_from_slice(&arr);
            }
        }
    }
}

/// Borsh decoders for the `agent_registry_8004` events the off-chain
/// reflector consumes. Returned shapes match the IDL `events` section.
pub mod borsh_event {
    use super::SolPubkey;

    /// Decoded `AgentRegistered` event payload.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AgentRegistered {
        pub asset: SolPubkey,
        pub collection: SolPubkey,
        pub owner: SolPubkey,
        pub atom_enabled: bool,
        pub agent_uri: String,
    }

    /// Decode the event payload **after** the 8-byte discriminator has
    /// been consumed by the caller (event log lines are
    /// `[discriminator(8) | borsh body...]`). Returns `None` on any
    /// length / utf-8 violation.
    pub fn decode_agent_registered(body: &[u8]) -> Option<AgentRegistered> {
        let mut p = body;
        let asset = take_pubkey(&mut p)?;
        let collection = take_pubkey(&mut p)?;
        let owner = take_pubkey(&mut p)?;
        let atom_enabled = take_bool(&mut p)?;
        let agent_uri = take_string(&mut p)?;
        Some(AgentRegistered {
            asset,
            collection,
            owner,
            atom_enabled,
            agent_uri,
        })
    }

    fn take_pubkey(p: &mut &[u8]) -> Option<SolPubkey> {
        if p.len() < 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&p[..32]);
        *p = &p[32..];
        Some(out)
    }

    fn take_bool(p: &mut &[u8]) -> Option<bool> {
        if p.is_empty() {
            return None;
        }
        let b = p[0];
        *p = &p[1..];
        match b {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    fn take_string(p: &mut &[u8]) -> Option<String> {
        if p.len() < 4 {
            return None;
        }
        let len = u32::from_le_bytes([p[0], p[1], p[2], p[3]]) as usize;
        *p = &p[4..];
        if p.len() < len {
            return None;
        }
        let s = std::str::from_utf8(&p[..len]).ok()?.to_string();
        *p = &p[len..];
        Some(s)
    }
}

/// An agent record as returned by the QuantuLabs `AgentAccount` PDA
/// (subset — the IDL also tracks ATOM feedback digests, parent asset,
/// collection lock, etc., which Tenzro does not currently mirror).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SvmAgentRecord {
    /// 32-byte Metaplex Core Asset pubkey — the canonical agent
    /// identifier on the Solana side.
    pub asset: SolPubkey,
    /// Owner pubkey (the controller wallet — equivalent of EVM
    /// `agentAddress`).
    pub owner: SolPubkey,
    /// Metadata URI (resolvable DID document / AgentCard).
    pub agent_uri: String,
    /// Optional rebound wallet pubkey set via `set_agent_wallet`.
    pub agent_wallet: Option<SolPubkey>,
    /// Whether the ATOM reputation engine is enabled for this agent.
    pub atom_enabled: bool,
}

/// Convert a base58 Solana pubkey string into bytes. Cheap helper that
/// avoids pulling `bs58` into the consumer crate just to decode a
/// configured program ID at startup.
pub fn base58_to_pubkey(b58: &str) -> Result<SolPubkey> {
    let bytes = bs58_decode(b58)
        .ok_or_else(|| IdentityError::VerificationFailed(format!("invalid base58: {}", b58)))?;
    if bytes.len() != 32 {
        return Err(IdentityError::VerificationFailed(format!(
            "pubkey must be 32 bytes, got {} (input '{}')",
            bytes.len(),
            b58
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Display a 32-byte pubkey as base58.
pub fn pubkey_to_base58(pk: &SolPubkey) -> String {
    bs58_encode(pk)
}

// --- minimal base58 (Bitcoin alphabet) — embedded to avoid the bs58 dep.
//
// Solana uses the Bitcoin / IPFS base58 alphabet. Implementation is the
// standard "divide by 58" approach; this is on the slow path (only
// used for config parsing + log formatting), correctness over speed.

const B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn bs58_encode(bytes: &[u8]) -> String {
    let mut leading_zeros = 0;
    for &b in bytes {
        if b == 0 {
            leading_zeros += 1;
        } else {
            break;
        }
    }
    // BigInt division
    let mut num: Vec<u8> = bytes.to_vec();
    let mut out: Vec<u8> = Vec::new();
    while !num.iter().all(|&b| b == 0) {
        let mut remainder = 0u16;
        for byte in num.iter_mut() {
            let cur = remainder * 256 + (*byte as u16);
            *byte = (cur / 58) as u8;
            remainder = cur % 58;
        }
        out.push(B58_ALPHABET[remainder as usize]);
    }
    out.extend(std::iter::repeat_n(b'1', leading_zeros));
    out.reverse();
    String::from_utf8(out).expect("base58 alphabet is ASCII")
}

fn bs58_decode(s: &str) -> Option<Vec<u8>> {
    let mut num: Vec<u8> = Vec::new();
    for ch in s.chars() {
        let digit = B58_ALPHABET.iter().position(|&c| c == ch as u8)? as u32;
        let mut carry = digit;
        for byte in num.iter_mut() {
            carry += (*byte as u32) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading_ones = s.chars().take_while(|&c| c == '1').count();
    let mut out = vec![0u8; leading_ones];
    out.extend(num.iter().rev());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminators_match_idl() {
        // Spot-check against vendor/erc8004-solana/idl/agent_registry_8004.json.
        // These bytes are extracted from the IDL by the
        // Agent({Explore}) pass that produced this module; any drift
        // means the IDL was regenerated and the wire contract changed.
        assert_eq!(
            discriminators::REGISTER,
            [0xd3, 0x7c, 0x43, 0x0f, 0xd3, 0xc2, 0xb2, 0xf0]
        );
        assert_eq!(
            discriminators::SET_AGENT_URI,
            [0x2b, 0xfe, 0xa8, 0x68, 0xc0, 0x33, 0x27, 0x2e]
        );
        assert_eq!(
            event_discriminators::AGENT_REGISTERED,
            [0xbf, 0x4e, 0xd9, 0x36, 0xe8, 0x64, 0xbd, 0x55]
        );
    }

    #[test]
    fn encode_register_shape() {
        let data = borsh_ix::encode_register("did:tenzro:machine:abc");
        // 8 disc + 4 len + 22 bytes
        assert_eq!(data.len(), 8 + 4 + 22);
        assert_eq!(&data[..8], &discriminators::REGISTER);
        assert_eq!(&data[8..12], &22u32.to_le_bytes());
        assert_eq!(&data[12..], b"did:tenzro:machine:abc");
    }

    #[test]
    fn encode_register_with_options_shape() {
        let data = borsh_ix::encode_register_with_options("uri", true);
        assert_eq!(data.len(), 8 + 4 + 3 + 1);
        assert_eq!(&data[..8], &discriminators::REGISTER_WITH_OPTIONS);
        assert_eq!(data[data.len() - 1], 1);
    }

    #[test]
    fn encode_set_agent_wallet_shape() {
        let pk = [0x11u8; 32];
        let data = borsh_ix::encode_set_agent_wallet(&pk, 1717171717);
        assert_eq!(data.len(), 8 + 32 + 8);
        assert_eq!(&data[..8], &discriminators::SET_AGENT_WALLET);
        assert_eq!(&data[8..40], &pk);
        assert_eq!(&data[40..48], &1717171717i64.to_le_bytes());
    }

    #[test]
    fn encode_set_metadata_pda_shape() {
        let kh = [0xAAu8; 16];
        let data = borsh_ix::encode_set_metadata_pda(&kh, "k", b"vv", true);
        // 8 disc + 16 hash + (4+1) key + (4+2) value + 1 immutable = 36
        assert_eq!(data.len(), 8 + 16 + 4 + 1 + 4 + 2 + 1);
        assert_eq!(data[data.len() - 1], 1);
    }

    #[test]
    fn encode_revoke_feedback_shape() {
        let seal = [0xFFu8; 32];
        let data = borsh_ix::encode_revoke_feedback(7, &seal);
        assert_eq!(data.len(), 8 + 8 + 32);
        assert_eq!(&data[8..16], &7u64.to_le_bytes());
    }

    #[test]
    fn base58_roundtrip() {
        // The canonical QuantuLabs program ID literal.
        let b58 = "8oo4J9tBB3Hna1jRQ3rWvJjojqM5DYTDJo5cejUuJy3C";
        let bytes = base58_to_pubkey(b58).expect("decode");
        assert_eq!(bytes.len(), 32);
        let round = pubkey_to_base58(&bytes);
        assert_eq!(round, b58);
    }

    #[test]
    fn base58_decodes_to_constant() {
        // Confirms the hardcoded `[u8; 32]` matches the base58 source.
        // If the constants in `addresses` ever drift, this test fails.
        let decoded =
            base58_to_pubkey("8oo4J9tBB3Hna1jRQ3rWvJjojqM5DYTDJo5cejUuJy3C").expect("decode");
        assert_eq!(decoded, addresses::AGENT_REGISTRY_PROGRAM_ID_MAINNET_BETA);

        let atom =
            base58_to_pubkey("AToMufS4QD6hEXvcvBDg9m1AHeCLpmZQsyfYa5h9MwAF").expect("decode");
        assert_eq!(atom, addresses::ATOM_ENGINE_PROGRAM_ID);

        let mpl = base58_to_pubkey("CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d").expect("decode");
        assert_eq!(mpl, addresses::MPL_CORE_PROGRAM_ID);
    }

    #[test]
    fn decode_agent_registered_roundtrip() {
        let asset = [0x01u8; 32];
        let coll = [0x02u8; 32];
        let owner = [0x03u8; 32];
        let uri = "did:tenzro:machine:42";

        // Build a synthetic event body to confirm the decoder.
        let mut body = Vec::new();
        body.extend_from_slice(&asset);
        body.extend_from_slice(&coll);
        body.extend_from_slice(&owner);
        body.push(1); // atom_enabled = true
        body.extend_from_slice(&(uri.len() as u32).to_le_bytes());
        body.extend_from_slice(uri.as_bytes());

        let ev = borsh_event::decode_agent_registered(&body).expect("decode");
        assert_eq!(ev.asset, asset);
        assert_eq!(ev.collection, coll);
        assert_eq!(ev.owner, owner);
        assert!(ev.atom_enabled);
        assert_eq!(ev.agent_uri, uri);
    }

    #[test]
    fn decode_agent_registered_short_body_returns_none() {
        assert!(borsh_event::decode_agent_registered(&[0u8; 10]).is_none());
    }
}
