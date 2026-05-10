//! ERC-8004 — Trustless Agents Identity / Reputation / Validation registry adapter.
//!
//! [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) defines a three-contract
//! architecture deployed to Ethereum for cross-vendor trustless agent identity:
//!
//! 1. **IdentityRegistry** — assigns each agent a sequentially-allocated
//!    `uint256 agentId` (ERC-721 tokenId semantics) and binds it to an
//!    on-chain controller address plus a metadata URI (resolvable DID
//!    document, AgentCard, etc.).
//! 2. **ReputationRegistry** — records cross-agent feedback (rating +
//!    context URI) so off-chain reputation services can aggregate.
//! 3. **ValidationRegistry** — lets a requester anchor a work hash and
//!    a validator countersign an approval or rejection with a proof URI
//!    (ZK proof CID, TEE attestation CID, etc.).
//!
//! # Position in Tenzro
//!
//! Tenzro uses TDIP as its native identity protocol. ERC-8004 is an
//! *outbound bridge*: a TDIP machine identity can optionally publish
//! itself to Ethereum so agents that only speak ERC-8004 can discover
//! and validate Tenzro agents. The mapping is:
//!
//! | TDIP | ERC-8004 |
//! | --- | --- |
//! | `TenzroIdentity::did_string()` | `agentId` (sequential `uint256` allocated on register) |
//! | Wallet binding address | `agentAddress` |
//! | DID document URL | `metadataUri` (returned by `getAgent`/`tokenURI`) |
//! | `VerifiableCredential` (attestation) | `ValidationRegistry.validationResponse()` |
//!
//! The reverse mapping `did → agentId` is held in the on-chain
//! IdentityRegistry by the [`OnChainAgentRegistry::lookup_agent_id_by_did`]
//! hook, so callers (settlement, reputation dispatcher, RPC) never need
//! to compute it themselves.
//!
//! # Transport abstraction
//!
//! The adapter is split into *calldata builders* (pure, no I/O) and an
//! `Erc8004Transport` trait. `tenzro-identity` stays dependency-light;
//! the node crate wires a real HTTP JSON-RPC transport at startup.
//!
//! # Deployed addresses
//!
//! ERC-8004 reference contracts are published on Ethereum mainnet by
//! the EIP authors. Consumers pass the concrete address to
//! [`Erc8004Addresses`]; the adapter is not pinned to any specific
//! deployment.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};

/// 20-byte Ethereum address. Stored big-endian, lowercased on display.
pub type EthAddress = [u8; 20];

/// Addresses of the three ERC-8004 registries for a given deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc8004Addresses {
    pub identity_registry: EthAddress,
    pub reputation_registry: EthAddress,
    pub validation_registry: EthAddress,
}

/// Transport abstraction so this module stays free of HTTP deps.
///
/// Implementors (typically in `tenzro-node`) should wrap a JSON-RPC
/// client that speaks Ethereum's `eth_call` and `eth_sendRawTransaction`.
#[async_trait]
pub trait Erc8004Transport: Send + Sync {
    /// Execute an `eth_call` against `to` with `data`. Returns the raw
    /// ABI-encoded return bytes (stripped of the `0x` prefix).
    async fn eth_call(&self, to: &EthAddress, data: &[u8]) -> Result<Vec<u8>>;

    /// Submit a signed raw transaction. Returns the transaction hash.
    async fn eth_send_raw(&self, signed_tx: &[u8]) -> Result<String>;
}

/// Hook for mirroring TDIP machine registrations into a native ERC-8004
/// IdentityRegistry — typically the Tenzro precompile at `0x101a`, but
/// any conforming registry works (e.g., a Solidity deployment on
/// Ethereum, or a test harness).
///
/// Implementors live in `tenzro-node` so `tenzro-identity` does not depend
/// on `tenzro-vm`. The TDIP `IdentityRegistry` calls
/// [`OnChainAgentRegistry::mirror_register_agent`] inside
/// `register_machine_with_fee` and `register_autonomous_machine_with_fee`
/// so every machine identity is discoverable via `getAgent(uint256)` on
/// the precompile without an explicit second user step.
///
/// Failures are logged but never block TDIP registration — the on-chain
/// mirror is best-effort and additive.
pub trait OnChainAgentRegistry: Send + Sync {
    /// Mirror a TDIP machine registration into the on-chain registry.
    ///
    /// The registry allocates a fresh sequential `uint256 agentId`, binds
    /// it to the supplied controller `agent_address` and `metadata_uri`,
    /// records the reverse `did → agentId` mapping, and returns the new
    /// id so the caller can persist it on the TDIP identity record.
    fn mirror_register_agent(
        &self,
        did: &str,
        agent_address: &EthAddress,
        metadata_uri: &str,
    ) -> Result<u64>;

    /// Resolve a TDIP DID string back to its allocated ERC-8004
    /// `agentId`. Returns `None` if the DID has never been mirrored.
    fn lookup_agent_id_by_did(&self, did: &str) -> Option<u64>;
}

/// ERC-8004 canonical function selectors.
///
/// Selectors are the first 4 bytes of `keccak256(canonical_signature)`.
///
/// These selectors MUST stay byte-identical to the EVM precompile
/// constants in `crates/tenzro-vm/src/evm/erc8004.rs` so that the same
/// calldata works against either the native Tenzro precompile (at
/// `0x101a` / `0x101b` / `0x101c`) or an external Solidity deployment
/// of the reference ERC-8004 contracts.
pub mod selectors {
    // -- IdentityRegistry (0x101a) --

    /// `register()` — ERC-8004 register overload that allocates a fresh
    /// `agentId` for `msg.sender` with no URI and no metadata entries.
    pub const REGISTER: [u8; 4] = [0x1a, 0xa3, 0xa0, 0x08];
    /// `register(string)` — ERC-8004 register overload that allocates a
    /// fresh `agentId` for `msg.sender` and binds the supplied
    /// `agentURI` (resolvable DID document / AgentCard pointer).
    pub const REGISTER_WITH_URI: [u8; 4] = [0xf2, 0xc2, 0x98, 0xbe];
    /// `register(string,(string,bytes)[])` — ERC-8004 register overload
    /// that allocates a fresh `agentId`, binds the `agentURI`, and
    /// atomically writes a batch of `(metadataKey, metadataValue)`
    /// entries. Empty values delete; identical to a sequence of
    /// `setMetadata` calls but cheaper and atomic.
    pub const REGISTER_WITH_METADATA: [u8; 4] = [0x8e, 0xa4, 0x22, 0x86];
    /// `getAgent(uint256)` — ERC-8004 read returning
    /// `(address controller, string metadataUri)` for an agent id.
    pub const GET_AGENT: [u8; 4] = [0x2d, 0xe5, 0xaa, 0xf7];
    /// `setAgentURI(uint256,string)` — ERC-8004 v0.6+ selector for
    /// updating an agent's metadata URI in place.
    pub const SET_AGENT_URI: [u8; 4] = [0x0a, 0xf2, 0x8b, 0xd3];
    /// `setAgentWallet(uint256,address,uint256,bytes)` — ERC-8004 v0.6+
    /// selector for rebinding an agent's controller wallet, with the
    /// reference contract's `(deadline, signature)` consent pair.
    pub const SET_AGENT_WALLET: [u8; 4] = [0x2d, 0x1e, 0xf5, 0xae];
    /// `unsetAgentWallet(uint256)` — ERC-8004 v0.6+ selector for
    /// clearing an agent's controller wallet binding (sets it to the
    /// zero address). Used when retiring or rotating an agent.
    pub const UNSET_AGENT_WALLET: [u8; 4] = [0x3f, 0xdd, 0xcf, 0x19];
    /// `setMetadata(uint256,string,bytes)` — ERC-8004 v0.6+ selector for
    /// writing a `(key → value)` metadata entry. Empty `value` deletes.
    pub const SET_METADATA: [u8; 4] = [0x46, 0x66, 0x48, 0xda];
    /// `getMetadata(uint256,string)` — ERC-8004 v0.6+ selector for
    /// reading the bytes stored at `(agentId, metadataKey)`.
    pub const GET_METADATA: [u8; 4] = [0xcb, 0x47, 0x99, 0xf2];
    /// `getAgentURI(uint256)` — ERC-8004 v0.6+ read selector returning
    /// the metadata URI bound to an agent. Splits out from `getAgent` so
    /// callers that only need the URI avoid decoding the full
    /// `(address, string)` tuple.
    pub const GET_AGENT_URI: [u8; 4] = [0xce, 0x91, 0xae, 0xde];
    /// `getAgentWallet(uint256)` — ERC-8004 v0.6+ read selector returning
    /// the controller wallet bound to an agent. Splits out from
    /// `getAgent` for the same reason: callers that only need the
    /// address skip the dynamic-string decode path.
    pub const GET_AGENT_WALLET: [u8; 4] = [0x00, 0x33, 0x95, 0x09];

    // -- ReputationRegistry (0x101b) --

    /// `submitFeedback(uint256,int8,string)` — submit a feedback rating
    /// against a subject agent identified by its sequential `uint256`
    /// `agentId`.
    pub const SUBMIT_FEEDBACK: [u8; 4] = [0xe5, 0x67, 0x9c, 0x29];
    /// `getFeedback(uint256,uint256)` — read selector for indexed lookup
    /// of a single feedback entry against `(subject_agent_id, index)`.
    pub const GET_FEEDBACK: [u8; 4] = [0x2d, 0x15, 0x04, 0x57];
    /// `getFeedbackCount(uint256)` — read selector returning the number
    /// of feedback entries recorded against a subject agent.
    pub const GET_FEEDBACK_COUNT: [u8; 4] = [0x45, 0x37, 0xb7, 0x64];
    /// `revokeFeedback(uint256,bytes32)` — ERC-8004 v0.6+ mutator. Marks
    /// a previously-submitted feedback entry as withdrawn by its rater.
    /// Idempotent on the wire: a second call against an already-revoked
    /// entry returns `false`.
    pub const REVOKE_FEEDBACK: [u8; 4] = [0xa2, 0x83, 0x34, 0xce];
    /// `appendResponse(uint256,bytes32,string)` — ERC-8004 v0.6+
    /// mutator. Lets the rated agent attach (or replace) a response URI
    /// on a feedback entry. "Latest response wins" — repeated calls
    /// overwrite the previous URI rather than appending to a list.
    pub const APPEND_RESPONSE: [u8; 4] = [0x60, 0x1f, 0x56, 0x76];
    /// `isFeedbackRevoked(uint256,bytes32)` — ERC-8004 v0.6+ read
    /// selector returning whether a `(agentId, feedbackId)` entry is in
    /// the revoked state. Unknown entries return `false` (i.e. an
    /// unsubmitted feedback is not revoked, it simply doesn't exist).
    pub const IS_FEEDBACK_REVOKED: [u8; 4] = [0xb0, 0x17, 0xcb, 0x04];
    /// `getFeedbackResponses(uint256,bytes32)` — ERC-8004 v0.6+ read
    /// selector returning the response URI most recently attached via
    /// `appendResponse`. Returns the empty string when no response has
    /// landed (or when the entry is unknown).
    pub const GET_FEEDBACK_RESPONSES: [u8; 4] = [0xcc, 0x84, 0x63, 0x3b];

    // -- ValidationRegistry (0x101c) --

    /// `validationRequest(address,uint256,string,bytes32)` per ERC-8004.
    /// The validator address is the on-chain account expected to
    /// countersign; `agentId` (uint256) names the subject; `requestURI`
    /// points at the work being attested to; `requestHash` is the
    /// 32-byte commitment a validator must reproduce.
    ///
    /// Selector = `bytes4(keccak256("validationRequest(address,uint256,string,bytes32)"))`
    /// = `0xaaf400c4`.
    pub const VALIDATION_REQUEST: [u8; 4] = [0xaa, 0xf4, 0x00, 0xc4];

    /// `validationResponse(bytes32,uint8,string,bytes32,string)` per ERC-8004.
    /// `requestHash` selects the request being answered; `response` is a
    /// 0..=100 quality score; `responseURI` carries proof material;
    /// `responseHash` is a commitment over that material; `tag` is a
    /// short categorical label (e.g. "valid", "invalid", "abstain").
    ///
    /// Selector = `bytes4(keccak256("validationResponse(bytes32,uint8,string,bytes32,string)"))`
    /// = `0x3d659a96`.
    pub const VALIDATION_RESPONSE: [u8; 4] = [0x3d, 0x65, 0x9a, 0x96];

    /// `getValidation(bytes32)` — read selector returning the
    /// `ValidationResult` recorded against a `requestHash`. This is a
    /// Tenzro-side convenience read; the canonical ERC-8004 contract
    /// emits events instead, but our precompile retains a getter for
    /// off-chain indexers.
    pub const GET_VALIDATION: [u8; 4] = [0xa8, 0x09, 0x1f, 0xc3];
}

/// An ERC-8004 agent record as returned by `getAgent(uint256)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRecord {
    /// Sequentially-allocated `uint256` agent id (held as a `u64` for
    /// the in-process registry; widened to a 32-byte big-endian word at
    /// the EVM precompile boundary).
    pub agent_id: u64,
    pub agent_address: EthAddress,
    pub metadata_uri: String,
}

/// A `(metadataKey, metadataValue)` pair as accepted by the
/// `register(string,(string,bytes)[])` overload and the `setMetadata`
/// mutator. An empty `metadata_value` deletes any existing entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataEntry {
    pub metadata_key: String,
    pub metadata_value: Vec<u8>,
}

/// Feedback entry submitted via the reputation registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    /// Sequential `uint256` agentId of the rated subject.
    pub subject_agent_id: u64,
    /// -100..=100, higher is better. Clamped on-chain.
    pub rating: i8,
    pub context_uri: String,
}

/// A validation request lifecycle object, modeling
/// `validationRequest(address,uint256,string,bytes32)` per ERC-8004.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRequest {
    /// Validator account expected to respond.
    pub validator_address: EthAddress,
    /// Sequential `uint256` agentId of the subject.
    pub agent_id: u64,
    /// Resolvable pointer to the work being validated.
    pub request_uri: String,
    /// 32-byte commitment over the work; used as the storage key for
    /// looking up the matching response.
    pub request_hash: [u8; 32],
}

/// The result a validator submits for a validation request, modeling
/// `validationResponse(bytes32,uint8,string,bytes32,string)` per ERC-8004.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// `requestHash` of the corresponding request.
    pub request_hash: [u8; 32],
    /// Quality score in `0..=100`. The canonical ERC-8004 leaves the
    /// semantics open; Tenzro recommends `0..=49 = invalid`,
    /// `50..=79 = partial`, `80..=100 = valid`.
    pub response: u8,
    /// Pointer at proof material (ZK proof CID, TEE quote CID, etc.).
    pub response_uri: String,
    /// 32-byte commitment over the response payload.
    pub response_hash: [u8; 32],
    /// Short categorical label (e.g. `"valid"`, `"invalid"`, `"abstain"`).
    pub tag: String,
}

/// Encode a `u64` Tenzro-internal agent id as a 32-byte big-endian
/// `uint256` word, matching the ERC-8004 wire shape.
pub fn agent_id_to_uint256_be(agent_id: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&agent_id.to_be_bytes());
    out
}

/// Decode a 32-byte big-endian `uint256` agentId word back to `u64`.
/// Returns `None` if the high 192 bits are non-zero — the registry
/// allocates agentIds sequentially as `u64`, so any wider value is
/// either silent truncation (a bug) or a foreign id we cannot service.
pub fn agent_id_from_uint256_be(word: &[u8; 32]) -> Option<u64> {
    if word[..24].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(word[24..32].try_into().ok()?))
}

/// Minimal ABI encoder for the handful of ERC-8004 function shapes we
/// need. Not a general-purpose ABI encoder — just enough to build
/// calldata for the three `register` overloads, `submitFeedback`,
/// `validationRequest`, and `validationResponse`.
pub mod abi {
    use super::{EthAddress, MetadataEntry};

    /// Pad `value` to 32 bytes, left-padded with zeros (big-endian).
    fn pad32_left(value: &[u8]) -> [u8; 32] {
        assert!(value.len() <= 32);
        let mut out = [0u8; 32];
        out[32 - value.len()..].copy_from_slice(value);
        out
    }

    /// Encode a dynamic bytes / string: head = offset, tail = length +
    /// padded data.
    fn encode_bytes_tail(bytes: &[u8]) -> Vec<u8> {
        let len = bytes.len();
        let mut out = Vec::with_capacity(32 + len.div_ceil(32) * 32);
        out.extend_from_slice(&pad32_left(&(len as u64).to_be_bytes()));
        out.extend_from_slice(bytes);
        // Right-pad to 32-byte boundary.
        let pad = (32 - (len % 32)) % 32;
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    /// Pack a `u64` agent id into a 32-byte big-endian `uint256` word.
    fn agent_id_word(agent_id: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&agent_id.to_be_bytes());
        out
    }

    /// `register()` — ERC-8004 register overload that allocates a fresh
    /// `agentId` for `msg.sender` with no URI and no metadata. Calldata
    /// is just the selector — no arguments.
    pub fn encode_register(selector: [u8; 4]) -> Vec<u8> {
        selector.to_vec()
    }

    /// `register(string agentURI)` — ERC-8004 register overload that
    /// allocates a fresh `agentId` and binds the supplied metadata URI.
    ///
    /// Head: `[offset-to-uri (=32)]`, tail: `[length | utf8-padded]`.
    pub fn encode_register_with_uri(selector: [u8; 4], agent_uri: &str) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32 + 32 + agent_uri.len().div_ceil(32) * 32);
        data.extend_from_slice(&selector);
        // offset-to-uri = 32 (single head slot)
        data.extend_from_slice(&pad32_left(&(32u64).to_be_bytes()));
        data.extend_from_slice(&encode_bytes_tail(agent_uri.as_bytes()));
        data
    }

    /// `register(string agentURI, (string,bytes)[] metadata)` —
    /// ERC-8004 register overload that allocates a fresh `agentId`,
    /// binds the URI, and atomically writes a batch of metadata entries.
    ///
    /// Head: `[offset-to-uri (=64) | offset-to-metadata-array]`. The
    /// metadata-array offset is `64 + (32 + ceil(uri_len/32)*32)`. The
    /// metadata array itself is encoded as `[length | encoded entries]`
    /// where the entries form a self-contained dynamic-tuple array
    /// (each entry is a `(string,bytes)` tuple, both fields dynamic).
    pub fn encode_register_with_metadata(
        selector: [u8; 4],
        agent_uri: &str,
        metadata: &[MetadataEntry],
    ) -> Vec<u8> {
        let uri_block_len = 32 + agent_uri.len().div_ceil(32) * 32;
        let metadata_offset = 64 + uri_block_len;

        // Encode the metadata array body relative to its own start
        // (Solidity convention for `T[]` of dynamic tuples: offsets
        // inside the array body are measured from the body start, i.e.
        // immediately after the length word).
        let metadata_body = encode_metadata_array_body(metadata);

        let mut data =
            Vec::with_capacity(4 + 64 + uri_block_len + 32 + metadata_body.len());
        data.extend_from_slice(&selector);
        // offset-to-uri = 64 (two head slots)
        data.extend_from_slice(&pad32_left(&(64u64).to_be_bytes()));
        // offset-to-metadata = 64 + uri block
        data.extend_from_slice(&pad32_left(&(metadata_offset as u64).to_be_bytes()));
        // URI tail
        data.extend_from_slice(&encode_bytes_tail(agent_uri.as_bytes()));
        // Metadata array length word + body
        data.extend_from_slice(&pad32_left(&(metadata.len() as u64).to_be_bytes()));
        data.extend_from_slice(&metadata_body);
        data
    }

    /// Encode a `(string,bytes)[]` array body (offsets-from-body-start)
    /// suitable for splicing in after the array length word.
    ///
    /// Layout: first `N` words are offsets to each tuple, where
    /// `offsets[i]` measures bytes from the start of the body to the
    /// start of tuple `i`. Each tuple is a `(string, bytes)` pair
    /// encoded as `[offset_string=64 | offset_bytes | string_tail | bytes_tail]`.
    fn encode_metadata_array_body(metadata: &[MetadataEntry]) -> Vec<u8> {
        let n = metadata.len();
        // Encode each tuple to its own buffer first, then assemble
        // offsets pointing at the concatenation.
        let tuples: Vec<Vec<u8>> = metadata.iter().map(encode_metadata_tuple).collect();
        let offsets_block_len = n * 32;
        let mut offsets = Vec::with_capacity(offsets_block_len);
        let mut running = offsets_block_len;
        for tuple in &tuples {
            offsets.extend_from_slice(&pad32_left(&(running as u64).to_be_bytes()));
            running += tuple.len();
        }
        let mut out = Vec::with_capacity(running);
        out.extend_from_slice(&offsets);
        for tuple in &tuples {
            out.extend_from_slice(tuple);
        }
        out
    }

    /// Encode a single `(string metadataKey, bytes metadataValue)` tuple
    /// as a self-contained block: head (2 × 32) + key tail + value tail.
    fn encode_metadata_tuple(entry: &MetadataEntry) -> Vec<u8> {
        let key_block_len = 32 + entry.metadata_key.len().div_ceil(32) * 32;
        let value_block_len = 32 + entry.metadata_value.len().div_ceil(32) * 32;
        let mut out = Vec::with_capacity(64 + key_block_len + value_block_len);
        // head[0] = offset to string field = 64 (two head slots)
        out.extend_from_slice(&pad32_left(&(64u64).to_be_bytes()));
        // head[1] = offset to bytes field = 64 + key_block_len
        out.extend_from_slice(&pad32_left(&((64 + key_block_len) as u64).to_be_bytes()));
        out.extend_from_slice(&encode_bytes_tail(entry.metadata_key.as_bytes()));
        out.extend_from_slice(&encode_bytes_tail(&entry.metadata_value));
        out
    }

    /// `getAgent(uint256)`
    pub fn encode_get_agent(selector: [u8; 4], agent_id: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data
    }

    /// `unsetAgentWallet(uint256)` — clear an agent's controller wallet.
    pub fn encode_unset_agent_wallet(selector: [u8; 4], agent_id: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data
    }

    /// `submitFeedback(uint256 agentId, int8 rating, string contextUri)`
    ///
    /// `int8` encodes as 32-byte two's complement. For the small
    /// negative values (-128..=-1) we sign-extend with 0xff.
    pub fn encode_submit_feedback(
        selector: [u8; 4],
        subject_agent_id: u64,
        rating: i8,
        context_uri: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 3 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(subject_agent_id));

        let mut rating_word = [0u8; 32];
        let sign_ext = if rating < 0 { 0xffu8 } else { 0u8 };
        for byte in rating_word.iter_mut().take(31) {
            *byte = sign_ext;
        }
        rating_word[31] = rating as u8;
        data.extend_from_slice(&rating_word);

        data.extend_from_slice(&pad32_left(&(96u64).to_be_bytes()));
        data.extend_from_slice(&encode_bytes_tail(context_uri.as_bytes()));
        data
    }

    /// `validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)`
    /// per ERC-8004.
    ///
    /// Head: `[validator (32-padded) | agent_id (32B) | offset-to-uri | request_hash (32B)]`
    /// = 4 × 32 = 128 bytes. The string tail follows at offset 128.
    pub fn encode_validation_request(
        selector: [u8; 4],
        validator_address: &EthAddress,
        agent_id: u64,
        request_uri: &str,
        request_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 4 * 32 + request_uri.len().div_ceil(32) * 32 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&pad32_left(validator_address));
        data.extend_from_slice(&agent_id_word(agent_id));
        // offset = 4 head slots × 32 = 128
        data.extend_from_slice(&pad32_left(&(128u64).to_be_bytes()));
        data.extend_from_slice(request_hash);
        data.extend_from_slice(&encode_bytes_tail(request_uri.as_bytes()));
        data
    }

    /// `validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)`
    /// per ERC-8004.
    ///
    /// Head: `[request_hash | response (32-padded) | offset-to-uri |
    ///         response_hash | offset-to-tag]` = 5 × 32 = 160 bytes.
    /// Tail layout: response_uri block, then tag block.
    pub fn encode_validation_response(
        selector: [u8; 4],
        request_hash: &[u8; 32],
        response: u8,
        response_uri: &str,
        response_hash: &[u8; 32],
        tag: &str,
    ) -> Vec<u8> {
        // Compute the offset-to-tag = 5*32 + uri_block_len, where
        // uri_block_len = 32 (length word) + ceil(len/32)*32.
        let head_len = 5 * 32;
        let uri_block_len = 32 + response_uri.len().div_ceil(32) * 32;
        let tag_offset = (head_len + uri_block_len) as u64;

        let mut data = Vec::with_capacity(
            4 + head_len + uri_block_len + 32 + tag.len().div_ceil(32) * 32,
        );
        data.extend_from_slice(&selector);
        data.extend_from_slice(request_hash);
        let mut response_word = [0u8; 32];
        response_word[31] = response;
        data.extend_from_slice(&response_word);
        // offset-to-uri = head length = 160
        data.extend_from_slice(&pad32_left(&(160u64).to_be_bytes()));
        data.extend_from_slice(response_hash);
        data.extend_from_slice(&pad32_left(&tag_offset.to_be_bytes()));
        data.extend_from_slice(&encode_bytes_tail(response_uri.as_bytes()));
        data.extend_from_slice(&encode_bytes_tail(tag.as_bytes()));
        data
    }

    /// `getFeedback(uint256 agentId, uint256 index)` — read-only.
    pub fn encode_get_feedback(
        selector: [u8; 4],
        subject_agent_id: u64,
        index: u128,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 2 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(subject_agent_id));
        let mut idx_word = [0u8; 32];
        idx_word[16..32].copy_from_slice(&index.to_be_bytes());
        data.extend_from_slice(&idx_word);
        data
    }

    /// `getFeedbackCount(uint256 agentId)` — read-only.
    pub fn encode_get_feedback_count(selector: [u8; 4], subject_agent_id: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(subject_agent_id));
        data
    }

    /// `revokeFeedback(uint256 agentId, bytes32 feedbackId)` per ERC-8004
    /// v0.6+. Both arguments are static 32-byte words, so the calldata
    /// is a flat `[selector | agent_id | feedback_id]` (4 + 64 bytes).
    pub fn encode_revoke_feedback(
        selector: [u8; 4],
        agent_id: u64,
        feedback_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 2 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data.extend_from_slice(feedback_id);
        data
    }

    /// `appendResponse(uint256 agentId, bytes32 feedbackId, string responseUri)`
    /// per ERC-8004 v0.6+.
    ///
    /// Head: `[agent_id | feedback_id | offset-to-response-uri (= 96)]`,
    /// followed by the standard `(length, utf8-padded-bytes)` tail.
    pub fn encode_append_response(
        selector: [u8; 4],
        agent_id: u64,
        feedback_id: &[u8; 32],
        response_uri: &str,
    ) -> Vec<u8> {
        let tail = encode_bytes_tail(response_uri.as_bytes());
        let mut data = Vec::with_capacity(4 + 3 * 32 + tail.len());
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data.extend_from_slice(feedback_id);
        // offset-to-response-uri = 3 head slots × 32 = 96
        data.extend_from_slice(&pad32_left(&(96u64).to_be_bytes()));
        data.extend_from_slice(&tail);
        data
    }

    /// `getAgentURI(uint256 agentId)` — ERC-8004 v0.6+ read. Static
    /// 32-byte argument, so calldata is `[selector | agent_id]`.
    pub fn encode_get_agent_uri(selector: [u8; 4], agent_id: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data
    }

    /// `getAgentWallet(uint256 agentId)` — ERC-8004 v0.6+ read. Static
    /// 32-byte argument, so calldata is `[selector | agent_id]`.
    pub fn encode_get_agent_wallet(selector: [u8; 4], agent_id: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data
    }

    /// `isFeedbackRevoked(uint256 agentId, bytes32 feedbackId)` —
    /// ERC-8004 v0.6+ read. Both arguments are static 32-byte words, so
    /// the calldata is a flat `[selector | agent_id | feedback_id]`.
    pub fn encode_is_feedback_revoked(
        selector: [u8; 4],
        agent_id: u64,
        feedback_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 2 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data.extend_from_slice(feedback_id);
        data
    }

    /// `getFeedbackResponses(uint256 agentId, bytes32 feedbackId)` —
    /// ERC-8004 v0.6+ read. Same shape as `isFeedbackRevoked`.
    pub fn encode_get_feedback_responses(
        selector: [u8; 4],
        agent_id: u64,
        feedback_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 2 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data.extend_from_slice(feedback_id);
        data
    }

    /// Decode the return of `getAgentURI(uint256) -> string` per the
    /// Tenzro precompile wire shape: `[offset = 32 | length | data]`.
    /// Returns the empty string when the agent is unset.
    pub fn decode_get_agent_uri(data: &[u8]) -> Option<String> {
        if data.len() < 64 {
            return None;
        }
        let offset = u64::from_be_bytes(data[24..32].try_into().ok()?) as usize;
        if offset + 32 > data.len() {
            return None;
        }
        let len = u64::from_be_bytes(data[offset + 24..offset + 32].try_into().ok()?) as usize;
        if len == 0 {
            return Some(String::new());
        }
        if offset + 32 + len > data.len() {
            return None;
        }
        String::from_utf8(data[offset + 32..offset + 32 + len].to_vec()).ok()
    }

    /// Decode the return of `getAgentWallet(uint256) -> address` per
    /// the Tenzro precompile wire shape: a single 32-byte left-padded
    /// address word. Returns the zero address when the agent is unset.
    pub fn decode_get_agent_wallet(data: &[u8]) -> Option<EthAddress> {
        if data.len() < 32 {
            return None;
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&data[12..32]);
        Some(addr)
    }

    /// Decode the return of `isFeedbackRevoked(uint256,bytes32) -> bool`.
    /// Single 32-byte word; non-zero last byte means revoked.
    pub fn decode_is_feedback_revoked(data: &[u8]) -> Option<bool> {
        if data.len() < 32 {
            return None;
        }
        Some(data[31] != 0)
    }

    /// Decode the return of `getFeedbackResponses(uint256,bytes32) -> string`
    /// per the Tenzro precompile wire shape: `[offset = 32 | length | data]`.
    /// Returns the empty string when no response has been attached.
    pub fn decode_get_feedback_responses(data: &[u8]) -> Option<String> {
        if data.len() < 64 {
            return None;
        }
        let offset = u64::from_be_bytes(data[24..32].try_into().ok()?) as usize;
        if offset + 32 > data.len() {
            return None;
        }
        let len = u64::from_be_bytes(data[offset + 24..offset + 32].try_into().ok()?) as usize;
        if len == 0 {
            return Some(String::new());
        }
        if offset + 32 + len > data.len() {
            return None;
        }
        String::from_utf8(data[offset + 32..offset + 32 + len].to_vec()).ok()
    }

    /// `getValidation(bytes32 requestId)` — read-only.
    pub fn encode_get_validation(selector: [u8; 4], request_id: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(request_id);
        data
    }

    /// `setAgentURI(uint256 agentId, string metadataUri)` — ERC-8004
    /// v0.6+. Head: `[agent_id | offset-to-uri (=64)]`, then the URI
    /// string tail.
    pub fn encode_set_agent_uri(
        selector: [u8; 4],
        agent_id: u64,
        metadata_uri: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 64 + 32 + metadata_uri.len().div_ceil(32) * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        // offset-to-uri = 64 (2 head slots × 32)
        data.extend_from_slice(&pad32_left(&(64u64).to_be_bytes()));
        data.extend_from_slice(&encode_bytes_tail(metadata_uri.as_bytes()));
        data
    }

    /// `setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature)`
    /// — ERC-8004 v0.6+.
    ///
    /// Head: `[agent_id | new_wallet (32-padded) | deadline | sig_offset]`
    /// = 4 × 32 = 128. The signature tail follows at offset 128.
    pub fn encode_set_agent_wallet(
        selector: [u8; 4],
        agent_id: u64,
        new_wallet: &EthAddress,
        deadline: u128,
        signature: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 4 * 32 + 32 + signature.len().div_ceil(32) * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        data.extend_from_slice(&pad32_left(new_wallet));
        // deadline (uint256, low 128 bits used)
        let mut deadline_word = [0u8; 32];
        deadline_word[16..32].copy_from_slice(&deadline.to_be_bytes());
        data.extend_from_slice(&deadline_word);
        // signature offset = 128 (4 head slots × 32)
        data.extend_from_slice(&pad32_left(&(128u64).to_be_bytes()));
        data.extend_from_slice(&encode_bytes_tail(signature));
        data
    }

    /// `setMetadata(uint256 agentId, string metadataKey, bytes metadataValue)`
    /// — ERC-8004 v0.6+.
    ///
    /// Head: `[agent_id | key_offset (=96) | value_offset]`. The
    /// `value_offset` is `96 + 32 + ceil(key_len/32)*32`.
    pub fn encode_set_metadata(
        selector: [u8; 4],
        agent_id: u64,
        metadata_key: &str,
        metadata_value: &[u8],
    ) -> Vec<u8> {
        let key_block = 32 + metadata_key.len().div_ceil(32) * 32;
        let value_offset = 96 + key_block;
        let value_block = 32 + metadata_value.len().div_ceil(32) * 32;
        let mut data = Vec::with_capacity(4 + 96 + key_block + value_block);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        // key offset = 96 (3 head slots × 32)
        data.extend_from_slice(&pad32_left(&(96u64).to_be_bytes()));
        // value offset
        data.extend_from_slice(&pad32_left(&(value_offset as u64).to_be_bytes()));
        // key tail
        data.extend_from_slice(&encode_bytes_tail(metadata_key.as_bytes()));
        // value tail
        data.extend_from_slice(&encode_bytes_tail(metadata_value));
        data
    }

    /// `getMetadata(uint256 agentId, string metadataKey)` — ERC-8004
    /// v0.6+ read selector. Head: `[agent_id | key_offset (=64)]`.
    pub fn encode_get_metadata(
        selector: [u8; 4],
        agent_id: u64,
        metadata_key: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 64 + 32 + metadata_key.len().div_ceil(32) * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&agent_id_word(agent_id));
        // offset = 64 (2 head slots × 32)
        data.extend_from_slice(&pad32_left(&(64u64).to_be_bytes()));
        data.extend_from_slice(&encode_bytes_tail(metadata_key.as_bytes()));
        data
    }

    /// Decode the return of `getMetadata(uint256,string) -> bytes` per
    /// the Tenzro precompile wire shape: `[offset = 32 | length | data]`.
    /// Returns `Some(Vec::new())` when the entry is unset.
    pub fn decode_get_metadata(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 64 {
            return None;
        }
        // Slot 0: offset (we expect 32 from the precompile).
        let offset = u64::from_be_bytes(data[24..32].try_into().ok()?) as usize;
        if offset + 32 > data.len() {
            return None;
        }
        let len = u64::from_be_bytes(data[offset + 24..offset + 32].try_into().ok()?) as usize;
        if len == 0 {
            return Some(Vec::new());
        }
        if offset + 32 + len > data.len() {
            return None;
        }
        Some(data[offset + 32..offset + 32 + len].to_vec())
    }

    /// Decode the return of `getFeedback(bytes32,uint256)` per the
    /// Tenzro precompile wire shape:
    /// `(int8 rating, string contextUri, bool exists)` — head is
    /// `[rating | offset | exists]`, tail is `[len | data]`.
    ///
    /// Returns `None` if the bytes don't decode, `Some((_, _, false))`
    /// when the precompile reports the slot is empty.
    pub fn decode_get_feedback(data: &[u8]) -> Option<(i8, String, bool)> {
        if data.len() < 96 {
            return None;
        }
        // Slot 0: rating sign-extended into 32 bytes.
        let rating = data[31] as i8;
        // Slot 1: offset to string tail (we expect 96 from the precompile).
        let offset = u64::from_be_bytes(data[32 + 24..64].try_into().ok()?) as usize;
        // Slot 2: exists flag.
        let exists = data[95] != 0;
        if offset >= data.len() || offset + 32 > data.len() {
            return None;
        }
        let len = u64::from_be_bytes(data[offset + 24..offset + 32].try_into().ok()?) as usize;
        if offset + 32 + len > data.len() {
            return None;
        }
        let uri = String::from_utf8(data[offset + 32..offset + 32 + len].to_vec()).ok()?;
        Some((rating, uri, exists))
    }

    /// Decode the return of `getFeedbackCount(bytes32) -> uint256`.
    pub fn decode_get_feedback_count(data: &[u8]) -> Option<u128> {
        if data.len() < 32 {
            return None;
        }
        Some(u128::from_be_bytes(data[16..32].try_into().ok()?))
    }

    /// Decoded shape of `getValidation(bytes32 requestHash)` per the
    /// Tenzro precompile wire layout. Mirrors the canonical ERC-8004
    /// `validationRequest` + `validationResponse` fields fused into one
    /// read for off-chain indexers.
    ///
    /// Wire shape (head, 7 × 32 = 224 bytes; then 3 string tails):
    /// `(address validator, uint256 agentId, uint8 response,
    ///   uint256 offset_to_request_uri, uint256 offset_to_response_uri,
    ///   uint256 offset_to_tag, bool exists,
    ///   string requestURI, string responseURI, string tag)`
    pub struct DecodedValidation {
        /// Validator address that was registered with the request.
        pub validator: EthAddress,
        /// `agentId` of the subject (sequential `uint256` widened from
        /// the on-wire 32-byte word; `None` if the high 192 bits were
        /// non-zero, which would indicate a foreign id).
        pub agent_id: Option<u64>,
        /// `0..=100` quality score; meaningful only when `exists` is
        /// true and the response slot has been filled.
        pub response: u8,
        /// Resolvable pointer to the work being validated.
        pub request_uri: String,
        /// Resolvable pointer to proof material — empty until a
        /// `validationResponse` lands.
        pub response_uri: String,
        /// Categorical label (e.g. `"valid"`) — empty until a response
        /// lands.
        pub tag: String,
        /// `true` if a request was opened against this `requestHash`.
        pub exists: bool,
    }

    /// Decode the return of `getValidation(bytes32 requestHash)`
    /// produced by the Tenzro precompile at `0x101c`. Returns `None` if
    /// the bytes don't match the 7-slot head + three dynamic-string
    /// tails layout.
    pub fn decode_get_validation(data: &[u8]) -> Option<DecodedValidation> {
        if data.len() < 7 * 32 {
            return None;
        }
        // Slot 0: validator (last 20 bytes of left-padded address word).
        let mut validator = [0u8; 20];
        validator.copy_from_slice(&data[12..32]);
        // Slot 1: agent_id as uint256 — narrow to u64 if it fits.
        let mut agent_id_word = [0u8; 32];
        agent_id_word.copy_from_slice(&data[32..64]);
        let agent_id = super::agent_id_from_uint256_be(&agent_id_word);
        // Slot 2: response (low byte).
        let response = data[95];
        // Slot 3..=5: offsets to dynamic strings.
        let request_uri_offset = u64::from_be_bytes(data[96 + 24..128].try_into().ok()?) as usize;
        let response_uri_offset = u64::from_be_bytes(data[128 + 24..160].try_into().ok()?) as usize;
        let tag_offset = u64::from_be_bytes(data[160 + 24..192].try_into().ok()?) as usize;
        // Slot 6: exists.
        let exists = data[223] != 0;

        let request_uri = decode_string_at(data, request_uri_offset)?;
        let response_uri = decode_string_at(data, response_uri_offset)?;
        let tag = decode_string_at(data, tag_offset)?;

        Some(DecodedValidation {
            validator,
            agent_id,
            response,
            request_uri,
            response_uri,
            tag,
            exists,
        })
    }

    /// Decode an ABI-encoded `string` whose length prefix begins at
    /// `offset` in `data` (offset is measured from the start of the
    /// returndata, matching Solidity's convention).
    fn decode_string_at(data: &[u8], offset: usize) -> Option<String> {
        if offset + 32 > data.len() {
            return None;
        }
        let len = u64::from_be_bytes(data[offset + 24..offset + 32].try_into().ok()?) as usize;
        if offset + 32 + len > data.len() {
            return None;
        }
        String::from_utf8(data[offset + 32..offset + 32 + len].to_vec()).ok()
    }

    /// Decode the return of `getAgent(uint256)` →
    /// `(address controller, string metadataUri)` per the ERC-8004
    /// canonical wire shape: head = `[address-padded-32 | offset-to-string]`,
    /// tail = `[length | utf8 padded]`.
    pub fn decode_get_agent(data: &[u8]) -> Option<(EthAddress, String)> {
        if data.len() < 64 {
            return None;
        }
        // Slot 0: address padded to 32 bytes (left-zeroed).
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&data[12..32]);
        // Slot 1: offset to string tail.
        let offset = u64::from_be_bytes(data[32 + 24..64].try_into().ok()?) as usize;
        if offset >= data.len() || offset + 32 > data.len() {
            return None;
        }
        let len = u64::from_be_bytes(data[offset + 24..offset + 32].try_into().ok()?) as usize;
        if offset + 32 + len > data.len() {
            return None;
        }
        let uri = String::from_utf8(data[offset + 32..offset + 32 + len].to_vec()).ok()?;
        Some((addr, uri))
    }
}

/// High-level client for the ERC-8004 contract suite.
pub struct Erc8004Adapter<T: Erc8004Transport> {
    transport: T,
    addresses: Erc8004Addresses,
}

impl<T: Erc8004Transport> Erc8004Adapter<T> {
    pub fn new(transport: T, addresses: Erc8004Addresses) -> Self {
        Self { transport, addresses }
    }

    pub fn addresses(&self) -> &Erc8004Addresses {
        &self.addresses
    }

    /// Build calldata for `register()` — the no-argument register
    /// overload. The contract allocates a fresh `agentId` for
    /// `msg.sender` with no URI and no metadata.
    pub fn build_register_calldata(&self) -> Vec<u8> {
        abi::encode_register(selectors::REGISTER)
    }

    /// Build calldata for `register(string agentURI)` — allocates a
    /// fresh `agentId` for `msg.sender` and binds the URI in one tx.
    pub fn build_register_with_uri_calldata(&self, agent_uri: &str) -> Vec<u8> {
        abi::encode_register_with_uri(selectors::REGISTER_WITH_URI, agent_uri)
    }

    /// Build calldata for `register(string agentURI, (string,bytes)[] metadata)`
    /// — allocates a fresh `agentId`, binds the URI, and atomically
    /// writes a batch of metadata entries.
    pub fn build_register_with_metadata_calldata(
        &self,
        agent_uri: &str,
        metadata: &[MetadataEntry],
    ) -> Vec<u8> {
        abi::encode_register_with_metadata(
            selectors::REGISTER_WITH_METADATA,
            agent_uri,
            metadata,
        )
    }

    /// Build calldata for `unsetAgentWallet(uint256)` — clear the
    /// controller wallet binding (sets it to the zero address).
    pub fn build_unset_agent_wallet_calldata(&self, agent_id: u64) -> Vec<u8> {
        abi::encode_unset_agent_wallet(selectors::UNSET_AGENT_WALLET, agent_id)
    }

    /// Look up an agent by its `agentId`.
    pub async fn get_agent(&self, agent_id: u64) -> Result<AgentRecord> {
        let data = abi::encode_get_agent(selectors::GET_AGENT, agent_id);
        let ret = self
            .transport
            .eth_call(&self.addresses.identity_registry, &data)
            .await?;
        let (addr, uri) = abi::decode_get_agent(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 getAgent return".into(),
            )
        })?;
        Ok(AgentRecord {
            agent_id,
            agent_address: addr,
            metadata_uri: uri,
        })
    }

    /// Build calldata for a feedback submission.
    pub fn build_submit_feedback_calldata(&self, entry: &FeedbackEntry) -> Vec<u8> {
        abi::encode_submit_feedback(
            selectors::SUBMIT_FEEDBACK,
            entry.subject_agent_id,
            entry.rating,
            &entry.context_uri,
        )
    }

    /// Build calldata for `revokeFeedback(uint256 agentId, bytes32 feedbackId)`
    /// per ERC-8004 v0.6+. The byte-identical calldata works against
    /// either the native Tenzro ReputationRegistry precompile or an
    /// Ethereum-side mirror contract.
    pub fn build_revoke_feedback_calldata(
        &self,
        agent_id: u64,
        feedback_id: &[u8; 32],
    ) -> Vec<u8> {
        abi::encode_revoke_feedback(selectors::REVOKE_FEEDBACK, agent_id, feedback_id)
    }

    /// Build calldata for `appendResponse(uint256 agentId, bytes32 feedbackId, string responseUri)`
    /// per ERC-8004 v0.6+. Lets the rated agent attach (or replace) a
    /// response URI on a feedback entry.
    pub fn build_append_response_calldata(
        &self,
        agent_id: u64,
        feedback_id: &[u8; 32],
        response_uri: &str,
    ) -> Vec<u8> {
        abi::encode_append_response(
            selectors::APPEND_RESPONSE,
            agent_id,
            feedback_id,
            response_uri,
        )
    }

    /// Build calldata for `validationRequest(address,uint256,string,bytes32)`
    /// per ERC-8004.
    pub fn build_validation_request_calldata(&self, request: &ValidationRequest) -> Vec<u8> {
        abi::encode_validation_request(
            selectors::VALIDATION_REQUEST,
            &request.validator_address,
            request.agent_id,
            &request.request_uri,
            &request.request_hash,
        )
    }

    /// Build calldata for `validationResponse(bytes32,uint8,string,bytes32,string)`
    /// per ERC-8004.
    pub fn build_validation_response_calldata(&self, result: &ValidationResult) -> Vec<u8> {
        abi::encode_validation_response(
            selectors::VALIDATION_RESPONSE,
            &result.request_hash,
            result.response,
            &result.response_uri,
            &result.response_hash,
            &result.tag,
        )
    }

    /// Look up a single feedback entry against a subject agent.
    ///
    /// Wraps the `getFeedback(uint256,uint256)` read selector at the
    /// ReputationRegistry. Returns the entry plus its `exists` flag —
    /// callers should treat `exists == false` as "no entry at this
    /// index" rather than a transport failure.
    pub async fn get_feedback(
        &self,
        subject_agent_id: u64,
        index: u128,
    ) -> Result<(FeedbackEntry, bool)> {
        let data = abi::encode_get_feedback(selectors::GET_FEEDBACK, subject_agent_id, index);
        let ret = self
            .transport
            .eth_call(&self.addresses.reputation_registry, &data)
            .await?;
        let (rating, context_uri, exists) = abi::decode_get_feedback(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 getFeedback return".into(),
            )
        })?;
        Ok((
            FeedbackEntry {
                subject_agent_id,
                rating,
                context_uri,
            },
            exists,
        ))
    }

    /// Return the count of feedback entries against a subject agent.
    ///
    /// Wraps the `getFeedbackCount(uint256)` read selector at the
    /// ReputationRegistry.
    pub async fn get_feedback_count(&self, subject_agent_id: u64) -> Result<u128> {
        let data = abi::encode_get_feedback_count(selectors::GET_FEEDBACK_COUNT, subject_agent_id);
        let ret = self
            .transport
            .eth_call(&self.addresses.reputation_registry, &data)
            .await?;
        abi::decode_get_feedback_count(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 getFeedbackCount return".into(),
            )
        })
    }

    /// Look up a validation entry by `requestHash`.
    ///
    /// Wraps the `getValidation(bytes32)` read selector at the
    /// ValidationRegistry. The decoded shape mirrors the Tenzro
    /// precompile's wire layout, which carries `validator + agentId +
    /// response + requestUri + responseUri + tag + exists`.
    pub async fn get_validation(
        &self,
        request_id: &[u8; 32],
    ) -> Result<abi::DecodedValidation> {
        let data = abi::encode_get_validation(selectors::GET_VALIDATION, request_id);
        let ret = self
            .transport
            .eth_call(&self.addresses.validation_registry, &data)
            .await?;
        abi::decode_get_validation(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 getValidation return".into(),
            )
        })
    }

    /// Build calldata for `setAgentURI(uint256,string)` — ERC-8004 v0.6+.
    /// Submission requires a signed transaction; the wallet binder
    /// owns that step.
    pub fn build_set_agent_uri_calldata(
        &self,
        agent_id: u64,
        metadata_uri: &str,
    ) -> Vec<u8> {
        abi::encode_set_agent_uri(selectors::SET_AGENT_URI, agent_id, metadata_uri)
    }

    /// Build calldata for `setAgentWallet(uint256,address,uint256,bytes)`
    /// — ERC-8004 v0.6+. The `(deadline, signature)` pair is the
    /// reference contract's EIP-712 consent payload; pass `&[]` if
    /// targeting the Tenzro precompile, which trusts the outer-tx
    /// `from` for authorization.
    pub fn build_set_agent_wallet_calldata(
        &self,
        agent_id: u64,
        new_wallet: &EthAddress,
        deadline: u128,
        signature: &[u8],
    ) -> Vec<u8> {
        abi::encode_set_agent_wallet(
            selectors::SET_AGENT_WALLET,
            agent_id,
            new_wallet,
            deadline,
            signature,
        )
    }

    /// Build calldata for `setMetadata(uint256,string,bytes)` — ERC-8004
    /// v0.6+. An empty `metadata_value` deletes the entry.
    pub fn build_set_metadata_calldata(
        &self,
        agent_id: u64,
        metadata_key: &str,
        metadata_value: &[u8],
    ) -> Vec<u8> {
        abi::encode_set_metadata(
            selectors::SET_METADATA,
            agent_id,
            metadata_key,
            metadata_value,
        )
    }

    /// Read the bytes stored at `(agent_id, metadata_key)`.
    ///
    /// Wraps the `getMetadata(uint256,string)` read selector at the
    /// IdentityRegistry. Returns an empty `Vec` when the entry is
    /// unset.
    pub async fn get_metadata(
        &self,
        agent_id: u64,
        metadata_key: &str,
    ) -> Result<Vec<u8>> {
        let data = abi::encode_get_metadata(selectors::GET_METADATA, agent_id, metadata_key);
        let ret = self
            .transport
            .eth_call(&self.addresses.identity_registry, &data)
            .await?;
        abi::decode_get_metadata(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 getMetadata return".into(),
            )
        })
    }

    /// Read the metadata URI bound to an agent — ERC-8004 v0.6+
    /// `getAgentURI(uint256)`.
    pub async fn get_agent_uri(&self, agent_id: u64) -> Result<String> {
        let data = abi::encode_get_agent_uri(selectors::GET_AGENT_URI, agent_id);
        let ret = self
            .transport
            .eth_call(&self.addresses.identity_registry, &data)
            .await?;
        abi::decode_get_agent_uri(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 getAgentURI return".into(),
            )
        })
    }

    /// Read the controller wallet bound to an agent — ERC-8004 v0.6+
    /// `getAgentWallet(uint256)`.
    pub async fn get_agent_wallet(&self, agent_id: u64) -> Result<EthAddress> {
        let data = abi::encode_get_agent_wallet(selectors::GET_AGENT_WALLET, agent_id);
        let ret = self
            .transport
            .eth_call(&self.addresses.identity_registry, &data)
            .await?;
        abi::decode_get_agent_wallet(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 getAgentWallet return".into(),
            )
        })
    }

    /// Check whether a feedback entry is revoked — ERC-8004 v0.6+
    /// `isFeedbackRevoked(uint256,bytes32)`. Unknown entries return
    /// `false`.
    pub async fn is_feedback_revoked(
        &self,
        agent_id: u64,
        feedback_id: &[u8; 32],
    ) -> Result<bool> {
        let data = abi::encode_is_feedback_revoked(
            selectors::IS_FEEDBACK_REVOKED,
            agent_id,
            feedback_id,
        );
        let ret = self
            .transport
            .eth_call(&self.addresses.reputation_registry, &data)
            .await?;
        abi::decode_is_feedback_revoked(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 isFeedbackRevoked return".into(),
            )
        })
    }

    /// Read the most recent response URI attached to a feedback entry —
    /// ERC-8004 v0.6+ `getFeedbackResponses(uint256,bytes32)`. Returns
    /// the empty string when no response has been attached.
    pub async fn get_feedback_responses(
        &self,
        agent_id: u64,
        feedback_id: &[u8; 32],
    ) -> Result<String> {
        let data = abi::encode_get_feedback_responses(
            selectors::GET_FEEDBACK_RESPONSES,
            agent_id,
            feedback_id,
        );
        let ret = self
            .transport
            .eth_call(&self.addresses.reputation_registry, &data)
            .await?;
        abi::decode_get_feedback_responses(&ret).ok_or_else(|| {
            IdentityError::VerificationFailed(
                "failed to decode ERC-8004 getFeedbackResponses return".into(),
            )
        })
    }

    /// Relay a pre-signed transaction through the transport.
    pub async fn send_signed(&self, signed_tx: &[u8]) -> Result<String> {
        self.transport.eth_send_raw(signed_tx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTransport {
        agent_return: Vec<u8>,
    }

    #[async_trait]
    impl Erc8004Transport for MockTransport {
        async fn eth_call(&self, _to: &EthAddress, _data: &[u8]) -> Result<Vec<u8>> {
            Ok(self.agent_return.clone())
        }
        async fn eth_send_raw(&self, _tx: &[u8]) -> Result<String> {
            Ok("0xdeadbeef".into())
        }
    }

    fn mk_addresses() -> Erc8004Addresses {
        Erc8004Addresses {
            identity_registry: [1u8; 20],
            reputation_registry: [2u8; 20],
            validation_registry: [3u8; 20],
        }
    }

    // -- Sequential agent_id wire roundtrip --

    #[test]
    fn agent_id_uint256_be_roundtrip() {
        for id in [0u64, 1, 42, 1_000_000, u64::MAX] {
            let word = agent_id_to_uint256_be(id);
            // Low 8 bytes must hold the BE-encoded id; high 24 must be zero.
            assert_eq!(&word[..24], &[0u8; 24]);
            assert_eq!(&word[24..], &id.to_be_bytes());
            assert_eq!(agent_id_from_uint256_be(&word), Some(id));
        }
    }

    #[test]
    fn agent_id_from_uint256_rejects_high_bits() {
        let mut word = [0u8; 32];
        word[0] = 1; // bit set above the u64 range
        assert_eq!(agent_id_from_uint256_be(&word), None);
    }

    // -- ERC-8004 register overload selectors (canonical pinning) --

    #[test]
    fn register_selectors_match_canonical_keccak() {
        // bytes4(keccak256("register()"))
        assert_eq!(selectors::REGISTER, [0x1a, 0xa3, 0xa0, 0x08]);
        // bytes4(keccak256("register(string)"))
        assert_eq!(selectors::REGISTER_WITH_URI, [0xf2, 0xc2, 0x98, 0xbe]);
        // bytes4(keccak256("register(string,(string,bytes)[])"))
        assert_eq!(selectors::REGISTER_WITH_METADATA, [0x8e, 0xa4, 0x22, 0x86]);
        // bytes4(keccak256("unsetAgentWallet(uint256)"))
        assert_eq!(selectors::UNSET_AGENT_WALLET, [0x3f, 0xdd, 0xcf, 0x19]);
        // bytes4(keccak256("getAgent(uint256)"))
        assert_eq!(selectors::GET_AGENT, [0x2d, 0xe5, 0xaa, 0xf7]);
        // bytes4(keccak256("submitFeedback(uint256,int8,string)"))
        assert_eq!(selectors::SUBMIT_FEEDBACK, [0xe5, 0x67, 0x9c, 0x29]);
        // bytes4(keccak256("getFeedback(uint256,uint256)"))
        assert_eq!(selectors::GET_FEEDBACK, [0x2d, 0x15, 0x04, 0x57]);
        // bytes4(keccak256("getFeedbackCount(uint256)"))
        assert_eq!(selectors::GET_FEEDBACK_COUNT, [0x45, 0x37, 0xb7, 0x64]);
        // bytes4(keccak256("getValidation(bytes32)"))
        assert_eq!(selectors::GET_VALIDATION, [0xa8, 0x09, 0x1f, 0xc3]);
    }

    // -- register encoders --

    #[test]
    fn encode_register_no_args() {
        let data = abi::encode_register(selectors::REGISTER);
        assert_eq!(data, selectors::REGISTER.to_vec());
    }

    #[test]
    fn encode_register_with_uri_layout() {
        let uri = "ipfs://card";
        let data = abi::encode_register_with_uri(selectors::REGISTER_WITH_URI, uri);
        assert_eq!(&data[0..4], &selectors::REGISTER_WITH_URI);
        // Head: offset = 32 (last byte of slot 0)
        assert_eq!(data[35], 32);
        // Length word at [36..68], last byte = uri.len()
        assert_eq!(data[67] as usize, uri.len());
        // String bytes at [68..]
        assert_eq!(&data[68..68 + uri.len()], uri.as_bytes());
    }

    #[test]
    fn encode_register_with_metadata_packs_uri_then_array() {
        let uri = "ipfs://card";
        let entries = vec![
            MetadataEntry {
                metadata_key: "skills".into(),
                metadata_value: b"forecast".to_vec(),
            },
            MetadataEntry {
                metadata_key: "model".into(),
                metadata_value: b"chronos".to_vec(),
            },
        ];
        let data =
            abi::encode_register_with_metadata(selectors::REGISTER_WITH_METADATA, uri, &entries);
        assert_eq!(&data[0..4], &selectors::REGISTER_WITH_METADATA);
        // Head[0]: offset-to-uri = 64
        assert_eq!(data[35], 64);
        // Head[1]: offset-to-metadata = 64 + 32 + ceil(uri_len/32)*32 = 64 + 32 + 32 = 128
        assert_eq!(data[67], 128);
        // URI tail at [4 + 64..]: length word then bytes
        assert_eq!(data[4 + 64 + 31] as usize, uri.len());
        assert_eq!(&data[4 + 96..4 + 96 + uri.len()], uri.as_bytes());
        // Metadata array length word at [4 + 128..4 + 160], last byte = 2
        assert_eq!(data[4 + 128 + 31], 2);
    }

    #[test]
    fn encode_register_with_metadata_empty_array() {
        let uri = "x";
        let data =
            abi::encode_register_with_metadata(selectors::REGISTER_WITH_METADATA, uri, &[]);
        // Head: 4 + 64 + uri_block (32 + 32) + length_word (32) = 4 + 160
        assert_eq!(data.len(), 4 + 160);
        // Length word at [4 + 128..4 + 160] is all zero
        assert_eq!(&data[4 + 128..4 + 160], &[0u8; 32]);
    }

    // -- unsetAgentWallet --

    #[test]
    fn encode_unset_agent_wallet_layout() {
        let data = abi::encode_unset_agent_wallet(selectors::UNSET_AGENT_WALLET, 42);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(&data[0..4], &selectors::UNSET_AGENT_WALLET);
        // agent_id = 42 in last byte (BE u64 word)
        assert_eq!(data[35], 42);
    }

    // -- get/submit feedback (uint256-keyed) --

    #[test]
    fn encode_submit_feedback_uses_uint256_subject() {
        let data = abi::encode_submit_feedback(selectors::SUBMIT_FEEDBACK, 7, -50, "ctx");
        assert_eq!(&data[0..4], &selectors::SUBMIT_FEEDBACK);
        // subject_agent_id = 7 in low byte of slot 0
        assert_eq!(data[35], 7);
        // rating word starts at offset 4 + 32 = 36
        assert_eq!(data[36..67], [0xff; 31]);
        assert_eq!(data[67], (-50i8) as u8);
    }

    #[test]
    fn encode_get_feedback_uses_uint256_subject_and_index() {
        let data = abi::encode_get_feedback(selectors::GET_FEEDBACK, 9, 42);
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[0..4], &selectors::GET_FEEDBACK);
        // subject = 9
        assert_eq!(data[35], 9);
        // index = 42 (uint256 in second slot)
        assert_eq!(data[67], 42);
    }

    #[test]
    fn encode_get_feedback_count_uses_uint256_subject() {
        let data = abi::encode_get_feedback_count(selectors::GET_FEEDBACK_COUNT, 11);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(&data[0..4], &selectors::GET_FEEDBACK_COUNT);
        assert_eq!(data[35], 11);
    }

    // -- decode getAgent --

    #[test]
    fn decode_get_agent_roundtrip() {
        // (address, offset-to-string, length, bytes)
        let mut ret = Vec::new();
        ret.extend_from_slice(&[0u8; 12]);
        ret.extend_from_slice(&[0xab; 20]);
        let mut offset = [0u8; 32];
        offset[31] = 64;
        ret.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[31] = 10;
        ret.extend_from_slice(&len);
        ret.extend_from_slice(b"ipfs://abc");
        ret.extend_from_slice(&[0u8; 22]);

        let (addr, uri) = abi::decode_get_agent(&ret).unwrap();
        assert_eq!(addr, [0xab; 20]);
        assert_eq!(uri, "ipfs://abc");
    }

    #[tokio::test]
    async fn adapter_get_agent_via_transport() {
        let mut ret = Vec::new();
        ret.extend_from_slice(&[0u8; 12]);
        ret.extend_from_slice(&[0xab; 20]);
        let mut offset = [0u8; 32];
        offset[31] = 64;
        ret.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[31] = 5;
        ret.extend_from_slice(&len);
        ret.extend_from_slice(b"hello");
        ret.extend_from_slice(&[0u8; 27]);

        let adapter = Erc8004Adapter::new(MockTransport { agent_return: ret }, mk_addresses());
        let record = adapter.get_agent(123).await.unwrap();
        assert_eq!(record.agent_address, [0xab; 20]);
        assert_eq!(record.metadata_uri, "hello");
        assert_eq!(record.agent_id, 123);
    }

    // -- selector distinctness --

    #[test]
    fn read_selectors_are_distinct_from_writes() {
        let all = [
            selectors::REGISTER,
            selectors::REGISTER_WITH_URI,
            selectors::REGISTER_WITH_METADATA,
            selectors::GET_AGENT,
            selectors::SET_AGENT_URI,
            selectors::SET_AGENT_WALLET,
            selectors::UNSET_AGENT_WALLET,
            selectors::SET_METADATA,
            selectors::GET_METADATA,
            selectors::GET_AGENT_URI,
            selectors::GET_AGENT_WALLET,
            selectors::SUBMIT_FEEDBACK,
            selectors::GET_FEEDBACK,
            selectors::GET_FEEDBACK_COUNT,
            selectors::REVOKE_FEEDBACK,
            selectors::APPEND_RESPONSE,
            selectors::IS_FEEDBACK_REVOKED,
            selectors::GET_FEEDBACK_RESPONSES,
            selectors::VALIDATION_REQUEST,
            selectors::VALIDATION_RESPONSE,
            selectors::GET_VALIDATION,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "selector collision at indices {i},{j}");
            }
        }
    }

    #[test]
    fn decode_get_feedback_round_trips_precompile_shape() {
        let rating: i8 = -25;
        let context = "ipfs://feedback-cid";
        let mut ret = Vec::new();
        // Slot 0: rating sign-extended
        let mut rating_word = [0xffu8; 32];
        rating_word[31] = rating as u8;
        ret.extend_from_slice(&rating_word);
        // Slot 1: offset = 96
        let mut offset = [0u8; 32];
        offset[31] = 96;
        ret.extend_from_slice(&offset);
        // Slot 2: exists = true
        let mut exists = [0u8; 32];
        exists[31] = 1;
        ret.extend_from_slice(&exists);
        // Tail: length + data
        let mut len_word = [0u8; 32];
        len_word[31] = context.len() as u8;
        ret.extend_from_slice(&len_word);
        ret.extend_from_slice(context.as_bytes());
        let pad = (32 - (context.len() % 32)) % 32;
        ret.extend(std::iter::repeat_n(0u8, pad));

        let (decoded_rating, decoded_uri, decoded_exists) =
            abi::decode_get_feedback(&ret).expect("must decode");
        assert_eq!(decoded_rating, rating);
        assert_eq!(decoded_uri, context);
        assert!(decoded_exists);
    }

    #[test]
    fn decode_get_feedback_count_extracts_low_uint128() {
        let mut ret = vec![0u8; 32];
        ret[16..32].copy_from_slice(&1_234_567u128.to_be_bytes());
        let count = abi::decode_get_feedback_count(&ret).unwrap();
        assert_eq!(count, 1_234_567);
    }

    #[test]
    fn decode_get_validation_narrows_agent_id_to_u64() {
        let validator = [0x99u8; 20];
        let agent_id_u64: u64 = 0x4242_4242_4242_4242;
        let request_uri = "ipfs://task";
        let response_uri = "ipfs://proof-doc";
        let tag = "valid";
        let response: u8 = 87;

        let request_padded = request_uri.len().div_ceil(32) * 32;
        let request_block = 32 + request_padded;
        let response_uri_offset = 224 + request_block;
        let response_padded = response_uri.len().div_ceil(32) * 32;
        let response_block = 32 + response_padded;
        let tag_offset = response_uri_offset + response_block;
        let tag_padded = tag.len().div_ceil(32) * 32;
        let total_len = tag_offset + 32 + tag_padded;

        let mut ret = vec![0u8; total_len];
        ret[12..32].copy_from_slice(&validator);
        // agent_id as uint256 BE
        ret[56..64].copy_from_slice(&agent_id_u64.to_be_bytes());
        ret[95] = response;
        ret[96 + 24..128].copy_from_slice(&224u64.to_be_bytes());
        ret[128 + 24..160].copy_from_slice(&(response_uri_offset as u64).to_be_bytes());
        ret[160 + 24..192].copy_from_slice(&(tag_offset as u64).to_be_bytes());
        ret[223] = 1;

        ret[224 + 24..256].copy_from_slice(&(request_uri.len() as u64).to_be_bytes());
        ret[256..256 + request_uri.len()].copy_from_slice(request_uri.as_bytes());

        ret[response_uri_offset + 24..response_uri_offset + 32]
            .copy_from_slice(&(response_uri.len() as u64).to_be_bytes());
        ret[response_uri_offset + 32..response_uri_offset + 32 + response_uri.len()]
            .copy_from_slice(response_uri.as_bytes());

        ret[tag_offset + 24..tag_offset + 32]
            .copy_from_slice(&(tag.len() as u64).to_be_bytes());
        ret[tag_offset + 32..tag_offset + 32 + tag.len()].copy_from_slice(tag.as_bytes());

        let decoded = abi::decode_get_validation(&ret).expect("must decode");
        assert_eq!(decoded.validator, validator);
        assert_eq!(decoded.agent_id, Some(agent_id_u64));
        assert_eq!(decoded.response, response);
        assert_eq!(decoded.request_uri, request_uri);
        assert_eq!(decoded.response_uri, response_uri);
        assert_eq!(decoded.tag, tag);
        assert!(decoded.exists);
    }

    // -- v0.6+ identity-side mutators (selectors unchanged) --

    #[test]
    fn encode_set_agent_uri_layout() {
        let uri = "ipfs://updated-cid";
        let data = abi::encode_set_agent_uri(selectors::SET_AGENT_URI, 0x42, uri);
        assert_eq!(&data[0..4], &selectors::SET_AGENT_URI);
        // agent_id = 0x42
        assert_eq!(data[35], 0x42);
        // offset = 64
        assert_eq!(data[67], 64);
        // length and string
        assert_eq!(data[4 + 64 + 31] as usize, uri.len());
        assert_eq!(&data[4 + 96..4 + 96 + uri.len()], uri.as_bytes());
    }

    #[test]
    fn encode_set_agent_wallet_layout() {
        let new_wallet = [0x22u8; 20];
        let signature = vec![0xaa; 65];
        let data = abi::encode_set_agent_wallet(
            selectors::SET_AGENT_WALLET,
            0x11,
            &new_wallet,
            42,
            &signature,
        );
        assert_eq!(&data[0..4], &selectors::SET_AGENT_WALLET);
        assert_eq!(data[35], 0x11);
        assert_eq!(&data[4 + 32 + 12..4 + 32 + 32], &new_wallet);
        assert_eq!(data[4 + 64 + 31], 42);
        assert_eq!(data[4 + 96 + 31], 128);
        assert_eq!(data[4 + 128 + 31] as usize, signature.len());
        assert_eq!(
            &data[4 + 160..4 + 160 + signature.len()],
            signature.as_slice(),
        );
    }

    #[test]
    fn encode_set_metadata_packs_key_then_value() {
        let key = "skills";
        let value: &[u8] = b"forecast,vision";
        let data = abi::encode_set_metadata(selectors::SET_METADATA, 0x33, key, value);
        assert_eq!(&data[0..4], &selectors::SET_METADATA);
        assert_eq!(data[35], 0x33);
        assert_eq!(data[4 + 32 + 31], 96);
        assert_eq!(data[4 + 64 + 31], 160);
        assert_eq!(data[4 + 96 + 31] as usize, key.len());
        assert_eq!(&data[4 + 128..4 + 128 + key.len()], key.as_bytes());
        assert_eq!(data[4 + 160 + 31] as usize, value.len());
        assert_eq!(&data[4 + 192..4 + 192 + value.len()], value);
    }

    #[test]
    fn encode_set_metadata_with_empty_value() {
        let key = "drop";
        let data = abi::encode_set_metadata(selectors::SET_METADATA, 0, key, &[]);
        assert_eq!(data[4 + 32 + 31], 96);
        assert_eq!(data[4 + 64 + 31], 160);
        assert_eq!(data[4 + 160 + 31], 0);
    }

    #[test]
    fn encode_get_metadata_layout() {
        let key = "skills";
        let data = abi::encode_get_metadata(selectors::GET_METADATA, 0x44, key);
        assert_eq!(&data[0..4], &selectors::GET_METADATA);
        assert_eq!(data[35], 0x44);
        assert_eq!(data[4 + 32 + 31], 64);
        assert_eq!(data[4 + 64 + 31] as usize, key.len());
        assert_eq!(&data[4 + 96..4 + 96 + key.len()], key.as_bytes());
    }

    #[test]
    fn decode_get_metadata_round_trips_precompile_shape() {
        let value: &[u8] = b"hello-world-bytes";
        let mut ret = Vec::new();
        let mut offset = [0u8; 32];
        offset[31] = 32;
        ret.extend_from_slice(&offset);
        let mut len_word = [0u8; 32];
        len_word[31] = value.len() as u8;
        ret.extend_from_slice(&len_word);
        ret.extend_from_slice(value);
        let pad = (32 - (value.len() % 32)) % 32;
        ret.extend(std::iter::repeat_n(0u8, pad));

        let decoded = abi::decode_get_metadata(&ret).expect("must decode");
        assert_eq!(decoded, value);
    }

    #[test]
    fn decode_get_metadata_unset_returns_empty_vec() {
        let mut ret = vec![0u8; 64];
        ret[31] = 32;
        let decoded = abi::decode_get_metadata(&ret).expect("must decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_revoke_feedback_layout() {
        let feedback_id = [0xb2u8; 32];
        let data = abi::encode_revoke_feedback(selectors::REVOKE_FEEDBACK, 0xa1, &feedback_id);
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[0..4], &selectors::REVOKE_FEEDBACK);
        assert_eq!(data[35], 0xa1);
        assert_eq!(&data[36..68], &feedback_id);
    }

    #[test]
    fn encode_append_response_layout() {
        let feedback_id = [0xd4u8; 32];
        let response = "ipfs://defense";
        let data = abi::encode_append_response(
            selectors::APPEND_RESPONSE,
            0xc3,
            &feedback_id,
            response,
        );
        assert_eq!(&data[0..4], &selectors::APPEND_RESPONSE);
        assert_eq!(data[35], 0xc3);
        assert_eq!(&data[36..68], &feedback_id);
        assert_eq!(data[99], 96);
        assert_eq!(data[131], response.len() as u8);
        assert_eq!(&data[132..132 + response.len()], response.as_bytes());
        let pad = response.len().div_ceil(32) * 32;
        assert_eq!(data.len(), 4 + 96 + 32 + pad);
    }

    #[test]
    fn encode_append_response_with_empty_uri() {
        let feedback_id = [0u8; 32];
        let data =
            abi::encode_append_response(selectors::APPEND_RESPONSE, 0, &feedback_id, "");
        assert_eq!(data.len(), 4 + 96 + 32);
        assert_eq!(&data[100..132], &[0u8; 32]);
    }

    #[test]
    fn revoke_and_append_selectors_match_canonical_keccak() {
        assert_eq!(selectors::REVOKE_FEEDBACK, [0xa2, 0x83, 0x34, 0xce]);
        assert_eq!(selectors::APPEND_RESPONSE, [0x60, 0x1f, 0x56, 0x76]);
    }

    // -- ERC-8004 v0.6+ read selectors --

    #[test]
    fn v06_read_selectors_match_canonical_keccak() {
        assert_eq!(selectors::GET_AGENT_URI, [0xce, 0x91, 0xae, 0xde]);
        assert_eq!(selectors::GET_AGENT_WALLET, [0x00, 0x33, 0x95, 0x09]);
        assert_eq!(selectors::IS_FEEDBACK_REVOKED, [0xb0, 0x17, 0xcb, 0x04]);
        assert_eq!(selectors::GET_FEEDBACK_RESPONSES, [0xcc, 0x84, 0x63, 0x3b]);
    }

    #[test]
    fn encode_get_agent_uri_layout() {
        let data = abi::encode_get_agent_uri(selectors::GET_AGENT_URI, 0x55);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(&data[0..4], &selectors::GET_AGENT_URI);
        assert_eq!(data[35], 0x55);
    }

    #[test]
    fn encode_get_agent_wallet_layout() {
        let data = abi::encode_get_agent_wallet(selectors::GET_AGENT_WALLET, 0x66);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(&data[0..4], &selectors::GET_AGENT_WALLET);
        assert_eq!(data[35], 0x66);
    }

    #[test]
    fn encode_is_feedback_revoked_layout() {
        let feedback_id = [0x88u8; 32];
        let data = abi::encode_is_feedback_revoked(
            selectors::IS_FEEDBACK_REVOKED,
            0x77,
            &feedback_id,
        );
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[0..4], &selectors::IS_FEEDBACK_REVOKED);
        assert_eq!(data[35], 0x77);
        assert_eq!(&data[36..68], &feedback_id);
    }

    #[test]
    fn encode_get_feedback_responses_layout() {
        let feedback_id = [0xaau8; 32];
        let data = abi::encode_get_feedback_responses(
            selectors::GET_FEEDBACK_RESPONSES,
            0x99,
            &feedback_id,
        );
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[0..4], &selectors::GET_FEEDBACK_RESPONSES);
        assert_eq!(data[35], 0x99);
        assert_eq!(&data[36..68], &feedback_id);
    }

    #[test]
    fn decode_get_agent_uri_round_trips_precompile_shape() {
        let uri = "ipfs://agent-uri-cid";
        let mut ret = Vec::new();
        let mut offset = [0u8; 32];
        offset[31] = 32;
        ret.extend_from_slice(&offset);
        let mut len_word = [0u8; 32];
        len_word[31] = uri.len() as u8;
        ret.extend_from_slice(&len_word);
        ret.extend_from_slice(uri.as_bytes());
        let pad = (32 - (uri.len() % 32)) % 32;
        ret.extend(std::iter::repeat_n(0u8, pad));

        let decoded = abi::decode_get_agent_uri(&ret).expect("must decode");
        assert_eq!(decoded, uri);
    }

    #[test]
    fn decode_get_agent_uri_unset_returns_empty_string() {
        let mut ret = vec![0u8; 64];
        ret[31] = 32;
        let decoded = abi::decode_get_agent_uri(&ret).expect("must decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_get_agent_wallet_round_trips_precompile_shape() {
        let wallet = [0xefu8; 20];
        let mut ret = vec![0u8; 32];
        ret[12..32].copy_from_slice(&wallet);
        let decoded = abi::decode_get_agent_wallet(&ret).expect("must decode");
        assert_eq!(decoded, wallet);
    }

    #[test]
    fn decode_get_agent_wallet_unset_returns_zero_address() {
        let ret = vec![0u8; 32];
        let decoded = abi::decode_get_agent_wallet(&ret).expect("must decode");
        assert_eq!(decoded, [0u8; 20]);
    }

    #[test]
    fn decode_is_feedback_revoked_round_trips() {
        let mut ret_true = vec![0u8; 32];
        ret_true[31] = 1;
        assert!(abi::decode_is_feedback_revoked(&ret_true).unwrap());

        let ret_false = vec![0u8; 32];
        assert!(!abi::decode_is_feedback_revoked(&ret_false).unwrap());
    }

    #[test]
    fn decode_get_feedback_responses_round_trips_precompile_shape() {
        let response = "ipfs://reply-cid";
        let mut ret = Vec::new();
        let mut offset = [0u8; 32];
        offset[31] = 32;
        ret.extend_from_slice(&offset);
        let mut len_word = [0u8; 32];
        len_word[31] = response.len() as u8;
        ret.extend_from_slice(&len_word);
        ret.extend_from_slice(response.as_bytes());
        let pad = (32 - (response.len() % 32)) % 32;
        ret.extend(std::iter::repeat_n(0u8, pad));

        let decoded = abi::decode_get_feedback_responses(&ret).expect("must decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn decode_get_feedback_responses_unset_returns_empty_string() {
        let mut ret = vec![0u8; 64];
        ret[31] = 32;
        let decoded = abi::decode_get_feedback_responses(&ret).expect("must decode");
        assert!(decoded.is_empty());
    }
}
