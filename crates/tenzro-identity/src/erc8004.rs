//! ERC-8004 — Trustless Agents Identity / Reputation / Validation registry adapter.
//!
//! [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) defines a three-contract
//! architecture deployed to Ethereum for cross-vendor trustless agent identity:
//!
//! 1. **IdentityRegistry** — maps a `bytes32 agentId` (typically
//!    `keccak256(did)`) to an on-chain address plus a metadata URI
//!    (resolvable DID document, AgentCard, etc.).
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
//! | `TenzroIdentity::did_string()` | `agentId = keccak256(did)` |
//! | Wallet binding address | `agentAddress` |
//! | DID document URL | `metadataUri` |
//! | `VerifiableCredential` (attestation) | `ValidationRegistry.validationResponse()` |
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

use tenzro_crypto::hash::keccak256;

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
/// so every machine identity is discoverable via `getAgent(bytes32)` on
/// the precompile without an explicit second user step.
///
/// Failures are logged but never block TDIP registration — the on-chain
/// mirror is best-effort and additive.
pub trait OnChainAgentRegistry: Send + Sync {
    /// Mirror a TDIP machine registration into the on-chain registry.
    ///
    /// `agent_id` is `keccak256(did_string)` (see [`derive_agent_id`]),
    /// `agent_address` is the 20-byte EVM address of the wallet bound to
    /// the identity, and `metadata_uri` is the resolvable DID document
    /// or AgentCard URL.
    fn mirror_register_agent(
        &self,
        agent_id: &[u8; 32],
        agent_address: &EthAddress,
        metadata_uri: &str,
    ) -> Result<()>;
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

    /// `registerAgent(bytes32,address,string)`
    pub const REGISTER_AGENT: [u8; 4] = [0xaa, 0xa3, 0x8f, 0x6c];
    /// `getAgent(bytes32)`
    pub const GET_AGENT: [u8; 4] = [0xdb, 0x4a, 0x7a, 0x9a];
    /// `setAgentURI(uint256,string)` — ERC-8004 v0.6+ selector for
    /// updating an agent's metadata URI in place.
    pub const SET_AGENT_URI: [u8; 4] = [0x0a, 0xf2, 0x8b, 0xd3];
    /// `setAgentWallet(uint256,address,uint256,bytes)` — ERC-8004 v0.6+
    /// selector for rebinding an agent's controller wallet, with the
    /// reference contract's `(deadline, signature)` consent pair.
    pub const SET_AGENT_WALLET: [u8; 4] = [0x2d, 0x1e, 0xf5, 0xae];
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

    /// `submitFeedback(bytes32,int8,string)`
    pub const SUBMIT_FEEDBACK: [u8; 4] = [0x3b, 0x2d, 0x6e, 0x41];
    /// `getFeedback(bytes32,uint256)` — read selector for indexed lookup
    /// of a single feedback entry against `(subject_agent_id, index)`.
    pub const GET_FEEDBACK: [u8; 4] = [0x7c, 0x9d, 0x4f, 0x52];
    /// `getFeedbackCount(bytes32)` — read selector returning the number
    /// of feedback entries recorded against a subject agent.
    pub const GET_FEEDBACK_COUNT: [u8; 4] = [0x4e, 0x71, 0xa2, 0x18];
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
    pub const GET_VALIDATION: [u8; 4] = [0x9b, 0x2e, 0x4f, 0x33];
}

/// An ERC-8004 agent record as returned by `getAgent()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRecord {
    pub agent_id: [u8; 32],
    pub agent_address: EthAddress,
    pub metadata_uri: String,
}

/// Feedback entry submitted via the reputation registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    pub subject_agent_id: [u8; 32],
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
    /// `agentId` of the subject as a `uint256` (high-byte first when
    /// projected into 32 bytes; we keep the full word for fidelity with
    /// the on-chain register).
    pub agent_id: [u8; 32],
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

/// Derive a canonical ERC-8004 `agentId` from a Tenzro DID.
///
/// `agentId = keccak256(utf8(did_string))`. This is collision-resistant
/// and deterministic across clients.
pub fn derive_agent_id(did_string: &str) -> [u8; 32] {
    keccak256(did_string.as_bytes()).to_bytes()
}

/// Minimal ABI encoder for the handful of ERC-8004 function shapes we
/// need. Not a general-purpose ABI encoder — just enough to build
/// calldata for `registerAgent`, `submitFeedback`, `validationRequest`,
/// and `validationResponse`.
pub mod abi {
    use super::EthAddress;

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

    /// `registerAgent(bytes32 agentId, address agentAddress, string metadataUri)`
    pub fn encode_register_agent(
        selector: [u8; 4],
        agent_id: &[u8; 32],
        agent_address: &EthAddress,
        metadata_uri: &str,
    ) -> Vec<u8> {
        // Head: selector | agent_id | address (padded to 32) | offset-to-string
        let mut data = Vec::with_capacity(4 + 3 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
        data.extend_from_slice(&pad32_left(agent_address));
        // offset-to-string = 3 words after the head (agent_id, address, offset)
        data.extend_from_slice(&pad32_left(&(96u64).to_be_bytes()));
        // Tail: length + data
        data.extend_from_slice(&encode_bytes_tail(metadata_uri.as_bytes()));
        data
    }

    /// `getAgent(bytes32)`
    pub fn encode_get_agent(selector: [u8; 4], agent_id: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
        data
    }

    /// `submitFeedback(bytes32 subject, int8 rating, string contextUri)`
    ///
    /// `int8` encodes as 32-byte two's complement. For the small
    /// negative values (-128..=-1) we sign-extend with 0xff.
    pub fn encode_submit_feedback(
        selector: [u8; 4],
        subject: &[u8; 32],
        rating: i8,
        context_uri: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 3 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(subject);

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
        agent_id: &[u8; 32],
        request_uri: &str,
        request_hash: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 4 * 32 + request_uri.len().div_ceil(32) * 32 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(&pad32_left(validator_address));
        data.extend_from_slice(agent_id);
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

    /// `getFeedback(bytes32 subject, uint256 index)` — read-only.
    pub fn encode_get_feedback(
        selector: [u8; 4],
        subject: &[u8; 32],
        index: u128,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 2 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(subject);
        let mut idx_word = [0u8; 32];
        idx_word[16..32].copy_from_slice(&index.to_be_bytes());
        data.extend_from_slice(&idx_word);
        data
    }

    /// `getFeedbackCount(bytes32 subject)` — read-only.
    pub fn encode_get_feedback_count(selector: [u8; 4], subject: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(subject);
        data
    }

    /// `revokeFeedback(uint256 agentId, bytes32 feedbackId)` per ERC-8004
    /// v0.6+. Both arguments are static 32-byte words, so the calldata
    /// is a flat `[selector | agent_id | feedback_id]` (4 + 64 bytes).
    pub fn encode_revoke_feedback(
        selector: [u8; 4],
        agent_id: &[u8; 32],
        feedback_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 2 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
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
        agent_id: &[u8; 32],
        feedback_id: &[u8; 32],
        response_uri: &str,
    ) -> Vec<u8> {
        let tail = encode_bytes_tail(response_uri.as_bytes());
        let mut data = Vec::with_capacity(4 + 3 * 32 + tail.len());
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
        data.extend_from_slice(feedback_id);
        // offset-to-response-uri = 3 head slots × 32 = 96
        data.extend_from_slice(&pad32_left(&(96u64).to_be_bytes()));
        data.extend_from_slice(&tail);
        data
    }

    /// `getAgentURI(uint256 agentId)` — ERC-8004 v0.6+ read. Static
    /// 32-byte argument, so calldata is `[selector | agent_id]`.
    pub fn encode_get_agent_uri(selector: [u8; 4], agent_id: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
        data
    }

    /// `getAgentWallet(uint256 agentId)` — ERC-8004 v0.6+ read. Static
    /// 32-byte argument, so calldata is `[selector | agent_id]`.
    pub fn encode_get_agent_wallet(selector: [u8; 4], agent_id: &[u8; 32]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
        data
    }

    /// `isFeedbackRevoked(uint256 agentId, bytes32 feedbackId)` —
    /// ERC-8004 v0.6+ read. Both arguments are static 32-byte words, so
    /// the calldata is a flat `[selector | agent_id | feedback_id]`.
    pub fn encode_is_feedback_revoked(
        selector: [u8; 4],
        agent_id: &[u8; 32],
        feedback_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 2 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
        data.extend_from_slice(feedback_id);
        data
    }

    /// `getFeedbackResponses(uint256 agentId, bytes32 feedbackId)` —
    /// ERC-8004 v0.6+ read. Same shape as `isFeedbackRevoked`.
    pub fn encode_get_feedback_responses(
        selector: [u8; 4],
        agent_id: &[u8; 32],
        feedback_id: &[u8; 32],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 2 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
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
        agent_id: &[u8; 32],
        metadata_uri: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 64 + 32 + metadata_uri.len().div_ceil(32) * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
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
        agent_id: &[u8; 32],
        new_wallet: &EthAddress,
        deadline: u128,
        signature: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 4 * 32 + 32 + signature.len().div_ceil(32) * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
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
        agent_id: &[u8; 32],
        metadata_key: &str,
        metadata_value: &[u8],
    ) -> Vec<u8> {
        let key_block = 32 + metadata_key.len().div_ceil(32) * 32;
        let value_offset = 96 + key_block;
        let value_block = 32 + metadata_value.len().div_ceil(32) * 32;
        let mut data = Vec::with_capacity(4 + 96 + key_block + value_block);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
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
        agent_id: &[u8; 32],
        metadata_key: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 64 + 32 + metadata_key.len().div_ceil(32) * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(agent_id);
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
        /// `agentId` of the subject.
        pub agent_id: [u8; 32],
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
        // Slot 1: agent_id (raw 32 bytes).
        let mut agent_id = [0u8; 32];
        agent_id.copy_from_slice(&data[32..64]);
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

    /// Decode the return of `getAgent(bytes32)` →
    /// `(address, string, bytes32?)`. We tolerate both the 3-slot
    /// (address, string-offset, metadataHash) and 2-slot layouts found
    /// across published ERC-8004 drafts.
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

    /// Build the calldata for `registerAgent`. Submission requires a
    /// signed transaction, which is the caller's responsibility (the
    /// wallet-binding signer in `tenzro-wallet`).
    pub fn build_register_agent_calldata(
        &self,
        agent_id: &[u8; 32],
        agent_address: &EthAddress,
        metadata_uri: &str,
    ) -> Vec<u8> {
        abi::encode_register_agent(
            selectors::REGISTER_AGENT,
            agent_id,
            agent_address,
            metadata_uri,
        )
    }

    /// Look up an agent by its `agentId`.
    pub async fn get_agent(&self, agent_id: &[u8; 32]) -> Result<AgentRecord> {
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
            agent_id: *agent_id,
            agent_address: addr,
            metadata_uri: uri,
        })
    }

    /// Build calldata for a feedback submission.
    pub fn build_submit_feedback_calldata(&self, entry: &FeedbackEntry) -> Vec<u8> {
        abi::encode_submit_feedback(
            selectors::SUBMIT_FEEDBACK,
            &entry.subject_agent_id,
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
        agent_id: &[u8; 32],
        feedback_id: &[u8; 32],
    ) -> Vec<u8> {
        abi::encode_revoke_feedback(selectors::REVOKE_FEEDBACK, agent_id, feedback_id)
    }

    /// Build calldata for `appendResponse(uint256 agentId, bytes32 feedbackId, string responseUri)`
    /// per ERC-8004 v0.6+. Lets the rated agent attach (or replace) a
    /// response URI on a feedback entry.
    pub fn build_append_response_calldata(
        &self,
        agent_id: &[u8; 32],
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
            &request.agent_id,
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
    /// Wraps the `getFeedback(bytes32,uint256)` read selector at the
    /// ReputationRegistry. Returns the entry plus its `exists` flag —
    /// callers should treat `exists == false` as "no entry at this
    /// index" rather than a transport failure.
    pub async fn get_feedback(
        &self,
        subject_agent_id: &[u8; 32],
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
                subject_agent_id: *subject_agent_id,
                rating,
                context_uri,
            },
            exists,
        ))
    }

    /// Return the count of feedback entries against a subject agent.
    ///
    /// Wraps the `getFeedbackCount(bytes32)` read selector at the
    /// ReputationRegistry.
    pub async fn get_feedback_count(&self, subject_agent_id: &[u8; 32]) -> Result<u128> {
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
        agent_id: &[u8; 32],
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
        agent_id: &[u8; 32],
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
        agent_id: &[u8; 32],
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
        agent_id: &[u8; 32],
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
    pub async fn get_agent_uri(&self, agent_id: &[u8; 32]) -> Result<String> {
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
    pub async fn get_agent_wallet(&self, agent_id: &[u8; 32]) -> Result<EthAddress> {
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
        agent_id: &[u8; 32],
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
        agent_id: &[u8; 32],
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

    #[test]
    fn derive_agent_id_is_deterministic() {
        let a = derive_agent_id("did:tenzro:machine:test");
        let b = derive_agent_id("did:tenzro:machine:test");
        assert_eq!(a, b);
        let c = derive_agent_id("did:tenzro:machine:other");
        assert_ne!(a, c);
    }

    #[test]
    fn encode_register_agent_has_selector_prefix() {
        let data = abi::encode_register_agent(
            selectors::REGISTER_AGENT,
            &[7u8; 32],
            &[8u8; 20],
            "ipfs://cid",
        );
        assert_eq!(&data[0..4], &selectors::REGISTER_AGENT);
        // 4 selector + 3 head words (agent_id + address + offset)
        // + 1 length word + 1 data word (10 chars pad-to-32)
        assert_eq!(data.len(), 4 + 3 * 32 + 32 + 32);
    }

    #[test]
    fn encode_submit_feedback_sign_extends_negative_rating() {
        let data = abi::encode_submit_feedback(
            selectors::SUBMIT_FEEDBACK,
            &[9u8; 32],
            -50,
            "ctx",
        );
        // Rating word starts at offset 4 + 32 = 36. Sign-extended
        // 0xff bytes should precede the int8 byte.
        assert_eq!(data[36..67], [0xff; 31]);
        assert_eq!(data[67], (-50i8) as u8);
    }

    #[test]
    fn decode_get_agent_roundtrip() {
        // Build a pretend return: (address, offset-to-string, string)
        let mut ret = Vec::new();
        ret.extend_from_slice(&[0u8; 12]);
        ret.extend_from_slice(&[0xab; 20]); // address
        // offset = 64 (points to length word right after the header)
        let mut offset = [0u8; 32];
        offset[31] = 64;
        ret.extend_from_slice(&offset);
        // length = 10
        let mut len = [0u8; 32];
        len[31] = 10;
        ret.extend_from_slice(&len);
        ret.extend_from_slice(b"ipfs://abc");
        ret.extend_from_slice(&[0u8; 22]); // pad to 32

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

        let adapter = Erc8004Adapter::new(
            MockTransport { agent_return: ret },
            mk_addresses(),
        );
        let record = adapter.get_agent(&[5u8; 32]).await.unwrap();
        assert_eq!(record.agent_address, [0xab; 20]);
        assert_eq!(record.metadata_uri, "hello");
        assert_eq!(record.agent_id, [5u8; 32]);
    }

    // -- read-selector parity with EVM precompile (0x101b / 0x101c) --

    #[test]
    fn read_selectors_are_distinct_from_writes() {
        // Sanity: the read selectors must not collide with the write
        // selectors. (Selector collisions would produce silent dispatch
        // errors in the precompile.) Includes the v0.6+ identity-side
        // mutators (setAgentURI / setAgentWallet / setMetadata /
        // getMetadata) and the v0.6+ reputation-side mutators
        // (revokeFeedback / appendResponse) added alongside the original
        // ERC-8004 surface.
        let all = [
            selectors::REGISTER_AGENT,
            selectors::GET_AGENT,
            selectors::SET_AGENT_URI,
            selectors::SET_AGENT_WALLET,
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
    fn encode_get_feedback_layout() {
        let data = abi::encode_get_feedback(selectors::GET_FEEDBACK, &[7u8; 32], 42);
        // selector + 32 (subject) + 32 (uint256 index)
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[0..4], &selectors::GET_FEEDBACK);
        assert_eq!(&data[4..36], &[7u8; 32]);
        // index = 42 lives at the very last byte (big-endian uint256)
        assert_eq!(data[67], 42);
    }

    #[test]
    fn decode_get_feedback_round_trips_precompile_shape() {
        // Build the exact wire layout the precompile produces:
        //   [0..32]   rating (int8 sign-extended)
        //   [32..64]  offset to string = 96
        //   [64..96]  exists
        //   [96..128] string length
        //   [128..]   string data (zero-padded to 32-byte boundary)
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
        // u256 = 1234567 in last 16 bytes
        ret[16..32].copy_from_slice(&1_234_567u128.to_be_bytes());
        let count = abi::decode_get_feedback_count(&ret).unwrap();
        assert_eq!(count, 1_234_567);
    }

    #[test]
    fn decode_get_validation_round_trips_precompile_shape() {
        // Mirror the precompile's `getValidation` 7-slot head layout
        // matching ERC-8004 `validationRequest` + `validationResponse`.
        let validator = [0x99u8; 20];
        let agent_id = [0x42u8; 32];
        let request_uri = "ipfs://task";
        let response_uri = "ipfs://proof-doc";
        let tag = "valid";
        let response: u8 = 87; // 0..=100 score

        // Head = 7 slots × 32 = 224 bytes.
        // request_uri tail starts at 224.
        let request_padded = request_uri.len().div_ceil(32) * 32;
        let request_block = 32 + request_padded;
        // response_uri tail starts after request block.
        let response_uri_offset = 224 + request_block;
        let response_padded = response_uri.len().div_ceil(32) * 32;
        let response_block = 32 + response_padded;
        // tag tail starts after response block.
        let tag_offset = response_uri_offset + response_block;
        let tag_padded = tag.len().div_ceil(32) * 32;
        let total_len = tag_offset + 32 + tag_padded;

        let mut ret = vec![0u8; total_len];
        // Slot 0: validator (left-padded address)
        ret[12..32].copy_from_slice(&validator);
        // Slot 1: agent_id
        ret[32..64].copy_from_slice(&agent_id);
        // Slot 2: response (low byte)
        ret[95] = response;
        // Slot 3: offset to request_uri = 224
        ret[96 + 24..128].copy_from_slice(&224u64.to_be_bytes());
        // Slot 4: offset to response_uri
        ret[128 + 24..160].copy_from_slice(&(response_uri_offset as u64).to_be_bytes());
        // Slot 5: offset to tag
        ret[160 + 24..192].copy_from_slice(&(tag_offset as u64).to_be_bytes());
        // Slot 6: exists = true
        ret[223] = 1;

        // Tails
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
        assert_eq!(decoded.agent_id, agent_id);
        assert_eq!(decoded.response, response);
        assert_eq!(decoded.request_uri, request_uri);
        assert_eq!(decoded.response_uri, response_uri);
        assert_eq!(decoded.tag, tag);
        assert!(decoded.exists);
    }

    // -- ERC-8004 v0.6+ identity-side mutators --

    #[test]
    fn encode_set_agent_uri_layout() {
        let agent_id = [0x42u8; 32];
        let uri = "ipfs://updated-cid";
        let data = abi::encode_set_agent_uri(selectors::SET_AGENT_URI, &agent_id, uri);
        // selector + agent_id + offset + length + padded data
        assert_eq!(&data[0..4], &selectors::SET_AGENT_URI);
        assert_eq!(&data[4..36], &agent_id);
        // offset = 64 in last byte of word
        assert_eq!(data[67], 64);
        // length lives in [4 + 64 .. 4 + 96]
        assert_eq!(data[4 + 64 + 31] as usize, uri.len());
        // string starts at 4 + 96
        assert_eq!(&data[4 + 96..4 + 96 + uri.len()], uri.as_bytes());
    }

    #[test]
    fn encode_set_agent_wallet_layout() {
        let agent_id = [0x11u8; 32];
        let new_wallet = [0x22u8; 20];
        let signature = vec![0xaa; 65]; // typical secp256k1 sig length
        let data = abi::encode_set_agent_wallet(
            selectors::SET_AGENT_WALLET,
            &agent_id,
            &new_wallet,
            42,
            &signature,
        );
        assert_eq!(&data[0..4], &selectors::SET_AGENT_WALLET);
        assert_eq!(&data[4..36], &agent_id);
        // new_wallet left-padded into [4 + 32 .. 4 + 64]; address bytes
        // live at [4 + 32 + 12 .. 4 + 32 + 32]
        assert_eq!(&data[4 + 32 + 12..4 + 32 + 32], &new_wallet);
        // deadline = 42 lives at [4 + 64 .. 4 + 96]
        assert_eq!(data[4 + 64 + 31], 42);
        // sig offset = 128 lives at [4 + 96 .. 4 + 128]
        assert_eq!(data[4 + 96 + 31], 128);
        // sig length at [4 + 128 .. 4 + 160] last byte
        assert_eq!(data[4 + 128 + 31] as usize, signature.len());
        // sig data at [4 + 160 ..]
        assert_eq!(
            &data[4 + 160..4 + 160 + signature.len()],
            signature.as_slice(),
        );
    }

    #[test]
    fn encode_set_metadata_packs_key_then_value() {
        let agent_id = [0x33u8; 32];
        let key = "skills";
        let value: &[u8] = b"forecast,vision";
        let data = abi::encode_set_metadata(selectors::SET_METADATA, &agent_id, key, value);
        assert_eq!(&data[0..4], &selectors::SET_METADATA);
        assert_eq!(&data[4..36], &agent_id);
        // key offset = 96
        assert_eq!(data[4 + 32 + 31], 96);
        // value offset = 96 + 32 + ceil(key_len/32)*32 = 96 + 32 + 32 = 160
        assert_eq!(data[4 + 64 + 31], 160);
        // key length at [4 + 96 .. 4 + 128] last byte
        assert_eq!(data[4 + 96 + 31] as usize, key.len());
        // key data starts at 4 + 128
        assert_eq!(&data[4 + 128..4 + 128 + key.len()], key.as_bytes());
        // value length at [4 + 160 + 32 .. ] = 4 + 192
        assert_eq!(data[4 + 160 + 31] as usize, value.len());
        // value data at 4 + 192
        assert_eq!(&data[4 + 192..4 + 192 + value.len()], value);
    }

    #[test]
    fn encode_set_metadata_with_empty_value() {
        let agent_id = [0u8; 32];
        let key = "drop";
        let data = abi::encode_set_metadata(selectors::SET_METADATA, &agent_id, key, &[]);
        // key offset = 96, value offset = 160, value length = 0
        assert_eq!(data[4 + 32 + 31], 96);
        assert_eq!(data[4 + 64 + 31], 160);
        // value length lives at [4 + 160 + 0 .. 4 + 192] last byte (empty
        // means no data tail past length word)
        assert_eq!(data[4 + 160 + 31], 0);
    }

    #[test]
    fn encode_get_metadata_layout() {
        let agent_id = [0x44u8; 32];
        let key = "skills";
        let data = abi::encode_get_metadata(selectors::GET_METADATA, &agent_id, key);
        assert_eq!(&data[0..4], &selectors::GET_METADATA);
        assert_eq!(&data[4..36], &agent_id);
        // offset = 64
        assert_eq!(data[4 + 32 + 31], 64);
        // key length lives at [4 + 64 .. 4 + 96] last byte
        assert_eq!(data[4 + 64 + 31] as usize, key.len());
        // key data starts at 4 + 96
        assert_eq!(&data[4 + 96..4 + 96 + key.len()], key.as_bytes());
    }

    #[test]
    fn decode_get_metadata_round_trips_precompile_shape() {
        // Build the wire shape the precompile produces:
        //   [0..32]   offset = 32
        //   [32..64]  length
        //   [64..]    bytes (zero-padded to 32-byte boundary)
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
        // Wire shape for an unset entry: offset=32, length=0, no tail.
        let mut ret = vec![0u8; 64];
        ret[31] = 32; // offset
        // length at [32..64] left at zero
        let decoded = abi::decode_get_metadata(&ret).expect("must decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_revoke_feedback_layout() {
        let agent_id = [0xa1u8; 32];
        let feedback_id = [0xb2u8; 32];
        let data = abi::encode_revoke_feedback(
            selectors::REVOKE_FEEDBACK,
            &agent_id,
            &feedback_id,
        );
        // selector + agent_id (32) + feedback_id (32) — both static, no tail
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[0..4], &selectors::REVOKE_FEEDBACK);
        assert_eq!(&data[4..36], &agent_id);
        assert_eq!(&data[36..68], &feedback_id);
    }

    #[test]
    fn encode_append_response_layout() {
        let agent_id = [0xc3u8; 32];
        let feedback_id = [0xd4u8; 32];
        let response = "ipfs://defense";
        let data = abi::encode_append_response(
            selectors::APPEND_RESPONSE,
            &agent_id,
            &feedback_id,
            response,
        );
        // Head: selector + agent_id (32) + feedback_id (32) + offset (32) = 4 + 96
        assert_eq!(&data[0..4], &selectors::APPEND_RESPONSE);
        assert_eq!(&data[4..36], &agent_id);
        assert_eq!(&data[36..68], &feedback_id);
        // Offset slot: last byte = 96
        assert_eq!(data[99], 96);
        // Length slot at [100..132]: last byte = response.len()
        assert_eq!(data[131], response.len() as u8);
        // String bytes start at 132
        assert_eq!(&data[132..132 + response.len()], response.as_bytes());
        // Total length = 4 + 3*32 + 32 (length) + ceil(len/32)*32
        let pad = response.len().div_ceil(32) * 32;
        assert_eq!(data.len(), 4 + 96 + 32 + pad);
    }

    #[test]
    fn encode_append_response_with_empty_uri() {
        // Empty response URI is allowed at the wire level — the
        // precompile treats it as "set response to empty string", which
        // (per v0.6 spec) effectively clears any previously-attached
        // response. The encoder should still produce the canonical
        // layout (offset=96, length=0, no tail).
        let agent_id = [0u8; 32];
        let feedback_id = [0u8; 32];
        let data = abi::encode_append_response(
            selectors::APPEND_RESPONSE,
            &agent_id,
            &feedback_id,
            "",
        );
        // selector + 3*32 head + 32 length, no tail
        assert_eq!(data.len(), 4 + 96 + 32);
        // length slot at [100..132] is all zero
        assert_eq!(&data[100..132], &[0u8; 32]);
    }

    #[test]
    fn revoke_and_append_selectors_match_canonical_keccak() {
        // Pin the v0.6+ selectors so the adapter↔precompile contract
        // stays byte-identical. Drift here would silently break the
        // Tenzro-side ReputationRegistry mutators.
        assert_eq!(selectors::REVOKE_FEEDBACK, [0xa2, 0x83, 0x34, 0xce]);
        assert_eq!(selectors::APPEND_RESPONSE, [0x60, 0x1f, 0x56, 0x76]);
    }

    // -- ERC-8004 v0.6+ read selectors (getAgentURI / getAgentWallet /
    //    isFeedbackRevoked / getFeedbackResponses) --

    #[test]
    fn v06_read_selectors_match_canonical_keccak() {
        // Byte-identical pinning between adapter and precompile so the
        // same calldata works against either dispatcher.
        assert_eq!(selectors::GET_AGENT_URI, [0xce, 0x91, 0xae, 0xde]);
        assert_eq!(selectors::GET_AGENT_WALLET, [0x00, 0x33, 0x95, 0x09]);
        assert_eq!(selectors::IS_FEEDBACK_REVOKED, [0xb0, 0x17, 0xcb, 0x04]);
        assert_eq!(selectors::GET_FEEDBACK_RESPONSES, [0xcc, 0x84, 0x63, 0x3b]);
    }

    #[test]
    fn encode_get_agent_uri_layout() {
        let agent_id = [0x55u8; 32];
        let data = abi::encode_get_agent_uri(selectors::GET_AGENT_URI, &agent_id);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(&data[0..4], &selectors::GET_AGENT_URI);
        assert_eq!(&data[4..36], &agent_id);
    }

    #[test]
    fn encode_get_agent_wallet_layout() {
        let agent_id = [0x66u8; 32];
        let data = abi::encode_get_agent_wallet(selectors::GET_AGENT_WALLET, &agent_id);
        assert_eq!(data.len(), 4 + 32);
        assert_eq!(&data[0..4], &selectors::GET_AGENT_WALLET);
        assert_eq!(&data[4..36], &agent_id);
    }

    #[test]
    fn encode_is_feedback_revoked_layout() {
        let agent_id = [0x77u8; 32];
        let feedback_id = [0x88u8; 32];
        let data = abi::encode_is_feedback_revoked(
            selectors::IS_FEEDBACK_REVOKED,
            &agent_id,
            &feedback_id,
        );
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[0..4], &selectors::IS_FEEDBACK_REVOKED);
        assert_eq!(&data[4..36], &agent_id);
        assert_eq!(&data[36..68], &feedback_id);
    }

    #[test]
    fn encode_get_feedback_responses_layout() {
        let agent_id = [0x99u8; 32];
        let feedback_id = [0xaau8; 32];
        let data = abi::encode_get_feedback_responses(
            selectors::GET_FEEDBACK_RESPONSES,
            &agent_id,
            &feedback_id,
        );
        assert_eq!(data.len(), 4 + 64);
        assert_eq!(&data[0..4], &selectors::GET_FEEDBACK_RESPONSES);
        assert_eq!(&data[4..36], &agent_id);
        assert_eq!(&data[36..68], &feedback_id);
    }

    #[test]
    fn decode_get_agent_uri_round_trips_precompile_shape() {
        // Wire shape: [offset = 32 | length | utf8 padded].
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
        // offset=32, length=0
        let mut ret = vec![0u8; 64];
        ret[31] = 32;
        let decoded = abi::decode_get_agent_uri(&ret).expect("must decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_get_agent_wallet_round_trips_precompile_shape() {
        // Single 32-byte left-padded address word.
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
