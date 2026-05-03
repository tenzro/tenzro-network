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
//! | `VerifiableCredential` (attestation) | `ValidationRegistry.submitValidation()` |
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
pub mod selectors {
    /// `registerAgent(bytes32,address,string)`
    pub const REGISTER_AGENT: [u8; 4] = [0xaa, 0xa3, 0x8f, 0x6c];
    /// `getAgent(bytes32)`
    pub const GET_AGENT: [u8; 4] = [0xdb, 0x4a, 0x7a, 0x9a];
    /// `submitFeedback(bytes32,int8,string)`
    pub const SUBMIT_FEEDBACK: [u8; 4] = [0x3b, 0x2d, 0x6e, 0x41];
    /// `requestValidation(bytes32,bytes32,string)`
    pub const REQUEST_VALIDATION: [u8; 4] = [0x1a, 0x8f, 0x2c, 0x7b];
    /// `submitValidation(bytes32,bool,string)`
    pub const SUBMIT_VALIDATION: [u8; 4] = [0x5c, 0x9e, 0x3d, 0x81];
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

/// A validation request lifecycle object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRequest {
    pub request_id: [u8; 32],
    pub subject_agent_id: [u8; 32],
    pub work_hash: [u8; 32],
    pub metadata_uri: String,
}

/// The result a validator submits for a validation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub request_id: [u8; 32],
    pub valid: bool,
    pub proof_uri: String,
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
/// calldata for `registerAgent`, `submitFeedback`, `requestValidation`,
/// and `submitValidation`.
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

    /// `requestValidation(bytes32 subject, bytes32 workHash, string metadataUri)`
    pub fn encode_request_validation(
        selector: [u8; 4],
        subject: &[u8; 32],
        work_hash: &[u8; 32],
        metadata_uri: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 3 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(subject);
        data.extend_from_slice(work_hash);
        data.extend_from_slice(&pad32_left(&(96u64).to_be_bytes()));
        data.extend_from_slice(&encode_bytes_tail(metadata_uri.as_bytes()));
        data
    }

    /// `submitValidation(bytes32 requestId, bool valid, string proofUri)`
    pub fn encode_submit_validation(
        selector: [u8; 4],
        request_id: &[u8; 32],
        valid: bool,
        proof_uri: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 3 * 32);
        data.extend_from_slice(&selector);
        data.extend_from_slice(request_id);
        let mut bool_word = [0u8; 32];
        bool_word[31] = if valid { 1 } else { 0 };
        data.extend_from_slice(&bool_word);
        data.extend_from_slice(&pad32_left(&(96u64).to_be_bytes()));
        data.extend_from_slice(&encode_bytes_tail(proof_uri.as_bytes()));
        data
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

    /// Build calldata for a validation request.
    pub fn build_request_validation_calldata(
        &self,
        subject_agent_id: &[u8; 32],
        work_hash: &[u8; 32],
        metadata_uri: &str,
    ) -> Vec<u8> {
        abi::encode_request_validation(
            selectors::REQUEST_VALIDATION,
            subject_agent_id,
            work_hash,
            metadata_uri,
        )
    }

    /// Build calldata for a validator to accept/reject a request.
    pub fn build_submit_validation_calldata(&self, result: &ValidationResult) -> Vec<u8> {
        abi::encode_submit_validation(
            selectors::SUBMIT_VALIDATION,
            &result.request_id,
            result.valid,
            &result.proof_uri,
        )
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
}
