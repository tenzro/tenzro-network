//! ERC-8004 System Contracts (Trustless Agents)
//!
//! Three native precompile registries that mirror the ERC-8004 reference
//! contracts on Ethereum, with byte-identical function selectors so the
//! same calldata works whether a caller targets Tenzro's native registry
//! or the Ethereum mirror via [`tenzro_identity::erc8004`].
//!
//! - **0x101a — IdentityRegistry**: `registerAgent` / `getAgent` for native
//!   Tenzro agent discovery.
//! - **0x101b — ReputationRegistry**: `submitFeedback` / `getFeedback` for
//!   peer-to-peer agent reputation.
//! - **0x101c — ValidationRegistry**: `validationRequest` / `validationResponse`
//!   / `getValidation` for verifiable agent work attestation.
//!
//! `agentId` is derived deterministically from a Tenzro DID:
//! `agentId = keccak256(utf8(did_string))`. The same derivation is used by
//! [`tenzro_identity::erc8004::derive_agent_id`] so an agent registered on
//! Tenzro is addressable on Ethereum (and vice-versa) without a separate
//! mapping table.

use crate::error::Result;
use crate::evm::wtnzo::abi;
use crate::precompiles::PrecompileResult;
use crate::VmError;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Gas constants
// ---------------------------------------------------------------------------

/// Gas cost for registering or updating an agent in IdentityRegistry
const GAS_REGISTER_AGENT: u64 = 80_000;
/// Gas cost for updating just the metadata URI on an existing agent.
const GAS_SET_AGENT_URI: u64 = 30_000;
/// Gas cost for rebinding an agent's controller wallet — heavier than a
/// metadata-only update because the caller passes a deadline+signature
/// payload that the reference contract verifies on-chain. Tenzro
/// charges the same gas envelope so callers see identical economics
/// whether they target the precompile or the Ethereum mirror.
const GAS_SET_AGENT_WALLET: u64 = 50_000;
/// Gas cost for writing a single metadata `(key, value)` pair against
/// an agent.
const GAS_SET_METADATA: u64 = 30_000;
/// Gas cost for submitting a feedback entry to ReputationRegistry
const GAS_SUBMIT_FEEDBACK: u64 = 60_000;
/// Gas cost for revoking a previously-submitted feedback entry
/// (`revokeFeedback` per ERC-8004 v0.6+). Cheaper than submit because
/// it only flips a flag on an existing record.
const GAS_REVOKE_FEEDBACK: u64 = 30_000;
/// Gas cost for attaching a response URI to a feedback entry
/// (`appendResponse` per ERC-8004 v0.6+). Same envelope as submit since
/// both write a UTF-8 string.
const GAS_APPEND_RESPONSE: u64 = 50_000;
/// Gas cost for opening a validation request (`validationRequest`).
const GAS_VALIDATION_REQUEST: u64 = 60_000;
/// Gas cost for submitting a validation response (`validationResponse`).
const GAS_VALIDATION_RESPONSE: u64 = 60_000;
/// Gas cost for read-only queries
const GAS_READ: u64 = 2_600;

// ---------------------------------------------------------------------------
// Function selectors (byte-identical to tenzro_identity::erc8004::selectors)
// ---------------------------------------------------------------------------

/// `registerAgent(bytes32 agentId, address agentAddress, string metadataUri)`
const SELECTOR_REGISTER_AGENT: [u8; 4] = [0xaa, 0xa3, 0x8f, 0x6c];
/// `getAgent(bytes32 agentId)`
const SELECTOR_GET_AGENT: [u8; 4] = [0xdb, 0x4a, 0x7a, 0x9a];
/// `setAgentURI(uint256 agentId, string metadataUri)` per ERC-8004 v0.6+.
/// Selector = `bytes4(keccak256("setAgentURI(uint256,string)"))` =
/// `0x0af28bd3`. Updates the metadata URI on an already-registered
/// agent without rebinding the wallet.
const SELECTOR_SET_AGENT_URI: [u8; 4] = [0x0a, 0xf2, 0x8b, 0xd3];
/// `setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature)`
/// per ERC-8004 v0.6+.
/// Selector = `bytes4(keccak256("setAgentWallet(uint256,address,uint256,bytes)"))`
/// = `0x2d1ef5ae`. Rebinds the controller wallet on an
/// already-registered agent. The `deadline + signature` pair is the
/// reference contract's EIP-712 consent proof; the Tenzro precompile
/// trusts the surrounding transaction's `from` field for authorization
/// (the outer EVM caller is auditable), but accepts the trailing pair
/// so callers can emit byte-identical calldata for both targets.
const SELECTOR_SET_AGENT_WALLET: [u8; 4] = [0x2d, 0x1e, 0xf5, 0xae];
/// `setMetadata(uint256 agentId, string metadataKey, bytes metadataValue)`
/// per ERC-8004 v0.6+.
/// Selector = `bytes4(keccak256("setMetadata(uint256,string,bytes)"))` =
/// `0x466648da`. Writes one `(key → value)` pair against an agent. An
/// empty `metadataValue` deletes the entry, matching the reference
/// contract's "set to empty = clear" convention.
const SELECTOR_SET_METADATA: [u8; 4] = [0x46, 0x66, 0x48, 0xda];
/// `getMetadata(uint256 agentId, string metadataKey)` per ERC-8004
/// v0.6+. Selector = `bytes4(keccak256("getMetadata(uint256,string)"))`
/// = `0xcb4799f2`. Reads back the bytes stored under
/// `(agentId, metadataKey)`; returns an empty bytestring if the entry
/// doesn't exist.
const SELECTOR_GET_METADATA: [u8; 4] = [0xcb, 0x47, 0x99, 0xf2];
/// `getAgentURI(uint256 agentId)` per ERC-8004 v0.6+. Selector =
/// `bytes4(keccak256("getAgentURI(uint256)"))` = `0xce91aede`. Returns
/// the metadata URI stored against an agent, or empty string if the
/// agent isn't registered. Pairs with `setAgentURI`.
const SELECTOR_GET_AGENT_URI: [u8; 4] = [0xce, 0x91, 0xae, 0xde];
/// `getAgentWallet(uint256 agentId)` per ERC-8004 v0.6+. Selector =
/// `bytes4(keccak256("getAgentWallet(uint256)"))` = `0x00339509`.
/// Returns the controller address bound to an agent, or the zero
/// address if the agent isn't registered. Pairs with `setAgentWallet`.
const SELECTOR_GET_AGENT_WALLET: [u8; 4] = [0x00, 0x33, 0x95, 0x09];
/// `submitFeedback(bytes32 subject, int8 rating, string contextUri)`
const SELECTOR_SUBMIT_FEEDBACK: [u8; 4] = [0x3b, 0x2d, 0x6e, 0x41];
/// `getFeedback(bytes32 subject, uint256 index)`
const SELECTOR_GET_FEEDBACK: [u8; 4] = [0x7c, 0x9d, 0x4f, 0x52];
/// `getFeedbackCount(bytes32 subject)`
const SELECTOR_GET_FEEDBACK_COUNT: [u8; 4] = [0x4e, 0x71, 0xa2, 0x18];
/// `revokeFeedback(uint256 agentId, bytes32 feedbackId)` per ERC-8004
/// v0.6+. Selector = `bytes4(keccak256("revokeFeedback(uint256,bytes32)"))`
/// = `0xa28334ce`. Marks an existing feedback entry as revoked without
/// removing it from the append-only log — `getFeedback` continues to
/// return the entry but with `revoked=true`.
const SELECTOR_REVOKE_FEEDBACK: [u8; 4] = [0xa2, 0x83, 0x34, 0xce];
/// `appendResponse(uint256 agentId, bytes32 feedbackId, string responseUri)`
/// per ERC-8004 v0.6+.
/// Selector = `bytes4(keccak256("appendResponse(uint256,bytes32,string)"))`
/// = `0x601f5676`. Lets the rated agent attach a single response URI to
/// a feedback entry. Idempotent overwrite: a second call replaces the
/// stored URI (matches the reference contract's "latest response wins"
/// semantics).
const SELECTOR_APPEND_RESPONSE: [u8; 4] = [0x60, 0x1f, 0x56, 0x76];
/// `isFeedbackRevoked(uint256 agentId, bytes32 feedbackId)` per
/// ERC-8004 v0.6+. Selector =
/// `bytes4(keccak256("isFeedbackRevoked(uint256,bytes32)"))` =
/// `0xb017cb04`. Returns `true` only if the entry exists and has been
/// revoked. Unknown entries return `false` (not an error) — callers
/// should pair with `getFeedbackCount` if they need to distinguish
/// "missing" from "present and not revoked".
const SELECTOR_IS_FEEDBACK_REVOKED: [u8; 4] = [0xb0, 0x17, 0xcb, 0x04];
/// `getFeedbackResponses(uint256 agentId, bytes32 feedbackId)` per
/// ERC-8004 v0.6+. Selector =
/// `bytes4(keccak256("getFeedbackResponses(uint256,bytes32)"))` =
/// `0xcc84633b`. Returns the response URI attached to a feedback entry
/// (empty string if none). Note: the v0.6 spec implies a *list* of
/// responses, but the reference contract only stores the latest, so we
/// surface a single string for round-trip parity with `appendResponse`.
const SELECTOR_GET_FEEDBACK_RESPONSES: [u8; 4] = [0xcc, 0x84, 0x63, 0x3b];
/// `validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)`
/// per ERC-8004. Selector = `bytes4(keccak256("validationRequest(address,uint256,string,bytes32)"))`
/// = `0xaaf400c4`.
const SELECTOR_VALIDATION_REQUEST: [u8; 4] = [0xaa, 0xf4, 0x00, 0xc4];
/// `validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag)`
/// per ERC-8004. Selector = `bytes4(keccak256("validationResponse(bytes32,uint8,string,bytes32,string)"))`
/// = `0x3d659a96`.
const SELECTOR_VALIDATION_RESPONSE: [u8; 4] = [0x3d, 0x65, 0x9a, 0x96];
/// `getValidation(bytes32 requestHash)` — Tenzro-side convenience read.
const SELECTOR_GET_VALIDATION: [u8; 4] = [0x9b, 0x2e, 0x4f, 0x33];

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// On-chain agent record stored in the IdentityRegistry.
#[derive(Debug, Clone)]
pub struct AgentRecord {
    pub agent_id: [u8; 32],
    pub agent_address: [u8; 20],
    pub metadata_uri: String,
}

/// One feedback entry on a subject agent.
///
/// `feedback_id` is derived inside `Erc8004ReputationRegistry::submit`
/// as `keccak256(subject ‖ index_be(8) ‖ context_uri)` and is what the
/// v0.6+ `revokeFeedback` / `appendResponse` selectors look up by. The
/// older index-based reads (`getFeedback(subject, index)`) keep working
/// because the per-subject `Vec` is preserved alongside.
///
/// `revoked` is set by `revokeFeedback`; the entry stays in the log
/// because the registry is append-only — readers should treat
/// `revoked=true` as "withdrawn by the rater".
///
/// `response_uri` is set by the rated agent via `appendResponse`. Empty
/// string means no response has been attached.
#[derive(Debug, Clone)]
pub struct FeedbackEntry {
    pub subject: [u8; 32],
    pub rater: [u8; 20],
    pub rating: i8,
    pub context_uri: String,
    pub feedback_id: [u8; 32],
    pub revoked: bool,
    pub response_uri: String,
}

/// On-chain validation entry — opened with `validationRequest`, closed
/// by a validator with `validationResponse`.
///
/// Storage key is the caller-supplied `request_hash` (32-byte commitment
/// over the work being attested to). The entry starts with the response
/// half empty: `response = 0`, `response_uri.is_empty()`,
/// `response_hash == [0u8; 32]`, `tag.is_empty()`. A
/// `validationResponse` call fills these fields. `responded` flips to
/// `true` when a validator responds; further responses on the same
/// `request_hash` are rejected to keep the registry append-only.
#[derive(Debug, Clone)]
pub struct ValidationEntry {
    /// Validator address that was named in the request.
    pub validator_address: [u8; 20],
    /// `agentId` of the subject (uint256 word).
    pub agent_id: [u8; 32],
    /// Resolvable pointer to the work being validated.
    pub request_uri: String,
    /// 32-byte commitment over the work; storage key.
    pub request_hash: [u8; 32],
    /// 0..=100 quality score. Meaningful only when `responded == true`.
    pub response: u8,
    /// Pointer at proof material (ZK proof CID, TEE quote CID, etc.).
    pub response_uri: String,
    /// 32-byte commitment over the response payload.
    pub response_hash: [u8; 32],
    /// Categorical label (e.g. `"valid"`, `"invalid"`, `"abstain"`).
    pub tag: String,
    /// `true` once a `validationResponse` has been recorded.
    pub responded: bool,
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

/// Native Tenzro IdentityRegistry — maps `agentId -> AgentRecord` plus a
/// per-agent `(key → value)` metadata KV store covering the
/// `setMetadata` / `getMetadata` selectors introduced in ERC-8004 v0.6+.
pub struct Erc8004IdentityRegistry {
    agents: DashMap<[u8; 32], AgentRecord>,
    /// Per-agent metadata KV. Keyed by `(agent_id, metadata_key)` so a
    /// single agent can store many distinct entries. Empty values
    /// (`Vec::new()`) are not stored — callers requesting an empty
    /// write hit the delete path below.
    metadata: DashMap<([u8; 32], String), Vec<u8>>,
}

impl Erc8004IdentityRegistry {
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
            metadata: DashMap::new(),
        }
    }

    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Register or update an agent. Idempotent: re-registering the same
    /// `agentId` overwrites the prior record (matches the reference
    /// contract's "owner-only update" with the simplification that the
    /// registry trusts the precompile caller).
    pub fn register(&self, record: AgentRecord) {
        self.agents.insert(record.agent_id, record);
    }

    pub fn get(&self, agent_id: &[u8; 32]) -> Option<AgentRecord> {
        self.agents.get(agent_id).map(|r| r.clone())
    }

    /// Update only the `metadata_uri` field on an already-registered
    /// agent. Returns `false` if the agent is unknown.
    pub fn set_agent_uri(&self, agent_id: &[u8; 32], metadata_uri: String) -> bool {
        match self.agents.get_mut(agent_id) {
            Some(mut record) => {
                record.metadata_uri = metadata_uri;
                true
            }
            None => false,
        }
    }

    /// Update only the `agent_address` field on an already-registered
    /// agent. Returns `false` if the agent is unknown.
    pub fn set_agent_wallet(&self, agent_id: &[u8; 32], new_wallet: [u8; 20]) -> bool {
        match self.agents.get_mut(agent_id) {
            Some(mut record) => {
                record.agent_address = new_wallet;
                true
            }
            None => false,
        }
    }

    /// Write a single `(key → value)` metadata pair against an agent.
    /// An empty `value` deletes the entry. Returns `true` once the
    /// requested mutation has been applied.
    pub fn set_metadata(&self, agent_id: [u8; 32], key: String, value: Vec<u8>) -> bool {
        if value.is_empty() {
            self.metadata.remove(&(agent_id, key));
        } else {
            self.metadata.insert((agent_id, key), value);
        }
        true
    }

    /// Read the bytes stored under `(agent_id, key)`; returns `None`
    /// when no value has been set.
    pub fn get_metadata(&self, agent_id: &[u8; 32], key: &str) -> Option<Vec<u8>> {
        self.metadata
            .get(&(*agent_id, key.to_string()))
            .map(|v| v.clone())
    }
}

impl Default for Erc8004IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Native Tenzro ReputationRegistry — append-only feedback per subject.
///
/// Two access paths are maintained side-by-side:
///
/// - **Index-keyed**: `feedback: subject -> Vec<FeedbackEntry>`. Drives
///   the legacy `getFeedback(subject, index)` and `getFeedbackCount`
///   reads.
/// - **Hash-keyed**: `index_by_id: (subject, feedback_id) -> usize`.
///   Drives the v0.6+ `revokeFeedback` and `appendResponse` mutators.
///
/// Both views see the same backing entries — there is no separate
/// storage for revocations or responses; mutators reach through
/// `index_by_id` to mutate the entry in `feedback` in place.
pub struct Erc8004ReputationRegistry {
    feedback: DashMap<[u8; 32], Vec<FeedbackEntry>>,
    /// `(subject, feedback_id) -> index_in_feedback_vec`. Populated by
    /// `submit`; consulted by `revoke` and `append_response`.
    index_by_id: DashMap<([u8; 32], [u8; 32]), usize>,
}

impl Erc8004ReputationRegistry {
    pub fn new() -> Self {
        Self {
            feedback: DashMap::new(),
            index_by_id: DashMap::new(),
        }
    }

    /// Append a feedback entry. Derives `feedback_id` deterministically
    /// from `(subject, index_at_submit_time, context_uri)` so the v0.6+
    /// hash-keyed selectors can address it. The caller is expected to
    /// emit the same `feedback_id` in any event log so off-chain
    /// indexers can correlate the two paths.
    pub fn submit(&self, mut entry: FeedbackEntry) -> [u8; 32] {
        let subject = entry.subject;
        let mut bucket = self.feedback.entry(subject).or_default();
        let index = bucket.len();
        let feedback_id = derive_feedback_id(&subject, index, &entry.context_uri);
        entry.feedback_id = feedback_id;
        bucket.push(entry);
        drop(bucket);
        self.index_by_id.insert((subject, feedback_id), index);
        feedback_id
    }

    pub fn count(&self, subject: &[u8; 32]) -> u128 {
        self.feedback.get(subject).map(|v| v.len() as u128).unwrap_or(0)
    }

    pub fn get_at(&self, subject: &[u8; 32], index: usize) -> Option<FeedbackEntry> {
        self.feedback
            .get(subject)
            .and_then(|v| v.get(index).cloned())
    }

    /// Look up a feedback entry by its content hash.
    pub fn get_by_id(
        &self,
        subject: &[u8; 32],
        feedback_id: &[u8; 32],
    ) -> Option<FeedbackEntry> {
        let index = *self.index_by_id.get(&(*subject, *feedback_id))?;
        self.feedback.get(subject).and_then(|v| v.get(index).cloned())
    }

    /// Mark the entry as revoked. Returns `false` if the entry doesn't
    /// exist or was already revoked (matching the reference contract's
    /// idempotency guard).
    pub fn revoke(&self, subject: &[u8; 32], feedback_id: &[u8; 32]) -> bool {
        let index = match self.index_by_id.get(&(*subject, *feedback_id)) {
            Some(i) => *i,
            None => return false,
        };
        let mut bucket = match self.feedback.get_mut(subject) {
            Some(b) => b,
            None => return false,
        };
        let entry = match bucket.get_mut(index) {
            Some(e) => e,
            None => return false,
        };
        if entry.revoked {
            return false;
        }
        entry.revoked = true;
        true
    }

    /// Attach (or replace) a response URI on the entry. Returns `false`
    /// if the entry doesn't exist. Idempotent overwrite — a subsequent
    /// call replaces the previous URI.
    pub fn append_response(
        &self,
        subject: &[u8; 32],
        feedback_id: &[u8; 32],
        response_uri: String,
    ) -> bool {
        let index = match self.index_by_id.get(&(*subject, *feedback_id)) {
            Some(i) => *i,
            None => return false,
        };
        let mut bucket = match self.feedback.get_mut(subject) {
            Some(b) => b,
            None => return false,
        };
        match bucket.get_mut(index) {
            Some(entry) => {
                entry.response_uri = response_uri;
                true
            }
            None => false,
        }
    }
}

/// Derive `feedback_id = keccak256(subject ‖ index_be(8) ‖ context_uri_utf8)`.
/// Pulled out so tests can address entries by hash without round-tripping
/// through the precompile dispatcher.
fn derive_feedback_id(subject: &[u8; 32], index: usize, context_uri: &str) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(subject);
    h.update((index as u64).to_be_bytes());
    h.update(context_uri.as_bytes());
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

impl Default for Erc8004ReputationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Native Tenzro ValidationRegistry — keyed by caller-supplied
/// `requestHash`, per ERC-8004. The 32-byte `request_hash` is a
/// commitment over the work being validated and is selected by the
/// requester; collisions on the same hash are rejected so the registry
/// stays append-only.
pub struct Erc8004ValidationRegistry {
    requests: DashMap<[u8; 32], ValidationEntry>,
}

impl Erc8004ValidationRegistry {
    pub fn new() -> Self {
        Self {
            requests: DashMap::new(),
        }
    }

    /// Open a validation request. Returns `false` if a request with the
    /// same `request_hash` is already on file (caller should pick a
    /// fresh hash — collisions are vanishingly unlikely for a real
    /// SHA-256/keccak commitment).
    pub fn open_request(
        &self,
        validator_address: [u8; 20],
        agent_id: [u8; 32],
        request_uri: String,
        request_hash: [u8; 32],
    ) -> bool {
        if self.requests.contains_key(&request_hash) {
            return false;
        }
        let entry = ValidationEntry {
            validator_address,
            agent_id,
            request_uri,
            request_hash,
            response: 0,
            response_uri: String::new(),
            response_hash: [0u8; 32],
            tag: String::new(),
            responded: false,
        };
        self.requests.insert(request_hash, entry);
        true
    }

    /// Record a validator's response. Returns `false` if no request is
    /// on file under `request_hash` or if a response was already
    /// recorded.
    pub fn record_response(
        &self,
        request_hash: &[u8; 32],
        response: u8,
        response_uri: String,
        response_hash: [u8; 32],
        tag: String,
    ) -> bool {
        let mut entry = match self.requests.get_mut(request_hash) {
            Some(e) => e,
            None => return false,
        };
        if entry.responded {
            return false;
        }
        entry.response = response;
        entry.response_uri = response_uri;
        entry.response_hash = response_hash;
        entry.tag = tag;
        entry.responded = true;
        true
    }

    pub fn get(&self, request_hash: &[u8; 32]) -> Option<ValidationEntry> {
        self.requests.get(request_hash).map(|e| e.clone())
    }
}

impl Default for Erc8004ValidationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public constructors
// ---------------------------------------------------------------------------

/// Closure factory for the IdentityRegistry precompile (0x101a).
pub fn create_erc8004_identity_precompile(
    registry: Arc<Erc8004IdentityRegistry>,
) -> Arc<dyn Fn(&[u8], u64) -> Result<PrecompileResult> + Send + Sync> {
    Arc::new(move |input: &[u8], gas_limit: u64| {
        execute_identity(&registry, input, gas_limit)
    })
}

/// Closure factory for the ReputationRegistry precompile (0x101b).
pub fn create_erc8004_reputation_precompile(
    registry: Arc<Erc8004ReputationRegistry>,
) -> Arc<dyn Fn(&[u8], u64) -> Result<PrecompileResult> + Send + Sync> {
    Arc::new(move |input: &[u8], gas_limit: u64| {
        execute_reputation(&registry, input, gas_limit)
    })
}

/// Closure factory for the ValidationRegistry precompile (0x101c).
pub fn create_erc8004_validation_precompile(
    registry: Arc<Erc8004ValidationRegistry>,
) -> Arc<dyn Fn(&[u8], u64) -> Result<PrecompileResult> + Send + Sync> {
    Arc::new(move |input: &[u8], gas_limit: u64| {
        execute_validation(&registry, input, gas_limit)
    })
}

// ---------------------------------------------------------------------------
// IdentityRegistry dispatch (0x101a)
// ---------------------------------------------------------------------------

fn execute_identity(
    registry: &Erc8004IdentityRegistry,
    input: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if input.len() < 4 {
        return Ok(PrecompileResult::failed(gas_limit));
    }
    let selector = &input[..4];
    let calldata = &input[4..];
    match selector {
        s if s == SELECTOR_REGISTER_AGENT => handle_register_agent(registry, calldata, gas_limit),
        s if s == SELECTOR_GET_AGENT => handle_get_agent(registry, calldata, gas_limit),
        s if s == SELECTOR_SET_AGENT_URI => handle_set_agent_uri(registry, calldata, gas_limit),
        s if s == SELECTOR_SET_AGENT_WALLET => {
            handle_set_agent_wallet(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_SET_METADATA => handle_set_metadata(registry, calldata, gas_limit),
        s if s == SELECTOR_GET_METADATA => handle_get_metadata(registry, calldata, gas_limit),
        s if s == SELECTOR_GET_AGENT_URI => handle_get_agent_uri(registry, calldata, gas_limit),
        s if s == SELECTOR_GET_AGENT_WALLET => {
            handle_get_agent_wallet(registry, calldata, gas_limit)
        }
        _ => Ok(PrecompileResult::failed(gas_limit)),
    }
}

/// `registerAgent(bytes32 agentId, address agentAddress, string metadataUri)`
///
/// Calldata layout (after selector):
///   [0..32]    agentId
///   [32..64]   agentAddress (left-padded)
///   [64..96]   offset to metadataUri
///   [96..]     metadataUri (length + utf8 bytes, padded)
///
/// Returns: ABI-encoded `(bool success)`.
fn handle_register_agent(
    registry: &Erc8004IdentityRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_REGISTER_AGENT {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_REGISTER_AGENT));
    }

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[..32]);

    let agent_address = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_REGISTER_AGENT)),
    };

    let metadata_uri = decode_dynamic_string(calldata, 64).unwrap_or_default();

    let record = AgentRecord {
        agent_id,
        agent_address,
        metadata_uri: metadata_uri.clone(),
    };
    registry.register(record);

    info!(
        "ERC-8004 IdentityRegistry: registered agent_id=0x{} address=0x{} uri={}",
        hex::encode(agent_id),
        hex::encode(agent_address),
        metadata_uri,
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(true),
        GAS_REGISTER_AGENT,
    ))
}

/// `getAgent(bytes32 agentId)`
///
/// Returns ABI-encoded `(address agentAddress, string metadataUri, bool exists)`.
/// Layout:
///   [0..32]    agentAddress (left-padded)
///   [32..64]   offset to metadataUri (always 96)
///   [64..96]   exists (bool as uint256)
///   [96..128]  metadataUri length
///   [128..]    metadataUri data, padded to 32-byte boundary
fn handle_get_agent(
    registry: &Erc8004IdentityRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 32 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[..32]);

    match registry.get(&agent_id) {
        Some(record) => Ok(PrecompileResult::success(
            encode_get_agent_result(&record.agent_address, &record.metadata_uri, true),
            GAS_READ,
        )),
        None => Ok(PrecompileResult::success(
            encode_get_agent_result(&[0u8; 20], "", false),
            GAS_READ,
        )),
    }
}

fn encode_get_agent_result(address: &[u8; 20], metadata_uri: &str, exists: bool) -> Vec<u8> {
    let uri_bytes = metadata_uri.as_bytes();
    let uri_padded = uri_bytes.len().div_ceil(32) * 32;
    let total_len = 96 + 32 + uri_padded;
    let mut out = vec![0u8; total_len];

    // [0..32]: address (left-padded)
    out[12..32].copy_from_slice(address);
    // [32..64]: offset to string = 96
    out[32..64].copy_from_slice(&abi::encode_uint256(96));
    // [64..96]: exists
    out[64..96].copy_from_slice(&abi::encode_bool(exists));
    // [96..128]: string length
    out[96..128].copy_from_slice(&abi::encode_uint256(uri_bytes.len() as u128));
    // [128..]: string data
    out[128..128 + uri_bytes.len()].copy_from_slice(uri_bytes);

    out
}

/// `setAgentURI(uint256 agentId, string metadataUri)`
///
/// Calldata layout (after selector):
///   [0..32]    agentId (uint256 word)
///   [32..64]   offset to metadataUri (= 64)
///   [64..]     metadataUri (length + utf8 bytes, padded)
///
/// Returns: ABI-encoded `(bool success)` — `false` if the agent is
/// unknown.
fn handle_set_agent_uri(
    registry: &Erc8004IdentityRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_SET_AGENT_URI {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_SET_AGENT_URI));
    }

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[..32]);

    let metadata_uri = decode_dynamic_string(calldata, 32).unwrap_or_default();

    let updated = registry.set_agent_uri(&agent_id, metadata_uri.clone());

    if updated {
        info!(
            "ERC-8004 IdentityRegistry: setAgentURI agent_id=0x{} uri={}",
            hex::encode(agent_id),
            metadata_uri,
        );
    } else {
        debug!(
            "ERC-8004 IdentityRegistry: setAgentURI on unknown agent_id=0x{}",
            hex::encode(agent_id),
        );
    }

    Ok(PrecompileResult::success(
        abi::encode_bool(updated),
        GAS_SET_AGENT_URI,
    ))
}

/// `setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature)`
///
/// Calldata layout (after selector):
///   [0..32]    agentId (uint256 word)
///   [32..64]   newWallet (address, left-padded)
///   [64..96]   deadline (uint256 — accepted but not enforced; outer-tx
///              `from` is the auditable authorization in the precompile)
///   [96..128]  offset to signature (= 128)
///   [128..]    signature tail (length + bytes, padded)
///
/// Returns: ABI-encoded `(bool success)` — `false` if the agent is
/// unknown. The `deadline + signature` pair is accepted for byte-level
/// calldata compatibility with the Ethereum mirror but is not verified
/// here; authorization is delegated to the surrounding EVM transaction.
fn handle_set_agent_wallet(
    registry: &Erc8004IdentityRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_SET_AGENT_WALLET {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 128 {
        return Ok(PrecompileResult::failed(GAS_SET_AGENT_WALLET));
    }

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[..32]);

    let new_wallet = match abi::decode_address_at(calldata, 32) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_SET_AGENT_WALLET)),
    };

    // Slots [64..96] (deadline) and [96..] (signature offset + tail) are
    // present but not consulted here — see the doc comment.

    let updated = registry.set_agent_wallet(&agent_id, new_wallet);

    if updated {
        info!(
            "ERC-8004 IdentityRegistry: setAgentWallet agent_id=0x{} new_wallet=0x{}",
            hex::encode(agent_id),
            hex::encode(new_wallet),
        );
    } else {
        debug!(
            "ERC-8004 IdentityRegistry: setAgentWallet on unknown agent_id=0x{}",
            hex::encode(agent_id),
        );
    }

    Ok(PrecompileResult::success(
        abi::encode_bool(updated),
        GAS_SET_AGENT_WALLET,
    ))
}

/// `setMetadata(uint256 agentId, string metadataKey, bytes metadataValue)`
///
/// Calldata layout (after selector):
///   [0..32]    agentId (uint256 word)
///   [32..64]   offset to metadataKey
///   [64..96]   offset to metadataValue
///   then string + bytes tails in the order the offsets reference.
///
/// Returns: ABI-encoded `(bool success)`. An empty `metadataValue`
/// deletes the entry; the call still returns `true`.
fn handle_set_metadata(
    registry: &Erc8004IdentityRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_SET_METADATA {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_SET_METADATA));
    }

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[..32]);

    let metadata_key = match decode_dynamic_string(calldata, 32) {
        Some(k) if !k.is_empty() => k,
        _ => return Ok(PrecompileResult::failed(GAS_SET_METADATA)),
    };

    let metadata_value = decode_dynamic_bytes(calldata, 64).unwrap_or_default();

    let value_len = metadata_value.len();
    registry.set_metadata(agent_id, metadata_key.clone(), metadata_value);

    debug!(
        "ERC-8004 IdentityRegistry: setMetadata agent_id=0x{} key={} value_len={}",
        hex::encode(agent_id),
        metadata_key,
        value_len,
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(true),
        GAS_SET_METADATA,
    ))
}

/// `getMetadata(uint256 agentId, string metadataKey)`
///
/// Calldata layout (after selector):
///   [0..32]    agentId (uint256 word)
///   [32..64]   offset to metadataKey
///   [64..]     metadataKey tail
///
/// Returns: ABI-encoded `(bytes metadataValue)` — empty bytes if the
/// entry is unset.
fn handle_get_metadata(
    registry: &Erc8004IdentityRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[..32]);

    let metadata_key = decode_dynamic_string(calldata, 32).unwrap_or_default();

    let value = registry
        .get_metadata(&agent_id, &metadata_key)
        .unwrap_or_default();

    Ok(PrecompileResult::success(
        encode_get_metadata_result(&value),
        GAS_READ,
    ))
}

/// Encode the return of `getMetadata(uint256,string) -> bytes`.
///
/// Layout: `[offset = 32 | length | data padded to 32-byte boundary]`.
fn encode_get_metadata_result(value: &[u8]) -> Vec<u8> {
    let padded = value.len().div_ceil(32) * 32;
    let total = 64 + padded;
    let mut out = vec![0u8; total];
    // [0..32]: offset to bytes = 32
    out[..32].copy_from_slice(&abi::encode_uint256(32));
    // [32..64]: length
    out[32..64].copy_from_slice(&abi::encode_uint256(value.len() as u128));
    // [64..]: data
    if !value.is_empty() {
        out[64..64 + value.len()].copy_from_slice(value);
    }
    out
}

/// `getAgentURI(uint256 agentId) -> string`
///
/// Calldata layout (after selector):
///   [0..32]    agentId
///
/// Returns ABI-encoded `string` — the metadata URI for a registered
/// agent, or empty string if the agent doesn't exist. Wire layout:
///   [0..32]    offset to string = 32
///   [32..64]   length
///   [64..]     utf8 bytes (zero-padded to 32-byte boundary)
fn handle_get_agent_uri(
    registry: &Erc8004IdentityRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 32 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[..32]);

    let uri = registry
        .get(&agent_id)
        .map(|r| r.metadata_uri)
        .unwrap_or_default();
    Ok(PrecompileResult::success(
        encode_string_return(&uri),
        GAS_READ,
    ))
}

/// `getAgentWallet(uint256 agentId) -> address`
///
/// Calldata layout (after selector):
///   [0..32]    agentId
///
/// Returns ABI-encoded `address` (20 bytes left-padded to 32). Returns
/// the zero address for unknown agents — callers needing to distinguish
/// "agent not registered" from "agent registered with zero wallet"
/// should pair this with `getAgent` (which returns `exists`).
fn handle_get_agent_wallet(
    registry: &Erc8004IdentityRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 32 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[..32]);

    let wallet = registry
        .get(&agent_id)
        .map(|r| r.agent_address)
        .unwrap_or([0u8; 20]);

    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(&wallet);
    Ok(PrecompileResult::success(out.to_vec(), GAS_READ))
}

/// Encode a single ABI `string` return value. Layout: offset(32) +
/// length(32) + utf8 padded to 32-byte boundary.
fn encode_string_return(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let padded = bytes.len().div_ceil(32) * 32;
    let total = 64 + padded;
    let mut out = vec![0u8; total];
    out[..32].copy_from_slice(&abi::encode_uint256(32));
    out[32..64].copy_from_slice(&abi::encode_uint256(bytes.len() as u128));
    if !bytes.is_empty() {
        out[64..64 + bytes.len()].copy_from_slice(bytes);
    }
    out
}

// ---------------------------------------------------------------------------
// ReputationRegistry dispatch (0x101b)
// ---------------------------------------------------------------------------

fn execute_reputation(
    registry: &Erc8004ReputationRegistry,
    input: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if input.len() < 4 {
        return Ok(PrecompileResult::failed(gas_limit));
    }
    let selector = &input[..4];
    let calldata = &input[4..];
    match selector {
        s if s == SELECTOR_SUBMIT_FEEDBACK => {
            handle_submit_feedback(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_GET_FEEDBACK => handle_get_feedback(registry, calldata, gas_limit),
        s if s == SELECTOR_GET_FEEDBACK_COUNT => {
            handle_get_feedback_count(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_REVOKE_FEEDBACK => {
            handle_revoke_feedback(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_APPEND_RESPONSE => {
            handle_append_response(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_IS_FEEDBACK_REVOKED => {
            handle_is_feedback_revoked(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_GET_FEEDBACK_RESPONSES => {
            handle_get_feedback_responses(registry, calldata, gas_limit)
        }
        _ => Ok(PrecompileResult::failed(gas_limit)),
    }
}

/// `submitFeedback(bytes32 subject, int8 rating, string contextUri)`
///
/// Calldata layout (after selector):
///   [0..32]    subject (agentId)
///   [32..64]   rating (int8 as 32-byte two's complement)
///   [64..96]   offset to contextUri
///   [96..]     contextUri (length + utf8 bytes, padded)
///
/// **Note**: the precompile cannot recover an EVM `msg.sender` from a
/// raw call here — we record the *caller-provided* rater address as a
/// 4th implicit slot. To match the reference contract while keeping
/// this stateless, the rater is encoded via the EVM CALLER opcode
/// outside this dispatcher. We store [0u8; 20] here; the on-chain
/// caller is auditable from the encompassing transaction's `from`.
fn handle_submit_feedback(
    registry: &Erc8004ReputationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_SUBMIT_FEEDBACK {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_SUBMIT_FEEDBACK));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&calldata[..32]);

    // rating: int8 sign-extended into 32 bytes
    let rating_byte = calldata[63]; // last byte of the second slot
    let rating = rating_byte as i8;

    let context_uri = decode_dynamic_string(calldata, 64).unwrap_or_default();

    let entry = FeedbackEntry {
        subject,
        rater: [0u8; 20], // recorded via outer-tx `from`; precompile is stateless wrt msg.sender
        rating,
        context_uri: context_uri.clone(),
        feedback_id: [0u8; 32], // populated by `submit()` from the assigned index
        revoked: false,
        response_uri: String::new(),
    };
    let _feedback_id = registry.submit(entry);

    debug!(
        "ERC-8004 ReputationRegistry: feedback subject=0x{} rating={} uri={}",
        hex::encode(subject),
        rating,
        context_uri,
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(true),
        GAS_SUBMIT_FEEDBACK,
    ))
}

/// `getFeedback(bytes32 subject, uint256 index)`
///
/// Returns ABI-encoded `(int8 rating, string contextUri, bool exists)`.
fn handle_get_feedback(
    registry: &Erc8004ReputationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&calldata[..32]);

    let index = match abi::decode_uint256_at(calldata, 32) {
        Some(i) => i as usize,
        None => return Ok(PrecompileResult::failed(GAS_READ)),
    };

    match registry.get_at(&subject, index) {
        Some(entry) => Ok(PrecompileResult::success(
            encode_get_feedback_result(entry.rating, &entry.context_uri, true),
            GAS_READ,
        )),
        None => Ok(PrecompileResult::success(
            encode_get_feedback_result(0, "", false),
            GAS_READ,
        )),
    }
}

fn encode_get_feedback_result(rating: i8, context_uri: &str, exists: bool) -> Vec<u8> {
    let uri_bytes = context_uri.as_bytes();
    let uri_padded = uri_bytes.len().div_ceil(32) * 32;
    let total_len = 96 + 32 + uri_padded;
    let mut out = vec![0u8; total_len];

    // [0..32]: rating as int8 sign-extended to 32 bytes
    let sign_ext = if rating < 0 { 0xffu8 } else { 0u8 };
    for byte in out.iter_mut().take(31) {
        *byte = sign_ext;
    }
    out[31] = rating as u8;
    // [32..64]: offset to string = 96
    out[32..64].copy_from_slice(&abi::encode_uint256(96));
    // [64..96]: exists
    out[64..96].copy_from_slice(&abi::encode_bool(exists));
    // [96..128]: string length
    out[96..128].copy_from_slice(&abi::encode_uint256(uri_bytes.len() as u128));
    // [128..]: string data
    out[128..128 + uri_bytes.len()].copy_from_slice(uri_bytes);

    out
}

/// `getFeedbackCount(bytes32 subject) -> uint256`
fn handle_get_feedback_count(
    registry: &Erc8004ReputationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 32 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&calldata[..32]);

    let count = registry.count(&subject);
    Ok(PrecompileResult::success(abi::encode_uint256(count), GAS_READ))
}

/// `revokeFeedback(uint256 agentId, bytes32 feedbackId) -> bool`
///
/// Calldata layout (after selector):
///   [0..32]    agentId (subject — uint256 word, but bytes-identical to bytes32)
///   [32..64]   feedbackId
///
/// Returns ABI-encoded `bool` — `true` if the entry was found and
/// successfully marked revoked, `false` if unknown or already revoked.
fn handle_revoke_feedback(
    registry: &Erc8004ReputationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_REVOKE_FEEDBACK {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_REVOKE_FEEDBACK));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&calldata[..32]);
    let mut feedback_id = [0u8; 32];
    feedback_id.copy_from_slice(&calldata[32..64]);

    let revoked = registry.revoke(&subject, &feedback_id);
    debug!(
        "ERC-8004 ReputationRegistry: revokeFeedback subject=0x{} feedback_id=0x{} ok={}",
        hex::encode(subject),
        hex::encode(feedback_id),
        revoked,
    );
    Ok(PrecompileResult::success(
        abi::encode_bool(revoked),
        GAS_REVOKE_FEEDBACK,
    ))
}

/// `appendResponse(uint256 agentId, bytes32 feedbackId, string responseUri) -> bool`
///
/// Calldata layout (after selector):
///   [0..32]    agentId (subject)
///   [32..64]   feedbackId
///   [64..96]   offset to responseUri (= 96)
///   [96..]     responseUri tail (length + utf8 bytes, padded)
///
/// Returns ABI-encoded `bool` — `true` if the response URI was attached
/// (or replaced an existing one), `false` if no entry exists at that
/// `(agentId, feedbackId)`.
fn handle_append_response(
    registry: &Erc8004ReputationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_APPEND_RESPONSE {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_APPEND_RESPONSE));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&calldata[..32]);
    let mut feedback_id = [0u8; 32];
    feedback_id.copy_from_slice(&calldata[32..64]);

    let response_uri = decode_dynamic_string(calldata, 64).unwrap_or_default();

    let ok = registry.append_response(&subject, &feedback_id, response_uri.clone());
    debug!(
        "ERC-8004 ReputationRegistry: appendResponse subject=0x{} feedback_id=0x{} uri={} ok={}",
        hex::encode(subject),
        hex::encode(feedback_id),
        response_uri,
        ok,
    );
    Ok(PrecompileResult::success(
        abi::encode_bool(ok),
        GAS_APPEND_RESPONSE,
    ))
}

/// `isFeedbackRevoked(uint256 agentId, bytes32 feedbackId) -> bool`
///
/// Calldata layout (after selector):
///   [0..32]    agentId (subject)
///   [32..64]   feedbackId
///
/// Returns ABI-encoded `bool` — `true` only if the entry exists and is
/// revoked. Unknown entries return `false` (matching the reference
/// contract: a revoke flag on a missing entry is meaningless, so it's
/// reported as not-revoked).
fn handle_is_feedback_revoked(
    registry: &Erc8004ReputationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&calldata[..32]);
    let mut feedback_id = [0u8; 32];
    feedback_id.copy_from_slice(&calldata[32..64]);

    let revoked = registry
        .get_by_id(&subject, &feedback_id)
        .map(|e| e.revoked)
        .unwrap_or(false);
    Ok(PrecompileResult::success(
        abi::encode_bool(revoked),
        GAS_READ,
    ))
}

/// `getFeedbackResponses(uint256 agentId, bytes32 feedbackId) -> string`
///
/// Calldata layout (after selector):
///   [0..32]    agentId (subject)
///   [32..64]   feedbackId
///
/// Returns the response URI attached via `appendResponse`. Empty string
/// if no response was attached or the entry doesn't exist. Although the
/// v0.6 spec naming hints at a list, the reference contract only stores
/// the latest response, so this returns a single string.
fn handle_get_feedback_responses(
    registry: &Erc8004ReputationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&calldata[..32]);
    let mut feedback_id = [0u8; 32];
    feedback_id.copy_from_slice(&calldata[32..64]);

    let response = registry
        .get_by_id(&subject, &feedback_id)
        .map(|e| e.response_uri)
        .unwrap_or_default();
    Ok(PrecompileResult::success(
        encode_string_return(&response),
        GAS_READ,
    ))
}

// ---------------------------------------------------------------------------
// ValidationRegistry dispatch (0x101c)
// ---------------------------------------------------------------------------

fn execute_validation(
    registry: &Erc8004ValidationRegistry,
    input: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if input.len() < 4 {
        return Ok(PrecompileResult::failed(gas_limit));
    }
    let selector = &input[..4];
    let calldata = &input[4..];
    match selector {
        s if s == SELECTOR_VALIDATION_REQUEST => {
            handle_validation_request(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_VALIDATION_RESPONSE => {
            handle_validation_response(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_GET_VALIDATION => handle_get_validation(registry, calldata, gas_limit),
        _ => Ok(PrecompileResult::failed(gas_limit)),
    }
}

/// `validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash) -> bool`
/// per ERC-8004.
///
/// Calldata layout (after selector):
///   [0..32]    validatorAddress (left-padded)
///   [32..64]   agentId (uint256 word)
///   [64..96]   offset to requestURI (= 128)
///   [96..128]  requestHash
///   [128..]    requestURI tail (length + utf8 bytes, padded)
fn handle_validation_request(
    registry: &Erc8004ValidationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_VALIDATION_REQUEST {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 128 {
        return Ok(PrecompileResult::failed(GAS_VALIDATION_REQUEST));
    }

    let validator_address = match abi::decode_address_at(calldata, 0) {
        Some(a) => a,
        None => return Ok(PrecompileResult::failed(GAS_VALIDATION_REQUEST)),
    };

    let mut agent_id = [0u8; 32];
    agent_id.copy_from_slice(&calldata[32..64]);

    let request_uri = decode_dynamic_string(calldata, 64).unwrap_or_default();

    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(&calldata[96..128]);

    let ok = registry.open_request(
        validator_address,
        agent_id,
        request_uri.clone(),
        request_hash,
    );

    info!(
        "ERC-8004 ValidationRegistry: validationRequest validator=0x{} agent_id=0x{} request_hash=0x{} uri={} ok={}",
        hex::encode(validator_address),
        hex::encode(agent_id),
        hex::encode(request_hash),
        request_uri,
        ok,
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(ok),
        GAS_VALIDATION_REQUEST,
    ))
}

/// `validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag) -> bool`
/// per ERC-8004.
///
/// Calldata layout (after selector):
///   [0..32]    requestHash
///   [32..64]   response (uint8 padded)
///   [64..96]   offset to responseURI (= 160)
///   [96..128]  responseHash
///   [128..160] offset to tag
///   [160..]    responseURI tail, then tag tail
fn handle_validation_response(
    registry: &Erc8004ValidationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_VALIDATION_RESPONSE {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 160 {
        return Ok(PrecompileResult::failed(GAS_VALIDATION_RESPONSE));
    }

    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(&calldata[..32]);

    let response = calldata[63];

    let response_uri = decode_dynamic_string(calldata, 64).unwrap_or_default();

    let mut response_hash = [0u8; 32];
    response_hash.copy_from_slice(&calldata[96..128]);

    let tag = decode_dynamic_string(calldata, 128).unwrap_or_default();

    let ok = registry.record_response(
        &request_hash,
        response,
        response_uri.clone(),
        response_hash,
        tag.clone(),
    );

    debug!(
        "ERC-8004 ValidationRegistry: validationResponse request_hash=0x{} response={} response_uri={} tag={} ok={}",
        hex::encode(request_hash),
        response,
        response_uri,
        tag,
        ok,
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(ok),
        GAS_VALIDATION_RESPONSE,
    ))
}

/// `getValidation(bytes32 requestHash)`
///
/// Returns ABI-encoded `(address validator, uint256 agentId, uint8 response,
/// string requestURI, string responseURI, string tag, bool exists)` —
/// fused read covering both request and response halves of an
/// ERC-8004 validation entry. Wire shape mirrors
/// [`tenzro_identity::erc8004::abi::decode_get_validation`]: 7-slot head
/// (224 bytes) plus three string tails in order request_uri,
/// response_uri, tag.
fn handle_get_validation(
    registry: &Erc8004ValidationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_READ {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 32 {
        return Ok(PrecompileResult::failed(GAS_READ));
    }

    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(&calldata[..32]);

    match registry.get(&request_hash) {
        Some(entry) => Ok(PrecompileResult::success(
            encode_get_validation_result(
                &entry.validator_address,
                &entry.agent_id,
                entry.response,
                &entry.request_uri,
                &entry.response_uri,
                &entry.tag,
                true,
            ),
            GAS_READ,
        )),
        None => Ok(PrecompileResult::success(
            encode_get_validation_result(&[0u8; 20], &[0u8; 32], 0, "", "", "", false),
            GAS_READ,
        )),
    }
}

fn encode_get_validation_result(
    validator: &[u8; 20],
    agent_id: &[u8; 32],
    response: u8,
    request_uri: &str,
    response_uri: &str,
    tag: &str,
    exists: bool,
) -> Vec<u8> {
    // Head: 7 slots × 32 = 224 bytes
    //   [0..32]    validator (left-padded address)
    //   [32..64]   agent_id (uint256 word)
    //   [64..96]   response (uint8 padded)
    //   [96..128]  offset to requestURI (= 224)
    //   [128..160] offset to responseURI
    //   [160..192] offset to tag
    //   [192..224] exists
    let head_len: usize = 7 * 32;

    let req_bytes = request_uri.as_bytes();
    let req_padded = req_bytes.len().div_ceil(32) * 32;
    let req_block = 32 + req_padded;
    let req_offset = head_len; // 224

    let resp_bytes = response_uri.as_bytes();
    let resp_padded = resp_bytes.len().div_ceil(32) * 32;
    let resp_block = 32 + resp_padded;
    let resp_offset = req_offset + req_block;

    let tag_bytes = tag.as_bytes();
    let tag_padded = tag_bytes.len().div_ceil(32) * 32;
    let tag_block = 32 + tag_padded;
    let tag_offset = resp_offset + resp_block;

    let total_len = tag_offset + tag_block;
    let mut out = vec![0u8; total_len];

    // validator (left-padded into [0..32])
    out[12..32].copy_from_slice(validator);
    // agent_id
    out[32..64].copy_from_slice(agent_id);
    // response
    out[95] = response;
    // request_uri offset
    out[96..128].copy_from_slice(&abi::encode_uint256(req_offset as u128));
    // response_uri offset
    out[128..160].copy_from_slice(&abi::encode_uint256(resp_offset as u128));
    // tag offset
    out[160..192].copy_from_slice(&abi::encode_uint256(tag_offset as u128));
    // exists
    out[192..224].copy_from_slice(&abi::encode_bool(exists));

    // request_uri tail
    out[req_offset..req_offset + 32]
        .copy_from_slice(&abi::encode_uint256(req_bytes.len() as u128));
    out[req_offset + 32..req_offset + 32 + req_bytes.len()].copy_from_slice(req_bytes);

    // response_uri tail
    out[resp_offset..resp_offset + 32]
        .copy_from_slice(&abi::encode_uint256(resp_bytes.len() as u128));
    out[resp_offset + 32..resp_offset + 32 + resp_bytes.len()].copy_from_slice(resp_bytes);

    // tag tail
    out[tag_offset..tag_offset + 32]
        .copy_from_slice(&abi::encode_uint256(tag_bytes.len() as u128));
    out[tag_offset + 32..tag_offset + 32 + tag_bytes.len()].copy_from_slice(tag_bytes);

    out
}

// ---------------------------------------------------------------------------
// Shared ABI helper
// ---------------------------------------------------------------------------

/// Decode a dynamic string at the given offset slot. Mirrors the helper
/// used in `nft_factory.rs` and `token_factory.rs` — kept local to this
/// module so the factory modules stay independently usable.
fn decode_dynamic_string(calldata: &[u8], offset_slot: usize) -> Option<String> {
    if calldata.len() < offset_slot + 32 {
        return None;
    }
    let offset = abi::decode_uint256_at(calldata, offset_slot)? as usize;
    if calldata.len() < offset + 32 {
        return None;
    }
    let length = abi::decode_uint256_at(calldata, offset)? as usize;
    if length == 0 || calldata.len() < offset + 32 + length {
        return None;
    }
    let string_bytes = &calldata[offset + 32..offset + 32 + length];
    String::from_utf8(string_bytes.to_vec()).ok()
}

/// Decode a dynamic `bytes` value at the given offset slot. Unlike
/// [`decode_dynamic_string`], the empty-value case is meaningful — for
/// `setMetadata(uint256,string,bytes)` an empty payload deletes the
/// entry — so we return `Some(Vec::new())` rather than `None`.
fn decode_dynamic_bytes(calldata: &[u8], offset_slot: usize) -> Option<Vec<u8>> {
    if calldata.len() < offset_slot + 32 {
        return None;
    }
    let offset = abi::decode_uint256_at(calldata, offset_slot)? as usize;
    if calldata.len() < offset + 32 {
        return None;
    }
    let length = abi::decode_uint256_at(calldata, offset)? as usize;
    if length == 0 {
        return Some(Vec::new());
    }
    if calldata.len() < offset + 32 + length {
        return None;
    }
    Some(calldata[offset + 32..offset + 32 + length].to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Keccak256};

    fn keccak(bytes: &[u8]) -> [u8; 32] {
        let mut h = Keccak256::new();
        h.update(bytes);
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    }

    fn encode_register_calldata(
        agent_id: &[u8; 32],
        agent_address: &[u8; 20],
        metadata_uri: &str,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + 96 + 32 + metadata_uri.len());
        data.extend_from_slice(&SELECTOR_REGISTER_AGENT);
        data.extend_from_slice(agent_id);
        // address left-padded
        let mut addr_word = [0u8; 32];
        addr_word[12..].copy_from_slice(agent_address);
        data.extend_from_slice(&addr_word);
        // offset to string = 96 (3 slots in)
        data.extend_from_slice(&abi::encode_uint256(96));
        // string length + bytes
        data.extend_from_slice(&abi::encode_uint256(metadata_uri.len() as u128));
        let pad = (32 - (metadata_uri.len() % 32)) % 32;
        data.extend_from_slice(metadata_uri.as_bytes());
        data.extend(std::iter::repeat_n(0u8, pad));
        data
    }

    #[test]
    fn identity_register_then_get_roundtrips() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let did = "did:tenzro:machine:abc";
        let agent_id = keccak(did.as_bytes());
        let address: [u8; 20] = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        ];

        // register
        let reg_input = encode_register_calldata(&agent_id, &address, "ipfs://meta");
        let result = execute_identity(&registry, &reg_input, 200_000).unwrap();
        assert!(result.success);
        assert_eq!(registry.agent_count(), 1);

        // getAgent
        let mut get_input = Vec::with_capacity(36);
        get_input.extend_from_slice(&SELECTOR_GET_AGENT);
        get_input.extend_from_slice(&agent_id);
        let result = execute_identity(&registry, &get_input, 10_000).unwrap();
        assert!(result.success);
        // exists slot at [64..96] -> last byte should be 1
        assert_eq!(result.output[95], 1);
        // address at [12..32]
        assert_eq!(&result.output[12..32], &address);
    }

    #[test]
    fn identity_get_missing_returns_exists_false() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let agent_id = keccak(b"did:tenzro:machine:nope");

        let mut get_input = Vec::with_capacity(36);
        get_input.extend_from_slice(&SELECTOR_GET_AGENT);
        get_input.extend_from_slice(&agent_id);
        let result = execute_identity(&registry, &get_input, 10_000).unwrap();
        assert!(result.success);
        // exists slot at [64..96] -> last byte should be 0
        assert_eq!(result.output[95], 0);
    }

    #[test]
    fn reputation_submit_and_count() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:victim");

        // submitFeedback(subject, +5, "ipfs://ctx")
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SUBMIT_FEEDBACK);
        data.extend_from_slice(&subject);
        // rating word: +5 in last byte
        let mut rating = [0u8; 32];
        rating[31] = 5;
        data.extend_from_slice(&rating);
        // offset to string = 96
        data.extend_from_slice(&abi::encode_uint256(96));
        // string len + content
        let ctx = "ipfs://ctx";
        data.extend_from_slice(&abi::encode_uint256(ctx.len() as u128));
        let pad = (32 - (ctx.len() % 32)) % 32;
        data.extend_from_slice(ctx.as_bytes());
        data.extend(std::iter::repeat_n(0u8, pad));

        let res = execute_reputation(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(registry.count(&subject), 1);

        // getFeedbackCount
        let mut count_input = Vec::new();
        count_input.extend_from_slice(&SELECTOR_GET_FEEDBACK_COUNT);
        count_input.extend_from_slice(&subject);
        let res = execute_reputation(&registry, &count_input, 10_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 1);
    }

    #[test]
    fn reputation_negative_rating_round_trips() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:bad");

        // rating = -3 (0xfd in last byte, sign-extended in upper bytes by caller)
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SUBMIT_FEEDBACK);
        data.extend_from_slice(&subject);
        let mut rating_word = [0xffu8; 32];
        rating_word[31] = (-3i8) as u8;
        data.extend_from_slice(&rating_word);
        data.extend_from_slice(&abi::encode_uint256(96));
        data.extend_from_slice(&abi::encode_uint256(0)); // empty string
        let _ = execute_reputation(&registry, &data, 100_000).unwrap();

        // getFeedback(subject, 0) -> rating = -3
        let mut get_input = Vec::new();
        get_input.extend_from_slice(&SELECTOR_GET_FEEDBACK);
        get_input.extend_from_slice(&subject);
        get_input.extend_from_slice(&abi::encode_uint256(0));
        let res = execute_reputation(&registry, &get_input, 10_000).unwrap();
        assert!(res.success);
        // rating sign-extended in [0..32]
        assert_eq!(res.output[0], 0xff);
        assert_eq!(res.output[31] as i8, -3);
        // exists at [64..96]
        assert_eq!(res.output[95], 1);
    }

    #[test]
    fn validation_request_then_response_then_get() {
        let registry = Arc::new(Erc8004ValidationRegistry::new());
        let validator: [u8; 20] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        ];
        let agent_id = keccak(b"did:tenzro:machine:worker");
        let request_hash = keccak(b"work-commitment-1");

        // validationRequest(validator, agent_id, "ipfs://task", request_hash)
        // Calldata head: [validator(32) | agent_id(32) | offset=128 | request_hash(32)]
        let mut req_input = Vec::new();
        req_input.extend_from_slice(&SELECTOR_VALIDATION_REQUEST);
        let mut validator_word = [0u8; 32];
        validator_word[12..].copy_from_slice(&validator);
        req_input.extend_from_slice(&validator_word);
        req_input.extend_from_slice(&agent_id);
        req_input.extend_from_slice(&abi::encode_uint256(128));
        req_input.extend_from_slice(&request_hash);
        let task = "ipfs://task";
        req_input.extend_from_slice(&abi::encode_uint256(task.len() as u128));
        let pad = (32 - (task.len() % 32)) % 32;
        req_input.extend_from_slice(task.as_bytes());
        req_input.extend(std::iter::repeat_n(0u8, pad));

        let res = execute_validation(&registry, &req_input, 100_000).unwrap();
        assert!(res.success);
        // returns bool(true)
        assert_eq!(res.output[31], 1);

        // validationResponse(request_hash, 90, "ipfs://proof", response_hash, "valid")
        // Calldata head: [request_hash(32) | response(32) | uri_offset=160 | response_hash(32) | tag_offset]
        let response_hash = keccak(b"response-commitment-1");
        let proof = "ipfs://proof";
        let proof_block_len = 32 + proof.len().div_ceil(32) * 32;
        let tag_offset_calldata = 160 + proof_block_len;
        let tag = "valid";

        let mut sub_input = Vec::new();
        sub_input.extend_from_slice(&SELECTOR_VALIDATION_RESPONSE);
        sub_input.extend_from_slice(&request_hash);
        let mut response_word = [0u8; 32];
        response_word[31] = 90;
        sub_input.extend_from_slice(&response_word);
        sub_input.extend_from_slice(&abi::encode_uint256(160));
        sub_input.extend_from_slice(&response_hash);
        sub_input.extend_from_slice(&abi::encode_uint256(tag_offset_calldata as u128));
        // proof tail
        sub_input.extend_from_slice(&abi::encode_uint256(proof.len() as u128));
        let pad = (32 - (proof.len() % 32)) % 32;
        sub_input.extend_from_slice(proof.as_bytes());
        sub_input.extend(std::iter::repeat_n(0u8, pad));
        // tag tail
        sub_input.extend_from_slice(&abi::encode_uint256(tag.len() as u128));
        let pad = (32 - (tag.len() % 32)) % 32;
        sub_input.extend_from_slice(tag.as_bytes());
        sub_input.extend(std::iter::repeat_n(0u8, pad));

        let res = execute_validation(&registry, &sub_input, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 1);

        // getValidation(request_hash)
        let mut get_input = Vec::new();
        get_input.extend_from_slice(&SELECTOR_GET_VALIDATION);
        get_input.extend_from_slice(&request_hash);
        let res = execute_validation(&registry, &get_input, 10_000).unwrap();
        assert!(res.success);
        // validator in [12..32]
        assert_eq!(&res.output[12..32], &validator);
        // agent_id in [32..64]
        assert_eq!(&res.output[32..64], &agent_id);
        // response at byte 95 = 90
        assert_eq!(res.output[95], 90);
        // exists at [192..224] last byte = 1
        assert_eq!(res.output[223], 1);
    }

    #[test]
    fn validation_double_response_rejected() {
        let registry = Arc::new(Erc8004ValidationRegistry::new());
        let validator = [0u8; 20];
        let agent_id = keccak(b"did:tenzro:machine:once");
        let request_hash = keccak(b"once-commitment");

        // open
        let ok = registry.open_request(
            validator,
            agent_id,
            "task".to_string(),
            request_hash,
        );
        assert!(ok);

        // first response succeeds
        let ok = registry.record_response(
            &request_hash,
            100,
            "proof".to_string(),
            [0u8; 32],
            "valid".to_string(),
        );
        assert!(ok);

        // second response on same hash fails
        let ok = registry.record_response(
            &request_hash,
            50,
            "proof2".to_string(),
            [0u8; 32],
            "abstain".to_string(),
        );
        assert!(!ok);
    }

    #[test]
    fn validation_duplicate_request_hash_rejected() {
        let registry = Arc::new(Erc8004ValidationRegistry::new());
        let validator = [0u8; 20];
        let agent_id = keccak(b"did:tenzro:machine:dup");
        let request_hash = keccak(b"reused-commitment");

        let ok = registry.open_request(
            validator,
            agent_id,
            "task1".to_string(),
            request_hash,
        );
        assert!(ok);
        // Same hash => second open is rejected.
        let ok = registry.open_request(
            validator,
            agent_id,
            "task2".to_string(),
            request_hash,
        );
        assert!(!ok);
    }

    #[test]
    fn rejects_unknown_selector() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let mut data = Vec::new();
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        data.extend_from_slice(&[0u8; 32]);
        let res = execute_identity(&registry, &data, 100_000).unwrap();
        assert!(!res.success);
    }

    fn register_basic_agent(registry: &Erc8004IdentityRegistry, did: &str) -> [u8; 32] {
        let agent_id = keccak(did.as_bytes());
        let address: [u8; 20] = [0x11; 20];
        let reg_input = encode_register_calldata(&agent_id, &address, "ipfs://orig");
        let res = execute_identity(registry, &reg_input, 200_000).unwrap();
        assert!(res.success);
        agent_id
    }

    #[test]
    fn set_agent_uri_updates_existing_record() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let agent_id = register_basic_agent(&registry, "did:tenzro:machine:uri-1");

        // setAgentURI(agent_id, "ipfs://updated")
        let new_uri = "ipfs://updated";
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SET_AGENT_URI);
        data.extend_from_slice(&agent_id);
        data.extend_from_slice(&abi::encode_uint256(64)); // offset to string
        data.extend_from_slice(&abi::encode_uint256(new_uri.len() as u128));
        let pad = (32 - (new_uri.len() % 32)) % 32;
        data.extend_from_slice(new_uri.as_bytes());
        data.extend(std::iter::repeat_n(0u8, pad));

        let res = execute_identity(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        // returns bool(true)
        assert_eq!(res.output[31], 1);

        // verify via getAgent
        let stored = registry.get(&agent_id).expect("agent must exist");
        assert_eq!(stored.metadata_uri, new_uri);
    }

    #[test]
    fn set_agent_uri_returns_false_for_unknown_agent() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let unknown = keccak(b"did:tenzro:machine:never-registered");

        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SET_AGENT_URI);
        data.extend_from_slice(&unknown);
        data.extend_from_slice(&abi::encode_uint256(64));
        data.extend_from_slice(&abi::encode_uint256(3));
        data.extend_from_slice(b"abc");
        data.extend(std::iter::repeat_n(0u8, 29));

        let res = execute_identity(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        // returns bool(false)
        assert_eq!(res.output[31], 0);
        // and registry stays untouched
        assert_eq!(registry.agent_count(), 0);
    }

    #[test]
    fn set_agent_wallet_updates_existing_record() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let agent_id = register_basic_agent(&registry, "did:tenzro:machine:wallet-1");

        let new_wallet: [u8; 20] = [0x22; 20];
        // Build calldata: agent_id | new_wallet (padded) | deadline | sig_offset=128 | sig_len=0
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SET_AGENT_WALLET);
        data.extend_from_slice(&agent_id);
        let mut wallet_word = [0u8; 32];
        wallet_word[12..].copy_from_slice(&new_wallet);
        data.extend_from_slice(&wallet_word);
        // deadline: u256 max
        data.extend_from_slice(&[0xff; 32]);
        // signature offset: 128
        data.extend_from_slice(&abi::encode_uint256(128));
        // empty signature tail (length=0)
        data.extend_from_slice(&abi::encode_uint256(0));

        let res = execute_identity(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 1);

        let stored = registry.get(&agent_id).expect("agent must exist");
        assert_eq!(stored.agent_address, new_wallet);
    }

    #[test]
    fn set_agent_wallet_returns_false_for_unknown_agent() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let unknown = keccak(b"did:tenzro:machine:no-wallet");
        let new_wallet: [u8; 20] = [0x33; 20];

        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SET_AGENT_WALLET);
        data.extend_from_slice(&unknown);
        let mut wallet_word = [0u8; 32];
        wallet_word[12..].copy_from_slice(&new_wallet);
        data.extend_from_slice(&wallet_word);
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&abi::encode_uint256(128));
        data.extend_from_slice(&abi::encode_uint256(0));

        let res = execute_identity(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 0);
    }

    #[test]
    fn set_metadata_round_trips_with_get_metadata() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let agent_id = register_basic_agent(&registry, "did:tenzro:machine:meta-1");

        // setMetadata(agent_id, "skills", b"forecast,vision")
        let key = "skills";
        let value: &[u8] = b"forecast,vision";

        // head: [agent_id | key_offset=96 | value_offset=160]
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SET_METADATA);
        data.extend_from_slice(&agent_id);
        data.extend_from_slice(&abi::encode_uint256(96));
        data.extend_from_slice(&abi::encode_uint256(160));
        // key block at offset 96: [len | bytes padded]
        data.extend_from_slice(&abi::encode_uint256(key.len() as u128));
        let kpad = (32 - (key.len() % 32)) % 32;
        data.extend_from_slice(key.as_bytes());
        data.extend(std::iter::repeat_n(0u8, kpad));
        // value block at offset 160: [len | bytes padded]
        data.extend_from_slice(&abi::encode_uint256(value.len() as u128));
        let vpad = (32 - (value.len() % 32)) % 32;
        data.extend_from_slice(value);
        data.extend(std::iter::repeat_n(0u8, vpad));

        let res = execute_identity(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 1);

        // getMetadata(agent_id, "skills")
        let mut get_data = Vec::new();
        get_data.extend_from_slice(&SELECTOR_GET_METADATA);
        get_data.extend_from_slice(&agent_id);
        get_data.extend_from_slice(&abi::encode_uint256(64));
        get_data.extend_from_slice(&abi::encode_uint256(key.len() as u128));
        get_data.extend_from_slice(key.as_bytes());
        get_data.extend(std::iter::repeat_n(0u8, kpad));

        let res = execute_identity(&registry, &get_data, 10_000).unwrap();
        assert!(res.success);
        // [0..32]: offset = 32
        assert_eq!(res.output[31], 32);
        // [32..64]: length
        assert_eq!(res.output[63] as usize, value.len());
        // [64..]: data
        assert_eq!(&res.output[64..64 + value.len()], value);
    }

    #[test]
    fn set_metadata_with_empty_value_deletes_entry() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let agent_id = register_basic_agent(&registry, "did:tenzro:machine:meta-2");

        // First: set "endpoint" → "https://example.com"
        registry.set_metadata(
            agent_id,
            "endpoint".to_string(),
            b"https://example.com".to_vec(),
        );
        assert!(registry.get_metadata(&agent_id, "endpoint").is_some());

        // Now setMetadata(agent_id, "endpoint", []) via the precompile
        let key = "endpoint";
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SET_METADATA);
        data.extend_from_slice(&agent_id);
        data.extend_from_slice(&abi::encode_uint256(96)); // key offset
        data.extend_from_slice(&abi::encode_uint256(160)); // value offset
        // key block
        data.extend_from_slice(&abi::encode_uint256(key.len() as u128));
        let kpad = (32 - (key.len() % 32)) % 32;
        data.extend_from_slice(key.as_bytes());
        data.extend(std::iter::repeat_n(0u8, kpad));
        // empty value block
        data.extend_from_slice(&abi::encode_uint256(0));

        let res = execute_identity(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 1);

        // entry is gone
        assert!(registry.get_metadata(&agent_id, "endpoint").is_none());
    }

    #[test]
    fn get_metadata_unset_returns_empty_bytes() {
        let registry = Arc::new(Erc8004IdentityRegistry::new());
        let agent_id = register_basic_agent(&registry, "did:tenzro:machine:meta-3");

        let key = "missing";
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_GET_METADATA);
        data.extend_from_slice(&agent_id);
        data.extend_from_slice(&abi::encode_uint256(64));
        data.extend_from_slice(&abi::encode_uint256(key.len() as u128));
        let kpad = (32 - (key.len() % 32)) % 32;
        data.extend_from_slice(key.as_bytes());
        data.extend(std::iter::repeat_n(0u8, kpad));

        let res = execute_identity(&registry, &data, 10_000).unwrap();
        assert!(res.success);
        // length is zero
        assert_eq!(res.output[63], 0);
        // total returndata length: 64 bytes (offset + len, no tail)
        assert_eq!(res.output.len(), 64);
    }

    /// Submit a feedback entry through the precompile dispatcher and
    /// return the derived `feedback_id`. Used by the v0.6+ mutator
    /// tests below so they exercise the same code path as production
    /// (register → submit → derive → mutate).
    fn submit_basic_feedback(
        registry: &Erc8004ReputationRegistry,
        subject: [u8; 32],
        rating: i8,
        context_uri: &str,
    ) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_SUBMIT_FEEDBACK);
        data.extend_from_slice(&subject);
        let mut rating_word = if rating < 0 { [0xffu8; 32] } else { [0u8; 32] };
        rating_word[31] = rating as u8;
        data.extend_from_slice(&rating_word);
        data.extend_from_slice(&abi::encode_uint256(96));
        data.extend_from_slice(&abi::encode_uint256(context_uri.len() as u128));
        let pad = (32 - (context_uri.len() % 32)) % 32;
        data.extend_from_slice(context_uri.as_bytes());
        data.extend(std::iter::repeat_n(0u8, pad));
        let res = execute_reputation(registry, &data, 100_000).unwrap();
        assert!(res.success);
        // Derive the same feedback_id the registry computed; it's the
        // entry-at-the-tail's id (this is the first/only submit per
        // subject in our test fixtures).
        let count = registry.count(&subject) as usize;
        let entry = registry
            .get_at(&subject, count - 1)
            .expect("just-submitted entry must exist");
        entry.feedback_id
    }

    #[test]
    fn revoke_feedback_marks_entry_revoked() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:rev-1");
        let feedback_id = submit_basic_feedback(&registry, subject, 4, "ipfs://orig");

        // Pre: entry exists, not revoked
        let before = registry.get_by_id(&subject, &feedback_id).unwrap();
        assert!(!before.revoked);

        // revokeFeedback(subject, feedback_id)
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_REVOKE_FEEDBACK);
        data.extend_from_slice(&subject);
        data.extend_from_slice(&feedback_id);
        let res = execute_reputation(&registry, &data, 50_000).unwrap();
        assert!(res.success);
        // returns bool(true)
        assert_eq!(res.output[31], 1);

        let after = registry.get_by_id(&subject, &feedback_id).unwrap();
        assert!(after.revoked);
    }

    #[test]
    fn revoke_feedback_returns_false_for_unknown_entry() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:rev-2");
        let bogus_id = keccak(b"this-was-never-submitted");

        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_REVOKE_FEEDBACK);
        data.extend_from_slice(&subject);
        data.extend_from_slice(&bogus_id);
        let res = execute_reputation(&registry, &data, 50_000).unwrap();
        assert!(res.success);
        // bool(false): all bytes zero
        assert_eq!(res.output[31], 0);
    }

    #[test]
    fn revoke_feedback_idempotent_second_call_returns_false() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:rev-3");
        let feedback_id = submit_basic_feedback(&registry, subject, 1, "ipfs://once");

        // First revoke succeeds
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_REVOKE_FEEDBACK);
        data.extend_from_slice(&subject);
        data.extend_from_slice(&feedback_id);
        let res = execute_reputation(&registry, &data, 50_000).unwrap();
        assert_eq!(res.output[31], 1);

        // Second revoke returns false (already revoked)
        let res2 = execute_reputation(&registry, &data, 50_000).unwrap();
        assert!(res2.success);
        assert_eq!(res2.output[31], 0);
    }

    #[test]
    fn append_response_attaches_uri_to_existing_entry() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:resp-1");
        let feedback_id = submit_basic_feedback(&registry, subject, -2, "ipfs://negative");

        // appendResponse(subject, feedback_id, "ipfs://rebuttal")
        let response = "ipfs://rebuttal";
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_APPEND_RESPONSE);
        data.extend_from_slice(&subject);
        data.extend_from_slice(&feedback_id);
        data.extend_from_slice(&abi::encode_uint256(96));
        data.extend_from_slice(&abi::encode_uint256(response.len() as u128));
        let pad = (32 - (response.len() % 32)) % 32;
        data.extend_from_slice(response.as_bytes());
        data.extend(std::iter::repeat_n(0u8, pad));

        let res = execute_reputation(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 1);

        let entry = registry.get_by_id(&subject, &feedback_id).unwrap();
        assert_eq!(entry.response_uri, response);
    }

    #[test]
    fn append_response_overwrites_previous_response() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:resp-2");
        let feedback_id = submit_basic_feedback(&registry, subject, 0, "ipfs://ctx");

        // First response
        let r1 = "ipfs://first";
        let mut data1 = Vec::new();
        data1.extend_from_slice(&SELECTOR_APPEND_RESPONSE);
        data1.extend_from_slice(&subject);
        data1.extend_from_slice(&feedback_id);
        data1.extend_from_slice(&abi::encode_uint256(96));
        data1.extend_from_slice(&abi::encode_uint256(r1.len() as u128));
        let pad1 = (32 - (r1.len() % 32)) % 32;
        data1.extend_from_slice(r1.as_bytes());
        data1.extend(std::iter::repeat_n(0u8, pad1));
        let _ = execute_reputation(&registry, &data1, 100_000).unwrap();

        // Second response replaces it
        let r2 = "ipfs://updated";
        let mut data2 = Vec::new();
        data2.extend_from_slice(&SELECTOR_APPEND_RESPONSE);
        data2.extend_from_slice(&subject);
        data2.extend_from_slice(&feedback_id);
        data2.extend_from_slice(&abi::encode_uint256(96));
        data2.extend_from_slice(&abi::encode_uint256(r2.len() as u128));
        let pad2 = (32 - (r2.len() % 32)) % 32;
        data2.extend_from_slice(r2.as_bytes());
        data2.extend(std::iter::repeat_n(0u8, pad2));
        let res = execute_reputation(&registry, &data2, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 1);

        let entry = registry.get_by_id(&subject, &feedback_id).unwrap();
        assert_eq!(entry.response_uri, r2);
    }

    #[test]
    fn append_response_returns_false_for_unknown_entry() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:resp-3");
        let bogus_id = keccak(b"unknown");

        let response = "ipfs://orphan";
        let mut data = Vec::new();
        data.extend_from_slice(&SELECTOR_APPEND_RESPONSE);
        data.extend_from_slice(&subject);
        data.extend_from_slice(&bogus_id);
        data.extend_from_slice(&abi::encode_uint256(96));
        data.extend_from_slice(&abi::encode_uint256(response.len() as u128));
        let pad = (32 - (response.len() % 32)) % 32;
        data.extend_from_slice(response.as_bytes());
        data.extend(std::iter::repeat_n(0u8, pad));

        let res = execute_reputation(&registry, &data, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 0);
    }

    #[test]
    fn submit_then_get_by_id_round_trip() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:hash-1");
        let feedback_id = submit_basic_feedback(&registry, subject, 3, "ipfs://hash-test");

        let entry = registry.get_by_id(&subject, &feedback_id).unwrap();
        assert_eq!(entry.rating, 3);
        assert_eq!(entry.context_uri, "ipfs://hash-test");
        assert!(!entry.revoked);
        assert!(entry.response_uri.is_empty());
        assert_eq!(entry.feedback_id, feedback_id);
    }
}
