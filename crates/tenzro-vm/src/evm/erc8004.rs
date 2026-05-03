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
//! - **0x101c — ValidationRegistry**: `requestValidation` / `submitValidation`
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
use sha3::{Digest, Keccak256};
use std::sync::Arc;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Gas constants
// ---------------------------------------------------------------------------

/// Gas cost for registering or updating an agent in IdentityRegistry
const GAS_REGISTER_AGENT: u64 = 80_000;
/// Gas cost for submitting a feedback entry to ReputationRegistry
const GAS_SUBMIT_FEEDBACK: u64 = 60_000;
/// Gas cost for opening a validation request
const GAS_REQUEST_VALIDATION: u64 = 60_000;
/// Gas cost for submitting a validation result
const GAS_SUBMIT_VALIDATION: u64 = 60_000;
/// Gas cost for read-only queries
const GAS_READ: u64 = 2_600;

// ---------------------------------------------------------------------------
// Function selectors (byte-identical to tenzro_identity::erc8004::selectors)
// ---------------------------------------------------------------------------

/// `registerAgent(bytes32 agentId, address agentAddress, string metadataUri)`
const SELECTOR_REGISTER_AGENT: [u8; 4] = [0xaa, 0xa3, 0x8f, 0x6c];
/// `getAgent(bytes32 agentId)`
const SELECTOR_GET_AGENT: [u8; 4] = [0xdb, 0x4a, 0x7a, 0x9a];
/// `submitFeedback(bytes32 subject, int8 rating, string contextUri)`
const SELECTOR_SUBMIT_FEEDBACK: [u8; 4] = [0x3b, 0x2d, 0x6e, 0x41];
/// `getFeedback(bytes32 subject, uint256 index)`
const SELECTOR_GET_FEEDBACK: [u8; 4] = [0x7c, 0x9d, 0x4f, 0x52];
/// `getFeedbackCount(bytes32 subject)`
const SELECTOR_GET_FEEDBACK_COUNT: [u8; 4] = [0x4e, 0x71, 0xa2, 0x18];
/// `requestValidation(bytes32 subject, string taskUri)`
const SELECTOR_REQUEST_VALIDATION: [u8; 4] = [0x1a, 0x8f, 0x2c, 0x7b];
/// `submitValidation(bytes32 requestId, bool valid, string proofUri)`
const SELECTOR_SUBMIT_VALIDATION: [u8; 4] = [0x5c, 0x9e, 0x3d, 0x81];
/// `getValidation(bytes32 requestId)`
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
#[derive(Debug, Clone)]
pub struct FeedbackEntry {
    pub subject: [u8; 32],
    pub rater: [u8; 20],
    pub rating: i8,
    pub context_uri: String,
}

/// State machine for a validation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    Pending = 0,
    Valid = 1,
    Invalid = 2,
}

/// On-chain validation entry — opened with `requestValidation`, closed
/// by a validator with `submitValidation`.
#[derive(Debug, Clone)]
pub struct ValidationEntry {
    pub request_id: [u8; 32],
    pub subject: [u8; 32],
    pub task_uri: String,
    pub status: ValidationStatus,
    pub validator: [u8; 20],
    pub proof_uri: String,
}

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

/// Native Tenzro IdentityRegistry — maps `agentId -> AgentRecord`.
pub struct Erc8004IdentityRegistry {
    agents: DashMap<[u8; 32], AgentRecord>,
}

impl Erc8004IdentityRegistry {
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
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
}

impl Default for Erc8004IdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Native Tenzro ReputationRegistry — append-only feedback per subject.
pub struct Erc8004ReputationRegistry {
    /// `subject_agent_id -> Vec<FeedbackEntry>`
    feedback: DashMap<[u8; 32], Vec<FeedbackEntry>>,
}

impl Erc8004ReputationRegistry {
    pub fn new() -> Self {
        Self {
            feedback: DashMap::new(),
        }
    }

    pub fn submit(&self, entry: FeedbackEntry) {
        self.feedback.entry(entry.subject).or_default().push(entry);
    }

    pub fn count(&self, subject: &[u8; 32]) -> u128 {
        self.feedback.get(subject).map(|v| v.len() as u128).unwrap_or(0)
    }

    pub fn get_at(&self, subject: &[u8; 32], index: usize) -> Option<FeedbackEntry> {
        self.feedback
            .get(subject)
            .and_then(|v| v.get(index).cloned())
    }
}

impl Default for Erc8004ReputationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Native Tenzro ValidationRegistry — request/submit/lookup with a
/// deterministic `requestId = keccak256("erc8004-validation:" ++ subject ++ nonce_be)`.
pub struct Erc8004ValidationRegistry {
    requests: DashMap<[u8; 32], ValidationEntry>,
    /// Per-subject monotonic nonce for deterministic request IDs.
    subject_nonces: DashMap<[u8; 32], u64>,
}

impl Erc8004ValidationRegistry {
    pub fn new() -> Self {
        Self {
            requests: DashMap::new(),
            subject_nonces: DashMap::new(),
        }
    }

    fn next_nonce(&self, subject: &[u8; 32]) -> u64 {
        let mut entry = self.subject_nonces.entry(*subject).or_insert(0);
        let n = *entry;
        *entry = n.saturating_add(1);
        n
    }

    /// Allocate a new request_id and store the pending entry.
    pub fn open_request(&self, subject: [u8; 32], task_uri: String) -> [u8; 32] {
        let nonce = self.next_nonce(&subject);
        let request_id = compute_request_id(&subject, nonce);
        let entry = ValidationEntry {
            request_id,
            subject,
            task_uri,
            status: ValidationStatus::Pending,
            validator: [0u8; 20],
            proof_uri: String::new(),
        };
        self.requests.insert(request_id, entry);
        request_id
    }

    /// Close an open request. Returns `false` if not found or already closed.
    pub fn close_request(
        &self,
        request_id: &[u8; 32],
        validator: [u8; 20],
        valid: bool,
        proof_uri: String,
    ) -> bool {
        let mut entry = match self.requests.get_mut(request_id) {
            Some(e) => e,
            None => return false,
        };
        if entry.status != ValidationStatus::Pending {
            return false;
        }
        entry.status = if valid {
            ValidationStatus::Valid
        } else {
            ValidationStatus::Invalid
        };
        entry.validator = validator;
        entry.proof_uri = proof_uri;
        true
    }

    pub fn get(&self, request_id: &[u8; 32]) -> Option<ValidationEntry> {
        self.requests.get(request_id).map(|e| e.clone())
    }
}

impl Default for Erc8004ValidationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// `request_id = keccak256("erc8004-validation:" ++ subject_be ++ nonce_be)`
fn compute_request_id(subject: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"erc8004-validation:");
    hasher.update(subject);
    hasher.update(nonce.to_be_bytes());
    let out = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&out);
    id
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
    };
    registry.submit(entry);

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
        s if s == SELECTOR_REQUEST_VALIDATION => {
            handle_request_validation(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_SUBMIT_VALIDATION => {
            handle_submit_validation(registry, calldata, gas_limit)
        }
        s if s == SELECTOR_GET_VALIDATION => handle_get_validation(registry, calldata, gas_limit),
        _ => Ok(PrecompileResult::failed(gas_limit)),
    }
}

/// `requestValidation(bytes32 subject, string taskUri) -> bytes32 requestId`
///
/// Calldata layout (after selector):
///   [0..32]   subject
///   [32..64]  offset to taskUri
///   [64..]    taskUri data
fn handle_request_validation(
    registry: &Erc8004ValidationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_REQUEST_VALIDATION {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 64 {
        return Ok(PrecompileResult::failed(GAS_REQUEST_VALIDATION));
    }

    let mut subject = [0u8; 32];
    subject.copy_from_slice(&calldata[..32]);

    let task_uri = decode_dynamic_string(calldata, 32).unwrap_or_default();

    let request_id = registry.open_request(subject, task_uri.clone());

    info!(
        "ERC-8004 ValidationRegistry: opened request_id=0x{} subject=0x{} task={}",
        hex::encode(request_id),
        hex::encode(subject),
        task_uri,
    );

    Ok(PrecompileResult::success(
        request_id.to_vec(),
        GAS_REQUEST_VALIDATION,
    ))
}

/// `submitValidation(bytes32 requestId, bool valid, string proofUri) -> bool`
fn handle_submit_validation(
    registry: &Erc8004ValidationRegistry,
    calldata: &[u8],
    gas_limit: u64,
) -> Result<PrecompileResult> {
    if gas_limit < GAS_SUBMIT_VALIDATION {
        return Err(VmError::OutOfGas);
    }
    if calldata.len() < 96 {
        return Ok(PrecompileResult::failed(GAS_SUBMIT_VALIDATION));
    }

    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(&calldata[..32]);

    let valid_byte = calldata[63];
    let valid = valid_byte != 0;

    let proof_uri = decode_dynamic_string(calldata, 64).unwrap_or_default();

    let ok = registry.close_request(&request_id, [0u8; 20], valid, proof_uri.clone());

    debug!(
        "ERC-8004 ValidationRegistry: submitted request_id=0x{} valid={} proof={} ok={}",
        hex::encode(request_id),
        valid,
        proof_uri,
        ok,
    );

    Ok(PrecompileResult::success(
        abi::encode_bool(ok),
        GAS_SUBMIT_VALIDATION,
    ))
}

/// `getValidation(bytes32 requestId)`
///
/// Returns ABI-encoded `(bytes32 subject, uint8 status, address validator,
/// string taskUri, string proofUri, bool exists)`.
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

    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(&calldata[..32]);

    match registry.get(&request_id) {
        Some(entry) => Ok(PrecompileResult::success(
            encode_get_validation_result(
                &entry.subject,
                entry.status,
                &entry.validator,
                &entry.task_uri,
                &entry.proof_uri,
                true,
            ),
            GAS_READ,
        )),
        None => Ok(PrecompileResult::success(
            encode_get_validation_result(
                &[0u8; 32],
                ValidationStatus::Pending,
                &[0u8; 20],
                "",
                "",
                false,
            ),
            GAS_READ,
        )),
    }
}

fn encode_get_validation_result(
    subject: &[u8; 32],
    status: ValidationStatus,
    validator: &[u8; 20],
    task_uri: &str,
    proof_uri: &str,
    exists: bool,
) -> Vec<u8> {
    // Fixed head: 6 slots × 32 = 192 bytes
    //   [0..32]    subject
    //   [32..64]   status (uint8 padded)
    //   [64..96]   validator (address padded)
    //   [96..128]  offset to taskUri
    //   [128..160] offset to proofUri
    //   [160..192] exists
    let task_bytes = task_uri.as_bytes();
    let task_padded = task_bytes.len().div_ceil(32) * 32;
    let task_block = 32 + task_padded;
    let proof_offset = 192 + task_block;

    let proof_bytes = proof_uri.as_bytes();
    let proof_padded = proof_bytes.len().div_ceil(32) * 32;

    let total_len = proof_offset + 32 + proof_padded;
    let mut out = vec![0u8; total_len];

    // subject
    out[..32].copy_from_slice(subject);
    // status
    out[63] = status as u8;
    // validator (left-padded)
    out[76..96].copy_from_slice(validator);
    // task offset
    out[96..128].copy_from_slice(&abi::encode_uint256(192));
    // proof offset
    out[128..160].copy_from_slice(&abi::encode_uint256(proof_offset as u128));
    // exists
    out[160..192].copy_from_slice(&abi::encode_bool(exists));

    // task dynamic block
    out[192..224].copy_from_slice(&abi::encode_uint256(task_bytes.len() as u128));
    out[224..224 + task_bytes.len()].copy_from_slice(task_bytes);

    // proof dynamic block
    out[proof_offset..proof_offset + 32]
        .copy_from_slice(&abi::encode_uint256(proof_bytes.len() as u128));
    out[proof_offset + 32..proof_offset + 32 + proof_bytes.len()].copy_from_slice(proof_bytes);

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn validation_request_then_submit_then_get() {
        let registry = Arc::new(Erc8004ValidationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:worker");

        // requestValidation(subject, "ipfs://task")
        let mut req_input = Vec::new();
        req_input.extend_from_slice(&SELECTOR_REQUEST_VALIDATION);
        req_input.extend_from_slice(&subject);
        req_input.extend_from_slice(&abi::encode_uint256(64)); // offset = 64 (after the 2 head slots)
        let task = "ipfs://task";
        req_input.extend_from_slice(&abi::encode_uint256(task.len() as u128));
        let pad = (32 - (task.len() % 32)) % 32;
        req_input.extend_from_slice(task.as_bytes());
        req_input.extend(std::iter::repeat_n(0u8, pad));

        let res = execute_validation(&registry, &req_input, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output.len(), 32);
        let mut request_id = [0u8; 32];
        request_id.copy_from_slice(&res.output);

        // determinism: re-derive the request_id
        assert_eq!(request_id, compute_request_id(&subject, 0));

        // submitValidation(request_id, true, "ipfs://proof")
        let mut sub_input = Vec::new();
        sub_input.extend_from_slice(&SELECTOR_SUBMIT_VALIDATION);
        sub_input.extend_from_slice(&request_id);
        // valid bool word
        let mut valid_word = [0u8; 32];
        valid_word[31] = 1;
        sub_input.extend_from_slice(&valid_word);
        // offset to proof string = 96
        sub_input.extend_from_slice(&abi::encode_uint256(96));
        let proof = "ipfs://proof";
        sub_input.extend_from_slice(&abi::encode_uint256(proof.len() as u128));
        let pad = (32 - (proof.len() % 32)) % 32;
        sub_input.extend_from_slice(proof.as_bytes());
        sub_input.extend(std::iter::repeat_n(0u8, pad));

        let res = execute_validation(&registry, &sub_input, 100_000).unwrap();
        assert!(res.success);
        assert_eq!(res.output[31], 1);

        // getValidation
        let mut get_input = Vec::new();
        get_input.extend_from_slice(&SELECTOR_GET_VALIDATION);
        get_input.extend_from_slice(&request_id);
        let res = execute_validation(&registry, &get_input, 10_000).unwrap();
        assert!(res.success);
        // subject in [0..32]
        assert_eq!(&res.output[..32], &subject);
        // status at byte 63 = Valid (1)
        assert_eq!(res.output[63], 1);
        // exists at [160..192] last byte
        assert_eq!(res.output[191], 1);
    }

    #[test]
    fn validation_double_submit_rejected() {
        let registry = Arc::new(Erc8004ValidationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:once");

        let request_id = registry.open_request(subject, "task".to_string());

        // First submit succeeds
        let ok = registry.close_request(&request_id, [0u8; 20], true, "proof".to_string());
        assert!(ok);

        // Second submit on the same request fails
        let ok = registry.close_request(&request_id, [0u8; 20], true, "proof2".to_string());
        assert!(!ok);
    }

    #[test]
    fn validation_request_ids_are_unique_per_subject() {
        let registry = Arc::new(Erc8004ValidationRegistry::new());
        let subject = keccak(b"did:tenzro:machine:repeater");

        let id1 = registry.open_request(subject, "task1".to_string());
        let id2 = registry.open_request(subject, "task2".to_string());
        assert_ne!(id1, id2);
        assert_eq!(id1, compute_request_id(&subject, 0));
        assert_eq!(id2, compute_request_id(&subject, 1));
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
}
