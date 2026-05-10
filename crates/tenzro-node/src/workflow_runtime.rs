//! Workflow runtime — node-side glue between the privileged-VM workflow
//! selectors (`0x01000040`–`0x0100004B`) and the typed `WorkflowManager` /
//! `PrivacyDomainRegistry` in `tenzro-workflow`.
//!
//! ## Architecture
//!
//! The native VM owns the on-chain side: gas, payload-size cap, JSON
//! well-formedness, replay marker (`wf:<op>:<id>` under `SYSTEM_ADDRESS`),
//! and the typed `Log` envelope. It deliberately does **not** depend on
//! `tenzro-workflow` — workflow payloads are opaque JSON to the VM.
//!
//! The node-side runtime owns the off-chain side: typed JSON decode,
//! dispatch into the manager (which writes through to RocksDB and emits
//! `WorkflowReceipt`s), and surfacing read accessors to RPC/MCP/A2A.
//!
//! ## Wire format
//!
//! Each VM log carries:
//!
//! ```text
//! data = from(32) || marker_key_len_le(4) || marker_key || payload_len_le(4) || payload
//! ```
//!
//! `marker_key` is `wf:<op>:<id>` and `payload` is the original JSON the
//! caller supplied. The `op` prefix and the `topic` are byte-identical
//! after lower-casing — `WorkflowCreate → wf:create:…`, etc.
//!
//! ## Errors
//!
//! Decode/dispatch failures are logged as `warn!` and skipped. Mirroring
//! must never abort the block — divergence is recoverable on restart via
//! `WorkflowManager::with_storage` hydration from the same RocksDB state.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenzro_storage::kv::KvStore;
use tenzro_types::primitives::{BlockHeight, Hash};
use tenzro_workflow::{
    ApprovalDecision, ApprovalGate, DischargeProof, FeeRouteRegistry, KillSwitchScope,
    Obligation, ParticipantSignature, PrivacyDomain, PrivacyDomainRegistry, Workflow,
    WorkflowManager, WorkflowStatus,
};
use tracing::{debug, warn};

/// Bundles the workflow manager and privacy-domain registry behind a single
/// `Arc` for ergonomic wiring into the event loop, RPC layer, MCP layer,
/// and A2A server.
pub struct WorkflowRuntime {
    manager: Arc<WorkflowManager>,
    privacy: Arc<PrivacyDomainRegistry>,
    fee_routes: Arc<FeeRouteRegistry>,
}

impl WorkflowRuntime {
    /// Construct a fresh runtime with no persistence backend (tests only).
    pub fn new() -> Self {
        Self {
            manager: Arc::new(WorkflowManager::new()),
            privacy: Arc::new(PrivacyDomainRegistry::new()),
            fee_routes: Arc::new(FeeRouteRegistry::new()),
        }
    }

    /// Construct a runtime backed by RocksDB. Hydrates the manager
    /// (workflows, obligations, approvals, lifecycle history, receipt
    /// chain heads), the privacy-domain registry, and the fee-route
    /// registry from `CF_SETTLEMENTS` + `CF_APPROVALS`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self, tenzro_workflow::WorkflowError> {
        let manager = Arc::new(WorkflowManager::with_storage(storage.clone())?);
        let privacy = Arc::new(PrivacyDomainRegistry::with_storage(storage.clone())?);
        let fee_routes = Arc::new(FeeRouteRegistry::with_storage(storage)?);
        Ok(Self {
            manager,
            privacy,
            fee_routes,
        })
    }

    pub fn manager(&self) -> &Arc<WorkflowManager> {
        &self.manager
    }

    pub fn privacy(&self) -> &Arc<PrivacyDomainRegistry> {
        &self.privacy
    }

    pub fn fee_routes(&self) -> &Arc<FeeRouteRegistry> {
        &self.fee_routes
    }

    /// Build an `OperationalMetrics` snapshot by walking the manager's
    /// in-memory indices and joining the sibling registry totals
    /// (fee routes, privacy domains).
    pub fn operational_metrics(&self) -> tenzro_workflow::OperationalMetrics {
        self.manager.operational_metrics(
            self.fee_routes.list().len() as u64,
            self.privacy.len() as u64,
        )
    }
}

impl Default for WorkflowRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// --- Wire-format decode helpers ---

/// Skip the `from(32) || marker_key_len(4) || marker_key || payload_len(4)`
/// header and return the raw JSON payload bytes.
pub(crate) fn decode_workflow_log_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 32 + 4 {
        return None;
    }
    let mut o = 32;
    let mk_len_bytes: [u8; 4] = data[o..o + 4].try_into().ok()?;
    let mk_len = u32::from_le_bytes(mk_len_bytes) as usize;
    o += 4;
    if data.len() < o + mk_len + 4 {
        return None;
    }
    o += mk_len;
    let pl_len_bytes: [u8; 4] = data[o..o + 4].try_into().ok()?;
    let pl_len = u32::from_le_bytes(pl_len_bytes) as usize;
    o += 4;
    if data.len() < o + pl_len {
        return None;
    }
    Some(&data[o..o + pl_len])
}

// --- Typed JSON payload schemas ---
//
// Each variant mirrors the JSON the CLI/RPC/SDK sends through the privileged
// VM selector. Field names match the keys `workflow_extract_field` reads in
// `tenzro-vm/src/native/mod.rs`; additional fields carry the rich payload.

/// `WorkflowCreate` payload — full workflow blob.
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateWorkflowPayload {
    /// Echoed in the marker for replay; the manager re-derives the id from
    /// the inner workflow body.
    pub workflow_id: String,
    pub workflow: Workflow,
}

/// `WorkflowSign` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignWorkflowPayload {
    pub workflow_id: String,
    pub signer_did: String,
    pub signature: ParticipantSignature,
    pub at: i64,
}

/// `WorkflowTransition` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransitionWorkflowPayload {
    pub workflow_id: String,
    pub to_status: String,
    pub trigger: tenzro_workflow::TransitionTrigger,
    pub at: i64,
}

/// `WorkflowObligationRegister` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterObligationPayload {
    pub obligation_id: String,
    pub obligation: Obligation,
}

/// `WorkflowObligationDischarge` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct DischargeObligationPayload {
    pub obligation_id: String,
    pub proof: DischargeProof,
    pub at: i64,
}

/// `WorkflowObligationDefault` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct DefaultObligationPayload {
    pub obligation_id: String,
    pub reason: String,
    pub at: i64,
}

/// `WorkflowGateRegister` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterGatePayload {
    pub gate_id: String,
    pub gate: ApprovalGate,
}

/// `WorkflowApprovalOpen` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct OpenApprovalPayload {
    pub request_id: String,
    pub gate_id: String,
    pub trigger_context: serde_json::Value,
    pub created_at: i64,
}

/// `WorkflowApprovalDecision` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct SubmitDecisionPayload {
    pub request_id: String,
    pub approver_did: String,
    pub decision: ApprovalDecision,
}

/// `WorkflowKillSwitch` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct KillSwitchPayload {
    pub workflow_id: String,
    pub invoker: String,
    pub scope: KillSwitchScope,
    pub reason: String,
    pub at: i64,
}

/// `WorkflowPrivacyDomainRegister` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterPrivacyDomainPayload {
    pub domain_id: String,
    pub domain: PrivacyDomain,
}

/// `WorkflowPrivacyDomainFreeze` payload.
#[derive(Debug, Deserialize, Serialize)]
pub struct FreezePrivacyDomainPayload {
    pub domain_id: String,
}

// --- Status string parsing for transition payloads ---

fn parse_status(s: &str) -> Option<WorkflowStatus> {
    match s {
        "draft" => Some(WorkflowStatus::Draft),
        "awaiting_signatures" => Some(WorkflowStatus::AwaitingSignatures),
        "active" => Some(WorkflowStatus::Active),
        "suspended" => Some(WorkflowStatus::Suspended),
        "settling" => Some(WorkflowStatus::Settling),
        "completed" => Some(WorkflowStatus::Completed),
        "failed" => Some(WorkflowStatus::Failed),
        "disputed" => Some(WorkflowStatus::Disputed),
        "cancelled" => Some(WorkflowStatus::Cancelled),
        _ => None,
    }
}

// --- Dispatch entry points used by the EventLoop ---
//
// Each function takes the raw VM log payload (bytes after the topic) and
// applies the typed mutation against the runtime. A failure is logged but
// does not propagate — see module-level docs.

impl WorkflowRuntime {
    pub fn apply_create(&self, log_data: &[u8], block_height: BlockHeight) {
        let payload = match decode_workflow_log_payload(log_data) {
            Some(p) => p,
            None => {
                warn!(block_height = block_height.0, "Malformed WorkflowCreate log");
                return;
            }
        };
        let p: CreateWorkflowPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowCreate JSON decode failed");
                return;
            }
        };
        match self.manager.create_workflow(p.workflow) {
            Ok(id) => debug!(workflow_id = %hex::encode(id.as_bytes()), "WorkflowCreate mirrored"),
            Err(e) => warn!(error = %e, "WorkflowCreate mirror rejected"),
        }
    }

    pub fn apply_sign(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowSign log");
            return;
        };
        let p: SignWorkflowPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowSign JSON decode failed");
                return;
            }
        };
        let Some(wf_id) = parse_hash_hex(&p.workflow_id) else {
            warn!(workflow_id = %p.workflow_id, "WorkflowSign: invalid workflow_id hex");
            return;
        };
        if let Err(e) = self.manager.sign(&wf_id, p.signature, p.at) {
            warn!(workflow_id = %p.workflow_id, signer = %p.signer_did, error = %e, "WorkflowSign mirror rejected");
        }
    }

    pub fn apply_transition(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowTransition log");
            return;
        };
        let p: TransitionWorkflowPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowTransition JSON decode failed");
                return;
            }
        };
        let Some(wf_id) = parse_hash_hex(&p.workflow_id) else {
            warn!(workflow_id = %p.workflow_id, "WorkflowTransition: invalid workflow_id hex");
            return;
        };
        let Some(next) = parse_status(&p.to_status) else {
            warn!(to = %p.to_status, "WorkflowTransition: unknown target status");
            return;
        };
        if let Err(e) = self.manager.transition(&wf_id, next, p.trigger, p.at) {
            warn!(workflow_id = %p.workflow_id, to = %p.to_status, error = %e, "WorkflowTransition mirror rejected");
        }
    }

    pub fn apply_register_obligation(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowObligationRegister log");
            return;
        };
        let p: RegisterObligationPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowObligationRegister JSON decode failed");
                return;
            }
        };
        if let Err(e) = self.manager.record_obligation(p.obligation) {
            warn!(obligation = %p.obligation_id, error = %e, "WorkflowObligationRegister mirror rejected");
        }
    }

    pub fn apply_discharge_obligation(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowObligationDischarge log");
            return;
        };
        let p: DischargeObligationPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowObligationDischarge JSON decode failed");
                return;
            }
        };
        let Some(oid) = parse_hash_hex(&p.obligation_id) else {
            warn!(obligation = %p.obligation_id, "WorkflowObligationDischarge: invalid id hex");
            return;
        };
        if let Err(e) = self.manager.discharge(&oid, p.proof, p.at) {
            warn!(obligation = %p.obligation_id, error = %e, "WorkflowObligationDischarge mirror rejected");
        }
    }

    pub fn apply_default_obligation(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowObligationDefault log");
            return;
        };
        let p: DefaultObligationPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowObligationDefault JSON decode failed");
                return;
            }
        };
        let Some(oid) = parse_hash_hex(&p.obligation_id) else {
            warn!(obligation = %p.obligation_id, "WorkflowObligationDefault: invalid id hex");
            return;
        };
        if let Err(e) = self.manager.default_obligation(&oid, p.reason, p.at) {
            warn!(obligation = %p.obligation_id, error = %e, "WorkflowObligationDefault mirror rejected");
        }
    }

    pub fn apply_register_gate(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowGateRegister log");
            return;
        };
        let p: RegisterGatePayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowGateRegister JSON decode failed");
                return;
            }
        };
        if let Err(e) = self.manager.register_gate(p.gate) {
            warn!(gate = %p.gate_id, error = %e, "WorkflowGateRegister mirror rejected");
        }
    }

    pub fn apply_open_approval(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowApprovalOpen log");
            return;
        };
        let p: OpenApprovalPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowApprovalOpen JSON decode failed");
                return;
            }
        };
        let Some(gid) = parse_hash_hex(&p.gate_id) else {
            warn!(gate = %p.gate_id, "WorkflowApprovalOpen: invalid gate_id hex");
            return;
        };
        if let Err(e) = self.manager.open_approval(&gid, p.trigger_context, p.created_at) {
            warn!(gate = %p.gate_id, error = %e, "WorkflowApprovalOpen mirror rejected");
        }
    }

    pub fn apply_submit_decision(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowApprovalDecision log");
            return;
        };
        let p: SubmitDecisionPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowApprovalDecision JSON decode failed");
                return;
            }
        };
        let Some(rid) = parse_hash_hex(&p.request_id) else {
            warn!(request = %p.request_id, "WorkflowApprovalDecision: invalid request_id hex");
            return;
        };
        // The decision owner field on `ApprovalDecision` is `by`; it must match
        // the marker's `approver_did`. Validate before submitting so a forged
        // log with mismatched fields is rejected here.
        if p.decision.by != p.approver_did {
            warn!(
                request = %p.request_id,
                marker = %p.approver_did,
                decision_by = %p.decision.by,
                "WorkflowApprovalDecision: marker DID and decision DID disagree"
            );
            return;
        }
        match self.manager.submit_decision(&rid, p.decision) {
            Ok(_) => {}
            Err(e) => warn!(request = %p.request_id, error = %e, "WorkflowApprovalDecision mirror rejected"),
        }
    }

    pub fn apply_kill_switch(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowKillSwitch log");
            return;
        };
        let p: KillSwitchPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowKillSwitch JSON decode failed");
                return;
            }
        };
        let Some(wf_id) = parse_hash_hex(&p.workflow_id) else {
            warn!(workflow_id = %p.workflow_id, "WorkflowKillSwitch: invalid workflow_id hex");
            return;
        };
        if let Err(e) = self.manager.invoke_kill_switch(&wf_id, p.invoker, p.scope, p.reason, p.at) {
            warn!(workflow_id = %p.workflow_id, error = %e, "WorkflowKillSwitch mirror rejected");
        }
    }

    pub fn apply_register_privacy_domain(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowPrivacyDomainRegister log");
            return;
        };
        let p: RegisterPrivacyDomainPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowPrivacyDomainRegister JSON decode failed");
                return;
            }
        };
        if let Err(e) = self.privacy.register(p.domain) {
            warn!(domain = %p.domain_id, error = %e, "WorkflowPrivacyDomainRegister mirror rejected");
        }
    }

    pub fn apply_freeze_privacy_domain(&self, log_data: &[u8], block_height: BlockHeight) {
        let Some(payload) = decode_workflow_log_payload(log_data) else {
            warn!(block_height = block_height.0, "Malformed WorkflowPrivacyDomainFreeze log");
            return;
        };
        let p: FreezePrivacyDomainPayload = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(e) => {
                warn!(block_height = block_height.0, error = %e, "WorkflowPrivacyDomainFreeze JSON decode failed");
                return;
            }
        };
        let Some(did) = parse_hash_hex(&p.domain_id) else {
            warn!(domain = %p.domain_id, "WorkflowPrivacyDomainFreeze: invalid domain_id hex");
            return;
        };
        if let Err(e) = self.privacy.freeze(&did) {
            warn!(domain = %p.domain_id, error = %e, "WorkflowPrivacyDomainFreeze mirror rejected");
        }
    }
}

fn parse_hash_hex(s: &str) -> Option<Hash> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Hash::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_workflow::{Participant, ParticipantRole, PolicyExpr, WorkflowStatus};

    fn mk_log_data(payload: &[u8]) -> Vec<u8> {
        let from = [0u8; 32];
        let marker_key = b"wf:create:abc";
        let mut data = Vec::new();
        data.extend_from_slice(&from);
        data.extend_from_slice(&(marker_key.len() as u32).to_le_bytes());
        data.extend_from_slice(marker_key);
        data.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn decode_workflow_log_payload_round_trips() {
        let payload = br#"{"hello":"world"}"#;
        let data = mk_log_data(payload);
        let decoded = decode_workflow_log_payload(&data).unwrap();
        assert_eq!(decoded, payload.as_slice());
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(decode_workflow_log_payload(&[0u8; 10]).is_none());
        assert!(decode_workflow_log_payload(&[]).is_none());
    }

    #[test]
    fn parse_hash_hex_round_trip() {
        let h = Hash::from([0x77u8; 32]);
        let s = hex::encode(h.as_bytes());
        assert_eq!(parse_hash_hex(&s), Some(h));
        assert_eq!(parse_hash_hex(&format!("0x{}", s)), Some(h));
        assert_eq!(parse_hash_hex("not hex"), None);
        assert_eq!(parse_hash_hex(""), None);
    }

    #[test]
    fn apply_create_round_trips() {
        let rt = WorkflowRuntime::new();
        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";
        let wf = Workflow {
            workflow_id: Hash::default(),
            template_id: None,
            creator: alice.into(),
            title: "test".into(),
            description: None,
            participants: vec![
                Participant::new(alice, vec![ParticipantRole::Initiator]),
                Participant::new(bob, vec![ParticipantRole::Counterparty]),
            ],
            obligations: vec![],
            approval_gates: vec![],
            root_policy: PolicyExpr::Allow,
            privacy_domain: None,
            fee_route: None,
            signatures: vec![],
            status: WorkflowStatus::Draft,
            canton_mirror: None,
            created_at: 100,
            updated_at: 100,
        };
        let payload = serde_json::to_vec(&CreateWorkflowPayload {
            workflow_id: hex::encode([0u8; 32]),
            workflow: wf,
        })
        .unwrap();
        let data = mk_log_data(&payload);
        rt.apply_create(&data, BlockHeight::from(1));
        // After the apply, exactly one workflow exists in the manager.
        assert_eq!(rt.manager.workflow_count(), 1);
    }

    #[test]
    fn apply_create_rejects_malformed_json() {
        let rt = WorkflowRuntime::new();
        let data = mk_log_data(b"not json");
        rt.apply_create(&data, BlockHeight::from(1));
        // Should be no-op: count remains zero and no panic.
        assert_eq!(rt.manager.workflow_count(), 0);
    }
}
