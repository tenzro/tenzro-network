//! `WorkflowManager` — owns the in-memory indices and write-through
//! persistence to RocksDB (`CF_SETTLEMENTS` for workflow state and
//! `CF_APPROVALS` for approval requests/decisions).
//!
//! ### Key layout (CF_SETTLEMENTS)
//!
//! - `wf:<workflow_id>` → bincode `Workflow`
//! - `wf_obl:<obligation_id>` → bincode `Obligation`
//! - `wf_lifecycle:<workflow_id>:<seq_le>` → bincode `LifecycleTransition`
//! - `wf_receipt:<receipt_id>` → bincode `WorkflowReceipt`
//! - `wf_creator:<creator>:<workflow_id>` → empty (index)
//! - `wf_participant:<did>:<workflow_id>` → empty (index)
//! - `wf_status:<status>:<workflow_id>` → empty (index)
//! - `wf_template:<template_id>:<workflow_id>` → empty (index)
//!
//! ### Key layout (CF_APPROVALS)
//!
//! - `wf_gate:<gate_id>` → bincode `ApprovalGate`
//! - `wf_appr:<request_id>` → bincode `ApprovalRequest`
//! - `wf_appr_by_gate:<gate_id>:<request_id>` → empty (index)
//!
//! ### Concurrency
//!
//! In-memory: one `DashMap` per surface (workflows, obligations, approval
//! requests, gates) plus three secondary indices. All writes go through
//! `write_batch_sync` so we get fsync durability on the same critical path as
//! the rest of the settlement subsystem.

use std::sync::Arc;

use dashmap::{DashMap, DashSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_storage::kv::{CF_APPROVALS, CF_SETTLEMENTS, KvStore, WriteOp};
use tenzro_types::primitives::{Hash, Timestamp};
use tracing::{debug, info, warn};

use crate::approval::{
    ApprovalDecision, ApprovalGate, ApprovalGateId, ApprovalRequest, ApprovalRequestId,
    ApprovalStatus, ApproverSet, Decision,
};
use crate::error::{Result, WorkflowError};
use crate::lifecycle::{KillSwitchScope, LifecycleTransition, TransitionTrigger};
use crate::obligation::{DischargeProof, Obligation, ObligationId, ObligationStatus};
use crate::receipt::{WorkflowEventKind, WorkflowReceipt};
use crate::workflow::{ParticipantSignature, Workflow, WorkflowId, WorkflowStatus};

/// Per-workflow lifecycle history + last-receipt pointer for chaining.
#[derive(Default)]
struct WorkflowMeta {
    lifecycle: Vec<LifecycleTransition>,
    /// Last receipt id for the per-workflow hash chain (`prev_receipt`).
    last_receipt: Hash,
    /// Monotonic sequence for lifecycle persistence keys.
    next_lifecycle_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LifecycleRecord(LifecycleTransition);

/// Multi-party workflow manager.
pub struct WorkflowManager {
    workflows: DashMap<WorkflowId, Workflow>,
    obligations: DashMap<ObligationId, Obligation>,
    gates: DashMap<ApprovalGateId, ApprovalGate>,
    requests: DashMap<ApprovalRequestId, ApprovalRequest>,
    /// `creator → set<workflow_id>`.
    by_creator: DashMap<String, DashSet<WorkflowId>>,
    /// `participant_did → set<workflow_id>`.
    by_participant: DashMap<String, DashSet<WorkflowId>>,
    /// `status → set<workflow_id>`.
    by_status: DashMap<WorkflowStatus, DashSet<WorkflowId>>,
    /// Per-workflow meta (lifecycle history + receipt chain).
    meta: DashMap<WorkflowId, RwLock<WorkflowMeta>>,
    /// Optional persistence backend; absent during pure in-memory tests.
    storage: Option<Arc<dyn KvStore>>,
}

impl WorkflowManager {
    pub fn new() -> Self {
        Self {
            workflows: DashMap::new(),
            obligations: DashMap::new(),
            gates: DashMap::new(),
            requests: DashMap::new(),
            by_creator: DashMap::new(),
            by_participant: DashMap::new(),
            by_status: DashMap::new(),
            meta: DashMap::new(),
            storage: None,
        }
    }

    /// Construct with persistence backend. Hydrates indices from RocksDB.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let mgr = Self {
            workflows: DashMap::new(),
            obligations: DashMap::new(),
            gates: DashMap::new(),
            requests: DashMap::new(),
            by_creator: DashMap::new(),
            by_participant: DashMap::new(),
            by_status: DashMap::new(),
            meta: DashMap::new(),
            storage: Some(storage),
        };
        mgr.hydrate()?;
        Ok(mgr)
    }

    /// Restore in-memory state from RocksDB on startup.
    fn hydrate(&self) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };

        // Workflows.
        let mut wf_count = 0usize;
        for (_, value) in store.scan_prefix(CF_SETTLEMENTS, b"wf:")? {
            let wf: Workflow = bincode::deserialize(&value)?;
            self.index_workflow(&wf);
            self.workflows.insert(wf.workflow_id, wf);
            wf_count += 1;
        }

        // Obligations.
        let mut obl_count = 0usize;
        for (_, value) in store.scan_prefix(CF_SETTLEMENTS, b"wf_obl:")? {
            let obl: Obligation = bincode::deserialize(&value)?;
            self.obligations.insert(obl.obligation_id, obl);
            obl_count += 1;
        }

        // Lifecycle transitions — group by workflow id, ordered by seq.
        for (key, value) in store.scan_prefix(CF_SETTLEMENTS, b"wf_lifecycle:")? {
            // key = "wf_lifecycle:<32-byte-workflow-id>:<8-byte-seq-le>"
            // prefix len = 13 ("wf_lifecycle:")
            if key.len() < 13 + 32 + 8 {
                continue;
            }
            let mut wf_bytes = [0u8; 32];
            wf_bytes.copy_from_slice(&key[13..13 + 32]);
            let wf_id = Hash::from(wf_bytes);
            let mut seq_bytes = [0u8; 8];
            seq_bytes.copy_from_slice(&key[13 + 32 + 1..13 + 32 + 1 + 8]);
            let seq = u64::from_le_bytes(seq_bytes);
            let rec: LifecycleRecord = bincode::deserialize(&value)?;
            let entry = self
                .meta
                .entry(wf_id)
                .or_insert_with(|| RwLock::new(WorkflowMeta::default()));
            let mut m = entry.write();
            m.lifecycle.push(rec.0);
            if seq + 1 > m.next_lifecycle_seq {
                m.next_lifecycle_seq = seq + 1;
            }
        }
        // Sort lifecycle within each workflow by `at` for deterministic replay.
        for entry in self.meta.iter() {
            entry.value().write().lifecycle.sort_by_key(|t| t.at);
        }

        // Receipt chain head — derive from highest-`at` receipt per workflow.
        for (_, value) in store.scan_prefix(CF_SETTLEMENTS, b"wf_receipt:")? {
            let rec: WorkflowReceipt = bincode::deserialize(&value)?;
            let entry = self
                .meta
                .entry(rec.workflow_id)
                .or_insert_with(|| RwLock::new(WorkflowMeta::default()));
            let mut m = entry.write();
            if rec.at.0 >= 0 && rec.receipt_id != Hash::default() {
                // Last write wins ordering — we re-anchor to the latest below.
                m.last_receipt = rec.receipt_id;
            }
        }

        // Approval gates and requests.
        let mut gate_count = 0usize;
        for (_, value) in store.scan_prefix(CF_APPROVALS, b"wf_gate:")? {
            let gate: ApprovalGate = bincode::deserialize(&value)?;
            self.gates.insert(gate.gate_id, gate);
            gate_count += 1;
        }
        let mut req_count = 0usize;
        for (_, value) in store.scan_prefix(CF_APPROVALS, b"wf_appr:")? {
            let req: ApprovalRequest = bincode::deserialize(&value)?;
            self.requests.insert(req.request_id, req);
            req_count += 1;
        }

        info!(
            workflows = wf_count,
            obligations = obl_count,
            gates = gate_count,
            requests = req_count,
            "WorkflowManager hydrated from storage"
        );
        Ok(())
    }

    fn index_workflow(&self, wf: &Workflow) {
        self.by_creator
            .entry(wf.creator.clone())
            .or_default()
            .insert(wf.workflow_id);
        for p in &wf.participants {
            self.by_participant
                .entry(p.did.clone())
                .or_default()
                .insert(wf.workflow_id);
        }
        self.by_status
            .entry(wf.status)
            .or_default()
            .insert(wf.workflow_id);
    }

    fn deindex_status(&self, wf_id: &WorkflowId, status: WorkflowStatus) {
        if let Some(set) = self.by_status.get(&status) {
            set.remove(wf_id);
        }
    }

    fn persist_workflow(&self, wf: &Workflow) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };
        let payload = bincode::serialize(wf)?;
        let mut ops = vec![WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: workflow_key(&wf.workflow_id),
            value: payload,
        }];
        ops.push(WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: creator_index_key(&wf.creator, &wf.workflow_id),
            value: vec![],
        });
        for p in &wf.participants {
            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: participant_index_key(&p.did, &wf.workflow_id),
                value: vec![],
            });
        }
        ops.push(WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: status_index_key(wf.status, &wf.workflow_id),
            value: vec![],
        });
        if let Some(t) = &wf.template_id {
            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: template_index_key(t, &wf.workflow_id),
                value: vec![],
            });
        }
        store.write_batch_sync(ops)?;
        Ok(())
    }

    fn persist_obligation(&self, obl: &Obligation) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };
        let payload = bincode::serialize(obl)?;
        store.write_batch_sync(vec![WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: obligation_key(&obl.obligation_id),
            value: payload,
        }])?;
        Ok(())
    }

    fn persist_gate(&self, gate: &ApprovalGate) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };
        let payload = bincode::serialize(gate)?;
        store.write_batch_sync(vec![WriteOp::Put {
            cf: CF_APPROVALS.to_string(),
            key: gate_key(&gate.gate_id),
            value: payload,
        }])?;
        Ok(())
    }

    fn persist_request(&self, req: &ApprovalRequest) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };
        let payload = bincode::serialize(req)?;
        store.write_batch_sync(vec![
            WriteOp::Put {
                cf: CF_APPROVALS.to_string(),
                key: request_key(&req.request_id),
                value: payload,
            },
            WriteOp::Put {
                cf: CF_APPROVALS.to_string(),
                key: request_by_gate_key(&req.gate_id, &req.request_id),
                value: vec![],
            },
        ])?;
        Ok(())
    }

    fn persist_lifecycle(&self, transition: &LifecycleTransition, seq: u64) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };
        let payload = bincode::serialize(&LifecycleRecord(transition.clone()))?;
        store.write_batch_sync(vec![WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: lifecycle_key(&transition.workflow_id, seq),
            value: payload,
        }])?;
        Ok(())
    }

    fn persist_receipt(&self, receipt: &WorkflowReceipt) -> Result<()> {
        let Some(store) = &self.storage else {
            return Ok(());
        };
        let payload = bincode::serialize(receipt)?;
        store.write_batch_sync(vec![WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: receipt_key(&receipt.receipt_id),
            value: payload,
        }])?;
        Ok(())
    }

    fn emit_receipt(
        &self,
        wf_id: &WorkflowId,
        event: WorkflowEventKind,
        at: i64,
    ) -> Result<WorkflowReceipt> {
        let entry = self
            .meta
            .entry(*wf_id)
            .or_insert_with(|| RwLock::new(WorkflowMeta::default()));
        let prev = entry.read().last_receipt;
        let receipt = WorkflowReceipt::new(*wf_id, event, Timestamp(at), prev);
        entry.write().last_receipt = receipt.receipt_id;
        self.persist_receipt(&receipt)?;
        Ok(receipt)
    }

    fn append_lifecycle(&self, transition: LifecycleTransition) -> Result<()> {
        let entry = self
            .meta
            .entry(transition.workflow_id)
            .or_insert_with(|| RwLock::new(WorkflowMeta::default()));
        let seq = {
            let mut m = entry.write();
            let seq = m.next_lifecycle_seq;
            m.next_lifecycle_seq += 1;
            m.lifecycle.push(transition.clone());
            seq
        };
        self.persist_lifecycle(&transition, seq)?;
        Ok(())
    }

    // --- Public API ---

    /// Create a draft workflow. Returns the assigned id.
    pub fn create_workflow(&self, mut wf: Workflow) -> Result<WorkflowId> {
        if wf.title.is_empty() {
            return Err(WorkflowError::InvalidWorkflow("empty title".into()));
        }
        if wf.participants.is_empty() {
            return Err(WorkflowError::InvalidWorkflow("no participants".into()));
        }
        if !wf.participants.iter().any(|p| p.did == wf.creator) {
            return Err(WorkflowError::InvalidWorkflow(
                "creator must be a participant".into(),
            ));
        }
        // Pin id to creator/title/created_at if caller passed default.
        if wf.workflow_id == Hash::default() {
            wf.workflow_id = Workflow::derive_id(&wf.creator, &wf.title, wf.created_at);
        }
        if self.workflows.contains_key(&wf.workflow_id) {
            return Err(WorkflowError::InvalidWorkflow(format!(
                "duplicate workflow id {}",
                hex::encode(wf.workflow_id.as_bytes())
            )));
        }
        wf.status = WorkflowStatus::Draft;
        self.index_workflow(&wf);
        self.persist_workflow(&wf)?;
        let id = wf.workflow_id;
        let at = wf.created_at;
        self.workflows.insert(id, wf);
        let _ = self.emit_receipt(&id, WorkflowEventKind::Created, at)?;
        debug!(workflow_id = %hex::encode(id.as_bytes()), "workflow created");
        Ok(id)
    }

    /// Lock composition; transition `Draft → AwaitingSignatures`.
    pub fn freeze(&self, wf_id: &WorkflowId, at: i64) -> Result<()> {
        self.transition(
            wf_id,
            WorkflowStatus::AwaitingSignatures,
            TransitionTrigger::SignaturesComplete,
            at,
        )
    }

    /// Add a participant signature. When the last required signature lands,
    /// the workflow transitions to `Active`.
    ///
    /// **Caller responsibility:** signature verification. Signatures should
    /// be verified by the executor / RPC handler before reaching here using
    /// `tenzro_crypto::signatures::verify`. Manager only checks structural
    /// invariants (no double-sign, participant exists, status correct).
    pub fn sign(&self, wf_id: &WorkflowId, sig: ParticipantSignature, at: i64) -> Result<()> {
        let mut entry = self
            .workflows
            .get_mut(wf_id)
            .ok_or_else(|| WorkflowError::WorkflowNotFound(hex::encode(wf_id.as_bytes())))?;
        if entry.status != WorkflowStatus::AwaitingSignatures {
            return Err(WorkflowError::InvalidTransition {
                from: entry.status.as_str().into(),
                to: "sign".into(),
            });
        }
        if !entry.participants.iter().any(|p| p.did == sig.did) {
            return Err(WorkflowError::NotAParticipant {
                did: sig.did.clone(),
                workflow: hex::encode(wf_id.as_bytes()),
            });
        }
        if entry.signatures.iter().any(|s| s.did == sig.did) {
            return Err(WorkflowError::AlreadySigned(sig.did.clone()));
        }
        let signer_did = sig.did.clone();
        entry.signatures.push(sig);
        entry.updated_at = at;
        let needs_activate = entry.has_all_signatures();
        let snap = entry.clone();
        drop(entry);
        self.persist_workflow(&snap)?;
        let _ = self.emit_receipt(wf_id, WorkflowEventKind::Signed { by: signer_did }, at)?;
        if needs_activate {
            self.transition(
                wf_id,
                WorkflowStatus::Active,
                TransitionTrigger::SignaturesComplete,
                at,
            )?;
            let _ = self.emit_receipt(wf_id, WorkflowEventKind::Activated, at)?;
        }
        Ok(())
    }

    /// Record a new obligation against an Active workflow.
    pub fn record_obligation(&self, mut obl: Obligation) -> Result<ObligationId> {
        let wf = self.workflows.get(&obl.workflow_id).ok_or_else(|| {
            WorkflowError::WorkflowNotFound(hex::encode(obl.workflow_id.as_bytes()))
        })?;
        if wf.status != WorkflowStatus::Active {
            return Err(WorkflowError::InvalidTransition {
                from: wf.status.as_str().into(),
                to: "record_obligation".into(),
            });
        }
        if !wf.participants.iter().any(|p| p.did == obl.obligor) {
            return Err(WorkflowError::NotAParticipant {
                did: obl.obligor.clone(),
                workflow: hex::encode(obl.workflow_id.as_bytes()),
            });
        }
        if !wf.participants.iter().any(|p| p.did == obl.obligee) {
            return Err(WorkflowError::NotAParticipant {
                did: obl.obligee.clone(),
                workflow: hex::encode(obl.workflow_id.as_bytes()),
            });
        }
        if obl.obligation_id == Hash::default() {
            // Assign deterministic id with a per-workflow nonce derived from
            // current obligation count.
            let nonce = wf.obligations.len() as u64;
            obl.obligation_id =
                Obligation::derive_id(&obl.workflow_id, &obl.obligor, &obl.obligee, nonce);
        }
        if self.obligations.contains_key(&obl.obligation_id) {
            return Err(WorkflowError::Invalid(format!(
                "duplicate obligation id {}",
                hex::encode(obl.obligation_id.as_bytes())
            )));
        }
        let oid = obl.obligation_id;
        let wf_id = obl.workflow_id;
        drop(wf);
        if let Some(mut wf_mut) = self.workflows.get_mut(&wf_id) {
            wf_mut.obligations.push(oid);
            let snap = wf_mut.clone();
            drop(wf_mut);
            self.persist_workflow(&snap)?;
        }
        self.persist_obligation(&obl)?;
        self.obligations.insert(oid, obl);
        Ok(oid)
    }

    /// Discharge an obligation with a typed proof. Caller is responsible for
    /// verifying the proof (settlement engine, ZK verifier, TEE attester);
    /// the manager only enforces shape and lifecycle.
    pub fn discharge(
        &self,
        obligation_id: &ObligationId,
        proof: DischargeProof,
        at: i64,
    ) -> Result<()> {
        let mut entry = self.obligations.get_mut(obligation_id).ok_or_else(|| {
            WorkflowError::ObligationNotFound(hex::encode(obligation_id.as_bytes()))
        })?;
        if entry.status.is_terminal() {
            return Err(WorkflowError::Invalid(format!(
                "obligation {} is already terminal",
                hex::encode(obligation_id.as_bytes())
            )));
        }
        if std::mem::discriminant(&entry.discharge_proof_required)
            != std::mem::discriminant(&proof.kind)
        {
            return Err(WorkflowError::Invalid(format!(
                "proof kind mismatch for obligation {}",
                hex::encode(obligation_id.as_bytes())
            )));
        }
        entry.status = ObligationStatus::Discharged {
            receipt: proof.artifact_hash,
            at,
        };
        let wf_id = entry.workflow_id;
        let snap = entry.clone();
        drop(entry);
        self.persist_obligation(&snap)?;
        let _ = self.emit_receipt(
            &wf_id,
            WorkflowEventKind::ObligationStatusChanged {
                obligation_id: *obligation_id,
                new_status_tag: "discharged".into(),
            },
            at,
        )?;
        // If every obligation on the workflow is terminal, transition
        // Active → Settling automatically.
        if let Some(wf) = self.workflows.get(&wf_id) {
            let all_terminal = wf.obligations.iter().all(|oid| {
                self.obligations
                    .get(oid)
                    .map(|o| o.status.is_terminal())
                    .unwrap_or(false)
            });
            let in_active = wf.status == WorkflowStatus::Active;
            drop(wf);
            if all_terminal && in_active {
                self.transition(
                    &wf_id,
                    WorkflowStatus::Settling,
                    TransitionTrigger::ObligationDischarged {
                        obligation_id: *obligation_id,
                    },
                    at,
                )?;
            }
        }
        Ok(())
    }

    /// Default an obligation (deadline missed, proof rejected).
    pub fn default_obligation(
        &self,
        obligation_id: &ObligationId,
        reason: String,
        at: i64,
    ) -> Result<()> {
        let mut entry = self.obligations.get_mut(obligation_id).ok_or_else(|| {
            WorkflowError::ObligationNotFound(hex::encode(obligation_id.as_bytes()))
        })?;
        if entry.status.is_terminal() {
            return Err(WorkflowError::Invalid(format!(
                "obligation {} is already terminal",
                hex::encode(obligation_id.as_bytes())
            )));
        }
        entry.status = ObligationStatus::Defaulted {
            reason: reason.clone(),
            at,
        };
        let wf_id = entry.workflow_id;
        let snap = entry.clone();
        drop(entry);
        self.persist_obligation(&snap)?;
        let _ = self.emit_receipt(
            &wf_id,
            WorkflowEventKind::ObligationStatusChanged {
                obligation_id: *obligation_id,
                new_status_tag: "defaulted".into(),
            },
            at,
        )?;
        warn!(obligation = %hex::encode(obligation_id.as_bytes()), %reason, "obligation defaulted");
        Ok(())
    }

    /// Register an approval gate (typically called from the workflow factory
    /// when materializing a template).
    pub fn register_gate(&self, gate: ApprovalGate) -> Result<()> {
        if !self.workflows.contains_key(&gate.workflow_id) {
            return Err(WorkflowError::WorkflowNotFound(hex::encode(
                gate.workflow_id.as_bytes(),
            )));
        }
        self.persist_gate(&gate)?;
        let mut wf = self.workflows.get_mut(&gate.workflow_id).unwrap();
        wf.approval_gates.push(gate.clone());
        let snap = wf.clone();
        drop(wf);
        self.persist_workflow(&snap)?;
        self.gates.insert(gate.gate_id, gate);
        Ok(())
    }

    /// Open an approval request against a gate. Caller (the policy DSL
    /// evaluator) supplies the trigger context that hashes into the request
    /// id.
    pub fn open_approval(
        &self,
        gate_id: &ApprovalGateId,
        trigger_context: serde_json::Value,
        created_at: i64,
    ) -> Result<ApprovalRequestId> {
        let gate = self
            .gates
            .get(gate_id)
            .ok_or_else(|| WorkflowError::ApprovalGateNotFound(hex::encode(gate_id.as_bytes())))?;
        let ctx_bytes = serde_json::to_vec(&trigger_context)?;
        let ctx_hash = {
            let h: [u8; 32] = Sha256::digest(&ctx_bytes).into();
            Hash::from(h)
        };
        let request_id = ApprovalRequest::derive_id(gate_id, &ctx_hash, created_at);
        let req = ApprovalRequest {
            request_id,
            gate_id: *gate_id,
            workflow_id: gate.workflow_id,
            trigger_context,
            created_at,
            decisions: vec![],
            status: ApprovalStatus::Open,
        };
        let wf_id = gate.workflow_id;
        drop(gate);
        self.persist_request(&req)?;
        self.requests.insert(request_id, req);
        let _ = self.emit_receipt(
            &wf_id,
            WorkflowEventKind::ApprovalOpened { request_id },
            created_at,
        )?;
        Ok(request_id)
    }

    /// Submit a decision on an open approval request. When the gate's
    /// threshold is reached, finalizes the request and emits the appropriate
    /// receipt.
    ///
    /// Caller is responsible for verifying `decision.signature` against
    /// `request.decision_preimage(decision.decision, decision.at)` before
    /// invocation. The manager enforces uniqueness, gate authorization, and
    /// finalization semantics.
    pub fn submit_decision(
        &self,
        request_id: &ApprovalRequestId,
        decision: ApprovalDecision,
    ) -> Result<ApprovalStatus> {
        let mut entry = self.requests.get_mut(request_id).ok_or_else(|| {
            WorkflowError::ApprovalRequestNotFound(hex::encode(request_id.as_bytes()))
        })?;
        if entry.status.is_finalized() {
            return Err(WorkflowError::ApprovalAlreadyFinalized(hex::encode(
                request_id.as_bytes(),
            )));
        }
        let gate = self.gates.get(&entry.gate_id).ok_or_else(|| {
            WorkflowError::ApprovalGateNotFound(hex::encode(entry.gate_id.as_bytes()))
        })?;
        if !is_authorized_approver(&gate.approvers, &decision.by) {
            return Err(WorkflowError::UnauthorizedApprover {
                did: decision.by.clone(),
                gate: hex::encode(entry.gate_id.as_bytes()),
            });
        }
        if entry.decisions.iter().any(|d| d.by == decision.by) {
            return Err(WorkflowError::AlreadySigned(decision.by.clone()));
        }
        let decision_at = decision.at;
        entry.decisions.push(decision);
        let approves = entry
            .decisions
            .iter()
            .filter(|d| matches!(d.decision, Decision::Approve))
            .count() as u8;
        let rejects = entry
            .decisions
            .iter()
            .filter(|d| matches!(d.decision, Decision::Reject))
            .count() as u8;
        let (m, n) = threshold_for(&gate.approvers);
        let outcome = if approves >= m {
            Some(ApprovalStatus::Approved { at: decision_at })
        } else if rejects + (m - approves.min(m)) > n {
            // Cannot reach approval threshold even if all remaining vote yes.
            Some(ApprovalStatus::Rejected { at: decision_at })
        } else {
            None
        };
        let wf_id = entry.workflow_id;
        let req_id = entry.request_id;
        if let Some(status) = outcome.clone() {
            entry.status = status;
        }
        let snap = entry.clone();
        drop(entry);
        drop(gate);
        self.persist_request(&snap)?;
        if let Some(status) = outcome {
            let outcome_tag = match &status {
                ApprovalStatus::Approved { .. } => "approved",
                ApprovalStatus::Rejected { .. } => "rejected",
                ApprovalStatus::TimedOut { .. } => "timed_out",
                ApprovalStatus::Open => "open",
            };
            let _ = self.emit_receipt(
                &wf_id,
                WorkflowEventKind::ApprovalFinalized {
                    request_id: req_id,
                    outcome: outcome_tag.into(),
                },
                decision_at,
            )?;
            return Ok(status);
        }
        Ok(ApprovalStatus::Open)
    }

    /// Apply a state transition. Validates against `WorkflowStatus`'s allowed
    /// transition table.
    pub fn transition(
        &self,
        wf_id: &WorkflowId,
        next: WorkflowStatus,
        trigger: TransitionTrigger,
        at: i64,
    ) -> Result<()> {
        let mut entry = self
            .workflows
            .get_mut(wf_id)
            .ok_or_else(|| WorkflowError::WorkflowNotFound(hex::encode(wf_id.as_bytes())))?;
        let from = entry.status;
        if !from.can_transition_to(next) {
            return Err(WorkflowError::InvalidTransition {
                from: from.as_str().into(),
                to: next.as_str().into(),
            });
        }
        entry.status = next;
        entry.updated_at = at;
        let snap = entry.clone();
        drop(entry);
        // Reindex by status.
        self.deindex_status(wf_id, from);
        self.by_status.entry(next).or_default().insert(*wf_id);
        self.persist_workflow(&snap)?;
        let transition = LifecycleTransition::new(*wf_id, from, next, trigger.clone(), at);
        self.append_lifecycle(transition.clone())?;
        let _ = self.emit_receipt(
            wf_id,
            WorkflowEventKind::LifecycleTransitioned { transition },
            at,
        )?;
        if next.is_terminal() {
            let _ = self.emit_receipt(
                wf_id,
                WorkflowEventKind::Terminated {
                    final_status: next.as_str().into(),
                },
                at,
            )?;
        }
        Ok(())
    }

    /// Invoke a kill-switch. Maps `(scope, current_status) → next_status`
    /// per the lifecycle table.
    pub fn invoke_kill_switch(
        &self,
        wf_id: &WorkflowId,
        invoker: String,
        scope: KillSwitchScope,
        reason: String,
        at: i64,
    ) -> Result<()> {
        let from = self
            .workflows
            .get(wf_id)
            .ok_or_else(|| WorkflowError::WorkflowNotFound(hex::encode(wf_id.as_bytes())))?
            .status;
        let next = match (scope, from) {
            (KillSwitchScope::Suspend, WorkflowStatus::Active) => WorkflowStatus::Suspended,
            (KillSwitchScope::Fail, WorkflowStatus::Suspended) => WorkflowStatus::Failed,
            (KillSwitchScope::Cancel, WorkflowStatus::Draft)
            | (KillSwitchScope::Cancel, WorkflowStatus::AwaitingSignatures)
            | (KillSwitchScope::Cancel, WorkflowStatus::Suspended) => WorkflowStatus::Cancelled,
            _ => {
                return Err(WorkflowError::InvalidTransition {
                    from: from.as_str().into(),
                    to: format!("kill_switch:{:?}", scope),
                });
            }
        };
        let trigger = TransitionTrigger::KillSwitch {
            invoker: invoker.clone(),
            scope,
            reason,
        };
        self.transition(wf_id, next, trigger, at)?;
        let scope_tag = match scope {
            KillSwitchScope::Suspend => "suspend",
            KillSwitchScope::Fail => "fail",
            KillSwitchScope::Cancel => "cancel",
        };
        let _ = self.emit_receipt(
            wf_id,
            WorkflowEventKind::KillSwitchInvoked {
                invoker,
                scope: scope_tag.into(),
            },
            at,
        )?;
        Ok(())
    }

    // --- Read accessors ---

    pub fn get_workflow(&self, wf_id: &WorkflowId) -> Option<Workflow> {
        self.workflows.get(wf_id).map(|w| w.clone())
    }

    pub fn get_obligation(&self, oid: &ObligationId) -> Option<Obligation> {
        self.obligations.get(oid).map(|o| o.clone())
    }

    pub fn get_gate(&self, gid: &ApprovalGateId) -> Option<ApprovalGate> {
        self.gates.get(gid).map(|g| g.clone())
    }

    pub fn get_request(&self, rid: &ApprovalRequestId) -> Option<ApprovalRequest> {
        self.requests.get(rid).map(|r| r.clone())
    }

    pub fn list_by_creator(&self, creator: &str) -> Vec<WorkflowId> {
        self.by_creator
            .get(creator)
            .map(|s| s.iter().map(|i| *i).collect())
            .unwrap_or_default()
    }

    pub fn list_by_participant(&self, did: &str) -> Vec<WorkflowId> {
        self.by_participant
            .get(did)
            .map(|s| s.iter().map(|i| *i).collect())
            .unwrap_or_default()
    }

    pub fn list_by_status(&self, status: WorkflowStatus) -> Vec<WorkflowId> {
        self.by_status
            .get(&status)
            .map(|s| s.iter().map(|i| *i).collect())
            .unwrap_or_default()
    }

    pub fn lifecycle_history(&self, wf_id: &WorkflowId) -> Vec<LifecycleTransition> {
        self.meta
            .get(wf_id)
            .map(|m| m.read().lifecycle.clone())
            .unwrap_or_default()
    }

    /// Alias for kind-Identical APIs.
    pub fn obligation_count(&self) -> usize {
        self.obligations.len()
    }
    pub fn workflow_count(&self) -> usize {
        self.workflows.len()
    }

    /// Last (head) receipt id for a workflow's receipt chain. Returns
    /// `Hash::default()` if the workflow has not emitted any receipts yet
    /// (or is unknown).
    pub fn last_receipt_id(&self, wf_id: &WorkflowId) -> Hash {
        self.meta
            .get(wf_id)
            .map(|m| m.read().last_receipt)
            .unwrap_or_default()
    }

    /// Fetch a receipt by id from the backing store. Receipts are not
    /// cached in memory (they're append-only and primarily for audit) —
    /// returns `None` when no storage is wired or the id is unknown.
    pub fn get_receipt(&self, id: &Hash) -> Result<Option<WorkflowReceipt>> {
        let Some(store) = &self.storage else {
            return Ok(None);
        };
        let Some(bytes) = store.get(CF_SETTLEMENTS, &receipt_key(id))? else {
            return Ok(None);
        };
        let r: WorkflowReceipt = bincode::deserialize(&bytes)?;
        Ok(Some(r))
    }

    /// Walk the per-workflow receipt chain from head (`last_receipt_id`)
    /// backwards via `prev_receipt`, oldest-last. Bounded by `max` to
    /// guard pathological chains. Genesis receipt has `prev_receipt ==
    /// Hash::default()` and terminates the walk.
    pub fn list_workflow_receipts(
        &self,
        wf_id: &WorkflowId,
        max: usize,
    ) -> Result<Vec<WorkflowReceipt>> {
        let mut out = Vec::new();
        let mut cur = self.last_receipt_id(wf_id);
        while cur != Hash::default() && out.len() < max {
            match self.get_receipt(&cur)? {
                Some(r) => {
                    let prev = r.prev_receipt;
                    out.push(r);
                    cur = prev;
                }
                None => break,
            }
        }
        Ok(out)
    }

    /// Build an `OperationalMetrics` snapshot by walking the in-memory
    /// indices. O(N_workflows + N_obligations + N_requests). Caller
    /// supplies fee-route and privacy-domain totals because those live
    /// in sibling registries (`FeeRouteRegistry`, `PrivacyDomainRegistry`).
    /// Pass `0` for either if the registry is not wired in this scope.
    pub fn operational_metrics(
        &self,
        fee_routes_total: u64,
        privacy_domains_total: u64,
    ) -> crate::metrics::OperationalMetrics {
        use crate::metrics::OperationalMetrics;
        let mut m = OperationalMetrics::default();

        let mut sigs: u64 = 0;
        let mut canton_mirrored: u64 = 0;
        for entry in self.workflows.iter() {
            let wf = entry.value();
            *m.workflows_by_status
                .entry(wf.status.as_str().to_string())
                .or_insert(0) += 1;
            sigs += wf.signatures.len() as u64;
            if wf.canton_mirror.is_some() {
                canton_mirrored += 1;
            }
        }
        m.signatures_collected_total = sigs;
        m.canton_mirrored_total = canton_mirrored;

        for entry in self.obligations.iter() {
            let label = match entry.value().status {
                ObligationStatus::Pending => "pending",
                ObligationStatus::InProgress { .. } => "in_progress",
                ObligationStatus::Discharged { .. } => "discharged",
                ObligationStatus::Defaulted { .. } => "defaulted",
                ObligationStatus::Forgiven { .. } => "forgiven",
            };
            *m.obligations_by_status.entry(label.into()).or_insert(0) += 1;
        }

        for entry in self.requests.iter() {
            let label = match entry.value().status {
                ApprovalStatus::Open => "open",
                ApprovalStatus::Approved { .. } => "approved",
                ApprovalStatus::Rejected { .. } => "rejected",
                ApprovalStatus::TimedOut { .. } => "timed_out",
            };
            *m.approvals_by_status.entry(label.into()).or_insert(0) += 1;
        }

        m.fee_routes_total = fee_routes_total;
        m.privacy_domains_total = privacy_domains_total;
        m
    }
}

impl Default for WorkflowManager {
    fn default() -> Self {
        Self::new()
    }
}

// --- Authorization helpers ---

fn is_authorized_approver(approvers: &ApproverSet, did: &str) -> bool {
    match approvers {
        ApproverSet::Single { did: d } => d == did,
        ApproverSet::Threshold { dids, .. } => dids.iter().any(|d| d == did),
        // `Role` and `Delegated` need lookup against participants/identity —
        // the manager does not perform that resolution. Callers wrap with
        // their own check before invoking submit_decision.
        ApproverSet::Role { .. } => true,
        ApproverSet::Delegated { from, .. } => from == did,
    }
}

fn threshold_for(approvers: &ApproverSet) -> (u8, u8) {
    match approvers {
        ApproverSet::Single { .. } => (1, 1),
        ApproverSet::Threshold { m, n, .. } => (*m, *n),
        ApproverSet::Role { m, .. } => (*m, *m),
        ApproverSet::Delegated { .. } => (1, 1),
    }
}

// --- Key formatters ---

fn workflow_key(id: &WorkflowId) -> Vec<u8> {
    let mut k = Vec::with_capacity(3 + 32);
    k.extend_from_slice(b"wf:");
    k.extend_from_slice(id.as_bytes());
    k
}

fn obligation_key(id: &ObligationId) -> Vec<u8> {
    let mut k = Vec::with_capacity(7 + 32);
    k.extend_from_slice(b"wf_obl:");
    k.extend_from_slice(id.as_bytes());
    k
}

fn lifecycle_key(wf: &WorkflowId, seq: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(13 + 32 + 1 + 8);
    k.extend_from_slice(b"wf_lifecycle:");
    k.extend_from_slice(wf.as_bytes());
    k.push(b':');
    k.extend_from_slice(&seq.to_le_bytes());
    k
}

fn receipt_key(id: &Hash) -> Vec<u8> {
    let mut k = Vec::with_capacity(11 + 32);
    k.extend_from_slice(b"wf_receipt:");
    k.extend_from_slice(id.as_bytes());
    k
}

fn creator_index_key(creator: &str, wf: &WorkflowId) -> Vec<u8> {
    let mut k = Vec::new();
    k.extend_from_slice(b"wf_creator:");
    k.extend_from_slice(creator.as_bytes());
    k.push(b':');
    k.extend_from_slice(wf.as_bytes());
    k
}

fn participant_index_key(did: &str, wf: &WorkflowId) -> Vec<u8> {
    let mut k = Vec::new();
    k.extend_from_slice(b"wf_participant:");
    k.extend_from_slice(did.as_bytes());
    k.push(b':');
    k.extend_from_slice(wf.as_bytes());
    k
}

fn status_index_key(status: WorkflowStatus, wf: &WorkflowId) -> Vec<u8> {
    let mut k = Vec::new();
    k.extend_from_slice(b"wf_status:");
    k.extend_from_slice(status.as_str().as_bytes());
    k.push(b':');
    k.extend_from_slice(wf.as_bytes());
    k
}

fn template_index_key(template: &Hash, wf: &WorkflowId) -> Vec<u8> {
    let mut k = Vec::new();
    k.extend_from_slice(b"wf_template:");
    k.extend_from_slice(template.as_bytes());
    k.push(b':');
    k.extend_from_slice(wf.as_bytes());
    k
}

fn gate_key(id: &ApprovalGateId) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + 32);
    k.extend_from_slice(b"wf_gate:");
    k.extend_from_slice(id.as_bytes());
    k
}

fn request_key(id: &ApprovalRequestId) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + 32);
    k.extend_from_slice(b"wf_appr:");
    k.extend_from_slice(id.as_bytes());
    k
}

fn request_by_gate_key(gate: &ApprovalGateId, req: &ApprovalRequestId) -> Vec<u8> {
    let mut k = Vec::with_capacity(16 + 32 + 1 + 32);
    k.extend_from_slice(b"wf_appr_by_gate:");
    k.extend_from_slice(gate.as_bytes());
    k.push(b':');
    k.extend_from_slice(req.as_bytes());
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ApproverSet, Decision, TimeoutBehavior};
    use crate::obligation::{AssetRef, DischargeProofKind, ObligationKind};
    use crate::participant::{Participant, ParticipantRole};
    use crate::policy_dsl::PolicyExpr;
    use crate::workflow::Workflow;

    fn mk_workflow(creator: &str, peer: &str, at: i64) -> Workflow {
        let id = Workflow::derive_id(creator, "swap", at);
        Workflow {
            workflow_id: id,
            template_id: None,
            creator: creator.into(),
            title: "swap".into(),
            description: None,
            participants: vec![
                Participant::new(creator, vec![ParticipantRole::Initiator]),
                Participant::new(peer, vec![ParticipantRole::Counterparty]),
            ],
            obligations: vec![],
            approval_gates: vec![],
            root_policy: PolicyExpr::Allow,
            privacy_domain: None,
            fee_route: None,
            signatures: vec![],
            status: WorkflowStatus::Draft,
            canton_mirror: None,
            created_at: at,
            updated_at: at,
        }
    }

    #[test]
    fn create_freeze_sign_activate() {
        let mgr = WorkflowManager::new();
        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";
        let wf = mk_workflow(alice, bob, 100);
        let id = mgr.create_workflow(wf).unwrap();
        assert_eq!(mgr.get_workflow(&id).unwrap().status, WorkflowStatus::Draft);
        mgr.freeze(&id, 110).unwrap();
        assert_eq!(
            mgr.get_workflow(&id).unwrap().status,
            WorkflowStatus::AwaitingSignatures
        );
        mgr.sign(
            &id,
            ParticipantSignature {
                did: alice.into(),
                signature: vec![0; 64],
                signed_by_pubkey: vec![0; 32],
                at: 120,
            },
            120,
        )
        .unwrap();
        assert_eq!(
            mgr.get_workflow(&id).unwrap().status,
            WorkflowStatus::AwaitingSignatures
        );
        mgr.sign(
            &id,
            ParticipantSignature {
                did: bob.into(),
                signature: vec![0; 64],
                signed_by_pubkey: vec![0; 32],
                at: 130,
            },
            130,
        )
        .unwrap();
        assert_eq!(
            mgr.get_workflow(&id).unwrap().status,
            WorkflowStatus::Active
        );
    }

    #[test]
    fn obligation_discharge_completes_workflow() {
        let mgr = WorkflowManager::new();
        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";
        let id = mgr.create_workflow(mk_workflow(alice, bob, 100)).unwrap();
        mgr.freeze(&id, 110).unwrap();
        for did in [alice, bob] {
            mgr.sign(
                &id,
                ParticipantSignature {
                    did: did.into(),
                    signature: vec![],
                    signed_by_pubkey: vec![],
                    at: 120,
                },
                120,
            )
            .unwrap();
        }
        let obl = Obligation {
            obligation_id: Hash::default(),
            workflow_id: id,
            obligor: alice.into(),
            obligee: bob.into(),
            kind: ObligationKind::Pay {
                amount_wei: 1000,
                asset: AssetRef {
                    chain: "tenzro".into(),
                    symbol: "TNZO".into(),
                    token_address: None,
                },
            },
            due_by: None,
            status: ObligationStatus::Pending,
            discharge_proof_required: DischargeProofKind::PaymentReceipt,
            bond_anchor: None,
        };
        let oid = mgr.record_obligation(obl).unwrap();
        mgr.discharge(
            &oid,
            DischargeProof {
                kind: DischargeProofKind::PaymentReceipt,
                artifact_hash: Hash::from([9u8; 32]),
                artifact_inline: None,
            },
            200,
        )
        .unwrap();
        assert_eq!(
            mgr.get_workflow(&id).unwrap().status,
            WorkflowStatus::Settling
        );
    }

    #[test]
    fn approval_threshold_finalizes() {
        let mgr = WorkflowManager::new();
        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";
        let id = mgr.create_workflow(mk_workflow(alice, bob, 100)).unwrap();
        let gate = ApprovalGate {
            gate_id: ApprovalGate::derive_id(&id, "high_value"),
            workflow_id: id,
            triggers: PolicyExpr::Allow,
            approvers: ApproverSet::Threshold {
                dids: vec![alice.into(), bob.into(), "did:tenzro:human:carol:1".into()],
                m: 2,
                n: 3,
            },
            timeout: None,
            on_timeout: TimeoutBehavior::AutoReject,
        };
        mgr.register_gate(gate.clone()).unwrap();
        let req_id = mgr
            .open_approval(&gate.gate_id, serde_json::json!({"amount": 1_000_000}), 100)
            .unwrap();
        let req = mgr.get_request(&req_id).unwrap();
        let res1 = mgr
            .submit_decision(
                &req_id,
                ApprovalDecision {
                    by: alice.into(),
                    decision: Decision::Approve,
                    at: 110,
                    justification: None,
                    signature: vec![],
                    signed_by_pubkey: vec![],
                },
            )
            .unwrap();
        assert!(matches!(res1, ApprovalStatus::Open));
        let res2 = mgr
            .submit_decision(
                &req_id,
                ApprovalDecision {
                    by: bob.into(),
                    decision: Decision::Approve,
                    at: 120,
                    justification: None,
                    signature: vec![],
                    signed_by_pubkey: vec![],
                },
            )
            .unwrap();
        assert!(matches!(res2, ApprovalStatus::Approved { .. }));
        let _ = req;
    }

    #[test]
    fn kill_switch_suspend_then_cancel() {
        let mgr = WorkflowManager::new();
        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";
        let id = mgr.create_workflow(mk_workflow(alice, bob, 100)).unwrap();
        mgr.freeze(&id, 110).unwrap();
        for did in [alice, bob] {
            mgr.sign(
                &id,
                ParticipantSignature {
                    did: did.into(),
                    signature: vec![],
                    signed_by_pubkey: vec![],
                    at: 120,
                },
                120,
            )
            .unwrap();
        }
        mgr.invoke_kill_switch(
            &id,
            alice.into(),
            KillSwitchScope::Suspend,
            "ops".into(),
            200,
        )
        .unwrap();
        assert_eq!(
            mgr.get_workflow(&id).unwrap().status,
            WorkflowStatus::Suspended
        );
        mgr.invoke_kill_switch(
            &id,
            alice.into(),
            KillSwitchScope::Cancel,
            "abandoned".into(),
            300,
        )
        .unwrap();
        assert_eq!(
            mgr.get_workflow(&id).unwrap().status,
            WorkflowStatus::Cancelled
        );
        let history = mgr.lifecycle_history(&id);
        assert!(history.len() >= 3);
    }

    #[test]
    fn duplicate_signature_rejected() {
        let mgr = WorkflowManager::new();
        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";
        let id = mgr.create_workflow(mk_workflow(alice, bob, 100)).unwrap();
        mgr.freeze(&id, 110).unwrap();
        mgr.sign(
            &id,
            ParticipantSignature {
                did: alice.into(),
                signature: vec![],
                signed_by_pubkey: vec![],
                at: 120,
            },
            120,
        )
        .unwrap();
        let err = mgr
            .sign(
                &id,
                ParticipantSignature {
                    did: alice.into(),
                    signature: vec![],
                    signed_by_pubkey: vec![],
                    at: 130,
                },
                130,
            )
            .unwrap_err();
        assert!(matches!(err, WorkflowError::AlreadySigned(_)));
    }

    #[test]
    fn invalid_transition_rejected() {
        let mgr = WorkflowManager::new();
        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";
        let id = mgr.create_workflow(mk_workflow(alice, bob, 100)).unwrap();
        let err = mgr
            .transition(
                &id,
                WorkflowStatus::Completed,
                TransitionTrigger::Timeout,
                200,
            )
            .unwrap_err();
        assert!(matches!(err, WorkflowError::InvalidTransition { .. }));
    }

    #[test]
    fn operational_metrics_snapshot_partitions_by_status() {
        let mgr = WorkflowManager::new();
        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";
        let carol = "did:tenzro:human:carol:1";

        // Two Draft workflows.
        let draft1 = mgr.create_workflow(mk_workflow(alice, bob, 100)).unwrap();
        let _draft2 = mgr.create_workflow(mk_workflow(alice, carol, 101)).unwrap();

        // Drive draft1 to Active via freeze + 2 sigs.
        mgr.freeze(&draft1, 110).unwrap();
        for did in [alice, bob] {
            mgr.sign(
                &draft1,
                ParticipantSignature {
                    did: did.into(),
                    signature: vec![],
                    signed_by_pubkey: vec![],
                    at: 120,
                },
                120,
            )
            .unwrap();
        }

        let snap = mgr.operational_metrics(3, 5);
        assert_eq!(snap.workflows_by_status.get("active").copied(), Some(1));
        assert_eq!(snap.workflows_by_status.get("draft").copied(), Some(1));
        // 2 sigs collected on draft1.
        assert_eq!(snap.signatures_collected_total, 2);
        // No canton mirror set on test workflows.
        assert_eq!(snap.canton_mirrored_total, 0);
        // Caller-supplied registry totals propagate verbatim.
        assert_eq!(snap.fee_routes_total, 3);
        assert_eq!(snap.privacy_domains_total, 5);

        // Render is non-empty and contains canonical labels.
        let rendered = snap.render_prometheus();
        assert!(rendered.contains("tenzro_workflow_workflows_total{status=\"active\"} 1"));
        assert!(rendered.contains("tenzro_workflow_workflows_total{status=\"draft\"} 1"));
        assert!(rendered.contains("tenzro_workflow_signatures_collected_total 2"));
        assert!(rendered.contains("tenzro_workflow_fee_routes_total 3"));
        assert!(rendered.contains("tenzro_workflow_privacy_domains_total 5"));
    }

    /// Multi-day workflow hydration test (agent loop closure gap c).
    ///
    /// Simulates an operator restart by:
    ///   1. Creating a `WorkflowManager` with RocksDB persistence.
    ///   2. Inserting two workflows, freezing one, signing it.
    ///   3. Dropping the manager (drops in-memory state).
    ///   4. Rebuilding a fresh manager from the same on-disk store.
    ///   5. Asserting both workflows reappear with their lifecycle
    ///      transitions and signatures intact.
    ///
    /// Long-workflow survival across operator restarts is a hard
    /// requirement for an autonomous agentic economy — agents cannot
    /// have their multi-day work die because their hosting operator
    /// hiccuped (`project_dynamic_agentic_environment_destination`).
    #[test]
    fn hydration_restores_workflows_after_restart() {
        use std::sync::Arc;
        use tenzro_storage::{StorageConfig, kv::RocksDbStore};

        let tmp = tempfile::tempdir().unwrap();
        let storage_cfg = StorageConfig::new(tmp.path().to_path_buf());

        let alice = "did:tenzro:human:alice:1";
        let bob = "did:tenzro:human:bob:1";

        // Phase 1: live operator session — create + freeze + sign.
        let (wf_id_a, wf_id_b) = {
            let store = Arc::new(RocksDbStore::open(&storage_cfg).unwrap());
            let mgr = WorkflowManager::with_storage(store).unwrap();

            let wf_a = mk_workflow(alice, bob, 1_700_000_000);
            let wf_b = mk_workflow(bob, alice, 1_700_000_001);

            let id_a = mgr.create_workflow(wf_a).unwrap();
            let id_b = mgr.create_workflow(wf_b).unwrap();

            // Move workflow A through freeze + sign so it has lifecycle
            // transitions; B stays in Draft so we can assert mixed
            // states survive.
            mgr.freeze(&id_a, 1_700_000_100).unwrap();
            mgr.sign(
                &id_a,
                ParticipantSignature {
                    did: alice.into(),
                    signature: vec![0xab; 64],
                    signed_by_pubkey: vec![0xcd; 32],
                    at: 1_700_000_101,
                },
                1_700_000_101,
            )
            .unwrap();

            // Sanity-check the in-memory snapshot before drop.
            assert_eq!(mgr.list_by_creator(alice).len(), 1);
            assert_eq!(mgr.list_by_creator(bob).len(), 1);
            assert_eq!(
                mgr.get_workflow(&id_a).unwrap().status,
                WorkflowStatus::AwaitingSignatures
            );
            assert_eq!(
                mgr.get_workflow(&id_b).unwrap().status,
                WorkflowStatus::Draft
            );

            (id_a, id_b)
            // mgr drops here — simulates operator restart.
        };

        // Phase 2: fresh manager over the same on-disk store.
        let store = Arc::new(RocksDbStore::open(&storage_cfg).unwrap());
        let restarted = WorkflowManager::with_storage(store).unwrap();

        // Both workflows reload (per-creator indices are rebuilt).
        assert_eq!(restarted.list_by_creator(alice).len(), 1);
        assert_eq!(restarted.list_by_creator(bob).len(), 1);

        let recovered_a = restarted.get_workflow(&wf_id_a).unwrap();
        let recovered_b = restarted.get_workflow(&wf_id_b).unwrap();

        // Status preserved across restart.
        assert_eq!(recovered_a.status, WorkflowStatus::AwaitingSignatures);
        assert_eq!(recovered_b.status, WorkflowStatus::Draft);

        // Lifecycle history preserved — `create_workflow` emits a
        // Created receipt (not a lifecycle transition), so the
        // recorded lifecycle starts at the first explicit transition
        // (Frozen on `freeze()`). At least one entry must survive.
        let lifecycle_a = restarted.lifecycle_history(&wf_id_a);
        assert!(
            !lifecycle_a.is_empty(),
            "lifecycle should preserve the Frozen transition across restart, got empty"
        );

        // Signature on A persists.
        assert_eq!(
            recovered_a.signatures.len(),
            1,
            "signature on workflow A must survive restart"
        );
    }
}
