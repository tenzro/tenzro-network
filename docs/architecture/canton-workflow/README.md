# Canton-Native Workflow Stack — Implementation Plan

**Status:** Drafting (2026-05-09)
**Phase:** 1 (workflow primitive + privacy + policy DSL); 2 (Canton mirror + reference templates); 3 (telemetry + fee routing + A2A hooks)
**Touches:** new `tenzro-workflow` crate; extends `tenzro-identity`, `tenzro-payments`, `tenzro-bridge`, `tenzro-events`, `tenzro-token`, `tenzro-agent-kit`, `tenzro-node`, `integrations/a2a/`

## 0. Why this exists

The current Tenzro stack ships transaction-grade primitives — typed transactions, settlements, escrows, payment receipts, agent identities — but the **agentic economy on Canton runs on workflows**: multi-party obligations, approval gates, conditional execution, and party-scoped visibility. Today the gap between "Tenzro can pay an inference provider" and "Tenzro can settle a multi-party autonomous procurement workflow on Canton with selective disclosure to auditor + buyer + seller + treasurer" is a missing primitive layer, not a missing protocol.

This document is the **full implementation plan** (not stubs) for that layer. It is structured so each section has: (a) verified-2026 architectural premise, (b) concrete file paths and type signatures, (c) RocksDB CF wiring + persistence semantics, (d) RPC + MCP + A2A surface, (e) integration with the existing crates listed above. Source citations for the Canton 2026 architectural premises are inlined at the section head.

## 0.1 2026 Canton architecture facts (verified)

| Fact | Source | Implication for this plan |
|---|---|---|
| Network = "Canton Network"; shared synchronizer = "Global Synchronizer"; governance body = "Canton Foundation" | https://www.canton.network/canton-network-press-releases/the-canton-networks-global-synchronizer-and-canton-coin-go-live ; https://canton.foundation/ | Use these terms throughout. Drop "Canton Sync" / "domain" from new code. |
| Canton 3.4 GA, 3.5 in DevNet→TestNet→MainNet rollout. **`synchronizer_id` format changes in 3.5** (breaking). | https://github.com/digital-asset/canton/releases ; https://forum.canton.network/t/format-of-synchronizer-id-will-change-in-canton-3-5-potential-breaking-change/8445 | New `CantonAdapter::SynchronizerId` newtype; flag-day cutover when 3.5 hits MainNet. |
| Sub-tx privacy = Merkle-tree-of-views + per-view symmetric key (HKDF from per-tx seed) + session key wrapped under each recipient participant's long-term encryption key. mTLS transport. | https://docs.daml.com/canton/usermanual/security.html ; https://www.canton.io/publications/canton-whitepaper.pdf | Tenzro's libp2p gossipsub **cannot mirror** Canton's view-encryption. CantonAdapter stays a bridge; PrivacyDomain (§2) is a Tenzro-side construct that maps onto Canton parties but does its own envelope encryption. |
| JSON Ledger API v2 endpoints in 3.4: `/v2/commands/submit-and-wait`, `/v2/state/active-contracts`, `/v2/updates`, `/v2/parties`, `/v2/parties/external/allocate`, `/v2/dars`. **No `/v2/updates/flats` in 3.4 OpenAPI.** | https://docs.digitalasset.com/build/3.4/reference/json-api/openapi.html | CantonAdapter audited: confirmed it uses `/admin/synchronizer/{id}/fee-schedule` (Admin API) and current JSON v2 endpoints. No `/v2/updates/flats` references in our code. |
| Canton 3.5 / Splice 0.6.0: **package-id refs dropped, must use package-name.** | https://docs.dev.sync.global | DAML codegen targets package-name, not package-id. |
| CIP-56 Splice Token Standard = three interfaces (`Holding`, `TransferInstruction`, `TokenMetadata`); BitGo custody live for USDCx + cBTC (March 2026); two-step proposal/accept/reject. | https://docs.global.canton.network.sync.global/app_dev/token_standard/index.html ; https://www.businesswire.com/news/home/20260325277049/en/ | Existing `crates/tenzro-vm/src/daml/cip56.rs` matches; verify explicit `interface instance` declarations in the codegen output of §1. |
| Global Synchronizer fees: $17/MB traffic + USD-pegged percentage tier (1% on first $100, 0.001% above $1M). CC burn-to-traffic-balance. | https://www.canton.network/blog/canton-coin-rewarding-utility | `bridge::canton::fee_quote()` updated in §7. |
| **No production ERC-7683 origin/destination settler on Canton** as of 2026-05. | https://www.erc7683.org/ + Canton CIP repo search | Tenzro is first; §5 procurement template uses 7683-style intent envelope on the Tenzro side, CIP-56 `TransferInstruction` on the Canton side. |
| No canonical "Obligation" template in DAML stdlib — it's a documented pattern. **Multiple Party Agreement** (`Pending` wrapper + per-party `Sign` choice) is the canonical multi-sig primitive. Choice qualifiers: `consuming` (default), `nonconsuming`, `preconsuming`, `postconsuming`. | https://docs.daml.com/daml/patterns/multiparty-agreement.html ; https://docs.daml.com/daml/reference/choices.html | §1 `Obligation` and §1 `ApprovalGate` codegen onto `Pending`/`Sign` and `nonconsuming RequestApproval` respectively. |
| **No native autonomous-AI-agent Canton workflow in production** (2026 search). The dominant production reference for tokenized US Treasuries + atomic DvP on Canton is a market-utility consortium settlement program announced by the participating institutions. | (vendor press releases of the participating market utility) | Greenfield. §5 reference templates target DvP, autonomous treasury, autonomous procurement — direct demos in the same problem space. |

---

## 1. `tenzro-workflow` crate — the workflow primitive

**Premise:** Today, Tenzro models *transactions* and *agents*. The agentic economy on Canton models *workflows* — long-lived multi-party obligations with lifecycle transitions and approval chains. We need a typed primitive that (a) compiles to a DAML template at the boundary, (b) is enforced by Tenzro's privileged VM as typed transactions on the Tenzro side, (c) emits typed lifecycle receipts, (d) plugs into TDIP delegation + AP2 mandates + AgentBond + insurance.

### 1.1 New crate layout

```
crates/tenzro-workflow/
├── Cargo.toml
├── src/
│   ├── lib.rs                    // public exports + WorkflowError
│   ├── error.rs                  // WorkflowError enum (thiserror)
│   ├── workflow.rs               // Workflow, WorkflowId, WorkflowStatus
│   ├── obligation.rs             // Obligation, ObligationId, ObligationStatus
│   ├── approval.rs               // ApprovalGate, ApprovalRequest, ApprovalDecision
│   ├── participant.rs            // Participant, ParticipantRole
│   ├── lifecycle.rs              // LifecycleTransition, TransitionId, transition rules engine
│   ├── receipt.rs                // WorkflowReceipt, ReceiptKind (extends DA-receipt envelope)
│   ├── manager.rs                // WorkflowManager (DashMap + KvStore write-through)
│   ├── codegen/
│   │   ├── mod.rs
│   │   ├── daml.rs               // Workflow → .daml source emitter (CIP-56 + Pending pattern)
│   │   ├── tenzro_tx.rs          // Workflow → typed Tenzro VM tx selectors
│   │   └── ts_types.rs           // Workflow → TypeScript types for SDK
│   ├── runtime.rs                // WorkflowRuntime: drives transitions, schedules approvals
│   ├── policy_dsl.rs             // PolicyExpr AST (§3) re-exported here for workflow gates
│   └── tests/
└── reference_workflows/          // Authoritative Workflow specs as JSON
    ├── autonomous_procurement.json
    ├── autonomous_treasury.json
    ├── dvp_settlement.json
    ├── supply_chain_dpp.json
    └── environmental_mrv.json
```

Add to workspace root `Cargo.toml` `[workspace.members]`. Dependencies: `tenzro-types`, `tenzro-crypto`, `tenzro-identity`, `tenzro-storage`, `tenzro-events`, `serde`, `dashmap`, `parking_lot`, `tracing`, `thiserror`, `async-trait`, `tokio`.

### 1.2 Core types (signatures)

```rust
// crates/tenzro-workflow/src/workflow.rs
use tenzro_types::{Hash, Timestamp};
use tenzro_identity::DelegationScope;
use crate::policy_dsl::PolicyExpr;

pub type WorkflowId = Hash;  // SHA-256("tenzro/workflow/id" || creator_did || nonce_le)

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowStatus {
    Draft,
    AwaitingSignatures { collected: Vec<String>, required: Vec<String> },
    Active,
    Suspended { reason: String, by: String, at: Timestamp },
    Settling,
    Completed { settled_at: Timestamp, settlement_receipt: Option<Hash> },
    Failed { reason: String, at: Timestamp },
    Disputed { dispute_id: Hash },
    Cancelled { by: String, at: Timestamp },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Workflow {
    pub workflow_id: WorkflowId,
    pub spec_version: u32,             // workflow JSON schema version
    pub template_id: String,           // e.g. "autonomous_procurement/v0"
    pub creator: String,               // DID of workflow creator
    pub created_at: Timestamp,
    pub status: WorkflowStatus,
    pub participants: Vec<Participant>,
    pub obligations: Vec<ObligationId>,
    pub approval_gates: Vec<ApprovalGate>,
    pub canton_mirror: Option<CantonMirror>,    // see §4
    pub privacy_domain: Option<Hash>,           // see §2 — domain id (frozen at create)
    pub policy: Option<PolicyExpr>,             // see §3 — composite enforcement above DelegationScope
    pub fee_route: FeeRouteId,                  // see §7
    pub a2a_card: Option<String>,               // optional A2A skill name
    pub principal_chain_anchor: Hash,           // controller DID hash for Spec 8 receipts
    pub tags: Vec<String>,                      // for indexing
}
```

```rust
// crates/tenzro-workflow/src/obligation.rs
pub type ObligationId = Hash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ObligationStatus {
    Pending,
    InProgress { since: Timestamp },
    Discharged { receipt: Hash, at: Timestamp },
    Defaulted { reason: String, at: Timestamp },
    Forgiven { by: String, at: Timestamp },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Obligation {
    pub obligation_id: ObligationId,
    pub workflow_id: WorkflowId,
    pub obligor: String,             // DID who owes
    pub obligee: String,             // DID who is owed
    pub kind: ObligationKind,
    pub due_by: Option<Timestamp>,
    pub status: ObligationStatus,
    pub discharge_proof_required: DischargeProofKind,
    pub bond_anchor: Option<Hash>,   // AgentBond record (Spec 9) — slashing target on default
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ObligationKind {
    Pay { amount_wei: u128, asset: AssetRef },
    Deliver { resource_did: String, qty: u64 },
    Attest { credential_type: String, subject: String },
    Settle { settlement_id: Hash },
    Custom { tag: String, payload: Vec<u8> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DischargeProofKind {
    PaymentReceipt,         // tenzro-payments MppReceipt / x402 / AP2
    SettlementReceipt,      // tenzro-settlement Settlement record
    Credential,             // tenzro-identity VerifiableCredential
    TeeAttestation,         // tenzro-tee TeeAttestation
    ZkProof { circuit_id: String },  // tenzro-zk Proof
    CantonExercise { template_id: String, choice: String },  // mirrored DAML choice exercise
}
```

```rust
// crates/tenzro-workflow/src/approval.rs
pub type ApprovalRequestId = Hash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalGate {
    pub gate_id: Hash,
    pub workflow_id: WorkflowId,
    pub triggers: PolicyExpr,        // when does this gate fire? (e.g., AmountGt(1000_TNZO))
    pub approvers: ApproverSet,      // who can approve? threshold semantics
    pub timeout: Option<Timestamp>,
    pub on_timeout: TimeoutBehavior, // AutoApprove | AutoReject | EscalateTo(DID)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ApproverSet {
    Single { did: String },
    Threshold { dids: Vec<String>, m_of_n: (u8, u8) },
    Role { role: String, m: u8 },     // any m members holding `role` in the workflow
    Delegated { from: String, scope: DelegationScope },  // delegated approval — controller authorizes a machine to approve
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub request_id: ApprovalRequestId,
    pub gate_id: Hash,
    pub workflow_id: WorkflowId,
    pub trigger_context: serde_json::Value,  // what tripped the gate
    pub created_at: Timestamp,
    pub decisions: Vec<ApprovalDecision>,
    pub status: ApprovalStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub by: String,                  // DID
    pub decision: Decision,          // Approve | Reject
    pub at: Timestamp,
    pub justification: Option<String>,
    pub signature: Vec<u8>,          // Ed25519 over canonical(request_id || decision || at)
    pub signed_by_pubkey: Vec<u8>,
}
```

```rust
// crates/tenzro-workflow/src/participant.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    pub did: String,
    pub roles: Vec<ParticipantRole>,
    pub canton_party_hint: Option<String>,   // populated when workflow is mirrored to Canton
    pub joined_at: Timestamp,
    pub bond_required: Option<u128>,         // wei; checked at signature collection
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ParticipantRole {
    Initiator,
    Counterparty,
    Approver,
    Auditor,         // read-only observer; gets unredacted receipts
    Treasurer,       // controls fee splits + escrow release
    Custodian,       // holds collateral
    OracleProvider,  // attests external state
    Custom(String),
}
```

```rust
// crates/tenzro-workflow/src/lifecycle.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleTransition {
    pub from: WorkflowStatus,
    pub to: WorkflowStatus,
    pub trigger: TransitionTrigger,
    pub authorizer: String,  // DID
    pub at: Timestamp,
    pub receipt: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransitionTrigger {
    SignatureCollected { by: String },
    AllSignaturesCollected,
    ObligationDischarged { obligation_id: ObligationId },
    ObligationDefaulted { obligation_id: ObligationId },
    ApprovalGranted { gate_id: Hash, request_id: ApprovalRequestId },
    ApprovalRejected { gate_id: Hash, request_id: ApprovalRequestId },
    ApprovalTimedOut { gate_id: Hash, request_id: ApprovalRequestId },
    KillSwitchInvoked { by: String, scope: KillSwitchScope },
    DisputeFiled { dispute_id: Hash },
    SettlementCompleted { settlement_id: Hash },
    CantonEvent { contract_id: String, choice_or_create: String },
    ManualCancel { by: String, reason: String },
}
```

### 1.3 Workflow as a typed Tenzro VM transaction

The Tenzro side enforces workflow lifecycle transitions as **privileged-VM typed transactions** (same model as escrow and kill-switch). New selectors in `crates/tenzro-vm/src/native/selectors.rs`:

| Selector | Operation | Gas |
|---|---|---|
| `0x01000020` | `CreateWorkflow` | 120k |
| `0x01000021` | `SignWorkflow` | 60k |
| `0x01000022` | `RecordObligation` | 50k |
| `0x01000023` | `DischargeObligation` | 70k |
| `0x01000024` | `OpenApprovalRequest` | 60k |
| `0x01000025` | `SubmitApprovalDecision` | 50k |
| `0x01000026` | `TransitionWorkflow` | 80k |
| `0x01000027` | `CancelWorkflow` | 70k |

Authorization invariants:
- `CreateWorkflow.from` == workflow.creator
- `SignWorkflow.from` ∈ workflow.participants && participant has not already signed
- `DischargeObligation.from` == obligation.obligor (or holds delegation from obligor with `discharge_obligation` op allowed)
- `SubmitApprovalDecision.from` ∈ resolved approver set for the gate
- `CancelWorkflow.from` == workflow.creator OR delegated cancellation authority

Vault address for any workflow-scoped escrow: `Address(SHA-256("tenzro/workflow/vault" || workflow_id))`. No private key — privileged VM is the only path to drain.

### 1.4 `WorkflowManager` — persistence + index

```rust
// crates/tenzro-workflow/src/manager.rs
use tenzro_storage::KvStore;

pub struct WorkflowManager {
    storage: Arc<dyn KvStore>,
    workflows: DashMap<WorkflowId, Workflow>,
    obligations: DashMap<ObligationId, Obligation>,
    approval_requests: DashMap<ApprovalRequestId, ApprovalRequest>,
    by_creator: DashMap<String, Vec<WorkflowId>>,
    by_participant: DashMap<String, Vec<WorkflowId>>,
    by_status: DashMap<String, Vec<WorkflowId>>,
    by_template: DashMap<String, Vec<WorkflowId>>,
}

impl WorkflowManager {
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> { ... }  // hydrates on construct
    pub async fn create(&self, w: Workflow) -> Result<WorkflowId>;
    pub async fn sign(&self, id: WorkflowId, signer: &str, sig: Signature) -> Result<()>;
    pub async fn record_obligation(&self, o: Obligation) -> Result<ObligationId>;
    pub async fn discharge(&self, id: ObligationId, proof: DischargeProof) -> Result<()>;
    pub async fn open_approval(&self, gate_id: Hash, ctx: serde_json::Value) -> Result<ApprovalRequestId>;
    pub async fn submit_decision(&self, req: ApprovalRequestId, dec: ApprovalDecision) -> Result<ApprovalStatus>;
    pub async fn transition(&self, id: WorkflowId, t: TransitionTrigger) -> Result<WorkflowStatus>;
    pub fn get(&self, id: &WorkflowId) -> Option<Workflow>;
    pub fn list_by_creator(&self, did: &str) -> Vec<Workflow>;
    pub fn list_by_participant(&self, did: &str) -> Vec<Workflow>;
    pub fn list_by_status(&self, status: &str) -> Vec<Workflow>;
}
```

### 1.5 Storage CF + key prefixes

Reuse `CF_SETTLEMENTS` (already opened) — adds prefixes:

| Prefix | Value |
|---|---|
| `wf:<workflow_id>` | bincode-serialized `Workflow` |
| `wf_obl:<obligation_id>` | bincode-serialized `Obligation` |
| `wf_appr:<request_id>` | bincode-serialized `ApprovalRequest` |
| `wf_lifecycle:<workflow_id>:<seq_le>` | bincode-serialized `LifecycleTransition` (append-only) |
| `wf_creator:<did>:<ts_le>` | `WorkflowId` |
| `wf_participant:<did>:<ts_le>` | `WorkflowId` |
| `wf_status:<status>:<ts_le>` | `WorkflowId` |
| `wf_template:<template_id>:<ts_le>` | `WorkflowId` |

All writes via `write_batch_sync` (fsync on lifecycle transition).

### 1.6 Runtime — `WorkflowRuntime`

`WorkflowRuntime` is the long-lived task that:
1. Listens on `tenzro_workflow_events/1.0.0` gossipsub (new topic) for participant signatures, decisions, obligation discharges from peer nodes.
2. Polls scheduled timeouts (approval gate `timeout`, obligation `due_by`).
3. Drives transitions via `WorkflowManager::transition()`.
4. Emits `TenzroEvent::WorkflowLifecycle { ... }` for each transition.
5. If `workflow.canton_mirror.is_some()`, calls `CantonAdapter::mirror_transition(...)` (§4).
6. If `workflow.policy.is_some()`, evaluates `PolicyExpr` (§3) on every action against the workflow's bound `DelegationScope`.

Construction: `WorkflowRuntime::new(manager, canton_adapter, event_bus, identity_registry)`. Wired in `crates/tenzro-node/src/lib.rs::start()` alongside `AgentRuntime`.

### 1.7 RPC surface (added to `tenzro-node/src/rpc.rs`)

| Method | Auth | Returns |
|---|---|---|
| `tenzro_createWorkflow` | controller signs | `{ workflow_id, status }` (writes via `tenzro_signAndSendTransaction`) |
| `tenzro_getWorkflow` | public | `Workflow` |
| `tenzro_listWorkflowsByCreator` | public | `Vec<WorkflowSummary>` |
| `tenzro_listWorkflowsByParticipant` | public | `Vec<WorkflowSummary>` |
| `tenzro_listWorkflowsByStatus` | public | `Vec<WorkflowSummary>` |
| `tenzro_listWorkflowsByTemplate` | public | `Vec<WorkflowSummary>` |
| `tenzro_getWorkflowLifecycle` | public | `Vec<LifecycleTransition>` |
| `tenzro_getObligation` | public | `Obligation` |
| `tenzro_listObligationsByObligor` | public | `Vec<Obligation>` |
| `tenzro_listObligationsByObligee` | public | `Vec<Obligation>` |
| `tenzro_getApprovalRequest` | public | `ApprovalRequest` |
| `tenzro_listPendingApprovalsForApprover` | DID arg | `Vec<ApprovalRequest>` |

Write paths (`SignWorkflow`, `DischargeObligation`, `SubmitApprovalDecision`, `CancelWorkflow`) flow through `tenzro_signAndSendTransaction` / `eth_sendRawTransaction` only — no convenience write RPCs that bypass signing.

### 1.8 MCP tools (added to `tenzro-node/src/mcp/server.rs`)

`create_workflow`, `get_workflow`, `list_workflows_by_creator`, `list_workflows_by_participant`, `list_workflows_by_status`, `list_pending_approvals`, `get_obligation`, `discharge_obligation`, `submit_approval_decision`, `get_workflow_lifecycle` — each wraps the corresponding RPC.

### 1.9 DAML codegen (`codegen/daml.rs`)

For any `Workflow` with `canton_mirror.is_some()`, `WorkflowDamlCodegen::emit(&workflow) -> String` produces a `.daml` source file. The emitter targets the **Multiple Party Agreement pattern**:

```daml
module Tenzro.Workflow.<Template> where

import DA.List

template Pending<Template>
  with
    workflow_id : Text             -- SHA-256 hex
    creator : Party
    participants : [Party]
    signatories : [Party]
    obligations : [ObligationSpec]
  where
    signatory creator
    observer participants

    -- Per-participant Sign choice replaces their slot in `signatories`
    choice Sign : ContractId Pending<Template>
      with signer : Party
      controller signer
      do
        assertMsg "signer not a participant" (signer `elem` participants)
        assertMsg "already signed" (notElem signer signatories)
        let next_signatories = signer :: signatories
        if length next_signatories == length participants
          then do
            -- All signed: materialize the Active workflow
            cid <- create Active<Template> with ..
            return cid  -- returns the new contract id, archives this Pending
          else create this with signatories = next_signatories

template Active<Template>
  with
    workflow_id : Text
    creator : Party
    participants : [Party]
    obligations : [ObligationSpec]
  where
    signatory participants
    -- Per CIP-56 TransferInstruction pattern for any Pay obligations
    interface instance Token.TransferInstruction for Active<Template> where
      view = ...

    -- Discharge choice for each obligation (nonconsuming until all discharged)
    nonconsuming choice DischargeObligation : ContractId Active<Template>
      with
        obligation_id : Text
        proof_kind : Text
        proof_payload : Text
      controller (head [p | p <- participants, ... obligor lookup ...])
      do
        ... emit event, archive when all obligations discharged ...
```

The emitter consumes the `Workflow` JSON spec + an associated **DAML mapping file** (`reference_workflows/<template>/daml_map.json`) that names the DAML record types for `ObligationSpec`, parameter types for choices, and any external `Token` interface to bind. The emitter is deterministic — same input → same `.daml` output (so DAR builds are reproducible).

Codegen is invoked via `tenzro workflow daml-emit <template-id> --out target/daml/`. The emitted DAML compiles to a DAR via `daml build` (offline tool), and the DAR is uploaded to the target Canton synchronizer via the existing `CantonAdapter::upload_dar()` path.

**No Rust-native DAR builder** — we shell out to `daml build` because (a) DAR is an internal Daml-LF format, (b) the toolchain is GA-stable, (c) reimplementing it in Rust is months of work for zero user benefit.

### 1.10 Tests

- `manager_persists_and_hydrates` — write a workflow, drop the manager, reopen, verify it's there.
- `signature_collection_threshold` — 3 participants, all sign, status flips to Active.
- `obligation_discharge_chain` — full procurement workflow: create → sign → discharge pay obligation → discharge deliver obligation → settle.
- `approval_gate_threshold` — 2-of-3 approvers, gate fires correctly.
- `approval_timeout_escalation` — timeout fires, EscalateTo path triggers.
- `kill_switch_authorized_transition` — kill-switch invocation transitions to Suspended.
- `policy_dsl_blocks_action` — policy denies an obligation discharge over the cap.
- `daml_codegen_deterministic` — same workflow JSON → byte-identical .daml output.

---

## 2. PrivacyDomain — party-scoped visibility on the Tenzro side

**Premise:** Canton enforces per-recipient view encryption; we cannot mirror that in libp2p gossipsub. What we *can* do is scope **which Tenzro events reach which recipients** at the application layer, with envelope encryption per recipient. This gives workflows the same *operational* property (an auditor sees the workflow, a competitor doesn't) without claiming to implement Canton's cryptography.

### 2.1 Type

```rust
// crates/tenzro-workflow/src/privacy.rs
pub type PrivacyDomainId = Hash;  // SHA-256("tenzro/privacy/domain" || creator_did || nonce_le)

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyDomain {
    pub domain_id: PrivacyDomainId,
    pub creator: String,                          // DID
    pub members: Vec<DomainMember>,
    pub visibility: VisibilityPolicy,
    pub created_at: Timestamp,
    pub frozen: bool,                             // once a workflow binds, members cannot be removed
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainMember {
    pub did: String,
    pub x25519_pubkey: Vec<u8>,                   // 32-byte X25519 public key for envelope encryption
    pub role_in_domain: DomainRole,
    pub joined_at: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DomainRole {
    Full,       // sees all events
    Auditor,    // sees lifecycle + receipts, not raw payload
    Limited(Vec<String>),  // event-kind allowlist
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VisibilityPolicy {
    MembersOnly,
    MembersPlusAuditors,
    PublicLifecycleAuditedPayload,
}
```

### 2.2 Per-event ACL on `TenzroEvent`

Extend `crates/tenzro-events/src/event.rs`:

```rust
pub struct TenzroEvent {
    // ... existing fields ...
    pub privacy: Option<EventPrivacy>,
}

pub struct EventPrivacy {
    pub domain_id: PrivacyDomainId,
    pub recipient_envelopes: Vec<RecipientEnvelope>,  // one per member
    pub public_summary: Option<serde_json::Value>,    // what non-members see (or None for fully private)
}

pub struct RecipientEnvelope {
    pub recipient_did: String,
    pub ephemeral_x25519_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,                          // AES-256-GCM(payload)
    pub tag: [u8; 16],
}
```

Encryption: ECIES-style.
- Sender generates ephemeral X25519 keypair (per event).
- For each member: `shared = X25519(ephemeral_priv, member_pub)`; `key = HKDF-SHA256(shared, domain_id_bytes)`; encrypt payload with AES-256-GCM.
- Reuses `tenzro-crypto::aes_gcm` and X25519 routines already in `tenzro-crypto`.

### 2.3 Network-layer filter

In `crates/tenzro-network/src/peer_manager.rs` add `EventPrivacyFilter`:

```rust
pub trait EventPrivacyFilter: Send + Sync {
    /// Returns true if `peer_did` is a member of `domain_id`.
    fn peer_in_domain(&self, peer_did: &str, domain_id: &PrivacyDomainId) -> bool;
}
```

A node implementation reads from `PrivacyDomainRegistry`. When publishing on `tenzro_workflow_events/1.0.0`, the publisher attaches the per-recipient envelopes; subscribers verify they have a matching envelope and decrypt locally. **The gossip topic itself is not encrypted** — what's encrypted is the per-recipient payload. Non-members see metadata (event kind, workflow_id) per `public_summary` but not the body.

### 2.4 Storage

CF_SETTLEMENTS prefixes:
- `pd:<domain_id>` → `PrivacyDomain` bincode
- `pd_member:<did>:<domain_id>` → marker (for fast peer-in-domain checks)
- `pd_workflow:<workflow_id>` → `domain_id` (for receipt routing)

### 2.5 RPC

| Method | Returns |
|---|---|
| `tenzro_createPrivacyDomain` | `{ domain_id }` (typed tx selector `0x01000028`) |
| `tenzro_addPrivacyDomainMember` | `{ ok }` (selector `0x01000029`, frozen check) |
| `tenzro_getPrivacyDomain` | `PrivacyDomain` |
| `tenzro_listPrivacyDomainsForDid` | `Vec<PrivacyDomain>` |

### 2.6 What this is NOT

This is **not** sub-transaction privacy. This is **not** equivalent to Canton's view encryption. It is application-layer envelope encryption on Tenzro events tied to a domain membership list. Workflows that need Canton-grade privacy must mirror to Canton and rely on Canton's enforcement (§4). The PrivacyDomain primitive exists so that the Tenzro side of a multi-party workflow has *some* selective-disclosure model when mirroring is not used.

---

## 3. Policy DSL — composite policies above DelegationScope

**Premise:** `DelegationScope` is a flat ceiling (max_transaction_value, allowed_operations, etc.). The agentic economy needs composite predicates: "approve any payment under 1000 TNZO **and** to a counterparty in our ERP whitelist **and** within business hours, **else** require treasurer approval". That is `(AmountLt(1000) ∧ CounterpartyIn(...) ∧ TimeWindow(...)) ∨ RequiresApprovalFrom(treasurer_did)`.

### 3.1 AST

```rust
// crates/tenzro-workflow/src/policy_dsl.rs
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PolicyExpr {
    // Boolean combinators
    And(Vec<PolicyExpr>),
    Or(Vec<PolicyExpr>),
    Not(Box<PolicyExpr>),
    // Always
    Allow,
    Deny,
    // Amount predicates (wei)
    AmountLte(u128),
    AmountGte(u128),
    DailyAmountLte(u128),
    // Counterparty
    CounterpartyIn(Vec<String>),       // DIDs
    CounterpartyDomain(String),        // ENS domain or canton party suffix
    CounterpartyKycTierGte(u8),
    CounterpartyBondGte(u128),
    // Time
    TimeWindow { start_hour: u8, end_hour: u8, tz_offset_minutes: i16 },
    DayOfWeekIn(Vec<u8>),              // 0=Mon..6=Sun
    BeforeBlock(u64),
    AfterBlock(u64),
    // Risk
    RiskTierLte(u8),                   // see `tenzro-identity::risk`
    AssetIn(Vec<String>),              // "TNZO" | "USDC" | etc.
    ChainIn(Vec<String>),              // CAIP-2
    PaymentProtocolIn(Vec<String>),    // "MPP" | "x402" | "AP2"
    // Workflow-scoped
    InWorkflowStatus(Vec<String>),
    ParticipantHasRole(String),
    // Escalation
    RequiresApprovalFrom(String),
    RequiresApprovalThreshold { dids: Vec<String>, m_of_n: (u8, u8) },
}
```

### 3.2 Evaluator

```rust
pub struct PolicyContext<'a> {
    pub amount_wei: u128,
    pub counterparty_did: Option<&'a str>,
    pub asset: &'a str,
    pub chain: &'a str,
    pub payment_protocol: &'a str,
    pub current_block: u64,
    pub current_ts: i64,
    pub workflow: Option<&'a Workflow>,
    pub identity_registry: &'a dyn IdentityLookup,
    pub daily_spent_wei: u128,
}

#[derive(Debug, PartialEq)]
pub enum PolicyVerdict {
    Allow,
    Deny { reason: String },
    RequireApproval { approvers: ApproverSet, reason: String },
}

pub fn evaluate(expr: &PolicyExpr, ctx: &PolicyContext) -> PolicyVerdict { ... }
```

The evaluator is **pure** (no async, no I/O beyond the `IdentityLookup` trait), so it is deterministic, unit-testable, and embeddable inside the privileged-VM transaction-validation path.

### 3.3 Wiring

- `DelegationScope` gains `pub policy: Option<PolicyExpr>` field. `IdentityRegistry::enforce_operation` evaluates it after the existing flat checks. (Backward compatible: `None` = current behavior.)
- `IdentityPaymentBinder::enforce_payment_with_policy` — extends current two-axis ceiling (DelegationScope + SpendingPolicy) into a three-axis ceiling (DelegationScope + PolicyExpr + SpendingPolicy).
- `Workflow.policy` (defined in §1.2) is evaluated by `WorkflowRuntime` on every state transition trigger.
- `Ap2Validator::validate_with_delegation_and_policy_expr` extends to evaluate the cart mandate against the controller's `PolicyExpr`.
- `RequireApproval` verdict from the evaluator is the trigger that opens an `ApprovalGate` (§1.2).

### 3.4 RPC

| Method | Returns |
|---|---|
| `tenzro_setIdentityPolicy` | typed tx selector `0x0100002A`, controller-only |
| `tenzro_getIdentityPolicy` | `Option<PolicyExpr>` |
| `tenzro_evaluatePolicy` | `PolicyVerdict` (read-only — for clients to dry-run) |

### 3.5 Tests

- `evaluator_short_circuits_on_deny`
- `and_or_not_combinators_correct`
- `time_window_handles_tz_and_dst`
- `requires_approval_routes_to_gate`
- `policy_overrides_flat_scope_when_more_restrictive`

---

## 4. Canton receipt mirror

**Premise:** Today `CantonAdapter` can submit DAML commands and read active contracts but does **not bidirectionally mirror state**: a Tenzro `Settlement` does not produce a corresponding DAML contract by default, and a DAML event does not produce a corresponding `TenzroEvent`. We add both directions.

### 4.1 Outbound: Tenzro receipt → DAML create

New methods on `crates/tenzro-bridge/src/canton.rs::CantonAdapter`:

```rust
impl CantonAdapter {
    /// Mirrors a Tenzro Settlement / WorkflowReceipt onto Canton as a DAML create.
    /// Returns the resulting DAML ContractId.
    pub async fn mirror_receipt(
        &self,
        synchronizer_id: &SynchronizerId,
        receipt: &MirrorableReceipt,
        as_party: &DamlParty,
    ) -> Result<DamlContractId>;

    /// Mirrors a Tenzro workflow lifecycle transition as a choice exercise.
    pub async fn mirror_transition(
        &self,
        synchronizer_id: &SynchronizerId,
        contract_id: &DamlContractId,
        choice: &str,
        argument: serde_json::Value,
        as_party: &DamlParty,
    ) -> Result<DamlTransaction>;
}

pub enum MirrorableReceipt {
    Settlement(tenzro_settlement::Settlement),
    WorkflowLifecycle(tenzro_workflow::LifecycleTransition),
    PaymentMpp(tenzro_payments::MppReceipt),
    PaymentX402(tenzro_payments::X402Receipt),
    PaymentAp2(tenzro_payments::Ap2Receipt),
    KillSwitch(tenzro_lifecycle::KillSwitchReceipt),
}
```

Implementation: each variant has a corresponding DAML template (`Tenzro.Mirror.SettlementReceipt`, `Tenzro.Mirror.WorkflowReceipt`, etc.) in a single `tenzro-mirror.dar` shipped with the node. The DAR is uploaded to the synchronizer at first use (idempotent — version-tagged so re-upload is a no-op).

### 4.2 Inbound: DAML event → TenzroEvent

```rust
impl CantonAdapter {
    /// Subscribes to all DAML events for the given party on the synchronizer
    /// and emits them as TenzroEvent::CantonEvent on the local event bus.
    pub async fn consume_daml_events(
        &self,
        synchronizer_id: &SynchronizerId,
        as_party: &DamlParty,
        event_bus: Arc<EventBus>,
    ) -> Result<JoinHandle<()>>;
}
```

Implementation: long-lived task that opens the JSON Ledger API v2 `/v2/updates` WebSocket (auth: JWT), filters for events visible to `as_party`, decodes each event, and dispatches to `event_bus.publish(TenzroEvent::CantonEvent { ... })`.

### 4.3 New `TenzroEvent` variant

```rust
pub enum TenzroEvent {
    // ... existing ...
    CantonEvent {
        synchronizer_id: String,
        party: String,
        contract_id: String,
        template_id: String,
        kind: CantonEventKind,           // Created | Archived | Exercised
        payload: serde_json::Value,
        observed_at: Timestamp,
        related_workflow: Option<WorkflowId>,
    },
}
```

When `related_workflow.is_some()`, `WorkflowRuntime` consumes the event and may trigger a `LifecycleTransition::CantonEvent { ... }`. Closes the loop: a Canton-side choice exercise drives a Tenzro-side workflow transition.

### 4.4 Configuration

`config.toml`:

```toml
[canton.mirror]
enabled = false                           # opt-in
synchronizer_id = "global-mainnet::abc..."
party = "tenzro::1220abcd"
auto_mirror_settlements = true
auto_mirror_workflows = true
mirror_dar_path = "/usr/share/tenzro/tenzro-mirror.dar"
jwt_token_env = "CANTON_JWT_TOKEN"
```

### 4.5 RPC

| Method | Returns |
|---|---|
| `tenzro_canton_mirrorReceipt` | `{ daml_contract_id }` |
| `tenzro_canton_mirrorTransition` | `{ daml_tx_id }` |
| `tenzro_canton_listMirroredContracts` | `Vec<MirrorRecord>` |
| `tenzro_canton_streamEvents` | WebSocket subscription |

### 4.6 Tests

- `mirror_settlement_creates_daml_contract` (against a DAML sandbox, feature-gated)
- `inbound_event_dispatches_tenzro_event`
- `workflow_canton_round_trip` (Tenzro create → Canton mirror → Canton choice → Tenzro transition)

---

## 5. Reference workflow templates

Five JSON workflow specs in `crates/tenzro-workflow/reference_workflows/`. Each ships with: (a) the `Workflow` JSON, (b) a `daml_map.json` for codegen, (c) a generated `.daml` source, (d) an A2A skill descriptor, (e) an integration test driving the full lifecycle.

### 5.1 `autonomous_procurement.json` — flagship demo

Workflow: A buyer agent (delegated by buyer org) issues a purchase request to a seller agent (delegated by seller org). Seller agent confirms availability and price. Buyer agent submits payment via AP2 cart mandate. Settlement happens on Tenzro and is mirrored to Canton. An auditor party observes on Canton; a treasurer is in a `PrivacyDomain` on Tenzro.

Participants: `buyer_controller` (Human), `buyer_agent` (Machine), `seller_controller` (Human), `seller_agent` (Machine), `auditor` (Auditor role), `treasurer` (Treasurer role).

Obligations:
1. Buyer obligation: `Pay { amount_wei, asset: USDC }` to seller; discharge proof = `PaymentReceipt(AP2)`.
2. Seller obligation: `Deliver { resource_did, qty }`; discharge proof = `Credential(DeliveryAttestation)` issued by seller_controller.

Approval gate: any `Pay` obligation > 50,000 USDC requires treasurer 1-of-1 approval.

PolicyExpr on buyer_agent's DelegationScope: `And([AmountLte(50_000_USDC), CounterpartyIn(seller_agent_allowlist), TimeWindow(business_hours)])`.

PrivacyDomain: domain `proc-{workflow_id}` with members [buyer_controller, buyer_agent, seller_controller, seller_agent, auditor, treasurer]; visibility = `MembersPlusAuditors`.

Canton mirror: `Tenzro.Workflow.AutonomousProcurement` template; obligations 1 & 2 become `PaymentProposal` and `DeliveryAttestation` choices.

Fee route (§7): 80% of network commission → seller_treasury, 15% → buyer_treasury, 5% → Tenzro treasury.

### 5.2 `autonomous_treasury.json`

A treasury agent rebalances a multi-token portfolio across chains. PolicyExpr enforces per-asset caps + per-chain caps + counterparty whitelist. Approval gate fires for any single trade > 5% of NAV. Mirrored to Canton as a `TreasuryAction` template observed by an auditor.

### 5.3 `dvp_settlement.json` — institutional DvP-style

Buyer pays cash CIP-56 (USDCx) and seller delivers cash-tokenized U.S. Treasuries (cBTC stand-in). Atomic DvP via a DAML choice that *both* transfers happen in one transaction. Tenzro side records the `Settlement` and emits the lifecycle transition; Canton side enforces atomicity.

### 5.4 `supply_chain_dpp.json` — PRVNZ alignment

Multi-stage supply chain: producer → carrier → distributor → retailer. Each stage discharges a `Deliver` obligation with TEE-attested provenance (`TeeAttestation` discharge proof). PrivacyDomain restricts payload to direct upstream/downstream only — auditor sees full chain.

### 5.5 `environmental_mrv.json` — Naturecode alignment

Environmental measurement → reporting → verification. Producer obligation: `Attest(emissions_credential)` issued from sensor TEE. Verifier obligation: `Attest(verification_credential)` after review. Mirrored to Canton for buyer of credit. Approval gate on credit issuance > 10,000 tonnes CO2e.

Each template ships with a `tests/` integration test that:
1. Starts an in-process node with mock CantonAdapter.
2. Creates the workflow, signs all participants.
3. Drives all obligations to discharge.
4. Asserts: workflow status = `Completed`; expected `LifecycleTransition`s in order; expected `TenzroEvent`s on the bus; expected mirror calls on the mock adapter.

---

## 6. Operational-density telemetry

**Premise:** Raw tx/sec is the wrong metric for an agentic-economy chain. The right metrics are **operational density**: workflow events/hour, approvals/hour, attestation events/hour, obligations-discharged/hour. These are what enterprises and regulators care about.

### 6.1 Metrics module

New `crates/tenzro-node/src/metrics/operational.rs`:

```rust
pub struct OperationalMetrics {
    workflows_created_total: IntCounter,
    workflows_completed_total: IntCounter,
    workflows_active: IntGauge,
    workflows_disputed_total: IntCounter,
    obligations_recorded_total: IntCounter,
    obligations_discharged_total: IntCounterVec,        // by discharge_proof_kind
    obligations_defaulted_total: IntCounter,
    approvals_opened_total: IntCounter,
    approvals_granted_total: IntCounter,
    approvals_rejected_total: IntCounter,
    approvals_timed_out_total: IntCounter,
    approval_decision_latency_seconds: Histogram,
    canton_mirror_writes_total: IntCounterVec,           // by template
    canton_mirror_reads_total: IntCounterVec,
    canton_mirror_errors_total: IntCounterVec,
    privacy_domain_active: IntGauge,
    policy_evaluations_total: IntCounterVec,             // by verdict
    workflow_lifecycle_transitions_total: IntCounterVec, // by transition kind
}
```

Exposed at `/metrics` (existing endpoint). Per-template, per-status, per-verdict label cardinality is bounded (templates ≤ ~50, statuses fixed, verdicts 3).

### 6.2 OperationalDigest (RPC for dashboards)

```rust
pub struct OperationalDigest {
    pub window_seconds: u64,
    pub workflows_created: u64,
    pub workflows_completed: u64,
    pub obligations_discharged_by_kind: HashMap<String, u64>,
    pub approval_throughput_per_hour: f64,
    pub mean_approval_latency_seconds: f64,
    pub canton_round_trips: u64,
    pub active_privacy_domains: u64,
    pub policy_deny_ratio: f64,
}
```

RPC: `tenzro_getOperationalDigest { window_seconds }` — pure read from in-memory metric snapshots; sub-second response.

### 6.3 Dashboard

Grafana JSON checked into `deploy/grafana/operational-density.json` (no auto-deploy; operator imports). Panels: workflows-created/hr, obligations-discharged/hr split by kind, approval-grant-rate, mean-approval-latency, Canton round-trip count, top-10 templates by activity.

---

## 7. Per-workflow / per-bridge fee routing

**Premise:** `NetworkTreasury` collects a flat 0.5% commission today. The agentic economy needs **routable splits**: a procurement workflow may route a slice to the buyer org's treasury, a CIP-56 transfer routes a slice to the issuer's registry-operator wallet, a Canton mirror routes a slice to cover CC traffic costs.

### 7.1 `FeeRoute` type

```rust
// crates/tenzro-token/src/fee_route.rs
pub type FeeRouteId = Hash;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRoute {
    pub route_id: FeeRouteId,
    pub creator: String,
    pub splits: Vec<FeeSplit>,                    // must sum to <= 10000 bps
    pub residual_to: String,                      // receives remainder up to 10000 bps
    pub created_at: Timestamp,
    pub frozen: bool,                             // true when bound to a workflow
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeSplit {
    pub recipient_did: String,
    pub bps: u16,                                 // basis points (0-10000)
    pub label: String,                            // "buyer_treasury" | "seller_treasury" | etc.
}
```

### 7.2 `NetworkTreasury` routing

`NetworkTreasury::collect_with_route(amount_wei, route_id)` looks up the route and credits each recipient's wallet via privileged-VM internal transfer. All routing happens in one privileged VM transaction (atomic). Each leg of the split emits a `TenzroEvent::FeeSplit { route_id, recipient, amount_wei, label }`.

If `route_id` is `None`, behavior is unchanged (residual_to = treasury_default).

### 7.3 Storage

`CF_TOKENS` prefixes:
- `fee_route:<route_id>` → `FeeRoute` bincode
- `fee_route_creator:<did>:<ts_le>` → `FeeRouteId`
- `fee_route_workflow:<workflow_id>` → `FeeRouteId`

### 7.4 RPC

| Method | Returns |
|---|---|
| `tenzro_createFeeRoute` | typed tx selector `0x0100002B`, creator-only writes |
| `tenzro_getFeeRoute` | `FeeRoute` |
| `tenzro_listFeeRoutesByCreator` | `Vec<FeeRoute>` |
| `tenzro_simulateFeeSplit` | dry-run `Vec<{recipient, amount_wei, label}>` |

### 7.5 Canton bridge fee model update

`bridge::canton::fee_quote()` updated to:
```rust
pub fn fee_quote(payload_bytes_size: usize, value_usd_cents: u64) -> CantonFeeQuote {
    let traffic_usd_cents = ((payload_bytes_size as u64 + 1_048_575) / 1_048_576) * 1700;  // $17/MB
    let pct_usd_cents = match value_usd_cents {
        0..=10_000 => value_usd_cents / 100,                        // 1% on first $100
        10_001..=100_000 => 100 + (value_usd_cents - 10_000) / 1000, // 0.1%
        100_001..=1_000_000 => 190 + (value_usd_cents - 100_000) / 10_000, // 0.01%
        _ => 280 + (value_usd_cents - 1_000_000) / 100_000,          // 0.001%
    };
    CantonFeeQuote {
        traffic_fee_usd_cents: traffic_usd_cents,
        percentage_fee_usd_cents: pct_usd_cents,
        total_usd_cents: traffic_usd_cents + pct_usd_cents,
        cc_at_published_rate: convert_usd_to_cc(traffic_usd_cents + pct_usd_cents),
    }
}
```

Source: https://www.canton.network/blog/canton-coin-rewarding-utility — $17/MB + tiered % fee schedule.

---

## 8. A2A hooks — workflow / obligation / approval / disclosure / privacy_domain skills

**Premise:** Today's A2A server exposes 33 skills mostly oriented around single-agent capabilities (wallet, identity, inference). For the agentic economy on Canton, agents need to *participate in workflows*, *discharge obligations*, *issue approval decisions*, *receive selectively disclosed events*. These become first-class A2A skills.

### 8.1 New A2A skills (registered in `integrations/a2a/tenzro_a2a_server/agent_card.py`)

| Skill | Description | JSON-RPC methods |
|---|---|---|
| `workflow` | Participate in workflows (sign, discharge, cancel). | `workflow/create`, `workflow/sign`, `workflow/cancel`, `workflow/get`, `workflow/list-mine` |
| `obligation` | Discharge or default obligations the agent owes. | `obligation/discharge`, `obligation/list-mine`, `obligation/get` |
| `approval` | Receive and respond to approval requests gated to this agent. | `approval/list-pending`, `approval/decide`, `approval/get` |
| `disclosure` | Pull selectively disclosed events by domain membership. | `disclosure/list-events`, `disclosure/decrypt-envelope`, `disclosure/list-domains` |
| `privacy_domain` | Manage domains the agent administers. | `privacy_domain/create`, `privacy_domain/add-member`, `privacy_domain/list` |
| `canton_mirror` | Trigger or query Canton mirror state. | `canton_mirror/mirror-receipt`, `canton_mirror/list-mirrored`, `canton_mirror/stream-events` |

### 8.2 Agent Card extensions

Update `/.well-known/agent.json` to advertise new skills. Each skill declares its RPC method names and required input/output schemas (JSON Schema). Agents discover capabilities by querying the card; no out-of-band documentation needed.

### 8.3 Streaming over SSE

`approval/listen-pending` and `disclosure/listen-events` are SSE-streaming endpoints (existing `/a2a/stream`). When an agent connects, the server pushes pending approvals and decrypted-for-this-agent disclosure events as they arrive. This is what makes agent-driven workflows responsive — no polling.

### 8.4 MCP parity

Same surface mirrored as MCP tools (`workflow_*`, `obligation_*`, `approval_*`, `disclosure_*`) so Claude/GPT/etc. can drive workflows directly via `mcp.tenzro.network/mcp`.

---

## 9. Phasing

### Phase 1 (foundational)
1. `tenzro-workflow` crate skeleton (workflow.rs, obligation.rs, approval.rs, lifecycle.rs, manager.rs, error.rs).
2. Storage CF prefixes + write-through + hydration.
3. Privileged-VM typed tx selectors `0x01000020`–`0x01000029`.
4. RPC surface for create/sign/get/list.
5. PolicyExpr AST + evaluator (pure, no DSL parser yet).
6. PrivacyDomain type + envelope encryption + per-event ACL.
7. Tests for manager, evaluator, encryption.

### Phase 2 (Canton integration)
1. `CantonAdapter::mirror_receipt` / `mirror_transition` / `consume_daml_events`.
2. `tenzro-mirror.dar` shipped with node binary.
3. DAML codegen (`codegen/daml.rs`) + `tenzro workflow daml-emit` CLI.
4. First reference template: `autonomous_procurement.json` (full integration test).
5. `TenzroEvent::CantonEvent` variant + `WorkflowRuntime` consumption.

### Phase 3 (operability + ecosystem)
1. Operational metrics (`OperationalMetrics`, `/metrics` labels, `tenzro_getOperationalDigest`).
2. Grafana dashboard JSON.
3. `FeeRoute` + per-workflow split routing + Canton fee quote update.
4. Remaining 4 reference templates (treasury, DvP, supply chain, environmental MRV).
5. A2A skill registration + Agent Card updates + MCP parity.
6. Public documentation (operator guide for workflows, developer guide for templates).

## 10. What this plan does NOT include

- **Mirroring Canton's view-encryption inside Tenzro gossip.** Canton-grade selective disclosure requires mirroring to Canton; Tenzro PrivacyDomain is application-layer envelope encryption only.
- **Rust-native DAR builder.** We shell out to `daml build` (offline, CI-only).
- **CIP-56 ↔ ERC-7683 standardization PR.** Tenzro implements 7683-style fills as CIP-56 `TransferInstruction` proposals; we may file a CIP if the pattern is reusable, but that's a separate work item.
- **Cross-controller workflow chains** where two unrelated controllers jointly govern an agent. Joint custody is a wallet-layer (FROST-Ed25519 threshold) construct, not a workflow-layer one.
- **Onchain DAML interpretation in `tenzro-vm`.** We continue to use Canton as the DAML execution environment; Tenzro mirrors and indexes, doesn't interpret.

## 11. Verification plan

For each Phase, the integration is considered done when:
- All unit + integration tests pass in CI (`cargo test --workspace`).
- Fresh node startup hydrates state from RocksDB (no in-memory-only).
- One end-to-end demo run on testnet using the relevant reference template, producing receipts queryable via RPC, A2A, and (for Phase 2+) on the Canton synchronizer.
- Operator docs land in the same PR as the feature.
- All workspace conventions honored: no backcompat shims, no dead code, no `/api/` redundancy, no version-prefix in tenzro-owned identifiers (`tenzro_workflow_events/1.0.0` is a gossip topic = third-party-style namespacing per existing convention; new RPC methods are `tenzro_*` flat).
