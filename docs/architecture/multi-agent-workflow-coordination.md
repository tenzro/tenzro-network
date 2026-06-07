# Multi-Agent Workflow Coordination

**Status:** Research / SOTA mapping. Not a shipped spec.
**Last updated:** 2026-06-02

## Why this doc exists

Single-agent task lifecycles (covered in `task-coordination-lifecycle.md`) handle the case where one poster hands one unit of work to one provider. Real 2026 production workloads — Magentic-One generalist agents, CrewAI hierarchical crews, AutoGen Selector Group Chat, LangGraph supervisor graphs — are **multi-agent workflows**: a DAG of subtasks where intermediate steps depend on prior outputs, failures need compensation, and the orchestrator may not even know all the agents at start time.

This doc maps where Tenzro can sit beneath those workflows as a coordination substrate without becoming yet another framework. Like the task-lifecycle doc, the position is: **Tenzro is the wire, the frameworks are the runtimes**. The frameworks already exist and are excellent; what's missing is a shared substrate for cross-framework workflow checkpointing, compensation, settlement, and identity-bound state transitions.

This is dev-tree-only research, not a published spec.

## Crucial architectural distinction

Tenzro is **not building a multi-agent orchestrator**. There are already ~7 best-in-class ones (LangGraph v0.4, CrewAI, AutoGen 1.0 GA, Letta, OpenAI SDK, Google ADK, Microsoft Agent Framework). Each has its own state model, its own checkpointing, its own retry semantics. Tenzro's role is to be the **durable, identity-bound, settlement-aware layer** these frameworks can checkpoint against when:

1. A workflow spans multiple agents owned by different parties
2. A step involves payment or stake
3. A failure needs compensation (saga pattern)
4. The outcome needs to be auditable on-chain

This positions Tenzro as the equivalent of **Temporal for trusted multi-agent workflows** — the durable execution layer beneath the framework, not a competitor to the framework.

## SOTA reference (2026 multi-agent workflow patterns)

| Framework | Coordination model | Checkpointing | Compensation | Cross-party |
|---|---|---|---|---|
| **LangGraph v0.4** | supervisor graph, conditional edges | Postgres / SQLite | none built-in; pair w/ Temporal | no |
| **CrewAI** | hierarchical (manager + workers) or sequential | in-memory or Redis | retry-based | no |
| **AutoGen 1.0** | Selector Group Chat, GraphFlow, Magentic-One | per-session in-memory | re-plan via Magentic Orchestrator | no |
| **Letta** | stateful single-agent + memory blocks | Postgres | none | no |
| **Microsoft Agent Framework** | hosted workflow service | Azure-backed | retry policies | partial (cross-tenant) |
| **SagaLLM** (research, Mar 2025) | saga pattern + validation agents | persistent memory | automated compensation | yes-conceptual |
| **A2A-SAGA** (proposal, Jan 2026) | A2A extension for saga semantics | A2A task store | Execute → Verify → Compensate | yes |

The two patterns to note specifically:

**Magentic-One ledger pattern** (Microsoft Research, Nov 2024, productionized in Microsoft Agent Framework 2026). The Orchestrator maintains:
- **Task Ledger** — outer loop: facts, guesses, plan
- **Progress Ledger** — inner loop: current progress, task assignment, completion check

Each step the Orchestrator self-reflects on the Progress Ledger, assigns a subtask, and rewrites the Task Ledger if it gets stuck. This is the dominant pattern for "agent that doesn't know the plan up front."

**Saga pattern for compensation** (SagaLLM March 2025, A2A-SAGA proposal Jan 2026). For workflows like "book flight → book hotel → book car", if the car booking fails, prior bookings must be rolled back via explicit compensation actions. LangGraph + Temporal is the current production answer; A2A-SAGA proposes standardizing the Execute → Verify → Compensate triad at the protocol level. This is where Tenzro should align — settle the workflow primitives **at the A2A wire level**, not in any single framework.

## Shipped surface (audited 2026-06-02)

### Workflow runtime (real, indexer-shaped)

`crates/tenzro-node/src/workflow_runtime.rs` ships a **state-machine ledger** that mirrors VM-side workflow events into in-memory state + `CF_SETTLEMENTS` + `CF_APPROVALS`. It is not a DAG execution engine — it's an **indexer of VM-executed workflow events**. The VM is the orchestrator; the runtime is the index.

Twelve mutation types ingested:
- `WorkflowCreate`, `Sign`, `Transition`
- `RegisterObligation`, `DischargeObligation`, `DefaultObligation`
- `RegisterGate`, `OpenApproval`, `SubmitDecision`
- `KillSwitch`, `RegisterPrivacyDomain`, `FreezePrivacyDomain`

Workflow states (Draft → AwaitingSignatures → Active → {Suspended, Settling, Completed, Failed, Disputed, Cancelled}) are real and persisted.

**This is shipped. Verdict: production-quality indexer for VM-mediated workflows, not a multi-agent execution layer.**

### Agent swarm (real, orchestrator-rooted tree)

`crates/tenzro-agent/src/swarm.rs` ships `SwarmManager` with:
- `create_swarm(orchestrator_id, member_ids[])` — registers a swarm rooted at one orchestrator
- `broadcast_task(swarm_id, task)` — dispatches the task to each member via `runtime.delegate_task`, collects success/error per member, returns aggregated result
- `terminate_swarm` — explicit termination, flips members to Terminated, removes record
- `check_swarm_liveness` — sweeps and auto-completes swarms whose members are all Terminated
- Persisted to `CF_AGENTS` under `swarm:` prefix, full hydration on startup

**This is shipped.** Coordination model is centralized-orchestrator tree, not P2P mesh. Single broadcast step (one task → N members). No DAG. No saga. No compensation.

### Agent runtime + delegate_task

`AgentRuntime::delegate_task` performs the actual subtask dispatch. Connection from `SwarmManager::broadcast_task` → `runtime.delegate_task` is wired. The runtime then routes the task to the target agent's MCP/A2A endpoint.

### Templates + spawning (real, 11-step pipeline)

`crates/tenzro-agent-kit/src/spawner.rs` provisions a new agent in 11 sequential, all-or-nothing steps:
1. Fetch template
2. Validate execution spec
3. Auto-discover tools/skills
4. Generate controller keypair
5. Register controller human identity (auto-provisioned MPC wallet)
6. Generate machine keypair
7. Compute delegation scope (with optional `DelegationScope::attenuate` for parent attenuation)
8. Register machine identity with 5% commission fee
9. Register with AgentRuntime
10. Activate (lifecycle: Created → Active)
11. Optional Canton party allocation
12. Issue DPoP-bound JWT (if `AuthIssuer` wired)

**This is shipped.** It's a single-shot agent factory, not a workflow primitive. Each new agent in a workflow could be spawned via this kit at workflow-start time.

## The gap

What's missing is a **cross-framework workflow checkpoint** primitive — a way for any of the seven frameworks above to record, at workflow-meaningful points, a verifiable on-chain (or DA-backed) state transition tied to:

1. The orchestrator's DID
2. The participating agents' DIDs
3. Optional payment/escrow state
4. Optional compensation hooks for rollback

The shipped `WorkflowManager` is **close** — it has the state machine, the obligations, the gates, the kill-switch. But it's driven by VM transactions, which means the framework needs to push every state change through a `tenzro_*` RPC. The friction is acceptable for high-stakes workflows (multi-agent payments, multi-step settlement) but too heavy for low-stakes coordination (CrewAI internal step transitions).

## Tenzro adaptation — three-tier checkpoint model

Different workflow surfaces have different durability needs. Proposal: three checkpoint tiers, each with different wire cost.

### Tier 1: Off-chain (framework-internal)

Framework state stays in the framework's own checkpoint store (LangGraph Postgres, CrewAI Redis, etc.). Tenzro is **not involved**. This is the right tier for: LLM call retries, internal step transitions, in-crew message passing.

### Tier 2: A2A-anchored

State transition is published as an A2A task event over the `tenzro/a2a` ALPN (Phase D2, shipped). Recorded by the recipient agent's A2A server but not chain-anchored. This is the right tier for: cross-agent handoff within a single workflow, request-response between unrelated agents.

Already shipped: A2A `tasks/send`, `tasks/get`, `tasks/list`, `tasks/cancel`, SSE streaming for task updates. No new primitive needed — frameworks just need to checkpoint at this layer for cross-party state.

### Tier 3: Chain-anchored (saga semantics)

Multi-step workflow with explicit Execute / Verify / Compensate triad recorded on-chain. This is the right tier for: payment-bearing workflows, multi-party stake-bonded execution, audit-required compliance flows.

Proposed wire primitives:

```
tenzro_workflowOpen(workflow_id, participants[], saga_steps[])
  -> creates WorkflowManager state, records on-chain commitment
tenzro_workflowStepExecute(workflow_id, step_idx, proof)
  -> transition step to Executed, optionally lock escrow per step
tenzro_workflowStepVerify(workflow_id, step_idx, witness_signatures[])
  -> transition step to Verified, release per-step escrow
tenzro_workflowStepCompensate(workflow_id, step_idx, compensation_proof)
  -> trigger inverse action: refund escrow, dispatch compensation tx
tenzro_workflowFinalize(workflow_id)
  -> all steps Verified → workflow Completed; record final receipt
```

Each step has its own escrow allocation and its own compensation handler. A failure at step k triggers compensation for steps {k-1, k-2, ...} in reverse order. The compensation handler is whatever the framework registered at `workflowOpen` — Tenzro doesn't define what compensation means semantically, just that the protocol records the transition.

## Worked example: Magentic-One supplier-research-then-payment

A Magentic-One Orchestrator is asked: "Research the top 3 perovskite cell suppliers, get a quote from each, pay the cheapest, return receipt."

The Orchestrator decomposes this into a DAG:
1. **Research** — WebSurfer agent collects supplier candidates
2. **Quote A** — Get quote from supplier A (parallel)
3. **Quote B** — Get quote from supplier B (parallel)
4. **Quote C** — Get quote from supplier C (parallel)
5. **Select** — Pick cheapest
6. **Pay** — Issue payment to selected supplier
7. **Receipt** — Get receipt back

Tenzro coordination:

```
# Tier 3 chain-anchor at workflow start (payment-bearing → high stakes)
tenzro_workflowOpen(
  workflow_id="wf_abc123",
  participants=[orchestrator_did, supplier_a_did, supplier_b_did, supplier_c_did],
  saga_steps=[
    {"id": "research", "compensation": "none"},
    {"id": "quote_a", "compensation": "none"},
    {"id": "quote_b", "compensation": "none"},
    {"id": "quote_c", "compensation": "none"},
    {"id": "select", "compensation": "none"},
    {"id": "pay", "compensation": "refund_payment"},
    {"id": "receipt", "compensation": "void_receipt"},
  ]
)

# Steps 1-5: Tier 2 (A2A task events) — no on-chain noise
# Magentic Orchestrator uses native A2A tasks/send for handoffs

# Step 6: Tier 3 (escrow-bearing)
tenzro_workflowStepExecute(
  workflow_id="wf_abc123", step_idx=5,
  proof={"intent": "pay supplier_a 30 TNZO"}
)
# -> locks 30 TNZO in escrow
# -> writes ERC-8004 ValidationRequest

# Step 7: Tier 3 (verification with witness)
tenzro_workflowStepVerify(
  workflow_id="wf_abc123", step_idx=6,
  witness_signatures=[supplier_a_signature_over_receipt]
)
# -> releases 30 TNZO from escrow to supplier_a
# -> writes ERC-8004 ReputationFeedback
# -> workflow Completed
```

If step 7 fails (supplier_a never delivers receipt), `tenzro_workflowStepCompensate(workflow_id="wf_abc123", step_idx=5, ...)` fires and refunds the 30 TNZO. The Magentic-One Orchestrator re-plans (per its native ledger pattern) and can re-issue the workflow against a different supplier.

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **P0** | Audit existing `WorkflowManager` semantics vs. proposed `tenzro_workflow*` RPC surface — what's already there, what's new | doc-only |
| **P1** | Add `tenzro_workflowOpen` / `tenzro_workflowStepExecute` / `tenzro_workflowStepVerify` as thin wrappers over `WorkflowManager` | 1 PR |
| **P2** | Add `tenzro_workflowStepCompensate` with explicit per-step compensation handler registry | 1 PR |
| **P3** | Wire escrow per workflow step — each `Execute` can optionally fund a step-scoped escrow, each `Verify` releases it, each `Compensate` refunds | 1 PR, internal to settlement+workflow |
| **P4** | A2A skill `workflow-coordination` exposing the four RPCs on the A2A server | 1 PR |
| **P5** | MCP tool surface for the four primitives (`workflow_open` / `workflow_step_execute` / etc.) | 1 PR |
| **P6** | Reference adapter for one framework (start with AutoGen Magentic-One — closest semantic fit) | external repo |
| **P7** | Reference adapters for the other six frameworks | external, per-framework |

## Out of scope (deliberate)

- **Building a workflow orchestrator.** The frameworks already exist and are excellent. Tenzro is not a runtime, it's a checkpoint substrate.
- **Defining what "compensation" means semantically.** That's framework + application concern. Tenzro records that the transition occurred and what artifact was produced, nothing more.
- **Replacing Temporal.** Temporal is the right answer for many durable execution problems. Tenzro is specifically for the subset where (a) participants are identity-bound, (b) payment or stake is in scope, (c) on-chain audit is required.
- **Defining a DAG execution semantics.** Frameworks already disagree on DAG vs supervisor vs hierarchical vs group-chat. Tenzro exposes a saga-step model that any of them can map onto.
- **Owning the agent address space.** Cross-framework agent identity is the W3C DID + ERC-8004 problem, covered in the agent-interop-protocol-bridge doc.

## Open questions

1. **Witness committee for `workflowStepVerify`.** Single-witness verification (the counterparty signs) is weak. K-of-N witness committee (the Tenzro Train pattern) is stronger but expensive. Where's the right tier-3 default?

2. **Cross-workflow dependencies.** Can workflow A's step 3 depend on workflow B's step 5 being verified? Today no. Adding this introduces graph-of-graphs complexity; probably out of scope for v1.

3. **Long-running workflows.** A workflow spanning days/weeks (e.g., a multi-stage research project) needs different keepalive semantics than one spanning minutes. Should each tier-3 step have an explicit liveness check?

4. **Compensation determinism.** If `Compensate` calls a downstream function that itself fails, what happens? Current proposal: idempotent compensation handlers + finite retry. Needs more thought.

5. **Privacy.** A multi-party workflow may need step contents to be private to subset of participants. Today `WorkflowManager` has `PrivacyDomain` registration but it's narrow. Generalizing to per-step privacy domains is a real ask.

6. **Workflow templates.** Should there be a `tenzro-agent-kit`-style template system for workflows (parameterizable saga step sequences)? Probably yes for the marketplace surface; out of scope for the protocol primitive.

## Mapping to existing standards

| Concept | Tenzro surface | External standard |
|---|---|---|
| Workflow open | `tenzro_workflowOpen` | (none — gap) |
| Step execute | `tenzro_workflowStepExecute` | A2A `tasks/send` (sibling) |
| Step verify | `tenzro_workflowStepVerify` | (none — A2A-SAGA proposal align) |
| Step compensate | `tenzro_workflowStepCompensate` | (A2A-SAGA proposal #1324, Jan 2026) |
| Step escrow | reuses `EscrowManager` | ERC-7683 (chain-discriminated outputs) |
| Participant binding | TDIP DID + DelegationScope | W3C DID + ERC-8004 IdentityRegistry |

## Comparison to existing layers

| Aspect | Temporal | LangGraph + Postgres | Magentic-One ledger | Tenzro proposal |
|---|---|---|---|---|
| Durable execution | yes | partial (checkpoint only) | no (in-memory) | yes (chain-anchored) |
| Compensation | yes (Cadence-style) | via Temporal or none | re-plan only | explicit saga step |
| Cross-party identity | no | no | no | yes (DID + ERC-8004) |
| On-chain audit | no | no | no | yes |
| Payment/escrow | no | no | no | yes |
| Best fit | infra workflows | LLM workflows | exploratory agents | trusted multi-party agent workflows |

The intent is not to replace any of these. Tenzro sits **above the frameworks, below the application**, providing the specific guarantees frameworks can't: identity binding, payment binding, on-chain audit. For the 80% of workflows where none of those matter, Tenzro is correctly invisible.

## Conclusion

The shipped `WorkflowManager` is a strong foundation — it's already a real state machine with obligations, gates, kill-switches, and approvals, persisted and indexed. The work to make it a multi-agent-workflow coordination primitive is mostly **wire** (four new RPCs as thin wrappers) plus **integration** (one framework adapter per release wave, starting with Magentic-One as the closest semantic fit).

The competitive position is **Temporal for trusted multi-agent workflows**: the durable substrate frameworks settle against when the workflow crosses party, payment, or audit boundaries. Frameworks keep their own runtime, their own UX, their own SDK; Tenzro provides the wire format and the on-chain anchor.

## Sources

1. Microsoft Research — Magentic-One: A Generalist Multi-Agent System (arXiv 2411.04468)
2. Microsoft Learn — Magentic Agent Orchestration in Microsoft Agent Framework (2026)
3. AutoGen Magentic-One documentation (microsoft.github.io/autogen)
4. Azure Architecture Center — AI Agent Orchestration Patterns (Microsoft, 2026)
5. SagaLLM: Context Management, Validation, and Transaction Guarantees for Multi-Agent LLM Planning (arXiv 2503.11951, March 2025)
6. A2A-SAGA Proposal — Standardizing Reliability and Compensation for Multi-Agent Workflows (a2aproject/A2A discussion #1324, January 2026)
7. AI Workflow Lab — Building Durable Agent Pipelines with LangGraph and Temporal (2026)
8. Kinde — Orchestrating Multi-Step Agents: Temporal/Dagster/LangGraph Patterns
9. LangGraph v0.4 — supervisor graph, conditional edges, Postgres checkpointing
10. CrewAI — hierarchical + sequential coordination models
11. AutoGen 1.0 GA — Selector Group Chat, GraphFlow, Magentic-One Orchestrator
12. Letta — stateful agent with memory blocks (Postgres)
13. Microsoft Agent Framework — unified Semantic Kernel + AutoGen workflow service (late 2025)
14. Temporal — durable execution for long-running workflows
15. ERC-7683 — Cross-Chain Intents Standard
16. ERC-8004 — Trustless Agents (IdentityRegistry + ReputationRegistry + ValidationRegistry)
17. A2A specification — `tasks/send`, `tasks/get`, SSE streaming (Linux Foundation)
18. W3C DID + W3C VC — agent identity portability (arXiv 2511.02841)
