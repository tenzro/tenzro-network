# Agent Kill-Switch: Pause / Quarantine / Terminate

**Status:** Drafting (2026-05-04)
**Phase:** 1 (regulatory deadline 2026-08-02)
**Touches:** `tenzro-identity`, `tenzro-token` (staking + slashing), `tenzro-agent`, `tenzro-vm` (precompile), `tenzro-node` (RPC + receipt schema)

## Context

EU AI Act high-risk obligations apply from 2026-08-02. Among them: a credible "human-in-the-loop can intervene on a misbehaving AI system" capability, with audit trail. Today an agent's only off-switch on Tenzro is its controller calling `revoke_did` — a single, irreversible, all-or-nothing action with no graduated response and no network-side intervention path. That is too coarse for:

- A controller who wants to *pause* an agent for inspection without destroying its state.
- A network that has flagged an agent as misbehaving (e.g., consensus-detected fraud, repeated dispute losses) but the controller is unreachable.
- A regulator or governance body that needs to wind an agent down in stages, with each stage on-chain and verifiable.

There's no graduated, multi-authority, auditable intervention surface. This spec adds it.

## Decision

Three typed transactions, each producing a typed receipt, each tied to a specific authorization graph. They escalate; they do not replace `revoke_did`, they sit beneath it.

| Tier | Reversible | Authorized by | Effect |
|---|---|---|---|
| **Pause** | Yes | Controller only | Agent stops accepting new tasks; existing obligations honored. Stake untouched. |
| **Quarantine** | Yes (with evidence review) | Controller **or** slashing-committee quorum | Inbound + outbound payments blocked. Stake frozen (cannot withdraw, cannot earn rewards). Existing tasks halted. |
| **Terminate** | No | Controller **or** governance vote | Identity revoked. Stake slashed (% governance-tunable). Downstream agents under it cascade-revoked. |

The existing `revoke_did` becomes the underlying primitive that **Terminate** invokes — not a separate path.

## Architecture

### Transaction types

Three new typed transactions in the Native VM, each routed through `tenzro_signAndSendTransaction`:

```
PauseAgent {
    agent_did:        String,
    reason_code:      u16,        // canonical enum, see §"Reason codes"
    reason_text:      Option<String>,  // ≤ 256 bytes
    until:            Option<Timestamp>,  // None = indefinite
}

QuarantineAgent {
    agent_did:        String,
    reason_code:      u16,
    reason_text:      Option<String>,
    evidence_hash:    Option<Hash>,  // commitment to off-chain evidence
}

TerminateAgent {
    agent_did:        String,
    reason_code:      u16,
    slash_bps:        u16,         // basis points of stake to slash, capped per governance
    cascade:          bool,        // also terminate child agents under this DID
}
```

Each gets a precompile selector at `0x101d`/`0x101e`/`0x101f` (next free slots after the ERC-8004 trio at `0x101a`–`0x101c`). Gas: 60k / 90k / 120k respectively — Quarantine is more expensive because it touches stake state, Terminate cascades.

### Authorization graph

```
PauseAgent
    └── controller_did MUST equal Tx.from
        OR controller_did has DelegationScope.allowed_operations ⊇ ["pause_agent"]

QuarantineAgent
    └── controller_did MUST equal Tx.from
        OR slashing committee quorum (≥ 2/3 of bonded validators) signed
            via existing EquivocationDetector → SlashingCallback path
        OR governance proposal Quorum executed

TerminateAgent
    └── controller_did MUST equal Tx.from
        OR governance proposal (timelock ≥ 48h, supermajority ≥ 2/3) executed
        OR cascade=true from a parent's Terminate (recursive, evaluated by VM)
```

Network-initiated quarantine reuses the slashing pipeline (`StakingSlashingCallback` in tenzro-node) — same evidence model, same quorum.

### State machine

Lifecycle states extend the existing `tenzro-agent::lifecycle::AgentLifecycleInfo`:

```
Active → Paused → Active                       (controller resumes)
Active → Quarantined → Active                  (after evidence review, controller or quorum)
Active → Quarantined → Terminated              (committee escalates)
Active → Terminated                            (direct, never reversed)
{Paused,Quarantined} → Terminated              (escalation path)
```

Transitions are write-through to RocksDB CF_AGENTS under the existing `lifecycle:<id>` key. Hydration on restart restores the exact state — no agent silently un-quarantines because the node bounced.

### Effects per state

| Effect | Active | Paused | Quarantined | Terminated |
|---|---|---|---|---|
| Accept new tasks | Yes | No | No | No |
| Honor open obligations | Yes | Yes | No (frozen) | No (canceled, refunds via escrow refund path) |
| Stake earns rewards | Yes | Yes | No | No (slashed) |
| Stake withdrawable | Per unbonding | Per unbonding | No | Slashed remainder per unbonding |
| Inbound payments | Yes | Yes | No | No |
| Outbound payments | Yes | No | No | No |
| Identity resolves | Yes | Yes | Yes (with flag) | No (revoked) |
| Children agents | Active | Unaffected | Unaffected | Cascade-terminated if `cascade=true` |

Enforcement points:
- **`tenzro-agent::lifecycle`** gates "accept new task" and child registration.
- **`tenzro-payments::IdentityPaymentBinder`** consults lifecycle state in addition to DelegationScope and SpendingPolicy. A Quarantined or Terminated payer fails closed.
- **`tenzro-token::StakingManager`** reads lifecycle state on `unstake` / reward distribution.
- **`tenzro-identity::IdentityRegistry::resolve_did`** returns the lifecycle flag in the DID Document `metadata.status` field.

### Cascade semantics

A `TerminateAgent { cascade: true }` traverses the existing `children:<parent_id>` index in CF_AGENTS, BFS-style, terminating every descendant. Cascade depth is bounded at 32 (governance-tunable) — anything deeper is a misconfiguration and aborts the whole tx.

Cascade Terminate produces **one parent receipt + one child receipt per descendant**, each linked by `parent_termination_id`. Regulators get a tree they can verify.

### Receipts

Every kill-switch tx emits a typed receipt log entry parallel to the `principal-chain receipts` spec:

```
KillSwitchReceipt {
    receipt_id:        Hash,
    tier:              "pause" | "quarantine" | "terminate",
    agent_did:         String,
    controller_did:    String,
    authorized_by:     "controller" | "committee" | "governance" | "cascade",
    auth_ref:          Option<Hash>,    // proposal_id, slashing evidence_id, parent_receipt_id
    reason_code:       u16,
    reason_text:       Option<String>,
    evidence_hash:     Option<Hash>,
    state_before:      LifecycleState,
    state_after:       LifecycleState,
    stake_slashed:     Option<u128>,
    timestamp:         Timestamp,
}
```

Indexed under CF_SETTLEMENTS prefixes:
- `killswitch:<receipt_id>` — primary
- `killswitch_agent:<agent_did>:<timestamp>` — chronological by agent
- `killswitch_controller:<controller_did>:<timestamp>` — chronological by controller (enables EU AI Act controller-side audit queries)

### Reason codes

Canonical `u16` enum, governance-tunable but additive-only (codes never repurposed):

| Range | Meaning | Examples |
|---|---|---|
| 0–99 | Controller-initiated | `1` user-requested pause, `2` maintenance, `3` software update |
| 100–199 | Network-detected misbehavior | `100` equivocation, `101` repeated dispute loss, `102` policy violation, `103` payment fraud |
| 200–299 | Regulatory | `200` GDPR data subject request, `201` EU AI Act intervention, `202` sanctions match |
| 300–399 | Operational | `300` controller wallet compromise (preemptive), `301` insufficient bond |
| 1000+  | Reserved for future tiers (e.g., per-jurisdiction codes) |  |

`reason_text` carries human detail, capped at 256 bytes to avoid abuse as a payload channel.

### RPC surface

Three write RPCs (typed-tx wrappers) and three read RPCs:

```
tenzro_pauseAgent           // controller-only, signs PauseAgent
tenzro_quarantineAgent      // controller-only, signs QuarantineAgent
tenzro_terminateAgent       // controller-only, signs TerminateAgent

tenzro_getAgentLifecycle    // returns current state + transition history
tenzro_listKillSwitchByAgent
tenzro_listKillSwitchByController
```

Network-initiated (committee/governance) paths do not get write RPCs — they originate inside the slashing callback or governance executor and submit via the privileged-VM dispatch path that already exists for `CreateEscrow`/`ReleaseEscrow`.

CLI: `tenzro agent pause <did>`, `tenzro agent quarantine <did>`, `tenzro agent terminate <did> [--cascade]`.

MCP: `pause_agent`, `quarantine_agent`, `terminate_agent` tools (same param shape as RPCs, controller-side only — committee/governance flows are not human-facing).

A2A: lifecycle skill exposed via Agent Card so peer agents can verify a counterparty's state before dealing.

### Pause-bypass for unstoppable obligations

A Paused agent may still need to honor an obligation it created pre-pause (e.g., complete a paid inference, refund an escrow). The lifecycle gate has a single bypass: outbound transactions whose `from` matches the agent and whose `tx_type` is in a governance-controlled allow-list — `RefundEscrow`, `ReleaseEscrow` to a pre-existing payee, and `complete_task` for tasks already assigned. Anything else fails. This is *not* a loophole because Quarantine has no bypass at all — it's there so Pause stays a soft state, encouraging controllers to use it for inspection rather than going straight to Quarantine.

## Interaction with existing systems

- **TDIP DelegationScope** continues to be the structural ceiling. `allowed_operations` may include `["pause_agent", "quarantine_agent", "terminate_agent"]` to let a delegated identity invoke the kill-switch on the controller's behalf.
- **`revoke_did`** is no longer the user-facing intervention path; it remains as the underlying primitive that `TerminateAgent` triggers.
- **`StakingSlashingCallback`** (today only consensus equivocation) gains a second invocation site: committee-initiated Quarantine that escalates to Terminate.
- **`AgentBond`** (Spec 9) is the natural slashing target for non-stake-holding agents. When AgentBond ships, `slash_bps` applies to bond, not stake, for agents without bonded stake.

## PQ posture

Kill-switch txs are signed under the same hybrid Ed25519 + ML-DSA-65 envelope as every other tx. Receipts are committed to the chain state Merkle root, so a future PQ-only verifier reading from a state proof gets the same guarantees.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `pause_max_duration` | 30 days | If `until` exceeds, tx rejected |
| `quarantine_committee_quorum` | 2/3 of bonded validators | Same as slashing |
| `terminate_governance_quorum` | 2/3 supermajority | Higher than ordinary proposals |
| `terminate_governance_timelock` | 48h | Lets controller contest |
| `cascade_max_depth` | 32 | Sanity cap |
| `slash_bps_cap` | 10000 (100%) | Per-tx cap, governance can lower |

## Verification

1. Controller-initiated Pause → Resume round-trip preserves all stake/balance state.
2. Committee Quarantine on a malicious agent freezes outbound payments within one block.
3. Governance Terminate with cascade produces one parent + N child receipts, all linked, all written to CF_SETTLEMENTS.
4. A Paused agent can `release_escrow` to a pre-existing payee; cannot `send_transaction` to a new address.
5. A Quarantined agent cannot do *any* outbound, including release_escrow.
6. Restart-after-Quarantine: node restarts, agent state hydrates as Quarantined, payment binder still rejects.
7. EU AI Act audit query: `tenzro_listKillSwitchByController(controller_did)` returns full history with reason codes and timestamps.

## Out of scope

- **Per-jurisdiction overlays.** Different regulators may want different reason-code namespaces; that's a Phase 3 concern handled by the reserved 1000+ range.
- **Insurance payouts on Terminate.** Slashed stake/bond flowing to harmed counterparties is the AgentBond spec's job (Spec 9).
- **Cross-chain kill-switch propagation.** If an agent has identity mirrored via ERC-8004 on Ethereum, Terminate-on-Tenzro doesn't auto-revoke the mirror. LayerZero V2 governance message propagation is a Phase 3 add-on.
