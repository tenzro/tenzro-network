# AgentBond Surety Primitive

**Status:** Drafting (2026-05-04)
**Phase:** 2 (pairs with Kill-Switch and Principal-Chain)
**Touches:** `tenzro-token` (bond manager + insurance pool), `tenzro-identity` (bond field on identity), `tenzro-payments` (bond consultation), `tenzro-vm` (typed bond txs)

## Context

The kill-switch (Spec 1) gives the network a way to terminate a misbehaving agent and slash its stake. But many autonomous agents won't have *staked* TNZO — they're not validators or providers. They're delegated workers. So slashing has nothing to bite on. Today, terminating such an agent is purely a state change; no economic deterrent, no recovery for harmed counterparties.

Two missing pieces:

1. **A surety primitive.** An autonomous agent posts a bond at registration. The bond is held in a contract, not the agent's hot balance. It can be slashed by Quarantine/Terminate. Below a minimum bond, the agent operates only in the Open lane (Spec 2).

2. **An insurance pool.** Slashed bonds + a fraction of fees flow to an insurance pool that pays out on adjudicated harm. This is what regulators and enterprise integrators are actually asking for: "if your agent damages me, where does my recovery come from?"

This pairs with the kill-switch: Quarantine freezes the bond; Terminate slashes it. It pairs with the principal-chain receipts: bond status is a snapshot field on every receipt.

## Decision

A new primitive — `AgentBond` — backing each autonomous agent identity. Three operations, all typed transactions on the Native VM:

- `PostAgentBond { agent_did, amount }` — locks TNZO from the controller's wallet into the agent's bond.
- `IncreaseAgentBond { agent_did, amount }` — top up.
- `WithdrawAgentBond { agent_did }` — claim back, subject to a cooldown and no active disputes.

Plus a slashing path triggered by Terminate (Spec 1) or by adjudicated dispute outcome.

The slashing pool feeds an `InsurancePool` contract. Insurance payouts are governance-mediated (proposal + vote per claim) for now; an automated claims pipeline is Phase 3.5.

## Architecture

### Bond lifecycle

```
   PostAgentBond  ──▶  Locked
       │                 │
       │   IncreaseAgentBond
       │  (additive)     │
       ▼                 ▼
   ┌─────────────────────────┐
   │  Active                  │  ← steady state
   └────┬───────────────┬─────┘
        │               │
   WithdrawAgentBond    Quarantine (Spec 1)
   (start cooldown)         │
        │                   │
        ▼                   ▼
   Cooldown               Frozen
        │                   │
   timeout                 Terminate
        │                   │
        ▼                   ▼
   Returned             Slashed
```

State stored in CF_AGENTS under `bond:<agent_did>`:

```
AgentBondState {
    agent_did:           String,
    controller_did:      String,
    amount:              u128,            // current bond
    state:               "Active" | "Cooldown" | "Frozen" | "Slashed" | "Returned",
    cooldown_until:      Option<Timestamp>,
    last_modified_block: u64,
    history:             Vec<BondEvent>,
}
```

Cooldown is governance-tunable, default 14 days. During cooldown:
- The bond is still bind-able for slashing (active disputes can drain it).
- The agent operates with `effective_bond = 0` for lane-promotion purposes (per Spec 2).
- After cooldown, withdrawal completes and TNZO returns to the controller's wallet.

`Frozen` is what Quarantine flips the bond to. `Slashed` is the terminal state when Terminate executes.

### Posting

Only the **controller** of an autonomous agent can post a bond on its behalf. The post tx specifies `agent_did` and `amount`; settlement transfers from controller wallet to the AgentBond contract address (deterministic per `agent_did`).

The agent itself cannot post its own bond — bonding is an external commitment by the principal. This matches the legal-surety model (a third party guarantees behavior of the bonded party).

### Lane promotion (interaction with Spec 2)

Per `per-did-flow-control.md`, an agent with bond `≥ bond_min_for_promotion` (governance-tunable, default 1,000 TNZO) can be promoted into the Delegated lane even if its controller isn't KYC'd. This is the substitute for KYC: skin in the game.

Promotion is conditional on:
- `state == Active` (not Cooldown / Frozen / Slashed).
- `amount ≥ bond_min_for_promotion` *currently*. A bond drained below threshold (by a partial slash) immediately demotes the agent.

A higher bond tier (`bond_min_for_verified`, e.g., 50,000 TNZO) can promote into Verified lane *if* the controller is also at KYC Basic. This is for agents whose controllers can't reach KYC Enhanced but want premium throughput.

### Slashing

Two slashing paths:

1. **Terminate-triggered.** `TerminateAgent` (Spec 1) carries `slash_bps`. The kill-switch handler debits `bond × slash_bps / 10000` from the agent's bond and credits the InsurancePool. Remainder, if any, is governance-decision: refund to controller, or also burned, depending on `terminate_remainder_disposition` (default: refund).

2. **Dispute-adjudicated.** A separate dispute proposal goes through governance (or, for fast-tracked disputes, through a slashing committee similar to Quarantine's quorum). The proposal names the agent, the amount, and the harmed counterparty. On passage, the bond is debited and the InsurancePool is credited as the intermediary. Counterparty claims from InsurancePool via a separate mechanism (below).

Slashing is bounded:
- `max_single_slash_bps` (default 5000 = 50%) per single dispute.
- Cumulative slashes that would drive bond below `min_residual` (default 10 TNZO) are capped.
- A bond fully drained → state transitions to `Slashed`, agent immediately demoted to Open lane.

### InsurancePool

```
InsurancePool {
    balance_wei:         u128,
    open_claims:         Vec<ClaimId>,
    paid_claims:         u64,
    total_paid_wei:      u128,
}

ClaimRecord {
    claim_id:            Hash,
    claimant_did:        String,
    against_agent_did:   String,
    amount_requested:    u128,
    receipt_refs:        Vec<ReceiptId>,    // chain-anchored evidence
    status:              "Open" | "Approved" | "Rejected" | "Paid",
    governance_ref:      Option<ProposalId>,
    paid_amount:         Option<u128>,
}
```

Claims are filed via `tenzro_fileInsuranceClaim`; the claimant references existing on-chain receipts as evidence. A governance proposal adjudicates: approved with payout amount, or rejected. Payout debits InsurancePool and credits claimant.

Pool funded from:
- Slashed bonds.
- A governance-tunable percentage of EIP-1559 burn (default 0% — start with bond-only funding to avoid double-charging users).
- Direct treasury contributions per governance proposal.

If the pool is empty and a claim is approved, the claim sits at `Approved` state; payout queues for next refill. The pool's balance is public state.

### Receipt fields

Receipts (Spec 5) snapshot `controller_bond` at receipt write time. Now extended:

- `controller_bond` becomes `actor_bond` — the bond on the *acting* agent (typically autonomous).
- A new `controller_bond_aggregate` sums bonds across all agents under the controller, for the regulator-facing view "how much does this controller have at risk."

### RPC surface

```
tenzro_postAgentBond { agent_did, amount }       // controller-only typed tx
tenzro_increaseAgentBond { agent_did, amount }
tenzro_withdrawAgentBond { agent_did }            // initiates cooldown

tenzro_getAgentBond { agent_did }
    → AgentBondState

tenzro_listAgentBondsByController { controller_did }
    → [AgentBondState]

tenzro_fileInsuranceClaim { against_agent_did, amount, receipt_refs, narrative? }
    → { claim_id, governance_proposal_id }

tenzro_listInsuranceClaims { filter? }
tenzro_getInsuranceClaim { claim_id }
tenzro_getInsurancePoolBalance
```

CLI: `tenzro agent bond post`, `tenzro agent bond withdraw`, `tenzro insurance claim`, `tenzro insurance pool`.

MCP: `post_agent_bond`, `get_agent_bond`, `file_insurance_claim` tools.

A2A: bond status published as a field in agent metadata via Agent Card so peer agents can verify counterparty's posted bond before transacting.

### Determining bond minima

Genesis defaults are conservative:

| Tier | Minimum bond | Lane outcome |
|---|---|---|
| None | 0 | Open lane |
| Basic | 1,000 TNZO | Delegated lane (if controller ≥ KYC Basic) |
| Premium | 50,000 TNZO | Verified lane (if controller ≥ KYC Basic) |

These are pre-mainnet floors — actual values calibrated against TNZO market price post-launch.

### Bond and Kill-switch interaction

| Kill-switch tier | Bond effect |
|---|---|
| Pause | Bond unchanged. Agent loses Delegated/Verified lane (Pause demotes for traffic shaping) — actually no, Pause does NOT demote per Spec 2. Bond is preserved as-is. |
| Quarantine | Bond → Frozen state. Cannot be withdrawn. Eligible for slashing through dispute path. |
| Terminate | Bond slashed per `slash_bps`. Remainder per `terminate_remainder_disposition`. |

Kill-switch triggers and bond state are linked but distinct; a bond can be Active (because no kill-switch action has occurred) on a Paused agent, etc.

### Dispute-without-Terminate

Not every dispute is severe enough for Terminate. A counterparty can file an InsuranceClaim against an `Active` agent — the claim adjudicates separately, and on passage debits the bond *without* terminating the agent. Bond drops; if it drops below `bond_min_for_promotion` the agent is auto-demoted to Open lane; the agent keeps operating.

This is the common path: most agent disputes are economic, not existential. Insurance pays; agent continues.

## Interaction with existing systems

- **`tenzro-token::StakingManager`** is unchanged — bonds are a separate balance class. A validator-staked controller's stake is independent of any bonds it posts on agents.
- **TDIP `IdentityRegistry`** gets a `bond_state` field cached per agent for fast reads, hydrated from CF_AGENTS on restart.
- **Per-DID flow control (Spec 2)** consults bond state for lane promotion.
- **Kill-switch (Spec 1)** is the slashing actuator alongside disputes.
- **Principal-chain receipts (Spec 5)** snapshot bond at receipt-write time.
- **Adaptive burn (Spec 8)**: insurance-pool refills from optional burn-share are governance-tunable and tracked, but default to 0% to avoid masking the supply signal.
- **AP2 mandate validation**: a cart mandate may carry a min-bond requirement on the acting agent. Validator rejects the cart if `actor_bond < cart.min_bond`.

## PQ posture

Bonds are state; bond txs are signed by the controller using hybrid Ed25519 + ML-DSA-65 like every other tx. No new signature surface.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `bond_enabled` | true | Master kill switch |
| `bond_min_for_promotion_delegated` | 1,000 TNZO | |
| `bond_min_for_promotion_verified` | 50,000 TNZO | requires controller KYC Basic+ |
| `bond_cooldown_days` | 14 | |
| `max_single_slash_bps` | 5000 (50%) | per dispute |
| `min_residual_wei` | 10 × 10^18 | floor; below, full Slashed |
| `terminate_remainder_disposition` | "refund_controller" | or "burn" / "treasury" |
| `insurance_burn_share_bps` | 0 | % of EIP-1559 burn redirected to insurance pool |
| `claim_governance_quorum` | simple majority | |
| `claim_proposal_timelock_hours` | 48 | |

## Verification

1. **Post happy path:** controller posts 5,000 TNZO bond on autonomous agent — bond Active, agent eligible for Delegated lane.
2. **Post promotes lane:** before-post agent in Open lane; immediately after post, next tx admitted to Delegated lane.
3. **Withdraw cooldown:** withdraw initiates 14-day Cooldown; agent demotes to Open during cooldown; after cooldown, TNZO returns to controller.
4. **Quarantine freezes bond:** Quarantined agent's bond cannot be withdrawn even if cooldown was started pre-Quarantine.
5. **Terminate slashes correctly:** Terminate with `slash_bps=2500` debits 25% of bond, credits InsurancePool, refunds remainder to controller per default disposition.
6. **Dispute slash without terminate:** approved insurance claim debits bond, agent stays Active but demoted lane.
7. **Insurance payout:** pool has 100k TNZO, claim approved for 50k → claimant receives 50k, pool drops to 50k.
8. **Insurance underfunded:** pool empty, claim approved → claim queued for next refill, claimant sees `Approved` state, eventual payout when funded.
9. **Bond aggregate in receipts:** controller with 3 agents (bonds 1k, 5k, 10k) — receipt's `controller_bond_aggregate == 16k`.

## Out of scope

- **Per-claimant insurance limits.** A given claimant can file unlimited claims; spam is rate-limited via lane mechanics. A repeat-claimant pattern that's clearly abusive becomes a governance issue.
- **Subrogation.** When InsurancePool pays out, it doesn't pursue separate recovery from the agent's controller. The bond was the recovery; what's left isn't worth the legal cost.
- **Cross-chain bond mirrors.** A bond on Tenzro doesn't auto-mirror to ERC-8004 on Ethereum. Reputation-mirroring spec (Phase 3) handles this.
- **Tiered insurance products.** Pool is single-tier. Premium tiers (faster payout, higher caps) are an application-layer offering on top of this primitive.
- **Automated claim adjudication.** Phase 1 and 2 use governance proposals per claim. Phase 3 may add ZK-proof-driven automated adjudication for well-typed disputes (e.g., inference receipt non-delivery).
