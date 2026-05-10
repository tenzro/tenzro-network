# SeedAgent Treasury Allocation

**Status:** Drafting (2026-05-04)
**Phase:** 3 (mainnet bootstrap)
**Touches:** `tenzro-token` (treasury earmark), `tenzro-agent` (registration), `tenzro-agent-kit` (templates), `tenzro-identity` (provisioning), `tenzro-node` (governance executor + reporting)

## Context

The cold-start problem for an agent-economy chain:

- Validators need provider income (gas + commissions) to break even on infrastructure spend.
- Providers (model + TEE) need agent customers to justify going online.
- Agent developers need providers and template marketplaces with depth.
- Template marketplaces need spawned-agent volume to validate template quality.
- Spawned agents need economic activity to justify their bonds.

Every node in this graph waits for every other node. Without an external prime mover, the chain runs at infrastructure-loss for many epochs while users trickle in. Faking volume (wash trading, fake providers) corrupts the signals every other system relies on.

The principled answer: the **protocol itself runs agents** for the first 12 months. Treasury earmarks a slice for `SeedAgents` — protocol-owned autonomous agents that exercise the full stack: register identity, post bonds, run inference jobs against real providers, settle in TNZO, file 7683 intents, transact across VMs, occasionally lose disputes (so the dispute pipeline gets exercised). Their economic activity is real, paid for from a pre-allocated treasury slice rather than user demand.

Three things this *isn't*:

- **It isn't fake volume.** SeedAgents pay real fees, real providers earn real income, real burns occur. The burn signal is honest.
- **It isn't a subsidy.** Treasury is not paying providers above market — SeedAgents pay market rate, which providers earn legitimately.
- **It isn't permanent.** Allocation has a hard sunset. After the bootstrap window, SeedAgents are wound down; the network either has organic volume or it doesn't.

## Decision

A genesis-allocated treasury slice (governance-decided %, suggested 2-5% of treasury) is dedicated to running protocol-owned autonomous agents during the first 12 mainnet months. SeedAgents:

- Are registered like any other autonomous agent (TDIP machine identity, MPC wallet, posted bond).
- Are funded from the SeedAgent allocation; their wallets receive periodic top-ups during the bootstrap window.
- Operate within published, on-chain mandates (not arbitrary discretion).
- Wind down to zero by month 12 per a governance-approved decay schedule.
- Their activity is publicly tagged in receipts (`is_seed_agent: true`) so the network's organic-volume metrics can subtract them cleanly.

After month 12, surplus from the SeedAgent allocation returns to general treasury or is burned per governance choice.

## Architecture

### Allocation structure

```
TreasuryEarmark {
    name:                     "SeedAgent",
    initial_allocation_wei:   X,                     // governance-decided at genesis (1 TNZO = 10^18 wei)
    allocation_remaining:     u128,
    bootstrap_start:          Timestamp,
    bootstrap_end:            Timestamp,             // typically +12 months
    decay_schedule:           Vec<DecayPoint>,        // monthly draw caps
    seed_agent_count:         u32,
    activity_charters:        Vec<CharterId>,
}

DecayPoint {
    month:           u8,           // 0..12
    max_draw_wei:    u128,         // upper bound on SeedAgent funding this month (wei)
}
```

A reasonable decay shape: 100% allocation drawable in months 1-3, 75% in months 4-6, 50% in months 7-9, 25% in months 10-12, 0% thereafter. Total draws across the year ≤ 80% of allocation; remainder either keeps allocation alive past month 12 (governance vote) or returns to treasury.

### Charters: the on-chain mandate for what SeedAgents do

A `SeedAgent Charter` is a signed-by-governance specification of what an agent class does:

```
Charter {
    charter_id:           Hash,
    name:                 String,
    purpose:              String,                 // human-readable
    operations:           Vec<OperationKind>,     // enumerated
    spend_caps:           SpendCaps,
    target_throughput:    Option<TargetThroughput>,
    counterparty_filter:  CounterpartyFilter,
    sunset:               Timestamp,
}

OperationKind ∈ {
    InferenceConsumer,        // pay real providers for real inferences
    TaskMarketplaceConsumer,  // post tasks, accept solutions
    TemplateInstantiator,     // spawn child agents from templates, exercise spawn flow
    BridgeUser,                // exercise LZ/Wormhole/CCT/deBridge by sending small amounts cross-chain
    SettlementProbe,           // open and resolve micropayment channels
    Settler7683Probe,          // open 7683 intents to be filled by external solvers
    DisputeFiler,              // intentionally enter losing positions to exercise dispute pipeline (small amounts)
}
```

Six initial charters at genesis (governance-tunable, additive):

| Charter | Operation | Purpose |
|---|---|---|
| C1: InferenceLoad | InferenceConsumer | Steady ~10 inferences/min across registered models |
| C2: BridgeProbe | BridgeUser | Quarterly small TNZO transfers across each bridge |
| C3: ChannelExerciser | SettlementProbe | Open/close 1-2 channels/day with random providers |
| C4: TemplateExerciser | TemplateInstantiator | Spawn 5 template instances/day, run for an hour, terminate |
| C5: IntentRoundtripper | Settler7683Probe | Open small intents, accept solver fills |
| C6: DisputeMicrocosm | DisputeFiler | Occasional intentional small losses (≤ 1 TNZO) to exercise insurance/Quarantine paths |

Each charter is constrained:
- **Counterparty filter.** SeedAgents must transact with the open market — they cannot route to other SeedAgents (would be wash). Filter explicitly denies `is_seed_agent` counterparties.
- **Spend caps.** Each charter has a daily cap; cumulative monthly cap; per-tx cap.
- **No principal-chain manipulation.** SeedAgent's `controller_did` is a well-known governance-controlled identity (e.g., `did:tenzro:org:treasury:seedagents`). All receipts attribute to that controller. No hiding behind delegation chains.

### Operating model

A small operator daemon (off-chain or as a node-collocated service) reads charters from chain state, instantiates agents per charter, and runs their loop. Each SeedAgent:

1. Registers TDIP machine identity (one-time at activation).
2. Posts AgentBond from SeedAgent allocation (typically minimum bond — these aren't VIP agents).
3. Operates per its charter, drawing from a per-agent funded wallet refilled by the daemon up to per-month caps.
4. Has a kill-switch authority: governance can `Pause`/`Quarantine`/`Terminate` any SeedAgent without proposal — they're protocol-owned.

The daemon code lives outside the consensus binary (in `tools/seed-agents/` or similar). It runs on operator-controlled infrastructure — typically the protocol team's own validator nodes during bootstrap. After bootstrap, the daemon is decommissioned; its agents are Terminated.

### Public visibility

`is_seed_agent` is a flag on TDIP identity records. Set by the controller at registration time (i.e., at SeedAgent provisioning) and immutable after. Visible in:

- `IdentityRegistry::resolve` output.
- All receipts (Spec 5 PrincipalChain link includes the flag).
- Block explorer / status pages.

Network-wide metrics carry an `excluding_seed_agents` cut alongside the all-inclusive cut. Anyone analyzing organic adoption can see real-vs-bootstrap clearly.

### RPC surface

```
tenzro_listSeedAgents
    → [{ agent_did, charter_id, status, allocation_used_wei, last_active }]

tenzro_getSeedAgentCharter { charter_id }
    → Charter

tenzro_listSeedAgentCharters
    → [Charter]

tenzro_getTreasuryEarmark { name }
    → TreasuryEarmark    // for "SeedAgent" returns the structure above

tenzro_getNetworkActivity { window?, exclude_seed: bool }
    → activity metrics with/without SeedAgent contribution
```

CLI: `tenzro seedagents list`, `tenzro seedagents charter <id>`, `tenzro treasury earmark SeedAgent`.

MCP: read-only tools for transparency; no write tools (governance-only writes).

Governance proposals can:
- Add a charter.
- Modify a charter (caps, counterparty filter, sunset).
- Terminate a charter early.
- Extend the bootstrap_end (with supermajority).
- Burn or return surplus at month 12.

### Sunset and wind-down

At `bootstrap_end`:

1. Charter sunsets are enforced; no new SeedAgent activity occurs under expired charters.
2. Active SeedAgents complete their open positions (channels close, escrows release/refund).
3. Bonds are withdrawn through normal cooldown.
4. Once an agent's wallet is empty, the agent is Terminated.
5. Allocation surplus is reported; governance proposal decides: extend, return, or burn. Default action absent a governance vote: burn 50% / return 50% to general treasury.

A "snap to zero" failure mode is avoided by the decay schedule — SeedAgents don't go from full operations one month to dead the next.

### What SeedAgents should *not* do

- **Originate revenue for treasury.** They consume; they don't earn. Any unexpected revenue (e.g., a SeedAgent winning a task auction it posted) returns to treasury directly.
- **Vote in governance.** SeedAgent identities are explicitly disenfranchised — controller votes, agents do not.
- **Hold any token other than TNZO.** Bridge probes use TNZO for accounting; foreign tokens received in test trades are sold back to TNZO at next epoch.
- **Operate after sunset under any condition.** Hard end-of-life.

### Operational accountability

The SeedAgent daemon is a treasury-funded operation, not a community pool. Governance:
- Reviews charter performance quarterly.
- Receives a public report: `seedagent_q1_report.md` etc., noting what charters did, allocation used, observed network impact.
- Can early-terminate any charter that is failing its purpose (e.g., InferenceLoad charter failing to drive inference revenue → cut).

## Interaction with existing systems

- **TDIP `IdentityRegistry`** gains the immutable `is_seed_agent` flag at registration.
- **AgentBond (Spec 9)** — SeedAgents post minimum bonds to participate in lanes.
- **Per-DID flow control (Spec 2)** — the SeedAgent controller (one identity, many child agents) is a Verified-lane controller (KYC at the protocol level, large bond aggregate).
- **Kill-switch (Spec 1)** — governance kill-switch authority over SeedAgents is direct (proposal+timelock), no committee path.
- **Adaptive burn governance (Spec 8)** — SeedAgent activity contributes to UsageTracker. The `excluding_seed_agents` cut is what governance should look at when assessing organic burn for adaptive-burn decisions; the inclusive cut is the actual chain-state delta.
- **Principal-chain receipts (Spec 5)** — receipts attribute to the SeedAgent controller; the chain shows the operation reached real providers.
- **7683 settler (Spec 4)** — SeedAgents per IntentRoundtripper charter open small 7683 intents, drawing solver attention to Tenzro's 7683 surface from day 1.

## PQ posture

SeedAgents use the same hybrid Ed25519 + ML-DSA-65 signing as any other identity. Daemon stores keys in HSM/MPC like any institutional operator. No new PQ surface.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `enabled` | true | Master kill switch |
| `allocation_pct_of_treasury` | 2-5% | governance-decided at genesis |
| `bootstrap_months` | 12 | Hard sunset |
| `decay_schedule` | (table above) | per-month max-draw caps |
| `charter_set` | C1..C6 | Initial; additive via proposal |
| `surplus_disposition` | "burn50_return50" | Action at sunset absent vote |
| `early_terminate_quorum` | simple majority | |
| `extend_quorum` | 2/3 supermajority | |

## Verification

1. **Charter publication:** all initial charters present in chain state, queryable via `listSeedAgentCharters`.
2. **Counterparty filter:** SeedAgent A attempts payment to SeedAgent B — rejected at admission per filter.
3. **Spend cap:** SeedAgent's monthly draw exceeds cap — daemon refuses next refill, agent rate-limited.
4. **Decay enforcement:** at month 5, daemon attempts to top up at month-3 rate — chain rejects, max_draw is the month-5 cap.
5. **Public visibility:** SeedAgent receipt's `is_seed_agent: true` visible in explorer query.
6. **Excluding-seed metric:** `getNetworkActivity {exclude_seed: true}` returns smaller numbers than inclusive query, by exactly the SeedAgent contribution.
7. **Sunset:** at bootstrap_end + 1 day, no new SeedAgent operations admitted; existing positions wind down per ordinary lifecycle.
8. **Governance kill:** proposal to early-terminate charter C6 — passes — all C6 SeedAgents Quarantine within next epoch, then Terminate.

## Out of scope

- **Multi-sig committee for daemon ops.** The daemon's signer is a single controlling identity; if compromised, governance can revoke and re-issue. Operationally treated as treasury-grade hot infrastructure.
- **Adversarial SeedAgent design** (testing the kill-switch, etc.). Charter C6 (DisputeFiler) does *bounded* adversarial action by design. A separate "red team SeedAgent" charter could be added later if specific attack surfaces need exercise.
- **Cross-chain SeedAgents.** SeedAgents are Tenzro-native; foreign-chain analogs (e.g., a SeedAgent that operates as a 7683 solver on Base, paid in foreign chain native gas) are out. Bootstrap activity stays Tenzro-internal apart from the BridgeProbe charter.
- **Allocation refresh post-sunset.** If, at month 12, organic activity is insufficient and governance wants more bootstrap, that's a new genesis-style allocation proposal — not an extension of this one. This spec is one-shot.
