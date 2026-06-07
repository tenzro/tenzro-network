# Task Coordination Lifecycle

**Status:** Research / SOTA mapping. Not a shipped spec.
**Last updated:** 2026-06-02

## Why this doc exists

Tenzro Network is becoming a coordination/interoperability layer for agents. The task-marketplace surface (`tenzro_postTask` → `quote` → `assign` → `complete`) is one of the load-bearing primitives in that story: it's where an outside caller (human, agent framework, or another agent) hands a unit of work to "the network" without picking a provider, and where money + reputation + identity get bound to a verifiable outcome.

This doc audits the shipped lifecycle, maps it against what 2026-era agent-economy platforms (Fetch.ai uAgents/ASI Alliance, Olas Pearl + Mech Marketplace, Naptha, Theoriq) actually ship, and identifies the gaps a network-as-coordination-layer needs to close before the surface is usable as a settlement substrate beneath LangGraph / CrewAI / AutoGen / Letta / Google ADK / Microsoft Agent Framework workloads.

This is dev-tree-only research, not a published spec.

## Crucial architectural distinction

Tenzro is **not building a task-marketplace product**. It's building the **wire-level lifecycle** that any task-marketplace product can settle against. The competing platforms above each ship a vertical: their own SDK, their own discovery, their own reputation, their own payment rails. The result is fragmentation — a task posted to Fetch.ai cannot be quoted by an Olas Mech, and neither has a portable reputation record outside its own walls.

Tenzro's job is to make the four primitives chain-anchored, framework-portable, and protocol-neutral: post a task via JSON-RPC / MCP / A2A, get quotes from any agent that speaks the wire format, assign with on-chain escrow, complete with token settlement + ERC-8004 reputation feedback. The agent on the other side can be a Letta agent, a CrewAI crew, an AutoGen GroupChat, or a hand-written Python script — Tenzro doesn't care, because the lifecycle is the contract, not the implementation.

## SOTA reference (what 2026 marketplaces actually do)

| Platform | Discovery | Quoting | Assignment | Settlement | Reputation | Identity |
|---|---|---|---|---|---|---|
| **Fetch.ai uAgents / ASI Alliance** | Almanac contract + agentverse.ai | ChatProtocol + custom protos | direct message | FET token on Fetch L1 | per-protocol scores, off-chain | uAgent address (bech32) |
| **Olas Pearl + Mech Marketplace** | on-chain Mech registry | request payload signed | tx-based delivery | OLAS + xDAI on Gnosis | service-level reputation oracle | ERC-721 service NFT |
| **Naptha** | hub-mediated task pool | bid messages over libp2p | leader-elected | NAPTHA token on Solana | endorsement graph | DID + W3C VC |
| **Theoriq** | swarm registry on Base | task envelope w/ price | swarm-selected | THQ on Base | proof-of-quality oracle | ERC-8004-aligned |
| **A2A native** (no marketplace) | AgentCard discovery | none built-in | direct | none built-in | none built-in | DID in AgentCard |

The pattern across all of them: **discovery + quoting + settlement + reputation are bundled into a single platform**. You cannot quote on Olas a task posted on Fetch.ai. The marketplaces are themselves silos. This is the gap Tenzro should fill — not by building a fifth silo, but by being the lifecycle protocol the others can adopt.

## Shipped surface (audited 2026-06-02)

### RPC handlers (real, end-to-end)

`crates/tenzro-node/src/rpc.rs`:
- `tenzro_postTask` (handle_post_task ~line 20556) — creates `TaskInfo`, persists to `CF_TASKS` under `task:{id}`, status `Posted`. Stores poster DID + reward + skill requirements + deadline.
- `tenzro_quoteTask` (handle_quote_task ~line 20812) — provider submits `{price, model_id, confidence, estimated_duration_secs}`. 5-minute validity. Persisted under `quote:{task_id}:{provider}`.
- `tenzro_assignTask` (handle_assign_task ~line 20889) — poster picks a quote, task transitions to `Assigned`, assignee field populated. **No escrow funded here today** — the reward sits in the poster's wallet, not an on-chain vault.
- `tenzro_completeTask` (handle_complete_task ~line 20966) — assignee submits proof of work, performs `token.transfer(&task.poster, assignee, final_price)`, status → `Completed`, returns settlement with `agent_balance + poster_balance`.

### Storage (persistent)

`CF_TASKS` column family:
- `task:{id}` → `TaskInfo`
- `quote:{task_id}:{provider}` → `TaskQuote`

`CF_SETTLEMENTS` column family:
- `escrow:{id}` → `Escrow` (separate primitive, not yet wired into the task path)

### Identity + delegation (wired)

- Poster authenticated via TDIP (`did:tenzro:human:*` or `did:tenzro:machine:*`)
- Provider DID resolved from quote signature
- `SpendingPolicyResolver` enforces per-agent ceilings on `record_spend` at the runtime layer (defence-in-depth; primary control is on-chain validator modules per `feedback_custody_enforce_at_signing_time`)

### Reputation (partial)

- `erc8004_reputation_dispatcher.rs` fires on **Stripe SPT settlement-outcome webhooks**, not on `tenzro_completeTask`. Maps outcome → score → detached `ReputationRegistry.submitFeedback` via system key.
- **Gap:** task-completion path does not currently trigger ERC-8004 feedback. The signal flows only when settlement comes through the SPT bridge.

### Settlement (mixed)

- `tenzro_completeTask` performs a direct `token.transfer` — **no escrow, no dispute window, no proof verification**.
- `crates/tenzro-settlement/src/escrow.rs` ships a real VM-backed escrow primitive (`CreateEscrow` / `ReleaseEscrow` / `RefundEscrow` typed transactions, derived vault addresses, payer-only release authorization, RocksDB write-through). Currently **unused by the task path**.
- `crates/tenzro-settlement/src/engine.rs` ships proof-verification dispatch (ZK / TEE / crypto / oracle / merkle proof types) and Spec 5 principal-chain receipt indexing. Currently **only invoked for the settlement RPCs, not the task RPCs**.

## Tenzro adaptation — proposed 5-stage lifecycle

The shipped surface already covers Post → Quote → Assign → Complete. The gap is in **what binds quote acceptance to escrow** and **what binds completion to reputation**. Proposal:

```
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│   Post   │───▶│  Quote   │───▶│  Escrow  │───▶│ Execute  │───▶│  Settle  │
│          │    │          │    │  + Bind  │    │          │    │  + Rep   │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │               │
   poster         provider         on-chain        provider       on-chain
   DID +          DID +           vault          executes,        token
   reward         price           locks           submits          transfer
   spec           confidence      reward          proof            + ERC-8004
                                                                   feedback
```

### Stage 1: Post (shipped)

`tenzro_postTask` already does the right thing. One missing field: **`acceptance_criteria` as a structured proof spec** — "must include ZK proof of inference run on model_id X" or "must include TEE attestation from provider class Y". Today it's free-form `description`.

### Stage 2: Quote (shipped)

`tenzro_quoteTask` already does the right thing. Two missing fields:
- **`provider_attestation`** — optional TEE attestation bound to the quote, so the poster can prefer attested providers
- **`provider_reputation_proof`** — optional Merkle proof that the provider has an ERC-8004 reputation above a threshold (avoids the RPC roundtrip to read the registry)

### Stage 3: Escrow + Bind (gap)

On `tenzro_assignTask`, the reward should auto-flow into the existing `EscrowManager` via a `CreateEscrow` typed tx. The escrow's payee is set to the assignee, the release condition is "proof matching `acceptance_criteria` accepted by poster OR oracle", the refund condition is "deadline + grace expired". This is **already implementable** — `EscrowManager::create_escrow` is shipped; the wire is from `handle_assign_task` into the VM tx dispatch.

### Stage 4: Execute (out of band)

This is where the agent framework actually does work. Tenzro does not care **how** — Letta agent, CrewAI crew, AutoGen GroupChat, hand-rolled MCP tool chain, whatever. The interface back to the network is: provider calls `tenzro_completeTask` with a proof envelope.

### Stage 5: Settle + Rep (partial)

`tenzro_completeTask` today does the token transfer but skips:
- **Proof verification** — should route through `SettlementEngine`'s proof-verification dispatch (ZK / TEE / crypto / oracle / merkle)
- **Escrow release** — should call `EscrowManager::release` instead of direct `token.transfer`
- **Reputation dispatch** — should invoke the ERC-8004 dispatcher with `(provider_did, outcome=success_score)` regardless of whether settlement came via SPT or native TNZO

## Worked example: agent procurement bot

A CrewAI procurement crew is asked: "find me a contractor to write a 3-page market analysis on perovskite solar cells, max $50 in TNZO, must complete in 24 hours."

1. **Post.** Crew posts via JSON-RPC `tenzro_postTask`:
   ```json
   {
     "method": "tenzro_postTask",
     "params": {
       "skill_tags": ["market-analysis", "research"],
       "description": "3-page market analysis on perovskite solar cells",
       "acceptance_criteria": {
         "format": "markdown",
         "min_word_count": 1500,
         "required_sections": ["market_size", "competitive_landscape", "outlook"]
       },
       "reward_tnzo": 50.0,
       "deadline_unix": 1717372800
     }
   }
   ```

2. **Quote.** Two providers respond via `tenzro_quoteTask`:
   - Provider A: `{price: 30, confidence: 0.85, estimated_duration_secs: 7200}` — anonymous LLM agent
   - Provider B: `{price: 45, confidence: 0.95, provider_reputation_proof: ..., estimated_duration_secs: 14400}` — ERC-8004-registered agent with rep score 870

3. **Assign + Escrow.** Crew picks B. `tenzro_assignTask` dispatches a `CreateEscrow` tx; 45 TNZO moves from the crew's poster wallet to the escrow vault. Status: `Assigned`. The remaining 5 TNZO stays with the poster.

4. **Execute.** Provider B's agent (could be a Letta+OpenAI agent, doesn't matter) does the research. Off-network.

5. **Settle.** Provider B calls `tenzro_completeTask` with the markdown payload + an attestation that it was generated inside their TEE-bound enclave. The handler:
   - Verifies the TEE attestation via `SettlementEngine` proof dispatch
   - Calls `EscrowManager::release(escrow_id, payee)` → 45 TNZO moves from vault to Provider B's wallet
   - Calls `erc8004_reputation_dispatcher.dispatch(provider_did, outcome=Success(95))` → submits feedback to on-chain `ReputationRegistry`

The crew never picked a specific agent. The network ran the marketplace. The settlement is on-chain. The reputation is on-chain. None of this required Provider B to be on the same agent framework as the crew, or even to be hosted on Tenzro infrastructure.

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **P0** | Wire `EscrowManager` into `handle_assign_task`. Currently `handle_assign_task` flips state but doesn't lock funds. | 1 PR, internal to rpc.rs |
| **P1** | Add `acceptance_criteria` as structured field on `TaskInfo` + matching proof types in `SettlementEngine` dispatch | 1 PR, touches types + engine |
| **P2** | Wire `handle_complete_task` to call `EscrowManager::release` + invoke ERC-8004 reputation dispatcher | 1 PR, internal to rpc.rs |
| **P3** | Add `provider_attestation` + `provider_reputation_proof` optional fields on `TaskQuote` | 1 PR, types + handler |
| **P4** | Dispute resolution path: `tenzro_disputeTask` triggers oracle-arbitrated release/refund. Today there is no dispute window — completion is immediate. | 2 PRs, new RPC + governance hook |
| **P5** | A2A skill `task-marketplace` exposing the lifecycle on the A2A server (already shipped per agent_card.py — verify wiring) | Audit + bind |

## Out of scope (deliberate)

- **Building a task-marketplace product.** The lifecycle is the protocol. Frontend marketplaces (the Tenzro equivalent of agentverse.ai or pearl.olas.network) are downstream consumers, not part of this primitive.
- **Reputation algorithm design.** ERC-8004's `submitFeedback` is the wire; how a downstream platform aggregates feedback into a score is their concern. Tenzro just guarantees the feedback is recorded and queryable on-chain.
- **Auto-matching / auction mechanics.** The poster picks the quote. Auctions, reverse Dutch, sealed-bid — all expressible as wrappers around the four primitives, none of which belong inside the protocol.
- **Off-chain reputation registries.** ERC-8004 is the chosen anchor; alternative reputation graphs (Theoriq's PoQ, Olas's mech-reputation) are downstream consumers that can read ERC-8004 if they choose.

## Open questions

1. **Multi-quote settlement.** Should `tenzro_completeTask` support multiple winners on a single task (e.g., k-of-N redundant execution)? Today it's strictly 1:1. Multi-winner adds a witness-committee pattern similar to Tenzro Train's k-of-N syncer model.

2. **Streaming completion.** For long-running tasks (training runs, large research jobs), does the lifecycle need a `tenzro_progressTask` heartbeat? Today completion is a single shot.

3. **Cross-chain payout.** If the poster has TNZO but the provider wants USDC on Base, who handles the swap? Options: (a) provider does it post-settlement via Li.Fi (probable default), (b) protocol-level route (more complex, higher trust burden).

4. **TEE-bound task execution.** Should `acceptance_criteria` be able to require not just a TEE attestation in the result, but that the **entire computation** ran inside a specific enclave class? This requires a separate primitive — sealed-task-input flow analogous to Tenzro Train's `SealedDatasetManifest`.

5. **Refund-on-deadline semantics.** Who triggers the refund tx after deadline expiry? Today nothing watches. Needs either a daemon (poster-side or network-side) or an on-chain expiry hook.

6. **Quote spam.** No rate-limit, no stake-to-quote requirement. A bad provider can flood `quoteTask` infinitely. Stake-to-quote would mirror Tenzro Train's stake-bonding model.

## Mapping to existing standards

| Concept | Tenzro surface | External standard |
|---|---|---|
| Task envelope | `TaskInfo` | A2A `tasks/send` (sibling, not subordinate) |
| Quote | `TaskQuote` | x402 `PaymentRequirements` (analogous) |
| Escrow | `EscrowManager` | ERC-7683 cross-chain order (chain-discriminated) |
| Reputation feedback | ERC-8004 `submitFeedback` | ERC-8004 |
| Identity | TDIP DID | W3C DID + did:tenzro method |
| Settlement proof | `SettlementEngine` proof types | Plonky3 STARK / TEE attestation |

## Comparison to platforms-not-protocols

| Aspect | Fetch.ai / Olas / Naptha / Theoriq | Tenzro |
|---|---|---|
| Sells | a marketplace | a lifecycle protocol |
| Token | platform-specific | TNZO + cross-chain via existing bridges |
| Reputation | platform-specific oracle | ERC-8004 on-chain registry |
| Identity | platform-specific address | W3C DID (TDIP) |
| Discovery | platform-specific registry | A2A AgentCard + ERC-8004 IdentityRegistry |
| SDK | one per platform | any framework via MCP / A2A / JSON-RPC |
| Cross-platform | no | yes by construction |

## Conclusion

The shipped surface covers four of the five necessary stages (Post, Quote, Assign, Complete) and ships the building blocks for the fifth (Escrow, ReputationDispatcher, SettlementEngine) but does **not yet wire them into the task path**. Closing that gap — five PRs, no new primitives needed — turns `tenzro_*Task` from a state-machine into a settlement substrate that frameworks-as-products can integrate against without giving up their UX, SDK, or token.

The competitive position is not "another marketplace" but **the lifecycle that every marketplace can settle against**, with portable identity and portable reputation as the structural reasons to adopt.

## Sources

1. Microsoft Research — Magentic-One generalist multi-agent system architecture (Nov 2024 + 2026 framework integration)
2. AutoGen Magentic-One documentation (microsoft.github.io/autogen)
3. Fetch.ai uAgents framework + ASI Alliance (Almanac contract, ChatProtocol)
4. Olas — Pearl + Mech Marketplace on Gnosis (ERC-721 service NFTs)
5. Naptha protocol whitepaper — hub-mediated task pools, DID + W3C VC
6. Theoriq AI — swarm registry on Base, proof-of-quality oracle
7. A2A specification — `tasks/send` semantics (Google → Linux Foundation)
8. ERC-7683 — Cross-Chain Intents Standard (chain-discriminated outputs)
9. ERC-8004 — Trustless Agents (IdentityRegistry + ReputationRegistry + ValidationRegistry)
10. x402 — HTTP 402 payment protocol (Coinbase + Cloudflare → Linux Foundation)
11. Linux Foundation A2A Project (agent-card discovery, extensions field)
12. W3C DID Method specification + did:tenzro registration (w3c/did-extensions#705)
13. arXiv 2511.02841 — Agent identity portability via W3C VC
14. MolTrust Protocol on Base L2 (March 2026 deployment, A2A + ERC-8004 hybrid)
15. AgentCard / Agent Governance Toolkit integration patterns (Microsoft, April 2026)
16. Coinbase x402 traffic report (165M total tx, $50M cumulative volume, late April 2026)
