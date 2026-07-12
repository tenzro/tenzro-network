# Tenzro Orchestration

**Self-organizing agent orchestration on Tenzro Network**

---

## Abstract

Tenzro Orchestration is the layer that turns a user's goal into a running,
settling constellation of agents without anyone hand-designing the
constellation. Today the agent marketplace executes *declared* work: a creator
writes an `AgentTemplate` (capabilities, runtime requirements, pricing,
delegation scope, execution steps), registers it on-chain, and the kit
resolves, spawns, and settles it. Orchestration adds the missing half:
templates that are **synthesized** by the system in response to intent,
spawned recursively under budget envelopes, routed by live network signals,
and — when they prove themselves — promoted into the permanent template
registry. Nothing in the execution or settlement path changes; orchestration
is an authoring and selection intelligence layered on primitives the network
already has.

The design principle is that coordination should be *emergent, not
scripted*. Tenzro already contains, in economic form, the mechanisms
biological systems use to coordinate without central planners: decaying
reinforcement (reputation), homeostatic regulation (utilization-driven
pricing, obligation shedding), selection pressure (revenue and settlement
outcomes), and immune response (proof challenges and slashing). Orchestration
consumes these signals instead of inventing a parallel control plane.

---

## 1. What exists, what is added

| Layer | Exists today | Added by orchestration |
|---|---|---|
| Agent shape | `AgentTemplate` JSON spec (`tenzro-agent-kit/src/spec.rs`) | Same shape, synthesized at runtime |
| Discovery | Template/skill/tool marketplaces, provider registry | Capability inventory fed to the planner |
| Execution | `executor.rs` step pipeline with delegation scopes and hard caps | Budget envelopes inherited across spawn depth |
| Placement | `InferenceRouter` strategies (price / latency / reputation) | Trail-weighted routing (§4.1) |
| Economics | Per-execution / per-token / subscription / revenue-share pricing, 5% network commission | Fitness signal for template promotion |
| Safety | Creator DID binding, hard-cap enforcement, dry-run reports | Depth limits, quarantine propagation (§4.4) |

An orchestrated agent is not a new kind of object. It is an `AgentTemplate`
that happens to have been written by a model instead of a person, executed
through the same spawner and executor, paying the same commission, bound to
the same delegation scopes.

## 2. Intent to agent: template synthesis

A user states a goal and a budget. A **planner** — a catalog language model,
run locally when the machine can serve it and through network providers
otherwise, exactly like any other inference call — receives three inputs:

1. **The goal**, verbatim.
2. **The live capability inventory**: registered skills, tools, and agent
   templates from the marketplaces; the node's own hardware readout and
   serving capacity; current effective pricing for inference, compute, and
   storage.
3. **The budget envelope**: a TNZO hard cap, a spawn-depth limit, and a
   delegation scope no wider than the caller's own.

The planner emits one of two things:

- **A resolution**: an existing registered template (or composition of
  templates) already covers the goal. Orchestration reduces to marketplace
  invocation — the cheap, common case, and the reason promotion (§5) matters.
- **A synthesis**: a new `AgentTemplate` — capabilities, execution steps,
  model requirements, tool bindings — tailored to the goal. The template is
  spawned immediately as an ephemeral (unregistered) agent. Its
  `creator_did` is the delegating identity's machine DID, so attribution and
  reputation accrue from the first run.

Synthesis is itself metered inference: the planner's tokens are billed like
any other request, inside the same envelope. There is no free-floating
orchestrator service and no privileged coordinator identity.

## 3. Recursive spawning under envelopes

Agents discover mid-task that they need capabilities they do not have. An
orchestrated agent may respond by synthesizing and spawning a sub-agent,
subject to three inherited constraints, all enforced by the executor's
existing delegation machinery:

- **Budget subdivision.** A child's TNZO cap is carved out of the parent's
  remaining envelope. The sum of live child caps can never exceed the
  parent's remainder; settlement returns unspent balance up the tree.
- **Depth limit.** Each spawn decrements an integer inherited from the root
  envelope. At zero, the agent must execute or fail — it cannot delegate.
- **Scope narrowing.** A child's delegation scope is the intersection of the
  parent's scope and what the child's task requires. Scopes widen never,
  narrow always.

This converts a static execution graph into a dynamic tree whose shape is
decided by the work actually encountered, while keeping the worst case —
runaway self-replication — economically impossible: the tree's total spend is
bounded by the root envelope regardless of its shape.

## 4. Emergent coordination signals

Orchestration makes no placement or retry decisions of its own. It reads
four network signals, each of which the protocol already produces.

### 4.1 Trails (stigmergy)

Provider reputation is settlement-derived (+1 on settled success, −5 on
settled failure). Orchestration extends this into **trails**: per-route
weights (requester → provider, for a model family or skill) that reinforce
on settled success and decay with time. The router's reputation strategy
consumes trail weight instead of raw score. The effect is ant-colony path
selection: heavily used, recently successful routes attract traffic; unused
routes evaporate back to neutral rather than persisting stale advantage.
Trails are gossip-carried like status, never consensus state — they are a
heuristic, and losing them costs nothing but warm-up.

### 4.2 Homeostasis

Resource pricing is already a proportional controller over EMA-smoothed
utilization. Orchestrated placement treats the live price *as* the
congestion signal: when a provider's effective price rises, the planner's
cost model steers new spawns elsewhere without any explicit load-balancer.
Similarly, the coverage tracker's obligation-shedding (roles shed when stake
cannot cover them) is respected as-is — an orchestrated agent whose provider
sheds the relevant role is rescheduled through the normal retry path.

### 4.3 Selection

Every template — registered or ephemeral — accumulates `invocation_count`,
`total_revenue`, settlement success ratio, and cost-per-success. These are
the fitness function for promotion (§5). Fitness is computed only from
*settled* outcomes, inheriting the network's existing resistance to
self-reported success.

### 4.4 Immune response

Proof challenges and slashing already police providers. Orchestration adds
the same posture toward synthesized agents: a template whose executions
repeatedly fail settlement, breach caps (attempted, blocked, and reported by
the executor), or trigger delegation violations is **quarantined** — its
template hash is gossiped with a rejection marker, and planners exclude it
from resolution and from few-shot synthesis context. Quarantine is
reversible by explicit creator action, not by decay; misbehavior is
remembered longer than success.

## 5. Promotion: the system grows its own library

An ephemeral template that clears a fitness bar — N settled successes,
bounded cost variance, no quarantine events — is offered back to its
originating identity for **promotion**: one-step registration into the
on-chain template registry, optionally priced for the marketplace. The
creator share of future invocations flows to the promoting identity's
wallet; the network takes its standard commission.

Promotion closes the loop that makes synthesis cheap over time: the planner
resolves against an ever-richer library of proven templates and synthesizes
only genuinely novel work. Variation arrives for free — planners synthesize
slightly different templates for similar goals, fitness selects among them,
and the registry keeps the winners. This is an evolutionary process in the
strict sense (variation, selection, heredity) without any component labeled
"evolution."

## 6. What the user sees

- **One input**: a goal and a budget. No graph editor, no agent
  configuration, no model selection.
- **A live tree**: which agents exist, where each is running (this machine /
  LAN / network provider), what each has spent, all derived from the
  settlement trail.
- **One guarantee**: total spend ≤ envelope, enforced by the executor's hard
  caps, not by planner good behavior.
- **A growing library**: agents that worked become one-click (or
  marketplace-sellable) templates.

## 7. Non-goals

- **No privileged orchestrator role.** Planning is inference; any capable
  node can do it. There is no coordinator to stake for, attack, or trust.
- **No new consensus state.** Trails and quarantine markers are gossip;
  envelopes and settlement are existing paths; templates use the existing
  registry. The chain learns nothing new.
- **No autonomous spending beyond the envelope.** Synthesis cannot mint
  authority: every capability an orchestrated agent holds was explicitly
  delegated, narrowed, and capped by a chain of custody rooted in a human or
  machine identity that paid for it.
