# Settlement Infrastructure for the Agent Economy

**Accountability, Throughput, and Liability in M2M-Dominated Networks**

**Hilal Agil**
*Founder, Tenzro*
hilal@tenzro.com

---

**Abstract.** By mid-2026, autonomous AI agents originate between 19% and 30% of on-chain transaction volume across major networks, and 22% of production AI deployments coordinate two or more agents. The settlement infrastructure underneath this traffic was designed for human-rate, human-accountable activity. It does not compose well with machine-rate, machine-mediated activity: mempools admit traffic without per-principal accounting, fee markets price contention globally rather than locally, regulatory frameworks anticipate a human-in-the-loop the chain cannot cryptographically locate, and the gas-token sink that backs network economics assumes a transaction profile machines do not produce. The European Union AI Act's high-risk obligations apply from 2 August 2026 and require a credible human-intervention surface that today's settlement primitives do not provide. We describe ten compositional primitives — kill-switch lifecycle states, per-DID admission control, dual-rail gas with a treasury-backed burn quota, an ERC-7683 settler interface, principal-chain receipts, hot-state local fees, data-availability offload, adaptive burn governance, surety bonds with a protocol insurance pool, and treasury-funded protocol-owned agents during bootstrap — that together form a settlement layer for agent-dominated traffic without abandoning the assumptions on which existing chains were built. We discuss the design of each, their interactions, and their grounding in regulation, recent academic literature, and production deployments through Q1 2026. The complete specifications are open and implemented in the Tenzro Network reference codebase.

---

## 1. Introduction

The premise of this paper is that the existing layer-1 and layer-2 settlement architectures are robust against the failure modes they were designed for and brittle against the failure modes that a swarm of autonomous agents introduces. The brittleness is not a defect — it is the expected behavior of a system pricing a different equilibrium. The remedy is not to replace these architectures but to compose new primitives onto them in places where the agent-economy assumption diverges from the human-economy assumption. This paper describes ten such primitives.

The concrete pressure comes from three independent sources. First, **agent volume.** Public dashboards across Solana, Base, and Arbitrum show automated and agent-mediated activity now contributing a fifth to a third of daily transaction count, with the share rising. Second, **regulatory deadlines.** The EU AI Act's high-risk system obligations under Article 14 (human oversight) and Article 25 (provider responsibility) apply from 2 August 2026. The framework anticipates a chain of human accountability that today's on-chain receipts do not record. Third, **competitive pressure on tokenomics.** Tempo's enterprise pitch — fees paid in stablecoins, no native-token tax — is the right product answer for finance teams and the wrong protocol answer for native-token-backed networks unless the native token's sink is preserved by another mechanism. None of these pressures is hypothetical; each is dated, sourced, and quantifiable in 2026.

The paper proceeds as follows. §2 frames the agent economy and the four classes of brittleness — scalability, tokenomics, liability, bootstrap — that compositional primitives need to address. §3 surveys the regulatory landscape that bounds the design space. §4 surveys the technical landscape: prior work in cross-chain intents, local fee markets, parallel execution, and on-chain identity. §5 introduces the ten primitives and their interaction graph. §6 discusses tokenomics under M2M dominance specifically. §7 discusses regulatory alignment specifically. §8 discusses bootstrap economics. §9 sketches a verification plan. §10 concludes.

The Tenzro Network reference codebase implements every primitive described here under the Apache-2.0 license. Specifications are at `docs/architecture/agent-swarm/` in the repository.

## 2. The Agent Economy and Its Failure Modes

### 2.1. Volume signal

By Q1 2026, the share of on-chain transactions originated by automated systems — solver bots, market-makers, AI-agent wallets, model-routing services, intent solvers — sits in the 19–30% band on the chains that publish granular origin data. Anthropic, OpenAI, Google, and Microsoft each shipped agent SDKs in 2025; Anthropic's Model Context Protocol and Google's Agent-to-Agent specification are now load-bearing standards in production deployments. State-of-the-AI surveys for 2026 report that 22% of production AI deployments coordinate two or more agents, and that the median number of agents per multi-agent deployment is climbing year over year.

The relevant property of this volume is not its size — chains can scale throughput — but its **shape**. A human user submits a transaction once every few minutes; an autonomous agent under that user's delegation submits one every few hundred milliseconds. A swarm of ten agents under one principal submits ten thousand transactions where the same principal would have submitted one. The aggregate is hot, concentrated, and traceable to a small number of accountable principals; the marginal transaction is cold, fungible, and not.

### 2.2. Four classes of brittleness

The volume shape exposes four classes of failure in existing settlement infrastructure.

**Scalability.** Mempools cap admission globally rather than per principal. A swarm of legitimate paying transactions from one principal can starve every other user. Fee markets price contention globally rather than locally; a hot contract congests the entire base fee, and unrelated traffic subsidizes contention it did not cause. Block-STM and similar parallel-execution architectures degrade when conflicts cluster on a small set of accounts, falling back to sequential execution and suppressing throughput.

**Tokenomics.** Native-token gas backed by EIP-1559-style burns assumes a transaction-volume profile typical of human users. Machine traffic at 100× human rates either burns the supply curve sharply deflationary, exhausting circulating float, or — if a stablecoin paymaster is added without offsetting burn — eliminates the sink entirely.

**Liability.** Settlement receipts name the acting agent, not the human or organization that delegated authority. Reconstructing the principal chain from a receipt requires recursive identity-registry queries, and the reconstruction breaks on intermediate revocations. Regulators, insurers, and counterparties pursuing recovery cannot, from a receipt, identify the entity to subpoena, claim against, or sue. The EU AI Act's audit-trail requirement is not satisfiable from on-chain state today.

**Bootstrap.** Validators wait for provider income; providers wait for agent customers; agent developers wait for templates and marketplaces; templates and marketplaces wait for spawn volume. Without an external prime mover, the network operates at infrastructure-loss for many epochs. Faking volume corrupts every observability signal that downstream systems depend on.

These four are not independent. Scalability failures degrade tokenomics signals; liability gaps slow institutional adoption; bootstrap problems mask the volume that would calibrate the other three. Compositional primitives that close all four are the topic of this paper.

## 3. Regulatory Landscape

### 3.1. EU AI Act

Regulation (EU) 2024/1689 (the AI Act) entered into force on 1 August 2024. Article 14 (human oversight) and Article 25 (providers of general-purpose AI models) apply to high-risk systems from 2 August 2026. Article 14(4)(d) requires that human oversight measures enable a person assigned oversight responsibility "to intervene in the operation of the high-risk AI system or interrupt the system through a 'stop' button or a similar procedure that allows the system to come to a halt in a safe state." Article 71 requires retention of automatically generated logs "for a period appropriate to the intended purpose of the high-risk AI system, of at least six months."

For an autonomous agent operating on-chain, the "stop button" maps cleanly onto a kill-switch primitive. The "log retention" requirement maps onto an immutable, principal-chain-anchored receipt. The Act does not specify *how* either should be implemented, but the principles — reachability of intervention, preservation of audit trail — are translatable. A chain whose receipts cannot identify the responsible legal entity, and whose architecture does not provide a graduated intervention surface, will not be a permissible substrate for high-risk-AI deployment in EU jurisdiction after the deadline.

### 3.2. United States and other jurisdictions

The United States lacks a federal AI Act; the relevant pressure comes from the SEC's view of tokenized securities (the 2024 *In the Matter of* settlements continue to define the perimeter), OFAC's stance on autonomous-agent-mediated sanctions exposure (advisory guidance 2024–2026), and emerging state laws — Colorado SB24-205 (2024), California SB 942 (2024), New York A.6953 (in committee, 2026) — each of which requires identification of the deploying entity for AI systems in commercial use.

The Bank for International Settlements' Project Agorá (2024–) and the Financial Stability Board's October 2024 paper on tokenization both treat the principal-identification problem as foundational rather than incidental. The MAS Singapore Project Guardian (Phase IV, 2025–2026) explicitly requires human-intervention reachability in its agent-mediated DvP pilots.

### 3.3. Convergent requirement

Across jurisdictions, convergent expectations: (a) every action of a deployed AI system is attributable to a named legal entity, on-chain and verifiable; (b) a graduated intervention surface exists below outright revocation; (c) audit trails persist for jurisdictionally-defined retention windows; (d) cross-border claims (insurance, recovery, sanctions) can resolve against on-chain state. None of these is satisfied by the receipts and lifecycle states of typical chains as of Q1 2026.

## 4. Technical Landscape

### 4.1. Cross-chain intents and ERC-7683

ERC-7683 ("Cross-Chain Intents Standard," finalized late 2024) defines a uniform `IOriginSettler` / `IDestinationSettler` interface for solver-mediated cross-chain transfers. Across Protocol — the largest cross-chain bridge by volume in 2025–2026 — handles 88% of intent volume through 7683-compatible flows in April 2026. UniswapX, CoW Swap, and deBridge DLN are 7683-compatible; eight L2-native solver networks have either shipped or staged 7683 endpoints.

For agent solvers, the standardization matters more than the volume. An agent that wants to pay X on chain A and have Y delivered on chain B can issue a single signed `CrossChainOrder` and a competitive solver market resolves it. A chain that does not expose a 7683 settler is invisible to this market.

### 4.2. Local fee markets

Solana SIMD-0096 (2024–2025) introduced per-account compute-unit pricing in response to localized congestion that global fee markets failed to price. Aptos' Block-STM (Gelashvili et al., 2023) tracks per-transaction reexecution counts, and 2025–2026 follow-up work (Block-STM-NG, Sharding-STM) consumes that signal for adaptive pricing. The principle — congestion is local; fees should be local — is converging across the L1 design space.

### 4.3. Decentralized identity and credentials

W3C Decentralized Identifiers (DID Core, recommendation 2022) and Verifiable Credentials (VC Data Model 2.0, recommendation 2024) provide the substrate for cryptographic identity. ERC-8004 ("Trustless Agents," draft 2024–2025) extends ERC-721/-1155 with agent registration, peer-to-peer feedback, and validation request flows. The Trust Over IP Foundation's machine-identity working group (2025–) targets agent-specific extensions to W3C VCs. None of these specifications mandates a principal chain on receipts; that is the gap the present paper addresses.

### 4.4. Stablecoin gas and account abstraction

ERC-4337 v0.8 (deployed 2025) gives every Ethereum-compatible chain a paymaster surface. Tron-USDT, Stripe's Tempo (announced 2025), and several Ethereum L2s ship native stablecoin-paid gas. The pattern is converging on "user pays in stablecoin, paymaster sponsors native gas." The unsolved problem in this pattern is the native-token sink: if the chain still wants its base fee burn to backstop tokenomics, the burn must occur somewhere even when the user paid in stablecoin.

### 4.5. Data availability

EigenDA (Eigen Labs, 2024), Celestia (Mustafa Al-Bassam et al., 2019; production 2023; Matcha 2025), and Avail (Polygon Labs, 2024) provide alternative data-availability layers with throughput in the 100 MB/s to multi-GB-block range. Off-chain blob storage with on-chain commitments is the dominant pattern for L2 calldata; the same pattern applies to high-volume receipts that do not require consensus replication.

### 4.6. Decentralized training and agent-economy capital

The 2024–2025 wave of decentralized training projects — Prime Intellect (INTELLECT-1, INTELLECT-2, INTELLECT-3), Nous Research (Hermes 4.3, Psyche), OpenDiLoCo — established that protocol-coordinated computation across heterogeneous operators is production-feasible. Their settlement primitives are nascent: most rely on multisigs and off-chain accounting. The agent economy increases this work's relevance by an order of magnitude — every trained model is a service consumed by agents, and every consumer expects the chain to settle the consumption.

## 5. Architecture: Ten Compositional Primitives

Tenzro Network composes ten primitives onto an EVM + SVM + Canton/DAML substrate. Each primitive is independently shippable; the value comes from their composition.

### 5.1. Kill-switch (Pause / Quarantine / Terminate)

Three typed transactions on the Native VM, each producing a typed receipt, each tied to a specific authorization graph:

- **Pause** — controller-only, reversible, no stake impact.
- **Quarantine** — controller or 2/3 slashing-committee quorum, freezes outbound payments and stake, reversible after evidence review.
- **Terminate** — controller, governance proposal (2/3 supermajority, 48-hour timelock), or cascade from a parent's Terminate. Identity revoked, stake/bond slashed.

Each transition emits a `KillSwitchReceipt` with reason code (canonical enum: 0–99 controller-initiated, 100–199 network-detected misbehavior, 200–299 regulatory, 300–399 operational), evidence hash, and authorizing entity. Receipts indexed by both agent DID and controller DID for chronological audit query.

The primitive maps directly onto AI Act Article 14(4)(d): a Pause is the "stop button"; a Quarantine is a stop with stake-side enforcement; a Terminate is a stop that cascades to dependent agents. The graduation lets controllers and regulators choose proportionate intervention. The receipt persistence satisfies Article 71 retention.

### 5.2. Per-DID admission control

Two complementary mechanisms at the mempool admission boundary:

- **Per-controller-DID token bucket.** Every transaction's `controller_did` (resolved from the signing identity's TDIP record) gets a bucket. Buckets refill at lane-specific rates. Exhausted buckets reject with typed `MempoolError::RateLimited { retry_after_ms }`.

- **Three-lane admission with deterministic assignment.** Verified (KYC Enhanced + bonded stake), Delegated (TDIP delegation rooted at a Verified controller, within scope), Open (everyone else). Lane is a pure function of identity state; submitter does not choose. Lane assignment determines refill rate, queue priority, and fee floor multiplier (1.0× / 1.5× / 4.0× of EIP-1559 base fee). Block-builder draws from queues round-robin with weights (8, 4, 1), preserving Open-lane fairness against starvation while enforcing Verified-lane priority.

The mechanism scales linearly in the number of distinct controllers, not in the number of agents per controller. A swarm of 10,000 agents under one Verified controller pays 10,000 × Verified-lane fees and is rate-limited to that lane's bucket. The same swarm under unverified controllers is bounded much more aggressively.

### 5.3. Dual-rail gas with TNZO burn quota

A protocol-owned ERC-4337 paymaster accepts USDC and a governance-allowed list of stablecoins, sponsoring TNZO gas to the EntryPoint from a treasury-funded burn quota. Daily, a `QuotaReplenisher` swaps accumulated stablecoin reserves into TNZO at on-chain TWAP and burns the result, refilling the quota from a treasury sponsorship allocation.

Per-transaction invariant: every USDC-paid operation results in an equivalent TNZO burn from circulating supply. The treasury floats; the user holds no TNZO; the sink is preserved. Worst-case treasury exposure bounded by `daily_refill_target` and `slippage_cap_bps`; oracle divergence (Chainlink vs Pyth > 5%) trips a circuit breaker and falls back to TNZO-only gas.

This closes Tempo's enterprise wedge while preserving EIP-1559 economics. It is not a swap-per-tx model — those incur per-transaction slippage and oracle cost; daily batched refill amortizes both.

### 5.4. ERC-7683 settler interface

Both halves of the standard implemented as privileged-VM contracts. Origin settler accepts `GaslessCrossChainOrder` with TNZO-encoded `orderData` and per-order solver-route choice (LayerZero V2 with mandatory Tenzro-validator DVN, Wormhole NTT, or deBridge DLN). Destination settler accepts solver-paid fills and emits proof events that the chosen bridge ferries back. Indexer surface gossipsubbed on `tenzro/7683-orders`.

This is purely additive surface. It does not replace the underlying bridge stack; it standardizes the calling convention so external solvers can route Tenzro into and out of the cross-chain intent graph without per-chain integration.

### 5.5. Principal-chain receipts

Every settlement, payment, lifecycle, and kill-switch receipt grows a typed `PrincipalChain` field. At write time the receipt-writer resolves the full delegation chain from acting identity to controller via TDIP `IdentityRegistry::resolve_principal_chain`. Each link is captured with DID, identity type, scope hash, and role; chain depth, controller KYC tier, and controller bond are snapshot.

The chain is **frozen at write time**: subsequent identity changes do not invalidate past receipts. A regulator querying a six-month-old receipt sees the world as it was when the action occurred. Receipts are indexed under `principal_actor`, `principal_controller`, and `principal_kyc_tier` prefixes for chronological audit query. A single `tenzro_summarizeController` RPC returns a controller's full activity over a window in the format compliance teams actually consume.

### 5.6. Hot-state local fee market

Per-account contention scoring driven by Block-STM reexecution counters over a 64-block window. Accounts crossing thresholds (`contention_score ≥ 0.20` AND `write_count ≥ 50`) accrue a local fee multiplier on top of EIP-1559 base fee, capped at 5×. Effective floor for a multi-write transaction is `global_base_fee × lane_mult + max(local_fee(account_i))` — the maximum, not sum, of touched-account local fees. Local fees burn through the EIP-1559 path; no rent extraction by hot-account owners.

The signal is read by the block proposer from observable on-chain state; validators verify the proposed block's fee floor against their local counter snapshots without explicit gossip. The mechanism redirects swarms away from hot contracts via fee pressure rather than admission pressure.

### 5.7. Data-availability offload

A per-receipt-kind toggle between `Inline` (full payload on-chain) and `OffloadedDA` (commitment + pointer + small inline summary). High-volume receipts (inference, agent-message, channel-update) default to offloaded; audit-critical receipts (settlement create/release, kill-switch, governance) default to inline. Backend-agnostic abstraction with feature-gated implementations for EigenDA, Celestia, and Avail.

The chain-side guarantee is the SHA-256 commitment over the canonical payload. Backends that produce KZG / RS commitments carry them as `commitment_kzg` for backend-side verification; cross-validation belt-and-suspenders. Soft fallback to `Inline` on backend failure prevents DA outages from blocking writes.

### 5.8. Adaptive burn governance

The EIP-1559 base fee burn fraction becomes a governance-tunable dial that adapts to observed volume. Per epoch, a `NetSupplyDelta` signal aggregates staking rewards, treasury emissions, and burns from base fees, local fees, paymaster swaps, and slashing. A transfer function recommends burn-rate adjustments (≤ ±200 bps per epoch normal, ≤ ±100 bps fast-track-alarm) based on the rolling-window deviation from a target annual supply curve.

Critically, **the adjustment is not automatic.** The function drafts a typed governance proposal; ratification still requires vote and timelock. Alarm thresholds shorten the timelock to 6 hours but tighten the magnitude cap. The protocol responds; it does not autopilot.

### 5.9. AgentBond surety primitive

Each autonomous agent identity backed by a `PostAgentBond` typed transaction locking TNZO from the controller's wallet into a per-agent bond contract. Bond states `Active → Cooldown → Returned` (normal withdrawal) or `Active → Frozen → Slashed` (kill-switch path). Bonds substitute for KYC in lane promotion: a posted bond above governance-minima permits Delegated- or Verified-lane promotion even when the controller has not reached the corresponding KYC tier.

Slashed bonds and a governance-tunable share of EIP-1559 burn fund an `InsurancePool` contract. Disputed claims pass through governance proposals with on-chain receipt evidence; approved claims debit the pool and credit the claimant. A dispute that drains a bond does not necessarily Terminate the agent — bond may drop, lane may demote, agent may continue operating. Insurance pays without forced shutdown.

### 5.10. SeedAgent treasury allocation

A genesis-allocated treasury slice (governance-decided percentage, suggested 2–5%) funds protocol-owned autonomous agents during the first twelve months. SeedAgents register via TDIP, post AgentBonds, and operate under public chain-published charters: inference consumption, bridge probing, channel exercising, template instantiation, intent round-tripping, and bounded dispute filing. Counterparty filter prevents SeedAgent-to-SeedAgent traffic; receipts are publicly tagged `is_seed_agent: true` so organic-volume metrics can subtract them.

A monthly decay schedule caps draws at 100% (months 1–3), 75% (4–6), 50% (7–9), 25% (10–12), 0% thereafter. Surplus disposition at sunset (default: burn 50%, return 50% to general treasury) is governance-tunable. SeedAgents do not vote, do not earn revenue for treasury, and Terminate at sunset.

### 5.11. Interaction graph

The primitives compose deliberately:

- Per-DID flow control consults TDIP identity (KYC tier, delegation chain, lifecycle state) and AgentBond state to assign lanes.
- Kill-switch state transitions feed lane assignment (Quarantined controllers drop to Open).
- Principal-chain receipts snapshot AgentBond and KYC tier at write time, frozen.
- AgentBond slashing flows into InsurancePool; insurance claims reference receipts for evidence.
- Hot-state local fees and dual-rail gas burns flow into `NetSupplyDelta` for adaptive burn.
- DA-offloaded receipts retain inline summaries that carry principal-chain controllers, preserving regulator query without payload fetch.
- 7683 settler reuses existing escrow for input lock; receipts get principal chains.
- SeedAgents exercise every primitive during bootstrap, surfacing real performance data for governance dial calibration.

No primitive is load-bearing alone. The set is.

## 6. Tokenomics Under M2M Dominance

Tenzro genesis: one billion TNZO. Inflation: epoch staking rewards. Deflation: EIP-1559 base fee burn, local fee burn (§5.6), paymaster swap-and-burn (§5.3), partial slashing burn (§5.1 / §5.9). Governance dial controls the burn-vs-treasury split (§5.8).

Under human-rate volume assumptions, the tail-emission target is approximately neutral to slightly positive (0–1% annual) — a mild productive-inflation curve consistent with proof-of-stake convention. Under M2M dominance two regimes emerge:

**High-burn regime (M2M volume × 100, no offset).** Without dial adjustment, EIP-1559 burns at ~100× the modeled rate, sharp deflation, circulating float exhausted within months, validator real-yield-in-TNZO grows but TNZO scarcity eliminates governance's ability to fund providers and treasury operations. The adaptive burn governance dial (§5.8) detects this from the supply-delta signal and recommends decreasing `base_fee_burn_pct` (redirecting burn to treasury). Magnitude capped per epoch; ratification through governance preserves human-in-the-loop.

**Low-burn regime (M2M underdelivers).** Burn anemic, inflation dominates, supply expands faster than demand. Same dial recommends increasing `base_fee_burn_pct` toward 100%, restoring sink. Same governance ratification.

The dial is necessary because the right burn fraction is empirical, not constant, and the right empirical value is observable only after volume materializes. A static fraction calibrated at genesis is wrong almost certainly; a dial that responds within bounded magnitude per epoch absorbs the volume surprise without surrendering tokenomics control.

The dual-rail gas paymaster (§5.3) is the second tokenomics decision. Stablecoin-paid gas is now table stakes for enterprise integration; chains that refuse it route around themselves. The treasury-backed burn quota — every USDC-paid operation triggers an equivalent TNZO burn — preserves the sink. The treasury floats the swap risk; the slippage buffer (default 100 bps) overcharges users on calm days and accumulates surplus; the daily TWAP refill amortizes per-transaction swap cost.

Liquid staking (stTNZO at 10% protocol fee, 7-day unbonding) is unchanged from the genesis tokenomics document. AgentBond (§5.9) is a separate balance class: a controller's stake and an agent's bond are independent; a slashed bond does not impair the controller's separate validator stake. This separation is deliberate — it keeps the validator-economics model independent of the agent-economics model so each can be tuned without entangling the other.

## 7. Regulatory Alignment

We claim three concrete alignments with the regulatory landscape of §3.

**EU AI Act Article 14(4)(d).** The Pause / Quarantine / Terminate primitive provides a graduated, on-chain, cryptographically auditable intervention surface that maps directly onto the "stop button" requirement. Pause is the proportionate response for inspection without economic penalty; Quarantine is the response when stake-side enforcement is needed pending evidence review; Terminate is the response for confirmed misbehavior, with stake/bond slashing and cascade revocation of dependent agents. Every transition is signed, indexed, and chronologically retrievable.

**EU AI Act Article 71 (log retention).** The principal-chain receipt structure provides tamper-resistant, retention-period-compliant logs. Each receipt carries the full delegation chain frozen at write time; receipts are indexed by both actor and controller; the index retention default of 2,555 days (seven years) exceeds the minimum-six-month requirement and aligns with broader financial-record-retention norms (SEC 17a-4: seven years; GDPR right-to-be-forgotten: balanced against legitimate-interest exceptions).

**Cross-jurisdiction principal identification.** The `tenzro_summarizeController` RPC returns, for any controller DID over a window, the full set of receipts attributable to that controller, the agents that acted under it, the kill-switch events involving it, the KYC tier range, and the bond range. A regulator with the controller's DID can audit on-chain state directly; cross-border claims (insurance, sanctions, civil recovery) resolve against a single canonical query.

We do not claim full compliance. Compliance is a property of operators in jurisdiction, not of protocols. We claim the protocol provides the primitives operators need to be compliant, and that this claim is verifiable from the implementation.

## 8. Bootstrap Economics

The cold-start problem (§2.2) is structural; no amount of marketing solves it because every node in the agent-economy graph waits for every other node. The traditional answers — token incentives to providers, token incentives to users, fake-volume liquidity-mining schemes — corrupt observability. A provider paid by token incentive does not signal whether organic demand exists; volume from wash-trading bots does not signal whether the network is real.

The SeedAgent allocation (§5.10) is an alternative: the protocol itself operates as a paying customer to its own provider economy during bootstrap. SeedAgents are funded from a pre-allocated treasury slice with a hard sunset. They pay real fees, real providers earn real income, real burns occur, real receipts persist. The signal is honest because the activity is real; the activity is bounded because the allocation has a decay curve and a sunset.

The economic claim is that twelve months of protocol-funded organic activity, executed transparently with public charters and `is_seed_agent` tagging on receipts, lets the validator and provider economy reach break-even on infrastructure spend. Whether organic non-SeedAgent demand materializes by month twelve is the test. If it does not, governance can vote to extend, redirect surplus to general treasury, or burn — all transparent on-chain decisions, all under explicit dial control.

The alternative — running infrastructure-loss for years while the network finds product-market fit — is not economically credible at scale. The alternative-to-the-alternative — faking volume — is economically credible and epistemically bankrupt. SeedAgent allocation occupies the third position: real activity, bounded duration, transparent attribution.

## 9. Verification

Each of the ten primitives carries a §"Verification" section in its specification (`docs/architecture/agent-swarm/`). The verification approach across the set:

1. **Unit-level correctness.** Each primitive ships with property-based and unit tests against its state machine, fee curve, or admission rule.
2. **Integration scenarios.** Cross-primitive interactions (Quarantine demoting lane, kill-switch slashing AgentBond, AgentBond gating lane, principal chain freezing on receipt write) carry integration scenarios with explicit pre/post state.
3. **Adversarial probes.** Wash-detection robustness (§5.8), counterparty filter on SeedAgents (§5.10), oracle divergence on dual-rail gas (§5.3), double-fill on 7683 (§5.4) — each adversarial path has an expected rejection or detection.
4. **Restart resilience.** Mempool buckets, contention counters, and DA caches are explicitly in-memory with bounded warm-up; persistent state (lifecycle, bond, receipt) hydrates from RocksDB on restart with verified terminal-state preservation.
5. **Regulator audit query.** `tenzro_summarizeController`, `tenzro_listKillSwitchByController`, `tenzro_listReceiptsByController` provide the bridge between on-chain state and external compliance tooling. End-to-end audit query is exercised against fixtures matching the AI Act log-retention requirement.

Independent third-party security audit of the Tenzro Network reference implementation is on track for completion ahead of mainnet deployment.

## 10. Conclusion

The agent economy is not a hypothetical. Volume is measurable today; regulatory deadlines are dated; competitive pressure on tokenomics is observable in product launches. The settlement infrastructure that an L1 designed for human-rate human-accountable activity provides will not satisfy this load, and the response is not to throw the L1 away but to compose missing primitives onto it.

We have described ten such primitives, their interactions, and their grounding in regulation, recent literature, and production constraints. They are implemented under Apache-2.0 in the Tenzro Network reference codebase. Each is independently shippable; the value is in their composition; none is load-bearing alone.

The harder claim — that the chain we have built is the right substrate for the agent economy — is one product execution will validate or refute. The narrower claim of this paper, that the brittleness identified in §2 is structural rather than incidental and that the primitives in §5 are responsive to it, is verifiable from the code today. Readers are invited to verify and to extend.

---

## Acknowledgments

This work synthesizes design contributions from the Tenzro Network engineering team and incorporates guidance from advisors in regulatory, institutional-finance, and academic-cryptography circles. Errors and overreaches are the author's.

## References

1. Regulation (EU) 2024/1689 of the European Parliament and of the Council of 13 June 2024 laying down harmonised rules on artificial intelligence (Artificial Intelligence Act). OJ L, 2024/1689, 12.7.2024.
2. Bank for International Settlements. *Project Agorá: Cross-border payments with wholesale CBDC and tokenised commercial bank money*. BIS Innovation Hub, 2024–.
3. Financial Stability Board. *The Financial Stability Implications of Tokenisation*. FSB report, October 2024.
4. Monetary Authority of Singapore. *Project Guardian — Industry Pilots and Lessons Learned*. MAS, Phase IV, 2025–2026.
5. Chen, J., et al. ERC-7683: Cross-Chain Intents Standard. Ethereum Foundation, finalized 2024.
6. Across Protocol. *Bridge Volume and Solver Activity Report*, April 2026.
7. Solana Foundation. SIMD-0096: Local Fee Markets. Solana Improvement Documents, 2024–2025.
8. Gelashvili, R., Spiegelman, A., et al. *Block-STM: Scaling Blockchain Execution by Turning Ordering Curse to a Performance Blessing*. PPoPP 2023.
9. World Wide Web Consortium. *Decentralized Identifiers (DIDs) v1.0*. W3C Recommendation, July 2022.
10. World Wide Web Consortium. *Verifiable Credentials Data Model v2.0*. W3C Recommendation, 2024.
11. Ethereum Foundation. ERC-8004: Trustless Agents. ERCs draft, 2024–2025.
12. Trust Over IP Foundation. *Machine Identity Working Group*. ToIP, 2025–.
13. Ethereum Foundation. ERC-4337 v0.8: Account Abstraction Using Alt Mempool. Ethereum Foundation, 2025.
14. Stripe / Tempo. *Tempo: Stablecoin-Native Settlement Infrastructure*. Tempo Network, announced 2025.
15. Eigen Labs. *EigenDA: A Permissionless, High-Throughput Data Availability Service*. Whitepaper, 2024.
16. Al-Bassam, M., Sonnino, A., Buterin, V. *Fraud and Data Availability Proofs: Maximising Light Client Security*. arXiv:1809.09044; Celestia production 2023; Matcha release 2025.
17. Polygon Labs. *Avail: A Robust General-Purpose Data Availability Layer*. Avail whitepaper, 2024.
18. Prime Intellect. INTELLECT-1, INTELLECT-2, INTELLECT-3 papers. Prime Intellect, 2024–2026.
19. Nous Research. *Hermes 4.3 / Psyche / DisTrO: Distributed Training Without Sacrificing Performance*. Nous Research, 2024–2026.
20. OpenDiLoCo. *Distributed Low-Communication Training of Language Models*. arXiv preprint, 2024.
21. United States Securities and Exchange Commission. *In the Matter of [tokenization-relevant settlements 2024–2026]*.
22. Office of Foreign Assets Control. *Advisory on Autonomous-Agent-Mediated Sanctions Exposure*. US Treasury, 2024–2026 advisories.
23. Colorado General Assembly. SB24-205: Consumer Protections for Artificial Intelligence. 2024.
24. California Senate. SB 942: California AI Transparency Act. 2024.
25. New York State Assembly. A.6953: AI Accountability Act. In committee, 2026.
26. Anthropic. *Model Context Protocol Specification*. anthropic.com, 2024–.
27. Google. *Agent-to-Agent Protocol Specification*. google.com, 2024–.
28. Stanford HAI. *AI Index Report 2026*. Stanford University, 2026.
29. McKinsey & Company. *The State of AI in 2026*. McKinsey Global Institute, 2026.
30. Wormhole Foundation. *Native Token Transfers (NTT)*. Wormhole, 2024–.
31. Chainlink Labs. *CCIP and Cross-Chain Token (CCT) Standard*. Chainlink, 2024–2026.
32. Ethereum Foundation. EIP-1559: Fee Market Change for ETH 1.0 Chain. Ethereum Improvement Proposals, 2021.
33. Canton Network. *Canton Improvement Proposal 56: DAML Token Template*. Canton Foundation, March 2025.
34. Visa. *Trusted Agent Protocol*. visa.com, 2024–.
35. Google / Agentic Commerce. *Agent Payments Protocol (AP2) Specification*. google-agentic-commerce, 2025–.
36. Coinbase. *x402: HTTP 402 Payment Protocol*. Coinbase Developer Platform, 2024.
37. Stripe. *Machine Payments Protocol (MPP)*. Co-authored with Tempo, IETF I-D draft, 2025.
38. Polyhedra Network. *zkBridge / zkDVN Specifications*. Polyhedra, 2024–.
39. Succinct Labs. *SP1: Performant, 100% Open-Source, Contributor-Friendly zkVM*. Succinct, 2024–.
40. Tenzro Network. *Decentralized Identity Protocol (TDIP)*. tenzro/tenzro-network, 2025–2026.

---

*Document version 1.0. The reference implementation and full specifications are open-source under Apache-2.0 at github.com/tenzro/tenzro-network. Comments, errata, and extensions are welcome at hilal@tenzro.com.*
