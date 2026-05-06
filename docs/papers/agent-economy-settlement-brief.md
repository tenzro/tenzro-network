# Settlement Infrastructure for the Agent Economy

**Executive Brief**

**Hilal Agil**
*Founder, Tenzro*
hilal@tenzro.com

---

## The problem

By mid-2026, autonomous AI agents originate between 19% and 30% of on-chain transaction volume across major networks. The settlement layer underneath this traffic — mempool admission, fee markets, transaction receipts, gas-token economics, regulatory hooks — was designed for human-rate, human-accountable activity. It composes badly with machines:

- **No principal of record.** A receipt names the EOA that signed and the contract that executed. It does not name the person, organization, or licensed entity ultimately responsible. When an agent acts wrongly, the chain cannot say who to hold liable.
- **No per-principal admission control.** Mempool fairness is global. One controller can run ten thousand agents and outcompete every human user with no protocol-level pushback.
- **No machine-grade intervention surface.** Article 14(4)(d) of the EU AI Act requires high-risk AI systems to support human override "by means of a 'stop' button or a similar procedure." The deadline is 2 August 2026. Existing chains have no primitive that satisfies this requirement at the controller level.
- **Gas economics assume the wrong workload.** Stablecoin-denominated gas (announced by Tempo and Codex) eliminates the volatility argument for token-denominated gas but also breaks the burn sink that backs network economics in machine-dominated traffic.
- **Local hot spots, global prices.** EIP-1559's single base fee cannot price contention on a single hot account caused by one runaway agent without raising costs for everyone.

These are coupled. Solving any one in isolation creates pressure on the others.

## The proposal

Ten compositional primitives that together form a settlement layer designed for agent-dominated traffic, without abandoning the assumptions on which existing chains were built. None require a new token, none break composability with ERC-20/4337/7683.

| # | Primitive | What it does |
|---|-----------|--------------|
| 1 | **Kill-Switch** | Pause / Quarantine / Terminate transactions that mutate agent lifecycle on-chain, gated by TDIP delegation, audited as receipts |
| 2 | **Per-DID Flow Control** | Token bucket per controller-DID, three lanes (Verified / Delegated / Open) with deterministic fee floors and admission weights |
| 3 | **Dual-Rail Gas** | ERC-4337 paymaster lets agents pay in stablecoin while a treasury-funded `BurnQuota` does daily TWAP swaps and burns equivalent TNZO — every USDC-paid op burns equivalent native token |
| 4 | **ERC-7683 Settler** | Origin and destination settler precompiles speak the cross-chain intent standard adopted by Across, Uniswap V4, and the OIF working group |
| 5 | **Principal-Chain Receipts** | Every receipt carries `actor → controller → KYC tier → bond`, traversable up to depth 16, queryable per-controller |
| 6 | **Local Fee Market** | Per-account contention multiplier (≤5×) computed from Block-STM reexecution and write count over a 64-block window — burn, not rent |
| 7 | **DA Offload** | Receipts above 4 KB record a 32-byte commitment on-chain and store the body on EigenDA / Celestia / Avail; SHA-256 commitment is canonical chain-of-custody |
| 8 | **Adaptive Burn** | Per-epoch `NetSupplyDelta` triggers governance proposals to retune the burn dial; auto-proposed, never auto-applied |
| 9 | **AgentBond** | Surety stake from controller, slashed on equivocation/fraud, funds an `InsurancePool` that pays principals when an agent misbehaves; substitutes for KYC in lane promotion |
| 10 | **SeedAgent** | Time-boxed treasury-funded protocol-owned agents during bootstrap, decaying over 12 months, charters fixed (load / bridge / channel / template / intent / dispute), counterparty filter prevents seed-to-seed circular volume |

These compose: receipts (5) carry kill-switch outcomes (1) and contention scores (6); flow control (2) reads bond state (9); the burn quota (3) is the integral the adaptive dial (8) tunes; SeedAgents (10) and the insurance pool (9) both draw from the same treasury-earmark line.

## Why governments and institutions should care

**Regulators.** The EU AI Act, the Council of Europe Framework Convention, the US AI Bill of Rights, and the upcoming UK AI Bill all require some combination of: (a) human override on high-risk systems, (b) auditable logs of automated decisions, (c) identifiable principal for liability. None of these are achievable on a chain whose receipts name only EOAs and whose mempool admits any well-formed transaction. The ten primitives, taken together, give regulators a cryptographically verifiable surface that satisfies all three: kill-switch (a), principal-chain receipts (b), AgentBond + KYC tier (c).

**Institutions.** Banks, asset managers, and insurers cannot custody agent activity if the protocol cannot tell them which controller is responsible when something fails. The principal-chain receipt is the missing primitive — every action on the network is attributable to a real-world principal up to a bounded delegation depth, with KYC tier and posted bond visible alongside the receipt.

**Operators of high-risk AI systems.** Article 14(4)(d) takes effect 2 August 2026. By that date, any operator running agents on settlement infrastructure needs a "stop button" they can demonstrate to an auditor. The kill-switch primitive provides exactly that — Pause / Quarantine / Terminate states, propagated through the controller graph, audited as on-chain receipts.

## What is novel

The ten primitives individually have antecedents — token buckets are old, ERC-4337 paymasters are 2023, ERC-7683 is 2024, Solana SIMD-0096 prototypes local fees, EigenDA is production. What is novel is **the composition**: TDIP delegation as the accounting axis, the controller-DID as the unit of flow control + liability + bond, receipts that carry the principal chain natively, and a burn-quota mechanism that lets stablecoin-gas coexist with token-denominated economics.

## Status

The full reference implementation is open-source at github.com/tenzro/tenzro-network under Apache-2.0. The companion specifications are at `docs/architecture/agent-swarm/`. The position paper at `docs/papers/agent-economy-settlement.md` (14 pp.) covers regulation, related literature, mechanism design, and verification methodology with full citations.

The testnet is live. Three validators and the RPC tier run the same `tenzro-node` binary on GKE. The kill-switch, per-DID flow control, and principal-chain receipt primitives ship in the next release. AgentBond and the dual-rail paymaster follow. The adaptive-burn dial begins as a manual governance dial and graduates to auto-proposal over the first 12 months of mainnet operation.

## Engagement

The architecture is designed to be implemented by other settlement layers, not just Tenzro. Receipt schemas, DA pointer formats, kill-switch reason codes, and principal-chain envelope are intended to standardize so that an agent posting a receipt on chain A can be audited by a regulator querying chain B without bespoke integration. We will submit the receipt envelope and the kill-switch reason-code enum as standards-track proposals (CAIP / ERC) once the interfaces stabilize on testnet.

Comments, errata, and collaboration enquiries: hilal@tenzro.com.

---

*Companion document to "Settlement Infrastructure for the Agent Economy: Accountability, Throughput, and Liability in M2M-Dominated Networks" (Tenzro Network, 2026).*
