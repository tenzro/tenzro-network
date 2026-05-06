# Agent-Swarm Architecture

**Status:** Drafting (2026-05-04)
**Scope:** Settlement, identity, fee, and liability primitives that must hold up when autonomous-agent traffic dominates Tenzro volume.

## Why this set exists

By mid-2026, AI agents drive 19–30% of on-chain activity industry-wide and 22% of production deployments orchestrate multiple agents. Tenzro is engineered for this — TDIP delegation scopes, MPC wallets, A2A/MCP, multi-VM execution. But the gap between *can host swarms* and *handles swarms gracefully under load and regulatory scrutiny* is the work below.

The 10 specs in this directory close that gap. They're listed in the order you'd staff them, not the order they were discovered.

## Ordered by leverage

| # | Spec | Why this slot |
|---|---|---|
| 1 | [Kill-switch](kill-switch.md) | EU AI Act high-risk obligations apply 2026-08-02. Hard deadline. |
| 2 | [Per-DID flow control](per-did-flow-control.md) | Protects every other system from being overwhelmed. Foundational. |
| 3 | [Dual-rail gas](dual-rail-gas.md) | Closes Tempo's enterprise wedge while preserving TNZO sink. |
| 4 | [ERC-7683 settler](erc-7683-settler.md) | 88% of cross-chain intent volume in April 2026. Pure additive surface. |
| 5 | [Principal-chain receipts](principal-chain-receipts.md) | Pairs with kill-switch — typed liability chain on every receipt. |
| 6 | [Hot-state local fee market](local-fee-market.md) | Per-account fee escalation when swarms cluster on hot contracts. |
| 7 | [DA offload](da-offload.md) | Receipts and inference payloads off-chain via EigenDA / Celestia / Avail. |
| 8 | [Adaptive burn governance](adaptive-burn.md) | M2M volume is 100×; calcified burn taper either drains or no-ops. |
| 9 | [AgentBond surety](agent-bond.md) | Slashable bond per autonomous agent, funds insurance pool. Pairs with kill-switch + receipts. |
| 10 | [SeedAgent allocation](seed-agent.md) | Treasury-funded protocol-owned agents to exercise the stack in months 0–12. |

## Cross-cutting invariants

These hold across every spec:

- **No new tokens.** Every fee, bond, slash, reward is denominated in TNZO. Stablecoin paths route through paymasters that still burn TNZO from a treasury quota.
- **DID is the unit of accounting.** Mempool admission, fee lanes, kill-switches, receipts, bonds — all keyed on `controller_did` (the human/org behind the agent), not the agent DID. Multiple agents under one controller are one accountable unit.
- **TDIP delegation scope is the structural ceiling.** Every runtime check that bounds an agent (spending, kill-switch authority, bond release) reads from the existing `DelegationScope` and `IdentityRegistry::enforce_operation` path. We are extending that surface, not replacing it.
- **Receipts are the audit primitive.** Liability chain, kill-switch state transitions, bond posting, paymaster sponsorship — all surface as typed fields on the existing settlement / lifecycle receipts. Regulators verify against on-chain state, not log files.
- **Governance dials, not hardcoded constants.** Every threshold (lane fill rate, burn quota size, kill-switch quorum, bond minimum) is a governance-controlled parameter, set conservatively at genesis, tunable without a chain fork.

## Phasing

- **Phase 1 (testnet, weeks 0–8):** Kill-switch, per-DID flow control, principal-chain receipts. Regulatory + foundational.
- **Phase 2 (testnet → mainnet readiness, weeks 8–16):** Dual-rail gas, ERC-7683, AgentBond. Competitive + economic.
- **Phase 3 (mainnet hardening, weeks 16–24):** Local fee market, DA offload, adaptive burn, SeedAgent.

Each spec stands on its own — Phase 1 specs ship without waiting for Phase 2/3 — but the cross-cutting invariants assume the full set lands eventually.
