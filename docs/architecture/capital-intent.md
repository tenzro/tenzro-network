# Capital Intent Standard

**Status:** SHIPPED (P1–P6, 2026-06-06) — `tenzro-types::capital_intent` + `reserve` types, the `tenzro_capitalIntent*` + `tenzro_{submitReserveAttestation,attestedMint,getReserve}` RPC family, Proof-of-Reserve + attested-mint, solver auto-selection (ERC-8004/KYA-ranked), best-execution proof, and all surfaces (Rust/Python MCP, SDK, `tenzro capital` CLI). Solver agents and venue adapters remain ecosystem (P7). See `agentic-economy-coordination.md`.
**Last updated:** 2026-06-06

## Why this doc exists

Tokenized real-world assets are arriving fast: **xStocks** (Backed Finance, now Kraken-owned) put 60+ US equities on-chain as 1:1-collateralized tokens; **Republic** (`rSpaceX`), **Jarsy** (`JSPAX`), PreStocks and Bitget IPO Prime tokenize **pre-IPO** equity (SpaceX, Anthropic, Figma), and Kraken and others are now promoting pre-IPO alongside public stocks. These are all **permissioned securities** (Reg S, KYC-gated, lock-ups), most issued under [ERC-3643](https://www.erc3643.org/) with on-chain identity.

Separately, the **intent** paradigm has matured: [ERC-7521](https://eips.ethereum.org/EIPS/eip-7521) (general intents for smart-contract wallets, from Anoma), CoW Protocol (batch-auction solvers), Across / Essential / Anoma — an intent declares a *desired outcome* and a **solver network** competes to fulfil it. [ERC-7683](https://www.erc7683.org/) standardised the **cross-chain settlement** intent ("move asset X to chain Y").

The gap: there is **no standard for a capital/investment intent** — "achieve this financial objective, within these compliance and risk limits" — that an agent/solver fulfils *using* settlement intents underneath. That is the layer this doc defines, and it is the one place Tenzro is uniquely positioned to own: **it is the rare stack that has both compliant tokenization (`erc3643` + identity + Proof-of-Reserve) and agentic capital orchestration (saga + AP2 + delegation + ERC-8004 + MPC custody).**

## Crucial architectural distinction

Tenzro is **not** building an exchange, a solver, or a trading strategy. There are already excellent venues (Kraken/xStocks) and intent solvers (CoW, Across). Tenzro's role is the **neutral standard + settlement + compliance substrate** beneath them:

1. A **typed, signed capital objective** (the Capital Intent) any party can express.
2. Protocol-enforced **invariants** in the middle: capital ceilings (AP2), compliance (`erc3643` transfer gating), 1:1 backing (Proof-of-Reserve), and agent trust (ERC-8004 / KYA).
3. An open **solver market** — solver agents compete to fulfil intents; Tenzro does not pick winners (exactly as ERC-7683 fillers are an open market).

This positions Tenzro as the equivalent of **"ERC-7683 for capital objectives"** — one level above mechanical asset movement.

## SOTA reference (2025–2026 intent landscape)

| Standard / system | Intent scope | Solver model | Compliance-aware | Cross-chain |
|---|---|---|---|---|
| **ERC-7683** | cross-chain asset transfer | fillers, Permit2 witness | no | yes |
| **ERC-7521** | general SC-wallet intents (validity predicates) | generic solvers | no | no |
| **CoW Protocol** | swap (best price, MEV-resistant) | batch-auction solvers | no | no |
| **Anoma / Essential** | general intents as base primitive | solver network | no | partial |
| **AP2** (Tenzro) | commerce mandate (pay for cart) | n/a (direct) | yes (ceilings + chains) | yes |
| **Capital Intent** (this doc) | **financial objective + risk/compliance limits** | **solver agents (KYA + ERC-8004 ranked)** | **yes (erc3643 + AP2 + PoR)** | **yes (ERC-7683/CCIP legs)** |

Capital Intent is deliberately a **superset position**: it *uses* ERC-7683/CCIP for settlement legs, AP2 for authorization ceilings, `erc3643` for compliance, Proof-of-Reserve for backing, and the saga lifecycle for multi-leg execution + compensation.

### Relationship to AP2 (the dominant agent-payments standard)

[AP2](https://agentpaymentsprotocol.info/) (Google + Coinbase + 60+ orgs; x402 is its stablecoin extension, now under the Linux Foundation with Google/Stripe/Visa) defines **three mandate types**: **Intent Mandate** (what the user authorizes the agent to *pursue*), **Cart Mandate** (the concrete purchase), and **Payment Mandate** (the payment authorization). Tenzro already implements AP2 (the cart/payment ceilings + `accepted_chains`), x402, Visa TAP, and Mastercard Agent Pay.

A **Capital Intent is the regulated-capital-markets analog of an AP2 Intent Mandate**: where an AP2 Intent Mandate says "buy me running shoes under $120," a Capital Intent says "acquire $10k of SpaceX exposure, Reg S, accredited-only, best execution across these venues." It adds what commerce mandates don't have — **financial objectives** (Acquire/Exit/Rebalance/Hedge/Yield), a **regulatory regime**, **best-execution** semantics, and **securities transfer gating** (`erc3643`). It then **composes downward with AP2 Cart/Payment mandates** for the actual settlement legs, so the agent-payment-protocol war (Visa TAP vs AP2 vs x402 vs PayPal) is something Capital Intent rides *on top of* rather than competes with.

## Layered architecture

### Layer 0 — Compliant asset substrate (exists)
`crates/tenzro-token/src/erc3643.rs` — permissioned securities (`TransferRestrictions`, `IdentityClaim`, `TrustedIssuer`, `FreezeInfo`, `RecoveryEvent`, `SupplyLimits`); TDIP identity + W3C VCs + `KycTier`; multi-chain derivation; MPC custody; Chainlink CCIP (`tenzro-bridge/src/chainlink_ccip.rs`) + ERC-7802 CCT.

### Layer 1 — Proof-of-Reserve (SHIPPED, infra)
`tenzro-types/reserve.rs` (`ReserveAttestation { asset_id, reserves, source, attestor_did, attested_at, signature }`) + `tenzro_submitReserveAttestation` (verifies the attestor's Ed25519 signature) / `tenzro_getReserve`. So "1:1 backed" is a **protocol invariant**, not an issuer promise. Complements the existing Chainlink PoR reader (`tenzro-node/src/mcp/chainlink.rs`).

### Layer 2 — Attested mint (SHIPPED, infra)
`tenzro_attestedMint(token_id, to, amount, caller)` calls `TokenRegistry::mint_token` **only if** `post_mint_supply <= attested_reserves` (`ReserveAttestation::covers`). 1:1 backing becomes un-bypassable at mint time.

### Layer 3 — Capital Intent standard (SHIPPED, infra)
The typed intent + its open/quote/assign/execute/verify/settle lifecycle. Reuses the task-lifecycle + saga machinery (`tenzro_postTask`/`workflow*`), AP2 authorization, ERC-7683 settlement, and ERC-8004 solver scoring.

### Layer 4 — Solver agents & venues (ecosystem, build ON Tenzro)
Execution strategies, exchange/venue adapters (xStocks, Kraken, DEXs), and principal-side UX. Open market — not protocol.

### Institutional venues (why this matters most here)
Capital Intent is most valuable where capital is **regulated and cross-domain** — exactly the institutional rails Tenzro already integrates:
- **Canton** (`tenzro-bridge/src/canton.rs`, `canton_auth.rs`, DAML executor) — privacy-preserving institutional settlement; a Capital Intent can target Canton-settled tokenized assets while keeping the objective/holdings private, with `erc3643` compliance and AP2 ceilings enforced.
- **Chainlink CCIP** (`tenzro-bridge/src/chainlink_ccip.rs`) — the institutional cross-chain standard (Coinbase wrapped assets, Stellar, Jovay); Capital Intent uses CCIP/CCT lanes for cross-domain settlement legs, carrying transfer restrictions across chains.
An institutional desk can express one signed Capital Intent ("acquire $5M SPAX, Reg S, settle on Canton, hedge via CCIP to chain X") and have solver agents fulfil it under protocol-enforced compliance, custody (MPC), and capital ceilings — a primitive no current standard provides.

## The Capital Intent

```text
CapitalIntent {
  intent_id:       String,                 // caller-chosen, unique
  principal_did:   String,                 // who wants the outcome
  objective:       Objective,              // Acquire | Exit | Rebalance | Hedge | Yield
  constraints:     Constraints,            // slippage, deadline, venues, chains
  compliance:      ComplianceReq,          // reg regime, min KycTier, accredited_only
  authorization:   Authorization,          // AP2 mandate + delegation scope (hard ceilings)
  settlement:      SettlementReq,          // proof requirements, preferred route
  signature:       Vec<u8>,                // principal's DID-envelope signature over the canonical form
}

Objective =
  | Acquire   { asset_id, target_notional, max_unit_price }
  | Exit      { asset_id, quantity, min_unit_price }
  | Rebalance { targets: Vec<(asset_id, weight_bps)> }
  | Hedge     { asset_id, notional, instrument }
  | Yield     { asset_id, amount, min_apy_bps }

Constraints   { max_slippage_bps, deadline_unix, allowed_venues: Vec<String>, allowed_chains: Vec<String> }
ComplianceReq { reg_regime: RegRegime, min_kyc_tier: KycTier, accredited_only: bool }   // gates via erc3643
Authorization { ap2_mandate_ref, delegation_scope_ref }                                  // capital ceilings
SettlementReq { proof: ProofRequirement, preferred_route: Option<String> }               // verified via PoR + ERC-7683
```

`reg_regime` ∈ { `RegS`, `RegD`, `MiFIDII`, `Unrestricted` }. The intent is signed with the **shared DID envelope** (`tenzro-identity::envelope`) so any surface (RPC, MCP, A2A) can verify the principal authorized it.

## Lifecycle (reuses task + saga)

```
capitalIntentOpen(CapitalIntent)
  → verify DID envelope; check AP2 mandate ceilings; persist (CF_SETTLEMENTS, capital_intent:)
capitalIntentQuote(intent_id, solver_did, plan, price, eta)        // solver agents bid; ranked by ERC-8004 + KYA
capitalIntentAssign(intent_id, solver_did)                         // pick winner; lock principal escrow
capitalIntentExecute(intent_id) → runs as a SAGA:
  per leg: route to venue → ERC-7683 settle → erc3643 compliant transfer (can_transfer gate)
           → PoR-verify backing → record proof
  any leg fails → saga COMPENSATE (reverse-order rollback, refund escrow)
capitalIntentVerify(intent_id, proofs)                            // proof requirements satisfied?
capitalIntentSettle(intent_id)                                    // release escrow to solver; ERC-8004 feedback
capitalIntentGet(intent_id)                                       // read state
```

Every leg is **compliance-gated** (`erc3643::can_transfer`: KYC tier, jurisdiction, lock-up, freeze) and **capped** by the AP2 mandate / delegation scope. The saga guarantees atomic multi-leg execution with compensation — so a partial fill never leaves the principal exposed.

## Worked example — agent acquires SpaceX (pre-IPO) exposure

1. Principal signs `CapitalIntent { objective: Acquire { SPAX, $10k, max $X }, compliance: { RegS, KycTier>=Enhanced, accredited_only }, authorization: AP2 mandate ≤ $10k }`.
2. `capitalIntentOpen` verifies the envelope + AP2 ceiling; persists.
3. Solver agents quote (KYA-verified, ERC-8004-ranked); best is assigned; escrow locked.
4. `capitalIntentExecute` (saga): solver sources `SPAX` on an allowed venue → ERC-7683 settles → `erc3643` transfer enforces RegS + non-US + 12-mo lock → PoR confirms the token is share-backed.
5. Verify → settle → solver paid, ERC-8004 feedback written. Any failure → compensation refunds the principal.

## Reuse vs net-new

| Capability | Source |
|---|---|
| authorization ceilings | **reuse** AP2 (`ap2/mod.rs`, 4-ceiling validate) |
| capital guardrails | **reuse** `DelegationScope`, ERC-7579 validators |
| multi-leg execute + compensate | **reuse** saga (`tenzro_workflow*`) |
| settlement legs | **reuse** ERC-7683 + escrow + CCIP/CCT |
| compliance gating | **reuse** `erc3643::can_transfer` |
| solver trust/scoring | **reuse** ERC-8004 + KYA |
| backing verification | **build** Proof-of-Reserve (Layer 1) |
| compliant issuance | **build** attested-mint (Layer 2) |
| **CapitalIntent type + lifecycle + solver dispatch** | **build** (Layer 3) |

~80% reuses shipped primitives; the net-new is the typed standard, PoR, attested-mint, and the capital-specific solver dispatch.

## Infra vs ecosystem

- **Infra (Tenzro):** the `CapitalIntent` standard + `capitalIntent*` RPC family; the protocol-enforced invariants (AP2 ceilings, `erc3643` gating, PoR backing, ERC-8004 scoring); Proof-of-Reserve + attested-mint.
- **Ecosystem (build on Tenzro):** solver agents, venue/exchange adapters, execution strategies, principal-side and issuer UX, secondary markets.

## Phased rollout (P1–P6 SHIPPED 2026-06-06)

- **P1 — types + open/get** ✅ (`tenzro-types::capital_intent`, persistence, envelope verify, AP2 ceiling check).
- **P2 — quote/assign** ✅ (solver bids; assign auto-ranks by ERC-8004 reputation→price→eta; escrow lock).
- **P3 — execute** ✅ (per-leg record + best-execution check; saga compensate via `capitalIntentCompensate`).
- **P4 — verify/settle** ✅ (proof check, escrow release, ERC-8004 feedback).
- **P5 — Proof-of-Reserve + attested-mint** ✅ (`reserve.rs` + `submitReserveAttestation`/`attestedMint`/`getReserve`).
- **P6 — surfaces** ✅ (`tenzro capital` CLI, Rust + Python MCP tools, Python SDK; agent-kit reaches all via `NodeRpc`).
- **P7 — solver SDK + venue adapters** — ecosystem (build on Tenzro).

## Open questions

1. **Best-execution proof** — ✅ first cut shipped: `CapitalLeg.venue_quotes` + `best_execution_verified` (`best_execution_ok` checks the chosen price is best for the side). Remaining: make the venue-quote set *attested* (signed/oracle-anchored) rather than solver-asserted.
2. **Multi-venue atomicity** — cross-venue legs may not be atomic; the saga compensates, but partial cross-venue exposure windows need bounding.
3. **Privacy** — capital intents leak strategy; a sealed-bid / commit-reveal solver auction (cf. CoW batch auctions) may be needed.
4. **Solver collateral / slashing** — should solvers stake (bond) against non-performance, scored via ERC-8004 + the bond crate?

## References
- ERC-3643 — <https://www.erc3643.org/>
- ERC-7683 — <https://www.erc7683.org/spec>
- ERC-7521 — <https://eips.ethereum.org/EIPS/eip-7521>
- CoW Protocol intents — <https://cow.fi/learn/what-is-a-crypto-intent>
- xStocks — <https://blog.quicknode.com/xstocks-solana-tokenized-stocks-2025/>
- Tenzro: `erc3643.rs`, `ap2/mod.rs`, `intent_7683.rs`, saga (`multi-agent-workflow-coordination.md`), `tenzro-identity::envelope`, ERC-8004 dispatcher, MPC custody.
