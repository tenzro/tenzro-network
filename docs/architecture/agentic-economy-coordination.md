# Tenzro as the Protocol Coordination Layer for the Agentic Economy

**Status:** Master positioning + architecture gap-map (dev-tree). Folds all 2026 landscape research into one thesis and one build plan.
**Last updated:** 2026-06-06

## Thesis

The agentic economy is being built as two disconnected halves:

- **Asset rails** &mdash; major banks tokenizing deposits (shared bank deposit-token networks; deposit-token products on public chains), asset managers tokenizing funds, credit and equities ($34.5B RWA market → $30T by 2034 per industry forecasts), regulated stablecoins (GENIUS Act), pre-IPO (Republic/Jarsy/Kraken).
- **Agent rails** — autonomous trading/treasury agents everywhere (68% of new DeFi protocols ship one; Robinhood + Lumenai bring it to retail and funds; ElizaOS/Virtuals/exchange kits proliferate), but each in its own silo with its own wallet, its own policy, no shared identity or governance.

**Neither half owns the layer between them.** Tenzro's power, stated plainly: **give an agent a single identity and a single wallet, plus every feature it needs, to do whatever is required across multiple VMs, networks, chains, and protocols (CCIP, Canton, and others) — with compliance, governance, and accountability enforced as protocol.** No other stack does this end-to-end: the asset issuers won't (not their business), the agent frameworks can't (no neutral identity/custody/compliance/cross-domain substrate), and the bridges/intent protocols only move value — they don't carry identity, mandate, or compliance with it.

This doc is the consolidated map: the landscape, why the gap is Tenzro-shaped, the architecture (what exists), and the gaps to build.

## Landscape folded (2026)

| Domain | State of the art | Implication for the coordination layer |
|---|---|---|
| **Tokenized deposits** | JPM/Citi/BofA shared TCH network (H1 2027); Kinexys ($3T+) on Base; Citi Token Services | Regulated money is fragmenting across bank silos + public L2s → needs neutral cross-domain coordination |
| **RWA** | $34.5B (+100% YoY); BUIDL as DeFi+trading collateral ("Phase 2"); private credit > treasuries | Assets become composable collateral → agents must coordinate them across venues under compliance |
| **Stablecoin / CBDC** | GENIUS Act: 1:1 backing, issuers = financial institutions, BSA/AML + OFAC; wholesale CBDC bank-intermediated | Compliance (KYC/sanctions/travel-rule) must travel with every agentic transfer |
| **Pre-IPO / equities** | xStocks (Kraken), Republic rSpaceX, Jarsy — Reg S, KYC-gated, ERC-3643 | Permissioned-transfer + identity gating is mandatory, not optional |
| **Intents** | ERC-7683 (settlement), ERC-7521 (general), AP2 Intent Mandate (commerce), CoW/Anoma solvers | A capital-objective intent layer is missing; solver models carry centralization risk |
| **Agentic payments** | AP2 (Google + 60 orgs), x402 (Linux Foundation, Visa/Stripe), Visa TAP, Mastercard | Payment-protocol war below; the coordination layer must ride on top of all of them |
| **Agentic trading** | Exchange agent kits (Kraken/Binance/OKX 60+ chains), DeFAI (ElizaOS/Virtuals), Robinhood retail, Lumenai fund; 80% of DeFi TVL agent-managed by 2030 | Execution is solved but siloed per venue; no neutral cross-venue intent + identity layer |
| **Agentic governance** | NIST AI Agent Standards (Feb 2026); Singapore Agentic AI Framework (Jan 2026); FINRA 2026; CA AB 316; TRM: $2.87B stolen, key-compromise → cross-chain dispersion | Identity, accountability, human-in-the-loop, custody, traceability are now *regulatory requirements* |

## Why the gap is Tenzro-shaped (and unfilled)

- **Major asset issuers** (deposit-token banks, large RWA fund managers, stablecoin issuers) build walled money/asset rails &mdash; they will not build a neutral, cross-competitor coordination layer.
- **Agent frameworks** (ElizaOS, Virtuals, exchange kits) build execution — each with its *own* wallet, *own* policy, *no* shared identity, custody, compliance, or cross-domain settlement.
- **Bridges / intent protocols** (CCIP, Wormhole, ERC-7683) move *value* — they don't carry *identity, mandate, or compliance* with the value.

Tenzro is the only stack combining all four missing dimensions: **single identity + single wallet + cross-VM/chain/protocol coordination + compliance/governance as protocol.**

## Architecture — the coordination spine (what exists)

### Layer A — One agent identity
`tenzro-identity`: TDIP DIDs (`did:tenzro|key|web|ethr`), W3C verifiable credentials (`credential.rs`, `w3c.rs`), **Know-Your-Agent** (`kya.rs`), `KycTier` (Unverified→Full), registry + universal resolver, signed **DID envelope** verified across every surface (RPC/MCP/A2A). One identity an agent carries everywhere.

### Layer B — One wallet, every chain
`tenzro-identity/derivation.rs`: single-seed **chain derivation to 17 targets** (Stellar, XRPL classic + EVM, HyperEVM, Ethereum, Base, SVM, …). `tenzro-wallet` + **MPC threshold custody** (`mpc/{keygen,sign,refresh}` + ReKey) — no single key to steal. **Account abstraction** (`tenzro-vm`: ERC-4337 + ERC-7579 + WebAuthn/TEE-bound/delegation/paymaster validators). One wallet, threshold-secured, programmable, addressable on every chain.

### Layer C — Every VM
`tenzro-vm`: **EVM** + **SVM** executors, **DAML** (Canton), a **native** VM, and a **cross-VM bridge** (`cross_vm_bridge.rs`) + parallel execution. An agent acts across execution environments through one account.

### Layer D — Every network, chain & protocol
`tenzro-bridge`: **CCIP** (`chainlink_ccip.rs`), **Canton** (`canton.rs`/`canton_auth.rs`), Wormhole, LayerZero, deBridge, LiFi + **router** + **circuit breaker**; **ERC-7683** intents; **ERC-7802** cross-chain mint/burn (CCT). `tenzro-network`: libp2p transport/gossip/discovery + MPC relay. Value + messages move across domains.

### Layer E — Agentic coordination standards
A2A, MCP (Rust + Python), **AP2** + **x402** + MPP + Visa TAP + Mastercard Agent Pay, **ERC-8004 reputation**, **saga** workflows (Execute→Verify→Compensate), task lifecycle, **agent-kit**, and the new **Capital Intent** standard (`capital-intent.md`). How agents express intent, get paid, build reputation, and run multi-step work.

### Layer F — Compliance, trust & settlement
`erc3643` permissioned securities; compliance/sanctions/travel-rule modules; EU AI disclosure; **TEE attestation** (`intel_tdx`), ZK, settlement proofs, Merkle; `tenzro-settlement` escrow; `tenzro-token` (TNZO, adaptive-burn, staking, bond); HotStuff2 consensus.

## Audit (2026-06-06): what already exists vs. the genuine gaps

A complete codebase audit shows the coordination architecture is **essentially complete** — almost every capability the 2026 landscape demands already ships. An earlier draft of this doc overstated the work; corrected below, grounded in modules.

### Already shipped — NOT gaps

| Capability | Where it lives |
|---|---|
| **Unified Agent Account** (the "headline") | **TDIP `TenzroIdentity`** — DID + auto-provisioned **MPC wallet** (`wallet_address`/`wallet_id`) + `IdentityData::Machine{ delegation_scope, controller_did, reputation, erc8004_agent_id, capabilities }` + Ed25519/ML-DSA-65/BLS keys + credentials + services. **TDIP was built for exactly this.** |
| Compliance-as-protocol | **`tenzro-token/erc3643.rs`** — `ComplianceRules`, `can_transfer`, `IdentityClaim`, `TrustedIssuer`, whitelist/country/freeze/recovery/supply-limits + `tenzro-auth/aap.rs` |
| Governance & accountability | **`tenzro-token/governance.rs`** (`GovernanceEngine`: proposals/voting/tally) + kill-switch + quarantine + approval + KYA + ERC-8004 |
| Bonding & slashing | **`tenzro-token/bond.rs`** (`AgentBondState`, insurance pool, bond vault) + `sla_slashing_bridge.rs` + staking slashing |
| Proof-of-Reserve (reading) | **`tenzro-node/mcp/chainlink.rs`** — Chainlink PoR feeds (WBTC/USDC/TUSD, `latestRoundData`) + `treasury.rs::backing_ratio` |
| Cross-VM / cross-chain | bridge **`router.rs`** + `cross_vm_bridge.rs` + CCIP/Canton/Wormhole/LayerZero/deBridge/LiFi + ERC-7683/7802 |
| Observability / audit | `event_loop.rs`, `snapshot.rs`, reputation dispatchers, `rpc_integrations.rs`; per-intent trail via `CapitalIntentRecord.legs` |
| Capital Intent standard | `tenzro-types/capital_intent.rs` + `tenzro_capitalIntent*` RPC + MCP/SDK/CLI (shipped this cycle) |
| Agentic payment standards | AP2, x402, MPP, Visa TAP, Mastercard Agent Pay |

### The three genuine gaps — NOW SHIPPED (2026-06-06)

All three remaining protocol-layer seams were implemented this cycle, reusing existing subsystems (no duplication):

| Gap | What was shipped |
|---|---|
| **Attested-mint** | `tenzro-types/reserve.rs` (`ReserveAttestation`) + `tenzro_submitReserveAttestation` / `tenzro_attestedMint` / `tenzro_getReserve` RPC. `attested_mint` gates `TokenRegistry::mint_token` on `post_mint_supply <= attested_reserves` — 1:1 backing is now a protocol invariant. Reuses the existing Chainlink PoR reader (`mcp/chainlink.rs`) as a complementary source. |
| **Capital Intent solver selection** | `capitalIntentAssign` now auto-ranks quotes by **TDIP/ERC-8004 reputation → lowest price → fastest eta** (`auto: true` or omit `solver_did`), via `agent_reputation()` over the resolved machine identity. |
| **Best-execution proof** | `CapitalLeg.venue_quotes` + `best_execution_verified`; `capitalIntentExecute` records the solver's observed venue quotes and flags whether the chosen price is best for the side (`best_execution_ok`). |

Surfaces wired for all three: node RPC + dispatch, Rust MCP tools, Python MCP tools, Python SDK, and the `tenzro capital` CLI.

### Not protocol-layer — ecosystem (Tenzro must NOT build)
Lending / RWA-as-collateral markets, stablecoin issuance, tokenized-deposit products, secondary markets / orderbooks, the solver agents / strategies themselves, and venue / exchange adapters. These build *on* Tenzro.

## Regulation alignment (by construction)

| Framework (2026) | Requirement | Tenzro primitive |
|---|---|---|
| NIST AI Agent Standards | interoperability, security, testing/eval | A2A/MCP + MPC/TEE + dry-run/adversarial verify |
| Singapore Agentic AI | risk-bounding, human accountability, controls, responsibility | AP2/delegation ceilings, KYA identity, kill-switch, saga audit |
| FINRA 2026 / CA AB 316 | traceability, no "autonomy" liability defense | ERC-8004 + saga audit trail + identifiable mandates |
| GENIUS / BSA / OFAC | KYC, AML, sanctions, travel-rule on regulated money | `erc3643` (shipped) |

## Roadmap (status)

The coordination spine is shipped, and the three remaining seams (attested-mint, solver selection, best-execution proof) shipped 2026-06-06. The architecture is now complete at the protocol layer; further work is ecosystem (solver agents, venue adapters, products) — built *on* Tenzro.

## Roadmap (historical — the genuine remaining work)

The coordination spine is **shipped**. Per the audit, only three small protocol-layer seams remain, in order:
1. **Attested-mint** — gate `mint_token` on the existing PoR reading (1:1 backing as invariant).
2. **Capital Intent solver selection** — wire ERC-8004/KYA ranking + bonded selection into `capitalIntentAssign` (reuse `erc8004_reputation_dispatcher` + `bond.rs`).
3. **Best-execution proof** — attested per-leg venue-quote set.

Everything else is already shipped or is ecosystem (build on Tenzro, not in it).

## What Tenzro must NOT build
Not a bank, asset issuer, stablecoin issuer, exchange, or trading strategy — those are incumbents' and the ecosystem's. Tenzro is the **neutral coordination layer**: one agent identity, one wallet, all features, across every VM/network/chain/protocol — the connective tissue of the agentic economy.

## References
- `capital-intent.md`, `multi-agent-workflow-coordination.md`, `task-coordination-lifecycle.md`
- Landscape sources (2026): bank deposit-token launches and announcements (industry press), BUIDL-class tokenized money-market fund rollouts (industry press), GENIUS Act, AP2 (public consortium), ERC-7683/7521/3643, agentic-trading product launches across exchanges and brokerages, NIST + Singapore agentic-AI governance, agent financial-crime research.
