# Tenzro Network — Native primitives by ecosystem

**Internal research document. Dev tree only — never mirrored to public repos per `feedback_research_docs_dev_tree_only`.**

Tenzro Network is the far-reaching coordination layer for the decentralized agentic economy. Developers build AI-agent-native applications on Tenzro — exchanges, dApps, wallets, marketplaces, custody, settlement systems, prediction markets, content platforms, any class of application — and get two things together as native primitives in their development surface: **advanced agentic and AI features** (the unique value), and **deep interoperability across chains and ecosystems** (the reach). Both natively integrated. Both accessible through one TDIP identity, one MPC wallet, one settlement substrate.

This document catalogs the native primitive surface by ecosystem. Canton DAML is the first complete chapter. EVM, SVM, Bitcoin, and cross-ecosystem composition follow the same pattern. Native primitives means: actual operations that compose with each ecosystem's own conventions, plus the AI/agent capabilities that come uniformly from the Tenzro layer above. Not abstractions, not wrappers, not lowest-common-denominator integrations.

## Framework

For each ecosystem chapter:

1. **Ecosystem overview** — what the ecosystem is, what its core abstractions are, what state of the art looks like in 2026.
2. **Standards and CIPs/ERCs/SIPs** — every approved and in-flight standard relevant to building applications.
3. **Native primitives** — the concrete operations Tenzro exposes that compose with the ecosystem's own conventions. Per primitive: what it is, current state in Tenzro, what's needed, where AI/agent nativity composes.
4. **AI/agent leading-edge composition** — the surface that makes Tenzro distinctive in this ecosystem: party-scoped delegation + AI inference + mandate-bound autonomous workflows + cross-protocol composition + confidential reasoning.
5. **Reference applications** — the worked examples that demonstrate the primitives, shipping as agent-kit templates with end-to-end execution.
6. **Open work** — bugs, gaps, and prioritized engineering for this ecosystem.

The pattern is uniform across ecosystems. The AI/agent layer is what makes Tenzro the lead in each — Canton parties, EVM smart-account validators, SVM signer accounts, and Bitcoin script paths are different shapes of the same underlying authorization concept that the agent layer composes against.

---

## Chapter 1 — Canton DAML

### 1.1 Ecosystem overview (Canton 2026)

Canton is a privacy-preserving distributed ledger built around DAML, an institutional smart-contract language with first-class encoding of rights, obligations, and party-scoped visibility. The Canton Network is the public deployment of Canton, operated by a federation of Super Validators (SVs) running the Splice reference implementation against the Global Synchronizer.

State of the network as of June 2026:

- **Canton protocol version 35**, shipping in Canton 3.5.x. Released in 3.5.1 (May 27, 2026), with 3.5.2 (June 3, 2026) addressing OOM during synchronizer reconnect.
- **Splice 0.6.7** is current. Notable: LSU-only upgrade mechanism (HDM removed in 0.6.2), Serial ID alongside frozen Migration ID, CIP-104 traffic-based rewards incrementally rolled out, Wallet SDK v1 multi-party / multi-transport surface, token standard controller adds `getInstrumentById` / `listInstruments`.
- **Contract keys** are available in DAML-LF 2.3 onward (PV 35) — non-unique unlike Canton 2.x.
- **Institutional production volume**: DTCC tokenized U.S. Treasury custody, Broadridge DLR repo, Hashnote USYC stablecoin infrastructure, Brale institutional stablecoin, October 2024 institutional collateral pilots involving 27 market participants tokenizing gilts, eurobonds, and gold. Major SVs include Tradeweb, Broadridge, 7RIDGE, Circle, Chainlink, DTCC, Visa, Nasdaq, Apollo, Societe Generale, Franklin Templeton.

The Canton 2026 stack is mature for institutional asset settlement and emerging fast for agent-driven workflows. The agentic surface is the leading edge — most participants are still building observer-only tooling against the Scan API.

### 1.2 CIPs — comprehensive index (through CIP-0118)

The Canton Improvement Proposal process governs every change to validators, economics, and infrastructure through Super Validator vote (two-thirds supermajority). The full CIP catalog as of June 2026 is below, grouped by relevance to Tenzro's primitive surface.

**Token and asset standards:**
- **CIP-0056 — Canton Network Token Standard.** **Final.** Six core APIs: TokenMetadata, Holding, TransferInstruction, Allocation, AllocationInstruction, AllocationRequest. Defines wallet/asset/app composability, atomic DvP, pre-approvals, MergeDelegation, FeaturedAppRightV1/V2, BatchedMarkersProxy, WalletUserProxy. The foundational token primitive in the network — everything else composes against it.
- **CIP-0112 — Token Standard V2 (Privacy & Performance).** **Proposed.** Account-based model replacing simple Party references. Batch settlement with configurable privacy (intermediaries cannot observe unrelated transfers). Iterated settlement. EventLog interface replacing factory-choice event parsing. Committed Allocations for prefunded trading. Flexible timing on AllocationSpecification. V1↔V2 compatibility layer.

**Application and developer standards:**
- **CIP-0103 — dApp Standard.** **Approved.** Vendor-neutral dApp API decoupling network connectivity and key management from applications. Synchronous + asynchronous variants. Provider abstraction (`request`, `on`, `emit`). Standardized error codes aligned with EIP-1474. Methods: `connect`, `isConnected`, `disconnect`, `status`, `listAccounts`, `getPrimaryAccount`, `signMessage`, `prepareExecute`, `ledgerApi`. Events: `accountsChanged`, `statusChanged`, `txChanged`.
- **CIP-0047 — Featured App Activity Markers.** **Final.** Metrics for Featured Application tracking. Pre-CIP-0104 mechanism.

**Rewards and tokenomics:**
- **CIP-0104 — Traffic-Based App Rewards.** **Approved Feb 12, 2026.** Removes featured app markers; bases rewards on traffic actually spent on transactions changing app-managed state. Measured via sequencer/mediator data. Removes need for app builders to plant `FeaturedAppActivityMarker` contracts. Avoids using DSO party in app transactions solely for activity recording — reduces transaction size and SV validation overhead.
- **CIP-0073 — Weighted Validator Liveness Rewards.** **Approved.** Links liveness rewards to SV-determined parties.
- **CIP-0082 — Establish 5% Development Fund.** **Approved.** Foundation-governed development treasury.
- **CIP-0084 — Tokenomics Committee Price Tuning.** **Approved.** Delegates $/MB fee adjustment to committee.
- **CIP-0096 — Remove Liveness Rewards from Pool.** **Approved.** Restructures validator reward allocation.
- **CIP-0098 — Cap Per-Transaction App Rewards.** **Approved.** $1.50 maximum per application transaction.
- **CIP-0042 — Stable Price per Canton Coin Transfer.** **Active.** Synchronizer fee structure for consistent pricing.
- **CIP-0078 — Canton Coin Fee Removal.** **Final.** Eliminates fees on Canton Coin transactions.

**Featured App program:**
- **CIP-0116 — Featured App Staking.** **Active.** Mandatory capital locking for FA designation. Non-Issuer FAs: 5M CC per PartyId. Asset Issuer FAs: 25M CC per PartyId. 60-day vesting at 1/60 per day. Segregated PartyIds with Foundation notification.

**Cross-chain and interop:**
- **CIP-0086 — ERC-20 Middleware & Distributed Indexer.** **Approved.** Ethereum token compatibility layer.

**Operational:**
- **CIP-0064 — Delegateless Automation.** **Final.** Enables automated transactions without delegation. Highly relevant for agent runtimes.
- **CIP-0079 — SV Readiness Price Feed Integration.** **Approved.** Third-party feed demonstration for listing.
- **CIP-0092 — Dynamic Market Feeds Post-CC Listing.** **Approved.** Transitions pricing to market-based mechanism.
- **CIP-0107 — 24h Submission Delay for End-User CC.** **Approved.** Transaction timing requirement.
- **CIP-0117 — Logical Synchronizers.** **Approved.** Logical synchronizer architecture (the LSU mechanism).

**Process / structural:**
- **CIP-0000** — CIP Process.
- **CIP-0006** — Distribution & Approval Process.
- **CIP-0021** — Featured Application & Validator Committee.
- **CIP-0045** — SV Operating Requirements.
- **CIP-0051** — Streamline Onchain Governance Votes.
- **CIP-0105** — SV Locking & Long-Term Commitment.
- **CIP-0111** — SV Weight Reduction Process.

SV admission CIPs (CIP-0009 through CIP-0118 sprinkled throughout) admit specific organizations as SVs with assigned weights — Broadridge, LCV, Tradeweb, 7RIDGE, Copper, Dfns, MPCH, Lukka, Five North, Kiln, Obsidian, Hexagate, Copper Clearloop, Deribit, Circle, TRM, Elliptic, Coin Metrics, AngelHack, Figment, Bitwave, Quantstamp, IntellectEU, Zero Hash, Chainlink, Kaiko, LayerZero, Wormhole, Ledger, Ubyx, Fireblocks, BitGo, Zodia, Hypernative, Taurus, Republic, YZi Labs, DTCC, Talos, Bosphorus, Blockdaemon, Nasdaq, Tharimmune, QCP Group, Visa, Apollo, Further Asset Management, Societe Generale, Franklin Templeton, Merkle Science (Proposed).

### 1.3 Native primitives

For each primitive: **(a) what it is**, **(b) Tenzro current state**, **(c) what's needed**, **(d) AI/agent composition surface**.

#### 1.3.1 Identity and authorization

**Canton parties as a Tenzro credential class.**

(a) A Canton party is the authorization principle in Canton — every contract names parties as signatories, observers, controllers. Party rights (`CanActAs`, `CanReadAs`, `CanReadAsAnyParty`) are granted to Canton users through the User Management Service (CIP-26).

(b) The Tenzro Canton adapter at `crates/tenzro-bridge/src/canton.rs` speaks the JSON Ledger API v2 directly. Per-tenant API keys can carry a `canton_user_id` binding (e.g., `tenzro-labs@clients`) that maps to a Canton user's `primaryParty`. The adapter forwards `actAs = primaryParty(canton_user_id)` automatically. Multi-tenant isolation is enforced at Canton's AuthService.

(c) Extend the API-key record with **agent delegation fields** (already partially implemented in `crates/tenzro-node/src/api_key.rs` — `AgentDelegation` struct shipped with `can_act_as_parties`, `can_read_as_parties`, `allowed_templates`, `allowed_commands`, `max_per_command_amulet`, `max_per_day_amulet`, `requires_mandate_for`, `valid_until`). Wire the corresponding `CanActAs`/`CanReadAs` provisioning on Canton-side at issuance via `POST /v2/users/{userId}/rights`. Tear down both Tenzro key and Canton rights atomically on revoke. The party identity layer composes one-to-one with TDIP — a Canton party becomes a credential the agent's DID holds; revoking the DID's delegation on Tenzro side revokes the Canton-side rights in lockstep.

(d) **AI/agent composition**: an autonomous agent under a controller's delegation holds *scoped* Canton party rights — the agent can act as `tenzro-validator-1` for `Splice.Amulet:Amulet` transfers up to 1000 amulet per day, only with named counterparties, only after a controller-signed mandate. Triple-ceiling enforcement at signing time (delegation + spending policy + AP2 mandate) maps onto Canton's AuthService for primary-enforcement and Tenzro's RPC layer for defense-in-depth.

#### 1.3.2 JSON Ledger API v2 read surface

(a) Canton 3.5 exposes `POST /v2/state/active-contracts`, `GET /v2/state/ledger-end`, `POST /v2/state/events`, `GET /v2/state/connected-synchronizers`, `GET /v2/parties/known`, `GET /v2/users/{userId}/rights`, plus the package endpoints.

(b) The Canton adapter speaks all of these. Critical wire fact (fixed in this session): the 3.5 `/v2/state/active-contracts` request body uses an `eventFormat` wrapper, not the legacy top-level `filter` field. The 3.4 shape returns HTTP 400 `Invalid value for: body` against a 3.5 participant. Regression tests `active_contracts_request_uses_event_format_wrapper` and `wildcard_resolve_uses_event_format_wrapper` pin the bytes.

(c) Build a **scoped scan RPC surface** on top: `tenzro_canton_watchParty(party_fq, template_filter, since_offset)`, `tenzro_canton_streamEvents(party_fq, template_filter)`, `tenzro_canton_aggregateAnalytics(party_fq, template_filter, window)`. Each validates the API key's delegation authorizes the party/template, translates to per-party active-contracts + event queries, filters to only what the key sees. Server-Sent Events or chunked JSON-RPC for streaming.

(d) **AI/agent composition**: an agent's read surface is structurally bounded by what the controller delegated. An agent watching tokenized treasury contracts for NAV computation sees only the parties it's been authorized for; an agent doing margin-call surveillance sees only its position-line parties. Aggregate analytics across the agent's authorized scope produce dashboards that *respect Canton's privacy model by construction* — each agent's view of the network is bounded by its delegation. Different tenants see different views; this is correct, because each is bounded by their party permissions.

#### 1.3.3 JSON Ledger API v2 write surface

(a) `POST /v2/commands/submit-and-wait-for-transaction` accepts `JsCommands` containing `JsCommand` entries (`CreateCommand`, `ExerciseCommand`, etc.). Canton 3.5 requires the outer body nested under `commands` AND each individual command externally-tagged with the variant name.

(b) The Canton adapter at `submit_request_nests_jscommands_under_commands_key` (regression-tested) produces the correct wire shape. The handler `handle_submit_daml_command` in `rpc.rs` forwards through the multi-tenant API key path with `actAs` resolved from `canton_user_id → primaryParty`.

(c) Extend with **mandate-bound write capability**. Add an AP2 cart mandate parameter to `tenzro_canton_submitCommand` (and higher-level helpers like `tenzro_canton_transfer`, `tenzro_canton_dvpSettle`). Validate the mandate signature against the controller's TDIP identity. Map the AP2 item set onto the DAML command's template + counterparties + value. Enforce the triple ceiling. Bind the resulting DAML receipt to the mandate via `MandateRef`. Refuse without mandate when `requires_mandate_for` includes the command shape.

(d) **AI/agent composition**: an agent submits a `Transfer` command only with a controller-signed mandate authorizing the specific recipient + amount + asset. The mandate is the audit anchor — every settled DAML transaction reconciles to a Tenzro-side mandate hash. Cross-ledger audit: the workflow receipt on Tenzro side and the DAML transaction tree on Canton side both reference the same `MandateRef`, so an institutional auditor sees one consistent trail. AI agents acting on behalf of a controller produce an audit reconciliable across both ledgers.

#### 1.3.4 CIP-56 token standard

(a) The six APIs of CIP-56: TokenMetadata, Holding, TransferInstruction, Allocation, AllocationInstruction, AllocationRequest. Implemented as DAML templates with the factory pattern (stateless factories create instructions; external parties invoke through registries). UTXO model — Holdings are active contracts, optimize under ~10 UTXOs per user. Atomic multi-instrument DvP through coordinated factory exercises and disclosed contracts. MergeDelegation contracts for wallet-driven auto-consolidation. TransferPreapproval for recurring payments with offline approval + spending limits + automatic renewal + cancellation.

(b) **Largely missing in Tenzro**. The Tenzro Canton adapter speaks the JSON Ledger API but does not yet expose CIP-56 typed surfaces. The CIP-56 wallet integration patterns (registry lookup → factory exercise → choiceContextData) are not wrapped in any Tenzro RPC method today.

(c) Build a **Tenzro CIP-56 surface**:
- `tenzro_canton_listInstruments(filter)` — query the registry for available tokens.
- `tenzro_canton_getInstrumentById(instrument_id)` — fetch token metadata.
- `tenzro_canton_listHoldings(party_fq, instrument_filter)` — UTXO listing.
- `tenzro_canton_transferToken(from_party, to_party, instrument_id, amount, mandate?)` — full CIP-56 transfer flow with factory lookup and disclosed contracts.
- `tenzro_canton_createTransferPreapproval(from, to, amount, expiry)` — pre-approval lifecycle.
- `tenzro_canton_allocate(allocation_request)` — atomic DvP allocation.
- `tenzro_canton_settleBatch(allocation_specs)` — batch settlement via `SettlementFactory_SettleBatch`.
- `tenzro_canton_setupMergeDelegation(party_fq)` — wallet onboarding step for auto-merge.

Each wraps the underlying CIP-56 patterns so app builders don't reimplement them. Pin the wire shapes with regression tests.

(d) **AI/agent composition**: agents transact in CIP-56-compliant tokens (USDCx, cBTC, tokenized treasuries, money-market funds) under mandates. Pre-approvals let an agent execute recurring payments without per-transaction signoff. Allocation factories enable agentic DvP: agent observes a contract maturation, computes the settlement amount via an AI model (e.g., NAV calculation), executes the allocation through the standard. The agent doesn't know any one issuer's bespoke API — it speaks CIP-56 to all of them.

#### 1.3.5 CIP-112 token standard V2 (future)

(a) Account-based model replacing simple Party references. Batch settlement with configurable per-leg privacy. Iterated settlement for ongoing trading. EventLog interface replacing factory-choice event parsing. Committed Allocations for prefunded trading.

(b) Not in Tenzro yet (proposed CIP, not yet final).

(c) Track CIP-0112 status. When approved, ship CIP-56 + V2 dual-surface in Tenzro (same pattern Splice itself uses — V2 implementations expose both V1 and V2 interfaces simultaneously, assets advertise compatibility via `supportedApis` metadata). The Tenzro layer abstracts the version difference for app builders so they target a Tenzro surface that works across V1 and V2 underlying assets.

(d) **AI/agent composition**: Committed Allocations are a perfect AI-agent surface. An agent commits assets for a deadline-bounded trading window; the agent's mandate authorizes the commitment; the workflow handler observes the settlement event or the expiration and reacts. EventLog interface improves the agent's signal/noise — agents subscribe to standalone settlement events instead of parsing factory-choice exercise trees.

#### 1.3.6 CIP-103 dApp standard

(a) Vendor-neutral dApp API. Provider abstraction. Synchronous + asynchronous variants for browser-extension and remote/server-side wallets. Standardized methods: `connect`, `listAccounts`, `signMessage`, `prepareExecute`, `ledgerApi`. Standardized events: `accountsChanged`, `statusChanged`, `txChanged`. Error codes aligned with EIP-1474.

(b) Tenzro has its own wallet model (TDIP DIDs + MPC + ERC-7579 validators). Not currently CIP-103-conformant.

(c) Ship a **CIP-103-conformant adapter** that lets a Canton dApp speak the standard methods and have them resolve through Tenzro's wallet underneath. The dApp doesn't know it's talking to a Tenzro-backed wallet — it just sees CIP-103. Tenzro becomes a CIP-103-compliant wallet that a Canton developer can target without rewriting their app. The browser-extension variant is in `apps/tenzro-extension/`; extend it to expose CIP-103 alongside the existing EIP-1193/EIP-6963 EVM interface.

(d) **AI/agent composition**: agents act as CIP-103 dApp clients. An agent connects to a Tenzro wallet via CIP-103, prepares + signs + submits transactions through `prepareExecute`, subscribes to `txChanged` for reactive workflow advancement. CIP-103 conformance means agents work against any CIP-103 wallet — Tenzro is one, but tenants who bring their own institutional wallets keep working.

#### 1.3.7 CIP-104 traffic-based rewards

(a) App rewards now based on traffic actually spent on state-changing transactions. Measured via sequencer/mediator data. No need to plant `FeaturedAppActivityMarker` contracts. Avoids DSO party in app transactions for activity recording.

(b) Tenzro's Canton adapter does not yet reflect CIP-104 in its analytics or reward visibility.

(c) Extend `tenzro_canton_getMyAnalytics` to surface CIP-104 traffic counters (per-tenant traffic burn on state-changing transactions). Add an admin-token-gated `tenzro_canton_appRewardsBreakdown` showing the SV-side traffic-derived reward attribution. App builders see, through Tenzro, exactly the same traffic measurement the SV nodes use.

(d) **AI/agent composition**: an agent operating a Featured App earns rewards proportional to the traffic its workflows produce. The agent's runtime can target high-reward state changes by design — settling a batch atomically (one transaction, lots of state change) vs. settling individually (many transactions, less aggregate state change per transaction). Workflows can be optimized for reward yield at the protocol level, not just at the application logic level.

#### 1.3.8 Featured App Staking (CIP-116)

(a) 5M CC lock per PartyId for non-issuer Featured Apps, 25M CC for asset issuers. 60-day vesting. Segregated PartyIds.

(b) Not exposed in Tenzro.

(c) Once CIP-116 ships its DAML implementation, expose:
- `tenzro_canton_lockFeaturedAppStake(party_id, amount, kind)` — initiates the 60-day vesting lock.
- `tenzro_canton_getFeaturedAppLockStatus(party_id)` — observes remaining vesting + lock expiry.
- `tenzro_canton_unlockFeaturedAppStake(party_id)` — withdraws after vesting completion.

(d) **AI/agent composition**: an autonomous agent running a Featured App can self-manage its FA stake — lock at onboarding, observe lock health, top up automatically when foundation rules require, unlock at sunset. Stake management becomes part of the agent's workflow, not a manual operations chore.

#### 1.3.9 Splice Wallet SDK and dApp SDK

(a) `@canton-network/wallet-sdk` (low-level wallet provider/exchange surface — synchronizer auth, party allocation, ACS read, sign, submit). `@canton-network/dapp-sdk` (CIP-103 dApp client integration). V1 namespaces: `ledger`, `party`, `token`, `amulet`, `user`, `asset`, `events`.

(b) Tenzro has its own SDKs (`tenzro-sdk` Rust, `tenzro-ts-sdk` TypeScript) that target Tenzro RPCs.

(c) Ship a **CantonAgentClient** sub-client in both SDKs that wraps the Tenzro Canton agentic surface. Methods: `provisionAgent` (mints scoped API key + Canton user binding), `watchParty` (subscribed scoped stream), `submitCommand` (mandate-bound write), `transferToken` (CIP-56 wrapper), `allocate` (CIP-56 DvP), `revokeAgent` (atomic teardown). Internally the SDK speaks the canonical Splice token-standard wire shapes via the Tenzro adapter, so developers don't need to install `@canton-network/wallet-sdk` separately if they're going through Tenzro.

(d) **AI/agent composition**: 20 lines of app code replace 2000. An agent template provisions an agent + Canton bindings + watches contracts + submits commands + tears down — all through one cohesive Tenzro SDK surface. The AI/agent layer (inference, agent memory, MCP, A2A) is the same SDK; Canton is one destination among several.

#### 1.3.10 Splice Scan API integration

(a) Splice Scan exposes traffic data, app activity records (under CIP-104), validator/SV stats, governance state, holdings summary, update history. Endpoint list evolved through 0.6.x — some `/v0` endpoints deprecated (in 0.6.6: `top-validators-by-validator-faucets`, `top-providers-by-app-rewards`, `top-validators-by-validator-rewards`, `top-validators-by-purchased-traffic` removed). New `/v1/holdings/summary` in 0.6.3. New `/v2/updates/hash/{hash}` in 0.6.1.

(b) Tenzro's Canton adapter does not currently call Splice Scan directly.

(c) Build a **Splice Scan integration layer** in the Canton adapter. Expose:
- `tenzro_canton_scanQuery(endpoint, params)` — generic Scan API passthrough with admin-token gate (only Tenzro operators query Scan; per-tenant agents go through the scoped scan surface, which is different).
- `tenzro_canton_getTrafficBreakdown(window)` — aggregate traffic by app provider party.
- `tenzro_canton_getHoldingsSummary(party_fq)` — call `/v1/holdings/summary` filtered to the agent's authorized parties.
- `tenzro_canton_getGovernanceVotes(party_filter)` — for agents participating in governance.

(d) **AI/agent composition**: agents read Scan data to make decisions — observe holdings drift, traffic trends, governance proposals. AI-enriched: an agent watches governance vote behavior, classifies votes by topic via an embedding model, alerts the controller on high-impact proposals matching policy preferences. Scan-derived signals feed AI reasoning that drives Canton workflows.

#### 1.3.11 Validator and Super Validator operations

(a) SV admission via on-chain CIP vote. Validator onboarding via SV sponsor (`SPLICE_APP_VALIDATOR_SV_SPONSOR_ADDRESS`). Validator lifecycle via `validatorLifecycle` DAR. CIP-0073 weighted liveness rewards. CIP-0079 SV readiness price feed integration. CIP-0096 liveness rewards restructuring. CIP-0105 SV locking. CIP-0111 SV weight reduction process.

(b) Tenzro is not a Canton SV. The tenzro-validator-1 party is hosted on the canton-validator-devnet GKE participant.

(c) Not a primitive Tenzro needs to expose to app builders — SV operation is its own concern. However, if Tenzro Foundation pursues SV status (relevant for CIP-authoring authority), build:
- SV admission proposal authoring tools.
- Validator-app integration so a Tenzro-operated validator participates in the Splice validator-rewards system.
- Reward distribution surface so validators running Tenzro can claim CC rewards.

This is a Foundation-level decision, not an engineering primitive.

(d) **AI/agent composition**: agents could be SVs — an autonomous validator monitoring chain state, computing liveness contributions, voting on CIPs via policy. Tenzro-operated SV running an LLM-based governance assistant that classifies CIP voting recommendations. Highly speculative; not for first wave.

#### 1.3.12 Canton Coin operations and Splice token standard

(a) Native Canton Coin (CC) is the gas-equivalent on the synchronizer. CIP-78 removed CC transfer fees. CIP-104 directs CC rewards via traffic. CIP-66 governs unminted-pool minting. CIP-67 covers historical unclaimed rewards. CIP-107 sets a 24h delay for end-user CC submission.

(b) Canton Coin operations are exposed through `tenzro_canton_coinBalance` (CIP-56 balance lookup) and the unified CIP-56 token operations.

(c) Build CC-specific helpers:
- `tenzro_canton_tap(party_fq, amount)` — devnet/localnet faucet.
- `tenzro_canton_topupTraffic(party_fq, amount)` — extra-traffic purchase tied to validator-wallet config.
- `tenzro_canton_getRewardsHistory(party_fq, window)` — observed reward inflows.

(d) **AI/agent composition**: agents auto-manage their CC balance — top up traffic when running low, observe reward inflows for accounting, optimize timing of CC operations against the 24h submission delay where applicable.

#### 1.3.13 ANS (Amulet Name Service)

(a) Splice ships an Amulet Name Service for human-readable name resolution. DAR: `amuletNameService`.

(b) Not exposed in Tenzro.

(c) Add:
- `tenzro_canton_resolveAns(name)` — name → party id.
- `tenzro_canton_reverseAns(party_id)` — party → name.
- `tenzro_canton_registerAns(party_fq, name)` — registration flow (mandate-bound).

(d) **AI/agent composition**: agents use ANS to make their workflows human-legible. Receipts attached to mandates can name parties by ANS, so the audit trail reads naturally for non-technical reviewers.

#### 1.3.14 Delegateless automation (CIP-0064)

(a) Enables automated transactions without explicit delegation. Final CIP. Significant for agent runtimes — automation that does not require setting up a separate delegate party.

(b) Not currently exposed.

(c) Map CIP-0064 onto Tenzro's mandate model: a mandate-bound autonomous workflow is the natural delegateless-automation surface — the controller signs a mandate authorizing a specific class of operation, and the agent runs that class without a separate delegate party setup.

(d) **AI/agent composition**: simplifies onboarding for institutional users. An institution holds a Canton party, signs an AP2 cart mandate authorizing an agent to do specific operations under specific limits, and the agent operates within those bounds — no separate delegate party, no separate user account.

### 1.4 AI/agent leading-edge composition

The differentiator: Tenzro brings AI/agent capabilities to Canton that nobody else can credibly match. This is the leading edge — what we lead positioning with.

**Confidential AI inference inside a Canton workflow.** An agent runs a forecast model (TimesFM 2.5), a vision model (DINOv3), or a language model (Qwen 3, Granite, Mistral) inside a TEE attached to the agent's workflow execution. Sensitive Canton contract state (e.g., a bond's coupon schedule, a fund's NAV inputs, a settlement counterparty's KYC tier) feeds into the model without ever leaving the enclave. Result hashes commit on-chain; the actual model output is consumed by the agent's next workflow step. Settlement decisions are AI-informed without compromising Canton's privacy model.

**Distributed training on Canton-resident data.** Tenzro Train coordinates training across operators. A consortium of asset managers can collectively train a forecast model on their tokenized fund historical data — none of which ever leaves each participant's TEE enclave. The trained model is jointly owned, accessible to consortium members, and licensed via Canton-side governance. Sealed-shard manifests (`SealedDatasetManifest`) bind the training pipeline to the consortium's enrollment-time attestation.

**Multi-modal AI services callable from Canton workflows.** A workflow step says "examine this scanned bond indenture, extract the redemption clause, classify it against our institutional taxonomy" — and a vision + language model pipeline produces the answer, bills the consumer in TNZO through the inference router, and returns the result to the workflow. The model could run on any Tenzro provider's GPU; the result is verifiable; the audit trail reconciles to Canton.

**Agent memory scoped per Canton party.** An agent acting for `tenzro-validator-1` retains context across sessions about contracts seen, decisions made, mandates received — bounded to that party's authorization. Memory is queryable via vector search (Lance) or full-text (Tantivy) with hybrid RRF retrieval. Agents become long-running stateful entities. Cross-session continuity is what makes autonomous agents actually useful in institutional workflows.

**Mandate-bound autonomous workflows.** Long-running multi-step flows where an agent walks through a sequence (open intent → quote → verify → execute → settle → reconcile). Each step is mandate-authorized; each step's authority is bounded by the agent's delegation; the workflow's audit binds across Tenzro receipts and Canton DAML events. This is Workflow B — the longer-arc programmable orchestration of Canton operations under AI judgment + controller policy.

**Cross-VM composition.** An agent's workflow can settle the asset leg on Canton (privacy + finality) and the payment leg on EVM (liquidity) — both under the same identity, the same mandate, the same audit trail. Cross-VM token model means the same agent's TNZO balance pays for both legs without bridging. The mandate authorizes the whole workflow; the controller doesn't need to sign each leg.

**Confidential reasoning over private contract state.** An agent observing a Canton-tokenized treasury contract runs an LLM-driven analysis ("does this NAV calculation match the contract terms?") inside an attested enclave. The model never sees raw contract state on a cleartext path. The result is committed on-chain with a ZK proof of the model's output. Institutional reviewers can verify the result was produced by a specific model on specific inputs without anyone — including Tenzro's operators — seeing the inputs.

### 1.5 Reference applications

The Tenzro-agent-kit reference templates that demonstrate the primitives, shipped end-to-end as runnable demos:

- **DvP atomic-swap saga** (`dvp_atomic_swap_saga.json`). Asset leg on Canton, payment leg on EVM, AI-driven settlement pricing check, mandate authorizes the whole workflow.
- **Agentic NAV calculator** (`agentic_nav_calculator.json`). AI forecast model computes NAV on tokenized fund data, attested clock witnesses time-of-calculation, Canton workflow commits the result.
- **Agentic LC examiner** (`agentic_lc_examiner.json`). Vision + language model examines a scanned letter of credit, extracts terms, validates against template constraints, Canton workflow records examination result.
- **Agentic treasury rebalancer** (`agentic_treasury_rebalancer.json`). Multi-asset Canton-tokenized fund rebalancing under a controller mandate, AI policy classifier decides rebalance targets.
- **Agentic margin call** (`agentic_margin_call.json`). Position monitoring against a TEE-attested clock, margin-call workflow triggers under controller-defined thresholds.
- **Agentic bond pricer RFQ** (`agentic_bond_pricer_rfq.json`). Auto-pricing of bond RFQs using AI model under capital-intent mandates.
- **Agentic best-ex router** (`agentic_best_ex_router.json`). Best-execution routing across Canton venues + cross-chain settlement, AI-driven counterparty selection.

These exist as JSON manifests in `crates/tenzro-agent-kit/reference_templates/`. The Canton-side execution path needs end-to-end wiring; the manifests are the spec.

### 1.6 Open work for Canton

Prioritized engineering for the Canton primitive surface, in execution order:

1. **Bug fix shipped** — `tenzro_listDamlContracts` now uses CIP-3.5 `eventFormat` wrapper (this session). Image rebuild + fleet roll required.
2. **API key delegation schema** — `AgentDelegation` struct shipped (this session) with `can_act_as_parties`, `can_read_as_parties`, `allowed_templates`, `allowed_commands`, value caps, mandate requirements, expiration. Persisted in CF_API_KEYS.
3. **Canton-side rights provisioning** — wire `tenzro_createApiKey` with delegation fields to atomically grant matching `CanActAs`/`CanReadAs` via `POST /v2/users/{userId}/rights`. Roll back on partial failure. Mirror to revoke path.
4. **Tenzro-side RPC enforcement** — refuse out-of-scope party/template/command/value/mandate calls before forwarding.
5. **Scoped scan RPC surface** — `tenzro_canton_watchParty`, `tenzro_canton_streamEvents`, `tenzro_canton_aggregateAnalytics`. Server-side filtering to authorized templates.
6. **CIP-56 typed surface** — listInstruments, getInstrumentById, listHoldings, transferToken, createTransferPreapproval, allocate, settleBatch, setupMergeDelegation. Wraps the wallet-SDK patterns under Tenzro's adapter.
7. **Mandate-bound write capability** — AP2 cart mandate parameter on `tenzro_canton_submitCommand`, with validation against the controller's TDIP and the API key's delegation. Bind receipt to mandate via `MandateRef`.
8. **tenzro-workflow Canton execution backend** — `CantonCommand` step kind. Audit binds workflow receipt to DAML events.
9. **Reference templates wired end-to-end** — 7 Canton templates execute under mandates.
10. **CantonAgentClient** in Rust + TypeScript SDKs.
11. **CIP-103 dApp Standard adapter** in `apps/tenzro-extension/`. Tenzro becomes a CIP-103 wallet.
12. **CIP-104 traffic analytics extension** — `tenzro_canton_appRewardsBreakdown`. Per-tenant traffic counter visibility.
13. **Splice Scan integration layer** — generic and scoped Scan-API passthrough.
14. **ANS resolution helpers** — `resolveAns`, `reverseAns`, `registerAns`.
15. **Splice version drift monitor** — automated check in smoke battery that the participant version meets a configured floor.
16. **CIP-112 token standard V2 prep** — track CIP status; ship V1+V2 dual surface when V2 finalizes.
17. **CIP-116 Featured App staking flows** — when DAML implementation ships.
18. **Documentation** — comprehensive `docs/operators/CANTON_AGENTIC.md`, `website/src/app/docs/canton/page.tsx` extension, `website/src/app/docs/canton-agents/page.tsx` new page.

---

## Chapter 2 — Ethereum EVM (placeholder)

To be written in a follow-up sprint. Same structure as Chapter 1: ecosystem overview (Ethereum 2026 state), ERC standards index (4337 v0.8, 7579, 7683, 7702, 7802, 7943, 8004, Permit2, EIP-1559 evolution), native primitives (smart accounts, modular validators, intent-based UX, paymasters, cross-chain intents, trustless agent registries), AI/agent composition, reference templates, open work.

Notable areas to research: ERC-4337 v0.8 EntryPoint evolution, ERC-7579 modular account ecosystem (Safe, Biconomy Nexus, Rhinestone, Kernel), modular account interoperability standards, intent-based cross-chain UX (ERC-7683 + Across + UniswapX), paymaster economics, ERC-8004 trustless agent registries adoption, Ethereum's account-abstraction roadmap through 2026, EIP-7702 institutional adoption patterns.

## Chapter 3 — Solana SVM (placeholder)

To be written in a follow-up sprint. Same structure. Ecosystem overview (Solana 2026 state, including Firedancer, Token Extensions, compressed NFTs, ZK-compression), SVM-specific primitives, agentic Solana ecosystem (Squads, Sphere, Lighthouse, Drift's agent integrations), DePIN coordination, MEV protection (Jito), AI/agent composition, reference templates.

Notable areas to research: Token Extensions (transfer hooks, confidential transfers, interest-bearing tokens, permanent delegate), ZK-compression (Light Protocol), compressed NFTs (Bubblegum), agent runtimes on Solana, Squads multisig as institutional custody primitive, DePIN coordination patterns, Jupiter v6 swap composability.

## Chapter 4 — Bitcoin (placeholder)

Babylon-based BTC staking, finality providers, BTC-secured Tenzro validator subset. Native BTC-as-collateral patterns. Lightning Network integration for agent micropayments. Discreet log contracts (DLCs) as a primitive for agent-driven oracles.

## Chapter 5 — Cross-ecosystem composition

The chapter where the multi-ecosystem story comes together. How an agent composes across Canton + EVM + SVM + Bitcoin + off-chain rails in a single workflow under a single mandate, with one audit trail, settled in TNZO. This is where Tenzro's unique architectural position shows — agents don't choose between ecosystems; they compose across them.

---

## Maintenance

This document is the canonical primitive catalog for Tenzro's ecosystem coverage. Update conventions:

- New CIP / ERC / SIP approved: add to the relevant chapter index, note implications for Tenzro primitives.
- New Splice release: update the ecosystem state, note any wire-shape changes.
- Tenzro ships a new primitive in an ecosystem: update the "current state" line and the "what's needed" list.
- Bug or operational gap surfaces: cross-reference to `[[project_open_bug_inventory]]`.

Architectural decisions in the catalog cross-reference to memory:
- `[[project_agentic_canton_feature_strategy]]` — strategic posture
- `[[project_canton_rpc_api_key_model]]` — existing multi-tenant API key model
- `[[project_open_bug_inventory]]` — known bugs and operational gaps
