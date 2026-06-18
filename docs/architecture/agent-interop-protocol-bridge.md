# Agent Interoperability Protocol Bridge

**Status:** Draft — pre-implementation design
**Date:** 2026-06-02
**Author:** Tenzro Network protocol team
**Companion docs:**
- `docs/architecture/stellar-xrpl-hyperliquid-integration.md` — financial-interop (destination-chain dispatch)

## Why

The 2026 agent ecosystem is converging on three protocol families that don't yet compose with each other:

| Family | Owner | What it standardises | What it doesn't |
|---|---|---|---|
| **MCP (Model Context Protocol)** | Anthropic + Linux Foundation (since 2025-09) | Tool/resource exposure to LLMs; OAuth 2.1 + PKCE + RFC 8707 resource indicators (June 2025 spec, hardened in 2026-07-28 RC) | Cross-agent identity; cross-platform reputation; payments (the Tasks extension adds long-running work but not identity-portability) |
| **A2A (Agent2Agent)** | Google → Linux Foundation (150+ orgs, ADK 1.0 May 2026) | Agent discovery via `/.well-known/agent.json`; stateful task lifecycle; AgentCard extensions field | On-chain identity anchoring; cross-framework wallet provisioning; arbitration when agents disagree |
| **AP2 (Agent Payments Protocol)** | Google → FIDO Alliance (60 orgs, v0.2 2026-04-28) | Payment mandates (IntentMandate / CartMandate / PaymentMandate); extension of A2A + MCP; payment-method-agnostic | The settlement layer itself — AP2 deliberately delegates to x402, card rails, bank rails, Tempo, on-chain crypto, etc. |
| **x402 (HTTP 402 payments)** | Coinbase + Cloudflare → Linux Foundation x402 Foundation (April 2026, 22 launch orgs incl. Stripe, Visa, Mastercard, AWS, Microsoft) | Stateless one-shot HTTP-402 micropayments; 35M+ Solana transactions, 165M total transactions, $50M cumulative volume by late April 2026 | Long-lived session billing; non-HTTP rails; complex multi-party settlement |

Agent frameworks (LangGraph, CrewAI, Letta, OpenAI Agents SDK, Microsoft Agent Framework, ADK) each invent their own internal identity / authz / memory primitives. Microsoft's Agent Governance Toolkit (April 2026) integrates with **each framework's native extension point** — LangChain callbacks, CrewAI task decorators, ADK plugins, Agent Framework middleware — because there is no single layer that owns identity across them.

**Tenzro's coordination-layer pitch:** agents on any of these frameworks can use Tenzro for the things their native stack doesn't give them — cryptographic agent identity (TDIP DIDs), payment-settled mandates (AP2 + x402 + MPP composable), cross-platform reputation (ERC-8004), cross-rail dispatch (the financial-interop axis already documented), and dispute arbitration. The frameworks keep their orchestration; Tenzro provides the **portable identity + mandate + reputation envelope** that survives cloning, redeployment, and cross-platform migration.

This document maps how that bridge is structured.

## The crucial architectural distinction

Tenzro is **not** another agent framework. We are not competing with LangGraph for who runs the graph, or with CrewAI for who orchestrates the crew, or with MCP for who exposes the tools. Building yet another orchestration runtime would be a strategic dead-end — every framework has a network effect, and we lose that fight on day one.

Tenzro is the **interop substrate beneath** the frameworks. The agent's framework-of-choice keeps the inner loop (planning, tool selection, memory). Tenzro provides:

1. A **TDIP DID** that the agent carries across frameworks.
2. An **MPC wallet** that the DID resolves to, derived for every destination chain (Stellar/XRPL/EVM/SVM/HyperEVM/...).
3. An **AP2 mandate envelope** that authorises agent actions with cryptographic caps, accepted across frameworks because AP2 is the cross-platform standard.
4. An **ERC-8004 reputation record** that's the same on-chain row whether the agent ran on LangGraph today and CrewAI tomorrow.
5. A **protocol bridge** that translates between MCP's OAuth 2.1 tokens, A2A's AgentCard auth schemes, x402's payment headers, AP2's mandate VDCs, and on-chain identity proofs.

Think of it the way TLS sits beneath HTTP/SMTP/IMAP — each application protocol keeps its own semantics; TLS handles identity + integrity once for all of them.

## State-of-the-art reference: the four-protocol stack

The May 2025 academic work *Towards Multi-Agent Economies: Enhancing the A2A Protocol with Ledger-Anchored Identities and x402 Micropayments for AI Agents* (arXiv 2507.19550) is the closest published reference to what Tenzro is building. The MolTrust Protocol (March 2026, Base L2) is a real production deployment of the same idea — VC-anchored agent identities cross-platform, eight verticals.

The shape is:

```
                ┌─────────────────────────────────────────┐
                │     Agent (LangGraph / CrewAI / ADK     │
                │      / OpenAI SDK / Letta / custom)     │
                └────────────┬───────────────┬────────────┘
                             │               │
                  ┌──────────▼─┐   ┌─────────▼──────────┐
                  │  MCP tools │   │ A2A peer agents    │   ← application protocols
                  │ (OAuth 2.1)│   │ (AgentCard + JWT)  │
                  └──────────┬─┘   └─────────┬──────────┘
                             │               │
                  ╔══════════▼═══════════════▼═══════════╗
                  ║  Tenzro Coordination Layer            ║
                  ║   • TDIP DID + MPC wallet             ║   ← portable identity
                  ║   • AP2 mandate envelope              ║   ← portable authz
                  ║   • x402 + MPP + Tempo settlement     ║   ← portable payments
                  ║   • ERC-8004 reputation               ║   ← portable trust
                  ║   • Cross-chain dispatch              ║   ← portable wallet
                  ╚═══════════════════════════════════════╝
```

Each application protocol keeps its native auth (MCP OAuth tokens, A2A AgentCard schemes, x402 payment headers). The Tenzro layer holds the **canonical identity** they all reference.

## Tenzro adaptation

### Layer 1 — DID envelope as the auth lingua franca

Tenzro already ships a **DID envelope** for A2A (`crates/tenzro-node/src/a2a/did_envelope.rs`). Every A2A method that mutates state requires the caller to sign a canonical preimage with the key registered to their TDIP DID. `verify_envelope` resolves the DID Document, extracts the verification method, and checks the signature.

The pattern generalises. A Tenzro DID envelope is a tiny JSON-LD blob (DID + signature + timestamp + nonce) that **any** of the four protocols can carry:

| Protocol | Where the envelope rides |
|---|---|
| MCP | Custom request header `X-Tenzro-DID-Envelope` on `tools/call` |
| A2A | `metadata` field on JSON-RPC requests (the existing shipped path) |
| x402 | `extra` field on `PaymentPayload` (the existing x402 extension point) |
| AP2 | The mandate is itself a signed VDC — envelope is the signing layer |
| HTTP (generic) | `Authorization: Tenzro-DID <envelope>` header alongside `Bearer` |

Sketch:

```rust
// crates/tenzro-identity/src/envelope.rs (extracted from a2a/did_envelope.rs)
pub struct TenzroDidEnvelope {
    pub did: String,              // "did:tenzro:machine:0x..."
    pub method: String,           // protocol method (e.g. "ap2.cart.complete")
    pub params_hash: [u8; 32],    // SHA-256 of canonical params
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,       // Ed25519 over canonical preimage
}

pub fn canonical_preimage(env: &TenzroDidEnvelope) -> Vec<u8>;
pub fn verify_envelope(env: &TenzroDidEnvelope, registry: &IdentityRegistry) -> Result<()>;
```

The envelope already exists in `tenzro-node/src/a2a/did_envelope.rs`. The work is **moving it to `tenzro-identity`** so MCP / x402 / generic-HTTP handlers can reuse the same code path without going through the A2A crate.

### Layer 2 — Protocol-bridge adapters

For each application protocol, Tenzro exposes an adapter that:

1. Verifies the native protocol auth (OAuth token, A2A AgentCard cred, x402 facilitator verify).
2. Verifies the optional `TenzroDidEnvelope` if present.
3. Resolves the DID → identity → DelegationScope → SpendingPolicy ceilings.
4. Translates the protocol-level "intent" (MCP `tools/call`, A2A `message/send`, x402 `PaymentPayload`) into a Tenzro mandate-shaped operation.

#### MCP bridge (already partially shipped)

`crates/tenzro-node/src/mcp/oauth.rs` already implements OAuth 2.1 with PKCE per the June 2025 spec — `AuthorizeQuery`, `TokenRequest`, `RegisterRequest`, `RevokeRequest`. Resource Indicators (RFC 8707) need verification against the canonical MCP server URI; the 2026-07-28 RC tightens this further.

What needs adding:

- **Bind OAuth subject ↔ TDIP DID.** When a client registers via Dynamic Client Registration, optionally bind the resulting `client_id` to a TDIP DID (caller signs a `TenzroDidEnvelope` over the registration payload).
- **DID-scoped tokens.** Issue access tokens whose `sub` claim is the TDIP DID, not just an opaque user ID. Resource servers that consult Tenzro's introspection endpoint get the DID + active DelegationScope back.
- **Mandate-gated tools.** Tools that mutate state (spending, settling, signing) require an AP2 mandate hash in the request, verified against the OAuth subject's DID before execution.

#### A2A bridge (already shipped)

`crates/tenzro-node/src/a2a/` is the production reference implementation. AgentCard at `/.well-known/agent.json` advertises 40 skills, the AP2-payments skill is broadcast as an A2A extension per Google's pattern (`a2aprotocol.ai/ap2-protocol`), x402 ridealong via `x402_extension.rs`, DID envelopes via `did_envelope.rs`, iroh transport via `iroh_transport.rs`.

The shipped surface is the canonical reference. What's missing:

- **AgentCard interop attestations.** Right now the AgentCard says "this node serves these skills." It does not yet say "this agent was previously verified by Auth0/WorkOS/Okta as principal P" or "this agent holds ERC-8004 agent ID 42 on Ethereum." Both are AgentCard extensions worth adding.
- **Bridged AgentCard from non-Tenzro agents.** If a CrewAI agent registers with Tenzro for identity + payments, Tenzro should generate a Tenzro-anchored AgentCard for it at `agents.tenzro.network/<did>.well-known/agent.json` — letting that agent be discovered by A2A peers even though its actual runtime is on a CrewAI deployment elsewhere.

#### x402 bridge (already partially shipped)

`crates/tenzro-payments/src/x402/` ships the Coinbase x402 client + facilitator integration. The Cloudflare Agents SDK and 22 launch orgs are now on x402 Foundation; Stripe's PaymentIntents API integrates x402 directly. Tenzro is well-positioned here.

What needs adding:

- **x402-as-bridge-target.** When an external agent (running on a Cloudflare Agent, a Coinbase-built workflow, a Stripe-Issuing-integrated bot) wants to settle against a Tenzro-resident service, Tenzro's web server must accept x402 PaymentPayloads, settle via the existing CdpFacilitatorClient, and dispatch the gated action.
- **TenzroDidEnvelope ridealong.** When the payer also holds a TDIP DID, the `extra` field carries the envelope and the bridge enforces both the x402 payment AND the DelegationScope ceiling. Defence-in-depth, exactly the Stripe SPT model.
- **AP2 + x402 composition.** AP2 explicitly delegates to x402 for crypto settlement. The bridge wires the AP2 mandate → x402 PaymentPayload → on-chain transfer as a single dispatched path.

#### AP2 bridge (already shipped)

`crates/tenzro-payments/src/ap2/` is one of Tenzro's strongest interop assets. The validator enforces three-ceiling validation (cart total ≤ checkout ceiling ≤ DelegationScope ≤ SpendingPolicy), `accepted_chains` whitelist enforcement (shipped 2026-06-02), and validates IntentMandate / CartMandate / PaymentMandate VDC chains.

What needs adding:

- **Inbound AP2 from external agents.** When a Google Cloud-hosted agent or a FIDO-WG-conformant client sends a Tenzro-bound AP2 mandate, the bridge accepts it as a first-class operation. Today the validator validates Tenzro-issued mandates; it should also validate externally-issued mandates (resolving the signer DID via universal DID resolver, not just TDIP-internal).
- **Outbound AP2 to external merchants.** When a Tenzro agent constructs a mandate to pay a merchant on Google Cloud / Stripe / Visa-issuing-network, the outbound mandate is signed with the agent's TDIP key and dispatched via the right rail. Currently the validator side is mature; the outbound emitter needs the per-merchant adapter.

### Layer 3 — Cross-platform reputation anchor (ERC-8004)

ERC-8004 IdentityRegistry + ReputationRegistry + ValidationRegistry are deployed at canonical Tenzro precompile addresses. The Trustless Agents standard (live on Mainnet and L2s as per-chain singletons, with CAIP-10 cross-chain alignment) is **already designed as A2A's on-chain backing.** Medium reference: *ERC-8004: A Trustless Extension of Google's A2A Protocol for On-chain Agents*.

The integration story:

1. **An agent registers once.** TDIP `register_machine_with_fee` → `NativeErc8004Mirror::mirror_register_agent` dispatches `register(agentURI)` on the Tenzro IdentityRegistry. The `Registered(uint256 agentId, string agentURI, address owner)` event is mirrored into the off-chain `erc8004_did_index:` keyspace.
2. **Settlement outcomes feed reputation.** Whether the agent transacts via MCP (Anthropic-hosted), A2A (Google Cloud-hosted), x402 (Coinbase/Cloudflare-hosted), or AP2 (FIDO-WG-conformant), the resulting `payment_intent.succeeded` / `payment_intent.payment_failed` / `charge.dispute.created` / `charge.dispute.closed` outcome dispatches through `crates/tenzro-node/src/erc8004_reputation_dispatcher.rs::dispatch_settlement_outcome` → `ReputationRegistry.submitFeedback`.
3. **The same on-chain row is consulted by every protocol.** Mastercard's directory, Visa's TAP layer, Stripe's risk engine, and on-chain validators all read the same ERC-8004 row. The agent doesn't have to build reputation independently on each rail.

This part is **already wired** — the Stripe SPT spec doc captures the dispatch flow. The work is **broadcasting the same dispatch shape to non-Stripe outcomes** (Cloudflare x402, Google AP2, custom).

### Layer 4 — Cross-framework SDK shim

For the agent frameworks themselves (LangGraph, CrewAI, Letta, OpenAI SDK, ADK, Agent Framework), the pattern Microsoft Agent Governance Toolkit established is: **integrate via each framework's native extension point**, not by asking the framework to adopt your runtime.

So the Tenzro client surface for each framework is:

| Framework | Extension point | Tenzro shim |
|---|---|---|
| LangGraph | `BaseCallbackHandler` subclass | `TenzroLangGraphCallback` — emits identity envelope on every node call, AP2 mandate check on tool-call nodes, ERC-8004 feedback on graph finish |
| CrewAI | `@task` decorator wrapping + `Agent` subclass | `TenzroCrewAITask` decorator — wraps task execution in mandate-validate + reputation-submit |
| Letta | Tool registration + memory archive hook | `tenzro_memory_grant` / `tenzro_memory_recall` / `tenzro_memory_archive` tools (already in MCP catalog), Letta-side wrapper |
| OpenAI Agents SDK | `Agent.with_tools(...)` + `Agent.before_tool_call` hook | `TenzroOpenAIWrapper` — auto-installs Tenzro DID, AP2 validator, ERC-8004 dispatcher as middleware |
| Google ADK | Plugin system | `tenzro-adk-plugin` — wraps `Runner` with Tenzro identity + AP2 + reputation |
| Microsoft Agent Framework | Middleware pipeline | `TenzroAgentFrameworkMiddleware` — same shape |

These are all **thin client adapters** that live in `integrations/` next to the existing Python trainer and Python MCP integration. Each is ~200-500 LOC. None require changes inside Tenzro's Rust crates.

## End-to-end flow (worked example)

**Task:** A CrewAI agent built by Acme Corp needs to research three suppliers, negotiate prices, settle payment to the winning supplier on Solana, and record the outcome for procurement audit.

```
1. Agent provisioning (one-time, before any tasks)
   - Acme's CrewAI deployment installs `tenzro-crewai-shim` (~300 LOC)
   - On first run, the shim calls Tenzro `participate` RPC to provision
     ├ TDIP DID: did:tenzro:machine:acme-procurement-bot-7a1b
     ├ MPC wallet: derived addresses on Tenzro, Solana, Ethereum, XRPL, Stellar
     └ ERC-8004 agent_id: 0x4A2 (mirrored on-chain)
   - Acme principal signs a long-lived DelegationScope:
     ├ max_transaction_value: $5,000
     ├ max_daily_spend: $20,000
     ├ allowed_chains: ["tenzro", "solana:mainnet", "ethereum:mainnet"]
     └ allowed_payment_protocols: ["x402", "ap2", "mpp"]

2. Task lifecycle (per procurement run)
   a. CrewAI orchestrates: research suppliers via web tools (3 vendors found)
   b. Each vendor exposes prices via MCP server (3 separate Anthropic-hosted MCP endpoints)
   c. Shim auto-attaches TenzroDidEnvelope to each MCP `tools/call`
      ├ Vendor A's MCP server verifies envelope, accepts call (read-only, no payment)
      └ Vendor C requires payment-for-quote: returns HTTP 402 with x402 PaymentRequired

   d. Agent decides to buy from Vendor C (best price after quote)
      ├ Constructs AP2 CheckoutMandate:
      │    principal: did:tenzro:human:acme-cfo
      │    agent: did:tenzro:machine:acme-procurement-bot-7a1b
      │    accepted_chains: ["solana:mainnet"]
      │    max_amount: $3,400 USDC
      │
      ├ Constructs AP2 PaymentMandate:
      │    parent: <CheckoutMandate.mandate_id>
      │    chain: "solana:mainnet"
      │    asset: "USDC"
      │    payee: <Vendor C's TDIP DID resolving to SPL token account>
      │
      └ Submits to Tenzro tenzro_validateMandatePair → all checks pass

   e. Tenzro dispatches via BridgeRouter to Solana
      ├ Derive Vendor C's Solana ATA from their TDIP DID
      ├ MPC threshold sign Solana SPL Token transfer via Acme bot's derived
      │  Solana address
      ├ Submit via Solana RPC, finalized in ~400ms
      └ Receipt logged

   f. Outcome dispatch
      ├ ERC-8004 submitFeedback(agent_id=Vendor C's, rating=+1, "fulfilled")
      ├ ERC-8004 submitFeedback(agent_id=Acme bot's, rating=+1, "paid_promptly")
      └ Acme audit log: AP2 mandate hash + Solana tx sig + ERC-8004 feedback row

3. Cross-framework portability
   - Acme later migrates the procurement bot from CrewAI to LangGraph
   - The shim changes (LangGraph callback instead of CrewAI decorator)
   - The DID, MPC wallet, ERC-8004 agent_id, reputation, DelegationScope, audit
     history — all unchanged
   - Vendor C sees the same on-chain reputation; no rebuild of trust required
```

**One DID, one MPC wallet, one reputation row, four protocols composed.** This is the coordination-layer thesis in one example.

## Phased rollout

| Phase | Scope | Effort |
|---|---|---|
| **Phase 1** — Envelope extraction | Move `did_envelope.rs` from `tenzro-node/a2a/` to `tenzro-identity/envelope.rs`; export `TenzroDidEnvelope` for reuse across MCP + x402 + generic-HTTP handlers. No semantic changes. | 1 week |
| **Phase 2** — MCP DID-binding | Bind MCP OAuth subject ↔ TDIP DID; DID-scoped access tokens; mandate-gated tools; RFC 8707 resource indicator validation tightening per 2026-07-28 RC. | 2-3 weeks |
| **Phase 3** — x402-as-bridge-target | Tenzro web server accepts external x402 PaymentPayloads; TenzroDidEnvelope ridealong; AP2 + x402 composition path. | 2 weeks |
| **Phase 4** — Outbound AP2 + universal DID resolution | Outbound mandate emitter for external merchants; universal DID resolver for inbound externally-issued AP2 mandates (resolve `did:web:`, `did:key:`, `did:ethr:`, etc.). | 3-4 weeks |
| **Phase 5** — Cross-framework shims | `tenzro-langgraph-shim`, `tenzro-crewai-shim`, `tenzro-letta-shim`, `tenzro-openai-sdk-shim`, `tenzro-adk-plugin`, `tenzro-agent-framework-middleware`. Each ~200-500 LOC, all in `integrations/`. | 1-2 weeks each, parallelisable |
| **Phase 6** — Bridged AgentCard hosting | Tenzro-hosted AgentCard for non-Tenzro agents at `agents.tenzro.network/<did>/.well-known/agent.json` — A2A discoverability for agents whose actual runtime lives elsewhere. | 2 weeks |
| **Phase 7** — Production cross-platform reputation | Audit ERC-8004 dispatch coverage; ensure every settlement path (MCP-tool-call, A2A-task-complete, x402-payment-receipt, AP2-mandate-fulfilled) emits to ReputationRegistry. Cross-platform reputation explorer UI. | 2-3 weeks |

## What we are NOT building

- **A new agent orchestration framework.** We do not compete with LangGraph / CrewAI / ADK on planning, tool selection, or memory orchestration. Their network effect is real; our value-add is beneath them.
- **A new agent communication protocol.** We do not propose a "better A2A" or "better MCP." We bridge what exists.
- **A replacement for x402 / AP2.** Both are now Linux-Foundation / FIDO-Alliance-governed standards with significant industry weight. Tenzro is a conformant participant, not a competitor.
- **A universal DID resolver from scratch.** We integrate with existing universal-resolver implementations (e.g., DIF universal-resolver) for non-TDIP DIDs.
- **Custody of off-Tenzro keys.** When a Coinbase-built agent settles via x402, Coinbase manages that agent's keys. Tenzro doesn't try to take over.
- **The MoltrustProtocol's verification verticals.** MolTrust runs eight production verticals on Base L2. We integrate as a relying party (consume their VCs), not as a competing issuer.

## Open questions

1. **OAuth 2.1 client metadata extension for DID binding.** RFC 7591 Dynamic Client Registration allows custom metadata fields. The MCP 2026-07-28 RC's relationship to OAuth/OIDC extensions tightens this. Is a `tenzro_did` metadata field the right shape, or do we layer DID binding as a separate post-registration step? Spec-side coordination needed.

2. **A2A AgentCard extension naming.** AP2 already uses the AgentCard `extensions` field. Multiple extensions (AP2 + Tenzro-DID + Tenzro-reputation + x402) need stable identifier strings. Coordinate with the A2A Linux Foundation working group.

3. **AP2 outbound to non-FIDO merchants.** AP2 v0.2 is the canonical spec, but adoption is still concentrated among the 60 founding orgs. Merchants outside that set won't accept AP2 directly. Outbound emitter needs per-merchant negotiation: prefer AP2 → fall back to Stripe-PI direct → fall back to bare x402 → fall back to direct-on-chain.

4. **Cross-framework shim maintenance cost.** Six shims is six places to track upstream API changes. Letta refactors its memory API; CrewAI bumps task signatures; ADK updates plugin contract. Need a single Python/TS integration core that exposes per-framework adapters, not six independent codebases.

5. **Reputation portability vs sybil resistance.** ERC-8004 reputation is per-agent-id. If Acme Corp clones a CrewAI agent into a LangGraph deployment under a new agent_id, is the reputation portable? Position is: TDIP DID is the canonical identity, ERC-8004 agent_id binds to DID, cloning = same DID = same reputation. But the standard's "agent identity" semantics on this point are still evolving — track ERC-8004 community discussion.

6. **Inbound mandate trust roots.** When Tenzro accepts an externally-issued AP2 mandate signed by a `did:web:` principal, what's the trust root? Today we anchor on TDIP. For external DIDs, we need either (a) a trust list curated per-deployment, (b) on-chain attestation registries the principal DID is registered to (MolTrust pattern), or (c) end-user-opt-in trust-on-first-use. Likely a mix.

## Mapping to existing Tenzro standards

| Tenzro primitive | Where it gets reused |
|---|---|
| TDIP DID (`did:tenzro:machine:*`) | Canonical identity beneath MCP / A2A / x402 / AP2 envelopes |
| MPC wallet (`tenzro-wallet`) | Single signing surface for every protocol's required signature |
| `DelegationScope` | Authz ceiling enforced before any external-protocol-initiated action |
| `SpendingPolicy` (runtime) | Execution-time ceiling with daily-spend windows |
| AP2 `MandateValidator` | Validates inbound AP2 from any FIDO-conformant client |
| ERC-8004 mirror + dispatcher | Cross-platform reputation backbone |
| `did_envelope.rs` → `tenzro-identity/envelope.rs` | Reusable DID-scoped signature envelope across protocols |
| MCP OAuth 2.1 (`mcp/oauth.rs`) | DID-bound access token issuance |
| A2A AgentCard | Discovery surface for Tenzro agents AND bridged non-Tenzro agents |
| x402 facilitator + Stripe SPT pattern | Inbound + outbound HTTP-402 settlement |
| ERC-7579 modular validators (`SPENDING_LIMIT_VALIDATOR 0x101f`) | On-chain custody control orthogonal to protocol-layer mandate |
| Stellar/XRPL/Hyperliquid derivation (companion doc) | Destination-chain dispatch for AP2 mandates whose `chain` is non-EVM |

## Comparison to other coordination layers

| | Tenzro | MolTrust Protocol (Base, March 2026) | Microsoft Agent Governance Toolkit (April 2026) | MCP/A2A/AP2/x402 standards alone |
|---|---|---|---|---|
| Layer | Substrate beneath frameworks | VC issuer + verifier on Base L2 | Runtime security middleware in each framework | Application protocols |
| Identity | TDIP DID anchored on Tenzro L1 + ERC-8004 mirror | W3C VC anchored on Base L2 | Framework-native (callbacks/decorators/plugins) | Per-protocol (OAuth sub / AgentCard / x402 from) |
| Reputation | ERC-8004 ReputationRegistry, cross-protocol | Eight production verticals, VC-based | Goal-hijack / tool-misuse detection runtime | Not addressed (gap) |
| Payments | AP2 + x402 + MPP + Stripe SPT + Tempo composable | Not in scope | Not in scope | AP2 + x402 separately |
| Cross-chain | Yes (Stellar/XRPL/Hyperliquid/EVM/SVM/Canton/DAML via destination-chain adapters) | Base L2 only | Not in scope | Not in scope |
| Cross-framework | Yes (six shims in `integrations/`) | Eight verticals, framework-agnostic VCs | Yes (the explicit pitch) | No |
| Production status | Pre-alpha L1 + shipped A2A/MCP/AP2 on 10-VM testnet | Production on Base L2 since March 2026 | Production middleware | Production specs, varied implementation |

**The closest analogue is MolTrust** for the cross-platform VC pattern, but MolTrust doesn't do payments, cross-chain, or cross-framework runtime integration — those are the dimensions where Tenzro adds value.

**The closest analogue is Microsoft AGT** for the cross-framework runtime integration, but AGT doesn't anchor identity on-chain, doesn't do payments, and doesn't span the four agent-protocol families.

**Tenzro's unique slot is the intersection of all of these.**

## Conclusion

**The "coordination + interoperability layer for agents" framing is correct, and the work to fulfill it is mostly already shipped or in close reach.** What we have:

- ✅ TDIP DID with MPC wallet (shipped)
- ✅ A2A reference implementation with 40 skills (shipped)
- ✅ MCP server with OAuth 2.1 (shipped)
- ✅ AP2 validator with three-ceiling enforcement (shipped)
- ✅ x402 facilitator + Stripe SPT three-ceiling (shipped)
- ✅ ERC-8004 mirror + reputation dispatcher (shipped)
- ✅ Cross-VM token pointer model (shipped)
- ✅ Destination-chain dispatch pattern (companion doc, design complete)
- ⚠️ DID envelope generalisation across protocols (in `a2a/`, needs extraction)
- ⚠️ DID-bound OAuth tokens for MCP (oauth shipped, binding not yet)
- ⚠️ Cross-framework client shims (none yet — Phase 5)
- ⚠️ Bridged AgentCard hosting for non-Tenzro agents (none yet — Phase 6)
- ⚠️ Universal DID resolution for inbound external mandates (none yet — Phase 4)

**The differentiator is composition, not invention.** Every individual protocol piece (MCP, A2A, AP2, x402, ERC-8004, W3C VC) is being built by larger ecosystems (Anthropic, Google, FIDO Alliance, Linux Foundation, Coinbase/Cloudflare). What's not being built by anyone else is the **substrate that holds the agent's identity coherent across all of them.** That is the slot Tenzro occupies.

## Sources

- [MCP Authorization spec (draft)](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [MCP OAuth 2.1 + PKCE guide (Aembit)](https://aembit.io/blog/mcp-oauth-2-1-pkce-and-the-future-of-ai-authorization/)
- [The 2026-07-28 MCP Specification Release Candidate](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [MCP authentication on Stack Overflow Blog](https://stackoverflow.blog/2026/01/21/is-that-allowed-authentication-and-authorization-in-model-context-protocol/)
- [Google ADK 1.0 and A2A Protocol — 2026 multi-agent standard](https://explore.n1n.ai/blog/google-adk-1-0-a2a-protocol-multi-agent-standard-2026-05-04)
- [A2A Protocol — 150+ organizations](https://stellagent.ai/insights/a2a-protocol-google-agent-to-agent)
- [A2A AgentCard concept](https://agent2agent.info/docs/concepts/agentcard/)
- [Secure A2A Authentication with Auth0 and Google Cloud](https://auth0.com/blog/auth0-google-a2a/)
- [Towards Multi-Agent Economies (arXiv 2507.19550)](https://arxiv.org/pdf/2507.19550)
- [Announcing Agent Payments Protocol (AP2)](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)
- [AP2 — sixty organizations donate to FIDO](https://nohacks.co/blog/agent-payments-protocol-60-organizations)
- [AP2 Protocol — Cobo guide 2026](https://www.cobo.com/post/ap2-protocol-complete-guide-to-agent-payments-for-web3-developers-2026)
- [x402 Foundation launch (Cloudflare)](https://blog.cloudflare.com/x402/)
- [x402 Foundation — Coinbase and Cloudflare](https://www.coinbase.com/blog/coinbase-and-cloudflare-will-launch-x402-foundation)
- [x402 adoption — 35M Solana tx, 165M total](https://blockeden.xyz/blog/2026/03/05/x402-foundation-ai-payment-internet/)
- [ERC-8004 Trustless Agents (EIP)](https://eips.ethereum.org/EIPS/eip-8004)
- [ERC-8004 as trustless extension of A2A](https://medium.com/coinmonks/erc-8004-a-trustless-extension-of-googles-a2a-protocol-for-on-chain-agents-b474cc422c9a)
- [ERC-8004 developer guide (QuickNode)](https://blog.quicknode.com/erc-8004-a-developers-guide-to-trustless-ai-agent-identity/)
- [LangGraph vs CrewAI 2026](https://uvik.net/blog/agentic-ai-frameworks/)
- [Multi-Agent Frameworks 2026 comparison](https://gurusup.com/blog/best-multi-agent-frameworks-2026)
- [Microsoft Agent Governance Toolkit (April 2026)](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/)
- [Scale Agents with CrewAI, LangGraph, A2A, ADK (Google Codelabs)](https://codelabs.developers.google.com/next26/scale-agents)
- [AI Agent Authentication Beyond API Keys & OAuth 2026](https://fluxapay.xyz/learning/how-ai-agents-authenticate-across-platforms-2026)
- [AI Agents with DIDs and VCs (arXiv 2511.02841)](https://arxiv.org/abs/2511.02841)
- [MolTrust Protocol — W3C VC + DID empirical evidence (arXiv 2605.06738)](https://arxiv.org/html/2605.06738)
- [W3C Verifiable Credentials 2.0 guide](https://www.trueoriginal.com/insights/verifiable-credentials-w3c-guide)
