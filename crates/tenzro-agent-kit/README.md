# Tenzro Agent Kit

Template/bootstrap/resolver/spawner kit for the Tenzro Network agent marketplace. Declarative JSON templates describe an autonomous or specialist agent (capabilities, runtime requirements, pricing, delegation scope, execution steps) that can be registered on-chain, discovered by users, and spawned into a live `tenzro-agent` runtime.

## Scope

- **Template spec** (`src/spec.rs`) — the on-disk + on-chain JSON shape mirroring `tenzro_types::AgentTemplate`.
- **Registry** (`src/registry.rs`) — in-memory + persisted template catalog backed by `tenzro-storage` (`CF_AGENT_TEMPLATES`).
- **Resolver** (`src/resolver.rs`) — template-ID → spec resolution with optional creator-DID verification.
- **Bootstrap** (`src/bootstrap.rs`) — loads reference templates from `reference_templates/` into the registry.
- **Spawner** (`src/spawner.rs`) — converts a resolved template into a running `RegisteredAgent` via `AgentRuntime`.
- **Executor** (`src/executor.rs`) — runs the `execution_spec.steps` pipeline (skill invocations, tool calls, inference, settlement) with delegation / hard-cap enforcement.

## Paid Agent Marketplace

The agent marketplace supports paid templates from publication through settlement. Creators can publish templates that other users pay to invoke; the network collects a commission on every paid call.

### Creator identity (optional) and payout wallet (required for paid)

| Field | Semantics |
|-------|-----------|
| `creator_did: Option<String>` | Optional DID binding to one of TDIP's three identity classes — human (`did:tenzro:human:{uuid}`), delegated agent (`did:tenzro:machine:{controller}:{uuid}`), or autonomous agent (`did:tenzro:machine:{uuid}`). Immutable after registration. Used for reputation and attribution. |
| `creator_wallet: Option<Address>` | **Mandatory** for any non-`Free` `pricing`. Receives the creator share of every paid invocation. Registration fails with `MissingCreatorWallet` if omitted for paid templates. |
| `invocation_count: u64` | Monotonically incremented by `tenzro_runAgentTemplate`. |
| `total_revenue: u128` | Cumulative `fee_paid` credited across all invocations. |

### Pricing models (`AgentPricingModel`)

Canonical enum with externally-tagged serde form (`#[serde(rename_all = "snake_case")]`):

| Variant | JSON | Compact string form |
|---------|------|---------------------|
| `Free` | `"free"` | `"free"` |
| `PerExecution { price: u128 }` | `{"per_execution":{"price":N}}` | `"per_execution:<u128>"` |
| `PerToken { price_per_token: u128 }` | `{"per_token":{"price_per_token":N}}` | `"per_token:<u128>"` |
| `Subscription { monthly_rate: u128 }` | `{"subscription":{"monthly_rate":N}}` | `"subscription:<u128>"` |
| `RevenueShare { creator_share_bps: u16 }` | `{"revenue_share":{"creator_share_bps":N}}` | `"revenue_share:<bps>"` |

The compact string form is accepted by `tenzro_registerAgentTemplate`, the CLI `tenzro marketplace register`, and both SDKs (`registerAgentTemplate(pricing: AgentPricingSpec)` in TS, `register_agent_template(pricing: &str)` in Rust).

### Network commission

`MARKETPLACE_COMMISSION_BPS = 500` (5%). Defined in `tenzro_types::marketplace` and shared across all three Tenzro marketplaces (agent templates, skills, tools). On every paid `tenzro_runAgentTemplate`:

```
fee_paid          = pricing.price_for(tokens_estimate, max_iterations)
network_commission = fee_paid * 500 / 10_000
creator_share      = fee_paid - network_commission

payer_wallet     -= fee_paid            // debited
treasury         += network_commission  // credited to NetworkTreasury
creator_wallet   += creator_share       // credited to template.creator_wallet
template.invocation_count += 1
template.total_revenue    += fee_paid
```

The return value of `tenzro_runAgentTemplate` is a `RunAgentTemplateReport` containing every field above plus execution counts (`steps_executed`, `steps_failed`, `steps_skipped_by_dry_run`). `dry_run = true` skips fee collection and persistence; all other fields are reported for estimation.

Free templates bypass the fee-collection path entirely — `fee_paid = 0`, no treasury or creator credits are made, and `creator_wallet` is not required.

## Reference templates

Located under `reference_templates/`. They are loaded at node startup by `tenzro-agent-kit::bootstrap::load_reference_templates()`.

> **Distinct from workflow templates.** Multi-party Canton workflow specs live under `crates/tenzro-workflow/reference_workflows/` (see `crates/tenzro-workflow/README.md` once published, or `docs/SPECIFICATION.md` §14.7.10). Those describe lifecycle/obligation/approval graphs across multiple parties; the agent templates here describe a single autonomous or specialist agent and its execution pipeline.

| Template | Type | Pricing | Purpose |
|----------|------|---------|---------|
| `agentic_inference_marketplace.json` | orchestrator | free | Routes inference requests to the cheapest/fastest provider |
| `autonomous_rwa_custodian.json` | autonomous | free | RWA custody + on-chain attestations |
| `bridge_arbitrage_scanner.json` | specialist | free | Cross-chain bridge rate deltas |
| `canton_trade_settler.json` | specialist | free | Canton CIP-56 DvP settlement |
| `cross_chain_liquidity_aggregator.json` | orchestrator | free | Aggregates liquidity across LayerZero + CCIP + deBridge |
| `intelligent_payment_router.json` | specialist | free | Picks MPP / x402 / native based on context |
| `model_inference_proxy.json` | specialist | free | OpenAI-compat proxy to network inference |
| `mpp_payment_agent.json` | specialist | free | MPP challenge/credential/receipt |
| `multi_chain_portfolio_manager.json` | autonomous | free | Multi-chain portfolio rebalancing |
| `yield_rebalancer.json` | autonomous | free | Yield farming rebalancer |
| `timeseries_forecaster.json` | specialist | free | Timeseries forecasting via `tenzro_forecast` (TimesFM 2.5) |
| `vision_indexer.json` | specialist | free | Image embedding + similarity indexing via `tenzro_visionEmbed` (CLIP, SigLIP2, DINOv3) |
| `audio_transcriber.json` | specialist | free | Audio ASR via `tenzro_transcribe` (Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary) |
| `video_analyst.json` | specialist | free | Video frame embedding via `tenzro_videoEmbed` (encoder scaffolding) |
| `language_trainer.json` | autonomous | free | Coordinates language-model training runs over the Tenzro Train protocol |
| `vision_trainer.json` | autonomous | free | Coordinates vision-model training runs over the Tenzro Train protocol |
| `timeseries_trainer.json` | autonomous | free | Coordinates timeseries-model training runs over the Tenzro Train protocol |
| **`premium_alpha_advisor.json`** | **specialist** | **`per_execution: 5 TNZO`** | **Paid reference template demonstrating the full paid flow: `creator_did` binding, `creator_wallet` payout, 5%/95% fee split, read-only delegation with zero transaction caps** |

### Adding a new paid template

1. Define the JSON spec under `reference_templates/<your_template>.json`. Required paid fields:
   ```json
   {
     "template_id": "ref-your-template-v1",
     "creator_did": "did:tenzro:human:your-handle",
     "creator_wallet": [0,0,...,0,N],
     "pricing": { "per_execution": { "price": 5000000000000000000 } },
     ...
   }
   ```
2. Ensure `execution_spec.delegation` matches your risk appetite (advisory vs. transactional). Use `allowed_operations: ["read_only"]` and zero `hard_caps` for advice-only agents.
3. Register the template on a live node:
   ```bash
   tenzro marketplace register \
     --name "Your Template" \
     --description "..." \
     --template-type specialist \
     --creator-did did:tenzro:human:your-handle \
     --creator-wallet 0x...01 \
     --pricing per_execution:5000000000000000000 \
     --system-prompt "..."
   ```
4. Consumers invoke via:
   ```bash
   tenzro marketplace run \
     --agent-id <spawned-agent-id> \
     --payer-wallet 0x...02 \
     --tokens-estimate 1024 \
     --max-iterations 4
   ```
   Or equivalently via `tenzro_runAgentTemplate` RPC, the MCP `run_agent_template` tool, or `MarketplaceClient.run_agent_template()` / `MarketplaceClient.runAgentTemplate()` in the Rust/TS SDKs.

## License

Apache-2.0.
