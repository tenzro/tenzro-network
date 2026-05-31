# Agent Launch Test Plan

**Status:** Draft
**Owner:** Tenzro Labs
**Scope:** Tenzro-operated reference cohort + open-call partner cohort on testnet
**Goal:** Demonstrate sustained agentic transaction volume on the Tenzro Ledger to validate the protocol at scale and seed the partner ecosystem.

---

## 1. Sequencing

| Phase | Cohort | Purpose |
|---|---|---|
| **A** | Tenzro-operated reference agents (5 → 100+) | Harden `tenzro agent deploy`, dogfood the SDK, generate baseline volume, prove the templates work end-to-end |
| **B** | Open-call partner cohort 1 (~20 partners) | Stress-test multi-tenant isolation, surface real-world template gaps, broaden modality coverage |
| **C** | Permissionless deploy via `tenzro.com/launch` web UI | Self-serve agent registration once A and B have validated the path |

Phase A must run for ≥ 2 weeks of sustained green metrics before Phase B opens.

---

## 2. Block Capacity (verified)

Testnet capacity from the live config:

| Parameter | Value | Source |
|---|---|---|
| Block time | 400 ms | `crates/tenzro-consensus/src/config.rs:66` |
| Max block size | 2 MB | `crates/tenzro-consensus/src/config.rs:67` |
| Max gas per block | 30,000,000 | `crates/tenzro-vm/src/lib.rs` (`MAX_GAS_LIMIT`) |
| Gas per simple transfer | 21,000 | `crates/tenzro-node/src/rpc.rs:4159` |
| Theoretical max tx/sec | **~3,570** | 30M gas / 21k gas × 2.5 blocks/sec |
| Theoretical max tx/day | **~308 M** | 3,570 × 86,400 |

Headroom: every projection in this document stays below 5% of theoretical capacity. We are nowhere near the consensus ceiling.

---

## 3. Tenzro-operated Reference Cohort (Phase A)

Five fleet types running real economic loops. Numbers are sustained steady-state, not bursts.

| Fleet | Template | Count | Tx rate per agent | Daily volume |
|---|---|---|---|---|
| Payment routers (MPP / x402 / AP2 micropayments) | `intelligent_payment_router`, `mpp_payment_agent` | 50 | 1 tx/sec | ~4.3 M |
| Bridge arbitrage scanners | `bridge_arbitrage_scanner`, `cross_chain_liquidity_aggregator` | 20 | 1 tx / 10 s | ~170 k |
| Inference proxies (multi-modal) | `model_inference_proxy`, `agentic_inference_marketplace` | 30 | 1 inference + 1 settlement / 30 s | ~170 k |
| Yield + portfolio | `yield_rebalancer`, `multi_chain_portfolio_manager` | 20 | 1 tx / min | ~30 k |
| RWA + Canton | `autonomous_rwa_custodian`, `canton_trade_settler` | 10 | 1 tx / 5 min | ~3 k |

**Phase A target:** ~4.5–5 M tx/day, ~150 M tx/month sustained.

This is achievable on commodity GKE nodes — agents are orchestration loops, not heavy compute. No new node pool needed for Phase A.

---

## 4. Models — CPU-runnable Inventory

Per `tenzro-model` ONNX runtimes. Permissive or already-gated licenses only.

### Text embedding (`TextEmbeddingRuntime`)
| Model | Params | License | CPU OK |
|---|---|---|---|
| EmbeddingGemma-300M | 300 M | CommercialCustom (Gemma) | yes |
| BGE-M3 | 568 M | MIT | yes |
| Snowflake Arctic Embed L v2.0 | 568 M | Apache-2 | yes |
| Qwen3-Embedding 0.6B | 600 M | Apache-2 | yes (q8) |

### Vision (`VisionRuntime`)
| Model | Params | License | CPU OK |
|---|---|---|---|
| CLIP ViT-B/32 | 150 M | MIT | yes (~100 ms/image) |
| SigLIP2 base | 200 M | Apache-2 | yes |
| DINOv3 vits16 / vitb16 | 22 M / 86 M | CommercialCustom | yes |

### Timeseries (`TimeseriesRuntime`)
| Model | Params | License | CPU OK |
|---|---|---|---|
| TimesFM 2.5 | 200 M | Apache-2 | yes |

### Detection (`DetectionRuntime`)
| Model | Variant | License | CPU OK |
|---|---|---|---|
| RF-DETR | nano, small | Apache-2 | yes |
| D-FINE | n, s | Apache-2 | yes |

### Segmentation (`SegmentationRuntime`)
| Model | License | CPU OK |
|---|---|---|
| EdgeSAM | Apache-2 | yes (mobile-class) |
| MobileSAM | Apache-2 | yes |

### Audio ASR (`AudioRuntime`)
| Model | Params | License | CPU OK |
|---|---|---|---|
| Moonshine v2 tiny | 27 M | MIT | yes (real-time) |
| Moonshine v2 base | 61 M | MIT | yes |
| Distil-Whisper small.en | 166 M | MIT | yes (batched) |

### What needs GPU (defer)
| Template | Reason |
|---|---|
| `language_trainer`, `vision_trainer`, `timeseries_trainer` | Training, not inference. Wait for Phase 9 training infra. |
| `premium_alpha_advisor`, `video_analyst` | Larger models — GPU-preferred. Can demo on CPU with quality tradeoff. |

**15 of 18 reference templates run on CPU-only nodes today.**

---

## 5. Funding Model

### 5.1 Faucet (existing)

`tenzro_faucet` RPC. Address-based, not identity-gated — agents can call it with their auto-provisioned MPC wallet address.

- Default: 100 TNZO / call
- Max: 1000 TNZO / call
- Cooldown: configured `86400 s` (24 h) in `config/genesis-local.toml`, but **not currently enforced in `handle_faucet`** (`crates/tenzro-node/src/rpc.rs:3994`). UI-side rate limit is the de-facto throttle. **Action item:** wire the cooldown gate into the handler before Phase B opens (see §8).

### 5.2 Partner Charters (activation needed)

The right primitive for funding partner agents is `tenzro-token::seed_agent::SeedAgentEarmarkManager`. Already built; activation pending.

- `TreasuryEarmark` — genesis-funded carve-out separate from the 10 M faucet pool
- `Charter` — per-partner mandate with `SpendCaps`, `OperationKind` whitelist, `CounterpartyFilter`, `sunset` date
- `DecaySchedule` — 100/100/100 → 75 → 50 → 25 → 0 over 12 months (anti-camping)

Read RPCs already work (`tenzro_getTreasuryEarmark`, `tenzro_listSeedAgentCharters`). Write paths (governance-executor mutation, monthly decay enforcement, gossipsub topic) need to land before Phase B.

### 5.3 Tenzro reference cohort (Phase A)

Direct treasury allocation. We hold the keys, no Charter needed. Cost estimate at 5 M tx/day × 21k gas × 4 gwei = ~420 TNZO/day in fees, all paid back to the network treasury (book-keeping no-op).

---

## 6. Volume Targets

### Phase A (Tenzro-operated, weeks 1–4)
- **5 M tx/day, 150 M tx/month**
- ~58 tx/sec average — 1.6 % of theoretical capacity

### Phase B (open-call cohort 1, weeks 5–12)
- 20 partners × ~10 agents each × ~50 k tx/day per partner = **10 M tx/day, 300 M tx/month**

### Combined steady-state target (week 12+)
- **~15 M tx/day, ~450 M tx/month** of agentic settlement on testnet
- ~4 % of theoretical capacity — comfortable

### Notional GMV-equivalent
- Bounded by Charter `SpendCaps`. Plausible projection: **$50–200 M/month**.
- Always framed externally as a projection, not an actual payment volume.

---

## 7. Success Metrics

| Metric | Phase A target | Phase B target | Telemetry source |
|---|---|---|---|
| Sustained tx/day | 5 M | 15 M | block stream / `tenzro_getBlockRange` |
| Agent uptime | ≥ 99 % over 7-day window | ≥ 95 % | `AgentLifecycleInfo` heartbeats |
| Mempool admission failure rate | < 1 % | < 5 % | RPC error counters |
| Block fullness | < 50 % | < 80 % | block size headroom |
| Median block time | ≤ 500 ms | ≤ 500 ms | consensus telemetry |
| Settlement finality | ≤ 2 s | ≤ 2 s | `tenzro_getTransactionReceipt` |
| Multi-modal inference success | ≥ 99 % | ≥ 97 % | `UsageTracker` |
| Cross-chain settle success (Wormhole/LZ/CCIP/deBridge) | ≥ 95 % | ≥ 90 % | bridge adapter receipts |

---

## 8. Pre-launch Gates

Must be green before Phase A starts:

1. **Faucet cooldown enforcement** — wire the `cooldown_seconds` config from `[faucet]` into `handle_faucet`. Without it, Phase A agents can drain the 10 M TNZO faucet pool in hours.
2. **`tenzro agent deploy` end-to-end** — single command spawns from a template, provisions identity + wallet, registers, starts. Currently scaffolded; needs full path validation.
3. **Agent telemetry dashboard** — pod-level metrics per agent fleet. Without this we can't tell if a fleet is healthy.
4. **Charter governance executor write path** (Phase B gate, not A) — `SeedAgentEarmarkManager` mutation paths land + signed-by-governance proposal flow.

Must be green before Phase B opens:

5. Phase A has run ≥ 14 days at ≥ 90 % of target volume.
6. No critical incidents in the prior 7 days.
7. Public partner application form live at `tenzro.com/launch`.

---

## 9. Risks

| Risk | Mitigation |
|---|---|
| Faucet drain by uncapped agents | Wire cooldown enforcement (gate #1) before Phase A. |
| Agent fleet pod resource exhaustion | Start small (50 payment routers), scale after 48 h green. |
| Mempool flood from buggy partner agent | Charter `SpendCaps` + `OperationKind` whitelist; per-DID rate limit. |
| Bridge adapter failure cascade | Per-adapter circuit breaker already in `tenzro-bridge`; alert on > 5 % failure. |
| Reputation system gaming by partner | `tenzro-model::ProviderManager` reputation update (+1 / −5 asymmetry) makes farming costly; monitor for collusion patterns. |
| Optics: "self-trading inflates volume" | Distinguish Tenzro-operated vs partner volume in the public dashboard. Don't conflate. |

---

## 10. Open Questions

- Block-explorer view filtered by agent DID — does the existing explorer support this, or does the test plan need a new RPC?
- Partner application review SLA — who reviews, what's the acceptance bar?
- Public dashboard: same `tenzro.com/launch` page or separate `/launch/dashboard`?
- Should the open-call page link to the partner application form, or use an embedded form?

---

## 11. Verification References

- Block params: `crates/tenzro-consensus/src/config.rs:66-67`, `crates/tenzro-vm/src/lib.rs` (`MAX_GAS_LIMIT`)
- Faucet handler: `crates/tenzro-node/src/rpc.rs:3994-4200`
- Faucet config: `config/genesis-local.toml:31-36`
- SeedAgent system: `crates/tenzro-token/src/seed_agent/`
- Agent kit templates: `crates/tenzro-agent-kit/reference_templates/`
- Multi-modal catalogs: `crates/tenzro-model/src/{vision_catalog,forecast_catalog,text_embedding_catalog,segmentation_catalog,detection_catalog,audio_catalog,video_catalog}.rs`
