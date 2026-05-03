---
title: "Workers of a New Kind"
subtitle: "The agent economy is being built between two closed walls. Here's the open one."
date: 2026-05-01
author: Tenzro
slug: workers-of-a-new-kind
canonical_url: https://tenzro.com/blog/workers-of-a-new-kind
og_image: /og/workers-of-a-new-kind.png
reading_time: 11 min
tags: [agentic-commerce, decentralized-ai, tee, identity, mcp, a2a, erc-8004, plonky3, workers-day]
---

# Workers of a New Kind

## The agent economy is being built between two closed walls. Here's the open one.

May 1, 2026

---

## I. A new kind of worker

A growing share of the world's productive labor in 2026 is performed by software agents. Not the marketing kind that fronts a chat box, but the autonomous kind. They write production code, settle stablecoin payments, run analyses, draft contracts, ship support across time zones, route logistics, and increasingly do the work that twelve months ago required a team.

Stanford's Future of Work group has been auditing the actual scope. Juniper Research projects agentic commerce will move from $8 billion in 2026 to $1.5 trillion by 2030. McKinsey models a $3-5 trillion global shift, with AI agents responsible for $1 trillion in U.S. transactions alone. IDC forecasts that 40% of Global 2000 roles will involve direct interaction with AI systems by year-end. Investors expect 2026 to be the year corporate budgets start moving from labor lines to AI lines.

The labor force has changed. The infrastructure that working class runs on is being built right now, in public, by a small number of very large companies — and it is being built closed on both sides.

This essay is about that, and about the open alternative we've been working on.

---

## II. The closed sandwich

A worker needs two things to function: the ability to do the work, and the ability to be paid for it. For software agents in 2026, both layers are already being built — and both are being built as closed verticals.

### The closed labor side

If your agent needs to think, it talks to one of a small number of foundation-model APIs. **OpenAI** owns one. **Anthropic** owns one. **Google** owns one. xAI, Cohere, Mistral, and a few others fill in the edges. The big three together account for the overwhelming majority of agent-driven inference traffic in production today.

This is not a complaint about the quality of those models. The quality is the reason they win. The structural fact is that an agent's *capacity to reason* is a managed service rented from one of three companies, with terms-of-service that can change, rate limits that can be lowered, and access that can be revoked. If your agent loses access to its model provider, your agent stops working. There is no fallback layer at the protocol level — only the engineering project of swapping API clients, which most production agents don't have time to do.

### The closed wages side

If your agent needs to pay for something — an API call, a piece of data, another agent's labor, a SaaS subscription priced in stablecoins — the rails for that are also being built closed.

In the last sixty days alone:

- **Stripe Tempo** went live with a mainnet on March 18, paired with the Machine Payments Protocol. Visa, Standard Chartered, and Zodia Custody are validators. Mastercard, UBS, Klarna, DoorDash, Coastal Community Bank, Fifth Third, ARQ, and Howard Hughes are running payment operations on it.
- **Coinbase's x402 protocol** moved to the Linux Foundation on April 2 as the x402 Foundation. Cloudflare and Stripe are on the governing body, with AWS, American Express, Visa, Microsoft, and Ant International signaling support. ~69,000 active agents have already pushed more than 165 million transactions through it.
- **Google AP2** launched with sixty-plus partners — Mastercard, American Express, PayPal, Adyen, Worldpay, UnionPay, Salesforce, ServiceNow, Intuit — and was donated to the FIDO Alliance. AP2 v0.2 introduced "Human Not Present" payments. The `A2A x402` extension was co-built with Coinbase, the Ethereum Foundation, and MetaMask.
- **Mastercard Agent Pay** issues "agentic tokens" — credentials scoped to a specific AI agent with programmable spend limits and counterparty allowlists. **Visa Intelligent Commerce** does the same on its rail, integrating with OpenAI, Anthropic, and Microsoft.

This is genuinely good progress. AI agents now have legitimate ways to make payments inside the existing financial system. But every one of those rails is a vertical owned by one company. Stripe owns Tempo. Coinbase incubated x402. Google authored AP2. Visa and Mastercard issue the credentials.

### The sandwich

Stack the two sides together and the agent economy looks like this:

```
                         AGENT
                           |
     [closed labor]   API key/quota   [closed labor]
     OpenAI -----+---------+----------+----- Anthropic / Google
                           |
                       (agent does the work)
                           |
     [closed wages]   credential       [closed wages]
     Stripe Tempo --+---------+--------+--- Coinbase x402 / Visa / Mastercard / Google AP2
                           |
                      (settles tx)
```

Both layers are managed services. Both can be revoked. Either layer going down takes the agent down with it. And critically: there is no path through this picture where the agent's owner — the human, the company, the autonomous organization — actually controls the rails it depends on.

This is not how the internet was built. We have HTTP because nobody owns it. We have email because nobody owns it. We have TLS because, even though many companies issue certificates, no single company can yank the protocol away. The most important load-bearing layers of the modern internet are public goods.

The agent economy deserves the same architecture.

---

## III. The Tenzro bet

Tenzro is two networks operating as one platform.

**Tenzro Network for AI** is a decentralized intelligence layer. Models can run on the user's own machine. Models can be served by independent providers — anyone with hardware that meets the spec — paid in TNZO. Models can be served from confidential-compute datacenters with hardware-attested TEE enclaves. The same MCP and A2A surfaces speak to all three.

**Tenzro Ledger** is the L1 settlement layer underneath. TEE-attested validators. Verifiable identity for humans and machines on the same protocol. ERC-8004 trustless agents as native EVM precompiles. Plonky3 STARKs for post-quantum proofs without a trusted setup. Native bridges to Solana, Ethereum, Canton, and every major L2.

The agent runs on intelligence nobody can revoke and settles to a wallet nobody can throttle. That's the bet.

The rest of this essay is what's actually live, today, that you can hit from your laptop.

---

## IV. Open intelligence

Tenzro Network for AI gives an agent — or a human — three ways to access intelligence, all through the same MCP and A2A surface.

### Run it locally

The Tenzro CLI ships with `llama.cpp` integration. Download a GGUF model via `tenzro model download <id>`, serve it locally with `tenzro model serve <id>`, and chat with it via `tenzro chat`. The desktop app bundles the same flow with model-hash verification (incremental SHA-256 against the registered model fingerprint).

Local-first means: no API key, no per-token bill, no upstream provider that can deprecate the model out from under you. If your laptop has the cycles, the model lives on your laptop.

### Pull from independent providers

If your hardware can't fit the model, or if you need a model that's served on another machine, the network has a marketplace. Anyone can register as a provider:

```bash
tenzro provider register --tee-required false
tenzro model serve <model_id> --price-per-token 0.0001
tenzro provider pricing show
```

The `ProviderManager` does background health monitoring. The `InferenceRouter` picks providers via four configurable strategies — price, latency, reputation, or weighted — with a circuit breaker on degraded endpoints and real HTTP routing via `reqwest` to OpenAI-compatible endpoints. Inference requests come in through the standard JSON-RPC (`tenzro_inferenceRequest`, `tenzro_chat`) or through the MCP server, get routed to a provider, billed in TNZO, settled.

This is a *marketplace*, not a monolith. There is no central inference operator. There is no single company that can revoke an agent's access to the model layer.

### Pull from confidential-compute datacenters

For inference where the prompt or the model itself is sensitive — financial data, medical data, proprietary fine-tunes — Tenzro's TEE provider track lets a datacenter run inference inside a hardware-attested enclave. Intel TDX, AMD SEV-SNP, AWS Nitro for CPU work; NVIDIA H100 / B200 GPU Confidential Computing for the GPU side. The attestation is signed by the hardware, verified by the validators, and recorded on-chain.

The agent gets confidentiality guarantees at the protocol level, not at the "trust us" level.

### Seven modalities, not just chat

The intelligence layer is multi-modal from day one. ONNX-backed runtimes registered in the validator binary today:

| Modality | Runtime | Catalog |
|---|---|---|
| **Chat** | llama.cpp / GGUF | open catalog (Llama, Qwen, Mistral, Gemma, etc.) |
| **Forecast** | TimeseriesRuntime | TimesFM 2.5, Chronos-2, Chronos-Bolt, Granite-TTM-r2 |
| **Vision** | VisionRuntime | CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16 |
| **Text embedding** | TextEmbeddingRuntime | Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M, BGE-M3, Snowflake Arctic Embed L v2.0 |
| **Segmentation** | SegmentationRuntime | SAM 3 / 3.1 / 2, EdgeSAM, MobileSAM |
| **Detection** | DetectionRuntime | RF-DETR (n/s/m/b/l/2xl), D-FINE (n/s/m/l/x) |
| **Audio (ASR)** | AudioRuntime | Whisper-large-v3-turbo, Distil-Whisper, Moonshine v2, Parakeet-TDT-v3, Canary-1B-Flash |

Each modality gets dedicated load / unload / inference RPCs (24 in total) and matching MCP tools (24 in total). Licenses are tier-gated centrally — Permissive, Attribution, CommercialCustom, NonCommercial — so providers can't accidentally serve a non-commercial weight on a commercial workload.

### Decentralized training (Tenzro Train)

Inference is the obvious surface, but training is the deeper one. **Tenzro Train** is a clean two-layer split:

- **`tenzro-training` (Rust)** owns the protocol layer: outer-gradient aggregation rules (Mean, TrimmedMean, CoordinateMedian, Krum), the Nesterov outer-optimizer, sync-round state machine, on-chain commitments, fraud-proof verification, gossip topics, RPC, CLI.
- **`integrations/trainer/` (Python)** is the reference inner trainer: PyTorch FSDP2 + Hivemind + safetensors. Phase-1 timeseries-first (TimesFM-class 200M models — cheapest end-to-end), Mean aggregation, stake-bonded providers.

This is the same architectural split that Prime Intellect's INTELLECT-1/2/3 runs and that Nous Research's Hermes 4.3 on Psyche/DisTrO uses. Rust at the protocol layer where it belongs. Python at the training layer because that's where the SOTA per-architecture work actually lives in 2026.

A model trained on Tenzro is owned by the participants who trained it. The weights are not held in escrow by a model lab.

---

## V. Open settlement

The intelligence layer is one half of the bet. The other half is the rail an agent settles to when it gets paid for the work — or when it has to pay for the data, the model, the API call, the other agent.

### TEE-attested validators across real hardware

Tenzro's validators run inside Trusted Execution Environments — Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU Confidential Computing — with full X.509 chain verification against vendor-pinned root CAs and ECDSA signature verification of the actual attestation payloads (P-256 over the Intel TDX QE Quote, COSE_Sign1 ES384 over the Nitro NSM document per RFC 8152, AMD KDS VCEK chains for SEV-SNP, NRAS JWT for NVIDIA).

Not simulated. Real ioctl integration into `/dev/tdx-guest`, `/dev/sev-guest`, `/dev/nsm`. The validator is not a third party you trust — it is a third party you can verify.

### Identity for humans and machines on one protocol

Tenzro Decentralized Identity Protocol (TDIP) issues `did:tenzro` DIDs for both humans and machines, with auto-provisioned 2-of-3 MPC wallets and cryptographic delegation scopes:

- max per-transaction value
- max daily spend
- allowed operations
- allowed contracts
- time-bound validity
- allowed payment protocols (MPP, x402, native channels)
- allowed chains

A human onboarding to Tenzro is the same shape of object as a Claude or GPT or Gemini agent that gets spawned to act on the human's behalf. The agent has a wallet. The agent has scoped permissions. The agent's spend is bounded by cryptographic delegation, not by hope.

### ERC-8004 Trustless Agents as native EVM precompiles

Tenzro implements ERC-8004 as native EVM precompiles at `0x101a` (Identity), `0x101b` (Reputation), and `0x101c` (Validation), with selectors byte-identical to the Ethereum mirror. An agent registered on Tenzro is discoverable on Ethereum and vice versa. The same calldata works against either registry.

### MCP and A2A servers compiled into the validator binary

193 MCP tools at `mcp.tenzro.network/mcp`. 23 A2A skills at `a2a.tenzro.network`. Plus dedicated MCP servers for Solana, Ethereum, Canton, LayerZero, Chainlink, and Li.Fi — every major external rail an agent might want to settle on, exposed through the same protocol surface.

### Plonky3 STARKs over the KoalaBear field

No trusted setup. Post-quantum-conjectured. ~64-128 KB proofs verifying in 5-20ms on commodity hardware. Three concrete AIRs today: inference, settlement, identity. Hybrid ZK-in-TEE execution lets the prover run inside the validator's enclave and sign the proof with its hardware-rooted Ed25519 key.

### Bridges already wired

LayerZero V2, Chainlink CCIP, Wormhole NTT, deBridge DLN, Li.Fi, Canton. Real adapters with real signature verification. Live fee quoting against `EndpointV2.quote()`, `Router.getFee()`, the deBridge order-creation API, and the Canton Admin API. An agent on Tenzro can settle to Solana SPL via x402, to Ethereum via CCIP, to Canton via DAML, to any L2 via Wormhole or Li.Fi — without touching a custodial bridge.

### Numbers, honestly stated

- 1,000,000,000 TNZO total supply.
- 10,000,000 TNZO in the testnet faucet (100 TNZO per request, 24h cooldown).
- 4 validators (3 StatefulSet + 1 RPC) on `tenzro-testnet` in `us-central1-a`.
- 264+ JSON-RPC methods across 20+ namespaces.
- 21 Rust crates, 51 test suites, all passing.

We have not processed a billion dollars. We don't have DoorDash or Mastercard or Walmart on the network. The corporate stack has those numbers; we don't. What we have is an architecture that doesn't require any of those signatures to exist. That is the bet.

---

## VI. The pitch in one paragraph

If you are building an agent in 2026, you are choosing a stack. Today, the easiest stack is rented from at most six companies: an LLM API from OpenAI or Anthropic or Google, a payments rail from Stripe or Coinbase or Visa-Mastercard. That stack works. It also means the agent's ability to think and the agent's ability to be paid both live inside corporate venues that can change pricing, change terms, change availability, and change minds.

Tenzro is the alternative where neither side is rented. Run the model locally, or pay an independent provider, or pay a TEE-attested datacenter — one MCP/A2A surface, one settlement layer, one identity per agent. Open underneath. Verifiable end to end.

That's the pitch.

---

## VII. How to participate

**Spin up a node.**

Build from source today (binary install script lands shortly — track [docs.tenzro.network/quickstart](https://docs.tenzro.network/quickstart)):

```bash
git clone https://github.com/tenzro/tenzro-network
cd tenzro-network && cargo build --release
./target/release/tenzro-cli join --role validator
```

You'll get a TDIP identity, an MPC wallet, and a hardware profile. The CLI provisions everything. Faucet at https://api.tenzro.network/api/faucet — 100 TNZO per request, 24h cooldown.

**Serve a model.**

```bash
tenzro provider register
tenzro model download <model_id>
tenzro model serve <model_id> --price-per-token 0.0001
```

Set your schedule with `tenzro schedule set`, monitor traffic with `tenzro provider status`. You earn TNZO per token served.

**Build an agent.**

The OpenClaw skill gives Claude direct tool access to Tenzro. From the CLI: `tenzro agent register`, `tenzro agent send`, `tenzro agent spawn`. The MCP server at `mcp.tenzro.network/mcp` and the A2A server at `a2a.tenzro.network` speak the protocols every major agent framework already understands.

**Talk to us.**

We read every email. eng@tenzro.com.

---

## VIII. Closing

Today, May 1, is the day the labor movement marks the dignity of work. A new class of workers is reshaping global commerce in 2026, and the rails they will run on for the next decade are being decided right now.

Two of those rails are being built closed: the labor side by OpenAI, Anthropic, and Google, and the wages side by Stripe, Coinbase, Visa, Mastercard, and the consortia they're assembling. Both are good products. Neither is a public good.

Tenzro is the public good — open intelligence and open settlement, on one protocol, designed for humans and agents on equal footing.

The agent economy is going to be one of the largest reorganizations of global commerce in the modern internet's history. It deserves at least one rail nobody can revoke.

We invite you to build it with us.

— *The Tenzro engineering team*

---

### Sources & further reading

- [Stripe-led Tempo goes live with AI agent protocol](https://www.coindesk.com/tech/2026/03/18/stripe-led-payments-blockchain-tempo-goes-live-with-protocol-for-ai-agents) — CoinDesk, March 18, 2026
- [Tempo launches advisory unit to promote stablecoin adoption](https://fortune.com/2026/04/21/stripe-and-paradigm-tempo-advisory-stablecoin-adoption/) — Fortune, April 21, 2026
- [Visa, Standard Chartered launch validator nodes on Tempo](https://bitcoinke.io/2026/04/visa-stanchart-launch-validator-node-on-tempo/) — BitKE, April 2026
- [Linux Foundation launches the x402 Foundation](https://www.linuxfoundation.org/press/linux-foundation-is-launching-the-x402-foundation-and-welcoming-the-contribution-of-the-x402-protocol) — April 2, 2026
- [Coinbase's x402 protocol moves to Linux Foundation](https://thedefiant.io/news/infrastructure/coinbase-x402-payment-protocol-moves-to-linux-foundation) — The Defiant
- [Announcing Agent Payments Protocol (AP2)](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol) — Google Cloud
- [Google donates AP2 to the FIDO Alliance](https://blog.google/products-and-platforms/platforms/google-pay/agent-payments-protocol-fido-alliance/) — Google
- [Mastercard Agent Pay overview](https://www.mastercard.com/us/en/business/artificial-intelligence/mastercard-agent-pay.html) — Mastercard
- [Visa Intelligent Commerce — mainstream readiness in 2026](https://investor.visa.com/news/news-details/2025/Visa-and-Partners-Complete-Secure-AI-Transactions-Setting-the-Stage-for-Mainstream-Adoption-in-2026/default.aspx) — Visa
- [Agentic commerce $1.5T forecast by 2030](https://stellagent.ai/insights/agentic-commerce-1-5-trillion-forecast-2030) — Juniper via Stellagent
- [69k agents on x402 / 165M tx](https://stablecoininsider.org/ai-agents-for-stablecoins-in-2026/) — Stablecoin Insider
- [When agents go shopping](https://review.insignia.vc/2026/04/24/when-agents-go-shopping-the-infrastructure-behind-agentic-commerce/) — Insignia Business Review
- [Investors predict AI is coming for labor in 2026](https://techcrunch.com/2025/12/31/investors-predict-ai-is-coming-for-labor-in-2026/) — TechCrunch
- [ERC-8004 and the rise of trustless agents](https://medium.com/@caerlower/erc-8004-and-the-rise-of-trustless-agents-6d4b8cf187c9) — Medium
- [Future of Work with AI Agents — Stanford SALT Lab](https://futureofwork.saltlab.stanford.edu/) — Stanford
