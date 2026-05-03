# Workers Day 2026 — Tenzro Network Launch Campaign

**Send date:** Friday, May 1, 2026
**Theme:** "Workers of a New Kind" — the agent economy between two closed walls, and the open alternative
**Owner:** eng@tenzro.com

---

## Files in this folder

| File | What it is | When to ship it |
|---|---|---|
| `00-campaign-brief.md` | Strategy, sequencing, two-rail story, distribution checklist, source pack | Internal — read first |
| `01-x-thread.md` | X / Twitter thread (16 posts) + headline post + reply-bait | 06:30 PT |
| `02-linkedin-post.md` | LinkedIn long-form (~830 words) | 07:30 PT |
| `03-blog-manifesto.md` | tenzro.com anchor blog post (~2,800 words) | 06:00 PT — ship first |
| `04-newsletter-email.md` | Ecosystem email + 3 subject-line options | 09:00 PT |

---

## TL;DR for the operator

1. **Read `00-campaign-brief.md`** for the strategy and the two-rail story every piece must land.
2. **Ship the blog first** (`03-blog-manifesto.md`) at 06:00 PT — it's the canonical URL the others link to.
3. **Then the X thread** (`01-x-thread.md`) at 06:30 PT.
4. **Then the LinkedIn post** (`02-linkedin-post.md`) at 07:30 PT.
5. **Then the newsletter** (`04-newsletter-email.md`) at 09:00 PT — pick one of the three subject-line variants based on segment.

Each piece links forward and back. The blog is the anchor.

---

## The argument the campaign is making, in one sentence

> The agent economy is being built between two closed walls — closed labor (OpenAI, Anthropic, Google) and closed wages (Stripe Tempo, Coinbase x402, Google AP2, Visa, Mastercard). Tenzro is the open alternative on both sides: decentralized intelligence (local + provider marketplace + TEE datacenters) settling to a neutral L1 nobody can revoke.

---

## The two-rail story (the load-bearing claim across every surface)

### Closed labor — OpenAI / Anthropic / Google
The agent's *capacity to reason* is rented from at most three companies. API key, rate limit, ToS, no protocol-level fallback.

### Closed wages — Stripe Tempo / Coinbase x402 / Google AP2 / Visa / Mastercard
The agent's *capacity to be paid* is rented from a small consortium of corporate payment rails, each owned by one company.

### Open intelligence — Tenzro Network for AI
- **Local** — `tenzro chat` runs llama.cpp / GGUF on your machine.
- **Provider marketplace** — `tenzro provider register`. Anyone serves models, paid in TNZO. ProviderManager + InferenceRouter (price/latency/reputation/weighted).
- **TEE datacenters** — Intel TDX, SEV-SNP, Nitro, NVIDIA H100/B200 GPU CC.
- **7 modalities** live: chat, forecast, vision, text-embed, segment, detect, audio ASR.
- **Tenzro Train** — decentralized training (Rust protocol + Python reference trainer).

### Open settlement — Tenzro Ledger
- TEE-attested validators (real ioctl integration, ECDSA verification of attestation payloads).
- TDIP unified human/machine identity; auto-provisioned 2-of-3 MPC wallets; cryptographic delegation scopes.
- ERC-8004 native EVM precompiles (byte-identical selectors to Ethereum).
- Plonky3 STARKs over KoalaBear (post-quantum, no trusted setup).
- 193 MCP tools + 23 A2A skills compiled into the validator binary.
- Bridges to LayerZero, CCIP, Wormhole, deBridge, Li.Fi, Canton.

---

## Honest claims policy

This campaign goes wide in public on Workers' Day. Tenzro is `0.1.0`, pre-alpha, testnet only — and the messaging respects that.

- ✅ Live testnet endpoints (`rpc.`, `api.`, `mcp.`, `a2a.tenzro.network`).
- ✅ TEE attestation is real hardware integration.
- ✅ ERC-8004 native EVM precompiles are real.
- ✅ Plonky3 STARKs over KoalaBear are real.
- ✅ Local llama.cpp inference, provider marketplace, 7-modality runtimes — all real, in `crates/tenzro-model` and `crates/tenzro-cli`.
- ❌ TNZO doesn't trade — testnet only with a faucet.
- ❌ No volume / TPS / merchant-base / provider-count claims.
- ❌ EVM Inference precompile returns simulated results — don't say it runs real inference. Real inference routing is through JSON-RPC + MCP.

---

## Distribution checklist (also in the brief)

- [ ] Schedule blog publish 06:00 PT
- [ ] Schedule X thread 06:30 PT (use a thread scheduler — don't paste manually)
- [ ] Schedule LinkedIn post 07:30 PT
- [ ] Send newsletter 09:00 PT (pick subject A, B, or C)
- [ ] Crosspost X thread headline to Mastodon / Bluesky / Farcaster
- [ ] Slack ecosystem partners after blog is live
- [ ] Pin blog link to tenzro.com landing hero for the day
- [ ] Pin X thread to @tenzro_ profile
- [ ] Add UTM params: `?utm_source={x|linkedin|email|farcaster}&utm_medium=social&utm_campaign=workers-day-2026`
- [ ] Watch responses for the first 4 hours; reply quickly to engineers asking about node setup or about serving a model
- [ ] Pre-write answers for "isn't this just Akash / Bittensor / io.net / Render / Gensyn?" — frame Tenzro as the protocol layer (TDIP + ERC-8004 + MCP/A2A native + settlement) over an inference + training network, not a competing GPU spot market

---

## Source pack (for fact-checking before send)

All sources are footnoted in the blog. Quick links:

- Stripe Tempo mainnet — [coindesk.com](https://www.coindesk.com/tech/2026/03/18/stripe-led-payments-blockchain-tempo-goes-live-with-protocol-for-ai-agents)
- Tempo advisory unit — [fortune.com](https://fortune.com/2026/04/21/stripe-and-paradigm-tempo-advisory-stablecoin-adoption/)
- x402 → Linux Foundation — [linuxfoundation.org](https://www.linuxfoundation.org/press/linux-foundation-is-launching-the-x402-foundation-and-welcoming-the-contribution-of-the-x402-protocol)
- Google AP2 — [cloud.google.com](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)
- AP2 → FIDO Alliance — [blog.google](https://blog.google/products-and-platforms/platforms/google-pay/agent-payments-protocol-fido-alliance/)
- Mastercard Agent Pay — [mastercard.com](https://www.mastercard.com/us/en/business/artificial-intelligence/mastercard-agent-pay.html)
- Visa Intelligent Commerce — [investor.visa.com](https://investor.visa.com/news/news-details/2025/Visa-and-Partners-Complete-Secure-AI-Transactions-Setting-the-Stage-for-Mainstream-Adoption-in-2026/default.aspx)
- Juniper $1.5T forecast — [stellagent.ai](https://stellagent.ai/insights/agentic-commerce-1-5-trillion-forecast-2030)
- 69k agents on x402 — [stablecoininsider.org](https://stablecoininsider.org/ai-agents-for-stablecoins-in-2026/)
- McKinsey $3-5T — [review.insignia.vc](https://review.insignia.vc/2026/04/24/when-agents-go-shopping-the-infrastructure-behind-agentic-commerce/)

---

## What's NOT in this folder (and why)

- **Visual assets** — no images / OG cards / video. The blog suggests `/og/workers-of-a-new-kind.png`, the LinkedIn post suggests a two-panel diagram (closed labor / closed wages, with Tenzro open underneath). Lead time is too short to produce them in this session.
- **Press release** — campaign is positioned as community-first, not press-first. The blog is essentially a pre-written long-form version that can be reformatted for wire distribution if desired.
- **Targeted partner outreach** — keep the May 1 lane public. Targeted outreach (Canton ecosystem, GPU datacenter operators, specific institutions, foundation-model labs) should follow the week of May 4.
- **Localization** — English only for the launch. Mandarin, Spanish, Japanese, Korean translations follow if it lands.

---

## Post-launch follow-up arc (not for May 1, for the days after)

- **Tuesday May 5 — open intelligence deep-dive:** Long blog/Twitter thread on the local-llama.cpp + provider-marketplace + TEE-datacenter trifecta. Lead with the "no API key" story for the dev audience. Demonstrate `tenzro provider register` end-to-end with a screen recording.
- **Wednesday May 6 — TEE attestation deep-dive:** Real ECDSA verification, X.509 chain pinning, the QE / NSM / VCEK / NRAS specifics. Audience: security and ZK engineers.
- **Thursday May 7 — protocol comparison:** Honest side-by-side of MPP vs x402 vs AP2 vs the native Tenzro identity / payment surface. Position Tenzro as the venue that speaks all of them.
- **Friday May 8 — Tenzro Train:** Decentralized training story. Phase-1 timeseries-first. Comparison to Prime Intellect's INTELLECT-1/2/3 architecture.
- **Following Monday May 11 — first community node showcase:** Highlight the first non-Tenzro-team validator that joins testnet over the weekend.
- **Following Tuesday May 12 — first community provider showcase:** Same for the first independent inference provider serving a model.

That's a two-week arc that takes the Workers' Day campaign and turns it into a sustained narrative. Each follow-up reinforces a specific technical claim from the original manifesto.
