# Ecosystem newsletter — May 1, 2026

**From:** Tenzro Engineering <eng@tenzro.com>
**To:** subscribers@tenzro.com (waitlist + partners + builder community)
**Send time:** 09:00 PT, May 1, 2026
**Preheader text:** "Open intelligence. Open settlement. One protocol."

---

## Subject line options (A/B/C — pick one before send)

**A — Hook-led (recommended for cold list):**
> The agent economy is being built between two closed walls

**B — Newsy (recommended for partner list):**
> OpenAI rents you the labor. Stripe rents you the wages. We built the open one.

**C — Direct (recommended for dev / builder list):**
> Run a model locally. Settle to a rail nobody can revoke. Tenzro testnet is live.

---

## Email body

Hi —

The agent economy in 2026 is being built between two closed walls.

**On the labor side**, an agent's ability to reason is rented from one of three companies: OpenAI, Anthropic, or Google. xAI, Cohere, and Mistral fill the edges. API key, rate limit, terms of service. If access goes away, the agent stops working.

**On the wages side**, the payments stack is being built closed too:

- Stripe Tempo (mainnet live since March 18, with Machine Payments Protocol)
- Coinbase x402 (moved to the Linux Foundation on April 2 as the x402 Foundation; ~69k agents, 165M tx)
- Google AP2 (60+ partners, donated to FIDO, "Human Not Present" payments in v0.2)
- Mastercard Agent Pay and Visa Intelligent Commerce (scoped tokenized credentials issued directly to agents)

Each is good. Each is owned by one company. Stack them and your agent's ability to think and its ability to be paid both live in corporate venues that can change overnight.

**Tenzro is open on both sides.**

→ **Open intelligence (Tenzro Network for AI)** — Run models locally on your own machine via `tenzro chat` (llama.cpp / GGUF). Or pull from independent providers in a marketplace paid in TNZO (`tenzro provider register`). Or run inference inside a hardware-attested TEE datacenter (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA H100/B200 GPU CC). Seven modalities live: chat, forecast (TimesFM, Chronos), vision (CLIP, SigLIP2, DINOv3), text-embed (Qwen3, EmbeddingGemma), segment (SAM 3), detect (RF-DETR, D-FINE), audio ASR (Whisper, Moonshine, Parakeet, Canary). 24 RPCs, 24 MCP tools. Plus Tenzro Train for decentralized training (Rust protocol + PyTorch FSDP2 reference trainer).

→ **Open settlement (Tenzro Ledger)** — TEE-attested validators across real hardware. TDIP unified identity for humans and machines. ERC-8004 trustless agents as native EVM precompiles. Plonky3 STARKs (post-quantum, no trusted setup). MCP and A2A servers compiled into the validator binary. Native bridges to LayerZero, CCIP, Wormhole, deBridge, Li.Fi, Canton.

Pre-alpha. Testnet only. Open source. Live today.

→ **Read the manifesto:** [tenzro.com/blog/workers-of-a-new-kind](https://tenzro.com/blog/workers-of-a-new-kind)
→ **Spin up a node:** `tenzro join` ([quickstart](https://docs.tenzro.network/quickstart))
→ **Serve a model:** `tenzro provider register && tenzro model serve <id>`
→ **Faucet for testnet TNZO:** [api.tenzro.network/api/faucet](https://api.tenzro.network/api/faucet)
→ **MCP for agents:** `https://mcp.tenzro.network/mcp` — 193 tools

If you build agents, you're choosing a stack. The easiest one today is rented from at most six companies. The open alternative now exists.

— Tenzro Engineering
eng@tenzro.com

---

*You're receiving this because you signed up at tenzro.com or one of your colleagues did. Manage subscription: [unsubscribe link]. Privacy policy: [link].*

---

## Notes for the operator sending this

1. **Pre-warm the from-address.** If `eng@tenzro.com` hasn't sent a newsletter recently, do a small batch (~500) first and watch deliverability before the full list.
2. **UTM params on every link.** `?utm_source=newsletter&utm_medium=email&utm_campaign=workers-day-2026`.
3. **CTA priority.** The blog link is the primary CTA. `tenzro join` is the secondary CTA for the technical segment. `tenzro provider register` is the tertiary CTA for the hardware-owner segment. Don't let any one segment see all three as equal weight.
4. **Plain-text version.** Send a plain-text alternative — the dev list reads in mutt / plain-text Gmail and HTML-only goes to spam.
5. **Reply-to.** Set `Reply-To: eng@tenzro.com`. Workers' Day messaging invites response — make sure responses can land somewhere.
6. **Send time.** 09:00 PT for the US engineering audience. For Europe-heavy segments, set 09:00 CET on the same day. Don't send before the X thread and blog are live — email should be the *third* surface a recipient sees, not the first.
7. **Provider-segment variant (optional).** If you have a known list of GPU/datacenter contacts, consider a separate send that opens with subject C ("Run a model locally...") and leads the body with the provider-marketplace bullet rather than the manifesto bullet.
