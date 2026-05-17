# Tenzro — Architecture for the Agentic Internet

**Status:** design doc. Companion to `ARCHITECTURE-PRIOR-ART.md` (prior-art survey) and `ARCHITECTURE-GAP-MATRIX.md` (what's shipped vs. what's outstanding). Reading order: Prior-Art → Gap-Matrix → this doc → `ROADMAP.md`.

This document states what Tenzro is building, why those choices, and how the existing primitives compose into the target. It does not catalogue alternatives that were considered and rejected (that's the prior-art doc) and does not enumerate ship dates (that's the roadmap).

---

## 0. Frame

### 0.1 What "agentic internet" means here

Humans and AI agents are first-class participants in the same protocol. Both transact in TNZO. Both have identities anchored on the Tenzro Ledger (TDIP). Both are accountable to the same primitives: identity, custody, settlement, verification. Neither gets a fast path the other doesn't.

The shape this forces:

- **One identity layer.** TDIP carries both human and machine identities in a single type (`TenzroIdentity`), with the human/machine distinction expressed as a variant on `IdentityData`. There is no "human registry" and "agent registry" — there is one registry.
- **One settlement spine.** Every payment — whether human-to-human, human-to-agent, agent-to-agent, or agent-to-human — flows through the same payment protocols (MPP, x402, AP2, ERC-7683) and settles on the same ledger.
- **One verification surface.** ZK proofs, TEE attestations, settlement receipts, and transaction signatures all surface through the same Web Verification API (`api.tenzro.network/verify/*`) and the same MCP `verify_*` tools. Humans verify in a browser, agents verify over RPC; same proofs, same hash domains.
- **One consensus.** HotStuff-2 finalises every state transition. There is no "fast inference layer" that escapes consensus and reconciles later — there is no settlement reconciliation problem because everything that mattered already cleared a quorum.

### 0.2 Non-goals

Tenzro is not:

- **A new general-purpose L1 alongside Ethereum/Solana.** Tenzro Ledger settles AI-economy primitives (identity, custody, inference billing, agent attestation, training receipts). For DeFi or NFT primary markets, use Ethereum or Solana — and use Tenzro's bridge surface (LayerZero V2 + Chainlink CCIP + deBridge DLN + Canton + Wormhole NTT for TNZO itself) to move value across.
- **A generic file storage layer.** Tenzro produces, persists, and verifies *receipts and commitments* about inference, training, and agent activity. Bulk model weights live on Hugging Face (or other CID-addressable stores); Tenzro stores the SHA-256 hash, not the bytes.
- **A model marketplace UX.** The protocol exposes registry, routing, pricing, and settlement surfaces over RPC and MCP. SDK consumers (Cookbook, desktop app, third-party agents) build the human-facing UX.
- **A wallet UX vendor.** `tenzro-wallet` is the MPC-threshold custody library; UX is built by SDK consumers and by Tenzro Wallet (separate repo) that wraps it.

### 0.3 What this doc covers vs. what it points to

| Surface | Where it lives |
|---|---|
| Each pillar (P2P, data, compute, agent, crypto) | This doc, §1 |
| Identity classes (human / delegated / autonomous) | This doc, §2 |
| Settlement spine | This doc, §3 |
| Consensus & validator overlay | This doc, §4 |
| What the data plane moves | This doc, §5 |
| The agent surface (MCP + A2A) | This doc, §6 |
| Failure modes & defenses | This doc, §7 |
| Phase shape | This doc, §8 (one sentence each; detail in `ROADMAP.md`) |
| Wiring sequencing call-outs | This doc, §9 |
| Vendor evaluations / rejected options | `ARCHITECTURE-PRIOR-ART.md` |
| What's shipped vs. outstanding | `ARCHITECTURE-GAP-MATRIX.md` |
| Phase dates & acceptance criteria | `ROADMAP.md` |

---

## 1. Architectural Pillars

Five pillars, one per prior-art section. Each pillar states what Tenzro asserts and how it composes with the others.

### 1.1 P2P substrate — libp2p + validator overlay split

Tenzro runs on rust-libp2p with the canonical 2026 behaviour stack: `gossipsub` + `kad` + `identify` + `ping` + `relay::v2` + `dcutr` + `autonat::v2::client`. The configuration is settled (`crates/tenzro-network/src/config.rs`):

- `idle_connection_timeout: 600s` — survives GCE Andromeda 10-minute conntrack eviction.
- `gossip_heartbeat_interval: 700ms` — Ethereum-class sub-second propagation.
- Connection limits 200 inbound / 200 outbound (mandatory post-`GHSA-jvgw-gccv-q5p8`).
- `external_addresses` explicitly enumerated; `identify::Config::with_hide_listen_addrs(true)` prevents docker-bridge ban (2026-05 incident).

Two architectural commitments:

**Validator-only direct-connect overlay for consensus traffic.** HotStuff-2 vote, proposal, and certificate messages move off `tenzro/consensus` gossipsub and onto a `gossipsub::Config.direct_peers` mesh populated from `ValidatorRegistry` at boot. Public mesh peer-scoring is wrong for low-volume vote topics (`P₃` mesh-message-delivery computes against expected rate; near-zero rate produces flat scores even under failure). Aptos / Sui / Monad / Solana all run validator-only overlays for the same reason. `NodeValidatorRegistry` (the `ValidatorRegistry` impl in `tenzro-node`) already authorises peers per-topic; populating `direct_peers` is the wiring step.

**NAT traversal is mandatory for non-validator joiners.** `enable_relay` and `enable_hole_punching` in `NetworkConfig` become live: Relay v2 + AutoNAT v2 + DCUtR get instantiated in `TenzroBehaviour`. The choreography is the libp2p canonical one — joiner dials reservation on a public relay, AutoNAT v2 confirms NAT type, DCUtR upgrades to direct connection where possible. Without this, only public-IP validators can participate; community joiners behind home/enterprise NAT can't dial in.

### 1.2 Data layer — content-addressing + pluggable DA

Tenzro stores small receipts inline and offloads high-volume payloads to a data availability backend. The boundary is `ReceiptEnvelope` (`crates/tenzro-storage/src/da.rs`):

```
ReceiptEnvelope {
    kind:           ReceiptKind,           // Settlement | Inference | AgentMessage | …
    storage_mode:   StorageMode,           // Inline | OffloadedDA
    inline_summary: SummaryJson,           // always present, small
    inline_payload: Option<Vec<u8>>,       // present iff Inline
    da_pointer:     Option<DaPointer>,     // present iff OffloadedDA
    commitment:     [u8; 32],              // SHA-256(canonical_payload)
}
```

The commitment binds the payload regardless of storage mode. Verifiers re-derive it from whatever they read, inline or fetched. `ReceiptKind` carries `default_mode()` — Settlement / KillSwitch / Lifecycle / Governance stay inline; SettlementChannel / Inference / AgentMessage offload by default. The async `DaBackend` trait (`submit` / `fetch` / `verify_availability`) is the pluggable seam.

Commitments:

- **CID for portable artifacts.** Inference results (image embedding, transcription text, forecast quantiles), training fragments, large config blobs — anything that should be addressable across the network — gets a content identifier so the receipt envelope can refer to it independent of which backend stored it.
- **`SHA-256(canonical_payload)` for receipts.** Bound at write time; re-derivable at read time.
- **safetensors hash for model weights and training fragments.** Already a field on `OuterGradient`. Bytes live on Hugging Face or a DA backend; only the hash and the safetensors offset table are in scope for ledger receipts.

Storage backends:

- **`InlineFallbackBackend`** is the safe default — offload-kinds refuse to write until a real backend is registered. No silent loss; data refuses to ship rather than be irretrievable.
- **Celestia** is the first real backend. Namespace-scoped blobs, Tendermint header inclusion, fast finality. CLAUDE.md decision; sequencing is "after receipt-envelope retrofit so writers exist."
- **EigenDA + Avail** follow Celestia. EigenDA for high-throughput inference traffic (100 MB/s claimed); Avail for redundant storage of governance-critical envelopes.

Columnar + vector layers (consumers of the offload backend, not the offload backend itself):

- **Apache Arrow + Arrow Flight** for streaming analytics — per-block usage records, per-provider performance histograms, per-agent message traces. Producers are validator nodes; consumers are dashboards, observability stacks, and the Tenzro Wallet history view.
- **Lance** for vector indices — embeddings produced by `TextEmbeddingRuntime` and `VisionRuntime`. Tenzro doesn't ship Lance as a built-in module; the Cookbook and third-party agents pull embeddings via RPC and index them locally (Lance is the canonical 2026 choice).

### 1.3 Compute & provider market

Two layers: how providers describe themselves, and how the network holds them accountable.

**ProviderManifest.** Today's `InferenceProvider` carries `address / endpoint / has_tee / capacity / reputation / pricing`. The target schema adds:

- Hardware: `gpu_model`, `vram_gb`, `cpu_cores`, `ram_gb`, `storage_tier`.
- Geography: `country`, `region`, `datacenter` (CAIP-2 style if peering with a known datacenter, free-form otherwise).
- Attestation: `tee_provider` (Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA CC), `attestation_tier` (Open / Attested / Sealed), `audited_attributes` (TPM event log digest etc.).
- Self-signature: the provider DID signs the full manifest. The network rejects manifests that don't verify against the on-chain identity.

The `HardwareCapabilities` type already exists in `tenzro-model/src/provisioning.rs`; it gets attached to `InferenceProvider` and surfaced in `ProviderAnnouncementMessage`. The route from announcement → registry → routing strategies is straight; no new RPCs.

**Bandwidth-aware accounting.** `UsageRecord` extends from `{input_tokens, output_tokens, cost, latency_ms}` to also carry `{bytes_in, bytes_out}`, wired from libp2p `BandwidthCounter` per-request. Token counts are meaningless for vision / audio / video modalities; bytes are the right primitive. The settlement path consumes bytes-or-tokens by modality.

**SLA + reputation-bonded slashing.** Three components:

1. **`SlaCommitment`** — provider declares `availability_target`, `latency_p99_target_ms`, `error_budget_bps` in their manifest. On-chain, not advisory.
2. **Validator-issued challenges** — validators (eligible by stake + reputation, selected per-epoch via the VRF precompile 0x1007 we already ship) periodically send probe inference requests to providers. Signed request, signed response, timestamps witnessed.
3. **Failure pipeline** — a failed SLA challenge consumes provider stake from a new `ComputeBond` (sibling to the existing `AgentBondState`). Asymmetric reputation (-5 per failure, +1 per success) stays as the soft signal; slashing is the hard one.

Restaking via `ComputeBond` makes providers economically liable for the compute they advertise. The bond is denominated in TNZO and slashable via the same `StakingManager::slash()` path used today for consensus equivocation.

### 1.4 Agent & MCP surface

Tenzro's external interface for both humans and agents is the same: JSON-RPC for transactions and queries; MCP for tool calls; A2A for agent-to-agent messaging. The internal commitment:

**Every MCP tool returns structured output.** The 2025-06-18 MCP spec added `structuredContent` + `outputSchema` alongside the text content type. Today's 246 Tenzro MCP tools all return `Content::text(serde_json::to_string_pretty(...))` — JSON-in-a-string, opaque to a validating client. The migration: every `#[tool]` handler's response type derives `schemars::JsonSchema` (input types already do), and the handler returns the typed response + a schema reference. LangGraph / OpenAI Agents SDK / Claude Code can then validate, route, and chain tool calls without re-parsing strings.

**A2A skills as MCP tool families.** An A2A "skill" is a named subset of MCP tools with an authorization profile and a description. The Agent Card published at `a2a.tenzro.network/.well-known/agent.json` lists the skills the local agent advertises (today: 25 in Rust, 34 in Python — the discrepancy is a doc-drift item flagged in the gap matrix). The relationship is curatorial: `wallet` skill = `get_balance` + `send_transaction` + `request_faucet`; `inference` skill = `list_models` + `chat_completion` + `list_model_endpoints`; etc. Adding a skill is curation, not new code.

**Memory tier.** Today, `AgentRuntime` persists identity, lifecycle, spawn tree, and agent-message history. The Letta-style memory model adds three tiers, all backed by `AgentRuntime` storage:

- **Core** — small, always-loaded context (agent's purpose, role, current task).
- **Recall** — large, searchable history (past conversations, retrieved on demand).
- **Archival** — bulk reference material (documents, knowledge bases the agent has been granted).

Access is gated by `DelegationScope`. `memory_grant` / `memory_recall` / `memory_archival` MCP tools become the user-facing surface. The underlying storage is the same RocksDB column family (`CF_AGENTS`) the runtime already uses.

**ERC-8004 identity, native + Ethereum mirror.** Native registry lives in `tenzro-identity::erc8004`; selectors match Ethereum's so the same calldata works against either side. The three precompiles (`ERC8004_IDENTITY` 0x101a / `ERC8004_REPUTATION` 0x101b / `ERC8004_VALIDATION` 0x101c) expose Identity / Reputation / Validation. `agentId` is sequential u64 in both the native code and the final ERC-8004 spec — CLAUDE.md says `keccak256(utf8(did))` and is wrong; this doc supersedes that claim (memory file note for #141).

### 1.5 Cryptography & verification

The crypto stack is hybrid-PQ end-to-end:

- **Signatures:** Ed25519 + ML-DSA-65 (Dilithium2 NIST level 3) composite. Wire format: `Ed25519Sig || ML-DSA-65-Sig`. Both must verify. Validator votes, transaction signatures, identity credentials all use this composite.
- **KEM:** X25519 + ML-KEM-768 (Kyber768) composite. Wire format: `X25519Shared || ML-KEM-768Shared`. KDF over both. TLS path is already PQ-hybrid via Caddy 2.10's BoringSSL backend (X25519MLKEM768 codepoint 0x11EC); the libp2p Noise path moves to the same primitive.
- **Threshold:**
  - **FROST-Ed25519** (RFC 9591) for validator and agent identity keys. Decentralised key generation; threshold signing without trusted dealer.
  - **CGGMP24** (secp256k1, LFDT-Lockness fork that supersedes CGGMP21 after CVE-2025-66017) for bridge custody. ECDSA threshold; resistant to TSSHOCK / BitForge attacks that ended the GG18/GG20/CGGMP21 era. Wiring is upstream-blocked on `LFDT-Lockness/fast-paillier#23`; sequenced to Phase D. Phase B's interim ceiling is TEE-sealing the existing single-key bridge signer on TDX/SEV-capable validators.
  - The `tenzro-crypto::mpc` Shamir-reconstruction module that this plan once replaced is gone — `tenzro-crypto::frost` is the only threshold path in tree.
- **ZK:** Plonky3 STARKs over the KoalaBear field (`2^31 - 2^24 + 1`, two-adicity 24). Poseidon2 hash, FRI commitments. Three AIRs in scope: `inference`, `settlement`, `identity`. Post-quantum sound, transparent setup. ~64–128 KB proofs, ~5–20ms verifier. Already shipped.
- **BLS12-381:** Real `blst` integration in `tenzro-crypto::bls`. Wires into HotStuff-2 BLS vote aggregation as a Phase B refactor (combined with the PQ flag-day to amortise one breaking change instead of two).
- **VRF:** ECVRF-EDWARDS25519-SHA512-TAI per RFC 9381 §5.4.1.1. Already shipped at precompile 0x1007 and consumed by `mintRandom()` on the NFT factory. Validator-jury selection (§1.3 SLA pipeline) is the next consumer.

**TEE + ZK composition.** Hybrid execution per the `tee_integration` module: the AIR witness is computed inside a TEE, the prover runs inside the enclave, the result is signed with the enclave's hardware-rooted Ed25519 key. Verifier checks both the STARK and the enclave signature. Intel Tiber Trust Authority `get_token_v2` integration makes the appraisal portable across vendors — Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA CC quotes get appraised by Intel's appraisal service and the resulting composite token is what the verifier sees. Single trust root for the verifier; vendor-specific paths underneath.

**Commitment-attestation model for on-chain ZK verification.** EVM `ZK_VERIFY` precompile is an O(1) HashSet lookup against `ZkCommitmentRegistry`. Validators verify Plonky3 proofs off-EVM via `verify_proof_envelope`, then record 32-byte commitments (`SHA-256(circuit_id || proof_bytes || Σ(len_le(pi) || pi))`) on chain. EVM gas cost is bounded; proof verification cost lives in the validator process where it can be amortised.

---

## 2. The Three Identity Classes

Custody is the load-bearing constraint. Every Tenzro identity falls into one of three classes, distinguished by who can sign:

### 2.1 Human identity

`TenzroIdentity` with `IdentityData::Human { display_name, kyc_tier, controlled_machines }`. DID format: `did:tenzro:human:{uuid}`.

**Signing path:** passkey-first. The default flow is FIDO/WebAuthn + biometric (Touch ID / Windows Hello / Android BiometricPrompt). Cross-device authentication uses FIDO caBLE (BLE-mediated QR scan, the Coinbase / Privy / Daimo pattern). No seed phrases by default; for users who want them, the seed-phrase backup is opt-in and gated by a confirmation flow.

**Power-user path:** `PluggableSigner` trait. Wallets (Ledger / Trezor / GridPlus / phone-based MPC / etc.) implement the trait; Tenzro Wallet and SDK consumers register signers and route signing requests by signer ID. The protocol is wallet-agnostic; UX is opinionated toward passkey.

**Custody enforcement:** the human's MPC wallet (2-of-3 threshold by default, auto-provisioned by `WalletBinder` at registration) holds the keys. Threshold means no single device compromise drains custody. Recovery via SocialRecovery module (`tenzro-vm::SmartAccount`).

### 2.2 Delegated identity (machine under human control)

`TenzroIdentity` with `IdentityData::Machine { controller_did: Some(human_did), delegation_scope, capabilities, … }`. DID format: `did:tenzro:machine:{controller}:{uuid}`.

**Signing path:** the machine's own keypair, scoped by the controller's `DelegationScope`. Two-axis ceiling:

1. **Protocol ceiling** — `DelegationScope` on the identity record: `max_transaction_value`, `max_daily_spend`, `allowed_operations`, `allowed_contracts`, `time_bound`, `allowed_payment_protocols`, `allowed_chains`. Set at registration; immutable without a controller-signed update.
2. **Runtime ceiling** — `SpendingPolicy` on `AgentRuntime`: per-machine-DID `DashMap<String, SpendingPolicy>` with daily-spend window and active/paused flag. Mutable by the controller without re-registering. Defense-in-depth.

Both checks happen on every signature. `IdentityPaymentBinder::with_spending_policy_resolver()` wires the runtime ceiling into the payment path; `IdentityRegistry::enforce_operation()` enforces the protocol ceiling.

**Where custody actually lives:** the machine's keypair is held by the runtime that operates the machine (a human's laptop, a cloud node, a TEE). The controller holds the *delegation*; revoking the delegation invalidates future signatures even if the keypair is intact. Revocation cascades via the `RevocationBroadcaster` trait.

**ERC-7579 validator modules** (Phase B) move the protocol ceiling on-chain at signing time: every machine transaction passes through a validator-module check that re-verifies the delegation scope before signing. Today's `SpendingPolicyResolver` is off-chain defense-in-depth; 7579 is the primary control. Lesson from Grok / Bankr May 2026: off-chain controls don't bind a compromised host.

### 2.3 Autonomous identity (machine without controller)

`TenzroIdentity` with `IdentityData::Machine { controller_did: None, … }`. DID format: `did:tenzro:machine:{uuid}` (no controller segment).

**Signing path:** the machine signs with its own keypair. Same ERC-7579 validator-module gate as the delegated path, but the policy is *fixed at registration* — there is no controller to update it. To change policy, the autonomous machine must publish a governance proposal and clear it.

**SeedAgent is a specific subtype** of autonomous identity (`IdentityData::Machine { is_seed_agent: true }`). Set at registration, immutable. Drives:

- The `CounterpartyFilter::deny_other_seed_agents` filter — protocol-owned seed-bootstrap agents don't transact with each other (would inflate organic-activity metrics).
- The 12-month treasury earmark decay schedule (`TreasuryEarmark`) — seed agents are funded from a singleton earmark that decays 100% → 75% → 50% → 25% → 0% over months 0–12.
- The `tenzro_seed_agents/1.0.0` gossipsub topic (validator-authenticated) for seed-agent coordination.

**No autonomous identity ships without ERC-7579 validator modules.** The autonomous path is the highest-stakes custody class; the protocol ceiling at signing time is non-optional.

---

## 3. The Settlement Spine

Single path: TNZO as the unit of account, multi-protocol payment surface, on-chain settlement with off-chain channels for micropayments.

### 3.1 TNZO + cross-VM pointer model

TNZO is the only native asset on Tenzro Ledger. Cross-VM representation follows the Sei V2 pointer model:

- **EVM:** `wTNZO` ERC-20 pointer contract at `0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93`.
- **SVM:** wTNZO SPL Token adapter (9-decimal truncation, ATA derivation).
- **DAML:** CIP-56 holding template.

All three share the same underlying native balance via the `TnzoToken` layer. There is no bridge contract, no liquidity fragmentation, no wrapping risk. A balance is a balance regardless of which VM the caller is in.

### 3.2 Payment protocols

The protocol does not pick one payment standard; it implements all of them and routes by counterparty preference. The supported set:

- **MPP (Machine Payments Protocol)** — Stripe + Tempo co-authored, IETF wire spec. Session-based streaming, HTTP 402 challenge/credential/receipt flow. Stripe Payment Intents integration as the fiat on-ramp.
- **x402** — Coinbase HTTP 402, stateless one-shot. EIP-3009 `transferWithAuthorization` calldata via CDP facilitator. Wallet-friendly; lowest friction for casual agents.
- **AP2 mandates** — cart-level user authorisation with intent + payment mandates. Three-axis check: AP2 IntentMandate constraints + TDIP DelegationScope + runtime SpendingPolicy. All three must pass.
- **ERC-7683 cross-chain intents** — origin/destination chain orders, gasless variant, fill-side idempotency. CAIP-2 chain IDs. State machine: Open → AwaitingProof → Settled / Refunded / ForceRefundEligible.
- **Visa Tap / Mastercard rails** — payment-protocol abstraction lives in `tenzro-payments::PaymentProtocol` trait; rail-specific adapters extend the protocol gateway. Both rails register through the same `PaymentGateway::route()` dispatcher.

The trait makes adding a rail uniform: declare a `PaymentProtocolId`, implement `create_challenge` / `verify_credential` / `settle` / `create_credential`, register with the gateway. Payment-side feature completeness is in scope per the `feedback_payment_protocols_all_in_scope.md` rule.

### 3.3 Escrow + micropayment channels

Two complementary primitives:

- **On-chain escrow** — consensus-mediated `CreateEscrow` (selector `0x01000010`) / `ReleaseEscrow` (`0x01000011`) / `RefundEscrow` (`0x01000012`) typed transactions. Vault address is deterministic (`Address(SHA-256("tenzro/escrow/vault" || escrow_id))` — no private key). Payer-only authorisation for release/refund; expiry-based force-refund.
- **Micropayment channels** — `MicropaymentChannelManager` for off-chain per-token billing. Channel state is `(nonce, payer_balance, payee_balance)`; Ed25519-signed updates. Settlement on-chain at channel close or dispute. Channel signatures verified against `ChannelState::canonical_message()` — the same preimage payer and verifier sign.

Per-token inference billing rides channels (open once per provider; settle per session). Settlement of a multi-step task rides escrow (lock at task post; release at completion).

### 3.4 Bridge custody

Cross-chain TNZO movement is the highest-stakes custody surface. Today it's single-key Secp256k1 — one compromised host signs an outgoing message and the bridge mints on the destination chain. Mitigations:

- **Wormhole NTT** for TNZO itself — Guardian-VAA consensus across 19 Guardians, not a single signer.
- **LayerZero V2 with mandatory Tenzro DVN** for non-TNZO messages — Tenzro DVN is one signer of N; LayerZero's stack requires N-of-M attestations.
- **Chainlink CCIP** for token transfers where the CCT (Cross-Chain Token) v1.6+ pool model is preferred.
- **deBridge DLN** for intent-based flows.
- **Canton bridge** for enterprise rails (DAML, CIP-56).

Phase B's bridge-custody hardening seals the single-key `EvmTransactionSigner` inside the validator's TEE (Intel TDX / AMD SEV-SNP); the host never sees the private key. **CGGMP24 threshold ECDSA** (LFDT-Lockness fork) replaces this single-key signer with a t-of-n quorum in Phase D, gated on `LFDT-Lockness/fast-paillier#23` resolving upstream. The bridge signer then becomes a threshold of validators configured at deploy time and a single-host compromise no longer produces a valid outgoing bridge message.

---

## 4. Consensus & Validator Overlay

### 4.1 HotStuff-2 + reputation-weighted proposer election

HotStuff-2 BFT with two-phase commit (PREPARE → COMMIT → DECIDE), linear O(n) communication. TEE-attested validators get 2× weight in leader selection.

**`ReputationProposer`** replaces round-robin proposer selection. Validators with consistent uptime, low latency, and clean attestation history get proposed more often. Combined with the no-endorsement-certificate (NEC) pattern (validators broadcast a signed "no endorsement" when they don't participate in a round, preventing silent stalls). The technical paper uses these names; user-facing docs use "reputation-weighted proposer election" and "no-endorsement certificates" — never the academic project names (Aptos, Monad). Per `feedback_no_aptos_brand.md`.

**Slashing:** consensus equivocation (double-vote) detected by `EquivocationDetector` in `VoteCollector`. `SlashingCallback` (implemented by `StakingSlashingCallback` in `tenzro-node`) bridges to `StakingManager::slash()` — 10% stake penalty. The same `slash()` path will be called by the SLA pipeline (§1.3) for provider failures, so provider-stake and validator-stake are unified accountability.

### 4.2 Validator-only direct-connect overlay

Repeated from §1.1 because it's the load-bearing consensus choice:

- HotStuff-2 votes / proposals / certificates ride a `gossipsub::Config.direct_peers` mesh populated from `ValidatorRegistry` at boot.
- The public `tenzro/consensus` topic deprecates; non-validators don't see vote traffic.
- `NodeValidatorRegistry::authorize_peer_for_topic` already authorises peers per-topic; the `direct_peers` population is the wiring step that completes the design.
- Reachability: every validator dials every other validator on startup; the mesh is N(N-1)/2 connections rather than gossipsub's `mesh_n=6`. For 10 validators that's 45 connections — bounded and predictable.

### 4.3 PQ migration — flag-day cutover

Every signature surface migrates to the Ed25519 + ML-DSA-65 hybrid on the same day. No deprecation, no shims, no "old format" backward compatibility. The pre-launch hygiene rule (`feedback_no_backcompat_no_deadcode.md`) makes this clean: there are no live users to migrate.

What flips on flag-day:

- Validator vote signatures.
- Transaction signatures (the canonical `Transaction::hash()` preimage stays the same; the signature over it becomes hybrid).
- Identity credential signatures.
- A2A message signatures.
- libp2p Noise handshake (already PQ-hybrid via Caddy on the TLS path; the libp2p path catches up).

**Combined with BLS12-381 vote aggregation** to amortise the breaking change. Two refactors → one cutover. `tenzro-crypto::bls` (real `blst`) wires into HotStuff-2 vote aggregation as part of this milestone; the hybrid sig wraps the BLS-aggregated vote envelope.

**ZK split as the follow-up.** Plonky3 AIR public inputs keep their current `Vec<Vec<u8>>` shape; the verifier rebinds public-input encoding to the hybrid pubkey wherever a pubkey appears as a public input (identity AIR). Wave 2, not part of the flag-day.

---

## 5. The Data Plane

What the protocol moves on the wire, in what format, with what commitment.

### 5.1 Receipts as the universal unit

Every Tenzro side-effect produces a `ReceiptEnvelope` (§1.2). Inline by default for low-volume kinds; offloaded to DA for high-volume kinds. The receipt is the unit of accountability; auditors verify receipts, not source data.

**Writers that retrofit to `ReceiptEnvelope`** (the no-dead-code work):

- Settlement engine — every settled payment produces a `Settlement` receipt.
- Inference router — every served inference produces an `Inference` receipt with the result CID.
- Agent message router — every cross-agent message produces an `AgentMessage` receipt.
- Channel manager — every channel close produces a `SettlementChannel` receipt with the full state-update chain.
- Governance — every proposal vote produces a `Governance` receipt.
- Kill-switch — every emergency action produces a `KillSwitch` receipt.
- 7683 fill — every fill produces a fill-side receipt under `7683_dest:` keyspace.

Order of retrofit (§9 sequencing call-out): Inference first (highest volume → biggest argument for DA offload), Settlement / SettlementChannel next, AgentMessage after, then Governance / KillSwitch / 7683.

### 5.2 Inference results as content

Every inference result gets a CID. The receipt envelope holds:

- `commitment` = SHA-256 of the canonical inference payload (request + response).
- `result_cid` = CID of the response artifact (image embedding, transcription, forecast quantiles, chat completion).
- `da_pointer` = backend-specific locator (Celestia namespace+commitment, EigenDA blob ID, Avail data root).

Verifiers re-derive `commitment`, optionally fetch the artifact via the DA backend, and check both. The `tenzro_verifyDaPointer` RPC orchestrates the round-trip. Until Celestia ships, the inline backend returns the inline payload directly.

### 5.3 Training artifacts (Tenzro Train)

Per the Rust-protocol-Python-trainer split (`project_tenzro_train_architecture.md`): `tenzro-training` (Rust) owns `OuterGradient`, `Fragment`, `SyncRound`, aggregation rules (Mean / TrimmedMean / CoordinateMedian / Krum), `OuterOptimizer`, `TrainingTaskSpec`, `TrainingReceipt`, gossip topic handling, on-chain commitments, fraud-proof verification, RPC, CLI. No tensor lib in the Rust workspace.

`integrations/trainer/` (Python) wraps PyTorch FSDP2 + Hivemind + safetensors and does the inner training loop. Communicates with the Rust syncer over JSON-RPC + the gossip topics. The reference trainer is the only one Tenzro ships; third parties implement compatible trainers in any language using the published gossip-topic + RPC contract.

Phase 1 scope: timeseries-first (TimesFM 2.5 — already on the live catalog), simple mean aggregation, stake bonding only (no Byzantine defense), Open trust tier. Phases 2–5 (Byzantine-robust aggregation, multi-region scale, multi-modal beyond timeseries, TEE-resident data) per `TRAIN.md` §7.4 stay on the roadmap.

### 5.4 Identity export

W3C DID JSON today. The path forward:

- **DID JSON stays** as the human-readable export. The ATProto / Solid / Nostr ecosystems consume it; the W3C DID method registration PR (`docs/did-registration/`) registers `did:tenzro` upstream.
- **CAR / MST** ships as a separate `tenzro identity export-car` flow for users who want a content-addressable bundle of their identity + credentials + agent delegations. CAR file holds a Merkle Search Tree of credentials, addressable by CID. Restorable on any Tenzro node.

The MST migration is Phase B; the JSON path is the daily-driver.

---

## 6. The Agent Surface

### 6.1 Tenzro as MCP server hub

Eight live MCP servers on tenzro.network subdomains:

| Server | Subdomain | Port | Focus |
|---|---|---|---|
| Tenzro main | `mcp.tenzro.network` | 3001 | Wallet, identity, payments, inference, multi-modal AI, staking, tokens, NFTs, bridges, verification, agents, tasks, skills, tools, compliance, TEE, ZK, VRF, events |
| Solana | `solana-mcp.tenzro.network` | 3003 | Jupiter swap, SPL, Metaplex DAS, Bonfida SNS |
| Ethereum | `ethereum-mcp.tenzro.network` | 3004 | Chainlink feeds, ENS, ERC-8004, EAS |
| Canton | `canton-mcp.tenzro.network` | 3005 | DAML, CIP-56, DvP |
| LayerZero | `layerzero-mcp.tenzro.network` | 3006 | V2 messaging, OFT, Value Transfer, Stargate V2, DVNs |
| Chainlink | `chainlink-mcp.tenzro.network` | 3007 | CCIP, Data Feeds, Data Streams, VRF v2.5, PoR, Automation |
| Li.Fi | `lifi-mcp.tenzro.network` | 3008 | Cross-chain aggregation, quotes, routes |
| External: deBridge | `agents.debridge.com/mcp` | — | DLN cross-chain swaps |
| External: 1inch | via 1inch Developer Portal | — | DEX aggregation |

All servers migrate to `structuredContent` + `outputSchema` in Phase A. The migration is mechanical — every `#[tool]` handler's response type derives `schemars::JsonSchema`, the macro emits the schema reference. Existing input-schema derivation is the template.

**OAuth 2.1 + PKCE + DPoP** is wired (ahead of the MCP spec on DPoP). `/.well-known/oauth-protected-resource` published. Bearer tokens scoped per skill.

### 6.2 A2A skills as MCP tool families

The A2A Agent Card at `a2a.tenzro.network/.well-known/agent.json` lists skills. Each skill is:

- A name (`wallet`, `inference`, `cortex`, …).
- A description.
- A set of MCP tool references (canonical names from the main MCP server's manifest).
- An authorisation profile (which DPoP scopes unlock the skill).

Skill curation is a config-level edit, not a code change. The Rust Agent Card builder and the Python equivalent should produce identical skill lists (today they don't — Rust 25, Python 34; gap matrix flagged this for #141 doc fix).

Adding a new skill: pick its MCP tools, give it a description, attach it to the Agent Card. The MCP tools themselves are already implemented; the skill is the curated view.

### 6.3 Memory tier

Three tiers (Letta pattern), all backed by `AgentRuntime` storage + RocksDB `CF_AGENTS`:

| Tier | Size | Latency | Access |
|---|---|---|---|
| Core | Small | Always-loaded | Read on every request |
| Recall | Medium | Indexed search | Vector + BM25 retrieval |
| Archival | Large | On-demand fetch | Explicit `memory_archival` tool call |

`DelegationScope` gates writes; the controller's scope decides which memory tiers a delegated agent can access and whether the agent can grant read access to other agents. Three MCP tools:

- `memory_grant(target_did, tier, ttl)` — grant another agent read access to a tier.
- `memory_recall(query, tier, limit)` — search the recall or archival tier.
- `memory_archival(item, tier, metadata)` — write to recall or archival.

The vector-search backend rides Lance (or a SQLite-backed VSS for small deployments); the BM25 backend rides Tantivy. Neither ships as a built-in module — the tool calls dispatch to a configured backend, with a small in-memory default for testing.

### 6.4 Skills + Tools registry

Today: 8 skills (`openclaw-tenzro`, `solana-defi`, `ethereum-defi`, `canton-enterprise`, `layerzero-bridge`, `chainlink-oracle`, `debridge-cross-chain`, `oneinch-aggregator`) and 7 tools (the 5 internal MCP servers + 2 external) registered at node startup.

The registry is the discovery surface for both humans (browsing via CLI / desktop / Cookbook) and agents (querying via `tenzro_searchSkills` / `tenzro_searchTools`). It's not a marketplace yet — there's no payment for skill use. Phase C: monetised skill/tool registration with the 5% creator commission already specified in the `tenzro-agent-kit` design.

---

## 7. Failure Modes & Defenses

### 7.1 Custody compromise

**Threat:** a single compromised host signs an outgoing transaction draining a wallet.

**Defense layers:**

1. **MPC threshold (2-of-3)** for every human wallet — no single device compromise drains.
2. **ERC-7579 validator modules** for machine wallets (delegated + autonomous) — the protocol ceiling re-checks delegation scope at signing time. Off-chain `SpendingPolicyResolver` stays as defense-in-depth; on-chain validator module is the primary control. Per the Grok / Bankr May 2026 lesson (`feedback_custody_enforce_at_signing_time.md`).
3. **TEE-sealed bridge signer (Phase B) → CGGMP24 t-of-n threshold (Phase D)** for bridge custody — Phase B keeps the bridge key inside a TDX/SEV enclave so a host compromise yields ciphertext, not the key; Phase D dissolves the single-key signer entirely once `LFDT-Lockness/fast-paillier#23` clears upstream.
4. **Time-bounded delegations** — every `DelegationScope` carries a `time_bound`; expired delegations fail at signing.
5. **Cascading revocation** — controller revokes → registry broadcasts via `RevocationBroadcaster` → every node's `apply_remote_revocation` removes the delegation.

### 7.2 Consensus liveness

**Threat:** validators stop producing blocks (network partition, configuration drift, idle-timeout churn).

**Defense layers:**

1. **`connection_idle_timeout: 600s`** — survives GCE Andromeda 10-minute conntrack eviction. Combined with kernel TCP keepalive every ~120s (configured in cloud-init).
2. **Tri-continental fleet** — 10 validators across us-central + europe-west + asia-southeast. Network partition of one continent loses ≤ f-1 votes; quorum holds. Tradeoff: high p99 RTT (cross-continental); tolerable for sub-second consensus.
3. **Reputation-weighted proposer election + NEC** — failing validators get rotated out of leadership; missing rounds are explicitly attested rather than silent.
4. **`/ready` endpoint** — Kubernetes / GCE health-check surfaces consensus state, not just process liveness. `docker healthy` ≠ consensus healthy (per the canary lesson `feedback_canary_one_validator_before_fleet.md`).

### 7.3 DA backend availability

**Threat:** offloaded receipt payloads are unrecoverable.

**Defense layers:**

1. **`InlineFallbackBackend` as default** — refuses to offload until a real backend is registered. No silent data loss; writes fail loudly.
2. **`commitment` is invariant** — the SHA-256 of the canonical payload is set at write time; verifiers can re-derive from whatever they read. Backend-level corruption doesn't break verification, only retrieval.
3. **Multiple backends in parallel** — Phase C runs Celestia + EigenDA + Avail concurrently for critical receipt kinds (Settlement, Governance). `verify_availability` polls all three; success on any one is sufficient.
4. **Inline by default for low-volume kinds** — Settlement, KillSwitch, Lifecycle, Governance stay inline regardless of backend availability. Only Inference / AgentMessage / SettlementChannel offload.

### 7.4 Sybil at the provider edge

**Threat:** a single actor registers many provider identities with low or fake hardware claims, inflating capacity numbers and arbitraging routing.

**Defense layers:**

1. **Self-signed ProviderManifest** — the provider DID signs the manifest, including the hardware claims. Identity registration is on-chain and stake-bonded.
2. **TEE attestation** — providers claiming `has_tee: true` produce a real attestation from Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA CC. Intel Tiber Trust Authority appraisal makes the trust root vendor-portable.
3. **Validator-issued challenges** — `tenzro/inference/challenges` topic, VRF-selected validators (precompile 0x1007), signed probe requests. Failed challenges slash `ComputeBond`.
4. **Reputation asymmetry** — −5 per failure, +1 per success (saturating at 0 / 1000). Sybils have to absorb many successes to recover from a single failure; rational behaviour is honest operation.
5. **Stake threshold** — minimum `ComputeBond` to register; bond size scales with declared capacity.

---

## 8. What Ships in Each Phase

Forward pointer to `ROADMAP.md` — one sentence per phase, just enough to anchor.

- **Phase A (current, Q3 2026 testnet stability):** tri-continental fleet operational; libp2p NAT-traversal trio wired; HotStuff-2 direct-connect overlay; ProviderManifest extended with `HardwareCapabilities`; `structuredContent` on all 246 MCP tools; Celestia DA backend; `ReceiptEnvelope` retrofit (Inference first); audio runtime (Moonshine + Whisper); ERC-8004 + A2A doc-drift cleanup.
- **Phase B:** PQ flag-day cutover (Ed25519 + ML-DSA-65 hybrid sigs everywhere) + BLS12-381 vote aggregation in one breaking change; FROST-Ed25519 DKG for the validator set; bridge `EvmTransactionSigner` sealed inside TDX/SEV enclaves (CGGMP24 t-of-n migration deferred to Phase D); ERC-7579 validator modules for delegated + autonomous custody; memory tier (core/recall/archival); Lance vector index + Tantivy BM25; `ComputeBond` + SLA challenge pipeline live.
- **Phase C:** Intel Tiber Trust Authority `get_token_v2` integration; EigenDA + Avail backends as redundancy; TEE+ZK production wave (verifiable inference in TEE-attested AIR); Tenzro Train Phase 1 (timeseries-first, Open trust tier, mean aggregation); monetised skill/tool registry (5% commission); CAR/MST identity export.
- **Phase D (mainnet readiness):** external security audit complete; IBC-Eureka SP1 path live; Byzantine-robust aggregation (TrimmedMean / CoordinateMedian / Krum) for Train Phase 2; multi-modal training beyond timeseries (vision, audio); mainnet TNZO genesis distribution and migration of testnet state.

---

## 9. Wiring Sequence (sequencing call-outs)

Items the gap matrix surfaced that aren't pure implementation work — they need sequencing direction. None of these are "should we do it" decisions; all of them are "in what order, against which existing primitive."

### 9.1 BLS12-381 vote aggregation timing

`tenzro-crypto::bls` (real `blst`) wires into HotStuff-2 vote aggregation. Sequencing: combine with the PQ flag-day (§4.3) so it's one breaking change instead of two. The vote signature envelope becomes `BLS-aggregated(Ed25519 + ML-DSA-65)`; verifier checks BLS aggregation first, then composite for any individual vote being inspected.

### 9.2 DA backend rollout order

Celestia first per CLAUDE.md. Sequencing: **`ReceiptEnvelope` retrofit must precede the Celestia backend**. Writers exist before backends; otherwise the backend has nothing to receive. Order:

1. Retrofit Inference writer to `ReceiptEnvelope` (highest volume).
2. Retrofit Settlement + SettlementChannel writers.
3. Retrofit AgentMessage writer.
4. Land Celestia backend; switch `Inference` / `SettlementChannel` / `AgentMessage` default mode to `OffloadedDA`.
5. Retrofit Governance + KillSwitch + 7683 writers (these stay `Inline` regardless).

### 9.3 ERC-7579 validator-module integration

Validator modules wire through `SmartAccount` in `tenzro-vm` (already has SocialRecovery / SessionKey / SpendingLimit / Batching modules) and ship in Phase B. Threshold-ECDSA bridge custody (§3.4) is upstream-blocked and ships in Phase D — so the sequencing question that used to exist (ERC-7579 first vs CGGMP24 first within Phase B) no longer arises.

### 9.4 Audio runtime — implementation timing

The `StubTranscriber` and empty audio catalog are scaffolding for the real Moonshine v2 + Whisper + Parakeet + Canary transcribers. The spec wants ASR — task #111 is the implementation. Sequencing: lands in Phase A alongside the receipt retrofit, not deprioritised. Other multi-modal runtimes (timeseries, vision, text-embedding, segmentation, detection, video) are already real; audio is the last placeholder.

### 9.5 Receipt retrofit order

Per §9.2: Inference → Settlement → SettlementChannel → AgentMessage → Governance / KillSwitch / 7683. Inference first because volume; the others follow in decreasing volume order.

### 9.6 Memory file refresh (part of #141)

Two stale memories the gap matrix surfaced:

- `feedback_no_gg18_gg20_use_cggmp21_or_frost.md` claims `tenzro-crypto::mpc` is Shamir-only. The module has been replaced wholesale by `tenzro-crypto::frost` (FROST-Ed25519 for validator/agent keys); CGGMP24 for secp256k1 bridge keys is sequenced to Phase D once `LFDT-Lockness/fast-paillier#23` resolves. The memory needs updating to reflect both halves.
- `project_consensus_upgrade.md` says "Replace round-robin select_leader." `ReputationProposer` is already wired in HotStuff-2; the memory needs to reflect that the upgrade is shipped, only the NEC half remains.

Plus three CLAUDE.md doc-drift fixes (part of #141):

- ERC-8004 `agentId` is sequential u64, not `keccak256(utf8(did))`.
- MCP server advertises `V_2025_11_25`, not `2025-03-26`.
- A2A skill count: 25 in Rust, 34 in Python; reconcile both to a single canonical list.

Plus one server.rs stale literal: `tools = 20` log line at `server.rs:10218` — real count is 246.

### 9.7 Cross-doc consistency

`CLAUDE.md`, `WHITEPAPER.md`, `SPECIFICATION.md`, this doc, and `ROADMAP.md` describe the same system at different scopes. Keep them aligned:

- This doc is the **design** — what we're building and why.
- `CLAUDE.md` is the **operational guide** — how to build / deploy / debug, what's currently true about the runtime.
- `WHITEPAPER.md` is the **vision** — for external audiences, lower technical detail.
- `SPECIFICATION.md` is the **wire spec** — exact formats, byte layouts, protocol messages.
- `ROADMAP.md` is the **schedule** — phases, acceptance criteria, dates.

When any of these change, propagate. The gap matrix is the audit point — it cross-references this doc against actual code and flags drift.

---

## 10. Reading-list pointers

Each pillar's `Sources` block in `ARCHITECTURE-PRIOR-ART.md` lists the primary references for that pillar. The minimum-viable reading list to understand this doc:

- **P2P:** rust-libp2p Cargo manifest + `crates/tenzro-network/src/{config,behaviour,event_loop}.rs`. The Lighthouse Kademlia bootstrap pattern (`sigp/lighthouse#3005`).
- **Data:** Celestia data availability paper; EigenDA whitepaper; the IPLD spec (`ipld.io/specs`); the Lance format docs.
- **Compute:** the Eigenlayer restaking paper; the Akash provider manifest schema as a reference for hardware fields.
- **Agent:** MCP 2025-06-18 spec; Google A2A spec at `linuxfoundation.org/projects/agent2agent`; the Letta architecture paper.
- **Crypto:** NIST FIPS 203 / 204 / 205 (ML-KEM / ML-DSA / SLH-DSA); RFC 9591 (FROST); the CGGMP21 paper; the Plonky3 source at git rev `32079474b1d31d9221656ae774afb322d2597db0`.

Everything in this doc has a citable upstream. Tenzro is composing existing primitives, not inventing new ones. The protocol's contribution is the composition: identity + custody + settlement + verification + multi-modal inference + decentralised training, on one ledger, under one consensus, with one identity model.
