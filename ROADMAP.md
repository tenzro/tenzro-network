# Tenzro — Roadmap

**Status:** roadmap. Companion to `ARCHITECTURE-PRIOR-ART.md`, `ARCHITECTURE-GAP-MATRIX.md`, and `ARCHITECTURE-AGENTIC-INTERNET.md`. Reading order: Prior-Art → Gap-Matrix → Design → this doc.

This roadmap turns the design into a sequence: four phases (A → D), with acceptance criteria per phase. Each phase is a coherent shipping unit — the criteria are the gates that move the protocol from one phase to the next.

The roadmap commits to **scope ordering**, not calendar dates. Phase boundaries are crossed when the criteria are met, not when a date arrives. Where dates appear, they are targets framing the order of magnitude (weeks vs. months vs. quarters), not deadlines.

---

## How to read this doc

Each phase has five blocks:

- **Goal** — what this phase exists to deliver.
- **In scope** — work that lands inside the phase boundary.
- **Out of scope** — work that explicitly waits for a later phase. Listed so reviewers don't ask "what about X?" mid-phase.
- **Acceptance criteria** — the gates. Every criterion must be green to cross into the next phase.
- **Dependencies** — what must be true before the phase can start.

Cross-references:
- `[GAP §N.M]` points to `ARCHITECTURE-GAP-MATRIX.md` Section N, subsection M.
- `[DESIGN §N]` points to `ARCHITECTURE-AGENTIC-INTERNET.md` Section N.
- `[#NNN]` is a task ID in the active TaskList.

---

## Phase A — Testnet Stability

**Goal:** the live testnet (`rpc.tenzro.network` + 10 GCE validators tri-continental) is operationally boring. Fleet stays up across deploys. NAT-traversal works for community joiners. The MCP surface emits structured output the way the 2025-06-18 spec expects. The first real DA backend (Celestia) is live behind `ReceiptEnvelope` retrofits. Audio modality stops being a placeholder.

### A.1 In scope

**Networking**

- Instantiate Relay v2 + AutoNAT v2 + DCUtR behaviours in `TenzroBehaviour`. Wire `enable_relay` / `enable_hole_punching` config fields to real behaviours. [GAP §1, top gap #2] [DESIGN §1.1] [#132]
- Populate `gossipsub::Config.direct_peers` from `NodeValidatorRegistry` at boot. Move HotStuff-2 vote, proposal, and certificate messages from `tenzro/consensus` gossipsub to the direct-connect mesh. [GAP §1, top gap #1] [DESIGN §4.2]
- Periodic Kademlia bootstrap (Lighthouse 60s pattern) — `service.rs` cleanup tick gets a `kad.bootstrap()` arm. [GAP §1, top gap #3]

**Node lifecycle**

- `/ready` endpoint surfacing consensus state, not just process liveness. [#129]
- Graceful exit — drain in-flight RPC, wait for current consensus round, then SIGTERM. [#129]
- Snapshot ABCI + state-sync bootstrap so new joiners catch up without full historical replay. [#129]

**Data layer**

- Retrofit `ReceiptEnvelope` to high-volume writers in this order (Inference → Settlement / SettlementChannel → AgentMessage). Inline mode by default; offload mode behind a feature flag until Celestia lands. [GAP §2, top gap #2] [DESIGN §5.1, §9.5]
- Implement `CelestiaBackend` against the `DaBackend` async trait. Namespace per receipt-kind. Blob inclusion proof verified against Tendermint header. [GAP §2, top gap #1] [DESIGN §1.2]
- Flip `Inference` / `SettlementChannel` / `AgentMessage` default storage mode to `OffloadedDA` once Celestia is registered and probed green.

**Compute / providers**

- Extend `InferenceProvider` with `HardwareCapabilities` (already exists at `tenzro-model/src/provisioning.rs`; attach + propagate). Surface in `ProviderAnnouncementMessage`. [GAP §3, top gap #1] [DESIGN §1.3]
- Add `bytes_in` / `bytes_out` to `UsageRecord`. Wire `libp2p::BandwidthCounter` per-request. [GAP §3, top gap #2]
- `ComputeBond` struct (sibling to `AgentBondState`). RPC: `tenzro_postComputeBond` / `tenzro_getComputeBond`. No challenge pipeline yet — bond is declared but not yet slashable.

**Agent / MCP**

- Migrate every `#[tool]` handler's response type to derive `schemars::JsonSchema`. Emit `outputSchema` + `structuredContent` per the 2025-06-18 spec. All 246 tools. [GAP §4, top gap #1] [DESIGN §6.1]
- Reconcile A2A skill count between Rust and Python — single canonical skill list in `proto/tenzro/v1` referenced by both. [GAP §4 doc-drift]
- Fix stale `tools = 20` literal at `server.rs:10218` → emit the real registered-tool count. [GAP §4 doc-drift]
- CLAUDE.md correctness pass — three doc-drift fixes: ERC-8004 `agentId` is sequential u64 (not keccak256), MCP server advertises `V_2025_11_25` (not `2025-03-26`), A2A skill count converges on the canonical Rust/Python-shared list. [DESIGN §9.6] [#141 partial]

**Multi-modal**

- Audio runtime — real Moonshine v2 (tiny/base), Distil-Whisper, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash transcribers. ORT encoder + autoregressive decoder loop with KV-cache. Mel-spectrogram preprocessing, BPE detokenization. RNN-T joint decoding for Parakeet. Replace `StubTranscriber`. [DESIGN §9.4] [#111]
- Forecast catalog stays TimesFM-only on the live testnet. Chronos-2 multi-input adapter is post-Phase-A.

**Memory / docs**

- Memory hygiene: stale snapshot-style memories are deleted rather than patched (see `feedback_stale_memory_delete_dont_edit.md`). New memories are written only from current code state, not from outdated framing.
- Rsync exclude lists verified to propagate the new architecture docs (`ARCHITECTURE-PRIOR-ART.md`, `ARCHITECTURE-GAP-MATRIX.md`, `ARCHITECTURE-AGENTIC-INTERNET.md`, `ROADMAP.md`) to the github mirror while keeping CLAUDE.md excluded. [#142 done]

### A.2 Out of scope

- PQ flag-day. Hybrid signatures stay aspirational until Phase B. [Phase B]
- BLS12-381 vote aggregation. Coupled with PQ flag-day. [Phase B]
- CGGMP24 secp256k1 threshold ECDSA bridge custody. [Phase D — gated on upstream `LFDT-Lockness/fast-paillier#23`]
- ERC-7579 validator modules. [Phase B]
- Memory tier (core/recall/archival). [Phase B]
- Intel Tiber Trust Authority `get_token_v2`. [Phase C]
- EigenDA / Avail backends. Celestia is the only DA in Phase A. [Phase C]
- Tenzro Train Phase 1 — Rust protocol crate + Python reference trainer ship in Phase C. The current `tenzro-training` crate stays at protocol-only scope.
- Mainnet anything. [Phase D]

### A.3 Acceptance criteria

Phase A is complete when all of these are green:

1. **Fleet liveness over 7 consecutive days** — `tenzro_nodeInfo` on rpc.tenzro.network returns `peer_count ≥ 9`, `health_status=Healthy`, block height advancing continuously. Tracked via a long-running monitor.
2. **NAT-traversal works for a community joiner** — a fresh node behind home NAT (residential ISP, no port forwarding) successfully joins the testnet via Relay v2 reservation + DCUtR upgrade and stays connected for ≥ 1 hour.
3. **HotStuff-2 votes ride the direct-connect overlay** — packet capture on any validator confirms vote / proposal / certificate messages travel over `direct_peers`, not gossipsub mesh propagation. `tenzro/consensus` topic has zero traffic.
4. **`/ready` reflects consensus state** — endpoint returns 503 during state-sync, 200 only when caught up and contributing votes. Verified via deploy rollover (new pod stays 503 until it joins quorum).
5. **`ReceiptEnvelope` retrofit complete for Inference + Settlement + SettlementChannel + AgentMessage** — every write produces an envelope; verifier (`tenzro_verifyDaPointer`) returns `available:true` for any envelope written under `OffloadedDA` mode.
6. **Celestia backend ships green** — `verify_availability` round-trips work for all four retrofit writers. Blob inclusion proofs verify against current Celestia mainnet headers.
7. **All 246 MCP tools return `structuredContent` + `outputSchema`** — a validating MCP client (e.g., the OpenAI Agents SDK in strict mode) iterates every tool, calls it with valid input, and validates the response against the emitted schema. Zero string-typed JSON responses.
8. **Audio runtime catalogues real transcribers** — `tenzro_listAudioCatalog` returns ≥ 5 entries (Moonshine v2 base, Distil-Whisper small.en, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash). `tenzro_transcribe` returns a non-stub result for each.
9. **ProviderManifest carries hardware + geography** — `tenzro_listProviders` response includes `gpu_model` / `vram_gb` / `cpu_cores` / `ram_gb` / `country` / `region` per provider entry. Self-signature on the manifest verifies against the provider's on-chain DID.
10. **Memory and docs are consistent** — gap-matrix doc-drift items resolved in CLAUDE.md; stale memories refreshed; new memories indexed; rsync excludes updated.

### A.4 Dependencies

- Fleet is up (already true as of 2026-05-14).
- Image build pipeline functional (`gcloud builds submit` to `tenzro-infra`).
- ARCHITECTURE-PRIOR-ART.md, ARCHITECTURE-GAP-MATRIX.md, ARCHITECTURE-AGENTIC-INTERNET.md are in the tree (true).
- No phase before this — Phase A is the current phase.

---

## Phase B — Cryptography Flag-Day + Custody Hardening

**Goal:** every signature in the protocol becomes post-quantum hybrid in one breaking change. Bridge custody stops being single-key. Machine custody is enforced at signing time, on-chain. Agents grow a real memory tier.

### B.1 In scope

**PQ flag-day (combined breaking change)**

- Validator vote signatures → BLS12-381 aggregated `(Ed25519 + ML-DSA-65)` hybrid. [DESIGN §4.3, §9.1]
- Transaction signatures → composite Ed25519+ML-DSA-65 over canonical `Transaction::hash()`.
- Identity credential signatures → same composite.
- A2A message signatures → same composite.
- libp2p Noise handshake → X25519+ML-KEM-768 hybrid (matching Caddy 2.10's TLS path).
- `tenzro-crypto::bls` (real `blst`) wired into HotStuff-2 vote aggregation as part of this cutover. [GAP §5, top gap #2]
- All chain state generated under the old signature scheme is dropped — pre-launch hygiene rule applies, no live users to migrate.
- Wire format documented in `SPECIFICATION.md` under `signatures/hybrid-pq`.

**Threshold cryptography**

- **FROST-Ed25519** (RFC 9591) replaces `tenzro-crypto::mpc` for validator and agent identity keys. DKG ceremony for validator key generation. Threshold signing without trusted dealer. [DESIGN §1.5]
- Bridge custody for Phase B continues to use the single-key `EvmTransactionSigner` in `tenzro-bridge`, sealed inside the validator's TEE where one is present (Intel TDX / AMD SEV-SNP). The TEE-sealed key is the Phase B ceiling on bridge-custody hardening. CGGMP24 secp256k1 threshold ECDSA is sequenced to Phase D — see B.5 below.

**Custody hardening**

- ERC-7579 validator modules wired through `SmartAccount` in `tenzro-vm`. Every machine transaction (delegated + autonomous identity classes) passes through a validator-module check at signing time that re-verifies `DelegationScope` from on-chain registry. [DESIGN §2.2, §2.3] [GAP §3, top gap #3]
- `SpendingPolicyResolver` becomes explicit defense-in-depth, not the primary control. Doc clarifies this.

**Agent memory tier**

- `memory_grant` / `memory_recall` / `memory_archival` MCP tools. Backed by `AgentRuntime` storage + `DelegationScope` gating. [DESIGN §6.3] [GAP §4, top gap #3]
- Vector backend: Lance (default for indexed search). BM25 backend: Tantivy.
- Tier storage in RocksDB `CF_AGENTS` under `memory_core:` / `memory_recall:` / `memory_archival:` prefixes.

**Compute market**

- SLA challenge pipeline live. `SlaCommitment` declared in `ProviderManifest`. VRF-selected validators (precompile 0x1007) issue signed probe inference requests on a per-epoch cadence. Failed challenges slash `ComputeBond` via the existing `StakingManager::slash()` path. [DESIGN §1.3, §7.4] [GAP §3, top gap #3]
- Asymmetric reputation continues (-5 / +1); slashing is the hard signal.

**Cross-chain**

- ERC-7683 fill-side idempotency tests on a Sepolia ↔ Tenzro testnet pairing.
- Wormhole NTT signer continues on the single-key `EvmTransactionSigner` (TEE-sealed where available); CGGMP24 migration tracked under Phase D.

### B.2 Out of scope

- Intel Tiber Trust Authority `get_token_v2` integration. [Phase C]
- ZK split (Plonky3 AIR public-input rebind to hybrid pubkeys). [Phase C]
- EigenDA / Avail backends. [Phase C]
- Tenzro Train Phase 1. [Phase C]
- Byzantine-robust aggregation for training. [Phase D]
- CGGMP24 secp256k1 threshold ECDSA bridge custody. [Phase D — B.5]
- Mainnet genesis. [Phase D]

### B.3 Acceptance criteria

1. **Flag-day cutover ships clean** — old-signature transactions are rejected at the mempool boundary. No fallback path. New testnet image deployed; old state wiped (per pre-launch hygiene).
2. **BLS-aggregated hybrid votes verify end-to-end** — a validator votes; the certificate carries the BLS aggregate; verifier on a non-validator full-node verifies both the BLS aggregation and any individual hybrid signature inspected from it.
3. **FROST-Ed25519 DKG completes for the validator set** — 10 validators run DKG; the resulting threshold key signs a test vote; no single key share is sufficient to forge.
4. **Bridge custody key is TEE-sealed on every TDX/SEV-capable validator** — `EvmTransactionSigner`'s secp256k1 key material lives inside the enclave; the host process never sees the cleartext private key. Verified via attestation + a key-extraction red-team exercise on the host filesystem.
5. **ERC-7579 validator-module check at signing time** — a machine transaction with a stale or revoked `DelegationScope` is rejected by the validator module before the signature is produced, regardless of `SpendingPolicyResolver` state.
6. **Memory tier round-trip** — an agent grants another agent recall-tier access via `memory_grant`; the second agent retrieves a memory item via `memory_recall`; the access is gated by `DelegationScope`. Vector search via Lance returns ranked results.
7. **SLA challenge slashes a delinquent provider** — a probe inference that times out or returns malformed output consumes the failing provider's `ComputeBond` proportional to the SLA breach. Reputation drops by -5; bond reduction visible on-chain.
8. **No remaining unattested single-key signers** outside `tenzro-cli` user identities. Consensus paths run on FROST-Ed25519; identity / transaction / A2A paths run on hybrid PQ; bridge `EvmTransactionSigner` is TEE-sealed (per criterion 4). CGGMP24 threshold-ECDSA migration of the bridge signer ships in Phase D.

### B.4 Dependencies

- Phase A acceptance criteria all green.
- `tenzro-crypto::bls` is wired (Phase A's BLS work is the prerequisite — the BLS aggregation lands during the flag-day, but the lib being verified-good is Phase A).
- Existing `SmartAccount` module infrastructure (`SocialRecovery`, `SessionKey`, `SpendingLimit`, `Batching`) — already present.

### B.5 Threshold-ECDSA bridge custody — deferred to Phase D

CGGMP24 (LFDT-Lockness fork that replaces CGGMP21 after CVE-2025-66017) is the production secp256k1 threshold ECDSA pick. Wiring it requires `cggmp24 → paillier-zk → fast-paillier → glass_pumpkin`. As of `cggmp24 0.7.0-alpha.3` (2025-12-04) and `fast-paillier 0.3.2` (2025-11-25), the chain does not build against `glass_pumpkin 1.10.0`'s `Rng + DerefMut` requirement. Upstream tracking issue: [`LFDT-Lockness/fast-paillier#23`](https://github.com/LFDT-Lockness/fast-paillier/issues/23) (open since 2026-03-16). Vendoring fast-paillier with a one-line trait-bound patch is technically possible but introduces ongoing maintenance burden on a Paillier crypto path where bug latency is catastrophic; we wait for the upstream fix.

Phase B's bridge-custody hardening therefore stops at TEE-sealing the existing `EvmTransactionSigner` key (acceptance criterion B.3.4). The full t-of-n threshold-ECDSA migration ships under Phase D once upstream stabilizes; until then, single-host bridge compromise is bounded by TEE attestation, not threshold dispersion.

---

## Phase C — Verifiable Compute + Decentralized Training

**Goal:** TEE attestation gets a vendor-portable trust root. Multiple DA backends ship for redundancy. ZK and TEE compose for verifiable inference. Tenzro Train Phase 1 (timeseries-first) goes live with the Rust protocol + Python reference trainer split.

### C.1 In scope

**TEE attestation**

- Intel Tiber Trust Authority `get_token_v2` integration. HTTP client to `api.trustauthority.intel.com`; JWT verifier for ITA tokens; policy-engine integration; composite token verifier in `tenzro-tee`. [DESIGN §1.5] [GAP §5, top gap #1]
- All four TEE providers (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA CC) emit attestations that the appraisal service converts to a single composite token. Verifier checks the composite, not the vendor-specific quote.

**DA backend redundancy**

- EigenDA backend implemented behind `DaBackend` trait. Throughput-oriented; the new default for `Inference` envelopes (volume).
- Avail backend implemented. Redundancy-oriented; mirrors `Settlement` + `Governance` envelopes in parallel with Celestia.
- `verify_availability` polls all configured backends; any one returning `available:true` is sufficient.

**Verifiable compute (ZK + TEE composition)**

- Production wave of TEE-resident Plonky3 proving. Inference results inside a TEE are accompanied by a Plonky3 STARK over the inference AIR; both verify on consumption.
- Identity AIR public inputs rebind to hybrid Ed25519+ML-DSA-65 pubkeys (the ZK half of the PQ flag-day, deferred from Phase B per `DESIGN §4.3`).

**Tenzro Train Phase 1**

- `tenzro-training` (Rust crate) ships protocol primitives: `OuterGradient`, `Fragment`, `SyncRound`, aggregation rule = Mean (simple, non-Byzantine), `OuterOptimizer` = Nesterov SGD, `TrainingTaskSpec`, `TrainingReceipt`, gossip topic handling, on-chain commitments, fraud-proof verification, RPC, CLI. No tensor lib in Rust.
- `integrations/trainer/` (Python) ships the reference trainer: PyTorch FSDP2 + Hivemind + safetensors. Timeseries-first (TimesFM-class 200M models). Communicates with Rust syncer over JSON-RPC + gossip topics.
- Open trust tier only (no TEE-required workers in Phase 1). Stake bonding via `ComputeBond` (carried forward from Phase B).
- `TrainingReceipt` is a `ReceiptKind`, written through `ReceiptEnvelope`, offloaded to a DA backend.

**Skill / Tool monetization**

- Skill / tool registry takes a payment surface: registering a skill or tool can specify a per-use price; consuming the skill triggers an MPP / x402 charge to the consumer with 5% commission to Tenzro treasury. [DESIGN §6.4]
- `tenzro-agent-kit` already defines the creator DID + creator wallet + 5% commission shape; Phase C wires it.

**Identity export**

- CAR/MST identity export — `tenzro identity export-car` produces a content-addressable bundle of identity + credentials + agent delegations. Restorable on any Tenzro node via `tenzro identity import-car`. [DESIGN §5.4]

### C.2 Out of scope

- Byzantine-robust aggregation (TrimmedMean / CoordinateMedian / Krum) for training. [Phase D]
- Multi-modal training beyond timeseries (vision, audio, language). [Phase D]
- TEE-resident training data (private datasets sealed in enclaves). [Phase D]
- IBC-Eureka SP1 path. [Phase D]
- External security audit. [Phase D]
- Mainnet genesis. [Phase D]

### C.3 Acceptance criteria

1. **Intel Tiber Trust Authority round-trip** — a TDX quote on validator-7 (asia-southeast1) is appraised by ITA, returns a composite token; verifier on validator-0 accepts the composite token without consulting Intel directly. Latency ≤ 2s round-trip.
2. **Three DA backends register concurrently** — Celestia + EigenDA + Avail all return `available:true` for the same `Inference` envelope. Single-backend outage does not break verification.
3. **TEE+ZK composition end-to-end** — an inference request runs in a TDX enclave; the response carries a Plonky3 STARK + the enclave's hybrid signature; verifier checks both; both must verify.
4. **Tenzro Train Phase 1 produces a converged model on testnet** — a public training run on a 200M TimesFM-class model, distributed across ≥ 3 worker nodes (Python trainer instances), produces a final safetensors checkpoint whose forecast loss on a held-out test set beats a random-init baseline by ≥ 20% absolute. `TrainingReceipt` chain is verifiable.
5. **Paid skill use settles correctly** — an agent consumes a paid skill; the skill creator's wallet receives 95% of the charge; the Tenzro treasury receives 5%; both are visible on-chain.
6. **CAR identity export round-trip** — a user exports their identity from one node; deletes their local state; imports the CAR bundle on a different node; resumes wallet / agent / credential operations seamlessly.

### C.4 Dependencies

- Phase B acceptance criteria all green.
- The PQ flag-day is in place (the ZK half of public-input rebind depends on it).
- ERC-7579 validator modules live (autonomous training-coordinator agents need them).
- ComputeBond + SLA challenges live (training task assignment uses the same stake/slash machinery).

---

## Phase D — Mainnet Readiness

**Goal:** Tenzro graduates from testnet. External security audit complete. Byzantine-robust aggregation lets training accept untrusted workers. Multi-modal training beyond timeseries. Mainnet TNZO genesis.

### D.1 In scope

**Audit + hardening**

- External security audit covering: `tenzro-crypto` (incl. FROST, CGGMP24 once landed, hybrid sigs, BLS), `tenzro-vm` (Block-STM, EIP-1559, ERC-4337, all precompiles), `tenzro-consensus` (HotStuff-2 + ReputationProposer + NEC), `tenzro-settlement` (escrow + channels), `tenzro-bridge` (CGGMP24 threshold + all adapters), `tenzro-identity` (TDIP + ERC-8004 + delegation enforcement), `tenzro-payments` (MPP + x402 + AP2 + ERC-7683), `tenzro-training` (aggregation + receipts).
- All P0 / P1 findings remediated before mainnet genesis.

**CGGMP24 secp256k1 threshold ECDSA bridge custody**

- Replace the TEE-sealed single-key `EvmTransactionSigner` (Phase B B.3.4) with a t-of-n threshold signer using CGGMP24 (LFDT-Lockness fork). Wormhole NTT, LayerZero V2, and Chainlink CCIP outgoing messages are signed by a quorum of validators; no single host produces a valid outgoing bridge message.
- Gated on `LFDT-Lockness/fast-paillier#23` resolving upstream (the `glass_pumpkin 1.10` / `rand_core 0.10` `Rng + DerefMut` bound). Vendoring fast-paillier locally is rejected — the maintenance burden on a Paillier dependency is incompatible with mainnet-grade security posture.
- Post-merge integration: `tenzro-crypto::cggmp24` module + `tenzro-bridge` t-of-n wiring + DKG ceremony for the bridge signer set + audit coverage in the same Phase D audit pass.

**Tenzro Train Phase 2 (Byzantine-robust)**

- Aggregation rules beyond Mean: TrimmedMean, CoordinateMedian, Krum. `TRAIN.md` §7.4 has the design.
- Workers can be untrusted; the aggregation rule absorbs Byzantine inputs up to f workers.

**Multi-modal training**

- Beyond timeseries: vision (ViT, DINOv3), audio (Whisper class), text (Llama-class via the Python reference trainer's per-architecture path).
- Per-modality `TrainingTaskSpec` schemas.
- Per-modality safetensors export and ONNX conversion for inference serving.

**Interoperability**

- IBC-Eureka SP1 path — Cosmos-side adapter using SP1 zero-knowledge light client. Tenzro Ledger consumable from any IBC-Eureka chain without trusted bridges. [Memory `project_interop_architecture.md`]

**Mainnet**

- Mainnet TNZO genesis. 1B total supply. Allocation per `TOKENOMICS.md` (community 35-40%, treasury, validators, ecosystem).
- Migration of testnet state — testnet is read-only after mainnet genesis; no state moves over. Users re-onboard on mainnet.
- Mainnet DNS migration: `rpc.tenzro.network` flips to mainnet endpoints; testnet moves to `testnet-rpc.tenzro.network`.

**Operational**

- Tenzro Wallet (desktop + mobile) GA. Onboarding wizard, recovery flow, hardware-wallet integration, paymaster-sponsored gas for first-week users.
- Documentation pass: every spec doc reviewed against final mainnet code; no `TODO` / `FIXME` markers remain in user-facing pages.

### D.2 Out of scope

(Phase D is the terminal phase in this roadmap; further work is captured in successor roadmaps.)

### D.3 Acceptance criteria

1. **External audit report published** — full report, including all findings and remediations. Auditor publicly identified.
2. **Zero open P0 / P1 findings** — every critical / high severity item resolved with a verified fix.
3. **Byzantine-robust aggregation defends against simulated Byzantine workers** — controlled experiment with 33% Byzantine workers (returning arbitrary gradients); TrimmedMean / Krum aggregation produces a converged model with loss within 5% of an all-honest baseline.
4. **Three multi-modal training runs converge** — one vision (DINOv3-class), one audio (Whisper-small.en class), one timeseries (TimesFM 200M class), each running on ≥ 3 trainer nodes, producing safetensors deliverables that beat random-init baselines on held-out data.
5. **IBC-Eureka relays a TNZO transfer to a Cosmos chain** — origin-side lock, light-client proof verified on destination, asset minted, no trusted intermediary.
6. **Mainnet genesis block produced** — block 0 includes the canonical TNZO allocation; validator set is the audited set; all governance parameters match `TOKENOMICS.md`.
7. **Mainnet runs for 30 consecutive days at full liveness** — no consensus stalls, no critical bugs, no rollbacks. Block production rate stays within target (1 block / 2-4s depending on cross-region RTT).
8. **Tenzro Wallet GA** — App Store / Play Store / desktop binaries published, code-signed, distributed via canonical channels.
9. **CGGMP24 t-of-n bridge custody live** — outgoing Wormhole / LayerZero / CCIP messages from Tenzro are signed by a quorum of validators using CGGMP24 secp256k1 threshold ECDSA. Single-host compromise produces no valid outgoing bridge message. Verified by a controlled key-extraction red-team on one validator host.

### D.4 Dependencies

- Phase C acceptance criteria all green.
- Audit firm engaged and scoped (long lead time — typically engaged during Phase B with audit work running through Phase C / D).
- Mainnet validator set finalized (selection process governed off-chain, ratified on-chain via Phase B-style governance proposal).
- `LFDT-Lockness/fast-paillier#23` resolved upstream so `cggmp24` builds cleanly against `glass_pumpkin 1.10` / `rand_core 0.10`. Until then D.3.9 is open.

---

## Cross-Phase Continuous Work

Items that aren't phase-bounded. Always-on.

- **Documentation parity** — every code change that touches a user-facing surface (RPC, MCP, A2A, SDK, CLI) updates `SPECIFICATION.md` / `CLAUDE.md` / SDK docstrings in the same commit. Drift is fixed in the commit that introduces it, not in a later sweep.
- **Cookbook examples** — every new RPC / MCP tool / A2A skill ships with a Cookbook example (Rust SDK + TS SDK + Python OpenClaw skill) in the same PR.
- **Memory hygiene** — memories get refreshed when their referenced code state changes. Stale memory entries are an audit item every quarter.
- **Gap-matrix re-baseline** — when a major piece of work lands (phase boundary, large refactor), the gap matrix is regenerated against the new code state. The gap matrix is the audit point for design ↔ code coherence.
- **Operational drills** — fleet failover (kill validator-0, watch the network promote a new leader), DA-backend outage simulation (block Celestia, watch EigenDA pick up), key-rotation drills (rotate a FROST share, verify continuity). Run quarterly.
- **Pre-launch hygiene** — no version bumps, no backcompat shims, no dead code, no `#[deprecated]`, no `_unused` fields. Pre-mainnet rules per `CLAUDE.md` "Pre-Launch Code Hygiene." Mainnet flips these rules: after mainnet genesis, breaking changes require a deprecation cycle.

---

## Phase relationships

```
Phase A — Testnet Stability
    │
    ├─ network NAT-traversal + direct-connect overlay
    ├─ receipt envelope retrofit + Celestia DA
    ├─ MCP structuredContent + audio runtime
    └─ provider hardware fields + ComputeBond
              │
              ▼
Phase B — Crypto Flag-Day + Custody Hardening
    │
    ├─ PQ hybrid (sigs + KEM + libp2p Noise)
    ├─ BLS aggregation in HotStuff-2
    ├─ FROST-Ed25519 (CGGMP24 secp256k1 → Phase D, gated upstream)
    ├─ ERC-7579 validator modules
    ├─ Agent memory tier
    └─ SLA challenges + slashing
              │
              ▼
Phase C — Verifiable Compute + Tenzro Train
    │
    ├─ Intel Tiber Trust Authority
    ├─ EigenDA + Avail backends
    ├─ TEE+ZK composition
    ├─ Tenzro Train Phase 1 (timeseries)
    ├─ Paid skill / tool registry
    └─ CAR identity export
              │
              ▼
Phase D — Mainnet Readiness
    │
    ├─ External audit
    ├─ Byzantine-robust aggregation
    ├─ Multi-modal training
    ├─ IBC-Eureka
    └─ Mainnet genesis
```

Each phase's acceptance criteria are the gates into the next. Crossing requires *all* criteria green, not most. The phases are coherent shipping units — partial-phase deployments are not how this roadmap composes.

---

## What this roadmap doesn't promise

- **No calendar dates.** Phase boundaries are crossed when the work is done.
- **No reordering for convenience.** The order is set by dependency: PQ flag-day cannot ship before BLS is verified-good; mainnet cannot ship before the audit. Skipping a phase is not a path.
- **No "MVP" subset of a phase.** A phase ships when its criteria are met. Half a phase is not a release.
- **No backward compatibility within pre-mainnet phases.** Every breaking change is a hard cutover. Mainnet flips this rule.
- **No silent scope expansion.** Items not in the phase's "In scope" block do not land in that phase. Adding to a phase mid-flight requires updating this doc first.

The roadmap is the schedule; the design is the destination; the gap matrix is the audit. Drift between them is the bug.
