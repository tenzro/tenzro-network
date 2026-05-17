# Section 1 — Gap Matrix: Networking Layer

Cross-reference of `ARCHITECTURE-PRIOR-ART.md` §1 (lines 1–198) against the actual `crates/tenzro-network/`, `crates/tenzro-consensus/`, and `deploy/terraform/gce_validators/cloud-init.yaml` as of 2026-05-14.

Legend: **Built ✅** / **Built but not wired 🟡** / **Partial 🟠** / **Missing 🔴** / **Out-of-scope ⬜**.

## 1.1 rust-libp2p in 2026

Tenzro is on `libp2p = "0.56"` workspace-pinned (`Cargo.toml:126`). All seven of the libp2p production-hardening claims in §1.1 are reachable from the runtime — `idle_connection_timeout`, `ConnectionLimits`, hardened gossipsub config, peer scoring, and the `hide_listen_addrs` Identify pattern all land in the actual `TenzroBehaviour::new`. Kademlia bootstrap-staleness re-call is the one missing piece.

1. **`idle_connection_timeout = 600s` override of libp2p's `Duration::ZERO` default — Built ✅.** `crates/tenzro-network/src/config.rs:101` (`connection_idle_timeout: Duration::from_secs(600)`), documented exactly as §1.1 describes including the GCE conntrack interaction.
2. **`ConnectionLimits` (400 total / 200 in / 200 out / 4 per-peer / 32 pending in / 64 pending out) — Built ✅.** `crates/tenzro-network/src/behaviour.rs:210-218`. Defends against `GHSA-jvgw-gccv-q5p8`.
3. **Gossipsub Strict validation + 1 MiB transmit cap + signed authenticity — Built ✅.** `behaviour.rs:108-136`. Beyond what §1.1 claims: includes `flood_publish(true)`, IDONTWANT v1.2, `do_px()` peer exchange.
4. **Gossipsub mesh params tuned for small validator sets — Built ✅ (different shape than §1.1's "Ethereum-class").** `behaviour.rs:114-118` uses `D=4, lo=2, hi=6, out_min=1`, not the Ethereum `D=8, lo=6, hi=12` shape the prior-art doc summarizes — chosen explicitly to support N=4 testnet. 700ms heartbeat is correct.
5. **Full 7-factor peer scoring (P1..P7) with graylist/publish/gossip thresholds — Built ✅.** `behaviour.rs:142-168`. `decay_interval = 1s`, `retain_score = 3600s`. Thresholds at gossip=-100, publish=-200, graylist=-500.
6. **Identify `hide_listen_addrs(true)` + `NetworkConfig.external_addresses` to stop docker-bridge leaks — Built ✅.** `behaviour.rs:190-193` sets the flag; `config.rs:64` declares the field; `service.rs:959-970` calls `Swarm::add_external_address` with a routability filter. The cloud-init script (`deploy/terraform/gce_validators/cloud-init.yaml:136-142`) passes the GCE public IP through as `--external-p2p-addr`.
7. **S/Kademlia disjoint paths, `k=10`, 30s query timeout — Built ✅.** `crates/tenzro-network/src/discovery.rs:20-25`. Long-lived records (36h TTL, 22h republish).
8. **Periodic Kademlia `bootstrap()` re-call (Lighthouse 60s pattern) — Missing 🔴.** `discovery.rs:69, 89` call `bootstrap()` once at startup only; `service.rs:1009-1027` invokes it during boot. No periodic re-call exists in the 60s cleanup tick (`service.rs:1052-1093`). Smallest step: add a `kad_rebootstrap_interval` field to `NetworkConfig` (default 60s) and a `tokio::time::interval` arm in the `service.rs` event loop that calls `swarm.behaviour_mut().kademlia.bootstrap()`.
9. **Yamux multiplexing (no Mplex) — Built ✅.** `transport.rs:37, 76`.
10. **mDNS disabled in production, enabled in `local()` — Built ✅.** `config.rs:87` and `:167`.

## 1.2 NAT Traversal — Relay v2 + AutoNAT v2 + DCUtR

Cargo features for `relay`, `autonat`, `dcutr` are turned on in the umbrella `libp2p` crate (`Cargo.toml:128-129`), but **none of the three behaviours are instantiated** in `TenzroBehaviour`. The CLAUDE.md sentence claiming "libp2p P2P (gossipsub, Kademlia, identify)" is accurate; §1 of ARCHITECTURE-PRIOR-ART.md and §1.7 are aspirational for community-joiner NAT cases.

1. **Relay v2 (`/libp2p/circuit/relay/0.2.0/hop|stop`) — Missing 🔴.** No `relay::Behaviour` field on `TenzroBehaviour` (`behaviour.rs:42-62`). `NetworkConfig.enable_relay` (`config.rs:51`) is declared but never read anywhere. Smallest step: add `relay: relay::Behaviour` to `TenzroBehaviour`, gate construction on `config.enable_relay`, plumb a relay-client variant for joiners. (Cargo feature already enabled.)
2. **AutoNAT v2 (`/libp2p/autonat/2/dial-request|dial-back`) — Missing 🔴.** No `autonat::v2::client::Behaviour` field on `TenzroBehaviour`. The §1.7 sentence "AutoNAT v2 confirms the address" describes intent, not code. Smallest step: add `autonat: autonat::v2::client::Behaviour` plus `autonat::v2::server::Behaviour` on relay-capable nodes.
3. **DCUtR (`/libp2p/dcutr`) — Missing 🔴.** No `dcutr::Behaviour` field. `NetworkConfig.enable_hole_punching` (`config.rs:48`) is declared (default `true`) but never read. Smallest step: add `dcutr: dcutr::Behaviour` once Relay+AutoNAT are present (DCUtR requires both).
4. **70% hole-punch success envelope — N/A.** Cannot measure without 1–3.

Net: validator cloud nodes work fine (they have static public IPs and `external_addresses` set), but community joiners behind NAT cannot rely on the choreography that §1.7 describes — the only NAT support today is whatever AutoNAT/DCUtR exposed inside `libp2p::request_response` plumbing that isn't actually composed in.

## 1.3 QUIC + Post-Quantum TLS in libp2p

The transport stack matches the §1.3 recommendation cleanly.

1. **Dual TCP + QUIC listen on port 9000 — Built ✅.** `config.rs:71-74` (`/ip4/0.0.0.0/tcp/9000` and `/ip4/0.0.0.0/udp/9000/quic-v1`); `transport.rs:42-53` composes both.
2. **libp2p-TLS (not Noise) so the TCP handshake inherits PQ-hybrid groups — Built ✅.** `transport.rs:7-9, 32-34` use `libp2p::tls::Config` with rustls + `aws-lc-rs`. Module doc-comment explicitly explains the choice.
3. **X25519MLKEM768 hybrid group on both TCP and QUIC — Built ✅ (inherited).** Both legs route through rustls with `aws-lc-rs` as the default `CryptoProvider` (configured at `tenzro-node::main` per `transport.rs:6-8`). PQ codepoint `0x11EC` is negotiated implicitly.
4. **No Noise fallback — Built ✅.** `transport.rs:33` is TLS-only; no `libp2p::noise` import in the crate.
5. **PQ-hybrid signature stack (Ed25519 + ML-DSA-65) — Out-of-scope for §1 ⬜.** Application-layer signatures are tracked in `project_pq_migration.md`; orthogonal to the transport.

## 1.4 Content Routing — Bitswap, IPNI, Trustless Gateway

Tenzro does not implement IPFS-style content routing today. §1.4 is forward-looking guidance for the model-artifact / DA-offload track, not a current dependency.

1. **Bitswap (`/ipfs/bitswap/1.2.0`) — Missing 🔴.** No reference anywhere in the workspace.
2. **IPNI client / advertise — Missing 🔴.** Not present.
3. **Trustless Gateway client — Missing 🔴.** Model artifacts download via `hf-hub` (HuggingFace Hub) per CLAUDE.md `tenzro-model`. DA offload is `InlineFallbackBackend` only (`tenzro-storage::da`).
4. **Saturn / `cid.contact` integration — Missing 🔴.**
5. **Block-sync request/response over libp2p — Built ✅ (Tenzro's local equivalent for chain catch-up, not content addressing).** `behaviour.rs:60-61` plus `block_sync_proto.rs` — `/tenzro/block-sync/1.0.0` request-response protocol modeled on Sui `state_sync` and Aptos `storage-service`. Fills the chain-tip-catch-up gap that §1.4's IPFS stack would otherwise serve.

Smallest step (only when (a) model artifacts need decentralization or (b) a real DA backend is wired): add a `tenzro-content-routing` crate exposing a `ContentFetcher` trait with an HTTP trustless-gateway backend; CID-verify locally before passing to caller.

## 1.5 Iroh as a Rust Alternative

1. **Iroh dependency present in workspace — Missing 🔴.** No `iroh`, `iroh-blobs`, `iroh-gossip`, `iroh-docs`, or `pkarr` in `Cargo.toml`. The §1.5 framing is "worth tracking, not Phase 1," which matches reality.

The CLI / desktop / TS SDK use HTTP/JSON-RPC against `rpc.tenzro.network`, which is the same path §1.5 describes. A2A and MCP are HTTP-transport today; an `a2a-over-iroh` binding would be the natural first slot.

## 1.6 Production Case Studies — What BFT Chains Actually Use

The §1.6 finding is unambiguous: BFT vote messages should leave gossipsub for a validator-only direct overlay. Tenzro has not done this — it is the single largest gap in the networking layer surfaced by §1.

1. **HotStuff-2 vote / proposal / timeout / NEC messages currently ride `tenzro/consensus` gossipsub — Built ✅ (as the status-quo Phase-1 choice §1.7 describes).** Evidence: `crates/tenzro-node/src/event_loop.rs:845, 1514-1516` broadcasts `ConsensusOutMessage::{Vote, Proposal, Timeout, NoEndorsement}` to `"tenzro/consensus"`; `crates/tenzro-node/src/node.rs:4495-4507` subscribes to the same topic for inbound.
2. **Validator-only authorization on consensus / attestation / block topics — Built ✅.** `peer_manager.rs:74` defines `VALIDATOR_ONLY_TOPICS`; `peer_manager.rs:288` `authorize_peer_for_topic` is checked at message ingest in `service.rs:1284`. `ValidatorRegistry` trait at `peer_manager.rs:40` is implemented by `NodeValidatorRegistry` at node startup (per CLAUDE.md). This is the right enforcement scope but does not move votes off gossip.
3. **Aptos-style direct-connect overlay (`DirectSend` / `RPC` per validator pair) — Missing 🔴.** No `tenzro/validator-direct/1` protocol exists. Block-sync request-response (`block_sync_proto.rs`) is the only direct-connect pattern in the crate and it carries block ranges, not votes. Smallest step (§1.7 Phase 2 option B): add a `validator_direct` `request_response::Behaviour` over QUIC keyed by validator-set membership, route `ConsensusOutMessage::Vote` and `Timeout` over it, leave `Proposal` on gossipsub.
4. **`gossipsub::Config.direct_peers` populated with the validator set at boot (§1.7 Phase 2 option A — the recommended cheap fix) — Missing 🔴.** No `.direct_peers(...)` call in `behaviour.rs:108-128`. `service.rs:986-996` deliberately *avoids* `explicit_peers` for boot nodes because it broke GRAFT. Smallest step: at validator-set materialization (`NodeValidatorRegistry` boot), build the PeerId list and call `gossipsub::Behaviour::add_explicit_peer` for each remote validator, accepting the GRAFT-rejection caveat the comment cites or migrating to `direct_peers` config builder.
5. **Sui anemo / RPC-over-QUIC overlay — Out-of-scope ⬜.** §1.7 explicitly rules out a custom non-libp2p stack until validator counts exceed ~100.
6. **Monad-style single-region-multi-zone topology constraint — Out-of-scope ⬜** (operational, not code). The 2026-05-14 stall postmortem in `project_consensus_stall_root_cause_2026_05_14.md` already collapsed Tenzro testnet to single-region.
7. **Solana Alpenglow / Votor direct-broadcast pattern — Out-of-scope ⬜** at ≤10 validators.

## 1.7 Tenzro-Specific Implications

1. **`connection_idle_timeout = 600s` shipped 2026-05-14 — Built ✅.** See §1.1 item 1.
2. **`identify::Config::with_hide_listen_addrs(true)` + `external_addresses` — Built ✅.** See §1.1 item 6.
3. **`ConnectionLimits` 200/200 — Built ✅.** See §1.1 item 2 (actually 400 total).
4. **QUIC + TCP dual-listen on 9000 — Built ✅.** See §1.3 item 1.
5. **Ethereum-class 700ms gossipsub heartbeat — Built ✅.** `config.rs:103`, `behaviour.rs:109`.
6. **mDNS disabled in production — Built ✅.** `config.rs:87`.
7. **Host TCP keepalive tuning (`tcp_keepalive_time=120 intvl=30 probes=4`, total 240s window) — Built ✅.** `deploy/terraform/gce_validators/cloud-init.yaml:254`, with the full 2026-05-14 stall postmortem inline.
8. **Phase-2-option-A `direct_peers` for HotStuff-2 vote traffic — Missing 🔴.** See §1.6 item 4. This is the recommended Phase 2 action and the highest-leverage networking change open today.
9. **Phase-2-option-B dedicated `tenzro_consensus_direct` request-response protocol — Missing 🔴.** See §1.6 item 3.
10. **Generalized cloud-fabric conntrack defense documented as the canonical reference inside the codebase — Built ✅.** `config.rs:88-100` comment + the cloud-init keepalive comment.

---

## Section 1 — Open Decisions

The 2026-05-14 hardening landed the libp2p + GCE conntrack defenses cleanly. Three calls remain:

- **D1. Vote-topic overlay choice.** Pick §1.7 Phase 2 option A (`gossipsub::Config.direct_peers` populated from `ValidatorRegistry` at boot — one-day change inside `behaviour.rs` + `service.rs`) versus option B (dedicated `tenzro_consensus_direct` request-response protocol — multi-day, more durable at >30 validators). Recommendation per §1.6/§1.7 is option A first, option B once N>30.
- **D2. NAT-traversal scope.** Either commit to wiring Relay v2 + AutoNAT v2 + DCUtR for community joiners (Cargo features already enabled, behaviours not instantiated), or remove the `enable_relay` / `enable_hole_punching` config fields and document validator-public-IP-only as the supported topology for Phase 1. Today these flags are declared but unread, which is dead-code-shaped and conflicts with the no-dead-code rule.
- **D3. Periodic Kademlia re-bootstrap.** §1.1 calls out the Lighthouse 60s pattern explicitly. Tenzro bootstraps once at startup only. Add a periodic re-call in the `service.rs` cleanup tick — single-day change.

Two items are tracked but explicitly deferred: content routing (§1.4 — defer until model artifacts or DA backend need it) and Iroh (§1.5 — track for future A2A-over-Iroh transport binding, not Phase 1).

# Section 2 — Gap Matrix: Data Layer

Cross-reference of `ARCHITECTURE-PRIOR-ART.md` §2 (lines 199–518) against the actual Tenzro codebase. Status legend: Built ✅ / Built but not wired 🟡 / Partial 🟠 / Missing 🔴 / Out-of-scope ⬜.

Code surveyed: `crates/tenzro-storage/src/{da,block_store,merkle,snapshot,kv,lib,traits,account_store,config,error}.rs`, `crates/tenzro-model/src/{hf_download,download,provenance/mod,provenance/c2pa}.rs`, `crates/tenzro-storage/Cargo.toml`, workspace-wide grep for IPLD/CID/Arrow/Lance/CAR/safetensors/Bitswap symbols.

---

## §2.1 IPLD + DAG-CBOR + CIDs

| Claim / capability                                              | Status | Evidence                                                                                                                           |
|-----------------------------------------------------------------|:------:|------------------------------------------------------------------------------------------------------------------------------------|
| CID types (multibase/multicodec/multihash)                      |  🔴    | Workspace grep for `cid::`, `libipld`, `multihash`, `multicodec`, `bafy` → zero matches outside `ARCHITECTURE-PRIOR-ART.md`.       |
| DAG-CBOR canonical encoding                                     |  🔴    | No `dag-cbor` dep in any `Cargo.toml`; commitments are bincode (`tenzro-workflow/src/receipt.rs:94`) or domain-tagged SHA-256.     |
| Domain-tagged SHA-256 commitments (Tenzro's analogue)           |  ✅    | `compute_commitment` in `tenzro-storage/src/da.rs:237-244`; domain tags in CLAUDE.md (escrow, 7683, zk_commitment).                |
| Self-describing on-chain commitments                            |  🟠    | Commitments are uniform 32-byte SHA-256 hashes; no multicodec/multihash tag — algorithm change would silently collide.            |

**Smallest next step (if pursued):** add a `tenzro-types::CidView` wrapper (multibase+multicodec+multihash) over existing 32-byte `Hash` — read-side only, no wire-format change. Crate: `cid = "0.11"` + `multihash-codetable`.

---

## §2.2 Bitswap + Trustless Gateways

| Claim / capability                                | Status | Evidence                                                                                                |
|---------------------------------------------------|:------:|---------------------------------------------------------------------------------------------------------|
| Bitswap client                                    |  🔴    | Zero matches for `Bitswap`/`bitswap` workspace-wide.                                                    |
| Trustless gateway client (`application/vnd.ipld.car`) |  🔴 | Zero matches for `TrustlessGateway`, `application/vnd.ipld`, `car_file`, `carv1`.                       |
| HTTP fetcher for content-addressed retrieval      |  🟠    | `tenzro-model/src/hf_download.rs:501-504` only fetches from `huggingface.co/<repo>/resolve/main/<f>` — content-addressed by policy, not by CID. |

**Smallest next step:** when a DA backend lands, add a `TrustlessGatewayClient` (reqwest + sha256-verify) behind an `ipfs-gateway` feature flag in `tenzro-storage`. Use as the retrieval fallback for `DaPointer.locator` when backend == `Filecoin`/`IPFS`.

---

## §2.3 Filecoin + FVM + Saturn / Storacha

| Claim / capability                                    | Status | Evidence                                                                                            |
|-------------------------------------------------------|:------:|-----------------------------------------------------------------------------------------------------|
| Filecoin storage-deal client (FVM RPC)                |  🔴    | Zero Filecoin/FVM dep in workspace; no `lotus`, `filecoin`, `web3.storage`, `storacha` crates.      |
| Saturn / Storacha gateway adapter                     |  🔴    | No HTTP client targeting `saturn.tech` or `storacha.network`.                                       |
| Cold-archival storage tier                            |  🔴    | All persistence is RocksDB local-disk via `tenzro-storage/src/kv.rs`; no remote cold tier.          |
| UCAN capability delegation (overlaps tenzro-identity) |  ⬜    | Tenzro uses TDIP DelegationScope + AP2 mandates; UCAN is conceptually adjacent but out of scope.    |

**Smallest next step:** for Class 3 (training-artifact archival), implement `FilecoinDealBackend: DaBackend` against Storacha's HTTP `upload` + UCAN bearer-token API. Gate behind `filecoin` feature flag.

---

## §2.4 EigenDA + Celestia + Avail

| Claim / capability                                    | Status | Evidence                                                                                                                                                                    |
|-------------------------------------------------------|:------:|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `DaBackend` trait                                     |  ✅    | `tenzro-storage/src/da.rs:271-281` (`submit`/`fetch`/`verify_availability`).                                                                                                |
| `DaBackendId` enum with EigenDA/Celestia/Avail        |  🟡    | `da.rs:71-92` — variants exist but no impls; `da.rs:80-89` only names them.                                                                                                |
| `InlineFallbackBackend` (safe default)                |  ✅    | `da.rs:290-342` — implemented, refuses offload by design.                                                                                                                  |
| EigenDA adapter                                       |  🔴    | No `eigenda` crate dep; no `eigenda-proxy` HTTP client; no KZG-attestation verification path.                                                                              |
| Celestia adapter                                      |  🔴    | No `celestia-rpc` / `celestia-types` dep; no `PayForBlobs` builder; no NMT verification.                                                                                  |
| Avail adapter                                         |  🔴    | No `avail-subxt` / `avail-light` client; no KZG-cell sampling.                                                                                                             |
| `tenzro_getDaBackends` RPC                            |  🟠    | `tenzro-node/src/rpc.rs:6177-6190` — returns only the static `inline_fallback` entry; does not enumerate a configured-backend registry (because no registry exists).       |
| `tenzro_verifyDaPointer` RPC                          |  🟠    | `rpc.rs:6213-6306` — accepts `eigenda`/`celestia`/`avail` backend strings but always probes `InlineFallbackBackend`, so external pointers always resolve `available: false`. |
| `OffloadedDA` storage mode is exercised               |  🔴    | Only call site of `ReceiptEnvelope::offloaded` is the unit test in `da.rs:441`. Sole production caller of any envelope ctor is `tenzro-workflow/src/receipt.rs:111`, which calls `::inline`. |

**Smallest next step (per CLAUDE.md decision):** implement `CelestiaBackend: DaBackend` first (Classes 1+2, cleanest namespace API). New file `crates/tenzro-storage/src/da/celestia.rs`, `celestia` feature flag in `tenzro-storage/Cargo.toml`, `celestia-rpc` + `celestia-types` deps. Then wire a `DaBackendRegistry: DashMap<DaBackendId, Arc<dyn DaBackend>>` into `TenzroNode` so `handle_get_da_backends` returns multiple entries.

---

## §2.5 Apache Arrow + Flight / Flight SQL

| Claim / capability                                          | Status | Evidence                                                                                          |
|-------------------------------------------------------------|:------:|---------------------------------------------------------------------------------------------------|
| Arrow IPC over the wire for inference inputs/outputs        |  🔴    | Workspace grep for `arrow-flight`, `arrow_flight`, `FlightSql`, `application/vnd.apache.arrow` → zero matches. |
| Arrow Flight server on inference providers                  |  🔴    | All inference dispatch goes JSON → `tenzro-model/src/routing.rs` via `reqwest`.                  |
| Parquet on-disk for datasets                                |  🔴    | No `parquet` / `arrow` deps anywhere in workspace.                                                |
| MCP-returns-Flight-ticket pattern (the §2.5 recommendation) |  🔴    | All multi-modal MCP tools embed payload bytes inline in JSON content blocks.                      |

**Smallest next step:** for the highest-value modality (text/vision embedding outputs, `[N, D]` f32), expose an optional `tenzro_arrow` JSON-RPC namespace that returns `{ticket, schema, rows, endpoint}` and stand up a tiny `arrow-flight = "55"` server on a sidecar port (default 50051) behind an `arrow-flight` feature flag in `tenzro-node`. Forecast outputs are the next candidate. Keep JSON path for back-compat — this is additive, not a replacement.

---

## §2.6 Lance + HF Datasets + safetensors

| Claim / capability                                                | Status | Evidence                                                                                                                                                    |
|-------------------------------------------------------------------|:------:|-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| HuggingFace Hub artifact fetcher                                  |  ✅    | `tenzro-model/src/hf_download.rs:1-665` — `HfArtifactDownloader` with `ArtifactSpec::{SingleFile, Bundle}`, tmp-rename atomic finalize, size-tolerance verification. |
| SHA-256 integrity verification of downloads                       |  🟠    | `tenzro-model/src/download.rs:186-193` requires checksum at API; `hf_download.rs:173` does file-size check only (5% tolerance, see `SIZE_TOLERANCE_PERCENT`). Content-hash verification is on the `DownloadManager` path, not `HfArtifactDownloader`. |
| safetensors as a wire/payload format                              |  🟠    | Referenced as a *foreign* format: `tenzro-types/src/training.rs:247-249` carries `safetensors_hash: Hash` (just the SHA-256 commitment); actual safetensors parsing lives in `integrations/trainer/` (Python). No `safetensors` Rust crate dep. |
| Lance / LanceDB columnar storage                                  |  🔴    | Zero `lance` / `lancedb` references workspace-wide.                                                                                                         |
| Vector index for embeddings                                       |  🔴    | `tenzro-model::TextEmbeddingRuntime` returns vectors to caller; no on-disk index, no ANN search.                                                            |
| `HfArtifactDownloader::Bundle` for multi-file ONNX                |  ✅    | `hf_download.rs:84-92` (`Bundle { files, dir_name }`); used by ASR + segmentation runtimes per CLAUDE.md.                                                  |

**Smallest next step:** add `safetensors = "0.4"` as a workspace dep used by a thin `tenzro-model::safetensors_loader` for Rust-side header parsing (zero-copy mmap). Lance is a Phase 3+ candidate — wait until embedding output volume justifies a vector-search index.

---

## §2.7 ATProto / Nostr / Farcaster — social-graph data layers

| Claim / capability                                          | Status | Evidence                                                                                                                          |
|-------------------------------------------------------------|:------:|-----------------------------------------------------------------------------------------------------------------------------------|
| Per-DID content-addressed repository (MST or equivalent)    |  🔴    | `tenzro-identity` stores `TenzroIdentity` records in `CF_IDENTITIES` keyed by DID; no per-DID Merkle tree over a record set.     |
| CAR-format bulk export of agent profile                     |  🔴    | No `car`/`carv1` codepath; identity has only W3C DID-Document JSON export (`tenzro-identity/README.md:23`).                       |
| Signed repo commit (head CID) per DID                       |  🔴    | Identities are signed individually; there is no commit-DAG over the per-DID record set.                                          |
| `did:plc`/`did:web` resolution for cross-protocol identity   |  ⬜    | Tenzro uses `did:tenzro:`; cross-resolve to `did:plc` is conceivable but explicitly out of scope today.                          |
| Lessons applied (avoid Nostr canonicalization, etc.)        |  ✅    | Tenzro already uses canonical SHA-256 commitments + domain-tagged preimages, not hand-rolled JSON canonicalization.              |

**Smallest next step (per §2.7 recommendation):** for Phase 2 identity-export, add `tenzro-identity::export::export_did_repo_car(did) -> Bytes` that walks per-DID records (`identity`, `credentials`, `delegations`) into a CARv1 file with a signed DAG-CBOR head. Deps: `iroh-car = "0.6"`, `serde_ipld_dagcbor = "0.6"`. Defer until at least one consumer (portable-agent flow) asks for it.

---

## §2.8 Tenzro-specific implications

| Claim / capability                                                                              | Status | Evidence                                                                                                                                                            |
|-------------------------------------------------------------------------------------------------|:------:|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ReceiptEnvelope { kind, storage_mode, inline_summary, inline_payload, da_pointer, commitment }` |  ✅   | `tenzro-storage/src/da.rs:143-159`.                                                                                                                                  |
| `ReceiptKind::default_mode()` per-kind defaults                                                 |  ✅    | `da.rs:54-67` — matches §2.8 spec exactly.                                                                                                                          |
| `commitment = SHA-256(canonical_payload)` always                                                |  ✅    | `da.rs:237-244` + `da.rs:165` (`Self::inline` computes it).                                                                                                          |
| `DaPointer { backend, namespace, locator, commitment_kzg, attestation_root }`                    |  ✅    | `da.rs:100-117`.                                                                                                                                                     |
| At least one external DA backend wired in                                                       |  🔴    | Only `InlineFallbackBackend` exists; the three other `DaBackendId` variants have no impls. RPC unconditionally instantiates the inline backend (`rpc.rs:6180,6295`). |
| Q1: `commitment_kzg` actually carries KZG bytes                                                 |  🔴    | Field is `Option<Vec<u8>>` populated only in unit tests; production code path doesn't compute KZG.                                                                  |
| Q2: Composed DA + cold-archive (Celestia + Filecoin)                                            |  🔴    | No composition — single `da_pointer` per envelope; no second cold-storage CID field.                                                                                |
| Q3: Native Tenzro DA from validators                                                            |  ⬜    | Out of scope per §2.8 (Phase 3+).                                                                                                                                    |
| Production callers using `OffloadedDA`                                                          |  🔴    | Zero. Only producer in tree is `tenzro-workflow/src/receipt.rs:111` and it calls `::inline`. The settlement and inference paths *do not* go through `ReceiptEnvelope` at all yet — they write directly to `CF_SETTLEMENTS` / inference response JSON. |
| Per-receipt-kind governance toggle (Inline↔OffloadedDA)                                         |  🔴    | No governance binding for storage_mode; defaults are hardcoded in `ReceiptKind::default_mode`.                                                                      |

**Smallest next step (composite, in dependency order):**
1. Land a `CelestiaBackend` impl (see §2.4). Without a real backend, every other DA item is academic.
2. Retrofit `tenzro-settlement::engine` and `tenzro-model::routing` to emit `ReceiptEnvelope` for `SettlementChannel` and `Inference` kinds — the registry of writers, not the trait, is the blocker today.
3. Add `DaBackendRegistry` on `TenzroNode` so multiple backends coexist and `tenzro_getDaBackends` returns the real set.

---

## Section 2 — Open Decisions

- **D2.1 — KZG vs SHA-256 for `commitment_kzg`.** Status: latent. Currently named like KZG, behaves like SHA-256, populated nowhere. Either rename the field to `commitment_backend` (algorithm-neutral, opaque to chain) or commit to KZG-when-backend-supports-it and document the multi-format expectation. Decision blocker: depends on which DA backend lands first — Celestia (NMT/Merkle, not KZG) vs EigenDA / Avail (both KZG).
- **D2.2 — IPLD/CID adoption surface.** Three options: (a) full adoption — CIDs replace 32-byte `Hash` on-chain (breaking); (b) view-only wrapper that surfaces existing SHA-256 commitments as CIDv1 multihashes (additive, cheap); (c) skip entirely. Pre-alpha favors (a) since there's no compat cost, but no consumer demands it yet. Recommend (b) until an IPLD-aware integration (Filecoin, ATProto export) makes a concrete demand.
- **D2.3 — First DA backend.** CLAUDE.md §"Architectural Decisions" already records the Celestia-first decision but no code reflects it. Confirm before any work starts: Celestia (§2.8 recommendation) vs EigenDA (Ethereum-ecosystem familiarity) vs deferring until volume demands it. Default per §2.8: Celestia.
- **D2.4 — Inference / settlement writers don't use `ReceiptEnvelope`.** The envelope shape is plumbed end-to-end but no high-volume writer emits envelopes today. Either retrofit the writers (settlement engine, inference router, agent message store) onto envelopes — even with all `Inline` — so a future flag-flip can offload them; or accept that the envelope is currently dead infrastructure outside `tenzro-workflow`. Per the "no dead code" hard rule in CLAUDE.md, the retrofit is the only valid path.
- **D2.5 — Arrow Flight sidecar.** Should `tenzro-node` open a Flight port (default 50051) for embeddings/forecasts? Marginal value pre-mainnet, but unlocks DuckDB/Polars/Snowflake integration without a translation layer. Recommend deferring until at least one external integration partner asks; the JSON path is sufficient for current testnet traffic.
- **D2.6 — Identity export as CAR.** §2.7 names this as "the right model" but no consumer exists yet. Defer until a portable-agent migration flow is on the roadmap; revisit alongside `tenzro-identity` cross-DID-method work.

# Section 3 — Gap Matrix: Compute & Inference Marketplace

Cross-reference of research §3.1–3.7 against `tenzro-model`, `tenzro-tee`, `tenzro-token`, `tenzro-types`, `tenzro-network`. CLAUDE.md describes the *intent*; this matrix reflects what is **actually wired in code** as of 2026-05-14.

Status legend: Built ✅ / Built but not wired 🟡 / Partial 🟠 / Missing 🔴 / Out-of-scope ⬜.

---

## 3.1 Decentralized AI Inference Networks — Production Survey

Bittensor / Akash / Render / io.net / Aethir / Gensyn / Prime Intellect each have one or more idioms that Tenzro could adopt. Most are **Missing**, and that is largely the right answer — Tenzro is its own L1, not a Bittensor subnet.

| Pattern (source) | Status | Evidence |
|---|---|---|
| **Bittensor Yuma Consensus** — weight-vector consensus over miners, on-chain incentive distribution | 🔴 Missing | No subnet abstraction. Provider scoring is local-per-node via `ProviderWithMetrics::calculate_score()` (`crates/tenzro-model/src/provider.rs:140–166`). No on-chain weight matrix, no validator-agreement reward. Reputation is local +1/-5 saturating (`provider.rs:476–500`). |
| **Bittensor subnet model** (validator+miner roles + per-subnet emissions) | ⬜ Out-of-scope | Per §3.7 Q1 — Tenzro is correctly an independent L1, not a subnet host. `NodeRole::ModelProvider` covers the same surface (`crates/tenzro-types/src/primitives.rs`). |
| **Akash SDL deploy manifest** (YAML, attribute-gated, audited attributes, reverse auction) | 🔴 Missing | No deploy-manifest type, no reverse auction, no auditor registry. Providers register a flat `InferenceProvider { models, capacity, pricing, reputation, endpoint_url }` (`tenzro-types/src/model.rs:742–800`) with **no hardware spec, no geo, no audited attributes**. |
| **Akash escrow + lease model** (per-block draw-down, deposit-on-bid) | 🟠 Partial | Generic on-chain escrow exists (`tenzro-settlement` — CreateEscrow/ReleaseEscrow consensus-mediated typed txns, see CLAUDE.md). Inference does not currently route through it; per-token billing flows via micropayment channels (`tenzro-settlement` channel manager). No provider-bid deposit, no reverse auction. |
| **Render BME** (Burn-Mint Equilibrium) | 🟠 Partial | Adjacent: `tenzro-token::adaptive_burn` exposes EIP-1559 base-fee burn + governance-dial burn for paymaster/local fees (`crates/tenzro-token/src/adaptive_burn.rs`). **No mint-on-job tied to provider payouts.** Render's "spend burns / serve mints" loop is not built. |
| **io.net IDE** (Incentive Dynamic Engine — USD-pegged supplier ROI, demand-elastic mint/burn) | 🔴 Missing | No USD-pegged payout mechanism. Pricing is per-token in TNZO (`PricingConfig::price_per_input_token` / `price_per_output_token`, `tenzro-types/src/model.rs:856–877`). No stable-supplier accounting. |
| **io.net co-staking** (token holders stake alongside operators) | 🔴 Missing | Liquid staking exists (`tenzro-token::liquid_staking`) but it's validator-only — there is no provider-side restaking surface. |
| **Aethir cloud-host cohorts** (vetted, periodic onboarding) | ⬜ Out-of-scope | Permissionless model is correct for Tenzro. |
| **Prime Intellect / Nous (Rust protocol + Python trainer)** | ✅ Built | Exactly Tenzro's split per CLAUDE.md "Tenzro Train: Rust protocol + Python reference trainer" — `tenzro-training` (Rust) + `integrations/trainer/` (Python FSDP2 + Hivemind). Matches §3.1's takeaway. |

**Highest-impact 3.1 gap:** ProviderManifest with hardware/geo/audited attributes. Without it, none of the price/reputation/cortex routing strategies (`routing.rs:556–590`) can prefer an H100 in Frankfurt over an RTX 4090 in a coffee shop. See §3.4 below.

---

## 3.2 TEE Attestation at Consumer Scale

Tenzro's TEE crate is the most production-leaning part of the inference stack — all four major TEE vendors have real ioctl paths, real signature verification, and AES-256-GCM enclave encryption. The gap is **policy** (PCC-style verifiable transparency), not **mechanism**.

| Pattern | Status | Evidence |
|---|---|---|
| **Intel TDX** (real `/dev/tdx-guest` ioctl, QE P-256 ECDSA over Quote[0..632], PCS cert chain) | ✅ Built | `crates/tenzro-tee/src/intel_tdx.rs` (1225 lines). PCS verification + ECDSA-P-256 via `attestation::verify_ecdsa_p256_raw_pubkey`. Sim fallback via `TENZRO_SIMULATE_TDX`. |
| **AMD SEV-SNP** (`/dev/sev-guest`, ARK→ASK→VCEK chain) | ✅ Built | `amd_sev_snp.rs:265` opens real device; AMD KDS VCEK fetch + verification (1165 lines). Sim fallback via `TENZRO_SIMULATE_SEV` (`amd_sev_snp.rs:1041–1046`). |
| **AWS Nitro** (`/dev/nsm`, CBOR doc, COSE_Sign1 ES384 over `Sig_structure1`) | ✅ Built | `aws_nitro.rs` (1666 lines). Real COSE_Sign1 ES384 per RFC 8152 §4.4, via `attestation::verify_ecdsa_p384_raw_pubkey`. |
| **NVIDIA H100/H200 Confidential Computing** (NRAS HTTP, JWT) | 🟠 Partial | `nvidia_gpu.rs` (1978 lines). NRAS endpoint wired (`nras_endpoint`, line 108). Evidence collection real on hardware, NRAS POST real (`verify_via_nras`, line 735+). **But:** sim path (`simulate: bool`, line 95) is heavy — half of the evidence-collection code in the file is the simulation branch. On non-CC architectures, the code short-circuits before even reaching NRAS (`nvidia_gpu.rs:744–748`). Composite TDX+H100 attestation per §3.2 not assembled. |
| **TDX+GPU composite attestation token** (Intel Trust Authority `get_token_v2`) | 🔴 Missing | Each provider verifies in isolation; no composite Intel Trust Authority JWT issuance/verification. Routing layer can't bind "this CPU TEE + that GPU TEE" together. |
| **Consumer-GPU TEE (RTX 4090/5090)** | ⬜ Out-of-scope (correctly) | Per §3.2 — hardware doesn't exist. Tenzro's stance (validators TEE-attested, home providers not) matches reality. **But: `attestation_tier` field for declaring evidence level is Missing** — see §3.4. |
| **TEE-weighted leader selection** (validators get 2× weight) | 🟡 Built but unrelated to inference | `tenzro-consensus` weights TEE-attested validators 2× for leader selection. The same `has_tee: bool` flag on `ProviderWithMetrics` (`provider.rs:126`) is consulted only by `RoutingConfig::require_tee` filter (`routing.rs:480–487`). No price premium, no tier ladder. |
| **PCC-style verifiable transparency** (public image log, device refuses unlisted builds) | 🔴 Missing | No image-log publication, no client-side build-allowlist enforcement, no SKR-equivalent gating. The closest analog is the ZK commitment registry (`ZkCommitmentRegistry` for proofs), which is not the same thing. |
| **Phala-style decentralized KMS / Proof-of-Cloud** | 🔴 Missing | No on-chain KMS split across TEE nodes; no physical-inspection axis. |

**Highest-impact 3.2 gap:** PCC-style verifiable transparency. The cryptographic substrate is all there — what's missing is the *operational commitment* that any inference served by a TEE-tagged provider corresponds to a publicly-attested image whose hash is on-chain. **Concrete next step:** add `ImageMeasurementRegistry` to `tenzro-tee` mirroring `ZkCommitmentRegistry` (32-byte SHA-256 of canonical-serialized enclave image, on-chain via consensus-mediated tx, queried by the routing layer before dispatch when `attestation_required = true`).

---

## 3.3 Eigenlayer-Style Restaking Applied to Compute

§3.3 explicitly recommends **no** restaking in Phase 1, and the code matches that decision.

| Pattern | Status | Evidence |
|---|---|---|
| **EigenLayer AVS slashing on operator stake** | ⬜ Out-of-scope (Phase 1) | Per §3.3 explicit recommendation. |
| **Consensus equivocation → 10% slash** | ✅ Built | `tenzro-consensus` `EquivocationDetector` → `StakingSlashingCallback` → `StakingManager::slash` (`tenzro-token/src/staking.rs:543`). |
| **Generic provider-failure → stake slash** | 🔴 Missing (intentionally, for now) | `StakingManager::slash(staker, amount, reason: String, slashed_by)` takes a free-form reason string. **Only consensus equivocation calls it.** Inference timeouts go to `ProviderManager::record_failure` → reputation -5, not slash (`provider.rs:492–500`). |
| **Optional `ComputeBond` (Phase 2)** — opt-in second bond separate from consensus stake | 🟡 Adjacent type exists | `tenzro-token::bond` (1132 lines) implements `AgentBondState` — per-agent surety bond with `Active`/`Cooldown`/`Frozen`/`Slashed`/`Returned` lifecycle, posted by controller, slashable to InsurancePool (`bond.rs:1–60`). **This is agent-DID-scoped, not provider-scoped.** A provider operating multiple agent identities has multiple bonds, but there is no `ComputeBond` keyed on `provider_did` directly. |
| **Symbiotic-style dispute resolution (veto committee)** | 🔴 Missing | No dispute committee, no VRF-rotated arbiter set. VRF precompile `0x1007` exists (`tenzro-vm`) and §3.6 suggests reusing it for 7-of-N validator dispute juries — wiring not present. |
| **Karak / Symbiotic arbitrary-ERC20 collateral** | ⬜ Out-of-scope | TNZO-only bond is correct for Phase 1. |

**Highest-impact 3.3 gap:** none for Phase 1. Phase 2 work: generalize `AgentBondState` (`bond.rs`) → `ComputeBondState` keyed on `provider_did`, with a slash-via-dispute path (not slash-via-callback). Reuse VRF precompile `0x1007` for jury rotation.

---

## 3.4 Provider Manifest Patterns

**This is the single largest gap in §3 — every routing decision in `routing.rs:540–596` operates on a provider record that lacks hardware, geography, SLA, and bandwidth declarations.**

| ProviderManifest v1 field (§3.4) | Status | Evidence |
|---|---|---|
| `provider_did` (did:tenzro:machine:...) | 🟠 Partial | Provider tracked by `Address` (`InferenceProvider.address`, `tenzro-types/src/model.rs:744`). DID linkage is via the TDIP `IdentityRegistry` but is not stored on the provider record. |
| `operator_did` (controller, did:tenzro:human:...) | 🔴 Missing | No controller field on `InferenceProvider`. |
| `signed_at` + `signature` (manifest signed by provider DID) | 🔴 Missing | Registration accepts a one-shot signature over the address bytes (`provider.rs:333–360`), but the *manifest itself* is not a signed payload — there is no canonical-serialized provider manifest with a self-signature. |
| `compute.gpu_models` (family/count/vram/interface) | 🔴 Missing | `ProviderCapacity { max_concurrent_requests, active_requests, requests_per_second, max_batch_size }` (`model.rs:803–814`) — no GPU model, no VRAM, no SXM/PCIe interface. `HardwareCapabilities` exists (`tenzro-model/src/provisioning.rs:14–42`) with `ram_gb`/`vram_gb`/`tee_available` but **is not attached to InferenceProvider** — it's only consumed by the local model-provisioning recommender. |
| `compute.cpu_cores`, `ram_gb`, `storage_gb`, `storage_class` | 🟡 Type exists, not on provider | `HardwareCapabilities` carries `cpu_cores`, `ram_gb` (`provisioning.rs:18–30`). Not propagated into the provider registry or gossip announcement. |
| `bandwidth` (ingress/egress mbps, monthly cap, metered flag) | 🔴 Missing | Not in `InferenceProvider`, not in `ProviderCapacity`, not in `ProviderAnnouncementMessage` (`tenzro-network/src/message.rs:422–460`). |
| `services[]` (modality, model_ids, max_concurrent, pricing) | 🟠 Partial | `InferenceProvider.models: Vec<String>` (`model.rs:751`) lists model_ids but not per-service modality, per-service concurrency, or per-service pricing — provider pricing is flat (`PricingConfig`). Modality is on the model side (`ModelInfo.modality`), not on the provider's service offering. |
| `attestation_tier` (None/SoftwareAttested/VendorAttested/TeeAttested) | 🔴 Missing | Only a `has_tee: bool` flag exists (`ProviderWithMetrics::has_tee`, `provider.rs:126`). No tier ladder, no price premium hook. |
| `tee_evidence` (Quote + cert chain attached to manifest) | 🟡 Built but not bound to provider | Full evidence flows exist in `tenzro-tee` (TDX Quote, SEV report, Nitro doc, NVIDIA evidence). Not attached to provider records — when a provider registers, the evidence is not stored alongside its registry entry. |
| `audited_attributes[]` (Akash auditor pattern) | 🔴 Missing | No auditor DID, no audited-attribute attestation. |
| `sla` (uptime, p50/p99 latency targets, challenge window) | 🔴 Missing | No SLA struct anywhere in the workspace. Targets are not declared, not enforced, not slashable. |
| `compute_bond_tnzo` (Phase 2 opt-in) | 🔴 Missing (correctly) | Per §3.3. |
| `geography` (country_iso2, region, datacenter) | 🔴 Missing | No geo field anywhere in `InferenceProvider`, `ProviderAnnouncementMessage`, or `HardwareCapabilities`. |
| `expires_at` + `manifest_version` (gossip re-broadcast) | 🟠 Partial | `ProviderAnnouncementMessage.ttl_secs` defaulting to 120s (`message.rs:444–446`) and `timestamp: i64` (line 443) cover liveness expiry. **No version field, no signed expiration.** |
| **On-chain SHA-256 commitment of manifest, persisted in `CF_PROVIDERS`** | 🟠 Partial | `CF_PROVIDERS` column family exists and `ProviderManager::with_storage()` writes `ProviderWithMetrics` records to it (`provider.rs:212–243, 269–303`). **But what is persisted is the dynamic in-memory record, not a hash-committed signed manifest.** No domain-tagged SHA-256 commitment. |
| **Gossipsub `tenzro/providers` topic** | 🟠 Partial | Topic exists, `ProviderAnnouncementMessage` propagates (`tenzro-network/src/message.rs:422`). Carries `peer_id`, `provider_address`, `provider_type`, `served_models`, `capabilities`, `rpc_endpoint`, `status`, `timestamp`, `ttl_secs`, plus RFC-0007 `runtime_support` / `network_profile` / `trust_profile`. **No self-signature**, **no SLA**, **no geography**, **no bandwidth**, **no audited attributes**. |

**Highest-impact 3.4 gap:** the entire ProviderManifest. Existing `ProviderAnnouncementMessage` (`tenzro-network/src/message.rs:422`) is the natural place to extend — it already has RFC-0007 trust/runtime/network sidecars. **Concrete next step:** (1) add `compute: ComputeCapacity`, `bandwidth: BandwidthCapacity`, `sla: SlaCommitment`, `geography: Geography`, `attestation_tier: AttestationTier`, and `signature: Signature` fields to `ProviderAnnouncementMessage`; (2) gate gossip-relay verification on the self-signature; (3) compute `SHA-256("tenzro/provider-manifest" || canonical_bytes)` and persist to `CF_PROVIDERS` under a `manifest:` prefix.

---

## 3.5 Bandwidth Metering + Egress Accounting

| Pattern | Status | Evidence |
|---|---|---|
| **Per-inference / per-message settlement** | ✅ Built | `tenzro-settlement` micropayment channels (per CLAUDE.md, real Ed25519 verification on channel updates). `UsageTracker` records per-request `cost` in `UsageRecord` (`crates/tenzro-model/src/usage.rs:27–76`). |
| **Per-byte bandwidth settlement** | 🔴 Missing | `UsageRecord` carries `input_tokens` / `output_tokens` / `cost` / `latency_ms` (`usage.rs:27–45`). **No `bytes_in` / `bytes_out` / `egress_bytes` field.** No per-byte settlement path. |
| **libp2p `BandwidthCounter` integration** | 🔴 Missing | `grep -r "BandwidthCounter\|bandwidth_meter" crates/tenzro-network/src/` returns zero hits. The standard libp2p Rust counter is **not** wired into `tenzro-network`. |
| **`monthly_egress_cap_gb` enforcement (home-operator protection)** | 🔴 Missing | No cap field exists. Routing layer cannot honor a cap that isn't declared. |
| **Zero-egress-fee pricing model (io.net / Aethir)** | 🟠 Partial | Default pricing model `PerToken` with optional `PerRequest` / `PerComputeTime` / `Dynamic` (`tenzro-types/src/model.rs:880–890`) — zero-egress is implicit because there is no egress unit. |

**Highest-impact 3.5 gap:** bandwidth-aware accounting. **Concrete next step:** (1) extend `UsageRecord` with `bytes_in: u64, bytes_out: u64` fields and surface them on `tenzro_listInferenceUsage`; (2) wire libp2p's `BandwidthLogging`/`BandwidthCounter` into `tenzro-network` per-peer + per-protocol; (3) add a new `PricingModel::PerByte` and route bulk artifact transfers (model downloads, DA payload retrieval) through the existing `tenzro-settlement` micropayment-channel path with the byte-priced unit.

---

## 3.6 SLA Enforcement + Reputation-Bonded Slashing

| Failure mode (§3.6 table) | Status | Evidence |
|---|---|---|
| **Consensus equivocation → 10% stake slash** | ✅ Built | `EquivocationDetector` → `StakingSlashingCallback` → `StakingManager::slash` (`tenzro-token/src/staking.rs:543`). |
| **Inference timeout / wrong output → reputation -5** | ✅ Built | `ProviderManager::record_failure` (`provider.rs:486–500`). Called by `InferenceRouter::forward_request_with_config` on every non-2xx response or transport error (`routing.rs:816–844`). |
| **Inference success → reputation +1 (saturating at 1000)** | ✅ Built | `provider.rs:476–484`. |
| **Circuit breaker** (5 failures → 60s open) | ✅ Built | `CircuitBreaker` in `routing.rs:213–293` is consulted before every dispatch (`routing.rs:514–526`). |
| **SLA breach (declared uptime / latency targets)** | 🔴 Missing | No SLA struct → nothing to breach. `ProviderHealth` tracks `consecutive_failures` (`provider.rs:21–42`) and auto-deactivates after threshold (`provider.rs:613–619`), but this is a *liveness* check (HTTP `/health` polling, `provider.rs:556–643`), not an SLA target measurement. |
| **Validator-issued challenges** (challenge-response window) | 🔴 Missing | No challenge protocol. Health checks are unauthenticated HTTP GETs from whichever node happens to be running the checker — no signed challenge transcript on-chain. |
| **Manifest fraud → audited-attribute revocation** | 🔴 Missing | No manifest, no auditor registry, no revocation path. |
| **Compute-bond breach → bond slash via validator subcommittee** | 🔴 Missing | Phase 2, per §3.3. |
| **Dispute resolution via VRF-rotated 7-validator jury** | 🔴 Missing (but VRF precompile available) | VRF precompile `0x1007` (RFC 9381 ECVRF) exists in `tenzro-vm` and is consumed by NFT factory `mintRandom`. No dispute jury consumes it. |

**Highest-impact 3.6 gap:** SLA targets in the manifest plus a challenge protocol. Reputation -5 per failure (already built) is the soft floor; without declared targets the network can't tell "I missed my 99% uptime" from "I happened to be down for 5 minutes." **Concrete next step:** add `SlaCommitment { uptime_target_bps, max_latency_p50_ms, max_latency_p99_ms, challenge_response_window_ms }` to the ProviderManifest; have validators (already TEE-weighted in consensus) issue signed challenges on a Poisson schedule; record challenge-response pairs in a new `CF_CHALLENGES` keyspace; reputation adjustment proportional to declared-vs-measured gap.

---

## 3.7 Open Questions — Implementation Status

| Question | §3.7 Answer | Codebase reality |
|---|---|---|
| **Q1: Bittensor subnet vs. independent L1?** | Independent L1 | ✅ Built. Tenzro Ledger is a full L1 with HotStuff-2, EVM+SVM+DAML, TDIP identity. No subnet abstraction. |
| **Q2: EigenLayer restaking on compute?** | No in Phase 1, optional `ComputeBond` in Phase 2+ | ✅ Built (the "no"). `tenzro-token::bond` exists as agent-bond, not provider-bond — a Phase 2 generalization point but not a regression. |
| **Q3: Data provider vs. inference provider role split?** | Unify under `ProviderManifest.services[].modality` | 🔴 Missing. `NodeRole::ModelProvider` is a single enum value with no per-service decomposition. Generalizing to `ServiceProvider` requires the ProviderManifest from §3.4. |

---

## Section 3 — Open Decisions

1. **ProviderManifest schema — extend `ProviderAnnouncementMessage` or new type?** Pragmatic: extend the existing message (`tenzro-network/src/message.rs:422`) with `compute`, `bandwidth`, `sla`, `geography`, `attestation_tier`, `audited_attributes`, `expires_at`, `manifest_version`, `signature`. The RFC-0007 sidecars (`runtime_support`, `network_profile`, `trust_profile`) already cover ~30% of the field surface. Flag-day cutover per CLAUDE.md hard rule — no legacy ProviderAnnouncementMessage parsing.

2. **Hardware attestation source for `compute.gpu_models`.** Self-declaration alone is fraud-prone (T4 claiming to be H100). Options: (a) require an attached `tee_evidence` blob whose measurement set includes the GPU SKU when `attestation_tier >= VendorAttested`; (b) audited-attribute attestation from a `did:tenzro:human:auditor:*` set (Akash pattern); (c) both. Recommend (c) for Phase 1 — TEE evidence is mechanical, auditor registry is governance.

3. **Bandwidth unit + price discovery.** `PricingModel::PerByte` is a one-line addition (`tenzro-types/src/model.rs:880–890`); the harder question is whether bulk byte transfer settles via the same channel infrastructure as per-token inference. Recommend yes — `tenzro-settlement` channel state machine is unit-agnostic; only the off-chain accumulator changes from `tokens_used: u64` to `bytes_transferred: u64`.

4. **SLA challenge cadence + cost.** Poisson process at λ = (1 hour)⁻¹ per provider keeps challenge volume bounded; challenge cost (validator gas) should be free per CLAUDE.md hard rule on the verification API. Open: who pays for the *response* — provider eats it as cost-of-doing-business, or it's reimbursed from a network challenge-pool funded by the 0.5% network fee.

5. **PCC verifiable-transparency analog.** The cryptographic substrate is the ZK commitment registry pattern — `ImageMeasurementRegistry` keyed by `SHA-256("tenzro/enclave-image" || canonical_image_bytes)`, written by governance, queried by routing on `attestation_required = true`. Open: image distribution channel (gossip, HTTP gateway from §2, IPFS CID per §2.1). The IPFS CID option dovetails with the §2 Data layer work.

6. **Cross-VM provider role unification (Q3).** Generalizing `NodeRole::ModelProvider` → `ServiceProvider` is a wire-format change that touches consensus, identity (`IdentityData::Machine.capabilities`), staking (`ProviderType` enum at `tenzro-token/src/staking.rs`), and gossip topics. Sequencing: ship ProviderManifest first (§3.4), then collapse the role enum in a second flag-day cutover.

# Section 4 — Gap Matrix: Agent Protocols & MCP/A2A

Cross-references `ARCHITECTURE-PRIOR-ART.md` §4 (lines 866–1000) against the actual code under
`crates/tenzro-node/src/{mcp,a2a}`, `crates/tenzro-agent/`, `crates/tenzro-identity/erc8004.rs`,
`crates/tenzro-vm/src/evm/erc8004.rs`, and `integrations/{mcp,a2a}/`.

Legend: Built ✅ · Built-but-not-wired 🟡 · Partial 🟠 · Missing 🔴 · Out-of-scope ⬜

---

## §4.1 — MCP 2025-06-18 Spec Conformance

| Item | Status | Evidence |
|---|---|---|
| MCP server running | ✅ | `crates/tenzro-node/src/mcp/server.rs` (10,332 lines); `rmcp` crate, `StreamableHttpService` mounted at `/mcp` (server.rs:10157–10192) |
| `protocolVersion` advertised | 🟠 | Server reports `ProtocolVersion::V_2025_11_25` (server.rs:9897). Research §4.1 cites `2025-06-18` as current; CLAUDE.md claims `2025-03-26`. **All three numbers disagree.** `2025-11-25` is the latest published rmcp const but the research text needs to be updated, or the server should advertise `2025-06-18` for max compat. |
| Streamable HTTP transport | ✅ | server.rs:10135 comment "Compliant with MCP Streamable HTTP spec (2025-06-18)"; uses `StreamableHttpService` from `rmcp::transport::streamable_http_server` (10126–10128) |
| **Stateless mode** (no session) | 🟡 | server.rs:10137 `with_stateful_mode(false)` + `with_json_response(true)`. Comment explicitly says session management was disabled because rmcp's `LocalSessionManager` closes sessions when the spawned service task exits (10131–10134). Means **no `Mcp-Session-Id` header**, no resumability, no SSE event-IDs. Research §4.1 says spec is stateless-friendly but spec also defines session semantics; Tenzro skipped them. |
| Structured tool output (`structuredContent` + `outputSchema`) | 🔴 | Zero hits for `structuredContent`, `outputSchema`, or `resource_link` in `crates/tenzro-node/src/mcp/`. All 246 `#[tool]` handlers return `Content::text(serde_json::to_string_pretty(...))` (e.g. server.rs:3923, 3931). Agents must re-parse the JSON from a text blob — the single biggest 2025-06-18 win is unused. |
| Resource links (`type: "resource_link"`) | 🔴 | Not used anywhere. Large tensor / Parquet returns would all base64-inline today. |
| OAuth 2.1 as Resource Server | ✅ | `crates/tenzro-node/src/mcp/oauth.rs` (1,290 lines). PKCE present (12 hits); `/.well-known/oauth-authorization-server` (RFC 8414) and `/.well-known/oauth-protected-resource` (RFC 9728) both wired (server.rs:10165–10172). |
| RFC 8707 Resource Indicators | 🟠 | Only 1 hit for `resource_indicator`/`audience` in mcp/. Discovery metadata advertises it; audience-bind enforcement on token verification needs verification. |
| DPoP (RFC 9449) | ✅ (early adopter) | 51 hits across `oauth.rs` + `server.rs`. Research §4.1 notes MCP spec does NOT yet require DPoP — Tenzro is ahead of the curve. Server-side AAP/DPoP RFC 8693 token-exchange tool present (`exchange_token`, server.rs:2911). |
| Elicitation | 🔴 | Not implemented. |
| `_meta` / `title` separated from `name` | 🟠 | `Implementation` sets `name` + `title` (server.rs:9900–9901); individual `#[tool]` macros use `description` only — no per-tool `title`. |
| Tool count | ✅ | 246 `#[tool]` registrations in `server.rs`. CLAUDE.md claims "200+" — accurate. Final log line `tools = 20` (server.rs:10218) is a stale literal, not the real registered count. |

**§4.1 next step:** (a) flip all 246 tool handlers to also emit `structuredContent` alongside `content`, with a `schemars::schema_for!()` `outputSchema` advertised in `tools/list`. The schemas already exist as `JsonSchema` derives on the input param structs — same machinery applied to output types. (b) Fix the `tools = 20` literal in `server.rs:10218`.

---

## §4.2 — A2A v0.3 / Linux Foundation Convergence

| Item | Status | Evidence |
|---|---|---|
| A2A server running | ✅ | `crates/tenzro-node/src/a2a/server.rs` (2,386 lines) |
| Agent Card discovery | 🟠 | Served at `GET /.well-known/agent.json` (server.rs:2275, agent_card.rs:238). **A2A v0.3 spec calls the path `/.well-known/agent-card.json`** — Tenzro is still on the v0.2.0-era name. |
| `protocolVersion` field | 🟠 | Rust card: `"0.2.0"` (agent_card.rs:114). Python card: `"protocolVersion": "0.2.0"` (integrations/a2a/.../agent_card.py:15). Current is **v0.3.0**. |
| JSON-RPC 2.0 dispatcher at `/a2a` | ✅ | server.rs:2276 routes `POST /a2a` → `jsonrpc_handler` (server.rs:245). Methods: `message/send`, `tasks/send`, `tasks/get`, `tasks/list`, `tasks/cancel` (server.rs:259–263). |
| SSE streaming at `/a2a/stream` | ✅ | server.rs:2277, handler at server.rs:278 |
| Skills listed | 🟠 | Rust card declares **25** `AgentSkill` entries (`grep -c 'AgentSkill {'`). Python card declares **34** skills (`grep -c '"id":'`). CLAUDE.md claims "33 skills" — close to Python but **the two implementations diverge** — same `/.well-known/agent.json` path can return different skill sets depending on which server you hit. |
| x402-over-A2A extension | ✅ | `crates/tenzro-node/src/a2a/x402_extension.rs` (648 lines) — full state machine `payment-required` → `payment-submitted` → `payment-verified` → `payment-completed`, hold-and-resume dispatcher contract. Mirrored in `integrations/a2a/.../x402_extension.py`. |
| ACP/A2A LF convergence | ⬜ | Out of scope (governance, not protocol code). |

**§4.2 next steps:** (1) bump `protocolVersion` to `"0.3.0"` and add a duplicate route `/.well-known/agent-card.json` (keep `/agent.json` for back-compat per LF transition window). (2) Reconcile Rust (25) vs Python (34) skill lists — Rust card is the source of truth for the deployed Rust node; the Python integrations package should mirror it or document that it overlays additional skills.

---

## §4.3 — Production Agent Frameworks (LangGraph / Claude Agent SDK / OpenAI / Letta / AutoGen / CrewAI)

| Item | Status | Evidence |
|---|---|---|
| Tenzro MCP is consumable by Claude Agent SDK | ✅ (implicit) | Standard `rmcp` Streamable HTTP server with OAuth 2.1 + DPoP — works against any spec-compliant client. Not explicitly tested in CI. |
| Tenzro MCP is consumable by OpenAI `HostedMCPTool` | 🟠 | Should work via Streamable HTTP; no test harness in this repo proves it. |
| Tenzro MCP is consumable by LangGraph / Microsoft Agent Framework / CrewAI | 🟠 | All consume JSON over HTTP — same path. Tool descriptions are present but lack `outputSchema`, so LangGraph cannot validate tool outputs in `ToolNode`. |
| Integration tests against any of the above | 🔴 | No Python test under `integrations/mcp/tests/` exercises a real LangGraph/Claude SDK/AutoGen client end-to-end. |

**§4.3 next step:** Add a smoke-test under `integrations/mcp/tests/` that boots the local Tenzro MCP with `rmcp` HTTP transport, then connects via (a) `mcp-python-sdk` client, (b) OpenAI Agents SDK `HostedMCPTool` against the same URL, (c) Claude Agent SDK in-process MCP, asserting `tools/list` returns the same 246 tools and `tools/call` round-trips at least the read-only `get_node_status` and `list_models` tools.

---

## §4.4 — AI-Native Content Types

| Item | Status | Evidence |
|---|---|---|
| MCP `text` content type | ✅ | Every tool returns `Content::text(...)` (e.g. server.rs:3923) |
| MCP `image` / `audio` / `resource` / `resource_link` | 🔴 | Zero hits for `Content::image`, `Content::audio`, `Content::resource`, `resource_link`. Multi-modal tools (`vision_embed`, `segment`, `detect`, `transcribe`) accept base64 input but **return JSON-text only** — segmentation masks and detection boxes are JSON, not embedded `image` blocks. |
| Arrow / Parquet / safetensors MIME types | 🔴 | No use of `application/vnd.apache.arrow.stream` etc. anywhere in the MCP surface. |
| Arrow Flight side-channel for large payloads | 🔴 | No Flight server, no `flight_endpoint` ticket pattern. |

**§4.4 next step:** For Phase 1 the smallest concrete improvement is the segmentation and detection tools returning `Content::image` (PNG-rendered mask/bbox overlay) alongside the JSON. The Arrow Flight side-channel is correctly scoped to a follow-up wave per the research §4.4 conclusion.

---

## §4.5 — RAG-2.0 & Agentic Retrieval

| Item | Status | Evidence |
|---|---|---|
| `data_vector_search` tool | 🔴 | No vector-search RPC in node, no tool registered. |
| `data_keyword_search` (BM25) tool | 🔴 | Not present. |
| `data_graph_neighborhood` tool | 🔴 | Not present. |
| `data_rerank` tool | 🔴 | Not present. |
| Built-in RAG pipeline (hybrid + reranker) | 🔴 | None. Text-embedding runtime ships (`crates/tenzro-model/src/te_runtime.rs` per CLAUDE.md), but indexing/retrieval primitives don't exist. |
| GraphRAG | ⬜ | Not on roadmap. |

**§4.5 next step:** This is the largest gap in §4. Phase-1-sized scope: a single `data_query(dataset_id, query, mode: "vector" | "keyword" | "hybrid")` MCP tool backed by FAISS or LanceDB on the node, indexing the local model catalog as the dogfood corpus. Defer GraphRAG and cross-encoder reranker to a later wave. Without retrieval primitives Tenzro is not a "Data MCP" in the §4.5 sense.

---

## §4.6 — Memory & State for Agents

| Item | Status | Evidence |
|---|---|---|
| Letta MemGPT-style core / recall / archival tiers | 🔴 | Zero hits for `Memory`/`recall`/`archival`/`core_memory` as memory-tier concepts in `crates/tenzro-agent/src/` (all 15 hits are "in-memory" referring to non-persisted state). |
| Per-agent persistent state | 🟠 | `AgentRuntime::with_storage()` persists `RegisteredAgent`, `AgentLifecycleInfo`, parent→children spawn tree under CF_AGENTS prefixes `agent:` / `lifecycle:` / `children:` (runtime.rs:27–38). **Identity & lifecycle only — not editable memory blocks.** |
| `AgentTransactionRecord` audit history | ✅ | Persisted under `agenttx:<machine_did>:<seq_be_u64>` (runtime.rs:39–60). Useful for audit, not for prompt-context recall. |
| `memory_create_block` / `memory_search` / `memory_grant` MCP tools | 🔴 | Not present. |
| Letta-style self-editing memory tool-calls | 🔴 | Not present. |

**§4.6 next step:** Add a `MemoryStore` trait in `tenzro-agent` (CF_AGENTS prefix `memblock:<machine_did>:<block_id>`) with `create/read/update/archive/search` and corresponding 5 MCP tools. Cross-link with `DelegationScope` so `memory_grant` reuses the existing delegation enforcement path. This is high-leverage: Tenzro becomes the first decentralized backend a Letta-compatible agent can plug into.

---

## §4.7 — ERC-8004 Trustless Agents

| Item | Status | Evidence |
|---|---|---|
| `ERC8004_IDENTITY` precompile at 0x101a | ✅ | `crates/tenzro-vm/src/evm/erc8004.rs` (2,649 lines), registered at precompiles.rs:70–75. Three `register` overloads (`register()`, `register(string)`, `register(string,(string,bytes)[])`) per ERC-8004 v0.6+, plus `setAgentURI`/`setAgentWallet`/`unsetAgentWallet`/`setMetadata`/`getAgent`. |
| `ERC8004_REPUTATION` precompile at 0x101b | ✅ | `submitFeedback` / `getFeedback` / `getFeedbackCount` + v0.6+ `revokeFeedback` / `appendResponse` / `isFeedbackRevoked` / `getFeedbackResponses` (erc8004.rs:155–197). |
| `ERC8004_VALIDATION` precompile at 0x101c | ✅ | `validationRequest` / `validationResponse` / `getValidation` (erc8004.rs:197–218). Selectors verified against canonical keccak in `register_selectors_match_canonical_keccak` test (erc8004.rs:1388–1399). |
| Byte-identical selectors with Ethereum mirror | ✅ | Tested at erc8004.rs:1388 against canonical `keccak256("register()")` etc. |
| `agentId` derivation matches ERC-8004 spec | ✅ — **but CLAUDE.md doc is wrong** | erc8004.rs:24–29: "`agentId` is a sequentially-allocated `u64` (encoded on the EVM wire as a 32-byte big-endian word)" via `AtomicU64::fetch_add`. **CLAUDE.md claims `agentId = keccak256(utf8(did_string))`**, which is what the old draft did — current code uses sequential ERC-721-style `tokenId` allocation per the final ERC-8004 spec. `did_to_agent_id` (erc8004.rs:334, 381–397) holds the DID→agentId reverse map separately. |
| TDIP outbound bridge to Ethereum ERC-8004 | ✅ | `crates/tenzro-identity/src/erc8004.rs` with `Erc8004Transport` trait + `OnChainAgentRegistry::lookup_agent_id_by_did` hook (lines 65–80, 30–33). |

**§4.7 next step:** Fix the CLAUDE.md line ~"agentId = keccak256(utf8(did_string)) matches `derive_agent_id` exactly" — it doesn't match anymore, the code is correct (sequential u64) and the doc is stale.

---

## §4.8 — Open Design Questions

| Question | Tenzro position | Evidence |
|---|---|---|
| Resource subscriptions vs request/response | Aligned with research (defer) | Server is stateless (`with_stateful_mode(false)`, server.rs:10137). No subscription surface. |
| Wrap Arrow Flight in MCP, or expose Flight separately | Not decided | No Flight server at all; no `flight_endpoint` ticket pattern. |
| One tool per dataset, or generic `data_query(dataset_id, …)` | Not decided | No dataset abstraction exists. |
| Payment before or after the call | Built for A2A, missing for MCP | `a2a/x402_extension.rs` implements full x402-over-A2A hold-and-resume. **MCP tools are unpriced.** Research §4.8 specifically calls out Vercel `x402-mcp` and Coinbase `x402-axios` `paidTools` — Tenzro has the underlying payment stack (`tenzro-payments` with x402 + CDP facilitator) but has not bound it to MCP tool metadata. |

---

## Section 4 — Open Decisions

1. **MCP `protocolVersion` — converge on one number.** Server says `2025-11-25` (rmcp default), research §4.1 quotes `2025-06-18` as current, CLAUDE.md says `2025-03-26`. Pick one and update the other two artefacts.
2. **A2A Agent Card divergence (Rust 25 skills vs Python 34 skills).** Same well-known URL behind a CDN/LB could return either depending on routing. Either consolidate or document the overlay.
3. **`structuredContent` rollout strategy.** All 246 tools need output schemas. Big mechanical change but unlocks LangGraph / OpenAI Agents SDK / Claude Agent SDK full integration. Block-wise rewrite or codegen?
4. **Memory tier (§4.6) — build native or integrate Letta-as-client.** Native gives every Tenzro agent persistent memory under its own DID; Letta-as-client puts Tenzro nodes in front of an existing memory protocol.
5. **x402-on-MCP** (Vercel `x402-mcp` pattern) is a Phase-1 candidate — payment stack already exists, just needs tool-metadata `price` + 402 path.
6. **CLAUDE.md doc drift.** ERC-8004 `derive_agent_id` claim is wrong; tool-count log line `tools = 20` is wrong; A2A skill count "33" matches neither implementation. These are doc-only fixes but they're load-bearing for anyone navigating the codebase.

---

## Status bucket counts

| Status | Count |
|---|---|
| Built ✅ | 14 |
| Built-but-not-wired 🟡 | 2 |
| Partial 🟠 | 9 |
| Missing 🔴 | 14 |
| Out-of-scope ⬜ | 2 |

Total: 41 items across 8 subsections.

# Section 5 — Gap Matrix: Cryptography, ZK, MPC, TEE+ZK

Cross-reference of `ARCHITECTURE-PRIOR-ART.md` §5.1-5.8 (lines 1001-1212) against the actual codebase under `/Users/hilarl/AI/tenzronetwork/crates/`. Status legend: Built ✅ / Built but not wired 🟡 / Partial 🟠 / Missing 🔴 / Out-of-scope ⬜.

---

## 5.1 NIST PQC Standards — FIPS 203 / 204 / 205 / 206

| Research claim | Status | Evidence |
|---|---|---|
| ML-DSA-65 (FIPS 204) implementation | ✅ | `crates/tenzro-crypto/src/pq.rs` — RustCrypto `ml-dsa` crate via `MlDsa65`; key sizes 1952/3309 enforced as constants (lines 49-53); seed-deterministic keygen; CVE GHSA-5x2r-hc65-25f9 fix pinned (line 223). 11 tests pass. |
| ML-KEM-768 (FIPS 203) implementation | ✅ | `crates/tenzro-crypto/src/pq.rs:242-313` — RustCrypto `ml-kem` crate, `MlKem768::generate_keypair()`, encapsulate/decapsulate roundtrip tested (lines 379-405). |
| FIPS-mandated sizes correct (vk 1952, sig 3309, ek 1184, ct 1088) | ✅ | `pq_constants_match_fips` test (`pq.rs:323-335`) asserts wire sizes against `ML_DSA_65_VK_LEN` / `ML_DSA_65_SIG_LEN` / `ML_KEM_768_EK_LEN` / `ML_KEM_768_CT_LEN`. |
| RustCrypto family preferred over `liboqs` FFI | ✅ | Pure-Rust `ml-dsa` 0.1.0-rc.8 and `ml-kem` are wired; no `liboqs-rs` or `pqcrypto-mldsa` in workspace. |
| SLH-DSA (FIPS 205) as long-lived-root fallback | 🔴 | No SLH-DSA module. Only ML-DSA-65 and ML-KEM-768 present. |
| FN-DSA (FIPS 206 draft) — held until final | ⬜ | Correctly out-of-scope per research §5.1; FIPS 206 still draft. |

**Next step (SLH-DSA):** Add `slh-dsa` (RustCrypto) for code-signing of node binaries / TEE measurement allowlists. Single ~150-line module, no consensus integration required.

---

## 5.2 Hybrid KEM + Signature Schemes

| Research claim | Status | Evidence |
|---|---|---|
| Concatenated Ed25519 + ML-DSA-65 hybrid sign + verify | ✅ | `crates/tenzro-crypto/src/composite.rs` — `CompositeSignature { classical, pq }`, `InMemoryHybridSigner`, `StandardHybridVerifier`; downgrade rejection (`composite.rs:178-193`); 6 tests including tampered-leg and downgrade-attempt cases. |
| Validator key Ed25519 + ML-DSA-65 actually loaded at node startup | ✅ | `crates/tenzro-node/src/node.rs:1083-1128` (`load_or_generate_validator_pq_key`) — 32-byte seed persisted at `{data_dir}/validator_pq_key` mode 0600, rederived deterministically. `node.rs:2173` constructs `InMemoryHybridSigner` and stashes on `TenzroNode.validator_hybrid_signer` (field decl `node.rs:779`). |
| Both signatures produced and verified on every block-vote path | ✅ | `crates/tenzro-consensus/src/voter.rs:8` imports `composite::*`; `Vote.signature: CompositeSignature` (line 41), `Vote.public_key: CompositePublicKey` (line 46); vote collector cross-checks `validator.pq_public_key` (voter.rs:278-288). VOTE_FORMAT_VERSION=3 rejects pre-hybrid format (lines 12-19). TimeoutMsg also hybrid (`timeout.rs:198, 1073`). |
| ML-KEM-768 + X25519 hybrid TLS via Caddy | ⬜ | Out-of-scope for code review (Caddy infrastructure layer, verified in Memory entry `project_pq_migration.md`). |
| X-Wing as application-layer KEM combiner | 🔴 | `tenzro-crypto/src/encryption.rs` uses straight X25519 + AES-256-GCM (envelope encryption). No X-Wing combiner. ML-KEM-768 + X25519 hybrid envelope encryption is wirable in <100 lines but not present. |
| OR-composite "either-verifies" mode | ⬜ | Correctly abandoned per research §5.2 — code only implements concatenated mode. |

**Next step (X-Wing):** Add `xwing` (RustCrypto) for application-layer hybrid encryption when payments / wallet payloads need PQ secrecy. Today `encryption.rs` is X25519-only and vulnerable to harvest-now-decrypt-later.

---

## 5.3 PQ-Secure BFT Consensus — What Breaks, What Replaces

| Research claim | Status | Evidence |
|---|---|---|
| Validator signatures replaced by Ed25519 + ML-DSA-65 hybrid | ✅ | See §5.2 row above. Both legs verify on every vote / timeout / NEC. |
| BLS12-381 aggregation broken by Shor — replacement plan | 🟠 | `crates/tenzro-crypto/src/bls.rs` exists (`BlsKeyPair`, `aggregate_signatures`, 96-byte G2 sigs via `blst`) but **is not consumed by `tenzro-consensus`**. Zero hits for `tenzro_crypto::bls` outside the crypto crate itself. Consensus aggregates `Vec<CompositeSignature>` per-voter, not via BLS. Research §5.3's "BLS aggregation hole" therefore doesn't apply — Tenzro never had BLS aggregation in consensus to begin with. |
| BLS rogue-key / proof-of-possession (PoP) | 🔴 | `bls.rs:34` only documents PoP as a comment; no `verify_pop()` or `generate_pop()` function exists. Moot today since BLS isn't used in consensus. |
| FROST-PQ / SNARK-aggregated ML-DSA / SLH-DSA+STARK aggregation | 🔴 | None of the three paths shipped. Per-vote signature is one 64B Ed25519 + one 3309B ML-DSA-65 — bandwidth cost real (~3.4KB × N voters per block) but research §5.3 lists this as Q2 2027 work. |
| VRF on Curve25519 — Shor-vulnerable; SNARK-of-PRF replacement | 🟠 | `crates/tenzro-crypto/src/vrf.rs` is full RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI per §5.4.1.1; wired into EVM precompile 0x1007 (`crates/tenzro-vm/src/precompiles.rs:63, 334`) and NFT factory `mintRandom` (`evm/nft_factory.rs:87`). Quantum-vulnerability is the known gap; SNARK-of-PRF replacement (research §5.3) is on the Q2 2027 roadmap. |
| Reputation-weighted leader election | ✅ | `crates/tenzro-consensus/src/leader_reputation.rs` — full Aptos LeaderReputation port (`FAILED_WEIGHT=1`, `INACTIVE_WEIGHT=10`, `ACTIVE_WEIGHT=1000`, 20-round buffer, SHA-256 anti-grinding seed). Wired via `ProposerElectionKind::Reputation` → `ReputationProposer` in `hotstuff2.rs:443-446`; round outcomes fed back at `hotstuff2.rs:1089, 2113`. Configurable; round-robin remains as fallback. |
| MonadBFT No-Endorsement Certificate | 🟠 | `timeout.rs:622-625` ("f+1 of these aggregate into a `NoEndorsementCertificate`") plus aggregation logic in `hotstuff2.rs:1387-1388` — at least scaffolded. Need to verify the leader-side consumption path that bypasses high-tip-reproposal; deferred. |
| Per-block hybrid attestation appended at finalization (mitigation) | ⬜ | Implicitly addressed: every QC is composed of composite-signed votes, so a "block-finalization-boundary PQ attestation" is already the per-vote ML-DSA-65 leg. Roadmap Q1 2027 line in research §5.8 may be redundant. |

**Top gap:** BLS code is dead — either delete `tenzro-crypto/src/bls.rs` entirely (per the "no dead code" hard rule in CLAUDE.md) or wire it into something concrete. Research §5.3 confirms BLS has no PQ-safe replacement, so deletion is the cleanest path.

---

## 5.4 ZK in 2026 — Plonky3, SP1, Risc0, Jolt

| Research claim | Status | Evidence |
|---|---|---|
| Plonky3 STARK over KoalaBear with FRI | ✅ | `crates/tenzro-zk/src/plonky3/config.rs` — `Val = KoalaBear`, `Challenge = BinomialExtensionField<Val, 4>`, Poseidon2 width-16/24, `TwoAdicFriPcs`. |
| Pinned config: log_blowup=1, num_queries=64, query_pow=16, commit_pow=8 | ✅ | `plonky3/config.rs:89-99` (`testnet_fri_parameters`) — exact values per research claim. |
| Pinned git rev `32079474b1d31d9221656ae774afb322d2597db0` | ⬜ | Workspace Cargo.toml pin not verified in this pass; CLAUDE.md and research both assert the rev. |
| Three AIRs (inference / settlement / identity) compiled and called | ✅ | `crates/tenzro-zk/src/circuits/airs/{inference,settlement,identity}.rs` all present; re-exported in `lib.rs:41-49`. Dispatcher `verify_proof_envelope` in `plonky3/verify_envelope.rs:52-78` matches on `circuit_id` ∈ {"inference", "settlement", "identity"} and runs the appropriate `Plonky3Verifier<A>`. Inline test (`verify_envelope.rs:91-106`) builds and verifies a real inference proof. |
| Wire format: bincode-encoded p3 proof + 4-byte LE field-chunk public inputs | ✅ | `plonky3/envelope.rs` (referenced from `verify_envelope.rs:23`); `Proof { proof_bytes, public_inputs, circuit_id, proof_type }` envelope. |
| `ZkCommitmentRegistry` for O(1) EVM precompile lookup | ⬜ | Not inspected in this pass; CLAUDE.md asserts wired in `tenzro-vm`. |
| SP1 / Risc0 / Jolt steelman | ⬜ | Per research §5.4 these are alternatives, not required. |
| Post-quantum soundness via FRI / SHA-256 commitments | ✅ | KoalaBear + Poseidon2 + FRI gives the PQ-conjectured soundness; commitment hash is SHA-256 (256-bit pre-image, Grover-safe at 128-bit margin). |

---

## 5.5 TEE + ZK Composition

| Research claim | Status | Evidence |
|---|---|---|
| Hybrid TEE+ZK proof type (`TeeZkProof`) | ✅ | `crates/tenzro-zk/src/tee_integration.rs:1-93` — `generate_tee_zk_proof` runs prover, bundles output with `AttestationReport`; `verify_tee_zk_proof` re-verifies STARK + (optionally) enclave-key Ed25519 signature. Verifier delegates hardware attestation to `tenzro-tee::AttestationVerifier`. |
| Four vendor families: TDX, SEV-SNP, Nitro, NVIDIA | ✅ | `crates/tenzro-tee/src/{intel_tdx,amd_sev_snp,aws_nitro,nvidia_gpu}.rs` all present; real ioctl paths + X.509 chain verification + ECDSA P-256/P-384 signature verification per CLAUDE.md. Simulation fallback only via `TENZRO_SIMULATE_*` env. |
| Intel Tiber Trust Authority `get_token_v2` composite token (TDX + NVIDIA H100 CC over PCIe) | 🔴 | **No `trust_authority` / `tiber` / `get_token_v2` references anywhere in the workspace.** Each vendor verifier stands alone; relying parties stitch TDX-quote + NVIDIA-NRAS + AMD-VCEK manually. Research §5.5 / §5.8 claims this is shipped — it is not. |
| Apple PCC-style public transparency log of TEE binaries | 🔴 | No transparency-log component. Measurement allowlisting is local. |
| Vendor-diverse provider pool routing | 🔴 | No protocol-level vendor-diversity enforcement; provider selection in `tenzro-model::InferenceRouter` is price/latency/reputation/weighted, not TEE-vendor-aware. |
| NVIDIA NRAS report max-age 24h | ⬜ | Constant pinned per CLAUDE.md; not inspected this pass. |

**Top gap:** The "composite TEE attestation tokens for TDX + NVIDIA H100/H200 CC via Intel Tiber Trust Authority `get_token_v2`" claim in `ARCHITECTURE-PRIOR-ART.md:1184` and CLAUDE.md is **aspirational** — there is no Tiber client. Smallest next step: implement `intel_tdx::TrustAuthorityClient::get_token_v2(report, gpu_evidence) -> Jwt` against the documented REST endpoint, then verify the JWT chain against Intel's signing root.

---

## 5.6 MPC, Threshold Signatures, FROST

| Research claim | Status | Evidence |
|---|---|---|
| FROST-Ed25519 (RFC 9591) implementation | ✅ | `crates/tenzro-crypto/src/frost.rs` — full RFC 9591 over `frost_ed25519` crate (ZcashFoundation). Trusted-dealer keygen (`keygen_with_trusted_dealer`), round1_commit, build_signing_package, round2_sign, aggregate_signature. **DKG (no-dealer)** also shipped: `dkg_part1` / `dkg_part2` / `dkg_part3` with tagged wire format (lines 145-207, 458-658). Output is byte-identical 64-byte Ed25519 signature verifiable via `tenzro_crypto::signatures::verify`. 17 unit tests including end-to-end DKG + 2-of-3 sign + verify. |
| FROST integration in `tenzro-crypto::mpc` (legacy memory note) | ✅ | **Memory entry `feedback_no_gg18_gg20_use_cggmp21_or_frost.md` is outdated.** No `mpc.rs` module exists in `tenzro-crypto/src/`. Module list confirmed: `bls, composite, encryption, error, frost, hash, keys, p256, pq, rng, signatures, vrf, webauthn`. Shamir+reconstruct anti-pattern has been removed. |
| Wallet uses FROST end-to-end | ✅ | `crates/tenzro-wallet/src/{wallet,mpc_signing,provisioning}.rs` — `MpcWallet.frost_pubkey_package: Option<PublicKeyPackage>`; `MpcSigner::sign` runs full FROST session in-process. `ProvisioningConfig::default()` = 2-of-3 Ed25519 (`provisioning.rs:89, 191`); calls `keygen_with_trusted_dealer(2, 3)` at line 121. |
| Distributed FROST (per-node signers, wire-exchanged commitments/shares) | 🟠 | Primitives exposed in `tenzro_crypto::frost` (per `mpc_signing.rs:9-12`), but the wallet runs both rounds in-process — distributed signing is a follow-up. Acceptable for current single-custody profile; required before m-of-n wallets ship to end users with shares on separate devices. |
| CGGMP24 (secp256k1, LFDT-Lockness fork) for EVM bridge signing | 🔴 | Zero hits for `cggmp24` / `cggmp21` / `dfns` / `lockness` in crate code (only a doc-comment reference in `frost.rs:11`). Bridge crate signs with `tenzro-crypto::signatures` (single-signer ECDSA / Ed25519). Wiring is upstream-blocked on [`LFDT-Lockness/fast-paillier#23`](https://github.com/LFDT-Lockness/fast-paillier/issues/23) (`glass_pumpkin 1.10` / `rand_core 0.10` `Rng + DerefMut` bound). Sequenced to Phase D (§B.5 / §D.1). Phase B's bridge-custody hardening stops at TEE-sealing the existing single-key signer. |
| Passkey-first auth (FIDO caBLE / webauthn) | 🟠 | `crates/tenzro-crypto/src/{p256,webauthn}.rs` — P256Signer/P256Verifier, `verify_webauthn_assertion`, signed-payload helpers all present. Wallet-side integration (PluggableSigner trait, passkey-bound MPC orchestration) not inspected; CLI auth uses OAuth 2.1 + DPoP per `tenzro-cli/main.rs:227`. |
| ERC-7579 SpendingLimit enforced at signing time on-chain | 🟠 | `tenzro-vm`'s ERC-4337 v0.8 + Smart-account modules incl. `SpendingLimit` are per CLAUDE.md; ERC-7579 modular-validator wiring at on-chain enforcement boundary not verified this pass. Off-chain `SpendingPolicyResolver` is well-established (`crates/tenzro-node/src/spending_policy_bridge.rs`). Per memory entry `feedback_custody_enforce_at_signing_time.md`, this is the open custody gap. |
| ERC-7444 passkey session keys | ⬜ | `SmartAccount` modules incl. `SessionKey` per CLAUDE.md — not inspected. |

---

## 5.7 Academic Papers Shaping 2026 Design

| Paper | Status in code | Evidence |
|---|---|---|
| HotStuff-2 (Malkhi & Nayak 2023) | ✅ | `crates/tenzro-consensus/src/hotstuff2.rs` — 2780+ lines. |
| HotStuff-1 one-phase speculation (arXiv:2408.04728) | 🔴 | Not implemented. Roadmap item. |
| Aptos LeaderReputation / Shoal | ✅ | `leader_reputation.rs` full port; see §5.3 row above. |
| Mysticeti (uncertified DAG, NDSS 2025) | ⬜ | Out-of-scope for current consensus design; research §5.7 lists as future direction if Tenzro moves DAG-ward. |
| MonadBFT (No-Endorsement Certificate, arXiv:2502.20692) | 🟠 | Scaffolded in `timeout.rs` and `hotstuff2.rs:1387-1388`; needs end-to-end verification. |
| Solana Alpenglow (SIMD-0326) | ⬜ | External standard, tracking only. |
| Bullshark / Narwhal / Tusk | ⬜ | Reference material; no consumption. |
| DiLoCo / DisTrO / INTELLECT-1/3 / OpenDiLoCo | ⬜ | Consumed by `tenzro-training` Rust protocol + Python reference trainer per CLAUDE.md "Tenzro Train architecture" — outside this section's scope. |
| Aequitas / Themis / F3B / Helix (fair ordering) | 🔴 | Not implemented. Research §5.8 places this at Q4 2027. |
| W3C DID Core 1.0 / VC Data Model 2.0 | ⬜ | Implemented in `tenzro-identity` per CLAUDE.md; out-of-scope for §5. |
| ERC-8004 (Trustless Agents) | ⬜ | Implemented as EVM precompiles `0x101a/b/c` per CLAUDE.md; out-of-scope for §5. |

---

## 5.8 Tenzro-Specific Implications — Already Shipped vs. Pending

Cross-check of research §5.8 "Already shipped" bullets:

| Claim | Truth |
|---|---|
| Plonky3 over KoalaBear with FRI — three production AIRs | ✅ Confirmed |
| Validator key = Ed25519 + ML-DSA-65 in concatenated hybrid mode | ✅ Confirmed — both legs sign and verify per-vote per-timeout |
| ML-KEM-768 + X25519 hybrid TLS at Caddy | ⬜ Infrastructure; not verified in code |
| Hybrid TEE-attested + ZK-of-commitment via `tenzro_zk::tee_integration` | ✅ Confirmed — `generate_tee_zk_proof` / `verify_tee_zk_proof` real, signing helpers real |
| Composite TEE attestation tokens via Intel Tiber Trust Authority `get_token_v2` | 🔴 **Not shipped.** No Tiber client, no JWT composite-token verifier. Research and CLAUDE.md both overclaim. |

---

## Section 5 — Open Decisions

1. **Delete `tenzro-crypto::bls` or wire it.** It is currently dead code (zero external callers), and research §5.3 confirms BLS aggregation has no PQ-safe successor. Either (a) delete the module per CLAUDE.md's "no dead code" hard rule, or (b) wire it as a non-PQ optimisation for some non-consensus use case (light-client receipts, bridge-message aggregation). Defaulting to (a) seems right.
2. **Implement Intel Tiber Trust Authority client** to actually produce the composite TDX+H100 token claimed in §5.8. ~300 lines: REST POST to `https://api.trustauthority.intel.com/appraisal/v2/attest`, JWT verify against Intel's signing root, surface `composite_token` on `TeeZkProof`.
3. **CGGMP24 secp256k1 threshold for bridge signing** sequenced to Phase D (ROADMAP §B.5 / §D.1). Phase B's interim bridge-custody ceiling is TEE-sealing the existing `EvmTransactionSigner` key on TDX/SEV-capable validators. Full t-of-n migration ships once `LFDT-Lockness/fast-paillier#23` resolves upstream — vendoring is rejected on maintenance-burden grounds for a Paillier dependency.
4. **Refresh `MEMORY.md`** `feedback_no_gg18_gg20_use_cggmp21_or_frost.md` — the "Current `tenzro-crypto::mpc` is Shamir+reconstruct" assertion is no longer true; the module has been replaced by `tenzro_crypto::frost`. Memory entry should be flipped to a positive "FROST shipped, CGGMP24 deferred to Phase D" status.
5. **Distributed FROST signing (wire-exchanged commitments / shares)** before any m-of-n end-user wallet ships with shares actually on separate devices. Today the wallet runs FROST in-process — fine for "auto-provisioned custodial-but-MPC-internally" mode, not fine for true multi-device custody.
6. **SLH-DSA (FIPS 205)** for node binary code-signing / TEE measurement allowlists — small effort, high audit-defensibility win.
7. **X-Wing application-layer KEM** for `tenzro-crypto::encryption` so payment / wallet payloads are PQ-secret-at-rest as well as PQ-signed.
