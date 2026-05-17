# Section 1: libp2p, NAT Traversal, Content Routing, and BFT Validator Overlays — Prior Art (2026)

Source survey for Tenzro's networking layer. Tenzro's `tenzro-network` crate runs on rust-libp2p (gossipsub + Kademlia + Identify + Ping + Relay v2 + AutoNAT v2 + DCUtR); this section grounds the choices already shipped (`crates/tenzro-network/src/{config,behaviour}.rs`) and frames the open question of whether HotStuff-2 vote traffic should stay on gossipsub or move to a validator-only direct-connect overlay.

---

## 1.1 rust-libp2p in 2026

The stack on which `tenzro-network` is built. The 0.53 → 0.56 evolution is the foundation: 0.53 (Nov 2023) introduced the type-safe `SwarmBuilder` and removed `ConnectionHandler::Error`; 0.54 (Aug 2023) and 0.54.1 (Sep 2023) stabilized the transport composition surface; 0.55 (Jan 2024) tightened lifecycle ergonomics; 0.56 (Jun 2024) cut `async-std` entirely. Two and a half years of minor-version churn, but the public `Swarm` surface has held — every Tenzro behaviour (`gossipsub::Behaviour`, `kad::Behaviour`, `identify::Behaviour`, `ping::Behaviour`, `relay::Behaviour`, `dcutr::Behaviour`, `autonat::v2::client::Behaviour`) composes through the same `NetworkBehaviour` derive.

**`idle_connection_timeout` — the most consequential default.** Since v0.53, `SwarmBuilder::with_swarm_config(|c| c)` defaults `idle_connection_timeout` to `Duration::ZERO`. Any TCP connection without an in-flight substream is closed immediately on the next poll. The issue thread (`libp2p/rust-libp2p#4912`, opened Nov 2023 by @thomaseizinger, closed by `#4967`) documents that the default value is wrong for nearly every production deployment but was left in place to avoid breaking the existing semantics. The library expects every operator to override it. Gossipsub doesn't log when a mesh peer disconnects from idle timeout — it treats it as ordinary `ConnectionClosed` — so the mesh degrades silently from N-1 → 0-4 peers under any long-quiet pairwise traffic pattern. HotStuff-2 has exactly that pattern between vote rounds; Tenzro hit this in production on 2026-05-14 across the 10-validator GCE multi-region testnet. The fix is one line: `SwarmConfig::idle_connection_timeout(Duration::from_secs(600))` (Tenzro's current value in `NetworkConfig::default()`).

**Gossipsub mesh dynamics under long-quiet pairwise links.** The default mesh parameters (`mesh_n=6`, `mesh_n_low=4`, `mesh_n_high=12`, `D_lazy=6`) assume a steady stream of messages on each topic — heartbeats every `heartbeat_interval` (Tenzro uses Ethereum's 700ms; default is 1s) keep the mesh wired. When two peers in the mesh have no traffic between them for the idle window, the connection drops; the peer drops out of the mesh; GRAFT re-attaches it on the next heartbeat *if* a transport-layer dial succeeds. On a healthy LAN this is invisible. On WAN with conntrack timeouts (GCE 600s, AWS varies, Cloudflare 60s on free tier) it's a continuous low-grade churn. Pinning `idle_connection_timeout >= heartbeat_interval * 10` is the working rule; Tenzro's 600s comfortably exceeds it.

**`ConnectionLimits`.** Tenzro caps inbound and outbound at 200 each (`max_inbound_peers: 200, max_outbound_peers: 200` in `NetworkConfig`), enforced via the `libp2p::connection_limits::Behaviour`. The unbounded-connection-handler advisory (`GHSA-jvgw-gccv-q5p8`, May 2024) made `ConnectionLimits` mandatory for production deployments; pre-advisory code without limits is a remote DoS vector. Pending substream limits (`StreamLimits`) are configured separately on each behaviour.

**Kademlia in production.** Tenzro uses S/Kademlia disjoint-path lookups (default `disjoint_query_paths(true)`), 30-second query timeout, `replication_factor = 10`. The two operational issues that bite every kad deployment: (1) bootstrap-list staleness — `Behaviour::bootstrap()` must be re-called on a cadence (Lighthouse's 60s pattern in `sigp/lighthouse#3005` is the canonical reference); a single call at startup is insufficient because the routing table evicts dead peers and never re-adds the boot nodes. (2) `add_address` vs. `RoutingUpdate::Pending` — when the routing table is full at a given bucket distance, new addresses are queued for ping-replacement and not active immediately; the lookup that triggered the add still completes with the pre-add view.

**Identify and the listen-addr enumeration question.** `libp2p::identify::Behaviour` by default broadcasts every address the swarm is listening on to every peer. On a cloud node that binds to `/ip4/0.0.0.0/tcp/9000`, the swarm enumerates every interface — including `docker0` (172.17.0.1) on hosts running `--network host` containers, every CNI overlay address on Kubernetes nodes, every WireGuard tunnel. Peers receive this bag, dial `172.17.0.1`, hit their *own* `docker0` bridge, get a peer-ID mismatch from a local container, and the per-IP rate limiter then bans the legitimate peer. The fix is `identify::Config::with_hide_listen_addrs(true)` combined with explicit `Swarm::add_external_address(...)` calls — the node advertises only the addresses it knows are publicly correct (a statically-configured public IP for cloud validators, or an address that AutoNAT v2 has confirmed). Tenzro adopted this pattern in May 2026 after observing the docker-bridge-ban behaviour on the multi-region GCE testnet (`crates/tenzro-network/src/behaviour.rs` and the `external_addresses` field in `NetworkConfig`).

**Gossipsub peer scoring.** Gossipsub v1.1 (the version Tenzro runs) added a peer-scoring system that weights mesh-peer behaviour across six metrics — `P₁` time-in-mesh, `P₂` first-message-delivery, `P₃` mesh-message-delivery (penalty if a peer underdelivers), `P₃b` mesh-failure-penalty (decay-on-removal), `P₄` invalid-messages, `P₇` application-specific score. Peers below the `graylist_threshold` are silently demoted from the mesh; peers below `publish_threshold` are excluded from new GRAFTs; peers below `gossip_threshold` are denied gossip metadata. Tenzro installs peer scoring with the default Gossipsub-v1.1 weights in `behaviour.rs::with_peer_score`. The two operational gotchas: (1) `decay_interval` must be set to a multiple of `heartbeat_interval` or scores reset between heartbeats and the system never converges; (2) `P₃` (mesh delivery) computes against an expected message rate per topic — for a low-volume topic like `tenzro/consensus` between vote rounds, the expected rate is near-zero, so peer scores stay flat even when peers are misbehaving. Peer scoring is the right defense against spam topics (`tenzro/transactions`) and the wrong defense for consensus-vote topics; another reason §1.6's overlay split matters.

**What's pinned vs drifting.** The `Cargo.toml` pin for `libp2p` minor versions matters because gossipsub's wire protocol (`/meshsub/1.1.0`) is stable but the configuration surface (`gossipsub::ConfigBuilder` field names, peer-scoring weights) has shifted between 0.53 and 0.55. Tenzro pins libp2p to a single minor version across the workspace; bumping requires re-testing the mesh under load. Long-term, the libp2p team is moving toward a stable 1.0 with separated transport/behaviour crates (libp2p-core, libp2p-swarm, libp2p-gossipsub each versioned independently), but the umbrella `libp2p` crate remains the canonical entry point in 2026.

**Yamux vs Mplex.** Mplex was deprecated in libp2p 0.49 (Jul 2022) and removed in 0.54 (Aug 2023); Yamux is the only remaining TCP-stream multiplexer in rust-libp2p. Yamux 1.4+ supports configurable receive-window sizes (`yamux::Config.set_max_buffer_size`) which matters for any stream that bursts (model artifact download, large transaction batches). The QUIC path bypasses Yamux entirely — QUIC has native stream multiplexing — which is one more reason to prefer QUIC for high-throughput peer traffic.

---

## 1.2 NAT Traversal — Relay v2 + AutoNAT v2 + DCUtR

NAT traversal in libp2p is a three-protocol choreography: AutoNAT v2 tells a node whether it's publicly reachable; Relay v2 gives it a fallback address when it isn't; DCUtR upgrades a relayed connection to a direct one via simultaneous hole-punching.

**Relay v2 (`/libp2p/circuit/relay/0.2.0/hop`, `/libp2p/circuit/relay/0.2.0/stop`).** Replaced the unconstrained v1 protocol. Peers must explicitly *reserve* a slot on a relay before traffic can be routed to them; the reservation has an expiry (default 1 hour) and yields a cryptographic voucher the peer can hand to dialers. The relay enforces per-connection limits on both `duration` (max seconds) and `data` (max bytes per direction); exceeding either resets the stream. This was the headline fix from v1, where any peer could route arbitrary traffic through any relay. Tenzro's `NetworkConfig.enable_relay` defaults to `false` — Tenzro nodes do not act as relays; community joiners behind NAT use third-party relays (libp2p public relays, IPFS bootstrap relays) until Tenzro stands up its own relay tier.

**AutoNAT v2 (`/libp2p/autonat/2/dial-request`, `/libp2p/autonat/2/dial-back`).** v2 is a near-complete redesign. v1 asked a server "am I publicly reachable?" and got a yes/no per node; v2 asks "is *this specific address* publicly reachable?" and gets a per-address answer. The v2 flow: client sends `DialRequest` with a list of candidate addresses and a 64-bit nonce; server picks one it can dial, opens a `/libp2p/autonat/2/dial-back` stream back, sends `DialBack` containing the nonce; client confirms receipt with `DialBackResponse`; server returns the final `DialResponse`. The nonce + dial-back-on-target-port mechanism is the amplification-attack defense — v1 forbade testing IPs that differ from the request source IP, v2 allows it because the dial-back proves possession of the keypair at the target address. AutoNAT v2 is what lets a node behind a fully-cone NAT (where the external port matches the internal port) discover its external address and publish it via Identify.

**DCUtR (`/libp2p/dcutr`).** Direct Connection Upgrade through Relay. Two peers, both behind NAT, both reserved on the same relay; they coordinate a simultaneous-open through the existing relay connection. The choreography: peer A sends `Connect` to peer B via the relay, containing A's observed external addresses; B replies with its own observed addresses and timing-synchronization data; both peers measure round-trip time to the relay, schedule a simultaneous dial (`Sync` message) at the predicted moment to coincide, and attempt a direct TCP simultaneous-open or QUIC UDP exchange to each other's external addresses. If any direct connection lands, the peers migrate substream traffic onto it and close the relay leg. If all attempts fail, they stay on the relay (graceful degradation). The relay never sees the post-upgrade traffic.

**Success rates in the wild.** Protocol Labs Research's 2022 study on libp2p hole-punching effectiveness measured ~70% success across IPFS deployments — the headline number that defines the practical envelope. The remaining 30% is gated by: symmetric NATs (most consumer-grade carrier-NAT — different external port per destination, so the dial-back address moves; AutoNAT v2 alone can't predict it), strict firewalls (corporate networks with deep packet inspection that block UDP), and CGNATs where the home router has no public IP at all. The QUIC path improves the punch rate marginally over TCP because UDP simultaneous-open is more forgiving than TCP's SYN-SYN race, but neither solves symmetric NAT — for that, Relay v2 stays the fallback indefinitely.

**Implication for Tenzro.** Validators in the testnet GKE/GCE deployment have static public IPs and skip AutoNAT/DCUtR entirely (`hide_listen_addrs(true)` + `external_addresses` configured in `NetworkConfig`). Home operators joining the network from behind NAT use the full choreography — AutoNAT v2 confirms the address, Relay v2 holds the fallback, DCUtR upgrades when possible. The 70% hole-punch rate is acceptable for an "agentic internet" L1 where the marginal stalled-on-relay node is still functional; it does not impede consensus because consensus is validator-only. For an agent at the edge talking to other agents at other edges, relay fallback bandwidth cost is the visible UX impact.

---

## 1.3 QUIC + Post-Quantum TLS in libp2p

QUIC is the transport priority in libp2p 2026 — TCP+Yamux+Noise is still supported, but every recent libp2p paper and config example leads with QUIC. The reasons are well-rehearsed: 0-RTT handshake on resumption, encrypted transport headers (Noise XX is plaintext at the framing layer), multiplexed streams without head-of-line blocking, and a friendlier hole-punch profile. libp2p-QUIC binds the libp2p peer identity directly to the QUIC TLS handshake — there's no separate Noise step — which is cleaner and faster than the TCP path. Tenzro listens on both (`/ip4/0.0.0.0/tcp/9000` and `/ip4/0.0.0.0/udp/9000/quic-v1` in `NetworkConfig::default()`) and the QUIC path is preferred by the dialer when available.

**Post-quantum TLS — the hybrid X25519+ML-KEM-768 codepoint.** NIST finalized ML-KEM as FIPS 203 in August 2024 (the standardized version of CRYSTALS-Kyber). The IETF TLS WG's `draft-kwiatkowski-tls-ecdhe-mlkem` defines three hybrid combinations — `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` — registered in the IANA TLS Supported Groups registry. `X25519MLKEM768` carries codepoint `0x11EC` (4588 decimal) — the hybrid that pairs a 32-byte X25519 share with a 1184-byte ML-KEM-768 share, providing classical security from X25519 and post-quantum security from ML-KEM. The draft `draft-ietf-tls-hybrid-design-16` defines the general construction framework and is in the "Submitted to IESG for Publication" stage as of early 2026.

**Implementation status (early 2026).** BoringSSL has shipped X25519MLKEM768 since late 2024 (`SSL_GROUP_X25519_MLKEM768`). OpenSSL 3.5 added it in April 2025 (`SSL_CTX_set1_groups_list("X25519MLKEM768:X25519")`). rustls 0.23 added it through the `aws-lc-rs` provider; the `rustls-post-quantum` crate exposes it as a default-on group. Cloudflare's TLS terminator has supported hybrid PQ since 2023 (initially Kyber pre-standardization, switched to ML-KEM-768 post-FIPS). Google Chrome enabled X25519MLKEM768 by default in M124 (April 2024) for outbound TLS connections; Firefox followed.

**libp2p's PQ status.** libp2p's TLS handshake (`/libp2p/tls/1.0.0`) uses the underlying language-specific TLS stack — go-libp2p's `go-libp2p-tls` consumes `crypto/tls`, rust-libp2p's `libp2p-tls` consumes `rustls`. Where the underlying stack supports X25519MLKEM768 the libp2p path *implicitly* gets it on the wire, but neither implementation has shipped explicit configuration knobs for PQ group selection as of the v0.56 line. The Noise path (`/noise`) uses 25519-only XX handshake with no PQ option — Noise's PQ extension (`pqNoise`) is research-stage. The pragmatic answer for 2026: prefer libp2p-QUIC over libp2p-Noise on validator-to-validator links specifically because libp2p-QUIC pulls TLS 1.3 with hybrid groups automatically when the rustls feature flag is enabled.

**Tenzro's PQ posture.** Caddy reverse-proxying the public RPC/MCP/A2A endpoints already negotiates X25519MLKEM768 (Caddy uses Go's `crypto/tls` which inherits the hybrid group). The libp2p mesh between Tenzro validators inherits whatever rustls negotiates on the QUIC leg. Tenzro's hybrid Ed25519+ML-DSA-65 signature migration (per the project memory `project_pq_migration.md`) is independent of the TLS layer — that one is about block signatures and consensus votes, which sit above the transport. The two PQ surfaces — transport (X25519+ML-KEM hybrid in TLS) and application (Ed25519+ML-DSA hybrid in signatures) — compose without overlap.

---

## 1.4 Content Routing — Bitswap, IPNI, Trustless Gateway

The IPFS content-routing stack in 2026 splits into three cooperating layers: Bitswap for block-level exchange between peers, IPNI for indexing who has what, and the Trustless Gateway specification for HTTP-fronted retrieval. Together they are how content addresses become bytes.

**Bitswap (`/ipfs/bitswap/1.2.0`).** Block-exchange protocol. The 1.2.0 revision (current production version) added `want-have` queries — a peer can ask "do you have block CID?" with a small response (`HAVE`/`DONT_HAVE`/block-size) before deciding to ask for the actual bytes with `want-block`. Pre-1.2.0 was `want-block`-only, which forced peers to download blocks blindly from anyone who might have them, wasting bandwidth. The 1.2.0 flow optimizes for fan-out: a peer sends `want-have` to its full session group, gets cheap `HAVE` responses from a subset, then `want-block` only to the closest holder. Bitswap is still the inter-peer block-transfer primitive even when content routing happens through IPNI or Kademlia.

**IPNI — Interplanetary Network Indexer.** Centralizes the "who has CID X?" query that would otherwise hit Kademlia's DHT. Storage providers and pinning services push advertisements to indexer nodes; clients query the indexer over HTTP (`https://cid.contact/cid/<cid>`) and receive a list of provider records with addresses and protocols. The motivation is operational: DHT lookups across the global Kademlia ring add 200-2000ms per CID, which is unacceptable for interactive retrieval; an indexed HTTP query returns in tens of milliseconds. The trade-off is centralization — `cid.contact` is the Filecoin Foundation's canonical indexer; alternate indexers can be run but the ecosystem is concentrated. Filecoin storage providers advertise to IPNI by default; non-Filecoin IPFS nodes opt in via the Storetheindex software.

**Trustless Gateway specification (`https://specs.ipfs.tech/http-gateways/trustless-gateway/`).** HTTP gateway that serves raw IPLD blocks or CAR archives rather than rendered HTML — the client is responsible for verifying the CID matches the bytes received. This is the "trustless" property: the gateway cannot lie because the hash check is local. Standard endpoints: `/ipfs/{cid}?format=raw` returns a single block, `/ipfs/{cid}?format=car` returns a CAR archive with the requested DAG. Saturn (Filecoin Foundation's CDN-of-Trustless-Gateways), Pinata, web3.storage, and Fleek's gateway all conform. The browser-side `helia` library and the Rust `rust-ipfs` (and Iroh, §1.5) use trustless gateways as the default fetch path when peer-to-peer paths are unavailable or slow.

**Filecoin Saturn.** Decentralized CDN of trustless gateways. Edge nodes run by community operators serve content addressed by CID, paid in FIL through L2 rollup settlements. Cache hit rates of 90%+ for hot content; cold fetches fall through to storage providers via IPNI lookup. Saturn is the production demonstration that content addressing scales to CDN traffic patterns when the lookup layer is centralized-enough (IPNI) and the serve layer is decentralized-enough (Saturn nodes).

**Production deployments.** The IPFS Foundation runs `dweb.link` and `ipfs.io` as trustless-gateway endpoints with `cid.contact` as the indexer. Fleek operates a commercial trustless-gateway CDN. Cloudflare ran an IPFS gateway through 2024 then deprecated it (the deprecation was operational, not technical — Cloudflare's `cloudflare-ipfs.com` is now defunct, but `ipfs.io` and `dweb.link` remain). web3.storage and Pinata both serve trustless responses for pinned content. The aggregate effect: content addressing has a working operational substrate in 2026, even if the original "every browser is an IPFS node" vision is not how the production stack is actually shaped — HTTP gateways do the heavy lifting and Bitswap is the protocol of last resort.

**Implication for Tenzro.** Tenzro does not run a Bitswap/IPNI/gateway stack today — model artifacts are downloaded from HuggingFace Hub directly (`hf-hub` crate in `tenzro-model`) and DA-offload primitives (`tenzro-storage::da`) hold pointers to external DA backends, not CIDs. The right time to adopt IPFS content routing is when (a) the model artifact store needs to be decentralized and (b) the DA backend (currently inline-fallback only) is wired to a real CID-addressed DA layer. EigenDA and Celestia both expose CID-shaped commitments; Avail uses KZG. The bridging layer between Tenzro's `ReceiptEnvelope` and the IPFS stack is small (one HTTP fetch by CID, hash-verified) — it does not require Tenzro to run a full libp2p IPFS node.

---

## 1.5 Iroh as a Rust Alternative

Iroh (`github.com/n0-computer/iroh`, v1.0.0-rc.0 May 2026) is a Rust networking library that takes a different stance from libp2p: NAT-traversal-first, Tailscale-grade UX, much lighter dependency tree. The pitch on the README: "IP addresses break, dial keys instead."

**Architecture.** Iroh is QUIC-only — no TCP+Noise fallback path. The QUIC implementation is built on `quinn` with a custom `noq` (`Noise-on-QUIC`-style) authentication layer that binds the peer's Ed25519 public key directly to the TLS handshake. Hole-punching is the default path; when it fails, traffic falls back to a global mesh of public relays operated by Number Zero (n0) and the community. The relay choreography is similar to libp2p's Relay v2 + DCUtR but simpler in surface area — one protocol, not three. Discovery uses `pkarr` (Public-Key Addressable Resource Records) and the BitTorrent Mainline DHT instead of Kademlia-style libp2p DHT.

**Composable protocols.** `iroh-blobs` (content-addressed transfer over QUIC streams, BLAKE3-hashed, supports range requests and verified streaming), `iroh-gossip` (publish-subscribe with HyParView + Plumtree, less feature-rich than libp2p-gossipsub but lower-overhead), `iroh-docs` (eventually-consistent key-value store built on `iroh-blobs`). These compose into the same agent-to-agent or agent-to-tool flows libp2p supports, but the API surface is dramatically smaller — `iroh::Endpoint::connect(public_key)` is the entire dial path.

**Dependency tree.** Tenzro's `tenzro-network` pulls in ~150 transitive crates via libp2p (gossipsub + kad + identify + ping + relay + dcutr + autonat + noise + yamux + quic + tcp + dns). Iroh's transitive dep count is ~40. The compile-time and binary-size difference is non-trivial for thin client deployments (CLI, desktop app, mobile SDK).

**When Iroh fits.** Single-tenant agent-to-agent direct connect — e.g. a Tenzro CLI in one home connecting to a Tenzro agent in another home for a one-off inference, without needing the full gossip mesh. Or a desktop wallet talking to a single RPC node by node-id rather than IP. The dial-by-public-key model collapses three steps (find IP via DNS, dial IP, authenticate peer) into one (dial the public key, the library handles discovery and authentication transparently).

**When libp2p still wins.** Full p2p mesh with structured topic-based pubsub, large peer counts (Tenzro's 200/200 cap is in libp2p's comfort zone, well above Iroh-Gossip's design center), Kademlia DHT for structured content routing, mature peer-scoring (libp2p-gossipsub's scoring is years more battle-tested than iroh-gossip's), and the integration surface with the broader IPFS/IPNI/Filecoin ecosystem. Validators in a BFT consensus mesh fit libp2p; an agent dialing one peer for one query fits Iroh.

**Implication for Tenzro.** The CLI, desktop app, and TypeScript SDK do not need the full libp2p stack to talk to a Tenzro node — they already use plain HTTP/JSON-RPC against `rpc.tenzro.network`. Iroh becomes interesting when agent-to-agent direct connect (A2A protocol traffic, MCP tool calls) wants to bypass the gateway entirely and go peer-to-peer. The A2A spec is HTTP-shaped today, but a future `a2a-over-iroh` transport binding would be a single afternoon of work on top of `iroh-blobs`. Not Phase 1; worth tracking.

---

## 1.6 Production Case Studies — What BFT Chains Actually Use

Tenzro's HotStuff-2 currently sends vote messages over the `tenzro/consensus` gossipsub topic. Every other production BFT chain in 2026 has moved (or is moving) consensus-critical traffic *off* gossipsub. The pattern is consistent enough that it warrants direct attention.

**Aptos — AptosNet (custom).** Aptos does not use libp2p at all. The networking layer is a bespoke stack called AptosNet: TCP transport, NoiseIK for authentication and encryption, a custom handshake protocol for version + application-protocol negotiation. Two application protocols on top: `DirectSend` (fire-and-forget) and `RPC` (unary request-response). Architecture is actor-model with `PeerManager` / `Peer` / `ConnectivityManager` / `HealthChecker` actors and a `validator-set-discovery` component that reads the on-chain validator set and maintains an at-most-one-connection-per-peer overlay. Vote messages flow on `DirectSend`, not on a gossip mesh. Aptos's reasoning (documented in their multi-region benchmark repo): with at most a few hundred validators in the consensus set, every-to-every direct connections are tractable and dramatically reduce vote-propagation tail latency — no GRAFT/PRUNE churn, no mesh-degradation failure mode.

**Sui — Mysticeti DAG.** Sui's consensus is Mysticeti, a multi-leader DAG-based BFT consensus that commits within three message exchanges (the NDSS 2025 paper, IACR ePrint 2024/995). Validator-to-validator messaging is direct: each validator maintains a TLS connection to every other validator and pushes blocks/votes over those connections. No gossip. Sui's networking stack is `anemo`, an in-house RPC library over QUIC — similar in spirit to AptosNet (direct overlay, validator-set-driven peering) but on QUIC rather than TCP+Noise. Mysticeti's DAG structure tolerates message loss gracefully; the overlay does not need ack-perfect delivery, only steady-state high bandwidth.

**Monad — single-region multi-zone.** MonadBFT (arXiv:2502.20692) is a pipelined HotStuff variant achieving 10k+ TPS on EVM-compatible execution. Validator overlay is also direct-connect — Monad explicitly contrasts itself with chains that route consensus through gossip, citing the same mesh-degradation concerns. Topology is single-region multi-zone in production (East US testnet across three AWS AZs); cross-region was deferred because the BFT timeout budget at 200ms+ inter-region p99 latency is unworkable without buffer increases that hurt throughput.

**Solana Alpenglow / Votor (SIMD-0326).** Solana's Tower BFT historically piggybacked validator votes on the regular gossip transaction layer (`Pubsub`-style). Alpenglow / Votor moves vote messages *off* gossip onto a direct-broadcast overlay: each validator sends each vote directly to every other validator, not through the mesh. The SIMD-0326 design doc explicitly cites bandwidth and finality-latency improvements as motivation — gossip's redundant fan-out wastes inter-validator bandwidth at Solana's scale (>1000 validators), and direct broadcast halves time-to-2/3-vote-quorum. Alpenglow targets sub-1-second finality, down from Tower BFT's ~12.8s pre-confirmation.

**Lighthouse and other Ethereum CL clients.** Worth noting as a counterexample: Ethereum consensus-layer clients (Lighthouse, Prysm, Teku, Nimbus, Lodestar) *do* use libp2p gossipsub for attestations and block proposals, with topic-per-subnet sharding (`beacon_attestation_*`, `sync_committee_*`) to keep fan-out tractable. The trade-off Ethereum accepts: gossipsub's redundant fan-out costs bandwidth, but the >1M-validator set is far too large for every-to-every direct overlay. Tenzro's validator count is bounded by stake economics in the hundreds-to-thousands range, sitting between Aptos/Sui scale (≤100s, direct overlay wins) and Ethereum scale (>1M, sharded gossipsub wins). The right call depends on where the validator set lands — Phase 1 fewer-than-50 validators is firmly in Aptos territory.

**The pattern.** Four independent BFT systems — Aptos (AptosNet), Sui (anemo), Monad (custom), Solana (Alpenglow) — all converged on the same structural choice: BFT vote messages belong on a validator-only direct-connect overlay, *not* on a public gossipsub mesh. The reasons are consistent: gossipsub's redundant fan-out wastes bandwidth at scale, mesh degradation under quiet links is invisible and unrecoverable without explicit re-graft, and the topology of "every validator must hear every vote" is not what gossipsub was designed for (gossipsub assumes message originators are a small subset of subscribers, but in BFT *every* validator originates *every* vote). Gossipsub remains the right tool for *block* propagation (one originator per block, fan-out to all) and for *transaction* propagation (many originators, many subscribers, redundant paths are useful). It is the wrong tool for *vote* propagation.

---

## 1.7 Tenzro-Specific Implications

**Already shipped.** Two patches landed in `tenzro-network` on 2026-05-14:

1. `NetworkConfig::default().connection_idle_timeout = Duration::from_secs(600)`. Overrides the rust-libp2p `Duration::ZERO` default. The doc comment in `config.rs` cites the two compounding causes from `project_consensus_stall_root_cause_2026_05_14.md`: rust-libp2p's silent close-on-idle and GCE's 10-min silent conntrack eviction. Without this override, validator-to-validator mesh degrades from N-1 → 0-4 peers within an hour on multi-region cloud topologies.
2. `identify::Config::with_hide_listen_addrs(true)` plus the new `NetworkConfig.external_addresses` field. Combined, this stops Identify from broadcasting `docker0` (172.17.0.1) and CNI overlay addresses to peers. Cloud validators with static public IPs configure `external_addresses` from Terraform output; community joiners behind NAT leave it empty and rely on AutoNAT v2 to publish a confirmed address.

Other already-shipped pieces: `ConnectionLimits` at 200/200 (against `GHSA-jvgw-gccv-q5p8`); QUIC + TCP dual-listen on port 9000; Ethereum-class 700ms gossipsub heartbeat; mDNS disabled in production (LAN-presence leak), enabled only in `NetworkConfig::local()`.

**Open question — validator-only direct-connect overlay for HotStuff-2 votes.** The four-chain pattern in §1.6 is unanimous: BFT votes should not ride gossipsub. Tenzro currently does. The migration path:

- *Phase 1 (status quo):* `tenzro/consensus` topic on gossipsub. Acceptable at ≤10 validators because the mesh is small enough that all-to-all-via-gossip approximates direct-connect bandwidth. Sufficient for 2026 testnet.
- *Phase 2 option A:* Add `gossipsub::Config.direct_peers` for all N-1 other validators on the consensus topic. This is the cheapest intervention — gossipsub treats direct peers as a guaranteed mesh member with no GRAFT/PRUNE churn — and it captures most of the win without rewriting the transport layer. Already in the remediation playbook from the 2026-05-14 stall postmortem.
- *Phase 2 option B:* Build a `tenzro_consensus_direct` libp2p protocol — request-response pattern, not gossip, opened on every pair of validators at validator-set boot. Vote messages dispatch over direct streams; block proposals continue over gossipsub. Aptos's DirectSend pattern adapted to libp2p instead of bespoke transport.
- *Phase 3:* If Phase 2 still hits limits at >100 validators, the case for a custom non-libp2p overlay (AptosNet-style) becomes serious. Until then, the libp2p surface is sufficient because `direct_peers` and a request-response protocol both fit within it.

The right choice for Tenzro 2026 is Phase 2 option A — direct_peers configured at validator-set boot, no transport rewrite, captures the Aptos/Sui win at minimal cost. Option B (a dedicated direct-connect protocol) is worth the engineering investment once the validator count exceeds ~30 and gossipsub fan-out starts wasting measurable bandwidth.

**The GCE consensus stall lesson, generalized.** The 2026-05-14 multi-region stall (`project_consensus_stall_root_cause_2026_05_14.md`) was not a one-off. The two underlying bugs — rust-libp2p's `idle_connection_timeout=0` default and cloud-fabric silent conntrack eviction — stack on every cloud BFT deployment unless explicitly defused. The pattern repeats on AWS (conntrack TTL varies by VPC config but is bounded), on Azure (60-minute default but tunable per NSG), on bare-metal datacenters with intermediate stateful firewalls. The fix is the same everywhere: libp2p `idle_connection_timeout >= max(cloud_conntrack_ttl, kernel_keepalive_interval * 5)` plus host-level TCP keepalive tuning under the conntrack TTL. Tenzro's `crates/tenzro-network/src/config.rs` comment is the canonical reference inside the codebase; this doc is the canonical external reference.

---

## Section 1 — Sources

### rust-libp2p
- [rust-libp2p GitHub](https://github.com/libp2p/rust-libp2p)
- [Issue #4912 — improve default idle_connection_timeout](https://github.com/libp2p/rust-libp2p/issues/4912)
- [PR #4967 — set idle_connection_timeout default](https://github.com/libp2p/rust-libp2p/pull/4967)
- [Discussion #5153 — gossipsub mesh degradation](https://github.com/libp2p/rust-libp2p/discussions/5153)
- [Discussion #4837 — InsufficientPeers under idle](https://github.com/libp2p/rust-libp2p/discussions/4837)
- [Discussion #5696 — gossipsub mesh churn](https://github.com/libp2p/rust-libp2p/discussions/5696)
- [rust-libp2p v0.53 release notes](https://github.com/libp2p/rust-libp2p/releases/tag/libp2p-v0.53.0)
- [rust-libp2p v0.56 release notes](https://github.com/libp2p/rust-libp2p/releases/tag/libp2p-v0.56.0)
- [GHSA-jvgw-gccv-q5p8 — unbounded connection handler advisory](https://github.com/libp2p/rust-libp2p/security/advisories/GHSA-jvgw-gccv-q5p8)

### gossipsub + kad
- [gossipsub v1.1 spec](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md)
- [Kademlia DHT spec](https://github.com/libp2p/specs/tree/master/kad-dht)
- [S/Kademlia paper](https://www.cl.cam.ac.uk/teaching/0910/AdvSysTop/SKademlia.pdf)
- [Lighthouse target peer count PR #3005](https://github.com/sigp/lighthouse/pull/3005)

### NAT traversal
- [AutoNAT v2 spec](https://github.com/libp2p/specs/blob/master/autonat/autonat-v2.md)
- [Circuit Relay v2 spec](https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md)
- [DCUtR spec](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md)
- [Protocol Labs Research — Decentralized Hole Punching Effectiveness (2022)](https://research.protocol.ai/blog/2022/decentralized-hole-punching-effectiveness/)

### QUIC + post-quantum TLS
- [libp2p QUIC transport spec](https://github.com/libp2p/specs/tree/master/quic)
- [draft-kwiatkowski-tls-ecdhe-mlkem (X25519MLKEM768 codepoint)](https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/)
- [draft-ietf-tls-hybrid-design-16](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
- [BoringSSL X25519MLKEM768 commit history](https://boringssl.googlesource.com/boringssl/)
- [OpenSSL 3.5 release notes (X25519MLKEM768)](https://github.com/openssl/openssl/blob/master/CHANGES.md)
- [rustls-post-quantum crate](https://crates.io/crates/rustls-post-quantum)
- [Cloudflare — Post-quantum TLS deployment](https://blog.cloudflare.com/post-quantum-for-all/)
- [Chrome M124 — X25519MLKEM768 enabled by default](https://blog.chromium.org/2024/05/advancing-our-amazing-bet-on-asymmetric.html)

### Content routing — Bitswap, IPNI, Trustless Gateway
- [Bitswap 1.2.0 spec (want-have / want-block)](https://github.com/ipfs/specs/blob/main/BITSWAP.md)
- [IPNI documentation](https://docs.ipni.io/)
- [Storetheindex (IPNI implementation)](https://github.com/ipni/storetheindex)
- [Trustless Gateway specification](https://specs.ipfs.tech/http-gateways/trustless-gateway/)
- [Filecoin Saturn](https://saturn.tech/)
- [helia (browser IPFS client)](https://github.com/ipfs/helia)

### Iroh
- [Iroh GitHub (n0-computer)](https://github.com/n0-computer/iroh)
- [Iroh documentation](https://www.iroh.computer/docs)
- [iroh-blobs](https://github.com/n0-computer/iroh-blobs)
- [iroh-gossip](https://github.com/n0-computer/iroh-gossip)
- [pkarr (Public-Key Addressable Resource Records)](https://github.com/pubky/pkarr)

### BFT validator overlays
- [AptosNet networking documentation](https://github.com/aptos-labs/aptos-core/tree/main/network)
- [Aptos multi-region benchmark](https://github.com/aptos-labs/aptos-multi-region-bench)
- [Mysticeti paper (IACR ePrint 2024/995)](https://eprint.iacr.org/2024/995)
- [Sui anemo (RPC over QUIC)](https://github.com/MystenLabs/sui/tree/main/crates/anemo)
- [MonadBFT paper (arXiv:2502.20692)](https://arxiv.org/abs/2502.20692)
- [Solana SIMD-0326 — Alpenglow / Votor](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0326-alpenglow.md)

### Operational context
- [Kubernetes #32457 — GCP 10-min conntrack idle eviction](https://github.com/kubernetes/kubernetes/issues/32457)
- [GCP VPC troubleshooting — idle connection drops](https://cloud.google.com/vpc/docs/connection-tracking)

# Section 2: Decentralized Data Layers and Content Addressing — Prior Art (2026)

Source survey for Tenzro's data-availability and content-addressing strategy. Tenzro's `tenzro-storage` already ships a `da/` module with a `DaBackend` trait and a `ReceiptEnvelope { Inline | OffloadedDA }` shape; the open question is which production DA backend(s) to integrate first and how the off-chain payload model relates to existing IPLD/Arrow/Lance ecosystems. Each subsection cites canonical references; do not paraphrase from memory beyond what's documented here.

---

## 2.1 IPLD + DAG-CBOR + CIDs in 2026

IPLD (InterPlanetary Linked Data) is the addressable data model behind IPFS, Filecoin, Ceramic, and AT Protocol. The model is unchanged at the spec layer since 2022: a content-addressed DAG where every node is identified by a self-describing CID. The pieces:

- **CID** — `<multibase-prefix><cid-version><multicodec><multihash>`. CIDv0 is the legacy `Qm…` base58btc-encoded SHA-256-only form (multicodec implicitly `dag-pb`). CIDv1 is the current form — a binary tuple prefixed by a multicodec indicating the content type and a multihash carrying the digest plus its function identifier. CIDv1 in base32 lowercase (`bafy…`) is the dominant on-wire shape since 2023.
- **Multicodec** — the registry of content type tags. `dag-cbor = 0x71`, `dag-pb = 0x70`, `dag-json = 0x0129`, `raw = 0x55`, `libp2p-key = 0x72`. Adding new codecs is open via the `multiformats/multicodec` table.
- **Multihash** — a hash function tag + digest length + digest. SHA-256 (`0x12`), BLAKE3 (`0x1e`), Keccak-256 (`0x1b`) coexist on the same wire format.
- **DAG-CBOR** — canonical CBOR (RFC 8949) restricted so that the same logical object hashes to the same bytes everywhere: tag 42 is the *only* CBOR tag and is interpreted as a CID; map keys must be strings and lex-sorted by their major-type+length+content byte sequence; integers and lengths must use the shortest valid encoding; floats are discouraged. This determinism is what makes DAG-CBOR a viable commitment format — a node's CID is a function of the bytes alone, not of the encoder.

**Production usage in 2026:**

- **Filecoin** is built on IPLD top to bottom — every block, every piece, every actor state in the FVM is an IPLD DAG. The Filecoin spec formalizes IPLD as a first-class subsystem.
- **AT Protocol (Bluesky)** uses DAG-CBOR for repository records and signed commits. Each PDS (personal data server) stores user data as a Merkle Search Tree of DAG-CBOR records; the commit object is a signed DAG-CBOR blob whose CID is the repo head. Bulk export uses the CAR (Content Addressable aRchive) format — a concatenation of length-prefixed DAG-CBOR blocks plus a header listing root CIDs.
- **Ceramic / ceramic-one** persists stream events as IPLD DAGs. `js-ceramic` and ComposeDB are slated for deprecation in favor of `ceramic-one`, but the IPLD model underneath is preserved.
- **Nostr** intentionally does *not* use CIDs — events are identified by `id = sha256(canonical_json_serialization(event))` per NIP-01. The protocol is content-addressed in spirit but uses a hand-rolled JSON canonicalization rather than the multihash/multicodec stack.

**Relationship to blockchain commitments.** IPLD's CID is a self-describing commitment scheme: the hash function is in-band, the codec is in-band, the digest is the cryptographic anchor. A blockchain that records a CID on-chain commits to *both* the content and the rules by which the content was hashed. This is structurally identical to Tenzro's `compute_zk_commitment(circuit_id, proof_bytes, public_inputs) = SHA-256(circuit_id ‖ proof_bytes ‖ Σ len_le(pi) ‖ pi)` — domain-tagged, deterministic, function-fingerprinted. The IPLD stack provides a 90% solution for any off-chain payload Tenzro wants to anchor on-chain; the remaining 10% is policy (where the payload lives, who serves it, how it's paid for).

**What "self-describing" buys you operationally.** A bare 32-byte hash on-chain is opaque — to verify, the consumer has to know out-of-band that it was `SHA-256(canonical_bytes)`, what the canonicalization rules were, and what content format to expect. A CID carries all three: change the hash function (SHA-256 → BLAKE3) and the CID's multihash tag changes, so old and new commitments don't collide even if a downstream consumer is unaware of the upgrade. This matters most for protocol-evolution windows. Tenzro's domain-tagged SHA-256 pattern (`SHA-256("tenzro/7683/order" || …)`, `SHA-256("tenzro/escrow/id" || …)`) achieves the same goal differently — domain separation by prefix rather than by self-description.

## 2.2 Bitswap + Trustless Gateways

The historic IPFS retrieval protocol is **Bitswap** — a libp2p protocol where peers exchange `want-have` and `want-block` messages, building per-session graphs of who has what. Modern Bitswap (2024+ boxo implementation) is session-based: a session opens, the requestor learns which peers have which blocks via `want-have`, then fetches blocks via `want-block`. Latency is the persistent weakness: a cold session in a sparsely-replicated DHT can take 5–15 seconds to find a provider, and per-block round trips dominate when fetching large DAGs.

The path of least resistance for production traffic in 2025–26 is the **Trustless HTTP Gateway**:

- **Path Gateway Spec** — the original HTTP gateway interface (`/ipfs/{cid}/{path}`) returning rendered content. Verifiable only if the requestor re-hashes; trusted in practice.
- **Trustless Gateway Spec** — HTTP gateway returning CAR-format responses (one or more IPLD blocks in a verifiable CAR file) or raw block bytes. Client re-verifies every byte against the CID. Authored by Henrique Dias, Marcin Rataj, Héctor Sanjuán, and Adin Schmahmann; current spec was updated 2026-03-05.
- **IPIP-0402** — adds partial-CAR support: a client can request a CAR with predefined export scopes (block, entity, all) and byte ranges, getting a verifiable response that's a small fraction of the full DAG.

**boxo** is the canonical Go implementation library (formerly `go-ipfs`'s reusable pieces, now a standalone library); **Helia** is the canonical JS implementation; **Rainbow** is a standalone trustless gateway server built on boxo. Helia's `@helia/verified-fetch` and the IPFS Service Worker Gateway both speak the Trustless spec end-to-end.

**Production providers (2026):**

- **Saturn** (Filecoin's decentralized CDN, 1 TB minimum per node, IPFS-content-addressed, verifiable, every response is a Trustless Gateway response). Saturn is the L1 cache layer; Project Rhea is the orchestration tier above it.
- **Storacha** (the rename of web3.storage, June 2024). Marketed as "decentralized hot storage" with UCAN-based capability delegation; storage is on Filecoin, retrieval is via Saturn/HTTP. Storacha allows Filecoin storage providers to also run as Storacha nodes serving unsealed data with low retrieval latency.
- **Pinata**, **Fleek**, **w3s.link** — centralized commercial gateway operators with global anycast. Pinata pins on its own infra; Fleek runs a managed IPFS + hosting platform; `w3s.link` is the gateway endpoint for content uploaded via Storacha. None are trustless by default but all can be queried in trustless mode by requesting `Accept: application/vnd.ipld.car`.

The shift from "Bitswap-as-default" to "HTTP-gateway-as-default" is the practical reality: agents don't run libp2p clients, they run `fetch()`. Tenzro's Data MCP (§4) should treat trustless HTTP gateways as the assumed retrieval surface and Bitswap as an optional optimization for peers that natively speak libp2p — which `tenzro-network` does.

**Latency profile in production.** A warm trustless-gateway response from Saturn for a sub-MB block lands in 50–200 ms; cold (gateway has to fetch from a Filecoin SP or another peer) is 500 ms – 5 s. Bitswap cold-session latency from a public IPFS node ranges 2 s – 30 s depending on DHT health and routing-V1 cache state. The takeaway: HTTP gateways amortize the libp2p cost across operator-side connection pools, which is exactly why agents — short-lived processes that don't keep DHT state — are better served by gateways.

## 2.3 Filecoin + FVM + storage market in 2026

Filecoin remains the largest decentralized cold-storage market (~25 EiB committed capacity as of Q2 2025 per Messari). Two FIPs from 2025 reshape provider economics:

- **FIP-0100** — removed the batch balancer and gas constraints from the sealing pipeline; replaced the prior batch mechanism with a daily per-sector fee. Reduced onboarding gas costs by up to 30% and removed batch-size limits. Passed earlier in 2025.
- **FIP-0086** and the related **FIP-0081 / FIP-0097** restructured the daily fee curve and the unsealed-copy incentives that feed retrieval. (Filecoin Foundation's 2025 Year-in-Review and Q2 Messari report are the consolidated source.)

**FVM (Filecoin Virtual Machine)** is an EVM-bytecode-compatible contract environment running native on the Filecoin chain. Over 5,000 FVM smart contracts were deployed by end-2025; the dominant use cases are deal-flow automation (`Storage Deals`, `Storage Providers Markets`, `Retrieval Pix`), DataDAOs, and tokenized data-onboarding flows. The FVM is not a high-throughput contract chain — it's a *coordination plane* for the storage market.

**Retrieval markets — split between cold and hot:**

- **Cold archival** lives in Filecoin storage deals. Verified deals via **Filecoin Plus / Fil+** get 10× quality-adjusted-power multiplier; DataCap is allocated by notaries to clients with real datasets. Retrieval from a sealed sector takes minutes-to-hours.
- **Hot retrieval** lives in **Saturn** (CDN-style L1 caching of unsealed Filecoin content, queried via trustless HTTP gateway) and **Storacha** (commercial hot tier, billed in $/GB). Filecoin Onchain Cloud, slated for early-2026 mainnet, formalizes this split — paid hot retrieval as a first-class on-chain product.

**The pragmatic split for any system that uses Filecoin:** *Filecoin = cold archival commitment; Saturn or Storacha = retrieval.* Writing directly against Filecoin for hot reads is a misuse of the protocol. Storacha's UCAN-spaces model (capability-delegated buckets) is the closest analogue to a "tenant" abstraction Tenzro would need.

**Cost shape.** Verified Fil+ deals are effectively subsidized — storage providers earn a 10× quality-adjusted-power multiplier for accepting them, so the marginal $/GB-year for the client approaches zero (the SP's revenue comes from block rewards, not the client). Unverified deals are negotiated bilaterally and historically clear at $0.0001–$0.001/GB-year. Saturn retrieval is currently free at the protocol level (operators earn FIL block rewards for serving). Storacha is the paid commercial tier — pricing tracks AWS S3 standard for hot reads, with the durability story being Filecoin-backed rather than S3-backed.

## 2.4 EigenDA + Celestia + Avail — DA layers for rollups

A "data-availability (DA) layer" is not the same as a storage network. DA layers guarantee that the bytes of a rollup block have been *published* to enough places that any honest party can reconstruct them, for a bounded time window (days to weeks), with cryptographic proofs of publication. They don't archive forever; they don't replace Filecoin.

### EigenDA (V2, mainnet 2025-07)

EigenDA V2 launched on Ethereum mainnet July 2025 at **100 MB/s** throughput, with peaks observed at 124 MB/s in 60-hour live tests. Average latency is 5 s; p99 is 10 s. The disperser sidecar erasure-encodes each blob into chunks, generates a **KZG commitment** plus per-chunk multi-reveal proofs, and disperses chunks to EigenDA operators who sign BLS attestations that they hold their assigned chunk. Operators are EigenLayer-restaked ETH/LSTs; the security guarantee is "if 2/3 of restaked stake says the blob is available, it's available, or the malicious operators get slashed." Major production consumers include Fuel Network and Aevo.

The model is **proof-of-custody-via-restaking** — there is no on-chain erasure-coding verification; the security flows from the slashing graph, not from sampling.

### Celestia (NMT + DAS, Blobstream bridge)

Celestia uses a different model. Block data is laid out in a `k × k` square of shares, then erasure-coded into a `2k × 2k` extended data square (EDS). For each row and each column of the EDS, a **Namespaced Merkle Tree (NMT)** is built; row roots and column roots are committed in the block header. Light clients perform **Data Availability Sampling (DAS)** — they randomly request small samples from rows and columns and verify NMT proofs; if any 25% of shares can be retrieved, the full block can be reconstructed (Reed-Solomon).

Each rollup app gets its own namespace and uses NMT proofs to fetch only its own data without trusting the full node. Blockspace on Celestia Mainnet Beta is up to **8 MB per block** (governance-upgradeable). **Blobstream** is the bridge to Ethereum — a zk-proof of Celestia block headers is verified in the `zk-Blobstream` contract, exposing a `(dataRoot, height)` Merkleized commitment Ethereum L2s can use.

The model is **proof-of-availability-via-sampling** — security flows from the math of erasure-coding sampling, not from restaking.

### Avail (KZG + light-client sampling)

Avail (Polygon spin-off, mainnet 2025) uses **KZG polynomial commitments** over an extended row layout. Block producers generate a KZG commitment per row at block production; light clients sample random cells and verify against the row commitments. Throughput today is **4 MB blocks** with a roadmap to 10 GB; finality is ~20 seconds. Avail's pitch is light-client-first verification with sub-minute finality — strongest light-client UX of the three.

### Throughput comparison (mid-2026)

| Layer | Throughput | Verification model | Bridge |
|---|---|---|---|
| EigenDA V2 | 100 MB/s (peaks 124 MB/s) | BLS-signed attestation + restaking slashing | Native to Ethereum (operator set on ETH) |
| Celestia | up to 8 MB/block (governance-tunable) | NMT + Reed-Solomon DAS | Blobstream zk-proof to Ethereum |
| Avail | 4 MB/block (10 GB roadmap) | KZG polynomial commitments | Multiple bridges in flight |

How rollups consume DA today: write blob to DA, get back a commitment (KZG root or attestation), post the commitment to L1 alongside the state root, prove on L1 (or trust the bridge) that the DA layer has the bytes. Optimistic rollups need DA for the fraud-proof window; ZK-rollups need DA so anyone can reconstruct and re-prove. *Neither rollup model archives the data after the dispute window* — DA is throughput, not storage.

**Proof-of-availability vs erasure-coded fragments.** EigenDA and Avail both use KZG polynomial commitments — homomorphic commitments where you can evaluate a polynomial at random points to spot-check the data, with constant-size proofs per point. Celestia uses Reed-Solomon erasure coding plus Merkle proofs over the extended square — a different math but the same goal: reconstruct the data even if a fraction is missing. The threshold differs: Celestia's `2k × 2k` extension means any 25% of shares lets you reconstruct; EigenDA's encoding parameters are operator-set dependent; Avail targets recoverability from any 50% of cells. None of these are storage layers in the Filecoin sense — they guarantee a **time-bounded availability window**, typically days to a few weeks, depending on operator/validator persistence policies.

**Settlement consequences.** A rollup that depends on DA for fraud proofs is implicitly bounded by the DA layer's retention window. Once DA expires, the rollup can no longer be challenged — which is fine for ZK rollups (validity proved at commit time) but is a liveness constraint for optimistic rollups. Tenzro is an L1 with its own consensus, not a rollup; the DA-layer dependency profile is therefore inverted — Tenzro might *offer DA-style commitments to its own users* but doesn't *depend* on a DA layer for its own settlement.

## 2.5 Apache Arrow + columnar formats for analytics

**Apache Arrow** is the in-memory columnar format that has become the lingua franca for analytics + AI data movement. Arrow defines:

- **Arrow IPC format** — a serialization for record batches and schemas. Two flavors: the *streaming format* (length-prefixed messages, schema-then-batches) and the *file format* (random-access with a footer). Both encode the same record-batch layout.
- **Arrow Flight RPC** — a gRPC-based RPC framework streaming Arrow record batches. Methods: `Handshake`, `ListFlights`, `GetFlightInfo`, `GetSchema`, `DoGet`, `DoPut`, `DoExchange`, `ListActions`, `DoAction`. A "flight" is a logical dataset; a "ticket" is an opaque identifier the client passes to `DoGet` to fetch the bytes. Zero-copy on the receive path when the client speaks Arrow natively.
- **Arrow Flight SQL** — Flight RPC plus a Protobuf-defined SQL command set (`CommandStatementQuery`, `CommandGetTables`, `CommandPreparedStatementQuery`, etc.). SQL metadata and results travel as Arrow record batches. The protocol replaces JDBC/ODBC for high-throughput federated query.

**Production consumers:**

- **DuckDB** speaks Arrow Flight as a transport — DuckDB-over-Flight gives remote analytical query against any Arrow-Flight-serving node.
- **ClickHouse** added Arrow Flight as a native interface in 2025.
- **Polars**, **Pandas**, **PyArrow**, **PyTorch DataLoader**, **Ray Data**, **Spark** — all consume Arrow zero-copy.
- **Parquet** is the on-disk columnar format that maps cleanly to Arrow in memory (Parquet → Arrow has compiler-style straight-through codepaths in `pyarrow.parquet`).

**Why this matters for Tenzro inference providers.** TimesFM 2.5 (the timeseries foundation model in `tenzro-model`'s forecast runtime) wants `[batch, context_len]` float tensors, not JSON. Sending 4096-context-length forecast inputs as JSON-encoded arrays inside HTTP bodies is ~5× larger over the wire than Arrow IPC and forces parse-and-reallocate on the receiver. A production Tenzro forecast provider serving Arrow Flight on a sidecar port would let analytics platforms (DuckDB, Polars, Snowflake) integrate without a translation layer. The same logic applies to embedding outputs from `tenzro_textEmbed` / `tenzro_visionEmbed` — a `Float32Array[N, D]` is the only sane wire format for downstream vector-search ingestion.

**The MCP-Flight composition story.** MCP (JSON-RPC over Streamable HTTP) and Flight (Arrow over gRPC) don't compose natively — wrapping Arrow record batches as base64 inside JSON content blocks defeats the zero-copy property that's the whole point. The production pattern Section 4 of this doc lands on: MCP brokers discovery, schema, and payment; Flight (or HTTP byte-range with `Content-Type: application/vnd.apache.arrow.stream`) carries the bytes. A `forecast` MCP tool returns `{"flight_endpoint": "grpc://node:50051", "ticket": "<opaque>", "schema": {...}, "rows": N, "payment_receipt": "..."}`; the agent's analytics layer connects to Flight directly. This is the same architectural split the LayerZero MCP server (`crates/tenzro-node/src/mcp/layerzero.rs`) already uses where MCP returns calldata and the on-chain call goes through a different channel.

## 2.6 Lance + Hugging Face datasets

**Lance** is a Rust-implemented columnar file format optimized for ML workloads — random-access reads on multimodal data (images, video frames, point clouds, embeddings, audio) at ML-scale. Built by the LanceDB team; benchmarks claim 100× faster random access than Parquet for point lookups. The format versions in place: **Lance v2** added a generic columnar container shape that lets non-image modalities use the same on-disk structure with appropriate encoders. Repository: `github.com/lancedb/lance` and `github.com/lancedb/lancedb`.

**LanceDB** is the vector-database product built on Lance — embedded retrieval library (no server required), DiskANN-style ANN indexes, full-text search via tantivy, integrates with LangChain, LlamaIndex, Pandas, Polars, DuckDB, PyArrow, PyTorch. Designed for embedding-heavy workloads at the billion-vector scale; the multi-version data management lets you snapshot the dataset and re-train against an exact prior version.

**Hugging Face datasets** is the higher-level distribution layer. The HF Hub stores datasets as Parquet (default) or in-format (LeRobot, Audio, etc.); `datasets` Python library streams from HF Hub into local Arrow tables. Native support for **safetensors** as the model-weight format (and increasingly as a tensor-payload format inside datasets):

**Safetensors format** — 8-byte little-endian header length + JSON UTF-8 header + raw tensor bytes. The header is a JSON map of tensor name → `{dtype, shape, data_offsets: [start, end]}`. Zero-copy mmap loads, no pickle deserialization (no arbitrary-code execution risk), guaranteed bounded header (100 MB max), guaranteed non-overlapping data regions. Default for new HF model uploads since 2023.

**The de facto standard stack for shipping ML data and models in 2026:**

- Training data → Parquet on HF Hub (small) or Lance on object storage (large multimodal)
- Model weights → safetensors on HF Hub
- Embeddings + vector indexes → Lance (or Lance + LanceDB for served queries)

This stack is what every decentralized-training and inference project (Prime Intellect, Nous Research, Bittensor RESI subnet) interoperates with. A Tenzro provider that wants to serve a foundation model has to handle safetensors as a first-class input format; one that wants to serve a dataset should accept Lance or Parquet as on-disk and Arrow IPC as on-wire.

**HF Hub's role as a content-addressed mirror.** HuggingFace Hub is a centralized Git-LFS service, but the dominant convention — `<org>/<model>/<file>` URLs, SHA-256 file hashes in the LFS pointers, immutable revisions — is content-addressing-by-policy. Decentralized-training subnets (Bittensor SN46 RESI, Prime Intellect, Nous) all anchor a SHA-256 commitment on-chain and upload the bytes to HF Hub. The pattern works because HF Hub has effectively zero failure rate at the scale where research teams need it (10k–10M downloads/model), but it remains a single point of trust. The natural Tenzro analogue is: anchor the commitment on the Tenzro Ledger; serve the bytes from a mix of HF Hub (compatibility), Filecoin/Storacha (durability), and Tenzro provider nodes (paid retrieval). `tenzro-model::HfArtifactDownloader` already speaks the HF Hub API.

## 2.7 ATProto, Nostr, Farcaster — social-graph data layers

These three protocols have all converged on "user identity + content-addressed record store + replicated transport" but made different trade-offs. They're worth studying because their replication strategies are exactly what a portable agent-profile system needs.

### AT Protocol (Bluesky)

- **Identity:** `did:plc` (PLC = Public Ledger of Credentials, a managed log) or `did:web`. DIDs resolve to DID documents listing the user's PDS (`pds.example.com`) and signing keys.
- **AT-URI:** `at://{did}/{nsid}/{rkey}` — a fully-qualified record reference, e.g. `at://did:plc:abc123/app.bsky.feed.post/3kx2…`.
- **Repository:** per-user content-addressed Merkle Search Tree (MST) of DAG-CBOR records. The repo head is a signed commit DAG-CBOR object whose CID is the repo's current state.
- **Bulk export:** **CAR file** — concatenated DAG-CBOR blocks plus a header with the root CID. A user's entire repo exports as a single CAR; replication is "fetch the CAR, walk the MST, verify signatures and CIDs." This is the cleanest portable-data primitive in production.
- **Sync:** `com.atproto.sync.subscribeRepos` — a websocket firehose pushing DAG-CBOR-framed events for the whole network. Relays gossip events; PDS hosts are authoritative.

### Nostr

- **Identity:** secp256k1 keypair, hex-encoded pubkey.
- **Events:** signed JSON objects (NIP-01) keyed by `id = sha256(canonical_json_serialization)`. No CID, no DAG-CBOR — Nostr opted for hand-rolled canonical JSON.
- **Replication:** clients post events to N relays; readers query relays via REQ/CLOSE subscriptions over websockets. Relays are dumb stores — no consensus, no sync protocol; replication is the union over the relays you trust.
- **Strength:** trivial to operate a relay (any developer can stand one up in a weekend); resilient against censorship via relay diversity. **Weakness:** no merkleized commitment to a user's history; no efficient bulk export; "did I miss an event?" is unanswerable without scanning all relays.

### Farcaster

- **Identity:** **FID** (numeric, registered on Optimism via the `IdRegistry` contract). Users sign messages with an on-chain-registered signer key.
- **Hubs:** As of April 2025 with **Snapchain** mainnet, Farcaster replaced its CRDT-based eventually-consistent hub system with **Malachite BFT consensus** (Rust Tendermint implementation, originally built for Starknet). Snapchain produces ordered blocks at ~200 ms; ~200 GB snapshot, 2–4 hour cold sync.
- **Architecture:** Hubs are full nodes — storage engine (RocksDB), P2P engine (libp2p Gossipsub), sync engine (Merkle-trie reconciliation for missed gossip). State is the union of valid signed messages.
- **Trade-off:** Farcaster now looks more like a small blockchain than a "social graph" — chosen because eventually-consistent CRDT replication was producing observable divergence at scale.

### Lessons for Tenzro agent profiles

A portable Tenzro agent (`did:tenzro:machine:…`) needs a profile that's: (a) signed by the agent's DID, (b) content-addressed so a counterparty can pin a specific version, (c) cheap to replicate to new providers. The AT Protocol pattern is the cleanest fit — a per-DID repository of DAG-CBOR records exported as CAR, with the repo head signed by the agent's key. Bluesky has demonstrated this at >35M user scale; the model is proven. The Tenzro Identity Registry (`CF_IDENTITIES`, §`tenzro-identity`) already stores DID documents and credentials; the missing piece is a bulk-export shape and a Merkle commitment over the per-agent record set. Adopt CAR + MST as the export format and you inherit the entire ATProto tooling ecosystem (libraries in Go, Python, TS, Rust).

**Three patterns to avoid:**

- *Nostr's hand-rolled canonicalization* — works at small scale but is fragile when the canonicalization rules evolve; the broader IPLD ecosystem has solved this problem already.
- *Farcaster's "promote the social graph to a blockchain"* — Tenzro is already a blockchain; the right layer for per-agent profile records is application-level, not consensus-level.
- *Centralized profile services* (e.g. a single Tenzro-hosted directory) — defeats the self-sovereign property that motivated TDIP in the first place.

## 2.8 Tenzro-specific implications

### What's already in tree

`tenzro-storage::da` ships:

- `ReceiptEnvelope { kind, storage_mode, inline_summary, inline_payload, da_pointer, commitment }` — receipts are either `Inline` (payload embedded) or `OffloadedDA` (payload elsewhere with a `DaPointer { backend, namespace, locator, commitment_kzg, attestation_root }`).
- `commitment = SHA-256(canonical_payload)` always — regardless of storage mode, the cryptographic anchor is identical. This matches the IPLD CID model in spirit: the commitment is in-band on-chain; the bytes live wherever.
- `ReceiptKind::default_mode()` — Settlement, KillSwitch, Lifecycle, Governance default to `Inline`; SettlementChannel, Inference, AgentMessage default to `OffloadedDA`. The intuition: anything a validator must replay during state reconstruction is inline; anything that's per-user log data is offloaded.
- `#[async_trait] DaBackend { submit, fetch, verify_availability }`.
- `InlineFallbackBackend` — the only implementation that ships today. Refuses offload; returns a domain error if asked to submit.

This is a clean abstraction. The open question is which real backend(s) to wire in.

### Three classes of workload, three different shapes

The mental model that matters: Tenzro is not a rollup, and "DA layer" maps onto Tenzro in a specific way — *offloaded receipt storage for high-volume protocol activity that doesn't need to live inside consensus state*. The class boundaries:

### Decision criteria for the first real DA backend

The choice depends on what Tenzro is actually offloading. Three workload classes have different DA shapes:

1. **High-volume agent message / inference log retention** (per-call, ~1–100 KB, 1k–10k/s aggregate at scale). Throughput-dominated. Retention need: weeks (audit / dispute window).
2. **Per-user settlement-channel state checkpoints** (~1 KB per checkpoint, low rate). Latency-tolerant, retention need: indefinite (settlement history).
3. **Training receipt / outer-gradient archival** (Tenzro Train, MB-to-GB per `OuterGradient`, low rate). Throughput-irrelevant; retention: weeks for fraud-proof window, indefinite for reproducibility.

| Backend | Best fit | Throughput | Cost shape | API surface | Notes |
|---|---|---|---|---|---|
| **EigenDA V2** | Class 1 (agent/inference) | 100 MB/s mainnet | restaked-ETH-secured, per-MB fee on Ethereum | Disperser sidecar HTTP+gRPC; KZG commitment | Familiar to ETH ecosystem; the cleanest path if Tenzro's audience is "rollup builders." Security model = EigenLayer slashing. |
| **Celestia** | Classes 1+2 | up to 8 MB/block ≈ ~1 MB/s sustained | TIA-denominated namespace fee | Cleanest namespace API of the three (`PayForBlobs`); Blobstream bridges to Ethereum | Best DAS story; namespaces map cleanly to per-app or per-agent isolation. |
| **Avail** | Class 1, low latency | 4 MB/block, 20 s finality (10 GB roadmap) | AVAIL fee | KZG-commitment-first; light client SDK in JS/Rust | Best throughput trajectory if 10 GB target holds; bridges still maturing. |
| **Filecoin + Saturn / Storacha** | Class 3 | irrelevant — cold storage with hot retrieval CDN | $/GB-month + Fil+ DataCap subsidies for verified deals | UCAN / HTTP gateway / Filecoin deal flow | Wrong layer for hot per-message offload; right layer for long-term archival of training artifacts. Pair *with* a DA layer, not as a replacement. |

### Recommendation shape (not a decision)

The cleanest sequencing — given Tenzro is pre-alpha and `InlineFallbackBackend` is the only thing shipping — is two backends in parallel, each handling its class:

1. **Celestia adapter** behind a feature flag for Classes 1+2. Reasons: cleanest namespace API (each Tenzro use case gets its own Celestia namespace), DAS gives the strongest "anyone can verify availability without trusting validators" story for an L1 that wants to be the *settlement* layer (i.e., Tenzro nodes don't want to be re-implementing DA themselves), light-client UX matches Tenzro's existing posture of "agents are clients, not full nodes." Blobstream gives an Ethereum bridge for free if cross-chain proofs ever become a Tenzro feature.

2. **Filecoin / Storacha adapter** for Class 3 training-artifact archival. Reasons: Filecoin is the only OSS protocol with the cold-storage economics that make multi-year retention of training artifacts financially viable; Storacha gives a UCAN-spaces-based capability model that maps onto the agent-DID delegation already in `tenzro-identity`; Filecoin Plus DataCap is a real subsidy for verified open-data deals.

**Not recommended for first integration:** EigenDA (security model assumes Tenzro is a rollup consuming Ethereum; Tenzro is an independent L1 — the restaking graph would be a perpetual second-class citizen on a host chain) and Avail (Avail's bridge story is the weakest of the three for non-Polygon ecosystems; throughput advantage doesn't matter for Class 1 volumes pre-mainnet).

**The IPLD layer is independent of this decision.** Whether Tenzro adopts CIDs and DAG-CBOR for the *commitment side* (replacing or augmenting the current `SHA-256(canonical_payload)` shape) is orthogonal to which DA backend ships first. The case for adopting IPLD/CID: every existing tool in the decentralized-data ecosystem already speaks it; Tenzro receipts would natively interop with Filecoin deal flow, ATProto-style portable export, and any future IPLD-aware retrieval layer. The case against: it's an additional surface to maintain, and the current 32-byte SHA-256 commitment is sufficient for on-chain anchoring. The middle path is to expose IPLD-style CIDs as a *view* over existing `DaPointer.commitment_kzg` / `commitment` fields (multicodec-tag the existing hash) without changing the on-wire commitment shape — same bytes, addressable by any IPLD tool.

The **CAR + DAG-CBOR shape from ATProto is the right model for Tenzro's identity-export story** (§2.7) regardless of which DA backend wins. Per-agent record sets exported as CAR files, signed by the agent's DID — this is the path to portable agent profiles and the natural commitment substrate for the Identity / Reputation / Validation triad already wired through `tenzro_identity::erc8004`.

### Open questions

**Q1: Should `commitment_kzg` in `DaPointer` actually be KZG?** Today the field name suggests KZG but the implementation defaults to SHA-256. KZG commitments have homomorphic properties (random-point evaluation proofs) that SHA-256 doesn't — useful if a Tenzro DA receipt ever needs to be challenge-sampled by an off-chain verifier. If the answer is "we'll never sample, we just need a binding commitment," rename to `commitment` (plain) and drop the KZG-shaped affordance. If the answer is "we might, when DA backends with KZG support are integrated," keep the field and document that it's KZG-when-the-backend-supports-it, SHA-256 otherwise (with a multicodec-style tag distinguishing them).

**Q2: How long is "DA"?** EigenDA, Celestia, Avail all guarantee availability for days-to-weeks, not years. If a Tenzro Inference receipt needs to be auditable a year later for compliance reasons, DA alone is insufficient — the payload has to land in Filecoin (or equivalent cold storage) as a second leg. `DaBackend` should compose: an outer backend writes to DA-for-replay (Celestia, EigenDA) and an inner backend writes to cold archival (Filecoin) with both pointers in the same `DaPointer`. The `attestation_root` field already accommodates one external commitment; a second field would carry the cold-storage CID.

**Q3: Native Tenzro DA, or just consume someone else's?** A long-tail option: Tenzro validators sign attestations over inference / agent-message payloads (because they already gossipsub them through `tenzro/inference` and `tenzro/agents`), and "DA" becomes "the set of validators willing to vouch they saw the bytes." This is structurally what EigenDA does, just with TNZO-restaked validators instead of ETH-restaked operators. The pitch: zero cross-chain dependency, native to the Tenzro economic loop. The cost: building DA-grade replication and erasure coding from scratch, against teams that have years of head start. *Probably not Phase 1.* If pursued, it's a Phase 3+ workstream after the Celestia/Filecoin path is in production and the demand profile is known.

---

## Section 2 — Sources

### IPLD / CID / DAG-CBOR
- [IPLD DAG-CBOR Specification](https://ipld.io/specs/codecs/dag-cbor/spec/)
- [IPLD DAG-CBOR Codec Docs](https://ipld.io/docs/codecs/known/dag-cbor/)
- [IPLD CARv1 Specification](https://ipld.io/specs/transport/car/carv1/)
- [Multiformats CID Specification](https://github.com/multiformats/cid)
- [IPLD CID Spec (ipld/specs)](https://github.com/ipld/specs/blob/master/block-layer/CID.md)
- [Content Identifiers (CIDs) — IPFS Docs](https://docs.ipfs.tech/concepts/content-addressing/)
- [Multicodec table (multiformats/multicodec)](https://github.com/multiformats/multicodec)
- [CBOR — RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)
- [Filecoin Spec — IPLD](https://spec.filecoin.io/libraries/ipld/)

### Bitswap / Trustless Gateway / boxo / Helia
- [IPFS Trustless Gateway Specification](https://specs.ipfs.tech/http-gateways/trustless-gateway/)
- [IPFS Path Gateway Specification](https://specs.ipfs.tech/http-gateways/path-gateway/)
- [IPIP-0402: Partial CAR Support on Trustless Gateways](https://specs.ipfs.tech/ipips/ipip-0402/)
- [IPFS gateway-conformance test suite](https://github.com/ipfs/gateway-conformance)
- [Helia HTTP Gateway](https://github.com/ipfs/helia-http-gateway)
- [IPFS Service Worker Gateway](https://github.com/ipfs/service-worker-gateway)
- [Shipyard 2025: Bringing IPFS Home (year in review)](https://ipshipyard.com/blog/2025-shipyard-ipfs-year-in-review/)

### Filecoin / FVM / Saturn / Storacha
- [Filecoin Saturn — Web3 CDN](https://saturn.tech/)
- [Filecoin Saturn — Docs](https://docs.filecoin.io/basics/how-retrieval-works/saturn)
- [Filecoin Saturn L1 Node (GitHub)](https://github.com/filecoin-saturn/L1-node)
- [Introducing Storacha — Filecoin blog](https://filecoin.io/blog/posts/introducing-storacha---the-future-of-hot-decentralized-data/)
- [Storacha Network](https://storacha.network/)
- [Storacha Documentation](https://docs.storacha.network/)
- [Filecoin in 2025: Year in Review](https://filecoin.io/blog/posts/filecoin-in-2025-year-in-review/)
- [State of Filecoin Q2 2025 — Messari](https://messari.io/report/state-of-filecoin-q2-2025)
- [Filecoin Foundation — Fresh From FF December 2025](https://fil.org/blog/fresh-from-ff-december-2025)

### EigenDA
- [Introducing EigenDA V2 on Mainnet at 100 MB/s](https://blog.eigencloud.xyz/introducing-eigenda-v2-on-mainnet-at-100-mb-s/)
- [EigenDA V2: Core Architecture](https://blog.eigencloud.xyz/eigenda-v2-core-architecture/)
- [EigenDA Overview — EigenCloud Docs](https://docs.eigencloud.xyz/eigenda/core-concepts/overview)
- [eigenda-proxy GitHub](https://github.com/Layr-Labs/eigenda-proxy)
- [EigenDA Blob Lifecycle — L2BEAT](https://docs.l2beat.com/code_walkthroughs/dalayers/eigenda/blob_lifecycle.html)

### Celestia
- [Celestia Data Availability Layer Docs](https://docs.celestia.org/learn/how-celestia-works/data-availability-layer)
- [Celestia DA layer (101)](https://docs.celestia.org/learn/celestia-101/data-availability/)
- [Blobstream — Streaming DA to Ethereum](https://blog.celestia.org/introducing-blobstream/)
- [Blobstream Docs](https://docs.celestia.org/learn/blobstream/)

### Avail
- [Avail DA — Project Page](https://availproject.org/da)
- [Choosing a Data Availability Layer — Avail blog](https://blog.availproject.org/a-guide-to-selecting-the-right-data-availability-layer/)

### Apache Arrow / Flight / Flight SQL
- [Arrow Flight RPC](https://arrow.apache.org/docs/format/Flight.html)
- [Arrow Flight SQL](https://arrow.apache.org/docs/format/FlightSql.html)
- [Arrow Columnar Format](https://arrow.apache.org/docs/format/Columnar.html)
- [Arrow IPC Format](https://arrow.apache.org/docs/format/Columnar.html#serialization-and-interprocess-communication-ipc)
- [Apache Parquet Format](https://parquet.apache.org/docs/file-format/)

### Lance / LanceDB / Hugging Face / Safetensors
- [LanceDB — AI-Native Multimodal Lakehouse](https://www.lancedb.com/)
- [LanceDB GitHub](https://github.com/lancedb/lancedb)
- [Lance Columnar Format GitHub](https://github.com/lancedb/lance)
- [Lance v2 — A New Columnar Container Format](https://www.lancedb.com/blog/lance-v2)
- [Hugging Face Safetensors Docs](https://huggingface.co/docs/safetensors/index)
- [Safetensors GitHub](https://github.com/huggingface/safetensors)
- [Safetensors security audit — HF blog](https://huggingface.co/blog/safetensors-security-audit)
- [Hugging Face datasets library](https://huggingface.co/docs/datasets/index)

### AT Protocol (Bluesky)
- [AT Protocol — Repository Spec](https://atproto.com/specs/repository)
- [AT Protocol — Data Model](https://atproto.com/specs/data-model)
- [AT Protocol GitHub](https://github.com/bluesky-social/atproto)
- [Bluesky — Download and Parse Repository Exports](https://docs.bsky.app/blog/repo-export)

### Nostr
- [NIP-01 — Basic Protocol Flow](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [Nostr NIPs Index](https://github.com/nostr-protocol/nips)

### Farcaster
- [Farcaster Protocol Spec (GitHub)](https://github.com/farcasterxyz/protocol)
- [Farcaster Architecture Overview](https://docs.farcaster.xyz/learn/architecture/overview)
- [Farcaster in 2025: The Protocol Paradox](https://blockeden.xyz/blog/2025/10/28/farcaster-in-2025-the-protocol-paradox/)

### Ceramic
- [Ceramic — How It Works](https://ceramic.network/how-it-works)
- [Ceramic FAQ — js-ceramic / ComposeDB deprecation](https://blog.ceramic.network/faq-ceramic-network/)

# Section 3: Decentralized Compute & AI Inference Marketplaces — Prior Art (2026)

Source survey for Tenzro's ProviderManifest design. Each subsection cites canonical references; do not paraphrase from memory beyond what's documented here.

---

## 3.1 Decentralized AI Inference Networks — Production Survey

### Bittensor (post-dTAO, Q1–Q2 2025)

Dynamic TAO (dTAO) shipped 2025-02-13, replacing the centralized root-network valuation with a stake-based per-subnet market. Each block mints TAO split 41% miners / 41% validators / 18% subnet creator. Subnet count went from ~32 pre-dTAO to >100 within months. Late-2025 added "Taoflow" — emissions weighted by net TAO inflows from staking activity, not raw token price.

**Validator selection:** ≥1000 stake-weight + top-K + active participation to hold a validator permit.

**Miner ranking — Yuma Consensus:** validators submit weight vectors over miner UIDs; YC runs on-chain in Subtensor, converts weight matrices to incentive distributions, rewards validators whose evaluations agree with the stake-weighted majority (dividends), and pays miners proportionally to their consensus score.

**Provider onboarding:** A miner registers a hotkey on the subnet, receives a UID, and publishes its Axon's `IP:PORT` for validators. Subnet 46 (RESI) is the canonical pattern for ML providers — train ONNX, commit model hash on-chain, upload weights to HuggingFace, models must be committed ≥30 days before evaluation to prove no eval-set leakage. This split — **cryptographic commitment on-chain, payload off-chain via HF** — is the dominant idiom across ML subnets.

**SLA / slashing:** No protocol-level SLA. Per-subnet collateral contracts (`bactensor/collateral-contracts`, one contract per validator per subnet) let validators slash miner-staked collateral for downtime or rule violations. Slashing must cite evidence; justification URL + content hash recorded on-chain. LIUM (SN51) and ComputeHorde (SN12) use this pattern in production.

### Akash Network

Reverse-auction GPU/CPU marketplace. Tenant publishes a **Stack Definition Language (SDL)** YAML manifest (`deploy.yaml`, Docker-Compose-like); providers who match the attribute set submit bids; lowest qualified bid wins by default.

**Provider declarations:** Audited attributes (geography, hardware family, datacenter tier) gated by provider auditors who govern attribute accuracy. GPU SDL accepts optional model lists + interface (`pcie` | `sxm`). Bandwidth is declared as max ingress/egress per endpoint — ongoing enforcement work, not fully production-hardened.

**Escrow + payments:** Time-based escrow account funds the lease; provider withdraws owed funds block-by-block from the deposit. Lease closes when deposit hits zero. **Bidding requires a provider deposit** held in escrow, returned on bid CLOSED. No protocol-level slashing of providers — disputes resolved by tenant cancelling lease.

### Render Network

Originally GPU rendering; expanded to AI inference via **RNP-019** (Compute Subnet) and **RNP-021** (Dispersed AI Subnet, launched at Solana Breakpoint, December 2025). Onboards U.S.-based H100/H200/MI300X operators.

**Rewards:** (a) Availability rewards for uptime/readiness, (b) Job-based rewards tied to hardware specs + time. Payments on-chain in RENDER, fed into **Burn-Mint Equilibrium (BME)** — tokens spent on jobs are burned; emissions mint to providers; supply tracks demand.

### io.net

Aggregates underutilized GPUs (consumer + miner-class + datacenter). Worker daemon onboards providers; **Co-Staking Marketplace** (Feb 2025) lets IO holders stake alongside operators, lowering operator bond requirements while sharing rewards.

**Tokenomics — Incentive Dynamic Engine (IDE):** replaces flat inflation. Mints or burns IO based on demand + revenue signals; ≥50% of post-supplier-payment revenue burned (targeting 150M IO removed). Supplier ROI pegged in USD — payouts stable through token-price drawdowns, preventing supplier exodus. Hourly→monthly emission cadence over 20 years, capped at 800M IO supply. $20M+ annualized on-chain revenue reported.

### Aethir

Decentralized GPU cloud — 440k+ enterprise GPU containers across 200+ sites in 94 countries; H100/H200/B200/B300 inventory. $39.8M Q3 2025 revenue, $147M ARR. **Strategic Compute Reserve (ATH-SCR)** subsidizes capacity expansion. Zero-egress-fee pricing is a stated differentiator vs. hyperscalers. Provider model = "Cloud Host" cohorts onboarded periodically — heavier vetting than Akash/Render.

### Gensyn

Distributed training (not inference) protocol. Mainnet launched late 2024 with focus on multi-cluster transformer training. 2025 operational pivot: onboarding mid-tier idle datacenters. First app: **Delphi**, prediction market for ML (testnet Dec 2025, now mainnet). Targets 70–90% lower training cost than centralized clouds.

### Prime Intellect / Nous Research

Centralized orchestration of decentralized training runs. Production runs:
- **INTELLECT-1** (10B, Dec 2024) — first decentralized 10B-param model
- **INTELLECT-2** (32B RL, 2025)
- **INTELLECT-3** (106B MoE, post-trained from GLM-4.5-Air-Base, scores 90.8% AIME 2024)

Protocol exposed at `PrimeIntellect-ai/protocol` (GitHub) — peer-to-peer compute coordination. **Nous Research's DisTrO** (Distributed Training Over the Internet) reports 857× bandwidth reduction vs. naive AllReduce; **Psyche** is the on-chain coordination layer built atop DisTrO.

**Takeaway for Tenzro:** Every production decentralized-training stack in 2025–26 pairs a Rust/protocol layer with a Python (PyTorch FSDP2 + Hivemind) inner training loop. This matches Tenzro's existing `tenzro-training` (Rust) + `integrations/trainer/` (Python) split.

---

## 3.2 TEE Attestation at Consumer Scale

### Apple Private Cloud Compute (Sep 2024)

Five core security requirements: **stateless computation, enforceable guarantees, no privileged access, non-targetability, verifiable transparency**. Device-side attestation: a client iPhone refuses to send a request to a PCC node that can't cryptographically prove it runs a publicly-listed build. Hardware roots: Apple Silicon Secure Enclave + Secure Boot; keys released via **Secure Key Release (SKR)** only after code verification. Apple publishes every production image for security research — the "verifiable transparency" anchor.

**What PCC proves:** code identity + boot integrity + image is in the public log.
**What PCC doesn't prove:** correctness of inference output, freedom from side channels at the hardware vendor level, or independence from Apple's own infrastructure.

### Confidential Containers (CoCo)

CNCF sandbox project. Runtime classes for Intel TDX, AMD SEV-SNP, Intel SGX, IBM SE; remote-hypervisor path for cloud integration; generic runtime for testing without hardware. Available GA on Azure AKS for TDX + SEV-SNP; OpenShift sandboxed containers from 1.10.0+. Bare-metal CoCo went preview Q1 2025. Trust model: container memory hardware-encrypted; decryption gated by attestation of the Kata pod sandbox image.

### NVIDIA H100/H200 Confidential Computing

H100 CC mode hardware-protects code+data on the GPU; requires new firmware/microcode + CUDA driver paths. **Protected PCIe** mode shipped on HGX H100 8-GPU and HGX H200 8-GPU. Composite attestation (CPU TEE + GPU TEE, e.g., TDX + H100) is the production deployment shape; Intel Trust Authority's `ITAConnector.get_token_v2` supports the composite token. NVIDIA Secure AI GA whitepaper (WP-12554-001, Aug 2025) covers Blackwell + Hopper.

**Critical for consumer scale:** Confidential mode is **only on datacenter-class GPUs** (H100/H200/B200). RTX 4090/5090-class consumer cards do not expose CC mode. A home operator on a 4090 cannot produce a hardware attestation of confidentiality — only of provenance (driver/firmware version via standard PCIe attestation, not the CC root).

### Intel Tiber Trust Authority

Zero-trust attestation-as-a-service. Collects Quote from TEE, verifies signatures, evaluates against user policy, issues JWT attestation token. Free tier on Google Cloud Confidential VMs / Confidential Space. Multi-cloud + on-prem + edge.

### Phala Network / Marlin

**Phala** runs a decentralized TEE cloud with on-chain registration of enclave software hashes, endorsements from Intel + NVIDIA, and Dstack (developer-facing deploy toolkit). Their **Decentralized Root of Trust** uses an external on-chain KMS where trust is split across TEE nodes verified by both blockchain consensus AND remote attestation. The "Proof of Cloud Alliance" adds physical inspection + cryptographic hardware binding as a third axis.

**Marlin** delegates compute to TEE-based off-chain microservices with on-chain attestation verification. Smaller surface than Phala — focused on coprocessor patterns, not general-purpose cloud.

### Tenzro's stance for 2026

Consumer-grade TEE for inference providers is **not realistic in the home-operator tier** — the hardware isn't deployed and the firmware paths don't exist for consumer GPUs. The pragmatic split:

1. **Validators are TEE-attested** (Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA CC on H100+) — they already get 2× consensus weight in `tenzro-consensus` leader selection.
2. **Home providers are NOT TEE-attested.** They get full network access, full earning capability, but `ProviderManifest.attestation_tier` declares their evidence level (None / SoftwareAttested / VendorAttested / TeeAttested) and the routing layer can prefer higher tiers for sensitive workloads at a price premium.
3. **Inference confidentiality, when required, routes to TEE-tier providers only** — the existing `tenzro-tee` provider abstraction already handles all four major TEE vendors and the `attestation_required: bool` field on inference requests can gate this.

---

## 3.3 Eigenlayer-Style Restaking Applied to Compute

### EigenLayer AVS model

Operators delegate restaked ETH (or LSTs) to AVSs (Actively Validated Services). Slashing launched **2025-04-17**, opt-in per AVS. Each AVS allocates Unique Stake = maximum slashable amount per operator failure. TVL peaked at ~$28.6B pre-slashing, dropped to ~$7B post-launch as risk got priced in. EigenCloud rebrand (Jun 2025) reframed the protocol as "verifiable cloud." 39 active AVSs.

### Symbiotic, Karak

**Symbiotic:** permissionless restaking; arbitrary ERC-20 collateral; vaults select their own dispute resolvers (e.g., UMA-style optimistic oracle). Veto committee for erroneous slashing recovery.

**Karak:** broadest asset support (LSTs + stables + LP tokens). No published dispute mechanism for erroneous slashing.

**Operator commissions:** EigenLayer fixed 10%; Symbiotic + Karak let AVSs set their own payment structure.

### Tenzro restaking position

Tenzro validators already bond TNZO in `tenzro-token::StakingManager`. The question is whether their bond should extend to *compute-provider* duties beyond consensus.

**Phase 1 answer: no.** Reasons:
1. Slashing surface should be small and well-defined in pre-alpha. Consensus equivocation = 10% slash (already implemented via `StakingSlashingCallback`); that's enough.
2. Compute SLA failures are noisier (network blips, model OOM, GPU thermal throttle) than consensus equivocation (cryptographically provable double-sign). Conflating them either over-slashes honest operators or under-slashes real bad actors.
3. EigenLayer's post-Apr-2025 TVL drop is the lesson: when risk gets real, capital flees. Better to keep the consensus bond clean.

**Phase 2+ option:** add an *optional* `ComputeBond` separate from the consensus stake, modeled on Symbiotic's per-vault dispute-resolver pattern. Operators choose to bond extra TNZO against an SLA contract; that bond is independently slashable. **Not Phase 1.**

---

## 3.4 Provider Manifest Patterns

### Akash SDL fields
`version`, `services` (image, env, expose, command, args, params), `profiles.compute` (CPU/GPU/RAM/storage units + GPU model list + interface), `profiles.placement` (datacenter/region + audited attribute filters + signedBy auditors + pricing), `deployment` (which profile applies to which service).

### Render service tiers
Hardware-tiered (consumer / pro / datacenter). Availability vs. job-based rewards split per RNP-019. No declared bandwidth caps.

### Bittensor miner metadata
On-chain: hotkey, UID, Axon `IP:PORT`, optional commitment hash (model SHA, contract address, knowledge commitment). Off-chain: weights on HuggingFace, served via Axon endpoint.

### Proposed Tenzro `ProviderManifest` (v1)

```rust
pub struct ProviderManifest {
    // Identity
    pub provider_did: String,              // did:tenzro:machine:...
    pub operator_did: String,              // did:tenzro:human:... (controller)
    pub signed_at: Timestamp,
    pub signature: Signature,              // signed by provider_did key

    // Capacity declarations
    pub compute: ComputeCapacity {
        gpu_models: Vec<GpuSpec>,          // {family: H100, count: 8, vram_gb: 80, interface: SXM}
        cpu_cores: u32,
        ram_gb: u32,
        storage_gb: u64,
        storage_class: StorageClass,       // NVMe | SSD | HDD
    },
    pub bandwidth: BandwidthCapacity {
        ingress_mbps: u32,
        egress_mbps: u32,
        monthly_egress_cap_gb: Option<u64>, // home operators
        metered_connection: bool,
    },

    // Service offerings — what this provider sells
    pub services: Vec<ServiceOffering {
        modality: Modality,                // Chat | Forecast | Vision | TextEmbed | Segment | Detect | Transcribe | Video
        model_ids: Vec<String>,            // catalogue entries served
        max_concurrent: u32,
        max_context_tokens: Option<u32>,
        pricing: Pricing {
            unit: PricingUnit,             // PerInference | Per1kTokens | PerByte | PerSecondGpu
            price_tnzo_per_unit: u128,
        },
    }>,

    // Trust + attestation
    pub attestation_tier: AttestationTier, // None | SoftwareAttested | VendorAttested | TeeAttested
    pub tee_evidence: Option<TeeEvidence>, // Quote + cert chain when tier >= TeeAttested
    pub audited_attributes: Vec<AuditedAttribute>, // {auditor_did, attribute, signature}

    // SLA + economic commitments
    pub sla: SlaCommitment {
        uptime_target_bps: u16,            // 9900 = 99.00%
        max_latency_p50_ms: u32,
        max_latency_p99_ms: u32,
        challenge_response_window_ms: u32,
    },
    pub compute_bond_tnzo: u128,           // 0 in Phase 1 = consensus-bond-only
    pub geography: Geography {
        country_iso2: String,
        region: Option<String>,
        datacenter_id: Option<String>,
    },

    // Lifecycle
    pub expires_at: Timestamp,             // re-gossip cadence
    pub manifest_version: u32,
}
```

Gossipsub topic: `tenzro/providers` (new). Manifest signed by provider DID, verified at every relay hop. On-chain commitment: SHA-256 of canonical-serialized manifest persisted in `CF_PROVIDERS` keyed by `provider_did`. The full manifest payload stays in gossip + provider's own service endpoint (Bittensor pattern, not Akash's full on-chain storage).

---

## 3.5 Bandwidth Metering + Egress Accounting

**Akash:** declared max ingress/egress per endpoint, provider-side enforcement under development (issue #67 in `akash-network/support`). Not protocol-level metered.

**libp2p:** `BandwidthCounter` (Go) / `BandwidthLogging` (Rust) wraps Transports and counts bytes per-peer + per-protocol. Prometheus-exportable. Already present in `tenzro-network` as part of standard libp2p stack — Tenzro can read these counters today.

**Production billing models:**
- **io.net + Aethir:** zero-egress-fee pricing (provider eats egress cost, baked into per-GPU-hour rate).
- **Akash:** per-deployment lease price (fixed-rate), no per-byte settlement.
- **Bittensor:** no bandwidth accounting — miners self-bound via inference throughput limits.

**Tenzro proposal:**
- **Inference / query / agent-message:** per-event settlement via `tenzro-settlement` micropayment channels — already implemented.
- **Bulk byte transfer (model downloads, training artifact upload, DA payload offload):** per-byte settlement using libp2p `BandwidthCounter` readings, signed by both peers, settled via micropayment channel. Same channel infrastructure, different unit.
- **Metered-home-operator protection:** `monthly_egress_cap_gb` in manifest; routing layer rate-limits to honor cap; provider pauses serving when cap hit (matches io.net's stable-supplier pattern of predictable economics).

---

## 3.6 SLA Enforcement + Reputation-Bonded Slashing

**Akash:** No slashing of providers. SLA failure → tenant closes lease → escrow refunded for unconsumed time. Reputation purely off-chain.

**Bittensor:** Per-subnet collateral contracts; validators enforce SLA deterministically. Yuma Consensus is the reputation layer — miners get incentive proportional to validator weight agreement. Knowledge-commitment + 30-day pre-eval window is the anti-cheat mechanism.

**EigenLayer:** AVS-defined slashing conditions; Unique Stake caps maximum loss per failure; veto committee for erroneous slashes. Operators forfeit principal, not just rewards.

**Tenzro decision tree:**

| Failure mode | Mechanism | Penalty |
|---|---|---|
| Consensus equivocation | Already implemented (`EquivocationDetector` → `StakingSlashingCallback`) | 10% stake slash |
| Inference timeout / wrong output | `ProviderManager.record_failure()` → reputation drops -5 (vs. +1 success), saturating floor 0 | Reputation only (already implemented) |
| SLA breach (uptime, latency) | Manifest declares targets; challenges issued by validators; failed challenges decrement reputation | Reputation; loss of routing weight |
| Manifest fraud (declared H100, runs T4) | Audited-attribute holder challenges; on-chain dispute | Reputation slash + audited-attribute revocation |
| Compute-bond breach (Phase 2+) | Opt-in `compute_bond_tnzo` separate from consensus bond | Up to bonded amount, dispute via validator subcommittee |

Reputation is the primary mechanism; capital slashing is reserved for cryptographically provable violations. Matches Bittensor's "soft" Yuma penalty (lower incentive) for honest-but-low-quality miners and "hard" collateral slash for evidenced misbehavior.

**Disputes:** validator subcommittee (rotating, 7 validators chosen by VRF — already available via `0x1007` VRF precompile) arbitrates manifest-fraud and compute-bond disputes. Evidence on-chain (challenge transcript, attestation, log hash); deterministic resolution.

---

## 3.7 Open Questions for Tenzro

**Q1: Bittensor subnet vs. independent L1?**
Already independent — and correctly so. Bittensor subnets share Yuma + TAO emissions and must fit into a fixed Validator/Miner role model. Tenzro needs richer roles (Validator, ModelProvider, TeeProvider, AgentRuntime, DataProvider) and richer payment surfaces (MPP, x402, ERC-7683 cross-chain intents, Canton DvP). Subordinating to Bittensor's emission curve would constrain TNZO economics. Worth a cross-listing partnership; not worth subordination.

**Q2: EigenLayer-style restaking?**
Not Phase 1. Reasons under §3.3. Phase 2 option: optional `ComputeBond` separate from the consensus stake, Symbiotic-style per-AVS dispute resolution.

**Q3: Data provider vs. inference provider role split?**
Unify under `ProviderManifest.services[].modality` — a single provider role with declared service offerings. A "data provider" is just a provider whose service offerings are limited to byte-transfer (model artifact hosting, DA payload retrieval). Avoids combinatorial role explosion. Matches Akash's "any compute attribute" model and io.net's worker abstraction. The existing `NodeRole::ModelProvider` enum value generalizes to `ServiceProvider` covering both.

---

## Section 3 — Sources

### Bittensor
- [Yuma Consensus](https://docs.learnbittensor.org/learn/yuma-consensus)
- [Mining in Bittensor](https://docs.learnbittensor.org/miners)
- [Validating in Bittensor](https://docs.learnbittensor.org/validators)
- [Subnet Metagraph](https://docs.learnbittensor.org/subnets/metagraph)
- [The Bittensor Standard](https://bittensor.com/content/the-bittensor-standard)
- [Collateral Smart Contract for Bittensor](https://github.com/bactensor/collateral-contracts)
- [LIUM Collateral Contract docs](https://docs.lium.io/bittensor-subnet/collateral/overview)
- [Bittensor Protocol: critical & empirical analysis (arXiv 2507.02951)](https://arxiv.org/html/2507.02951v1)
- [Cruciblelabs — Bittensor Decentralized Training subnets](https://cruciblelabs.com/wp-content/uploads/2024/12/Bittensor-Decentralized-Training.pdf)

### Akash
- [Stack Definition Language (SDL)](https://docs.akash.network/readme/stack-definition-language)
- [Akash Audited Attributes](https://akash.network/docs/providers/audited-attributes/)
- [Bids and Leases](https://akash.network/docs/getting-started/intro-to-akash/bids-and-leases/)
- [Akash Escrow / Payments](https://docs.akash.network/glossary/escrow)
- [Endpoint Resource: Bandwidth Caps (issue #67)](https://github.com/akash-network/support/issues/67)
- [Messari — Understanding Akash](https://messari.io/report/understanding-akash-a-comprehensive-overview)

### Render
- [RNP-019 (Compute Subnet)](https://github.com/rendernetwork/RNPs/blob/main/RNP-019.md)
- [Render Foundation — RNP-019 explainer](https://rendernetwork.medium.com/why-rnp-019-matters-a-pivotal-expansion-for-render-network-into-general-and-ai-compute-cbabe7333e45)
- [Render — Dispersed launch](https://rendernetwork.medium.com/render-network-launches-dispersed-to-address-global-ai-compute-shortage-84a16dacde78)
- [Messari — Render Network](https://messari.io/report/understanding-the-render-network-a-comprehensive-overview)

### io.net
- [io.net tokenomics page](https://io.net/tokenomics)
- [Messari — io.net new tokenomics](https://messari.io/report/io-net-new-tokenomics-and-the-path-to-sustainable-incentives)
- [io.net $20M annualized on-chain revenue](https://io.net/blog/io-net-20m-in-annualized-on-chain-revenue)
- [Nansen Research — io.net](https://research.nansen.ai/articles/ionet-does-it-have-what-it-takes)

### Aethir
- [Aethir 2025 Wrap-Up](https://ecosystem.aethir.com/blog-posts/aethirs-2025-wrap-up-decentralized-gpu-cloud-milestones)
- [Aethir Strategic Compute Reserve](https://ecosystem.aethir.com/blog-posts/aethirs-strategic-compute-reserve-scr-to-accelerate-expansion-of-gpu-capacity-and-enterprise-compute-deals)

### Gensyn
- [Gensyn Testnet docs](https://docs.gensyn.ai/testnet)
- [Gensyn Litepaper](https://docs.gensyn.ai/litepaper)
- [Introducing Delphi](https://blog.gensyn.ai/introducing-delphi/)

### Prime Intellect / Nous
- [Prime Intellect protocol (GitHub)](https://github.com/PrimeIntellect-ai/protocol)
- [Prime Intellect — approach to decentralized training](https://www.primeintellect.ai/blog/our-approach-to-decentralized-training)
- [INTELLECT-1 technical report (arXiv 2412.01152)](https://arxiv.org/html/2412.01152v1)
- [INTELLECT-3 model card (HF)](https://huggingface.co/PrimeIntellect/INTELLECT-3)

### Apple PCC
- [Apple Security — Private Cloud Compute](https://security.apple.com/blog/private-cloud-compute/)
- [Apple Security — PCC Security Research](https://security.apple.com/blog/pcc-security-research/)
- [PCC Security Guide](https://security.apple.com/documentation/private-cloud-compute)

### Confidential Containers
- [CoCo: Introduction](https://confidentialcontainers.org/blog/2024/02/16/introduction-to-confidential-containers-coco/)
- [Red Hat — Confidential Containers on bare metal](https://developers.redhat.com/articles/2025/02/19/how-deploy-confidential-containers-bare-metal)
- [Azure AKS Confidential Containers](https://learn.microsoft.com/en-us/azure/aks/confidential-containers-overview)

### NVIDIA Confidential Computing
- [NVIDIA Technical Blog — Confidential Computing on H100](https://developer.nvidia.com/blog/confidential-computing-on-h100-gpus-for-secure-and-trustworthy-ai/)
- [NVIDIA Secure AI GA](https://developer.nvidia.com/blog/announcing-nvidia-secure-ai-general-availability/)
- [NVIDIA Secure AI Blackwell + Hopper whitepaper (WP-12554-001)](https://docs.nvidia.com/nvidia-secure-ai-with-blackwell-and-hopper-gpus-whitepaper.pdf)
- [NVIDIA GPU Confidential Computing Demystified (arXiv 2507.02770)](https://arxiv.org/html/2507.02770v1)

### Intel Tiber Trust Authority
- [Intel Trust Authority](https://www.intel.com/content/www/us/en/security/trust-authority.html)
- [Intel Trust Authority — Attestation overview](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-attestation-overview.html)
- [Intel Trust Authority — GPU attestation](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html)

### Phala + Marlin
- [Phala Cloud overview](https://docs.phala.com/network/overview/phala-network)
- [Phala Decentralized Root of Trust](https://github.com/Phala-Network/phala-docs/blob/main/dstack/design-documents/decentralized-root-of-trust.md)
- [Marlin Protocol](https://www.marlin.org/)

### EigenLayer / Symbiotic / Karak
- [EigenLayer slashing launch (CoinDesk, 2025-04-17)](https://www.coindesk.com/tech/2025/04/17/eigenlayer-adds-key-slashing-feature-completing-original-vision)
- [Kiln — EigenLayer rewards v2 + slashing 2025](https://www.kiln.fi/post/eigenlayer-unveils-rewards-v2-and-slashing-for-2025)
- [EigenCloud Restaking Overview](https://docs.eigencloud.xyz/eigenlayer/restakers/concepts/overview)
- [Restaking Wars 2025: EigenLayer vs Symbiotic vs Karak](https://yellow.com/learn/restaking-wars-in-2025-eigenlayer-vs-symbiotic-vs-karak-%E2%80%93-what-you-need-to-know)

### libp2p bandwidth
- [Rust libp2p BandwidthLogging](https://docs.rs/libp2p/0.45.0/libp2p/bandwidth/struct.BandwidthLogging.html)
- [Go libp2p metrics package](https://pkg.go.dev/github.com/libp2p/go-libp2p-core/metrics)
- [js-libp2p METRICS.md](https://github.com/libp2p/js-libp2p/blob/main/doc/METRICS.md)

---


# Section 4: Agent Protocols, MCP/A2A, and Agent Frameworks — 2026 State

Tenzro's "Data MCP" — one MCP server per node exposing AI-native datasets (Arrow, Parquet, safetensors, vector indexes) as tools that agents can discover and pay for in TNZO — must drop into the protocol stack the rest of the industry has already converged on. This section is a literature review of the relevant specs and frameworks as of May 2026, with citations.

## 4.1 MCP — Current Specification (2025-06-18)

The current MCP revision is `2025-06-18`. Tenzro's RPC, A2A, and ecosystem MCP servers (Solana/Ethereum/Canton/LayerZero/Chainlink/Li.Fi) currently advertise `2025-03-26` via the `protocolVersion` field; the Data MCP should advertise `2025-06-18` and accept `2025-03-26` for backwards compatibility per the spec's `MCP-Protocol-Version` header rules.

**What changed from 2025-03-26 → 2025-06-18** (Anthropic's own changelog):

- **JSON-RPC batching removed.** Single request/response per HTTP body; Tenzro's `rmcp`-based servers already operate this way.
- **Structured tool output.** Tools may now return a `structuredContent` JSON object alongside (or instead of) the legacy `content` array, and may declare an `outputSchema` for client-side validation. This is the single biggest change for a Data MCP: a `data_query` tool can return a typed result envelope (rows, schema, embedding) without forcing the agent to parse Markdown.
- **MCP servers reclassified as OAuth 2.1 Resource Servers** with mandatory protected-resource metadata (`/.well-known/oauth-protected-resource`, RFC 9728), mandatory RFC 8707 Resource Indicators on every authorization and token request, and mandatory PKCE.
- **Resource links in tool results** (`type: "resource_link"`) — tools can return URI handles to large payloads rather than inlining them. Critical for tensor/Parquet payloads.
- **Elicitation** — servers may request additional input from the user mid-call.
- `_meta` field added across interfaces; `title` field separated from `name` (name = programmatic ID, title = display).

**Streamable HTTP transport.** Both `2025-03-26` and `2025-06-18` use Streamable HTTP, replacing the pre-2024-11-05 `HTTP+SSE` two-endpoint pattern. One endpoint, supports POST (client→server) and optional GET (server→client SSE). Sessions are identified by an `Mcp-Session-Id` header returned in `InitializeResult`; clients must echo it on every subsequent request. Resumability is via per-stream SSE event IDs plus the `Last-Event-ID` header on reconnect — but the spec is explicit that replay is per-stream, not per-session, so resumability is more constrained than e.g. Kafka. Tenzro's existing MCP endpoints already conform.

**Authorization — OAuth 2.1 + PKCE + RFC 8707, no native DPoP yet.** MCP's 2025-06-18 auth chapter cites OAuth 2.1 draft-13, RFC 8414, RFC 7591, and RFC 9728, and mandates PKCE for all clients, but does **not** require RFC 9449 DPoP. Token theft is mitigated only by short-lived bearer tokens and audience binding via RFC 8707 — bearer tokens remain extractable from a compromised client. DPoP (sender-constraining via a public/private keypair, with a fresh per-request JWT in the `DPoP` header) is the natural next layer and is widely flagged as the direction MCP will move; Tenzro should adopt DPoP early on the Data MCP since agents are public clients with attractive credential surface area.

**Roadmap (official MCP 2026 roadmap).** Four priorities: (1) stateless Streamable HTTP at scale (load-balancer-friendly), (2) Tasks primitive lifecycle (retry/expiry), (3) governance ladder, (4) enterprise readiness (audit/SSO/gateway). On the horizon: webhook-style server→client notifications (resource subscriptions today are barely adopted — Claude Desktop doesn't implement them as of March 2026), reference-based result streaming, and a "Skills" primitive for composed capabilities. The structured-output story is "live"; long-lived streams and webhook subscriptions are the open work.

## 4.2 A2A — Google's Spec + Linux Foundation Convergence

A2A's current release is **v0.3.0** (spec also published as Draft v1.0). It is a JSON-RPC 2.0 + SSE protocol with three discovery surfaces: an Agent Card at `/.well-known/agent-card.json` (in Tenzro deployments served by `integrations/a2a/tenzro_a2a_server/agent_card.py`), a `/a2a` JSON-RPC dispatcher, and a `/a2a/stream` SSE endpoint. Methods: `message/send`, `tasks/send`, `tasks/get`, `tasks/list`, `tasks/cancel`. The Agent Card declares **skills** (named capabilities with input/output media types and per-skill security schemes) and **capabilities** (streaming, push notifications, etc.). Tenzro's Agent Card already exposes 33 skills.

**The ACP merge.** In June 2025 the Linux Foundation launched the A2A project; in August 2025 IBM's Agent Communication Protocol (ACP, BeeAI-powered, donated to LF in March 2025) was merged into A2A. ACP wound down active development; Kate Blair joined the A2A Technical Steering Committee alongside Google, Microsoft, AWS, Cisco, Salesforce, ServiceNow, and SAP. BeeAI now runs over A2A. The result: A2A is the single LF-governed agent-to-agent protocol; MCP (also moving to LF governance) is the agent↔tool protocol. There is no remaining ACP/A2A schism.

**A2A vs MCP overlap.** MCP = agent↔tool/data, single client and single server, model-controlled tool invocation. A2A = agent↔agent, JSON-RPC over HTTP with SSE streaming, peer-to-peer task delegation. They compose: an agent receives a task over A2A, then uses MCP to call data/tool servers to fulfill it. Tenzro's stack already implements both — the Data MCP slots into the MCP lane.

## 4.3 Production Agent Frameworks — What They Expect

**LangGraph (LangChain).** A low-level orchestration runtime built around explicit state schemas (`TypedDict` + `Annotated` reducers). Tool calling via `ToolNode` and `InjectedState` annotations that pass current state into tools; concurrent tool updates must use reducer functions. Tools are Python functions with auto-generated JSON Schema; results are JSON, optionally accompanied by `Command` objects that direct graph transitions. LangGraph does not consume Arrow or tensor formats natively — anything binary must be base64-in-JSON or fronted by a Python helper. Auth is application-level (no built-in OAuth flow).

**Claude Agent SDK (Anthropic).** Renamed from Claude Code SDK; runs the agent loop in the host process. Tools are Python or TypeScript functions, including in-process MCP servers (no separate process). Built-in tools (Read/Write/Edit/Bash) are first-class. Result envelopes are MCP `content` blocks, so text/image/audio/resource_link/embedded resource are all natively understood. This is the single framework that consumes the full MCP content spectrum without translation — Tenzro's Data MCP should pin its content types to what Claude Agent SDK already parses.

**OpenAI Agents SDK.** Released March 2025; updated April 2026 with sandbox/harness capabilities. Tools fall into three categories: OpenAI-hosted (`WebSearchTool`, `FileSearchTool` against OpenAI Vector Stores, `CodeInterpreterTool`, `HostedMCPTool` — fronts a remote MCP server), local function tools (Python/TypeScript with auto schema generation), and the new sandbox-executed tools. `HostedMCPTool` is the supported path for plugging an MCP server in; it speaks Streamable HTTP and consumes structured `content` arrays. JSON in/out is the dominant shape; Arrow/Parquet must be fronted by a server-side `data_query → JSON rows` adapter or served via `resource_link` with a follow-up HTTP fetch.

**Letta (formerly MemGPT).** Memory is the agent's editable state, tiered as a virtual-memory hierarchy: **Core Memory** (always in context, block-structured), **Recall Memory** (searchable conversation/event history), and **Archival Memory** (cold storage with `archival_memory_insert` / `archival_memory_search` / `conversation_search` tools). Agents edit their own memory via tool calls (`memory_replace`, `memory_insert`, `memory_rethink`). The Letta server exposes these as REST APIs; the natural fit for Tenzro Data MCP is to **mirror** archival memory as a Data MCP tool category — `agent_memory_store` and `agent_memory_search` — so a Letta-style agent can use Tenzro nodes as a paid, decentralized archival tier.

**AutoGen v0.4 (Microsoft, Jan 2025).** Actor-model multi-agent orchestration, async event-driven core, layered (Core / AgentChat / Extensions). OpenTelemetry built in. As of October 2025, AutoGen and Semantic Kernel converged into **Microsoft Agent Framework** (public preview Oct 1, 2025) — the production-grade unified surface. Tools are .NET/Python functions; consumes MCP via the framework's MCP client. JSON-first.

**CrewAI.** Role-based multi-agent crews with `allow_delegation=True` granting agents collaboration tools. Hierarchical delegation via a manager agent; `allowed_agents` parameter restricts which subordinates a given agent may delegate to. Reported as the fastest-growing multi-agent framework in 2026 (~14.8k monthly searches). Tools are Python functions; the framework is JSON-only end-to-end.

**Common denominator for Data MCP design.** Every framework above consumes JSON tool results zero-effort. None consume Arrow IPC, Parquet, or safetensors natively as a tool result — they all require a wrapper (decode server-side, return JSON, or return a `resource_link` URI for the agent to fetch out-of-band). Tenzro's Data MCP must therefore: (a) default to JSON-rows-and-schema for small results, (b) return `resource_link` for large/tensor payloads pointing to an HTTP byte-range or Arrow Flight endpoint, (c) optionally expose a parallel Arrow Flight surface for high-throughput downstream consumers (analytics pipelines, training jobs) where MCP wrapping is overhead.

## 4.4 AI-Native Content Types in MCP

The MCP `2025-06-18` content spec recognizes five tool-result content types: `text`, `image` (base64 + mimeType), `audio` (base64 + mimeType), `resource_link` (URI handle), and `resource` (embedded URI with inlined text or blob). All carry optional `annotations` (audience, priority, lastModified). **There is no structured tensor type.** Binary payloads outside image/audio must travel either base64-encoded inside `resource.blob`, or by reference via `resource_link`.

No registered IANA MIME type exists for `application/x-arrow`, `application/x-parquet`, `application/x-safetensors`, `application/x-onnx`, or `application/x-faiss-index`. Apache Arrow Flight uses gRPC + Protobuf for transport, not MIME-typed HTTP bodies; the IPC stream format has no registered MIME. Tenzro should pick stable de-facto types and document them in the Data MCP spec: `application/vnd.apache.arrow.stream`, `application/vnd.apache.parquet`, `application/vnd.safetensors`, `application/vnd.onnx`. Use `resource_link` for anything over a few hundred KB; the agent fetches via HTTP with the resource URI carrying a TNZO-paid query token.

**Streaming Arrow Flight inside MCP — not natively supported.** Flight is a gRPC RPC framework streaming Arrow record batches over `DoGet`/`DoPut`/`DoExchange`. MCP's transport is JSON-RPC over Streamable HTTP. The two do not compose without wrapping (which would defeat Flight's zero-copy advantage). The pragmatic split: **MCP advertises the dataset and brokers the payment; Arrow Flight (or HTTP byte-range) serves the actual bytes.** A `data_query` MCP tool returns `{"flight_endpoint": "grpc://...", "ticket": "...", "schema": {...}, "rows": 1234567, "payment_receipt": "..."}` and the agent's analytics layer connects to Flight directly. This mirrors the LayerZero MCP pattern Tenzro already uses where the MCP server builds and returns calldata, and the actual on-chain call goes through a different channel.

## 4.5 RAG-2.0 and Agentic Retrieval Patterns

The 2025–2026 production consensus: single-shot vector search is obsolete. Three patterns dominate.

**Hybrid retrieval (BM25 + dense vector + reranker).** Microsoft, Pinecone, Weaviate, and the open-source RAG-flow ecosystem all run BM25 in parallel with dense vector search, RRF-merge the results, then apply a cross-encoder reranker (Cohere Rerank, BGE-reranker, Jina reranker). Reported recall@5 jumps from 0.587 (dense alone) and 0.644 (BM25 alone) to 0.816 with the two-stage pipeline — a >27% absolute improvement.

**GraphRAG (Microsoft Research, mid-2024 open-source release).** Extracts entities + relationships into a knowledge graph during indexing; retrieval traverses graph neighborhoods rather than returning isolated chunks. Closes the "semantic gap" where related-but-not-similar passages would be missed. Now the dominant pattern for multi-hop QA over corpora with named entities (research papers, legal docs, code).

**Agentic loops (Self-RAG, Corrective RAG, A-RAG).** The agent decides when to re-query, with what reformulation, and which tool (vector / BM25 / graph / web). A-RAG (Feb 2026) exposes keyword, semantic, and chunk-level retrieval as separate tools to the agent and reports +5–13% QA accuracy over flat retrieval. The implication for tool design: **the Data MCP should expose retrieval primitives separately rather than as a single magic `search` tool** — let the agent compose.

For Tenzro: a Data MCP node hosting a dataset should expose at minimum `data_vector_search`, `data_keyword_search` (BM25), `data_graph_neighborhood` (where applicable), and `data_rerank`. Agents will not "fetch one CID"; they will multi-hop, re-query, and rerank. Per-call TNZO pricing must accommodate that an answer takes 5–15 tool calls, not one.

## 4.6 Memory and State for Agents

Letta's three-tier hierarchy (Core / Recall / Archival, §4.3) is the most-cited reference implementation. OpenAI's hosted Memory feature persists per-user facts across ChatGPT sessions, surfaced as a JSON-rows store the assistant reads and writes via tool call. Anthropic ships per-session and per-project context for Claude, with a documented direction toward persistent memory accessible via Agent Skills.

**Implication for Tenzro Data MCP.** Yes — exposing "agent memory storage" as a tool category is the right call. A node-hosted memory tier offers two things no centralized provider can: (1) the agent's own DID owns the memory blocks (not the framework vendor), (2) per-write pricing in TNZO with on-chain receipts. Suggested tools: `memory_create_block`, `memory_read_block`, `memory_update_block`, `memory_archive` (move to cold), `memory_search` (semantic), `memory_grant` (delegate read/write to another agent DID — leverages Tenzro's DelegationScope). This dovetails with ERC-8004 identity (§4.7) so memory is portable across A2A counterparties.

## 4.7 ERC-8004 — Trustless Agents

**ERC-8004 is final and live on Ethereum mainnet as of January 29, 2026,** deployed across 20+ networks. Tenzro already mirrors it in `tenzro-identity` and as EVM precompiles `ERC8004_IDENTITY` (0x101a), `ERC8004_REPUTATION` (0x101b), `ERC8004_VALIDATION` (0x101c), with byte-identical selectors so the same calldata works against either the native Tenzro registry or the Ethereum mirror.

**Three registries.** Identity (ERC-721-based portable agent NFTs resolving to a registration file), Reputation (bounded-score feedback + categorical tags, e.g. response-time/uptime, posted by authorized agents/users), Validation (request verification, validator contracts respond — backed by stake-secured re-execution, zkML, or TEE oracles; the validation registry is still under active community revision specifically around TEE integration).

**A2A compatibility.** ERC-8004 was designed explicitly as a trustless extension of A2A — discovery via Agent Card → identity resolution via the on-chain registry → reputation lookup before delegation. For Tenzro's Data MCP, this means: when an agent queries a Data MCP tool, the node can verify the caller's ERC-8004 identity, look up reputation, and price-discriminate or rate-limit accordingly. Agents discover each other across Ethereum/Tenzro/L2s via the unified registry.

## 4.8 Open Design Questions for Tenzro Data MCP

1. **Resource subscriptions vs request/response.** MCP subscriptions are barely adopted (Claude Desktop doesn't support them; few production servers implement them). For Phase 1, request/response is sufficient and aligns with how every major framework consumes MCP. Add subscriptions later once the MCP roadmap's webhook-style server→client notifications stabilize (on the 2026 roadmap but not yet specified).

2. **Wrap Arrow Flight in MCP, or expose Flight separately?** Expose separately. MCP brokers discovery, schema, and payment; Flight (or HTTP byte-range) carries the bytes. The MCP tool returns a Flight ticket + payment receipt; the agent's data layer connects directly to Flight. Wrapping Flight in JSON-RPC defeats its zero-copy advantage and bloats every payload with base64 overhead.

3. **One tool per dataset, or generic `data_query(dataset_id, …)`?** Hybrid. Expose a small fixed set of generic tools — `data_list`, `data_describe(dataset_id)`, `data_query(dataset_id, …)`, `data_fetch(dataset_id, locator)`, `data_vector_search`, `data_keyword_search`, `data_graph_neighborhood` — so the MCP tool list stays bounded regardless of how many datasets the node hosts (tool lists are loaded into the agent's context window; one tool per dataset would not scale past a few dozen datasets per node). Datasets are addressed by `dataset_id`; agents discover them through `data_list` (paginated, with reputation/pricing metadata) or via an external registry indexed by Tenzro's existing `tenzro_listModels`-style RPC.

4. **Payment before or after the call?** MCP has no native payment hook, but **x402 already integrates with MCP** — Vercel's `x402-mcp` (announced 2026) and Coinbase/Cloudflare's `x402-axios` define `paidTools` with prices declared in tool metadata, returning HTTP 402 with payment requirements, accepting a `PAYMENT-SIGNATURE` header, and replying with `PAYMENT-RESPONSE` containing a settlement receipt. Tenzro's existing x402 stack in `tenzro-payments` (Coinbase CDP facilitator integration) maps onto this directly — add a TNZO-on-Tenzro facilitator and Tenzro becomes a first-class x402 settlement chain for MCP tool calls. The Data MCP server marks each tool with a TNZO price; first call returns 402; agent re-submits with a signed payment payload bound to the agent's DID; server verifies on-chain (or against a micropayment channel for hot tools) and returns the result. Subscriptions (long-running streams) need an additional channel-based metering model — defer to Phase 2.

## Sources

- [MCP 2025-06-18 changelog](https://modelcontextprotocol.io/specification/2025-06-18/changelog)
- [MCP Streamable HTTP transport spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [MCP Authorization spec (OAuth 2.1 + RFC 8707)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Tools spec — structured output, resource links](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
- [MCP 2026 Roadmap](https://modelcontextprotocol.io/development/roadmap)
- [Official MCP 2026 Roadmap blog](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/)
- [MCP Real-Time Streaming patterns](https://chatforest.com/guides/mcp-real-time-streaming/)
- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
- [DPoP explained — WorkOS](https://workos.com/blog/dpop-rfc-9449-explained)
- [A2A v0.3 Specification](https://a2a-protocol.org/v0.3.0/specification/)
- [A2A latest specification](https://a2a-protocol.org/latest/specification/)
- [A2A GitHub](https://github.com/a2aproject/A2A)
- [Linux Foundation: ACP joins forces with A2A (Aug 2025)](https://lfaidata.foundation/communityblog/2025/08/29/acp-joins-forces-with-a2a-under-the-linux-foundations-lf-ai-data/)
- [Linux Foundation launches A2A project (Jun 2025)](https://www.linuxfoundation.org/press/linux-foundation-launches-the-agent2agent-protocol-project-to-enable-secure-intelligent-communication-between-ai-agents)
- [A2A surpasses 150 orgs — LF press](https://www.linuxfoundation.org/press/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year)
- [LangGraph overview docs](https://docs.langchain.com/oss/python/langgraph/overview)
- [LangGraph GitHub](https://github.com/langchain-ai/langgraph)
- [Building agents with the Claude Agent SDK — Anthropic engineering](https://www.anthropic.com/engineering/building-agents-with-the-claude-agent-sdk)
- [Claude Agent SDK overview](https://platform.claude.com/docs/en/agent-sdk/overview)
- [OpenAI Agents SDK — Tools](https://openai.github.io/openai-agents-python/tools/)
- [OpenAI: next evolution of the Agents SDK](https://openai.com/index/the-next-evolution-of-the-agents-sdk/)
- [Letta MemGPT memory model](https://docs.letta.com/concepts/memgpt/)
- [MemGPT paper and Letta integration](https://www.letta.com/blog/memgpt-and-letta)
- [AutoGen v0.4 — Microsoft Research](https://www.microsoft.com/en-us/research/articles/autogen-v0-4-reimagining-the-foundation-of-agentic-ai-for-scale-extensibility-and-robustness/)
- [Microsoft Agent Framework (AutoGen + Semantic Kernel convergence)](https://learn.microsoft.com/en-us/agent-framework/overview/)
- [CrewAI Collaboration docs](https://docs.crewai.com/en/concepts/collaboration)
- [CrewAI GitHub](https://github.com/crewaiinc/crewai)
- [Apache Arrow Flight RPC](https://arrow.apache.org/docs/format/Flight.html)
- [GraphRAG / hybrid retrieval analysis — NetApp Community](https://community.netapp.com/t5/Tech-ONTAP-Blogs/Hybrid-RAG-in-the-Real-World-Graphs-BM25-and-the-End-of-Black-Box-Retrieval/ba-p/464834)
- [Agentic RAG Survey (arXiv 2501.09136)](https://arxiv.org/html/2501.09136v4)
- [Agentic RAG with Knowledge Graphs (arXiv 2507.16507)](https://arxiv.org/abs/2507.16507)
- [AgenticRAGTracer benchmark (arXiv 2602.19127)](https://arxiv.org/html/2602.19127)
- [ERC-8004: Trustless Agents — EIP](https://eips.ethereum.org/EIPS/eip-8004)
- [erc-8004-contracts](https://github.com/erc-8004/erc-8004-contracts)
- [ERC-8004 as A2A trustless extension — Coinmonks](https://medium.com/coinmonks/erc-8004-a-trustless-extension-of-googles-a2a-protocol-for-on-chain-agents-b474cc422c9a)
- [x402 standard](https://www.x402.org/)
- [x402-mcp — Vercel](https://vercel.com/blog/introducing-x402-mcp-open-protocol-payments-for-mcp-tools)
- [x402 on Cloudflare Agents](https://developers.cloudflare.com/agents/x402/)
- [Autonomous API & MCP payments with x402 — Zuplo](https://zuplo.com/blog/mcp-api-payments-with-x402)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707.html)
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)

# Section 5: Post-Quantum Cryptography, Adjacent Ledger Primitives, and the 2026 Academic Landscape

Tenzro's stack must survive (a) the harvest-now-decrypt-later threat against today's elliptic-curve primitives, (b) BFT-consensus state of the art moving on a 6–12 month cadence, and (c) a ZK/zkVM ecosystem that fully turned over between 2024 and 2026. This section reviews the standards, schemes, and papers that constrain or unlock concrete design choices in `tenzro-crypto`, `tenzro-consensus`, `tenzro-zk`, `tenzro-tee`, and `tenzro-wallet`, with citations.

## 5.1 NIST PQC Standards — FIPS 203 / 204 / 205 Final, FIPS 206 Draft

NIST published the first three final post-quantum standards on **August 13, 2024** (effective date in the Federal Register notice: **August 14, 2024**):

- **FIPS 203 — ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism, derived from CRYSTALS-Kyber round 3). Parameter sets `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`, claimed NIST security categories 1, 3, 5. Public-key sizes 800/1184/1568 bytes; ciphertext sizes 768/1088/1568 bytes; shared-secret 32 bytes. Encapsulation and decapsulation are both fast (microseconds on modern x86). The standard is **not bit-for-bit Kyber** — there are FIPS-mandated tweaks (domain separation, NIST DRBG, transcript hashing) that mean "Kyber-compatible" libraries are not automatically "ML-KEM-compliant."

- **FIPS 204 — ML-DSA** (Module-Lattice-Based Digital Signature Algorithm, derived from CRYSTALS-Dilithium). Parameter sets `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`. Public-key sizes 1312/1952/2592 bytes; signature sizes 2420/3309/4627 bytes. Verification is fast (~100 µs on x86); signing is slower than Ed25519 by ~5–10× depending on parameter set. Pure ML-DSA and external-mu variants both standardized.

- **FIPS 205 — SLH-DSA** (Stateless Hash-Based Digital Signatures, derived from SPHINCS+). Conservative fallback whose security rests only on the underlying hash (SHA-2 or SHAKE). Signatures are 7,856–49,856 bytes depending on parameter set; signing is slow (10–100 ms). Used where reviewers want the smallest possible cryptographic assumption set — long-lived firmware roots-of-trust, code-signing.

- **FIPS 206 — FN-DSA** (Falcon-based, lattice signatures with small signatures via NTRU + Gaussian sampling). NIST submitted the draft for approval on **August 28, 2025** as an Initial Public Draft. Expected finalization late-2026 / early-2027. Open issues that delayed FIPS 206: floating-point side-channel risk in the original Falcon reference implementation, External-μ variant, HashFN-DSA. Falcon signatures are ~666 bytes for the 512 variant — the smallest of any standardized PQ signature — but the implementation complexity is the highest.

For Tenzro: ML-DSA-65 is the operational signature parameter set (matches NIST category 3, balances key/sig size against perf); ML-KEM-768 is the operational KEM (category 3, matches the IETF hybrid TLS choice). SLH-DSA is the long-lived-root fallback. FN-DSA stays out of the wire format until FIPS 206 is final.

**Operational cost on a BFT chain.** ML-DSA-65 signatures are ~25× larger than Ed25519 (3309 vs 64 bytes) and ~5–10× slower to sign. The block-level impact depends on how many signatures finalize a block: with N=100 validators voting per round, the all-PQ overhead is ~330 KB per block of signature data alone, which dominates block gossip bandwidth at any nontrivial TPS. This is the practical reason every live BFT chain that has touched PQ in 2024–2026 (Cosmos SDK PQ branch, Ethereum's PQC roadmap, Tenzro itself) treats PQ signatures as either (a) **aggregated** before gossip via FROST-PQ or SNARK-aggregation, or (b) **hybrid-attached only at the block-finalization boundary**, not on every per-round vote. The cost dictates the design, not the other way around.

**Implementation crates.** The production Rust implementations as of May 2026: `pqcrypto-mlkem` and `pqcrypto-mldsa` (Open Quantum Safe / `pqcrypto` family, audited), `mlkem768` / `mldsa65` direct ports in the `RustCrypto` org, and `liboqs-rust` (FFI wrapper around `liboqs` C library — used by BoringSSL and rustls). The RustCrypto family is the preferred path for new code (pure Rust, no FFI). NIST CAVP test-vector compliance is the conformance gate.

## 5.2 Hybrid KEM + Signature Schemes in Production

The deployed wire-protocol consensus as of 2026 is **hybrid**: ship a classical primitive concatenated with a PQ primitive so a break in either does not compromise the session.

**TLS 1.3 — `X25519MLKEM768` (codepoint `0x11EC`).** Specified in `draft-kwiatkowski-tls-ecdhe-mlkem` (now `draft-ietf-tls-ecdhe-mlkem`). The shared secret is `X25519(s) || ML-KEM-768.decap(c)` fed into the TLS 1.3 key schedule. Cloudflare announced essentially-universal `0x11EC` support across its edge as of late 2024, replacing the earlier `0x6399 — X25519Kyber768Draft00` codepoint. As of October 2024 Cloudflare reported ~17% of human traffic negotiating a PQ-hybrid key exchange; that figure has continued climbing as Chrome (default since version 124), Firefox, and Safari rolled out client support. BoringSSL, OpenSSL 3.5 (April 2025), and rustls all support `0x11EC` natively.

**SSH — `mlkem768x25519-sha256`.** OpenSSH offered PQ-hybrid key agreement by default since OpenSSH 9.0 (April 2022) via `sntrup761x25519-sha512`. In OpenSSH 9.9, `mlkem768x25519-sha256` was added and **became the new default in OpenSSH 10.0 (April 2025)**. GitHub deployed `mlkem768x25519-sha256` on its SSH endpoints in October 2025. The migration path is "both keys, agree on whichever the client picks"; `sntrup761x25519-sha512` remains supported as a fallback.

**Hybrid signature models.** Two distinct composites exist in the wild:

1. **Concatenated / "both-must-verify."** Sign with both Ed25519 and ML-DSA-65; verifier checks both, accepts only if both pass. Used by browsers' code-signing experiments, Cloudflare's internal mTLS, and Tenzro's validator key path. Cost: two signatures (Ed25519 64 bytes + ML-DSA-65 3309 bytes ≈ 3.4 KB), two verifies. Security: holds as long as **either** scheme is unbroken (defense in depth).
2. **OR composite / "either-verifies."** Encode both keys, signer chooses one. Useful only as a soft migration aid; loses PQ guarantees the moment any signature is verified via the classical key. Largely abandoned in 2025–2026 designs.

Tenzro's validator keys are Ed25519 + ML-DSA-65 in the concatenated mode; the per-block vote is signed twice and verified twice. The PQ-hybrid TLS termination on Caddy in front of `rpc.tenzro.network` / `api.tenzro.network` already speaks `X25519MLKEM768`.

**X-Wing and the KEM-combiner question.** A naive hybrid KEM `H(secret1 || secret2)` is not provably secure as a combiner — it requires modeling assumptions on the underlying KEMs that NIST does not guarantee. The X-Wing combiner (Barbosa, Bos, Heutscher, Houfan, Kannwischer, Schwabe, Wiggers — 2024) specifies a tightly-secure ML-KEM + X25519 hybrid with a fixed structure and proven indistinguishability under standard assumptions. X-Wing is the construction that the IETF TLS WG's `X25519MLKEM768` codepoint inherits — meaning Tenzro's existing PQ-hybrid TLS already benefits from the tighter security proof. For application-layer hybrid encryption (envelope encryption in `tenzro-crypto`), X-Wing is the right primitive to standardize on rather than inventing a per-app combiner.

**Hybrid handshake performance.** Cloudflare's published measurements show `X25519MLKEM768` adds ~1 ms server-side handshake CPU vs. pure X25519, and ~1184 bytes to the TLS ClientHello (ML-KEM-768 public key + classical share). The connection-establishment cost is dominated by RTT, not CPU; the bandwidth cost matters more on slow links. For Tenzro's RPC/API endpoints terminated by Caddy, the cost is negligible. For agent-to-agent direct connections over libp2p, the same calculus applies if libp2p switches its Noise handshake to a PQ-hybrid variant (current standardization work: `xx-pq` draft).

## 5.3 PQ-Secure BFT Consensus — What Breaks, What Replaces

Shor's algorithm collapses the security of any discrete-log-based primitive on a sufficiently large quantum computer. For a BFT L1 the immediate casualties are:

- **Validator signatures** (Ed25519 / secp256k1) — replaced by ML-DSA-65 in hybrid.
- **Aggregated multi-sig over BLS12-381** — the BLS aggregation magic depends on bilinear pairings on a pairing-friendly curve, which is *broken* by Shor along with all other discrete-log instances. There is no drop-in PQ replacement that preserves the O(1)-verification, O(1)-size aggregate signature property of BLS.
- **VRF on Curve25519** (RFC 9381 ECVRF-EDWARDS25519) — same fate, broken by Shor.

The aggregation hole is the awkward one. Three replacement paths are currently active:

**(a) FROST-style threshold over a PQ signature.** Run a multi-party threshold protocol that produces a single ML-DSA signature whose verification is identical to a single-signer ML-DSA. Active research; NIST published a sixth PQC standardization conference note on *Efficient Threshold ML-DSA up to 6 parties* (April 2025). The bottleneck is the lattice-based commit/open arithmetic — current academic protocols are practical for small committees (≤ 8 parties) but do not scale to a 100-validator quorum.

**(b) Hash-based aggregators with STARK compression.** Sign with SLH-DSA (purely hash-based, conservative) and compress N signatures into one STARK proof. *Aggregating and Thresholdizing Hash-based Signatures using STARKs* (Boneh, Drake, Fisch — 2022) is the foundational reference; production prototypes exist in the Ethereum PQ working group.

**(c) SNARK-aggregated ML-DSA.** Verify N ML-DSA signatures inside a SNARK / STARK; aggregate by folding (e.g., HyperNova / Nova / Mova-style folding). Srinath Setty (Microsoft Research) demonstrated post-quantum signature aggregation via folding in late 2025. *CAPSS* (eprint 2025/061) and *Loquat* (eprint 2024/868) propose SNARK-friendly PQ signatures with aggregate sizes in the hundreds of KB range for thousands of signers. The Ethereum PQC Interop working group is actively benchmarking this path (issue ethereum/pm#2035, April 2026).

For Tenzro's vote-aggregation layer (currently using BLS12-381 for VoteCollector aggregation), the trade matrix is: FROST-PQ is the cleanest substitute *if* the committee stays small (e.g., a rotating consensus committee of ≤ 32 validators); SNARK-aggregated ML-DSA is the path if the quorum grows. Both are research-grade in May 2026; the pragmatic interim is to keep BLS12-381 for in-protocol aggregation and bind every committee output with a PQ-hybrid attestation at the block-finalization boundary — so a "harvest-now-attack-later" adversary cannot retroactively forge finalized blocks even if BLS is broken.

**Verifiable randomness (VRF).** RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI — used in `tenzro-crypto::vrf` and consumed by the EVM precompile `0x1007`, the NFT factory `mintRandom`, and the dispute-committee selector — is also Shor-broken. The PQ replacement candidate set is shallower than for signatures: lattice-based VRFs are an active research topic (e.g., LB-VRF, Buser et al. 2022) but not standardized; hash-based VRFs sacrifice the public-verifiability + unbiasability properties; SNARK-of-PRF constructions (prove a Poseidon2/SHA-256 evaluation in zk) work but cost orders of magnitude more per call. Tenzro's downstream consumers care more about unbiasability and uniqueness than non-malleability, so a SNARK-of-PRF construction inside the existing Plonky3 pipeline is the most likely landing point — every VRF call becomes a tiny AIR proof, verifiable via the same `ZkCommitmentRegistry` path.

**Liveness during the transition.** A naive "flag-day swap from BLS to FROST-PQ" risks consensus stalls if any validator's PQ stack is misconfigured. The conservative migration is to gossip *both* a BLS aggregate and a PQ-hybrid attestation per block for a defined epoch range, accept either at finalize, then deprecate BLS once telemetry shows the PQ path is uniformly healthy. This is the same pattern OpenSSH used for `sntrup761x25519-sha512` → `mlkem768x25519-sha256` and the IETF TLS WG used for `0x6399` → `0x11EC`.

## 5.4 ZK in 2026 — Plonky3, SP1, Risc0, Jolt

The 2023 trusted-setup-Groth16 era is over for new designs. The 2026 production zk stack is transparent-setup STARKs with small fields and FRI commitments, plus RISC-V zkVMs that compile arbitrary Rust to provable code.

**Plonky3 (Polygon Labs, MIT/Apache, GitHub `Plonky3/Plonky3`).** A toolkit for polynomial IOPs (STARKs and PLONK-style PIOPs). Five finite fields shipped: **BabyBear** (`2^31 − 2^27 + 1`), **KoalaBear** (`2^31 − 2^24 + 1 = 127 · 2^24 + 1`), **Mersenne31** (`2^31 − 1`), Goldilocks (64-bit), and BN254-Fr (compatibility). The 31-bit fields are where Plonky3's optimization effort lives — vectorized add/mul on AVX2/AVX-512, NEON, and CUDA. KoalaBear specifically admits a smaller hash-function multiplicative degree `d = 3` for Poseidon2, lowering proving cost vs. BabyBear's `d = 7`. Production users include Polygon's own zkEVM, Succinct (used as the inner STARK in SP1), Risc Zero (in Risc0 v2), and Lita's Valida zkVM.

**SP1 (Succinct, GitHub `succinctlabs/sp1`).** RISC-V (RV32IM) zkVM. STARK back-end over BabyBear with FRI. The strongest position on precompiles in production: native acceleration for keccak256, sha256, secp256k1 + ed25519 signature verification, bn254 and bls12-381 arithmetic (and pairing in roadmap). GPU prover. Rust developers compile ordinary `cargo` binaries with minimal changes. Deployed in production for Ethereum block proving and several rollups.

**Risc0.** Older RISC-V zkVM; current versions use Plonky3 internally. Precompile coverage expanding through 2025. Strong CUDA prover; on-chain Groth16 wrapping for cheap mainnet verification.

**Jolt (a16z crypto).** Different proof machinery — Lasso lookups + sum-check PIOP + multilinear commitments. Currently RV32I only (no multiplication/division), small upper bound on cycle count (~16M), no precompiles, no recursion, no on-chain verifier as of May 2026. Conceptually cleaner than the STARK-based zkVMs (no AIR engineering, lookups replace arithmetization) but operationally not yet production-grade.

**On-chain verification cost.** STARK proofs are 64–128 KB and verify in ~5–20 ms in native code; verifying them inside an EVM precompile is too expensive to do per-transaction. The deployed pattern is: validators run the full STARK verifier off-chain (or in an SP1/Risc0 proof wrapped into a Groth16/PLONK for mainnet); the on-chain primitive is a commitment to "this proof was verified" — exactly what `ZkCommitmentRegistry` in `tenzro-vm` does today, with the `ZK_VERIFY` precompile reduced to an O(1) HashSet lookup.

**Why Tenzro picks Plonky3 + KoalaBear for inference proofs.** (1) Transparent setup — no per-circuit ceremony tax, no per-circuit CRS to ship. (2) KoalaBear's `d = 3` Poseidon2 makes hash-heavy inference AIRs (matmul commit, activation lookups) cheaper than BabyBear's `d = 7`. (3) Permissive license (MIT/Apache) and pinned dependency (rev `32079474b1d31d9221656ae774afb322d2597db0` in `tenzro-zk`). (4) The transparent setup composes cleanly with TEE-in-the-loop attestation — both primitives have the same "no shared setup state" property.

**Steelman for SP1.** If Tenzro wanted "any Rust program is provable" rather than "specific AIRs per circuit," SP1 is the right tool — the inference verifier becomes a 200-line Rust program rather than a 2,000-line AIR. The trade-off is proof size and prover memory: a hand-written AIR over KoalaBear produces a 64 KB proof in seconds; an SP1 zkVM proof of the same statement is 1–10 MB and takes minutes-to-hours unless the prover has dedicated GPUs. For Tenzro's per-inference proof case, where the same circuit shape is reused millions of times, the AIR approach amortizes the engineering cost; SP1 wins for one-off proofs or rapidly-changing logic.

**Post-quantum soundness of STARKs.** Plonky3, SP1, and Risc0 are all FRI-based, and FRI's soundness rests only on collision-resistance of the underlying hash (Poseidon2 / Keccak / BLAKE3) — no number-theoretic assumption is involved. This is **the** reason new BFT L1s consistently picked STARKs over Groth16 / PLONK-KZG between 2024 and 2026: a KZG-based SNARK over BN254 inherits BN254's discrete-log assumption, which Shor breaks; a STARK over a 31-bit prime field does not. The commitment registry that Tenzro uses (`ZkCommitmentRegistry`, `compute_zk_commitment(circuit_id, proof_bytes, public_inputs)`) is itself a SHA-256 commitment — also post-quantum-sound as long as Grover's quadratic speedup is the only quantum attack on the hash (256-bit pre-image security halves to 128-bit under Grover, which is the design margin).

**Recursion + folding.** Both SP1 and Risc0 ship in-zkVM recursive proof composition; Plonky3 supports recursion via FRI batching across multiple AIRs. The 2025 folding wave (Nova → SuperNova → HyperNova → ProtoStar → Mova) is the academic frontier; in production, recursion stays inside zkVMs rather than running as standalone fold operations. For Tenzro this matters for one specific case: training-receipt aggregation. A training round produces N per-worker `OuterGradient` receipts; rather than verify all N on-chain, validators fold them into one recursive proof attesting "all N receipts verified against the canonical aggregation rule." The Plonky3 + KoalaBear path supports this today.

**ethSTARK and the "big-field" tradition.** ethSTARK (StarkWare, 2021) remains the reference STARK over a 251-bit field with hash-friendly arithmetic (Poseidon over Stark-friendly fields). The mid-2020s shift to 31-bit fields (BabyBear / KoalaBear / Mersenne31) was driven by single-precision FFT performance: a multiplication in a 31-bit field is one machine instruction on x86; a 251-bit-field multiplication is a multi-word routine. Per-statement proving cost on a 31-bit field is 5–20× lower than on the 251-bit equivalent. The trade-off: 31-bit fields require either extension-field arithmetic for security or larger trace tables; modern implementations handle both. ethSTARK is no longer the production target for new designs but remains relevant as the architectural reference and as the proving backend used by StarkWare's Cairo zkVM (Starknet).

**FRI vs. STIR vs. WHIR.** The post-FRI polynomial commitment landscape is moving fast. STIR (Arnon, Chiesa, Fenzi, Yogev — 2024) reduces the number of FRI queries for the same soundness, lowering proof size by 1.5–3×. WHIR (Arnon, Chiesa, Fenzi, Yogev — 2025) is the successor with even tighter parameters and faster verification. Plonky3 ships FRI today with STIR / WHIR migrations on the roadmap. For Tenzro this is a forward-compatibility note: the pinned testnet config (`log_blowup=1, num_queries=64, query_pow=16, commit_pow=8`) is FRI-specific; a future migration to STIR or WHIR would change the parameter set and the proof bytes layout, but the AIR definitions and the public-input chunking remain stable.

## 5.5 TEE + ZK Composition — Verifiable Compute in 2026

The 2026 production stack for "prove this AI inference ran on the model you think it did, on hardware you trust" is **not** pure-zkML and **not** pure-TEE; it is the composition.

**Apple Private Cloud Compute (PCC, June 2024).** Verifiable transparency: every PCC build is reproducible, attested by Secure Enclave, and its binary hash is published to a public transparency log. Apple commits that any request a device sends is only routable to a node whose attestation matches a logged binary. This is the gold-standard "verifiable inference" UX in the field — Apple does not currently use zk proofs here; the security argument rests on (a) attestation of the binary, (b) public transparency of the binary, (c) audit of the published binary.

**Intel Tiber Trust Authority.** Issues an Intel-signed *composite token* (`get_token_v2`) over a TDX guest report plus optional NVIDIA H100/H200 CC evidence. The relying party verifies one JWT instead of stitching together the TDX quote chain + AMD KDS + NVIDIA NRAS endpoint. This is the operationally simplest path for a node that runs ML inference inside TDX + H100 CC, and it is what Tenzro's `tenzro-tee` integrates against for the TDX + NVIDIA pairings.

**Production "TEE-attested + ZK-of-commitment" deployments.**

- **Phala Cloud + dstack** — decentralized TEE marketplace; nodes run TDX with attestation gossiped on chain. ZK is used only at the membership-proof layer, not per-inference.
- **Marlin Protocol** — decentralized confidential compute on AWS Nitro; attestation verified on chain.
- **Worldcoin Orb** — attested image-capture + zk-proof-of-personhood; the iris embedding is computed inside the Orb's TEE and committed via a ZK proof rather than transmitted in cleartext. The Orb is the single largest-scale production deployment of TEE + ZK composition (~7M users as of 2026).
- **Modulus Labs / EZKL** — zkML for specific verticals (DeFi agent rebalancing, on-chain ML predictions). EZKL's 2025-2026 work added CUDA proving and benchmarking against Lagrange / zkPyTorch / Jolt. The 2026 industry consensus is that zkML will run inline for *high-value, low-volume* inference (autonomous financial agents, model-output verification for governance) and as an *audit trail* for everything else.
- **Ocean Protocol Compute-to-Data** — older pattern of attested-compute over private data; TEE-only, no ZK.

The Tenzro position (already implemented in `tenzro-tee` and `tenzro-zk::tee_integration`): a hybrid proof = TEE quote + Plonky3 proof of model-commitment. The TEE attests "this binary ran on this hardware"; the STARK attests "this binary's output is consistent with the published model weight commitment." Either alone is bypassable (a compromised TEE can produce a quote over arbitrary output; a STARK alone cannot prove the inference happened on real hardware); together the trust assumption is the strictly weaker conjunction.

**TEE vendor trust hierarchy.** All TEE attestation paths terminate at a vendor root certificate: Intel PCS for TDX, AMD KDS for SEV-SNP, AWS Nitro CA for Nitro Enclaves, NVIDIA NRAS for H100/H200 CC. Any chain anchored at a single vendor's root is single-point-of-trust by construction. The 2024–2026 mitigation patterns: (1) composite tokens (Intel Trust Authority's `get_token_v2` wraps multi-vendor evidence into one signed JWT, but the JWT itself is Intel-signed); (2) **vendor-diverse provider pools** — match each inference job to a TEE family different from the one the model was trained on, so a vendor-rooted compromise cannot silently corrupt both training and serving; (3) **public transparency logs** of TEE binaries (Apple PCC's model). Tenzro's `tenzro-tee` supports four vendor families; vendor-diverse routing is a Phase-2 protocol-level feature.

**NVIDIA H100/H200 Confidential Computing — what attestation covers.** The GPU's CC mode locks PCIe BAR access, enables on-die memory encryption (HBM3 encrypted with per-launch key), and produces an SPDM-based attestation report verifiable via NVIDIA's NRAS endpoint. The trust boundary is the GPU package itself — the CPU side must run inside a separate TEE (TDX or SEV-SNP) for the full secure path. The composite path (TDX VM + H100 CC over PCIe with encrypted RDMA) is what production "verifiable AI inference" deployments use today: Azure CC, GCP Confidential GKE Nodes with H100, AWS Nitro + H100 instances. The NRAS report's maximum age is 24 hours by spec, which is the operational refresh cadence Tenzro pins in `tenzro-tee::providers::nvidia_gpu`.

**Limits of zkML.** Even with 2026's GPU-accelerated provers (EZKL CUDA, Lagrange GPU, zkPyTorch), proving a forward pass through a 70B-parameter model is impractical — proving time scales with floating-point operation count, and the 10^15 ops in a Llama-3-70B forward pass mean ~minutes-to-hours per inference, not the sub-second range needed for interactive serving. Production zkML deployments in 2026 prove (a) small specialized models (sub-1B-param decision models for DeFi rebalancing, AML scoring, recommendation systems) or (b) **only the critical computation** (zk-prove the model's argmax over the final logits, not the full forward pass). The Tenzro hybrid (TEE for the full pass + ZK for the model-weight commitment + output digest) is the pragmatic middle: full-model attestation comes from the TEE; the ZK proof binds the result to a public weight commitment so a swapped model is detectable without proving every multiply-add.

**Floating-point in ZK.** Neural networks operate in bfloat16 / float16 / int8; SNARKs and STARKs operate over finite fields. Bridging the two is a known-hard problem: lookup tables (Lasso/Jolt-style) for activation functions, fixed-point quantization with proof-of-bounds for linear layers, and per-layer commit-and-prove rather than monolithic circuits. The 2025–2026 SOTA (EZKL, Modulus's Remainder, zkPyTorch) supports quantized inference of small models with measurable error vs. native float execution. Tenzro's `tenzro-zk::inference` AIR uses the commitment-and-attestation model rather than per-multiply proving — the AIR binds (input commitment, weight commitment, output commitment, model_id, provider_id) without proving the float-arithmetic itself; the TEE quote is what makes the actual computation trustworthy. This is a deliberate architectural choice that buys orders-of-magnitude lower proving cost at the cost of requiring TEE hardware on the inference side.

## 5.6 MPC, Threshold Signatures, and FROST in 2026

The 2023 disclosures of TSSHOCK (Verichains) and BitForge (Fireblocks) ended the GG18 / GG20 / CGGMP21 era for new deployments without remediation. The summary:

- **BitForge (CVE-2023-33241, Fireblocks).** Parties in GG18 / GG20 do not verify that the attacker's Paillier modulus N is a biprime with no small factors. One attacker-chosen-N exfiltrates the secret key in 16-bit chunks; 16 signatures suffice. Affected ten-plus major wallet/custody products including Binance custody's threshold-ECDSA implementation.
- **TSSHOCK (Verichains).** Three new attacks (α-shuffle, c-split, c-guess) against the zero-knowledge proofs in GG18 / GG20 / CGGMP21 implementations. Recovers the key while the protocol completes normally — no abort, no trace. Most audited implementations were found vulnerable; the patches are non-trivial.

The 2024–2026 replacements:

- **FROST — RFC 9591 (Connolly, Komlo, Goldberg, Wood; June 2024).** "Flexible Round-Optimized Schnorr Threshold." Two-round Schnorr threshold over Ed25519 / Ed448 / Ristretto255 / Pallas / secp256k1-Taproot. Output: a single, standard Schnorr signature indistinguishable from a single-signer one. Reference implementations: ZcashFoundation/frost (Rust, audited), taurushq-io/frost-ed25519. Strong academic provenance (Komlo & Goldberg, SAC 2020). The natural choice for Ed25519 wallets — Tenzro's identity and validator keys are Ed25519, so FROST is the drop-in upgrade for `tenzro-crypto::mpc` (which is currently Shamir secret-sharing + reconstruct, **not** a true threshold signature scheme).
- **CGGMP21 — patched (Dfns / LFDT-Lockness Rust implementation).** State-of-the-art threshold ECDSA. Dfns released `dfns/cggmp21` in 2024 (audited by Kudelski Security, dual MIT/Apache), generalized from the n-of-n paper to t-of-n, with offline pre-signature support. Now governed under Linux Foundation Decentralized Trust (`LFDT-Lockness/cggmp21`). The TSSHOCK-vulnerable zero-knowledge proofs are patched and explained in Dfns' public writeup. Used by Dfns, Fireblocks (post-patch), Zodia Custody, several agent-payment custodians. The right choice for **secp256k1** wallets — Ethereum, Bitcoin — where FROST-on-secp256k1-Taproot is not always usable because counterparties expect ECDSA signatures.

**Production wallets shipping threshold MPC in 2026.** Fireblocks (CGGMP21, post-patch), Coinbase Wallet (custom 2-of-3 MPC), Privy (server-assisted Shamir + transaction signing), Dfns (CGGMP21), Lit Protocol (BLS-based custom MPC). All ship a **passkey-first UX** as the human-side authenticator: the user authenticates with a platform passkey (biometric, hardware-bound) and the threshold signature is composed across the user device + cloud share(s) + recovery share. FIDO caBLE (cloud-assisted Bluetooth low-energy) enables cross-device passkey authentication so a desktop client can sign with a phone's passkey without screen-sharing or seed-phrase transcription — this is the pattern Coinbase Wallet, Privy, and Daimo all converged on through 2024–2025.

**Pluggable signers as an architectural pattern.** The two-track wallet UX (passkey-first for end users + BYO-key-management for custom integrations) requires a `PluggableSigner` abstraction in the wallet layer — a trait whose implementors include `PasskeyFrostSigner`, `Cggmp21EvmSigner`, `HardwareWalletSigner` (Ledger / Trezor), `MockSigner` for tests, and (Phase 2) `EnclaveSigner` for in-TEE key custody. The Tenzro wallet's tenzro-auth integration must consume signers through this trait rather than hard-coding a single key model. Same lesson as the Stripe / Tempo / x402 integration: never let one payment protocol's data model leak into the core wallet contract.

**Threshold ML-DSA — what's known, what isn't.** A line of academic work since 2024 (Cozzo & Smart, "Sashimi"; Bandiera, Del Pino, Esgin et al.; NIST 6th PQC Conference April 2025) proposes practical threshold protocols for ML-DSA up to small committee sizes. The current state-of-the-art (May 2026) is: ≤ 6 parties is practical; 8–32 is research-grade; 100+ is not viable without aggressive optimization or a fundamentally different approach (FROST-style with a different PQ primitive, or SNARK-aggregation per §5.3). For Tenzro's *wallet* layer (typically 2-of-3 or 3-of-5), threshold ML-DSA at the small-committee end is on track for production by 2027. For the *consensus* layer (100+ validators), threshold ML-DSA is not the answer — SNARK-aggregation is.

For Tenzro: the wallet roadmap is FROST (Ed25519, RFC 9591) for native Tenzro identity / validator keys + CGGMP21 (secp256k1, patched) for the cross-chain bridge / EVM signing path, both fronted by a passkey-first authenticator. The current `tenzro-crypto::mpc` (Shamir SSS over GF(256) + reconstruct-to-sign) is a placeholder — keys are reconstructed in memory at sign time, which defeats the threshold guarantee. Replacement is sequenced.

**ERC-7579 modular accounts as the enforcement layer.** Off-chain spending-policy resolvers (Tenzro's `SpendingPolicyResolver` trait) are defense-in-depth — they cannot stop a compromised client from signing whatever a malicious operator presents to it. The primary control must live in the smart-account validator module: ERC-7579 + ERC-4337 v0.8 (already implemented in `tenzro-vm`) lets a wallet install a `SpendingLimit` validator that the EntryPoint enforces *at signature-validation time* on chain. Combined with FROST/CGGMP21 distributed key storage, the result is: keys are never on a single device, the signature is composed via threshold MPC, and the on-chain validator enforces the spending policy regardless of what the off-chain resolver says. The May 2026 Grok/Bankr-style drains (compromised agent operator signs unauthorized transfers via legitimate keys) are the empirical motivation; smart-account-validator-enforced policy is the production answer.

**ERC-7444 / passkey-first session keys.** Session keys are short-lived, scope-restricted sub-keys that the user authenticates with a passkey to mint, then the agent uses for a bounded window before re-authentication. ERC-7444 is the standardization path for "passkey session keys" in 4337 smart accounts. Coinbase Wallet's smart-wallet, Privy, and Dynamic.xyz all ship some variant. Tenzro's `SmartAccount` modules already include `SessionKey` as a first-class module; the FROST integration on top extends this to threshold-shared session keys.

## 5.7 Academic Papers Shaping 2026 Design

### BFT consensus

- **HotStuff-2 / HotStuff-1.** HotStuff-2 (Malkhi & Nayak, 2023) introduced two-phase commit improvements over HotStuff with a tighter view-change. HotStuff-1 (arXiv:2408.04728, August 2024; published in ACM PoMACS / SIGMOD 2025) adds one-phase speculation, cutting commit latency by two network hops while preserving linear communication. Why it matters for Tenzro: `tenzro-consensus` implements HotStuff-2; the HotStuff-1 speculation path is a worthwhile follow-up that does not require a fork-rule change.

- **Aptos LeaderReputation / Shoal.** The AptosBFT v4 / Shoal papers introduce reputation-weighted leader selection: a deterministic formula combining stake, recent commit success, and recent vote participation chooses the next leader. Validators with recent failures are deprioritized; the leader stream stabilizes around the fastest-and-most-available subset of the active validator set. Why it matters for Tenzro: current `select_leader` is round-robin; replacing it with a reputation-weighted election is one of the highest-leverage protocol changes for testnet stability (a single sluggish validator currently bottlenecks every ~Nth round).

- **Mysticeti — NDSS 2025 (Babel, Chursin, Danezis, Kichidis, Kokoris-Kogias, Koshy, Sonnino, Tian).** DAG-based Byzantine consensus that achieves 3-message-round commit latency, the theoretical lower bound, by **uncertified** DAG blocks (skipping the explicit certification step every prior DAG-BFT protocol required). Mysticeti-C: 0.5 s WAN commit at >200k TPS; integrated into Sui in late 2024 with a measured 4× latency reduction. Mysticeti-FPC adds a fast path for asset transfers. Why it matters for Tenzro: the lower bound and the uncertified-DAG technique are the new reference for any consensus team designing a high-throughput L1; if Tenzro's roadmap moves beyond HotStuff-2 it will be in the DAG direction, and Mysticeti is the paper.

- **MonadBFT (arXiv:2502.20692, February 2025).** Fork-resistant streamlined consensus. The protocol's distinctive primitive is the **No-Endorsement Certificate (NEC)**: a 2f+1-signed cryptographic attestation that the signers did *not* vote for a given proposal. An NEC allows an honest leader who cannot recover the previous high-tip block to safely propose a new block at the same height, bypassing the reproposal requirement. Combines responsive timing, fork resistance, and linear communication. Deployed in Monad's mainnet path. Why it matters for Tenzro: NEC is the cleanest known answer to the "leader stuck waiting for unavailable predecessor block" failure mode that HotStuff-derived chains all suffer from; worth pairing with reputation-based leader selection.

- **Solana Alpenglow — SIMD-0326.** Proposal to replace Solana's Proof-of-History + Tower BFT with **Votor** (direct-vote-based finalization, 1 or 2 voting rounds depending on conditions) and **Rotor** (replacement for Turbine block propagation). 100–150 ms finalization (vs. 12.8 s prior). Validator voting moves off-chain, freeing ~75% of block space. Timeline: Agave 4.1 release in Q3 2026, mainnet activation late 2026. Why it matters for Tenzro: Alpenglow is the largest live BFT redesign of 2026 and the empirical test of whether direct-vote-based protocols win over DAG approaches at high TPS / low latency in adversarial WAN conditions.

- **Bullshark / Narwhal / Tusk (Mysten Labs, 2022–2023).** The pre-Mysticeti DAG-BFT line. Narwhal separates data dissemination from consensus ordering; Bullshark adds zero-message-overhead consensus on top of the certified DAG. Worth understanding as the precursor to Mysticeti's uncertified DAG: Mysticeti's specific contribution is dropping the certification step Narwhal/Bullshark required. Why it matters for Tenzro: if `tenzro-consensus` moves DAG-ward, the design choice is whether to inherit certification (Bullshark-style, simpler safety analysis) or skip it (Mysticeti-style, lower latency at the cost of a more involved commit rule).

- **Raptr (Aptos, 2025).** Aptos Labs' announced "consensus layer for the global trading engine" — a DAG-BFT design optimized for sub-second finality at high throughput. Public technical details thin as of May 2026; worth tracking as a 2026 deployment of the Bullshark/Mysticeti family pattern in production.

### Networking and gossip

- **GossipSub v1.1 (Vyzovitis, Napora, McCormick, Dias, Psaras — Protocol Labs, 2020).** Mesh-based pub/sub overlay with score-based peer ranking, robust against eclipse and sybil attacks under the published threat model. Tenzro's libp2p stack uses GossipSub v1.1 for `tenzro/blocks`, `tenzro/transactions`, `tenzro/consensus`, etc. Why it matters: any consensus liveness improvement (reputation election, MonadBFT NEC) must compose with the gossip-layer score system — a validator who is "fast and online" at consensus but persistently scored low by GossipSub's peer-scoring is a contradiction worth flagging at runtime.

- **QUIC and PQ-hybrid Noise (libp2p WG, 2024–2026).** libp2p's Noise handshake is currently XX-pattern over X25519. The `xx-pq` draft adds an ML-KEM-768 + X25519 hybrid in the same handshake style as TLS 1.3's `0x11EC`. Adoption tracking: rust-libp2p, go-libp2p, js-libp2p all have open PRs as of Q1 2026; no production deployment yet. For Tenzro's agent-to-agent direct connections this is the path forward when libp2p WG ratifies.

### Decentralized AI training

- **DiLoCo (Douillard et al., arXiv:2311.08105, presented ICML 2024).** Local-SGD-style federated optimization where each worker runs many AdamW inner steps before exchanging outer-gradients (Nesterov momentum). On C4 with 8 workers, DiLoCo matches fully-synchronous SGD while communicating ~500× less. Why it matters for Tenzro: `tenzro-training`'s protocol layer (Rust) plus the Python reference trainer (PyTorch FSDP2 + Hivemind) is the DiLoCo lineage; OpenDiLoCo (Prime Intellect) is the production INTELLECT-1 / INTELLECT-3 implementation. Decoupled DiLoCo (Google, late 2025) extends the pattern to asynchronous "islands."

- **DisTrO (Nous Research, August 2024).** Distributed Training Over-The-Internet — a family of low-latency distributed optimizers that reduce inter-GPU communication by 3–4 orders of magnitude (74.4 GB → 86.8 MB per step in the Llama-2 benchmark, ≈857× efficiency vs. All-Reduce). Enables training across consumer 100 Mbps / 10 Mbps connections. Used in Nous's 15B-parameter open training run in late 2024. Why it matters for Tenzro: DisTrO and DiLoCo are the two production-scale "decentralized training works" demonstrations; Tenzro's protocol layer treats them as wire-compatible families rather than picking one.

- **PowerSGD (Vogels, Karimireddy, Jaggi, NeurIPS 2019).** Low-rank gradient compression for synchronous data-parallel training. Still cited in 2026 designs as the canonical compressor for outer-gradients in DiLoCo-style protocols (DisTrO's compression is more aggressive but PowerSGD's analysis is the reference).

- **INTELLECT-1 / INTELLECT-3 (Prime Intellect, 2024–2026; arXiv:2412.01152).** Production decentralized pretraining runs of 10B (INTELLECT-1) and ~70B (INTELLECT-3) parameter models across globally-distributed worker pools using OpenDiLoCo + PyTorch FSDP2. The technical reports are the existence proofs that the DiLoCo communication-reduction approach holds at scale; INTELLECT-1 reported reaching frontier-comparable training efficiency at >85% utilization over a 100 Mbps WAN. Why it matters for Tenzro: the protocol/trainer split (`tenzro-training` Rust + Python reference trainer) follows the same architectural decomposition as Prime Intellect's `protocol` crate; the gossip + aggregation rules are wire-compatible.

### MEV and ordering

- **Aequitas (Kelkar, Zhang, Goldfeder, Shi — arXiv:2009.04114; CRYPTO 2020).** First BFT protocol with **block-order-fairness**: if a sufficient majority of nodes received tx1 before tx2, that order is preserved in the final ordering. The Condorcet impossibility result rules out perfect receive-order-fairness; Aequitas defines a relaxed batch-order-fairness instead.

- **Themis (Kelkar et al., eprint 2021/1465; CCS 2023).** Improves Aequitas with graph-based deferred ordering, fixing a liveness bug and achieving practical performance on top of HotStuff. The reference paper for any "fair-ordering on a streamlined-BFT chain" design.

- **F3B (Flash Freezing Flash Boys).** Threshold-encrypt each transaction with a committee-held key; reveal the key only after ordering finalizes. Pivots from per-epoch encrypted-mempool designs (Shutter) to per-transaction privacy.

- **Helix.** Hybrid protocol combining fair ordering with threshold encryption on a synchronous fully-connected network; leader-based committee.

Why it matters for Tenzro: agent-driven inference markets are MEV-exposed in the same way DEX trades are. A naive sequencer can front-run an agent's "buy inference token from cheapest provider" call by reading the gossip before settlement. The fair-ordering literature (Themis, BlindPerm, F3B, Helix) is the candidate set if Tenzro's inference router becomes a credible MEV target; the entry cost is a per-transaction encrypted mempool, which is a meaningful change to gossip semantics and warrants its own design pass.

### Identity and credential schemes

- **W3C DID Core 1.0 / VC Data Model 2.0.** DID Core 1.0 has been a W3C Recommendation since 2022; the DID method registry at `w3c/did-extensions` is the canonical method index. VC Data Model 2.0 became a W3C Recommendation in 2025, adding presentation derivation, status lists 2021, and JWT-VC integration. Tenzro's `tenzro-identity` exports W3C-compliant DID Documents and VC envelopes; the `did:tenzro` registration is prepared at `docs/did-registration/` and pending PR submission.

- **ERC-8004 (Trustless Agents).** Final on Ethereum mainnet 2026-01-29, deployed across 20+ networks. Three registries: Identity (ERC-721 portable agent NFTs), Reputation (bounded-score feedback + categorical tags), Validation (request verification via stake-secured re-execution, zkML, or TEE oracles). Tenzro mirrors all three as native EVM precompiles (`0x101a`/`0x101b`/`0x101c`) with byte-identical selectors. Why it matters for Tenzro: post-quantum identity migration must preserve these on-chain registries — the precompiles wrap Ed25519/secp256k1 verification today; a hybrid path adds an ML-DSA-65 verifier alongside without breaking the existing calldata ABI.

## 5.8 Tenzro-Specific Implications

### Already shipped

- **Plonky3 over KoalaBear with FRI** in `tenzro-zk` — three production AIRs (inference, settlement, identity), pinned at `log_blowup=1, num_queries=64, query_pow=16, commit_pow=8`, git rev `32079474b1d31d9221656ae774afb322d2597db0`.
- **Validator key = Ed25519 + ML-DSA-65** in concatenated hybrid mode. Both signatures verified on every block-vote path. Keys persisted in the `tenzro-tenzro-rpc-keys` K8s secret per testnet deployment.
- **ML-KEM-768 + X25519 hybrid TLS** terminated by Caddy in front of `rpc.tenzro.network` and the other `*.tenzro.network` subdomains. Browser clients with Chrome 124+ negotiate `0x11EC` automatically.
- **Hybrid TEE-attested + ZK-of-commitment** verifiable inference via `tenzro_zk::tee_integration::{generate_tee_zk_proof, verify_tee_zk_proof}` — the TEE produces the AIR witness and runs the Plonky3 prover inside the enclave, signing the result with a hardware-rooted Ed25519 key.
- **Composite TEE attestation tokens** for TDX + NVIDIA H100/H200 CC via Intel Tiber Trust Authority `get_token_v2`, with full X.509 chain verification, COSE_Sign1 ES384 for Nitro, and ECDSA P-256 for TDX QE.

### Pending PQ work

- **PQ-safe vote aggregation.** `tenzro-consensus`'s `VoteCollector` currently aggregates over BLS12-381 (broken by Shor). Replacement options (§5.3): FROST-ML-DSA for small rotating committees; SNARK-aggregated ML-DSA via folding for the larger quorum. Interim mitigation: per-block hybrid attestation appended to each finalized block so a future BLS break cannot be retroactively exploited.
- **PQ-safe VRF.** `tenzro-crypto::vrf` is ECVRF-EDWARDS25519 per RFC 9381 — also Shor-vulnerable. Candidate replacements: hash-based VRF (e.g., LMS-derived) or lattice-based (e.g., Crystals-derived VRF constructions in active academic research). The VRF is consumed by NFT factory `mintRandom`, the dispute-committee selector, and (planned) reputation-weighted leader election; downstream consumers all care more about determinism than cryptographic non-malleability, so a hash-based replacement is likely.
- **FROST integration in `tenzro-crypto::mpc`.** Current state is Shamir SSS + reconstruct (keys assembled in cleartext at sign time — not a true threshold scheme). Replacement: FROST RFC 9591 for Ed25519 paths, CGGMP21 (Dfns / LFDT-Lockness, post-patch) for secp256k1 paths. Required before native wallets ship to end-users.
- **Reputation-weighted leader selection.** Replace round-robin `select_leader` in `tenzro-consensus` with the Aptos-style reputation formula (stake × commit-success × vote-success). Independent of any PQ work; high-leverage testnet-stability win.
- **MonadBFT NEC.** Optional addition once reputation-weighted election is in place: a leader who cannot recover the high-tip predecessor block requests an NEC from 2f+1 validators and proposes at the same height. Addresses a known intermittent stall mode.

### What the migration is *not*

A few things this section explicitly does **not** prescribe, with reasoning:

- **No move to a pairing-free curve for vote aggregation as an interim measure.** Replacing BLS12-381 with secp256k1 + Schnorr aggregation (MuSig2-style) is mathematically possible but yields no PQ benefit (secp256k1 is also Shor-broken) and loses aggregation succinctness. The only useful intermediate step is hybrid attestation alongside BLS; the actual replacement waits for PQ aggregation.
- **No SLH-DSA in the hot path.** SLH-DSA signatures (7–50 KB) and signing cost (10–100 ms) make it operationally infeasible for per-block consensus. It is the long-lived-root primitive: TEE binary signing, governance multisig root, genesis state attestation.
- **No "PQ wallets only" flag day for end-users.** The wallet stays Ed25519 + ML-DSA-65 hybrid at the protocol level; end-user signing flows go through FROST / CGGMP21 at the wallet layer. Migrating end users to PQ-only would orphan every existing wallet without operational benefit (the protocol's hybrid posture already covers the attack surface).
- **No replacement of the Plonky3 + KoalaBear choice.** SP1 / Risc0 / Jolt are noted in §5.4 as the alternatives Tenzro evaluated; the AIR-per-circuit approach for inference / settlement / identity is locked in. The next ZK design pass is *what new AIRs to write*, not *which proving system to use*.

The PQ-hybrid posture is already strictly stronger than every other live L1 we benchmark against — Tenzro shipped Ed25519 + ML-DSA-65 validator keys before Solana, Sui, Aptos, or Ethereum committed to a PQ migration calendar. The remaining gaps (aggregation, VRF, MPC) are the open work, sequenced through 2026 and into mainnet.

### Sequencing

| Quarter | Item | Crate(s) | Dependency |
|---|---|---|---|
| Q3 2026 | Reputation-weighted leader election | `tenzro-consensus` | None (independent of PQ work) |
| Q3 2026 | FROST-Ed25519 in `mpc` module | `tenzro-crypto`, `tenzro-wallet` | RFC 9591 reference impls audited |
| Q4 2026 | CGGMP21-secp256k1 for EVM bridge signing | `tenzro-crypto`, `tenzro-bridge` | Dfns/LFDT-Lockness crate stabilization |
| Q4 2026 | ERC-7579 SpendingLimit enforced at signing time | `tenzro-vm`, `tenzro-wallet` | Smart-account module wiring |
| Q1 2027 | MonadBFT NEC | `tenzro-consensus` | Reputation election in production |
| Q1 2027 | PQ-hybrid attestation at block-finalization boundary | `tenzro-consensus` | Per-block size budget verified |
| Q2 2027 | SNARK-aggregated ML-DSA vote aggregation | `tenzro-consensus`, `tenzro-zk` | Folding-based PQ aggregation matures upstream |
| Q2 2027 | SNARK-of-PRF VRF replacement | `tenzro-crypto`, `tenzro-vm` | Plonky3 AIR for hash-PRF |
| Q3 2027 | FN-DSA (Falcon) option for size-constrained signatures | `tenzro-crypto` | FIPS 206 final |
| Q4 2027 | Fair-ordering layer (Themis-derived) | `tenzro-consensus`, `tenzro-network` | Inference router MEV exposure measured |

The sequencing is deliberately conservative — each item lands on a known-stable upstream and a known-clean Tenzro dependency. The hard rule (CLAUDE.md): replace cleanly, no backward-compat shims, no deprecation paths. When BLS aggregation is replaced, BLS goes; when the legacy `mpc` module is replaced, it goes. Flag-day cutover is the model.

---

## Section 5 — Sources

### NIST PQC standards
1. [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (final)](https://csrc.nist.gov/pubs/fips/203/final)
2. [FIPS 203 PDF (NVL Publications)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf)
3. [Federal Register — Issuance of FIPS 203, 204, 205 (Aug 14, 2024)](https://www.federalregister.gov/documents/2024/08/14/2024-17956/announcing-issuance-of-federal-information-processing-standards-fips-fips-203-module-lattice-based)
4. [NIST press release — first 3 finalized PQ encryption standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
5. [CSRC — Post-Quantum Cryptography FIPS Approved (Aug 2024)](https://csrc.nist.gov/news/2024/postquantum-cryptography-fips-approved)
6. [FIPS 206 (FN-DSA / Falcon) status update — Perlner, NIST](https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf)
7. [CSRC — FIPS 206 FN-DSA presentation (2025)](https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon)
8. [Efficient Threshold ML-DSA up to 6 parties — NIST 6th PQC Conference](https://csrc.nist.gov/csrc/media/events/2025/sixth-pqc-standardization-conference/efficient%20threshold%20ml-dsa%20up%20to%206%20parties.pdf)

### TLS / SSH PQ hybrid deployment
9. [draft-ietf-tls-ecdhe-mlkem — Post-quantum hybrid ECDHE-MLKEM for TLS 1.3](https://datatracker.ietf.org/doc/draft-kwiatkowski-tls-ecdhe-mlkem/02/)
10. [Cloudflare — Post-quantum cryptography (PQC) docs](https://developers.cloudflare.com/ssl/post-quantum-cryptography/)
11. [Cloudflare TLS WG — Planned changes to PQ deployment (mail-archive)](https://www.mail-archive.com/tls@ietf.org/msg18105.html)
12. [OpenSSH — Post-Quantum Cryptography](https://www.openssh.org/pq.html)
13. [GitHub Engineering — Post-quantum SSH access](https://github.blog/engineering/platform-security/post-quantum-security-for-ssh-access-on-github/)
14. [OpenSSH 10.0 introduces default PQ key exchange — Quantum Computing Report](https://quantumcomputingreport.com/openssh-10-0-introduces-default-post-quantum-key-exchange-algorithm/)
15. [InfoQ — GitHub adds PQ-secure SSH (Oct 2025)](https://www.infoq.com/news/2025/10/github-post-quantun-ssh-key/)

### PQ-safe BFT / signature aggregation
16. [CAPSS — SNARK-friendly PQ signatures (eprint 2025/061)](https://eprint.iacr.org/2025/061)
17. [Loquat — SNARK-friendly PQ signature (eprint 2024/868)](https://eprint.iacr.org/2024/868)
18. [Ethereum PQ Interop #37 (issue ethereum/pm#2035, April 2026)](https://github.com/ethereum/pm/issues/2035)
19. [Post-Quantum Signature Aggregation: a Folding Approach — ethresear.ch](https://ethresear.ch/t/post-quantum-signature-aggregation-a-folding-approach/23639)
20. [Aggregating and Thresholdizing Hash-based Signatures using STARKs](https://www.researchgate.net/publication/360948276_Aggregating_and_Thresholdizing_Hash-based_Signatures_using_STARKs)

### ZK / zkVM
21. [Plonky3 — GitHub `Plonky3/Plonky3`](https://github.com/Plonky3/Plonky3)
22. [Polygon — Plonky3 production-ready announcement](https://polygon.technology/blog/polygon-plonky3-the-next-generation-of-zk-proving-systems-is-production-ready)
23. [Small Fields in Plonky3 — HackMD (Syxton)](https://hackmd.io/@Syxton/small_fields_in_plonky3)
24. [SP1 — GitHub `succinctlabs/sp1`](https://github.com/succinctlabs/sp1)
25. [Succinct — Introducing SP1](https://blog.succinct.xyz/introducing-sp1/)
26. [SP1 vs RISC Zero comparative analysis (Liu, Medium)](https://medium.com/@gwrx2005/comparative-analysis-of-sp1-and-risc-zero-zero-knowledge-virtual-machines-4abf806daa70)
27. [RISC-V ZKVMs — Argument Computer (Lurk Labs)](https://argument.xyz/blog/riscv-good-bad/)
28. [a16z crypto — FAQ on Jolt's initial implementation](https://a16zcrypto.com/posts/article/faqs-on-jolts-initial-implementation/)
29. [RISC Zero — Designing high-performance zkVMs](https://risczero.com/blog/designing-high-performance-zkVMs)

### TEE + ZK verifiable compute
30. [Apple Security — Private Cloud Compute](https://security.apple.com/blog/private-cloud-compute/)
31. [Intel Trust Authority — Attestation overview](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-attestation-overview.html)
32. [Phala — Decentralized Root of Trust](https://github.com/Phala-Network/phala-docs/blob/main/dstack/design-documents/decentralized-root-of-trust.md)
33. [Marlin Protocol](https://www.marlin.org/)
34. [EZKL — zkonduit/ezkl](https://github.com/zkonduit/ezkl)
35. [EZKL — Benchmarking ZKML Frameworks](https://blog.ezkl.xyz/post/benchmarks/)
36. [The Definitive Guide to ZKML 2025 — ICME](https://blog.icme.io/the-definitive-guide-to-zkml-2025/)
37. [The State of zkML — Spectral](https://blog.spectral.finance/the-state-of-zero-knowledge-machine-learning-zkml/)
38. [Worldcoin awesome-zkml](https://github.com/worldcoin/awesome-zkml)

### MPC / threshold signatures
39. [RFC 9591 — FROST: Flexible Round-Optimized Schnorr Threshold](https://datatracker.ietf.org/doc/html/rfc9591)
40. [RFC 9591 (rfc-editor)](https://www.rfc-editor.org/info/rfc9591)
41. [ZcashFoundation/frost — Rust implementation](https://github.com/ZcashFoundation/frost)
42. [taurushq-io/frost-ed25519](https://github.com/taurushq-io/frost-ed25519)
43. [Dfns — CGGMP21 in Rust](https://www.dfns.co/article/cggmp21-in-rust-at-last)
44. [LFDT-Lockness/cggmp21](https://github.com/LFDT-Lockness/cggmp21)
45. [Dfns — CGGMP21 Vulnerabilities Patched and Explained](https://www.dfns.co/article/cggmp21-vulnerabilities-patched-and-explained)
46. [Verichains — TSSHOCK disclosure](https://verichains.io/tsshock/)
47. [Fireblocks — BitForge (CVE-2023-33241) technical report](https://www.fireblocks.com/blog/gg18-and-gg20-paillier-key-vulnerability-technical-report)
48. [Safeheron — BitForge analysis](https://safeheron.com/blog/bitforge-vulnerability/)

### BFT consensus papers
49. [HotStuff-1: Linear Consensus with One-Phase Speculation (arXiv:2408.04728)](https://arxiv.org/abs/2408.04728)
50. [HotStuff-1 / Prefix Speculation Dilemma — Decentralized Thoughts](https://decentralizedthoughts.github.io/2024-08-24-hotstuff1/)
51. [Mysticeti: Reaching the Latency Limits with Uncertified DAGs — NDSS 2025](https://www.ndss-symposium.org/ndss-paper/mysticeti-reaching-the-latency-limits-with-uncertified-dags/)
52. [Mysticeti NDSS 2025 PDF](https://www.ndss-symposium.org/wp-content/uploads/2025-929-paper.pdf)
53. [MonadBFT: Fast, Responsive, Fork-Resistant Streamlined Consensus (arXiv:2502.20692)](https://arxiv.org/abs/2502.20692)
54. [MonadBFT — Stanford Blockchain Review #73](https://review.stanfordblockchain.xyz/p/73-unpacking-monadbft-fast-responsive)
55. [SIMD-0326 — Alpenglow Consensus Protocol (Solana)](https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0326-alpenglow.md)
56. [Solana Forum — SIMD-0326 discussion](https://forum.solana.com/t/simd-0326-proposal-for-the-new-alpenglow-consensus-protocol/4236)
57. [Aptos — Validator Nodes Overview (LeaderReputation)](https://aptos.dev/network/blockchain/validator-nodes)
58. [Aptos Validator Leaderboard / reputation metrics](https://aptos.dev/network/nodes/validator-node/verify-nodes/leaderboard-metrics)

### Decentralized AI training
59. [DiLoCo: Distributed Low-Communication Training (arXiv:2311.08105)](https://arxiv.org/abs/2311.08105)
60. [Google DeepMind — Decoupled DiLoCo](https://deepmind.google/blog/decoupled-diloco/)
61. [Prime Intellect — OpenDiLoCo](https://www.primeintellect.ai/blog/opendiloco)
62. [Nous DisTrO — GitHub](https://github.com/NousResearch/DisTrO)
63. [Nous DisTrO — preliminary report site](https://distro.nousresearch.com/)
64. [PowerSGD — Vogels, Karimireddy, Jaggi (NeurIPS 2019)](https://arxiv.org/abs/1905.13727)

### MEV / fair ordering
65. [Themis — Fast, Strong Order-Fairness (eprint 2021/1465)](https://eprint.iacr.org/2021/1465.pdf)
66. [Aequitas — Order-Fairness for Byzantine Consensus (eprint 2020/269)](https://eprint.iacr.org/2020/269.pdf)
67. [BlindPerm — Encrypted Mempool + Permutation (eprint 2023/1061)](https://eprint.iacr.org/2023/1061.pdf)
68. [F3B — Flash Freezing Flash Boys (CoinTelegraph Research)](https://cointelegraph.com/research/flash-freezing-flash-boys-per-transaction-encryption-to-fight-malicious-mev)
69. [MEV Mitigation Survey (arXiv:2407.19572)](https://arxiv.org/html/2407.19572v1)

### Identity, networking, and miscellaneous
70. [W3C DID Core 1.0 Recommendation](https://www.w3.org/TR/did-core/)
71. [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
72. [ERC-8004: Trustless Agents — EIP](https://eips.ethereum.org/EIPS/eip-8004)
73. [ERC-7579 Modular Accounts](https://eips.ethereum.org/EIPS/eip-7579)
74. [ERC-4337 v0.8 — Account Abstraction](https://eips.ethereum.org/EIPS/eip-4337)
75. [INTELLECT-1 technical report (arXiv:2412.01152)](https://arxiv.org/abs/2412.01152)
76. [GossipSub v1.1 specification (libp2p)](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md)
77. [STIR — Reducing Proof Size for STARKs (Arnon et al., 2024)](https://eprint.iacr.org/2024/390)
78. [WHIR — Successor to STIR (Arnon et al., 2025)](https://eprint.iacr.org/2024/1586)
79. [X-Wing — General-purpose ML-KEM + X25519 combiner](https://eprint.iacr.org/2024/039)
80. [PowerSGD: Practical Low-Rank Gradient Compression (arXiv:1905.13727)](https://arxiv.org/abs/1905.13727)
