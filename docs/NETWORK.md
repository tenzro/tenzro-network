# Tenzro Network

**The decentralized networking layer of Tenzro — peer discovery, message propagation, NAT traversal, request/response protocols, validator authentication, and the dual control / data planes.**

---

## Abstract

A coordination layer is only as good as the substrate underneath it. Tenzro Network is the protocol layer that lets thousands of independently operated peers — validators, model providers, compute providers, storage providers, TEE providers, light clients, agents behind home / mobile / corporate NAT — find each other, propagate messages efficiently, distinguish validator traffic from non-validator traffic, and exchange large content-addressed payloads without going through a central broker. A single peer can take on several of these roles at once against one stake; the roles describe what a node serves, not how many nodes there are.

The design has two planes. The **control plane** (`tenzro-network`) is libp2p — gossipsub for topic-based pub/sub, Kademlia DHT for peer discovery, request/response protocols for direct exchanges (block sync, consensus messages, MPC relay), Identify for protocol negotiation, AutoNAT v2 + Circuit-Relay v2 + DCUtR for NAT traversal. The **data plane** (`tenzro-iroh`) is iroh — content-addressed transport over QUIC, used for model weights, training gradients, sealed shards, agent memory archives, and A2A + MCP-over-iroh ALPNs.

Both planes share peer identity. A node's libp2p peer ID and its iroh `EndpointId` are both derived from its TDIP Ed25519 key, so authentication on one plane carries to the other.

This document covers the wire protocols, the topics, the NAT traversal stack, the validator-authorization model, the iroh data plane, and the bootstrap path.

---

## 1. The two planes

### Control plane — `tenzro-network`

Built on `libp2p` 0.56. Wraps the standard libp2p protocols into a single `TenzroBehaviour` struct that the node embeds in its swarm:

- **`gossipsub`** — pub/sub messaging (`gossipsub::Behaviour`)
- **`kademlia`** — DHT for peer discovery (`kad::Behaviour<MemoryStore>`) on protocol `/tenzro/kad`
- **`identify`** — peer information exchange
- **`ping`** — connection keep-alive and RTT measurement
- **`connection_limits`** — per-peer connection caps (closes the unbounded-connection DoS vector)
- **`allow_block_list`** — permanent ban list for byzantine peers
- **`block_sync`** — request/response on `/tenzro/block-sync/1.0.0`, used by lagging nodes to catch up without relying on gossipsub backfill
- **`consensus_direct`** — request/response on `/tenzro/consensus-direct/1.0.0`, carries HotStuff-2 votes and quorum certificates between validators with bounded latency
- **`mpc_relay`** — request/response on `/tenzro/mpc/req-resp/1.0.0` plus gossipsub topic `/tenzro/mpc/session/<instance_id>`, carries DKLS23 round messages
- **`relay`** + **`autonat`** + **`dcutr`** — NAT traversal stack (server halves on validators with confirmed public addresses; client halves on joiners behind NAT)

### Data plane — `tenzro-iroh`

A single `iroh::Endpoint` per node carries every content-addressed payload Tenzro moves between peers:

- **DA backend** — receipts that exceed the inline-payload bound get offloaded to iroh-blobs, with the canonical SHA-256 hash recorded in the receipt envelope and the iroh BLAKE3 hash recorded as the locator
- **Gradient store** — outer-gradient safetensors blobs for Tenzro Train, distributed peer-to-peer between trainers and the syncer
- **Sealed-shard store** — HPKE-wrapped data shards for confidential training (Phase B2)
- **Agent memory archives** — `MemoryManager::archive()` submits the canonical payload to iroh-blobs when the resolver is bound, falling back to the inline backend otherwise
- **Model-weight distribution** — `BlobFetcher` trait with `IrohBlobFetcher` adapter; provider downloads are peer-first via `PeerHint`, fall back to HuggingFace Hub
- **A2A and MCP over iroh** — two ALPNs on the shared endpoint: `tenzro/a2a` for A2A JSON-RPC 2.0 (peer-to-peer agent), `tenzro/mcp` for MCP Streamable HTTP JSON-RPC 2.0 (tool invocation)
- **Direct `tenzro://blob/<hash>` URI fetches** — the same endpoint services any URI lookup

The data plane lets agents on a public network connect peer-to-peer without an HTTP router in the middle and without trusting a central content service.

---

## 2. Gossipsub topics

The control plane carries thirteen topics built on top of `gossipsub` with a hardened configuration (Strict validation mode, 1 MiB max message size, mesh degree D=8, peer scoring enabled).

| Topic | Producer | Consumer | Validator-only |
|---|---|---|---|
| `tenzro/blocks` | leader / proposer | every node | yes |
| `tenzro/transactions` | wallets / agents | every node | no |
| `tenzro/consensus` | every validator | every validator | yes |
| `tenzro/attestations` | TEE providers, light clients | every node | no |
| `tenzro/models` | model providers | every node | no |
| `tenzro/inference` | inference clients | model providers | no |
| `tenzro/status` | every node | every node | no |
| `tenzro/agents` | agents | agents and clients | no |
| `tenzro/providers` | any provider role | discovery clients | no |
| `tenzro/cortex` | Cortex workers | reasoning-depth router | no |
| `tenzro/training` | trainers + syncer | every training participant | no |
| `tenzro/training/syncer` | witness committee | training participants | no |
| `/tenzro/mpc/session/<instance_id>` | DKLS23 round participants | session participants | no |

Validator-only topics enforce origin on the receive side: `ValidatorRegistry::is_validator(peer_id)` is consulted before a `tenzro/blocks` or `tenzro/consensus` message is admitted. Non-validators that publish on these topics get their messages dropped.

Model and provider announcements are authenticated independently of the validator gate. Messages on `tenzro/models` and `tenzro/providers` carry the announcing node's Ed25519 public key and a signature over a canonical preimage of their routable fields. Each message is verified on ingest against the embedded key; unsigned or tampered announcements are dropped before they reach the discovery index. Model announcements additionally advertise `weights_sha256`, a streaming SHA-256 of the served on-disk weights, so consumers can detect weight substitution before routing inference to a provider.

---

## 3. NAT traversal

Most home, mobile, and corporate networks are behind NAT. Tenzro composes Circuit-Relay v2, AutoNAT v2, and DCUtR in `TenzroBehaviour`. The composition lets community nodes participate from any consumer connection without operator intervention.

- **Validators with a confirmed public address** run the **server** halves of `relay::Behaviour` and `autonat::v2::server::Behaviour`. They serve as relay hops and AutoNAT dial-back probes for the rest of the network.
- **Joiners (LightClient / ModelProvider / TeeProvider)** run the **client** halves — `relay::client::Behaviour`, `autonat::v2::client::Behaviour`, and `dcutr::Behaviour`. AutoNAT v2 confirms reachability. When direct connection fails, DCUtR attempts hole-punching. The final fallback is `/p2p-circuit` through a relay validator.

Driven by `NetworkConfig::enable_relay` (server side, default-on for `Validator` role) and `NetworkConfig::enable_hole_punching` (client side, default-on for every role). All five sub-behaviours are wrapped in libp2p `Toggle` so disabled halves are no-ops without bifurcating the `NetworkBehaviour` type.

By default every node binds both `/ip4/0.0.0.0/tcp/9000` and `/ip4/0.0.0.0/udp/9000/quic-v1` — the universal transport set that lets cloud VMs, residential WiFi, mobile devices, and embedded boards reach the network through whichever transport NAT permits. Identify observed-address discovery gives a node its own external address as a tally of what peers report seeing.

---

## 4. Validator authentication

The protocol distinguishes validator and non-validator traffic at the topic level. The mechanism is the `ValidatorRegistry` trait:

```rust
pub trait ValidatorRegistry: Send + Sync {
    fn is_validator(&self, peer_id: &PeerId) -> bool;
    fn validator_peer_ids(&self) -> HashSet<PeerId>;
    fn authorize_peer_for_topic(&self, peer_id: &PeerId, topic: &str) -> bool;
    // ...
}
```

The node-side implementation (`NodeValidatorRegistry`) walks the on-chain validator set for the current epoch and answers `is_validator()` against it. It also handles the case where a validator dynamically rotates its libp2p peer ID by participating in the standard Identify handshake.

Validator-only topics (`tenzro/blocks`, `tenzro/consensus`, `tenzro/attestations` when carrying validator-side attestations) gate inbound messages through `authorize_peer_for_topic()`. A message from a peer that's not a current validator is dropped before it reaches the consensus engine. This keeps the network's consensus-critical paths free of unauthorized traffic without requiring per-message signature verification.

The same authorization gate covers the consensus-direct request/response protocol — only validators are admitted as peers on `/tenzro/consensus-direct/1.0.0`.

---

## 5. Request/response protocols

Some message flows are too sensitive to gossipsub's lossy fanout. Tenzro carries them through libp2p request/response with explicit per-protocol concurrency limits.

- **`/tenzro/block-sync/1.0.0`** — a lagging node requests a contiguous range of blocks from a chosen peer. The provider streams the response in framed chunks. Modeled on Sui's `state_sync` and Aptos's `storage-service`. The wire types live in `block_sync_proto.rs`.
- **`/tenzro/consensus-direct/1.0.0`** — validators exchange HotStuff-2 vote messages and quorum certificates directly without going through gossipsub. Bounded latency, validator-only.
- **`/tenzro/mpc/req-resp/1.0.0`** — DKLS23 round messages between MPC committee members. Pairs with the `/tenzro/mpc/session/<instance_id>` gossipsub topic for broadcast rounds.
- **`/tenzro/cluster-tunnel/1.0.0`** — the authenticated transport for intra-cluster pipeline traffic. A LAN cluster head opens one tunnel session per member; framed payloads carry the ggml RPC byte stream between the head's loopback bridge and the member's loopback `rpc-server` (see AI.md §3.5). The member never binds its `rpc-server` on a network interface — the tunnel is the only way in, so the unauthenticated RPC protocol is wrapped in libp2p's authenticated transport. Sessions are demultiplexed by a session id carried on each frame; one request-response pair is full-duplex with return bytes piggybacked on the acknowledgement.
- **`/tenzro/da/committee/1.0.0`** — the committee-resident data-availability store. A writer sends `StoreSliver` to each committee member ("hold this erasure-coded sliver for this blob commitment") and the member replies with a signed attestation of custody; a reader sends `FetchSliver` and the member returns the sliver it holds (or `None`). Slivers and encoding shapes travel as opaque bincode blobs because `tenzro-network` does not depend on `tenzro-storage` — the node-layer adapter does the typed encode/decode. 16 MiB request/response cap. The wire types live in `da_committee_relay.rs`.

Each protocol uses a separate `request_response::Behaviour` instance with its own codec and concurrency cap.

---

## 6. Peer discovery and bootstrap

A new node finds the network through a multi-source bootstrap path:

- **Explicit `--boot-nodes`** — a comma-separated list of libp2p multiaddrs and peer IDs. Authoritative and direct.
- **`--bootstrap-dns <base>`** — DNS-based discovery. The node resolves `_tenzro-boot._tcp.<base>` SRV records to a set of `(priority, weight, port, target)` tuples, then resolves each target's TXT records to obtain its libp2p peer ID. Rotating a boot validator's identity is a zone edit, not a fleet-wide wrapper update.
- **Kademlia DHT** — once an initial connection is established, Kademlia handles ongoing peer discovery. The protocol id is `/tenzro/kad` so Tenzro peers don't accidentally exchange routing tables with other libp2p networks.
- **Identify observed_addr tally** — Identify reports back what a peer sees as the local node's external address. With N≥3 confirmations from independent peers, the node treats the address as confirmed and updates its `external_addrs` so future Identify exchanges propagate the address forward.

The result is permissionless joining: a node with the binary, the genesis, and a DNS name (or one explicit peer) becomes a network participant without any operator-side allowlisting.

### mDNS local discovery and `LocalPeerSet`

The four sources above find peers across the WAN. On the local segment a node also runs libp2p mDNS inside `TenzroBehaviour`, so machines on the same LAN find each other with zero configuration — no boot node, no DNS, no DHT round. This is the discovery substrate for two local-network features: forming a LAN cluster that jointly serves an oversized model (see AI.md §3.5), and preferring a local provider when one is present.

mDNS results are tracked in a `LocalPeerSet` — a concurrent set of peer IDs the node currently sees on its local segment. The mDNS `Discovered` event inserts a peer; the `Expired` event removes it. Membership is one orthogonal signal layered onto the existing reachability tier: a peer can be both WAN-reachable and local-direct, and local-direct membership is what marks it eligible to carry per-token cluster pipeline traffic.

`LocalPeerSet` is exposed up the stack — `TenzroNetworkService::local_peers()` → `Node::local_peers()` — so the routing and orchestration layers can consult it without re-deriving membership.

An AI-serving node willing to join LAN clusters attaches a `ClusterProfile { llama_commit, backend, cap_key }` to its periodic provider announcement. This is what lets a cluster head auto-discover members from gossip rather than requiring a hand-supplied roster (see AI.md §3.5): the head folds every provider that advertised a `ClusterProfile`, plus itself, into the planner. A node that omits the field is never auto-clustered. No serving socket is advertised — the head reaches each member's loopback `rpc-server` over the `/tenzro/cluster-tunnel/1.0.0` protocol keyed by the announcing peer's id.

### Local-first routing

When a node resolves which provider serves a request (`resolve_execution`), a provider that is a current `LocalPeerSet` member is preferred over an equally-capable remote provider. The preference is a prefer-local-with-fallback ordering, not a hard pin: the resolver sorts candidates by `(is_local, reachability_rank)`, so a local provider wins ties but the request still falls back to the best remote provider when no local one is eligible. This mirrors Kubernetes `trafficDistribution: PreferSameZone` (prefer-local, fall back to anywhere) rather than the request-dropping `internalTrafficPolicy: Local`. Local-first keeps latency and egress low when capacity exists nearby, without ever stranding a request that only a remote provider can serve.

---

## 7. iroh data plane in depth

The iroh endpoint is constructed by `TenzroIrohConfig::bind_with_config`. Three properties make it the right substrate for Tenzro's content-addressed traffic:

- **TDIP-anchored peer identity.** The iroh `EndpointId` is byte-identical to the node's TDIP Ed25519 public key when `secret_key_seed` is supplied in the config. This means a node's libp2p peer ID and its iroh peer id derive from the same root, so authentication on one plane carries to the other.
- **Pkarr discovery.** When `pkarr_relay_url` is set (e.g. `https://pkarr.tenzro.network/`), the iroh endpoint publishes its `(EndpointId, AddrInfo)` to the Tenzro-operated Pkarr relay using its TDIP secret key. Resolution flows through the same relay. Local-dev falls back to n0's default `dns.iroh.link/pkarr` when no Tenzro relay is configured.
- **Single shared endpoint.** All iroh-anchored Tenzro traffic — DA, gradient store, sealed-shard store, agent-memory archive, model-weight distribution, A2A-over-iroh, MCP-over-iroh, direct `tenzro://blob/<hash>` lookups — share one endpoint. One ALPN per protocol, one hash space (BLAKE3 indexed by iroh-blobs, SHA-256 indexed by Tenzro's higher-level receipt schema).

### URI scheme

All iroh-served content addresses through the `tenzro://` URI scheme:

| URI form | Resolver | Use |
|---|---|---|
| `tenzro://blob/<blake3-hex>` | `IrohBackedResolver::fetch_bytes` | Raw content-addressed blob |
| `tenzro://node/<endpoint-id>/...` | iroh QUIC dial | Direct peer dial |
| `tenzro://did/<did>` | TDIP resolver | DID resolution |
| `tenzro://model/<model-id>` | model registry | Model artifact lookup |
| `tenzro://gradient/<sha256-hex>` | `IrohGradientStore::fetch` | Outer-gradient retrieval |
| `tenzro://shard/<sha256-hex>` | `IrohSealedShardStore::fetch` | Sealed training shard |
| `tenzro://manifest/<sha256-hex>` | training manifest store | Sealed dataset manifest |
| `tenzro://memory/<sha256-hex>` | agent memory DA | Archived memory record |
| `tenzro://receipt/<sha256-hex>` | DA backend | Off-chain settlement receipt |

The transport is hidden behind the scheme — callers do not write `iroh://` URIs.

---

## 8. Roles

The node binary `tenzro-node` ships four roles, all running the same wire protocol:

- **`Validator`** — produces blocks, runs HotStuff-2 consensus, gets the 1.5× multiplier on leader-selection draw when TEE-attested. Runs the server halves of relay + AutoNAT for community joiners.
- **`ModelProvider`** — serves AI inference (chat / multi-modal / MoE expert shards / MTP). Subscribes to `tenzro/inference` and `tenzro/models`. Bonds optionally; bond required for Verified / Confidential tiers.
- **`TeeProvider`** — serves confidential compute, custody, attested execution. Carries the `Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA GPU CC / Intel Tiber` attestation chain.
- **`LightClient`** — consumes the network without producing. Subscribes to the topics it cares about, dials specific request/response endpoints as needed. Default role for `tenzro join` clients.

All four are real binaries — the same `tenzro-node` differentiated by `--role`. There is no RPC-only mode; the public RPC pod is a validator with extra HTTP / MCP / A2A exposure.

---

## 9. The agent transport surface

Agents on Tenzro coordinate through MCP and A2A. Both are exposed two ways:

- **HTTP** — the canonical `tenzro-node` MCP server on port 3001 (Streamable HTTP) and A2A server on port 3002 (JSON-RPC 2.0 + SSE). Any MCP- or A2A-compatible client can dial them.
- **iroh QUIC** — dedicated ALPNs `tenzro/a2a` and `tenzro/mcp` on the shared iroh endpoint. Each inbound bi-directional stream becomes a full agent session. The wire format is newline-delimited JSON-RPC — the same shape an MCP stdio client speaks — wrapped in a length-prefixed bidirectional QUIC stream.

The iroh path matters when two agents prefer content-addressed peer transport: no HTTP router in the middle, no public IP requirement, the agent's TDIP key authenticates the session, and the data plane is encrypted by QUIC.s built-in TLS 1.3.

---

## 10. Storage and durability

Every node persists its block history, state, and per-subsystem data through RocksDB column families. The column families relevant to networking and the agent surface:

- `CF_BLOCKS` — finalized blocks
- `CF_STATE` — VM state (Merkle Patricia Trie)
- `CF_METADATA` — chain id, genesis hash, configured weak-subjectivity anchor
- `CF_VALIDATOR_MODULES` — ERC-7579 validator modules per smart account
- `CF_AGENTS` — agent registry
- `CF_MODELS` / `CF_MODEL_SERVICES` — model catalog and provider serving declarations
- `CF_PROVIDERS` — provider registry
- `CF_BRIDGE_ANALYTICS` — per-tenant cross-chain compute-unit attribution
- `CF_CANTON_ANALYTICS` — per-tenant Canton call counters
- `CF_API_KEYS` — `tnz_...` API key registry
- `CF_MPC_KEYSHARES` — TEE-sealed DKLS23 keyshares (each node stores only its own share)
- `CF_TRAINING_RUNS` / `CF_TRAINING_RECEIPTS` / `CF_TRAINING_MANIFESTS` — Tenzro Train state
- `CF_AUDIT` — equivocation evidence

Durable writes go through `write_batch_sync` with `fdatasync`. Block writes are atomic. Auto-repair handles WAL corruption on startup. Snapshot bootstrap is cryptographically anchored — the joining node specifies a block hash it trusts; the snapshot must hash to that root or the bootstrap aborts.

---

## 11. Observability

Every node exposes a Prometheus `/metrics` endpoint with per-subsystem counters. Network-side metrics include:

- `tenzro_gossipsub_messages_published_total` / `_received_total` per topic
- `tenzro_request_response_inflight` per protocol
- `tenzro_libp2p_connections` (gauge), `tenzro_libp2p_dials_total` / `_failed_total`
- `tenzro_kademlia_peers_in_routing_table` (gauge)
- `tenzro_validator_peer_count` (gauge)
- `tenzro_workflow_canton_mirrored_total` (gauge — workflows with a Canton mirror)
- `tenzro_block_sync_blocks_served_total` / `_blocks_received_total`
- `tenzro_consensus_direct_messages_sent_total` / `_received_total`

These Prometheus metrics let operators monitor mesh size, validator reachability, request/response saturation, and gossipsub message rate per topic.

---

## 12. Security properties

- **Validator-only topic enforcement.** Consensus, block, and validator-side attestation traffic is gated through `ValidatorRegistry::authorize_peer_for_topic`. Non-validators that try to publish on these topics see their messages dropped before consensus inspects them.
- **Connection caps.** `connection_limits::Behaviour` caps inbound and outbound connections per peer, closing the unbounded-connection DoS vector.
- **Permanent ban list.** `allow_block_list::Behaviour<BlockedPeers>` permanently bans byzantine peers — equivocators, repeat policy violators, sybils caught attempting double-vote.
- **Hybrid PQ signatures.** Every safety-critical message — consensus votes, quorum certificates, equivocation evidence — carries an Ed25519 + ML-DSA-65 + BLS12-381 hybrid signature. An attacker would have to defeat all three legs to forge.
- **Snapshot anchoring.** Fast-sync requires the joining node to specify a block hash it trusts. The snapshot must hash to that root bit-for-bit or the bootstrap aborts. New validators do not silently adopt a hostile fork.
- **TDIP-anchored iroh identity.** A node's iroh `EndpointId` is byte-identical to its TDIP Ed25519 public key. Authentication on the libp2p plane carries to the iroh plane.

---

## 13. Reference

- Crates: `tenzro-network`, `tenzro-iroh`
- Behaviour composition: `crates/tenzro-network/src/behaviour.rs::TenzroBehaviour`
- Validator authentication: `crates/tenzro-network/src/peer_manager.rs::ValidatorRegistry`
- Gossipsub topics: `crates/tenzro-network/src/gossip.rs`
- Wire protocols: `crates/tenzro-network/src/{block_sync_proto, consensus_direct_proto, mpc_relay, da_committee_relay}.rs`
- Bootstrap DNS: `crates/tenzro-node/src/bootstrap_dns.rs`
- Iroh config: `crates/tenzro-iroh/src/config.rs::TenzroIrohConfig`
- Iroh A2A + MCP ALPNs: `crates/tenzro-iroh/src/jsonrpc.rs`, `crates/tenzro-iroh/src/lib.rs`

For the consensus algorithm that runs over this network layer, see [`SPECIFICATION.md`](SPECIFICATION.md) §5. For the agent surfaces (MCP / A2A) that ride this network layer, see [`SPECIFICATION.md`](SPECIFICATION.md) §14. For the AI workloads (inference, MoE, training) carried over this network layer, see [`AI.md`](AI.md).
