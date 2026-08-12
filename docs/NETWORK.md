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
- **Confined shell over iroh** — `tenzro/shell` carries an interactive session against hardware a renter leased. No inbound port is opened: the session rides a connection the node already established, which is the move GCP's IAP and AWS's SSM Session Manager make. The ALPN is advertised only when a handler is installed and a confinement boundary is configured
- **Direct `tenzro://blob/<hash>` URI fetches** — the same endpoint services any URI lookup

The data plane lets agents on a public network connect peer-to-peer without an HTTP router in the middle and without trusting a central content service.

---

## 2. Gossipsub topics

The control plane carries fifteen topics built on top of `gossipsub` with a hardened configuration (Strict validation mode, 1 MiB max message size, mesh degree D=8, peer scoring enabled).

| Topic | Producer | Consumer | Validator-only |
|---|---|---|---|
| `tenzro/blocks` | leader / proposer | every node | yes |
| `tenzro/transactions` | wallets / agents | every node | no |
| `tenzro/consensus` | every validator | every validator | yes |
| `tenzro/batches` | any validator (batch producer) | every validator | yes |
| `tenzro/attestations` | TEE providers, light clients | every node | no |
| `tenzro/models` | model providers | every node | no |
| `tenzro/inference` | inference clients | model providers | no |
| `tenzro/status` | every node | every node | no |
| `tenzro/agents` | agents | agents and clients | no |
| `tenzro/providers` | any provider role | discovery clients | no |
| `tenzro/cortex` | Cortex workers | reasoning-depth router | no |
| `tenzro/training` | trainers + syncer | every training participant | no |
| `tenzro/training/syncer` | witness committee | training participants | no |
| `tenzro/media-gen` | requesters + media workers | enrolled media workers | no |
| `/tenzro/mpc/session/<instance_id>` | DKLS23 round participants | session participants | no |

Validator-only topics enforce origin on the receive side: `ValidatorRegistry::is_validator(peer_id)` is consulted before a `tenzro/blocks`, `tenzro/consensus`, or `tenzro/batches` message is admitted. Non-validators that publish on these topics get their messages dropped.

The `tenzro/batches` topic carries the availability-dissemination plane that decouples transaction data from ordering. A batch producer broadcasts a batch body; validators that store it return a signed availability acknowledgment; the producer aggregates 2f+1 stake-weight of acknowledgments into a BLS availability certificate. The ordering path then references certified batches by hash instead of carrying full transaction bodies, so leader bandwidth on the ordering path scales with the number of certificates rather than block size. Three message shapes travel on the topic — batch bodies, availability acknowledgments/certificates, and body requests (for a peer that holds a certificate but not the body). Above a validator-count activation threshold, batch bodies are erasure-coded so no single node fans the full body out to every peer.

Model and provider announcements are authenticated independently of the validator gate. Messages on `tenzro/models` and `tenzro/providers` carry the announcing node's Ed25519 public key and a signature over a canonical preimage of their routable fields. Each message is verified on ingest against the embedded key; unsigned or tampered announcements are dropped before they reach the discovery index. Model announcements additionally advertise `weights_sha256`, a streaming SHA-256 of the served on-disk weights, so consumers can detect weight substitution before routing inference to a provider.

---

## 3. NAT traversal

Most home, mobile, and corporate networks are behind NAT. Tenzro composes Circuit-Relay v2, AutoNAT v2, and DCUtR in `TenzroBehaviour`. The composition lets community nodes participate from any consumer connection without operator intervention.

- **Validators with a confirmed public address** run the **server** halves of `relay::Behaviour` and `autonat::v2::server::Behaviour`. They serve as relay hops and AutoNAT dial-back probes for the rest of the network.
- **Joiners (LightClient / ModelProvider / TeeProvider)** run the **client** halves — `relay::client::Behaviour`, `autonat::v2::client::Behaviour`, and `dcutr::Behaviour`. AutoNAT v2 confirms reachability. When direct connection fails, DCUtR attempts hole-punching. The final fallback is `/p2p-circuit` through a relay validator.

Driven by `NetworkConfig::enable_relay` (server side, default-on for `Validator` role) and `NetworkConfig::enable_hole_punching` (client side, default-on for every role). All five sub-behaviours are wrapped in libp2p `Toggle` so disabled halves are no-ops without bifurcating the `NetworkBehaviour` type.

### Runtime-adaptive traversal

Wiring the client behaviours is not enough — a NAT'd node still has to *act* on its reachability as it changes. Two runtime decisions close the loop, both keyed off the reachability tracker's tier (`Unknown` → `Private` → `Direct`):

- **Kademlia mode promotion.** A node behind NAT starts Kademlia in **Client** mode. In Server mode it would advertise records that other peers cannot validate via dial-back, polluting their k-buckets. Once the reachability tracker reports sustained `Direct`, the node promotes itself to **Server** mode (`maybe_promote_kad_to_server`), called from the AutoNAT-client and DCUtR success handlers. Validators with a confirmed public address start directly in Server. Setting Server mode is idempotent, so repeated confirmations are no-ops.
- **Relay reservation booking.** Constructing the relay-client behaviour does not itself book a slot — libp2p's relay-client treats `Swarm::listen_on(<relay-addr>/p2p-circuit)` as the reservation request. During the Identify handshake, a non-`Direct` node that meets a peer advertising the relay HOP protocol (`/libp2p/circuit/relay/0.2.0/hop`) on a globally-routable address books a reservation on it. The attempt is gated three ways: only when our own tier is not `Direct` (a public node would burn a relay slot a NAT'd peer needs), only against a HOP-advertising peer on a globally-routable address (a LAN reservation produces an unreachable circuit), and idempotently per peer (tracked in `attempted_relay_reservations`, cleared on relay-lost). With a reservation booked, peers reach the edge node through `/p2p-circuit` and DCUtR has a relayed connection to upgrade to a direct one via hole-punching.

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

- **`/tenzro/block-sync/1.0.0`** — a lagging node requests a contiguous range of blocks from a chosen peer. The provider streams the response in framed chunks. A standard state-sync / storage-service protocol. The wire types live in `block_sync_proto.rs`.
- **`/tenzro/consensus-direct/1.0.0`** — validators exchange HotStuff-2 vote messages and quorum certificates directly without going through gossipsub. Bounded latency, validator-only.
- **`/tenzro/mpc/req-resp/1.0.0`** — DKLS23 round messages between MPC committee members. Pairs with the `/tenzro/mpc/session/<instance_id>` gossipsub topic for broadcast rounds.
- **`/tenzro/cluster-tunnel/1.0.0`** — the authenticated transport for intra-cluster pipeline traffic. A LAN cluster head opens one tunnel session per member; framed payloads carry the ggml RPC byte stream between the head's loopback bridge and the member's loopback `rpc-server` (see AI.md §3.5). The member never binds its `rpc-server` on a network interface — the tunnel is the only way in, so the unauthenticated RPC protocol is wrapped in libp2p's authenticated transport. Sessions are demultiplexed by a session id carried on each frame; one request-response pair is full-duplex with return bytes piggybacked on the acknowledgement.
- **`/tenzro/da/committee/1.0.0`** — the committee-resident data-availability store. A writer sends `StoreSliver` to each committee member ("hold this erasure-coded sliver for this blob commitment") and the member replies with a signed attestation of custody; a reader sends `FetchSliver` and the member returns the sliver it holds (or `None`). A challenger sends `ChallengeSliver` with a random 32-byte nonce and the member must reply with its full sliver plus an Ed25519 signature binding the nonce — the challenger re-verifies the sliver against the blob commitment, so a member cannot pass a possession challenge with cached metadata. Every resolution feeds the target's rolling 0–1000 availability score (+1 pass, −5 silence or honest not-held, −25 bad proof); each validator also runs a background auditor that challenges one random certificate attester every 10 minutes. Slivers and encoding shapes travel as opaque bincode blobs because `tenzro-network` does not depend on `tenzro-storage` — the node-layer adapter does the typed encode/decode. 16 MiB request/response cap. The wire types live in `da_committee_relay.rs`; challenge issuance, scoring, and persistence live in the node adapter (`da_committee.rs`), surfaced over `tenzro_daChallenge` / `tenzro_daListChallenges` / `tenzro_daAvailability` / `tenzro_daCommittee` / `tenzro_daListBlobs`, the matching MCP tools, and `tenzro da`.

Each protocol uses a separate `request_response::Behaviour` instance with its own codec and concurrency cap.

### Measured DA committee throughput

Two measurements pin down what the committee-resident DA path costs, both run on an `n1-highcpu-32` worker via `cloudbuild-da-committee-bench.yaml` (nothing touches the testnet):

**Sustained-write pipeline** (`cargo test -p tenzro-node --release --test da_committee_load -- --ignored --nocapture`) drives the full `DaCommitteeBackend` writer path per blob — 2D Reed-Solomon encode, per-member bincode wire framing, Merkle proof verification at each member, Ed25519 custody attestation, per-member RocksDB persistence, and 2f+1 quorum certificate assembly — over an in-process mesh that keeps every cost of the `/tenzro/da/committee/1.0.0` wire path except the socket. 96 × 1 MiB blobs per committee size:

| Committee | Write | Write p50 / p95 | Fetch (reconstruct) | Fetch p50 |
|---|---|---|---|---|
| n=4 | 17.8 MiB/s | 54.9 / 56.8 ms | 11.7 MiB/s | 85.5 ms |
| n=10 | 13.4 MiB/s | 72.5 / 75.9 ms | 8.1 MiB/s | 120.0 ms |

These are **single-writer** figures — the upper bound the coding/signing/persistence pipeline imposes before network latency. Blobs are independent, so aggregate ingest scales with concurrent writers; in deployment, WAN round-trips to committee members dominate the per-blob latency, not this pipeline.

**Coding core** (`cargo bench -p tenzro-storage --bench da_redstuff`, criterion, single-threaded) isolates the pure Reed-Solomon math, reported as bytes-of-source-blob per second:

| Operation (1 MiB blob) | n=4 | n=10 |
|---|---|---|
| encode (2n slivers + Merkle) | 52.3 MiB/s (19.1 ms) | 38.4 MiB/s (26.1 ms) |
| reconstruct from slivers | 30.4 MiB/s (32.9 ms) | 23.7 MiB/s (42.2 ms) |
| verify one sliver | 4.1 ms | 1.9 ms |

Encode at 8 MiB holds the same per-byte cost (n=4: 39.3 MiB/s, n=10: 30.2 MiB/s); 64 KiB blobs encode in 1.2–1.6 ms. Per-sliver verification is cheaper at larger n because each sliver shrinks as the blob is split across more members.

---

## 6. Peer discovery and bootstrap

A new node finds the network through a multi-source bootstrap path:

- **Explicit `--boot-nodes`** — a comma-separated list of libp2p multiaddrs and peer IDs. Authoritative and direct.
- **`--bootstrap-dns <base>`** — DNS-based discovery. The node resolves `_tenzro-boot._tcp.<base>` SRV records to a set of `(priority, weight, port, target)` tuples, then resolves each target's TXT records to obtain its libp2p peer ID. Rotating a boot validator's identity is a zone edit, not a fleet-wide wrapper update.
- **Built-in fallback set** — the compiled-in testnet bootstrap list carries both DNS names *and* raw IP multiaddrs for the bootstrap validators, so a DNS outage cannot partition new joiners: a node that fails to resolve the DNS entry still dials the raw-IP fallback. The two are equivalent addresses for the same peers; whichever resolves first wins.
- **Kademlia DHT** — once an initial connection is established, Kademlia handles ongoing peer discovery. The protocol id is `/tenzro/kad` so Tenzro peers don't accidentally exchange routing tables with other libp2p networks.
- **Identify observed_addr tally** — Identify reports back what a peer sees as the local node's external address. With N≥3 confirmations from independent peers, the node treats the address as confirmed and updates its `external_addrs` so future Identify exchanges propagate the address forward.

The result is permissionless joining: a node with the binary, the genesis, and a DNS name (or one explicit peer) becomes a network participant without any operator-side allowlisting.

### Kademlia mode and overlay-network reachability

DHT discovery is only *decentralized* — torrent-style, where any node finds any
other through the routing table rather than a hand-maintained peer list — when
reachable nodes run Kademlia in **Server** mode. A **Client**-mode node queries
the DHT but is not advertised in it, so its peers can find *it* only if they
already hold its address. If every node is a Client, discovery collapses to the
boot-node set: spokes reach the boot node but never each other (a **star**), with
the boot node a single point of connectivity.

Mode is chosen from reachability (§3): a node starts Server only with a
confirmed-reachable external address (validator class, `enable_relay`), otherwise
Client, and promotes Client→Server once AutoNAT reports sustained `Direct`.

**Overlay/VPN caveat.** On an overlay network (e.g. Tailscale/WireGuard) every
node *is* directly reachable at its stable overlay address, but AutoNAT's
dial-back probe often cannot certify `Direct` through the overlay, so nodes never
promote and stay Client → the DHT never meshes → star. Two operational fixes:

1. **Multi-boot mesh (any binary, config only).** Give each node *all* the other
   validators in `--boot-nodes`, not just one. Every node then dials every other
   directly — a full mesh independent of DHT/AutoNAT — and the boot list doubles
   as redundant bootstrap entry points (no single entry can partition a joiner).
   Best for a known, fixed validator set.
2. **Force Server mode for known-reachable nodes.** A node with a stable,
   operator-declared external address on an overlay is reachable by definition;
   run it in Server mode (`enable_relay=true` for the validator class) so it
   DHT-advertises and the routing table meshes the network decentrally — the path
   for permissionless joiners that are not in anyone's boot list.

Prefer (2) for a growing permissionless network; (1) is the immediate, foolproof
mesh for a fixed backbone and composes with (2).

### Resilience: node drop and restart

The network tolerates any single node dropping or restarting with no operator
action:

- **Consensus** is HotStuff-2 with a 2f+1 quorum, so with N validators the chain
  keeps finalizing through up to f simultaneous failures; a dropped validator's
  slot is simply not counted until it returns.
- **Auto-restart.** Each node runs under `systemd` with `Restart=always` +
  `RestartSec=5` and `WantedBy=multi-user.target`, so it comes back after a crash
  *and* after a host reboot.
- **Persistent identity + state.** The libp2p key (`p2p_key`), the TPM-sealed
  key material, the consensus store, and the block DB live under the data dir and
  survive restarts and binary upgrades. Because the peer ID is derived from the
  persisted key, a restarted node keeps the *same* identity, so multi-boot mesh
  entries and DHT records for it stay valid — the mesh reconnects on its own.
- **Re-sync + re-mesh.** On restart a node re-dials its boot nodes, re-runs the
  periodic Kademlia bootstrap (every 60 s), and block-syncs from tip. A node that
  fell behind while down catches up on the next block via the behind-hint →
  block-sync path (§5).

Binary upgrades follow the same contract: swap the binary and restart the unit —
never wipe the data dir — and the node rejoins with its identity, wallets, and
chain state intact.

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
- **Pkarr discovery.** When `pkarr_relay_url` is set (e.g. `https://pkarr.tenzro.xyz/`), the iroh endpoint publishes its `(EndpointId, AddrInfo)` to the Tenzro-operated Pkarr relay using its TDIP secret key. Resolution flows through the same relay. Local-dev falls back to n0's default `dns.iroh.link/pkarr` when no Tenzro relay is configured.
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

The node binary `tenzro-node` runs one wire protocol under twelve roles, selected with `--roles <token>[,<token>...]`. A single node may serve any combination:

| Token | Role | What it does |
|---|---|---|
| `validator` | Validator | Produces blocks, runs HotStuff-2 consensus, gets the 1.5× multiplier on leader-selection draw when TEE-attested. Runs the server halves of relay + AutoNAT for community joiners. |
| `fullnode` | FullNode | Follows and serves the full chain without producing blocks. |
| `light` | LightClient | Consumes the network without producing. Subscribes to the topics it cares about, dials specific request/response endpoints as needed. Default role for `tenzro join` clients. |
| `tee` | TeeProvider | Serves confidential compute, custody, attested execution. Carries the `Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA GPU CC / Intel Tiber` attestation chain. |
| `ai` | ModelProvider | Serves inference (chat / multi-modal / MoE expert shards / MTP). Subscribes to `tenzro/inference` and `tenzro/models`. |
| `compute` | ComputeProvider | Rents accelerator capacity for fixed terms. Distinct from `ai`: serving catalog weights and renting a card to run someone else's workload are different obligations and carry different bonds. |
| `storage` | StorageProvider | Holds content-addressed blobs, model weights, sealed shards; serves snapshot and DA requests. |
| `cloud` | CloudProvider | Runs hosted services on top of the network — functions, static sites, managed databases, machines. |
| `edge` | Edge | Terminates public TLS at a controlled DNS name and host-routes an incoming hostname to whichever node holds the content, serving locally or forwarding over p2p. A public front door, not a consensus participant. |
| `archive` | Archive | Stores full history. |
| `bootstrap` | Bootstrap | Seed node for peer discovery. |
| `micro` | MicroNode | Ultra-lightweight participant; no P2P required. |

All twelve are the same binary differentiated by `--roles`. There is no RPC-only mode; a public RPC node is a validator with extra HTTP / MCP / A2A exposure.

The role selects what a node *does*. What a node must *bond* is a separate ladder covering validator, RPC operator, TEE, model, compute, storage, cloud, trainer, and syncer — see `docs/TOKENOMICS.md` section 7.

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

- `tenzro_network_gossip_published_total` / `tenzro_network_gossip_accepted_total`
- `tenzro_network_gossip_rejected_validator_only_total` / `_rejected_invalid_total` / `_rejected_duplicate_total`
- `tenzro_network_connections_established` (gauge), `tenzro_network_connections_inbound_total` / `_outbound_total`
- `tenzro_network_dials_rejected_per_ip_total` / `tenzro_network_dials_rejected_global_total`
- `tenzro_network_peers_connected` (gauge), `tenzro_network_peers_banned` (gauge)
- `tenzro_network_kad_routing_table_size` (gauge), `tenzro_network_gossipsub_mesh_size` (gauge)
- `tenzro_network_peer_address_migrations_total`
- `tenzro_network_events_dropped_total`
- `tenzro_workflow_canton_mirrored_total` (gauge — workflows with a Canton mirror)

These Prometheus metrics let operators monitor mesh size, dial rate-limit pressure, connection churn, gossip accept/reject rates, and peer address migration.

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

## Node addressing

A node carries five identifiers. Until the DID Document existed, a caller
holding one had no documented path to the others.

| Identifier | What it is | Derives from |
|---|---|---|
| TDIP DID | `did:tenzro:machine:<uuid>` — the on-chain identity | provisioned identity |
| Ed25519 public key | the node's signing key | its keystore |
| iroh `EndpointId` | QUIC, NAT-traversing transport identity | **byte-identical** to the Ed25519 key since Phase C2 |
| libp2p `PeerId` | gossip and consensus mesh identity | a separate p2p keypair |
| Pkarr record | DNS-over-DHT address record | signed by the Ed25519 key |

Resolving the DID yields all of them plus the RPC/MCP/A2A/web service URLs, so
DID resolution is the single entry point rather than one of five things a
caller has to already know.

```bash
tenzro node did-document                       # via JSON-RPC
curl https://your-node.example/.well-known/did.json   # generic DID resolvers
```

The document is served with `Content-Type: application/did+json` at the W3C
well-known path, so a resolver that knows nothing Tenzro-specific can read it.

### Why the node signs it itself

The Ed25519 key and the iroh `EndpointId` are the same key material. A document
signed by that key is therefore self-certifying for the transport half: a
resolver that verifies the signature has, by that act, verified that the
endpoint it is about to dial belongs to the DID it asked about. This is the
property Phase C2 was built to create, and Pkarr publication composes with it.

### What it deliberately omits

Bind addresses that are not routable. `0.0.0.0:8545` is what the node listens
on, not where anyone can reach it — publishing it costs the caller a timeout
and tells them nothing, so wildcard and loopback addresses are dropped from
both the service URLs and the libp2p multiaddrs. A node behind NAT with no
dialable multiaddr still publishes its bare `PeerId`, which a peer already on
the mesh can route to.

Likewise, an ALPN appears only when a handler is actually installed. A renter
who dialled `tenzro/shell` on a node that merely registered the ALPN would get
a refusal, and the document would have promised them something.

A node with no provisioned identity publishes nothing and returns 404. A
document for a DID that resolves to nothing anywhere else is worse than saying
there is none.
