# Tenzro Network

**The decentralized networking layer of Tenzro — peer discovery, message propagation, NAT traversal, request/response protocols, validator authentication, and content-addressed transport, all on one iroh endpoint.**

---

## Abstract

A coordination layer is only as good as the substrate underneath it. Tenzro Network is the protocol layer that lets thousands of independently operated peers — validators, model providers, compute providers, storage providers, TEE providers, light clients, agents behind home / mobile / corporate NAT — find each other, propagate messages efficiently, distinguish validator traffic from non-validator traffic, and exchange large content-addressed payloads without going through a central broker. A single peer can take on several of these roles at once against one stake; the roles describe what a node serves, not how many nodes there are.

All networking runs on iroh (`tenzro-iroh`): QUIC connections between endpoints, found through signed endpoint records, Tenzro discovery and relays. On that one endpoint run topic gossip (`tenzro/gossip`, on iroh-gossip), validator consensus channels (`tenzro/consensus`), block sync (`tenzro/block-sync`), state sync (`tenzro/state-sync`), point-to-point protocols (cluster tunnel, DA committee, database replication) each on its own ALPN, content-addressed transport for model weights, training gradients and sealed shards, and the A2A and MCP ALPNs. The `tenzro-network` crate holds what gossip carries: message types, topics, validation, metrics and the peer status tracker.

A node's iroh `EndpointId` is derived from its TDIP Ed25519 key, so the endpoint a peer is talking to and the identity it authenticates are the same key.

This document covers the wire protocols, the topics, NAT traversal, the validator-authorization model, content-addressed transport, and the bootstrap path.

---

## 1. The iroh endpoint

### Gossip types — `tenzro-network`

`tenzro-network` defines the gossip message types and topic names, validates every received message, keeps the gossip metrics (`gossip_published`, `gossip_accepted`, `gossip_rejected_invalid`, `gossip_rejected_duplicate`, and `peers_connected`, the direct gossip neighbours on `tenzro/status`), and tracks the status each peer reports, keyed by iroh endpoint id.

### Content-addressed transport — `tenzro-iroh`

A single `iroh::Endpoint` per node carries every content-addressed payload Tenzro moves between peers:

- **DA backend** — receipts that exceed the inline-payload bound get offloaded to iroh-blobs, with the canonical SHA-256 hash recorded in the receipt envelope and the iroh BLAKE3 hash recorded as the locator
- **Model-weight distribution** — `BlobFetcher` trait with `IrohBlobFetcher` adapter; provider downloads are peer-first via `PeerHint`, fall back to HuggingFace Hub
- **A2A and MCP over iroh** — two ALPNs on the shared endpoint: `tenzro/a2a` for A2A JSON-RPC 2.0 (peer-to-peer agent), `tenzro/mcp` for MCP Streamable HTTP JSON-RPC 2.0 (tool invocation)
- **Confined shell over iroh** — `tenzro/shell` carries an interactive session against hardware a renter leased. No inbound port is opened: the session rides a connection the node already established, which is the move GCP's IAP and AWS's SSM Session Manager make. The ALPN is advertised only when a handler is installed and a confinement boundary is configured
- **Direct `tenzro://blob/<hash>` URI fetches** — the same endpoint services any URI lookup
- **State sync** — `tenzro/state-sync` answers which snapshot manifest a node holds for a height; the manifest, anchor chain and state buckets then travel as BLAKE3-verified blobs from any peer that has them (iroh 1.2, iroh-blobs 0.103)

The endpoint lets agents on a public network connect peer-to-peer without an HTTP router in the middle and without trusting a central content service.

---

## 2. Gossip topics

Gossip runs on iroh-gossip over the node's iroh endpoint (ALPN `tenzro/gossip`, `crates/tenzro-iroh/src/gossip.rs`); each topic name maps to one iroh-gossip topic per chain id. A node checks every received message before it delivers it or passes it on: the delivering neighbour must not be banned and must stay within its budget for the topic's traffic class, a message seen before is dropped, and the message must fit 1 MiB, decode and pass `validate_message`. A publish goes to every direct neighbour of the topic. Each neighbour has two message budgets per window: one for the topics consensus and sync depend on (`tenzro/certificates`, `tenzro/blocks`, `tenzro/validators`, `tenzro/status`) and one for every other topic, transactions included. A message over its budget is dropped without penalty, so a busy relay loses only its excess and never its certificates. The window, both budgets and the ban length are governed parameters (`gossip.rate_window_ms`, `gossip.consensus_messages_per_window`, `gossip.general_messages_per_window`, `gossip.ban_seconds`, see GOVERNANCE_PARAMS.md); a node rereads them as governance changes them. Neighbours are scored for the session on what they deliver: only invalid messages lower a score. A score, a budget and a ban belong to the neighbour's machine identity when a verified, unexpired endpoint record names its endpoint, so a banned machine is not readmitted by presenting a new endpoint key; a neighbour no record names is scored by its endpoint id, which is free to make. A neighbour no record names may not deliver on the four consensus topics: its messages there are dropped without penalty and not passed on (`tenzro_network_gossip_shed_unidentified_total`), while the other topics stay open to it within the general budget. The one exception is `tenzro/validators`: a validator learns of the others, and the records that name them, from their signed endpoint announcements, so an announcement from a neighbour no record names is heard from a budget shared by all such neighbours and is passed on only when it verifies under the key of a validator of a committee the node holds (any other message from it there is invalid). The peers a node joined its topics through are exempt. Topics join through the best-scored peers, and a banned neighbour's gossip connections are closed and refused.

| Topic | Producer | Consumer |
|---|---|---|
| `tenzro/blocks` | validators | every node |
| `tenzro/certificates` | validators | every node |
| `tenzro/validators` | validators (signed per-boot endpoint announcements) | every node |
| `tenzro/transactions` | wallets / agents | every node |
| `tenzro/models` | model providers | every node |
| `tenzro/status` | every node | every node |
| `tenzro/agents` | agents | agents and clients |
| `tenzro/providers` | any provider role | discovery clients |
| `tenzro/blobs` | nodes holding blobs | every node |
| `tenzro/databases` | database members | every node |
| `tenzro/sla` | SLA probes and fault attestations | providers and validators |
| `tenzro/compute-observations` | validator-signed compute observations | every node |

Blocks and certificates need no origin gate: a follower executes a block only once a checkpoint certificate it verifies covers it. Validators exchange consensus messages over the iroh ALPN `tenzro/consensus`, not over gossip.

Transaction data travels in batches that each validator pushes to every other over its consensus channels; a vertex introduces a batch and others acknowledge it, and a batch executes once its introduction and a quorum of acknowledgements are ordered.

A transaction travels on `tenzro/transactions` under its origin's envelope only; no node relays it under a new one. The node that admits a transaction over RPC publishes it at once, from the RPC handler rather than its event loop, so a node busy importing blocks does not delay it. Until a block includes it or the mempool drops it, that node publishes it again, first after 5 s and then at doubling waits up to 60 s, at most 512 transactions per second, in sender and nonce order, so a validator whose gossip subscription lagged still receives it and a sender's later transactions do not wait behind a missing nonce. A validator whose mempool refuses one for a reason that passes as blocks execute (the sender's nonce window or pending cap, the rate limit, the fee floor, a full mempool) holds it, never relays it, and offers it to its mempool again until it is admitted, refused for good or too old. Node configuration sets the limits:

```toml
[held_transactions]
max_age_secs = 300        # dropped after this long
max_held = 4096           # past this many, the oldest is dropped
retry_interval_ms = 1000  # how often the held ones are offered again
```

Model and provider announcements are authenticated independently of the validator gate. Messages on `tenzro/models` and `tenzro/providers` name the announcing node's machine DID and carry a session signature over a canonical preimage of the whole message, certified by the node's hardware identity key (P-256, plus ML-DSA-65 where the chip holds one). Each message is verified on ingest against the key registered for that DID in the identity registry, never against a key the message carries; unsigned, tampered or unregistered announcements are dropped before they reach the discovery index. The same holds for heartbeats, blob announcements and shard-replication requests. Provider announcements are keyed by the provider's iroh endpoint id and bound to it: the endpoint key signs the announce key (`endpoint_binding_sig`, checked by `verify_endpoint_binding`), so an announcement cannot claim an endpoint its signer does not hold. Model announcements additionally advertise `weights_sha256`, a streaming SHA-256 of the served on-disk weights, so consumers can detect weight substitution before routing inference to a provider.

---

## 3. NAT traversal

Most home, mobile, and corporate networks are behind NAT. A Tenzro node needs no inbound port: its iroh endpoint reaches its relays outbound, peers reach it through those relays, and iroh upgrades a relayed path to a direct one by hole-punching when both sides can. Community nodes therefore participate from any consumer connection without operator intervention.

Relaying is an ordinary operator role. A node that runs it serves the iroh relay protocol, which forwards end-to-end encrypted QUIC between endpoints that cannot reach each other directly, together with its operator's signed endpoint record, which announces the relay by identity. A relay sees only ciphertext.

The endpoint binds UDP `0.0.0.0:9001` and `[::]:9001` by default. The fixed port only makes direct paths predictable for an operator who chooses to allow them; nothing depends on it being reachable.

A node finds its way to direct paths three ways:

- **Port mapping.** The endpoint asks the local router to forward its UDP port over UPnP IGD, PCP (RFC 6887) or NAT-PMP (RFC 6886), whichever it answers.
- **Peer-observed addresses.** A peer that reaches a node over a direct path answers the `Observe` request of the `tenzro/discovery` ALPN with the address it sees the node at. Each discovery round a node asks up to 8 peers. An address that at least two different machines report within 30 minutes is added to the endpoint as an external address, so it is offered to peers as a hole-punching candidate; one peer alone cannot place an address on a node. Comparing the reports gives the NAT kind (none, endpoint-independent, endpoint-dependent).
- **Birthday punching.** A node behind an endpoint-dependent NAT punches a direct path to a peer behind an endpoint-independent one: it asks over `tenzro/punch/1`, opens 256 sockets towards the peer's punch socket (whose public address a peer relay reports), and the peer sends 1,024 paced probes to random ports at the node's public IP; the first probe through is answered and that socket pair carries the path, kept open every 15 s. One attempt per peer per 10 minutes, one at a time, at most 5 seconds. The path is a custom-transport path of the same module.
- **Peer relays.** Every edge operator's node also forwards packets between endpoints that cannot reach each other directly, over QUIC datagrams on connections both opened to it (ALPN `tenzro/peer-relay/1`). A node keeps connections to the two forwarders with the lowest round-trip time among its admitted relays' operators that it reaches on a direct path, names them in its signed endpoint record (`forwarders`, at most 4), and peers dialing it try the path through them beside the relay; iroh prefers it. A forwarder holds at most 4,096 nodes and forwards at most 4 MiB/s from any one. The path is iroh's custom transport, implemented in one module (`tenzro-iroh/src/paths.rs`) that is replaced when iroh carries the same capability.
- **Edge nodes on UDP 443.** A node serving the relay role binds its endpoint on UDP 443 (needs `CAP_NET_BIND_SERVICE` on Linux), so a node on a network that passes only web traffic reaches it, and peers through it, directly.
- **Relays.** When no direct path opens, traffic stays on a relay. Relay TLS is checked against the operating system's certificate store, so a TLS-inspecting proxy whose CA the machine trusts does not cut a node off. Relays speak HTTPS on TCP 443, so a node on a network that blocks UDP still reaches the network.

A relay listener also answers `/generate_204`, the captive-portal check an endpoint runs on a new network. `tenzro-node doctor` reports the NAT kind, the addresses peers see, the relays in use, the router's port mapping and the host firewall, with fixes; see [NODE-NETWORKING.md](NODE-NETWORKING.md).

---

## 4. Validator authentication

Validator traffic is authenticated by key, not by where it arrives from. Consensus channels on the iroh ALPN `tenzro/consensus` admit only the endpoints the committee names, and both ends prove their hardware consensus keys in the handshake.

The node also keeps a validator identity set (`NodeValidatorRegistry`): the genesis validators' Ed25519 node keys until consensus runs, then the active validators of the current epoch, so stake-based joins and rotations are tracked. `is_validator_identity()` answers against it; the compute observation window uses it to admit observations only from active validators.

---

## 5. Point-to-point protocols

Some message flows are too sensitive to gossip's lossy fanout. Tenzro carries them as point-to-point streams on the node's iroh endpoint, one ALPN per protocol, dialed by endpoint id so they reach a peer behind NAT, a relay-only node, or a node with no listener of its own. An endpoint id is reached only through the signed endpoint record of the machine behind it (section 6).

- **Block sync (iroh ALPN `tenzro/block-sync`)** — a lagging node asks the committee members of the current and previous epoch, at the endpoints the committee names, for their tips and then for contiguous ranges of blocks. A response carries the blocks, the checkpoint bodies covering them and a checkpoint certificate they chain to; the node imports a block only once an authenticated checkpoint's blocks root commits it. One request and one response frame per stream; the wire types live in `crates/tenzro-node/src/block_sync.rs`, the transport in `crates/tenzro-iroh/src/block_sync.rs`.
- **iroh ALPN `tenzro/da-committee`** — the committee-resident data-availability store. A writer sends `StoreSliver` to each committee member ("hold this erasure-coded sliver for this blob commitment") and the member replies with a signed attestation of custody; a reader sends `FetchSliver` and the member returns the sliver it holds (or `None`). A challenger sends `ChallengeSliver` with a random 32-byte nonce and the member must reply with its full sliver plus a session signature binding the nonce — the challenger re-verifies the sliver against the blob commitment, so a member cannot pass a possession challenge with cached metadata. Every resolution feeds the target's rolling 0–1000 availability score (+1 pass, −5 silence or honest not-held, −25 bad proof); each validator also runs a background auditor that challenges one random certificate attester every 10 minutes. Attestations and possession proofs are signed by the member's session key, certified by its hardware identity key; a verifier takes that key from the identity registry entry of the member's machine DID (derived from the P-256 leg of its consensus key), and a member whose machine DID has no registered key cannot attest. Members are dialed at the endpoint their verified consensus endpoint announcement names. 16 MiB request cap. The wire types live in `da_committee_surface.rs`; challenge issuance, scoring, and persistence live in the node adapter (`da_committee.rs`), surfaced over `tenzro_daChallenge` / `tenzro_daListChallenges` / `tenzro_daAvailability` / `tenzro_daCommittee` / `tenzro_daListBlobs`, the matching MCP tools, and `tenzro da`.

- **iroh ALPN `tenzro/db-replicate`** — replicated database writes. A serving holder sends `ApplyWrite` to every other holder of the partition, addressed by the endpoint id in the holder's `host#<endpoint id>` placement entry, and counts acknowledgements for the Quorum and All write-consistency levels. A holder applies a write only when both it and the sender are holders of that partition. 16 MiB request cap.
- **iroh ALPN `tenzro/infer`** — inference between nodes. A consumer forwards a `tenzro_chat` frame or an OpenAI chat completion to the provider's announced endpoint id; the provider answers with a status and a body, streamed for `stream: true`, so refusals (402, 403) and server-sent events arrive exactly as its own HTTP surface would send them.

DA, database replication and inference share one wire shape (`crates/tenzro-iroh/src/request.rs`): a length-prefixed request, then a status and a streamed body, one exchange per QUIC stream.

### Measured DA committee throughput

Two measurements pin down what the committee-resident DA path costs, both run on a 32-core build worker, isolated from any live network:

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

- **Boot identities** — `--boot-nodes`, `TENZRO_BOOT_NODES` and `[iroh] boot` take machine identities, `did:tenzro:machine:<id>[@<relay url>]`, never network addresses; a network address in any entry refuses the whole list. Without `--boot-nodes` the node joins through the genesis validators: each one's machine identity derives from the P-256 leg of its consensus key, and its genesis entry names the relay it is reachable through.
- **Relays by identity** — a relay is admitted only when its operator's signed endpoint record, served at `<relay>/identity`, announces exactly that relay URL. No relay, discovery service or peer is built in.
- **Staked relays** — relaying is part of the `edge` role. At start a node reads the URLs staked edge operators publish (`tenzro_listRoleEndpoints { role: "edge" }`) from its own chain state and admits up to 8 of them, most bonded first, each by its operator's record as above; an edge operator that serves no relay at its URL is skipped. The edge role takes a bond (governed `stake.edge_tnzo`, 10,000 TNZO at genesis). Validators probe each staked relay at its published URL on the SLA schedule every bonded role is held to, and an epoch frozen unavailable costs the edge bond the governed SLA penalty. Every node also checks the staked relays every five minutes (record valid and announcing the URL, latency); `tenzro_listRelays` serves the staked relays with the last frozen SLA verdict and the answering node's latest check, and `tenzro_getConnectivity` how the node is reached, without its addresses.
- **Signed endpoint records** — each machine's hardware key signs a record naming its transport endpoint key (for iroh, its per-boot `EndpointId`), the relays it is reachable through, a sequence number, a sharing scope, and a lifetime of 6 hours (at most 24), renewed at half-life. A record signed by another identity, expired, naming another endpoint, or with a lower sequence than one held is refused.
- **Tenzro discovery network** — every node keeps a store of verified records and answers other nodes on the `tenzro/discovery` iroh ALPN (publish, look up by identity, snapshot). Each minute a node publishes its record to up to 16 known peers and takes their snapshots, so a node that knows one Tenzro node comes to know the rest. The same store resolves an `EndpointId` to the relays its record names. Nothing outside the Tenzro network (no n0 relays or DNS, no pkarr server, no DHT) is consulted. Records scoped to the epoch set are answered only to peers a member certifies.

- **Remembered relay operators** — a running node writes the relay operators it met through the discovery network (up to 16, newest records first) to `{data_dir}/iroh/known-relays.json` and joins through them too after a restart. The configured and genesis boot lists are therefore only a way in: once a node has run, it no longer depends on them being reachable.

The result is permissionless joining: a node with the binary and the genesis (or one explicit boot identity) becomes a network participant without any operator-side allowlisting.

### Reaching the network as a client

RPC operators bond the `rpc` role and publish the public URL they serve it at with a `Stake` endpoint operation (`tenzro stake endpoint --role rpc --url https://...`). The URL lives in consensus state beside the bond, so every node answers the same list: `tenzro_listRoleEndpoints { role }` returns the operators whose bond meets the role's required stake, most bonded first. An operator that unbonds drops off the list.

The SDKs use the list instead of a fixed domain. `connectToNetwork` (TypeScript), `network::connect_to_network` (Rust) and `NetworkRpcClient.connect` (Python) take a few seed URLs and the chain id, then:

1. ask every seed for the `rpc` operators and merge the lists (any node will do; a seed is a way in, not an authority);
2. keep the endpoints that report the expected `eth_chainId`;
3. compare them at the lowest checkpoint they all hold (`tenzro_getCheckpointCertificate`) and keep only those reporting the most common digest, so an endpoint serving another history is dropped rather than trusted;
4. send each call to the first endpoint kept and move to the next when one cannot be reached.

These clients carry no access credential: they serve open methods and signed transactions, which every operator accepts on their own signature.

### Resilience: node drop and restart

The network tolerates any single node dropping or restarting with no operator
action:

- **Consensus** tolerates up to f of n seats failing at once (quorum n − f);
  a restarted validator rebuilds its consensus state from its recovery journal
  and resumes its epoch.
- **Auto-restart.** Each node runs under `systemd` with `Restart=always` +
  `RestartSec=5` and `WantedBy=multi-user.target`, so it comes back after a crash
  *and* after a host reboot.
- **Persistent state, per-boot transport keys.** The consensus store and the block
  DB live under the data dir and survive restarts and binary upgrades. The iroh
  endpoint key is generated at every start and never written, so the endpoint id
  changes on restart; the node's lasting identity is its hardware key, from which
  its validator keys are derived on demand, and which vouches for the current
  endpoint id in its signed endpoint record and signed announcements.
- **Re-sync + re-mesh.** On restart a node reaches its boot identities, publishes
  its new endpoint record to the discovery network, and block-syncs from tip. A node that
  fell behind while down catches up on the next block via the behind-hint →
  block-sync path (§5).

Binary upgrades follow the same contract: swap the binary and restart the unit —
never wipe the data dir (a corrupt chain database is replaced as GUIDE.md section 9.8 describes) — and the node rejoins with its identity, wallets, and
chain state intact.

### Local-network cluster discovery

Cluster members on the same LAN find each other by multicast DNS on the iroh endpoint, with no relay, DNS server or outside service involved, so discovery works on a LAN with no internet at all. A member announces its endpoint together with its hardware key's signature over its claim to that endpoint. A sighting is only a claim: it is treated as that member only when the binding checks against the cluster's verified membership list (see AI.md §3.5, "Cluster identity").

An AI-serving node that is a member of a cluster attaches a `ClusterProfile { memberships, llama_commit, backend, cap_key }` to its periodic provider announcement; `memberships` carries the signed membership list of every cluster that names it, and each receiver checks those lists and keeps the latest per cluster. A node whose AI capability is private announces no profile. The head plans only over verified members of its cluster found on the local network, plus itself (see AI.md §3.5). No serving socket is advertised — the head reaches each member's loopback `rpc-server` over the `tenzro/cluster-tunnel` ALPN at the endpoint the member's hardware-signed local-network binding names.

---

## 7. The iroh endpoint in depth

The iroh endpoint is constructed by `TenzroIrohConfig::bind_with_config`. Three properties make it the right substrate for Tenzro's content-addressed traffic:

- **Stable endpoint identity.** On a node with a hardware root the iroh endpoint key is derived from it at each start and held only in memory, so the `EndpointId` is the same after a restart; a node without one uses a key made for the boot. The machine's hardware key certifies the `EndpointId` in its signed endpoint record, so a verifier trusts an endpoint id only through a record the claimed machine identity signed.
- **Relays as an operator role.** A node started with `--relay-listen <addr> --relay-url <url>` serves, on one HTTP listener, the iroh relay protocol (`/relay`) and its operator's own record (`/identity`), the door new nodes enter the discovery network through. Exposing the listener at the published URL, with TLS, is the operator's choice. Every other node reaches relays outbound only and needs no inbound port; a node with `[iroh] relay_only = true` binds no IP socket at all.
- **No direct addresses published.** Records name relays, never IP addresses.
- **PQ-hybrid key exchange.** Every endpoint handshakes with aws-lc-rs offering the X25519MLKEM768 hybrid first, with X25519 alone as the fallback, so two Tenzro endpoints agree on the hybrid unless a peer or an attacker on the path forces the fallback. Endpoint authentication is by Ed25519 endpoint keys, which are classical.
- **Single shared endpoint.** All iroh-anchored Tenzro traffic — DA, gradient store, sealed-shard store, model-weight distribution, A2A-over-iroh, MCP-over-iroh, direct `tenzro://blob/<hash>` lookups — share one endpoint. One ALPN per protocol, one hash space (BLAKE3 indexed by iroh-blobs, SHA-256 indexed by Tenzro's higher-level receipt schema).

### URI scheme

All iroh-served content addresses through the `tenzro://` URI scheme:

| URI form | Resolver | Use |
|---|---|---|
| `tenzro://blob/<blake3-hex>` | `IrohBackedResolver::fetch_bytes` | Raw content-addressed blob |
| `tenzro://node/<endpoint-id>/...` | iroh QUIC dial | Direct peer dial |
| `tenzro://did/<did>` | TDIP resolver | DID resolution |
| `tenzro://model/<model-id>` | model registry | Model artifact lookup |
| `tenzro://shard/<sha256-hex>` | blob resolver | Content-addressed blob |
| `tenzro://receipt/<sha256-hex>` | DA backend | Off-chain settlement receipt |

The transport is hidden behind the scheme — callers do not write `iroh://` URIs.

---

## 8. Roles

The node binary `tenzro-node` runs one wire protocol under fifteen roles, selected with `--roles <token>[,<token>...]`. A single node may serve any combination:

| Token | Role | What it does |
|---|---|---|
| `validator` | Validator | Orders blocks and signs checkpoints with its hardware consensus key (TEE attestation is a reputation signal only). |
| `fullnode` | FullNode | Follows and serves the full chain without producing blocks. |
| `light` | LightClient | Consumes the network without producing. Subscribes to the topics it cares about, dials specific request/response endpoints as needed. Default role for `tenzro join` clients. |
| `tee` | TeeProvider | Serves confidential compute, custody, attested execution. Carries the `Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA GPU CC / Intel Tiber` attestation chain. |
| `ai` | ModelProvider | Serves inference (chat / multi-modal / MoE expert shards / MTP). Subscribes to `tenzro/inference` and `tenzro/models`. |
| `compute` | ComputeProvider | Rents accelerator capacity for fixed terms. Distinct from `ai`: serving catalog weights and renting a card to run someone else's workload are different obligations and carry different bonds. |
| `storage` | StorageProvider | Holds content-addressed blobs, model weights, sealed shards; serves snapshot and DA requests. |
| `rpc` | Rpc | Carries tenant traffic and issues tenant access. |
| `attestor` | Attestor | Confirms settlement plans' bank, card or ISO 20022 legs on a payment rail it connected. |
| `catalog` | CatalogPublisher | Signs model catalog entries; the bond answers for every entry it signs and an upheld catalog fault slashes it. Needs no node. |
| `wallet` | WalletProvider | Bonds for the passkey domain its wallet serves; validators check the domain names the bonding account. Needs no node. |
| `edge` | Edge | Terminates public TLS at a controlled DNS name and host-routes an incoming hostname to whichever node holds the content, serving locally or forwarding over p2p, and serves the relay at the URL its bond publishes. A public front door, not a consensus participant. |
| `archive` | Archive | Stores full history. |
| `bootstrap` | Bootstrap | Seed node for peer discovery. |
| `micro` | MicroNode | Ultra-lightweight participant; no P2P required. |

All fifteen are the same binary differentiated by `--roles`. There is no RPC-only mode; a public RPC node is a validator with extra HTTP / MCP / A2A exposure.

The role selects what a node *does*. What a node must *bond* is a separate ladder covering validator, RPC operator, attestor, TEE, model, compute, storage, wallet provider and catalog publisher — set by governance, see `docs/TOKENOMICS.md` section 7 and `docs/GOVERNANCE_PARAMS.md`.

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
- `CF_STATE` — VM state (committed into the unified binary state trie, `CF_STATE_TRIE`)
- `CF_METADATA` — chain id, genesis hash, configured weak-subjectivity anchor
- `CF_VALIDATOR_MODULES` — the validator modules installed on each account (the account-side signature checks, such as the WebAuthn passkey validator) and passkey auth sessions; unrelated to consensus validators, whose keys are in hardware
- `CF_AGENTS` — agent registry
- `CF_MODELS` / `CF_MODEL_SERVICES` — model catalog and provider serving declarations
- `CF_PROVIDERS` — provider registry
- `CF_BRIDGE_ANALYTICS` — per-tenant cross-chain compute-unit attribution
- `CF_AUDIT` — equivocation evidence

Durable writes go through `write_batch_sync` with `fdatasync`. Block writes are atomic. Auto-repair handles WAL corruption on startup. Every block's state root is the root of the unified binary state trie (`CF_STATE_TRIE`) over the consensus column families; see Section 12 for how snapshots are verified against it.

### History retention

A node keeps the live state and the most recent `storage.history_retention_blocks` blocks (a governed parameter; the genesis value is 1,209,600). Older blocks are handed to the committee's data-availability layer in segments: a run of certified checkpoints, closed at an epoch's last checkpoint or at 4,096 blocks. A segment is written to the DA layer, where bonded members hold its erasure-coded slivers and answer possession challenges, and its pointer is recorded before its blocks are deleted locally. A pruned block requested through `tenzro_getBlock` is fetched from the DA layer and returned only after the segment's blocks rebuild the blocks root of every checkpoint it covers, each checkpoint authenticated by a certificate. Committee members write the segments. A node outside the committee (an RPC node) applies the same retention window but writes nothing: it asks committee members over the `tenzro/da-committee` ALPN where the DA layer holds each closed segment, fetches it, and deletes its own copy only once the fetched segment verifies against its certified checkpoints; until then it keeps the blocks. It serves pruned blocks the same way validators do. A node with no DA layer to reach applies the same window and deletes what falls below it. A block's transactions, their locations and their receipts go with the block: `eth_getTransactionByHash` and `eth_getTransactionReceipt` answer only for transactions inside the window, while the block itself, transactions included, is still served by height from the DA layer. `[storage] archival = true` keeps every block, event and transaction locally instead; archives opt in, no node does by default. A node that follows no chain keeps its full history.

### Audit retention

Agent audit entries follow their own retention, `storage.audit_retention_seconds` (a governed parameter whose floor and genesis value are 183 days), independent of the block-history window. Entries are recorded outside the node by whoever runs the agent; the governed retention is how long a recorder keeps a session's entries and the data to prove them after the session closed. The roots they commit stay in chain state for that retention past their epoch, plus the commit window, and are then deleted.

### Epoch snapshots and backups

When an epoch's last checkpoint is certified, the node checkpoints its store under `<data_dir>/epoch-snapshots` (hardlinked SST files, near-zero cost) and keeps the newest `[storage] snapshots_kept` (default 2). `tenzro-node backup --dest DIR` copies the newest snapshot to `DIR`, copying only SST files no earlier backup there holds and hardlinking the rest, at idle priority and a paced rate (`--rate-mb`). The node never sends a backup anywhere itself: the schedule, encryption and off-site copy of `DIR` are the operator's. Each snapshot keeps, beside it, the proof from genesis that its checkpoint is certified: the genesis committee, the handover certificate of every earlier epoch with the committee it commits, and the checkpoint's own certificate, each with the session certificates it names. `tenzro-node restore --snapshot DIR --chain-id N --genesis-hash HEX --genesis-committee-root HEX` rebuilds an empty store only if that proof verifies from the genesis committee named in the genesis file: every certificate must carry a quorum of ML-DSA session signatures from the committee of its epoch, each committee must be the one the previous epoch's last checkpoint commits, and the proof must certify exactly the snapshot's checkpoint. The snapshot's state, recomputed from its own entries, must then rebuild that checkpoint's certified state root. `--proof-from URL` fetches the proof from a peer's RPC (`tenzro_getCommittee`, `tenzro_getEpochHandover`, `tenzro_getCheckpointCertificate`) instead, and `--proof FILE` reads it from a file; either is verified the same way. A bare checkpoint digest is never accepted.

### Disk and memory bounds

`[storage]` in the node config sets two disk watermarks on the data volume. At `prune_watermark_pct` (default 75) the node prunes to the retention floor, keeps a single epoch snapshot and compacts. At `refuse_watermark_pct` (default 90) it also refuses non-essential data, model downloads and file uploads, with a warning, a degraded `disk` health subsystem and a `disk` object in `tenzro_getNodeStatus`. Consensus-critical writes are never refused.

The store's block cache and memtables share one limit (`[storage] memory_mb`, by default 1/32 of the memory budget's pool, between 256 MiB and 4 GiB); that figure and the consensus core's buffered bytes are charged to the resident tier of the node's memory budget, so model loads see only what is left. Compaction and flush are rate-limited (`background_write_mb_per_sec`, default 64) and run at idle CPU and I/O priority.

---

## 11. Observability

Every node exposes a Prometheus `/metrics` endpoint with per-subsystem counters. Network-side metrics include:

- `tenzro_network_gossip_published_total` / `tenzro_network_gossip_accepted_total`
- `tenzro_network_gossip_rejected_invalid_total` / `_rejected_duplicate_total`
- `tenzro_network_gossip_shed_over_budget_total` (messages dropped because the neighbour spent its budget) / `_shed_unidentified_total` (consensus-topic messages dropped because no endpoint record names the neighbour)

The count of direct gossip neighbours on `tenzro/status` is `peers_connected` in `tenzro_getNodeStatus`.

These Prometheus metrics let operators monitor gossip accept, reject and shed rates.

---

## 12. Security properties

- **Consensus traffic is committee-gated.** A connection on `tenzro/consensus` is admitted only if its endpoint belongs to a member of the current committee, as that member disclosed it to this validator; any other endpoint is refused before a stream opens. On the gossip topics, a block or certificate is accepted by what it proves (a certificate verifying against the epoch's committee), not by who relayed it, and a neighbour that no verified endpoint record names may not deliver on the consensus topics, except a verified validator endpoint announcement (see section 3).
- **Connection and stream limits.** The endpoint holds at most `[iroh.connection]` connections, overall and per peer, in two pools (consensus and everything else), refuses new attempts before the handshake once both are full, and bounds streams, idle time and the receive window of each connection (docs/NODE-NETWORKING.md, "Connection limits"). Each request protocol also bounds the streams it serves at once, overall and per peer, with read and write timeouts (`[iroh.admission]`).
- **Bans follow the machine.** A neighbour that earns a ban is banned for `gossip.ban_seconds` and its gossip connections are closed and refused. When a verified endpoint record names the neighbour, the ban belongs to its machine identity and a new endpoint key for the same machine stays banned. Bans are held in memory for the session.
- **Hybrid PQ signatures.** Every checkpoint vote carries an ML-DSA-65 + P-256 composite signature by the validator's hardware-held key; a certificate carries a quorum of them. Consensus keys are admitted only with a proof of possession.
- **Certified blocks only.** A block from gossip or block-sync is executed only after a checkpoint certificate covering it verifies against its epoch's committee, it extends the local tip by one height with a matching `prev_hash`, its body hashes to `tx_root`, and it commits the state root this node computed. A gossiped block is passed on to other nodes only after it passes (its `ValidationTicket` is accepted), and a rejected block costs the neighbour that delivered it score. Block-sync responses must answer the range that was asked; unsolicited or mismatched responses are dropped and penalised.
- **Verified state sync.** A joining node restores state from a weak-subjectivity checkpoint (a block hash it trusts). The snapshot manifest is fetched over the `tenzro/state-sync` iroh ALPN, its anchor chain must end in the trusted block, its bucket summaries must fold to the root that block commits, and each BLAKE3-verified bucket must rebuild its summary before it is written. Nothing a peer sends is used before it is checked, so buckets may come from any peer; a stopped sync resumes where it left off.
- **Stable iroh endpoint key.** A node with a hardware root derives its iroh `EndpointId` key from it, so the id is the same at every start and peers that hold its signed endpoint record reach it again after a restart. The record, signed by the machine's hardware key, is how a verifier ties an endpoint to a machine identity.

---

## 13. Reference

- Crates: `tenzro-network`, `tenzro-iroh`
- Validator identity set: `crates/tenzro-node/src/node.rs::NodeValidatorRegistry`
- Local-network cluster discovery: `crates/tenzro-iroh/src/lan_discovery.rs`
- Gossip: `crates/tenzro-iroh/src/gossip.rs` (transport), `crates/tenzro-network/src/{gossip, gossip_validation}.rs` (topics and rules)
- Point-to-point protocols: `crates/tenzro-iroh/src/{request, block_sync}.rs`; node adapters `crates/tenzro-node/src/{da_committee_surface, db_holder_dispatch, cluster_serving_runtime, infer}.rs`
- Endpoint records: `crates/tenzro-iroh/src/identity_record.rs`; discovery network: `crates/tenzro-iroh/src/discovery.rs`; relay role: `crates/tenzro-iroh/src/relay.rs`; bootstrap by identity: `crates/tenzro-iroh/src/identity_transport.rs`, `crates/tenzro-node/src/identity_bootstrap.rs`
- Iroh config: `crates/tenzro-iroh/src/config.rs::TenzroIrohConfig`
- Iroh A2A + MCP ALPNs: `crates/tenzro-iroh/src/jsonrpc.rs`, `crates/tenzro-iroh/src/lib.rs`

For the consensus algorithm that runs over this network layer, see [`SPECIFICATION.md`](SPECIFICATION.md) §5. For the agent surfaces (MCP / A2A) that ride this network layer, see [`SPECIFICATION.md`](SPECIFICATION.md) §14. For the AI workloads (inference, MoE, training) carried over this network layer, see [`AI.md`](AI.md).

## Node addressing

A node carries four identifiers. Until the DID Document existed, a caller
holding one had no documented path to the others.

| Identifier | What it is | Derives from |
|---|---|---|
| TDIP DID | `did:tenzro:machine:<device-key-id>` — the on-chain identity | provisioned identity |
| Ed25519 public key | the node's signing key | its keystore |
| iroh `EndpointId` | QUIC, NAT-traversing transport identity | **byte-identical** to the Ed25519 key |
| Relays | where the iroh endpoint is reachable, by relay URL | the signed endpoint record |

Resolving the DID yields all of them plus the RPC/MCP/A2A/web service URLs, so
DID resolution is the single entry point rather than one of four things a
caller has to already know.

```bash
tenzro node did-document                       # via JSON-RPC
curl https://<your-node>/.well-known/did.json   # generic DID resolvers
```

The document is served with `Content-Type: application/did+json` at the W3C
well-known path, so a resolver that knows nothing Tenzro-specific can read it.

### Why the node signs it itself

The Ed25519 key and the iroh `EndpointId` are the same key material. A document
signed by that key is therefore self-certifying for the transport half: a
resolver that verifies the signature has, by that act, verified that the
endpoint it is about to dial belongs to the DID it asked about. This is the
property the endpoint binding was built to create, and Pkarr publication composes with it.

### What it deliberately omits

Bind addresses that are not routable. `0.0.0.0:8545` is what the node listens
on, not where anyone can reach it — publishing it costs the caller a timeout
and tells them nothing, so an endpoint is published only when the operator
configured an external address or the bind address is actually dialable. A
node behind NAT with no dialable address is still reachable: its iroh
`EndpointId` and the relays its endpoint record names are enough to connect.

Likewise, an ALPN appears only when a handler is actually installed. A renter
who dialled `tenzro/shell` on a node that merely registered the ALPN would get
a refusal, and the document would have promised them something.

A node with no provisioned identity publishes nothing and returns 404. A
document for a DID that resolves to nothing anywhere else is worse than saying
there is none.
