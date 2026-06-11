# TEE Capability Routing

How Tenzro nodes discover which peers can serve TEE-gated workloads, and how those workloads are routed without coupling to consensus participation.

## Model

**All nodes participate in consensus.** TEE capability is orthogonal to validation: a commodity-hardware node and a SEV-SNP-attested node have identical roles in HotStuff-2 voting, block production, and finality.

What TEE-capable nodes provide *additionally* is a service surface for workloads that require hardware-rooted confidentiality or attested execution:

- Confidential AI inference (model weights or inputs that must not leak to the host)
- Custodial key management (MPC shares held inside an enclave)
- Attested computation for verifiable receipts
- Hybrid ZK-in-TEE (witness generation inside the enclave, proof signed with the hardware-rooted Ed25519 key)

A node without TEE hardware can still *consume* these services from a peer that has them, paying the provider in TNZO via the standard settlement path. This is the "TEE-capable nodes provide TEE capabilities to others as needed" model: the network self-organises so that confidential-compute capacity is available wherever a request originates, regardless of the local node's hardware.

## Wire format

TEE capability is advertised on the existing `tenzro/status` gossipsub topic. Every node broadcasts a `StatusMessage` every 10 seconds; the relevant fields are:

```rust
pub struct StatusMessage {
    pub peer_id: String,                          // base58 PeerId of sender
    pub best_block: Hash,
    pub height: u64,
    pub chain_id: u64,
    pub protocol_version: String,
    pub tee_capable: bool,                        // has a TEE provider
    pub tee_vendor: Option<TeeVendor>,            // IntelTdx | AmdSevSnp | AwsNitro | NvidiaGpu
}
```

`tee_capable` is `true` iff the sending node has a `TeeProvider` registered at startup. `tee_vendor` carries the specific vendor when present, so peers can filter for vendor-specific requirements (e.g. SEV-SNP-only workloads, NVIDIA GPU CC for confidential inference on accelerators).

The capability is **fixed at process start**. There is no hot-attach path — a node either initialises a TEE provider during boot (real hardware via `/dev/tdx-guest`, `/dev/sev-guest`, `/dev/nsm`, or NVIDIA NRAS) or it does not. The status broadcaster snapshots the value once and embeds it in every subsequent message.

## Discovery

Receivers feed `StatusMessage` into `PeerStatusTracker`, a `DashMap<PeerId, PeerStatus>` keyed on PeerId with a 60-second freshness window. Stale entries are excluded from queries and pruned periodically.

The tracker exposes:

```rust
fn find_tee_peers(&self, vendor: Option<TeeVendor>) -> Vec<(PeerId, PeerStatus)>;
```

`vendor = None` returns any fresh TEE-capable peer; `vendor = Some(v)` filters to that specific vendor. Stale entries are excluded automatically. This is the primitive routing logic builds on top of.

## Routing

A node that needs to dispatch a TEE-gated workload follows this pattern:

1. **Local-first.** If the local node is TEE-capable and the workload's vendor requirements (if any) match, serve locally — no network round-trip.
2. **Peer fan-out.** Otherwise call `find_tee_peers(required_vendor)` and select a peer. Selection policy is workload-specific; current policies include round-robin, latency-weighted (using fresh `last_seen`), and reputation-weighted (using `ProviderManager` reputation when the peer is also a registered model/TEE provider).
3. **Settle.** The requester pays the provider through the standard settlement path (escrow, micropayment channel, or direct transfer), with the workload's TEE attestation embedded in the receipt. No bespoke billing track for TEE-gated work.

Workloads that *require* a TEE but find no fresh capable peer fail explicitly rather than silently degrading to non-TEE execution.

## Trust model

`tee_capable` and `tee_vendor` are self-reported. A malicious peer can lie. The mitigations:

- **Attestation gates execution, not discovery.** A peer claiming `tee_capable: true` only matters when a workload is actually dispatched — at which point the requester verifies the peer's attestation (TDX QE P-256, SEV-SNP VCEK chain, Nitro COSE_Sign1 ES384, NVIDIA NRAS) before sending sensitive inputs or releasing payment. A liar can advertise capability but cannot produce a valid attestation, so the workload aborts before any harm is done.
- **Discovery cost is bounded.** False advertisements pollute the routing table but do not affect consensus, balances, or stored state. Pruning the entry on first attestation failure is sufficient.

This separates *advertised capability* (cheap, gossipped, freshness-bounded) from *verified capability* (expensive, on-demand, cryptographically rooted). The split is intentional: discovery must be O(1) per query for routing to be usable; verification must be rigorous for the security model to hold.

## Relationship to consensus

The consensus layer treats TEE attestation as a **leader-election multiplier** — validators with a fresh valid TEE attestation in the current epoch get a 1.5× weight in the proposer-election draw (see `docs/papers/tenzro-consensus.md` §4.4–4.5). That is the only place TEE state enters consensus.

In particular:

- A non-TEE validator participates fully in voting, block production, and finality.
- A TEE validator does not have veto power, does not produce more blocks except by virtue of being drawn more often, and does not bypass quorum.
- Loss of TEE attestation drops the multiplier back to 1× but does not eject the validator from the active set (re-attestation is a metadata update, not a re-registration).

The `tee_capable` field on `StatusMessage` is **not** consumed by the consensus engine. It exists purely for the routing/discovery layer described in this document.

## Code references

- `crates/tenzro-network/src/message.rs` — `StatusMessage` struct (`tee_capable`, `tee_vendor` fields)
- `crates/tenzro-network/src/peer_status.rs` — `PeerStatusTracker`, `PeerStatus`, `find_tee_peers`
- `crates/tenzro-node/src/node.rs` — status broadcast loop (snapshots `tee_capable` / `tee_vendor` once at startup, embeds in every 10 s broadcast); status receive handler (records into the tracker)
- `crates/tenzro-tee/` — `TeeProvider` trait and per-vendor implementations (TDX, SEV-SNP, Nitro, NVIDIA GPU)
