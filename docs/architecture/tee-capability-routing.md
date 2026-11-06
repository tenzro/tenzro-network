# TEE Capability Routing

How Tenzro nodes discover which peers can serve TEE-gated workloads, and how those workloads are routed without coupling to consensus participation.

## Model

**Consensus is run by the bonded validator committee, not by every node** (see [consensus.md](consensus.md)). TEE capability is orthogonal to validation: among validators, a commodity-hardware node and a SEV-SNP-attested node have identical roles in ordering, checkpoint signing, and finality, since voting weight comes from bonded stake alone and TEE attestation is a reputation signal only. A node that does not validate can still offer TEE services.

What TEE-capable nodes provide in addition is a service surface for workloads that require hardware-rooted confidentiality or attested execution:

- Confidential AI inference (model weights or inputs that must not leak to the host)
- Attested computation for verifiable receipts
- Hybrid ZK-in-TEE (witness generation inside the enclave, the proof bound to the enclave's attestation report)

A TEE is not a custody layer. It proves what code ran; it does not hold a key that its operator or anyone with the same image cannot reproduce, so no wallet, bridge or agent key is kept or derived inside one. Keys live in a TPM, a Secure Enclave or a passkey.

A node without TEE hardware can still consume these services from a peer that has them, paying the provider in TNZO via the standard settlement path. This is the "TEE-capable nodes provide TEE capabilities to others as needed" model: the network self-organises so that confidential-compute capacity is available wherever a request originates, regardless of the local node's hardware.

## Wire format

TEE capability is advertised on the existing `tenzro/status` gossip topic. Every node broadcasts a `StatusMessage` every 10 seconds; the relevant fields are:

```rust
pub struct StatusMessage {
    pub endpoint_id: String,                      // iroh EndpointId of sender, hex
    pub best_block: Hash,
    pub height: u64,
    pub chain_id: u64,
    pub protocol_version: String,
    pub tee_capable: bool,                        // has a TEE provider
    pub tee_vendor: Option<TeeVendor>,            // IntelTdx | AmdSevSnp | AwsNitro | NvidiaGpu
}
```

`tee_capable` is `true` iff the sending node has a `TeeProvider` registered at startup. `tee_vendor` carries the specific vendor when present, so peers can filter for vendor-specific requirements (e.g. SEV-SNP-only workloads, NVIDIA GPU CC for confidential inference on accelerators).

The capability is **fixed at process start**. There is no hot-attach path — a node either initialises a TEE provider during boot (against `/dev/tdx-guest`, `/dev/sev-guest`, `/dev/nsm`, or NVIDIA NRAS) or it does not. The status broadcaster snapshots the value once and embeds it in every subsequent message.

## Discovery

Receivers feed `StatusMessage` into `PeerStatusTracker`, a `DashMap<EndpointId, PeerStatus>` keyed on the sender's iroh endpoint with a 60-second freshness window. Stale entries are excluded from queries and pruned periodically.

The tracker exposes:

```rust
fn find_tee_peers(&self, vendor: Option<TeeVendor>) -> Vec<(EndpointId, PeerStatus)>;
```

`vendor = None` returns any fresh TEE-capable peer; `vendor = Some(v)` filters to that specific vendor. Stale entries are excluded automatically. This is the primitive routing logic builds on top of.

## Routing

A node that needs to dispatch a TEE-gated workload follows this pattern:

1. **Local-first.** If the local node is TEE-capable and the workload's vendor requirements (if any) match, serve locally — no network round-trip.
2. **Peer fan-out.** Otherwise call `find_tee_peers(required_vendor)` and select a peer. Selection policy is workload-specific; current policies include round-robin, latency-weighted (using fresh `last_seen`), and reputation-weighted (using `ProviderManager` reputation when the peer is also a registered model/TEE provider).
3. **Settle.** The requester pays the provider through the standard settlement path (escrow, micropayment channel, or direct transfer), with the workload's TEE attestation embedded in the receipt. No bespoke billing track for TEE-gated work.

Workloads that require a TEE but find no fresh capable peer fail explicitly rather than silently degrading to non-TEE execution.

## Trust model

`tee_capable` and `tee_vendor` are self-reported. A malicious peer can lie. The mitigations:

- **Attestation gates execution, not discovery.** A peer claiming `tee_capable: true` only matters when a workload is actually dispatched. The requester first obtains a single-use nonce (`tenzro_teeAttestationChallenge`), the peer answers with a report whose hardware-signed user data commits to that nonce, and `tenzro_tee::verify_report` checks it before any sensitive input or payment is released: TDX through DCAP (PCK chain, CRLs, QE identity, TCB info), SEV-SNP by the VCEK->ASK->ARK signature chain with the VCEK bound to the chip and its reported TCB, Nitro by COSE_Sign1 and the certificate chain to the AWS root, and NVIDIA GPUs only as a composite with a verified CPU leg answering the same nonce. A report replayed from another session answers a different nonce and is refused.
- **Where the hardware is.** A report says which chip ran which code, not where the chip is, and the published attacks on TDX and SEV-SNP need physical access. A deployment can require a facility claim signed by the facility's own hardware key and committed into the report data (`tenzro_tee::verify::facility`), and record each chip's first facility in the attestation transparency log (`tenzro_tee::verify::transparency`), which refuses measurements nobody published and yields evidence when a chip reappears elsewhere.
- **Discovery cost is bounded.** False advertisements pollute the routing table but do not affect consensus, balances, or stored state. Pruning the entry on first attestation failure is sufficient.

This separates advertised capability (cheap, gossipped, freshness-bounded) from verified capability (expensive, on-demand, cryptographically rooted). The split is intentional: discovery must be O(1) per query for routing to be usable; verification must be rigorous for the security model to hold.

## Relationship to consensus

TEE attestation does not enter consensus. The leader schedule is seats times observed behaviour only; attestation is a reputation signal outside the protocol.

In particular:

- A non-TEE validator participates fully in voting, block production, and finality.
- A TEE validator does not have veto power, is not drawn as leader more often, and does not bypass quorum.
- Loss of TEE attestation does not affect the validator's seat (re-attestation is a metadata update, not a re-registration).

The `tee_capable` field on `StatusMessage` is **not** consumed by the consensus engine. It exists purely for the routing/discovery layer described in this document.

## Code references

- `crates/tenzro-network/src/message.rs` — `StatusMessage` struct (`tee_capable`, `tee_vendor` fields)
- `crates/tenzro-network/src/peer_status.rs` — `PeerStatusTracker`, `PeerStatus`, `find_tee_peers`
- `crates/tenzro-node/src/node.rs` — status broadcast loop (snapshots `tee_capable` / `tee_vendor` once at startup, embeds in every 10 s broadcast); status receive handler (records into the tracker)
- `crates/tenzro-tee/` — `TeeProvider` trait and per-vendor implementations (TDX, SEV-SNP, Nitro, NVIDIA GPU)
