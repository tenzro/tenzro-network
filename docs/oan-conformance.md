# OAN Conformance

This document points to the Open Agent Network (OAN) protocol specifications and describes how Tenzro Network maps onto each.

## Pointer

- **OAN specification repository:** [github.com/tenzro/open-agent-network](https://github.com/tenzro/open-agent-network).
- **Foundational paper:** `papers/open-agent-network.md`.
- **Tenzro mapping (authoritative):** `implementations/tenzro.md` in the OAN repo.
- **Spec family:** `spec/00-overview.md` through `spec/22-x402-binding.md` (TNIP-001 through TNIP-022).

## Why this file exists

OAN is the agentic-web standards family stewarded by **Tenzro Foundation**, the non-profit that also stewards Tenzro Network (the reference implementation). Individual specifications are published as **Tenzro Network Improvement Proposals (TNIPs)**. The OAN specs are the authority for OAN conformance; this document is informational for Tenzro Network developers.

The OAN repository MUST NOT reach into Tenzro Network source. This document is the only place in the Tenzro Network repository that points back to OAN specs. Updates to OAN that change Tenzro Network's conformance posture are tracked in the OAN repo's `implementations/tenzro.md`, not here.

## Specs at a glance

### Substrate

| TNIP | Spec | Tenzro Network subsystem |
|---|---|---|
| TNIP-001 | Resolver — DIDs and AgentCards | `tenzro-identity` (TDIP) |
| TNIP-002 | Skills — Portable skill manifests | `tenzro-agent-kit` |
| TNIP-003 | Mesh — Content-addressed paid hosting | `tenzro-storage` Mesh layer |
| TNIP-004 | Discover — Conversational discovery | Tenzro Discover (planned) |
| TNIP-005 | Validation — TEE / ZK / optimistic / restaked | `tenzro-tee`, `tenzro-zk`, `ZkCommitmentRegistry` |
| TNIP-006 | Federation — Cross-registry mirror | `tenzro-network` registry mirror (planned) |

### Composition

| TNIP | Spec | Tenzro Network subsystem |
|---|---|---|
| TNIP-007 | Handles — Human-readable handle resolution | `tenzro-identity` handle layer (planned) |
| TNIP-008 | Compute — Verifiable inference routing | `tenzro-model` inference router |
| TNIP-009 | Memory — Persistent agent memory tier | `tenzro-agent` memory module |
| TNIP-010 | Credentials — Selective-disclosure VCs | `tenzro-identity` credential layer |
| TNIP-011 | Auth — UCAN-based delegated authority | `tenzro-identity` delegation layer |

### Identity

| TNIP | Spec | Tenzro Network subsystem |
|---|---|---|
| TNIP-012 | Identity — Guardian/agent hierarchy, KYC tiers, MPC custody | `tenzro-identity` (TDIP) |
| TNIP-013 | Delegation — Spending policies, HITL approval, lifecycle controls | `tenzro-identity` delegation scopes |
| TNIP-014 | Knowledge — Knowledge graph and social intelligence | `tenzro-agent` memory module |
| TNIP-015 | Marketplace — Intelligence marketplace protocol | `tenzro-agent-kit` marketplace |
| TNIP-016 | Consensus — Multi-agent coordination and consensus | `tenzro-agent` swarm manager |
| TNIP-017 | Tenzro Binding — Tenzro Network identity + verification | `tenzro-node` (this repo) |
| TNIP-018 | Tempo Binding — Tempo Network payment + MPP | `tenzro-payments` Tempo integration |
| TNIP-019 | Canton Binding — Canton Network private settlement | `tenzro-vm` DAML executor |
| TNIP-020 | EVM Binding — ERC-8004 NFT identity on EVM | `tenzro-identity::erc8004` |
| TNIP-021 | Solana Binding — R8004 Token-2022 soulbound NFTs | `tenzro-bridge` Solana adapter |
| TNIP-022 | x402 Binding — x402 micropayment protocol | `tenzro-payments::x402` |

The full per-spec mapping with field-level translations and conformance gaps is at `implementations/tenzro.md` in the OAN repo.

## TNIP status flow

Each TNIP carries a `Status` field. The identifier is stable across stages — `TNIP-NNN` refers to the same document whether Draft or Final.

| Status | Meaning |
|---|---|
| Draft | Initial proposal. Open for substantive change. |
| Review | Editorial review complete. Open for community comment. |
| Last Call | Final review window. Substantive change requires consensus. |
| Final | Ratified. Substantive change requires a successor TNIP. |
| Deprecated | Superseded or withdrawn. |

All 22 TNIPs are currently Draft.

## What "OAN-conformant" means for Tenzro Network

A Tenzro Network deployment claims OAN conformance when:

1. AgentCards are published at `/.well-known/tn/agent-card.json` with JCS-canonicalized signatures.
2. MeshNodeCards are published per TNIP-003 §4.1.
3. ValidationRecords from `ZkCommitmentRegistry` and TEE attestation paths emit OAN-shaped JSON envelopes per TNIP-005 §4.2.
4. AgentCard signatures validate under JCS (RFC 8785).

The Tenzro Network adoption path is staged in three steps (read-only publishing, federation push, federation pull). Each step is described in `implementations/tenzro.md`.

## Boundary

- **OAN specs are authoritative for the wire format.** Tenzro Network adapts to the wire; the specs do not adapt to Tenzro Network.
- **Tenzro Network keeps its native types** (TDIP identities, MeshReceipts, on-chain validation records). OAN projection happens at the boundary.
- **No reference-implementation privilege.** Tenzro Network's status as the reference implementation does not privilege it in OAN conformance — any other implementation conforming to the OAN wire format is equally valid.

## See also

- `WHITEPAPER.md` for the broader Tenzro Network architecture.
- `TDIP.md` for Tenzro Network's identity layer (which projects to OAN TNIP-001 and TNIP-012).
