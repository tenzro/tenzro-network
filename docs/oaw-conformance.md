# OAW Conformance

This document points to the Open Agent Web (OAW) protocol specifications and describes how Tenzro Network maps onto each.

## Pointer

- **OAW specification repository:** [github.com/ipnops/open-agent-web](https://github.com/ipnops/open-agent-web) (working tree at `~/AI/ipnops-open-agent-web/`).
- **Foundational paper:** `papers/open-agent-web.md`.
- **Tenzro mapping (authoritative):** `implementations/tenzro.md` in the OAW repo.
- **Spec family:** `spec/00-overview.md` through `spec/06-federation.md`.

## Why this file exists

OAW is a separately-stewarded protocol family (sponsoring entity: Ipnops). Tenzro Network is the full-stack reference implementation. The OAW specs are the authority for OAW conformance; this document is informational for Tenzro developers.

The OAW repository MUST NOT reach into Tenzro source. This document is the only place in the Tenzro repository that points back to OAW specs. Updates to OAW that change Tenzro's conformance posture are tracked in the OAW repo's `implementations/tenzro.md`, not here.

## Specs at a glance

| OAW spec | What it is | Tenzro subsystem |
|---|---|---|
| IPN-001 Resolver | DIDs and AgentCards | `tenzro-identity` (TDIP) |
| IPN-002 Skills | Portable skill manifests | `tenzro-agent-kit` |
| IPN-003 Mesh | Content-addressed paid hosting | `tenzro-storage` Mesh layer |
| IPN-004 Discover | Conversational discovery | Tenzro Discover (planned) |
| IPN-005 Validation | TEE / ZK / optimistic / restaked | `tenzro-tee`, `tenzro-zk`, `ZkCommitmentRegistry` |
| IPN-006 Federation | Cross-registry mirror | `tenzro-network` registry mirror (planned) |

The full per-spec mapping with field-level translations and conformance gaps is at `implementations/tenzro.md` in the OAW repo.

## What "OAW-conformant" means for Tenzro

A Tenzro deployment claims OAW conformance when:

1. AgentCards are published at `/.well-known/oaw/agent-card.json` with JCS-canonicalized signatures.
2. MeshNodeCards are published per IPN-003 §4.1.
3. ValidationRecords from `ZkCommitmentRegistry` and TEE attestation paths emit OAW-shaped JSON envelopes per IPN-005 §4.2.
4. AgentCard signatures validate under JCS (RFC 8785).

The Tenzro adoption path is staged across three waves (read-only publishing, federation push, federation pull). Wave details are in `implementations/tenzro.md`.

## Boundary

- **OAW specs are authoritative for the wire format.** Tenzro adapts to the wire; the specs do not adapt to Tenzro.
- **Tenzro continues to ship its native types** (TDIP identities, MeshReceipts, on-chain validation records). OAW projection happens at the boundary.
- **No vendor lock-in.** Tenzro's claim to be a reference implementation does not privilege Tenzro in OAW conformance — any other implementation conforming to the OAW wire format is equally valid.

## See also

- The Tenzro Foundation document at `FOUNDATION.md` (covers the general Tenzro stewardship posture).
- The Tenzro WHITEPAPER at `WHITEPAPER.md` (covers the broader Tenzro architecture).
- `TDIP.md` for Tenzro's identity layer (which projects to OAW IPN-001).
