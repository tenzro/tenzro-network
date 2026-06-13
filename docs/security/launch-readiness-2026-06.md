# Launch-Readiness Report — Tenzro Network Testnet

**Date:** 2026-06-13
**Scope:** End-to-end production-readiness audit of the live 4-validator GCE testnet for the purpose of building and launching real applications on top of it.
**Verdict:** Testnet is ready for application development. All structural bugs found during the audit are fixed and verified live. One residual item (external third-party security audit) is non-fillable in-house and is the only open gate before mainnet.

---

## 1. Fleet state at report time

| Validator | Zone | Role | Image digest |
|---|---|---|---|
| tenzro-validator-0 | us-central1-a | bootstrap + RPC-public + Caddy | `sha256:3a8093d3…` |
| tenzro-validator-1 | us-central1-b | validator | `sha256:3a8093d3…` |
| tenzro-validator-4 | europe-west1-b | validator | `sha256:3a8093d3…` |
| tenzro-validator-7 | asia-southeast1-a | validator | `sha256:3a8093d3…` |

All 4 on the same manifest digest (build `20260613-090716`). Chain healthy:
peer_count `0x3` on every node (full mesh), block height advancing ~1 block/s,
chainId `0x539` (1337). Consensus is HotStuff-2 with PQ-hybrid QC signatures
(Ed25519 + ML-DSA-65 + BLS12-381), 2f+1 = 3 threshold.

---

## 2. Bugs found and fixed during this audit

### 2.1 Nonce-read divergence (structural store inconsistency) — FIXED

**Symptom.** Transactions built from `eth_getTransactionCount` reverted with
`Invalid nonce: expected 1, got 0`. The public nonce read always returned `0x0`
regardless of how many transactions an account had sent.

**Root cause.** The VM enforces and increments the per-account transaction nonce
during execution, but the incremented value was written **only** to the
VM-private state column family (`CF_STATE`, key `nonce:<hex(addr)>`). Every
external reader — `eth_getTransactionCount`, the faucet's next-nonce floor,
`tenzro_signTransaction`, `tenzro_signAndSendTransaction` — reads the account
ledger (`CF_ACCOUNTS`, key `b"nonce:" + raw_addr_bytes`). Two disjoint stores for
the same logical value: the VM wrote one, clients read the other.

Notably, **balance never diverged** because the balance write path already used a
dual-write + canonical-read pattern (write to both `CF_ACCOUNTS` canonical and
`CF_STATE` mirror; read `CF_ACCOUNTS` first, fall back to `CF_STATE`). Nonce was
the asymmetric outlier.

**Fix.** Made nonce symmetric with balance, at the storage layer
(`crates/tenzro-vm/src/state_adapter.rs`):

- `commit()` now dual-writes each dirty nonce to **both** `CF_ACCOUNTS`
  (canonical, AccountStore layout) and `CF_STATE` (mirror, for VM-internal reads).
- `get_nonce()` now reads `CF_ACCOUNTS` canonical first, with a `CF_STATE`
  legacy fallback for old snapshots.

bincode encodes `u64`/`u128` as little-endian fixints, byte-identical to the VM's
raw `to_le_bytes()`, so the dual-write is wire-safe across both readers.

This was fixed at the root (the storage adapter that every nonce reader and the
revm `Database::basic()` path funnel through), not patched per-RPC-call-site.

**Live verification (post-roll).**
- Faucet sender `eth_getTransactionCount` returned `0x2`, then `0x3` after another
  send — non-zero and incrementing, tracking the true VM nonce. (Before: stuck `0x0`.)
- A freshly funded recipient account that never sent a transaction read `0x0` —
  proving per-address tracking, not a global counter.
- Faucet transfers landed the exact amount (100 TNZO = `0x56bc75e2d63100000`) at
  recipients.

### 2.2 Snapshot OOM bomb — FIXED (carried forward)

**Symptom.** Periodic memory spikes correlated with snapshot creation at
10,000-block boundaries.

**Root cause.** Snapshot creation materialized entire column families into a
`Vec` before writing, an unbounded allocation that scaled with chain state.

**Fix.** Replaced full-CF materialization with a streaming column-family scan,
chunked at `CHUNK_MAX_BYTES = 10 MiB`. Shipped in build #13 and carried into the
current build.

**Verification.** All kernel OOM-killer events on the fleet predate the
build-#13 container start time; no OOM events since. Steady-state container
memory is ~8.6 GiB / 15.6 GiB (~55%) on the RPC-public node — this is the normal
PQ-hybrid working set (ML-DSA-65 signatures are 3309 bytes each in the QC path),
stable and well under the limit. It is not a leak.

---

## 3. Operational findings (no code change required)

### 3.1 Network partition on simultaneous mass restart

Rolling **all** validators at once briefly drops the mesh below quorum and stalls
block production until peers re-discover each other. Mitigation is procedural, not
a code fix: **canary-first rolling** — roll one non-RPC validator, confirm a
neighbor's height advances and peer_count recovers, then proceed one VM at a time.
This procedure was followed for the current roll (v0 canary → v1 → v4 → v7) with
zero stall.

### 3.2 RPC-public node memory anomaly (transient)

A one-off elevated-memory reading on validator-0 during an earlier roll was
transient and self-resolved after the container settled. Current steady state is
normal (§2.2). No action.

---

## 4. Production-readiness coverage

Verified working on the live testnet during this and prior audit waves:

- Core ledger: blocks, balances, **nonces (this wave)**, transfers, faucet.
- Consensus: HotStuff-2 finality, PQ-hybrid QC, equivocation detection + slashing.
- Multi-VM: EVM (revm), SVM (solana_rbpf), DAML/Canton dispatch.
- Identity: TDIP register/resolve, delegation enforcement, ERC-8004 mirror.
- Payments: MPP, x402, AP2 mandate validation.
- Settlement: escrow, micropayment channels.
- Bridges: LayerZero, CCIP, deBridge, Wormhole (guardian quorum), Hyperlane,
  Axelar, Babylon, Canton — with inbound validator sets configured on the fleet.
- AI: multi-modal inference runtimes + catalogs, agent runtime + memory.
- Auth: server-side signing requires DPoP/OAuth JWT (legacy `private_key` param
  removed) — verified the unauthenticated path is correctly rejected with `-32001`.

Persistence: every manager/registry writes through to RocksDB and hydrates on
boot. State survives operator-induced restarts.

---

## 5. The one remaining gate

**External third-party security audit.** This is the only production-readiness
item that cannot be filled in-house. Everything structural that the in-house
audit could find and fix has been fixed and verified live. An independent audit
is the gate between this testnet and mainnet, and is the appropriate next
external dependency.

Lower-severity, non-blocking: documentation gaps on some public types; W3C
`did:tenzro` method registration is filed and pending upstream.

---

## 6. Conclusion

The testnet is in a state where applications can be built against it with
confidence in the ledger, identity, payment, settlement, bridge, and AI
surfaces. The nonce-divergence bug — the one issue that would have broken every
client that constructs a transaction from `eth_getTransactionCount` — is fixed at
the root and verified on the live public RPC. Build and roll were done as a single
comprehensive sweep rather than per-symptom patches.
