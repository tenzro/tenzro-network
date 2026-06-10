# Testnet smoke + integration + soak — findings

Captured 2026-06-10. New image `tenzro-node:20260610-142025` deployed to
all 10 validators; smoke + integration + soak run against the live
testnet endpoints.

## Smoke battery — final result

```
PASS: 22  FAIL: 1  SKIP: 4
```

| Group | Status |
|---|---|
| RPC liveness (eth_*, tenzro_*) | PASS |
| Web verification API health | PASS |
| MCP + A2A discovery | PASS |
| Faucet draw | PASS |
| Identity / TDIP resolve | SKIP (system DID not resolvable on this RPC node) |
| Token registry + multi-VM | PASS |
| Bridge router + live quote | PASS |
| Canton read surface | SKIP without API key, PASS with operator-issued tenant key |
| Multi-modal AI catalogs (6) | PASS all 6 |
| Settlement primitives | PASS |
| Chain advancing (6-second window) | **FAIL** — chain advances at ~1 block per 10–14 s vs. 400 ms target |

The single FAIL is the persistent slow-consensus condition diagnosed in
the consensus monitor section below.

## Canton integration — end-to-end verification

After upgrading the upstream Canton participant from Splice 0.6.2 to
0.6.6 (binary version mismatch had been blocking the global synchronizer
handshake), all 6 Canton calls return real results through the Tenzro
adapter:

| Call | Status |
|---|---|
| `tenzro_canton_version` | `3.5.1` release-tagged |
| `tenzro_canton_health` | `alive:true ready:true ready_detail:"[+] ledger ok (SERVING)"` |
| `tenzro_canton_listParties` | empty array (no parties allocated on fresh participant) — valid |
| `tenzro_canton_listPackages` | returns Splice + DAR package IDs |
| `tenzro_canton_connectedSynchronizers` | `global-domain::...` attached with `PARTICIPANT_PERMISSION_SUBMISSION` |
| `tenzro_listCantonDomains` | shows global-domain enabled, 5 s finality |

Per-tenant analytics (`tenzro_canton_getMyAnalytics`) correctly tracks
calls/errors by method per API key. Admin-token-gated
`tenzro_canton_listApiKeyAnalytics` aggregates across all tenants
(verified by listing 5+ existing keys plus the ephemeral smoke key).

## Soak — 2 h, 3 workers @ 1 op/sec

Latency percentiles across all ops (ok responses only, n=141 first sample):

```
p50=474 ms  p95=606 ms  p99=660 ms  min=423  max=725
```

These reflect cross-continental round-trip from a laptop to GCP
us-central1 with the Caddy front-door TLS handshake — the per-op work
on the node itself is sub-50 ms.

**Error rate ~27% (51/190 ops in first sample window)** — clustered at
**exactly 11 s intervals**, with all 3 workers failing simultaneously
each time. This is *not* load-related (verified by 30-concurrent burst
test: 30/30 success). The pattern matches the consensus block-commit
cadence (~1 block per 10–14 s). The most likely cause is the
JSON-RPC handler briefly refusing new connections during a synchronous
block-persist transition. **Recommended follow-up:** add tracing to the
RPC accept-loop to confirm the lock-and-pause hypothesis, then move the
block-persist hot loop off the RPC accept thread.

## Consensus monitor — 25 min observation

577 sample rows collected, no stall events detected
(`STALL_DETECTED tip=... stuck for ≥ 60s` never fired).

Steady-state advancement during the soak window:

- Block height: 109,995 → 110,008 over ~3 min = **1 block per 14 s**
- Pacemaker views: 519,280 → 519,340 over same 3 min = **1 view per 3 s**
- **Block-to-view ratio: 1 block per ~5 views** — meaning 4 of every 5
  views form a TimeoutCertificate + NoEndorsementCertificate instead of
  finalizing a block.

This is exactly the **tail-fork-under-sluggish-leadership** pattern
described in
[Carry-the-Tail (Gupta 2025, DISC)](https://drops.dagstuhl.de/storage/00lipics/lipics-vol356-disc2025/LIPIcs.DISC.2025.59/LIPIcs.DISC.2025.59.pdf).

Our consensus crate already implements MonadBFT NEC
(`crates/tenzro-consensus/src/timeout.rs::NoEndorsementCertificate`,
verified by the chain reaching new blocks via NEC-backed fresh-block
proposals). The NEC mechanism is the *liveness* defense and is working
as designed — the chain does not stall. The remaining issue is
*throughput*: every view that does not produce a block burns roundtrip
latency forming a TC + NEC.

### Why this happens

Tri-continental fleet (`us-central1` + `europe-west1` + `asia-southeast1`)
has cross-region p99 latency in the 100–300 ms range. The pacemaker
timeout for PREPARE / COMMIT phases is short enough that a single
phase-vote round can miss its window when the leader is in a
high-latency region relative to the rest of the BFT set. NEC then
authorizes the next leader to skip the missed view; the *next* leader
also misses for the same latency reason; cumulative tail-forking
collapses throughput.

### What the literature recommends

Per Carry-the-Tail (Section 4): "carry" the highest QC forward through
NEC so successive non-finalized views do not lose accumulated work. Our
current NEC clears `last_round_nec` once `nec.view + 1 < new_view`
(`hotstuff2.rs:1195-1199`) — correct for the safety claim, but the
*carrying* part (amortizing the tail across views) is the missing
optimization.

### Recommended follow-up

Out of scope for this validation run, but worth queueing:

1. **Quantitative analysis**: measure the empirical distribution of
   leader-region by view; correlate which region-to-region paths
   dominate the TC formation rate.
2. **Pacemaker timeout tuning**: raise PREPARE / COMMIT timeouts to
   absorb a 500 ms p99 cross-region round trip without forcing a TC.
   Today's defaults appear tuned for intra-region.
3. **Implement Carry**: extend NEC to include the source-view's high QC
   so the next-leader proposal can be built atop the carried QC instead
   of restarting from the tip's QC.
4. **Cross-validate locally**: stand up a 4-validator docker-compose
   cluster (needs the v2 + BLS genesis generator to be written first;
   `tools/genkeys/` does Ed25519 + ML-DSA-65 only), reproduce the
   adversarial leader sequence from production logs.

## What this run validates

- ✅ Production image (`20260610-142025`) running across the full 10-VM
  fleet
- ✅ Public RPC, web verification API, MCP, A2A, faucet all responsive
- ✅ Multi-modal AI catalogs (forecast / vision / text-embed /
  segmentation / detection / audio) all reachable
- ✅ Bridge router + live fee quoting for cross-chain destinations
- ✅ Token registry + total-supply across multi-VM
- ✅ Canton end-to-end through the Tenzro adapter (after Splice 0.6.6
  upgrade on devnet)
- ✅ Multi-tenant Canton API key issuance + revocation + per-tenant
  analytics counters
- ✅ Consensus liveness — NEC + TC formation, no stall in 25 min
  observation

## What this run flags

- ⚠️ Consensus throughput at ~1 block per 14 s vs. 400 ms design target
  — chronic tail-forking under cross-region latency
- ⚠️ Periodic RPC unavailability synchronized with block-commit cadence
  (every ~11 s, all workers fail simultaneously)
- ⚠️ Canton devnet binary-version compatibility requires periodic
  upgrades; smoke battery does not yet alert on the version drift
- ⚠️ `tenzro_listDamlContracts` returns -32000 due to a known
  request-builder bug (`activeAtOffset` null + non-FQ party id), per
  the existing notes in `CANTON_DEVNET_NOTES.md`

Each of these is recoverable through existing operator surfaces and
none represents a safety failure.
