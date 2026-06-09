# Bridge / Fee Oracle / ERC-7683 Benchmarks — Wave 12

**Date:** 2026-06-09  
**Image:** `tenzro-node:20260609-192215` @ `sha256:224873abda61b80070d9bce7abf93665aac43a8c29ca27c2be3217343d829277`  
**Hardware:** Apple Silicon (aarch64, Darwin 24.1.0), local dev.  
**Mode:** `cargo bench --release` (criterion `--quick` calibration).

## Results

### Bridge message wire (`TenzroMessage`)

| Operation | Time |
|---|---|
| `new_token_transfer_256b_payload` | (within sub-µs of `compute_hash`) |
| `sign / ed25519` (256B payload) | **31.96 µs** |
| `sign / secp256k1` (256B payload) | **49.84 µs** |
| `verify / ed25519` | **41.03 µs** |
| `encode_json` (signed envelope) | **2.71 µs** |
| `decode_json` (signed envelope) | **5.64 µs** |

### Fee-in-TNZO oracle (Wave 9)

| Operation | Time |
|---|---|
| `governance_set_quote_single_pair` | **964 ns** |
| `governance_set_quote_all_8_adapters` (sequential) | **8.16 µs** |

The governance-set oracle is a `DashMap` point read + `mul_q18` arithmetic + SHA-256 over the canonical preimage. The all-8-adapter run is dominated by the SHA-256 per-quote (~1 µs each).

### Fee sponsor (Wave 9/10)

| Operation | Time |
|---|---|
| `record_sponsorship_single` | **1.42 µs** |

Includes quote-expiry check, per-adapter pool upsert, receipt SHA-256, in-memory receipt insert.

### Bridge router (Wave 9/10)

| Operation | Time |
|---|---|
| `list_sponsorship_pools_8_adapters` | **350 ns** |

Cold-path read of the full per-adapter pool snapshot. Note this is 8 deterministic vault addresses with current balances — well under microsecond.

### ERC-7683 envelope (Wave 11)

| Operation | Time |
|---|---|
| `compute_order_id` (with `BridgeFeeHint`) | **987 ns** |
| `serde_round_trip_order_data` (with `BridgeFeeHint`) | **1.55 µs** |

The order ID is SHA-256 over a domain-separated canonical preimage; serde round-trip is JSON encode + decode.

## Headline numbers for agent-grade transacting

For an agent that quotes-and-sponsors a single bridge fee in TNZO and constructs one ERC-7683 envelope:

- **Total path: < 6 µs** for the structural primitives (quote 1 µs + sponsor 1.4 µs + envelope construct + order id 1 µs + serde 1.5 µs).
- **Wire encode + decode of a signed TenzroMessage: 8.4 µs combined.**
- **Sign + verify with Ed25519: 73 µs** (dominated by signing).

Even at 1000 quotes/sec sustained, the structural primitives consume **6 ms/sec** — well below 1% of one core. The router fan-out scales linearly because the fee surface is per-adapter `DashMap` + per-pool `DashMap`.

## What's not measured here (because it's network-bound)

- Live `ChainlinkFeedClient::read_feed` (`eth_call` to a remote RPC) — bounded by RPC round-trip (50-300 ms for public endpoints, 5-20 ms for private). The 30s cache TTL eliminates the hot-path RPC for steady-state quoting.
- `BridgeRouter::bridge_tokens` end-to-end (network-bound).
- Cross-chain finality (~5 min for LayerZero/CCIP, ~15 min for Wormhole on Ethereum).

## Reproducibility

```bash
cargo bench -p tenzro-bridge --bench bridge_benchmarks -- --quick
```

For full statistical confidence (default criterion mode), drop `--quick`. The numbers in this report come from quick-mode calibration on a developer machine; production-grade benchmarks should pin a baseline GCE instance and rerun across versions.
