# Tenzro fuzz harnesses

Coverage-guided fuzzing (libFuzzer via `cargo-fuzz`) for the code paths
that consume untrusted input: bridge inbound messages, consensus vote
ingestion, settlement channel signatures, staking arithmetic,
transaction decoding, and ERC-7683 intent primitives.

This directory is a standalone package (empty `[workspace]` table in
`Cargo.toml`) — it is not a member of the root workspace and does not
affect `cargo build --workspace`.

## Targets

| Target | Crate under test | Property |
|---|---|---|
| `bridge_inner_message` | tenzro-bridge | `verify_inner_message` never panics on arbitrary bytes; malformed hashes/signatures/nonces are rejected with typed errors |
| `wormhole_vaa` | tenzro-bridge | `Vaa::parse` + `verify_quorum` fail closed without panicking inside secp256k1 recovery on attacker-controlled (r,s,v) |
| `consensus_vote` | tenzro-consensus | bincode/JSON-decoded `Vote`s can never panic `signing_payload` or `VoteCollector::add_vote` (format-version gate, `high_qc_view < view` invariant, membership check) |
| `settlement_channel_state` | tenzro-settlement | 40-byte canonical preimage is stable; strict Ed25519 verification rejects malformed keys/signatures of any length without panicking |
| `staking_arithmetic` | tenzro-token | stake/slash/unstake and liquid-staking pool math return typed errors on overflow/underflow across the full u128 range — never panic |
| `transaction_decode` | tenzro-types | arbitrary JSON never panics `Transaction::hash` or `SignedTransaction::validate` |
| `intent_7683` | tenzro-types | uint256↔u128 round-trip; non-zero high 128 bits rejected (no silent truncation); `compute_order_id` deterministic and total |

## Running

Requires nightly Rust and `cargo-fuzz`. Run on a Linux build host
(fuzzing is not run on developer laptops):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
cargo +nightly fuzz run bridge_inner_message -- -max_total_time=3600
```

Run every target for a fixed budget:

```bash
for t in bridge_inner_message wormhole_vaa consensus_vote \
         settlement_channel_state staking_arithmetic \
         transaction_decode intent_7683; do
  cargo +nightly fuzz run "$t" -- -max_total_time=1800 -rss_limit_mb=4096
done
```

Crashes land in `artifacts/<target>/`; reproduce with:

```bash
cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>
```

Corpora persist in `corpus/<target>/` and are gitignored — keep them on
the build host between runs for cumulative coverage.
