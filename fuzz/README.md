# Tenzro fuzz harnesses

Coverage-guided fuzzing (libFuzzer via `cargo-fuzz`) for the code paths
that consume untrusted input: bridge inbound messages, consensus frame
ingestion, settlement channel signatures, staking arithmetic,
transaction decoding, and settlement plans.

This directory is a standalone package (empty `[workspace]` table in
`Cargo.toml`) — it is not a member of the root workspace and does not
affect `cargo build --workspace`.

## Targets

| Target | Crate under test | Property |
|---|---|---|
| `bridge_route_delivery` | tenzro-bridge | `Delivery::decode` never panics on arbitrary bytes, and any delivery it accepts re-encodes to exactly the input |
| `consensus_frame` | tenzro-consensus | no frame a committee member can send panics `Frame::decode` or the protocol core (`Core::on_messages`, `on_tick`) |
| `staking_arithmetic` | tenzro-vm | bonding, unbonding, withdrawal and the correlated equivocation slash return typed errors across the full u128 range, never panic, and keep the total bond equal to the sum of the bonds |
| `settlement_channel_state` | tenzro-settlement | 40-byte canonical preimage is stable; strict Ed25519 verification rejects malformed keys/signatures of any length without panicking |
| `transaction_decode` | tenzro-types | arbitrary JSON or bincode never panics `Transaction::hash` or `SignedTransaction::validate` |
| `settlement_plan` | tenzro-types | any decodable `PlanOp` validates without panic and round-trips; any valid split rule divides any gross exactly and deterministically |
| `gossip_decode` | tenzro-network | no bytes a neighbour publishes panic gossip framing and validation; a decoded message round-trips |
| `jsonrpc_parse` | tenzro-types | no JSON-RPC body (call or batch) panics request decoding (envelope, version, params) |
| `settlement_native` | tenzro-vm | no calldata panics the settlement plan native entry; a refused call moves nothing and an accepted one creates no value |
| `bridge_verify` | tenzro-bridge | delivery decoding, committee signature checks and receipt proofs never panic; no delivery passes a committee none of whose members signed |
| `iroh_request` | tenzro-iroh | request, consensus and discovery stream framing never panics, refuses lengths above the limit and returns a body only when all of it arrived; discovery requests and boot lists decode without panic |
| `identity_documents` | tenzro-identity | DIDs, DID documents, signed DID envelopes, delegation scopes, KERI events and agent registry ABI answers decode without panic |
| `auth_tokens` | tenzro-auth | access tokens, DPoP proofs, JWK thumbprints and WebAuthn registration data never panic, and no fuzzed token validates |
| `http_signature` | tenzro-payments | RFC 9421 signature headers, signature bases and every verification algorithm never panic; no request verifies under an asymmetric key the input chose |
| `tee_attestation` | tenzro-tee | TDX, SEV-SNP, Nitro and NVIDIA evidence and the X.509 under it never panic, and no fuzzed evidence verifies |
| `device_attestation` | tenzro-device-key, tenzro-tee | TPM key certifications, wire structures, machine evidence and sealed envelopes never panic; no fuzzed certification or quote verifies |
| `x402_payload` | tenzro-payments | x402 payment headers, payload credentials and ERC-7710 redemption proofs never panic; no fuzzed delegation chain verifies |
| `ton_cell` | tenzro-bridge | no bytes panic the TON bag-of-cells decoder; an accepted root re-serializes to a bag that parses back to the same cell; checking it as a Merkle proof never panics |
| `ml_dsa_differential` | tenzro-crypto | the RustCrypto and libcrux ML-DSA-65 verifiers give the same verdict on every key, message, context and signature, starting from real signatures and editing them |
| `proof_decode` | tenzro-finality, tenzro-cert-stark, tenzro-zk | finality journals, compact certificates, their claims and ML-DSA keys and signatures, proof envelopes of every system (alone and as legs of a diverse statement) and Groth16 finality seals never panic; a journal or claim that decodes re-encodes to exactly the input; no fuzzed proof, legs or seal verifies |
| `agent_protocol_messages` | tenzro-node (light build) | A2A requests and their signed DID envelopes, A2A agent cards and MCP client metadata documents never panic; no fuzzed envelope verifies against a wallet nobody holds |

## Scheduled runs

The scheduled suite's `fuzz` stage (`scripts/testnet/stages.sh`) runs once a
night (`DAILY_STAGES`), whether or not main moved. It builds every target in
this package (a check fails the suite when one is missing from the stage) and
runs them, `FUZZ_PARALLEL` at a time for `FUZZ_SECONDS` each, inside a network
namespace that has only a loopback, keeps their corpora between passes and
files each new crash with its replay command. A crash is fixed red then green: the input goes under `regressions/<target>/` with the fix, so it is replayed on every pass. Inputs under `regressions/<target>/` (each once crashed or stalled a target) are replayed first on every pass and seed the target's corpus; `seeds/<target>/` holds the starting corpus of each target. It builds with the pinned
toolchain (`RUSTC_BOOTSTRAP=1 cargo fuzz build -O --debug-assertions
--sanitizer none`), since a panic or failed assertion is what these targets
look for.

## Running

Requires nightly Rust and `cargo-fuzz`. Run on a Linux build host
(fuzzing is not run on developer laptops):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

cd fuzz
cargo +nightly fuzz run bridge_route_delivery -- -max_total_time=3600
```

Run every target for a fixed budget:

```bash
for t in bridge_route_delivery consensus_frame \
         settlement_channel_state staking_arithmetic \
         transaction_decode settlement_plan; do
  cargo +nightly fuzz run "$t" -- -max_total_time=1800 -rss_limit_mb=4096
done
```

Crashes land in `artifacts/<target>/`; reproduce with:

```bash
cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>
```

Corpora persist in `corpus/<target>/` and are gitignored — keep them on
the build host between runs for cumulative coverage.
