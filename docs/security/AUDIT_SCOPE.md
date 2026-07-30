# External audit scope

Prepared for a scoped engagement with an external security firm. Read
alongside `THREAT_MODEL.md` (assets, actors, boundaries, residual
risks) and `INVARIANTS.md` (falsifiable claims with code anchors).

## Repository layout

Rust workspace, edition 2024, 32 crates under `crates/` plus
`tools/genkeys`. Fuzz harnesses live in `fuzz/` as a standalone
package. Criterion benchmarks live in per-crate `benches/` directories.
Python integration packages (`integrations/`), SDKs (`sdk/`), the
desktop app (`apps/`), and the website are out of the proposed core
scope.

## Risk tiers

### Tier 1 — funds or consensus at direct risk (audit in depth)

| Crate | Why | Untrusted input |
|---|---|---|
| `tenzro-consensus` | HotStuff-2 vote/QC/view-change logic, equivocation detection, slashing trigger | Gossip bytes (bincode + JSON `Vote` decode) |
| `tenzro-bridge` | Cross-chain transfer authorization, VAA/ISM/OCR envelope verification, threshold-signing seam | Foreign-chain messages, adapter API responses |
| `tenzro-settlement` | Escrow funds custody, micropayment channel signatures, batch atomicity | Channel-state updates, settlement requests |
| `tenzro-token` | Staking, slashing, liquid staking, treasury, governance, adaptive burn | RPC params, governance proposals |
| `tenzro-vm` | EVM/SVM/DAML execution, precompiles, ERC-4337/7579/7702, Permit2, secure-mint | Contract bytecode, UserOperations, calldata |
| `tenzro-crypto` | All signature verification, MPC, BLS, VRF, envelope encryption | Signatures, public keys, proofs |
| `tenzro-wallet` | MPC key shares, keystore encryption, transaction building | Keystore files, sign requests |
| `tenzro-types` | Canonical transaction hashing, ERC-7683 primitives — every signature binds to these | JSON/bincode from RPC, MCP, A2A, the web API, and peer gossip |

### Tier 2 — authorization and identity (audit targeted)

| Crate | Why |
|---|---|
| `tenzro-identity` | DID resolution, delegation-scope enforcement, credential chains, cascading revocation |
| `tenzro-payments` | MPP/x402/Stripe/Tempo settlement, spending-policy two-axis check, AP2 mandate validation |
| `tenzro-auth` | DPoP, JWT/JWS, OAuth surfaces |
| `tenzro-tee` | Attestation verification (chain-of-trust to pinned vendor roots), enclave crypto |
| `tenzro-zk` | Plonky3 STARK verification, commitment registry feeding the `ZK_VERIFY` precompile |
| `tenzro-node` (RPC layer) | Admin-token gate, API-key scopes, Canton tenant isolation, transaction submission paths |
| `tenzro-keystore-unlock`, `tenzro-device-key` | Key-material handling on user devices |

### Tier 3 — availability and integrity (review, not line-by-line)

`tenzro-network` (peer auth, rate limits, NAT stack),
`tenzro-storage` (fsync discipline, trie proofs), `tenzro-iroh`
(blob verification, ALPN dispatch), `tenzro-training` (aggregation
rules, witness committee, sealed shards), `tenzro-media-gen`
(job-id binding, pixel-step pricing ceiling, split-expert handoff and
payment division, receipt commitment), `tenzro-agent` /
`tenzro-agent-kit` (lifecycle, spawn tree, memory tier),
`tenzro-events`, `tenzro-workflow`, `tenzro-cortex`, `tenzro-model`,
`tenzro-storage-provider`, `tenzro-database` (descriptor,
placement, access control, gossip), `tenzro-cluster` (reachability
tiers, link-cost probing, rendezvous placement), `tenzro-wasm` (WASI
sandbox boundary), `tenzro-cli`, `tools/genkeys`.

## Entry-point map

| Surface | Port | Code | Auth |
|---|---|---|---|
| libp2p gossip + request-response | 9000 tcp/quic | `tenzro-network`, dispatch in `tenzro-node/src/event_loop.rs` | Peer scoring; validator-only topics via `peer_manager.rs:386` |
| JSON-RPC | 8545 | `tenzro-node/src/rpc.rs` (855 methods) | None (public) / API key / admin token (`rpc.rs:641`) |
| Web verification API | 8080 | `tenzro-node/src/web/server.rs` | None; `/chat` optionally 402-gated |
| MCP | 3001 (+3003–3008) | `tenzro-node/src/mcp/` | None on testnet |
| A2A | 3002 | `tenzro-node/src/a2a/` | None on testnet |
| iroh ALPNs (`tenzro/a2a`, `tenzro/mcp`, blobs) | QUIC | `tenzro-iroh` | Endpoint identity = TDIP Ed25519 key |
| Bridge inbound | n/a (adapter polling / relayer delivery) | `tenzro-bridge` per-adapter `receive_message` | Envelope verification per adapter |

## Evidence inventory

### Tests
`cargo test --workspace` green across all crates. Unit tests colocated
in `mod tests`; integration tests in per-crate `tests/`. Current
counts: `cargo nextest list --workspace`.

### Fuzzing (`fuzz/`)
Seven libFuzzer targets over the untrusted-input hot paths:
`bridge_inner_message`, `wormhole_vaa`, `consensus_vote`,
`settlement_channel_state`, `staking_arithmetic`,
`transaction_decode`, `intent_7683`. Target-to-invariant mapping in
`INVARIANTS.md`; run instructions in `fuzz/README.md`. Corpora are
young — auditors should treat existing coverage as a starting point.

### Benchmarks
Criterion benches in 16 crates (17 files):
bridge, consensus, crypto, identity, iroh, model, payments,
settlement, storage, tee, token, training, types, vm (execution +
passkey), wallet, zk. These document hot-path performance envelopes
(signature verification, STARK verify, channel updates, Block-STM)
and can support DoS-cost reasoning.

### Live deployment
4-validator testnet on GCE (genesis schema v3: Ed25519 + ML-DSA-65 +
BLS12-381 per validator), public RPC at `rpc.tenzro.xyz`. TEE
simulation disabled on all live nodes.

## Known limitations to probe

1. Bridge outer-envelope verification is skipped for adapters without
   an installed guardian/validator set (misconfiguration weakens a
   lane silently). See `THREAT_MODEL.md` residual risk 1.
2. Training round finalization commits coordinator-supplied
   `post_step_hashes` without recomputing them from trainer payloads.
3. `tenzro-crypto` BLS aggregation uses a SHA-256 hash-to-curve stub
   in some aggregate paths; composite Ed25519 + ML-DSA-65 per-vote
   verification is the binding check.
4. `crates/tenzro-consensus/src/voter.rs:59` doc comment states the
   vote format version is 3; the constant at `voter.rs:53` is 4
   (documentation drift, not a logic bug — flagged for cleanup).
5. Raw-env-key bridge signer backend exists alongside the TEE-sealed
   and threshold backends.
6. RocksDB contents are trusted at hydration; no integrity layer
   below the process boundary.
7. Plonky3 proving is CPU-only; proof verification cost per request
   is a DoS consideration on public verify endpoints.

## Suggested engagement shape

1. **Week 1–2:** Tier 1 crates — consensus vote/QC state machine,
   bridge envelope verification + replay protection, settlement
   channel/escrow authorization, staking arithmetic, canonical
   transaction hashing.
2. **Week 3:** Tier 2 — RPC authorization matrix (admin token, API-key
   scopes, Canton tenant isolation), delegation-scope enforcement,
   TEE attestation chain validation, ZK commitment registry.
3. **Week 4:** Targeted review of Tier 3 plus continuous fuzzing of
   the seven harnesses on auditor infrastructure; triage of any
   crashes against `INVARIANTS.md`.
