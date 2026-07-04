# Quantum-Resistance Audit — Tenzro Network

**Audit date:** 2026-04-27
**Audit method:** Repository-wide static analysis (7 parallel auditors) + live testnet TLS probe (`openssl s_client -trace` against `rpc.tenzro.network`, `api.tenzro.network`, `mcp.tenzro.network`, `a2a.tenzro.network`).
**Target migration:** Hybrid Ed25519 + ML-DSA-65 (FIPS 204) signing; hybrid X25519 + ML-KEM-768 (FIPS 203) key exchange; pure-PQ ZK as a separate follow-up; forward-compatible wire format.
**Threat models considered:** Shor's algorithm (breaks ECDLP — affects Ed25519, Secp256k1, BLS12-381, X25519); Grover's algorithm (halves symmetric/hash effective security); HNDL (Harvest Now Decrypt Later — relevant to recorded TLS sessions and any encrypted-at-rest material whose plaintext stays sensitive past CRQC).

---

## 1. Executive summary

Tenzro Network's cryptographic surface separates cleanly into three categories:

| Category | Scope | Migration posture |
|---|---|---|
| **TENZRO_INTERNAL_MIGRATABLE** | Consensus voting, native message signing, MPC threshold wallet, identity/credential issuance, RFC9421 payments, libp2p peer transport, outbound bridge HTTPS | Migrate to hybrid in this round |
| **DUAL_END** | W3C DID Documents, Verifiable Credentials | Add second `verificationMethod` entry; current spec already supports it |
| **EXTERNAL_LOCKED** | Secp256k1 EVM transaction signing, ERC-8004 Ethereum mirror, Wormhole VAA, LayerZero DVN, Chainlink CCIP DON, EVM `ecrecover` precompile, Solana Ed25519 | Cannot migrate unilaterally; document residual risk and accept |

**One pleasant surprise from the live probe:** the public TLS pipe (everything behind Caddy at `*.tenzro.network`) is **already negotiating X25519MLKEM768** as of 2026-04-27. ServerHello carries `key_share: NamedGroup: X25519MLKEM768 (4588)` and `signature_algorithms` advertises `mldsa65 (0x0905)`. Caddy 2.11 + Go 1.24 `crypto/tls` does this transparently. No Caddyfile change is required. Public client→RPC traffic is therefore not on the critical path for this migration; the work is internal.

**The migration is consensus-breaking.** `Transaction::hash()` preimage (in `crates/tenzro-types/src/transaction.rs:75-95`) feeds the consensus layer; adding `pq_signature` and `pq_public_key` fields changes the hash and invalidates pre-PQ blocks. Tenzro is pre-alpha with no live users, so this round will execute as a flag-day cutover at the next testnet wipe. No dual-codepath, no backwards-compat shim.

---

## 2. Findings by primitive

### 2.1 Signing (Ed25519, Secp256k1, BLS12-381, VRF)

#### TENZRO_INTERNAL_MIGRATABLE

| Site | File:Line | Function |
|---|---|---|
| HotStuff-2 vote signing | `crates/tenzro-consensus/src/hotstuff2.rs:462` | `create_vote` |
| Vote collection / verify | `crates/tenzro-consensus/src/voter.rs:209,405` | `VoteCollector::collect` |
| BLS keypair generation | `crates/tenzro-crypto/src/bls.rs:442` | `BlsKeyPair::generate` |
| BLS sign | `crates/tenzro-crypto/src/bls.rs:491` | `BlsKeyPair::sign` |
| BLS verify | `crates/tenzro-crypto/src/bls.rs:408` | `BlsSignature::verify` |
| BLS aggregate verify | `crates/tenzro-crypto/src/bls.rs:630` | `AggregateSignature::verify` |
| BLS aggregate serialize | `crates/tenzro-crypto/src/bls.rs:598` | `AggregateSignature::to_bytes` |
| Credential proof verify | `crates/tenzro-identity/src/credential.rs:93` | `VerifiableCredential::verify` |
| W3C credential chain | `crates/tenzro-identity/src/verification.rs:731,746` | trust-chain traversal |
| VRF prove | `crates/tenzro-crypto/src/vrf.rs:226` | RFC 9381 ECVRF |
| VRF verify | `crates/tenzro-crypto/src/vrf.rs:273` | RFC 9381 ECVRF |
| VRF precompile | `crates/tenzro-vm/src/precompiles.rs:1611` | `precompile_vrf_verify` (0x1007) |
| Ed25519 keygen | `crates/tenzro-crypto/src/keys.rs:198` | `KeyPair::generate` (Ed25519 branch) |
| MPC threshold sign | `crates/tenzro-wallet/src/mpc_signing.rs:30` | `MpcSigner::sign` |
| Shamir per-share signing | `crates/tenzro-crypto/src/mpc.rs:361-368,393-454` | `combine_signatures_with_message` |
| x402 payment verify | `crates/tenzro-payments/src/x402/server.rs:170` | `X402PaymentServer::verify` |
| x402 facilitator | `crates/tenzro-payments/src/x402/facilitator.rs:190` | `X402Facilitator::verify` |
| RFC9421 sign | `crates/tenzro-payments/src/rfc9421/signature.rs:350` | `RFC9421Signature::sign` |
| RFC9421 verify | `crates/tenzro-payments/src/rfc9421/signature.rs:310` | `RFC9421Signature::verify` |
| Native bridge sign | `crates/tenzro-bridge/src/message_format.rs:110-138` | `TenzroMessage::sign` |
| Native bridge verify | `crates/tenzro-bridge/src/message_format.rs:221-262` | `TenzroMessage::verify_signature` |

#### EXTERNAL_LOCKED (residual quantum risk; do not unilaterally migrate)

| Site | File:Line | Reason |
|---|---|---|
| Secp256k1 keygen | `crates/tenzro-crypto/src/keys.rs:219` | Used for Ethereum bridge / EVM tx signing |
| EVM tx signer | `crates/tenzro-bridge/src/evm_signer.rs:42,326` | EIP-1559 demands Secp256k1 |
| `ecrecover` precompile | `crates/tenzro-vm/src/precompiles.rs:314` | Ethereum-spec mandated |
| EIP-7702 EOA recovery | `crates/tenzro-vm/src/account_abstraction.rs:1206` | EIP-7702 demands Secp256k1 |
| ERC-8004 Ethereum mirror | `crates/tenzro-identity/src/erc8004.rs:128-130` | Ethereum is classical until Ethereum migrates |
| Wormhole guardian VAA | `crates/tenzro-bridge/src/wormhole.rs:56-84` | Wormhole protocol locked |
| LayerZero DVN | `crates/tenzro-bridge/src/layerzero.rs:1-35` | DVN attests on EVM, Secp256k1 |
| Chainlink CCIP DON | `crates/tenzro-bridge/src/chainlink_ccip.rs:1-36` | Chainlink nodes sign Secp256k1 |
| Canton DAML | `crates/tenzro-bridge/src/canton.rs:1-49` | DAML ledger signature scheme |

#### Hardcoded signature lengths that BREAK with ML-DSA-65 (3309 bytes)

These must be refactored to `Vec<u8>` before adding ML-DSA-65:

- `crates/tenzro-crypto/src/signatures.rs:169,407` — Ed25519 `SIGNATURE_LENGTH = 64`
- `crates/tenzro-crypto/src/mpc.rs:718` — test asserts 64-byte Ed25519 sig
- `crates/tenzro-crypto/src/bls.rs:358,372,598` — `[u8; 96]` BLS sig
- `crates/tenzro-crypto/src/vrf.rs:63` — `PROOF_LEN = 80`

### 2.2 Transport / KEX (X25519, libp2p-noise, rustls)

| Finding | File:Line | Status |
|---|---|---|
| `aws-lc-rs` not in `Cargo.lock` | `Cargo.lock` | Must add |
| `rustls 0.23.38` resolved via reqwest 0.12, using **ring** | transitively via `reqwest 0.12` | Switch to aws-lc-rs feature |
| libp2p Noise (X25519) prod transport | `crates/tenzro-network/src/transport.rs:23,37,60` | Replace with libp2p-tls 0.6.2 |
| `libp2p-tls 0.6.2` in lockfile but **disabled** | workspace `Cargo.toml:102` | Enable |
| Outbound HTTPS via ring-rustls | `crates/tenzro-bridge/src/{debridge.rs:48,layerzero.rs:58,wormhole.rs}` | Switch to aws-lc-rs |
| All axum servers HTTP-only | `crates/tenzro-node/src/{rpc.rs,web/server.rs,mcp/server.rs,a2a/server.rs}` | TLS terminated by Caddy; not Tenzro's concern |
| X25519 wallet envelope encryption (NON_TRANSPORT) | `crates/tenzro-crypto/src/encryption.rs:117-162,193,157` | Defer to follow-up; not consensus-critical |

**Live probe confirmation (2026-04-27):** Caddy `2-alpine` (resolves ≥2.11.x) negotiates X25519MLKEM768 by default. ServerHello on all four `*.tenzro.network` endpoints carried `NamedGroup: X25519MLKEM768 (4588)` and signature_algorithms `mldsa65 (0x0905)`. Public-facing TLS is already PQ-hybrid.

### 2.3 Hash and symmetric crypto (Grover degradation)

All 256-bit primitives are PQ_OK:

| Primitive | File:Line | Verdict |
|---|---|---|
| SHA-256 | `crates/tenzro-crypto/src/hash.rs:116-123` | PQ_OK |
| Keccak-256 | `crates/tenzro-crypto/src/hash.rs:104-112` | PQ_OK |
| AES-256-GCM | `crates/tenzro-crypto/src/encryption.rs:6-107` | PQ_OK |
| Argon2id (64MB / 3 iters / parallelism 4) | `crates/tenzro-wallet/src/keystore.rs:231-253` | ACCEPTABLE |
| Merkle SHA-256 | `crates/tenzro-crypto/src/hash.rs:125-162` | PQ_OK |

**No MD5, SHA-1, RIPEMD-160, or AES-128 in security-critical paths.**

#### Known residual: 160-bit address collision space (PQ_DEGRADED)

- `crates/tenzro-crypto/src/keys.rs:68-74` — Ed25519 address: `SHA-256(pk)[..20]`
- `crates/tenzro-crypto/src/keys.rs:76-82` — Secp256k1 address: `Keccak-256(pk)[12..]`

160-bit space → 80-bit collision resistance under Grover. **Decision (this round):** do not extend to 32 bytes. Extending would invalidate every persisted account in `CF_ACCOUNTS`, every Ethereum-compat path, every existing wallet. 80-bit collision attack is ~2^80 ops — impractical even quantum-assisted before 2040+. Document residual; revisit at the next consensus-breaking change opportunity.

### 2.4 Zero-knowledge (Plonky3 STARKs over KoalaBear)

Tenzro's ZK system is Plonky3 STARKs over the KoalaBear field with Poseidon2 + FRI.

**Construction:**
- Three AIRs in `crates/tenzro-zk/src/plonky3/{inference,settlement,identity}.rs`.
- Poseidon2 (Plonky3 `KoalaBearPoseidon2`) for all internal hashes.
- Generic dispatcher `verify_proof_envelope(&Proof)` in `crates/tenzro-zk/src/lib.rs` matches on `circuit_id` ∈ {`"inference"`, `"settlement"`, `"identity"`}.
- The on-chain `ZK_VERIFY` precompile is an O(1) HashSet lookup against `ZkCommitmentRegistry`; validators verify off-EVM and record 32-byte SHA-256 commitments via `compute_zk_commitment(circuit_id, proof_bytes, public_inputs)`.
- Pinned testnet config: `log_blowup = 1, num_queries = 64, query_pow = 16, commit_pow = 8`, Plonky3 git rev `32079474b1d31d9221656ae774afb322d2597db0`.

**Threat classification:**
- ZK proof bytes: **NOT_HNDL** — STARK proofs leak no secret information.
- Verifying state: **PQ_SAFE** — STARK soundness rests only on collision-resistant hashing (Poseidon2). No elliptic curve, no pairing, no Shor exposure.
- Trusted setup: **N/A** — Plonky3 STARKs require none.

The `ProofType` enum exposes only `Plonky3`.

### 2.5 MPC / identity / bridge

| Component | File:Line | Classification |
|---|---|---|
| Shamir SSS (GF(256)) | `crates/tenzro-crypto/src/mpc.rs:57-141` | Field stays; per-share sigs go hybrid |
| Per-share sig | `crates/tenzro-crypto/src/mpc.rs:361-368` | Add ML-DSA share signing alongside Ed25519 |
| W3C DID Document | `crates/tenzro-identity/src/document.rs:89-108`, `w3c.rs:21-26` | `verification_method: Vec` already supports multiple keys per identity — DUAL_END |
| Verifiable credential proof | `crates/tenzro-identity/src/credential.rs:96-135` | `proof_type: String` already pluggable; add ML-DSA match arm |
| Revocation broadcast | `crates/tenzro-identity/src/registry.rs:44-46`, `identity.rs:296-305` | **UNSIGNED — HIGH #96.** Add hybrid sig in this round |

---

## 3. Library targets (snapshot 2026-04-27)

| Crate | Pinned version | Notes |
|---|---|---|
| `ml-kem` | `0.3.0-rc.2` | FIPS 203, beta, MSRV 1.85 |
| `ml-dsa` | `>= 0.1.0-rc.8` | FIPS 204, **MUST be ≥ rc.4** for GHSA-5x2r-hc65-25f9 |
| `slh-dsa` | `0.2.0-rc.4` | FIPS 205, optional defense-in-depth |
| `rustls` | `0.23.39` | `prefer-post-quantum` default-on for aws-lc-rs |
| `aws-lc-rs` | `1.16.3` | X25519MLKEM768 in stable `kx_group` namespace |
| `libp2p-tls` | `0.6.2` | PQ-capable transport |
| `p3-poseidon2` | `0.5.2` | For STARK follow-up; expect 0.x churn |

**Composite signature wire format:** No production-grade Rust crate publishes `draft-ietf-lamps-pq-composite-sigs-16`. Hand-roll per draft §4 (`Ed25519||ML-DSA-65` SEQUENCE-of-BIT-STRING with OID `id-MLDSA65-Ed25519`); test against Bouncy Castle vectors.

**Critical caveat:** ml-dsa is not 1.0 yet, no independent audit. **This is the single biggest reason to do hybrid not pure-PQ** — Ed25519 is a known-good fallback if a future ml-dsa CVE lands.

---

## 4. Out of scope (residual quantum risk, accepted)

These layers cannot migrate unilaterally because they are dictated by external protocols. Document and accept:

1. **EVM / Ethereum-compat** — `eth_sendRawTransaction`, `ecrecover`, EIP-7702, ERC-8004 Ethereum mirror — Secp256k1 forever, until Ethereum itself migrates.
2. **Wormhole guardian set** — Wormhole protocol owns the signature scheme.
3. **LayerZero DVN, Chainlink CCIP DON** — EVM-rooted, classical Secp256k1.
4. **Solana cross-chain** — Ed25519 is what Solana validators recognize.
5. **Canton DAML** — DAML ledger signature scheme.
6. **20-byte addresses** — 80-bit Grover collision space; impractical to extend without invalidating all persisted accounts.

The migration plan (`quantum-resistance-migration-plan.md`) covers the in-scope work item by item.
