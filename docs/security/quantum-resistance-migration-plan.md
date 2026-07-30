# Quantum-Resistance Migration Plan — Tenzro Network

**Plan date:** 2026-04-27
**Scope:** Hybrid Ed25519 + ML-DSA-65 signing; hybrid X25519 + ML-KEM-768 key exchange via libp2p-tls and aws-lc-rs rustls; signed revocation broadcasts. Forward-compatible wire format that supports a clean parameter flip to pure-PQ in 2030.
**Out of scope:** Plonky3 STARK ZK migration (deferred to follow-up workstream — see task #95).
**Cutover model:** Flag-day at next testnet wipe. Tenzro is pre-alpha with no live users — no dual-codepath, no backwards-compat shim.
**Companion doc:** `quantum-resistance-audit.md`.

---

## 1. Step ordering and parallelism

```
                    ┌──────────────────────────────────────┐
                    │ Crypto foundation — tenzro-crypto    │
                    │  + rustls (base for everything below)│
                    └──────────────┬───────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
   ┌──────────▼──────────┐ ┌──────▼─────────┐ ┌────────▼────────┐
   │ Transport           │ │ Tx wire format │ │  (ZK migration  │
   │ libp2p-noise → tls  │ │ (forward-compat)│ │   = follow-up)  │
   └──────────┬──────────┘ └──────┬─────────┘ └─────────────────┘
              │                   │
              │         ┌─────────▼──────────┐
              │         │ Wire consumers +   │
              │         │ revocation signing │
              │         │                    │
              │         └─────────┬──────────┘
              │                   │
              └─────────┬─────────┘
                        │
              ┌─────────▼──────────┐
              │ Integration tests  │
              │ + restart survives │
              │                    │
              └────────────────────┘
```

Transport and Tx wire format can run in parallel once the crypto foundation is in place. Wire consumers depend on the Tx wire format. Integration tests depend on transport + wire consumers.

---

## 2. tenzro-crypto + rustls foundation

### 2.1 Cargo dependencies (workspace `Cargo.toml`)

Add:
```toml
ml-kem    = "0.3.0-rc.2"
ml-dsa    = ">=0.1.0-rc.8"   # MUST be >= rc.4 for GHSA-5x2r-hc65-25f9
slh-dsa   = "0.2.0-rc.4"     # optional fallback
aws-lc-rs = { version = "1.16.3", features = ["bindgen"] }
```

Modify:
- `rustls = "0.23.39"` with feature flags switched: drop `ring`, enable `aws-lc-rs`.
- Same for `tokio-rustls`, `hyper-rustls`, `reqwest` (the `rustls-tls-aws-lc-rs` feature on reqwest 0.12).
- `libp2p` 0.56: add the `tls` feature.

### 2.2 `crates/tenzro-node/src/main.rs` — install default CryptoProvider

Add at the very top of `main()`:
```rust
rustls::crypto::aws_lc_rs::default_provider()
    .install_default()
    .expect("failed to install rustls aws-lc-rs CryptoProvider");
```

Same for `crates/tenzro-cli/src/main.rs` (CLI also makes outbound HTTPS calls via reqwest).

### 2.3 `Dockerfile` — builder stage

Add to the Rust builder stage:
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
```
aws-lc-rs requires cmake + clang for its bindgen build path.

### 2.4 `crates/tenzro-crypto/src/signatures.rs` — refactor to `Vec<u8>`

Today (line 169, 407) hardcodes `[u8; 64]` for Ed25519. Refactor every public signature type to `Vec<u8>`. ML-DSA-65 signatures are **3309 bytes** — fixed-size arrays will not fit.

New trait surface:
```rust
pub trait HybridSigner {
    fn sign(&self, msg: &[u8]) -> CompositeSignature;
}

pub trait HybridVerifier {
    fn verify(&self, msg: &[u8], sig: &CompositeSignature) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeSignature {
    /// Classical signature (Ed25519 64B or Secp256k1 65B).
    pub classical: Vec<u8>,
    /// ML-DSA-65 signature (3309 bytes).
    pub pq: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositePublicKey {
    pub classical: Vec<u8>, // Ed25519 32B or Secp256k1 33B
    pub pq: Vec<u8>,        // ML-DSA-65 1952B
}
```

**Verification semantics: logical AND.** Both halves must verify. There is no pre-PQ verify path — flag-day cutover at the testnet wipe means every accepted signature is composite.

### 2.5 `crates/tenzro-crypto/src/{bls.rs,vrf.rs,mpc.rs}` — relax fixed lengths

- `bls.rs:358,372,598` — `[u8; 96]` → `Vec<u8>` (reasoning: when BLS validator pubkeys also gain ML-DSA companions, aggregate signature payloads grow).
- `vrf.rs:63` — `PROOF_LEN = 80` constant: keep for VRF (RFC 9381 ECVRF stays Ed25519-rooted; VRF doesn't have a PQ replacement that matches the 64-byte hash output API). VRF is a Shor-vulnerable consensus path but the input/output API is stable. **Decision:** document residual; revisit when NIST standardizes a PQ VRF.
- `mpc.rs:718` — test `assert_eq!(64, ...)` becomes `assert_eq!(64 + ML_DSA_65_SIG_LEN, ...)` and asserts on `CompositeSignature` len.

### 2.6 New file: `crates/tenzro-crypto/src/pq.rs`

Wraps `ml-dsa::MlDsa65` and `ml-kem::MlKem768` behind types that match the existing `Signer`/`Verifier` trait shape so call sites can drop `HybridSigner` in next to existing `Ed25519Signer`.

### 2.7 New file: `crates/tenzro-crypto/src/composite.rs`

Implements draft-ietf-lamps-pq-composite-sigs-16 §4 wire encoding for `Ed25519||ML-DSA-65`:
```
CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
```
With OID `id-MLDSA65-Ed25519`. Round-trip test against Bouncy Castle vectors (BC has reference vectors as of 1.79, Apr 2026).

---

## 3. libp2p-noise → libp2p-tls

### 3.1 `crates/tenzro-network/src/transport.rs`

Replace lines 23, 37, 60. Construct a libp2p-tls authentication layer using rustls-aws-lc-rs:

```rust
let tls_config = libp2p::tls::Config::new(&keypair)
    .map_err(|e| NetworkError::Transport(format!("tls config: {e}")))?;

let tcp = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
    .authenticate(tls_config)
    .multiplex(libp2p::yamux::Config::default());
```

The QUIC transport stays — it uses rustls internally and once we install aws-lc-rs as the default provider, QUIC inherits PQ-hybrid KEX automatically.

**Why not keep Noise:** libp2p-noise has no upstream PQ path and no spec is in flight. libp2p-tls + rustls-aws-lc-rs is the only PQ-capable libp2p transport in April 2026.

### 3.2 No protocol-version bump needed

libp2p multistream selection happens before the security handshake; Noise-only peers fail to negotiate (intentional — flag-day cutover). All testnet nodes restart simultaneously after the wipe.

---

## 4. Forward-compatible Transaction wire format

### 4.1 `crates/tenzro-types/src/transaction.rs`

Replace `Transaction`'s existing `signature` and `public_key` fields with composite versions:
```rust
pub struct Transaction {
    // ... existing fields ...

    /// Composite signature (classical + PQ).
    pub signature: Option<CompositeSignature>,

    /// Composite public key (classical + PQ).
    pub public_key: Option<CompositePublicKey>,
}
```

The `Option<>` wrapper covers unsigned/draft transactions only; once a transaction is signed, both halves of the composite are mandatory. Replace the existing fields, don't add adjacent ones.

### 4.2 `Transaction::hash()` preimage (current lines 75-95)

The hash preimage **must include the composite public key** but **must not include the signature** (otherwise signing the hash is impossible). The classical/pq concatenation order is fixed for determinism:

```rust
hasher.update(&compose_pubkey_for_hash(&self.public_key));
// ...
fn compose_pubkey_for_hash(pk: &Option<CompositePublicKey>) -> Vec<u8> {
    match pk {
        None => Vec::new(),
        Some(c) => {
            let mut out = Vec::with_capacity(c.classical.len() + c.pq.len() + 8);
            out.extend_from_slice(&(c.classical.len() as u32).to_le_bytes());
            out.extend_from_slice(&c.classical);
            out.extend_from_slice(&(c.pq.len() as u32).to_le_bytes());
            out.extend_from_slice(&c.pq);
            out
        }
    }
}
```

### 4.3 Genesis version bump

`config/genesis-local.toml` and the live testnet genesis: bump version to `2`, mark in genesis comment as `# PQ-hybrid era (Ed25519 + ML-DSA-65, X25519 + ML-KEM-768)`. Refuse to start if loaded genesis declares version `1` and binary is PQ-era — fail closed with a clear error message about wiping and re-genesis-ing.

---

## 5. Wire consumers + revocation signing

### 5.1 `tenzro-wallet`

`crates/tenzro-wallet/src/transaction_builder.rs` — when constructing a tx, sign with `HybridSigner`. The wallet's `Wallet` struct carries both an Ed25519 key and an ML-DSA-65 key. The wallet is auto-provisioned without a seed phrase: the two legs are generated independently (each key from its own CSPRNG source), so the hybrid key pair is produced at provisioning time rather than derived from any shared secret to recover.

Persistent keystore (`tenzro-wallet/src/keystore.rs`): bump format version, store both private keys. Argon2id parameters unchanged.

### 5.2 `tenzro-identity`

- `crates/tenzro-identity/src/w3c.rs:21-26` — extend the type-tag map: `"Ed25519" → "Ed25519VerificationKey2020"`, `"ML-DSA-65" → "MlDsa65VerificationKey2026"`. Each `TenzroIdentity` exports a DID Document with **two** `verificationMethod` entries, one per key.
- `crates/tenzro-identity/src/credential.rs:96-135` — replace the existing match arm. All credentials are signed with `proof_type = "MlDsa65Signature2026"`. No pre-cutover credential path.
- **HIGH #96 — sign revocation broadcasts.** `crates/tenzro-identity/src/registry.rs:44-46` — change the trait:
  ```rust
  pub trait RevocationBroadcaster: Send + Sync {
      fn broadcast_revocation(
          &self,
          entry: &SignedRevocationEntry,
      ) -> Result<()>;
  }
  pub struct SignedRevocationEntry {
      pub entry: RevocationEntry,
      pub signature: CompositeSignature,    // signed by `revoked_by` DID's keys
      pub public_key: CompositePublicKey,
  }
  ```
  And update `apply_remote_revocation()` to verify the signature before applying.

### 5.3 `tenzro-bridge`

`crates/tenzro-bridge/src/message_format.rs:110-138,221-262` — `TenzroMessage::sign` and `verify_signature` accept `HybridSigner` / `HybridVerifier`. Inbound messages from external chains (Wormhole, LayerZero, CCIP) keep their EXTERNAL_LOCKED Secp256k1/Ed25519 verify paths unchanged.

### 5.4 `tenzro-consensus`

`crates/tenzro-consensus/src/hotstuff2.rs:462` — `create_vote` signs with `HybridSigner`. `crates/tenzro-consensus/src/voter.rs:209,405` — `VoteCollector::collect` verifies with `HybridVerifier`. The `Vote` struct's `signature: Vec<u8>` stays (already flexible) but is now serialized `CompositeSignature` bytes; bump a `vote_format_version: u8 = 2` field on `Vote`.

### 5.5 `tenzro-vm`

`crates/tenzro-node/src/rpc.rs` — the `tenzro_signAndSendTransaction`, `tenzro_signTransaction`, `eth_sendRawTransaction` paths all pass through `HybridVerifier::verify` against `Transaction::hash()`. Invalid hybrid sigs return JSON-RPC error `-32003` (the existing transaction-signing pattern). The Secp256k1 path on `eth_sendRawTransaction` for Ethereum-compat tx **stays classical** (EXTERNAL_LOCKED).

### 5.6 `tenzro-payments`

`crates/tenzro-payments/src/x402/{server.rs,facilitator.rs}`, `rfc9421/signature.rs` — accept `HybridVerifier`. Stripe / Coinbase webhook HMAC paths unchanged (HMAC-SHA256 is PQ_OK).

### 5.7 `tenzro-agent`

`crates/tenzro-agent/src/identity.rs` — agent identity provisioning calls `tenzro-identity` which now generates hybrid keys. Each agent's W3C DID Document has two `verificationMethod` entries.

---

## 6. Integration tests

### 6.1 New test: `crates/tenzro-node/tests/pq_hybrid_integration.rs`

```rust
#[tokio::test]
async fn hybrid_signed_tx_round_trip() { ... }

#[tokio::test]
async fn pre_pq_classical_only_tx_rejected() { ... }

#[tokio::test]
async fn restart_survives_pq_genesis() {
    // 1. Start node, submit hybrid-signed tx, finalize.
    // 2. Drop node, reopen storage, reconstruct registries.
    // 3. Assert: tx replays from CF_TRANSACTIONS, signature verifies, balances intact.
}

#[tokio::test]
async fn revocation_broadcast_signature_required() {
    // 1. Construct unsigned RevocationEntry, attempt apply_remote_revocation().
    // 2. Assert error.
    // 3. Sign properly, retry, assert success.
}
```

### 6.2 Workspace test surface

- `cargo test --workspace` — must pass with the new types
- `cargo clippy --workspace --all-targets -- -D warnings`
- `tenzro-zk` has 40 unit tests covering the Plonky3 dispatcher, Poseidon2 hashing, and the three AIRs (inference, settlement, identity) — already post-quantum-conjectured-sound under STARKs over KoalaBear, so no PQ migration is required for the ZK layer.

### 6.3 Network smoke (after deploy authorization)

Once the image build and each per-node rollout are authorized:

```
TAG=$(date +%Y%m%d-%H%M%S)
docker build -t <your-registry>/tenzro-node:$TAG .
docker push <your-registry>/tenzro-node:$TAG

# Wipe + re-genesis: flag-day cutover requires destroying all v2 chain state
# before validators boot the v3 binary. The exact mechanic depends on your
# deployment (delete the persistent volume, re-attach a blank data disk, or
# `rm -rf /var/lib/tenzro/data` on bare metal).
# Then restart each validator with the new genesis embedded and the new image.
```

After pods are Ready, smoke tests:

```
# 1. Verify TLS still negotiates X25519MLKEM768
echo | openssl s_client -connect rpc.tenzro.xyz:443 -tls1_3 -trace 2>&1 | grep "NamedGroup: X25519MLKEM768"

# 2. Faucet a wallet, submit a hybrid-signed tx, confirm receipt
curl -sX POST https://api.tenzro.xyz/faucet -H 'content-type: application/json' \
  -d '{"address":"0x...","amount":"100"}'
# (then `tenzro-cli wallet send` with new hybrid wallet — should succeed)
```

---

## 7. Test recomputation list

Tests that touch changed signature types and need updating:

| Crate | Test file patterns | Estimated count |
|---|---|---|
| `tenzro-crypto` | `signatures.rs`, `bls.rs`, `vrf.rs`, `mpc.rs` (size assertions) | ~15 |
| `tenzro-wallet` | `keystore.rs`, `mpc_signing.rs`, integration tests | ~12 |
| `tenzro-consensus` | `hotstuff2.rs`, `voter.rs` | ~8 |
| `tenzro-identity` | `credential.rs`, `verification.rs`, `registry.rs` (revocation) | ~10 |
| `tenzro-bridge` | `message_format.rs` | ~5 |
| `tenzro-payments` | `x402`, `rfc9421` | ~6 |
| `tenzro-node` | `rpc.rs` tests, new integration test file | ~8 |
| **Total** | | **~64** |

ZK tests (~221) are not touched in this round.

---

## 8. Rollback plan

Because cutover is flag-day with testnet wipe, "rollback" means:
1. Detect breakage post-deploy via smoke tests.
2. Re-pin each validator (and the RPC-serving node) to the prior image digest and restart.
3. Re-wipe, re-genesis with the old binary.

The fact that we wiped means there's no production state to lose. Old tx history is gone either way, by design.

---

## 9. Documentation updates

After implementation:
- Project README / production-readiness notes: add tenzro-crypto hybrid PQ entry
- Project README / Crate Details / tenzro-crypto: list `pq` and `composite` modules
- `docs/SPECIFICATION.md`: add a "post-quantum security" subsection citing FIPS 203/204 and the hybrid model
- `crates/tenzro-crypto/README.md`: hybrid signing usage example
- This plan stays in `docs/security/` as the migration record

---

## 10. Out of scope (for clarity)

- Plonky3 STARK ZK migration — task #95, separate workstream.
- 32-byte address extension — accepted residual at 80-bit Grover collision.
- ERC-8004 / Wormhole / LayerZero / CCIP / Canton / Solana — EXTERNAL_LOCKED, accepted residual.
- VRF replacement — no NIST-blessed PQ VRF available; revisit later.
- X25519 wallet envelope encryption (`tenzro-crypto/src/encryption.rs`) — non-consensus, follow-up.
