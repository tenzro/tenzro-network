# tenzro-zk

Zero-knowledge proof infrastructure for the Tenzro Network, built on Plonky3 STARKs over the KoalaBear field.

## Overview

`tenzro-zk` provides cryptographic proof systems for verifiable computation on the Tenzro Network. The crate uses **Plonky3 STARKs** with Poseidon2 hashing and FRI commitments over the KoalaBear field (`p = 2^31 − 2^24 + 1`, two-adicity 24). STARKs require **no trusted setup** and are **post-quantum sound**, relying only on collision-resistant hashing.

The Plonky3 git revision is pinned at `32079474b1d31d9221656ae774afb322d2597db0`. Testnet FRI parameters: `log_blowup = 1`, `num_queries = 64`, `query_pow = 16`, `commit_pow = 8`.

## Modules

- `plonky3` — Plonky3 STARK prover/verifier wrappers (`Plonky3Prover`, `Plonky3Verifier`, `TenzroStarkConfig`, `build_testnet_config`), `verify_proof_envelope` dispatcher
- `circuits` — Three concrete AIRs (`InferenceAir`, `SettlementAir`, `IdentityAir`) with trace generators and public-input encoders
- `proof` — `Proof` envelope, `ProofType` (`Plonky3` only), `ProofMetadata`, `TeeZkProof`
- `tee_integration` — Hybrid ZK-in-TEE execution combining STARK proofs with hardware attestation
- `error` — `ZkError`, `VerifyEnvelopeError` (`WrongProofType`, `UnknownCircuit`, `EnvelopeDecode`, `VerifierRejected`)
- Top-level: `verify_proof_envelope`, `compute_zk_commitment`

## Key Features

- **Plonky3 STARKs** over the KoalaBear field — no trusted setup, post-quantum sound
- **Three pre-built AIRs**, addressed by `circuit_id`:
  - `"inference"` — Verify AI model inference results (model hash, input hash, output hash)
  - `"settlement"` — Verify payment settlements (service hash, settlement hash, amount)
  - `"identity"` — Verify identity claims (public-key hash, capability commitment)
- **Poseidon2 hashing** — canonical Plonky3 algebraic hash, far more efficient inside STARK constraints than SHA-256/Keccak
- **Generic dispatcher** — `verify_proof_envelope(&Proof)` matches on `circuit_id` and routes to the right AIR verifier
- **Wire format** — public inputs are 4-byte little-endian KoalaBear field-element chunks; the verifier reassembles them before checking AIR boundary constraints
- **Commitment-attestation model** — `compute_zk_commitment(circuit_id, proof_bytes, public_inputs) = SHA-256(circuit_id ‖ proof_bytes ‖ Σ(len_le(pi) ‖ pi))` with a 4-byte LE length prefix per public input. Used by the EVM `ZK_VERIFY` precompile (O(1) HashSet lookup against `ZkCommitmentRegistry`)
- **Hybrid ZK-in-TEE** — Combines STARK proofs with TEE attestations for stronger guarantees

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
tenzro-zk = { path = "../tenzro-zk" }
```

### Generic dispatch via `verify_proof_envelope`

```rust
use tenzro_zk::{Proof, verify_proof_envelope, VerifyEnvelopeError};

fn handle_proof(p: &Proof) -> Result<(), VerifyEnvelopeError> {
    verify_proof_envelope(p)?;          // dispatches on p.circuit_id
    Ok(())
}
```

### TEE-Enhanced Proofs

```rust
use tenzro_zk::tee_integration::{generate_tee_zk_proof, verify_tee_zk_proof};
use tenzro_types::tee::TeeVendor;

// Generate STARK proof inside TEE with hardware attestation bound to the proof
let tee_zk_proof = generate_tee_zk_proof(
    &prover,
    circuit,
    public_inputs,
    TeeVendor::IntelTDX,
).await?;

// Verify both STARK proof and TEE attestation
let valid = verify_tee_zk_proof(&tee_zk_proof).await?;
assert!(valid);
```

### Computing the on-chain commitment

```rust
use tenzro_zk::compute_zk_commitment;

let commitment = compute_zk_commitment(
    "inference",
    &proof.proof_bytes,
    &proof.public_inputs,
);
// validators record `commitment` in ZkCommitmentRegistry; EVM ZK_VERIFY does an O(1) lookup
```

## Security Considerations

- Plonky3 STARKs over KoalaBear are sound under collision-resistant hashing alone — no trusted setup, no pairing assumptions
- AIR constraint correctness is critical — bugs in the AIR translate to soundness gaps. Constraint sets should be reviewed against the soundness analysis on every change
- TEE attestations must be verified against vendor roots of trust before trusting any TEE-bound proof
- Always verify proof freshness for time-sensitive applications
- Plonky3 STARK proving is currently CPU-only; GPU/MSM acceleration is a mainnet optimization

## Dependencies

- `tenzro-types`, `tenzro-crypto` — Tenzro shared types and primitives
- Plonky3 crates pinned at git rev `32079474b1d31d9221656ae774afb322d2597db0`: `p3-koala-bear`, `p3-uni-stark`, `p3-fri`, `p3-poseidon2`, `p3-merkle-tree`, `p3-field`, `p3-air`, `p3-matrix`
- `bincode` 1.x for `p3_uni_stark::Proof` serialization
- `sha2` for the on-chain commitment hash
- `serde`, `serde_json` for the `Proof` envelope

## Test Coverage

40 unit tests + 5 doc tests covering:
- Plonky3 STARK proof generation and verification across all three AIRs
- `verify_proof_envelope` dispatch (correct circuit, unknown circuit, malformed bytes)
- Public-input KoalaBear field-chunk encode/decode round-trip
- `compute_zk_commitment` determinism + length-prefix robustness
- TEE-enhanced proof generation and verification

## Production Status

Components:
- Plonky3 STARK proving + verification across the three AIRs
- Commitment-attestation registry wired into the EVM `ZK_VERIFY` precompile
- TEE-in-ZK hybrid execution

Known limitations:
- STARK proving is CPU-only — GPU/MSM acceleration is a mainnet optimization

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License (http://opensource.org/licenses/MIT)

at your option.
