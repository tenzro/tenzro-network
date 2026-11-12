# tenzro-zk

Zero-knowledge proof infrastructure for the Tenzro Network: Keccak-f preimage statements proven in two Plonky3 STARK systems and an independent Halo2 implementation.

## Overview

`tenzro-zk` proves hash-preimage statements (`digest == SHA3-256(domain || witness)` for a 32-byte private witness) with the Keccak-f[1600] AIR evaluated in-circuit. The two Plonky3 systems are STARKs, which require **no trusted setup** and rely only on collision-resistant hashing; the Halo2 system uses an inner-product argument over Pallas, also without trusted setup. The full record is `docs/architecture/zk-proof-systems.md`.

The Plonky3 git revision is pinned at `32079474b1d31d9221656ae774afb322d2597db0`. Proof systems (`ProofSystem`): `koala-bear-sha256-fri` (FRI rate 1/16, 60 queries, 16-bit query PoW), `goldilocks-blake3-fri` (FRI rate 1/32, 48 queries, 16-bit query PoW) and `halo2-ipa-pasta`.

## Modules

- `plonky3` — Plonky3 STARK prover and verifier for the two pinned configurations, `prove`, `verify_proof_envelope`, and the proven-soundness computation
- `halo2` — the same statement in `halo2_proofs`, system `halo2-ipa-pasta`
- `circuits` — `Circuit` (`identity`, `settlement`) and `PreimageAir`
- `diverse` — `verify_k_of_n`, `DIVERSE_THRESHOLD`, `statement_commitment`
- `proof` — `Proof` envelope, `ProofSystem`, `Implementation`, `TeeZkProof`
- `tee_integration` — `bind_tee_attestation`, `verify_tee_zk_proof`: a proof bound to a hardware attestation
- `finality_proof`, `handover_chain` — checkpoint finality proofs
- `error` — `ZkError`, `VerifyEnvelopeError` (`UnknownCircuit`, `EnvelopeDecode`, `VerifierRejected`)

## Key Features

- **Two circuits**, addressed by `circuit_id`:
  - `"identity"` — proven by the holder locally; the witness is the identity secret
  - `"settlement"` — proven by the provider; the witness is the service result the customer committed to
- **Public inputs** are `[digest, binding]`, 32 bytes each; `binding` (a challenge or request hash) is absorbed into the transcript
- **Generic dispatcher** — `verify_proof_envelope(&Proof)` is the single verification entry point; it rejects a proof whose trace height differs from the circuit's
- **k-of-n acceptance** — `verify_k_of_n(legs, DIVERSE_THRESHOLD)`; `statement_commitment(circuit_id, public_inputs)` keys a statement independent of proof system
- **Hybrid ZK-in-TEE** — the enclave attests over `TeeZkProof::binding_digest(proof)`; `verify_tee_zk_proof` checks that the signed report data carries it

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

### TEE-Bound Proofs

```rust
use tenzro_zk::{bind_tee_attestation, verify_tee_zk_proof};

// `attestation` is the report the enclave produced over TeeZkProof::binding_digest(&proof)
let bundle = bind_tee_attestation(proof, attestation)?;

// Check the report data carries the proof's binding digest
verify_tee_zk_proof(&bundle)?;
```

### Statement commitment

```rust
use tenzro_zk::statement_commitment;

let commitment = statement_commitment("settlement", &proof.public_inputs);
// the same value whichever proof system proved the statement
```

## Security Considerations

- Plonky3 STARKs are sound under collision-resistant hashing alone — no trusted setup, no pairing assumptions
- AIR constraint correctness is critical — bugs in the AIR translate to soundness gaps. Constraint sets are reviewed against the soundness analysis on every change
- Proven soundness of the two Plonky3 systems (Johnson-bound FRI, `plonky3/soundness.rs`) is 135.9 and 136.0 bits; unit tests pin both at no less than 128. There is no inference circuit and no PQ quorum-certificate circuit.
- TEE attestations must be verified against vendor roots of trust before trusting any TEE-bound proof
- Always verify proof freshness for time-sensitive applications
- STARK proving is currently CPU-only; GPU/MSM acceleration is a mainnet optimization

## Dependencies

- `tenzro-types`, `tenzro-crypto` — Tenzro shared types and primitives
- Plonky3 crates pinned at git rev `32079474b1d31d9221656ae774afb322d2597db0` (`p3-koala-bear`, `p3-goldilocks`, `p3-uni-stark`, `p3-fri`, `p3-keccak-air`, `p3-merkle-tree`, `p3-sha256`, `p3-blake3`, and others) and `halo2_proofs`
- `bincode` 1.x for `p3_uni_stark::Proof` serialization
- `sha2` for the statement commitment hash
- `serde`, `serde_json` for the `Proof` envelope

## Test Coverage

Unit tests and doc tests cover:
- Proof generation and verification in every proof system for both circuits
- `verify_proof_envelope` dispatch (correct circuit, unknown circuit, malformed bytes)
- `statement_commitment` determinism and `verify_k_of_n` acceptance rules
- TEE-bound proof binding and verification

## Production Status

Components:
- Proving and verification across the three proof systems
- Commitment-attestation registry wired into the EVM `ZK_VERIFY` precompile
- TEE-in-ZK hybrid execution

Known limitations:
- STARK proving is CPU-only — GPU/MSM acceleration is a mainnet optimization

## License

Apache-2.0.
