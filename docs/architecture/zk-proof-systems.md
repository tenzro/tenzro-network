# Zero-knowledge proof systems

Status: implemented in `crates/tenzro-zk`. This document records what the
circuits prove, the parameters of the three proof systems, how their soundness
was computed, and why the hashes were chosen.

## 1. Statements

Tenzro proves hash-preimage statements (`crates/tenzro-zk/src/circuits/preimage.rs`).
For a circuit with a 32-byte domain label `D`, public inputs `(digest, binding)`
and a private 32-byte witness `w`:

```
digest == SHA3-256(D || w)
```

| circuit_id | Domain label | Witness | Who proves |
|---|---|---|---|
| `identity` | `tenzro/zk/identity-key` | the 32-byte identity secret | the holder, locally (`tenzro zk prove`); a node never receives it |
| `settlement` | `tenzro/zk/settlement-service` | the 32-byte service result the customer committed to | the provider (locally, or `tenzro_createZkProof` / `tenzro_createTeeZkProof` on its own node) |

`binding` is a 32-byte value chosen by the relying party (a challenge, or the
hash of the settlement request). It is absorbed into the Fiat-Shamir transcript
with the other public values, so a proof made for one binding does not verify
for another. The settlement engine sets
`binding = H(request_id || customer || provider || amount || nonce)` and compare
it before release; that binding check is owned by the payments stream.

### Why the constraints bind the witness

The AIR is the Plonky3 Keccak-f[1600] AIR (every round constrained bit by bit,
24 rows per permutation) plus one `active` selector column:

1. On the first row every preimage lane except the four witness lanes is pinned
   to a constant: the domain label (lanes 0-3), the SHA3 padding byte `0x06`
   (lane 8) and `0x80` (lane 16), and zero for every other rate and capacity
   lane. Witness lanes are range checked to 16-bit limbs by the Keccak AIR.
2. `active` is 1 on the first row, constant within a permutation, and 0 after
   the first permutation's last round.
3. Where `active == 1` and the round flag is the last round, the first 256 bits
   of the permuted state equal the `digest` public values.

A prover who knows only `digest` must produce a SHA3-256 preimage under the
fixed domain. Two negative tests pin this and were mutation checked (each fails
when its constraint is removed):
`trace_of_one_witness_cannot_prove_another_digest` (constraint 3) and
`trace_under_one_domain_cannot_prove_the_other_circuit` (constraint 1).

## 2. Proof systems

Three systems from two implementations. The two Plonky3 systems are
configured in `crates/tenzro-zk/src/plonky3/config.rs`. Both are Plonky3 uni-STARKs with the
hiding FRI PCS (salted Merkle leaves, randomized trace), so openings do not
reveal the witness. They share the statement and the uni-STARK protocol code,
nothing else:

| | `koala-bear-sha256-fri` | `goldilocks-blake3-fri` |
|---|---|---|
| Base field | KoalaBear `2^31 - 2^24 + 1` | Goldilocks `2^64 - 2^32 + 1` |
| Challenge field | degree-8 binomial extension, about 2^247.9 | degree-5 binomial extension, about 2^320 |
| Merkle leaf and node hash | SHA-256 | BLAKE3 |
| Fiat-Shamir transcript | SHA-256 (serializing challenger) | BLAKE3 (serializing challenger) |
| FRI rate | 1/16 (`log_blowup = 4`) | 1/32 (`log_blowup = 5`) |
| FRI queries | 60 | 48 |
| Query proof of work | 16 bits | 16 bits |
| Merkle leaf salt | 5 field elements (155 bits) | 3 field elements (192 bits) |
| Proven security (section 3) | 135.9 bits | 136.0 bits |

Trace: 128 rows (five Keccak permutations, the first carrying the statement),
2,634 columns, 3,286 constraints of degree at most 3. The hiding PCS doubles
the committed height to 256. The verifier rejects any proof whose `degree_bits`
differs from 8, so the soundness inputs below cannot be changed by the prover.

Proof sizes are dominated by the 2,634-column trace openings: 1,084,177 bytes for
KoalaBear and 1,484,293 bytes for Goldilocks (bincode, measured). This is the cost of a standard byte hash in
the statement; a Poseidon-class in-circuit hash would be several times smaller.

### The Halo2 system

`crates/tenzro-zk/src/halo2.rs`, system `halo2-ipa-pasta`. The same statement,
written a second time in a different proving stack (`halo2_proofs` 0.3, the
Zcash implementation) that shares no code with Plonky3:

| | `halo2-ipa-pasta` |
|---|---|
| Arithmetization | PLONKish: custom gates plus copy constraints |
| Field | Pallas scalar field (255 bits) |
| Commitment | inner-product argument over Pallas, no trusted setup |
| Fiat-Shamir transcript | BLAKE2b |
| Circuit | 2^14 rows, 32 advice columns (8 gate slots of 4 cells), one fixed constant column, one instance column |
| Keccak-f encoding | one cell per state bit; `xor3`, `chi`, `chi_not` gates of degree 3 over boolean inputs; rho and pi as copy constraints; iota folded into chi of lane (0,0) |
| Gates per proof | 92,160 Keccak gates plus 256 witness booleanity checks |
| Security | computational, discrete logarithm in the Pallas group: about 126 bits |

The digest bits are constrained to the instance column; the binding bits sit
in the same instance column unconstrained, and the verifier commits to the
whole instance column in the transcript, so a proof for one binding does not
verify for another. Halo2 blinds every advice column, so the proof is
zero-knowledge. `MockProver` checks that the constraints hold for the true
digest and fail for a digest with one flipped bit.

### k-of-n acceptance

`crates/tenzro-zk/src/diverse.rs`. `verify_k_of_n(legs, k)` accepts a statement
when proofs of it verify in at least `k` distinct systems, and those systems
come from at least `MIN_IMPLEMENTATIONS` (2) independent implementations
(`ProofSystem::implementation`: Plonky3 or Halo2). Every supplied leg must
verify and all legs must name the same circuit and public inputs; a leg that
one implementation accepts and the other rejects fails the whole set.
`DIVERSE_THRESHOLD` is 3 (every system). The node submits a statement to the
`ZK_VERIFY` attestation path only when the threshold is met
(`crates/tenzro-node/src/zk_rpc.rs::verify_statement`, reached from
`tenzro_verifyZkProof`, the MCP `verify_zk_proof` tool and
`POST /verify/zk-proof`). `statement_commitment(circuit_id, public_inputs)` is a
proof-independent commitment for registries that key by statement.

What the systems protect against, and what they do not:

- A break confined to one field, one extension, one hash, or one FRI parameter
  set yields at most one accepting Plonky3 leg.
- A defect in the Plonky3 uni-STARK protocol code (constraint folding,
  quotient check, transcript ordering) could make both Plonky3 legs accept a
  false statement, but not the Halo2 leg, and the reverse holds for a defect
  in Halo2. Accepting needs both implementations.
- A flaw in the statement itself (for example, SHA3-256 preimages becoming
  easy) is common to all systems by construction.

This follows the multi-proof direction of EIP-8025 (k-of-n independent proofs
for execution), applied to application proofs.

## 3. Soundness computation

`crates/tenzro-zk/src/plonky3/soundness.rs`, reported live by
`tenzro_listCircuits`. The proven regime is FRI list decoding up to the Johnson
bound. It does not use the up-to-capacity proximity conjecture, which was
disproved in 2025 (ePrint 2025/2046) together with two related conjectures
(arXiv 2604.09724).

Notation: `|F|` challenge-field size, `ρ` code rate, `N` committed trace height,
`n = N/ρ` evaluation domain, `L` polynomials batched into FRI, `C` constraints,
`d` max constraint degree, `s` queries, `m ≥ 3` the Johnson proximity parameter.
With `α = √ρ·(1 + 1/(2m))` and list size `ℓ = (m + 1/2)/√ρ`, the soundness error
is at most the sum of:

| Term | Bound |
|---|---|
| Constraint batching | `ℓ·C / |F|` |
| DEEP out-of-domain sampling | `ℓ·2·(d + 1)·N / |F|` |
| FRI batching and folding (proximity gaps, curve form) | `(L + log2 n)·(m + 1/2)^7·n^2 / (3·ρ^{3/2}·|F|)`, less `commit_pow_bits` of grinding |
| FRI queries | `α^s`, less `query_pow_bits` of grinding |

Reported bits are `-log2` of the sum, maximized over `m`. Inputs:
`N = 256`, `L = 2,698` (2,634 columns plus a 64-polynomial allowance for quotient
chunks and randomizer columns), `C = 3,286`, `d = 3`.

| Parameter set | Queries term | Batching/folding | Constraints | DEEP | Proven | Conjectured (capacity) |
|---|---|---|---|---|---|---|
| KoalaBear/SHA-256, rate 1/16, 60 queries, 16-bit PoW (`m = 622`) | 135.9 | 143.1 | 224.9 | 225.6 | **135.9** | 256 |
| Goldilocks/BLAKE3, rate 1/32, 48 queries, 16-bit PoW (`m = 4096`) | 136.0 | 192.7 | 293.8 | 294.5 | **136.0** | 256 |
| Previous config: KoalaBear degree-4, rate 1/2, 64 queries, 16/8-bit PoW (`m = 141`) | 47.7 | 52.6 | 104.6 | 105.3 | **47.6** | 80 |

The last row is kept as a regression check on the formula: it reproduces the
independent estimate of about 48 proven bits for the old parameters. Unit tests
assert both live systems are at or above 128 proven bits
(`koala_bear_system_reaches_128_proven_bits`,
`goldilocks_system_reaches_128_proven_bits`) and that the old parameters come
out between 40 and 50 (`rate_one_half_with_64_queries_is_far_below_100_bits`).
128 proven bits meets the Ethereum Foundation zkEVM target for end of 2026;
100 bits was the May 2026 target.

These numbers are classical random-oracle-model bounds. In the quantum random
oracle model the query term roughly halves for a Grover-capable adversary; the
16-bit grinding terms also lose about half their value.

The hiding PCS keeps the witness hidden only while the number of opened points
(queries plus two DEEP points) stays below the number of randomizing rows (128);
`opened_points_stay_below_the_randomized_rows` pins this.

## 4. Hash choice

The Merkle trees and transcripts now use SHA-256 and BLAKE3; the in-circuit
statement hash is SHA3-256 (Keccak-f[1600]).

- The Ethereum Foundation's Poseidon cryptanalysis initiative found that
  Poseidon2 "did not hold as cleanly" as expected in its first phase, and on
  2026-08-13 the Ethereum roadmap dropped Poseidon for L1 in favor of
  SHA-256/BLAKE-class hashes ("hash-friendly SNARKs, not SNARK-friendly
  hashes"). A full-round Poseidon1 KoalaBear collision exists in a model where
  the attacker chooses the MDS matrix (ePrint 2026/1760); default Plonky3
  Poseidon2 is not directly affected.
- A STARK's soundness reduces to the collision resistance and random-oracle
  behavior of its commitment and transcript hash. Using SHA-256 and BLAKE3
  there rests soundness on hashes with long public cryptanalysis. Using a
  different hash in each system means a break in one leaves the other standing.
- The statement hash is SHA3-256 because the identity commitment is a
  long-lived public value; its preimage resistance should not depend on a young
  algebraic design either. Keccak-f is also field-agnostic (bit-level AIR), which
  is what allows the same statement to be proven over KoalaBear and Goldilocks.
- Cost: commitments are slower and proofs larger than with Poseidon2. For the
  statement sizes Tenzro proves this is acceptable; proving time is dominated by
  the 2,634-column Keccak trace.

## 5. TEE-bound proofs

`crates/tenzro-zk/src/tee_integration.rs`. A `TeeZkProof` pairs a proof with an
attestation whose signed report data (REPORT_DATA on SGX/TDX/SEV-SNP, the
`user_data` field of a Nitro document) equals

```
SHA-256("tenzro/zk/tee-bound-proof" || len(circuit_id) || circuit_id ||
        system_tag || count(pi) || Σ(len(pi) || pi) || SHA-256(proof_bytes))
```

The attestation is requested after proving, over this digest. Verification
checks the STARK and that the report data extracted from the signed evidence
(never the report's unsigned `user_data` copy) equals the digest; the node then
runs the strict attestation verifier (`verify_report_strict`: real, not
simulated, chained to a pinned vendor root). There is no separate enclave
signing key: a key supplied from outside is self-certifying, and a key derived
from the TEE would treat the TEE as custody. The attestation signature is the
enclave's signature over the proof. NVIDIA GPU reports carry no standard
report-data field and are refused for TEE-bound proofs.

## 6. Post-quantum quorum certificates

The `pq-qc` AIR is deleted. It let the prover write `verified[i] = 1` for any
signer and so proved nothing about ML-DSA signatures. Quorum certificates
carry composite ML-DSA-65 + P-256 signatures (see consensus.md); per-vote ML-DSA binding is unchanged. A value-binding PQ
certificate needs either in-circuit signature verification (ML-DSA in-circuit
is expensive; hash-based signatures of the XMSS/leanSig family are the
STARK-friendly option) or native re-verification of every vote.

## 7. Sources

- ePrint 2025/2046, arXiv 2604.09724 (disproved proximity conjectures)
- https://github.com/ethereum/soundcalc (EF soundness calculator)
- https://www.poseidon-initiative.info/ and the 2026-08-13 Ethereum roadmap change
- ePrint 2026/1760 (Poseidon1 KoalaBear collision, attacker-chosen MDS)
- https://eips.ethereum.org/EIPS/eip-8025 (k-of-n execution proofs)
- ethSTARK documentation (ePrint 2021/582) and the Reed-Solomon proximity-gaps
  theorem (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf 2020) for the formula
