# Tenzro VRF — Verifiable Random Function

**Status**: Implemented in tenzro-crypto / tenzro-vm precompile 0x1007
**Spec**: [RFC 9381 §5.4.1.1](https://datatracker.ietf.org/doc/rfc9381/) — ECVRF-EDWARDS25519-SHA512-TAI (suite string `0x04`)

## Overview

A Verifiable Random Function (VRF) lets the holder of a secret key compute a
pseudorandom output from an input message along with a proof that the output
was computed correctly. Anyone with the matching public key can verify the
proof. Without the secret key, the output is unpredictable.

Tenzro's VRF is byte-compatible with Ed25519 validator identity keys, which
means every validator can already generate VRF proofs without provisioning a
new key.

## Use cases

- **NFT reveals** — randomize trait assignment and token-ID selection with
  cryptographic proof of fairness.
- **Lotteries and draws** — on-chain randomness for games, airdrops, raffles.
- **Leader / shard selection** — protocol-level randomness for validator
  subset sampling (not used by consensus, whose leader schedule is seeded from the committed prefix).
- **Commit/reveal schemes** — replace two-phase commit/reveal with a single
  VRF invocation against a public beacon (block hash, oracle round).

## Ciphersuite

| Parameter | Value |
|-----------|-------|
| Curve | Edwards25519 (same as Ed25519 signatures) |
| Hash | SHA-512 |
| Encode-to-curve | try-and-increment (TAI, §5.4.1.1) |
| Suite string | `0x04` |
| Cofactor | 8 |
| Challenge length | 16 bytes (truncated) |

## Wire format

### Proof (80 bytes)

```
┌──────────────────────────┐
│ Gamma (32B, compressed)  │  curve point
├──────────────────────────┤
│ c     (16B)              │  truncated SHA-512 challenge scalar
├──────────────────────────┤
│ s     (32B, little-end.) │  response scalar mod L
└──────────────────────────┘
```

### Output (64 bytes)

`proof_to_hash(π) = SHA-512(suite_string || 0x03 || encode(cofactor · Gamma) || 0x00)`

## Implementation

**Location:** `crates/tenzro-crypto/src/vrf.rs`

**Public API:**
```rust
pub fn prove(secret_key: &[u8; 32], alpha: &[u8]) -> Result<([u8; 32], [u8; 80], [u8; 64]), VrfError>
pub fn verify(public_key: &[u8; 32], alpha: &[u8], proof: &[u8; 80]) -> Result<[u8; 64], VrfError>
pub fn proof_to_hash(proof: &[u8; 80]) -> [u8; 64]
```

**Key features:**
- Low-order-key rejection (per RFC 9381 §5.4.1.1)
- Canonical-scalar rejection (rejects non-canonical scalars)
- Ed25519-key-compatible (reuses validator keys)
- 80-byte proofs, 64-byte deterministic outputs

## Precompile (0x1007)

Stateless EVM precompile. Input/output layout:

**Input**:
```
pubkey         (32 bytes)
proof          (80 bytes)
alpha_len      (32-byte big-endian uint)
alpha          (alpha_len bytes)
```

**Output** (on success, 96 bytes):
```
status (32B, right-padded 0x...01)
output (64B, VRF beta)
```

**Output** (on failure, 32 bytes): all zeros.

**Gas**: `50_000 + 3 × alpha_len` bytes.

## NFT random mints

The NFT factory no longer takes a VRF key or input from the minter: a
minter-supplied key and input let the minter grind outputs. Random mints are
commit then reveal and use no key at all: `mintRandom(bytes32,address,uint256)`
records a request in block N, and `fulfillRandom(bytes32)` from block N+2 on
draws the token id and rarity from the hash of block N+1. See
`cross-vm-token-architecture.md`. Applications that need randomness without
their own VRF key use the randomness beacon precompile at `0x1009`.

## RPC

| Method | Params | Result |
|--------|--------|--------|
| `tenzro_verifyVrfProof` | `{pubkey, proof, alpha}` hex | `{valid, output, output_len}` |

No RPC generates a proof or a key: a VRF secret key must stay on the device
that holds it, never cross an RPC boundary.

## CLI

```bash
# Verify a VRF proof (calls tenzro_verifyVrfProof)
tenzro vrf verify --pubkey 0x... --proof 0x... --alpha 0xdeadbeef
```

## The validator randomness beacon

Bonded validators contribute VRF outputs to the chain's randomness beacon. Each contribution proves, with the validator's registered VRF key, the output on the beacon's current round and mix; the new mix is the hash of the old mix and that output. An output is unique per key and input, and the input is the current mix, so a contributor cannot choose its value or compute it early; the most it can do is withhold. Every value the beacon took is kept with its block time, and a draw names its value by time (the first value at or after a moment), so nobody changes it by choosing when to submit.

Because the VRF is elliptic-curve, governance can also enable hash commit-reveal (`beacon.commit_reveal.status`): each contribution then commits to the validator's next 32-byte secret and reveals the previous one, and the mix takes the revealed secret beside the VRF output. A secret stays hidden behind its hash until revealed, so the beacon stays unpredictable while the hash holds even if the VRF does not. The secrets derive from the validator's hardware root and the commitment's index, so nothing is stored and a restart reveals the secret it committed to.

## Security

RFC 9381 §3 guarantees hold for Edwards25519 with correctly validated public
keys: **full uniqueness**, **trusted collision resistance**, **full
pseudorandomness**.

**Do not use TAI encoding with secret inputs.** The try-and-increment loop
in `encode_to_curve_try_and_increment` is data-dependent and can leak
information through timing. For public inputs (block hashes, request IDs, NFT
mint nonces) this is fine.

## Comparison to Chainlink VRF v2.5

| Feature | Chainlink VRF v2.5 | Tenzro VRF |
|---------|--------------------|-----------|
| Ciphersuite | secp256k1 (Schnorr-style) | Edwards25519 (RFC 9381) |
| Key source | Chainlink coordinator | Any Ed25519 keypair |
| Verification latency | Cross-chain callback | Single-tx on Tenzro |
| Cost (Ethereum L1) | ~0.25 LINK + gas | n/a |
| Cost (Tenzro) | n/a | 50k + 3/byte gas |
| Randomness source | Chainlink oracle network | Validator's own secret key |

Tenzro VRF removes the oracle dependency and callback pattern for
randomness use cases that stay on Tenzro. For cross-chain consumers that
need randomness delivered to Ethereum/Solana/Base, Chainlink VRF remains the
right tool, used directly on those chains.

## References

- [RFC 9381 — Verifiable Random Functions (VRFs)](https://datatracker.ietf.org/doc/rfc9381/)
- [Goldberg, Naor, Papadopoulos, Reyzin (2023). "Making NSEC5 Practical for DNSSEC"](https://eprint.iacr.org/2017/099)
- [Chainlink VRF v2.5 docs](https://docs.chain.link/vrf/v2-5/overview)
