# Tenzro VRF — Verifiable Random Function

**Status**: Shipped in tenzro-crypto v0.1 / tenzro-vm precompile 0x1007
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
  cryptographic proof of fairness (see `mintRandom` below).
- **Lotteries and draws** — on-chain randomness for games, airdrops, raffles.
- **Leader / shard selection** — protocol-level randomness for validator
  subset sampling (not currently used by HotStuff-2 but available).
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

## NFT `mintRandom` (selector `0x52517e21`)

Token-factory NFT collections expose a `mintRandom` entry point that:

1. ABI-decodes `(collection_id, to, id_space, vrfPubkey, vrfProof, alpha)`.
2. Verifies the VRF proof via `tenzro_crypto::vrf::verify`.
3. Derives up to four token-id candidates from rolling 8-byte windows of the
   VRF output; the first collision-free candidate becomes the new token id.
4. Derives rarity tier from `output[32]` (0..=255):
   - **Common**: 70% (0-178)
   - **Uncommon**: 20% (179-229)
   - **Rare**: 7% (230-247)
   - **Epic**: 2.5% (248-254)
   - **Legendary**: 0.5% (255)
5. Commits owner, URI, balance, and total_supply.
6. Returns `(uint256 token_id, uint256 rarity)`.

**Gas:** 130,000.

If a collision-free slot cannot be found after 4 attempts the call reverts —
callers should choose `id_space` large enough (`≥ 8 × total_expected_mints`).

## RPC

| Method | Params | Result |
|--------|--------|--------|
| `tenzro_verifyVrfProof` | `{pubkey, proof, alpha}` hex | `{valid, output, output_len}` |
| `tenzro_generateVrfProof` | `{secret_key, alpha}` hex | `{pubkey, proof, output}` |

## MCP tools

- `verify_vrf_proof` — verify a proof and return deterministic output.
- `generate_vrf_proof` — generate a proof from a 32-byte seed.

Both are exposed on the Tenzro MCP server (default `http://0.0.0.0:3001/mcp`).

## A2A skill

`verification` skill on the Agent-to-Agent card now includes `vrf` and
`randomness` tags. Compatible agents can discover VRF capability via the
Agent Card at `/.well-known/agent.json`.

## CLI

```bash
# Generate a fresh VRF secret key (hex)
tenzro vrf keygen

# Generate a VRF proof from a secret key and input (calls tenzro_generateVrfProof)
tenzro vrf prove --secret-key 0x... --alpha 0xdeadbeef

# Verify a VRF proof (calls tenzro_verifyVrfProof)
tenzro vrf verify --pubkey 0x... --proof 0x... --alpha 0xdeadbeef
```

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
right tool and is exposed via the Chainlink MCP server (port 3007).

## References

- [RFC 9381 — Verifiable Random Functions (VRFs)](https://datatracker.ietf.org/doc/rfc9381/)
- [Goldberg, Naor, Papadopoulos, Reyzin (2023). "Making NSEC5 Practical for DNSSEC"](https://eprint.iacr.org/2017/099)
- [Chainlink VRF v2.5 docs](https://docs.chain.link/vrf/v2-5/overview)
