# Tenzro inference receipts

Status: draft. This document defines the receipt a Tenzro node signs over one
inference it served, and how anyone holding the receipt verifies it without
Tenzro software. `tools/receipt-verify` is an implementation written from this
document alone; it links no Tenzro crate. The vectors in
[`vectors/inference-receipt.json`](vectors/inference-receipt.json) are receipts
signed by the node's own code with test keys, and both the node's tests and the
verifier's tests check them.

## 1. What a receipt states

A node that serves a chat completion signs a statement of what it served: the
model and its identity as the signed catalog states it, the machine that served
it, the caller's nonce, a commitment to the input the engine was given, a hash
of the output, the billable units it claims, the sampling parameters and seed,
and, when the request asked for them, a decode commitment and a
confidential-compute attestation. A chat completion carries it as
`tenzro_receipt` (see [chat-api.md](../chat-api.md)); a streamed completion
carries it on its final chunk.

A receipt verifies with nothing but itself and, for the model check, the model
hash the catalog states for the model it names.

## 2. JSON form

| Field | Type | Meaning |
| --- | --- | --- |
| `model_id` | string | The catalog id of the model served |
| `model_hash` | string, hex | The catalog identity of the weights (section 6) |
| `engine` | string | The engine family that ran the model |
| `machine_did` | string | The serving machine, `did:tenzro:machine:...` |
| `nonce` | string | The requester's per-request nonce, echoed |
| `input_commitment` | string, hex | SHA-256 commitment to the engine's input (section 6) |
| `output_hash` | string, hex | SHA-256 over the output (section 6) |
| `units` | object | Billable units: meter key to quantity |
| `priced` | object or null | `{card, rate_nano_usd, charge}`: the price card digest, the rate and the charge |
| `provenance` | array of strings | Content hashes of what the call used besides the model |
| `sampling` | object | `{seed, temperature, top_p, top_k, min_p, max_output_tokens, keyed_sampler}`; `top_k` and `min_p` may be null |
| `decode` | object | `{precision, engine_version, hardware_class}` |
| `commitment_hash` | string or null | Hash of the decode commitment |
| `tee` | object or null | `{report}`: a confidential-compute attestation report |
| `activation_fingerprint` | string or null | Reserved; signed either way |
| `signed_at_ms` | integer | When it was signed, ms since the Unix epoch |
| `public_key` | object | The node's hardware identity key: `p256` (hex, the uncompressed point `x‖y`, 64 bytes) and, when the hardware holds one, `pq` (hex, an ML-DSA-65 verifying key, 1952 bytes) |
| `signature` | object | `{certificate, signature}` (section 4) |

Quantities and amounts (`units` values, `rate_nano_usd`, `charge`) are JSON
numbers up to 2^64 − 1 and decimal strings above. A `units` key with quantity
zero is never present.

## 3. The signed preimage

The receipt's signature covers these bytes, concatenated in this order. `field(x)`
is the 64-bit little-endian length of `x` followed by `x`; strings are UTF-8.

1. The ASCII domain tag `tenzro/inference-receipt` (no length prefix).
2. `field` of each of `model_id`, `model_hash`, `engine`, `machine_did`,
   `nonce`, `input_commitment`, `output_hash`.
3. `field(U)`, where `U` is the units encoding: the ASCII tag
   `tenzro/meter/v1`, the number of keys as a u32 LE, then for each key in
   byte order its length as a u32 LE, the key, and its quantity as a u128 LE.
4. `priced`: the byte `0` when null; otherwise the byte `1`, `field(card)`,
   `rate_nano_usd` as u128 LE and `charge` as u128 LE.
5. The number of `provenance` entries as a u32 LE, then `field` of each.
6. `sampling`: `seed` u64 LE; `temperature` and `top_p` as the IEEE 754 bits
   of the f64, u64 LE; `top_k` u64 LE (2^64 − 1 when null); `min_p` as f64
   bits u64 LE (2^64 − 1 when null); `max_output_tokens` u32 LE; one byte,
   `1` if `keyed_sampler` else `0`.
7. `field` of each of `decode.precision`, `decode.engine_version`,
   `decode.hardware_class`.
8. `field(commitment_hash)`, the empty string when null.
9. `field(T)`, where `T` is the empty string when `tee` is null, otherwise the
   lowercase hex SHA-256 of the report's compact JSON encoding, keys in the
   order the receipt carries them.
10. `field(activation_fingerprint)`, the empty string when null.
11. `signed_at_ms` as u64 LE, then `field` of the P-256 key bytes, then
    `field` of the ML-DSA-65 key bytes (empty when the key has none).

The receipt's **digest**, its identity for every holder, is the lowercase hex
SHA-256 of the preimage.

## 4. The signature

A node signs receipts with an Ed25519 session key held only in memory. Its
hardware identity key (`public_key`) certifies the session key, and the
receipt carries the certificate:

```json
"signature": {
  "certificate": {
    "session_key": { "key_type": "Ed25519", "bytes": [32 numbers] },
    "not_after_ms": 1761400000000,
    "signature": { "classical": { "form": "raw", "signature": "<hex>" }, "pq": "<hex or null>" }
  },
  "signature": { "key_type": "Ed25519", "bytes": [64 numbers] }
}
```

To verify:

1. **The certificate.** Its message is: the P-256 key bytes with a u32 LE
   length; the byte `1` and the ML-DSA-65 key with a u32 LE length when the
   key has one, else the byte `0`; the byte `0` (Ed25519); the session key with
   a u32 LE length; `not_after_ms` as u64 LE. The certificate's `signature` is
   a composite signature over that message under the context
   `tenzro/session/certificate` (section 5).
2. **Expiry.** `signed_at_ms` must not be after `not_after_ms`.
3. **The receipt.** The outer `signature` is an Ed25519 signature by the
   session key over the preimage (section 3), checked strictly (RFC 8032 with
   canonical encodings).

## 5. Composite signatures

A composite signature has a P-256 leg and, when the key has an ML-DSA-65 key,
an ML-DSA-65 leg. Both legs sign the message representative

`M' = "CompositeAlgorithmSignatures2025" ‖ "COMPSIG-MLDSA65-ECDSA-P256-SHA512" ‖ len(ctx) ‖ ctx ‖ SHA-512(message)`

where `len(ctx)` is one byte.

- **P-256 leg** (`classical`, form `raw`): ECDSA over P-256 with SHA-256, on
  the prehash `SHA-256(M')`; the signature is `r‖s` (64 bytes) or DER.
- **ML-DSA-65 leg** (`pq`, hex, 3309 bytes): ML-DSA-65 (FIPS 204) over `M'`
  with the context string `COMPSIG-MLDSA65-ECDSA-P256-SHA512`.

A key with an ML-DSA-65 key must carry both legs; a key without one must carry
no ML-DSA-65 leg. Hardware keys sign the raw form; the passkey (`web_authn`)
form does not occur in receipts.

## 6. Commitments

- `model_hash`: SHA-256 over the ASCII tag `tenzro/model-hash` followed by,
  for each weight file in `(repo, path)` order, `field(repo)`, `field(path)`
  and `field(sha256)` as the catalog lists them; lowercase hex.
- `input_commitment`: SHA-256 over the ASCII tag `tenzro/inference-input`,
  then the JSON encoding of the messages the engine was given with a u64 LE
  length, then each media item with a u64 LE length. A raw completion uses
  the tag `tenzro/inference-input/prompt` and the prompt bytes with a u64 LE
  length.
- `output_hash`: SHA-256 over the visible text, the reasoning and the tool
  calls JSON, each with a u64 LE length (no tag).

## 7. Checks a holder makes

A receipt is accepted when its signature verifies (section 4), it names a
serving machine and an input commitment, and, as far as the holder knows them:
`model_hash` equals the catalog's hash for `model_id`, `nonce` equals the
nonce the request carried, and `output_hash` equals the hash of the output the
holder received.

## 8. The vectors

Each vector carries the receipt, the catalog model hash it is checked against,
its preimage in hex and its digest. A vector with a `refused` member is one a
verifier must refuse, for the reason it names. The set covers:

- `hybrid` and `p256_only`: receipts by a hardware key with and without an
  ML-DSA-65 key; both verify.
- `tee_attested`: a receipt carrying a confidential-compute report, whose
  digest is in the preimage (section 3, item 9). It verifies as a receipt, and
  any change to the report breaks its signature. The report comes from a test
  provider that no vendor root signed, so a holder that also checks the
  attestation against vendor roots refuses the attestation.
- `certificate_expired` (`refused`): the hardware key did certify the session
  key, and the session key did sign the receipt, but the receipt was signed
  after the certificate's `not_after_ms` (section 4, step 2).

## 9. The verifier

```bash
cargo run --release --manifest-path tools/receipt-verify/Cargo.toml -- \
    --model-hash <catalog hash> --nonce <request nonce> --output "<text>" response.json
```

The input is a receipt, or a chat completion response carrying one as
`tenzro_receipt`. It prints `verified <digest>` and exits 0, or names the first
check that failed and exits 1.
