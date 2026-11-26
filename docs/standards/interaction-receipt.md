# Interaction receipt digest

Every metered interaction on Tenzro, charged or free, has an interaction
record: who consumed what, under which authority, when, and where the charge
landed. The record has a digest that anyone can recompute from the record
alone. This document specifies the digest so that a verifier can be written
without reading the node's code. `docs/standards/vectors/interaction-receipt.json`
holds test vectors: records with their preimage and digest, and records a
verifier must refuse.

The record type is `InteractionProvenance` in
`crates/tenzro-types/src/provenance.rs`. A node reports the digest as
`attestation_digest` (`tenzro_mirrorSettlement`), and a digest-only mirror
writes the same 32 bytes onto another chain.

## The digest

```
digest = SHA-256(preimage)

preimage = domain || field(1) || field(2) || ... || field(13)
domain   = the 33 ASCII bytes "tenzro/interaction-attestation/v2"
field(x) = len(x) as a 4-byte little-endian unsigned integer || x
```

There is no separator and no terminator other than the length in front of
each field. The domain is not length-prefixed.

The thirteen fields, in order. Each field is read from the record's JSON by the name shown.

| # | Field | Bytes |
|---|-------|-------|
| 1 | `interaction_id` | UTF-8 |
| 2 | `kind` | One of `inference`, `rental`, `storage`, `database`, `hosting`, `security`, `marketplace`, `rpc_brokerage`, `access` |
| 3 | `payer_did` | UTF-8 |
| 4 | `on_behalf_of` | UTF-8; empty (length 0) when absent |
| 5 | `attester_did` | UTF-8 |
| 6 | `resource_id` | UTF-8 |
| 7 | `authority.kind` | One of `delegation`, `x402_payment`, `credential`, `open` |
| 8 | authority value | `delegation`: `authority.controller_did`. `x402_payment`: `authority.scheme`. `credential`: `authority.digest`. `open`: empty |
| 9 | `charge.kind` | One of `settlement`, `channel`, `accrued`, `free` |
| 10 | charge value | `settlement`: `charge.settlement_id`. `channel`: `charge.channel_id`, `:`, `charge.nonce` in decimal. `accrued`: `charge.accrued_wei`. `free`: empty |
| 11 | `amount_charged` | Wei, as a decimal ASCII string with no leading zeros (`0` for zero). In JSON a writer puts a number up to 2^64 - 1 and a decimal string above; a reader takes a number up to 2^64 - 1 or a string of decimal digits for any value |
| 12 | `settled_asset` | UTF-8 |
| 13 | `occurred_at` | Unix milliseconds (a JSON integer) as an 8-byte little-endian signed integer |

## What the digest does not cover

The payee breakdown (`payees`) and the mirrors onto other chains
(`secondary_settlements`) are not in the preimage. They are the serving node's
accounting and change as mirrors confirm, so two copies of one record that
differ only there have the same digest. The payer's kind and wallet, the
billable units, the access tier, the inbound rail
and the settlement transaction hash are not covered either.

## Records that have no digest

A verifier refuses a record when a field above is missing or has the wrong
JSON type, when `kind`, `authority.kind` or `charge.kind` is not one of the
values listed, and when:

- `payer_did`, `attester_did` or `interaction_id` is empty;
- the charge is `free` and `amount_charged` is not zero;
- the charge is not `free` and `amount_charged` is zero.

## Worked example

| # | Field | Value |
|---|-------|-------|
| 1 | `interaction_id` | `int_1` |
| 2 | `kind` | `inference` |
| 3 | `payer_did` | `did:tenzro:machine:agent` |
| 4 | `on_behalf_of` | `did:tenzro:human:alice` |
| 5 | `attester_did` | `did:tenzro:machine:node` |
| 6 | `resource_id` | `qwen3-27b` |
| 7 | authority kind | `x402_payment` |
| 8 | authority value | `exact` |
| 9 | charge kind | `settlement` |
| 10 | charge value | `s-1` |
| 11 | `amount_charged` | `1000` |
| 12 | `settled_asset` | `tenzro:1337/native:tnzo` |
| 13 | `occurred_at` | `1700000000000`, bytes `00 68 e5 cf 8b 01 00 00` |

The preimage is 242 bytes and the digest is

```
d6d89cd298efecf601be462c2a4e76878fbd021033753663db55af3728ab0bf7
```

It is the first vector in `docs/standards/vectors/interaction-receipt.json`.

## Verifiers

`tools/receipt-verify` implements this document from its text with a SHA-256
library only and links no Tenzro crate:

```
tenzro-receipt-verify --interaction record.json
tenzro-receipt-verify --interaction --expect 58cda40b... record.json
```

The Tenzro CLI computes the same digest with the node's own code:

```
tenzro interaction verify record.json [--expect 58cda40b...]
```

Both read the record's JSON, refuse a record that has no digest, and print
the digest. With `--expect` they exit with an error unless the record's
digest is the one given (hex, with or without `0x`, any case). Neither
contacts a node. The tests of both run every vector, so the published rules,
the independent verifier and the node's code cannot drift apart.

What a matching digest shows: the record you hold is, in every covered field,
the record the digest was made from. Whether that digest was written by the
node you think, or settled on a chain, is a separate check against that node's
signature or that chain's transaction.
