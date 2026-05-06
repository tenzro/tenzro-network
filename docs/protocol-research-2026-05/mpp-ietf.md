# MPP IETF Research — `draft-ryan-httpauth-payment-01`

**Date:** 2026-05-05
**Source:** https://datatracker.ietf.org/doc/html/draft-ryan-httpauth-payment-01
**Companion:** https://paymentauth.org/, https://github.com/tempoxyz/mpp-specs

## Wire format (verbatim from draft)

### Challenge

```
challenge   = "Payment" [ 1*SP auth-params ]
auth-param  = token BWS "=" BWS ( token / quoted-string )
```

Required params: `id`, `realm`, `method`, `intent`, `request`.
Optional: `expires`, `digest`, `description`, `opaque`.

```
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="x7Tg2pLqR9mKvNwY3hBcZa",
    realm="api.example.com", method="example", intent="charge",
    expires="2025-01-15T12:05:00Z",
    request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0Qi..."
```

### Credential

```
payment-credentials = "Payment" 1*SP base64url-nopad
```

Body is base64url-nopad-encoded JSON (NOT a JWT):

```json
{
  "challenge": { ...echoed challenge params... },
  "source": "did:tenzro:machine:...",
  "payload": { ...method-specific proof... }
}
```

### Receipt

`Payment-Receipt` header = base64url-JSON `{status, method, timestamp, reference}`.

## Extension points (spec-blessed)

- `source` field is "RECOMMENDED: DID format per [W3C-DID]" → TDIP DIDs are first-class
- `opaque` parameter is server-defined base64url-JSON → arbitrary correlation data
- Custom params allowed: "Implementations MAY define additional parameters in challenges; parameters MUST use lowercase names"
- No native delegation/RBAC scoping defined → open territory

## Tenzro angle (YES)

**Sibling draft proposal:** `draft-tenzro-httpauth-payment-mandate-00`

Extends MPP credential JSON with:
- `mandate` object: `{ max_transaction_value, allowed_operations, time_bound, controller_did, signature }` — TDIP delegation scope inline
- `settlement_proof` field: `{ tx_hash, zk_commitment, circuit_id: "settlement" }` — Plonky3-verified on-chain proof reference in the receipt

**Outcome:** Single MPP round-trip = payment-auth + agent-mandate + cryptographic settlement proof. AP2 + MPP + on-chain finality fused into one header. Nobody else has filed this.

## Implementation order

1. **Spec conformance first** — `WWW-Authenticate: Payment ...` + `Authorization: Payment <base64url>` headers in `crates/tenzro-payments/src/middleware.rs:252-261` and `parse_credential` at `:205-234`.
2. **`source` field accepts TDIP DIDs** — `did:tenzro:machine:*` resolves via `IdentityRegistry::resolve_identity()`, controller is checked via `enforce_operation()`.
3. **Tenzro `mandate` extension** — added as a custom credential JSON field; backward-compatible (parsers ignore unknown fields).
4. **Receipt `reference` field carries settlement-tx hash + ZK commitment** — when settlement is on Tenzro chain.
