# The `tenzro` payment method for the HTTP Payment authentication scheme

Status: draft, written against `draft-httpauth-payment-01` (the core of the
Machine Payments Protocol). It follows the shape of the published `evm`,
`solana` and `tempo` method documents and defines how a payment on a Tenzro
network answers a `Payment` challenge.

## 1. Method identifier

`tenzro`. A server offering it sends a challenge whose `method` parameter is
`tenzro`; the network is `tenzro` with its chain id in the request
(`extra.chain_id`), the CAIP-2 network `tenzro:<chain id>`.

## 2. Intents

| Intent | What the payer authorizes | How it settles |
| --- | --- | --- |
| `charge` | One payment of exactly the requested amount | A `PayerSettle` transaction carrying the payer's signed authorization; the receipt is issued after it executes in a finalized block |
| `session` | A capped stream of requests against an escrow the payer funded | Each request carries a cumulative voucher on the escrow; the payee claims the highest voucher before expiry, and the payer refunds the rest after it |

## 3. Challenge

```
HTTP/1.1 402 Payment Required
WWW-Authenticate: Payment id="<challenge id>", realm="<resource>",
    method="tenzro", intent="charge"|"session",
    request="<base64url JSON>", expires="<RFC 3339>"
```

The `request` JSON:

| Field | Meaning |
| --- | --- |
| `challenge_id` | Equals the `id` parameter |
| `protocol` | `mpp` |
| `resource` | The resource paid for |
| `amount` | Smallest units of `asset`; for `session`, the price of one request |
| `asset` | `TNZO` or a token id on the network |
| `recipient` | Payee account, hex |
| `chain` | `tenzro` |
| `expires_at` | RFC 3339 |
| `extra` | `chain_id` (the network's chain id) and `intent` (`charge` or `session`) |

## 4. Credential

```
Authorization: Payment <base64url JSON>
```

with JSON `{ "challenge": { "id": "<challenge id>", ... }, "source": "<payer DID or account>", "payload": { ... } }`.

For `charge`, `payload` is the signed payment credential:

| Field | Meaning |
| --- | --- |
| `challenge_id` | The challenge answered; must equal `challenge.id` |
| `payer_did` | The paying DID, or empty to pay by key alone |
| `payer_address` | The account the signing key controls |
| `amount`, `asset` | As requested |
| `signature` | Composite signature (P-256, plus ML-DSA-65 when the account has enrolled one) over the canonical payment authorization: chain id, challenge id, payer, payee, ceiling, asset and the request and quote binding |

For `session`, `payload` carries an escrow voucher: `escrow_id`,
`cumulative_amount`, `binding`, `public_key` and `signature`. Vouchers never
go backwards. A request costing `c` is accepted while
`voucher - spent >= c`.

## 5. Verification

A server accepts a credential only when all of the following hold:

1. The signature verifies, and the key controls `payer_address`.
2. A named `payer_did` lists that key or that account.
3. The authorization names this chain, challenge, payee and asset.
4. The amount does not exceed the request.
5. If the payer is a delegated agent, its consensus Terms allow the payment: scope, per-transaction and per-period limits, counterparties, and kill-switch state.

The ledger checks the signature again when the payment executes. It also
refuses a second settlement of the same challenge id.

## 6. Receipt

```
Payment-Receipt: <base64url JSON>
```

with `{ "status": "success", "method": "tenzro", "timestamp": "<RFC 3339>", "reference": "<ledger transaction hash, or the escrow id for a session>", "challenge_id": "<id>" }`.

## 7. Security considerations

- **Replay.** The challenge id is the payment id on the ledger, so a challenge is settled at most once.
- **Price substitution.** The authorization binds the request and quote digests, so a payment cannot be moved to another price or request.
- **Agent authority.** A delegated agent pays only inside its Terms. Authority is never read from the credential.
- **Keys.** Payer keys live in hardware (passkey, TPM or Secure Enclave). The server never holds them.

## 8. Implementation status

The reference node implements both intents (`tenzro-payments` `mpp`
module), and its challenges name the `tenzro` method in the `method`
parameter. Credentials are matched to their challenge by `id`, so no client
sends the method back and none depends on the old value.
