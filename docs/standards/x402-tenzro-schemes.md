# x402 on a Tenzro network: settlement profile and test vectors

Status: draft, written against x402 wire version 2 (`PAYMENT-REQUIRED`,
`PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`). It defines the schemes a Tenzro
facilitator accepts on the network `tenzro:<chain id>`, what each payer
signs, how each settles, and the vectors an implementation checks itself
against.

## 1. Network

`tenzro:<chain id>` (CAIP-2). A requirement's `asset` is `TNZO` or a token the
chain registers; `payTo` is the payee's 32-byte account in lowercase hex;
`extra.challengeId` names the challenge the payment answers.

## 2. Schemes

| Scheme | The payer signs | Settles by | Receipt `transaction` |
|---|---|---|---|
| `tenzro-hybrid` | Ed25519 + ML-DSA-65 composite over the challenge authorization (context `tenzro/payment/authorization`) | a `PayerSettle` transaction carrying that authorization, executed before the resource is served | the ledger transaction hash |
| `upto` | the same authorization over a maximum; the charge is the actual amount at or below it, bound to a meter-signed usage record when the challenge names a meter key | as `tenzro-hybrid`, for the actual amount | the ledger transaction hash |
| `batch-settlement` | a cumulative voucher on an escrow the payer funded | nothing at request time: the voucher is checked against the escrow in chain state, and the payee claims the advance of the latest voucher later with `ClaimEscrow` | the reference the node's voucher rail returns once it accepted the voucher |

A payment may carry AP2 mandates in its payload `extensions` under the key
`ap2`; they are checked as [AP2 mandates and agent Terms](ap2-terms-vectors.md)
describes, with the challenge id as the key-binding `nonce` and the payee as
its `aud`.

## 3. The deferred scheme

x402's `deferred` scheme (the payer signs now, the payee collects later in
aggregate) is `batch-settlement` here: the escrow is the payer's prepaid
commitment, each voucher is the signed promise for everything consumed so
far, and one `ClaimEscrow` collects any number of vouchers. A facilitator
answers a requirement only under the scheme ids in section 2; a client
offering `deferred` maps it to `batch-settlement` before it signs.

## 4. Test vectors

Each file states what it pins in its `description`; the Rust facilitator and
the payer SDKs are tested against the same bytes.

| File | Pins |
|---|---|
| `sdk/fixtures/payments/x402_hybrid_authorization.json` | the message a payer signs for a `tenzro-hybrid` requirement, as the facilitator rebuilds it from the requirement and the payload's resource |
| `sdk/fixtures/payments/challenge_authorization.json` | the authorization for a quoted, metered challenge with a developer margin (`upto`) |
| `sdk/fixtures/payments/x402_agent_voucher.json` | an agent's `batch-settlement` voucher as the SDKs send it and the facilitator decodes it |
| `sdk/fixtures/ap2_terms/vectors.json` | AP2 mandates presented with a payment, and the Terms decision for each |

## 5. Conformance

An implementation conforms when it rebuilds every signed message in section
4 byte for byte, accepts every vector marked valid and refuses every other
for the reason given. The registry's `standard` and `conformance` entries
name a bundle by its digest; this document and the files in section 4 are
that bundle.
