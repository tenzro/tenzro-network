# IVMS101 Travel Rule

Tenzro carries the FATF Travel Rule data envelope per the IVMS101
v1.1.0 schema natively. The envelope binds an originator + beneficiary
+ originating VASP + beneficiary VASP + transfer data to every
above-threshold transfer, matching the EEA/UK CASP standardised TRP
open HTTPS protocol that the wider compliance ecosystem ingests.

## Scope

Tenzro Ledger is the consensus network; the IVMS101 envelope is the typed payload binding
payments and settlements to originator/beneficiary identity records.
The actual VASP-to-VASP TRP wire transport sits a layer up — handled
by integration partners or by the tenzro-payments HTTP middleware.

This module gives integrators:

1. Canonical Rust types matching the IVMS101 JSON schema.
2. An on-chain binding between the envelope hash and the settlement
   receipt — auditors trace
   `tenzro_payments::receipt → IVMS101 originator + beneficiary →
   originating VASP DID → KYC tier`.
3. CAIP-10 wallet identifiers natively (the form Tenzro consumes),
   alongside the legal-entity identifiers (LEI, national-id) the
   Travel Rule itself names.

## Wire shape

The envelope carries four nested records:

- `originator` — natural/legal person initiating the transfer, plus
  CAIP-10 wallet identifiers
- `beneficiary` — natural/legal person receiving the transfer, plus
  CAIP-10 wallet identifiers
- `originatingVasp` — legal entity custodying the originator (LEI +
  country + optional `tenzro_did`)
- `beneficiaryVasp` — legal entity custodying the beneficiary
- `transfer` — asset CAIP-19 + amount in smallest unit + ISO 8601
  timestamp + transaction hash + optional ISO 20022 message id

All field labels follow the FATF JSON spec (`camelCase` at top level,
nested types follow the same convention) so external compliance tooling
ingests the JSON form without Tenzro-specific transforms.

## RPC surface

| Method | Description |
|---|---|
| `tenzro_ivms101Hash` | Compute the canonical SHA-256 hash for an IVMS101 envelope. The caller submits the envelope payload; the node returns the binding hash plus the originator/beneficiary VASP DIDs + asset CAIP-19 + amount-smallest-unit summary. |

## Receipt binding

The on-chain receipt records ONLY the binding hash + originator/
beneficiary VASP DIDs + asset/amount summary — the full envelope
remains off-chain (carried via TRP). This keeps PII off-chain while
giving auditors a tamper-evident proof that the receipt was bound to
a specific IVMS101 envelope at issuance time.

The binding emits as a `MandateRef { protocol: "ivms101", … }` on the
receipt envelope per the existing mandate-receipt binding model —
closes the audit loop from intent → settlement → travel-rule envelope.

## ISO 20022 shim

A minimal `Iso20022Message` type captures the canonical MX headers
needed to bind a TradFi instruction (`pacs.008` customer credit
transfer, `pacs.009` financial-institution credit transfer, etc.) to
an on-chain settlement: `messageType`, `messageId`, `creationIso8601`,
and an optional `cre_intent_calldata_hex` set when the message arrived
via the Chainlink Runtime Environment translator (the canonical
SWIFT → on-chain path).

## Status

Library types + canonical-hash RPC + receipt binding live. Full
TRP server / client + Chainalysis/Elliptic risk-feed adapter +
MiCA-reporting hook land in subsequent waves alongside the wider
compliance roadmap.
