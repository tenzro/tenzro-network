# AP2 mandates and agent Terms: test vectors

AP2 v0.2 open Payment Mandates carry constraints. On Tenzro, a mandate only
narrows what the paying agent's consensus Terms already allow: the node checks
the mandate, then the Terms, with the same Terms check every x402 and MPP
payment passes. Nothing is stored.

| AP2 constraint | Terms field it corresponds to | Checked statelessly |
| --- | --- | --- |
| `payment.reference` | (binds the payment to one checkout) | yes, required |
| `payment.amount_range` | per-transaction limit | yes |
| `payment.allowed_payees` | counterparties | yes |
| `payment.allowed_payment_instruments` | allowed payment protocols | yes |
| `payment.execution_date` | Terms expiry | yes |
| `payment.allowed_pisps` | none (no PISP initiates an on-chain payment) | accepted, no effect |
| `payment.budget` | per-period limit | refused: needs a record of earlier payments |
| `payment.agent_recurrence` | per-period limit | refused: needs a record of earlier payments |
| any other type | none | refused |

The vectors are in `sdk/fixtures/ap2_terms/vectors.json`, one payment per
case with its constraints, the Terms per-payment limit and the expected
outcome after both checks. `crates/tenzro-payments/tests/ap2_terms_vectors.rs`
signs fresh mandates for every case and runs them through the verifier.
