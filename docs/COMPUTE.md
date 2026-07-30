# Tenzro Compute

**Rentable compute capacity on Tenzro Network — booked per epoch, gated on an availability proof, settled in TNZO.**

---

## Abstract

Serving a model is one way a node turns hardware into income. Renting out spare capacity is another. Tenzro Compute is the protocol surface that lets a node offer its idle cycles to the network: a consumer books capacity for a fixed number of epochs, the provider proves it stayed available each epoch, and TNZO moves one epoch-slice at a time from the consumer's balance to the provider's.

Compute rental is not a separate role with its own stake. A node that serves AI already declares the capability; renting out compute rides the same `serves_ai()` role and the same stake that backs serving a model. One node can serve inference and rent capacity at once, and a single stake covers both obligations.

Renting capacity is not the only way an accelerator earns. Generative image and video rendering is a third surface, and a distinct one: a render job is priced per pixel-step and paid once against a signed receipt rather than booked per epoch against an availability proof, and a media worker carries no stake and no coverage obligation. See [`AI.md`](AI.md) §8 for that surface.

This document describes the rental lifecycle, the availability-proof gate, the streaming-escrow settlement model, how compute shares a coverage budget with storage, and the RPC / CLI / SDK surfaces.

---

## 1. Design

Three properties shape the compute surface:

1. **One stake, many roles.** A provider stakes once. The same stake underwrites serving a model, renting out compute, and holding data. There is no per-service bond. A single `ProviderObligations` tracker and a single balance map account for every obligation the provider has taken on, all measured against that one stake.

2. **Availability is proven, not asserted.** A rental settles per epoch only when the provider supplies a valid availability proof for that epoch. A missed proof does not silently drain the consumer — the epoch is recorded as missed and the consumer is made whole for that slice. Repeated misses cross a threshold and close the rental.

3. **Settlement streams.** A rental is not paid up front. The consumer locks the full term, but value is released one epoch-slice at a time as the provider proves availability. Unspent term remains the consumer's until it is earned.

The crates that implement this:

- `tenzro-settlement` — `RentalManager`, `RentalAgreement`, `EpochOutcome`, `ProviderObligations` (the shared coverage tracker)
- `tenzro-node` — `compute_rental_runtime`, which wires a provider's identity, stake ledger, obligations, and pricing policy into a `RentalManager`
- `tenzro-types` — `RoleSet` with `serves_ai()` / `serves_storage()`

---

## 2. The rental lifecycle

A rental moves through a small, explicit state machine. `RentalManager` owns it.

### Book

A consumer books capacity from a provider for a fixed term:

```
book_rental(renter, provider, asset_id, price_per_epoch, total_epochs)
```

Booking locks the consumer's exposure (`price_per_epoch × total_epochs`) and registers the provider's obligation against its stake. Booking fails if the provider's stake cannot cover the new obligation on top of everything else it already owes — storage included.

### Settle an epoch

Each epoch, the provider settles with an availability proof:

```
settle_epoch(rental_id, proof_valid) -> EpochOutcome
```

The outcome is one of three:

- `Settled { slice }` — the proof was valid; one epoch-slice moved from the consumer's balance to the provider's.
- `Missed { made_whole }` — the proof was missing or invalid; no value moved and the consumer keeps that slice.
- `Closed { reason }` — the rental reached its term, ran out of coverage, or crossed the miss threshold.

### Coverage recheck

When a provider's stake changes — a withdrawal, a slash, a new obligation elsewhere — the network rechecks whether its active rentals are still covered:

```
recheck_coverage(provider) -> Vec<rental_id>   // rentals shed because coverage no longer holds
```

Coverage is shared. A provider that over-commits across compute and storage sheds obligations until what remains fits its stake. This is the cross-service invariant: one stake, one coverage budget.

---

## 3. Pricing

A provider chooses how its per-epoch rate is set:

- **Fixed.** The provider names a flat rate per epoch and it stays put.
- **Network-dynamic.** The rate tracks network utilization through an EIP-1559-style controller over an exponentially smoothed utilization signal. When demand for compute runs above target, the rate rises; below target, it falls. Compute uses a denominator of 8 (a per-step move bounded at ±12.5%), a 50% target, and a smoothing window of 4.

The controller is the same proportional step the chain's gas base fee uses (`tenzro-vm`'s `FeeMarket::calculate_next_base_fee`), applied to the per-epoch rate instead of gas price. It is integer-only — no floats in the settlement path:

```
util  = EMA over the last `window` epochs of (busy_capacity / total_capacity), scaled to the target's integer domain
target = 50% utilization

if util == target:   rate stays
if util  > target:   rate += rate × (util − target) / target / D      // capped at +12.5% per step
if util  < target:   rate -= rate × (target − util) / target / D       // capped at −12.5% per step
```

with `D = 8` for compute (and inference), `D = 16` for storage — storage moves at half the per-step speed because storage demand is stickier than inference demand. The new rate is clamped to a configured floor and ceiling so a quiet or saturated window cannot drive it to zero or unbounded. The EMA smoothing (`window = 4`) keeps a single burst epoch from whipsawing the rate.

Pricing is the provider's call. Consumers see the effective rate before they book.

---

## 4. Money flow

The invariant is uniform across every Tenzro service: **the consumer pays from their TNZO balance; the provider earns into theirs.** Renting out compute credits the provider; consuming it debits the consumer. There is no separate settlement path for compute — it uses the same balances the rest of the network settles against.

Before a rental streams, the renter funds a prepaid balance: TNZO is locked out of their on-chain account into a key-less prepaid vault and becomes their spendable balance for streaming settlement. Per-epoch charges draw down that balance; any unspent remainder can be withdrawn back. Prepaid balances persist across restarts and are billed once per epoch by a background loop on the node.

---

## 5. Interfaces

### RPC

- `tenzro_computeBookRental` — book a rental for a term
- `tenzro_computeSettleEpoch` — settle one epoch with an availability proof
- `tenzro_computeRental` — fetch a rental's state
- `tenzro_computeSetPricing` — switch between fixed and network-dynamic pricing
- `tenzro_computeStatus` — whether this node is a compute provider, its effective rate, and its active rentals
- `tenzro_prepaidDeposit` / `tenzro_prepaidWithdraw` / `tenzro_prepaidBalance` — fund, refund, and read the prepaid streaming balance

### CLI

```
tenzro node compute status
tenzro node compute book-rental --asset <id> --epochs <n>
tenzro node compute settle-epoch --rental <id>
tenzro node compute rental --rental <id>
tenzro node compute set-pricing --mode <fixed|dynamic>
tenzro escrow prepaid-deposit --renter <addr> --amount <wei>
tenzro escrow prepaid-balance --renter <addr>
tenzro escrow prepaid-withdraw --renter <addr> --amount <wei>
```

### SDKs

Both the Rust and TypeScript SDKs expose a `compute` client with `book_rental`, `settle_epoch`, `get_rental`, `set_dynamic_pricing`, and `status`. Prepaid balances are managed through the `settlement` client (`prepaid_deposit` / `prepaid_withdraw` / `prepaid_balance`).

---

## 6. How compute relates to storage

Compute and storage are two roles a node can take on against one stake. They share the same `ProviderObligations` tracker and the same balance map. The difference is the gate: compute settles on an availability proof per epoch; storage settles on a proof of retrievability per byte-epoch. Both shed coverage the same way when a provider's stake no longer covers what it owes. See [`docs/STORAGE.md`](STORAGE.md) for the storage side of the same substrate.
