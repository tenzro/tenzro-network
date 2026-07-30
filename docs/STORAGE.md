# Tenzro Storage

**Decentralized storage on Tenzro Network — content-addressed objects, billed per byte-epoch, held to a proof of retrievability, settled in TNZO.**

---

## Abstract

A node with spare disk can hold data for the network. Tenzro Storage is the protocol surface that turns that disk into a paid service: a consumer opens a deal for an object, the provider proves each epoch that it can still return the data, and TNZO moves one byte-epoch slice at a time from the consumer to the provider.

Storage is a role a node takes on, not a separate network. A node that serves AI can hold data at the same time, and the one stake that backs serving a model also backs the storage it offers. There is no second coverage budget — storage shares the compute rental one, one stake, one set of obligations. A storage provider does post the same one-time admission bond every non-validator provider posts; see [`docs/COMPUTE.md`](COMPUTE.md) section 1.1.

This document describes the object model, the deal lifecycle, the proof-of-retrievability gate, redundancy, the shared coverage budget, and the RPC / CLI / SDK surfaces.

---

## 1. Design

Three properties shape the storage surface:

1. **Content-addressed objects over the data plane.** Objects are stored as shards on the iroh data plane and referenced by content address. A `StorageProvider` resolves an object's `ObjectDescriptor` — its shards and their references — through an iroh resolver.

2. **Retrievability is proven, not assumed.** Each epoch the provider answers a proof-of-retrievability challenge: the network samples shards, the provider returns digests over them, and only a correct answer settles the epoch. A failed or missing answer settles nothing and is recorded as a miss.

3. **One stake, shared with compute.** Storage obligations register against the same `ProviderObligations` tracker that compute rental uses. A provider's stake covers everything it owes across both services at once; over-commit and it sheds deals until the rest fits.

The crates that implement this:

- `tenzro-storage-provider` — `StorageProvider`, `ObjectDescriptor`, `StorageMeter`, `StoragePricing`, `StorageDeal`, `ChargeOutcome`, the proof-of-retrievability challenge (`por`), and redundancy
- `tenzro-settlement` — `ProviderObligations`, the coverage tracker shared with compute
- `tenzro-node` — the storage provider runtime that wires identity, stake, obligations, and pricing into a `StorageMeter`

---

## 2. The deal lifecycle

`StorageMeter` owns the deal state machine.

### Open

A consumer opens a deal for an object:

```
open_deal(...)   // locks the consumer's exposure, registers the provider's obligation
```

The exposure is the per-epoch price (a function of object size and the provider's `rate_per_byte_epoch`) times the deal's term. Opening fails if the provider's stake cannot cover the new obligation on top of everything else it owes — compute rentals included.

### Charge an epoch

Each epoch, the provider settles by answering a retrievability challenge:

```
charge_epoch(deal_id, challenge_passed) -> ChargeOutcome
```

The outcome is one of three:

- `Charged { slice }` — the challenge passed; one byte-epoch slice moved from the consumer to the provider.
- `Missed` — the challenge failed or was not answered; no value moved.
- `Closed { completed }` — the deal reached its term or ran out of coverage.

### Proof of retrievability

A challenge samples a subset of an object's shards. The provider answers by fetching those shards and returning a digest keyed to a per-challenge nonce, so a stale or fabricated answer does not pass. Sampling means the provider must actually hold the data to answer, without the network having to re-download the whole object.

---

## 3. Pricing

Storage is priced per byte-epoch. A provider sets its `rate_per_byte_epoch`; the epoch price for a deal is that rate scaled by object size.

- **Fixed.** A flat rate per byte-epoch.
- **Network-dynamic.** The rate tracks storage utilization through an EIP-1559-style controller over a smoothed utilization signal. Storage uses a denominator of 16 (a per-step move bounded at ±6.25%) — a gentler curve than compute, because storage commitments are longer-lived.

### Slashing and re-replication

The metering loop charges an epoch only when the provider passes that epoch's retrievability challenge. A failed challenge is a *miss*: the renter is not charged and that epoch's slice returns to their withdrawable deposit. Consecutive misses past the deal's `miss_threshold` terminate the deal and refund the unearned remainder to the renter.

The meter itself moves only renter↔provider value — it does not slash. Repeated misses are the *signal* the staking subsystem consumes: it slashes the provider's stake and the redundancy layer re-replicates the object onto a healthy provider. This keeps the value-transfer path (the meter) and the stake-penalty path (consensus/settlement) cleanly separated, reached through the same `StakeLedger` indirection that compute rentals use. Storage exposure and rental exposure share one coverage budget per provider, so a multi-role node's storage deals and compute rentals admit against the same stake.

---

## 4. Redundancy

Objects can be stored with redundancy so the loss of a single provider does not lose the data. The `redundancy` module describes how an object's shards are spread; a consumer chooses a redundancy level when the durability of the object justifies the extra cost.

---

## 5. Access control

Every stored object is owned, and retrieval is gated. `ObjectDescriptor` carries the same `AccessPolicy` (from `tenzro-types`) that gates a database, so a file and a database are protected identically:

- **`public`** — any caller may retrieve; only the owner administers.
- **`owner_only`** — only the owner DID may retrieve or administer. The default when a store request supplies just `owner_did`.
- **`did_allowlist`** — a named set of reader DIDs may retrieve; the owner administers.
- **`capability_required`** — retrieval requires an AAP capability naming the policy's read action; the owner always administers.

`tenzro_storageStoreObject` accepts either a full `access_policy` object or a bare `owner_did` (which defaults to `owner_only`). The node adjudicates every retrieval fail-closed before returning shards.

**Confidential seal.** A sensitive object can additionally carry a `ConfidentialSeal`: encryption-at-rest with one wrapped data key per authorized DID (`hpke-x25519-hkdf-sha256-aes-256-gcm`). The descriptor records the wrapped-key envelopes; the node and client do the crypto. This is opt-in on top of the always-on access policy — a capability gate for every object, encryption-at-rest for sensitive data.

---

## 6. Money flow

The invariant is the same one the whole network settles on: **the consumer pays from their TNZO balance; the provider earns into theirs.** Holding data credits the provider per byte-epoch; consuming storage debits the consumer. A missed retrievability proof moves nothing and is the network's signal that the provider is not holding what it agreed to.

### Prepaid balances

Before a deal can stream, the renter funds a prepaid balance: TNZO is locked out of their on-chain account into a key-less prepaid vault, and the locked amount becomes their spendable balance for streaming settlement. Per-epoch charges draw down that prepaid balance; any unspent remainder can be withdrawn back to the on-chain account. Prepaid balances persist across restarts and are billed once per epoch by a background loop on the node.

---

## 7. Interfaces

### RPC

The node exposes storage endpoints for opening deals, charging epochs, querying deal state, setting pricing, and reporting storage-provider status. Prepaid balances are funded and read through `tenzro_prepaidDeposit`, `tenzro_prepaidWithdraw`, and `tenzro_prepaidBalance`.

### CLI

```
tenzro node storage status
tenzro node storage open-deal --object <id> --epochs <n>
tenzro node storage deal --deal <id>
tenzro escrow prepaid-deposit --renter <addr> --amount <wei>
tenzro escrow prepaid-balance --renter <addr>
tenzro escrow prepaid-withdraw --renter <addr> --amount <wei>
```

### SDKs

Both the Rust and TypeScript SDKs expose a `storage` client mirroring the RPC surface. Prepaid balances are managed through the `settlement` client (`prepaid_deposit` / `prepaid_withdraw` / `prepaid_balance`).

---

## 8. How storage relates to compute

Storage and compute rental are two roles against one stake. They share the same `ProviderObligations` tracker and the same balance map; they differ only in the gate. Storage settles on a proof of retrievability per byte-epoch; compute settles on an availability proof per epoch. When a provider's stake no longer covers what it owes, both shed coverage through the same recheck. See [`docs/COMPUTE.md`](COMPUTE.md) for the compute side of the same substrate.

Not everything content-addressed on the data plane is a storage deal. A rendered image or video is written to the producing worker's own blob store and is fetched from there by content address, which is how a requester gets bytes it can check against the hash in its receipt — but no byte-epoch is billed for it, no retrievability challenge is answered, and no redundancy is promised. A requester that wants the network to keep an output opens a deal for it like any other object. See [`AI.md`](AI.md) §8.
