# Tenzro Storage

**Decentralized storage on Tenzro Network — content-addressed objects, billed per byte-epoch, held to a proof of retrievability, settled in TNZO.**

---

## Abstract

A node with spare disk can hold data for the network. Tenzro Storage is the protocol surface that turns that disk into a paid service: a consumer buys a storage claim for an object, validators check each hour that the provider can still return the data, and the claim pays the provider hour by hour on their verdicts.

Storage is a role a node takes on, not a separate network. A node that serves AI can hold data at the same time, and the one stake that backs serving a model also backs the storage it offers. There is no second coverage budget — storage shares the compute rental one, one stake, one set of obligations. A storage provider does post the same one-time admission bond every non-validator provider posts; see [`docs/COMPUTE.md`](COMPUTE.md) section 1.1.

This document describes the object model, the storage claim lifecycle, the possession gate, redundancy, and the RPC / CLI / SDK surfaces.

---

## 1. Design

Three properties shape the storage surface:

1. **Content-addressed objects over the data plane.** Objects are stored as shards on the iroh data plane and referenced by content address. A `StorageProvider` resolves an object's `ObjectDescriptor` — its shards and their references — through an iroh resolver.

2. **Possession is proven, not assumed.** Each epoch the provider answers a possession challenge: a fresh nonce selects chunk positions across the object's shards, the provider returns those chunks with Merkle paths to the per-shard roots committed at store time, and the question is asked by validators. A provider whose bond delivers a storage claim is found available for an hour only while it proves possession of every object it is paid to keep, and the claim settles hour by hour on that verdict.

3. **Payment is a compute claim in consensus state.** A provider writes a storage claim against its compute bond, or against its storage role stake when it sells storage only, and posts collateral; the renter buys it. The claim commits the object's descriptor digest, and its vault pays the provider for each hour validators found the bond available and makes the renter whole from collateral for each hour they did not.

The crates that implement this:

- `tenzro-storage-provider` — `StorageProvider`, `ObjectDescriptor`, the provable-data-possession challenge (`pdp`), and redundancy
- `tenzro-vm` — `ComputeClaimOp` with `storage_descriptor`, settled on SLA verdicts (`compute_claim`)
- `tenzro-node` — the storage provider runtime (objects and pricing) and the possession probes validators send and providers answer (`capacity_probe`)

---

### Storage-only providers

A provider without a compute bond delivers storage claims from its `storage` role stake. It bonds the role (`tenzro stake bond --role storage`), answers probes as the hardware identity registered on chain for that account, and names its stake subject `did:tenzro:role:storage:<account hex>` as the claim's `provider_did`. `tenzro_getRoleStakes` returns that subject as `sla_subject`. Validators probe the subject each round, `SlaAttest` accepts it, and an hour frozen unavailable takes the governed SLA penalty from the storage stake into the insurance pool. A storage stake delivers storage claims only; a compute claim still needs a compute bond.

## 2. The storage claim lifecycle

1. **Store.** The provider stores the object (`tenzro_storageStoreObject`) and returns its `descriptor_digest`: hex SHA-256 of the bincode object descriptor.
2. **Offer.** The provider sends `ComputeClaim { op: Offer { .., provider_did: <its compute bond>, storage_descriptor: <digest> } }` with collateral and a strike per hour (size times its byte-epoch rate). A storage claim is always delivered, never cash-settled.
3. **Buy.** The renter sends `Accept { claim_id, max_total }`, paying the total strike into the claim's vault.
4. **Prove.** For each hour of the term, validators' SLA probes of the bond carry possession work; the provider answers with a proof per due claim, keyed by claim id. The bond is scored available only when every due object is proven against the descriptor the claim committed.
5. **Settle.** Anyone may send `Settle`: each hour with an available verdict pays the provider that hour's strike; an unavailable hour refunds the renter and pays a penalty from collateral; an hour with no verdict within the submission window refunds it.

### Provable data possession

When an object is stored, each shard is cut into 1 KiB chunks and committed as a Merkle root; the root and chunk count are recorded on the shard's `ShardRef`. A challenge is a fresh random nonce, and the nonce alone determines which `(shard, chunk)` positions must be proven, so neither side chooses them and the provider cannot know them in advance. The answer is each sampled chunk with its Merkle path; the verifier checks the paths against the committed roots using only the object descriptor, and never downloads a shard. A proof is a few kilobytes whatever the object size. A provider that kept a fraction `f` of a shard survives `s` samples of it with probability about `f^s`.

---

## 3. Pricing

Storage is priced per byte-epoch. A provider sets its `rate_per_byte_epoch`; the hourly strike of a storage claim is that rate scaled by object size.

The rate is fixed: it never follows utilization or demand, so a renter pays the same rate whenever it opens a deal, and a provider cannot raise its price by filling its own capacity. `tenzro_storageSetPricing` sets it. A node configured with any other pricing mode refuses the configuration.

Each hour a storage claim pays its provider is a settlement: it pays the settlement fee and the governed storage treasury leg (`fees.treasury_leg_storage_bps`), and it records `StorageServed` provider work, since validators found the object retrievable that hour.

### Slashing and re-replication

An hour in which the bond could not prove a due object is an unavailable verdict: the renter gets that hour's strike back plus a penalty from the claim's collateral, and repeated unavailable verdicts carry the compute bond's SLA slashes. The redundancy layer re-replicates the object onto a healthy provider. No node keeps a book of its own: the claim, its vault and the verdicts are consensus state.

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

Who may call what:

- `tenzro_storageStoreObject`, `tenzro_storageRetrieveObject` and `tenzro_storageSetPricing` are operator-only (node administrators): they place and read back objects on this provider and set its rates. Payment needs no node method: the renter buys the storage claim on chain.

**Confidential seal.** A sensitive object can additionally carry a `ConfidentialSeal`: encryption-at-rest with one wrapped data key per authorized DID (`hpke-x25519-hkdf-sha256-aes-256-gcm`). The descriptor records the wrapped-key envelopes; the node and client do the crypto. This is opt-in on top of the always-on access policy — a capability gate for every object, encryption-at-rest for sensitive data.

---

## 6. Money flow

The invariant is the same one the whole network settles on: **the consumer pays from their TNZO balance; the provider earns into theirs**, and the chain is the only balance. No node holds a deposit.

### Storage claims

A storage claim's vault holds the renter's payment and the provider's collateral; nobody holds a key to it. Value leaves it only through `Settle`, hour by hour on committed SLA verdicts, so no node decides the outcome. The holder may transfer or pledge the claim like any compute claim.

---

## 7. Interfaces

The node offers the market layer: an object is addressed by an id you choose, and ownership, funding and naming are yours. It is what you build a storage product on.

A tenant layer (an OpenAI-shaped `/v1/files` that names files, keeps tenants apart and returns the descriptor digest a storage claim commits) is an application a harness provides, which a provider's operator runs beside the node, storing with `tenzro_storageStoreObject` and reading back with `tenzro_storageRetrieveObject`. Deleting a file there unlinks it; shards expire when no claim pays for them.

### RPC (market layer)

The node exposes `tenzro_storageStoreObject` (returns `descriptor_digest`), `tenzro_storageRetrieveObject` (the bytes, rebuilt from shards), `tenzro_storageSetPricing` and `tenzro_storageStatus`; the store and the read-back are the operator's own. Payment is a storage compute claim, read with `tenzro_computeGetClaim` / `tenzro_computeListClaims`.

### CLI

```
tenzro node storage store --object-id <id> --owner <address> --file <path>
tenzro node storage retrieve --object-id <id> --out <path>
tenzro node storage status
```

### SDKs

The Rust and TypeScript SDKs expose a `storage` client mirroring the market-layer RPC surface (`storeObject` / `retrieveObject` / pricing / status). Storing is signed by the owner DID and reading by a DID the object's access policy admits, each with a DID envelope over the request.

---

## 8. How storage relates to compute

Storage and compute are two roles against one bonded stake; they differ only in the gate. Storage settles on a proof of retrievability per byte-epoch; compute settles on an availability proof per epoch. When a provider's stake no longer covers what it owes, both shed coverage through the same recheck. See [`docs/COMPUTE.md`](COMPUTE.md) for the compute side of the same substrate.

Not everything content-addressed on the data plane is under a storage claim. A rendered image or video is written to the producing worker's own blob store and is fetched from there by content address, which is how a requester gets bytes it can check against the hash in its receipt — but no byte-epoch is billed for it, no retrievability challenge is answered, and no redundancy is promised. A requester that wants the network to keep an output buys a storage claim for it like any other object. See [`AI.md`](AI.md) §8.
