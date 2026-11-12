# Tenzro Compute

**Rentable compute capacity on Tenzro Network — a stream escrow to the provider, paid per epoch, held to validator SLA verdicts, settled in TNZO.**

---

## Abstract

Serving a model is one way a node turns hardware into income. Renting out spare capacity is another. Tenzro Compute is the protocol surface that lets a node offer its idle cycles to the network: a consumer posts a rental task, a bonded provider wins it, validators judge each epoch whether the provider stayed available, and TNZO streams one epoch at a time from the consumer's escrow to the provider.

Compute rental is not a separate role with its own stake. A node that serves AI already declares the capability; renting out compute rides the same `serves_ai()` role and the same stake that backs serving a model. One node can serve inference and rent capacity at once, and a single stake covers both obligations.

Renting capacity is not the only way an accelerator earns. Generative image and video rendering is a third surface, and a distinct one: a render job is priced per pixel-step and paid once, against a worker receipt for a job its requester signed, both verified against the keys their DIDs list, rather than streamed per epoch against SLA verdicts, and a media worker carries no stake and no coverage obligation. See [`AI.md`](AI.md) §8 for that surface.

Compute rental sits beside the other ways machines of every class take part: GPU providers serve models and rent capacity, and edge devices are designed to orchestrate hybrid jobs that call GPU providers for large models, with every party paid from the caller's budget ([AI.md](AI.md#hybrid-jobs-edge-orchestration-and-model-ladders)).

This document describes the rental lifecycle, the validator SLA verdicts, the streaming-escrow settlement model, how compute shares a coverage budget with storage, and the RPC / CLI / SDK surfaces.

---

## 1. Design

Three properties shape the compute surface:

1. **One stake, many roles.** A provider stakes once. The same stake underwrites serving a model, renting out compute, and holding data. There is no per-service bond. Coverage is read from the provider's bonded role stake in consensus state.

2. **Availability is proven, not asserted.** Validators probe every bonded provider and freeze a verdict per epoch once two thirds of bonded stake have attested it (§1.3). An epoch judged unavailable slashes the provider's compute bond into the insurance pool, and the renter claims that epoch's value back from the pool with the verdict as evidence. No provider's own word settles anything.

3. **Settlement streams.** The renter locks the whole term when it awards the rental, and value is released one epoch at a time. The renter may stop the stream at any epoch and take back what has not accrued.

The crates that implement this:

- `tenzro-vm` — `native/compute_claim.rs`, the claims capacity is rented through (§6)
- `tenzro-types` — `RoleSet` with `serves_ai()` / `serves_storage()`
- `tenzro-vm` — `native::ComputeBond`, `compute_bond`, `compute_bonds` (the admission bond below, read from chain state)

### 1.1 The admission bond

Before a provider can register, it posts a compute bond. The bond sits in a
vault derived deterministically from the provider DID — nobody holds its key.
It is admission collateral, distinct from the coverage a rental consumes: the
bond is posted once and stays put, while coverage rises and falls with the
obligations the provider has taken on.

A compute bond must hold at least `compute_bond.min_tnzo` (100 TNZO at
genesis), a consensus parameter that only an enacted governance proposal
changes: a post below it is refused, and a bond below the minimum in force
backs nothing. A raised minimum takes effect only after the tightening grace
window, so bonds posted under the old value keep backing their providers
until then. A treasury-posted probation bond is exempt. Each role carries its
own bond besides (`tenzro join --provider` posts the compute bond minimum and
the `ai` role's bond). `tenzro_computeBondParams` reports the minimum in force
and the withdrawal cooldown.

Recovering the bond is two-phase. `withdraw` moves it from `Active` to
`Cooldown`; `finalize` moves it from `Cooldown` to `Returned` once the cooldown
has elapsed. The bond stays slashable throughout the cooldown, which is what
keeps a provider from exiting ahead of a dispute filed against work it has
already served. A slashed bond moves to `Slashed` and is never returned.

All four mutations — `PostComputeBond`, `IncreaseComputeBond`,
`WithdrawComputeBond`, `FinalizeComputeBondWithdrawal` — are native transaction
types, so the vault transfer and the bond state change land in the same block.

### 1.2 SLA probes and the answering identity

Validators check that a bonded provider is really there by probing it: a
VRF-seeded challenge on `tenzro/sla` that the provider must sign before a
deadline. Misses count toward slashing the bond, so two rules keep a probe from
being turned against an honest provider:

- **Only the registered identity answers.** A compute bond is held for the
  provider's machine DID, and a storage stake for an account whose identity is
  registered on chain. Answers are signed by a session key that identity's
  hardware key (P-256, plus ML-DSA-65 where the chip holds one) certified, and
  validators verify them against the key registered on chain for it. They
  ignore any other answer rather than score it: a stranger's answer can neither
  stand in for the provider nor, by arriving first, get it marked as failing. A
  subject whose identity is not registered is not probed, because nobody may
  answer for it; its rentals are voided rather than paid (§2).
- **A probe must leave time to answer.** Scheduled probes give the provider 30
  seconds. Probes issued by hand are operator-only (`tenzro_slaIssueProbe`) and
  must leave at least ten.

### 1.3 Attesting availability on chain

Every validator probes every active, keyed bond every ten minutes. When an
hour closes, each validator submits one `SlaAttest` native transaction with an
outcome per provider it probed: available if the provider answered more than
half of that validator's probes in time.

The chain records at most one attestation per validator per provider and hour,
and only from validators with bonded stake. Once the validators that have
attested hold two thirds of bonded stake, the provider's verdict for that hour
is frozen: available when the stake that said so outweighs the stake that said
not. Attestations are accepted for 24 closed hours, and a frozen verdict cannot
be changed. `tenzro_slaVerdict` (`provider_did`, `epoch`) reads it.

---

## 2. Renting capacity

A rental is a stream escrow from the renter to the provider's bonded address. Finding a provider and agreeing a price happens off chain, in a task market a harness runs over the public RPC; the chain holds only the money and the SLA verdicts. The renter opens the escrow with `CreateEscrow` and release `Stream { rate_per_epoch, epoch_ms }`, expiring at the end of the term: it accrues `rate_per_epoch` for every whole `epoch_ms` from funding to expiry.

| Step | Transaction | Effect |
| --- | --- | --- |
| Rent | `CreateEscrow` with release `Stream`, payee the provider's bonded address | The price locked, accruing per epoch until expiry |
| Draw | `ClaimEscrowStream` | Pays the provider what has accrued over epochs judged available, or whose 24-epoch attestation window closed with no verdict |
| Stop | `RefundEscrow` (renter) | Accrued part to the provider (epochs not yet judged included), the rest back to the renter |
| Missed epoch | none | An epoch the validators judged the provider unavailable is never paid out of the stream: it stays with the renter and returns when the stream is stopped |

A rental takes no deliveries and no disputes: availability is decided by the validators' SLA verdicts, not by either party. A stream pays a positive rate, at most its amount, over a positive epoch. An escrow may carry a `reference` (32 bytes) the application that opened it chose, so a harness can find its rentals again with `tenzro_listEscrowsByPayer`. Delegated agents rent within their consensus Terms with an `AgentAct` of operation `create_escrow`.

Compute claims (§6) buy capacity ahead, hour-aligned, settled on the same SLA verdicts. Buying capacity to use now is a stream escrow.

## 3. Pricing

A provider names a flat rate per epoch and it stays put. The rate is fixed: it never follows utilization or demand, so a renter pays the same rate whenever it opens a deal, and a provider cannot raise its price by filling its own capacity. A node configured with any other pricing mode refuses the configuration (`crates/tenzro-node/src/pricing.rs`).

Pricing is the provider's call: it is the basis of the provider's bid on a rental task, and the renter sees every bid before it awards.

---

## 4. Money flow

The invariant is uniform across every Tenzro service: **the consumer pays from their TNZO balance; the provider earns into theirs**, and the chain is the only balance. A rental's value sits in its stream escrow's vault on chain; no node holds a deposit. The provider draws each accrued epoch with `ClaimEscrowStream`, which anyone may submit and which can only pay the stream's payee as fast as it accrues.

Each stream claim, and each compute claim hour judged available, is an on-chain settlement: it pays the settlement fee (`fees.settlement_fee_bps`, 10 bps at genesis, half burned) and may carry the governed treasury leg for compute (`fees.treasury_leg_compute_bps`, 0 at genesis, at most 5,000 bps, taken from the provider's credit). Paid to the account that posted the compute bond, it records `ComputeLease` provider work, whose reward is bounded by the fee and leg it paid ([TOKENOMICS.md](TOKENOMICS.md#reward-calculation)).

---

## 5. The price feed

Agents choosing a provider need price, latency and reliability for each provider and model. The obvious source, provider announcements, is the one source that cannot be trusted. A provider can advertise a low price and charge a high one, or advertise low latency and serve slowly. A feed built on announcements would price compute on numbers the provider wrote.

So the feed is built from **observations**. After every routed call, the node that routed it signs what it measured at its own HTTP boundary:

- the price it charged;
- the latency on its own clock;
- the token counts, capped at the wire byte count;
- whether the call succeeded.

It then gossips the signed observation on `tenzro/compute-observations`. Two rules decide what an observation can move:

- **Only validators count.** A node admits an observation only if its signer is an active validator identity. Validators are bonded and slashable, so a fabricated observation has a named, staked author. Observations from non-validators are dropped at ingest.
- **One validator is not enough.** A (provider, model) entry is *attested* only once at least two distinct validators have observed it. Only attested entries enter the index, so a validator routing to its own provider cannot move the index alone. An observer signing about its own address is refused outright.

Hardware class and region come from the provider's announcement and remain **claims**. The feed labels them that way and sets the observed numbers beside them.

The **index** covers one hardware class, optionally narrowed to a region. Its value is the median, across attested providers, of each provider's median **price per second of served compute** (wei × 1000 / latency ms). It is priced per compute-second rather than per token so that it measures hardware, not model choice. Taking a median of per-provider medians means a provider with many observations cannot outweigh the others.

Each node keeps a rolling 24-hour observation window in memory and refills it from gossip. A node's view is its own, so the window is evidence for pricing and provider choice, not a number two parties settle a contract against.

| Surface | Feed |
| --- | --- |
| RPC | `tenzro_computePriceFeed` (`model_id`, `hardware_class`, `region`, `attested_only`, `limit`) |
| MCP | `compute_price_feed` |

The feed is an open read. Other surfaces reach it through the universal RPC gateway.

---

## 6. Compute claims

A compute claim is a provider's promise of capacity, written against standard terms and bought ahead of delivery. The hard part is proving the capacity was delivered: a claim pays out hour by hour on the SLA verdicts validators froze for the bond that delivers it (§1.3). No node decides a claim's outcome, and a claim does not depend on any node staying up. Trading, pledging or cash-settling claims against the index are applications built over them, not part of the protocol.

### Terms

| Field | Meaning |
| --- | --- |
| `hardware_class` | `1` cpu, `2` consumer GPU, `3` datacenter GPU, `4` multi-accelerator: the writer's statement. SLA probes prove the bond answers, not what hardware it runs on. |
| `region` | An ISO 3166-1 alpha-2 code, or empty. |
| `delivery_start_ms` | The first hour of delivery. It must be on an hour boundary and in the future, so each claim hour is exactly one chain hour. |
| `epochs` | Hours delivered, 1 to 8,784. |
| `strike_per_epoch` | Price per hour, paid up front by the buyer. |
| `collateral` | Posted by the writer when writing the claim; it makes the holder whole for missed hours. |
| `provider_did` | The compute bond (or storage stake) that delivers the claim. The writer must own it. |
| `storage_descriptor` | Optional, for a storage claim: hex SHA-256 of the bincode object descriptor the bond keeps retrievable. Each hour's verdict for the bond then requires a possession proof of that object. |

### Lifecycle

Every step is a `ComputeClaim` native transaction, whose `op` names the step. The claim's money sits in a vault derived from its id, and nobody holds that vault's key.

1. **Offer.** The writer posts `collateral`. The claim id is fixed by the writer and the nonce it was written at.
2. **Accept.** A buyer pays `strike × epochs` into the vault and becomes the holder. The buyer names `max_total`, the most it agrees to pay, and the purchase is refused above it. That is also the amount delegation ceilings check.
3. **Settle.** Anyone may send it, because the outcome is fixed by committed state. It moves as far as that state allows:
   - **Per closed hour:**
     - the verdict says available: that hour's strike goes to the writer;
     - the verdict says unavailable: that hour's strike returns to the holder, and the same again comes from the collateral while any is left;
     - no verdict within 24 hours: that hour's strike returns to the holder, with no penalty.
     - An hour still waiting for its verdict holds the hours after it. When every hour is settled, the remaining collateral returns to the writer.
   - **Unbought at delivery start:** the offer lapses and the collateral returns to the writer.
4. **Cancel.** The writer may withdraw an unbought offer, and the collateral returns.

Every path pays out exactly what the vault holds, so value is conserved.

```json
{ "from": "0x…buyer", "to": "0x00…00",
  "tx_type": { "ComputeClaim": { "op": { "accept": { "claim_id": "…", "max_total": "300000000000000000000" } } } } }
```

---

## 7. Interfaces

### RPC

- `tenzro_slaVerdict` — a provider's frozen SLA verdict for one hour (§1.3), or `null`
- `tenzro_computeGetClaim` / `tenzro_computeListClaims` — read a claim, or the claims a `party` has written or held, from chain state. Claims are written and bought with the `ComputeClaim` transaction (§6), not by RPC.
- `tenzro_computePriceFeed` — the observed price feed (§5)
- `tenzro_computeBondParams` — the node's minimum bond and withdrawal cooldown
- `tenzro_getComputeBond` — one provider's bond, or `null` when it has never posted one
- `tenzro_listComputeBonds` — every bond this node knows about

Bond mutations are native transactions rather than RPCs; the CLI below signs and submits them.

### CLI

```
tenzro provider compute-price-feed
tenzro provider compute-claims
tenzro provider pricing show

tenzro provider bond params
tenzro provider bond post --did <provider-did> --address <addr> --amount 1000
tenzro provider bond increase --did <provider-did> --address <addr> --amount 500
tenzro provider bond get --did <provider-did>
tenzro provider bond list
tenzro provider bond withdraw --did <provider-did> --address <addr>
tenzro provider bond finalize --did <provider-did> --address <addr>
```

`--amount` on `bond post` and `bond increase` is whole TNZO.

### SDKs

Bonds are read through the `provider` client (`compute_bond_params` / `get_compute_bond` / `list_compute_bonds` in Rust, `computeBondParams` / `getComputeBond` / `listComputeBonds` in TypeScript).

### MCP and A2A

The MCP tool `get_compute_bond` reads one bond or lists them all, and returns the node's minimum bond and cooldown on every call. Over A2A, the `staking` skill reports the same figures alongside provider stats.

---

## 8. How compute relates to storage

Compute and storage are two roles a node can take on against one stake. Both are paid through physical compute claims. A storage claim also commits an object's descriptor digest (`storage_descriptor` on `Offer`), and the delivering bond is found available for an hour only while it proves possession of every object it is paid to keep, so the same hourly SLA verdict settles both. See [`docs/STORAGE.md`](STORAGE.md) for the storage side of the same substrate.
