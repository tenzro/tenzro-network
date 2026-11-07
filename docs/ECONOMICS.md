# Tenzro Network Economics

The canonical description of who pays, who is paid, and how much. Where any
other document disagrees with this one, this one is right and the other is
stale — the rates here are read from live code, not restated from memory.

**Source of truth in code:** `crates/tenzro-types/src/economics.rs`
(`EconomicPolicy`, `NodeEconomicMode`, `PayeeRole`),
`crates/tenzro-payments/src/revenue_split.rs` (`split_revenue`),
`crates/tenzro-token/src/economic_policy.rs` (the live, governance-set policy).

---

## The economy in brief

Tenzro is an open network for the machine economy. Its economy exists to make
one loop turn by itself: demand from agents and apps pays providers; provider
income draws more machines; more machines improve price, quality and
availability; and that draws more demand. Fees from real use carry the loop.
Rewards help it start and are bounded so they can never pay more than the
work behind them paid.

**Who pays.** Most usage reaches the network through apps whose users do not
care where the AI runs, so the network wins demand only by being cheaper or
better at equal quality. Demand arrives through four channels, on equal terms:

| Channel | How it pays |
|---|---|
| Resellers and platforms | Buy from providers at the providers' prices and sell to developers with their own commission on top, billed off chain on their own terms, or on chain as a line of the payment's split rule |
| Consumer apps | Buy AI for their own products, directly or through a reseller |
| Partners | Pay for their own deployments |
| Direct developers | Call models on the network themselves |

No channel has a protocol privilege: the same fees and rules apply to every
payer. End users pay with what they already use; the app or platform pays the
network.

**Who is paid.** Providers of compute, models, agents and apps, each for its
own part of a request. Provider work is recorded per class when a bonded
provider is paid (`InferenceServed`, `TeeSession`, `RpcTraffic`,
`ComputeLease`, `StorageServed`), and a payer can name the app, agent and tool
behind a payment (`CallAttribution`, signed by the payer, each a registered
identity), so their creators earn the settlement's activity weight and any
governed creator royalty. A hybrid job, in which an edge device orchestrates an
agent and calls a GPU provider for the large model, pays each party directly
from the caller's budget ([AI.md](AI.md#hybrid-jobs-edge-orchestration-and-model-ladders)).

**What the network takes, visibly on chain.**

| Charge | Parameter | Genesis | Bounds |
|---|---|---|---|
| Settlement fee, on the value each on-chain settlement pays out | `fees.settlement_fee_bps` | 10 bps | 0 to 1,000 |
| Share of that fee burned (the rest to the treasury) | `fees.settlement_fee_burn_bps` | 5,000 bps | 0 to 10,000 |
| Treasury leg per class of provider work, from the provider's credit | `fees.treasury_leg_{inference,tee,rpc,compute,storage}_bps` | 0 | 0 to 5,000 |
| Creator royalty, from the treasury part of the fee and leg | `fees.creator_royalty_fee_bps` | 0 | 0 to 9,000 |

The settlement fee is never below the governed USD minimum and never above
the value settled. A treasury leg leaves the buyer's price unchanged. The
genesis values of the legs, like every other rate, are governed parameters:
governance sets them within these bounds by enacted proposal. The full list is
in [GOVERNANCE_PARAMS.md](GOVERNANCE_PARAMS.md).

**Prices in USD terms, a fixed tariff.** Protocol fees are set in micro-USD
and charged in TNZO at the rate in force (below), so they do not drift with
the token. Day to day the tariff is fixed; governance is the lever, acting
within hard bounds and after timelocks, not demand-driven repricing.

**Built against farming.** What one settlement may earn in rewards is bounded
by what it paid outside the trade, its fee plus its treasury leg: provider,
activity and royalty weights together stay at or below 9,000 bps of that cost,
so any group of parties acting together ends each settlement poorer. Payer and
payee that share an identity root earn nothing from it; roots are followed
through agent controllers. Usage a provider's own projects or related parties
bring is real revenue at the normal tariff, earns no extra reward, and is
reported apart from unrelated demand. Nothing pays for holding, volume, sign-ups or
engagement.

**Bootstrapped, then decentralized by governance.** The first operators run the
network until it is stable. It opens as a preview, then a testnet, then the
stages governance decides on the way to mainnet, each started on measured
evidence and an enacted proposal, never on a date. During the preview a new
validator is admitted only by an enacted `ApproveValidators` proposal
(`validator.admission_approval`).

**The node revenue split is separate.** The rest of this document describes,
among other things, how a node divides a service payment it collects between
its operator, an RPC provider and the treasury (section 2). That division is
the node's; the settlement fee and treasury legs above are charged by the chain
on every on-chain settlement.

---


## Funding: Tenzro integrates providers, it does not become one

Tenzro is **not a licensed provider**. Every regulated
function at the fiat boundary — KYC, fiat acceptance, card issuance, network
settlement — is performed by a licensed party that already does it well. What
Tenzro adds is the layer none of them occupy: a portable agent identity with
enforceable delegation, so the *same* agent can be funded through one provider,
spend through another, and settle on-network under one set of ceilings.

This makes the provider list a **registry of integrations, not a shortlist to
pick a winner from**. An operator can integrate a provider Tenzro has never
heard of without a protocol change.

### Funding has a direction, and the two halves are not alternatives

| Direction | What it does | Shape |
|---|---|---|
| `fiat_to_stablecoin` | Fiat arrives and becomes stablecoin the agent can spend | Virtual accounts: a deposit account in the customer's name whose incoming fiat converts to USDC |
| `stablecoin_to_merchant` | The agent spends an existing balance at merchants that never handle stablecoins | Card issuing against stablecoin collateral |

A network with only the first has agents that can be paid but cannot buy; one
with only the second has agents that can buy but cannot be funded. Both halves
are needed, which is why picking "a funding partner" is the wrong question.

### Custody is recorded separately from the provider

Custody decides who can lose the money, and it does not follow from the
provider's name. A custodial orchestrator holds the keys, so the balance is a
claim on the provider and provider failure is user loss. A non-custodial issuer
underwrites against collateral sitting in a contract the customer owns and can
withdraw from at any time. Those are different risks to the same user, and
`user_can_exit_unilaterally()` is the question a delegating human is actually
asking.

### Funding never widens a delegation scope

Both the funding source's own cap and the identity's delegation-scope ceiling
are checked, and **the narrower one binds**. An agent that could not spend an
amount before it was funded still cannot afterwards. Checking only the source
cap would make the on-ramp a hole straight through every control the identity
layer enforces.

### The card networks are integrated at a different layer

Verified against Visa's own newsroom rather than secondary coverage: Visa's
stablecoin settlement program settles with **issuers and acquirers — banks and
fintechs — not with merchants directly**. A merchant sees the effect only
through its acquirer. The program reached nine blockchains in April 2026 at a
~$7B annualised run rate across USDC, EURC, USDG and PYUSD, with Circle's Arc
and Base among the named partners.

That is network settlement one layer *below* anything Tenzro touches — it is how
a card authorisation Tenzro initiated through an issuer eventually settles
between Visa and the acquiring bank. So Visa and Mastercard are integrated where
they actually expose a surface to a party in Tenzro's position: as agent
identity and mandate layers (Trusted Agent Protocol, Agent Pay), both of which
authenticate over RFC 9421 HTTP Message Signatures, with which every Tenzro
agent signs its requests.


## The accounting layer: receipts a third party can check

Tenzro is not only the payment layer for agent activity — it is the **accounting
layer**, and the two are different problems.

An edge gateway can meter a request and take payment for it. Cloudflare, which
ships exactly that over x402, states the limit plainly: *payment proves budget,
not trust*, and audit trails are the developer's problem. So after the money has
moved, nobody can answer — to anybody else — which party consumed what, under
whose authority, and whether the payment that cleared corresponds to the work
that happened. Each side keeps its own log, the logs disagree, and the
disagreement is settled by whoever is more trusted rather than by evidence.

Every interaction on Tenzro therefore produces one `InteractionProvenance`
record binding four things that only mean something together:

1. **Who** — the consuming DID, and the DID it acts for when delegated.
2. **What** — the resource and the units actually consumed.
3. **Under what authority** — the specific delegation, AP2 mandate, x402
   payment or credential that permitted it. A receipt carrying only the access
   tier proves consumption happened, not that it was allowed.
4. **Against which payment** — settled, folded into a channel, accrued below the
   floor, or free.

That last field matters more than it looks. A settlement transaction hash alone
is ambiguous — absent means *either* nothing was charged *or* the charge accrued
into a channel rather than settling on its own. Those are opposite facts to an
auditor. **Accrued** is also precisely the state Cloudflare's proposed deferred
x402 scheme describes and which x402 itself has nowhere to record.

### One record for every kind of interaction

A web fetch, an inference, a storage read and a marketplace invocation are the
same shape: a party consumed a resource under an authority and a charge landed
somewhere. They share one record and one digest. Giving web access its own
receipt type would produce two accounting systems that then have to be
reconciled — the exact problem the unified record removes. `InteractionKind`
now carries `Access` alongside inference, rental, storage, database, hosting,
security, marketplace and RPC brokerage.

### Verification does not require trusting the issuer

The record has a canonical, domain-separated, length-prefixed preimage and a
SHA-256 content address. Every field a counterparty must be able to check is
covered; the payee breakdown and secondary-settlement mirrors deliberately are
not, since those are the serving node's own accounting and change as mirrors
land — binding them would make the digest unstable for facts the consuming party
never agreed to.

Length-prefixing is load-bearing rather than stylistic: without it a record for
subject `"ab"` / resource `"c"` and one for subject `"a"` / resource `"bc"`
concatenate to identical bytes, so a signature over one would validate the
other, letting a resource be swapped without breaking the signature.

A counterparty recomputes the content address from the record it was handed
and compares it to the address it was shown, so the check does not depend on
trusting whoever issued the record: the same digest can be recomputed offline
from the same published rule.


## Parallel settlement: the same settlement on several chains

Tenzro settles on its own ledger and treats every other chain as a **secondary**
layer. A settler may want one book or several, and both are first-class: a plan
with no targets settles only on the Tenzro Ledger, and a plan with targets fans
the same settlement out across them.

### Durability is the whole point

Tenzro opens in phases. A preview or testnet chain can be reset, and moving
to a later phase can renumber or discard chain state. **A settlement mirrored to another chain must
remain meaningful after that happens** — the settler owns that record, not
Tenzro.

That rules out the obvious design. Writing a Tenzro reference to the external
chain produces a record only interpretable by asking Tenzro what the reference
meant; when Tenzro's state is gone, the settler holds a hash of nothing. So each
target declares its durability:

| Durability | What is written | Survives Tenzro losing state |
|---|---|---|
| `self_contained` | The canonical settlement bytes | **Yes** — readable and verifiable with no Tenzro node |
| `digest_only` | The 32-byte commitment | No — proves a payload you already hold matches, cannot say what settled |

Both are legitimate; only one is durable. `durable_beyond_primary` in the
response answers it directly, and it requires **both** a committed primary and
at least one confirmed self-contained mirror — a self-contained mirror of a
settlement that never committed is a record of something that did not happen.

### Mirrors are independent, and partial success is normal

There is no two-phase commit across chains that do not know about each other. A
congested chain, a reorg or a rejected transaction must not roll back a
settlement that already committed elsewhere, so every target is dispatched on
its own and the report says plainly which landed. A failed or pending mirror
never enters the provenance record — listing it would claim a settlement that
does not exist on that chain.

### Every chain the adapters reach

Targets are validated against what this node can actually write to: the
networks it settles on natively **plus** every chain the registered bridge
adapters reach — LayerZero, Chainlink CCIP, Wormhole, deBridge, Li.Fi,
Hyperlane, Axelar, Stargate, IBC Eureka, Hyperbridge and NEAR chain signatures,
which is well over a hundred chains between them.

Both identifier forms are accepted. The adapters route on names (`base`) while
settlement uses CAIP-2 (`eip155:8453`), and a caller does not need to know
which this node happens to hold.

RPC `tenzro_mirrorSettlement` (admin) takes the settlement's interaction record and keeps no copy; it returns the record with its confirmed secondary settlements folded in. With `from`: every mirror is a `Bridge`
transaction that wallet (the payer's or a relayer's, matching the bearer) signs
and pays the gas of; the node's own account never sends one. CLI
`tenzro interaction mirror`; SDK `client.device().mirror_settlement()`; MCP
`mirror_settlement`; A2A `interaction-receipts`; TenzroClaw `mirror_settlement`.


## Fee splits and mirroring: the division happens once

A settlement mirrored onto five chains is **five copies of one settlement, not
five settlements**. This is worth stating because the payload makes it look
otherwise: a self-contained mirror writes the whole record, `payees` and
`amount_charged` included, onto each target chain.

Those fields are a **record of a division that already happened on the Tenzro
Ledger**, not a request for that chain to perform one. The revenue split runs
exactly once, at settlement, before any mirror is dispatched. Nothing in the
mirror path calls it, and three tests enforce that: the mirrored payload is
byte-identical to the settled record, every target carries the same payload,
and a structural guard fails the build if the split is ever called from the
dispatch path.

So a reader of a mirrored record learns who was paid and how much. It does not
learn that it owes anyone anything.

## Multi-VM: what executes versus where it settles

Tenzro executes three VMs — EVM, SVM, and its own native runtime —
and every transaction routes to exactly one of them with no fallthrough. An
agent can settle on the Tenzro Ledger and, in the same breath, record that
settlement on EVM and SVM chains in parallel.

The two vocabularies are deliberately not the same size:

| | Covers |
|---|---|
| `VmType` (3) | What Tenzro **executes**: EVM, SVM, Tenzro native |
| `NetworkFamily` (5) | Where Tenzro **settles**: those three, plus Stellar and XRPL |

Every VM has a settlement family, because a VM that can execute work nobody can
be paid for is not useful. The reverse deliberately does not hold: Stellar and
the XRP Ledger are settlement families with no VM, because Tenzro settles there
through an adapter rather than executing there. A test asserts the first
direction and not the second — asserting a bijection would assert something
false.

**One accounting layer is a first-class choice.** A plan with no mirror targets
settles on the Tenzro Ledger alone and is complete. It is simply reported as not
durable beyond the primary, which is the honest answer rather than a flattering
one.

### Value conservation

The EVM, SVM and native executors all read and write the one native TNZO
balance of an account through the same state adapter, so there is no per-VM
ledger to reconcile: moving TNZO between VM views is a move between two
addresses. Every node holds every block to the same rules
(`tenzro_vm::ledger`):

- **Per transaction.** A successful transaction changes the balances it touched
  by exactly `supply_change − gas_price × gas_used`, where `supply_change` is
  what it declares it burned (zero for everything except slashing). TNZO is
  never minted, so no transaction adds supply.
  A transaction that does anything else is undone and charged gas like any
  failed transaction; its receipt says `value not conserved`.
- **Fees.** Fees collect in a fee pool account as they are paid. At the end of
  the block the governed share of the base-fee part is burned and the rest goes
  to the treasury, from the amounts actually paid.
- **Per block.** Before commit, the net change across every balance the block
  wrote, measured against the values they held before the block, must equal the
  supply change the block recorded. A block that fails is refused and its
  writes discarded.

Total supply and cumulative burn are stored in consensus state and included in
the state root.


## Which rail a payment settles on

Tenzro settles on its own ledger and treats every other chain as a **secondary**
settlement layer. Which secondary layer, for a given payment, is a routing
decision rather than a preference — and getting it wrong is silent, because the
payment still succeeds, it just destroys more value than it moves.

An economy metered per token produces charges spanning six orders of magnitude:
a tenth of a cent for one token, tens of dollars for a video render, thousands
for a month's rental. No single rail is correct across that range.

**Supporting x402 is not the same as being able to carry a micropayment.** Base
speaks x402 fluently and still cannot carry a one-cent charge without roughly
10% overhead. A rail chosen on protocol support alone loses money on every
metered call. So each rail carries an indicative fee floor, and the smallest
worthwhile payment on it is that floor times a ratio — 100 by default, meaning
settlement may cost at most 1% of the payment. The ratio is set against the
split itself: the treasury leg of a public validating node is 10%, so a
settlement cost above that order would dominate the economics the split
describes.

| Rail | CAIP-2 | Family | Carries natively | x402 |
|---|---|---|---|---|
| Tenzro Ledger | `tenzro:<chain-id>`, the chain id the network's genesis sets (`tenzro:13380` on the preview network; see `docs/caip2-namespace/README.md`) | tenzro | TNZO | yes |
| Stellar | `stellar:pubnet` | stellar | USDC, PYUSD, USDY | yes |
| XRP Ledger | `xrpl:0` | xrpl | RLUSD | yes |
| Solana | `solana:5eykt4Us…` | svm | USDC, PYUSD, USDG | yes |
| Base | `eip155:8453` | evm | USDC | yes |
| Plume | `eip155:98866` | evm | pUSD, USDC | no |
| Arbitrum | `eip155:42161` | evm | USDC | no |
| Polygon | `eip155:137` | evm | USDC | no |
| Ethereum | `eip155:1` | evm | USDC, USDT, PYUSD, USDP | no |

Ordered cheapest-first, which is also the order the router scans. Ethereum L1
sits at the bottom deliberately: it is settlement for size, not frequency. It
never wins a micropayment race, and it is chosen explicitly.

Routing returns exactly four answers, and they are kept distinct because they
imply different remedies:

- **Accumulate** — below the governance-set micro-settlement floor. It belongs
  in a payment channel (an escrow plus cumulative vouchers) until it is worth
  settling. The remedy is to open a channel or pay under the x402 `upto` /
  `batch-settlement` scheme.
- **Primary** — settle on the Tenzro Ledger. The default, and what a payee
  holding TNZO always gets.
- **Secondary** — settle on the cheapest rail carrying the payee's declared
  asset.
- **No viable rail** — the charge clears the floor, so it *would* settle, but
  nothing carries the payee's asset at this size. The remedy is to accumulate or
  to accept another asset. Reporting this as an accumulation would tell an
  operator to open a channel when the real fix is the declared asset.

The floor binds before the asset preference. A dust charge does not become
movable because the payee would like it in USDC.

Read the rails with `tenzro_settlementNetworks`; pass `amount_wei` and `asset`
to get the routing decision for a specific charge. CLI: `tenzro rails list` and
`tenzro rails route`.

### Prices are not read from an oracle here

Comparing a TNZO amount against a rail's USD-denominated fee needs a price, and
the router takes it as an argument rather than reading a feed. A caller with no
price gets home-chain settlement — the safe answer — instead of a rail chosen on
an invented number. The fee floors themselves are **indicative ordering hints**,
not quotes: they rank rails against each other and are deliberately not used to
quote a payer, because gas markets move and constants do not.

### The TNZO/USD rate fees are priced at

Gas, identity registration (`fees.identity_register_micro_usd`), verification
(`fees.verify_micro_usd`) and inference settlement
(`fees.inference_settle_micro_usd`) are priced in USD and paid in TNZO at a rate
chain state holds, at the time of use, and burned. Nothing is prepaid: no credit
can be bought at one rate and spent at another, which bounds what a wrong rate
can cost anyone to the fees paid while it stood.

In validator mode (`fees.usd_rate_mode = 1`) each bonded validator seals its
rates for a closed hourly epoch in the following hour (a SHA-256 commitment over
its address, the epoch, a salt and its quotes) and opens them the hour after, in
the same transaction that seals the next epoch. When the opening hour ends, and
if validators holding `fees.usd_rate_quorum_bps` of bonded stake opened, the rate
moves only into the band between the stake-weighted
`fees.usd_rate_quantile_low_bps` and `fees.usd_rate_quantile_high_bps` quantiles
of the opened rates, rising by at most `fees.usd_rate_max_change_bps` an hour
and falling by at most `fees.usd_rate_max_fall_bps` (five times as fast at
genesis: 1% and 5%), so a crash is followed within days while a pump is not. A
group holding a third of the stake or less can neither move the rate nor hold
it, and a group short of two thirds cannot move it; honest agreement moves it
fully. (The thresholds are 6,666 bps, not 6,667: with stake split exactly in
thirds, an honest two thirds suffices.) A group holding more than a third can
slow the rate, which is the price of no smaller group being able to move it.
When the quorum is missed because reports are withheld, the rate stays, but
once `fees.usd_rate_stale_epochs` epochs in a row leave it further than
`fees.usd_rate_stale_gap_bps` from the median of the stake that still opened
(at least `fees.usd_rate_stale_quorum_bps`, never less than a majority), it
moves toward that median at the hourly bounds: withholding freezes the rate for
the window at most, and only stake that reports moves it. Reports outside the
band are never slashed, because under a majority group the honest reporters are
the outliers. Governance can hold the rate (`fees.usd_rate_frozen`) while a
challenge is decided; signed or TLS-proven outside prices are evidence for that
challenge, never an input to the rate. In governance mode the validators'
medians are still recorded and published.

Missing or outvoted reports never leave fees unpriced: fees go on at the last
frozen rate, and the fallback is visible. An epoch whose reports reach too
little stake, or that governance holds, logs `FeeRateHeld` with the reason and
the rate kept. Once no median newer than `fees.usd_rate_max_age_epochs` has set
the rate, `tenzro_getFeeRate` answers `held: true` with the rate's age, whether
or not any report arrives. See
[operations/FEE-RATE.md](operations/FEE-RATE.md).

Payments use the rate in force. Safety checks do not: the security ratio, the
stake-backed bridge caps and the USD floor on bonds value TNZO at the **safety
rate**, the lower of the rate in force and the lowest frozen median of the
last `fees.safety_rate_window_epochs` (24) epochs. A crash shows in the
medians at once, so no check trusts stake or collateral to be worth more than
the market said within the last day, while the rate in force walks down at
its capped speed. `tenzro_getFeeRate` reports both.

New bonds keep their USD value. A new or raised role bond, and a validator
joining the set, must meet each `stake.*` amount raised in proportion when
TNZO trades below `stake.bond_floor_rate_nano_usd` at the safety rate (0.10
USD at genesis): after a 95% fall entering costs twenty times the TNZO, so a
crash does not make Sybil entry cheap. Bonds already in place keep serving
at the TNZO amounts.

Each validator reads the rate from the sources in its `fee_rate_sources`
configuration. Every source names its provider (`name`) and how it is read
(`kind`):

| `kind` | Read from | Accepted when |
|--------|-----------|---------------|
| `json` | an HTTPS endpoint answering JSON (`url`, `pointer`) | the value is a positive decimal |
| `aggregator` | an `AggregatorV3Interface` price feed on an EVM chain (`rpc_url`, `address`) | the round is complete, positive and fresh |
| `data_stream` | the latest signed Data Streams report (schema v3) for `feed_id` from `url`, authenticated with `client_id` and the HMAC secret in the environment variable `secret_env` | at least `threshold` of the configured `oracles` signed it, it has not expired, and it was observed within `max_age_secs` |

Sources that share a provider name count as one source: their rates collapse to
their median before the report is built. A report needs at least two providers,
and the chain refuses one that names fewer, so a validator configured with a
single provider's feeds reports nothing, and no single provider sets the rate on
its own.


## 1. One division, one place

A settled service payment is divided **exactly once**, by `split_revenue`, and
nothing downstream takes a further cut.

The settlement engine's network fee is **zero**. The split is the fee.

**The invariant:** the shares sum to exactly the amount that was charged.
`RevenueSplit::total()` equals the input, always, and
`InteractionProvenance::is_conserved()` re-checks it on the receipt. A sum that
comes up short strands value with no owner; one that comes up long means someone
was paid out of another party's share. Both are caught.

---

## 2. A node's economic mode is derived, never declared

There is no setting an operator can change to be paid more. The mode follows
from two facts the node already knows: whether its visibility announces it to
the network (`public` or `gated`), and whether the node validates.

| Mode                   | Condition                                        | Division                           |
| ---------------------- | ------------------------------------------------ | ---------------------------------- |
| **Private**            | The node's visibility is `private`               | Operator takes 100%                |
| **Public, validating** | Advertised, and the node runs the validator role | Operator + treasury                |
| **Public, delegated**  | Advertised, and the node does _not_ validate     | Operator + RPC provider + treasury |

### Why private keeps the whole payment

A private node is **connected to the network but not advertising itself**. Its
resources are reached as the operator's access policy admits, and the network
can still reach it — signed in, under that policy — but nobody
_discovered_ it. No discovery was consumed and no validator was engaged on the
caller's behalf, so there is no network share to take. Ledger gas is still owed
on any transaction it settles; that is a separate stream and is not a
commission.

Note that a node which does not advertise is private **whether or not it
validates**. Validating earns consensus rewards, which is a different stream,
and does not entitle the network to a share of revenue from callers the network
never introduced.

### Why the delegated mode has a third leg

A node that advertises but does not validate still needs its users' transactions
validated. Some RPC provider does that work, and is owed for it. The difference
between the two public schedules is exactly that leg — the operator is buying
validation it does not perform. The treasury's cut is unchanged either way,
because what the treasury does for the payment (discovery, settlement, the
registry) is the same.

A node in this mode that cannot name its RPC provider is **refused at
settlement**, not defaulted. Paying that share to the treasury because nobody was
configured would pay the wrong party and report nothing wrong. Set it in
`[economics] rpc_provider_payee`, or enable the validator role.

### Default rates

|                    | Operator  | RPC provider | Treasury |
| ------------------ | --------- | ------------ | -------- |
| Private            | 10000 bps | —            | —        |
| Public, validating | 9000 bps  | —            | 1000 bps |
| Public, delegated  | 8000 bps  | 1000 bps     | 1000 bps |

Every one of these is governance-settable (§6). The **operator must always hold
a strict majority** — enforced at construction, not merely documented, and
enforced against governance too. A schedule that gives the serving party half or
less is rejected: at that point the operator is not being paid to serve, they are
splitting with parties that did not do the work.

Rounding dust goes to the operator, the party whose share is least distorted by
it and the one already receiving the residual.

---

### Operator earnings: spot, standby and the availability reward

Besides the price a provider sets for the work it serves, three legs pay an operator for capacity.

- **Spot.** A chat buyer can ask for spot treatment with the `spot` request field. The request is admitted under the batch class, which is shed before it starts once the node's batch reservation is full, so full-price interactive work keeps its capacity; a spot job already admitted is never stopped. The served tokens are billed under the `@spot` tier, priced by the operator's own spot rate-card line, and the response names its tier (`spot` or `standard`). A routed call carries the choice to the remote provider.
- **Standby.** An operator can hold a model warm on standby in a jurisdiction for an hourly fee it advertises. `tenzro_standbyQuote { model_id, jurisdiction }` (CLI `tenzro inference standby-quote`, MCP `standby_quote`, TypeScript SDK) returns the live operators holding that model there, cheapest first, with the account a reservation escrow must pay; the buyer funds a stream escrow to that operator before its session starts. The light build answers standby quotes too.
- **Availability reward.** A provider whose SLA probe returns a verified-available verdict earns a bounded, treasury-funded payment, once per subject and epoch, for every serving role an SLA probe owes (TEE, model, compute, storage and RPC providers, plus wallet and edge stakes). It vests like every other earned reward, decays on a deterministic integer half-life once governance starts the clock, phases out as verified paid demand reaches a governed target, and scales by the readiness tier a subject declares (warm, cool or cold). It pays nothing while `reward.availability_require_hardware_binding` is zero, because nothing then ties a verdict to a real machine; an empty treasury forfeits that epoch's reward rather than refusing the verdict. Its parameters are the `reward.availability_*` entries in [GOVERNANCE_PARAMS.md](GOVERNANCE_PARAMS.md).

A provider's hardware security level adds a small, capped bonus to its provider reward share; it never admits or excludes anyone. The chain derives it at every reward epoch close from attestation evidence in state: level 0 is no hardware proof; level 1 a machine identity whose manufacturer-certified TPM proved this epoch it still holds it; level 2 the same TPM holding the identity's enrolled ML-DSA key; level 3 a restricted TPM ML-DSA attestation key, or an NVIDIA GPU proven beside the TPM in the same epoch. See [Hardware levels](GOVERNANCE_PARAMS.md#hardware-levels).

## 3. Three ways to use a node

The distinction is economic before it is technical, so each is nameable at
settlement time. The operator is the admin: they issue every credential below,
write its policy and scope, and can revoke it.

| Tier           | Credential            | Pays                             | Gets                                              |
| -------------- | --------------------- | -------------------------------- | ------------------------------------------------- |
| **User**       | none — payment itself | per request, on demand           | whatever the node serves publicly                 |
| **Subscriber** | access token          | a subscription the operator sets | scoped resources on the node                      |
| **Renter**     | rental                | locked or prepaid up front       | raw capacity — compute, storage, memory, security |

**A user** is anyone on the network paying to use resources on it, with no prior
relationship — a human, an agent, or a machine. Each holds its own identity and
its own wallet, so each pays for itself.

**A subscriber** buys access to resources the node _serves_ — inference on a
model, queries against a database, objects in storage — under a scope the
operator wrote, reached with an access token for a DID the operator's access
policy names.

**A renter** buys the raw capacity itself, having locked funds in escrow or
prepaid for a term, bounded by that term. The node
hands over use of the hardware rather than answers from it.

Only a user is charged at serve time. The other two settled up front. **Metering
still runs for all three** — an operator who cannot see what a prepaid tenant
consumed cannot price the next term.

Types: `crates/tenzro-types/src/access_tier.rs`.

### RPC providers bill their own tenants

An RPC provider selling access to **external networks they broker** — chains
beyond Tenzro — does so on their own terms, the way every other
chain's RPC operators do. That revenue is theirs and never enters a node's
revenue split (`RpcServiceGrant`).

This is a different thing from the RPC-provider leg in §2, which pays for
_validation performed on a serving node's behalf_. Charging in both places for
the same relationship would be charging twice for two different things and
calling it one.

---

## 4. Settlement: Tenzro first, other layers optionally alongside

**Every charge settles on the Tenzro Ledger.** That is the settlement layer.

Some charges are _also_ mirrored onto a ledger a counterparty treats as their
system of record — an EVM or SVM chain holding a token leg, a bridge carrying a cross-chain transfer.
Those are mirrors of a settlement that already happened, never the settlement
itself. `InteractionProvenance` records this as a single `settlement_tx` (the
Tenzro anchor) plus a list of `secondary_settlements`, and a mirror never
changes what was charged or what the legs total.

`InboundRail` separately records where a payment _originated_ — natively in
TNZO, over HTTP 402 under an x402 scheme, bridged from a secondary chain, or
drawn against a standing mandate an agent held.

### Asset

The network takes **TNZO by default** (`ConversionPolicy::ConvertToTnzo`): it is
the unit the ledger accounts in, and a treasury holding forty stablecoins is a
treasury nobody can value. A payee may declare otherwise and keep the inbound
asset rather than take conversion risk on every microtransaction. The default
itself is governance-settable.

---

## 5. Provenance

Identity and wallet are the two coordinates that make an interaction
attributable: the DID says _who or what_, the wallet says _where value moved_.
`InteractionProvenance` (`crates/tenzro-types/src/provenance.rs`) binds them to
the rest of the answer — **what** was used, **when**, **how** it was reached, and
**how much** was paid — and is emitted on every metered interaction, including
the ones that move no money on that call.

It records what happened, not what was intended: `amount_charged` is what
actually moved and `payees` is where it actually went, not the rate card that
was quoted. A receipt that echoes intent rather than outcome is precisely how a
split that double-charged went unnoticed.

---

## 6. Governance sets every rate

`EconomicPolicy` is one block holding every rate the network charges. It is
persisted (`CF_TOKENS / economic_policy:current`), hydrated on boot, and changed
only by governance proposal.

- **Propose:** `tenzro governance propose --type economic_policy --policy-json '<policy>'`
- **Read:** `tenzro governance economic-policy`, or the `tenzro_getEconomicPolicy` RPC
- **Executor:** `ProposalType::EconomicPolicyUpdate` → `EconomicPolicyManager::apply`

The whole policy travels in one proposal rather than a field at a time: a change
that moved one leg without the others would not sum to a whole payment.

A proposal is validated **before** it is stored, and again before anyone votes on
it. A rejected policy leaves the previous one live. Governance can move the
numbers; it cannot make them incoherent.

No rate has a `const` twin anywhere in the workspace. A rate living in a constant
has to be found and changed in a release, and every node that has not upgraded
keeps charging the old one — so the network disagrees with itself about what a
payment is worth, invisibly, until someone reconciles two receipts.

---

## 7. The treasury

The treasury account is **derived, not configured**: `SHA-256("tenzro/treasury")`.
Every replica computes the same 32 bytes, so a share credited on one node lands
at the same account as one credited on another. There is no genesis field and
nothing an operator can point at their own wallet. No private key exists for
those bytes. It is the one treasury account: settlement shares, the fee share
each block settles, and native governance treasury grants all use it.

Only an enacted governance proposal moves treasury funds: a grant, a tranche
or a recovery, each after its voting period and
timelock. Tenzro Foundation holds steward seats that can veto or hold a
treasury proposal inside that timelock but never spend; the seats end at the
governed sunset. There is no withdrawal key, administrator or multisig.

### Treasury policy

The chain bounds what the treasury may pay: at most 2% of its balance per
proposal and 3% in any thirty days (`treasury.max_proposal_outflow_bps`,
`treasury.max_period_outflow_bps`, `treasury.outflow_period_ms`). Grants
and recoveries drawn from the treasury all count. Any
payment out of the treasury or the running-cost reserve, however small, needs
yes votes of three quarters of all eligible stake
(`governance.large_spend_approval_bps`), more than the two thirds that orders
blocks, so validators who vote while others stay away cannot pay themselves.
One of 100,000 TNZO or more (`governance.large_spend_tnzo`) also waits
fourteen days of timelock. A change that loosens any of these guards,
or the reserve's spending limits, moves at most one step (double or half) per
proposal and applies only after `governance.guard_loosening_grace_epochs`
(ninety days). Stake that captures a vote therefore takes out at most what
the guards in force allow for ninety days while every holder sees the change
coming; the economic simulator checks that this stays below what buying that
stake costs, at every pool depth it tests. The insurance pool pays only
claims that prove a loss and cannot be spent by a vote.

The same rule holds for the values a buyer of cheap stake after a price
crash would loosen first: the vote's quorum and thresholds, the pool's
release schedule (its base, floor, decay and controller range), validator pay (the base
cost, its TNZO cap and its share of the burn), slashing (the equivocation
minimum, the correlation multiplier and window, the bridge committee's, the
catalog fault and the settlement attestor slashes) and unbonding, and the
fee rate's move cap and quorum. Loosening one moves one step and waits the
same ninety days; tightening one, or cutting the pool's release, applies as before.
A step is measured from the stricter of the value in force and the value
already scheduled, so proposals queued back to back move a guard one step
per grace, not one step each.

No funding amount is fixed anywhere. The treasury and its running-cost
reserve may both start at zero, and the network runs the same way whether
they hold nothing or a great deal: validators and providers are paid by
protocol rewards and fees, not by the treasury. Running costs are paid from
the **running-cost reserve**, a keyless vault beside the treasury, under
rules every node applies at each epoch boundary from chain state and
governed parameters (`crates/tenzro-vm/src/native/treasury_reserve.rs`):

- **Filling.** `treasury.reserve_fill_share_bps` of the fee revenue the
  treasury realized since the last boundary moves into the reserve, while
  the reserve is under its target and only as far as the target.
- **Target.** `treasury.reserve_target_months` months of observed running
  cost: the larger of what the reserve paid over the trailing month
  (`treasury.month_epochs`) and what that month's revenue allowed it to pay.
  The target is never a fiat figure; it grows and shrinks with the network.
- **Spending.** A `running_cost_payment` proposal, once enacted, joins a
  queue that is paid in order at epoch boundaries. Over any trailing month
  the reserve pays at most `treasury.running_cost_revenue_share_bps` of the
  month's realized fee revenue plus `treasury.reserve_drawdown_bps` of its
  own balance, and never more than it holds. A payment the caps do not yet
  cover waits in the queue for `treasury.payment_ttl_epochs`; what is still
  unpaid then lapses, so a payment sized at one price is never paid out at a
  much later one.
- **Selling.** One epoch pays out at most `treasury.sale_volume_share_bps` of
  the TNZO the market traded in an epoch, as the validators' sealed volume
  reports observe it (symbol `TNZOVOL`, reported with their rates, through
  the same sources, quorum and band). Each epoch's report counts at the
  lower of its frozen median and the banded value, and the cap takes the
  lowest report of the last `treasury.volume_window_epochs` market epochs,
  so a reported rise takes effect slowly and a fall at once, and a sale is
  never sized from a busier market than the recent past has shown; with no
  report from the last `treasury.volume_max_age_epochs` epochs the reserve
  sells nothing. Whatever the reports say, one epoch pays out at most
  `treasury.max_sale_tnzo_epoch` (10,000 TNZO at genesis): most reported
  volume on unregulated venues can be wash trading, and a washed report
  cannot lift the sale past this ceiling. Raising it is a capture guard:
  one step, then the ninety-day grace. The chain bounds what it releases;
  it cannot see the next day's market. Whoever is paid sells within a participation rule of
  its own, at most that share of the volume the market trades while it
  sells, carrying the rest forward. The simulator's paid desk does this,
  and its sales stay within the share on every day of every run. The treasury never sells into a market
  it cannot see.

An empty reserve, an empty treasury, a month without revenue or a market
without volume pays nothing and waits: nothing is refused, no balance goes
negative and no block is held up. Every one of these values is a governed
parameter, changed only by an enacted `parameter_change` proposal that
applies at an epoch boundary on every node at the same block; a node's own
configuration cannot set them (a node configuration that names one is
refused at start). `tenzro_getNetworkParams` lists them with the reserve's
balance, last boundary and queue.

Grants are budgeted in USD but capped in TNZO and at a share of the treasury
a month, so a falling price cuts what a grant is worth rather than how fast
the treasury empties; an empty treasury grants nothing.

The economic simulator's `treasury` study runs this from a zero and a tiny
reserve seed with an empty treasury, no raised funds and a thin pool, across
low, medium and high adoption, a revenue drought and a 90% price crash, and
reports the share of asked running costs paid, when the reserve first held
its target, its sales as a share of traded volume, and any rule broken. Its
results hold only for the span and inputs it ran.

---

### Circuit breakers

Every economic path that pays out has a breaker that stops it before a bad input moves value, each set by governance and listed in [GOVERNANCE_PARAMS.md](GOVERNANCE_PARAMS.md):

- **Settlement asset peg.** A settlement asset whose frozen rate sits outside its par band for `settlement_asset.breaker_suspend_epochs` epochs in a row is suspended: it settles nothing and pays nothing out. It settles again only after its rate holds inside the tighter `settlement_asset.breaker_resume_band_bps` band for `settlement_asset.breaker_resume_epochs` epochs, so a rate at the edge cannot switch it on and off.
- **Fee rate.** An epoch whose validator rate reports spread wider than `fees.usd_rate_breaker_spread_bps`, or whose median strays more than `fees.usd_rate_breaker_gap_bps` from the governance rate, holds the rate instead of moving it. After `fees.usd_rate_breaker_epochs` such epochs in a row, the TNZO rate falls back to the governance rate. See [operations/FEE-RATE.md](operations/FEE-RATE.md).
- **Treasury exposure and payout swaps.** Payout swaps from the treasury's stable holdings are collected through the epoch and filled pro-rata under `fees.payout_swap_max_units_epoch`; a swap that would take any asset past its `max_exposure_bps` share of the treasury does not run, and the unfilled part is carried for `fees.payout_swap_carry_epochs` before it is paid in the asset it arrived in.
- **Running-cost reserve.** Treasury grants and tranche releases are refused while the reserve is under `treasury.grant_reserve_floor_bps` of its target; running costs are still paid, within the per-epoch and per-month ceilings.
- **Insurance.** All claims together pay at most `insurance.max_paid_tnzo_epoch` TNZO in one epoch, whatever rate their USD losses were priced at, and one claim at most `insurance.max_claim_tnzo`.
- **Availability reward.** It pays nothing until hardware binding is on, and an empty treasury forfeits an epoch's reward.

## 8. Machine identity

Economics rests on knowing which machine is being paid, so the identity rules
belong here too.

**A machine identity must be answerable to something other than itself.** Either
a human (or institution) delegated it and remains accountable, or a hardware root
of trust that can _prove which machine it is_ stands in their place. There is no
third option, and a machine that can satisfy neither is refused before a record
exists. An identity nobody can be held to is the one thing a machine must not be
able to mint for itself.

Agents are delegated the same way — from a human, or from the machine that owns
them.

### Identity roots in the chipset and processor, not the GPU

An accelerator is the most-swapped component in a machine: cards move between
chassis, get resold, are replaced on failure, and partition (MIG, SR-IOV) so one
device presents several identifiers. Rooting identity in one means the identity
follows the card rather than the machine, and a node that loses a GPU loses the
ability to prove it is itself. **GPU serials and UUIDs are not identity sources.**

`crates/tenzro-types/src/machine_id.rs` grades every source, because they are not
equivalent:

| Grade          | Meaning                                     | Examples                                                                                                                                                                                                                                                              |
| -------------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Attestable** | A per-unit secret that can prove possession | TPM 2.0 EK / IDevID, TCM/TPCM (SM2/SM3/SM4), Apple Secure Enclave, AMD SEV-SNP `CHIP_ID`/VCEK, Intel SGX/TDX PPID, Qualcomm QFPROM/StrongBox, ATECC608, NXP SE050, ESP32 DS/ECDSA + HUK, Raspberry Pi device unique secret, HiSilicon/Kunpeng, Hygon secure processor |
| **Fused**      | Per-unit, readable, not a secret            | Intel PPIN, AMD PPIN, Apple ECID, Allwinner SID, Rockchip OTP, MediaTek eFuse, Raspberry Pi serial, Renesas RA unique ID, SMBIOS UUID / board serial                                                                                                                  |
| **Model**      | Identifies a design, not a unit             | Arm `MIDR_EL1`, x86 CPUID family/model/stepping                                                                                                                                                                                                                       |

A readable identifier tells you which machine _claims_ to be talking. An
attestable one tells you that claim is true. Only an attestable source can anchor
a machine that no human delegated — a fused serial is readable by anything on the
machine and claimable by anything anywhere.

`MIDR_EL1` is modelled explicitly so it can never be mistaken for a serial: every
chip of that core design returns the same value, and a fingerprint built from it
is identical across every machine of that SKU.

Only the SHA-256 digest of a value is ever carried, never the value: a fused
serial is a stable cross-service correlator, and publishing one would let anyone
track the same machine across every network it joins.

---

## 9. What is metered

Tenzro serves far more than language models, and the meter reflects that.
`BillableUnits` spans every modality in one type — text tokens (prompt,
completion, cached read, cached write), reasoning loops, image tokens derived
from geometry, audio and video milliseconds, denoising pixel-steps, frames,
characters spoken, audio produced, reranked pairs and forecast points.
LLM tokens are one unit type among many; vision, image, video, world models,
timeseries, embeddings, segmentation and detection all meter through the same
structure and settle through the same split.

Frames are charged only when `pixel_steps` is zero, so a generative video call is
not billed twice for the same work.

Three modalities bill on their own unit rather than on tokens. An embedding
bills per input token. A reranker bills per (query, document) pair scored. A
forecast bills per point: one series at one horizon step, with every quantile
requested at that step included, so the context read and the number of
quantile bands never change the charge.

## 10. The reference agent-to-compute payment flow

An agent paying for inference cannot know what the call will cost before it
runs: the token count, the audio seconds and the pixel-steps are only known
once the work is done. The flow that prices this honestly has four steps.

1. **Discover.** Read `tenzro_computePriceFeed` (MCP `compute_price_feed`) for
   observed price per 1k output tokens, latency and success rate per provider
   and model. These are validator observations, not provider claims.
2. **Authorize a ceiling.** An AI node answers an unpaid request with HTTP 402
   and an x402 challenge under the `upto` scheme. The amount in that challenge
   is a *ceiling*. The agent signs that maximum (`extra.upto_max`), not a
   guess at the price.
3. **Serve.** The node checks the signed ceiling and the payer's delegation
   scope and spending policy against it, then runs the call. It meters the
   work and reports the cost in the response as `cost_wei`.
4. **Settle the actual.** The gate settles `min(cost_wei, upto_max)` after the
   response, with a usage record the node's meter key signs for that charge,
   and returns the receipt in `PAYMENT-RESPONSE`. A streamed response passes
   through unchanged and settles when it ends, or when the client disconnects,
   at the last `cost_wei` it reported. A failed response is not charged. One
   credential pays for one request at a time: a second concurrent request
   presenting it is refused while the first is being served.

This is the default (`payments.metered_settlement = true`). It applies to
TNZO-priced challenges, because `cost_wei` is denominated in TNZO. A response
that reports no cost, such as a stream whose client did not ask for usage,
settles at the amount the agent declared in its credential. An operator who
sets `metered_settlement = false` gets that behavior for every request: the
declared amount, settled before the call runs.

A call below the network's micro-settlement floor does not settle on its own
at all: open a micropayment channel and let per-call charges accrue (see
"Which rail a payment settles on").
