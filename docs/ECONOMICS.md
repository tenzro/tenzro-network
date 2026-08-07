# Tenzro Network Economics

The canonical description of who pays, who is paid, and how much. Where any
other document disagrees with this one, this one is right and the other is
stale — the rates here are read from live code, not restated from memory.

**Source of truth in code:** `crates/tenzro-types/src/economics.rs`
(`EconomicPolicy`, `NodeEconomicMode`, `PayeeRole`),
`crates/tenzro-payments/src/revenue_split.rs` (`split_revenue`),
`crates/tenzro-token/src/economic_policy.rs` (the live, governance-set policy).

---


## Funding: Tenzro integrates providers, it does not become one

Tenzro is **not a licensed provider and does not aim to be**. Every regulated
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
~$7B annualised run rate across USDC, EURC, USDG and PYUSD, with Circle's Arc,
Base and **Canton** among the named partners.

That is network settlement one layer *below* anything Tenzro touches — it is how
a card authorisation Tenzro initiated through an issuer eventually settles
between Visa and the acquiring bank. So Visa and Mastercard are integrated where
they actually expose a surface to a party in Tenzro's position: as agent
identity and mandate layers (Trusted Agent Protocol, Agent Pay), both of which
authenticate over Web Bot Auth, which Tenzro now speaks.


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

### Verification does not require trusting the verifier

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

`tenzro_verifyInteraction` compares content addresses rather than checking a
signature against the node's key, so the answer does not depend on trusting the
node that answers — a caller can recompute the same digest offline from the same
published rule and reach the same conclusion.

| RPC | Gate | Purpose |
|---|---|---|
| `tenzro_recordInteraction` | admin | Anchor a record. Admin because the node is the *attester*: an open endpoint would let anyone forge receipts in the operator's name |
| `tenzro_getInteraction` | open | Read a record and its digest. A receipt only the issuer can read is not a receipt |
| `tenzro_verifyInteraction` | open | Check a receipt against what was anchored |

CLI `tenzro interaction {get,verify}`; SDK `client.device().get_interaction()` /
`verify_interaction()`; MCP `get_interaction`; A2A `interaction-receipts` skill;
TenzroClaw `get_interaction` / `verify_interaction`.

Re-anchoring the same id is permitted and reported: a record legitimately gains
fields as a charge moves from accrued to settled, and the digest changes when it
does. Both remain checkable against whatever was anchored at the time.


## Parallel settlement: the same settlement on several chains

Tenzro settles on its own ledger and treats every other chain as a **secondary**
layer. A settler may want one book or several, and both are first-class: a plan
with no targets settles only on the Tenzro Ledger, and a plan with targets fans
the same settlement out across them.

### Durability is the whole point

Tenzro is on testnet. A testnet can be reset, and a mainnet migration can
renumber or discard chain state. **A settlement mirrored to another chain must
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
Hyperlane, Axelar, Stargate, IBC Eureka, Hyperbridge, NEAR chain signatures and
Canton, which is well over a hundred chains between them.

Both identifier forms are accepted. The adapters route on names (`base`) while
settlement uses CAIP-2 (`eip155:8453`), and a caller should not have to know
which this node happens to hold.

RPC `tenzro_mirrorSettlement` (admin — mirroring spends gas on every target and
publishes this node's attestation under its own name). CLI
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

Tenzro executes four VMs — EVM, SVM, DAML/Canton, and its own native runtime —
and every transaction routes to exactly one of them with no fallthrough. An
agent can settle on the Tenzro Ledger and, in the same breath, record that
settlement on EVM, SVM and Canton in parallel.

The two vocabularies are deliberately not the same size:

| | Covers |
|---|---|
| `VmType` (4) | What Tenzro **executes**: EVM, SVM, DAML, Tenzro native |
| `NetworkFamily` (6) | Where Tenzro **settles**: those four, plus Stellar and XRPL |

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
| Tenzro Ledger | `tenzro:1337` | tenzro | TNZO | yes |
| Stellar | `stellar:pubnet` | stellar | USDC, PYUSD, USDY | yes |
| XRP Ledger | `xrpl:0` | xrpl | RLUSD | yes |
| Solana | `solana:5eykt4Us…` | svm | USDC, PYUSD, USDG | yes |
| Base | `eip155:8453` | evm | USDC | yes |
| Plume | `eip155:98866` | evm | pUSD, USDC | no |
| Arbitrum | `eip155:42161` | evm | USDC | no |
| Polygon | `eip155:137` | evm | USDC | no |
| Canton | `canton:global` | canton | USDC | no |
| Ethereum | `eip155:1` | evm | USDC, USDT, PYUSD, USDP | no |

Ordered cheapest-first, which is also the order the router scans. Canton and
Ethereum L1 sit at the bottom deliberately: Canton is institutional
delivery-versus-payment and Ethereum is settlement for size, not frequency.
Neither should ever win a micropayment race, and both are chosen explicitly.

Routing returns exactly four answers, and they are kept distinct because they
imply different remedies:

- **Accumulate** — below the governance-set micro-settlement floor. It belongs
  in a micropayment channel until it is worth settling. The remedy is to open a
  channel or pay under the x402 `upto` / `batch-settlement` scheme.
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


## 1. One division, one place

A settled service payment is divided **exactly once**, by `split_revenue`, and
nothing downstream takes a further cut.

This is worth stating plainly because it was not previously true. Four call
sites each carved their own percentage — a revenue split, a settlement-engine
network fee, a commission-rate table, and a marketplace constant — and on
`tenzro_settle` two of them stacked: the split took the network's share, then
the settlement engine took another 0.5% of what was left. The basis points
reported on the receipt described a division that had not happened, and the
operator quietly absorbed the difference.

The settlement engine's network fee is now **zero**. The split is the fee.

**The invariant:** the shares sum to exactly the amount that was charged.
`RevenueSplit::total()` equals the input, always, and
`InteractionProvenance::is_conserved()` re-checks it on the receipt. A sum that
comes up short strands value with no owner; one that comes up long means someone
was paid out of another party's share. Both are caught.

---

## 2. A node's economic mode is derived, never declared

There is no setting an operator can change to be paid more. The mode follows
from two facts the node already knows: whether the capability that served the
request is advertised to the network, and whether the node validates.

| Mode                   | Condition                                        | Division                           |
| ---------------------- | ------------------------------------------------ | ---------------------------------- |
| **Private**            | The serving capability is not advertised         | Operator takes 100%                |
| **Public, validating** | Advertised, and the node runs the validator role | Operator + treasury                |
| **Public, delegated**  | Advertised, and the node does _not_ validate     | Operator + RPC provider + treasury |

### Why private keeps the whole payment

A private node is **connected to the network but not advertising itself**. Its
resources are reached through API keys and service keys the operator issues, and
the network can still reach it — through those credentials — but nobody
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

## 3. Three ways to use a node

The distinction is economic before it is technical, so each is nameable at
settlement time. The operator is the admin: they issue every credential below,
write its policy and scope, and can revoke it.

| Tier           | Credential            | Pays                             | Gets                                              |
| -------------- | --------------------- | -------------------------------- | ------------------------------------------------- |
| **User**       | none — payment itself | per request, on demand           | whatever the node serves publicly                 |
| **Subscriber** | API key               | a subscription the operator sets | scoped resources on the node                      |
| **Renter**     | service key           | locked or prepaid up front       | raw capacity — compute, storage, memory, security |

**A user** is anyone on the network paying to use resources on it, with no prior
relationship — a human, an agent, or a machine. Each holds its own identity and
its own wallet, so each pays for itself.

**A subscriber** buys access to resources the node _serves_ — inference on a
model, queries against a database, objects in storage — under a scope the
operator wrote, reached with an API key.

**A renter** buys the raw capacity itself, having locked funds in escrow or
prepaid for a term, reached with a service key bounded by that term. The node
hands over confined use of the hardware rather than answers from it.

Only a user is charged at serve time. The other two settled up front. **Metering
still runs for all three** — an operator who cannot see what a prepaid tenant
consumed cannot price the next term.

Types: `crates/tenzro-types/src/access_tier.rs`.

### RPC providers bill their own tenants

An RPC provider selling access to **external networks they broker** — Canton,
and other chains beyond Tenzro — does so on their own terms, the way every other
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
system of record — a Canton participant holding an enterprise obligation, an EVM
or SVM chain holding a token leg, a bridge carrying a cross-chain transfer.
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
those bytes.

During the testnet phases the treasury is **administered by Tenzro Labs** through
the authorised-withdrawer path. **The Tenzro Treasury will be permissionless.**
Because the payee address is supplied by configuration rather than fixed in
code, that handover is a configuration change with no code motion and no
redeployment.

---

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
from geometry, audio and video milliseconds, denoising pixel-steps, and frames.
LLM tokens are one unit type among many; vision, image, video, world models,
timeseries, embeddings, segmentation and detection all meter through the same
structure and settle through the same split.

Frames are charged only when `pixel_steps` is zero, so a generative video call is
not billed twice for the same work.
