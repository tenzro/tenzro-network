# Tenzro Network Economics

The canonical description of who pays, who is paid, and how much. Where any
other document disagrees with this one, this one is right and the other is
stale — the rates here are read from live code, not restated from memory.

**Source of truth in code:** `crates/tenzro-types/src/economics.rs`
(`EconomicPolicy`, `NodeEconomicMode`, `PayeeRole`),
`crates/tenzro-payments/src/revenue_split.rs` (`split_revenue`),
`crates/tenzro-token/src/economic_policy.rs` (the live, governance-set policy).

---

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
