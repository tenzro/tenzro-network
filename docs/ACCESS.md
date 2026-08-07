# Access model — subscribers, renters, and users

Tenzro has three ways a caller reaches a node. The distinction is **economic
before it is technical** — each pays differently, so each has to be nameable at
settlement time — and keeping them separate is what lets a node be private about
its machine while still serving models to the network.

| Tier               | Credential      | Pays                            | What they get                                                    | Scope lives on                                                              |
| ------------------ | --------------- | ------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **User**           | none — payment  | per request, on demand          | whatever the node serves publicly                                | The model's own price and the settlement path                               |
| **Subscriber**     | API key         | a subscription the operator sets | scoped access to resources the node **serves**                   | `ApiKeyRecord.scopes`, class, tier ceiling                                  |
| **Renter**         | service key     | locked or prepaid up front      | the **raw capacity itself** — compute, storage, memory, security | `ServiceKeyGrant` (reachability) + `AccessLease` / `AccessScope` (capacity) |

Types: `crates/tenzro-types/src/access_tier.rs`
(`AccessTier`, `CredentialKind`, `PayerKind`, `RentableResource`,
`RentalFunding`).

**A user** is anyone on the network paying to use resources on it, with no prior
relationship — a human, an agent, or a machine. Each holds its own identity and
its own wallet, so each pays for itself rather than borrowing another's
credential.

**A subscriber** buys access to resources the node *serves*: inference on a
model, queries against a database, objects in storage — answers produced with
the hardware, under a scope the operator wrote.

**A renter** buys the capacity itself, having locked funds in escrow or prepaid
for a term. The node hands over confined use of the hardware rather than answers
from it. That is why the credentials differ rather than being one credential
with a flag: an API key names scopes on services, a service key names a lease
over a machine and is bounded by that lease's term.

Only a user is charged at serve time — the other two settled up front. **Metering
runs for all three regardless**: an operator who cannot see what a prepaid tenant
consumed cannot price the next term.

## Private is about discovery, not access

A **private node** is connected to the network but does not advertise itself.
The network can still reach it — through the API keys and service keys its
operator issues — but nobody browsing discovery finds it. Because no discovery
was consumed and no validator was engaged on the caller's behalf, a private
node keeps the whole payment; see [ECONOMICS.md](ECONOMICS.md).

Privacy reduces the set of people who know you exist. It does not authenticate
the ones who do.

The rule that ties them together:

> A credential for the **machine** never decides what the **network** may be
> served. A model's own visibility decides that.

## The operator is the admin

The node operator is the admin of their node and makes **every** gating
decision on it: issuing and revoking service keys, issuing and revoking API
keys, opening and revoking rental leases, and setting each model's visibility.

That authority is the operator's admin token, and it is enforced rather than
assumed — `tenzro_addServiceKey` / `tenzro_revokeServiceKey`, the API-key
create/revoke RPCs, and `tenzro_openAccessLease` / `tenzro_revokeAccessLease`
are all admin-token gated, with tests (`service_key_rpcs_are_admin_gated`,
`lease_management_is_admin_gated`) asserting it on the live dispatch path.

Two consequences worth stating plainly:

- The admin token is admitted as a service key, but **only once some other key
  has turned the gate on**. Otherwise merely setting `TENZRO_ADMIN_TOKEN` would
  silently gate a node whose operator never asked for a gate.
- An operator who gates their node is never locked out of it by their own
  setting. The remedy would otherwise be editing config and restarting — at
  the exact moment they are trying to revoke a leaked key.

## Renters — service keys over the machine

A service key is a **rental credential**. It buys access to raw resources —
a confined shell, storage, memory, compute — for a period, up to a capacity.

Every accepted key carries a `ServiceKeyGrant`:

- `surfaces` — which service surfaces it admits on. `None` means all.
- `expires_at_ms` — when the rental ends. `None` never expires.
- `lease_id` — the `AccessLease` it was minted for, when it came from one.

Capacity is deliberately _not_ duplicated onto the grant. Devices, workspace,
network reachability, session ceiling and reserved inference slots live on
`AccessScope`, because that is where they are enforced; two homes for one
number means two answers to one question.

A grant is refused for two distinguishable reasons — expired, or not scoped to
this surface — because they are different operator mistakes with different
remedies: one reopens a lapsed rental, the other widens a grant that was
narrowed on purpose.

### One registry, not two

There used to be two unrelated things called a "service key":

- the scoped, expiring, lease-bound credential in `remote_access`, and
- a flat set of bare digests in the admission gate, with no scope, no expiry
  and no subject, which gated all four service surfaces at once.

An operator holding a key could not tell which one it was. Worse, the unscoped
door ended up standing in front of model serving, so a node that gated itself
for any reason silently stopped being able to serve the network — a posture
nobody chose.

They are now one registry. A bare digest in `node.toml` or
`TENZRO_SERVICE_KEYS` becomes an unrestricted grant, so existing configuration
keeps working exactly as before; narrowing is opt-in.

### What service keys never gate

- **Consensus and P2P.** A gated node still validates, votes and gossips. This
  is structural: `ServiceSurface` has no consensus variant, so the question
  cannot be asked. A node that stopped validating because its operator
  restricted who may call its inference API would be withholding something it
  is staked to provide.
- **Liveness probes.** `/health`, `/ready` and the `/verify/*` aliases are
  never gated. Orchestrators cannot present credentials, and a gate that makes
  a node look dead to its own supervisor causes an outage rather than
  preventing one.
- **Model serving.** See below.

## Subscribers — API keys over the node's services

An `ApiKeyRecord` carries granted `scopes`, a `KeyClass`, an optional subject
DID, a tier ceiling with a rolling rate budget, and any Canton bindings. This
is the credential for a caller the operator has a _relationship_ with: the
terms were agreed before the first call.

Tiers bound a key's budget over a sliding 60-second window — `free` at 60
requests/min with writes refused, `standard` at 600, `priority` at 6,000. Over
budget returns `-32005` with `retry_after_ms`.

A key's holder can read its own entitlements (`listMine`), so a tenant can
answer "what may I do here" without asking the operator.

### Direct node access vs. operator-operated external networks

The distinction that matters: **one tier is direct access to the node itself;
the other is access to external networks the operator operates.** They are
different systems and should never be reasoned about as one.

An API key does both jobs, and only the first is affected by anything described
here.

1. **Scopes on this node's own resources** — what the holder may call.
2. **Authorization for upstream networks the operator brokers** — Canton
   synchronizers and equivalents that the operator runs, pays for, or holds
   credentials to.

The second is a pre-existing system and is unchanged. A key carries
`canton_networks` (the set it may reach; a key naming none reaches no ledger)
and an optional `canton_user_id` binding it to a party, plus a tier bounding
its budget over a sliding 60-second window — `free` at 60 requests/min with
writes refused, `standard` at 600, `priority` at 6,000. A key authorizing more
than one network and given no pin returns `-32004` naming the authorized set;
over budget returns `-32005` with `retry_after_ms`.

This is the operator brokering access to something _upstream of the node_. It
is not the node's service-key gate, and it is not model visibility. Three
different questions:

|                               | Gates what                               | Set by               |
| ----------------------------- | ---------------------------------------- | -------------------- |
| Service key                   | this machine's raw resources             | operator, per rental |
| Model visibility              | who may call a given model               | operator, per model  |
| API-key network authorization | which upstream networks a tenant reaches | operator, per key    |

Publishing a model at `network` visibility does not grant anyone Canton access,
and holding a Canton-authorized API key does not make a private model callable.

## Users — payment on demand, no relationship

x402 / TNZO settlement. The caller pays per call. There is no key to issue and
nothing to agree in advance, which is the only thing that works for a peer that
just discovered an offer over gossip and has no way to obtain a credential.

## Model serving answers to the model, not the machine

Which callers may invoke a model is a property of the **model**, expressed by
`ModelVisibility`:

| Visibility | Announced?                                                | Who may call it                                                 |
| ---------- | --------------------------------------------------------- | --------------------------------------------------------------- |
| `Network`  | Yes — gossiped on `tenzro/models`, in provider heartbeats | **Anyone, by paying.** No service key, no prior relationship    |
| `Gated`    | No                                                        | Callers holding an API key whose policy the operator pre-agreed |
| `Private`  | No                                                        | Callers of this node only; never served off-node                |

`Gated` is servable but deliberately not discoverable: the operator's
counterparties already know it is there, and announcing it would advertise
capacity to callers who cannot use it.

Publishing a model at `Network` is an explicit decision to serve the network,
and it overrides the node's service-key gate **for that model's inference path
alone**. Every other method on every surface stays gated. This is the inverse
of a default-open hole: nothing becomes reachable unless an operator named a
model and published it.

So the combinations an operator can hold at once:

- A **gated machine** — service key required for the shell, storage and the
  operator surfaces — that still serves two models to the whole network for
  TNZO, because those two are `Network`.
- A model served only to three counterparties under agreed terms (`Gated`),
  on the same node, at the same time.
- A model that never leaves the box (`Private`), also on the same node.

None of these force the others.

### Setting it

```bash
# Publish to the network — any caller may invoke it by paying, with no key,
# even on a node whose service-key gate is on. This is the default.
tenzro model serve --model-id timesfm-2.5-200m

# Servable to counterparties holding an API key you issued, and not announced.
tenzro model serve --model-id partner-model --gated

# Never leaves the box.
tenzro model serve --model-id house-model --private
```

`--gated` and `--private` are mutually exclusive; omitting both publishes.

### How it is enforced

The blanket admission middleware runs before the request body is parsed, so it
knows neither the method nor the model — which is why it previously refused
every call on a gated node, including inference on a model the operator had
deliberately published. The JSON-RPC root now defers to a method-aware check
that runs after parsing (`service_key_refusal`), and the carve-out is:

- the method is on the `PUBLIC_INFERENCE_METHODS` allowlist, **and**
- the named model is currently served at `Network` visibility.

Everything else falls through to the refusal — a `Gated` or `Private` model, an
unknown model, an unlisted method, or a missing model parameter. A method added
later is unreachable on a gated node until someone adds it to the allowlist,
which is the same default-deny posture `rpc_gates.rs` enforces for the
admin/open split.

Every other path on that listener (`/v1/*`, media, audio) keeps the blanket
gate, and the refusal a caller sees is byte-identical to the one the middleware
has always sent — `401` with `{error, header, surface}`.

## Advertised endpoint

An announcement carries the endpoint a peer should dial, which is not
necessarily what the node binds. Set `external_rpc_addr` (CLI
`--external-rpc-addr`) when the two differ — behind a proxy, a relay, or a NAT
port-forward.

This matters more than it looks. A node bound to `127.0.0.1:8545` that
advertises its bind address gossips a URL which, for every peer that receives
it, resolves to _that peer_. It is not filtered out as an empty endpoint would
be; it dials successfully against the wrong machine.

Both model offers and agent announcements now resolve through
`external_rpc_addr` when set, matching what model-service registrations
already did.


## RPC providers sell their own tenants a fourth thing

An RPC provider brokers access to **external networks** — Canton, and other
chains beyond Tenzro — using upstream credentials they hold. They sell scoped
access to that on their own terms and bill for it themselves, the way every
other chain's RPC operators do. Modelled as
`tenzro_types::access_tier::RpcServiceGrant`.

That revenue is theirs and **never enters a node's revenue split**. It must not
be confused with the RPC-provider leg described in
[ECONOMICS.md](ECONOMICS.md), which pays for *validation performed on a serving
node's behalf* and appears only when a node advertises without validating.
Charging in both places for the same relationship would be charging twice for
two different things and calling it one.

A grant that names no network is refused at issuance rather than stored: the
natural reading of an empty list at a call site is "unrestricted", and that
reading would hand a tenant every upstream credential the provider holds.


## Devices are what authenticate, and sessions name them

Every tier above is reached by an identity, and an identity authenticates
through the **devices bound to it** — a phone, a laptop, a machine. A binding
counts only when the credential cannot sync off the device *and* an attestation
verified to a pinned vendor root says its key lives in hardware. No platform
account is an identity authority.

An authenticated session names the bound device that authorised it, not only the
identity, so unbinding a device ends exactly the access it granted. A wallet
cannot be created behind a single device: the machine is the first, and a
genuinely separate one must be bound before there is anything to lose.

Full model, including why a phone has no serial number to read and why the
signature counter is only meaningful for device-bound credentials:
[TDIP.md](TDIP.md).

## Wire compatibility

`network` and `private` are unchanged, so existing records and announcements
parse as before. `gated` is new — a peer on an older build refuses to parse it
rather than silently reading it as something more open, which is the correct
direction to fail.
