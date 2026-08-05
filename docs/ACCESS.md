# Access model — service keys, API keys, and payment

Tenzro has three ways a caller earns access. They answer different questions,
and keeping them separate is what lets a node be private about its machine
while still serving models to the network.

| Credential      | Question it answers                          | Bought / issued how                                | Scope lives on                                                              |
| --------------- | -------------------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------- |
| **Service key** | _May you use this machine's raw resources?_  | Rented — a period, up to a capacity                | `ServiceKeyGrant` (reachability) + `AccessLease` / `AccessScope` (capacity) |
| **API key**     | _May you use this resource, on these terms?_ | Issued by the operator against a pre-agreed policy | `ApiKeyRecord.scopes`, class, tier ceiling                                  |
| **Payment**     | _Have you paid for this call?_               | On demand, per call, no prior relationship         | The model's own price and the settlement path                               |

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

## Service keys — renting the machine

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

## API keys — using a resource on agreed terms

An `ApiKeyRecord` carries granted `scopes`, a `KeyClass`, an optional subject
DID, a tier ceiling with a rolling rate budget, and any Canton bindings. This
is the credential for a caller the operator has a _relationship_ with: the
terms were agreed before the first call.

Tiers bound a key's budget over a sliding 60-second window — `free` at 60
requests/min with writes refused, `standard` at 600, `priority` at 6,000. Over
budget returns `-32005` with `retry_after_ms`.

A key's holder can read its own entitlements (`listMine`), so a tenant can
answer "what may I do here" without asking the operator.

## Payment — on demand, no relationship

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

## Wire compatibility

`network` and `private` are unchanged, so existing records and announcements
parse as before. `gated` is new — a peer on an older build refuses to parse it
rather than silently reading it as something more open, which is the correct
direction to fail.
