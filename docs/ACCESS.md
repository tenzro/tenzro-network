# Access: who may use a node

Tenzro has three ways a caller reaches a node. The distinction is **economic
before it is technical**: each pays differently, so each has to be nameable at
settlement time, and keeping them separate is what lets a node be private about
its machine while still serving models to the network.

| Tier           | Credential     | Pays                             | What they get                                                    |
| -------------- | -------------- | -------------------------------- | ---------------------------------------------------------------- |
| **User**       | none, payment  | per request, on demand           | whatever the node serves publicly                                |
| **Subscriber** | access token   | a subscription the operator sets | resources the node **serves**, as its access policy admits       |
| **Renter**     | lease          | locked or prepaid up front       | the **raw capacity itself**: compute, storage, memory, security  |

Types: `crates/tenzro-types/src/access_tier.rs` (`AccessTier`,
`CredentialKind`, `PayerKind`, `RentableResource`, `RentalFunding`).

Only a user is charged at serve time; the other two settled up front.
**Metering runs for all three regardless**: an operator who cannot see what a
prepaid tenant consumed cannot price the next term.

## One policy, one file

Who may use a node is one policy, `access.toml` in the node's data directory
(`tenzro_types::node_access::NodeAccessPolicy`). It maps each **surface** and
**method class** to a **rule**:

- Surfaces: `rpc`, `mcp`, `a2a`, `openai`, `web`, `iroh`.
- Method classes: `read`, `owner_write`, `admin`, `inference`, `media`,
  `storage`, `index`, `payments`, `identity`. Every
  JSON-RPC method has exactly one class, derived from its name and its gate in
  `rpc_gates.rs`.
- Rules: `open`, `closed`, `paid`, `allow` (DIDs and organizations),
  `credential` (a KYA credential from named issuers), `terms` (an agent acting
  under consensus Terms that permit the action), `tier` (signed in, with a rate
  and quota tier), and `all` / `any` / `not` to combine them.

```toml
admins = ["did:tenzro:human:..."]
token_ttl_secs = 900

[default_rule]
rule = "open"

[[rules]]
surface = "rpc"
class = "index"
[rules.rule]
rule = "allow"
dids = ["did:tenzro:human:..."]
orgs = []

[[tiers]]
name = "standard"
rate_per_minute = 600
burst = 100
quota_per_period = 0
```

The first matching rule wins; `default_rule` covers the rest. Admin-class
methods admit only the operator DID and the `admins` the policy names, whatever
the rules say.

There is one store and three ways in, and all three write through it:
validate, write atomically, bump `version`, append a line to `access.log`,
apply. A running node watches the file and applies an edit within seconds; an
edit that does not parse or validate is refused and the policy in force stays.

- **The wizard**: `tenzro-node access` asks for a preset (`open`, `signed_in`,
  `agents_with_terms`, `closed`) and the administrators; flags
  (`--preset`, `--admin`, `--remove-admin`, `--token-ttl-secs`, `--show`) do
  the same without asking.
- **The admin page**: `tenzro-node access --page` writes a fifteen-minute
  ticket into the data directory and prints `http://127.0.0.1:8545/access#...`.
  The page answers loopback callers holding that ticket only: whoever can
  write the data directory already administers the policy, and the ticket
  confers nothing more.
- **The file**: edit `access.toml` directly.

Remotely, an administrator signed in with an access token uses
`tenzro_getAccessPolicy`, `tenzro_setAccessPolicy` and `tenzro_previewAccess`
(CLI `tenzro access show | set | preview`, MCP `get_access_policy`,
`set_access_policy`, `preview_access`). `previewAccess` answers what the
policy would decide for a DID on a surface and method without serving
anything.

## Signing in: access tokens

There is no shared secret anywhere. A caller proves who it is once, with a
passkey or a hardware key, and receives a short-lived ES256 access token bound
to its DPoP key:

1. `tenzro_accessChallenge { did, dpop_jkt }` returns a single-use challenge
   bound to the DID and the DPoP key's thumbprint.
2. `tenzro_issueAccessToken { challenge_id, proof }` answers it: a passkey
   assertion over `challenge`, or a hardware-key signature over
   `device_digest`. Optional `credentials` are KYA credentials about the DID,
   for `credential` rules.

The token is signed by a P-256 key the node derives from its own hardware
root, and lasts `token_ttl_secs` (fifteen minutes by default, one day at
most). Every request carries it as `Authorization: DPoP <token>` with a fresh
`DPoP` proof for that request. Each request re-evaluates the policy for the
token's DID, so a policy change applies to tokens already issued; an
administrator withdraws tokens with `tenzro_revokeAccessToken` and lists live
ones with `tenzro_listAccessTokens`.

The CLI signs in with this machine's hardware key and stores the token:
`tenzro access sign-in`. Over iroh, a frame carries the token and a proof whose
`htu` is `tenzro-iroh://<alpn>`.

## Administrative calls are recorded

Every call to an admin-class method leaves a record, whether the gate
admits it or refuses it, so after the fact an operator can say who stopped a
model, from which machine and with which credential. Nothing about it is
optional: a node that cannot write the record refuses the call.

### Who is an administrator, and how they prove it

There is no shared administrator secret. An administrator is a DID: the
node's `operator_did`, or one of the `admins` in `access.toml`. Each signs in
for their own access token with their own credential, so every call names a
person or a machine rather than whoever held a file:

- **A person** signs in with a passkey: a `webauthn.get` assertion over the
  challenge (`tenzro_issueAccessToken` with `proof.kind = "passkey"`). The
  DID is `did:tenzro:human:...`.
- **A machine** signs in with its TPM or Secure Enclave key:
  `tenzro access sign-in` on that machine. The DID is
  `did:tenzro:machine:...`.
- **A delegated agent** signs in with the key a serving machine holds for it
  under its consensus Terms. The record names the agent, its Terms version
  and approval, and the human or machine at the root of the delegation.

To give a colleague administrative access, add their DID to `admins` (CLI
`tenzro-node access --admin <did>`, or `tenzro access set`) and have them sign
in. To take it away, remove the DID and withdraw its live tokens with
`tenzro access revoke --did <did>`.

### What a record holds

Records are JSON lines in `audit/admin-audit.jsonl` in the data directory,
each `{"record": {...}, "hash": "..."}`. A record carries:

| Field | Content |
| --- | --- |
| `seq`, `prev`, `at` | position in the chain, the previous record's hash, the time (UTC, milliseconds) |
| `node`, `chain_id` | this machine's DID and the chain id |
| `entry.kind` | `call` (the gate's decision), `completion` (how an admitted call ended), `sign_in` (an administrator signed in), `checkpoint`, `opened` (the node started) |
| `method`, `surface` | the method, and the access-policy surface it was decided under |
| `params` | SHA-256 of the parameters and a few non-secret key fields (`model_id`, `did`, `role`, `visibility` and the like); never the payload |
| `principal` | the DID, its root (`passkey` or `machine`), its role (`operator` or `policy_admin`), the credential (`passkey`, `hardware_key`, `delegated_agent_key`, `access_token` for a token issued before a restart, `node`), the token by `fingerprint` (a truncated, domain-separated SHA-256), `jti` and DPoP key thumbprint, and for an agent its delegation |
| `source` | transport (`http`, `mcp`, `iroh`, `in_process`, `node`), TCP peer, client address, the `X-Forwarded-For` chain only when the peer is a trusted proxy (`http_surface.trusted_proxies`), the client machine's name and login (`peer_identity`) when a configured local identity service knows the client address, an overlay peer's endpoint id, `User-Agent` and `X-Tenzro-Client` |
| `request_id`, `client_request_id`, `jsonrpc_id` | the node's id for the call, the caller's `X-Request-Id`, the JSON-RPC id |
| `decision` | `admitted`, or `refused` with the code and reason the caller received |
| `outcome`, `elapsed_ms` | on the completion record: `ok` or the error code, and how long the call ran |

The node also records its own privileged actions: when surge loading serves
or stops a model, the record names the node as principal with
`actor: "surge"`.

### Why the log can be trusted

- **Write-ahead, fail closed.** The admission record is synced to disk before
  the call runs. If it cannot be written the call is refused with `-32040`,
  and an administrator's sign-in is refused the same way.
- **Hash-chained.** Each record carries the hash of the one before, so an
  edit, insertion or deletion anywhere breaks the chain.
- **Signed checkpoints.** Every 64 records (`[admin] audit_checkpoint_every`)
  and whenever a segment closes, the node signs the chain's head with its
  hardware identity key (TPM or Secure Enclave) and appends the signature as a
  record. The key never leaves the hardware.
- **A second copy of the head.** Every record is also logged at INFO under the
  `tenzro::admin_audit` target with its sequence number, hash, method,
  principal and client address, so the journal holds the chain's head
  independently of the file.
- **Rotation without deletion.** Past 64 MiB (`audit_rotate_bytes`) the active
  segment is checkpointed and renamed `admin-audit.<last seq>.jsonl`; the
  chain continues into the next file. The node never deletes a segment.

Reads stay out of the log: only admin-class methods are recorded, which is
where every state change without its own proof lives. `[admin] audit_skip`
drops admin-class reads an operator polls often, and `audit_also` adds other
methods.

### Restricting where administrative calls come from

```toml
[admin]
networks = ["127.0.0.1/32", "::1/128", "100.64.0.0/10"]
```

With `networks` set, an administrative call is admitted only when its client
address is in one of them; in-process calls are always admitted and overlay
calls, which carry no address, are refused. Unset, any network is accepted
and every administrative call from off the machine logs a warning.

### Naming the machine a call came from

When operators reach their nodes over a private overlay network, the
overlay's local identity service usually knows which machine, and which
login, an address belongs to. Point the node at it and every record carries
that name in `source.peer_identity`:

```toml
[admin.peer_identity]
socket = "/run/identity/identity.sock"   # the service's Unix socket
request = "/whois?addr={addr}"            # {addr} is the client address and port
host = "localhost"                        # the Host header the service expects
machine_field = "/machine"                # JSON pointer to the machine name
login_field = "/login"                    # JSON pointer to the login
networks = ["10.0.0.0/8"]                 # addresses to ask about; empty = any off this machine
```

The node sends `GET <request>` over HTTP/1.0 on the socket and reads the two
fields from the JSON answer. Only `socket` is required; the other values
shown are the defaults, except `networks`. A service that does not answer
within half a second, or answers anything but 200 with JSON, leaves
`peer_identity` empty for that call and never delays it further. Without an
`[admin.peer_identity]` table nothing is asked.

### Reading and checking the log

```bash
# The most recent administrative calls, oldest first.
tenzro access audit --limit 50

# Who called tenzro_stopModel, and from where.
tenzro access audit --method tenzro_stopModel --since 2026-10-11T00:00:00Z

# Everything one DID did.
tenzro access audit --principal did:tenzro:human:...

# Check the chain, the signatures and the end of the log.
tenzro access audit-verify
```

The RPCs are `tenzro_listAdminAudit` and `tenzro_verifyAdminAudit` (MCP
`list_admin_audit`, `verify_admin_audit`), both admin-class and both
recorded. On the machine itself the file reads with `jq`:

```bash
jq -c 'select(.record.entry.kind == "call")
       | .record.entry.data | {method, principal: .principal.did,
         ip: .source.client_ip, machine: .source.peer_identity, decision}' \
  /var/lib/tenzro/audit/admin-audit.jsonl

journalctl -u tenzro-node | grep tenzro::admin_audit
```

`audit-verify` exits non-zero and lists each problem when a record was
altered, records are missing, a checkpoint does not verify under this node's
identity key, or the log ends before the record the running node last wrote.
A line cut short by a crash is reported too; the node continues the chain
from the last readable record at its next start and marks that with an
`opened` record. The Prometheus counter
`tenzro_admin_actions_total{method,outcome}` counts calls by `refused`, `ok`,
`error` and `audit_failed`.

## Users: payment on demand, no relationship

x402 / TNZO settlement. The caller pays per call. There is nothing to issue and
nothing to agree in advance, which is the only thing that works for a peer that
just discovered an offer over gossip.

## Renters: leases over the machine

A renter buys the capacity itself, having locked funds in escrow or prepaid for
a term. The node hands over use of the hardware rather than answers from it:
the operator names the renter's DID in the access policy for the classes the
rental covers, and withdraws it when the term ends.

## Private is about discovery, not access

A **private node** is connected to the network but does not advertise itself.
The network can still reach it, as its access policy admits, but nobody
browsing discovery finds it. Because no discovery was consumed and no
validator was engaged on the caller's behalf, a private node keeps the whole
payment; see [ECONOMICS.md](ECONOMICS.md).

Gating is local policy over service surfaces only. Consensus, gossip and
voting never pass through it, and it can only refuse: what an agent may do is
decided by its consensus Terms, and no rule grants beyond them.

## One admission rule for every resource

Which callers may use a resource is decided by its effective **visibility**:
the node's visibility, or the resource's own override
(see [PRIVACY.md](PRIVACY.md)), applied on top of the access policy. The same
rule applies to models of every type, compute, storage, databases, hosting and
tools:

| Visibility | Announced?                                                | Who may use it                                                     |
| ---------- | --------------------------------------------------------- | ------------------------------------------------------------------ |
| `public`   | Yes, gossiped on `tenzro/models`, in provider heartbeats  | **Anyone, by paying** the operator's per-use price (`0` is free)   |
| `gated`    | Yes, flagged as access-required (`key_required_models`)   | Only callers the access policy names (signed in, not merely open)  |
| `private`  | No                                                        | This node's own callers only; never served off-node                |

A caller the access policy names is served in every mode. `gated` has no
pay-per-use path.

So the combinations an operator can hold at once:

- A **closed machine**, nobody but administrators on the shell, storage and
  operator surfaces, that still serves two models to the whole network for
  TNZO, because those two are `public` and the policy leaves `inference` open.
- A model served only to callers the policy names (`gated`), on the same node,
  at the same time.
- A model that never leaves the box (`private`), also on the same node.

None of these force the others.

### Setting it

```bash
# The node's visibility, which every resource without an override follows.
tenzro visibility set public

# Per-model overrides.
tenzro model serve timesfm-2.5-200m --public
tenzro model serve partner-model --gated
tenzro model serve house-model --private
```

The three flags are mutually exclusive; with none the model follows the node.

### How it is enforced

Every HTTP route but the JSON-RPC root passes the access policy as middleware,
classed by route. The JSON-RPC root applies it per method after the body is
parsed, so the decision knows the method's class. MCP, A2A and the web gateway
apply it with their own surface; iroh frames apply it with surface `iroh`.

Past the policy, every inference route (the JSON-RPC inference methods,
`/tenzro/forecasts` and the other `/tenzro/*` routes, and the OpenAI-compatible
`/v1/*` routes) runs the same model admission check before any payment logic:
a caller the policy names is admitted on all of them, and an unnamed call to a
`gated` model is refused with `402 credential_required` on all of them. The
model is read from the JSON body (`model` or `model_id`) or from a multipart
`model` field.

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

An RPC provider brokers access to **external networks** (chains beyond
Tenzro) using upstream credentials they hold, keyed by each
tenant's DID. They sell scoped
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
counts only when the credential cannot sync off the device. Whether an
attestation verified to a vendor root says its key lives in hardware is
recorded on the binding as a reputation signal, not required: no platform
account and no hardware vendor is an identity authority.

An authenticated session names the bound device that authorised it, not only the
identity, so unbinding a device ends exactly the access it granted. A wallet
cannot be created behind a single device: the machine is the first, and a
genuinely separate one must be bound before there is anything to lose.

Full model, including why a phone has no serial number to read and why the
signature counter is only meaningful for device-bound credentials:
[TDIP.md](TDIP.md).
