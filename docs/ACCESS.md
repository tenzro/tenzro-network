# Access: who may use a node

Tenzro has three ways a caller reaches a node. The distinction is **economic
before it is technical**: each pays differently, so each has to be nameable at
settlement time, and keeping them separate is what lets a node be private about
its machine while still serving models to the network.

| Tier           | Credential    | Pays                             | What they get                                                   |
| -------------- | ------------- | -------------------------------- | --------------------------------------------------------------- |
| **User**       | none, payment | per request, on demand           | whatever the node serves publicly                               |
| **Subscriber** | access token  | a subscription the operator sets | resources the node **serves**, as its access policy admits      |
| **Renter**     | lease         | locked or prepaid up front       | the **raw capacity itself**: compute, storage, memory, security |

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
   `device_message`. Optional `credentials` are KYA credentials about the DID,
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

### Signing in from an Android app

A passkey assertion names the origin it was made at, and a node accepts one
made on its relying party's site or a subdomain of it. A native Android app
has no site: it reports `android:apk-key-hash:<hash>`, where `<hash>` is the
base64url SHA-256 (43 characters, no padding) of the certificate the app is
signed with. A node accepts that origin at sign-in only when its operator
lists it:

```bash
TENZRO_WEBAUTHN_RELATED_ORIGINS="android:apk-key-hash:<hash>"
```

The list is comma-separated and each entry is compared whole. What it admits
is narrow:

- Only entries that start `android:apk-key-hash:` are used. Any other entry, a
  web origin included, admits nothing, and the node says so in its log at
  start, as it does for an app entry whose hash is not 43 base64url
  characters.
- An entry names a signing certificate, not an app: every app signed with
  that certificate reports the same origin.
- It applies to passkey sign-in, for a passkey linked under the node's own
  relying party: `tenzro_issueAccessToken` with a passkey proof, and the MCP
  server's hosted sign-in page (`POST /authorize`). The passkey must still be one of
  that relying party (the authenticator's `rpIdHash` is checked), be linked
  to the account, and verify its user.
- It applies to the operator's passkey approvals too, which the operator's
  phone app makes with Credential Manager at its app origin: approving a
  waiting condition (`tenzro_submitApproval`), a paired device's
  `tenzro_restartNode` and `tenzro_installUpdate`, and a television's device
  code (`tenzro_approveDeviceCode`). An app origin the node does not list is
  refused on each of them, and the relying party's own `https` page is
  accepted whatever the list says. The passkey must still be a device bound
  to the operator.
- Transactions, custody changes, passkey enrolment and grants for a remote
  hardware key never read it: an assertion made in an app authorizes none of
  them on any node.

Android offers an app a passkey of the relying party only when
`https://<relying party>/.well-known/assetlinks.json` names the app's package
and the same certificate, so the relying party's site narrows an entry to the
packages it names, and the list alone does not make an app work. An iOS
app reports the relying party's own `https` origin and needs no entry.

## Paired devices

A phone, a television or a browser that is not the node's own machine is
paired with a one-time code. An administrator calls `tenzro_pairDevice` with no
arguments and gets the code, the same code as a QR code (`qr_rows`, rows of `0`
and `1`) and the pairing's `id`. `tenzro_pairDevice { id }` tells the
administrator where a pairing stands: `waiting`, `done`, `failed` or `expired`.

The QR code holds a link, `https://control.tenzro.com/pair#node=<rpc>&did=<node DID>&secret=<code>`
(`node` only when the node publishes an RPC address; `did` is the node's
machine identity, also in the answer as `node_did`; and the paired-device
listener's `lan` and `pin` entries described below), so a phone's camera
opens it in the Control app that claims the link, or in a browser at the
Control web app. The code and the address travel in the fragment, which a
browser sends to no server.

The code is twenty characters, shown as five groups of four. The first four
name the pairing and are no secret; the other sixteen are an 80-bit secret. A
code works once, for five minutes, and the node keeps only its digest in
memory.

The device signs in with its own key, as its own identity, and passes the code
as `pairing_code` to `tenzro_issueAccessToken`. Checking the code there does
not spend it. The token that sign-in issues carries no method class, lasts at
most five minutes and is accepted by one call,
`tenzro_pairDevice { secret, label, kind }`, which redeems the code; every
other method refuses it. Once paired the device signs in again, without a code,
for the token of a paired device. An administrator's identity is not paired as
a device.

Wrong codes are counted twice. A wrong secret counts against the pairing its
first four characters name, and the fifth cancels that pairing: its status
reads `failed` and says why, and no other pairing is touched. Every wrong code,
whichever pairing it names or none, counts against the address it came from (or
the peer, on the node's own transport); after five the node reads no further
code from that address until five minutes after its first. Callers that reach
the node through one address share that count.

A paired device is never an administrator. Pairing adds its identity to an
allow rule on each admin call a paired device may make, written into
`access.toml` as a resource named `rpc:<method>`, and to nothing else:

```toml
[[resources]]
resource = "rpc:tenzro_listPairedDevices"
[resources.rule]
rule = "allow"
dids = ["<the device's identity>"]
orgs = []
```

The node consults such a rule only for those calls, so a resource rule naming
any other admin method opens nothing. `tenzro_listPairedDevices` lists the
devices; `tenzro_unpairDevice { id }` removes a device from the rules and drops
its record. An administrator removes any device and a paired device removes
only itself. The token the device holds stays valid until it runs out and opens
nothing a paired device had.

A paired device also reads the node's conditions (`tenzro_listConditions`)
and makes three calls that act on the node, each of which the operator's
passkey decides on the call itself; pairing alone never makes them:

- `tenzro_restartNode` and `tenzro_installUpdate`: a call without the
  operator's assertion is refused, and the refusal's `data` carries a
  `challenge` (base64url) and the `rp_id` to sign it under. The device has the
  operator sign it with a passkey bound to the operator and calls again with
  `assertion` (`credential_id`, `authenticator_data`, `client_data_json`,
  `signature`, as `tenzro_submitApproval` takes it). The challenge covers the
  call itself, its method and its parameters without the assertion, so the
  assertion approves that call and no other: a release or a source changed
  between the refusal and the retry fails. A challenge answers once, within
  five minutes, for that device and that method only.
- `tenzro_submitApproval`: approving a waiting condition needs the operator's
  assertion over the challenge the condition asks with; declining needs none.

Unpairing withdraws all of these at once, with any challenge still waiting.
A paired device can unpair only itself; an administrator unpairs any.
`tenzro_approveDeviceCode` and `tenzro_submitApproval` are open to any paired
device because each carries the operator's passkey assertion, which is what
authorises it: the device only relays it.

Open decisions on what a neighbour on the same network can do, kept as they
are. Five wrong codes against the four characters a pairing is named by cancel
that pairing, so someone who can see the name can end it; the operator starts
another in a moment, and the alternative would let the same guesses go on
against the secret. The device-code table holds sixteen waiting requests and
two per address for ten minutes, so a neighbour can fill it; a television then
waits for a slot. A rejected proof or token is answered with the reason the
engine gives, the audience included, which is the node's own public address.
A batch of calls arrives under one proof, as it does for any token, and each
call is checked for the purpose its method belongs to.

A device whose passkey cannot make the ML-DSA-65 leg, such as a browser,
signs in with the passkey alone: `tenzro_issueAccessToken` with a `passkey`
proof and no `ml_dsa_signature`. That is accepted only with a `pairing_code`
(the token then redeems the code and nothing else) or for an identity already
paired as a device; any other sign-in without the leg is refused. A paired
device signed in that way gets a token for the paired-device calls only,
refused on every other method whatever the policy says, and its record reads
`signed_in_with: "passkey (no post-quantum leg)"`. Unpairing ends it like any
other paired access. A leg that is presented is always checked.

Why the leg may be left out there and nowhere else: a browser's passkey is
held by the platform's authenticator, which signs P-256 and nothing else, so
a browser can never make the ML-DSA-65 leg and could not be paired at all
otherwise. What such a sign-in opens is kept to what a paired device may do,
which the operator granted by pairing it, can withdraw at once by unpairing
it, and which acts on the node only with the operator's own passkey on the
call; an administrator's, an operator's and every other sign-in, MCP's
included, still needs both legs.

A browser need not know which identity or account its passkey belongs to.
It asks `tenzro_accessChallenge { dpop_jkt }` without a `did` and answers
with a `passkey` proof without `account_address`; the node finds the
accounts whose keystore links that credential on its relying party, and the
first whose passkey verifies the assertion names the identity, which the
answer's `did` carries. Which accounts link a credential is learnt only
through an assertion that verifies, and no call reads it otherwise. A
hardware key still names its `did` and signs `device_message`.

A browser page is served from its own origin, and the node answers it only
because of pairing, never through a default:

- while a pairing waits, a page at an `https` origin at or under the node's
  relying-party id may sign in and redeem (`tenzro_accessChallenge`,
  `tenzro_issueAccessToken`, `tenzro_pairDevice`) and make no other call;
- pairing a device of kind `browser` records the page's origin when it is
  such an origin (any other is never recorded), and from then on that page
  makes the paired-device calls and the open reads and no other call;
- unpairing the browser removes its origin.

Origins in the node's `cors_allowed_origins` are answered as configured.

### A television: signing in by device code

A device with no passkey and no hardware key the node can check, such as a
television, signs in the way the OAuth device authorization grant (RFC 8628)
describes, with nothing typed on the device:

1. It calls `tenzro_requestDeviceCode { dpop_jkt, label? }` and gets a secret
   `device_code`, a `user_code` such as `BCDF-GHJK` to show, `expires_in`
   (600 seconds) and `interval` (5 seconds). Two codes wait per address and
   sixteen in all.
2. The operator answers from an administrator's session or a paired phone:
   `tenzro_approveDeviceCode { user_code, approve }`. Declining needs nothing
   more. Approving needs the operator's passkey on that call: without
   `assertion` it is refused with a `challenge` to sign, the `rp_id` and the
   device's `label`, and with the assertion the device is listed with the
   paired devices as kind `tv`.
3. Meanwhile the device polls `tenzro_pollDeviceCode { device_code }`, no
   sooner than `interval` (each early poll is answered `slow_down` and adds
   five seconds), and is told `authorization_pending`, `access_denied` or
   `expired_token` until approved. Once approved, each poll returns an access
   token bound to `dpop_jkt`, for the open reads and no other method, for as
   long as the device stays listed.

Unpairing the television (`tenzro_unpairDevice`) refuses its tokens at once
and its device code gets no new ones.

### How a paired device reaches the node

A phone or a television is another machine, and the node's listeners are on
loopback. Starting a pairing opens one more listener, the paired-device
listener (`paired_device_addr`, `0.0.0.0:8543` unless set), and the node opens
it at every start while a device is paired. Nothing is configured by hand: the
answer to `tenzro_pairDevice` carries, under `lan`, the listener's IPv4 addresses on
the operator's private networks and the SHA-256 of each certificate it serves
under, and the QR code repeats them (`https://control.tenzro.com/pair#lan=<address>&pin=<hash>&secret=<code>`,
with `node=<url>` first when the node publishes an RPC address). When the
listener could not open, `lan.unavailable` says why and the pairing still
works over any other way the device has to the node.

The listener is the `paired-devices` feature of `tenzro-node`, on in every
default build. A build made with `--no-default-features` and without it (an
edge or embedded build) has no paired-device listener and no self-signed
certificates: `lan.unavailable` reads "this build has no paired-device
listener", and devices pair through the node's RPC address alone.

The listener speaks TLS only, under a certificate the node makes itself and
replaces every few days. A device accepts the certificates whose hashes it was
given and no other, and learns the next one from `GET /certificates`: the
hashes of the certificate served now and the one served next, signed with the
key the node signs access tokens with. Redeeming a pairing returns that key
(`node_key`), so a device checks the list against what it was handed when it
paired.

It answers peers on private networks only (loopback, RFC 1918, link-local,
carrier-grade NAT and unique-local addresses) and drops every other
connection. It serves signing in, the three pairing methods and the reads a
paired device shows (`tenzro_getNodeStatus`, `tenzro_syncing`, `tenzro_getRole`,
`tenzro_getRoleStakes`, `tenzro_getConnectivity`, `tenzro_getUpdateNotice`,
`tenzro_nodeProfile`, `tenzro_queryEvents`), the conditions and the three
calls that act on the node (`tenzro_listConditions`, `tenzro_restartNode`,
`tenzro_installUpdate`, `tenzro_submitApproval`); every other method is not found
there, for an administrator too. The access policy decides each call exactly
as on the node's own listener.

## Administrative calls are recorded

Every call to an admin-class method leaves a record, whether the gate
admits it or refuses it, so after the fact an operator can say who stopped a
model, from which machine and with which credential. Nothing about it is
optional: a node that cannot write the record refuses the call.

### Who is an administrator, and how they prove it

There is no shared administrator secret. An administrator is a DID: the
node's `operator_did`, or one of the `admins` in `access.toml`. A node whose
configuration names no `operator_did` is administered by its own machine DID,
so a validator signs in to its own node with `tenzro access sign-in` and no
further setup; naming an `operator_did` hands that role to the DID it names.
Each signs in
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

| Field                                           | Content                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `seq`, `prev`, `at`                             | position in the chain, the previous record's hash, the time (UTC, milliseconds)                                                                                                                                                                                                                                                                                                   |
| `node`, `chain_id`                              | this machine's DID and the chain id                                                                                                                                                                                                                                                                                                                                               |
| `entry.kind`                                    | `call` (the gate's decision), `completion` (how an admitted call ended), `sign_in` (an administrator signed in), `checkpoint`, `opened` (the node started)                                                                                                                                                                                                                        |
| `method`, `surface`                             | the method, and the access-policy surface it was decided under                                                                                                                                                                                                                                                                                                                    |
| `params`                                        | SHA-256 of the parameters and a few non-secret key fields (`model_id`, `did`, `role`, `visibility` and the like); never the payload                                                                                                                                                                                                                                               |
| `principal`                                     | the DID, its root (`passkey` or `machine`), its role (`operator` or `policy_admin`), the credential (`passkey`, `hardware_key`, `delegated_agent_key`, `access_token` for a token issued before a restart, `node`), the token by `fingerprint` (a truncated, domain-separated SHA-256), `jti` and DPoP key thumbprint, and for an agent its delegation                            |
| `source`                                        | transport (`http`, `mcp`, `iroh`, `in_process`, `node`), TCP peer, client address, the `X-Forwarded-For` chain only when the peer is a trusted proxy (`http_surface.trusted_proxies`), the client machine's name and login (`peer_identity`) when a configured local identity service knows the client address, an overlay peer's endpoint id, `User-Agent` and `X-Tenzro-Client` |
| `request_id`, `client_request_id`, `jsonrpc_id` | the node's id for the call, the caller's `X-Request-Id`, the JSON-RPC id                                                                                                                                                                                                                                                                                                          |
| `decision`                                      | `admitted`, or `refused` with the code and reason the caller received                                                                                                                                                                                                                                                                                                             |
| `outcome`, `elapsed_ms`                         | on the completion record: `ok` or the error code, and how long the call ran                                                                                                                                                                                                                                                                                                       |

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
`[admin.peer_identity]` table nothing is asked. The service is reached over
a Unix socket, so on Windows a node refuses to start with this table set.

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
browsing discovery finds it. Privacy does not change what a
payment pays; see [ECONOMICS.md](ECONOMICS.md).

Gating is local policy over service surfaces only. Consensus, gossip and
voting never pass through it, and it can only refuse: what an agent may do is
decided by its consensus Terms, and no rule grants beyond them.

## One admission rule for every resource

Which callers may use a resource is decided by its effective **visibility**:
the node's visibility, or the resource's own override
(see [PRIVACY.md](PRIVACY.md)), applied on top of the access policy. The same
rule applies to models of every type, compute, storage, databases, hosting and
tools:

| Visibility | Announced?                                               | Who may use it                                                    |
| ---------- | -------------------------------------------------------- | ----------------------------------------------------------------- |
| `public`   | Yes, gossiped on `tenzro/models`, in provider heartbeats | **Anyone, by paying** the operator's per-use price (`0` is free)  |
| `gated`    | Yes, flagged as access-required (`key_required_models`)  | Only callers the access policy names (signed in, not merely open) |
| `private`  | No                                                       | This node's own callers only; never served off-node               |

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

## The metrics endpoint is public

`GET /metrics` on the web surface serves Prometheus counters: blocks and
transactions processed, inference requests, settlements and the value they
settled, the peer count and the uptime. They are counts only: no address,
DID, key, request or payment detail. The access policy classes the path
`read` on the `web` surface, the same class as the `/verify/*` routes, so the
policy cannot close it without closing those.

A node that should not publish its counters closes the path in front of the
node. Behind a reverse proxy, refuse `/metrics` for outside callers and let
the scraper reach the node's web address directly:

```nginx
location = /metrics { allow 10.0.0.0/8; deny all; proxy_pass http://127.0.0.1:8080; }
```

```caddy
@metrics path /metrics
respond @metrics 403
```

A node whose web address is not public needs nothing: the default web bind is
`127.0.0.1:8080`.

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

That revenue is theirs; nothing is taken out of a settled payment for it.

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

## The local helper: one user, and reads only

`tenzro control` is not a surface of the node and the access policy does not
govern it. It is a helper the operator starts on the node's own machine, and the
Tenzro Control apps talk to it over a local socket: a Unix socket on Linux and
macOS, a named pipe on Windows.

**Who can open it.** The user who started the helper, and nobody else. The
socket is created with that user as its only reader and writer, the directory
it sits in must belong to that user with no write permission for its group or
for others (the helper refuses to start otherwise), and on Linux and macOS each
connection's peer is checked against the socket's owner. The helper cannot tell
that user's programs apart: every program running as that user can open the
socket, and opening it is the whole sign-in.

**What opening it grants.** The helper's own `control_*` calls, and a fixed
list of the node's reads (status, sync, role, stakes, connectivity, the update
notice, the node's profile, conditions, paired devices, events). Those reads
are sent to the node with the operator's signed-in session, so a caller reads
what the operator may read. Every other method of the node is refused by the
helper and never reaches the node: calling the node's method by name through
the helper does not stop the node, install a release, move stake, change a
role, change this policy or remove a device.

**Where the session goes.** Because the operator's session travels with each
read, the helper only talks to a node on a loopback address. `--remote-node`
is the operator saying the session should go to a node elsewhere.

The helper reads lines of at most 1 MiB, answers 32 connections at once,
closes a connection that sends no whole line for 30 seconds, and gives the
node five seconds to answer before it reports the node as silent.
