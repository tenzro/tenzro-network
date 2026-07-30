# Tenzro API Keys

Tenzro mediates access to upstream services that callers should not hold
credentials for directly — most notably the Canton devnet JSON Ledger
API, which is gated by an Auth0-issued JWT. Rather than handing the
Auth0 secret to every developer, the **operator** (the RPC node) holds
the upstream credential server-side and proxies calls on the caller's
behalf. Callers authenticate to the Tenzro node with a per-developer
**API key** (`tnz_...`) that carries a set of scopes.

This document is the canonical reference for developers and operators
who need to issue, use, or revoke those keys.

## What API keys do *not* gate

An API key gates **operator-brokered resources** — the ones where the
operator holds an upstream credential and pays an upstream bill on the
caller's behalf. Canton is the archetype: the operator holds the
Auth0/JWT credential for a participant node and proxies ledger calls.
Third-party chain RPC (Alchemy, Infura, dRPC) is the same shape.

The marketplace registries are **permissionless**. Registering an
agent, a skill, a workflow template, an MCP server, a model, or a
knowledge source needs no API key and no operator approval:

| Registry            | Register with                                          | Admission control |
|---------------------|--------------------------------------------------------|-------------------|
| Agents              | `tenzro_registerAgent`                                  | None — DID-signed |
| Agent templates     | `tenzro_registerAgentTemplate`                          | None — DID-signed |
| Skills              | `tenzro_registerSkill`                                  | None — DID-signed |
| Tools / MCP servers | `tenzro_registerTool`                                   | None — DID-signed |
| Workflow templates  | `tenzro_registerWorkflowTemplate`                       | None — DID-signed |
| Knowledge sources   | `tenzro_registerKnowledge`                              | None — DID-signed |

Anyone with a Tenzro DID can list a resource. The listing declares its
own price: free, or a TNZO amount that settles to the provider's wallet
on use, minus the protocol commission. No operator can refuse a
listing, delist someone else's resource, or gate discovery. Consumers
choose what to invoke; the network settles the payment.

Serving a model (`tenzro_serveModel`) is likewise open. The one
adjacent method that *is* admin-gated is `tenzro_registerProvider`,
because it enrols **the node itself** as a provider — a decision that
belongs to whoever runs the node, not to a remote caller.

Rejection at *invocation* time is a different thing and stays available:
a consumer's delegation scope, spending policy, or approval policy can
refuse a call the consumer's own controller did not authorize. That is
consumer-side control, not registry admission.

## The sovereignty model

Tenzro draws a sharp line between two kinds of resources:

| Tier               | Control surface                                                                  | Examples                                                                                                                          |
|--------------------|----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| **Node-scoped**    | Per-node `X-Tenzro-Admin-Token` held by that node's operator                     | API keys, this node's admin token, upstream creds (Auth0 / Canton JWT), what this node serves, local TLS, local secret store      |
| **Network-wide**   | `tenzro-token` `GovernanceEngine` + EVM `0x1005` `GOVERNANCE` precompile         | Validator set, treasury, fee schedule, staking params, TNZO contract, system contracts (ERC-8004, NFT factory), protocol upgrades |

API key issuance lives on the left. **Every node operator is sovereign
over their own node's API keys** — Tenzro Labs (operating
`rpc.tenzro.xyz`), validator operators (each on their own validator
node), and self-hosted operators all hold their own admin token and
issue their own keys. There is no global "Tenzro Labs token," no
network-wide key registry, and no operator can mint or revoke keys at
another operator's node.

The right column — anything that changes network-wide state — is
governed by stake-weighted on-chain proposals. No operator (including
Tenzro Labs) can mutate it via the admin token.

> **To get a key for a particular Tenzro RPC node**, contact whichever
> operator runs that node out of band — there is no self-service portal.
> The CLI / SDK / MCP / OpenClaw tooling described below is for
> *operators* of any tenzro-node instance; it doesn't bypass the admin
> gate.

## At a glance

| Surface                    | Header                       | Used for                                                          |
|----------------------------|------------------------------|-------------------------------------------------------------------|
| Per-developer API key      | `X-Tenzro-Api-Key`           | Calling scoped RPCs (e.g. Canton); also self-listing / self-revoke |
| Operator admin token       | `X-Tenzro-Admin-Token`       | Minting / listing / revoking API keys on the operator's node       |
| Canton network selector    | `X-Canton-Network`           | Naming the target Canton ledger on the Canton MCP server           |

The admin token is held by that node's operator. Developers never see it.

On the JSON-RPC surface the Canton network travels as a `canton_network`
**param** rather than a header — see [Canton networks](#canton-networks).

## Key classes

Every issued key carries a `class` that controls who can revoke it.

| Class                | Mint by         | Subject-revokable?     | Admin-revokable via RPC?            | Use case                                                                                       |
|----------------------|-----------------|------------------------|-------------------------------------|------------------------------------------------------------------------------------------------|
| `subject`            | Admin           | Yes (`tenzro_revokeMyApiKey`) | Yes (`tenzro_revokeApiKey`)         | Default: per-developer keys                                                                    |
| `operator_internal`  | Admin           | No                     | Yes                                  | Operator-only ops keys (background jobs, internal services). Subject not necessarily set.       |
| `operator_protected` | Admin (with confirm flag) | No            | **No** — RPC-side revocation is refused | The operator's own self-imposed lockdown. Rotate by updating secrets storage and restarting.    |

`operator_protected` is unusual: even the admin token cannot revoke it
through the JSON-RPC surface. That is by design — it lets an operator
mint a key for their own production service and guarantee that even an
accidental or compromised admin-token call cannot pull the rug.
Rotation requires updating the secret store and restarting the node.

`subject` keys are the only ones a developer can revoke themselves.
`subject` and `operator_internal` keys are both revokable by the admin
via `tenzro_revokeApiKey`. `operator_protected` is the only class
where RPC-side revocation is refused outright.

## Scopes

| Scope    | Gated methods                                                       |
|----------|---------------------------------------------------------------------|
| `canton` | `tenzro_listCantonDomains`, `tenzro_listDamlContracts`, `tenzro_submitDamlCommand`, and the Canton MCP tools |
| `issuer` | `tenzro_registerStableAsset`, `tenzro_mintStableAsset`, `tenzro_redeemStableAsset`, and the issuer's policy reads/updates |

Mints under the `issuer` scope are still hard-bounded by the
SecureMint reserve floor regardless of the key — the scope authorises
*who may operate* an issuer's unit, not the reserve invariant itself.

The subject-gated RPCs (`tenzro_revokeMyApiKey`, `tenzro_listMyApiKeys`)
are *not* tied to a scope — any active key with a `subject` set is
authorised to manage its own subject's keys. Additional scopes (`evm`,
`svm`, `inference`, `tee`, `bridge`, `chainlink`) are variants of the
`ApiKeyScope` enum on the node side; the wire format is unchanged.

## Tiers

A scope decides *which* surfaces a key reaches. A **tier** decides *how
much* of a reachable surface it gets: a per-minute request budget, and
whether state-mutating methods are permitted at all.

| Tier       | Requests / minute | Mutating methods |
|------------|-------------------|------------------|
| `free`     | 60                | Refused          |
| `standard` | 600               | Allowed          |
| `priority` | 6,000             | Allowed          |

`free` is the default when `tier` is omitted at issuance, so a key never
silently acquires write access. The budget is a sliding 60-second window
per key; keys do not share a pool.

The mutating methods the `free` tier refuses are the ones that change
upstream state:

- Canton ledger writes — `tenzro_submitDamlCommand`,
  `tenzro_canton_submitWithMandate`,
  `tenzro_allocateParty`, `tenzro_canton_uploadDar`,
  `tenzro_canton_grantUserRights`, `tenzro_canton_createIdp`,
  `tenzro_canton_deleteIdp`, `tenzro_canton_watchParty`,
  `tenzro_consumeDamlEvents`, `tenzro_canton_mirrorReceipt`,
  `tenzro_mirrorWorkflowToCanton`, `tenzro_mirrorObligationToCanton`
- Bridge-fee sponsorship — `tenzro_sponsorBridgeFee`
- Stable-asset issuance — `tenzro_registerStableAsset`,
  `tenzro_mintStableAsset`, `tenzro_redeemStableAsset`

Reads on the same scopes (health, version, package and party listings,
contract queries) are available at every tier.

Refusals: a `free` key calling a mutating method gets `-32004`; any key
over its budget gets `-32005` with a `retry_after_ms` field so a client
can back off without parsing the message.

## Canton networks

A Canton network is a **distinct ledger** — distinct parties, distinct
contracts, distinct assets. A key therefore names the networks it may
reach, and a request naming more than one authorized network says which
one it means.

### At issuance

`tenzro_createApiKey` takes `canton_networks`, an array of `devnet` /
`mainnet`. It is fail-closed: **omitted or empty means the key reaches
no Canton network**, and every canton-scoped call through it is refused.
A network the node does not serve is refused at issuance (`-32602`)
rather than producing a key that looks authorized and fails at dispatch.

```bash
curl -s -X POST https://rpc.tenzro.xyz \
  -H "content-type: application/json" \
  -H "X-Tenzro-Admin-Token: $TENZRO_ADMIN_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tenzro_createApiKey",
    "params": {
      "label": "alice-laptop",
      "subject": "did:tenzro:human:alice",
      "scopes": ["canton"],
      "canton_networks": ["devnet"],
      "tier": "standard"
    }
  }'
```

Canton-side provisioning (party allocation, user creation, IDP
registration, rights grants) binds the key to exactly one ledger, so
requesting any of it alongside multiple `canton_networks` is refused
with `-32602`. A multi-network key is fine for party-less reads.

### On the JSON-RPC surface — a param

The node resolves the target network from the request params:

1. an explicit `canton_network` param, if present;
2. otherwise the key's single authorized network, if it has exactly one;
3. otherwise the operator's default network.

So a single-network key never has to say anything. A key authorizing
both networks must name one, and the node names the authorized set in
the error when it doesn't.

```bash
curl -s -X POST https://rpc.tenzro.xyz \
  -H "content-type: application/json" \
  -H "X-Tenzro-Api-Key: tnz_3v8q7s2XQYf..." \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tenzro_listDamlContracts",
    "params": {"template_id": "...", "canton_network": "devnet"}
  }'
```

### On the Canton MCP server — a header

The Canton MCP server's gate sits above the MCP JSON-RPC envelope and
does not read tool arguments, so the network travels as
`X-Canton-Network: devnet` alongside `X-Tenzro-Api-Key`. Resolution
order, refusal codes and fail-closed behaviour are otherwise identical.
The other ecosystem MCP servers are open and take neither header.

### Tenant and operator paths

Both credentials reach Canton, and they reach different parts of it:

| | Tenant (`X-Tenzro-Api-Key`) | Operator (`X-Tenzro-Admin-Token`) |
|---|---|---|
| Network choice | `canton_network` param, bounded by `canton_networks` | `canton_network` param, unbounded |
| Party | The key's bound `primaryParty` | The participant's own parties |
| Reads | Contracts, health, version, packages | Same, plus party and IDP listings |
| Writes | Command submission at `standard`+ | Party allocation, DAR upload, rights grants, IDP management, receipt mirroring |
| Refused | Anything outside `canton_networks` | Nothing Canton-side; network-wide Tenzro state still needs governance |

An admin-token request skips the api-key gate entirely, so it is *not*
bounded by any key's `canton_networks` — but it still has to name the
network it means, because there is no key to infer one from. The CLI
surfaces this as `--canton-network` on both paths.

Operator-only canton commands take `--admin-token`; tenant commands
take `--api-key`. Passing the wrong one returns `-32001` (admin gate)
or `-32004` (api-key gate) rather than silently falling back.

### Client configuration

| Surface                | Network selector                                  |
|------------------------|---------------------------------------------------|
| CLI                    | `--canton-network devnet`, else `TENZRO_CANTON_NETWORK` |
| Rust SDK               | `client.canton().on_network("devnet")`            |
| TypeScript SDK         | `client.canton.onNetwork('devnet')`               |
| Python clients         | `TENZRO_CANTON_NETWORK=devnet`                    |
| Raw JSON-RPC           | `canton_network` param                            |
| Canton MCP             | `X-Canton-Network` header                         |

The Python clients (`integrations/mcp`, `integrations/a2a`,
`integrations/agents`, the OpenClaw skill) read
`TENZRO_CANTON_NETWORK` and merge it into the params of every
canton-scoped JSON-RPC call. The OpenClaw skill also has an MCP client
path, which sends the same value as `X-Canton-Network`. An explicit
`canton_network` already in the params always wins.

## Wire format

- Issued keys are 32-byte random tokens, base64url-encoded without
  padding, with a `tnz_` prefix: `tnz_3v8q7s2X...`.
- The raw key is **never persisted** — only its SHA-256 hash is
  stored in `CF_API_KEYS`. The plaintext is returned exactly once,
  at issuance time. If a developer loses it, the key must be revoked
  and re-issued.
- The non-secret `key_id` is the first 8 bytes of the hash, hex-encoded.
  This is the handle for `revoke` and audit.

## How developers request a key

Issuance is per-operator: there is no public mint endpoint on any
Tenzro node. To request a key:

1. Identify which operator runs the node you want to use (e.g. Tenzro
   Labs for `rpc.tenzro.xyz`; a particular validator or
   self-hosted operator for any other endpoint).
2. Reach out to that operator out of band with your Tenzro DID (or
   org), the scopes you need (currently just `canton`), and the
   integration you're building.
3. The operator mints the key — `class=subject` by default — and
   hands you the `tnz_...` string securely. **Save it immediately —
   it is shown only once.**
4. Use the key as documented in [Developer: using a key](#developer-using-a-key).

If you run your own tenzro-node, you are the operator and you mint
your own keys.

## Operator: issuing a key

Admin RPCs require the `X-Tenzro-Admin-Token` header. The node
fail-closes on missing or mismatched tokens (`-32001`). A node started
without `TENZRO_ADMIN_TOKEN` rejects every admin call regardless of
input.

### `tenzro_createApiKey`

```bash
curl -s -X POST https://rpc.tenzro.xyz \
  -H "content-type: application/json" \
  -H "X-Tenzro-Admin-Token: $TENZRO_ADMIN_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tenzro_createApiKey",
    "params": {
      "label": "alice-laptop",
      "subject": "did:tenzro:human:alice",
      "scopes": ["canton"],
      "class": "subject"
    }
  }'
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "key": "tnz_3v8q7s2XQYf...",
    "key_id": "a1b2c3d4e5f60718",
    "label": "alice-laptop",
    "subject": "did:tenzro:human:alice",
    "scopes": ["canton"],
    "class": "subject",
    "created_at": 1735603200,
    "note": "Save the `key` field now — it is shown only once."
  }
}
```

Params:

| Field                          | Type             | Required | Notes                                                                                                                          |
|--------------------------------|------------------|----------|--------------------------------------------------------------------------------------------------------------------------------|
| `label`                        | string           | no       | Free-form label; defaults to `"unnamed"`                                                                                       |
| `subject`                      | string           | no       | Typically a Tenzro DID; used for audit. Required for any key the operator wants the holder to self-revoke.                     |
| `scopes`                       | array of strings | no       | Defaults to `["canton"]`. Unknown scopes → `-32602`.                                                                            |
| `class`                        | string           | no       | One of `subject` (default), `operator_internal`, `operator_protected`.                                                          |
| `confirm_operator_protected`   | bool             | yes if `class=operator_protected` | Safety interlock — must be `true`, since `operator_protected` keys cannot be revoked via RPC.                            |
| `canton_networks`              | array of strings | no       | Which Canton ledgers the key reaches: `devnet` and/or `mainnet`. Deduped. Omitted or empty means no Canton access. A network this node does not serve → `-32602`. See [Canton networks](#canton-networks). |
| `tier`                         | string           | no       | One of `free` (default), `standard`, `priority`. Sets the per-minute budget and whether mutating methods are allowed. See [Tiers](#tiers). |
| `canton_user_id`               | string           | no       | Binds the key to a Canton User Management Service user id (e.g. `alice@clients`). With the `canton` scope on a Canton-enabled node this also allocates the party, creates the user, and grants `CanActAs` in one call. Requires exactly one entry in `canton_networks`. |
| `auto_provision_canton`        | bool             | no       | Defaults to `true`. Set `false` when the Canton user is already provisioned out of band.                                        |

### `tenzro_listApiKeys`

```bash
curl -s -X POST https://rpc.tenzro.xyz \
  -H "content-type: application/json" \
  -H "X-Tenzro-Admin-Token: $TENZRO_ADMIN_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listApiKeys","params":{}}'
```

Returns `{ "keys": [ <ApiKeyRecord>, ... ] }` — every record, active
and revoked, including its `class`. No plaintext keys are returned
(the node never stores them).

### `tenzro_revokeApiKey`

```bash
curl -s -X POST https://rpc.tenzro.xyz \
  -H "content-type: application/json" \
  -H "X-Tenzro-Admin-Token: $TENZRO_ADMIN_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tenzro_revokeApiKey",
    "params": {"key_id": "a1b2c3d4e5f60718"}
  }'
```

Response: `{ "key_id": "...", "revoked": true }`. Per-dev isolation:
revoking one key never affects another.

This RPC refuses to revoke `operator_protected` keys and returns
`-32004` with `data.class = "operator_protected"`. To rotate one of
those, update the operator secret store and restart the node.

## Developer: managing your own keys

Once you hold a `tnz_...` key whose `class` is `subject`, you can list
and revoke keys you own without touching the operator. Present your
key in the `X-Tenzro-Api-Key` header.

### `tenzro_listMyApiKeys`

```bash
curl -s -X POST https://rpc.tenzro.xyz \
  -H "content-type: application/json" \
  -H "X-Tenzro-Api-Key: tnz_3v8q7s2XQYf..." \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listMyApiKeys","params":{}}'
```

Returns every active and revoked key issued to *your* subject (resolved
from the presented key). Other subjects' keys are never exposed.

This is also the entitlement self-read: each row carries everything the
node will enforce against the key, so you can determine what you may do
without asking the operator.

```json
{
  "keys": [
    {
      "key_id": "a1b2c3d4e5f60718",
      "subject": "did:tenzro:machine:acme",
      "label": "acme-prod",
      "scopes": ["canton"],
      "class": "subject",
      "tier": "standard",
      "requests_per_minute": 600,
      "allows_write": true,
      "canton_networks": ["mainnet"],
      "canton_user_id": "acme@clients",
      "canton_identity_provider_id": null,
      "can_act_as_parties": [],
      "can_read_as_parties": [],
      "allowed_templates": [],
      "allowed_commands": [],
      "created_at": 1769000000,
      "revoked_at": null,
      "active": true
    }
  ],
  "subject": "did:tenzro:machine:acme"
}
```

Reading the row:

| Field | Meaning |
|---|---|
| `scopes` | Which resource classes the key may reach at all. |
| `tier` / `requests_per_minute` / `allows_write` | Rate ceiling, and whether write methods are permitted (`free` is read-only). |
| `canton_networks` | Which Canton ledgers the key may name in `canton_network`. Empty means no Canton access. A key authorizing more than one network must pass `canton_network` explicitly on every Canton call. |
| `canton_user_id` | The Canton User Management Service user bound to the key. |
| `canton_identity_provider_id` | Which identity provider that user resolves in. `null` means the participant's default. |
| `can_act_as_parties` / `can_read_as_parties` | Parties the key may submit or read as, beyond the bound user's primary party. |
| `allowed_templates` / `allowed_commands` | Restrictions on what DAML work the key may do. Empty means unrestricted. |

**`canton_user_id: null` with a non-empty `canton_networks` means node
access without ledger access.** The key authenticates and can call the
node, but it is bound to no Canton party, so command submission is
refused. Two ways forward: ask the operator to reissue the key with a
`canton_user_id` — the node then mints the tenant JWT server-side — or
present your own JWT from your own issuer in the `X-Canton-Auth` header.

The OAuth client material behind a Stage 2 tenant binding is never
returned by this RPC.

### `tenzro_revokeMyApiKey`

```bash
curl -s -X POST https://rpc.tenzro.xyz \
  -H "content-type: application/json" \
  -H "X-Tenzro-Api-Key: tnz_3v8q7s2XQYf..." \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tenzro_revokeMyApiKey",
    "params": {"key_id": "a1b2c3d4e5f60718"}
  }'
```

You may revoke any `subject`-class key whose subject matches yours,
including the key you presented (after which you'll need to ask the
operator for a new one). The error for "this key_id does not exist
on this node" and "it exists but belongs to a different subject" is
intentionally identical, so ownership of keys you don't hold cannot
be probed.

`operator_internal` and `operator_protected` keys are not
subject-revokable and return `-32004`.

## Developer: using a key

Once an operator hands you a `tnz_...` key, present it in the
`X-Tenzro-Api-Key` header on every scoped call. No other auth is
required.

```bash
curl -s -X POST https://rpc.tenzro.xyz \
  -H "content-type: application/json" \
  -H "X-Tenzro-Api-Key: tnz_3v8q7s2XQYf..." \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listCantonDomains","params":[]}'
```

The Tenzro node verifies your key against `CF_API_KEYS`, confirms the
required scope (`canton` for this method), and forwards the request
upstream using its own Auth0 JWT. You never touch Auth0.

### Client tooling

Every Tenzro client tool reads `TENZRO_API_KEY` from the environment
and adds the header automatically:

```bash
export TENZRO_API_KEY=tnz_3v8q7s2XQYf...

tenzro canton domains
tenzro canton contracts --template-id "..."
```

CLI flags (`--api-key`) override the env var when set explicitly.

The Rust SDK, TypeScript SDK, and OpenClaw Python skill follow the
same convention — see their respective READMEs for per-language
configuration.

Self-management (subject-gated) commands live under `tenzro key`:

```bash
tenzro key list-mine                            # uses TENZRO_API_KEY
tenzro key revoke-mine --key-id a1b2c3d4e5f60718
```

Operator-side tooling lives under `tenzro admin`:

```bash
export TENZRO_ADMIN_TOKEN=...
tenzro admin api-key create --label "alice-laptop" --subject "did:tenzro:human:alice"
tenzro admin api-key list
tenzro admin api-key revoke --key-id a1b2c3d4e5f60718
```

## Errors

| Code     | Message                                                                                              | Cause                                                                                                  |
|----------|------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `-32001` | `Unauthorized: operator admin gate is fail-closed (TENZRO_ADMIN_TOKEN not configured on this node)`  | Admin RPC called on a node started without the operator token                                          |
| `-32001` | `Unauthorized: ...admin token...`                                                                    | Admin RPC called without / with a wrong `X-Tenzro-Admin-Token`                                          |
| `-32004` | `missing X-Tenzro-Api-Key header (required scope: ...)`                                              | Scoped RPC called without an API key                                                                   |
| `-32004` | `API key is unknown or revoked`                                                                      | Key not in `CF_API_KEYS` or `revoked_at` is set                                                        |
| `-32004` | `API key lacks required scope (...)`                                                                 | Key exists but lacks the scope the RPC requires                                                        |
| `-32004` | `no active key with that key_id belongs to your subject`                                             | Subject-gated revoke targeted a non-existent or different-subject key                                  |
| `-32004` | `key is not subject-revokable (operator-internal or operator-protected class)`                       | Subject-gated revoke targeted a non-subject class                                                      |
| `-32004` | `operator-protected key cannot be revoked via RPC (rotate the operator secret + restart the node)`   | Admin attempted to revoke an `operator_protected` key                                                  |
| `-32004` | `Unauthorized: tier '...' is read-only; ... requires tier standard or higher`                        | A `free` key called a mutating method                                                                  |
| `-32004` | `Unauthorized: this API key authorizes no Canton network; ask the operator to reissue it naming canton_networks` | Canton-scoped RPC with a key whose `canton_networks` is empty                                |
| `-32004` | `Unauthorized: this API key does not authorize Canton network '...' (authorized: ...)`               | Explicit `canton_network` outside what the key authorizes                                               |
| `-32005` | `Rate limit exceeded: tier '...' allows N requests per minute; retry after M ms`                     | Key over its per-minute budget. `data` carries `retry_after_ms`, `requests_per_minute`, `tier`.          |
| `-32602` | `Unknown scope: ...`                                                                                 | `createApiKey` called with a scope the node doesn't know                                               |
| `-32602` | `Unknown tier: ... (expected free \| standard \| priority)`                                          | `createApiKey` called with an unknown `tier`                                                            |
| `-32602` | `Unknown canton network: ... (expected devnet \| mainnet)`                                           | `createApiKey` called with an unknown entry in `canton_networks`                                        |
| `-32602` | `This node does not serve Canton network '...' (available: ...)`                                     | `createApiKey` named a network this node has no Canton config for                                       |
| `-32602` | `... requires the key to authorize exactly one Canton network ...`                                   | Canton-side provisioning requested with a multi-network key — a party exists on one ledger only          |
| `-32602` | `Unknown canton_network: ... (expected devnet \| mainnet)`                                           | A request passed an unknown `canton_network` param                                                      |
| `-32602` | `This API key authorizes N Canton networks; name the target with the canton_network param (authorized: ...)` | Multi-network key called a Canton RPC without naming the network               |
| `-32603` | `API key manager is not initialized`                                                                 | Node started without admin token (admin-only feature off)                                              |

## Rotation

Rotating a `subject` key:

1. Operator issues a new key for the same subject.
2. Operator hands the new key to the developer out of band.
3. Developer cuts over.
4. Developer self-revokes the old key (`tenzro_revokeMyApiKey`) or the
   operator revokes it (`tenzro_revokeApiKey`).

The two keys can be in flight simultaneously — there is no enforced
limit on active keys per subject.

Rotating an `operator_protected` key: update the secret store and
restart the node. There is no RPC path. The node's wrapper script
(systemd `tenzro-node.service` on the testnet fleet) reloads the
secret on boot.

Rotating the **admin token** is a node-level operation: update the
operator secret store and restart the node. Whatever secret-manager
procedure the operator uses for the node's other boot secrets applies
unchanged.

## Operational notes

- **Rate limiting is per key, not per upstream.** Every api-key-gated
  request counts against that key's own sliding 60-second window, so a
  noisy key exhausts its own budget rather than a shared one. The
  budget comes from the key's [tier](#tiers).
- **Per-request audit (which `key_id` made which call) is not yet
  surfaced** in node logs. Tracked.
- **Self-service issuance is not exposed.** There is no public portal
  for minting keys; issuance is per-operator by design. The
  same admin RPCs can be wrapped by an internal ops bot or
  onboarding agent — see the MCP `create_api_key` tool for the
  agent-driven path.
- **Network-wide changes** (validator set, treasury, fee schedule,
  system contracts, protocol parameters) do not flow through the
  admin token at all. Those go through `tenzro-token` governance
  proposals and stake-weighted voting; the admin token only controls
  state local to the node it lives on.
