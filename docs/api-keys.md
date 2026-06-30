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

## The sovereignty model

Tenzro draws a sharp line between two kinds of resources:

| Tier               | Control surface                                                                  | Examples                                                                                                                          |
|--------------------|----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| **Node-scoped**    | Per-node `X-Tenzro-Admin-Token` held by that node's operator                     | API keys, this node's admin token, upstream creds (Auth0 / Canton JWT), what this node serves, local TLS, local secret store      |
| **Network-wide**   | `tenzro-token` `GovernanceEngine` + EVM `0x1005` `GOVERNANCE` precompile         | Validator set, treasury, fee schedule, staking params, TNZO contract, system contracts (ERC-8004, NFT factory), protocol upgrades |

API key issuance lives on the left. **Every node operator is sovereign
over their own node's API keys** — Tenzro Labs (operating
`rpc.tenzro.network`), validator operators (each on their own validator
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

The admin token is held by that node's operator. Developers never see it.

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
   Labs for `rpc.tenzro.network`; a particular validator or
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
curl -s -X POST https://rpc.tenzro.network \
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

### `tenzro_listApiKeys`

```bash
curl -s -X POST https://rpc.tenzro.network \
  -H "content-type: application/json" \
  -H "X-Tenzro-Admin-Token: $TENZRO_ADMIN_TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listApiKeys","params":{}}'
```

Returns `{ "keys": [ <ApiKeyRecord>, ... ] }` — every record, active
and revoked, including its `class`. No plaintext keys are returned
(the node never stores them).

### `tenzro_revokeApiKey`

```bash
curl -s -X POST https://rpc.tenzro.network \
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
curl -s -X POST https://rpc.tenzro.network \
  -H "content-type: application/json" \
  -H "X-Tenzro-Api-Key: tnz_3v8q7s2XQYf..." \
  -d '{"jsonrpc":"2.0","id":1,"method":"tenzro_listMyApiKeys","params":{}}'
```

Returns every active and revoked key issued to *your* subject (resolved
from the presented key). Other subjects' keys are never exposed.

### `tenzro_revokeMyApiKey`

```bash
curl -s -X POST https://rpc.tenzro.network \
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
curl -s -X POST https://rpc.tenzro.network \
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
| `-32602` | `Unknown scope: ...`                                                                                 | `createApiKey` called with a scope the node doesn't know                                               |
| `-32602` | `class=operator_protected requires confirm_operator_protected:true ...`                              | Safety interlock — confirm the class is intended                                                       |
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
operator secret store and restart the node. On the live testnet RPC
node, the canton-network Secret Manager rotation procedure applies.

## Operational notes

- **Per-key rate limiting is not yet enforced.** A noisy key currently
  affects all callers sharing the upstream. Tracked.
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
