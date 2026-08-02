# Canton for autonomous agents

Tenzro Network exposes Canton (DAML) as a destination an autonomous
agent can write to under a controller's authority. This guide covers the
three RPCs that carry that path — mandate-bound DAML write, scoped-read
snapshots, and operator-only analytics rollup — and how a request selects
its Canton network. It complements the operator-side
[CANTON_MULTITENANT.md](operators/CANTON_MULTITENANT.md).

## The three RPCs

- **`tenzro_canton_submitWithMandate`** — submit a DAML command bound
  to an AP2 mandate pair. The handler validates the cart against AP2
  invariants + TDIP DelegationScope + runtime SpendingPolicy + optional
  on-chain escrow + optional Stripe SPT ceiling. Only when all
  applicable ceilings pass does the DAML command submit.
- **`tenzro_canton_watchParty`** — get the active-contracts snapshot
  for a single party. Gated against the presenting API key's
  `can_read_as_parties` allow-list. Tenants only see parties they're
  authorized to read for.
- **`tenzro_canton_aggregateAnalytics`** — operator admin-read of
  rolled-up per-key Canton call counters, grouped by `subject` or
  `key_id`. Useful for billing + capacity planning.

These compose with the rest of the Canton surface
(`tenzro_submitDamlCommand`, `tenzro_listDamlContracts`,
`tenzro_canton_*`) and with the agent delegation fields on
`tenzro_createApiKey` ([API keys](api-keys.md)).

## Mandate-bound write flow

The autonomous agent presents two things on every Canton write:

1. **A scoped API key** with `can_act_as_parties` populated for the
   parties this agent is allowed to bind. The operator provisioned this
   key with `tenzro_createApiKey`, and the corresponding Canton-side
   `CanActAs` rights were granted atomically.
2. **An AP2 mandate pair** — `checkout_vdc` (the principal's
   pre-authorization) + `payment_vdc` (the agent's payment
   authorization). Both are W3C Verifiable Credentials signed by the
   controlling DID.

Example request body for `tenzro_canton_submitWithMandate`:

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_canton_submitWithMandate",
  "params": {
    "mandate": {
      "checkout": { /* AP2 checkout VDC */ },
      "payment":  { /* AP2 payment VDC */ }
    },
    "command_type": "create",
    "template_id": "#Splice.AmuletRules:AmuletRules:Transfer",
    "create_arguments": {
      "to": "Counterparty::abc123...",
      "amount": "1000000",
      "memo": "settlement-2026-06"
    }
  },
  "id": 1
}
```

The handler executes in this order, fail-closed at every step:

1. Parse the mandate pair (rejects with `-32602` on malformed VDCs).
2. Run AP2 validator with `enforce_delegation=true` — this hits the
   identity registry, the runtime `SpendingPolicy` resolver, the on-chain
   escrow resolver if the mandate names one, and the Stripe SPT cache
   if named. Validation failure returns `-32004` Unauthorized.
3. Forward the stripped command (mandate fields removed) to the
   existing `handle_submit_daml_command` path. Canton's AuthService is
   the second gate — it enforces `CanActAs` rights upstream.
4. Return both receipts: the AP2 receipt and the Canton receipt.

## Scoped read flow

`tenzro_canton_watchParty` is the agent-facing read surface. The agent
specifies the party id and the template ids it cares about:

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_canton_watchParty",
  "params": {
    "party": "TenzroLabs::abc123...",
    "template_ids": ["#Splice.AmuletRules:AmuletRules:Holding"]
  },
  "id": 1
}
```

Authorization: the presenting API key must satisfy
`can_read_as(party)` (which `can_act_as_parties` implies). Without the
matching delegation field, the handler returns `-32004 Unauthorized`.
The response is the canonical active-contracts shape — same row format
as `tenzro_listDamlContracts`, scoped to the specified party.

## Choosing the Canton network

A Canton network is a distinct ledger with distinct parties and assets,
so every canton-scoped request resolves to exactly one. Resolution
order:

1. An explicit `canton_network` param on the request (`"devnet"` or
   `"mainnet"`). An unrecognized value returns `-32602`.
2. The presenting API key's sole authorized network, when it authorizes
   exactly one.
3. The operator's configured default — the admin-token path, which
   skips the API-key gate.

A key that authorizes no network authorizes nothing: `-32004`, and the
operator has to reissue it naming `canton_networks`. A key that
authorizes more than one and names none returns `-32602` listing the
authorized set. Naming a network the key does not authorize returns
`-32004`, also listing the set.

On the MCP surface the same selection arrives as the
`X-Canton-Network` header rather than a param, because MCP tool
arguments belong to the tool's own schema.

The CLI reads `--canton-network`, falling back to the
`TENZRO_CANTON_NETWORK` environment variable. Both SDKs pin a network
per client with `on_network("mainnet")` (Rust) /
`onNetwork('mainnet')` (TypeScript), which injects the param on every
call the returned client makes.

## Operator analytics

`tenzro_canton_aggregateAnalytics` rolls up the per-key counters
`CantonAnalyticsManager` already tracks on every canton-scoped RPC. The
result is bucketed by `subject` (default) or `key_id`:

```json
{
  "buckets": [
    { "key": "did:tenzro:machine:abc...", "total_calls": 12450, "last_called_at": 1717977600 },
    { "key": "did:tenzro:machine:def...", "total_calls": 3187,  "last_called_at": 1717976000 }
  ],
  "row_count": 2,
  "group_by": "subject"
}
```

Use this for billing or for capacity planning. Admin-token-gated —
tenants can't read across each other.

## Workflow templates that hit Canton

[`templates/workflows/canton-settlement.json`](../templates/workflows/canton-settlement.json)
is a single-step reference template over `submitWithMandate`. The step is
a `use_tool` against the node's `tool-canton-submit-mandate` builtin, so
a tenant instantiates the template via `tenzro_useResource` and the
workflow executor dispatches the call.

A template cannot carry a signature, so the mandate pair is not embedded:
`checkout_vdc` and `payment_vdc` are `required_inputs`, supplied at
instantiation from the controller's wallet. The node registers
`tool-canton-submit-mandate` only when it has Canton configured — check
`tenzro_listTools` on the node you are talking to.

See [Resources](resources-and-mcp-host.md) for the full workflow
runtime model and [Workflow](workflow.md) for the multi-party
obligation-saga layer.

## SDK access

Both SDKs carry these three RPCs on their Canton client, alongside the
rest of the Canton surface.

### Rust

```rust
use tenzro_sdk::{TenzroClient, config::SdkConfig};
use tenzro_sdk::canton::CantonMandate;

let client = TenzroClient::connect(SdkConfig::testnet()).await?;
let canton = client.canton().on_network("mainnet");

let mandate = CantonMandate {
    checkout: checkout_vdc_json,
    payment: payment_vdc_json,
};

let receipt = canton
    .create_contract_with_mandate(
        &mandate,
        "#Splice.AmuletRules:AmuletRules:Transfer",
        serde_json::json!({ "to": "...", "amount": "1000000" }),
        None, // `act_as` override
    )
    .await?;

let snapshot = canton
    .watch_party(
        "TenzroLabs::abc123...",
        vec!["#Splice.AmuletRules:AmuletRules:Holding".to_string()],
    )
    .await?;
```

`exercise_choice_with_mandate` is the same call for an `exercise`
command, taking a contract id, choice name and choice argument.

### TypeScript

```ts
import { TenzroClient } from '@tenzro/sdk';

const client = new TenzroClient({ rpcUrl: 'https://rpc.tenzro.xyz' });
const canton = client.canton.onNetwork('mainnet');

const receipt = await canton.submitWithMandate(
  { checkout: checkoutVdc, payment: paymentVdc },
  {
    command_type: 'create',
    template_id: '#Splice.AmuletRules:AmuletRules:Transfer',
    create_arguments: { to: '...', amount: '1000000' },
  },
);

const snapshot = await canton.watchParty('TenzroLabs::abc123...', [
  '#Splice.AmuletRules:AmuletRules:Holding',
]);
```

## CLI access

```bash
tenzro canton submit-with-mandate \
  --checkout-vdc ./checkout.json \
  --payment-vdc ./payment.json \
  --command-type create \
  --template '#Splice.AmuletRules:AmuletRules:Transfer' \
  --create-arguments '{"to":"...","amount":"1000000"}' \
  --canton-network mainnet

tenzro canton watch-party \
  --party 'TenzroLabs::abc123...' \
  --template-id '#Splice.AmuletRules:AmuletRules:Holding'

# Operator admin-read.
tenzro canton aggregate-analytics --group-by subject
```

Both mandate files hold a signed verifiable credential. `--api-key`
reads `TENZRO_API_KEY` and `--canton-network` reads
`TENZRO_CANTON_NETWORK`, so a shell that exports both can omit them.
`aggregate-analytics` takes an admin token (`--admin-token`, or
`TENZRO_ADMIN_TOKEN`) instead of an API key.
