# Canton agentic feature

Tenzro Network exposes Canton (DAML) as a first-class destination for
autonomous agents. This guide covers the three RPCs that make Canton
agentic: mandate-bound DAML write, scoped-read snapshots, and
operator-only analytics rollup. It complements the operator-side
[CANTON_MULTITENANT.md](operators/CANTON_MULTITENANT.md).

## What's new

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

These compose with the existing Canton surface (`tenzro_submitDamlCommand`,
`tenzro_listDamlContracts`, `tenzro_canton_*`) and with the agent
delegation fields shipped on `tenzro_createApiKey`
([API keys](api-keys.md)).

## Mandate-bound write flow

The autonomous agent presents two things on every Canton write:

1. **A scoped API key** with `can_act_as_parties` populated for the
   parties this agent is allowed to bind. The operator provisioned this
   key with `tenzro_createApiKey`, and the corresponding Canton-side
   `CanActAs` rights were granted atomically.
2. **An AP2 cart mandate pair** — `checkout_vdc` (the principal's
   intent) + `payment_vdc` (the agent's payment authorization). Both
   are W3C Verifiable Credentials signed by the controlling DID.

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

The reference workflow templates ship a Canton-settlement example at
[`templates/workflows/canton-settlement.json`](../templates/workflows/canton-settlement.json).
It's a single-step workflow that wraps `submitWithMandate` so tenants
can instantiate it via `tenzro_useResource` and let the workflow
executor handle the dispatch.

See [Resources](resources-and-mcp-host.md) for the full workflow
runtime model and [Workflow](workflow.md) for the multi-party
obligation-saga layer.

## SDK access

### Rust

```rust
use tenzro_sdk::{TenzroClient, config::SdkConfig};
use tenzro_sdk::canton_agent::{SubmitWithMandateParams, Mandate};

let client = TenzroClient::connect(SdkConfig::testnet()).await?;
let canton = client.canton_agent();

let receipt = canton.submit_with_mandate(SubmitWithMandateParams {
    mandate: Mandate {
        checkout: checkout_vdc_json,
        payment: payment_vdc_json,
    },
    command_type: "create".to_string(),
    template_id: "#Splice.AmuletRules:AmuletRules:Transfer".to_string(),
    create_arguments: Some(serde_json::json!({ "to": "...", "amount": "1000000" })),
    contract_id: None,
    choice: None,
    choice_argument: None,
    act_as: None,
}).await?;
```

### TypeScript

```ts
import { TenzroClient, CantonAgentClient } from '@tenzro/sdk';

const client = new TenzroClient({ rpcUrl: 'https://rpc.tenzro.network' });
const canton = new CantonAgentClient(client.rpc);

const receipt = await canton.submitWithMandate({
  mandate: { checkout: checkoutVdc, payment: paymentVdc },
  command_type: 'create',
  template_id: '#Splice.AmuletRules:AmuletRules:Transfer',
  create_arguments: { to: '...', amount: '1000000' },
});
```

## CLI access

The `tenzro canton` command tree carries the existing surface; the new
agentic RPCs can be invoked directly via any JSON-RPC client. A
dedicated `tenzro canton-agent` command tree lands in a follow-up CLI
update; today, use `tenzro resources use` against a workflow template
that wraps the agentic flow.
