# Resources and MCP Host

Tenzro Network is a substrate where agents discover and use **resources** — AI models, MCP servers, knowledge sources, workflow templates, agent templates, and tools — paid for in TNZO. Operators host these resources on their nodes. Tenants present an API key, discover what's available, invoke what they need, and pay per use.

This guide covers the resource registries, the MCP plugin host, the unified discovery surface, and the child-agent spawn flow.

## Resource classes

| Class | Column family | What it is | Discovery RPC | Use RPC |
|---|---|---|---|---|
| Tool | `CF_TOOLS` | MCP server, API endpoint, native capability | `tenzro_listTools` | `tenzro_useTool` |
| Skill | `CF_SKILLS` | Declarative capability descriptor | `tenzro_listSkills` | `tenzro_useSkill` |
| Knowledge | `CF_KNOWLEDGE` | Queryable data (vector DB, feed, corpus, index) | `tenzro_listKnowledge` | `tenzro_useKnowledge` |
| Workflow template | `CF_WORKFLOW_TEMPLATES` | Reusable multi-step blueprint | `tenzro_listWorkflowTemplates` | `tenzro_instantiateWorkflow` |
| Agent template | `CF_AGENT_TEMPLATES` | Reusable agent spec | `tenzro_listAgentTemplates` | `tenzro_spawnAgentFromTemplate` |
| Model | `CF_MODELS` | AI inference (LLM, forecast, vision, audio, video, embed, segment, detect) | `tenzro_listModels` | `tenzro_chat`, modality RPCs |

The **unified discovery surface** collapses all six into one query — see [Unified resource discovery](#unified-resource-discovery) below.

## Built-in resources

Every node registers a set of skills and tools under the creator DID `did:tenzro:system:tenzro-network`, priced at zero. Some point at a remote MCP endpoint; the rest use the `builtin://` scheme and run inside the node that serves them, with no outbound hop. Boot-time reconciliation owns their lifecycle: matching rows are refreshed in place (preserving id, creation time, and usage counters), missing rows inserted, and rows from a prior configuration deleted.

### Built-in skills on `builtin://`

| Skill | What it dispatches to | Input |
|---|---|---|
| `web-search` | The operator's SearXNG-compatible JSON endpoint | `query`, optional `limit` (1–50, default 10), `categories`, `language`, `time_range`, `page`, `safesearch` |
| `code-review` | Intent-based model routing, `use_case: code` | `text` |
| `data-analysis` | Intent-based model routing, `use_case: reasoning` | `text` |
| `text-summarization` | Intent-based model routing, `use_case: summarize` | `text` |
| `blockchain-query` | The node's own ledger reads | `operation`: `balance` \| `nonce` \| `block` \| `transaction` \| `block_number` \| `status`, plus that operation's params |
| `oneinch-aggregator` | 1inch classic swap, with the operator's key | `operation`: `quote` \| `swap` \| `tokens` \| `liquidity_sources` \| `approve_spender` \| `approve_transaction` \| `approve_allowance` |
| `tenzro-trainer` | The node's Tenzro Train handlers | `operation`: `post_task` \| `list_runs` \| `get_run` \| `get_receipt` \| `enroll_trainer` \| `submit_gradient` \| `finalize_round` \| `decide_round` \| `challenge_commitment` \| `install_sealed_manifest` \| `get_sealed_manifest` |

The three model-routed skills pin no model — the router selects one from what the node can reach. They forward `budget`, `optimize`, `quality_floor`, `est_input_tokens`, `est_output_tokens`, `max_tokens` and `temperature` when the caller sets them, so a skill invocation has the same reach as a direct `tenzro_chatByIntent` call.

### Built-in tools on `builtin://`

| Tool | `tool_name` | Params |
|---|---|---|
| `web-search-mcp` | `web_search` | Same as the `web-search` skill |
| | `url_fetch` | `url` (http/https), optional `max_bytes` (1–4194304, default 262144) |
| `code-executor` | `execute_component` | `component_b64`, optional `function` (default `invoke`), optional `input`, optional `deadline_ms`, optional `fuel_limit` |
| `file-manager` | `read` \| `write` \| `list` \| `delete` | `path`, relative, plus `content` on `write` |

`code-executor` runs a WASI 0.2 component under the sandbox's fuel and deadline budget. The bytes are re-hashed on registration, so the `component_id` reported back is the content address of exactly what executed, and the registration is dropped when the call returns. `function` names an export inside the `tenzro:skill/skill@1.0.0` interface. The languages the tool advertises are the languages a component is compiled from, not source text the node interprets.

`file-manager` roots every path at `<data_dir>/agent_workspace`. Absolute paths and any `..` component are rejected.

### Operator upstreams

Two built-in skills and one built-in tool call something the operator supplies. Configure them under `[builtins]` in the node config TOML:

```toml
[builtins]
# SearXNG-compatible JSON search endpoint. Backs the `web-search` skill
# and the `web_search` call on the `web-search-mcp` tool.
search_url = "https://search.example.org"
search_api_key = "..."          # optional bearer token

# 1inch Developer Portal key. Backs the `oneinch-aggregator` skill.
oneinch_api_key = "..."
```

A node that has not configured an upstream does not register the corresponding built-in, so discovery lists only what that node can serve. Remove a key and the row disappears at the next start. `code-executor` follows the same rule against the component sandbox: a node built without it does not register the tool.

## Published skills

Anyone can publish to `CF_SKILLS` through `tenzro_registerSkill`. A published skill takes one of two forms, and the form decides where the code runs.

| Form | Field | Who runs the code |
|---|---|---|
| Endpoint | `endpoint` — an HTTP, MCP, or A2A URL, or `builtin://<name>` | The publisher's host, or the node itself for `builtin://` |
| Bundle | `bundle` — a content-addressed WASI 0.2 component | The node serving the invocation, inside the component sandbox |

A row that names neither is refused at invocation with `-32603` before settlement, so it costs the caller nothing.

### Bundle form

```json
{
  "bundle": {
    "uri": "tenzro://blob/<blake3-hex>",
    "sha256": "<sha256-hex>",
    "size_bytes": 481232
  }
}
```

The two digests serve different parties. The `tenzro://blob/` locator is BLAKE3, which the transport verifies on read. `sha256` is the digest the publisher declares and the one a caller pins through `expected_sha256`; the node re-hashes the fetched bytes against it before anything executes. A mismatch returns `-32006` carrying both the declared and the actual digest.

Registry admission is permissionless, so a published bundle is untrusted code from an unknown author. The sandbox is the boundary a caller relies on: the component runs with no filesystem, no network, no environment and no host methods, under a 50,000,000-fuel budget and a ten-second deadline. `required_capabilities` on the skill row is a discovery tag the publisher writes, not a grant — an operator who wants a skill to reach anything beyond its own JSON hosts it behind an endpoint they control instead.

The guest contract is one `invoke` export inside the `tenzro:skill/skill@1.0.0` interface, taking a JSON request string and returning a JSON response string. `tenzro_useSkill` returns the guest's JSON under `output` and the execution record under `sandbox`:

```json
{
  "output": {},
  "sandbox": {
    "content_hash": "<sha256-hex>",
    "bundle_uri": "tenzro://blob/<blake3-hex>",
    "receipt": {
      "component_id": "skill:<skill_id>:<invocation_id>",
      "content_hash_hex": "<sha256-hex>",
      "function": "invoke",
      "input_hash_hex": "<sha256-hex>",
      "output_hash_hex": "<sha256-hex>",
      "outcome": "success",
      "fuel": {
        "budget": 50000000,
        "consumed": 182344,
        "remaining": 49817656,
        "elapsed": { "secs": 0, "nanos": 41230000 }
      },
      "completed_at_ms": 1769472000000
    }
  }
}
```

`outcome` is one of `success`, `trapped`, `fuel-exhausted`, `deadline-exceeded`, `host-contract-violation`. Each invocation registers under its own id so concurrent calls against one skill never contend, while the content hash stays the identity the receipt binds.

### Pinning an invocation

Because a publisher can update their own row, a caller that needs certainty names what it expects. `expected_version` and `expected_sha256` are checked against the row ahead of settlement; a mismatch is refused rather than silently substituted.

```bash
tenzro skill use <skill_id> \
  --expected-version 1.4.0 \
  --expected-sha256 <sha256-hex> \
  --input '{"query":"..."}'
```

## MCP Plugin Host

The plugin host lets operators run custom and third-party MCPs (Stripe MCP, Plaid MCP, GitHub MCP, Linear MCP, Notion MCP, payment-rail MCPs, custody MCPs, data-feed MCPs, or operator-built ones) on their node without forking the codebase.

### Transport modes

| `tool_type` | When to use | Required fields |
|---|---|---|
| `mcp` | Hosted remote MCP over JSON-RPC 2.0 Streamable HTTP | `endpoint` |
| `mcp-stdio` | Local MCP subprocess (npm package, executable) | `spawn_spec` |
| `mcp-sse` | Legacy SSE transport | `endpoint` |
| `api` | OpenAPI / REST endpoint that accepts JSON POST | `endpoint` |
| `native` | Built-in node capability | — |

### Operator credential vault

Operator's upstream credentials (payment-processor secrets, model-provider API keys, premium data-feed subscriptions, etc.) are stored in the node's sealed credential vault. The vault is AES-256-GCM at rest, keyed by per-secret HKDF-derived material rooted at one of:

1. **Operator-supplied master secret** — set `mcp_plugin_host.master_secret_hex` (64-char hex) in the node config TOML. Recommended for production multi-tenant operators.
2. **Auto-derived from node identity** — when no master secret is configured, the vault root IKM is derived from the node's persistent identity. Suitable for single-operator dev nodes.

Tenants never see operator credentials. The plaintext is read from the vault at invocation time, injected into the outbound MCP request (or subprocess env var), and zeroized from memory after the call completes.

### Storing a credential (operator only)

```bash
curl -X POST $RPC_URL \
  -H "X-Tenzro-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_storeMcpSecret",
    "params": {
      "sealed_secret_ref": "openai_api_key_v1",
      "plaintext": "sk-proj-..."
    },
    "id": 1
  }'
```

The `sealed_secret_ref` is an opaque label of the operator's choosing — they reference it later from the MCP registration. To rotate, store the new secret under a fresh `sealed_secret_ref` and update the MCP's registration to point at the new ref.

To delete:

```bash
curl -X POST $RPC_URL \
  -H "X-Tenzro-Admin-Token: $ADMIN_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"tenzro_forgetMcpSecret","params":{"sealed_secret_ref":"openai_api_key_v1"},"id":1}'
```

### Registering an MCP (operator)

Three flavours below. All take TNZO `price_per_call` (atto-TNZO) and a `creator_wallet` for the operator's payout share.

#### Remote Streamable HTTP MCP

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_registerTool",
  "params": {
    "name": "anthropic-context-mcp",
    "version": "1.0.0",
    "tool_type": "mcp",
    "endpoint": "https://mcp.anthropic.com/v1",
    "description": "Anthropic-hosted context MCP",
    "category": "ai",
    "capabilities": ["context", "memory"],
    "creator_did": "did:tenzro:machine:operator-xyz",
    "creator_wallet": "0x...",
    "price_per_call": "1000000000000000",
    "upstream_auth": {
      "kind": "bearer",
      "sealed_secret_ref": "anthropic_api_key_v1"
    }
  },
  "id": 1
}
```

#### Stdio subprocess MCP

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_registerTool",
  "params": {
    "name": "stripe-mcp",
    "version": "1.0.0",
    "tool_type": "mcp-stdio",
    "endpoint": "stripe-mcp-local",
    "description": "Stripe MCP — payment intents, customers, charges",
    "category": "payments",
    "capabilities": ["payment_intents", "customers", "subscriptions"],
    "creator_did": "did:tenzro:machine:operator-xyz",
    "creator_wallet": "0x...",
    "price_per_call": "2000000000000000",
    "spawn_spec": {
      "command": "npx",
      "args": ["-y", "@stripe/mcp", "--tools=all"],
      "env": {
        "LOG_LEVEL": "info"
      },
      "persistent": true
    },
    "upstream_auth": {
      "kind": "env_var",
      "env_var_name": "STRIPE_API_KEY",
      "sealed_secret_ref": "stripe_api_key_v1"
    }
  },
  "id": 1
}
```

The subprocess is spawned on first use, kept alive across calls, and auto-respawned on detected exit. Set `persistent: false` to spawn per-call (slower, used for compliance scenarios).

#### API endpoint (non-MCP)

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_registerTool",
  "params": {
    "name": "bloomberg-prices",
    "version": "1.0.0",
    "tool_type": "api",
    "endpoint": "https://bloomberg.example.com/api/prices",
    "category": "finance",
    "capabilities": ["prices", "us-equities"],
    "creator_wallet": "0x...",
    "price_per_call": "5000000000000000",
    "upstream_auth": {
      "kind": "header",
      "header_name": "X-API-Key",
      "sealed_secret_ref": "bloomberg_api_key_v1"
    }
  },
  "id": 1
}
```

### Using an MCP (tenant)

```bash
curl -X POST $RPC_URL \
  -H "X-Tenzro-Api-Key: tnz_..." \
  -d '{
    "jsonrpc":"2.0",
    "method":"tenzro_useTool",
    "params":{
      "tool_id": "tool-abc-123",
      "tool_name": "search",
      "params": { "query": "TLS handshake" },
      "payer_wallet": "0x..."
    },
    "id":1
  }'
```

The plugin host fetches the operator's sealed credential, dispatches to the upstream MCP, settles the TNZO payment (5% to treasury, 95% to operator's `creator_wallet`), and returns the MCP response.

## Knowledge registry

For queryable data resources — vector DBs (managed or operator-hosted), RAG indices, document corpora, indexed historical datasets, live data feeds (decentralized oracles, premium market data, oracle aggregators), embedding stores. The pattern mirrors tools but with knowledge-specific metadata.

### Registering a knowledge resource

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_registerKnowledge",
  "params": {
    "name": "us-equities-pricefeed",
    "version": "2.0.0",
    "kind": "feed",
    "endpoint": "https://feeds.example.com/v1/us-equities",
    "description": "Real-time US equities price feed",
    "category": "finance",
    "capabilities": ["prices", "us-equities", "real-time"],
    "creator_wallet": "0x...",
    "price_per_call": "500000000000000",
    "params_schema": {
      "type": "object",
      "properties": { "symbol": {"type": "string"} },
      "required": ["symbol"]
    },
    "response_schema": {
      "type": "object",
      "properties": {
        "symbol": {"type": "string"},
        "bid": {"type": "number"},
        "ask": {"type": "number"},
        "ts": {"type": "integer"}
      }
    }
  },
  "id": 1
}
```

When `backing_tool_id` is set on a knowledge resource, invocations dispatch through the named tool — useful when the same underlying MCP serves both as a tool and as a knowledge query surface.

### Using a knowledge resource

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_useKnowledge",
  "params": {
    "knowledge_id": "k-abc-123",
    "params": { "symbol": "SOL/USD" },
    "payer_wallet": "0x..."
  },
  "id": 1
}
```

## Workflow template catalog

Reusable workflow blueprints. Anyone with a Tenzro DID publishes one via `tenzro_registerWorkflowTemplate` — there is no operator approval step. Callers discover via `tenzro_listWorkflowTemplates` and instantiate via `tenzro_instantiateWorkflow`.

### Step types

Each step in a workflow template is one of:

- `use_tool` — invoke a registered tool / MCP
- `use_model` — invoke a registered model
- `use_knowledge` — query a knowledge resource
- `spawn_agent` — create a child agent under a sub-budget
- `wait` — sleep / await external signal / await on-chain event
- `compound` — branch or parallel fan-out, referencing other step indices

Step outputs can be referenced from later steps via `output_as` bindings.

### Registering a template

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_registerWorkflowTemplate",
  "params": {
    "name": "research-then-trade",
    "version": "1.0.0",
    "description": "Query price feed, generate analysis with LLM, execute trade",
    "category": "trading",
    "creator_wallet": "0x...",
    "price_per_instantiate": "10000000000000000",
    "required_inputs": {
      "type": "object",
      "properties": {
        "symbol": {"type": "string"},
        "max_position_size": {"type": "string"}
      },
      "required": ["symbol", "max_position_size"]
    },
    "expected_outputs": {
      "type": "object",
      "properties": {
        "trade_executed": {"type": "boolean"},
        "fill_price": {"type": "string"}
      }
    },
    "steps": [
      {
        "kind": "use_knowledge",
        "knowledge_id": "k-pricefeed-001",
        "params": { "symbol": "{{ inputs.symbol }}" },
        "output_as": "price_quote"
      },
      {
        "kind": "use_model",
        "model_id": "qwen3-7b",
        "params": {
          "prompt": "Given price quote {{ steps.price_quote.output }}, should we buy?"
        },
        "output_as": "analysis"
      },
      {
        "kind": "use_tool",
        "tool_id": "trade-execution-mcp",
        "tool_name": "submit_order",
        "params": { "symbol": "{{ inputs.symbol }}", "side": "{{ steps.analysis.output.recommendation }}" }
      }
    ]
  },
  "id": 1
}
```

### Instantiating a template

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_instantiateWorkflow",
  "params": {
    "template_id": "wf-tpl-abc-123",
    "inputs": { "symbol": "SOL/USD", "max_position_size": "100" },
    "payer_wallet": "0x..."
  },
  "id": 1
}
```

Returns a `workflow_id` for status polling via `tenzro_getWorkflow`.

## Unified resource discovery

Collapses all six registries into one query.

### Listing all resources

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_listResources",
  "params": {
    "classes": ["tool", "knowledge", "model"],
    "capability_tags": ["prices", "finance"],
    "max_tnzo_price": "10000000000000000",
    "query": "us equities",
    "limit": 50
  },
  "id": 1
}
```

Returns an array of `ResourceDescriptor`:

```json
[
  {
    "class": "knowledge",
    "resource_id": "k-pricefeed-001",
    "name": "us-equities-pricefeed",
    "version": "2.0.0",
    "description": "Real-time US equities price feed",
    "category": "finance",
    "capabilities": ["prices", "us-equities", "real-time"],
    "creator_did": "did:tenzro:machine:operator-xyz",
    "creator_wallet": "0x...",
    "price_per_call": "500000000000000",
    "is_available": true,
    "last_seen_at": 1717977600,
    "subtype": "feed"
  }
]
```

### Invoking by resource_id (auto-detect class)

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_useResource",
  "params": {
    "resource_id": "k-pricefeed-001",
    "params": { "symbol": "SOL/USD" },
    "payer_wallet": "0x..."
  },
  "id": 1
}
```

The dispatcher auto-detects which registry holds the `resource_id` and routes to the per-class handler.

Pass `class` explicitly to skip auto-detect:

```json
{
  "resource_id": "k-pricefeed-001",
  "class": "knowledge",
  "params": { "symbol": "SOL/USD" }
}
```

## Per-tenant scoping

Tenant API keys carry per-resource-class allow-lists. When a key has a non-empty allow-list for a class, only resource ids in that list are invokable; any other invocation returns `-32004 Unauthorized`. Per-resource TNZO ceilings let an operator further cap what any one resource invocation may charge against a key.

The full set of allow-list fields on `tenzro_createApiKey`:

- `allowed_tools` — tool / MCP resource_ids
- `allowed_skills` — skill_ids
- `allowed_knowledge` — knowledge resource_ids
- `allowed_workflow_templates` — workflow template_ids
- `allowed_agent_templates` — agent template_ids
- `allowed_models` — model_ids
- `max_per_resource_tnzo` — `{ "<resource_id>": "<atto_tnzo>" }` per-resource cap

All optional. An empty field leaves that class unrestricted for the key. See [api-keys.md](api-keys.md) for the full API key issuance reference.

## Controller oversight of agent spend

Per-tenant scoping is the operator's leash: it bounds what any holder of a
given API key may invoke. Controller oversight is the other leash, and it
belongs to the agent's identity rather than to the key the agent happens to
hold — so it travels with the agent across every operator's registry.

A controller expresses it two ways, both carried on the agent's DPoP-bound
JWT:

- A `resource_invocation` grant in `authorization_details` (RFC 9396) caps
  what the agent may spend per invocation, and optionally narrows it to one
  resource class and a set of resource ids:

  ```json
  {
    "type": "resource_invocation",
    "max_amount_per_call": "1000000000000000",
    "class": "skill",
    "allowed_resource_ids": ["web-search"]
  }
  ```

  Omitting `class` permits any class; omitting `allowed_resource_ids`
  permits any id within the class. An invocation the grant does not cover
  returns `-32001` with the denial reason.

- Listing `resource.invoke` in the AAP oversight claim's
  `requires_human_approval_for` parks every paid invocation for a human. The
  call returns `-32002` with the new record under `data.approval_id`; the
  controller rules on it, and the agent retries the same call with
  `approval_id` in its params.

The gate runs immediately before settlement on `tenzro_useSkill`,
`tenzro_useTool`, `tenzro_useKnowledge`, `tenzro_useResource`, and on the
skill and tool steps a `tenzro_orchestrate` plan runs — a plan spends on the
caller's behalf, so the caller's authority travels into its steps.

Two invocations bypass the gate by design. A free invocation
(`price_per_call` of zero) has no spend to authorize. A request carrying no
authorization headers has no bearer identity, so there is no controller to
consult — which is what keeps the registry permissionless. Such a request is
still bound by the API key's own allow-lists and ceilings.

## Child agent spawn

`tenzro_spawnChildAgent` atomically:

1. Registers a new machine identity (TDIP) with `controller_did = parent_did` and auto-provisions an MPC wallet via `WalletBinder`.
2. Transfers the requested TNZO budget from `parent_wallet` to the child's wallet.
3. Binds a runtime `SpendingPolicy` on `AgentRuntime` so the child's autonomous activity respects `max_per_transaction` and `max_daily_spend`.

```json
{
  "jsonrpc": "2.0",
  "method": "tenzro_spawnChildAgent",
  "params": {
    "parent_did": "did:tenzro:machine:parent-abc",
    "display_name": "trading-subagent-7",
    "tnzo_budget": "100000000000000000",
    "parent_wallet": "0x...",
    "valid_until": 1750000000,
    "max_per_transaction": "10000000000000000",
    "max_daily_spend": "50000000000000000",
    "key_type": "ed25519"
  },
  "id": 1
}
```

Response:

```json
{
  "child_did": "did:tenzro:machine:parent-abc:abc123",
  "parent_did": "did:tenzro:machine:parent-abc",
  "child_wallet": "0x...",
  "registration": { /* full TDIP registration receipt */ },
  "funding": {
    "funded": true,
    "amount": "100000000000000000",
    "from": "0x...",
    "to": "0x..."
  },
  "spending_policy": {
    "applied": true,
    "max_per_transaction": "10000000000000000",
    "max_daily_spend": "50000000000000000"
  }
}
```

Failure semantics: identity registration comes first. If it fails, no funds move. If funding fails after registration, the identity remains (operator can fund later) and the error surfaces explicitly. Spending policy is best-effort.

## TNZO economics

Every paid resource invocation goes through the same commission split:

- **5%** to network treasury (the governance-set marketplace commission, on every paid invocation)
- **95%** to operator's `creator_wallet`

The operator's upstream costs (payment-processor fees, model-provider plans, premium data-feed subscriptions, etc.) are off-protocol — the operator converts TNZO revenue to fiat to pay them. The protocol charges only for network use.

See [TOKENOMICS.md](TOKENOMICS.md) for the full TNZO model.
