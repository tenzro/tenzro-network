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

Operator-curated reusable workflow blueprints. Tenants discover via `tenzro_listWorkflowTemplates` and instantiate via `tenzro_instantiateWorkflow`.

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

All optional. Empty fields preserve legacy unrestricted access. See [api-keys.md](api-keys.md) for the full API key issuance reference.

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

Failure semantics: identity registration is the load-bearing step. If it fails, no funds move. If funding fails after registration, the identity remains (operator can fund later) and the error surfaces explicitly. Spending policy is best-effort.

## TNZO economics

Every paid resource invocation goes through the same commission split:

- **5%** to network treasury (network commission, on every paid invocation)
- **95%** to operator's `creator_wallet`

The operator's upstream costs (payment-processor fees, model-provider plans, premium data-feed subscriptions, etc.) are off-protocol — the operator converts TNZO revenue to fiat to pay them. The protocol charges only for network use.

See [TOKENOMICS.md](TOKENOMICS.md) for the full TNZO model.
