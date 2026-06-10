# Reference workflow templates

These seven JSON files are canonical reference templates for the
Tenzro workflow runtime. Operators register them via
`tenzro_registerWorkflowTemplate` and tenants instantiate them via
`tenzro_instantiateWorkflow` or `tenzro_useResource`.

Each template demonstrates a real-world agent workflow pattern. The
step kinds are documented in
[`docs/resources-and-mcp-host.md`](../../docs/resources-and-mcp-host.md).
Variable interpolation is `{{ inputs.X.Y }}` for inputs and
`{{ steps.NAME.output.PATH }}` for prior step outputs.

| Template | Demonstrates |
|---|---|
| `research-then-trade.json` | Knowledge query → LLM analysis → tool call (trade) |
| `canton-settlement.json` | AP2 mandate → multi-party DAML create → receipt |
| `rwa-custody-onboarding.json` | Knowledge query → identity register → custody bind |
| `cross-chain-arbitrage.json` | Knowledge (bridge fees) → LLM quote → ERC-7683 origin |
| `agent-spawn-tree.json` | Parent agent spawns 3 child specialists |
| `data-aggregation-pipeline.json` | 5 knowledge sources → embed → DA store |
| `autonomous-monitor.json` | Periodic price feed → conditional alert |

## Registering all seven

```bash
for f in templates/workflows/*.json; do
  curl -X POST $RPC_URL \
    -H "X-Tenzro-Admin-Token: $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"tenzro_registerWorkflowTemplate\",\"params\":$(cat $f),\"id\":1}"
done
```

## Instantiating

```bash
curl -X POST $RPC_URL \
  -H "X-Tenzro-Api-Key: $TENANT_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "method":"tenzro_instantiateWorkflow",
    "params":{
      "template_id":"<from-registration>",
      "inputs":{...},
      "payer_wallet":"0x..."
    },
    "id":1
  }'
```
