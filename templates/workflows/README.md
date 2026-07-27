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
| `research-then-trade.json` | Knowledge query → model analysis → tool call (trade) |
| `canton-settlement.json` | AP2 mandate pair → DAML create → receipt |
| `rwa-custody-onboarding.json` | Knowledge query → identity register → custody bind |
| `cross-chain-arbitrage.json` | Knowledge (bridge fees + two prices) → model sizing → ERC-7683 origin |
| `agent-spawn-tree.json` | Parent agent spawns 3 child specialists |
| `data-aggregation-pipeline.json` | Two knowledge sources → embed each → DA publish |
| `autonomous-monitor.json` | Knowledge poll → model condition check → alert → wait |

## Reading the result

A run's result is `run.step_outputs`: one entry per step, keyed by that
step's `output_as` binding. Each template's `expected_outputs` describes
that map, so the keys you see there are the keys you read back.

## Inputs a template cannot carry

A template pins the node-native operations it calls, but it cannot pin a
third-party knowledge base, tool, or agent template — those ids are
specific to the registry the node can reach. Every such id is a
`required_inputs` entry, discovered at instantiation time with
`tenzro_listKnowledge`, `tenzro_listTools`, or
`tenzro_listAgentTemplates`. Signed material is the same: an AP2 mandate
is produced by the controller's wallet, so `canton-settlement.json` takes
its `checkout_vdc` / `payment_vdc` as inputs rather than embedding them.

Inputs are checked against `required_inputs` before the instantiation
fee is charged. A missing input, a value of the wrong JSON type, or a
value outside a declared `enum` returns `-32602` and costs nothing.

## Node-native operations these templates pin

| Tool id | Backs |
|---|---|
| `tool-canton-submit-mandate` | AP2-gated DAML command submission |
| `tool-identity-register` | TDIP identity registration |
| `tool-da-publish` | Blob publish to the node's data-availability backend |
| `tool-erc7683-origin` | Opening an ERC-7683 origin order |

Each is registered by the node itself, so the id is stable across
operators. `tool-canton-submit-mandate` is registered only when the node
has Canton configured, and `tool-da-publish` only when its blob backend
is bound — `tenzro_listTools` reflects what the node you are talking to
actually offers.

The model steps pin catalog ids: `qwen3-8b` for text, and
`qwen3-embedding-0.6b` for the embedding steps in
`data-aggregation-pipeline.json`. A step carrying `input` rather than
`prompt` is served by the text-embedding runtime; the model has to be
loaded on the serving node first.

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
