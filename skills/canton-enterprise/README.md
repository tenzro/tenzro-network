# Canton Enterprise Skill

Canton (DAML 3.x) enterprise skill for the Tenzro Network. Backed by the Tenzro Canton MCP server, which covers JSON Ledger API v2 command submission, contract and event queries, party allocation, CIP-56 token balances and transfers, DvP settlement, DAR upload, and fee schedules.

## MCP backend

| Field | Value |
|---|---|
| Server | Tenzro Canton MCP server |
| Port | 3005 |
| Testnet endpoint | `https://canton-mcp.tenzro.xyz/mcp` |
| Local endpoint | `http://localhost:3005/mcp` |
| Transport | Streamable HTTP |

## Tools (15)

`canton_submit_command` (JSON Ledger API v2), `canton_list_contracts`, `canton_get_events`, `canton_get_transaction`, `canton_allocate_party`, `canton_list_parties`, `canton_list_domains`, `canton_get_health`, `canton_get_balance` (CIP-56), `canton_transfer`, `canton_create_asset`, `canton_dvp_settle`, `canton_upload_dar`, `canton_get_fee_schedule`.

See [`SKILL.md`](SKILL.md) for the full reference, payload shapes, and curl examples.

## Skill registration

This skill is registered in the Tenzro Skills Registry (`CF_SKILLS`) at node startup as:

| Field | Value |
|---|---|
| Skill ID | `canton-enterprise` |
| Category | `enterprise` |
| Tags | `canton, daml, enterprise, tokenization, dvp, cip56` |

Discover it from any Tenzro node via `tenzro_listSkills` / `tenzro_searchSkills` and invoke its tools through the MCP endpoint above.

## Quick Start

```bash
curl -X POST https://canton-mcp.tenzro.xyz/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"canton_list_domains","arguments":{}}}'
```

## License

Apache-2.0
