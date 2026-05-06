# deBridge Cross-Chain Skill

deBridge DLN (DLN = Decentralized Liquidity Network) intent-based cross-chain skill for the Tenzro Network. Backed directly by the official deBridge MCP server.

## MCP backend

| Field | Value |
|---|---|
| Server | deBridge MCP server (external, official) |
| Endpoint | `https://agents.debridge.com/mcp` |
| Transport | Streamable HTTP |
| Auth | None |

## Tools

deBridge intent-based DLN tooling for cross-chain swaps, token search, supported chains, transaction creation, and same-chain swap routing. The Tenzro JSON-RPC and Rust SDK also expose `debridge_*` wrappers (see `tenzro-sdk::debridge` and the OpenClaw skill's `debridge_*` commands) that round-trip through this MCP server.

## Skill registration

This skill is registered in the Tenzro Skills Registry (`CF_SKILLS`) at node startup as:

| Field | Value |
|---|---|
| Skill ID | `debridge-cross-chain` |
| Category | `bridge` |
| Tags | `debridge, cross-chain, bridge, dln, intent` |

Discover it from any Tenzro node via `tenzro_listSkills` / `tenzro_searchSkills` and invoke its tools through the deBridge MCP endpoint above.

## Quick Start

```bash
curl -X POST https://agents.debridge.com/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## License

Apache-2.0
