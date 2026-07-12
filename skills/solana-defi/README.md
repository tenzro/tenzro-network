# Solana DeFi Skill

Solana ecosystem skill for the Tenzro Network. Backed by the Tenzro Solana MCP server, which exposes Jupiter swaps, SPL token balances and transfers, Metaplex DAS NFT queries, Bonfida SNS domain resolution, and network telemetry.

## MCP backend

| Field | Value |
|---|---|
| Server | Tenzro Solana MCP server |
| Port | 3003 |
| Testnet endpoint | `https://solana-mcp.tenzro.xyz/mcp` |
| Local endpoint | `http://localhost:3003/mcp` |
| Transport | Streamable HTTP |

## Tools (14)

`solana_swap` (Jupiter), `solana_get_price`, `solana_stake`, `solana_get_yield`, `solana_get_balance`, `solana_get_token_accounts`, `solana_transfer`, `solana_get_token_info`, `solana_get_nft` (Metaplex DAS), `solana_get_nfts_by_owner`, `solana_get_slot`, `solana_get_tps`, `solana_get_transaction`, `solana_resolve_domain` (Bonfida SNS).

See [`SKILL.md`](SKILL.md) for the full reference, payload shapes, and curl examples.

## Skill registration

This skill is registered in the Tenzro Skills Registry (`CF_SKILLS`) at node startup as:

| Field | Value |
|---|---|
| Skill ID | `solana-defi` |
| Category | `defi` |
| Tags | `solana, defi, swap, jupiter, nft, metaplex, spl` |

Discover it from any Tenzro node via `tenzro_listSkills` / `tenzro_searchSkills` and invoke its tools through the MCP endpoint above.

## Quick Start

```bash
curl -X POST https://solana-mcp.tenzro.xyz/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"solana_get_slot","arguments":{}}}'
```

## License

Apache-2.0
