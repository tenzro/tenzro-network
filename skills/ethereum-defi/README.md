# Ethereum DeFi Skill

Ethereum ecosystem skill for the Tenzro Network. Backed by the Tenzro Ethereum MCP server, which covers Chainlink price feeds, gas pricing, ENS resolution, ERC-20 balances, EAS attestations, and the ERC-8004 Trustless Agents Registry.

## MCP backend

| Field | Value |
|---|---|
| Server | Tenzro Ethereum MCP server |
| Port | 3004 |
| Testnet endpoint | `https://ethereum-mcp.tenzro.network/mcp` |
| Local endpoint | `http://localhost:3004/mcp` |
| Transport | Streamable HTTP |

## Tools (16)

`eth_get_price` (Chainlink feeds), `eth_get_gas_price`, `eth_estimate_gas`, `eth_get_fee_history`, `eth_get_balance`, `eth_get_token_balance` (ERC-20), `eth_get_transaction`, `eth_get_block`, `eth_get_transaction_receipt`, `eth_resolve_ens`, `eth_lookup_ens`, `eth_call_contract`, `eth_encode_function` (ABI encoding), `eth_register_agent_8004`, `eth_lookup_agent_8004` (ERC-8004), `eth_get_attestation` (EAS).

See [`SKILL.md`](SKILL.md) for the full reference, payload shapes, and curl examples.

## Skill registration

This skill is registered in the Tenzro Skills Registry (`CF_SKILLS`) at node startup as:

| Field | Value |
|---|---|
| Skill ID | `ethereum-defi` |
| Category | `defi` |
| Tags | `ethereum, defi, erc20, ens, chainlink, erc8004, eas` |

Discover it from any Tenzro node via `tenzro_listSkills` / `tenzro_searchSkills` and invoke its tools through the MCP endpoint above.

## Quick Start

```bash
curl -X POST https://ethereum-mcp.tenzro.network/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"eth_get_gas_price","arguments":{}}}'
```

## License

Apache-2.0
