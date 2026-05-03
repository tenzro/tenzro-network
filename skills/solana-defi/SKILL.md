---
name: solana-defi
version: 0.1.0
author: Tenzro Network
description: Solana DeFi skill — swap tokens via Jupiter, get prices, stake SOL, query balances, transfer SPL tokens, browse NFTs via Metaplex DAS, resolve .sol domains, and monitor network health.
tags:
  - solana
  - defi
  - swap
  - jupiter
  - nft
  - metaplex
  - spl
  - staking
  - web3
---

# Solana DeFi Skill

Interact with the Solana blockchain for DeFi operations, token management, NFTs, and network monitoring. All tools are available via the Tenzro Solana MCP Server.

## MCP Endpoint

| Service | URL | Description |
|---------|-----|-------------|
| Solana MCP | `https://solana-mcp.tenzro.network/mcp` | Solana MCP Server (port 3003) |

For local development, use `http://localhost:3003/mcp`.

## Tools

### DeFi — Jupiter Aggregator

#### solana_swap
Get a swap quote from Jupiter aggregator for any SPL token pair.

**Parameters:**
- `input_mint` (string, required) — Input token mint address (e.g. `So11111111111111111111111111111111111111112` for SOL)
- `output_mint` (string, required) — Output token mint address (e.g. `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` for USDC)
- `amount` (string, required) — Amount in smallest unit (lamports for SOL)
- `slippage_bps` (u32, optional, default 50) — Slippage tolerance in basis points

**Example:**
```
solana_swap(input_mint="So11111111111111111111111111111111111111112", output_mint="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", amount="1000000000", slippage_bps=50)
```

**Returns:** Jupiter quote with `inAmount`, `outAmount`, `priceImpactPct`, route plan.

#### solana_get_price
Get current token price from Jupiter Price API.

**Parameters:**
- `token_id` (string, required) — Token symbol or mint address (e.g. "SOL", "USDC", or mint address)

**Returns:** Price in USD, confidence interval.

#### solana_stake
Get staking instructions for native SOL staking or liquid staking via Marinade/Jito.

**Parameters:**
- `amount_sol` (f64, required) — Amount of SOL to stake
- `validator_address` (string, optional) — Validator vote account address

**Returns:** Staking instructions and expected APY.

#### solana_get_yield
Get current DeFi yield rates across Solana protocols (Marinade, Jito, Raydium, Orca, Kamino).

**Returns:** Protocol name, asset, APY, TVL for top yield opportunities.

### Tokens — SPL

#### solana_get_balance
Get SOL balance for an address.

**Parameters:**
- `address` (string, required) — Solana public key (base58)

**Returns:** Balance in SOL and lamports.

#### solana_get_token_accounts
Get all SPL token accounts owned by an address.

**Parameters:**
- `owner_address` (string, required) — Solana public key

**Returns:** List of token accounts with mint, balance, decimals.

#### solana_transfer
Build a SOL or SPL token transfer instruction.

**Parameters:**
- `from` (string, required) — Sender public key
- `to` (string, required) — Recipient public key
- `amount_lamports` (u64, required) — Amount in lamports (1 SOL = 10^9 lamports)

**Returns:** Transfer instruction details.

#### solana_get_token_info
Get token metadata from Jupiter token list.

**Parameters:**
- `mint_address` (string, required) — Token mint address

**Returns:** Token name, symbol, decimals, logo URI, tags.

### NFTs — Metaplex / DAS

#### solana_get_nft
Get NFT metadata from Metaplex Digital Asset Standard API.

**Parameters:**
- `mint_address` (string, required) — NFT mint address

**Returns:** Name, description, image URI, collection, attributes, owner.

#### solana_get_nfts_by_owner
Get all NFTs owned by an address.

**Parameters:**
- `owner_address` (string, required) — Solana public key

**Returns:** List of NFTs with metadata.

### Network

#### solana_get_slot
Get current slot height on Solana.

**Returns:** Current slot number, epoch info.

#### solana_get_tps
Get current transactions per second on Solana.

**Returns:** Average TPS from recent performance samples.

#### solana_get_transaction
Get transaction details by signature.

**Parameters:**
- `signature` (string, required) — Transaction signature (base58)

**Returns:** Full transaction details including instructions, logs, status.

#### solana_resolve_domain
Resolve a .sol domain name to a Solana address via Bonfida SNS.

**Parameters:**
- `domain` (string, required) — Domain name (e.g. "toly.sol")

**Returns:** Resolved Solana address.

## Common Workflows

### Swap SOL for USDC
1. `solana_get_price(token_id="SOL")` — Check current SOL price
2. `solana_get_balance(address="...")` — Check SOL balance
3. `solana_swap(input_mint="So111...2", output_mint="EPjF...1v", amount="1000000000")` — Get quote for 1 SOL → USDC

### Check Portfolio
1. `solana_get_balance(address="...")` — SOL balance
2. `solana_get_token_accounts(owner_address="...")` — All SPL tokens
3. `solana_get_nfts_by_owner(owner_address="...")` — All NFTs

### Monitor Network
1. `solana_get_slot()` — Current slot
2. `solana_get_tps()` — Network throughput
