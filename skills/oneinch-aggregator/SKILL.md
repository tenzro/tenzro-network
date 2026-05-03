---
name: oneinch-aggregator
version: 0.1.0
author: Tenzro Network
description: 1inch DEX aggregator skill — swap tokens across 400+ DEXes, get quotes, check token approvals, Fusion+ cross-chain swaps, portfolio tracking. Requires API key from 1inch Developer Portal.
tags:
  - 1inch
  - dex
  - aggregator
  - swap
  - defi
  - fusion
  - cross-chain
---

# 1inch Aggregator Skill

DEX aggregation across 400+ liquidity sources on 12+ chains. Supports instant swaps, limit orders, and Fusion+ cross-chain swaps with MEV protection.

## MCP Endpoint

1inch provides an official MCP server via the 1inch Developer Portal:

| Service | URL | Description |
|---------|-----|-------------|
| 1inch MCP | Via 1inch Business Portal | Official 1inch MCP (requires API key) |
| 1inch API | `https://api.1inch.dev` | REST API (15 endpoints, 1 rps public) |

**Setup:** Obtain an API key from the 1inch Developer Portal and configure it in the Tenzro node settings.

## Supported Chains

| Chain | Chain ID |
|-------|----------|
| Ethereum | 1 |
| BSC | 56 |
| Polygon | 137 |
| Optimism | 10 |
| Arbitrum | 42161 |
| Avalanche | 43114 |
| Base | 8453 |
| zkSync Era | 324 |
| Gnosis | 100 |
| Fantom | 250 |

## Available Tools

### Swap

#### swap_tokens
Get optimal swap route and transaction data across 400+ DEXes.

**Parameters:**
- `chain_id` (number, required) — Chain ID
- `src` (string, required) — Source token address (0xEeee... for native)
- `dst` (string, required) — Destination token address
- `amount` (string, required) — Amount in smallest unit
- `from` (string, required) — Sender address
- `slippage` (number, required) — Slippage tolerance (0.1-50)

**Returns:** Optimal route, output amount, gas estimate, transaction data.

#### get_quote
Get swap quote without transaction data (read-only).

**Parameters:**
- `chain_id` (number, required) — Chain ID
- `src` (string, required) — Source token address
- `dst` (string, required) — Destination token address
- `amount` (string, required) — Amount

**Returns:** Estimated output, route, gas estimate.

### Approval

#### check_allowance
Check ERC-20 token approval for 1inch router.

**Parameters:**
- `chain_id` (number, required) — Chain ID
- `token_address` (string, required) — Token contract address
- `wallet_address` (string, required) — Wallet address

**Returns:** Current allowance amount.

#### get_approve_tx
Get approval transaction data for 1inch router.

**Parameters:**
- `chain_id` (number, required) — Chain ID
- `token_address` (string, required) — Token to approve
- `amount` (string, optional) — Amount to approve (default: unlimited)

**Returns:** Transaction data for approval.

### Fusion+ (Cross-Chain)

#### fusion_quote
Get a Fusion+ cross-chain swap quote (gasless, MEV-protected).

**Parameters:**
- `src_chain_id` (number, required) — Source chain ID
- `dst_chain_id` (number, required) — Destination chain ID
- `src_token` (string, required) — Source token address
- `dst_token` (string, required) — Destination token address
- `amount` (string, required) — Amount
- `wallet_address` (string, required) — Wallet address

**Returns:** Quote with expected output, auction parameters, resolver list.

#### fusion_create_order
Create a Fusion+ gasless limit order.

**Parameters:**
- Same as fusion_quote, plus:
- `receiver` (string, optional) — Destination address (default: sender)

**Returns:** Order data to sign (EIP-712).

### Portfolio

#### get_portfolio
Get token portfolio for a wallet across chains.

**Parameters:**
- `addresses` (string, required) — Comma-separated wallet addresses
- `chain_id` (number, optional) — Filter by chain

**Returns:** Token balances with USD values.

### Token Info

#### get_token_info
Get token details (name, symbol, decimals, logo).

**Parameters:**
- `chain_id` (number, required) — Chain ID
- `address` (string, required) — Token address

**Returns:** Token metadata.

#### search_tokens
Search for tokens by name or symbol.

**Parameters:**
- `chain_id` (number, required) — Chain ID
- `query` (string, required) — Search query

**Returns:** Matching tokens.

## Common Workflows

### Swap ETH for USDC
1. `get_quote(chain_id=1, src="0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE", dst="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", amount="1000000000000000000")` — Quote 1 ETH → USDC
2. `swap_tokens(chain_id=1, src="...", dst="...", amount="...", from="0xwallet", slippage=1)` — Get swap tx
3. Sign and submit the returned transaction data

### Cross-Chain Swap (Fusion+)
1. `fusion_quote(src_chain_id=1, dst_chain_id=8453, src_token="0xEeee...", dst_token="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", amount="1000000000000000000", wallet_address="0x...")` — Quote ETH→USDC cross-chain
2. `fusion_create_order(...)` — Create gasless order
3. Sign the EIP-712 typed data

### Check Portfolio
1. `get_portfolio(addresses="0xwallet1,0xwallet2")` — Multi-wallet portfolio

## Integration Notes

The 1inch MCP is registered as an external tool in the Tenzro tools registry (CF_TOOLS). Agents discover it via `tenzro_useTool` with provider "1inch". API key is configured at node level and injected into requests.

**Rate Limits:** Public tier: 1 request/second. For production use, obtain a premium API key from the 1inch Developer Portal.
