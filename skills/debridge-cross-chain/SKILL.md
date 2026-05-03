---
name: debridge-cross-chain
version: 0.1.0
author: Tenzro Network
description: deBridge cross-chain skill — intent-based bridging via DLN, get quotes, create orders, track order status, list supported chains and tokens. Uses the official deBridge MCP server.
tags:
  - debridge
  - cross-chain
  - bridge
  - dln
  - intent
  - swap
---

# deBridge Cross-Chain Skill

Intent-based cross-chain bridging via deBridge DLN (Decentralized Liquidity Network). Supports fast cross-chain swaps across 20+ chains with MEV protection.

## MCP Endpoint

deBridge provides an official hosted MCP server:

| Service | URL | Description |
|---------|-----|-------------|
| deBridge MCP | `https://agents.debridge.com/mcp` | Official deBridge MCP (Streamable HTTP, no auth) |

Can also be installed locally via npm: `npx @debridge-finance/debridge-mcp`

## Key Concepts

- **DLN** — Decentralized Liquidity Network, intent-based protocol
- **Orders** — Cross-chain swap intents created by users, filled by market makers
- **Takers** — Professional market makers who fill orders for a fee
- **Chain IDs** — deBridge uses standard EVM chain IDs (1=Ethereum, 56=BSC, 137=Polygon, 42161=Arbitrum, 8453=Base, 10=Optimism, 43114=Avalanche, 7565164=Solana)

## Available Tools (via official MCP)

### Quote & Order Creation

#### get_quote
Get a quote for a cross-chain swap.

**Parameters:**
- `srcChainId` — Source chain ID
- `srcChainTokenIn` — Input token address
- `srcChainTokenInAmount` — Amount in smallest unit
- `dstChainId` — Destination chain ID
- `dstChainTokenOut` — Output token address
- `slippage` (optional) — Slippage tolerance (bps)

**Returns:** Quote with estimated output, fees, execution time.

#### create_order
Create a DLN cross-chain swap order.

**Parameters:**
- `srcChainId` — Source chain ID
- `srcChainTokenIn` — Input token address
- `srcChainTokenInAmount` — Amount
- `dstChainId` — Destination chain ID
- `dstChainTokenOut` — Output token address
- `dstChainTokenOutRecipient` — Recipient address on destination
- `srcChainOrderAuthorityAddress` — Order creator address

**Returns:** Transaction data to sign and submit.

### Order Tracking

#### get_order_status
Track a DLN order by order ID.

**Parameters:**
- `orderId` — Order ID (returned from create_order)

**Returns:** Order status (Created/Filled/Cancelled), fill transaction hash. Status tracking uses stats-api.dln.trade. Intermediate states ClaimedUnlock and SentUnlock map to Filled.

#### get_orders_by_tx
Get orders associated with a transaction hash.

**Parameters:**
- `txHash` — Transaction hash

**Returns:** List of orders with status.

### Chain & Token Info

#### get_supported_chains
List chains supported by deBridge DLN.

**Returns:** Chain IDs, names, native tokens.

#### get_token_list
Get supported tokens on a specific chain.

**Parameters:**
- `chainId` — Chain ID

**Returns:** Token addresses, symbols, decimals.

## Common Workflows

### Cross-Chain Swap (ETH → USDC on Base)
1. `get_quote(srcChainId=1, srcChainTokenIn="0x0000000000000000000000000000000000000000", srcChainTokenInAmount="1000000000000000000", dstChainId=8453, dstChainTokenOut="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")` — Quote 1 ETH → USDC on Base
2. `create_order(...)` — Create order with quote params + recipient
3. `get_order_status(orderId="...")` — Track via stats-api.dln.trade until Filled

### Check Available Routes
1. `get_supported_chains()` — List all chains
2. `get_token_list(chainId=1)` — Ethereum tokens
3. `get_quote(...)` — Check if route has liquidity

## Integration Notes

The deBridge MCP server is registered as an external tool in the Tenzro tools registry (CF_TOOLS). Agents can discover it via `tenzro_useTool` with provider "debridge". No API key required.
