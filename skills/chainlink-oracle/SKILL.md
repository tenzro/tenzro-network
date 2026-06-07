---
name: chainlink-oracle
version: 0.2.0
author: Tenzro Network
description: The most complete Chainlink MCP server — 20 tools covering CCIP v1.6 cross-chain messaging with token pools, Data Feeds, Data Streams (sub-second), VRF v2.5 randomness, Proof of Reserve, Automation upkeeps, and Functions subscriptions.
tags:
  - chainlink
  - ccip
  - cross-chain
  - oracle
  - data-feeds
  - data-streams
  - automation
  - functions
  - vrf
  - proof-of-reserve
  - price-feed
---

# Chainlink Oracle Skill

The most complete Chainlink MCP server available. 20 tools covering the full Chainlink product surface: CCIP v1.6+ cross-chain messaging with token pools and allowOutOfOrderExecution=true, on-chain Data Feeds via AggregatorV3, sub-second Data Streams, VRF v2.5 verifiable randomness, Proof of Reserve verification, Automation upkeeps, and Functions subscriptions.

## MCP Endpoint

| Service | URL | Description |
|---------|-----|-------------|
| Chainlink MCP | `https://chainlink-mcp.tenzro.network/mcp` | Chainlink MCP Server (port 3007) |

For local development, use `http://localhost:3007/mcp`.

## Key Concepts

- **CCIP** — Cross-Chain Interoperability Protocol for secure messaging and token transfers
- **Router** — Per-chain CCIP entry point contract
- **Chain Selector** — uint64 identifier for each chain in CCIP
- **Token Pool** — CCIP v1.6+ Lock/Release or Burn/Mint pool for cross-chain tokens (CCT)
- **Data Feeds** — On-chain price oracles via AggregatorV3Interface (~1 min updates)
- **Data Streams** — Off-chain sub-second latency market data (crypto, forex, equities, commodities)
- **VRF v2.5** — Verifiable Random Function for provably fair onchain randomness
- **Proof of Reserve** — On-chain reserve verification for wrapped/synthetic assets
- **Automation** — Decentralized keeper network for contract maintenance
- **Functions** — DON-hosted serverless compute for off-chain data

## Tools (21)

### CCIP Cross-Chain (8 tools)

#### ccip_get_fee
Estimate CCIP messaging fee via Router.getFee() on-chain call.

#### ccip_send_message
Build Router.ccipSend() calldata with automatic fee estimation.

#### ccip_track_message
Track CCIP message delivery via OffRamp.getExecutionState().

#### ccip_get_supported_chains
List CCIP-supported chains from Chainlink REST API.

#### ccip_get_supported_tokens
List CCIP-supported tokens from Chainlink REST API.

#### ccip_get_lanes
Get available CCIP lanes (chain pairs).

#### ccip_get_token_pool
Get CCT token pool info — token address, owner, pool type (v1.5+).

#### ccip_get_rate_limits
Get per-lane inbound/outbound rate limiter config (capacity, rate, tokens available).

### Data Feeds (2 tools)

#### chainlink_get_price
Read latestRoundData() from a Chainlink AggregatorV3 feed on-chain.

#### chainlink_list_feeds
List popular feed addresses per chain (Ethereum, Arbitrum, Base).

### Data Streams (2 tools)

#### ds_get_report
Fetch a Data Streams report by feed ID via REST API. Sub-second latency market data.

#### ds_list_feeds
List available Data Streams feeds by asset class (crypto, forex, equities, commodities).

### VRF v2.5 (2 tools)

#### vrf_request_random
Build requestRandomWords() calldata for VRFCoordinatorV2_5. Supports LINK or native token payment.

#### vrf_get_subscription
Get VRF v2.5 subscription details — balance, native balance, request count, owner.

### Proof of Reserve (2 tools)

#### por_get_reserve
Read reserve amount from a Chainlink PoR AggregatorV3 feed.

#### por_list_feeds
List well-known Proof of Reserve feeds (WBTC, USDC, TUSD).

### Automation (2 tools)

#### chainlink_check_upkeep
Dry-run checkUpkeep() on an Automation-compatible contract.

#### chainlink_get_upkeep_info
Get upkeep details (target, gas limit, balance, admin) from the registry.

### Functions (2 tools)

#### chainlink_estimate_functions_cost
Estimate LINK cost for a Functions request based on callback gas.

#### chainlink_get_subscription
Get Functions subscription details (balance, owner, consumers).

## CCIP Chain Selectors

| Chain | Selector | Router |
|-------|----------|--------|
| Ethereum | 5009297550715157269 | `0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D` |
| Arbitrum | 4949039107694359620 | `0x141fa059441E0ca23ce184B6A78bafD2A517DdE8` |
| Base | 15971525489660198786 | `0x881e3A65B4d4a04dD529061dd0071cf975F58bCD` |
| BSC | 11344663589394136015 | `0x34B03Cb9086d7D758AC55af71584F81A598759FE` |
| Optimism | 3734403246176062136 | `0x3206915f1B60Ab37Bd1E04223000a8D9fadc42a9` |
| Polygon | 4051577828743386545 | `0x849c5ED5a80F5B408Dd4969b78c2C8fdf0565Bfe` |

## Common Workflows

### Cross-Chain Token Transfer
1. `ccip_get_supported_chains()` — List supported chains
2. `ccip_get_lanes(source="ethereum", dest="base")` — Check lane exists
3. `ccip_get_fee(src="ethereum", dst="base", receiver="0x...")` — Estimate fee
4. `ccip_send_message(...)` — Build transfer tx
5. `ccip_track_message(message_id="0x...")` — Track delivery

### Get Multi-Asset Prices
1. `chainlink_get_price(feed_address="0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419")` — ETH/USD
2. `chainlink_get_price(feed_address="0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c")` — BTC/USD

### Verify Asset Reserves
1. `por_list_feeds()` — List available PoR feeds
2. `por_get_reserve(feed_address="0xa81FE04086865e63E12dD3776978E49DEEa2ea4e")` — WBTC reserve

### Request Verifiable Randomness
1. `vrf_get_subscription(subscription_id="123")` — Check balance
2. `vrf_request_random(subscription_id="123", key_hash="0x...", num_words=2)` — Build request tx
