---
name: chainlink-oracle
version: 0.2.0
author: Tenzro Network
description: Chainlink MCP server — 13 tools covering Data Feeds, Data Streams (sub-second), VRF v2.5 randomness, Proof of Reserve, Automation upkeeps, and Functions subscriptions.
tags:
  - chainlink
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

Chainlink MCP server. 13 tools covering on-chain Data Feeds via AggregatorV3, sub-second Data Streams, VRF v2.5 verifiable randomness, Proof of Reserve verification, Automation upkeeps, and Functions subscriptions.

## MCP Endpoint

| Service | URL | Description |
|---------|-----|-------------|
| Chainlink MCP | `https://chainlink-mcp.tenzro.com/mcp` | Chainlink MCP Server (port 3007) |

For local development, use `http://localhost:3007/mcp`.

## Key Concepts

- **Data Feeds** — On-chain price oracles via AggregatorV3Interface (~1 min updates)
- **Data Streams** — Off-chain sub-second latency market data (crypto, forex, equities, commodities)
- **VRF v2.5** — Verifiable Random Function for provably fair onchain randomness
- **Proof of Reserve** — On-chain reserve verification for wrapped/synthetic assets
- **Automation** — Decentralized keeper network for contract maintenance
- **Functions** — DON-hosted serverless compute for off-chain data

## Tools (13)

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

### Transactions (1 tool)

#### chainlink_broadcast_signed_tx
Broadcast an externally signed transaction (a VRF or Functions request) with eth_sendRawTransaction and return its hash.

## TNZO on other chains

The node's own MCP server publishes the governed bridge routes TNZO moves over: `list_bridge_routes` and `get_bridge_route` return each route's limits, the lane's token buckets in each direction, and the TNZO locked on Tenzro against the representation outstanding on the other chain.

## Common Workflows

### Get Multi-Asset Prices
1. `chainlink_get_price(feed_address="0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419")` — ETH/USD
2. `chainlink_get_price(feed_address="0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c")` — BTC/USD

### Verify Asset Reserves
1. `por_list_feeds()` — List available PoR feeds
2. `por_get_reserve(feed_address="0xa81FE04086865e63E12dD3776978E49DEEa2ea4e")` — WBTC reserve

### Request Verifiable Randomness
1. `vrf_get_subscription(subscription_id="123")` — Check balance
2. `vrf_request_random(subscription_id="123", key_hash="0x...", num_words=2)` — Build request tx
