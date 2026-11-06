# Tenzro Chainlink MCP Server

Chainlink MCP server. **13 tools** covering on-chain Data Feeds, sub-second Data Streams, VRF v2.5 verifiable randomness, Proof of Reserve, Automation, and Functions.

## Quick Start

```bash
# Testnet
curl -X POST https://chainlink-mcp.tenzro.com/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chainlink_get_price","arguments":{"feed_address":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"}}}'

# Local
curl -X POST http://localhost:3007/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"chainlink_list_feeds","arguments":{}}}'
```

## Endpoint

| Transport | URL | Port |
|-----------|-----|------|
| Streamable HTTP | `POST /mcp` | 3007 |

**Testnet:** `https://chainlink-mcp.tenzro.com/mcp`
**Local:** `http://localhost:3007/mcp`

## Tools (13)

### Data Feeds (2)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `chainlink_get_price` | Read `latestRoundData()` from AggregatorV3 feed | Yes |
| `chainlink_list_feeds` | List popular feed addresses per chain | No |

### Data Streams (2) — sub-second latency

| Tool | Description | On-Chain |
|------|-------------|----------|
| `ds_get_report` | Fetch Data Streams report by feed ID (REST API) | No |
| `ds_list_feeds` | List available Data Streams feeds by asset class | No |

### VRF v2.5 (2) — verifiable randomness

| Tool | Description | On-Chain |
|------|-------------|----------|
| `vrf_request_random` | Build `requestRandomWords()` calldata | Calldata |
| `vrf_get_subscription` | Get VRF subscription balance, owner, consumers | Yes |

### Proof of Reserve (2)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `por_get_reserve` | Read reserve amount from PoR AggregatorV3 feed | Yes |
| `por_list_feeds` | List well-known PoR feeds (WBTC, USDC, TUSD) | No |

### Automation (2)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `chainlink_check_upkeep` | Dry-run `checkUpkeep()` on Automation contract | Yes |
| `chainlink_get_upkeep_info` | Get upkeep details from registry | Yes |

### Functions (2)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `chainlink_estimate_functions_cost` | Estimate LINK cost for a Functions request | No |
| `chainlink_get_subscription` | Get Functions subscription details | Yes |

### Transactions (1)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `chainlink_broadcast_signed_tx` | Broadcast an externally signed transaction (VRF or Functions request) with `eth_sendRawTransaction` | Yes |

### TNZO on other chains

TNZO moves to and from other chains over governed bridge routes. The node's
own MCP server publishes them: `list_bridge_routes` and `get_bridge_route`
return each route's limits, the lane's token buckets in each direction, the
TNZO locked on Tenzro and the representation outstanding on the other chain.
A route's reserve feed is read with `tenzro_readPorReserve` on the asset id
`tnzo:<route key>`, which also sets the reading against the route's supply
record. See `docs/BRIDGE.md`.

## Data Feed Addresses

### Ethereum

| Pair | Address | Decimals |
|------|---------|----------|
| ETH/USD | `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419` | 8 |
| BTC/USD | `0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c` | 8 |
| LINK/USD | `0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c` | 8 |
| USDC/USD | `0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6` | 8 |
| SOL/USD | `0x4ffC43a60e009B551865A93d232E33Fce9f01507` | 8 |

### Arbitrum

| Pair | Address | Decimals |
|------|---------|----------|
| ETH/USD | `0x639Fe6ab55C921f74e7fac1ee960C0B6293ba612` | 8 |
| BTC/USD | `0x6ce185860a4963106506C203335A2910413708e9` | 8 |
| ARB/USD | `0xb2A824043730FE05F3DA2efaFa1CBbe83fa548D6` | 8 |

### Base

| Pair | Address | Decimals |
|------|---------|----------|
| ETH/USD | `0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70` | 8 |
| USDC/USD | `0x7e860098F58bBFC8648a4311b374B1D669a2bc6B` | 8 |

## VRF v2.5 Coordinators

| Chain | Coordinator |
|-------|-------------|
| Ethereum | `0x271682DEB8C4E0901D1a1550aD2e64D568E69909` |
| Arbitrum | `0x41034678D6C633D8a95c75e1138A360a28bA15d1` |
| Base | `0xd5D517aBE5cF79B7e95eC98dB0f0277788aFF634` |

## Proof of Reserve Feeds (Ethereum)

| Asset | Address |
|-------|---------|
| WBTC | `0xa81FE04086865e63E12dD3776978E49DEEa2ea4e` |
| USDC | `0x9a177Bb065A0636C7972C6D27Abcd4B1e5EDb65c` |
| TUSD | `0x478f4c42b877c697C4b19E396865D5437Ef4E08B` |

## Examples

### Get ETH Price

```
chainlink_get_price(feed_address="0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419")
-> { price: "1842.50", round_id: "...", updated_at: 1712678400 }
```

### Check WBTC Reserves

```
por_get_reserve(feed_address="0xa81FE04086865e63E12dD3776978E49DEEa2ea4e")
-> { reserve: "187432.50", feed_name: "WBTC Proof of Reserve" }
```

### Request VRF Randomness

```
1. vrf_get_subscription(subscription_id="123", chain="ethereum")
   -> { balance_link: "5.000000", owner: "0x...", request_count: 42 }

2. vrf_request_random(subscription_id="123",
                      key_hash="0x...",
                      num_words=2,
                      native_payment=true,
                      chain="ethereum")
   -> { calldata: "0x...", coordinator: "0x271682..." }
```

### Check Automation Upkeep

```
chainlink_check_upkeep(contract_address="0x...", chain_id="ethereum")
-> { upkeep_needed: true, perform_data: "0x..." }

chainlink_get_upkeep_info(upkeep_id="12345",
                          registry_address="0x...",
                          chain_id="ethereum")
-> { target: "0x...", execute_gas: 200000, balance_link: "2.500000" }
```

### Data Streams (Sub-Second Prices)

```
1. ds_list_feeds()
   -> List all available Data Streams feeds

2. ds_get_report(feed_id="0x000359843a543ee2fe414dc14c7e7920ef10f4372990b79d6361cdc0dd1ba782")
   -> { benchmarkPrice, bid, ask, observationsTimestamp }

Note: Data Streams requires API credentials from Chainlink.
```

## Architecture

```
              Chainlink Ecosystem
                     |
  +---------+---------+---------+---------+---------+
  |         |         |         |         |         |
 Data      Data      VRF     Proof of  Automation Functions
 Feeds    Streams    v2.5    Reserve
  |         |         |         |         |         |
2 tools   2 tools   2 tools   2 tools   2 tools   2 tools
```

## Skill registration

This skill is registered in the Tenzro Skills Registry (`CF_SKILLS`) at node startup as:

| Field | Value |
|---|---|
| Skill ID | `chainlink-oracle` |
| Category | `oracle` |
| Tags | `chainlink, oracle, data-feeds` |
| MCP backend | Chainlink MCP server on port 3007 (`https://chainlink-mcp.tenzro.com/mcp`) |


## References

- [Chainlink CCIP Docs](https://docs.chain.link/ccip)
- [Chainlink Data Feeds](https://docs.chain.link/data-feeds)
- [Chainlink Data Streams](https://docs.chain.link/data-streams)
- [Chainlink VRF v2.5](https://docs.chain.link/vrf/v2-5)
- [Chainlink Proof of Reserve](https://docs.chain.link/data-feeds/proof-of-reserve)
- [Chainlink Automation](https://docs.chain.link/chainlink-automation)
- [Chainlink Functions](https://docs.chain.link/chainlink-functions)
- [CCIP Explorer](https://ccip.chain.link)
