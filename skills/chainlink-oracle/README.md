# Tenzro Chainlink MCP Server

The most complete Chainlink MCP server available. **21 tools** covering the full Chainlink product surface: CCIP cross-chain messaging with token pools, on-chain Data Feeds, sub-second Data Streams, VRF v2.5 verifiable randomness, Proof of Reserve, Automation, and Functions.

## Quick Start

```bash
# Testnet
curl -X POST https://chainlink-mcp.tenzro.xyz/mcp \
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

**Testnet:** `https://chainlink-mcp.tenzro.xyz/mcp`
**Local:** `http://localhost:3007/mcp`

## Tools (20)

### CCIP Cross-Chain (8)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `ccip_get_fee` | Estimate CCIP fee via `Router.getFee()` eth_call | Yes |
| `ccip_send_message` | Build `Router.ccipSend()` calldata with fee estimation | Yes |
| `ccip_track_message` | Track message via `OffRamp.getExecutionState()` | Yes |
| `ccip_get_supported_chains` | List CCIP chains from Chainlink API | No |
| `ccip_get_supported_tokens` | List CCIP tokens from Chainlink API | No |
| `ccip_get_lanes` | Get available source-destination lanes | No |
| `ccip_get_token_pool` | Get CCT token pool info (v1.5+) | Yes |
| `ccip_get_rate_limits` | Get per-lane inbound/outbound rate limiter config | Yes |

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

## CCIP Chain Selectors

| Chain | Selector | Router |
|-------|----------|--------|
| Ethereum | `5009297550715157269` | `0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D` |
| Arbitrum | `4949039107694359620` | `0x141fa059441E0ca23ce184B6A78bafD2A517DdE8` |
| Base | `15971525489660198786` | `0x881e3A65B4d4a04dD529061dd0071cf975F58bCD` |
| Optimism | `3734403246176062136` | `0x3206915f1B60Ab37Bd1E04223000a8D9fadc42a9` |
| Polygon | `4051577828743386545` | `0x849c5ED5a80F5B408Dd4969b78c2C8fdf0565Bfe` |
| BSC | `11344663589394136015` | -- |
| Avalanche | `6433500567565415381` | -- |

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

### Cross-Chain Token Transfer (CCIP)

```
1. ccip_get_supported_chains()
   -> List all CCIP chains

2. ccip_get_lanes(source_chain_selector="5009297550715157269",
                  dest_chain_selector="15971525489660198786")
   -> Ethereum -> Base lane info

3. ccip_get_fee(src_chain_id="ethereum", dst_chain_selector="base",
                receiver="0x...", data_hex="0x")
   -> { fee_wei: "...", fee_native: "0.00012345" }

4. ccip_send_message(src_chain_id="ethereum", dst_chain_selector="base",
                     receiver="0x...", sender_key="0x...")
   -> { calldata: "0x...", estimated_fee_wei: "..." }

5. ccip_track_message(message_id="0x...", dst_chain_id="base",
                      offramp_address="0x...")
   -> { state_name: "SUCCESS" }
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
  +--------+---------+---------+---------+--------+
  |        |         |         |         |        |
 CCIP   Data      Data       VRF    Proof of  Automation
        Feeds    Streams    v2.5    Reserve
  |        |         |         |         |        |
8 tools  2 tools  2 tools  2 tools  2 tools   2 tools
  |        |                   |
Router  AggV3              Coordinator
getFee  latest             requestRandom
ccipSend RoundData         getSubscription
track    list
chains
tokens
lanes
tokenPool
rateLimits                            Functions
                                      2 tools
                                      estimateCost
                                      getSubscription
```

## Skill registration

This skill is registered in the Tenzro Skills Registry (`CF_SKILLS`) at node startup as:

| Field | Value |
|---|---|
| Skill ID | `chainlink-oracle` |
| Category | `oracle` |
| Tags | `chainlink, ccip, cross-chain, oracle, data-feeds` |
| MCP backend | Chainlink MCP server on port 3007 (`https://chainlink-mcp.tenzro.xyz/mcp`) |

Discover it from any Tenzro node via `tenzro_listSkills` / `tenzro_searchSkills` and invoke its tools through the MCP endpoint above.

## References

- [Chainlink CCIP Docs](https://docs.chain.link/ccip)
- [Chainlink Data Feeds](https://docs.chain.link/data-feeds)
- [Chainlink Data Streams](https://docs.chain.link/data-streams)
- [Chainlink VRF v2.5](https://docs.chain.link/vrf/v2-5)
- [Chainlink Proof of Reserve](https://docs.chain.link/data-feeds/proof-of-reserve)
- [Chainlink Automation](https://docs.chain.link/chainlink-automation)
- [Chainlink Functions](https://docs.chain.link/chainlink-functions)
- [CCIP Explorer](https://ccip.chain.link)
