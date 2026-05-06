# Tenzro LayerZero MCP Server

The most complete LayerZero V2 MCP server available. **20 tools** covering every LayerZero integration surface: low-level EndpointV2 messaging, OFT token transfers, Stargate V2 native bridging, and the new Value Transfer API.

## Quick Start

```bash
# Testnet
curl -X POST https://layerzero-mcp.tenzro.network/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lz_list_chains","arguments":{}}}'

# Local
curl -X POST http://localhost:3006/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lz_list_chains","arguments":{}}}'
```

## Endpoint

| Transport | URL | Port |
|-----------|-----|------|
| Streamable HTTP | `POST /mcp` | 3006 |

**Testnet:** `https://layerzero-mcp.tenzro.network/mcp`
**Local:** `http://localhost:3006/mcp`

## Tools (20)

### Messaging (4)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `lz_quote_fee` | Estimate messaging fee via `EndpointV2.quote()` eth_call | Yes |
| `lz_send_message` | Build `EndpointV2.send()` calldata | Calldata |
| `lz_track_message` | Track message via LayerZero Scan API | No |
| `lz_get_message` | Get message details by GUID | No |

### OFT (4)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `lz_oft_quote` | Quote OFT transfer via Metadata API | No |
| `lz_oft_send` | Build OFT `send()` calldata with auto fee quoting | Yes |
| `lz_oft_list` | List all OFT deployments | No |
| `lz_encode_options` | Encode LayerZero V3 options bytes | No |

### Value Transfer API (5) — replaces deprecated Stargate REST API

| Tool | Description | Chains |
|------|-------------|--------|
| `lz_transfer_quote` | Get cross-chain transfer quote | 130+ incl Solana |
| `lz_transfer_build` | Build signable tx steps from quote | 130+ |
| `lz_transfer_status` | Track transfer by quote ID | 130+ |
| `lz_transfer_chains` | List all supported chains | 130+ |
| `lz_transfer_tokens` | List available tokens, filter by chain | 130+ |

### Stargate V2 Native Bridging (2)

| Tool | Description | On-Chain |
|------|-------------|----------|
| `lz_stargate_quote` | Quote via `StargatePoolNative.quoteSend()` | Yes |
| `lz_stargate_send` | Build `sendToken()` calldata + approval step | Yes |

**Supported Stargate tokens:**

| Token | Ethereum | Optimism | Arbitrum | Base |
|-------|----------|----------|----------|------|
| ETH | `0x7784...7931` | `0xe8CD...7d0d3` | `0xA45B...27F5` | `0xdc18...F7C7` |
| USDC | `0xc026...5860` | `0xcE8C...7fe4` | `0xe8CD...7d0d3` | `0x27a1...b5d26` |
| USDT | `0x9335...3Eb` | `0x19cF...7dD` | `0xcE8C...7fe4` | -- |

### Network (5)

| Tool | Description |
|------|-------------|
| `lz_get_deployments` | Get LayerZero deployment addresses per chain |
| `lz_list_dvns` | List Decentralized Verifier Networks |
| `lz_get_messages_by_address` | Get messages for a wallet address |
| `lz_list_chains` | List supported chains with EIDs |
| `lz_get_chain_rpc` | Get RPC URL for a chain |

## Supported Chains

| Chain | LayerZero EID | RPC |
|-------|---------------|-----|
| Ethereum | 30101 | `eth.llamarpc.com` |
| Arbitrum | 30110 | `arb1.arbitrum.io/rpc` |
| Optimism | 30111 | `mainnet.optimism.io` |
| Polygon | 30109 | `polygon-rpc.com` |
| BSC | 30102 | `bsc-dataseed.binance.org` |
| Avalanche | 30106 | `api.avax.network/ext/bc/C/rpc` |
| Base | 30184 | `mainnet.base.org` |
| Solana | 30168 | `api.mainnet-beta.solana.com` |

## Examples

### Bridge ETH from Optimism to Base (Stargate V2)

```
1. lz_stargate_quote(src_chain="optimism", dst_chain="base", token="ETH",
                      amount="300000000000000", wallet_address="0x...")
   -> Returns: native_fee, total_msg_value, amount_received

2. lz_stargate_send(src_chain="optimism", dst_chain="base", token="ETH",
                     amount="300000000000000", wallet_address="0x...")
   -> Returns: calldata, pool_contract, msg_value

3. Sign and submit transaction to pool_contract with msg.value

4. lz_track_message(tx_hash="0x...")
   -> Returns: INFLIGHT / DELIVERED / FAILED
```

### Bridge to Solana (Value Transfer API)

```
1. lz_transfer_chains()
   -> Returns 130+ chains with keys

2. lz_transfer_tokens(chain="optimism")
   -> Returns available tokens

3. lz_transfer_quote(src_chain="optimism", dst_chain="solana",
                      src_token="0xEeee...eEEeE", dst_token="...",
                      amount="300000000000000",
                      src_address="0x...", dst_address="...")
   -> Returns quote with quoteId

4. lz_transfer_build(quote_id="...")
   -> Returns signable transaction steps

5. lz_transfer_status(quote_id="...")
   -> Returns transfer progress
```

### Send OFT Tokens

```
1. lz_oft_list()
   -> Returns all OFT deployments with addresses

2. lz_oft_send(src_chain="ethereum", dst_chain="arbitrum",
               oft_address="0x...", recipient="0x...",
               amount="1000000000000000000")
   -> Returns calldata with auto-quoted fee

3. Sign and submit with msg.value = native fee
```

### Low-Level Messaging

```
1. lz_quote_fee(src_chain="ethereum", dst_eid=30110,
                message_hex="0xdeadbeef", sender_hex="0x...")

2. lz_send_message(src_chain="ethereum", dst_eid=30110,
                   receiver="0x000...abc", message_hex="0xdeadbeef")

3. lz_track_message(tx_hash="0x...")
```

## Architecture

```
                 LayerZero V2 Protocol
                         |
    +--------------------+--------------------+
    |                    |                    |
EndpointV2          Stargate V2       Value Transfer API
(messaging)    (native ETH/USDC)     (130+ chains, Solana)
    |                    |                    |
lz_quote_fee     lz_stargate_quote   lz_transfer_quote
lz_send_message  lz_stargate_send    lz_transfer_build
lz_track_message                     lz_transfer_status
lz_get_message                       lz_transfer_chains
                                     lz_transfer_tokens
    |
  OFT Standard
    |
lz_oft_quote
lz_oft_send
lz_oft_list
lz_encode_options
```

## Skill registration

This skill is registered in the Tenzro Skills Registry (`CF_SKILLS`) at node startup as:

| Field | Value |
|---|---|
| Skill ID | `layerzero-bridge` |
| Category | `bridge` |
| Tags | `layerzero, cross-chain, bridge, omnichain, oft` |
| MCP backend | LayerZero MCP server on port 3006 (`https://layerzero-mcp.tenzro.network/mcp`) |

Discover it from any Tenzro node via `tenzro_listSkills` / `tenzro_searchSkills` and invoke its tools through the MCP endpoint above.

## References

- [LayerZero V2 Docs](https://docs.layerzero.network/v2)
- [LayerZero Value Transfer API](https://transfer.layerzero-api.com/v1/docs)
- [Stargate V2 Docs](https://docs.stargate.finance)
- [LayerZero Scan](https://layerzeroscan.com)
- [OFT Standard](https://docs.layerzero.network/v2/home/token-standards/oft-standard)
