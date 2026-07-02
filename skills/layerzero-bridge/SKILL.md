---
name: layerzero-bridge
version: 0.2.0
author: Tenzro Network
description: The most complete LayerZero V2 MCP server — 20 tools for cross-chain messaging, Stargate V2 native bridging (ETH/USDC/USDT), Value Transfer API (130+ chains including Solana), OFT transfers, message tracking, DVN configuration, and network queries.
tags:
  - layerzero
  - cross_chain
  - bridge
  - omnichain
  - oft
  - messaging
  - interoperability
  - stargate
  - value_transfer
---

# LayerZero Bridge Skill

The most complete LayerZero V2 MCP server available. 20 tools covering every LayerZero integration surface: low-level EndpointV2 messaging, OFT token transfers, Stargate V2 native bridging (ETH/USDC/USDT via StargatePoolNative contracts), and the new Value Transfer API (unified quotes across 130+ chains including Solana).

## MCP Endpoint

| Service | URL | Description |
|---------|-----|-------------|
| LayerZero MCP | `https://layerzero-mcp.tenzro.network/mcp` | LayerZero MCP Server (port 3006) |

For local development, use `http://localhost:3006/mcp`.

## LayerZero V2 Overview

LayerZero is an omnichain interoperability protocol enabling cross-chain messaging between 130+ blockchains. V2 uses EndpointV2 contracts with configurable security (DVNs) and execution (Executors).

**Key concepts:**
- **EID (Endpoint ID)** — Unique chain identifier (Ethereum: 30101, Solana: 30168)
- **OFT (Omnichain Fungible Token)** — Tokens transferable across chains via LayerZero. OFT V2 uses uint64 amountSD (shared decimals) instead of uint256 amountLD
- **Stargate V2** — Liquidity-based bridge built on LayerZero for native assets (ETH, USDC, USDT)
- **Value Transfer API** — New unified LayerZero API replacing deprecated Stargate REST API (130+ chains)
- **DVN (Decentralized Verifier Network)** — Security verification layer
- **Options** — TYPE_3 options (version tag 0x0003) for configurable gas and native drop on destination execution

**Supported Chains (16 chains):**
| Chain | EID | RPC |
|-------|-----|-----|
| Ethereum | 30101 | eth.llamarpc.com |
| Arbitrum | 30110 | arb1.arbitrum.io/rpc |
| Optimism | 30111 | mainnet.optimism.io |
| Polygon | 30109 | polygon-rpc.com |
| BSC | 30102 | bsc-dataseed.binance.org |
| Avalanche | 30106 | api.avax.network/ext/bc/C/rpc |
| Base | 30184 | mainnet.base.org |
| Solana | 30168 | api.mainnet-beta.solana.com |
| zkSync | 30165 | mainnet.era.zksync.io |
| Sei | 30280 | evm-rpc.sei-apis.com |
| Sonic | 30332 | rpc.soniclabs.com |
| Berachain | 30362 | rpc.berachain.com |
| Story | 30364 | rpc.story.foundation |
| Monad | 30390 | rpc.monad.xyz |
| MegaETH | 30398 | rpc.megaeth.com |
| Robinhood Chain | 30416 | rpc.mainnet.chain.robinhood.com |
| Tron | 30420 | api.trongrid.io/jsonrpc |

## Tools (21)

### Messaging (4 tools)

#### lz_quote_fee
Estimate cross-chain messaging fee via EndpointV2.quote().

**Parameters:**
- `src_chain` (string, required) — Source chain name (e.g. "ethereum")
- `dst_eid` (u32, required) — Destination endpoint ID
- `message_hex` (string, optional, default "0x") — Message payload
- `options_hex` (string, optional) — Encoded options (default: 200k gas lzReceive)
- `sender_hex` (string, optional) — Sender address

**Returns:** Native fee and LZ token fee in Wei.

#### lz_send_message
Build cross-chain message transaction data for EndpointV2.send().

**Parameters:**
- `src_chain` (string, required) — Source chain
- `dst_eid` (u32, required) — Destination EID
- `receiver` (string, required) — Destination receiver (bytes32 hex)
- `message_hex` (string, required) — Message payload
- `options_hex` (string, optional) — Encoded options

**Returns:** Hex-encoded transaction calldata.

#### lz_track_message
Track cross-chain message status via LayerZero Scan API.

**Parameters:**
- `tx_hash` (string, required) — Source transaction hash

**Returns:** Message status (INFLIGHT / CONFIRMING / DELIVERED / FAILED / BLOCKED), source/destination chains, GUID.

#### lz_get_message
Get message details by GUID.

**Parameters:**
- `guid` (string, required) — Message GUID

**Returns:** Full message details.

### OFT — Omnichain Fungible Token (4 tools)

#### lz_oft_quote
Quote an OFT token transfer fee.

**Parameters:**
- `src_chain` (string, required) — Source chain name
- `dst_chain` (string, required) — Destination chain name
- `amount` (string, required) — Amount to transfer
- `token_symbol` (string, required) — Token symbol

**Returns:** Fee quote, estimated delivery time.

#### lz_oft_send
Build OFT send() calldata with automatic fee quoting. OFT V2 uses uint64 amountSD (shared decimals).

**Parameters:**
- `src_chain` (string, required) — Source chain name
- `dst_chain` (string, required) — Destination chain name
- `oft_address` (string, required) — OFT contract address on source chain
- `recipient` (string, required) — Recipient address (20 bytes EVM)
- `amount` (string, required) — Amount in shared decimals (amountSD, uint64)
- `min_amount` (string, optional) — Minimum acceptable in shared decimals (minAmountSD, uint64, default: 90% of amount)
- `gas_limit` (u128, optional) — lzReceive gas on destination (default: 200000)

**Returns:** Hex calldata for OFT.send(), msg.value, quoted fee, amount_sd received.

#### lz_oft_list
List available OFT tokens across all chains.

**Returns:** Token name, symbol, chains deployed on, addresses.

#### lz_encode_options
Encode LayerZero TYPE_3 options bytes (version tag 0x0003, the current standard format).

**Parameters:**
- `gas_limit` (u64, optional, default 200000) — Gas for lzReceive on destination
- `native_drop` (u64, optional, default 0) — Native token to airdrop on destination

**Returns:** Hex-encoded TYPE_3 options bytes.

### Value Transfer API (5 tools) — replaces deprecated Stargate REST API

#### lz_transfer_quote
Get a cross-chain transfer quote from the unified LayerZero Value Transfer API. Supports 130+ chains including Solana.

**Parameters:**
- `src_chain` (string, required) — Source chain key (e.g. "optimism", "solana")
- `dst_chain` (string, required) — Destination chain key (e.g. "base", "solana")
- `src_token` (string, required) — Source token address (0xEeee...eEEeE for native ETH)
- `dst_token` (string, required) — Destination token address
- `amount` (string, required) — Amount in base units
- `src_address` (string, required) — Sender wallet address
- `dst_address` (string, required) — Recipient wallet address

**Returns:** Quote with fees, estimated time, and quote ID for building transaction steps.

#### lz_transfer_build
Build signable transaction steps from a Value Transfer API quote.

**Parameters:**
- `quote_id` (string, required) — Quote ID from lz_transfer_quote

**Returns:** Pre-built transaction calldata (to, data, value) that the caller signs and broadcasts.

#### lz_transfer_status
Check transfer status by quote ID.

**Parameters:**
- `quote_id` (string, required) — Quote ID or transfer ID

**Returns:** Transfer status, source/destination tx hashes, delivery progress.

#### lz_transfer_chains
List all chains supported by the Value Transfer API.

**Returns:** 130+ chains with chain keys, names, and types.

#### lz_transfer_tokens
List tokens available for transfer, optionally filtered by chain.

**Parameters:**
- `chain` (string, optional) — Filter by chain key

**Returns:** Token addresses, symbols, decimals, supported chains.

### Stargate V2 Native Bridging (2 tools)

#### lz_stargate_quote
Quote a Stargate V2 native bridge fee via quoteSend() on StargatePoolNative contracts.

**Parameters:**
- `src_chain` (string, required) — Source chain (ethereum/optimism/arbitrum/base)
- `dst_chain` (string, required) — Destination chain
- `token` (string, required) — Token: "ETH", "USDC", or "USDT"
- `amount` (string, required) — Amount in base units (wei)
- `wallet_address` (string, required) — Wallet address (20 bytes)

**Returns:** Native fee, LZ fee, amount received, total msg.value, pool contract address.

**Stargate V2 Pool Contracts:**
| Token | Ethereum | Optimism | Arbitrum | Base |
|-------|----------|----------|----------|------|
| ETH | 0x7784...7931 | 0xe8CD...7d0d3 | 0xA45B...27F5 | 0xdc18...F7C7 |
| USDC | 0xc026...5860 | 0xcE8C...7fe4 | 0xe8CD...7d0d3 | 0x27a1...b5d26 |
| USDT | 0x9335...3Eb | 0x19cF...7dD | 0xcE8C...7fe4 | — |

#### lz_stargate_send
Build sendToken() calldata for a Stargate V2 bridge transfer with automatic fee quoting.

**Parameters:**
- `src_chain` (string, required) — Source chain
- `dst_chain` (string, required) — Destination chain
- `token` (string, required) — Token: "ETH", "USDC", or "USDT"
- `amount` (string, required) — Amount in base units
- `wallet_address` (string, required) — Wallet address
- `slippage_bps` (u32, optional) — Slippage tolerance in bps (default: 50 = 0.5%)

**Returns:** Hex calldata, pool contract, msg.value, fee breakdown. For ERC-20 tokens, includes approval calldata and token contract address.

### Network (5 tools)

#### lz_get_deployments
Get LayerZero deployment addresses for all supported chains.

**Returns:** EndpointV2, SendLib, ReceiveLib addresses per chain.

#### lz_list_dvns
List available Decentralized Verifier Networks.

**Returns:** DVN name, address, supported chains, security level.

#### lz_get_messages_by_address
Get recent messages sent by a wallet address.

**Parameters:**
- `address` (string, required) — Wallet address
- `limit` (u32, optional, default 10) — Max results

**Returns:** List of messages with status, chains, timestamps.

#### lz_list_chains
List all supported LayerZero chains with their EIDs.

**Returns:** Chain name, EID, status.

#### lz_get_chain_rpc
Get the RPC URL for a specific chain.

**Parameters:**
- `chain_name` (string, required) — Chain name (e.g. "ethereum", "arbitrum")

**Returns:** RPC URL.

## Common Workflows

### Bridge Native ETH (Optimism -> Base) via Stargate V2
1. `lz_stargate_quote(src_chain="optimism", dst_chain="base", token="ETH", amount="300000000000000", wallet_address="0x...")` — Get fee quote
2. `lz_stargate_send(src_chain="optimism", dst_chain="base", token="ETH", amount="300000000000000", wallet_address="0x...")` — Build tx calldata
3. Sign and broadcast the transaction with msg.value from the response
4. `lz_track_message(tx_hash="0x...")` — Track delivery

### Bridge USDC (Ethereum -> Arbitrum) via Stargate V2
1. `lz_stargate_send(src_chain="ethereum", dst_chain="arbitrum", token="USDC", amount="1000000", wallet_address="0x...")` — Quote + build
2. First, submit the `approval_step` transaction (approve pool to spend USDC)
3. Then, submit the main sendToken transaction
4. `lz_track_message(tx_hash="0x...")` — Track delivery

### Transfer via Value Transfer API (any chain including Solana)
1. `lz_transfer_chains()` — Find chain keys
2. `lz_transfer_tokens(chain="optimism")` — Find available tokens
3. `lz_transfer_quote(src_chain="optimism", dst_chain="solana", ...)` — Get quote
4. `lz_transfer_build(quote_id="...")` — Get signable transaction steps
5. Sign and broadcast each step
6. `lz_transfer_status(quote_id="...")` — Track delivery

### Bridge OFT Tokens Cross-Chain
1. `lz_oft_list()` — Find available OFT tokens
2. `lz_oft_send(src_chain="ethereum", dst_chain="arbitrum", oft_address="0x...", recipient="0x...", amount="1000000000000000000")` — Build tx
3. Sign and broadcast with msg.value from response
4. `lz_track_message(tx_hash="0x...")` — Monitor delivery

### Send Custom Message
1. `lz_list_chains()` — Find destination EID
2. `lz_quote_fee(src_chain="ethereum", dst_eid=30110)` — Quote fee
3. `lz_send_message(src_chain="ethereum", dst_eid=30110, receiver="0x...", message_hex="0x...")` — Build tx
4. `lz_track_message(tx_hash="0x...")` — Monitor delivery

### Monitor Network
1. `lz_get_deployments()` — Contract addresses
2. `lz_list_dvns()` — Available verifiers
3. `lz_get_messages_by_address(address="0x...")` — Recent activity
