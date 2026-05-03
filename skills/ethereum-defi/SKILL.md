---
name: ethereum-defi
version: 0.1.0
author: Tenzro Network
description: Ethereum DeFi skill — query balances, get Chainlink prices, estimate gas, resolve ENS names, call smart contracts, ABI-encode functions, interact with ERC-8004 agent registry, query EAS attestations.
tags:
  - ethereum
  - defi
  - erc20
  - ens
  - chainlink
  - erc8004
  - eas
  - smart_contracts
  - web3
---

# Ethereum DeFi Skill

Interact with the Ethereum blockchain for DeFi, token management, ENS resolution, smart contract calls, ERC-8004 agent identity, and Ethereum Attestation Service.

## MCP Endpoint

| Service | URL | Description |
|---------|-----|-------------|
| Ethereum MCP | `https://ethereum-mcp.tenzro.network/mcp` | Ethereum MCP Server (port 3004) |

For local development, use `http://localhost:3004/mcp`.

## Tools

### DeFi — Prices & Gas

#### eth_get_price
Get token price from Chainlink data feed via on-chain AggregatorV3Interface.

**Parameters:**
- `feed_address` (string, optional, default ETH/USD) — Chainlink price feed contract address
- `chain` (string, optional, default "ethereum") — Chain name

**Known feeds (Ethereum mainnet):**
- ETH/USD: `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419`
- BTC/USD: `0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c`
- LINK/USD: `0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c`
- USDC/USD: `0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6`

**Returns:** Price, round ID, updated timestamp.

#### eth_get_gas_price
Get current gas price in Gwei.

**Returns:** Gas price in Gwei and Wei.

#### eth_estimate_gas
Estimate gas for a transaction.

**Parameters:**
- `from` (string, required) — Sender address
- `to` (string, required) — Recipient address
- `data` (string, optional) — Hex-encoded calldata
- `value` (string, optional) — Value in Wei (hex)

**Returns:** Estimated gas units.

#### eth_get_fee_history
Get fee history for recent blocks (EIP-1559).

**Parameters:**
- `block_count` (string, optional, default "5") — Number of blocks
- `newest_block` (string, optional, default "latest") — Block tag
- `reward_percentiles` (string, optional) — Comma-separated percentiles

**Returns:** Base fees, gas used ratios, reward percentiles per block.

### Accounts & Tokens

#### eth_get_balance
Get ETH balance for an address.

**Parameters:**
- `address` (string, required) — Ethereum address (0x...)
- `block` (string, optional, default "latest") — Block number or tag

**Returns:** Balance in ETH and Wei.

#### eth_get_token_balance
Get ERC-20 token balance.

**Parameters:**
- `token_address` (string, required) — ERC-20 contract address
- `owner_address` (string, required) — Owner address

**Returns:** Token balance (raw and formatted).

#### eth_get_transaction
Get transaction details by hash.

**Parameters:**
- `tx_hash` (string, required) — Transaction hash (0x...)

**Returns:** Full transaction details.

#### eth_get_block
Get block by number.

**Parameters:**
- `block_number` (string, optional, default "latest") — Block number (hex) or tag
- `full_transactions` (bool, optional, default false) — Include full tx objects

**Returns:** Block header and transactions.

#### eth_get_transaction_receipt
Get transaction receipt with logs.

**Parameters:**
- `tx_hash` (string, required) — Transaction hash

**Returns:** Receipt with status, gas used, logs.

### ENS (Ethereum Name Service)

#### eth_resolve_ens
Resolve ENS name to Ethereum address.

**Parameters:**
- `name` (string, required) — ENS name (e.g. "vitalik.eth")

**Returns:** Resolved address.

#### eth_lookup_ens
Reverse lookup: address to ENS name.

**Parameters:**
- `address` (string, required) — Ethereum address

**Returns:** Primary ENS name if set.

### Smart Contracts

#### eth_call_contract
Execute a read-only smart contract call.

**Parameters:**
- `to` (string, required) — Contract address
- `data` (string, required) — Hex-encoded calldata
- `block` (string, optional, default "latest") — Block number or tag

**Returns:** Hex-encoded return data.

#### eth_encode_function
ABI-encode a function call (compute selector + encode args).

**Parameters:**
- `function_sig` (string, required) — Function signature (e.g. "transfer(address,uint256)")
- `args` (string, required) — JSON array of hex-encoded arguments

**Returns:** Complete hex calldata.

### ERC-8004 Agent Registry

#### eth_register_agent_8004
Describe registration of an AI agent in the ERC-8004 on-chain registry.

**Parameters:**
- `agent_name` (string, required) — Agent display name
- `capabilities` (string, required) — Comma-separated capability list
- `metadata_uri` (string, optional) — URI to agent metadata JSON

**Returns:** Registration instructions and expected transaction data.

#### eth_lookup_agent_8004
Look up an agent in the ERC-8004 registry.

**Parameters:**
- `agent_id` (string, required) — Agent ID or address

**Returns:** Agent info, capabilities, reputation score.

### EAS (Ethereum Attestation Service)

#### eth_get_attestation
Query an attestation from EAS by UID.

**Parameters:**
- `uid` (string, required) — Attestation UID

**Returns:** Attestation schema, attester, recipient, data, timestamp.

## Common Workflows

### Check Token Price & Balance
1. `eth_get_price(feed_address="0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419")` — ETH/USD price
2. `eth_get_balance(address="0x...")` — ETH balance
3. `eth_get_token_balance(token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", owner_address="0x...")` — USDC balance

### Deploy & Call Contract
1. `eth_encode_function(function_sig="transfer(address,uint256)", args='["0xrecipient","0x amount"]')` — Build calldata
2. `eth_estimate_gas(from="0x...", to="0xcontract", data="0x...")` — Estimate gas
3. `eth_get_gas_price()` — Check current gas

### Verify Agent Identity
1. `eth_lookup_agent_8004(agent_id="0x...")` — Check agent registration
2. `eth_get_attestation(uid="0x...")` — Verify EAS attestation
