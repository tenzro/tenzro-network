# Tenzro Bridge

Cross-chain bridge adapters for Tenzro Network — LayerZero V2, Chainlink CCIP + CCT, deBridge DLN, Canton, Wormhole NTT (with on-Tenzro Guardian quorum verification), Li.Fi aggregator, Hyperlane V3 (sovereign Tenzro-validator-set ISM), Axelar GMP (Cosmos / Move / Stellar reach), and Babylon Bitcoin staking (finality-providers protocol).

## Overview

The `tenzro-bridge` crate provides a unified interface for cross-chain interoperability through multiple bridge protocols. It uses an adapter pattern to support different bridge technologies while providing a consistent API for developers.

## Supported Bridge Protocols

### LayerZero V2
- **Type**: Message-passing framework with configurable security
- **Security**: Independent oracles and relayers (DVN model)
- **Patterns**: OApp (Omnichain Application), OFT (Omnichain Fungible Token)
- **Chains**: Ethereum, Arbitrum, Optimism, Polygon, BSC, Avalanche, Base, Solana
- **Best for**: Flexible cross-chain messaging with customizable security
- **Fee Quoting**: Live `eth_call` to `EndpointV2.quote()` with static fallback

### Chainlink CCIP
- **Type**: Decentralized oracle network
- **Security**: Chainlink's Risk Management Network
- **Patterns**: Token transfers with arbitrary data
- **Chains**: Ethereum, Arbitrum, Optimism, Polygon, Avalanche, Base
- **Best for**: Enterprise-grade security and reliability
- **Fee Options**: LINK token or native gas token
- **Fee Quoting**: Live `eth_call` to `Router.getFee()` with static fallback

### deBridge DLN
- **Type**: Intent-based liquidity network
- **Security**: Maker-taker model with economic guarantees
- **Patterns**: DLN orders (give/take)
- **Chains**: Ethereum, Arbitrum, Optimism, Polygon, BSC, Avalanche, Solana, Base
- **Best for**: Fast, capital-efficient transfers (seconds to minutes)
- **Fee Quoting**: Live HTTP call to deBridge order-creation API with static fallback

### Canton
- **Type**: Enterprise-grade distributed ledger using Daml 3.x
- **Security**: Privacy-preserving cross-domain synchronization
- **Patterns**: Multi-party workflows, DvP settlements
- **Best for**: Regulated enterprise use cases (tokenization, trade finance)
- **Fee Quoting**: Live HTTP call to Canton Admin API `/admin/synchronizer/{id}/fee-schedule` with static fallback
- **Workflow receipt mirror**: `tenzro-workflow` emits `Tenzro.Workflow.Receipt` Daml contracts through the co-located participant Ledger API for every `WorkflowReceipt` produced by the workflow runtime. See `docs/SPECIFICATION.md` §14.7.3 and `crates/tenzro-workflow/`.

### Wormhole
- **Type**: Generic cross-chain message passing and token transfer protocol
- **Security**: 19-node Guardian network signing Verifiable Action Approvals (VAAs)
- **Patterns**: Portal token bridge, NTT (Native Token Transfers), arbitrary messaging
- **Chains**: Ethereum, Solana, Aptos, Sui, BSC, Polygon, Avalanche, 30+ supported
- **Best for**: Broad chain coverage including non-EVM ecosystems
- **Client API**: `wormhole_chain_id()` maps Tenzro chain names to Wormhole numeric chain IDs; `parse_vaa_id()` decodes VAA identifiers; `bridge()` routes token transfers

### Chainlink CCT (Cross-Chain Token)
- **Type**: CCIP v1.6+ self-serve token pool registry
- **Security**: Chainlink CCIP Risk Management Network
- **Patterns**: LockRelease pools (source chain lock) and BurnMint pools (destination chain mint)
- **Chains**: Any CCIP-supported chain
- **Best for**: Token issuers deploying natively cross-chain assets without custom bridge code
- **Client API**: `cct_list_pools()` returns all TNZO pools registered in the CCT registry; `cct_get_pool(chain)` returns the pool address, type, and rate limits for a specific chain

### Li.Fi Aggregator
- **Type**: Cross-chain DEX and bridge aggregator
- **Security**: Aggregates execution across underlying liquidity venues
- **Patterns**: Quote / route / execute via Li.Fi public API
- **Best for**: Optimal-route asset swaps across heterogeneous bridges

### Hyperlane V3
- **Type**: Modular cross-chain messaging
- **Security**: Sovereign Tenzro-validator-set ISM — Tenzro consensus has the final say over inbound message security rather than delegating to a third-party validator quorum
- **Patterns**: Mailbox `dispatch` / `process`. Message id = `SHA-256(encoded)` over the canonical envelope `version || nonce || origin || sender || dest || recipient || body`
- **Chains**: Ethereum, Polygon, Arbitrum, Optimism, Base, Avalanche, BSC, Celo, Moonbeam, Mantle, Blast, Scroll, Zircuit, Fraxtal, Mode, Linea, Manta, zkSync, Tenzro
- **Best for**: Long-tail app-chain coverage at low cost

### Axelar GMP
- **Type**: General Message Passing
- **Security**: Axelar validator network
- **Patterns**: `callContract(destinationChain, destinationContractAddress, payload)`; Gas Service pre-pay. Payload-hash acts as the GMP correlation id
- **Chains**: 30+ canonical Axelar chains including Cosmos (Osmosis, Cosmos Hub, Juno, Neutron, Injective, Kujira, Crescent, Evmos, Kava), Move (Aptos, Sui), Stellar, XRP Ledger, Hyperliquid, Filecoin EVM, plus the standard EVM L1/L2 set
- **Best for**: Cosmos / Move / Stellar reach that the other adapters don't cover

### Babylon Bitcoin Staking
- **Type**: Bitcoin-secured finality-providers protocol (not a token bridge)
- **Security**: BTC delegations timelocked on Bitcoin L1; equivocation slashed via EOTS (Extractable One-Time Signatures)
- **Patterns**: `register_finality_provider(validator_address, btc_pk, commission_bps)`, `BtcDelegation` tracking, `submit_finality_signature` (EOTS over Tenzro block hash), `total_stake_for_provider`
- **Networks**: Babylon Mainnet (`bbn-1`), Testnet (`bbn-test-5`), Devnet
- **Best for**: Tenzro validators that want BTC economic security alongside TNZO stake

## Architecture

```
┌─────────────────────────────────────┐
│        BridgeRouter                 │  ← Intelligent routing
│  - Fee comparison                   │
│  - Route selection                  │
│  - Fallback handling                │
└─────────────┬───────────────────────┘
              │
      ┌───────┴────────┬──────────────┬──────────┐
      │                │              │          │
┌─────▼─────┐   ┌─────▼─────┐  ┌────▼──────┐  ┌──▼─────┐
│ LayerZero │   │   CCIP    │  │ deBridge  │  │ Canton │
│  Adapter  │   │  Adapter  │  │  Adapter  │  │Adapter │
└───────────┘   └───────────┘  └───────────┘  └────────┘
      │                │              │          │
      └────────────────┴──────────────┴──────────┘
              BridgeAdapter Trait
```

## Features

- **Multi-Protocol Support**: Integrate with LayerZero, Chainlink CCIP, deBridge, and Canton
- **Intelligent Routing**: Automatically select the best bridge based on cost, speed, or custom preferences
- **Live Fee Quoting**: Real fee estimation via protocol-specific APIs with static fallback
- **Transfer Tracking**: Monitor cross-chain transfer status in real-time
- **Message Signing**: Real Ed25519/Secp256k1 signature generation via `tenzro-crypto`
- **Signature Verification**: Real cryptographic verification via `tenzro_crypto::signatures::verify()`
- **Replay Protection**: Nonce-based message replay prevention
- **Circuit Breaker**: Automatic failure detection and adapter disabling
- **Type Safety**: Strongly-typed Rust implementation with comprehensive error handling
- **Async/Await**: Full async support for non-blocking operations

## Usage

### Basic Token Bridge

```rust
use tenzro_bridge::{
    BridgeRouter,
    layerzero::{LayerZeroAdapter, LayerZeroConfig},
    traits::BridgeTokenRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create router
    let router = BridgeRouter::new();

    // Register LayerZero adapter
    let lz_config = LayerZeroConfig::new(
        "0x1a44076050125825900e736c501f859c50fE728c",
        30101,
        "0xOracle",
        "0xRelayer",
    );
    router.register_adapter("layerzero", Box::new(LayerZeroAdapter::new(lz_config))).await;

    // Bridge tokens
    let request = BridgeTokenRequest::new(
        "ethereum",
        "arbitrum",
        "USDC",
        1_000_000, // 1 USDC (6 decimals)
        "0xsender",
        "0xreceiver",
    );

    let receipt = router.bridge_tokens(request).await?;
    println!("Transfer ID: {}", receipt.transfer_id);
    println!("Fee paid: {}", receipt.fee_paid);

    Ok(())
}
```

### Fee Comparison

```rust
use tenzro_bridge::BridgeRouter;

async fn compare_bridge_fees(router: &BridgeRouter) -> Result<(), Box<dyn std::error::Error>> {
    let fees = router.compare_fees("ethereum", "polygon", 1000).await?;

    for comparison in fees {
        println!("{}: {} wei", comparison.adapter_name, comparison.fee);
    }

    Ok(())
}
```

### Custom Routing Preferences

```rust
use tenzro_bridge::router::{RoutingPreferences, RoutingStrategy};

async fn set_routing_preferences(router: &BridgeRouter) {
    let preferences = RoutingPreferences {
        strategy: RoutingStrategy::FastestTime,
        max_fee: Some(1_000_000_000_000_000), // Max 0.001 ETH
        max_time_secs: Some(300), // Max 5 minutes
    };

    router.set_preferences(preferences).await;
}
```

### Using Chainlink CCIP

```rust
use tenzro_bridge::chainlink_ccip::{ChainlinkCcipAdapter, CcipConfig, FeeToken};

let ccip_config = CcipConfig::new(
    "0x80226fc0Ee2b096224EeAc085Bb9a8cba1146f7D", // Router
    5009297550715157269, // Chain selector
    "0x514910771AF9Ca656af840dff83E8264EcF986CA", // LINK token
    FeeToken::Link, // Pay fees in LINK
);

let ccip_adapter = ChainlinkCcipAdapter::new(ccip_config);
router.register_adapter("ccip", Box::new(ccip_adapter)).await;
```

### Using deBridge DLN

```rust
use tenzro_bridge::debridge::{DeBridgeAdapter, DeBridgeConfig};

let debridge_config = DeBridgeConfig::new(
    "https://api.dln.trade",
    1, // Ethereum chain ID
    "0xDLNSource",
    "0xDLNDestination",
);

let debridge_adapter = DeBridgeAdapter::new(debridge_config);
router.register_adapter("debridge", Box::new(debridge_adapter)).await;
```

### Standardized Message Format

```rust
use tenzro_bridge::message_format::{TenzroMessage, MessageType, TokenTransferPayload};

// Create a token transfer message
let payload = TokenTransferPayload::new("TNZO", 1_000_000)
    .with_memo("Payment for services")
    .encode()?;

let message = TenzroMessage::new(
    MessageType::TokenTransfer,
    "sender_address",
    "receiver_address",
    payload,
    1, // nonce
);

// Sign with Ed25519 or Secp256k1
let signed_message = message.sign(&keypair)?;

// Validate and verify signature
signed_message.validate()?;
signed_message.verify_signature()?;

// Encode for transmission
let encoded = signed_message.encode()?;
```

## Message Types

The standardized `TenzroMessage` supports multiple message types:

- `TokenTransfer` - Cross-chain token transfers
- `DataMessage` - Arbitrary data messages
- `GovernanceAction` - Cross-chain governance proposals
- `ModelRegistration` - AI model registration across chains
- `AgentMessage` - AI agent communication
- `Custom(u8)` - Custom message types

## Transfer Status

Track the status of your cross-chain transfers:

```rust
use tenzro_bridge::traits::TransferStatus;

let status = router.get_transfer_status(&transfer_id).await?;

match status {
    TransferStatus::Pending => println!("Waiting for confirmation"),
    TransferStatus::SourceConfirmed => println!("Confirmed on source chain"),
    TransferStatus::InTransit => println!("Being relayed"),
    TransferStatus::Delivered => println!("Successfully delivered!"),
    TransferStatus::Failed => println!("Transfer failed"),
}
```

## Implementation Details

### Adapter Pattern

All bridge protocols implement the `BridgeAdapter` trait:

```rust
#[async_trait]
pub trait BridgeAdapter: Send + Sync {
    fn protocol_name(&self) -> &str;
    fn supported_chains(&self) -> Vec<ChainInfo>;
    async fn send_message(&self, dest_chain: &str, payload: Vec<u8>) -> Result<String>;
    async fn receive_message(&self, source_chain: &str, payload: Vec<u8>) -> Result<()>;
    async fn bridge_tokens(&self, request: BridgeTokenRequest) -> Result<BridgeTokenReceipt>;
    async fn get_transfer_status(&self, transfer_id: &str) -> Result<TransferStatus>;
    async fn estimate_fee(&self, dest_chain: &str, payload_size: usize) -> Result<u128>;
}
```

### Live Fee Quoting

All adapters support live fee quoting with static fallback:

- **LayerZero**: `eth_call` to `EndpointV2.quote(uint32 _dstEid, bytes calldata _message, bytes calldata _options, bool _payInLzToken)` → returns `(uint256 nativeFee, uint256 lzTokenFee)`
- **Chainlink CCIP**: `eth_call` to `Router.getFee(uint64 destinationChainSelector, EVM2AnyMessage memory message)` → returns `uint256 fee`
- **deBridge**: HTTP POST to deBridge order-creation API → returns order quote with fees
- **Canton**: HTTP GET to Canton Admin API `/admin/synchronizer/{id}/fee-schedule` → returns fee schedule

All fee queries fall back to static estimates if the live RPC call fails.

### Message Signing and Verification

- **Signing**: Real Ed25519 or Secp256k1 signature generation via `TenzroMessage::sign(&keypair)`
- **Verification**: Real cryptographic verification via `TenzroMessage::verify_signature()` using `tenzro_crypto::signatures::verify()`
- **Replay Protection**: Nonce-based message replay prevention via `NonceTracker`

## Chain Support

| Chain        | LayerZero | CCIP | deBridge | Canton |
|--------------|-----------|------|----------|--------|
| Ethereum     | ✓         | ✓    | ✓        | ✓      |
| Arbitrum     | ✓         | ✓    | ✓        | ✓      |
| Optimism     | ✓         | ✓    | ✓        | ✓      |
| Polygon      | ✓         | ✓    | ✓        | ✓      |
| BSC          | ✓         | ✗    | ✓        | ✗      |
| Avalanche    | ✓         | ✓    | ✓        | ✓      |
| Base         | ✓         | ✓    | ✓        | ✓      |
| Solana       | ✓         | ✗    | ✓        | ✗      |

## Error Handling

The crate provides comprehensive error types:

```rust
pub enum BridgeError {
    BridgeNotSupported(String),
    ChainNotSupported(String),
    TransferFailed(String),
    MessageDeliveryFailed(String),
    InsufficientLiquidity,
    InvalidProof,
    AdapterError(String),
    ConfigurationError(String),
    Timeout,
    UnsupportedAsset(String),
    SignatureVerificationFailed,
    InvalidNonce,
    ReplayAttack,
}
```

## Testing

Run the test suite:

```bash
cargo test -p tenzro-bridge
```

Test coverage: extensive (`cargo test -p tenzro-bridge` for the current count).

## Production Status

Components:
- Real Ed25519/Secp256k1 message signing via `tenzro-crypto`
- Real signature verification via `tenzro_crypto::signatures::verify()`
- Nonce-based replay protection via `NonceTracker`
- Live fee quoting with protocol-specific APIs and static fallback
- Circuit breaker for automatic failure detection
- Transfer status monitoring

## Dependencies

- `tenzro-types` - Core Tenzro Network types
- `tenzro-token` - Token operations
- `tenzro-crypto` - Cryptographic primitives (Ed25519, Secp256k1 signing/verification)
- `tokio` - Async runtime
- `serde` - Serialization
- `dashmap` - Concurrent hash maps
- `tracing` - Logging
- `reqwest` - HTTP client for fee quoting
- `k256` - Secp256k1 cryptography
- `sha2` - SHA-256 hashing
- `sha3` - Keccak-256 hashing

## License

Apache-2.0 OR MIT
