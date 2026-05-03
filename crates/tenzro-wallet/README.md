# tenzro-wallet

MPC Wallet System for Tenzro Network — Auto-Provisioned Threshold Wallets

## Overview

`tenzro-wallet` provides seamless wallet provisioning using Multi-Party Computation (MPC) for the Tenzro Network blockchain. Users get instant, secure wallets without managing seed phrases or private keys.

## Key Features

- **Seamless Onboarding**: Auto-provisioned MPC wallets with no seed phrases
- **Threshold Signatures**: Default 2-of-3 (configurable) multi-party signing
- **Multi-Asset Support**: TNZO, USDC, USDT, ETH, SOL, BTC, and custom assets
- **Encrypted Storage**: Password-protected keystore for key shares using Argon2id (64MB memory, 3 iterations, parallelism 4)
- **Transaction Validation**: Chain ID, nonce, gas bounds, address checks, data size limits, memo validation, tx-type-specific rules
- **Signature Verification**: Automatic post-signing cryptographic verification via `tenzro_crypto::signatures::verify()`
- **Transaction Builder**: Type-safe builder pattern with auto gas estimation per transaction type
- **Nonce Management**: Per-address sequential nonces with replay protection, on-chain sync support
- **Transaction History**: Full lifecycle tracking (Created → Pending → Confirmed → Finalized/Failed/Dropped), filtering, pagination
- **Address Book**: Contact management with name resolution, tag filtering, persistent JSON storage
- **State Sync**: Pluggable `ChainStateProvider` trait for on-chain balance/nonce synchronization, `LocalStateProvider` for offline use
- **Key Zeroization**: Sensitive key material zeroized on drop via `zeroize` crate

## Architecture

### MPC Wallet Model

Each wallet uses threshold secret sharing:
- **Key Shares**: Distributed across multiple parties (default: 3 shares)
- **Threshold**: Minimum shares needed to sign (default: 2)
- **Security**: No single point of failure; compromise of one share does not expose the wallet

### Components

- **WalletProvisioner**: Auto-generates MPC wallets with threshold key shares
- **WalletService**: Main service for wallet operations (provision, sign, balance)
- **MpcSigner**: Handles threshold signature generation and combination
- **TransactionValidator**: Validates transactions against security policies
- **TransactionBuilder**: Type-safe transaction construction with validation
- **NonceManager**: Per-address nonce tracking with replay protection
- **TransactionHistory**: Full lifecycle tracking with status transitions
- **AddressBook**: Contact management with persistent storage
- **BalanceTracker**: Tracks balances across multiple assets
- **AssetManager**: Manages supported assets and metadata
- **Keystore**: Encrypted persistent storage of key shares (Argon2id)
- **ChainStateProvider**: Trait for on-chain synchronization

## Usage

### Basic Wallet Provisioning

```rust
use tenzro_wallet::service::TenzroWalletService;
use tenzro_wallet::traits::WalletService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create wallet service
    let service = TenzroWalletService::new()?;

    // Auto-provision a new MPC wallet
    let wallet = service.provision_wallet().await?;

    println!("Wallet ID: {}", wallet.wallet_id);
    println!("Address: {}", wallet.address);
    println!("Threshold: {}-of-{}", wallet.threshold, wallet.total_shares);

    Ok(())
}
```

### Building and Signing Transactions

```rust
use tenzro_wallet::service::TenzroWalletService;
use tenzro_wallet::traits::WalletService;
use tenzro_wallet::builder::TransactionBuilder;
use tenzro_types::primitives::Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = TenzroWalletService::new()?;
    let wallet = service.provision_wallet().await?;

    // Build a validated transfer transaction
    let tx = TransactionBuilder::default_chain()
        .from_wallet(&wallet)
        .to(Address::new([2u8; 32]))
        .nonce(service.next_nonce(&wallet.address))
        .transfer(1000)
        .build_validated()?;

    // Sign (validates, signs with MPC threshold, and verifies signature)
    let signature = service.sign_transaction(&wallet.wallet_id, &tx).await?;
    println!("Signature: {} bytes", signature.len());

    Ok(())
}
```

### Balance Management

```rust
use tenzro_wallet::service::TenzroWalletService;
use tenzro_wallet::traits::WalletService;
use tenzro_types::asset::AssetId;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = TenzroWalletService::new()?;
    let wallet = service.provision_wallet().await?;

    // Check TNZO balance
    let balance = service.balance(&wallet.address, &AssetId::tnzo()).await?;
    println!("TNZO balance: {}", balance);

    Ok(())
}
```

### Custom Threshold Configuration

```rust
use tenzro_wallet::provisioning::{ProvisioningConfig, WalletProvisioner};
use tenzro_crypto::KeyType;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a 3-of-5 threshold configuration with Secp256k1
    let config = ProvisioningConfig::new(3, 5)?
        .with_key_type(KeyType::Secp256k1);

    let provisioner = WalletProvisioner::with_config(config)?;
    let wallet = provisioner.provision_wallet()?;

    println!("Created {}-of-{} wallet", wallet.threshold, wallet.total_shares);
    println!("Key type: {:?}", wallet.key_type);

    Ok(())
}
```

### Transaction History

```rust
use tenzro_wallet::history::{TransactionHistory, HistoryFilter, TxStatus};

let mut history = TransactionHistory::new();

// Add transaction
history.add(tx_record);

// Filter by status
let filter = HistoryFilter::default().with_status(TxStatus::Confirmed);
let confirmed_txs = history.filter(&filter);

// Pagination
let page = history.paginate(10, 0);
```

### Address Book

```rust
use tenzro_wallet::contacts::{AddressBook, Contact};
use tenzro_types::primitives::Address;

let mut book = AddressBook::new();

// Add contact
let contact = Contact {
    name: "Alice".to_string(),
    address: Address::default(),
    tags: vec!["friend".to_string()],
    notes: Some("My friend Alice".to_string()),
};
book.add(contact)?;

// Lookup by name
let alice = book.find_by_name("Alice")?;
```

## Modules

### `wallet`
Core wallet types including `MpcWallet`, `WalletId`, and `KeyShare`.

### `provisioning`
Automatic wallet provisioning with configurable threshold schemes.

### `mpc_signing`
Threshold signature operations: partial signature creation and combination.

### `validation`
Transaction validation with chain ID, nonce, gas, address, and data size checks.

### `builder`
Type-safe transaction builder with auto gas estimation.

### `nonce`
Per-address nonce management with replay protection.

### `history`
Transaction lifecycle tracking with filtering and pagination.

### `contacts`
Address book with name resolution and persistent storage.

### `balance`
Multi-asset balance tracking with support for pending transactions.

### `asset_manager`
Asset registry managing supported assets and metadata.

### `keystore`
Encrypted storage of MPC key shares using Argon2id KDF.

### `state_sync`
On-chain balance/nonce synchronization via `ChainStateProvider` trait.

### `service`
Main `WalletService` implementation with all wallet operations.

### `traits`
Core `WalletService` trait defining the wallet interface.

## Default Configuration

- **Threshold**: 2-of-3 (2 shares required to sign, 3 total shares)
- **Key Type**: Ed25519 (native Tenzro signatures)
- **Default Assets**: TNZO, USDT, USDC, ETH, SOL, BTC
- **Keystore**: Argon2id with 64MB memory, 3 iterations, parallelism 4
- **Storage**: In-memory with encrypted keystore for key shares

## Security Features

### Production-Ready Components

- **Key Shares**: Generated using Shamir's Secret Sharing over GF(256)
- **Keystore Encryption**: Argon2id KDF with 64MB memory cost, 3 iterations, parallelism 4
- **Transaction Validation**: Chain ID, nonce, gas bounds, address format checks, data size limits
- **Signature Verification**: Automatic post-signing verification via `tenzro_crypto::signatures::verify()`
- **Key Zeroization**: Sensitive key material zeroized on drop
- **Nonce Management**: Sequential per-address nonces with replay protection
- **Balance Tracking**: Safe arithmetic with overflow checks

## Wallet Lifecycle

### 1. Provisioning
```
User joins network → Auto-provision MPC wallet → Generate key shares → Store encrypted
```

### 2. Signing
```
Transaction created → Validate → Gather threshold shares → Create partial signatures → Combine → Verify → Final signature
```

### 3. Balance Updates
```
Transaction confirmed → Update balance → Track pending → Confirm/reject
```

## Testing

Run the test suite:

```bash
cargo test -p tenzro-wallet
```

Run integration tests:

```bash
cargo test -p tenzro-wallet --test integration_test
```

Test coverage: 99 unit tests + 6 integration tests passing.

## Dependencies

- `tenzro-types` - Core types for Tenzro Network
- `tenzro-crypto` - Cryptographic primitives and MPC operations
- `tokio` - Async runtime
- `serde` - Serialization framework
- `uuid` - Unique wallet identifiers
- `dashmap` - Concurrent hash maps
- `zeroize` - Secure key zeroization
- `argon2` - Argon2id KDF for keystore encryption

## License

Apache-2.0 OR MIT
