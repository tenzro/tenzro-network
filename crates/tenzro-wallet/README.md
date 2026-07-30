# tenzro-wallet

FROST-Ed25519 Threshold Wallet System for Tenzro Network — Auto-Provisioned

## Overview

`tenzro-wallet` provisions wallets using FROST-Ed25519 (RFC 9591) threshold signatures for the Tenzro Network blockchain. Users get wallets without managing seed phrases or private keys. Every wallet also carries a mandatory ML-DSA-65 post-quantum signing key for hybrid signatures.

## Key Features

- **Onboarding**: Auto-provisioned FROST-Ed25519 wallets with no seed phrases
- **Threshold Signatures**: Default 2-of-3 (configurable) FROST-Ed25519 signing per RFC 9591
- **Hybrid PQ Signatures**: Every wallet pairs a FROST-Ed25519 classical leg with a mandatory ML-DSA-65 post-quantum leg
- **Multi-Asset Support**: TNZO, USDC, USDT, ETH, SOL, BTC, and custom assets
- **Encrypted Storage**: Password-protected keystore for FROST secret shares + public-key package using Argon2id (64MB memory, 3 iterations, parallelism 4)
- **Transaction Validation**: Chain ID, nonce, gas bounds, address checks, data size limits, memo validation, tx-type-specific rules
- **Signature Verification**: Automatic post-signing cryptographic verification via `tenzro_crypto::signatures::verify()`
- **Transaction Builder**: Type-safe builder pattern with auto gas estimation per transaction type
- **Nonce Management**: Per-address sequential nonces with replay protection, on-chain sync support
- **Transaction History**: Full lifecycle tracking (Created → Pending → Confirmed → Finalized/Failed/Dropped), filtering, pagination
- **Address Book**: Contact management with name resolution, tag filtering, persistent JSON storage
- **State Sync**: Pluggable `ChainStateProvider` trait for on-chain balance/nonce synchronization, with `TenzroRpcChainProvider` against a live node and `LocalStateProvider` for offline use
- **Self-Custodial Signing**: Client-side ERC-4337 v0.8 `UserOp` construction and EIP-712 hashing, signed with a device-bound key so the node never holds signing material
- **Hardware Signers**: `PluggableSigner` trait abstracting Ledger, Trezor, GridPlus Lattice1, and YubiKey behind a public key plus a signature over a 32-byte hash
- **Key Zeroization**: Sensitive key material zeroized on drop via `zeroize` crate

## Architecture

### FROST-Ed25519 Wallet Model

Each wallet uses FROST-Ed25519 threshold signatures (RFC 9591):
- **Secret Shares**: Distributed across multiple parties (default: 3 shares) via FROST trusted-dealer keygen
- **Threshold**: Minimum shares needed to sign (default: 2)
- **Public Key Package**: Group public key + per-signer verifying shares; persisted alongside secret shares
- **Aggregated Output**: Single 64-byte standard Ed25519 signature that verifies under the group public key
- **Security**: No single point of failure; compromise of fewer than `threshold` shares does not expose the wallet

### Components

- **WalletProvisioner**: Auto-generates FROST-Ed25519 wallets with threshold secret shares
- **WalletService**: Main service for wallet operations (provision, sign, balance)
- **FrostSigner**: Coordinates FROST round1 commitments, round2 signature shares, and aggregation in-process
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

    // Auto-provision a new FROST-Ed25519 threshold wallet
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

    // Sign (validates, runs FROST round1+round2, aggregates, and verifies signature)
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a 3-of-5 FROST-Ed25519 threshold configuration (RFC 9591)
    let config = ProvisioningConfig::new(3, 5)?;

    let provisioner = WalletProvisioner::with_config(config)?;
    let wallet = provisioner.provision_wallet()?;

    println!("Created {}-of-{} wallet", wallet.threshold, wallet.total_shares);
    println!("Key type: {:?}", wallet.key_type());

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
Core wallet types including `MpcWallet` (FROST-Ed25519 + ML-DSA-65 hybrid), `WalletId`, and `KeyShare`.

### `provisioning`
Automatic wallet provisioning with configurable FROST-Ed25519 threshold schemes.

### `mpc_signing`
FROST-Ed25519 signing flow: in-process round1 commit, round2 signature share, and aggregation to a single 64-byte standard Ed25519 signature.

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
Encrypted storage of FROST secret shares + public-key package using Argon2id KDF; ML-DSA-65 seed sealed in the same bundle.

### `state_sync`
On-chain balance/nonce synchronization via the `ChainStateProvider` trait, plus `LocalStateProvider` for offline use.

### `rpc_provider`
`TenzroRpcChainProvider` — a `reqwest`-backed `ChainStateProvider` that talks to a live node over JSON-RPC. It reads balances (`eth_getBalance`, `tenzro_tokenBalance`), the sender nonce (`eth_getTransactionCount` at the pending block tag), transaction status (`eth_getTransactionReceipt`), and block height (`eth_blockNumber`), and submits signed transactions via `eth_sendRawTransaction`. Also builds ABI calldata for the cross-VM bridge precompile, with `DestVm` naming the destination runtime.

### `signing`
`HybridSigner` and `HybridSignatureBytes` — the output type carrying both the classical leg and the ML-DSA-65 leg. Admission gates verify both against the `pq_public_key` on the transaction.

### `userop`
The self-custodial ERC-4337 v0.8 path: `UserOpBuilder` constructs a `UserOp`, `user_op_hash` computes its EIP-712 hash, `pack_validator_signature` packs the signature for the on-chain validator, and `encode_user_op_json` serializes it for `eth_sendUserOperation`. The wallet signs the hash with a device-bound key — Secure Enclave, TPM, StrongBox, passkey, or a FROST share — so the node never holds the signing key. The `UserOp` struct is wire-identical to the VM's `UserOperation` and the hash matches byte for byte; a dedicated integration test cross-checks the two so they cannot drift.

### `pluggable_signer`
`PluggableSigner` — the hardware-signer seam for advanced custody. Ledger and Trezor speak APDU over HID, GridPlus Lattice1 a REST API, YubiKey FIDO2/CTAP; the trait reduces all of them to `device_kind()`, `public_key()`, `sign_hash(hash)`, and an optional `attest()`, so the rest of the wallet and the on-chain hardware validator module deal only with a public key and a signature over a 32-byte hash. `GenericSigner` covers backends with no device-specific protocol; `HardwareDeviceKind` and `HardwareAttestation` carry the device identifier and its attestation.

### `service`
Main `WalletService` implementation with all wallet operations.

### `traits`
Core `WalletService` trait defining the wallet interface.

### `error`
`WalletError` and the crate `Result` alias.

## Default Configuration

- **Threshold**: 2-of-3 (2 shares required to sign, 3 total shares)
- **Signature Scheme**: FROST-Ed25519 (RFC 9591) classical leg + ML-DSA-65 post-quantum leg
- **Default Assets**: TNZO, USDT, USDC, ETH, SOL, BTC
- **Keystore**: Argon2id with 64MB memory, 3 iterations, parallelism 4
- **Storage**: In-memory with encrypted keystore for FROST shares + ML-DSA-65 seed

## Security Features

### Components

- **Key Shares**: Generated via FROST-Ed25519 trusted-dealer keygen (RFC 9591); DKG variant (`frost::dkg_part1`) available
- **Keystore Encryption**: Argon2id KDF with 64MB memory cost, 3 iterations, parallelism 4
- **Transaction Validation**: Chain ID, nonce, gas bounds, address format checks, data size limits
- **Signature Verification**: Automatic post-signing verification via `tenzro_crypto::signatures::verify()`
- **Key Zeroization**: Sensitive key material zeroized on drop
- **Nonce Management**: Sequential per-address nonces with replay protection
- **Balance Tracking**: Safe arithmetic with overflow checks

## Wallet Lifecycle

### 1. Provisioning
```
User joins network → Auto-provision FROST-Ed25519 wallet → Run trusted-dealer keygen → Generate ML-DSA-65 keypair → Store encrypted bundle
```

### 2. Signing
```
Transaction created → Validate → FROST round1 commit (threshold signers) → Build signing package → FROST round2 sign → Aggregate to Ed25519 sig → Verify → Sign ML-DSA-65 leg → Hybrid signature
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


## Dependencies

- `tenzro-types` - Core types for Tenzro Network
- `tenzro-crypto` - Cryptographic primitives, FROST-Ed25519 (RFC 9591), and ML-DSA-65
- `tokio` - Async runtime
- `serde` - Serialization framework
- `uuid` - Unique wallet identifiers
- `dashmap` - Concurrent hash maps
- `zeroize` - Secure key zeroization
- `argon2` - Argon2id KDF for keystore encryption

## License

Apache-2.0.
