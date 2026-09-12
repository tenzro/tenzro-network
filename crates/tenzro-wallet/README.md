# tenzro-wallet

Permissionless Wallet System for Tenzro Network — Auto-Provisioned, Hardware-Held Keys

## Overview

`tenzro-wallet` provisions permissionless wallets for the Tenzro Network blockchain. There is no custodian, no gatekeeper, and no protocol-held key: the classical signing key is held by the identity's own hardware and never leaves the device. The hardware root *is* the wallet. Every wallet also carries a mandatory ML-DSA-65 post-quantum leg and a BLS leg for hybrid signatures, both protected by an encrypted keystore.

A wallet is always tied to an identity: a **human** signs with a passkey (WebAuthn / FIDO2), a **machine** signs with a TPM 2.0 or Apple Secure Enclave key. The private half of the classical key is generated and used only inside that hardware, so the node never holds signing material.

## Key Features

- **Onboarding**: Auto-provisioned wallets with no seed phrases and no key ceremony — provision against an identity and start signing
- **Hardware-Held Keys**: The classical signing key lives in the identity's hardware (passkey / TPM / Secure Enclave) and never enters process memory
- **Hybrid PQ Signatures**: Every wallet pairs the classical device leg with a mandatory ML-DSA-65 post-quantum leg and a BLS leg
- **Multi-Asset Support**: TNZO, USDC, USDT, ETH, SOL, BTC, and custom assets
- **Encrypted Storage**: Password-protected keystore for the ML-DSA-65 + BLS legs using Argon2id (64MB memory, 3 iterations, parallelism 4) — the classical key is in hardware, not the keystore
- **Transaction Validation**: Chain ID, nonce, gas bounds, address checks, data size limits, memo validation, tx-type-specific rules
- **Signature Verification**: Automatic post-signing cryptographic verification via `tenzro_crypto::signatures::verify()`
- **Transaction Builder**: Type-safe builder pattern with auto gas estimation per transaction type
- **Nonce Management**: Per-address sequential nonces with replay protection, on-chain sync support
- **Transaction History**: Full lifecycle tracking (Created → Pending → Confirmed → Finalized/Failed/Dropped), filtering, pagination
- **Address Book**: Contact management with name resolution, tag filtering, persistent JSON storage
- **State Sync**: Pluggable `ChainStateProvider` trait for on-chain balance/nonce synchronization, with `TenzroRpcChainProvider` against a live node and `LocalStateProvider` for offline use
- **Self-Custodial Signing**: Client-side ERC-4337 v0.8 `UserOp` construction and EIP-712 hashing, signed with the device-bound key so the node never holds signing material
- **Hardware Signers**: `PluggableSigner` trait abstracting Ledger, Trezor, GridPlus Lattice1, and YubiKey behind a public key plus a signature over a 32-byte hash
- **Key Zeroization**: Sensitive key material zeroized on drop via `zeroize` crate

## Architecture

### Permissionless Wallet Model

Each wallet is bound to an identity, and the classical key is held by that identity's hardware:

- **Identity Binding**: A `WalletIdentity` is either `Human` (passkey / WebAuthn) or `Machine` (TPM 2.0 / Apple Secure Enclave). The wallet cannot exist without one.
- **Hardware-Held Classical Key**: The classical private key is generated and used inside the identity's secure element. The `Wallet` type deliberately holds only the classical *public* key — there is no secret half to reconstruct and nothing to distribute.
- **Hybrid Legs**: Alongside the hardware classical leg, the wallet holds an ML-DSA-65 post-quantum signing key and a BLS12-381 signing key. Signing produces a `HybridSignatureBytes` carrying every leg.
- **Signature Output**: A standard 64-byte Ed25519 signature (or secp256k1, per key type) from the device key, verified under the identity's public key, plus the ML-DSA-65 and BLS legs.
- **Security**: The network / node never holds the signing key. Compromising the node cannot forge signatures because the private half never leaves the hardware root.

### Components

- **WalletService**: Main service for wallet operations (provision, sign, balance)
- **DeviceCustodySigner / HybridSigner**: The signing seam over the hardware-held key — `device_custody` drives the classical leg through the identity's `DeviceBackend` (Secure Enclave, TPM, passkey) and aggregates the ML-DSA-65 leg
- **SecureEnclaveBackend**: Apple Secure Enclave `DeviceBackend` implementation
- **TransactionValidator**: Validates transactions against security policies
- **TransactionBuilder**: Type-safe transaction construction with validation
- **NonceManager**: Per-address nonce tracking with replay protection
- **TransactionHistory**: Full lifecycle tracking with status transitions
- **AddressBook**: Contact management with persistent storage
- **BalanceTracker**: Tracks balances across multiple assets
- **AssetManager**: Manages supported assets and metadata
- **Keystore**: Encrypted persistent storage of the ML-DSA-65 + BLS legs (Argon2id)
- **ChainStateProvider**: Trait for on-chain synchronization

## Usage

### Basic Wallet Provisioning

```rust
use tenzro_wallet::service::TenzroWalletService;
use tenzro_wallet::traits::WalletService;
use tenzro_wallet::identity_binding::WalletIdentity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create wallet service
    let service = TenzroWalletService::new()?;

    // Bind the wallet to an identity. A human signs with a passkey;
    // a machine signs with a TPM 2.0 / Secure Enclave key. The classical
    // public key comes from the identity's hardware.
    let identity = WalletIdentity::human(credential_id, passkey_public_key)?;

    // Auto-provision a permissionless wallet. The service mints only the
    // ML-DSA-65 and BLS legs; the classical secret stays in hardware.
    let wallet = service.provision_wallet(identity).await?;

    println!("Wallet ID: {}", wallet.wallet_id);
    println!("Address: {}", wallet.address);
    println!("Key type: {:?}", wallet.key_type());

    Ok(())
}
```

### Building and Signing Transactions

```rust
use tenzro_wallet::service::TenzroWalletService;
use tenzro_wallet::traits::WalletService;
use tenzro_wallet::builder::TransactionBuilder;
use tenzro_wallet::identity_binding::WalletIdentity;
use tenzro_types::primitives::Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = TenzroWalletService::new()?;
    let identity = WalletIdentity::human(credential_id, passkey_public_key)?;
    let wallet = service.provision_wallet(identity).await?;

    // Build a validated transfer transaction
    let tx = TransactionBuilder::default_chain()
        .from_wallet(&wallet)
        .to(Address::new([2u8; 32]))
        .nonce(service.next_nonce(&wallet.address))
        .transfer(1000)
        .build_validated()?;

    // Sign (validates, produces the hybrid signature over the hardware
    // classical leg + ML-DSA-65 + BLS legs, and verifies it)
    let signature = service.sign_transaction(&wallet.wallet_id, &tx).await?;
    println!("Signature: {} bytes", signature.len());

    Ok(())
}
```

### Balance Management

```rust
use tenzro_wallet::service::TenzroWalletService;
use tenzro_wallet::traits::WalletService;
use tenzro_wallet::identity_binding::WalletIdentity;
use tenzro_types::asset::AssetId;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = TenzroWalletService::new()?;
    let identity = WalletIdentity::human(credential_id, passkey_public_key)?;
    let wallet = service.provision_wallet(identity).await?;

    // Check TNZO balance
    let balance = service.balance(&wallet.address, &AssetId::tnzo()).await?;
    println!("TNZO balance: {}", balance);

    Ok(())
}
```

### Key Type Selection

The classical device key is Ed25519 by default; secp256k1 is also supported for EVM-native flows. Over RPC, `tenzro_createWallet` takes the key type as its argument:

```jsonc
// JSON-RPC: provision a wallet with an Ed25519 device key
{ "method": "tenzro_createWallet", "params": ["ed25519"] }

// ...or a secp256k1 device key
{ "method": "tenzro_createWallet", "params": ["secp256k1"] }
```

The returned wallet's `key_type()` reflects the choice. Either way the classical private key is held by the identity's hardware; only the public half and the ML-DSA-65 / BLS legs are managed here.

### Watch-Only Wallets

A watch-only wallet tracks an address without any signing legs (`pq_signing_key` / `bls_signing_key` are `None`), so it cannot sign:

```rust
use tenzro_wallet::wallet::{Wallet, WalletId};

// Address is derived from the classical public key exactly as for a signing wallet.
let wallet = Wallet::new_watch_only(WalletId::new(), classical_public_key)?;
assert!(wallet.is_watch_only());
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
Core wallet types including `Wallet` (hardware classical key + ML-DSA-65 + BLS hybrid), `WalletId`, and `WalletIdentity`. `Wallet::new(wallet_id, address, classical_public_key, pq_signing_key, bls_signing_key)` builds a signing wallet that holds only the classical public key; `Wallet::new_watch_only` builds a tracking-only wallet.

### `identity_binding`
`WalletIdentity` — `Human { credential_id, public_key }` (passkey / WebAuthn) and `Machine { machine_id, public_key }` (TPM 2.0 / Apple Secure Enclave). A wallet is always bound to one.

### `device_custody` / `device_custody_se`
`DeviceCustodySigner` implements the `HybridSigner` seam over the identity's hardware-held key via a `DeviceBackend`. `SecureEnclaveBackend` is the Apple Secure Enclave backend; TPM and passkey backends plug in the same way. The signer produces the classical leg without the classical secret ever entering process memory.

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
Encrypted storage of the ML-DSA-65 + BLS legs using the Argon2id KDF. The classical signing key is held in hardware and is not stored here.

### `state_sync`
On-chain balance/nonce synchronization via the `ChainStateProvider` trait, plus `LocalStateProvider` for offline use.

### `rpc_provider`
`TenzroRpcChainProvider` — a `reqwest`-backed `ChainStateProvider` that talks to a live node over JSON-RPC. It reads balances (`eth_getBalance`, `tenzro_tokenBalance`), the sender nonce (`eth_getTransactionCount` at the pending block tag), transaction status (`eth_getTransactionReceipt`), and block height (`eth_blockNumber`), and submits signed transactions via `eth_sendRawTransaction`. Also builds ABI calldata for the cross-VM bridge precompile, with `DestVm` naming the destination runtime.

### `signing`
`HybridSigner` and `HybridSignatureBytes` — the output type carrying both the classical leg and the ML-DSA-65 leg. Admission gates verify both against the `pq_public_key` on the transaction.

### `userop`
The self-custodial ERC-4337 v0.8 path: `UserOpBuilder` constructs a `UserOp`, `user_op_hash` computes its EIP-712 hash, `pack_validator_signature` packs the signature for the on-chain validator, and `encode_user_op_json` serializes it for `eth_sendUserOperation`. The wallet signs the hash with the device-bound key — Secure Enclave, TPM, StrongBox, or passkey — so the node never holds the signing key. The `UserOp` struct is wire-identical to the VM's `UserOperation` and the hash matches byte for byte; a dedicated integration test cross-checks the two so they cannot drift.

### `pluggable_signer`
`PluggableSigner` — the hardware-signer seam for advanced custody. Ledger and Trezor speak APDU over HID, GridPlus Lattice1 a REST API, YubiKey FIDO2/CTAP; the trait reduces all of them to `device_kind()`, `public_key()`, `sign_hash(hash)`, and an optional `attest()`, so the rest of the wallet and the on-chain hardware validator module deal only with a public key and a signature over a 32-byte hash. `GenericSigner` covers backends with no device-specific protocol; `HardwareDeviceKind` and `HardwareAttestation` carry the device identifier and its attestation.

### `service`
Main `WalletService` implementation with all wallet operations. `provision_wallet(identity)` mints only the ML-DSA-65 and BLS legs and binds them to the identity's hardware-held classical key.

### `traits`
Core `WalletService` trait defining the wallet interface.

### `error`
`WalletError` and the crate `Result` alias.

## Default Configuration

- **Identity**: Human (passkey / WebAuthn) or Machine (TPM 2.0 / Apple Secure Enclave) — mandatory
- **Classical Key**: Hardware-held, Ed25519 by default (secp256k1 selectable), private half never leaves the device
- **Signature Scheme**: Hardware classical leg + ML-DSA-65 post-quantum leg + BLS leg
- **Default Assets**: TNZO, USDT, USDC, ETH, SOL, BTC
- **Keystore**: Argon2id with 64MB memory, 3 iterations, parallelism 4
- **Storage**: In-memory with an encrypted keystore for the ML-DSA-65 + BLS legs

## Security Features

### Components

- **Hardware-Held Classical Key**: Generated and used inside the identity's secure element (passkey / TPM / Secure Enclave); the node never holds the signing key
- **Keystore Encryption**: Argon2id KDF with 64MB memory cost, 3 iterations, parallelism 4, protecting the ML-DSA-65 + BLS legs
- **Transaction Validation**: Chain ID, nonce, gas bounds, address format checks, data size limits
- **Signature Verification**: Automatic post-signing verification via `tenzro_crypto::signatures::verify()`
- **Key Zeroization**: Sensitive key material zeroized on drop
- **Nonce Management**: Sequential per-address nonces with replay protection
- **Balance Tracking**: Safe arithmetic with overflow checks

## Wallet Lifecycle

### 1. Provisioning
```
User/machine presents identity → Auto-provision wallet bound to the identity's hardware key → Mint ML-DSA-65 + BLS legs → Store encrypted keystore bundle
```

### 2. Signing
```
Transaction created → Validate → Sign classical leg in hardware (passkey / TPM / Secure Enclave) → Verify → Sign ML-DSA-65 + BLS legs → Hybrid signature
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
- `tenzro-crypto` - Cryptographic primitives and ML-DSA-65
- `tokio` - Async runtime
- `serde` - Serialization framework
- `uuid` - Unique wallet identifiers
- `dashmap` - Concurrent hash maps
- `zeroize` - Secure key zeroization
- `argon2` - Argon2id KDF for keystore encryption

## License

Apache-2.0.
