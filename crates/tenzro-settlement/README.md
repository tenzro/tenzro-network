# tenzro-settlement

Payment settlement engine for the Tenzro Network, handling escrow, micropayments, batch processing, and fee collection.

## Overview

`tenzro-settlement` implements the settlement layer for the Tenzro Network, enabling secure payment flows for AI inference, TEE services, and general token transfers. The crate supports multiple settlement modes including immediate settlement, escrow-based settlement with proof-gated release, and off-chain micropayment channels.

## Modules

- `engine` - Core settlement processing engine with cryptographic proof verification
- `escrow` - Escrow manager with conditional release
- `micropayments` - Payment channel manager for off-chain per-token billing with dispute resolution
- `batch` - Atomic multi-settlement batch processor with rollback
- `fee_collector` - Network fee collection and routing (default 0.5%)
- `error` - Error types

## Key Features

- **Settlement Engine**: Core settlement processing with cryptographic proof verification (ZK proofs, TEE attestations)
- **Escrow Manager**: Conditional escrow with proof-gated release
- **Micropayment Channels**: Off-chain payment channels for low-latency per-token billing with dispute resolution
- **Batch Processing**: Atomic multi-settlement operations with all-or-nothing guarantees
- **Fee Collection**: Automatic network fee routing (default 0.5% commission on AI/TEE payments)
- **Settlement Modes**:
  - `Immediate` - Direct on-chain settlement
  - `Escrow` - Conditional settlement with proof-based release
  - `Batch` - Multiple settlements in a single atomic transaction
- **Channel Dispute Resolution**: On-chain dispute mechanism for micropayment channel fraud
- **RocksDB Persistence**: Channel state and settlement receipts backed by storage

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Default network fee | 0.5% | Network commission on AI/TEE payments |

## Usage

### Immediate Settlement

```rust
use tenzro_settlement::engine::SettlementEngine;
use tenzro_types::{Address, settlement::{SettlementRequest, ServiceType, ServiceProof, ProofType}};

let engine = SettlementEngine::new(config, treasury)?;

let proof = ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3]);
let request = SettlementRequest::new(
    provider,
    customer,
    ServiceType::ModelInference {
        model_id: "gpt-4".to_string(),
        tokens: 1000,
    },
    10000, // amount
    proof,
);

let receipt = engine.settle(request).await?;
println!("Settlement completed: {:?}", receipt.receipt_id);
```

### Escrow (on-chain primitive)

Escrow is a **consensus-mediated** primitive. Funds are locked on-chain at a
vault address derived from the escrow id; only the original payer can later
release funds to the payee or refund them to themselves. The `EscrowManager`
in this crate is a **query cache** for read RPCs (`tenzro_getEscrow`,
`tenzro_listEscrowsByPayer`, `tenzro_listEscrowsByPayee`); it is not the
source of truth for funds.

#### On-chain flow

```
client → TransactionBuilder → sign(payer key) → tenzro_sendRawTransaction
       → mempool (signature verified at admission)
       → block → Native VM dispatch (4-byte selector)
       → debit payer / credit vault (or vault → payee/payer on release/refund)
       → write-through to CF_SETTLEMENTS (escrow:<escrow_id>)
```

#### Deterministic identifiers

- **`escrow_id`**: `SHA-256("tenzro/escrow/id" || payer || nonce_le)` — derived
  by the VM, observable via the receipt log emitted on `CreateEscrow`.
- **Vault address**: `Address(SHA-256("tenzro/escrow/vault" || escrow_id))` —
  has no private key. Release/refund payouts are a privileged VM operation
  that calls `state.set_balance` directly via a single auditable helper, never
  via normal `TnzoToken::transfer`.

#### Native-VM selectors

| Selector       | Operation        | Gas    |
|----------------|------------------|--------|
| `0x01000010`   | CreateEscrow     | 75,000 |
| `0x01000011`   | ReleaseEscrow    | 60,000 |
| `0x01000012`   | RefundEscrow     | 50,000 |

#### Authorization invariants (enforced by VM)

- `CreateEscrow.from` must equal the signing payer (verified at mempool
  admission). The VM never trusts a `payer` field in the payload.
- `ReleaseEscrow` is rejected unless `tx.from == escrow.payer` and the escrow
  is in `Funded` state and not expired, and the proof verifies against the
  recorded `release_conditions`.
- `RefundEscrow` is rejected unless `tx.from == escrow.payer` AND (the escrow
  is expired OR `release_conditions ∈ {Timeout, Custom}`).

#### Persistence + hydration

`EscrowManager::with_storage(balances, storage)` enables write-through to
RocksDB `CF_SETTLEMENTS` under the prefixes:

- `escrow:<escrow_id>` — full `EscrowAccount` record
- `escrow_payer:<address_hex>` — Vec<escrow_id> index
- `escrow_payee:<address_hex>` — Vec<escrow_id> index

On construction, the manager scans `escrow:` and rebuilds in-memory indices.
All mutations use `KvStore::write_batch_sync` (fsync on commit). Restart-safe.

#### Submitting from a client

Clients construct a signed `CreateEscrow` / `ReleaseEscrow` / `RefundEscrow`
transaction via `tenzro_signAndSendTransaction` (ambient server-side signing
against the DPoP-bound bearer JWT) or build + sign locally and submit via
`eth_sendRawTransaction`. Escrow writes flow through the consensus path only.

```rust
// Ambient auth: caller sets TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF before
// invoking the SDK; the node resolves the signer from the JWT's FROST-Ed25519 threshold wallet.
// `tx_type` uses serde's externally-tagged enum form — the variant name is the
// key. Unit variants such as `ReleaseConditions::Timeout` are bare strings.
let tx_type = serde_json::json!({
    "CreateEscrow": {
        "payee": payee_address,
        "amount": amount.to_string(),
        "asset_id": "TNZO",
        "expires_at": expires_at_ms,
        "release_conditions": "Timeout",
    },
});

let tx_hash: String = rpc.call("tenzro_signAndSendTransaction", json!({
    "from": payer_address,
    "to":   payee_address,
    "value": 0,
    "gas_limit": 75_000,
    "gas_price": 1_000_000_000,
    "nonce": nonce,
    "chain_id": chain_id,
    "tx_type": tx_type,
})).await?;
```

The `EscrowManager` API (`create_escrow`, `release_escrow`, `refund_escrow`)
is the VM's write path and an in-memory query cache; external callers always
go through signed transactions.

### Micropayment Channels

```rust
use tenzro_settlement::micropayments::ChannelManager;

let channel_manager = ChannelManager::new();

// Open channel
let channel = channel_manager.open_channel(
    payer,
    payee,
    initial_deposit,
    asset_id,
    expiry_timestamp,
)?;

// Make off-chain payments. The signature must be a real Ed25519 signature
// by the payer over the canonical encoding of the *next* channel state
// (`nonce || payer_balance || payee_balance`); see the `ChannelState`
// docs and `tenzro_crypto::signatures::Ed25519SignerImpl` for the signing
// helper.
let next = channel.state.next(payer_balance, payee_balance);
let sig = ed25519_signer.sign(&next.canonical_message())?;
channel_manager.update_channel(&channel.channel_id, amount, sig.as_bytes().to_vec())?;

// Close channel and settle on-chain
channel_manager.close_channel(&channel.channel_id)?;
```

#### Channel disputes

If the counterparty stops cooperating or replays a stale state, either party
opens a dispute via `MicropaymentChannelManager::open_dispute`. Disputes are
persisted in `CF_CHANNELS` under the `dispute:<dispute_id>` prefix and
exposed read-only via:

- `tenzro_getDispute { dispute_id }` — full dispute record
- `tenzro_listDisputesByChannel { channel_id }` — all disputes filed against a channel

CLI:

```bash
tenzro dispute status --dispute-id <id>
tenzro dispute list-by-channel --channel-id <id>
```

The dispute window holds the channel open for the configured challenge period
during which the counterparty can submit a higher-nonce signed state. After
the window expires, the highest-nonce verified state settles on-chain.

### Batch Settlement

```rust
use tenzro_settlement::batch::BatchProcessor;

let processor = BatchProcessor::new(max_batch_size);

let settlements = vec![request1, request2, request3];
let result = processor.process_batch(settlements).await?;

// All settlements succeed atomically or all fail
match result.status {
    BatchStatus::Completed => println!("Batch completed successfully"),
    BatchStatus::Failed => println!("Batch failed, all rolled back"),
    _ => println!("Batch status: {:?}", result.status),
}
```

## Production Status

Components:
- **On-chain escrow primitive** with consensus-mediated `CreateEscrow` /
  `ReleaseEscrow` / `RefundEscrow` transactions, derived vault addresses,
  privileged-VM payout, payer-only authorization, RocksDB write-through to
  `CF_SETTLEMENTS`, and full hydration on restart
- Atomic batch processing with rollback on failure
- Settlement receipt generation and tracking
- Micropayment channel persistence with RocksDB backing
- Dispute resolution mechanism for channel fraud
- Real ZK proof verification via `tenzro_zk::verify_proof_envelope` (Plonky3 STARKs over KoalaBear; non-Plonky3 proof types rejected)
- Real TEE attestation verification (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)

Unit tests cover the escrow, batch, channel, and dispute paths.

## Dependencies

- `tenzro-types` - Core types
- `tenzro-crypto` - Cryptographic primitives
- `tenzro-token` - Token operations
- `tenzro-wallet` - Wallet integration
- `tenzro-storage` - RocksDB persistence
- `tenzro-zk` - ZK proof verification
- `tenzro-tee` - TEE attestation verification
- `tokio` - Async runtime
- `dashmap` - Concurrent hash maps
- `parking_lot` - High-performance locks

## License

Apache-2.0.
