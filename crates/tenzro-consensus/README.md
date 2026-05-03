# tenzro-consensus

HotStuff-2 BFT consensus engine for Tenzro Network with TEE attestation. Powers consensus on Tenzro Ledger (the L1 settlement layer).

## Overview

This crate implements the HotStuff-2 consensus protocol, a two-phase BFT consensus algorithm designed for high performance and strong finality guarantees.

## Modules

**10 modules:** config, epoch_manager, error, finality, hotstuff2, mempool, proposer, traits, validator, voter

- `config` - ConsensusConfig, BftThreshold, LeaderRotation
- `epoch_manager` - Epoch, EpochManager, EpochStats for validator set transitions
- `error` - ConsensusError, Result types
- `finality` - FinalityNotification, FinalityTracker, ForkChoice
- `hotstuff2` - HotStuff2Engine, Phase (Prepare/Commit/Decide), StateRootProvider, ConsensusOutMessage
- `mempool` - Mempool, MempoolStats with gas price ordering
- `proposer` - BlockProposer for transaction selection
- `traits` - ConsensusEngine, ConsensusNetwork, SlashingCallback, StateManager
- `validator` - ValidatorInfo, ValidatorSet, ValidatorStatus, EquivocationDetector, EquivocationEvidence
- `voter` - QuorumCertificate, Vote, VoteCollector, VoteType

## Key Features

- **Fast Finality**: Two-phase protocol (PREPARE → COMMIT → DECIDE)
- **Linear Communication**: O(n) message complexity per view
- **Optimistic Responsiveness**: Block commits in network delay time under good conditions
- **TEE Integration**: Validators with TEE attestation receive 2x priority in leader selection
- **Robust Liveness**: Automatic view changes on timeout
- **Epoch-based Validator Management**: Clean validator set transitions at epoch boundaries
- **Equivocation Detection**: `EquivocationDetector` catches double-votes, wires into `SlashingCallback` for stake penalties
- **Peer Authentication**: `ValidatorRegistry` trait enforces validator-only topics (consensus, block proposals, attestations)

## HotStuff-2 Protocol

### Protocol Flow

1. **PREPARE Phase**:
   - Leader proposes a block
   - Validators vote on the proposal
   - Prepare QC formed when 2f+1 votes collected

2. **COMMIT Phase**:
   - Leader shares prepare QC
   - Validators vote to commit
   - Commit QC formed when 2f+1 votes collected

3. **DECIDE Phase**:
   - Block is finalized with commit QC
   - Transactions removed from mempool
   - Advance to next height

### Byzantine Fault Tolerance

The protocol tolerates up to `f` Byzantine faults where `f = (n-1)/3` and `n` is the number of validators. A quorum requires `2f+1` votes, ensuring:

- Safety: No two conflicting blocks can be finalized
- Liveness: Progress is guaranteed with honest majority and synchrony

### Leader Selection

Leader selection uses deterministic rotation with optional TEE-based priority:

- **Round-Robin**: Simple rotation based on view number (default)
- **TEE-Weighted**: Validators with valid TEE attestation get 2x priority for leader selection (voting power remains standard)
- **Stake-Weighted**: Selection weighted by validator stake

## TEE Integration

Validators can provide TEE attestation to gain priority in leader selection:

```rust
use tenzro_consensus::ValidatorInfo;
use tenzro_types::tee::{AttestationReport, AttestationResult};

let mut validator = ValidatorInfo::new(address, public_key, stake);

// Add TEE attestation
let attestation = AttestationReport::new(/* ... */);
let result = AttestationResult::success(/* ... */);
validator = validator.with_tee_attestation(attestation, result);

// This validator now has 2x leader selection priority
```

## Configuration

```rust
use tenzro_consensus::ConsensusConfig;

let config = ConsensusConfig::default()
    .with_block_time(400)           // 400ms block time
    .with_view_timeout(2000)        // 2s view timeout
    .with_max_block_size(2_097_152) // 2MB max block size
    .with_max_gas_per_block(30_000_000);
```

### Key Parameters

- **block_time_ms**: Target block time (default: 400ms)
- **view_timeout_ms**: Timeout before view change (default: 2000ms)
- **max_transactions_per_block**: Transaction limit (default: 10,000)
- **max_gas_per_block**: Gas limit (default: 30M)
- **max_block_size**: Block size limit (default: 2MB)
- **epoch_duration**: Blocks per epoch (default: 10,000)

## Usage Example

```rust
use tenzro_consensus::{
    HotStuff2Engine, ConsensusConfig, ConsensusEngine,
    EpochManager, ValidatorInfo,
};
use tenzro_crypto::{KeyPair, KeyType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate validator keypair
    let keypair = KeyPair::generate(KeyType::Ed25519)?;

    // Convert address (20 bytes -> 32 bytes)
    let crypto_addr = keypair.address();
    let mut addr_bytes = [0u8; 32];
    addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
    let address = tenzro_types::primitives::Address::new(addr_bytes);

    // Create validators
    let validators = vec![
        ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            1000, // stake
        ),
    ];

    // Create epoch manager
    let epoch_manager = EpochManager::new(validators, 10000)?;

    // Create consensus engine
    let config = ConsensusConfig::default();
    let mut engine = HotStuff2Engine::new(keypair, config, epoch_manager);

    // Start consensus
    engine.start().await?;

    // Subscribe to finality notifications
    let mut finality_rx = engine.finality_tracker.subscribe();

    tokio::spawn(async move {
        while let Ok(notification) = finality_rx.recv().await {
            println!("Block finalized: height={}, hash={}",
                notification.height, notification.hash);
        }
    });

    Ok(())
}
```

## Epoch Management

Validators are organized into epochs with clean transitions:

```rust
use tenzro_consensus::EpochManager;

// Create epoch manager with 100-block epochs
let manager = EpochManager::new(validators, 100)?;

// Add pending validator for next epoch
manager.add_pending_validator(new_validator);

// Transition happens automatically at epoch boundary
if manager.should_transition(current_height) {
    let new_validator_set = manager.transition_epoch(current_height)?;
}
```

## Equivocation Detection and Slashing

```rust
use tenzro_consensus::{EquivocationDetector, SlashingCallback};

// EquivocationDetector is wired into VoteCollector
// When double-vote detected:
// 1. EquivocationEvidence generated
// 2. SlashingCallback::on_equivocation() invoked
// 3. In tenzro-node: StakingSlashingCallback slashes 10% of validator stake
```

## Performance Characteristics

- **Throughput**: 2,500+ TPS (400ms blocks, 10k tx/block)
- **Finality**: ~800ms (2 phases × 400ms)
- **Communication**: O(n) messages per view
- **Network Overhead**: ~64 bytes per vote signature

## Safety and Liveness

### Safety Guarantees

- No two conflicting blocks can be finalized
- Finality is irreversible once achieved
- Fork-choice follows highest QC view

### Liveness Guarantees

- Progress guaranteed with:
  - 2f+1 honest validators
  - Eventual synchrony
  - Non-faulty leader

- View changes ensure progress:
  - Timeout triggers view change
  - Round-robin ensures eventual honest leader

## Dependencies

- `tenzro-types` - Shared types
- `tenzro-crypto` - Cryptographic primitives (Ed25519 signatures)
- `tokio` - Async runtime
- `async-trait` - Async trait support
- `serde`, `serde_json` - Serialization
- `thiserror` - Error handling
- `tracing` - Logging
- `futures` - Async utilities
- `dashmap` - Concurrent maps
- `parking_lot` - High-performance locks
- `chrono` - Timestamps
- `rand` - Randomness
- `bytes` - Data buffers

## Test Coverage

39 unit tests covering:
- HotStuff-2 two-phase protocol (Prepare/Commit/Decide)
- Vote collection and QC formation
- Leader selection (round-robin and TEE-weighted)
- Epoch transitions and validator set updates
- Mempool ordering and transaction selection
- Equivocation detection and evidence generation
- View change timeouts
- Finality tracking and fork choice

## License

Licensed under either of:

- MIT license ([LICENSE](../../LICENSE) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.
