# tenzro-vm

Multi-VM runtime for Tenzro Network — EVM, SVM, and DAML execution engines with parallel execution and account abstraction.

## Overview

The `tenzro-vm` crate provides the virtual machine execution layer for Tenzro Network, supporting multiple blockchain execution environments:

- **EVM** (Ethereum Virtual Machine) - For Ethereum-compatible smart contracts via revm
- **SVM** (Solana Virtual Machine) - For high-performance BPF programs via solana_rbpf
- **DAML** - For Canton/DAML enterprise smart contracts

## Architecture

The VM layer is designed with a pluggable executor architecture that implements a common `VmExecutor` trait. This allows Tenzro Network to support multiple execution environments while maintaining a unified interface.

```
┌─────────────────────────────────────┐
│       MultiVmRuntime                │
│  (Automatic routing & orchestration)│
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┬────────────┐
       │                │            │
   ┌───▼────┐      ┌───▼────┐  ┌───▼────┐
   │  EVM   │      │  SVM   │  │  DAML  │
   │Executor│      │Executor│  │Executor│
   └───┬────┘      └───┬────┘  └───┬────┘
       │                │            │
       └───────┬────────┴────────────┘
               │
       ┌───────▼────────┐
       │  StateAdapter  │
       │   (Caching)    │
       └───────┬────────┘
               │
       ┌───────▼────────┐
       │ Storage Layer  │
       └────────────────┘
```

## Features

- **Triple VM Support**: Execute EVM, SVM, and DAML transactions on the same blockchain
- **Automatic Routing**: Transactions are automatically routed to the correct VM based on address format
- **Gas Accounting**: Comprehensive gas metering and pricing
- **Standard EVM Precompiles (0x01-0x09)**: ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, EC_ADD, EC_MUL, EC_PAIRING, BLAKE2F
- **BLS12-381 Precompiles (0x0a-0x10, EIP-2537)**: G1ADD, G1MSM, G2ADD, G2MSM, PAIRING_CHECK, MAP_FP_TO_G1, MAP_FP2_TO_G2 using blst
- **EIP-7951 P256VERIFY (0x100)**: secp256r1 ECDSA signature verification (Fusaka Dec 2025) — bit-exact compatibility with FIDO2 / WebAuthn / Apple Secure Enclave / Android Keystore P-256 signatures
- **Tenzro-Specific Precompiles**:
  - TEE attestation verification (0x010000)
  - ZK proof verification (0x010001) — O(1) HashSet lookup against `ZkCommitmentRegistry`
  - AI model inference triggering (0x010002)
  - Settlement processing (0x010003)
  - TNZO_BRIDGE (0x1001)
  - TOKEN_FACTORY (0x1002)
  - CROSS_VM_BRIDGE (0x1003)
  - STAKING (0x1004)
  - GOVERNANCE (0x1005)
  - NFT_FACTORY (0x1006)
  - VRF_VERIFY (0x1007) — ECVRF-EDWARDS25519-SHA512-TAI per RFC 9381
  - TRAINING_VERIFY (0x1008) — Tenzro Train receipt commitment-chain verification
- **ERC-8004 System Contracts**:
  - IDENTITY (0x101a) — `registerAgent` / `getAgent` for native Tenzro agent discovery
  - REPUTATION (0x101b) — `submitFeedback` / `getFeedback` for peer-to-peer agent reputation
  - VALIDATION (0x101c) — `validationRequest` / `validationResponse` / `getValidation` for verifiable agent work attestation
- **NFT Factory**: `mintRandom()` (selector 0x52517e21) for collision-checked VRF-randomized token ID assignment and rarity tier derivation
- **Cross-VM Token Architecture (Sei V2 pointer model)**: wTNZO ERC-20 pointer at 0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93, SPL Token Adapter with 9-decimal truncation, CIP-56 DAML template — all share same underlying native TNZO balance
- **Unified Token Registry**: DashMap-indexed catalog across all VMs with RocksDB persistence (CF_TOKENS)
- **Block-STM Parallel Execution**: MVCC multi-version data, conflict detection, automatic sequential fallback
- **EIP-1559 Fee Market**: Dynamic base fee adjustment (±12.5%), fee burning, priority fee suggestions, min/max bounds
- **Account Abstraction (ERC-4337 v0.8)**: EntryPoint, UserOperation with split gas fields, PackedUserOperation, EIP-712 hashing, gas penalty 40,000, AccountFactory (CREATE2), SmartAccount modules (SocialRecovery, SessionKey, SpendingLimit, Batching), Paymaster
- **EIP-7702 Type-4 Delegation** (`eip7702.rs`): `DelegationRegistry` records authority → target pointers applied via the Pectra spec. `Authorization { chain_id, delegate_address, nonce, signature }` recovers via secp256k1 over `MAGIC(0x05) || rlp([chain_id, address, nonce])`. `delegate_address == 0x0` is a revocation. EVM executor consults `resolve_target` when an account's code begins with the 23-byte `0xef0100 || target20` designator
- **Permit2 SignatureTransfer** (`permit2.rs`): canonical Tenzro Permit2 verifying contract at `0x0000…00001023`. Full EIP-712 typed-data — `TokenPermissions`, `PermitTransferFrom`, `PermitWitnessTransferFrom` — with deterministic typehashes; Uniswap-layout 256-bit-per-word `Permit2NonceBitmap`. The witness path lets an ERC-7683 origin opener fold the cross-chain order id into the same signature that authorizes the token pull
- **Secure-Mint Registry** (`secure_mint.rs`): per-token 1:1 reserve-attestation invariant for tokenized assets. `SecureMintPolicy { asset_id, reserve, circulating, por_feed_id, attester_did, attestation_hash, attested_at, ttl_secs }`; `check_and_mint` enforces `circulating + amount ≤ reserve` plus attestation freshness; `TokenizedEquityProfile` sidecar for xStocks-class assets (CCT pool address, ISIN, CUSIP, per-share ratio, corporate-action hash). Precompile slot reserved at `0x0000…00001024`
- **State Caching**: High-performance state adapter with caching layer

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| MAX_GAS_LIMIT | 30,000,000 | Maximum gas limit per transaction |
| DEFAULT_GAS_LIMIT | 10,000,000 | Default gas limit |
| Min gas price | 0.1 Gwei | Minimum gas price (EIP-1559) |
| Max gas price | 1000 Gwei | Maximum gas price (EIP-1559) |
| Target gas | 15,000,000 | EIP-1559 target gas per block |
| Max contract size | 24,576 bytes | Maximum contract bytecode size |
| Default chain ID | 1337 | Default chain identifier |
| Max call depth | 1,024 | Maximum call stack depth |
| Block-STM conflict threshold | 50% | Conflict rate for sequential fallback |
| Block-STM max reexecutions | 16 | Maximum retry attempts |
| AA max bundle size | 100 | Max user operations per bundle |

## Usage

### Basic Example

```rust
use tenzro_vm::{
    MultiVmRuntime,
    VmTransaction,
    VmType,
    config::VmConfig,
    state_adapter::StateAdapter,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create VM configuration
    let config = VmConfig::default()
        .with_chain_id(1337)
        .with_debug(true);

    // Initialize multi-VM runtime
    let runtime = MultiVmRuntime::new(config).await?;

    // Create a state adapter
    let mut state = StateAdapter::new();

    // Create an EVM transaction
    let tx = VmTransaction::new(
        vec![1u8; 20],           // from (EVM address - 20 bytes)
        Some(vec![2u8; 20]),     // to
        1_000_000_000_000_000,   // value (1 ETH in wei)
        vec![],                  // data
        21_000,                  // gas_limit
        1_000_000_000,           // gas_price (1 Gwei)
        0,                       // nonce
        VmType::Evm,             // vm_type
        1337,                    // chain_id
    );

    // Execute transaction (automatically routed to EVM)
    let result = runtime.execute_transaction(&tx, &mut state).await?;

    println!("Success: {}", result.success);
    println!("Gas used: {}", result.gas_used);

    // Commit state changes
    state.commit()?;

    Ok(())
}
```

## VM Types

### EVM (Ethereum Virtual Machine)

- **Address Format**: 20 bytes (e.g., `0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb`)
- **Implementation**: revm
- **Gas Costs**: Ethereum-compatible gas costs
- **Bytecode**: EVM opcodes
- **Precompiles**: Standard Ethereum precompiles (0x01-0x09), BLS12-381 (0x0a-0x10, EIP-2537), EIP-7951 P256VERIFY (0x100), Tenzro service precompiles (0x010000+), Tenzro token-system precompiles (0x1001+), ERC-8004 system contracts (0x101a-0x101c)

### SVM (Solana Virtual Machine)

- **Address Format**: 32 bytes (Pubkey)
- **Implementation**: solana_rbpf
- **Compute Units**: Solana-style compute unit accounting
- **Bytecode**: BPF programs
- **Account Model**: Separate program and account data

### DAML (Canton)

- **Address Format**: Variable length (Canton party identifiers)
- **Implementation**: gRPC Canton Admin/Ledger API clients
- **Smart Contracts**: Daml 3.x templates
- **Token Standard**: CIP-56 holding contracts

## Address Format Detection

The runtime automatically detects the VM type based on address format:

- **20-byte addresses** → EVM
- **32-byte addresses** → SVM
- **Other formats** → DAML or native Tenzro

You can also explicitly specify the VM type in the transaction.

## Precompiles

### Standard EVM Precompiles (0x01-0x09)

All 9 standard precompiles fully implemented per EIPs 196/197/198/1108/2565/152:

- `0x01` - ecRecover (ECDSA signature recovery)
- `0x02` - SHA-256
- `0x03` - RIPEMD-160
- `0x04` - Identity (data copy)
- `0x05` - ModExp (modular exponentiation)
- `0x06` - ecAdd (BN254 G1 point addition)
- `0x07` - ecMul (BN254 G1 scalar multiplication)
- `0x08` - ecPairing (BN254 pairing check)
- `0x09` - BLAKE2f (BLAKE2b compression function)

### BLS12-381 Precompiles (0x0a-0x10, EIP-2537)

7 BLS12-381 precompiles using blst library:

- `0x0a` - BLS12_G1ADD
- `0x0b` - BLS12_G1MSM
- `0x0c` - BLS12_G2ADD
- `0x0d` - BLS12_G2MSM
- `0x0e` - BLS12_PAIRING_CHECK
- `0x0f` - BLS12_MAP_FP_TO_G1
- `0x10` - BLS12_MAP_FP2_TO_G2

### EIP-7951 P256VERIFY (0x100)

- `0x100` - secp256r1 ECDSA signature verification (Fusaka Dec 2025) — bit-exact compatibility with FIDO2 / WebAuthn / Apple Secure Enclave / Android Keystore

### Tenzro Service Precompiles (0x010000+)

- `0x010000` - TEE Attestation Verification (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)
- `0x010001` - ZK Proof Verification (O(1) HashSet lookup against `ZkCommitmentRegistry`; Plonky3 STARK proofs are verified off-EVM by validators, who record 32-byte SHA-256 commitments)
- `0x010002` - AI Model Inference (simulation)
- `0x010003` - Settlement Processing

### Tenzro Token-System Precompiles (0x1001+)

- `0x1001` - TNZO Bridge (wTNZO pointer operations)
- `0x1002` - Token Factory (ERC-20/SPL/CIP-56 creation)
- `0x1003` - Cross-VM Bridge (atomic cross-VM transfers)
- `0x1004` - Staking (validator/provider staking)
- `0x1005` - Governance (proposal voting)
- `0x1006` - NFT Factory (ERC-721/1155 creation, mintRandom)
- `0x1007` - VRF Verify (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI)
- `0x1008` - Training Verify (Tenzro Train receipt commitment-chain verification)

### ERC-8004 System Contracts

The ERC-8004 IdentityRegistry / ReputationRegistry / ValidationRegistry
are deployed at genesis as canonical OpenZeppelin-ERC721 upgradeable
proxies. See the addresses + ABIs in
[`tenzro_identity::erc8004::addresses`](../tenzro-identity/src/erc8004.rs).
Writes flow through standard EVM transactions; no precompile state is
involved.

## State Management

### State Adapter

The `StateAdapter` provides an in-memory caching layer for VM state with RocksDB persistence:

```rust
use tenzro_vm::StateAdapter;

let mut state = StateAdapter::new();

// Set account balance
state.set_balance(&address, 1_000_000_000_000_000_000);

// Get account balance
let balance = state.get_balance(&address);

// Set contract code
state.set_code(&address, bytecode);

// Commit changes to storage
state.commit()?;

// Or rollback
state.rollback();
```

## Integration Points

### Storage Integration

The VM integrates with `tenzro-storage` through the `VmState` trait:

```rust
pub trait VmState: Send + Sync {
    fn get_code(&self, address: &[u8]) -> Option<Vec<u8>>;
    fn set_code(&mut self, address: &[u8], code: Vec<u8>);
    fn get_storage(&self, address: &[u8], key: &[u8]) -> Option<Vec<u8>>;
    fn set_storage(&mut self, address: &[u8], key: &[u8], value: Vec<u8>);
    fn get_balance(&self, address: &[u8]) -> u128;
    fn set_balance(&mut self, address: &[u8], balance: u128);
    fn get_nonce(&self, address: &[u8]) -> u64;
    fn set_nonce(&mut self, address: &[u8], nonce: u64);
    fn exists(&self, address: &[u8]) -> bool;
}
```

## Testing

Run tests with:

```bash
cargo test -p tenzro-vm
```

Run with logging:

```bash
RUST_LOG=tenzro_vm=debug cargo test -p tenzro-vm
```

Test coverage: 286 tests passing.

## Performance Considerations

- **State Caching**: The `StateAdapter` caches all state access to minimize storage reads
- **Lazy Commit**: State changes are only written to storage on explicit commit
- **Gas Metering**: Gas is tracked incrementally during execution to catch out-of-gas early
- **Precompile Registry**: Uses `DashMap` for concurrent access to precompiles
- **Parallel Execution**: Block-STM executor for transaction-level parallelism

## Security

- **Gas Limits**: All operations are subject to gas limits to prevent DoS
- **Contract Size Limits**: Enforces maximum contract size (24 KB by default)
- **Balance Checks**: All transfers validate sufficient balance before execution
- **Nonce Tracking**: Prevents replay attacks through nonce management
- **Overflow Protection**: Checked arithmetic throughout

## Known Limitations

- Model Inference precompile returns simulated results (full inference routing works via RPC/MCP)

## Dependencies

- `tenzro-types` - Core types
- `tenzro-crypto` - Cryptographic primitives
- `tenzro-storage` - Persistent storage
- `tenzro-tee` - TEE attestation
- `tenzro-zk` - ZK proofs
- `tenzro-model` - AI model routing
- `tenzro-settlement` - Payment settlement
- `tenzro-token` - Token economics
- `revm` - EVM execution
- `solana_rbpf` - SVM BPF execution
- `blst` - BLS12-381 precompiles
- `tokio` - Async runtime

## License

Apache-2.0 OR MIT
