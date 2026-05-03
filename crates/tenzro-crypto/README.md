# tenzro-crypto

Cryptographic primitives for the Tenzro Network.

## Overview

`tenzro-crypto` provides a comprehensive cryptographic toolkit for the Tenzro Network, including key generation, digital signatures, hashing, symmetric and asymmetric encryption, multi-party computation (MPC) threshold signatures, BLS12-381 signature aggregation, and verifiable random functions (VRF).

## Modules

**9 modules:** bls, encryption, error, hash, keys, mpc, rng, signatures, vrf

### Key Generation
- `KeyPair` - Ed25519 and Secp256k1 key pair generation
- `KeyType` - Ed25519 or Secp256k1 selection
- `PublicKey`, `SecretKey` - Public and private key types
- `Address` derivation from public keys

### Digital Signatures
- `Signer` and `Verifier` traits for pluggable signature schemes
- `Ed25519SignerImpl` - Ed25519 signature implementation
- `Secp256k1SignerImpl` - Secp256k1 signature implementation
- `Signature` - Unified signature type
- `verify()` - Signature verification with automatic algorithm detection

### Hashing
- `sha256()` - SHA-256 hashing
- `keccak256()` - Keccak-256 hashing (Ethereum-compatible)
- `Hash`, `Hasher` - Hash type and trait
- `Sha256`, `Keccak256` - Hasher implementations

### Encryption
- `SymmetricKey` - AES-256-GCM symmetric encryption
- `aes_gcm_encrypt()`/`aes_gcm_decrypt()` - AES-256-GCM operations
- `X25519KeyPair` - X25519 ECDH key exchange
- `x25519_key_exchange()` - Key agreement protocol
- `envelope_encrypt()`/`envelope_decrypt()` - Hybrid envelope encryption

### Multi-Party Computation (MPC)
- `ThresholdConfig` - Configure threshold signature schemes (e.g., 2-of-3)
- `generate_key_shares()` - Distribute key shares to parties using Shamir Secret Sharing
- `create_partial_signature()` - Generate partial signatures from key shares
- `combine_signatures_with_message()` - Reconstruct master key from shares and produce a real Ed25519/Secp256k1 signature

### BLS12-381 Signature Aggregation
- `BlsKeyPair` - BLS key pair generation on BLS12-381 curve
- `BlsSignature` - Individual BLS signatures
- `AggregateSignature` - Aggregate multiple signatures into one
- `AggregatePublicKey` - Aggregate verification keys
- Uses `blst` library for production-grade BLS12-381 operations

### Verifiable Random Function (VRF)
- RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite string `0x04`)
- `VrfSecretKey` / `VrfPublicKey` - Ed25519-compatible VRF keys (reuses validator keys)
- `VrfProof` (80 bytes) / `VrfOutput` (64 bytes)
- `prove()` / `verify()` / `proof_output()` - End-to-end VRF workflow
- Low-order key rejection and canonical scalar verification
- Used by EVM precompile 0x1007 and NFT `mintRandom` for provably-fair on-chain randomness

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
tenzro-crypto = { path = "../tenzro-crypto" }
```

### Key Generation and Signing

```rust
use tenzro_crypto::keys::{KeyPair, KeyType};
use tenzro_crypto::signatures::{Signer, Ed25519SignerImpl};
use tenzro_crypto::hash::{sha256, keccak256};

// Generate a new Ed25519 key pair
let keypair = KeyPair::generate(KeyType::Ed25519)?;
let address = keypair.address();

// Create a signer
let signer = Ed25519SignerImpl::new(keypair)?;

// Sign a message
let message = b"Hello, Tenzro Network!";
let signature = signer.sign(message)?;

// Hash data
let hash = sha256(message);
let eth_hash = keccak256(message);
```

### Encryption

```rust
use tenzro_crypto::encryption::{SymmetricKey, X25519KeyPair, envelope_encrypt, envelope_decrypt};

// Symmetric encryption
let key = SymmetricKey::generate();
let plaintext = b"secret data";
let ciphertext = key.encrypt(plaintext)?;
let decrypted = key.decrypt(&ciphertext)?;

// Envelope encryption (asymmetric)
let recipient = X25519KeyPair::generate();
let envelope = envelope_encrypt(recipient.public_key(), plaintext)?;
let decrypted = envelope_decrypt(&recipient, &envelope)?;
```

### MPC Threshold Signatures

```rust
use tenzro_crypto::mpc::{ThresholdConfig, generate_key_shares, create_partial_signature, combine_signatures_with_message, MpcKeyShare};
use tenzro_crypto::KeyType;

// Create a 2-of-3 threshold configuration
let config = ThresholdConfig::new(2, 3)?;

// Generate key shares
let shares = generate_key_shares(KeyType::Ed25519, config)?;

// Create partial signatures (need at least 2 of 3)
let message = b"Tenzro Network MPC transaction";
let partial_sigs: Vec<_> = shares.iter()
    .take(2)
    .map(|share| create_partial_signature(share, message))
    .collect::<Result<_, _>>()?;

// Reconstruct the master key from shares and produce a real Ed25519 signature
let share_refs: Vec<&MpcKeyShare> = shares.iter().take(2).collect();
let signature = combine_signatures_with_message(&share_refs, &partial_sigs, message)?;
```

### VRF (Verifiable Random Function)

```rust
use tenzro_crypto::vrf::{VrfSecretKey, prove, verify};

// Generate VRF keypair (can reuse Ed25519 validator key)
let secret_key = VrfSecretKey::from_bytes(&seed)?;
let public_key = secret_key.to_public();

// Generate VRF proof
let alpha = b"input message";
let (proof, output) = prove(&secret_key, alpha)?;

// Verify proof and extract deterministic output
let verified_output = verify(&public_key, alpha, &proof)?;
assert_eq!(output, verified_output);
```

## Dependencies

- `ed25519-dalek` - Ed25519 signatures
- `k256` - Secp256k1 signatures
- `curve25519-dalek` - Edwards25519 group operations (used by VRF)
- `aes-gcm` - AES-GCM encryption
- `x25519-dalek` - X25519 key exchange
- `argon2` - Key derivation (used by wallet keystore)
- `frost-ed25519` - Threshold signatures (MPC)
- `blst` - BLS12-381 operations (signature aggregation)
- `sha2` - SHA-256 / SHA-512 (SHA-512 used by VRF)
- `sha3` - Keccak-256
- `rand` - Random number generation
- `zeroize` - Secure memory zeroing
- `subtle` - Constant-time comparisons

## Test Coverage

68 unit tests + 9 doc tests covering:
- Key generation and address derivation
- Signature creation and verification
- Hash functions (SHA-256, Keccak-256)
- Symmetric and asymmetric encryption
- MPC threshold signatures
- BLS12-381 aggregation
- VRF proof generation and verification

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License (http://opensource.org/licenses/MIT)

at your option.
