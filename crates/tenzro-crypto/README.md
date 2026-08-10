# tenzro-crypto

Cryptographic primitives for the Tenzro Network.

## Overview

`tenzro-crypto` provides the cryptographic toolkit for the Tenzro Network, including key generation, digital signatures, hashing, symmetric and asymmetric encryption, FROST-Ed25519 threshold signatures (RFC 9591), BLS12-381 signature aggregation, and verifiable random functions (VRF).

## Modules

**13 modules:** bls, composite, encryption, error, frost, hash, keys, p256, pq, rng, signatures, vrf, webauthn

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

### FROST-Ed25519 Threshold Signatures (RFC 9591)
- `keygen_with_trusted_dealer(threshold, total)` - Trusted-dealer keygen producing per-signer `SecretShare` + group `PublicKeyPackage`
- `dkg_part1` / `dkg_part2` / `dkg_part3` - Distributed key generation variant (no trusted dealer)
- `round1_commit(share)` - Per-signer round-1 nonce + commitment
- `build_signing_package(message, commitments)` - Coordinator's signing package
- `round2_sign(signing_pkg, nonces, share)` - Per-signer signature share
- `aggregate_signature(signing_pkg, sig_shares, group_pkg)` - Aggregate to a single 64-byte standard Ed25519 signature that verifies under the group public key with the standard Ed25519 verifier

### BLS12-381 Signature Aggregation
- `BlsKeyPair` - BLS key pair generation on BLS12-381 curve
- `BlsSignature` - Individual BLS signatures
- `AggregateSignature` - Aggregate multiple signatures into one
- `AggregatePublicKey` - Aggregate verification keys
- Uses the `blst` library for BLS12-381 curve operations

### Verifiable Random Function (VRF)
- RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite string `0x04`)
- `VrfSecretKey` / `VrfPublicKey` - Ed25519-compatible VRF keys (reuses validator keys)
- `VrfProof` (80 bytes) / `VrfOutput` (64 bytes)
- `prove()` / `verify()` / `proof_output()` - full VRF workflow
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

### FROST-Ed25519 Threshold Signatures (RFC 9591)

```rust
use tenzro_crypto::frost::{
    keygen_with_trusted_dealer, round1_commit, build_signing_package,
    round2_sign, aggregate_signature,
};
use tenzro_crypto::signatures;

// 2-of-3 threshold key (trusted dealer; DKG variant in `frost::dkg_part1`).
let (group_pkg, shares) = keygen_with_trusted_dealer(2, 3)?;

// Round 1: each signer commits.
let (n1, c1) = round1_commit(&shares[0])?;
let (n2, c2) = round1_commit(&shares[1])?;

// Coordinator builds the signing package over the message.
let message = b"Tenzro Network FROST transaction";
let signing_pkg = build_signing_package(message, &[c1, c2])?;

// Round 2: each signer produces its signature share.
let s1 = round2_sign(&signing_pkg, &n1, &shares[0])?;
let s2 = round2_sign(&signing_pkg, &n2, &shares[1])?;

// Aggregate to a single 64-byte standard Ed25519 signature that verifies
// under the group public key with the standard Ed25519 verifier.
let sig = aggregate_signature(&signing_pkg, &[s1, s2], &group_pkg)?;
let group_pk = group_pkg.group_public_key.as_public_key();
signatures::verify(&group_pk, message, &sig)?;
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
- `frost-ed25519` - FROST-Ed25519 threshold signatures (RFC 9591)
- `blst` - BLS12-381 operations (signature aggregation)
- `sha2` - SHA-256 / SHA-512 (SHA-512 used by VRF)
- `sha3` - Keccak-256
- `rand` - Random number generation
- `zeroize` - Secure memory zeroing
- `subtle` - Constant-time comparisons

## Test Coverage

Unit tests and doc tests cover:
- Key generation and address derivation
- Signature creation and verification
- Hash functions (SHA-256, Keccak-256)
- Symmetric and asymmetric encryption
- FROST-Ed25519 threshold signatures (RFC 9591)
- BLS12-381 aggregation
- VRF proof generation and verification

## License

Apache-2.0.
