# tenzro-crypto

Cryptographic primitives for the Tenzro Network.

## Overview

`tenzro-crypto` provides the cryptographic toolkit for the Tenzro Network, including key generation, digital signatures, hashing, symmetric and asymmetric encryption, and verifiable random functions (VRF).

## Modules

**12 modules:** composite, encryption, error, hash, keys, p256, pq, rng, session, signatures, vrf, webauthn

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
- `encrypt_aes()`/`decrypt_aes()` - AES-256-GCM operations (also `SymmetricKey::encrypt`/`decrypt`)
- `X25519KeyPair` - X25519 ECDH key exchange
- `X25519KeyPair::diffie_hellman()` - Key agreement
- `envelope_encrypt()`/`envelope_decrypt()` - Hybrid envelope encryption

- `hybrid_seal` - seal a secret to an in-memory X25519 + ML-KEM-768 key (`x25519-mlkem768-hkdf-sha256-aes-256-gcm`); reading it needs both exchanges broken
- `ml_kem768` - ML-KEM-768 (FIPS 203), checked against the Wycheproof vectors

### Hash-based vouchers
- `hash_voucher` - WOTS+ one-time keys (SHA-256, Winternitz 16) under a Merkle root a payment channel on another chain commits to; one key per voucher, secrets derived from a seed the signer derives from its hardware root

### Session signatures
- `session` - session keys a hardware identity certifies; stored records carry hybrid Ed25519 / ML-DSA-65 signatures and are refused without them from the moment governance sets

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
- VRF proof generation and verification

## License

Apache-2.0.
