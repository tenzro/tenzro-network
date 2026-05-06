# tenzro-tee

Hardware TEE (Trusted Execution Environment) abstraction layer for the Tenzro Network.

## Overview

`tenzro-tee` provides a unified abstraction layer for multiple hardware TEE vendors, enabling secure computation, key management, and attestation across Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, and NVIDIA Confidential Computing platforms. The crate supports runtime detection of available TEE hardware and provides a consistent API across all vendors.

## Modules

**10 modules:** attestation, certs, detection, enclave_crypto, error, registry, traits, intel_tdx (feature), amd_sev_snp (feature), aws_nitro (feature), nvidia_gpu (feature)

### TEE Provider Abstraction
- `TeeProvider` trait - Unified interface for all TEE vendors
- `TeeRegistry` - Manages and tracks available TEE providers
- `AttestationVerifier` - Verifies TEE attestation reports with X.509 certificate chains
- `detect_tee()` - Runtime detection of available TEE hardware

### Supported Vendors
- **Intel TDX** - `IntelTdxProvider` for Intel Trust Domain Extensions
  - Real `/dev/tdx-guest` ioctl integration
  - TDREPORT to Quote pipeline
  - Intel PCS certificate chain verification
  - QE P-256 ECDSA signature verification over `Quote[0..632]` against the PCK leaf SPKI
- **AMD SEV-SNP** - `AmdSevSnpProvider` for AMD Secure Encrypted Virtualization
  - Real `/dev/sev-guest` ioctl integration
  - SNP_GET_REPORT command
  - AMD KDS VCEK certificate fetching and ARK→ASK→VCEK chain verification
- **AWS Nitro** - `AwsNitroProvider` for AWS Nitro Enclaves
  - Real NSM device (`/dev/nsm`) integration
  - CBOR attestation documents
  - COSE_Sign1 ES384 (P-384 ECDSA) signature verification per RFC 8152 §4.4 — rebuilds `Sig_structure1` and verifies the 96-byte signature against the leaf cert SPKI
  - AWS Nitro root CA chain validation
- **NVIDIA GPU** - `NvidiaGpuProvider` for NVIDIA Confidential Computing
  - Supports Hopper, Blackwell, and Ada Lovelace architectures
  - NRAS (NVIDIA Remote Attestation Service) HTTP API integration
  - GPU evidence collection and JWT token verification
  - SPDM-based measurements

### Attestation
- Hardware attestation report generation
- Remote attestation verification
- X.509 certificate chain validation with pinned vendor root CAs (Intel, AMD, AWS, NVIDIA)
- TEE measurement verification
- Validity period and key usage extension validation
- Functions: `verify_certificate_chain()`, `parse_x509_certificate()`, `verify_certificate_signature()`

### Enclave Encryption
- Shared AES-256-GCM encryption module (`enclave_crypto.rs`) used by all vendors
- Key derivation: `HKDF-SHA256(key_id, vendor_tag)` with domain separation
- Wire format: `nonce(12) || ciphertext || tag(16)`
- In production: keys sealed by hardware (MKTME/VMSA/KMS/CC memory)
- In simulation: keys derived from key UUID

### Simulation Support
- Runtime detection via `detect_tee()` with automatic fallback
- Environment variables for simulation: `TENZRO_SIMULATE_TDX`, `TENZRO_SIMULATE_SEV_SNP`, `TENZRO_SIMULATE_NITRO`, `TENZRO_SIMULATE_GPU`
- Consistent API in both real and simulated modes

## Feature Flags

Control which TEE vendors to compile:

- `intel-tdx` - Enable Intel TDX support (requires `reqwest`)
- `amd-sev-snp` - Enable AMD SEV-SNP support (requires `reqwest`)
- `aws-nitro` - Enable AWS Nitro support
- `nvidia-gpu` - Enable NVIDIA GPU support (requires `reqwest`)
- `all-tees` - Enable all vendors (default)

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
tenzro-tee = { path = "../tenzro-tee", features = ["all-tees"] }
```

Or select specific vendors:

```toml
[dependencies]
tenzro-tee = { path = "../tenzro-tee", features = ["intel-tdx", "nvidia-gpu"] }
```

### Basic Usage

```rust
use tenzro_tee::{detect_tee, TeeRegistry, AttestationVerifier, TeeProvider};
use tenzro_types::tee::TeeVendor;

// Detect available TEE hardware
let tee_type = detect_tee()?;
println!("Detected TEE: {:?}", tee_type);

// Create a TEE registry
let mut registry = TeeRegistry::new();

// Register a provider
let provider_id = [0u8; 32];
registry.register_provider(provider_id, tee_type)?;

// Generate an attestation
let tee_provider = registry.get_provider(&tee_type)?;
let attestation = tee_provider.generate_attestation(b"nonce")?;

// Verify the attestation
let verifier = AttestationVerifier::new();
let is_valid = verifier.verify(&attestation)?;
```

### Enclave Encryption

```rust
use tenzro_tee::enclave_crypto::{encrypt_in_enclave, decrypt_in_enclave};
use tenzro_types::tee::TeeVendor;

// Encrypt data inside TEE
let key_id = "my-key-uuid";
let plaintext = b"sensitive data";
let ciphertext = encrypt_in_enclave(key_id, plaintext, TeeVendor::IntelTDX)?;

// Decrypt data inside TEE
let decrypted = decrypt_in_enclave(key_id, &ciphertext, TeeVendor::IntelTDX)?;
assert_eq!(plaintext, &decrypted[..]);
```

## Dependencies

- `tenzro-types` - Shared types
- `tenzro-crypto` - Cryptographic primitives
- `x509-cert` - X.509 certificate parsing
- `p256`, `p384`, `rsa` - Public key cryptography
- `der`, `spki`, `signature`, `ecdsa` - Certificate chain verification
- `aes-gcm` - AES-256-GCM encryption (enclave crypto)
- `sha2` - HKDF key derivation
- `reqwest` - HTTP client for remote attestation services (Intel PCS, AMD KDS, NVIDIA NRAS)
- `libc` - System calls for `/dev/tdx-guest`, `/dev/sev-guest`, `/dev/nsm` access
- `base64` - Base64 encoding for attestation documents
- `chrono` - Certificate validity period checks
- `uuid` - Key identifiers
- `dashmap`, `parking_lot` - Concurrent registry management

## Test Coverage

80 unit tests + 1 doc test covering:
- Intel TDX attestation generation and verification
- AMD SEV-SNP attestation and certificate chain validation
- AWS Nitro attestation document parsing and signature verification
- NVIDIA GPU attestation and NRAS integration
- X.509 certificate chain verification with pinned root CAs
- Enclave encryption and decryption (all vendors)
- TEE detection and simulation fallback
- Registry management and provider lookup

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License (http://opensource.org/licenses/MIT)

at your option.
