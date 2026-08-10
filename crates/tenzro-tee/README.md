# tenzro-tee

Hardware TEE (Trusted Execution Environment) abstraction layer for the Tenzro Network.

## Overview

`tenzro-tee` provides a unified abstraction layer for multiple hardware TEE vendors, enabling secure computation, key management, and attestation across Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, and NVIDIA Confidential Computing platforms. The crate supports runtime detection of available TEE hardware and provides a consistent API across all vendors.

## Modules

**15 modules:** attestation, certs, detection, enclave_crypto, enclave_keystore, error, registry, sealed_agent_keypair, sealed_secp256k1, traits, intel_tdx (feature), amd_sev_snp (feature), aws_nitro (feature), nvidia_gpu (feature), intel_tiber (feature)

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

### Enclave Key Storage
- `enclave_keystore.rs` holds the private scalar behind every `EnclaveKeyHandle` returned by `TeeProvider::enclave_keygen`, and backs `enclave_sign` / `enclave_encrypt` / `enclave_decrypt`
- Keys are HKDF-SHA256-derived from per-vendor IKM (TDX `MRTD`, SNP `SNP_GET_DERIVED_KEY`, the Nitro signed attestation report, the NVIDIA vBIOS measurement). Off hardware, `is_available()` is `false` and `enclave_keygen` returns `TeeError::not_available` — there is no software-only fabrication path
- Scalars live in `Zeroizing` buffers and are wiped on drop

### Sealed Signing Keys
- `sealed_secp256k1.rs` derives a `k256` ECDSA signing key from the hardware root so a bridge EVM signer never holds a long-lived private key in ordinary process memory. The same measured VM image redeploys to the same key; a tampered image or another tenant cannot recover it
- `sealed_agent_keypair.rs` does the same for the Ed25519 keys behind TDIP / ERC-8004 machine identities. `AgentKeyHandle` exposes only the public key, the vendor measurement, the rotation epoch and a `sign()` entry point; `rotate_agent_key` bumps the epoch while leaving the prior handle alive so in-flight operations finish, and `attest_agent_key` binds the public key into an attestation report's `user_data` slot

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
- `intel-tiber` - Enable Intel Tiber Trust Authority hosted attestation (implies `intel-tdx`)
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
use tenzro_tee::enclave_crypto::{enclave_encrypt_aes256gcm, enclave_decrypt_aes256gcm};
use uuid::Uuid;

// Vendor tag binds the derived AES key to a specific TEE family.
// Use the vendor's `enclave_vendor_tag()` helper to obtain this (e.g. `b"intel-tdx"`).
let key_id = Uuid::new_v4();
let vendor_tag: &[u8] = b"intel-tdx";
let plaintext = b"sensitive data";

// Encrypt: nonce(12) || ciphertext || tag(16)
let ciphertext = enclave_encrypt_aes256gcm(&key_id, vendor_tag, plaintext)?;

// Decrypt with the same key_id + vendor_tag
let decrypted = enclave_decrypt_aes256gcm(&key_id, vendor_tag, &ciphertext)?;
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

Unit tests and doc tests cover:
- Intel TDX attestation generation and verification
- AMD SEV-SNP attestation and certificate chain validation
- AWS Nitro attestation document parsing and signature verification
- NVIDIA GPU attestation and NRAS integration
- X.509 certificate chain verification with pinned root CAs
- Enclave encryption and decryption (all vendors)
- TEE detection and simulation fallback
- Registry management and provider lookup

## License

Apache-2.0.

## `tpm_seal` — sealing a machine's own key to its TPM

A machine that stores its own key seals it rather than writing a keyfile: the
blob on disk is ciphertext under the TPM's storage hierarchy, so copying the
disk yields something no other TPM will open. A host that cannot seal is refused
rather than degrading to plaintext — the value of the autonomous claim rests on
the key being unextractable.

Driven through `tpm2-tools`, the same way this workspace already talks to
`nvidia-smi` and `rocm-smi`; the secret reaches the TPM over the tool's stdin and
never touches disk in the clear.

A TPM is also the **third platform root** (`platform_root`), after SEV-SNP and
TDX, and on commodity hardware the only one. It has no measured-image binding —
it seals to the platform, not to what the platform is running — but it is what
an ordinary machine has, and the identity rule already requires an attestable
root before a machine may speak for itself.
