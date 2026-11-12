# tenzro-tee

Hardware TEE (Trusted Execution Environment) abstraction layer for the Tenzro Network.

## Overview

`tenzro-tee` provides a unified abstraction layer for multiple hardware TEE vendors, enabling secure computation, key management, and attestation across Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, and NVIDIA Confidential Computing platforms. The crate supports runtime detection of available TEE hardware and provides a consistent API across all vendors.

## Modules

**23 modules:** certs, detection, error, measurements, registry, report_data, traits, verify, x509, hardware_identity, identity_evidence, nvidia_device, nvidia_rim, ocsp, tpm_attest, confidential_job, key_release, intel_tdx (feature), amd_sev_snp (feature), aws_nitro (feature), nvidia_gpu (feature), nvml (feature), intel_tiber (feature)

### TEE Provider Abstraction
- `TeeProvider` trait - Unified interface for all TEE vendors
- `TeeRegistry` - Manages and tracks available TEE providers
- `verify::verify_report` - Verifies a vendor attestation report against a `VerifyPolicy`, including its X.509 certificate chain
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
- Functions in `x509`: `parse()`, `parse_pem_chain()`, `verify_issued_by()`, `verify_chain()`

### Key release and confidential jobs

- `key_release` - `verify_release` checks an environment's evidence for one release of a private model's content key (TPM quote by the admitted attestation key, TDX or SEV-SNP launch measurement, NVIDIA GPU measurements against governed roots and reference values) against the model's policy; `KeyReleaseBroker` records the release on chain, then seals the key to the environment's hybrid release key, and never stores it.
- `confidential_job` - `verify_job_evidence` checks a workload's TDX, SEV-SNP or NVIDIA GPU attestation against the job's challenge; each completed unit becomes an `AttestedUnitReceipt` the payer chains and vouchers, so the chain settles per verified unit.

### What this crate does NOT hold

A TEE is an execution environment, not a key store. No identity key, wallet key
or consensus key is sealed here: those live in a TPM, a Secure Enclave or a
passkey, and `tpm_attest.rs` / `identity_evidence.rs` verify that a machine
holds one rather than issuing it. There is no simulation mode; off supported
hardware every entry point refuses.

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
use tenzro_tee::{detect_tee, TeeRegistry, TeeProvider};
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

// Verify the attestation against a policy (`VerifyPolicy`)
let verified = tenzro_tee::verify::verify_report(&attestation, &policy)?;
```

## Dependencies

- `tenzro-types` - Shared types
- `tenzro-crypto` - Cryptographic primitives
- `x509-cert` - X.509 certificate parsing
- `p256`, `p384`, `rsa` - Public key cryptography
- `der`, `spki`, `signature`, `ecdsa` - Certificate chain verification
- `sha2` - SHA-256 digests
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
- TEE detection (no simulation path: a host without the vendor device reports no TEE)
- Registry management and provider lookup

## License

Apache-2.0.

## `tpm_attest` — a machine's TPM as its root

A TPM is the platform root on commodity hardware. `tpm_attest` reads the
endorsement key from its persistent handle, runs credential activation to prove
the attestation key lives in that TPM, and checks a quote over the verifier's
challenge. A TPM has no measured-image binding: it speaks for the platform, not
for what the platform is running.
