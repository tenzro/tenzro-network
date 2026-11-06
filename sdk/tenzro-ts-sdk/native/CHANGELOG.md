# Changelog

## 0.1.1

First release.

- Reads the public key and signs a SHA-256 digest (P-256, r||s) with a key held
  in the TPM 2.0 (Linux, Windows) or the Apple Secure Enclave (macOS).
- `attest()` is declared and rejects: no backend produces attestation evidence
  yet.
- The private key never leaves the hardware; there is no export and no software
  fallback.
- Prebuilt binaries for linux-x64-gnu, linux-arm64-gnu, darwin-arm64,
  darwin-x64 and win32-x64-msvc (the platforms Tenzro releases for), installed as optional
  per-platform packages.
- `provisionTpm()` and the `tenzro-device-key provision` command (`npx @tenzro/device-key provision`) provision the machine's TPM once, the step that `tenzro-node tpm provision` performs. Idempotent; a Secure Enclave needs none. The error for an unprovisioned TPM names that command.
