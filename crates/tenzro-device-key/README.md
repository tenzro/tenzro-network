# tenzro-device-key

Hardware-backed device keys for Tenzro — macOS/iOS **Secure Enclave** P-256
signing + ECIES secret-wrapping, plus a biometric `KeystoreUnlocker` for
passkey-gated wallet persistence.

A device key is a non-extractable P-256 keypair living in the platform's
hardware-rooted secure element. On macOS/iOS that is the Secure Enclave (via
`security-framework` + `kSecAttrTokenIDSecureEnclave`), gated by Touch ID /
Face ID. The private key never enters process memory.

## Two capabilities

1. **Signing** (`DeviceKey::sign_prehash`) — sign a 32-byte digest; the OS
   triggers the user-presence (Touch ID / Face ID) ceremony.
2. **Secret wrapping** (`DeviceKey::wrap_secret` / `unwrap_secret`) — ECIES-
   encrypt an arbitrary secret to the device public key (no biometrics), and
   decrypt it with the private key (biometrics). The decrypt output is **stable**
   across calls, which makes this the right primitive for deriving a persistent
   keystore password.

## SecureEnclaveUnlocker

`SecureEnclaveUnlocker` implements [`tenzro-keystore-unlock`]'s
`KeystoreUnlocker`. On first run it creates an SE key, generates a random
keystore password, wraps it to the key, and persists the ciphertext. On later
runs it reopens the key and unwraps the ciphertext (Touch ID) to recover the
**same** password — so an embedded `tenzro-node`'s FROST wallet persists across
restarts.

```rust,ignore
use std::sync::Arc;
use tenzro_device_key::SecureEnclaveUnlocker;

let unlocker = Arc::new(SecureEnclaveUnlocker::under_data_dir(&node_config.data_dir));
let handle = tenzro_node::spawn_in_background_with_unlocker(node_config, unlocker).await?;
```

## Cargo features

The default build depends only on the platform keychain, so an embedder that
wants a device-local enclave key gets exactly that and nothing else.

| Feature | Default | Adds |
|---|---|---|
| `pq-companion` | off | `PqCompanion`, an ML-DSA-65 (FIPS-204) key whose seed is ECIES-wrapped to the enclave key, for the post-quantum leg of hybrid passkey custody. Pulls in `tenzro-crypto` and its elliptic-curve + post-quantum dependency graph. |

## Persistence

Cross-restart unlock works on a plain Developer-ID build with no extra
entitlements: the Secure-Enclave key is persisted in the file-based (login)
keychain via `Location::DefaultFileKeychain`, which sets `kSecAttrIsPermanent`
without requiring the `keychain-access-groups` entitlement or a provisioning
profile (those are needed only by the data-protection keychain — see Apple
TN3137). Touch ID / Face ID still gates every signing operation. A later run
reopens the key by label and unwraps the on-disk ciphertext to recover the same
password. If the key is gone (a different machine, or a reset login keychain),
the unlocker reports the wallet as unavailable and the node recreates it.

Non-Apple platforms currently compile to a stub backend.

## License

Apache-2.0

[`tenzro-keystore-unlock`]: https://crates.io/crates/tenzro-keystore-unlock
