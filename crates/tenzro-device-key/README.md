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

## Provisioning requirement

Cross-restart unlock requires the embedding app to ship a
`keychain-access-groups` entitlement + an embedded provisioning profile so the
SE key persists in the data-protection keychain. This is an **app-deployment**
responsibility (the operator shipping the desktop app), not a node concern. On
an un-provisioned build, first-run create+wrap+unwrap works within the session,
but a restart cannot reopen the key — the unlocker reports the wallet as
unavailable and the node treats it as ephemeral (recreated each launch).

Non-Apple platforms currently compile to a stub backend.

## License

Apache-2.0

[`tenzro-keystore-unlock`]: https://crates.io/crates/tenzro-keystore-unlock
