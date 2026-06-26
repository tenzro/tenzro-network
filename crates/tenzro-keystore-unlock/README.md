# tenzro-keystore-unlock

Platform-agnostic keystore-unlock abstraction for the Tenzro wallet.

The Tenzro wallet keystore (`tenzro-wallet`) encrypts FROST key shares at rest
with a password (Argon2id). For wallets to **persist** across restarts, a node
must reproduce that password on every launch. *Where* the password comes from is
deployment-specific, so this crate defines only the boundary:

- the [`KeystoreUnlocker`] trait, whose `unlock_password()` must return the
  **same** password bytes on every call for a given device/deployment;
- two trivial, always-available implementations: [`StaticUnlocker`] (fixed
  in-memory password) and [`EnvUnlocker`] (reads an environment variable).

It deliberately has **no platform dependencies**, so it compiles everywhere and
can sit in the public API of `tenzro-wallet` / `tenzro-node` without dragging in
`security-framework`. The biometric, hardware-backed implementation lives in the
separate, macOS/iOS-flavored [`tenzro-device-key`] crate
(`SecureEnclaveUnlocker`).

```rust
use tenzro_keystore_unlock::{EnvUnlocker, KeystoreUnlocker};

// Headless / server node: operator injects the secret via the environment.
let unlocker = EnvUnlocker::new("TENZRO_KEYSTORE_PASSWORD");
let password = unlocker.unlock_password()?;
# Ok::<(), tenzro_keystore_unlock::UnlockError>(())
```

Returned passwords are wrapped in `zeroize::Zeroizing` so they are wiped from
memory on drop.

## License

Apache-2.0

[`tenzro-device-key`]: https://crates.io/crates/tenzro-device-key
