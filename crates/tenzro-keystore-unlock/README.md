# tenzro-keystore-unlock

Platform-agnostic keystore-unlock abstraction for the Tenzro wallet.

The wallet keystore (`tenzro-wallet`) seals a wallet's record at rest with a
password (Argon2id). For a wallet to **persist** across restarts, a node must
reproduce that password on every launch. *Where* the password comes from is
deployment-specific, so this crate defines only the boundary: the
[`KeystoreUnlocker`] trait, whose `unlock_password()` must return the **same**
password bytes on every call for a given device.

It deliberately has **no platform dependencies**, so it compiles everywhere and
can sit in the public API of `tenzro-wallet` / `tenzro-node` without dragging in
`security-framework`. The implementations live where the hardware does:
[`tenzro-device-key`] for a Secure Enclave key gated by biometrics, and
`tenzro-keygen` for a TPM-derived one.

There is no environment-variable or fixed-password implementation. One would
put the password that opens the keystore into the process environment, where a
core dump, `/proc/<pid>/environ` or an orchestrator's secret listing hands it to
anything that can read them.

Returned passwords are wrapped in `zeroize::Zeroizing` so they are wiped from
memory on drop.

## License

Apache-2.0

[`tenzro-device-key`]: https://crates.io/crates/tenzro-device-key
