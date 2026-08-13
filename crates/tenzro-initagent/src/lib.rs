//! `tenzro-initagent` — the Tenzro machine-class guest init.
//!
//! A machine-class app is an unmodified server process running inside a
//! Firecracker microVM on a node ([`tenzro_node::machines`]). The microVM boots
//! the operator-pinned `vmlinux` with `init=/sbin/tenzro-initagent`, so this
//! binary is **PID 1** and must do everything an init does plus everything a
//! process supervisor does:
//!
//! 1. mount the kernel pseudo-filesystems (`/proc`, `/sys`, `/dev`, `/tmp`,
//!    `/run`) — nothing else brings them up when we are PID 1;
//! 2. bring up networking — loopback, and `eth0` which the kernel already
//!    addressed from the `ip=` boot cmdline the supervisor set;
//! 3. read the microVM metadata service (MMDS v2 at `169.254.169.254`, token
//!    handshake) to collect the environment the supervisor injected;
//! 4. if any secrets were delivered *sealed* rather than pre-unsealed, unseal
//!    them with the guest sealing key using the same X25519+AES-GCM envelope the
//!    node uses ([`crypto`]);
//! 5. read `/etc/tenzro/run.json` (written into the rootfs by
//!    [`tenzro_machine_builder`]) for the command, working directory, listen
//!    port and user to run as;
//! 6. assemble the final environment and `exec` the app, then **supervise** it:
//!    reap orphaned zombies (the unavoidable duty of PID 1), restart the app on
//!    crash with backoff, forward termination signals, and answer a `/health`
//!    probe.
//!
//! ## Testability
//!
//! The mount / network / exec / supervise steps are Linux syscalls and only
//! make sense inside the microVM, so they live in `main.rs` behind
//! `#[cfg(target_os = "linux")]`. Everything that can be reasoned about without
//! a VM — MMDS parsing, `run.json` parsing, sealed-env unsealing, and
//! environment assembly — is pure logic in this library with unit tests, so the
//! agent's decision-making is verified off-VM in `cargo test`.
//!
//! ## Relationship to the node's sealing model
//!
//! The shipped node ([`tenzro_node::machines`]) unseals `sealed_env` **on the
//! host, in the node enclave**, and delivers the resulting *plaintext* over
//! MMDS under the `env` key; the guest just reads it. This is the default and
//! most secure path: the X25519 private key never enters the guest. The
//! [`crypto`] module additionally lets the guest unseal envelopes *itself* when
//! a deployment opts into delivering `sealed_env` + a guest key over MMDS (e.g.
//! a TEE-attested guest that holds its own sealing key); the envelope format is
//! kept byte-identical to the node's so either side can be the unsealer.

pub mod crypto;
pub mod env;
pub mod mmds;
pub mod runjson;

pub use crypto::{EncryptedEnvelope, SealedEnvVar, envelope_decrypt, unseal_all};
pub use env::assemble_env;
pub use mmds::{MmdsData, parse_mmds};
pub use runjson::{RunSpec, parse_run_json};
