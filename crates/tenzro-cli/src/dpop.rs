//! This CLI's DPoP key: where it lives, and opening it once per process.
//!
//! Every signing RPC on a node is DPoP-bound, so the CLI holds a key and
//! mints a proof per request. The key, its proofs and the sign-in exchange
//! are `tenzro_auth::client`, shared with the node binary's own
//! administrative subcommands; what is the CLI's own is where the key lives:
//! this machine's TPM or Secure Enclave, or, for a machine whose keys are in
//! another machine's TPM, the key holder its node signs through.

use anyhow::Result;
use tenzro_auth::client::{DPOP_KEY_LABEL, KeyHolderDpopKey};
use tenzro_device_key::HardwareSigner;

pub use tenzro_auth::client::DpopKey;

/// The DPoP key for this machine, created in its TPM or Secure Enclave on
/// first use. Fails closed on a machine with neither: a DPoP key authorises
/// signing requests, and a key held anywhere else could be copied.
///
/// Opened once per process and kept: a command that then selects a hardware
/// key namespace (`access sign-in --key-namespace`) still proves with this
/// client's own key, which the token it is issued binds.
pub fn load_or_create() -> Result<&'static DpopKey> {
    static KEY: std::sync::Mutex<Option<&'static DpopKey>> = std::sync::Mutex::new(None);
    let mut slot = KEY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(key) = *slot {
        return Ok(key);
    }
    let signer: Box<dyn HardwareSigner> = if crate::keystore::route_keys_to_key_holder()? {
        Box::new(KeyHolderDpopKey::open()?)
    } else {
        tenzro_device_key::signer::open_or_create(DPOP_KEY_LABEL)
            .map_err(|e| anyhow::anyhow!("no hardware key for DPoP: {e}"))?
    };
    let key: &'static DpopKey = Box::leak(Box::new(DpopKey::new(signer)));
    *slot = Some(key);
    Ok(key)
}

/// Whether this machine can hold a DPoP key at all: in its own TPM or Secure
/// Enclave, or through the key holder its node signs with.
pub fn exists() -> bool {
    tenzro_device_key::signer::platform_backend().is_some()
        || crate::keystore::key_is_delegated()
        || crate::keystore::configured_key_holder().is_some()
}
