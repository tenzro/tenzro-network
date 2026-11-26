//! A payee's choice of the validator that validates on its behalf.
//!
//! A node that serves without validating relies on a validator for the
//! chain it settles on. Its payee names that validator, and once the leg is
//! in force the validator is paid a governed share of what the payee
//! settles. The rule that pays the leg is in `tenzro-vm`.

use serde::{Deserialize, Serialize};

/// The naming. An all-zero account clears it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcProviderOp {
    /// The validator's account, 20 or 32 bytes, hex.
    #[serde(with = "hex::serde")]
    pub provider: Vec<u8>,
}

impl RpcProviderOp {
    /// The account is 20 or 32 bytes.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.provider.len() != 20 && self.provider.len() != 32 {
            return Err("an RPC provider is named by its 20- or 32-byte account");
        }
        Ok(())
    }

    /// Whether the op clears the naming.
    pub fn clears(&self) -> bool {
        self.provider.iter().all(|b| *b == 0)
    }
}
