//! A compute provider's own word on whether it is serving.
//!
//! The owner of a compute bond says when the machine stops serving and when
//! it serves again. The rule that leaves an offline hour unjudged is in
//! `tenzro-vm`.

use serde::{Deserialize, Serialize};

/// Gas a provider presence change is sent with.
pub const GAS: u64 = 60_000;

/// The change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderPresenceOp {
    /// The DID the compute bond is posted under.
    pub provider_did: String,
    /// Whether the provider serves from the next hour.
    pub online: bool,
}

impl ProviderPresenceOp {
    /// The provider DID is a DID of at most 256 bytes.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.provider_did.starts_with("did:") || self.provider_did.len() > 256 {
            return Err("a provider presence names the provider's DID (at most 256 bytes)");
        }
        Ok(())
    }
}
