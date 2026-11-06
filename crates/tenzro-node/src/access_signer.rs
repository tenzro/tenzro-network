//! The node's access-token signer: a P-256 key derived from the machine's
//! hardware root. Each token costs one derivation and one signature; the key
//! is wiped after each.

use tenzro_keygen::NodeKeys;

use crate::error::NodeError;

/// Signs access tokens with the node's hardware-rooted P-256 key.
pub struct AccessTokenSigner {
    keys: NodeKeys,
    public_key: [u8; 64],
}

impl AccessTokenSigner {
    /// The signer over `keys`.
    pub fn new(keys: NodeKeys) -> Result<Self, NodeError> {
        let public_key = keys
            .access_token_public_key()
            .map_err(|e| NodeError::Internal(format!("access-token key: {e}")))?;
        Ok(Self { keys, public_key })
    }
}

impl tenzro_auth::TokenSigner for AccessTokenSigner {
    fn public_key(&self) -> [u8; 64] {
        self.public_key
    }

    fn sign_prehash(&self, prehash: &[u8; 32]) -> Result<[u8; 64], String> {
        self.keys
            .sign_access_token(prehash)
            .map_err(|e| e.to_string())
    }
}
