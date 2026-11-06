//! The operator's own credential for the Hugging Face origin.
//!
//! Some catalog entries are gated by their origin behind an account and a
//! licence. A node fetches gated weights from network providers holding them;
//! an operator who also has their own Hugging Face account can give the node
//! that account's access token so it can fetch gated weights from the origin
//! itself. The credential belongs to the operator, never to the network: no
//! default exists, the node never reads a token from anywhere but the
//! operator's sealed store or [`ENV`], and a node without one still serves
//! every open model and fetches gated ones from peers.
//!
//! The credential is sent only as the `Authorization` header of a download of
//! a gated file from the origin. It is not logged, not serialized, not sent to
//! peers or the chain and not part of any receipt: the type has no `Serialize`
//! impl and its `Debug` prints nothing of it.

use std::sync::{Arc, RwLock};

use zeroize::Zeroizing;

/// The environment variable an operator who keeps secrets outside the node
/// sets to their own Hugging Face access token. A token sealed to the machine
/// is used before it.
pub const ENV: &str = "TENZRO_HUGGINGFACE_CREDENTIAL";

/// How an operator sets the credential, for error messages.
pub const HOW_TO_SET: &str = "set this operator's own Hugging Face credential with `tenzro-node credentials set huggingface` \
     (or the TENZRO_HUGGINGFACE_CREDENTIAL environment variable) to fetch it from its origin";

/// An operator's access token for the Hugging Face origin.
pub struct OriginCredential(Zeroizing<String>);

impl OriginCredential {
    /// Accept `token` as given by the operator, trimmed. Refuses an empty
    /// token and one with whitespace or control characters inside it, which
    /// no access token has and which could not be sent as a header.
    pub fn new(token: &str) -> Result<Self, String> {
        let t = token.trim();
        if t.is_empty() {
            return Err("the credential is empty".into());
        }
        if t.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("the credential has whitespace or control characters in it".into());
        }
        Ok(Self(Zeroizing::new(t.to_string())))
    }

    /// The token, for sealing it into the operator's store.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The `Authorization` header value, marked sensitive so the HTTP stack
    /// never prints it.
    pub(crate) fn header_value(&self) -> Option<reqwest::header::HeaderValue> {
        let mut v =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", self.0.as_str())).ok()?;
        v.set_sensitive(true);
        Some(v)
    }
}

impl std::fmt::Debug for OriginCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OriginCredential(redacted)")
    }
}

static INSTALLED: RwLock<Option<Arc<OriginCredential>>> = RwLock::new(None);

/// Install the operator's credential for this process, or remove it.
pub fn install(credential: Option<OriginCredential>) {
    *INSTALLED.write().unwrap_or_else(|e| e.into_inner()) = credential.map(Arc::new);
}

/// Whether the operator set a credential.
pub fn installed() -> bool {
    INSTALLED
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
}

pub(crate) fn current() -> Option<Arc<OriginCredential>> {
    INSTALLED.read().unwrap_or_else(|e| e.into_inner()).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_nothing_of_the_token() {
        let c = OriginCredential::new("  secret-value-123 ").unwrap();
        assert_eq!(c.expose(), "secret-value-123");
        assert!(!format!("{c:?}").contains("secret"));
        let h = c.header_value().unwrap();
        assert!(h.is_sensitive());
        assert!(!format!("{h:?}").contains("secret"));
    }

    #[test]
    fn empty_and_malformed_tokens_are_refused() {
        assert!(OriginCredential::new(" ").is_err());
        assert!(OriginCredential::new("a b").is_err());
        assert!(OriginCredential::new("a\nb").is_err());
    }
}
