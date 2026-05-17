//! Configuration for the Tenzro iroh integration.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration for the Tenzro iroh endpoint and its companion stores.
///
/// Constructed by `tenzro-node` from the node-level config and passed into
/// [`crate::IrohBackedResolver::bind_with_config`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenzroIrohConfig {
    /// Directory under which iroh persists blob store, docs replicas, and
    /// the endpoint's secret key. Defaults to `{data_dir}/iroh`.
    pub data_dir: PathBuf,

    /// Whether to publish addressing information via the n0-relay-backed
    /// pkarr default. When `pkarr_relay_url` is set, this controls whether
    /// to *also* publish to the n0 default for cross-network discoverability;
    /// when `pkarr_relay_url` is `None`, the n0 default is the only publisher.
    pub publish_to_n0_default_discovery: bool,

    /// Tenzro-operated Pkarr relay URL — Phase C2 (#220).
    ///
    /// When set (e.g. `https://pkarr.tenzro.network/pkarr`), the iroh
    /// endpoint publishes its addressing record (`SignedPacket`) to this
    /// relay *in addition to* or *instead of* the n0 default
    /// (`dns.iroh.link/pkarr`), depending on
    /// [`Self::publish_to_n0_default_discovery`]. The relay accepts records
    /// signed by the iroh `SecretKey` returned by
    /// [`crate::tdip::derive_iroh_secret_key_from_ed25519`], which is the
    /// same 32-byte Ed25519 seed used by the node's TDIP identity — so the
    /// iroh `EndpointId` is provably anchored to the node's DID.
    ///
    /// Leave as `None` for local development and tests; the endpoint then
    /// falls back to n0-dns alone.
    pub pkarr_relay_url: Option<Url>,

    /// 32-byte seed used to derive the iroh endpoint's `SecretKey`.
    ///
    /// For protocol nodes this MUST be the same seed used to derive the
    /// node's Ed25519 validator/identity key (loaded from
    /// `{data_dir}/keys/validator_ed25519.seed` or equivalent), so the iroh
    /// `EndpointId` is byte-identical to the node's TDIP public key. The
    /// node layer is responsible for plumbing this through.
    ///
    /// Leave as `None` to let iroh generate a fresh ephemeral key (useful
    /// for tests and ad-hoc clients that don't have a TDIP identity yet).
    #[serde(skip)]
    pub secret_key_seed: Option<[u8; 32]>,

    /// Whether to enable iroh-docs (CRDT documents over iroh-blobs +
    /// iroh-gossip). Required for sealed-dataset manifest sync (Phase B2)
    /// and the agent-template registry (Phase D).
    pub enable_docs: bool,
}

impl TenzroIrohConfig {
    /// Default configuration anchored to a data directory. No custom Pkarr
    /// relay, no identity-derived secret key — suitable for local
    /// development. Protocol nodes override `pkarr_relay_url` and
    /// `secret_key_seed` from their CLI/config layer.
    pub fn with_data_dir(data_dir: PathBuf) -> Self {
        Self {
            data_dir: data_dir.join("iroh"),
            publish_to_n0_default_discovery: true,
            pkarr_relay_url: None,
            secret_key_seed: None,
            enable_docs: true,
        }
    }

    /// Anchor the iroh endpoint to a TDIP-issued Ed25519 seed. Use the same
    /// 32-byte seed the node uses for its validator/identity key.
    pub fn with_secret_key_seed(mut self, seed: [u8; 32]) -> Self {
        self.secret_key_seed = Some(seed);
        self
    }

    /// Direct the endpoint to publish its addressing record to a
    /// Tenzro-operated Pkarr relay (e.g. `https://pkarr.tenzro.network/pkarr`).
    pub fn with_pkarr_relay_url(mut self, url: Url) -> Self {
        self.pkarr_relay_url = Some(url);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_is_namespaced_under_iroh_subfolder() {
        let cfg = TenzroIrohConfig::with_data_dir(PathBuf::from("/var/lib/tenzro"));
        assert_eq!(cfg.data_dir, PathBuf::from("/var/lib/tenzro/iroh"));
        assert!(cfg.publish_to_n0_default_discovery);
        assert!(cfg.enable_docs);
        assert!(cfg.pkarr_relay_url.is_none());
        assert!(cfg.secret_key_seed.is_none());
    }

    #[test]
    fn builder_methods_set_pkarr_and_seed() {
        let url = Url::parse("https://pkarr.tenzro.network/pkarr").unwrap();
        let seed = [7u8; 32];
        let cfg = TenzroIrohConfig::with_data_dir(PathBuf::from("/tmp"))
            .with_pkarr_relay_url(url.clone())
            .with_secret_key_seed(seed);
        assert_eq!(cfg.pkarr_relay_url, Some(url));
        assert_eq!(cfg.secret_key_seed, Some(seed));
    }
}
