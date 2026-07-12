//! Configuration for the Tenzro iroh integration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::Url;

/// Default UDP socket address for the iroh QUIC endpoint (magicsock).
///
/// `0.0.0.0:9001` — one above the libp2p QUIC port (9000) so the two QUIC
/// stacks can coexist on a single host. Operators open UDP/9001 alongside
/// UDP/9000 in their firewall; community joiners on home/mobile networks
/// override via [`TenzroIrohConfig::bind_addr`] when their NAT mapping
/// requires a different port.
///
/// Pinning a fixed port is required because iroh's magicsock binds two
/// random ephemeral UDP ports per boot by default, which cannot be opened
/// in any firewall ahead of time. Without pinning, cross-region QUIC dials
/// from non-permissive networks are silently dropped at the destination.
pub const DEFAULT_IROH_BIND_PORT: u16 = 9001;

fn default_iroh_bind_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_IROH_BIND_PORT)
}

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

    /// Tenzro-operated Pkarr relay URL.
    ///
    /// When set (e.g. `https://pkarr.tenzro.xyz`), the iroh endpoint
    /// publishes its addressing record (`SignedPacket`) to this relay *in
    /// addition to* or *instead of* the n0 default (`dns.iroh.link/pkarr`),
    /// depending on [`Self::publish_to_n0_default_discovery`]. The relay
    /// accepts records signed by the iroh `SecretKey` returned by
    /// [`crate::tdip::derive_iroh_secret_key_from_ed25519`], which is the
    /// same 32-byte Ed25519 seed used by the node's TDIP identity — so the
    /// iroh `EndpointId` is provably anchored to the node's DID.
    ///
    /// The URL is the relay's HTTP base; iroh's `PkarrPublisher`/`PkarrResolver`
    /// append `/<z32_key>` internally per the Pkarr relay HTTP spec served
    /// by the upstream `pkarr-relay` binary (`pubky/pkarr` crate). Do not
    /// suffix `/pkarr` — the relay binary serves PUT/GET at the root.
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

    /// Fixed UDP socket address for iroh's QUIC endpoint (magicsock).
    ///
    /// Defaults to `0.0.0.0:9001` — see [`DEFAULT_IROH_BIND_PORT`] for the
    /// rationale. Operators on cloud platforms (GCE/AWS/Azure) open the
    /// matching UDP port in their firewall. Community joiners on
    /// home/mobile networks may need to override to a different port if
    /// their NAT/router requires a specific mapping.
    ///
    /// Setting the port to `0` requests a random free port (only useful
    /// for tests and ad-hoc clients; cross-node reachability requires a
    /// deterministic port).
    #[serde(default = "default_iroh_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Externally-reachable UDP socket addresses for this endpoint.
    ///
    /// iroh's [`crate::address_lookup::PkarrPublisher`] publishes a DNS
    /// record containing the endpoint's `direct_addrs` so peers can dial
    /// back via plain UDP. Two things must be true for that record to be
    /// non-empty:
    ///
    /// 1. The endpoint must actually know its public reachable address.
    ///    With `presets::Minimal` (relay disabled, no STUN-based
    ///    `net_report`), iroh has no way to autodiscover this — magicsock
    ///    only sees its bind socket's local address (e.g. `10.0.0.37:9001`
    ///    on GCE), which isn't reachable from outside the VPC. Operators
    ///    plumb the routable address through this field.
    /// 2. The publisher's `AddrFilter` must permit direct addresses (i.e.
    ///    `AddrFilter::unfiltered()`). The default filter is `relay_only`
    ///    which drops direct addrs from the published DNS body — fine for
    ///    NAT'd nodes that round-trip through an iroh relay, broken for
    ///    nodes with public IPs and no relay. The resolver layer flips this
    ///    to `unfiltered()` when `external_addrs` is non-empty.
    ///
    /// Each entry is a `host:port` socket address. For GCE / AWS / Azure
    /// fleets this is the VM's external IP plus the iroh bind port
    /// (typically `9001`). Home / mobile / corporate-NAT nodes leave this
    /// empty and rely on a forthcoming relay-fallback path (Phase C4); the
    /// current relay-disabled `Minimal` preset means those nodes can only
    /// receive cross-node fetches via libp2p, not iroh.
    ///
    /// Multiple addresses are accepted (e.g. v4 + v6, or multi-NIC hosts).
    /// The serde default is empty so existing configs deserialize unchanged.
    #[serde(default)]
    pub external_addrs: Vec<SocketAddr>,
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
            bind_addr: default_iroh_bind_addr(),
            external_addrs: Vec::new(),
        }
    }

    /// Anchor the iroh endpoint to a TDIP-issued Ed25519 seed. Use the same
    /// 32-byte seed the node uses for its validator/identity key.
    pub fn with_secret_key_seed(mut self, seed: [u8; 32]) -> Self {
        self.secret_key_seed = Some(seed);
        self
    }

    /// Direct the endpoint to publish its addressing record to a
    /// Tenzro-operated Pkarr relay (e.g. `https://pkarr.tenzro.xyz`).
    pub fn with_pkarr_relay_url(mut self, url: Url) -> Self {
        self.pkarr_relay_url = Some(url);
        self
    }

    /// Override the UDP socket address bound by iroh's QUIC endpoint.
    ///
    /// Default is `0.0.0.0:9001`. Override on hosts where UDP/9001 is
    /// already taken or where the NAT mapping requires a specific port.
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Append an externally-reachable UDP socket address. See
    /// [`Self::external_addrs`] for why this is required on nodes with
    /// public IPs that don't proxy through an iroh relay.
    pub fn with_external_addr(mut self, addr: SocketAddr) -> Self {
        self.external_addrs.push(addr);
        self
    }
}

impl Default for TenzroIrohConfig {
    /// Production default — TDIP-anchored, publishing to the Tenzro-operated
    /// Pkarr relay (`https://pkarr.tenzro.xyz`), with the n0 fallback
    /// disabled so discovery cannot leak off-network.
    ///
    /// The `data_dir` is set to `./data/iroh` and is expected to be
    /// overridden by the caller (e.g. `tenzro-node` rebases it under the
    /// node's `--data-dir`). `secret_key_seed` stays `None` here and is
    /// populated by `tenzro-node` at startup from the validator/identity
    /// keypair so the iroh `EndpointId` is byte-identical to the node DID.
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data/iroh"),
            publish_to_n0_default_discovery: false,
            pkarr_relay_url: Some(
                Url::parse("https://pkarr.tenzro.xyz")
                    .expect("pkarr.tenzro.xyz is a valid URL"),
            ),
            secret_key_seed: None,
            enable_docs: true,
            bind_addr: default_iroh_bind_addr(),
            external_addrs: Vec::new(),
        }
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
        assert_eq!(cfg.bind_addr, default_iroh_bind_addr());
        assert!(cfg.external_addrs.is_empty());
    }

    #[test]
    fn with_external_addr_appends() {
        let a1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(35, 184, 63, 8)), 9001);
        let a2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(35, 232, 48, 224)), 9001);
        let cfg = TenzroIrohConfig::with_data_dir(PathBuf::from("/tmp"))
            .with_external_addr(a1)
            .with_external_addr(a2);
        assert_eq!(cfg.external_addrs, vec![a1, a2]);
    }

    #[test]
    fn builder_methods_set_pkarr_and_seed() {
        let url = Url::parse("https://pkarr.tenzro.xyz").unwrap();
        let seed = [7u8; 32];
        let cfg = TenzroIrohConfig::with_data_dir(PathBuf::from("/tmp"))
            .with_pkarr_relay_url(url.clone())
            .with_secret_key_seed(seed);
        assert_eq!(cfg.pkarr_relay_url, Some(url));
        assert_eq!(cfg.secret_key_seed, Some(seed));
    }

    #[test]
    fn default_points_at_tenzro_pkarr_relay_and_skips_n0_fallback() {
        let cfg = TenzroIrohConfig::default();
        assert_eq!(
            cfg.pkarr_relay_url,
            Some(Url::parse("https://pkarr.tenzro.xyz").unwrap())
        );
        assert!(!cfg.publish_to_n0_default_discovery);
        assert!(cfg.enable_docs);
        assert!(cfg.secret_key_seed.is_none());
        assert_eq!(cfg.data_dir, PathBuf::from("./data/iroh"));
        assert_eq!(
            cfg.bind_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_IROH_BIND_PORT)
        );
    }

    #[test]
    fn with_bind_addr_overrides_default() {
        let custom = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 12345);
        let cfg = TenzroIrohConfig::with_data_dir(PathBuf::from("/tmp"))
            .with_bind_addr(custom);
        assert_eq!(cfg.bind_addr, custom);
    }
}
