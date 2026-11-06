//! Configuration for the Tenzro iroh integration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::identity_record::BootIdentity;
use crate::identity_transport::RelayRoleConfig;

/// Default UDP socket address for the iroh QUIC endpoint (magicsock).
///
/// `0.0.0.0:9001`. A node needs no inbound port: it reaches its relays
/// outbound and iroh upgrades a relayed path to a direct one when both
/// sides can. A fixed port only makes those direct paths predictable for an
/// operator who chooses to allow them.
pub const DEFAULT_IROH_BIND_PORT: u16 = 9001;

/// Default UDP port a node serving the relay role binds instead of its
/// configured one ([`TenzroIrohConfig::relay_udp_port`]): 443, which networks that pass only web traffic leave open, so a node
/// on such a network still reaches it, and through it its peers. Binding it
/// needs the right to bind a port below 1024 (on Linux the capability
/// `CAP_NET_BIND_SERVICE`, e.g. `AmbientCapabilities=CAP_NET_BIND_SERVICE` in
/// the service unit).
pub const EDGE_UDP_PORT: u16 = 443;

fn default_iroh_bind_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_IROH_BIND_PORT)
}

/// Configuration for the Tenzro iroh endpoint and its companion stores.
///
/// Constructed by `tenzro-node` from the node-level config and passed into
/// [`crate::IrohBackedResolver::bind_with_config`].
/// Every field carries the [`Default`] below when the TOML omits it, so an
/// operator can override one value without restating the whole section.
///
/// Nothing here names a relay, pkarr host or peer by default: the node
/// reaches only the machine identities its operator lists in `boot` (and the
/// genesis validators), through the relays those entries name.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TenzroIrohConfig {
    /// The endpoint's key, when the node derived a stable one: the same
    /// endpoint id at every boot, so peers that hold this machine's record
    /// reach it again after a restart. Without it the key is made at random
    /// at each bind. Each endpoint's own, so endpoints bound in one process
    /// never share a key; set by the node at startup and never read from or
    /// written to a configuration file.
    #[serde(skip)]
    pub endpoint_secret: EndpointSecret,

    /// Directory under which iroh persists its blob store and docs
    /// replicas. Defaults to `{data_dir}/iroh`.
    pub data_dir: PathBuf,

    /// Whether to enable iroh-docs (CRDT documents over iroh-blobs +
    /// iroh-gossip).
    pub enable_docs: bool,

    /// UDP socket address for iroh's QUIC endpoint (magicsock). Setting the
    /// port to `0` requests a random free port.
    #[serde(default = "default_iroh_bind_addr")]
    pub bind_addr: SocketAddr,

    /// Machine identities to join the network through, each optionally with
    /// the relay it is reachable at: `did:tenzro:machine:{id}` or
    /// `did:tenzro:machine:{id}@{relay URL}`. Never a network address.
    pub boot: Vec<BootIdentity>,

    /// The relay role, when this node serves it.
    pub relay: Option<RelayRoleConfig>,

    /// UDP port the endpoint binds while this node serves the relay role,
    /// in place of `bind_addr`'s port. [`EDGE_UDP_PORT`] by default; one
    /// process per host can hold a port, so machines that run several
    /// relays (test clusters) give each its own.
    pub relay_udp_port: u16,

    /// A private node: its endpoint binds no IP socket at all and reaches
    /// every peer through its relays, so no peer ever learns an address of
    /// it. A validator leaves this off, since validators connect directly.
    pub relay_only: bool,

    /// The machine identities a private node's endpoint record is shared
    /// with, besides its boot identities. Unused on a node whose
    /// capabilities are advertised.
    pub counterparties: Vec<String>,

    /// Ask the local router to forward the endpoint's UDP port (UPnP IGD,
    /// PCP or NAT-PMP, whichever it answers). On by default; a node needs
    /// no inbound port either way, a mapped port only adds direct paths.
    pub port_mapping: bool,

    /// An HTTP proxy relays are reached through, for networks that allow
    /// outbound web traffic only through one (`http://proxy.corp:3128`).
    /// Unset, the `HTTPS_PROXY`/`HTTP_PROXY` environment applies, as for
    /// other command-line tools.
    pub proxy: Option<url::Url>,

    /// Bounds on each request protocol the endpoint serves to peers it has
    /// not vetted: streams served at once, overall and per peer, and how long
    /// a peer may take to send a request or to take a reply.
    pub admission: crate::limits::AdmissionLimits,

    /// How many connections the endpoint holds, overall and per peer, and
    /// the QUIC limits each runs under: idle timeout, concurrent streams and
    /// the connection-wide receive window. The `[iroh.connection]` table.
    pub connection: crate::connection_limits::ConnectionLimits,
}

impl TenzroIrohConfig {
    /// Default configuration anchored to a data directory.
    pub fn with_data_dir(data_dir: PathBuf) -> Self {
        Self {
            data_dir: data_dir.join("iroh"),
            ..Self::default()
        }
    }

    /// Default configuration with the endpoint on a loopback port that was
    /// free when this was called, for a node that only talks to peers on
    /// the same host and must not contend for the fixed default port. When no
    /// port can be probed, port 0 leaves the choice to the operating system.
    pub fn loopback() -> Self {
        let bind_addr = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|s| s.local_addr())
            .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
        Self {
            bind_addr,
            ..Self::default()
        }
    }
}

/// A stable key for the node's endpoint, kept out of logs and out of
/// configuration files.
#[derive(Clone, Default)]
pub struct EndpointSecret(pub Option<[u8; 32]>);

impl std::fmt::Debug for EndpointSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "EndpointSecret(set)"
        } else {
            "EndpointSecret(none)"
        })
    }
}

impl TenzroIrohConfig {
    /// This configuration for an endpoint that only dials out: the same
    /// address but an ephemeral port, and no relay port, so it never holds
    /// the ports the node's own endpoint binds, and a blob store of its own
    /// under `data_dir/state-sync`, so it never holds the one the node opens
    /// next.
    pub fn dial_only(&self) -> Self {
        let mut cfg = self.clone();
        cfg.data_dir = self.data_dir.join("state-sync");
        cfg.bind_addr.set_port(0);
        cfg.relay_udp_port = 0;
        cfg
    }
}

impl Default for TenzroIrohConfig {
    /// The `data_dir` is set under the Tenzro root's default instance and is
    /// expected to be overridden by the caller (e.g. `tenzro-node` rebases it
    /// under the node's `--data-dir`).
    fn default() -> Self {
        Self {
            data_dir: tenzro_types::paths::default_data_dir().join("iroh"),
            enable_docs: true,
            bind_addr: default_iroh_bind_addr(),
            boot: Vec::new(),
            relay: None,
            relay_udp_port: EDGE_UDP_PORT,
            relay_only: false,
            counterparties: Vec::new(),
            port_mapping: true,
            proxy: None,
            admission: crate::limits::AdmissionLimits::default(),
            connection: crate::connection_limits::ConnectionLimits::default(),
            endpoint_secret: EndpointSecret::default(),
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
        assert!(cfg.enable_docs);
        assert_eq!(cfg.bind_addr, default_iroh_bind_addr());
    }

    #[test]
    fn no_default_config_names_a_relay_pkarr_host_or_peer() {
        for cfg in [
            TenzroIrohConfig::default(),
            TenzroIrohConfig::with_data_dir(PathBuf::from("/tmp")),
        ] {
            assert!(cfg.boot.is_empty());
            assert!(cfg.relay.is_none());
            let rendered = serde_json::to_string(&cfg).unwrap();
            for host in ["://", "iroh.link", "n0", "pkarr", "relay."] {
                assert!(
                    !rendered.contains(host),
                    "default config mentions {host}: {rendered}"
                );
            }
        }
        // Under the Tenzro root's default instance rather than a
        // cwd-relative path: two nodes started from different directories
        // used to get different blob stores and re-fetch everything.
        assert_eq!(
            TenzroIrohConfig::default().data_dir,
            tenzro_types::paths::default_data_dir().join("iroh")
        );
    }

    /// No endpoint this crate builds can reach an outside discovery or relay
    /// service: none of the calls that would configure one appears in its
    /// source. The needles are assembled so this test does not match itself.
    #[test]
    fn no_outside_relay_dns_pkarr_or_dht_service_is_wired_anywhere() {
        let sources = [
            include_str!("resolver.rs"),
            include_str!("identity_transport.rs"),
            include_str!("discovery.rs"),
            include_str!("relay.rs"),
            include_str!("jsonrpc.rs"),
            include_str!("consensus.rs"),
            include_str!("block_sync.rs"),
        ];
        let needles = [
            ["presets::", "N0"].concat(),
            ["n0", "_dns("].concat(),
            ["iroh", ".link"].concat(),
            ["RelayMode::", "Default"].concat(),
            ["RelayMode::", "Staging"].concat(),
            ["Pkarr", "Publisher"].concat(),
            ["Pkarr", "Resolver"].concat(),
            ["DnsAddress", "Lookup"].concat(),
            ["Dht", "AddressLookup"].concat(),
            ["main", "line"].concat(),
        ];
        for source in sources {
            for needle in &needles {
                assert!(
                    !source.contains(needle.as_str()),
                    "{needle} is wired into an endpoint"
                );
            }
        }
    }

    #[test]
    fn a_relay_binds_443_unless_its_operator_names_another_port() {
        let default: TenzroIrohConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(default.relay_udp_port, EDGE_UDP_PORT);
        let own: TenzroIrohConfig = serde_json::from_str(r#"{"relay_udp_port": 28045}"#).unwrap();
        assert_eq!(own.relay_udp_port, 28045);
    }

    #[test]
    fn a_config_boot_list_refuses_network_addresses() {
        let bad: Result<TenzroIrohConfig, _> = serde_json::from_str(
            r#"{"boot": ["/ip4/192.0.2.10/tcp/9000/p2p/12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo"]}"#,
        );
        assert!(bad.is_err());
        let did = format!("did:tenzro:machine:{}", "ab".repeat(32));
        let good: TenzroIrohConfig = serde_json::from_str(&format!(
            r#"{{"boot": ["{did}@https://relay.example.org"]}}"#
        ))
        .unwrap();
        assert_eq!(good.boot[0].did, did);
    }
}
