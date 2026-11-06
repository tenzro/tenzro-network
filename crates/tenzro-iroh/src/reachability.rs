//! How reachable this node is, as its peers see it.
//!
//! An iroh endpoint knows the addresses of its own sockets and, when the
//! router offers UPnP, PCP or NAT-PMP, the port the router mapped for it. It
//! does not know the address a NAT gives it on the internet. A peer that
//! reaches the node over a direct path sees that address, and tells it when
//! asked (the `Observe` request of the discovery protocol), the way a STUN
//! server or an ICE connectivity check reports a server-reflexive address.
//!
//! An address that at least [`CONFIRMATIONS`] different machines report is
//! added to the endpoint as an external address, so iroh offers it to peers
//! as a hole-punching candidate. One peer alone cannot place an address on a
//! node: a report has to agree with another machine's to be used.
//!
//! Comparing the reports also tells the kind of NAT in front of the node:
//!
//! - every peer sees the node's own socket address: no NAT;
//! - every peer sees the same address and port: endpoint-independent mapping,
//!   which hole punching gets through;
//! - peers see different ports (or addresses): endpoint-dependent mapping
//!   (often called symmetric NAT). Hole punching reaches peers with a public
//!   or mapped address; other peers are reached through a relay.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use iroh::{Endpoint, Watcher};
use serde::{Deserialize, Serialize};

/// Different machines that must report the same address before it is used.
pub const CONFIRMATIONS: usize = 2;

/// How long a report counts, in milliseconds.
pub const OBSERVATION_TTL_MS: u64 = 30 * 60 * 1000;

/// Most reports kept at once, one per reporting machine.
const MAX_OBSERVERS: usize = 64;

/// The kind of NAT in front of the node, from its peers' reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatKind {
    /// Fewer than two peers have seen the node over a direct path yet.
    Unknown,
    /// Peers see the node's own socket address.
    None,
    /// Every peer sees the same address and port.
    EndpointIndependent,
    /// Peers see different ports or addresses.
    EndpointDependent,
}

/// How peers reach the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    /// Directly, at a public address of its own.
    Public,
    /// Directly, at a port its router mapped for it.
    PortMapped,
    /// Directly once both sides punch through their NATs.
    HolePunch,
    /// Through a peer relay: a directly reachable node forwarding over UDP.
    PeerRelay,
    /// Through a relay, except from peers with a public or mapped address.
    Relay,
    /// Neither directly nor through a relay.
    Unreachable,
}

/// The address one machine reported for this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// The reporting machine.
    pub peer: String,
    /// The address it saw.
    pub addr: SocketAddr,
    /// Seconds since the report.
    pub age_secs: u64,
}

/// A relay this node uses, and whether it is connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayState {
    /// The relay URL.
    pub url: String,
    /// Whether the endpoint holds a connection to it now.
    pub connected: bool,
    /// The last connection error, if any.
    pub error: Option<String>,
}

/// A forwarder the endpoint keeps a connection to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwarderState {
    /// The forwarder's endpoint id.
    pub endpoint: String,
    /// Round-trip time to it, in milliseconds.
    pub rtt_ms: u64,
    /// Whether the connection to it runs on a direct path.
    pub direct: bool,
}

/// What the node knows about its own reachability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connectivity {
    /// How peers reach the node.
    pub reachability: Reachability,
    /// The NAT in front of it.
    pub nat: NatKind,
    /// The sockets the endpoint bound.
    pub bound: Vec<SocketAddr>,
    /// The addresses the endpoint offers peers for direct paths.
    pub advertised: Vec<SocketAddr>,
    /// Addresses peers confirmed and the endpoint now offers as well.
    pub external: Vec<SocketAddr>,
    /// A port the router mapped, when one is offered.
    pub port_mapped: Option<SocketAddr>,
    /// The current reports, newest first.
    pub observed: Vec<Observation>,
    /// The relays the endpoint connects through.
    pub relays: Vec<RelayState>,
    /// The peer relays (forwarders) the endpoint offers paths through.
    pub forwarders: Vec<ForwarderState>,
    /// Peers reached on a birthday-punched path.
    pub punched: usize,
    /// Whether the node has an IPv4 path to the internet.
    pub ipv4: bool,
    /// Whether the node has an IPv6 path to the internet.
    pub ipv6: bool,
}

/// Whether `ip` can be an address a peer saw this node at.
fn reportable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Whether `ip` is a private, shared (carrier-grade NAT) or unique-local
/// address, which the internet cannot reach.
fn internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// The reports peers made, one per reporting machine.
#[derive(Debug, Default)]
pub struct Observations {
    by_peer: HashMap<String, (SocketAddr, u64)>,
}

impl Observations {
    /// Keeps `peer`'s report that it saw this node at `addr`. A report of an
    /// address no peer can see (loopback, link-local, unspecified) is
    /// dropped.
    pub fn record(&mut self, peer: &str, addr: SocketAddr, now_ms: u64) {
        if !reportable(addr.ip()) {
            return;
        }
        self.by_peer
            .retain(|_, (_, at)| now_ms.saturating_sub(*at) < OBSERVATION_TTL_MS);
        if self.by_peer.len() >= MAX_OBSERVERS
            && !self.by_peer.contains_key(peer)
            && let Some(oldest) = self
                .by_peer
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(p, _)| p.clone())
        {
            self.by_peer.remove(&oldest);
        }
        self.by_peer.insert(peer.to_string(), (addr, now_ms));
    }

    fn current(&self, now_ms: u64) -> impl Iterator<Item = (&String, SocketAddr, u64)> {
        self.by_peer
            .iter()
            .filter(move |(_, (_, at))| now_ms.saturating_sub(*at) < OBSERVATION_TTL_MS)
            .map(|(p, (a, at))| (p, *a, *at))
    }

    /// The current reports, newest first.
    pub fn list(&self, now_ms: u64) -> Vec<Observation> {
        let mut out: Vec<Observation> = self
            .current(now_ms)
            .map(|(peer, addr, at)| Observation {
                peer: peer.clone(),
                addr,
                age_secs: now_ms.saturating_sub(at) / 1000,
            })
            .collect();
        out.sort_by(|a, b| {
            a.age_secs
                .cmp(&b.age_secs)
                .then_with(|| a.peer.cmp(&b.peer))
        });
        out
    }

    /// Addresses at least [`CONFIRMATIONS`] machines report, other than
    /// addresses on the node's own interfaces `local` (which the endpoint
    /// offers anyway).
    pub fn confirmed(&self, local: &[IpAddr], now_ms: u64) -> Vec<SocketAddr> {
        let mut count: HashMap<SocketAddr, usize> = HashMap::new();
        for (_, addr, _) in self.current(now_ms) {
            *count.entry(addr).or_default() += 1;
        }
        let mut out: Vec<SocketAddr> = count
            .into_iter()
            .filter(|(a, n)| *n >= CONFIRMATIONS && !local.contains(&a.ip()))
            .map(|(a, _)| a)
            .collect();
        out.sort();
        out
    }

    /// The NAT in front of the node, judged from the IPv4 reports when there
    /// are any (IPv6 is rarely translated), else the IPv6 ones. `local` are
    /// the addresses of the node's own interfaces: a peer on the same network
    /// sees one of them, which says nothing about the NAT.
    pub fn nat_kind(&self, local: &[IpAddr], now_ms: u64) -> NatKind {
        let all: Vec<SocketAddr> = self.current(now_ms).map(|(_, a, _)| a).collect();
        let v4: Vec<SocketAddr> = all.iter().copied().filter(SocketAddr::is_ipv4).collect();
        let family = if v4.is_empty() { all } else { v4 };
        if family.is_empty() {
            return NatKind::Unknown;
        }
        let family: Vec<SocketAddr> = family
            .into_iter()
            .filter(|a| !local.contains(&a.ip()))
            .collect();
        if family.is_empty() {
            return NatKind::None;
        }
        let mut distinct = family.clone();
        distinct.sort();
        distinct.dedup();
        if distinct.len() > 1 {
            NatKind::EndpointDependent
        } else if family.len() >= CONFIRMATIONS {
            NatKind::EndpointIndependent
        } else {
            NatKind::Unknown
        }
    }
}

/// The addresses of this machine's interfaces, and of the sockets the
/// endpoint bound to one address.
pub fn local_ips(endpoint: &Endpoint) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = netdev::get_interfaces()
        .into_iter()
        .flat_map(|i| {
            i.ipv4
                .into_iter()
                .map(|n| IpAddr::V4(n.addr()))
                .chain(i.ipv6.into_iter().map(|n| IpAddr::V6(n.addr())))
        })
        .collect();
    out.extend(
        endpoint
            .bound_sockets()
            .into_iter()
            .map(|a| a.ip())
            .filter(|ip| !ip.is_unspecified()),
    );
    out.sort();
    out.dedup();
    out
}

/// What `endpoint` knows about its reachability, given the reports peers
/// made and the external addresses taken from them.
pub fn connectivity(
    endpoint: &Endpoint,
    observations: &Observations,
    external: &[SocketAddr],
    forwarders: Vec<ForwarderState>,
    punched: usize,
    now_ms: u64,
) -> Connectivity {
    let observed = observations.list(now_ms);
    let bound = endpoint.bound_sockets();
    let advertised: Vec<SocketAddr> = endpoint.addr().ip_addrs().copied().collect();
    let local = local_ips(endpoint);
    let nat = observations.nat_kind(&local, now_ms);
    // Behind a NAT, an offered address on the NAT's public IP (the one peers
    // report) that peers did not report themselves is the port the router
    // mapped: no interface of this machine carries that IP.
    let port_mapped = matches!(
        nat,
        NatKind::EndpointIndependent | NatKind::EndpointDependent
    )
    .then(|| {
        advertised.iter().copied().find(|a| {
            observed.iter().any(|o| o.addr.ip() == a.ip())
                && !external.contains(a)
                && !observed.iter().any(|o| o.addr == *a)
        })
    })
    .flatten();
    let relays: Vec<RelayState> = endpoint
        .home_relay_status()
        .get()
        .iter()
        .map(|s| RelayState {
            url: s.url().to_string(),
            connected: s.is_connected(),
            error: s.last_error().map(ToString::to_string),
        })
        .collect();
    let relay_up = relays.iter().any(|r| r.connected);
    let reachability = match nat {
        NatKind::None => Reachability::Public,
        _ if port_mapped.is_some() => Reachability::PortMapped,
        NatKind::EndpointIndependent => Reachability::HolePunch,
        _ if !forwarders.is_empty() => Reachability::PeerRelay,
        _ if relay_up => Reachability::Relay,
        NatKind::EndpointDependent | NatKind::Unknown => Reachability::Unreachable,
    };
    let global = |v6: bool| {
        advertised
            .iter()
            .chain(observed.iter().map(|o| &o.addr))
            .any(|a| a.is_ipv6() == v6 && !internal(a.ip()))
    };
    Connectivity {
        reachability,
        nat,
        bound,
        external: external.to_vec(),
        port_mapped,
        ipv4: global(false),
        ipv6: global(true),
        advertised,
        observed,
        relays,
        forwarders,
        punched,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_peer_on_the_same_network_says_nothing_about_the_nat() {
        let mut o = Observations::default();
        o.record("did:lan", a("10.0.0.2:40000"), 1_000);
        o.record("did:a", a("198.51.100.7:40000"), 1_000);
        o.record("did:b", a("198.51.100.7:40000"), 1_000);
        let local = [ip("10.0.0.2")];
        assert_eq!(o.nat_kind(&local, 1_000), NatKind::EndpointIndependent);
        assert_eq!(o.confirmed(&local, 1_000), vec![a("198.51.100.7:40000")]);
    }

    #[test]
    fn one_report_is_not_enough_to_use_an_address() {
        let mut o = Observations::default();
        o.record("did:a", a("198.51.100.7:40000"), 1_000);
        assert!(o.confirmed(&[], 1_000).is_empty());
        assert_eq!(o.nat_kind(&[ip("10.0.0.2")], 1_000), NatKind::Unknown);
        o.record("did:b", a("198.51.100.7:40000"), 2_000);
        assert_eq!(o.confirmed(&[], 2_000), vec![a("198.51.100.7:40000")]);
        assert_eq!(
            o.nat_kind(&[ip("10.0.0.2")], 2_000),
            NatKind::EndpointIndependent
        );
    }

    #[test]
    fn the_same_machine_reporting_twice_counts_once() {
        let mut o = Observations::default();
        o.record("did:a", a("198.51.100.7:40000"), 1_000);
        o.record("did:a", a("198.51.100.7:40000"), 2_000);
        assert!(o.confirmed(&[], 2_000).is_empty());
    }

    #[test]
    fn different_ports_mean_an_endpoint_dependent_nat() {
        let mut o = Observations::default();
        o.record("did:a", a("198.51.100.7:40000"), 1_000);
        o.record("did:b", a("198.51.100.7:51234"), 1_000);
        assert_eq!(
            o.nat_kind(&[ip("10.0.0.2")], 1_000),
            NatKind::EndpointDependent
        );
        assert!(
            o.confirmed(&[], 1_000).is_empty(),
            "no address two machines agree on"
        );
    }

    #[test]
    fn peers_seeing_the_own_address_mean_no_nat() {
        let mut o = Observations::default();
        o.record("did:a", a("203.0.113.5:9001"), 1_000);
        o.record("did:b", a("203.0.113.5:9001"), 1_000);
        let local = [ip("203.0.113.5")];
        assert_eq!(o.nat_kind(&local, 1_000), NatKind::None);
        assert!(
            o.confirmed(&local, 1_000).is_empty(),
            "the own address is offered already"
        );
    }

    #[test]
    fn reports_expire_and_unseeable_addresses_are_dropped() {
        let mut o = Observations::default();
        o.record("did:a", a("127.0.0.1:9001"), 1_000);
        o.record("did:b", a("0.0.0.0:9001"), 1_000);
        o.record("did:c", a("[fe80::1]:9001"), 1_000);
        assert!(o.list(1_000).is_empty());
        o.record("did:a", a("198.51.100.7:40000"), 1_000);
        o.record("did:b", a("198.51.100.7:40000"), 1_000);
        assert_eq!(
            o.confirmed(&[], 1_000 + OBSERVATION_TTL_MS),
            Vec::<SocketAddr>::new()
        );
    }

    #[test]
    fn ipv4_reports_decide_the_nat_kind_over_ipv6_ones() {
        let mut o = Observations::default();
        o.record("did:a", a("198.51.100.7:40000"), 1_000);
        o.record("did:b", a("198.51.100.7:40000"), 1_000);
        o.record("did:c", a("[2001:db8::2]:9001"), 1_000);
        assert_eq!(
            o.nat_kind(&[ip("10.0.0.2"), ip("2001:db8::2")], 1_000),
            NatKind::EndpointIndependent
        );
    }

    #[test]
    fn the_report_set_is_bounded() {
        let mut o = Observations::default();
        for i in 0..(MAX_OBSERVERS + 10) {
            o.record(
                &format!("did:{i}"),
                a("198.51.100.7:40000"),
                1_000 + i as u64,
            );
        }
        assert_eq!(o.list(2_000).len(), MAX_OBSERVERS);
    }
}
