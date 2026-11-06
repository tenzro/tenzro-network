//! `tenzro-node doctor`: whether peers can reach this node, and what to do
//! when they cannot.
//!
//! The report joins what this machine shows on its own (its IPv4 and IPv6
//! routes, whether the router offers port mapping, the host firewall) with
//! what the running node learned from its peers (the NAT in front of it, the
//! addresses peers see it at, the relays it is connected to), read from the
//! node's loopback admin page. Every problem comes with the fix in plain
//! words.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use tenzro_iroh::{Connectivity, NatKind, Reachability};

use crate::host_firewall::{self, FirewallState};

/// Port mapping protocols the local router answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PortMapping {
    /// UPnP Internet Gateway Device.
    pub upnp: bool,
    /// Port Control Protocol (RFC 6887).
    pub pcp: bool,
    /// NAT Port Mapping Protocol (RFC 6886).
    pub nat_pmp: bool,
}

impl PortMapping {
    fn any(&self) -> bool {
        self.upnp || self.pcp || self.nat_pmp
    }

    fn names(&self) -> String {
        let names: Vec<&str> = [
            (self.upnp, "UPnP"),
            (self.pcp, "PCP"),
            (self.nat_pmp, "NAT-PMP"),
        ]
        .into_iter()
        .filter_map(|(on, n)| on.then_some(n))
        .collect();
        names.join(", ")
    }
}

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// The node's UDP port.
    pub port: u16,
    /// Whether the node runs as a private, relay-only node.
    pub relay_only: bool,
    /// Whether the node holds the validator role.
    pub validator: bool,
    /// The source address of this machine's IPv4 default route.
    pub ipv4_route: Option<IpAddr>,
    /// The source address of this machine's IPv6 default route.
    pub ipv6_route: Option<IpAddr>,
    /// What the router offers, when it answered the probe.
    pub port_mapping: Option<PortMapping>,
    /// The host firewall.
    pub firewall: FirewallState,
    /// The running node's view, when it answered.
    pub node: Option<Connectivity>,
    /// Why the running node could not be read.
    pub node_error: Option<String>,
    /// What to do, in order.
    pub fixes: Vec<String>,
}

/// The local source address a packet to `probe` would leave from. Connecting
/// a UDP socket only looks up the route; nothing is sent.
fn route_source(probe: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match probe {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect((probe, 9)).ok()?;
    let ip = sock.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
}

/// Asks the local router which port mapping protocols it answers.
async fn probe_port_mapping() -> Option<PortMapping> {
    let client = portmapper::Client::default();
    match tokio::time::timeout(Duration::from_secs(5), client.probe()).await {
        Ok(Ok(Ok(out))) => Some(PortMapping {
            upnp: out.upnp,
            pcp: out.pcp,
            nat_pmp: out.nat_pmp,
        }),
        _ => None,
    }
}

/// The admin-page ticket to read the node's report with: the current one
/// while it is fresh, else a new one.
fn ticket(data_dir: &Path) -> Result<String, String> {
    let path = data_dir.join(crate::access::PAGE_TICKET_FILE);
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age + Duration::from_secs(60) < crate::access::PAGE_TICKET_TTL);
    if fresh && let Ok(t) = std::fs::read_to_string(&path) {
        return Ok(t.trim().to_string());
    }
    crate::access::issue_page_ticket(data_dir)
}

/// The running node's connectivity report, read from its loopback admin page
/// at `rpc_addr`.
async fn node_connectivity(rpc_addr: &str, data_dir: &Path) -> Result<Connectivity, String> {
    let ticket = ticket(data_dir)?;
    let url = format!("http://{rpc_addr}/access/connectivity");
    let resp = crate::http_client::shared()
        .get(&url)
        .header(crate::access::PAGE_TICKET_HEADER, ticket)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            format!("no node answered at {rpc_addr} ({e}); start it for the NAT and relay results")
        })?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        return Err(format!("{status}: {body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("node report: {e}"))
}

/// The fixes for what `report` found, most important first.
pub fn fixes(report: &DoctorReport) -> Vec<String> {
    let mut out = Vec::new();
    let port = report.port;
    let inbound_hint = report.firewall.allows_node == Some(false);
    if report.ipv4_route.is_none() && report.ipv6_route.is_none() {
        out.push(
            "This machine has no route to the internet. Check its network connection.".to_string(),
        );
    } else if report.ipv4_route.is_none() {
        out.push(
            "This network has IPv6 only. Peers with IPv6 reach the node directly; IPv4-only peers reach it \
             through relays, which needs relays that answer over IPv6."
                .to_string(),
        );
    }
    let Some(node) = &report.node else {
        if inbound_hint {
            out.push(optional_inbound(report));
        }
        return out;
    };
    if !node.relays.iter().any(|r| r.connected) && !report.relay_only {
        out.push(
            "No relay is connected. The node reaches relays over HTTPS (TCP 443): check that outbound HTTPS is \
             allowed, or name a reachable relay with --boot-nodes did:tenzro:machine:<id>@https://<relay>."
                .to_string(),
        );
    }
    match (node.reachability, node.nat) {
        (Reachability::Unreachable, _) => out.push(
            "Peers cannot reach this node yet. If it persists, check the relay and firewall lines above.".to_string(),
        ),
        (Reachability::Relay, NatKind::EndpointDependent) => out.push(format!(
            "The NAT in front of this machine gives each peer a different port (often called symmetric NAT), so \
             most peers reach the node through a relay. For direct paths, turn on UPnP, NAT-PMP or PCP on the \
             router, or forward UDP {port} to this machine."
        )),
        (Reachability::Relay, NatKind::Unknown) if node.observed.is_empty() => out.push(format!(
            "No peer has reached this node over UDP yet. Peers reach it through relays, over HTTPS. If this \
             stays so, this network may block UDP: allow outbound UDP, or forward UDP {port} to this machine."
        )),
        _ => {}
    }
    if inbound_hint
        && !matches!(
            node.reachability,
            Reachability::Public | Reachability::PortMapped
        )
    {
        out.push(optional_inbound(report));
    }
    if report.validator
        && !matches!(
            node.reachability,
            Reachability::Public | Reachability::PortMapped
        )
    {
        out.push(format!(
            "This node is a validator. Validators exchange consensus messages with every other validator, so \
             give it a direct address: a host with a public IP, a port forward of UDP {port}, or a router with \
             UPnP, NAT-PMP or PCP turned on."
        ));
    }
    out
}

/// The optional step for a host firewall that refuses unsolicited inbound
/// traffic: the node works without it, peers just cannot open a path first.
fn optional_inbound(report: &DoctorReport) -> String {
    match &report.firewall.fix {
        Some(fix) => format!(
            "Optional: the host firewall lets peers in only on paths this node opened ({}). For peers to reach \
             it first, run {fix}.",
            report.firewall.detail
        ),
        None => format!(
            "Optional: the host firewall lets peers in only on paths this node opened ({}).",
            report.firewall.detail
        ),
    }
}

/// Builds the report for a node with `config`.
pub async fn report(config: &crate::config::NodeConfig, binary: &Path) -> DoctorReport {
    let port = config.iroh.bind_addr.port();
    let firewall = {
        let binary = binary.to_path_buf();
        tokio::task::spawn_blocking(move || host_firewall::state(&binary, port))
            .await
            .unwrap_or(FirewallState {
                system: "host firewall".to_string(),
                enabled: None,
                allows_node: None,
                detail: "could not be read".to_string(),
                fix: None,
            })
    };
    let (port_mapping, node) = tokio::join!(
        probe_port_mapping(),
        node_connectivity(&config.rpc_addr, &config.data_dir)
    );
    let (node, node_error) = match node {
        Ok(c) => (Some(c), None),
        Err(e) => (None, Some(e)),
    };
    let mut report = DoctorReport {
        port,
        relay_only: config.iroh.relay_only,
        validator: config.roles.is_validator(),
        ipv4_route: route_source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        ipv6_route: route_source(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        port_mapping,
        firewall,
        node,
        node_error,
        fixes: Vec::new(),
    };
    report.fixes = fixes(&report);
    report
}

fn reach_words(r: Reachability) -> &'static str {
    match r {
        Reachability::Public => "directly, at a public address",
        Reachability::PortMapped => "directly, through a port the router mapped",
        Reachability::HolePunch => "directly, after hole punching",
        Reachability::PeerRelay => {
            "through a peer relay over UDP (a staked, directly reachable node), and relays"
        }
        Reachability::Relay => {
            "through relays (direct only from peers with a public or mapped address)"
        }
        Reachability::Unreachable => "not yet",
    }
}

fn nat_words(n: NatKind) -> &'static str {
    match n {
        NatKind::Unknown => "not known yet (fewer than two peers have reached the node over UDP)",
        NatKind::None => "none: peers see this machine's own address",
        NatKind::EndpointIndependent => {
            "endpoint-independent: every peer sees the same address and port"
        }
        NatKind::EndpointDependent => "endpoint-dependent (symmetric): peers see different ports",
    }
}

/// The report in plain text.
pub fn render(r: &DoctorReport) -> String {
    let mut s = String::new();
    let mut line = |k: &str, v: String| s.push_str(&format!("  {k:<16} {v}\n"));
    let yes = |o: &Option<IpAddr>| o.map_or("no".to_string(), |ip| format!("yes ({ip})"));
    line("IPv4", yes(&r.ipv4_route));
    line("IPv6", yes(&r.ipv6_route));
    line(
        "port mapping",
        match &r.port_mapping {
            Some(m) if m.any() => format!("the router offers {}", m.names()),
            Some(_) => "the router offers none of UPnP, PCP, NAT-PMP".to_string(),
            None => "no router answered".to_string(),
        },
    );
    line(
        "firewall",
        format!("{}: {}", r.firewall.system, r.firewall.detail),
    );
    match &r.node {
        Some(n) => {
            line("reachable", reach_words(n.reachability).to_string());
            line("NAT", nat_words(n.nat).to_string());
            let seen: Vec<String> = n
                .observed
                .iter()
                .take(4)
                .map(|o| format!("{} (by {})", o.addr, short(&o.peer)))
                .collect();
            line(
                "peers see",
                if seen.is_empty() {
                    "nothing yet".to_string()
                } else {
                    seen.join(", ")
                },
            );
            if let Some(m) = n.port_mapped {
                line("mapped port", m.to_string());
            }
            let relays: Vec<String> = n
                .relays
                .iter()
                .map(|x| {
                    format!(
                        "{} ({})",
                        x.url,
                        if x.connected {
                            "connected"
                        } else {
                            "not connected"
                        }
                    )
                })
                .collect();
            line(
                "relay",
                if relays.is_empty() {
                    "none".to_string()
                } else {
                    relays.join(", ")
                },
            );
            let forwarders: Vec<String> = n
                .forwarders
                .iter()
                .map(|f| {
                    format!(
                        "{} ({} ms, {})",
                        short(&f.endpoint),
                        f.rtt_ms,
                        if f.direct { "direct" } else { "relayed" }
                    )
                })
                .collect();
            line(
                "peer relays",
                if forwarders.is_empty() {
                    "none".to_string()
                } else {
                    forwarders.join(", ")
                },
            );
            if n.punched > 0 {
                line(
                    "punched",
                    format!("direct paths to {} peers across this NAT", n.punched),
                );
            }
            line("UDP port", format!("{} on {}", r.port, join(&n.bound)));
        }
        None => line("node", r.node_error.clone().unwrap_or_default()),
    }
    if r.fixes.is_empty() {
        s.push_str("\nNothing to fix.\n");
    } else {
        s.push_str("\nTo fix:\n");
        for (i, f) in r.fixes.iter().enumerate() {
            s.push_str(&format!("  {}. {f}\n", i + 1));
        }
    }
    s
}

fn short(did: &str) -> String {
    let tail = did.rsplit(':').next().unwrap_or(did);
    tail.chars().take(12).collect()
}

fn join(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The node binary this process runs from.
pub fn current_binary() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("tenzro-node"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_iroh::reachability::{Observation, RelayState};

    fn base(node: Option<Connectivity>) -> DoctorReport {
        DoctorReport {
            port: 9001,
            relay_only: false,
            validator: false,
            ipv4_route: Some("192.168.1.5".parse().unwrap()),
            ipv6_route: None,
            port_mapping: Some(PortMapping::default()),
            firewall: FirewallState {
                system: "macOS application firewall".into(),
                enabled: Some(false),
                allows_node: Some(true),
                detail: "off".into(),
                fix: None,
            },
            node,
            node_error: None,
            fixes: Vec::new(),
        }
    }

    fn conn(
        reachability: Reachability,
        nat: NatKind,
        relay: bool,
        observed: usize,
    ) -> Connectivity {
        Connectivity {
            reachability,
            nat,
            bound: vec!["0.0.0.0:9001".parse().unwrap()],
            advertised: vec![],
            external: vec![],
            port_mapped: None,
            observed: (0..observed)
                .map(|i| Observation {
                    peer: format!("did:tenzro:machine:{i}"),
                    addr: "198.51.100.7:1000".parse().unwrap(),
                    age_secs: 1,
                })
                .collect(),
            relays: vec![RelayState {
                url: "https://relay.example.org/".into(),
                connected: relay,
                error: None,
            }],
            forwarders: vec![],
            punched: 0,
            ipv4: true,
            ipv6: false,
        }
    }

    #[test]
    fn a_symmetric_nat_points_at_the_router() {
        let r = base(Some(conn(
            Reachability::Relay,
            NatKind::EndpointDependent,
            true,
            2,
        )));
        let f = fixes(&r);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f.iter()
                .any(|x| x.contains("symmetric NAT") && x.contains("forward UDP 9001"))
        );
    }

    #[test]
    fn no_udp_and_no_relay_are_named() {
        let r = base(Some(conn(Reachability::Relay, NatKind::Unknown, true, 0)));
        assert!(fixes(&r).iter().any(|x| x.contains("block UDP")));
        let r = base(Some(conn(
            Reachability::Unreachable,
            NatKind::Unknown,
            false,
            0,
        )));
        assert!(fixes(&r).iter().any(|x| x.contains("TCP 443")));
    }

    #[test]
    fn a_validator_behind_nat_is_told_to_get_a_direct_address() {
        let mut r = base(Some(conn(
            Reachability::HolePunch,
            NatKind::EndpointIndependent,
            true,
            2,
        )));
        r.validator = true;
        assert!(fixes(&r).iter().any(|x| x.contains("validator")));
        r.node = Some(conn(Reachability::Public, NatKind::None, true, 2));
        assert!(!fixes(&r).iter().any(|x| x.contains("validator")));
    }

    #[test]
    fn an_inbound_rule_is_only_ever_an_optional_step() {
        let mut r = base(Some(conn(
            Reachability::HolePunch,
            NatKind::EndpointIndependent,
            true,
            2,
        )));
        r.firewall.allows_node = Some(false);
        r.firewall.fix = Some("sudo tenzro-node doctor --allow-inbound".into());
        let f = fixes(&r);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].starts_with("Optional:") && f[0].contains("--allow-inbound"),
            "{f:?}"
        );
        r.fixes = f;
        assert!(render(&r).contains("To fix:"));
        // A node peers already reach directly needs no rule at all.
        r.node = Some(conn(Reachability::Public, NatKind::None, true, 2));
        assert!(fixes(&r).is_empty());
    }

    #[test]
    fn route_lookup_sends_nothing_and_never_names_loopback() {
        if let Some(ip) = route_source(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))) {
            assert!(!ip.is_loopback());
        }
    }
}
