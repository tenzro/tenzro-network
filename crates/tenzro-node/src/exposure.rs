//! What a node exposes: the addresses its HTTP listeners bind and the URLs it
//! publishes about itself.
//!
//! A node runs confined. Every HTTP listener (RPC, web, MCP, A2A and the chain
//! MCP servers) binds loopback, for local clients only; peers are reached over
//! the network's own identity-addressed transport. [`validate`] refuses, at
//! startup, a listener bound to anything but loopback. It never derives a public URL from a bind
//! address: `0.0.0.0:8545` names every interface of this machine, and a
//! loopback, private, CGNAT or link-local address names a network the reader
//! is not on. Publishing either leaks the operator's network layout and
//! points peers at an address that is not theirs to dial.
//!
//! Exposure is the operator's decision, made outside the node: a reverse
//! proxy or edge of their own in front of the loopback listener. When they
//! make it, they tell the node the resulting public URL through
//! `external_rpc_addr` / `external_mcp_addr` / `external_a2a_addr`, and those are the ONLY URLs the
//! node ever publishes. [`validate`] refuses, at startup, a configured URL
//! that is not `https` or whose host is not publicly routable.

use crate::config::NodeConfig;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Refuse a listener bound off loopback, and a configured published URL that
/// would publish a non-public address. `None` (the default) publishes nothing.
pub fn validate(config: &NodeConfig) -> Result<(), String> {
    for (field, addr) in [
        ("rpc_addr", &config.rpc_addr),
        ("web_addr", &config.web_addr),
        ("mcp_addr", &config.mcp_addr),
        ("a2a_addr", &config.a2a_addr),
    ] {
        if !binds_loopback(addr) {
            return Err(format!(
                "{field} = {addr:?}: a node listens on loopback only; expose it through \
                 your own reverse proxy outside the node"
            ));
        }
    }
    if let Some(relay) = &config.iroh.relay {
        if !relay.bind_addr.ip().is_loopback() {
            return Err(format!(
                "iroh.relay.bind_addr = {}: the relay listener binds loopback only; expose it through \
                 your own TLS-terminating proxy outside the node",
                relay.bind_addr
            ));
        }
        if !is_own_loopback_relay(&relay.public_url, relay.bind_addr) {
            check_public_https(relay.public_url.as_str()).map_err(|why| {
                format!(
                    "iroh.relay.public_url = {:?}: {why}",
                    relay.public_url.as_str()
                )
            })?;
        }
    }
    for (field, value) in [
        ("external_rpc_addr", config.external_rpc_addr.as_deref()),
        ("external_mcp_addr", config.external_mcp_addr.as_deref()),
        ("external_a2a_addr", config.external_a2a_addr.as_deref()),
    ] {
        if let Some(url) = value {
            check_public_https(url).map_err(|why| format!("{field} = {url:?}: {why}"))?;
        }
    }
    Ok(())
}

/// The MCP endpoint URL (`.../mcp`) peers may call, if the operator published
/// one.
pub fn mcp_endpoint(config: &NodeConfig) -> Option<String> {
    with_suffix(config.external_mcp_addr.as_deref()?, "/mcp")
}

/// The origin this node's MCP server answers as: the operator's published
/// `external_mcp_addr`, or the loopback listener when nothing is published.
/// It is the OAuth issuer and the base of the `/mcp` resource, so a node
/// behind any operator's domain issues and accepts tokens for itself.
pub fn mcp_origin(config: &NodeConfig) -> String {
    config
        .external_mcp_addr
        .as_deref()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("http://{}", config.mcp_addr))
}

/// The host of the operator's published MCP URL, if any: the one public
/// `Host` the MCP listener answers besides loopback.
pub fn mcp_public_host(config: &NodeConfig) -> Option<String> {
    url_host(config.external_mcp_addr.as_deref()?)
}

/// The host of the operator's published RPC URL, if any: the authority that
/// requests signed for this node name.
pub fn rpc_public_host(config: &NodeConfig) -> Option<String> {
    url_host(config.external_rpc_addr.as_deref()?)
}

fn url_host(url: &str) -> Option<String> {
    let rest = url.trim().split("://").nth(1)?;
    let host = host_of(rest.split(['/', '?', '#']).next()?);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The A2A endpoint URL (`.../a2a`) peers may call, if the operator
/// published one.
pub fn a2a_url(config: &NodeConfig) -> Option<String> {
    with_suffix(config.external_a2a_addr.as_deref()?, "/a2a")
}

/// The operator-published RPC base URL, verbatim.
pub fn rpc_url(config: &NodeConfig) -> Option<String> {
    config
        .external_rpc_addr
        .as_deref()
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
}

/// Whether a listen address names this machine's loopback interface only.
fn binds_loopback(addr: &str) -> bool {
    if let Ok(sock) = addr.parse::<std::net::SocketAddr>() {
        return sock.ip().is_loopback();
    }
    matches!(addr.rsplit_once(':'), Some(("localhost", port)) if port.parse::<u16>().is_ok())
}

fn with_suffix(url: &str, suffix: &str) -> Option<String> {
    let base = url.trim().trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    if base.ends_with(suffix) {
        Some(base.to_string())
    } else {
        Some(format!("{base}{suffix}"))
    }
}

/// Whether `url` is the relay listener itself on loopback
/// (`http://127.0.0.1:<bind port>/` or `http://[::1]:<bind port>/`): the
/// relay of a cluster whose nodes all run on this machine, which nothing off
/// the machine can reach, so it exposes nothing.
fn is_own_loopback_relay(url: &url::Url, bind: std::net::SocketAddr) -> bool {
    let host_is_loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    url.scheme() == "http"
        && host_is_loopback
        && url.port() == Some(bind.port())
        && url.path() == "/"
        && url.query().is_none()
}

fn check_public_https(url: &str) -> Result<(), &'static str> {
    let url = url.trim();
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("must be an https:// URL served by the operator's own edge");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host_of(authority);
    if host.is_empty() {
        return Err("has no host");
    }
    if is_public_host(host) {
        Ok(())
    } else {
        Err("names a loopback, private, CGNAT, link-local or otherwise non-public host")
    }
}

/// The host part of an `authority` (`host`, `host:port`, `[v6]:port` or a bare
/// IPv6 literal).
fn host_of(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(h, _)| h);
    }
    if authority.matches(':').count() > 1 {
        // A bare IPv6 literal carries no port.
        return authority;
    }
    match authority.rsplit_once(':') {
        Some((h, port)) if !h.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    }
}

/// Whether `host` may appear in a URL published to the network.
///
/// A DNS name is the operator's own claim of reachability and is not resolved
/// here, except the names that by definition resolve to this machine or a
/// local network.
fn is_public_host(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => is_public_v4(ip),
        Ok(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(ip),
        },
        Err(_) => {
            let h = host.trim_end_matches('.').to_ascii_lowercase();
            !(h == "localhost"
                || h.ends_with(".localhost")
                || h.ends_with(".local")
                || h.ends_with(".internal")
                || h.ends_with(".lan")
                || h.ends_with(".home.arpa"))
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let cgnat = a == 100 && (64..=127).contains(&b);
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || cgnat
        || a == 0)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    let unique_local = (first & 0xfe00) == 0xfc00;
    let link_local = (first & 0xffc0) == 0xfe80;
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || unique_local || link_local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(rpc: Option<&str>, mcp: Option<&str>) -> NodeConfig {
        let mut c = NodeConfig::default_validator();
        c.external_rpc_addr = rpc.map(str::to_string);
        c.external_mcp_addr = mcp.map(str::to_string);
        c
    }

    #[test]
    fn nothing_configured_publishes_nothing() {
        let c = config_with(None, None);
        assert!(validate(&c).is_ok());
        assert_eq!(mcp_endpoint(&c), None);
        assert_eq!(rpc_url(&c), None);
    }

    #[test]
    fn a_public_https_url_is_published_with_its_suffix() {
        let c = config_with(
            Some("https://rpc.example.org/"),
            Some("https://mcp.example.org"),
        );
        assert!(validate(&c).is_ok());
        assert_eq!(
            mcp_endpoint(&c).as_deref(),
            Some("https://mcp.example.org/mcp")
        );
        assert_eq!(rpc_url(&c).as_deref(), Some("https://rpc.example.org"));
        let c = config_with(Some("https://203.0.113.7/v1"), None);
        assert!(validate(&c).is_ok());
        assert_eq!(rpc_url(&c).as_deref(), Some("https://203.0.113.7/v1"));
    }

    #[test]
    fn the_relay_listener_binds_loopback_behind_a_public_https_url() {
        let role = |bind: &str, url: &str| tenzro_iroh::RelayRoleConfig {
            bind_addr: bind.parse().unwrap(),
            public_url: url.parse().unwrap(),
        };
        let mut c = config_with(None, None);
        c.iroh.relay = Some(role("127.0.0.1:3340", "https://relay.example.org/"));
        assert!(validate(&c).is_ok());
        c.iroh.relay = Some(role("0.0.0.0:3340", "https://relay.example.org/"));
        assert!(
            validate(&c).is_err(),
            "the relay listener never binds off loopback"
        );
        c.iroh.relay = Some(role("127.0.0.1:3340", "http://relay.example.org/"));
        assert!(
            validate(&c).is_err(),
            "the published relay URL is https from the operator's proxy"
        );
        c.iroh.relay = Some(role("127.0.0.1:3340", "https://10.0.0.5/"));
        assert!(
            validate(&c).is_err(),
            "a private address is never published"
        );
        // A cluster on one machine reaches the relay listener itself on
        // loopback, which nothing off the machine can.
        c.iroh.relay = Some(role("127.0.0.1:3340", "http://127.0.0.1:3340/"));
        assert!(validate(&c).is_ok());
        c.iroh.relay = Some(role("[::1]:3340", "http://[::1]:3340/"));
        assert!(validate(&c).is_ok());
        c.iroh.relay = Some(role("127.0.0.1:3340", "http://127.0.0.1:3341/"));
        assert!(
            validate(&c).is_err(),
            "a loopback URL other than the listener's own"
        );
        c.iroh.relay = Some(role("127.0.0.1:3340", "http://10.0.0.5:3340/"));
        assert!(validate(&c).is_err(), "plain http off loopback");
        c.iroh.relay = Some(role("127.0.0.1:3340", "http://localhost:3340/"));
        assert!(validate(&c).is_err(), "a name, not the loopback address");
    }

    #[test]
    fn an_a2a_url_is_published_only_when_the_operator_gives_a_public_one() {
        let mut c = config_with(None, None);
        assert_eq!(a2a_url(&c), None);
        c.external_a2a_addr = Some("https://agents.example.org".to_string());
        assert!(validate(&c).is_ok());
        assert_eq!(
            a2a_url(&c).as_deref(),
            Some("https://agents.example.org/a2a")
        );
        c.external_a2a_addr = Some("http://127.0.0.1:3002".to_string());
        assert!(validate(&c).is_err(), "a listen address is never published");
    }

    #[test]
    fn non_public_addresses_are_refused_at_startup() {
        for url in [
            "https://127.0.0.1:8545",
            "https://localhost",
            "https://node.local",
            "https://0.0.0.0:8545",
            "https://10.1.2.3",
            "https://172.20.0.5:8545/v1",
            "https://192.168.1.10",
            "https://100.64.0.92:8545/v1",
            "https://100.64.0.1",
            "https://169.254.169.254",
            "https://[::1]:8545",
            "https://[fd00::1]",
            "https://[fe80::1]",
            "https://[::ffff:10.0.0.1]",
        ] {
            let c = config_with(Some(url), None);
            assert!(validate(&c).is_err(), "{url} must be refused");
            let c = config_with(None, Some(url));
            assert!(validate(&c).is_err(), "{url} must be refused as an MCP URL");
        }
    }

    #[test]
    fn plain_http_and_bare_addresses_are_refused() {
        for url in [
            "http://rpc.example.org",
            "rpc.example.org:8545",
            "203.0.113.7:8545",
            "",
        ] {
            let c = config_with(Some(url), None);
            assert!(validate(&c).is_err(), "{url:?} must be refused");
        }
    }

    #[test]
    fn a_listener_off_loopback_is_refused_at_startup() {
        for addr in [
            "0.0.0.0:8545",
            "[::]:8545",
            "192.168.1.10:8545",
            "203.0.113.7:8545",
            ":8545",
            "rpc.example.org:8545",
        ] {
            let mut c = NodeConfig::default_validator();
            c.rpc_addr = addr.to_string();
            assert!(validate(&c).is_err(), "rpc_addr {addr} must be refused");
        }
        for addr in ["127.0.0.1:8545", "[::1]:8545", "localhost:8545"] {
            let mut c = NodeConfig::default_validator();
            c.rpc_addr = addr.to_string();
            assert!(validate(&c).is_ok(), "rpc_addr {addr} must be accepted");
        }
    }

    #[test]
    fn the_default_config_publishes_no_bind_address() {
        for c in [
            NodeConfig::default_validator(),
            NodeConfig::default_provider(),
            NodeConfig::default_tee_provider(),
            NodeConfig::default_user(),
        ] {
            assert_eq!(mcp_endpoint(&c), None);
            assert_eq!(rpc_url(&c), None);
        }
    }
}
