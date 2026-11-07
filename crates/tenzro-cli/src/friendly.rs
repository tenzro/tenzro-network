//! Errors a person can act on.
//!
//! A connection that fails says what happened, why it most likely happened,
//! and what to do next, and says it once, here, for every command. The
//! classification is a pure function of what the transport reported, so each
//! class is tested without a network.

use std::error::Error as _;
use std::fmt;

/// The public network's RPC host. While it does not resolve, every default
/// command would otherwise fail with a transport message.
pub const PUBLIC_RPC_HOST: &str = "rpc.tenzro.com";

/// What kind of failure the transport reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The name does not resolve.
    Dns,
    /// The machine answered and refused: nothing is listening on that port.
    Refused,
    /// No answer in time.
    Timeout,
    /// The connection started and the certificate or protocol was refused.
    Tls,
    /// The server answered with an HTTP error status.
    Status(u16),
    /// Anything else that stopped the request before an answer.
    Other,
}

/// Classify a failure from what the transport reported: whether it was a
/// timeout or a connect error, an HTTP status when there was one, and the
/// error chain as text.
pub fn classify(is_timeout: bool, is_connect: bool, status: Option<u16>, chain: &str) -> Class {
    if let Some(s) = status {
        return Class::Status(s);
    }
    let c = chain.to_ascii_lowercase();
    if c.contains("dns error")
        || c.contains("failed to lookup address")
        || c.contains("name or service not known")
        || c.contains("nodename nor servname")
        || c.contains("no such host")
        || c.contains("temporary failure in name resolution")
        || c.contains("no address associated")
    {
        return Class::Dns;
    }
    if c.contains("certificate") || c.contains("tls") || c.contains("handshake") {
        return Class::Tls;
    }
    if is_timeout || c.contains("timed out") || c.contains("deadline has elapsed") {
        return Class::Timeout;
    }
    if c.contains("connection refused") || c.contains("os error 111") || c.contains("os error 61") {
        return Class::Refused;
    }
    if is_connect {
        return Class::Other;
    }
    Class::Other
}

/// The host part of an endpoint URL.
pub fn host_of(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(stripped) = authority.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or(stripped);
    }
    authority.split(':').next().unwrap_or(authority)
}

/// Whether the endpoint is the public network's default.
pub fn is_public_default(url: &str) -> bool {
    host_of(url).eq_ignore_ascii_case(PUBLIC_RPC_HOST)
}

/// Whether the endpoint is this machine.
pub fn is_local(url: &str) -> bool {
    matches!(host_of(url), "127.0.0.1" | "localhost" | "::1")
}

/// A failure told as what happened, why, and what to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explained {
    pub what: String,
    pub why: String,
    pub fix: Vec<String>,
}

/// Explain a failure of class `class` against `url`. Pure.
pub fn explain(class: Class, url: &str) -> Explained {
    let host = host_of(url);
    let public = is_public_default(url);
    let local = is_local(url);
    let what = match class {
        Class::Status(s) => format!("{url} answered, but with an error (HTTP {s})."),
        _ => format!("Could not reach {url}."),
    };
    let why = match class {
        Class::Dns if public => format!(
            "The name {host} does not resolve yet: the public Tenzro network is not reachable at this address yet."
        ),
        Class::Dns => format!(
            "The name {host} does not resolve. Either it is misspelled or this machine has no working DNS or internet."
        ),
        Class::Refused if local => {
            "Nothing is listening on that port: no Tenzro node is running on this machine.".to_string()
        }
        Class::Refused => format!("{host} is there but refused the connection; the node is not running or the port is closed."),
        Class::Timeout => format!("{host} did not answer in time; the network is slow or down, or a firewall drops the traffic."),
        Class::Tls => format!("The connection to {host} started but its certificate or encryption was refused."),
        Class::Status(s) => format!("The server returned HTTP {s}; it is up but not serving this request."),
        Class::Other => "The request failed before any answer came back.".to_string(),
    };
    let mut fix = Vec::new();
    match class {
        Class::Dns | Class::Timeout | Class::Other if public => {
            fix.push("Tenzro can run on this machine without the public network: tenzro dev".to_string());
            fix.push("Or check this machine's internet connection and try again later.".to_string());
        }
        Class::Dns | Class::Timeout | Class::Other => {
            fix.push("Check the address, and this machine's internet connection.".to_string());
            fix.push("Run: tenzro doctor".to_string());
        }
        Class::Refused if local => {
            fix.push("Start a local chain with: tenzro dev".to_string());
            fix.push("Or start a node with: tenzro node start".to_string());
            fix.push("Or point at a node elsewhere: tenzro --rpc <url> ...".to_string());
        }
        Class::Refused => {
            fix.push("Start the node on that machine, or check its RPC port and firewall.".to_string());
        }
        Class::Tls => {
            fix.push("Check that the address starts with https:// only when the node serves TLS, and that this machine's clock is right.".to_string());
        }
        Class::Status(_) => {
            fix.push("Try again in a minute; if it persists, run: tenzro doctor".to_string());
        }
    }
    Explained { what, why, fix }
}

/// A command could not reach its endpoint. Printed by `main` without a
/// backtrace or an "Error:" prefix.
#[derive(Debug)]
pub struct Unreachable {
    pub url: String,
    pub class: Class,
    pub detail: String,
    pub explained: Explained,
}

impl fmt::Display for Unreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n  Why: {}", self.explained.what, self.explained.why)?;
        for (i, line) in self.explained.fix.iter().enumerate() {
            let lead = if i == 0 { "  Fix: " } else { "       " };
            write!(f, "\n{lead}{line}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Unreachable {}

/// Turn a transport error into a friendly error when it is a connection
/// failure; any other error (a decode failure, say) is returned unchanged.
pub fn from_reqwest(url: &str, e: reqwest::Error) -> anyhow::Error {
    let mut chain = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        chain.push_str(": ");
        chain.push_str(&s.to_string());
        src = s.source();
    }
    let status = e.status().map(|s| s.as_u16());
    let class = classify(e.is_timeout(), e.is_connect(), status, &chain);
    if class == Class::Other && !e.is_connect() && !e.is_timeout() {
        return anyhow::Error::new(e);
    }
    anyhow::Error::new(Unreachable {
        url: url.to_string(),
        class,
        detail: chain,
        explained: explain(class, url),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_failure_is_recognised_in_each_platform_wording() {
        for chain in [
            "error sending request: dns error: failed to lookup address information: Name or service not known",
            "client error (Connect): dns error: no such host",
            "nodename nor servname provided, or not known",
        ] {
            assert_eq!(classify(false, true, None, chain), Class::Dns, "{chain}");
        }
    }

    #[test]
    fn refused_timeout_tls_and_status_are_told_apart() {
        assert_eq!(
            classify(false, true, None, "tcp connect error: Connection refused (os error 111)"),
            Class::Refused
        );
        assert_eq!(classify(true, false, None, "operation timed out"), Class::Timeout);
        assert_eq!(
            classify(false, true, None, "invalid peer certificate: UnknownIssuer"),
            Class::Tls
        );
        assert_eq!(classify(false, false, Some(502), ""), Class::Status(502));
    }

    #[test]
    fn host_of_handles_ports_paths_and_brackets() {
        assert_eq!(host_of("https://rpc.tenzro.com"), "rpc.tenzro.com");
        assert_eq!(host_of("http://127.0.0.1:8545/x"), "127.0.0.1");
        assert_eq!(host_of("http://[::1]:8545"), "::1");
        assert_eq!(host_of("localhost:8545"), "localhost");
    }

    #[test]
    fn the_public_default_offers_the_local_chain() {
        let e = explain(Class::Dns, "https://rpc.tenzro.com");
        assert!(e.why.contains("not reachable at this address yet"));
        assert!(e.fix[0].contains("tenzro dev"));
    }

    #[test]
    fn a_local_refusal_says_no_node_is_running() {
        let e = explain(Class::Refused, "http://127.0.0.1:8545");
        assert!(e.why.contains("no Tenzro node is running"));
        assert!(e.fix.iter().any(|l| l.contains("tenzro dev")));
    }

    #[test]
    fn every_class_has_what_why_and_a_fix() {
        for class in [
            Class::Dns,
            Class::Refused,
            Class::Timeout,
            Class::Tls,
            Class::Status(500),
            Class::Other,
        ] {
            for url in ["https://rpc.tenzro.com", "http://127.0.0.1:8545", "https://node.example"] {
                let e = explain(class, url);
                assert!(!e.what.is_empty() && !e.why.is_empty() && !e.fix.is_empty());
            }
        }
    }
}
