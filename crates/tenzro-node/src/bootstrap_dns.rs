//! Bootstrap discovery via DNS.
//!
//! Replaces the failure-prone "hardcoded BOOT_PEER_ID in the wrapper script"
//! model. When a validator boots, instead of relying on operator-shipped
//! peer IDs in `--boot-nodes`, it can resolve `--bootstrap-dns <name>` to
//! an SRV record list of currently-healthy bootstrap targets and a paired
//! TXT record list of their libp2p peer IDs.
//!
//! Wire format:
//!
//! - **SRV** `_tenzro-boot._tcp.<NAME>` → `priority weight port target`
//!   records, one per bootstrap host. The target is a DNS A/AAAA name
//!   (e.g. `v0.boot.tenzro.network`) that resolves to one or more IPs.
//! - **TXT** `_tenzro-id._tcp.<TARGET>` → a single quoted string of the
//!   form `peer_id=<base58>` for that host. One TXT record per SRV
//!   target.
//!
//! The function returns a list of fully-formed multiaddrs of the shape
//! `/ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>` (and the QUIC dual at
//! `/udp/<PORT>/quic-v1/p2p/<PEER_ID>`), ready to drop into
//! `config.network.boot_nodes`.
//!
//! Why DNS rather than a custom on-chain registry:
//!
//! - DNS is universally cacheable + has TTLs out of the box.
//! - SRV + TXT lets operators rotate hosts without touching every
//!   validator's wrapper.
//! - The pkarr relay on `pkarr.tenzro.network` is a separate primitive
//!   for iroh `EndpointId` resolution — it does not speak libp2p PeerId.
//!   Conflating the two would mean dragging iroh's address-lookup
//!   machinery into the libp2p boot path. Keeping bootstrap-DNS as a
//!   plain Hickory resolver call keeps the two surfaces independent.
//!
//! Single point of failure: the DNS zone itself. That's no worse than
//! the status quo (the zone is owned by the same operator as the
//! validator fleet). Multiple SRV targets + DNS caching make it
//! resilient to single-host outages.

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::config::ResolverOpts;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::Resolver;
use libp2p::Multiaddr;
use tracing::{info, warn};

/// Errors produced while resolving the bootstrap DNS records.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapDnsError {
    #[error("DNS resolver init failed: {0}")]
    ResolverInit(String),
    #[error("SRV lookup for {name} failed: {source}")]
    SrvLookup {
        name: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Resolve bootstrap multiaddrs from a DNS zone.
///
/// The lookup procedure:
///
/// 1. `_tenzro-boot._tcp.<base>` → SRV records `(priority, weight, port, target)`.
/// 2. For each SRV target:
///    - `_tenzro-id._tcp.<target>` → TXT record `peer_id=<base58>`.
///    - `target` itself → A and/or AAAA records.
/// 3. For every `(IP, PORT, PEER_ID)` triple, emit both a TCP and a QUIC
///    multiaddr. The libp2p swarm will pick whichever connects first.
///
/// Records that fail to parse are warned about and skipped — a single
/// malformed entry must not break the rest of the bootstrap set.
pub async fn resolve_bootstrap_dns(
    base: &str,
) -> Result<Vec<Multiaddr>, BootstrapDnsError> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 2;

    // `builder_tokio()` selects the system resolver config (/etc/resolv.conf
    // on Unix; the relevant Win32 APIs elsewhere). This is the right default
    // for a Tenzro validator — operators set their DNS upstream via the
    // host system; we don't second-guess it.
    let resolver = Resolver::builder_tokio()
        .map_err(|e| BootstrapDnsError::ResolverInit(format!("{}", e)))?
        .with_options(opts)
        .build()
        .map_err(|e| BootstrapDnsError::ResolverInit(format!("{}", e)))?;

    let srv_name = format!("_tenzro-boot._tcp.{}", base);
    info!(
        target: "bootstrap_dns",
        "Resolving bootstrap SRV records at {}",
        srv_name
    );
    let srv = resolver
        .srv_lookup(srv_name.as_str())
        .await
        .map_err(|e| BootstrapDnsError::SrvLookup {
            name: srv_name.clone(),
            source: Box::new(e),
        })?;

    let mut out: Vec<Multiaddr> = Vec::new();

    for record in srv.answers() {
        let srv_rdata = match record.data {
            RData::SRV(ref s) => s,
            _ => continue,
        };
        let target = srv_rdata.target.to_utf8();
        let target_trimmed = target.trim_end_matches('.');
        let port = srv_rdata.port;

        // Per-target TXT lookup for the peer ID.
        let txt_name = format!("_tenzro-id._tcp.{}", target_trimmed);
        let txt = match resolver.txt_lookup(txt_name.as_str()).await {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    target: "bootstrap_dns",
                    %target_trimmed,
                    error = %e,
                    "Skipping SRV target: TXT lookup failed"
                );
                continue;
            }
        };

        // Parse `peer_id=<base58>` from the first matching TXT record.
        let peer_id_str = txt
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(t) => Some(t),
                _ => None,
            })
            .flat_map(|t| t.txt_data.iter())
            .map(|d| String::from_utf8_lossy(d).into_owned())
            .find_map(|s| s.strip_prefix("peer_id=").map(|p| p.to_owned()));
        let peer_id_str = match peer_id_str {
            Some(p) => p,
            None => {
                warn!(
                    target: "bootstrap_dns",
                    %target_trimmed,
                    "Skipping SRV target: TXT record missing peer_id=<...>"
                );
                continue;
            }
        };

        // Per-target A/AAAA lookup for IPs.
        let ips_lookup = match resolver.lookup_ip(target_trimmed).await {
            Ok(ip) => ip,
            Err(e) => {
                warn!(
                    target: "bootstrap_dns",
                    %target_trimmed,
                    error = %e,
                    "Skipping SRV target: A/AAAA lookup failed"
                );
                continue;
            }
        };

        for ip in ips_lookup.iter() {
            let ip_proto = match ip {
                IpAddr::V4(v4) => format!("/ip4/{}", v4),
                IpAddr::V6(v6) => format!("/ip6/{}", v6),
            };
            // Emit both TCP and QUIC dial paths — libp2p picks whichever
            // succeeds first under the local NAT regime.
            let tcp = format!("{}/tcp/{}/p2p/{}", ip_proto, port, peer_id_str);
            let quic = format!("{}/udp/{}/quic-v1/p2p/{}", ip_proto, port, peer_id_str);
            for s in [tcp, quic] {
                match s.parse::<Multiaddr>() {
                    Ok(addr) => {
                        info!(
                            target: "bootstrap_dns",
                            %addr,
                            "Resolved bootstrap multiaddr"
                        );
                        out.push(addr);
                    }
                    Err(e) => {
                        warn!(
                            target: "bootstrap_dns",
                            address = %s,
                            error = %e,
                            "Skipping malformed multiaddr"
                        );
                    }
                }
            }
        }
    }

    info!(
        target: "bootstrap_dns",
        base = %base,
        count = out.len(),
        "Bootstrap DNS resolution complete"
    );
    Ok(out)
}
