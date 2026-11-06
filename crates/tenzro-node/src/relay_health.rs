//! Relays as a staked role, checked by every node.
//!
//! Relaying is part of the edge role: an edge operator bonds the role and
//! publishes the URL it serves the relay at (`tenzro stake endpoint --role
//! edge --url ...`). Validators probe that URL on the SLA schedule every
//! bonded role is held to (see `sla_attest`), and an epoch frozen unavailable
//! costs the edge bond the governed SLA penalty. Every node also checks each
//! staked relay every few minutes the same way it admits one, for choosing
//! among them. `tenzro_listRelays` serves both: the last frozen SLA verdict
//! and this node's latest check, so nothing depends on a relay any single
//! party runs.
//!
//! `tenzro_getConnectivity` answers how this node is reached (through which
//! relays, behind which kind of NAT), without naming its network addresses;
//! the full report, addresses included, is on the node's loopback admin page
//! for `tenzro-node doctor`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// How often the staked relays are checked.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(300);

/// Most staked relays one round checks, most bonded first.
pub const MAX_CHECKED: usize = 32;

/// Checks the staked relays every [`CHECK_INTERVAL`] for as long as the node
/// runs.
pub fn start(node: &Arc<TenzroNode>) {
    let node = Arc::clone(node);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        loop {
            if let (Some(transport), Some(chain)) =
                (node.identity_transport.clone(), node.chain_state())
            {
                let mut urls = crate::identity_bootstrap::staked_relays(&chain);
                urls.truncate(MAX_CHECKED);
                transport.check_relays(&urls).await;
            }
            tokio::time::sleep(CHECK_INTERVAL).await;
        }
    });
}

fn unavailable(what: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: format!("{what} is not up yet"),
        data: None,
    }
}

/// `tenzro_listRelays`: every staked edge operator's relay, most bonded
/// first, with the SLA verdict validators froze for the last closed epoch,
/// this node's latest check of it, and whether this node uses it.
pub(crate) async fn handle_list_relays(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let chain = node
        .chain_state()
        .ok_or_else(|| unavailable("chain state"))?;
    let transport = node.identity_transport.clone();
    let checks = transport
        .as_ref()
        .map(|t| t.relay_checks())
        .unwrap_or_default();
    let relays: Vec<Value> = tenzro_vm::native::role_endpoints(&chain, tenzro_types::NetworkRole::Edge)
        .into_iter()
        .map(|e| {
            let check = checks.iter().find(|c| c.url == e.url || url_eq(&c.url, &e.url));
            let sla = hex::decode(&e.account).ok().and_then(|owner| {
                let subject = tenzro_vm::native::role_stake_subject(&owner, tenzro_types::NetworkRole::Edge);
                let epoch = last_closed_epoch();
                tenzro_vm::native::read_sla_verdict(&chain, &subject, epoch)
                    .map(|v| json!({ "epoch": epoch, "available": v.available, "attesters": v.attesters }))
            });
            json!({
                "account": format!("0x{}", e.account),
                "url": e.url,
                "bonded": e.bonded.to_string(),
                "used": transport.as_ref().is_some_and(|t| t.uses_relay(&e.url) || check.is_some_and(|c| t.uses_relay(&c.url))),
                "check": check,
                "sla": sla,
            })
        })
        .collect();
    Ok(json!({ "relays": relays }))
}

/// The SLA epoch that closed last.
fn last_closed_epoch() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    ((now / tenzro_vm::native::MARKET_EPOCH_MS) as u64).saturating_sub(1)
}

fn url_eq(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// `tenzro_getConnectivity`: how this node is reached, without its
/// addresses: reachability, NAT kind, how many peers reported an address,
/// whether the router mapped a port, IPv4/IPv6, its relays and the peer
/// relays it offers paths through.
pub(crate) async fn handle_get_connectivity(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let transport = node
        .identity_transport
        .clone()
        .ok_or_else(|| unavailable("the identity transport"))?;
    let resolver = node
        .iroh_resolver()
        .cloned()
        .ok_or_else(|| unavailable("the iroh endpoint"))?;
    let c = transport.connectivity(resolver.endpoint());
    Ok(json!({
        "reachability": c.reachability,
        "nat": c.nat,
        "observers": c.observed.len(),
        "port_mapped": c.port_mapped.is_some(),
        "external_addresses": c.external.len(),
        "ipv4": c.ipv4,
        "ipv6": c.ipv6,
        "relays": c.relays.iter().map(|r| json!({ "url": r.url, "connected": r.connected })).collect::<Vec<_>>(),
        "punched_paths": c.punched,
        "peer_relays": c.forwarders.iter().map(|f| json!({ "endpoint": f.endpoint, "rtt_ms": f.rtt_ms, "direct": f.direct })).collect::<Vec<_>>(),
    }))
}
