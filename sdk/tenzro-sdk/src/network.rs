//! Reaching the network rather than one node.
//!
//! RPC operators bond the `rpc` role and publish the public URL they serve
//! it at in consensus state, so every node answers the same list
//! (`tenzro_listRoleEndpoints`). [`discover_endpoints`] asks a few seeds for
//! that list, keeps the operators that answer for the expected chain and
//! agree on its history, and [`connect_to_network`] builds a client that
//! moves between them when one cannot be reached. A seed is only a way in,
//! never an authority: any node of the network will do.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::client::TenzroClient;
use crate::config::SdkConfig;
use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;

/// One staked operator of a role and the URL it published on chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEndpoint {
    /// The staking account, `0x` hex.
    pub account: String,
    /// The published URL.
    pub url: String,
    /// Bonded for the role, wei, decimal.
    pub bonded: String,
}

/// Result of `tenzro_listRoleEndpoints`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEndpoints {
    /// The role.
    pub role: String,
    /// Its operators, most bonded first.
    pub endpoints: Vec<RoleEndpoint>,
}

/// A named Tenzro network: its chain id and the public endpoints it serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkPreset {
    /// The network's name.
    pub name: &'static str,
    /// The chain id every endpoint reports (`eth_chainId`).
    pub chain_id: u64,
    /// JSON-RPC.
    pub rpc: &'static str,
    /// REST API.
    pub api: &'static str,
    /// MCP server.
    pub mcp: &'static str,
    /// A2A, with its Agent Card.
    pub a2a: &'static str,
    /// Relay for node-to-node connections.
    pub relay: &'static str,
}

impl NetworkPreset {
    /// Options for finding this network's staked RPC operators, starting
    /// from its seeds: [`NETWORK_SEEDS`] for the preview network, otherwise
    /// its public RPC endpoint.
    pub fn options(&self) -> NetworkOptions {
        let seeds = if self.chain_id == PREVIEW_NETWORK.chain_id {
            NETWORK_SEEDS.iter().map(|s| s.to_string()).collect()
        } else {
            vec![self.rpc.to_string()]
        };
        NetworkOptions::new(seeds, self.chain_id)
    }
}

/// The Tenzro preview network.
pub const PREVIEW_NETWORK: NetworkPreset = NetworkPreset {
    name: "preview",
    chain_id: 133801,
    rpc: "https://rpc.tenzro.com",
    api: "https://api.tenzro.com",
    mcp: "https://mcp.tenzro.com/mcp",
    a2a: "https://a2a.tenzro.com",
    relay: "https://relay.tenzro.com",
};

/// The chain id the SDK expects by default: [`PREVIEW_NETWORK`]'s.
pub const NETWORK_CHAIN_ID: u64 = PREVIEW_NETWORK.chain_id;

/// Bootstrap hints for finding the network's staked RPC operators. A seed is
/// a way in, never an authority: the client asks every seed for the on-chain
/// operator list, keeps only the endpoints that report [`NETWORK_CHAIN_ID`]
/// and agree on a checkpoint digest, and from then on talks to those
/// operators. Pass your own seeds to [`NetworkOptions::new`] to start from
/// any node.
pub const NETWORK_SEEDS: &[&str] = &[PREVIEW_NETWORK.rpc];

/// How to find and check the network's operators of a role.
#[derive(Debug, Clone)]
pub struct NetworkOptions {
    /// URLs to ask for the operator list first.
    pub seeds: Vec<String>,
    /// The chain every endpoint must report (`eth_chainId`).
    pub chain_id: u64,
    /// The role whose operators to use, `rpc` by default.
    pub role: String,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl NetworkOptions {
    /// Options for `chain_id` reached through `seeds`, `rpc` role, 10 s timeout.
    pub fn new(seeds: Vec<String>, chain_id: u64) -> Self {
        Self {
            seeds,
            chain_id,
            role: "rpc".into(),
            timeout: Duration::from_secs(10),
        }
    }
}

impl Default for NetworkOptions {
    /// The preview network: [`PREVIEW_NETWORK`]'s options.
    fn default() -> Self {
        PREVIEW_NETWORK.options()
    }
}

/// An endpoint that passed the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedEndpoint {
    /// The URL.
    pub url: String,
    /// The staking account, when the endpoint came from the on-chain list.
    pub account: Option<String>,
    /// The checkpoint the endpoints were compared at.
    pub checkpoint_index: u64,
    /// That checkpoint's digest, as the endpoints that were kept reported it.
    pub checkpoint_digest: String,
}

#[derive(Deserialize)]
struct Checkpoint {
    index: u64,
    #[serde(default)]
    digest: String,
}

/// Find the network's staked operators of a role and keep those that answer
/// for the expected chain and agree on its history.
///
/// Every seed is asked for the operator list and the lists are merged; each
/// candidate (and each seed) must report `chain_id`; each reports its latest
/// checkpoint, all are compared at the lowest index they all hold, and only
/// those reporting the most common digest there are kept. Returned in list
/// order (most bonded first), seeds last.
pub async fn discover_endpoints(options: &NetworkOptions) -> SdkResult<Vec<CheckedEndpoint>> {
    let mut candidates: Vec<(String, Option<String>)> = Vec::new();
    for seed in &options.seeds {
        let Ok(rpc) = RpcClient::new(seed, options.timeout, None) else {
            continue;
        };
        let Ok(list) = rpc
            .call::<RoleEndpoints>(
                "tenzro_listRoleEndpoints",
                serde_json::json!({ "role": options.role }),
            )
            .await
        else {
            continue;
        };
        for e in list.endpoints {
            if !candidates.iter().any(|(u, _)| *u == e.url) {
                candidates.push((e.url, Some(e.account)));
            }
        }
    }
    for seed in &options.seeds {
        if !candidates.iter().any(|(u, _)| u == seed) {
            candidates.push((seed.clone(), None));
        }
    }

    let expected = format!("0x{:x}", options.chain_id);
    let mut on_chain: Vec<(RpcClient, String, Option<String>, u64)> = Vec::new();
    for (url, account) in candidates {
        let Ok(rpc) = RpcClient::new(&url, options.timeout, None) else {
            continue;
        };
        let Ok(chain) = rpc
            .call::<String>("eth_chainId", serde_json::json!([]))
            .await
        else {
            continue;
        };
        if !chain.eq_ignore_ascii_case(&expected) {
            continue;
        }
        let Ok(latest) = rpc
            .call::<Checkpoint>("tenzro_getCheckpointCertificate", serde_json::json!({}))
            .await
        else {
            continue;
        };
        on_chain.push((rpc, url, account, latest.index));
    }
    let index = on_chain.iter().map(|c| c.3).min().ok_or_else(|| {
        SdkError::ConnectionError(format!(
            "no endpoint answered for chain {}",
            options.chain_id
        ))
    })?;

    let mut by_digest: BTreeMap<String, Vec<CheckedEndpoint>> = BTreeMap::new();
    for (rpc, url, account, _) in on_chain {
        let Ok(cert) = rpc
            .call::<Checkpoint>(
                "tenzro_getCheckpointCertificate",
                serde_json::json!({ "index": index }),
            )
            .await
        else {
            continue;
        };
        by_digest
            .entry(cert.digest.clone())
            .or_default()
            .push(CheckedEndpoint {
                url,
                account,
                checkpoint_index: index,
                checkpoint_digest: cert.digest,
            });
    }
    agreeing(by_digest).ok_or_else(|| {
        SdkError::ConnectionError(format!(
            "no endpoint could be compared at checkpoint {index}"
        ))
    })
}

/// The largest group of endpoints reporting one digest; the earliest-listed
/// group wins a tie, so the result does not depend on map order alone.
fn agreeing(by_digest: BTreeMap<String, Vec<CheckedEndpoint>>) -> Option<Vec<CheckedEndpoint>> {
    by_digest
        .into_values()
        .filter(|g| !g.is_empty())
        .max_by(|a, b| a.len().cmp(&b.len()))
}

/// A client for the network: it discovers the staked RPC operators on
/// chain, keeps those that agree on the chain's history and moves between
/// them when one cannot be reached. It carries no access credential.
pub async fn connect_to_network(options: &NetworkOptions) -> SdkResult<TenzroClient> {
    let endpoints = discover_endpoints(options).await?;
    let urls: Vec<String> = endpoints.into_iter().map(|e| e.url).collect();
    let config = SdkConfig::builder()
        .endpoint(&urls[0])
        .timeout(options.timeout.as_millis() as u64)
        .chain_id(options.chain_id)
        .build()?;
    TenzroClient::with_rpc(config, RpcClient::with_failover(urls, options.timeout)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checked(url: &str, digest: &str) -> CheckedEndpoint {
        CheckedEndpoint {
            url: url.into(),
            account: None,
            checkpoint_index: 7,
            checkpoint_digest: digest.into(),
        }
    }

    #[test]
    fn an_endpoint_reporting_another_history_is_dropped() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "0xaa".to_string(),
            vec![
                checked("https://a.example", "0xaa"),
                checked("https://b.example", "0xaa"),
            ],
        );
        groups.insert(
            "0xbb".to_string(),
            vec![checked("https://liar.example", "0xbb")],
        );
        let kept = agreeing(groups).unwrap();
        assert_eq!(
            kept.iter().map(|e| e.url.as_str()).collect::<Vec<_>>(),
            ["https://a.example", "https://b.example"]
        );
    }

    #[test]
    fn a_failover_client_needs_an_endpoint() {
        assert!(RpcClient::with_failover(Vec::new(), Duration::from_secs(1)).is_err());
        assert!(
            RpcClient::with_failover(vec!["https://a.example".into()], Duration::from_secs(1))
                .is_ok()
        );
    }
}
