//! Role stakes on Tenzro Network.
//!
//! An account bonds stake per role (`rpc`, `tee`, `ai`, `compute`, `storage`,
//! `attestor`, `wallet`, `catalog`) with a `Stake` transaction it
//! signs itself. A node serves a bonded role only while its operator account
//! holds that role's bond. The validator role is bonded by `RegisterValidator`.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// One relay check, as a node ran it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayCheck {
    pub url: String,
    pub operator: Option<String>,
    pub healthy: bool,
    pub latency_ms: Option<u64>,
    pub checked_ms: u64,
    pub error: Option<String>,
}

/// A staked edge operator's relay and the answering node's latest check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakedRelay {
    pub account: String,
    pub url: String,
    pub bonded: String,
    pub used: bool,
    pub check: Option<RelayCheck>,
    /// The SLA verdict validators froze for the last closed epoch, if any.
    pub sla: Option<RelaySla>,
}

/// An SLA verdict on a staked relay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelaySla {
    pub epoch: u64,
    pub available: bool,
    pub attesters: u64,
}

/// Result of `tenzro_listRelays`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakedRelays {
    pub relays: Vec<StakedRelay>,
}

/// A relay a node is connected through.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectedRelay {
    pub url: String,
    pub connected: bool,
}

/// Result of `tenzro_getConnectivity`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connectivity {
    /// `public`, `port_mapped`, `hole_punch`, `peer_relay`, `relay` or `unreachable`.
    pub reachability: String,
    /// `unknown`, `none`, `endpoint_independent` or `endpoint_dependent`.
    pub nat: String,
    pub observers: u64,
    pub port_mapped: bool,
    pub external_addresses: u64,
    pub ipv4: bool,
    pub ipv6: bool,
    pub relays: Vec<ConnectedRelay>,
    /// Peers reached on a birthday-punched direct path.
    pub punched_paths: u64,
    /// Peer relays (forwarders) the node offers paths through.
    pub peer_relays: Vec<PeerRelayPath>,
}

/// A peer relay a node offers a path through.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRelayPath {
    pub endpoint: String,
    pub rtt_ms: u64,
    pub direct: bool,
}

/// Client for role stakes.
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let staking = client.staking();
/// let stakes = staking.role_stakes(Some("0xwallet...")).await?;
/// println!("{} roles bonded", stakes.stakes.len());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct StakingClient {
    rpc: Arc<RpcClient>,
}

impl StakingClient {
    /// Creates a new staking client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// An account's stake per role and every role's network total
    /// (`tenzro_getRoleStakes`). `None` reads the node's operator payee.
    pub async fn role_stakes(&self, address: Option<&str>) -> SdkResult<RoleStakes> {
        let params = match address {
            Some(a) => serde_json::json!({ "address": a }),
            None => serde_json::json!({}),
        };
        self.rpc.call("tenzro_getRoleStakes", params).await
    }

    /// A role's staked operators and the public URLs they published on
    /// chain, most bonded first (`tenzro_listRoleEndpoints`). See
    /// [`crate::network`] for a client that uses them.
    pub async fn role_endpoints(&self, role: &str) -> SdkResult<crate::network::RoleEndpoints> {
        self.rpc
            .call(
                "tenzro_listRoleEndpoints",
                serde_json::json!({ "role": role }),
            )
            .await
    }

    /// The relays staked edge operators serve, most bonded first, with the
    /// SLA verdict validators froze for the last closed epoch and the
    /// answering node's latest check of each (`tenzro_listRelays`).
    pub async fn relays(&self) -> SdkResult<StakedRelays> {
        self.rpc
            .call("tenzro_listRelays", serde_json::json!({}))
            .await
    }

    /// How the answering node is reached: directly, after hole punching, or
    /// through relays (`tenzro_getConnectivity`). Names no address.
    pub async fn connectivity(&self) -> SdkResult<Connectivity> {
        self.rpc
            .call("tenzro_getConnectivity", serde_json::json!({}))
            .await
    }

    /// Whether a staked wallet provider serves the passkey relying-party
    /// domain `rp_id` (`tenzro_getWalletProvider`). A wallet linking a
    /// credential from that domain shows it as coming from a staked provider
    /// only when `staked` is true; credentials from other domains still work.
    pub async fn wallet_provider(&self, rp_id: &str) -> SdkResult<WalletProviderStatus> {
        self.rpc
            .call(
                "tenzro_getWalletProvider",
                serde_json::json!({ "rp_id": rp_id }),
            )
            .await
    }
}

/// Result of `tenzro_getWalletProvider`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletProviderStatus {
    /// The relying-party domain asked about.
    pub rp_id: String,
    /// True when an account bonded for the domain and the validators' latest
    /// check found the domain's `/.well-known/tenzro-provider` naming it.
    pub staked: bool,
    /// Every account bonded for the domain, verified ones first.
    pub providers: Vec<WalletProviderBond>,
}

/// One account bonded as a wallet provider for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletProviderBond {
    /// The bonding account, 0x hex.
    pub account: String,
    /// Bonded, wei, decimal string.
    pub bonded: String,
    /// Whether the latest recent check found the domain naming the account.
    pub verified: bool,
    /// The closed epoch of that check, when one is recent enough to count.
    pub verdict_epoch: Option<u64>,
}

/// Result of `tenzro_getRoleStakes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleStakes {
    /// The account, 0x hex.
    pub address: String,
    /// Its stake per role.
    pub stakes: Vec<RoleStake>,
    /// Every bondable role's network total.
    pub totals: Vec<RoleStakeTotal>,
}

/// One account's stake for one role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleStake {
    /// The role's wire token.
    pub role: String,
    /// Bonded, wei, decimal string.
    pub bonded: String,
    /// The role's required stake for the declared capacity, wei.
    pub required: String,
    /// What a new or raised bond for that capacity must meet, wei:
    /// `required`, raised when TNZO trades below
    /// `stake.bond_floor_rate_nano_usd` at the safety rate.
    pub entry_required: String,
    /// The declared capacity.
    pub capacity: serde_json::Value,
    /// Unbonding, wei.
    pub unbonding: String,
    /// When the unbonding stake can be withdrawn, ms.
    pub release_at_ms: i64,
    /// For a serving role's stake, the SLA subject validators probe it under
    /// (`did:tenzro:role:<role>:<account hex>`); an unavailable verdict
    /// slashes the stake. A storage stake's storage claims also name it.
    #[serde(default)]
    pub sla_subject: Option<String>,
}

/// A role's stake across every account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleStakeTotal {
    /// The role's wire token.
    pub role: String,
    /// Bonded, wei.
    pub bonded: String,
    /// Accounts with a bond above zero.
    pub stakers: u64,
}
