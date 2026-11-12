//! Role stakes for the Tenzro CLI.
//!
//! An account bonds stake per role (`rpc`, `tee`, `ai`, `compute`, `storage`,
//! `attestor`, `wallet`, `catalog`) with a `Stake`
//! transaction signed by its hardware key. A node serves a bonded role only
//! while its operator account holds the bond; the validator role is bonded by
//! `RegisterValidator`. A wallet provider bonds for the passkey domain it
//! serves and needs no node.
//!
//! - `tenzro stake bond` — bond stake for a role, declaring its capacity
//! - `tenzro stake unbond` — start unbonding part or all of a role's stake
//! - `tenzro stake withdraw` — return unbonded stake once the period has passed
//! - `tenzro stake info` — an account's stake per role (`tenzro_getRoleStakes`)
//! - `tenzro stake wallet-provider` — whether a staked wallet provider serves a
//!   passkey domain (`tenzro_getWalletProvider`)
//! - `tenzro stake endpoint` — publish (or clear) the public URL a bonded role
//!   is served at
//! - `tenzro stake endpoints` — a role's staked operators and their URLs
//!   (`tenzro_listRoleEndpoints`)

use crate::output::{self};
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use tenzro_types::network::NetworkRole;
use tenzro_types::token::{AcceleratorClass, StakeCapacity, StakeOp};
use tenzro_types::transaction::TransactionType;

/// Role-stake commands
#[derive(Debug, Subcommand)]
pub enum StakeCommand {
    /// Bond stake for a role
    Bond(StakeBondCmd),
    /// Start unbonding stake for a role
    Unbond(StakeUnbondCmd),
    /// Withdraw unbonded stake for a role once its period has passed
    Withdraw(StakeWithdrawCmd),
    /// Show an account's stake per role (read-only)
    Info(StakeInfoCmd),
    /// Show whether a staked wallet provider serves a passkey domain (read-only)
    WalletProvider(StakeWalletProviderCmd),
    /// Publish, or clear, the public URL a bonded role is served at
    Endpoint(StakeEndpointCmd),
    /// List a role's staked operators and the URLs they published (read-only)
    Endpoints(StakeEndpointsCmd),
    /// List the relays staked edge operators serve, with their last SLA verdict and the node's latest check (read-only)
    Relays(StakeRelaysCmd),
}

impl StakeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Bond(cmd) => cmd.execute().await,
            Self::Unbond(cmd) => cmd.execute().await,
            Self::Withdraw(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
            Self::WalletProvider(cmd) => cmd.execute().await,
            Self::Endpoint(cmd) => cmd.execute().await,
            Self::Endpoints(cmd) => cmd.execute().await,
            Self::Relays(cmd) => cmd.execute().await,
        }
    }
}

/// Signing account and endpoint shared by the stake writes.
#[derive(Debug, Parser)]
pub struct StakeSigner {
    /// The staking account's hardware key namespace
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeSigner {
    /// `gate`: for a bond, the role it is for and the TNZO it needs, so a
    /// wallet below that in the initial phase gets the plain application
    /// message before anything is signed, and a refusal for lack of funds is
    /// told the same way.
    async fn send(
        &self,
        op: StakeOp,
        what: &str,
        gate: Option<(
            &'static str,
            Option<crate::onboarding::role::JoinRole>,
            u128,
        )>,
    ) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let tx_type = serde_json::to_value(TransactionType::Stake { op })?;
        let (account, _) = crate::keystore::client_account(&self.key_namespace)?;
        if let Some((label, role, required)) = gate {
            crate::onboarding::flow::gate(&self.rpc, &account, label, role, required).await?;
        }
        let to: [u8; 32] = hex::decode(account.trim_start_matches("0x"))?
            .try_into()
            .map_err(|_| anyhow!("the client account is 32 bytes"))?;
        let result =
            crate::keystore::send_as_client(&rpc, &self.key_namespace, to, tx_type, 150_000)
                .await
                .map_err(|e| match gate {
                    Some((label, role, required)) => crate::onboarding::flow::plain_send_error(
                        e, label, role, required, &account,
                    ),
                    None => e,
                })?;
        output::print_success(&format!("{what} signed in hardware and submitted"));
        output::print_field("Account", &account);
        output::print_field(
            "Tx Hash",
            &result
                .as_str()
                .map_or_else(|| result.to_string(), str::to_string),
        );
        Ok(())
    }
}

fn parse_role(role: &str) -> Result<NetworkRole> {
    role.parse().map_err(|e: String| anyhow!(e))
}

/// Bond stake for a role
#[derive(Debug, Parser)]
pub struct StakeBondCmd {
    /// Role: rpc, tee, ai, compute, storage, attestor, wallet, catalog or edge (relay)
    #[arg(long)]
    role: String,

    /// Amount: whole or fractional TNZO (`10000`, `10000 TNZO`, `0.5tnzo`)
    /// or wei with its suffix (`250000000000000000wei`)
    #[arg(long, value_parser = crate::units::parse_amount_wei)]
    amount: u128,

    /// The relying-party domain your passkeys are bound to, for wallet. The
    /// domain must serve /.well-known/tenzro-provider naming the bonding account
    #[arg(long)]
    domain: Option<String>,

    /// For attestor: the 20-byte secp256k1 address (hex) you sign bridge
    /// deliveries with, which makes you eligible for bridge route committees
    #[arg(long, requires_all = ["rpc_provider", "signer_proof"])]
    bridge_signer: Option<String>,

    /// For attestor with a bridge signer: the RPC provider you read source
    /// chains from
    #[arg(long)]
    rpc_provider: Option<String>,

    /// For attestor with a bridge signer: that key's 65-byte recoverable
    /// signature (hex) over the bridge signer digest of the bonding account
    #[arg(long)]
    signer_proof: Option<String>,

    /// For attestor with a bridge signer: the ML-DSA-65 verifying key (hex,
    /// 1952 bytes) of the signer's second leg. Both legs are mandatory
    #[arg(long, requires = "bridge_signer")]
    pq_public_key: Option<String>,

    /// For attestor with a bridge signer: the ML-DSA-65 key's signature (hex)
    /// over the same bridge signer digest, context
    /// `tenzro/bridge/signer/ml-dsa-65`
    #[arg(long, requires = "bridge_signer")]
    pq_proof: Option<String>,

    /// Accelerator classes pledged, for compute (integrated, consumer, workstation, datacentre)
    #[arg(long, value_delimiter = ',')]
    accelerators: Vec<String>,

    /// Whole terabytes pledged, for storage
    #[arg(long)]
    terabytes: Option<u32>,

    #[command(flatten)]
    signer: StakeSigner,
}

impl StakeBondCmd {
    fn capacity(&self, role: NetworkRole) -> Result<StakeCapacity> {
        Ok(match role {
            NetworkRole::ComputeProvider => StakeCapacity::Accelerators(
                self.accelerators
                    .iter()
                    .map(|c| c.parse::<AcceleratorClass>().map_err(|e| anyhow!(e)))
                    .collect::<Result<_>>()?,
            ),
            NetworkRole::StorageProvider => StakeCapacity::Terabytes(self.terabytes.unwrap_or(0)),
            NetworkRole::Attestor => match &self.bridge_signer {
                None => StakeCapacity::None,
                Some(address) => StakeCapacity::BridgeSigner {
                    address: hex::decode(address.trim_start_matches("0x"))?
                        .try_into()
                        .map_err(|_| anyhow!("a bridge signer is a 20-byte address"))?,
                    rpc_provider: self.rpc_provider.clone().unwrap_or_default(),
                    proof: hex::decode(
                        self.signer_proof
                            .as_deref()
                            .unwrap_or("")
                            .trim_start_matches("0x"),
                    )?,
                    pq_public_key: hex::decode(
                        self.pq_public_key
                            .as_deref()
                            .ok_or_else(|| anyhow!("a bridge signer needs --pq-public-key"))?
                            .trim_start_matches("0x"),
                    )?,
                    pq_proof: hex::decode(
                        self.pq_proof
                            .as_deref()
                            .ok_or_else(|| anyhow!("a bridge signer needs --pq-proof"))?
                            .trim_start_matches("0x"),
                    )?,
                },
            },
            NetworkRole::WalletProvider => {
                StakeCapacity::Domain(self.domain.clone().ok_or_else(|| {
                    anyhow!("a wallet provider bonds for its passkey domain: pass --domain")
                })?)
            }
            _ => StakeCapacity::None,
        })
    }

    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bond Role Stake");
        let role = parse_role(&self.role)?;
        let capacity = self.capacity(role)?;
        output::print_field("Role", role.as_str());
        // Bond amounts are governed: tenzro_getNetworkParams lists the
        // `stake.*` values in force and any raise still pending.
        self.signer
            .send(
                StakeOp::Bond {
                    role,
                    amount: self.amount,
                    capacity,
                },
                "Stake bond",
                crate::onboarding::role::JoinRole::parse(&self.role)
                    .map(|j| (j.label(), Some(j), self.amount.max(j.stake_minimum_wei()))),
            )
            .await
    }
}

/// Start unbonding stake for a role
#[derive(Debug, Parser)]
pub struct StakeUnbondCmd {
    /// Role
    #[arg(long)]
    role: String,

    /// Amount: TNZO (`100`, `100 TNZO`) or wei with its suffix (`100wei`)
    #[arg(long, value_parser = crate::units::parse_amount_wei)]
    amount: u128,

    #[command(flatten)]
    signer: StakeSigner,
}

impl StakeUnbondCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Unbond Role Stake");
        let role = parse_role(&self.role)?;
        self.signer
            .send(
                StakeOp::Unbond {
                    role,
                    amount: self.amount,
                },
                "Stake unbond",
                None,
            )
            .await
    }
}

/// Withdraw unbonded stake for a role
#[derive(Debug, Parser)]
pub struct StakeWithdrawCmd {
    /// Role
    #[arg(long)]
    role: String,

    #[command(flatten)]
    signer: StakeSigner,
}

impl StakeWithdrawCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Withdraw Role Stake");
        let role = parse_role(&self.role)?;
        self.signer
            .send(StakeOp::Withdraw { role }, "Stake withdrawal", None)
            .await
    }
}

/// Show an account's stake per role
#[derive(Debug, Parser)]
pub struct StakeInfoCmd {
    /// Account to query (defaults to the node's operator payee)
    #[arg(long)]
    address: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Role Stakes");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let params = match &self.address {
            Some(a) => serde_json::json!({ "address": a }),
            None => serde_json::json!({}),
        };
        let info: serde_json::Value = rpc.call("tenzro_getRoleStakes", params).await?;
        if let Some(addr) = info.get("address").and_then(|v| v.as_str()) {
            output::print_field("Account", &output::format_address(addr));
        }
        for s in info
            .get("stakes")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let field = |k: &str| s.get(k).and_then(|v| v.as_str()).unwrap_or("0").to_string();
            output::print_field(
                &field("role"),
                &format!(
                    "bonded {} (requires {}, a new bond {}), unbonding {}",
                    field("bonded"),
                    field("required"),
                    field("entry_required"),
                    field("unbonding")
                ),
            );
        }
        Ok(())
    }
}

/// Show whether a staked wallet provider serves a passkey domain
#[derive(Debug, Parser)]
pub struct StakeWalletProviderCmd {
    /// The relying-party domain (RP ID) a wallet's passkeys are bound to
    rp_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeWalletProviderCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Wallet Provider");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let info: serde_json::Value = rpc
            .call(
                "tenzro_getWalletProvider",
                serde_json::json!({ "rp_id": self.rp_id }),
            )
            .await?;
        let staked = info
            .get("staked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        output::print_field("Domain", &self.rp_id);
        output::print_field("Staked provider", if staked { "yes" } else { "no" });
        for p in info
            .get("providers")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let field = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let verified = p.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
            output::print_field(
                &output::format_address(&field("account")),
                &format!(
                    "bonded {}, domain {}",
                    field("bonded"),
                    if verified { "verified" } else { "not verified" }
                ),
            );
        }
        Ok(())
    }
}

/// Publish the public URL a bonded role is served at
#[derive(Debug, Parser)]
pub struct StakeEndpointCmd {
    /// Role
    #[arg(long)]
    role: String,

    /// Public https URL of your own edge in front of the role, or "" to clear
    #[arg(long)]
    url: String,

    #[command(flatten)]
    signer: StakeSigner,
}

impl StakeEndpointCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Role Endpoint");
        let role = parse_role(&self.role)?;
        let url = self.url.trim().to_string();
        if !url.is_empty() {
            tenzro_types::token::check_role_endpoint(&url).map_err(|e| anyhow!(e))?;
        }
        output::print_field("Role", role.as_str());
        output::print_field("URL", if url.is_empty() { "(cleared)" } else { &url });
        self.signer
            .send(StakeOp::Endpoint { role, url }, "Role endpoint", None)
            .await
    }
}

/// List a role's staked operators and their published URLs
#[derive(Debug, Parser)]
pub struct StakeEndpointsCmd {
    /// Role
    #[arg(long, default_value = "rpc")]
    role: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeEndpointsCmd {
    pub async fn execute(&self) -> Result<()> {
        let role = parse_role(&self.role)?;
        output::print_header(&format!("{} endpoints", role.as_str()));
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let list: serde_json::Value = rpc
            .call(
                "tenzro_listRoleEndpoints",
                serde_json::json!({ "role": role.as_str() }),
            )
            .await?;
        for e in list
            .get("endpoints")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let field = |k: &str| e.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            output::print_field(
                &field("url"),
                &format!(
                    "{} bonded {}",
                    output::format_address(&field("account")),
                    field("bonded")
                ),
            );
        }
        Ok(())
    }
}

/// List the relays staked edge operators serve. Relaying is part of the
/// edge role: bond it (`tenzro stake bond --role edge`) and publish the relay
/// URL (`tenzro stake endpoint --role edge --url https://...`).
#[derive(Debug, Parser)]
pub struct StakeRelaysCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StakeRelaysCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Staked relays");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let list: serde_json::Value = rpc.call("tenzro_listRelays", serde_json::json!({})).await?;
        for r in list
            .get("relays")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let field = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let check = r.get("check").filter(|c| !c.is_null());
            let health = match check {
                Some(c) if c.get("healthy").and_then(|v| v.as_bool()) == Some(true) => {
                    format!(
                        "healthy, {} ms",
                        c.get("latency_ms").and_then(|v| v.as_u64()).unwrap_or(0)
                    )
                }
                Some(c) => format!(
                    "failing: {}",
                    c.get("error").and_then(|v| v.as_str()).unwrap_or("")
                ),
                None => "not checked yet".to_string(),
            };
            let used = if r.get("used").and_then(|v| v.as_bool()) == Some(true) {
                ", in use"
            } else {
                ""
            };
            let sla = match r.get("sla").filter(|v| !v.is_null()) {
                Some(v) if v.get("available").and_then(|a| a.as_bool()) == Some(false) => {
                    ", SLA: unavailable last epoch"
                }
                Some(_) => ", SLA: available last epoch",
                None => "",
            };
            output::print_field(
                &field("url"),
                &format!(
                    "{} bonded {} ({health}{used}{sla})",
                    output::format_address(&field("account")),
                    field("bonded")
                ),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bond(role: &str) -> StakeBondCmd {
        StakeBondCmd {
            role: role.into(),
            amount: 1,
            accelerators: vec!["consumer".into(), "datacentre".into()],
            terabytes: Some(4),
            domain: Some("wallet.example".into()),
            bridge_signer: None,
            rpc_provider: None,
            signer_proof: None,
            pq_public_key: None,
            pq_proof: None,
            signer: StakeSigner {
                key_namespace: "client".into(),
                rpc: String::new(),
            },
        }
    }

    #[test]
    fn capacity_follows_the_role() {
        let c = |r: &str| bond(r).capacity(parse_role(r).unwrap()).unwrap();
        assert_eq!(
            c("compute"),
            StakeCapacity::Accelerators(vec![
                AcceleratorClass::Consumer,
                AcceleratorClass::Datacentre
            ])
        );
        assert_eq!(c("storage"), StakeCapacity::Terabytes(4));
        assert_eq!(c("rpc"), StakeCapacity::None);
        assert_eq!(c("wallet"), StakeCapacity::Domain("wallet.example".into()));
        let mut no_domain = bond("wallet");
        no_domain.domain = None;
        assert!(no_domain.capacity(NetworkRole::WalletProvider).is_err());
        assert!(parse_role("nonsense").is_err());
    }
}
