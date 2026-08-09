//! Node-alias operations: claim, bind, release, and read a node's name.
//!
//! # Why these are transactions, not RPC writes
//!
//! Naming is permissionless. Ownership is settled by block order rather than
//! by whichever RPC endpoint a claimant happened to reach, so `claim` / `bind`
//! / `release` submit **typed transactions** through
//! `tenzro_signAndSendTransaction` — the same shape as validator registration
//! and escrow. `resolve` / `list` are ordinary reads of the applied result.
//!
//! # Why binding takes two parties
//!
//! A bind decides which physical node a public name points at, so it needs
//! consent from both sides and neither can forge the other's half:
//!
//!   * the **claim owner** sends the transaction — they hold the name;
//!   * the **machine** signs a consent statement — it holds the node key.
//!
//! Without the machine's half, anyone could claim a name and point it at
//! somebody else's node; on a registrable domain shared by every node — the
//! one every passkey is scoped to — that is a phishing primitive rather than a
//! misconfiguration. `bind` therefore fetches the consent signature from the
//! target node (`tenzro_nodeAliasConsent`) and carries it in the transaction.

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Gas for a claim. Priced above bind/release because it consumes a globally
/// unique name out of a finite namespace.
const GAS_CLAIM: u64 = 100_000;
const GAS_BIND: u64 = 40_000;
const GAS_RELEASE: u64 = 25_000;
const GAS_PRICE_WEI: u64 = 1_000_000_000;

#[derive(Debug, Subcommand)]
pub enum NodeAliasCommand {
    /// Claim a readable name for a node
    Claim(AliasClaimCmd),
    /// Point a claimed name at a running node
    Bind(AliasBindCmd),
    /// Return a claimed name to the unclaimed pool
    Release(AliasReleaseCmd),
    /// Look up who owns a name
    Resolve(AliasResolveCmd),
    /// List known claims
    List(AliasListCmd),
}

impl NodeAliasCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Claim(c) => c.execute().await,
            Self::Bind(c) => c.execute().await,
            Self::Release(c) => c.execute().await,
            Self::Resolve(c) => c.execute().await,
            Self::List(c) => c.execute().await,
        }
    }
}

/// Claim a readable name for a node.
#[derive(Debug, Parser)]
pub struct AliasClaimCmd {
    /// Bare DNS label to claim, e.g. `alice`. Not a hostname — the public
    /// suffix is node configuration, so a claim outlives a domain change.
    pub name: String,

    /// Account that pays for and owns the claim. This address is the sole
    /// authority over the name afterwards.
    #[arg(long)]
    pub from: String,

    /// DID displayed alongside the name. Informational; authority is `--from`.
    #[arg(long)]
    pub did: Option<String>,

    /// Request paths served publicly under this name. Repeatable. Omit for
    /// the fail-closed default set (health/status/v1/models/providers).
    #[arg(long = "expose")]
    pub expose: Vec<String>,

    /// RPC endpoint.
    #[arg(long, default_value = "https://rpc.tenzro.xyz")]
    pub rpc: String,
}

impl AliasClaimCmd {
    pub async fn execute(&self) -> Result<()> {
        let name = normalize(&self.name)?;
        output::print_header("Claim Node Alias");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Checking availability...");
        if let Ok(existing) = rpc
            .call::<serde_json::Value>(
                "tenzro_resolveNodeAlias",
                serde_json::json!({ "name": name }),
            )
            .await
        {
            spinner.finish_and_clear();
            let owner = existing
                .get("owner_address")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if !owner.eq_ignore_ascii_case(&with_0x(&self.from)) {
                return Err(anyhow!(
                    "`{name}` is already claimed by {owner}. Names are first-claimed on-chain, \
                     so this cannot be taken over — pick another name, or have the current \
                     owner release it."
                ));
            }
            output::print_info("You already hold this name — re-claiming refreshes its settings.");
        } else {
            spinner.finish_and_clear();
        }

        let (nonce, chain_id) = crate::rpc::fetch_nonce_and_chain_id(&rpc, &self.from).await;
        let exposed = (!self.expose.is_empty()).then(|| self.expose.clone());
        let tx_type = serde_json::json!({
            "ClaimNodeAlias": {
                "name": name,
                "owner_did": self.did.clone().unwrap_or_default(),
                "exposed_prefixes": exposed,
            }
        });

        let spinner = output::create_spinner("Submitting claim...");
        let result = submit(&rpc, &self.from, tx_type, GAS_CLAIM, nonce, chain_id).await?;
        spinner.finish_and_clear();

        output::print_success(&format!("Claimed `{name}`"));
        print_tx(&result);
        output::print_info(&format!(
            "Next: start the node, then `tenzro node alias bind {name} --from {}`",
            self.from
        ));
        Ok(())
    }
}

/// Point a claimed name at a running node.
#[derive(Debug, Parser)]
pub struct AliasBindCmd {
    /// The claimed label to bind.
    pub name: String,

    /// The claim's owning account. Must match the claim, or the chain rejects
    /// the transaction.
    #[arg(long)]
    pub from: String,

    /// RPC of the node the name should resolve to. Defaults to the local
    /// node, which is the usual case — you are binding the machine you are on.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub node_rpc: String,

    /// RPC the transaction is submitted through.
    #[arg(long, default_value = "https://rpc.tenzro.xyz")]
    pub rpc: String,

    /// Re-declare the public path allowlist at bind time. Repeatable.
    #[arg(long = "expose")]
    pub expose: Vec<String>,
}

impl AliasBindCmd {
    pub async fn execute(&self) -> Result<()> {
        let name = normalize(&self.name)?;
        output::print_header("Bind Node Alias");

        // Ask the target node to sign its consent. It will only sign for its
        // own identity, so this is the step that proves the machine agreed —
        // the CLI cannot fabricate it, and neither can the name's owner.
        let node = RpcClient::new(&self.node_rpc);
        let spinner = output::create_spinner("Requesting the node's consent signature...");
        let consent: serde_json::Value = node
            .call(
                "tenzro_nodeAliasConsent",
                serde_json::json!({
                    "name": name,
                    "owner_address": self.from,
                }),
            )
            .await
            .map_err(|e| {
                anyhow!(
                    "could not get consent from the node at {}: {e}\n\
                     The node must be running and have a provisioned identity. \
                     Binding requires proof the machine agreed to answer for this name.",
                    self.node_rpc
                )
            })?;
        spinner.finish_and_clear();

        let machine_did = consent
            .get("machine_did")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("node returned no machine_did"))?;
        let endpoint_id = consent
            .get("endpoint_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("node returned no endpoint_id"))?;
        let machine_consent = consent
            .get("machine_consent")
            .cloned()
            .ok_or_else(|| anyhow!("node returned no consent signature"))?;

        output::print_field("Machine DID", machine_did);
        output::print_field("Endpoint", endpoint_id);

        let rpc = RpcClient::new(&self.rpc);
        let (nonce, chain_id) = crate::rpc::fetch_nonce_and_chain_id(&rpc, &self.from).await;
        let exposed = (!self.expose.is_empty()).then(|| self.expose.clone());
        let tx_type = serde_json::json!({
            "BindNodeAlias": {
                "name": name,
                "machine_did": machine_did,
                "endpoint_id": endpoint_id,
                "machine_consent": machine_consent,
                "exposed_prefixes": exposed,
            }
        });

        let spinner = output::create_spinner("Submitting bind...");
        let result = submit(&rpc, &self.from, tx_type, GAS_BIND, nonce, chain_id).await?;
        spinner.finish_and_clear();

        output::print_success(&format!("`{name}` now resolves to this node"));
        print_tx(&result);
        Ok(())
    }
}

/// Return a claimed name to the unclaimed pool.
#[derive(Debug, Parser)]
pub struct AliasReleaseCmd {
    /// The claimed label to release.
    pub name: String,
    /// The claim's owning account.
    #[arg(long)]
    pub from: String,
    /// RPC endpoint.
    #[arg(long, default_value = "https://rpc.tenzro.xyz")]
    pub rpc: String,
}

impl AliasReleaseCmd {
    pub async fn execute(&self) -> Result<()> {
        let name = normalize(&self.name)?;
        output::print_header("Release Node Alias");
        let rpc = RpcClient::new(&self.rpc);
        let (nonce, chain_id) = crate::rpc::fetch_nonce_and_chain_id(&rpc, &self.from).await;
        let tx_type = serde_json::json!({ "ReleaseNodeAlias": { "name": name } });
        let spinner = output::create_spinner("Submitting release...");
        let result = submit(&rpc, &self.from, tx_type, GAS_RELEASE, nonce, chain_id).await?;
        spinner.finish_and_clear();
        output::print_success(&format!("Released `{name}` — anyone may now claim it"));
        print_tx(&result);
        Ok(())
    }
}

/// Look up who owns a name.
#[derive(Debug, Parser)]
pub struct AliasResolveCmd {
    /// The label to look up.
    pub name: String,
    /// RPC endpoint.
    #[arg(long, default_value = "https://rpc.tenzro.xyz")]
    pub rpc: String,
}

impl AliasResolveCmd {
    pub async fn execute(&self) -> Result<()> {
        let name = normalize(&self.name)?;
        output::print_header("Node Alias");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_resolveNodeAlias",
                serde_json::json!({ "name": name }),
            )
            .await
            .map_err(|e| anyhow!("`{name}` is not claimed ({e})"))?;

        for (label, key) in [
            ("Name", "name"),
            ("Owner", "owner_address"),
            ("Owner DID", "owner_did"),
            ("Machine DID", "machine_did"),
            ("Endpoint", "endpoint_id"),
            ("Hostname", "hostname"),
        ] {
            if let Some(v) = result.get(key).and_then(|v| v.as_str()) {
                output::print_field(label, v);
            }
        }
        output::print_field(
            "Routable",
            if result.get("bound").and_then(|v| v.as_bool()) == Some(true) {
                "yes"
            } else {
                "no — claimed but not yet bound to a node"
            },
        );
        Ok(())
    }
}

/// List known claims.
#[derive(Debug, Parser)]
pub struct AliasListCmd {
    /// Only claims held by this address.
    #[arg(long)]
    pub owner: Option<String>,
    /// RPC endpoint.
    #[arg(long, default_value = "https://rpc.tenzro.xyz")]
    pub rpc: String,
}

impl AliasListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Node Aliases");
        let rpc = RpcClient::new(&self.rpc);
        let params = match &self.owner {
            Some(o) => serde_json::json!({ "owner_address": o }),
            None => serde_json::json!({}),
        };
        let result: serde_json::Value = rpc.call("tenzro_listNodeAliases", params).await?;

        let rows = result
            .get("aliases")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if rows.is_empty() {
            output::print_info("No claims found.");
            return Ok(());
        }
        for row in &rows {
            let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let bound = row.get("bound").and_then(|v| v.as_bool()).unwrap_or(false);
            let host = row.get("hostname").and_then(|v| v.as_str()).unwrap_or(name);
            output::print_field(name, if bound { host } else { "(claimed, unbound)" });
        }
        output::print_info(&format!("{} claim(s)", rows.len()));
        Ok(())
    }
}

/// Lowercase and validate a label against the DNS-label rule.
///
/// Validated client-side so a typo costs nothing, rather than being spent as
/// gas on a transaction the chain will reject.
fn normalize(raw: &str) -> Result<String> {
    let name = raw.trim().to_ascii_lowercase();
    tenzro_types::node_alias::validate_alias(&name)
        .map_err(|e| anyhow!("invalid node alias `{name}`: {e}"))?;
    Ok(name)
}

fn with_0x(addr: &str) -> String {
    if addr.starts_with("0x") {
        addr.to_string()
    } else {
        format!("0x{addr}")
    }
}

async fn submit(
    rpc: &RpcClient,
    from: &str,
    tx_type: serde_json::Value,
    gas_limit: u64,
    nonce: u64,
    chain_id: u64,
) -> Result<serde_json::Value> {
    rpc.send_tx_clearing_fee_floor(
        "tenzro_signAndSendTransaction",
        serde_json::json!({
            "from": from,
            "to": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "value": 0u64,
            "gas_limit": gas_limit,
            "gas_price": GAS_PRICE_WEI,
            "nonce": nonce,
            "chain_id": chain_id,
            "tx_type": tx_type,
        }),
    )
    .await
}

fn print_tx(result: &serde_json::Value) {
    if let Some(h) = result
        .get("tx_hash")
        .or_else(|| result.get("hash"))
        .and_then(|v| v.as_str())
    {
        output::print_field("Transaction", h);
    }
}
