//! `tenzro machine-access` — what the machine owner lets agents, tools and
//! models on a node reach.
//!
//! Every change is signed by the machine owner, in two steps. Run a command
//! without `--challenge-id`: the node issues a custody challenge bound to
//! exactly that change and this prints it. Approve the challenge in the
//! owner's wallet (passkey assertion and ML-DSA-65 signature), save the
//! authorization it produces, then run the same command again with
//! `--challenge-id` and `--authorization`.

use crate::output;
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};

/// Owner-signed machine-access grants.
#[derive(Debug, Subcommand)]
pub enum MachineAccessCommand {
    /// Grant access to a network range, a local service or a folder.
    Add(AddCmd),
    /// List the grants on the node, with their use counts.
    List(ListCmd),
    /// Revoke a grant. It stops applying at once.
    Revoke(RevokeCmd),
}

impl MachineAccessCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Add(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Revoke(c) => c.execute().await,
        }
    }
}

/// The owner's approval of one change.
#[derive(Debug, Args)]
pub struct Approval {
    /// The challenge the first run printed.
    #[arg(long, requires = "authorization")]
    challenge_id: Option<String>,
    /// JSON file from the owner's wallet: `credential_id_hex`, `assertion`
    /// and `ml_dsa_signature_hex` over that challenge.
    #[arg(long, requires = "challenge_id")]
    authorization: Option<std::path::PathBuf>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl Approval {
    /// Submit `method` with the approval, or, without one, obtain and print
    /// the challenge for `change`. Returns the method's result once submitted.
    async fn run(&self, method: &str, change: Value, params: Value) -> Result<Option<Value>> {
        use crate::rpc::RpcClient;
        let client = RpcClient::new(&self.rpc);
        let (Some(challenge_id), Some(path)) = (&self.challenge_id, &self.authorization) else {
            let issued: Value = client
                .call(
                    "tenzro_createCustodyChallenge",
                    json!({ "operation": "machine_access", "machine_access": change }),
                )
                .await?;
            output::print_header("Owner approval required");
            output::print_field("Challenge", issued["challenge_id"].as_str().unwrap_or("?"));
            output::print_field(
                "WebAuthn challenge",
                issued["webauthn_challenge"].as_str().unwrap_or("?"),
            );
            output::print_field(
                "Owner account",
                issued["account_address"].as_str().unwrap_or("?"),
            );
            output::print_field(
                "Expires in",
                &format!("{} s", issued["expires_in_secs"].as_u64().unwrap_or(0)),
            );
            println!();
            println!(
                "Approve the WebAuthn challenge with the machine owner's passkey, save the authorization it \
                 produces, and run the same command again with --challenge-id and \
                 --authorization."
            );
            return Ok(None);
        };
        let raw = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let mut authorization: Value = serde_json::from_slice(&raw)
            .with_context(|| format!("{} is not an authorization JSON object", path.display()))?;
        authorization["challenge_id"] = json!(challenge_id);
        let mut params = params;
        params["authorization"] = authorization;
        Ok(Some(client.call(method, params).await?))
    }
}

#[derive(Debug, Parser)]
pub struct AddCmd {
    /// Who the grant is for: the node's machine DID for any sandboxed job on
    /// it, or an agent or tool DID.
    #[arg(long)]
    grantee: String,
    /// A network range, as CIDR with an optional port: `198.51.100.0/24`,
    /// `127.0.0.1/32:5432`, `fd12::/64:443`. Repeatable.
    #[arg(long = "network")]
    networks: Vec<String>,
    /// An absolute folder path the sandbox mounts. Repeatable.
    #[arg(long = "folder")]
    folders: Vec<String>,
    /// Operations: `connect` for networks, `read` and/or `write` for folders.
    #[arg(long, value_delimiter = ',', required = true)]
    operations: Vec<String>,
    /// When the grant ends, in milliseconds since the Unix epoch. Pass the
    /// value the first run printed when approving.
    #[arg(
        long,
        required_unless_present = "expires_in_secs",
        conflicts_with = "expires_in_secs"
    )]
    expires_at_ms: Option<i64>,
    /// When the grant ends, in seconds from now. Resolved on the first run.
    #[arg(long)]
    expires_in_secs: Option<i64>,
    #[arg(long)]
    max_uses_per_minute: Option<u32>,
    /// Most bytes moved through the grant.
    #[arg(long)]
    max_bytes: Option<u64>,
    #[command(flatten)]
    approval: Approval,
}

/// Parse `CIDR[:PORT]` into a network resource.
fn network_resource(spec: &str) -> Result<Value> {
    let (address, prefix) = spec
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("{spec:?} is not CIDR: use address/prefix[:port]"))?;
    let (prefix, port) = match prefix.split_once(':') {
        Some((prefix, port)) => (
            prefix,
            Some(
                port.parse::<u16>()
                    .with_context(|| format!("{spec:?} has an invalid port"))?,
            ),
        ),
        None => (prefix, None),
    };
    Ok(json!({ "kind": "network", "cidr": format!("{address}/{prefix}"), "port": port }))
}

impl AddCmd {
    fn terms(&self, expires_at_ms: i64) -> Result<Value> {
        let mut resources = self
            .networks
            .iter()
            .map(|n| network_resource(n))
            .collect::<Result<Vec<_>>>()?;
        resources.extend(
            self.folders
                .iter()
                .map(|path| json!({ "kind": "folder", "path": path })),
        );
        Ok(json!({
            "grantee_did": self.grantee,
            "resources": resources,
            "operations": self.operations,
            "expires_at_ms": expires_at_ms,
            "max_uses_per_minute": self.max_uses_per_minute,
            "max_bytes": self.max_bytes,
        }))
    }

    pub async fn execute(&self) -> Result<()> {
        let expires_at_ms = match (self.expires_at_ms, self.expires_in_secs) {
            (Some(at), _) => at,
            (None, Some(secs)) => {
                let at = chrono::Utc::now().timestamp_millis() + secs.saturating_mul(1000);
                output::print_field("Expires at", &format!("--expires-at-ms {at}"));
                at
            }
            (None, None) => anyhow::bail!("--expires-at-ms or --expires-in-secs is required"),
        };
        let terms = self.terms(expires_at_ms)?;
        let mut change = terms.clone();
        change["action"] = json!("add");
        let Some(result) = self
            .approval
            .run("tenzro_addMachineAccess", change, terms)
            .await?
        else {
            return Ok(());
        };
        output::print_header("Machine access granted");
        output::print_field("Grant", result["grant_id"].as_str().unwrap_or("?"));
        output::print_field("Grantee", result["grantee_did"].as_str().unwrap_or("?"));
        output::print_field("Until", &result["not_after"].to_string());
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ListCmd {
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    approval: Approval,
}

impl ListCmd {
    pub async fn execute(&self) -> Result<()> {
        let Some(result) = self
            .approval
            .run(
                "tenzro_listMachineAccess",
                json!({ "action": "list" }),
                json!({}),
            )
            .await?
        else {
            return Ok(());
        };
        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        output::print_header("Machine-access grants");
        for grant in result["grants"].as_array().unwrap_or(&Vec::new()) {
            output::print_field(
                grant["grant_id"].as_str().unwrap_or("?"),
                &format!(
                    "{} -> {} | uses {} | refusals {} | bytes {}{}",
                    grant["grantee_did"].as_str().unwrap_or("?"),
                    grant["resources"],
                    grant["uses"],
                    grant["refusals"],
                    grant["bytes"],
                    if grant["revoked"].as_bool().unwrap_or(false) {
                        " | REVOKED"
                    } else {
                        ""
                    },
                ),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RevokeCmd {
    grant_id: String,
    #[command(flatten)]
    approval: Approval,
}

impl RevokeCmd {
    pub async fn execute(&self) -> Result<()> {
        let Some(result) = self
            .approval
            .run(
                "tenzro_revokeMachineAccess",
                json!({ "action": "revoke", "grant_id": self.grant_id }),
                json!({ "grant_id": self.grant_id }),
            )
            .await?
        else {
            return Ok(());
        };
        output::print_header("Machine access revoked");
        output::print_field("Grant", result["grant_id"].as_str().unwrap_or("?"));
        output::print_field("Revoked at", &result["revoked_at"].to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_specs_parse_with_and_without_a_port() {
        assert_eq!(
            network_resource("198.51.100.0/24").unwrap(),
            json!({ "kind": "network", "cidr": "198.51.100.0/24", "port": null })
        );
        assert_eq!(
            network_resource("127.0.0.1/32:5432").unwrap(),
            json!({ "kind": "network", "cidr": "127.0.0.1/32", "port": 5432 })
        );
        assert_eq!(
            network_resource("fd12::/64:443").unwrap(),
            json!({ "kind": "network", "cidr": "fd12::/64", "port": 443 })
        );
        assert!(network_resource("127.0.0.1:5432").is_err());
        assert!(network_resource("10.0.0.0/8:99999").is_err());
    }

    #[test]
    fn the_command_parses() {
        use clap::Parser as _;
        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            cmd: MachineAccessCommand,
        }
        let cli = Cli::try_parse_from([
            "tenzro",
            "add",
            "--grantee",
            "did:tenzro:machine:x",
            "--network",
            "127.0.0.1/32:5432",
            "--operations",
            "connect",
            "--expires-at-ms",
            "1900000000000",
        ])
        .unwrap();
        let MachineAccessCommand::Add(add) = cli.cmd else {
            panic!("not add");
        };
        let terms = add.terms(1_900_000_000_000).unwrap();
        assert_eq!(terms["resources"][0]["port"], 5432);
        assert_eq!(terms["operations"], json!(["connect"]));
        // Approval needs both halves or neither.
        assert!(Cli::try_parse_from(["tenzro", "revoke", "g1", "--challenge-id", "c1"]).is_err());
    }
}
