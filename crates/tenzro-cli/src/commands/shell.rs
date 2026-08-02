//! `tenzro shell` — interactive access to hardware you rented.
//!
//! The sign-in is the `gcloud auth login` shape, reusing the passkey ceremony
//! the Tenzro wallet already runs: present the service key your operator gave
//! you, open the printed link, verify with your passkey, and the session
//! opens.
//!
//! Three things have to hold, and each answers a different question:
//!
//! - the **service key** says which lease you mean;
//! - the **passkey ceremony** says which wallet you are;
//! - the operator's **authorized-wallet list** says whether that wallet may
//!   use that lease.
//!
//! A key on its own reaches nothing. That is deliberate — it means a leaked
//! key is not a compromise, and it means the session receipt on the operator's
//! node names the wallet that actually signed in rather than "whoever had the
//! string".

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use super::passkey::{derive_web_url, launch_browser, poll_session};
use crate::output;
use crate::rpc::RpcClient;

/// Interactive access to rented hardware.
#[derive(Debug, Subcommand)]
pub enum ShellCommand {
    /// Sign in and open a session on a node you rented.
    Login(ShellLoginCmd),
    /// Operator: lease management for hardware you rent out.
    #[command(subcommand)]
    Lease(LeaseSubcommand),
}

impl ShellCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Login(cmd) => cmd.execute().await,
            Self::Lease(cmd) => cmd.execute().await,
        }
    }
}

/// Sign in to a rented node.
#[derive(Debug, Parser)]
pub struct ShellLoginCmd {
    /// The service key the node operator issued you.
    #[arg(long, env = "TENZRO_SERVICE_KEY", hide_env_values = true)]
    service_key: String,

    /// Your wallet smart-account address — the one whose passkey you will use.
    #[arg(long)]
    account: String,

    /// RPC endpoint of the node you rented.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Web base URL for the passkey page. Derived from `--rpc` when omitted.
    #[arg(long)]
    web_url: Option<String>,
}

impl ShellLoginCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Shell Sign-In");

        let rpc = RpcClient::new(&self.rpc);
        let web_base = derive_web_url(self.web_url.as_deref(), &self.rpc)?;

        // The node checks the key and the wallet list before minting a
        // ceremony, so a request that was never going to be granted fails
        // here rather than after you have tapped your passkey.
        let session: Value = rpc
            .call(
                "tenzro_requestShellSession",
                json!({
                    "service_key": self.service_key,
                    "account_address": self.account,
                }),
            )
            .await?;

        let session_id = session
            .get("session_id")
            .and_then(|v| v.as_str())
            .context("node returned no session_id")?
            .to_string();
        let verification_path = session
            .get("verification_path")
            .and_then(|v| v.as_str())
            .context("node returned no verification_path")?;

        // Shown before the browser opens so you can see what you are about to
        // get, and notice if it is not what you paid for.
        output::print_field(
            "Lease",
            session
                .get("lease_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        );
        output::print_field(
            "Accelerators",
            &match session.get("accelerators").and_then(|v| v.as_array()) {
                Some(a) if !a.is_empty() => a
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => "none".to_string(),
            },
        );
        output::print_field(
            "Session ceiling",
            &format!(
                "{} s",
                session
                    .get("max_session_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            ),
        );

        launch_browser(&format!("{web_base}{verification_path}"));
        let result = poll_session(&rpc, &session_id).await?;

        let grant = result.get("shell_grant").context(
            "the ceremony completed but the node minted no session grant — the \
                      operator may have removed your wallet from the lease while you were \
                      verifying",
        )?;
        let grant_id = grant
            .get("grant_id")
            .and_then(|v| v.as_str())
            .context("node returned a malformed session grant")?;

        output::print_success(&format!(
            "Verified as {}",
            grant.get("wallet").and_then(|v| v.as_str()).unwrap_or("?")
        ));
        // Printed rather than used directly: opening the QUIC stream needs the
        // node's iroh EndpointId, which the renter gets from the operator or
        // from the node's DID document. Keeping the two steps separate also
        // means a grant can be handed to a terminal multiplexer that is not
        // this process.
        output::print_field("Session grant", grant_id);
        output::print_info(
            "The grant is single-use and expires in two minutes. Present it as the first line \
             on a `tenzro/shell` stream to the node's iroh endpoint.",
        );
        Ok(())
    }
}

/// Operator lease management.
#[derive(Debug, Subcommand)]
pub enum LeaseSubcommand {
    /// Issue a service key and open a lease for it.
    Open(LeaseOpenCmd),
    /// End a lease. Kills every outstanding session grant against it.
    Revoke(LeaseRevokeCmd),
    /// List every lease on this node.
    List(LeaseListCmd),
}

impl LeaseSubcommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Open(cmd) => cmd.execute().await,
            Self::Revoke(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
        }
    }
}

/// Open a lease.
#[derive(Debug, Parser)]
pub struct LeaseOpenCmd {
    /// The service key to issue. Only its digest is stored — keep your copy.
    #[arg(long)]
    service_key: String,

    /// A wallet permitted to sign in against this lease. Repeat for several.
    ///
    /// At least one is required: a lease naming no wallet is a key with
    /// nothing behind it, and the node refuses to create one.
    #[arg(long = "wallet", required = true)]
    wallets: Vec<String>,

    /// The renter's DID, for the audit record.
    #[arg(long)]
    renter_did: String,

    /// The compute rental this accompanies, if any.
    #[arg(long)]
    rental_id: Option<String>,

    /// Accelerator index the renter may use. Repeat for several. Omit for a
    /// CPU-only lease — "all GPUs" is not a scope anyone chose.
    #[arg(long = "gpu")]
    gpus: Vec<u32>,

    /// CPU cores.
    #[arg(long, default_value_t = 4)]
    cores: u32,

    /// Memory ceiling, MiB.
    #[arg(long, default_value_t = 16384)]
    memory_mib: u64,

    /// Allow outbound internet from the session. Off by default: a rented
    /// shell is for compute, and the operator's local networks stay
    /// unreachable either way.
    #[arg(long)]
    allow_egress: bool,

    /// Per-session wall-clock ceiling, seconds. Capped at 12 hours.
    #[arg(long, default_value_t = 3600)]
    max_session_secs: u64,

    /// Lease term, hours.
    #[arg(long, default_value_t = 24)]
    term_hours: u64,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token.
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl LeaseOpenCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Open Access Lease");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        }

        let mut devices = vec![
            json!({ "cpu": { "cores": self.cores } }),
            json!({ "memory": { "mib": self.memory_mib } }),
        ];
        devices.extend(
            self.gpus
                .iter()
                .map(|i| json!({ "accelerator": { "index": i } })),
        );

        let result: Value = rpc
            .call(
                "tenzro_openAccessLease",
                json!({
                    "service_key": self.service_key,
                    "authorized_wallets": self.wallets,
                    "renter_did": self.renter_did,
                    "rental_id": self.rental_id,
                    "scope": {
                        "workspace": "/workspace",
                        "devices": devices,
                        "network": if self.allow_egress { "egress_only" } else { "none" },
                        "max_session_secs": self.max_session_secs,
                        "confinement": "kata_vm",
                    },
                    "term_ms": self.term_hours.saturating_mul(3_600_000),
                }),
            )
            .await?;

        output::print_field(
            "Lease",
            result
                .get("lease_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        );
        output::print_field(
            "Key digest",
            result
                .get("service_key_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        );
        output::print_field("Authorized wallets", &self.wallets.join(", "));
        output::print_info(
            "Give the renter the service key. They also need a passkey enrolled on one of the \
             wallets above — the key alone opens nothing.",
        );
        Ok(())
    }
}

/// Revoke a lease.
#[derive(Debug, Parser)]
pub struct LeaseRevokeCmd {
    /// The lease to end.
    #[arg(long)]
    lease_id: String,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token.
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl LeaseRevokeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Revoke Access Lease");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        }

        let _: Value = rpc
            .call(
                "tenzro_revokeAccessLease",
                json!({ "lease_id": self.lease_id }),
            )
            .await?;

        output::print_success(&format!("Revoked {}", self.lease_id));
        output::print_info(
            "Every outstanding session grant against this lease died with it — one action, no \
             window.",
        );
        Ok(())
    }
}

/// List leases.
#[derive(Debug, Parser)]
pub struct LeaseListCmd {
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token.
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl LeaseListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Access Leases");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        }

        let result: Value = rpc.call("tenzro_listAccessLeases", json!({})).await?;
        let leases = result
            .get("leases")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if result
            .get("confinement")
            .map(Value::is_null)
            .unwrap_or(true)
        {
            // Worth saying loudly: without a boundary every session is
            // refused, so leases that look fine open nothing.
            output::print_warning(
                "No confinement backend is configured on this node (TENZRO_CONFINEMENT_LAUNCHER \
                 unset) — every interactive session is refused, whatever the leases below say.",
            );
        }

        if leases.is_empty() {
            output::print_info("No leases.");
            return Ok(());
        }

        for lease in &leases {
            let id = lease
                .get("lease_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let status = lease.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            let wallets = lease
                .get("authorized_wallets")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            output::print_field(id, &format!("{status}, {wallets} wallet(s)"));
        }
        Ok(())
    }
}
