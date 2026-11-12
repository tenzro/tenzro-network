//! Auth commands: refresh access tokens and link an existing wallet to
//! a new auth session.
//!
//! Onboarding (humans, delegated agents, autonomous agents) goes through
//! `tenzro join` (one-call provisioning) or the dedicated SDK/RPC entry
//! points; once the holder has a refresh token or a wallet, the two
//! sub-commands here let them keep auth current without re-onboarding.
//!
//! Tokens are persisted to `~/.tenzro/config.json` (`access_token`,
//! `refresh_token`, `access_token_expires_at`, `dpop_bound`) so subsequent
//! CLI calls can pick them up automatically.

use crate::config;
use crate::output;
use crate::rpc::RpcClient;
use anyhow::{Context as _, Result, anyhow};
use clap::{Parser, Subcommand};

/// OAuth 2.1 + DPoP auth management
#[derive(Debug, Parser)]
pub struct AuthCommand {
    #[command(subcommand)]
    pub action: AuthAction,
}

#[derive(Debug, Subcommand)]
pub enum AuthAction {
    #[command(flatten)]
    Rpc(AuthRpcAction),
    /// Exchange a refresh token for a fresh access token.
    Refresh(RefreshArgs),
    /// Show this machine's DPoP key, creating one on first use.
    ///
    /// Prints the RFC 7638 thumbprint (`jkt`) that `--dpop-jkt` wants: bind a
    /// token to it once, and every later CLI call signs its own proof.
    DpopKey,
    /// Sign a one-off DPoP proof for a request.
    ///
    /// Ordinary CLI calls mint their own, so this is for driving the node from
    /// curl or a script — anywhere the proof has to be produced by hand.
    DpopProof(DpopProofArgs),
}

#[derive(Debug, Parser)]
pub struct DpopProofArgs {
    /// HTTP method the proof authorises. Bound into the proof, so it must
    /// match the request.
    #[arg(long, default_value = "POST")]
    pub method: String,

    /// Target URL. Query and fragment are stripped, matching what the node
    /// compares against.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub url: String,

    /// Access token this proof is presented with. Hashed into `ath`, which the
    /// node requires on access-token requests. Falls back to
    /// `TENZRO_BEARER_JWT`.
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Debug, Parser)]
pub struct RefreshArgs {
    /// RPC endpoint
    #[arg(long, default_value = "https://rpc.tenzro.com")]
    pub rpc: String,

    /// Refresh token. If omitted, reads from `~/.tenzro/config.json`.
    #[arg(long)]
    pub refresh_token: Option<String>,
}

impl AuthCommand {
    pub async fn execute(&self) -> Result<()> {
        match &self.action {
            AuthAction::Rpc(cmd) => cmd.execute().await,
            AuthAction::Refresh(args) => execute_refresh(args).await,
            AuthAction::DpopKey => execute_dpop_key(),
            AuthAction::DpopProof(args) => execute_dpop_proof(args),
        }
    }
}

async fn execute_refresh(args: &RefreshArgs) -> Result<()> {
    output::print_header("Refresh Access Token");

    let mut cfg = config::load_config();

    let token = match &args.refresh_token {
        Some(t) => t.clone(),
        None => cfg.refresh_token.clone().ok_or_else(|| {
            anyhow!(
                "no refresh token provided and none stored in config; \
                 supply --refresh-token <value> or onboard first"
            )
        })?,
    };

    // The refresh token is bound to this machine's DPoP key (or is bound to
    // it by this exchange), proven with a proof that accompanies no access
    // token.
    let spinner = output::create_spinner("Exchanging refresh token...");
    let rpc = RpcClient::new(&args.rpc);
    let result: serde_json::Value = rpc
        .call_with_proof(
            "tenzro_refreshToken",
            serde_json::json!({ "refresh_token": token }),
        )
        .await
        .map_err(|e| anyhow!("refresh failed: {}", e))?;
    spinner.finish_and_clear();

    let access_token = result
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("response missing access_token"))?
        .to_string();
    let expires_in = result
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);
    let dpop_bound = result
        .get("dpop_bound")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let next_refresh = result
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("response missing refresh_token"))?
        .to_string();
    cfg.refresh_token = Some(next_refresh);
    cfg.access_token = Some(access_token.clone());
    cfg.access_token_expires_at = Some(now + expires_in);
    cfg.access_token_rpc = Some(args.rpc.clone());
    cfg.dpop_bound = Some(dpop_bound);
    config::save_config(&cfg)?;

    output::print_success("Access token refreshed");
    output::print_field(
        "Token type",
        result
            .get("token_type")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
    output::print_field("Expires in", &format!("{} seconds", expires_in));
    output::print_field("DPoP-bound", &dpop_bound.to_string());
    output::print_field(
        "Token (truncated)",
        &format!("{}...", &access_token[..access_token.len().min(32)]),
    );
    output::print_field("Saved to", &config::config_path().display().to_string());
    Ok(())
}

/// Show the DPoP key this machine signs proofs with.
///
/// The key is created in, and never leaves, this machine's TPM or Secure
/// Enclave, so there is no path to print.
fn execute_dpop_key() -> Result<()> {
    let key = crate::dpop::DpopKey::load_or_create()?;
    output::print_success("DPoP key ready");
    output::print_field("Source", "held by this machine's TPM or Secure Enclave");
    output::print_field("JWK", &key.jwk()?);
    output::print_field("Thumbprint (jkt)", &key.jkt()?);
    output::print_info(
        "Bind a token to it, then every CLI call signs its own proof:\n  \
         tenzro auth link-wallet --dpop-jkt <jkt>\n  \
         tenzro auth refresh",
    );
    Ok(())
}

/// Sign one proof, for driving the node outside this CLI.
fn execute_dpop_proof(args: &DpopProofArgs) -> Result<()> {
    let key = crate::dpop::DpopKey::load_or_create()?;
    let token = args
        .token
        .clone()
        .or_else(|| std::env::var("TENZRO_BEARER_JWT").ok())
        .filter(|t| !t.is_empty());
    if token.is_none() {
        // Not fatal — a /token request legitimately has no access token to
        // bind to — but on any other call the node will refuse a proof with
        // no `ath`, and that refusal is confusing after the fact.
        output::print_info(
            "No access token given, so the proof carries no `ath`. That is right \
             for a token request and wrong for anything else.",
        );
    }
    let proof = key.proof(&args.method, &args.url, token.as_deref())?;
    println!("{proof}");
    Ok(())
}

/// Auth commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum AuthRpcAction {
    /// Call tenzro_exchangeToken (exchange token) and print the node's answer
    ExchangeToken(AuthExchangeTokenRpcCmd),
    /// Call tenzro_introspectToken (introspect token) and print the node's answer
    Introspect(AuthIntrospectRpcCmd),
    /// Call tenzro_oauthDiscovery (oauth discovery) and print the node's answer
    Discovery(AuthDiscoveryRpcCmd),
    /// Call tenzro_onboardAutonomousAgent (onboard autonomous agent) and print the node's answer
    OnboardAgent(AuthOnboardAgentRpcCmd),
    /// Call tenzro_onboardHuman (onboard human) and print the node's answer
    OnboardHuman(AuthOnboardHumanRpcCmd),
}

impl AuthRpcAction {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::ExchangeToken(cmd) => cmd.execute().await,
            Self::Introspect(cmd) => cmd.execute().await,
            Self::Discovery(cmd) => cmd.execute().await,
            Self::OnboardAgent(cmd) => cmd.execute().await,
            Self::OnboardHuman(cmd) => cmd.execute().await,
        }
    }
}

/// Exchange a parent token for a narrower child token (tenzro_exchangeToken)
#[derive(Debug, clap::Parser)]
pub struct AuthExchangeTokenRpcCmd {
    /// The parent access token
    #[arg(long)]
    subject_token: String,
    /// DID the child token is issued to
    #[arg(long)]
    child_bearer_did: String,
    /// JWK thumbprint of the child holder's key; the child token is DPoP-bound to it
    #[arg(long)]
    child_dpop_jkt: String,
    /// File holding the child's `authorization_details` array, a subset of the parent's
    #[arg(long)]
    requested_rar: std::path::PathBuf,
    /// A capability the child carries, a subset of the parent's (repeatable)
    #[arg(long = "capability")]
    requested_aap_capabilities: Vec<String>,
    /// Child lifetime in seconds, clamped to the parent's remaining lifetime
    #[arg(long)]
    requested_ttl_secs: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AuthExchangeTokenRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rar_raw = std::fs::read(&self.requested_rar)
            .with_context(|| format!("cannot read {}", self.requested_rar.display()))?;
        let requested_rar: serde_json::Value = serde_json::from_slice(&rar_raw)
            .context("--requested-rar must hold an authorization_details array")?;
        anyhow::ensure!(
            requested_rar.is_array(),
            "--requested-rar must hold an authorization_details array"
        );
        let params = serde_json::json!({
            "subject_token": self.subject_token,
            "child_bearer_did": self.child_bearer_did,
            "child_dpop_jkt": self.child_dpop_jkt,
            "requested_rar": requested_rar,
            "requested_aap_capabilities": self.requested_aap_capabilities,
            "requested_ttl_secs": self.requested_ttl_secs,
        });
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_exchangeToken", params).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_introspectToken (introspect token)
#[derive(Debug, clap::Parser)]
pub struct AuthIntrospectRpcCmd {
    /// token
    #[arg(long)]
    token: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AuthIntrospectRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_introspectToken",
                serde_json::json!({ "token": self.token }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_oauthDiscovery (oauth discovery)
#[derive(Debug, clap::Parser)]
pub struct AuthDiscoveryRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AuthDiscoveryRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_oauthDiscovery", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Onboard an autonomous agent against its posted bond (tenzro_onboardAutonomousAgent)
#[derive(Debug, clap::Parser)]
pub struct AuthOnboardAgentRpcCmd {
    /// The agent's device public key (hex), held by its secure element; its
    /// DID derives from it, and its bond is posted on chain for that DID
    #[arg(long)]
    device_public_key: String,
    /// Identifier of the secure element that holds the device key
    #[arg(long)]
    machine_id: String,
    /// JWK thumbprint to DPoP-bind the issued token to
    #[arg(long)]
    dpop_jkt: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AuthOnboardAgentRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let mut params = serde_json::json!({
            "device_public_key": self.device_public_key,
            "machine_id": self.machine_id,
        });
        if let Some(jkt) = &self.dpop_jkt {
            params["dpop_jkt"] = serde_json::Value::String(jkt.clone());
        }
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_onboardAutonomousAgent", params).await?;
        crate::output::print_json(&result)
    }
}

/// Onboard a human identity from its passkey enrolment (tenzro_onboardHuman)
#[derive(Debug, clap::Parser)]
pub struct AuthOnboardHumanRpcCmd {
    /// Display name
    #[arg(long)]
    display_name: String,
    /// Passkey credential id, hex
    #[arg(long)]
    credential_id_hex: String,
    /// Passkey P-256 public key (raw x||y), hex
    #[arg(long)]
    public_key_hex: String,
    /// ML-DSA-65 verifying key, hex
    #[arg(long)]
    ml_dsa_public_key_hex: String,
    /// Custody challenge id (tenzro_createCustodyChallenge, operation `enroll_passkey`)
    #[arg(long)]
    challenge_id: String,
    /// The passkey's assertion over the challenge
    #[command(flatten)]
    assertion: crate::commands::passkey::AssertionArgs,
    /// ML-DSA-65 signature over the challenge, hex
    #[arg(long)]
    ml_dsa_signature_hex: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AuthOnboardHumanRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params = serde_json::json!({
            "display_name": self.display_name,
            "credential_id": self.credential_id_hex,
            "public_key": self.public_key_hex,
            "ml_dsa_public_key_hex": self.ml_dsa_public_key_hex,
            "authorization": {
                "challenge_id": self.challenge_id,
                "credential_id_hex": self.credential_id_hex,
                "assertion": self.assertion.to_json()?,
                "ml_dsa_signature_hex": self.ml_dsa_signature_hex,
            },
        });
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_onboardHuman", params).await?;
        crate::output::print_json(&result)
    }
}
