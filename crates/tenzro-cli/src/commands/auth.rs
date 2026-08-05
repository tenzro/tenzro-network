//! Auth commands: refresh access tokens and link an existing MPC wallet to
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
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};

/// OAuth 2.1 + DPoP auth management
#[derive(Debug, Parser)]
pub struct AuthCommand {
    #[command(subcommand)]
    pub action: AuthAction,
}

#[derive(Debug, Subcommand)]
pub enum AuthAction {
    /// Exchange a refresh token for a fresh access token.
    Refresh(RefreshArgs),
    /// Mint access + refresh tokens for an existing MPC wallet.
    LinkWallet(LinkWalletArgs),
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
    #[arg(long, default_value = "https://rpc.tenzro.xyz")]
    pub rpc: String,

    /// Refresh token. If omitted, reads from `~/.tenzro/config.json`.
    #[arg(long)]
    pub refresh_token: Option<String>,

    /// Optional RFC 7638 SHA-256 thumbprint of a client-held P-256/Ed25519
    /// public key. Binds the new access token to that key (DPoP).
    #[arg(long)]
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Parser)]
pub struct LinkWalletArgs {
    /// RPC endpoint
    #[arg(long, default_value = "https://rpc.tenzro.xyz")]
    pub rpc: String,

    /// Wallet ID to link (the `wallet_id` returned by `tenzro_createWallet`).
    /// If omitted, reads from `~/.tenzro/config.json`.
    #[arg(long)]
    pub wallet_id: Option<String>,

    /// Optional RFC 7638 SHA-256 thumbprint to DPoP-bind the issued token.
    #[arg(long)]
    pub dpop_jkt: Option<String>,

    /// Optional human-readable label surfaced in approver UIs.
    #[arg(long)]
    pub display_name: Option<String>,

    /// Optional access-token TTL override (seconds). Server-side caps apply.
    #[arg(long)]
    pub ttl_secs: Option<u64>,
}

impl AuthCommand {
    pub async fn execute(&self) -> Result<()> {
        match &self.action {
            AuthAction::Refresh(args) => execute_refresh(args).await,
            AuthAction::LinkWallet(args) => execute_link_wallet(args).await,
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

    let mut params = serde_json::json!({ "refresh_token": token });
    if let Some(jkt) = &args.dpop_jkt {
        params["dpop_jkt"] = serde_json::Value::String(jkt.clone());
    }

    let spinner = output::create_spinner("Exchanging refresh token...");
    let rpc = RpcClient::new(&args.rpc);
    let result: serde_json::Value = rpc
        .call("tenzro_refreshToken", serde_json::json!([params]))
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
    cfg.access_token = Some(access_token.clone());
    cfg.access_token_expires_at = Some(now + expires_in);
    cfg.dpop_bound = Some(dpop_bound);
    config::save_config(&cfg)?;

    output::print_success("Access token refreshed");
    output::print_field("Token type", "Bearer");
    output::print_field("Expires in", &format!("{} seconds", expires_in));
    output::print_field("DPoP-bound", &dpop_bound.to_string());
    output::print_field(
        "Token (truncated)",
        &format!("{}...", &access_token[..access_token.len().min(32)]),
    );
    output::print_field("Saved to", &config::config_path().display().to_string());
    Ok(())
}

async fn execute_link_wallet(args: &LinkWalletArgs) -> Result<()> {
    output::print_header("Link Wallet for Auth");

    let mut cfg = config::load_config();

    let wallet_id = match &args.wallet_id {
        Some(w) => w.clone(),
        None => cfg.wallet_id.clone().ok_or_else(|| {
            anyhow!(
                "no wallet id provided and none stored in config; \
                 supply --wallet-id <id> or run `tenzro wallet create` first"
            )
        })?,
    };

    let mut params = serde_json::json!({ "wallet_id": wallet_id });
    if let Some(jkt) = &args.dpop_jkt {
        params["dpop_jkt"] = serde_json::Value::String(jkt.clone());
    }
    if let Some(name) = &args.display_name {
        params["display_name"] = serde_json::Value::String(name.clone());
    }
    if let Some(ttl) = args.ttl_secs {
        params["ttl_secs"] = serde_json::Value::Number(ttl.into());
    }

    let spinner = output::create_spinner("Minting auth session for wallet...");
    let rpc = RpcClient::new(&args.rpc);
    let result: serde_json::Value = rpc
        .call("tenzro_linkWalletForAuth", serde_json::json!([params]))
        .await
        .map_err(|e| anyhow!("link wallet failed: {}", e))?;
    spinner.finish_and_clear();

    let access_token = result
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("response missing access_token"))?
        .to_string();
    let refresh_token = result
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
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
    cfg.access_token = Some(access_token.clone());
    cfg.access_token_expires_at = Some(now + expires_in);
    cfg.dpop_bound = Some(dpop_bound);
    if let Some(rt) = &refresh_token {
        cfg.refresh_token = Some(rt.clone());
    }
    if let Some(did) = result
        .get("identity")
        .and_then(|v| v.get("did"))
        .and_then(|v| v.as_str())
    {
        cfg.did = Some(did.to_string());
    }
    config::save_config(&cfg)?;

    output::print_success("Wallet linked to auth session");
    output::print_field("Wallet", &wallet_id);
    output::print_field("Token type", "Bearer");
    output::print_field("Expires in", &format!("{} seconds", expires_in));
    output::print_field("DPoP-bound", &dpop_bound.to_string());
    if refresh_token.is_some() {
        output::print_field("Refresh token", "stored in config");
    }
    output::print_field("Saved to", &config::config_path().display().to_string());

    output::print_info(
        "Use this access token via `Authorization: Bearer <token>` for privileged RPC calls. \
         When it expires (default 1h), run `tenzro auth refresh` to mint a new one.",
    );
    Ok(())
}

/// Show (creating on first use) the DPoP key this machine signs proofs with.
fn execute_dpop_key() -> Result<()> {
    let key = crate::dpop::DpopKey::load_or_create()?;
    output::print_success("DPoP key ready");
    output::print_field("Path", &crate::dpop::key_path().display().to_string());
    output::print_field("JWK", &key.jwk());
    output::print_field("Thumbprint (jkt)", &key.jkt());
    output::print_info(
        "Bind a token to it, then every CLI call signs its own proof:\n  \
         tenzro auth link-wallet --dpop-jkt <jkt>\n  \
         tenzro auth refresh --dpop-jkt <jkt>",
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
