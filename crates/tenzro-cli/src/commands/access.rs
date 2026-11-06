//! Node access: sign in for an access token, and administer who may use a
//! node.
//!
//! `sign-in` answers the node's challenge with this machine's hardware key
//! and stores the DPoP-bound access token it returns, so later commands
//! present it on their own. The policy and token commands are for the node's
//! operator and the administrators its policy names; the node refuses anyone
//! else.

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use crate::output;
use crate::rpc::RpcClient;

/// Sign in to a node, and administer its access policy.
#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Sign in with this machine's hardware key and store the access token.
    SignIn(SignInCmd),
    /// The access policy in force, as `access.toml`.
    Show(RpcArg),
    /// Replace the access policy with a TOML file.
    Set(SetCmd),
    /// What the policy decides for a caller, without serving anything.
    Preview(PreviewCmd),
    /// The live access tokens the node issued.
    Tokens(RpcArg),
    /// Withdraw one access token, or every live token of a DID.
    Revoke(RevokeCmd),
    /// The node's administrative audit log: who called which administrative
    /// method, from where, with which credential, and what came of it.
    Audit(AuditCmd),
    /// Check the administrative audit log's chain and signed checkpoints.
    AuditVerify(RpcArg),
}

impl AccessCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::SignIn(c) => c.execute().await,
            Self::Show(c) => show(c).await,
            Self::Set(c) => c.execute().await,
            Self::Preview(c) => c.execute().await,
            Self::Tokens(c) => tokens(c).await,
            Self::Revoke(c) => c.execute().await,
            Self::Audit(c) => c.execute().await,
            Self::AuditVerify(c) => audit_verify(c).await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct RpcArg {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

#[derive(Debug, Parser)]
pub struct SignInCmd {
    /// Hardware key to sign in with, by label. The default is this machine's
    /// identity key, which signs in as its machine DID.
    #[arg(long, default_value = tenzro_types::did_derivation::MACHINE_KEY_LABEL)]
    key_label: String,
    /// Hardware key namespace the key lives under: a node's
    /// `hardware_key_namespace`, to sign in as that node's identity rather
    /// than the machine's default one. The DPoP key stays this client's own.
    #[arg(long)]
    key_namespace: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SignInCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Sign In");
        // The DPoP key is opened before the namespace is set, so the token
        // binds the client key every later request proves with.
        let jkt = crate::dpop::DpopKey::load_or_create()?.jkt()?;
        if let Some(namespace) = &self.key_namespace {
            tenzro_device_key::set_label_namespace(namespace)
                .map_err(|e| anyhow!("--key-namespace: {e}"))?;
        }
        let key = tenzro_device_key::signer::open_or_create(&self.key_label)
            .map_err(|e| anyhow!("hardware key {}: {e}", self.key_label))?;
        let public_key = key
            .public_key_sec1()
            .map_err(|e| anyhow!("hardware key: {e}"))?;
        let did = tenzro_types::did_derivation::machine_did(&public_key);

        let rpc = RpcClient::new(&self.rpc);
        let challenge: Value = rpc
            .call(
                "tenzro_accessChallenge",
                json!({ "did": did, "dpop_jkt": jkt }),
            )
            .await
            .context("asking for a sign-in challenge")?;
        let digest_hex = challenge["device_digest"]
            .as_str()
            .ok_or_else(|| anyhow!("no device_digest"))?;
        let digest = hex::decode(digest_hex).context("device_digest is not hex")?;
        let signature = key
            .sign(&digest)
            .map_err(|e| anyhow!("signing the challenge: {e}"))?;

        let issued: Value = rpc
            .call(
                "tenzro_issueAccessToken",
                json!({
                    "challenge_id": challenge["challenge_id"],
                    "proof": {
                        "kind": "device",
                        "public_key": hex::encode(public_key),
                        "signature": hex::encode(signature),
                    },
                }),
            )
            .await
            .context("answering the sign-in challenge")?;
        let token = issued["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("no access_token"))?;
        let expires_in = issued["expires_in"].as_u64().unwrap_or(0);

        let mut cfg = crate::config::load_config();
        cfg.access_token = Some(token.to_string());
        cfg.access_token_expires_at = Some(chrono::Utc::now().timestamp() as u64 + expires_in);
        cfg.access_token_rpc = Some(self.rpc.clone());
        crate::config::save_config(&cfg)?;

        output::print_field("DID", &did);
        output::print_field("Expires in", &format!("{expires_in}s"));
        output::print_json(&issued["classes"])
    }
}

async fn show(arg: &RpcArg) -> Result<()> {
    let result: Value = RpcClient::new(&arg.rpc)
        .call("tenzro_getAccessPolicy", json!({}))
        .await?;
    print!("{}", result["toml"].as_str().unwrap_or_default());
    Ok(())
}

#[derive(Debug, Parser)]
pub struct SetCmd {
    /// The new `access.toml`
    file: std::path::PathBuf,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SetCmd {
    pub async fn execute(&self) -> Result<()> {
        let text = std::fs::read_to_string(&self.file)
            .with_context(|| format!("reading {}", self.file.display()))?;
        let result: Value = RpcClient::new(&self.rpc)
            .call("tenzro_setAccessPolicy", json!({ "toml": text }))
            .await?;
        output::print_success(&format!(
            "Access policy version {} in force",
            result["version"]
        ));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PreviewCmd {
    /// rpc, mcp, a2a, openai, files, web or iroh
    #[arg(long)]
    surface: String,
    /// A JSON-RPC method name
    #[arg(long, conflicts_with = "class", required_unless_present = "class")]
    method: Option<String>,
    /// A method class
    #[arg(long)]
    class: Option<String>,
    /// The caller's DID; omit for an anonymous caller
    #[arg(long)]
    did: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PreviewCmd {
    pub async fn execute(&self) -> Result<()> {
        let mut params = json!({ "surface": self.surface });
        if let Some(m) = &self.method {
            params["method"] = json!(m);
        }
        if let Some(c) = &self.class {
            params["class"] = json!(c);
        }
        if let Some(d) = &self.did {
            params["did"] = json!(d);
        }
        let result: Value = RpcClient::new(&self.rpc)
            .call("tenzro_previewAccess", params)
            .await?;
        output::print_json(&result)
    }
}

async fn tokens(arg: &RpcArg) -> Result<()> {
    let result: Value = RpcClient::new(&arg.rpc)
        .call("tenzro_listAccessTokens", json!({}))
        .await?;
    output::print_json(&result["tokens"])
}

#[derive(Debug, Parser)]
pub struct RevokeCmd {
    /// The token id
    #[arg(long, conflicts_with = "did", required_unless_present = "did")]
    jti: Option<String>,
    /// Withdraw every live token of this DID
    #[arg(long)]
    did: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RevokeCmd {
    pub async fn execute(&self) -> Result<()> {
        let params = match (&self.jti, &self.did) {
            (Some(jti), None) => json!({ "jti": jti }),
            (None, Some(did)) => json!({ "did": did }),
            _ => return Err(anyhow!("give exactly one of --jti or --did")),
        };
        let result: Value = RpcClient::new(&self.rpc)
            .call("tenzro_revokeAccessToken", params)
            .await?;
        output::print_json(&result["revoked"])
    }
}

#[derive(Debug, Parser)]
pub struct AuditCmd {
    /// Only calls to this method
    #[arg(long)]
    method: Option<String>,
    /// Only calls by this DID
    #[arg(long)]
    principal: Option<String>,
    /// Only records at or after this time (RFC 3339)
    #[arg(long)]
    since: Option<String>,
    /// Only records before this time (RFC 3339)
    #[arg(long)]
    until: Option<String>,
    /// At most this many records, the most recent
    #[arg(long, default_value_t = 100)]
    limit: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AuditCmd {
    pub async fn execute(&self) -> Result<()> {
        let mut params = json!({ "limit": self.limit });
        for (key, value) in [
            ("method", &self.method),
            ("principal", &self.principal),
            ("since", &self.since),
            ("until", &self.until),
        ] {
            if let Some(v) = value {
                params[key] = json!(v);
            }
        }
        let result: Value = RpcClient::new(&self.rpc)
            .call("tenzro_listAdminAudit", params)
            .await?;
        output::print_json(&result["records"])
    }
}

async fn audit_verify(arg: &RpcArg) -> Result<()> {
    let result: Value = RpcClient::new(&arg.rpc)
        .call("tenzro_verifyAdminAudit", json!({}))
        .await?;
    output::print_json(&result)?;
    if result["ok"].as_bool() != Some(true) {
        return Err(anyhow!("the administrative audit log does not verify"));
    }
    Ok(())
}
