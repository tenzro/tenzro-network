//! Passkey-first wallet onboarding + custody CLI surface.
//!
//! Maps `tenzro_*Passkey*` / `tenzro_*Keystore*` to user-friendly commands.
//! Examples:
//!
//! ```text
//! tenzro passkey login --display-name "My laptop"
//!
//! tenzro passkey keystore 0x...
//! tenzro passkey resolve <credential-id-hex>
//! tenzro passkey update update.json --key-namespace default
//! ```
//!
//! What an agent may spend is its Terms in consensus state (`tenzro agent`),
//! never a module one node holds.
//!
//! An account's passkeys, policy and recovery signers live in its keystore in
//! consensus state. Changing them is a `KeystoreUpdate` the account's devices
//! approve; `update` only sends one and pays its fee.
//!
//! The WebAuthn ceremony of `login` runs in the browser: it creates a pending
//! session on the node (`tenzro_createPasskeySession`), opens the node-served
//! `/auth/passkey` page, and polls `tenzro_getPasskeySession` until the
//! ceremony is terminal — the same device-login pattern as `gcloud auth
//! login`. The raw `enroll` subcommand remains for
//! callers that already hold ceremony outputs (Tauri desktop,
//! `sdk/tenzro-ts-sdk`).

use crate::output;
use crate::rpc::RpcClient;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::time::Duration;

fn default_rpc_url(override_url: Option<&str>) -> String {
    override_url
        .map(|s| s.to_string())
        .or_else(|| std::env::var("TENZRO_RPC_URL").ok())
        .unwrap_or_else(|| "https://rpc.tenzro.com".to_string())
}

#[derive(Debug, Subcommand)]
pub enum PasskeyCommand {
    /// Create a passkey account via the browser (gcloud-style login)
    Login(LoginCmd),
    /// Enroll a passkey-bound smart account from pre-acquired ceremony output
    Enroll(EnrollCmd),
    /// Show an account's keystore from consensus state
    Keystore(KeystoreCmd),
    /// Find the accounts whose keystore links a passkey credential id
    Resolve(ResolveCmd),
    /// Send a keystore change (link or unlink a passkey, policy, recovery
    /// signers, recovery) approved by the account's passkeys, paying its fee
    /// from this machine's client account
    Update(UpdateCmd),
}

impl PasskeyCommand {
    pub async fn execute(&self, rpc_url: Option<&str>) -> Result<()> {
        let url = default_rpc_url(rpc_url);
        let rpc = RpcClient::new(&url);
        match self {
            Self::Login(cmd) => cmd.execute(&rpc, &url).await,
            Self::Enroll(cmd) => cmd.execute(&rpc).await,
            Self::Keystore(cmd) => cmd.execute(&rpc).await,
            Self::Resolve(cmd) => cmd.execute(&rpc).await,
            Self::Update(cmd) => cmd.execute(&rpc).await,
        }
    }
}

/// A custody authorization given on the command line, as JSON.
fn authorization(text: &str) -> Result<Value> {
    serde_json::from_str::<Value>(text).context("--authorization is not valid JSON")
}

#[derive(Debug, Args)]
pub struct EnrollCmd {
    /// Raw or SEC1 P-256 public key hex
    #[arg(long)]
    pub passkey_pubkey_hex: String,
    /// Opaque credential ID returned by the platform authenticator
    #[arg(long)]
    pub credential_id_hex: String,
    /// The ML-DSA-65 verifying key of the hardware that holds the passkey,
    /// hex; the authorization carries its signature over the same challenge
    #[arg(long)]
    pub ml_dsa_public_key_hex: String,
    /// The registration's `authenticatorData`, hex, as
    /// `navigator.credentials.create()` returned it; required for a first
    /// wallet (salt 0)
    #[arg(long)]
    pub registration_authenticator_data_hex: Option<String>,
    /// The relying party the passkey is registered on (the wallet
    /// provider's domain); the node's own when omitted
    #[arg(long)]
    pub rp_id: Option<String>,
    /// Proof of possession (JSON), `{challenge_id, credential_id_hex,
    /// assertion, ml_dsa_signature_hex}` for an `enroll_passkey` custody
    /// challenge: the assertion signing its `webauthn_challenge` and the
    /// ML-DSA-65 key signing the same challenge
    #[arg(long)]
    pub authorization: Option<String>,
    /// Optional display name
    #[arg(long)]
    pub display_name: Option<String>,
    /// CREATE2 salt
    #[arg(long, default_value_t = 0)]
    pub salt: u64,
}

impl EnrollCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_enrollPasskey",
                json!({
                    "display_name": self.display_name,
                    "passkey_public_key_hex": self.passkey_pubkey_hex,
                    "credential_id_hex": self.credential_id_hex,
                    "ml_dsa_public_key_hex": self.ml_dsa_public_key_hex,
                    "authorization": self.authorization.as_deref().map(authorization).transpose()?,
                    "registration_authenticator_data_hex": self.registration_authenticator_data_hex,
                    "rp_id": self.rp_id,
                    "salt": self.salt,
                }),
            )
            .await?;
        println!("Passkey enrollment");
        output::print_field(
            "DID",
            result.get("did").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Smart Account",
            result
                .get("smart_account_address")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        );
        output::print_field(
            "Credential ID",
            result
                .get("credential_id_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        );
        output::print_field(
            "WebAuthn Validator",
            result
                .get("webauthn_validator_address")
                .and_then(|v| v.as_str())
                .unwrap_or("?"),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Browser-mediated ceremony flow (gcloud-style device login)
// ---------------------------------------------------------------------------

/// Resolve the web-API base URL that serves `/auth/passkey`. The web API
/// listens on a different host than JSON-RPC, so it is inferred from the
/// RPC host: any `rpc.<zone>` under the Tenzro network zone (`tenzro.com`)
/// maps to `api.<zone>` — the WebAuthn ceremony must be served from a real
/// domain because the passkey rpId is bound to it. New RPC subdomains under
/// that zone therefore work without `--web-url`.
///
/// No other domain is inferred: a host anywhere else needs `--web-url`, as
/// for any third party.
///
/// Local development is inferred to the loopback web port. Any other host
/// (a third-party operator's own domain) must pass `--web-url` explicitly —
/// and, in future, such operators will need to be trusted network operators
/// before their domain can host a ceremony.
pub(crate) fn derive_web_url(explicit: Option<&str>, rpc_url: &str) -> Result<String> {
    if let Some(url) = explicit {
        return Ok(url.trim_end_matches('/').to_string());
    }
    if rpc_url.contains("127.0.0.1") || rpc_url.contains("localhost") {
        return Ok("http://127.0.0.1:8080".to_string());
    }
    // Extract the host from the RPC URL (strip scheme, path, port).
    // `rsplit` rather than `split(..).next_back()`: `Split` is only
    // double-ended when its pattern is reversible, and a `&str` pattern is not,
    // so `next_back()` does not compile here.
    let host = rpc_url
        .rsplit("://")
        .next()
        .unwrap_or(rpc_url)
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    // `rpc.<zone>` -> `api.<zone>` for the Tenzro network zone. Only
    // `tenzro.com` is inferred by convention; any other domain is a
    // third-party host (pass `--web-url` explicitly).
    let zone = "tenzro.com";
    if host == format!("rpc.{zone}").as_str() || host.ends_with(&format!(".rpc.{zone}")) {
        return Ok(format!("https://api.{zone}"));
    }
    // A bare-zone or other `*.tenzro.com` RPC host still routes to the
    // zone's canonical api host.
    if host == zone || host.ends_with(&format!(".{zone}")) {
        return Ok(format!("https://api.{zone}"));
    }
    bail!(
        "cannot derive the browser-ceremony URL from RPC URL {rpc_url}; \
         it is not a *.tenzro.com host, so pass --web-url with \
         the node's web API base (default port 8080)"
    )
}

pub(crate) fn launch_browser(url: &str) {
    println!("Open this link in your browser to continue:");
    println!("  {url}");
    println!();
    #[cfg(target_os = "macos")]
    let opener = "open";
    #[cfg(not(target_os = "macos"))]
    let opener = "xdg-open";
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Poll `tenzro_getPasskeySession` until the session is terminal.
/// Returns the handler result on completion.
pub(crate) async fn poll_session(rpc: &RpcClient, session_id: &str) -> Result<Value> {
    println!("Waiting for the browser ceremony to complete (Ctrl-C to abort)…");
    loop {
        let session: Value = rpc
            .call(
                "tenzro_getPasskeySession",
                json!({ "session_id": session_id }),
            )
            .await?;
        match session.get("status").and_then(|v| v.as_str()).unwrap_or("") {
            "completed" => return Ok(session.get("result").cloned().unwrap_or(Value::Null)),
            "failed" => {
                let err = session
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown error");
                bail!("passkey ceremony failed: {err}");
            }
            "expired" => bail!(
                "passkey session expired before the ceremony completed — run the command again"
            ),
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
}

#[derive(Debug, Args)]
pub struct LoginCmd {
    /// Optional display name for the new identity
    #[arg(long)]
    pub display_name: Option<String>,
    /// CREATE2 salt
    #[arg(long, default_value_t = 0)]
    pub salt: u64,
    /// Web API base serving /auth/passkey (derived from the RPC URL when omitted)
    #[arg(long)]
    pub web_url: Option<String>,
}

impl LoginCmd {
    pub(crate) async fn execute(&self, rpc: &RpcClient, rpc_url: &str) -> Result<()> {
        let web_base = derive_web_url(self.web_url.as_deref(), rpc_url)?;
        let session: Value = rpc
            .call(
                "tenzro_createPasskeySession",
                json!({
                    "kind": "enroll",
                    "display_name": self.display_name,
                    "salt": self.salt,
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

        launch_browser(&format!("{web_base}{verification_path}"));
        let result = poll_session(rpc, &session_id).await?;

        let account = result
            .get("smart_account_address")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cred = result
            .get("credential_id_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!("Passkey account created");
        output::print_field(
            "DID",
            result.get("did").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Smart Account",
            if account.is_empty() { "?" } else { account },
        );
        output::print_field("Credential ID", if cred.is_empty() { "?" } else { cred });
        Ok(())
    }
}

/// One WebAuthn assertion as the authenticator returned it.
#[derive(Debug, clap::Args)]
pub(crate) struct AssertionArgs {
    /// `authenticatorData` bytes, hex
    #[arg(long)]
    authenticator_data_hex: String,
    /// File holding the exact `clientDataJSON` bytes; they are signed as
    /// returned and must not be re-serialized
    #[arg(long)]
    client_data_json: std::path::PathBuf,
    /// Assertion signature (DER or raw r||s), hex
    #[arg(long)]
    signature_hex: String,
}

impl AssertionArgs {
    pub(crate) fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        use anyhow::Context as _;
        let unhex = |name: &str, s: &str| {
            hex::decode(s.trim_start_matches("0x")).with_context(|| format!("--{name} is not hex"))
        };
        let client_data = std::fs::read(&self.client_data_json)
            .with_context(|| format!("cannot read {}", self.client_data_json.display()))?;
        Ok(serde_json::json!({
            "authenticator_data": unhex("authenticator-data-hex", &self.authenticator_data_hex)?,
            "client_data_json": client_data,
            "signature": unhex("signature-hex", &self.signature_hex)?,
            "user_handle": serde_json::Value::Null,
        }))
    }
}

/// An account's keystore from consensus state.
#[derive(Debug, Args)]
pub struct KeystoreCmd {
    /// The account, 20-byte hex
    pub account: String,
    /// For an account with no keystore on chain: its anchor (the JSON
    /// `tenzro_enrollPasskey` returned, or a file holding it)
    #[arg(long)]
    pub anchor: Option<String>,
}

impl KeystoreCmd {
    pub async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let mut params = json!({ "account": self.account });
        if let Some(anchor) = &self.anchor {
            let raw = std::fs::read_to_string(anchor).unwrap_or_else(|_| anchor.clone());
            params["anchor"] =
                serde_json::from_str(raw.trim()).map_err(|e| anyhow::anyhow!("anchor: {e}"))?;
        }
        let result: Value = rpc.call("tenzro_getKeystore", params).await?;
        crate::output::print_json(&result)
    }
}

/// The accounts whose keystore links a passkey.
#[derive(Debug, Args)]
pub struct ResolveCmd {
    /// The WebAuthn credential id, hex
    pub credential_id: String,
    /// The relying party the passkey is registered on (the wallet
    /// provider's domain)
    #[arg(long)]
    pub rp_id: String,
}

impl ResolveCmd {
    pub async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_resolveCredential",
                json!({ "credential_id": self.credential_id, "rp_id": self.rp_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Send a `KeystoreUpdate` whose approvals were made on the account's
/// devices. Any account may send it; this machine's client account pays the
/// fee and gains no authority over the account by doing so.
#[derive(Debug, Args)]
pub struct UpdateCmd {
    /// The update as JSON (chain_id, account, anchor, previous_commitment,
    /// op, approvals, possession), or a file holding it
    pub update: String,
    /// Key namespace of the client account that pays the fee
    #[arg(long, default_value = "default")]
    pub key_namespace: String,
}

impl UpdateCmd {
    pub async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let raw = std::fs::read_to_string(&self.update).unwrap_or_else(|_| self.update.clone());
        let update: tenzro_types::keystore::KeystoreUpdate =
            serde_json::from_str(raw.trim()).map_err(|e| anyhow::anyhow!("update: {e}"))?;
        update
            .validate()
            .map_err(|e| anyhow::anyhow!("update: {e}"))?;
        let chain: String = rpc.call("eth_chainId", json!([])).await?;
        let chain_id = u64::from_str_radix(chain.trim_start_matches("0x"), 16)
            .map_err(|e| anyhow::anyhow!("eth_chainId: {e}"))?;
        if update.chain_id != chain_id {
            anyhow::bail!(
                "the update was approved for chain {}, but the node runs chain {chain_id}",
                update.chain_id
            );
        }
        let result = crate::keystore::send_as_client(
            rpc,
            &self.key_namespace,
            [0u8; 32],
            json!({ "KeystoreUpdate": { "update": update } }),
            300_000,
        )
        .await?;
        crate::output::print_json(&result)
    }
}

#[cfg(test)]
mod web_url_tests {
    use super::derive_web_url;

    #[test]
    fn maps_the_tenzro_zone_by_convention() {
        assert_eq!(
            derive_web_url(None, "https://rpc.tenzro.com").unwrap(),
            "https://api.tenzro.com"
        );
        // Port and path are stripped from the host before matching.
        assert_eq!(
            derive_web_url(None, "https://rpc.tenzro.com:8545/rpc").unwrap(),
            "https://api.tenzro.com"
        );
        // Any other subdomain under the Tenzro zone routes to that zone's api host.
        assert_eq!(
            derive_web_url(None, "https://node7.tenzro.com").unwrap(),
            "https://api.tenzro.com"
        );
    }

    #[test]
    fn another_domain_is_not_inferred_and_needs_explicit_web_url() {
        // A host outside the network's zone is treated like any third party.
        assert!(derive_web_url(None, "https://rpc.example.org").is_err());
    }

    #[test]
    fn loopback_maps_to_local_web_port() {
        assert_eq!(
            derive_web_url(None, "http://127.0.0.1:8545").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            derive_web_url(None, "http://localhost:8545").unwrap(),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn explicit_web_url_wins_and_is_trimmed() {
        assert_eq!(
            derive_web_url(Some("https://my.host/"), "https://rpc.tenzro.com").unwrap(),
            "https://my.host"
        );
    }

    #[test]
    fn third_party_host_requires_explicit_web_url() {
        assert!(derive_web_url(None, "https://rpc.example.com").is_err());
    }
}
