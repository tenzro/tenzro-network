//! Passkey-first wallet onboarding + custody CLI surface.
//!
//! Maps `tenzro_*Passkey*` / `tenzro_*Recovery*` / `tenzro_*SessionKey*` /
//! `tenzro_*HardwareSigner*` / `tenzro_*SmartAccount*` to user-friendly
//! commands. Examples:
//!
//! ```text
//! tenzro passkey login --display-name "My laptop"
//!
//! tenzro passkey add --account-address 0x... --label "My phone"
//!
//! tenzro passkey sign \
//!     --account-address 0x... \
//!     --op-hash-hex 0x... \
//!     --ml-dsa-seed-file ~/.tenzro/passkey/<account>-<cred>.mldsa.seed
//!
//! tenzro passkey enroll \
//!     --passkey-pubkey-hex 0x... \
//!     --credential-id-hex 0x... \
//!     --ml-dsa-pubkey-hex 0x... \
//!     --display-name "My iPhone"
//!
//! tenzro passkey list-accounts
//!
//! tenzro passkey add-guardian \
//!     --account-address 0x... \
//!     --guardian-ed25519-hex 0x... \
//!     --guardian-ml-dsa-hex 0x... \
//!     --threshold 2
//!
//! tenzro passkey initiate-recovery \
//!     --account-address 0x... \
//!     --new-passkey-pubkey-hex 0x... \
//!     --new-credential-id-hex 0x... \
//!     --new-ml-dsa-pubkey-hex 0x...
//!
//! tenzro passkey grant-session-key \
//!     --account-address 0x... \
//!     --session-pubkey-hex 0x... \
//!     --selectors a9059cbb,095ea7b3 \
//!     --max-per-call 1000000000000000000 \
//!     --valid-until 1735689600
//!
//! tenzro passkey add-hardware-signer \
//!     --account-address 0x... \
//!     --device-kind ledger \
//!     --public-key-hex 0x... \
//!     --required-always
//! ```
//!
//! WebAuthn ceremonies run in the browser: `login` / `add` / `sign`
//! create a pending session on the node (`tenzro_createPasskeySession`),
//! open the node-served `/auth/passkey` page, and poll
//! `tenzro_getPasskeySession` until the ceremony is terminal — the same
//! device-login pattern as `gcloud auth login`. The ML-DSA-65 hybrid PQ
//! leg is generated CLI-side and its seed stored under
//! `~/.tenzro/passkey/` (mode 0600); the browser never sees
//! post-quantum key material. The raw `enroll` subcommand remains for
//! callers that already hold ceremony outputs (Tauri desktop,
//! `sdk/tenzro-ts-sdk`).

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use crate::output;
use crate::rpc::RpcClient;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tenzro_crypto::pq::MlDsaSigningKey;

fn default_rpc_url(override_url: Option<&str>) -> String {
    override_url
        .map(|s| s.to_string())
        .or_else(|| std::env::var("TENZRO_RPC_URL").ok())
        .unwrap_or_else(|| "https://rpc.tenzro.xyz".to_string())
}

#[derive(Debug, Subcommand)]
pub enum PasskeyCommand {
    /// Create a passkey account via the browser (gcloud-style login)
    Login(LoginCmd),
    /// Add a passkey to an existing account via the browser
    Add(AddCmd),
    /// List enrolled passkey credentials on an account
    List(ListCmd),
    /// Remove a passkey credential from an account
    Remove(RemoveCmd),
    /// Set the account's second-factor policy (single_credential | two_credentials)
    SetPolicy(SetPolicyCmd),
    /// Show the account's second-factor policy
    GetPolicy(GetPolicyCmd),
    /// Approve an operation hash with a passkey via the browser
    Sign(SignCmd),
    /// Enroll a passkey-bound smart account from pre-acquired ceremony output
    Enroll(EnrollCmd),
    /// Add a social-recovery guardian
    AddGuardian(AddGuardianCmd),
    /// Initiate a social-recovery ceremony (new passkey rotation)
    InitiateRecovery(InitiateRecoveryCmd),
    /// Submit one guardian's signature against an in-flight recovery
    SubmitRecoverySignature(SubmitRecoverySignatureCmd),
    /// Finalize a recovery once quorum is reached
    FinalizeRecovery(FinalizeRecoveryCmd),
    /// Grant a scoped session key
    GrantSessionKey(GrantSessionKeyCmd),
    /// Revoke the session-key config from a smart account
    RevokeSessionKey(RevokeSessionKeyCmd),
    /// Set a smart account's per-tx + daily spending caps
    SetSpendingLimit(SetSpendingLimitCmd),
    /// Add a hardware signer (Ledger / Trezor / GridPlus / YubiKey)
    AddHardwareSigner(AddHardwareSignerCmd),
    /// Fetch a smart account's installed validators
    GetSmartAccount(GetSmartAccountCmd),
    /// List every smart account known to the node
    ListSmartAccounts,
    /// List in-flight recoveries for an account
    ListPendingRecoveries(ListPendingRecoveriesCmd),
}

impl PasskeyCommand {
    pub async fn execute(&self, rpc_url: Option<&str>) -> Result<()> {
        let url = default_rpc_url(rpc_url);
        let rpc = RpcClient::new(&url);
        match self {
            Self::Login(cmd) => cmd.execute(&rpc, &url).await,
            Self::Add(cmd) => cmd.execute(&rpc, &url).await,
            Self::List(cmd) => cmd.execute(&rpc).await,
            Self::Remove(cmd) => cmd.execute(&rpc).await,
            Self::SetPolicy(cmd) => cmd.execute(&rpc).await,
            Self::GetPolicy(cmd) => cmd.execute(&rpc).await,
            Self::Sign(cmd) => cmd.execute(&rpc, &url).await,
            Self::Enroll(cmd) => cmd.execute(&rpc).await,
            Self::AddGuardian(cmd) => cmd.execute(&rpc).await,
            Self::InitiateRecovery(cmd) => cmd.execute(&rpc).await,
            Self::SubmitRecoverySignature(cmd) => cmd.execute(&rpc).await,
            Self::FinalizeRecovery(cmd) => cmd.execute(&rpc).await,
            Self::GrantSessionKey(cmd) => cmd.execute(&rpc).await,
            Self::RevokeSessionKey(cmd) => cmd.execute(&rpc).await,
            Self::SetSpendingLimit(cmd) => cmd.execute(&rpc).await,
            Self::AddHardwareSigner(cmd) => cmd.execute(&rpc).await,
            Self::GetSmartAccount(cmd) => cmd.execute(&rpc).await,
            Self::ListSmartAccounts => list_smart_accounts(&rpc).await,
            Self::ListPendingRecoveries(cmd) => cmd.execute(&rpc).await,
        }
    }
}

#[derive(Debug, Args)]
pub struct EnrollCmd {
    /// Raw or SEC1 P-256 public key hex
    #[arg(long)]
    pub passkey_pubkey_hex: String,
    /// Opaque credential ID returned by the platform authenticator
    #[arg(long)]
    pub credential_id_hex: String,
    /// ML-DSA-65 verifying key (1952 bytes) for the hybrid PQ leg
    #[arg(long)]
    pub ml_dsa_pubkey_hex: String,
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
                    "ml_dsa_public_key_hex": self.ml_dsa_pubkey_hex,
                    "salt": self.salt,
                }),
            )
            .await?;
        println!("Passkey enrollment");
        output::print_field("DID", result.get("did").and_then(|v| v.as_str()).unwrap_or("?"));
        output::print_field(
            "Smart Account",
            result.get("smart_account_address").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Credential ID",
            result.get("credential_id_hex").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "WebAuthn Validator",
            result.get("webauthn_validator_address").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct AddGuardianCmd {
    #[arg(long)]
    pub account_address: String,
    /// 32-byte Ed25519 guardian pubkey hex
    #[arg(long)]
    pub guardian_ed25519_hex: String,
    /// 1952-byte ML-DSA-65 guardian vk hex
    #[arg(long)]
    pub guardian_ml_dsa_hex: String,
    /// Optional label
    #[arg(long)]
    pub label: Option<String>,
    /// New threshold (defaults to preserving the current one)
    #[arg(long)]
    pub threshold: Option<u32>,
}

impl AddGuardianCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_addGuardian",
                json!({
                    "account_address": self.account_address,
                    "guardian_ed25519_pubkey_hex": self.guardian_ed25519_hex,
                    "guardian_ml_dsa_pubkey_hex": self.guardian_ml_dsa_hex,
                    "label": self.label,
                    "threshold": self.threshold,
                }),
            )
            .await?;
        println!("Guardian added");
        output::print_field(
            "Guardians",
            &result
                .get("guardian_count")
                .and_then(|v| v.as_u64())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into()),
        );
        output::print_field(
            "Threshold",
            &result
                .get("threshold")
                .and_then(|v| v.as_u64())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into()),
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct InitiateRecoveryCmd {
    #[arg(long)]
    pub account_address: String,
    #[arg(long)]
    pub new_passkey_pubkey_hex: String,
    #[arg(long)]
    pub new_credential_id_hex: String,
    #[arg(long)]
    pub new_ml_dsa_pubkey_hex: String,
    /// Ceremony TTL in seconds (default 86400)
    #[arg(long)]
    pub ttl_secs: Option<u64>,
}

impl InitiateRecoveryCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_initiateRecovery",
                json!({
                    "account_address": self.account_address,
                    "new_passkey_public_key_hex": self.new_passkey_pubkey_hex,
                    "new_credential_id_hex": self.new_credential_id_hex,
                    "new_ml_dsa_public_key_hex": self.new_ml_dsa_pubkey_hex,
                    "ttl_secs": self.ttl_secs,
                }),
            )
            .await?;
        println!("Recovery initiated");
        output::print_field(
            "Recovery ID",
            result.get("recovery_id").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Op Hash",
            result.get("recovery_op_hash_hex").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Quorum required",
            &format!(
                "{} of {}",
                result.get("guardians_required").and_then(|v| v.as_u64()).unwrap_or(0),
                result.get("guardians_total").and_then(|v| v.as_u64()).unwrap_or(0),
            ),
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SubmitRecoverySignatureCmd {
    #[arg(long)]
    pub recovery_id: String,
    #[arg(long)]
    pub guardian_index: u32,
    /// Composite signature: 64-byte Ed25519 + 3309-byte ML-DSA-65 concat hex
    #[arg(long)]
    pub composite_signature_hex: String,
}

impl SubmitRecoverySignatureCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_submitRecoverySignature",
                json!({
                    "recovery_id": self.recovery_id,
                    "guardian_index": self.guardian_index,
                    "composite_signature_hex": self.composite_signature_hex,
                }),
            )
            .await?;
        println!("Guardian signature submitted");
        output::print_field(
            "Collected",
            &format!(
                "{} of {}",
                result.get("guardian_signatures_collected").and_then(|v| v.as_u64()).unwrap_or(0),
                result.get("guardians_required").and_then(|v| v.as_u64()).unwrap_or(0),
            ),
        );
        output::print_field(
            "Quorum reached",
            &result.get("quorum_reached").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct FinalizeRecoveryCmd {
    #[arg(long)]
    pub recovery_id: String,
}

impl FinalizeRecoveryCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_finalizeRecovery",
                json!({ "recovery_id": self.recovery_id }),
            )
            .await?;
        println!("Recovery finalized");
        output::print_field(
            "Account",
            result.get("account_address").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "New Credential",
            result.get("new_credential_id_hex").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        if let Some(validators) = result.get("installed_validators").and_then(|v| v.as_array()) {
            output::print_field(
                "Installed Validators",
                &validators
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct GrantSessionKeyCmd {
    #[arg(long)]
    pub account_address: String,
    /// 32-byte Ed25519 session-key pubkey hex
    #[arg(long)]
    pub session_pubkey_hex: String,
    /// Comma-separated 4-byte selectors (hex without 0x)
    #[arg(long, value_delimiter = ',')]
    pub selectors: Vec<String>,
    /// Optional comma-separated 20-byte target addresses
    #[arg(long, value_delimiter = ',')]
    pub targets: Vec<String>,
    /// Per-call value cap in wei (decimal); empty for unlimited
    #[arg(long)]
    pub max_per_call: Option<String>,
    /// Cumulative value cap in wei (decimal); empty for unlimited
    #[arg(long)]
    pub max_total: Option<String>,
    /// Earliest unix timestamp the key is valid (0 = no lower bound)
    #[arg(long, default_value_t = 0)]
    pub valid_after: u64,
    /// Latest unix timestamp the key is valid
    #[arg(long)]
    pub valid_until: u64,
    /// Optional label
    #[arg(long)]
    pub label: Option<String>,
}

impl GrantSessionKeyCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_grantSessionKey",
                json!({
                    "account_address": self.account_address,
                    "session_pubkey_hex": self.session_pubkey_hex,
                    "allowed_selectors_hex": self.selectors,
                    "allowed_targets": self.targets,
                    "max_value_per_call_wei": self.max_per_call,
                    "max_total_value_wei": self.max_total,
                    "valid_after_unix": self.valid_after,
                    "valid_until_unix": self.valid_until,
                    "label": self.label,
                }),
            )
            .await?;
        println!("Session key granted");
        output::print_field(
            "Account",
            result.get("account_address").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Session Pubkey",
            result.get("session_pubkey_hex").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field("Valid Until", &self.valid_until.to_string());
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct RevokeSessionKeyCmd {
    #[arg(long)]
    pub account_address: String,
}

impl RevokeSessionKeyCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_revokeSessionKey",
                json!({ "account_address": self.account_address }),
            )
            .await?;
        println!("Session key revoked");
        output::print_field(
            "Account",
            result.get("account_address").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Revoked",
            &result.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SetSpendingLimitCmd {
    #[arg(long)]
    pub account_address: String,
    /// Per-tx cap in wei (decimal). 0 = unlimited.
    #[arg(long)]
    pub per_tx_cap_wei: String,
    /// Daily cap in wei. 0 = unlimited.
    #[arg(long)]
    pub daily_cap_wei: String,
    /// 32-byte Ed25519 authenticator pubkey hex
    #[arg(long)]
    pub authenticator_pubkey_hex: String,
}

impl SetSpendingLimitCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let _: Value = rpc
            .call(
                "tenzro_setSpendingLimit",
                json!({
                    "account_address": self.account_address,
                    "per_tx_cap_wei": self.per_tx_cap_wei,
                    "daily_cap_wei": self.daily_cap_wei,
                    "authenticator_pubkey_hex": self.authenticator_pubkey_hex,
                }),
            )
            .await?;
        println!("Spending limit updated");
        output::print_field("Per-tx cap", &self.per_tx_cap_wei);
        output::print_field("Daily cap", &self.daily_cap_wei);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct AddHardwareSignerCmd {
    #[arg(long)]
    pub account_address: String,
    /// One of: ledger, trezor, gridplus, yubikey, generic
    #[arg(long)]
    pub device_kind: String,
    /// Hardware public key hex (33-byte compressed secp256k1, 65-byte uncompressed,
    /// or 64-byte raw P-256 for FIDO2)
    #[arg(long)]
    pub public_key_hex: String,
    /// Make this signer mandatory on every operation
    #[arg(long, default_value_t = false)]
    pub required_always: bool,
    /// Value threshold above which this signer becomes required (decimal wei)
    #[arg(long)]
    pub required_above_wei: Option<String>,
    #[arg(long)]
    pub label: Option<String>,
}

impl AddHardwareSignerCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_addHardwareSigner",
                json!({
                    "account_address": self.account_address,
                    "device_kind": self.device_kind,
                    "public_key_hex": self.public_key_hex,
                    "required_always": self.required_always,
                    "required_above_wei": self.required_above_wei,
                    "label": self.label,
                }),
            )
            .await?;
        println!("Hardware signer installed");
        output::print_field(
            "Device",
            result.get("device_kind").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Validator",
            result.get("validator_module_address").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct GetSmartAccountCmd {
    #[arg(long)]
    pub account_address: String,
}

impl GetSmartAccountCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_getSmartAccount",
                json!({ "account_address": self.account_address }),
            )
            .await?;
        print_smart_account(&result);
        Ok(())
    }
}

async fn list_smart_accounts(rpc: &RpcClient) -> Result<()> {
    let result: Value = rpc.call("tenzro_listSmartAccounts", json!({})).await?;
    let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
    println!("{} smart account(s)", count);
    if let Some(accounts) = result.get("smart_accounts").and_then(|v| v.as_array()) {
        for acct in accounts {
            print_smart_account(acct);
            println!();
        }
    }
    Ok(())
}

fn print_smart_account(v: &Value) {
    output::print_field(
        "Address",
        v.get("address").and_then(|x| x.as_str()).unwrap_or("?"),
    );
    output::print_field(
        "Owner",
        v.get("owner_hex").and_then(|x| x.as_str()).unwrap_or("?"),
    );
    output::print_field(
        "Nonce",
        &v.get("nonce")
            .and_then(|x| x.as_u64())
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into()),
    );
    if let Some(installed) = v.get("installed_validators").and_then(|x| x.as_array()) {
        let addrs: Vec<String> = installed
            .iter()
            .filter_map(|m| m.get("module_address").and_then(|a| a.as_str()).map(String::from))
            .collect();
        output::print_field("Validators", &addrs.join(", "));
    }
}

#[derive(Debug, Args)]
pub struct ListPendingRecoveriesCmd {
    #[arg(long)]
    pub account_address: String,
}

impl ListPendingRecoveriesCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_listPendingRecoveries",
                json!({ "account_address": self.account_address }),
            )
            .await?;
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        println!("{} pending recovery ceremonies", count);
        if let Some(recs) = result.get("pending_recoveries").and_then(|v| v.as_array()) {
            for r in recs {
                output::print_field(
                    "Recovery ID",
                    r.get("recovery_id").and_then(|x| x.as_str()).unwrap_or("?"),
                );
                output::print_field(
                    "Signatures",
                    &r.get("guardian_signatures_collected")
                        .and_then(|x| x.as_u64())
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "?".into()),
                );
                output::print_field(
                    "Expires (ms)",
                    &r.get("expires_at_ms")
                        .and_then(|x| x.as_u64())
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "?".into()),
                );
                output::print_field(
                    "Finalized",
                    &r.get("finalized").and_then(|x| x.as_bool()).unwrap_or(false).to_string(),
                );
                println!();
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Browser-mediated ceremony flow (gcloud-style device login)
// ---------------------------------------------------------------------------

/// Resolve the web-API base URL that serves `/auth/passkey`. The web API
/// listens on a different port/host than JSON-RPC, so it cannot be
/// derived mechanically — only the two well-known layouts are inferred.
fn derive_web_url(explicit: Option<&str>, rpc_url: &str) -> Result<String> {
    if let Some(url) = explicit {
        return Ok(url.trim_end_matches('/').to_string());
    }
    if rpc_url.contains("127.0.0.1") || rpc_url.contains("localhost") {
        return Ok("http://127.0.0.1:8080".to_string());
    }
    if rpc_url.contains("rpc.tenzro.xyz") {
        return Ok("https://api.tenzro.xyz".to_string());
    }
    bail!(
        "cannot derive the browser-ceremony URL from RPC URL {rpc_url}; \
         pass --web-url with the node's web API base (default port 8080)"
    )
}

fn launch_browser(url: &str) {
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
async fn poll_session(rpc: &RpcClient, session_id: &str) -> Result<Value> {
    println!("Waiting for the browser ceremony to complete (Ctrl-C to abort)…");
    loop {
        let session: Value = rpc
            .call("tenzro_getPasskeySession", json!({ "session_id": session_id }))
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
            "expired" => bail!("passkey session expired before the ceremony completed — run the command again"),
            _ => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
}

fn passkey_state_dir() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .context("cannot resolve home directory for ~/.tenzro/passkey")?
        .join(".tenzro")
        .join("passkey");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Write an ML-DSA seed (hex) to a fresh file with owner-only permissions.
fn write_seed_file(path: &Path, seed_hex: &str) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .with_context(|| format!("creating ML-DSA seed file {}", path.display()))?;
    file.write_all(seed_hex.as_bytes())?;
    Ok(())
}

/// Rename a `pending-*` seed file to its account/credential-keyed name
/// once the ceremony has bound the key to an account.
fn finalize_seed_file(pending: &Path, account_address: &str, credential_id_hex: &str) -> Result<PathBuf> {
    let account = account_address.trim_start_matches("0x");
    let cred8: String = credential_id_hex
        .trim_start_matches("0x")
        .chars()
        .take(8)
        .collect();
    let final_path = pending.with_file_name(format!("{account}-{cred8}.mldsa.seed"));
    std::fs::rename(pending, &final_path)
        .with_context(|| format!("renaming seed file to {}", final_path.display()))?;
    Ok(final_path)
}

fn load_ml_dsa_seed(path: &Path) -> Result<MlDsaSigningKey> {
    let seed_hex = std::fs::read_to_string(path)
        .with_context(|| format!("reading ML-DSA seed file {}", path.display()))?;
    let seed = hex::decode(seed_hex.trim())
        .with_context(|| format!("ML-DSA seed file {} is not valid hex", path.display()))?;
    MlDsaSigningKey::from_seed(&seed)
        .with_context(|| format!("ML-DSA seed file {} has the wrong length", path.display()))
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
    async fn execute(&self, rpc: &RpcClient, rpc_url: &str) -> Result<()> {
        let web_base = derive_web_url(self.web_url.as_deref(), rpc_url)?;
        let ml_dsa = MlDsaSigningKey::generate();
        let session: Value = rpc
            .call(
                "tenzro_createPasskeySession",
                json!({
                    "kind": "enroll",
                    "display_name": self.display_name,
                    "ml_dsa_public_key_hex": hex::encode(ml_dsa.verifying_key_bytes()),
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

        // Persist the PQ seed before any ceremony can complete — losing
        // it after enrollment would orphan the account's ML-DSA leg.
        let prefix: String = session_id.chars().take(8).collect();
        let pending = passkey_state_dir()?.join(format!("pending-{prefix}.mldsa.seed"));
        write_seed_file(&pending, &hex::encode(ml_dsa.seed_bytes()))?;

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
        output::print_field("DID", result.get("did").and_then(|v| v.as_str()).unwrap_or("?"));
        output::print_field("Smart Account", if account.is_empty() { "?" } else { account });
        output::print_field("Credential ID", if cred.is_empty() { "?" } else { cred });
        let seed_path = if !account.is_empty() && !cred.is_empty() {
            finalize_seed_file(&pending, account, cred)?
        } else {
            pending
        };
        output::print_field("ML-DSA seed file", &seed_path.display().to_string());
        println!("Keep the seed file safe — `tenzro passkey sign` needs it for the post-quantum leg.");
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct AddCmd {
    /// Smart account to add the credential to
    #[arg(long)]
    pub account_address: String,
    /// Optional display label for the new credential
    #[arg(long)]
    pub label: Option<String>,
    /// Web API base serving /auth/passkey (derived from the RPC URL when omitted)
    #[arg(long)]
    pub web_url: Option<String>,
}

impl AddCmd {
    async fn execute(&self, rpc: &RpcClient, rpc_url: &str) -> Result<()> {
        let web_base = derive_web_url(self.web_url.as_deref(), rpc_url)?;
        let session: Value = rpc
            .call(
                "tenzro_createPasskeySession",
                json!({
                    "kind": "add",
                    "account_address": self.account_address,
                    "label": self.label,
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
            .get("account_address")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let cred = result
            .get("credential_id_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!("Passkey added");
        output::print_field("Account", if account.is_empty() { "?" } else { account });
        output::print_field("Credential ID", if cred.is_empty() { "?" } else { cred });
        output::print_field(
            "Credentials total",
            &result
                .get("credentials_total")
                .and_then(|v| v.as_u64())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into()),
        );
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct ListCmd {
    #[arg(long)]
    pub account_address: String,
}

impl ListCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_listPasskeys",
                json!({ "account_address": self.account_address }),
            )
            .await?;
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        println!(
            "{} credential(s) on {}",
            count,
            result.get("account_address").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        if let Some(ids) = result.get("credential_ids").and_then(|v| v.as_array()) {
            for id in ids.iter().filter_map(|v| v.as_str()) {
                println!("  {id}");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct RemoveCmd {
    #[arg(long)]
    pub account_address: String,
    /// Credential id to revoke (hex)
    #[arg(long)]
    pub credential_id_hex: String,
}

impl RemoveCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_removePasskey",
                json!({
                    "account_address": self.account_address,
                    "credential_id_hex": self.credential_id_hex,
                }),
            )
            .await?;
        println!("Passkey removal");
        output::print_field(
            "Removed",
            &result.get("removed").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
        );
        output::print_field(
            "Credentials remaining",
            &result
                .get("credentials_remaining")
                .and_then(|v| v.as_u64())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".into()),
        );
        Ok(())
    }
}

fn print_policy(result: &Value) {
    output::print_field(
        "Second factor",
        result
            .get("second_factor")
            .and_then(|v| v.as_str())
            .unwrap_or("?"),
    );
    output::print_field(
        "Required signatures",
        &result
            .get("required_signatures")
            .and_then(|v| v.as_u64())
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into()),
    );
    output::print_field(
        "Credentials enrolled",
        &result
            .get("credentials_enrolled")
            .and_then(|v| v.as_u64())
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into()),
    );
}

#[derive(Debug, Args)]
pub struct SetPolicyCmd {
    #[arg(long)]
    pub account_address: String,
    /// `single_credential` (one passkey approves) or `two_credentials`
    /// (two distinct enrolled passkeys must both sign every operation)
    #[arg(long)]
    pub second_factor: String,
}

impl SetPolicyCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_setPasskeyPolicy",
                json!({
                    "account_address": self.account_address,
                    "second_factor": self.second_factor,
                }),
            )
            .await?;
        println!("Passkey second-factor policy updated");
        print_policy(&result);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct GetPolicyCmd {
    #[arg(long)]
    pub account_address: String,
}

impl GetPolicyCmd {
    async fn execute(&self, rpc: &RpcClient) -> Result<()> {
        let result: Value = rpc
            .call(
                "tenzro_getPasskeyPolicy",
                json!({ "account_address": self.account_address }),
            )
            .await?;
        println!("Passkey second-factor policy");
        print_policy(&result);
        Ok(())
    }
}

#[derive(Debug, Args)]
pub struct SignCmd {
    #[arg(long)]
    pub account_address: String,
    /// 32-byte operation hash to approve (hex)
    #[arg(long)]
    pub op_hash_hex: String,
    /// ML-DSA seed file written by `login` / `add` — enables the hybrid
    /// PQ leg (required for accounts enrolled with an ML-DSA key)
    #[arg(long)]
    pub ml_dsa_seed_file: Option<PathBuf>,
    /// Web API base serving /auth/passkey (derived from the RPC URL when omitted)
    #[arg(long)]
    pub web_url: Option<String>,
}

impl SignCmd {
    async fn execute(&self, rpc: &RpcClient, rpc_url: &str) -> Result<()> {
        let web_base = derive_web_url(self.web_url.as_deref(), rpc_url)?;
        let op_hash = hex::decode(self.op_hash_hex.trim_start_matches("0x"))
            .context("op-hash-hex is not valid hex")?;
        if op_hash.len() != 32 {
            bail!("op-hash-hex must be exactly 32 bytes, got {}", op_hash.len());
        }
        let ml_dsa_signature_hex = match &self.ml_dsa_seed_file {
            Some(path) => Some(hex::encode(load_ml_dsa_seed(path)?.sign(&op_hash))),
            None => None,
        };
        let session: Value = rpc
            .call(
                "tenzro_createPasskeySession",
                json!({
                    "kind": "sign",
                    "account_address": self.account_address,
                    "op_hash_hex": self.op_hash_hex,
                    "ml_dsa_signature_hex": ml_dsa_signature_hex,
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

        println!("Passkey approval");
        output::print_field(
            "Verified",
            &result.get("verified").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
        );
        output::print_field(
            "Op Hash",
            result.get("op_hash_hex").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        output::print_field(
            "Validator",
            result.get("validator").and_then(|v| v.as_str()).unwrap_or("?"),
        );
        Ok(())
    }
}

