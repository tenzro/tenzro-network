//! Passkey-first wallet onboarding + custody CLI surface.
//!
//! Maps `tenzro_*Passkey*` / `tenzro_*Recovery*` / `tenzro_*SessionKey*` /
//! `tenzro_*HardwareSigner*` / `tenzro_*SmartAccount*` to user-friendly
//! commands. Examples:
//!
//! ```text
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
//! Note: this CLI does NOT acquire the WebAuthn assertion itself — the
//! passkey signature must come from a platform authenticator (Tauri
//! desktop, browser, mobile app). The CLI is the *network* surface;
//! local-signing is done by `apps/tenzro-desktop` or `sdk/tenzro-ts-sdk`.

use anyhow::Result;
use clap::{Args, Subcommand};
use crate::output;
use crate::rpc::RpcClient;
use serde_json::{json, Value};

fn default_rpc_url(override_url: Option<&str>) -> String {
    override_url
        .map(|s| s.to_string())
        .or_else(|| std::env::var("TENZRO_RPC_URL").ok())
        .unwrap_or_else(|| "https://rpc.tenzro.network".to_string())
}

#[derive(Debug, Subcommand)]
pub enum PasskeyCommand {
    /// Enroll a passkey-bound smart account
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

