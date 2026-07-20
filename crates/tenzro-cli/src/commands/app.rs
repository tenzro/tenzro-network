//! Application management commands for the Tenzro CLI
//!
//! Register applications in the on-chain app registry, manage their status,
//! and submit developer-signed settlement authorizations.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;

use crate::output;

/// Application management operations
#[derive(Debug, Subcommand)]
pub enum AppCommand {
    /// Register an app in the on-chain app registry (developer-signed)
    Register(AppRegisterCmd),
    /// Activate or deactivate a registered app (developer-signed)
    SetStatus(AppSetStatusCmd),
    /// Look up a registered app
    Get(AppGetCmd),
    /// List all registered apps
    List(AppListCmd),
    /// Submit a developer-signed settlement authorization
    SettleAuthorized(AppSettleAuthorizedCmd),
    /// Fetch the recorded outcome for a settlement authorization
    GetOutcome(AppGetOutcomeCmd),
}

impl AppCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::SetStatus(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::SettleAuthorized(cmd) => cmd.execute().await,
            Self::GetOutcome(cmd) => cmd.execute().await,
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Decode a hex string (0x-optional) into bytes.
fn decode_hex(label: &str, s: &str) -> Result<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .with_context(|| format!("invalid {label} hex"))
}

/// Parse a wallet address the same way the node does: hex, up to 32 bytes,
/// copied into the front of a zero-filled 32-byte address.
fn parse_wallet_address(s: &str) -> Result<tenzro_types::primitives::Address> {
    let bytes = decode_hex("app wallet address", s)?;
    if bytes.len() > 32 {
        bail!("address too long: {} bytes", bytes.len());
    }
    let mut addr = [0u8; 32];
    addr[..bytes.len()].copy_from_slice(&bytes);
    Ok(tenzro_types::primitives::Address::new(addr))
}

/// Build an Ed25519 signer from a 32-byte hex seed.
pub(crate) fn ed25519_signer(signing_key_hex: &str) -> Result<tenzro_crypto::signatures::Ed25519SignerImpl> {
    let seed = decode_hex("signing key", signing_key_hex)?;
    let keypair = tenzro_crypto::keys::KeyPair::from_bytes(tenzro_crypto::keys::KeyType::Ed25519, &seed)
        .map_err(|e| anyhow!("invalid Ed25519 signing key: {e}"))?;
    tenzro_crypto::signatures::Ed25519SignerImpl::new(keypair)
        .map_err(|e| anyhow!("failed to build signer: {e}"))
}

/// Sign a DID envelope for an authorized node write and return its header
/// value. Shared with the identity and compliance commands, which bind the
/// same envelope convention to their own canonical params.
pub(crate) fn sign_envelope(
    did: &str,
    method: &str,
    params_hash: [u8; 32],
    signing_key_hex: &str,
) -> Result<String> {
    use tenzro_crypto::signatures::Signer;

    let signer = ed25519_signer(signing_key_hex)?;
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut env = tenzro_identity::envelope::TenzroDidEnvelope {
        did: did.to_string(),
        method: method.to_string(),
        params_hash,
        timestamp: now_ms(),
        nonce,
        signature: Vec::new(),
    };
    let preimage = tenzro_identity::envelope::canonical_preimage(&env);
    env.signature = signer
        .sign(&preimage)
        .map_err(|e| anyhow!("envelope signing failed: {e}"))?
        .as_bytes()
        .to_vec();
    Ok(env.to_header_value())
}

fn print_app_record(record: &serde_json::Value) {
    output::print_field(
        "App ID",
        record.get("app_id").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Developer DID",
        record.get("developer_did").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "App Wallet",
        record.get("app_wallet").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Margin (bps)",
        &record.get("margin_bps").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
    );
    output::print_field(
        "Active",
        &record.get("active").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
    );
    if let Some(keys) = record.get("signing_pubkeys").and_then(|v| v.as_array()) {
        output::print_field("Signing Keys", &keys.len().to_string());
    }
}

/// Register an app in the on-chain app registry.
///
/// The registration is permissionless and first-writer-wins: the developer
/// signs a DID envelope over the canonical registration params with their own
/// key, and any node accepts it. Provide either `--signing-key` (a 32-byte
/// Ed25519 seed for the developer DID key — the envelope is built and signed
/// locally) or `--envelope` (a pre-signed envelope header value produced
/// elsewhere, e.g. by the developer's backend).
#[derive(Debug, Parser)]
pub struct AppRegisterCmd {
    /// App identifier (1-128 bytes, unique network-wide)
    #[arg(long)]
    app_id: String,
    /// Developer DID that owns the app (e.g. did:tenzro:... or did:key:z6Mk...)
    #[arg(long)]
    did: String,
    /// App wallet address (hex) — the developer's own TNZO treasury for this app
    #[arg(long)]
    app_wallet: String,
    /// Settlement signing key as `key_id:pubkey_hex[:daily_limit_tnzo]` (repeatable)
    #[arg(long = "key", required = true)]
    keys: Vec<String>,
    /// Developer margin in basis points (max 2000)
    #[arg(long, default_value_t = 0)]
    margin_bps: u32,
    /// Minimum app-wallet balance hint in smallest TNZO units
    #[arg(long)]
    min_balance: Option<String>,
    /// Register the app as inactive
    #[arg(long)]
    inactive: bool,
    /// 32-byte Ed25519 seed (hex) for the developer DID key — signs the envelope locally
    #[arg(long, conflicts_with = "envelope")]
    signing_key: Option<String>,
    /// Pre-signed envelope header value (hex) produced externally
    #[arg(long)]
    envelope: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Application");

        // Parse `key_id:pubkey_hex[:daily_limit]` entries.
        let mut signing_pubkeys = Vec::with_capacity(self.keys.len());
        for entry in &self.keys {
            let mut parts = entry.splitn(3, ':');
            let key_id = parts
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("--key must be key_id:pubkey_hex[:daily_limit_tnzo]"))?;
            let pk_hex = parts
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow!("--key must be key_id:pubkey_hex[:daily_limit_tnzo]"))?;
            let public_key = decode_hex("signing pubkey", pk_hex)?;
            let daily_limit_tnzo = match parts.next() {
                Some(limit) => Some(
                    limit
                        .parse::<u128>()
                        .with_context(|| format!("invalid daily limit `{limit}`"))?,
                ),
                None => None,
            };
            signing_pubkeys.push(tenzro_node::app_registry::AppSigningKey {
                key_id: key_id.to_string(),
                public_key,
                daily_limit_tnzo,
            });
        }

        let min_balance: u128 = match &self.min_balance {
            Some(s) => s
                .parse::<u128>()
                .with_context(|| format!("invalid min balance `{s}`"))?,
            None => 0,
        };
        let active = !self.inactive;

        // Build the exact record the node will validate so the envelope's
        // params_hash binds to the same canonical bytes.
        let record = tenzro_node::app_registry::AppRecord {
            app_id: self.app_id.clone(),
            developer_did: self.did.clone(),
            app_wallet: parse_wallet_address(&self.app_wallet)?,
            signing_pubkeys: signing_pubkeys.clone(),
            margin_bps: self.margin_bps,
            min_balance,
            created_at: 0,
            active,
        };

        let envelope = match (&self.signing_key, &self.envelope) {
            (Some(sk), None) => sign_envelope(
                &self.did,
                tenzro_node::app_registry::METHOD_REGISTER_APP,
                tenzro_identity::envelope::params_hash(&record.canonical_params()),
                sk,
            )?,
            (None, Some(env)) => env.clone(),
            _ => bail!("provide exactly one of --signing-key or --envelope"),
        };

        let keys_json: Vec<serde_json::Value> = record
            .signing_pubkeys
            .iter()
            .map(|k| {
                serde_json::json!({
                    "key_id": k.key_id,
                    "public_key": hex::encode(&k.public_key),
                    "daily_limit_tnzo": k.daily_limit_tnzo.map(|l| l.to_string()),
                })
            })
            .collect();

        let spinner = output::create_spinner("Registering...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_registerApp",
                serde_json::json!({
                    "app_id": self.app_id,
                    "developer_did": self.did,
                    "app_wallet": self.app_wallet,
                    "signing_pubkeys": keys_json,
                    "margin_bps": self.margin_bps,
                    "min_balance": min_balance.to_string(),
                    "active": active,
                    "envelope": envelope,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        output::print_success("Application registered!");
        print_app_record(&result);
        Ok(())
    }
}

/// Activate or deactivate a registered app.
#[derive(Debug, Parser)]
pub struct AppSetStatusCmd {
    /// App identifier
    #[arg(long)]
    app_id: String,
    /// New active status (true or false)
    #[arg(long)]
    active: bool,
    /// Developer DID that owns the app
    #[arg(long)]
    did: Option<String>,
    /// 32-byte Ed25519 seed (hex) for the developer DID key — signs the envelope locally
    #[arg(long, conflicts_with = "envelope", requires = "did")]
    signing_key: Option<String>,
    /// Pre-signed envelope header value (hex) produced externally
    #[arg(long)]
    envelope: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppSetStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Set Application Status");

        let envelope = match (&self.signing_key, &self.envelope) {
            (Some(sk), None) => {
                let did = self
                    .did
                    .as_deref()
                    .ok_or_else(|| anyhow!("--did is required with --signing-key"))?;
                let canonical = tenzro_node::app_registry::canonical_status_params(
                    &self.app_id,
                    self.active,
                );
                sign_envelope(
                    did,
                    tenzro_node::app_registry::METHOD_SET_APP_STATUS,
                    tenzro_identity::envelope::params_hash(&canonical),
                    sk,
                )?
            }
            (None, Some(env)) => env.clone(),
            _ => bail!("provide exactly one of --signing-key or --envelope"),
        };

        let spinner = output::create_spinner("Updating status...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_setAppStatus",
                serde_json::json!({
                    "app_id": self.app_id,
                    "active": self.active,
                    "envelope": envelope,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        output::print_success("Application status updated!");
        print_app_record(&result);
        Ok(())
    }
}

/// Look up a registered app.
#[derive(Debug, Parser)]
pub struct AppGetCmd {
    /// App identifier
    #[arg(long)]
    app_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Application");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getApp", serde_json::json!({ "app_id": self.app_id }))
            .await?;
        print_app_record(&result);
        output::print_json(&result)?;
        Ok(())
    }
}

/// List all registered apps.
#[derive(Debug, Parser)]
pub struct AppListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Registered Applications");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listApps", serde_json::json!({}))
            .await?;

        let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        output::print_field("Count", &count.to_string());
        if let Some(apps) = result.get("apps").and_then(|v| v.as_array()) {
            for app in apps {
                let id = app.get("app_id").and_then(|v| v.as_str()).unwrap_or("?");
                let did = app.get("developer_did").and_then(|v| v.as_str()).unwrap_or("?");
                let active = app.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                output::print_field(id, &format!("{did} (active: {active})"));
            }
        }
        Ok(())
    }
}

/// Submit a developer-signed settlement authorization.
///
/// The developer backend has already charged the end user in fiat on its own
/// payment-provider account; this command signs (or forwards) the TNZO
/// settlement authorization that moves TNZO from the app wallet to the payer,
/// minus the network commission. The signing key must be one of the app's
/// registered settlement keys.
#[derive(Debug, Parser)]
pub struct AppSettleAuthorizedCmd {
    /// App identifier
    #[arg(long)]
    app_id: String,
    /// Chain id the authorization is valid on (default: query the node)
    #[arg(long)]
    chain_id: Option<u64>,
    /// Payer DID that receives the TNZO
    #[arg(long)]
    payer_did: String,
    /// TNZO amount in smallest units (decimal)
    #[arg(long)]
    amount: String,
    /// Payment-provider reference (idempotency key per app)
    #[arg(long)]
    external_ref: String,
    /// Expiry in unix milliseconds (default: now + 120000)
    #[arg(long)]
    expiry: Option<u64>,
    /// Registered signing key id producing the signature
    #[arg(long)]
    key_id: String,
    /// 32-byte Ed25519 seed (hex) of the registered app signing key
    #[arg(long)]
    signing_key: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppSettleAuthorizedCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use tenzro_crypto::signatures::Signer;

        output::print_header("Settle Authorized");
        let rpc = RpcClient::new(&self.rpc);

        let amount_tnzo: u128 = self
            .amount
            .parse::<u128>()
            .with_context(|| format!("invalid amount `{}`", self.amount))?;

        let chain_id = match self.chain_id {
            Some(id) => id,
            None => {
                let chain_id_hex: String = rpc
                    .call("eth_chainId", serde_json::json!([]))
                    .await
                    .unwrap_or_else(|_| "0x539".to_string());
                u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16).unwrap_or(1337)
            }
        };
        let expiry = self.expiry.unwrap_or_else(|| now_ms() + 120_000);

        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut auth = tenzro_types::settlement::SettlementAuthorization {
            app_id: self.app_id.clone(),
            chain_id,
            payer_did: self.payer_did.clone(),
            amount_tnzo,
            external_ref: self.external_ref.clone(),
            nonce,
            expiry,
            key_id: self.key_id.clone(),
            signature: Vec::new(),
        };
        let signer = ed25519_signer(&self.signing_key)?;
        auth.signature = signer
            .sign(&auth.signing_hash())
            .map_err(|e| anyhow!("authorization signing failed: {e}"))?
            .as_bytes()
            .to_vec();

        let spinner = output::create_spinner("Settling...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_settleAuthorized",
                serde_json::json!({
                    "app_id": auth.app_id,
                    "chain_id": auth.chain_id,
                    "payer_did": auth.payer_did,
                    "amount_tnzo": auth.amount_tnzo.to_string(),
                    "external_ref": auth.external_ref,
                    "nonce": hex::encode(auth.nonce),
                    "expiry": auth.expiry,
                    "key_id": auth.key_id,
                    "signature": hex::encode(&auth.signature),
                }),
            )
            .await?;
        spinner.finish_and_clear();

        let success = result.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        let duplicate = result.get("duplicate").and_then(|v| v.as_bool()).unwrap_or(false);
        if success {
            output::print_success(if duplicate {
                "Settlement already recorded (idempotent replay)"
            } else {
                "Settlement executed!"
            });
        } else {
            output::print_info("Settlement recorded as failed");
        }
        output::print_json(&result)?;
        Ok(())
    }
}

/// Fetch the recorded outcome for a settlement authorization.
#[derive(Debug, Parser)]
pub struct AppGetOutcomeCmd {
    /// App identifier
    #[arg(long)]
    app_id: String,
    /// Payment-provider reference used at settlement time
    #[arg(long)]
    external_ref: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl AppGetOutcomeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Settlement Outcome");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getSettleAuthorizedOutcome",
                serde_json::json!({
                    "app_id": self.app_id,
                    "external_ref": self.external_ref,
                }),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}
