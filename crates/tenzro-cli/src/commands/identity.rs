//! Identity management commands for the Tenzro CLI
//!
//! Supports TDIP (Tenzro Decentralized Identity Protocol) identities.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output::{self};

/// Identity management commands (TDIP)
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Register a new TDIP identity
    Register(IdentityRegisterCmd),
    /// Resolve a DID to its identity or W3C DID Document
    Resolve(IdentityResolveCmd),
    /// List locally known identities
    List(IdentityListCmd),
    /// Show W3C DID Document for a DID
    Document(IdentityDocumentCmd),
    /// Add a verifiable credential to an identity
    AddCredential(IdentityAddCredentialCmd),
    /// Add a service endpoint to an identity
    AddService(IdentityAddServiceCmd),
    /// Resolve a DID to identity info (alias for resolve)
    ResolveDid(IdentityResolveDidCmd),
    /// Resolve a DID to its W3C DID Document
    ResolveDocument(IdentityResolveDocumentCmd),
    /// Set delegation scope for a machine identity
    SetDelegation(IdentitySetDelegationCmd),
    /// Register a new machine identity
    RegisterMachine(IdentityRegisterMachineCmd),
    /// List the public JWK Set published by this node (RFC 7517)
    Jwks(IdentityJwksCmd),
    /// Look up a single JWK by `keyid` (RFC 9421 keyid resolution)
    JwksGet(IdentityJwksGetCmd),
    /// Revoke an identity by DID (logical delete, cascades through act-chain)
    Revoke(IdentityRevokeCmd),
    /// Hard-delete a revoked identity (TDIP/GDPR Article 17 right-to-erasure)
    Forget(IdentityForgetCmd),
    /// Export a portable CARv1 identity bundle (DID + credentials + encrypted keystore files)
    ExportCar(IdentityExportCarCmd),
    /// Import a portable CARv1 identity bundle produced by `export-car`
    ImportCar(IdentityImportCarCmd),
}

impl IdentityCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::Resolve(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Document(cmd) => cmd.execute().await,
            Self::AddCredential(cmd) => cmd.execute().await,
            Self::AddService(cmd) => cmd.execute().await,
            Self::ResolveDid(cmd) => cmd.execute().await,
            Self::ResolveDocument(cmd) => cmd.execute().await,
            Self::SetDelegation(cmd) => cmd.execute().await,
            Self::RegisterMachine(cmd) => cmd.execute().await,
            Self::Jwks(cmd) => cmd.execute().await,
            Self::JwksGet(cmd) => cmd.execute().await,
            Self::Revoke(cmd) => cmd.execute().await,
            Self::Forget(cmd) => cmd.execute().await,
            Self::ExportCar(cmd) => cmd.execute().await,
            Self::ImportCar(cmd) => cmd.execute().await,
        }
    }
}

/// Register a new TDIP identity
#[derive(Debug, Parser)]
pub struct IdentityRegisterCmd {
    /// Display name for the identity
    #[arg(long)]
    name: String,

    /// Identity type: human or machine
    #[arg(long, default_value = "human")]
    identity_type: String,

    /// Controller DID (required for machine identities)
    #[arg(long)]
    controller: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Identity");

        let spinner = output::create_spinner("Registering identity...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_registerIdentity", serde_json::json!([{
            "display_name": self.name,
            "identity_type": self.identity_type,
            "controller": self.controller.as_deref()
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Identity registered successfully!");
        println!();

        if let Some(did) = result.get("did").and_then(|v| v.as_str()) {
            output::print_field("DID", did);
        }
        output::print_field("Display Name", &self.name);
        output::print_field("Type", &self.identity_type);

        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", status);
        }

        if let Some(controller) = &self.controller {
            output::print_field("Controller", controller);
        }

        if let Some(tx_hash) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", tx_hash);
        }

        Ok(())
    }
}

/// Resolve a DID to its identity information
#[derive(Debug, Parser)]
pub struct IdentityResolveCmd {
    /// The DID to resolve (e.g. did:tenzro:human:abc123)
    did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityResolveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Resolve Identity");

        let spinner = output::create_spinner("Resolving DID...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call("tenzro_resolveIdentity", serde_json::json!({"did": self.did}))
            .await?;

        spinner.finish_and_clear();

        println!();
        output::print_field("DID", &self.did);

        if let Some(identity_type) = result.get("identity_type").and_then(|v| v.as_str()) {
            output::print_field("Type", identity_type);
        }
        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", status);
        }
        if let Some(display_name) = result.get("display_name").and_then(|v| v.as_str()) {
            output::print_field("Display Name", display_name);
        }
        if let Some(key_count) = result.get("key_count").and_then(|v| v.as_u64()) {
            output::print_field("Key Count", &key_count.to_string());
        }
        if let Some(cred_count) = result.get("credential_count").and_then(|v| v.as_u64()) {
            output::print_field("Credential Count", &cred_count.to_string());
        }
        if let Some(svc_count) = result.get("service_count").and_then(|v| v.as_u64()) {
            output::print_field("Service Count", &svc_count.to_string());
        }

        Ok(())
    }
}

/// List locally known identities
#[derive(Debug, Parser)]
pub struct IdentityListCmd {
    /// Filter by type: human, machine, or all
    #[arg(long, default_value = "all")]
    identity_type: String,

    /// Show detailed information
    #[arg(long)]
    detailed: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Identities");

        let spinner = output::create_spinner("Loading identities...");

        let rpc = RpcClient::new(&self.rpc);

        let identities: Vec<serde_json::Value> = rpc.call("tenzro_listIdentities", serde_json::json!([{
            "identity_type": if self.identity_type == "all" { serde_json::Value::Null } else { serde_json::Value::String(self.identity_type.clone()) }
        }])).await.unwrap_or_default();

        spinner.finish_and_clear();

        if identities.is_empty() {
            output::print_info("No identities found. Register one with: tenzro-cli identity register --name <name>");
            return Ok(());
        }

        if self.detailed {
            for identity in &identities {
                println!();
                if let Some(v) = identity.get("did").and_then(|v| v.as_str()) {
                    output::print_field("DID", v);
                }
                if let Some(v) = identity.get("display_name").and_then(|v| v.as_str()) {
                    output::print_field("Name", v);
                }
                if let Some(v) = identity.get("identity_type").and_then(|v| v.as_str()) {
                    output::print_field("Type", v);
                }
                if let Some(v) = identity.get("controller").and_then(|v| v.as_str()) {
                    output::print_field("Controller", v);
                }
                if let Some(v) = identity.get("status").and_then(|v| v.as_str()) {
                    output::print_field("Status", v);
                }
                if let Some(v) = identity.get("key_count").and_then(|v| v.as_u64()) {
                    output::print_field("Keys", &v.to_string());
                }
                if let Some(v) = identity.get("credential_count").and_then(|v| v.as_u64()) {
                    output::print_field("Credentials", &v.to_string());
                }
            }
            println!();
        } else {
            let headers = vec!["DID", "Type", "Name", "Status"];
            let mut rows = Vec::new();
            for identity in &identities {
                rows.push(vec![
                    identity.get("did").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    identity.get("identity_type").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    identity.get("display_name").and_then(|v| v.as_str()).unwrap_or("unnamed").to_string(),
                    identity.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                ]);
            }
            output::print_table(&headers, &rows);
        }

        println!("Total: {} identities", identities.len());

        Ok(())
    }
}

/// Show W3C DID Document for a DID
#[derive(Debug, Parser)]
pub struct IdentityDocumentCmd {
    /// The DID to get the document for
    did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityDocumentCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("W3C DID Document");

        let spinner = output::create_spinner("Resolving DID Document...");

        let rpc = RpcClient::new(&self.rpc);

        // First resolve the identity to get its data
        let identity: serde_json::Value = rpc
            .call("tenzro_resolveIdentity", serde_json::json!({"did": self.did}))
            .await?;

        spinner.finish_and_clear();

        // Format as W3C DID Document
        let doc = serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1"
            ],
            "id": self.did,
            "verificationMethod": [{
                "id": format!("{}#key-1", self.did),
                "type": "Ed25519VerificationKey2020",
                "controller": self.did,
                "publicKeyMultibase": identity.get("public_key").and_then(|v| v.as_str()).unwrap_or("z6Mkf5rGMoatrSj1f...")
            }],
            "authentication": [format!("{}#key-1", self.did)],
            "service": identity.get("services").unwrap_or(&serde_json::json!([]))
        });

        println!();
        println!("{}", serde_json::to_string_pretty(&doc)?);

        Ok(())
    }
}

/// Add a verifiable credential to an identity
#[derive(Debug, Parser)]
pub struct IdentityAddCredentialCmd {
    /// The DID to add the credential to
    did: String,

    /// Credential type (e.g. KycVerification, ModelAttestation)
    #[arg(long)]
    credential_type: String,

    /// Issuer DID
    #[arg(long)]
    issuer: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityAddCredentialCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Add Verifiable Credential");

        let spinner = output::create_spinner("Adding credential...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_addCredential", serde_json::json!([{
            "did": self.did,
            "credential_type": self.credential_type,
            "issuer": self.issuer,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Credential added successfully!");
        println!();
        output::print_field("Subject DID", &self.did);
        output::print_field("Type", &self.credential_type);
        output::print_field("Issuer", &self.issuer);
        if let Some(v) = result.get("credential_id").and_then(|v| v.as_str()) {
            output::print_field("Credential ID", v);
        }
        if let Some(v) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", v);
        }

        Ok(())
    }
}

/// Add a service endpoint to an identity
#[derive(Debug, Parser)]
pub struct IdentityAddServiceCmd {
    /// The DID to add the service to
    did: String,

    /// Service type (e.g. InferenceEndpoint, MessagingService)
    #[arg(long)]
    service_type: String,

    /// Service endpoint URL
    #[arg(long)]
    endpoint: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityAddServiceCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Add Service Endpoint");

        let spinner = output::create_spinner("Adding service...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_addService", serde_json::json!([{
            "did": self.did,
            "service_type": self.service_type,
            "endpoint": self.endpoint,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Service endpoint added!");
        println!();
        output::print_field("DID", &self.did);
        output::print_field("Service Type", &self.service_type);
        output::print_field("Endpoint", &self.endpoint);
        if let Some(v) = result.get("service_id").and_then(|v| v.as_str()) {
            output::print_field("Service ID", v);
        }
        if let Some(v) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", v);
        }

        Ok(())
    }
}

/// Resolve a DID to identity info
#[derive(Debug, Parser)]
pub struct IdentityResolveDidCmd {
    /// DID to resolve
    did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityResolveDidCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Resolve DID");
        let spinner = output::create_spinner("Resolving...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_resolveDid", serde_json::json!([self.did])).await?;
        spinner.finish_and_clear();
        output::print_field("DID", &self.did);
        if let Some(v) = result.get("identity_type").and_then(|v| v.as_str()) { output::print_field("Type", v); }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) { output::print_field("Status", v); }
        if let Some(v) = result.get("display_name").and_then(|v| v.as_str()) { output::print_field("Name", v); }
        if let Some(v) = result.get("wallet_address").and_then(|v| v.as_str()) { output::print_field("Wallet", v); }
        Ok(())
    }
}

/// Resolve a DID to W3C DID Document
#[derive(Debug, Parser)]
pub struct IdentityResolveDocumentCmd {
    /// DID to resolve
    did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityResolveDocumentCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Resolve DID Document");
        let spinner = output::create_spinner("Resolving...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_resolveDidDocument", serde_json::json!({"did": self.did}))
            .await?;
        spinner.finish_and_clear();
        println!();
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// Set delegation scope for a machine identity
#[derive(Debug, Parser)]
pub struct IdentitySetDelegationCmd {
    /// Machine DID
    did: String,
    /// Max transaction value, in whole TNZO (e.g. "1.5"). Converted to wei.
    #[arg(long)]
    max_tx_value: Option<String>,
    /// Max daily spend, in whole TNZO (e.g. "10"). Converted to wei.
    #[arg(long)]
    max_daily_spend: Option<String>,
    /// Allowed operations (comma-separated)
    #[arg(long)]
    allowed_ops: Option<String>,
    /// Allowed chains (comma-separated)
    #[arg(long)]
    allowed_chains: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentitySetDelegationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Set Delegation Scope");
        let spinner = output::create_spinner("Setting delegation...");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "did": self.did });
        if let Some(ref v) = self.max_tx_value {
            let wei = crate::units::tnzo_to_wei_string(v)?;
            params["max_transaction_value"] = serde_json::json!(wei);
        }
        if let Some(ref v) = self.max_daily_spend {
            let wei = crate::units::tnzo_to_wei_string(v)?;
            params["max_daily_spend"] = serde_json::json!(wei);
        }
        if let Some(ref v) = self.allowed_ops {
            let ops: Vec<&str> = v.split(',').map(|s| s.trim()).collect();
            params["allowed_operations"] = serde_json::json!(ops);
        }
        if let Some(ref v) = self.allowed_chains {
            let chains: Vec<&str> = v.split(',').map(|s| s.trim()).collect();
            params["allowed_chains"] = serde_json::json!(chains);
        }
        let _result: serde_json::Value = rpc.call("tenzro_setDelegationScope", serde_json::json!([params])).await?;
        spinner.finish_and_clear();
        output::print_success("Delegation scope updated!");
        output::print_field("DID", &self.did);
        Ok(())
    }
}

/// Register a new machine identity
#[derive(Debug, Parser)]
pub struct IdentityRegisterMachineCmd {
    /// Machine name
    #[arg(long)]
    name: String,
    /// Controller DID
    #[arg(long)]
    controller: String,
    /// Capabilities (comma-separated)
    #[arg(long)]
    capabilities: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityRegisterMachineCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Register Machine Identity");
        let spinner = output::create_spinner("Registering...");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "display_name": self.name,
            "identity_type": "machine",
            "controller": self.controller,
        });
        if let Some(ref caps) = self.capabilities {
            let caps: Vec<&str> = caps.split(',').map(|s| s.trim()).collect();
            params["capabilities"] = serde_json::json!(caps);
        }
        let result: serde_json::Value = rpc.call("tenzro_registerMachineIdentity", serde_json::json!([params])).await?;
        spinner.finish_and_clear();
        output::print_success("Machine identity registered!");
        if let Some(v) = result.get("did").and_then(|v| v.as_str()) { output::print_field("DID", v); }
        output::print_field("Controller", &self.controller);
        if let Some(v) = result.get("wallet_address").and_then(|v| v.as_str()) { output::print_field("Wallet", v); }
        Ok(())
    }
}

/// List the public JWK Set published by this node (RFC 7517)
#[derive(Debug, Parser)]
pub struct IdentityJwksCmd {
    /// Emit raw JSON (the JWK Set object) instead of a human-readable table
    #[arg(long)]
    json: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityJwksCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_listAgentJwks", serde_json::json!([])).await?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Public JWK Set");

        let keys = result.get("keys").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        if keys.is_empty() {
            output::print_info("No published keys.");
            return Ok(());
        }

        for jwk in &keys {
            println!();
            if let Some(kid) = jwk.get("kid").and_then(|v| v.as_str()) {
                output::print_field("kid", kid);
            }
            if let Some(kty) = jwk.get("kty").and_then(|v| v.as_str()) {
                output::print_field("kty", kty);
            }
            if let Some(alg) = jwk.get("alg").and_then(|v| v.as_str()) {
                output::print_field("alg", alg);
            }
            if let Some(crv) = jwk.get("crv").and_then(|v| v.as_str()) {
                output::print_field("crv", crv);
            }
            if let Some(use_) = jwk.get("use").and_then(|v| v.as_str()) {
                output::print_field("use", use_);
            }
        }

        println!();
        output::print_field("Total keys", &keys.len().to_string());
        Ok(())
    }
}

/// Look up a single JWK by `keyid` (RFC 9421 keyid resolution)
#[derive(Debug, Parser)]
pub struct IdentityJwksGetCmd {
    /// The `kid` to look up — typically `<did>#<key_fragment>`
    keyid: String,

    /// Emit raw JSON (the JWK object) instead of a human-readable table
    #[arg(long)]
    json: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityJwksGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getAgentJwk", serde_json::json!([self.keyid]))
            .await?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("JWK");
        if let Some(kid) = result.get("kid").and_then(|v| v.as_str()) {
            output::print_field("kid", kid);
        }
        if let Some(kty) = result.get("kty").and_then(|v| v.as_str()) {
            output::print_field("kty", kty);
        }
        if let Some(alg) = result.get("alg").and_then(|v| v.as_str()) {
            output::print_field("alg", alg);
        }
        if let Some(crv) = result.get("crv").and_then(|v| v.as_str()) {
            output::print_field("crv", crv);
        }
        if let Some(use_) = result.get("use").and_then(|v| v.as_str()) {
            output::print_field("use", use_);
        }
        if let Some(x) = result.get("x").and_then(|v| v.as_str()) {
            output::print_field("x", x);
        }
        if let Some(y) = result.get("y").and_then(|v| v.as_str()) {
            output::print_field("y", y);
        }
        if let Some(n) = result.get("n").and_then(|v| v.as_str()) {
            output::print_field("n", n);
        }
        if let Some(e) = result.get("e").and_then(|v| v.as_str()) {
            output::print_field("e", e);
        }
        Ok(())
    }
}

/// Revoke an identity (logical delete) — sets status to `Revoked` and
/// cascades JWT invalidation through the entire act-chain rooted at this
/// DID. Distinct from `forget` which is a hard-delete after revocation.
#[derive(Debug, Parser)]
pub struct IdentityRevokeCmd {
    /// The DID to revoke
    did: String,

    /// Optional reason for revocation (recorded in audit log)
    #[arg(long)]
    reason: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityRevokeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Revoke Identity");
        let spinner = output::create_spinner("Revoking DID...");

        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "did": self.did });
        if let Some(reason) = &self.reason {
            params["reason"] = serde_json::Value::String(reason.clone());
        }
        let result: serde_json::Value = rpc.call("tenzro_revokeDid", params).await?;

        spinner.finish_and_clear();
        output::print_success("Identity revoked");
        println!();
        output::print_field("DID", &self.did);
        if let Some(count) = result.get("affected_jti_count").and_then(|v| v.as_u64()) {
            output::print_field("Affected JTIs", &count.to_string());
        }
        if let Some(cascade) = result.get("cascade").and_then(|v| v.as_str()) {
            output::print_field("Cascade", cascade);
        }
        Ok(())
    }
}

/// TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously
/// revoked identity from the registry and persistent storage. The
/// identity must already be in `Revoked` status — call `revoke` first,
/// allow the cascading revocation to propagate, then call `forget`.
#[derive(Debug, Parser)]
pub struct IdentityForgetCmd {
    /// The DID to erase. Must already be in `Revoked` status.
    did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityForgetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Forget Identity (Article 17)");
        let spinner = output::create_spinner("Erasing identity record...");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_forgetIdentity", serde_json::json!({ "did": self.did }))
            .await?;

        spinner.finish_and_clear();
        output::print_success("Identity erased");
        println!();
        output::print_field("DID", &self.did);
        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", status);
        }
        if let Some(note) = result.get("note").and_then(|v| v.as_str()) {
            output::print_field("Note", note);
        }
        Ok(())
    }
}

/// Export a portable CARv1 identity bundle. The bundle contains the
/// TenzroIdentity (DID + credentials + delegations) plus the encrypted
/// keystore files for the bound MPC wallet (FROST shares, ML-DSA-65 seed,
/// BLS12-381 seed). The keystore files are exported as already-encrypted
/// ciphertext — the password never leaves the user's head, so the CAR
/// bundle can travel over insecure transport (email, USB stick, etc.).
#[derive(Debug, Parser)]
pub struct IdentityExportCarCmd {
    /// The DID to export
    did: String,

    /// Output path for the CAR file
    #[arg(long)]
    output: std::path::PathBuf,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityExportCarCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use base64::Engine as _;

        output::print_header("Export Identity (CARv1)");
        let spinner = output::create_spinner("Building bundle...");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_exportIdentityCar", serde_json::json!({ "did": self.did }))
            .await?;

        let car_base64 = result
            .get("car_base64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("RPC response missing car_base64"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(car_base64)
            .map_err(|e| anyhow::anyhow!("base64 decode failed: {e}"))?;
        std::fs::write(&self.output, &bytes)
            .map_err(|e| anyhow::anyhow!("write {}: {e}", self.output.display()))?;

        spinner.finish_and_clear();
        output::print_success("Bundle written");
        println!();
        output::print_field("DID", &self.did);
        output::print_field("Output", &self.output.display().to_string());
        output::print_field("Size (bytes)", &bytes.len().to_string());
        if let Some(wallet_id) = result.get("wallet_id").and_then(|v| v.as_str()) {
            output::print_field("Wallet ID", wallet_id);
        }
        Ok(())
    }
}

/// Import a portable CARv1 identity bundle previously produced by
/// `export-car`. Restores the TenzroIdentity into the registry and the
/// encrypted keystore files into the local wallet service. The original
/// keystore password (never embedded in the CAR) is required to actually
/// unlock the wallet afterward.
#[derive(Debug, Parser)]
pub struct IdentityImportCarCmd {
    /// Path to the CAR file to import
    #[arg(long)]
    input: std::path::PathBuf,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityImportCarCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use base64::Engine as _;

        output::print_header("Import Identity (CARv1)");
        let spinner = output::create_spinner("Restoring bundle...");

        let bytes = std::fs::read(&self.input)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", self.input.display()))?;
        let car_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_importIdentityCar",
                serde_json::json!({ "car_base64": car_base64 }),
            )
            .await?;

        spinner.finish_and_clear();
        output::print_success("Identity restored");
        println!();
        if let Some(did) = result.get("did").and_then(|v| v.as_str()) {
            output::print_field("DID", did);
        }
        if let Some(wid) = result.get("wallet_id").and_then(|v| v.as_str()) {
            output::print_field("Wallet ID", wid);
        }
        if let Some(addr) = result.get("wallet_address").and_then(|v| v.as_str()) {
            output::print_field("Wallet Address", addr);
        }
        if let Some(n) = result.get("credential_count").and_then(|v| v.as_u64()) {
            output::print_field("Credentials", &n.to_string());
        }
        if let Some(n) = result.get("imported_wallet_files").and_then(|v| v.as_u64()) {
            output::print_field("Wallet Files", &n.to_string());
        }
        Ok(())
    }
}
