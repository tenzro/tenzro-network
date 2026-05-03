//! Identity management commands for the Tenzro CLI
//!
//! Supports both TDIP (Tenzro Decentralized Identity Protocol) and PDIS (Personal Decentralized
//! Identity Standard) identities.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output::{self};

/// Identity management commands (TDIP + PDIS)
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

        let result: serde_json::Value = rpc.call("tenzro_resolveIdentity", serde_json::json!([self.did])).await?;

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
        let identity: serde_json::Value = rpc.call("tenzro_resolveIdentity", serde_json::json!([self.did])).await?;

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
        let result: serde_json::Value = rpc.call("tenzro_resolveDidDocument", serde_json::json!([self.did])).await?;
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
    /// Max transaction value (TNZO)
    #[arg(long)]
    max_tx_value: Option<String>,
    /// Max daily spend (TNZO)
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
        if let Some(ref v) = self.max_tx_value { params["max_transaction_value"] = serde_json::json!(v); }
        if let Some(ref v) = self.max_daily_spend { params["max_daily_spend"] = serde_json::json!(v); }
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
