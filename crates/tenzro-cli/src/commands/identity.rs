//! Identity management commands for the Tenzro CLI
//!
//! Supports TDIP (Tenzro Decentralized Identity Protocol) identities.

use crate::output::{self};
use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};

/// Identity management commands (TDIP)
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    #[command(flatten)]
    Rpc(IdentityRpcCommand),
    /// Register a new TDIP identity
    Register(IdentityRegisterCmd),
    /// Resolve a DID to its identity or W3C DID Document
    Resolve(IdentityResolveCmd),
    /// List locally known identities
    List(IdentityListCmd),
    /// Show W3C DID Document for a DID
    Document(IdentityDocumentCmd),
    /// Resolve a DID to identity info (alias for resolve)
    ResolveDid(IdentityResolveDidCmd),
    /// Resolve a DID to its W3C DID Document
    ResolveDocument(IdentityResolveDocumentCmd),
    /// Register a new machine identity
    RegisterMachine(IdentityRegisterMachineCmd),
    /// Register the on-chain identity of this CLI's own account; the account pays the gas
    RegisterAccount(IdentityRegisterAccountCmd),
    /// Revoke an identity on its root's authority (a RevokeIdentity transaction)
    Revoke(IdentityRevokeCmd),
    /// Revoke a single JWT by its `jti` (cascades through the act-chain)
    RevokeJwt(IdentityRevokeJwtCmd),
    /// Hard-delete a revoked identity (TDIP/GDPR Article 17 right-to-erasure)
    Forget(IdentityForgetCmd),
}

impl IdentityCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Register(cmd) => cmd.execute().await,
            Self::Resolve(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Document(cmd) => cmd.execute().await,
            Self::ResolveDid(cmd) => cmd.execute().await,
            Self::ResolveDocument(cmd) => cmd.execute().await,
            Self::RegisterMachine(cmd) => cmd.execute().await,
            Self::RegisterAccount(cmd) => cmd.execute().await,
            Self::Revoke(cmd) => cmd.execute().await,
            Self::RevokeJwt(cmd) => cmd.execute().await,
            Self::Forget(cmd) => cmd.execute().await,
        }
    }
}

/// Gas the registration of a client account is sent with.
const REGISTER_ACCOUNT_GAS: u64 = 200_000;

/// Register the identity of this CLI's own account on chain.
///
/// The commands of this CLI sign as the client account, held by this
/// machine's TPM or Secure Enclave under `--key-namespace`. A network that
/// requires a registered identity refuses a transaction from an account that
/// has none, so the account registers once before it sends anything else:
/// the machine identity that its hardware key derives, with the account as
/// its wallet. The same key signs the registration, and the account submits
/// it and pays the gas, so it must hold TNZO first; anyone may send TNZO to
/// an account that is not registered yet. Nothing is sent when the identity
/// already resolves.
///
/// No TPM attestation is recorded: the machine's TPM stays free to be
/// admitted under the machine root of a node running on it
/// (`tenzro validator register-machine`). A person registers with a passkey
/// instead (`tenzro identity register`).
#[derive(Debug, Parser)]
pub struct IdentityRegisterAccountCmd {
    /// Display name recorded with the identity
    #[arg(long, default_value = "client account")]
    name: String,

    /// The account's hardware key namespace (a-z, 0-9, '-', '_'). Each
    /// namespace is its own account.
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityRegisterAccountCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let (did, account, register) =
            crate::keystore::client_identity_registration(&self.key_namespace, &self.name)?;
        output::print_header("Register Account Identity");
        output::print_field("DID", &did);
        output::print_field("Account", &format!("0x{}", hex::encode(account)));
        if crate::keystore::identity_registered(&rpc, &did).await {
            output::print_info("already registered");
            return Ok(());
        }
        let answer = crate::keystore::send_as_client(
            &rpc,
            &self.key_namespace,
            [0u8; 32],
            register,
            REGISTER_ACCOUNT_GAS,
        )
        .await?;
        let tx_hash = crate::keystore::submitted_hash(&answer).ok_or_else(|| {
            anyhow::anyhow!("the node answered without a transaction hash: {answer}")
        })?;
        output::print_field("Transaction Hash", &tx_hash);
        let waited = crate::keystore::RECEIPT_WAIT;
        if crate::keystore::await_receipt(&rpc, &tx_hash, waited)
            .await?
            .is_none()
        {
            anyhow::bail!(
                "the registration was in no block after {} seconds; run this again to see \
                 whether it is registered",
                waited.as_secs()
            );
        }
        crate::keystore::await_identity(&rpc, &did).await?;
        output::print_success("account identity registered");
        Ok(())
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

    /// Controller DID (required for machine identities; it signs the registration)
    #[arg(long, required_if_eq("identity_type", "machine"))]
    controller: Option<String>,

    /// Machine P-256 public key, hex x || y from its TPM or Secure Enclave
    #[arg(long, required_if_eq("identity_type", "machine"))]
    public_key: Option<String>,

    /// Machine capabilities, comma-separated
    #[arg(long, required_if_eq("identity_type", "machine"))]
    capabilities: Option<String>,

    /// Hardware key namespace of the controller account that signs a machine registration
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "https://rpc.tenzro.com")]
    rpc: String,
}

/// Registers a human identity at `rpc`, signed by the person's passkey: the
/// node opens a passkey enrolment session and the passkey answers it in the
/// browser, so the key that roots the identity never leaves its hardware.
pub async fn register_human(rpc: &str, name: &str) -> Result<()> {
    output::print_header("Register Identity");
    let client = crate::rpc::RpcClient::new(rpc);
    crate::commands::passkey::LoginCmd {
        display_name: Some(name.to_string()),
        salt: 0,
        web_url: None,
    }
    .execute(&client, rpc)
    .await
}

/// The method a controller-signed machine registration is sent as.
pub(crate) const REGISTER_MACHINE_METHOD: &str = "tenzro_registerMachineIdentity";

/// A machine registration under `controller`, carrying the controller's DID
/// envelope by `signer` over every field. The machine acts for its
/// controller and draws on its admission quota, so the node refuses it
/// without that envelope.
pub(crate) fn controller_signed_machine_request(
    signer: &impl tenzro_crypto::composite::HybridSigner,
    controller: &str,
    public_key: &str,
    capabilities: &str,
) -> Result<serde_json::Value> {
    let capabilities: Vec<String> = capabilities
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut request = serde_json::json!({
        "controller_did": controller,
        "public_key": public_key,
        "capabilities": capabilities,
    });
    let envelope = crate::keystore::did_envelope_by(
        signer,
        controller,
        REGISTER_MACHINE_METHOD,
        &tenzro_identity::envelope::request_binding(&request),
    )?;
    request["did_envelope"] = envelope.into();
    Ok(request)
}

impl IdentityRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        if self.identity_type.eq_ignore_ascii_case("machine") {
            return self.register_machine().await;
        }
        if !self.identity_type.eq_ignore_ascii_case("human") {
            anyhow::bail!(
                "--identity-type is human or machine; a machine that answers for itself \
                 registers with `tenzro setup --operator autonomous`, and this CLI's own account \
                 with `tenzro identity register-account`"
            );
        }
        register_human(&self.rpc, &self.name).await
    }

    /// Register a machine under `--controller`, signed by the controller's
    /// hardware key.
    async fn register_machine(&self) -> Result<()> {
        let required = |v: &Option<String>, name: &str| {
            v.clone()
                .ok_or_else(|| anyhow::anyhow!("--{name} is required for a machine identity"))
        };
        let controller = required(&self.controller, "controller")?;
        output::print_header("Register Machine Identity");
        let signer = crate::keystore::client_signer(&self.key_namespace)?;
        let request = controller_signed_machine_request(
            &signer,
            &controller,
            &required(&self.public_key, "public-key")?,
            &required(&self.capabilities, "capabilities")?,
        )?;
        let spinner = output::create_spinner("Registering...");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call(REGISTER_MACHINE_METHOD, request).await?;
        spinner.finish_and_clear();
        output::print_success("Machine identity registered!");
        if let Some(did) = result.get("did").and_then(|v| v.as_str()) {
            output::print_field("DID", did);
        }
        output::print_field("Controller", &controller);
        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", status);
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
    #[arg(long, default_value = "https://rpc.tenzro.com")]
    rpc: String,
}

impl IdentityResolveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Resolve Identity");

        let spinner = output::create_spinner("Resolving DID...");

        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call(
                "tenzro_resolveIdentity",
                serde_json::json!({"did": self.did}),
            )
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
    #[arg(long, default_value = "https://rpc.tenzro.com")]
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
        }])).await?;

        spinner.finish_and_clear();

        if identities.is_empty() {
            output::print_info(
                "No identities found. Register one with: tenzro-cli identity register --name <name>",
            );
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
            }
            println!();
        } else {
            let headers = vec!["DID", "Type", "Name", "Status"];
            let mut rows = Vec::new();
            for identity in &identities {
                rows.push(vec![
                    identity
                        .get("did")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    identity
                        .get("identity_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    identity
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed")
                        .to_string(),
                    identity
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
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
            .call(
                "tenzro_resolveIdentity",
                serde_json::json!({"did": self.did}),
            )
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
        let result: serde_json::Value = rpc
            .call("tenzro_resolveIdentity", serde_json::json!([self.did]))
            .await?;
        spinner.finish_and_clear();
        output::print_field("DID", &self.did);
        if let Some(v) = result.get("identity_type").and_then(|v| v.as_str()) {
            output::print_field("Type", v);
        }
        if let Some(v) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", v);
        }
        if let Some(v) = result.get("display_name").and_then(|v| v.as_str()) {
            output::print_field("Name", v);
        }
        if let Some(v) = result.get("wallet_address").and_then(|v| v.as_str()) {
            output::print_field("Wallet", v);
        }
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
            .call(
                "tenzro_resolveDidDocument",
                serde_json::json!({"did": self.did}),
            )
            .await?;
        spinner.finish_and_clear();
        println!();
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// Register a new machine identity.
///
/// The controller signs the whole request, so it is made in two steps:
/// `--request-out <file>` writes the request and prints the `params_hash` to
/// sign with the controller's key; `--request-in <file> --did-envelope <hex>`
/// sends it.
#[derive(Debug, Parser)]
pub struct IdentityRegisterMachineCmd {
    /// Controller DID: who the machine acts for and who signs the request
    #[arg(long, required_unless_present = "request_in")]
    controller: Option<String>,
    /// The machine's public key (hex), from its TPM or Secure Enclave
    #[arg(long, required_unless_present = "request_in")]
    public_key: Option<String>,
    /// Capabilities (comma-separated)
    #[arg(long, required_unless_present = "request_in")]
    capabilities: Option<String>,
    /// Write the prepared request here and print the `params_hash` to sign
    #[arg(
        long,
        conflicts_with = "request_in",
        required_unless_present = "request_in"
    )]
    request_out: Option<std::path::PathBuf>,
    /// Send a request prepared with `--request-out`
    #[arg(long, requires = "did_envelope")]
    request_in: Option<std::path::PathBuf>,
    /// Hex DID envelope by the controller over the prepared request
    #[arg(long, requires = "request_in")]
    did_envelope: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityRegisterMachineCmd {
    /// The request the controller signs.
    fn prepare(&self) -> Result<serde_json::Value> {
        let required = |v: &Option<String>, name: &str| {
            v.clone()
                .ok_or_else(|| anyhow::anyhow!("--{name} is required to prepare the request"))
        };
        let caps: Vec<String> = required(&self.capabilities, "capabilities")?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(serde_json::json!({
            "controller_did": required(&self.controller, "controller")?,
            "public_key": required(&self.public_key, "public-key")?,
            "capabilities": caps,
        }))
    }

    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Register Machine Identity");

        let Some(request) = &self.request_in else {
            let out = self
                .request_out
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--request-out is required"))?;
            return crate::commands::signed_request::write_for_signing(
                "tenzro_registerMachineIdentity",
                &self.prepare()?,
                out,
            );
        };
        let envelope = self
            .did_envelope
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--did-envelope is required"))?;
        let spinner = output::create_spinner("Registering...");
        let rpc = RpcClient::new(&self.rpc);
        let result = crate::commands::signed_request::submit(
            &rpc,
            "tenzro_registerMachineIdentity",
            request,
            envelope,
        )
        .await?;
        spinner.finish_and_clear();
        output::print_success("Machine identity registered!");
        if let Some(v) = result.get("did").and_then(|v| v.as_str()) {
            output::print_field("DID", v);
        }
        if let Some(v) = result.get("controller_did").and_then(|v| v.as_str()) {
            output::print_field("Controller", v);
        }
        if let Some(v) = result.get("wallet_address").and_then(|v| v.as_str()) {
            output::print_field("Wallet", v);
        }
        Ok(())
    }
}

/// Revoke an identity on its root's authority: a root revokes itself (with
/// its passkey, or a machine with its hardware key), a delegated agent is
/// revoked by its controller, and a machine a root registered by that root.
/// The CLI signs a `RevokeIdentity` transaction carrying the approval with
/// the client account and submits it; the node checks the approval before
/// admitting it and every validator re-verifies it. Revoking a root also
/// revokes every agent it delegated. Distinct from `forget`, which is a
/// hard-delete after revocation.
///
/// The approval answers a `revoke_identity` custody challenge over
/// `revocation_target(did, reason)` on the approver's account
/// (`tenzro_createCustodyChallenge` with that `target_hex`), as chain state
/// carries it: `{account, nonce, root_public_key, signature}`.
#[derive(Debug, Parser)]
pub struct IdentityRevokeCmd {
    /// The DID to revoke
    did: String,

    /// Reason recorded with the revocation; the approval covers it, so it must
    /// be the reason the challenge was issued for
    #[arg(long)]
    reason: Option<String>,

    /// The approving root's DID; the DID itself when absent
    #[arg(long)]
    approver: Option<String>,

    /// JSON file with the approving root's approval of the challenge
    #[arg(long)]
    approval: std::path::PathBuf,

    /// Hardware key namespace of the account that sends the transaction
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// Gas for the transaction; a root with many agents needs more
    #[arg(long, default_value_t = crate::keystore::DEFAULT_REVOCATION_GAS)]
    gas_limit: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityRevokeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Revoke Identity");
        let op = revocation_op(
            &self.did,
            self.reason.as_deref(),
            self.approver.as_deref().unwrap_or(&self.did),
            &self.approval,
        )?;
        let spinner = output::create_spinner("Signing and submitting the revocation...");
        let rpc = RpcClient::new(&self.rpc);
        let result =
            crate::keystore::send_revocation(&rpc, &self.key_namespace, &op, self.gas_limit)
                .await?;

        spinner.finish_and_clear();
        output::print_success("Revocation admitted");
        println!();
        output::print_field("DID", &self.did);
        if let Some(v) = result.get("approver_did").and_then(|v| v.as_str()) {
            output::print_field("Approver", v);
        }
        if let Some(v) = result.get("tx_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction", v);
        }
        Ok(())
    }
}

/// The `RevokeIdentity` operation for `did`, approved by `approver_did` with
/// the approval read from `approval`.
pub(crate) fn revocation_op(
    did: &str,
    reason: Option<&str>,
    approver_did: &str,
    approval: &std::path::Path,
) -> Result<tenzro_types::identity::IdentityRevocationOp> {
    let approval: tenzro_types::agent_terms::AgentTermsApproval =
        serde_json::from_str(&std::fs::read_to_string(approval)?)?;
    let op = tenzro_types::identity::IdentityRevocationOp {
        did: did.to_string(),
        reason: reason
            .unwrap_or(tenzro_types::identity::DEFAULT_REVOCATION_REASON)
            .to_string(),
        approver_did: approver_did.to_string(),
        approval,
    };
    op.validate().map_err(|e| anyhow::anyhow!(e))?;
    Ok(op)
}

/// Revoke a single JWT by its `jti`. Unlike `revoke` (which invalidates
/// every token in an entire DID's act-chain), this targets one specific
/// token id — the revocation still cascades transitively to any tokens
/// that were issued *by* the revoked token's act-chain.
///
/// Requires a signed DID envelope from the token's bearer or its
/// controller. A `jti` is not a secret, so knowing one is not authority
/// to destroy it.
#[derive(Debug, Parser)]
pub struct IdentityRevokeJwtCmd {
    /// The JWT id (`jti`) to revoke.
    jti: String,

    /// Optional reason for revocation (recorded in the audit log).
    #[arg(long)]
    reason: Option<String>,

    /// Hex DID envelope proving control of the token's bearer DID or of
    /// the controller DID that authorized it. Must be bound to method
    /// `tenzro_revokeJwt` with the jti as the params hash.
    #[arg(long)]
    did_envelope: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityRevokeJwtCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Revoke JWT");
        let spinner = output::create_spinner("Revoking token...");

        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "jti": self.jti,
            "did_envelope": self.did_envelope,
        });
        if let Some(reason) = &self.reason {
            params["reason"] = serde_json::Value::String(reason.clone());
        }
        let result: serde_json::Value = rpc.call("tenzro_revokeJwt", params).await?;

        spinner.finish_and_clear();
        output::print_success("Token revoked");
        println!();
        output::print_field("JTI", &self.jti);
        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
            output::print_field("Status", status);
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
            .call(
                "tenzro_forgetIdentity",
                serde_json::json!({ "did": self.did }),
            )
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

/// Identity commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum IdentityRpcCommand {
    /// Call tenzro_verifyDidEnvelope (verify did envelope) and print the node's answer
    VerifyEnvelope(IdentityVerifyEnvelopeRpcCmd),
    /// Call tenzro_verifyKyaCredential (verify kya credential) and print the node's answer
    VerifyKyaCredential(IdentityVerifyKyaCredentialRpcCmd),
    /// Call tenzro_verifyNodeDidDocument (verify node did document) and print the node's answer
    VerifyDidDocument(IdentityVerifyDidDocumentRpcCmd),
    /// Call tenzro_get7702Delegation (get7702 delegation) and print the node's answer
    Delegation7702(IdentityDelegation7702RpcCmd),
    /// Call tenzro_issueKyaCredential (issue kya credential) and print the node's answer
    IssueKyaCredential(IdentityIssueKyaCredentialRpcCmd),
    /// Add a resource to a DID (tenzro_updateIdentity, operator only)
    Update(IdentityUpdateRpcCmd),
    /// Publish or remove a service entry of a machine DID's document, approved
    /// by the machine's identity key (an IdentityServices transaction)
    Service(IdentityServiceCmd),
    /// Show the service entries of a DID's document from consensus state (tenzro_getDidServices)
    Services(IdentityServicesCmd),
    /// Hand the identity to a hardware ML-DSA-65 key (tenzro_rotateIdentityToPq)
    RotateToPq(IdentityRotateToPqRpcCmd),
}

impl IdentityRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::VerifyEnvelope(cmd) => cmd.execute().await,
            Self::VerifyKyaCredential(cmd) => cmd.execute().await,
            Self::VerifyDidDocument(cmd) => cmd.execute().await,
            Self::Delegation7702(cmd) => cmd.execute().await,
            Self::IssueKyaCredential(cmd) => cmd.execute().await,
            Self::Service(cmd) => cmd.execute().await,
            Self::Services(cmd) => cmd.execute().await,
            Self::Update(cmd) => cmd.execute().await,
            Self::RotateToPq(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_verifyDidEnvelope (verify did envelope)
#[derive(Debug, clap::Parser)]
pub struct IdentityVerifyEnvelopeRpcCmd {
    /// envelope (JSON)
    #[arg(long)]
    envelope: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityVerifyEnvelopeRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let envelope_v: serde_json::Value =
            serde_json::from_str(&self.envelope).context("--envelope is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyDidEnvelope",
                serde_json::json!({ "envelope": envelope_v }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_verifyKyaCredential (verify kya credential)
#[derive(Debug, clap::Parser)]
pub struct IdentityVerifyKyaCredentialRpcCmd {
    /// credential (JSON)
    #[arg(long)]
    credential: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityVerifyKyaCredentialRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let credential: serde_json::Value =
            serde_json::from_str(&self.credential).context("--credential is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyKyaCredential",
                serde_json::json!({ "credential": credential }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_verifyNodeDidDocument (verify node did document)
#[derive(Debug, clap::Parser)]
pub struct IdentityVerifyDidDocumentRpcCmd {
    /// document (JSON)
    #[arg(long)]
    document: String,
    /// id
    #[arg(long)]
    id: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityVerifyDidDocumentRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let document: serde_json::Value =
            serde_json::from_str(&self.document).context("--document is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyNodeDidDocument",
                serde_json::json!({ "document": document, "id": self.id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_get7702Delegation (get7702 delegation)
#[derive(Debug, clap::Parser)]
pub struct IdentityDelegation7702RpcCmd {
    /// authority
    #[arg(long)]
    authority: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityDelegation7702RpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_get7702Delegation",
                serde_json::json!({ "authority": self.authority }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_issueKyaCredential (issue kya credential)
#[derive(Debug, clap::Parser)]
pub struct IdentityIssueKyaCredentialRpcCmd {
    /// did
    #[arg(long)]
    did: String,
    /// validity secs
    #[arg(long)]
    validity_secs: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityIssueKyaCredentialRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_issueKyaCredential",
                serde_json::json!({ "did": self.did, "validity_secs": self.validity_secs }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Update a DID: add a resource. Service entries are consensus state: see `identity service`.
#[derive(Debug, clap::Parser)]
pub struct IdentityUpdateRpcCmd {
    /// The DID to update
    #[arg(long)]
    did: String,
    /// The update (JSON) with its `kind`:
    /// `{"kind":"resource","resource_type":..,"resource_id":..}`
    #[arg(long)]
    update: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityUpdateRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let update: serde_json::Value =
            serde_json::from_str(&self.update).context("--update is not JSON")?;
        match update.get("kind").and_then(|v| v.as_str()) {
            Some("resource") => {}
            Some(other) => anyhow::bail!("unknown update kind {other}: expected resource"),
            None => anyhow::bail!("--update has no `kind`"),
        }
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_updateIdentity",
                serde_json::json!({ "did": self.did, "update": update }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Publish or remove a service entry of a machine DID's document. The
/// machine's identity key approves the change for the current version of the
/// DID's service list, and the account under `--key-namespace` sends and pays
/// for it. A human DID's services are approved by one of its passkeys, in a
/// wallet.
#[derive(Debug, clap::Parser)]
pub struct IdentityServiceCmd {
    /// The machine DID whose document changes
    #[arg(long)]
    did: String,
    /// The service id fragment (`<did>#<id>`)
    #[arg(long)]
    id: String,
    /// The service type, for example LinkedDomains; required unless --remove
    #[arg(long)]
    service_type: Option<String>,
    /// The service endpoint URL; required unless --remove
    #[arg(long)]
    endpoint: Option<String>,
    /// Remove the entry instead of publishing it
    #[arg(long)]
    remove: bool,
    /// The machine's node key namespace (its identity key); the default node when omitted
    #[arg(long)]
    machine_namespace: Option<String>,
    /// The hardware key namespace of the account that sends and pays
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityServiceCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        use tenzro_types::did_services::{
            DidServiceChange, DidServiceEntry, IdentityServiceOp, OP_DID_SERVICE,
        };
        let change = if self.remove {
            DidServiceChange::Remove {
                id: self.id.clone(),
            }
        } else {
            DidServiceChange::Set {
                service: DidServiceEntry {
                    id: self.id.clone(),
                    service_type: self
                        .service_type
                        .clone()
                        .context("--service-type is required")?,
                    endpoint: self.endpoint.clone().context("--endpoint is required")?,
                },
            }
        };
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let current: serde_json::Value = rpc
            .call(
                "tenzro_getDidServices",
                serde_json::json!({ "did": self.did }),
            )
            .await?;
        let version = current.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        let (account, _) = crate::keystore::client_account(&self.key_namespace)?;
        let to: [u8; 32] = hex::decode(account.trim_start_matches("0x"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("the client account is 32 bytes"))?;
        let target = tenzro_types::did_services::service_change_target(&self.did, version, &change);
        let chain_id = crate::rpc::fetch_chain_id(&rpc).await?;
        let approval = crate::keystore::machine_root_approval(
            self.machine_namespace.as_deref(),
            chain_id,
            OP_DID_SERVICE,
            &target,
            &to,
        )?;
        let op = IdentityServiceOp {
            did: self.did.clone(),
            version,
            change,
            approval,
        };
        op.validate().map_err(|e| anyhow::anyhow!(e))?;
        let tx_type = serde_json::to_value(
            tenzro_types::transaction::TransactionType::IdentityServices { op },
        )?;
        let result =
            crate::keystore::send_as_client(&rpc, &self.key_namespace, to, tx_type, 150_000)
                .await?;
        crate::output::print_success(
            "Service change approved by the machine's identity key and submitted",
        );
        crate::output::print_field(
            "Tx Hash",
            &result
                .as_str()
                .map_or_else(|| result.to_string(), str::to_string),
        );
        Ok(())
    }
}

/// Show the service entries of a DID's document from consensus state.
#[derive(Debug, clap::Parser)]
pub struct IdentityServicesCmd {
    /// The DID
    did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityServicesCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getDidServices",
                serde_json::json!({ "did": self.did }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Hand an identity's authority to this machine's hardware ML-DSA-65 key. The
/// P-256 key the DID derives from signs the rotation, and the new key signs it
/// to prove possession. Both are held in hardware; a machine whose hardware
/// cannot hold an ML-DSA-65 key is refused.
#[derive(Debug, clap::Parser)]
pub struct IdentityRotateToPqRpcCmd {
    /// The DID to rotate
    #[arg(long)]
    did: String,
    /// The rotation's sequence number: one more than the last rotation (1 for the first)
    #[arg(long, default_value_t = 1)]
    sequence: u64,
    /// The hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IdentityRotateToPqRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        use tenzro_identity::pq_rotation::{PqKeyBackend, PqRotation};
        let label = format!("client/{}/ml-dsa-65", self.key_namespace);
        let pq = tenzro_device_key::signer::open_or_create_ml_dsa(
            &label,
            tenzro_types::signature_scheme::SignatureScheme::MlDsa65P256,
        )
        .map_err(|e| anyhow::anyhow!("the new ML-DSA-65 key: {e}"))?;
        let backend = match pq.backend() {
            tenzro_device_key::HardwareBackend::Tpm => PqKeyBackend::Tpm,
            tenzro_device_key::HardwareBackend::SecureEnclave => PqKeyBackend::SecureEnclave,
            tenzro_device_key::HardwareBackend::RemoteTpm => {
                anyhow::bail!("an ML-DSA-65 key is not held through a remote TPM")
            }
        };
        let new_pq_key = pq
            .verifying_key()
            .map_err(|e| anyhow::anyhow!("reading the ML-DSA-65 key: {e}"))?;
        let statement = PqRotation::statement(&self.did, &new_pq_key, backend, self.sequence);
        let new_key_signature = pq
            .sign(tenzro_crypto::pq::context::PQ_ROTATION, &statement)
            .map_err(|e| anyhow::anyhow!("signing with the ML-DSA-65 key: {e}"))?;
        let (_, authority_signature, _) =
            crate::keystore::sign_p256(&self.key_namespace, &statement)?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_rotateIdentityToPq",
                serde_json::json!({
                    "did": self.did,
                    "new_pq_key": hex::encode(&new_pq_key),
                    "backend": backend.as_str(),
                    "sequence": self.sequence,
                    "authority_signature": hex::encode(authority_signature),
                    "new_key_signature": hex::encode(new_key_signature),
                }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::HybridSigner as _;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_identity::envelope::{
        TenzroDidEnvelope, params_hash, request_binding, verify_envelope_with_key,
    };

    const CONTROLLER: &str = "did:tenzro:human:controller";

    /// The envelope the CLI attaches is the controller's, names the method
    /// it is sent as, and binds every field sent beside it, as the node's
    /// own envelope verifier reads it.
    #[test]
    fn a_machine_registration_carries_the_controllers_envelope() {
        let controller = TestHybridSigner::p256_only(0x41);
        let request = controller_signed_machine_request(
            &controller,
            CONTROLLER,
            &"ab".repeat(64),
            "inference, transfer",
        )
        .unwrap();
        assert_eq!(
            request["capabilities"],
            serde_json::json!(["inference", "transfer"])
        );
        let env = TenzroDidEnvelope::from_header_value(request["did_envelope"].as_str().unwrap())
            .unwrap();
        assert_eq!(env.did, CONTROLLER);
        assert_eq!(env.method, REGISTER_MACHINE_METHOD);
        assert_eq!(env.params_hash, params_hash(&request_binding(&request)));
        verify_envelope_with_key(&env, &controller.public_key().p256)
            .expect("the controller's key verifies it");
        let other = TestHybridSigner::p256_only(0x43);
        assert!(
            verify_envelope_with_key(&env, &other.public_key().p256).is_err(),
            "no other key verifies it"
        );

        let mut swapped = request.clone();
        swapped["public_key"] = serde_json::json!("cd".repeat(64));
        assert_ne!(
            env.params_hash,
            params_hash(&request_binding(&swapped)),
            "the envelope does not cover another machine key"
        );
    }

    /// A machine identity needs its controller, its key and its capabilities.
    #[test]
    fn a_machine_registration_without_its_fields_is_refused() {
        let parse = |args: &[&str]| {
            IdentityRegisterCmd::try_parse_from(
                [
                    &["register", "--name", "m", "--identity-type", "machine"],
                    args,
                ]
                .concat(),
            )
        };
        assert!(parse(&[]).is_err());
        assert!(parse(&["--controller", CONTROLLER, "--capabilities", "x"]).is_err());
        assert!(
            parse(&[
                "--controller",
                CONTROLLER,
                "--public-key",
                "ab",
                "--capabilities",
                "x"
            ])
            .is_ok()
        );
        assert!(IdentityRegisterCmd::try_parse_from(["register", "--name", "h"]).is_ok());
    }
}

#[cfg(test)]
mod public_network_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: IdentityCommand,
    }

    #[test]
    fn identity_commands_default_to_the_public_network() {
        for args in [
            vec!["t", "register", "--name", "a"],
            vec!["t", "resolve", "did:tenzro:human:x"],
            vec!["t", "list"],
        ] {
            let rpc = match Cli::try_parse_from(args).unwrap().cmd {
                IdentityCommand::Register(c) => c.rpc,
                IdentityCommand::Resolve(c) => c.rpc,
                IdentityCommand::List(c) => c.rpc,
                _ => unreachable!(),
            };
            assert_eq!(rpc, "https://rpc.tenzro.com");
        }
    }

    /// A node that refuses every call and records the methods asked for.
    async fn refusing_node() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let log = log.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let start = loop {
                        let n = sock.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..start]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    while buf.len() < start + len {
                        let n = sock.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let req: serde_json::Value = serde_json::from_slice(&buf[start..]).unwrap();
                    log.lock()
                        .unwrap()
                        .push(req["method"].as_str().unwrap_or("").to_string());
                    let body = serde_json::json!({
                        "jsonrpc": "2.0", "id": req["id"],
                        "error": { "code": -32000, "message": "refused" },
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        (url, seen)
    }

    /// A human registers through a passkey enrolment session the passkey
    /// signs; the command never asks the node to register an identity
    /// without a signature.
    #[tokio::test]
    async fn a_human_registration_asks_for_a_passkey_session_not_an_unsigned_record() {
        let (url, seen) = refusing_node().await;
        let cmd = Cli::try_parse_from(["t", "register", "--name", "alice", "--rpc", url.as_str()])
            .unwrap()
            .cmd;
        assert!(cmd.execute().await.is_err());
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen, vec!["tenzro_createPasskeySession".to_string()]);
    }

    #[tokio::test]
    async fn listing_reports_a_node_error_instead_of_an_empty_list() {
        let (url, _) = refusing_node().await;
        let cmd = Cli::try_parse_from(["t", "list", "--rpc", url.as_str()])
            .unwrap()
            .cmd;
        assert!(cmd.execute().await.is_err());
    }
}
