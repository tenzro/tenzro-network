//! Function hosting commands for the Tenzro CLI.
//!
//! A function is a single `wasi:http` component (a `.wasm` file that exports the
//! `wasi:http/incoming-handler` proxy world) served over the same ingress path
//! as a static site. `deploy` uploads the component to the node's iroh blob
//! store and publishes a deployment record referencing its hash plus a
//! capability grant; the function then serves requests once a hostname resolves
//! to its id. TLS/DNS at the edge is automatic — no manual certificate setup.
//!
//! Mutating operations (deploy/remove) require a signed DID envelope proving
//! control of `owner_did`, supplied as the hex `--did-envelope` value produced
//! by the identity tooling.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::output;

/// Function hosting operations.
#[derive(Debug, Subcommand)]
pub enum FunctionCommand {
    /// Upload a `wasi:http` component and publish a deployment (owner-authenticated).
    Deploy(FunctionDeployCmd),
    /// Get a function deployment by id.
    Get(FunctionGetCmd),
    /// List function deployments, optionally filtered by owner DID.
    List(FunctionListCmd),
    /// Remove a function deployment (owner-authenticated).
    Remove(FunctionRemoveCmd),
}

impl FunctionCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Deploy(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Remove(cmd) => cmd.execute().await,
        }
    }
}

/// Deploy a `wasi:http` component.
#[derive(Debug, Parser)]
pub struct FunctionDeployCmd {
    /// Function name (owner-scoped; the id is derived from owner_did + name).
    #[arg(long)]
    name: String,
    /// Owner DID.
    #[arg(long)]
    owner_did: String,
    /// Path to the `wasi:http` component `.wasm` file to upload.
    #[arg(long)]
    wasm: PathBuf,
    /// Path to a JSON capability grant (storage/network/env/host_methods). When
    /// omitted the component runs with no ambient authority.
    #[arg(long)]
    capabilities: Option<PathBuf>,
    /// Per-request fuel budget (deterministic metering). Uses the node default
    /// when omitted.
    #[arg(long)]
    fuel_limit: Option<u64>,
    /// Per-request wall-clock deadline in milliseconds. Uses the node default
    /// when omitted.
    #[arg(long)]
    deadline_ms: Option<u64>,
    /// TNZO per request; when set, serving is x402-gated.
    #[arg(long)]
    price_per_request: Option<u128>,
    /// Number of distinct nodes to lease for this function. Defaults to 1.
    #[arg(long)]
    replicas: Option<u32>,
    /// Preferred region; ranked ahead of others during placement (not required).
    #[arg(long)]
    region_hint: Option<String>,
    /// Upper bound on a candidate node's per-hour TNZO price during placement.
    #[arg(long)]
    max_price_per_hour: Option<u128>,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FunctionDeployCmd {
    pub async fn execute(&self) -> Result<()> {
        use base64::Engine as _;
        use crate::rpc::RpcClient;
        use crate::commands::lease::print_placement;

        output::print_header("Deploy Function");
        if !self.wasm.is_file() {
            anyhow::bail!("not a file: {:?}", self.wasm);
        }
        let bytes = std::fs::read(&self.wasm).with_context(|| format!("read {:?}", self.wasm))?;

        let capabilities: serde_json::Value = match &self.capabilities {
            Some(path) => {
                let raw = std::fs::read_to_string(path)
                    .with_context(|| format!("read capabilities {path:?}"))?;
                serde_json::from_str(&raw)
                    .with_context(|| format!("parse capabilities {path:?}"))?
            }
            None => serde_json::json!({}),
        };

        let rpc = RpcClient::new(&self.rpc);

        // Upload the component as a content-addressed iroh blob.
        let spinner = output::create_spinner("Uploading component...");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_iroh_publishBlob",
                serde_json::json!({ "bytes_b64": b64 }),
            )
            .await
            .context("publish component blob")?;
        spinner.finish_and_clear();
        let uri = result
            .get("tenzro_uri")
            .and_then(|v| v.as_str())
            .context("publishBlob returned no tenzro_uri")?;
        // tenzro://blob/<blake3-hex> — the deployment stores the raw hash.
        let wasm_blob_hash = uri
            .rsplit('/')
            .next()
            .context("malformed tenzro_uri")?
            .to_string();
        output::print_field("Component size", &format!("{} bytes", bytes.len()));

        let mut params = serde_json::json!({
            "name": self.name,
            "owner_did": self.owner_did,
            "wasm_blob_hash": wasm_blob_hash,
            "capabilities": capabilities,
            "did_envelope": self.did_envelope,
        });
        if let Some(f) = self.fuel_limit {
            params["fuel_limit"] = serde_json::json!(f);
        }
        if let Some(d) = self.deadline_ms {
            params["deadline_ms"] = serde_json::json!(d);
        }
        if let Some(price) = self.price_per_request {
            params["price_per_request"] = serde_json::json!(price.to_string());
        }
        if let Some(r) = self.replicas {
            params["replicas"] = serde_json::json!(r);
        }
        if let Some(region) = &self.region_hint {
            params["region_hint"] = serde_json::json!(region);
        }
        if let Some(cap) = self.max_price_per_hour {
            params["max_price_per_hour"] = serde_json::json!(cap.to_string());
        }

        let spinner = output::create_spinner("Publishing deployment...");
        let deployment: serde_json::Value = rpc.call("tenzro_functionDeploy", params).await?;
        spinner.finish_and_clear();

        output::print_success("Function deployed");
        let id = deployment.get("id").and_then(|v| v.as_str()).unwrap_or("");
        output::print_field("Function ID", id);
        output::print_field(
            "Version",
            &deployment
                .get("version")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        print_placement(&deployment);
        output::print_info(
            "Point a hostname at this id with `tenzro site set-alias` to serve it publicly.",
        );
        Ok(())
    }
}

/// Get a function deployment.
#[derive(Debug, Parser)]
pub struct FunctionGetCmd {
    /// Function id.
    #[arg(long)]
    id: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FunctionGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let deployment: serde_json::Value = rpc
            .call("tenzro_functionGet", serde_json::json!({ "id": self.id }))
            .await?;
        output::print_json(&deployment)?;
        Ok(())
    }
}

/// List function deployments.
#[derive(Debug, Parser)]
pub struct FunctionListCmd {
    /// Filter by owner DID.
    #[arg(long)]
    owner_did: Option<String>,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FunctionListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({});
        if let Some(owner) = &self.owner_did {
            params["owner_did"] = serde_json::json!(owner);
        }
        let result: serde_json::Value = rpc.call("tenzro_listFunctions", params).await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Remove a function deployment.
#[derive(Debug, Parser)]
pub struct FunctionRemoveCmd {
    /// Function id.
    #[arg(long)]
    id: String,
    /// Owner DID.
    #[arg(long)]
    owner_did: String,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FunctionRemoveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_functionRemove",
                serde_json::json!({
                    "id": self.id,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Function removed");
        output::print_json(&result)?;
        Ok(())
    }
}
