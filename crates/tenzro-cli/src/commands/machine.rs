//! Machine hosting commands for the Tenzro CLI.
//!
//! A machine is an unmodified long-lived server (Node, Python, Rust, Go — any
//! process that binds a loopback port) run inside a hardware-virtualized
//! Firecracker microVM on an operator node that has KVM + nested virtualization.
//! `deploy` uploads the microVM image to the node's iroh blob store and
//! publishes a deployment record referencing its content-addressed id, the
//! internal port the guest server listens on, and (optionally) a set of sealed
//! environment secrets. The machine then serves requests once a hostname
//! resolves to its id. TLS/DNS at the edge is automatic — no manual certificate
//! setup.
//!
//! Environment secrets are sealed client-side: `deploy` fetches the assigned
//! node's X25519 sealing public key, HPKE/envelope-wraps each value to it, and
//! ships only the ciphertext. The plaintext never leaves this machine.
//!
//! Mutating operations (deploy/remove) require a signed DID envelope proving
//! control of `owner_did`, supplied as the hex `--did-envelope` value produced
//! by the identity tooling.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::output;

/// Machine hosting operations.
#[derive(Debug, Subcommand)]
pub enum MachineCommand {
    /// Upload a microVM image and publish a deployment (owner-authenticated).
    Deploy(MachineDeployCmd),
    /// Get a machine deployment by id.
    Get(MachineGetCmd),
    /// List machine deployments, optionally filtered by owner DID.
    List(MachineListCmd),
    /// Remove a machine deployment (owner-authenticated).
    Remove(MachineRemoveCmd),
    /// Report the runtime status of a machine deployment.
    Status(MachineStatusCmd),
}

impl MachineCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Deploy(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Remove(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
        }
    }
}

/// Deploy a microVM machine.
#[derive(Debug, Parser)]
pub struct MachineDeployCmd {
    /// Machine name (owner-scoped; the id is derived from owner_did + name).
    #[arg(long)]
    name: String,
    /// Owner DID.
    #[arg(long)]
    owner_did: String,
    /// Path to the microVM image (rootfs/ext4 or packaged bundle) to upload.
    #[arg(long)]
    image: PathBuf,
    /// Loopback port the guest server listens on (1-65535).
    #[arg(long)]
    internal_port: u16,
    /// Guest vCPU count. Uses the node default when omitted.
    #[arg(long)]
    vcpus: Option<u32>,
    /// Guest memory in MiB. Uses the node default when omitted.
    #[arg(long)]
    mem_mib: Option<u32>,
    /// Guest disk in MiB. Uses the node default when omitted.
    #[arg(long)]
    disk_mib: Option<u32>,
    /// Path to a JSON file `{"KEY":"value"}` of environment secrets to seal to
    /// the assigned node before deploying. The plaintext never leaves this host.
    #[arg(long)]
    env: Option<PathBuf>,
    /// Require the assigned node to run the microVM inside a TEE.
    #[arg(long)]
    tee_required: bool,
    /// TNZO per request; when set, serving is x402-gated.
    #[arg(long)]
    price_per_request: Option<u128>,
    /// Number of distinct nodes to lease for this deployment. Defaults to 1.
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

impl MachineDeployCmd {
    pub async fn execute(&self) -> Result<()> {
        use base64::Engine as _;
        use crate::rpc::RpcClient;
        use crate::commands::lease::print_placement;

        output::print_header("Deploy Machine");
        if !self.image.is_file() {
            anyhow::bail!("not a file: {:?}", self.image);
        }
        let bytes = std::fs::read(&self.image).with_context(|| format!("read {:?}", self.image))?;

        let rpc = RpcClient::new(&self.rpc);

        // Seal environment secrets to the assigned node's X25519 sealing key.
        let sealed_env = self.seal_env(&rpc).await?;

        // Upload the microVM image as a content-addressed iroh blob.
        let spinner = output::create_spinner("Uploading microVM image...");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_iroh_publishBlob",
                serde_json::json!({ "bytes_b64": b64 }),
            )
            .await
            .context("publish machine image blob")?;
        spinner.finish_and_clear();
        let uri = result
            .get("tenzro_uri")
            .and_then(|v| v.as_str())
            .context("publishBlob returned no tenzro_uri")?;
        // tenzro://blob/<blake3-hex> — the deployment stores the raw hash.
        let artifact_caid = uri
            .rsplit('/')
            .next()
            .context("malformed tenzro_uri")?
            .to_string();
        output::print_field("Image size", &format!("{} bytes", bytes.len()));
        if !sealed_env.is_empty() {
            output::print_field("Sealed secrets", &sealed_env.len().to_string());
        }

        let mut params = serde_json::json!({
            "name": self.name,
            "owner_did": self.owner_did,
            "artifact_caid": artifact_caid,
            "internal_port": self.internal_port,
            "sealed_env": sealed_env,
            "tee_required": self.tee_required,
            "did_envelope": self.did_envelope,
        });
        let mut resources = serde_json::Map::new();
        if let Some(v) = self.vcpus {
            resources.insert("vcpus".into(), serde_json::json!(v));
        }
        if let Some(m) = self.mem_mib {
            resources.insert("mem_mib".into(), serde_json::json!(m));
        }
        if let Some(d) = self.disk_mib {
            resources.insert("disk_mib".into(), serde_json::json!(d));
        }
        if !resources.is_empty() {
            params["resources"] = serde_json::Value::Object(resources);
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
        let deployment: serde_json::Value = rpc.call("tenzro_machineDeploy", params).await?;
        spinner.finish_and_clear();

        output::print_success("Machine deployed");
        let id = deployment.get("id").and_then(|v| v.as_str()).unwrap_or("");
        output::print_field("Machine ID", id);
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

    /// Read the `--env` JSON file, fetch the node's sealing key, and envelope-wrap
    /// each value. Returns the `sealed_env` array for `tenzro_machineDeploy`.
    async fn seal_env(&self, rpc: &crate::rpc::RpcClient) -> Result<Vec<serde_json::Value>> {
        use tenzro_crypto::encryption::{envelope_encrypt, X25519PublicKey};

        let Some(path) = &self.env else {
            return Ok(Vec::new());
        };
        let raw = std::fs::read_to_string(path).with_context(|| format!("read env {path:?}"))?;
        let map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&raw).with_context(|| format!("parse env {path:?}"))?;
        if map.is_empty() {
            return Ok(Vec::new());
        }

        // The node's X25519 sealing public key; secrets are wrapped to it so only
        // the assigned node can unseal them at launch.
        let spinner = output::create_spinner("Fetching node sealing key...");
        let key_resp: serde_json::Value = rpc
            .call("tenzro_machineSealingKey", serde_json::json!({}))
            .await
            .context("fetch node sealing key")?;
        spinner.finish_and_clear();
        let hex_key = key_resp
            .get("sealing_public_key")
            .and_then(|v| v.as_str())
            .context("machineSealingKey returned no sealing_public_key")?;
        let key_bytes = hex::decode(hex_key).context("decode sealing_public_key hex")?;
        let key_arr: [u8; 32] = key_bytes
            .as_slice()
            .try_into()
            .context("sealing_public_key is not 32 bytes")?;
        let recipient = X25519PublicKey::from(key_arr);

        let mut sealed = Vec::with_capacity(map.len());
        for (name, value) in map {
            let plaintext = value
                .as_str()
                .with_context(|| format!("env var {name} must be a string"))?;
            let envelope = envelope_encrypt(&recipient, plaintext.as_bytes())
                .map_err(|e| anyhow::anyhow!("seal env var {name}: {e}"))?;
            let sealed_value = serde_json::to_value(&envelope)
                .with_context(|| format!("serialize sealed env var {name}"))?;
            sealed.push(serde_json::json!({ "name": name, "sealed_value": sealed_value }));
        }
        Ok(sealed)
    }
}

/// Get a machine deployment.
#[derive(Debug, Parser)]
pub struct MachineGetCmd {
    /// Machine id.
    #[arg(long)]
    id: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MachineGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let deployment: serde_json::Value = rpc
            .call("tenzro_machineGet", serde_json::json!({ "id": self.id }))
            .await?;
        output::print_json(&deployment)?;
        Ok(())
    }
}

/// List machine deployments.
#[derive(Debug, Parser)]
pub struct MachineListCmd {
    /// Filter by owner DID.
    #[arg(long)]
    owner_did: Option<String>,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MachineListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({});
        if let Some(owner) = &self.owner_did {
            params["owner_did"] = serde_json::json!(owner);
        }
        let result: serde_json::Value = rpc.call("tenzro_listMachines", params).await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Remove a machine deployment.
#[derive(Debug, Parser)]
pub struct MachineRemoveCmd {
    /// Machine id.
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

impl MachineRemoveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_machineRemove",
                serde_json::json!({
                    "id": self.id,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Machine removed");
        output::print_json(&result)?;
        Ok(())
    }
}

/// Report the runtime status of a machine deployment.
#[derive(Debug, Parser)]
pub struct MachineStatusCmd {
    /// Machine id.
    #[arg(long)]
    id: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MachineStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_machineStatus", serde_json::json!({ "id": self.id }))
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}
