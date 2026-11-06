//! Engine upgrades: signed releases the operator applies.
//!
//! A publisher hashes the node binary for each platform and signs a release
//! with its hardware key (`publish`). The release travels the network like
//! any trust record; a node reports the releases of the publishers its
//! operator names (`--release-publisher`) (`check`), and never installs
//! one itself. `apply` verifies a downloaded binary against the signed hashes
//! and installs it in place; the operator restarts the node when it chooses.
//! A release changes the software a node runs, never the chain.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use crate::commands::trust::{hardware_did, sign_with_hardware};
use crate::output;
use crate::rpc::RpcClient;

const DEFAULT_RPC: &str = "http://127.0.0.1:8545";

#[derive(Debug, Subcommand)]
pub enum NodeUpgradeCommand {
    /// Show the releases the node reports and whether one is newer than it runs.
    Check(CheckCmd),
    /// Verify a downloaded binary against a signed release and install it.
    Apply(ApplyCmd),
    /// Hash node binaries, sign a release with your hardware key and submit it.
    Publish(PublishCmd),
}

impl NodeUpgradeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Check(c) => c.execute().await,
            Self::Apply(c) => c.execute().await,
            Self::Publish(c) => c.execute().await,
        }
    }
}

async fn releases(rpc: &str) -> Result<Value> {
    RpcClient::new(rpc)
        .call("tenzro_getEngineReleases", json!({}))
        .await
}

/// `tenzro node upgrade check`
#[derive(Debug, Parser)]
pub struct CheckCmd {
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl CheckCmd {
    async fn execute(&self) -> Result<()> {
        let res = releases(&self.rpc).await?;
        match res["available"].as_str() {
            Some(v) => output::print_info(&format!(
                "release {v} is available (running {}); verify and install it with `tenzro node upgrade apply`",
                res["running"].as_str().unwrap_or("?")
            )),
            None => output::print_info("no newer release from a trusted publisher"),
        }
        output::print_json(&res)
    }
}

fn hash_file(path: &Path) -> Result<(u64, String, String)> {
    tenzro_trust::manifest::hash_file(path).map_err(|e| anyhow!("{}: {e}", path.display()))
}

/// `tenzro node upgrade apply --version <v> --file <binary> --install-to <path>`
#[derive(Debug, Parser)]
pub struct ApplyCmd {
    /// The release version to install.
    #[arg(long)]
    version: String,
    /// The downloaded binary.
    #[arg(long)]
    file: PathBuf,
    /// Where the node binary is installed; replaced atomically.
    #[arg(long)]
    install_to: PathBuf,
    /// The artifact platform; defaults to the platform the node reports.
    #[arg(long)]
    platform: Option<String>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ApplyCmd {
    async fn execute(&self) -> Result<()> {
        let res = releases(&self.rpc).await?;
        let platform = self
            .platform
            .clone()
            .or_else(|| res["platform"].as_str().map(str::to_string))
            .ok_or_else(|| anyhow!("the node reported no platform; pass --platform"))?;
        let release = res["releases"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["version"] == self.version.as_str())
            .ok_or_else(|| {
                anyhow!(
                    "no trusted publisher has published release {}",
                    self.version
                )
            })?;
        // Re-verify the signed record here rather than trusting the node's word.
        let verified = tenzro_trust::release::EngineRelease::parse(&release["record"])
            .map_err(|e| anyhow!("release {} does not verify: {e}", self.version))?;
        let artifact = verified
            .artifact(&platform)
            .ok_or_else(|| anyhow!("release {} has no artifact for {platform}", self.version))?;
        let (size, sha256, blake3) = hash_file(&self.file)?;
        if size != artifact.size || sha256 != artifact.sha256 || blake3 != artifact.blake3 {
            bail!(
                "{} is not the {platform} binary of release {} (signed SHA-256 {}, file {sha256}); refusing to install it",
                self.file.display(),
                self.version,
                artifact.sha256
            );
        }
        let staged = self.install_to.with_extension("upgrade.tmp");
        std::fs::copy(&self.file, &staged)
            .with_context(|| format!("stage {}", staged.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::File::open(&staged)?.sync_all()?;
        std::fs::rename(&staged, &self.install_to)
            .with_context(|| format!("install {}", self.install_to.display()))?;
        output::print_success(&format!(
            "Installed release {} ({}) at {}; restart the node to run it",
            self.version,
            verified.publisher,
            self.install_to.display()
        ));
        Ok(())
    }
}

/// `tenzro node upgrade publish --version <v> --artifact <platform>=<binary> ... --key-label <label>`
#[derive(Debug, Parser)]
pub struct PublishCmd {
    #[arg(long)]
    version: String,
    /// `<platform>=<path to binary>`, once per platform.
    #[arg(long = "artifact", required = true)]
    artifacts: Vec<String>,
    /// Label of the publisher's key in this machine's TPM or Secure Enclave.
    #[arg(long)]
    key_label: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl PublishCmd {
    async fn execute(&self) -> Result<()> {
        let mut artifacts = Vec::new();
        for a in &self.artifacts {
            let (platform, path) = a
                .split_once('=')
                .ok_or_else(|| anyhow!("--artifact takes <platform>=<path>, got {a}"))?;
            let (size, sha256, blake3) = hash_file(Path::new(path))?;
            artifacts.push(tenzro_trust::release::Artifact {
                platform: platform.to_string(),
                size,
                sha256,
                blake3,
            });
        }
        let publisher = hardware_did(&self.key_label)?;
        let unsigned =
            tenzro_trust::release::EngineRelease::unsigned(&publisher, &self.version, &artifacts);
        let record = sign_with_hardware(unsigned, &self.key_label)?;
        tenzro_trust::release::EngineRelease::parse(&record).map_err(|e| anyhow!("{e}"))?;
        let res: Value = RpcClient::new(&self.rpc)
            .call("tenzro_submitTrustRecord", json!({ "record": record }))
            .await?;
        output::print_json(&res)
    }
}
