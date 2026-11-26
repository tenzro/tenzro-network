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
    /// Attest on chain, as a bonded builder, the binary you rebuilt from a release's source.
    AttestBuild(AttestBuildCmd),
    /// Order the restarts of validators so the rest keep certifying with a spare.
    Plan(PlanCmd),
}

impl NodeUpgradeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Check(c) => c.execute().await,
            Self::Apply(c) => c.execute().await,
            Self::Publish(c) => c.execute().await,
            Self::AttestBuild(c) => c.execute().await,
            Self::Plan(c) => c.execute(),
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

/// `tenzro node upgrade attest-build --version <v> --platform <triple> --file <binary>`
///
/// A builder bonded in the attestor role rebuilds the release from its
/// published source and records the SHA-256 it got with a build attestation
/// transaction from its client account. Once builder attestations are in
/// force on chain, a protocol upgrade enacts only when each binary it names
/// has the governed number of them.
#[derive(Debug, Parser)]
pub struct AttestBuildCmd {
    /// The release that was rebuilt, `major.minor.patch`.
    #[arg(long)]
    version: String,
    /// The target triple it was built for, such as `x86_64-unknown-linux-gnu`.
    #[arg(long)]
    platform: String,
    /// The binary the rebuild produced.
    #[arg(long)]
    file: PathBuf,
    /// Hardware key namespace of the bonded builder's client account.
    #[arg(long, default_value = "client")]
    key_namespace: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl AttestBuildCmd {
    async fn execute(&self) -> Result<()> {
        let (_, sha256, _) = hash_file(&self.file)?;
        let code_hash = hex::decode(&sha256).context("the file's SHA-256")?;
        let op = tenzro_native_ops::build_attestation::BuildAttestationOp {
            version: self.version.clone(),
            platform: self.platform.clone(),
            code_hash,
        };
        op.validate().map_err(|e| anyhow::anyhow!(e))?;
        let tx = tenzro_types::transaction::TransactionType::NativeCall {
            selector: tenzro_native_ops::SELECTOR_BUILD_ATTESTATION,
            data: tenzro_native_ops::encode(&op),
        };
        let res = crate::keystore::send_as_client(
            &RpcClient::new(&self.rpc),
            &self.key_namespace,
            [0u8; 32],
            serde_json::to_value(tx)?,
            200_000,
        )
        .await?;
        output::print_field("Binary SHA-256", &sha256);
        output::print_json(&res)
    }
}

/// `tenzro node upgrade plan --validators <validators.tsv> [name...]`
///
/// Prints the order in which to restart validators onto a new binary: one
/// validator alone first (the one with the least stake), then waves that can
/// be down together while the validators left running still certify and
/// still survive one more loss. Each wave is live again before the next is
/// stopped. The arithmetic is the pre-stop check's
/// (`scripts/validator-prestop-check.sh`), which still judges every stop
/// when it is made.
#[derive(Debug, Parser)]
pub struct PlanCmd {
    /// One validator per line: name, stake in whole TNZO, live (1 or 0),
    /// separated by whitespace; lines starting with # are ignored. The file
    /// the pre-stop check reads.
    #[arg(long)]
    validators: PathBuf,
    /// The validators to restart; every live one when none is named.
    names: Vec<String>,
}

/// The validators a `validators.tsv` lists.
fn read_validators(text: &str) -> Result<Vec<tenzro_consensus::launch_check::LaunchValidator>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let mut fields = line.split_whitespace();
            let (Some(name), Some(stake), Some(live), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                bail!("'{line}' is not: name stake live");
            };
            Ok(tenzro_consensus::launch_check::LaunchValidator {
                name: name.to_string(),
                stake: stake
                    .parse()
                    .with_context(|| format!("the stake of {name}"))?,
                live: match live {
                    "1" => true,
                    "0" => false,
                    other => bail!("the live column of {name} is 1 or 0, not '{other}'"),
                },
                // The file lists validators of a running network, admitted
                // with their hardware identities.
                hardware_identity: true,
            })
        })
        .collect()
}

impl PlanCmd {
    fn execute(&self) -> Result<()> {
        let text = std::fs::read_to_string(&self.validators)
            .with_context(|| format!("reading {}", self.validators.display()))?;
        let set = read_validators(&text)?;
        let names: Vec<&str> = if self.names.is_empty() {
            set.iter()
                .filter(|v| v.live)
                .map(|v| v.name.as_str())
                .collect()
        } else {
            self.names.iter().map(String::as_str).collect()
        };
        let waves = tenzro_consensus::launch_check::plan_restarts(&set, &names)
            .map_err(|e| anyhow!("no safe restart order: {e}"))?;
        for (i, wave) in waves.iter().enumerate() {
            let label = if i == 0 {
                "Canary".to_string()
            } else {
                format!("Wave {i}")
            };
            output::print_field(&label, &wave.join(" "));
        }
        output::print_info(
            "Restart one wave at a time, and start the next only when every validator of the \
             last is live and certifying again. Stop after the canary if it does not come back.",
        );
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_validators_file_is_read_as_the_pre_stop_check_reads_it() {
        let set = read_validators(
            "# name stake live\nalpha 5000000 1\n\n  beta\t5000000\t0\ngamma 7 1\n",
        )
        .unwrap();
        assert_eq!(
            set.iter()
                .map(|v| (v.name.as_str(), v.stake, v.live))
                .collect::<Vec<_>>(),
            [
                ("alpha", 5_000_000, true),
                ("beta", 5_000_000, false),
                ("gamma", 7, true)
            ]
        );
        for bad in ["alpha 5", "alpha five 1", "alpha 5 yes", "alpha 5 1 extra"] {
            assert!(read_validators(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_plan_of_seven_equal_validators_is_one_at_a_time() {
        let text: String = (0..7).map(|i| format!("v{i} 5 1\n")).collect();
        let set = read_validators(&text).unwrap();
        let names: Vec<&str> = set.iter().map(|v| v.name.as_str()).collect();
        let waves = tenzro_consensus::launch_check::plan_restarts(&set, &names).unwrap();
        assert_eq!(waves.len(), 7);
        assert!(waves.iter().all(|w| w.len() == 1));
    }
}
