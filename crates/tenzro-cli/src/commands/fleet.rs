//! Fleet commands for the Tenzro CLI.
//!
//! An operator with many machines proves their hardware in one transaction.
//! Each host's node makes that host's evidence (`fleet evidence`, on the
//! host); the operator gathers the files and sends them from the operator's
//! wallet (`fleet prove`).

use crate::output;
use crate::rpc::RpcClient;
use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tenzro_fleet_proof::Rack;
use tenzro_types::hardware_level::FleetHost;

/// Fleet commands
#[derive(Debug, Subcommand)]
pub enum FleetCommand {
    /// On a host: write this machine's evidence for the operator's fleet proof
    Evidence(FleetEvidenceCmd),
    /// As the operator: send the hosts' evidence as one hardware proof
    Prove(FleetProveCmd),
}

impl FleetCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Evidence(cmd) => cmd.execute().await,
            Self::Prove(cmd) => cmd.execute().await,
        }
    }
}

/// Ask this host's node for its evidence for the current reward epoch: its
/// TPM's quote over the epoch's possession challenge and, when asked, its
/// GPU's report and the quote that joins it to the operator's fleet.
#[derive(Debug, Parser)]
pub struct FleetEvidenceCmd {
    /// The operator's identity (the identity of the wallet that will send the proof)
    #[arg(long)]
    operator: String,
    /// Include the quote that joins this host to the operator's fleet (the first proof only)
    #[arg(long)]
    bind: bool,
    /// Include this host's GPU report; fails when the GPU gives none
    #[arg(long)]
    gpu: bool,
    /// Where to write the evidence
    #[arg(long)]
    out: PathBuf,
    /// This host's node
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FleetEvidenceCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let host: FleetHost = rpc
            .call(
                "tenzro_fleetHostEvidence",
                json!({ "operator": self.operator, "bind": self.bind, "gpu": self.gpu }),
            )
            .await?;
        std::fs::write(&self.out, serde_json::to_vec_pretty(&host)?)
            .with_context(|| format!("writing {}", self.out.display()))?;
        output::print_success("Host evidence written");
        output::print_field("Host", &host.did);
        output::print_field("Reward epoch", &host.epoch.to_string());
        output::print_field("GPUs", &host.gpus.len().to_string());
        output::print_field("File", &self.out.display().to_string());
        Ok(())
    }
}

/// Send the evidence of the operator's hosts as one `HardwareProof`
/// transaction. A host given with --host is judged on its own; the hosts of
/// a --rack are judged together.
#[derive(Debug, Parser)]
pub struct FleetProveCmd {
    #[command(flatten)]
    signing: crate::keystore::SigningAccount,
    /// A host's evidence file, as `fleet evidence` wrote it (repeat for each host)
    #[arg(long)]
    host: Vec<PathBuf>,
    /// A rack proven as one unit: <label>=<file>,<file>,... (repeat for each rack)
    #[arg(long)]
    rack: Vec<String>,
    /// DER certificates every GPU chain shares above its device certificate
    #[arg(long)]
    issuers: Option<PathBuf>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

fn read_host(path: &Path) -> Result<FleetHost> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not a host's fleet evidence", path.display()))
}

/// A rack from its `<label>=<file>,<file>,...` argument.
fn read_rack(arg: &str) -> Result<Rack> {
    let (label, files) = arg
        .split_once('=')
        .ok_or_else(|| anyhow!("a rack is given as <label>=<file>,<file>,..."))?;
    let hosts = files
        .split(',')
        .map(|file| read_host(Path::new(file)))
        .collect::<Result<Vec<_>>>()?;
    Ok(Rack {
        label: label.to_string(),
        hosts,
    })
}

impl FleetProveCmd {
    pub async fn execute(&self) -> Result<()> {
        if self.host.is_empty() && self.rack.is_empty() {
            bail!("give at least one host with --host or one rack with --rack");
        }
        let hosts = self
            .host
            .iter()
            .map(|path| read_host(path))
            .collect::<Result<Vec<_>>>()?;
        let racks = self
            .rack
            .iter()
            .map(|arg| read_rack(arg))
            .collect::<Result<Vec<_>>>()?;
        let issuers = match &self.issuers {
            Some(path) => {
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?
            }
            None => Vec::new(),
        };
        let count = hosts.len() + racks.iter().map(|r| r.hosts.len()).sum::<usize>();
        let op = tenzro_fleet_proof::assemble(hosts, racks, issuers).map_err(|e| anyhow!(e))?;
        // Twice what the chain charges, as a node sends its own proof.
        let gas = tenzro_fleet_proof::gas_limit(&op).saturating_mul(2);
        let tx_type = json!({ "HardwareProof": { "op": op } });

        let rpc = RpcClient::new(&self.rpc);
        let (signer, from) = self.signing.open()?;
        let spinner = output::create_spinner("Submitting fleet proof...");
        let result: Value =
            crate::keystore::SigningAccount::send(&rpc, signer, [0u8; 32], tx_type, gas).await?;
        spinner.finish_and_clear();
        output::print_success("Fleet proof submitted");
        output::print_field("From", &format!("0x{}", hex::encode(from)));
        output::print_field("Hosts", &count.to_string());
        let tx_hash = result
            .get("tx_hash")
            .and_then(Value::as_str)
            .or_else(|| result.as_str())
            .unwrap_or_default();
        output::print_field("Transaction Hash", tx_hash);
        output::print_info(
            "A host or rack whose evidence the chain refuses is named in the transaction's log.",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rack_argument_names_its_label_and_files() {
        let err = read_rack("no-files-here").unwrap_err().to_string();
        assert!(err.contains("<label>=<file>"), "{err}");
        let err = read_rack("r1=/nonexistent/host.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("/nonexistent/host.json"), "{err}");
    }
}
