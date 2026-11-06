//! Finality commands: verify the chain's latest compact certificate from
//! genesis, as a light client, trusting nothing the node says.
//!
//! The only trust anchors are the ones given on the command line: the chain
//! id, the genesis hash, the root of the genesis committee and, once the
//! chain's handovers are proven, the handover program. Everything else comes
//! from the node and is checked: the handover chain proof against the
//! program and the genesis anchor (or, before one, the genesis committee
//! against its root), the members of the committee it reaches against the
//! root it commits, each later epoch's handover certificate against the
//! committee of that epoch and the session certificates it names, each next
//! committee against the root its handover commits, and finally the compact
//! certificate against the committee of its epoch. A node that pruned the
//! handovers its chain proof covers serves all of it.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tenzro_consensus::compact::CompactCertificate;
use tenzro_consensus::light_client::{ChainSegment, GenesisAnchor, LightClient};
use tenzro_consensus::{Certificate, Member, SessionCertificate};

use crate::output;
use crate::rpc::RpcClient;

/// Finality operations
#[derive(Debug, Subcommand)]
pub enum FinalityCommand {
    /// Verify the latest compact certificate from genesis, as a light client
    Verify(FinalityVerifyCmd),
    /// Write the finality step of one checkpoint: the input a finality
    /// prover turns into a STARK finality proof, the quantum-safe form every
    /// light client and settlement uses. The prover can also wrap it in a
    /// Groth16 proof over BN254 for an EVM verifier; that wrap rests on a
    /// classical assumption and is not quantum-safe
    Step(FinalityStepCmd),
    /// Write the handover of one epoch (bincode), as `tenzro-finality-prover
    /// handover` takes it for one link of the handover chain proof
    Handover(FinalityHandoverCmd),
}

impl FinalityCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Verify(cmd) => cmd.execute().await,
            Self::Step(cmd) => cmd.execute().await,
            Self::Handover(cmd) => cmd.execute().await,
        }
    }
}

/// Write the handover of one epoch
#[derive(Debug, Parser)]
pub struct FinalityHandoverCmd {
    /// The epoch handed over
    #[arg(long)]
    epoch: u64,
    /// Where to write the handover (bincode)
    #[arg(long)]
    out: std::path::PathBuf,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FinalityHandoverCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let h: Value = rpc
            .call("tenzro_getEpochHandover", json!([self.epoch]))
            .await?;
        let certificate: Certificate = decode(&h, "certificate")?;
        let sessions: Vec<SessionCertificate> = decode(&h, "sessions")?;
        let next_members: Vec<Member> = decode(&h, "next_members")?;
        let index = certificate.checkpoint.index;
        let handover = tenzro_consensus::light_client::EpochHandover {
            certificate,
            sessions,
            next_members,
        };
        std::fs::write(&self.out, bincode::serialize(&handover)?)?;
        output::print_success("Handover written");
        output::print_field("Epoch", &self.epoch.to_string());
        output::print_field("Checkpoint", &index.to_string());
        output::print_field("Written to", &self.out.display().to_string());
        Ok(())
    }
}

/// Write the finality step of one checkpoint
#[derive(Debug, Parser)]
pub struct FinalityStepCmd {
    /// Checkpoint index; the latest when omitted
    #[arg(long)]
    index: Option<u64>,
    /// Chain id
    #[arg(long)]
    chain_id: u64,
    /// Genesis block hash (0x-prefixed hex)
    #[arg(long)]
    genesis_hash: String,
    /// Where to write the step (bincode)
    #[arg(long)]
    out: std::path::PathBuf,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FinalityStepCmd {
    pub async fn execute(&self) -> Result<()> {
        use sha2::Digest as _;
        use tenzro_finality::step::FinalityStep;
        output::print_header("Finality Step");
        let rpc = RpcClient::new(&self.rpc);
        let params = match self.index {
            Some(i) => json!([i]),
            None => json!([]),
        };
        let got: Value = rpc.call("tenzro_getCheckpointCertificate", params).await?;
        let certificate: Certificate = decode(&got, "certificate")?;
        let sessions: Vec<SessionCertificate> = decode(&got, "sessions")?;
        let committee: Value = rpc
            .call("tenzro_getCommittee", json!([certificate.checkpoint.epoch]))
            .await?;
        let members: Vec<Member> = decode(&committee, "members")?;
        let step = FinalityStep {
            chain_id: self.chain_id,
            genesis_hash: hex32(&self.genesis_hash, "genesis hash")?,
            members,
            sessions,
            certificate,
        };
        // Checked here first: a step that does not verify can never be proven.
        let journal = step.verify().context("the step does not verify")?;
        let bytes = bincode::serialize(&step)?;
        std::fs::write(&self.out, &bytes)
            .with_context(|| format!("writing {}", self.out.display()))?;
        output::print_success("Step written; a prover wraps it into a finality proof");
        output::print_field("Checkpoint", &journal.index.to_string());
        output::print_field(
            "Checkpoint digest",
            &format!("0x{}", hex::encode(journal.checkpoint_digest)),
        );
        output::print_field(
            "Committee root",
            &format!("0x{}", hex::encode(journal.committee_root)),
        );
        output::print_field(
            "Inputs digest",
            &format!("0x{}", hex::encode(sha2::Sha256::digest(&bytes))),
        );
        Ok(())
    }
}

/// Verify the chain's latest compact certificate from genesis
#[derive(Debug, Parser)]
pub struct FinalityVerifyCmd {
    #[command(flatten)]
    genesis: GenesisArgs,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

/// The trust anchors a light client starts from, from the genesis file.
#[derive(Debug, clap::Args)]
pub struct GenesisArgs {
    /// Chain id
    #[arg(long)]
    chain_id: u64,
    /// Genesis block hash (0x-prefixed hex)
    #[arg(long)]
    genesis_hash: String,
    /// Root of the genesis committee (0x-prefixed hex), from the genesis file
    #[arg(long)]
    genesis_committee_root: String,
    /// Image id of the handover program (0x-prefixed hex), from the chain's
    /// governance: needed once the node serves a handover chain proof
    #[arg(long)]
    handover_program: Option<String>,
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(s.trim_start_matches("0x")).with_context(|| format!("{what} is not hex"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow!("{what} must be 32 bytes"))
}

fn decode<T: DeserializeOwned>(v: &Value, field: &str) -> Result<T> {
    let s = v[field]
        .as_str()
        .ok_or_else(|| anyhow!("response has no {field}"))?;
    let bytes =
        hex::decode(s.trim_start_matches("0x")).with_context(|| format!("{field} is not hex"))?;
    bincode::deserialize(&bytes).with_context(|| format!("{field} does not decode"))
}

/// A light client that followed the node's chain from `genesis` to its
/// latest compact certificate, which it has accepted.
pub(crate) async fn follow(
    rpc: &RpcClient,
    genesis: &GenesisArgs,
) -> Result<(LightClient, CompactCertificate)> {
    let anchor = GenesisAnchor {
        chain_id: genesis.chain_id,
        genesis_hash: hex32(&genesis.genesis_hash, "genesis hash")?,
        committee_root: hex32(&genesis.genesis_committee_root, "genesis committee root")?,
    };
    let program = genesis
        .handover_program
        .as_deref()
        .map(|h| hex32(h, "handover program"))
        .transpose()?;

    let latest: Value = rpc.call("tenzro_getCompactCertificate", json!([])).await?;
    let compact: CompactCertificate = decode(&latest, "certificate")?;
    let target = compact.checkpoint.epoch;
    let reply: Value = rpc.call("tenzro_getHandoverChain", json!([target])).await?;
    let segment = ChainSegment::from_reply(&reply)?;
    if segment.first_epoch() + segment.handovers.len() as u64 != target {
        bail!(
            "the node served handovers to epoch {}, the compact certificate is of epoch {target}",
            segment.first_epoch() + segment.handovers.len() as u64
        );
    }
    let mut client = segment
        .light_client(&anchor, program, tenzro_zk::handover_chain::verify_receipt)
        .context("following the chain to the compact certificate's epoch")?;
    if segment.journal.is_some() {
        output::print_field(
            "handover chain proof",
            &format!("reaches epoch {}", segment.first_epoch()),
        );
    }
    for h in &segment.handovers {
        output::print_field(
            &format!("epoch {} handover", h.certificate.checkpoint.epoch),
            &format!("checkpoint {}", h.certificate.checkpoint.index),
        );
    }
    let sessions: Vec<SessionCertificate> = decode(&latest, "sessions")?;
    client.add_sessions(sessions);
    client
        .accept_compact(&compact)
        .context("compact certificate")?;
    Ok((client, compact))
}

impl FinalityVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Verify Finality From Genesis");
        let rpc = RpcClient::new(&self.rpc);
        let (_, compact) = follow(&rpc, &self.genesis).await?;

        let cp = &compact.checkpoint;
        output::print_success("Compact certificate verified from genesis");
        output::print_field("Epoch", &cp.epoch.to_string());
        output::print_field("Checkpoint", &cp.index.to_string());
        output::print_field("Last height", &cp.last_height.to_string());
        output::print_field("State root", &format!("0x{}", hex::encode(cp.state_root)));
        output::print_field("Signers", &compact.signers().len().to_string());
        Ok(())
    }
}
