//! `tenzro-finality-prover`: turns a finality step into a finality proof.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tenzro_finality::chain::{
    EpochHandover, HandoverChainJournal, HandoverChainProof, HandoverLink,
};
use tenzro_finality::committee::Member;
use tenzro_finality::step::FinalityStep;
use tenzro_finality_prover::StarkProof;

#[derive(Parser)]
#[command(about = "Proves Tenzro checkpoint finality as a quantum-safe STARK, with an optional Groth16 wrap")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print the finality program's image id
    ImageId,
    /// Prove a step written by `tenzro finality step` as a STARK finality
    /// proof, the quantum-safe form light clients verify (the GPU stage)
    Stark {
        /// The step (bincode)
        #[arg(long)]
        step: std::path::PathBuf,
        /// Where to write the proof (JSON)
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Print the handover program's image id
    HandoverProgram,
    /// Prove the next link of the epoch handover chain (the GPU stage): the
    /// handover of one epoch, under that epoch's committee, added to the
    /// chain the previous receipt proves
    Handover {
        /// The epoch's handover (bincode), as a node serves it
        #[arg(long)]
        handover: std::path::PathBuf,
        /// Members of the epoch's committee (bincode): the genesis members for
        /// epoch 0, else the members the previous link handed over to
        #[arg(long)]
        members: std::path::PathBuf,
        /// Root of the genesis committee (hex)
        #[arg(long)]
        genesis_root: String,
        /// The receipt of the chain so far; none for epoch 0's handover
        #[arg(long)]
        prev: Option<std::path::PathBuf>,
        /// Where to write the new receipt, which the next link builds on
        #[arg(long)]
        out: std::path::PathBuf,
        /// Where to write the chain proof a node installs (its proof log's
        /// `incoming-chain.bin`)
        #[arg(long)]
        chain_proof: std::path::PathBuf,
    },
    /// Wrap a handover chain receipt written by `handover` into the Groth16
    /// proof a handover proof duty pays for (the x86-64 CPU stage)
    WrapHandover {
        /// The receipt `handover` wrote
        #[arg(long)]
        receipt: std::path::PathBuf,
        /// Where to write the wrapped proof (JSON)
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Verify a STARK finality proof as a light client does, and print the
    /// checkpoint it proves final
    Verify {
        /// The proof `stark` wrote
        #[arg(long)]
        proof: std::path::PathBuf,
    },
    /// Wrap a STARK finality proof into the Groth16 form over BN254 for a
    /// chain that needs it (the x86-64 CPU stage; not quantum-safe)
    Wrap {
        /// The proof `stark` wrote
        #[arg(long)]
        proof: std::path::PathBuf,
        /// Where to write the wrapped proof (JSON)
        #[arg(long)]
        out: std::path::PathBuf,
    },
}

fn read_proof(path: &std::path::Path) -> Result<StarkProof> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    StarkProof::from_json(&serde_json::from_slice(&bytes).context("the proof is not JSON")?)
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::ImageId => println!("0x{}", hex::encode(tenzro_finality_prover::image_id())),
        Command::Stark { step, out } => {
            let bytes = std::fs::read(&step).with_context(|| format!("reading {}", step.display()))?;
            let step: FinalityStep = bincode::deserialize(&bytes).context("the step does not decode")?;
            let proof = tenzro_finality_prover::prove(&step)?;
            std::fs::write(&out, serde_json::to_vec_pretty(&proof.to_json())?)?;
            println!("{}", out.display());
        }
        Command::HandoverProgram => {
            println!("0x{}", hex::encode(tenzro_finality_prover::handover_program()))
        }
        Command::Handover { handover, members, genesis_root, prev, out, chain_proof } => {
            let read = |p: &std::path::PathBuf| std::fs::read(p).with_context(|| format!("reading {}", p.display()));
            let handover: EpochHandover =
                bincode::deserialize(&read(&handover)?).context("the handover does not decode")?;
            let members: Vec<Member> =
                bincode::deserialize(&read(&members)?).context("the members do not decode")?;
            let genesis_root: [u8; 32] = hex::decode(genesis_root.trim_start_matches("0x"))
                .ok()
                .and_then(|b| b.try_into().ok())
                .context("--genesis-root must be 32 bytes of hex")?;
            let prev = prev
                .map(|p| tenzro_finality_prover::read_receipt(&read(&p)?))
                .transpose()?;
            let prev_journal = prev
                .as_ref()
                .map(|r| HandoverChainJournal::decode(&r.journal.bytes).context("the previous receipt commits no chain journal"))
                .transpose()?;
            let cp = &handover.certificate.checkpoint;
            let link = HandoverLink {
                program: tenzro_finality_prover::handover_program(),
                genesis_root,
                prev: prev_journal,
                step: FinalityStep {
                    chain_id: cp.chain_id,
                    genesis_hash: cp.genesis_hash,
                    members,
                    sessions: handover.sessions,
                    certificate: handover.certificate.clone(),
                },
            };
            let receipt = tenzro_finality_prover::prove_handover(&link, prev.as_ref())?;
            let bytes = tenzro_finality_prover::write_receipt(&receipt)?;
            std::fs::write(&out, &bytes)?;
            let proof = HandoverChainProof { members: handover.next_members, receipt: bytes };
            std::fs::write(&chain_proof, bincode::serialize(&proof)?)?;
            println!("{}", out.display());
        }
        Command::WrapHandover { receipt, out } => {
            let bytes = std::fs::read(&receipt).with_context(|| format!("reading {}", receipt.display()))?;
            let proof = tenzro_finality_prover::wrap_receipt(&tenzro_finality_prover::read_receipt(&bytes)?)?;
            std::fs::write(&out, serde_json::to_vec_pretty(&proof.to_json())?)?;
            println!("{}", out.display());
        }
        Command::Verify { proof } => {
            let journal = read_proof(&proof)?.verify()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "chain_id": journal.chain_id,
                    "epoch": journal.epoch,
                    "committee_root": hex::encode(journal.committee_root),
                    "index": journal.index,
                    "checkpoint_digest": hex::encode(journal.checkpoint_digest),
                    "last_height": journal.last_height,
                    "state_root": hex::encode(journal.state_root),
                    "next_committee_root": hex::encode(journal.next_committee_root),
                }))?
            );
        }
        Command::Wrap { proof, out } => {
            let wrapped = tenzro_finality_prover::wrap(&read_proof(&proof)?)?;
            std::fs::write(&out, serde_json::to_vec_pretty(&wrapped.to_json())?)?;
            println!("{}", out.display());
        }
    }
    Ok(())
}
