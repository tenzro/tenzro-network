//! Proves Tenzro checkpoint finality.
//!
//! The finality program ([`FINALITY_GUEST_ELF`]) runs
//! [`FinalityStep::verify`] inside the RISC Zero zkVM and commits the step's
//! journal. Its succinct STARK receipt is the finality proof ([`StarkProof`]):
//! hash-based, so quantum-safe, and what light clients and Tenzro verify.
//!
//! For a chain that cannot verify a STARK, the receipt can also be wrapped
//! into a Groth16 proof over BN254 ([`WrappedProof`]): a 256-byte seal an EVM
//! contract checks with the BN254 pairing precompile. That form is optional
//! and classical: a quantum computer that solves discrete logarithms in
//! BN254 forges it.
//!
//! The STARK ([`prove`]) is the costly part and runs on an NVIDIA GPU (the
//! `cuda` feature). The wrap ([`wrap`]) turns a STARK proof into the Groth16
//! proof on the CPU of an x86-64 host, in RISC Zero's Groth16 prover
//! container ([`GROTH16_PROVER_IMAGE`], run by digest, without network), in
//! a build without the `cuda` feature; any other build refuses to wrap.
//! Proving is work for the machines that bid on such tasks.

use anyhow::{Context, Result};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    ExecutorEnv, Groth16ReceiptVerifierParameters, InnerReceipt, ProverOpts, Receipt, default_prover,
};
use serde_json::json;
use tenzro_finality::chain::HandoverLink;
use tenzro_finality::step::{FinalityJournal, FinalityStep};
use tenzro_zk::finality_proof::{ProofForm, encode_stark, verify_stark};

pub use tenzro_finality_methods::{
    FINALITY_GUEST_ELF, FINALITY_GUEST_ID, HANDOVER_GUEST_ELF, HANDOVER_GUEST_ID,
};

/// A finality proof: the journal the program committed and the program's
/// succinct STARK receipt proving it. Quantum-safe, and the canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkProof {
    /// The journal ([`FinalityJournal::encode`]).
    pub journal: Vec<u8>,
    /// The succinct receipt ([`tenzro_zk::finality_proof::encode_stark`]).
    pub stark: Vec<u8>,
}

impl StarkProof {
    /// The form: [`ProofForm::Stark`].
    pub const FORM: ProofForm = ProofForm::Stark;

    /// What a light client runs: checks the STARK against the finality
    /// program and returns the checkpoint it proves final. The caller then
    /// compares the journal's `committee_root` with the root it holds for
    /// the journal's epoch, and adopts `next_committee_root` when it is set.
    pub fn verify(&self) -> Result<FinalityJournal> {
        verify_stark(&image_id(), &self.journal, &self.stark)
            .map_err(|e| anyhow::anyhow!("the STARK does not verify: {e}"))?;
        FinalityJournal::decode(&self.journal).context("the journal does not decode")
    }

    /// The proof as a `finality_proof` evidence item carries it (journal and
    /// stark), labelled with its form.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "image_id": hex::encode(image_id()),
            "form": Self::FORM.name(),
            "quantum_safe": Self::FORM.quantum_safe(),
            "journal": hex::encode(&self.journal),
            "stark": hex::encode(&self.stark),
        })
    }

    /// The proof [`Self::to_json`] wrote.
    pub fn from_json(value: &serde_json::Value) -> Result<Self> {
        let field = |name: &str| -> Result<Vec<u8>> {
            let hex = value
                .get(name)
                .and_then(|v| v.as_str())
                .with_context(|| format!("no {name}"))?;
            hex::decode(hex).with_context(|| format!("{name} is not hex"))
        };
        Ok(Self {
            journal: field("journal")?,
            stark: field("stark")?,
        })
    }

    /// The receipt the wrap reproves.
    #[cfg(all(target_arch = "x86_64", not(feature = "cuda")))]
    fn receipt(&self) -> Result<Receipt> {
        let succinct =
            tenzro_zk::finality_proof::decode_stark(&self.stark).map_err(anyhow::Error::msg)?;
        Ok(Receipt::new(
            InnerReceipt::Succinct(succinct),
            self.journal.clone(),
        ))
    }
}

/// The Groth16 wrap of a finality proof over BN254: the journal the program
/// committed and the 256-byte seal proving it. A compact form for chains
/// that need one; not quantum-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedProof {
    /// The journal ([`tenzro_finality::step::FinalityJournal::encode`]).
    pub journal: Vec<u8>,
    /// The 256-byte Groth16 seal.
    pub seal: Vec<u8>,
}

/// The finality program's image id, as chains configure it.
pub fn image_id() -> [u8; 32] {
    risc0_zkvm::sha::Digest::from(FINALITY_GUEST_ID).into()
}

/// The four bytes an EVM verifier selects the Groth16 verifier by: the
/// leading bytes of its parameters' digest.
pub fn evm_selector() -> [u8; 4] {
    let d = Groth16ReceiptVerifierParameters::default().digest();
    d.as_bytes()[..4].try_into().expect("four bytes")
}

impl WrappedProof {
    /// The seal as an EVM verifier takes it: the selector, then the seal.
    pub fn evm_seal(&self) -> Vec<u8> {
        let mut out = evm_selector().to_vec();
        out.extend_from_slice(&self.seal);
        out
    }

    /// The form: [`ProofForm::Groth16Bn254`].
    pub const FORM: ProofForm = ProofForm::Groth16Bn254;

    /// The proof as a `finality_proof` evidence item carries it (journal and
    /// seal), labelled with its form.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "image_id": hex::encode(image_id()),
            "form": Self::FORM.name(),
            "quantum_safe": Self::FORM.quantum_safe(),
            "journal": hex::encode(&self.journal),
            "seal": hex::encode(&self.seal),
            "evm_seal": format!("0x{}", hex::encode(self.evm_seal())),
        })
    }
}

/// The finality proof of `step`: the program's succinct STARK receipt, the
/// costly part of proving. The step is checked natively first, so a step
/// that would not verify costs no proving, and the proof is checked before
/// it is returned.
pub fn prove(step: &FinalityStep) -> Result<StarkProof> {
    step.verify().context("the step does not verify")?;
    let input = bincode::serialize(step)?;
    let env = ExecutorEnv::builder().write_slice(&input).build()?;
    let info =
        default_prover().prove_with_opts(env, FINALITY_GUEST_ELF, &ProverOpts::succinct())?;
    let succinct = info
        .receipt
        .inner
        .succinct()
        .context("the prover returned no succinct receipt")?;
    let proof = StarkProof {
        journal: info.receipt.journal.bytes.clone(),
        stark: encode_stark(succinct).map_err(anyhow::Error::msg)?,
    };
    proof.verify()?;
    Ok(proof)
}

/// The handover program's image id, as governance names it.
pub fn handover_program() -> [u8; 32] {
    risc0_zkvm::sha::Digest::from(HANDOVER_GUEST_ID).into()
}

/// The succinct receipt of the handover chain with `link` added: the link
/// is proven by the handover program, which verifies the receipt `prev` it
/// builds on (none for epoch 0's handover). The link is checked natively
/// first, and `prev` must be a receipt of the handover program that commits
/// exactly `link.prev`. The returned receipt carries no assumption, so it
/// is verified alone and the next link builds on it.
pub fn prove_handover(link: &HandoverLink, prev: Option<&Receipt>) -> Result<Receipt> {
    if link.program != handover_program() {
        anyhow::bail!("the link names another program than this handover program");
    }
    link.verify().context("the link does not verify")?;
    let mut builder = ExecutorEnv::builder();
    match (prev, &link.prev) {
        (None, None) => {}
        (Some(receipt), Some(journal)) => {
            receipt
                .verify(HANDOVER_GUEST_ID)
                .context("the previous receipt does not verify")?;
            if receipt.journal.bytes != journal.encode() {
                anyhow::bail!("the previous receipt proves another chain than the link builds on");
            }
            builder.add_assumption(receipt.clone());
        }
        _ => anyhow::bail!("a link builds on a previous receipt exactly when it names one"),
    }
    let input = bincode::serialize(link)?;
    let env = builder.write_slice(&input).build()?;
    let info =
        default_prover().prove_with_opts(env, HANDOVER_GUEST_ELF, &ProverOpts::succinct())?;
    Ok(info.receipt)
}

/// Writes a succinct receipt as the wrap stage reads it.
pub fn write_receipt(receipt: &Receipt) -> Result<Vec<u8>> {
    Ok(bincode::serialize(receipt)?)
}

/// Reads a succinct receipt written by [`write_receipt`].
pub fn read_receipt(bytes: &[u8]) -> Result<Receipt> {
    bincode::deserialize(bytes).context("the receipt does not decode")
}

/// The Groth16 prover container the wrap runs, by digest. The wrap never
/// pulls it: a host pulls it once by this reference, which checks the content
/// against the digest.
pub use tenzro_zk::finality_proof::GROTH16_PROVER_IMAGE;

/// Wraps a STARK finality proof into the Groth16 form, on the CPU of an
/// x86-64 host: the receipt is reproven over BN254 and the Groth16 proof of
/// that is made in [`GROTH16_PROVER_IMAGE`] (`docker` on the path), with no
/// network and no pull. The STARK is checked first, so a proof of another
/// program or a forged one costs no wrapping, and the wrapped receipt is
/// checked before it is returned.
#[cfg(all(target_arch = "x86_64", not(feature = "cuda")))]
pub fn wrap(proof: &StarkProof) -> Result<WrappedProof> {
    proof.verify()?;
    wrap_receipt(&proof.receipt()?)
}

/// Wraps a succinct receipt of the finality or the handover program into a
/// Groth16 proof, on the CPU of an x86-64 host: the receipt is reproven over
/// BN254 and the Groth16 proof of that is made in [`GROTH16_PROVER_IMAGE`]
/// (`docker` on the path), with no network and no pull. The receipt is
/// checked first, so a receipt of another program or a forged one costs no
/// wrapping, and the wrapped receipt is checked before it is returned. A
/// wrapped handover receipt is what a handover proof duty pays for.
#[cfg(all(target_arch = "x86_64", not(feature = "cuda")))]
pub fn wrap_receipt(receipt: &Receipt) -> Result<WrappedProof> {
    use risc0_zkvm::Groth16Receipt;
    let program = [FINALITY_GUEST_ID, HANDOVER_GUEST_ID]
        .into_iter()
        .find(|id| receipt.verify(*id).is_ok())
        .context(
            "the receipt does not verify as a receipt of the finality or the handover program",
        )?;
    let succinct = receipt
        .inner
        .succinct()
        .context("the receipt is not a succinct receipt")?;
    let p254 = risc0_zkvm::recursion::identity_p254(succinct)?;
    let seal = groth16_in_container(&p254.get_seal_bytes())?;
    let groth16 = Groth16Receipt::new(
        seal,
        succinct.claim.clone(),
        Groth16ReceiptVerifierParameters::default().digest(),
    );
    let wrapped = Receipt::new(
        InnerReceipt::Groth16(groth16),
        receipt.journal.bytes.clone(),
    );
    wrapped
        .verify(program)
        .context("the wrapped receipt does not verify")?;
    let seal = wrapped
        .inner
        .groth16()
        .context("the receipt is not a Groth16 receipt")?
        .seal
        .clone();
    Ok(WrappedProof {
        journal: wrapped.journal.bytes,
        seal,
    })
}

/// The Groth16 proof of a BN254 STARK seal, made in [`GROTH16_PROVER_IMAGE`].
#[cfg(all(target_arch = "x86_64", not(feature = "cuda")))]
fn groth16_in_container(p254_seal: &[u8]) -> Result<Vec<u8>> {
    use std::process::Command;
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("seal.r0"), p254_seal)?;
    std::fs::write(
        dir.path().join("input.json"),
        risc0_groth16::prove::to_json(p254_seal)?,
    )?;
    let out = Command::new("docker")
        .args(["run", "--rm", "--network=none", "--pull=never", "-v"])
        .arg(format!("{}:/mnt", dir.path().display()))
        .arg(GROTH16_PROVER_IMAGE)
        .output()
        .context("running docker")?;
    if !out.status.success() {
        anyhow::bail!(
            "the Groth16 prover container failed ({}); the host needs exactly {GROTH16_PROVER_IMAGE} (`docker pull` it once): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let proof = std::fs::read_to_string(dir.path().join("proof.json"))
        .context("the container wrote no proof")?;
    let proof: risc0_groth16::ProofJson = serde_json::from_str(&proof)?;
    let seal: risc0_groth16::Seal = proof.try_into()?;
    Ok(seal.to_vec())
}

/// Only an x86-64 build without the `cuda` feature wraps; any other build
/// refuses before doing any work.
#[cfg(not(all(target_arch = "x86_64", not(feature = "cuda"))))]
pub fn wrap(proof: &StarkProof) -> Result<WrappedProof> {
    let _ = proof;
    anyhow::bail!(WRAP_HOST)
}

/// Only an x86-64 build without the `cuda` feature wraps; any other build
/// refuses before doing any work.
#[cfg(not(all(target_arch = "x86_64", not(feature = "cuda"))))]
pub fn wrap_receipt(receipt: &Receipt) -> Result<WrappedProof> {
    let _ = receipt;
    anyhow::bail!(WRAP_HOST)
}

/// Why this build cannot wrap.
pub const WRAP_HOST: &str = "the Groth16 wrap runs on an x86-64 host in a build without the cuda feature: prove the STARK on the GPU host (`stark`), then `wrap` its proof there";
