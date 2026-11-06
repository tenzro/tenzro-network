//! `tenzro bridge descriptor` and `tenzro bridge withdrawal`: the Bitcoin
//! deposit descriptor a route governs, and the signing of its withdrawals.
//!
//! A withdrawal is a transaction Tenzro derived from its own state when a
//! holder burned the deposit asset. Each signer reads it from a node, checks
//! it, and signs the digest of every input with its own hardware key; this
//! command collects the signatures and, once `threshold` signers signed every
//! input, prints the transaction ready to broadcast.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use serde_json::{Value, json};
use tenzro_bridge::route::bitcoin_spend::{DepositDescriptor, Withdrawal, verify_schnorr};

use crate::output;
use crate::rpc::RpcClient;

fn key32(s: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("{what} must be 32 bytes of hex"))
}

/// Print the deposit descriptor for a set of signers: the descriptor wallets
/// import, its output script, and the route `peer` governance sets
#[derive(Debug, Parser)]
pub struct BridgeDescriptorCmd {
    /// The signers' BIP-340 keys (hex, x-only), in order
    #[arg(long, value_delimiter = ',', required = true)]
    signers: Vec<String>,
    /// How many must sign a withdrawal
    #[arg(long)]
    threshold: u32,
}

impl BridgeDescriptorCmd {
    pub async fn execute(&self) -> Result<()> {
        use sha2::Digest;
        let signers = self
            .signers
            .iter()
            .map(|s| key32(s, "a signer key"))
            .collect::<Result<Vec<_>>>()?;
        if self.threshold as usize <= signers.len() / 2 || self.threshold as usize > signers.len() {
            bail!("the threshold must be a majority of the signers");
        }
        let desc = DepositDescriptor {
            signers,
            threshold: self.threshold,
        };
        let script = desc.script_pubkey()?;
        output::print_header("Bitcoin Deposit Descriptor");
        output::print_field("Descriptor", &desc.descriptor());
        output::print_field("Output script", &hex::encode(&script));
        output::print_field(
            "Route peer",
            &format!("0x{}", hex::encode(sha2::Sha256::digest(&script))),
        );
        Ok(())
    }
}

/// Sign a Bitcoin route's withdrawal: show it and the digests to sign, or
/// add a signer's signatures and print the transaction once complete
#[derive(Debug, Parser)]
pub struct BridgeWithdrawalCmd {
    /// The deposit route's external chain
    #[arg(long, default_value = "bitcoin")]
    chain: String,
    /// The withdrawal's sequence on the route
    #[arg(long, required_unless_present = "request_in")]
    sequence: Option<u64>,
    /// Where to write the withdrawal to collect signatures in
    #[arg(long, conflicts_with = "request_in")]
    request_out: Option<PathBuf>,
    /// A withdrawal written by --request-out
    #[arg(long)]
    request_in: Option<PathBuf>,
    /// The signer's BIP-340 key (hex)
    #[arg(long, requires_all = ["request_in", "signatures"])]
    signer: Option<String>,
    /// The signer's signature over each input's digest, in input order (hex)
    #[arg(long, value_delimiter = ',', requires = "signer")]
    signatures: Vec<String>,
    /// Tenzro RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeWithdrawalCmd {
    async fn fetch(&self, rpc: &RpcClient, sequence: u64) -> Result<Value> {
        let record: Value = rpc
            .call(
                "tenzro_getBridgeOutbound",
                json!({ "adapter": "deposit", "source_chain": self.chain, "sequence": sequence }),
            )
            .await?;
        if record.get("withdrawal").is_none() {
            bail!("outbound record {sequence} is not a withdrawal");
        }
        Ok(record)
    }

    fn parts(record: &Value) -> Result<(Withdrawal, DepositDescriptor)> {
        let bytes = hex::decode(
            record["message"]
                .as_str()
                .unwrap_or_default()
                .trim_start_matches("0x"),
        )?;
        let w = Withdrawal::decode(&bytes)?;
        let wd = &record["withdrawal"];
        let signers = wd["signers"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|s| key32(s.as_str().unwrap_or_default(), "a signer key"))
            .collect::<Result<Vec<_>>>()?;
        let threshold = wd["threshold"]
            .as_u64()
            .ok_or_else(|| anyhow!("no threshold"))? as u32;
        Ok((w, DepositDescriptor { signers, threshold }))
    }

    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bitcoin Withdrawal");
        let rpc = RpcClient::new(&self.rpc);
        let Some(path) = &self.request_in else {
            let sequence = self.sequence.ok_or_else(|| anyhow!("give --sequence"))?;
            let record = self.fetch(&rpc, sequence).await?;
            let wd = &record["withdrawal"];
            output::print_field("Transaction", wd["txid"].as_str().unwrap_or_default());
            for (i, o) in wd["outputs"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                output::print_field(
                    &format!("Output {i}"),
                    &format!(
                        "{} sat to {}",
                        o["value"],
                        o["script"].as_str().unwrap_or_default()
                    ),
                );
            }
            for (i, d) in wd["sighashes"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                output::print_field(&format!("Input {i} digest"), d.as_str().unwrap_or_default());
            }
            if let Some(out) = &self.request_out {
                let request = json!({ "chain": self.chain, "sequence": sequence, "record": record, "signatures": {} });
                std::fs::write(out, serde_json::to_vec_pretty(&request)?)?;
                output::print_field("Request", &out.display().to_string());
            }
            return Ok(());
        };

        let mut request: Value = serde_json::from_slice(
            &std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        )?;
        let sequence = request["sequence"]
            .as_u64()
            .ok_or_else(|| anyhow!("malformed request"))?;
        // The withdrawal is read again: a signer signs only what the chain holds.
        let record = self.fetch(&rpc, sequence).await?;
        if record["message"] != request["record"]["message"] {
            bail!("the node's withdrawal {sequence} differs from the request's");
        }
        let (w, desc) = Self::parts(&record)?;
        if let Some(signer) = &self.signer {
            let key = key32(signer, "--signer")?;
            if !desc.signers.contains(&key) {
                bail!("{signer} is not one of the descriptor's signers");
            }
            if self.signatures.len() != w.tx.inputs.len() {
                bail!("give one signature per input ({})", w.tx.inputs.len());
            }
            let mut sigs = Vec::new();
            for (i, s) in self.signatures.iter().enumerate() {
                let sig: [u8; 64] = hex::decode(s.trim_start_matches("0x"))
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| anyhow!("signature {i} must be 64 bytes of hex"))?;
                verify_schnorr(&key, &w.sighash(&desc, i)?, &sig)
                    .with_context(|| format!("signature {i}"))?;
                sigs.push(hex::encode(sig));
            }
            request["signatures"][hex::encode(key)] = json!(sigs);
            std::fs::write(path, serde_json::to_vec_pretty(&request)?)?;
        }

        let collected = request["signatures"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        output::print_field(
            "Signers",
            &format!("{} of {}", collected.len(), desc.threshold),
        );
        if collected.len() >= desc.threshold as usize {
            let per_input = (0..w.tx.inputs.len())
                .map(|i| {
                    collected
                        .iter()
                        .map(|(k, v)| {
                            let sig: [u8; 64] = hex::decode(v[i].as_str().unwrap_or_default())?
                                .try_into()
                                .map_err(|_| anyhow!("a stored signature is not 64 bytes"))?;
                            Ok((key32(k, "a stored key")?, sig))
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .collect::<Result<Vec<_>>>()?;
            let signed = w.assemble(&desc, &per_input)?;
            output::print_success("Signed by the threshold; broadcast it with any Bitcoin node");
            output::print_field("Transaction", &hex::encode(signed));
        }
        Ok(())
    }
}
