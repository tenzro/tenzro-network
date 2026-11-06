//! The model catalog: read what a node serves, and publish or withdraw
//! entries as a publisher.
//!
//! A catalog entry is signed with a P-256 key held in this machine's TPM or
//! Secure Enclave and submitted to a node, which verifies it and gossips it.
//! A node serves an entry only when its operator names the publisher
//! (`--catalog-publisher`), or names none. Local model commands read the catalog of the node they are
//! pointed at.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};

use crate::commands::trust::{hardware_did, sign_with_hardware};
use crate::output;
use crate::rpc::RpcClient;

const DEFAULT_RPC: &str = "http://127.0.0.1:8545";

#[derive(Debug, Subcommand)]
pub enum CatalogCommand {
    /// List the models a node's catalog serves, and any it left out and why.
    List(ListCmd),
    /// Show one model's entry, its publishers, and whether a token is needed.
    Show(ShowCmd),
    /// Sign catalog entries (a JSON file, or a directory of them) and submit
    /// them.
    Publish(PublishCmd),
    /// Sign and submit the withdrawal of a model you published.
    Withdraw(WithdrawCmd),
}

impl CatalogCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(c) => c.execute().await,
            Self::Show(c) => c.execute().await,
            Self::Publish(c) => c.execute().await,
            Self::Withdraw(c) => c.execute().await,
        }
    }
}

/// Install the catalog the node at `rpc` serves as this process's catalog.
pub async fn install_from(rpc: &str) -> Result<()> {
    let res: Value = RpcClient::new(rpc)
        .call("tenzro_listCatalog", json!({}))
        .await
        .with_context(|| format!("read the model catalog from {rpc}"))?;
    let entries: Vec<tenzro_catalog::CatalogEntry> =
        serde_json::from_value(res.get("entries").cloned().unwrap_or(Value::Null))
            .map_err(|e| anyhow!("the catalog from {rpc} does not parse: {e}"))?;
    let (catalog, errors) = tenzro_catalog::Catalog::build(entries);
    for e in errors {
        output::print_warning(&format!("catalog entry left out: {e}"));
    }
    if catalog.is_empty() {
        let note = res
            .pointer("/status/note")
            .and_then(Value::as_str)
            .unwrap_or("no trusted publisher has published a model");
        output::print_warning(&format!("the catalog of {rpc} is empty: {note}"));
    }
    tenzro_catalog::store::install(catalog);
    Ok(())
}

/// `tenzro catalog list [--engine <family>]`
#[derive(Debug, Parser)]
pub struct ListCmd {
    /// Only this engine family (gguf, onnx-vision, media-gen, ...).
    #[arg(long)]
    engine: Option<String>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ListCmd {
    async fn execute(&self) -> Result<()> {
        let mut params = json!({});
        if let Some(e) = &self.engine {
            params["engine"] = json!(e);
        }
        let res: Value = RpcClient::new(&self.rpc)
            .call("tenzro_listCatalog", params)
            .await?;
        let rows: Vec<Value> = res["entries"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|e| {
                        json!({
                            "id": e.pointer("/model/spec/id"),
                            "engine": e.pointer("/model/engine"),
                            "licence": e.pointer("/licence/name"),
                            "tier": e.pointer("/licence/tier"),
                            "gated": e.get("gated"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        output::print_json(
            &json!({ "status": res["status"], "count": res["count"], "models": rows }),
        )
    }
}

/// `tenzro catalog show <model>`
#[derive(Debug, Parser)]
pub struct ShowCmd {
    model: String,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl ShowCmd {
    async fn execute(&self) -> Result<()> {
        let res: Value = RpcClient::new(&self.rpc)
            .call("tenzro_getCatalogEntry", json!({ "model": self.model }))
            .await?;
        output::print_json(&res)
    }
}

/// `tenzro catalog publish <file|dir> --key-label <label>`
#[derive(Debug, Parser)]
pub struct PublishCmd {
    /// A catalog entry JSON file (one entry or an array), or a directory of them.
    path: PathBuf,
    /// Label of the publisher's key in this machine's TPM or Secure Enclave.
    #[arg(long)]
    key_label: String,
    /// Sequence of this publication; a node replaces a model's entry only
    /// with a higher one. Defaults to the current Unix time.
    #[arg(long)]
    sequence: Option<u64>,
    /// Write the signed records here instead of submitting them.
    #[arg(long)]
    out: Option<PathBuf>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

fn sequence_or_now(sequence: Option<u64>) -> u64 {
    sequence.unwrap_or_else(|| chrono::Utc::now().timestamp().max(0) as u64)
}

async fn submit(rpc: &str, record: &Value) -> Result<Value> {
    RpcClient::new(rpc)
        .call("tenzro_submitTrustRecord", json!({ "record": record }))
        .await
}

impl PublishCmd {
    async fn execute(&self) -> Result<()> {
        let entries = tenzro_catalog::read_entries(&self.path).map_err(|e| anyhow!(e))?;
        if entries.is_empty() {
            bail!("{} holds no catalog entry", self.path.display());
        }
        for e in &entries {
            e.validate().map_err(|e| anyhow!("{e}"))?;
        }
        let publisher = hardware_did(&self.key_label)?;
        let sequence = sequence_or_now(self.sequence);
        let mut signed = Vec::new();
        for e in &entries {
            let body = serde_json::to_value(e)?;
            let unsigned = tenzro_trust::catalog::CatalogRecord::unsigned(
                &publisher,
                e.id(),
                sequence,
                Some(&body),
            );
            signed.push(sign_with_hardware(unsigned, &self.key_label)?);
        }
        if let Some(out) = &self.out {
            std::fs::write(out, serde_json::to_vec_pretty(&signed)?)?;
            output::print_success(&format!(
                "Wrote {} signed entries to {}",
                signed.len(),
                out.display()
            ));
            return Ok(());
        }
        let mut results = Vec::new();
        for (e, record) in entries.iter().zip(&signed) {
            let res = submit(&self.rpc, record)
                .await
                .with_context(|| format!("submit {}", e.id()))?;
            results.push(json!({ "model": e.id(), "result": res }));
        }
        output::print_json(
            &json!({ "publisher": publisher, "sequence": sequence, "published": results }),
        )
    }
}

/// `tenzro catalog withdraw <model> --key-label <label>`
#[derive(Debug, Parser)]
pub struct WithdrawCmd {
    model: String,
    #[arg(long)]
    key_label: String,
    #[arg(long)]
    sequence: Option<u64>,
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl WithdrawCmd {
    async fn execute(&self) -> Result<()> {
        let publisher = hardware_did(&self.key_label)?;
        let unsigned = tenzro_trust::catalog::CatalogRecord::unsigned(
            &publisher,
            &self.model,
            sequence_or_now(self.sequence),
            None,
        );
        let record = sign_with_hardware(unsigned, &self.key_label)?;
        output::print_json(&submit(&self.rpc, &record).await?)
    }
}
