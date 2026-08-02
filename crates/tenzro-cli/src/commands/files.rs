//! Tenant object storage — the CLI over `/v1/files`.
//!
//! Every subcommand here needs an API key carrying the `storage` scope, and
//! the key's subject is who ends up owning the file. That is not an
//! authentication detail to mention in passing: two different keys are two
//! different tenants, so uploading with the wrong one puts the file somewhere
//! the caller cannot list it from. `--api-key` is therefore surfaced on every
//! subcommand rather than left to the `TENZRO_API_KEY` environment variable
//! alone.

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Multi-tenant file storage
#[derive(Debug, Subcommand)]
pub enum FilesCommand {
    /// Store a local file, erasure-coded across providers
    Upload(UploadCmd),
    /// List the files owned by your API key's subject
    List(ListCmd),
    /// Show one file's record
    Get(GetCmd),
    /// Download a stored file back to disk
    Download(DownloadCmd),
    /// Unlink a file (this is not erasure — see the printed note)
    Delete(DeleteCmd),
    /// Show what you are storing and what it bills against
    Usage(UsageCmd),
}

impl FilesCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::Upload(c) => c.execute().await,
            Self::List(c) => c.execute().await,
            Self::Get(c) => c.execute().await,
            Self::Download(c) => c.execute().await,
            Self::Delete(c) => c.execute().await,
            Self::Usage(c) => c.execute().await,
        }
    }
}

/// Flags every subcommand shares.
#[derive(Debug, Parser)]
pub struct Common {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545", global = true)]
    pub rpc: String,
    /// Storage-scoped API key. Its subject owns the files. Falls back to
    /// `TENZRO_API_KEY`.
    #[arg(long)]
    pub api_key: Option<String>,
}

impl Common {
    fn client(&self) -> RpcClient {
        let c = RpcClient::new(&self.rpc);
        match &self.api_key {
            Some(k) => c.with_api_key(k.clone()),
            None => c,
        }
    }
}

fn field_str(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("—")
        .to_string()
}

/// Bytes as something a person can compare at a glance.
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[derive(Debug, Parser)]
pub struct UploadCmd {
    /// Path to the file to store
    path: std::path::PathBuf,
    /// What the file is for: assistants | batch | fine_tune | vision | user_data
    #[arg(long)]
    purpose: Option<String>,
    #[command(flatten)]
    common: Common,
}

impl UploadCmd {
    pub async fn execute(self) -> Result<()> {
        let bytes = std::fs::read(&self.path)
            .with_context(|| format!("reading {}", self.path.display()))?;
        let filename = self
            .path
            .file_name()
            .and_then(|f| f.to_str())
            .context("the path has no filename")?
            .to_string();

        output::print_header("Upload File");
        let spinner = output::create_spinner("Erasure-coding and publishing shards...");
        let mut params = serde_json::json!({
            "filename": filename,
            "data": base64::engine::general_purpose::STANDARD.encode(&bytes),
        });
        if let Some(p) = &self.purpose {
            params["purpose"] = serde_json::json!(p);
        }
        let result: Result<serde_json::Value> =
            self.common.client().call("tenzro_uploadFile", params).await;
        spinner.finish_and_clear();

        match result {
            Ok(v) => {
                println!();
                output::print_field("File ID", &field_str(&v, "id"));
                output::print_field("Filename", &field_str(&v, "filename"));
                output::print_field(
                    "Size",
                    &human_bytes(v.get("bytes").and_then(|b| b.as_u64()).unwrap_or(0)),
                );
                output::print_field("Purpose", &field_str(&v, "purpose"));
                output::print_field("Owner", &field_str(&v, "owner"));
                match v.get("deal_id").and_then(|d| d.as_str()) {
                    Some(d) => output::print_field("Storage Deal", d),
                    // Worth saying plainly rather than printing a dash: the
                    // bytes are stored but nothing is paying to keep the
                    // shards alive, so durability is the operator's goodwill.
                    None => output::print_warning(
                        "No storage deal was opened — the file is stored but unbilled, and its \
                         shards are not funded. Do not rely on it persisting.",
                    ),
                }
                Ok(())
            }
            Err(e) => {
                output::print_error(&format!("Upload failed: {e}"));
                Ok(())
            }
        }
    }
}

#[derive(Debug, Parser)]
pub struct ListCmd {
    /// Narrow to one purpose
    #[arg(long)]
    purpose: Option<String>,
    /// How many to return, newest first
    #[arg(long)]
    limit: Option<u64>,
    #[command(flatten)]
    common: Common,
}

impl ListCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Files");
        let spinner = output::create_spinner("Listing...");
        let mut params = serde_json::json!({});
        if let Some(p) = &self.purpose {
            params["purpose"] = serde_json::json!(p);
        }
        if let Some(l) = self.limit {
            params["limit"] = serde_json::json!(l);
        }
        let result: Result<serde_json::Value> =
            self.common.client().call("tenzro_listFiles", params).await;
        spinner.finish_and_clear();

        match result {
            Ok(v) => {
                let rows = v
                    .get("data")
                    .and_then(|d| d.as_array())
                    .cloned()
                    .unwrap_or_default();
                println!();
                output::print_field("Files", &rows.len().to_string());
                output::print_field(
                    "Total",
                    &human_bytes(v.get("total_bytes").and_then(|b| b.as_u64()).unwrap_or(0)),
                );
                for f in &rows {
                    println!();
                    output::print_field(&field_str(f, "id"), &field_str(f, "filename"));
                    output::print_field(
                        "  Size",
                        &format!(
                            "{} · {}",
                            human_bytes(f.get("bytes").and_then(|b| b.as_u64()).unwrap_or(0)),
                            field_str(f, "purpose")
                        ),
                    );
                }
                if rows.is_empty() {
                    output::print_info("No files. Upload one with `tenzro files upload <path>`.");
                }
                Ok(())
            }
            Err(e) => {
                output::print_error(&format!("List failed: {e}"));
                Ok(())
            }
        }
    }
}

#[derive(Debug, Parser)]
pub struct GetCmd {
    /// File id (`file-<uuid>`)
    file_id: String,
    #[command(flatten)]
    common: Common,
}

impl GetCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("File");
        let result: Result<serde_json::Value> = self
            .common
            .client()
            .call(
                "tenzro_getFile",
                serde_json::json!({ "file_id": self.file_id }),
            )
            .await;
        match result {
            Ok(v) => {
                println!();
                output::print_field("File ID", &field_str(&v, "id"));
                output::print_field("Filename", &field_str(&v, "filename"));
                output::print_field(
                    "Size",
                    &human_bytes(v.get("bytes").and_then(|b| b.as_u64()).unwrap_or(0)),
                );
                output::print_field("Purpose", &field_str(&v, "purpose"));
                output::print_field("Owner", &field_str(&v, "owner"));
                output::print_field("Storage Deal", &field_str(&v, "deal_id"));
                Ok(())
            }
            Err(e) => {
                output::print_error(&format!("Lookup failed: {e}"));
                Ok(())
            }
        }
    }
}

#[derive(Debug, Parser)]
pub struct DownloadCmd {
    /// File id (`file-<uuid>`)
    file_id: String,
    /// Where to write it. Defaults to the stored filename in the current
    /// directory.
    #[arg(long)]
    out: Option<std::path::PathBuf>,
    #[command(flatten)]
    common: Common,
}

impl DownloadCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Download File");
        let spinner = output::create_spinner("Rebuilding from shards...");
        let result: Result<serde_json::Value> = self
            .common
            .client()
            .call(
                "tenzro_downloadFile",
                serde_json::json!({ "file_id": self.file_id }),
            )
            .await;
        spinner.finish_and_clear();

        let v = match result {
            Ok(v) => v,
            Err(e) => {
                output::print_error(&format!("Download failed: {e}"));
                return Ok(());
            }
        };
        let data = v
            .get("data")
            .and_then(|d| d.as_str())
            .context("the response carried no data")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .context("decoding the returned payload")?;
        let out = self
            .out
            .unwrap_or_else(|| std::path::PathBuf::from(field_str(&v, "filename")));
        std::fs::write(&out, &bytes).with_context(|| format!("writing {}", out.display()))?;

        println!();
        output::print_field("Wrote", &out.display().to_string());
        output::print_field("Size", &human_bytes(bytes.len() as u64));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct DeleteCmd {
    /// File id (`file-<uuid>`)
    file_id: String,
    #[command(flatten)]
    common: Common,
}

impl DeleteCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Delete File");
        let result: Result<serde_json::Value> = self
            .common
            .client()
            .call(
                "tenzro_deleteFile",
                serde_json::json!({ "file_id": self.file_id }),
            )
            .await;
        match result {
            Ok(v) => {
                println!();
                output::print_field("File ID", &field_str(&v, "id"));
                output::print_field("Deleted", "yes");
                // Printed in full, every time. A caller who reads "deleted:
                // yes" and stops there has drawn exactly the wrong conclusion
                // about what happened to the bytes.
                if let Some(note) = v.get("note").and_then(|n| n.as_str()) {
                    println!();
                    output::print_warning(note);
                }
                Ok(())
            }
            Err(e) => {
                output::print_error(&format!("Delete failed: {e}"));
                Ok(())
            }
        }
    }
}

#[derive(Debug, Parser)]
pub struct UsageCmd {
    #[command(flatten)]
    common: Common,
}

impl UsageCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Storage Usage");
        let result: Result<serde_json::Value> = self
            .common
            .client()
            .call("tenzro_fileStorageUsage", serde_json::json!({}))
            .await;
        match result {
            Ok(v) => {
                let unfunded = v
                    .get("files_without_open_deal")
                    .and_then(|n| n.as_u64())
                    .unwrap_or(0);
                println!();
                output::print_field("Owner", &field_str(&v, "owner"));
                output::print_field(
                    "Files",
                    &v.get("file_count")
                        .and_then(|n| n.as_u64())
                        .unwrap_or(0)
                        .to_string(),
                );
                output::print_field(
                    "Total",
                    &human_bytes(v.get("total_bytes").and_then(|b| b.as_u64()).unwrap_or(0)),
                );
                output::print_field("Billing Address", &field_str(&v, "renter_address"));
                if unfunded > 0 {
                    println!();
                    output::print_warning(&format!(
                        "{unfunded} file(s) have no open storage deal. They are stored but \
                         unbilled, and their shards are not funded — do not rely on them \
                         persisting."
                    ));
                }
                Ok(())
            }
            Err(e) => {
                output::print_error(&format!("Usage lookup failed: {e}"));
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_render_at_the_right_scale() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn the_largest_unit_does_not_overflow_the_table() {
        // A petabyte-scale number must still render, in TB, rather than
        // indexing past the end of the unit list.
        let s = human_bytes(u64::MAX);
        assert!(s.ends_with(" TB"), "{s}");
    }

    #[test]
    fn a_missing_field_renders_as_a_dash_rather_than_empty() {
        let v = serde_json::json!({ "id": "file-1" });
        assert_eq!(field_str(&v, "id"), "file-1");
        assert_eq!(field_str(&v, "deal_id"), "—");
    }
}
