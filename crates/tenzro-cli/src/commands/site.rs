//! Static-site hosting commands for the Tenzro CLI.
//!
//! `deploy` walks a local build-output directory, uploads each file to the
//! node's iroh blob store, builds a route map, detects whether the output is a
//! single-page app, and publishes a site manifest. `publish` is the same
//! deploy path with an explicit route set already resolved. `set-alias` points
//! a public hostname at a site so the Web-API edge serves it by Host header.
//!
//! Mutating operations (deploy/publish/remove/set-alias/remove-alias) require a
//! signed DID envelope proving control of `owner_did`, supplied as the hex
//! `--did-envelope` value produced by the identity tooling.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::output;

/// Static-site hosting operations.
#[derive(Debug, Subcommand)]
pub enum SiteCommand {
    /// Deploy a build-output directory: upload files, build routes, publish.
    Deploy(SiteDeployCmd),
    /// Get a site manifest by id.
    Get(SiteGetCmd),
    /// List sites, optionally filtered by owner DID.
    List(SiteListCmd),
    /// Remove a site (owner-authenticated).
    Remove(SiteRemoveCmd),
    /// Point a hostname at a site (owner-authenticated).
    SetAlias(SiteSetAliasCmd),
    /// Show a hostname alias.
    GetAlias(SiteGetAliasCmd),
    /// List hostname aliases, optionally filtered by owner DID.
    ListAliases(SiteListAliasesCmd),
    /// Remove a hostname alias (owner-authenticated).
    RemoveAlias(SiteRemoveAliasCmd),
    /// Set the serving nodes a site is placed on (owner-authenticated).
    SetPlacement(SiteSetPlacementCmd),
    /// Show a site's placement record.
    GetPlacement(SiteGetPlacementCmd),
    /// List all site placements.
    ListPlacements(SiteListPlacementsCmd),
    /// Clear a site's placement, reverting to local serving (owner-authenticated).
    RemovePlacement(SiteRemovePlacementCmd),
    /// Bring-your-own custom domain operations.
    #[command(subcommand)]
    Domain(SiteDomainCommand),
}

impl SiteCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Deploy(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Remove(cmd) => cmd.execute().await,
            Self::SetAlias(cmd) => cmd.execute().await,
            Self::GetAlias(cmd) => cmd.execute().await,
            Self::ListAliases(cmd) => cmd.execute().await,
            Self::RemoveAlias(cmd) => cmd.execute().await,
            Self::SetPlacement(cmd) => cmd.execute().await,
            Self::GetPlacement(cmd) => cmd.execute().await,
            Self::ListPlacements(cmd) => cmd.execute().await,
            Self::RemovePlacement(cmd) => cmd.execute().await,
            Self::Domain(cmd) => cmd.execute().await,
        }
    }
}

/// Custom-domain (bring-your-own hostname) operations. `add` claims a domain
/// for a site and prints the DNS records to publish; `verify` checks the DNS
/// TXT proof and, on success, admits the domain so a certificate is issued and
/// the hostname serves the site. TLS/DNS at the edge is automatic — no manual
/// certificate or Caddy setup.
#[derive(Debug, Subcommand)]
pub enum SiteDomainCommand {
    /// Claim a custom domain for a site and print the DNS records to publish.
    Add(SiteDomainAddCmd),
    /// Verify the DNS ownership proof for a claimed domain.
    Verify(SiteDomainVerifyCmd),
    /// Show a claimed custom domain.
    Get(SiteDomainGetCmd),
    /// List custom domains, optionally filtered by owner DID.
    List(SiteDomainListCmd),
    /// Remove a custom-domain claim (owner-authenticated).
    Remove(SiteDomainRemoveCmd),
}

impl SiteDomainCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Add(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Remove(cmd) => cmd.execute().await,
        }
    }
}

/// Map a file extension to a content type. Covers the static-web surface; an
/// unknown extension falls back to `application/octet-stream`.
fn content_type_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .as_deref()
    {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("map") => "application/json",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("avif") => "image/avif",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("webmanifest") => "application/manifest+json",
        Some("pdf") => "application/pdf",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        _ => "application/octet-stream",
    }
}

/// Recursively collect files under `root`, returning each file's absolute path
/// and its site route path (POSIX, leading slash, relative to `root`).
fn collect_files(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).with_context(|| format!("read_dir {dir:?}"))? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .with_context(|| format!("strip_prefix {path:?}"))?;
                let route = format!(
                    "/{}",
                    rel.components()
                        .filter_map(|c| c.as_os_str().to_str())
                        .collect::<Vec<_>>()
                        .join("/")
                );
                out.push((path, route));
            }
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

/// Whether a directory's output looks like a single-page app: an `index.html`
/// at the root with a client-side bundle (a `.js`/`.mjs` route) and no obvious
/// per-route HTML fanning-out. Heuristic, overridable with `--spa`/`--no-spa`.
fn detect_spa(routes: &BTreeMap<String, String>) -> bool {
    let has_index = routes.contains_key("/index.html");
    let html_count = routes.keys().filter(|p| p.ends_with(".html")).count();
    let has_bundle = routes
        .keys()
        .any(|p| p.ends_with(".js") || p.ends_with(".mjs"));
    has_index && has_bundle && html_count == 1
}

/// Deploy a build-output directory.
#[derive(Debug, Parser)]
pub struct SiteDeployCmd {
    /// Site name (owner-scoped; the site id is derived from owner_did + name).
    #[arg(long)]
    name: String,
    /// Owner DID.
    #[arg(long)]
    owner_did: String,
    /// Build-output directory to publish (e.g. ./dist, ./build, ./out).
    #[arg(long)]
    dir: PathBuf,
    /// Index route (default /index.html).
    #[arg(long)]
    index_path: Option<String>,
    /// Not-found route (served at HTTP 404 for asset misses).
    #[arg(long)]
    not_found_path: Option<String>,
    /// Force single-page-app fallback on (route misses serve the index at 200).
    #[arg(long)]
    spa: bool,
    /// Force single-page-app fallback off, overriding auto-detection.
    #[arg(long)]
    no_spa: bool,
    /// TNZO per request; when set, serving is x402-gated.
    #[arg(long)]
    price_per_request: Option<u128>,
    /// Number of distinct nodes to lease for this site. Defaults to 1.
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

impl SiteDeployCmd {
    pub async fn execute(&self) -> Result<()> {
        use base64::Engine as _;
        use crate::rpc::RpcClient;
        use crate::commands::lease::print_placement;

        output::print_header("Deploy Site");
        if !self.dir.is_dir() {
            anyhow::bail!("not a directory: {:?}", self.dir);
        }
        let files = collect_files(&self.dir)?;
        if files.is_empty() {
            anyhow::bail!("no files under {:?}", self.dir);
        }

        let rpc = RpcClient::new(&self.rpc);

        // Upload each file as an iroh blob; build the route map.
        let mut routes: BTreeMap<String, String> = BTreeMap::new();
        let mut route_entries: Vec<serde_json::Value> = Vec::new();
        let spinner = output::create_spinner("Uploading files...");
        for (path, route) in &files {
            let bytes = std::fs::read(path).with_context(|| format!("read {path:?}"))?;
            let size = bytes.len() as u64;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            let result: serde_json::Value = rpc
                .call(
                    "tenzro_iroh_publishBlob",
                    serde_json::json!({ "bytes_b64": b64 }),
                )
                .await
                .with_context(|| format!("publish blob for {route}"))?;
            let uri = result
                .get("tenzro_uri")
                .and_then(|v| v.as_str())
                .context("publishBlob returned no tenzro_uri")?;
            // tenzro://blob/<blake3-hex> — the route stores the raw hash.
            let blob_hash = uri
                .rsplit('/')
                .next()
                .context("malformed tenzro_uri")?
                .to_string();
            let content_type = content_type_for(path);
            route_entries.push(serde_json::json!({
                "path": route,
                "blob_hash": blob_hash,
                "content_type": content_type,
                "size": size,
            }));
            routes.insert(route.clone(), content_type.to_string());
        }
        spinner.finish_and_clear();
        output::print_field("Files", &files.len().to_string());

        let spa = if self.spa {
            true
        } else if self.no_spa {
            false
        } else {
            detect_spa(&routes)
        };
        output::print_field("Single-page app", if spa { "yes" } else { "no" });

        let mut params = serde_json::json!({
            "name": self.name,
            "owner_did": self.owner_did,
            "routes": route_entries,
            "spa": spa,
            "did_envelope": self.did_envelope,
        });
        if let Some(ip) = &self.index_path {
            params["index_path"] = serde_json::json!(ip);
        }
        if let Some(nf) = &self.not_found_path {
            params["not_found_path"] = serde_json::json!(nf);
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

        let spinner = output::create_spinner("Publishing manifest...");
        let manifest: serde_json::Value = rpc.call("tenzro_sitePublish", params).await?;
        spinner.finish_and_clear();

        output::print_success("Site deployed");
        let site_id = manifest
            .get("site_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        output::print_field("Site ID", site_id);
        output::print_field(
            "Version",
            &manifest
                .get("version")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        print_placement(&manifest);
        output::print_info(&format!("Served at GET /sites/{site_id}"));
        Ok(())
    }
}

/// Get a site manifest.
#[derive(Debug, Parser)]
pub struct SiteGetCmd {
    /// Site id.
    #[arg(long)]
    site_id: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let manifest: serde_json::Value = rpc
            .call("tenzro_siteGet", serde_json::json!({ "site_id": self.site_id }))
            .await?;
        output::print_json(&manifest)?;
        Ok(())
    }
}

/// List sites.
#[derive(Debug, Parser)]
pub struct SiteListCmd {
    /// Filter by owner DID.
    #[arg(long)]
    owner_did: Option<String>,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({});
        if let Some(o) = &self.owner_did {
            params["owner_did"] = serde_json::json!(o);
        }
        let result: serde_json::Value = rpc.call("tenzro_listSites", params).await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Remove a site.
#[derive(Debug, Parser)]
pub struct SiteRemoveCmd {
    /// Site id.
    #[arg(long)]
    site_id: String,
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

impl SiteRemoveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_siteRemove",
                serde_json::json!({
                    "site_id": self.site_id,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Site removed");
        output::print_json(&result)?;
        Ok(())
    }
}

/// Point a hostname at a site.
#[derive(Debug, Parser)]
pub struct SiteSetAliasCmd {
    /// Hostname to point at the site (a subdomain of your operator's app domain).
    #[arg(long)]
    hostname: String,
    /// Site id the hostname should resolve to.
    #[arg(long)]
    site_id: String,
    /// Owner DID (must own the target site).
    #[arg(long)]
    owner_did: String,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteSetAliasCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let alias: serde_json::Value = rpc
            .call(
                "tenzro_siteSetAlias",
                serde_json::json!({
                    "hostname": self.hostname,
                    "site_id": self.site_id,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Alias set");
        output::print_json(&alias)?;
        Ok(())
    }
}

/// Show a hostname alias.
#[derive(Debug, Parser)]
pub struct SiteGetAliasCmd {
    /// Hostname.
    #[arg(long)]
    hostname: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteGetAliasCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let alias: serde_json::Value = rpc
            .call(
                "tenzro_siteGetAlias",
                serde_json::json!({ "hostname": self.hostname }),
            )
            .await?;
        output::print_json(&alias)?;
        Ok(())
    }
}

/// List hostname aliases.
#[derive(Debug, Parser)]
pub struct SiteListAliasesCmd {
    /// Filter by owner DID.
    #[arg(long)]
    owner_did: Option<String>,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteListAliasesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({});
        if let Some(o) = &self.owner_did {
            params["owner_did"] = serde_json::json!(o);
        }
        let result: serde_json::Value = rpc.call("tenzro_listSiteAliases", params).await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Remove a hostname alias.
#[derive(Debug, Parser)]
pub struct SiteRemoveAliasCmd {
    /// Hostname.
    #[arg(long)]
    hostname: String,
    /// Owner DID (must own the alias).
    #[arg(long)]
    owner_did: String,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteRemoveAliasCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_siteRemoveAlias",
                serde_json::json!({
                    "hostname": self.hostname,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Alias removed");
        output::print_json(&result)?;
        Ok(())
    }
}

/// Set the serving nodes a site is placed on. An empty set reverts the site to
/// local serving on whichever node receives the request. Each entry is a serving
/// node's iroh EndpointId; the edge forwards requests over the `tenzro/http`
/// transport to a placed node when the site is not served locally.
#[derive(Debug, Parser)]
pub struct SiteSetPlacementCmd {
    /// Site id.
    #[arg(long)]
    site_id: String,
    /// Serving node EndpointId (repeatable). Omit to clear placement.
    #[arg(long = "serving-node")]
    serving_nodes: Vec<String>,
    /// Owner DID (must own the target site).
    #[arg(long)]
    owner_did: String,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteSetPlacementCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let record: serde_json::Value = rpc
            .call(
                "tenzro_siteSetPlacement",
                serde_json::json!({
                    "site_id": self.site_id,
                    "serving_nodes": self.serving_nodes,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Placement set");
        output::print_json(&record)?;
        Ok(())
    }
}

/// Show a site's placement record.
#[derive(Debug, Parser)]
pub struct SiteGetPlacementCmd {
    /// Site id.
    #[arg(long)]
    site_id: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteGetPlacementCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let record: serde_json::Value = rpc
            .call(
                "tenzro_siteGetPlacement",
                serde_json::json!({ "site_id": self.site_id }),
            )
            .await?;
        output::print_json(&record)?;
        Ok(())
    }
}

/// List all site placements.
#[derive(Debug, Parser)]
pub struct SiteListPlacementsCmd {
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteListPlacementsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listSitePlacements", serde_json::json!({}))
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Clear a site's placement, reverting to local serving.
#[derive(Debug, Parser)]
pub struct SiteRemovePlacementCmd {
    /// Site id.
    #[arg(long)]
    site_id: String,
    /// Owner DID (must own the target site).
    #[arg(long)]
    owner_did: String,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteRemovePlacementCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_siteRemovePlacement",
                serde_json::json!({
                    "site_id": self.site_id,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Placement cleared");
        output::print_json(&result)?;
        Ok(())
    }
}

/// Claim a custom domain for a site.
#[derive(Debug, Parser)]
pub struct SiteDomainAddCmd {
    /// Custom hostname you control (apex e.g. example.com, or subdomain e.g. app.example.com).
    #[arg(long)]
    hostname: String,
    /// Site id the hostname should serve.
    #[arg(long)]
    site_id: String,
    /// Owner DID (must own the target site).
    #[arg(long)]
    owner_did: String,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteDomainAddCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let domain: serde_json::Value = rpc
            .call(
                "tenzro_siteClaimDomain",
                serde_json::json!({
                    "hostname": self.hostname,
                    "site_id": self.site_id,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Custom domain claimed");

        println!("\nPublish these DNS records at your domain registrar, then run:");
        println!(
            "  tenzro site domain verify --hostname {} --owner-did {} --did-envelope <hex>\n",
            self.hostname, self.owner_did
        );
        // The node reports the exact records — including the edge address of the
        // operator that served this claim. A null `value` means the operator has
        // not published its edge address; fill it in from your operator.
        if let Some(records) = domain.get("dns_records").and_then(|v| v.as_array()) {
            for rec in records {
                let rtype = rec.get("record_type").and_then(|v| v.as_str()).unwrap_or("");
                let name = rec.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let value = rec
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<ask your operator for its edge address>");
                println!("       {name:<32} {rtype:<7} {value}");
            }
        }
        println!(
            "\nOnce these resolve, `verify` admits the domain and TLS is issued automatically — no certificate or web-server setup on your side.\n"
        );

        output::print_json(&domain)?;
        Ok(())
    }
}

/// Verify the DNS ownership proof for a claimed custom domain.
#[derive(Debug, Parser)]
pub struct SiteDomainVerifyCmd {
    /// Custom hostname previously claimed with `domain add`.
    #[arg(long)]
    hostname: String,
    /// Owner DID (must own the claim).
    #[arg(long)]
    owner_did: String,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteDomainVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let domain: serde_json::Value = rpc
            .call(
                "tenzro_siteVerifyDomain",
                serde_json::json!({
                    "hostname": self.hostname,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Custom domain verified — TLS is issued on first request");
        output::print_json(&domain)?;
        Ok(())
    }
}

/// Show a claimed custom domain.
#[derive(Debug, Parser)]
pub struct SiteDomainGetCmd {
    /// Custom hostname.
    #[arg(long)]
    hostname: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteDomainGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let domain: serde_json::Value = rpc
            .call(
                "tenzro_siteGetDomain",
                serde_json::json!({ "hostname": self.hostname }),
            )
            .await?;
        output::print_json(&domain)?;
        Ok(())
    }
}

/// List custom domains.
#[derive(Debug, Parser)]
pub struct SiteDomainListCmd {
    /// Filter by owner DID.
    #[arg(long)]
    owner_did: Option<String>,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteDomainListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({});
        if let Some(o) = &self.owner_did {
            params["owner_did"] = serde_json::json!(o);
        }
        let result: serde_json::Value = rpc.call("tenzro_listSiteDomains", params).await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Remove a custom-domain claim.
#[derive(Debug, Parser)]
pub struct SiteDomainRemoveCmd {
    /// Custom hostname.
    #[arg(long)]
    hostname: String,
    /// Owner DID (must own the claim).
    #[arg(long)]
    owner_did: String,
    /// Hex DID envelope proving control of owner_did.
    #[arg(long)]
    did_envelope: String,
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SiteDomainRemoveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_siteRemoveDomain",
                serde_json::json!({
                    "hostname": self.hostname,
                    "owner_did": self.owner_did,
                    "did_envelope": self.did_envelope,
                }),
            )
            .await?;
        output::print_success("Custom domain removed");
        output::print_json(&result)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_covers_web_surface() {
        assert_eq!(content_type_for(Path::new("a/index.html")), "text/html; charset=utf-8");
        assert_eq!(content_type_for(Path::new("app.js")), "text/javascript; charset=utf-8");
        assert_eq!(content_type_for(Path::new("style.css")), "text/css; charset=utf-8");
        assert_eq!(content_type_for(Path::new("logo.svg")), "image/svg+xml");
        assert_eq!(content_type_for(Path::new("bundle.wasm")), "application/wasm");
        assert_eq!(content_type_for(Path::new("noext")), "application/octet-stream");
    }

    #[test]
    fn detect_spa_recognizes_single_index_with_bundle() {
        let mut routes = BTreeMap::new();
        routes.insert("/index.html".to_string(), "text/html".to_string());
        routes.insert("/assets/app.js".to_string(), "text/javascript".to_string());
        routes.insert("/assets/app.css".to_string(), "text/css".to_string());
        assert!(detect_spa(&routes));
    }

    #[test]
    fn detect_spa_false_for_multipage() {
        let mut routes = BTreeMap::new();
        routes.insert("/index.html".to_string(), "text/html".to_string());
        routes.insert("/about.html".to_string(), "text/html".to_string());
        routes.insert("/app.js".to_string(), "text/javascript".to_string());
        assert!(!detect_spa(&routes));
    }

    #[test]
    fn detect_spa_false_without_bundle() {
        let mut routes = BTreeMap::new();
        routes.insert("/index.html".to_string(), "text/html".to_string());
        routes.insert("/style.css".to_string(), "text/css".to_string());
        assert!(!detect_spa(&routes));
    }
}
