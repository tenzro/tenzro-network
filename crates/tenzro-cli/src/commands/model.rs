//! Model management commands for the Tenzro CLI
//!
//! Uses tenzro-model directly to download, serve and delete models on this
//! machine. The catalog those commands read is the one a node serves
//! (`--catalog-rpc`, the local node by default).

use crate::output::{self};
use crate::rpc::RpcClient;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Model management commands
#[derive(Debug, Subcommand)]
pub enum ModelCommand {
    #[command(flatten)]
    Rpc(ModelRpcCommand),
    /// List available models from catalog
    List(ModelListCmd),
    /// Show this node's territorial licensing policy
    Territory(ModelTerritoryCmd),
    /// Show detailed model information
    Info(ModelInfoCmd),
    /// Download a model from HuggingFace
    Download(ModelDownloadCmd),
    /// Load and serve a model locally
    Serve(ModelServeCmd),
    /// Stop serving a model
    Stop(ModelStopCmd),
    /// Delete a downloaded model (removes all local files and caches)
    Delete(ModelDeleteCmd),
    /// List all model service endpoints
    Endpoints(ModelEndpointsCmd),
    /// Get details of a specific model endpoint
    Endpoint(ModelEndpointCmd),
    /// Discover models on the network
    Discover(ModelDiscoverCmd),
    /// Register a new model endpoint
    RegisterEndpoint(ModelRegisterEndpointCmd),
    /// Unregister a model endpoint
    UnregisterEndpoint(ModelUnregisterEndpointCmd),
    /// Reconcile the node's model registry (auto-reload served models, prune stale endpoints)
    Prune(ModelPruneCmd),
    /// Seal a local model artifact into encrypted shards for named recipients
    Seal(ModelSealCmd),
    /// Install a sealed model (fetch, verify, decrypt into local model storage)
    InstallSealed(ModelInstallSealedCmd),
    /// List sealed-model manifests stored on the node
    SealedList(ModelSealedListCmd),
    /// Fetch a full sealed-model manifest (for out-of-band delivery to recipients)
    SealedGet(ModelSealedGetCmd),
    /// Show the node's hybrid X25519 + ML-KEM-768 recipient public key for sealed models
    RecipientKey(ModelRecipientKeyCmd),
}

impl ModelCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Territory(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
            Self::Download(cmd) => cmd.execute().await,
            Self::Serve(cmd) => cmd.execute().await,
            Self::Stop(cmd) => cmd.execute().await,
            Self::Delete(cmd) => cmd.execute().await,
            Self::Endpoints(cmd) => cmd.execute().await,
            Self::Endpoint(cmd) => cmd.execute().await,
            Self::Discover(cmd) => cmd.execute().await,
            Self::RegisterEndpoint(cmd) => cmd.execute().await,
            Self::UnregisterEndpoint(cmd) => cmd.execute().await,
            Self::Prune(cmd) => cmd.execute().await,
            Self::Seal(cmd) => cmd.execute().await,
            Self::InstallSealed(cmd) => cmd.execute().await,
            Self::SealedList(cmd) => cmd.execute().await,
            Self::SealedGet(cmd) => cmd.execute().await,
            Self::RecipientKey(cmd) => cmd.execute().await,
        }
    }
}

/// List available models
#[derive(Debug, Parser)]
pub struct ModelListCmd {
    /// Show only downloaded models
    #[arg(long)]
    downloaded: bool,

    /// Show only models currently being served
    #[arg(long)]
    serving: bool,

    /// Filter by family (e.g. qwen3, gemma3, mistral)
    #[arg(long)]
    family: Option<String>,

    /// List every model the node holds, of every type (chat, vision,
    /// embedding, forecast, segmentation, detection, audio, video, media,
    /// speech), with its engine, visibility, access and state
    #[arg(long)]
    loaded: bool,

    /// Output format (table, json)
    #[arg(long, default_value = "table")]
    format: String,

    /// Node whose model catalog is read (the catalog is published data
    /// that nodes serve, not compiled into this binary).
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    catalog_rpc: String,
}

impl ModelListCmd {
    /// `--loaded`: what the node holds, from `tenzro_listModels { loaded: true }`.
    async fn execute_loaded(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.catalog_rpc);
        let res: serde_json::Value = rpc
            .call("tenzro_listModels", serde_json::json!({ "loaded": true }))
            .await?;
        if self.format == "json" {
            return output::print_json(&res);
        }
        output::print_header("Loaded Models");
        let field = |m: &serde_json::Value, k: &str| match m.get(k) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Bool(b)) => if *b { "yes" } else { "no" }.to_string(),
            _ => "-".to_string(),
        };
        let rows: Vec<Vec<String>> = res
            .get("models")
            .and_then(|v| v.as_array())
            .map(|models| {
                models
                    .iter()
                    .map(|m| {
                        vec![
                            field(m, "model_id"),
                            field(m, "type"),
                            field(m, "engine"),
                            field(m, "visibility"),
                            m.get("access")
                                .map(|a| field(a, "mode"))
                                .unwrap_or_else(|| "-".into()),
                            field(m, "loaded"),
                            field(m, "serving"),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        if rows.is_empty() {
            output::print_info("This node holds no models.");
            return Ok(());
        }
        output::print_table(
            &[
                "Model ID",
                "Type",
                "Engine",
                "Visibility",
                "Access",
                "Loaded",
                "Serving",
            ],
            &rows,
        );
        Ok(())
    }

    pub async fn execute(&self) -> Result<()> {
        use tenzro_model::{HfDownloader, get_model_catalog};

        if self.loaded {
            return self.execute_loaded().await;
        }

        crate::commands::catalog::install_from(&self.catalog_rpc).await?;

        output::print_header("Available Models");

        let models_dir = tenzro_types::paths::models_dir();
        let downloader = HfDownloader::new(models_dir);

        let catalog = get_model_catalog();

        // Load persisted config to know which models are served
        let config = crate::config::load_config();
        let served_models = config.served_models;

        if self.format == "json" {
            let json_models: Vec<serde_json::Value> = catalog
                .iter()
                .filter(|m| {
                    if let Some(ref family) = self.family
                        && m.family != *family
                    {
                        return false;
                    }
                    let is_downloaded = downloader.is_downloaded(&m.id);
                    let is_serving = served_models.contains(&m.id);
                    if self.downloaded && !is_downloaded {
                        return false;
                    }
                    if self.serving && !is_serving {
                        return false;
                    }
                    true
                })
                .map(|m| {
                    let is_downloaded = downloader.is_downloaded(&m.id);
                    let is_serving = served_models.contains(&m.id);
                    let availability = if is_serving {
                        "local"
                    } else if is_downloaded {
                        "downloaded"
                    } else {
                        "downloadable"
                    };
                    serde_json::json!({
                        "id": m.id,
                        "name": m.name,
                        "family": m.family,
                        "parameters": m.parameters,
                        "architecture": m.architecture.to_string(),
                        "quantization": m.quantization,
                        "size_bytes": m.size_bytes,
                        "min_ram_gb": m.min_ram_gb,
                        "context_length": m.context_length,
                        "license": tenzro_model::catalog::entry(&m.id).map(|e| e.licence.name),
                        "downloaded": is_downloaded,
                        "serving": is_serving,
                        "availability": availability,
                        "pricing": {
                            "input_per_token": if is_serving { 0.0 } else { 0.0001 },
                            "output_per_token": if is_serving { 0.0 } else { 0.0002 },
                            "currency": "TNZO",
                        },
                    })
                })
                .collect();
            output::print_json(&json_models)?;
            return Ok(());
        }

        let headers = vec![
            "Model ID",
            "Name",
            "Params",
            "Quant",
            "Size",
            "Availability",
            "Cost",
        ];
        let mut rows = Vec::new();

        for m in &catalog {
            if let Some(ref family) = self.family
                && m.family != *family
            {
                continue;
            }

            let is_downloaded = downloader.is_downloaded(&m.id);
            let is_serving = served_models.contains(&m.id);

            if self.downloaded && !is_downloaded {
                continue;
            }
            if self.serving && !is_serving {
                continue;
            }

            let availability = if is_serving {
                format!("{}local{}", output::colors::ok(), output::colors::reset())
            } else if is_downloaded {
                format!(
                    "{}downloaded{}",
                    output::colors::accent(),
                    output::colors::reset()
                )
            } else {
                "downloadable".to_string()
            };

            let cost_str = if is_serving {
                format!("{}free{}", output::colors::ok(), output::colors::reset())
            } else {
                "TNZO".to_string()
            };

            let size = format_bytes(m.size_bytes);

            rows.push(vec![
                m.id.clone(),
                m.name.clone(),
                m.parameters.clone(),
                m.quantization.clone(),
                size,
                availability,
                cost_str,
            ]);
        }

        if rows.is_empty() {
            output::print_info("No models found matching filters");
        } else {
            output::print_table(&headers, &rows);
            println!("Total: {} models", rows.len());
        }

        Ok(())
    }
}

/// Show model information
#[derive(Debug, Parser)]
pub struct ModelInfoCmd {
    /// Model ID
    model_id: String,

    /// Node whose model catalog is read (the catalog is published data
    /// that nodes serve, not compiled into this binary).
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    catalog_rpc: String,
}

impl ModelInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use tenzro_model::{HfDownloader, get_model_by_id};

        crate::commands::catalog::install_from(&self.catalog_rpc).await?;
        let licence = tenzro_model::catalog::entry(&self.model_id)
            .map(|e| e.licence.name)
            .unwrap_or_default();

        let entry = get_model_by_id(&self.model_id);

        match entry {
            Some(m) => {
                output::print_header(&format!("Model Information: {}", self.model_id));

                let models_dir = tenzro_types::paths::models_dir();
                let downloader = HfDownloader::new(models_dir);
                let is_downloaded = downloader.is_downloaded(&m.id);

                let config = crate::config::load_config();
                let is_serving = config.served_models.contains(&m.id);

                println!();
                output::print_field("Model ID", &m.id);
                output::print_field("Name", &m.name);
                output::print_field("Family", &m.family);
                output::print_field("Parameters", &m.parameters);
                output::print_field("Architecture", &m.architecture.to_string());
                output::print_field("Context Length", &format!("{} tokens", m.context_length));
                output::print_field("Quantization", &m.quantization);
                output::print_field("Size", &format_bytes(m.size_bytes));
                output::print_field("Min RAM", &format!("{} GB", m.min_ram_gb));
                output::print_field("License", &licence);

                // Mixture-of-Experts section — detected via architecture name
                // (Qwen3Moe, Qwen35Moe, Gemma4Moe etc.) and encoded total/active
                // parameter counts in the parameters / description strings.
                let arch_str = m.architecture.to_string();
                if arch_str.contains("moe") {
                    println!();
                    output::print_field("Mixture-of-Experts", "Yes");
                    // The `parameters` string encodes total/active counts, e.g.
                    // "30B (MoE, 32B active)" or "1T (MoE, 32B active)".
                    if let Some(open) = m.parameters.find('(') {
                        let total = m.parameters[..open].trim();
                        output::print_field("Total Parameters", total);
                        if let Some(close) = m.parameters[open..].find(')') {
                            let inside = &m.parameters[open + 1..open + close];
                            // Extract the "X active" token if present.
                            for part in inside.split(',') {
                                let p = part.trim();
                                if let Some(stripped) = p.strip_suffix(" active") {
                                    output::print_field("Active Parameters", stripped);
                                }
                            }
                        }
                    }
                    output::print_field(
                        "Routing",
                        "Sparse expert routing (llama.cpp auto-detects expert count from GGUF)",
                    );
                }

                // Multimodal (vision-language) — carries a separate mmproj
                // projector that llama.cpp loads via --mmproj for image input.
                if let Some(mmproj) = m.mmproj.as_ref() {
                    println!();
                    output::print_field("Multimodal", "Yes (text + image)");
                    output::print_field("Projector (mmproj)", &mmproj.filename);
                }

                // Speculative decoding — drafter pairing + flavour.
                if let Some(drafter) = m.drafter_id.as_ref() {
                    println!();
                    let flavour = match m.mtp_kind {
                        tenzro_catalog::MtpKind::DraftMtp => "MTP (joint draft head)",
                        tenzro_catalog::MtpKind::DraftDflash => {
                            "DFlash (block-diffusion self-draft)"
                        }
                        tenzro_catalog::MtpKind::Generic => "Generic (two-model)",
                        tenzro_catalog::MtpKind::None => "None",
                    };
                    output::print_field("Speculative Decoding", flavour);
                    output::print_field("Drafter", drafter);
                    if let Some(n) = m.mtp_default_draft_n {
                        output::print_field("Draft n (default)", &n.to_string());
                    }
                }

                // Serving profile — the catalog's model-author-recommended
                // sampler defaults (Unsloth per-family guidance). Requests may
                // override these; they're the defaults, not a ceiling.
                println!();
                let s = &m.serving;
                output::print_field("Serving — Temperature", &s.temperature.to_string());
                output::print_field("Serving — Top-P", &s.top_p.to_string());
                if s.top_k > 0 {
                    output::print_field("Serving — Top-K", &s.top_k.to_string());
                }
                if s.min_p > 0.0 {
                    output::print_field("Serving — Min-P", &s.min_p.to_string());
                }
                if s.presence_penalty > 0.0 {
                    output::print_field(
                        "Serving — Presence Penalty",
                        &s.presence_penalty.to_string(),
                    );
                }
                output::print_field(
                    "Serving — Chat Template (jinja)",
                    if s.jinja_required {
                        "required"
                    } else {
                        "optional"
                    },
                );
                output::print_field(
                    "Serving — Reasoning",
                    if s.reasoning_default {
                        "on by default"
                    } else {
                        "off by default"
                    },
                );

                println!();
                output::print_field("HF Repo", &m.hf_repo);
                output::print_field("Description", &m.description);
                println!();

                if is_serving {
                    output::print_status("Status", "Serving locally", true);
                } else if is_downloaded {
                    output::print_status("Status", "Downloaded (not serving)", true);
                } else {
                    output::print_status("Status", "Not downloaded", false);
                }

                if is_downloaded {
                    if let Some(size) = downloader.downloaded_size(&m.id) {
                        output::print_field("Local Size", &format_bytes(size));
                    }
                    output::print_field(
                        "Local Path",
                        &downloader.model_path(&m.id).display().to_string(),
                    );
                }
            }
            None => {
                output::print_warning(&format!("Model '{}' not found in catalog", self.model_id));
                output::print_info("Use 'tenzro model list' to see available models");
            }
        }

        Ok(())
    }
}

/// Download a model
#[derive(Debug, Parser)]
pub struct ModelDownloadCmd {
    /// Model ID to download
    model_id: String,

    /// Fetch source: 'network' (verified network providers only),
    /// 'huggingface' (HuggingFace only), or omit for network-first with a
    /// HuggingFace fallback.
    #[arg(long)]
    source: Option<String>,

    /// Node whose model catalog is read (the catalog is published data
    /// that nodes serve, not compiled into this binary).
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    catalog_rpc: String,
}

impl ModelDownloadCmd {
    fn policy(&self) -> tenzro_model::SourcePolicy {
        match self.source.as_deref() {
            Some("network") => tenzro_model::SourcePolicy::Network,
            Some("huggingface") | Some("hf") => tenzro_model::SourcePolicy::HuggingFace,
            _ => tenzro_model::SourcePolicy::Auto,
        }
    }

    pub async fn execute(&self) -> Result<()> {
        self.execute_local().await
    }

    async fn execute_local(&self) -> Result<()> {
        use tenzro_model::{HfDownloader, get_model_by_id};

        crate::commands::catalog::install_from(&self.catalog_rpc).await?;

        let entry = match get_model_by_id(&self.model_id) {
            Some(e) => e,
            None => {
                return Err(anyhow::anyhow!(
                    "Model '{}' not found in catalog. Use 'tenzro model list' to see available models.",
                    self.model_id
                ));
            }
        };

        let models_dir = tenzro_types::paths::models_dir();
        let downloader = HfDownloader::new(models_dir);

        if downloader.is_downloaded(&self.model_id) {
            output::print_success(&format!("Model '{}' is already downloaded", self.model_id));
            output::print_field(
                "Path",
                &downloader.model_path(&self.model_id).display().to_string(),
            );
            return Ok(());
        }

        output::print_header(&format!("Downloading Model: {}", entry.name));
        println!();
        output::print_field("Model", &entry.name);
        output::print_field(
            "Source",
            &format!("{}/{}", entry.hf_repo, entry.hf_filename),
        );
        output::print_field("Size", &format_bytes(entry.size_bytes));
        println!();

        let source_note = match self.policy() {
            tenzro_model::SourcePolicy::Network => "from verified network providers",
            tenzro_model::SourcePolicy::HuggingFace => "from HuggingFace",
            tenzro_model::SourcePolicy::Auto => "from the network, or HuggingFace if needed",
        };
        let task = crate::progress::global().bytes("Model download", Some(entry.size_bytes));
        task.message(source_note);

        let (progress_tx, mut progress_rx) =
            tokio::sync::watch::channel(tenzro_model::DownloadProgress {
                model_id: self.model_id.clone(),
                status: tenzro_model::DownloadState::Pending,
                progress_percent: 0.0,
                downloaded_bytes: 0,
                total_bytes: entry.size_bytes,
            });

        // Feed the progress display from the download as it moves.
        let reporter = task.reporter();
        let monitor = tokio::spawn(async move {
            while progress_rx.changed().await.is_ok() {
                let progress = progress_rx.borrow().clone();
                if progress.total_bytes > 0 {
                    reporter.set_total(progress.total_bytes);
                }
                reporter.set(progress.downloaded_bytes);
                if progress.total_bytes > 0 && progress.downloaded_bytes >= progress.total_bytes {
                    reporter.message("checking the file");
                }
            }
        });

        // Perform download
        let result = downloader
            .download_model(&entry, None, self.policy(), progress_tx)
            .await;
        monitor.abort();
        match result {
            Ok(path) => {
                task.finish();
                output::print_success(&format!("Model downloaded to: {}", path.display()));
            }
            Err(e) => {
                task.fail(&e.to_string());
                return Err(anyhow::anyhow!("Download failed: {}", e));
            }
        }
        Ok(())
    }
}

/// Start serving a model
#[derive(Debug, Parser)]
pub struct ModelServeCmd {
    /// Model ID to serve
    model_id: String,

    /// RPC endpoint to serve on a remote node (omit to serve locally)
    #[arg(long)]
    rpc: Option<String>,

    /// Force a LAN cluster even when the model fits one machine. By default
    /// the node forms a cluster only when the model is too large for the
    /// biggest single member; this requests one regardless.
    #[arg(long, conflicts_with = "force_single")]
    cluster: bool,

    /// Never form a cluster — load the whole model on this node even if it is
    /// too large for one machine (the load will fail if it does not fit).
    #[arg(long)]
    force_single: bool,

    /// Announce the model; any caller may invoke it by paying your per-use
    /// price (free at 0), with no key, even on a node whose service-key gate
    /// is on. Overrides the node's visibility for this model.
    #[arg(long, conflicts_with_all = ["gated", "private"])]
    public: bool,

    /// Announce the model as access-required: only callers your access
    /// policy names may invoke it. There is no pay-per-use path. Overrides the
    /// node's visibility for this model.
    #[arg(long, conflicts_with_all = ["public", "private"])]
    gated: bool,

    /// Do not announce the model; only this node's own callers may invoke it.
    /// Overrides the node's visibility for this model.
    ///
    /// With none of --public, --gated or --private the model follows the
    /// node's visibility (`tenzro visibility show`).
    #[arg(long, conflicts_with_all = ["public", "gated"])]
    private: bool,

    /// Serve without speculative decoding, even where the catalog pairs a
    /// drafter with this model.
    ///
    /// # What this costs and what it saves
    ///
    /// A drafter is a second model. Where the catalog declares one, serving
    /// fetches it if it is not already on disk and holds it resident beside
    /// the target for as long as the target is served — several more
    /// gigabytes of download and of VRAM, bought for roughly a 2x decode
    /// speed-up.
    ///
    /// That is usually the right trade and it is why it is the default. It is
    /// the wrong trade on a machine that is short of VRAM, on one paying for
    /// the bandwidth, or when the target is being served to sit idle most of
    /// the time — and until now there was no way to say so from here. The node
    /// has always accepted `load_drafter: false`; nothing exposed it.
    ///
    /// Models with an inline MTP head are unaffected: their speculation is
    /// trained into the target's own weights, so there is nothing separate to
    /// decline.
    ///
    /// Applies to a node serve — `--rpc`, or a node running locally. Drafters
    /// are loaded by the node, so a bare `model serve` that only warms weights
    /// in this process never loads one either way.
    #[arg(long)]
    no_speculative: bool,

    /// Node whose model catalog is read (the catalog is published data
    /// that nodes serve, not compiled into this binary).
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    catalog_rpc: String,
}

impl ModelServeCmd {
    pub async fn execute(&self) -> Result<()> {
        if let Some(ref rpc_url) = self.rpc {
            return self.execute_remote(rpc_url).await;
        }
        self.execute_local().await
    }

    async fn execute_remote(&self, rpc_url: &str) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header(&format!("Serving Model on Node: {}", self.model_id));
        println!();
        output::print_field("Node", rpc_url);
        output::print_field("Model", &self.model_id);
        println!();

        let rpc = RpcClient::new(rpc_url);
        let spinner = output::create_spinner("Loading model on node...");

        let mut req = serde_json::json!({
            "model_id": self.model_id,
            "user_forced": self.cluster,
            "force_single": self.force_single,
        });
        if self.public {
            req["visibility"] = serde_json::json!("public");
        } else if self.gated {
            req["visibility"] = serde_json::json!("gated");
        } else if self.private {
            req["visibility"] = serde_json::json!("private");
        }
        // Sent only when declining, so a serve that wants the default
        // behaviour carries no opinion about it — an explicit `true` here
        // would override a node-side default if one is ever introduced.
        if self.no_speculative {
            req["load_drafter"] = serde_json::json!(false);
        }
        let result: serde_json::Value = rpc
            .call("tenzro_serveModel", req)
            .await
            .map_err(|e| anyhow::anyhow!("Serve request failed: {}", e))?;

        spinner.finish_and_clear();

        if let Some(mc) = result.get("max_concurrent").and_then(|v| v.as_u64()) {
            output::print_success(&format!(
                "Model '{}' is now serving on node (max_concurrent: {})",
                self.model_id, mc
            ));
        } else {
            let status = result
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("ok");
            output::print_success(&format!(
                "Model '{}' serve request sent — status: {}",
                self.model_id, status
            ));
        }
        if let Some(ep) = result.get("endpoint_id").and_then(|v| v.as_str()) {
            output::print_field("Endpoint ID", ep);
        }
        println!();
        output::print_info(&format!(
            "Use 'tenzro chat {} --rpc {}' to interact.",
            self.model_id, rpc_url
        ));

        Ok(())
    }

    async fn execute_local(&self) -> Result<()> {
        use tenzro_model::{HfDownloader, ModelRuntime, get_model_by_id};

        crate::commands::catalog::install_from(&self.catalog_rpc).await?;

        let entry = match get_model_by_id(&self.model_id) {
            Some(e) => e,
            None => {
                return Err(anyhow::anyhow!(
                    "Model '{}' not found in catalog",
                    self.model_id
                ));
            }
        };

        let models_dir = tenzro_types::paths::models_dir();
        let downloader = HfDownloader::new(models_dir);

        if !downloader.is_downloaded(&self.model_id) {
            return Err(anyhow::anyhow!(
                "Model '{}' is not downloaded. Run 'tenzro model download {}' first.",
                self.model_id,
                self.model_id
            ));
        }

        output::print_header(&format!("Serving Model: {}", entry.name));

        let spinner = output::create_spinner("Loading model into memory...");

        let runtime = ModelRuntime::new()?;
        let gguf_path = downloader.model_path(&self.model_id);

        match runtime
            .load_model_with_context(&self.model_id, &gguf_path, Some(entry.context_length))
            .await
        {
            Ok(()) => {
                spinner.finish_and_clear();
                output::print_success(&format!("Model '{}' loaded successfully!", entry.name));

                // Update persisted config
                let mut config = crate::config::load_config();
                if !config.served_models.contains(&self.model_id) {
                    config.served_models.push(self.model_id.clone());
                }
                let _ = crate::config::save_config(&config);

                println!();
                output::print_info("Model is ready for inference. Use 'tenzro chat' to interact.");
            }
            Err(e) => {
                spinner.finish_and_clear();
                return Err(anyhow::anyhow!("Failed to load model: {}", e));
            }
        }

        Ok(())
    }
}

/// Stop serving a model
#[derive(Debug, Parser)]
pub struct ModelStopCmd {
    /// Model ID to stop serving
    model_id: String,

    /// RPC endpoint of the node serving the model. Defaults to the local one,
    /// which is what an operator running their own node and chain wants.
    ///
    /// If nothing answers there, the decision is still recorded locally: an
    /// operator who starts their node on demand is not a failed stop. What is
    /// a failed stop is a node that answers and refuses — that used to print
    /// success too.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelStopCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("Stopping Model: {}", self.model_id));

        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Stopping model on node...");
        let result: Result<serde_json::Value> = rpc
            .call(
                "tenzro_stopModel",
                serde_json::json!([{
                    "model_id": self.model_id
                }]),
            )
            .await;
        spinner.finish_and_clear();

        // Two different failures wear the same error, and conflating them is
        // what made this command lie. A node that ANSWERS and refuses has not
        // stopped anything: the weights stay resident, the memory stays held,
        // the endpoint stays online and the persisted intent stays on disk, so
        // a restart warms it straight back. A node that does not answer at all
        // is an operator who runs theirs on demand — nothing is serving, and
        // recording the decision locally is the whole of what "stop" can mean.
        if let Err(e) = result {
            let node_answered = rpc
                .call::<serde_json::Value>("tenzro_getNodeStatus", serde_json::json!([]))
                .await
                .is_ok();

            if node_answered {
                output::print_error(&format!("Model '{}' was NOT stopped: {}", self.model_id, e));
                output::print_info(&format!(
                    "The node at {} is running and still serving it, still \
                     holding its memory. Stopping a model is for node \
                     administrators: sign in with `tenzro access sign-in`.",
                    self.rpc
                ));
                return Err(anyhow::anyhow!("stop refused by {}: {}", self.rpc, e));
            }

            let mut config = crate::config::load_config();
            config.served_models.retain(|id| id != &self.model_id);
            let _ = crate::config::save_config(&config);
            output::print_info(&format!(
                "No node answered at {}. Recorded locally: '{}' will not be \
                 served when a node starts here.",
                self.rpc, self.model_id
            ));
            return Ok(());
        }

        // Only now: the node has unloaded it and cleared the persisted intent,
        // so this records the same decision on the CLI side.
        let mut config = crate::config::load_config();
        config.served_models.retain(|id| id != &self.model_id);
        let _ = crate::config::save_config(&config);

        output::print_success(&format!(
            "Model '{}' stopped on {} — memory released, and it will not be \
             warmed again on restart",
            self.model_id, self.rpc
        ));

        Ok(())
    }
}

/// Delete a downloaded model
#[derive(Debug, Parser)]
pub struct ModelDeleteCmd {
    /// Model ID to delete
    model_id: String,

    /// Skip confirmation prompt
    #[arg(long, short = 'y')]
    yes: bool,
}

impl ModelDeleteCmd {
    pub async fn execute(&self) -> Result<()> {
        use tenzro_model::HfDownloader;

        let models_dir = tenzro_types::paths::models_dir();
        let downloader = HfDownloader::new(models_dir);

        if !downloader.is_downloaded(&self.model_id) {
            output::print_info(&format!("Model '{}' is not downloaded", self.model_id));
            return Ok(());
        }

        if !self.yes {
            use dialoguer::Confirm;
            let confirm = Confirm::new()
                .with_prompt(format!(
                    "Delete model '{}' and all cached files?",
                    self.model_id
                ))
                .default(false)
                .interact()?;

            if !confirm {
                output::print_info("Cancelled");
                return Ok(());
            }
        }

        // Remove from served_models config first
        let mut config = crate::config::load_config();
        config.served_models.retain(|id| id != &self.model_id);
        let _ = crate::config::save_config(&config);

        // Delete model files (including HF cache)
        match downloader.delete_model(&self.model_id) {
            Ok(()) => {
                output::print_success(&format!(
                    "Model '{}' deleted (local files and HF cache removed)",
                    self.model_id
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to delete model: {}", e));
            }
        }

        Ok(())
    }
}

/// List all model service endpoints
#[derive(Debug, Parser)]
pub struct ModelEndpointsCmd {
    /// Output format (table, json)
    #[arg(long, default_value = "table")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelEndpointsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Model Endpoints");
        println!();

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Fetching model endpoints...");

        let endpoints_result: Result<Vec<serde_json::Value>> = rpc
            .call("tenzro_listModelEndpoints", serde_json::json!([]))
            .await;

        spinner.finish_and_clear();

        match endpoints_result {
            Ok(endpoints) => {
                if self.format == "json" {
                    output::print_json(&endpoints)?;
                    return Ok(());
                }

                if endpoints.is_empty() {
                    output::print_info("No model endpoints registered.");
                    return Ok(());
                }

                let headers = vec![
                    "Served by",
                    "Model",
                    "Instance ID",
                    "Endpoint ID",
                    "Status",
                    "Load",
                ];
                let mut rows = Vec::new();

                for endpoint in &endpoints {
                    let location = endpoint
                        .get("location")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let iroh_endpoint_id = endpoint
                        .get("iroh_endpoint_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let model_name = endpoint
                        .get("model_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let instance_id = endpoint
                        .get("instance_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let endpoint_id = endpoint
                        .get("iroh_endpoint_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let status = endpoint
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");

                    // A non-empty iroh_endpoint_id means the model is reachable
                    // over the network by that EndpointId (resolved via Pkarr,
                    // not by IP). Otherwise fall back to `location`: "local" is
                    // a same-machine endpoint, anything else is network-reached
                    // by URL only.
                    let location_colored = if !iroh_endpoint_id.is_empty() {
                        let short = if iroh_endpoint_id.len() > 10 {
                            &iroh_endpoint_id[..10]
                        } else {
                            iroh_endpoint_id
                        };
                        format!(
                            "{}network · {}…{}",
                            output::colors::accent(),
                            short,
                            output::colors::reset()
                        )
                    } else if location == "local" {
                        format!(
                            "{}local{}",
                            output::colors::accent(),
                            output::colors::reset()
                        )
                    } else {
                        format!(
                            "{}network{}",
                            output::colors::accent(),
                            output::colors::reset()
                        )
                    };

                    let status_colored = if status.to_lowercase() == "online" {
                        format!("{}online{}", output::colors::ok(), output::colors::reset())
                    } else {
                        format!(
                            "{}offline{}",
                            output::colors::bad(),
                            output::colors::reset()
                        )
                    };

                    let load_str = if let Some(load) = endpoint.get("load") {
                        output::format_load_info(load)
                    } else {
                        String::new()
                    };

                    // Truncate instance_id for display
                    let instance_id_short = if instance_id.len() > 12 {
                        format!("{}...", &instance_id[..12])
                    } else {
                        instance_id.to_string()
                    };

                    rows.push(vec![
                        location_colored,
                        model_name.to_string(),
                        instance_id_short,
                        endpoint_id.to_string(),
                        status_colored,
                        load_str,
                    ]);
                }

                output::print_table(&headers, &rows);
                println!("Total: {} endpoint(s)", endpoints.len());
            }
            Err(e) => {
                output::print_warning(&format!("Failed to fetch endpoints: {}", e));
                println!();
                output::print_info(&format!(
                    "Make sure a Tenzro node is running at {}",
                    self.rpc
                ));
            }
        }

        Ok(())
    }
}

/// Get details of a specific model endpoint
#[derive(Debug, Parser)]
pub struct ModelEndpointCmd {
    /// Instance ID of the endpoint
    id: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelEndpointCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header(&format!("Model Endpoint: {}", self.id));
        println!();

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Fetching endpoint details...");

        let params = serde_json::json!({
            "instance_id": self.id
        });

        let endpoint_result: Result<serde_json::Value> = rpc
            .call("tenzro_getModelEndpoint", serde_json::json!([params]))
            .await;

        spinner.finish_and_clear();

        match endpoint_result {
            Ok(endpoint) => {
                if self.format == "json" {
                    output::print_json(&endpoint)?;
                    return Ok(());
                }

                let instance_id = endpoint
                    .get("instance_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.id);
                let model_name = endpoint
                    .get("model_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let model_id = endpoint
                    .get("model_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let location = endpoint
                    .get("location")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let provider_name = endpoint
                    .get("provider_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let status = endpoint
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let mcp_endpoint = endpoint
                    .get("mcp_endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let iroh_endpoint_id = endpoint
                    .get("iroh_endpoint_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                output::print_field("Instance ID", instance_id);

                if !model_id.is_empty() {
                    output::print_field("Model", &format!("{} ({})", model_name, model_id));
                } else {
                    output::print_field("Model", model_name);
                }

                // A non-empty iroh_endpoint_id means the model is reachable over
                // the network by that EndpointId (resolved through the signed
                // endpoint records, not by IP).
                let served_by = if !iroh_endpoint_id.is_empty() {
                    format!("network ({})", iroh_endpoint_id)
                } else if location == "local" {
                    "local".to_string()
                } else {
                    "network".to_string()
                };
                output::print_field("Served by", &served_by);
                output::print_field("Provider", provider_name);
                output::print_field("Status", status);

                if let Some(parameters) = endpoint.get("parameters")
                    && let Some(params_str) = parameters.as_str()
                {
                    output::print_field("Parameters", params_str);
                }

                if !mcp_endpoint.is_empty() {
                    output::print_field("MCP Endpoint", mcp_endpoint);
                }

                // Pricing information
                if let Some(pricing) = endpoint.get("pricing").and_then(|v| v.as_object()) {
                    let input_price = pricing
                        .get("input_per_token")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");
                    let output_price = pricing
                        .get("output_per_token")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");

                    let pricing_str = if location == "local" {
                        "Free (local)".to_string()
                    } else {
                        format!(
                            "{} TNZO per input token, {} TNZO per output token",
                            input_price, output_price
                        )
                    };
                    output::print_field("Pricing", &pricing_str);
                }

                // Load information
                if let Some(load) = endpoint.get("load") {
                    println!();
                    output::print_field("Load", &output::format_load_info(load));
                    if let Some(active) = load.get("active_requests").and_then(|v| v.as_u64()) {
                        output::print_field("  Active Requests", &active.to_string());
                    }
                    if let Some(max) = load.get("max_concurrent").and_then(|v| v.as_u64()) {
                        output::print_field("  Max Concurrent", &max.to_string());
                    }
                }
            }
            Err(e) => {
                output::print_warning(&format!("Failed to fetch endpoint details: {}", e));
                println!();
                output::print_info(&format!(
                    "Make sure a Tenzro node is running at {}",
                    self.rpc
                ));
                output::print_info(&format!("and that endpoint '{}' exists", self.id));
            }
        }

        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Discover models on the network
#[derive(Debug, Parser)]
pub struct ModelDiscoverCmd {
    /// Filter by category (e.g. "text-generation", "image", "embedding")
    #[arg(long)]
    category: Option<String>,
    /// Filter by name substring
    #[arg(long)]
    name: Option<String>,
    /// Maximum results
    #[arg(long, default_value = "20")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelDiscoverCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Discover Models");
        let spinner = output::create_spinner("Discovering...");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({ "limit": self.limit });
        if let Some(ref c) = self.category {
            params["category"] = serde_json::json!(c);
        }
        if let Some(ref n) = self.name {
            params["name"] = serde_json::json!(n);
        }
        let result: serde_json::Value = rpc.call("tenzro_discoverModels", params).await?;
        spinner.finish_and_clear();
        if let Some(models) = result.as_array() {
            if models.is_empty() {
                output::print_info("No models discovered.");
            } else {
                let headers = vec!["Model ID", "Name", "Category", "Provider"];
                let mut rows = Vec::new();
                for m in models {
                    rows.push(vec![
                        m.get("model_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        m.get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        m.get("category")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        m.get("provider")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        } else {
            output::print_json(&result)?;
        }
        Ok(())
    }
}

/// Register a new model endpoint
#[derive(Debug, Parser)]
pub struct ModelRegisterEndpointCmd {
    /// Model ID
    #[arg(long)]
    model_id: String,
    /// Provider name
    #[arg(long)]
    provider: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelRegisterEndpointCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Register Model Endpoint");
        let spinner = output::create_spinner("Registering...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_registerModelEndpoint",
                serde_json::json!({
                    "model_id": self.model_id,
                    "provider": self.provider,
                }),
            )
            .await?;
        spinner.finish_and_clear();
        output::print_success("Endpoint registered!");
        if let Some(v) = result.get("instance_id").and_then(|v| v.as_str()) {
            output::print_field("Instance ID", v);
        }
        output::print_field("Model", &self.model_id);
        Ok(())
    }
}

/// Unregister a model endpoint
#[derive(Debug, Parser)]
pub struct ModelUnregisterEndpointCmd {
    /// Instance ID of the endpoint to unregister
    instance_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelUnregisterEndpointCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Unregister Model Endpoint");
        let spinner = output::create_spinner("Unregistering...");
        let rpc = RpcClient::new(&self.rpc);
        let _result: serde_json::Value = rpc
            .call(
                "tenzro_unregisterModelEndpoint",
                serde_json::json!({
                    "instance_id": self.instance_id,
                }),
            )
            .await?;
        spinner.finish_and_clear();
        output::print_success(&format!("Endpoint {} unregistered", self.instance_id));
        Ok(())
    }
}

/// Reconcile the node's model registry — auto-reload served models from disk,
/// clear stale served flags, and prune orphaned endpoints.
#[derive(Debug, Parser)]
pub struct ModelPruneCmd {
    /// RPC endpoint (default: http://127.0.0.1:8545)
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl ModelPruneCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Reconciling Model Registry");

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Running reconcile on node...");
        let result: serde_json::Value = rpc
            .call("tenzro_pruneModelRegistry", serde_json::Value::Null)
            .await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        let reloaded = result.get("reloaded").and_then(|v| v.as_u64()).unwrap_or(0);
        let cleared_models = result
            .get("cleared_models")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let cleared_services = result
            .get("cleared_services")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        output::print_success(&format!(
            "Reconcile complete: {} auto-reloaded, {} served flag(s) cleared, {} endpoint(s) pruned",
            reloaded, cleared_models, cleared_services
        ));
        Ok(())
    }
}

/// Seal a local model artifact into encrypted shards for named recipients.
///
/// Splits the file into AES-256-GCM shards published to the blob layer,
/// wraps the content key to each recipient's hybrid X25519 + ML-KEM-768 public key
/// (`x25519-mlkem768-hkdf-sha256-envelope-aes-256-gcm`), and stores the signed
/// manifest on the node. For node administrators only.
#[derive(Debug, Parser)]
pub struct ModelSealCmd {
    /// Model ID to seal under
    model_id: String,

    /// Local artifact file to seal (e.g. a GGUF)
    #[arg(long)]
    path: String,

    /// Publisher DID recorded on the manifest
    #[arg(long)]
    owner_did: String,

    /// Recipient in `did:...=<2432-hex hybrid recipient key>[=<enclave measurement hex>]`
    /// form (repeatable). A third component pins the recipient to an enclave
    /// measurement — that node must produce a matching attestation to install.
    #[arg(long = "recipient", required = true)]
    recipients: Vec<String>,

    /// Artifact name (defaults to the file name)
    #[arg(long)]
    artifact_name: Option<String>,

    /// Shard size in bytes (defaults to 256 MiB)
    #[arg(long)]
    shard_bytes: Option<u64>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl ModelSealCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header(&format!("Sealing Model: {}", self.model_id));

        let mut recipients = Vec::with_capacity(self.recipients.len());
        for r in &self.recipients {
            let mut parts = r.splitn(3, '=');
            let did = parts.next().filter(|s| !s.is_empty());
            let pubkey = parts.next().filter(|s| !s.is_empty());
            let (did, pubkey) = match (did, pubkey) {
                (Some(d), Some(p)) => (d, p),
                _ => {
                    return Err(anyhow::anyhow!(
                        "recipient '{}' must be \
                         'did:...=<2432-hex hybrid recipient key>[=<enclave measurement hex>]'",
                        r
                    ));
                }
            };
            let mut entry = serde_json::json!({
                "did": did,
                "recipient_key": pubkey,
            });
            if let Some(measurement) = parts.next().filter(|s| !s.is_empty()) {
                entry["enclave_measurement_hex"] = serde_json::json!(measurement);
            }
            recipients.push(entry);
        }

        let mut params = serde_json::json!({
            "model_id": self.model_id,
            "path": self.path,
            "owner_did": self.owner_did,
            "recipients": recipients,
        });
        if let Some(ref name) = self.artifact_name {
            params["artifact_name"] = serde_json::json!(name);
        }
        if let Some(bytes) = self.shard_bytes {
            params["shard_bytes"] = serde_json::json!(bytes);
        }

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Sealing artifact and publishing shards...");
        let result: serde_json::Value = rpc.call("tenzro_sealModel", params).await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        output::print_success(&format!("Model '{}' sealed", self.model_id));
        output::print_field(
            "Manifest hash",
            result
                .get("manifest_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
        );
        output::print_field(
            "Model hash",
            result
                .get("model_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
        );
        output::print_field(
            "Shards",
            &result
                .get("shard_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        output::print_field(
            "Recipients",
            &result
                .get("recipient_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        output::print_field(
            "Wrap alg",
            result
                .get("wrap_alg")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
        );
        Ok(())
    }
}

/// Install a sealed model on this node: fetch shards from the blob layer,
/// verify the manifest signature and hashes, decrypt with the node's
/// hybrid X25519 + ML-KEM-768 recipient key, and write the artifact into local model storage.
#[derive(Debug, Parser)]
pub struct ModelInstallSealedCmd {
    /// Recipient DID (must match a manifest recipient addressed to this node)
    #[arg(long)]
    recipient_did: String,

    /// Model ID whose manifest is already stored on the node
    #[arg(long, conflicts_with = "manifest_file")]
    model_id: Option<String>,

    /// Path to a manifest JSON file received out-of-band from the publisher
    #[arg(long, conflicts_with = "model_id")]
    manifest_file: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl ModelInstallSealedCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Installing Sealed Model");

        let mut params = serde_json::json!({
            "recipient_did": self.recipient_did,
        });
        match (&self.model_id, &self.manifest_file) {
            (Some(id), None) => {
                params["model_id"] = serde_json::json!(id);
            }
            (None, Some(file)) => {
                let raw = std::fs::read_to_string(file)?;
                let manifest: serde_json::Value = serde_json::from_str(&raw)?;
                params["manifest"] = manifest;
            }
            _ => {
                anyhow::bail!("provide exactly one of --model-id or --manifest-file");
            }
        }

        let rpc = RpcClient::new(&self.rpc);

        let spinner = output::create_spinner("Fetching, verifying, and decrypting shards...");
        let result: serde_json::Value = rpc.call("tenzro_installSealedModel", params).await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        output::print_success(&format!(
            "Sealed model '{}' installed",
            result
                .get("model_id")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
        ));
        output::print_field(
            "Path",
            result
                .get("installed_path")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
        );
        output::print_field(
            "Bytes",
            &result
                .get("total_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        Ok(())
    }
}

/// List sealed-model manifests stored on the node.
#[derive(Debug, Parser)]
pub struct ModelSealedListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (table, json)
    #[arg(long, default_value = "table")]
    format: String,
}

impl ModelSealedListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Sealed Models");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listSealedModels", serde_json::Value::Null)
            .await?;

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        let empty = Vec::new();
        let models = result
            .get("sealed_models")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);
        if models.is_empty() {
            output::print_info("No sealed models stored on this node");
            return Ok(());
        }

        let headers = vec![
            "Model ID",
            "Artifact",
            "Size",
            "Shards",
            "Recipients",
            "Owner DID",
        ];
        let rows: Vec<Vec<String>> = models
            .iter()
            .map(|m| {
                vec![
                    m.get("model_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    m.get("artifact_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    format_bytes(m.get("total_bytes").and_then(|v| v.as_u64()).unwrap_or(0)),
                    m.get("shard_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0)
                        .to_string(),
                    m.get("recipients")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                        .to_string(),
                    m.get("owner_did")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                ]
            })
            .collect();
        output::print_table(&headers, &rows);
        Ok(())
    }
}

/// Fetch a full sealed-model manifest — pass the JSON to recipients
/// out-of-band so they can run `model install-sealed --manifest-file`.
#[derive(Debug, Parser)]
pub struct ModelSealedGetCmd {
    /// Model ID
    model_id: String,

    /// Write the manifest JSON to this file instead of stdout
    #[arg(long)]
    out: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelSealedGetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getSealedModel",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;

        match &self.out {
            Some(path) => {
                std::fs::write(path, serde_json::to_string_pretty(&result)?)?;
                output::print_success(&format!("Manifest written to {}", path));
            }
            None => {
                output::print_json(&result)?;
            }
        }
        Ok(())
    }
}

/// Show the node's hybrid X25519 + ML-KEM-768 recipient public key for sealed models. Give
/// this key to a publisher so they can address a sealed model to this
/// node.
#[derive(Debug, Parser)]
pub struct ModelRecipientKeyCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl ModelRecipientKeyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_modelRecipientKey", serde_json::Value::Null)
            .await?;

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        output::print_field(
            "Recipient key (X25519 + ML-KEM-768)",
            result
                .get("recipient_key")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
        );
        output::print_field(
            "Wrap alg",
            result
                .get("wrap_alg")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
        );
        Ok(())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else {
        format!("{} KB", bytes / 1_000)
    }
}

/// Show this node's territorial licensing policy.
///
/// Reports the operator's posture and which licences carry a territorial term —
/// never a caller's location or a past decision, which are personal data and
/// stay in the node's log.
#[derive(Debug, Parser)]
pub struct ModelTerritoryCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl ModelTerritoryCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Territorial Licensing Policy");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getTerritoryPolicy", serde_json::json!([]))
            .await?;

        let mode = result.get("mode").and_then(|m| m.as_str()).unwrap_or("?");
        println!();
        output::print_field("Mode", mode);
        let explanation = match mode {
            "enforce" => "restricted models are checked per request",
            "refuse_restricted" => "territorially-restricted models are not served at all",
            _ => "unrecognised mode",
        };
        output::print_field("Meaning", explanation);
        output::print_field(
            "Node jurisdiction",
            result
                .get("node_jurisdiction")
                .and_then(|j| j.as_str())
                .unwrap_or("undeclared (territorial models are not loaded)"),
        );
        output::print_field(
            "Database",
            result
                .get("database")
                .and_then(|d| d.as_str())
                .unwrap_or("none"),
        );
        output::print_field(
            "Trusted proxies",
            &result
                .get("trusted_proxies")
                .and_then(|t| t.as_u64())
                .unwrap_or(0)
                .to_string(),
        );

        let restricted = result
            .get("restricted_licenses")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        println!();
        if restricted.is_empty() {
            output::print_field("Restricted licences", "none");
        } else {
            for l in &restricted {
                let id = l.get("license_id").and_then(|i| i.as_str()).unwrap_or("?");
                let excluded = l
                    .get("excluded")
                    .and_then(|e| e.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let per_request = l
                    .get("per_request")
                    .and_then(|p| p.as_bool())
                    .unwrap_or(false);
                let scope = if per_request {
                    "per request"
                } else {
                    "at registration"
                };
                output::print_field(id, &format!("excludes {excluded} — enforced {scope}"));
            }
        }

        Ok(())
    }
}

/// Model commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum ModelRpcCommand {
    /// Call tenzro_deleteModel (delete model) and print the node's answer
    DeleteServed(ModelDeleteServedRpcCmd),
    /// Call tenzro_previewServe (preview serve) and print the node's answer
    PreviewServe(ModelPreviewServeRpcCmd),
    /// Call tenzro_buildModelManifest (build model manifest) and print the node's answer
    BuildManifest(ModelBuildManifestRpcCmd),
    /// Call tenzro_pinModel (pin model) and print the node's answer
    Pin(ModelPinRpcCmd),
    /// Call tenzro_unpinModel (unpin model) and print the node's answer
    Unpin(ModelUnpinRpcCmd),
    /// Call tenzro_modelMetadata (model metadata) and print the node's answer
    Metadata(ModelMetadataRpcCmd),
    /// Call tenzro_getAttestationLog (get attestation log) and print the node's answer
    AttestationLog(ModelAttestationLogRpcCmd),
    /// Call tenzro_moeListReceipts (moe list receipts) and print the node's answer
    MoeReceipts(ModelMoeReceiptsRpcCmd),
    /// Call tenzro_loadMediaModel (load media model) and print the node's answer
    LoadMediaModel(ModelLoadMediaModelRpcCmd),
    /// Call tenzro_unloadMediaModel (unload media model) and print the node's answer
    UnloadMediaModel(ModelUnloadMediaModelRpcCmd),
    /// Call tenzro_registerKeyRelease (register a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy) and print the node's answer
    KeyReleaseRegister(ModelKeyReleaseRegisterRpcCmd),
    /// Call tenzro_revokeKeyRelease (revoke a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy) and print the node's answer
    KeyReleaseRevoke(ModelKeyReleaseRevokeRpcCmd),
    /// Call tenzro_requestKeyRelease (submit an attested environment's release request (`request`), which the provider node verifies and records) and print the node's answer
    KeyReleaseRequest(ModelKeyReleaseRequestRpcCmd),
    /// Call tenzro_getKeyRelease (a model's release policy and releases (`model_id`), or for a recorded `request` the content key sealed to the environment) and print the node's answer
    KeyReleaseGet(ModelKeyReleaseGetRpcCmd),
    /// Call tenzro_commitTrainingRound (commit a training round's signed receipt against its milestone escrow) and print the node's answer
    TrainingCommitRound(ModelTrainingCommitRoundRpcCmd),
    /// Call tenzro_settleTrainingRound (settle a committed training round (`receipt_id`) once its challenge window has closed) and print the node's answer
    TrainingSettleRound(ModelTrainingSettleRoundRpcCmd),
    /// Call tenzro_trainedModelProvenance (the provenance of a trained model (`model_id`) from its committed training rounds (`rounds`)) and print the node's answer
    TrainedProvenance(ModelTrainedProvenanceRpcCmd),
}

impl ModelRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::DeleteServed(cmd) => cmd.execute().await,
            Self::PreviewServe(cmd) => cmd.execute().await,
            Self::BuildManifest(cmd) => cmd.execute().await,
            Self::Pin(cmd) => cmd.execute().await,
            Self::Unpin(cmd) => cmd.execute().await,
            Self::Metadata(cmd) => cmd.execute().await,
            Self::AttestationLog(cmd) => cmd.execute().await,
            Self::MoeReceipts(cmd) => cmd.execute().await,
            Self::LoadMediaModel(cmd) => cmd.execute().await,
            Self::UnloadMediaModel(cmd) => cmd.execute().await,
            Self::KeyReleaseRegister(cmd) => cmd.execute().await,
            Self::KeyReleaseRevoke(cmd) => cmd.execute().await,
            Self::KeyReleaseRequest(cmd) => cmd.execute().await,
            Self::KeyReleaseGet(cmd) => cmd.execute().await,
            Self::TrainingCommitRound(cmd) => cmd.execute().await,
            Self::TrainingSettleRound(cmd) => cmd.execute().await,
            Self::TrainedProvenance(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_deleteModel (delete model)
#[derive(Debug, clap::Parser)]
pub struct ModelDeleteServedRpcCmd {
    /// model id
    #[arg(long)]
    model_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelDeleteServedRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_deleteModel", serde_json::json!([self.model_id]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_previewServe (preview serve)
#[derive(Debug, clap::Parser)]
pub struct ModelPreviewServeRpcCmd {
    /// model id
    #[arg(long)]
    model_id: String,
    /// quant
    #[arg(long)]
    quant: Option<String>,
    /// context length
    #[arg(long)]
    context_length: Option<u64>,
    /// max concurrent
    #[arg(long)]
    max_concurrent: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelPreviewServeRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_previewServe", serde_json::json!({ "model_id": self.model_id, "quant": self.quant, "context_length": self.context_length, "max_concurrent": self.max_concurrent })).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_buildModelManifest (build model manifest)
#[derive(Debug, clap::Parser)]
pub struct ModelBuildManifestRpcCmd {
    /// name
    #[arg(long)]
    name: String,
    /// Absolute directory on the node holding the model's files
    #[arg(long)]
    path: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelBuildManifestRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_buildModelManifest",
                serde_json::json!({ "name": self.name, "path": self.path }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_pinModel (pin model)
#[derive(Debug, clap::Parser)]
pub struct ModelPinRpcCmd {
    /// model id
    #[arg(long)]
    model_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelPinRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_pinModel",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_unpinModel (unpin model)
#[derive(Debug, clap::Parser)]
pub struct ModelUnpinRpcCmd {
    /// model id
    #[arg(long)]
    model_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelUnpinRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_unpinModel",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_modelMetadata (model metadata)
#[derive(Debug, clap::Parser)]
pub struct ModelMetadataRpcCmd {
    /// model id
    #[arg(long)]
    model_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelMetadataRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_modelMetadata",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getAttestationLog (get attestation log)
#[derive(Debug, clap::Parser)]
pub struct ModelAttestationLogRpcCmd {
    /// model
    #[arg(long)]
    model: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelAttestationLogRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getAttestationLog",
                serde_json::json!({ "model": self.model }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_moeListReceipts (moe list receipts)
#[derive(Debug, clap::Parser)]
pub struct ModelMoeReceiptsRpcCmd {
    /// model id
    #[arg(long)]
    model_id: Option<String>,
    /// limit
    #[arg(long)]
    limit: Option<u64>,
    /// The next_cursor of the page before
    #[arg(long)]
    cursor: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelMoeReceiptsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_moeListReceipts",
                serde_json::json!({ "model_id": self.model_id, "limit": self.limit, "cursor": self.cursor }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_loadMediaModel (load media model)
#[derive(Debug, clap::Parser)]
pub struct ModelLoadMediaModelRpcCmd {
    /// model id
    #[arg(long)]
    model_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelLoadMediaModelRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_loadMediaModel",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_unloadMediaModel (unload media model)
#[derive(Debug, clap::Parser)]
pub struct ModelUnloadMediaModelRpcCmd {
    /// model id
    #[arg(long)]
    model_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelUnloadMediaModelRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_unloadMediaModel",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_registerKeyRelease: register a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy
#[derive(Debug, clap::Parser)]
pub struct ModelKeyReleaseRegisterRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelKeyReleaseRegisterRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_registerKeyRelease", params).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_revokeKeyRelease: revoke a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy
#[derive(Debug, clap::Parser)]
pub struct ModelKeyReleaseRevokeRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelKeyReleaseRevokeRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_revokeKeyRelease", params).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_requestKeyRelease: submit an attested environment's release request (`request`), which the provider node verifies and records
#[derive(Debug, clap::Parser)]
pub struct ModelKeyReleaseRequestRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelKeyReleaseRequestRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_requestKeyRelease", params).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getKeyRelease: a model's release policy and releases (`model_id`), or for a recorded `request` the content key sealed to the environment
#[derive(Debug, clap::Parser)]
pub struct ModelKeyReleaseGetRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelKeyReleaseGetRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_getKeyRelease", params).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_commitTrainingRound: commit a training round's signed receipt against its milestone escrow
#[derive(Debug, clap::Parser)]
pub struct ModelTrainingCommitRoundRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelTrainingCommitRoundRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_commitTrainingRound", params).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_settleTrainingRound: settle a committed training round (`receipt_id`) once its challenge window has closed
#[derive(Debug, clap::Parser)]
pub struct ModelTrainingSettleRoundRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelTrainingSettleRoundRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_settleTrainingRound", params).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_trainedModelProvenance: the provenance of a trained model (`model_id`) from its committed training rounds (`rounds`)
#[derive(Debug, clap::Parser)]
pub struct ModelTrainedProvenanceRpcCmd {
    /// Parameters as a JSON object
    #[arg(long, default_value = "{}")]
    params: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelTrainedProvenanceRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let params: serde_json::Value = serde_json::from_str(&self.params)
            .map_err(|e| anyhow::anyhow!("--params is not valid JSON: {e}"))?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_trainedModelProvenance", params).await?;
        crate::output::print_json(&result)
    }
}
