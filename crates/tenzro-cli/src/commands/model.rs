//! Model management commands for the Tenzro CLI
//!
//! Uses tenzro-model crate directly for local model catalog, download, serve, and delete.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output::{self};

/// Model management commands
#[derive(Debug, Subcommand)]
pub enum ModelCommand {
    /// List available models from catalog
    List(ModelListCmd),
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
    /// Get download progress for a model
    Progress(ModelProgressCmd),
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
    /// Show the node's X25519 recipient public key for sealed models
    RecipientKey(ModelRecipientKeyCmd),
}

impl ModelCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
            Self::Download(cmd) => cmd.execute().await,
            Self::Serve(cmd) => cmd.execute().await,
            Self::Stop(cmd) => cmd.execute().await,
            Self::Delete(cmd) => cmd.execute().await,
            Self::Endpoints(cmd) => cmd.execute().await,
            Self::Endpoint(cmd) => cmd.execute().await,
            Self::Discover(cmd) => cmd.execute().await,
            Self::Progress(cmd) => cmd.execute().await,
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

    /// Output format (table, json)
    #[arg(long, default_value = "table")]
    format: String,
}

impl ModelListCmd {
    pub async fn execute(&self) -> Result<()> {
        use tenzro_model::{get_model_catalog, HfDownloader};

        output::print_header("Available Models");

        let models_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".tenzro")
            .join("models");
        let downloader = HfDownloader::new(models_dir);

        let catalog = get_model_catalog();

        // Load persisted config to know which models are served
        let config = crate::config::load_config();
        let served_models = config.served_models;

        if self.format == "json" {
            let json_models: Vec<serde_json::Value> = catalog.iter()
                .filter(|m| {
                    if let Some(ref family) = self.family
                        && m.family != *family { return false; }
                    let is_downloaded = downloader.is_downloaded(&m.id);
                    let is_serving = served_models.contains(&m.id);
                    if self.downloaded && !is_downloaded { return false; }
                    if self.serving && !is_serving { return false; }
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
                        "license": m.license,
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

        let headers = vec!["Model ID", "Name", "Params", "Quant", "Size", "Availability", "Cost"];
        let mut rows = Vec::new();

        for m in &catalog {
            if let Some(ref family) = self.family
                && m.family != *family { continue; }

            let is_downloaded = downloader.is_downloaded(&m.id);
            let is_serving = served_models.contains(&m.id);

            if self.downloaded && !is_downloaded { continue; }
            if self.serving && !is_serving { continue; }

            let availability = if is_serving {
                format!("{}local{}", output::colors::GREEN, output::colors::RESET)
            } else if is_downloaded {
                format!("{}downloaded{}", output::colors::CYAN, output::colors::RESET)
            } else {
                "downloadable".to_string()
            };

            let cost_str = if is_serving {
                format!("{}free{}", output::colors::GREEN, output::colors::RESET)
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
}

impl ModelInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use tenzro_model::{get_model_by_id, HfDownloader};

        let entry = get_model_by_id(&self.model_id);

        match entry {
            Some(m) => {
                output::print_header(&format!("Model Information: {}", self.model_id));

                let models_dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join(".tenzro")
                    .join("models");
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
                output::print_field("License", &m.license);

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
                        tenzro_model::catalog::MtpKind::DraftMtp => "MTP (joint draft head)",
                        tenzro_model::catalog::MtpKind::Generic => "Generic (two-model)",
                        tenzro_model::catalog::MtpKind::None => "None",
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
                output::print_field(
                    "Serving — Chat Template (jinja)",
                    if s.jinja_required { "required" } else { "optional" },
                );
                output::print_field(
                    "Serving — Reasoning",
                    if s.reasoning_default { "on by default" } else { "off by default" },
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
                    output::print_field("Local Path", &downloader.model_path(&m.id).display().to_string());
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

    /// RPC endpoint to download on a remote node (omit to download locally)
    #[arg(long)]
    rpc: Option<String>,
}

impl ModelDownloadCmd {
    pub async fn execute(&self) -> Result<()> {
        // If --rpc is provided, delegate download to the remote node
        if let Some(ref rpc_url) = self.rpc {
            return self.execute_remote(rpc_url).await;
        }
        self.execute_local().await
    }

    async fn execute_remote(&self, rpc_url: &str) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header(&format!("Downloading Model on Node: {}", self.model_id));
        println!();
        output::print_field("Node", rpc_url);
        output::print_field("Model", &self.model_id);
        println!();

        let rpc = RpcClient::new(rpc_url);
        let spinner = output::create_spinner("Requesting model download on node...");

        let result: serde_json::Value = rpc.call("tenzro_downloadModel", serde_json::json!({
            "model_id": self.model_id
        })).await.map_err(|e| anyhow::anyhow!("Download request failed: {}", e))?;

        spinner.finish_and_clear();

        let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
        if status.to_lowercase().contains("complet") || status.to_lowercase().contains("ok") || status.to_lowercase().contains("success") {
            output::print_success(&format!("Model '{}' downloaded on node", self.model_id));
        } else {
            output::print_field("Status", status);
        }
        if let Some(msg) = result.get("message").and_then(|v| v.as_str()) {
            output::print_info(msg);
        }

        Ok(())
    }

    async fn execute_local(&self) -> Result<()> {
        use tenzro_model::{get_model_by_id, HfDownloader};

        let entry = match get_model_by_id(&self.model_id) {
            Some(e) => e,
            None => return Err(anyhow::anyhow!(
                "Model '{}' not found in catalog. Use 'tenzro model list' to see available models.",
                self.model_id
            )),
        };

        let models_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".tenzro")
            .join("models");
        let downloader = HfDownloader::new(models_dir);

        if downloader.is_downloaded(&self.model_id) {
            output::print_success(&format!("Model '{}' is already downloaded", self.model_id));
            output::print_field("Path", &downloader.model_path(&self.model_id).display().to_string());
            return Ok(());
        }

        output::print_header(&format!("Downloading Model: {}", entry.name));
        println!();
        output::print_field("Model", &entry.name);
        output::print_field("Source", &format!("{}/{}", entry.hf_repo, entry.hf_filename));
        output::print_field("Size", &format_bytes(entry.size_bytes));
        println!();

        let pb = output::create_progress_bar(entry.size_bytes, "Downloading from HuggingFace...");

        let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(
            tenzro_model::DownloadProgress {
                model_id: self.model_id.clone(),
                status: tenzro_model::DownloadState::Pending,
                progress_percent: 0.0,
                downloaded_bytes: 0,
                total_bytes: entry.size_bytes,
            }
        );

        // Monitor progress in background
        let pb_clone = pb.clone();
        let monitor = tokio::spawn(async move {
            while progress_rx.changed().await.is_ok() {
                let progress = progress_rx.borrow().clone();
                pb_clone.set_position(progress.downloaded_bytes);
            }
        });

        // Perform download
        match downloader.download_model(&entry, None, progress_tx).await {
            Ok(path) => {
                pb.finish_with_message("Download complete!");
                output::print_success(&format!("Model downloaded to: {}", path.display()));
            }
            Err(e) => {
                pb.finish_with_message("Download failed");
                return Err(anyhow::anyhow!("Download failed: {}", e));
            }
        }

        monitor.abort();
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

    /// Serve privately: register the model locally without gossiping it to the
    /// network. It stays reachable over a direct or LAN connection. Omit to
    /// announce the model so any peer can route inference to it.
    #[arg(long)]
    private: bool,

    /// Front an external OpenAI-compatible serving engine instead of loading
    /// weights in-process: vllm, sglang, llama-server, or external (any
    /// OpenAI-compatible endpoint). Requires --base-url. The node routes
    /// chat for this model to the engine; the engine owns batching and GPU
    /// memory.
    #[arg(long, requires = "base_url")]
    engine: Option<String>,

    /// Base URL of the external engine (e.g. http://127.0.0.1:8000).
    #[arg(long, requires = "engine")]
    base_url: Option<String>,

    /// Model name the external engine was launched with, when it differs
    /// from the catalog id (e.g. the HF repo path passed to vLLM's --model).
    #[arg(long, requires = "engine")]
    upstream_model: Option<String>,

    /// Bearer token when the external engine was launched with an API key.
    #[arg(long, requires = "engine")]
    api_key: Option<String>,
}

impl ModelServeCmd {
    pub async fn execute(&self) -> Result<()> {
        if let Some(ref rpc_url) = self.rpc {
            return self.execute_remote(rpc_url).await;
        }
        if self.engine.is_some() {
            // External engines are registered on a running node — the node
            // routes inference and announces the model. Default to the local
            // node's RPC when --rpc is omitted.
            return self.execute_remote("http://127.0.0.1:8545").await;
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
        let spinner = output::create_spinner(if self.engine.is_some() {
            "Registering external engine on node..."
        } else {
            "Loading model on node..."
        });

        let mut req = serde_json::json!({
            "model_id": self.model_id,
            "user_forced": self.cluster,
            "force_single": self.force_single,
            "visibility": if self.private { "private" } else { "network" },
        });
        if let Some(ref engine) = self.engine {
            req["engine"] = serde_json::json!(engine);
            req["base_url"] = serde_json::json!(self.base_url);
            if let Some(ref up) = self.upstream_model {
                req["upstream_model"] = serde_json::json!(up);
            }
            if let Some(ref key) = self.api_key {
                req["api_key"] = serde_json::json!(key);
            }
        }
        let result: serde_json::Value = rpc.call("tenzro_serveModel", req)
            .await.map_err(|e| anyhow::anyhow!("Serve request failed: {}", e))?;

        spinner.finish_and_clear();

        if let Some(mc) = result.get("max_concurrent").and_then(|v| v.as_u64()) {
            output::print_success(&format!("Model '{}' is now serving on node (max_concurrent: {})", self.model_id, mc));
        } else {
            let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("ok");
            output::print_success(&format!("Model '{}' serve request sent — status: {}", self.model_id, status));
        }
        if let Some(ep) = result.get("api_endpoint").and_then(|v| v.as_str()) {
            output::print_field("API Endpoint", ep);
        }
        if let Some(engine) = result.get("engine").and_then(|v| v.as_str()) {
            output::print_field("Engine", engine);
        }
        if let Some(base) = result.get("base_url").and_then(|v| v.as_str()) {
            output::print_field("Engine URL", base);
        }
        println!();
        output::print_info(&format!("Use 'tenzro chat {} --rpc {}' to interact.", self.model_id, rpc_url));

        Ok(())
    }

    async fn execute_local(&self) -> Result<()> {
        use tenzro_model::{get_model_by_id, HfDownloader, ModelRuntime};

        let entry = match get_model_by_id(&self.model_id) {
            Some(e) => e,
            None => return Err(anyhow::anyhow!(
                "Model '{}' not found in catalog", self.model_id
            )),
        };

        let models_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".tenzro")
            .join("models");
        let downloader = HfDownloader::new(models_dir);

        if !downloader.is_downloaded(&self.model_id) {
            return Err(anyhow::anyhow!(
                "Model '{}' is not downloaded. Run 'tenzro model download {}' first.",
                self.model_id, self.model_id
            ));
        }

        output::print_header(&format!("Serving Model: {}", entry.name));

        let spinner = output::create_spinner("Loading model into memory...");

        let runtime = ModelRuntime::new();
        let gguf_path = downloader.model_path(&self.model_id);

        match runtime.load_model_with_context(&self.model_id, &gguf_path, Some(entry.context_length)).await {
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

    /// RPC endpoint (omit for local-only stop)
    #[arg(long)]
    rpc: Option<String>,
}

impl ModelStopCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("Stopping Model: {}", self.model_id));

        // Call RPC to stop on node if rpc is specified
        if let Some(ref rpc_url) = self.rpc {
            use crate::rpc::RpcClient;
            let rpc = RpcClient::new(rpc_url);
            let spinner = output::create_spinner("Stopping model on node...");
            let result: Result<serde_json::Value> = rpc.call("tenzro_stopModel", serde_json::json!([{
                "model_id": self.model_id
            }])).await;
            spinner.finish_and_clear();
            match result {
                Ok(_) => output::print_success(&format!("Model '{}' stopped on node", self.model_id)),
                Err(e) => output::print_warning(&format!("Node stop failed: {} (local config updated)", e)),
            }
        }

        // Update persisted config to remove from served_models
        let mut config = crate::config::load_config();
        config.served_models.retain(|id| id != &self.model_id);
        let _ = crate::config::save_config(&config);

        output::print_success(&format!("Model '{}' stopped", self.model_id));

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

        let models_dir = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".tenzro")
            .join("models");
        let downloader = HfDownloader::new(models_dir);

        if !downloader.is_downloaded(&self.model_id) {
            output::print_info(&format!("Model '{}' is not downloaded", self.model_id));
            return Ok(());
        }

        if !self.yes {
            use dialoguer::Confirm;
            let confirm = Confirm::new()
                .with_prompt(format!("Delete model '{}' and all cached files?", self.model_id))
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

                let headers = vec!["Served by", "Model", "Instance ID", "API Endpoint", "Status", "Load"];
                let mut rows = Vec::new();

                for endpoint in &endpoints {
                    let location = endpoint.get("location")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let iroh_endpoint_id = endpoint.get("iroh_endpoint_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let model_name = endpoint.get("model_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let instance_id = endpoint.get("instance_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let api_endpoint = endpoint.get("api_endpoint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let status = endpoint.get("status")
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
                        format!("{}network · {}…{}", output::colors::BLUE, short, output::colors::RESET)
                    } else if location == "local" {
                        format!("{}local{}", output::colors::CYAN, output::colors::RESET)
                    } else {
                        format!("{}network{}", output::colors::BLUE, output::colors::RESET)
                    };

                    let status_colored = if status.to_lowercase() == "online" {
                        format!("{}online{}", output::colors::GREEN, output::colors::RESET)
                    } else {
                        format!("{}offline{}", output::colors::RED, output::colors::RESET)
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
                        api_endpoint.to_string(),
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
                output::print_info(&format!("Make sure a Tenzro node is running at {}", self.rpc));
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

                let instance_id = endpoint.get("instance_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&self.id);
                let model_name = endpoint.get("model_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let model_id = endpoint.get("model_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let location = endpoint.get("location")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let provider_name = endpoint.get("provider_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let status = endpoint.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let api_endpoint = endpoint.get("api_endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let mcp_endpoint = endpoint.get("mcp_endpoint")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let iroh_endpoint_id = endpoint.get("iroh_endpoint_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                output::print_field("Instance ID", instance_id);

                if !model_id.is_empty() {
                    output::print_field("Model", &format!("{} ({})", model_name, model_id));
                } else {
                    output::print_field("Model", model_name);
                }

                // A non-empty iroh_endpoint_id means the model is reachable over
                // the network by that EndpointId (resolved via Pkarr, not by IP).
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
                    && let Some(params_str) = parameters.as_str() {
                        output::print_field("Parameters", params_str);
                    }

                output::print_field("API Endpoint", api_endpoint);

                if !mcp_endpoint.is_empty() {
                    output::print_field("MCP Endpoint", mcp_endpoint);
                }

                // Pricing information
                if let Some(pricing) = endpoint.get("pricing").and_then(|v| v.as_object()) {
                    let input_price = pricing.get("input_per_token")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");
                    let output_price = pricing.get("output_per_token")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0");

                    let pricing_str = if location == "local" {
                        "Free (local)".to_string()
                    } else {
                        format!("{} TNZO per input token, {} TNZO per output token",
                            input_price, output_price)
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
                output::print_info(&format!("Make sure a Tenzro node is running at {}", self.rpc));
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
        if let Some(ref c) = self.category { params["category"] = serde_json::json!(c); }
        if let Some(ref n) = self.name { params["name"] = serde_json::json!(n); }
        let result: serde_json::Value = rpc.call("tenzro_discoverModels", params).await?;
        spinner.finish_and_clear();
        if let Some(models) = result.as_array() {
            if models.is_empty() { output::print_info("No models discovered."); }
            else {
                let headers = vec!["Model ID", "Name", "Category", "Provider"];
                let mut rows = Vec::new();
                for m in models {
                    rows.push(vec![
                        m.get("model_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        m.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        m.get("category").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        m.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        } else { output::print_json(&result)?; }
        Ok(())
    }
}

/// Get download progress for a model
#[derive(Debug, Parser)]
pub struct ModelProgressCmd {
    /// Model ID
    model_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ModelProgressCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Download Progress");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_getDownloadProgress", serde_json::json!({
            "model_id": self.model_id,
        })).await?;
        output::print_field("Model", &self.model_id);
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"));
        if let Some(pct) = result.get("progress_percent").and_then(|v| v.as_f64()) {
            output::print_field("Progress", &format!("{:.1}%", pct));
        }
        if let Some(downloaded) = result.get("downloaded_bytes").and_then(|v| v.as_u64()) {
            let total = result.get("total_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
            output::print_field("Downloaded", &format!("{} / {}", format_bytes(downloaded), format_bytes(total)));
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
    /// API endpoint URL
    #[arg(long)]
    api_endpoint: String,
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
        let result: serde_json::Value = rpc.call("tenzro_registerModelEndpoint", serde_json::json!({
            "model_id": self.model_id,
            "api_endpoint": self.api_endpoint,
            "provider": self.provider,
        })).await?;
        spinner.finish_and_clear();
        output::print_success("Endpoint registered!");
        if let Some(v) = result.get("instance_id").and_then(|v| v.as_str()) { output::print_field("Instance ID", v); }
        output::print_field("Model", &self.model_id);
        output::print_field("Endpoint", &self.api_endpoint);
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
        let _result: serde_json::Value = rpc.call("tenzro_unregisterModelEndpoint", serde_json::json!({
            "instance_id": self.instance_id,
        })).await?;
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
/// wraps the content key to each recipient's X25519 public key
/// (`x25519-envelope-aes-256-gcm`), and stores the signed manifest on the
/// node. Operator-only (requires the node admin token).
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

    /// Recipient in `did:...=<64-hex x25519 pubkey>` form (repeatable)
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

    /// Operator admin token (`X-Tenzro-Admin-Token`)
    #[arg(long)]
    admin_token: Option<String>,

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
            let (did, pubkey) = r.split_once('=').ok_or_else(|| {
                anyhow::anyhow!(
                    "recipient '{}' must be 'did:...=<64-hex x25519 pubkey>'",
                    r
                )
            })?;
            recipients.push(serde_json::json!({
                "did": did,
                "x25519_pubkey": pubkey,
            }));
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

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        }

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
            result.get("manifest_hash").and_then(|v| v.as_str()).unwrap_or("-"),
        );
        output::print_field(
            "Model hash",
            result.get("model_hash").and_then(|v| v.as_str()).unwrap_or("-"),
        );
        output::print_field(
            "Shards",
            &result.get("shard_count").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
        );
        output::print_field(
            "Recipients",
            &result.get("recipient_count").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
        );
        output::print_field(
            "Wrap alg",
            result.get("wrap_alg").and_then(|v| v.as_str()).unwrap_or("-"),
        );
        Ok(())
    }
}

/// Install a sealed model on this node: fetch shards from the blob layer,
/// verify the manifest signature and hashes, decrypt with the node's
/// X25519 recipient key, and write the artifact into local model storage.
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

    /// Operator admin token (`X-Tenzro-Admin-Token`)
    #[arg(long)]
    admin_token: Option<String>,

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

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        }

        let spinner = output::create_spinner("Fetching, verifying, and decrypting shards...");
        let result: serde_json::Value = rpc.call("tenzro_installSealedModel", params).await?;
        spinner.finish_and_clear();

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        output::print_success(&format!(
            "Sealed model '{}' installed",
            result.get("model_id").and_then(|v| v.as_str()).unwrap_or("-")
        ));
        output::print_field(
            "Path",
            result.get("installed_path").and_then(|v| v.as_str()).unwrap_or("-"),
        );
        output::print_field(
            "Bytes",
            &result.get("total_bytes").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
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
        let result: serde_json::Value =
            rpc.call("tenzro_listSealedModels", serde_json::Value::Null).await?;

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

        let headers = vec!["Model ID", "Artifact", "Size", "Shards", "Recipients", "Owner DID"];
        let rows: Vec<Vec<String>> = models
            .iter()
            .map(|m| {
                vec![
                    m.get("model_id").and_then(|v| v.as_str()).unwrap_or("-").to_string(),
                    m.get("artifact_name").and_then(|v| v.as_str()).unwrap_or("-").to_string(),
                    format_bytes(m.get("total_bytes").and_then(|v| v.as_u64()).unwrap_or(0)),
                    m.get("shard_count").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
                    m.get("recipients")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                        .to_string(),
                    m.get("owner_did").and_then(|v| v.as_str()).unwrap_or("-").to_string(),
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

/// Show the node's X25519 recipient public key for sealed models. Give
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
        let result: serde_json::Value =
            rpc.call("tenzro_modelRecipientKey", serde_json::Value::Null).await?;

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        output::print_field(
            "X25519 pubkey",
            result.get("x25519_pubkey").and_then(|v| v.as_str()).unwrap_or("-"),
        );
        output::print_field(
            "Wrap alg",
            result.get("wrap_alg").and_then(|v| v.as_str()).unwrap_or("-"),
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

