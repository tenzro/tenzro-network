//! Inference request commands for the Tenzro CLI

use clap::{Parser, Subcommand};
use anyhow::{Context, Result};
use crate::output;

/// Inference commands
#[derive(Debug, Subcommand)]
pub enum InferenceCommand {
    /// Submit an inference request
    Request(InferenceRequestCmd),
    /// Stream a chat completion, optionally billed against a payment channel.
    Stream(InferenceStreamCmd),
}

impl InferenceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Request(cmd) => cmd.execute().await,
            Self::Stream(cmd) => cmd.execute().await,
        }
    }
}

/// Submit an inference request
#[derive(Debug, Parser)]
pub struct InferenceRequestCmd {
    /// Model ID to use
    model_id: String,

    /// Input text, file path, or URL
    input: String,

    /// Maximum price willing to pay (TNZO)
    #[arg(long, default_value = "1.0")]
    max_price: String,

    /// Require TEE attestation
    #[arg(long)]
    require_tee: bool,

    /// Temperature (0.0-2.0, for text models)
    #[arg(long)]
    temperature: Option<f32>,

    /// Maximum output tokens (for text models)
    #[arg(long)]
    max_tokens: Option<u32>,

    /// Save output to file
    #[arg(long)]
    output_file: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceRequestCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Inference Request");

        // Parse max price
        let _max_price_float: f64 = self.max_price.parse()?;

        // Determine if input is a file or direct text
        let input_preview = if std::path::Path::new(&self.input).exists() {
            format!("File: {}", self.input)
        } else if self.input.starts_with("http://") || self.input.starts_with("https://") {
            format!("URL: {}", self.input)
        } else {
            // Direct text input
            if self.input.len() > 100 {
                format!("{}...", &self.input[..97])
            } else {
                self.input.clone()
            }
        };

        // Show request details
        println!();
        output::print_field("Model", &self.model_id);
        output::print_field("Input", &input_preview);
        output::print_field("Max Price", &format!("{} TNZO", self.max_price));

        if self.require_tee {
            output::print_field("TEE Required", "Yes");
        }

        if let Some(temp) = self.temperature {
            output::print_field("Temperature", &format!("{:.2}", temp));
        }

        if let Some(max_tokens) = self.max_tokens {
            output::print_field("Max Tokens", &max_tokens.to_string());
        }

        println!();

        // Confirm with user
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt("Submit inference request?")
            .default(true)
            .interact()?;

        if !confirmed {
            output::print_warning("Request cancelled");
            return Ok(());
        }

        let spinner = output::create_spinner("Creating inference request...");

        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);

        spinner.set_message("Finding available provider...");

        // Submit inference request
        let result: serde_json::Value = rpc.call("tenzro_inferenceRequest", serde_json::json!([{
            "model_id": self.model_id,
            "input": self.input,
            "max_price": self.max_price,
            "require_tee": self.require_tee,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }])).await?;

        spinner.set_message("Receiving response...");

        spinner.finish_and_clear();

        output::print_success("Inference completed successfully!");

        // Display response
        println!();
        output::print_header("Response");
        println!();

        if let Some(response_text) = result.get("response").and_then(|v| v.as_str()) {
            println!("{}", response_text);
        } else if let Some(output) = result.get("output") {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("Model inference completed. Response data received.");
        }

        println!();

        // Show metadata
        output::print_header("Metadata");
        println!();

        if let Some(request_id) = result.get("request_id").and_then(|v| v.as_str()) {
            output::print_field("Request ID", request_id);
        }
        if let Some(provider) = result.get("provider").and_then(|v| v.as_str()) {
            output::print_field("Provider", &output::format_address(provider));
        }
        if let Some(latency) = result.get("latency").and_then(|v| v.as_f64()) {
            output::print_field("Latency", &format!("{:.2} seconds", latency));
        }
        if let Some(input_tokens) = result.get("input_tokens").and_then(|v| v.as_u64()) {
            output::print_field("Input Tokens", &input_tokens.to_string());
        }
        if let Some(output_tokens) = result.get("output_tokens").and_then(|v| v.as_u64()) {
            output::print_field("Output Tokens", &output_tokens.to_string());
        }
        if let Some(price) = result.get("actual_price").and_then(|v| v.as_str()) {
            output::print_field("Actual Price", price);
        }

        if self.require_tee {
            if let Some(attestation) = result.get("attestation") {
                println!();
                output::print_success("TEE Attestation verified");
                if let Some(vendor) = attestation.get("vendor").and_then(|v| v.as_str()) {
                    output::print_field("Vendor", vendor);
                }
                if let Some(enclave_id) = attestation.get("enclave_id").and_then(|v| v.as_str()) {
                    output::print_field("Enclave ID", enclave_id);
                }
            }
        }

        // Save to file if requested
        if let Some(output_file) = &self.output_file {
            if let Some(response_text) = result.get("response").and_then(|v| v.as_str()) {
                std::fs::write(output_file, response_text)?;
                println!();
                output::print_success(&format!("Response saved to: {}", output_file));
            }
        }

        Ok(())
    }
}

/// `tenzro inference stream <model_id> <message> [--channel <id>]`
///
/// Stream a chat completion via `tenzro_chatStream`. When `--channel` is
/// supplied, the channel id is forwarded so the node can bill the
/// streamed tokens against that micropayment channel; without it, the
/// node falls back to whatever billing default is configured.
///
/// The streaming JSON-RPC method currently returns a single envelope
/// with the full result plus token-usage metadata; this command prints
/// the response text inline (with the EU AI Act §50(1) `[AI]` prefix —
/// see `main.rs` for the rationale) and the usage block separately.
#[derive(Debug, Parser)]
pub struct InferenceStreamCmd {
    /// Model ID to use.
    model_id: String,

    /// Prompt text.
    message: String,

    /// Optional micropayment channel id to bill streamed tokens against.
    #[arg(long)]
    channel: Option<String>,

    /// Maximum output tokens.
    #[arg(long, default_value_t = 1024)]
    max_tokens: u64,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl InferenceStreamCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Streaming Inference");
        output::print_field("Model", &self.model_id);
        if let Some(ch) = &self.channel {
            output::print_field("Channel", ch);
        }

        let mut params = serde_json::Map::new();
        params.insert(
            "model_id".to_string(),
            serde_json::Value::String(self.model_id.clone()),
        );
        params.insert(
            "message".to_string(),
            serde_json::Value::String(self.message.clone()),
        );
        params.insert(
            "max_tokens".to_string(),
            serde_json::Value::Number(self.max_tokens.into()),
        );
        if let Some(ch) = &self.channel {
            params.insert(
                "channel_id".to_string(),
                serde_json::Value::String(ch.clone()),
            );
        }

        let spinner = output::create_spinner("Streaming...");
        use crate::rpc::RpcClient;
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_chatStream", serde_json::Value::Object(params))
            .await
            .context("calling tenzro_chatStream")?;
        spinner.finish_and_clear();

        // Per EU AI Act Article 50(1): mark machine-generated text.
        // Single source of truth lives in
        // `tenzro_node::eu_ai_disclosure::render_cli_chat_chunk` so the
        // workspace can audit the literal in one place.
        let response_text = result
            .get("result")
            .and_then(|r| r.get("response"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !response_text.is_empty() {
            println!();
            println!("{}", tenzro_node::eu_ai_disclosure::render_cli_chat_chunk(response_text));
        }

        if let Some(usage) = result.get("usage") {
            println!();
            output::print_header("Usage");
            output::print_json(usage)?;
        }

        Ok(())
    }
}
