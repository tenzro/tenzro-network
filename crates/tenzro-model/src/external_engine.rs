//! External OpenAI-compatible inference engine backend.
//!
//! Some providers front their GPUs with a dedicated high-throughput serving
//! engine (vLLM, SGLang, TGI, llama.cpp's own `llama-server`) instead of the
//! in-process `llama-cpp-2` runtime. Those engines run PagedAttention /
//! RadixAttention, continuous batching, and prefix caching that a single
//! in-process context cannot match at high concurrency.
//!
//! This backend lets a provider register such an engine against a `model_id`.
//! `ModelRuntime` then routes chat/generate for that model to the external
//! HTTP endpoint instead of loading a local GGUF, mapping our
//! [`ChatMessage`]/[`GenerationConfig`]/[`InferenceResult`] types onto the
//! OpenAI `/v1/chat/completions` wire contract (both vLLM and SGLang implement
//! it identically; they differ only in default bind address, which the
//! provider supplies as `base_url`).

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{ModelError, Result};
use crate::runtime::{ChatMessage, GenerationConfig, InferenceResult};

/// Which serving engine sits behind the endpoint. Purely informational —
/// both speak the same OpenAI wire contract — but recorded so operators and
/// the routing layer can see what a model is served through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExternalEngineKind {
    Vllm,
    Sglang,
    /// llama.cpp's own HTTP server (`llama-server`).
    LlamaServer,
    /// Any other OpenAI-compatible server (TGI, LMDeploy, a hosted API).
    OpenAiCompatible,
}

impl ExternalEngineKind {
    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "vllm" => Some(Self::Vllm),
            "sglang" => Some(Self::Sglang),
            "llama-server" | "llama_server" | "llamaserver" => Some(Self::LlamaServer),
            "external" | "openai" | "openai-compatible" | "openai_compatible" => {
                Some(Self::OpenAiCompatible)
            }
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vllm => "vllm",
            Self::Sglang => "sglang",
            Self::LlamaServer => "llama-server",
            Self::OpenAiCompatible => "openai-compatible",
        }
    }
}

/// A registered external engine. Cloneable so `ModelRuntime` can hand a copy to
/// a `spawn`-ed request without holding a `DashMap` guard across the await.
#[derive(Debug, Clone)]
pub struct ExternalEngine {
    kind: ExternalEngineKind,
    /// Base URL of the OpenAI-compatible server, e.g. `http://127.0.0.1:8000`.
    /// No trailing slash, no `/v1` suffix — paths are appended here.
    base_url: String,
    /// The name the upstream engine knows the model by (its `--model` /
    /// `--model-path`). Sent as the `model` field; may differ from our
    /// catalog `model_id`.
    upstream_model: String,
    /// Optional bearer token when the operator launched the engine with an
    /// `--api-key`. Both vLLM and SGLang default to no auth.
    api_key: Option<String>,
    client: reqwest::Client,
}

impl ExternalEngine {
    /// Build an external-engine handle. `base_url` is normalized (trailing
    /// slash and any `/v1` suffix stripped) so path joins are unambiguous.
    pub fn new(
        kind: ExternalEngineKind,
        base_url: impl Into<String>,
        upstream_model: impl Into<String>,
        api_key: Option<String>,
    ) -> Result<Self> {
        let mut base = base_url.into();
        while base.ends_with('/') {
            base.pop();
        }
        if let Some(stripped) = base.strip_suffix("/v1") {
            base = stripped.to_string();
        }
        if base.is_empty() {
            return Err(ModelError::Other(
                "external engine base_url is empty".to_string(),
            ));
        }

        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| ModelError::Other(format!("external engine HTTP client: {}", e)))?;

        Ok(Self {
            kind,
            base_url: base,
            upstream_model: upstream_model.into(),
            api_key,
            client,
        })
    }

    pub fn kind(&self) -> ExternalEngineKind {
        self.kind
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn upstream_model(&self) -> &str {
        &self.upstream_model
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(k) => req.bearer_auth(k),
            None => req,
        }
    }

    /// Probe the engine's `/health` endpoint. Both vLLM and SGLang expose it
    /// and return 200 when ready. Returns `Ok(())` on 2xx.
    pub async fn health(&self) -> Result<()> {
        let url = format!("{}/health", self.base_url);
        let resp = self
            .auth(self.client.get(&url))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| ModelError::Other(format!("external engine health request: {}", e)))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(ModelError::Other(format!(
                "external engine health returned {}",
                resp.status()
            )))
        }
    }

    fn build_body(
        &self,
        messages: &[ChatMessage],
        config: &GenerationConfig,
        stream: bool,
    ) -> Value {
        let msgs: Vec<Value> = messages
            .iter()
            .map(|m| json!({ "role": m.role, "content": m.content }))
            .collect();
        let mut body = json!({
            "model": self.upstream_model,
            "messages": msgs,
            "temperature": config.temperature,
            "top_p": config.top_p,
            "max_tokens": config.max_tokens,
            "seed": config.seed,
            "stream": stream,
        });
        // `frequency_penalty` is the OpenAI analogue of llama.cpp's repeat
        // penalty; both engines accept it. Only send when non-neutral so we
        // don't perturb the engine's defaults on a plain request.
        if (config.repeat_penalty - 1.0).abs() > f32::EPSILON {
            body["frequency_penalty"] = json!((config.repeat_penalty - 1.0) as f64);
        }
        if stream {
            // Ask both engines to include the final usage block in the stream.
            body["stream_options"] = json!({ "include_usage": true });
        }
        body
    }

    /// Non-streaming chat completion. Returns the assembled
    /// [`InferenceResult`] with token counts taken from the engine's `usage`
    /// block (falling back to a whitespace estimate when absent).
    pub async fn chat(
        &self,
        messages: &[ChatMessage],
        config: &GenerationConfig,
    ) -> Result<InferenceResult> {
        let url = format!("{}/v1/chat/completions", self.base_url);
        let started = Instant::now();
        let resp = self
            .auth(self.client.post(&url))
            .json(&self.build_body(messages, config, false))
            .send()
            .await
            .map_err(|e| ModelError::Other(format!("external engine request: {}", e)))?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ModelError::Other(format!("external engine body read: {}", e)))?;
        if !status.is_success() {
            return Err(ModelError::Other(format!(
                "external engine returned {}: {}",
                status,
                text.chars().take(400).collect::<String>()
            )));
        }

        let v: Value = serde_json::from_str(&text)
            .map_err(|e| ModelError::Other(format!("external engine JSON: {}", e)))?;

        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let input_tokens = v["usage"]["prompt_tokens"].as_u64().unwrap_or_else(|| {
            messages.iter().map(|m| m.content.split_whitespace().count() as u64).sum()
        }) as u32;
        let output_tokens = v["usage"]["completion_tokens"]
            .as_u64()
            .unwrap_or_else(|| content.split_whitespace().count() as u64)
            as u32;

        let elapsed_ms = started.elapsed().as_millis() as u64;
        let tps = if elapsed_ms > 0 {
            output_tokens as f64 / (elapsed_ms as f64 / 1000.0)
        } else {
            0.0
        };

        Ok(InferenceResult {
            text: content,
            input_tokens,
            output_tokens,
            generation_time_ms: elapsed_ms,
            tokens_per_second: tps,
        })
    }

    /// Streaming chat completion. Each `choices[0].delta.content` fragment is
    /// forwarded through `token_tx`; the final [`InferenceResult`] is returned
    /// when the stream closes (`data: [DONE]`).
    pub async fn chat_stream(
        &self,
        messages: &[ChatMessage],
        config: &GenerationConfig,
        token_tx: tokio::sync::mpsc::Sender<String>,
    ) -> Result<InferenceResult> {
        use futures::StreamExt;

        let url = format!("{}/v1/chat/completions", self.base_url);
        let started = Instant::now();
        let resp = self
            .auth(self.client.post(&url))
            .json(&self.build_body(messages, config, true))
            .send()
            .await
            .map_err(|e| ModelError::Other(format!("external engine stream request: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(ModelError::Other(format!(
                "external engine stream returned {}: {}",
                status,
                body.chars().take(400).collect::<String>()
            )));
        }

        let mut assembled = String::new();
        let mut output_tokens: u32 = 0;
        let mut usage_prompt: Option<u32> = None;
        let mut usage_completion: Option<u32> = None;

        // SSE framing: accumulate bytes, split on `\n\n`, strip the `data: `
        // prefix, stop on `[DONE]`. A single chunk may straddle byte-stream
        // reads, so we buffer until a frame boundary is present.
        let mut buf = String::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk
                .map_err(|e| ModelError::Other(format!("external engine stream read: {}", e)))?;
            buf.push_str(&String::from_utf8_lossy(&bytes));

            while let Some(pos) = buf.find("\n\n") {
                let frame = buf[..pos].to_string();
                buf.drain(..pos + 2);
                for line in frame.lines() {
                    let line = line.trim();
                    let payload = match line.strip_prefix("data:") {
                        Some(p) => p.trim(),
                        None => continue,
                    };
                    if payload == "[DONE]" {
                        buf.clear();
                        break;
                    }
                    let v: Value = match serde_json::from_str(payload) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if let Some(delta) = v["choices"][0]["delta"]["content"].as_str() {
                        if !delta.is_empty() {
                            assembled.push_str(delta);
                            output_tokens += 1;
                            // Best-effort forward; a closed receiver (client
                            // disconnect) ends the stream early.
                            if token_tx.send(delta.to_string()).await.is_err() {
                                return Ok(finalize(
                                    assembled,
                                    usage_prompt,
                                    usage_completion,
                                    output_tokens,
                                    started,
                                    messages,
                                ));
                            }
                        }
                    }
                    if let Some(p) = v["usage"]["prompt_tokens"].as_u64() {
                        usage_prompt = Some(p as u32);
                    }
                    if let Some(c) = v["usage"]["completion_tokens"].as_u64() {
                        usage_completion = Some(c as u32);
                    }
                }
            }
        }

        Ok(finalize(
            assembled,
            usage_prompt,
            usage_completion,
            output_tokens,
            started,
            messages,
        ))
    }
}

/// Assemble the terminal [`InferenceResult`] from streamed state, preferring
/// the engine's reported usage over the token-delta tally.
fn finalize(
    text: String,
    usage_prompt: Option<u32>,
    usage_completion: Option<u32>,
    delta_tokens: u32,
    started: Instant,
    messages: &[ChatMessage],
) -> InferenceResult {
    let input_tokens = usage_prompt.unwrap_or_else(|| {
        messages
            .iter()
            .map(|m| m.content.split_whitespace().count() as u32)
            .sum()
    });
    let output_tokens = usage_completion.unwrap_or(delta_tokens);
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let tps = if elapsed_ms > 0 {
        output_tokens as f64 / (elapsed_ms as f64 / 1000.0)
    } else {
        0.0
    };
    InferenceResult {
        text,
        input_tokens,
        output_tokens,
        generation_time_ms: elapsed_ms,
        tokens_per_second: tps,
    }
}
