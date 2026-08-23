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

use tracing::warn;

/// What one scrape of an external engine's Prometheus endpoint tells us.
///
/// Both vLLM and SGLang expose these; the metric families differ only in
/// prefix, so [`EngineMetrics::parse`] accepts either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineMetrics {
    /// Requests currently decoding.
    pub running: u32,
    /// Requests admitted but queued behind them.
    pub waiting: u32,
    /// Tokens the engine has looked up in its prefix cache, cumulative.
    ///
    /// The **counter, not the metric's presence**, is the signal that matters.
    /// vLLM registers this family whether or not prefix caching is on: a live
    /// qwen3.8 server reports `vllm:prefix_cache_queries_total 0.0` because it
    /// is a hybrid Gated-DeltaNet model and vLLM disables prefix caching for
    /// it. So "the metric exists" proves nothing and "it has incremented"
    /// proves the cache is real.
    pub prefix_cache_queries: u64,
    /// Of those lookups, how many hit.
    pub prefix_cache_hits: u64,
}

impl EngineMetrics {
    /// Whether this engine demonstrably reuses a prefix cache.
    ///
    /// Gating warm-prefix advertisement on this keeps the announcement honest.
    /// A provider that cannot reuse a prefix but advertises one attracts the
    /// long prompts it is worst at, pays the full prefill anyway, and displaces
    /// a provider that would genuinely have saved it — the same harm the
    /// forged-`run_len` check rejects, arrived at by accident rather than
    /// malice.
    pub fn prefix_cache_is_real(&self) -> bool {
        self.prefix_cache_queries > 0
    }

    /// In-flight work: decoding plus queued.
    pub fn active_requests(&self) -> u32 {
        self.running.saturating_add(self.waiting)
    }

    /// Parse a Prometheus exposition body, ignoring `#` comment lines.
    ///
    /// A sample line is `name{labels} value`; values are floats even for
    /// counters (`0.0`), so each is parsed as `f64` and truncated. Samples for
    /// several engines or models on one endpoint are summed, which is what the
    /// node-wide announcement wants.
    fn parse(body: &str) -> Option<Self> {
        let mut m = EngineMetrics::default();
        let mut saw_any = false;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = match line.rsplit_once(' ') {
                Some((n, v)) => (n, v),
                None => continue,
            };
            let Ok(value) = value.parse::<f64>() else {
                continue;
            };
            if !value.is_finite() || value < 0.0 {
                continue;
            }
            let family = name.split('{').next().unwrap_or(name);
            let field = match family {
                "vllm:num_requests_running" | "sglang:num_running_reqs" => &mut m.running,
                "vllm:num_requests_waiting" | "sglang:num_queue_reqs" => &mut m.waiting,
                "vllm:prefix_cache_queries_total" | "sglang:prefix_cache_queries_total" => {
                    m.prefix_cache_queries = m.prefix_cache_queries.saturating_add(value as u64);
                    saw_any = true;
                    continue;
                }
                "vllm:prefix_cache_hits_total" | "sglang:prefix_cache_hits_total" => {
                    m.prefix_cache_hits = m.prefix_cache_hits.saturating_add(value as u64);
                    saw_any = true;
                    continue;
                }
                _ => continue,
            };
            *field = field.saturating_add(value as u32);
            saw_any = true;
        }
        saw_any.then_some(m)
    }
}

use crate::error::{ModelError, Result};
use crate::runtime::{ChatMessage, GenerationConfig, InferenceResult, StopReason};

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

    /// One scrape of the engine's Prometheus endpoint.
    ///
    /// This is the only way the node learns what an external engine is doing.
    /// Both `generate_chat` and `generate_chat_stream` hand a request straight
    /// to the engine and return before `acquire_inflight`, so `LoadTracker`
    /// counts nothing for these models and the node cannot otherwise tell a
    /// saturated engine from an idle one.
    ///
    /// Returns `None` when the endpoint is unreachable or unparseable —
    /// "unknown", never a fabricated zero, because zero in-flight requests is
    /// exactly the value that makes a provider look most attractive.
    pub async fn scrape_metrics(&self) -> Option<EngineMetrics> {
        let url = format!("{}/metrics", self.base_url);
        let body = self
            .auth(self.client.get(&url))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .ok()?
            .text()
            .await
            .ok()?;
        EngineMetrics::parse(&body)
    }

    fn build_body(
        &self,
        messages: &[ChatMessage],
        config: &GenerationConfig,
        stream: bool,
    ) -> Value {
        // Tool structure has to survive the round trip, not just the outbound
        // schemas. An assistant turn that called a tool carries `tool_calls`,
        // and the `role: "tool"` turn answering it carries `tool_call_id` —
        // which the OpenAI message schema marks *required*, so vLLM and SGLang
        // reject a tool message without one with a 400. Serializing only
        // role+content dropped both: strict servers failed the second turn of
        // every tool conversation, and lenient ones saw a result answering a
        // call the transcript no longer contained.
        let msgs: Vec<Value> = messages
            .iter()
            .map(|m| {
                let mut v = json!({ "role": m.role, "content": m.content });
                if let Some(calls) = &m.tool_calls {
                    v["tool_calls"] = calls.clone();
                }
                if let Some(name) = &m.name {
                    v["name"] = json!(name);
                }
                if let Some(id) = &m.tool_call_id {
                    v["tool_call_id"] = json!(id);
                }
                v
            })
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
        let (inner, _) = self.chat_inner(messages, &[], config).await?;
        Ok(inner)
    }

    /// Chat with the tool schemas attached, returning any structured calls.
    ///
    /// The schemas go over the wire in the OpenAI function shape, which every
    /// engine this type fronts already speaks, so the engine's own tool parser
    /// performs the extraction. That is the point of sending them: a parser
    /// built for the model's own format cannot be defeated by the model
    /// phrasing a call slightly differently, whereas reading calls back out of
    /// prose can be, and is — the more so the higher the temperature, and
    /// qwen3.8's own recommended sampling is 1.0.
    ///
    /// `tool_choice` is left as the engine's default rather than forced: a turn
    /// that answers in words instead of acting is a legitimate turn.
    ///
    /// An engine started without a tool parser simply returns no `tool_calls`,
    /// and the caller falls back to parsing the text exactly as it did before.
    pub async fn chat_with_tools(
        &self,
        messages: &[ChatMessage],
        tools: &[crate::runtime::ToolDefinition],
        config: &GenerationConfig,
    ) -> Result<(InferenceResult, Vec<crate::runtime::ToolCall>)> {
        self.chat_inner(messages, tools, config).await
    }

    /// Read `choices[0].message.tool_calls` in the OpenAI shape.
    ///
    /// Arguments arrive as a JSON *string* and are parsed one level. One that
    /// will not parse is passed through as a string rather than dropped: a
    /// malformed argument the caller can see and report beats a call that
    /// silently disappeared.
    fn tool_calls_from_choice(choice: &Value) -> Vec<crate::runtime::ToolCall> {
        let Some(arr) = choice["message"]["tool_calls"].as_array() else {
            return Vec::new();
        };
        arr.iter()
            .filter_map(|c| {
                // A call with no name cannot be dispatched, but dropping it
                // silently ends the turn as an empty `end_turn` and the agent
                // loop simply stops with nothing logged. Say so.
                let Some(name) = c["function"]["name"].as_str() else {
                    warn!(call = %c, "dropping tool call with no function name");
                    return None;
                };
                Some(crate::runtime::ToolCall {
                    id: Self::call_id(c),
                    name: name.to_string(),
                    input: Self::call_arguments(c, name),
                })
            })
            .collect()
    }

    /// A stable, unique id for one tool call.
    ///
    /// A blank `id` is as useless as a missing one — and `as_str()` returns
    /// `Some("")` for it, so a naive fallback never fires. The previous
    /// per-response index (`call_0`, `call_1`) collided *across* turns: the
    /// caller builds one id→name map over the whole history, so turn 3's
    /// `call_0` overwrote turn 1's and stamped the wrong tool name on an
    /// earlier result. Mint a unique id instead, matching `muse_harmony`'s
    /// `toolu_{uuid}` convention.
    fn call_id(call: &Value) -> String {
        match call["id"].as_str() {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => format!("toolu_{}", uuid::Uuid::new_v4().simple()),
        }
    }

    /// The call's arguments as a JSON object.
    ///
    /// The OpenAI spec makes `arguments` a *stringified* JSON object, but TGI
    /// and several gateways send the object inline. Reading only the string
    /// form meant an inline object fell to the `"{}"` default and produced a
    /// perfectly well-formed call with every argument missing — which then
    /// *executed*. A wrong call that runs is worse than one that errors, so
    /// both encodings are accepted.
    ///
    /// An empty string means "no arguments" (several servers emit it for a
    /// no-arg tool), not "a string argument": the downstream `ToolUse.input`
    /// contract is an object, and a bare `""` breaks clients that parse it.
    fn call_arguments(call: &Value, name: &str) -> Value {
        let args = &call["function"]["arguments"];
        if args.is_object() {
            return args.clone();
        }
        match args.as_str() {
            None | Some("") => Value::Object(serde_json::Map::new()),
            Some(raw) => serde_json::from_str(raw).unwrap_or_else(|_| {
                // Passed through rather than dropped: a malformed argument the
                // caller can see and report beats a call that vanished.
                warn!(
                    tool = %name,
                    arguments = %raw,
                    "tool-call arguments are not valid JSON; passing through verbatim"
                );
                Value::String(raw.to_string())
            }),
        }
    }

    async fn chat_inner(
        &self,
        messages: &[ChatMessage],
        tools: &[crate::runtime::ToolDefinition],
        config: &GenerationConfig,
    ) -> Result<(InferenceResult, Vec<crate::runtime::ToolCall>)> {
        let url = format!("{}/v1/chat/completions", self.base_url);
        let started = Instant::now();
        let mut body = self.build_body(messages, config, false);
        if !tools.is_empty() {
            body["tools"] = Value::Array(
                tools
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "type": "function",
                            "function": {
                                "name": t.name,
                                "description": t.description.clone().unwrap_or_default(),
                                "parameters": t.input_schema,
                            }
                        })
                    })
                    .collect(),
            );
        }
        let resp = self
            .auth(self.client.post(&url))
            .json(&body)
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
            messages
                .iter()
                .map(|m| m.content.split_whitespace().count() as u64)
                .sum()
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

        // An upstream OpenAI-compatible server hands back whatever the model
        // emitted, reasoning tags included — there is no `StopStream` on this
        // path to classify them as they decode, so split the finished text.
        let (content, thinking) = crate::runtime::split_reasoning(&content);
        let calls = Self::tool_calls_from_choice(&v["choices"][0]);
        Ok((
            InferenceResult {
                text: content,
                thinking,
                input_tokens,
                output_tokens,
                generation_time_ms: elapsed_ms,
                tokens_per_second: tps,
                stop_reason: stop_reason_from_choice(&v["choices"][0]),
                commitment: None,
            },
            calls,
        ))
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
        // Set from whichever frame carries the terminal choice. A client that
        // disconnects mid-stream never sees one, which leaves the default.
        let mut stop_reason = StopReason::Eos;

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
                    if let Some(delta) = v["choices"][0]["delta"]["content"].as_str()
                        && !delta.is_empty()
                    {
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
                                stop_reason,
                            ));
                        }
                    }
                    if !v["choices"][0]["finish_reason"].is_null() {
                        stop_reason = stop_reason_from_choice(&v["choices"][0]);
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
            stop_reason,
        ))
    }
}

/// Termination cause reported by an OpenAI-compatible engine for one choice.
///
/// `finish_reason` distinguishes an exhausted budget (`length`) from a natural
/// end, but conflates an end-of-generation token with a matched stop sequence —
/// both are spelled `stop`. Engines that separate the two carry the matched
/// stop string in a sibling `stop_reason`, so a non-null sibling resolves
/// `stop` to [`StopReason::StopSequence`].
fn stop_reason_from_choice(choice: &Value) -> StopReason {
    match choice["finish_reason"].as_str() {
        Some("length") => StopReason::Length,
        Some("stop") if !choice["stop_reason"].is_null() => StopReason::StopSequence,
        _ => StopReason::Eos,
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
    stop_reason: StopReason,
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
    // Streamed deltas were already forwarded verbatim, so this only cleans the
    // assembled text a non-streaming caller reads back.
    let (text, thinking) = crate::runtime::split_reasoning(&text);
    InferenceResult {
        text,
        thinking,
        input_tokens,
        output_tokens,
        generation_time_ms: elapsed_ms,
        tokens_per_second: tps,
        stop_reason,
        commitment: None,
    }
}

#[cfg(test)]
mod engine_metrics_tests {
    use super::EngineMetrics;

    /// Verbatim from a live vLLM serving qwen3.8-27b on the Spark, including
    /// the HELP/TYPE comments and the `_by_reason` family that shares a prefix
    /// with `num_requests_waiting`.
    const LIVE_VLLM: &str = r#"
# HELP vllm:num_requests_running Number of requests in model execution batches.
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{engine="0",model_name="qwen3.8-27b"} 3.0
# HELP vllm:num_requests_waiting Number of requests waiting to be processed.
# TYPE vllm:num_requests_waiting gauge
vllm:num_requests_waiting{engine="0",model_name="qwen3.8-27b"} 2.0
# TYPE vllm:num_requests_waiting_by_reason gauge
vllm:num_requests_waiting_by_reason{engine="0",model_name="qwen3.8-27b",reason="capacity"} 2.0
vllm:num_requests_waiting_by_reason{engine="0",model_name="qwen3.8-27b",reason="deferred"} 0.0
# TYPE vllm:prefix_cache_queries_total counter
vllm:prefix_cache_queries_total{engine="0",model_name="qwen3.8-27b"} 0.0
# TYPE vllm:prefix_cache_hits_total counter
vllm:prefix_cache_hits_total{engine="0",model_name="qwen3.8-27b"} 0.0
"#;

    /// `num_requests_waiting_by_reason` sums to `num_requests_waiting` by
    /// construction, so matching families by prefix would double-count every
    /// queued request and make a busy engine look twice as busy.
    #[test]
    fn a_shared_prefix_family_is_not_double_counted() {
        let m = EngineMetrics::parse(LIVE_VLLM).expect("parses");
        assert_eq!(m.running, 3);
        assert_eq!(m.waiting, 2, "by_reason must not be added in");
        assert_eq!(m.active_requests(), 5);
    }

    /// The counter, not the metric's presence, is the signal. This is the real
    /// qwen3.8 case: vLLM registers the family and it stays at zero because
    /// the model is hybrid and prefix caching is disabled for it.
    #[test]
    fn a_registered_but_never_incremented_counter_is_not_a_real_cache() {
        let m = EngineMetrics::parse(LIVE_VLLM).expect("parses");
        assert!(
            !m.prefix_cache_is_real(),
            "a zero counter means no prefix cache, however present the metric"
        );

        let warm = LIVE_VLLM.replace("prefix_cache_queries_total{engine=\"0\",model_name=\"qwen3.8-27b\"} 0.0", "prefix_cache_queries_total{engine=\"0\",model_name=\"qwen3.8-27b\"} 4096.0");
        let m = EngineMetrics::parse(&warm).expect("parses");
        assert!(m.prefix_cache_is_real());
        assert_eq!(m.prefix_cache_queries, 4096);
    }

    /// An unreachable or foreign endpoint must read as unknown, never as an
    /// idle engine — zero in-flight is the most attractive value there is.
    #[test]
    fn nothing_recognisable_is_unknown_not_idle() {
        assert_eq!(EngineMetrics::parse(""), None);
        assert_eq!(EngineMetrics::parse("# HELP something else\nfoo_bar 1.0"), None);
    }

    /// SGLang exposes the same facts under its own prefix.
    #[test]
    fn sglang_families_are_accepted_too() {
        let m = EngineMetrics::parse(
            "sglang:num_running_reqs{model=\"x\"} 1.0\nsglang:num_queue_reqs{model=\"x\"} 4.0",
        )
        .expect("parses");
        assert_eq!(m.active_requests(), 5);
    }
}
