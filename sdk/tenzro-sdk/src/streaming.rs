//! Streaming & Real-time SDK for Tenzro Network
//!
//! This module provides streaming chat against the node's
//! `POST /v1/chat/completions`, real-time event subscriptions, and SSE
//! connections to A2A/MCP servers.

use crate::chat::{ChatCompletion, ChatRequest, ChatStreamAssembler, ChatStreamEvent};
use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use crate::sse::SseDecoder;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Client for streaming and real-time operations
///
/// Provides streaming chat inference, event subscriptions, and SSE connections.
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # use tenzro_sdk::chat::{ChatRequest, ChatStreamEvent};
/// # use tenzro_sdk::provider::ChatMessage;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let request = ChatRequest::new("qwen3.5-4b", vec![ChatMessage::user("What is Tenzro?")]);
/// let completion = client.streaming().chat_stream(&request, |event| {
///     if let ChatStreamEvent::Content { text } = event {
///         print!("{}", text);
///     }
/// }).await?;
/// println!("\n{:?}", completion.usage);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct StreamingClient {
    rpc: Arc<RpcClient>,
}

impl StreamingClient {
    /// Creates a new streaming client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Streams a chat completion from the node's `POST /v1/chat/completions`,
    /// calling `on_event` for each reasoning, content, tool-call, finish and
    /// usage event as it arrives, and returns the assembled completion.
    ///
    /// An error the node reports, before or during the stream, returns as
    /// [`SdkError::Api`].
    pub async fn chat_stream(
        &self,
        request: &ChatRequest,
        mut on_event: impl FnMut(&ChatStreamEvent),
    ) -> SdkResult<ChatCompletion> {
        let mut reader = ChatStreamReader::new(self.open_chat(request).await?);
        while let Some(event) = reader.next().await {
            on_event(&event?);
        }
        Ok(reader.assembler.completion())
    }

    /// Streams a chat completion as a channel of events. The channel closes
    /// after the last event; an error ends it with an `Err` item.
    pub async fn chat_stream_channel(
        &self,
        request: &ChatRequest,
    ) -> SdkResult<mpsc::Receiver<SdkResult<ChatStreamEvent>>> {
        let mut reader = ChatStreamReader::new(self.open_chat(request).await?);
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Some(item) = reader.next().await {
                if tx.send(item).await.is_err() {
                    return;
                }
            }
        });
        Ok(rx)
    }

    async fn open_chat(&self, request: &ChatRequest) -> SdkResult<reqwest::Response> {
        let mut body = serde_json::to_value(request)?;
        body["stream"] = serde_json::Value::Bool(true);
        self.rpc.post_stream("/v1/chat/completions", &body).await
    }

    /// Opens an SSE connection to an A2A or MCP endpoint
    ///
    /// Returns a handle to the connection that can be used to receive messages.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Full URL of the SSE endpoint
    pub async fn open_sse_connection(&self, endpoint: &str) -> SdkResult<SseConnection> {
        // Validate the endpoint is reachable
        let client = reqwest::Client::new();
        let _response = client
            .get(endpoint)
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(|e| SdkError::ConnectionError(e.to_string()))?;

        Ok(SseConnection {
            url: endpoint.to_string(),
        })
    }
}

type ByteStream = std::pin::Pin<Box<dyn futures::Stream<Item = reqwest::Result<Vec<u8>>> + Send>>;

/// Reads a chat stream body into events, one network read at a time.
struct ChatStreamReader {
    body: ByteStream,
    decoder: SseDecoder,
    assembler: ChatStreamAssembler,
    pending: std::collections::VecDeque<ChatStreamEvent>,
    failure: Option<SdkError>,
    finished: bool,
}

impl ChatStreamReader {
    fn new(response: reqwest::Response) -> Self {
        Self {
            body: Box::pin(response.bytes_stream().map(|r| r.map(|b| b.to_vec()))),
            decoder: SseDecoder::new(),
            assembler: ChatStreamAssembler::new(),
            pending: Default::default(),
            failure: None,
            finished: false,
        }
    }

    /// The next event, `None` once the stream has ended. Events decoded
    /// before an error are delivered first; the error ends the stream.
    async fn next(&mut self) -> Option<SdkResult<ChatStreamEvent>> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Some(Ok(event));
            }
            if let Some(e) = self.failure.take() {
                return Some(Err(e));
            }
            if self.finished {
                return None;
            }
            let frames = match self.body.next().await {
                Some(Ok(chunk)) => self.decoder.push(&chunk),
                Some(Err(e)) => {
                    self.finished = true;
                    self.failure = Some(SdkError::ConnectionError(e.to_string()));
                    continue;
                }
                None => {
                    self.finished = true;
                    self.decoder.finish()
                }
            };
            for frame in frames {
                match self.assembler.push(&frame.data) {
                    Ok(events) => self.pending.extend(events),
                    Err(e) => {
                        self.failure = Some(e.into());
                        self.finished = true;
                        break;
                    }
                }
                if self.assembler.is_done() {
                    self.finished = true;
                    break;
                }
            }
        }
    }
}

/// SSE connection handle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseConnection {
    /// SSE endpoint URL
    pub url: String,
}
