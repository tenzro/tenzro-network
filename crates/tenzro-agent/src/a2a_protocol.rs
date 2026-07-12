//! Agent-to-Agent (A2A) protocol implementation for Tenzro Network.
//!
//! This module implements the A2A protocol (inspired by Google A2A and
//! Anthropic MCP) for inter-agent communication, task delegation, and
//! capability negotiation.

use crate::error::{AgentError, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use tenzro_types::{primitives::Timestamp, AgentIdentity};
use uuid::Uuid;

/// A2A protocol version
pub const A2A_PROTOCOL_VERSION: &str = "1.0.0";

/// Types of A2A protocol messages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum A2aMessageType {
    /// Request to execute a task
    TaskRequest,
    /// Response to a task request
    TaskResponse,
    /// Query for capability information
    CapabilityQuery,
    /// Response to capability query
    CapabilityResponse,
    /// Negotiate protocol parameters
    Negotiate,
    /// Acknowledge receipt/completion
    Acknowledge,
    /// Error response
    Error,
}

/// A2A protocol message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aMessage {
    /// Protocol version
    pub protocol_version: String,
    /// Message type
    pub message_type: A2aMessageType,
    /// Message ID
    pub message_id: String,
    /// Sender agent
    pub sender: AgentIdentity,
    /// Receiver agent
    pub receiver: AgentIdentity,
    /// Message payload (JSON)
    pub payload: JsonValue,
    /// Message timestamp
    pub timestamp: Timestamp,
    /// Digital signature
    pub signature: Option<Vec<u8>>,
    /// Correlation ID (for request-response pairing)
    pub correlation_id: Option<String>,
}

impl A2aMessage {
    /// Creates a new A2A message
    pub fn new(
        sender: AgentIdentity,
        receiver: AgentIdentity,
        message_type: A2aMessageType,
        payload: JsonValue,
    ) -> Self {
        Self {
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            message_type,
            message_id: Uuid::new_v4().to_string(),
            sender,
            receiver,
            payload,
            timestamp: Timestamp::now(),
            signature: None,
            correlation_id: None,
        }
    }

    /// Sets the correlation ID for request-response pairing
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Adds a signature to the message
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Serializes the message to JSON bytes
    pub fn to_bytes(&self) -> Result<Bytes> {
        let json = serde_json::to_vec(self)?;
        Ok(Bytes::from(json))
    }

    /// Deserializes a message from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let message = serde_json::from_slice(bytes)?;
        Ok(message)
    }
}

/// Task request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRequest {
    /// Task ID
    pub task_id: String,
    /// Task type/name
    pub task_type: String,
    /// Task parameters
    pub parameters: HashMap<String, JsonValue>,
    /// Required capabilities
    pub required_capabilities: Vec<String>,
    /// Maximum execution time in seconds
    pub timeout: Option<u64>,
    /// Priority (0-10, higher is more urgent)
    pub priority: u8,
}

impl TaskRequest {
    /// Creates a new task request
    pub fn new(task_type: String, parameters: HashMap<String, JsonValue>) -> Self {
        Self {
            task_id: Uuid::new_v4().to_string(),
            task_type,
            parameters,
            required_capabilities: Vec::new(),
            timeout: None,
            priority: 5,
        }
    }

    /// Adds a required capability
    pub fn require_capability(mut self, capability: String) -> Self {
        self.required_capabilities.push(capability);
        self
    }

    /// Sets the timeout
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority.min(10);
        self
    }
}

/// Task response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResponse {
    /// Task ID (from request)
    pub task_id: String,
    /// Success status
    pub success: bool,
    /// Result data
    pub result: Option<JsonValue>,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl TaskResponse {
    /// Creates a successful task response
    pub fn success(task_id: String, result: JsonValue, execution_time_ms: u64) -> Self {
        Self {
            task_id,
            success: true,
            result: Some(result),
            error: None,
            execution_time_ms,
            metadata: HashMap::new(),
        }
    }

    /// Creates an error task response
    pub fn error(task_id: String, error: String, execution_time_ms: u64) -> Self {
        Self {
            task_id,
            success: false,
            result: None,
            error: Some(error),
            execution_time_ms,
            metadata: HashMap::new(),
        }
    }

    /// Adds metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Capability query payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityQuery {
    /// Specific capabilities to query (empty = all)
    pub capabilities: Vec<String>,
    /// Include TEE backing information
    pub include_tee_info: bool,
}

/// Capability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityInfo {
    /// Capability name
    pub name: String,
    /// Capability version
    pub version: String,
    /// Is TEE-backed
    pub tee_backed: bool,
    /// Additional parameters
    pub parameters: HashMap<String, JsonValue>,
}

/// Capability response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityResponse {
    /// Available capabilities
    pub capabilities: Vec<CapabilityInfo>,
    /// Agent metadata
    pub metadata: HashMap<String, String>,
}

/// Protocol negotiation payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiatePayload {
    /// Supported protocol versions
    pub supported_versions: Vec<String>,
    /// Supported message types
    pub supported_message_types: Vec<A2aMessageType>,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Additional features
    pub features: Vec<String>,
}

/// A2A Protocol handler
pub struct A2aProtocol {
    /// Supported protocol versions
    supported_versions: Vec<String>,
    /// Maximum message size
    max_message_size: usize,
}

impl A2aProtocol {
    /// Creates a new A2A protocol handler
    pub fn new() -> Self {
        Self {
            supported_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
            max_message_size: 10 * 1024 * 1024, // 10 MB
        }
    }

    /// Creates a new A2A protocol handler with custom configuration
    pub fn with_max_message_size(max_message_size: usize) -> Self {
        Self {
            supported_versions: vec![A2A_PROTOCOL_VERSION.to_string()],
            max_message_size,
        }
    }

    /// Validates a message
    pub fn validate_message(&self, message: &A2aMessage) -> Result<()> {
        // Check protocol version
        if !self.supported_versions.contains(&message.protocol_version) {
            return Err(AgentError::ProtocolError(format!(
                "Unsupported protocol version: {}",
                message.protocol_version
            )));
        }

        // Check message size
        let message_bytes = message.to_bytes()?;
        if message_bytes.len() > self.max_message_size {
            return Err(AgentError::ProtocolError(format!(
                "Message size {} exceeds maximum {}",
                message_bytes.len(),
                self.max_message_size
            )));
        }

        Ok(())
    }

    /// Sends a task request
    pub fn send_task_request(
        &self,
        sender: AgentIdentity,
        receiver: AgentIdentity,
        task_request: TaskRequest,
    ) -> Result<A2aMessage> {
        let payload = serde_json::to_value(task_request)?;
        let message = A2aMessage::new(sender, receiver, A2aMessageType::TaskRequest, payload);

        self.validate_message(&message)?;
        Ok(message)
    }

    /// Handles a task response
    pub fn handle_task_response(&self, message: A2aMessage) -> Result<TaskResponse> {
        if message.message_type != A2aMessageType::TaskResponse {
            return Err(AgentError::ProtocolError(
                "Expected TaskResponse message type".to_string(),
            ));
        }

        let response: TaskResponse = serde_json::from_value(message.payload)?;
        Ok(response)
    }

    /// Negotiates protocol capabilities
    pub fn negotiate_capability(
        &self,
        sender: AgentIdentity,
        receiver: AgentIdentity,
    ) -> Result<A2aMessage> {
        let payload = NegotiatePayload {
            supported_versions: self.supported_versions.clone(),
            supported_message_types: vec![
                A2aMessageType::TaskRequest,
                A2aMessageType::TaskResponse,
                A2aMessageType::CapabilityQuery,
                A2aMessageType::CapabilityResponse,
                A2aMessageType::Negotiate,
                A2aMessageType::Acknowledge,
            ],
            max_message_size: self.max_message_size,
            features: vec!["delegation".to_string(), "streaming".to_string()],
        };

        let payload_json = serde_json::to_value(payload)?;
        let message = A2aMessage::new(sender, receiver, A2aMessageType::Negotiate, payload_json);

        Ok(message)
    }

    /// Delegates a task to another agent
    pub fn delegate_task(
        &self,
        sender: AgentIdentity,
        receiver: AgentIdentity,
        task_type: String,
        parameters: HashMap<String, JsonValue>,
    ) -> Result<A2aMessage> {
        let task_request = TaskRequest::new(task_type, parameters);
        self.send_task_request(sender, receiver, task_request)
    }

    /// Queries agent capabilities
    pub fn query_capabilities(
        &self,
        sender: AgentIdentity,
        receiver: AgentIdentity,
        specific_capabilities: Vec<String>,
    ) -> Result<A2aMessage> {
        let query = CapabilityQuery {
            capabilities: specific_capabilities,
            include_tee_info: true,
        };

        let payload = serde_json::to_value(query)?;
        let message = A2aMessage::new(sender, receiver, A2aMessageType::CapabilityQuery, payload);

        Ok(message)
    }

    /// Creates a capability response
    pub fn create_capability_response(
        &self,
        sender: AgentIdentity,
        receiver: AgentIdentity,
        capabilities: Vec<CapabilityInfo>,
    ) -> Result<A2aMessage> {
        let response = CapabilityResponse {
            capabilities,
            metadata: HashMap::new(),
        };

        let payload = serde_json::to_value(response)?;
        let message = A2aMessage::new(sender, receiver, A2aMessageType::CapabilityResponse, payload);

        Ok(message)
    }

    /// Creates an acknowledgment message
    pub fn create_acknowledgment(
        &self,
        sender: AgentIdentity,
        receiver: AgentIdentity,
        correlation_id: String,
    ) -> Result<A2aMessage> {
        let payload = serde_json::json!({
            "status": "acknowledged",
            "correlation_id": correlation_id,
        });

        let message = A2aMessage::new(sender, receiver, A2aMessageType::Acknowledge, payload)
            .with_correlation_id(correlation_id);

        Ok(message)
    }
}

impl Default for A2aProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Model Context Protocol (MCP) message types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpMessageType {
    /// Call a tool/function
    ToolCall,
    /// Return result from tool call
    ToolResult,
    /// Update context
    ContextUpdate,
    /// Request context
    ContextRequest,
}

/// MCP message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMessage {
    /// Message type
    pub message_type: McpMessageType,
    /// Message ID
    pub message_id: String,
    /// Payload
    pub payload: JsonValue,
    /// Timestamp
    pub timestamp: Timestamp,
    /// Correlation ID
    pub correlation_id: Option<String>,
}

impl McpMessage {
    /// Creates a new MCP message
    pub fn new(message_type: McpMessageType, payload: JsonValue) -> Self {
        Self {
            message_type,
            message_id: Uuid::new_v4().to_string(),
            payload,
            timestamp: Timestamp::now(),
            correlation_id: None,
        }
    }

    /// Sets correlation ID
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }
}

/// Tool call payload for MCP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool name
    pub tool_name: String,
    /// Tool arguments
    pub arguments: HashMap<String, JsonValue>,
}

/// Tool result payload for MCP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Success status
    pub success: bool,
    /// Result data
    pub result: Option<JsonValue>,
    /// Error message
    pub error: Option<String>,
}

/// MCP client for connecting to remote MCP servers via Streamable HTTP transport.
///
/// Implements the MCP Streamable HTTP transport specification:
/// - JSON-RPC 2.0 over HTTP POST
/// - Session management via `Mcp-Session-Id` header
/// - Tool discovery via `tools/list`
/// - Tool invocation via `tools/call`
pub struct McpClient {
    /// HTTP client for making requests
    http_client: reqwest::Client,
    /// MCP server endpoint URL (e.g., "https://mcp.tenzro.xyz/mcp")
    endpoint: String,
    /// Session ID assigned by the server during initialization
    session_id: Option<String>,
    /// JSON-RPC request ID counter
    next_id: std::sync::atomic::AtomicU64,
    /// Whether the client has been initialized
    initialized: bool,
    /// Server info from initialization
    pub server_info: Option<JsonValue>,
}

impl McpClient {
    /// Creates a new MCP client for the given endpoint URL.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            endpoint: endpoint.into(),
            session_id: None,
            next_id: std::sync::atomic::AtomicU64::new(1),
            initialized: false,
            server_info: None,
        }
    }

    /// Creates a new MCP client with a custom HTTP client.
    pub fn with_http_client(endpoint: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            http_client: client,
            endpoint: endpoint.into(),
            session_id: None,
            next_id: std::sync::atomic::AtomicU64::new(1),
            initialized: false,
            server_info: None,
        }
    }

    fn next_request_id(&self) -> u64 {
        self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Sends a JSON-RPC request to the MCP server and returns the result.
    async fn send_request(&self, method: &str, params: Option<JsonValue>) -> Result<JsonValue> {
        let id = self.next_request_id();
        let mut body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
        });
        if let Some(p) = params {
            body["params"] = p;
        }

        let mut request = self.http_client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(ref session_id) = self.session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }

        let response = request
            .json(&body)
            .send()
            .await
            .map_err(|e| AgentError::ProtocolError(format!("MCP request failed: {}", e)))?;

        // Check for session ID in response headers
        // (handled in initialize() specifically)

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AgentError::ProtocolError(format!(
                "MCP server returned HTTP {}: {}",
                status, error_text,
            )));
        }

        let result: JsonValue = response
            .json()
            .await
            .map_err(|e| AgentError::ProtocolError(format!("Failed to parse MCP response: {}", e)))?;

        // Check for JSON-RPC error
        if let Some(error) = result.get("error") {
            return Err(AgentError::ProtocolError(format!(
                "MCP JSON-RPC error: {}",
                error,
            )));
        }

        Ok(result.get("result").cloned().unwrap_or(JsonValue::Null))
    }

    /// Initializes the MCP session with the server.
    ///
    /// Sends `initialize` request per the MCP specification and stores the session ID.
    pub async fn initialize(&mut self) -> Result<JsonValue> {
        let id = self.next_request_id();
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "tenzro-agent",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }
        });

        let mut request = self.http_client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(ref session_id) = self.session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }

        let response = request
            .json(&body)
            .send()
            .await
            .map_err(|e| AgentError::ProtocolError(format!("MCP initialize failed: {}", e)))?;

        // Extract session ID from response header
        if let Some(session_id) = response.headers().get("Mcp-Session-Id")
            && let Ok(sid) = session_id.to_str()
        {
            self.session_id = Some(sid.to_string());
        }

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AgentError::ProtocolError(format!(
                "MCP initialize returned HTTP {}: {}",
                status, error_text,
            )));
        }

        let result: JsonValue = response
            .json()
            .await
            .map_err(|e| AgentError::ProtocolError(format!("Failed to parse initialize response: {}", e)))?;

        let server_info = result.get("result").cloned().unwrap_or(JsonValue::Null);
        self.server_info = Some(server_info.clone());
        self.initialized = true;

        // Send initialized notification (per MCP spec)
        let _notification = self.send_notification("notifications/initialized", None).await;

        Ok(server_info)
    }

    /// Sends a JSON-RPC notification (no response expected).
    async fn send_notification(&self, method: &str, params: Option<JsonValue>) -> Result<()> {
        let mut body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
        });
        if let Some(p) = params {
            body["params"] = p;
        }

        let mut request = self.http_client
            .post(&self.endpoint)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(ref session_id) = self.session_id {
            request = request.header("Mcp-Session-Id", session_id);
        }

        let response = request
            .json(&body)
            .send()
            .await
            .map_err(|e| AgentError::ProtocolError(format!("MCP notification failed: {}", e)))?;

        // Notifications should return 202 Accepted
        let status = response.status();
        if status != reqwest::StatusCode::ACCEPTED && !status.is_success() {
            tracing::warn!("MCP notification returned unexpected status: {}", status);
        }

        Ok(())
    }

    /// Lists available tools on the MCP server.
    ///
    /// Returns the list of tools with their names, descriptions, and input schemas.
    pub async fn list_tools(&self) -> Result<JsonValue> {
        if !self.initialized {
            return Err(AgentError::ProtocolError(
                "MCP client not initialized. Call initialize() first.".to_string(),
            ));
        }
        self.send_request("tools/list", None).await
    }

    /// Calls a tool on the MCP server.
    ///
    /// # Arguments
    /// * `tool_name` - Name of the tool to call
    /// * `arguments` - Tool arguments as a JSON object
    pub async fn call_tool(&self, tool_name: &str, arguments: JsonValue) -> Result<JsonValue> {
        if !self.initialized {
            return Err(AgentError::ProtocolError(
                "MCP client not initialized. Call initialize() first.".to_string(),
            ));
        }
        self.send_request("tools/call", Some(serde_json::json!({
            "name": tool_name,
            "arguments": arguments,
        }))).await
    }

    /// Returns whether the client has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the current session ID, if any.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

/// Bridge between A2A and MCP protocols with optional remote MCP transport.
pub struct McpBridge {
    /// Optional MCP client for remote server communication
    mcp_client: Option<McpClient>,
}

impl McpBridge {
    /// Creates a new MCP bridge (local format conversion only)
    pub fn new() -> Self {
        Self {
            mcp_client: None,
        }
    }

    /// Creates a new MCP bridge connected to a remote MCP server.
    pub fn with_remote(endpoint: impl Into<String>) -> Self {
        Self {
            mcp_client: Some(McpClient::new(endpoint)),
        }
    }

    /// Initializes the remote MCP connection.
    ///
    /// Must be called before using `call_remote_tool()` or `list_remote_tools()`.
    pub async fn connect(&mut self) -> Result<()> {
        if let Some(ref mut client) = self.mcp_client {
            client.initialize().await?;
            tracing::info!("MCP bridge connected to remote server");
            Ok(())
        } else {
            Err(AgentError::ProtocolError(
                "No remote MCP server configured. Use McpBridge::with_remote().".to_string(),
            ))
        }
    }

    /// Lists tools available on the remote MCP server.
    pub async fn list_remote_tools(&self) -> Result<JsonValue> {
        if let Some(ref client) = self.mcp_client {
            client.list_tools().await
        } else {
            Err(AgentError::ProtocolError(
                "No remote MCP server configured".to_string(),
            ))
        }
    }

    /// Calls a tool on the remote MCP server.
    pub async fn call_remote_tool(&self, tool_name: &str, arguments: JsonValue) -> Result<JsonValue> {
        if let Some(ref client) = self.mcp_client {
            client.call_tool(tool_name, arguments).await
        } else {
            Err(AgentError::ProtocolError(
                "No remote MCP server configured".to_string(),
            ))
        }
    }

    /// Returns a reference to the MCP client, if connected.
    pub fn mcp_client(&self) -> Option<&McpClient> {
        self.mcp_client.as_ref()
    }

    /// Converts an A2A task request to an MCP tool call
    pub fn a2a_to_mcp_tool_call(&self, message: &A2aMessage) -> Result<McpMessage> {
        if message.message_type != A2aMessageType::TaskRequest {
            return Err(AgentError::ProtocolError(
                "Expected TaskRequest message type".to_string(),
            ));
        }

        let task_request: TaskRequest = serde_json::from_value(message.payload.clone())?;

        let tool_call = ToolCall {
            tool_name: task_request.task_type,
            arguments: task_request.parameters,
        };

        let payload = serde_json::to_value(tool_call)?;
        let mcp_message = McpMessage::new(McpMessageType::ToolCall, payload)
            .with_correlation_id(message.message_id.clone());

        Ok(mcp_message)
    }

    /// Converts an MCP tool result to an A2A task response
    pub fn mcp_to_a2a_task_response(
        &self,
        mcp_message: &McpMessage,
        sender: AgentIdentity,
        receiver: AgentIdentity,
        task_id: String,
    ) -> Result<A2aMessage> {
        if mcp_message.message_type != McpMessageType::ToolResult {
            return Err(AgentError::ProtocolError(
                "Expected ToolResult message type".to_string(),
            ));
        }

        let tool_result: ToolResult = serde_json::from_value(mcp_message.payload.clone())?;

        let task_response = if tool_result.success {
            TaskResponse::success(task_id, tool_result.result.unwrap_or(JsonValue::Null), 0)
        } else {
            TaskResponse::error(task_id, tool_result.error.unwrap_or_default(), 0)
        };

        let payload = serde_json::to_value(task_response)?;
        let mut a2a_message = A2aMessage::new(sender, receiver, A2aMessageType::TaskResponse, payload);

        if let Some(correlation_id) = &mcp_message.correlation_id {
            a2a_message = a2a_message.with_correlation_id(correlation_id.clone());
        }

        Ok(a2a_message)
    }

    /// Bridges an A2A message to MCP — either locally or to a remote MCP server.
    ///
    /// If a remote MCP client is connected, forwards the tool call to the remote server.
    /// Otherwise, performs local A2A-to-MCP format conversion only.
    pub async fn bridge_a2a_to_mcp_remote(
        &self,
        message: &A2aMessage,
    ) -> Result<McpMessage> {
        // Convert A2A to MCP tool call
        let mcp_message = self.a2a_to_mcp_tool_call(message)?;

        // If we have a remote MCP client, forward the call
        if let Some(ref client) = self.mcp_client
            && client.is_initialized()
        {
            let tool_call: ToolCall = serde_json::from_value(mcp_message.payload.clone())?;
            let result = client.call_tool(
                &tool_call.tool_name,
                serde_json::to_value(&tool_call.arguments)?,
            ).await?;

            let tool_result = ToolResult {
                success: true,
                result: Some(result),
                error: None,
            };

            return Ok(McpMessage::new(
                McpMessageType::ToolResult,
                serde_json::to_value(tool_result)?,
            ).with_correlation_id(mcp_message.message_id));
        }

        // No remote client — return the local conversion only
        Ok(mcp_message)
    }

    /// Bridges an A2A message to MCP (local format conversion only, sync)
    pub fn bridge_a2a_to_mcp(&self, message: &A2aMessage) -> Result<McpMessage> {
        match message.message_type {
            A2aMessageType::TaskRequest => self.a2a_to_mcp_tool_call(message),
            _ => Err(AgentError::ProtocolError(
                "Unsupported message type for MCP bridging".to_string(),
            )),
        }
    }
}

impl Default for McpBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::Address;

    fn create_test_identity(id: &str) -> AgentIdentity {
        AgentIdentity::new(
            id.to_string(),
            Address::from([0u8; 32]),
            id.to_string(),
            Address::from([1u8; 32]),
        )
    }

    #[test]
    fn test_task_request_creation() {
        let mut params = HashMap::new();
        params.insert("input".to_string(), serde_json::json!("test data"));

        let task = TaskRequest::new("analyze".to_string(), params)
            .require_capability("data_analysis".to_string())
            .with_timeout(60)
            .with_priority(8);

        assert_eq!(task.task_type, "analyze");
        assert_eq!(task.priority, 8);
        assert_eq!(task.timeout, Some(60));
    }

    #[test]
    fn test_a2a_message_creation() {
        let sender = create_test_identity("sender");
        let receiver = create_test_identity("receiver");

        let message = A2aMessage::new(
            sender,
            receiver,
            A2aMessageType::TaskRequest,
            serde_json::json!({"test": "data"}),
        );

        assert_eq!(message.protocol_version, A2A_PROTOCOL_VERSION);
        assert_eq!(message.message_type, A2aMessageType::TaskRequest);
    }

    #[test]
    fn test_protocol_validation() {
        let protocol = A2aProtocol::new();
        let sender = create_test_identity("sender");
        let receiver = create_test_identity("receiver");

        let message = A2aMessage::new(
            sender,
            receiver,
            A2aMessageType::Negotiate,
            serde_json::json!({}),
        );

        assert!(protocol.validate_message(&message).is_ok());
    }

    #[test]
    fn test_mcp_bridge() {
        let bridge = McpBridge::new();
        let sender = create_test_identity("sender");
        let receiver = create_test_identity("receiver");

        let mut params = HashMap::new();
        params.insert("arg1".to_string(), serde_json::json!("value1"));

        let task = TaskRequest::new("test_task".to_string(), params);
        let payload = serde_json::to_value(task).unwrap();

        let a2a_message = A2aMessage::new(sender, receiver, A2aMessageType::TaskRequest, payload);

        let mcp_message = bridge.a2a_to_mcp_tool_call(&a2a_message).unwrap();
        assert_eq!(mcp_message.message_type, McpMessageType::ToolCall);
    }
}
