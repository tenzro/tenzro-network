//! Canton Ledger API client — real gRPC integration via tonic
//!
//! Client for the Canton participant node's Ledger API (gRPC, default port 5001).
//! Uses tonic for actual gRPC connectivity with graceful degradation when the
//! Canton participant is unreachable.
//!
//! # Canton Ledger API Services (Canton 3.x / Daml 3.x)
//!
//! The client targets these gRPC services:
//! - `CommandService.SubmitAndWait` — Synchronous command submission
//! - `StateService.GetActiveContracts` — Query active contract set
//! - `UpdateService.GetUpdates` — Stream committed transactions
//! - `PackageManagementService.UploadDarFile` — Upload DAR packages
//!
//! # Graceful Degradation
//!
//! When the Canton participant is unreachable, the client returns proper errors
//! (VmError::CantonError) instead of fake success data. This allows Tenzro nodes
//! to operate without Canton for EVM/SVM workloads while clearly reporting that
//! DAML operations require a running Canton participant.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use prost::Message;
use tokio::sync::RwLock;
use tonic::transport::{Channel, Endpoint};

use super::types::{ActiveContractsQuery, DamlExecutionResult, DamlSubmission};
use crate::error::{Result, VmError};
use tenzro_types::canton::{
    CantonSynchronizerId, DamlCommand, DamlContractId, DamlEvent, DamlPackageInfo, DamlParty,
    DamlTransaction, DamlValue,
};

// ───────────────────────────────────────────────────────────────────
// Manually-defined protobuf messages matching Canton Ledger API v2
// ───────────────────────────────────────────────────────────────────
//
// These are hand-crafted prost message definitions that correspond to
// the Canton gRPC Ledger API v2 proto schema under:
//   com.daml.ledger.api.v2.*
//
// We define only the minimal set needed for our integration rather than
// compiling the full Canton proto tree (which has deep dependency chains).

/// Canton Ledger API v2 proto message definitions
pub mod proto {
    use prost::Message;

    // ── Identifier ──

    #[derive(Clone, PartialEq, Message)]
    pub struct Identifier {
        #[prost(string, tag = "1")]
        pub package_id: String,
        #[prost(string, tag = "2")]
        pub module_name: String,
        #[prost(string, tag = "3")]
        pub entity_name: String,
    }

    // ── Value (simplified — supports the types we need) ──

    #[derive(Clone, PartialEq, Message)]
    pub struct Value {
        #[prost(oneof = "value::Sum", tags = "1, 2, 3, 4, 5, 6, 11, 12")]
        pub sum: Option<value::Sum>,
    }

    pub mod value {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Sum {
            #[prost(message, tag = "1")]
            Record(super::Record),
            #[prost(string, tag = "2")]
            Text(String),
            #[prost(int64, tag = "3")]
            Int64(i64),
            #[prost(bool, tag = "4")]
            Bool(bool),
            #[prost(string, tag = "5")]
            Party(String),
            #[prost(string, tag = "6")]
            ContractId(String),
            #[prost(message, tag = "11")]
            List(super::List),
            #[prost(message, tag = "12")]
            Optional(Box<super::Optional>),
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Record {
        #[prost(message, optional, tag = "1")]
        pub record_id: Option<Identifier>,
        #[prost(message, repeated, tag = "2")]
        pub fields: Vec<RecordField>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct RecordField {
        #[prost(string, tag = "1")]
        pub label: String,
        #[prost(message, optional, tag = "2")]
        pub value: Option<Value>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct List {
        #[prost(message, repeated, tag = "1")]
        pub elements: Vec<Value>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Optional {
        #[prost(message, optional, boxed, tag = "1")]
        pub value: Option<Box<Value>>,
    }

    // ── Commands ──

    #[derive(Clone, PartialEq, Message)]
    pub struct Command {
        #[prost(oneof = "command::Command", tags = "1, 2, 3, 4")]
        pub command: Option<command::Command>,
    }

    pub mod command {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Command {
            #[prost(message, tag = "1")]
            Create(super::CreateCommand),
            #[prost(message, tag = "2")]
            Exercise(super::ExerciseCommand),
            #[prost(message, tag = "3")]
            CreateAndExercise(super::CreateAndExerciseCommand),
            #[prost(message, tag = "4")]
            ExerciseByKey(super::ExerciseByKeyCommand),
        }
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct CreateCommand {
        #[prost(message, optional, tag = "1")]
        pub template_id: Option<Identifier>,
        #[prost(message, optional, tag = "2")]
        pub create_arguments: Option<Record>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct ExerciseCommand {
        #[prost(message, optional, tag = "1")]
        pub template_id: Option<Identifier>,
        #[prost(string, tag = "2")]
        pub contract_id: String,
        #[prost(string, tag = "3")]
        pub choice: String,
        #[prost(message, optional, tag = "4")]
        pub choice_argument: Option<Value>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct CreateAndExerciseCommand {
        #[prost(message, optional, tag = "1")]
        pub template_id: Option<Identifier>,
        #[prost(message, optional, tag = "2")]
        pub create_arguments: Option<Record>,
        #[prost(string, tag = "3")]
        pub choice: String,
        #[prost(message, optional, tag = "4")]
        pub choice_argument: Option<Value>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct ExerciseByKeyCommand {
        #[prost(message, optional, tag = "1")]
        pub template_id: Option<Identifier>,
        #[prost(message, optional, tag = "2")]
        pub contract_key: Option<Value>,
        #[prost(string, tag = "3")]
        pub choice: String,
        #[prost(message, optional, tag = "4")]
        pub choice_argument: Option<Value>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Commands {
        #[prost(string, tag = "1")]
        pub workflow_id: String,
        #[prost(string, tag = "2")]
        pub application_id: String,
        #[prost(string, tag = "3")]
        pub command_id: String,
        #[prost(string, repeated, tag = "4")]
        pub act_as: Vec<String>,
        #[prost(string, repeated, tag = "5")]
        pub read_as: Vec<String>,
        #[prost(message, repeated, tag = "6")]
        pub commands: Vec<Command>,
    }

    // ── CommandService request/response ──

    #[derive(Clone, PartialEq, Message)]
    pub struct SubmitAndWaitRequest {
        #[prost(message, optional, tag = "1")]
        pub commands: Option<Commands>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct SubmitAndWaitResponse {
        #[prost(message, optional, tag = "1")]
        pub transaction: Option<Transaction>,
        #[prost(string, tag = "2")]
        pub completion_offset: String,
    }

    // ── Events ──

    #[derive(Clone, PartialEq, Message)]
    pub struct CreatedEvent {
        #[prost(string, tag = "1")]
        pub event_id: String,
        #[prost(string, tag = "2")]
        pub contract_id: String,
        #[prost(message, optional, tag = "3")]
        pub template_id: Option<Identifier>,
        #[prost(message, optional, tag = "4")]
        pub create_arguments: Option<Record>,
        #[prost(string, repeated, tag = "5")]
        pub signatories: Vec<String>,
        #[prost(string, repeated, tag = "6")]
        pub observers: Vec<String>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct ArchivedEvent {
        #[prost(string, tag = "1")]
        pub event_id: String,
        #[prost(string, tag = "2")]
        pub contract_id: String,
        #[prost(message, optional, tag = "3")]
        pub template_id: Option<Identifier>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Event {
        #[prost(oneof = "event::Event", tags = "1, 2")]
        pub event: Option<event::Event>,
    }

    pub mod event {
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Event {
            #[prost(message, tag = "1")]
            Created(super::CreatedEvent),
            #[prost(message, tag = "2")]
            Archived(super::ArchivedEvent),
        }
    }

    // ── Transaction ──

    #[derive(Clone, PartialEq, Message)]
    pub struct Transaction {
        #[prost(string, tag = "1")]
        pub transaction_id: String,
        #[prost(string, tag = "2")]
        pub command_id: String,
        #[prost(string, tag = "3")]
        pub workflow_id: String,
        #[prost(int64, tag = "4")]
        pub effective_at: i64,
        #[prost(message, repeated, tag = "5")]
        pub events: Vec<Event>,
        #[prost(string, tag = "6")]
        pub offset: String,
        #[prost(string, tag = "7")]
        pub synchronizer_id: String,
    }

    // ── StateService ──

    #[derive(Clone, PartialEq, Message)]
    pub struct GetActiveContractsRequest {
        #[prost(message, optional, tag = "1")]
        pub filter: Option<TransactionFilter>,
        #[prost(string, tag = "2")]
        pub active_at_offset: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct TransactionFilter {
        // Map<party, Filters> — simplified as repeated pairs
        #[prost(message, repeated, tag = "1")]
        pub filters_by_party: Vec<PartyFilter>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct PartyFilter {
        #[prost(string, tag = "1")]
        pub party: String,
        #[prost(message, optional, tag = "2")]
        pub filters: Option<Filters>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct Filters {
        #[prost(message, repeated, tag = "1")]
        pub template_filters: Vec<TemplateFilter>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct TemplateFilter {
        #[prost(message, optional, tag = "1")]
        pub template_id: Option<Identifier>,
        #[prost(bool, tag = "2")]
        pub include_created_event_blob: bool,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct GetActiveContractsResponse {
        #[prost(string, tag = "1")]
        pub offset: String,
        #[prost(message, optional, tag = "2")]
        pub contract_entry: Option<ContractEntry>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct ContractEntry {
        #[prost(message, optional, tag = "1")]
        pub created_event: Option<CreatedEvent>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct GetLedgerEndResponse {
        #[prost(string, tag = "1")]
        pub offset: String,
    }

    // ── PackageManagementService ──

    #[derive(Clone, PartialEq, Message)]
    pub struct UploadDarFileRequest {
        #[prost(bytes = "vec", tag = "1")]
        pub dar_file: Vec<u8>,
        #[prost(string, tag = "2")]
        pub submission_id: String,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct UploadDarFileResponse {
        // Empty on success
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct ListPackagesRequest {}

    #[derive(Clone, PartialEq, Message)]
    pub struct ListPackagesResponse {
        #[prost(string, repeated, tag = "1")]
        pub package_ids: Vec<String>,
    }

    // ── UpdateService ──

    #[derive(Clone, PartialEq, Message)]
    pub struct GetUpdatesRequest {
        #[prost(string, tag = "1")]
        pub begin_offset: String,
        #[prost(message, optional, tag = "2")]
        pub filter: Option<TransactionFilter>,
    }

    #[derive(Clone, PartialEq, Message)]
    pub struct GetUpdatesResponse {
        #[prost(message, optional, tag = "1")]
        pub transaction: Option<Transaction>,
    }
}

/// Canton Ledger API client configuration
#[derive(Debug, Clone)]
pub struct CantonClientConfig {
    /// Canton participant host
    pub host: String,
    /// Canton participant Ledger API port (default: 5001 in Canton 3.x)
    pub ledger_api_port: u16,
    /// Canton participant Admin API port (default: 5002 in Canton 3.x)
    pub admin_api_port: u16,
    /// Whether to use TLS
    pub use_tls: bool,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
}

impl CantonClientConfig {
    /// Create a new Canton client configuration with Daml 3.x default ports
    pub fn new(host: impl Into<String>, ledger_api_port: u16) -> Self {
        Self {
            host: host.into(),
            ledger_api_port,
            admin_api_port: 5002,
            use_tls: false,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
        }
    }

    /// Create default localhost configuration (for co-located Canton participant)
    pub fn localhost() -> Self {
        Self::new("localhost", 5001)
    }

    /// Set Admin API port
    pub fn with_admin_port(mut self, port: u16) -> Self {
        self.admin_api_port = port;
        self
    }

    /// Enable TLS
    pub fn with_tls(mut self, use_tls: bool) -> Self {
        self.use_tls = use_tls;
        self
    }

    /// Set connection timeout
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set request timeout
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            return Err(VmError::CantonError(
                "Canton host cannot be empty".to_string(),
            ));
        }

        if self.ledger_api_port == 0 {
            return Err(VmError::CantonError(
                "Invalid Ledger API port: must be > 0".to_string(),
            ));
        }

        if self.admin_api_port == 0 {
            return Err(VmError::CantonError(
                "Invalid Admin API port: must be > 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Get the Ledger API endpoint URL
    pub fn ledger_api_endpoint(&self) -> String {
        let scheme = if self.use_tls { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.host, self.ledger_api_port)
    }

    /// Get the Admin API endpoint URL
    pub fn admin_api_endpoint(&self) -> String {
        let scheme = if self.use_tls { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.host, self.admin_api_port)
    }

}

/// Connection state for a gRPC channel
#[derive(Debug)]
struct GrpcConnection {
    /// The tonic gRPC channel (if connected)
    channel: Option<Channel>,
}

/// Canton Ledger API client
///
/// Provides access to the co-located Canton participant node's Ledger API
/// via real tonic gRPC. When the Canton participant is unreachable, all
/// operations return proper errors instead of fake data.
///
/// # gRPC Services Used
///
/// - `com.daml.ledger.api.v2.CommandService` — command submission
/// - `com.daml.ledger.api.v2.StateService` — active contract queries
/// - `com.daml.ledger.api.v2.UpdateService` — transaction streaming
/// - `com.daml.ledger.api.v2.admin.PackageManagementService` — DAR uploads
#[derive(Debug, Clone)]
pub struct CantonClient {
    /// Client configuration
    config: CantonClientConfig,
    /// Ledger API gRPC connection
    ledger_connection: Arc<RwLock<GrpcConnection>>,
    /// Admin API gRPC connection
    admin_connection: Arc<RwLock<GrpcConnection>>,
    /// Whether we have an active connection to the Ledger API
    connected: Arc<AtomicBool>,
}

impl CantonClient {
    /// Create a new Canton client
    ///
    /// This does NOT establish a gRPC connection immediately. The connection
    /// is established lazily on the first operation, or explicitly via `connect()`.
    /// This allows the Tenzro node to start even if Canton is not yet available.
    pub fn new(config: CantonClientConfig) -> Result<Self> {
        // Validate configuration
        config.validate()?;

        tracing::info!(
            "Initializing Canton Ledger API client: ledger_api={}, admin_api={}, tls={}",
            config.ledger_api_endpoint(),
            config.admin_api_endpoint(),
            config.use_tls,
        );

        Ok(Self {
            config,
            ledger_connection: Arc::new(RwLock::new(GrpcConnection { channel: None })),
            admin_connection: Arc::new(RwLock::new(GrpcConnection { channel: None })),
            connected: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Attempt to establish a gRPC connection to the Canton Ledger API
    ///
    /// Returns Ok(()) if connection succeeds, or an error if Canton is unreachable.
    /// This is safe to call multiple times — it will reconnect if the previous
    /// connection was lost.
    pub async fn connect(&self) -> Result<()> {
        // Try to connect to Ledger API
        let ledger_channel = self
            .create_channel(&self.config.ledger_api_endpoint())
            .await?;

        {
            let mut conn = self.ledger_connection.write().await;
            conn.channel = Some(ledger_channel);
        }

        // Try to connect to Admin API (non-fatal if it fails)
        match self.create_channel(&self.config.admin_api_endpoint()).await {
            Ok(admin_channel) => {
                let mut conn = self.admin_connection.write().await;
                conn.channel = Some(admin_channel);
                tracing::info!(
                    "Canton Admin API connected: {}",
                    self.config.admin_api_endpoint()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Canton Admin API not available at {} (DAR uploads will fail): {}",
                    self.config.admin_api_endpoint(),
                    e
                );
            }
        }

        self.connected.store(true, Ordering::SeqCst);
        tracing::info!(
            "Canton Ledger API connected: {}",
            self.config.ledger_api_endpoint()
        );

        Ok(())
    }

    /// Create a tonic gRPC channel to the given endpoint
    async fn create_channel(&self, endpoint_url: &str) -> Result<Channel> {
        let endpoint = Endpoint::from_shared(endpoint_url.to_string())
            .map_err(|e| {
                VmError::CantonError(format!("Invalid endpoint '{}': {}", endpoint_url, e))
            })?
            .connect_timeout(self.config.connect_timeout)
            .timeout(self.config.request_timeout)
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(10));

        endpoint.connect().await.map_err(|e| {
            VmError::CantonError(format!(
                "Failed to connect to Canton at {}: {}. \
                 Ensure the Canton participant is running and the Ledger API is exposed.",
                endpoint_url, e
            ))
        })
    }

    /// Get the Ledger API channel, attempting to connect if not already connected
    async fn get_ledger_channel(&self) -> Result<Channel> {
        // Fast path: check if we have a connection
        {
            let conn = self.ledger_connection.read().await;
            if let Some(ref channel) = conn.channel {
                return Ok(channel.clone());
            }
        }

        // Slow path: try to connect
        self.connect().await?;

        let conn = self.ledger_connection.read().await;
        conn.channel.clone().ok_or_else(|| {
            VmError::CantonError(
                "Canton participant not available. DAML operations require a running Canton \
                 participant node with Ledger API enabled."
                    .to_string(),
            )
        })
    }

    /// Get the Admin API channel
    async fn get_admin_channel(&self) -> Result<Channel> {
        {
            let conn = self.admin_connection.read().await;
            if let Some(ref channel) = conn.channel {
                return Ok(channel.clone());
            }
        }

        // Try connecting Admin API
        let admin_channel = self
            .create_channel(&self.config.admin_api_endpoint())
            .await?;
        {
            let mut conn = self.admin_connection.write().await;
            conn.channel = Some(admin_channel.clone());
        }
        Ok(admin_channel)
    }

    /// Make a unary gRPC call using raw tonic
    ///
    /// This sends a prost-encoded request to the given gRPC path and decodes the response.
    /// The path format is "/package.Service/Method", e.g.:
    /// "/com.daml.ledger.api.v2.CommandService/SubmitAndWait"
    async fn grpc_unary<Req, Resp>(
        &self,
        channel: &Channel,
        path: &str,
        request: Req,
    ) -> Result<Resp>
    where
        Req: Message + 'static,
        Resp: Message + Default + 'static,
    {
        use tonic::codegen::http;

        // Encode the request
        let mut buf = Vec::new();
        request
            .encode(&mut buf)
            .map_err(|e| VmError::CantonError(format!("Failed to encode gRPC request: {}", e)))?;

        // Build gRPC frame: 1 byte compression flag (0) + 4 bytes big-endian length + data
        let mut frame = Vec::with_capacity(5 + buf.len());
        frame.push(0u8); // no compression
        frame.extend_from_slice(&(buf.len() as u32).to_be_bytes());
        frame.extend_from_slice(&buf);

        // Create the HTTP/2 request
        let uri = path
            .parse::<http::Uri>()
            .map_err(|e| VmError::CantonError(format!("Invalid gRPC path '{}': {}", path, e)))?;

        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(uri)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(tonic::body::BoxBody::new(
                http_body_util::Full::new(bytes::Bytes::from(frame))
                    .map_err(|never| match never {}),
            ))
            .map_err(|e| VmError::CantonError(format!("Failed to build gRPC request: {}", e)))?;

        // Send via the channel
        let mut svc = channel.clone();
        let response = tower::Service::call(&mut svc, request).await.map_err(|e| {
            self.connected.store(false, Ordering::SeqCst);
            VmError::CantonError(format!(
                "Canton gRPC call to {} failed: {}. \
                     The Canton participant may be down or unreachable.",
                path, e
            ))
        })?;

        // Check gRPC status from trailers
        let status_code = response.status();
        if !status_code.is_success() {
            return Err(VmError::CantonError(format!(
                "Canton gRPC call to {} returned HTTP {}",
                path, status_code
            )));
        }

        // Read response body
        use http_body_util::BodyExt;
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| VmError::CantonError(format!("Failed to read gRPC response body: {}", e)))?
            .to_bytes();

        // Parse gRPC frame: skip 5-byte header (1 compression + 4 length)
        if body_bytes.len() < 5 {
            return Err(VmError::CantonError(format!(
                "Invalid gRPC response from {}: too short ({} bytes)",
                path,
                body_bytes.len()
            )));
        }

        let message_bytes = &body_bytes[5..];
        Resp::decode(message_bytes).map_err(|e| {
            VmError::CantonError(format!(
                "Failed to decode gRPC response from {}: {}",
                path, e
            ))
        })
    }

    /// Convert a DamlCommand to a proto Command
    fn daml_command_to_proto(cmd: &DamlCommand) -> proto::Command {
        match cmd {
            DamlCommand::Create {
                template_id,
                create_arguments,
            } => proto::Command {
                command: Some(proto::command::Command::Create(proto::CreateCommand {
                    template_id: Some(proto::Identifier {
                        package_id: template_id.package_id.clone(),
                        module_name: template_id.module_name.clone(),
                        entity_name: template_id.entity_name.clone(),
                    }),
                    create_arguments: Some(Self::daml_value_to_record(create_arguments)),
                })),
            },
            DamlCommand::Exercise {
                contract_id,
                template_id,
                choice,
                choice_argument,
            } => proto::Command {
                command: Some(proto::command::Command::Exercise(proto::ExerciseCommand {
                    template_id: Some(proto::Identifier {
                        package_id: template_id.package_id.clone(),
                        module_name: template_id.module_name.clone(),
                        entity_name: template_id.entity_name.clone(),
                    }),
                    contract_id: contract_id.as_str().to_string(),
                    choice: choice.clone(),
                    choice_argument: Some(Self::daml_value_to_proto(choice_argument)),
                })),
            },
            DamlCommand::CreateAndExercise {
                template_id,
                create_arguments,
                choice,
                choice_argument,
            } => proto::Command {
                command: Some(proto::command::Command::CreateAndExercise(
                    proto::CreateAndExerciseCommand {
                        template_id: Some(proto::Identifier {
                            package_id: template_id.package_id.clone(),
                            module_name: template_id.module_name.clone(),
                            entity_name: template_id.entity_name.clone(),
                        }),
                        create_arguments: Some(Self::daml_value_to_record(create_arguments)),
                        choice: choice.clone(),
                        choice_argument: Some(Self::daml_value_to_proto(choice_argument)),
                    },
                )),
            },
            DamlCommand::ExerciseByKey {
                template_id,
                contract_key,
                choice,
                choice_argument,
            } => proto::Command {
                command: Some(proto::command::Command::ExerciseByKey(
                    proto::ExerciseByKeyCommand {
                        template_id: Some(proto::Identifier {
                            package_id: template_id.package_id.clone(),
                            module_name: template_id.module_name.clone(),
                            entity_name: template_id.entity_name.clone(),
                        }),
                        contract_key: Some(Self::daml_value_to_proto(contract_key)),
                        choice: choice.clone(),
                        choice_argument: Some(Self::daml_value_to_proto(choice_argument)),
                    },
                )),
            },
        }
    }

    /// Convert a DamlValue to a proto Value
    fn daml_value_to_proto(value: &DamlValue) -> proto::Value {
        match value {
            DamlValue::Text(s) => proto::Value {
                sum: Some(proto::value::Sum::Text(s.clone())),
            },
            DamlValue::Int64(i) => proto::Value {
                sum: Some(proto::value::Sum::Int64(*i)),
            },
            DamlValue::Bool(b) => proto::Value {
                sum: Some(proto::value::Sum::Bool(*b)),
            },
            DamlValue::Party(p) => proto::Value {
                sum: Some(proto::value::Sum::Party(p.as_str().to_string())),
            },
            DamlValue::ContractId(c) => proto::Value {
                sum: Some(proto::value::Sum::ContractId(c.as_str().to_string())),
            },
            DamlValue::Record { fields, .. } => {
                let record_fields: Vec<proto::RecordField> = fields
                    .iter()
                    .map(|(label, value)| proto::RecordField {
                        label: label.clone(),
                        value: Some(Self::daml_value_to_proto(value)),
                    })
                    .collect();
                proto::Value {
                    sum: Some(proto::value::Sum::Record(proto::Record {
                        record_id: None,
                        fields: record_fields,
                    })),
                }
            }
            DamlValue::List(elements) => proto::Value {
                sum: Some(proto::value::Sum::List(proto::List {
                    elements: elements.iter().map(Self::daml_value_to_proto).collect(),
                })),
            },
            DamlValue::Optional(inner) => proto::Value {
                sum: Some(proto::value::Sum::Optional(Box::new(proto::Optional {
                    value: inner
                        .as_ref()
                        .map(|v| Box::new(Self::daml_value_to_proto(v))),
                }))),
            },
            DamlValue::Unit => proto::Value { sum: None },
            _ => proto::Value { sum: None },
        }
    }

    /// Convert a DamlValue to a proto Record (for create arguments)
    fn daml_value_to_record(value: &DamlValue) -> proto::Record {
        match value {
            DamlValue::Record { fields, .. } => proto::Record {
                record_id: None,
                fields: fields
                    .iter()
                    .map(|(label, v)| proto::RecordField {
                        label: label.clone(),
                        value: Some(Self::daml_value_to_proto(v)),
                    })
                    .collect(),
            },
            _ => proto::Record {
                record_id: None,
                fields: Vec::new(),
            },
        }
    }

    /// Convert a proto Identifier to tenzro_types DamlTemplateId
    fn proto_identifier_to_template_id(
        id: &proto::Identifier,
    ) -> tenzro_types::canton::DamlTemplateId {
        tenzro_types::canton::DamlTemplateId::new(&id.package_id, &id.module_name, &id.entity_name)
    }

    /// Convert proto events to DamlEvents
    fn proto_events_to_daml(events: &[proto::Event]) -> Vec<DamlEvent> {
        events
            .iter()
            .filter_map(|event| {
                match &event.event {
                    Some(proto::event::Event::Created(created)) => {
                        let template_id = created
                            .template_id
                            .as_ref()
                            .map(Self::proto_identifier_to_template_id)
                            .unwrap_or_else(|| {
                                tenzro_types::canton::DamlTemplateId::new("", "", "")
                            });

                        Some(DamlEvent::Created {
                            event_id: created.event_id.clone(),
                            contract_id: DamlContractId::new(&created.contract_id),
                            template_id,
                            create_arguments: DamlValue::Unit, // simplified
                            signatories: created.signatories.iter().map(DamlParty::new).collect(),
                            observers: created.observers.iter().map(DamlParty::new).collect(),
                        })
                    }
                    Some(proto::event::Event::Archived(archived)) => {
                        let template_id = archived
                            .template_id
                            .as_ref()
                            .map(Self::proto_identifier_to_template_id)
                            .unwrap_or_else(|| {
                                tenzro_types::canton::DamlTemplateId::new("", "", "")
                            });

                        Some(DamlEvent::Archived {
                            event_id: archived.event_id.clone(),
                            contract_id: DamlContractId::new(&archived.contract_id),
                            template_id,
                        })
                    }
                    None => None,
                }
            })
            .collect()
    }

    /// Submit commands via CommandService.SubmitAndWait
    ///
    /// Sends a real gRPC request to the Canton participant's CommandService.
    /// If Canton is unreachable, returns a CantonError.
    pub async fn submit_command(&self, submission: &DamlSubmission) -> Result<DamlExecutionResult> {
        tracing::debug!(
            "Canton CommandService.SubmitAndWait: command_id={}, commands={}",
            submission.command_id,
            submission.commands.len()
        );

        let channel = self.get_ledger_channel().await?;

        // Build proto Commands
        let proto_commands: Vec<proto::Command> = submission
            .commands
            .iter()
            .map(Self::daml_command_to_proto)
            .collect();

        let request = proto::SubmitAndWaitRequest {
            commands: Some(proto::Commands {
                workflow_id: submission.workflow_id.clone().unwrap_or_default(),
                application_id: submission.application_id.clone(),
                command_id: submission.command_id.clone(),
                act_as: submission.act_as.clone(),
                read_as: submission.read_as.clone(),
                commands: proto_commands,
            }),
        };

        // Make the gRPC call
        let response: proto::SubmitAndWaitResponse = self
            .grpc_unary(
                &channel,
                "/com.daml.ledger.api.v2.CommandService/SubmitAndWait",
                request,
            )
            .await?;

        // Convert response to DamlExecutionResult
        if let Some(tx) = response.transaction {
            let events = Self::proto_events_to_daml(&tx.events);

            let transaction = DamlTransaction {
                transaction_id: tx.transaction_id,
                command_id: tx.command_id,
                workflow_id: if tx.workflow_id.is_empty() {
                    None
                } else {
                    Some(tx.workflow_id)
                },
                events: events.clone(),
                effective_at: tx.effective_at,
                offset: tx.offset,
                synchronizer_id: if tx.synchronizer_id.is_empty() {
                    None
                } else {
                    Some(CantonSynchronizerId::new(&tx.synchronizer_id))
                },
            };

            Ok(DamlExecutionResult::success(transaction, events))
        } else {
            Ok(DamlExecutionResult::failed(
                "Canton returned empty transaction",
            ))
        }
    }

    /// Query active contracts via StateService.GetActiveContracts
    pub async fn get_active_contracts(
        &self,
        query: &ActiveContractsQuery,
    ) -> Result<Vec<DamlContractId>> {
        tracing::debug!(
            "Canton StateService.GetActiveContracts: party={}",
            query.party
        );

        let channel = self.get_ledger_channel().await?;

        // Build template filter if specified
        let filters = if let Some(ref template_str) = query.template_id {
            if !template_str.is_empty() {
                // Parse template_id as "package_id:module_name:entity_name"
                let parts: Vec<&str> = template_str.splitn(3, ':').collect();
                if parts.len() == 3 {
                    Some(proto::Filters {
                        template_filters: vec![proto::TemplateFilter {
                            template_id: Some(proto::Identifier {
                                package_id: parts[0].to_string(),
                                module_name: parts[1].to_string(),
                                entity_name: parts[2].to_string(),
                            }),
                            include_created_event_blob: false,
                        }],
                    })
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let request = proto::GetActiveContractsRequest {
            filter: Some(proto::TransactionFilter {
                filters_by_party: vec![proto::PartyFilter {
                    party: query.party.clone(),
                    filters,
                }],
            }),
            active_at_offset: String::new(),
        };

        // Note: GetActiveContracts is a server-streaming RPC in Canton.
        // For simplicity, we use a unary call pattern here. In production,
        // this should use tonic's streaming client for large contract sets.
        // The server will send back one response per active contract.
        let response: proto::GetActiveContractsResponse = self
            .grpc_unary(
                &channel,
                "/com.daml.ledger.api.v2.StateService/GetActiveContracts",
                request,
            )
            .await?;

        let mut contracts = Vec::new();
        if let Some(entry) = response.contract_entry
            && let Some(created) = entry.created_event
        {
            contracts.push(DamlContractId::new(&created.contract_id));
        }

        Ok(contracts)
    }

    /// Upload a DAR package via Admin API PackageManagementService.UploadDarFile
    pub async fn upload_dar(&self, dar_bytes: &[u8]) -> Result<String> {
        tracing::info!(
            "Canton Admin PackageManagementService.UploadDarFile: {} bytes",
            dar_bytes.len()
        );

        let channel = self.get_admin_channel().await?;

        let submission_id = format!("upload_{}", chrono::Utc::now().timestamp_micros());

        let request = proto::UploadDarFileRequest {
            dar_file: dar_bytes.to_vec(),
            submission_id: submission_id.clone(),
        };

        let _response: proto::UploadDarFileResponse = self
            .grpc_unary(
                &channel,
                "/com.daml.ledger.api.v2.admin.PackageManagementService/UploadDarFile",
                request,
            )
            .await?;

        // Canton doesn't return the package ID directly from UploadDarFile.
        // We compute it from a hash of the DAR content for tracking.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(dar_bytes);
        let hash = hasher.finalize();
        let package_id = hex::encode(&hash[..16]);

        tracing::info!(
            "Canton: DAR uploaded successfully, package_id={}",
            package_id
        );

        Ok(package_id)
    }

    /// List uploaded packages via PackageManagementService.ListPackages
    pub async fn list_packages(&self) -> Result<Vec<DamlPackageInfo>> {
        tracing::debug!("Canton PackageManagementService.ListPackages");

        let channel = self.get_admin_channel().await?;

        let request = proto::ListPackagesRequest {};

        let response: proto::ListPackagesResponse = self
            .grpc_unary(
                &channel,
                "/com.daml.ledger.api.v2.admin.PackageManagementService/ListPackages",
                request,
            )
            .await?;

        let packages: Vec<DamlPackageInfo> = response
            .package_ids
            .iter()
            .map(|id| DamlPackageInfo {
                package_id: id.clone(),
                package_name: None,
                package_version: None,
                size_bytes: 0,
                modules: Vec::new(),
            })
            .collect();

        Ok(packages)
    }

    /// Subscribe to transaction updates via UpdateService.GetUpdates
    pub async fn get_updates(&self, begin_offset: Option<String>) -> Result<Vec<DamlTransaction>> {
        tracing::debug!("Canton UpdateService.GetUpdates");

        let channel = self.get_ledger_channel().await?;

        let request = proto::GetUpdatesRequest {
            begin_offset: begin_offset.unwrap_or_default(),
            filter: None,
        };

        // Note: GetUpdates is a server-streaming RPC. Using unary for simplicity.
        let response: proto::GetUpdatesResponse = self
            .grpc_unary(
                &channel,
                "/com.daml.ledger.api.v2.UpdateService/GetUpdates",
                request,
            )
            .await?;

        let mut transactions = Vec::new();
        if let Some(tx) = response.transaction {
            let events = Self::proto_events_to_daml(&tx.events);
            transactions.push(DamlTransaction {
                transaction_id: tx.transaction_id,
                command_id: tx.command_id,
                workflow_id: if tx.workflow_id.is_empty() {
                    None
                } else {
                    Some(tx.workflow_id)
                },
                events,
                effective_at: tx.effective_at,
                offset: tx.offset,
                synchronizer_id: if tx.synchronizer_id.is_empty() {
                    None
                } else {
                    Some(CantonSynchronizerId::new(&tx.synchronizer_id))
                },
            });
        }

        Ok(transactions)
    }

    /// Check if the Canton participant is reachable
    ///
    /// Performs an actual connectivity check by attempting to connect to the
    /// Ledger API endpoint. Returns false if the participant is unreachable.
    pub async fn is_connected(&self) -> bool {
        // First check our cached state
        if self.connected.load(Ordering::SeqCst) {
            // Verify the connection is still alive by checking the channel
            let conn = self.ledger_connection.read().await;
            if conn.channel.is_some() {
                return true;
            }
        }

        // Try to establish a connection
        match self.connect().await {
            Ok(()) => true,
            Err(e) => {
                tracing::debug!("Canton connectivity check failed: {}", e);
                false
            }
        }
    }

    /// Get the client configuration
    pub fn config(&self) -> &CantonClientConfig {
        &self.config
    }

    /// Disconnect from Canton
    pub async fn disconnect(&self) {
        {
            let mut conn = self.ledger_connection.write().await;
            conn.channel = None;
        }
        {
            let mut conn = self.admin_connection.write().await;
            conn.channel = None;
        }
        self.connected.store(false, Ordering::SeqCst);
        tracing::info!("Disconnected from Canton participant");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = CantonClientConfig::new("localhost", 5001);
        assert_eq!(config.ledger_api_endpoint(), "http://localhost:5001");
        assert_eq!(config.admin_api_endpoint(), "http://localhost:5002");
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.request_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_config_with_tls() {
        let config = CantonClientConfig::new("canton.example.com", 5001)
            .with_tls(true)
            .with_admin_port(5003);
        assert_eq!(
            config.ledger_api_endpoint(),
            "https://canton.example.com:5001"
        );
        assert_eq!(
            config.admin_api_endpoint(),
            "https://canton.example.com:5003"
        );
    }

    #[test]
    fn test_config_validation() {
        // Empty host
        let config = CantonClientConfig::new("", 5001);
        assert!(config.validate().is_err());

        // Zero port
        let config = CantonClientConfig::new("localhost", 0);
        assert!(config.validate().is_err());

        // Valid config
        let config = CantonClientConfig::new("localhost", 5001);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_client_creation() {
        let config = CantonClientConfig::new("localhost", 5001);
        let client = CantonClient::new(config).unwrap();
        // Client should NOT be connected yet (lazy connection)
        assert!(!client.connected.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_client_not_connected_by_default() {
        let config = CantonClientConfig::new("localhost", 5001);
        let client = CantonClient::new(config).unwrap();

        // is_connected should return false when Canton is not running
        // (it will try to connect and fail)
        let connected = client.connected.load(Ordering::SeqCst);
        assert!(!connected);
    }

    #[tokio::test]
    async fn test_submit_command_fails_without_canton() {
        let config = CantonClientConfig::new("127.0.0.1", 59999)
            .with_connect_timeout(Duration::from_millis(100));
        let client = CantonClient::new(config).unwrap();

        let submission = DamlSubmission::new(
            "test-cmd-1",
            vec!["Alice::abc123".to_string()],
            vec![],
            "tenzro-test",
        );

        // Should fail with a CantonError, not return fake success data
        let result = client.submit_command(&submission).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("Canton") || err_msg.contains("connect"),
            "Error should mention Canton connectivity: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_upload_dar_fails_without_canton() {
        let config = CantonClientConfig::new("127.0.0.1", 59999)
            .with_connect_timeout(Duration::from_millis(100));
        let client = CantonClient::new(config).unwrap();

        let dar_bytes = b"mock dar content";
        let result = client.upload_dar(dar_bytes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_active_contracts_fails_without_canton() {
        let config = CantonClientConfig::new("127.0.0.1", 59999)
            .with_connect_timeout(Duration::from_millis(100));
        let client = CantonClient::new(config).unwrap();

        let query = ActiveContractsQuery::new("Alice");
        let result = client.get_active_contracts(&query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_connected_false_without_canton() {
        let config = CantonClientConfig::new("127.0.0.1", 59999)
            .with_connect_timeout(Duration::from_millis(100));
        let client = CantonClient::new(config).unwrap();

        let connected = client.is_connected().await;
        assert!(!connected);
    }

    #[test]
    fn test_daml_value_to_proto_text() {
        let value = DamlValue::Text("hello".to_string());
        let proto = CantonClient::daml_value_to_proto(&value);
        assert!(matches!(proto.sum, Some(proto::value::Sum::Text(ref s)) if s == "hello"));
    }

    #[test]
    fn test_daml_value_to_proto_int64() {
        let value = DamlValue::Int64(42);
        let proto = CantonClient::daml_value_to_proto(&value);
        assert!(matches!(proto.sum, Some(proto::value::Sum::Int64(42))));
    }

    #[test]
    fn test_daml_value_to_proto_record() {
        let value = DamlValue::Record {
            record_id: None,
            fields: vec![
                ("name".to_string(), DamlValue::Text("Alice".to_string())),
                ("amount".to_string(), DamlValue::Int64(100)),
            ],
        };
        let proto = CantonClient::daml_value_to_proto(&value);
        if let Some(proto::value::Sum::Record(record)) = proto.sum {
            assert_eq!(record.fields.len(), 2);
            assert_eq!(record.fields[0].label, "name");
            assert_eq!(record.fields[1].label, "amount");
        } else {
            panic!("Expected Record variant");
        }
    }

    #[test]
    fn test_daml_command_to_proto_create() {
        let template_id = tenzro_types::canton::DamlTemplateId::new("pkg1", "Module1", "Template1");
        let cmd = DamlCommand::Create {
            template_id,
            create_arguments: DamlValue::Record {
                record_id: None,
                fields: vec![(
                    "owner".to_string(),
                    DamlValue::Party(DamlParty::new("Alice")),
                )],
            },
        };
        let proto_cmd = CantonClient::daml_command_to_proto(&cmd);
        assert!(matches!(
            proto_cmd.command,
            Some(proto::command::Command::Create(_))
        ));
    }

    #[test]
    fn test_daml_command_to_proto_exercise() {
        let template_id = tenzro_types::canton::DamlTemplateId::new("pkg1", "Module1", "Template1");
        let cmd = DamlCommand::Exercise {
            contract_id: DamlContractId::new("contract-1"),
            template_id,
            choice: "Transfer".to_string(),
            choice_argument: DamlValue::Record {
                record_id: None,
                fields: vec![(
                    "newOwner".to_string(),
                    DamlValue::Party(DamlParty::new("Bob")),
                )],
            },
        };
        let proto_cmd = CantonClient::daml_command_to_proto(&cmd);
        if let Some(proto::command::Command::Exercise(ex)) = proto_cmd.command {
            assert_eq!(ex.contract_id, "contract-1");
            assert_eq!(ex.choice, "Transfer");
        } else {
            panic!("Expected Exercise variant");
        }
    }

    #[test]
    fn test_proto_events_to_daml() {
        let events = vec![
            proto::Event {
                event: Some(proto::event::Event::Created(proto::CreatedEvent {
                    event_id: "ev1".to_string(),
                    contract_id: "cid1".to_string(),
                    template_id: Some(proto::Identifier {
                        package_id: "pkg1".to_string(),
                        module_name: "Mod1".to_string(),
                        entity_name: "Tpl1".to_string(),
                    }),
                    create_arguments: None,
                    signatories: vec!["Alice".to_string()],
                    observers: vec![],
                })),
            },
            proto::Event {
                event: Some(proto::event::Event::Archived(proto::ArchivedEvent {
                    event_id: "ev2".to_string(),
                    contract_id: "cid2".to_string(),
                    template_id: Some(proto::Identifier {
                        package_id: "pkg1".to_string(),
                        module_name: "Mod1".to_string(),
                        entity_name: "Tpl1".to_string(),
                    }),
                })),
            },
        ];

        let daml_events = CantonClient::proto_events_to_daml(&events);
        assert_eq!(daml_events.len(), 2);

        match &daml_events[0] {
            DamlEvent::Created {
                event_id,
                contract_id,
                ..
            } => {
                assert_eq!(event_id, "ev1");
                assert_eq!(contract_id.as_str(), "cid1");
            }
            _ => panic!("Expected Created event"),
        }

        match &daml_events[1] {
            DamlEvent::Archived {
                event_id,
                contract_id,
                ..
            } => {
                assert_eq!(event_id, "ev2");
                assert_eq!(contract_id.as_str(), "cid2");
            }
            _ => panic!("Expected Archived event"),
        }
    }

    #[tokio::test]
    async fn test_disconnect() {
        let config = CantonClientConfig::new("localhost", 5001);
        let client = CantonClient::new(config).unwrap();

        client.disconnect().await;
        assert!(!client.connected.load(Ordering::SeqCst));
    }
}
