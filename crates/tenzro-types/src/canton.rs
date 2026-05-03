//! Canton Network / Daml 3.x types for Tenzro Network
//!
//! Types representing Canton/Daml concepts as specified by the Canton Network protocol
//! and Daml 3.x Ledger API. Tenzro nodes run Canton participant/validator processes
//! natively, making every Tenzro validator a full participant in the Canton Network.
//!
//! # Canton Architecture
//!
//! Canton operates as a "network of networks" — a permissionless network of permissioned
//! subnets (synchronizers) that delivers enterprise-grade sub-transaction privacy without
//! sacrificing composability. Key components:
//!
//! - **Participant Nodes**: Runtime environment for Daml contracts, exposing Ledger API (gRPC)
//! - **Synchronizers** (formerly "domains"): Provide message routing, ordering, and 2PC coordination
//! - **Global Synchronizer**: Public, permissionless sync domain for cross-domain coordination
//!
//! # Daml 3.x Ledger API Services
//!
//! The Ledger API (default port 5001) exposes these gRPC services:
//! - `CommandService` / `CommandSubmissionService` — Submit Daml commands
//! - `CommandCompletionService` — Track command execution status
//! - `UpdateService` (replaces TransactionService) — Stream committed transactions
//! - `StateService` (replaces ActiveContractsService) — Query active contracts
//! - `EventQueryService` — Query create/archive events
//! - `PackageService` / `PackageManagementService` — Manage DAR packages
//! - `PartyManagementService` — Allocate and query parties
//! - `UserManagementService` — Manage users and access rights
//! - `InteractiveSubmissionService` — Two-step prepare→sign→execute flow
//!
//! The Admin API (default port 5002) exposes:
//! - `PackageService` — DAR upload/removal via `com.digitalasset.canton.admin.participant.v30`
//! - `TopologyManagerWriteService` / `TopologyManagerReadService` — Topology transactions
//! - `ParticipantStatusService` — Node health and status

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Unique identifier for a Daml contract instance.
///
/// In the Daml Ledger API, contract IDs are opaque strings assigned by the
/// participant when a contract is created. They are globally unique.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DamlContractId(pub String);

impl DamlContractId {
    /// Create a new contract ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the contract ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DamlContractId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Fully-qualified Daml template/interface identifier.
///
/// Maps to the Ledger API protobuf `Identifier` message:
/// ```protobuf
/// message Identifier {
///   string package_id = 1;
///   string module_name = 2;
///   string entity_name = 3;
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DamlTemplateId {
    /// Package ID (content-hash of the DAR package)
    pub package_id: String,
    /// Module name within the package (e.g. "MyModule.Contracts")
    pub module_name: String,
    /// Entity (template/interface) name within the module
    pub entity_name: String,
}

impl DamlTemplateId {
    /// Create a new template ID
    pub fn new(
        package_id: impl Into<String>,
        module_name: impl Into<String>,
        entity_name: impl Into<String>,
    ) -> Self {
        Self {
            package_id: package_id.into(),
            module_name: module_name.into(),
            entity_name: entity_name.into(),
        }
    }

    /// Get the fully-qualified name in `package_id:module_name:entity_name` format
    pub fn qualified_name(&self) -> String {
        format!("{}:{}:{}", self.package_id, self.module_name, self.entity_name)
    }
}

impl std::fmt::Display for DamlTemplateId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.package_id, self.module_name, self.entity_name)
    }
}

/// A Daml party identifier.
///
/// In Canton, parties follow the format `name::fingerprint` where the fingerprint
/// is derived from a SHA-256 hash of the party's namespace signing key. Parties
/// are on-ledger identities that can be hosted on multiple participant nodes
/// simultaneously via `PartyToParticipant` topology transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DamlParty(pub String);

impl DamlParty {
    /// Create a new party
    pub fn new(party: impl Into<String>) -> Self {
        Self(party.into())
    }

    /// Get the party as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DamlParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Canton synchronizer identifier (formerly "domain ID").
///
/// In Canton 3.x, what was previously called a "domain" is now called a
/// "synchronizer". A synchronizer provides message routing, transaction ordering,
/// and two-phase commit coordination. It comprises three core services:
///
/// - **Sequencer**: Establishes total order of messages, assigns unique timestamps
/// - **Mediator**: Transaction commit coordinator, collects confirmations
/// - **Topology Manager**: Manages participant joins/leaves, key registration
///
/// The Global Synchronizer is a special public, permissionless synchronizer
/// operated by Super Validators using BFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CantonSynchronizerId(pub String);

impl CantonSynchronizerId {
    /// Create a new synchronizer ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the synchronizer ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CantonSynchronizerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Backwards-compatible alias: Canton 3.x renamed "domain" to "synchronizer"
pub type CantonDomainId = CantonSynchronizerId;

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// Daml value — represents any Daml data value.
///
/// Maps to the Ledger API protobuf `Value` message. Daml's type system includes
/// records (product types), variants (sum types), lists, optionals, maps, and
/// primitive types (Int64, Numeric, Text, Bool, Timestamp, Date, Party, ContractId).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum DamlValue {
    /// Record (product type) with named fields.
    /// Maps to `Value.record` with `record_id` (Identifier) and repeated `fields` (RecordField).
    Record {
        /// Record type ID (optional Identifier)
        record_id: Option<DamlTemplateId>,
        /// Fields as (label, value) pairs
        fields: Vec<(String, DamlValue)>,
    },
    /// Variant (sum type) with a constructor and value.
    /// Maps to `Value.variant` with `variant_id`, `constructor`, and `value`.
    Variant {
        /// Variant type ID (optional Identifier)
        variant_id: Option<DamlTemplateId>,
        /// Constructor name
        constructor: String,
        /// Constructor argument
        value: Box<DamlValue>,
    },
    /// Ordered list of values. Maps to `Value.list`.
    List(Vec<DamlValue>),
    /// 64-bit signed integer. Maps to `Value.int64`.
    Int64(i64),
    /// Arbitrary-precision decimal (as string). Maps to `Value.numeric`.
    Numeric(String),
    /// Text string. Maps to `Value.text`.
    Text(String),
    /// Boolean. Maps to `Value.bool`.
    Bool(bool),
    /// Timestamp (microseconds since epoch). Maps to `Value.timestamp`.
    Timestamp(i64),
    /// Date (days since epoch). Maps to `Value.date`.
    Date(i32),
    /// Party identifier. Maps to `Value.party`.
    Party(DamlParty),
    /// Contract ID reference. Maps to `Value.contract_id`.
    ContractId(DamlContractId),
    /// Optional value. Maps to `Value.optional`.
    Optional(Option<Box<DamlValue>>),
    /// Map with text keys. Maps to `Value.map`.
    Map(Vec<(String, DamlValue)>),
    /// Enum constructor (no value). Maps to `Value.enum`.
    Enum {
        /// Enum type ID (optional Identifier)
        enum_id: Option<DamlTemplateId>,
        /// Constructor name
        constructor: String,
    },
    /// Unit value. Maps to `Value.unit`.
    Unit,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Daml command — an action to submit to the Canton Ledger API.
///
/// Commands are submitted via `CommandService.SubmitAndWait` (synchronous) or
/// `CommandSubmissionService.Submit` (asynchronous). Multiple commands in a
/// single submission are executed atomically.
///
/// In Daml 3.x, the `InteractiveSubmissionService` also supports a two-step
/// prepare→sign→execute flow for external signing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "command_type")]
pub enum DamlCommand {
    /// Create a new contract from a template.
    /// The submitting party must be a signatory of the template.
    Create {
        /// Template to instantiate
        template_id: DamlTemplateId,
        /// Contract arguments (Record value matching template fields)
        create_arguments: DamlValue,
    },
    /// Exercise a choice on an existing contract.
    /// The submitting party must be a controller of the choice.
    /// Consuming choices archive the contract; non-consuming choices leave it active.
    Exercise {
        /// Template of the contract
        template_id: DamlTemplateId,
        /// Contract to exercise on
        contract_id: DamlContractId,
        /// Choice name
        choice: String,
        /// Choice arguments
        choice_argument: DamlValue,
    },
    /// Create a contract and immediately exercise a choice on it.
    /// Useful when commands depend on each other within a single transaction.
    CreateAndExercise {
        /// Template to instantiate
        template_id: DamlTemplateId,
        /// Contract arguments
        create_arguments: DamlValue,
        /// Choice to exercise
        choice: String,
        /// Choice arguments
        choice_argument: DamlValue,
    },
    /// Exercise a choice on a contract identified by its key rather than contract ID.
    /// The contract key must be maintained by the submitting party.
    ExerciseByKey {
        /// Template of the contract
        template_id: DamlTemplateId,
        /// Contract key value
        contract_key: DamlValue,
        /// Choice name
        choice: String,
        /// Choice arguments
        choice_argument: DamlValue,
    },
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// A Daml ledger event.
///
/// Events are produced by committed transactions and delivered through the
/// `UpdateService` (Daml 3.x) or `TransactionService` (legacy). Parties only
/// receive events for contracts where they are a stakeholder (signatory or observer),
/// enforcing Canton's sub-transaction privacy model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum DamlEvent {
    /// A contract was created (maps to `CreatedEvent` in the Ledger API).
    Created {
        /// Event ID (unique within the transaction)
        event_id: String,
        /// Contract ID of the created contract
        contract_id: DamlContractId,
        /// Template ID
        template_id: DamlTemplateId,
        /// Contract arguments (the template payload)
        create_arguments: DamlValue,
        /// Signatories — parties who authorized the creation
        signatories: Vec<DamlParty>,
        /// Observers — parties who can see the contract
        observers: Vec<DamlParty>,
    },
    /// A contract was archived (maps to `ArchivedEvent` in the Ledger API).
    /// This occurs when a consuming choice is exercised on the contract.
    Archived {
        /// Event ID
        event_id: String,
        /// Contract ID of the archived contract
        contract_id: DamlContractId,
        /// Template ID
        template_id: DamlTemplateId,
    },
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// A completed Daml transaction.
///
/// Transactions are the result of successfully committed command submissions.
/// They contain the events produced and metadata about where and when the
/// transaction was committed. In Canton, transactions have sub-transaction privacy:
/// each party only sees the events they are entitled to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DamlTransaction {
    /// Unique transaction ID
    pub transaction_id: String,
    /// Command ID that triggered this transaction (for correlation)
    pub command_id: String,
    /// Workflow ID (for cross-party workflow tracking)
    pub workflow_id: Option<String>,
    /// Events produced by this transaction
    pub events: Vec<DamlEvent>,
    /// When the transaction took effect (microseconds since epoch)
    pub effective_at: i64,
    /// Offset in the participant's ledger (for resuming event streams)
    pub offset: String,
    /// Synchronizer on which the transaction was committed
    pub synchronizer_id: Option<CantonSynchronizerId>,
}

// ---------------------------------------------------------------------------
// Participant configuration
// ---------------------------------------------------------------------------

/// Canton participant node configuration.
///
/// Each Tenzro validator runs a Canton participant process that exposes:
/// - **Ledger API** (default port 5001): gRPC API for applications
/// - **Admin API** (default port 5002): gRPC API for administration
///
/// The participant maintains a Private Contract Store (PCS) with party-specific
/// views of the distributed ledger, runs the Daml engine for contract execution,
/// and can connect to multiple synchronizers simultaneously.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonParticipantConfig {
    /// Ledger API host
    pub host: String,
    /// Ledger API port (default: 5001 in Canton 3.x)
    pub ledger_api_port: u16,
    /// Admin API port (default: 5002 in Canton 3.x)
    pub admin_api_port: u16,
    /// Whether to use TLS for Ledger API connections
    pub use_tls: bool,
    /// Optional TLS certificate path
    pub tls_cert_path: Option<String>,
    /// Acting-as parties for command submissions
    pub act_as: Vec<DamlParty>,
    /// Read-as parties for queries (additional visibility)
    pub read_as: Vec<DamlParty>,
    /// Application ID for command deduplication
    pub application_id: String,
    /// Synchronizer IDs this participant is connected to
    pub synchronizer_ids: Vec<CantonSynchronizerId>,
}

impl Default for CantonParticipantConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            ledger_api_port: 5001,
            admin_api_port: 5002,
            use_tls: false,
            tls_cert_path: None,
            act_as: vec![],
            read_as: vec![],
            application_id: "tenzro-canton-participant".to_string(),
            synchronizer_ids: vec![],
        }
    }
}

impl CantonParticipantConfig {
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

// ---------------------------------------------------------------------------
// Command status
// ---------------------------------------------------------------------------

/// Status of a Canton command submission.
///
/// Commands go through: Accepted → Committed (success) or Rejected (failure).
/// The `CommandCompletionService` streams these status updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CantonCommandStatus {
    /// Command accepted by the participant and being processed
    Accepted,
    /// Command successfully committed to the ledger
    Committed,
    /// Command rejected by the ledger (validation failure, authorization error, etc.)
    Rejected { reason: String },
    /// Command timed out before receiving a definitive result
    TimedOut,
}

// ---------------------------------------------------------------------------
// Package management
// ---------------------------------------------------------------------------

/// A DAR (Daml Archive) package descriptor.
///
/// DARs are uploaded via the Admin API's `PackageService.UploadDar` or the
/// Ledger API's `PackageManagementService`. Each package is identified by a
/// content-hash and must be "vetted" by participants via `VettedPackages`
/// topology transactions before contracts from it can be created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DamlPackageInfo {
    /// Package ID (content hash of the Daml-LF archive)
    pub package_id: String,
    /// Package name (from Daml.yaml)
    pub package_name: Option<String>,
    /// Package version (from Daml.yaml)
    pub package_version: Option<String>,
    /// Size of the DAR in bytes
    pub size_bytes: u64,
    /// Modules contained in the package
    pub modules: Vec<String>,
}

// ---------------------------------------------------------------------------
// Topology transactions
// ---------------------------------------------------------------------------

/// Canton topology transaction types.
///
/// Topology transactions define the network structure: which parties are hosted
/// on which participants, which keys are authorized, and which packages are vetted.
/// All topology transactions require signatures from authorized namespace keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologyTransaction {
    /// Delegates namespace authorization to a key.
    /// Root delegations inherit the right to authorize other delegations.
    NamespaceDelegation {
        /// Namespace being delegated
        namespace: String,
        /// Target signing key fingerprint
        target_key: String,
        /// Whether this is a root delegation
        is_root: bool,
    },
    /// Maps a party to one or more participant nodes.
    /// A party can be hosted on multiple participants simultaneously.
    PartyToParticipant {
        /// Party identifier
        party: DamlParty,
        /// Participant ID
        participant_id: String,
        /// Permission level (Submission, Confirmation, Observation)
        permission: ParticipantPermission,
    },
    /// Maps an owner to their public signing/encryption keys.
    OwnerToKeyMapping {
        /// Owner (participant or party namespace)
        owner: String,
        /// Public key fingerprints
        keys: Vec<String>,
    },
    /// Declares packages vetted by a participant.
    /// Contracts from unvetted packages cannot be created on that participant.
    VettedPackages {
        /// Participant ID
        participant_id: String,
        /// Package IDs that are vetted
        package_ids: Vec<String>,
    },
    /// Defines participant permissions on a synchronizer.
    ParticipantSynchronizerPermission {
        /// Synchronizer ID
        synchronizer_id: CantonSynchronizerId,
        /// Participant ID
        participant_id: String,
        /// Permission level
        permission: ParticipantPermission,
    },
}

/// Permission level for a participant on a synchronizer or for a party on a participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipantPermission {
    /// Can submit commands (highest level)
    Submission,
    /// Can confirm transactions
    Confirmation,
    /// Can only observe (read-only)
    Observation,
}

// ---------------------------------------------------------------------------
// Synchronizer configuration
// ---------------------------------------------------------------------------

/// Configuration for a Canton synchronizer (formerly "domain").
///
/// A synchronizer provides the coordination layer for Daml transactions. It
/// comprises three services that can be deployed monolithically or distributed:
///
/// - **Sequencer**: Total-order multicast, assigns timestamps
/// - **Mediator**: 2PC coordinator, collects confirmations
/// - **Topology Manager**: Party/key/package topology state
///
/// All payloads are end-to-end encrypted between participant nodes — the
/// synchronizer is "blind" to transaction contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynchronizerConfig {
    /// Synchronizer ID
    pub synchronizer_id: CantonSynchronizerId,
    /// Sequencer connection endpoints
    pub sequencer_connections: Vec<String>,
    /// Whether this is the Global Synchronizer (public, permissionless)
    pub is_global: bool,
    /// Estimated finality time in seconds
    pub finality_seconds: u32,
}

impl Default for SynchronizerConfig {
    fn default() -> Self {
        Self {
            synchronizer_id: CantonSynchronizerId::new("default"),
            sequencer_connections: vec!["http://localhost:5008".to_string()],
            is_global: false,
            finality_seconds: 5,
        }
    }
}
