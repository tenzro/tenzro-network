//! Daml-specific VM types

use serde::{Deserialize, Serialize};
use tenzro_types::canton::{CantonCommandStatus, DamlCommand, DamlEvent, DamlTransaction};

use crate::types::{ExecutionResult, Log, StateChange};

/// Daml submission wrapper for Canton command submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DamlSubmission {
    /// Command ID for deduplication
    pub command_id: String,

    /// The party submitting the command
    pub act_as: Vec<String>,

    /// Additional parties for reading
    pub read_as: Vec<String>,

    /// The Daml commands to execute
    pub commands: Vec<DamlCommand>,

    /// Application ID
    pub application_id: String,

    /// Optional workflow ID
    pub workflow_id: Option<String>,
}

impl DamlSubmission {
    /// Create a new Daml submission
    pub fn new(
        command_id: impl Into<String>,
        act_as: Vec<String>,
        commands: Vec<DamlCommand>,
        application_id: impl Into<String>,
    ) -> Self {
        Self {
            command_id: command_id.into(),
            act_as,
            read_as: Vec::new(),
            commands,
            application_id: application_id.into(),
            workflow_id: None,
        }
    }

    /// Add read-as parties
    pub fn with_read_as(mut self, read_as: Vec<String>) -> Self {
        self.read_as = read_as;
        self
    }

    /// Add workflow ID
    pub fn with_workflow_id(mut self, workflow_id: impl Into<String>) -> Self {
        self.workflow_id = Some(workflow_id.into());
        self
    }
}

/// Daml execution result wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DamlExecutionResult {
    /// The Canton transaction result
    pub transaction: Option<DamlTransaction>,

    /// Command status
    pub status: CantonCommandStatus,

    /// Events produced by the transaction
    pub events: Vec<DamlEvent>,

    /// Error message if failed
    pub error: Option<String>,
}

impl DamlExecutionResult {
    /// Create a successful result
    pub fn success(transaction: DamlTransaction, events: Vec<DamlEvent>) -> Self {
        Self {
            transaction: Some(transaction),
            status: CantonCommandStatus::Committed,
            events,
            error: None,
        }
    }

    /// Create a failed result
    pub fn failed(error: impl Into<String>) -> Self {
        let error_string: String = error.into();
        Self {
            transaction: None,
            status: CantonCommandStatus::Rejected {
                reason: error_string.clone(),
            },
            events: Vec::new(),
            error: Some(error_string),
        }
    }

    /// Convert to VM ExecutionResult
    pub fn to_execution_result(&self) -> ExecutionResult {
        match &self.status {
            CantonCommandStatus::Committed => {
                // Daml doesn't have gas, but we provide a fixed estimate for compatibility
                let estimated_gas = 100_000u64;

                // Convert events to logs
                let logs = self
                    .events
                    .iter()
                    .map(|event| match event {
                        DamlEvent::Created {
                            event_id,
                            contract_id,
                            template_id,
                            ..
                        } => Log {
                            address: template_id.qualified_name().as_bytes().to_vec(),
                            topics: vec![event_id.as_bytes().to_vec(), b"Created".to_vec()],
                            data: contract_id.as_str().as_bytes().to_vec(),
                        },
                        DamlEvent::Archived {
                            event_id,
                            contract_id,
                            template_id,
                        } => Log {
                            address: template_id.qualified_name().as_bytes().to_vec(),
                            topics: vec![event_id.as_bytes().to_vec(), b"Archived".to_vec()],
                            data: contract_id.as_str().as_bytes().to_vec(),
                        },
                    })
                    .collect();

                // Build state changes from Daml events
                let state_changes: Vec<StateChange> = self
                    .events
                    .iter()
                    .map(|event| {
                        match event {
                            DamlEvent::Created {
                                contract_id,
                                template_id,
                                ..
                            } => {
                                StateChange::new(
                                    template_id.qualified_name().as_bytes().to_vec(),
                                    contract_id.as_str().as_bytes().to_vec(),
                                    None, // Contract didn't exist before
                                    Some(serde_json::to_vec(event).unwrap_or_default()),
                                )
                            }
                            DamlEvent::Archived {
                                contract_id,
                                template_id,
                                ..
                            } => {
                                StateChange::new(
                                    template_id.qualified_name().as_bytes().to_vec(),
                                    contract_id.as_str().as_bytes().to_vec(),
                                    Some(serde_json::to_vec(event).unwrap_or_default()),
                                    None, // Contract archived (deleted)
                                )
                            }
                        }
                    })
                    .collect();

                ExecutionResult::success(
                    estimated_gas,
                    serde_json::to_vec(&self.transaction).unwrap_or_default(),
                    logs,
                    state_changes,
                )
            }
            CantonCommandStatus::Rejected { reason } => ExecutionResult::failed(0, reason.clone()),
            _ => ExecutionResult::failed(0, "Command not committed".to_string()),
        }
    }
}

/// DAR package deployment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DarDeployment {
    /// DAR file content (bytes)
    pub dar_bytes: Vec<u8>,

    /// Package name (optional, for tracking)
    pub package_name: Option<String>,

    /// Deployer party
    pub deployer: String,
}

impl DarDeployment {
    /// Create a new DAR deployment
    pub fn new(dar_bytes: Vec<u8>, deployer: impl Into<String>) -> Self {
        Self {
            dar_bytes,
            package_name: None,
            deployer: deployer.into(),
        }
    }

    /// Add package name
    pub fn with_package_name(mut self, name: impl Into<String>) -> Self {
        self.package_name = Some(name.into());
        self
    }
}

/// Active contract query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveContractsQuery {
    /// Template filter (optional)
    pub template_id: Option<String>,

    /// Party viewing the contracts
    pub party: String,
}

impl ActiveContractsQuery {
    /// Create a new active contracts query
    pub fn new(party: impl Into<String>) -> Self {
        Self {
            template_id: None,
            party: party.into(),
        }
    }

    /// Filter by template ID
    pub fn with_template_id(mut self, template_id: impl Into<String>) -> Self {
        self.template_id = Some(template_id.into());
        self
    }
}
