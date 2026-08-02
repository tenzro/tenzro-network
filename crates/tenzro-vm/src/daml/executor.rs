//! Daml executor implementation

use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    config::VmConfig,
    error::{Result, VmError},
    traits::{VmExecutor, VmState, VmType},
    types::{
        CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, VmTransaction,
    },
};

use super::{
    canton_client::{CantonClient, CantonClientConfig},
    types::{ActiveContractsQuery, DamlSubmission},
};
use tenzro_types::canton::DamlCommand;

/// Daml executor for Canton 3.x
///
/// This executor connects to the co-located Canton participant node's Ledger API
/// (gRPC, default port 5001) to execute Daml smart contracts. Each Tenzro
/// validator runs a Canton participant process natively, so the executor
/// communicates with localhost.
///
/// The executor handles:
/// - Command submission via `CommandService.SubmitAndWait`
/// - Active contract queries via `StateService.GetActiveContracts` (Daml 3.x)
/// - DAR package deployment via Admin API `PackageService.UploadDar`
/// - Gas estimation (compatibility shim — Daml has no gas concept)
pub struct DamlExecutor {
    /// Configuration
    config: VmConfig,

    /// Canton Ledger API client (connected to co-located participant)
    client: Arc<CantonClient>,

    /// Default application ID for command deduplication
    application_id: String,
}

impl DamlExecutor {
    /// Create a new Daml executor connected to the co-located Canton participant
    ///
    /// The connection to Canton is NOT established immediately — it is deferred
    /// until the first DAML operation. This allows the Tenzro node to start even
    /// if Canton is not yet available. EVM and SVM operations are unaffected.
    pub fn new(config: VmConfig, canton_host: impl Into<String>, canton_port: u16) -> Result<Self> {
        tracing::info!("Initializing Daml executor (Canton 3.x Ledger API)");

        let client_config = CantonClientConfig::new(canton_host, canton_port);
        let client = CantonClient::new(client_config)?;

        Ok(Self {
            config,
            client: Arc::new(client),
            application_id: "tenzro-daml-executor".to_string(),
        })
    }

    /// Check if the Canton participant is connected
    pub async fn is_canton_connected(&self) -> bool {
        self.client.is_connected().await
    }

    /// Create a Daml executor with custom client
    pub fn with_client(config: VmConfig, client: CantonClient) -> Self {
        Self {
            config,
            client: Arc::new(client),
            application_id: "tenzro-daml-executor".to_string(),
        }
    }

    /// Set the application ID
    pub fn with_application_id(mut self, app_id: impl Into<String>) -> Self {
        self.application_id = app_id.into();
        self
    }

    /// Generate a unique command ID
    fn generate_command_id(&self) -> String {
        format!("cmd_{}", chrono::Utc::now().timestamp_micros())
    }

    /// Convert transaction data to Daml commands
    ///
    /// Expects transaction data to be JSON-encoded DamlCommand or Vec<DamlCommand>
    fn decode_commands(&self, data: &[u8]) -> Result<Vec<DamlCommand>> {
        if data.is_empty() {
            return Err(VmError::CantonError(
                "Empty transaction data: cannot decode Daml commands".to_string(),
            ));
        }

        // Try to parse as a single command first
        if let Ok(cmd) = serde_json::from_slice::<DamlCommand>(data) {
            // Validate the command
            self.validate_command(&cmd)?;
            return Ok(vec![cmd]);
        }

        // Try to parse as multiple commands
        if let Ok(cmds) = serde_json::from_slice::<Vec<DamlCommand>>(data) {
            if cmds.is_empty() {
                return Err(VmError::CantonError(
                    "Empty command list: at least one command required".to_string(),
                ));
            }
            // Validate all commands
            for cmd in &cmds {
                self.validate_command(cmd)?;
            }
            return Ok(cmds);
        }

        Err(VmError::CantonError(format!(
            "Invalid Daml command format: expected JSON-encoded DamlCommand or Vec<DamlCommand>, got {} bytes",
            data.len()
        )))
    }

    /// Validate a Daml command structure
    fn validate_command(&self, cmd: &DamlCommand) -> Result<()> {
        match cmd {
            DamlCommand::Create { template_id, .. } => {
                if template_id.package_id.is_empty() {
                    return Err(VmError::CantonError(
                        "Create command: package_id cannot be empty".to_string(),
                    ));
                }
                if template_id.module_name.is_empty() {
                    return Err(VmError::CantonError(
                        "Create command: module_name cannot be empty".to_string(),
                    ));
                }
                if template_id.entity_name.is_empty() {
                    return Err(VmError::CantonError(
                        "Create command: entity_name cannot be empty".to_string(),
                    ));
                }
            }
            DamlCommand::Exercise {
                contract_id,
                choice,
                ..
            } => {
                if contract_id.0.is_empty() {
                    return Err(VmError::CantonError(
                        "Exercise command: contract_id cannot be empty".to_string(),
                    ));
                }
                if choice.is_empty() {
                    return Err(VmError::CantonError(
                        "Exercise command: choice cannot be empty".to_string(),
                    ));
                }
            }
            DamlCommand::CreateAndExercise {
                template_id,
                choice,
                ..
            } => {
                if template_id.package_id.is_empty() {
                    return Err(VmError::CantonError(
                        "CreateAndExercise command: package_id cannot be empty".to_string(),
                    ));
                }
                if choice.is_empty() {
                    return Err(VmError::CantonError(
                        "CreateAndExercise command: choice cannot be empty".to_string(),
                    ));
                }
            }
            DamlCommand::ExerciseByKey {
                template_id,
                choice,
                ..
            } => {
                if template_id.package_id.is_empty() {
                    return Err(VmError::CantonError(
                        "ExerciseByKey command: package_id cannot be empty".to_string(),
                    ));
                }
                if choice.is_empty() {
                    return Err(VmError::CantonError(
                        "ExerciseByKey command: choice cannot be empty".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Extract party from address
    ///
    /// Converts address bytes to a party string
    fn address_to_party(&self, address: &[u8]) -> String {
        // Use hex encoding for the party identifier
        hex::encode(address)
    }

    /// Compute contract address for Daml (package ID hash)
    fn compute_daml_address(&self, package_id: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(package_id.as_bytes());
        let hash = hasher.finalize();

        // Use 32-byte address with Daml prefix [0xDA, 0x71]
        let mut address = vec![0xDA, 0x71];
        address.extend_from_slice(&hash[..30]);
        address
    }
}

#[async_trait]
impl VmExecutor for DamlExecutor {
    fn vm_type(&self) -> VmType {
        VmType::Daml
    }

    async fn execute_transaction(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
    ) -> Result<ExecutionResult> {
        tracing::debug!("Daml: Executing transaction from {}", hex::encode(&tx.from));

        // Decode Daml commands from transaction data
        let commands = self.decode_commands(&tx.data)?;

        if commands.is_empty() {
            return Err(VmError::CantonError(
                "No Daml commands found in transaction".to_string(),
            ));
        }

        // Convert sender address to party
        let party = self.address_to_party(&tx.from);

        // Create submission
        let command_id = self.generate_command_id();
        let submission = DamlSubmission::new(
            command_id,
            vec![party.clone()],
            commands,
            self.application_id.clone(),
        );

        // Submit to Canton
        let result = self
            .client
            .submit_command(&submission)
            .await
            .map_err(|e| VmError::CantonError(format!("Canton submission failed: {}", e)))?;

        // Update nonce
        let nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, nonce + 1);

        // Daml doesn't use gas in the traditional sense, but we provide an estimate
        // for compatibility with the VM interface
        let mut execution_result = result.to_execution_result();

        // Add nonce state change to the result
        if execution_result.success {
            execution_result
                .state_changes
                .push(crate::types::StateChange::new(
                    tx.from.clone(),
                    b"nonce".to_vec(),
                    Some(nonce.to_le_bytes().to_vec()),
                    Some((nonce + 1).to_le_bytes().to_vec()),
                ));
        }

        tracing::debug!(
            "Daml: Transaction executed, success={}",
            execution_result.success
        );

        Ok(execution_result)
    }

    async fn call(&self, call: &ContractCall, _state: &dyn VmState) -> Result<CallResult> {
        tracing::debug!("Daml: Read-only call to {}", hex::encode(&call.contract));

        // For Daml, a "call" is typically a query for active contracts
        // The contract address is used as a party identifier
        let party = self.address_to_party(&call.contract);

        // Try to decode template filter from call data
        let template_id = if !call.data.is_empty() {
            serde_json::from_slice::<String>(&call.data).ok()
        } else {
            None
        };

        let query =
            ActiveContractsQuery::new(party).with_template_id(template_id.unwrap_or_default());

        // Query active contracts
        let contracts = self
            .client
            .get_active_contracts(&query)
            .await
            .map_err(|e| VmError::CantonError(format!("Canton query failed: {}", e)))?;

        // Encode contract IDs as output
        let output = serde_json::to_vec(&contracts)
            .map_err(|e| VmError::CantonError(format!("Failed to encode query result: {}", e)))?;

        Ok(CallResult::success(output, 50_000))
    }

    async fn deploy_contract(
        &self,
        deployment: &ContractDeployment,
        state: &mut dyn VmState,
    ) -> Result<DeployResult> {
        tracing::info!(
            "Daml: Deploying DAR package from {}",
            hex::encode(&deployment.deployer)
        );

        // Validate DAR size
        self.config.validate_contract_size(deployment.code.len())?;

        // Upload DAR to Canton
        let package_id = self
            .client
            .upload_dar(&deployment.code)
            .await
            .map_err(|e| VmError::CantonError(format!("DAR upload failed: {}", e)))?;

        tracing::info!("Daml: DAR uploaded with package ID: {}", package_id);

        // Compute contract address from package ID
        let contract_address = self.compute_daml_address(&package_id);

        // Store package ID as "code" in state
        state.set_code(&contract_address, package_id.as_bytes().to_vec());

        // Update deployer nonce
        let nonce = state.get_nonce(&deployment.deployer);
        state.set_nonce(&deployment.deployer, nonce + 1);

        // Daml doesn't have gas, provide fixed estimate
        let gas_used = 200_000u64;

        Ok(DeployResult::success(contract_address, gas_used))
    }

    async fn estimate_gas(&self, tx: &VmTransaction, _state: &dyn VmState) -> Result<u64> {
        // Daml doesn't use gas, but we provide fixed estimates for compatibility

        if tx.to.is_none() {
            // DAR deployment
            Ok(200_000)
        } else if tx.data.is_empty() {
            // Simple query
            Ok(50_000)
        } else {
            // Command execution - estimate based on command count
            match self.decode_commands(&tx.data) {
                Ok(commands) => {
                    // Base cost + per-command cost
                    Ok(100_000 + (commands.len() as u64 * 50_000))
                }
                Err(_) => {
                    // Default estimate if we can't decode
                    Ok(100_000)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    fn create_executor() -> DamlExecutor {
        let config = VmConfig::default();
        DamlExecutor::new(config, "localhost", 5001).unwrap()
    }

    #[test]
    fn test_address_to_party() {
        let executor = create_executor();
        let address = vec![1u8; 32];
        let party = executor.address_to_party(&address);
        assert!(!party.is_empty());
    }

    #[test]
    fn test_compute_daml_address() {
        let executor = create_executor();
        let address = executor.compute_daml_address("test-package-id");
        assert_eq!(address.len(), 32);
        assert_eq!(address[0], 0xDA);
        assert_eq!(address[1], 0x71);
    }

    #[tokio::test]
    async fn test_deploy_dar_fails_without_canton() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let deployer = vec![1u8; 32];
        let dar_bytes = b"mock dar content".to_vec();

        state.set_balance(&deployer, 10_000_000_000_000_000_000u128);

        let deployment = ContractDeployment::new(
            deployer.clone(),
            dar_bytes,
            Vec::new(),
            0,
            500_000,
            1_000_000_000,
            0,
            VmType::Daml,
        );

        // Without a Canton participant running, deploy should fail gracefully
        let result = executor.deploy_contract(&deployment, &mut state).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Canton") || err.contains("connect"),
            "Expected Canton connection error, got: {}",
            err
        );
    }

    #[test]
    fn test_compute_daml_address_format() {
        let executor = create_executor();
        let address = executor.compute_daml_address("test-package-id");
        assert_eq!(address.len(), 32);
        assert_eq!(address[0], 0xDA);
        assert_eq!(address[1], 0x71);

        // Same input should produce same address (deterministic)
        let address2 = executor.compute_daml_address("test-package-id");
        assert_eq!(address, address2);

        // Different input should produce different address
        let address3 = executor.compute_daml_address("other-package-id");
        assert_ne!(address, address3);
    }

    #[tokio::test]
    async fn test_estimate_gas() {
        let executor = create_executor();
        let state = StateAdapter::new();

        // Test deployment estimate
        let deploy_tx = VmTransaction::new(
            vec![1u8; 32],
            None,
            0,
            vec![],
            500_000,
            1_000_000_000,
            0,
            VmType::Daml,
            1337,
        );

        let gas = executor.estimate_gas(&deploy_tx, &state).await.unwrap();
        assert_eq!(gas, 200_000);

        // Test query estimate
        let query_tx = VmTransaction::new(
            vec![1u8; 32],
            Some(vec![2u8; 32]),
            0,
            vec![],
            100_000,
            1_000_000_000,
            0,
            VmType::Daml,
            1337,
        );

        let gas = executor.estimate_gas(&query_tx, &state).await.unwrap();
        assert_eq!(gas, 50_000);
    }
}
