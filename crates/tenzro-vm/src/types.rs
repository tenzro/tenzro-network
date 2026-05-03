//! VM-specific types and data structures

use serde::{Deserialize, Serialize};

use crate::VmType;

/// A transaction to be executed by a VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmTransaction {
    /// Sender address
    pub from: Vec<u8>,

    /// Recipient address (None for contract deployment)
    pub to: Option<Vec<u8>>,

    /// Value to transfer (in smallest units)
    pub value: u128,

    /// Transaction data/input
    pub data: Vec<u8>,

    /// Gas limit
    pub gas_limit: u64,

    /// Gas price
    pub gas_price: u128,

    /// Transaction nonce
    pub nonce: u64,

    /// VM type to execute on
    pub vm_type: VmType,

    /// Chain ID
    pub chain_id: u64,

    /// Transaction signature (required for security)
    pub signature: Option<Vec<u8>>,

    /// Sender's public key for signature verification
    pub public_key: Option<Vec<u8>>,
}

impl VmTransaction {
    /// Create a new VM transaction
    pub fn new(
        from: Vec<u8>,
        to: Option<Vec<u8>>,
        value: u128,
        data: Vec<u8>,
        gas_limit: u64,
        gas_price: u128,
        nonce: u64,
        vm_type: VmType,
        chain_id: u64,
    ) -> Self {
        Self {
            from,
            to,
            value,
            data,
            gas_limit,
            gas_price,
            nonce,
            vm_type,
            chain_id,
            signature: None,
            public_key: None,
        }
    }

    /// Create a transaction with signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Check if this is a contract deployment transaction
    pub fn is_deployment(&self) -> bool {
        self.to.is_none()
    }

    /// Compute the signing hash of the transaction.
    ///
    /// This hashes only the transaction fields that are covered by the signature
    /// (excludes `signature` and `public_key` to avoid circular dependency).
    pub fn signing_hash(&self) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.from);
        if let Some(ref to) = self.to {
            hasher.update(to);
        }
        hasher.update(self.value.to_le_bytes());
        hasher.update(&self.data);
        hasher.update(self.gas_limit.to_le_bytes());
        hasher.update(self.gas_price.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        hasher.update(format!("{:?}", self.vm_type).as_bytes());
        hasher.update(self.chain_id.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Get the full transaction hash (includes all fields for indexing/lookup).
    pub fn hash(&self) -> Vec<u8> {
        use sha2::{Sha256, Digest};
        let data = serde_json::to_vec(self).unwrap_or_default();
        Sha256::digest(&data).to_vec()
    }
}

/// Result of executing a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Whether execution was successful
    pub success: bool,

    /// Gas used during execution
    pub gas_used: u64,

    /// Gas refunded (e.g., from SSTORE clearing)
    pub gas_refund: u64,

    /// Return data/output
    pub output: Vec<u8>,

    /// Logs emitted during execution
    pub logs: Vec<Log>,

    /// State changes made during execution
    pub state_changes: Vec<StateChange>,

    /// Revert reason (if execution failed)
    pub revert_reason: Option<String>,

    /// Contract address (for deployment transactions)
    pub contract_address: Option<Vec<u8>>,

    /// Maximum call depth reached during execution
    pub call_depth: u32,
}

impl ExecutionResult {
    /// Create a successful execution result
    pub fn success(gas_used: u64, output: Vec<u8>, logs: Vec<Log>, state_changes: Vec<StateChange>) -> Self {
        Self {
            success: true,
            gas_used,
            gas_refund: 0,
            output,
            logs,
            state_changes,
            revert_reason: None,
            contract_address: None,
            call_depth: 1,
        }
    }

    /// Create a failed execution result
    pub fn failed(gas_used: u64, revert_reason: String) -> Self {
        Self {
            success: false,
            gas_used,
            gas_refund: 0,
            output: Vec::new(),
            logs: Vec::new(),
            state_changes: Vec::new(),
            revert_reason: Some(revert_reason),
            contract_address: None,
            call_depth: 1,
        }
    }

    /// Create a deployment result
    pub fn deployment(gas_used: u64, contract_address: Vec<u8>, logs: Vec<Log>, state_changes: Vec<StateChange>) -> Self {
        Self {
            success: true,
            gas_used,
            gas_refund: 0,
            output: Vec::new(),
            logs,
            state_changes,
            revert_reason: None,
            contract_address: Some(contract_address),
            call_depth: 1,
        }
    }
}

/// A read-only contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCall {
    /// Caller address
    pub caller: Vec<u8>,

    /// Contract address
    pub contract: Vec<u8>,

    /// Call data
    pub data: Vec<u8>,

    /// Value to send with call
    pub value: u128,

    /// Gas limit
    pub gas_limit: u64,

    /// VM type
    pub vm_type: VmType,
}

impl ContractCall {
    /// Create a new contract call
    pub fn new(
        caller: Vec<u8>,
        contract: Vec<u8>,
        data: Vec<u8>,
        value: u128,
        gas_limit: u64,
        vm_type: VmType,
    ) -> Self {
        Self {
            caller,
            contract,
            data,
            value,
            gas_limit,
            vm_type,
        }
    }
}

/// Result of a contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallResult {
    /// Return data
    pub output: Vec<u8>,

    /// Gas used
    pub gas_used: u64,

    /// Whether the call succeeded
    pub success: bool,

    /// Revert reason (if call failed)
    pub revert_reason: Option<String>,
}

impl CallResult {
    /// Create a successful call result
    pub fn success(output: Vec<u8>, gas_used: u64) -> Self {
        Self {
            output,
            gas_used,
            success: true,
            revert_reason: None,
        }
    }

    /// Create a failed call result
    pub fn failed(gas_used: u64, revert_reason: String) -> Self {
        Self {
            output: Vec::new(),
            gas_used,
            success: false,
            revert_reason: Some(revert_reason),
        }
    }
}

/// Contract deployment parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDeployment {
    /// Deployer address
    pub deployer: Vec<u8>,

    /// Contract bytecode
    pub code: Vec<u8>,

    /// Constructor arguments
    pub constructor_args: Vec<u8>,

    /// Value to send with deployment
    pub value: u128,

    /// Gas limit
    pub gas_limit: u64,

    /// Gas price
    pub gas_price: u128,

    /// Deployment nonce
    pub nonce: u64,

    /// VM type
    pub vm_type: VmType,
}

impl ContractDeployment {
    /// Create a new contract deployment
    pub fn new(
        deployer: Vec<u8>,
        code: Vec<u8>,
        constructor_args: Vec<u8>,
        value: u128,
        gas_limit: u64,
        gas_price: u128,
        nonce: u64,
        vm_type: VmType,
    ) -> Self {
        Self {
            deployer,
            code,
            constructor_args,
            value,
            gas_limit,
            gas_price,
            nonce,
            vm_type,
        }
    }
}

/// Result of contract deployment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    /// Deployed contract address
    pub address: Vec<u8>,

    /// Gas used
    pub gas_used: u64,

    /// Whether deployment succeeded
    pub success: bool,

    /// Revert reason (if deployment failed)
    pub revert_reason: Option<String>,
}

impl DeployResult {
    /// Create a successful deployment result
    pub fn success(address: Vec<u8>, gas_used: u64) -> Self {
        Self {
            address,
            gas_used,
            success: true,
            revert_reason: None,
        }
    }

    /// Create a failed deployment result
    pub fn failed(gas_used: u64, revert_reason: String) -> Self {
        Self {
            address: Vec::new(),
            gas_used,
            success: false,
            revert_reason: Some(revert_reason),
        }
    }
}

/// Event log emitted during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// Contract address that emitted the log
    pub address: Vec<u8>,

    /// Indexed topics
    pub topics: Vec<Vec<u8>>,

    /// Non-indexed data
    pub data: Vec<u8>,
}

impl Log {
    /// Create a new log
    pub fn new(address: Vec<u8>, topics: Vec<Vec<u8>>, data: Vec<u8>) -> Self {
        Self {
            address,
            topics,
            data,
        }
    }
}

/// State change record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    /// Address of the account
    pub address: Vec<u8>,

    /// Storage key that changed
    pub key: Vec<u8>,

    /// Old value (None if key didn't exist)
    pub old_value: Option<Vec<u8>>,

    /// New value (None if key was deleted)
    pub new_value: Option<Vec<u8>>,
}

impl StateChange {
    /// Create a new state change
    pub fn new(
        address: Vec<u8>,
        key: Vec<u8>,
        old_value: Option<Vec<u8>>,
        new_value: Option<Vec<u8>>,
    ) -> Self {
        Self {
            address,
            key,
            old_value,
            new_value,
        }
    }
}
