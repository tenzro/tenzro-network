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

    /// The sender's signature: the P-256 leg and, for an account with an
    /// ML-DSA-65 key enrolled in state, the ML-DSA-65 leg.
    pub signature: Option<tenzro_crypto::composite::CompositeSignature>,

    /// The sender's P-256 public key (`x || y`); it names the sender account.
    pub public_key: Option<Vec<u8>>,

    /// Canonical signing digest carried from the parent `SignedTransaction`.
    ///
    /// This is the exact byte sequence the signature in `signature` was
    /// produced over — `tenzro_types::Transaction::hash()` for production
    /// txs converted via `convert_transaction` in the node event loop.
    /// When `Some`, the runtime verifies the signature against this digest
    /// directly instead of recomputing a preimage from VmTransaction fields,
    /// preventing hash divergence between admission and execution.
    ///
    /// Set to `None` for synthetic txs built in tests/examples that aren't
    /// signed; in that case the runtime skips in-VM verification (the tx
    /// has no signature to verify in the first place).
    pub signing_digest: Option<Vec<u8>>,

    /// Block timestamp (Unix milliseconds) under which this transaction
    /// is being executed, supplied by the consensus event loop from the
    /// finalized block being applied. Native-VM handlers that depend on
    /// wall-clock time (escrow expiry checks, time-bound delegation
    /// checks, lifecycle TTL) MUST read this field instead of calling
    /// `chrono::Utc::now()` — the latter is a non-deterministic
    /// system call and breaks consensus replay across validators with
    /// even a few ms of clock skew.
    ///
    /// `None` indicates the transaction is being executed outside a
    /// consensus context (e.g. tests, eth_call read-only paths). In
    /// that case time-dependent handlers fall back to `Utc::now()` for
    /// best-effort observability, but consensus admission MUST always
    /// set this field.
    pub block_timestamp_ms: Option<i64>,

    /// Last block time (Unix milliseconds) at which the transaction may
    /// execute, copied from the signed transaction. A transaction carrying a
    /// `signing_digest` must carry it; see [`crate::tx_validity`].
    pub valid_until_ms: Option<i64>,

    /// Height of the block this transaction executes in. The EVM reads it
    /// for `block.number` and the randomness beacon derives from the block
    /// before it. `None` outside block execution (tests, `eth_call`), where
    /// the EVM sees height 0.
    pub block_height: Option<u64>,

    /// Base fee of the block this transaction executes in, as set by the fee
    /// market for that block. The EVM exposes it as `block.basefee`.
    pub block_base_fee: Option<u128>,

    /// EIP-7702 authorization list of a set-code transaction. Empty for
    /// every other transaction.
    pub authorization_list: Vec<crate::account_abstraction::Eip7702Authorization>,

    /// EIP-2930 access list of a typed EVM transaction: addresses and their
    /// storage keys, charged in intrinsic gas and warm from the start.
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
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
            signing_digest: None,
            block_timestamp_ms: None,
            valid_until_ms: None,
            block_height: None,
            block_base_fee: None,
            authorization_list: Vec::new(),
            access_list: Vec::new(),
        }
    }

    /// Attach the EIP-7702 authorization list of a set-code transaction.
    pub fn with_authorization_list(
        mut self,
        authorizations: Vec<crate::account_abstraction::Eip7702Authorization>,
    ) -> Self {
        self.authorization_list = authorizations;
        self
    }

    /// Attach the EIP-2930 access list of a typed EVM transaction.
    pub fn with_access_list(mut self, access_list: Vec<([u8; 20], Vec<[u8; 32]>)>) -> Self {
        self.access_list = access_list;
        self
    }

    /// Attach the height of the block this transaction executes in.
    pub fn with_block_height(mut self, height: u64) -> Self {
        self.block_height = Some(height);
        self
    }

    /// Attach the base fee of the block this transaction executes in.
    pub fn with_block_base_fee(mut self, base_fee: u128) -> Self {
        self.block_base_fee = Some(base_fee);
        self
    }

    /// Attach the canonical signing digest produced by the originating
    /// `SignedTransaction`. Used by `convert_transaction` in the node event
    /// loop so the runtime verifies the signature against the same preimage
    /// the admission boundary verified against.
    pub fn with_signing_digest(mut self, digest: Vec<u8>) -> Self {
        self.signing_digest = Some(digest);
        self
    }

    /// Attach the block timestamp under which this transaction executes.
    /// MUST be set by the consensus event loop to the finalized block's
    /// timestamp so all validators observe identical wall-clock state
    /// during replay. Native-VM handlers that depend on time should
    /// read [`Self::block_timestamp_ms`] instead of `Utc::now()`.
    pub fn with_block_timestamp_ms(mut self, ts_ms: i64) -> Self {
        self.block_timestamp_ms = Some(ts_ms);
        self
    }

    /// Create a transaction with signature.
    ///
    /// When the caller has not separately attached a `signing_digest` via
    /// [`with_signing_digest`], this helper auto-populates it from
    /// [`signing_hash`] so the runtime's signature verification has a
    /// canonical preimage to verify against. Production txs built via
    /// `convert_transaction` in the node event loop call
    /// `with_signing_digest` first (with the upstream `Transaction::hash()`)
    /// and that takes precedence — this default applies only to synthetic
    /// txs constructed directly that wouldn't otherwise carry a digest.
    pub fn with_signature(
        mut self,
        signature: tenzro_crypto::composite::CompositeSignature,
    ) -> Self {
        self.signature = Some(signature);
        if self.signing_digest.is_none() {
            self.signing_digest = Some(self.signing_hash());
        }
        self
    }

    /// Attach a public key (paired with a signature for in-VM verification).
    pub fn with_public_key(mut self, public_key: Vec<u8>) -> Self {
        self.public_key = Some(public_key);
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
        use sha2::{Digest, Sha256};
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
        use sha2::{Digest, Sha256};
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

    /// Native TNZO this transaction burned, as a negative amount. Zero for
    /// every transaction that only moves value.
    ///
    /// Block execution holds the transaction to it: the balances it touched
    /// must change by exactly this amount less the gas fee it paid, and total
    /// supply falls by the same amount. TNZO supply is fixed at genesis, so a
    /// positive value is refused and the transaction reverted.
    pub supply_change: i128,

    /// The part of `gas_used` spent verifying proofs, priced by the proof
    /// resource's own fee market (see [`crate::ledger::Resource`]).
    pub proof_gas: u64,

    /// EIP-7702 code writes `(authority, code)` the transaction made before
    /// it executed: a delegation designator, or empty code where an
    /// authorization cleared one. They stand whatever the execution's
    /// outcome, so block execution reapplies them when it reverts the rest.
    pub delegations: Vec<(Vec<u8>, Vec<u8>)>,

    /// TNZO a provider-work settlement in this transaction paid the
    /// treasury as its work class's treasury leg, when the transaction type
    /// declares it; `None` for a transaction that does not.
    pub treasury_leg: Option<u128>,
}

impl ExecutionResult {
    /// Declares the treasury leg the transaction's settlement paid.
    pub fn with_treasury_leg(mut self, leg: u128) -> Self {
        self.treasury_leg = Some(leg);
        self
    }

    /// Declares that `gas` of this transaction's gas verified proofs.
    pub fn with_proof_gas(mut self, gas: u64) -> Self {
        self.proof_gas = gas;
        self
    }

    /// Declares that this transaction burned `amount` of native TNZO.
    pub fn with_burn(mut self, amount: u128) -> Self {
        self.supply_change = self.supply_change.saturating_sub(amount as i128);
        self
    }

    /// Create a successful execution result
    pub fn success(
        gas_used: u64,
        output: Vec<u8>,
        logs: Vec<Log>,
        state_changes: Vec<StateChange>,
    ) -> Self {
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
            supply_change: 0,
            proof_gas: 0,
            delegations: Vec::new(),
            treasury_leg: None,
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
            supply_change: 0,
            proof_gas: 0,
            delegations: Vec::new(),
            treasury_leg: None,
        }
    }

    /// Create a deployment result
    pub fn deployment(
        gas_used: u64,
        contract_address: Vec<u8>,
        logs: Vec<Log>,
        state_changes: Vec<StateChange>,
    ) -> Self {
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
            supply_change: 0,
            proof_gas: 0,
            delegations: Vec::new(),
            treasury_leg: None,
        }
    }
}

/// A read-only contract call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCall {
    /// Caller address
    pub caller: Vec<u8>,

    /// Contract address. Empty simulates a contract creation (EVM): `data`
    /// is the init code and the output is the code it would deploy.
    pub contract: Vec<u8>,

    /// Call data
    pub data: Vec<u8>,

    /// Value to send with call
    pub value: u128,

    /// Gas limit
    pub gas_limit: u64,

    /// VM type
    pub vm_type: VmType,

    /// Height of the block whose state the call reads. The EVM sees it as
    /// `block.number`.
    pub block_height: u64,

    /// Timestamp (Unix milliseconds) of that block. The EVM sees it as
    /// `block.timestamp`, and time-dependent precompiles measure against it.
    pub block_timestamp_ms: i64,
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
            block_height: 0,
            block_timestamp_ms: 0,
        }
    }

    /// Read state as of the block at `height` with timestamp `timestamp_ms`.
    pub fn at_block(mut self, height: u64, timestamp_ms: i64) -> Self {
        self.block_height = height;
        self.block_timestamp_ms = timestamp_ms;
        self
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_abstraction::Eip7702Authorization;

    fn roundtrip(tx: &VmTransaction) -> VmTransaction {
        let bytes = bincode::serialize(tx).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    fn assert_same(a: &VmTransaction, b: &VmTransaction) {
        assert_eq!(
            serde_json::to_value(a).unwrap(),
            serde_json::to_value(b).unwrap()
        );
    }

    /// Bincode is positional, so every optional field must be encoded even
    /// when absent; a transaction round-trips with its optional fields unset.
    #[test]
    fn transaction_with_no_optional_fields_roundtrips_through_bincode() {
        let tx = VmTransaction::new(
            vec![1; 20],
            None,
            7,
            vec![],
            21_000,
            1,
            0,
            VmType::Tenzro,
            1337,
        );
        let back = roundtrip(&tx);
        assert_same(&tx, &back);
        assert!(back.signature.is_none() && back.block_height.is_none());
        assert!(back.authorization_list.is_empty());
    }

    #[test]
    fn transaction_with_every_optional_field_roundtrips_through_bincode() {
        let mut tx = VmTransaction::new(
            vec![1; 20],
            Some(vec![2; 20]),
            7,
            vec![9; 5],
            21_000,
            1,
            3,
            VmType::Evm,
            1337,
        )
        .with_block_height(42)
        .with_block_base_fee(1_000_000_000)
        .with_access_list(vec![([1; 20], vec![[2; 32]])])
        .with_authorization_list(vec![Eip7702Authorization {
            chain_id: crate::account_abstraction::U256::from(1337u64),
            delegate_address: vec![5; 20],
            nonce: 1,
            signature: vec![6; 65],
        }]);
        tx.signature = Some(tenzro_crypto::composite::CompositeSignature::hybrid(
            tenzro_crypto::composite::ClassicalProof::Raw {
                signature: vec![3; 64],
            },
            vec![7; 3309],
        ));
        tx.public_key = Some(vec![4; 64]);
        tx.signing_digest = Some(vec![5; 32]);
        tx.block_timestamp_ms = Some(1_700_000_000_000);
        let back = roundtrip(&tx);
        assert_same(&tx, &back);
        assert_eq!(back.block_base_fee, Some(1_000_000_000));
        assert_eq!(back.authorization_list.len(), 1);
        assert_eq!(
            back.authorization_list[0].chain_id,
            tx.authorization_list[0].chain_id
        );
        assert_eq!(back.access_list, tx.access_list);
    }
}
