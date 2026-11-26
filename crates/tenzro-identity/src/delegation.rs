//! Delegation scopes and entries for the Tenzro Decentralized Identity Protocol
//!
//! Delegation allows human identities to grant scoped permissions to machine
//! identities, controlling what operations machines can perform, how much they
//! can spend, and which payment protocols they may use.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Time boundaries for a delegation scope
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeBound {
    /// Delegation is not valid before this time
    pub not_before: DateTime<Utc>,
    /// Delegation expires after this time
    pub not_after: DateTime<Utc>,
}

impl TimeBound {
    /// Creates a new time bound
    pub fn new(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> Self {
        Self {
            not_before,
            not_after,
        }
    }

    /// Returns true if the current time is within the bound
    pub fn is_active(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }
}

/// Delegation scope defining what a machine identity is allowed to do
///
/// A delegation scope is attached to every machine identity and enforced
/// by the registry and payment systems. It controls spending limits,
/// allowed operations, and which payment rails the machine may use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationScope {
    /// Maximum transaction value the machine can execute (in smallest unit)
    pub max_transaction_value: Option<u128>,
    /// Maximum daily spend across all transactions
    pub max_daily_spend: Option<u128>,
    /// List of allowed operation types (e.g., "inference", "trade", "transfer")
    pub allowed_operations: Vec<String>,
    /// List of allowed smart contract addresses
    pub allowed_contracts: Vec<Vec<u8>>,
    /// Time bounds for this delegation
    pub time_bound: Option<TimeBound>,
    /// Payment protocols this machine may use (e.g., "mpp", "x402", "direct")
    pub allowed_payment_protocols: Vec<String>,
    /// Chains this machine may operate on (e.g., "tenzro", "tempo", "ethereum")
    pub allowed_chains: Vec<String>,
    /// Parts of the grantor's machine this delegation reaches. Unlike the
    /// allow-lists above, an empty list grants nothing: machine access exists
    /// only where it is named.
    pub machine_resources: Vec<MachineResource>,
    /// Most uses of this delegation in any one minute, where uses are metered
    /// (machine access). `None` places no rate limit.
    pub max_uses_per_minute: Option<u32>,
    /// Most bytes moved under this delegation over its lifetime, where bytes
    /// are metered (machine access). `None` places no volume limit.
    pub max_bytes: Option<u64>,
    /// Limits on individual operations named in `allowed_operations`. Every
    /// bound naming an operation applies to each use of it; an operation
    /// with no bound is limited only by being named.
    pub operation_bounds: Vec<OperationBound>,
}

/// Limits on each use of one named operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationBound {
    /// The operation limited, as named in `allowed_operations`.
    pub operation: String,
    /// The values a use may carry (a model id, a message intent). Empty
    /// places no limit on the value.
    pub allowed_values: Vec<String>,
    /// Smallest numeric argument a use may carry.
    pub min: Option<u64>,
    /// Largest numeric argument a use may carry.
    pub max: Option<u64>,
    /// Most uses in any one hour.
    pub max_per_hour: Option<u32>,
}

impl OperationBound {
    /// Whether a use carrying `value` and `number`, made when `uses_this_hour`
    /// uses already happened in the last hour, is within this bound. `None`
    /// means the use carries no such argument; a bound that limits one then
    /// refuses it.
    pub fn permits(&self, value: Option<&str>, number: Option<u64>, uses_this_hour: u32) -> bool {
        if !self.allowed_values.is_empty()
            && !value.is_some_and(|v| self.allowed_values.iter().any(|a| a == v))
        {
            return false;
        }
        if self.min.is_some() || self.max.is_some() {
            let Some(n) = number else { return false };
            if self.min.is_some_and(|min| n < min) || self.max.is_some_and(|max| n > max) {
                return false;
            }
        }
        self.max_per_hour.is_none_or(|cap| uses_this_hour < cap)
    }
}

/// A part of a machine that a delegation can reach.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MachineResource {
    /// Network destinations inside `cidr` (`10.20.0.0/16`, `127.0.0.1/32`,
    /// `fd12::/64`), on `port` when one is named and on any port otherwise.
    /// A service on the machine itself is a loopback address and its port.
    Network { cidr: String, port: Option<u16> },
    /// A directory on the machine, mounted at the same path inside a sandbox.
    Folder { path: String },
    /// A device node on the machine.
    Device { path: String },
}

impl DelegationScope {
    /// A scope with no limits except an expiry `ttl` from now. What a
    /// delegation grants when nothing narrower was asked for: never a
    /// standing authority that outlives the reason it was given.
    pub fn expiring_after(ttl: chrono::Duration) -> Self {
        let now = Utc::now();
        Self {
            time_bound: Some(TimeBound::new(now, now + ttl)),
            ..Self::unrestricted()
        }
    }

    /// Creates a new delegation scope with no restrictions
    pub fn unrestricted() -> Self {
        Self {
            max_transaction_value: None,
            max_daily_spend: None,
            allowed_operations: Vec::new(),
            allowed_contracts: Vec::new(),
            time_bound: None,
            allowed_payment_protocols: Vec::new(),
            allowed_chains: Vec::new(),
            machine_resources: Vec::new(),
            max_uses_per_minute: None,
            max_bytes: None,
            operation_bounds: Vec::new(),
        }
    }

    /// Sets the maximum transaction value
    pub fn with_max_transaction_value(mut self, value: u128) -> Self {
        self.max_transaction_value = Some(value);
        self
    }

    /// Sets the maximum daily spend
    pub fn with_max_daily_spend(mut self, value: u128) -> Self {
        self.max_daily_spend = Some(value);
        self
    }

    /// Sets allowed operations
    pub fn with_allowed_operations(mut self, ops: Vec<String>) -> Self {
        self.allowed_operations = ops;
        self
    }

    /// Sets a time bound
    pub fn with_time_bound(mut self, bound: TimeBound) -> Self {
        self.time_bound = Some(bound);
        self
    }

    /// Sets allowed payment protocols
    pub fn with_allowed_payment_protocols(mut self, protocols: Vec<String>) -> Self {
        self.allowed_payment_protocols = protocols;
        self
    }

    /// Sets allowed chains
    pub fn with_allowed_chains(mut self, chains: Vec<String>) -> Self {
        self.allowed_chains = chains;
        self
    }

    /// Checks if the delegation scope is currently active (time-wise)
    pub fn is_active(&self) -> bool {
        match &self.time_bound {
            Some(bound) => bound.is_active(),
            None => true,
        }
    }

    /// Checks if an operation is allowed by this scope
    ///
    /// An empty `allowed_operations` list means all operations are allowed.
    pub fn is_operation_allowed(&self, operation: &str) -> bool {
        allowlist_admits(&self.allowed_operations, &operation.to_string())
    }

    /// Checks if a transaction value is within the allowed range
    pub fn is_value_allowed(&self, value: u128) -> bool {
        match self.max_transaction_value {
            Some(max) => value <= max,
            None => true,
        }
    }

    /// Checks if a payment protocol is allowed
    ///
    /// An empty `allowed_payment_protocols` list means all protocols are allowed.
    pub fn is_protocol_allowed(&self, protocol: &str) -> bool {
        allowlist_admits(&self.allowed_payment_protocols, &protocol.to_string())
    }

    /// Checks if a chain is allowed
    ///
    /// An empty `allowed_chains` list means all chains are allowed.
    pub fn is_chain_allowed(&self, chain: &str) -> bool {
        allowlist_admits(&self.allowed_chains, &chain.to_string())
    }

    /// Checks if a contract address is allowed
    ///
    /// An empty `allowed_contracts` list means all contracts are allowed.
    pub fn is_contract_allowed(&self, contract: &[u8]) -> bool {
        allowlist_admits(&self.allowed_contracts, &contract.to_vec())
    }
}

/// Whether an allow-list admits `item`. An empty list admits everything; the
/// default value (an empty name or address) is never admitted by a non-empty
/// list.
fn allowlist_admits<T: PartialEq + Default>(list: &[T], item: &T) -> bool {
    if list.is_empty() {
        return true;
    }
    *item != T::default() && list.iter().any(|x| x == item)
}

impl Default for DelegationScope {
    fn default() -> Self {
        Self::unrestricted()
    }
}

/// A delegation entry representing a specific grant from a human to a machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationEntry {
    /// Unique delegation ID
    pub delegation_id: String,
    /// The human DID granting the delegation
    pub grantor_did: String,
    /// The machine DID receiving the delegation
    pub grantee_did: String,
    /// The scope of the delegation
    pub scope: DelegationScope,
    /// When this delegation was created
    pub created_at: DateTime<Utc>,
    /// Whether this delegation has been revoked
    pub revoked: bool,
    /// When this delegation was revoked (if applicable)
    pub revoked_at: Option<DateTime<Utc>>,
}

impl DelegationEntry {
    /// Creates a new delegation entry
    pub fn new(grantor_did: String, grantee_did: String, scope: DelegationScope) -> Self {
        Self {
            delegation_id: uuid::Uuid::new_v4().to_string(),
            grantor_did,
            grantee_did,
            scope,
            created_at: Utc::now(),
            revoked: false,
            revoked_at: None,
        }
    }

    /// Returns true if this delegation is currently active
    pub fn is_active(&self) -> bool {
        !self.revoked && self.scope.is_active()
    }

    /// Revokes this delegation
    pub fn revoke(&mut self) {
        self.revoked = true;
        self.revoked_at = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unrestricted_scope() {
        let scope = DelegationScope::unrestricted();
        assert!(scope.is_active());
        assert!(scope.is_operation_allowed("anything"));
        assert!(scope.is_value_allowed(u128::MAX));
        assert!(scope.is_protocol_allowed("mpp"));
        assert!(scope.is_chain_allowed("tenzro"));
    }

    #[test]
    fn test_restricted_scope() {
        let scope = DelegationScope::unrestricted()
            .with_max_transaction_value(10_000)
            .with_allowed_operations(vec!["inference".to_string(), "trade".to_string()])
            .with_allowed_payment_protocols(vec!["mpp".to_string(), "x402".to_string()])
            .with_allowed_chains(vec!["tenzro".to_string(), "tempo".to_string()]);

        assert!(scope.is_value_allowed(10_000));
        assert!(!scope.is_value_allowed(10_001));
        assert!(scope.is_operation_allowed("inference"));
        assert!(!scope.is_operation_allowed("admin"));
        assert!(scope.is_protocol_allowed("mpp"));
        assert!(!scope.is_protocol_allowed("direct"));
        assert!(scope.is_chain_allowed("tempo"));
        assert!(!scope.is_chain_allowed("ethereum"));
    }

    #[test]
    fn test_time_bound() {
        let active_bound = TimeBound::new(
            Utc::now() - chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(1),
        );
        assert!(active_bound.is_active());

        let expired_bound = TimeBound::new(
            Utc::now() - chrono::Duration::hours(2),
            Utc::now() - chrono::Duration::hours(1),
        );
        assert!(!expired_bound.is_active());

        let future_bound = TimeBound::new(
            Utc::now() + chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::hours(2),
        );
        assert!(!future_bound.is_active());
    }

    #[test]
    fn test_delegation_entry() {
        let scope = DelegationScope::unrestricted().with_max_transaction_value(5_000);
        let entry = DelegationEntry::new(
            "did:tenzro:human:alice".to_string(),
            "did:tenzro:machine:alice:bot1".to_string(),
            scope,
        );

        assert!(entry.is_active());
        assert!(!entry.revoked);
    }

    #[test]
    fn operation_bounds_limit_value_number_and_rate() {
        let bound = OperationBound {
            operation: "throttle_peer".into(),
            allowed_values: vec!["a".into()],
            min: Some(5),
            max: Some(10),
            max_per_hour: Some(2),
        };
        assert!(bound.permits(Some("a"), Some(5), 0));
        assert!(bound.permits(Some("a"), Some(10), 1));
        assert!(
            !bound.permits(Some("b"), Some(7), 0),
            "value outside the list"
        );
        assert!(!bound.permits(None, Some(7), 0), "a value is required");
        assert!(!bound.permits(Some("a"), Some(4), 0), "below min");
        assert!(!bound.permits(Some("a"), Some(11), 0), "above max");
        assert!(!bound.permits(Some("a"), None, 0), "a number is required");
        assert!(!bound.permits(Some("a"), Some(7), 2), "hourly cap reached");
    }

    #[test]
    fn test_revoke_delegation() {
        let scope = DelegationScope::default();
        let mut entry = DelegationEntry::new(
            "did:tenzro:human:alice".to_string(),
            "did:tenzro:machine:alice:bot1".to_string(),
            scope,
        );

        assert!(entry.is_active());
        entry.revoke();
        assert!(!entry.is_active());
        assert!(entry.revoked);
        assert!(entry.revoked_at.is_some());
    }
}
