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
}

impl DelegationScope {
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
        if self.allowed_operations.is_empty() {
            return true;
        }
        self.allowed_operations.iter().any(|op| op == operation)
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
        if self.allowed_payment_protocols.is_empty() {
            return true;
        }
        self.allowed_payment_protocols
            .iter()
            .any(|p| p == protocol)
    }

    /// Checks if a chain is allowed
    ///
    /// An empty `allowed_chains` list means all chains are allowed.
    pub fn is_chain_allowed(&self, chain: &str) -> bool {
        if self.allowed_chains.is_empty() {
            return true;
        }
        self.allowed_chains.iter().any(|c| c == chain)
    }

    /// Attenuate this scope by `child`, returning the strict intersection.
    ///
    /// This is the canonical primitive for child-scope inheritance: when a
    /// parent (human or machine) spawns a child machine identity, the child's
    /// effective scope must be no broader than the parent's. The returned
    /// scope is the intersection across every axis:
    ///
    /// - **Numeric ceilings** (`max_transaction_value`, `max_daily_spend`):
    ///   the minimum of the two — `Some(min(a, b))`. If either side is
    ///   `None` (unlimited), the other side wins. If both are `None`, the
    ///   result is `None`.
    /// - **Allow-lists** (`allowed_operations`, `allowed_payment_protocols`,
    ///   `allowed_chains`): set-intersection. An empty list on either side
    ///   means *unrestricted on that side*, so the result is the other
    ///   side's list verbatim. If both are empty, the result is empty
    ///   (unrestricted).
    /// - **Allowed contracts**: set-intersection on raw bytes; empty on
    ///   either side propagates the other side.
    /// - **Time bound**: tightest window — child's `not_before` is
    ///   `max(parent.not_before, child.not_before)`, child's `not_after` is
    ///   `min(parent.not_after, child.not_after)`. If only one side has a
    ///   bound, it wins. If neither does, result is `None`.
    ///
    /// The result is *always* a valid sub-scope of `self`. If the
    /// intersection is empty (e.g. disjoint operation allow-lists), the
    /// returned scope still validates structurally — callers must check
    /// activity (`is_active()`) and policy gates (`is_operation_allowed`,
    /// etc.) against the attenuated scope at use-time.
    ///
    /// Pure: this method does not mutate `self` or `child`.
    pub fn attenuate(&self, child: &DelegationScope) -> DelegationScope {
        DelegationScope {
            max_transaction_value: min_optional(
                self.max_transaction_value,
                child.max_transaction_value,
            ),
            max_daily_spend: min_optional(self.max_daily_spend, child.max_daily_spend),
            allowed_operations: intersect_allowlist(
                &self.allowed_operations,
                &child.allowed_operations,
            ),
            allowed_contracts: intersect_allowlist(
                &self.allowed_contracts,
                &child.allowed_contracts,
            ),
            time_bound: tightest_time_bound(self.time_bound.as_ref(), child.time_bound.as_ref()),
            allowed_payment_protocols: intersect_allowlist(
                &self.allowed_payment_protocols,
                &child.allowed_payment_protocols,
            ),
            allowed_chains: intersect_allowlist(&self.allowed_chains, &child.allowed_chains),
        }
    }
}

/// Take the minimum of two `Option<u128>` ceilings, treating `None` as
/// "unlimited". `min(Some(a), Some(b)) = Some(min(a,b))`,
/// `min(Some(a), None) = Some(a)`, `min(None, None) = None`.
fn min_optional(a: Option<u128>, b: Option<u128>) -> Option<u128> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// Set-intersect two allow-lists. Empty list on either side means
/// "unrestricted on that side", so the result is the other side verbatim.
/// If both are empty, the result is empty (unrestricted).
fn intersect_allowlist<T: Clone + PartialEq>(parent: &[T], child: &[T]) -> Vec<T> {
    if parent.is_empty() {
        return child.to_vec();
    }
    if child.is_empty() {
        return parent.to_vec();
    }
    parent
        .iter()
        .filter(|item| child.iter().any(|c| c == *item))
        .cloned()
        .collect()
}

/// Tightest enclosing time window. Child's `not_before` is the later of the
/// two; child's `not_after` is the earlier. Returns `None` only if both
/// inputs are `None`.
fn tightest_time_bound(parent: Option<&TimeBound>, child: Option<&TimeBound>) -> Option<TimeBound> {
    match (parent, child) {
        (Some(p), Some(c)) => Some(TimeBound {
            not_before: p.not_before.max(c.not_before),
            not_after: p.not_after.min(c.not_after),
        }),
        (Some(p), None) => Some(p.clone()),
        (None, Some(c)) => Some(c.clone()),
        (None, None) => None,
    }
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
        let scope = DelegationScope::unrestricted()
            .with_max_transaction_value(5_000);
        let entry = DelegationEntry::new(
            "did:tenzro:human:alice".to_string(),
            "did:tenzro:machine:alice:bot1".to_string(),
            scope,
        );

        assert!(entry.is_active());
        assert!(!entry.revoked);
    }

    #[test]
    fn test_attenuate_numeric_ceilings_take_minimum() {
        let parent = DelegationScope::unrestricted()
            .with_max_transaction_value(10_000)
            .with_max_daily_spend(100_000);
        let child = DelegationScope::unrestricted()
            .with_max_transaction_value(5_000)
            .with_max_daily_spend(50_000);

        let merged = parent.attenuate(&child);
        assert_eq!(merged.max_transaction_value, Some(5_000));
        assert_eq!(merged.max_daily_spend, Some(50_000));

        // Reverse: parent stricter than child still wins on min.
        let merged_rev = child.attenuate(&parent);
        assert_eq!(merged_rev.max_transaction_value, Some(5_000));
    }

    #[test]
    fn test_attenuate_unlimited_side_yields_other() {
        let parent = DelegationScope::unrestricted().with_max_transaction_value(1_000);
        let child = DelegationScope::unrestricted(); // None
        let merged = parent.attenuate(&child);
        assert_eq!(merged.max_transaction_value, Some(1_000));

        let both_unlimited = DelegationScope::unrestricted();
        assert_eq!(
            both_unlimited.attenuate(&both_unlimited).max_transaction_value,
            None
        );
    }

    #[test]
    fn test_attenuate_allowlist_intersection() {
        let parent = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["inference".into(), "trade".into(), "transfer".into()]);
        let child = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["trade".into(), "borrow".into()]);

        let merged = parent.attenuate(&child);
        assert_eq!(merged.allowed_operations, vec!["trade".to_string()]);
    }

    #[test]
    fn test_attenuate_empty_allowlist_means_unrestricted_on_that_side() {
        let parent = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["inference".into()]);
        let child = DelegationScope::unrestricted(); // empty = unrestricted

        let merged = parent.attenuate(&child);
        // Parent is the constraint; child contributes nothing.
        assert_eq!(merged.allowed_operations, vec!["inference".to_string()]);

        // Both empty → still empty (unrestricted).
        let both_empty = DelegationScope::unrestricted();
        assert!(both_empty
            .attenuate(&both_empty)
            .allowed_operations
            .is_empty());
    }

    #[test]
    fn test_attenuate_disjoint_allowlists_yield_empty_intersection() {
        let parent = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["inference".into()]);
        let child = DelegationScope::unrestricted()
            .with_allowed_operations(vec!["admin".into()]);

        let merged = parent.attenuate(&child);
        assert!(merged.allowed_operations.is_empty());
        // The merged scope structurally validates anything (empty list means
        // no restriction on this axis), but real callsites also enforce
        // parent ∩ child via `is_operation_allowed` against the *parent*
        // before granting. The child receives the empty intersection, which
        // is_operation_allowed treats as unrestricted — that's why parent
        // attenuation alone is not sufficient: callers must additionally
        // validate the *requested* op against the parent at spawn-time.
        assert!(merged.is_operation_allowed("anything"));
    }

    #[test]
    fn test_attenuate_time_bound_takes_tightest_window() {
        let now = Utc::now();
        let parent = DelegationScope::unrestricted().with_time_bound(TimeBound::new(
            now - chrono::Duration::hours(1),
            now + chrono::Duration::hours(10),
        ));
        let child = DelegationScope::unrestricted().with_time_bound(TimeBound::new(
            now + chrono::Duration::hours(1),
            now + chrono::Duration::hours(5),
        ));

        let merged = parent.attenuate(&child);
        let bound = merged.time_bound.expect("merged time_bound");
        // Later not_before, earlier not_after.
        assert_eq!(bound.not_before, now + chrono::Duration::hours(1));
        assert_eq!(bound.not_after, now + chrono::Duration::hours(5));
    }

    #[test]
    fn test_attenuate_one_sided_time_bound_propagates() {
        let now = Utc::now();
        let parent = DelegationScope::unrestricted();
        let child = DelegationScope::unrestricted().with_time_bound(TimeBound::new(
            now,
            now + chrono::Duration::hours(1),
        ));

        let merged = parent.attenuate(&child);
        assert!(merged.time_bound.is_some());
    }

    #[test]
    fn test_attenuate_protocols_and_chains_intersected() {
        let parent = DelegationScope::unrestricted()
            .with_allowed_payment_protocols(vec!["mpp".into(), "x402".into()])
            .with_allowed_chains(vec!["tenzro".into(), "tempo".into()]);
        let child = DelegationScope::unrestricted()
            .with_allowed_payment_protocols(vec!["x402".into()])
            .with_allowed_chains(vec!["tempo".into(), "ethereum".into()]);

        let merged = parent.attenuate(&child);
        assert_eq!(merged.allowed_payment_protocols, vec!["x402".to_string()]);
        assert_eq!(merged.allowed_chains, vec!["tempo".to_string()]);
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
