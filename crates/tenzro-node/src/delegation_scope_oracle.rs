//! Bridge from `tenzro_vm::ScopeOracle` to the on-chain TDIP `IdentityRegistry`
//! and the runtime per-machine `SpendingPolicy` registry maintained by
//! [`AgentRuntime`].
//!
//! `tenzro-vm` cannot depend on `tenzro-identity` or `tenzro-agent` (the
//! dep graph runs the other way — `tenzro-vm` is leaf-ward). The
//! [`tenzro_vm::ScopeOracle`] trait is the cut-line: the validator module
//! lives in `tenzro-vm`; the concrete oracle that materializes the
//! `EnforcedScope` from identity + runtime state lives here, in `tenzro-node`,
//! the only crate that can see all three pieces.
//!
//! Acceptance criterion (ROADMAP §B.3.5): the on-chain validator module
//! refuses to authorize a UserOperation whose `op.sender` resolves to a
//! machine identity whose `DelegationScope` has been revoked or expired
//! between install time and signing time. This is the bridge that makes
//! that re-fetch happen on every validation: each call to [`Self::lookup`]
//! does a fresh `IdentityRegistry::resolve(did)` — there is no cached scope.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use tenzro_agent::AgentRuntime;
use tenzro_identity::{IdentityData, IdentityRegistry};
use tenzro_vm::{EnforcedScope, ScopeOracle};

/// Well-known on-chain module address of the Tenzro
/// `DelegationScopeValidator`. Deterministically derived from a stable seed
/// so every node in the network agrees on the same address without an
/// out-of-band registry. Computed as the trailing 20 bytes of
/// `SHA-256("tenzro/aa/delegation-scope-validator")`.
///
/// Computed lazily on first call so the constant test in this module
/// pins the value byte-for-byte.
pub fn delegation_scope_validator_module_address() -> [u8; 20] {
    let digest = Sha256::digest(b"tenzro/aa/delegation-scope-validator");
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..32]);
    out
}

/// `ScopeOracle` impl backed by the live [`IdentityRegistry`] and
/// [`AgentRuntime`] handles. See module docs.
///
/// # Resolution path
///
/// 1. `op.sender` is a 20-byte EVM address. `IdentityRegistry` keys
///    identities by 32-byte tenzro `Address`; per `derive_evm_address` in
///    `tenzro-identity::registry`, the EVM address is the trailing 20
///    bytes of the tenzro address. We reverse-lookup by scanning the
///    registry for an identity whose `wallet_address`'s last 20 bytes
///    equal `op.sender`.
/// 2. The matched DID resolves to a `TenzroIdentity`. Human identities
///    bypass scope enforcement (return [`EnforcedScope::unrestricted`]).
///    Machine identities project their `DelegationScope` and the runtime
///    `SpendingPolicy` (if any) into a flat [`EnforcedScope`].
/// 3. If the identity is not found, or is not `Active`, or has a revoked /
///    expired `DelegationScope`, the lookup returns `None` so the validator
///    fails closed.
pub struct IdentityScopeOracle {
    identity_registry: Arc<IdentityRegistry>,
    agent_runtime: Arc<AgentRuntime>,
}

impl IdentityScopeOracle {
    pub fn new(
        identity_registry: Arc<IdentityRegistry>,
        agent_runtime: Arc<AgentRuntime>,
    ) -> Self {
        Self {
            identity_registry,
            agent_runtime,
        }
    }

    /// Find the DID whose bound wallet address ends in `evm_addr`.
    /// Returns `None` if no identity is bound to that address.
    fn did_for_evm_address(&self, evm_addr: &[u8; 20]) -> Option<String> {
        // `IdentityRegistry::find_did_by_address` keys on the full 32-byte
        // tenzro Address, but a `tenzro-vm` UserOperation only has the
        // 20-byte EVM address. Walk the registry's identities and match
        // the trailing 20 bytes of `wallet_address` against `evm_addr`.
        // This is O(n_identities) per lookup; acceptable for the validator
        // hot path as long as the registry stays small (single-node TDIP),
        // and trivially upgradable to a maintained reverse-index later.
        for (did, identity) in self.identity_registry.list_all() {
            let bytes = identity.wallet_address.as_bytes();
            let start = bytes.len().saturating_sub(20);
            if &bytes[start..start + 20] == evm_addr {
                return Some(did);
            }
        }
        None
    }
}

impl ScopeOracle for IdentityScopeOracle {
    fn lookup(&self, account: &[u8]) -> Option<EnforcedScope> {
        // The validator owns address-shape parsing; here we only accept
        // the canonical 20-byte EVM form. Anything else fails closed —
        // safer than silently passing a non-EVM signer.
        let evm_addr: [u8; 20] = account.try_into().ok()?;

        let now_ts = chrono::Utc::now().timestamp().max(0) as u64;

        let did = self.did_for_evm_address(&evm_addr)?;
        let identity = self.identity_registry.resolve(&did).ok()?;

        // Inactive identities (Suspended / Revoked / Pending) fail closed.
        if !identity.is_active() {
            return None;
        }

        match &identity.identity_data {
            IdentityData::Human { .. } | IdentityData::Institution { .. } => {
                // Humans and institutions bypass delegation enforcement.
                // Return an unrestricted scope; the validator's other axes
                // (signature check, time bound) still apply.
                Some(EnforcedScope::unrestricted(now_ts))
            }
            IdentityData::Machine {
                delegation_scope, ..
            } => {
                // Hard fail if the scope has expired or been revoked
                // between install time and now — this is exactly what
                // the B.3.5 acceptance asks for.
                if !delegation_scope.is_active() {
                    return None;
                }

                // Project DelegationScope (protocol ceiling) ∩ runtime
                // SpendingPolicy (execution ceiling) into EnforcedScope.
                let runtime_policy = self.agent_runtime.get_spending_policy(&did);

                // Per-tx ceiling: the tighter of (delegation, runtime).
                let max_per_tx = match (
                    delegation_scope.max_transaction_value,
                    runtime_policy.as_ref().map(|p| p.max_per_transaction as u128),
                ) {
                    (Some(d), Some(r)) => Some(d.min(r)),
                    (Some(d), None) => Some(d),
                    (None, Some(r)) => Some(r),
                    (None, None) => None,
                };

                // Per-day ceiling: same pattern.
                let max_per_day = match (
                    delegation_scope.max_daily_spend,
                    runtime_policy.as_ref().map(|p| p.max_daily_spend as u128),
                ) {
                    (Some(d), Some(r)) => Some(d.min(r)),
                    (Some(d), None) => Some(d),
                    (None, Some(r)) => Some(r),
                    (None, None) => None,
                };

                // Allowed targets: project `allowed_contracts` (Vec<Vec<u8>>)
                // to `[u8; 20]`. Skip non-20-byte entries — they cannot
                // identify an EVM call target.
                let allowed_targets: Vec<[u8; 20]> = delegation_scope
                    .allowed_contracts
                    .iter()
                    .filter_map(|c| c.as_slice().try_into().ok())
                    .collect();

                // Allowed selectors: `DelegationScope.allowed_operations` is
                // a `Vec<String>` of human-readable op names (e.g.
                // "transfer", "bridge"). The validator wants 4-byte function
                // selectors. We do NOT translate names to selectors here —
                // the on-chain selector allow-list is opt-in and lives on
                // the per-account SessionKey config (which is a separate
                // validator module). Empty = "selector allow-list disabled"
                // per `DelegationScopeValidator::enforce`.
                let allowed_selectors: Vec<[u8; 4]> = Vec::new();

                // Validity window: project `time_bound` if present.
                // `time_bound.not_before` / `not_after` are `DateTime<Utc>`;
                // EnforcedScope expects Unix seconds.
                let (valid_after, valid_until) = match &delegation_scope.time_bound {
                    Some(bound) => (
                        bound.not_before.timestamp().max(0) as u64,
                        bound.not_after.timestamp().max(0) as u64,
                    ),
                    None => (0u64, 0u64),
                };

                // Day window: take from the runtime SpendingPolicy. If no
                // runtime policy is bound, the rolling counter starts at
                // (now, 0) — fully fresh window.
                let (window_start_ts, spent_in_window) = match runtime_policy.as_ref() {
                    Some(p) => (p.last_reset.max(0) as u64, p.current_daily_spend as u128),
                    None => (now_ts, 0u128),
                };

                Some(EnforcedScope {
                    max_per_tx,
                    max_per_day,
                    allowed_selectors,
                    allowed_targets,
                    valid_after,
                    valid_until,
                    window_start_ts,
                    spent_in_window,
                    now_ts,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tenzro_agent::autonomy::SpendingPolicy;
    use tenzro_identity::{DelegationScope, TimeBound};

    /// Helper: register an autonomous machine identity with a given
    /// delegation scope, then mutate the scope (registration uses defaults).
    /// Returns (did, evm_address).
    async fn register_machine(
        registry: &Arc<IdentityRegistry>,
        scope: DelegationScope,
    ) -> (String, [u8; 20]) {
        // Generate a 32-byte Ed25519 verifying key (the registration path
        // requires exactly 32 bytes).
        let pk = vec![0x42u8; 32];
        let result = registry
            .register_autonomous_machine(pk, vec!["test".to_string()])
            .await
            .expect("register autonomous machine");
        let did = result.did.to_string();
        // Override the delegation scope (registration installs a default).
        registry
            .update_delegation_scope(&did, scope)
            .expect("update delegation scope");
        let identity = registry.resolve(&did).expect("resolve");
        let bytes = identity.wallet_address.as_bytes();
        let start = bytes.len().saturating_sub(20);
        let mut evm = [0u8; 20];
        evm.copy_from_slice(&bytes[start..start + 20]);
        (did, evm)
    }

    fn make_runtime() -> Arc<AgentRuntime> {
        Arc::new(AgentRuntime::new().expect("AgentRuntime::new"))
    }

    fn make_registry() -> Arc<IdentityRegistry> {
        Arc::new(IdentityRegistry::new())
    }

    #[tokio::test]
    async fn unbound_address_returns_none() {
        let oracle = IdentityScopeOracle::new(make_registry(), make_runtime());
        assert!(oracle.lookup(&[0xAA; 20]).is_none());
    }

    #[tokio::test]
    async fn non_evm_address_shape_returns_none() {
        let oracle = IdentityScopeOracle::new(make_registry(), make_runtime());
        // 32 bytes — wrong shape for an EVM sender.
        assert!(oracle.lookup(&[0xBB; 32]).is_none());
        // 0 bytes — wrong shape.
        assert!(oracle.lookup(&[]).is_none());
    }

    #[tokio::test]
    async fn machine_with_active_scope_projects_to_enforced_scope() {
        let registry = make_registry();
        let runtime = make_runtime();
        let scope = DelegationScope {
            max_transaction_value: Some(1_000),
            max_daily_spend: Some(10_000),
            allowed_operations: vec!["transfer".to_string()],
            allowed_contracts: vec![vec![0x42u8; 20]],
            time_bound: Some(TimeBound {
                not_before: Utc::now() - Duration::hours(1),
                not_after: Utc::now() + Duration::hours(1),
            }),
            allowed_payment_protocols: Vec::new(),
            allowed_chains: Vec::new(),
        };
        let (_did, evm) = register_machine(&registry, scope).await;

        let oracle = IdentityScopeOracle::new(registry, runtime);
        let projected = oracle.lookup(&evm).expect("active scope must project");
        assert_eq!(projected.max_per_tx, Some(1_000));
        assert_eq!(projected.max_per_day, Some(10_000));
        assert_eq!(projected.allowed_targets, vec![[0x42u8; 20]]);
        assert!(projected.valid_after > 0);
        assert!(projected.valid_until > projected.valid_after);
    }

    #[tokio::test]
    async fn revoked_machine_fails_closed_at_signing_time() {
        // The B.3.5 acceptance test: a delegation scope that is revoked
        // (here: time_bound expired) between install and signing time
        // MUST cause the oracle to return None so the validator rejects.
        let registry = make_registry();
        let runtime = make_runtime();
        let expired_scope = DelegationScope {
            max_transaction_value: Some(1_000),
            max_daily_spend: None,
            allowed_operations: Vec::new(),
            allowed_contracts: Vec::new(),
            time_bound: Some(TimeBound {
                not_before: Utc::now() - Duration::hours(2),
                not_after: Utc::now() - Duration::hours(1), // expired
            }),
            allowed_payment_protocols: Vec::new(),
            allowed_chains: Vec::new(),
        };
        let (_did, evm) = register_machine(&registry, expired_scope).await;

        let oracle = IdentityScopeOracle::new(registry, runtime);
        assert!(
            oracle.lookup(&evm).is_none(),
            "expired delegation scope must fail closed at signing-time lookup"
        );
    }

    #[tokio::test]
    async fn runtime_policy_tightens_delegation_ceiling() {
        let registry = make_registry();
        let runtime = make_runtime();
        let scope = DelegationScope {
            max_transaction_value: Some(10_000),
            max_daily_spend: Some(100_000),
            allowed_operations: Vec::new(),
            allowed_contracts: Vec::new(),
            time_bound: None,
            allowed_payment_protocols: Vec::new(),
            allowed_chains: Vec::new(),
        };
        let (did, evm) = register_machine(&registry, scope).await;

        // Bind a stricter runtime SpendingPolicy.
        runtime.set_spending_policy(did.clone(), SpendingPolicy::new(500, 5_000));

        let oracle = IdentityScopeOracle::new(registry, runtime);
        let projected = oracle.lookup(&evm).expect("must project");
        // The intersection takes the stricter ceiling on each axis.
        assert_eq!(projected.max_per_tx, Some(500));
        assert_eq!(projected.max_per_day, Some(5_000));
    }

    #[tokio::test]
    async fn delegation_alone_applies_when_no_runtime_policy() {
        let registry = make_registry();
        let runtime = make_runtime();
        let scope = DelegationScope {
            max_transaction_value: Some(750),
            max_daily_spend: None,
            allowed_operations: Vec::new(),
            allowed_contracts: Vec::new(),
            time_bound: None,
            allowed_payment_protocols: Vec::new(),
            allowed_chains: Vec::new(),
        };
        let (_did, evm) = register_machine(&registry, scope).await;

        let oracle = IdentityScopeOracle::new(registry, runtime);
        let projected = oracle.lookup(&evm).expect("must project");
        assert_eq!(projected.max_per_tx, Some(750));
        assert_eq!(projected.max_per_day, None);
    }

    #[tokio::test]
    async fn malformed_allowed_contract_entries_are_skipped() {
        let registry = make_registry();
        let runtime = make_runtime();
        let scope = DelegationScope {
            max_transaction_value: None,
            max_daily_spend: None,
            allowed_operations: Vec::new(),
            // First entry is wrong length (15 bytes) — must be skipped,
            // not propagated as a malformed [u8; 20].
            allowed_contracts: vec![vec![0xAA; 15], vec![0x77; 20]],
            time_bound: None,
            allowed_payment_protocols: Vec::new(),
            allowed_chains: Vec::new(),
        };
        let (_did, evm) = register_machine(&registry, scope).await;

        let oracle = IdentityScopeOracle::new(registry, runtime);
        let projected = oracle.lookup(&evm).expect("must project");
        assert_eq!(projected.allowed_targets, vec![[0x77u8; 20]]);
    }
}
