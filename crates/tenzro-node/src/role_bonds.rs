//! A node serves a bonded role only while it holds the bond for it.
//!
//! Roles that take a bond are checked against consensus state: the validator
//! role against the node's validator bond, every other bonded role against the
//! operator's `Stake` bond for that role at or above the role's required stake
//! for the capacity it declared. At startup a node configured with a bonded
//! role it has not bonded comes up without that role and logs which bond is
//! missing; only an unbonded validator role refuses to boot, since consensus
//! is already set up for it by then. While it runs, the node takes up a role
//! whose bond lands and puts down a role whose bond goes, without a restart
//! ([`spawn_watch`]): everything a role needs is built for the configured
//! roles at startup, and what is served and announced follows the roles
//! served now. A runtime role change to an unbonded role is refused. A
//! bootstrap node's role stakes are bonded by the genesis (`[[role_stakes]]`).

use tenzro_types::network::{NetworkRole, RoleSet};
use tenzro_types::primitives::Address;
use tenzro_vm::VmState;

/// The roles in `roles` that take a bond the accounts do not hold. `operator`
/// is the account role stakes are bonded from; `validator_accounts` are the
/// accounts the node's validator bond may be held under.
pub(crate) fn unbonded_roles(
    chain: &dyn VmState,
    roles: &RoleSet,
    operator: Option<&Address>,
    validator_accounts: &[Address],
) -> Vec<NetworkRole> {
    roles
        .iter()
        .filter(|role| role.requires_bond())
        .filter(|role| {
            let bonded = if role.is_validator() {
                validator_accounts
                    .iter()
                    .any(|a| tenzro_vm::native::bonded_stake_of(chain, a.as_bytes()) > 0)
            } else {
                operator.is_some_and(|a| tenzro_vm::native::role_bonded(chain, a.as_bytes(), *role))
            };
            !bonded
        })
        .collect()
}

/// The roles a node starts with when `missing` of its configured `roles` are
/// unbonded: the rest of them, falling back to the client role when none is
/// left. `Err` names the missing roles when the validator role is among them.
pub(crate) fn roles_to_serve(roles: &RoleSet, missing: &[NetworkRole]) -> Result<RoleSet, ()> {
    if missing.iter().any(NetworkRole::is_validator) {
        return Err(());
    }
    Ok(RoleSet::from_roles(
        roles.iter().filter(|role| !missing.contains(role)),
    ))
}

/// The bonded roles in `roles` this node does not hold a bond for, with the
/// refusal message naming them and how to bond them.
fn missing_bonds(
    node: &crate::TenzroNode,
    roles: &RoleSet,
) -> Result<(Vec<NetworkRole>, String), String> {
    let chain = crate::rpc::chain_state_of(node).ok_or_else(|| {
        "this node has no chain state to check its role bonds against".to_string()
    })?;
    let mut validator_accounts: Vec<Address> = node
        .local_validator_address()
        .copied()
        .into_iter()
        .collect();
    if let Some(signer) = node.identity_signer() {
        validator_accounts.push(Address::new(signer.public_key().account_slot()));
    }
    let operator = node.operator_payee();
    let missing = unbonded_roles(&chain, roles, operator.as_ref(), &validator_accounts);
    let names = missing
        .iter()
        .map(NetworkRole::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let message = format!(
        "roles {names} take a bond this node does not hold in chain state: bond each with a signed \
         Stake transaction from the operator account{} (the validator role with RegisterValidator) \
         or, on a new chain, in the genesis [[role_stakes]], or drop it from --roles",
        operator
            .map(|a| format!(" 0x{}", hex::encode(a.as_bytes())))
            .unwrap_or_default(),
    );
    Ok((missing, message))
}

/// Refuse `roles` unless this node holds a bond for every bonded role in it.
pub(crate) fn check(node: &crate::TenzroNode, roles: &RoleSet) -> Result<(), String> {
    let (missing, message) = missing_bonds(node, roles)?;
    if missing.is_empty() {
        Ok(())
    } else {
        Err(message)
    }
}

/// The roles this node starts with: `roles` without the bonded ones it holds
/// no bond for, each dropped with a warning. Refuses when the validator role
/// is unbonded or there is no chain state to check against.
pub(crate) fn at_start(node: &crate::TenzroNode, roles: &RoleSet) -> Result<RoleSet, String> {
    let (missing, message) = missing_bonds(node, roles)?;
    if missing.is_empty() {
        return Ok(roles.clone());
    }
    let kept = roles_to_serve(roles, &missing).map_err(|()| message.clone())?;
    tracing::warn!("Dropping unbonded roles at startup; this node serves {kept}: {message}");
    Ok(kept)
}

/// How often the node compares its roles with their bonds in chain state.
const WATCH_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether any of the roles a node serves or awaits takes a bond.
fn has_bonded_role(awaiting: &[NetworkRole], served: &RoleSet) -> bool {
    awaiting
        .iter()
        .copied()
        .chain(served.iter())
        .any(|role| role.requires_bond())
}

/// The roles whose bond changed: of `awaiting` (started without for want of
/// a bond), those bonded now; of `served`, those `missing` a bond now.
fn bond_changes(
    awaiting: &[NetworkRole],
    served: &RoleSet,
    missing: &[NetworkRole],
) -> (Vec<NetworkRole>, Vec<NetworkRole>) {
    let landed = awaiting
        .iter()
        .copied()
        .filter(|r| !missing.contains(r))
        .collect();
    let lost = served.iter().filter(|r| missing.contains(r)).collect();
    (landed, lost)
}

/// Why `roles` cannot be served by this node as built, if it cannot: a role
/// that needs the model engines on a build without them (`engines` is the
/// engine check's verdict), or the storage role with no storage runtime
/// (state storage or the iroh data plane is missing). Every other role's
/// runtime is in place, so taking it up needs nothing more.
pub(crate) fn unbuildable(
    roles: &RoleSet,
    engines: Result<(), String>,
    storage_runtime: bool,
) -> Option<String> {
    if let Err(why) = engines {
        return Some(why);
    }
    (roles.serves_storage() && !storage_runtime).then(|| {
        "the storage role needs this node's state storage and its iroh data plane, and this \
         node has no storage runtime"
            .to_string()
    })
}

/// The configured roles a node starting with `kept` set aside for want of a
/// bond.
pub(crate) fn set_aside(configured: &RoleSet, kept: &RoleSet) -> Vec<NetworkRole> {
    configured.iter().filter(|r| !kept.has(*r)).collect()
}

/// Applies bond changes to the roles served and the roles waiting for a bond:
/// a waiting role in `landed` is served, and a served role in `lost` waits
/// again. Each is checked against the lists as they stand, so a role list set
/// by hand meanwhile stays as set; the validator role is never put down
/// here, consensus answers for its bond. Returns the roles taken up and those
/// put down.
fn apply_bond_changes(
    served: &mut RoleSet,
    waiting: &mut Vec<NetworkRole>,
    landed: &[NetworkRole],
    lost: &[NetworkRole],
) -> (Vec<NetworkRole>, Vec<NetworkRole>) {
    let up: Vec<NetworkRole> = landed
        .iter()
        .copied()
        .filter(|r| waiting.contains(r) && !served.has(*r))
        .collect();
    let down: Vec<NetworkRole> = lost
        .iter()
        .copied()
        .filter(|r| !r.is_validator() && served.has(*r))
        .collect();
    waiting.retain(|r| !up.contains(r));
    waiting.extend(down.iter().copied());
    *served = RoleSet::from_roles(
        served
            .iter()
            .filter(|r| !down.contains(r))
            .chain(up.iter().copied()),
    );
    (up, down)
}

/// Takes up a role whose bond lands and puts down a role whose bond goes,
/// while the node runs: the role joins or leaves the roles served, which the
/// announcements, the payment challenges and shard replication read, and the
/// storage runtime starts or stops serving with the storage role.
pub fn spawn_watch(node: std::sync::Arc<crate::TenzroNode>) {
    // Roles change only here, so a node with no role that takes a bond has
    // nothing to watch and keeps no task.
    if !has_bonded_role(&node.roles_awaiting_bond.lock(), &node.runtime_roles.read()) {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(WATCH_EVERY);
        loop {
            tick.tick().await;
            let awaiting = node.roles_awaiting_bond.lock().clone();
            let served = node.runtime_roles.read().clone();
            let all = RoleSet::from_roles(awaiting.iter().copied().chain(served.iter()));
            let (missing, _) = match missing_bonds(&node, &all) {
                Ok(found) => found,
                Err(e) => {
                    tracing::debug!(error = %e, "role bonds not read this round");
                    continue;
                }
            };
            let (landed, lost) = bond_changes(&awaiting, &served, &missing);
            if landed.is_empty() && lost.is_empty() {
                continue;
            }
            // The storage runtime's flag changes under the same lock as the
            // roles, so the two never disagree.
            let (up, down) = {
                let mut waiting = node.roles_awaiting_bond.lock();
                let mut serving = node.runtime_roles.write();
                let changed = apply_bond_changes(&mut serving, &mut waiting, &landed, &lost);
                node.follow_served_roles(&serving);
                changed
            };
            let now = node.runtime_roles.read().clone();
            for role in up {
                tracing::info!(
                    "The bond for the {} role landed; this node serves {now}",
                    role.as_str()
                );
            }
            for role in down {
                tracing::warn!(
                    "The bond for the {} role is gone; this node serves {now} and takes the role \
                     up again once it is bonded",
                    role.as_str()
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::constants::MIN_RPC_OPERATOR_STAKE;
    use tenzro_types::token::{RoleStake, StakeCapacity};
    use tenzro_vm::StateAdapter;

    /// A role started without its bond is reported once the bond is in
    /// place, and a served role once its bond is gone.
    #[test]
    fn a_bond_that_lands_or_goes_is_reported() {
        let awaiting = [NetworkRole::StorageProvider, NetworkRole::ModelProvider];
        let served = RoleSet::from_roles([NetworkRole::Validator, NetworkRole::TeeProvider]);
        let (landed, lost) = bond_changes(&awaiting, &served, &awaiting);
        assert!(landed.is_empty() && lost.is_empty());
        let (landed, lost) = bond_changes(&awaiting, &served, &[NetworkRole::ModelProvider]);
        assert_eq!(landed, vec![NetworkRole::StorageProvider]);
        assert!(lost.is_empty());
        let (landed, lost) = bond_changes(
            &[],
            &served,
            &[NetworkRole::TeeProvider, NetworkRole::StorageProvider],
        );
        assert!(landed.is_empty());
        assert_eq!(lost, vec![NetworkRole::TeeProvider]);
    }

    /// A role whose runtime this node cannot have is refused, naming what is
    /// missing; any other is taken up.
    #[test]
    fn a_role_the_node_cannot_serve_is_refused_by_name() {
        let storage = RoleSet::from_roles([NetworkRole::StorageProvider]);
        let refused = unbuildable(&storage, Ok(()), false).unwrap();
        assert!(refused.contains("storage runtime"), "{refused}");
        assert_eq!(unbuildable(&storage, Ok(()), true), None);
        let ai = RoleSet::from_roles([NetworkRole::ModelProvider]);
        let light = crate::engine_roles::check_for_build(&ai, false, false);
        assert!(unbuildable(&ai, light, true).is_some());
        let full = crate::engine_roles::check_for_build(&ai, true, false);
        assert_eq!(unbuildable(&ai, full, true), None);
    }

    /// The roles a node starts without are the configured ones its kept
    /// roles leave out.
    #[test]
    fn the_roles_set_aside_at_start_are_the_unbonded_ones() {
        let configured = RoleSet::from_roles([
            NetworkRole::Validator,
            NetworkRole::StorageProvider,
            NetworkRole::ModelProvider,
        ]);
        let kept = RoleSet::from_roles([NetworkRole::Validator, NetworkRole::ModelProvider]);
        assert_eq!(
            set_aside(&configured, &kept),
            vec![NetworkRole::StorageProvider]
        );
        assert!(set_aside(&kept, &kept).is_empty());
    }

    /// A landed role is served and leaves the waiting list; a lost role is
    /// put down and waits again; a role list set meanwhile is left as set,
    /// and the validator role is never put down.
    #[test]
    fn a_role_is_taken_up_when_its_bond_lands_and_put_down_when_it_goes() {
        let mut served = RoleSet::from_roles([NetworkRole::Validator, NetworkRole::TeeProvider]);
        let mut waiting = vec![NetworkRole::StorageProvider];
        let (up, down) = apply_bond_changes(
            &mut served,
            &mut waiting,
            &[NetworkRole::StorageProvider],
            &[NetworkRole::TeeProvider, NetworkRole::Validator],
        );
        assert_eq!(up, vec![NetworkRole::StorageProvider]);
        assert_eq!(down, vec![NetworkRole::TeeProvider]);
        assert!(served.has(NetworkRole::StorageProvider) && served.is_validator());
        assert!(!served.has(NetworkRole::TeeProvider));
        assert_eq!(waiting, vec![NetworkRole::TeeProvider]);

        // Cleared by hand meanwhile: a landed bond takes nothing up.
        let mut waiting = Vec::new();
        let (up, _) = apply_bond_changes(
            &mut served,
            &mut waiting,
            &[NetworkRole::ModelProvider],
            &[],
        );
        assert!(up.is_empty() && !served.has(NetworkRole::ModelProvider));
    }

    const OPERATOR: Address = Address([4; 32]);
    const VALIDATOR: Address = Address([5; 32]);

    fn rpc_bond(state: &mut StateAdapter, amount: u128) {
        let stake = RoleStake {
            bonded: amount,
            capacity: StakeCapacity::None,
            unbonding: 0,
            release_at_ms: 0,
            bonded_at_ms: 0,
            endpoint: None,
        };
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            format!("role_stake:{}:rpc", hex::encode(OPERATOR.as_bytes())).as_bytes(),
            serde_json::to_vec(&stake).unwrap(),
        );
    }

    #[test]
    fn a_role_without_its_bond_is_refused() {
        let mut state = StateAdapter::new();
        let roles: RoleSet = "rpc,fullnode".parse().unwrap();
        assert_eq!(
            unbonded_roles(&state, &roles, Some(&OPERATOR), &[]),
            vec![NetworkRole::Rpc]
        );
        // A bond below the role's floor does not count.
        rpc_bond(&mut state, MIN_RPC_OPERATOR_STAKE - 1);
        assert_eq!(
            unbonded_roles(&state, &roles, Some(&OPERATOR), &[]),
            vec![NetworkRole::Rpc]
        );
        rpc_bond(&mut state, MIN_RPC_OPERATOR_STAKE);
        assert!(unbonded_roles(&state, &roles, Some(&OPERATOR), &[]).is_empty());
        // Another account's bond is not this operator's.
        assert_eq!(
            unbonded_roles(&state, &roles, Some(&VALIDATOR), &[]),
            vec![NetworkRole::Rpc]
        );
        assert_eq!(
            unbonded_roles(&state, &roles, None, &[]),
            vec![NetworkRole::Rpc]
        );
    }

    #[test]
    fn the_validator_role_needs_the_validator_bond() {
        let mut state = StateAdapter::new();
        let roles = RoleSet::validator_only();
        assert_eq!(
            unbonded_roles(&state, &roles, Some(&OPERATOR), &[VALIDATOR]),
            vec![NetworkRole::Validator]
        );
        let (entries, _) =
            tenzro_vm::native::genesis_validator_bonds(&[(VALIDATOR.0, [6; 32], [7; 32], 1)])
                .unwrap();
        for (key, value) in entries {
            state.set_storage(&tenzro_vm::native::SYSTEM_ADDRESS, &key, value);
        }
        assert!(unbonded_roles(&state, &roles, Some(&OPERATOR), &[VALIDATOR]).is_empty());
        // Roles that take no bond never refuse. (An edge relay bonds.)
        let free: RoleSet = "fullnode,light,archive,bootstrap,micro".parse().unwrap();
        assert!(unbonded_roles(&state, &free, None, &[]).is_empty());
    }

    #[test]
    fn an_unbonded_extra_role_is_dropped_and_the_bonded_roles_stay() {
        let roles: RoleSet = "validator,storage".parse().unwrap();
        assert_eq!(
            roles_to_serve(&roles, &[NetworkRole::StorageProvider]),
            Ok(RoleSet::validator_only())
        );
        assert_eq!(roles_to_serve(&roles, &[]), Ok(roles.clone()));
    }

    #[test]
    fn an_unbonded_validator_role_still_refuses() {
        let roles: RoleSet = "validator,storage".parse().unwrap();
        assert_eq!(roles_to_serve(&roles, &[NetworkRole::Validator]), Err(()));
        assert_eq!(
            roles_to_serve(
                &roles,
                &[NetworkRole::Validator, NetworkRole::StorageProvider]
            ),
            Err(())
        );
    }

    #[test]
    fn a_node_left_with_no_role_runs_as_a_client() {
        let roles: RoleSet = "storage".parse().unwrap();
        assert_eq!(
            roles_to_serve(&roles, &[NetworkRole::StorageProvider]),
            Ok(RoleSet::client())
        );
    }

    /// A client node has no bond to watch; a node serving or awaiting a
    /// bonded role has.
    #[test]
    fn only_a_node_with_a_bonded_role_watches_bonds() {
        assert!(!has_bonded_role(&[], &RoleSet::client()));
        assert!(has_bonded_role(
            &[NetworkRole::StorageProvider],
            &RoleSet::client()
        ));
        assert!(has_bonded_role(
            &[],
            &RoleSet::from_roles([NetworkRole::Validator])
        ));
    }
}
