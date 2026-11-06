//! A node serves a bonded role only while it holds the bond for it.
//!
//! Roles that take a bond are checked against consensus state: the validator
//! role against the node's validator bond, every other bonded role against the
//! operator's `Stake` bond for that role at or above the role's required stake
//! for the capacity it declared. A node configured with a role it has not
//! bonded refuses to boot, and a runtime role change to one is refused. A
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

/// Refuse `roles` unless this node holds a bond for every bonded role in it.
pub(crate) fn check(node: &crate::TenzroNode, roles: &RoleSet) -> Result<(), String> {
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
    if missing.is_empty() {
        return Ok(());
    }
    let names = missing
        .iter()
        .map(NetworkRole::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "roles {names} take a bond this node does not hold in chain state: bond each with a signed \
         Stake transaction from the operator account{} (the validator role with RegisterValidator) \
         or, on a new chain, in the genesis [[role_stakes]], or drop it from --roles",
        operator
            .map(|a| format!(" 0x{}", hex::encode(a.as_bytes())))
            .unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::constants::MIN_RPC_OPERATOR_STAKE;
    use tenzro_types::token::{RoleStake, StakeCapacity};
    use tenzro_vm::StateAdapter;

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
}
