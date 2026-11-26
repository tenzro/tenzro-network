//! `NativeCall`: one transaction kind for native operations.
//!
//! A `NativeCall { selector, data }` reaches the native operation its
//! selector names, but only an operation listed in [`LISTED`]: never a
//! system or privileged selector, which the node reaches by other kinds or
//! not at all from a transaction. The operations' payloads and stateless
//! checks are in `tenzro-native-ops`; the rules that run in consensus stay
//! in each operation's module here.
//!
//! The kind waits for [`GATE`], and each listed operation for its own gate:
//! a call is refused at submission while either is dormant, and refused in
//! a block while [`GATE`] is.

use super::*;

/// The gate of `NativeCall`.
pub const GATE: &str = "feature.native_call.activation_epoch";

/// The selector the node prefixes a `NativeCall` with when it hands the call
/// to the VM: `SELECTOR_NATIVE_CALL || selector || data`.
pub const SELECTOR_NATIVE_CALL: [u8; 4] = [0x01, 0x00, 0x00, 0xF0];

/// The operations a `NativeCall` may name, each with its own gate.
pub const LISTED: &[([u8; 4], &str)] = &[
    (SELECTOR_IDENTITY_KEYS, identity_keys::GATE),
    (SELECTOR_IDENTITY_SUCCESSION, identity_succession::GATE),
    (SELECTOR_BUILD_ATTESTATION, build_attestation::GATE),
    (presence::SELECTOR_PROVIDER_PRESENCE, presence::GATE),
    (SELECTOR_ZK_VERDICT, zk_verdict::GATE),
    (SELECTOR_RPC_PROVIDER, rpc_provider_leg::GATE),
    (bond_onramp::SELECTOR_BOND_WITH_STABLE, bond_onramp::GATE),
    (
        tenzro_native_ops::SELECTOR_GATEWAY_DELIVERY,
        crate::evm::gateway::GATEWAY_KEY,
    ),
];

fn listed_gate(selector: [u8; 4]) -> Option<&'static str> {
    LISTED
        .iter()
        .find(|(s, _)| *s == selector)
        .map(|(_, gate)| *gate)
}

/// The listed operation and its payload a wrapped call carries, while
/// [`GATE`] and the operation's own gate are in force. `body` is what follows [`SELECTOR_NATIVE_CALL`].
pub(super) fn open<'a>(state: &dyn VmState, body: &'a [u8]) -> Result<([u8; 4], &'a [u8])> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Err(VmError::InvalidTransaction(format!(
            "native calls are not in force on this chain yet (they wait for {GATE})"
        )));
    }
    let (selector, data) = body
        .split_first_chunk::<4>()
        .ok_or_else(|| VmError::InvalidTransaction("a native call names a selector".into()))?;
    let gate = listed_gate(*selector).ok_or_else(|| {
        VmError::InvalidTransaction(format!(
            "{} is not an operation a native call may reach",
            hex::encode(selector)
        ))
    })?;
    // Every listed operation waits for its own gate here, so a future one
    // cannot be reached in a block while its gate is dormant by leaving the
    // check out of its own apply.
    if !crate::feature_gate::is_live_now(state, gate) {
        return Err(VmError::InvalidTransaction(format!(
            "this native operation is not in force on this chain yet (it waits for {gate})"
        )));
    }
    Ok((*selector, data))
}

/// Whether a `NativeCall` naming `selector` with `data` is admitted now:
/// the operation is listed, its gate is in force, and its payload passes the
/// operation's stateless check. The kind's own gate is checked with every
/// appended kind ([`crate::feature_gate::refuse_dormant_kind`]).
pub fn admit(
    state: &dyn VmState,
    selector: [u8; 4],
    data: &[u8],
) -> std::result::Result<(), String> {
    let gate = listed_gate(selector).ok_or_else(|| {
        format!(
            "{} is not an operation a native call may reach",
            hex::encode(selector)
        )
    })?;
    if !crate::feature_gate::is_live_now(state, gate) {
        return Err(format!(
            "this native operation is not in force on this chain yet (it waits for {gate})"
        ));
    }
    tenzro_native_ops::check(selector, data)
}

/// The gas a listed operation is estimated at.
pub(super) fn gas(selector: [u8; 4]) -> Option<u64> {
    match selector {
        SELECTOR_IDENTITY_KEYS => Some(identity_keys::GAS_IDENTITY_KEYS),
        SELECTOR_IDENTITY_SUCCESSION => Some(identity_succession::GAS_IDENTITY_SUCCESSION),
        SELECTOR_BUILD_ATTESTATION => Some(build_attestation::GAS_BUILD_ATTESTATION),
        presence::SELECTOR_PROVIDER_PRESENCE => Some(presence::GAS_PROVIDER_PRESENCE),
        SELECTOR_ZK_VERDICT => Some(zk_verdict::GAS_ZK_VERDICT),
        SELECTOR_RPC_PROVIDER => Some(rpc_provider_leg::GAS_RPC_PROVIDER),
        bond_onramp::SELECTOR_BOND_WITH_STABLE => Some(bond_onramp::GAS_BOND_WITH_STABLE),
        // The most a delivery can be charged: the largest payload and the
        // highest delivery gas governance may set.
        tenzro_native_ops::SELECTOR_GATEWAY_DELIVERY => Some(
            bridge::GAS_BRIDGE
                + bridge::GAS_BRIDGE_BYTE
                    * tenzro_types::bridge_transfer::MAX_BRIDGE_PAYLOAD_LEN as u64
                + crate::governance::governed_param(crate::evm::gateway::DELIVERY_GAS_KEY)
                    .map_or(0, |p| p.max),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    fn wrapped(selector: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut body = selector.to_vec();
        body.extend_from_slice(payload);
        body
    }

    /// Only listed operations open, and only once the kind is in force; a
    /// governance selector and an unknown one never do, before or after.
    #[test]
    fn a_native_call_reaches_listed_operations_only() {
        let mut state = StateAdapter::new();
        let listed = wrapped(SELECTOR_BUILD_ATTESTATION, b"{}");
        let governance = wrapped(SELECTOR_GOVERNANCE_EXECUTE, b"{}");
        let unknown = wrapped([0x7f, 0x7f, 0x7f, 0x7f], b"{}");
        for body in [&listed, &governance, &unknown] {
            assert!(open(&state, body).is_err());
        }
        set_governed_param_for_test(&mut state, GATE, 0);
        set_governed_param_for_test(&mut state, build_attestation::GATE, 0);
        let (selector, payload) = open(&state, &listed).unwrap();
        assert_eq!(selector, SELECTOR_BUILD_ATTESTATION);
        assert_eq!(payload, b"{}");
        assert!(open(&state, &governance).is_err());
        assert!(open(&state, &unknown).is_err());
        assert!(open(&state, &[0x01, 0x00]).is_err());
        for selector in [SELECTOR_GOVERNANCE_EXECUTE, [0x7f; 4]] {
            assert!(admit(&state, selector, b"{}").is_err());
        }
    }

    /// Every listed operation has a gas estimate and a gate of its own.
    #[test]
    fn every_listed_operation_has_its_gas_and_its_gate() {
        for (selector, gate) in LISTED {
            assert!(gas(*selector).is_some());
            assert!(crate::governance::governed_param(gate).is_some(), "{gate}");
        }
    }

    /// Every listed operation is refused in a block while the kind's gate is
    /// in force and its own is dormant, and opens once both are.
    #[test]
    fn every_listed_operation_waits_for_its_own_gate() {
        for (selector, gate) in LISTED {
            let mut state = StateAdapter::new();
            set_governed_param_for_test(&mut state, GATE, 0);
            let body = wrapped(*selector, b"{}");
            let refused = open(&state, &body).unwrap_err().to_string();
            assert!(refused.contains(gate), "{gate}: {refused}");
            set_governed_param_for_test(&mut state, gate, 0);
            assert_eq!(open(&state, &body).unwrap().0, *selector, "{gate}");
        }
    }
}
