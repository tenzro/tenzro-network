//! DID document service entries in consensus state (see
//! [`tenzro_types::did_services`]). A change applies to the version of the
//! DID's service list it names and carries its root's approval, checked by
//! the one root-approval path every root-signed operation uses.

use tenzro_types::did_services::{
    DidServiceChange, DidServices, IdentityServiceOp, MAX_DID_SERVICES, OP_DID_SERVICE,
};

use super::agent_terms::verify_root_approval;
use super::funding::{read_json, refuse, write_json};
use super::*;

/// Selector of an `IdentityServices` transaction.
pub const SELECTOR_IDENTITY_SERVICES: [u8; 4] = [0x01, 0x00, 0x00, 0xD5];

/// Gas for one service change: a root approval check and one record write.
pub const GAS_IDENTITY_SERVICES: u64 = 60_000;

fn services_key(did: &str) -> String {
    format!("did_services:{did}")
}

/// The service entries `did`'s document publishes, from consensus state.
pub fn read_did_services(state: &dyn VmState, did: &str) -> DidServices {
    read_json(state, &services_key(did)).unwrap_or_default()
}

/// Apply one service change approved by the DID's root.
pub fn apply(
    state: &mut dyn VmState,
    op: &IdentityServiceOp,
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    op.validate().map_err(refuse)?;
    let current = read_did_services(state, &op.did);
    if op.version != current.version {
        return Err(refuse(format!(
            "the change names version {} of {}'s services; the current version is {}",
            op.version, op.did, current.version
        )));
    }
    verify_root_approval(
        state,
        &op.did,
        OP_DID_SERVICE,
        &op.target(),
        &op.approval,
        now_ms.max(0) as u64,
    )
    .map_err(refuse)?;

    let mut next = DidServices {
        version: current.version + 1,
        services: current.services,
    };
    match &op.change {
        DidServiceChange::Set { service } => {
            match next.services.iter_mut().find(|s| s.id == service.id) {
                Some(existing) => *existing = service.clone(),
                None => {
                    if next.services.len() >= MAX_DID_SERVICES {
                        return Err(refuse(format!(
                            "a DID publishes at most {MAX_DID_SERVICES} services"
                        )));
                    }
                    next.services.push(service.clone());
                }
            }
        }
        DidServiceChange::Remove { id } => {
            if !next.services.iter().any(|s| s.id == *id) {
                return Err(refuse(format!("{} publishes no service {id}", op.did)));
            }
            next.services.retain(|s| s.id != *id);
        }
    }
    next.services.sort_by(|a, b| a.id.cmp(&b.id));

    let mut changes = Vec::new();
    write_json(state, &services_key(&op.did), &next, &mut changes)?;
    Ok((changes, Vec::new()))
}
