//! The chain's protocol version in state, raised by an enacted protocol
//! upgrade at its activation height. The upgrade mechanism itself is covered,
//! unchanged, by `upgrade_tests`.

use super::upgrade_tests::{CODE, execute_data, network, queued, ready_data, tx, upgrade};
use super::*;
use crate::governance::PolicyTrack;
use crate::state_adapter::StateAdapter;

fn genesis_version(state: &mut StateAdapter, version: u32) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        PROTOCOL_VERSION_KEY.as_bytes(),
        genesis_protocol_version(version).unwrap(),
    );
}

async fn enact(
    ex: &NativeExecutor,
    state: &mut StateAdapter,
    vs: &[super::upgrade_tests::Validator],
    id: [u8; 32],
    version: &str,
    code: [u8; 32],
    at_height: Option<u64>,
) -> ExecutionResult {
    let mut action = upgrade(PolicyTrack::Standard);
    if let crate::governance::ProposalAction::PolicyUpdate {
        update:
            tenzro_types::token::PolicyUpdate::ProtocolUpgrade {
                version: v,
                code_hash,
            },
        ..
    } = &mut action
    {
        *v = version.into();
        *code_hash = code.to_vec();
    }
    queued(state, id, action);
    for v in vs {
        ex.execute_transaction(&tx(&v.addr, ready_data(v, &code, &code), 1), state)
            .await
            .unwrap();
    }
    let mut t = tx(&vs[0].addr, execute_data(&id), 3);
    if let Some(h) = at_height {
        t.block_height = Some(h);
    }
    ex.execute_transaction(&t, state).await.unwrap()
}

#[tokio::test]
async fn the_protocol_version_rises_at_the_activation_height_and_never_falls() {
    let (ex, mut state, vs) = network();
    genesis_version(&mut state, 2);
    assert_eq!(protocol_version_at(&state, 0), Some(2));

    let r = enact(&ex, &mut state, &vs, [0xaa; 32], "3.1.0", CODE, None).await;
    assert!(r.logs.iter().any(|l| l.topics[0] == PROTOCOL_VERSION_TOPIC));
    let at = read_upgrade_activation(&state).unwrap().activation_height;
    assert_eq!(protocol_version_at(&state, at - 1), Some(2));
    assert_eq!(protocol_version_at(&state, at), Some(3));
    assert_eq!(protocol_version_at(&state, at + 1_000), Some(3));

    // A later upgrade naming a lower major does not take the chain back.
    enact(
        &ex,
        &mut state,
        &vs,
        [0xbb; 32],
        "2.9.0",
        [0x44; 32],
        Some(at + 10),
    )
    .await;
    let at2 = read_upgrade_activation(&state).unwrap().activation_height;
    assert_eq!(protocol_version_at(&state, at2), Some(3));
}

#[tokio::test]
async fn a_chain_without_a_recorded_version_records_none() {
    let (ex, mut state, vs) = network();
    assert_eq!(protocol_version_at(&state, 0), None);
    let r = enact(&ex, &mut state, &vs, [0xaa; 32], "3.0.0", CODE, None).await;
    assert!(!r.logs.iter().any(|l| l.topics[0] == PROTOCOL_VERSION_TOPIC));
    assert_eq!(protocol_version_at(&state, u64::MAX), None);
}
