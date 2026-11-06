//! The requests `tenzro_types::account_outflow_ui` builds are exactly what the
//! VM's `account_outflow::Op` reads, so a wallet and the chain cannot drift
//! apart.

use tenzro_types::account_outflow_ui::OutflowRequest;
use tenzro_vm::account_outflow::Op;

const ACCOUNT: [u8; 32] = [0xa1; 32];

#[test]
fn every_request_a_wallet_builds_reads_back_as_the_vms_op() {
    let guardian = "did:tenzro:human:g1".to_string();
    let cases = vec![
        OutflowRequest::Set {
            window_ms: 86_400_000,
            cap: 10_000_000_000_000_000_000,
            hold_ms: 3_600_000,
            guardian: Some(guardian.clone()),
        },
        OutflowRequest::Set {
            window_ms: 86_400_000,
            cap: 1,
            hold_ms: 3_600_000,
            guardian: None,
        },
        OutflowRequest::Remove,
        OutflowRequest::CancelPending { approval: None },
        OutflowRequest::RequestRelease {
            to: vec![0xb1; 32],
            amount: 5,
        },
        OutflowRequest::CancelRelease {
            id: 7,
            approval: None,
        },
        OutflowRequest::ClaimRelease {
            id: 7,
            approval: None,
        },
    ];
    for c in cases {
        let op: Op = serde_json::from_slice(&c.op_json(&ACCOUNT))
            .unwrap_or_else(|e| panic!("{c:?} does not read back: {e}"));
        match (&c, &op) {
            (
                OutflowRequest::Set { cap, guardian, .. },
                Op::Set {
                    cap: c2,
                    guardian: g2,
                    account,
                    ..
                },
            ) => {
                assert_eq!(cap, c2);
                assert_eq!(guardian, g2);
                assert_eq!(account, &ACCOUNT.to_vec());
            }
            (OutflowRequest::Remove, Op::Remove { .. })
            | (OutflowRequest::CancelPending { .. }, Op::CancelPending { .. }) => {}
            (
                OutflowRequest::RequestRelease { amount, .. },
                Op::RequestRelease { amount: a2, .. },
            ) => assert_eq!(amount, a2),
            (OutflowRequest::CancelRelease { id, .. }, Op::CancelRelease { id: i2, .. })
            | (OutflowRequest::ClaimRelease { id, .. }, Op::ClaimRelease { id: i2, .. }) => {
                assert_eq!(id, i2)
            }
            other => panic!("wrong operation: {other:?}"),
        }
    }
}

#[test]
fn the_guardian_approval_target_matches_the_chains() {
    for (action, id, step) in [
        ("cancel_pending", 0, 0),
        ("cancel_release", 3, 9),
        ("claim_release", 7, 1),
    ] {
        assert_eq!(
            tenzro_types::account_outflow_ui::approval_target(&ACCOUNT, action, id, step),
            tenzro_vm::account_outflow::approval_target(&ACCOUNT, action, id, step)
        );
    }
}
