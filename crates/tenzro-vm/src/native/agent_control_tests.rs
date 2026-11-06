//! Who may stop a delegated agent. Pause, quarantine, terminate, lift and
//! revoke answer to the controller the agent's terms name, from the wallet
//! its identity is registered with. Anyone else reaches a quarantine only
//! through a finding the validator quorum stands behind.

use super::agent_terms::tests::Agent;
use super::*;
use crate::VmConfig;
use crate::VmType;
use crate::state_adapter::StateAdapter;
use tenzro_types::agent_audit::AuditFinding;
use tenzro_types::agent_terms::TermsScope;

const CHAIN: u64 = 1337;
const TNZO: u128 = 1_000_000_000_000_000_000;
const CONTROLLER_WALLET: [u8; 32] = [0xC0; 32];
const MALLORY_WALLET: [u8; 32] = [0x51; 32];
const MALLORY: &str = "did:tenzro:human:mallory";
const BONDED_WALLET: [u8; 32] = [0x52; 32];

/// A termed agent whose controller's identity is registered with
/// CONTROLLER_WALLET, a stranger MALLORY registered with MALLORY_WALLET, and
/// an account BONDED_WALLET with 1 TNZO of bonded stake and no identity.
fn world() -> (Agent, String) {
    let mut a = Agent::new(TermsScope {
        max_daily_spend: Some("100".into()),
        allowed_operations: vec!["transfer".into()],
        ..Default::default()
    });
    let controller = agent_terms::read_agent_terms(&a.state, &a.did)
        .unwrap()
        .terms
        .controller_did;
    for (wallet, did) in [
        (CONTROLLER_WALLET, controller.as_str()),
        (MALLORY_WALLET, MALLORY),
    ] {
        a.state.set_storage(
            &SYSTEM_ADDRESS,
            identity_wallet_index_key(&wallet).as_bytes(),
            did.as_bytes().to_vec(),
        );
    }
    for w in [CONTROLLER_WALLET, MALLORY_WALLET, BONDED_WALLET] {
        a.state.set_balance(&w, 100 * TNZO);
    }
    bond(&mut a.state, &BONDED_WALLET, TNZO);
    (a, controller)
}

fn bond(state: &mut StateAdapter, who: &[u8], stake: u128) {
    staking::add_bond(state, who, stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    state.set_balance(&STAKING_VAULT_ADDRESS, vault + stake);
}

/// Execute `selector(body)` from `from`; true when it took effect.
async fn send(
    state: &mut StateAdapter,
    from: &[u8],
    selector: [u8; 4],
    body: serde_json::Value,
) -> bool {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut data = selector.to_vec();
    data.extend(serde_json::to_vec(&body).unwrap());
    let mut t = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        5_000_000,
        0,
        state.get_nonce(from),
        VmType::Tenzro,
        CHAIN,
    );
    t.block_timestamp_ms = Some(1_000);
    matches!(ex.execute_transaction(&t, state).await, Ok(r) if r.success)
}

/// [`send`] at block time `at`.
async fn send_at(
    state: &mut StateAdapter,
    from: &[u8],
    selector: [u8; 4],
    body: serde_json::Value,
    at: i64,
) -> bool {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut data = selector.to_vec();
    data.extend(serde_json::to_vec(&body).unwrap());
    let mut t = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        5_000_000,
        0,
        state.get_nonce(from),
        VmType::Tenzro,
        CHAIN,
    );
    t.block_timestamp_ms = Some(at);
    matches!(ex.execute_transaction(&t, state).await, Ok(r) if r.success)
}

fn quarantine(agent: &str, controller: &str, evidence: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "agent_did": agent,
        "controller_did": controller,
        "reason_code": 2,
        "evidence_hash": evidence,
    })
}

fn lift(agent: &str) -> serde_json::Value {
    serde_json::json!({ "agent_did": agent })
}

fn quarantined(a: &Agent) -> bool {
    agent_audit::read_agent_quarantine(&a.state, &a.did).is_some()
}

#[tokio::test]
async fn a_stranger_naming_himself_controller_cannot_quarantine_an_agent() {
    let (mut a, _) = world();
    let did = a.did.clone();
    let body = quarantine(&did, MALLORY, None);
    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_KILLSWITCH_QUARANTINE,
            body
        )
        .await
    );
    assert!(!quarantined(&a));
    a.act(&a.action(10), 0).unwrap();
}

#[tokio::test]
async fn a_bonded_account_with_made_up_evidence_cannot_quarantine_an_agent() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    let evidence = "ab".repeat(32);
    for named in [controller.as_str(), MALLORY] {
        let body = quarantine(&did, named, Some(&evidence));
        assert!(
            !send(
                &mut a.state,
                &BONDED_WALLET,
                SELECTOR_KILLSWITCH_QUARANTINE,
                body
            )
            .await
        );
        let body = quarantine(&did, named, Some(&evidence));
        assert!(
            !send(
                &mut a.state,
                &MALLORY_WALLET,
                SELECTOR_KILLSWITCH_QUARANTINE,
                body
            )
            .await
        );
    }
    assert!(!quarantined(&a));
    a.act(&a.action(10), 0).unwrap();
}

#[tokio::test]
async fn the_controller_quarantines_and_lifts_and_no_one_else_lifts() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    let body = quarantine(&did, &controller, None);
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_KILLSWITCH_QUARANTINE,
            body
        )
        .await
    );
    let q = agent_audit::read_agent_quarantine(&a.state, &did).unwrap();
    assert_eq!(q.controller_did, controller);
    assert!(a.act(&a.action(10), 0).unwrap_err().contains("quarantined"));

    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_LIFT_AGENT_QUARANTINE,
            lift(&did)
        )
        .await
    );
    assert!(
        !send(
            &mut a.state,
            &BONDED_WALLET,
            SELECTOR_LIFT_AGENT_QUARANTINE,
            lift(&did)
        )
        .await
    );
    assert!(quarantined(&a));
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_LIFT_AGENT_QUARANTINE,
            lift(&did)
        )
        .await
    );
    assert!(!quarantined(&a));
    a.act(&a.action(10), 0).unwrap();
}

#[tokio::test]
async fn a_quorum_finding_quarantines_and_the_real_controller_lifts_it() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    let vs = [[1u8; 32], [2u8; 32], [3u8; 32]];
    for v in &vs {
        bond(&mut a.state, v, 100 * TNZO);
        a.state.set_balance(v, 10 * TNZO);
    }
    // The finding names the wrong controller; the record keeps the real one.
    let finding = AuditFinding::QuarantineAgent {
        agent_did: did.clone(),
        controller_did: MALLORY.into(),
        evidence_hash: "cd".repeat(32),
    };
    let body = serde_json::json!({ "epoch": 0, "findings": [finding] });
    assert!(
        send(
            &mut a.state,
            &vs[0],
            SELECTOR_AGENT_AUDIT_FLAG,
            body.clone()
        )
        .await
    );
    assert!(!quarantined(&a), "one validator is not a quorum");
    assert!(
        send(
            &mut a.state,
            &vs[1],
            SELECTOR_AGENT_AUDIT_FLAG,
            body.clone()
        )
        .await
    );
    assert!(send(&mut a.state, &vs[2], SELECTOR_AGENT_AUDIT_FLAG, body).await);
    let q = agent_audit::read_agent_quarantine(&a.state, &did).unwrap();
    assert_eq!(
        (q.by.as_str(), q.controller_did.as_str()),
        ("validators", controller.as_str())
    );
    assert!(a.act(&a.action(10), 0).is_err());

    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_LIFT_AGENT_QUARANTINE,
            lift(&did)
        )
        .await
    );
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_LIFT_AGENT_QUARANTINE,
            lift(&did)
        )
        .await
    );
    assert!(!quarantined(&a));
}

#[tokio::test]
async fn a_stranger_cannot_revoke_an_agent_with_a_made_up_approval() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    let body = serde_json::json!({
        "agent_did": did,
        "controller_did": controller,
        "approval_digest": "ee".repeat(32),
    });
    assert!(
        !send(
            &mut a.state,
            &BONDED_WALLET,
            SELECTOR_REVOKE_DELEGATED_AGENT,
            body.clone()
        )
        .await
    );
    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_REVOKE_DELEGATED_AGENT,
            body.clone()
        )
        .await
    );
    assert!(!quarantined(&a));
    a.act(&a.action(10), 0).unwrap();
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_REVOKE_DELEGATED_AGENT,
            body
        )
        .await
    );
    assert!(a.act(&a.action(10), 0).unwrap_err().contains("revoked"));
}

#[tokio::test]
async fn a_stranger_naming_itself_as_controller_cannot_revoke() {
    let (mut a, _controller) = world();
    let did = a.did.clone();
    for (wallet, named) in [
        (&MALLORY_WALLET, "did:tenzro:human:mallory"),
        (&BONDED_WALLET, "did:tenzro:human:bonded"),
    ] {
        let body = serde_json::json!({
            "agent_did": did,
            "controller_did": named,
            "approval_digest": "ee".repeat(32),
        });
        assert!(!send(&mut a.state, wallet, SELECTOR_REVOKE_DELEGATED_AGENT, body).await);
    }
    assert!(!quarantined(&a));
    a.act(&a.action(10), 0).unwrap();
}

#[tokio::test]
async fn a_stranger_who_posts_the_bond_does_not_gain_the_kill_switch() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    // The stranger posts a bond naming the real controller, then tries to
    // pause and terminate the agent as its bond owner.
    let posted = send(
        &mut a.state,
        &MALLORY_WALLET,
        SELECTOR_POST_AGENT_BOND,
        serde_json::json!({ "agent_did": did, "controller_did": controller, "amount": 10 * TNZO }),
    )
    .await;
    assert!(!posted, "only the controller bonds an agent that has terms");
    let pause =
        serde_json::json!({ "agent_did": did, "controller_did": controller, "reason_code": 1 });
    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_KILLSWITCH_PAUSE,
            pause
        )
        .await
    );
    let terminate = serde_json::json!({
        "agent_did": did, "controller_did": controller, "reason_code": 1, "slash_bps": 0,
    });
    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_KILLSWITCH_TERMINATE,
            terminate
        )
        .await
    );
    assert!(!agent_bond_frozen(&a.state, &did, 2_000));
}

/// The controller approves refills once; anyone then triggers them, and the
/// chain moves no more than the allowance: up to the target, within each
/// period's amount, never to a paused agent, and not once cancelled.
#[tokio::test]
async fn anyone_tops_up_an_agent_within_its_controllers_allowance() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    let wallet = tenzro_types::agent_terms::agent_wallet(&did);
    // The agent starts with nothing of its own, so each refill is exact.
    a.state.set_balance(&wallet, 0);
    let hour = 3_600_000i64;
    let allowance = serde_json::json!({
        "agent_did": did, "controller_did": controller,
        "allowance": {
            "per_period": (5 * TNZO).to_string(), "period_ms": hour,
            "target": (3 * TNZO).to_string(), "expires_at_ms": 100 * hour,
        },
    });
    let topup = serde_json::json!({ "agent_did": did });
    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_SET_AGENT_TOPUP,
            allowance.clone()
        )
        .await
    );
    assert!(
        !send_at(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_TOPUP_AGENT,
            topup.clone(),
            2_000
        )
        .await
    );
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_SET_AGENT_TOPUP,
            allowance
        )
        .await
    );
    // A stranger triggers it; the money comes from the controller.
    assert!(
        send_at(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_TOPUP_AGENT,
            topup.clone(),
            2_000
        )
        .await
    );
    assert_eq!(a.state.get_balance(&wallet), 3 * TNZO);
    assert_eq!(a.state.get_balance(&CONTROLLER_WALLET), 97 * TNZO);
    assert!(
        !send_at(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_TOPUP_AGENT,
            topup.clone(),
            3_000
        )
        .await
    );
    // Spent down: refilled only by what the period has left.
    a.state.set_balance(&wallet, 0);
    assert!(
        send_at(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_TOPUP_AGENT,
            topup.clone(),
            4_000
        )
        .await
    );
    assert_eq!(a.state.get_balance(&wallet), 2 * TNZO);
    assert!(
        !send_at(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_TOPUP_AGENT,
            topup.clone(),
            5_000
        )
        .await
    );
    // The next period refills to the target.
    assert!(
        send_at(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_TOPUP_AGENT,
            topup.clone(),
            hour + 10
        )
        .await
    );
    assert_eq!(a.state.get_balance(&wallet), 3 * TNZO);
    assert_eq!(a.state.get_balance(&CONTROLLER_WALLET), 94 * TNZO);
    // A paused agent is not refilled.
    a.state.set_balance(&wallet, 0);
    let pause =
        serde_json::json!({ "agent_did": did, "controller_did": controller, "reason_code": 1 });
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_KILLSWITCH_PAUSE,
            pause
        )
        .await
    );
    assert!(
        !send_at(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_TOPUP_AGENT,
            topup.clone(),
            2 * hour
        )
        .await
    );
    // Cancelled: nothing more moves.
    let cancel = serde_json::json!({ "agent_did": did, "controller_did": controller });
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_SET_AGENT_TOPUP,
            cancel
        )
        .await
    );
    assert!(read_agent_topup(&a.state, &did).is_none());
    assert_eq!(a.state.get_balance(&CONTROLLER_WALLET), 94 * TNZO);
}

/// The controller takes back what its agent holds, even while the agent is
/// paused; no one else can.
#[tokio::test]
async fn the_controller_reclaims_its_agents_unspent_funds() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    let wallet = tenzro_types::agent_terms::agent_wallet(&did);
    a.state.set_balance(&wallet, 7 * TNZO);
    let pause =
        serde_json::json!({ "agent_did": did, "controller_did": controller, "reason_code": 1 });
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_KILLSWITCH_PAUSE,
            pause
        )
        .await
    );
    let all = serde_json::json!({ "agent_did": did, "controller_did": controller });
    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_RECLAIM_AGENT_FUNDS,
            all.clone()
        )
        .await
    );
    let some = serde_json::json!({
        "agent_did": did, "controller_did": controller, "amount": (2 * TNZO).to_string(),
    });
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_RECLAIM_AGENT_FUNDS,
            some
        )
        .await
    );
    assert_eq!(a.state.get_balance(&wallet), 5 * TNZO);
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_RECLAIM_AGENT_FUNDS,
            all.clone()
        )
        .await
    );
    assert_eq!(a.state.get_balance(&wallet), 0);
    assert_eq!(a.state.get_balance(&CONTROLLER_WALLET), 107 * TNZO);
    assert_eq!(a.state.get_balance(&MALLORY_WALLET), 100 * TNZO);
    // Nothing left: refused.
    assert!(
        !send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_RECLAIM_AGENT_FUNDS,
            all
        )
        .await
    );
}

#[tokio::test]
async fn the_controller_still_pauses_and_terminates() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    let pause =
        serde_json::json!({ "agent_did": did, "controller_did": controller, "reason_code": 1 });
    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_KILLSWITCH_PAUSE,
            pause.clone()
        )
        .await
    );
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_KILLSWITCH_PAUSE,
            pause
        )
        .await
    );
    assert!(agent_bond_frozen(&a.state, &did, 2_000));
    let terminate = serde_json::json!({
        "agent_did": did, "controller_did": controller, "reason_code": 1, "slash_bps": 0,
    });
    let wrong = serde_json::json!({
        "agent_did": did, "controller_did": MALLORY, "reason_code": 1, "slash_bps": 0,
    });
    assert!(
        !send(
            &mut a.state,
            &MALLORY_WALLET,
            SELECTOR_KILLSWITCH_TERMINATE,
            wrong
        )
        .await
    );
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_KILLSWITCH_TERMINATE,
            terminate
        )
        .await
    );
}

/// An allowance always runs out: one that never expires, already expired, or
/// expires past the governed limit is refused; one at the limit is kept.
#[tokio::test]
async fn a_top_up_allowance_must_expire_within_the_governed_limit() {
    let (mut a, controller) = world();
    let did = a.did.clone();
    let day = 86_400_000i64;
    let now = 1_000i64;
    let with_expiry = |expires_at_ms: i64| {
        serde_json::json!({
            "agent_did": did, "controller_did": controller,
            "allowance": {
                "per_period": TNZO.to_string(), "period_ms": day,
                "target": TNZO.to_string(), "expires_at_ms": expires_at_ms,
            },
        })
    };
    for refused in [i64::MAX, now, now + 90 * day + 1] {
        assert!(
            !send(
                &mut a.state,
                &CONTROLLER_WALLET,
                SELECTOR_SET_AGENT_TOPUP,
                with_expiry(refused)
            )
            .await,
            "an allowance expiring at {refused} was kept"
        );
    }
    assert!(
        send(
            &mut a.state,
            &CONTROLLER_WALLET,
            SELECTOR_SET_AGENT_TOPUP,
            with_expiry(now + 90 * day)
        )
        .await
    );
    assert_eq!(
        crate::native::read_agent_topup(&a.state, &did).map(|t| t.expires_at_ms),
        Some(now + 90 * day)
    );
}
