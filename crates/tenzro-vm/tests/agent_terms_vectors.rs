//! The vectors an off-chain pre-check of agent actions is tested against:
//! `check_action` and `check_asset` verdicts as the VM computes them, the
//! action digests a serving node signs, and state proofs of the Terms and
//! history slots under a real state-trie root, in the shape
//! `tenzro_getStateProof` serves.
//!
//! The test regenerates the vectors and checks them against
//! `sdk/fixtures/agent_terms/vectors.json`; run it with
//! `TENZRO_WRITE_FIXTURES=1` to rewrite the file.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_storage::state_trie::capture::Writes;
use tenzro_storage::{MemoryStore, StateTrie};
use tenzro_types::agent_terms::{
    ActionHistory, AgentAction, AgentBallot, AgentEscrow, AgentPayment, AgentTerms, AssetLimit,
    ServingNode, TermsScope, check_action, check_asset,
};
use tenzro_types::evidence_pack::{STATE_NAMESPACE, vm_storage_key};
use tenzro_types::remote_grant::{RemoteGrantRequest, RemoteTarget};
use tenzro_types::settlement::ReleaseConditions;
use tenzro_types::transaction::{CallVm, VmCall};
use tenzro_vm::native::SYSTEM_ADDRESS;
use tenzro_vm::native::agent_terms::{StoredAgentTerms, terms_key};

const AGENT: &str = "did:tenzro:agent:example";
const MACHINE: &str = "did:tenzro:machine:serving-a";
const PEER: &str = "abababababababababababababababababababab";
const NOW: u64 = 1_700_000_000_000;

fn terms(scope: TermsScope) -> AgentTerms {
    AgentTerms {
        controller_did: "did:tenzro:human:controller".into(),
        agent_name: "example".into(),
        delegation_scope: scope,
        capabilities: vec![],
        serving_nodes: vec![ServingNode {
            machine_did: MACHINE.into(),
            operator_did: "did:tenzro:human:operator".into(),
            ..Default::default()
        }],
        min_distinct_operators: 1,
        expires_at_ms: None,
        trifecta_exception: false,
        auto_approve: None,
        credentials: vec![],
    }
}

fn base_scope() -> TermsScope {
    TermsScope {
        max_transaction_value: Some("1000".into()),
        max_daily_spend: Some("5000".into()),
        allowed_operations: [
            "transfer",
            "pay",
            "create_escrow",
            "refund_escrow",
            "remote_grant",
            "governance.vote",
            "governance.veto_signal",
            "settlement_plan",
            "inference",
        ]
        .map(String::from)
        .to_vec(),
        allowed_chains: vec!["tenzro".into(), "eip155:8453".into()],
        ..Default::default()
    }
}

fn action(operation: &str, amount: u128) -> AgentAction {
    AgentAction {
        agent_did: AGENT.into(),
        machine_did: MACHINE.into(),
        operation: operation.into(),
        counterparty: PEER.into(),
        amount,
        asset: None,
        usd_e6: 0,
        payment: None,
        chain: "tenzro".into(),
        payment_protocol: None,
        model: None,
        calls: vec![],
        escrow: None,
        remote_grant: None,
        ballot: None,
        veto_signal: None,
        nonce: 7,
        tainted: false,
        step_up: None,
    }
}

fn history(
    spent_today: u128,
    spent_this_hour: u128,
    today: u32,
    hour: u32,
    known: bool,
    asset: u128,
) -> ActionHistory {
    ActionHistory {
        spent_today,
        spent_this_hour,
        actions_today: today,
        actions_this_hour: hour,
        known_counterparty: known,
        asset_spent_today: asset,
        ..Default::default()
    }
}

fn payment() -> AgentPayment {
    AgentPayment {
        payment_id: "run-1/step-2".into(),
        request_digest: [0x11; 32],
        quote_digest: [0x22; 32],
    }
}

fn cases() -> Vec<(
    &'static str,
    AgentTerms,
    AgentAction,
    ActionHistory,
    bool,
    u64,
)> {
    let none = ActionHistory::default();
    let mut out = Vec::new();
    let mut push = |name, t, a, h, s, now| out.push((name, t, a, h, s, now));

    push(
        "within terms",
        terms(base_scope()),
        action("transfer", 100),
        none,
        false,
        NOW,
    );
    push(
        "operation not listed",
        terms(base_scope()),
        action("stake", 1),
        none,
        false,
        NOW,
    );
    push(
        "operation in another letter case is refused",
        terms(base_scope()),
        action("TRANSFER", 1),
        none,
        false,
        NOW,
    );
    let mut a = action("transfer", 1);
    a.machine_did = "did:tenzro:machine:other".into();
    push(
        "machine not a serving node",
        terms(base_scope()),
        a,
        none,
        false,
        NOW,
    );
    push(
        "per-transaction limit",
        terms(base_scope()),
        action("transfer", 1001),
        none,
        false,
        NOW,
    );
    push(
        "daily limit",
        terms(base_scope()),
        action("transfer", 600),
        history(4500, 0, 0, 0, true, 0),
        false,
        NOW,
    );
    let mut s = base_scope();
    s.max_hourly_spend = Some("300".into());
    s.max_actions_per_hour = Some(5);
    s.max_actions_per_day = Some(20);
    push(
        "hourly limit",
        terms(s.clone()),
        action("transfer", 200),
        history(0, 200, 0, 0, true, 0),
        false,
        NOW,
    );
    push(
        "actions per hour",
        terms(s.clone()),
        action("transfer", 1),
        history(0, 0, 0, 5, true, 0),
        false,
        NOW,
    );
    push(
        "actions per day",
        terms(s.clone()),
        action("transfer", 1),
        history(0, 0, 20, 0, true, 0),
        false,
        NOW,
    );
    let mut s = base_scope();
    s.allowed_hours_utc = Some([22, 6]);
    push(
        "hours window wraps midnight (inside)",
        terms(s.clone()),
        action("transfer", 1),
        none,
        false,
        NOW,
    );
    push(
        "hours window (outside)",
        terms(s),
        action("transfer", 1),
        none,
        false,
        NOW + 8 * 3_600_000,
    );
    let mut t = terms(base_scope());
    t.expires_at_ms = Some(NOW);
    push("expired terms", t, action("transfer", 1), none, false, NOW);
    let mut a = action("transfer", 1);
    a.chain = "solana:mainnet".into();
    push("chain not listed", terms(base_scope()), a, none, false, NOW);
    let mut s = base_scope();
    s.allowed_counterparties = vec!["0xABABABABABABABABABABABABABABABABABABABAB".into()];
    push(
        "listed counterparty, other case and prefix",
        terms(s.clone()),
        action("transfer", 1),
        none,
        false,
        NOW,
    );
    let mut a = action("transfer", 1);
    a.counterparty = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".into();
    push("counterparty not listed", terms(s), a, none, false, NOW);
    let mut s = base_scope();
    s.allowed_models = vec!["qwen3.5-4b".into()];
    let mut a = action("inference", 0);
    a.counterparty.clear();
    a.model = Some("other-model".into());
    push(
        "model not listed",
        terms(s.clone()),
        a.clone(),
        none,
        false,
        NOW,
    );
    a.model = Some("QWEN3.5-4B".into());
    push("model listed", terms(s), a, none, false, NOW);
    let mut s = base_scope();
    s.allowed_payment_protocols = vec!["mpp".into()];
    let mut a = action("transfer", 1);
    a.payment_protocol = Some("x402".into());
    push("payment protocol not listed", terms(s), a, none, false, NOW);
    let mut s = base_scope();
    s.step_up_above = Some("500".into());
    s.step_up_new_counterparty = true;
    push(
        "step-up above threshold",
        terms(s.clone()),
        action("transfer", 501),
        history(0, 0, 0, 0, true, 0),
        false,
        NOW,
    );
    push(
        "step-up above threshold, stepped up",
        terms(s.clone()),
        action("transfer", 501),
        none,
        true,
        NOW,
    );
    push(
        "step-up new counterparty",
        terms(s.clone()),
        action("transfer", 10),
        none,
        false,
        NOW,
    );
    push(
        "known counterparty",
        terms(s),
        action("transfer", 10),
        history(0, 0, 0, 0, true, 0),
        false,
        NOW,
    );
    let mut s = base_scope();
    s.tainted_value_limit = Some("50".into());
    let mut a = action("transfer", 60);
    a.tainted = true;
    push(
        "tainted over limit",
        terms(s.clone()),
        a.clone(),
        history(0, 0, 0, 0, true, 0),
        false,
        NOW,
    );
    a.amount = 40;
    push(
        "tainted new counterparty",
        terms(s.clone()),
        a.clone(),
        none,
        false,
        NOW,
    );
    push(
        "tainted within limit, known",
        terms(s),
        a,
        history(0, 0, 0, 0, true, 0),
        false,
        NOW,
    );
    let mut s = base_scope();
    s.max_transaction_value = Some("01000".into());
    push(
        "non-canonical limit",
        terms(s),
        action("transfer", 1),
        none,
        false,
        NOW,
    );

    let mut a = action("pay", 100);
    a.payment = Some(payment());
    a.payment_protocol = Some("mpp".into());
    push(
        "pay with payment",
        terms(base_scope()),
        a.clone(),
        none,
        false,
        NOW,
    );
    let mut b = a.clone();
    b.payment = None;
    push(
        "pay without payment",
        terms(base_scope()),
        b,
        none,
        false,
        NOW,
    );
    let mut b = a.clone();
    b.amount = 0;
    push("pay of zero", terms(base_scope()), b, none, false, NOW);
    let mut b = a;
    b.payment.as_mut().unwrap().request_digest = [0; 32];
    push(
        "pay with empty request digest",
        terms(base_scope()),
        b,
        none,
        false,
        NOW,
    );

    let mut a = action("create_escrow", 100);
    a.escrow = Some(AgentEscrow::Create {
        expires_at_ms: NOW + 3_600_000,
        release_conditions: ReleaseConditions::BothSignatures,
        reference: None,
    });
    push("create escrow", terms(base_scope()), a, none, false, NOW);
    let mut a = action("refund_escrow", 0);
    a.escrow = Some(AgentEscrow::Refund {
        escrow_id: [0x33; 32],
    });
    push(
        "refund escrow",
        terms(base_scope()),
        a.clone(),
        none,
        false,
        NOW,
    );
    a.amount = 5;
    push(
        "refund escrow with amount",
        terms(base_scope()),
        a,
        none,
        false,
        NOW,
    );
    push(
        "escrow operation without escrow",
        terms(base_scope()),
        action("create_escrow", 1),
        none,
        false,
        NOW,
    );

    let mut a = action("remote_grant", 0);
    a.counterparty.clear();
    a.chain = "eip155:8453".into();
    a.remote_grant = Some(RemoteGrantRequest {
        caip19: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
        budget: 1_000_000,
        per_action_max: 250_000,
        ttl_ms: 600_000,
        targets: vec![RemoteTarget {
            target: vec![0x83; 20],
            selector: vec![0xa9, 0x05, 0x9c, 0xbb],
        }],
        payload_hash: Some([0x44; 32]),
        relay_fee_max: 1_000,
    });
    push(
        "remote grant",
        terms(base_scope()),
        a.clone(),
        none,
        false,
        NOW,
    );
    a.chain = "eip155:1".into();
    push(
        "remote grant on an unlisted chain",
        terms(base_scope()),
        a,
        none,
        false,
        NOW,
    );

    let mut a = action("governance.vote", 0);
    a.counterparty.clear();
    a.ballot = Some(AgentBallot {
        proposal_id: "prop-9".into(),
        in_favour: true,
        validator: "did:tenzro:validator:v".into(),
    });
    push("ballot", terms(base_scope()), a, none, false, NOW);
    let mut a = action("governance.veto_signal", 10);
    a.counterparty.clear();
    a.veto_signal = Some("prop-9".into());
    push("veto signal", terms(base_scope()), a, none, false, NOW);
    let mut a = action("settlement_plan", 10);
    push(
        "settlement plan with counterparty",
        terms(base_scope()),
        a.clone(),
        none,
        false,
        NOW,
    );
    a.counterparty.clear();
    push(
        "settlement plan",
        terms(base_scope()),
        a.clone(),
        none,
        false,
        NOW,
    );
    a.asset = Some("usdc".into());
    a.usd_e6 = 10;
    push(
        "settlement plan in an unlisted asset",
        terms(base_scope()),
        a.clone(),
        none,
        false,
        NOW,
    );
    let mut s = base_scope();
    s.asset_limits = vec![AssetLimit {
        min_counterparty_kyc_tier: 0,
        asset: "usdc".into(),
        max_per_tx: Some("5".into()),
        max_per_day: "1000".into(),
    }];
    push(
        "settlement plan over its asset limit",
        terms(s),
        a,
        none,
        false,
        NOW,
    );

    let mut a = action("transfer", 0);
    a.counterparty.clear();
    a.calls = vec![
        VmCall {
            vm: CallVm::Evm,
            to: vec![0xaa; 20],
            value: 5,
            data: vec![1, 2, 3],
        },
        VmCall {
            vm: CallVm::Svm,
            to: vec![0xbb; 32],
            value: 0,
            data: vec![],
        },
    ];
    push("vm calls", terms(base_scope()), a.clone(), none, false, NOW);
    a.asset = Some("USDC".into());
    push("asset with calls", terms(base_scope()), a, none, false, NOW);

    let mut s = base_scope();
    s.asset_limits = vec![AssetLimit {
        min_counterparty_kyc_tier: 0,
        asset: "usdc".into(),
        max_per_tx: Some("300".into()),
        max_per_day: "1000".into(),
    }];
    let mut a = action("transfer", 200);
    a.asset = Some("USDC".into());
    a.usd_e6 = 200_000_000;
    push(
        "asset within limits",
        terms(s.clone()),
        a.clone(),
        history(0, 0, 0, 0, true, 700),
        false,
        NOW,
    );
    push(
        "asset daily limit",
        terms(s.clone()),
        a.clone(),
        history(0, 0, 0, 0, true, 900),
        false,
        NOW,
    );
    let mut b = a.clone();
    b.amount = 301;
    push(
        "asset per-transaction limit",
        terms(s.clone()),
        b,
        none,
        false,
        NOW,
    );
    let mut b = a.clone();
    b.usd_e6 = 0;
    push(
        "asset without a price",
        terms(s.clone()),
        b,
        none,
        false,
        NOW,
    );
    let mut b = a;
    b.asset = Some("DAI".into());
    push("asset without a limit", terms(s), b, none, false, NOW);
    let mut a = action("transfer", u64::MAX as u128);
    let mut s = base_scope();
    s.max_transaction_value = Some(u64::MAX.to_string());
    s.max_daily_spend = None;
    a.nonce = u64::MAX;
    push(
        "amount beyond 2^53 at the limit",
        terms(s),
        a,
        none,
        false,
        NOW,
    );
    let mut s = base_scope();
    s.counterparty_kyc = Some(tenzro_types::agent_terms::KycRequirement {
        min_tier: 2,
        registry: "11".repeat(32),
    });
    s.asset_limits = vec![AssetLimit {
        asset: "0x".to_string() + &"22".repeat(32),
        max_per_tx: None,
        max_per_day: "500".into(),
        min_counterparty_kyc_tier: 1,
    }];
    s.max_split_fee_bps = Some(150);
    push(
        "kyc and split fee bounds",
        terms(s),
        action("settlement_plan", 1),
        none,
        false,
        NOW,
    );
    out
}

fn verdict(r: Result<(), &str>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(d) => d.into(),
    }
}

fn check_action_vectors() -> Value {
    let vectors: Vec<Value> = cases()
        .into_iter()
        .map(|(name, t, a, h, stepped_up, now)| {
            json!({
                "name": name,
                "terms": t,
                "action": a,
                "history": {
                    "spent_today": h.spent_today.to_string(),
                    "spent_this_hour": h.spent_this_hour.to_string(),
                    "actions_today": h.actions_today,
                    "actions_this_hour": h.actions_this_hour,
                    "known_counterparty": h.known_counterparty,
                    "asset_spent_today": h.asset_spent_today.to_string(),
                },
                "stepped_up": stepped_up,
                "now_ms": now,
                "expect": verdict(check_action(&t, &a, &h, stepped_up, now)),
                "expect_asset": verdict(check_asset(&t, &a, h.asset_spent_today)),
                "digest": hex::encode(a.digest()),
                "target": {
                    "delegate": hex::encode(t.target(None)),
                    "update": hex::encode(t.target(Some(false))),
                    "update_rotate": hex::encode(t.target(Some(true))),
                },
            })
        })
        .collect();
    json!(vectors)
}

fn slot_key(slot: &str) -> Vec<u8> {
    vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes())
}

fn proof_vectors() -> Value {
    let stored = StoredAgentTerms {
        terms: terms(base_scope()),
        root: tenzro_types::agent_terms::RootKind::Passkey,
        version: 3,
        approval_digest: "aa".repeat(32),
        updated_at_ms: NOW as i64,
        renewed_at_ms: None,
    };
    let day = NOW / 86_400_000;
    let slots = [
        (terms_key(AGENT), serde_json::to_vec(&stored).unwrap()),
        (
            format!("agent_spent:{AGENT}:{day}"),
            serde_json::to_vec(&"4500").unwrap(),
        ),
        (
            format!("agent_acts:{AGENT}:{day}"),
            serde_json::to_vec(&12u32).unwrap(),
        ),
        (
            format!("agent_act_nonce:{AGENT}"),
            serde_json::to_vec(&7u64).unwrap(),
        ),
        (
            format!("agent_paid:{AGENT}:{PEER}"),
            serde_json::to_vec(&true).unwrap(),
        ),
    ];
    let trie = StateTrie::new(Arc::new(MemoryStore::new()));
    let mut writes = Writes::new();
    for (slot, value) in &slots {
        writes.insert(
            (STATE_NAMESPACE.to_string(), slot_key(slot)),
            Some(value.clone()),
        );
    }
    for i in 0..64u32 {
        writes.insert(
            (
                STATE_NAMESPACE.to_string(),
                slot_key(&format!("filler:{i}")),
            ),
            Some(i.to_be_bytes().to_vec()),
        );
    }
    let root = trie.commit(1, &writes).unwrap();
    let prove = |slot: &str| {
        let (value, proof) = trie.prove(1, STATE_NAMESPACE, &slot_key(slot)).unwrap();
        json!({
            "slot": slot,
            "key": hex::encode(slot_key(slot)),
            "served": {
                "height": 1,
                "state_root": hex::encode(root.as_bytes()),
                "value": value.map(hex::encode),
                "proof": proof,
            },
        })
    };
    let mut out: Vec<Value> = slots.iter().map(|(slot, _)| prove(slot)).collect();
    out.push(prove(&terms_key("did:tenzro:agent:revoked")));
    out.push(prove(&format!(
        "agent_spent_hour:{AGENT}:{}",
        NOW / 3_600_000
    )));
    json!(out)
}

#[test]
fn the_agent_terms_vectors_are_current() {
    let doc = json!({
        "source": "tenzro-types agent_terms::{check_action, check_asset, AgentAction::digest} as the VM runs them; state proofs from tenzro-storage StateTrie::prove",
        "system_address": hex::encode(SYSTEM_ADDRESS),
        "state_namespace": STATE_NAMESPACE,
        "check_action": check_action_vectors(),
        "state_proofs": proof_vectors(),
    });
    let path = format!(
        "{}/../../sdk/fixtures/agent_terms/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        on_disk, text,
        "sdk/fixtures/agent_terms/vectors.json is stale: rerun with TENZRO_WRITE_FIXTURES=1"
    );
}
