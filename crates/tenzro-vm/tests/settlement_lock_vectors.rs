//! The shared vectors every chain's settlement lock is tested against: plan
//! and leg ids, decision commitments as the VM writes them at
//! `decision:<plan_id>`, leg receipts as it writes them at `plr:<leg_id>`, and
//! their state proofs under real state-trie roots.
//!
//! The test regenerates the vectors and checks them against
//! `sdk/fixtures/settlement_lock/vectors.json`; run it with
//! `TENZRO_WRITE_FIXTURES=1` to rewrite them.

use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_storage::state_trie::capture::Writes;
use tenzro_storage::{MemoryStore, StateTrie};
use tenzro_types::primitives::Address;
use tenzro_types::settlement::{LegClass, LegReceipt, decision_commitment, leg_id, plan_id};

const CHAIN: u64 = 1337;
const DECIDED_AT_MS: u64 = 1_800_000_000_000;

fn record_key(plan: &[u8; 32]) -> Vec<u8> {
    let key = format!("decision:{}", hex::encode(plan));
    format!(
        "storage:{}:{}",
        hex::encode([0xFFu8; 20]),
        hex::encode(key.as_bytes())
    )
    .into_bytes()
}

fn tree_key(plan: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro.state-trie.key");
    h.update(5u16.to_le_bytes());
    h.update(b"state");
    h.update(record_key(plan));
    h.finalize().into()
}

fn x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn vectors() -> Value {
    let payer = Address::new([0x07; 32]);
    let committed = plan_id(CHAIN, &payer, &[0x09; 32], 1);
    let aborted = plan_id(CHAIN, &payer, &[0x09; 32], 2);
    let undecided = plan_id(CHAIN, &payer, &[0x09; 32], 3);
    let commit = decision_commitment(&committed, true, DECIDED_AT_MS);
    let abort = decision_commitment(&aborted, false, DECIDED_AT_MS + 1);

    let trie = StateTrie::new(Arc::new(MemoryStore::new()));
    let mut w = Writes::new();
    for i in 0..64u32 {
        w.insert(
            ("state".into(), format!("storage:filler:{i}").into_bytes()),
            Some(i.to_be_bytes().to_vec()),
        );
    }
    w.insert(
        ("state".into(), record_key(&committed)),
        Some(commit.to_vec()),
    );
    w.insert(("state".into(), record_key(&aborted)), Some(abort.to_vec()));
    let root = trie.commit(1, &w).unwrap();
    let prove = |plan: &[u8; 32]| {
        let (value, proof) = trie.prove(1, "state", &record_key(plan)).unwrap();
        (value, x(&proof.encode()))
    };
    let (v_commit, p_commit) = prove(&committed);
    let (v_abort, p_abort) = prove(&aborted);
    let (v_none, p_none) = prove(&undecided);
    assert_eq!(v_commit.as_deref(), Some(commit.as_slice()));
    assert_eq!(v_abort.as_deref(), Some(abort.as_slice()));
    assert!(v_none.is_none());

    let plan = |id: &[u8; 32], decision: Option<&[u8]>, proof: &str| {
        json!({
            "plan_id": x(id),
            "leg_ids": (0..3u8).map(|i| x(&leg_id(id, i))).collect::<Vec<_>>(),
            "tree_key": x(&tree_key(id)),
            "decision": decision.map(x),
            "proof": proof,
        })
    };
    json!({
        "root": root.to_string(),
        "committed": plan(&committed, Some(&commit), &p_commit),
        "aborted": plan(&aborted, Some(&abort), &p_abort),
        "undecided": plan(&undecided, None, &p_none),
    })
}

#[test]
fn settlement_lock_vectors_match_the_fixture() {
    let path = format!(
        "{}/../../sdk/fixtures/settlement_lock/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = serde_json::to_string_pretty(&vectors()).unwrap() + "\n";
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        on_disk, text,
        "sdk/fixtures/settlement_lock/vectors.json is stale: rerun with TENZRO_WRITE_FIXTURES=1"
    );
}

fn receipt_record_key(leg: &[u8; 32]) -> Vec<u8> {
    let key = format!("plr:{}", hex::encode(leg));
    format!(
        "storage:{}:{}",
        hex::encode([0xFFu8; 20]),
        hex::encode(key.as_bytes())
    )
    .into_bytes()
}

fn receipt_tree_key(leg: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro.state-trie.key");
    h.update(5u16.to_le_bytes());
    h.update(b"state");
    h.update(receipt_record_key(leg));
    h.finalize().into()
}

/// Leg receipts as the VM writes them at `plr:<leg_id>`, with their state
/// proofs: what a contract on another chain checks before it relies on a
/// leg's outcome or its relayer's repaid network fee.
fn receipt_vectors() -> Value {
    let payer = Address::new([0x07; 32]);
    let plan = plan_id(CHAIN, &payer, &[0x09; 32], 4);
    let committed = LegReceipt {
        plan_id: plan,
        leg_id: leg_id(&plan, 1),
        index: 1,
        committed: true,
        class_achieved: Some(LegClass::Proven),
        amount: 5_000_000_000_000_000_000,
        proof_digest: Some([0xf1; 32]),
        decided_at_ms: DECIDED_AT_MS,
        compensation: None,
        network_fee: 10_000_000_000_000_000,
        relayer: Some(Address::new([0x05; 32])),
    };
    let aborted = LegReceipt {
        plan_id: plan,
        leg_id: leg_id(&plan, 2),
        index: 2,
        committed: false,
        class_achieved: None,
        amount: 7,
        proof_digest: None,
        decided_at_ms: DECIDED_AT_MS,
        compensation: Some(3),
        network_fee: 0,
        relayer: None,
    };
    let absent = leg_id(&plan, 3);

    let trie = StateTrie::new(Arc::new(MemoryStore::new()));
    let mut w = Writes::new();
    for i in 0..64u32 {
        w.insert(
            ("state".into(), format!("storage:filler:{i}").into_bytes()),
            Some(i.to_be_bytes().to_vec()),
        );
    }
    for r in [&committed, &aborted] {
        w.insert(
            ("state".into(), receipt_record_key(&r.leg_id)),
            Some(r.encode().to_vec()),
        );
    }
    let root = trie.commit(1, &w).unwrap();
    let entry = |leg: &[u8; 32], receipt: Option<&LegReceipt>| {
        let (value, proof) = trie.prove(1, "state", &receipt_record_key(leg)).unwrap();
        assert_eq!(value, receipt.map(|r| r.encode().to_vec()));
        if let Some(r) = receipt {
            assert_eq!(LegReceipt::decode(&r.encode()).as_ref(), Some(r));
        }
        json!({
            "leg_id": x(leg),
            "tree_key": x(&receipt_tree_key(leg)),
            "receipt": receipt.map(|r| x(&r.encode())),
            "network_fee": receipt.map(|r| r.network_fee.to_string()),
            "amount": receipt.map(|r| r.amount.to_string()),
            "relayer": receipt.and_then(|r| r.relayer).map(|a| x(a.as_bytes())),
            "proof": x(&proof.encode()),
        })
    };
    json!({
        "root": root.to_string(),
        "plan_id": x(&plan),
        "committed": entry(&committed.leg_id, Some(&committed)),
        "aborted": entry(&aborted.leg_id, Some(&aborted)),
        "absent": entry(&absent, None),
    })
}

#[test]
fn leg_receipt_vectors_match_the_fixture() {
    let path = format!(
        "{}/../../sdk/fixtures/settlement_lock/leg_receipts.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = serde_json::to_string_pretty(&receipt_vectors()).unwrap() + "\n";
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::write(&path, text).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        on_disk, text,
        "sdk/fixtures/settlement_lock/leg_receipts.json is stale: rerun with TENZRO_WRITE_FIXTURES=1"
    );
}

/// Every lock family folds its entries into the same running hash; the
/// fixture `recon.json` lists entries over the shared plans with the hash
/// after each, and the fold reproduces every one of them.
#[test]
fn the_reconciliation_hash_matches_the_fixture() {
    use tenzro_types::settlement::{ReconKind, leg_id, recon_step};
    let path = format!(
        "{}/../../sdk/fixtures/settlement_lock/recon.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let h32 = |v: &Value| -> [u8; 32] {
        hex::decode(&v.as_str().unwrap()[2..])
            .unwrap()
            .try_into()
            .unwrap()
    };
    let mut acc = [0u8; 32];
    let entries = fixture["entries"].as_array().unwrap();
    for e in entries {
        let plan = h32(&e["plan_id"]);
        let leg = leg_id(&plan, e["index"].as_u64().unwrap() as u8);
        assert_eq!(leg, h32(&e["leg_id"]));
        let kind = match e["kind"].as_u64().unwrap() {
            1 => ReconKind::Locked,
            2 => ReconKind::Released,
            3 => ReconKind::Refunded,
            k => panic!("kind {k}"),
        };
        acc = recon_step(
            &acc,
            &plan,
            &leg,
            kind,
            e["amount"].as_str().unwrap().parse().unwrap(),
        );
        assert_eq!(acc, h32(&e["acc"]));
    }
    assert_eq!(entries.len() as u64, fixture["count"].as_u64().unwrap());
    assert_eq!(acc, h32(&fixture["acc"]));
}
