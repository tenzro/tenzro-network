//! The vectors an off-chain audit log is tested against: entry bodies and
//! leaf hashes, MMR roots and proofs at every size, epoch roots and proofs
//! over the session lines, a full audit proof, and the commit attestation
//! digest, all as `tenzro_types::agent_audit` computes them.
//!
//! The test regenerates the vectors and checks them against
//! `sdk/fixtures/agent_audit/vectors.json`; run it with
//! `TENZRO_WRITE_FIXTURES=1` to rewrite the file.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_types::agent_audit::{
    ActionKind, ActionOutcome, AuditEntry, AuditProof, Digest32, Mmr, SessionLeaf,
    SignedAuditEntry, commit_attestation_digest, detail_digest, epoch_root, prove_epoch,
};

const AGENT: &str = "did:tenzro:agent:example";
const COMMITTER: &str = "did:tenzro:machine:serving-a";
const SESSION: Digest32 = [9; 32];

fn h(tag: &str, i: u64) -> Digest32 {
    Sha256::new()
        .chain_update(tag.as_bytes())
        .chain_update(i.to_le_bytes())
        .finalize()
        .into()
}

/// A deterministic stand-in for the serving node's signature; the leaf hash
/// covers it, so the vectors fix it rather than a key.
fn signature(seq: u64) -> Vec<u8> {
    let a = h("sig-a", seq);
    let b = h("sig-b", seq);
    [a, b].concat()
}

fn session() -> Vec<SignedAuditEntry> {
    let steps: [(ActionKind, &str, ActionOutcome, Option<&str>); 6] = [
        (ActionKind::ToolCall, "fetch", ActionOutcome::Allowed, None),
        (
            ActionKind::Egress,
            "api.example.org:443",
            ActionOutcome::Refused("not in terms".into()),
            None,
        ),
        (
            ActionKind::Spend,
            "transfer",
            ActionOutcome::Allowed,
            Some("0xabc123"),
        ),
        (
            ActionKind::ModelCall,
            "chat \"quoted\" \u{e9}",
            ActionOutcome::Pending("step-up".into()),
            None,
        ),
        (
            ActionKind::GrantUse,
            "read /data",
            ActionOutcome::Allowed,
            None,
        ),
        (
            ActionKind::Violation,
            "rate",
            ActionOutcome::Refused("hourly cap".into()),
            None,
        ),
    ];
    let mut prev = [0u8; 32];
    let mut out = Vec::new();
    for (seq, (kind, action, outcome, linked_tx)) in steps.into_iter().enumerate() {
        let seq = seq as u64;
        let entry = AuditEntry {
            session_id: SESSION,
            seq,
            at_ms: 1_700_000_000_000 + seq * 250,
            agent: AGENT.into(),
            kind,
            action: action.into(),
            outcome,
            detail: detail_digest(format!("args-{seq}").as_bytes()),
            linked_tx: linked_tx.map(Into::into),
            prev,
            image: None,
            call: None,
        };
        let signed = SignedAuditEntry {
            body: serde_json::to_vec(&entry).unwrap(),
            signature: signature(seq),
        };
        prev = signed.leaf_hash();
        out.push(signed);
    }
    out
}

fn entry_vectors(entries: &[SignedAuditEntry]) -> Value {
    json!(
        entries
            .iter()
            .map(|e| json!({
                "entry": e.entry().unwrap(),
                "body": String::from_utf8(e.body.clone()).unwrap(),
                "signed": e,
                "leaf_hash": hex::encode(e.leaf_hash()),
            }))
            .collect::<Vec<_>>()
    )
}

fn mmr_vectors() -> Value {
    let leaves: Vec<Digest32> = (0..11).map(|i| h("leaf", i)).collect();
    let mmr = Mmr::from_leaves(leaves.iter().copied());
    let sizes: Vec<Value> = (1..=leaves.len() as u64)
        .map(|size| {
            let proofs: Vec<Value> = (0..size).map(|i| json!(mmr.prove(i, size).unwrap())).collect();
            json!({ "size": size, "root": hex::encode(mmr.root_at(size).unwrap()), "proofs": proofs })
        })
        .collect();
    json!({
        "leaves": leaves.iter().map(hex::encode).collect::<Vec<_>>(),
        "sizes": sizes,
    })
}

fn epoch_vectors() -> Value {
    json!(
        (1..=6u64)
            .map(|n| {
                let leaves: Vec<SessionLeaf> = (0..n)
                    .map(|i| SessionLeaf { session_id: h("session", 40 - i), mmr_root: h("root", i), count: i + 1 })
                    .collect();
                let proofs: Vec<Value> = leaves
                    .iter()
                    .map(|l| json!({ "leaf_hash": hex::encode(l.hash()), "proof": prove_epoch(&leaves, &l.session_id).unwrap() }))
                    .collect();
                json!({ "leaves": leaves, "root": hex::encode(epoch_root(&leaves)), "proofs": proofs })
            })
            .collect::<Vec<_>>()
    )
}

fn audit_proof_vector(entries: &[SignedAuditEntry]) -> Value {
    let mmr = Mmr::from_leaves(entries.iter().map(SignedAuditEntry::leaf_hash));
    let size = mmr.len();
    let ours = SessionLeaf {
        session_id: SESSION,
        mmr_root: mmr.root(),
        count: size,
    };
    let others = (0..3u64).map(|i| SessionLeaf {
        session_id: h("other-session", i),
        mmr_root: h("other-root", i),
        count: i + 2,
    });
    let leaves: Vec<SessionLeaf> = std::iter::once(ours).chain(others).collect();
    let proof = AuditProof {
        entry: entries[3].clone(),
        mmr: mmr.prove(3, size).unwrap(),
        epoch_proof: prove_epoch(&leaves, &SESSION).unwrap(),
        epoch: 7,
        committer: COMMITTER.into(),
    };
    let root = proof.verify().unwrap();
    assert_eq!(root, epoch_root(&leaves));
    json!({
        "leaves": leaves,
        "proof": proof,
        "root": hex::encode(root),
        "attestation_digest": hex::encode(commit_attestation_digest(7, &root)),
    })
}

#[test]
fn the_agent_audit_vectors_are_current() {
    let entries = session();
    let details: Vec<Value> = ["", "fetch https://example.org", "\u{e9}"]
        .iter()
        .map(|s| json!({ "args": s, "digest": hex::encode(detail_digest(s.as_bytes())) }))
        .collect();
    let doc = json!({
        "source": "tenzro-types agent_audit::{SignedAuditEntry::leaf_hash, Mmr, epoch_root, prove_epoch, AuditProof::verify, commit_attestation_digest}",
        "session_id": hex::encode(SESSION),
        "agent": AGENT,
        "entries": entry_vectors(&entries),
        "session_root": hex::encode(Mmr::from_leaves(entries.iter().map(SignedAuditEntry::leaf_hash)).root()),
        "mmr": mmr_vectors(),
        "epoch": epoch_vectors(),
        "audit_proof": audit_proof_vector(&entries),
        "detail_digest": details,
    });
    let path = format!(
        "{}/../../sdk/fixtures/agent_audit/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    // Compared as parsed values, not text: the key order serde_json writes
    // depends on whether another crate in the build turns on its
    // `preserve_order` feature, and no reader of the file depends on it.
    let on_disk: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    assert_eq!(
        on_disk, doc,
        "sdk/fixtures/agent_audit/vectors.json is stale: rerun with TENZRO_WRITE_FIXTURES=1"
    );
}
