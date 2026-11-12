//! The OpenShell vectors the TS, Python and Rust SDKs check their record
//! verifiers against: sessions this crate's [`RecordLog`] signed, and the
//! tamperings a verifier must refuse.
//!
//! The committed `sdk/fixtures/openshell/vectors.json` is checked here with
//! the crate's own verifier.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_crypto::session::SessionSignature;
use tenzro_openshell::records::RecordLog;
use tenzro_types::agent_audit::{ActionKind, AuditEntry, Mmr, SignedAuditEntry};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdk/fixtures/openshell/vectors.json")
}

/// Every check `records::verify_session` makes, with the hybrid-record
/// moment given rather than read from the process.
fn verify(
    identity: &CompositePublicKey,
    entries: &[SignedAuditEntry],
    hybrid_from_ms: u64,
) -> Result<Vec<AuditEntry>, String> {
    let mut prev = [0u8; 32];
    let mut out = Vec::new();
    for (i, signed) in entries.iter().enumerate() {
        let entry = signed.entry()?;
        let signature: SessionSignature =
            serde_json::from_slice(&signed.signature).map_err(|e| e.to_string())?;
        signature
            .verify_record_under(identity, &signed.body, entry.at_ms, hybrid_from_ms)
            .map_err(|e| format!("entry {i}: {e}"))?;
        if entry.seq != i as u64 {
            return Err(format!("entry {i} is numbered {}", entry.seq));
        }
        if entry.prev != prev {
            return Err(format!("entry {i} does not chain to the entry before it"));
        }
        prev = signed.leaf_hash();
        out.push(entry);
    }
    Ok(out)
}

fn root(entries: &[SignedAuditEntry]) -> String {
    hex::encode(Mmr::from_leaves(entries.iter().map(SignedAuditEntry::leaf_hash)).root())
}

fn payments(entries: &[AuditEntry]) -> Vec<Value> {
    entries
        .iter()
        .filter_map(|e| {
            let (rail, target) = match e.kind {
                ActionKind::Spend => {
                    let (rail, target) = e.action.split_once(' ')?;
                    (rail.to_string(), target.to_string())
                }
                ActionKind::ModelCall if e.linked_tx.is_some() => {
                    ("inference".to_string(), e.action.clone())
                }
                _ => return None,
            };
            Some(json!({
                "seq": e.seq, "at_ms": e.at_ms, "rail": rail, "target": target,
                "outcome": e.outcome, "linked_tx": e.linked_tx,
            }))
        })
        .collect()
}

fn from_json(v: &Value) -> (CompositePublicKey, u64, Vec<SignedAuditEntry>) {
    (
        serde_json::from_value(v["identity"].clone()).unwrap(),
        v["hybrid_records_from_ms"].as_u64().unwrap_or(u64::MAX),
        serde_json::from_value(v["entries"].clone()).unwrap(),
    )
}

#[test]
fn the_sdk_vectors_verify_with_the_crate_verifier() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path()).unwrap()).unwrap();
    for s in v["sessions"].as_array().unwrap() {
        let (id, hybrid, entries) = from_json(s);
        let decoded =
            verify(&id, &entries, hybrid).unwrap_or_else(|e| panic!("{}: {e}", s["name"]));
        let x = &s["expect"];
        assert_eq!(root(&entries), x["root"].as_str().unwrap());
        assert_eq!(decoded.len() as u64, x["count"].as_u64().unwrap());
        assert_eq!(
            serde_json::to_value(payments(&decoded)).unwrap(),
            x["payments"]
        );
        let sid = hex::encode(RecordLog::session_id_on(
            s["gateway"].as_str().unwrap(),
            s["session"].as_str().unwrap(),
        ));
        assert!(
            decoded
                .iter()
                .all(|e| hex::encode(e.session_id) == sid && e.agent == x["agent"])
        );
        assert_eq!(sid, x["session_id"].as_str().unwrap());
        for e in decoded.iter().filter(|e| e.kind == ActionKind::ToolCall) {
            assert_eq!(e.call.as_ref().unwrap().surface, "openshell");
        }
    }
    for c in v["session_ids"].as_array().unwrap() {
        let sid = RecordLog::session_id_on(
            c["gateway"].as_str().unwrap(),
            c["session"].as_str().unwrap(),
        );
        assert_eq!(hex::encode(sid), c["session_id"].as_str().unwrap());
    }
    let r = &v["receipt"];
    let entry: SignedAuditEntry =
        serde_json::from_slice(&B64.decode(r["header"].as_str().unwrap()).unwrap()).unwrap();
    let id: CompositePublicKey = serde_json::from_value(r["identity"].clone()).unwrap();
    let sig: SessionSignature = serde_json::from_slice(&entry.signature).unwrap();
    let decoded = entry.entry().unwrap();
    sig.verify_record_under(&id, &entry.body, decoded.at_ms, 0)
        .unwrap();
    assert_eq!(decoded.kind.as_str(), r["expect"]["kind"]);
    for c in v["refusals"].as_array().unwrap() {
        let (id, hybrid, entries) = from_json(c);
        assert!(
            verify(&id, &entries, hybrid).is_err(),
            "{} verified",
            c["name"]
        );
    }
}
