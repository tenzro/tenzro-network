//! Signed records of what the extensions decided.
//!
//! Every decision is one [`AuditEntry`] in the session it belongs to (a
//! sandbox, or an agent for calls that reach Tenzro without one), chained to
//! the entry before it and appended to the session's Merkle Mountain Range.
//! The body is signed through the node's [`RecordSigner`] (a hardware batch
//! of its identity key; the earlier session-key form still verifies inside
//! the governed window); the signature is the JSON of the
//! [`RecordSignature`], so a verifier needs only the hardware identity's
//! public key. Each entry carries the verified host binding in `image`.
//!
//! A log given a directory ([`RecordLog::with_export_dir`]) also appends
//! every entry, as it is signed, to `<session id hex>.jsonl` there (one
//! `SignedAuditEntry` JSON per line) and writes `identity.json`: the
//! hardware identity the session keys sign for (`p256`, and `pq` when it
//! holds an ML-DSA-65 key) and `hybrid_records_from_ms`. That directory is
//! what a verifier reads; nothing in it is secret.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_crypto::batch::{RecordSignature, RecordSigner};
use tenzro_types::agent_audit::{
    ActionKind, ActionOutcome, AuditEntry, Digest32, Mmr, SignedAuditEntry, ToolCallFacts,
};

#[derive(Default)]
struct Session {
    seq: u64,
    prev: Digest32,
    mmr: Mmr,
    entries: Vec<SignedAuditEntry>,
}

/// One decision to record.
#[derive(Debug, Clone)]
pub struct Decision<'a> {
    /// The session: a sandbox name, or an agent DID.
    pub session: &'a str,
    /// The agent the decision concerns.
    pub agent: &'a str,
    /// Kind of action.
    pub kind: ActionKind,
    /// What it acted on: a host and path, a tool, a model, an RPC.
    pub action: &'a str,
    /// The decision.
    pub outcome: ActionOutcome,
    /// The action's arguments; only their digest is recorded.
    pub detail: &'a [u8],
    /// The settlement or payment this action is linked to.
    pub linked_tx: Option<String>,
}

/// The signed record log of one serving node.
pub struct RecordLog {
    signer: Arc<dyn RecordSigner>,
    image: Option<String>,
    gateway: String,
    node: String,
    export: Option<std::path::PathBuf>,
    sessions: Mutex<HashMap<Digest32, Session>>,
}

impl RecordLog {
    /// A log signed by `signer`, binding `image` (the verified host binding)
    /// into every entry.
    pub fn new(signer: Arc<dyn RecordSigner>, image: Option<String>) -> Self {
        Self {
            signer,
            image,
            gateway: "default".to_string(),
            node: String::new(),
            export: None,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// The hardware identity the session keys sign for.
    pub fn identity(&self) -> &CompositePublicKey {
        self.signer.identity()
    }

    /// The host binding each entry carries.
    pub fn image(&self) -> Option<&str> {
        self.image.as_deref()
    }

    /// The session id of a sandbox on a gateway:
    /// SHA-256("tenzro/openshell/session/v1" 0x00 gateway 0x00 sandbox).
    pub fn session_id_on(gateway: &str, session: &str) -> Digest32 {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tenzro/openshell/session/v1\0");
        h.update(gateway.as_bytes());
        h.update([0]);
        h.update(session.as_bytes());
        h.finalize().into()
    }

    /// The session id of a session name on this log's gateway.
    pub fn session_id(&self, session: &str) -> Digest32 {
        Self::session_id_on(&self.gateway, session)
    }

    /// Name the serving node (its machine DID) tool-call entries carry.
    pub fn with_node(mut self, node: impl Into<String>) -> Self {
        self.node = node.into();
        self
    }

    /// Name the gateway the sessions belong to (default `default`).
    pub fn with_gateway(mut self, gateway: impl Into<String>) -> Self {
        self.gateway = gateway.into();
        self
    }

    /// Also write every entry to `dir` as it is signed, with the identity
    /// that verifies them.
    pub fn with_export_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut identity =
            serde_json::to_value(self.signer.identity()).map_err(|e| e.to_string())?;
        identity["hybrid_records_from_ms"] =
            tenzro_crypto::session::hybrid_records_from_ms().into();
        let path = dir.join("identity.json");
        std::fs::write(&path, identity.to_string())
            .map_err(|e| format!("{}: {e}", path.display()))?;
        self.export = Some(dir);
        Ok(self)
    }

    fn export(&self, session: &Digest32, signed: &SignedAuditEntry) -> Result<(), String> {
        use std::io::Write as _;
        let Some(dir) = &self.export else {
            return Ok(());
        };
        let path = dir.join(format!("{}.jsonl", hex::encode(session)));
        let mut line = serde_json::to_vec(signed).map_err(|e| e.to_string())?;
        line.push(b'\n');
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut f| f.write_all(&line))
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Sign and append one decision; returns the stored entry.
    pub fn record(&self, d: Decision<'_>) -> Result<SignedAuditEntry, String> {
        let id = self.session_id(d.session);
        let mut sessions = self.sessions.lock();
        let session = sessions.entry(id).or_default();
        let entry = AuditEntry {
            session_id: id,
            seq: session.seq,
            at_ms: crate::now_ms(),
            agent: d.agent.to_string(),
            kind: d.kind,
            action: d.action.to_string(),
            outcome: d.outcome,
            detail: crate::digest(b"tenzro/openshell/detail/v1", &[d.detail]),
            linked_tx: d.linked_tx,
            prev: session.prev,
            image: self.image.clone(),
            call: (d.kind == ActionKind::ToolCall).then(|| ToolCallFacts {
                node: self.node.clone(),
                surface: "openshell".to_string(),
                principal: None,
                result: None,
                approval: None,
            }),
        };
        let body = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
        let signature = self.signer.sign_record(&body).map_err(|e| e.to_string())?;
        let signed = SignedAuditEntry {
            body,
            signature: serde_json::to_vec(&signature).map_err(|e| e.to_string())?,
        };
        self.export(&id, &signed)?;
        let leaf = signed.leaf_hash();
        session.mmr.append(leaf);
        session.prev = leaf;
        session.seq += 1;
        session.entries.push(signed.clone());
        Ok(signed)
    }

    /// The entries of a session, in order.
    pub fn entries(&self, session: &str) -> Vec<SignedAuditEntry> {
        self.sessions
            .lock()
            .get(&self.session_id(session))
            .map(|s| s.entries.clone())
            .unwrap_or_default()
    }

    /// The session's MMR root.
    pub fn root(&self, session: &str) -> Digest32 {
        self.sessions
            .lock()
            .get(&self.session_id(session))
            .map(|s| s.mmr.root())
            .unwrap_or_default()
    }
}

/// Check a session's entries: each is signed by a session key `identity`
/// certified, numbered from 0 without gaps, and chained to the one before.
/// Returns the decoded entries.
pub fn verify_session(
    identity: &CompositePublicKey,
    entries: &[SignedAuditEntry],
) -> Result<Vec<AuditEntry>, String> {
    let mut prev = [0u8; 32];
    let mut out = Vec::with_capacity(entries.len());
    for (i, signed) in entries.iter().enumerate() {
        let entry = signed.entry()?;
        let signature: RecordSignature =
            serde_json::from_slice(&signed.signature).map_err(|e| e.to_string())?;
        signature
            .verify_record_at(identity, &signed.body, entry.at_ms)
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

/// Whether an outcome allowed the action.
pub fn allowed(outcome: &ActionOutcome) -> bool {
    matches!(outcome, ActionOutcome::Allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::testing::TestHybridSigner;

    fn log() -> RecordLog {
        let identity = Arc::new(TestHybridSigner::p256_only(7));
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(identity);
        RecordLog::new(Arc::new(signer), Some("tee:tpm:ab".into()))
    }

    fn decide(log: &RecordLog, action: &str) -> SignedAuditEntry {
        log.record(Decision {
            session: "sb",
            agent: "did:tenzro:machine:a:b",
            kind: ActionKind::Egress,
            action,
            outcome: ActionOutcome::Allowed,
            detail: b"GET /",
            linked_tx: None,
        })
        .unwrap()
    }

    #[test]
    fn a_session_verifies_under_the_identity_that_certified_its_keys() {
        let log = log();
        decide(&log, "a");
        decide(&log, "b");
        let entries = verify_session(log.identity(), &log.entries("sb")).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].image.as_deref(), Some("tee:tpm:ab"));
        assert_ne!(log.root("sb"), [0; 32]);
    }

    #[test]
    fn an_altered_entry_is_refused() {
        let log = log();
        decide(&log, "a");
        let mut entries = log.entries("sb");
        let mut entry = entries[0].entry().unwrap();
        entry.outcome = ActionOutcome::Refused("x".into());
        entries[0].body = serde_json::to_vec(&entry).unwrap();
        assert!(verify_session(log.identity(), &entries).is_err());
    }

    #[test]
    fn a_dropped_entry_breaks_the_chain() {
        let log = log();
        decide(&log, "a");
        decide(&log, "b");
        decide(&log, "c");
        let mut entries = log.entries("sb");
        entries.remove(1);
        assert!(verify_session(log.identity(), &entries).is_err());
    }

    #[test]
    fn the_export_holds_every_entry_and_the_identity_that_verifies_them() {
        let dir = tempfile::tempdir().unwrap();
        let log = log()
            .with_gateway("gw")
            .with_export_dir(dir.path())
            .unwrap();
        decide(&log, "a");
        decide(&log, "b");
        let id = RecordLog::session_id_on("gw", "sb");
        let text =
            std::fs::read_to_string(dir.path().join(format!("{}.jsonl", hex::encode(id)))).unwrap();
        let entries: Vec<SignedAuditEntry> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let identity: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("identity.json")).unwrap(),
        )
        .unwrap();
        let identity: CompositePublicKey = serde_json::from_value(identity).unwrap();
        assert_eq!(verify_session(&identity, &entries).unwrap().len(), 2);
    }

    #[test]
    fn another_identity_does_not_verify() {
        let log = log();
        decide(&log, "a");
        let other = TestHybridSigner::p256_only(8);
        use tenzro_crypto::composite::HybridSigner;
        assert!(verify_session(other.public_key(), &log.entries("sb")).is_err());
    }

    #[test]
    fn batched_entries_verify_and_a_tampered_one_does_not() {
        let signer = Arc::new(crate::testing::Immediate::new(11));
        let id = signer.identity().clone();
        let log = RecordLog::new(signer, Some("tee:tpm:ab".into()));
        let a = decide(&log, "api.example.com");
        let b = decide(&log, "api.example.org");
        assert!(String::from_utf8_lossy(&a.signature).contains("batched"));
        let entries = vec![a.clone(), b.clone()];
        assert_eq!(verify_session(&id, &entries).unwrap().len(), 2);
        let mut bad = b;
        let n = bad.body.len();
        bad.body[n - 3] ^= 1;
        assert!(verify_session(&id, &[a, bad]).is_err());
        let other = crate::testing::Immediate::new(12);
        assert!(verify_session(other.identity(), &entries).is_err());
    }
}
