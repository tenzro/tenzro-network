//! Signed records of the tool calls agents make through this node.
//!
//! Every tool call an authenticated agent makes through `/mcp`,
//! `/mcp/compact` or A2A leaves one entry in the agent's audit log
//! ([`tenzro_types::agent_audit`]), recorded and signed by this node: the
//! agent, the tool, the SHA-256 of the arguments and of the result, the
//! decision (allowed, or refused with the reason), the approval the caller
//! presented, and the root that delegated the agent as chain state held it.
//! The node signs each entry with its record signer: its hardware identity
//! key signs a batch holding the entry. The arguments and results themselves are
//! never stored.
//!
//! Entries of one agent form a session per node process: each entry names
//! the previous one, and the session's Merkle Mountain Range root goes into
//! the epoch book, so the node's `AgentAuditCommit` fixes it on chain once
//! the epoch ends. An evidence pack then carries each entry with its proof
//! to the committed root, and a verifier checks the node's signature against
//! the identity the node registered on chain.
//!
//! Entries are appended, one JSON line each, to a file per session under
//! `audit/tool-calls/` in the data directory; the epoch lines the node
//! committed are kept beside them, so proofs can be built after the epoch
//! has left the book.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::batch::RecordSigner;
use tenzro_types::agent_audit::{
    ActionKind, ActionOutcome, AuditEntry, AuditProof, CallPrincipal, Digest32, Mmr, SessionLeaf,
    SignedAuditEntry, ToolCallFacts, detail_digest, prove_epoch,
};

/// Directory under the data directory that holds the records.
pub const TOOL_CALL_DIR: &str = "audit/tool-calls";

/// The key of the approval reference a caller presents with a call: in an
/// MCP request's `_meta`, or in an A2A data part.
pub const APPROVAL_META: &str = "tenzro/approval";

/// Domain of a session id.
const SESSION_DOMAIN: &[u8] = b"tenzro/tool-calls/session/v1";

/// Where a call arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Mcp,
    McpCompact,
    A2a,
}

impl Surface {
    /// Wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::McpCompact => "mcp_compact",
            Self::A2a => "a2a",
        }
    }
}

/// One served call, as the serving path saw it.
#[derive(Debug, Clone)]
pub struct Call<'a> {
    pub surface: Surface,
    pub agent: &'a str,
    pub tool: &'a str,
    /// The arguments as received, serialized.
    pub args: &'a [u8],
    /// Allowed, or refused with the reason.
    pub outcome: ActionOutcome,
    /// The result as returned, serialized; `None` for a call refused before
    /// it ran.
    pub result: Option<&'a [u8]>,
    /// The approval reference the caller presented, if any.
    pub approval: Option<String>,
    pub principal: Option<CallPrincipal>,
}

/// The epoch lines this node committed, with the account that committed
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedEpoch {
    pub epoch: u64,
    /// Ledger account, `0x` hex.
    pub committer: String,
    pub lines: Vec<SessionLeaf>,
}

struct Session {
    id: Digest32,
    agent: String,
    mmr: Mmr,
    prev: Digest32,
}

/// The tool-call records of this node.
pub struct ToolCallLog {
    dir: PathBuf,
    started_ms: u64,
    sessions: Mutex<HashMap<String, Session>>,
    /// Sessions of earlier processes found on disk, by agent.
    earlier: Mutex<Option<HashMap<String, Vec<Digest32>>>>,
    unrecorded: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for ToolCallLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolCallLog")
            .field("dir", &self.dir)
            .finish()
    }
}

/// The id of the session of `agent` on node `node` begun at `started_ms`.
pub fn session_id(node: &str, agent: &str, started_ms: u64) -> Digest32 {
    let mut h = Sha256::new();
    h.update(SESSION_DOMAIN);
    for part in [node.as_bytes(), agent.as_bytes()] {
        h.update((part.len() as u32).to_le_bytes());
        h.update(part);
    }
    h.update(started_ms.to_le_bytes());
    h.finalize().into()
}

/// The machine DID of the identity a record signer is certified by.
pub fn signer_did(signer: &dyn RecordSigner) -> String {
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&signer.identity().p256);
    tenzro_types::did_derivation::machine_did(&sec1)
}

impl ToolCallLog {
    /// A log under `data_dir`; nothing is written until the first call.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join(TOOL_CALL_DIR),
            started_ms: tenzro_crypto::session::now_ms(),
            sessions: Mutex::new(HashMap::new()),
            earlier: Mutex::new(None),
            unrecorded: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Agent calls refused because this node has no record signer.
    pub fn unrecorded(&self) -> u64 {
        self.unrecorded.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Note an agent call refused for want of a record signer.
    pub fn note_unrecorded(&self) {
        let n = self
            .unrecorded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n == 0 {
            tracing::warn!(
                target: "tool_calls",
                "this node has no record signer: tool calls by authenticated agents are refused"
            );
        }
    }

    fn session_path(&self, id: &Digest32) -> PathBuf {
        self.dir.join(format!("{}.jsonl", hex::encode(id)))
    }

    fn epoch_path(&self, epoch: u64) -> PathBuf {
        self.dir.join(format!("epoch-{epoch:016x}.json"))
    }

    /// Record `call`, signed by `signer`, as the next entry of the agent's
    /// session, and return it with the session's line after it. The entry
    /// is on disk before this returns.
    pub fn record(
        &self,
        signer: &dyn RecordSigner,
        call: Call<'_>,
    ) -> Result<(SignedAuditEntry, SessionLeaf), String> {
        let node = signer_did(signer);
        let mut sessions = self.sessions.lock();
        let session = sessions
            .entry(call.agent.to_string())
            .or_insert_with(|| Session {
                id: session_id(&node, call.agent, self.started_ms),
                agent: call.agent.to_string(),
                mmr: Mmr::new(),
                prev: [0; 32],
            });
        let entry = AuditEntry {
            session_id: session.id,
            seq: session.mmr.len(),
            at_ms: tenzro_crypto::session::now_ms(),
            agent: session.agent.clone(),
            kind: ActionKind::ToolCall,
            action: call.tool.to_string(),
            outcome: call.outcome,
            detail: detail_digest(call.args),
            linked_tx: None,
            prev: session.prev,
            image: None,
            call: Some(ToolCallFacts {
                node,
                surface: call.surface.as_str().to_string(),
                principal: call.principal,
                result: call.result.map(|r| hex::encode(detail_digest(r))),
                approval: call.approval,
            }),
        };
        let body = serde_json::to_vec(&entry).map_err(|e| e.to_string())?;
        let signature = signer.sign_record(&body).map_err(|e| e.to_string())?;
        let signed = SignedAuditEntry {
            body,
            signature: serde_json::to_vec(&signature).map_err(|e| e.to_string())?,
        };
        let mut line = serde_json::to_vec(&signed).map_err(|e| e.to_string())?;
        line.push(b'\n');
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.session_path(&session.id))
            .and_then(|mut f| f.write_all(&line))
            .map_err(|e| format!("the tool-call record could not be written: {e}"))?;
        let leaf = signed.leaf_hash();
        session.mmr.append(leaf);
        session.prev = leaf;
        Ok((
            signed,
            SessionLeaf {
                session_id: session.id,
                mmr_root: session.mmr.root(),
                count: session.mmr.len(),
            },
        ))
    }

    /// Every entry of session `id`, in order.
    pub fn entries(&self, id: &Digest32) -> Result<Vec<SignedAuditEntry>, String> {
        let file = match std::fs::File::open(self.session_path(id)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.to_string()),
        };
        std::io::BufReader::new(file)
            .lines()
            .map(|l| {
                l.map_err(|e| e.to_string())
                    .and_then(|l| serde_json::from_str(&l).map_err(|e| e.to_string()))
            })
            .collect()
    }

    /// The sessions of `agent`: those of this process and those found on
    /// disk.
    pub fn sessions_of(&self, agent: &str) -> Result<Vec<Digest32>, String> {
        let mut earlier = self.earlier.lock();
        if earlier.is_none() {
            let mut found: HashMap<String, Vec<Digest32>> = HashMap::new();
            if let Ok(dir) = std::fs::read_dir(&self.dir) {
                for f in dir.flatten() {
                    let name = f.file_name().to_string_lossy().to_string();
                    let Some(id) = name
                        .strip_suffix(".jsonl")
                        .and_then(|h| tenzro_types::agent_audit::parse_digest(h).ok())
                    else {
                        continue;
                    };
                    let first = std::fs::File::open(f.path())
                        .ok()
                        .and_then(|f| std::io::BufReader::new(f).lines().next())
                        .and_then(|l| l.ok())
                        .and_then(|l| serde_json::from_str::<SignedAuditEntry>(&l).ok())
                        .and_then(|s| s.entry().ok());
                    if let Some(e) = first {
                        found.entry(e.agent).or_default().push(id);
                    }
                }
            }
            *earlier = Some(found);
        }
        let mut ids = earlier
            .as_ref()
            .and_then(|m| m.get(agent).cloned())
            .unwrap_or_default();
        if let Some(s) = self.sessions.lock().get(agent)
            && !ids.contains(&s.id)
        {
            ids.push(s.id);
        }
        Ok(ids)
    }

    /// Keep the lines this node committed for `epoch`.
    pub fn committed(&self, committed: &CommittedEpoch) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(committed).map_err(|e| e.to_string())?;
        let path = self.epoch_path(committed.epoch);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)
            .and_then(|_| std::fs::rename(&tmp, &path))
            .map_err(|e| e.to_string())
    }

    /// The epochs this node committed, oldest first.
    pub fn committed_epochs(&self) -> Vec<CommittedEpoch> {
        let mut out: Vec<CommittedEpoch> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|f| {
                let n = f.file_name().to_string_lossy().to_string();
                n.starts_with("epoch-") && n.ends_with(".json")
            })
            .filter_map(|f| std::fs::read(f.path()).ok())
            .filter_map(|b| serde_json::from_slice(&b).ok())
            .collect();
        out.sort_by_key(|c: &CommittedEpoch| c.epoch);
        out
    }

    /// Proofs of every committed entry of `agents`, each against the first
    /// epoch whose commitment covers it, at most `limit`.
    pub fn proofs(&self, agents: &[String], limit: usize) -> Result<Vec<AuditProof>, String> {
        let epochs = self.committed_epochs();
        let mut out = Vec::new();
        for agent in agents {
            for id in self.sessions_of(agent)? {
                let entries = self.entries(&id)?;
                let leaves: Vec<Digest32> = entries.iter().map(|e| e.leaf_hash()).collect();
                let mmr = Mmr::from_leaves(leaves);
                let mut proven = 0u64;
                for c in &epochs {
                    let Some(line) = c.lines.iter().find(|l| l.session_id == id) else {
                        continue;
                    };
                    if line.count <= proven || line.count > mmr.len() {
                        continue;
                    }
                    if mmr.root_at(line.count) != Some(line.mmr_root) {
                        return Err(format!(
                            "session {} on disk does not reach the root committed at epoch {}",
                            hex::encode(id),
                            c.epoch
                        ));
                    }
                    let epoch_proof = prove_epoch(&c.lines, &id)
                        .ok_or("a committed epoch does not hold its own line")?;
                    for seq in proven..line.count {
                        if out.len() >= limit {
                            return Ok(out);
                        }
                        out.push(AuditProof {
                            entry: entries[seq as usize].clone(),
                            mmr: mmr
                                .prove(seq, line.count)
                                .ok_or("an entry has no proof in its range")?,
                            epoch_proof: epoch_proof.clone(),
                            epoch: c.epoch,
                            committer: c.committer.clone(),
                        });
                    }
                    proven = line.count;
                }
            }
        }
        Ok(out)
    }
}

/// The root that delegated `agent`, as chain state holds it now; `None` for
/// an agent with no Terms on chain.
pub(crate) fn principal_of(
    node: &Arc<crate::node::TenzroNode>,
    agent: &str,
) -> Option<CallPrincipal> {
    crate::agent_delegation::delegation_facts(node, agent).map(|d| CallPrincipal {
        controller_did: d.controller_did,
        root_kind: d.root_kind,
        terms_version: d.terms_version,
        approval_digest: d.approval_digest,
    })
}

/// JSON-RPC code of an agent call refused because this node cannot sign
/// its record, or could not write it.
pub const UNRECORDABLE: i32 = -32041;

/// Why a node with no record signer refuses agent calls.
pub const NO_RECORD_SIGNER: &str = "this node cannot sign tool-call records (it has no hardware \
    identity key), so it serves no tool calls to authenticated agents";

/// The signer an authenticated agent's call is recorded with. A node that
/// has none refuses the call before it runs: no agent call is served
/// without its signed record.
pub(crate) fn admit(node: &crate::node::TenzroNode) -> Result<Arc<dyn RecordSigner>, String> {
    match node.records() {
        Some(signer) => Ok(signer.clone()),
        None => {
            node.tool_calls().note_unrecorded();
            Err(NO_RECORD_SIGNER.to_string())
        }
    }
}

/// Record `call` on `node` with `signer`: signed, written, and its session
/// line entered in the current epoch's book. An error means the record is
/// not on disk; the caller withholds the call's result.
pub(crate) fn record(
    node: &Arc<crate::node::TenzroNode>,
    signer: &dyn RecordSigner,
    call: Call<'_>,
) -> Result<SignedAuditEntry, String> {
    let agent = call.agent.to_string();
    let (entry, line) = node.tool_calls().record(signer, call).map_err(|e| {
        tracing::error!(target: "tool_calls", agent, "tool call not recorded: {e}");
        format!("the call's record could not be written, so its result is withheld: {e}")
    })?;
    let epoch = crate::rpc::chain_state_of(node)
        .and_then(|c| tenzro_vm::native::read_reward_state(&c).ok())
        .map(|rs| rs.current_epoch);
    if let Some(epoch) = epoch
        && let Err(e) = node.agent_audit().book().record(epoch, line)
    {
        tracing::warn!(target: "tool_calls", agent, "session line refused: {e}");
    }
    Ok(entry)
}

/// JSON-RPC codes that mean the call was refused rather than failed.
pub const REFUSAL_CODES: &[i32] = &[-32001, -32003, -32005, -32040];

/// `tenzro_getToolCallRecords { agent_did, limit? }`: the signed tool-call
/// entries this node recorded for the agent, newest sessions last, with
/// whether this node records at all.
pub(crate) async fn handle_get(
    node: &Arc<crate::node::TenzroNode>,
    params: Option<serde_json::Value>,
    auth_ctx: &crate::rpc::AuthContext,
) -> Result<serde_json::Value, crate::rpc::JsonRpcError> {
    let bad = |m: String| crate::rpc::JsonRpcError {
        code: -32602,
        message: m,
        data: None,
    };
    let params = params.unwrap_or_default();
    let agent = params
        .get("agent_did")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| bad("'agent_did' is required".into()))?
        .to_string();
    let limit = params
        .get("limit")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(256)
        .min(4096) as usize;
    let controller = tenzro_vm::funding::root_did(&agent);
    crate::agent_audit::may_read(node, auth_ctx, Some(&controller)).await?;
    let log = node.tool_calls();
    let internal = |m: String| crate::rpc::JsonRpcError {
        code: -32603,
        message: m,
        data: None,
    };
    let mut entries = Vec::new();
    for id in log.sessions_of(&agent).map_err(internal)? {
        for e in log.entries(&id).map_err(internal)? {
            if entries.len() >= limit {
                break;
            }
            entries.push(e);
        }
    }
    Ok(serde_json::json!({
        "agent_did": agent,
        "recording": node.records().is_some(),
        "node": node.records().map(|s| signer_did(s.as_ref())),
        "refused_unrecordable": log.unrecorded(),
        "entries": entries,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::batch::{ImmediateRecordSigner, RecordSignature};
    use tenzro_crypto::testing::TestHybridSigner;

    fn signer() -> ImmediateRecordSigner {
        let id: Arc<dyn tenzro_crypto::composite::HybridSigner> =
            Arc::new(TestHybridSigner::p256_only(9));
        ImmediateRecordSigner::new(id)
    }

    fn call<'a>(agent: &'a str, args: &'a [u8], outcome: ActionOutcome) -> Call<'a> {
        let refused = matches!(outcome, ActionOutcome::Refused(_));
        Call {
            surface: Surface::Mcp,
            agent,
            tool: "get_balance",
            args,
            outcome,
            result: (!refused).then_some(b"{\"balance\":\"1\"}".as_slice()),
            approval: Some("approval-7".into()),
            principal: Some(CallPrincipal {
                controller_did: "did:tenzro:human:alice".into(),
                root_kind: "passkey".into(),
                terms_version: 3,
                approval_digest: "ab".repeat(32),
            }),
        }
    }

    #[test]
    fn each_call_is_a_signed_chained_entry_the_node_identity_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let log = ToolCallLog::new(dir.path());
        let s = signer();
        let agent = "did:tenzro:human:alice:bot";
        let (first, l1) = log
            .record(&s, call(agent, b"{\"a\":1}", ActionOutcome::Allowed))
            .unwrap();
        let (second, l2) = log
            .record(
                &s,
                call(
                    agent,
                    b"{\"a\":2}",
                    ActionOutcome::Refused("outside terms".into()),
                ),
            )
            .unwrap();
        assert_eq!((l1.count, l2.count), (1, 2));
        let e1 = first.entry().unwrap();
        let e2 = second.entry().unwrap();
        assert_eq!(e2.prev, first.leaf_hash());
        assert_eq!(e1.detail, detail_digest(b"{\"a\":1}"));
        let facts = e1.call.as_ref().unwrap();
        assert_eq!(facts.node, signer_did(&s));
        assert_eq!(facts.principal.as_ref().unwrap().root_kind, "passkey");
        assert_eq!(facts.approval.as_deref(), Some("approval-7"));
        assert!(facts.result.is_some());
        assert_eq!(e2.outcome, ActionOutcome::Refused("outside terms".into()));
        assert!(e2.call.as_ref().unwrap().result.is_none());

        let sig: RecordSignature = serde_json::from_slice(&first.signature).unwrap();
        sig.verify_record_at(s.identity(), &first.body, e1.at_ms)
            .unwrap();
        let mut forged = first.body.clone();
        let at = forged.iter().position(|b| *b == b'1').unwrap();
        forged[at] = b'2';
        assert!(sig.verify_record_at(s.identity(), &forged, e1.at_ms).is_err());

        // The disk holds what was signed, and a new process finds it.
        assert_eq!(log.entries(&e1.session_id).unwrap(), vec![first, second]);
        let again = ToolCallLog::new(dir.path());
        assert_eq!(again.sessions_of(agent).unwrap(), vec![e1.session_id]);
        assert!(
            again
                .sessions_of("did:tenzro:human:bob:bot")
                .unwrap()
                .is_empty()
        );
    }

    /// A node with no record signer refuses every authenticated agent call
    /// before it runs; with one, the call is admitted and recorded.
    #[tokio::test]
    async fn a_node_that_cannot_sign_records_refuses_agent_calls() {
        let tmp = tempfile::tempdir().unwrap();
        let config = crate::config::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..crate::config::NodeConfig::default()
        };
        let mut node = crate::node::TenzroNode::new(config).await.expect("node");
        assert!(node.records().is_none());
        match admit(&node) {
            Err(why) => assert_eq!(why, NO_RECORD_SIGNER),
            Ok(_) => panic!("a node with no record signer admitted an agent call"),
        }
        assert_eq!(node.tool_calls().unrecorded(), 1);

        node.set_record_signer(signer());
        let node = Arc::new(node);
        let Ok(s) = admit(&node) else {
            panic!("refused although it can sign")
        };
        let e = record(
            &node,
            &s,
            call("did:tenzro:human:alice:bot", b"{}", ActionOutcome::Allowed),
        )
        .unwrap();
        assert_eq!(e.entry().unwrap().call.unwrap().node, signer_did(&s));
    }

    #[test]
    fn committed_entries_prove_to_the_epoch_root() {
        let dir = tempfile::tempdir().unwrap();
        let log = ToolCallLog::new(dir.path());
        let s = signer();
        let a = "did:tenzro:human:alice:bot";
        let b = "did:tenzro:human:bob:bot";
        let mut lines = HashMap::new();
        for i in 0..3u8 {
            let (_, l) = log
                .record(&s, call(a, &[i], ActionOutcome::Allowed))
                .unwrap();
            lines.insert(a, l);
        }
        let (_, lb) = log
            .record(&s, call(b, b"x", ActionOutcome::Allowed))
            .unwrap();
        let mut first: Vec<SessionLeaf> = vec![lines[a].clone(), lb];
        first.sort_by_key(|l| l.session_id);
        log.committed(&CommittedEpoch {
            epoch: 5,
            committer: "0xaa".into(),
            lines: first.clone(),
        })
        .unwrap();
        let (_, l4) = log
            .record(&s, call(a, b"y", ActionOutcome::Allowed))
            .unwrap();
        log.committed(&CommittedEpoch {
            epoch: 6,
            committer: "0xaa".into(),
            lines: vec![l4],
        })
        .unwrap();

        let proofs = log.proofs(&[a.to_string()], 100).unwrap();
        assert_eq!(proofs.len(), 4);
        let root5 = tenzro_types::agent_audit::epoch_root(&first);
        for (i, p) in proofs.iter().enumerate() {
            assert_eq!(p.entry.entry().unwrap().seq, i as u64);
            let reached = p.verify().unwrap();
            if i < 3 {
                assert_eq!((p.epoch, reached), (5, root5));
            } else {
                assert_eq!(p.epoch, 6);
            }
        }
        assert_eq!(log.proofs(&[a.to_string()], 2).unwrap().len(), 2);
    }

    /// What one record costs: the signature, the disk append and the MMR
    /// update. Printed for the record;
    /// the bounds only catch a regression by an order of magnitude. The time
    /// is this thread's CPU time, so other work on a shared host does not
    /// count as the record's cost.
    #[test]
    fn the_cost_of_a_record_is_measured() {
        #[cfg(unix)]
        fn thread_cpu() -> std::time::Duration {
            let mut t = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `t` is a valid timespec for the call to write.
            let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut t) };
            assert_eq!(rc, 0, "thread CPU clock");
            std::time::Duration::new(t.tv_sec as u64, t.tv_nsec as u32)
        }
        #[cfg(windows)]
        fn thread_cpu() -> std::time::Duration {
            use windows_sys::Win32::Foundation::FILETIME;
            use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};
            let zero = FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            };
            let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
            // SAFETY: the four FILETIMEs are valid for the call to write.
            let ok = unsafe {
                GetThreadTimes(
                    GetCurrentThread(),
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            };
            assert_ne!(ok, 0, "thread CPU clock");
            let ticks =
                |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
            std::time::Duration::from_nanos((ticks(kernel) + ticks(user)) * 100)
        }
        {
            let dir = tempfile::tempdir().unwrap();
            let log = ToolCallLog::new(dir.path());
            let s = signer();
            let args = vec![b'a'; 512];
            log.record(
                &s,
                call("did:tenzro:human:alice:bot", &args, ActionOutcome::Allowed),
            )
            .unwrap();
            let n = 200u32;
            let started = thread_cpu();
            let mut bytes = 0usize;
            for _ in 0..n {
                let (e, _) = log
                    .record(
                        &s,
                        call("did:tenzro:human:alice:bot", &args, ActionOutcome::Allowed),
                    )
                    .unwrap();
                bytes += serde_json::to_vec(&e).unwrap().len();
            }
            let per = (thread_cpu() - started) / n;
            let size = bytes / n as usize;
            println!(
                "tool-call record cost: {} us per call, {} bytes per stored entry",
                per.as_micros(),
                size
            );
            assert!(per < std::time::Duration::from_millis(50));
            assert!(size < 64_000);
        }
    }

    #[test]
    fn a_call_signed_in_a_hardware_batch_verifies() {
        use tenzro_crypto::batch::{BatchParams, BatchRecordSigner, BatchService};
        let dir = tempfile::tempdir().unwrap();
        let log = ToolCallLog::new(dir.path());
        let id: Arc<dyn tenzro_crypto::composite::HybridSigner> =
            Arc::new(TestHybridSigner::hybrid(12));
        let service = Arc::new(
            BatchService::new(
                id,
                BatchParams {
                    max_batch: 1,
                    flush_interval_ms: 1_000,
                },
                0,
            )
            .unwrap(),
        );
        let signer = BatchRecordSigner::new(service, std::time::Duration::from_millis(200));
        let agent = "did:tenzro:human:alice:bot";
        let (entry, _) = log
            .record(&signer, call(agent, b"{\"a\":1}", ActionOutcome::Allowed))
            .unwrap();
        let e = entry.entry().unwrap();
        let sig: RecordSignature = serde_json::from_slice(&entry.signature).unwrap();
        sig.verify_record_at(signer.identity(), &entry.body, e.at_ms)
            .unwrap();
        let mut forged = entry.body.clone();
        let at = forged.iter().position(|b| *b == b'1').unwrap();
        forged[at] = b'2';
        assert!(
            sig.verify_record_at(signer.identity(), &forged, e.at_ms)
                .is_err()
        );
    }
}
