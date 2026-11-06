//! The per-action audit trail of agents a node supervises.
//!
//! The supervisor, outside the agent's sandbox, appends one entry per agent
//! action (tool call, egress request, spend, model call, grant use, approval)
//! to that session's append-only Merkle Mountain Range. Every entry carries a
//! sequence number and the hash of the entry before it, and is signed by the
//! node's hardware identity key, in a batch.
//!
//! Once per epoch the node commits one Merkle root over
//! `(session_id, MMR root, entry count)` for every session active in the
//! epoch, in a single `AgentAuditCommit` transaction. The proof of an entry
//! runs entry -> session MMR root -> epoch root -> the committed transaction,
//! and anyone holding the entry can check it against chain state.
//!
//! Hashing is SHA-256 with a one-byte domain tag: `0x00` for an entry leaf,
//! `0x01` for an interior node, `0x02` for a session leaf of the epoch tree.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A 32-byte digest.
pub type Digest32 = [u8; 32];

const TAG_ENTRY: u8 = 0x00;
const TAG_NODE: u8 = 0x01;
const TAG_SESSION: u8 = 0x02;

/// Hex (de)serialization for a 32-byte digest.
pub mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize as lowercase hex.
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    /// Deserialize from hex, with or without `0x`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        super::parse_digest(&s).map_err(serde::de::Error::custom)
    }
}

/// Hex (de)serialization for a list of 32-byte digests.
pub mod hex32_vec {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    /// Serialize each digest as lowercase hex.
    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for d in v {
            seq.serialize_element(&hex::encode(d))?;
        }
        seq.end()
    }

    /// Deserialize a list of hex digests.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| super::parse_digest(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Parse a 32-byte digest from hex, with or without `0x`.
pub fn parse_digest(s: &str) -> Result<Digest32, String> {
    let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| e.to_string())?;
    raw.try_into()
        .map_err(|_| "a digest is 32 bytes".to_string())
}

/// What an agent did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// A tool or skill invocation.
    ToolCall,
    /// An outbound network request.
    Egress,
    /// Value leaving the agent's wallet.
    Spend,
    /// A call to a model.
    ModelCall,
    /// An action checked against the delegation grant the agent holds.
    GrantUse,
    /// An action held for, or cleared by, the principal's approval.
    Approval,
    /// Telemetry: resources a node or a machine it runs used.
    Resource,
    /// Telemetry: a decision the node's policy made.
    Policy,
    /// Telemetry: an attempt the sandbox refused, or a limit it enforced.
    Violation,
}

impl ActionKind {
    /// Wire name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ToolCall => "tool_call",
            Self::Egress => "egress",
            Self::Spend => "spend",
            Self::ModelCall => "model_call",
            Self::GrantUse => "grant_use",
            Self::Approval => "approval",
            Self::Resource => "resource",
            Self::Policy => "policy",
            Self::Violation => "violation",
        }
    }
}

/// What the supervisor decided about an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "reason")]
pub enum ActionOutcome {
    /// It ran.
    Allowed,
    /// It was refused, and why.
    Refused(String),
    /// It waits on the named approval.
    Pending(String),
}

/// One action of one agent session, as the supervisor recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Session the entry belongs to.
    #[serde(with = "hex32")]
    pub session_id: Digest32,
    /// Position in the session, from 0 with no gaps.
    pub seq: u64,
    /// When the supervisor recorded it, ms since the Unix epoch.
    pub at_ms: u64,
    /// The agent that acted.
    pub agent: String,
    /// Kind of action.
    pub kind: ActionKind,
    /// What it acted on: a tool, a host, a model, a resource.
    pub action: String,
    /// The supervisor's decision.
    pub outcome: ActionOutcome,
    /// SHA-256 of the action's arguments. The arguments themselves are never
    /// logged.
    #[serde(with = "hex32")]
    pub detail: Digest32,
    /// Hash of the ledger transaction the action produced (a spend, a grant
    /// use), when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_tx: Option<String>,
    /// Leaf hash of the previous entry of the session; zero for the first.
    #[serde(with = "hex32")]
    pub prev: Digest32,
    /// The attested image the action ran under: the runtime binding of a
    /// machine's image and provenance, or its content id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// For a tool call the serving node recorded itself, what it served:
    /// see [`ToolCallFacts`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<ToolCallFacts>,
}

/// What a serving node states about one tool call it served to an agent,
/// beside the entry's tool name, argument digest and decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallFacts {
    /// Machine DID of the node that served the call and signed the entry.
    pub node: String,
    /// Where the call arrived: `mcp`, `mcp_compact` or `a2a`.
    pub surface: String,
    /// The root that delegated the agent, when the agent acts under Terms
    /// on chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<CallPrincipal>,
    /// SHA-256 of the result the call returned, success or error, hex;
    /// absent for a call refused before it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// The approval reference the caller presented for this call, as
    /// presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
}

/// The root of a delegated agent's authority, as chain state held it when
/// the call was served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallPrincipal {
    /// The human (passkey) or machine DID at the root of the delegation.
    pub controller_did: String,
    /// `passkey` or `machine`.
    pub root_kind: String,
    /// The Terms version in force.
    pub terms_version: u64,
    /// Digest of the challenge the root approved for those Terms: the
    /// reference of the approval the agent acts under.
    pub approval_digest: String,
}

/// An entry as stored and disclosed: the exact bytes that were signed, and
/// the node's batch signature over them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAuditEntry {
    /// JSON of the [`AuditEntry`], exactly as signed.
    #[serde(with = "hex_bytes")]
    pub body: Vec<u8>,
    /// The node's batch signature over `body`, encoded as JSON.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// Hex (de)serialization for a byte string.
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize as lowercase hex.
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    /// Deserialize from hex, with or without `0x`.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)
    }
}

impl SignedAuditEntry {
    /// The entry the body encodes.
    pub fn entry(&self) -> Result<AuditEntry, String> {
        serde_json::from_slice(&self.body).map_err(|e| e.to_string())
    }

    /// The entry's leaf hash in its session's MMR. It covers the signature,
    /// so a disclosed entry cannot be re-signed under another key.
    pub fn leaf_hash(&self) -> Digest32 {
        let mut h = Sha256::new();
        h.update([TAG_ENTRY]);
        h.update((self.body.len() as u64).to_le_bytes());
        h.update(&self.body);
        h.update(&self.signature);
        h.finalize().into()
    }
}

/// Hash of two children.
pub fn node_hash(left: &Digest32, right: &Digest32) -> Digest32 {
    let mut h = Sha256::new();
    h.update([TAG_NODE]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of a perfect binary tree over `leaves` (a power-of-two count).
fn perfect_root(leaves: &[Digest32]) -> Digest32 {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level.chunks(2).map(|p| node_hash(&p[0], &p[1])).collect();
    }
    level[0]
}

/// Sizes of the perfect trees an MMR of `n` leaves is made of, largest first.
fn mountain_sizes(n: u64) -> Vec<u64> {
    (0..64)
        .rev()
        .map(|b| 1u64 << b)
        .filter(|size| n & size != 0)
        .collect()
}

/// Bag the peaks into one root, right to left. No peaks is the zero root.
pub fn bag_peaks(peaks: &[Digest32]) -> Digest32 {
    let Some((last, rest)) = peaks.split_last() else {
        return [0u8; 32];
    };
    rest.iter().rev().fold(*last, |acc, p| node_hash(p, &acc))
}

/// An append-only Merkle Mountain Range. Appending never changes an earlier
/// node; the root after `n` appends is the bag of the `n`-leaf peaks.
#[derive(Debug, Clone, Default)]
pub struct Mmr {
    leaves: Vec<Digest32>,
    peaks: Vec<(u32, Digest32)>,
}

impl Mmr {
    /// An empty range.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from leaf hashes in order.
    pub fn from_leaves(leaves: impl IntoIterator<Item = Digest32>) -> Self {
        let mut mmr = Self::new();
        for leaf in leaves {
            mmr.append(leaf);
        }
        mmr
    }

    /// Append one leaf.
    pub fn append(&mut self, leaf: Digest32) {
        self.leaves.push(leaf);
        let mut height = 0u32;
        let mut hash = leaf;
        while let Some(&(h, left)) = self.peaks.last() {
            if h != height {
                break;
            }
            self.peaks.pop();
            hash = node_hash(&left, &hash);
            height += 1;
        }
        self.peaks.push((height, hash));
    }

    /// Number of leaves.
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Whether there are no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Leaf hash at `index`.
    pub fn leaf(&self, index: u64) -> Option<Digest32> {
        self.leaves.get(index as usize).copied()
    }

    /// The current root.
    pub fn root(&self) -> Digest32 {
        let peaks: Vec<Digest32> = self.peaks.iter().map(|(_, h)| *h).collect();
        bag_peaks(&peaks)
    }

    /// The peaks of the first `size` leaves.
    fn peaks_at(&self, size: u64) -> Vec<Digest32> {
        let mut start = 0usize;
        mountain_sizes(size)
            .into_iter()
            .map(|m| {
                let root = perfect_root(&self.leaves[start..start + m as usize]);
                start += m as usize;
                root
            })
            .collect()
    }

    /// The root the range had when it held `size` leaves.
    pub fn root_at(&self, size: u64) -> Option<Digest32> {
        (size <= self.len()).then(|| bag_peaks(&self.peaks_at(size)))
    }

    /// Proof that leaf `index` is in the range as it stood at `size` leaves.
    pub fn prove(&self, index: u64, size: u64) -> Option<MmrProof> {
        if index >= size || size > self.len() {
            return None;
        }
        let mut start = 0u64;
        let mut siblings = Vec::new();
        for m in mountain_sizes(size) {
            if index < start + m {
                let mut level: Vec<Digest32> =
                    self.leaves[start as usize..(start + m) as usize].to_vec();
                let mut pos = (index - start) as usize;
                while level.len() > 1 {
                    siblings.push(level[pos ^ 1]);
                    level = level.chunks(2).map(|p| node_hash(&p[0], &p[1])).collect();
                    pos /= 2;
                }
                break;
            }
            start += m;
        }
        Some(MmrProof {
            index,
            size,
            siblings,
            peaks: self.peaks_at(size),
        })
    }
}

/// Inclusion of one leaf in an MMR of `size` leaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrProof {
    /// Leaf index.
    pub index: u64,
    /// Leaves in the range the proof is against.
    pub size: u64,
    /// Siblings from the leaf up to its peak.
    #[serde(with = "hex32_vec")]
    pub siblings: Vec<Digest32>,
    /// Every peak of the range, left to right.
    #[serde(with = "hex32_vec")]
    pub peaks: Vec<Digest32>,
}

impl MmrProof {
    /// The root `leaf` proves to, or an error when the proof is malformed or
    /// the leaf is not the one it covers.
    pub fn root_for(&self, leaf: &Digest32) -> Result<Digest32, String> {
        if self.index >= self.size {
            return Err("leaf index is past the range".into());
        }
        let sizes = mountain_sizes(self.size);
        if sizes.len() != self.peaks.len() {
            return Err("peak count does not match the range size".into());
        }
        let mut start = 0u64;
        for (t, m) in sizes.iter().enumerate() {
            if self.index < start + m {
                if 1u64 << self.siblings.len() != *m {
                    return Err("path length does not match the peak height".into());
                }
                let mut pos = self.index - start;
                let mut hash = *leaf;
                for s in &self.siblings {
                    hash = if pos & 1 == 0 {
                        node_hash(&hash, s)
                    } else {
                        node_hash(s, &hash)
                    };
                    pos >>= 1;
                }
                if hash != self.peaks[t] {
                    return Err("leaf does not reach its peak".into());
                }
                return Ok(bag_peaks(&self.peaks));
            }
            start += m;
        }
        Err("leaf index is past the range".into())
    }
}

/// One session's line in an epoch commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLeaf {
    /// The session.
    #[serde(with = "hex32")]
    pub session_id: Digest32,
    /// Its MMR root at the commitment.
    #[serde(with = "hex32")]
    pub mmr_root: Digest32,
    /// Entries the root covers.
    pub count: u64,
}

impl SessionLeaf {
    /// Leaf hash in the epoch tree.
    pub fn hash(&self) -> Digest32 {
        let mut h = Sha256::new();
        h.update([TAG_SESSION]);
        h.update(self.session_id);
        h.update(self.mmr_root);
        h.update(self.count.to_le_bytes());
        h.finalize().into()
    }
}

/// Root over session leaves, ordered by session id. An odd node at the end
/// of a level moves up unchanged. No sessions is the zero root.
pub fn epoch_root(leaves: &[SessionLeaf]) -> Digest32 {
    let mut level: Vec<Digest32> = sorted(leaves).iter().map(SessionLeaf::hash).collect();
    if level.is_empty() {
        return [0u8; 32];
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|p| {
                if p.len() == 2 {
                    node_hash(&p[0], &p[1])
                } else {
                    p[0]
                }
            })
            .collect();
    }
    level[0]
}

fn sorted(leaves: &[SessionLeaf]) -> Vec<SessionLeaf> {
    let mut v = leaves.to_vec();
    v.sort_by_key(|a| a.session_id);
    v
}

/// Proof that `leaf` is line `index` of `count` in an epoch tree.
pub fn prove_epoch(leaves: &[SessionLeaf], session_id: &Digest32) -> Option<EpochProof> {
    let ordered = sorted(leaves);
    let index = ordered.iter().position(|l| &l.session_id == session_id)?;
    let mut level: Vec<Digest32> = ordered.iter().map(SessionLeaf::hash).collect();
    let mut pos = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        let sib = pos ^ 1;
        if sib < level.len() {
            siblings.push(level[sib]);
        }
        level = level
            .chunks(2)
            .map(|p| {
                if p.len() == 2 {
                    node_hash(&p[0], &p[1])
                } else {
                    p[0]
                }
            })
            .collect();
        pos /= 2;
    }
    Some(EpochProof {
        leaf: ordered[index].clone(),
        index: index as u64,
        count: ordered.len() as u64,
        siblings,
    })
}

/// Inclusion of one session in an epoch tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochProof {
    /// The session's line.
    pub leaf: SessionLeaf,
    /// Its position among the sessions, ordered by id.
    pub index: u64,
    /// Sessions in the tree.
    pub count: u64,
    /// Siblings from the leaf to the root; a level where the node had none
    /// contributes nothing.
    #[serde(with = "hex32_vec")]
    pub siblings: Vec<Digest32>,
}

impl EpochProof {
    /// The epoch root this proof reaches.
    pub fn root(&self) -> Result<Digest32, String> {
        if self.index >= self.count {
            return Err("session index is past the tree".into());
        }
        let mut hash = self.leaf.hash();
        let mut pos = self.index;
        let mut width = self.count;
        let mut sibs = self.siblings.iter();
        while width > 1 {
            let sib = pos ^ 1;
            if sib < width {
                let s = sibs.next().ok_or("proof is short a sibling")?;
                hash = if pos & 1 == 0 {
                    node_hash(&hash, s)
                } else {
                    node_hash(s, &hash)
                };
            }
            pos /= 2;
            width = width.div_ceil(2);
        }
        if sibs.next().is_some() {
            return Err("proof has extra siblings".into());
        }
        Ok(hash)
    }
}

/// Everything needed to check one entry against chain state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditProof {
    /// The disclosed entry.
    pub entry: SignedAuditEntry,
    /// Entry -> session MMR root.
    pub mmr: MmrProof,
    /// Session MMR root -> epoch root.
    pub epoch_proof: EpochProof,
    /// Epoch the root was committed for.
    pub epoch: u64,
    /// Ledger account that committed it, `0x` hex.
    pub committer: String,
}

impl AuditProof {
    /// Check the chain of hashes and return the epoch root it reaches. The
    /// caller compares it with the root committed on chain for
    /// `(committer, epoch)`.
    pub fn verify(&self) -> Result<Digest32, String> {
        let entry = self.entry.entry()?;
        if entry.seq != self.mmr.index {
            return Err("entry sequence number and proof position differ".into());
        }
        if entry.session_id != self.epoch_proof.leaf.session_id {
            return Err("entry and epoch line name different sessions".into());
        }
        if self.mmr.size != self.epoch_proof.leaf.count {
            return Err("MMR size and committed entry count differ".into());
        }
        let root = self.mmr.root_for(&self.entry.leaf_hash())?;
        if root != self.epoch_proof.leaf.mmr_root {
            return Err("entry does not reach the committed session root".into());
        }
        self.epoch_proof.root()
    }
}

/// A session's closing statement, handed to its owner or controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReceipt {
    /// The session.
    #[serde(with = "hex32")]
    pub session_id: Digest32,
    /// The agent that acted.
    pub agent: String,
    /// Owner or controller the receipt is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    /// Final MMR root.
    #[serde(with = "hex32")]
    pub final_root: Digest32,
    /// Entries in the session.
    pub count: u64,
    /// When the session closed, ms since the Unix epoch.
    pub closed_at_ms: u64,
}

/// A receipt with the node's batch signature over its JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSessionReceipt {
    /// JSON of the [`SessionReceipt`], exactly as signed.
    #[serde(with = "hex_bytes")]
    pub body: Vec<u8>,
    /// The node's batch signature over `body`, encoded as JSON.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// Domain of the digest a machine's attestation over a commitment quotes.
pub const COMMIT_ATTESTATION_DOMAIN: &[u8] = b"tenzro/agent-audit/commit";

/// The 32 bytes a machine's attestation over `(epoch, root)` quotes.
pub fn commit_attestation_digest(epoch: u64, root: &Digest32) -> Digest32 {
    let mut h = Sha256::new();
    h.update(COMMIT_ATTESTATION_DOMAIN);
    h.update(epoch.to_le_bytes());
    h.update(root);
    h.finalize().into()
}

/// Most findings one flag carries.
pub const MAX_FINDINGS: usize = 256;

/// What a validator found checking a peer's committed roots, or what it asks
/// the network to do on the strength of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditFinding {
    /// The node committed the epoch before `epoch` but not `epoch`.
    MissingCommit {
        /// Ledger account of the node, `0x` hex
        committer: String,
        /// The epoch it skipped
        epoch: u64,
    },
    /// The node's commitment for `epoch` carries an attestation that does
    /// not verify, or quotes something other than the committed root.
    AttestationInvalid {
        /// Ledger account of the node, `0x` hex
        committer: String,
        /// Epoch of the commitment
        epoch: u64,
    },
    /// The node's measured boot state in `epoch` differs from the one it
    /// attested before, with no change of image declared.
    ImageChanged {
        /// Ledger account of the node, `0x` hex
        committer: String,
        /// Epoch of the commitment
        epoch: u64,
    },
    /// Quarantine an agent on the network's authority.
    QuarantineAgent {
        /// The agent
        agent_did: String,
        /// Its owner or controller, who alone may lift the quarantine
        controller_did: String,
        /// SHA-256 of the evidence, hex
        evidence_hash: String,
    },
    /// Trip the circuit breaker of one bridge route: mints and releases on
    /// the route stop until governance lifts it.
    TripBridge {
        /// The route's bridge protocol
        adapter: crate::bridge_route::BridgeRouteAdapter,
        /// The route's external chain, as the route names it
        source_chain: String,
        /// SHA-256 of the anomaly evidence, hex
        evidence_hash: String,
        /// Why
        reason: String,
    },
    /// A receipt the operator signed contradicts its own published policy
    /// (`TenzroPolicyViolation`). The operator's compute bond pays the
    /// governed penalty into the insurance pool, once per violation.
    PolicyViolation {
        /// The violation's id: SHA-256 over the policy digest and the receipt
        /// preimage, hex
        violation_id: String,
        /// The operator whose policy was violated
        operator_did: String,
    },
}

impl AuditFinding {
    /// Stable id of the finding, so validators agreeing on it add up.
    pub fn id(&self) -> Digest32 {
        let body = serde_json::to_vec(self).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(b"tenzro/agent-audit/finding");
        h.update(body);
        h.finalize().into()
    }
}

/// Digest of an action's arguments.
pub fn detail_digest(args: &[u8]) -> Digest32 {
    Sha256::digest(args).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(i: u8) -> Digest32 {
        [i; 32]
    }

    #[test]
    fn mmr_proofs_hold_at_every_size() {
        let mut mmr = Mmr::new();
        for i in 0..23u8 {
            mmr.append(leaf(i));
            let size = mmr.len();
            assert_eq!(mmr.root_at(size), Some(mmr.root()));
            for idx in 0..size {
                let p = mmr.prove(idx, size).unwrap();
                assert_eq!(p.root_for(&leaf(idx as u8)).unwrap(), mmr.root());
                assert!(p.root_for(&leaf(200)).is_err());
            }
        }
    }

    #[test]
    fn epoch_proofs_reach_the_root() {
        let leaves: Vec<SessionLeaf> = (0..7u8)
            .map(|i| SessionLeaf {
                session_id: [i.wrapping_mul(37); 32],
                mmr_root: leaf(i),
                count: i as u64,
            })
            .collect();
        let root = epoch_root(&leaves);
        for l in &leaves {
            let p = prove_epoch(&leaves, &l.session_id).unwrap();
            assert_eq!(p.root().unwrap(), root);
        }
    }
}
