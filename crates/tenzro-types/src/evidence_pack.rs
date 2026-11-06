//! A compliance and dispute evidence pack: everything a deployer, a merchant
//! or an assessor needs to establish what an agent did and under which
//! controls, in one document that checks offline.
//!
//! The pack carries a proof from genesis that one checkpoint is certified,
//! and every chain record it relies on (audit commitments, terms, quarantine
//! and revocation, reputation) with a state proof under that checkpoint's
//! state root. Each disclosed audit entry carries its proof to the epoch
//! root committed on chain. Nothing in it is trusted: the verifier needs only
//! the chain's genesis anchor.
//!
//! The manifest names, per section, the SHA-256 of its JSON and the control
//! references the section supports; what each reference covers is described
//! in the repository's agent trust documentation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_audit::{AuditProof, SignedSessionReceipt};

/// Committed-state namespace of VM contract storage.
pub const STATE_NAMESPACE: &str = "state";

/// Key, in [`STATE_NAMESPACE`], of a VM storage slot.
pub fn vm_storage_key(address: &[u8], key: &[u8]) -> Vec<u8> {
    format!("storage:{}:{}", hex::encode(address), hex::encode(key)).into_bytes()
}

/// One chain record with its proof under the pack's certified state root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenRecord {
    /// What the record is: `audit_commit`, `terms`, `quarantine` or
    /// `reputation`.
    pub kind: String,
    /// Who or what it is about: an agent or root DID, or `committer:epoch`.
    pub subject: String,
    /// The VM storage key, UTF-8.
    pub slot: String,
    /// The value, hex; `None` when chain state holds nothing there.
    pub value: Option<String>,
    /// State proof of `(STATE_NAMESPACE, vm_storage_key(system, slot))`.
    pub proof: serde_json::Value,
}

/// A model an agent called, with the hashes the catalog pins for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProvenance {
    /// Model id as the audit entries name it.
    pub model: String,
    /// `(path, sha256)` of each file the catalog lists; empty when the
    /// catalog does not list the model.
    pub files: Vec<(String, String)>,
}

/// Where the supervising node operates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jurisdiction {
    /// ISO 3166-1 alpha-2 code the node declares, if any.
    pub country: Option<String>,
    /// Regulatory blocs it declares.
    pub blocs: Vec<String>,
}

/// One manifest line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSection {
    pub section: String,
    /// SHA-256 of the section's JSON, hex.
    pub digest: String,
    /// Control references the section supports.
    pub controls: Vec<String>,
}

/// The export.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencePack {
    /// The agent, or the root identity of a deployment.
    pub subject: String,
    /// The agents covered.
    pub agents: Vec<String>,
    /// When the node assembled it, ms.
    pub generated_at_ms: u64,
    /// Height of the certified state the records are proven under.
    pub state_height: u64,
    /// That state root, hex.
    pub state_root: String,
    /// The node hash of the state trie at `state_height`, which the proofs
    /// are checked under. Packs made before the hash was named have none
    /// and were made under SHA-256.
    #[serde(default)]
    pub state_trie_hash: crate::hash_scheme::HashScheme,
    /// Proof from genesis that the checkpoint committing `state_root` is
    /// certified.
    pub checkpoint: serde_json::Value,
    /// Audit entries, each with its proof to a committed epoch root.
    pub audit: Vec<AuditProof>,
    /// The on-chain commitments those proofs reach.
    pub commitments: Vec<ProvenRecord>,
    /// Quarantines, revocations and the root's reputation ledger, plus the
    /// grant and approval entries of the audit log by `(session, seq)`.
    pub oversight: Oversight,
    /// The terms each agent acts under.
    pub mandate: Vec<ProvenRecord>,
    /// Payment records of the agents covered, each proven under
    /// `state_root`: payer, payee, asset, amount, the request, quote and
    /// USD price the payer signed, and the payee's delivery receipts.
    #[serde(default)]
    pub commerce: Vec<ProvenRecord>,
    /// Governance decisions touching the subject: each proposal's record and
    /// its decision record, proven under `state_root`.
    pub governance: Vec<ProvenRecord>,
    /// Issuer actions on tokens the covered agents held: freezes, halts,
    /// forced transfers and policy changes, each with its reason code and
    /// evidence hash, proven under `state_root`.
    pub token_actions: Vec<ProvenRecord>,
    /// Signed closing receipts of the sessions covered.
    pub receipts: Vec<SignedSessionReceipt>,
    /// Models the agents called.
    pub models: Vec<ModelProvenance>,
    /// Where the supervising node operates.
    pub jurisdiction: Jurisdiction,
    pub manifest: Vec<ManifestSection>,
}

/// Oversight actions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Oversight {
    pub records: Vec<ProvenRecord>,
    /// `(session id hex, seq)` of grant-use and approval entries.
    pub actions: Vec<(String, u64)>,
}

/// Control references per section.
pub const SECTION_CONTROLS: &[(&str, &[&str])] = &[
    (
        "audit",
        &["eu-ai-act:12(1)", "eu-ai-act:12(2)", "iso-42001:A.6.2.8"],
    ),
    ("commitments", &["eu-ai-act:12(1)", "iso-42001:A.6.2.8"]),
    (
        "oversight",
        &[
            "eu-ai-act:14(4)(d)",
            "eu-ai-act:14(4)(e)",
            "iso-42001:A.9.2",
            "iso-42001:A.6.2.6",
        ],
    ),
    ("mandate", &["eu-ai-act:14(3)", "iso-42001:A.9.4"]),
    ("commerce", &["eu-ai-act:12(2)", "iso-42001:A.6.2.8"]),
    ("governance", &["eu-ai-act:14(4)(e)", "iso-42001:A.9.2"]),
    ("token_actions", &["eu-ai-act:12(2)", "iso-42001:A.6.2.8"]),
    ("receipts", &["eu-ai-act:12(2)", "iso-42001:A.6.2.8"]),
    (
        "models",
        &["eu-ai-act:12(2)", "iso-42001:A.6.2.7", "iso-42001:A.10.3"],
    ),
    ("jurisdiction", &["iso-42001:A.9.4"]),
];

fn digest_of<T: Serialize>(v: &T) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap_or_default()))
}

impl EvidencePack {
    /// The SHA-256 of each section's JSON, in manifest order.
    pub fn section_digests(&self) -> Vec<(&'static str, String)> {
        SECTION_CONTROLS
            .iter()
            .map(|(section, _)| {
                let d = match *section {
                    "audit" => digest_of(&self.audit),
                    "commitments" => digest_of(&self.commitments),
                    "oversight" => digest_of(&self.oversight),
                    "mandate" => digest_of(&self.mandate),
                    "commerce" => digest_of(&self.commerce),
                    "governance" => digest_of(&self.governance),
                    "token_actions" => digest_of(&self.token_actions),
                    "receipts" => digest_of(&self.receipts),
                    "models" => digest_of(&self.models),
                    _ => digest_of(&self.jurisdiction),
                };
                (*section, d)
            })
            .collect()
    }

    /// The manifest of the pack as it stands.
    pub fn build_manifest(&self) -> Vec<ManifestSection> {
        self.section_digests()
            .into_iter()
            .zip(SECTION_CONTROLS)
            .map(|((section, digest), (_, controls))| ManifestSection {
                section: section.to_string(),
                digest,
                controls: controls.iter().map(|c| c.to_string()).collect(),
            })
            .collect()
    }
}

/// A governance decision with proofs: the proposal, its tally, its veto
/// escrow total, its decision record and, for a protocol upgrade, its
/// readiness and activation, each proven under a certified state root, and
/// the proof from genesis that the checkpoint committing that root is
/// certified. Checked with the evidence pack's verifier and the genesis
/// anchor alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceReceipt {
    /// The proposal, 64 hex.
    pub proposal_id: String,
    /// Height of the certified state the records are proven under.
    pub state_height: u64,
    /// That state root, hex.
    pub state_root: String,
    /// The node hash of the state trie at `state_height`, which the proofs
    /// are checked under. Packs made before the hash was named have none
    /// and were made under SHA-256.
    #[serde(default)]
    pub state_trie_hash: crate::hash_scheme::HashScheme,
    /// Proof from genesis that the checkpoint committing `state_root` is
    /// certified.
    pub checkpoint: serde_json::Value,
    /// The records, by kind: `proposal`, `tally`, `veto_total`, `decision`,
    /// `readiness`, `activation`.
    pub records: Vec<ProvenRecord>,
}

impl GovernanceReceipt {
    /// The record of `kind`.
    pub fn record(&self, kind: &str) -> Option<&ProvenRecord> {
        self.records.iter().find(|r| r.kind == kind)
    }
}

/// Decode a decision record: `(SHA-256 of the executed proposal record,
/// executed height)`.
pub fn decode_decision(value: &[u8]) -> Option<([u8; 32], u64)> {
    if value.len() != 40 {
        return None;
    }
    let digest: [u8; 32] = value[..32].try_into().ok()?;
    let height = u64::from_be_bytes(value[32..].try_into().ok()?);
    Some((digest, height))
}
