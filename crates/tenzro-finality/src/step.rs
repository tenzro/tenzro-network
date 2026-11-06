//! One step of a light client of Tenzro, as a light client on another chain
//! takes it, and the statement it proves there.
//!
//! The other chain keeps the root of each epoch's committee, starting from
//! the genesis committee. A step checks a checkpoint certificate against the
//! committee whose members it is handed: their root is what the other chain
//! compares with the root it holds for the checkpoint's epoch. The session
//! certificates the certificate names are checked against those members'
//! hardware keys, and each signer's ML-DSA-65 and P-256 signatures over the
//! checkpoint against its session key. A checkpoint that ends an epoch
//! commits the next committee's root, which the other chain then holds for
//! the next epoch.
//!
//! The step takes the full certificate rather than its compact form: a
//! compact certificate's verifier first sets up the proof system for the
//! committee's session keys, which inside a zkVM costs tens of billions of
//! cycles for a single key, while checking the signatures themselves costs
//! a small multiple of the signer count.

use serde::{Deserialize, Serialize};

use crate::Digest;
use crate::checkpoint::{Certificate, CertificateContext};
use crate::committee::{Committee, Member};
use crate::error::Result;
use crate::session::{SessionBook, SessionCertificate};

/// What one step checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityStep {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis block hash.
    pub genesis_hash: Digest,
    /// Members of the committee of the checkpoint's epoch.
    pub members: Vec<Member>,
    /// Session certificates the certificate's signers name.
    pub sessions: Vec<SessionCertificate>,
    /// The checkpoint's certificate.
    pub certificate: Certificate,
}

/// What a verified step states: the checkpoint and the committee root it was
/// certified under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityJournal {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis block hash.
    pub genesis_hash: Digest,
    /// The checkpoint's epoch.
    pub epoch: u64,
    /// Root of the committee that certified it.
    pub committee_root: Digest,
    /// Checkpoint index.
    pub index: u64,
    /// Checkpoint digest.
    pub checkpoint_digest: Digest,
    /// Last block height covered.
    pub last_height: u64,
    /// Height of the post-state `state_root` commits.
    pub state_height: u64,
    /// Post-state root at `state_height`.
    pub state_root: Digest,
    /// Merkle root of the covered block hashes.
    pub blocks_root: Digest,
    /// Merkle root of the statements validators attested in the range.
    pub statement_root: Digest,
    /// Root of the next epoch's committee, zero unless the checkpoint ends
    /// its epoch.
    pub next_committee_root: Digest,
    /// Block timestamp of the last covered block, milliseconds.
    pub timestamp_ms: u64,
}

/// Bytes of an encoded journal: thirteen 32-byte words.
pub const JOURNAL_LEN: usize = 13 * 32;

fn word_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&v.to_be_bytes());
}

fn read_u64(word: &[u8]) -> Option<u64> {
    if word[..24].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(word[24..32].try_into().ok()?))
}

impl FinalityJournal {
    /// The journal as Solidity's `abi.encode` lays out its fields, in
    /// declaration order: `uint64` and `bytes32` words.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(JOURNAL_LEN);
        word_u64(&mut out, self.chain_id);
        out.extend_from_slice(&self.genesis_hash);
        word_u64(&mut out, self.epoch);
        out.extend_from_slice(&self.committee_root);
        word_u64(&mut out, self.index);
        out.extend_from_slice(&self.checkpoint_digest);
        word_u64(&mut out, self.last_height);
        word_u64(&mut out, self.state_height);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.blocks_root);
        out.extend_from_slice(&self.statement_root);
        out.extend_from_slice(&self.next_committee_root);
        word_u64(&mut out, self.timestamp_ms);
        out
    }

    /// The journal [`FinalityJournal::encode`] wrote. None if the length or
    /// a `uint64` word is wrong.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != JOURNAL_LEN {
            return None;
        }
        let w: Vec<&[u8]> = bytes.chunks(32).collect();
        let d = |i: usize| -> Digest { w[i].try_into().expect("32-byte word") };
        Some(Self {
            chain_id: read_u64(w[0])?,
            genesis_hash: d(1),
            epoch: read_u64(w[2])?,
            committee_root: d(3),
            index: read_u64(w[4])?,
            checkpoint_digest: d(5),
            last_height: read_u64(w[6])?,
            state_height: read_u64(w[7])?,
            state_root: d(8),
            blocks_root: d(9),
            statement_root: d(10),
            next_committee_root: d(11),
            timestamp_ms: read_u64(w[12])?,
        })
    }
}

impl FinalityStep {
    /// Checks the step and states what it proves: the members form a
    /// committee for the checkpoint's epoch, every session certificate is
    /// one of theirs for this chain and epoch, and the certificate verifies
    /// under them.
    pub fn verify(&self) -> Result<FinalityJournal> {
        let cp = &self.certificate.checkpoint;
        let committee = Committee::from_members(cp.epoch, self.members.clone())?;
        let mut book = SessionBook::new(self.chain_id, self.genesis_hash, cp.epoch);
        for s in &self.sessions {
            book.admit(&committee, s.clone())?;
        }
        let ctx = CertificateContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &committee,
            sessions: &book,
        };
        self.certificate.verify(&ctx)?;
        Ok(FinalityJournal {
            chain_id: cp.chain_id,
            genesis_hash: cp.genesis_hash,
            epoch: cp.epoch,
            committee_root: committee.root(),
            index: cp.index,
            checkpoint_digest: cp.digest(),
            last_height: cp.last_height,
            state_height: cp.state_height,
            state_root: cp.state_root,
            blocks_root: cp.blocks_root,
            statement_root: cp.statement_root,
            next_committee_root: cp.next_committee_root.unwrap_or([0; 32]),
            timestamp_ms: cp.timestamp_ms,
        })
    }
}
