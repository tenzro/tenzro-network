//! The chain of epoch handovers as one proof.
//!
//! A light client that starts from the genesis committee moves to each next
//! committee through the certificate of the checkpoint that ends an epoch.
//! Carried as data, those handovers grow with every epoch. Proven instead,
//! one link at a time, they fold into a single proof: the handover program
//! checks one handover under the committee the previous proof reached, checks
//! that previous proof inside the zkVM, and commits the committee the chain
//! now reaches. Its newest proof stands for every handover from genesis, so a
//! node keeps that proof alone and a light client verifies from it.
//!
//! A proof names the program that made it, and so does each proof it builds
//! on: a verifier that accepts the proof for one program and finds that same
//! program named in its journal has, by induction, every link checked by it.

use serde::{Deserialize, Serialize};

use crate::Digest;
use crate::checkpoint::{Certificate, Checkpoint};
use crate::committee::{Committee, Member};
use crate::error::{FinalityError, Result};
use crate::session::SessionCertificate;
use crate::step::FinalityStep;

/// How a client moves past one epoch: the certificate of the checkpoint that
/// ends it, the session certificates that certificate names, and the members
/// of the committee it commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochHandover {
    /// Certificate of the epoch's last checkpoint.
    pub certificate: Certificate,
    /// Session certificates the certificate names.
    pub sessions: Vec<SessionCertificate>,
    /// Members of the next epoch's committee.
    pub next_members: Vec<Member>,
}

/// What a proof of the handover chain states: from the genesis committee
/// whose root is `genesis_root`, the handovers of epochs `0..epoch` each
/// verified under the committee before it, ending at the committee of
/// `epoch`, whose root is `committee_root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverChainJournal {
    /// Image id of the program that proved this and every earlier link.
    pub program: Digest,
    /// Chain id.
    pub chain_id: u64,
    /// Genesis block hash.
    pub genesis_hash: Digest,
    /// Root of the genesis committee.
    pub genesis_root: Digest,
    /// The epoch whose committee the chain reaches.
    pub epoch: u64,
    /// Root of that committee.
    pub committee_root: Digest,
}

/// Bytes of an encoded chain journal: six 32-byte words.
pub const CHAIN_JOURNAL_LEN: usize = 6 * 32;

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

fn refuse(what: impl Into<String>) -> FinalityError {
    FinalityError::InvalidCertificate(what.into())
}

impl HandoverChainJournal {
    /// The journal as `uint64` and `bytes32` words, in declaration order.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHAIN_JOURNAL_LEN);
        out.extend_from_slice(&self.program);
        word_u64(&mut out, self.chain_id);
        out.extend_from_slice(&self.genesis_hash);
        out.extend_from_slice(&self.genesis_root);
        word_u64(&mut out, self.epoch);
        out.extend_from_slice(&self.committee_root);
        out
    }

    /// The journal [`HandoverChainJournal::encode`] wrote. None if the
    /// length or a `uint64` word is wrong.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CHAIN_JOURNAL_LEN {
            return None;
        }
        let w: Vec<&[u8]> = bytes.chunks(32).collect();
        let d = |i: usize| -> Digest { w[i].try_into().expect("32-byte word") };
        Some(Self {
            program: d(0),
            chain_id: read_u64(w[1])?,
            genesis_hash: d(2),
            genesis_root: d(3),
            epoch: read_u64(w[4])?,
            committee_root: d(5),
        })
    }
}

/// One link of the chain: the handover of one epoch, added to the chain
/// `prev` states (or starting it, at genesis).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverLink {
    /// Image id of the handover program, as the program is handed it.
    pub program: Digest,
    /// Root of the genesis committee.
    pub genesis_root: Digest,
    /// What the proof this link builds on states; `None` for epoch 0's
    /// handover, which builds on the genesis committee.
    pub prev: Option<HandoverChainJournal>,
    /// The certificate of the epoch's last checkpoint, under that epoch's
    /// committee.
    pub step: FinalityStep,
}

impl HandoverLink {
    /// What the chain states with this link added, given that `prev` is
    /// proven by `program` (the program checks that inside the zkVM): the
    /// link's committee is the one `prev` reached, or the genesis committee
    /// for epoch 0; its certificate verifies under that committee and ends
    /// the epoch.
    pub fn verify(&self) -> Result<HandoverChainJournal> {
        let j = self.step.verify()?;
        if j.chain_id != self.step.chain_id || j.genesis_hash != self.step.genesis_hash {
            return Err(refuse("the checkpoint is of another chain"));
        }
        match &self.prev {
            None => {
                if j.epoch != 0 || j.committee_root != self.genesis_root {
                    return Err(refuse(
                        "the first link must hand over epoch 0 under the genesis committee",
                    ));
                }
            }
            Some(p) => {
                if p.program != self.program {
                    return Err(refuse("the previous link was proven by another program"));
                }
                if p.chain_id != j.chain_id
                    || p.genesis_hash != j.genesis_hash
                    || p.genesis_root != self.genesis_root
                {
                    return Err(refuse("the previous link is of another chain"));
                }
                if p.epoch != j.epoch || p.committee_root != j.committee_root {
                    return Err(refuse(format!(
                        "the chain reaches epoch {} under another committee than the link's epoch {}",
                        p.epoch, j.epoch
                    )));
                }
            }
        }
        if j.next_committee_root == [0; 32] {
            return Err(refuse("the checkpoint does not end its epoch"));
        }
        Ok(HandoverChainJournal {
            program: self.program,
            chain_id: j.chain_id,
            genesis_hash: j.genesis_hash,
            genesis_root: self.genesis_root,
            epoch: j.epoch + 1,
            committee_root: j.next_committee_root,
        })
    }
}

/// What a prover delivers for the chain: its newest receipt and the members
/// of the committee of the epoch it reaches, which the receipt commits by
/// their root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverChainProof {
    /// Members of the committee the chain reaches.
    pub members: Vec<Member>,
    /// The receipt, as the receipt verifier reads it.
    pub receipt: Vec<u8>,
}

/// What a client trusts before it has seen any proof: the chain, its genesis
/// committee's root, and the handover program whose proofs it accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainAnchor {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis block hash.
    pub genesis_hash: Digest,
    /// Root of the genesis committee.
    pub genesis_root: Digest,
    /// Image id of the handover program.
    pub program: Digest,
}

/// Proof that one checkpoint is certified, of a size that does not grow with
/// the chain's age: the newest proof of the handover chain, the members of
/// the committee it reaches, the handovers of the epochs since (those not yet
/// proven), and the checkpoint's own certificate. Nothing in it is trusted;
/// [`ChainedCheckpointProof::verify`] checks it all against a
/// [`ChainAnchor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainedCheckpointProof {
    /// The handover chain's proof, as the receipt verifier reads it; empty
    /// when no handover is proven yet and the walk starts at genesis.
    pub chain: Vec<u8>,
    /// Members of the committee the chain reaches (the genesis committee
    /// when `chain` is empty).
    pub members: Vec<Member>,
    /// One handover per epoch after the chain's, before the checkpoint's.
    pub handovers: Vec<EpochHandover>,
    /// The checkpoint's certificate.
    pub certificate: Certificate,
    /// Session certificates the certificate names.
    pub sessions: Vec<SessionCertificate>,
}

impl ChainAnchor {
    /// The epoch and committee root the chain proof `chain` reaches: the
    /// genesis committee at epoch 0 when `chain` is empty.
    /// `verify_receipt(program, chain)` must check that `chain` proves the
    /// program `program` halted having committed exactly the returned
    /// journal, with nothing left assumed.
    pub fn reached<F>(&self, chain: &[u8], verify_receipt: F) -> Result<(u64, Digest)>
    where
        F: FnOnce(&Digest, &[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        if chain.is_empty() {
            return Ok((0, self.genesis_root));
        }
        let journal = verify_receipt(&self.program, chain)
            .map_err(|e| refuse(format!("the handover chain proof does not verify: {e}")))?;
        let j = HandoverChainJournal::decode(&journal)
            .ok_or_else(|| refuse("the handover chain proof commits no chain journal"))?;
        if j.program != self.program {
            return Err(refuse("the handover chain proof names another program"));
        }
        if j.chain_id != self.chain_id
            || j.genesis_hash != self.genesis_hash
            || j.genesis_root != self.genesis_root
        {
            return Err(refuse("the handover chain proof is of another chain"));
        }
        Ok((j.epoch, j.committee_root))
    }
}

impl ChainedCheckpointProof {
    /// The certified checkpoint. `verify_receipt(program, chain)` must check
    /// that `chain` proves the program `program` halted having committed
    /// exactly the returned journal, with nothing left assumed.
    pub fn verify<F>(&self, anchor: &ChainAnchor, verify_receipt: F) -> Result<&Checkpoint>
    where
        F: FnOnce(&Digest, &[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        let (mut epoch, root) = anchor.reached(&self.chain, verify_receipt)?;
        if Committee::from_members(epoch, self.members.clone())?.root() != root {
            return Err(refuse(format!(
                "the members are not the committee of epoch {epoch} the chain reaches"
            )));
        }
        let step =
            |members: &[Member], certificate: &Certificate, sessions: &[SessionCertificate]| {
                FinalityStep {
                    chain_id: anchor.chain_id,
                    genesis_hash: anchor.genesis_hash,
                    members: members.to_vec(),
                    sessions: sessions.to_vec(),
                    certificate: certificate.clone(),
                }
                .verify()
            };
        let mut members = &self.members;
        for h in &self.handovers {
            let j = step(members, &h.certificate, &h.sessions)?;
            if j.epoch != epoch || j.next_committee_root == [0; 32] {
                return Err(refuse(format!(
                    "the handover of epoch {epoch} does not end it"
                )));
            }
            if Committee::from_members(epoch + 1, h.next_members.clone())?.root()
                != j.next_committee_root
            {
                return Err(refuse(format!(
                    "the members are not the committee epoch {epoch}'s last checkpoint commits"
                )));
            }
            members = &h.next_members;
            epoch += 1;
        }
        let j = step(members, &self.certificate, &self.sessions)?;
        if j.epoch != epoch {
            return Err(refuse(format!(
                "a checkpoint of epoch {} under a proof that reaches epoch {epoch}",
                j.epoch
            )));
        }
        Ok(&self.certificate.checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chain_journal_round_trips_and_refuses_a_wide_word() {
        let j = HandoverChainJournal {
            program: [1; 32],
            chain_id: 1337,
            genesis_hash: [2; 32],
            genesis_root: [3; 32],
            epoch: 8760 * 20,
            committee_root: [4; 32],
        };
        let bytes = j.encode();
        assert_eq!(bytes.len(), CHAIN_JOURNAL_LEN);
        assert_eq!(HandoverChainJournal::decode(&bytes), Some(j));
        let mut wide = bytes.clone();
        wide[32] = 1;
        assert_eq!(HandoverChainJournal::decode(&wide), None);
        assert_eq!(HandoverChainJournal::decode(&bytes[1..]), None);
    }
}
