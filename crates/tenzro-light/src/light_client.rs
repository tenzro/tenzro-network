//! Proofs that a checkpoint is certified, from genesis or from the newest
//! proof of the handover chain, checked with a [`LightClient`].
//!
//! The client accepts a checkpoint once a certificate for it verifies under
//! the committee of the checkpoint's epoch, either the full certificate or
//! its compact form. It moves to the next epoch's committee only through the
//! checkpoint that ends an epoch: that checkpoint, certified by the outgoing
//! committee, commits the root of the incoming one, so the client checks the
//! members it is handed against that root before it counts their signatures.

use serde::{Deserialize, Serialize};

use tenzro_finality::Digest;
use tenzro_finality::checkpoint::{Certificate, Checkpoint};
use tenzro_finality::committee::{Committee, Member};
use tenzro_finality::session::SessionCertificate;

use crate::client::{LightClient, Proof, TrustAnchor};
use crate::error::{LightError, Result, malformed};

/// A proof from genesis is checked from an anchor at epoch 0.
fn at_genesis(anchor: &TrustAnchor) -> Result<()> {
    if anchor.epoch != 0 {
        return Err(LightError::InvalidCertificate(format!(
            "a proof from genesis needs the genesis anchor, this one is of epoch {}",
            anchor.epoch
        )));
    }
    Ok(())
}

pub use tenzro_finality::chain::{
    ChainAnchor, ChainedCheckpointProof, EpochHandover, HandoverChainJournal, HandoverChainProof,
    HandoverLink,
};

/// Proof, from genesis, that one checkpoint is certified: the genesis
/// committee, a handover for every epoch before the checkpoint's, and the
/// checkpoint's own certificate with the session certificates it names.
/// Nothing in it is trusted; [`CheckpointProof::verify`] checks it all
/// against the genesis [`TrustAnchor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointProof {
    /// Members of the genesis committee.
    pub genesis_members: Vec<Member>,
    /// One handover per epoch before the certified checkpoint's, in order.
    pub handovers: Vec<EpochHandover>,
    /// The checkpoint's certificate.
    pub certificate: Certificate,
    /// Session certificates the certificate names.
    pub sessions: Vec<SessionCertificate>,
}

impl CheckpointProof {
    /// The certified checkpoint, once every certificate verifies under the
    /// committee of its epoch, walked from the anchored genesis committee.
    pub fn verify(&self, anchor: &TrustAnchor) -> Result<&Checkpoint> {
        at_genesis(anchor)?;
        let genesis = Committee::from_members(0, self.genesis_members.clone())?;
        if genesis.root() != anchor.committee_root {
            return Err(LightError::InvalidCertificate(
                "the genesis committee is not the one the genesis anchor names".into(),
            ));
        }
        if self.handovers.len() as u64 != self.certificate.checkpoint.epoch {
            return Err(LightError::InvalidCertificate(format!(
                "a checkpoint of epoch {} needs {} handovers, the proof has {}",
                self.certificate.checkpoint.epoch,
                self.certificate.checkpoint.epoch,
                self.handovers.len()
            )));
        }
        let mut client = LightClient::over(anchor.chain_id, anchor.genesis_hash, genesis, None);
        for h in &self.handovers {
            client.replay(Proof::Quorum(h.certificate.clone()), h.sessions.clone())?;
            client.replay_hand_over(h.next_members.clone())?;
        }
        client.replay(
            Proof::Quorum(self.certificate.clone()),
            self.sessions.clone(),
        )?;
        Ok(&self.certificate.checkpoint)
    }
}

/// Certification of one checkpoint: walked from genesis, or from the newest
/// proof of the handover chain and the handovers since. A node that keeps
/// every handover serves the first; one that keeps the chain proof in their
/// place serves the second. In JSON each form is its own object, told apart
/// by its fields: a proof from genesis names `genesis_members`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Certification {
    /// Every handover from genesis.
    FromGenesis(CheckpointProof),
    /// The handover chain proof and the handovers since.
    Chained(ChainedCheckpointProof),
}

impl<'de> Deserialize<'de> for Certification {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let v = serde_json::Value::deserialize(d)?;
        if v.get("genesis_members").is_some() {
            serde_json::from_value(v)
                .map(Self::FromGenesis)
                .map_err(D::Error::custom)
        } else {
            serde_json::from_value(v)
                .map(Self::Chained)
                .map_err(D::Error::custom)
        }
    }
}

impl Certification {
    /// The checkpoint it names, before it is verified.
    pub fn checkpoint(&self) -> &Checkpoint {
        match self {
            Self::FromGenesis(p) => &p.certificate.checkpoint,
            Self::Chained(p) => &p.certificate.checkpoint,
        }
    }

    /// The certified checkpoint, verified from the genesis `anchor`. A
    /// chained certification also needs the handover program whose proofs it
    /// takes, and `verify_receipt(program, receipt)`, which checks that the
    /// receipt proves the program and returns the journal it committed.
    pub fn verify<F>(
        &self,
        anchor: &TrustAnchor,
        handover_program: Option<Digest>,
        verify_receipt: F,
    ) -> Result<&Checkpoint>
    where
        F: FnOnce(&Digest, &[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        match self {
            Self::FromGenesis(p) => p.verify(anchor),
            Self::Chained(p) => {
                at_genesis(anchor)?;
                let program = handover_program.ok_or_else(|| {
                    LightError::InvalidCertificate(
                        "the certification builds on a handover chain proof: name the handover program"
                            .into(),
                    )
                })?;
                let chain = ChainAnchor {
                    chain_id: anchor.chain_id,
                    genesis_hash: anchor.genesis_hash,
                    genesis_root: anchor.committee_root,
                    program,
                };
                Ok(p.verify(&chain, verify_receipt)?)
            }
        }
    }
}

/// The part of a proof log a checkpoint is certified from: the newest proof
/// of the handover chain, the members of the committee it reaches and the
/// handovers since. Nodes serve it (`tenzro_getHandoverChain`); restoring
/// nodes and light clients follow the chain from it, and provers extend the
/// chain proof from it. Untrusted until the certification built
/// from it verifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSegment {
    /// What the chain proof states; `None` before one is installed, when the
    /// handovers start at genesis.
    pub journal: Option<HandoverChainJournal>,
    /// The chain proof's receipt; empty without one.
    pub receipt: Vec<u8>,
    /// Members of the committee of the first handover's epoch.
    pub members: Vec<Member>,
    /// One handover per epoch from the chain proof's on.
    pub handovers: Vec<EpochHandover>,
}

impl ChainSegment {
    /// The epoch of the first handover, the one the chain proof reaches.
    pub fn first_epoch(&self) -> u64 {
        self.journal.map_or(0, |j| j.epoch)
    }

    /// The certification of `certificate`, a checkpoint of the epoch after
    /// the segment's last handover: from genesis without a chain proof, from
    /// the chain proof otherwise.
    pub fn certify(
        self,
        certificate: Certificate,
        sessions: Vec<SessionCertificate>,
    ) -> Certification {
        match self.journal {
            None => Certification::FromGenesis(CheckpointProof {
                genesis_members: self.members,
                handovers: self.handovers,
                certificate,
                sessions,
            }),
            Some(_) => Certification::Chained(ChainedCheckpointProof {
                chain: self.receipt,
                members: self.members,
                handovers: self.handovers,
                certificate,
                sessions,
            }),
        }
    }

    /// The `tenzro_getHandoverChain` answer carrying the segment.
    pub fn to_reply(&self) -> serde_json::Value {
        serde_json::json!({
            "first_epoch": self.first_epoch(),
            "to_epoch": self.first_epoch() + self.handovers.len() as u64,
            "segment": format!("0x{}", hex::encode(bincode::serialize(self).expect("a segment encodes"))),
        })
    }

    /// The segment a `tenzro_getHandoverChain` answer carries.
    pub fn from_reply(reply: &serde_json::Value) -> Result<Self> {
        let bytes = reply["segment"]
            .as_str()
            .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok())
            .ok_or_else(|| {
                malformed(
                    "handover chain segment",
                    "the answer carries no hex segment",
                )
            })?;
        bincode::deserialize(&bytes).map_err(|e| {
            malformed(
                "handover chain segment",
                format!("the segment does not decode: {e}"),
            )
        })
    }

    /// A light client at the end of the segment: started from the committee
    /// the chain proof reaches (checked against `anchor` and, through
    /// `verify_receipt`, the handover program), or from the genesis committee
    /// without one, then moved through every handover, each certificate
    /// verified under the committee of its epoch. It accepts checkpoints of
    /// epoch `first_epoch() + handovers.len()`.
    pub fn light_client<F>(
        &self,
        anchor: &TrustAnchor,
        handover_program: Option<Digest>,
        verify_receipt: F,
    ) -> Result<LightClient>
    where
        F: FnOnce(&Digest, &[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        at_genesis(anchor)?;
        let program = match (handover_program, self.receipt.is_empty()) {
            (Some(p), _) => p,
            (None, true) => [0; 32],
            (None, false) => {
                return Err(LightError::InvalidCertificate(
                    "the segment builds on a handover chain proof: name the handover program"
                        .into(),
                ));
            }
        };
        let chain = ChainAnchor {
            chain_id: anchor.chain_id,
            genesis_hash: anchor.genesis_hash,
            genesis_root: anchor.committee_root,
            program,
        };
        let (epoch, root) = chain.reached(&self.receipt, verify_receipt)?;
        if epoch != self.first_epoch() {
            return Err(LightError::InvalidCertificate(format!(
                "the segment starts at epoch {}, its chain proof reaches epoch {epoch}",
                self.first_epoch()
            )));
        }
        let committee = Committee::from_members(epoch, self.members.clone())?;
        if committee.root() != root {
            return Err(LightError::InvalidCertificate(format!(
                "the members are not the committee of epoch {epoch} the chain reaches"
            )));
        }
        let mut client = LightClient::over(anchor.chain_id, anchor.genesis_hash, committee, None);
        for h in &self.handovers {
            client.replay(Proof::Quorum(h.certificate.clone()), h.sessions.clone())?;
            client.replay_hand_over(h.next_members.clone())?;
        }
        Ok(client)
    }
}
