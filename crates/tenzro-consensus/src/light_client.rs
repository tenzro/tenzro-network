//! Following the chain's finality without executing it.
//!
//! A [`LightClient`] starts from the genesis committee and trusts nothing
//! else. It accepts a checkpoint once a certificate for it verifies under
//! the committee of the checkpoint's epoch, either the full certificate or
//! its compact form, given the epoch's session-certificate bundle. It moves
//! to the next epoch's committee only through the checkpoint that ends an
//! epoch: that checkpoint, certified by the outgoing committee, commits the
//! root of the incoming one, so the client checks the members it is handed
//! against that root before it counts their signatures.

use serde::{Deserialize, Serialize};

use crate::checkpoint::{Certificate, CertificateContext, Checkpoint};
use crate::committee::{Committee, Member};
use crate::compact::{CompactCertificate, ProofSetups};
use crate::error::{ConsensusError, Result};
use crate::session::{SessionBook, SessionCertificate};
use crate::vertex::Digest;

/// What a client trusts before it has seen any certificate: the chain, and
/// the root of its genesis committee, both from the genesis file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisAnchor {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis block hash.
    pub genesis_hash: Digest,
    /// Root of the genesis committee.
    pub committee_root: Digest,
}

pub use tenzro_finality::chain::{
    ChainAnchor, ChainedCheckpointProof, EpochHandover, HandoverChainJournal, HandoverChainProof,
    HandoverLink,
};

/// Proof, from genesis, that one checkpoint is certified: the genesis
/// committee, a handover for every epoch before the checkpoint's, and the
/// checkpoint's own certificate with the session certificates it names.
/// Nothing in it is trusted; [`CheckpointProof::verify`] checks it all
/// against a [`GenesisAnchor`].
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
    pub fn verify(&self, anchor: &GenesisAnchor) -> Result<&Checkpoint> {
        let genesis = Committee::from_members(0, self.genesis_members.clone())?;
        if genesis.root() != anchor.committee_root {
            return Err(ConsensusError::InvalidCertificate(
                "the genesis committee is not the one the genesis anchor names".into(),
            ));
        }
        if self.handovers.len() as u64 != self.certificate.checkpoint.epoch {
            return Err(ConsensusError::InvalidCertificate(format!(
                "a checkpoint of epoch {} needs {} handovers, the proof has {}",
                self.certificate.checkpoint.epoch,
                self.certificate.checkpoint.epoch,
                self.handovers.len()
            )));
        }
        let mut client = LightClient::new(anchor.chain_id, anchor.genesis_hash, genesis);
        for h in &self.handovers {
            client.add_sessions(h.sessions.clone());
            client.accept_certificate(&h.certificate)?;
            client.hand_over(h.next_members.clone())?;
        }
        client.add_sessions(self.sessions.clone());
        client.accept_certificate(&self.certificate)?;
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
        anchor: &GenesisAnchor,
        handover_program: Option<Digest>,
        verify_receipt: F,
    ) -> Result<&Checkpoint>
    where
        F: FnOnce(&Digest, &[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        match self {
            Self::FromGenesis(p) => p.verify(anchor),
            Self::Chained(p) => {
                let program = handover_program.ok_or_else(|| {
                    ConsensusError::InvalidCertificate(
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
            .ok_or_else(|| ConsensusError::Malformed("the answer carries no hex segment".into()))?;
        bincode::deserialize(&bytes)
            .map_err(|e| ConsensusError::Malformed(format!("the segment does not decode: {e}")))
    }

    /// A light client at the end of the segment: started from the committee
    /// the chain proof reaches (checked against `anchor` and, through
    /// `verify_receipt`, the handover program), or from the genesis committee
    /// without one, then moved through every handover, each certificate
    /// verified under the committee of its epoch. It accepts checkpoints of
    /// epoch `first_epoch() + handovers.len()`.
    pub fn light_client<F>(
        &self,
        anchor: &GenesisAnchor,
        handover_program: Option<Digest>,
        verify_receipt: F,
    ) -> Result<LightClient>
    where
        F: FnOnce(&Digest, &[u8]) -> std::result::Result<Vec<u8>, String>,
    {
        let program = match (handover_program, self.receipt.is_empty()) {
            (Some(p), _) => p,
            (None, true) => [0; 32],
            (None, false) => {
                return Err(ConsensusError::InvalidCertificate(
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
            return Err(ConsensusError::InvalidCertificate(format!(
                "the segment starts at epoch {}, its chain proof reaches epoch {epoch}",
                self.first_epoch()
            )));
        }
        let committee = Committee::from_members(epoch, self.members.clone())?;
        if committee.root() != root {
            return Err(ConsensusError::InvalidCertificate(format!(
                "the members are not the committee of epoch {epoch} the chain reaches"
            )));
        }
        let mut client = LightClient::new(anchor.chain_id, anchor.genesis_hash, committee);
        for h in &self.handovers {
            client.add_sessions(h.sessions.clone());
            client.accept_certificate(&h.certificate)?;
            client.hand_over(h.next_members.clone())?;
        }
        Ok(client)
    }
}

/// A client that verifies certificates, epoch by epoch, from genesis.
pub struct LightClient {
    chain_id: u64,
    genesis_hash: Digest,
    committee: Committee,
    sessions: SessionBook,
    setups: ProofSetups,
    latest: Option<Checkpoint>,
}

impl LightClient {
    /// A client of the chain `chain_id` whose genesis committee is `genesis`.
    pub fn new(chain_id: u64, genesis_hash: Digest, genesis: Committee) -> Self {
        let sessions = SessionBook::new(chain_id, genesis_hash, genesis.epoch);
        Self {
            chain_id,
            genesis_hash,
            committee: genesis,
            sessions,
            setups: ProofSetups::new(),
            latest: None,
        }
    }

    /// The committee the client currently checks certificates against.
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// The latest checkpoint the client accepted.
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.latest.as_ref()
    }

    /// Adds session certificates of the current epoch to its bundle. Each is
    /// checked against the hardware key of the member it names; those that
    /// fail are dropped. Returns how many the bundle now holds of these.
    pub fn add_sessions(&mut self, bundle: Vec<SessionCertificate>) -> usize {
        bundle
            .into_iter()
            .filter(|c| self.sessions.admit(&self.committee, c.clone()).is_ok())
            .count()
    }

    fn context(&self) -> CertificateContext<'_> {
        CertificateContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &self.committee,
            sessions: &self.sessions,
        }
    }

    fn advance(&mut self, checkpoint: &Checkpoint) {
        if self
            .latest
            .as_ref()
            .is_none_or(|l| checkpoint.index > l.index)
        {
            self.latest = Some(checkpoint.clone());
        }
    }

    /// Accepts the checkpoint `cert` certifies, if it verifies under the
    /// current committee.
    pub fn accept_certificate(&mut self, cert: &Certificate) -> Result<()> {
        cert.verify(&self.context())?;
        self.advance(&cert.checkpoint);
        Ok(())
    }

    /// Accepts the checkpoint a compact certificate certifies, if it
    /// verifies under the current committee.
    pub fn accept_compact(&mut self, cert: &CompactCertificate) -> Result<()> {
        cert.verify(&self.context(), &self.setups)?;
        self.advance(&cert.checkpoint);
        Ok(())
    }

    /// Moves to the next epoch, whose committee has `members`: the latest
    /// accepted checkpoint must end the current epoch and commit exactly
    /// that committee.
    pub fn hand_over(&mut self, members: Vec<Member>) -> Result<()> {
        let Some(root) = self.latest.as_ref().and_then(|c| c.next_committee_root) else {
            return Err(ConsensusError::InvalidCertificate(
                "no accepted checkpoint ends the current epoch".into(),
            ));
        };
        if self
            .latest
            .as_ref()
            .is_some_and(|c| c.epoch != self.committee.epoch)
        {
            return Err(ConsensusError::InvalidCertificate(
                "the latest checkpoint is of another epoch".into(),
            ));
        }
        let next = Committee::from_members(self.committee.epoch + 1, members)?;
        if next.root() != root {
            return Err(ConsensusError::InvalidCertificate(
                "the members are not the committee the epoch's last checkpoint commits".into(),
            ));
        }
        self.sessions = SessionBook::new(self.chain_id, self.genesis_hash, next.epoch);
        self.committee = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::test_support::{MemoryHighWater, checkpoint, sign_as};
    use crate::checkpoint::{VoteCollector, VoteOutcome};
    use crate::committee::ValidatorIndex;
    use crate::committee::test_support::committee;
    use crate::validator_key::test_signer::SoftwareTestSigner;

    fn certify<S: std::borrow::Borrow<SoftwareTestSigner>>(
        c: &Committee,
        s: &[S],
        who: &[ValidatorIndex],
        cp: &Checkpoint,
    ) -> (Certificate, Vec<SessionCertificate>) {
        let mut book = SessionBook::new(cp.chain_id, cp.genesis_hash, cp.epoch);
        let mut col = VoteCollector::new();
        let mut out = None;
        for i in who {
            let v = sign_as(s[*i as usize].borrow(), &MemoryHighWater::default(), *i, cp).unwrap();
            book.admit(c, v.signature.session.clone()).unwrap();
            if let VoteOutcome::Certified(cert) = col.add(c, v) {
                out = Some(*cert);
            }
        }
        let cert = out.expect("quorum");
        let sessions = book.bundle(&cert.sessions);
        (cert, sessions)
    }

    /// A checkpoint of epoch 1, proved from the genesis committee through
    /// the handover that ends epoch 0.
    fn proof() -> (CheckpointProof, GenesisAnchor) {
        let (c0, s) = committee(4);
        let c1 = Committee::from_members(1, c0.members().to_vec()).unwrap();
        let end = Checkpoint {
            next_committee_root: Some(c1.root()),
            ..checkpoint(5, 1)
        };
        let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
        let cp = Checkpoint {
            epoch: 1,
            ..checkpoint(9, 2)
        };
        let (certificate, sessions) = certify(&c1, &s, &[1, 2, 3], &cp);
        let anchor = GenesisAnchor {
            chain_id: 7,
            genesis_hash: [1; 32],
            committee_root: c0.root(),
        };
        let proof = CheckpointProof {
            genesis_members: c0.members().to_vec(),
            handovers: vec![EpochHandover {
                certificate: handover,
                sessions: handover_sessions,
                next_members: c1.members().to_vec(),
            }],
            certificate,
            sessions,
        };
        (proof, anchor)
    }

    #[test]
    fn a_checkpoint_proof_verifies_from_genesis_and_refuses_what_is_not_certified() {
        let (proof, anchor) = proof();
        assert_eq!(proof.verify(&anchor).unwrap().index, 9);

        let mut m = proof.clone();
        m.certificate.checkpoint.state_root[0] ^= 1;
        assert!(
            m.verify(&anchor).is_err(),
            "a state root the committee did not sign"
        );

        let mut m = proof.clone();
        m.certificate.signers.truncate(2);
        m.certificate.sessions.truncate(2);
        m.certificate.signatures.truncate(2);
        assert!(m.verify(&anchor).is_err(), "less than a quorum");

        let mut m = proof.clone();
        m.handovers.clear();
        assert!(
            m.verify(&anchor).is_err(),
            "no way from genesis to the checkpoint's epoch"
        );

        let mut m = proof.clone();
        m.handovers[0].next_members[0].stake += 1;
        assert!(
            m.verify(&anchor).is_err(),
            "a committee the handover does not commit"
        );

        assert!(
            proof
                .verify(&GenesisAnchor {
                    committee_root: [0; 32],
                    ..anchor
                })
                .is_err(),
            "another genesis committee"
        );
        assert!(
            proof
                .verify(&GenesisAnchor {
                    chain_id: 8,
                    ..anchor
                })
                .is_err(),
            "another chain"
        );

        // Signed by a committee that is not the chain's: its own members,
        // presented as genesis, do not match the anchor.
        let (outsiders, _) = committee(5);
        let mut m = proof.clone();
        m.genesis_members = outsiders.members().to_vec();
        assert!(m.verify(&anchor).is_err(), "a committee outside the anchor");
    }

    /// A checkpoint proven from the newest handover chain proof alone: the
    /// receipt stands for every handover before the epoch it reaches, so the
    /// proof carries that epoch's committee and no handover. Checking the
    /// receipt itself is the zkVM verifier's part; here it hands the journal.
    #[test]
    fn a_chained_proof_verifies_from_the_chain_proof_alone() {
        let (proof, a) = proof();
        let program = [0x42; 32];
        let anchor = ChainAnchor {
            chain_id: a.chain_id,
            genesis_hash: a.genesis_hash,
            genesis_root: a.committee_root,
            program,
        };
        let c1 = proof.handovers[0].next_members.clone();
        let c1_root = Committee::from_members(1, c1.clone()).unwrap().root();
        let journal = HandoverChainJournal {
            program,
            chain_id: 7,
            genesis_hash: [1; 32],
            genesis_root: a.committee_root,
            epoch: 1,
            committee_root: c1_root,
        };
        let proves = |j: HandoverChainJournal| {
            move |p: &Digest, r: &[u8]| -> std::result::Result<Vec<u8>, String> {
                if r == b"receipt" && *p == j.program {
                    Ok(j.encode())
                } else {
                    Err("not a receipt of the program".into())
                }
            }
        };
        let chained = ChainedCheckpointProof {
            chain: b"receipt".to_vec(),
            members: c1.clone(),
            handovers: Vec::new(),
            certificate: proof.certificate.clone(),
            sessions: proof.sessions.clone(),
        };
        assert_eq!(chained.verify(&anchor, proves(journal)).unwrap().index, 9);

        // With no chain proof yet, the same proof walks from genesis.
        let walked = ChainedCheckpointProof {
            chain: Vec::new(),
            members: proof.genesis_members.clone(),
            handovers: proof.handovers.clone(),
            certificate: proof.certificate.clone(),
            sessions: proof.sessions.clone(),
        };
        assert_eq!(walked.verify(&anchor, proves(journal)).unwrap().index, 9);

        let other = HandoverChainJournal {
            program: [7; 32],
            ..journal
        };
        assert!(
            chained
                .verify(
                    &ChainAnchor {
                        program: [7; 32],
                        ..anchor
                    },
                    proves(journal)
                )
                .is_err(),
            "a receipt of another program"
        );
        assert!(
            chained
                .verify(&anchor, |_: &Digest, _: &[u8]| Ok(other.encode()))
                .is_err(),
            "a journal naming another program"
        );
        assert!(
            chained
                .verify(&anchor, |_: &Digest, _: &[u8]| Err("forged".to_string()))
                .is_err(),
            "a receipt that does not verify"
        );
        let elsewhere = HandoverChainJournal {
            genesis_root: [9; 32],
            ..journal
        };
        assert!(
            chained.verify(&anchor, proves(elsewhere)).is_err(),
            "a chain from another genesis committee"
        );
        let mut m = chained.clone();
        m.members[0].stake += 1;
        assert!(
            m.verify(&anchor, proves(journal)).is_err(),
            "members that are not the committee the chain reaches"
        );
        let behind = HandoverChainJournal {
            epoch: 0,
            committee_root: a.committee_root,
            ..journal
        };
        let mut m = chained.clone();
        m.members = proof.genesis_members.clone();
        assert!(
            m.verify(&anchor, proves(behind)).is_err(),
            "a chain that stops short of the checkpoint's epoch"
        );
        let mut m = chained.clone();
        m.certificate.checkpoint.state_root[0] ^= 1;
        assert!(
            m.verify(&anchor, proves(journal)).is_err(),
            "a state root the committee did not sign"
        );
    }

    /// Either form of certification verifies through the one call, a chained
    /// one only against a named handover program, and the JSON of each comes
    /// back as the same form.
    #[test]
    fn a_certification_takes_either_form() {
        let (proof, a) = proof();
        let program = [0x42; 32];
        let no_receipt = |_: &Digest, _: &[u8]| -> std::result::Result<Vec<u8>, String> {
            Err("no receipt".into())
        };
        let walked = ChainedCheckpointProof {
            chain: Vec::new(),
            members: proof.genesis_members.clone(),
            handovers: proof.handovers.clone(),
            certificate: proof.certificate.clone(),
            sessions: proof.sessions.clone(),
        };
        for c in [
            Certification::FromGenesis(proof.clone()),
            Certification::Chained(walked),
        ] {
            assert_eq!(c.checkpoint().index, 9);
            assert_eq!(c.verify(&a, Some(program), no_receipt).unwrap().index, 9);
            let json = serde_json::to_value(&c).unwrap();
            assert_eq!(serde_json::from_value::<Certification>(json).unwrap(), c);
        }
        let chained = Certification::Chained(ChainedCheckpointProof {
            chain: b"receipt".to_vec(),
            members: proof.genesis_members.clone(),
            handovers: Vec::new(),
            certificate: proof.certificate.clone(),
            sessions: proof.sessions.clone(),
        });
        assert!(
            chained.verify(&a, None, no_receipt).is_err(),
            "a chained certification is checked against a named program"
        );
        assert!(
            chained.verify(&a, Some(program), no_receipt).is_err(),
            "a receipt that does not verify"
        );
    }

    /// A light client follows a served segment: from genesis through its
    /// handovers, or from the committee its chain proof reaches with none,
    /// and then accepts the checkpoint; members that are not that committee,
    /// another genesis or an unnamed program are refused.
    #[test]
    fn a_light_client_follows_a_served_segment() {
        let (proof, a) = proof();
        let program = [0x42; 32];
        let c1 = proof.handovers[0].next_members.clone();
        let journal = HandoverChainJournal {
            program,
            chain_id: a.chain_id,
            genesis_hash: a.genesis_hash,
            genesis_root: a.committee_root,
            epoch: 1,
            committee_root: Committee::from_members(1, c1.clone()).unwrap().root(),
        };
        let proves = move |p: &Digest, r: &[u8]| -> std::result::Result<Vec<u8>, String> {
            if r == b"receipt" && *p == program {
                Ok(journal.encode())
            } else {
                Err("not a receipt of the program".into())
            }
        };
        let walked = ChainSegment {
            journal: None,
            receipt: Vec::new(),
            members: proof.genesis_members.clone(),
            handovers: proof.handovers.clone(),
        };
        let chained = ChainSegment {
            journal: Some(journal),
            receipt: b"receipt".to_vec(),
            members: c1,
            handovers: Vec::new(),
        };
        for (segment, program) in [(&walked, None), (&chained, Some(program))] {
            let mut client = segment.light_client(&a, program, proves).unwrap();
            client.add_sessions(proof.sessions.clone());
            client.accept_certificate(&proof.certificate).unwrap();
            assert_eq!(client.latest().unwrap().index, 9);
        }
        assert!(
            chained.light_client(&a, None, proves).is_err(),
            "a chain proof names its program"
        );
        let mut wrong = chained.clone();
        wrong.members[0].stake += 1;
        assert!(
            wrong.light_client(&a, Some(program), proves).is_err(),
            "members that are not the committee the chain reaches"
        );
        let elsewhere = GenesisAnchor {
            committee_root: [9; 32],
            ..a
        };
        assert!(
            chained
                .light_client(&elsewhere, Some(program), proves)
                .is_err(),
            "another genesis"
        );
        assert!(
            walked.light_client(&elsewhere, None, proves).is_err(),
            "another genesis committee"
        );
    }

    /// A governance receipt certified from genesis: an executed proposal's
    /// records, proven under a state root that an epoch-1 checkpoint commits,
    /// with that checkpoint's proof from the genesis committee. It is the
    /// shared fixture under `sdk/fixtures/governance_receipt/`, which the CLI
    /// checks from the genesis anchor and the SDKs check under the certified
    /// root. Session keys are fresh per run, so the stored fixture is not
    /// regenerated byte for byte; this test checks that it still verifies,
    /// and `TENZRO_WRITE_FIXTURES=1` rewrites it after a deliberate change.
    #[test]
    fn the_governance_receipt_fixture_is_certified_from_genesis() {
        use sha2::Digest as _;
        use std::sync::Arc;
        use tenzro_storage::state_trie::capture::Writes;
        use tenzro_storage::{MemoryStore, StateTrie};
        use tenzro_types::evidence_pack::{
            GovernanceReceipt, ProvenRecord, STATE_NAMESPACE, vm_storage_key,
        };

        const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/fixtures/governance_receipt/receipt_from_genesis.json");

        if std::env::var_os("TENZRO_WRITE_FIXTURES").is_some() {
            let id = "ab".repeat(32);
            let proposal = serde_json::to_vec(
                &serde_json::json!({ "id": id, "status": "executed", "track": "standard" }),
            )
            .unwrap();
            let mut decision = sha2::Sha256::digest(&proposal).to_vec();
            decision.extend_from_slice(&7u64.to_be_bytes());
            let slots = [
                ("proposal", format!("proposal:{id}"), Some(proposal)),
                (
                    "tally",
                    format!("proposal_tally:{id}"),
                    Some(br#"{"yes":"3","no":"1","total_eligible":"4"}"#.to_vec()),
                ),
                ("veto_total", format!("veto_total:{id}"), None),
                (
                    "decision",
                    format!("governance_decision:{id}"),
                    Some(decision),
                ),
            ];
            let trie = StateTrie::new(Arc::new(MemoryStore::new()));
            let mut writes = Writes::new();
            for (_, slot, value) in &slots {
                if value.is_some() {
                    writes.insert(
                        (
                            STATE_NAMESPACE.to_string(),
                            vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                        ),
                        value.clone(),
                    );
                }
            }
            let root: [u8; 32] = trie
                .commit(1, &writes)
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap();
            let records = slots
                .iter()
                .map(|(kind, slot, _)| {
                    let (value, proof) = trie
                        .prove(
                            1,
                            STATE_NAMESPACE,
                            &vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                        )
                        .unwrap();
                    ProvenRecord {
                        kind: (*kind).into(),
                        subject: id.clone(),
                        slot: slot.clone(),
                        value: value.map(hex::encode),
                        proof: serde_json::to_value(proof).unwrap(),
                    }
                })
                .collect();

            let (c0, s) = committee(4);
            let c1 = Committee::from_members(1, c0.members().to_vec()).unwrap();
            let end = Checkpoint {
                next_committee_root: Some(c1.root()),
                ..checkpoint(5, 1)
            };
            let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
            let cp = Checkpoint {
                epoch: 1,
                state_root: root,
                ..checkpoint(9, 2)
            };
            let (certificate, sessions) = certify(&c1, &s, &[1, 2, 3], &cp);
            let anchor = GenesisAnchor {
                chain_id: 7,
                genesis_hash: [1; 32],
                committee_root: c0.root(),
            };
            let proof = CheckpointProof {
                genesis_members: c0.members().to_vec(),
                handovers: vec![EpochHandover {
                    certificate: handover,
                    sessions: handover_sessions,
                    next_members: c1.members().to_vec(),
                }],
                certificate,
                sessions,
            };
            let receipt = GovernanceReceipt {
                proposal_id: id,
                state_height: cp.state_height,
                state_root: hex::encode(root),
                state_trie_hash: Default::default(),
                checkpoint: serde_json::to_value(&proof).unwrap(),
                records,
            };
            let fixture = serde_json::json!({
                "anchor": {
                    "chain_id": anchor.chain_id,
                    "genesis_hash": hex::encode(anchor.genesis_hash),
                    "committee_root": hex::encode(anchor.committee_root),
                },
                "certified_checkpoint": cp.index,
                "certified_state_root": hex::encode(root),
                "executed_height": 7,
                "receipt": receipt,
            });
            std::fs::write(&path, serde_json::to_string(&fixture).unwrap() + "\n").unwrap();
        }

        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the shared fixture")).unwrap();
        let b32 = |v: &serde_json::Value| -> [u8; 32] {
            hex::decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let anchor = GenesisAnchor {
            chain_id: fixture["anchor"]["chain_id"].as_u64().unwrap(),
            genesis_hash: b32(&fixture["anchor"]["genesis_hash"]),
            committee_root: b32(&fixture["anchor"]["committee_root"]),
        };
        let proof: CheckpointProof =
            serde_json::from_value(fixture["receipt"]["checkpoint"].clone()).unwrap();
        let cp = proof.verify(&anchor).unwrap();
        assert_eq!(cp.index, fixture["certified_checkpoint"].as_u64().unwrap());
        assert_eq!(cp.state_root, b32(&fixture["certified_state_root"]));
        assert_eq!(cp.state_root, b32(&fixture["receipt"]["state_root"]));
        assert_eq!(
            cp.state_height,
            fixture["receipt"]["state_height"].as_u64().unwrap()
        );
        assert!(
            proof
                .verify(&GenesisAnchor {
                    committee_root: [0; 32],
                    ..anchor
                })
                .is_err()
        );
    }

    /// An evidence pack with node-signed tool-call records and its EU AI Act
    /// profile, certified from genesis: the shared fixture under
    /// `sdk/fixtures/eu_ai_act/`, which the CLI verifies from the genesis
    /// anchor alone. `TENZRO_WRITE_FIXTURES=1` rewrites it.
    #[test]
    fn the_eu_ai_act_pack_fixture_is_certified_from_genesis() {
        use crate::eu_ai_act::{Profile, build_profile, verify_profile};
        use tenzro_types::evidence_pack::EvidencePack;

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../sdk/fixtures/eu_ai_act/pack_from_genesis.json");
        let no_receipt = |_: &[u8; 32], _: &[u8]| -> std::result::Result<Vec<u8>, String> {
            Err("no handover program".into())
        };
        if std::env::var_os("TENZRO_WRITE_FIXTURES").is_some() {
            let (mut pack, root) = crate::eu_ai_act::fixture::pack();
            let (c0, s) = committee(4);
            let c1 = Committee::from_members(1, c0.members().to_vec()).unwrap();
            let end = Checkpoint {
                next_committee_root: Some(c1.root()),
                ..checkpoint(5, 1)
            };
            let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
            let cp = Checkpoint {
                epoch: 1,
                state_root: root,
                ..checkpoint(9, 2)
            };
            let (certificate, sessions) = certify(&c1, &s, &[1, 2, 3], &cp);
            let anchor = GenesisAnchor {
                chain_id: 7,
                genesis_hash: [1; 32],
                committee_root: c0.root(),
            };
            let proof = CheckpointProof {
                genesis_members: c0.members().to_vec(),
                handovers: vec![EpochHandover {
                    certificate: handover,
                    sessions: handover_sessions,
                    next_members: c1.members().to_vec(),
                }],
                certificate,
                sessions,
            };
            pack.state_height = cp.state_height;
            pack.checkpoint = serde_json::to_value(&proof).unwrap();
            let profile = build_profile(&pack);
            let fixture = serde_json::json!({
                "anchor": {
                    "chain_id": anchor.chain_id,
                    "genesis_hash": hex::encode(anchor.genesis_hash),
                    "committee_root": hex::encode(anchor.committee_root),
                },
                "pack": pack,
                "profile": profile,
            });
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&fixture).unwrap() + "\n",
            )
            .unwrap();
        }

        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the shared fixture")).unwrap();
        let b32 = |v: &serde_json::Value| -> [u8; 32] {
            hex::decode(v.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let anchor = GenesisAnchor {
            chain_id: fixture["anchor"]["chain_id"].as_u64().unwrap(),
            genesis_hash: b32(&fixture["anchor"]["genesis_hash"]),
            committee_root: b32(&fixture["anchor"]["committee_root"]),
        };
        let pack: EvidencePack = serde_json::from_value(fixture["pack"].clone()).unwrap();
        let profile: Profile = serde_json::from_value(fixture["profile"].clone()).unwrap();
        let report = verify_profile(&pack, &profile, &anchor, None, no_receipt).unwrap();
        assert_eq!(report.signed_tool_calls, 2);
        assert_eq!(report.pack.entries, 3);
        assert!(
            verify_profile(
                &pack,
                &profile,
                &GenesisAnchor {
                    committee_root: [0; 32],
                    ..anchor
                },
                None,
                no_receipt
            )
            .is_err()
        );
    }
    /// A validator replaces its hardware key at an epoch boundary on the
    /// running chain: the committee of epoch 1 carries its new key, which the
    /// last checkpoint of epoch 0 commits. A client from genesis still
    /// verifies the epoch 0 checkpoint signed with the old key, verifies the
    /// epoch 1 checkpoint signed with the new one, and from epoch 1 refuses a
    /// session certified by the retired key.
    #[test]
    fn a_validator_rekeys_at_an_epoch_boundary_and_earlier_checkpoints_still_verify() {
        use crate::validator_key::ValidatorSigner;
        let (c0, s) = committee(4);
        let replacement = SoftwareTestSigner::from_seed(4_242);
        let mut members = c0.members().to_vec();
        assert_ne!(&members[0].public_key, replacement.public_key());
        members[0].public_key = replacement.public_key().clone();
        let c1 = Committee::from_members(1, members).unwrap();
        let end = Checkpoint {
            next_committee_root: Some(c1.root()),
            ..checkpoint(5, 1)
        };
        let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
        let s1 = [&replacement, &s[1], &s[2], &s[3]];
        let cp = Checkpoint {
            epoch: 1,
            ..checkpoint(9, 2)
        };
        let (certificate, sessions) = certify(&c1, &s1, &[0, 1, 2], &cp);
        let anchor = GenesisAnchor {
            chain_id: 7,
            genesis_hash: [1; 32],
            committee_root: c0.root(),
        };

        // The epoch 0 checkpoint, signed by the old key, from genesis.
        let old = CheckpointProof {
            genesis_members: c0.members().to_vec(),
            handovers: vec![],
            certificate: handover.clone(),
            sessions: handover_sessions.clone(),
        };
        assert_eq!(old.verify(&anchor).unwrap().index, 5);

        // The epoch 1 checkpoint, signed with the new key, through the
        // handover.
        let new = CheckpointProof {
            genesis_members: c0.members().to_vec(),
            handovers: vec![EpochHandover {
                certificate: handover,
                sessions: handover_sessions,
                next_members: c1.members().to_vec(),
            }],
            certificate,
            sessions,
        };
        assert_eq!(new.verify(&anchor).unwrap().index, 9);

        // The retired key no longer certifies a session in epoch 1; the new
        // one does.
        let stale = sign_as(&s[0], &MemoryHighWater::default(), 0, &cp).unwrap();
        let mut book = SessionBook::new(cp.chain_id, cp.genesis_hash, 1);
        assert!(book.admit(&c1, stale.signature.session.clone()).is_err());
        let fresh = sign_as(&replacement, &MemoryHighWater::default(), 0, &cp).unwrap();
        assert!(book.admit(&c1, fresh.signature.session.clone()).is_ok());
    }
    /// The whole committee moves to ML-DSA-87 hardware keys at an epoch
    /// boundary on the running chain. A client from genesis verifies the
    /// epoch 0 checkpoint certified under the ML-DSA-65 keys and the epoch 1
    /// checkpoint certified under the ML-DSA-87 keys; a signature of one
    /// scheme never verifies under a key of the other.
    #[test]
    fn a_committee_migrates_to_a_second_signature_scheme_and_earlier_checkpoints_still_verify() {
        use crate::validator_key::{SignatureScheme, ValidatorSigner};
        let (c0, s) = committee(4);
        let next: Vec<SoftwareTestSigner> = (0..4)
            .map(|i| {
                SoftwareTestSigner::from_seed_with_scheme(9_000 + i, SignatureScheme::MlDsa87P384)
            })
            .collect();
        let mut members = c0.members().to_vec();
        for (m, k) in members.iter_mut().zip(&next) {
            assert_eq!(k.public_key().scheme(), SignatureScheme::MlDsa87P384);
            m.public_key = k.public_key().clone();
        }
        let c1 = Committee::from_members(1, members).unwrap();
        let end = Checkpoint {
            next_committee_root: Some(c1.root()),
            ..checkpoint(5, 1)
        };
        let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
        let cp = Checkpoint {
            epoch: 1,
            ..checkpoint(9, 2)
        };
        let (certificate, sessions) = certify(&c1, &next, &[0, 1, 3], &cp);
        let anchor = GenesisAnchor {
            chain_id: 7,
            genesis_hash: [1; 32],
            committee_root: c0.root(),
        };
        let old = CheckpointProof {
            genesis_members: c0.members().to_vec(),
            handovers: vec![],
            certificate: handover.clone(),
            sessions: handover_sessions.clone(),
        };
        assert_eq!(old.verify(&anchor).unwrap().index, 5);
        let new = CheckpointProof {
            genesis_members: c0.members().to_vec(),
            handovers: vec![EpochHandover {
                certificate: handover,
                sessions: handover_sessions,
                next_members: c1.members().to_vec(),
            }],
            certificate,
            sessions,
        };
        assert_eq!(new.verify(&anchor).unwrap().index, 9);

        // No cross-scheme verification, in either direction.
        let by_old = s[0].sign(b"tenzro/test", b"m").unwrap();
        let by_new = next[0].sign(b"tenzro/test", b"m").unwrap();
        assert!(next[0].public_key().verify(b"tenzro/test", b"m", &by_new));
        assert!(!next[0].public_key().verify(b"tenzro/test", b"m", &by_old));
        assert!(!s[0].public_key().verify(b"tenzro/test", b"m", &by_new));
    }
}
