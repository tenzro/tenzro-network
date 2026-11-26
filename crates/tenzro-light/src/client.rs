//! The light client's state: the committee it trusts and the newest
//! checkpoint certified under it.

use bincode::Options as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenzro_finality::Digest;
use tenzro_finality::checkpoint::{Certificate, CertificateContext, Checkpoint};
use tenzro_finality::committee::{Committee, Member};
use tenzro_finality::session::{SessionBook, SessionCertificate};

#[cfg(feature = "compact")]
use crate::compact::{CompactCertificate, ProofSetups};
use crate::error::{LightError, Result, malformed};

/// Where trust starts: a chain and the root of one epoch's committee. At
/// epoch 0 it is the genesis anchor, both from the genesis file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustAnchor {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis block hash.
    pub genesis_hash: Digest,
    /// Epoch of the trusted committee.
    pub epoch: u64,
    /// Root of the trusted committee.
    pub committee_root: Digest,
}

/// The caller's clock and how far a checkpoint's block time may be from it.
///
/// A checkpoint's time is the block time of its last block, inside the body
/// a quorum signed. It is trusted exactly as far as the state root beside
/// it: a quorum of seats that would sign a false time would sign a false
/// state. What the bound adds is a defence against a node, not against the
/// committee: a node cannot forge a certificate, but it can serve an old one
/// to hide what changed since, and only the caller's clock tells the two
/// apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// The caller's time, milliseconds since the Unix epoch.
    pub now_ms: u64,
    /// Oldest a checkpoint may be.
    pub max_age_ms: u64,
    /// Furthest a checkpoint's time may be ahead of `now_ms`: the clock
    /// difference the caller tolerates.
    pub max_ahead_ms: u64,
}

impl Clock {
    /// Refuses a checkpoint older than the bound or further ahead of the
    /// caller's clock than the tolerated difference.
    pub fn check(&self, checkpoint: &Checkpoint) -> Result<()> {
        let ahead_ms = checkpoint.timestamp_ms.saturating_sub(self.now_ms);
        if ahead_ms > self.max_ahead_ms {
            return Err(LightError::AheadOfClock {
                ahead_ms,
                max_ahead_ms: self.max_ahead_ms,
            });
        }
        let age_ms = self.now_ms.saturating_sub(checkpoint.timestamp_ms);
        if age_ms > self.max_age_ms {
            return Err(LightError::TooOld {
                age_ms,
                max_age_ms: self.max_age_ms,
            });
        }
        Ok(())
    }
}

/// What certifies a checkpoint: a quorum's signatures, or the compact form
/// in which one STARK stands in for the quorum's ML-DSA signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proof {
    /// A quorum certificate.
    Quorum(Certificate),
    /// A compact certificate.
    #[cfg(feature = "compact")]
    Compact(CompactCertificate),
}

impl Proof {
    /// The checkpoint the proof certifies.
    pub fn checkpoint(&self) -> &Checkpoint {
        match self {
            Proof::Quorum(c) => &c.checkpoint,
            #[cfg(feature = "compact")]
            Proof::Compact(c) => &c.checkpoint,
        }
    }
}

/// A certificate and the session certificates it names: all a third party
/// needs, with the committee, to check it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certified {
    /// The certificate.
    pub proof: Proof,
    /// The session certificates it names.
    pub sessions: Vec<SessionCertificate>,
}

/// Two certificates of one committee that cannot both be of one chain: the
/// same index with different checkpoints, or neighbouring indices where the
/// later does not build on the earlier. A quorum signed each, so more than
/// a third of the seats signed both: the committee's safety is broken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    /// The certificate the client held.
    pub held: Certified,
    /// The certificate that contradicts it.
    pub offered: Certified,
}

const SAVED_MAGIC: &[u8; 4] = b"TZLC";
const SAVED_VERSION: u8 = 1;
const SAVED_CHECK_LEN: usize = 32;

/// What [`LightClient::save`] writes after the magic and the version.
#[derive(Serialize, Deserialize)]
struct Saved {
    chain_id: u64,
    genesis_hash: Digest,
    epoch: u64,
    committee_root: Digest,
    members: Vec<Member>,
    latest: Option<Certified>,
    conflict: Option<Conflict>,
}

impl Saved {
    /// The magic, the version, the state and a digest of all three.
    fn sealed(&self) -> Vec<u8> {
        let mut out = SAVED_MAGIC.to_vec();
        out.push(SAVED_VERSION);
        bincode::serialize_into(&mut out, self).expect("light client state encodes");
        let check = Sha256::digest(&out);
        out.extend_from_slice(&check);
        out
    }
}

/// A light client of one chain.
pub struct LightClient {
    chain_id: u64,
    genesis_hash: Digest,
    committee: Committee,
    sessions: SessionBook,
    /// Set-ups of the compact certificate proof, built on the first compact
    /// certificate of an epoch.
    #[cfg(feature = "compact")]
    setups: ProofSetups,
    latest: Option<Certified>,
    conflict: Option<Box<Conflict>>,
}

impl LightClient {
    /// A client trusting the committee `anchor` names. `members` come from
    /// anywhere; they are kept only when they hash to the anchor's root.
    pub fn new(anchor: &TrustAnchor, members: Vec<Member>) -> Result<Self> {
        let committee = Committee::from_members(anchor.epoch, members)?;
        if committee.root() != anchor.committee_root {
            return Err(LightError::CommitteeMismatch);
        }
        Ok(Self::over(
            anchor.chain_id,
            anchor.genesis_hash,
            committee,
            None,
        ))
    }

    pub(crate) fn over(
        chain_id: u64,
        genesis_hash: Digest,
        committee: Committee,
        latest: Option<Certified>,
    ) -> Self {
        let sessions = SessionBook::new(chain_id, genesis_hash, committee.epoch);
        Self {
            chain_id,
            genesis_hash,
            committee,
            sessions,
            #[cfg(feature = "compact")]
            setups: ProofSetups::new(),
            latest,
            conflict: None,
        }
    }

    /// The client's state as bytes the caller keeps: the committee reached,
    /// the newest certified checkpoint with its certificate, and a conflict
    /// if one was found. The bytes carry a format version and a digest of
    /// themselves, so damage is noticed on [`Self::restore`].
    ///
    /// The digest is not a signature. Whoever can write the caller's storage
    /// can put back an older blob this client once wrote, and that is the
    /// very rollback the client refuses from a node. Keeping the blob from
    /// being replaced is the caller's job; a caller that can keep one number
    /// safely (a hardware counter, a keystore entry) keeps the newest
    /// checkpoint's index and passes it to [`Self::restore`].
    pub fn save(&self) -> Vec<u8> {
        Saved {
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            epoch: self.committee.epoch,
            committee_root: self.committee.root(),
            members: self.committee.members().to_vec(),
            latest: self.latest.clone(),
            conflict: self.conflict.as_deref().cloned(),
        }
        .sealed()
    }

    /// A client from bytes [`Self::save`] wrote, for the chain the caller
    /// names. Refused: bytes of another format version, damaged bytes, a
    /// state of another chain, members that do not hash to the saved root, a
    /// newest checkpoint that is not of the saved committee's epoch or the
    /// handover into it, and a state whose newest checkpoint is behind
    /// `at_least_index`, the index the caller last saw this client reach
    /// (zero when the caller keeps none).
    ///
    /// The bytes are trusted as the caller's own storage is: the trailing
    /// SHA-256 catches damage, not a forgery, since anyone who can write the
    /// storage can recompute it.
    pub fn restore(
        saved: &[u8],
        chain_id: u64,
        genesis_hash: &Digest,
        at_least_index: u64,
    ) -> Result<Self> {
        let what = "saved state";
        let header = SAVED_MAGIC.len() + 1;
        if saved.len() < header + SAVED_CHECK_LEN || &saved[..SAVED_MAGIC.len()] != SAVED_MAGIC {
            return Err(malformed(what, "not a saved light client state"));
        }
        if saved[SAVED_MAGIC.len()] != SAVED_VERSION {
            return Err(malformed(
                what,
                format!(
                    "format version {}, this client reads {SAVED_VERSION}",
                    saved[4]
                ),
            ));
        }
        let (body, check) = saved.split_at(saved.len() - SAVED_CHECK_LEN);
        if Sha256::digest(body).as_slice() != check {
            return Err(malformed(what, "the bytes are damaged"));
        }
        let s: Saved = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes()
            .with_limit(body.len() as u64)
            .deserialize(&body[header..])
            .map_err(|e| malformed(what, e))?;
        if s.chain_id != chain_id || &s.genesis_hash != genesis_hash {
            return Err(malformed(what, "it is of another chain"));
        }
        let committee = Committee::from_members(s.epoch, s.members)?;
        if committee.root() != s.committee_root {
            return Err(LightError::CommitteeMismatch);
        }
        let held = s.latest.as_ref().map(|l| l.proof.checkpoint());
        if let Some(cp) = held {
            let of_this_epoch = cp.epoch == s.epoch;
            let handed_over = cp.epoch.checked_add(1) == Some(s.epoch)
                && cp.next_committee_root == Some(s.committee_root);
            if cp.chain_id != chain_id
                || &cp.genesis_hash != genesis_hash
                || !(of_this_epoch || handed_over)
            {
                return Err(malformed(
                    what,
                    "its newest checkpoint is not of its committee",
                ));
            }
        }
        let reached = held.map_or(0, |cp| cp.index);
        if reached < at_least_index {
            return Err(LightError::SavedStateBehind {
                at_least: at_least_index,
                got: reached,
            });
        }
        let mut client = Self::over(s.chain_id, s.genesis_hash, committee, s.latest);
        client.conflict = s.conflict.map(Box::new);
        Ok(client)
    }

    /// Chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Epoch of the committee the client trusts now.
    pub fn epoch(&self) -> u64 {
        self.committee.epoch
    }

    /// Root of the committee the client trusts now.
    pub fn committee_root(&self) -> Digest {
        self.committee.root()
    }

    /// The newest checkpoint certified so far.
    pub fn latest(&self) -> Option<&Checkpoint> {
        self.latest.as_ref().map(|l| l.proof.checkpoint())
    }

    /// The conflict that stopped the client, if one was found.
    pub fn conflict(&self) -> Option<&Conflict> {
        self.conflict.as_deref()
    }

    /// Lets a stopped client check certificates again. The caller decides
    /// when: a conflict means the committee signed two histories, and the
    /// client cannot tell which one the rest of the network follows.
    pub fn resume(&mut self) {
        self.conflict = None;
    }

    /// Verifies `proof` under the current committee. A session certificate
    /// enters the book only when the certificate that names it verified.
    fn verified(&mut self, proof: &Proof, sessions: &[SessionCertificate]) -> Result<()> {
        if self.conflict.is_some() {
            return Err(LightError::Stopped);
        }
        let mut book = self.sessions.clone();
        for s in sessions {
            book.admit(&self.committee, s.clone())?;
        }
        let ctx = CertificateContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &self.committee,
            sessions: &book,
        };
        match proof {
            Proof::Quorum(c) => c.verify(&ctx)?,
            #[cfg(feature = "compact")]
            Proof::Compact(c) => c.verify(&ctx, &self.setups)?,
        }
        self.sessions = book;
        Ok(())
    }

    /// Holds a verified proof against the newest one held. Returns whether
    /// it is behind the newest. A contradiction stops the client.
    fn behind_held(&mut self, proof: &Proof, sessions: &[SessionCertificate]) -> Result<bool> {
        let Some(held) = &self.latest else {
            return Ok(false);
        };
        let (new, old) = (proof.checkpoint(), held.proof.checkpoint());
        let contradicts = if new.index == old.index {
            new != old
        } else if new.index == old.index + 1 {
            new.prev != old.digest()
        } else if new.index + 1 == old.index {
            old.prev != new.digest()
        } else {
            false
        };
        if contradicts {
            let conflict = Box::new(Conflict {
                held: held.clone(),
                offered: Certified {
                    proof: proof.clone(),
                    sessions: sessions.to_vec(),
                },
            });
            self.conflict = Some(conflict.clone());
            return Err(LightError::Conflict(conflict));
        }
        Ok(new.index < old.index)
    }

    /// Refuses a verified proof behind the newest held.
    fn not_behind_held(&mut self, proof: &Proof, sessions: &[SessionCertificate]) -> Result<()> {
        if self.behind_held(proof, sessions)? {
            return Err(LightError::Stale {
                held: self.latest().map_or(0, |cp| cp.index),
                got: proof.checkpoint().index,
            });
        }
        Ok(())
    }

    /// Checks a certificate of the current epoch and returns its checkpoint.
    /// `sessions` are the session certificates it names; each is checked
    /// against the hardware key of the committee member it names. The
    /// client's newest checkpoint does not move: this is how a checkpoint
    /// older than the newest is verified. One that contradicts the newest
    /// stops the client. It does no age check: the checkpoint may be of any
    /// age, and the caller judges whether it is recent enough.
    pub fn certified(
        &mut self,
        certificate: &Certificate,
        sessions: Vec<SessionCertificate>,
    ) -> Result<Checkpoint> {
        let proof = Proof::Quorum(certificate.clone());
        self.verified(&proof, &sessions)?;
        self.behind_held(&proof, &sessions)?;
        Ok(certificate.checkpoint.clone())
    }

    /// Checks `proof` and makes its checkpoint the newest. The clock is
    /// checked first, so a stale checkpoint is never kept.
    fn accept(
        &mut self,
        proof: Proof,
        sessions: Vec<SessionCertificate>,
        clock: &Clock,
    ) -> Result<&Checkpoint> {
        clock.check(proof.checkpoint())?;
        self.verified(&proof, &sessions)?;
        self.not_behind_held(&proof, &sessions)?;
        let held = self.latest.insert(Certified { proof, sessions });
        Ok(held.proof.checkpoint())
    }

    /// Checks a certificate as [`Self::certified`] does and makes its
    /// checkpoint the newest. A checkpoint with a lower index than the
    /// newest held is refused, so a node cannot walk the client back, and
    /// so is one outside `clock`'s bounds, before anything is kept: a
    /// stale checkpoint never becomes the newest, so it is never saved.
    pub fn advance(
        &mut self,
        certificate: &Certificate,
        sessions: Vec<SessionCertificate>,
        clock: &Clock,
    ) -> Result<&Checkpoint> {
        self.accept(Proof::Quorum(certificate.clone()), sessions, clock)
    }

    /// [`Self::advance`] for a compact certificate. The first one of an
    /// epoch builds the proof set-up for the committee's session keys, the
    /// costly part of checking it.
    #[cfg(feature = "compact")]
    pub fn advance_compact(
        &mut self,
        certificate: &CompactCertificate,
        sessions: Vec<SessionCertificate>,
        clock: &Clock,
    ) -> Result<&Checkpoint> {
        self.accept(Proof::Compact(certificate.clone()), sessions, clock)
    }

    /// Checks `proof` as the node's own followers always have, for proofs a
    /// node or a block may be asked to verify: a session certificate that
    /// fails admission is dropped, an older checkpoint is accepted without
    /// becoming the newest, and two checkpoints are not compared. Nodes old
    /// and new must reach the same verdict on such a proof during a rolling
    /// update, so this path does not take the stricter checks of
    /// [`Self::advance`].
    pub(crate) fn replay(&mut self, proof: Proof, sessions: Vec<SessionCertificate>) -> Result<()> {
        for s in &sessions {
            let _ = self.sessions.admit(&self.committee, s.clone());
        }
        let ctx = CertificateContext {
            chain_id: self.chain_id,
            genesis_hash: &self.genesis_hash,
            committee: &self.committee,
            sessions: &self.sessions,
        };
        match &proof {
            Proof::Quorum(c) => c.verify(&ctx)?,
            #[cfg(feature = "compact")]
            Proof::Compact(c) => c.verify(&ctx, &self.setups)?,
        }
        if self
            .latest()
            .is_none_or(|held| proof.checkpoint().index > held.index)
        {
            self.latest = Some(Certified { proof, sessions });
        }
        Ok(())
    }

    /// Moves to the next epoch after [`Self::replay`] accepted the epoch's
    /// last checkpoint, as the node's own followers always have: the newest
    /// accepted checkpoint must end the current epoch and commit exactly
    /// `members`.
    pub(crate) fn replay_hand_over(&mut self, members: Vec<Member>) -> Result<()> {
        let refuse = |why: &str| Err(LightError::InvalidCertificate(why.into()));
        let Some(newest) = self.latest() else {
            return refuse("no accepted checkpoint ends the current epoch");
        };
        let Some(root) = newest.next_committee_root else {
            return refuse("no accepted checkpoint ends the current epoch");
        };
        if newest.epoch != self.committee.epoch {
            return refuse("the latest checkpoint is of another epoch");
        }
        let next = Committee::from_members(self.committee.epoch + 1, members)?;
        if next.root() != root {
            return refuse("the members are not the committee the epoch's last checkpoint commits");
        }
        let held = self.latest.take();
        *self = Self::over(self.chain_id, self.genesis_hash, next, held);
        Ok(())
    }

    /// Moves to the next epoch: `certificate` is of the current epoch's last
    /// checkpoint, which commits the root of the next committee, and
    /// `next_members` hash to that root. The handover takes the quorum
    /// certificate: there is no compact handover, and a compact certificate
    /// of an epoch's last checkpoint moves no committee.
    pub fn hand_over(
        &mut self,
        certificate: &Certificate,
        sessions: Vec<SessionCertificate>,
        next_members: Vec<Member>,
    ) -> Result<()> {
        let proof = Proof::Quorum(certificate.clone());
        self.verified(&proof, &sessions)?;
        self.not_behind_held(&proof, &sessions)?;
        let root = certificate
            .checkpoint
            .next_committee_root
            .ok_or(LightError::NotEpochEnd)?;
        let next = Committee::from_members(self.committee.epoch + 1, next_members)?;
        if next.root() != root {
            return Err(LightError::CommitteeMismatch);
        }
        let held = Certified { proof, sessions };
        *self = Self::over(self.chain_id, self.genesis_hash, next, Some(held));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{CHAIN_ID, GENESIS, Net};
    use tenzro_finality::FinalityError;

    fn refused(r: Result<impl std::fmt::Debug>, needle: &str) {
        match r {
            Err(LightError::Finality(FinalityError::InvalidCertificate(why))) => {
                assert!(why.contains(needle), "refused for another reason: {why}")
            }
            other => panic!("expected a refused certificate, got {other:?}"),
        }
    }

    #[test]
    fn a_quorum_certificate_is_accepted_and_becomes_the_newest() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (cert, sessions) = net.certify(&net.checkpoint(7), &[0, 1, 2]);
        let cp = lc.advance(&cert, sessions, &Net::clock()).unwrap().clone();
        assert_eq!(cp.index, 7);
        assert_eq!(lc.latest(), Some(&cp));
    }

    #[test]
    fn members_that_do_not_match_the_anchor_are_refused() {
        let net = Net::new(4);
        let other = Net::new(5);
        assert!(matches!(
            LightClient::new(&net.anchor(), other.members.clone()),
            Err(LightError::CommitteeMismatch)
        ));
    }

    #[test]
    fn fewer_seats_than_a_quorum_are_refused() {
        let net = Net::new(4);
        let (cert, sessions) = net.certify(&net.checkpoint(1), &[0, 1]);
        refused(
            net.client().advance(&cert, sessions, &Net::clock()),
            "less than a quorum",
        );
    }

    #[test]
    fn a_certificate_of_another_chain_is_refused() {
        let net = Net::new(4);
        let mut cp = net.checkpoint(1);
        cp.chain_id += 1;
        let (cert, sessions) = net.certify(&cp, &[0, 1, 2]);
        refused(
            net.client().advance(&cert, sessions, &Net::clock()),
            "another chain",
        );
    }

    #[test]
    fn a_certificate_of_another_epoch_is_refused() {
        let net = Net::new(4);
        let mut cp = net.checkpoint(1);
        cp.epoch += 1;
        let (cert, sessions) = net.certify(&cp, &[0, 1, 2]);
        refused(
            net.client().advance(&cert, sessions, &Net::clock()),
            "another epoch",
        );
    }

    #[test]
    fn a_checkpoint_changed_after_signing_is_refused() {
        let net = Net::new(4);
        let (mut cert, sessions) = net.certify(&net.checkpoint(1), &[0, 1, 2]);
        cert.checkpoint.state_root = [0xEE; 32];
        refused(
            net.client().advance(&cert, sessions, &Net::clock()),
            "does not verify",
        );
    }

    #[test]
    fn a_session_key_its_validator_did_not_certify_is_refused() {
        let net = Net::new(4);
        let (cert, mut sessions) = net.certify(&net.checkpoint(1), &[0, 1, 2]);
        // Validator 2's session certificate signed by validator 3's hardware key.
        sessions[2].signature = net.hardware_signature(3, &sessions[2]);
        refused(
            net.client().advance(&cert, sessions, &Net::clock()),
            "not signed by its validator",
        );
    }

    #[test]
    fn a_certificate_without_its_session_certificates_is_refused() {
        let net = Net::new(4);
        let (cert, _) = net.certify(&net.checkpoint(1), &[0, 1, 2]);
        refused(
            net.client().advance(&cert, Vec::new(), &Net::clock()),
            "not in the epoch's bundle",
        );
    }

    #[test]
    fn a_node_cannot_walk_the_client_back() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (new, s) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        lc.advance(&new, s, &Net::clock()).unwrap();
        let (old, s) = net.certify(&net.checkpoint(8), &[0, 1, 2]);
        assert!(matches!(
            lc.advance(&old, s.clone(), &Net::clock()),
            Err(LightError::Stale { held: 9, got: 8 })
        ));
        // The older checkpoint is still certified; it only cannot be the newest.
        assert_eq!(lc.certified(&old, s).unwrap().index, 8);
        assert_eq!(lc.latest().unwrap().index, 9);
    }

    #[test]
    fn two_certified_checkpoints_with_one_index_are_a_conflict() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (a, s) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        lc.advance(&a, s, &Net::clock()).unwrap();
        let mut other = net.checkpoint(9);
        other.state_root = [0xEE; 32];
        let (b, s) = net.certify(&other, &[1, 2, 3]);
        match lc.advance(&b, s, &Net::clock()) {
            Err(LightError::Conflict(pair)) => {
                assert_eq!(pair.held.proof, Proof::Quorum(a.clone()));
                assert_eq!(pair.offered.proof, Proof::Quorum(b.clone()));
                assert_eq!(pair.offered.sessions.len(), 3);
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        assert_eq!(
            lc.conflict().unwrap().offered.proof,
            Proof::Quorum(b.clone())
        );

        // Stopped: not even a good certificate is checked, across a restart too.
        let good = net.after(&a.checkpoint);
        let (next, s) = net.certify(&good, &[0, 1, 2]);
        assert!(matches!(
            lc.advance(&next, s.clone(), &Net::clock()),
            Err(LightError::Stopped)
        ));
        assert!(matches!(
            lc.certified(&next, s.clone()),
            Err(LightError::Stopped)
        ));
        let mut back = LightClient::restore(&lc.save(), CHAIN_ID, &GENESIS, 9).unwrap();
        assert!(matches!(
            back.advance(&next, s.clone(), &Net::clock()),
            Err(LightError::Stopped)
        ));

        // The caller decides to go on.
        lc.resume();
        assert_eq!(lc.advance(&next, s, &Net::clock()).unwrap().index, 10);
    }

    #[test]
    fn a_checkpoint_the_newest_does_not_build_on_is_a_conflict() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (held, s) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        lc.advance(&held, s, &Net::clock()).unwrap();
        // One below the newest, but not the one the newest names as previous.
        let mut below = net.checkpoint(8);
        below.state_root = [0xEE; 32];
        let (cert, s) = net.certify(&below, &[0, 1, 2]);
        assert!(matches!(
            lc.certified(&cert, s),
            Err(LightError::Conflict(_))
        ));
        assert!(lc.conflict().is_some());
    }

    #[test]
    fn a_next_checkpoint_that_does_not_build_on_the_newest_is_a_conflict() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (held, s) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        lc.advance(&held, s, &Net::clock()).unwrap();
        let mut above = net.checkpoint(10);
        above.prev = [0xEE; 32];
        let (cert, s) = net.certify(&above, &[0, 1, 2]);
        assert!(matches!(
            lc.advance(&cert, s, &Net::clock()),
            Err(LightError::Conflict(_))
        ));
        assert_eq!(lc.latest().unwrap().index, 9);
    }

    #[test]
    fn a_signer_counted_twice_is_refused() {
        let net = Net::new(4);
        let (cert, sessions) = net.certify(&net.checkpoint(1), &[0, 1, 1]);
        refused(
            net.client().advance(&cert, sessions, &Net::clock()),
            "not strictly ascending",
        );
    }

    #[test]
    fn session_certificates_of_a_refused_certificate_are_not_kept() {
        let net = Net::new(4);
        let mut lc = net.client();
        let cp = net.checkpoint(1);
        let (short, sessions) = net.certify(&cp, &[0, 1]);
        refused(
            lc.advance(&short, sessions, &Net::clock()),
            "less than a quorum",
        );
        // Had the two been kept, this certificate would need only the third.
        let (full, sessions) = net.certify(&cp, &[0, 1, 2]);
        refused(
            lc.advance(&full, sessions[2..].to_vec(), &Net::clock()),
            "not in the epoch's bundle",
        );
    }

    #[test]
    fn a_handover_moves_to_the_committed_committee_only() {
        let net = Net::new(4);
        let next = net.next_epoch(5);
        let mut last = net.checkpoint(3);
        last.next_committee_root = Some(next.committee().root());
        let (cert, sessions) = net.certify(&last, &[0, 1, 2]);

        let mut lc = net.client();
        let wrong = net.next_epoch(6);
        assert!(matches!(
            lc.hand_over(&cert, sessions.clone(), wrong.members.clone()),
            Err(LightError::CommitteeMismatch)
        ));
        assert_eq!(lc.epoch(), 0);

        lc.hand_over(&cert, sessions, next.members.clone()).unwrap();
        assert_eq!(lc.epoch(), 1);
        assert_eq!(lc.committee_root(), next.committee().root());

        // The new committee's certificates verify; the old committee's no longer do.
        let (cert, sessions) = next.certify(&next.after(&last), &[0, 1, 2, 3]);
        assert_eq!(lc.advance(&cert, sessions, &Net::clock()).unwrap().index, 4);
        let mut stray = net.checkpoint(5);
        stray.epoch = 1;
        let (cert, sessions) = net.certify(&stray, &[0, 1, 2]);
        assert!(lc.advance(&cert, sessions, &Net::clock()).is_err());
    }

    #[test]
    fn a_handover_replayed_is_refused() {
        let net = Net::new(4);
        let next = net.next_epoch(4);
        let mut last = net.checkpoint(3);
        last.next_committee_root = Some(next.committee().root());
        let (cert, sessions) = net.certify(&last, &[0, 1, 2]);
        let mut lc = net.client();
        lc.hand_over(&cert, sessions.clone(), next.members.clone())
            .unwrap();
        assert!(lc.hand_over(&cert, sessions, next.members.clone()).is_err());
        assert_eq!(lc.epoch(), 1);
    }

    #[test]
    fn a_handover_out_of_a_future_epoch_is_refused() {
        let net = Net::new(4);
        let after_next = net.next_epoch(4).next_epoch(4);
        // The current committee's keys on a checkpoint that claims epoch 1.
        let mut last = net.checkpoint(3);
        last.epoch = 1;
        last.next_committee_root = Some(after_next.committee().root());
        let (cert, sessions) = net.certify(&last, &[0, 1, 2]);
        let mut lc = net.client();
        refused(
            lc.hand_over(&cert, sessions, after_next.members.clone()),
            "another epoch",
        );
        assert_eq!(lc.epoch(), 0);
    }

    #[test]
    fn a_handover_needs_a_checkpoint_that_ends_its_epoch() {
        let net = Net::new(4);
        let (cert, sessions) = net.certify(&net.checkpoint(3), &[0, 1, 2]);
        assert!(matches!(
            net.client()
                .hand_over(&cert, sessions, net.next_epoch(4).members.clone()),
            Err(LightError::NotEpochEnd)
        ));
    }

    #[test]
    fn saved_state_restores_the_committee_and_the_newest_checkpoint() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (cert, sessions) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        lc.advance(&cert, sessions, &Net::clock()).unwrap();
        let mut back = LightClient::restore(&lc.save(), CHAIN_ID, &GENESIS, 9).unwrap();
        assert_eq!(back.committee_root(), lc.committee_root());
        assert_eq!(back.latest(), lc.latest());
        let (old, s) = net.certify(&net.checkpoint(8), &[0, 1, 2]);
        assert!(matches!(
            back.advance(&old, s, &Net::clock()),
            Err(LightError::Stale { .. })
        ));
    }

    #[test]
    fn two_certificates_of_one_checkpoint_are_no_conflict() {
        // One checkpoint certified twice by different quorums.
        let net = Net::new(4);
        let mut lc = net.client();
        let cp = net.checkpoint(9);
        let (a, s) = net.certify(&cp, &[0, 1, 2]);
        lc.advance(&a, s, &Net::clock()).unwrap();
        let (b, s) = net.certify(&cp, &[1, 2, 3]);
        lc.advance(&b, s, &Net::clock()).unwrap();
        let (next, s) = net.certify(&net.checkpoint(10), &[0, 1, 3]);
        lc.advance(&next, s, &Net::clock()).unwrap();
        assert!(lc.conflict().is_none());
        assert_eq!(lc.latest().unwrap().index, 10);
    }

    #[test]
    fn a_restarted_validator_signing_a_checkpoint_again_is_no_conflict() {
        // A validator restarts from its last certified checkpoint and decides
        // the next index again. Every field of a checkpoint comes from the
        // committed prefix (its time is the median of the anchor's parents),
        // so it derives the same checkpoint; only its session key is new.
        let net = Net::new(4);
        let mut lc = net.client();
        let cp = net.checkpoint(9);
        let (a, s) = net.certify(&cp, &[0, 1, 2]);
        lc.advance(&a, s, &Net::clock()).unwrap();
        let after = net.restarted(0);
        let (b, s) = after.certify(&cp, &[0, 1, 2]);
        assert_ne!(a.sessions[0], b.sessions[0]);
        assert_eq!(lc.advance(&b, s, &Net::clock()).unwrap().index, 9);
        let (next, s) = after.certify(&net.checkpoint(10), &[0, 1, 3]);
        lc.advance(&next, s, &Net::clock()).unwrap();
        assert!(lc.conflict().is_none());
        assert_eq!(lc.latest().unwrap().index, 10);
    }

    #[test]
    fn the_node_path_accepts_an_older_checkpoint_without_moving_back() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (new, s) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        lc.replay(Proof::Quorum(new), s).unwrap();
        let (old, s) = net.certify(&net.checkpoint(8), &[0, 1, 2]);
        lc.replay(Proof::Quorum(old), s).unwrap();
        assert_eq!(lc.latest().unwrap().index, 9);
    }

    #[test]
    fn the_node_path_drops_a_session_certificate_that_fails_admission() {
        let net = Net::new(4);
        let (cert, mut sessions) = net.certify(&net.checkpoint(1), &[0, 1, 2]);
        let mut foreign = sessions[0].clone();
        foreign.chain_id += 1;
        sessions.push(foreign);
        let mut lc = net.client();
        lc.replay(Proof::Quorum(cert.clone()), sessions.clone())
            .unwrap();
        assert_eq!(lc.latest().unwrap().index, 1);
        // The app path refuses the same bundle.
        assert!(
            net.client()
                .advance(&cert, sessions, &Net::clock())
                .is_err()
        );
    }

    #[test]
    fn a_saved_state_put_back_from_before_is_refused() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (cert, sessions) = net.certify(&net.checkpoint(8), &[0, 1, 2]);
        lc.advance(&cert, sessions, &Net::clock()).unwrap();
        let older = lc.save();
        let (cert, sessions) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        lc.advance(&cert, sessions, &Net::clock()).unwrap();
        // The caller saw the client reach 9; the blob from 8 is a rollback.
        assert!(matches!(
            LightClient::restore(&older, CHAIN_ID, &GENESIS, 9),
            Err(LightError::SavedStateBehind {
                at_least: 9,
                got: 8
            })
        ));
        assert!(matches!(
            LightClient::restore(&net.client().save(), CHAIN_ID, &GENESIS, 1),
            Err(LightError::SavedStateBehind {
                at_least: 1,
                got: 0
            })
        ));
        LightClient::restore(&lc.save(), CHAIN_ID, &GENESIS, 9).unwrap();
    }

    #[test]
    fn damaged_or_foreign_saved_bytes_are_refused() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (cert, sessions) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        lc.advance(&cert, sessions, &Net::clock()).unwrap();
        let good = lc.save();
        let malformed = |bytes: &[u8]| {
            matches!(
                LightClient::restore(bytes, CHAIN_ID, &GENESIS, 0),
                Err(LightError::Malformed { .. })
            )
        };
        assert!(malformed(&[]));
        assert!(malformed(&good[..good.len() - 1]));
        let mut flipped = good.clone();
        flipped[good.len() / 2] ^= 1;
        assert!(malformed(&flipped));
        let mut other_version = good.clone();
        other_version[4] += 1;
        assert!(malformed(&other_version));
        let mut no_magic = good.clone();
        no_magic[0] = b'X';
        assert!(malformed(&no_magic));
        // A state of another chain, intact.
        assert!(matches!(
            LightClient::restore(&good, CHAIN_ID + 1, &GENESIS, 0),
            Err(LightError::Malformed { .. })
        ));
        assert!(matches!(
            LightClient::restore(&good, CHAIN_ID, &[0xEE; 32], 0),
            Err(LightError::Malformed { .. })
        ));
    }

    #[test]
    fn a_saved_state_that_does_not_agree_with_itself_is_refused() {
        let net = Net::new(4);
        let (cert, sessions) = net.certify(&net.checkpoint(9), &[0, 1, 2]);
        let saved = |edit: &dyn Fn(&mut Saved)| {
            let mut s = Saved {
                chain_id: CHAIN_ID,
                genesis_hash: GENESIS,
                epoch: 0,
                committee_root: net.committee().root(),
                members: net.members.clone(),
                latest: Some(Certified {
                    proof: Proof::Quorum(cert.clone()),
                    sessions: sessions.clone(),
                }),
                conflict: None,
            };
            edit(&mut s);
            LightClient::restore(&s.sealed(), CHAIN_ID, &GENESIS, 0)
        };
        saved(&|_| {}).unwrap();
        // Members swapped for another committee under the saved root.
        assert!(matches!(
            saved(&|s| s.members = Net::new(5).members.clone()),
            Err(LightError::CommitteeMismatch)
        ));
        // A newest checkpoint of an epoch the saved committee is not of.
        assert!(matches!(
            saved(&|s| s.epoch = 3),
            Err(LightError::CommitteeMismatch | LightError::Malformed { .. })
        ));
        assert!(matches!(
            saved(&|s| {
                if let Some(Certified {
                    proof: Proof::Quorum(c),
                    ..
                }) = s.latest.as_mut()
                {
                    c.checkpoint.epoch = 7;
                }
            }),
            Err(LightError::Malformed { .. })
        ));
    }

    #[test]
    fn a_checkpoint_outside_the_clock_s_bounds_never_becomes_the_newest() {
        let net = Net::new(4);
        let mut lc = net.client();
        let (cert, sessions) = net.certify(&net.checkpoint(1), &[0, 1, 2]);
        let late = Clock {
            now_ms: cert.checkpoint.timestamp_ms + 3_600_000,
            max_age_ms: 60_000,
            max_ahead_ms: 5_000,
        };
        let before = lc.save();
        assert!(matches!(
            lc.advance(&cert, sessions, &late),
            Err(LightError::TooOld { .. })
        ));
        assert_eq!(lc.latest(), None);
        assert_eq!(lc.save(), before);
    }

    #[test]
    fn a_checkpoint_outside_the_clock_s_bounds_is_refused() {
        let net = Net::new(4);
        let cp = net.checkpoint(1);
        let clock = |now_ms| Clock {
            now_ms,
            max_age_ms: 5_000,
            max_ahead_ms: 1_000,
        };
        clock(cp.timestamp_ms + 5_000).check(&cp).unwrap();
        clock(cp.timestamp_ms - 1_000).check(&cp).unwrap();
        assert!(matches!(
            clock(cp.timestamp_ms + 5_001).check(&cp),
            Err(LightError::TooOld { age_ms: 5_001, .. })
        ));
        assert!(matches!(
            clock(cp.timestamp_ms - 1_001).check(&cp),
            Err(LightError::AheadOfClock {
                ahead_ms: 1_001,
                ..
            })
        ));
    }
}
