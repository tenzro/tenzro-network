//! Checkpoints: the transferable, accountable finality layer.
//!
//! Ordering (the DAG and its commit rule) is final for every honest
//! validator but proves nothing to anyone else. At the first committed
//! anchor at least the checkpoint interval after the previous checkpoint,
//! every validator closes a checkpoint over the blocks ordered since, checks
//! it against its own execution, persists that it is about to vote, and signs
//! the checkpoint digest with its session key, which its hardware key
//! certified for the epoch (see [`crate::session`]); the vote carries that
//! certificate, so it is attributable to the hardware key. A quorum of seats
//! signing one digest is a certificate: anyone holding the committee can
//! check it, and two certificates for one checkpoint index name at least
//! `f + 1` seats that signed both, which is slashable evidence.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::committee::{Committee, SeatSet, ValidatorIndex};
use crate::error::{ConsensusError, Result};
use crate::session::{SessionBook, SessionCertificate};
use crate::validator_key::{ValidatorPublicKey, ValidatorSigner};
use crate::vertex::Digest;

pub use tenzro_finality::checkpoint::{
    CHECKPOINT_VOTE_DOMAIN, Certificate, CertificateContext, Checkpoint, STATE_ROOT_LAG,
    VoteSignature, checkpoint_state_height, state_root_height,
};
pub use tenzro_types::merkle::merkle_root;

/// One validator's signed vote for a checkpoint. The vote carries the
/// checkpoint itself, so two conflicting votes are complete evidence and a
/// validator that has not built the checkpoint yet can still certify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointVote {
    /// The checkpoint voted for.
    pub checkpoint: Checkpoint,
    /// Voter.
    pub signer: ValidatorIndex,
    /// The session key's signature, with its certificate.
    pub signature: VoteSignature,
}

impl CheckpointVote {
    /// Whether the vote is by the validator holding hardware key `key`.
    pub fn verify(&self, key: &ValidatorPublicKey) -> bool {
        self.signature.verify(key, &self.checkpoint)
    }
}

/// Every how many checkpoints a publisher sends the whole bundle of session
/// certificates its certificate names, so that a follower that joined the
/// epoch late, or missed a publication, catches up.
pub const FULL_BUNDLE_EVERY: u64 = 16;

/// A certificate as published to followers, with the session certificates
/// it names that the publisher has not published before in the epoch (all
/// of them on every [`FULL_BUNDLE_EVERY`]th checkpoint).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedCertificate {
    /// The certificate.
    pub certificate: Certificate,
    /// Session certificates for the epoch's bundle.
    pub sessions: Vec<SessionCertificate>,
}

/// Signer `i`'s vote signature in `cert`, with its session certificate from
/// `sessions`.
fn vote_signature(cert: &Certificate, i: usize, sessions: &SessionBook) -> Option<VoteSignature> {
    let (_, session) = sessions.get(cert.sessions.get(i)?)?;
    Some(VoteSignature {
        session: session.clone(),
        signature: cert.signatures.get(i)?.clone(),
    })
}

/// Transferable evidence that one validator signed two different
/// checkpoints with the same index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointEquivocation {
    /// The hardware key of the validator that signed both, through the
    /// session keys it certified.
    pub public_key: ValidatorPublicKey,
    /// One checkpoint.
    pub first: Checkpoint,
    /// Its signature, with the session certificate.
    pub first_signature: VoteSignature,
    /// The other checkpoint, same chain, epoch and index.
    pub second: Checkpoint,
    /// Its signature, with the session certificate.
    pub second_signature: VoteSignature,
}

impl CheckpointEquivocation {
    /// Whether this is proof of equivocation on `chain_id`: both
    /// checkpoints name that chain, one epoch and one index, differ, and
    /// both signatures verify under the key.
    pub fn is_valid(&self, chain_id: u64) -> bool {
        let (a, b) = (&self.first, &self.second);
        if a.chain_id != chain_id
            || b.chain_id != chain_id
            || a.genesis_hash != b.genesis_hash
            || a.epoch != b.epoch
            || a.index != b.index
        {
            return false;
        }
        a.digest() != b.digest()
            && self.first_signature.verify(&self.public_key, a)
            && self.second_signature.verify(&self.public_key, b)
    }

    /// Evidence against every validator that signed both certificates.
    /// Returns nothing unless both certificates verify and certify
    /// different checkpoints with one index.
    pub fn from_conflicting_certificates(
        a: &Certificate,
        b: &Certificate,
        ctx: &CertificateContext<'_>,
    ) -> Vec<(ValidatorIndex, CheckpointEquivocation)> {
        if a.verify(ctx).is_err()
            || b.verify(ctx).is_err()
            || a.checkpoint.index != b.checkpoint.index
            || a.checkpoint.digest() == b.checkpoint.digest()
        {
            return Vec::new();
        }
        let b_at: HashMap<ValidatorIndex, usize> =
            b.signers.iter().enumerate().map(|(i, s)| (*s, i)).collect();
        a.signers
            .iter()
            .enumerate()
            .filter_map(|(i, s)| {
                let j = *b_at.get(s)?;
                Some((
                    *s,
                    CheckpointEquivocation {
                        public_key: ctx.committee.member(*s)?.public_key.clone(),
                        first: a.checkpoint.clone(),
                        first_signature: vote_signature(a, i, ctx.sessions)?,
                        second: b.checkpoint.clone(),
                        second_signature: vote_signature(b, j, ctx.sessions)?,
                    },
                ))
            })
            .collect()
    }
}

/// The checkpoints this validator has signed, persisted before a signature
/// is released so it never signs two different checkpoints for one index,
/// across restarts too.
pub trait VoteHighWater: Send + Sync {
    /// Records that this validator is about to sign `digest` for
    /// (`epoch`, `index`), whose predecessor's digest is `prev`. Refuses a
    /// digest other than one it signed for that index, and, behind its
    /// latest signature, any digest it cannot show consistent with what it
    /// signed: the one it signed for that index, or the predecessor named by
    /// the checkpoint it signed after it.
    fn record(&self, epoch: u64, index: u64, digest: &Digest, prev: &Digest) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct HighWaterMark {
    epoch: u64,
    index: u64,
    digest: Digest,
}

/// Checkpoints behind the high-water mark whose signatures are kept, so a
/// validator can sign again what it signed, after a restart too, and sign
/// a checkpoint it reaches after the next one: the same content signed
/// twice is no equivocation, and a quorum still forming may need the vote.
pub const SIGNED_VOTE_WINDOW: u64 = 1_024;

/// What this validator signed for one checkpoint index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Signed {
    epoch: u64,
    digest: Digest,
    prev: Digest,
}

/// What recording a vote does.
#[derive(Debug, PartialEq, Eq)]
enum Record {
    /// A new latest signature: the mark moves to it.
    Mark,
    /// A checkpoint behind the mark, consistent with what was signed after
    /// it: kept, the mark stays.
    Behind,
    /// The same content signed before: nothing to keep.
    Again,
}

/// Whether to record a vote for (`epoch`, `index`, `digest`), given the
/// mark, what this validator signed for that index, and what it signed for
/// the index after it, while within [`SIGNED_VOTE_WINDOW`] of the mark.
fn check_high_water(
    mark: Option<HighWaterMark>,
    at: Option<Signed>,
    next: Option<Signed>,
    epoch: u64,
    index: u64,
    digest: &Digest,
) -> Result<Record> {
    let refuse = |why: String| Err(ConsensusError::VoteRefused(why));
    match mark {
        None => Ok(Record::Mark),
        Some(m) if (m.epoch, m.index) == (epoch, index) => {
            if &m.digest == digest {
                Ok(Record::Again)
            } else {
                refuse(format!(
                    "already signed a different checkpoint {index} in epoch {epoch}"
                ))
            }
        }
        Some(m) if (m.epoch, m.index) > (epoch, index) => {
            if m.index.saturating_sub(index) >= SIGNED_VOTE_WINDOW {
                return refuse(format!(
                    "already signed checkpoint {} of epoch {}, refusing {index} of epoch {epoch} beyond the window kept",
                    m.index, m.epoch
                ));
            }
            match at {
                Some(a) if a.epoch == epoch && &a.digest == digest => Ok(Record::Again),
                Some(_) => refuse(format!(
                    "already signed a different checkpoint {index} in epoch {epoch}"
                )),
                None if next.is_some_and(|n| &n.prev == digest) => Ok(Record::Behind),
                None => refuse(format!(
                    "already signed checkpoint {} of epoch {}, and checkpoint {index} of epoch {epoch} is not the one it follows",
                    m.index, m.epoch
                )),
            }
        }
        Some(_) => Ok(Record::Mark),
    }
}

/// [`VoteHighWater`] in the node's key-value store, written with fsync.
pub struct KvVoteHighWater {
    store: Arc<dyn tenzro_storage::KvStore>,
    lock: parking_lot::Mutex<()>,
}

const HIGH_WATER_KEY: &[u8] = b"consensus/checkpoint-vote-high-water";

/// Key of the digest signed for checkpoint `index`.
fn signed_vote_key(index: u64) -> Vec<u8> {
    let mut k = b"consensus/checkpoint-vote-signed/".to_vec();
    k.extend_from_slice(&index.to_be_bytes());
    k
}

impl KvVoteHighWater {
    /// The high-water mark kept in `store`.
    pub fn new(store: Arc<dyn tenzro_storage::KvStore>) -> Self {
        Self {
            store,
            lock: parking_lot::Mutex::new(()),
        }
    }
}

impl KvVoteHighWater {
    fn signed(&self, index: u64) -> Result<Option<Signed>> {
        Ok(self
            .store
            .get(tenzro_storage::CF_METADATA, &signed_vote_key(index))
            .map_err(|e| ConsensusError::Storage(e.to_string()))?
            .and_then(|b| bincode::deserialize::<Signed>(&b).ok()))
    }
}

impl VoteHighWater for KvVoteHighWater {
    fn record(&self, epoch: u64, index: u64, digest: &Digest, prev: &Digest) -> Result<()> {
        let _g = self.lock.lock();
        let mark = self
            .store
            .get(tenzro_storage::CF_METADATA, HIGH_WATER_KEY)
            .map_err(|e| ConsensusError::Storage(e.to_string()))?
            .map(|b| bincode::deserialize::<HighWaterMark>(&b))
            .transpose()
            .map_err(|e| ConsensusError::Storage(format!("vote high-water mark: {e}")))?;
        let behind = mark.is_some_and(|m| (m.epoch, m.index) > (epoch, index));
        let (at, next) = if behind {
            (self.signed(index)?, self.signed(index + 1)?)
        } else {
            (None, None)
        };
        let record = check_high_water(mark, at, next, epoch, index, digest)?;
        if record == Record::Again {
            return Ok(());
        }
        let signed = Signed {
            epoch,
            digest: *digest,
            prev: *prev,
        };
        let mut ops = vec![tenzro_storage::WriteOp::Put {
            cf: tenzro_storage::CF_METADATA.to_string(),
            key: signed_vote_key(index),
            value: bincode::serialize(&signed).expect("signed vote encodes"),
        }];
        if record == Record::Mark {
            let mark = HighWaterMark {
                epoch,
                index,
                digest: *digest,
            };
            ops.push(tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_METADATA.to_string(),
                key: HIGH_WATER_KEY.to_vec(),
                value: bincode::serialize(&mark).expect("mark encodes"),
            });
            if let Some(old) = index.checked_sub(SIGNED_VOTE_WINDOW) {
                ops.push(tenzro_storage::WriteOp::Delete {
                    cf: tenzro_storage::CF_METADATA.to_string(),
                    key: signed_vote_key(old),
                });
            }
        }
        self.store
            .write_batch_sync(ops)
            .map_err(|e| ConsensusError::Storage(e.to_string()))
    }
}

/// Persists the high-water mark and then signs `checkpoint`.
pub fn sign_checkpoint(
    session: &dyn ValidatorSigner,
    certificate: &SessionCertificate,
    high_water: &dyn VoteHighWater,
    me: ValidatorIndex,
    checkpoint: &Checkpoint,
) -> Result<CheckpointVote> {
    if &certificate.session_key != session.public_key() || certificate.epoch != checkpoint.epoch {
        return Err(ConsensusError::VoteRefused(
            "the session certificate is not for this key and this checkpoint's epoch".into(),
        ));
    }
    let digest = checkpoint.digest();
    high_water.record(
        checkpoint.epoch,
        checkpoint.index,
        &digest,
        &checkpoint.prev,
    )?;
    let signature = session.sign(CHECKPOINT_VOTE_DOMAIN, &digest)?;
    Ok(CheckpointVote {
        checkpoint: checkpoint.clone(),
        signer: me,
        signature: VoteSignature {
            session: certificate.clone(),
            signature,
        },
    })
}

/// What adding one vote produced.
#[derive(Debug, PartialEq, Eq)]
pub enum VoteOutcome {
    /// Counted; no quorum yet.
    Counted,
    /// Already counted, or for a checkpoint already certified.
    Duplicate,
    /// The vote formed this certificate.
    Certified(Box<Certificate>),
    /// The signer signed a different checkpoint with the same index.
    Equivocation(Box<(CheckpointVote, CheckpointVote)>),
}

#[derive(Default)]
struct IndexVotes {
    by_signer: HashMap<ValidatorIndex, CheckpointVote>,
    by_digest: HashMap<Digest, SeatSet>,
    certified: bool,
}

/// Collects verified checkpoint votes into certificates.
#[derive(Default)]
pub struct VoteCollector {
    indices: BTreeMap<u64, IndexVotes>,
    floor: u64,
}

impl VoteCollector {
    /// An empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a vote whose signature the caller already verified.
    pub fn add(&mut self, committee: &Committee, vote: CheckpointVote) -> VoteOutcome {
        if vote.checkpoint.index < self.floor {
            return VoteOutcome::Duplicate;
        }
        let digest = vote.checkpoint.digest();
        let e = self.indices.entry(vote.checkpoint.index).or_default();
        if let Some(prev) = e.by_signer.get(&vote.signer) {
            if prev.checkpoint.digest() == digest {
                return VoteOutcome::Duplicate;
            }
            return VoteOutcome::Equivocation(Box::new((prev.clone(), vote)));
        }
        let signer = vote.signer;
        e.by_signer.insert(signer, vote);
        if e.certified {
            return VoteOutcome::Duplicate;
        }
        let seats = e.by_digest.entry(digest).or_default();
        seats.insert(signer, committee.seats(signer));
        if seats.weight() < committee.quorum() {
            return VoteOutcome::Counted;
        }
        let mut signers: Vec<ValidatorIndex> = seats.iter().collect();
        signers.sort_unstable();
        let sessions = signers
            .iter()
            .map(|s| e.by_signer[s].signature.session.digest())
            .collect();
        let signatures = signers
            .iter()
            .map(|s| e.by_signer[s].signature.signature.clone())
            .collect();
        let checkpoint = e.by_signer[&signer].checkpoint.clone();
        e.certified = true;
        VoteOutcome::Certified(Box::new(Certificate {
            checkpoint,
            signers,
            sessions,
            signatures,
        }))
    }

    /// How many indices hold votes.
    #[cfg(test)]
    pub(crate) fn held_indices(&self) -> usize {
        self.indices.len()
    }

    /// Drops everything for indices below `index`. Votes kept for already
    /// certified indices still catch a validator that signs a conflicting
    /// checkpoint afterwards, until they are pruned.
    pub fn prune_below(&mut self, index: u64) {
        if index > self.floor {
            self.floor = index;
            self.indices = self.indices.split_off(&index);
        }
    }
}

#[cfg(any(test, feature = "test-keys"))]
pub mod test_support {
    //! In-memory stand-ins for what a node persists, for tests and the
    //! network simulator.
    use super::*;

    /// A high-water mark in memory, with what was signed within
    /// [`SIGNED_VOTE_WINDOW`] of it.
    #[derive(Default)]
    pub struct MemoryHighWater(
        parking_lot::Mutex<(
            Option<HighWaterMark>,
            std::collections::BTreeMap<u64, Signed>,
        )>,
    );

    impl VoteHighWater for MemoryHighWater {
        fn record(&self, epoch: u64, index: u64, digest: &Digest, prev: &Digest) -> Result<()> {
            let mut g = self.0.lock();
            let (at, next) = (g.1.get(&index).copied(), g.1.get(&(index + 1)).copied());
            match check_high_water(g.0, at, next, epoch, index, digest)? {
                Record::Again => {}
                Record::Behind => {
                    g.1.insert(
                        index,
                        Signed {
                            epoch,
                            digest: *digest,
                            prev: *prev,
                        },
                    );
                }
                Record::Mark => {
                    g.0 = Some(HighWaterMark {
                        epoch,
                        index,
                        digest: *digest,
                    });
                    g.1.insert(
                        index,
                        Signed {
                            epoch,
                            digest: *digest,
                            prev: *prev,
                        },
                    );
                    if let Some(old) = index.checked_sub(SIGNED_VOTE_WINDOW) {
                        g.1 = g.1.split_off(&(old + 1));
                    }
                }
            }
            Ok(())
        }
    }

    /// A vote by the validator holding hardware key `hardware`: a fresh
    /// session key, certified by `hardware` for the checkpoint's epoch,
    /// signs it.
    #[cfg(test)]
    pub(crate) fn sign_as(
        hardware: &dyn ValidatorSigner,
        high_water: &dyn VoteHighWater,
        me: ValidatorIndex,
        cp: &Checkpoint,
    ) -> Result<CheckpointVote> {
        let session =
            crate::session::SessionKey::generate_with_scheme(hardware.public_key().scheme())?;
        let cert = crate::session::sign_certificate(
            hardware,
            cp.chain_id,
            cp.genesis_hash,
            cp.epoch,
            session.public_key().clone(),
        )?;
        sign_checkpoint(&session, &cert, high_water, me, cp)
    }

    #[cfg(test)]
    pub(crate) fn checkpoint(index: u64, state: u8) -> Checkpoint {
        Checkpoint {
            chain_id: 7,
            genesis_hash: [1; 32],
            epoch: 0,
            index,
            prev: [0; 32],
            first_height: 1,
            last_height: 10,
            blocks_root: [2; 32],
            state_height: 8,
            state_root: [state; 32],
            statement_root: [0; 32],
            next_committee_root: None,
            anchor_round: 9,
            timestamp_ms: 1_000,
            ordering_root: [0; 32],
        }
    }
}

#[cfg(test)]
mod tests {
    /// A validator signs again what it signed for a checkpoint, after a
    /// restart too, and signs a checkpoint it reaches after the next one
    /// when it is the one the next one follows; anything else for a
    /// checkpoint behind its latest signature, or beyond the window it
    /// keeps, is refused.
    #[test]
    fn a_validator_signs_only_what_is_consistent_with_what_it_signed() {
        use super::test_support::MemoryHighWater;
        let dir = tempfile::tempdir().unwrap();
        let store: std::sync::Arc<dyn tenzro_storage::KvStore> = std::sync::Arc::new(
            tenzro_storage::RocksDbStore::open_default(dir.path().join("db")).expect("store"),
        );
        let kv = super::KvVoteHighWater::new(store);
        let mem = MemoryHighWater::default();
        let hws: [&dyn super::VoteHighWater; 2] = [&kv, &mem];
        for hw in hws {
            let (d529, d530, d531, other) = ([9u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]);
            // 531 is reached first; it follows 530 with digest d530.
            hw.record(105, 531, &d531, &d530).unwrap();
            assert!(
                hw.record(105, 530, &other, &d529).is_err(),
                "not the one 531 follows"
            );
            hw.record(105, 530, &d530, &d529)
                .expect("the one 531 follows");
            hw.record(105, 530, &d530, &d529).expect("the same again");
            hw.record(105, 531, &d531, &d530).expect("the same again");
            assert!(hw.record(105, 530, &other, &d529).is_err());
            assert!(hw.record(105, 531, &other, &d530).is_err());
            // Nothing signed after 528: refused.
            assert!(hw.record(105, 528, &other, &d529).is_err());
            // Far past the window, nothing older is signed.
            hw.record(106, 531 + super::SIGNED_VOTE_WINDOW + 1, &d531, &d530)
                .unwrap();
            assert!(
                hw.record(105, 530, &d530, &d529).is_err(),
                "beyond the window it is refused"
            );
        }
    }

    use super::test_support::*;
    use super::*;
    use crate::committee::test_support::committee;

    /// Certifies `cp` with votes from `who`, admitting each vote's session
    /// certificate into `book`.
    fn certify(
        c: &Committee,
        signers: &[crate::validator_key::test_signer::SoftwareTestSigner],
        who: &[ValidatorIndex],
        cp: &Checkpoint,
        book: &mut SessionBook,
    ) -> Certificate {
        let mut col = VoteCollector::new();
        let mut out = None;
        for i in who {
            let hw = MemoryHighWater::default();
            let v = sign_as(&signers[*i as usize], &hw, *i, cp).unwrap();
            assert!(v.verify(&c.member(*i).unwrap().public_key));
            book.admit(c, v.signature.session.clone()).unwrap();
            if let VoteOutcome::Certified(cert) = col.add(c, v) {
                out = Some(*cert);
            }
        }
        out.expect("quorum reached")
    }

    fn book(epoch: u64) -> SessionBook {
        SessionBook::new(7, [1; 32], epoch)
    }

    fn ctx<'a>(c: &'a Committee, sessions: &'a SessionBook) -> CertificateContext<'a> {
        CertificateContext {
            chain_id: 7,
            genesis_hash: &[1; 32],
            committee: c,
            sessions,
        }
    }

    #[test]
    fn a_quorum_of_votes_forms_a_certificate_that_verifies() {
        let (c, s) = committee(4);
        let cp = checkpoint(1, 3);
        let mut b = book(0);
        let cert = certify(&c, &s, &[0, 1, 2], &cp, &mut b);
        assert!(cert.verify(&ctx(&c, &b)).is_ok());
        // The certificate names each session certificate once; the bundle
        // carries them for anyone who verifies it later.
        assert_eq!(b.bundle(&cert.sessions).len(), 3);
        let mut rebuilt = book(0);
        for sc in b.bundle(&cert.sessions) {
            rebuilt.admit(&c, sc).unwrap();
        }
        assert!(
            cert.verify(&ctx(&c, &rebuilt)).is_ok(),
            "the bundle alone is enough to verify"
        );
        assert!(
            cert.verify(&ctx(&c, &book(0))).is_err(),
            "without the bundle nothing verifies"
        );
    }

    #[test]
    fn forged_certificates_are_refused() {
        let (c, s) = committee(4);
        let cp = checkpoint(1, 3);
        let mut b = book(0);
        let cert = certify(&c, &s, &[0, 1, 2], &cp, &mut b);
        let ctx = ctx(&c, &b);
        let mut m = cert.clone();
        m.checkpoint.state_root[0] ^= 1;
        assert!(m.verify(&ctx).is_err(), "altered body");
        let mut m = cert.clone();
        m.signers.pop();
        m.sessions.pop();
        m.signatures.pop();
        assert!(m.verify(&ctx).is_err(), "below quorum");
        let mut m = cert.clone();
        m.signers[2] = 3;
        assert!(m.verify(&ctx).is_err(), "signer substituted");
        let mut m = cert.clone();
        m.signers.push(2);
        m.sessions.push(m.sessions[2]);
        m.signatures.push(m.signatures[2].clone());
        assert!(
            m.verify(&ctx).is_err(),
            "signer repeated to inflate the count"
        );
        let mut m = cert.clone();
        m.signatures[1].p256 = vec![];
        assert!(m.verify(&ctx).is_err(), "P-256 leg stripped");
        let mut m = cert.clone();
        m.signatures.swap(0, 1);
        assert!(
            m.verify(&ctx).is_err(),
            "signatures swapped between signers"
        );
        let mut m = cert.clone();
        m.sessions.swap(0, 1);
        assert!(
            m.verify(&ctx).is_err(),
            "session certificates swapped between signers"
        );
        let mut m = cert.clone();
        m.sessions.pop();
        assert!(
            m.verify(&ctx).is_err(),
            "a signer without a session certificate"
        );
        let other = CertificateContext { chain_id: 8, ..ctx };
        assert!(cert.verify(&other).is_err(), "another chain");
    }

    #[test]
    fn a_validator_never_signs_two_checkpoints_for_one_index() {
        let (_, s) = committee(4);
        let hw = MemoryHighWater::default();
        assert!(sign_as(&s[0], &hw, 0, &checkpoint(5, 1)).is_ok());
        assert!(
            sign_as(&s[0], &hw, 0, &checkpoint(5, 1)).is_ok(),
            "same digest again"
        );
        assert!(sign_as(&s[0], &hw, 0, &checkpoint(5, 2)).is_err());
        assert!(
            sign_as(&s[0], &hw, 0, &checkpoint(4, 2)).is_err(),
            "regression"
        );
        assert!(sign_as(&s[0], &hw, 0, &checkpoint(6, 2)).is_ok());
    }

    #[test]
    fn two_certificates_for_one_index_convict_exactly_the_double_signers() {
        let (c, s) = committee(7);
        let a = checkpoint(3, 1);
        let b = checkpoint(3, 2);
        let mut sessions = book(0);
        let ca = certify(&c, &s, &[0, 1, 2, 3, 4], &a, &mut sessions);
        let cb = certify(&c, &s, &[2, 3, 4, 5, 6], &b, &mut sessions);
        let ev =
            CheckpointEquivocation::from_conflicting_certificates(&ca, &cb, &ctx(&c, &sessions));
        let who: Vec<_> = ev.iter().map(|(i, _)| *i).collect();
        assert_eq!(who, vec![2, 3, 4]);
        assert!(who.len() as u64 >= c.validity());
        // The evidence carries the session certificates, so it stands on
        // its own without the bundle.
        assert!(ev.iter().all(|(_, e)| e.is_valid(7)));
        assert!(!ev[0].1.is_valid(8));
    }

    #[test]
    fn a_second_vote_for_another_digest_is_equivocation() {
        let (c, s) = committee(4);
        let mut col = VoteCollector::new();
        let v1 = sign_as(&s[1], &MemoryHighWater::default(), 1, &checkpoint(2, 1)).unwrap();
        let v2 = sign_as(&s[1], &MemoryHighWater::default(), 1, &checkpoint(2, 9)).unwrap();
        assert_eq!(col.add(&c, v1), VoteOutcome::Counted);
        let VoteOutcome::Equivocation(pair) = col.add(&c, v2) else {
            panic!("not caught")
        };
        let (a, b) = *pair;
        let ev = CheckpointEquivocation {
            public_key: c.member(1).unwrap().public_key.clone(),
            first: a.checkpoint,
            first_signature: a.signature,
            second: b.checkpoint,
            second_signature: b.signature,
        };
        assert!(
            ev.is_valid(7),
            "two conflicting votes are complete evidence"
        );
        // The evidence names the hardware key; each session certificate
        // must be that key's, or it proves nothing about the validator.
        let framed = sign_as(&s[2], &MemoryHighWater::default(), 1, &checkpoint(2, 9)).unwrap();
        let mut ev2 = ev.clone();
        ev2.second_signature = framed.signature;
        assert!(
            !ev2.is_valid(7),
            "a vote by another validator's session key is not evidence"
        );
    }

    fn vote_with(
        cp: &Checkpoint,
        signer: ValidatorIndex,
        session: SessionCertificate,
        by: &dyn ValidatorSigner,
    ) -> CheckpointVote {
        let signature = by.sign(CHECKPOINT_VOTE_DOMAIN, &cp.digest()).unwrap();
        CheckpointVote {
            checkpoint: cp.clone(),
            signer,
            signature: VoteSignature { session, signature },
        }
    }

    #[test]
    fn a_vote_whose_session_key_is_uncertified_is_refused() {
        let (c, s) = committee(4);
        let key = &c.member(1).unwrap().public_key;
        let cp = checkpoint(2, 1);
        let session = crate::session::SessionKey::generate().unwrap();
        let other = crate::session::SessionKey::generate().unwrap();
        // The certificate names another session key.
        let cert =
            crate::session::sign_certificate(&s[1], 7, [1; 32], 0, other.public_key().clone())
                .unwrap();
        assert!(
            sign_checkpoint(&session, &cert, &MemoryHighWater::default(), 1, &cp).is_err(),
            "signing refuses"
        );
        assert!(!vote_with(&cp, 1, cert, &session).verify(key));
        // The session key certifies itself, claiming the validator's name.
        let mut own =
            crate::session::sign_certificate(&session, 7, [1; 32], 0, session.public_key().clone())
                .unwrap();
        own.validator = key.fingerprint();
        assert!(!vote_with(&cp, 1, own.clone(), &session).verify(key));
        assert!(book(0).admit(&c, own).is_err(), "and no book admits it");
        // The hardware key signing the checkpoint directly is not a vote.
        let hw_cert =
            crate::session::sign_certificate(&s[1], 7, [1; 32], 0, s[1].public_key().clone())
                .unwrap();
        assert!(
            vote_with(&cp, 1, hw_cert.clone(), &s[1]).verify(key),
            "control: a certified key votes"
        );
        assert!(!vote_with(&cp, 1, hw_cert, &session).verify(key));
    }

    #[test]
    fn a_session_key_certified_for_another_validator_is_refused() {
        let (c, s) = committee(4);
        let cp = checkpoint(2, 1);
        let v = sign_as(&s[2], &MemoryHighWater::default(), 1, &cp).unwrap();
        assert!(!v.verify(&c.member(1).unwrap().public_key));
        assert!(
            v.verify(&c.member(2).unwrap().public_key),
            "control: it is validator 2's vote"
        );
        let mut b = book(0);
        let mut cert = certify(&c, &s, &[0, 1, 2], &cp, &mut b);
        // Validator 3's session certificate, genuinely in the book, under
        // signer 1's slot.
        let v3 = sign_as(&s[3], &MemoryHighWater::default(), 1, &cp).unwrap();
        cert.sessions[1] = b.admit(&c, v3.signature.session).unwrap();
        cert.signatures[1] = v3.signature.signature;
        assert!(cert.verify(&ctx(&c, &b)).is_err());
    }

    #[test]
    fn a_session_key_certified_for_an_expired_epoch_is_refused() {
        let (c, s) = committee(4);
        let key = &c.member(1).unwrap().public_key;
        let session = crate::session::SessionKey::generate().unwrap();
        let epoch0 =
            crate::session::sign_certificate(&s[1], 7, [1; 32], 0, session.public_key().clone())
                .unwrap();
        let cp1 = Checkpoint {
            epoch: 1,
            ..checkpoint(2, 1)
        };
        assert!(
            sign_checkpoint(&session, &epoch0, &MemoryHighWater::default(), 1, &cp1).is_err(),
            "signing refuses"
        );
        assert!(!vote_with(&cp1, 1, epoch0.clone(), &session).verify(key));
        assert!(
            vote_with(&checkpoint(2, 1), 1, epoch0.clone(), &session).verify(key),
            "control: valid in its own epoch"
        );
        // A certificate of epoch 1 naming a session certificate of epoch 0.
        let mut committee1 = c.clone();
        committee1.epoch = 1;
        let mut b1 = book(1);
        let mut cert = certify(&committee1, &s, &[0, 1, 2], &cp1, &mut b1);
        assert!(
            b1.admit(&committee1, epoch0.clone()).is_err(),
            "epoch 1's book refuses it"
        );
        cert.sessions[1] = epoch0.digest();
        cert.signatures[1] = session.sign(CHECKPOINT_VOTE_DOMAIN, &cp1.digest()).unwrap();
        assert!(cert.verify(&ctx(&committee1, &b1)).is_err());
        // Nor does epoch 0's book verify an epoch-1 certificate.
        let mut b0 = book(0);
        b0.admit(&c, epoch0).unwrap();
        assert!(cert.verify(&ctx(&committee1, &b0)).is_err());
    }

    /// Mutated certificates and votes, `TDC_FORGERY_MUTATIONS` of them
    /// (default one million) across all cores. A forgery is a mutation that
    /// verifies while attesting a different checkpoint or signer set, or
    /// that verifies at all after its session certificates were altered; a
    /// mutation that verifies with only a signature encoding changed (the
    /// P-256 `s` negated) is counted separately. Session certificates reach
    /// a verifier only through its book, so every altered or foreign one is
    /// offered to a copy of the book first, the way a bundle from the
    /// network would be. Prints one `GATE {json}` line. Run with
    /// `--release --ignored --nocapture`.
    #[test]
    #[ignore]
    fn gate_certificate_forgery() {
        use rand::{Rng, SeedableRng};
        let total: u64 = std::env::var("TDC_FORGERY_MUTATIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000);
        let (c, s) = committee(7);
        let cp = checkpoint(4, 3);
        let mut sessions = book(0);
        let cert = certify(&c, &s, &[0, 1, 2, 3, 4], &cp, &mut sessions);
        let votes: Vec<CheckpointVote> = (0..5u16)
            .map(|i| sign_as(&s[i as usize], &MemoryHighWater::default(), i, &cp).unwrap())
            .collect();
        let mut chain8 = SessionBook::new(8, [1; 32], 0);
        let other_chain = certify(
            &c,
            &s,
            &[0, 1, 2, 3, 4],
            &Checkpoint {
                chain_id: 8,
                ..cp.clone()
            },
            &mut chain8,
        );
        let mut committee1 = c.clone();
        committee1.epoch = 1;
        let mut epoch1 = book(1);
        let other_epoch = certify(
            &committee1,
            &s,
            &[0, 1, 2, 3, 4],
            &Checkpoint {
                epoch: 1,
                ..cp.clone()
            },
            &mut epoch1,
        );
        let rogue = crate::session::SessionKey::generate().unwrap();
        let cert_bytes = bincode::serialize(&cert).unwrap();
        let ctx = ctx(&c, &sessions);
        let kinds = [
            "bit_flip",
            "byte_burst",
            "bitmap_inflation",
            "signer_substitution",
            "cross_chain_replay",
            "cross_epoch_replay",
            "index_replay",
            "field_rewrite",
            "stripped_p256",
            "stripped_ml_dsa",
            "signature_swap",
            "session_swap",
            "p256_s_negated",
            "session_rewrite",
            "rogue_session_key",
            "cross_epoch_session",
            "cross_chain_session",
            "vote_bit_flip",
            "vote_signer_rewrite",
        ];
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) as u64;
        let per = total.div_ceil(threads);
        let results: Vec<(Vec<u64>, Vec<u64>, u64)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..threads)
                .map(|t| {
                    let (cert, cert_bytes, votes, c, ctx, sessions) =
                        (&cert, &cert_bytes, &votes, &c, &ctx, &sessions);
                    let (other_chain, other_epoch, rogue, chain8, epoch1) =
                        (&other_chain, &other_epoch, &rogue, &chain8, &epoch1);
                    scope.spawn(move || {
                        let mut rng = rand::rngs::StdRng::seed_from_u64(0x7dc0 + t);
                        let mut tried = vec![0u64; kinds.len()];
                        let mut forged = vec![0u64; kinds.len()];
                        let mut variants = 0u64;
                        let attests_other = |m: &Certificate| {
                            m.checkpoint != cert.checkpoint || m.signers != cert.signers
                        };
                        for _ in 0..per {
                            let k = rng.gen_range(0..kinds.len());
                            tried[k] += 1;
                            let mut m = cert.clone();
                            // A session certificate the attacker offers the
                            // verifier's book alongside the certificate.
                            let mut offered: Option<SessionCertificate> = None;
                            match kinds[k] {
                                "bit_flip" => {
                                    let mut b = cert_bytes.clone();
                                    let bit = rng.gen_range(0..b.len() * 8);
                                    b[bit / 8] ^= 1 << (bit % 8);
                                    match bincode::deserialize::<Certificate>(&b) {
                                        Ok(d) => m = d,
                                        Err(_) => continue,
                                    }
                                }
                                "byte_burst" => {
                                    let mut b = cert_bytes.clone();
                                    let at = rng.gen_range(0..b.len());
                                    let len = rng.gen_range(1..=16).min(b.len() - at);
                                    rng.fill(&mut b[at..at + len]);
                                    match bincode::deserialize::<Certificate>(&b) {
                                        Ok(d) => m = d,
                                        Err(_) => continue,
                                    }
                                }
                                "bitmap_inflation" => {
                                    let extra = rng.gen_range(0..7u16);
                                    let from = rng.gen_range(0..m.signatures.len());
                                    let (session, sig) =
                                        (m.sessions[from], m.signatures[from].clone());
                                    let at = m.signers.partition_point(|x| *x < extra);
                                    m.signers.insert(at, extra);
                                    m.sessions.insert(at, session);
                                    m.signatures.insert(at, sig);
                                    if rng.gen_bool(0.5) {
                                        let drop = rng.gen_range(0..m.signers.len());
                                        m.signers.remove(drop);
                                        m.sessions.remove(drop);
                                        m.signatures.remove(drop);
                                    }
                                }
                                "signer_substitution" => {
                                    let at = rng.gen_range(0..m.signers.len());
                                    m.signers[at] = rng.gen_range(0..9u16);
                                }
                                "cross_chain_replay" => {
                                    m = other_chain.clone();
                                    offered = Some(
                                        chain8.bundle(&m.sessions)
                                            [rng.gen_range(0..m.sessions.len())]
                                        .clone(),
                                    );
                                }
                                "cross_epoch_replay" => {
                                    m = other_epoch.clone();
                                    offered = Some(
                                        epoch1.bundle(&m.sessions)
                                            [rng.gen_range(0..m.sessions.len())]
                                        .clone(),
                                    );
                                }
                                "index_replay" => m.checkpoint.index = rng.gen_range(0..16u64),
                                "field_rewrite" => match rng.gen_range(0..6) {
                                    0 => m.checkpoint.prev[rng.gen_range(0..32)] ^= 1,
                                    1 => m.checkpoint.last_height += rng.gen_range(1..4),
                                    2 => m.checkpoint.blocks_root[rng.gen_range(0..32)] ^= 0x80,
                                    3 => m.checkpoint.next_committee_root = Some([9; 32]),
                                    4 => m.checkpoint.anchor_round ^= 1,
                                    _ => m.checkpoint.timestamp_ms += 1,
                                },
                                "stripped_p256" => {
                                    let at = rng.gen_range(0..m.signatures.len());
                                    let keep = rng.gen_range(0..m.signatures[at].p256.len());
                                    m.signatures[at].p256.truncate(keep);
                                }
                                "stripped_ml_dsa" => {
                                    let at = rng.gen_range(0..m.signatures.len());
                                    let keep = rng.gen_range(0..m.signatures[at].ml_dsa.len());
                                    m.signatures[at].ml_dsa.truncate(keep);
                                }
                                "signature_swap" => {
                                    let a = rng.gen_range(0..m.signatures.len());
                                    let b = (a + rng.gen_range(1..m.signatures.len()))
                                        % m.signatures.len();
                                    m.signatures.swap(a, b);
                                }
                                "session_swap" => {
                                    let a = rng.gen_range(0..m.sessions.len());
                                    let b =
                                        (a + rng.gen_range(1..m.sessions.len())) % m.sessions.len();
                                    m.sessions.swap(a, b);
                                }
                                "p256_s_negated" => {
                                    let at = rng.gen_range(0..m.signatures.len());
                                    let sig =
                                        p256::ecdsa::Signature::from_slice(&m.signatures[at].p256)
                                            .unwrap();
                                    let (r, s_scalar) = sig.split_scalars();
                                    let high_s = -*s_scalar;
                                    let neg = p256::ecdsa::Signature::from_scalars(
                                        r.to_bytes(),
                                        high_s.to_bytes(),
                                    )
                                    .unwrap();
                                    m.signatures[at].p256 = neg.to_bytes().to_vec();
                                }
                                "session_rewrite" => {
                                    let at = rng.gen_range(0..m.sessions.len());
                                    let mut sc = sessions
                                        .get(&m.sessions[at])
                                        .expect("in the book")
                                        .1
                                        .clone();
                                    match rng.gen_range(0..5) {
                                        0 => sc.epoch = rng.gen_range(1..4u64),
                                        1 => sc.chain_id ^= 1,
                                        2 => sc.validator[rng.gen_range(0..32)] ^= 1,
                                        3 => {
                                            let l = sc.signature.ml_dsa.len();
                                            sc.signature.ml_dsa[rng.gen_range(0..l)] ^= 1
                                        }
                                        _ => sc.session_key = rogue.public_key().clone(),
                                    }
                                    m.sessions[at] = sc.digest();
                                    if sc.session_key == *rogue.public_key() {
                                        m.signatures[at] = rogue
                                            .sign(CHECKPOINT_VOTE_DOMAIN, &m.checkpoint.digest())
                                            .unwrap();
                                    }
                                    offered = Some(sc);
                                }
                                "rogue_session_key" => {
                                    // A key the signer never certified signs the
                                    // checkpoint, under the signer's genuine
                                    // session certificate or one it forged.
                                    let at = rng.gen_range(0..m.signatures.len());
                                    m.signatures[at] = rogue
                                        .sign(CHECKPOINT_VOTE_DOMAIN, &m.checkpoint.digest())
                                        .unwrap();
                                    if rng.gen_bool(0.5) {
                                        let mut sc = crate::session::sign_certificate(
                                            rogue,
                                            7,
                                            [1; 32],
                                            0,
                                            rogue.public_key().clone(),
                                        )
                                        .unwrap();
                                        sc.validator = c
                                            .member(m.signers[at])
                                            .unwrap()
                                            .public_key
                                            .fingerprint();
                                        m.sessions[at] = sc.digest();
                                        offered = Some(sc);
                                    }
                                }
                                "cross_epoch_session" => {
                                    let at = rng.gen_range(0..m.sessions.len());
                                    let sc = epoch1
                                        .get(&other_epoch.sessions[at])
                                        .expect("in epoch 1's book")
                                        .1
                                        .clone();
                                    m.sessions[at] = sc.digest();
                                    m.signatures[at] = other_epoch.signatures[at].clone();
                                    offered = Some(sc);
                                }
                                "cross_chain_session" => {
                                    let at = rng.gen_range(0..m.sessions.len());
                                    let sc = chain8
                                        .get(&other_chain.sessions[at])
                                        .expect("in chain 8's book")
                                        .1
                                        .clone();
                                    m.sessions[at] = sc.digest();
                                    m.signatures[at] = other_chain.signatures[at].clone();
                                    offered = Some(sc);
                                }
                                "vote_bit_flip" | "vote_signer_rewrite" => {
                                    let v = &votes[rng.gen_range(0..votes.len())];
                                    let mut mv = v.clone();
                                    if kinds[k] == "vote_bit_flip" {
                                        let mut b = bincode::serialize(v).unwrap();
                                        let bit = rng.gen_range(0..b.len() * 8);
                                        b[bit / 8] ^= 1 << (bit % 8);
                                        match bincode::deserialize::<CheckpointVote>(&b) {
                                            Ok(d) => mv = d,
                                            Err(_) => continue,
                                        }
                                    } else {
                                        mv.signer = rng.gen_range(0..7u16);
                                    }
                                    let Some(member) = c.member(mv.signer) else {
                                        continue;
                                    };
                                    let changed =
                                        mv.checkpoint != v.checkpoint || mv.signer != v.signer;
                                    if mv.verify(&member.public_key) {
                                        if changed {
                                            forged[k] += 1;
                                        } else if mv != *v {
                                            variants += 1;
                                        }
                                    }
                                    continue;
                                }
                                _ => unreachable!(),
                            }
                            let accepted = match offered {
                                None => m.verify(ctx).is_ok(),
                                Some(sc) => {
                                    let mut book = sessions.clone();
                                    // An offered certificate that the book admits is
                                    // one the signer's hardware key really signed.
                                    let _ = book.admit(c, sc);
                                    m.verify(&CertificateContext {
                                        sessions: &book,
                                        ..*ctx
                                    })
                                    .is_ok()
                                }
                            };
                            if accepted {
                                if attests_other(&m) || m.sessions != cert.sessions {
                                    forged[k] += 1;
                                } else if m != *cert {
                                    variants += 1;
                                }
                            }
                        }
                        (tried, forged, variants)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let mut tried = vec![0u64; kinds.len()];
        let mut forged = vec![0u64; kinds.len()];
        let mut variants = 0;
        for (t, f, v) in results {
            for i in 0..kinds.len() {
                tried[i] += t[i];
                forged[i] += f[i];
            }
            variants += v;
        }
        let per_kind: Vec<String> = kinds
            .iter()
            .enumerate()
            .map(|(i, k)| format!("\"{k}\":[{},{}]", tried[i], forged[i]))
            .collect();
        let accepted: u64 = forged.iter().sum();
        println!(
            "GATE {{\"gate\":\"certificate_forgery\",\"mutations\":{},\"forgeries_accepted\":{accepted},\
             \"encoding_variants_accepted\":{variants},\"per_kind_tried_forged\":{{{}}}}}",
            tried.iter().sum::<u64>(),
            per_kind.join(",")
        );
        assert_eq!(accepted, 0);
    }

    #[test]
    fn merkle_roots_bind_order_and_content() {
        let a = merkle_root(&[[1; 32], [2; 32], [3; 32]]);
        assert_ne!(a, merkle_root(&[[2; 32], [1; 32], [3; 32]]));
        assert_ne!(a, merkle_root(&[[1; 32], [2; 32]]));
        assert_ne!(merkle_root(&[]), merkle_root(&[[0; 32]]));
    }
}
