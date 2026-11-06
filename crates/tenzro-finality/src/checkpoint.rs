//! Checkpoints: what a quorum of the committee signs.

use serde::{Deserialize, Serialize};

use crate::committee::{Committee, SeatSet, ValidatorIndex};
use crate::error::{FinalityError, Result};
use crate::key::{CompositeSignature, ValidatorPublicKey};
use crate::session::{SessionBook, SessionCertificate};
use crate::{Digest, Round};

/// Domain separator of a checkpoint vote signature.
pub const CHECKPOINT_VOTE_DOMAIN: &[u8] = b"tenzro/consensus/checkpoint";

/// Number of blocks a checkpoint's state root lags its last block.
pub const STATE_ROOT_LAG: u64 = 2;

/// The height whose post-state a checkpoint ending at `last_height` commits.
pub fn state_root_height(last_height: u64) -> u64 {
    last_height.saturating_sub(STATE_ROOT_LAG)
}

/// A checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis block hash.
    pub genesis_hash: Digest,
    /// Epoch.
    pub epoch: u64,
    /// Checkpoint index, counted from genesis across epochs.
    pub index: u64,
    /// Digest of the previous checkpoint (zero for the first).
    pub prev: Digest,
    /// First block height covered.
    pub first_height: u64,
    /// Last block height covered.
    pub last_height: u64,
    /// Merkle root of the covered block hashes, in height order.
    pub blocks_root: Digest,
    /// The height whose post-state `state_root` is:
    /// [`state_root_height`]`(last_height)` for a checkpoint covering new
    /// blocks, whose execution may still be running when it is decided, and
    /// `last_height` itself for one covering none, so the state after the
    /// last block before an idle spell is certified without a later block.
    pub state_height: u64,
    /// Post-state root at `state_height`.
    pub state_root: Digest,
    /// Merkle root of the statements validators attest in this range.
    pub statement_root: Digest,
    /// Root of the next epoch's committee, on the checkpoint that ends an
    /// epoch.
    pub next_committee_root: Option<Digest>,
    /// Round of the anchor that closed the checkpoint.
    pub anchor_round: Round,
    /// Block timestamp of the last covered block, milliseconds.
    pub timestamp_ms: u64,
    /// Digest of the ordering state validators hold right after deciding
    /// this checkpoint: what a validator that fell behind within the epoch
    /// takes from a peer to order on from here.
    pub ordering_root: Digest,
}

/// The height whose post-state a checkpoint over `first_height..=last_height`
/// commits: the lagged height when it covers blocks, and `last_height` when
/// it covers none (`first_height` one past `last_height`).
pub fn checkpoint_state_height(first_height: u64, last_height: u64) -> u64 {
    if first_height > last_height {
        last_height
    } else {
        state_root_height(last_height)
    }
}

impl Checkpoint {
    /// Whether the range is a run of blocks or empty (`first_height` one
    /// past `last_height`), and `state_height` is the one the range fixes.
    pub fn well_formed(&self) -> bool {
        self.first_height <= self.last_height.saturating_add(1)
            && self.state_height == checkpoint_state_height(self.first_height, self.last_height)
    }

    /// The digest validators sign, with the scheme
    /// [`tenzro_types::hash_scheme::CHECKPOINT_DIGEST_SCHEMES`] gives the
    /// checkpoint's epoch.
    pub fn digest(&self) -> Digest {
        self.digest_under(tenzro_types::hash_scheme::CHECKPOINT_DIGEST_SCHEMES)
    }

    /// [`Self::digest`] under the epoch to scheme table `schemes`.
    pub fn digest_under(&self, schemes: &[(u64, tenzro_types::hash_scheme::HashScheme)]) -> Digest {
        let scheme = tenzro_types::hash_scheme::scheme_from(self.epoch, schemes.iter().copied());
        let mut bytes = b"tenzro/consensus/checkpoint/body".to_vec();
        bytes.extend_from_slice(&bincode::serialize(self).expect("checkpoint encodes"));
        scheme.digest(&bytes)
    }
}

/// What a certificate is checked against.
#[derive(Debug, Clone, Copy)]
pub struct CertificateContext<'a> {
    /// Expected chain id.
    pub chain_id: u64,
    /// Expected genesis hash.
    pub genesis_hash: &'a Digest,
    /// The committee of the checkpoint's epoch.
    pub committee: &'a Committee,
    /// The epoch's session certificates, each already checked against its
    /// validator's hardware key.
    pub sessions: &'a SessionBook,
}

/// A signature over a checkpoint by a validator's session key, and the
/// certificate by which the validator's hardware key vouches for that
/// session key in the checkpoint's epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoteSignature {
    /// The hardware key's certificate of the session key.
    pub session: SessionCertificate,
    /// Composite signature by the session key over the checkpoint digest.
    pub signature: CompositeSignature,
}

impl VoteSignature {
    /// Whether this is a signature on `checkpoint` by the validator holding
    /// hardware key `key`: the certificate is `key`'s, for the checkpoint's
    /// chain, genesis and epoch, and the session key it certifies signed the
    /// checkpoint digest.
    pub fn verify(&self, key: &ValidatorPublicKey, checkpoint: &Checkpoint) -> bool {
        self.session.certifies(
            key,
            checkpoint.chain_id,
            &checkpoint.genesis_hash,
            checkpoint.epoch,
        ) && self.session.session_key.verify(
            CHECKPOINT_VOTE_DOMAIN,
            &checkpoint.digest(),
            &self.signature,
        )
    }
}

/// A checkpoint signed by a quorum of seats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Certificate {
    /// The checkpoint.
    pub checkpoint: Checkpoint,
    /// Signers, strictly ascending.
    pub signers: Vec<ValidatorIndex>,
    /// Per signer, in the same order, the digest of the session certificate
    /// by which its hardware key vouches for the key that signed. The
    /// session certificates themselves travel once per epoch, in the
    /// epoch's [`SessionBook`] bundle.
    pub sessions: Vec<Digest>,
    /// Per signer, in the same order, the session key's signature over the
    /// checkpoint digest.
    pub signatures: Vec<CompositeSignature>,
}

impl Certificate {
    /// Checks the certificate: chain, genesis and epoch match, the signer
    /// list is strictly ascending committee indices carrying a quorum of
    /// seats, each signer's session certificate is in the epoch's book and
    /// certifies that signer, and every session signature verifies over the
    /// digest recomputed from the checkpoint body.
    pub fn verify(&self, ctx: &CertificateContext<'_>) -> Result<()> {
        let bad = |why: &str| Err(FinalityError::InvalidCertificate(why.to_string()));
        let cp = &self.checkpoint;
        if cp.chain_id != ctx.chain_id || &cp.genesis_hash != ctx.genesis_hash {
            return bad("certificate is for another chain");
        }
        if cp.epoch != ctx.committee.epoch || cp.epoch != ctx.sessions.epoch() {
            return bad("certificate is for another epoch's committee");
        }
        if !cp.well_formed() {
            return bad("checkpoint's height range or state height is malformed");
        }
        if self.signers.len() != self.signatures.len() || self.signers.len() != self.sessions.len()
        {
            return bad("signer, session and signature counts differ");
        }
        let mut seats = SeatSet::new();
        let mut prev: Option<ValidatorIndex> = None;
        for s in &self.signers {
            if prev.is_some_and(|p| p >= *s) {
                return bad("signers are not strictly ascending");
            }
            prev = Some(*s);
            if ctx.committee.member(*s).is_none() {
                return bad("signer is not a committee member");
            }
            seats.insert(*s, ctx.committee.seats(*s));
        }
        if seats.weight() < ctx.committee.quorum() {
            return bad("signers carry less than a quorum of seats");
        }
        let digest = cp.digest();
        for ((s, session), sig) in self
            .signers
            .iter()
            .zip(&self.sessions)
            .zip(&self.signatures)
        {
            let Some((holder, cert)) = ctx.sessions.get(session) else {
                return bad("a signer's session certificate is not in the epoch's bundle");
            };
            if holder != *s {
                return bad("a session certificate is another validator's");
            }
            if !cert
                .session_key
                .verify(CHECKPOINT_VOTE_DOMAIN, &digest, sig)
            {
                return bad(
                    "a signature does not verify under a session key its signer certified for this epoch",
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod digest_scheme_tests {
    use super::*;
    use tenzro_types::hash_scheme::HashScheme;

    fn cp(epoch: u64, index: u64, prev: Digest) -> Checkpoint {
        Checkpoint {
            chain_id: 1,
            genesis_hash: [3; 32],
            epoch,
            index,
            prev,
            first_height: index * 4 + 1,
            last_height: index * 4 + 4,
            blocks_root: [4; 32],
            state_height: checkpoint_state_height(index * 4 + 1, index * 4 + 4),
            state_root: [5; 32],
            statement_root: [6; 32],
            next_committee_root: None,
            anchor_round: index,
            timestamp_ms: 0,
            ordering_root: [7; 32],
        }
    }

    fn blake3_as_before(c: &Checkpoint) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/checkpoint/body");
        h.update(&bincode::serialize(c).unwrap());
        h.finalize().into()
    }

    /// Every checkpoint keeps its digest; from the epoch an upgrade names the
    /// digest is SHA3-256, and the `prev` links across the switch still
    /// chain.
    #[test]
    fn the_checkpoint_digest_changes_at_the_named_epoch_and_old_ones_keep_theirs() {
        let schemes = [(0u64, HashScheme::Blake3), (5, HashScheme::Sha3_256)];
        let mut prev = [0u8; 32];
        let mut chain = Vec::new();
        for (i, epoch) in [(0u64, 3u64), (1, 4), (2, 5), (3, 6)] {
            let c = cp(epoch, i, prev);
            prev = c.digest_under(&schemes);
            chain.push(c);
        }
        for c in &chain {
            assert_eq!(c.digest(), blake3_as_before(c));
        }
        assert_eq!(chain[1].digest_under(&schemes), blake3_as_before(&chain[1]));
        assert_ne!(chain[2].digest_under(&schemes), blake3_as_before(&chain[2]));
        for w in chain.windows(2) {
            assert_eq!(w[1].prev, w[0].digest_under(&schemes));
        }
    }
}
