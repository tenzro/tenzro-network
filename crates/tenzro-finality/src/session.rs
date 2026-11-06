//! Session certificates: a validator's hardware key certifying the session
//! key that signs its checkpoint votes for one epoch, and the book of an
//! epoch's certificates checked against the committee.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::Digest;
use crate::committee::{Committee, ValidatorIndex};
use crate::error::{FinalityError, Result};
use crate::key::{CompositeSignature, ValidatorPublicKey};

/// Domain separator of a session certificate.
pub const SESSION_CERTIFICATE_DOMAIN: &[u8] = b"tenzro/consensus/session-certificate";

/// A validator's hardware key certifying a session key for the checkpoint
/// votes of one epoch on one chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCertificate {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis hash.
    pub genesis_hash: [u8; 32],
    /// The one epoch whose checkpoints the session key may vote for.
    pub epoch: u64,
    /// Fingerprint of the certifying validator's hardware key.
    pub validator: [u8; 32],
    /// The certified session key.
    pub session_key: ValidatorPublicKey,
    /// Composite signature by the validator's hardware key.
    pub signature: CompositeSignature,
}

/// The message a session certificate's hardware signature covers.
pub fn certificate_message(c: &SessionCertificate) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + 32 + 8 + 32 + 32);
    m.extend_from_slice(&c.chain_id.to_be_bytes());
    m.extend_from_slice(&c.genesis_hash);
    m.extend_from_slice(&c.epoch.to_be_bytes());
    m.extend_from_slice(&c.validator);
    m.extend_from_slice(&c.session_key.fingerprint());
    m
}

impl SessionCertificate {
    /// Whether the validator holding `hardware_key` certified this session
    /// key for exactly (`chain_id`, `genesis_hash`, `epoch`).
    pub fn certifies(
        &self,
        hardware_key: &ValidatorPublicKey,
        chain_id: u64,
        genesis_hash: &[u8; 32],
        epoch: u64,
    ) -> bool {
        self.chain_id == chain_id
            && &self.genesis_hash == genesis_hash
            && self.epoch == epoch
            && self.validator == hardware_key.fingerprint()
            && hardware_key.verify(
                SESSION_CERTIFICATE_DOMAIN,
                &certificate_message(self),
                &self.signature,
            )
    }

    /// What a checkpoint certificate names this session certificate by.
    pub fn digest(&self) -> Digest {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/session-certificate/id");
        h.update(&bincode::serialize(self).expect("session certificate encodes"));
        h.finalize().into()
    }
}

/// Most session certificates one validator may have in one epoch: one per
/// boot, so a validator that restarts keeps voting, while one that signs
/// certificates without end cannot grow anyone's book.
pub const MAX_SESSIONS_PER_VALIDATOR: usize = 16;

/// The session certificates of one epoch this node has checked, each
/// against the hardware key of the committee member it names.
///
/// A checkpoint certificate names each signer's session certificate by
/// digest instead of carrying it, so the certificates of an epoch travel
/// once, as the epoch's bundle, rather than in every checkpoint certificate.
#[derive(Debug, Clone)]
pub struct SessionBook {
    chain_id: u64,
    genesis_hash: Digest,
    epoch: u64,
    by_digest: HashMap<Digest, (ValidatorIndex, SessionCertificate)>,
    per_validator: HashMap<ValidatorIndex, usize>,
    latest: HashMap<ValidatorIndex, Digest>,
}

impl SessionBook {
    /// An empty book for `epoch` on one chain.
    pub fn new(chain_id: u64, genesis_hash: Digest, epoch: u64) -> Self {
        Self {
            chain_id,
            genesis_hash,
            epoch,
            by_digest: HashMap::new(),
            per_validator: HashMap::new(),
            latest: HashMap::new(),
        }
    }

    /// The epoch the book is for.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Checks `cert` against the hardware key of the member of `committee`
    /// it names and keeps it. Returns its digest, also when it was already
    /// kept.
    pub fn admit(&mut self, committee: &Committee, cert: SessionCertificate) -> Result<Digest> {
        let digest = cert.digest();
        if self.by_digest.contains_key(&digest) {
            return Ok(digest);
        }
        if committee.epoch != self.epoch {
            return Err(FinalityError::InvalidCertificate(
                "session book and committee are for different epochs".into(),
            ));
        }
        let Some(index) = committee
            .members()
            .iter()
            .position(|m| m.public_key.fingerprint() == cert.validator)
        else {
            return Err(FinalityError::InvalidCertificate(
                "session certificate of a non-member".into(),
            ));
        };
        let index = index as ValidatorIndex;
        let key = &committee.member(index).expect("indexed").public_key;
        if !cert.certifies(key, self.chain_id, &self.genesis_hash, self.epoch) {
            return Err(FinalityError::InvalidCertificate(
                "session certificate not signed by its validator for this chain and epoch".into(),
            ));
        }
        let count = self.per_validator.entry(index).or_default();
        if *count >= MAX_SESSIONS_PER_VALIDATOR {
            return Err(FinalityError::InvalidCertificate(
                "too many session certificates for one validator".into(),
            ));
        }
        *count += 1;
        self.by_digest.insert(digest, (index, cert));
        self.latest.insert(index, digest);
        Ok(digest)
    }

    /// The session certificate of `member` admitted last.
    pub fn latest(&self, member: ValidatorIndex) -> Option<Digest> {
        self.latest.get(&member).copied()
    }

    /// The session certificate with `digest`, and the member it certifies.
    pub fn get(&self, digest: &Digest) -> Option<(ValidatorIndex, &SessionCertificate)> {
        self.by_digest.get(digest).map(|(i, c)| (*i, c))
    }

    /// The certificates with these digests, each once, in the order first
    /// named. Digests not in the book are skipped.
    pub fn bundle(&self, digests: &[Digest]) -> Vec<SessionCertificate> {
        let mut seen = std::collections::HashSet::new();
        digests
            .iter()
            .filter(|d| seen.insert(**d))
            .filter_map(|d| self.by_digest.get(d).map(|(_, c)| c.clone()))
            .collect()
    }
}
