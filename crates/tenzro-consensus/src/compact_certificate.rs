//! Compact checkpoint certificates.
//!
//! A checkpoint certificate carries one composite session signature per
//! signer. Its compact form keeps the ECDSA halves and replaces the quorum's
//! ML-DSA halves with one STARK over the committee's session keys (see
//! [`tenzro_cert_stark`]). The session keys of a compact certificate are of
//! one scheme, ML-DSA-65 with P-256 or ML-DSA-87 with P-384, and the encoded
//! proof names it.
//!
//! The proof has one slot per committee member, in index order. A slot holds
//! the ML-DSA key of a session certificate of that member from the epoch's
//! bundle ([`SessionBook`]): the one the member signed with, or, for a member
//! that did not sign, the one it was last certified with. A member with no
//! session certificate fills its slot with a key nobody holds.

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tenzro_cert_stark::{CompactProof, Epoch as ProofSetup, Scheme as ProofScheme};

use tenzro_finality::checkpoint::{CHECKPOINT_VOTE_DOMAIN, CertificateContext, Checkpoint};
use tenzro_finality::committee::{SeatSet, ValidatorIndex};
use tenzro_finality::key::{
    SignatureScheme, ValidatorPublicKey, message_representative_for, verify_ecdsa_for,
};
use tenzro_finality::session::SessionBook;
use tenzro_finality::{Digest, FinalityError, Result};

/// A checkpoint certificate whose ML-DSA signatures one STARK stands in for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactCertificate {
    /// The checkpoint.
    pub checkpoint: Checkpoint,
    /// Per committee member: the session certificate whose key fills its
    /// slot of the proof, if any.
    pub slots: Vec<Option<Digest>>,
    /// Per committee member: the ECDSA half of its session signature over
    /// the checkpoint (P-256 or P-384, by the scheme), if it signed.
    pub p256: Vec<Option<Vec<u8>>>,
    /// The scheme, the per-slot claims and the STARK
    /// ([`tenzro_cert_stark::CompactProof::encode`]); its first byte names
    /// the scheme of the slot keys.
    pub proof: Vec<u8>,
}

/// The proof system's name for the ML-DSA leg of `scheme`.
pub fn proof_scheme(scheme: SignatureScheme) -> ProofScheme {
    match scheme {
        SignatureScheme::MlDsa65P256 => ProofScheme::MlDsa65,
        SignatureScheme::MlDsa87P384 => ProofScheme::MlDsa87,
    }
}

/// The ML-DSA message a session vote signature of `scheme` covers for
/// `checkpoint`.
pub fn message_prime(checkpoint: &Checkpoint, scheme: SignatureScheme) -> Vec<u8> {
    let representative =
        message_representative_for(scheme, CHECKPOINT_VOTE_DOMAIN, &checkpoint.digest())
            .expect("vote domain fits a context");
    tenzro_cert_stark::message_prime(&representative, scheme.label()).expect("context fits")
}

/// Whether `ecdsa` is the ECDSA half of `key`'s session signature over
/// `checkpoint_digest`: P-256 or P-384, by the key's scheme.
fn ecdsa_leg_verifies(key: &ValidatorPublicKey, checkpoint_digest: &Digest, ecdsa: &[u8]) -> bool {
    let scheme = key.scheme();
    ecdsa.len() == scheme.ecdsa_signature_len()
        && message_representative_for(scheme, CHECKPOINT_VOTE_DOMAIN, checkpoint_digest)
            .is_some_and(|rep| verify_ecdsa_for(scheme, &key.p256, &rep, ecdsa))
}

/// Proof set-ups by their slot keys, the most recent few. Setting up is the
/// costly part of both proving and verifying, and slot keys change only
/// when a validator restarts.
#[derive(Default)]
pub struct ProofSetups {
    recent: Mutex<VecDeque<(Digest, Arc<ProofSetup>)>>,
    built: std::sync::atomic::AtomicU64,
}

/// Set-ups [`ProofSetups`] keeps: the current slot keys and the ones before
/// a validator's restart changed them. Each holds about 110 MB for a
/// committee of 7.
const SETUPS_KEPT: usize = 2;

impl ProofSetups {
    /// No set-ups yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many set-ups have been made.
    pub fn built(&self) -> u64 {
        self.built.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The set-up for the bare slot keys `keys` of `scheme`, made on first
    /// use.
    pub fn get(
        &self,
        scheme: SignatureScheme,
        keys: &[Option<Vec<u8>>],
    ) -> Result<Arc<ProofSetup>> {
        let mut h = blake3::Hasher::new();
        h.update(b"tenzro/consensus/compact-slot-keys");
        h.update(&[scheme.id()]);
        for k in keys {
            match k {
                None => h.update(&[0]),
                Some(k) => h.update(&[1]).update(k),
            };
        }
        let id: Digest = h.finalize().into();
        if let Some((_, s)) = self.recent.lock().iter().find(|(d, _)| *d == id) {
            return Ok(s.clone());
        }
        let slots: Vec<Option<&[u8]>> = keys.iter().map(|k| k.as_deref()).collect();
        let setup = Arc::new(
            ProofSetup::new(proof_scheme(scheme), &slots).ok_or_else(|| {
                FinalityError::InvalidCertificate("a session key does not decode".into())
            })?,
        );
        self.built
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut recent = self.recent.lock();
        recent.push_front((id, setup.clone()));
        recent.truncate(SETUPS_KEPT);
        Ok(setup)
    }
}

/// The scheme of the slot keys and the bare session ML-DSA key of each
/// slot, from `slots` and the book. Every slot key is of one scheme; a
/// committee whose session keys mix schemes has no compact form.
pub fn slot_keys(
    slots: &[Option<Digest>],
    sessions: &SessionBook,
) -> Result<(SignatureScheme, Vec<Option<Vec<u8>>>)> {
    let mut scheme = None;
    let keys = slots
        .iter()
        .enumerate()
        .map(|(i, d)| match d {
            None => Ok(None),
            Some(d) => match sessions.get(d) {
                Some((holder, cert)) if holder as usize == i => {
                    let Some((s, bare)) =
                        SignatureScheme::split_public_key(&cert.session_key.ml_dsa)
                    else {
                        return Err(FinalityError::InvalidCertificate(
                            "a session key names no scheme".into(),
                        ));
                    };
                    if *scheme.get_or_insert(s) != s {
                        return Err(FinalityError::InvalidCertificate(
                            "a compact certificate's session keys are of one scheme".into(),
                        ));
                    }
                    Ok(Some(bare.to_vec()))
                }
                Some(_) => Err(FinalityError::InvalidCertificate(
                    "a slot holds another validator's session key".into(),
                )),
                None => Err(FinalityError::InvalidCertificate(
                    "a slot's session certificate is not in the epoch's bundle".into(),
                )),
            },
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((scheme.unwrap_or_default(), keys))
}

impl CompactCertificate {
    /// Checks the compact certificate: chain, genesis and epoch match; every
    /// slot's session certificate is in the epoch's bundle and certifies the
    /// member of that slot; the slot keys are of the scheme the proof names;
    /// the members with a claim carry a quorum of seats; each of them has an
    /// ECDSA signature over the checkpoint by its session key; and the STARK
    /// proves an ML-DSA signature by each of those session keys over the
    /// checkpoint.
    pub fn verify(&self, ctx: &CertificateContext<'_>, setups: &ProofSetups) -> Result<()> {
        let bad = |why: &str| Err(FinalityError::InvalidCertificate(why.to_string()));
        let cp = &self.checkpoint;
        if cp.chain_id != ctx.chain_id || &cp.genesis_hash != ctx.genesis_hash {
            return bad("compact certificate is for another chain");
        }
        if cp.epoch != ctx.committee.epoch || cp.epoch != ctx.sessions.epoch() {
            return bad("compact certificate is for another epoch's committee");
        }
        if !cp.well_formed() {
            return bad("checkpoint's height range or state height is malformed");
        }
        let size = ctx.committee.size();
        if self.slots.len() != size || self.p256.len() != size {
            return bad("compact certificate does not have one slot per member");
        }
        let Some(proof) = CompactProof::decode(&self.proof) else {
            return bad("compact proof does not decode");
        };
        let claimed = proof.claimed();
        if claimed.len() != size {
            return bad("compact proof does not have one claim slot per member");
        }
        // A non-signer's slot is its latest session key, as the prover sets
        // it: the sender cannot choose slot keys to force fresh set-ups.
        if claimed
            .iter()
            .enumerate()
            .any(|(i, c)| !c && self.slots[i] != ctx.sessions.latest(i as ValidatorIndex))
        {
            return bad("a non-signer's slot is not its latest session key");
        }
        let (scheme, keys) = slot_keys(&self.slots, ctx.sessions)?;
        if proof_scheme(scheme) != proof.scheme() {
            return bad("the proof names another scheme than its slot keys");
        }
        let digest = cp.digest();
        let mut seats = SeatSet::new();
        for (i, claim) in claimed.iter().enumerate() {
            if !claim {
                continue;
            }
            let (Some(session), Some(sig)) = (&self.slots[i], &self.p256[i]) else {
                return bad("a signer's slot lacks its session certificate or ECDSA signature");
            };
            let (_, cert) = ctx.sessions.get(session).expect("checked by slot_keys");
            if !ecdsa_leg_verifies(&cert.session_key, &digest, sig) {
                return bad("an ECDSA signature does not verify under its signer's session key");
            }
            seats.insert(
                i as ValidatorIndex,
                ctx.committee.seats(i as ValidatorIndex),
            );
        }
        if seats.weight() < ctx.committee.quorum() {
            return bad("signers carry less than a quorum of seats");
        }
        if self
            .p256
            .iter()
            .zip(&claimed)
            .any(|(p, c)| p.is_some() && !c)
        {
            return bad("an ECDSA signature without a claim");
        }
        let setup = setups.get(scheme, &keys)?;
        if !setup.verify(&message_prime(cp, scheme), &proof) {
            return bad("the STARK does not prove the signers' ML-DSA signatures");
        }
        Ok(())
    }

    /// The members whose signatures the certificate proves.
    pub fn signers(&self) -> Vec<ValidatorIndex> {
        (0..self.p256.len())
            .filter(|i| self.p256[*i].is_some())
            .map(|i| i as ValidatorIndex)
            .collect()
    }
}
