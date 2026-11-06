//! A second ML-DSA-65 implementation for the finality checks.
//!
//! The certificate, vote and session checks in `tenzro-finality` run the
//! RustCrypto ML-DSA-65 verifier, the one the finality prover also runs.
//! Before a validator counts a vote or accepts a certificate it asks the
//! formally verified `libcrux-ml-dsa` the same question for every ML-DSA-65
//! leg the object carries. When the two implementations answer differently
//! the object is refused and the core halts (see `Core::on_disagreement`):
//! a signature one implementation accepts and the other refuses is an attack
//! on one of them or a bug in one of them, and going on would let validators
//! that run different builds certify different histories.

use tenzro_finality::checkpoint::{CHECKPOINT_VOTE_DOMAIN, Certificate};
use tenzro_finality::key::{
    CompositeSignature, ValidatorPublicKey, message_representative, ml_dsa_context, verify_ml_dsa,
};
use tenzro_finality::session::{SESSION_CERTIFICATE_DOMAIN, SessionBook, certificate_message};

use crate::checkpoint::CheckpointVote;
use crate::committee::Committee;
use crate::session::SessionCertificate;

/// One implementation's verdict on an ML-DSA-65 leg: public key, message
/// representative, signature.
pub(crate) type MlDsaLeg = fn(&[u8], &[u8], &[u8]) -> bool;

/// The two ML-DSA-65 implementations a validator checks every leg with.
#[derive(Clone, Copy)]
pub(crate) struct Verifiers {
    pub(crate) primary: MlDsaLeg,
    pub(crate) second: MlDsaLeg,
}

impl Default for Verifiers {
    fn default() -> Self {
        Self {
            primary: verify_ml_dsa,
            second: libcrux_leg,
        }
    }
}

fn libcrux_leg(public_key: &[u8], representative: &[u8], signature: &[u8]) -> bool {
    tenzro_crypto::pq::libcrux_ml_dsa_verify(
        public_key,
        ml_dsa_context(),
        representative,
        signature,
    )
    .is_ok()
}

impl Verifiers {
    /// Whether both implementations give one verdict on the ML-DSA-65 leg of
    /// `sig` by `key`, made for `domain` over `message`.
    fn agree(
        &self,
        key: &ValidatorPublicKey,
        domain: &[u8],
        message: &[u8],
        sig: &CompositeSignature,
    ) -> bool {
        // A domain too long for a context makes every verifier refuse.
        let Some(rep) = message_representative(domain, message) else {
            return true;
        };
        (self.primary)(&key.ml_dsa, &rep, &sig.ml_dsa)
            == (self.second)(&key.ml_dsa, &rep, &sig.ml_dsa)
    }

    /// Whether both agree on a session certificate's signature by the
    /// committee member it names. A certificate naming no member is refused
    /// by the finality checks without any signature being verified.
    pub(crate) fn session_agrees(&self, committee: &Committee, cert: &SessionCertificate) -> bool {
        let Some(member) = committee
            .members()
            .iter()
            .find(|m| m.public_key.fingerprint() == cert.validator)
        else {
            return true;
        };
        self.agree(
            &member.public_key,
            SESSION_CERTIFICATE_DOMAIN,
            &certificate_message(cert),
            &cert.signature,
        )
    }

    /// Whether both agree on every ML-DSA-65 leg of a vote: its session
    /// certificate's and the session key's over the checkpoint.
    pub(crate) fn vote_agrees(&self, committee: &Committee, vote: &CheckpointVote) -> bool {
        self.session_agrees(committee, &vote.signature.session)
            && self.agree(
                &vote.signature.session.session_key,
                CHECKPOINT_VOTE_DOMAIN,
                &vote.checkpoint.digest(),
                &vote.signature.signature,
            )
    }

    /// Whether both agree on every session signature of a certificate whose
    /// session certificate is in `sessions`.
    pub(crate) fn certificate_agrees(&self, c: &Certificate, sessions: &SessionBook) -> bool {
        let digest = c.checkpoint.digest();
        c.sessions.iter().zip(&c.signatures).all(|(session, sig)| {
            sessions.get(session).is_none_or(|(_, cert)| {
                self.agree(&cert.session_key, CHECKPOINT_VOTE_DOMAIN, &digest, sig)
            })
        })
    }
}
