//! A validator's per-boot session key.
//!
//! A hardware signature costs a validator about a second of TPM time, so the
//! hardware key signs only statements that tie a key to it. Checkpoint votes
//! and channel handshakes are signed instead by a session key: a composite
//! key of the hardware key's scheme (ML-DSA-65 + P-256 or ML-DSA-87 +
//! P-384) made from the OS random source when the node starts, held only in this process's memory, never stored or exported,
//! and zeroised when it is dropped.
//!
//! The hardware key certifies the session key twice over: for channel
//! handshakes in the validator's endpoint announcement (see
//! [`crate::announce`]), and for checkpoint votes in a
//! [`SessionCertificate`] bound to one epoch, signed once per epoch. A vote
//! is valid only together with its certificate, so a vote, a certificate
//! formed from votes, and evidence of equivocation all trace back to the
//! validator's hardware key. A checkpoint certificate names each signer's
//! session certificate by digest rather than carrying it: the session
//! certificates of an epoch travel once, as the epoch's bundle, and a
//! verifier keeps them in a [`SessionBook`].

use ml_dsa::{ExpandedSigningKey, MlDsa65, MlDsa87};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use rand::RngCore;
use sha2::Digest as _;
use zeroize::Zeroizing;

use crate::error::{ConsensusError, Result};
use crate::validator_key::{
    CompositeSignature, SignatureScheme, ValidatorPublicKey, ValidatorSigner,
    message_representative_for,
};

/// The two legs of a session key, of one scheme. Boxed: an expanded ML-DSA
/// key is tens of kilobytes.
enum Legs {
    MlDsa65P256(Box<ExpandedSigningKey<MlDsa65>>, p256::ecdsa::SigningKey),
    MlDsa87P384(Box<ExpandedSigningKey<MlDsa87>>, p384::ecdsa::SigningKey),
}

/// This boot's session key.
pub struct SessionKey {
    legs: Legs,
    public: ValidatorPublicKey,
}

/// A scalar of an ECDSA curve from the OS random source. A draw of zero or
/// at least the group order is not a scalar; the chance is below 2^-32, so
/// drawing again is enough.
fn draw<K>(rng: &mut impl RngCore, len: usize, make: impl Fn(&[u8]) -> Option<K>) -> K {
    loop {
        let mut scalar = Zeroizing::new(vec![0u8; len]);
        rng.fill_bytes(scalar.as_mut());
        if let Some(k) = make(scalar.as_ref()) {
            break k;
        }
    }
}

impl SessionKey {
    /// A fresh session key of the default scheme (ML-DSA-65 with P-256)
    /// from the OS random source.
    pub fn generate() -> Result<Self> {
        Self::generate_with_scheme(SignatureScheme::default())
    }

    /// A fresh session key of `scheme` from the OS random source. A
    /// validator's session keys follow its hardware key's scheme, so a
    /// committee on ML-DSA-87 hardware keys votes with ML-DSA-87 session
    /// keys.
    pub fn generate_with_scheme(scheme: SignatureScheme) -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut());
        let (legs, bare_pk, ecdsa_pk) = match scheme {
            SignatureScheme::MlDsa65P256 => {
                let ml = Box::new(ExpandedSigningKey::<MlDsa65>::from_seed(&(*seed).into()));
                let ec = draw(&mut rng, 32, |b| {
                    p256::ecdsa::SigningKey::from_slice(b).ok()
                });
                let pk = ml.verifying_key().encode().to_vec();
                let ec_pk = ec.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                (Legs::MlDsa65P256(ml, ec), pk, ec_pk)
            }
            SignatureScheme::MlDsa87P384 => {
                let ml = Box::new(ExpandedSigningKey::<MlDsa87>::from_seed(&(*seed).into()));
                let ec = draw(&mut rng, 48, |b| {
                    p384::ecdsa::SigningKey::from_slice(b).ok()
                });
                let pk = ml.verifying_key().encode().to_vec();
                let ec_pk = ec.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                (Legs::MlDsa87P384(ml, ec), pk, ec_pk)
            }
        };
        let public = ValidatorPublicKey::new(scheme.tag(&bare_pk), ecdsa_pk)?;
        Ok(Self { legs, public })
    }
}

impl ValidatorSigner for SessionKey {
    fn public_key(&self) -> &ValidatorPublicKey {
        &self.public
    }

    fn sign(&self, domain: &[u8], message: &[u8]) -> Result<CompositeSignature> {
        let scheme = self.public.scheme();
        let rep = message_representative_for(scheme, domain, message).ok_or_else(|| {
            ConsensusError::InvalidValidatorKey("domain longer than 255 bytes".into())
        })?;
        fn failed(e: impl std::fmt::Display) -> ConsensusError {
            ConsensusError::Crypto(format!("ML-DSA session signature: {e}"))
        }
        let (bare, ec) = match &self.legs {
            Legs::MlDsa65P256(ml, ec) => {
                let sig = ml
                    .sign_deterministic(&rep, scheme.label())
                    .map_err(failed)?;
                let digest: [u8; 32] = sha2::Sha256::digest(&rep).into();
                let e: p256::ecdsa::Signature = ec
                    .sign_prehash(&digest)
                    .map_err(|e| ConsensusError::Crypto(format!("P-256 session signature: {e}")))?;
                (sig.encode().to_vec(), e.to_bytes().to_vec())
            }
            Legs::MlDsa87P384(ml, ec) => {
                let sig = ml
                    .sign_deterministic(&rep, scheme.label())
                    .map_err(failed)?;
                let digest: [u8; 48] = sha2::Sha384::digest(&rep).into();
                let e: p384::ecdsa::Signature = ec
                    .sign_prehash(&digest)
                    .map_err(|e| ConsensusError::Crypto(format!("P-384 session signature: {e}")))?;
                (sig.encode().to_vec(), e.to_bytes().to_vec())
            }
        };
        Ok(CompositeSignature {
            ml_dsa: scheme.tag(&bare),
            p256: ec,
        })
    }
}

pub use tenzro_finality::session::{
    MAX_SESSIONS_PER_VALIDATOR, SESSION_CERTIFICATE_DOMAIN, SessionBook, SessionCertificate,
    certificate_message,
};

/// `hardware` certifies `session_key` for `epoch`.
pub fn sign_certificate(
    hardware: &dyn ValidatorSigner,
    chain_id: u64,
    genesis_hash: [u8; 32],
    epoch: u64,
    session_key: ValidatorPublicKey,
) -> Result<SessionCertificate> {
    let mut c = SessionCertificate {
        chain_id,
        genesis_hash,
        epoch,
        validator: hardware.public_key().fingerprint(),
        session_key,
        signature: CompositeSignature {
            ml_dsa: Vec::new(),
            p256: Vec::new(),
        },
    };
    c.signature = hardware.sign(SESSION_CERTIFICATE_DOMAIN, &certificate_message(&c))?;
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_key::test_signer::SoftwareTestSigner;

    #[test]
    fn a_book_admits_only_members_own_certificates_for_its_chain_and_epoch() {
        let (c, s) = crate::committee::test_support::committee(4);
        let session = SessionKey::generate().unwrap();
        let mut book = SessionBook::new(7, [1; 32], 0);
        let good =
            crate::session::sign_certificate(&s[2], 7, [1; 32], 0, session.public_key().clone())
                .unwrap();
        let d = book.admit(&c, good.clone()).unwrap();
        assert_eq!(d, good.digest());
        assert_eq!(
            book.get(&d).map(|(i, _)| i),
            Some(2),
            "kept under the member it certifies"
        );
        assert_eq!(
            book.admit(&c, good.clone()).unwrap(),
            d,
            "admitting again is harmless"
        );

        let outsider = SoftwareTestSigner::from_seed(99);
        let foreign = crate::session::sign_certificate(
            &outsider,
            7,
            [1; 32],
            0,
            session.public_key().clone(),
        )
        .unwrap();
        assert!(book.admit(&c, foreign).is_err(), "not a member");
        let other_chain =
            crate::session::sign_certificate(&s[2], 8, [1; 32], 0, session.public_key().clone())
                .unwrap();
        assert!(book.admit(&c, other_chain).is_err(), "another chain");
        let other_epoch =
            crate::session::sign_certificate(&s[2], 7, [1; 32], 1, session.public_key().clone())
                .unwrap();
        assert!(book.admit(&c, other_epoch).is_err(), "another epoch");
        let mut claimed = good.clone();
        claimed.validator = c.member(1).unwrap().public_key.fingerprint();
        assert!(
            book.admit(&c, claimed).is_err(),
            "member 2's signature claimed for member 1"
        );
        let mut committee1 = c.clone();
        committee1.epoch = 1;
        let k = SessionKey::generate().unwrap();
        let fresh =
            crate::session::sign_certificate(&s[1], 7, [1; 32], 0, k.public_key().clone()).unwrap();
        assert!(
            book.admit(&committee1, fresh).is_err(),
            "checked against another epoch's committee"
        );

        // One validator cannot grow the book without end.
        for _ in 1..MAX_SESSIONS_PER_VALIDATOR {
            let k = SessionKey::generate().unwrap();
            book.admit(
                &c,
                crate::session::sign_certificate(&s[2], 7, [1; 32], 0, k.public_key().clone())
                    .unwrap(),
            )
            .unwrap();
        }
        let k = SessionKey::generate().unwrap();
        let one_too_many =
            crate::session::sign_certificate(&s[2], 7, [1; 32], 0, k.public_key().clone()).unwrap();
        assert!(book.admit(&c, one_too_many).is_err());
        let k = SessionKey::generate().unwrap();
        let other_member =
            crate::session::sign_certificate(&s[3], 7, [1; 32], 0, k.public_key().clone()).unwrap();
        assert!(
            book.admit(&c, other_member).is_ok(),
            "the cap is per validator"
        );
    }

    #[test]
    fn the_session_key_is_wiped_when_dropped() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<ExpandedSigningKey<MlDsa65>>();
        wipes_on_drop::<p256::ecdsa::SigningKey>();
    }

    #[test]
    fn a_certificate_certifies_exactly_its_key_validator_chain_and_epoch() {
        let hw = SoftwareTestSigner::from_seed(1);
        let other = SoftwareTestSigner::from_seed(2);
        let session = SessionKey::generate().unwrap();
        let c = crate::session::sign_certificate(&hw, 7, [1; 32], 3, session.public_key().clone())
            .unwrap();
        assert!(c.certifies(hw.public_key(), 7, &[1; 32], 3));
        assert!(
            !c.certifies(other.public_key(), 7, &[1; 32], 3),
            "another validator"
        );
        assert!(
            !c.certifies(hw.public_key(), 8, &[1; 32], 3),
            "another chain"
        );
        assert!(
            !c.certifies(hw.public_key(), 7, &[2; 32], 3),
            "another genesis"
        );
        assert!(
            !c.certifies(hw.public_key(), 7, &[1; 32], 4),
            "a later epoch"
        );
        assert!(
            !c.certifies(hw.public_key(), 7, &[1; 32], 2),
            "an earlier epoch"
        );
        // Every field is covered by the signature.
        let mutations: Vec<Box<dyn Fn(&mut SessionCertificate)>> = vec![
            Box::new(|c| c.chain_id ^= 1),
            Box::new(|c| c.genesis_hash[0] ^= 1),
            Box::new(|c| c.epoch ^= 1),
            Box::new(|c| c.validator[0] ^= 1),
            Box::new(|c| c.session_key = SoftwareTestSigner::from_seed(9).public_key().clone()),
            Box::new(|c| c.signature.ml_dsa[0] ^= 1),
            Box::new(|c| c.signature.p256[0] ^= 1),
        ];
        for (i, m) in mutations.iter().enumerate() {
            let mut t = c.clone();
            m(&mut t);
            assert!(
                !t.certifies(hw.public_key(), t.chain_id, &t.genesis_hash, t.epoch),
                "mutation {i}"
            );
        }
    }

    #[test]
    fn a_session_key_signs_composites_that_verify_and_each_boot_gets_its_own() {
        let a = SessionKey::generate().unwrap();
        let b = SessionKey::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
        let sig = a.sign(b"tenzro/test", b"m").unwrap();
        assert!(a.public_key().verify(b"tenzro/test", b"m", &sig));
        assert!(!b.public_key().verify(b"tenzro/test", b"m", &sig));
        assert!(!a.public_key().verify(b"tenzro/other", b"m", &sig));
    }
}
