//! Validator composite keys: ML-DSA-65 together with ECDSA-P256.
//!
//! A validator's hardware key signs three things in consensus: its
//! registration, once per boot the announcement of its endpoint and session
//! key, and once per epoch the certificate of that session key for checkpoint
//! votes. The session key ([`crate::session`]) signs the checkpoint votes and
//! the channel handshakes.
//! Each signature is a composite of an ML-DSA-65 signature and an ECDSA-P256
//! signature over the same message representative, and a composite verifies
//! only when both legs verify. Forging one therefore needs both schemes
//! broken.
//!
//! The construction is the composite ML-DSA-65 / ECDSA-P256-SHA512 scheme of
//! the IETF LAMPS composite-signature specification:
//!
//! ```text
//! M' = PREFIX || LABEL || len(ctx) || ctx || SHA-512(M)
//! mldsa_sig = ML-DSA-65.Sign(sk_mldsa, M', context = LABEL)
//! ecdsa_sig = ECDSA-P256-SHA256.Sign(sk_p256, M')
//! ```
//!
//! `ctx` is the consensus domain separator of the object being signed (a
//! checkpoint, a channel transcript, a registration), so a signature made for
//! one purpose never verifies for another.
//!
//! A validator's own private keys come from hardware. [`ValidatorSigner`] is
//! the only way consensus asks for a signature; the node implements it over
//! this machine's TPM or Secure Enclave. Outside tests the one software
//! signer is the per-boot session key, which holds no stake, lives only in
//! memory, and is accepted only under the hardware key's certification.

use crate::error::{ConsensusError, Result};

pub use tenzro_finality::key::{
    CompositeSignature, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN, P256_PUBLIC_KEY_LEN,
    P256_SIGNATURE_LEN, SignatureScheme, ValidatorPublicKey, message_representative,
    message_representative_for, ml_dsa_context,
};

/// Domain separator of a registration's proof of possession.
pub const REGISTRATION_DOMAIN: &[u8] = b"tenzro/consensus/registration";

/// The message a registrant signs with the key it registers: the validator
/// address, both key legs and the node's Ed25519 key. The network endpoint
/// is not registered: it is a per-boot key the validator announces
/// separately, signed by this key.
pub fn registration_message(
    address: &[u8],
    key: &ValidatorPublicKey,
    node_key: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + address.len() + key.ml_dsa.len() + key.p256.len() + 32);
    m.extend_from_slice(&(address.len() as u64).to_be_bytes());
    m.extend_from_slice(address);
    m.extend_from_slice(&key.ml_dsa);
    m.extend_from_slice(&key.p256);
    m.extend_from_slice(node_key);
    m
}

/// Checks a registration's proof of possession: `proof` is the encoded
/// composite signature of `key` over [`registration_message`].
pub fn verify_registration(
    address: &[u8],
    key: &ValidatorPublicKey,
    node_key: &[u8; 32],
    proof: &[u8],
) -> Result<()> {
    use bincode::Options as _;
    // One encoding per proof: no trailing bytes, no length past a signature's.
    let sig: CompositeSignature = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(8_192)
        .reject_trailing_bytes()
        .deserialize(proof)
        .map_err(|_| {
            ConsensusError::InvalidValidatorKey("proof of possession does not decode".into())
        })?;
    if !key.verify(
        REGISTRATION_DOMAIN,
        &registration_message(address, key, node_key),
        &sig,
    ) {
        return Err(ConsensusError::InvalidValidatorKey(
            "proof of possession does not verify under the registered key".into(),
        ));
    }
    Ok(())
}

/// Domain separator of the node key's signature over a registration.
pub const NODE_KEY_REGISTRATION_DOMAIN: &[u8] = b"tenzro/consensus/registration/node-key";

/// The bytes the node key signs to register: its domain separator and the
/// [`registration_message`].
pub fn node_key_registration_message(
    address: &[u8],
    key: &ValidatorPublicKey,
    node_key: &[u8; 32],
) -> Vec<u8> {
    let mut m = NODE_KEY_REGISTRATION_DOMAIN.to_vec();
    m.extend_from_slice(&registration_message(address, key, node_key));
    m
}

/// Checks that `node_key` signed the registration: `signature` is its
/// Ed25519 signature over [`node_key_registration_message`]. Without it
/// anyone could register another node's key as their own and take the peer
/// admission and availability attestations that key signs.
pub fn verify_node_key_registration(
    address: &[u8],
    key: &ValidatorPublicKey,
    node_key: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    let public = tenzro_crypto::PublicKey::new(tenzro_crypto::KeyType::Ed25519, node_key.to_vec());
    let sig = tenzro_crypto::Signature::new(tenzro_crypto::KeyType::Ed25519, signature.to_vec());
    tenzro_crypto::signatures::verify(
        &public,
        &node_key_registration_message(address, key, node_key),
        &sig,
    )
    .map_err(|_| {
        ConsensusError::InvalidValidatorKey("the node key did not sign this registration".into())
    })
}

/// Domain separator of the VRF key's proof over a registration.
pub const VRF_KEY_REGISTRATION_DOMAIN: &[u8] = b"tenzro/consensus/registration/vrf-key";

/// The VRF input the VRF key proves over to register: its domain separator,
/// the [`registration_message`] and the VRF key itself.
pub fn vrf_key_registration_alpha(
    address: &[u8],
    key: &ValidatorPublicKey,
    node_key: &[u8; 32],
    vrf_key: &[u8; 32],
) -> Vec<u8> {
    let mut m = VRF_KEY_REGISTRATION_DOMAIN.to_vec();
    m.extend_from_slice(&registration_message(address, key, node_key));
    m.extend_from_slice(vrf_key);
    m
}

/// Checks that the registrant holds `vrf_key`: `proof` is its VRF proof over
/// [`vrf_key_registration_alpha`]. The VRF key is a key of its own, never
/// the node key, so a VRF proof and a node-key signature never share a
/// secret or a nonce.
pub fn verify_vrf_key_registration(
    address: &[u8],
    key: &ValidatorPublicKey,
    node_key: &[u8; 32],
    vrf_key: &[u8; 32],
    proof: &[u8],
) -> Result<()> {
    if vrf_key == node_key {
        return Err(ConsensusError::InvalidValidatorKey(
            "the VRF key must not be the node key".into(),
        ));
    }
    let proof = tenzro_crypto::vrf::VrfProof::from_bytes(proof).map_err(|_| {
        ConsensusError::InvalidValidatorKey("the VRF key proof does not decode".into())
    })?;
    tenzro_crypto::vrf::verify(
        &tenzro_crypto::vrf::VrfPublicKey(*vrf_key),
        &vrf_key_registration_alpha(address, key, node_key, vrf_key),
        &proof,
    )
    .map(|_| ())
    .map_err(|_| {
        ConsensusError::InvalidValidatorKey("the VRF key did not prove this registration".into())
    })
}

/// Signs a registration with the key being registered.
pub fn prove_registration(
    signer: &dyn ValidatorSigner,
    address: &[u8],
    node_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let sig = signer.sign(
        REGISTRATION_DOMAIN,
        &registration_message(address, signer.public_key(), node_key),
    )?;
    Ok(bincode::serialize(&sig).expect("signature encodes"))
}

/// Signs consensus messages with a validator's hardware-held composite key.
pub trait ValidatorSigner: Send + Sync {
    /// The composite public key.
    fn public_key(&self) -> &ValidatorPublicKey;

    /// Signs `message` for `domain`. Both legs are produced by hardware.
    fn sign(&self, domain: &[u8], message: &[u8]) -> Result<CompositeSignature>;
}

#[cfg(any(test, feature = "test-keys"))]
pub mod test_signer {
    //! A software signer standing in for hardware. Compiled into tests and
    //! the `test-keys` feature only, which the network simulator enables and
    //! no release crate does: no release build can construct a software
    //! [`ValidatorSigner`].

    use super::*;
    use ml_dsa::{ExpandedSigningKey, MlDsa65, MlDsa87};
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::Digest as _;

    // Boxed: an expanded ML-DSA-87 key is tens of kilobytes, and the test
    // signer is moved around on the stack.
    enum MlDsaKey {
        MlDsa65(Box<ExpandedSigningKey<MlDsa65>>),
        MlDsa87(Box<ExpandedSigningKey<MlDsa87>>),
    }

    enum EcdsaKey {
        P256(p256::ecdsa::SigningKey),
        P384(p384::ecdsa::SigningKey),
    }

    pub struct SoftwareTestSigner {
        ml_dsa: MlDsaKey,
        ecdsa: EcdsaKey,
        public: ValidatorPublicKey,
    }

    impl SoftwareTestSigner {
        /// A deterministic key for test party `seed`.
        pub fn from_seed(seed: u64) -> Self {
            Self::from_seed_with_scheme(seed, SignatureScheme::default())
        }

        /// A deterministic key of `scheme` for test party `seed`.
        pub fn from_seed_with_scheme(seed: u64, scheme: SignatureScheme) -> Self {
            let mut xi = [0u8; 32];
            xi[..8].copy_from_slice(&seed.to_le_bytes());
            xi[8] = 0xA5;
            let (ml_dsa, bare_pk) = match scheme {
                SignatureScheme::MlDsa65P256 => {
                    let k = Box::new(ExpandedSigningKey::<MlDsa65>::from_seed(&xi.into()));
                    let pk = k.verifying_key().encode().to_vec();
                    (MlDsaKey::MlDsa65(k), pk)
                }
                SignatureScheme::MlDsa87P384 => {
                    let k = Box::new(ExpandedSigningKey::<MlDsa87>::from_seed(&xi.into()));
                    let pk = k.verifying_key().encode().to_vec();
                    (MlDsaKey::MlDsa87(k), pk)
                }
            };
            let ml_dsa_pk = scheme.tag(&bare_pk);
            let mut p_seed = [0u8; 32];
            p_seed[..8].copy_from_slice(&seed.to_le_bytes());
            p_seed[31] = 1;
            let (ecdsa, ecdsa_pk) = match scheme {
                SignatureScheme::MlDsa65P256 => {
                    let k =
                        p256::ecdsa::SigningKey::from_slice(&p_seed).expect("valid P-256 scalar");
                    let pk = k.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                    (EcdsaKey::P256(k), pk)
                }
                SignatureScheme::MlDsa87P384 => {
                    let mut s48 = [0u8; 48];
                    s48[16..].copy_from_slice(&p_seed);
                    let k = p384::ecdsa::SigningKey::from_slice(&s48).expect("valid P-384 scalar");
                    let pk = k.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                    (EcdsaKey::P384(k), pk)
                }
            };
            Self {
                ml_dsa,
                ecdsa,
                public: ValidatorPublicKey::new(ml_dsa_pk, ecdsa_pk).expect("well-formed test key"),
            }
        }
    }

    impl ValidatorSigner for SoftwareTestSigner {
        fn public_key(&self) -> &ValidatorPublicKey {
            &self.public
        }
        fn sign(&self, domain: &[u8], message: &[u8]) -> Result<CompositeSignature> {
            let scheme = self.public.scheme();
            let rep = message_representative_for(scheme, domain, message).ok_or_else(|| {
                ConsensusError::InvalidValidatorKey("domain longer than 255 bytes".into())
            })?;
            let failed = |_| ConsensusError::InvalidValidatorKey("ML-DSA sign failed".into());
            let bare = match &self.ml_dsa {
                MlDsaKey::MlDsa65(k) => k
                    .sign_deterministic(&rep, scheme.label())
                    .map_err(failed)?
                    .encode()
                    .to_vec(),
                MlDsaKey::MlDsa87(k) => k
                    .sign_deterministic(&rep, scheme.label())
                    .map_err(failed)?
                    .encode()
                    .to_vec(),
            };
            let ec = match &self.ecdsa {
                EcdsaKey::P256(k) => {
                    let digest: [u8; 32] = sha2::Sha256::digest(&rep).into();
                    let ec: p256::ecdsa::Signature =
                        k.sign_prehash(&digest).expect("P-256 prehash sign");
                    ec.to_bytes().to_vec()
                }
                EcdsaKey::P384(k) => {
                    let digest: [u8; 48] = sha2::Sha384::digest(&rep).into();
                    let ec: p384::ecdsa::Signature =
                        k.sign_prehash(&digest).expect("P-384 prehash sign");
                    ec.to_bytes().to_vec()
                }
            };
            Ok(CompositeSignature {
                ml_dsa: scheme.tag(&bare),
                p256: ec,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_signer::SoftwareTestSigner;
    use super::*;
    use tenzro_finality::key::{verify_ml_dsa, verify_p256};

    #[test]
    fn a_composite_signature_verifies_only_for_its_domain_and_message() {
        let s = SoftwareTestSigner::from_seed(1);
        let sig = s.sign(b"tenzro/consensus/checkpoint", b"m").unwrap();
        assert!(
            s.public_key()
                .verify(b"tenzro/consensus/checkpoint", b"m", &sig)
        );
        assert!(
            !s.public_key()
                .verify(b"tenzro/consensus/checkpoint", b"n", &sig)
        );
        assert!(
            !s.public_key()
                .verify(b"tenzro/consensus/channel", b"m", &sig)
        );
        let other = SoftwareTestSigner::from_seed(2);
        assert!(
            !other
                .public_key()
                .verify(b"tenzro/consensus/checkpoint", b"m", &sig)
        );
    }

    #[test]
    fn a_composite_with_either_leg_stripped_or_swapped_is_refused() {
        let s = SoftwareTestSigner::from_seed(3);
        let t = SoftwareTestSigner::from_seed(4);
        let d = b"tenzro/consensus/checkpoint";
        let a = s.sign(d, b"m").unwrap();
        let b = t.sign(d, b"m").unwrap();
        let pk = s.public_key();
        assert!(!pk.verify(
            d,
            b"m",
            &CompositeSignature {
                ml_dsa: a.ml_dsa.clone(),
                p256: vec![]
            }
        ));
        assert!(!pk.verify(
            d,
            b"m",
            &CompositeSignature {
                ml_dsa: vec![],
                p256: a.p256.clone()
            }
        ));
        assert!(!pk.verify(
            d,
            b"m",
            &CompositeSignature {
                ml_dsa: a.ml_dsa.clone(),
                p256: b.p256.clone()
            }
        ));
        assert!(!pk.verify(
            d,
            b"m",
            &CompositeSignature {
                ml_dsa: b.ml_dsa.clone(),
                p256: a.p256.clone()
            }
        ));
    }

    #[test]
    fn a_high_s_p256_leg_still_verifies() {
        let s = SoftwareTestSigner::from_seed(5);
        let d = b"tenzro/consensus/checkpoint";
        let mut sig = s.sign(d, b"m").unwrap();
        let low = p256::ecdsa::Signature::from_slice(&sig.p256).unwrap();
        let (r, s_scalar) = low.split_scalars();
        let high_s = -*s_scalar;
        let high = p256::ecdsa::Signature::from_scalars(r.to_bytes(), high_s.to_bytes()).unwrap();
        sig.p256 = high.to_bytes().to_vec();
        assert!(s.public_key().verify(d, b"m", &sig));
    }

    #[test]
    fn only_the_vrf_key_itself_proves_its_registration_and_it_is_not_the_node_key() {
        use tenzro_crypto::vrf::{VrfProver, VrfSecretKey};
        let s = SoftwareTestSigner::from_seed(10);
        let vrf = VrfSecretKey([7u8; 32]);
        let vk = vrf.public_key().0;
        let (addr, nk) = ([1u8; 32], [2u8; 32]);
        let alpha = vrf_key_registration_alpha(&addr, s.public_key(), &nk, &vk);
        let proof = vrf.prove(&alpha).unwrap();
        assert!(
            verify_vrf_key_registration(&addr, s.public_key(), &nk, &vk, proof.as_bytes()).is_ok()
        );
        assert!(
            verify_vrf_key_registration(&[3u8; 32], s.public_key(), &nk, &vk, proof.as_bytes())
                .is_err(),
            "another address"
        );
        let squat = VrfSecretKey([8u8; 32]);
        let squat_proof = squat.prove(&alpha).unwrap();
        assert!(
            verify_vrf_key_registration(&addr, s.public_key(), &nk, &vk, squat_proof.as_bytes())
                .is_err(),
            "a proof by another key"
        );
        let same = vrf_key_registration_alpha(&addr, s.public_key(), &vk, &vk);
        let same_proof = vrf.prove(&same).unwrap();
        assert!(
            verify_vrf_key_registration(&addr, s.public_key(), &vk, &vk, same_proof.as_bytes())
                .is_err(),
            "the node key as VRF key"
        );
    }

    #[test]
    fn a_registration_proves_possession_of_exactly_its_key_address_and_node_key() {
        let s = SoftwareTestSigner::from_seed(8);
        let other = SoftwareTestSigner::from_seed(9);
        let (addr, nk) = ([1u8; 32], [2u8; 32]);
        let proof = prove_registration(&s, &addr, &nk).unwrap();
        assert!(verify_registration(&addr, s.public_key(), &nk, &proof).is_ok());
        let mut padded = proof.clone();
        padded.push(0);
        assert!(
            verify_registration(&addr, s.public_key(), &nk, &padded).is_err(),
            "a proof with trailing bytes"
        );
        assert!(
            verify_registration(&[3u8; 32], s.public_key(), &nk, &proof).is_err(),
            "another address"
        );
        assert!(
            verify_registration(&addr, s.public_key(), &[4u8; 32], &proof).is_err(),
            "another node key"
        );
        assert!(
            verify_registration(&addr, other.public_key(), &nk, &proof).is_err(),
            "someone else's key"
        );
        let forged = prove_registration(&other, &addr, &nk).unwrap();
        assert!(
            verify_registration(&addr, s.public_key(), &nk, &forged).is_err(),
            "signed by another key"
        );
        assert!(
            verify_registration(&addr, s.public_key(), &nk, &[0u8; 10]).is_err(),
            "garbage"
        );
    }

    #[test]
    fn only_the_node_key_itself_can_sign_its_registration() {
        use tenzro_crypto::Signer;
        let s = SoftwareTestSigner::from_seed(8);
        let node = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let other = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let nk: [u8; 32] = node.public_key().as_bytes().try_into().unwrap();
        let addr = [1u8; 32];
        let msg = node_key_registration_message(&addr, s.public_key(), &nk);
        let good = node.sign(&msg).unwrap().to_bytes();
        assert!(verify_node_key_registration(&addr, s.public_key(), &nk, &good).is_ok());
        assert!(
            verify_node_key_registration(&[2u8; 32], s.public_key(), &nk, &good).is_err(),
            "another address"
        );
        let squat = other.sign(&msg).unwrap().to_bytes();
        assert!(
            verify_node_key_registration(&addr, s.public_key(), &nk, &squat).is_err(),
            "another node's key"
        );
        let plain = node
            .sign(&registration_message(&addr, s.public_key(), &nk))
            .unwrap()
            .to_bytes();
        assert!(
            verify_node_key_registration(&addr, s.public_key(), &nk, &plain).is_err(),
            "no domain separator"
        );
    }

    /// Single-core verification cost of the ML-DSA-65 leg, the P-256 leg
    /// and the composite, over `TDC_MICRO_ITERS` signatures (default 4000).
    /// Prints one `GATE {json}` line. Run with `--release --ignored
    /// --nocapture`.
    #[test]
    #[ignore]
    fn gate_signature_verification_micro() {
        let iters: usize = std::env::var("TDC_MICRO_ITERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4000);
        let d = b"tenzro/consensus/checkpoint";
        let signers: Vec<SoftwareTestSigner> = (0..16).map(SoftwareTestSigner::from_seed).collect();
        let signed: Vec<(usize, Vec<u8>, CompositeSignature)> = (0..iters)
            .map(|i| {
                let msg = (i as u64).to_be_bytes().to_vec();
                let sig = signers[i % 16].sign(d, &msg).unwrap();
                (i % 16, msg, sig)
            })
            .collect();
        let time = |f: &dyn Fn(&(usize, Vec<u8>, CompositeSignature)) -> bool| {
            let start = std::time::Instant::now();
            for s in &signed {
                assert!(f(s));
            }
            start.elapsed().as_secs_f64() * 1e6 / iters as f64
        };
        let rep =
            |s: &(usize, Vec<u8>, CompositeSignature)| message_representative(d, &s.1).unwrap();
        let ml_dsa_us =
            time(&|s| verify_ml_dsa(&signers[s.0].public_key().ml_dsa, &rep(s), &s.2.ml_dsa));
        let p256_us = time(&|s| verify_p256(&signers[s.0].public_key().p256, &rep(s), &s.2.p256));
        let composite_us = time(&|s| signers[s.0].public_key().verify(d, &s.1, &s.2));
        println!(
            "GATE {{\"gate\":\"signature_verification_micro\",\"iters\":{iters},\"ml_dsa_65_verify_us\":{ml_dsa_us:.1},\
             \"p256_verify_us\":{p256_us:.1},\"composite_verify_us\":{composite_us:.1},\
             \"certificate_67_verify_ms\":{:.2}}}",
            composite_us * 67.0 / 1e3
        );
    }

    #[test]
    fn a_malformed_key_is_refused() {
        assert!(ValidatorPublicKey::new(vec![0; 10], vec![4; 65]).is_err());
        assert!(ValidatorPublicKey::new(vec![0; ML_DSA_65_PUBLIC_KEY_LEN], vec![4; 65]).is_err());
    }
}
