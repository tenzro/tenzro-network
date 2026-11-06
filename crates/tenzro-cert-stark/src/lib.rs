//! Compact checkpoint certificates.
//!
//! A raw checkpoint certificate carries one composite signature per signer.
//! The compact form replaces the quorum's ML-DSA signatures with one STARK
//! and a short claim per signer; the ECDSA halves travel alongside it
//! unaggregated.
//!
//! A committee's session keys are of one ML-DSA parameter set, its
//! [`Scheme`]: ML-DSA-65 ([`ml_dsa_65`]) or ML-DSA-87 ([`ml_dsa_87`]). Each
//! has its own verifier layout, lattice arithmetic tables and proof set-up;
//! [`Epoch`] and [`CompactProof`] hold either, and an encoded compact proof
//! names its scheme in its first byte. [`config`] holds the proof system's
//! parameters, the same for both.

pub mod config;
pub mod ml_dsa_65;
pub mod ml_dsa_87;

/// `M' = 0 || len(ctx) || ctx || M`, the message ML-DSA.Verify signs, the
/// same for every parameter set.
pub use ml_dsa_65::mldsa::message_prime;

/// The ML-DSA parameter set of a committee's session keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
}

impl Scheme {
    /// The byte an encoded compact proof names the scheme by.
    pub const fn id(self) -> u8 {
        match self {
            Self::MlDsa65 => 0,
            Self::MlDsa87 => 1,
        }
    }

    /// The scheme with id `id`.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::MlDsa65),
            1 => Some(Self::MlDsa87),
            _ => None,
        }
    }

    /// Bytes of an encoded public key.
    pub const fn public_key_bytes(self) -> usize {
        match self {
            Self::MlDsa65 => ml_dsa_65::mldsa::PUBLIC_KEY_BYTES,
            Self::MlDsa87 => ml_dsa_87::mldsa::PUBLIC_KEY_BYTES,
        }
    }

    /// Bytes of an encoded signature.
    pub const fn signature_bytes(self) -> usize {
        match self {
            Self::MlDsa65 => ml_dsa_65::mldsa::SIGNATURE_BYTES,
            Self::MlDsa87 => ml_dsa_87::mldsa::SIGNATURE_BYTES,
        }
    }

    /// Bytes a compact proof reveals per signer.
    pub const fn claim_bytes(self) -> usize {
        match self {
            Self::MlDsa65 => ml_dsa_65::compact::Claim::ENCODED_LEN,
            Self::MlDsa87 => ml_dsa_87::compact::Claim::ENCODED_LEN,
        }
    }
}

/// A compact certificate's claims and STARK, of either scheme.
pub enum CompactProof {
    /// Over ML-DSA-65 keys.
    MlDsa65(ml_dsa_65::compact::CompactProof),
    /// Over ML-DSA-87 keys.
    MlDsa87(ml_dsa_87::compact::CompactProof),
}

impl CompactProof {
    /// The scheme of the keys the proof is over.
    pub fn scheme(&self) -> Scheme {
        match self {
            Self::MlDsa65(_) => Scheme::MlDsa65,
            Self::MlDsa87(_) => Scheme::MlDsa87,
        }
    }

    /// Per slot, whether it carries a claim.
    pub fn claimed(&self) -> Vec<bool> {
        match self {
            Self::MlDsa65(p) => p.claims.iter().map(Option::is_some).collect(),
            Self::MlDsa87(p) => p.claims.iter().map(Option::is_some).collect(),
        }
    }

    /// The scheme's id, then the claims and the proof.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![self.scheme().id()];
        out.extend(match self {
            Self::MlDsa65(p) => p.encode(),
            Self::MlDsa87(p) => p.encode(),
        });
        out
    }

    /// The compact proof [`CompactProof::encode`] wrote. None if it names
    /// no known scheme or does not decode.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (&id, rest) = bytes.split_first()?;
        Some(match Scheme::from_id(id)? {
            Scheme::MlDsa65 => Self::MlDsa65(ml_dsa_65::compact::CompactProof::decode(rest)?),
            Scheme::MlDsa87 => Self::MlDsa87(ml_dsa_87::compact::CompactProof::decode(rest)?),
        })
    }
}

/// The proof set-up of a committee's session keys, of either scheme.
pub enum Epoch {
    /// ML-DSA-65 keys.
    MlDsa65(ml_dsa_65::compact::Epoch),
    /// ML-DSA-87 keys.
    MlDsa87(ml_dsa_87::compact::Epoch),
}

impl Epoch {
    /// Sets up the committee whose slots hold the encoded `keys` of
    /// `scheme`, in slot order; `None` in a slot is a key nobody holds (all
    /// zero). None if a key does not decode.
    pub fn new(scheme: Scheme, keys: &[Option<&[u8]>]) -> Option<Self> {
        macro_rules! setup {
            ($m:ident, $v:ident) => {{
                let absent = [0u8; $m::mldsa::PUBLIC_KEY_BYTES];
                let keys = keys
                    .iter()
                    .map(|k| $m::mldsa::PublicKey::decode(k.unwrap_or(&absent)))
                    .collect::<Option<Vec<_>>>()?;
                Self::$v($m::compact::Epoch::new(keys))
            }};
        }
        Some(match scheme {
            Scheme::MlDsa65 => setup!(ml_dsa_65, MlDsa65),
            Scheme::MlDsa87 => setup!(ml_dsa_87, MlDsa87),
        })
    }

    /// The scheme of the keys.
    pub fn scheme(&self) -> Scheme {
        match self {
            Self::MlDsa65(_) => Scheme::MlDsa65,
            Self::MlDsa87(_) => Scheme::MlDsa87,
        }
    }

    /// Number of slots.
    pub fn slots(&self) -> usize {
        match self {
            Self::MlDsa65(e) => e.slots(),
            Self::MlDsa87(e) => e.slots(),
        }
    }

    /// Proves the compact certificate of the encoded `signatures` (one per
    /// slot, `None` where the member did not sign) over `message_prime`.
    /// None if a signature does not decode or verify, or the count is not
    /// one per slot.
    pub fn prove(
        &self,
        message_prime: &[u8],
        signatures: &[Option<&[u8]>],
    ) -> Option<CompactProof> {
        macro_rules! prove {
            ($m:ident, $v:ident, $e:expr) => {{
                let sigs = signatures
                    .iter()
                    .map(|s| match s {
                        None => Some(None),
                        Some(b) => $m::mldsa::Signature::decode(b).map(Some),
                    })
                    .collect::<Option<Vec<_>>>()?;
                CompactProof::$v($e.prove(message_prime, &sigs)?)
            }};
        }
        Some(match self {
            Self::MlDsa65(e) => prove!(ml_dsa_65, MlDsa65, e),
            Self::MlDsa87(e) => prove!(ml_dsa_87, MlDsa87, e),
        })
    }

    /// Whether `cert` is of this set-up's scheme and proves, for every slot
    /// with a claim, an ML-DSA signature by that slot's key over
    /// `message_prime`.
    pub fn verify(&self, message_prime: &[u8], cert: &CompactProof) -> bool {
        match (self, cert) {
            (Self::MlDsa65(e), CompactProof::MlDsa65(p)) => e.verify(message_prime, p),
            (Self::MlDsa87(e), CompactProof::MlDsa87(p)) => e.verify(message_prime, p),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{ExpandedSigningKey, MlDsa65, MlDsa87, MlDsaParams};

    fn keys<P: MlDsaParams>(n: u8) -> Vec<ExpandedSigningKey<P>> {
        (0..n)
            .map(|i| ExpandedSigningKey::<P>::from_seed(&[i + 40; 32].into()))
            .collect()
    }

    /// One committee per scheme proves and verifies through the scheme
    /// dispatch; a proof names its scheme and never verifies under a set-up
    /// of the other.
    #[test]
    fn each_scheme_proves_under_its_own_setup_only() {
        let msg = [0x33; 120];
        let s87 = keys::<MlDsa87>(3);
        let pk87: Vec<Vec<u8>> = s87
            .iter()
            .map(|k| k.verifying_key().encode().to_vec())
            .collect();
        let sig87: Vec<Vec<u8>> = s87
            .iter()
            .map(|k| {
                k.sign_deterministic(&msg, ml_dsa_87::params::LABEL)
                    .unwrap()
                    .encode()
                    .to_vec()
            })
            .collect();
        assert_eq!(pk87[0].len(), Scheme::MlDsa87.public_key_bytes());
        assert_eq!(sig87[0].len(), Scheme::MlDsa87.signature_bytes());
        let mp = message_prime(&msg, ml_dsa_87::params::LABEL).unwrap();
        let slots: Vec<Option<&[u8]>> = vec![Some(&pk87[0]), Some(&pk87[1]), Some(&pk87[2]), None];
        let epoch = Epoch::new(Scheme::MlDsa87, &slots).unwrap();
        assert_eq!((epoch.scheme(), epoch.slots()), (Scheme::MlDsa87, 4));
        let sigs: Vec<Option<&[u8]>> = vec![Some(&sig87[0]), None, Some(&sig87[2]), None];
        let proof = epoch.prove(&mp, &sigs).expect("proves");
        assert_eq!(proof.scheme(), Scheme::MlDsa87);
        assert_eq!(proof.claimed(), vec![true, false, true, false]);
        let bytes = proof.encode();
        assert_eq!(bytes[0], Scheme::MlDsa87.id());
        let decoded = CompactProof::decode(&bytes).unwrap();
        assert!(epoch.verify(&mp, &decoded));

        // The same bytes named as the other scheme do not decode, and a
        // committee of ML-DSA-65 keys does not accept the proof.
        let mut renamed = bytes.clone();
        renamed[0] = Scheme::MlDsa65.id();
        assert!(CompactProof::decode(&renamed).is_none_or(|p| !epoch.verify(&mp, &p)));
        let s65 = keys::<MlDsa65>(4);
        let pk65: Vec<Vec<u8>> = s65
            .iter()
            .map(|k| k.verifying_key().encode().to_vec())
            .collect();
        let slots65: Vec<Option<&[u8]>> = pk65.iter().map(|k| Some(k.as_slice())).collect();
        let epoch65 = Epoch::new(Scheme::MlDsa65, &slots65).unwrap();
        assert!(!epoch65.verify(&mp, &decoded));
        assert!(
            Epoch::new(Scheme::MlDsa65, &slots).is_none(),
            "ML-DSA-87 keys are not ML-DSA-65 keys"
        );
        assert!(
            CompactProof::decode(&[9, 0, 0]).is_none(),
            "an unknown scheme"
        );
    }
}
