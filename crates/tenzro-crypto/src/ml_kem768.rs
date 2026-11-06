//! ML-KEM-768 (FIPS 203) key encapsulation with ephemeral keys.
//!
//! The consensus channel handshake and the hybrid seal
//! ([`crate::hybrid_seal`]) both use it the same way: one side makes a fresh
//! decapsulation key for a single exchange, sends the encapsulation key, and
//! drops the private key once it has decapsulated the peer's ciphertext. The
//! key is never stored or reused.
//!
//! Every operation runs in two implementations: the formally verified
//! `libcrux-ml-kem`, whose result is used, and RustCrypto `ml-kem`, which
//! must produce the same bytes. Keys come from a 64-byte seed and
//! encapsulation from a 32-byte message, both from the OS random source, so
//! the two are given identical inputs and must give identical outputs: the
//! same encapsulation key from a seed, the same ciphertext and secret from a
//! key and message, the same secret from a ciphertext (implicit rejection
//! included), and the same verdict on a malformed encapsulation key. When
//! they differ the exchange is refused and the event logged: a secret one
//! implementation derives and the other does not is a bug in one of them,
//! and a key derived from it is not one both builds would agree on.

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{B32, Ciphertext, EncapsulationKey, MlKem768, Seed};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CryptoError, Result};

/// Encapsulation key length (FIPS 203, ML-KEM-768).
pub const ML_KEM_768_EK_LEN: usize = 1184;
/// Ciphertext length (FIPS 203, ML-KEM-768).
pub const ML_KEM_768_CT_LEN: usize = 1088;
/// Shared secret length.
pub const ML_KEM_SS_LEN: usize = 32;
/// Key generation seed length (`d || z`).
pub const SEED_LEN: usize = 64;
/// Encapsulation randomness length.
const MESSAGE_LEN: usize = 32;

type EncapsulationKeyBytes = [u8; ML_KEM_768_EK_LEN];
type CiphertextBytes = [u8; ML_KEM_768_CT_LEN];
type Secret = [u8; ML_KEM_SS_LEN];

/// One ML-KEM-768 implementation, as the three FIPS 203 operations on
/// byte strings.
#[derive(Clone, Copy)]
pub(crate) struct Implementation {
    name: &'static str,
    /// The encapsulation key of the key pair derived from a seed.
    public: fn(&[u8; SEED_LEN]) -> EncapsulationKeyBytes,
    /// The secret a ciphertext carries to the key pair derived from a seed.
    decapsulate: fn(&[u8; SEED_LEN], &CiphertextBytes) -> Secret,
    /// The ciphertext and secret for a key and message; `None` when the
    /// key is refused (a coefficient not reduced modulo q).
    encapsulate:
        fn(&EncapsulationKeyBytes, &[u8; MESSAGE_LEN]) -> Option<(CiphertextBytes, Secret)>,
}

/// `libcrux-ml-kem`, the implementation whose results are used.
pub(crate) const LIBCRUX: Implementation = Implementation {
    name: "libcrux",
    public: |seed| {
        let pair = libcrux_ml_kem::mlkem768::generate_key_pair(*seed);
        *pair.pk()
    },
    decapsulate: |seed, ct| {
        let pair = libcrux_ml_kem::mlkem768::generate_key_pair(*seed);
        let ct = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(*ct);
        libcrux_ml_kem::mlkem768::decapsulate(pair.private_key(), &ct)
    },
    encapsulate: |ek, m| {
        let ek = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(*ek);
        if !libcrux_ml_kem::mlkem768::validate_public_key(&ek) {
            return None;
        }
        let (ct, ss) = libcrux_ml_kem::mlkem768::encapsulate(&ek, *m);
        Some((*ct.as_slice(), ss))
    },
};

/// RustCrypto `ml-kem`, the implementation every result is checked against.
pub(crate) const RUSTCRYPTO: Implementation = Implementation {
    name: "rustcrypto",
    public: |seed| {
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
        let mut out = [0u8; ML_KEM_768_EK_LEN];
        out.copy_from_slice(&dk.encapsulation_key().to_bytes());
        out
    },
    decapsulate: |seed, ct| {
        let dk = ml_kem::DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
        let mut c: Ciphertext<MlKem768> = Default::default();
        AsMut::<[u8]>::as_mut(&mut c).copy_from_slice(ct);
        let mut out = [0u8; ML_KEM_SS_LEN];
        out.copy_from_slice(dk.decapsulate(&c).as_slice());
        out
    },
    encapsulate: |ek, m| {
        let ek = EncapsulationKey::<MlKem768>::new(&(*ek).into()).ok()?;
        let (ct, ss) = ek.encapsulate_deterministic(&B32::from(*m));
        let (mut c, mut s) = ([0u8; ML_KEM_768_CT_LEN], [0u8; ML_KEM_SS_LEN]);
        c.copy_from_slice(ct.as_slice());
        s.copy_from_slice(ss.as_slice());
        Some((c, s))
    },
};

/// The implementation whose results are used and the one that checks it.
#[derive(Clone, Copy)]
pub(crate) struct Implementations {
    pub(crate) primary: Implementation,
    pub(crate) second: Implementation,
}

impl Default for Implementations {
    fn default() -> Self {
        Self {
            primary: LIBCRUX,
            second: RUSTCRYPTO,
        }
    }
}

fn disagreement(op: &str, i: &Implementations) -> CryptoError {
    tracing::error!(
        operation = op,
        primary = i.primary.name,
        second = i.second.name,
        "ML-KEM-768 implementations disagree; the exchange is refused"
    );
    CryptoError::Other(format!(
        "ML-KEM-768 implementations disagree on {op}; the exchange is refused"
    ))
}

/// An ephemeral ML-KEM-768 decapsulation key for one exchange.
pub struct EphemeralKem {
    seed: Zeroizing<[u8; SEED_LEN]>,
    encapsulation_key: Vec<u8>,
    implementations: Implementations,
    /// Whether both implementations derived the same encapsulation key from
    /// the seed. When not, every decapsulation is refused.
    keys_agree: bool,
}

impl EphemeralKem {
    /// A fresh key pair from the OS random source.
    pub fn generate() -> Self {
        Self::generate_with(Implementations::default())
    }

    fn generate_with(implementations: Implementations) -> Self {
        let mut seed = crate::rng::random_array::<SEED_LEN>();
        let kem = Self::from_seed(&seed, implementations);
        seed.zeroize();
        kem
    }

    /// The key pair FIPS 203 derives from the 64-byte `seed` (`d || z`), for
    /// a key derived on demand from hardware rather than made at random.
    pub fn from_seed_bytes(seed: &[u8; SEED_LEN]) -> Self {
        Self::from_seed(seed, Implementations::default())
    }

    /// The key pair FIPS 203 derives from `seed` (`d || z`).
    fn from_seed(seed: &[u8; SEED_LEN], implementations: Implementations) -> Self {
        let ek = (implementations.primary.public)(seed);
        let keys_agree = ek == (implementations.second.public)(seed);
        if !keys_agree {
            let _ = disagreement("key generation", &implementations);
        }
        Self {
            seed: Zeroizing::new(*seed),
            encapsulation_key: ek.to_vec(),
            implementations,
            keys_agree,
        }
    }

    /// The encapsulation key, sent to the peer.
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.encapsulation_key
    }

    /// The shared secret a peer's ciphertext carries.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; ML_KEM_SS_LEN]> {
        let ct: &CiphertextBytes = ciphertext.try_into().map_err(|_| {
            CryptoError::Other(format!(
                "ML-KEM-768 ciphertext must be {ML_KEM_768_CT_LEN} bytes, got {}",
                ciphertext.len()
            ))
        })?;
        let i = &self.implementations;
        if !self.keys_agree {
            return Err(disagreement("key generation", i));
        }
        let secret = Zeroizing::new((i.primary.decapsulate)(&self.seed, ct));
        let check = Zeroizing::new((i.second.decapsulate)(&self.seed, ct));
        if *secret != *check {
            return Err(disagreement("decapsulation", i));
        }
        Ok(*secret)
    }
}

/// Encapsulates a fresh shared secret to `encapsulation_key`: the ciphertext
/// for the peer, and the secret.
pub fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, [u8; ML_KEM_SS_LEN])> {
    let mut m = crate::rng::random_array::<MESSAGE_LEN>();
    let out = encapsulate_with(encapsulation_key, &m, &Implementations::default());
    m.zeroize();
    out
}

/// Encapsulation with the randomness `m` given.
fn encapsulate_with(
    encapsulation_key: &[u8],
    m: &[u8; MESSAGE_LEN],
    i: &Implementations,
) -> Result<(Vec<u8>, [u8; ML_KEM_SS_LEN])> {
    let ek: &EncapsulationKeyBytes = encapsulation_key.try_into().map_err(|_| {
        CryptoError::Other(format!(
            "ML-KEM-768 encapsulation key must be {ML_KEM_768_EK_LEN} bytes, got {}",
            encapsulation_key.len()
        ))
    })?;
    let out = (i.primary.encapsulate)(ek, m);
    if out != (i.second.encapsulate)(ek, m) {
        return Err(disagreement("encapsulation", i));
    }
    let (ct, ss) = out.ok_or_else(|| {
        CryptoError::Other(
            "ML-KEM-768 encapsulation key does not decode: a coefficient is not reduced modulo q"
                .to_string(),
        )
    })?;
    Ok((ct.to_vec(), ss))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree_on_the_secret_and_nobody_else_does() {
        let a = EphemeralKem::generate();
        let b = EphemeralKem::generate();
        assert_eq!(a.encapsulation_key().len(), ML_KEM_768_EK_LEN);
        let (ct, secret) = encapsulate(a.encapsulation_key()).unwrap();
        assert_eq!(ct.len(), ML_KEM_768_CT_LEN);
        assert_eq!(a.decapsulate(&ct).unwrap(), secret);
        assert_ne!(b.decapsulate(&ct).unwrap(), secret);
    }

    #[test]
    fn malformed_inputs_are_refused() {
        assert!(encapsulate(&[0u8; 100]).is_err());
        assert!(EphemeralKem::generate().decapsulate(&[0u8; 10]).is_err());
    }

    /// The secret an exchange uses comes from libcrux.
    #[test]
    fn the_secret_is_libcrux_s() {
        let seed = [7u8; SEED_LEN];
        let kem = EphemeralKem::from_seed(&seed, Implementations::default());
        let pair = libcrux_ml_kem::mlkem768::generate_key_pair(seed);
        assert_eq!(kem.encapsulation_key(), pair.pk().as_slice());
        let (ct, ss) = encapsulate(kem.encapsulation_key()).unwrap();
        let ct = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::try_from(ct.as_slice()).unwrap();
        assert_eq!(
            libcrux_ml_kem::mlkem768::decapsulate(pair.private_key(), &ct),
            ss
        );
    }

    /// A second implementation that differs in one operation: every
    /// exchange step that reaches that operation is refused.
    #[test]
    fn a_disagreeing_implementation_refuses_the_exchange() {
        let mut wrong_secret = RUSTCRYPTO;
        wrong_secret.decapsulate = |seed, ct| {
            let mut s = (RUSTCRYPTO.decapsulate)(seed, ct);
            s[0] ^= 1;
            s
        };
        let mut wrong_key = RUSTCRYPTO;
        wrong_key.public = |seed| {
            let mut ek = (RUSTCRYPTO.public)(seed);
            ek[0] ^= 1;
            ek
        };
        let mut wrong_ct = RUSTCRYPTO;
        wrong_ct.encapsulate = |ek, m| {
            let (mut c, s) = (RUSTCRYPTO.encapsulate)(ek, m)?;
            c[0] ^= 1;
            Some((c, s))
        };
        let mut accepts_any_key = RUSTCRYPTO;
        accepts_any_key.encapsulate = |_, m| Some(([0u8; ML_KEM_768_CT_LEN], *m));
        let with = |second| Implementations {
            primary: LIBCRUX,
            second,
        };

        let honest = EphemeralKem::generate();
        let (ct, _) = encapsulate(honest.encapsulation_key()).unwrap();
        let m = [3u8; MESSAGE_LEN];

        let kem = EphemeralKem::generate_with(with(wrong_secret));
        let (ct2, _) = encapsulate(kem.encapsulation_key()).unwrap();
        assert!(kem.decapsulate(&ct2).is_err());
        assert!(
            EphemeralKem::generate_with(with(wrong_key))
                .decapsulate(&ct)
                .is_err()
        );
        assert!(encapsulate_with(honest.encapsulation_key(), &m, &with(wrong_ct)).is_err());
        // An encapsulation key with a coefficient of 0xFFF (not reduced
        // modulo q) is refused by libcrux; a second implementation that
        // accepts it is a disagreement too.
        let unreduced = [0xffu8; ML_KEM_768_EK_LEN];
        assert!(encapsulate_with(&unreduced, &m, &Implementations::default()).is_err());
        assert!(encapsulate_with(&unreduced, &m, &with(accepts_any_key)).is_err());
        // The honest pair accepts what the planted ones refused.
        assert!(
            encapsulate_with(honest.encapsulation_key(), &m, &Implementations::default()).is_ok()
        );
        assert!(honest.decapsulate(&ct).is_ok());
    }

    /// Every test of a Wycheproof file (C2SP/wycheproof, `testvectors_v1`).
    fn vectors(name: &str) -> Vec<serde_json::Value> {
        let path = format!("{}/testdata/wycheproof/{name}", env!("CARGO_MANIFEST_DIR"));
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let tests: Vec<_> = file["testGroups"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| g["tests"].as_array().unwrap().clone())
            .collect();
        assert!(!tests.is_empty(), "{path}: no vectors");
        tests
    }

    fn hex_field(t: &serde_json::Value, key: &str) -> Vec<u8> {
        hex::decode(t[key].as_str().unwrap_or_default()).unwrap()
    }

    /// `mlkem_768_test`: key generation from the seed, then decapsulation,
    /// in each implementation alone and through the pair. A valid case
    /// yields the key pair's encapsulation key and the shared secret `K`
    /// (implicit rejection included); an invalid one (a seed or ciphertext of
    /// the wrong length) is refused.
    #[test]
    fn decapsulation_matches_the_wycheproof_vectors() {
        let mut failures = Vec::new();
        let only = |imp| Implementations {
            primary: imp,
            second: imp,
        };
        for t in vectors("mlkem_768_test.json") {
            let (seed, c) = (hex_field(&t, "seed"), hex_field(&t, "c"));
            for (name, imp) in [
                ("pair", Implementations::default()),
                ("libcrux", only(LIBCRUX)),
                ("rustcrypto", only(RUSTCRYPTO)),
            ] {
                let got = <[u8; SEED_LEN]>::try_from(seed.as_slice())
                    .ok()
                    .map(|s| EphemeralKem::from_seed(&s, imp))
                    .and_then(|k| {
                        let ss = k.decapsulate(&c).ok()?;
                        Some((k.encapsulation_key().to_vec(), ss.to_vec()))
                    });
                let ok = match t["result"].as_str() {
                    Some("valid") => got == Some((hex_field(&t, "ek"), hex_field(&t, "K"))),
                    _ => got.is_none(),
                };
                if !ok {
                    failures.push(format!("tc {} {name}", t["tcId"]));
                }
            }
        }
        assert!(failures.is_empty(), "wrong verdict: {failures:?}");
    }

    /// `mlkem_768_encaps_test`: encapsulation to `ek` with the randomness
    /// `m`, in each implementation alone and through the pair. A valid case
    /// yields the ciphertext and shared secret; an invalid key (a
    /// coefficient not reduced modulo q, or the wrong length) is refused.
    #[test]
    fn encapsulation_matches_the_wycheproof_vectors() {
        let mut failures = Vec::new();
        let only = |imp| Implementations {
            primary: imp,
            second: imp,
        };
        for t in vectors("mlkem_768_encaps_test.json") {
            let m: [u8; MESSAGE_LEN] = hex_field(&t, "m").try_into().unwrap();
            for (name, imp) in [
                ("pair", Implementations::default()),
                ("libcrux", only(LIBCRUX)),
                ("rustcrypto", only(RUSTCRYPTO)),
            ] {
                let got = encapsulate_with(&hex_field(&t, "ek"), &m, &imp)
                    .ok()
                    .map(|(c, k)| (c, k.to_vec()));
                let ok = match t["result"].as_str() {
                    Some("valid") => got == Some((hex_field(&t, "c"), hex_field(&t, "K"))),
                    _ => got.is_none(),
                };
                if !ok {
                    failures.push(format!("tc {} {name}", t["tcId"]));
                }
            }
        }
        assert!(failures.is_empty(), "wrong verdict: {failures:?}");
    }
}
