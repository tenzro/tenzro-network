//! TPM credential protection (TPM 2.0 Part 1, section 24): a secret encrypted
//! to a TPM's endorsement key that the TPM releases only to an object with a
//! given name, through `TPM2_ActivateCredential`. Recovering it proves the
//! object lives in the same TPM as the endorsement key.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

use crate::tpm_wire::{self, PublicArea};
use crate::{DeviceKeyError, Result};

fn fail(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Enclave(msg.into())
}

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

/// A verifier's challenge for credential activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    /// `TPM2B_ID_OBJECT` contents.
    pub blob: Vec<u8>,
    /// `TPM2B_ENCRYPTED_SECRET` contents: the ephemeral ECC point for an
    /// ECC endorsement key, the OAEP ciphertext of the seed for an RSA one.
    pub encrypted_secret: Vec<u8>,
}

/// The endorsement key's name algorithm, which every hash in credential
/// protection uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameHash {
    Sha256,
    Sha384,
}

impl NameHash {
    fn of(alg: u16) -> Result<Self> {
        match alg {
            tpm_wire::TPM2_ALG_SHA256 => Ok(Self::Sha256),
            tpm_wire::TPM2_ALG_SHA384 => Ok(Self::Sha384),
            _ => Err(fail(
                "endorsement key name algorithm is not SHA-256 or SHA-384",
            )),
        }
    }

    /// Digest size in bytes.
    #[allow(clippy::len_without_is_empty)] // a digest size; no hash has an empty one
    pub fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Self::Sha256 => {
                let mut h = Sha256::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            Self::Sha384 => {
                let mut h = Sha384::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
        }
    }

    fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        match self {
            Self::Sha256 => {
                let mut m = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
                parts.iter().for_each(|p| m.update(p));
                m.finalize().into_bytes().to_vec()
            }
            Self::Sha384 => {
                let mut m = HmacSha384::new_from_slice(key).expect("HMAC takes any key length");
                parts.iter().for_each(|p| m.update(p));
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// TPM `KDFa` (SP 800-108 counter mode, HMAC-SHA256).
pub fn kdf_a(key: &[u8], label: &str, context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    kdf_a_with(NameHash::Sha256, key, label, context_u, context_v, bits)
}

/// TPM `KDFa` (SP 800-108 counter mode) with the HMAC of `hash`.
pub fn kdf_a_with(
    hash: NameHash,
    key: &[u8],
    label: &str,
    context_u: &[u8],
    context_v: &[u8],
    bits: u32,
) -> Vec<u8> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::with_capacity(bytes + hash.len());
    let mut counter = 1u32;
    while out.len() < bytes {
        out.extend_from_slice(&hash.hmac(
            key,
            &[
                &counter.to_be_bytes(),
                label.as_bytes(),
                &[0],
                context_u,
                context_v,
                &bits.to_be_bytes(),
            ],
        ));
        counter += 1;
    }
    out.truncate(bytes);
    out
}

/// TPM `KDFe` (SP 800-56A concatenation KDF, SHA-256).
pub fn kdf_e(z: &[u8], usage: &str, party_u: &[u8], party_v: &[u8], bits: u32) -> Vec<u8> {
    kdf_e_with(NameHash::Sha256, z, usage, party_u, party_v, bits)
}

/// TPM `KDFe` (SP 800-56A concatenation KDF) with `hash`.
pub fn kdf_e_with(
    hash: NameHash,
    z: &[u8],
    usage: &str,
    party_u: &[u8],
    party_v: &[u8],
    bits: u32,
) -> Vec<u8> {
    let bytes = bits.div_ceil(8) as usize;
    let mut out = Vec::with_capacity(bytes + hash.len());
    let mut counter = 1u32;
    while out.len() < bytes {
        out.extend_from_slice(&hash.digest(&[
            &counter.to_be_bytes(),
            z,
            usage.as_bytes(),
            &[0],
            party_u,
            party_v,
        ]));
        counter += 1;
    }
    out.truncate(bytes);
    out
}

/// AES-CFB with a zero IV, the mode TPM credential protection uses.
pub fn aes_cfb(key: &[u8], data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    enum Aes {
        A128(Box<aes::Aes128>),
        A256(Box<aes::Aes256>),
    }
    let cipher = match key.len() {
        16 => Aes::A128(Box::new(aes::Aes128::new(GenericArray::from_slice(key)))),
        32 => Aes::A256(Box::new(aes::Aes256::new(GenericArray::from_slice(key)))),
        n => return Err(fail(format!("unsupported AES key length {n}"))),
    };
    let mut feedback = [0u8; 16];
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut block = GenericArray::clone_from_slice(&feedback);
        match &cipher {
            Aes::A128(c) => c.encrypt_block(&mut block),
            Aes::A256(c) => c.encrypt_block(&mut block),
        }
        let start = out.len();
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ block[i]);
        }
        let ciphertext = if encrypt { &out[start..] } else { chunk };
        feedback = [0u8; 16];
        feedback[..ciphertext.len()].copy_from_slice(ciphertext);
    }
    Ok(out)
}

/// The public key of an endorsement key, by type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndorsementPublic {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    Rsa(rsa::RsaPublicKey),
}

/// An endorsement key checked to be TCG-shaped: its public key, its name
/// algorithm and the size of its symmetric (AES-CFB) key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndorsementKey {
    pub public: EndorsementPublic,
    pub hash: NameHash,
    pub sym_bytes: usize,
}

/// The RSA public exponent a TPM means by 0.
const RSA_DEFAULT_EXPONENT: u32 = 65_537;

/// Check that a public area is a TCG-shaped endorsement key (ECC P-256,
/// ECC P-384, RSA-2048 or RSA-3072) and return its key.
pub fn endorsement_key(ek: &PublicArea) -> Result<EndorsementKey> {
    use tpm_wire::*;
    let needed = TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_DECRYPT;
    if ek.attributes & needed != needed || ek.attributes & TPMA_OBJECT_SIGN_ENCRYPT != 0 {
        return Err(fail("endorsement key attributes are not those of an EK"));
    }
    let hash = NameHash::of(ek.name_alg)?;
    let sym_bytes = match ek.symmetric {
        Some((TPM2_ALG_AES, bits, TPM2_ALG_CFB)) if bits == 128 || bits == 256 => bits as usize / 8,
        _ => return Err(fail("endorsement key symmetric scheme is not AES-CFB")),
    };
    let public = match &ek.key {
        PublicKey::EccP256 { .. } => {
            let sec1 = ek.p256_sec1().ok_or_else(|| fail("P-256 point"))?;
            EndorsementPublic::P256(
                p256::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| fail("endorsement key point is not on P-256"))?,
            )
        }
        PublicKey::EccP384 { .. } => {
            let sec1 = ek.p384_sec1().ok_or_else(|| fail("P-384 point"))?;
            EndorsementPublic::P384(
                p384::PublicKey::from_sec1_bytes(&sec1)
                    .map_err(|_| fail("endorsement key point is not on P-384"))?,
            )
        }
        PublicKey::MlDsa { .. } => {
            return Err(fail("an endorsement key is ECC or RSA, not ML-DSA"));
        }
        PublicKey::Rsa { modulus, exponent } => {
            if modulus.len() != 256 && modulus.len() != 384 {
                return Err(fail("an RSA endorsement key must be RSA-2048 or RSA-3072"));
            }
            let e = if *exponent == 0 {
                RSA_DEFAULT_EXPONENT
            } else {
                *exponent
            };
            EndorsementPublic::Rsa(
                rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(modulus), rsa::BigUint::from(e))
                    .map_err(|e| fail(format!("RSA endorsement key: {e}")))?,
            )
        }
    };
    Ok(EndorsementKey {
        public,
        hash,
        sym_bytes,
    })
}

/// The OAEP label TPM credential protection uses, NUL included.
const IDENTITY_LABEL: &str = "IDENTITY\0";

/// Encrypt `secret` to the endorsement key `ek`, releasable only to the
/// object named `ak_name` in the same TPM (TPM2_MakeCredential, done by the
/// verifier in software). For an ECC key the seed is agreed with an
/// ephemeral key (KDFe); for an RSA key it is random and travels under
/// RSA-OAEP. Either way only the TPM holding the endorsement key's private
/// half recovers it.
pub fn make_credential(ek: &PublicArea, ak_name: &[u8], secret: &[u8]) -> Result<Credential> {
    let key = endorsement_key(ek)?;
    let hash = key.hash;
    if secret.is_empty() || secret.len() > hash.len() {
        return Err(fail(format!(
            "credential secret must be 1 to {} bytes",
            hash.len()
        )));
    }
    let bits = (hash.len() * 8) as u32;
    let (seed, encrypted_secret) = match &key.public {
        EndorsementPublic::P256(ek_point) => {
            let eph = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
            let eph_point = p256::PublicKey::from(&eph).to_sec1_bytes();
            let z = eph.diffie_hellman(ek_point);
            let ek_sec1 = ek_point.to_sec1_bytes();
            let seed = kdf_e_with(
                hash,
                z.raw_secret_bytes().as_slice(),
                "IDENTITY",
                &eph_point[1..33],
                &ek_sec1[1..33],
                bits,
            );
            (seed, ecc_point(&eph_point[1..33], &eph_point[33..65]))
        }
        EndorsementPublic::P384(ek_point) => {
            let eph = <p384::ecdh::EphemeralSecret as p384::elliptic_curve::Generate>::generate();
            let eph_point = p384::PublicKey::from(&eph).to_sec1_bytes();
            let z = eph.diffie_hellman(ek_point);
            let ek_sec1 = ek_point.to_sec1_bytes();
            let seed = kdf_e_with(
                hash,
                z.raw_secret_bytes().as_slice(),
                "IDENTITY",
                &eph_point[1..49],
                &ek_sec1[1..49],
                bits,
            );
            (seed, ecc_point(&eph_point[1..49], &eph_point[49..97]))
        }
        EndorsementPublic::Rsa(pk) => {
            let mut seed = vec![0u8; hash.len()];
            use rand::RngCore;
            rand::rngs::OsRng
                .try_fill_bytes(&mut seed)
                .map_err(|e| fail(format!("OS RNG: {e}")))?;
            let padding = match hash {
                NameHash::Sha256 => rsa::Oaep::new_with_label::<sha2::Sha256, _>(IDENTITY_LABEL),
                NameHash::Sha384 => rsa::Oaep::new_with_label::<sha2::Sha384, _>(IDENTITY_LABEL),
            };
            let encrypted = pk
                .encrypt(&mut rand::rngs::OsRng, padding, &seed)
                .map_err(|e| fail(format!("RSA-OAEP: {e}")))?;
            (seed, encrypted)
        }
    };
    Ok(Credential {
        blob: wrap_credential(hash, &seed, key.sym_bytes, ak_name, secret)?,
        encrypted_secret,
    })
}

/// `TPMS_ECC_POINT` contents.
fn ecc_point(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut w = tpm_wire::Writer::new();
    w.tpm2b(x);
    w.tpm2b(y);
    w.finish()
}

/// The symmetric part of credential protection (TPM 2.0 Part 1, 24.4 and
/// 24.5): the secret encrypted under a key derived from the seed and the
/// object's name, then an integrity HMAC over the ciphertext and the name.
fn wrap_credential(
    hash: NameHash,
    seed: &[u8],
    sym_bytes: usize,
    ak_name: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>> {
    let sym_key = kdf_a_with(hash, seed, "STORAGE", ak_name, &[], (sym_bytes * 8) as u32);
    let mut plain = tpm_wire::Writer::new();
    plain.tpm2b(secret);
    let enc_identity = aes_cfb(&sym_key, &plain.finish(), true)?;
    let hmac_key = kdf_a_with(hash, seed, "INTEGRITY", &[], &[], (hash.len() * 8) as u32);
    let mut blob = tpm_wire::Writer::new();
    blob.tpm2b(&hash.hmac(&hmac_key, &[&enc_identity, ak_name]));
    blob.bytes(&enc_identity);
    Ok(blob.finish())
}

/// The other half of [`wrap_credential`], as `TPM2_ActivateCredential` runs
/// it once the seed is recovered: check the integrity HMAC against the name
/// of the object actually loaded, then decrypt.
#[cfg(test)]
fn unwrap_credential(
    hash: NameHash,
    seed: &[u8],
    sym_bytes: usize,
    loaded_name: &[u8],
    blob: &[u8],
) -> Option<Vec<u8>> {
    use subtle::ConstantTimeEq;
    let mut b = tpm_wire::Reader::new(blob);
    let mac = b.tpm2b().ok()?.to_vec();
    let enc_identity = b.take(b.remaining()).ok()?.to_vec();
    let hmac_key = kdf_a_with(hash, seed, "INTEGRITY", &[], &[], (hash.len() * 8) as u32);
    let expected = hash.hmac(&hmac_key, &[&enc_identity, loaded_name]);
    if !bool::from(expected.ct_eq(&mac)) {
        return None;
    }
    let sym = kdf_a_with(
        hash,
        seed,
        "STORAGE",
        loaded_name,
        &[],
        (sym_bytes * 8) as u32,
    );
    let plain = aes_cfb(&sym, &enc_identity, false).ok()?;
    Some(tpm_wire::Reader::new(&plain).tpm2b().ok()?.to_vec())
}

/// An endorsement key's private half held in memory, standing in for a TPM
/// in tests: `TPM2_ActivateCredential` done in software.
#[cfg(test)]
pub(crate) enum SoftEndorsement {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    Rsa(rsa::RsaPrivateKey, NameHash),
}

#[cfg(test)]
impl SoftEndorsement {
    /// Release the credential's secret if `loaded_name` is the object it was
    /// made for, as the TPM holding this endorsement key would.
    pub(crate) fn activate(
        &self,
        ek: &PublicArea,
        loaded_name: &[u8],
        cred: &Credential,
    ) -> Option<Vec<u8>> {
        let key = endorsement_key(ek).ok()?;
        let hash = key.hash;
        let bits = (hash.len() * 8) as u32;
        let seed = match self {
            Self::P256(sk) => {
                let mut r = tpm_wire::Reader::new(&cred.encrypted_secret);
                let (ex, ey) = (r.tpm2b().ok()?.to_vec(), r.tpm2b().ok()?.to_vec());
                let eph =
                    p256::PublicKey::from_sec1_bytes(&[&[4u8][..], &ex, &ey].concat()).ok()?;
                let z = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), eph.as_affine());
                let ekx = sk.public_key().to_sec1_bytes()[1..33].to_vec();
                kdf_e_with(
                    hash,
                    z.raw_secret_bytes().as_slice(),
                    "IDENTITY",
                    &ex,
                    &ekx,
                    bits,
                )
            }
            Self::P384(sk) => {
                let mut r = tpm_wire::Reader::new(&cred.encrypted_secret);
                let (ex, ey) = (r.tpm2b().ok()?.to_vec(), r.tpm2b().ok()?.to_vec());
                let eph =
                    p384::PublicKey::from_sec1_bytes(&[&[4u8][..], &ex, &ey].concat()).ok()?;
                let z = p384::ecdh::diffie_hellman(sk.to_nonzero_scalar(), eph.as_affine());
                let ekx = sk.public_key().to_sec1_bytes()[1..49].to_vec();
                kdf_e_with(
                    hash,
                    z.raw_secret_bytes().as_slice(),
                    "IDENTITY",
                    &ex,
                    &ekx,
                    bits,
                )
            }
            Self::Rsa(sk, h) => {
                let padding = match h {
                    NameHash::Sha256 => {
                        rsa::Oaep::new_with_label::<sha2::Sha256, _>(IDENTITY_LABEL)
                    }
                    NameHash::Sha384 => {
                        rsa::Oaep::new_with_label::<sha2::Sha384, _>(IDENTITY_LABEL)
                    }
                };
                sk.decrypt(padding, &cred.encrypted_secret).ok()?
            }
        };
        unwrap_credential(hash, &seed, key.sym_bytes, loaded_name, &cred.blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm_wire::*;

    fn ak_name(seed: u8) -> Vec<u8> {
        let mut n = TPM2_ALG_SHA256.to_be_bytes().to_vec();
        n.extend_from_slice(&[seed; 32]);
        n
    }

    fn with_unique(template: Vec<u8>, unique: &[&[u8]]) -> Vec<u8> {
        // The templates end with the unique field(s); replace them with the
        // generated key.
        let parsed = parse_public(&template).unwrap();
        let empty_len: usize = match parsed.key {
            PublicKey::Rsa { ref modulus, .. } => 2 + modulus.len(),
            PublicKey::EccP256 { .. } => 2 + 32 + 2 + 32,
            PublicKey::EccP384 { .. } => 4,
            PublicKey::MlDsa { .. } => unreachable!("endorsement templates are ECC or RSA"),
        };
        let mut out = template[..template.len() - empty_len].to_vec();
        let mut w = Writer::new();
        for u in unique {
            w.tpm2b(u);
        }
        out.extend_from_slice(&w.finish());
        out
    }

    fn p256_ek(seed: u8) -> (SoftEndorsement, PublicArea) {
        let sk = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
        let sec1 = sk.public_key().to_sec1_bytes();
        let ek = parse_public(&with_unique(
            ek_ecc_template(),
            &[&sec1[1..33], &sec1[33..]],
        ))
        .unwrap();
        (SoftEndorsement::P256(sk), ek)
    }

    fn p384_ek(seed: u8) -> (SoftEndorsement, PublicArea) {
        let sk = p384::SecretKey::from_slice(&[seed; 48]).unwrap();
        let sec1 = sk.public_key().to_sec1_bytes();
        let ek = parse_public(&with_unique(
            ek_ecc_p384_template(),
            &[&sec1[1..49], &sec1[49..]],
        ))
        .unwrap();
        (SoftEndorsement::P384(sk), ek)
    }

    fn rsa_ek(bits: usize, seed: u64) -> (SoftEndorsement, PublicArea) {
        use rand::SeedableRng;
        use rsa::traits::PublicKeyParts;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let sk = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
        let n = sk.n().to_bytes_be();
        let (template, hash) = if bits == 2048 {
            (ek_rsa2048_template(), NameHash::Sha256)
        } else {
            (ek_rsa3072_template(), NameHash::Sha384)
        };
        let ek = parse_public(&with_unique(template, &[&n])).unwrap();
        (SoftEndorsement::Rsa(sk, hash), ek)
    }

    fn round_trip(soft: &SoftEndorsement, ek: &PublicArea) {
        let secret = [7u8; 32];
        let cred = make_credential(ek, &ak_name(1), &secret).unwrap();
        assert_eq!(soft.activate(ek, &ak_name(1), &cred).unwrap(), secret);
        // Released only to the object the credential names.
        assert!(soft.activate(ek, &ak_name(2), &cred).is_none());
    }

    #[test]
    fn credentials_activate_for_every_endorsement_key_type() {
        let (soft, ek) = p256_ek(3);
        round_trip(&soft, &ek);
        let (soft, ek) = p384_ek(4);
        assert_eq!(endorsement_key(&ek).unwrap().hash, NameHash::Sha384);
        assert_eq!(endorsement_key(&ek).unwrap().sym_bytes, 32);
        round_trip(&soft, &ek);
        let (soft, ek) = rsa_ek(2048, 5);
        round_trip(&soft, &ek);
        let (soft, ek) = rsa_ek(3072, 6);
        assert_eq!(endorsement_key(&ek).unwrap().hash, NameHash::Sha384);
        round_trip(&soft, &ek);
    }

    #[test]
    fn a_credential_for_one_endorsement_key_is_not_released_by_another() {
        let secret = [9u8; 32];
        let pairs = [
            (p256_ek(3), p256_ek(8)),
            (p384_ek(4), p384_ek(9)),
            (rsa_ek(2048, 5), rsa_ek(2048, 10)),
        ];
        for ((_, ek_a), (soft_b, ek_b)) in pairs {
            let cred = make_credential(&ek_a, &ak_name(1), &secret).unwrap();
            assert_ne!(
                soft_b.activate(&ek_b, &ak_name(1), &cred),
                Some(secret.to_vec())
            );
        }
    }

    #[test]
    fn an_endorsement_key_of_another_shape_is_refused() {
        // A signing key is not an endorsement key, whatever its curve.
        let (_, mut ek) = p384_ek(4);
        ek.attributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        assert!(endorsement_key(&ek).is_err());
        // RSA-1024 is too weak to stand for a TPM.
        let mut raw = Writer::new();
        raw.u16(TPM2_ALG_RSA)
            .u16(TPM2_ALG_SHA256)
            .u32(EK_LOW_RANGE_ATTRIBUTES);
        raw.tpm2b(&EK_POLICY)
            .u16(TPM2_ALG_AES)
            .u16(128)
            .u16(TPM2_ALG_CFB);
        raw.u16(TPM2_ALG_NULL).u16(1024).u32(0).tpm2b(&[0xC5; 128]);
        let weak = parse_public(&raw.finish()).unwrap();
        assert!(make_credential(&weak, &ak_name(1), &[1; 32]).is_err());
    }
}
