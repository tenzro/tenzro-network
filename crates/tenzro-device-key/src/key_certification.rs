//! Hardware proof that a signing key lives in a TPM.
//!
//! `TPM2_Certify` has the TPM's restricted attestation key sign a
//! `TPMS_ATTEST` naming the certified key. A restricted key refuses to sign
//! anything that starts with `TPM_GENERATED_VALUE`, so a verifying
//! certification is a statement by the TPM itself that the key is loaded in
//! it. The key's public area then shows it is TPM-generated and cannot leave
//! the chip (`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`).
//!
//! All of that holds only when the attestation key is known to be a TPM's:
//! the attribute bits and the signature are as easy to produce in software
//! as in a TPM. A verifier therefore names the attestation key it trusts,
//! the one admitted for the machine after an endorsement-key check.
//!
//! The Secure Enclave offers no attestation for a key an application
//! creates, so on Apple hardware no certification can be produced and the
//! caller is told so rather than handed a self-signature.

use sha2::{Digest, Sha256};

use crate::tpm_wire::{self, PublicArea, PublicKey};

/// Label of the attestation key template. The same label the machine's
/// admission quote uses, so one attestation key speaks for the machine.
pub const ATTESTATION_KEY_LABEL: &str = "tenzro/tpm/attestation-key";

/// A certification: the attestation key and certified key public areas, the
/// signed `TPMS_ATTEST` and its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCertification {
    /// `TPMT_PUBLIC` of the attestation key.
    pub ak_public: Vec<u8>,
    /// `TPMT_PUBLIC` of the certified key.
    pub key_public: Vec<u8>,
    /// `TPMS_ATTEST` of type certify.
    pub attest: Vec<u8>,
    /// Attestation key's signature over `attest`, raw `r || s`.
    pub signature: Vec<u8>,
}

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn take<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    if input.len() < 4 {
        return Err("certification is truncated".to_string());
    }
    let n = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if input.len() < 4 + n {
        return Err("certification is truncated".to_string());
    }
    let (v, rest) = input[4..].split_at(n);
    *input = rest;
    Ok(v)
}

impl KeyCertification {
    /// Length-prefixed encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [
            &self.ak_public,
            &self.key_public,
            &self.attest,
            &self.signature,
        ] {
            put(&mut out, part);
        }
        out
    }

    /// Decode [`Self::to_bytes`]; returns the rest of the input.
    pub fn from_bytes(mut input: &[u8]) -> Result<(Self, &[u8]), String> {
        let ak_public = take(&mut input)?.to_vec();
        let key_public = take(&mut input)?.to_vec();
        let attest = take(&mut input)?.to_vec();
        let signature = take(&mut input)?.to_vec();
        Ok((
            Self {
                ak_public,
                key_public,
                attest,
                signature,
            },
            input,
        ))
    }

    /// Name of the attestation key, `nameAlg || H(TPMT_PUBLIC)`.
    pub fn ak_name(&self) -> Result<Vec<u8>, String> {
        tpm_wire::parse_public(&self.ak_public)
            .and_then(|a| a.name())
            .map_err(|e| e.to_string())
    }
}

fn sec1(p: &PublicArea) -> Option<[u8; 65]> {
    let xy = p256_point(p)?;
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..].copy_from_slice(&xy);
    Some(out)
}

fn p256_point(p: &PublicArea) -> Option<[u8; 64]> {
    match p.key {
        PublicKey::EccP256 { x, y, scheme } if scheme == tpm_wire::TPM2_ALG_ECDSA => {
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(&x);
            out[32..].copy_from_slice(&y);
            Some(out)
        }
        _ => None,
    }
}

/// Verify that `cert` proves the P-256 key `key_xy` lives in the TPM whose
/// attestation key is `attestation_key` (uncompressed SEC1), and that the TPM
/// certified it over `extra_data`.
///
/// Everything in a certification can be produced in software except a
/// signature by a key the verifier already trusts, so the attestation key is
/// the verifier's to name: one admitted with an endorsement-key check, never
/// the one the certification carries.
pub fn verify(
    cert: &KeyCertification,
    key_xy: &[u8],
    extra_data: &[u8],
    attestation_key: &[u8; 65],
) -> Result<(), String> {
    let key = certified_key(cert, extra_data, attestation_key)?;
    if p256_point(&key).as_ref().map(|p| p.as_slice()) != Some(key_xy) {
        return Err("the certification is for another key".to_string());
    }
    Ok(())
}

/// What a verified certification of an ML-DSA key shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertifiedMlDsaKey {
    /// `TPMI_MLDSA_PARAMETER_SET` of the key.
    pub parameter_set: u16,
    /// Whether the key is restricted: an attestation key, which signs only
    /// digests the TPM itself produced or checked.
    pub attestation_key: bool,
}

/// Verify that `cert` proves the ML-DSA public key `ml_dsa_key` (FIPS 204
/// encoding) lives in the TPM whose attestation key is `attestation_key`,
/// certified over `extra_data`. The key is an ML-DSA object of TPM 2.0
/// library v1.85: generated in the TPM, never leaving it, and with external
/// mu refused, so the TPM signs only messages it is given.
pub fn verify_ml_dsa(
    cert: &KeyCertification,
    ml_dsa_key: &[u8],
    extra_data: &[u8],
    attestation_key: &[u8; 65],
) -> Result<CertifiedMlDsaKey, String> {
    let key = certified_key(cert, extra_data, attestation_key)?;
    let PublicKey::MlDsa {
        parameter_set,
        allow_external_mu,
        key: public,
    } = &key.key
    else {
        return Err("the certified key is not an ML-DSA key".to_string());
    };
    let expected_len = match *parameter_set {
        tpm_wire::TPM2_MLDSA_65 => 1952,
        tpm_wire::TPM2_MLDSA_87 => 2592,
        other => return Err(format!("ML-DSA parameter set {other:#06x} is not admitted")),
    };
    if *allow_external_mu {
        return Err("the certified ML-DSA key signs a caller's mu".to_string());
    }
    if public.len() != expected_len || public.as_slice() != ml_dsa_key {
        return Err("the certification is for another key".to_string());
    }
    Ok(CertifiedMlDsaKey {
        parameter_set: *parameter_set,
        attestation_key: key.attributes & tpm_wire::TPMA_OBJECT_RESTRICTED != 0,
    })
}

/// The certified key of `cert`, once every check but which key it is has
/// passed: the attestation key is `attestation_key`, the certified key is a
/// TPM-generated, non-exportable signing key, and the signed `TPMS_ATTEST`
/// names it over `extra_data`.
fn certified_key(
    cert: &KeyCertification,
    extra_data: &[u8],
    attestation_key: &[u8; 65],
) -> Result<PublicArea, String> {
    use tpm_wire::*;
    let ak = parse_public(&cert.ak_public).map_err(|e| e.to_string())?;
    let needed_ak = TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_RESTRICTED
        | TPMA_OBJECT_SIGN_ENCRYPT;
    if ak.attributes & needed_ak != needed_ak || ak.attributes & TPMA_OBJECT_DECRYPT != 0 {
        return Err("the certifying key is not a restricted TPM attestation key".to_string());
    }
    let ak_sec1 = sec1(&ak).ok_or("the attestation key is not ECDSA P-256")?;
    if ak_sec1 != *attestation_key {
        return Err("the certification is by another attestation key".to_string());
    }

    let key = parse_public(&cert.key_public).map_err(|e| e.to_string())?;
    let needed_key = TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_SENSITIVEDATAORIGIN
        | TPMA_OBJECT_SIGN_ENCRYPT;
    if key.attributes & needed_key != needed_key || key.attributes & TPMA_OBJECT_DECRYPT != 0 {
        return Err(
            "the certified key is not a TPM-generated, non-exportable signing key".to_string(),
        );
    }

    let digest: [u8; 32] = Sha256::digest(&cert.attest).into();
    if !crate::signer::verify_p256_prehash(&ak_sec1, &digest, &cert.signature) {
        return Err("the certification signature does not verify".to_string());
    }
    let info = parse_certify(&cert.attest).map_err(|e| e.to_string())?;
    if info.extra_data != extra_data {
        return Err("the certification was made for another statement".to_string());
    }
    let key_name = key.name().map_err(|e| e.to_string())?;
    if info.name != key_name {
        return Err("the certification names another object".to_string());
    }
    let ak_name = ak.name().map_err(|e| e.to_string())?;
    if info.qualified_signer != endorsement_primary_qualified_name(&ak_name) {
        return Err("the certification was not signed by this attestation key".to_string());
    }
    Ok(key)
}

/// Have this machine's TPM certify the signing key under `label` over
/// `extra_data` (at most 64 bytes). Returns the key's `x || y` and the
/// certification.
#[cfg(any(target_os = "linux", windows))]
pub fn certify_local_key(
    label: &str,
    extra_data: &[u8],
) -> Result<([u8; 64], KeyCertification), String> {
    if extra_data.len() > 64 {
        return Err("a certification carries at most 64 bytes of extra data".to_string());
    }
    // The key and the persistent attestation key, both already in the TPM:
    // a read and one certify, no key generation.
    let ak_handle = tpm_wire::NODE_ATTESTATION_HANDLE;
    let (key, ak, attest, signature) =
        crate::backend_tpm::with_signing_key(label, |dev, key_handle, key| {
            let ak = dev.read_public(ak_handle)?;
            let (attest, signature) = dev.certify(key_handle, ak_handle, extra_data)?;
            Ok((key.clone(), ak, attest, signature))
        })
        .map_err(|e| format!("TPM: {e}"))?;
    let key_xy = p256_point(&key).ok_or("the TPM key is not ECDSA P-256")?;
    let ak_sec1 = sec1(&ak).ok_or("the attestation key is not ECDSA P-256")?;
    let cert = KeyCertification {
        ak_public: ak.raw,
        key_public: key.raw,
        attest,
        signature: signature.to_vec(),
    };
    verify(&cert, &key_xy, extra_data, &ak_sec1)?;
    Ok((key_xy, cert))
}

/// No TPM certification exists without a TPM: the Secure Enclave has no
/// attestation for application keys.
#[cfg(not(any(target_os = "linux", windows)))]
pub fn certify_local_key(
    _label: &str,
    _extra_data: &[u8],
) -> Result<([u8; 64], KeyCertification), String> {
    Err(if cfg!(any(target_os = "macos", target_os = "ios")) {
        "the Secure Enclave offers no attestation for this key, so this machine cannot prove \
         where it lives"
            .to_string()
    } else {
        "key certification needs a TPM 2.0".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use tpm_wire::*;

    fn xy(key: &SigningKey) -> [u8; 64] {
        let point = key.verifying_key().to_sec1_point(false);
        let mut out = [0u8; 64];
        out.copy_from_slice(&point.as_bytes()[1..]);
        out
    }

    fn public(attributes: u32, key: &SigningKey) -> Vec<u8> {
        let p = xy(key);
        let mut w = Writer::new();
        w.u16(TPM2_ALG_ECC).u16(TPM2_ALG_SHA256);
        w.u32(attributes);
        w.tpm2b(&[]);
        w.u16(TPM2_ALG_NULL);
        w.u16(TPM2_ALG_ECDSA).u16(TPM2_ALG_SHA256);
        w.u16(TPM2_ECC_NIST_P256).u16(TPM2_ALG_NULL);
        w.tpm2b(&p[..32]).tpm2b(&p[32..]);
        w.finish()
    }

    /// A certification made entirely in software: an "attestation key" and
    /// a "certified key" whose public areas claim every TPM attribute, and a
    /// `TPMS_ATTEST` signed by that software key.
    fn software_certification(ak: &SigningKey, key: &SigningKey, extra: &[u8]) -> KeyCertification {
        let ak_public = public(ATTESTATION_KEY_ATTRIBUTES, ak);
        let key_public = public(
            TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN
                | TPMA_OBJECT_USERWITHAUTH
                | TPMA_OBJECT_SIGN_ENCRYPT,
            key,
        );
        let ak_name = parse_public(&ak_public).unwrap().name().unwrap();
        let key_name = parse_public(&key_public).unwrap().name().unwrap();
        let mut a = Writer::new();
        a.u32(TPM2_GENERATED_VALUE).u16(TPM2_ST_ATTEST_CERTIFY);
        a.tpm2b(&endorsement_primary_qualified_name(&ak_name));
        a.tpm2b(extra);
        a.bytes(&1u64.to_be_bytes()).u32(0).u32(0).u8(1);
        a.bytes(&1u64.to_be_bytes());
        a.tpm2b(&key_name).tpm2b(&key_name);
        let attest = a.finish();
        let digest: [u8; 32] = Sha256::digest(&attest).into();
        let sig: p256::ecdsa::Signature = ak.sign_prehash(&digest).unwrap();
        KeyCertification {
            ak_public,
            key_public,
            attest,
            signature: sig.to_bytes().to_vec(),
        }
    }

    fn sec1(key: &SigningKey) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..].copy_from_slice(&xy(key));
        out
    }

    /// An ML-DSA public area as a v1.85 TPM reports it, with `attributes`.
    fn ml_dsa_public(
        attributes: u32,
        parameter_set: u16,
        external_mu: bool,
        key: &[u8],
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(TPM2_ALG_MLDSA).u16(TPM2_ALG_SHA256);
        w.u32(attributes);
        w.tpm2b(&[]);
        w.u16(parameter_set);
        w.u8(u8::from(external_mu));
        w.tpm2b(key);
        w.finish()
    }

    fn certify_area(ak: &SigningKey, key_public: Vec<u8>, extra: &[u8]) -> KeyCertification {
        let ak_public = public(ATTESTATION_KEY_ATTRIBUTES, ak);
        let ak_name = parse_public(&ak_public).unwrap().name().unwrap();
        let key_name = parse_public(&key_public).unwrap().name().unwrap();
        let mut a = Writer::new();
        a.u32(TPM2_GENERATED_VALUE).u16(TPM2_ST_ATTEST_CERTIFY);
        a.tpm2b(&endorsement_primary_qualified_name(&ak_name));
        a.tpm2b(extra);
        a.bytes(&1u64.to_be_bytes()).u32(0).u32(0).u8(1);
        a.bytes(&1u64.to_be_bytes());
        a.tpm2b(&key_name).tpm2b(&key_name);
        let attest = a.finish();
        let digest: [u8; 32] = Sha256::digest(&attest).into();
        let sig: p256::ecdsa::Signature = ak.sign_prehash(&digest).unwrap();
        KeyCertification {
            ak_public,
            key_public,
            attest,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// A v1.85 ML-DSA key certified by the trusted attestation key verifies
    /// for exactly that key and statement; a key that would sign a caller's
    /// mu, a duplicable key, an unknown parameter set, a mismatched length
    /// or another attestation key is refused. A restricted key is reported
    /// as an attestation key.
    #[test]
    fn an_ml_dsa_key_certified_by_the_attestation_key_verifies() {
        let ak = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let other = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let key = vec![0x5a; 1952];
        let good = certify_area(
            &ak,
            ml_dsa_public(SIGNING_KEY_ATTRIBUTES, TPM2_MLDSA_65, false, &key),
            b"statement",
        );
        assert_eq!(
            verify_ml_dsa(&good, &key, b"statement", &sec1(&ak)).unwrap(),
            CertifiedMlDsaKey {
                parameter_set: TPM2_MLDSA_65,
                attestation_key: false
            }
        );
        assert!(verify_ml_dsa(&good, &key, b"another statement", &sec1(&ak)).is_err());
        assert!(verify_ml_dsa(&good, &vec![0x5b; 1952], b"statement", &sec1(&ak)).is_err());
        assert!(verify_ml_dsa(&good, &key, b"statement", &sec1(&other)).is_err());
        // The P-256 verifier does not take an ML-DSA certification.
        assert!(verify(&good, &[0u8; 64], b"statement", &sec1(&ak)).is_err());

        let restricted = certify_area(
            &ak,
            ml_dsa_public(ATTESTATION_KEY_ATTRIBUTES, TPM2_MLDSA_65, false, &key),
            b"statement",
        );
        assert!(
            verify_ml_dsa(&restricted, &key, b"statement", &sec1(&ak))
                .unwrap()
                .attestation_key
        );
        let refused = [
            ml_dsa_public(SIGNING_KEY_ATTRIBUTES, TPM2_MLDSA_65, true, &key),
            ml_dsa_public(
                SIGNING_KEY_ATTRIBUTES & !TPMA_OBJECT_FIXEDTPM,
                TPM2_MLDSA_65,
                false,
                &key,
            ),
            ml_dsa_public(SIGNING_KEY_ATTRIBUTES, 0x0001, false, &key),
            ml_dsa_public(SIGNING_KEY_ATTRIBUTES, TPM2_MLDSA_87, false, &key),
        ];
        for area in refused {
            let cert = certify_area(&ak, area, b"statement");
            assert!(verify_ml_dsa(&cert, &key, b"statement", &sec1(&ak)).is_err());
        }
    }

    #[test]
    fn only_the_expected_attestation_key_certifies() {
        let ak = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let other = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let key = SigningKey::from_slice(&[4u8; 32]).unwrap();
        let cert = software_certification(&ak, &key, b"statement");
        assert!(verify(&cert, &xy(&key), b"statement", &sec1(&other)).is_err());
        verify(&cert, &xy(&key), b"statement", &sec1(&ak)).unwrap();
        assert!(verify(&cert, &xy(&key), b"another statement", &sec1(&ak)).is_err());
        assert!(verify(&cert, &xy(&other), b"statement", &sec1(&ak)).is_err());
    }
}
