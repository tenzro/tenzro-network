//! Binding a confidential VM's attestation to the facility it runs in.
//!
//! A TEE report proves which code runs on which chip. It says nothing about
//! where the chip is, and physical access to the memory bus is what defeats
//! TDX and SEV-SNP. A facility claim closes that gap with evidence the
//! operator can be held to:
//!
//! - the facility is identified by a hardware key (TPM or Secure Enclave, via
//!   `tenzro_device_key::signer`) that signs a [`FacilityClaim`] naming the
//!   facility and its region;
//! - the TEE report's user data commits to that signed claim together with
//!   the verifier's nonce ([`bound_packet`]), so the claim is part of what the
//!   vendor-signed report attests;
//! - the attestation transparency log records which facility each chip was
//!   first seen in, so a chip later presented from a different facility is a
//!   provable contradiction ([`super::transparency`]).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::fail;
use crate::error::Result;

/// A facility's statement about itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacilityClaim {
    /// Stable facility identifier (the facility operator's choice).
    pub facility_id: String,
    /// Coarse location, e.g. an ISO 3166-2 region code.
    pub region: String,
    /// Uncompressed SEC1 P-256 key of the facility's hardware signer.
    pub facility_key: Vec<u8>,
}

impl FacilityClaim {
    /// The bytes the facility signs: length-prefixed fields under a domain tag.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = b"tenzro/facility-claim/v1\0".to_vec();
        for f in [
            self.facility_id.as_bytes(),
            self.region.as_bytes(),
            &self.facility_key,
        ] {
            out.extend_from_slice(&(f.len() as u32).to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }
}

/// A claim with the facility key's signature over it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFacilityClaim {
    pub claim: FacilityClaim,
    /// Raw `r || s` ECDSA-P256 over SHA-256 of [`FacilityClaim::signing_bytes`].
    pub signature: Vec<u8>,
}

impl SignedFacilityClaim {
    /// Check the facility key signed this claim.
    pub fn verify(&self) -> Result<()> {
        if tenzro_device_key::signer::verify_p256(
            &self.claim.facility_key,
            &self.claim.signing_bytes(),
            &self.signature,
        ) {
            Ok(())
        } else {
            Err(fail("facility claim is not signed by the facility key"))
        }
    }

    /// Digest of the signed claim, as committed into a report.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.claim.signing_bytes());
        h.update(&self.signature);
        h.finalize().into()
    }
}

/// The packet a report's user data must commit to when it binds `facility`:
/// the verifier nonce, the signed claim and the attester's own subject (for
/// example the key it wants certified). Pack it for the vendor with
/// [`tenzro_types::tee::pack_user_data_for_vendor`].
pub fn bound_packet(
    nonce: &[u8; 32],
    facility: &SignedFacilityClaim,
    subject: &[u8],
) -> Result<Vec<u8>> {
    facility.verify()?;
    let mut out = b"tenzro/facility-bound-attestation/v1\0".to_vec();
    out.extend_from_slice(nonce);
    out.extend_from_slice(&facility.digest());
    out.extend_from_slice(&Sha256::digest(subject));
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    pub(crate) fn signed(facility_id: &str, seed: u8) -> SignedFacilityClaim {
        let k = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let claim = FacilityClaim {
            facility_id: facility_id.into(),
            region: "DE-HE".into(),
            facility_key: k.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
        };
        let sig: p256::ecdsa::Signature = k.sign(&claim.signing_bytes());
        SignedFacilityClaim {
            claim,
            signature: sig.to_bytes().to_vec(),
        }
    }

    #[test]
    fn a_signed_claim_binds_into_a_packet() {
        let s = signed("fra-1", 4);
        let p = bound_packet(&[1; 32], &s, b"key").unwrap();
        assert_ne!(p, bound_packet(&[2; 32], &s, b"key").unwrap());
        assert_ne!(
            p,
            bound_packet(&[1; 32], &signed("fra-2", 4), b"key").unwrap()
        );
    }

    #[test]
    fn an_altered_claim_is_refused() {
        let mut s = signed("fra-1", 4);
        s.claim.region = "US-VA".into();
        assert!(s.verify().is_err());
        assert!(bound_packet(&[1; 32], &s, b"key").is_err());
    }
}
