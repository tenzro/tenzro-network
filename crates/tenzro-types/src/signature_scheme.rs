//! Signature schemes of composite keys and signatures, and how a key or
//! signature names its scheme.
//!
//! A composite key or signature pairs an ML-DSA leg with an ECDSA leg, as the
//! IETF LAMPS composite ML-DSA signature specification defines them.
//! Its scheme is named in the ML-DSA leg: a leg of the default scheme is the
//! bare ML-DSA-65 key or signature, as every key and signature written
//! before schemes were named; a leg of any other scheme is [`SCHEME_TAG`],
//! the scheme's id, then the bare key or signature. A default-scheme leg is
//! never tagged, so each leg has one encoding.

use serde::{Deserialize, Serialize};

/// First byte of the ML-DSA leg of a key or signature of a scheme other
/// than the default.
pub const SCHEME_TAG: u8 = 0xA7;

/// A composite signature scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    /// ML-DSA-65 (FIPS 204) with ECDSA-P256-SHA256 over the composite
    /// message representative. Every key and signature that names no
    /// scheme is of this one.
    #[default]
    MlDsa65P256,
    /// ML-DSA-87 (FIPS 204) with ECDSA-P384-SHA384 over the composite
    /// message representative: the IETF composite
    /// `id-MLDSA87-ECDSA-P384-SHA512`.
    MlDsa87P384,
}

impl SignatureScheme {
    /// Every scheme, by id.
    pub const ALL: [Self; 2] = [Self::MlDsa65P256, Self::MlDsa87P384];

    /// The scheme's id.
    pub const fn id(self) -> u8 {
        match self {
            Self::MlDsa65P256 => 0,
            Self::MlDsa87P384 => 1,
        }
    }

    /// The scheme with `id`.
    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.id() == id)
    }

    /// Length of a bare ML-DSA verifying key of the scheme.
    pub const fn ml_dsa_public_key_len(self) -> usize {
        match self {
            Self::MlDsa65P256 => 1952,
            Self::MlDsa87P384 => 2592,
        }
    }

    /// Length of a bare ML-DSA signature of the scheme.
    pub const fn ml_dsa_signature_len(self) -> usize {
        match self {
            Self::MlDsa65P256 => 3309,
            Self::MlDsa87P384 => 4627,
        }
    }

    /// The composite label: part of the message representative both legs
    /// sign, and the ML-DSA context string.
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::MlDsa65P256 => b"COMPSIG-MLDSA65-ECDSA-P256-SHA512",
            Self::MlDsa87P384 => b"COMPSIG-MLDSA87-ECDSA-P384-SHA512",
        }
    }

    /// The scheme named by its composite label, with or without the
    /// trailing `-SHA512`, as a node config names it.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| {
            let label = std::str::from_utf8(s.label()).unwrap_or_default();
            name == label || label.strip_suffix("-SHA512") == Some(name)
        })
    }

    /// Length of the uncompressed SEC1 ECDSA public key of the scheme.
    pub const fn ecdsa_public_key_len(self) -> usize {
        match self {
            Self::MlDsa65P256 => 65,
            Self::MlDsa87P384 => 97,
        }
    }

    /// Length of a raw `r || s` ECDSA signature of the scheme.
    pub const fn ecdsa_signature_len(self) -> usize {
        match self {
            Self::MlDsa65P256 => 64,
            Self::MlDsa87P384 => 96,
        }
    }

    /// The ML-DSA leg of the scheme for the bare key or signature `bare`.
    pub fn tag(self, bare: &[u8]) -> Vec<u8> {
        if self == Self::default() {
            return bare.to_vec();
        }
        let mut out = Vec::with_capacity(2 + bare.len());
        out.push(SCHEME_TAG);
        out.push(self.id());
        out.extend_from_slice(bare);
        out
    }

    /// The scheme and bare key of the ML-DSA leg of a verifying key, or
    /// `None` when the leg names no known scheme or has the wrong length.
    pub fn split_public_key(leg: &[u8]) -> Option<(Self, &[u8])> {
        Self::split(leg, Self::ml_dsa_public_key_len)
    }

    /// The scheme and bare signature of the ML-DSA leg of a signature.
    pub fn split_signature(leg: &[u8]) -> Option<(Self, &[u8])> {
        Self::split(leg, Self::ml_dsa_signature_len)
    }

    fn split(leg: &[u8], len: fn(Self) -> usize) -> Option<(Self, &[u8])> {
        if leg.len() == len(Self::default()) {
            return Some((Self::default(), leg));
        }
        let (&tag, rest) = leg.split_first()?;
        let (&id, bare) = rest.split_first()?;
        let scheme = Self::from_id(id).filter(|s| *s != Self::default())?;
        (tag == SCHEME_TAG && bare.len() == len(scheme)).then_some((scheme, bare))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_leg_is_bare_and_any_other_names_its_scheme() {
        let bare65 = vec![7u8; 1952];
        assert_eq!(SignatureScheme::MlDsa65P256.tag(&bare65), bare65);
        assert_eq!(
            SignatureScheme::split_public_key(&bare65),
            Some((SignatureScheme::MlDsa65P256, bare65.as_slice()))
        );
        let bare87 = vec![7u8; 2592];
        let leg = SignatureScheme::MlDsa87P384.tag(&bare87);
        assert_eq!(
            SignatureScheme::split_public_key(&leg),
            Some((SignatureScheme::MlDsa87P384, bare87.as_slice()))
        );
        // No second encoding of a default leg, no unknown id, no wrong length.
        let mut tagged65 = vec![SCHEME_TAG, 0];
        tagged65.extend_from_slice(&bare65);
        assert_eq!(SignatureScheme::split_public_key(&tagged65), None);
        let mut unknown = vec![SCHEME_TAG, 9];
        unknown.extend_from_slice(&bare87);
        assert_eq!(SignatureScheme::split_public_key(&unknown), None);
        assert_eq!(SignatureScheme::split_public_key(&bare87), None);
        assert_eq!(SignatureScheme::split_signature(&leg), None);
    }
}
