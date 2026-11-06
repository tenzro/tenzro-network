// SPDX-License-Identifier: Apache-2.0
//! BN254 computed in software, for chains without curve natives, with the
//! Ethereum precompile encodings.

use ark_bn254::{Bn254 as Curve, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use crate::Bn254;

fn fq(b: &[u8]) -> Option<Fq> {
    let v = Fq::from_be_bytes_mod_order(b);
    // Refuse non-canonical coordinates.
    (v.into_bigint().to_bytes_be() == b).then_some(v)
}

fn g1(b: &[u8; 64]) -> Option<G1Affine> {
    let (x, y) = (fq(&b[..32])?, fq(&b[32..])?);
    if x.is_zero() && y.is_zero() {
        return Some(G1Affine::zero());
    }
    let p = G1Affine::new_unchecked(x, y);
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

fn g2(b: &[u8; 128]) -> Option<G2Affine> {
    let x = Fq2::new(fq(&b[32..64])?, fq(&b[..32])?);
    let y = Fq2::new(fq(&b[96..])?, fq(&b[64..96])?);
    if x.is_zero() && y.is_zero() {
        return Some(G2Affine::zero());
    }
    let p = G2Affine::new_unchecked(x, y);
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

fn out(p: G1Affine) -> [u8; 64] {
    let mut o = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        o[..32].copy_from_slice(&x.into_bigint().to_bytes_be());
        o[32..].copy_from_slice(&y.into_bigint().to_bytes_be());
    }
    o
}

/// BN254 computed in software.
pub struct Arkworks;

impl Bn254 for Arkworks {
    fn g1_add(&self, a: &[u8; 64], b: &[u8; 64]) -> Option<[u8; 64]> {
        Some(out((g1(a)? + g1(b)?).into_affine()))
    }

    fn g1_mul(&self, p: &[u8; 64], s: &[u8; 32]) -> Option<[u8; 64]> {
        let s = Fr::from_be_bytes_mod_order(s);
        Some(out((g1(p)? * s).into_affine()))
    }

    fn pairing4(&self, pairs: &[([u8; 64], [u8; 128]); 4]) -> Option<bool> {
        let mut a = [G1Affine::zero(); 4];
        let mut b = [G2Affine::zero(); 4];
        for (i, (p, q)) in pairs.iter().enumerate() {
            a[i] = g1(p)?;
            b[i] = g2(q)?;
        }
        Some(Curve::multi_pairing(a, b).is_zero())
    }
}
