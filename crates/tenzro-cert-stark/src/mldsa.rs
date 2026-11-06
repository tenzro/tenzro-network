//! ML-DSA verification (FIPS 204) of one parameter set ([`super::params`])
//! laid out as the values the compact
//! certificate's AIR checks.
//!
//! [`decompose`] runs the verifier and keeps every intermediate the circuit
//! needs: the key's matrix in coefficient form, the signature's `z`, `c` and
//! hint, the approximate `w`, its high bits, and the SHAKE256 inputs whose
//! permutations the circuit proves. It accepts exactly the signatures the
//! `ml-dsa` crate accepts (see the tests).

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

/// The modulus.
pub const Q: u32 = 8_380_417;
/// Coefficients per polynomial.
pub const N: usize = 256;
/// Dropped bits of `t`.
pub const D: u32 = 13;
/// Range of `z` before the norm bound.
pub const GAMMA1: i32 = 1 << 19;
/// Low-order rounding range.
pub const GAMMA2: u32 = (Q - 1) / 32;
pub use super::params::{BETA, C_TILDE_BYTES, K, L, OMEGA, TAU};
/// Encoded public key length.
pub const PUBLIC_KEY_BYTES: usize = 32 + K * 320;
/// Encoded signature length.
pub const SIGNATURE_BYTES: usize = C_TILDE_BYTES + L * 640 + OMEGA + K;
/// High-bits range: `w1` coefficients lie in `0..M1`.
pub const M1: u32 = (Q - 1) / (2 * GAMMA2);

/// A polynomial with coefficients in `0..Q`.
pub type Poly = [u32; N];

fn reduce(x: u64) -> u32 {
    (x % Q as u64) as u32
}

fn pow_mod(mut b: u64, mut e: u64) -> u32 {
    let mut r = 1u64;
    b %= Q as u64;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % Q as u64;
        }
        b = b * b % Q as u64;
        e >>= 1;
    }
    r as u32
}

fn zetas() -> [u32; N] {
    let mut z = [0u32; N];
    for (k, slot) in z.iter_mut().enumerate() {
        let brv = (k as u8).reverse_bits() as u64;
        *slot = pow_mod(1753, brv);
    }
    z
}

/// FIPS 204 Algorithm 41.
pub fn ntt(mut w: Poly) -> Poly {
    let zetas = zetas();
    let mut m = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let z = zetas[m] as u64;
            for j in start..start + len {
                let t = reduce(z * w[j + len] as u64);
                w[j + len] = reduce(w[j] as u64 + Q as u64 - t as u64);
                w[j] = reduce(w[j] as u64 + t as u64);
            }
            start += 2 * len;
        }
        len /= 2;
    }
    w
}

/// FIPS 204 Algorithm 42.
pub fn ntt_inverse(mut w: Poly) -> Poly {
    let zetas = zetas();
    let mut m = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            m -= 1;
            let z = (Q - zetas[m]) as u64;
            for j in start..start + len {
                let t = w[j];
                w[j] = reduce(t as u64 + w[j + len] as u64);
                w[j + len] = reduce(t as u64 + Q as u64 - w[j + len] as u64);
                w[j + len] = reduce(z * w[j + len] as u64);
            }
            start += 2 * len;
        }
        len *= 2;
    }
    let f = 8_347_681u64;
    for x in w.iter_mut() {
        *x = reduce(f * *x as u64);
    }
    w
}

/// Product in `Z_q[X]/(X^256 + 1)`, computed schoolbook (the reference the
/// AIR's relation is checked against).
pub fn mul_ring(a: &Poly, b: &Poly) -> Poly {
    let mut acc = [0i128; N];
    for i in 0..N {
        for j in 0..N {
            let p = a[i] as i128 * b[j] as i128;
            if i + j < N {
                acc[i + j] += p;
            } else {
                acc[i + j - N] -= p;
            }
        }
    }
    let mut out = [0u32; N];
    for (o, v) in out.iter_mut().zip(acc) {
        *o = v.rem_euclid(Q as i128) as u32;
    }
    out
}

fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

/// The key matrix `A` in the NTT domain (ExpandA, Algorithm 32).
pub fn expand_a(rho: &[u8; 32]) -> [[Poly; L]; K] {
    let mut a = [[[0u32; N]; L]; K];
    for (r, row) in a.iter_mut().enumerate() {
        for (s, poly) in row.iter_mut().enumerate() {
            let mut h = Shake128::default();
            h.update(rho);
            h.update(&[s as u8, r as u8]);
            let mut reader = h.finalize_xof();
            let mut j = 0usize;
            while j < N {
                let mut b = [0u8; 3];
                reader.read(&mut b);
                let v = b[0] as u32 | (b[1] as u32) << 8 | ((b[2] & 0x7f) as u32) << 16;
                if v < Q {
                    poly[j] = v;
                    j += 1;
                }
            }
        }
    }
    a
}

/// A decoded public key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Matrix seed.
    pub rho: [u8; 32],
    /// High bits of `t`, coefficients in `0..1024`.
    pub t1: [Poly; K],
    /// `tr = H(pk, 64)`.
    pub tr: [u8; 64],
    /// The key matrix in coefficient form.
    pub a: [[Poly; L]; K],
}

impl PublicKey {
    /// Decodes a [`PUBLIC_KEY_BYTES`]-byte public key (pkDecode) and derives everything
    /// that depends on the key alone. None if it is the wrong length.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return None;
        }
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[..32]);
        let mut t1 = [[0u32; N]; K];
        for (i, poly) in t1.iter_mut().enumerate() {
            let chunk = &bytes[32 + i * 320..32 + (i + 1) * 320];
            for (j, c) in poly.iter_mut().enumerate() {
                let bit = j * 10;
                let lo = bit / 8;
                let v = chunk[lo] as u32 | (chunk.get(lo + 1).copied().unwrap_or(0) as u32) << 8;
                *c = (v >> (bit % 8)) & 0x3ff;
            }
        }
        let mut tr = [0u8; 64];
        shake256(&[bytes], &mut tr);
        let a_hat = expand_a(&rho);
        let mut a = [[[0u32; N]; L]; K];
        for r in 0..K {
            for s in 0..L {
                a[r][s] = ntt_inverse(a_hat[r][s]);
            }
        }
        Some(Self { rho, t1, tr, a })
    }
}

/// A decoded signature.
#[derive(Clone, Debug)]
pub struct Signature {
    /// Challenge seed.
    pub c_tilde: [u8; C_TILDE_BYTES],
    /// Response, centered: coefficients in `-(GAMMA1-1)..=GAMMA1`.
    pub z: [[i32; N]; L],
    /// Hint bits.
    pub h: [[bool; N]; K],
}

impl Signature {
    /// Decodes a [`SIGNATURE_BYTES`]-byte signature (sigDecode with HintBitUnpack). None
    /// if it is malformed.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SIGNATURE_BYTES {
            return None;
        }
        let mut c_tilde = [0u8; C_TILDE_BYTES];
        c_tilde.copy_from_slice(&bytes[..C_TILDE_BYTES]);
        let mut z = [[0i32; N]; L];
        for (i, poly) in z.iter_mut().enumerate() {
            let chunk = &bytes[C_TILDE_BYTES + i * 640..C_TILDE_BYTES + (i + 1) * 640];
            for (j, c) in poly.iter_mut().enumerate() {
                let bit = j * 20;
                let lo = bit / 8;
                let v = chunk[lo] as u32
                    | (chunk[lo + 1] as u32) << 8
                    | (chunk.get(lo + 2).copied().unwrap_or(0) as u32) << 16;
                let v = (v >> (bit % 8)) & 0xf_ffff;
                *c = GAMMA1 - v as i32;
            }
        }
        let hint = &bytes[C_TILDE_BYTES + L * 640..];
        let mut h = [[false; N]; K];
        let mut index = 0usize;
        for (i, row) in h.iter_mut().enumerate() {
            let end = hint[OMEGA + i] as usize;
            if end < index || end > OMEGA {
                return None;
            }
            let first = index;
            while index < end {
                if index > first && hint[index - 1] >= hint[index] {
                    return None;
                }
                row[hint[index] as usize] = true;
                index += 1;
            }
        }
        if hint[index..OMEGA].iter().any(|b| *b != 0) {
            return None;
        }
        Some(Self { c_tilde, z, h })
    }
}

/// SampleInBall (Algorithm 29): the challenge, coefficients in {-1, 0, 1}.
pub fn sample_in_ball(c_tilde: &[u8; C_TILDE_BYTES]) -> [i32; N] {
    let mut h = Shake256::default();
    h.update(c_tilde);
    let mut reader = h.finalize_xof();
    let mut s = [0u8; 8];
    reader.read(&mut s);
    let signs = u64::from_le_bytes(s);
    let mut c = [0i32; N];
    for i in (N - TAU)..N {
        let j = loop {
            let mut b = [0u8; 1];
            reader.read(&mut b);
            if (b[0] as usize) <= i {
                break b[0] as usize;
            }
        };
        c[i] = c[j];
        c[j] = if (signs >> (i + TAU - N)) & 1 == 1 {
            -1
        } else {
            1
        };
    }
    c
}

/// Decompose (Algorithm 36) of `r` in `0..Q`: `(r1, r0)` with
/// `r = r1 * 2 GAMMA2 + r0` and `r0` centered, except at the top edge.
pub fn decompose(r: u32) -> (u32, i32) {
    let alpha = 2 * GAMMA2 as i32;
    let mut r0 = (r as i32).rem_euclid(alpha);
    if r0 > alpha / 2 {
        r0 -= alpha;
    }
    if r as i32 - r0 == Q as i32 - 1 {
        (0, r0 - 1)
    } else {
        (((r as i32 - r0) / alpha) as u32, r0)
    }
}

/// UseHint (Algorithm 40).
pub fn use_hint(h: bool, r: u32) -> u32 {
    let (r1, r0) = decompose(r);
    match (h, r0 > 0) {
        (false, _) => r1,
        (true, true) => (r1 + 1) % M1,
        (true, false) => (r1 + M1 - 1) % M1,
    }
}

/// `M' = 0 || len(ctx) || ctx || M`, the message ML-DSA.Verify signs.
pub fn message_prime(message: &[u8], context: &[u8]) -> Option<Vec<u8>> {
    let len = u8::try_from(context.len()).ok()?;
    let mut out = Vec::with_capacity(2 + context.len() + message.len());
    out.push(0);
    out.push(len);
    out.extend_from_slice(context);
    out.extend_from_slice(message);
    Some(out)
}

/// `mu = H(tr || M', 64)`.
pub fn mu(tr: &[u8; 64], message_prime: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    shake256(&[tr, message_prime], &mut out);
    out
}

/// w1Encode: four bits per coefficient, little end first.
pub fn w1_encode(w1: &[Poly; K]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * N / 2);
    for poly in w1 {
        for pair in poly.chunks(2) {
            out.push((pair[0] | pair[1] << 4) as u8);
        }
    }
    out
}

/// Whether `c~ = H(mu || w1Encode(w1), 48)` for `pk` and `message_prime`:
/// the hash half of verification, given the high bits `w1` (coefficients
/// below [`M1`]).
pub fn challenge_matches(
    pk: &PublicKey,
    message_prime: &[u8],
    c_tilde: &[u8; C_TILDE_BYTES],
    w1: &[Poly; K],
) -> bool {
    if w1.iter().flatten().any(|c| *c >= M1) {
        return false;
    }
    let mu = mu(&pk.tr, message_prime);
    let mut out = [0u8; C_TILDE_BYTES];
    shake256(&[&mu, &w1_encode(w1)], &mut out);
    out == *c_tilde
}

/// `NTT(c) * NTT(t1 2^d)` for the challenge of `c_tilde`: the part of
/// `w'_approx` that depends on the signature only through `c~`, in the NTT
/// domain.
pub fn challenge_term(pk: &PublicKey, c_tilde: &[u8; C_TILDE_BYTES]) -> [Poly; K] {
    let c = sample_in_ball(c_tilde);
    let c_hat = ntt(core::array::from_fn(|i| c[i].rem_euclid(Q as i32) as u32));
    core::array::from_fn(|r| {
        let t1_hat = ntt(core::array::from_fn(|i| pk.t1[r][i] << D));
        core::array::from_fn(|i| reduce(c_hat[i] as u64 * t1_hat[i] as u64))
    })
}

/// The values of one signature's verification the AIR checks.
#[derive(Clone, Debug)]
pub struct Witness {
    /// `w'_approx = A z - c t1 2^d` in `R_q`, coefficients in `0..Q`.
    pub w_approx: [Poly; K],
    /// `UseHint(h, w'_approx)`.
    pub w1: [Poly; K],
}

/// Runs ML-DSA verification of `sig` over `message_prime` under `pk` and
/// returns its intermediate values, or None if it does not verify.
#[allow(clippy::needless_range_loop)] // s and i index the matrix, both vectors and the accumulator together
pub fn decompose_verification(
    pk: &PublicKey,
    message_prime: &[u8],
    sig: &Signature,
) -> Option<Witness> {
    if sig.z.iter().flatten().any(|c| c.abs() >= GAMMA1 - BETA) {
        return None;
    }
    let to_q = |x: i32| x.rem_euclid(Q as i32) as u32;
    let z_hat: Vec<Poly> = sig
        .z
        .iter()
        .map(|p| ntt(core::array::from_fn(|i| to_q(p[i]))))
        .collect();
    let ct = challenge_term(pk, &sig.c_tilde);
    let mut w_approx = [[0u32; N]; K];
    let mut w1 = [[0u32; N]; K];
    for r in 0..K {
        let mut acc = [0u64; N];
        for s in 0..L {
            let a_hat = ntt(pk.a[r][s]);
            for i in 0..N {
                acc[i] += a_hat[i] as u64 * z_hat[s][i] as u64 % Q as u64;
            }
        }
        let mut v = [0u32; N];
        for i in 0..N {
            v[i] = reduce(acc[i] % Q as u64 + Q as u64 - ct[r][i] as u64);
        }
        w_approx[r] = ntt_inverse(v);
        for i in 0..N {
            w1[r][i] = use_hint(sig.h[r][i], w_approx[r][i]);
        }
    }
    challenge_matches(pk, message_prime, &sig.c_tilde, &w1).then_some(Witness { w_approx, w1 })
}

#[cfg(test)]
mod tests {
    use super::super::params::MlDsa;
    use super::*;
    use ml_dsa::ExpandedSigningKey;

    fn keypair(seed: u8) -> ExpandedSigningKey<MlDsa> {
        ExpandedSigningKey::<MlDsa>::from_seed(&[seed; 32].into())
    }

    fn sign(sk: &ExpandedSigningKey<MlDsa>, message: &[u8], ctx: &[u8]) -> Vec<u8> {
        sk.sign_deterministic(message, ctx)
            .expect("signs")
            .encode()
            .to_vec()
    }

    #[test]
    fn the_ntt_inverts_and_multiplies_in_the_ring() {
        let a: Poly = core::array::from_fn(|i| (i as u32 * 7919 + 13) % Q);
        let b: Poly = core::array::from_fn(|i| (i as u32 * 104_729 + 3) % Q);
        assert_eq!(ntt_inverse(ntt(a)), a);
        let (ah, bh) = (ntt(a), ntt(b));
        let prod: Poly = core::array::from_fn(|i| reduce(ah[i] as u64 * bh[i] as u64));
        assert_eq!(ntt_inverse(prod), mul_ring(&a, &b));
    }

    #[test]
    fn it_accepts_exactly_what_ml_dsa_accepts() {
        let ctx = super::super::params::LABEL;
        for seed in 0..4u8 {
            let sk = keypair(seed);
            let vk = sk.verifying_key().encode().to_vec();
            let pk = PublicKey::decode(&vk).unwrap();
            let msg = [seed; 97];
            let sig_bytes = sign(&sk, &msg, ctx);
            let sig = Signature::decode(&sig_bytes).unwrap();
            let mp = message_prime(&msg, ctx).unwrap();
            let w = decompose_verification(&pk, &mp, &sig).expect("a valid signature verifies");
            // The ring relation the AIR checks, computed without the NTT.
            for r in 0..K {
                let mut expect = [0i64; N];
                for s in 0..L {
                    let z: Poly = core::array::from_fn(|i| sig.z[s][i].rem_euclid(Q as i32) as u32);
                    let p = mul_ring(&pk.a[r][s], &z);
                    for i in 0..N {
                        expect[i] += p[i] as i64;
                    }
                }
                let challenge = sample_in_ball(&sig.c_tilde);
                let c: Poly = core::array::from_fn(|i| challenge[i].rem_euclid(Q as i32) as u32);
                let t: Poly = core::array::from_fn(|i| pk.t1[r][i] << D);
                let ct = mul_ring(&c, &t);
                for i in 0..N {
                    assert_eq!(
                        (expect[i] - ct[i] as i64).rem_euclid(Q as i64) as u32,
                        w.w_approx[r][i]
                    );
                }
            }
            // Another message does not verify.
            let other = message_prime(&[seed ^ 1; 97], ctx).unwrap();
            assert!(decompose_verification(&pk, &other, &sig).is_none());
            // A flipped bit of z does not verify.
            let mut bad = sig_bytes.clone();
            bad[C_TILDE_BYTES + 5] ^= 1;
            if let Some(bad) = Signature::decode(&bad) {
                assert!(decompose_verification(&pk, &mp, &bad).is_none());
            }
        }
    }
}
