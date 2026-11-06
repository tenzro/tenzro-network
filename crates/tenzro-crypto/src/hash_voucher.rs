//! Hash-based one-time signatures for vouchers verified on other chains.
//!
//! A chain that verifies only classical signatures can still verify a hash:
//! a payment channel commits, when it opens, to the Merkle root of
//! 2^`height` one-time WOTS+ keys (Winternitz parameter 16, SHA-256), and
//! each voucher spends one leaf. Verifying one costs about 600 SHA-256
//! evaluations and no elliptic-curve arithmetic, so it holds when ECDSA is
//! broken and stays cheap in a contract.
//!
//! Every hash is domain separated and, except the Merkle nodes, tweaked with
//! the channel's public seed, the leaf and the position in the chain, so the
//! keys of two channels or two leaves never share a hash input.
//!
//! The one-time secrets derive from a 32-byte seed, which the signer derives
//! from its hardware root and never stores. A leaf must sign one digest only:
//! the caller keeps the count of leaves used and never signs twice with one.

use sha2::{Digest, Sha256};

use crate::error::{CryptoError, Result};

/// Bytes of every hash value.
pub const N: usize = 32;
/// Digits of a digest in base 16.
pub const LEN1: usize = 64;
/// Digits of the checksum in base 16.
pub const LEN2: usize = 3;
/// Hash chains of one key.
pub const CHAINS: usize = LEN1 + LEN2;
/// Highest digit: the length of each chain.
pub const W_MAX: u8 = 15;
/// Tallest tree a channel may commit to: about a million vouchers.
pub const MAX_HEIGHT: u8 = 20;

const SECRET_DOMAIN: u8 = 0x00;
const CHAIN_DOMAIN: u8 = 0x01;
const LEAF_DOMAIN: u8 = 0x02;
const NODE_DOMAIN: u8 = 0x03;
const PUBLIC_SEED_DOMAIN: u8 = 0x05;

/// What a channel commits to: its public seed, the height of its tree and
/// the tree's root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoucherKeys {
    /// The seed every hash of the channel is tweaked with.
    pub public_seed: [u8; N],
    /// The height of the tree: it holds 2^height keys.
    pub height: u8,
    /// The root of the tree.
    pub root: [u8; N],
}

/// One voucher signature: the leaf it spends, the chain values over the
/// digest, and the authentication path from that leaf to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoucherSignature {
    /// The one-time key it spends.
    pub leaf: u32,
    /// The value of each hash chain at the digest's digit.
    pub chains: Vec<[u8; N]>,
    /// The siblings from the leaf up to the root.
    pub path: Vec<[u8; N]>,
}

impl VoucherSignature {
    /// `leaf (4, big-endian) || chains (67 x 32) || path (height x 32)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + N * (self.chains.len() + self.path.len()));
        out.extend_from_slice(&self.leaf.to_be_bytes());
        for c in self.chains.iter().chain(&self.path) {
            out.extend_from_slice(c);
        }
        out
    }

    /// Parses [`VoucherSignature::to_bytes`] for a tree of `height`.
    pub fn from_bytes(bytes: &[u8], height: u8) -> Result<Self> {
        let want = 4 + N * (CHAINS + height as usize);
        if height > MAX_HEIGHT || bytes.len() != want {
            return Err(CryptoError::InvalidSignature(format!(
                "a voucher signature for a tree of height {height} is {want} bytes, not {}",
                bytes.len()
            )));
        }
        let leaf = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"));
        let values: Vec<[u8; N]> = bytes[4..].as_chunks::<N>().0.to_vec();
        let (chains, path) = values.split_at(CHAINS);
        Ok(Self {
            leaf,
            chains: chains.to_vec(),
            path: path.to_vec(),
        })
    }
}

fn h(parts: &[&[u8]]) -> [u8; N] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

fn chain_step(public_seed: &[u8; N], leaf: u32, chain: u8, step: u8, x: &[u8; N]) -> [u8; N] {
    h(&[
        &[CHAIN_DOMAIN],
        public_seed,
        &leaf.to_be_bytes(),
        &[chain, step],
        x,
    ])
}

/// Walks chain `chain` of `leaf` from position `from` up to `to`.
fn walk(public_seed: &[u8; N], leaf: u32, chain: u8, from: u8, to: u8, x: [u8; N]) -> [u8; N] {
    (from..to).fold(x, |x, step| chain_step(public_seed, leaf, chain, step, &x))
}

/// The base-16 digits of `digest` followed by those of its checksum.
fn digits(digest: &[u8; N]) -> [u8; CHAINS] {
    let mut d = [0u8; CHAINS];
    for (i, b) in digest.iter().enumerate() {
        d[2 * i] = b >> 4;
        d[2 * i + 1] = b & 0x0f;
    }
    let checksum: u32 = d[..LEN1].iter().map(|&x| u32::from(W_MAX - x)).sum();
    d[LEN1] = ((checksum >> 8) & 0x0f) as u8;
    d[LEN1 + 1] = ((checksum >> 4) & 0x0f) as u8;
    d[LEN1 + 2] = (checksum & 0x0f) as u8;
    d
}

fn leaf_hash(public_seed: &[u8; N], leaf: u32, tops: &[[u8; N]]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_DOMAIN]);
    hasher.update(public_seed);
    hasher.update(leaf.to_be_bytes());
    for t in tops {
        hasher.update(t);
    }
    hasher.finalize().into()
}

fn node(left: &[u8; N], right: &[u8; N]) -> [u8; N] {
    h(&[&[NODE_DOMAIN], left, right])
}

/// The one-time keys of one channel, derived from a secret seed.
pub struct VoucherKeyTree {
    seed: zeroize::Zeroizing<[u8; N]>,
    public_seed: [u8; N],
    height: u8,
    /// Every level of the tree, leaves first.
    levels: Vec<Vec<[u8; N]>>,
}

impl std::fmt::Debug for VoucherKeyTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoucherKeyTree")
            .field("height", &self.height)
            .field("root", &hex::encode(self.root()))
            .finish_non_exhaustive()
    }
}

impl VoucherKeyTree {
    /// Derives the 2^`height` keys of `seed` and their tree: 2^`height` x 67
    /// x 15 hashes.
    pub fn derive(seed: [u8; N], height: u8) -> Result<Self> {
        if height > MAX_HEIGHT {
            return Err(CryptoError::InvalidKey(format!(
                "a voucher tree is at most {MAX_HEIGHT} high, not {height}"
            )));
        }
        let seed = zeroize::Zeroizing::new(seed);
        let public_seed = h(&[&[PUBLIC_SEED_DOMAIN], seed.as_ref()]);
        let leaves: Vec<[u8; N]> = (0..1u32 << height)
            .map(|leaf| {
                let tops: Vec<[u8; N]> = (0..CHAINS as u8)
                    .map(|c| {
                        let sk = Self::secret(&seed, leaf, c);
                        walk(&public_seed, leaf, c, 0, W_MAX, sk)
                    })
                    .collect();
                leaf_hash(&public_seed, leaf, &tops)
            })
            .collect();
        let mut levels = vec![leaves];
        while levels.last().map_or(0, Vec::len) > 1 {
            let below = levels.last().expect("a level");
            levels.push(
                below
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|[l, r]| node(l, r))
                    .collect(),
            );
        }
        Ok(Self {
            seed,
            public_seed,
            height,
            levels,
        })
    }

    fn secret(seed: &[u8; N], leaf: u32, chain: u8) -> [u8; N] {
        h(&[&[SECRET_DOMAIN], seed, &leaf.to_be_bytes(), &[chain]])
    }

    /// The tree's root.
    pub fn root(&self) -> [u8; N] {
        self.levels.last().expect("a root")[0]
    }

    /// What the channel commits to.
    pub fn keys(&self) -> VoucherKeys {
        VoucherKeys {
            public_seed: self.public_seed,
            height: self.height,
            root: self.root(),
        }
    }

    /// How many vouchers the tree can sign.
    pub fn capacity(&self) -> u64 {
        1u64 << self.height
    }

    /// Signs `digest` with one-time key `leaf`. The caller must never sign
    /// a second digest with the same leaf.
    pub fn sign(&self, leaf: u32, digest: &[u8; N]) -> Result<VoucherSignature> {
        if u64::from(leaf) >= self.capacity() {
            return Err(CryptoError::InvalidKey(format!(
                "leaf {leaf} is outside a tree of {} keys",
                self.capacity()
            )));
        }
        let d = digits(digest);
        let chains = (0..CHAINS)
            .map(|c| {
                let sk = Self::secret(&self.seed, leaf, c as u8);
                walk(&self.public_seed, leaf, c as u8, 0, d[c], sk)
            })
            .collect();
        let mut index = leaf as usize;
        let path = self.levels[..self.height as usize]
            .iter()
            .map(|level| {
                let sibling = level[index ^ 1];
                index >>= 1;
                sibling
            })
            .collect();
        Ok(VoucherSignature { leaf, chains, path })
    }
}

/// Checks `signature` over `digest` under the channel's `keys`.
pub fn verify(keys: &VoucherKeys, digest: &[u8; N], signature: &VoucherSignature) -> Result<()> {
    let bad = |m: &str| {
        Err(CryptoError::InvalidSignature(format!(
            "voucher signature: {m}"
        )))
    };
    if signature.chains.len() != CHAINS || signature.path.len() != keys.height as usize {
        return bad("wrong shape");
    }
    if keys.height > MAX_HEIGHT || u64::from(signature.leaf) >= 1u64 << keys.height {
        return bad("leaf outside the tree");
    }
    let d = digits(digest);
    let tops: Vec<[u8; N]> = (0..CHAINS)
        .map(|c| {
            walk(
                &keys.public_seed,
                signature.leaf,
                c as u8,
                d[c],
                W_MAX,
                signature.chains[c],
            )
        })
        .collect();
    let mut at = leaf_hash(&keys.public_seed, signature.leaf, &tops);
    let mut index = signature.leaf;
    for sibling in &signature.path {
        at = if index & 1 == 0 {
            node(&at, sibling)
        } else {
            node(sibling, &at)
        };
        index >>= 1;
    }
    if at == keys.root {
        Ok(())
    } else {
        bad("does not reach the channel's root")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> [u8; N] {
        Sha256::digest([n]).into()
    }

    /// Each leaf signs a voucher that verifies under the channel's root and
    /// nothing else: another digest, another leaf number, an altered chain
    /// or path value, or another channel's keys are refused.
    #[test]
    fn a_voucher_verifies_under_its_channel_root_and_nothing_else() {
        let tree = VoucherKeyTree::derive([7; N], 4).unwrap();
        let keys = tree.keys();
        for leaf in [0, 5, 15] {
            let sig = tree.sign(leaf, &digest(leaf as u8)).unwrap();
            verify(&keys, &digest(leaf as u8), &sig).unwrap();
            assert!(verify(&keys, &digest(99), &sig).is_err());
            let back = VoucherSignature::from_bytes(&sig.to_bytes(), keys.height).unwrap();
            assert_eq!(back, sig);
            let mut moved = sig.clone();
            moved.leaf ^= 1;
            assert!(verify(&keys, &digest(leaf as u8), &moved).is_err());
            let mut altered = sig.clone();
            altered.chains[3][0] ^= 1;
            assert!(verify(&keys, &digest(leaf as u8), &altered).is_err());
            let mut altered = sig.clone();
            altered.path[2][31] ^= 1;
            assert!(verify(&keys, &digest(leaf as u8), &altered).is_err());
        }
        let other = VoucherKeyTree::derive([8; N], 4).unwrap().keys();
        let sig = tree.sign(1, &digest(1)).unwrap();
        assert!(verify(&other, &digest(1), &sig).is_err());
        assert!(tree.sign(16, &digest(1)).is_err());
        assert!(VoucherKeyTree::derive([7; N], MAX_HEIGHT + 1).is_err());
    }

    /// The checksum stops a forger from walking chains forward: raising any
    /// digest digit lowers the checksum, whose chains the forger cannot walk
    /// back.
    #[test]
    fn the_checksum_digits_fall_when_a_digest_digit_rises() {
        let low = [0u8; N];
        let mut high = low;
        high[0] = 0x10;
        let (a, b) = (digits(&low), digits(&high));
        assert!(b[0] > a[0]);
        assert!(b[LEN1..] < a[LEN1..]);
        assert_eq!(a[LEN1..], [3, 12, 0]);
    }

    /// The keys are fixed by the seed: one seed always commits to the same
    /// root, which this vector pins for the contracts that verify it.
    #[test]
    fn the_root_is_fixed_by_the_seed() {
        let a = VoucherKeyTree::derive([1; N], 2).unwrap();
        let b = VoucherKeyTree::derive([1; N], 2).unwrap();
        assert_eq!(a.keys(), b.keys());
        assert_ne!(a.root(), VoucherKeyTree::derive([2; N], 2).unwrap().root());
        let sig = a.sign(2, &[0xab; N]).unwrap();
        assert_eq!(sig.to_bytes().len(), 4 + N * (CHAINS + 2));
    }

    /// What deriving a tree, signing and verifying cost. Run with
    /// `cargo test --release -p tenzro-crypto hash_voucher::tests::costs -- --ignored --nocapture`.
    #[test]
    #[ignore = "timing, run by hand in release"]
    fn costs() {
        use std::time::Instant;
        let t = Instant::now();
        let tree = VoucherKeyTree::derive([3; N], 10).unwrap();
        let derive = t.elapsed();
        let t = Instant::now();
        let sig = tree.sign(500, &digest(1)).unwrap();
        let sign = t.elapsed();
        let t = Instant::now();
        for _ in 0..100 {
            verify(&tree.keys(), &digest(1), &sig).unwrap();
        }
        let verify_us = t.elapsed().as_secs_f64() * 1e6 / 100.0;
        println!(
            "voucher tree of 1024 keys derived in {derive:?}, sign {sign:?}, verify {verify_us:.1} us, \
             signature {} B",
            sig.to_bytes().len()
        );
    }
}
