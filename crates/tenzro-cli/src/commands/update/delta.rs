//! Delta packages: a release file as the changes from the file it replaces.
//!
//! A release usually changes a small part of each binary, and a whole binary
//! is large. A delta names the exact file it applies to (its length and
//! SHA-256) and rebuilds the new file from that file's bytes and the bytes
//! that are new. The publisher puts a delta for each recent release beside
//! the full file, at `<path>.from-<base sha256>.delta`; the signed manifest
//! is unchanged.
//!
//! A delta carries no authority. The client applies it only to the file it
//! names, and keeps the result only when its length and SHA-256 are the ones
//! the signed manifest states for the full file; otherwise it downloads the
//! full file. A delta from anyone else can therefore cost a download, never
//! install anything.
//!
//! Format: `TZDELTA1`, then the base's length (u64) and SHA-256, the
//! target's length (u64), then operations until the end: `0x01` copy
//! (offset u64, length u32) from the base, or `0x02` insert (length u32 and
//! the bytes). Integers are big-endian.

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"TZDELTA1";
const OP_COPY: u8 = 1;
const OP_INSERT: u8 = 2;
/// The length of the blocks a delta matches against the base.
const BLOCK: usize = 64;
/// Longest single copy or insert.
const MAX_OP: usize = u32::MAX as usize;

/// Why a delta was not applied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeltaError {
    #[error("not a delta package: {0}")]
    Malformed(&'static str),
    #[error("the delta is for another file than the one installed")]
    WrongBase,
    #[error("the delta does not rebuild the file it claims to")]
    WrongTarget,
}

/// The channel path of the delta from the file with SHA-256 `base_sha256`
/// to the file at `path`.
pub fn delta_path(path: &str, base_sha256: &str) -> String {
    format!("{path}.from-{base_sha256}.delta")
}

/// A weak hash of a block that rolls one byte at a time.
#[derive(Clone, Copy)]
struct Rolling {
    a: u32,
    b: u32,
}

impl Rolling {
    fn of(block: &[u8]) -> Self {
        let mut a = 0u32;
        let mut b = 0u32;
        for (i, &x) in block.iter().enumerate() {
            a = a.wrapping_add(u32::from(x));
            b = b.wrapping_add((block.len() - i) as u32 * u32::from(x));
        }
        Self { a, b }
    }

    fn roll(&mut self, out: u8, into: u8) {
        self.a = self
            .a
            .wrapping_sub(u32::from(out))
            .wrapping_add(u32::from(into));
        self.b = self
            .b
            .wrapping_sub(BLOCK as u32 * u32::from(out))
            .wrapping_add(self.a);
    }

    fn value(&self) -> u32 {
        (self.a & 0xffff) | (self.b << 16)
    }
}

fn push_insert(out: &mut Vec<u8>, bytes: &[u8]) {
    for chunk in bytes.chunks(MAX_OP) {
        out.push(OP_INSERT);
        out.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
        out.extend_from_slice(chunk);
    }
}

/// The delta that rebuilds `target` from `base`.
pub fn encode(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(base.len() as u64).to_be_bytes());
    out.extend_from_slice(&Sha256::digest(base));
    out.extend_from_slice(&(target.len() as u64).to_be_bytes());

    let mut index: std::collections::HashMap<u32, Vec<usize>> = Default::default();
    for offset in (0..base.len().saturating_sub(BLOCK - 1)).step_by(BLOCK) {
        index
            .entry(Rolling::of(&base[offset..offset + BLOCK]).value())
            .or_default()
            .push(offset);
    }

    let mut pending = 0usize; // start of bytes not yet emitted
    let mut i = 0usize;
    let mut weak = (target.len() >= BLOCK).then(|| Rolling::of(&target[..BLOCK]));
    while let Some(w) = weak {
        let window = &target[i..i + BLOCK];
        let found = index.get(&w.value()).and_then(|offsets| {
            offsets
                .iter()
                .copied()
                .find(|&o| &base[o..o + BLOCK] == window)
        });
        if let Some(start) = found {
            let mut len = BLOCK;
            while i + len < target.len()
                && start + len < base.len()
                && target[i + len] == base[start + len]
                && len < MAX_OP
            {
                len += 1;
            }
            push_insert(&mut out, &target[pending..i]);
            out.push(OP_COPY);
            out.extend_from_slice(&(start as u64).to_be_bytes());
            out.extend_from_slice(&(len as u32).to_be_bytes());
            i += len;
            pending = i;
            weak = (i + BLOCK <= target.len()).then(|| Rolling::of(&target[i..i + BLOCK]));
        } else if i + BLOCK < target.len() {
            let mut next = w;
            next.roll(target[i], target[i + BLOCK]);
            weak = Some(next);
            i += 1;
        } else {
            weak = None;
        }
    }
    push_insert(&mut out, &target[pending..]);
    out
}

/// The next `n` bytes of `r`, which then starts after them.
fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], DeltaError> {
    if r.len() < n {
        return Err(DeltaError::Malformed("it ends early"));
    }
    let (head, rest) = r.split_at(n);
    *r = rest;
    Ok(head)
}

/// Rebuild the file a delta describes from `base`, which must be the file
/// the delta names, and check the result against `target_len` and
/// `target_sha256` (lowercase hex), the full file's values from the signed
/// manifest.
pub fn apply(
    base: &[u8],
    delta: &[u8],
    target_len: u64,
    target_sha256: &str,
) -> Result<Vec<u8>, DeltaError> {
    let mut r = delta;
    if take(&mut r, MAGIC.len())? != MAGIC {
        return Err(DeltaError::Malformed("no TZDELTA1 header"));
    }
    let base_len = u64::from_be_bytes(take(&mut r, 8)?.try_into().expect("8 bytes"));
    let base_sha = take(&mut r, 32)?.to_vec();
    let claimed_len = u64::from_be_bytes(take(&mut r, 8)?.try_into().expect("8 bytes"));
    if base_len != base.len() as u64 || base_sha != Sha256::digest(base).as_slice() {
        return Err(DeltaError::WrongBase);
    }
    if claimed_len != target_len {
        return Err(DeltaError::WrongTarget);
    }
    let cap = usize::try_from(target_len).map_err(|_| DeltaError::WrongTarget)?;
    let mut out = Vec::with_capacity(cap);
    while !r.is_empty() {
        let op = take(&mut r, 1)?[0];
        match op {
            OP_COPY => {
                let offset = u64::from_be_bytes(take(&mut r, 8)?.try_into().expect("8 bytes"));
                let len =
                    u32::from_be_bytes(take(&mut r, 4)?.try_into().expect("4 bytes")) as usize;
                let start = usize::try_from(offset)
                    .map_err(|_| DeltaError::Malformed("a copy starts past the base"))?;
                let end = start
                    .checked_add(len)
                    .filter(|e| *e <= base.len())
                    .ok_or(DeltaError::Malformed("a copy runs past the base"))?;
                out.extend_from_slice(&base[start..end]);
            }
            OP_INSERT => {
                let len =
                    u32::from_be_bytes(take(&mut r, 4)?.try_into().expect("4 bytes")) as usize;
                out.extend_from_slice(take(&mut r, len)?);
            }
            _ => return Err(DeltaError::Malformed("an unknown operation")),
        }
        if out.len() > cap {
            return Err(DeltaError::WrongTarget);
        }
    }
    if out.len() as u64 != target_len || hex::encode(Sha256::digest(&out)) != target_sha256 {
        return Err(DeltaError::WrongTarget);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes that look like a binary: mostly repeated structure, some noise.
    fn binary(seed: u64, len: usize) -> Vec<u8> {
        let mut x = seed;
        (0..len)
            .map(|i| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                if i % 7 == 0 {
                    (x >> 56) as u8
                } else {
                    (i % 251) as u8
                }
            })
            .collect()
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    #[test]
    fn a_delta_rebuilds_the_new_release_from_the_old_and_is_small() {
        let base = binary(1, 300_000);
        // The new release: a changed stretch, an inserted one, a removed one
        // and a new tail.
        let mut target = base.clone();
        target[10_000..10_200].copy_from_slice(&binary(2, 200));
        target.splice(50_000..50_000, binary(3, 5_000));
        target.drain(120_000..130_000);
        target.extend(binary(4, 3_000));
        let delta = encode(&base, &target);
        assert!(
            delta.len() < target.len() / 10,
            "{} of {}",
            delta.len(),
            target.len()
        );
        let rebuilt = apply(&base, &delta, target.len() as u64, &sha(&target)).unwrap();
        assert_eq!(rebuilt, target);
    }

    #[test]
    fn a_delta_applies_only_to_its_own_base_and_only_to_its_own_target() {
        let base = binary(1, 20_000);
        let mut target = base.clone();
        target[100..200].fill(9);
        let delta = encode(&base, &target);
        let mut other = base.clone();
        other[0] ^= 1;
        assert_eq!(
            apply(&other, &delta, target.len() as u64, &sha(&target)),
            Err(DeltaError::WrongBase)
        );
        // A delta that rebuilds something other than the signed file.
        assert_eq!(
            apply(&base, &delta, target.len() as u64, &sha(&base)),
            Err(DeltaError::WrongTarget)
        );
        assert_eq!(
            apply(&base, &delta, target.len() as u64 + 1, &sha(&target)),
            Err(DeltaError::WrongTarget)
        );
        // Damaged deltas are refused, never followed past the base.
        let mut cut = delta.clone();
        cut.truncate(cut.len() - 1);
        assert!(apply(&base, &cut, target.len() as u64, &sha(&target)).is_err());
        let mut far = delta[..56].to_vec();
        far.push(OP_COPY);
        far.extend_from_slice(&(base.len() as u64).to_be_bytes());
        far.extend_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            apply(&base, &far, target.len() as u64, &sha(&target)),
            Err(DeltaError::Malformed(_))
        ));
        assert!(apply(&base, b"not a delta", 1, &sha(b"x")).is_err());
    }

    #[test]
    fn short_and_empty_files_round_trip() {
        for (base, target) in [
            (Vec::new(), b"new".to_vec()),
            (b"old".to_vec(), Vec::new()),
            (b"same".to_vec(), b"same".to_vec()),
        ] {
            let delta = encode(&base, &target);
            assert_eq!(
                apply(&base, &delta, target.len() as u64, &sha(&target)).unwrap(),
                target
            );
        }
        assert_eq!(
            delta_path("x86_64-linux/tenzro-node", "ab"),
            "x86_64-linux/tenzro-node.from-ab.delta"
        );
    }
}
