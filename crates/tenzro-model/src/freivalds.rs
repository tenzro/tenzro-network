//! Matrix work a verifier checks in far less time than it takes to do.
//!
//! Both `n × n` matrices derive from a nonce, so the prover cannot have
//! computed the product in advance. The prover commits to the product's rows
//! with a Merkle root, then opens the rows the root itself selects: the
//! commitment fixes every row before the prover learns which will be opened,
//! so a prover that computed only a fraction `f` of the rows survives with
//! probability about `f^k` for `k` opened rows. Each opened row is checked
//! with Freivalds' test against a random vector drawn from the root: one
//! matrix-vector product for all rows, then `O(n)` per row, instead of the
//! `O(n^3)` product.
//!
//! Arithmetic is over the prime field `2^31 - 1`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The field modulus.
pub const MODULUS: u64 = (1 << 31) - 1;

/// Largest matrix dimension a probe may ask for.
pub const MAX_DIMENSION: u32 = 1_024;

/// Most rows a probe may ask the prover to open.
pub const MAX_OPENED_ROWS: u32 = 64;

type Hash = [u8; 32];

/// One opened row of the product, with its Merkle path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenedRow {
    pub index: u32,
    pub values: Vec<u32>,
    pub path: Vec<Hash>,
}

/// The prover's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatmulProof {
    pub root: Hash,
    pub rows: Vec<OpenedRow>,
}

fn field_stream(nonce: &[u8; 32], label: &[u8], len: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"tenzro/freivalds/");
        h.update(label);
        h.update(nonce);
        h.update(counter.to_be_bytes());
        let block = h.finalize();
        for chunk in block.as_chunks::<4>().0 {
            if out.len() == len {
                break;
            }
            let v = u32::from_be_bytes(*chunk) as u64 % MODULUS;
            out.push(v as u32);
        }
        counter += 1;
    }
    out
}

/// The two input matrices, row-major.
pub fn inputs(nonce: &[u8; 32], n: u32) -> (Vec<u32>, Vec<u32>) {
    let len = (n as usize) * (n as usize);
    (
        field_stream(nonce, b"a", len),
        field_stream(nonce, b"b", len),
    )
}

fn row_leaf(index: u32, values: &[u32]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(index.to_be_bytes());
    for v in values {
        h.update(v.to_be_bytes());
    }
    h.finalize().into()
}

fn parent(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// All levels of the Merkle tree over `leaves`, leaves first. An odd node is
/// paired with itself.
fn levels(leaves: Vec<Hash>) -> Vec<Vec<Hash>> {
    let mut levels = vec![leaves];
    while levels.last().map_or(0, Vec::len) > 1 {
        let prev = levels.last().expect("non-empty");
        let next = prev
            .chunks(2)
            .map(|p| parent(&p[0], p.get(1).unwrap_or(&p[0])))
            .collect();
        levels.push(next);
    }
    levels
}

/// The rows a root selects for opening.
pub fn opened_indices(nonce: &[u8; 32], root: &Hash, n: u32, k: u32) -> Vec<u32> {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(
        &Sha256::new()
            .chain_update(nonce)
            .chain_update(root)
            .finalize(),
    );
    field_stream(&seed, b"rows", k.min(n) as usize)
        .into_iter()
        .map(|v| v % n)
        .collect()
}

fn challenge_vector(nonce: &[u8; 32], root: &Hash, n: u32) -> Vec<u32> {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(
        &Sha256::new()
            .chain_update(root)
            .chain_update(nonce)
            .finalize(),
    );
    field_stream(&seed, b"r", n as usize)
}

fn dot(a: &[u32], b: &[u32]) -> u64 {
    a.iter().zip(b).fold(0u64, |acc, (x, y)| {
        (acc + (*x as u64) * (*y as u64) % MODULUS) % MODULUS
    })
}

/// Prover: compute the product, commit to its rows, open the selected ones.
pub fn prove(nonce: &[u8; 32], n: u32, k: u32) -> MatmulProof {
    let (a, b) = inputs(nonce, n);
    let n_us = n as usize;
    let mut c = vec![0u32; n_us * n_us];
    for i in 0..n_us {
        for l in 0..n_us {
            let ail = a[i * n_us + l] as u64;
            if ail == 0 {
                continue;
            }
            let row_b = &b[l * n_us..(l + 1) * n_us];
            let row_c = &mut c[i * n_us..(i + 1) * n_us];
            for (cj, bj) in row_c.iter_mut().zip(row_b) {
                *cj = ((*cj as u64 + ail * (*bj as u64) % MODULUS) % MODULUS) as u32;
            }
        }
    }
    let leaves = (0..n_us)
        .map(|i| row_leaf(i as u32, &c[i * n_us..(i + 1) * n_us]))
        .collect();
    let tree = levels(leaves);
    let root = tree.last().expect("root")[0];
    let rows = opened_indices(nonce, &root, n, k)
        .into_iter()
        .map(|index| {
            let mut path = Vec::new();
            let mut pos = index as usize;
            for level in &tree[..tree.len() - 1] {
                let sibling = pos ^ 1;
                path.push(*level.get(sibling).unwrap_or(&level[pos]));
                pos /= 2;
            }
            OpenedRow {
                index,
                values: c[index as usize * n_us..(index as usize + 1) * n_us].to_vec(),
                path,
            }
        })
        .collect();
    MatmulProof { root, rows }
}

/// Verifier: the opened rows are the ones the root selects, each is in the
/// committed tree, and each passes Freivalds' test.
pub fn verify(nonce: &[u8; 32], n: u32, k: u32, proof: &MatmulProof) -> bool {
    if n == 0 || n > MAX_DIMENSION || k == 0 || k > MAX_OPENED_ROWS {
        return false;
    }
    let expected = opened_indices(nonce, &proof.root, n, k);
    if proof.rows.len() != expected.len()
        || proof.rows.iter().zip(&expected).any(|(r, i)| r.index != *i)
    {
        return false;
    }
    let n_us = n as usize;
    let (a, b) = inputs(nonce, n);
    let r = challenge_vector(nonce, &proof.root, n);
    // B·r once.
    let br: Vec<u32> = (0..n_us)
        .map(|l| dot(&b[l * n_us..(l + 1) * n_us], &r) as u32)
        .collect();
    proof.rows.iter().all(|row| {
        if row.values.len() != n_us || row.values.iter().any(|v| *v as u64 >= MODULUS) {
            return false;
        }
        // Merkle path from the row to the root.
        let mut node = row_leaf(row.index, &row.values);
        let mut pos = row.index as usize;
        for sibling in &row.path {
            node = if pos.is_multiple_of(2) {
                parent(&node, sibling)
            } else {
                parent(sibling, &node)
            };
            pos /= 2;
        }
        if node != proof.root {
            return false;
        }
        // Freivalds: C[i]·r == A[i]·(B·r).
        let i = row.index as usize;
        dot(&row.values, &r) == dot(&a[i * n_us..(i + 1) * n_us], &br)
    })
}

/// Multiply-adds a proof of dimension `n` stands for.
pub fn work_units(n: u32) -> u64 {
    (n as u64).pow(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_honest_product_verifies() {
        let proof = prove(&[3; 32], 32, 8);
        assert!(verify(&[3; 32], 32, 8, &proof));
    }

    #[test]
    fn a_wrong_value_in_an_opened_row_fails() {
        let mut proof = prove(&[3; 32], 32, 8);
        proof.rows[0].values[5] = (proof.rows[0].values[5] + 1) % MODULUS as u32;
        assert!(!verify(&[3; 32], 32, 8, &proof));
    }

    #[test]
    fn rows_other_than_the_selected_ones_fail() {
        let mut proof = prove(&[3; 32], 32, 8);
        proof.rows.swap(0, 1);
        assert!(!verify(&[3; 32], 32, 8, &proof));
        let other = prove(&[4; 32], 32, 8);
        assert!(!verify(&[3; 32], 32, 8, &other), "work for another nonce");
    }

    #[test]
    fn a_product_computed_for_other_inputs_fails_freivalds() {
        // Commit honestly to the product of the wrong matrices: the paths
        // hold, the test does not.
        let wrong = prove(&[9; 32], 32, 8);
        let mut forged = wrong.clone();
        forged.rows = opened_indices(&[3; 32], &wrong.root, 32, 8)
            .into_iter()
            .map(|index| OpenedRow {
                index,
                values: vec![1; 32],
                path: vec![],
            })
            .collect();
        assert!(!verify(&[3; 32], 32, 8, &forged));
    }

    #[test]
    fn oversized_requests_are_refused() {
        let proof = prove(&[3; 32], 8, 4);
        assert!(!verify(&[3; 32], MAX_DIMENSION + 1, 4, &proof));
        assert!(!verify(&[3; 32], 8, MAX_OPENED_ROWS + 1, &proof));
    }
}
