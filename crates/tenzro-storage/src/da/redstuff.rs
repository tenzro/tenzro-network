//! Two-dimensional Reed-Solomon encoding for the committee data-availability
//! store (Red Stuff).
//!
//! This module is the pure, dependency-light core: it turns a blob into a set
//! of per-node sliver pairs plus a binding commitment, and turns a quorum of
//! slivers back into the blob. It has no networking, no validator keys, and no
//! knowledge of the attestation certificate — those live in the node layer,
//! which drives this core to distribute slivers over a libp2p protocol and
//! collect `2f+1` signatures into an availability certificate.
//!
//! # Encoding shape
//!
//! For a committee of `n = 3f+1` nodes tolerating `f` Byzantine faults, the
//! blob is arranged into an `(f+1) × (2f+1)` matrix of equal-size **source
//! symbols** (zero-padded; the true byte length is carried separately so the
//! padding is stripped on decode). Two independent Reed-Solomon codes extend it
//! along each dimension:
//!
//! - **Primary dimension.** Each of the `2f+1` columns is a `(f+1)`-symbol
//!   codeword extended to `n` symbols (`ReedSolomon::new(f+1, n-(f+1))`). Node
//!   `i` receives extended row `i` — its **primary sliver** of `2f+1` symbols.
//! - **Secondary dimension.** Each of the `f+1` rows is a `(2f+1)`-symbol
//!   codeword extended to `n` symbols (`ReedSolomon::new(2f+1, n-(2f+1))`). Node
//!   `i` receives extended column `i` — its **secondary sliver** of `f+1`
//!   symbols.
//!
//! Total encoded volume is `n × (f+1) + n × (2f+1) = n(3f+2)` symbols against a
//! source of `(f+1)(2f+1)` symbols — a replication factor that tends to 4.5×
//! for large `f`, versus 3× for a naive `(f+1)-of-n` single-dimension code with
//! the same fault tolerance.
//!
//! # Reconstruction
//!
//! Recovering the blob needs any `2f+1` correct **secondary slivers**: their
//! `2f+1` symbols per row are enough to Reed-Solomon-decode every source row.
//! Equivalently `f+1` correct **primary slivers** recover every source column.
//! Each sliver is verified against the blob's Merkle commitment before use, so
//! a corrupt or forged sliver is discarded rather than trusted, and the decoded
//! blob is re-encoded to confirm its commitment matches the one the writer
//! bound — mismatched bytes fail closed.

use crate::error::{Result, StorageError};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::primitives::Hash;

/// Domain-separation tag for a leaf commitment over one sliver.
const LEAF_TAG: &[u8] = b"tenzro/redstuff/sliver";
/// Domain-separation tag for an internal Merkle node.
const NODE_TAG: &[u8] = b"tenzro/redstuff/node";
/// Domain-separation tag binding the blob commitment to its metadata.
const BLOB_TAG: &[u8] = b"tenzro/redstuff/blob";

/// Committee dimensions for a Red Stuff encoding, derived from the fault
/// bound `f`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeShape {
    /// Byzantine fault bound. The committee is `n = 3f+1` nodes.
    pub f: usize,
}

impl CommitteeShape {
    /// Build a shape from a fault bound. `f` must be at least 1 (a committee of
    /// `n = 3f+1 = 4` is the smallest that tolerates a single fault).
    pub fn from_fault_bound(f: usize) -> Result<Self> {
        if f == 0 {
            return Err(StorageError::InvalidValue(
                "Red Stuff fault bound f must be >= 1".into(),
            ));
        }
        Ok(Self { f })
    }

    /// Derive the shape from a committee size `n`, taking the largest `f` with
    /// `3f+1 <= n`. Requires `n >= 4`.
    pub fn from_committee_size(n: usize) -> Result<Self> {
        if n < 4 {
            return Err(StorageError::InvalidValue(format!(
                "Red Stuff committee needs n >= 4, got {n}"
            )));
        }
        Self::from_fault_bound((n - 1) / 3)
    }

    /// Committee size `n = 3f+1`.
    pub fn n(&self) -> usize {
        3 * self.f + 1
    }

    /// Source-matrix rows (`f+1`), and the primary-dimension code dimension.
    pub fn rows(&self) -> usize {
        self.f + 1
    }

    /// Source-matrix columns (`2f+1`), and the secondary-dimension code
    /// dimension. Also the number of correct secondary slivers needed to
    /// reconstruct.
    pub fn cols(&self) -> usize {
        2 * self.f + 1
    }

    /// Quorum threshold `2f+1` — the number of signed acknowledgments required
    /// for an availability certificate, and the number of correct secondary
    /// slivers required to reconstruct.
    pub fn quorum(&self) -> usize {
        2 * self.f + 1
    }
}

/// One node's share of an encoded blob: a primary sliver (a source-matrix row
/// extended along the primary dimension) and a secondary sliver (a source-matrix
/// column extended along the secondary dimension), with the Merkle proofs that
/// bind both to the blob commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliverPair {
    /// Committee index `0..n` this pair is assigned to.
    pub node_index: usize,
    /// Primary sliver: `cols()` symbols, each `symbol_len` bytes. This is
    /// extended row `node_index` of the primary code.
    pub primary: Vec<u8>,
    /// Secondary sliver: `rows()` symbols, each `symbol_len` bytes. This is
    /// extended column `node_index` of the secondary code.
    pub secondary: Vec<u8>,
    /// Merkle inclusion proof binding the primary sliver leaf to
    /// `EncodedBlob::commitment`. Sibling hashes bottom-up.
    pub primary_proof: Vec<Hash>,
    /// Merkle inclusion proof binding the secondary sliver leaf to
    /// `EncodedBlob::commitment`.
    pub secondary_proof: Vec<Hash>,
}

/// The full output of encoding a blob: the binding commitment, the metadata a
/// reader needs to reconstruct, and one [`SliverPair`] per committee node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedBlob {
    /// Committee shape the blob was encoded for.
    pub shape: CommitteeShape,
    /// True (pre-padding) byte length of the blob.
    pub blob_len: u64,
    /// Bytes per source/encoded symbol. Every sliver symbol is this long.
    pub symbol_len: usize,
    /// Binding commitment: a Merkle root over all `2n` sliver leaves, hashed
    /// together with the shape and length. Written to the chain as the
    /// blob's "point of availability" identity — a reader confirms a decoded
    /// blob re-encodes to this exact value.
    pub commitment: Hash,
    /// One sliver pair per committee node, index `0..n`.
    pub slivers: Vec<SliverPair>,
}

impl EncodedBlob {
    /// The 32-byte blob identifier used as a DA locator: the commitment bytes.
    pub fn blob_id(&self) -> Hash {
        self.commitment
    }
}

fn hash_leaf(kind: u8, node_index: usize, symbols: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(LEAF_TAG);
    h.update([kind]);
    h.update((node_index as u64).to_le_bytes());
    h.update(symbols);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Hash::new(out)
}

fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(NODE_TAG);
    h.update(left.as_bytes());
    h.update(right.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Hash::new(out)
}

/// Build a Merkle tree over `leaves`, returning the root and, for each leaf, its
/// bottom-up sibling path. Odd levels duplicate the last node (standard
/// last-node promotion).
fn merkle_tree(leaves: &[Hash]) -> (Hash, Vec<Vec<Hash>>) {
    if leaves.is_empty() {
        return (Hash::new([0u8; 32]), Vec::new());
    }
    let mut proofs: Vec<Vec<Hash>> = vec![Vec::new(); leaves.len()];
    // Track, per original leaf, its index within the current level.
    let mut positions: Vec<usize> = (0..leaves.len()).collect();
    let mut level: Vec<Hash> = leaves.to_vec();

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(hash_node(&left, &right));
        }
        for (leaf, pos) in proofs.iter_mut().zip(positions.iter_mut()) {
            let sibling = if *pos % 2 == 0 {
                // Left child: sibling is the right node, or self when promoted.
                let s = *pos + 1;
                if s < level.len() { level[s] } else { level[*pos] }
            } else {
                level[*pos - 1]
            };
            leaf.push(sibling);
            *pos /= 2;
        }
        level = next;
    }
    (level[0], proofs)
}

/// Recompute a Merkle root from a leaf and its sibling path. The caller supplies
/// the leaf's original index so the left/right ordering at each level matches
/// the tree that produced `proof`.
fn merkle_root_from_proof(leaf: Hash, mut index: usize, proof: &[Hash]) -> Hash {
    let mut acc = leaf;
    for sibling in proof {
        acc = if index.is_multiple_of(2) {
            hash_node(&acc, sibling)
        } else {
            hash_node(sibling, &acc)
        };
        index /= 2;
    }
    acc
}

/// Fold the sliver-leaf Merkle root together with the shape/length metadata into
/// the final blob commitment.
fn blob_commitment(shape: CommitteeShape, blob_len: u64, symbol_len: usize, sliver_root: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(BLOB_TAG);
    h.update((shape.f as u64).to_le_bytes());
    h.update(blob_len.to_le_bytes());
    h.update((symbol_len as u64).to_le_bytes());
    h.update(sliver_root.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Hash::new(out)
}

/// Encode `data` into `2n` slivers under the Red Stuff two-dimensional code for
/// the given committee shape.
pub fn encode(data: &[u8], shape: CommitteeShape) -> Result<EncodedBlob> {
    let rows = shape.rows();
    let cols = shape.cols();
    let n = shape.n();

    // Source matrix is rows×cols symbols; pick a symbol length so the whole
    // blob fits, and pad the tail with zeros. blob_len records the true length.
    let source_symbols = rows * cols;
    let symbol_len = data.len().div_ceil(source_symbols).max(1);

    // matrix[r][c] = source symbol at (row r, col c), symbol_len bytes.
    let mut matrix = vec![vec![0u8; symbol_len]; source_symbols];
    for (i, chunk) in data.chunks(symbol_len).enumerate() {
        matrix[i][..chunk.len()].copy_from_slice(chunk);
    }
    let at = |r: usize, c: usize| &matrix[r * cols + c];

    // Primary code: each column is a codeword of `rows` data symbols extended
    // to `n`. primary_rows[i] is the extended row for node i (cols symbols).
    let primary_rs = ReedSolomon::new(rows, n - rows)
        .map_err(|e| StorageError::Generic(format!("primary RS init: {e}")))?;
    // Build, per column, the n extended symbols; then transpose into per-node rows.
    let mut primary_ext: Vec<Vec<Vec<u8>>> = Vec::with_capacity(cols); // [col][node] = symbol
    for c in 0..cols {
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(n);
        for r in 0..rows {
            shards.push(at(r, c).clone());
        }
        for _ in rows..n {
            shards.push(vec![0u8; symbol_len]);
        }
        primary_rs
            .encode(&mut shards)
            .map_err(|e| StorageError::Generic(format!("primary encode col {c}: {e}")))?;
        primary_ext.push(shards);
    }
    // primary_rows[node] = concatenation of that node's symbol from every column.
    let mut primary_rows: Vec<Vec<u8>> = vec![Vec::with_capacity(cols * symbol_len); n];
    for node_symbols in primary_ext.iter() {
        for (node, sym) in node_symbols.iter().enumerate() {
            primary_rows[node].extend_from_slice(sym);
        }
    }

    // Secondary code: each row is a codeword of `cols` data symbols extended to
    // `n`. secondary_cols[i] is the extended column for node i (rows symbols).
    let secondary_rs = ReedSolomon::new(cols, n - cols)
        .map_err(|e| StorageError::Generic(format!("secondary RS init: {e}")))?;
    let mut secondary_ext: Vec<Vec<Vec<u8>>> = Vec::with_capacity(rows); // [row][node] = symbol
    for r in 0..rows {
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(n);
        for c in 0..cols {
            shards.push(at(r, c).clone());
        }
        for _ in cols..n {
            shards.push(vec![0u8; symbol_len]);
        }
        secondary_rs
            .encode(&mut shards)
            .map_err(|e| StorageError::Generic(format!("secondary encode row {r}: {e}")))?;
        secondary_ext.push(shards);
    }
    let mut secondary_cols: Vec<Vec<u8>> = vec![Vec::with_capacity(rows * symbol_len); n];
    for node_symbols in secondary_ext.iter() {
        for (node, sym) in node_symbols.iter().enumerate() {
            secondary_cols[node].extend_from_slice(sym);
        }
    }

    // Leaves: node 0..n primary, then node 0..n secondary. This ordering is
    // fixed and both writer and reader recompute leaf indices the same way.
    let mut leaves = Vec::with_capacity(2 * n);
    for (node, primary) in primary_rows.iter().enumerate() {
        leaves.push(hash_leaf(0, node, primary));
    }
    for (node, secondary) in secondary_cols.iter().enumerate() {
        leaves.push(hash_leaf(1, node, secondary));
    }
    let (sliver_root, proofs) = merkle_tree(&leaves);
    let commitment = blob_commitment(shape, data.len() as u64, symbol_len, &sliver_root);

    let mut slivers = Vec::with_capacity(n);
    for node in 0..n {
        slivers.push(SliverPair {
            node_index: node,
            primary: std::mem::take(&mut primary_rows[node]),
            secondary: std::mem::take(&mut secondary_cols[node]),
            primary_proof: proofs[node].clone(),
            secondary_proof: proofs[n + node].clone(),
        });
    }

    Ok(EncodedBlob {
        shape,
        blob_len: data.len() as u64,
        symbol_len,
        commitment,
        slivers,
    })
}

/// Verify that a sliver pair binds to `commitment` under the given shape/length.
/// Both the primary and secondary leaves must produce the recorded commitment.
pub fn verify_sliver(
    sliver: &SliverPair,
    shape: CommitteeShape,
    blob_len: u64,
    symbol_len: usize,
    commitment: &Hash,
) -> bool {
    let n = shape.n();
    if sliver.node_index >= n {
        return false;
    }
    if sliver.primary.len() != shape.cols() * symbol_len
        || sliver.secondary.len() != shape.rows() * symbol_len
    {
        return false;
    }
    let primary_leaf = hash_leaf(0, sliver.node_index, &sliver.primary);
    let secondary_leaf = hash_leaf(1, sliver.node_index, &sliver.secondary);
    let primary_root = merkle_root_from_proof(primary_leaf, sliver.node_index, &sliver.primary_proof);
    let secondary_root =
        merkle_root_from_proof(secondary_leaf, n + sliver.node_index, &sliver.secondary_proof);
    // Both proofs must reach the same sliver-leaf root, which folds into the
    // commitment. Recompute the commitment from that root and compare.
    if primary_root != secondary_root {
        return false;
    }
    &blob_commitment(shape, blob_len, symbol_len, &primary_root) == commitment
}

/// Reconstruct the blob from a set of sliver pairs.
///
/// Every supplied sliver is verified against `commitment` first; any that fail
/// (corrupt, forged, or wrong metadata) are discarded. Reconstruction uses the
/// secondary dimension: each source row is a `cols`-symbol codeword whose
/// symbols are spread one-per-node across the secondary slivers, so `cols =
/// 2f+1` correct secondary slivers Reed-Solomon-decode every row. The decoded
/// blob is re-encoded and its commitment compared to `commitment`; a mismatch
/// fails closed.
pub fn reconstruct(
    slivers: &[SliverPair],
    shape: CommitteeShape,
    blob_len: u64,
    symbol_len: usize,
    commitment: &Hash,
) -> Result<Vec<u8>> {
    let rows = shape.rows();
    let cols = shape.cols();
    let n = shape.n();

    // Keep only verified slivers, deduplicated by node index.
    let mut present: Vec<Option<&SliverPair>> = vec![None; n];
    let mut valid = 0usize;
    for s in slivers {
        if s.node_index >= n || present[s.node_index].is_some() {
            continue;
        }
        if verify_sliver(s, shape, blob_len, symbol_len, commitment) {
            present[s.node_index] = Some(s);
            valid += 1;
        }
    }
    if valid < cols {
        return Err(StorageError::InvalidValue(format!(
            "Red Stuff reconstruct needs {cols} valid secondary slivers, have {valid}"
        )));
    }

    let secondary_rs = ReedSolomon::new(cols, n - cols)
        .map_err(|e| StorageError::Generic(format!("secondary RS init: {e}")))?;

    // For each source row r, gather the n per-node symbols (symbol r of each
    // node's secondary sliver), decode, and take the first `cols` data symbols.
    let mut matrix = vec![vec![0u8; symbol_len]; rows * cols];
    for r in 0..rows {
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; n];
        for (node, slot) in present.iter().enumerate() {
            if let Some(s) = slot {
                let start = r * symbol_len;
                shards[node] = Some(s.secondary[start..start + symbol_len].to_vec());
            }
        }
        secondary_rs
            .reconstruct(&mut shards)
            .map_err(|e| StorageError::Generic(format!("secondary reconstruct row {r}: {e}")))?;
        for c in 0..cols {
            let sym = shards[c]
                .as_ref()
                .ok_or_else(|| StorageError::Generic("row symbol missing after decode".into()))?;
            matrix[r * cols + c].copy_from_slice(sym);
        }
    }

    // Flatten source matrix row-major and strip padding.
    let mut out = Vec::with_capacity(rows * cols * symbol_len);
    for sym in &matrix {
        out.extend_from_slice(sym);
    }
    out.truncate(blob_len as usize);

    // Belt-and-braces: re-encode and confirm the commitment matches.
    let re = encode(&out, shape)?;
    if &re.commitment != commitment {
        return Err(StorageError::InvalidValue(
            "Red Stuff reconstruct: re-encoded commitment does not match".into(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_derivations() {
        let s = CommitteeShape::from_fault_bound(1).unwrap();
        assert_eq!(s.n(), 4);
        assert_eq!(s.rows(), 2);
        assert_eq!(s.cols(), 3);
        assert_eq!(s.quorum(), 3);

        // n=10 → largest f with 3f+1<=10 is f=3 (n=10).
        let s10 = CommitteeShape::from_committee_size(10).unwrap();
        assert_eq!(s10.f, 3);
        assert_eq!(s10.n(), 10);
        assert_eq!(s10.quorum(), 7);

        assert!(CommitteeShape::from_fault_bound(0).is_err());
        assert!(CommitteeShape::from_committee_size(3).is_err());
    }

    #[test]
    fn encode_produces_n_sliver_pairs() {
        let shape = CommitteeShape::from_fault_bound(2).unwrap(); // n=7
        let data = vec![42u8; 5000];
        let enc = encode(&data, shape).unwrap();
        assert_eq!(enc.slivers.len(), 7);
        assert_eq!(enc.blob_len, 5000);
        for s in &enc.slivers {
            assert_eq!(s.primary.len(), shape.cols() * enc.symbol_len);
            assert_eq!(s.secondary.len(), shape.rows() * enc.symbol_len);
        }
    }

    #[test]
    fn every_sliver_binds_to_commitment() {
        let shape = CommitteeShape::from_fault_bound(2).unwrap();
        let data = b"red stuff two-dimensional erasure encoding round trip".to_vec();
        let enc = encode(&data, shape).unwrap();
        for s in &enc.slivers {
            assert!(verify_sliver(s, shape, enc.blob_len, enc.symbol_len, &enc.commitment));
        }
    }

    #[test]
    fn reconstruct_from_exact_quorum() {
        let shape = CommitteeShape::from_fault_bound(2).unwrap(); // n=7, quorum=5
        let data = vec![9u8; 4096];
        let enc = encode(&data, shape).unwrap();
        // Take exactly cols() = 5 secondary slivers.
        let subset: Vec<SliverPair> = enc.slivers.iter().take(shape.cols()).cloned().collect();
        let back = reconstruct(&subset, shape, enc.blob_len, enc.symbol_len, &enc.commitment).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn reconstruct_tolerates_f_missing() {
        let shape = CommitteeShape::from_fault_bound(3).unwrap(); // n=10, quorum=7
        let data: Vec<u8> = (0..8000u32).map(|i| (i % 251) as u8).collect();
        let enc = encode(&data, shape).unwrap();
        // Drop f = 3 slivers (nodes 0,1,2): 7 remain == quorum.
        let subset: Vec<SliverPair> =
            enc.slivers.iter().filter(|s| s.node_index >= 3).cloned().collect();
        assert_eq!(subset.len(), 7);
        let back = reconstruct(&subset, shape, enc.blob_len, enc.symbol_len, &enc.commitment).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn reconstruct_fails_below_quorum() {
        let shape = CommitteeShape::from_fault_bound(2).unwrap(); // quorum=5
        let data = vec![1u8; 1000];
        let enc = encode(&data, shape).unwrap();
        let subset: Vec<SliverPair> = enc.slivers.iter().take(4).cloned().collect();
        assert!(reconstruct(&subset, shape, enc.blob_len, enc.symbol_len, &enc.commitment).is_err());
    }

    #[test]
    fn forged_sliver_is_discarded() {
        let shape = CommitteeShape::from_fault_bound(2).unwrap();
        let data = vec![7u8; 3000];
        let enc = encode(&data, shape).unwrap();
        let mut tampered = enc.slivers.clone();
        // Corrupt node 0's secondary bytes without fixing the proof.
        tampered[0].secondary[0] ^= 0xFF;
        assert!(!verify_sliver(
            &tampered[0],
            shape,
            enc.blob_len,
            enc.symbol_len,
            &enc.commitment
        ));
        // With the forged sliver plus 4 honest = only 4 valid < quorum 5 → fail;
        // but all 7 present (1 forged, 6 honest) still reconstruct.
        let back = reconstruct(&tampered, shape, enc.blob_len, enc.symbol_len, &enc.commitment).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn wrong_commitment_rejects_all() {
        let shape = CommitteeShape::from_fault_bound(1).unwrap();
        let data = vec![5u8; 256];
        let enc = encode(&data, shape).unwrap();
        let bogus = Hash::new([0xAAu8; 32]);
        for s in &enc.slivers {
            assert!(!verify_sliver(s, shape, enc.blob_len, enc.symbol_len, &bogus));
        }
        assert!(reconstruct(&enc.slivers, shape, enc.blob_len, enc.symbol_len, &bogus).is_err());
    }

    #[test]
    fn empty_and_small_blobs_round_trip() {
        let shape = CommitteeShape::from_fault_bound(1).unwrap();
        for data in [Vec::new(), vec![1u8], b"hi".to_vec()] {
            let enc = encode(&data, shape).unwrap();
            let subset: Vec<SliverPair> = enc.slivers.iter().take(shape.cols()).cloned().collect();
            let back =
                reconstruct(&subset, shape, enc.blob_len, enc.symbol_len, &enc.commitment).unwrap();
            assert_eq!(back, data);
        }
    }
}
