//! TON cells: bags of cells, cell hashes at every level, Merkle proofs, and
//! the bit-level reading the block structures need.
//!
//! A cell holds up to 1023 bits and up to four references. Its hash covers
//! its descriptor bytes, its data and its references' depths and hashes;
//! a pruned-branch cell stands in for a subtree it carries only the hashes
//! and depths of, at the levels below its own, so a Merkle proof (an exotic
//! cell over a tree with pruned branches) hashes, at level 0, to the root
//! hash of the full tree it was cut from. Reading never looks inside a
//! pruned branch: a proof that pruned something the reader needs is refused.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::error::{BridgeError, Result};

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("ton cell: {}", what.into()))
}

/// Most cells a bag may hold.
pub const MAX_CELLS: usize = 1 << 17;

/// What kind of cell this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellKind {
    Ordinary,
    PrunedBranch,
    Library,
    MerkleProof,
    MerkleUpdate,
}

/// A cell, with its hashes and depths at every significant level.
#[derive(Debug)]
pub struct Cell {
    pub kind: CellKind,
    /// The data, padded to whole bytes.
    pub data: Vec<u8>,
    /// How many of the data's bits are used.
    pub bits: usize,
    pub refs: Vec<Arc<Cell>>,
    level_mask: u8,
    hashes: Vec<[u8; 32]>,
    depths: Vec<u16>,
}

fn hashes_count(mask: u8) -> usize {
    mask.count_ones() as usize + 1
}

fn apply(mask: u8, level: u8) -> u8 {
    mask & ((1u8 << level) - 1)
}

fn level_of(mask: u8) -> u8 {
    8 - mask.leading_zeros() as u8
}

impl Cell {
    /// Build a cell, checking an exotic cell's layout and computing its
    /// hashes and depths.
    pub fn new(
        exotic: bool,
        data: Vec<u8>,
        bits: usize,
        refs: Vec<Arc<Cell>>,
    ) -> Result<Arc<Cell>> {
        if bits > 1023 || refs.len() > 4 || data.len() != bits.div_ceil(8) {
            return Err(bad("a cell holds at most 1023 bits and four references"));
        }
        let kind = if !exotic {
            CellKind::Ordinary
        } else {
            match data.first() {
                Some(1) => CellKind::PrunedBranch,
                Some(2) => CellKind::Library,
                Some(3) => CellKind::MerkleProof,
                Some(4) => CellKind::MerkleUpdate,
                _ => return Err(bad("unknown exotic cell type")),
            }
        };
        let level_mask = match kind {
            CellKind::Ordinary => refs.iter().fold(0, |m, r| m | r.level_mask),
            CellKind::PrunedBranch => {
                let mask = *data
                    .get(1)
                    .ok_or_else(|| bad("a pruned branch without its level"))?;
                let n = hashes_count(mask) - 1;
                if mask == 0 || mask > 7 || !refs.is_empty() || bits != (2 + n * 34) * 8 {
                    return Err(bad("a malformed pruned branch"));
                }
                mask
            }
            CellKind::Library => {
                if bits != 8 + 256 || !refs.is_empty() {
                    return Err(bad("a malformed library cell"));
                }
                0
            }
            CellKind::MerkleProof => {
                if bits != 8 + 256 + 16 || refs.len() != 1 {
                    return Err(bad("a malformed Merkle proof cell"));
                }
                refs[0].level_mask >> 1
            }
            CellKind::MerkleUpdate => {
                if bits != 8 + 2 * (256 + 16) || refs.len() != 2 {
                    return Err(bad("a malformed Merkle update cell"));
                }
                (refs[0].level_mask | refs[1].level_mask) >> 1
            }
        };
        let mut cell = Cell {
            kind,
            data,
            bits,
            refs,
            level_mask,
            hashes: Vec::new(),
            depths: Vec::new(),
        };
        cell.compute()?;
        let cell = Arc::new(cell);
        match kind {
            CellKind::MerkleProof => {
                let (h, d) = (
                    cell.data[1..33].to_vec(),
                    u16::from_be_bytes([cell.data[33], cell.data[34]]),
                );
                if cell.refs[0].hash(0).as_slice() != h.as_slice() || cell.refs[0].depth(0) != d {
                    return Err(bad("a Merkle proof's hash is not its tree's"));
                }
            }
            CellKind::MerkleUpdate => {
                for (i, r) in cell.refs.iter().enumerate() {
                    let o = 1 + 32 * i;
                    let d = u16::from_be_bytes([cell.data[65 + 2 * i], cell.data[66 + 2 * i]]);
                    if r.hash(0).as_slice() != &cell.data[o..o + 32] || r.depth(0) != d {
                        return Err(bad("a Merkle update's hash is not its tree's"));
                    }
                }
            }
            _ => {}
        }
        Ok(cell)
    }

    fn d1(&self, mask: u8) -> u8 {
        self.refs.len() as u8
            + if self.kind == CellKind::Ordinary {
                0
            } else {
                8
            }
            + 32 * mask
    }

    fn d2(&self) -> u8 {
        (self.bits / 8 + self.bits.div_ceil(8)) as u8
    }

    /// The data with its completion tag, as hashing and serialization use it.
    fn padded(&self) -> Vec<u8> {
        let mut d = self.data.clone();
        if !self.bits.is_multiple_of(8) {
            let last = d.len() - 1;
            d[last] = (d[last] & !(0xffu8 >> (self.bits % 8))) | (0x80 >> (self.bits % 8));
        }
        d
    }

    fn compute(&mut self) -> Result<()> {
        let level = level_of(self.level_mask);
        let (offset, stored) = if self.kind == CellKind::PrunedBranch {
            let n = hashes_count(self.level_mask) - 1;
            (n, n)
        } else {
            (0, 0)
        };
        if stored > 0 {
            for i in 0..stored {
                let o = 2 + 32 * i;
                self.hashes
                    .push(self.data[o..o + 32].try_into().expect("32 bytes"));
            }
            for i in 0..stored {
                let o = 2 + 32 * stored + 2 * i;
                self.depths
                    .push(u16::from_be_bytes([self.data[o], self.data[o + 1]]));
            }
        }
        let mut computed = 0usize;
        for l in 0..=level {
            if l > 0 && self.level_mask & (1 << (l - 1)) == 0 {
                continue;
            }
            let hash_i = hashes_count(apply(self.level_mask, l)) - 1;
            if hash_i < offset {
                continue;
            }
            let mut h = Sha256::new();
            let mask_l = if self.kind == CellKind::PrunedBranch {
                self.level_mask
            } else {
                apply(self.level_mask, l)
            };
            h.update([self.d1(mask_l), self.d2()]);
            if computed == 0 {
                h.update(self.padded());
            } else {
                h.update(self.hashes[self.hashes.len() - 1]);
            }
            let ref_level = if matches!(self.kind, CellKind::MerkleProof | CellKind::MerkleUpdate) {
                l + 1
            } else {
                l
            };
            let mut depth = 0u16;
            for r in &self.refs {
                let d = r.depth(ref_level);
                h.update(d.to_be_bytes());
                depth = depth.max(d.checked_add(1).ok_or_else(|| bad("too deep"))?);
            }
            for r in &self.refs {
                h.update(r.hash(ref_level));
            }
            if depth > 1024 {
                return Err(bad("a tree deeper than 1024 cells"));
            }
            self.hashes.push(h.finalize().into());
            self.depths.push(depth);
            computed += 1;
        }
        Ok(())
    }

    /// The level mask.
    pub fn level_mask(&self) -> u8 {
        self.level_mask
    }

    fn index(&self, level: u8) -> usize {
        (hashes_count(apply(self.level_mask, level.min(3))) - 1).min(self.hashes.len() - 1)
    }

    /// The hash at `level`; at level 3 (or the cell's own level) the
    /// representation hash.
    pub fn hash(&self, level: u8) -> [u8; 32] {
        self.hashes[self.index(level)]
    }

    /// The depth at `level`.
    pub fn depth(&self, level: u8) -> u16 {
        self.depths[self.index(level)]
    }

    /// The representation hash.
    pub fn repr_hash(&self) -> [u8; 32] {
        self.hash(3)
    }

    /// A reader over this cell; refused for a pruned branch, whose content
    /// the proof left out.
    pub fn parse(self: &Arc<Self>) -> Result<Slice> {
        if self.kind == CellKind::PrunedBranch {
            return Err(bad("the proof pruned a cell that is needed"));
        }
        READS.with(|r| {
            if let Some(set) = r.borrow_mut().as_mut() {
                set.insert(self.repr_hash());
            }
        });
        Ok(Slice {
            cell: self.clone(),
            pos: 0,
            ref_pos: 0,
        })
    }
}

thread_local! {
    static READS: std::cell::RefCell<Option<std::collections::HashSet<[u8; 32]>>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` and return, with its result, every cell it read: what a Merkle
/// proof must keep for the same reading to succeed on the proof alone.
pub fn record_reads<T>(f: impl FnOnce() -> T) -> (T, std::collections::HashSet<[u8; 32]>) {
    READS.with(|r| *r.borrow_mut() = Some(std::collections::HashSet::new()));
    let out = f();
    let reads = READS.with(|r| r.borrow_mut().take()).unwrap_or_default();
    (out, reads)
}

/// Parse a bag of cells and return its roots.
pub fn parse_boc(b: &[u8]) -> Result<Vec<Arc<Cell>>> {
    let take = |p: &mut usize, n: usize| -> Result<u64> {
        let s = b
            .get(*p..*p + n)
            .ok_or_else(|| bad("truncated bag of cells"))?;
        *p += n;
        Ok(s.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
    };
    if b.get(..4) != Some(&[0xb5, 0xee, 0x9c, 0x72][..]) {
        return Err(bad("not a bag of cells"));
    }
    let mut p = 4;
    let flags = take(&mut p, 1)? as u8;
    let (has_index, has_crc, size) = (flags & 0x80 != 0, flags & 0x40 != 0, (flags & 7) as usize);
    if size == 0 || size > 4 || flags & 0x18 != 0 {
        return Err(bad("bad bag-of-cells header"));
    }
    let off = take(&mut p, 1)? as usize;
    if off == 0 || off > 8 {
        return Err(bad("bad offset size"));
    }
    let cells = take(&mut p, size)? as usize;
    let roots = take(&mut p, size)? as usize;
    let absent = take(&mut p, size)?;
    let total = take(&mut p, off)? as usize;
    if cells == 0 || cells > MAX_CELLS || roots == 0 || roots > cells || absent != 0 {
        return Err(bad("bad cell counts"));
    }
    let root_idx = (0..roots)
        .map(|_| take(&mut p, size).map(|v| v as usize))
        .collect::<Result<Vec<_>>>()?;
    if root_idx.iter().any(|r| *r >= cells) {
        return Err(bad("a root index past the last cell"));
    }
    if has_index {
        p += cells * off;
    }
    let start = p;
    let mut raw = Vec::with_capacity(cells);
    for i in 0..cells {
        let d1 = take(&mut p, 1)? as u8;
        let d2 = take(&mut p, 1)? as u8;
        let nrefs = (d1 & 7) as usize;
        if nrefs > 4 {
            return Err(bad("bad cell descriptor"));
        }
        let exotic = d1 & 8 != 0;
        if d1 & 16 != 0 {
            // Stored hashes and depths, recomputed here rather than trusted.
            p += hashes_count(d1 >> 5) * 34;
        }
        let nbytes = d2.div_ceil(2) as usize;
        let mut data = b
            .get(p..p + nbytes)
            .ok_or_else(|| bad("truncated cell"))?
            .to_vec();
        p += nbytes;
        let bits = if d2 % 2 == 1 {
            let last = *data.last().ok_or_else(|| bad("empty padded cell"))?;
            if last == 0 {
                return Err(bad("a padded cell without its completion tag"));
            }
            let tz = last.trailing_zeros() as usize;
            let bits = nbytes * 8 - tz - 1;
            let li = data.len() - 1;
            data[li] &= !(0xffu8 >> (bits % 8)) | if bits.is_multiple_of(8) { 0xff } else { 0 };
            if bits.is_multiple_of(8) {
                data.pop();
            }
            bits
        } else {
            nbytes * 8
        };
        let refs = (0..nrefs)
            .map(|_| take(&mut p, size).map(|v| v as usize))
            .collect::<Result<Vec<_>>>()?;
        if refs.iter().any(|r| *r <= i || *r >= cells) {
            return Err(bad("references must point forward"));
        }
        raw.push((exotic, data, bits, refs));
    }
    if p - start != total {
        return Err(bad("the cell data length does not match"));
    }
    if has_crc {
        let crc = b.get(p..p + 4).ok_or_else(|| bad("missing checksum"))?;
        if crc32c(&b[..p]).to_le_bytes() != crc {
            return Err(bad("bad checksum"));
        }
        p += 4;
    }
    if p != b.len() {
        return Err(bad("trailing bytes after the bag of cells"));
    }
    let mut built: Vec<Option<Arc<Cell>>> = vec![None; cells];
    for i in (0..cells).rev() {
        let (exotic, data, bits, refs) = std::mem::take(&mut raw[i]);
        let refs = refs
            .iter()
            .map(|r| built[*r].clone().expect("built later index first"))
            .collect();
        built[i] = Some(Cell::new(exotic, data, bits, refs)?);
    }
    Ok(root_idx
        .iter()
        .map(|i| built[*i].clone().expect("built"))
        .collect())
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Serialize `root` as a bag of cells (one root, no index, no checksum).
pub fn serialize_boc(root: &Arc<Cell>) -> Vec<u8> {
    // Order cells so every reference points forward: a depth-first listing
    // with parents before children, each cell once.
    let mut order: Vec<Arc<Cell>> = Vec::new();
    let mut index: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();
    fn visit(
        c: &Arc<Cell>,
        order: &mut Vec<Arc<Cell>>,
        index: &mut std::collections::HashMap<[u8; 32], usize>,
    ) {
        if index.contains_key(&c.repr_hash()) {
            return;
        }
        index.insert(c.repr_hash(), usize::MAX);
        for r in &c.refs {
            visit(r, order, index);
        }
        order.push(c.clone());
    }
    visit(root, &mut order, &mut index);
    order.reverse();
    for (i, c) in order.iter().enumerate() {
        index.insert(c.repr_hash(), i);
    }
    let n = order.len();
    let size = (64 - (n as u64).leading_zeros()).div_ceil(8).max(1) as usize;
    let mut body = Vec::new();
    for c in &order {
        body.push(c.d1(c.level_mask));
        body.push(c.d2());
        body.extend_from_slice(&c.padded());
        for r in &c.refs {
            body.extend_from_slice(&(index[&r.repr_hash()] as u64).to_be_bytes()[8 - size..]);
        }
    }
    let off = (64 - (body.len() as u64).leading_zeros())
        .div_ceil(8)
        .max(1) as usize;
    let mut out = vec![0xb5, 0xee, 0x9c, 0x72, size as u8, off as u8];
    for v in [n as u64, 1, 0] {
        out.extend_from_slice(&v.to_be_bytes()[8 - size..]);
    }
    out.extend_from_slice(&(body.len() as u64).to_be_bytes()[8 - off..]);
    out.extend_from_slice(&0u64.to_be_bytes()[8 - size..]);
    out.extend_from_slice(&body);
    out
}

/// A Merkle proof of `root` that keeps the cells in `keep` (by
/// representation hash) and the path to each of them, and prunes every other
/// subtree.
pub fn merkle_proof(
    root: &Arc<Cell>,
    keep: &std::collections::HashSet<[u8; 32]>,
) -> Result<Arc<Cell>> {
    // A Merkle update or proof inside the tree is kept whole or pruned
    // whole: its cells hash one level up, and a cell shared with the read
    // path (an empty dictionary, say) is no reason to open it.
    fn merkle(c: &Cell) -> bool {
        matches!(c.kind, CellKind::MerkleProof | CellKind::MerkleUpdate)
    }
    fn needed(
        c: &Arc<Cell>,
        keep: &std::collections::HashSet<[u8; 32]>,
        memo: &mut std::collections::HashMap<[u8; 32], bool>,
    ) -> bool {
        if let Some(v) = memo.get(&c.repr_hash()) {
            return *v;
        }
        let v = keep.contains(&c.repr_hash())
            || (!merkle(c) && c.refs.iter().any(|r| needed(r, keep, memo)));
        memo.insert(c.repr_hash(), v);
        v
    }
    fn build(
        c: &Arc<Cell>,
        keep: &std::collections::HashSet<[u8; 32]>,
        memo: &mut std::collections::HashMap<[u8; 32], bool>,
    ) -> Result<Arc<Cell>> {
        if !needed(c, keep, memo) {
            // The branch keeps the cell's hash and depth at every level
            // significant below its own, so each level of every ancestor
            // hashes as it did over the whole cell.
            let mask = c.level_mask | 1;
            let levels: Vec<u8> = (0..level_of(mask))
                .filter(|l| *l == 0 || mask & (1 << (l - 1)) != 0)
                .collect();
            let mut data = vec![1u8, mask];
            for l in &levels {
                data.extend_from_slice(&c.hash(*l));
            }
            for l in &levels {
                data.extend_from_slice(&c.depth(*l).to_be_bytes());
            }
            let bits = data.len() * 8;
            return Cell::new(true, data, bits, Vec::new());
        }
        if merkle(c) {
            return Ok(c.clone());
        }
        let refs = c
            .refs
            .iter()
            .map(|r| build(r, keep, memo))
            .collect::<Result<Vec<_>>>()?;
        Cell::new(c.kind != CellKind::Ordinary, c.data.clone(), c.bits, refs)
    }
    let mut memo = std::collections::HashMap::new();
    let tree = build(root, keep, &mut memo)?;
    let mut data = vec![3u8];
    data.extend_from_slice(&root.hash(0));
    data.extend_from_slice(&root.depth(0).to_be_bytes());
    Cell::new(true, data, 8 + 256 + 16, vec![tree])
}

/// The tree a Merkle proof proves, checked to hash to `expected` at level 0.
pub fn proven_tree(proof: &Arc<Cell>, expected: &[u8; 32]) -> Result<Arc<Cell>> {
    if proof.kind != CellKind::MerkleProof {
        return Err(bad("not a Merkle proof"));
    }
    if &proof.data[1..33] != expected {
        return Err(bad("the proof is of another tree"));
    }
    Ok(proof.refs[0].clone())
}

/// A bit reader over one cell.
#[derive(Debug, Clone)]
pub struct Slice {
    cell: Arc<Cell>,
    pos: usize,
    ref_pos: usize,
}

impl Slice {
    /// The cell read.
    pub fn cell(&self) -> &Arc<Cell> {
        &self.cell
    }

    /// Bits left.
    pub fn remaining(&self) -> usize {
        self.cell.bits - self.pos
    }

    /// References left.
    pub fn refs_left(&self) -> usize {
        self.cell.refs.len() - self.ref_pos
    }

    pub fn bit(&mut self) -> Result<bool> {
        if self.pos >= self.cell.bits {
            return Err(bad("read past the end of a cell"));
        }
        let b = self.cell.data[self.pos / 8] >> (7 - self.pos % 8) & 1 == 1;
        self.pos += 1;
        Ok(b)
    }

    pub fn uint(&mut self, n: usize) -> Result<u64> {
        if n > 64 {
            return Err(bad("an integer wider than 64 bits"));
        }
        (0..n).try_fold(0u64, |v, _| Ok((v << 1) | u64::from(self.bit()?)))
    }

    pub fn int(&mut self, n: usize) -> Result<i64> {
        let v = self.uint(n)?;
        Ok(if n > 0 && n < 64 && v >> (n - 1) & 1 == 1 {
            (v as i64) - (1i64 << n)
        } else {
            v as i64
        })
    }

    pub fn bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        for b in out.iter_mut() {
            *b = self.uint(8)? as u8;
        }
        Ok(out)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.cell.bits {
            return Err(bad("skipped past the end of a cell"));
        }
        self.pos += n;
        Ok(())
    }

    /// The next reference, unread.
    pub fn reference(&mut self) -> Result<Arc<Cell>> {
        let r = self
            .cell
            .refs
            .get(self.ref_pos)
            .cloned()
            .ok_or_else(|| bad("a missing reference"))?;
        self.ref_pos += 1;
        Ok(r)
    }

    /// The next reference, as a reader.
    pub fn ref_slice(&mut self) -> Result<Slice> {
        self.reference()?.parse()
    }

    /// Skip a `Grams`/`VarUInteger 16`.
    pub fn skip_grams(&mut self) -> Result<()> {
        let len = self.uint(4)? as usize;
        self.skip(len * 8)
    }

    /// Skip a `CurrencyCollection`.
    pub fn skip_currency(&mut self) -> Result<()> {
        self.skip_grams()?;
        if self.bit()? {
            self.reference()?;
        }
        Ok(())
    }

    /// Read a `HmLabel` for a node with `m` key bits left: the label's value
    /// and length.
    fn label(&mut self, m: usize) -> Result<Vec<bool>> {
        let width = usize::BITS as usize - m.leading_zeros() as usize;
        let bits: Vec<bool> = if !self.bit()? {
            let mut n = 0;
            while self.bit()? {
                n += 1;
            }
            (0..n).map(|_| self.bit()).collect::<Result<_>>()?
        } else if !self.bit()? {
            let n = self.uint(width)? as usize;
            (0..n).map(|_| self.bit()).collect::<Result<_>>()?
        } else {
            let v = self.bit()?;
            let n = self.uint(width)? as usize;
            vec![v; n]
        };
        if bits.len() > m {
            return Err(bad("a dictionary label longer than its key"));
        }
        Ok(bits)
    }
}

/// How a dictionary's nodes carry an augmentation beside each fork and leaf.
#[derive(Clone, Copy)]
pub enum Aug {
    None,
    /// A `CurrencyCollection` (the transactions and account blocks of a
    /// block).
    Currency,
}

/// Look `key` (its `n` bits, most significant first) up in the dictionary
/// whose root node is `root` (the cell a `Hashmap`, or the reference of a
/// non-empty `HashmapE`, starts in) and return a reader at the value.
pub fn dict_get(mut node: Slice, n: usize, key: &[bool], aug: Aug) -> Result<Option<Slice>> {
    if key.len() != n {
        return Err(bad("a key of the wrong length"));
    }
    let mut at = 0;
    loop {
        let m = n - at;
        let label = node.label(m)?;
        if key[at..].len() < label.len() || key[at..at + label.len()] != label[..] {
            return Ok(None);
        }
        at += label.len();
        if at == n {
            if let Aug::Currency = aug {
                node.skip_currency()?;
            }
            return Ok(Some(node));
        }
        let left = node.reference()?;
        let right = node.reference()?;
        let next = if key[at] { right } else { left };
        at += 1;
        node = next.parse()?;
    }
}

/// The bits of `bytes`, most significant first.
pub fn bits_of(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| b >> i & 1 == 1))
        .collect()
}

/// The `n` low bits of `v`, most significant first.
pub fn bits_of_uint(v: u64, n: usize) -> Vec<bool> {
    (0..n).rev().map(|i| v >> i & 1 == 1).collect()
}

/// Every `(key, value reader)` of the dictionary rooted at `node`, for small
/// dictionaries read whole (a validator set's list).
pub fn dict_all(node: Slice, n: usize) -> Result<Vec<(Vec<bool>, Slice)>> {
    let mut out = Vec::new();
    let mut stack = vec![(node, Vec::new())];
    while let Some((mut s, prefix)) = stack.pop() {
        let m = n - prefix.len();
        let label = s.label(m)?;
        let mut key = prefix;
        key.extend(label);
        if key.len() == n {
            out.push((key, s));
            continue;
        }
        let left = s.ref_slice()?;
        let right = s.ref_slice()?;
        let mut lk = key.clone();
        lk.push(false);
        let mut rk = key;
        rk.push(true);
        stack.push((right, rk));
        stack.push((left, lk));
        if out.len() + stack.len() > 1 << 16 {
            return Err(bad("a dictionary too large to read whole"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root index past the last cell is refused, not indexed.
    #[test]
    fn a_root_index_past_the_last_cell_is_refused() {
        let boc = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0xff, 0x00, 0x00,
        ];
        assert!(parse_boc(&boc).is_err());
        let mut ok = boc;
        ok[10] = 0x00;
        assert_eq!(parse_boc(&ok).unwrap().len(), 1);
    }
}
