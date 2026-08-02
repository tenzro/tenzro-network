//! GGUF k-quant block codecs for MoE expert weights.
//!
//! Expert FFN projections are large and dominate a holder's memory budget.
//! Storing them as `f32` caps how many experts stay resident in the memory
//! tier of [`crate::moe_exec::MoeExpertRuntime`]. Holding the same weights
//! in a GGUF block-quantized form (int4/int6/int8 with per-block scales)
//! shrinks the resident footprint 4–8× — so the byte-bounded LRU keeps
//! proportionally more experts warm — while decode stays pure CPU: a
//! dequant to `f32` followed by the existing `f32` accumulate.
//!
//! The block layouts match the canonical `ggml` definitions
//! (`ggml/src/ggml-common.h`), so a blob quantized by any GGUF-producing
//! tool decodes here bit-for-bit:
//!
//! - [`QuantKind::Q8_0`] — 32-weight blocks, one `f16` scale + 32 `i8`
//!   quants (34 bytes / 32 weights). Near-lossless; the format used for
//!   hidden-state activations on the wire ([`quantize_row_q8_0`]).
//! - [`QuantKind::Q4_K`] — 256-weight super-blocks, 6-bit block scales/mins
//!   and 4-bit weights (144 bytes / 256 weights, ~4.5 bpw). The Q4_K_M
//!   quality/size operating point.
//! - [`QuantKind::Q6_K`] — 256-weight super-blocks, 8-bit block scales and
//!   6-bit weights (210 bytes / 256 weights, ~6.6 bpw). Near-`f16`.
//!
//! `QK_K = 256` throughout (the k-quant super-block width). A quantized
//! projection is a whole number of super-blocks per row; the loader rejects
//! rows whose width is not a multiple of the block width for the kind.

use half::f16;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// K-quant super-block width.
pub const QK_K: usize = 256;
/// Q8_0 block width.
pub const QK8_0: usize = 32;

/// Serialized size of one `block_q8_0`: `f16` scale + 32 `i8` quants.
pub const Q8_0_BLOCK_BYTES: usize = 2 + QK8_0; // 34
/// Serialized size of one `block_q4_K`.
pub const Q4_K_BLOCK_BYTES: usize = 2 + 2 + 12 + QK_K / 2; // 144
/// Serialized size of one `block_q6_K`.
pub const Q6_K_BLOCK_BYTES: usize = QK_K / 2 + QK_K / 4 + QK_K / 16 + 2; // 210

/// Errors from quant decode.
#[derive(Debug, Clone, Error, PartialEq)]
pub enum QuantError {
    /// The quantized byte length does not factor into whole blocks.
    #[error("{kind:?} payload {len} bytes is not a whole number of {block} blocks")]
    RaggedPayload {
        /// Quant kind being decoded.
        kind: QuantKind,
        /// Payload byte length.
        len: usize,
        /// Per-block byte size for the kind.
        block: usize,
    },
    /// A row width is not a multiple of the kind's block width.
    #[error("row width {cols} is not a multiple of {block_width} for {kind:?}")]
    UnalignedRow {
        /// Quant kind.
        kind: QuantKind,
        /// Row width in weights.
        cols: usize,
        /// Weights per block for the kind.
        block_width: usize,
    },
    /// Declared shape does not match the decoded weight count.
    #[error("{kind:?} weight count {got} does not match declared shape {rows}x{cols}")]
    ShapeMismatch {
        /// Quant kind.
        kind: QuantKind,
        /// Decoded weight count.
        got: usize,
        /// Declared row count.
        rows: usize,
        /// Declared column count.
        cols: usize,
    },
}

/// Result alias for quant decode.
pub type QuantResult<T> = std::result::Result<T, QuantError>;

/// A supported GGUF block-quant kind for expert weights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuantKind {
    /// 8-bit, 32-weight blocks. Near-lossless; used for wire activations.
    Q8_0,
    /// 4-bit k-quant, 256-weight super-blocks (~4.5 bpw). Q4_K_M point.
    Q4K,
    /// 6-bit k-quant, 256-weight super-blocks (~6.6 bpw). Near-f16.
    Q6K,
}

impl QuantKind {
    /// Weights represented by one serialized block of this kind.
    pub fn block_width(self) -> usize {
        match self {
            QuantKind::Q8_0 => QK8_0,
            QuantKind::Q4K | QuantKind::Q6K => QK_K,
        }
    }

    /// Serialized byte size of one block of this kind.
    pub fn block_bytes(self) -> usize {
        match self {
            QuantKind::Q8_0 => Q8_0_BLOCK_BYTES,
            QuantKind::Q4K => Q4_K_BLOCK_BYTES,
            QuantKind::Q6K => Q6_K_BLOCK_BYTES,
        }
    }

    /// Short string tag used in safetensors dtype metadata and status.
    pub fn tag(self) -> &'static str {
        match self {
            QuantKind::Q8_0 => "q8_0",
            QuantKind::Q4K => "q4_k",
            QuantKind::Q6K => "q6_k",
        }
    }

    /// Parse a tag emitted by [`QuantKind::tag`].
    pub fn from_tag(s: &str) -> Option<Self> {
        match s {
            "q8_0" => Some(QuantKind::Q8_0),
            "q4_k" | "q4_k_m" | "q4_k_s" => Some(QuantKind::Q4K),
            "q6_k" => Some(QuantKind::Q6K),
            _ => None,
        }
    }
}

/// A quantized 2-D weight matrix: row-major `[rows, cols]`, each row a whole
/// number of quant blocks. Decodes to `f32` on demand (whole matrix, or one
/// row at a time in the fused matmul path).
#[derive(Debug, Clone, PartialEq)]
pub struct QuantMatrix {
    kind: QuantKind,
    rows: usize,
    cols: usize,
    /// Concatenated block bytes, row-major: `rows * (cols / block_width)`
    /// blocks of `kind.block_bytes()` each.
    data: Vec<u8>,
}

impl QuantMatrix {
    /// Wrap pre-quantized block bytes as a matrix, validating alignment.
    pub fn from_blocks(
        kind: QuantKind,
        rows: usize,
        cols: usize,
        data: Vec<u8>,
    ) -> QuantResult<Self> {
        let bw = kind.block_width();
        if !cols.is_multiple_of(bw) {
            return Err(QuantError::UnalignedRow {
                kind,
                cols,
                block_width: bw,
            });
        }
        let bb = kind.block_bytes();
        if !data.len().is_multiple_of(bb) {
            return Err(QuantError::RaggedPayload {
                kind,
                len: data.len(),
                block: bb,
            });
        }
        let expected_blocks = rows.saturating_mul(cols / bw);
        if data.len() / bb != expected_blocks {
            return Err(QuantError::ShapeMismatch {
                kind,
                got: (data.len() / bb) * bw,
                rows,
                cols,
            });
        }
        Ok(Self {
            kind,
            rows,
            cols,
            data,
        })
    }

    /// Quantize an `f32` row-major `[rows, cols]` matrix into this kind.
    pub fn quantize(kind: QuantKind, rows: usize, cols: usize, src: &[f32]) -> QuantResult<Self> {
        let bw = kind.block_width();
        if !cols.is_multiple_of(bw) {
            return Err(QuantError::UnalignedRow {
                kind,
                cols,
                block_width: bw,
            });
        }
        if src.len() != rows * cols {
            return Err(QuantError::ShapeMismatch {
                kind,
                got: src.len(),
                rows,
                cols,
            });
        }
        let bb = kind.block_bytes();
        let blocks_per_row = cols / bw;
        let mut data = Vec::with_capacity(rows * blocks_per_row * bb);
        for r in 0..rows {
            let row = &src[r * cols..(r + 1) * cols];
            for b in 0..blocks_per_row {
                let block = &row[b * bw..(b + 1) * bw];
                match kind {
                    QuantKind::Q8_0 => encode_block_q8_0(block, &mut data),
                    QuantKind::Q4K => encode_block_q4_k(block, &mut data),
                    QuantKind::Q6K => encode_block_q6_k(block, &mut data),
                }
            }
        }
        Ok(Self {
            kind,
            rows,
            cols,
            data,
        })
    }

    /// Quant kind.
    pub fn kind(&self) -> QuantKind {
        self.kind
    }

    /// Row count.
    pub fn nrows(&self) -> usize {
        self.rows
    }

    /// Column count (weights per row).
    pub fn ncols(&self) -> usize {
        self.cols
    }

    /// Resident bytes: the block payload plus shape overhead.
    pub fn approx_bytes(&self) -> u64 {
        self.data.len() as u64
    }

    /// Borrow the concatenated block payload (row-major GGUF blocks).
    pub fn block_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume the matrix and yield the block payload.
    pub fn into_block_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Number of blocks per row.
    pub fn blocks_per_row(&self) -> usize {
        self.cols / self.kind.block_width()
    }

    /// Borrow one row's raw block payload (`blocks_per_row * kind.block_bytes()`
    /// bytes). Used by SIMD dot kernels that consume Q8_0 blocks directly
    /// without a dequantize-to-scratch step.
    pub fn row_block_bytes(&self, row: usize) -> &[u8] {
        let bb = self.kind.block_bytes();
        let bpr = self.blocks_per_row();
        let off = row * bpr * bb;
        &self.data[off..off + bpr * bb]
    }

    /// Dequantize one row (`cols` weights) into `out` (must be `cols` long).
    pub fn dequantize_row(&self, row: usize, out: &mut [f32]) {
        debug_assert_eq!(out.len(), self.cols);
        let bb = self.kind.block_bytes();
        let bw = self.kind.block_width();
        let bpr = self.blocks_per_row();
        let row_off = row * bpr * bb;
        for b in 0..bpr {
            let block = &self.data[row_off + b * bb..row_off + (b + 1) * bb];
            let dst = &mut out[b * bw..(b + 1) * bw];
            match self.kind {
                QuantKind::Q8_0 => decode_block_q8_0(block, dst),
                QuantKind::Q4K => decode_block_q4_k(block, dst),
                QuantKind::Q6K => decode_block_q6_k(block, dst),
            }
        }
    }

    /// Dequantize the whole matrix to a fresh row-major `f32` `Vec`.
    pub fn dequantize(&self) -> Vec<f32> {
        let mut out = vec![0.0f32; self.rows * self.cols];
        for r in 0..self.rows {
            let (_, tail) = out.split_at_mut(r * self.cols);
            self.dequantize_row(r, &mut tail[..self.cols]);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Q8_0 — 32 weights: f16 d + 32 i8 quants
// ---------------------------------------------------------------------------

/// Dequantize a Q8_0 activation row into `out` (`n` a multiple of 32).
pub fn dequantize_row_q8_0(blocks: &[u8], out: &mut [f32]) {
    debug_assert_eq!(out.len() % QK8_0, 0);
    for (b, chunk) in blocks.chunks_exact(Q8_0_BLOCK_BYTES).enumerate() {
        decode_block_q8_0(chunk, &mut out[b * QK8_0..(b + 1) * QK8_0]);
    }
}

/// Quantize an `f32` row (`len` a multiple of 32) into concatenated Q8_0
/// blocks. Used to compress hidden-state activations on the `tenzro/moe`
/// wire.
pub fn quantize_row_q8_0(src: &[f32]) -> Vec<u8> {
    debug_assert_eq!(src.len() % QK8_0, 0);
    let mut out = Vec::with_capacity(src.len() / QK8_0 * Q8_0_BLOCK_BYTES);
    for block in src.chunks_exact(QK8_0) {
        encode_block_q8_0(block, &mut out);
    }
    out
}

fn encode_block_q8_0(block: &[f32], out: &mut Vec<u8>) {
    debug_assert_eq!(block.len(), QK8_0);
    let amax = block.iter().fold(0.0f32, |m, &x| m.max(x.abs()));
    let d = amax / 127.0;
    let id = if d > 0.0 { 1.0 / d } else { 0.0 };
    out.extend_from_slice(&f16::from_f32(d).to_le_bytes());
    for &x in block {
        let q = (x * id).round().clamp(-127.0, 127.0) as i8;
        out.push(q as u8);
    }
}

fn decode_block_q8_0(block: &[u8], out: &mut [f32]) {
    debug_assert_eq!(block.len(), Q8_0_BLOCK_BYTES);
    debug_assert_eq!(out.len(), QK8_0);
    let d = f16::from_le_bytes([block[0], block[1]]).to_f32();
    for i in 0..QK8_0 {
        out[i] = d * (block[2 + i] as i8 as f32);
    }
}

// ---------------------------------------------------------------------------
// Q4_K — 256 weights: f16 d, f16 dmin, 12 packed 6-bit scales/mins, 128 nibbles
// ---------------------------------------------------------------------------
//
// Layout (block_q4_K, 144 bytes):
//   d       : f16                       — super-block scale for the 6-bit sub-scales
//   dmin    : f16                       — super-block scale for the 6-bit sub-mins
//   scales  : u8[12]                    — eight 6-bit scales + eight 6-bit mins, packed
//   qs      : u8[128]                   — 256 4-bit weights (two per byte)
//
// The 256 weights split into 8 sub-blocks of 32. Sub-block j has a 6-bit
// scale sc_j and 6-bit min m_j; a weight q (0..15) dequantizes to
//   w = d*sc_j*q - dmin*m_j.

/// Unpack the eight 6-bit scales and eight 6-bit mins from the 12-byte
/// packed `scales` field (canonical ggml `get_scale_min_k4` layout).
fn q4k_unpack_scales_mins(scales: &[u8; 12]) -> ([u8; 8], [u8; 8]) {
    let mut sc = [0u8; 8];
    let mut m = [0u8; 8];
    for j in 0..8 {
        if j < 4 {
            sc[j] = scales[j] & 63;
            m[j] = scales[j + 4] & 63;
        } else {
            sc[j] = (scales[j + 4] & 0x0F) | ((scales[j - 4] >> 6) << 4);
            m[j] = (scales[j + 4] >> 4) | ((scales[j] >> 6) << 4);
        }
    }
    (sc, m)
}

fn decode_block_q4_k(block: &[u8], out: &mut [f32]) {
    debug_assert_eq!(block.len(), Q4_K_BLOCK_BYTES);
    debug_assert_eq!(out.len(), QK_K);
    let d = f16::from_le_bytes([block[0], block[1]]).to_f32();
    let dmin = f16::from_le_bytes([block[2], block[3]]).to_f32();
    let scales: [u8; 12] = block[4..16].try_into().unwrap();
    let qs = &block[16..16 + QK_K / 2]; // 128 bytes
    let (sc, m) = q4k_unpack_scales_mins(&scales);

    // Two sub-blocks of 32 are packed per 32-byte qs stripe: low nibbles are
    // sub-block 2i, high nibbles are sub-block 2i+1 (canonical ggml order).
    for i in 0..4 {
        let stripe = &qs[i * 32..(i + 1) * 32];
        let j_lo = 2 * i;
        let j_hi = 2 * i + 1;
        let d_lo = d * sc[j_lo] as f32;
        let min_lo = dmin * m[j_lo] as f32;
        let d_hi = d * sc[j_hi] as f32;
        let min_hi = dmin * m[j_hi] as f32;
        for k in 0..32 {
            let q = stripe[k];
            out[j_lo * 32 + k] = d_lo * (q & 0x0F) as f32 - min_lo;
            out[j_hi * 32 + k] = d_hi * (q >> 4) as f32 - min_hi;
        }
    }
}

fn encode_block_q4_k(block: &[f32], out: &mut Vec<u8>) {
    debug_assert_eq!(block.len(), QK_K);
    // Per sub-block of 32: fit q in 0..15 as w ≈ scale*q + min. Use the
    // min/max affine fit ggml's reference quantizer uses.
    let mut sub_scale = [0f32; 8];
    let mut sub_min = [0f32; 8];
    let mut q4 = [0u8; QK_K];
    for j in 0..8 {
        let s = &block[j * 32..(j + 1) * 32];
        let mut vmin = s[0];
        let mut vmax = s[0];
        for &x in s {
            vmin = vmin.min(x);
            vmax = vmax.max(x);
        }
        if vmin > 0.0 {
            vmin = 0.0;
        }
        let scale = (vmax - vmin) / 15.0;
        let inv = if scale > 0.0 { 1.0 / scale } else { 0.0 };
        sub_scale[j] = scale;
        sub_min[j] = -vmin; // stored as a positive min magnitude
        for (k, &x) in s.iter().enumerate() {
            let q = ((x - vmin) * inv).round().clamp(0.0, 15.0) as u8;
            q4[j * 32 + k] = q;
        }
    }
    // Quantize the eight scales/mins to 6-bit with super-block scales d/dmin.
    let max_scale = sub_scale.iter().cloned().fold(0.0f32, f32::max);
    let max_min = sub_min.iter().cloned().fold(0.0f32, f32::max);
    let d = max_scale / 63.0;
    let dmin = max_min / 63.0;
    let inv_d = if d > 0.0 { 1.0 / d } else { 0.0 };
    let inv_dmin = if dmin > 0.0 { 1.0 / dmin } else { 0.0 };
    let mut sc = [0u8; 8];
    let mut m = [0u8; 8];
    for j in 0..8 {
        sc[j] = (sub_scale[j] * inv_d).round().clamp(0.0, 63.0) as u8;
        m[j] = (sub_min[j] * inv_dmin).round().clamp(0.0, 63.0) as u8;
    }
    let scales = q4k_pack_scales_mins(&sc, &m);

    out.extend_from_slice(&f16::from_f32(d).to_le_bytes());
    out.extend_from_slice(&f16::from_f32(dmin).to_le_bytes());
    out.extend_from_slice(&scales);
    // Pack nibbles in the same low/high stripe order the decoder reads.
    for i in 0..4 {
        let j_lo = 2 * i;
        let j_hi = 2 * i + 1;
        for k in 0..32 {
            let lo = q4[j_lo * 32 + k] & 0x0F;
            let hi = q4[j_hi * 32 + k] & 0x0F;
            out.push(lo | (hi << 4));
        }
    }
}

/// Inverse of [`q4k_unpack_scales_mins`].
fn q4k_pack_scales_mins(sc: &[u8; 8], m: &[u8; 8]) -> [u8; 12] {
    let mut scales = [0u8; 12];
    for j in 0..4 {
        scales[j] = sc[j] & 63;
        scales[j + 4] = m[j] & 63;
    }
    for j in 4..8 {
        scales[j + 4] = (sc[j] & 0x0F) | ((m[j] & 0x0F) << 4);
        scales[j - 4] |= (sc[j] >> 4) << 6;
        scales[j] |= (m[j] >> 4) << 6;
    }
    scales
}

// ---------------------------------------------------------------------------
// Q6_K — 256 weights: 128 low-nibble bytes, 64 high-2-bit bytes, 16 i8 scales, f16 d
// ---------------------------------------------------------------------------
//
// Layout (block_q6_K, 210 bytes):
//   ql     : u8[128]   — low 4 bits of each 6-bit weight (two per byte)
//   qh     : u8[64]    — high 2 bits of each 6-bit weight (four per byte)
//   scales : i8[16]    — per-16-weight block scale (signed)
//   d      : f16       — super-block scale
//
// The 256 weights split into 16 groups of 16, each with a signed scale.
// A 6-bit quant q is centered: w = d * scale * (q - 32).

fn decode_block_q6_k(block: &[u8], out: &mut [f32]) {
    debug_assert_eq!(block.len(), Q6_K_BLOCK_BYTES);
    debug_assert_eq!(out.len(), QK_K);
    let ql = &block[0..128];
    let qh = &block[128..192];
    let scales = &block[192..208];
    let d = f16::from_le_bytes([block[208], block[209]]).to_f32();

    // Canonical ggml dequant: the super-block is processed in two halves of
    // 128 weights; within each half, four 16-lane groups draw ql/qh bits.
    for half in 0..2 {
        let ql_base = half * 64;
        let qh_base = half * 32;
        let sc_base = half * 8;
        let out_base = half * 128;
        for l in 0..32 {
            let qh_byte = qh[qh_base + l];
            // Four weights per l, one per 16-lane group.
            let q1 = ((ql[ql_base + l] & 0x0F) | ((qh_byte & 0x03) << 4)) as i32 - 32;
            let q2 = ((ql[ql_base + l + 32] & 0x0F) | (((qh_byte >> 2) & 0x03) << 4)) as i32 - 32;
            let q3 = ((ql[ql_base + l] >> 4) | (((qh_byte >> 4) & 0x03) << 4)) as i32 - 32;
            let q4 = ((ql[ql_base + l + 32] >> 4) | (((qh_byte >> 6) & 0x03) << 4)) as i32 - 32;
            let is = l / 16;
            let s1 = scales[sc_base + is] as i8 as f32;
            let s2 = scales[sc_base + is + 2] as i8 as f32;
            let s3 = scales[sc_base + is + 4] as i8 as f32;
            let s4 = scales[sc_base + is + 6] as i8 as f32;
            out[out_base + l] = d * s1 * q1 as f32;
            out[out_base + l + 32] = d * s2 * q2 as f32;
            out[out_base + l + 64] = d * s3 * q3 as f32;
            out[out_base + l + 96] = d * s4 * q4 as f32;
        }
    }
}

fn encode_block_q6_k(block: &[f32], out: &mut Vec<u8>) {
    debug_assert_eq!(block.len(), QK_K);
    // Per 16-weight group: signed symmetric scale, q in 0..63 centered at 32.
    let mut group_scale = [0f32; 16];
    let mut q6 = [0u8; QK_K];
    for g in 0..16 {
        let s = &block[g * 16..(g + 1) * 16];
        let amax = s.iter().fold(0.0f32, |m, &x| m.max(x.abs()));
        let scale = amax / 32.0;
        let inv = if scale > 0.0 { 1.0 / scale } else { 0.0 };
        group_scale[g] = scale;
        for (k, &x) in s.iter().enumerate() {
            let q = ((x * inv).round() + 32.0).clamp(0.0, 63.0) as u8;
            q6[g * 16 + k] = q;
        }
    }
    let max_scale = group_scale.iter().cloned().fold(0.0f32, f32::max);
    let d = max_scale / 127.0;
    let inv_d = if d > 0.0 { 1.0 / d } else { 0.0 };
    let mut i8_scales = [0i8; 16];
    for g in 0..16 {
        i8_scales[g] = (group_scale[g] * inv_d).round().clamp(-127.0, 127.0) as i8;
    }

    // Emit ql (128 bytes), qh (64 bytes) in the same order the decoder reads.
    let mut ql = [0u8; 128];
    let mut qh = [0u8; 64];
    for half in 0..2 {
        let ql_base = half * 64;
        let qh_base = half * 32;
        let out_base = half * 128;
        for l in 0..32 {
            let a = q6[out_base + l];
            let b = q6[out_base + l + 32];
            let c = q6[out_base + l + 64];
            let e = q6[out_base + l + 96];
            ql[ql_base + l] = (a & 0x0F) | ((c & 0x0F) << 4);
            ql[ql_base + l + 32] = (b & 0x0F) | ((e & 0x0F) << 4);
            qh[qh_base + l] = ((a >> 4) & 0x03)
                | (((b >> 4) & 0x03) << 2)
                | (((c >> 4) & 0x03) << 4)
                | (((e >> 4) & 0x03) << 6);
        }
    }
    out.extend_from_slice(&ql);
    out.extend_from_slice(&qh);
    for s in i8_scales {
        out.push(s as u8);
    }
    out.extend_from_slice(&f16::from_f32(d).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn max_abs_err(a: &[f32], b: &[f32]) -> f32 {
        a.iter()
            .zip(b)
            .fold(0.0f32, |m, (x, y)| m.max((x - y).abs()))
    }

    fn ramp(n: usize) -> Vec<f32> {
        (0..n)
            .map(|i| ((i as f32) - (n as f32) / 2.0) * 0.013)
            .collect()
    }

    #[test]
    fn block_sizes_match_ggml() {
        assert_eq!(Q8_0_BLOCK_BYTES, 34);
        assert_eq!(Q4_K_BLOCK_BYTES, 144);
        assert_eq!(Q6_K_BLOCK_BYTES, 210);
    }

    #[test]
    fn q8_0_roundtrip_is_near_lossless() {
        let src = ramp(QK8_0 * 4);
        let blocks = quantize_row_q8_0(&src);
        assert_eq!(blocks.len(), 4 * Q8_0_BLOCK_BYTES);
        let mut back = vec![0.0f32; src.len()];
        dequantize_row_q8_0(&blocks, &mut back);
        // Per-block scale d = amax/127 → error bound ~0.5 lsb of that scale.
        let amax = src.iter().fold(0.0f32, |m, &x| m.max(x.abs()));
        assert!(max_abs_err(&src, &back) <= amax / 127.0, "{:?}", &back[..4]);
    }

    #[test]
    fn q4_k_scale_min_pack_roundtrips() {
        let sc = [1u8, 62, 5, 40, 15, 33, 7, 50];
        let m = [2u8, 61, 6, 39, 14, 32, 8, 49];
        let packed = q4k_pack_scales_mins(&sc, &m);
        let (sc2, m2) = q4k_unpack_scales_mins(&packed);
        assert_eq!(sc, sc2);
        assert_eq!(m, m2);
    }

    #[test]
    fn q4_k_roundtrip_bounded_error() {
        let src = ramp(QK_K * 2);
        let q = QuantMatrix::quantize(QuantKind::Q4K, 2, QK_K, &src).unwrap();
        assert_eq!(q.approx_bytes(), 2 * Q4_K_BLOCK_BYTES as u64);
        let back = q.dequantize();
        let span = {
            let mn = src.iter().cloned().fold(f32::INFINITY, f32::min);
            let mx = src.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
            mx - mn
        };
        // ~4.5 bpw affine quant: error within a few percent of the span.
        assert!(max_abs_err(&src, &back) < span * 0.1);
    }

    #[test]
    fn q6_k_roundtrip_tighter_than_q4() {
        let src = ramp(QK_K * 2);
        let q4 = QuantMatrix::quantize(QuantKind::Q4K, 2, QK_K, &src)
            .unwrap()
            .dequantize();
        let q6m = QuantMatrix::quantize(QuantKind::Q6K, 2, QK_K, &src).unwrap();
        assert_eq!(q6m.approx_bytes(), 2 * Q6_K_BLOCK_BYTES as u64);
        let q6 = q6m.dequantize();
        assert!(
            max_abs_err(&src, &q6) <= max_abs_err(&src, &q4),
            "q6 err {} should not exceed q4 err {}",
            max_abs_err(&src, &q6),
            max_abs_err(&src, &q4)
        );
    }

    #[test]
    fn dequantize_row_matches_full() {
        let src = ramp(QK_K * 3);
        let q = QuantMatrix::quantize(QuantKind::Q4K, 3, QK_K, &src).unwrap();
        let full = q.dequantize();
        let mut row1 = vec![0.0f32; QK_K];
        q.dequantize_row(1, &mut row1);
        assert_eq!(&full[QK_K..2 * QK_K], &row1[..]);
    }

    #[test]
    fn unaligned_row_is_rejected() {
        let err = QuantMatrix::quantize(QuantKind::Q4K, 1, 100, &vec![0.0; 100]).unwrap_err();
        assert!(matches!(err, QuantError::UnalignedRow { .. }));
    }

    #[test]
    fn from_blocks_validates_shape() {
        let src = ramp(QK_K);
        let q = QuantMatrix::quantize(QuantKind::Q6K, 1, QK_K, &src).unwrap();
        let raw = q.data.clone();
        // Correct shape accepted.
        assert!(QuantMatrix::from_blocks(QuantKind::Q6K, 1, QK_K, raw.clone()).is_ok());
        // Wrong declared rows rejected.
        let err = QuantMatrix::from_blocks(QuantKind::Q6K, 2, QK_K, raw).unwrap_err();
        assert!(matches!(err, QuantError::ShapeMismatch { .. }));
    }

    #[test]
    fn tag_roundtrips() {
        for k in [QuantKind::Q8_0, QuantKind::Q4K, QuantKind::Q6K] {
            assert_eq!(QuantKind::from_tag(k.tag()), Some(k));
        }
        assert_eq!(QuantKind::from_tag("q4_k_m"), Some(QuantKind::Q4K));
        assert_eq!(QuantKind::from_tag("nope"), None);
    }
}
