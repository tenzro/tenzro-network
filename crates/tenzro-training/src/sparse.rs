//! Chunked top-k sparsification + 2-bit codec for outer-gradient payloads.
//!
//! Where [`crate::quantization`] compresses a *dense* fragment 4–8× by
//! low-bit blockwise quantization, this module compresses a fragment >100× by
//! keeping only the top-`k` largest-magnitude coordinates per chunk and
//! encoding those kept values at 2 bits. The dropped mass is not lost: the
//! trainer folds it into a local **error-feedback accumulator** (decay β) that
//! is re-added to the next round's pseudo-gradient, so no gradient signal is
//! discarded — it is merely deferred. Momentum lives entirely in that
//! accumulator, which is why the sparse error-feedback outer update
//! ([`tenzro_types::training::OuterUpdateMode::SparseEf`]) carries no syncer
//! momentum.
//!
//! # Wire format
//!
//! The flattened fragment is split into chunks of `chunk_size` coordinates
//! (the final chunk may be shorter). Within each chunk the `min(k, chunk_len)`
//! largest-magnitude coordinates are kept. The payload is:
//!
//! ```text
//! for each chunk:
//!   f32  scale            (little-endian; = kept_max_abs / 1.0, see below)
//!   for each kept coord (ascending chunk-local index):
//!     u16  index          (little-endian; chunk-local offset, 0..chunk_len)
//!   ceil(kept / 4) bytes  (2-bit codes, 4 per byte, low pair first)
//! ```
//!
//! The 2-bit code is a signed magnitude in `{-1, 0, +1}` (2's-complement over
//! 2 bits: `00→0, 01→+1, 11→-1`, `10` unused/reserved and decodes to 0).
//! Because top-k already selects the large coordinates, a per-chunk 2-bit
//! sign-magnitude against `scale = max_abs_of_kept` reproduces the dominant
//! direction; the residual (true value minus `code * scale`) is what the
//! trainer's error-feedback accumulator carries forward. `scale = 0.0` marks
//! an all-zero (or empty) chunk and decodes every code to 0.
//!
//! The kept count per chunk is *derivable* from `chunk_size`, `k`, and the
//! fragment length — it is **not** stored per chunk, so the decoder recomputes
//! it and there is no size ambiguity. A payload whose byte length disagrees
//! with the derived structure is rejected as malformed.

use tenzro_types::training::SparseTopKParams;

use crate::error::{Result, TrainingError};

/// A decoded sparse payload: a dense-length dequantized vector where dropped
/// coordinates are exactly `0.0`. Aggregation treats an absent (dropped)
/// coordinate as a zero contribution, so returning the densified form keeps
/// the aggregation surface identical to the dense path.
pub type SparseDecoded = Vec<f32>;

/// Byte length of a single chunk's encoding for `kept` kept coordinates.
fn chunk_encoded_len(kept: usize) -> usize {
    // f32 scale + kept u16 indices + ceil(kept/4) code bytes.
    4 + kept * 2 + kept.div_ceil(4)
}

/// Total byte length of the sparse encoding of a length-`len` fragment under
/// `params`.
pub fn sparse_encoded_len(len: usize, params: SparseTopKParams) -> usize {
    let cs = params.chunk_size.max(1) as usize;
    let mut total = 0usize;
    let mut rem = len;
    while rem > 0 {
        let chunk_len = rem.min(cs);
        total += chunk_encoded_len(params.kept_for_chunk(chunk_len));
        rem -= chunk_len;
    }
    total
}

/// Encode a flattened fragment into the sparse top-k + 2-bit wire format.
///
/// `values` is the *transmit* vector — the caller has already added the
/// error-feedback accumulator to the raw pseudo-gradient (see
/// [`ErrorFeedback::prepare_transmit`]). Returns the wire bytes; the caller
/// pairs them with [`select_transmitted`] to know exactly what was sent so it
/// can subtract it from the accumulator.
pub fn sparse_encode(values: &[f32], params: SparseTopKParams) -> Vec<u8> {
    let cs = params.chunk_size.max(1) as usize;
    let mut out = Vec::with_capacity(sparse_encoded_len(values.len(), params));

    for chunk in values.chunks(cs) {
        let kept = params.kept_for_chunk(chunk.len());
        let top = top_k_indices(chunk, kept);
        // Scale is the max magnitude among the kept coordinates.
        let max_abs = top.iter().fold(0.0f32, |acc, &i| acc.max(chunk[i].abs()));
        out.extend_from_slice(&max_abs.to_le_bytes());
        // Indices (ascending), then packed 2-bit codes.
        for &i in &top {
            out.extend_from_slice(&(i as u16).to_le_bytes());
        }
        let mut packer = NibblePacker::new(&mut out);
        for &i in &top {
            packer.push(encode_2bit(chunk[i], max_abs));
        }
        packer.flush();
    }
    out
}

/// Decode a sparse wire payload back into a dense length-`expected_len`
/// `f32` vector with dropped coordinates zero-filled.
pub fn sparse_decode(
    bytes: &[u8],
    params: SparseTopKParams,
    expected_len: usize,
) -> Result<SparseDecoded> {
    let expected_bytes = sparse_encoded_len(expected_len, params);
    if bytes.len() != expected_bytes {
        return Err(TrainingError::QuantizedPayloadMalformed(format!(
            "sparse {params} payload is {} bytes, expected {expected_bytes} for {expected_len} values",
            bytes.len()
        )));
    }
    let cs = params.chunk_size.max(1) as usize;
    let mut out = vec![0.0f32; expected_len];
    let mut cursor = 0usize;
    let mut base = 0usize; // global offset of the current chunk

    while base < expected_len {
        let chunk_len = (expected_len - base).min(cs);
        let kept = params.kept_for_chunk(chunk_len);

        let scale = f32::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]);
        cursor += 4;

        let mut indices = Vec::with_capacity(kept);
        for _ in 0..kept {
            let idx = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            if idx >= chunk_len {
                return Err(TrainingError::QuantizedPayloadMalformed(format!(
                    "sparse {params}: chunk-local index {idx} out of range for chunk length {chunk_len}"
                )));
            }
            indices.push(idx);
            cursor += 2;
        }

        let code_bytes = kept.div_ceil(4);
        for (n, &idx) in indices.iter().enumerate() {
            let byte = bytes[cursor + n / 4];
            let code = (byte >> ((n % 4) * 2)) & 0b11;
            out[base + idx] = decode_2bit(code) * scale;
        }
        cursor += code_bytes;

        base += chunk_len;
    }
    Ok(out)
}

/// Chunk-local indices of the `kept` largest-magnitude coordinates in a chunk,
/// returned in *ascending* order (the wire order). Ties break toward the lower
/// index, deterministically, so encode/decode is reproducible across peers.
fn top_k_indices(chunk: &[f32], kept: usize) -> Vec<usize> {
    if kept >= chunk.len() {
        return (0..chunk.len()).collect();
    }
    if kept == 0 {
        return Vec::new();
    }
    // Partial selection by magnitude, then sort the winners by index.
    let mut idx: Vec<usize> = (0..chunk.len()).collect();
    idx.sort_unstable_by(|&a, &b| {
        chunk[b]
            .abs()
            .partial_cmp(&chunk[a].abs())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cmp(&b))
    });
    idx.truncate(kept);
    idx.sort_unstable();
    idx
}

/// The exact `(global_index, transmitted_value)` pairs `sparse_encode` would
/// send for `values` under `params`. Used by the trainer to subtract the
/// transmitted mass from its error-feedback accumulator (error feedback:
/// `acc ← acc − transmitted` at exactly the coordinates that were sent).
pub fn select_transmitted(values: &[f32], params: SparseTopKParams) -> Vec<(usize, f32)> {
    let cs = params.chunk_size.max(1) as usize;
    let mut sent = Vec::new();
    let mut base = 0usize;
    for chunk in values.chunks(cs) {
        let kept = params.kept_for_chunk(chunk.len());
        let top = top_k_indices(chunk, kept);
        let max_abs = top.iter().fold(0.0f32, |acc, &i| acc.max(chunk[i].abs()));
        for &i in &top {
            let q = decode_2bit(encode_2bit(chunk[i], max_abs)) * max_abs;
            sent.push((base + i, q));
        }
        base += chunk.len();
    }
    sent
}

// ---------------------------------------------------------------------------
// 2-bit sign-magnitude codec
// ---------------------------------------------------------------------------

/// Encode a value to a 2-bit code against a per-chunk scale.
/// `00 → 0`, `01 → +1`, `11 → -1`. A zero scale always encodes `0`.
fn encode_2bit(value: f32, scale: f32) -> u8 {
    if scale == 0.0 || value == 0.0 {
        return 0b00;
    }
    if value > 0.0 { 0b01 } else { 0b11 }
}

/// Decode a 2-bit code to a signed magnitude in `{-1, 0, +1}`.
fn decode_2bit(code: u8) -> f32 {
    match code & 0b11 {
        0b01 => 1.0,
        0b11 => -1.0,
        // 0b00 and the reserved 0b10 both decode to 0.
        _ => 0.0,
    }
}

/// Packs 2-bit codes 4 per byte, low pair first.
struct NibblePacker<'a> {
    out: &'a mut Vec<u8>,
    cur: u8,
    filled: u8,
}

impl<'a> NibblePacker<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            out,
            cur: 0,
            filled: 0,
        }
    }

    fn push(&mut self, code: u8) {
        self.cur |= (code & 0b11) << (self.filled * 2);
        self.filled += 1;
        if self.filled == 4 {
            self.out.push(self.cur);
            self.cur = 0;
            self.filled = 0;
        }
    }

    fn flush(&mut self) {
        if self.filled > 0 {
            self.out.push(self.cur);
            self.cur = 0;
            self.filled = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Error-feedback accumulator (trainer-side state)
// ---------------------------------------------------------------------------

/// Trainer-local error-feedback accumulator.
///
/// This is the state that replaces the syncer's outer momentum. Each round the
/// trainer:
///
/// 1. computes the raw outer pseudo-gradient `g = θ_before − θ_after`;
/// 2. calls [`Self::prepare_transmit`], which returns `t = decay·acc + g`
///    (the vector actually sparsified and sent);
/// 3. encodes `t` with [`sparse_encode`];
/// 4. calls [`Self::commit_transmitted`] with the pairs from
///    [`select_transmitted`] to set `acc ← t` with the transmitted coordinates
///    zeroed — the residual (dropped mass + quantization error) carries into
///    the next round.
///
/// The accumulator is persisted next to the optimizer checkpoint. This Rust
/// type exists so the protocol layer can validate the trainer's error-feedback
/// discipline in tests and so a Rust-side syncer (Confidential tier, where the
/// syncer may run inside the enclave) can reproduce it; the production trainer
/// runs the byte-identical Python implementation in
/// `integrations/trainer/tenzro_trainer/gradient.py`.
#[derive(Debug, Clone)]
pub struct ErrorFeedback {
    decay: f32,
    acc: Vec<f32>,
}

impl ErrorFeedback {
    /// New accumulator over a length-`len` fragment. `decay` is β (≈ 0.95);
    /// it is clamped to `[0, 1]`.
    pub fn new(len: usize, decay: f32) -> Self {
        Self {
            decay: decay.clamp(0.0, 1.0),
            acc: vec![0.0f32; len],
        }
    }

    /// The decay coefficient β.
    pub fn decay(&self) -> f32 {
        self.decay
    }

    /// Read-only view of the current accumulator.
    pub fn accumulator(&self) -> &[f32] {
        &self.acc
    }

    /// Produce the transmit vector `t = decay·acc + grad` for this round.
    /// `grad` is the raw outer pseudo-gradient; length must match the
    /// accumulator. The returned vector is what the caller sparsifies and
    /// sends; the caller must follow up with [`Self::commit_transmitted`].
    pub fn prepare_transmit(&self, grad: &[f32]) -> Result<Vec<f32>> {
        if grad.len() != self.acc.len() {
            return Err(TrainingError::DimensionMismatch(format!(
                "error-feedback grad length {} != accumulator length {}",
                grad.len(),
                self.acc.len()
            )));
        }
        Ok(self
            .acc
            .iter()
            .zip(grad.iter())
            .map(|(a, g)| self.decay * a + g)
            .collect())
    }

    /// Set the accumulator to the transmit vector `t`, then zero the exact
    /// coordinates that were transmitted (error feedback). `transmit` is the
    /// vector returned by [`Self::prepare_transmit`]; `transmitted` is the pair
    /// list from [`select_transmitted`] run on the same `transmit`.
    pub fn commit_transmitted(&mut self, transmit: &[f32], transmitted: &[(usize, f32)]) {
        debug_assert_eq!(transmit.len(), self.acc.len());
        self.acc.copy_from_slice(transmit);
        for &(idx, value) in transmitted {
            if idx < self.acc.len() {
                self.acc[idx] -= value;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> SparseTopKParams {
        SparseTopKParams {
            chunk_size: 8,
            k: 2,
        }
    }

    #[test]
    fn encoded_len_matches_bytes() {
        let p = params();
        // 20 values → chunks of 8, 8, 4 → kept 2, 2, 2.
        let values: Vec<f32> = (0..20).map(|i| (i as f32) - 10.0).collect();
        let bytes = sparse_encode(&values, p);
        assert_eq!(bytes.len(), sparse_encoded_len(20, p));
    }

    #[test]
    fn top_k_keeps_largest_magnitude() {
        // Chunk [0.1, -5.0, 0.2, 3.0, 0.0, 0.0, 0.0, 0.0], k=2 → keep {1, 3}.
        let chunk = [0.1f32, -5.0, 0.2, 3.0, 0.0, 0.0, 0.0, 0.0];
        let top = top_k_indices(&chunk, 2);
        assert_eq!(top, vec![1, 3]);
    }

    #[test]
    fn decode_recovers_sign_at_scale() {
        let p = params();
        // One chunk, dominant +8 and -6. k=2.
        let mut values = vec![0.0f32; 8];
        values[2] = 8.0;
        values[5] = -6.0;
        let bytes = sparse_encode(&values, p);
        let back = sparse_decode(&bytes, p, 8).unwrap();
        // scale = max_abs = 8.0; +8 → +1*8 = 8; -6 → -1*8 = -8; rest 0.
        assert_eq!(back[2], 8.0);
        assert_eq!(back[5], -8.0);
        for (i, v) in back.iter().enumerate() {
            if i != 2 && i != 5 {
                assert_eq!(*v, 0.0);
            }
        }
    }

    #[test]
    fn all_zero_chunk_round_trips_to_zeros() {
        let p = params();
        let values = vec![0.0f32; 16];
        let bytes = sparse_encode(&values, p);
        let back = sparse_decode(&bytes, p, 16).unwrap();
        assert!(back.iter().all(|v| *v == 0.0));
    }

    #[test]
    fn wrong_length_rejected() {
        let p = params();
        let values: Vec<f32> = (0..16).map(|i| i as f32).collect();
        let bytes = sparse_encode(&values, p);
        assert!(sparse_decode(&bytes, p, 17).is_err());
        assert!(sparse_decode(&bytes[..bytes.len() - 1], p, 16).is_err());
    }

    #[test]
    fn compresses_well_over_100x() {
        // 1M coords, chunk 4096, k 64 → density ~1.5%, 2-bit codes.
        let p = SparseTopKParams::DEFAULT;
        let dense = 1_000_000 * 4;
        let sparse = sparse_encoded_len(1_000_000, p);
        let ratio = dense as f64 / sparse as f64;
        assert!(ratio > 100.0, "ratio {ratio}");
    }

    #[test]
    fn select_transmitted_matches_decode() {
        let p = params();
        let mut values = vec![0.0f32; 8];
        values[1] = 4.0;
        values[6] = -3.0;
        let sent = select_transmitted(&values, p);
        let back = sparse_decode(&sparse_encode(&values, p), p, 8).unwrap();
        for (idx, v) in sent {
            assert_eq!(back[idx], v, "coord {idx}");
        }
    }

    #[test]
    fn error_feedback_carries_dropped_mass() {
        // decay 0.0 isolates a single round: acc after = transmit with
        // transmitted coords zeroed = the dropped residual.
        let mut ef = ErrorFeedback::new(8, 0.0);
        // grad has 3 nonzeros but k=2 keeps only the top 2 by magnitude.
        let mut grad = vec![0.0f32; 8];
        grad[0] = 5.0; // kept
        grad[3] = -4.0; // kept
        grad[7] = 1.0; // dropped
        let transmit = ef.prepare_transmit(&grad).unwrap();
        let p = params();
        let sent = select_transmitted(&transmit, p);
        ef.commit_transmitted(&transmit, &sent);
        // Dropped coordinate survives in the accumulator; transmitted ones are
        // reduced by exactly what was sent.
        assert_eq!(ef.accumulator()[7], 1.0);
        // coord 0 sent +5 (quantized to +1*5 = 5) → residual 0.
        assert!((ef.accumulator()[0]).abs() < 1e-6);
    }

    #[test]
    fn error_feedback_accumulates_across_rounds() {
        // A coordinate that is always just below the top-k threshold should
        // accumulate until it crosses it and gets transmitted.
        let p = SparseTopKParams {
            chunk_size: 4,
            k: 1,
        };
        let mut ef = ErrorFeedback::new(4, 0.95);
        let grad = vec![1.0f32, 0.9, 0.0, 0.0]; // coord 0 always wins round 1
        let mut crossed = false;
        for _ in 0..20 {
            let t = ef.prepare_transmit(&grad).unwrap();
            let sent = select_transmitted(&t, p);
            // If coord 1 ever gets transmitted, error feedback did its job.
            if sent.iter().any(|(i, _)| *i == 1) {
                crossed = true;
                break;
            }
            ef.commit_transmitted(&t, &sent);
        }
        assert!(
            crossed,
            "error feedback never surfaced the sub-threshold coord"
        );
    }

    #[test]
    fn dim_mismatch_rejected() {
        let ef = ErrorFeedback::new(8, 0.95);
        assert!(ef.prepare_transmit(&[0.0; 7]).is_err());
    }
}
