//! Blockwise symmetric quantization for outer-gradient payloads.
//!
//! Streaming DiLoCo (arXiv 2501.18512) shows outer gradients tolerate 4-bit
//! quantization with no convergence loss — they are momentum-smoothed deltas,
//! not raw activations. This module is the Rust side of the wire format; the
//! Python reference trainer (`tenzro_trainer.quantization`) implements the
//! byte-identical encoder/decoder.
//!
//! # Wire format
//!
//! The tensor is split into blocks of `block_size` values (the final block
//! may be shorter). Each block serializes as:
//!
//! - `Int8`: 4-byte little-endian `f32` scale, then one `i8` code per value.
//!   `scale = max_abs / 127`, `code = round(value / scale)` clamped to
//!   `[-127, 127]`.
//! - `Int4`: 4-byte little-endian `f32` scale, then `ceil(len / 2)` bytes of
//!   codes packed two per byte (low nibble first, odd tail zero-padded).
//!   `scale = max_abs / 7`, codes clamped to `[-7, 7]`, stored as 4-bit
//!   two's complement.
//!
//! All-zero blocks store `scale = 0.0` and all-zero codes; dequantization of
//! a zero scale yields zeros. Dequantized value = `code as f32 * scale`.
//!
//! `GradientQuantization::None` is raw little-endian `f32` — the pre-existing
//! payload format, unchanged.

use tenzro_types::training::GradientQuantization;

use crate::error::{Result, TrainingError};

/// Encode a slice of `f32` values into the quantized wire format.
pub fn quantize(values: &[f32], quantization: GradientQuantization) -> Vec<u8> {
    match quantization {
        GradientQuantization::None => {
            let mut out = Vec::with_capacity(values.len() * 4);
            for v in values {
                out.extend_from_slice(&v.to_le_bytes());
            }
            out
        }
        GradientQuantization::Int8 { block_size } => {
            let block = block_size.max(1) as usize;
            let mut out = Vec::with_capacity(values.len() + values.len().div_ceil(block) * 4);
            for chunk in values.chunks(block) {
                let max_abs = chunk.iter().fold(0.0f32, |acc, v| acc.max(v.abs()));
                let scale = max_abs / 127.0;
                out.extend_from_slice(&scale.to_le_bytes());
                for v in chunk {
                    let code = if scale == 0.0 {
                        0i8
                    } else {
                        (v / scale).round().clamp(-127.0, 127.0) as i8
                    };
                    out.push(code as u8);
                }
            }
            out
        }
        GradientQuantization::Int4 { block_size } => {
            let block = block_size.max(1) as usize;
            let mut out =
                Vec::with_capacity(values.len() / 2 + values.len().div_ceil(block) * 5);
            for chunk in values.chunks(block) {
                let max_abs = chunk.iter().fold(0.0f32, |acc, v| acc.max(v.abs()));
                let scale = max_abs / 7.0;
                out.extend_from_slice(&scale.to_le_bytes());
                let mut iter = chunk.iter();
                loop {
                    let Some(lo) = iter.next() else { break };
                    let hi = iter.next();
                    let lo_code = encode_nibble(*lo, scale);
                    let hi_code = hi.map(|v| encode_nibble(*v, scale)).unwrap_or(0);
                    out.push((lo_code & 0x0F) | (hi_code << 4));
                }
            }
            out
        }
    }
}

/// Decode a quantized wire payload back into `f32` values. `expected_len`
/// is the element count declared by the task's architecture — a payload
/// whose structure disagrees with it is rejected as malformed.
pub fn dequantize(
    bytes: &[u8],
    quantization: GradientQuantization,
    expected_len: usize,
) -> Result<Vec<f32>> {
    match quantization {
        GradientQuantization::None => {
            if bytes.len() != expected_len * 4 {
                return Err(TrainingError::QuantizedPayloadMalformed(format!(
                    "raw f32 payload is {} bytes, expected {} for {} values",
                    bytes.len(),
                    expected_len * 4,
                    expected_len
                )));
            }
            Ok(bytes
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect())
        }
        GradientQuantization::Int8 { block_size } => {
            let block = block_size.max(1) as usize;
            let num_blocks = expected_len.div_ceil(block);
            let expected_bytes = expected_len + num_blocks * 4;
            if bytes.len() != expected_bytes {
                return Err(TrainingError::QuantizedPayloadMalformed(format!(
                    "int8/{block_size} payload is {} bytes, expected {expected_bytes} for \
                     {expected_len} values",
                    bytes.len()
                )));
            }
            let mut out = Vec::with_capacity(expected_len);
            let mut cursor = 0usize;
            let mut remaining = expected_len;
            while remaining > 0 {
                let block_len = remaining.min(block);
                let scale = f32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]);
                cursor += 4;
                for _ in 0..block_len {
                    out.push(bytes[cursor] as i8 as f32 * scale);
                    cursor += 1;
                }
                remaining -= block_len;
            }
            Ok(out)
        }
        GradientQuantization::Int4 { block_size } => {
            let block = block_size.max(1) as usize;
            let num_blocks = expected_len.div_ceil(block);
            // Each block: 4-byte scale + ceil(block_len / 2) code bytes.
            let mut expected_bytes = num_blocks * 4;
            let mut rem = expected_len;
            while rem > 0 {
                let block_len = rem.min(block);
                expected_bytes += block_len.div_ceil(2);
                rem -= block_len;
            }
            if bytes.len() != expected_bytes {
                return Err(TrainingError::QuantizedPayloadMalformed(format!(
                    "int4/{block_size} payload is {} bytes, expected {expected_bytes} for \
                     {expected_len} values",
                    bytes.len()
                )));
            }
            let mut out = Vec::with_capacity(expected_len);
            let mut cursor = 0usize;
            let mut remaining = expected_len;
            while remaining > 0 {
                let block_len = remaining.min(block);
                let scale = f32::from_le_bytes([
                    bytes[cursor],
                    bytes[cursor + 1],
                    bytes[cursor + 2],
                    bytes[cursor + 3],
                ]);
                cursor += 4;
                let code_bytes = block_len.div_ceil(2);
                for i in 0..block_len {
                    let byte = bytes[cursor + i / 2];
                    let nibble = if i % 2 == 0 { byte & 0x0F } else { byte >> 4 };
                    out.push(decode_nibble(nibble) as f32 * scale);
                }
                cursor += code_bytes;
                remaining -= block_len;
            }
            Ok(out)
        }
    }
}

/// Size in bytes of the quantized encoding of `len` values.
pub fn encoded_len(len: usize, quantization: GradientQuantization) -> usize {
    match quantization {
        GradientQuantization::None => len * 4,
        GradientQuantization::Int8 { block_size } => {
            let block = block_size.max(1) as usize;
            len + len.div_ceil(block) * 4
        }
        GradientQuantization::Int4 { block_size } => {
            let block = block_size.max(1) as usize;
            let mut total = len.div_ceil(block) * 4;
            let mut rem = len;
            while rem > 0 {
                let block_len = rem.min(block);
                total += block_len.div_ceil(2);
                rem -= block_len;
            }
            total
        }
    }
}

fn encode_nibble(value: f32, scale: f32) -> u8 {
    let code = if scale == 0.0 {
        0i8
    } else {
        (value / scale).round().clamp(-7.0, 7.0) as i8
    };
    // 4-bit two's complement.
    (code as u8) & 0x0F
}

fn decode_nibble(nibble: u8) -> i8 {
    // Sign-extend a 4-bit two's-complement value.
    if nibble & 0x08 != 0 {
        (nibble | 0xF0) as i8
    } else {
        nibble as i8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> Vec<f32> {
        // Deterministic pseudo-gradient values spanning signs and magnitudes.
        (0..n)
            .map(|i| {
                let x = i as f32;
                ((x * 0.7311).sin() * 0.05) + ((x * 0.1123).cos() * 0.002)
            })
            .collect()
    }

    #[test]
    fn none_round_trips_exactly() {
        let values = sample(1000);
        let bytes = quantize(&values, GradientQuantization::None);
        assert_eq!(bytes.len(), 4000);
        let back = dequantize(&bytes, GradientQuantization::None, 1000).unwrap();
        assert_eq!(back, values);
    }

    #[test]
    fn int8_round_trip_error_bounded() {
        let values = sample(1000);
        let q = GradientQuantization::Int8 { block_size: 256 };
        let bytes = quantize(&values, q);
        assert_eq!(bytes.len(), encoded_len(1000, q));
        let back = dequantize(&bytes, q, 1000).unwrap();
        assert_eq!(back.len(), values.len());
        for (chunk_v, chunk_b) in values.chunks(256).zip(back.chunks(256)) {
            let max_abs = chunk_v.iter().fold(0.0f32, |a, v| a.max(v.abs()));
            let bound = max_abs / 127.0 / 2.0 + f32::EPSILON;
            for (v, b) in chunk_v.iter().zip(chunk_b) {
                assert!(
                    (v - b).abs() <= bound * 1.01,
                    "int8 error {} exceeds half-step {}",
                    (v - b).abs(),
                    bound
                );
            }
        }
    }

    #[test]
    fn int4_round_trip_error_bounded() {
        let values = sample(999); // odd length exercises nibble padding
        let q = GradientQuantization::Int4 { block_size: 128 };
        let bytes = quantize(&values, q);
        assert_eq!(bytes.len(), encoded_len(999, q));
        let back = dequantize(&bytes, q, 999).unwrap();
        assert_eq!(back.len(), values.len());
        for (chunk_v, chunk_b) in values.chunks(128).zip(back.chunks(128)) {
            let max_abs = chunk_v.iter().fold(0.0f32, |a, v| a.max(v.abs()));
            let bound = max_abs / 7.0 / 2.0 + f32::EPSILON;
            for (v, b) in chunk_v.iter().zip(chunk_b) {
                assert!(
                    (v - b).abs() <= bound * 1.01,
                    "int4 error {} exceeds half-step {}",
                    (v - b).abs(),
                    bound
                );
            }
        }
    }

    #[test]
    fn int4_compresses_roughly_8x() {
        let q = GradientQuantization::Int4 { block_size: 256 };
        let raw = encoded_len(100_000, GradientQuantization::None);
        let packed = encoded_len(100_000, q);
        assert!(
            (raw as f64 / packed as f64) > 7.5,
            "ratio {}",
            raw as f64 / packed as f64
        );
    }

    #[test]
    fn zero_block_round_trips_to_zeros() {
        let values = vec![0.0f32; 300];
        for q in [
            GradientQuantization::Int8 { block_size: 128 },
            GradientQuantization::Int4 { block_size: 128 },
        ] {
            let bytes = quantize(&values, q);
            let back = dequantize(&bytes, q, 300).unwrap();
            assert!(back.iter().all(|v| *v == 0.0), "{q}");
        }
    }

    #[test]
    fn odd_tail_block_shorter_than_block_size() {
        let values = sample(130); // 128 + 2 tail
        let q = GradientQuantization::Int8 { block_size: 128 };
        let bytes = quantize(&values, q);
        assert_eq!(bytes.len(), encoded_len(130, q));
        let back = dequantize(&bytes, q, 130).unwrap();
        assert_eq!(back.len(), 130);
    }

    #[test]
    fn wrong_length_rejected() {
        let values = sample(100);
        for q in [
            GradientQuantization::None,
            GradientQuantization::Int8 { block_size: 64 },
            GradientQuantization::Int4 { block_size: 64 },
        ] {
            let bytes = quantize(&values, q);
            let err = dequantize(&bytes, q, 101).unwrap_err();
            assert!(
                matches!(err, TrainingError::QuantizedPayloadMalformed(_)),
                "{q}: {err:?}"
            );
            let err = dequantize(&bytes[..bytes.len() - 1], q, 100).unwrap_err();
            assert!(
                matches!(err, TrainingError::QuantizedPayloadMalformed(_)),
                "{q}: {err:?}"
            );
        }
    }

    #[test]
    fn saturating_values_clamp() {
        // One outlier per block saturates the code range without panicking.
        let mut values = vec![0.001f32; 64];
        values[0] = 10.0;
        for q in [
            GradientQuantization::Int8 { block_size: 64 },
            GradientQuantization::Int4 { block_size: 64 },
        ] {
            let bytes = quantize(&values, q);
            let back = dequantize(&bytes, q, 64).unwrap();
            assert!((back[0] - 10.0).abs() < 0.01, "{q}: outlier {}", back[0]);
        }
    }
}
