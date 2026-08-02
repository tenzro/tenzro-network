//! Minimal GGUF header reader for cluster fit decisions.
//!
//! To decide whether a model needs a LAN cluster we need its layer count,
//! hidden dimension, and loaded footprint — but reading those via the
//! llama.cpp binding requires loading the model, which is the very thing the
//! decision gates. This module parses just the GGUF metadata key/value header
//! (no tensor data) to pull `<arch>.block_count` and `<arch>.embedding_length`,
//! and derives the footprint from the file size.
//!
//! GGUF v2/v3 layout (little-endian): magic `GGUF`, `u32` version, `u64`
//! tensor count, `u64` metadata-KV count, then each KV is a length-prefixed
//! UTF-8 key, a `u32` value-type tag, and the value. We walk the KV section,
//! skipping values we don't need, and stop once both target keys are found.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use crate::cluster::ModelShape;

/// GGUF metadata value-type tags (subset we decode; others are skipped by
/// their fixed or length-prefixed size).
const GGUF_TYPE_UINT8: u32 = 0;
const GGUF_TYPE_INT8: u32 = 1;
const GGUF_TYPE_UINT16: u32 = 2;
const GGUF_TYPE_INT16: u32 = 3;
const GGUF_TYPE_UINT32: u32 = 4;
const GGUF_TYPE_INT32: u32 = 5;
const GGUF_TYPE_FLOAT32: u32 = 6;
const GGUF_TYPE_BOOL: u32 = 7;
const GGUF_TYPE_STRING: u32 = 8;
const GGUF_TYPE_ARRAY: u32 = 9;
const GGUF_TYPE_UINT64: u32 = 10;
const GGUF_TYPE_INT64: u32 = 11;
const GGUF_TYPE_FLOAT64: u32 = 12;

/// Errors raised while reading a GGUF header.
#[derive(Debug, thiserror::Error)]
pub enum GgufShapeError {
    /// The file could not be opened or read.
    #[error("gguf io error: {0}")]
    Io(#[from] io::Error),
    /// The file does not begin with the `GGUF` magic.
    #[error("not a gguf file (bad magic)")]
    BadMagic,
    /// The GGUF version is not one this reader understands (2 or 3).
    #[error("unsupported gguf version {0}")]
    UnsupportedVersion(u32),
    /// A required metadata key was absent.
    #[error("gguf missing key {0}")]
    MissingKey(String),
    /// A value carried an unexpected type tag.
    #[error("gguf key {key} had unexpected type {ty}")]
    UnexpectedType {
        /// The key whose value type was wrong.
        key: String,
        /// The type tag found.
        ty: u32,
    },
}

/// Fixed byte width of a scalar GGUF value type, or `None` for variable-width
/// (string / array) types that must be length-decoded.
fn scalar_width(ty: u32) -> Option<u64> {
    match ty {
        GGUF_TYPE_UINT8 | GGUF_TYPE_INT8 | GGUF_TYPE_BOOL => Some(1),
        GGUF_TYPE_UINT16 | GGUF_TYPE_INT16 => Some(2),
        GGUF_TYPE_UINT32 | GGUF_TYPE_INT32 | GGUF_TYPE_FLOAT32 => Some(4),
        GGUF_TYPE_UINT64 | GGUF_TYPE_INT64 | GGUF_TYPE_FLOAT64 => Some(8),
        _ => None,
    }
}

struct Reader<R: Read> {
    inner: R,
}

impl<R: Read> Reader<R> {
    fn u32(&mut self) -> Result<u32, GgufShapeError> {
        let mut b = [0u8; 4];
        self.inner.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, GgufShapeError> {
        let mut b = [0u8; 8];
        self.inner.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// Read a GGUF length-prefixed UTF-8 string (`u64` length + bytes).
    fn string(&mut self) -> Result<String, GgufShapeError> {
        let len = self.u64()?;
        let mut buf = vec![0u8; len as usize];
        self.inner.read_exact(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Advance over `n` bytes without retaining them.
    fn skip(&mut self, n: u64) -> Result<(), GgufShapeError> {
        io::copy(&mut self.inner.by_ref().take(n), &mut io::sink())?;
        Ok(())
    }

    /// Skip a value of the given type tag (the key and tag are already read).
    fn skip_value(&mut self, ty: u32) -> Result<(), GgufShapeError> {
        if let Some(w) = scalar_width(ty) {
            self.skip(w)?;
        } else if ty == GGUF_TYPE_STRING {
            let len = self.u64()?;
            self.skip(len)?;
        } else if ty == GGUF_TYPE_ARRAY {
            let elem_ty = self.u32()?;
            let count = self.u64()?;
            if let Some(w) = scalar_width(elem_ty) {
                self.skip(w * count)?;
            } else if elem_ty == GGUF_TYPE_STRING {
                for _ in 0..count {
                    let len = self.u64()?;
                    self.skip(len)?;
                }
            } else {
                // Nested arrays are not used by the keys we read; treat as a
                // hard stop rather than guessing a width.
                return Err(GgufShapeError::UnexpectedType {
                    key: "<array element>".to_string(),
                    ty: elem_ty,
                });
            }
        } else {
            return Err(GgufShapeError::UnexpectedType {
                key: "<value>".to_string(),
                ty,
            });
        }
        Ok(())
    }

    /// Read a `u32`-typed scalar value, accepting the narrower int tags GGUF
    /// writers sometimes use for the same field.
    fn read_u32_value(&mut self, key: &str, ty: u32) -> Result<u32, GgufShapeError> {
        match ty {
            GGUF_TYPE_UINT32 | GGUF_TYPE_INT32 => Ok(self.u32()?),
            GGUF_TYPE_UINT64 | GGUF_TYPE_INT64 => Ok(self.u64()? as u32),
            GGUF_TYPE_UINT16 | GGUF_TYPE_INT16 => {
                let mut b = [0u8; 2];
                self.inner.read_exact(&mut b)?;
                Ok(u16::from_le_bytes(b) as u32)
            }
            _ => Err(GgufShapeError::UnexpectedType {
                key: key.to_string(),
                ty,
            }),
        }
    }
}

/// Read the [`ModelShape`] from a GGUF file by parsing only its metadata
/// header. `total_vram_gb` is taken from the on-disk file size (the dominant
/// term in the loaded footprint; KV-cache and scratch are modeled by the
/// per-member VRAM floor in the planner, not here).
pub fn read_model_shape(path: &Path) -> Result<ModelShape, GgufShapeError> {
    let file_size = std::fs::metadata(path)?.len();
    let file = File::open(path)?;
    let mut r = Reader {
        inner: BufReader::new(file),
    };

    let mut magic = [0u8; 4];
    r.inner.read_exact(&mut magic)?;
    if &magic != b"GGUF" {
        return Err(GgufShapeError::BadMagic);
    }
    let version = r.u32()?;
    if version != 2 && version != 3 {
        return Err(GgufShapeError::UnsupportedVersion(version));
    }
    let _tensor_count = r.u64()?;
    let kv_count = r.u64()?;

    // First pass goal: learn the architecture prefix, then match the two
    // arch-scoped keys. The architecture key may appear after the layer keys,
    // so we collect candidates by suffix and resolve once known.
    let mut arch: Option<String> = None;
    let mut block_count: Option<u32> = None;
    let mut embedding_length: Option<u32> = None;

    for _ in 0..kv_count {
        let key = r.string()?;
        let ty = r.u32()?;

        if key == "general.architecture" {
            if ty != GGUF_TYPE_STRING {
                return Err(GgufShapeError::UnexpectedType { key, ty });
            }
            arch = Some(r.string()?);
        } else if key.ends_with(".block_count") {
            block_count = Some(r.read_u32_value(&key, ty)?);
        } else if key.ends_with(".embedding_length") {
            embedding_length = Some(r.read_u32_value(&key, ty)?);
        } else {
            r.skip_value(ty)?;
        }

        if arch.is_some() && block_count.is_some() && embedding_length.is_some() {
            break;
        }
    }

    let layers = block_count.ok_or_else(|| GgufShapeError::MissingKey("*.block_count".into()))?;
    let hidden_dim =
        embedding_length.ok_or_else(|| GgufShapeError::MissingKey("*.embedding_length".into()))?;

    Ok(ModelShape {
        layers,
        hidden_dim,
        total_vram_gb: file_size as f32 / 1_073_741_824.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads a real on-disk GGUF when one is present in the default models
    /// dir. Skips silently when absent so CI without model artifacts stays
    /// green; run locally after a `tenzro model download` to exercise it.
    #[test]
    fn reads_shape_from_local_gguf_when_present() {
        let home = match std::env::var("HOME") {
            Ok(h) => h,
            Err(_) => return,
        };
        let path = std::path::Path::new(&home).join(".tenzro/models/gemma3-270m.gguf");
        if !path.exists() {
            return;
        }
        let shape = read_model_shape(&path).expect("parse gemma3-270m gguf header");
        assert_eq!(shape.layers, 18);
        assert_eq!(shape.hidden_dim, 640);
        assert!(shape.total_vram_gb > 0.0);
        // Boundary activation is hidden_dim * 2 bytes (fp16).
        assert_eq!(shape.activation_bytes_per_token(), 640 * 2);
    }

    /// Build a GGUF header in memory, so the parser is covered without a
    /// multi-gigabyte artifact.
    ///
    /// The pre-existing local-file test above skips silently when no model has
    /// been downloaded, which on CI means it never runs at all — a parser
    /// guarded only by a test that does not execute is a parser with no tests.
    fn synthetic_gguf(
        arch: &str,
        layers: u32,
        hidden: u32,
        filler_kvs: &[(&str, &str)],
    ) -> Vec<u8> {
        fn push_str(buf: &mut Vec<u8>, s: &str) {
            buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        let mut b = Vec::new();
        b.extend_from_slice(b"GGUF");
        b.extend_from_slice(&3u32.to_le_bytes()); // version
        b.extend_from_slice(&0u64.to_le_bytes()); // tensor count
        b.extend_from_slice(&((3 + filler_kvs.len()) as u64).to_le_bytes());

        push_str(&mut b, "general.architecture");
        b.extend_from_slice(&GGUF_TYPE_STRING.to_le_bytes());
        push_str(&mut b, arch);

        // Interleave unrelated keys, because a real header has hundreds of them
        // and the parser has to skip every value type it does not want.
        for (k, v) in filler_kvs {
            push_str(&mut b, k);
            b.extend_from_slice(&GGUF_TYPE_STRING.to_le_bytes());
            push_str(&mut b, v);
        }

        push_str(&mut b, &format!("{arch}.block_count"));
        b.extend_from_slice(&GGUF_TYPE_UINT32.to_le_bytes());
        b.extend_from_slice(&layers.to_le_bytes());

        push_str(&mut b, &format!("{arch}.embedding_length"));
        b.extend_from_slice(&GGUF_TYPE_UINT32.to_le_bytes());
        b.extend_from_slice(&hidden.to_le_bytes());
        b
    }

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(name);
        std::fs::write(&p, bytes).expect("write fixture");
        p
    }

    #[test]
    fn reads_layers_and_hidden_dim_from_a_synthetic_header() {
        // The numbers are Qwen3-0.6B's, checked against the real artifact on
        // disk: 28 layers, hidden 1024.
        let bytes = synthetic_gguf("qwen3", 28, 1024, &[]);
        let path = write_temp("tenzro_gguf_plain.gguf", &bytes);
        let shape = read_model_shape(&path).expect("parses");
        assert_eq!(shape.layers, 28);
        assert_eq!(shape.hidden_dim, 1024);
        assert_eq!(shape.activation_bytes_per_token(), 1024 * 2);
        assert!(shape.total_vram_gb > 0.0, "size comes from the file length");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn skips_over_unrelated_keys_before_the_ones_it_wants() {
        // A real header carries hundreds of keys — tokenizer tables, chat
        // templates, quantization notes — ahead of the two that matter. A
        // parser that only works when its keys come first works on nothing.
        let bytes = synthetic_gguf(
            "gemma3",
            18,
            640,
            &[
                ("general.name", "Gemma 3 270M"),
                ("general.license", "gemma"),
                ("tokenizer.ggml.model", "llama"),
                (
                    "tokenizer.chat_template",
                    "{% for m in messages %}...{% endfor %}",
                ),
            ],
        );
        let path = write_temp("tenzro_gguf_filled.gguf", &bytes);
        let shape = read_model_shape(&path).expect("parses");
        assert_eq!(shape.layers, 18);
        assert_eq!(shape.hidden_dim, 640);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_header_missing_the_layer_count_is_an_error_not_a_guess() {
        // Returning a default here would hand the planner an invented layer
        // count it cannot distinguish from a measured one — and layers is what
        // decides whether a long-context serve fits.
        let mut b = Vec::new();
        b.extend_from_slice(b"GGUF");
        b.extend_from_slice(&3u32.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes());
        b.extend_from_slice(&("general.architecture".len() as u64).to_le_bytes());
        b.extend_from_slice(b"general.architecture");
        b.extend_from_slice(&GGUF_TYPE_STRING.to_le_bytes());
        b.extend_from_slice(&5u64.to_le_bytes());
        b.extend_from_slice(b"qwen3");
        let path = write_temp("tenzro_gguf_nolayers.gguf", &b);
        assert!(matches!(
            read_model_shape(&path),
            Err(GgufShapeError::MissingKey(_))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_non_gguf_file() {
        let mut tmp = std::env::temp_dir();
        tmp.push("tenzro_not_a_gguf.bin");
        std::fs::write(&tmp, b"NOTGGUFDATA").unwrap();
        let err = read_model_shape(&tmp).unwrap_err();
        assert!(matches!(err, GgufShapeError::BadMagic));
        let _ = std::fs::remove_file(&tmp);
    }
}
