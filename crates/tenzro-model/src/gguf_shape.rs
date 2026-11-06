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

    /// Read a `u32` list: a scalar yields one element, an array one per
    /// element. Hybrid models (Nemotron-H, Granite hybrid) store per-layer
    /// KV head counts and feed-forward widths as arrays.
    fn read_u32_list(&mut self, key: &str, ty: u32) -> Result<Vec<u32>, GgufShapeError> {
        if ty != GGUF_TYPE_ARRAY {
            return Ok(vec![self.read_u32_value(key, ty)?]);
        }
        let elem_ty = self.u32()?;
        let count = self.u64()?;
        if count > (1 << 20) {
            return Err(GgufShapeError::UnexpectedType {
                key: key.to_string(),
                ty,
            });
        }
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            out.push(self.read_u32_value(key, elem_ty)?);
        }
        Ok(out)
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

/// Total on-disk bytes of a model file. A sharded set
/// (`name-00001-of-00009.gguf`) is one model spread over several files, and
/// the entry point is only the first of them (a few MB of metadata for the
/// large sets), so the footprint is the sum of every shard that is present.
fn sharded_total_bytes(path: &Path) -> Result<u64, GgufShapeError> {
    let own = std::fs::metadata(path)?.len();
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(own);
    };
    let Some(stem) = name.strip_suffix(".gguf") else {
        return Ok(own);
    };
    let Some(of_at) = stem.rfind("-of-") else {
        return Ok(own);
    };
    let total = &stem[of_at + 4..];
    let head = &stem[..of_at];
    let Some(idx_at) = head.rfind('-') else {
        return Ok(own);
    };
    let (prefix, idx) = (&head[..=idx_at], &head[idx_at + 1..]);
    if total.parse::<u32>().is_err() || idx.parse::<u32>().is_err() || idx.len() != total.len() {
        return Ok(own);
    }
    let count: u32 = total.parse().unwrap_or(1);
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut sum = 0u64;
    for i in 1..=count {
        let shard = dir.join(format!(
            "{prefix}{i:0width$}-of-{total}.gguf",
            width = total.len()
        ));
        if let Ok(m) = std::fs::metadata(&shard) {
            sum += m.len();
        }
    }
    Ok(sum.max(own))
}

/// Read the [`ModelShape`] from a GGUF file by parsing only its metadata
/// header. `total_vram_gb` is taken from the on-disk file size (the dominant
/// term in the loaded footprint; KV-cache and scratch are modeled by the
/// per-member VRAM floor in the planner, not here).
pub fn read_model_shape(path: &Path) -> Result<ModelShape, GgufShapeError> {
    let file_size = sharded_total_bytes(path)?;
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

    // The architecture-scoped keys are matched by suffix, because the
    // architecture key may appear after them.
    let mut block_count: Option<u32> = None;
    let mut embedding_length: Option<u32> = None;
    // KV-cache inputs. Optional: a model whose gguf omits them still yields a
    // ModelShape (weights + activation), just without a KV estimate.
    let mut key_length: Option<u32> = None;
    let mut context_length: Option<u32> = None;
    // Hybrid inputs: per-layer KV heads / feed-forward widths (arrays) and the
    // state-space block's dimensions.
    let mut kv_heads_list: Vec<u32> = Vec::new();
    let mut ff_list: Vec<u32> = Vec::new();
    let mut ssm_conv_kernel: Option<u32> = None;
    let mut ssm_inner: Option<u32> = None;
    let mut ssm_state: Option<u32> = None;
    let mut ssm_groups: Option<u32> = None;

    for _ in 0..kv_count {
        let key = r.string()?;
        let ty = r.u32()?;

        if key == "general.architecture" {
            if ty != GGUF_TYPE_STRING {
                return Err(GgufShapeError::UnexpectedType { key, ty });
            }
            r.string()?;
        } else if key.ends_with(".block_count") {
            block_count = Some(r.read_u32_value(&key, ty)?);
        } else if key.ends_with(".embedding_length") {
            embedding_length = Some(r.read_u32_value(&key, ty)?);
        } else if key.ends_with(".attention.head_count_kv") {
            kv_heads_list = r.read_u32_list(&key, ty)?;
        } else if key.ends_with(".feed_forward_length") {
            ff_list = r.read_u32_list(&key, ty)?;
        } else if key.ends_with(".ssm.conv_kernel") {
            ssm_conv_kernel = Some(r.read_u32_value(&key, ty)?);
        } else if key.ends_with(".ssm.inner_size") {
            ssm_inner = Some(r.read_u32_value(&key, ty)?);
        } else if key.ends_with(".ssm.state_size") {
            ssm_state = Some(r.read_u32_value(&key, ty)?);
        } else if key.ends_with(".ssm.group_count") {
            ssm_groups = Some(r.read_u32_value(&key, ty)?);
        } else if key.ends_with(".attention.key_length") {
            key_length = Some(r.read_u32_value(&key, ty)?);
        } else if key.ends_with(".context_length") {
            context_length = Some(r.read_u32_value(&key, ty)?);
        } else {
            r.skip_value(ty)?;
        }
        // No early break: the KV keys can appear after the three required ones,
        // so the whole metadata block is scanned. GGUF headers are small.
    }

    let layers = block_count.ok_or_else(|| GgufShapeError::MissingKey("*.block_count".into()))?;
    let hidden_dim =
        embedding_length.ok_or_else(|| GgufShapeError::MissingKey("*.embedding_length".into()))?;

    let per_layer = kv_heads_list.len() == layers as usize && layers > 1;
    let head_count_kv: Option<u32> = if per_layer {
        kv_heads_list.iter().copied().filter(|h| *h > 0).max()
    } else {
        kv_heads_list.first().copied()
    };
    let attention_layers =
        per_layer.then(|| kv_heads_list.iter().filter(|h| **h > 0).count() as u32);
    // Recurrent layers: in a per-layer hybrid, a layer with neither KV heads
    // nor a feed-forward width is a state-space layer; a model that declares
    // state-space dimensions and no attention at all is recurrent throughout.
    let recurrent_layers = match (ssm_inner, per_layer) {
        (Some(_), true) => {
            let ff_per_layer = ff_list.len() == layers as usize;
            (0..layers as usize)
                .filter(|i| kv_heads_list[*i] == 0 && (!ff_per_layer || ff_list[*i] == 0))
                .count() as u64
        }
        (Some(_), false) if head_count_kv.is_none() => u64::from(layers),
        _ => 0,
    };
    let recurrent_state_bytes = match ssm_inner {
        Some(inner) => {
            let inner = u64::from(inner);
            let state = u64::from(ssm_state.unwrap_or(0));
            let groups = u64::from(ssm_groups.unwrap_or(0));
            let kernel = u64::from(ssm_conv_kernel.unwrap_or(1)).saturating_sub(1);
            let conv = kernel * (inner + 2 * groups * state);
            // f32 state.
            recurrent_layers * (conv + inner * state) * 4
        }
        None => 0,
    };

    Ok(ModelShape {
        attention_layers,
        recurrent_state_bytes,
        layers,
        hidden_dim,
        total_vram_gb: file_size as f32 / 1_073_741_824.0,
        head_count_kv,
        key_length,
        context_length,
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

    /// A header with typed KVs, to carry the array-valued per-layer keys a
    /// hybrid model uses.
    fn typed_gguf(arch: &str, kvs: &[(String, u32, Vec<u8>)]) -> Vec<u8> {
        fn push_str(buf: &mut Vec<u8>, s: &str) {
            buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        let mut b = Vec::new();
        b.extend_from_slice(b"GGUF");
        b.extend_from_slice(&3u32.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&((1 + kvs.len()) as u64).to_le_bytes());
        push_str(&mut b, "general.architecture");
        b.extend_from_slice(&GGUF_TYPE_STRING.to_le_bytes());
        push_str(&mut b, arch);
        for (k, ty, v) in kvs {
            push_str(&mut b, k);
            b.extend_from_slice(&ty.to_le_bytes());
            b.extend_from_slice(v);
        }
        b
    }

    fn u32_kv(k: &str, v: u32) -> (String, u32, Vec<u8>) {
        (k.to_string(), GGUF_TYPE_UINT32, v.to_le_bytes().to_vec())
    }

    fn u32_array_kv(k: &str, vs: &[u32]) -> (String, u32, Vec<u8>) {
        let mut v = Vec::new();
        v.extend_from_slice(&GGUF_TYPE_UINT32.to_le_bytes());
        v.extend_from_slice(&(vs.len() as u64).to_le_bytes());
        for x in vs {
            v.extend_from_slice(&x.to_le_bytes());
        }
        (k.to_string(), GGUF_TYPE_ARRAY, v)
    }

    /// The Nemotron 3 Ultra layout at full size: 108 layers, 48 Mamba-2, 48
    /// MoE and 12 attention with 2 KV heads of 128, state-space inner size
    /// 16384, state 128, 8 groups, kernel 4. The header stores per-layer KV
    /// heads and feed-forward widths as arrays, which the reader used to refuse.
    fn ultra_header() -> Vec<u8> {
        let a = "nemotron_h_moe";
        let mut kv = Vec::new();
        let mut ff = Vec::new();
        // Pattern of Ultra: mamba, moe repeated, with an attention layer every
        // ninth layer: 12 attention, 48 mamba, 48 moe.
        for i in 0..108u32 {
            // mamba, moe, mamba, moe, mamba, moe, mamba, attention, moe
            let (h, f) = [
                (0, 0),
                (0, 5120),
                (0, 0),
                (0, 5120),
                (0, 0),
                (0, 5120),
                (0, 0),
                (2, 0),
                (0, 5120),
            ][(i % 9) as usize];
            kv.push(h);
            ff.push(f);
        }
        let attn = kv.iter().filter(|h| **h > 0).count();
        assert_eq!(attn, 12);
        typed_gguf(
            a,
            &[
                u32_kv(&format!("{a}.block_count"), 108),
                u32_kv(&format!("{a}.embedding_length"), 8192),
                u32_kv(&format!("{a}.context_length"), 1_048_576),
                u32_array_kv(&format!("{a}.attention.head_count_kv"), &kv),
                u32_array_kv(&format!("{a}.feed_forward_length"), &ff),
                u32_kv(&format!("{a}.attention.key_length"), 128),
                u32_kv(&format!("{a}.ssm.conv_kernel"), 4),
                u32_kv(&format!("{a}.ssm.inner_size"), 16384),
                u32_kv(&format!("{a}.ssm.state_size"), 128),
                u32_kv(&format!("{a}.ssm.group_count"), 8),
            ],
        )
    }

    #[test]
    fn a_hybrid_header_with_per_layer_arrays_is_read_not_refused() {
        let path = write_temp("tenzro_gguf_nemotron_h.gguf", &ultra_header());
        let shape = read_model_shape(&path).expect("per-layer arrays parse");
        assert_eq!(shape.layers, 108);
        assert_eq!(shape.hidden_dim, 8192);
        assert_eq!(shape.head_count_kv, Some(2));
        assert_eq!(shape.attention_layers, Some(12));
        assert_eq!(shape.context_length, Some(1_048_576));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_hybrid_model_holds_a_cache_in_its_attention_layers_only() {
        let path = write_temp("tenzro_gguf_nemotron_h2.gguf", &ultra_header());
        let shape = read_model_shape(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        // Mamba-2 layers: 48. Per layer: conv (4-1) * (16384 + 2*8*128) f32
        // plus the scan state 16384 * 128 f32.
        let per_layer = (3 * (16384 + 2 * 8 * 128) + 16384 * 128) * 4;
        assert_eq!(shape.recurrent_state_bytes, 48 * per_layer as u64);
        // 1M tokens of KV on 12 attention layers: 2 (K,V) * 12 * 2 heads * 128 * 2 bytes.
        let kv = 2u64 * 12 * 2 * 128 * 2 * 1_000_000;
        assert_eq!(
            shape.kv_cache_bytes(1_000_000),
            Some(kv + shape.recurrent_state_bytes)
        );
        // A dense model of the same depth would hold 9x as much.
        let dense = ModelShape {
            attention_layers: None,
            recurrent_state_bytes: 0,
            ..shape
        };
        assert_eq!(dense.kv_cache_bytes(1_000_000), Some(kv * 9));
        // The advisor multiplies the per-layer figure by all layers and must
        // not under-count the attention-only total.
        let per = shape.kv_bytes_per_token_per_layer().unwrap();
        assert!(per * 108 >= 2 * 12 * 2 * 128 * 2);
    }

    #[test]
    fn a_sharded_model_is_sized_by_every_shard_not_the_entry_point() {
        let dir = std::env::temp_dir().join(format!("tenzro_shards_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = dir.join("Model-UD-IQ1_M-00001-of-00003.gguf");
        std::fs::write(&first, ultra_header()).unwrap();
        std::fs::write(
            dir.join("Model-UD-IQ1_M-00002-of-00003.gguf"),
            vec![0u8; 3_000_000],
        )
        .unwrap();
        std::fs::write(
            dir.join("Model-UD-IQ1_M-00003-of-00003.gguf"),
            vec![0u8; 2_000_000],
        )
        .unwrap();
        let shape = read_model_shape(&first).unwrap();
        let header = std::fs::metadata(&first).unwrap().len();
        let expect = (header + 5_000_000) as f32 / 1_073_741_824.0;
        assert!((shape.total_vram_gb - expect).abs() < 1e-6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pure_state_space_header_is_recurrent_in_every_layer() {
        let a = "mamba";
        let h = typed_gguf(
            a,
            &[
                u32_kv("mamba.block_count", 24),
                u32_kv("mamba.embedding_length", 768),
                u32_kv("mamba.ssm.conv_kernel", 4),
                u32_kv("mamba.ssm.inner_size", 1536),
                u32_kv("mamba.ssm.state_size", 16),
            ],
        );
        let path = write_temp("tenzro_gguf_mamba.gguf", &h);
        let shape = read_model_shape(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(shape.head_count_kv, None);
        assert_eq!(
            shape.recurrent_state_bytes,
            24 * (3 * 1536 + 1536 * 16) as u64 * 4
        );
    }

    /// The Nemotron 3.5 Bolt 74B-A9B layout: 88 layers, 40 Mamba-2, 40 MoE
    /// and 8 attention (2 KV heads of 128), state-space inner size 8192,
    /// state 128, 8 groups, kernel 4.
    fn bolt_74b_header() -> Vec<u8> {
        let a = "nemotron_h_moe";
        let (mut kv, mut ff) = (Vec::new(), Vec::new());
        // mamba, moe pairs with an attention layer every eleventh layer.
        for i in 0..88u32 {
            let (h, f) = if i % 11 == 7 {
                (2, 0)
            } else if i % 2 == 0 {
                (0, 0)
            } else {
                (0, 2048)
            };
            kv.push(h);
            ff.push(f);
        }
        assert_eq!(kv.iter().filter(|h| **h > 0).count(), 8);
        typed_gguf(
            a,
            &[
                u32_kv(&format!("{a}.block_count"), 88),
                u32_kv(&format!("{a}.embedding_length"), 4096),
                u32_kv(&format!("{a}.context_length"), 262_144),
                u32_array_kv(&format!("{a}.attention.head_count_kv"), &kv),
                u32_array_kv(&format!("{a}.feed_forward_length"), &ff),
                u32_kv(&format!("{a}.attention.key_length"), 128),
                u32_kv(&format!("{a}.ssm.conv_kernel"), 4),
                u32_kv(&format!("{a}.ssm.inner_size"), 8192),
                u32_kv(&format!("{a}.ssm.state_size"), 128),
                u32_kv(&format!("{a}.ssm.group_count"), 8),
            ],
        )
    }

    /// The cache a full-context request needs, at the contexts the registry
    /// publishes: 256K for Bolt 74B and 1M for Ultra. Hybrid layouts hold a
    /// cache only in their attention layers, so the figures are a small
    /// fraction of what the same depth would cost as a dense transformer, and
    /// they grow linearly with the context while the recurrent state does not.
    #[test]
    fn the_cache_of_a_full_context_request_is_sized_for_the_hybrid_layouts() {
        let ultra = write_temp("tenzro_gguf_ultra_sizing.gguf", &ultra_header());
        let bolt = write_temp("tenzro_gguf_bolt_sizing.gguf", &bolt_74b_header());
        let u = read_model_shape(&ultra).unwrap();
        let b = read_model_shape(&bolt).unwrap();
        let _ = std::fs::remove_file(&ultra);
        let _ = std::fs::remove_file(&bolt);

        // Ultra at 1,048,576 tokens: 12 attention layers x 2 heads x 128 x K and V x 2 bytes.
        let ultra_per_token = 2u64 * 12 * 2 * 128 * 2;
        let ultra_state = 48 * ((3 * (16384 + 2 * 8 * 128) + 16384 * 128) * 4) as u64;
        assert_eq!(u.recurrent_state_bytes, ultra_state);
        let ultra_1m = u.kv_cache_bytes(1_048_576).unwrap();
        assert_eq!(ultra_1m, ultra_per_token * 1_048_576 + ultra_state);
        // About 12.9 GB of keys and values plus 0.4 GB of recurrent state.
        assert!(
            ultra_1m > 13_000_000_000 && ultra_1m < 13_500_000_000,
            "{ultra_1m}"
        );
        // Dense, the same 108 layers would need nine times the keys and values.
        let dense = ModelShape {
            attention_layers: None,
            recurrent_state_bytes: 0,
            ..u
        };
        assert_eq!(
            dense.kv_cache_bytes(1_048_576).unwrap(),
            ultra_per_token * 9 * 1_048_576
        );

        // Bolt 74B at 262,144 tokens.
        let bolt_per_token = 2u64 * 8 * 2 * 128 * 2;
        let bolt_state = 40 * ((3 * (8192 + 2 * 8 * 128) + 8192 * 128) * 4) as u64;
        assert_eq!(b.recurrent_state_bytes, bolt_state);
        let bolt_256k = b.kv_cache_bytes(262_144).unwrap();
        assert_eq!(bolt_256k, bolt_per_token * 262_144 + bolt_state);
        assert!(
            bolt_256k > 2_000_000_000 && bolt_256k < 2_600_000_000,
            "{bolt_256k}"
        );

        // Doubling the context doubles the keys and values and not the state.
        let half = u.kv_cache_bytes(524_288).unwrap() - ultra_state;
        assert_eq!(2 * half, ultra_1m - ultra_state);
        // The serve advisor spreads the figure over all layers and never
        // under-counts it.
        let spread = u.kv_bytes_per_token_per_layer().unwrap() * u64::from(u.layers);
        assert!(spread >= ultra_per_token);
        // With the cache, the weights of the smallest Ultra build (188 GB)
        // plus a 1M-token request fit two 128 GB nodes.
        let weights = 188_031_516_192u64;
        assert!(weights + ultra_1m < 2 * 128 * 1_000_000_000);
    }
}
