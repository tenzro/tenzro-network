//! Ingest safety scanning of model files.
//!
//! Files are classified by their content, never by their name: a pickle
//! renamed to `.safetensors` is still a pickle. Pickle (including a PyTorch
//! ZIP archive holding one, and NumPy arrays of Python objects) executes code
//! when loaded, so it is refused outright rather than inspected. Weights must
//! be safetensors or GGUF with a header that is internally consistent.
//!
//! A GGUF file can carry its own chat template, which the serving engine
//! applies to every prompt. Its SHA-256 is part of the report, so a relying
//! party can see exactly which template a model ships.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::Result;

/// Unknown binary files above this size are refused: anything that large in
/// a model directory is weights in a format the scanner cannot vouch for.
pub const MAX_UNKNOWN_BINARY: u64 = 16 * 1024 * 1024;
/// Largest safetensors JSON header accepted.
const MAX_SAFETENSORS_HEADER: u64 = 100 * 1024 * 1024;
/// Bytes read from the start of a file to classify it.
const SNIFF: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileFormat {
    Safetensors,
    Gguf,
    Pickle,
    PytorchZip,
    NumpyObject,
    Numpy,
    Json,
    Text,
    SentencePiece,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileScan {
    pub path: String,
    pub format: FileFormat,
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// SHA-256 of a GGUF file's embedded `tokenizer.chat_template`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_template_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    pub accepted: bool,
    pub files: Vec<FileScan>,
}

fn is_pickle(head: &[u8], last: Option<u8>) -> bool {
    // Protocol 2 and later open with PROTO (0x80) and the protocol number.
    if head.len() >= 2 && head[0] == 0x80 && (2..=5).contains(&head[1]) {
        return true;
    }
    // Protocol 0 and 1 have no header. A stream that opens with a GLOBAL
    // (`c<module>\n<name>\n`) names a callable to import; a binary stream
    // that opens with MARK, EMPTY_DICT or EMPTY_LIST and ends with STOP is a
    // protocol 1 pickle.
    if head.first() == Some(&b'c') {
        let mut lines = head[1..].splitn(3, |b| *b == b'\n');
        let ident = |s: &[u8]| {
            !s.is_empty()
                && s.iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.')
        };
        if let (Some(module), Some(name), Some(_)) = (lines.next(), lines.next(), lines.next())
            && ident(module)
            && ident(name)
        {
            return true;
        }
    }
    matches!(head.first(), Some(b'(' | b'}' | b']'))
        && last == Some(b'.')
        && std::str::from_utf8(head).is_err()
}

fn zip_names(bytes: &[u8]) -> Vec<String> {
    // Local file headers: "PK\x03\x04", name length at 26, name at 30.
    let mut names = Vec::new();
    let mut i = 0;
    while i + 30 <= bytes.len() {
        if &bytes[i..i + 4] == b"PK\x03\x04" {
            let n = u16::from_le_bytes([bytes[i + 26], bytes[i + 27]]) as usize;
            if let Some(name) = bytes.get(i + 30..i + 30 + n) {
                names.push(String::from_utf8_lossy(name).into_owned());
            }
            i += 30 + n;
        } else {
            i += 1;
        }
    }
    names
}

fn check_safetensors(f: &mut std::fs::File, size: u64) -> std::result::Result<(), String> {
    let mut len = [0u8; 8];
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    f.read_exact(&mut len)
        .map_err(|_| "shorter than a safetensors header".to_string())?;
    let header_len = u64::from_le_bytes(len);
    if header_len == 0 || header_len > MAX_SAFETENSORS_HEADER || 8 + header_len > size {
        return Err(format!("header length {header_len} does not fit the file"));
    }
    let mut header = vec![0u8; header_len as usize];
    f.read_exact(&mut header).map_err(|e| e.to_string())?;
    let parsed: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&header).map_err(|_| "header is not a JSON object".to_string())?;
    let data_len = size - 8 - header_len;
    let mut spans = Vec::new();
    for (name, t) in &parsed {
        if name == "__metadata__" {
            if !t
                .as_object()
                .is_some_and(|m| m.values().all(|v| v.is_string()))
            {
                return Err("__metadata__ must map strings to strings".into());
            }
            continue;
        }
        let dtype = t.get("dtype").and_then(|d| d.as_str()).unwrap_or("");
        let width: u64 = match dtype {
            "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" | "F8_E8M0" | "F4" | "F6_E2M3"
            | "F6_E3M2" => 1,
            "U16" | "I16" | "F16" | "BF16" => 2,
            "U32" | "I32" | "F32" => 4,
            "U64" | "I64" | "F64" | "C64" => 8,
            other => return Err(format!("{name}: unknown dtype {other:?}")),
        };
        let shape: Vec<u64> = t
            .get("shape")
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|d| d.as_u64()).collect())
            .ok_or_else(|| format!("{name}: no shape"))?;
        let offs: Vec<u64> = t
            .get("data_offsets")
            .and_then(|s| s.as_array())
            .map(|a| a.iter().filter_map(|d| d.as_u64()).collect())
            .filter(|v: &Vec<u64>| v.len() == 2)
            .ok_or_else(|| format!("{name}: data_offsets must be two integers"))?;
        let (start, end) = (offs[0], offs[1]);
        if start > end || end > data_len {
            return Err(format!(
                "{name}: data_offsets [{start}, {end}] are outside the data"
            ));
        }
        let elements = shape.iter().try_fold(1u64, |acc, d| acc.checked_mul(*d));
        // Sub-byte dtypes pack several elements per byte; for them only check
        // the span is no larger than one byte per element.
        let expected = elements.and_then(|e| e.checked_mul(width));
        let packed = matches!(dtype, "F4" | "F6_E2M3" | "F6_E3M2");
        match expected {
            Some(n) if (!packed && n == end - start) || (packed && end - start <= n) => {}
            _ => {
                return Err(format!(
                    "{name}: {dtype} {shape:?} does not match {} bytes",
                    end - start
                ));
            }
        }
        spans.push((start, end));
    }
    spans.sort();
    let mut cursor = 0;
    for (s, e) in spans {
        if s != cursor {
            return Err("tensor data has gaps or overlaps".into());
        }
        cursor = e;
    }
    if cursor != data_len {
        return Err("bytes after the last tensor are not accounted for".into());
    }
    Ok(())
}

/// GGUF metadata value type ids.
const GGUF_STRING: u32 = 8;
const GGUF_ARRAY: u32 = 9;

fn read_u32(r: &mut impl Read) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(r: &mut impl Read) -> std::io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn gguf_scalar_size(t: u32) -> Option<u64> {
    match t {
        0 | 1 | 7 => Some(1),
        2 | 3 => Some(2),
        4..=6 => Some(4),
        10..=12 => Some(8),
        _ => None,
    }
}

fn read_gguf_string(r: &mut impl Read, limit: u64) -> std::result::Result<Vec<u8>, String> {
    let len = read_u64(r).map_err(|e| e.to_string())?;
    if len > limit {
        return Err(format!("string of {len} bytes"));
    }
    let mut s = vec![0u8; len as usize];
    r.read_exact(&mut s).map_err(|e| e.to_string())?;
    Ok(s)
}

fn skip_gguf_value(
    r: &mut (impl Read + Seek),
    t: u32,
    depth: u32,
) -> std::result::Result<(), String> {
    if let Some(n) = gguf_scalar_size(t) {
        r.seek(SeekFrom::Current(n as i64))
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    match t {
        GGUF_STRING => {
            read_gguf_string(r, 64 * 1024 * 1024)?;
            Ok(())
        }
        GGUF_ARRAY if depth < 2 => {
            let inner = read_u32(r).map_err(|e| e.to_string())?;
            let count = read_u64(r).map_err(|e| e.to_string())?;
            if count > 16 * 1024 * 1024 {
                return Err(format!("array of {count} items"));
            }
            if let Some(n) = gguf_scalar_size(inner) {
                r.seek(SeekFrom::Current((n * count) as i64))
                    .map_err(|e| e.to_string())?;
                return Ok(());
            }
            for _ in 0..count {
                skip_gguf_value(r, inner, depth + 1)?;
            }
            Ok(())
        }
        other => Err(format!("unknown metadata type {other}")),
    }
}

/// Check a GGUF header and return the chat template's SHA-256 when present.
fn check_gguf(f: &mut std::fs::File, size: u64) -> std::result::Result<Option<String>, String> {
    let mut r = std::io::BufReader::new(f);
    r.seek(SeekFrom::Start(4)).map_err(|e| e.to_string())?;
    let version = read_u32(&mut r).map_err(|e| e.to_string())?;
    if !(2..=3).contains(&version) {
        return Err(format!("GGUF version {version} is not 2 or 3"));
    }
    let tensors = read_u64(&mut r).map_err(|e| e.to_string())?;
    let kvs = read_u64(&mut r).map_err(|e| e.to_string())?;
    if tensors > 1 << 20 || kvs > 1 << 16 || tensors * 24 > size {
        return Err(format!(
            "{tensors} tensors and {kvs} metadata entries do not fit a {size}-byte file"
        ));
    }
    let mut template = None;
    for _ in 0..kvs {
        let key = read_gguf_string(&mut r, 1024)?;
        let t = read_u32(&mut r).map_err(|e| e.to_string())?;
        if key == b"tokenizer.chat_template" && t == GGUF_STRING {
            let s = read_gguf_string(&mut r, 64 * 1024 * 1024)?;
            template = Some(hex::encode(Sha256::digest(&s)));
        } else {
            skip_gguf_value(&mut r, t, 0)?;
        }
    }
    Ok(template)
}

fn last_byte(f: &mut std::fs::File, size: u64) -> Result<Option<u8>> {
    if size == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(size - 1))?;
    f.read_exact(&mut b)?;
    Ok(Some(b[0]))
}

fn looks_like_text(head: &[u8]) -> bool {
    std::str::from_utf8(head).is_ok() || head.iter().all(|b| *b >= 0x09)
}

/// Scan one file.
pub fn scan_file(path: &Path, display_path: &str) -> Result<FileScan> {
    let mut f = std::fs::File::open(path)?;
    let size = f.metadata()?.len();
    let mut head = vec![0u8; SNIFF.min(size as usize)];
    f.read_exact(&mut head)?;
    let mut out = FileScan {
        path: display_path.to_string(),
        format: FileFormat::Unknown,
        accepted: true,
        reason: None,
        chat_template_sha256: None,
    };
    let refuse = |out: &mut FileScan, format: FileFormat, reason: String| {
        out.format = format;
        out.accepted = false;
        out.reason = Some(reason);
    };
    if head.starts_with(b"GGUF") {
        out.format = FileFormat::Gguf;
        match check_gguf(&mut f, size) {
            Ok(t) => out.chat_template_sha256 = t,
            Err(e) => refuse(&mut out, FileFormat::Gguf, e),
        }
    } else if head.starts_with(b"PK\x03\x04") {
        let mut all = Vec::new();
        f.seek(SeekFrom::Start(0))?;
        Read::take(&mut f, 64 * 1024 * 1024).read_to_end(&mut all)?;
        let names = zip_names(&all);
        if names
            .iter()
            .any(|n| n.ends_with(".pkl") || n.ends_with("/data.pkl") || n.ends_with("data.pkl"))
        {
            refuse(
                &mut out,
                FileFormat::PytorchZip,
                "a ZIP archive holding a pickle executes code when loaded".into(),
            );
        } else if size > MAX_UNKNOWN_BINARY {
            refuse(
                &mut out,
                FileFormat::Unknown,
                "a large ZIP archive is not a model format".into(),
            );
        }
    } else if head.starts_with(b"\x93NUMPY") {
        let header = String::from_utf8_lossy(&head[..head.len().min(512)]).into_owned();
        if header.contains("'descr': '|O'") || header.contains("\"descr\": \"|O\"") {
            refuse(
                &mut out,
                FileFormat::NumpyObject,
                "a NumPy array of Python objects is a pickle".into(),
            );
        } else {
            out.format = FileFormat::Numpy;
        }
    } else if size >= 8
        && u64::from_le_bytes(head[..8].try_into().unwrap_or_default()) > 0
        && head.get(8) == Some(&b'{')
    {
        // Checked before pickle: a header length can begin with the bytes a
        // pickle opens with. A file that passes the full safetensors check is
        // loaded as safetensors, never unpickled.
        out.format = FileFormat::Safetensors;
        if let Err(e) = check_safetensors(&mut f, size) {
            refuse(&mut out, FileFormat::Safetensors, e);
        }
    } else if is_pickle(&head, last_byte(&mut f, size)?) {
        refuse(
            &mut out,
            FileFormat::Pickle,
            "pickle executes code when loaded".into(),
        );
    } else if serde_json::from_slice::<serde_json::Value>(&head).is_ok()
        && size as usize == head.len()
    {
        out.format = FileFormat::Json;
    } else if looks_like_text(&head) {
        out.format = FileFormat::Text;
    } else if head.first() == Some(&0x0a) && size <= MAX_UNKNOWN_BINARY {
        out.format = FileFormat::SentencePiece;
    } else if size > MAX_UNKNOWN_BINARY {
        refuse(
            &mut out,
            FileFormat::Unknown,
            format!("a {size}-byte file in no known format"),
        );
    }
    Ok(out)
}

/// Scan every file of a manifest under `dir`.
pub fn scan_dir(manifest: &crate::ModelManifest, dir: &Path) -> Result<ScanReport> {
    let mut files = Vec::with_capacity(manifest.files.len());
    for e in &manifest.files {
        files.push(scan_file(&dir.join(&e.path), &e.path)?);
    }
    Ok(ScanReport {
        accepted: files.iter().all(|f| f.accepted),
        files,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn safetensors_bytes() -> Vec<u8> {
        let header = br#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"__metadata__":{"format":"pt"}}"#;
        let mut out = (header.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(header);
        out.extend_from_slice(&[0u8; 8]);
        out
    }

    pub(crate) fn gguf_bytes(template: &str) -> Vec<u8> {
        let mut out = b"GGUF".to_vec();
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&2u64.to_le_bytes());
        let key = b"general.architecture";
        out.extend_from_slice(&(key.len() as u64).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&GGUF_STRING.to_le_bytes());
        out.extend_from_slice(&5u64.to_le_bytes());
        out.extend_from_slice(b"llama");
        let key = b"tokenizer.chat_template";
        out.extend_from_slice(&(key.len() as u64).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&GGUF_STRING.to_le_bytes());
        out.extend_from_slice(&(template.len() as u64).to_le_bytes());
        out.extend_from_slice(template.as_bytes());
        out
    }

    fn scan(bytes: &[u8]) -> FileScan {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.safetensors");
        std::fs::write(&p, bytes).unwrap();
        scan_file(&p, "f.safetensors").unwrap()
    }

    #[test]
    fn valid_safetensors_and_gguf_are_accepted() {
        let s = scan(&safetensors_bytes());
        assert!(s.accepted && s.format == FileFormat::Safetensors, "{s:?}");
        let g = scan(&gguf_bytes("{{ bos_token }}"));
        assert!(g.accepted && g.format == FileFormat::Gguf, "{g:?}");
        assert_eq!(
            g.chat_template_sha256.unwrap(),
            hex::encode(Sha256::digest(b"{{ bos_token }}"))
        );
    }

    #[test]
    fn a_pickle_named_safetensors_is_refused() {
        let s = scan(b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94.");
        assert!(!s.accepted && s.format == FileFormat::Pickle);
    }

    #[test]
    fn a_pytorch_zip_with_a_pickle_is_refused() {
        let mut z = b"PK\x03\x04".to_vec();
        z.extend_from_slice(&[0u8; 22]);
        let name = b"archive/data.pkl";
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(name);
        z.extend_from_slice(b"\x80\x02}q\x00.");
        let s = scan(&z);
        assert!(!s.accepted && s.format == FileFormat::PytorchZip);
    }

    #[test]
    fn a_numpy_object_array_is_refused() {
        let s =
            scan(b"\x93NUMPY\x01\x00v\x00{'descr': '|O', 'fortran_order': False, 'shape': (1,), }");
        assert!(!s.accepted && s.format == FileFormat::NumpyObject);
    }

    #[test]
    fn a_safetensors_header_pointing_outside_the_file_is_refused() {
        let header = br#"{"w":{"dtype":"F32","shape":[4],"data_offsets":[0,16]}}"#;
        let mut out = (header.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(header);
        out.extend_from_slice(&[0u8; 8]);
        let s = scan(&out);
        assert!(!s.accepted && s.format == FileFormat::Safetensors, "{s:?}");
    }

    #[test]
    fn a_gguf_with_an_impossible_header_is_refused() {
        let mut g = b"GGUF".to_vec();
        g.extend_from_slice(&3u32.to_le_bytes());
        g.extend_from_slice(&u64::MAX.to_le_bytes());
        g.extend_from_slice(&0u64.to_le_bytes());
        assert!(!scan(&g).accepted);
    }

    #[test]
    fn small_json_and_text_files_are_accepted() {
        assert_eq!(scan(b"{\"vocab\": {}}").format, FileFormat::Json);
        assert_eq!(scan(b"a merges file\nline two\n").format, FileFormat::Text);
    }
}
