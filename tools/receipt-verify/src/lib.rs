//! An independent verifier for Tenzro inference receipts.
//!
//! It implements `docs/standards/inference-receipt.md` from the text of that
//! document, with general-purpose cryptography crates only: it links no
//! Tenzro crate, so a receipt that verifies here verifies by the published
//! rules, not by sharing the signer's code.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519Key};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

/// Domain tag every receipt preimage starts with.
pub const RECEIPT_DOMAIN: &[u8] = b"tenzro/inference-receipt";
/// Domain tag of the billable-units encoding.
pub const METER_DOMAIN: &[u8] = b"tenzro/meter/v1";
/// Prefix of a composite signature's message representative.
pub const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
/// The composite algorithm label, also the ML-DSA-65 context string.
pub const COMPOSITE_LABEL: &[u8] = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512";
/// The signature context a hardware key certifies a session key under.
pub const SESSION_CERTIFICATE_CONTEXT: &[u8] = b"tenzro/session/certificate";

/// Why a receipt does not verify.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The JSON is not a receipt: a field is missing or has the wrong type.
    Malformed(String),
    /// The hardware key's signature over the session certificate fails.
    BadCertificate(String),
    /// The session certificate had expired when the receipt was signed.
    CertificateExpired {
        not_after_ms: u64,
        signed_at_ms: u64,
    },
    /// The session key's signature over the receipt fails.
    BadSignature,
    /// The receipt names a different model hash than the catalog states.
    ModelHashMismatch,
    /// The receipt answers a different request nonce.
    NonceMismatch,
    /// The receipt commits to a different output.
    OutputMismatch,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed receipt: {m}"),
            Self::BadCertificate(m) => write!(f, "session certificate does not verify: {m}"),
            Self::CertificateExpired {
                not_after_ms,
                signed_at_ms,
            } => write!(
                f,
                "session certificate expired at {not_after_ms} ms, before the receipt was signed at {signed_at_ms} ms"
            ),
            Self::BadSignature => write!(f, "receipt signature does not verify"),
            Self::ModelHashMismatch => write!(f, "model hash differs from the catalog's"),
            Self::NonceMismatch => write!(f, "nonce differs from the request's"),
            Self::OutputMismatch => write!(f, "output hash differs from the output received"),
        }
    }
}

impl std::error::Error for Error {}

fn malformed(what: &str) -> Error {
    Error::Malformed(what.to_string())
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value, Error> {
    v.get(name)
        .ok_or_else(|| malformed(&format!("`{name}` is missing")))
}

fn text<'a>(v: &'a Value, name: &str) -> Result<&'a str, Error> {
    field(v, name)?
        .as_str()
        .ok_or_else(|| malformed(&format!("`{name}` is not a string")))
}

fn opt_text<'a>(v: &'a Value, name: &str) -> Result<Option<&'a str>, Error> {
    match v.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(malformed(&format!("`{name}` is not a string"))),
    }
}

fn uint(v: &Value, name: &str) -> Result<u64, Error> {
    field(v, name)?
        .as_u64()
        .ok_or_else(|| malformed(&format!("`{name}` is not an unsigned integer")))
}

/// A 128-bit amount: a JSON number up to 2^64 - 1, a decimal string above.
fn amount(v: &Value, name: &str) -> Result<u128, Error> {
    match field(v, name)? {
        Value::Number(n) => n.as_u64().map(u128::from),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
    .ok_or_else(|| malformed(&format!("`{name}` is not an amount")))
}

fn float(v: &Value, name: &str) -> Result<f64, Error> {
    field(v, name)?
        .as_f64()
        .ok_or_else(|| malformed(&format!("`{name}` is not a number")))
}

fn hex_bytes(v: &Value, name: &str) -> Result<Vec<u8>, Error> {
    hex::decode(text(v, name)?).map_err(|_| malformed(&format!("`{name}` is not hex")))
}

/// A byte string carried as a JSON array of numbers.
fn byte_array(v: &Value, name: &str) -> Result<Vec<u8>, Error> {
    field(v, name)?
        .as_array()
        .and_then(|a| {
            a.iter()
                .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect::<Option<Vec<u8>>>()
        })
        .ok_or_else(|| malformed(&format!("`{name}` is not a byte array")))
}

fn put(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// The hardware identity key a receipt names: a P-256 point `x || y` and,
/// when the hardware holds one, an ML-DSA-65 key.
struct IdentityKey {
    p256: Vec<u8>,
    pq: Option<Vec<u8>>,
}

fn identity_key(receipt: &Value) -> Result<IdentityKey, Error> {
    let k = field(receipt, "public_key")?;
    let p256 = hex_bytes(k, "p256")?;
    let pq = match k.get("pq") {
        None | Some(Value::Null) => None,
        Some(_) => Some(hex_bytes(k, "pq")?),
    };
    Ok(IdentityKey { p256, pq })
}

/// The billable units, length-prefixed with 32-bit lengths, in key order.
fn units_bytes(units: &Value) -> Result<Vec<u8>, Error> {
    let map = units
        .as_object()
        .ok_or_else(|| malformed("`units` is not an object"))?;
    let mut entries: Vec<(&String, u128)> = Vec::with_capacity(map.len());
    for k in map.keys() {
        entries.push((k, amount(units, k)?));
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut out = METER_DOMAIN.to_vec();
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (k, v) in entries {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&v.to_le_bytes());
    }
    Ok(out)
}

/// The exact bytes a receipt's signature covers, rebuilt from its JSON.
pub fn preimage(receipt: &Value) -> Result<Vec<u8>, Error> {
    let mut buf = RECEIPT_DOMAIN.to_vec();
    for name in [
        "model_id",
        "model_hash",
        "engine",
        "machine_did",
        "nonce",
        "input_commitment",
        "output_hash",
    ] {
        put(&mut buf, text(receipt, name)?.as_bytes());
    }
    put(&mut buf, &units_bytes(field(receipt, "units")?)?);
    match receipt.get("priced") {
        None | Some(Value::Null) => buf.push(0),
        Some(p) => {
            buf.push(1);
            put(&mut buf, text(p, "card")?.as_bytes());
            buf.extend_from_slice(&amount(p, "rate_nano_usd")?.to_le_bytes());
            buf.extend_from_slice(&amount(p, "charge")?.to_le_bytes());
        }
    }
    let provenance = match receipt.get("provenance") {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => v
            .as_array()
            .ok_or_else(|| malformed("`provenance` is not an array"))?
            .iter()
            .map(|h| {
                h.as_str()
                    .ok_or_else(|| malformed("a provenance hash is not a string"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    buf.extend_from_slice(&(provenance.len() as u32).to_le_bytes());
    for h in provenance {
        put(&mut buf, h.as_bytes());
    }
    let s = field(receipt, "sampling")?;
    buf.extend_from_slice(&uint(s, "seed")?.to_le_bytes());
    buf.extend_from_slice(&float(s, "temperature")?.to_bits().to_le_bytes());
    buf.extend_from_slice(&float(s, "top_p")?.to_bits().to_le_bytes());
    let top_k = match s.get("top_k") {
        None | Some(Value::Null) => u64::MAX,
        Some(_) => uint(s, "top_k")?,
    };
    buf.extend_from_slice(&top_k.to_le_bytes());
    let min_p = match s.get("min_p") {
        None | Some(Value::Null) => u64::MAX,
        Some(_) => float(s, "min_p")?.to_bits(),
    };
    buf.extend_from_slice(&min_p.to_le_bytes());
    buf.extend_from_slice(&(uint(s, "max_output_tokens")? as u32).to_le_bytes());
    let keyed = field(s, "keyed_sampler")?
        .as_bool()
        .ok_or_else(|| malformed("`keyed_sampler` is not a boolean"))?;
    buf.push(keyed as u8);
    let empty = Value::Object(Default::default());
    let decode = receipt
        .get("decode")
        .filter(|d| !d.is_null())
        .unwrap_or(&empty);
    for name in ["precision", "engine_version", "hardware_class"] {
        put(&mut buf, opt_text(decode, name)?.unwrap_or("").as_bytes());
    }
    put(
        &mut buf,
        opt_text(receipt, "commitment_hash")?
            .unwrap_or("")
            .as_bytes(),
    );
    let tee = match receipt.get("tee") {
        None | Some(Value::Null) => String::new(),
        Some(t) => {
            let report = serde_json::to_vec(field(t, "report")?)
                .map_err(|e| Error::Malformed(e.to_string()))?;
            hex::encode(Sha256::digest(report))
        }
    };
    put(&mut buf, tee.as_bytes());
    put(
        &mut buf,
        opt_text(receipt, "activation_fingerprint")?
            .unwrap_or("")
            .as_bytes(),
    );
    buf.extend_from_slice(&uint(receipt, "signed_at_ms")?.to_le_bytes());
    let key = identity_key(receipt)?;
    put(&mut buf, &key.p256);
    put(&mut buf, key.pq.as_deref().unwrap_or_default());
    Ok(buf)
}

/// The receipt's identity: SHA-256 of its preimage, hex.
pub fn digest(receipt: &Value) -> Result<String, Error> {
    Ok(hex::encode(Sha256::digest(preimage(receipt)?)))
}

/// The bytes a hardware key signs to certify a session key, with 32-bit
/// length prefixes.
fn certificate_message(key: &IdentityKey, session_key: &[u8], not_after_ms: u64) -> Vec<u8> {
    fn put32(m: &mut Vec<u8>, b: &[u8]) {
        m.extend_from_slice(&(b.len() as u32).to_le_bytes());
        m.extend_from_slice(b);
    }
    let mut m = Vec::new();
    put32(&mut m, &key.p256);
    match &key.pq {
        Some(pq) => {
            m.push(1);
            put32(&mut m, pq);
        }
        None => m.push(0),
    }
    // Key type 0: Ed25519.
    m.push(0);
    put32(&mut m, session_key);
    m.extend_from_slice(&not_after_ms.to_le_bytes());
    m
}

/// `M'` of a composite signature over `message` under `context`.
fn message_representative(context: &[u8], message: &[u8]) -> Vec<u8> {
    let mut out = COMPOSITE_PREFIX.to_vec();
    out.extend_from_slice(COMPOSITE_LABEL);
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out.extend_from_slice(&Sha512::digest(message));
    out
}

/// Verify the hardware key's composite signature (P-256 and, when the key
/// has one, ML-DSA-65) over `message` under `context`.
fn verify_composite(
    key: &IdentityKey,
    context: &[u8],
    message: &[u8],
    sig: &Value,
) -> Result<(), String> {
    let m_prime = message_representative(context, message);
    let classical = sig.get("classical").ok_or("no classical leg")?;
    if classical.get("form").and_then(Value::as_str) != Some("raw") {
        return Err("only the raw P-256 form is supported".to_string());
    }
    let raw = hex::decode(
        classical
            .get("signature")
            .and_then(Value::as_str)
            .ok_or("no P-256 signature")?,
    )
    .map_err(|_| "P-256 signature is not hex")?;
    let p256_sig = if raw.len() == 64 {
        P256Signature::from_slice(&raw)
    } else {
        P256Signature::from_der(&raw)
    }
    .map_err(|_| "P-256 signature does not decode")?;
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&key.p256);
    let vk = P256Key::from_sec1_bytes(&sec1).map_err(|_| "P-256 key does not decode")?;
    vk.verify_prehash(&Sha256::digest(&m_prime), &p256_sig)
        .map_err(|_| "P-256 leg fails")?;
    let pq_sig = match sig.get("pq") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            hex::decode(v.as_str().ok_or("ML-DSA-65 leg is not a string")?)
                .map_err(|_| "ML-DSA-65 leg is not hex")?,
        ),
    };
    match (&key.pq, pq_sig) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err("ML-DSA-65 leg for a key with no ML-DSA-65 key".to_string()),
        (Some(_), None) => Err("the key has an ML-DSA-65 key, so the leg is required".to_string()),
        (Some(vk_bytes), Some(sig_bytes)) => {
            let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes.as_slice())
                .map_err(|_| "ML-DSA-65 key has the wrong length")?;
            let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&vk_enc);
            let sig_enc = EncodedSignature::<MlDsa65>::try_from(sig_bytes.as_slice())
                .map_err(|_| "ML-DSA-65 signature has the wrong length")?;
            let sig = ml_dsa::Signature::<MlDsa65>::decode(&sig_enc)
                .ok_or("ML-DSA-65 signature does not decode")?;
            if vk.verify_with_context(&m_prime, COMPOSITE_LABEL, &sig) {
                Ok(())
            } else {
                Err("ML-DSA-65 leg fails".to_string())
            }
        }
    }
}

/// Verify a receipt's signature chain: the hardware key certified the
/// session key, the certificate was valid when the receipt was signed, and
/// the session key signed the receipt's preimage.
pub fn verify_signature(receipt: &Value) -> Result<(), Error> {
    let key = identity_key(receipt)?;
    let signed_at_ms = uint(receipt, "signed_at_ms")?;
    let sig = field(receipt, "signature")?;
    let cert = field(sig, "certificate")?;
    let session = field(cert, "session_key")?;
    if text(session, "key_type")? != "Ed25519" {
        return Err(malformed("the session key is not an Ed25519 key"));
    }
    let session_key = byte_array(session, "bytes")?;
    let not_after_ms = uint(cert, "not_after_ms")?;
    verify_composite(
        &key,
        SESSION_CERTIFICATE_CONTEXT,
        &certificate_message(&key, &session_key, not_after_ms),
        field(cert, "signature")?,
    )
    .map_err(Error::BadCertificate)?;
    if signed_at_ms > not_after_ms {
        return Err(Error::CertificateExpired {
            not_after_ms,
            signed_at_ms,
        });
    }
    let session_key: [u8; 32] = session_key
        .try_into()
        .map_err(|_| malformed("the session key is not 32 bytes"))?;
    let vk = Ed25519Key::from_bytes(&session_key)
        .map_err(|_| malformed("the session key does not decode"))?;
    let inner = field(sig, "signature")?;
    if text(inner, "key_type")? != "Ed25519" {
        return Err(malformed(
            "the receipt signature is not an Ed25519 signature",
        ));
    }
    let bytes: [u8; 64] = byte_array(inner, "bytes")?
        .try_into()
        .map_err(|_| malformed("the receipt signature is not 64 bytes"))?;
    vk.verify_strict(&preimage(receipt)?, &Ed25519Signature::from_bytes(&bytes))
        .map_err(|_| Error::BadSignature)
}

/// SHA-256 over a completion's visible text, reasoning and tool calls, each
/// with a 64-bit length prefix: the `output_hash` a receipt commits to.
pub fn output_hash(text: &str, reasoning: &str, tool_calls_json: &str) -> String {
    let mut h = Sha256::new();
    for part in [text, reasoning, tool_calls_json] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(h.finalize())
}

/// What a holder checks a receipt against, beyond its own signature.
#[derive(Debug, Default)]
pub struct Expect<'a> {
    /// The model hash the catalog states for the model the receipt names.
    pub model_hash: Option<&'a str>,
    /// The nonce the request carried.
    pub nonce: Option<&'a str>,
    /// The output received, as `output_hash` computes it.
    pub output_hash: Option<&'a str>,
}

/// Verify a receipt: its signature chain, then each expectation given.
pub fn verify(receipt: &Value, expect: &Expect<'_>) -> Result<(), Error> {
    verify_signature(receipt)?;
    if text(receipt, "machine_did")?.is_empty() || text(receipt, "input_commitment")?.is_empty() {
        return Err(malformed(
            "a receipt names its machine and commits to its input",
        ));
    }
    if expect
        .model_hash
        .is_some_and(|h| h != text(receipt, "model_hash").unwrap_or(""))
    {
        return Err(Error::ModelHashMismatch);
    }
    if expect
        .nonce
        .is_some_and(|n| n != text(receipt, "nonce").unwrap_or(""))
    {
        return Err(Error::NonceMismatch);
    }
    if expect
        .output_hash
        .is_some_and(|o| o != text(receipt, "output_hash").unwrap_or(""))
    {
        return Err(Error::OutputMismatch);
    }
    Ok(())
}
