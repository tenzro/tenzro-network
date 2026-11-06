//! Protocol-neutral Tenzro DID envelope (interop bridge Layer 1).
//!
//! This module generalises the A2A-specific DID envelope
//! (`tenzro-node/src/a2a/did_envelope.rs`) into a protocol-neutral, registry-
//! coupled (but node-decoupled) primitive that MCP, x402, A2A, and
//! generic-HTTP bridges can all share. See
//! `docs/architecture/agent-interop-protocol-bridge.md` Layer 1.
//!
//! A [`TenzroDidEnvelope`] is a small signed blob:
//!
//! ```text
//! { did, method, params_hash, timestamp, nonce, signature }
//! ```
//!
//! The signer commits to a deterministic, domain-separated **canonical
//! preimage** (see [`canonical_preimage`]) with its hardware P-256 key (a
//! passkey, TPM or Secure Enclave), and with its hardware ML-DSA-65 key where
//! one is enrolled. Verification resolves the DID through an
//! [`IdentityRegistry`], pulls the registered P-256 key and enrolled
//! ML-DSA-65 key, checks the composite signature, timestamp freshness
//! (bounded skew), and a non-empty nonce.
//!
//! Unlike the A2A wrapper, this layer does NOT bind the public key to the
//! identity's `wallet_address` — it trusts the registry's verification method
//! directly, which is the W3C DID resolution model. The A2A wrapper keeps its
//! additional wallet-address binding on top of this shared core.

use crate::registry::IdentityRegistry;
use sha2::{Digest, Sha256};
use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, PqPolicy, SignatureContext, verify_composite,
};

/// Domain-separation tag for the canonical preimage. Bumping the `:v1`
/// suffix invalidates every previously-signed envelope, so it doubles as a
/// wire-format version. Chosen distinct from the A2A `tenzro:a2a:` tag so an
/// A2A signature can never be replayed as a generalized-envelope signature.
pub const ENVELOPE_DOMAIN: &[u8] = b"tenzro-did-envelope:v1";

/// Maximum tolerated clock skew between signer and verifier, in milliseconds.
/// Envelopes whose `timestamp` differs from local wall-clock by more than this
/// (in either direction) are rejected as stale or future-dated.
pub const MAX_SKEW_MS: u64 = 60_000;

/// Protocol-neutral Tenzro DID envelope.
///
/// Field layout is fixed by
/// `docs/architecture/agent-interop-protocol-bridge.md` Layer 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenzroDidEnvelope {
    /// The signer's TDIP DID (e.g. `did:tenzro:machine:...`).
    pub did: String,
    /// Protocol method this envelope authorizes (e.g. `payment/authorize`,
    /// `message/send`, `tools/call`). Bound into the preimage so a signature
    /// for one method cannot be replayed against another.
    pub method: String,
    /// SHA-256 of the canonical, protocol-specific params. Computed via
    /// [`params_hash`].
    pub params_hash: [u8; 32],
    /// Unix milliseconds at signing time.
    pub timestamp: u64,
    /// 16 random bytes for replay defense.
    pub nonce: [u8; 16],
    /// Signature over [`canonical_preimage`]: the JSON encoding of a
    /// [`CompositeSignature`] under [`SignatureContext::DidEnvelope`] (TDIP,
    /// `did:key` and `did:web` signers), or a 65-byte recoverable secp256k1
    /// signature (`did:ethr` signers).
    pub signature: Vec<u8>,
}

impl TenzroDidEnvelope {
    /// Serialize to a compact, self-describing header value (hex of a binary
    /// layout) for carriage in an HTTP header (`Authorization: Tenzro-DID …`,
    /// `X-Tenzro-DID-Envelope`) or an MCP/x402 metadata field.
    ///
    /// Layout: `u32 did_len ‖ did ‖ u32 method_len ‖ method ‖ params_hash(32)
    /// ‖ timestamp(8 BE) ‖ nonce(16) ‖ u32 sig_len ‖ signature`.
    pub fn to_header_value(&self) -> String {
        let did = self.did.as_bytes();
        let method = self.method.as_bytes();
        let mut buf = Vec::with_capacity(
            4 + did.len() + 4 + method.len() + 32 + 8 + 16 + 4 + self.signature.len(),
        );
        buf.extend_from_slice(&(did.len() as u32).to_be_bytes());
        buf.extend_from_slice(did);
        buf.extend_from_slice(&(method.len() as u32).to_be_bytes());
        buf.extend_from_slice(method);
        buf.extend_from_slice(&self.params_hash);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        hex::encode(buf)
    }

    /// Parse a header value produced by [`TenzroDidEnvelope::to_header_value`].
    /// Returns a description string on any malformation (caller maps it to its
    /// own transport error).
    pub fn from_header_value(s: &str) -> Result<Self, String> {
        let buf =
            hex::decode(s.trim()).map_err(|_| "envelope header is not valid hex".to_string())?;
        let mut o = 0usize;
        fn take_u32(buf: &[u8], o: &mut usize) -> Result<u32, String> {
            if *o + 4 > buf.len() {
                return Err("truncated envelope (u32)".to_string());
            }
            let v = u32::from_be_bytes([buf[*o], buf[*o + 1], buf[*o + 2], buf[*o + 3]]);
            *o += 4;
            Ok(v)
        }
        fn take(buf: &[u8], o: &mut usize, n: usize) -> Result<Vec<u8>, String> {
            if *o + n > buf.len() {
                return Err("truncated envelope (field)".to_string());
            }
            let v = buf[*o..*o + n].to_vec();
            *o += n;
            Ok(v)
        }
        let did_len = take_u32(&buf, &mut o)? as usize;
        let did = String::from_utf8(take(&buf, &mut o, did_len)?)
            .map_err(|_| "did is not valid UTF-8".to_string())?;
        let method_len = take_u32(&buf, &mut o)? as usize;
        let method = String::from_utf8(take(&buf, &mut o, method_len)?)
            .map_err(|_| "method is not valid UTF-8".to_string())?;
        let params_hash: [u8; 32] = take(&buf, &mut o, 32)?
            .try_into()
            .map_err(|_| "params_hash length".to_string())?;
        let timestamp = u64::from_be_bytes(
            take(&buf, &mut o, 8)?
                .try_into()
                .map_err(|_| "timestamp length".to_string())?,
        );
        let nonce: [u8; 16] = take(&buf, &mut o, 16)?
            .try_into()
            .map_err(|_| "nonce length".to_string())?;
        let sig_len = take_u32(&buf, &mut o)? as usize;
        let signature = take(&buf, &mut o, sig_len)?;
        if o != buf.len() {
            return Err("trailing bytes after envelope".to_string());
        }
        Ok(Self {
            did,
            method,
            params_hash,
            timestamp,
            nonce,
            signature,
        })
    }
}

/// Errors returned by [`verify_envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The DID could not be resolved through the registry.
    UnknownDid(String),
    /// The resolved identity has no usable P-256 verification key.
    NoVerificationKey(String),
    /// `timestamp` is outside the `±MAX_SKEW_MS` window. `skew_ms` is the
    /// absolute difference from local wall-clock at verification time.
    StaleOrFuture { skew_ms: u64 },
    /// The nonce is all-zero (treated as "not set" — a real nonce must be
    /// random, and an all-zero nonce defeats replay defense).
    EmptyNonce,
    /// The signature did not verify against the canonical preimage. Coarse on
    /// purpose: it must not act as an oracle distinguishing "bad signature"
    /// from "wrong key".
    InvalidSignature,
    /// The local clock is before the Unix epoch (should never happen).
    ClockError,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownDid(did) => write!(f, "unknown DID: {did}"),
            Self::NoVerificationKey(did) => {
                write!(f, "no P-256 verification key for DID: {did}")
            }
            Self::StaleOrFuture { skew_ms } => {
                write!(
                    f,
                    "envelope timestamp out of window (skew {skew_ms} ms, max ±{MAX_SKEW_MS} ms)"
                )
            }
            Self::EmptyNonce => write!(f, "envelope nonce is empty (all-zero)"),
            Self::InvalidSignature => write!(f, "envelope signature did not verify"),
            Self::ClockError => write!(f, "system clock is before the Unix epoch"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// SHA-256 of the canonical, protocol-specific params bytes.
///
/// Callers serialize their protocol params deterministically (canonical JSON,
/// CBOR, etc.) and pass the bytes here; the digest becomes
/// [`TenzroDidEnvelope::params_hash`].
pub fn params_hash(canonical_params_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_params_bytes);
    hasher.finalize().into()
}

/// Canonical bytes of a whole JSON-RPC params object, for envelopes that bind
/// every parameter: the object minus its `did_envelope` field, as JSON with
/// object keys sorted at every level and no insignificant whitespace.
///
/// Binding only a resource name leaves every other field free; a relay
/// holding a genuine deploy envelope could keep the name and swap the image,
/// the secrets or the capability grant. Methods whose parameters all matter
/// hash these bytes into `params_hash`.
pub fn request_binding(params: &serde_json::Value) -> Vec<u8> {
    fn write(v: &serde_json::Value, skip_envelope: bool, out: &mut String) {
        match v {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map
                    .keys()
                    .filter(|k| !(skip_envelope && *k == "did_envelope"))
                    .collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::Value::String(k.clone()).to_string());
                    out.push(':');
                    write(&map[k], false, out);
                }
                out.push('}');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, false, out);
                }
                out.push(']');
            }
            scalar => out.push_str(&scalar.to_string()),
        }
    }
    let mut out = String::new();
    write(params, true, &mut out);
    out.into_bytes()
}

/// Build the deterministic, domain-separated preimage the signer commits to.
///
/// ## Exact byte layout
///
/// ```text
/// ENVELOPE_DOMAIN                       (22 bytes, b"tenzro-did-envelope:v1")
/// || (did.len()    as u32 big-endian)      (4 bytes)
/// || did                                   (UTF-8 bytes)
/// || (method.len() as u32 big-endian)      (4 bytes)
/// || method                                (UTF-8 bytes)
/// || params_hash                           (32 bytes)
/// || timestamp                             (8 bytes, u64 big-endian)
/// || nonce                                 (16 bytes)
/// ```
///
/// Length-prefixing `did` and `method` makes the encoding injective: no two
/// distinct (did, method) pairs can produce the same byte string (which a bare
/// concatenation with a separator char would not guarantee against a DID/method
/// that itself contained the separator). All multi-byte integers are
/// big-endian for cross-language reproducibility.
pub fn canonical_preimage(env: &TenzroDidEnvelope) -> Vec<u8> {
    let did = env.did.as_bytes();
    let method = env.method.as_bytes();
    let mut buf =
        Vec::with_capacity(ENVELOPE_DOMAIN.len() + 4 + did.len() + 4 + method.len() + 32 + 8 + 16);
    buf.extend_from_slice(ENVELOPE_DOMAIN);
    buf.extend_from_slice(&(did.len() as u32).to_be_bytes());
    buf.extend_from_slice(did);
    buf.extend_from_slice(&(method.len() as u32).to_be_bytes());
    buf.extend_from_slice(method);
    buf.extend_from_slice(&env.params_hash);
    buf.extend_from_slice(&env.timestamp.to_be_bytes());
    buf.extend_from_slice(&env.nonce);
    buf
}

/// Resolve the P-256 verification key (`x || y`) from a `did:key:zDn…`
/// identifier (the multicodec `0x1200` P-256 form, compressed point,
/// base58btc multibase). Any trailing `#fragment` is ignored. Returns `None`
/// for a non-`did:key` string, a non-base58btc body, or a key of another
/// type.
///
/// `did:key` signers carry their key in the identifier itself, so they can be
/// verified with no registry lookup.
pub fn resolve_did_key_p256(did: &str) -> Option<Vec<u8>> {
    let body = did.strip_prefix("did:key:")?;
    let body = body.split('#').next().unwrap_or(body);
    let z = body.strip_prefix('z')?; // 'z' = base58btc multibase prefix
    let bytes = bs58::decode(z).into_vec().ok()?;
    // multicodec p256-pub = varint(0x1200) = [0x80, 0x24], then the 33-byte
    // compressed point.
    if bytes.len() == 35 && bytes[0] == 0x80 && bytes[1] == 0x24 {
        p256_xy(&bytes[2..])
    } else {
        None
    }
}

/// `x || y` of a P-256 key given as `x || y`, or as an uncompressed or
/// compressed SEC1 point; `None` when it is not a point on the curve.
fn p256_xy(key: &[u8]) -> Option<Vec<u8>> {
    let verifier = if key.len() == 64 {
        tenzro_crypto::p256::P256Verifier::from_public_key_bytes(key)
    } else {
        tenzro_crypto::p256::P256Verifier::from_sec1_bytes(key)
    };
    verifier.ok().map(|v| v.public_key_bytes().to_vec())
}

/// The composite key a TDIP identity signs with: its registered P-256 key and,
/// when enrolled, its ML-DSA-65 key.
pub fn identity_key(identity: &crate::TenzroIdentity) -> Option<CompositePublicKey> {
    let p256 = identity
        .public_keys
        .iter()
        .filter(|pk| pk.key_type == "P-256")
        .find_map(|pk| p256_xy(&pk.public_key))?;
    let pq = (!identity.pq_verifying_key.is_empty()).then(|| identity.pq_verifying_key.clone());
    CompositePublicKey::new(p256, pq).ok()
}

/// Nonce and freshness: an all-zero nonce carries no replay entropy, and the
/// timestamp must be within `±MAX_SKEW_MS` of local wall-clock.
fn check_fresh(env: &TenzroDidEnvelope) -> Result<(), EnvelopeError> {
    if env.nonce == [0u8; 16] {
        return Err(EnvelopeError::EmptyNonce);
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| EnvelopeError::ClockError)?
        .as_millis() as u64;
    let skew_ms = now_ms.abs_diff(env.timestamp);
    if skew_ms > MAX_SKEW_MS {
        return Err(EnvelopeError::StaleOrFuture { skew_ms });
    }
    Ok(())
}

/// Verify an envelope against the registry.
///
/// Steps:
/// 1. Reject an empty (all-zero) nonce.
/// 2. Enforce timestamp freshness within `±MAX_SKEW_MS` of local wall-clock.
/// 3. Resolve `env.did`: a `did:key` carries its P-256 key, a `did:ethr`
///    signature recovers its key, any other DID resolves through the registry
///    to its P-256 key and enrolled ML-DSA-65 key.
/// 4. Verify the composite signature over [`canonical_preimage`]; once an
///    ML-DSA-65 key is enrolled, its leg is required.
pub fn verify_envelope(
    env: &TenzroDidEnvelope,
    registry: &IdentityRegistry,
) -> Result<(), EnvelopeError> {
    check_fresh(env)?;

    if env.did.starts_with("did:key:") {
        let xy = resolve_did_key_p256(&env.did)
            .ok_or_else(|| EnvelopeError::NoVerificationKey(env.did.clone()))?;
        let key = CompositePublicKey::new(xy, None)
            .map_err(|_| EnvelopeError::NoVerificationKey(env.did.clone()))?;
        return check_envelope_sig(env, &key);
    }

    // did:ethr signers use a recoverable secp256k1 signature; the key is
    // recovered from the signature and bound to the address in the DID, so no
    // registry lookup is needed.
    if env.did.starts_with("did:ethr:") {
        return check_envelope_sig_ethr(env);
    }

    let identity = registry
        .resolve(&env.did)
        .map_err(|_| EnvelopeError::UnknownDid(env.did.clone()))?;
    let key =
        identity_key(&identity).ok_or_else(|| EnvelopeError::NoVerificationKey(env.did.clone()))?;
    check_envelope_sig(env, &key)
}

/// Signature-only check: verify `env.signature` (a JSON-encoded
/// [`CompositeSignature`]) over the canonical preimage with `key`. Nonce and
/// freshness are the caller's job.
fn check_envelope_sig(
    env: &TenzroDidEnvelope,
    key: &CompositePublicKey,
) -> Result<(), EnvelopeError> {
    let sig: CompositeSignature =
        serde_json::from_slice(&env.signature).map_err(|_| EnvelopeError::InvalidSignature)?;
    verify_composite(
        key,
        SignatureContext::DidEnvelope,
        &canonical_preimage(env),
        &sig,
        PqPolicy::WhenPresent,
    )
    .map(|_| ())
    .map_err(|_| EnvelopeError::InvalidSignature)
}

/// Verify an envelope against an explicitly supplied P-256 key (`x || y`),
/// for DIDs resolved outside the registry (e.g. `did:web`, fetched over HTTPS
/// by the node). Checks nonce, freshness and signature; never touches the
/// registry.
pub fn verify_envelope_with_key(
    env: &TenzroDidEnvelope,
    p256_xy: &[u8],
) -> Result<(), EnvelopeError> {
    check_fresh(env)?;
    let key = CompositePublicKey::new(p256_xy.to_vec(), None)
        .map_err(|_| EnvelopeError::NoVerificationKey(env.did.clone()))?;
    check_envelope_sig(env, &key)
}

/// Extract the first usable P-256 verification key (`x || y`) from a W3C DID
/// document JSON (the `did:web` resolution target). Supports
/// `publicKeyMultibase` (z-base58btc multicodec, as in did:key) and
/// `publicKeyJwk` (`kty` EC, `crv` P-256). Returns `None` if no P-256 method
/// is present.
pub fn p256_from_did_document(doc: &serde_json::Value) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let vms = doc.get("verificationMethod")?.as_array()?;
    for vm in vms {
        if let Some(mb) = vm.get("publicKeyMultibase").and_then(|v| v.as_str())
            && let Some(k) = resolve_did_key_p256(&format!("did:key:{mb}"))
        {
            return Some(k);
        }
        if let Some(jwk) = vm.get("publicKeyJwk")
            && jwk.get("kty").and_then(|v| v.as_str()) == Some("EC")
            && jwk.get("crv").and_then(|v| v.as_str()) == Some("P-256")
        {
            let coord = |name: &str| {
                jwk.get(name)
                    .and_then(|v| v.as_str())
                    .and_then(|c| {
                        base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(c)
                            .ok()
                    })
                    .filter(|c| c.len() == 32)
            };
            if let (Some(x), Some(y)) = (coord("x"), coord("y"))
                && let Some(k) = p256_xy(&[x, y].concat())
            {
                return Some(k);
            }
        }
    }
    None
}

/// Parse the 20-byte Ethereum address from a `did:ethr` identifier:
/// `did:ethr:0x<40hex>` or `did:ethr:<chain>:0x<40hex>` (fragment ignored).
fn ethr_address(did: &str) -> Option<Vec<u8>> {
    let rest = did.strip_prefix("did:ethr:")?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let last = rest.rsplit(':').next()?;
    let h = last
        .strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .unwrap_or(last);
    let bytes = hex::decode(h).ok()?;
    (bytes.len() == 20).then_some(bytes)
}

/// Verify a `did:ethr` envelope's recoverable secp256k1 signature + address
/// binding (nonce/freshness are the caller's job). The signature is 65 bytes
/// `r ‖ s ‖ v` (v ∈ {0,1} or {27,28}) over `keccak256(canonical_preimage)`;
/// the pubkey is recovered and its Ethereum address compared to the DID's.
fn check_envelope_sig_ethr(env: &TenzroDidEnvelope) -> Result<(), EnvelopeError> {
    use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};
    use sha3::{Digest, Keccak256};

    let want =
        ethr_address(&env.did).ok_or_else(|| EnvelopeError::NoVerificationKey(env.did.clone()))?;
    if env.signature.len() != 65 {
        return Err(EnvelopeError::InvalidSignature);
    }
    let v = env.signature[64];
    let y_parity = if v >= 27 { v - 27 } else { v };
    let recovery_id =
        RecoveryId::try_from(y_parity).map_err(|_| EnvelopeError::InvalidSignature)?;
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&env.signature[..64]);
    let sig =
        K256Sig::from_bytes(&sig_bytes.into()).map_err(|_| EnvelopeError::InvalidSignature)?;
    let prehash = Keccak256::digest(canonical_preimage(env));
    let vk = VerifyingKey::recover_from_prehash(&prehash, &sig, recovery_id)
        .map_err(|_| EnvelopeError::InvalidSignature)?;
    let encoded = vk.to_sec1_point(false);
    let addr = Keccak256::digest(&encoded.as_bytes()[1..]);
    if &addr[12..32] == want.as_slice() {
        Ok(())
    } else {
        Err(EnvelopeError::InvalidSignature)
    }
}

/// Verify every check on a `did:ethr` envelope (nonce + freshness + recoverable
/// secp256k1 signature + address binding). The key is recovered from the
/// signature, so no registry entry is needed.
pub fn verify_envelope_ethr(env: &TenzroDidEnvelope) -> Result<(), EnvelopeError> {
    check_fresh(env)?;
    check_envelope_sig_ethr(env)
}

#[cfg(test)]
mod request_binding_tests {
    use super::request_binding;
    use serde_json::json;

    #[test]
    fn key_order_and_the_envelope_do_not_change_the_binding() {
        let a = json!({"name": "x", "image": {"b": 1, "a": [2, {"z": 0, "y": 1}]}, "did_envelope": "e1"});
        let b = json!({"image": {"a": [2, {"y": 1, "z": 0}], "b": 1}, "did_envelope": "e2", "name": "x"});
        assert_eq!(request_binding(&a), request_binding(&b));
        assert_eq!(
            String::from_utf8(request_binding(&a)).unwrap(),
            r#"{"image":{"a":[2,{"y":1,"z":0}],"b":1},"name":"x"}"#
        );
    }

    #[test]
    fn any_field_change_changes_the_binding() {
        assert_ne!(
            request_binding(&json!({"name": "x", "image": "sha256:aa"})),
            request_binding(&json!({"name": "x", "image": "sha256:bb"}))
        );
        // A nested field named like the envelope is still bound.
        assert_ne!(
            request_binding(&json!({"a": {"did_envelope": 1}})),
            request_binding(&json!({"a": {}}))
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::IdentityRegistry;
    use tenzro_crypto::composite::HybridSigner as _;
    use tenzro_crypto::testing::TestHybridSigner;

    /// `signer`'s envelope signature over `env`.
    fn sign(signer: &TestHybridSigner, env: &TenzroDidEnvelope) -> Vec<u8> {
        let sig = signer
            .sign(SignatureContext::DidEnvelope, &canonical_preimage(env))
            .unwrap();
        serde_json::to_vec(&sig).unwrap()
    }

    /// The `did:key` of `signer`'s P-256 key: z + base58btc(0x8024 || compressed point).
    fn did_key(signer: &TestHybridSigner) -> String {
        let xy = &signer.public_key().p256;
        let mut mc = vec![0x80, 0x24, 0x02 | (xy[63] & 1)];
        mc.extend_from_slice(&xy[..32]);
        format!("did:key:z{}", bs58::encode(mc).into_string())
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    #[test]
    fn preimage_layout_is_deterministic_and_injective() {
        let env = TenzroDidEnvelope {
            did: "did:tenzro:human:abc".to_string(),
            method: "payment/authorize".to_string(),
            params_hash: [7u8; 32],
            timestamp: 1_700_000_000_000,
            nonce: [9u8; 16],
            signature: vec![],
        };
        let p = canonical_preimage(&env);
        // domain(22) + 4 + did(20) + 4 + method(17) + 32 + 8 + 16
        assert_eq!(p.len(), 22 + 4 + 20 + 4 + 17 + 32 + 8 + 16);
        assert!(p.starts_with(ENVELOPE_DOMAIN));

        // Injectivity: moving a char between did and method changes the preimage.
        let mut env2 = env.clone();
        env2.did = "did:tenzro:human:ab".to_string();
        env2.method = "cpayment/authorize".to_string();
        assert_ne!(canonical_preimage(&env), canonical_preimage(&env2));
    }

    #[test]
    fn params_hash_matches_sha256() {
        // SHA-256("abc") known-answer.
        // ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
        let h = params_hash(b"abc");
        assert_eq!(
            hex::encode(h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Register a human identity carrying `pk` as its P-256 key and return
    /// its DID string.
    async fn register_with_key(registry: &IdentityRegistry, pk: Vec<u8>) -> String {
        registry
            .register_human_via_binder(b"test-credential".to_vec(), pk, "Tester".to_string())
            .await
            .unwrap()
            .identity
            .did
            .to_string()
    }

    #[tokio::test]
    async fn verify_round_trip_ok() {
        let registry = IdentityRegistry::new();
        let signer = TestHybridSigner::p256_only(42);
        let did = register_with_key(&registry, signer.public_key().p256.clone()).await;

        let mut env = TenzroDidEnvelope {
            did,
            method: "message/send".to_string(),
            params_hash: params_hash(b"{\"to\":\"bob\"}"),
            timestamp: now_ms(),
            nonce: [1u8; 16],
            signature: vec![],
        };
        env.signature = sign(&signer, &env);
        assert_eq!(verify_envelope(&env, &registry), Ok(()));

        // Another key's signature does not verify for this DID.
        env.signature = sign(&TestHybridSigner::p256_only(43), &env);
        assert_eq!(
            verify_envelope(&env, &registry),
            Err(EnvelopeError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn verify_rejects_tampered_method() {
        let registry = IdentityRegistry::new();
        let signer = TestHybridSigner::p256_only(7);
        let did = register_with_key(&registry, signer.public_key().p256.clone()).await;

        let mut env = TenzroDidEnvelope {
            did,
            method: "message/send".to_string(),
            params_hash: params_hash(b"x"),
            timestamp: now_ms(),
            nonce: [1u8; 16],
            signature: vec![],
        };
        env.signature = sign(&signer, &env);
        env.method = "tasks/cancel".to_string(); // tamper after signing
        assert_eq!(
            verify_envelope(&env, &registry),
            Err(EnvelopeError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn verify_rejects_stale_and_empty_nonce() {
        let registry = IdentityRegistry::new();
        let signer = TestHybridSigner::p256_only(3);
        let did = register_with_key(&registry, signer.public_key().p256.clone()).await;

        // Stale timestamp.
        let mut env = TenzroDidEnvelope {
            did: did.clone(),
            method: "m".to_string(),
            params_hash: [0u8; 32],
            timestamp: now_ms() - MAX_SKEW_MS - 10_000,
            nonce: [1u8; 16],
            signature: vec![],
        };
        env.signature = sign(&signer, &env);
        assert!(matches!(
            verify_envelope(&env, &registry),
            Err(EnvelopeError::StaleOrFuture { .. })
        ));

        // Empty nonce (checked before freshness).
        let env2 = TenzroDidEnvelope {
            did,
            method: "m".to_string(),
            params_hash: [0u8; 32],
            timestamp: now_ms(),
            nonce: [0u8; 16],
            signature: vec![],
        };
        assert_eq!(
            verify_envelope(&env2, &registry),
            Err(EnvelopeError::EmptyNonce)
        );
    }

    #[tokio::test]
    async fn verify_rejects_unknown_did() {
        let registry = IdentityRegistry::new();
        let env = TenzroDidEnvelope {
            did: "did:tenzro:human:does-not-exist".to_string(),
            method: "m".to_string(),
            params_hash: [0u8; 32],
            timestamp: now_ms(),
            nonce: [1u8; 16],
            signature: vec![0u8; 64],
        };
        assert!(matches!(
            verify_envelope(&env, &registry),
            Err(EnvelopeError::UnknownDid(_))
        ));
    }

    #[test]
    fn did_key_p256_resolves_its_key() {
        let signer = TestHybridSigner::p256_only(21);
        let did = did_key(&signer);
        assert!(did.starts_with("did:key:zDn"), "{did}");
        let key = resolve_did_key_p256(&did).expect("should resolve");
        assert_eq!(key, signer.public_key().p256);
        // A trailing #fragment is ignored.
        assert_eq!(resolve_did_key_p256(&format!("{did}#key-1")), Some(key));
        // Non-did:key and Ed25519 did:key inputs return None.
        assert!(resolve_did_key_p256("did:tenzro:human:abc").is_none());
        assert!(resolve_did_key_p256("did:key:zNotBase58!!").is_none());
        assert!(
            resolve_did_key_p256("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
                .is_none()
        );
    }

    #[test]
    fn verify_envelope_accepts_did_key_signer_without_registry() {
        let registry = IdentityRegistry::new(); // unused on the did:key path
        let signer = TestHybridSigner::p256_only(55);
        let mut env = TenzroDidEnvelope {
            did: did_key(&signer),
            method: "tools/call".to_string(),
            params_hash: params_hash(b"{}"),
            timestamp: now_ms(),
            nonce: [2u8; 16],
            signature: vec![],
        };
        env.signature = sign(&signer, &env);
        assert_eq!(verify_envelope(&env, &registry), Ok(()));

        // Tampering the method breaks verification (signature no longer matches).
        let mut bad = env.clone();
        bad.method = "tasks/cancel".to_string();
        assert_eq!(
            verify_envelope(&bad, &registry),
            Err(EnvelopeError::InvalidSignature)
        );
    }

    #[test]
    fn header_value_round_trips() {
        let env = TenzroDidEnvelope {
            did: "did:tenzro:machine:0xabc".to_string(),
            method: "tools/call".to_string(),
            params_hash: params_hash(b"{\"x\":1}"),
            timestamp: 1_700_000_000_123,
            nonce: [5u8; 16],
            signature: vec![9u8; 64],
        };
        let hv = env.to_header_value();
        assert_eq!(TenzroDidEnvelope::from_header_value(&hv).unwrap(), env);
        // Surrounding whitespace tolerated.
        assert_eq!(
            TenzroDidEnvelope::from_header_value(&format!("  {hv}  ")).unwrap(),
            env
        );
        // Malformed inputs error rather than panic.
        assert!(TenzroDidEnvelope::from_header_value("zzz").is_err());
        assert!(TenzroDidEnvelope::from_header_value(&hv[..hv.len() - 4]).is_err());
    }

    #[test]
    fn did_document_p256_extraction_and_external_verify() {
        use base64::Engine as _;
        let signer = TestHybridSigner::p256_only(77);
        let xy = signer.public_key().p256.clone();

        // did.json with a publicKeyMultibase (did:key form) P-256 method.
        let mb = did_key(&signer).trim_start_matches("did:key:").to_string();
        let doc = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key-1",
                "type": "Multikey",
                "controller": "did:web:example.com",
                "publicKeyMultibase": mb,
            }]
        });
        assert_eq!(p256_from_did_document(&doc), Some(xy.clone()));

        // publicKeyJwk form also works.
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let doc2 = serde_json::json!({
            "verificationMethod": [{
                "type": "JsonWebKey2020",
                "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": b64.encode(&xy[..32]), "y": b64.encode(&xy[32..])},
            }]
        });
        assert_eq!(p256_from_did_document(&doc2), Some(xy.clone()));

        // No P-256 method -> None.
        assert!(p256_from_did_document(&serde_json::json!({})).is_none());

        // Sign an envelope and verify against the externally-resolved key.
        let mut env = TenzroDidEnvelope {
            did: "did:web:example.com".to_string(),
            method: "message/send".to_string(),
            params_hash: params_hash(b"{}"),
            timestamp: now_ms(),
            nonce: [3u8; 16],
            signature: vec![],
        };
        env.signature = sign(&signer, &env);
        assert_eq!(verify_envelope_with_key(&env, &xy), Ok(()));

        // Wrong key -> InvalidSignature.
        assert_eq!(
            verify_envelope_with_key(&env, &TestHybridSigner::p256_only(78).public_key().p256),
            Err(EnvelopeError::InvalidSignature)
        );
    }

    #[test]
    fn did_ethr_secp256k1_recover_and_verify() {
        use k256::ecdsa::{SigningKey, VerifyingKey};
        use sha3::{Digest, Keccak256};

        let sk = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
        let vk = VerifyingKey::from(&sk);
        let enc = vk.to_sec1_point(false);
        let addr = &Keccak256::digest(&enc.as_bytes()[1..])[12..32];
        let did = format!("did:ethr:0x{}", hex::encode(addr));

        let mut env = TenzroDidEnvelope {
            did,
            method: "payments/execute".to_string(),
            params_hash: params_hash(b"{}"),
            timestamp: now_ms(),
            nonce: [4u8; 16],
            signature: vec![],
        };
        let prehash = Keccak256::digest(canonical_preimage(&env));
        let (sig, rid) = sk.sign_prehash_recoverable(&prehash).unwrap();
        let mut s = sig.to_bytes().to_vec();
        s.push(rid.to_byte());
        env.signature = s;
        assert_eq!(verify_envelope_ethr(&env), Ok(()));

        // Routes through verify_envelope too (registry unused for did:ethr).
        let registry = IdentityRegistry::new();
        assert_eq!(verify_envelope(&env, &registry), Ok(()));

        // A different address in the DID (re-signed so the sig itself is valid)
        // fails the address binding.
        let mut bad = env.clone();
        bad.did = "did:ethr:0x0000000000000000000000000000000000000001".to_string();
        let ph = Keccak256::digest(canonical_preimage(&bad));
        let (sig2, rid2) = sk.sign_prehash_recoverable(&ph).unwrap();
        let mut s2 = sig2.to_bytes().to_vec();
        s2.push(rid2.to_byte());
        bad.signature = s2;
        assert_eq!(
            verify_envelope_ethr(&bad),
            Err(EnvelopeError::InvalidSignature)
        );
    }

    /// The shared envelope vector the SDKs check themselves against: the
    /// request binding, `params_hash`, preimage, composite message
    /// representative and header value of a controller's envelope over a
    /// machine registration all match this crate, and the signature in it is
    /// the controller's.
    #[test]
    fn the_shared_machine_registration_envelope_vector_matches() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sdk/fixtures/did_envelope/machine_registration.json"
        );
        let f: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("the shared fixture")).unwrap();
        let text = |k: &str| f[k].as_str().unwrap().to_string();
        let bytes = |k: &str| hex::decode(f[k].as_str().unwrap()).unwrap();

        let binding = request_binding(&f["request"]);
        assert_eq!(
            String::from_utf8(binding.clone()).unwrap(),
            text("request_binding")
        );
        let mut with_envelope = f["request"].clone();
        with_envelope["did_envelope"] = serde_json::json!(text("did_envelope"));
        assert_eq!(request_binding(&with_envelope), binding);
        assert_eq!(params_hash(&binding).to_vec(), bytes("params_hash"));

        let mut env = TenzroDidEnvelope {
            did: text("did"),
            method: text("method"),
            params_hash: params_hash(&binding),
            timestamp: f["timestamp_ms"].as_u64().unwrap(),
            nonce: bytes("nonce").try_into().unwrap(),
            signature: serde_json::to_vec(&f["signature"]).unwrap(),
        };
        assert_eq!(canonical_preimage(&env), bytes("preimage"));
        assert_eq!(
            tenzro_crypto::composite::message_representative(
                SignatureContext::DidEnvelope,
                &canonical_preimage(&env)
            ),
            bytes("m_prime")
        );
        assert_eq!(env.to_header_value(), text("did_envelope"));
        assert_eq!(
            TenzroDidEnvelope::from_header_value(&text("did_envelope")).unwrap(),
            env
        );

        let key = CompositePublicKey::new(bytes("controller_public_key"), None).unwrap();
        let sig: CompositeSignature = serde_json::from_value(f["signature"].clone()).unwrap();
        verify_composite(
            &key,
            SignatureContext::DidEnvelope,
            &canonical_preimage(&env),
            &sig,
            PqPolicy::WhenPresent,
        )
        .expect("the controller's signature");
        env.method = "tenzro_registerIdentity".to_string();
        assert!(
            verify_composite(
                &key,
                SignatureContext::DidEnvelope,
                &canonical_preimage(&env),
                &sig,
                PqPolicy::WhenPresent,
            )
            .is_err(),
            "the signature binds the method"
        );
    }
}
