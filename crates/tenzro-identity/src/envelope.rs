//! Protocol-neutral Tenzro DID envelope (interop bridge Layer 1).
//!
//! This module generalises the A2A-specific DID envelope
//! (`tenzro-node/src/a2a/did_envelope.rs`) into a protocol-neutral, registry-
//! coupled (but node-decoupled) primitive that MCP, x402, AP2, A2A, and
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
//! preimage** (see [`canonical_preimage`]). Verification resolves the DID
//! through an [`IdentityRegistry`], pulls the registered Ed25519 verification
//! key, checks signature validity, timestamp freshness (bounded skew), and a
//! non-empty nonce.
//!
//! Unlike the A2A wrapper, this layer does NOT bind the public key to the
//! identity's `wallet_address` — it trusts the registry's verification method
//! directly, which is the W3C DID resolution model. The A2A wrapper keeps its
//! additional wallet-address binding on top of this shared core.

use crate::registry::IdentityRegistry;
use sha2::{Digest, Sha256};
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::{verify, Signature};

/// Domain-separation tag for the canonical preimage. Bumping the `:v1`
/// suffix invalidates every previously-signed envelope, so it doubles as a
/// wire-format version. Chosen distinct from the A2A `tenzro:a2a:` tag so an
/// A2A signature can never be replayed as a generalized-envelope signature.
pub const ENVELOPE_DOMAIN_V1: &[u8] = b"tenzro-did-envelope:v1";

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
    /// Protocol method this envelope authorizes (e.g. `ap2.cart.complete`,
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
    /// Ed25519 signature over [`canonical_preimage`].
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
        let buf = hex::decode(s.trim()).map_err(|_| "envelope header is not valid hex".to_string())?;
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
        Ok(Self { did, method, params_hash, timestamp, nonce, signature })
    }
}

/// Errors returned by [`verify_envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The DID could not be resolved through the registry.
    UnknownDid(String),
    /// The resolved identity has no usable Ed25519 verification key.
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
                write!(f, "no Ed25519 verification key for DID: {did}")
            }
            Self::StaleOrFuture { skew_ms } => {
                write!(f, "envelope timestamp out of window (skew {skew_ms} ms, max ±{MAX_SKEW_MS} ms)")
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

/// Build the deterministic, domain-separated preimage the signer commits to.
///
/// ## Exact byte layout
///
/// ```text
/// ENVELOPE_DOMAIN_V1                       (22 bytes, b"tenzro-did-envelope:v1")
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
    let mut buf = Vec::with_capacity(
        ENVELOPE_DOMAIN_V1.len() + 4 + did.len() + 4 + method.len() + 32 + 8 + 16,
    );
    buf.extend_from_slice(ENVELOPE_DOMAIN_V1);
    buf.extend_from_slice(&(did.len() as u32).to_be_bytes());
    buf.extend_from_slice(did);
    buf.extend_from_slice(&(method.len() as u32).to_be_bytes());
    buf.extend_from_slice(method);
    buf.extend_from_slice(&env.params_hash);
    buf.extend_from_slice(&env.timestamp.to_be_bytes());
    buf.extend_from_slice(&env.nonce);
    buf
}

/// Resolve the Ed25519 verification key from a `did:key:z6Mk…` identifier (the
/// multicodec `0xed01` Ed25519 form, base58btc multibase). Any trailing
/// `#fragment` is ignored. Returns `None` for a non-`did:key` string, a
/// non-base58btc body, or a non-Ed25519 multicodec.
///
/// `did:key` signers carry their key in the identifier itself, so they can be
/// verified with no registry lookup — universal resolution for external agents
/// per `docs/architecture/agent-interop-protocol-bridge.md` Phase 4.
pub fn resolve_did_key_ed25519(did: &str) -> Option<[u8; 32]> {
    let body = did.strip_prefix("did:key:")?;
    let body = body.split('#').next().unwrap_or(body);
    let z = body.strip_prefix('z')?; // 'z' = base58btc multibase prefix
    let bytes = bs58::decode(z).into_vec().ok()?;
    // multicodec ed25519-pub = varint(0xed) = [0xed, 0x01], then the 32-byte key.
    if bytes.len() == 34 && bytes[0] == 0xed && bytes[1] == 0x01 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[2..]);
        Some(key)
    } else {
        None
    }
}

/// Verify an envelope against the registry.
///
/// Steps:
/// 1. Reject an empty (all-zero) nonce.
/// 2. Enforce timestamp freshness within `±MAX_SKEW_MS` of local wall-clock.
/// 3. Resolve `env.did` through the registry to a [`crate::TenzroIdentity`].
/// 4. Find the identity's Ed25519 verification method (a 32-byte
///    `public_keys[i]` entry — TDIP stores the W3C verification methods here).
/// 5. Verify the Ed25519 signature over [`canonical_preimage`].
pub fn verify_envelope(
    env: &TenzroDidEnvelope,
    registry: &IdentityRegistry,
) -> Result<(), EnvelopeError> {
    // (1) Nonce must be non-empty. An all-zero nonce provides no replay
    // entropy, so we treat it as "unset" and reject.
    if env.nonce == [0u8; 16] {
        return Err(EnvelopeError::EmptyNonce);
    }

    // (2) Freshness. Reject before doing any expensive crypto / DID lookup.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| EnvelopeError::ClockError)?
        .as_millis() as u64;
    let skew_ms = now_ms.abs_diff(env.timestamp);
    if skew_ms > MAX_SKEW_MS {
        return Err(EnvelopeError::StaleOrFuture { skew_ms });
    }

    // (2b) `did:key` signers carry their Ed25519 key in the identifier itself,
    // so they resolve without a registry lookup (external agents / offline
    // verification). Other DID methods fall through to registry resolution.
    if env.did.starts_with("did:key:") {
        let ed_key = resolve_did_key_ed25519(&env.did)
            .ok_or_else(|| EnvelopeError::NoVerificationKey(env.did.clone()))?;
        return check_envelope_sig(env, &ed_key);
    }

    // did:ethr signers use a recoverable secp256k1 signature; the key is
    // recovered from the signature and bound to the address in the DID, so no
    // registry lookup is needed.
    if env.did.starts_with("did:ethr:") {
        return check_envelope_sig_ethr(env);
    }

    // (3) Resolve the DID. The registry handles local + canonical + remote
    // resolution.
    let identity = registry
        .resolve(&env.did)
        .map_err(|_| EnvelopeError::UnknownDid(env.did.clone()))?;

    // (4) Locate an Ed25519 verification key. TDIP stores W3C verification
    // methods in `public_keys`; an Ed25519 key is the 32-byte entry whose
    // `key_type` is "Ed25519".
    let ed_key = identity
        .public_keys
        .iter()
        .find(|pk| pk.key_type == "Ed25519" && pk.public_key.len() == 32)
        .ok_or_else(|| EnvelopeError::NoVerificationKey(env.did.clone()))?;

    // (5) Verify the signature over the canonical preimage.
    check_envelope_sig(env, &ed_key.public_key)
}

/// Signature-only check: verify `env.signature` over the canonical preimage
/// with the supplied Ed25519 key bytes. Nonce + freshness are the caller's job.
fn check_envelope_sig(env: &TenzroDidEnvelope, ed25519_key: &[u8]) -> Result<(), EnvelopeError> {
    let preimage = canonical_preimage(env);
    let pk = PublicKey::new(KeyType::Ed25519, ed25519_key.to_vec());
    let sig = Signature::new(KeyType::Ed25519, env.signature.clone());
    verify(&pk, &preimage, &sig).map_err(|_| EnvelopeError::InvalidSignature)
}

/// Verify an envelope against an explicitly-supplied Ed25519 verification key,
/// for DIDs resolved outside the registry (e.g. `did:web`, fetched over HTTPS by
/// the node). Checks nonce + freshness + signature; never touches the registry.
pub fn verify_envelope_with_key(
    env: &TenzroDidEnvelope,
    ed25519_key: &[u8; 32],
) -> Result<(), EnvelopeError> {
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
    check_envelope_sig(env, ed25519_key)
}

/// Extract the first usable Ed25519 verification key from a W3C DID document
/// JSON (the `did:web` resolution target). Supports `publicKeyMultibase`
/// (z-base58btc multicodec, as in did:key) and `publicKeyBase58` (raw 32-byte
/// Ed25519). Returns `None` if no Ed25519 method is present.
pub fn ed25519_from_did_document(doc: &serde_json::Value) -> Option<[u8; 32]> {
    let vms = doc.get("verificationMethod")?.as_array()?;
    for vm in vms {
        if let Some(mb) = vm.get("publicKeyMultibase").and_then(|v| v.as_str())
            && let Some(k) = resolve_did_key_ed25519(&format!("did:key:{mb}"))
        {
            return Some(k);
        }
        if let Some(b58) = vm.get("publicKeyBase58").and_then(|v| v.as_str())
            && let Ok(bytes) = bs58::decode(b58).into_vec()
            && bytes.len() == 32
        {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Some(key);
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

    let want = ethr_address(&env.did)
        .ok_or_else(|| EnvelopeError::NoVerificationKey(env.did.clone()))?;
    if env.signature.len() != 65 {
        return Err(EnvelopeError::InvalidSignature);
    }
    let v = env.signature[64];
    let y_parity = if v >= 27 { v - 27 } else { v };
    let recovery_id =
        RecoveryId::try_from(y_parity).map_err(|_| EnvelopeError::InvalidSignature)?;
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&env.signature[..64]);
    let sig = K256Sig::from_bytes(&sig_bytes.into()).map_err(|_| EnvelopeError::InvalidSignature)?;
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
    check_envelope_sig_ethr(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::IdentityRegistry;
    use ed25519_dalek::{Signer as _, SigningKey};

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
            method: "ap2.cart.complete".to_string(),
            params_hash: [7u8; 32],
            timestamp: 1_700_000_000_000,
            nonce: [9u8; 16],
            signature: vec![],
        };
        let p = canonical_preimage(&env);
        // domain(22) + 4 + did(20) + 4 + method(17) + 32 + 8 + 16
        assert_eq!(p.len(), 22 + 4 + 20 + 4 + 17 + 32 + 8 + 16);
        assert!(p.starts_with(ENVELOPE_DOMAIN_V1));

        // Injectivity: moving a char between did and method changes the preimage.
        let mut env2 = env.clone();
        env2.did = "did:tenzro:human:ab".to_string();
        env2.method = "cap2.cart.complete".to_string();
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

    /// Register a human identity carrying `pk` as its Ed25519 key and return
    /// its DID string. Bypasses wallet provisioning by inserting through the
    /// public registration path with an explicit key.
    async fn register_with_key(registry: &IdentityRegistry, pk: Vec<u8>) -> String {
        registry
            .register_human_with_fee(pk, "Tester".to_string(), tenzro_types::identity::KycTier::Basic)
            .await
            .unwrap()
            .identity
            .did
            .to_string()
    }

    #[tokio::test]
    async fn verify_round_trip_ok() {
        let registry = IdentityRegistry::new();
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let vk = signing.verifying_key().to_bytes().to_vec();
        let did = register_with_key(&registry, vk).await;

        let mut env = TenzroDidEnvelope {
            did,
            method: "message/send".to_string(),
            params_hash: params_hash(b"{\"to\":\"bob\"}"),
            timestamp: now_ms(),
            nonce: [1u8; 16],
            signature: vec![],
        };
        let sig = signing.sign(&canonical_preimage(&env));
        env.signature = sig.to_bytes().to_vec();

        assert_eq!(verify_envelope(&env, &registry), Ok(()));
    }

    #[tokio::test]
    async fn verify_rejects_tampered_method() {
        let registry = IdentityRegistry::new();
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let vk = signing.verifying_key().to_bytes().to_vec();
        let did = register_with_key(&registry, vk).await;

        let mut env = TenzroDidEnvelope {
            did,
            method: "message/send".to_string(),
            params_hash: params_hash(b"x"),
            timestamp: now_ms(),
            nonce: [1u8; 16],
            signature: vec![],
        };
        env.signature = signing.sign(&canonical_preimage(&env)).to_bytes().to_vec();
        env.method = "tasks/cancel".to_string(); // tamper after signing
        assert_eq!(
            verify_envelope(&env, &registry),
            Err(EnvelopeError::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn verify_rejects_stale_and_empty_nonce() {
        let registry = IdentityRegistry::new();
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let vk = signing.verifying_key().to_bytes().to_vec();
        let did = register_with_key(&registry, vk).await;

        // Stale timestamp.
        let mut env = TenzroDidEnvelope {
            did: did.clone(),
            method: "m".to_string(),
            params_hash: [0u8; 32],
            timestamp: now_ms() - MAX_SKEW_MS - 10_000,
            nonce: [1u8; 16],
            signature: vec![],
        };
        env.signature = signing.sign(&canonical_preimage(&env)).to_bytes().to_vec();
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
    fn did_key_ed25519_resolves_known_vector() {
        // W3C did:key spec Ed25519 example.
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let key = resolve_did_key_ed25519(did).expect("should resolve");
        assert_eq!(
            hex::encode(key),
            "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6"
        );
        // A trailing #fragment is ignored.
        assert_eq!(resolve_did_key_ed25519(&format!("{did}#key-1")), Some(key));
        // Non-did:key and non-Ed25519 inputs return None.
        assert!(resolve_did_key_ed25519("did:tenzro:human:abc").is_none());
        assert!(resolve_did_key_ed25519("did:key:zNotBase58!!").is_none());
    }

    #[test]
    fn verify_envelope_accepts_did_key_signer_without_registry() {
        let registry = IdentityRegistry::new(); // unused on the did:key path
        let signing = SigningKey::from_bytes(&[55u8; 32]);
        let vk = signing.verifying_key().to_bytes();
        // Construct the did:key for this Ed25519 key: z + base58btc(0xed01 || vk).
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(&vk);
        let did = format!("did:key:z{}", bs58::encode(mc).into_string());

        let mut env = TenzroDidEnvelope {
            did,
            method: "tools/call".to_string(),
            params_hash: params_hash(b"{}"),
            timestamp: now_ms(),
            nonce: [2u8; 16],
            signature: vec![],
        };
        env.signature = signing.sign(&canonical_preimage(&env)).to_bytes().to_vec();
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
    fn did_document_ed25519_extraction_and_external_verify() {
        let signing = SigningKey::from_bytes(&[77u8; 32]);
        let vk = signing.verifying_key().to_bytes();

        // did.json with a publicKeyMultibase (did:key form) Ed25519 method.
        let mut mc = vec![0xed, 0x01];
        mc.extend_from_slice(&vk);
        let mb = format!("z{}", bs58::encode(mc).into_string());
        let doc = serde_json::json!({
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": mb,
            }]
        });
        assert_eq!(ed25519_from_did_document(&doc), Some(vk));

        // publicKeyBase58 (2018) form also works.
        let doc2 = serde_json::json!({
            "verificationMethod": [{
                "type": "Ed25519VerificationKey2018",
                "publicKeyBase58": bs58::encode(vk).into_string(),
            }]
        });
        assert_eq!(ed25519_from_did_document(&doc2), Some(vk));

        // No Ed25519 method → None.
        assert!(ed25519_from_did_document(&serde_json::json!({})).is_none());

        // Sign an envelope and verify against the externally-resolved key.
        let mut env = TenzroDidEnvelope {
            did: "did:web:example.com".to_string(),
            method: "message/send".to_string(),
            params_hash: params_hash(b"{}"),
            timestamp: now_ms(),
            nonce: [3u8; 16],
            signature: vec![],
        };
        env.signature = signing.sign(&canonical_preimage(&env)).to_bytes().to_vec();
        assert_eq!(verify_envelope_with_key(&env, &vk), Ok(()));

        // Wrong key → InvalidSignature.
        assert_eq!(
            verify_envelope_with_key(&env, &[0u8; 32]),
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
        assert_eq!(verify_envelope_ethr(&bad), Err(EnvelopeError::InvalidSignature));
    }
}
