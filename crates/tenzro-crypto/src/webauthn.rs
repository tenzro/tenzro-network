//! WebAuthn / FIDO2 signature verification primitives.
//!
//! This module bridges the WebAuthn assertion format produced by platform
//! authenticators (Apple Secure Enclave, Android StrongBox, Windows Hello /
//! Pluton, TPM 2.0, YubiKey FIDO2) to the raw P-256 verifier in
//! [`crate::p256`] and the on-chain `0x100` precompile.
//!
//! # The signed payload
//!
//! Per the [WebAuthn Level 3
//! spec](https://www.w3.org/TR/webauthn-3/#fig-signature), an authenticator
//! signs the concatenation
//!
//! ```text
//! authenticatorData ‖ SHA-256(clientDataJSON)
//! ```
//!
//! using the credential's private key. The `clientDataJSON` bytes **must
//! not** be re-serialized — the verifier hashes the exact byte sequence the
//! authenticator hashed. Re-serializing breaks verification because JSON
//! field order, whitespace, and Unicode escaping all matter.
//!
//! # Signature unwrapping
//!
//! Most platform authenticators return signatures in ASN.1 DER form
//! (`SEQUENCE { r INTEGER, s INTEGER }`). The on-chain precompile and the
//! [`crate::p256`] verifier consume the raw 64-byte `r ‖ s` form. This
//! module's [`unwrap_der_signature`] decodes the DER envelope and applies
//! the WebAuthn-mandated leading-zero stripping for short integers.

use crate::error::{CryptoError, Result};
use crate::p256::{P256_SIGNATURE_LEN, P256Signature, P256Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A WebAuthn assertion as received from the client.
///
/// The fields mirror the `AuthenticatorAssertionResponse` IDL exactly. All
/// byte fields are the **raw** bytes the authenticator returned, not
/// base64url-decoded copies of intermediate strings — re-serializing
/// `clientDataJSON` will silently break verification, so callers must keep
/// the original bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAssertion {
    /// Raw `authenticatorData` bytes from the assertion.
    pub authenticator_data: Vec<u8>,
    /// Raw UTF-8 bytes of `clientDataJSON` — preserve byte-exact, never
    /// re-serialize.
    pub client_data_json: Vec<u8>,
    /// Raw signature bytes as returned by the authenticator. May be either
    /// DER-encoded ECDSA (the common case for P-256 platform authenticators)
    /// or a raw 64-byte `r ‖ s` payload.
    pub signature: Vec<u8>,
    /// Optional 32-byte user handle returned by the authenticator (RFC
    /// 8809 / WebAuthn user identification).
    pub user_handle: Option<Vec<u8>>,
}

/// Compute the exact byte sequence the authenticator hashed and signed:
///
/// ```text
/// authenticatorData ‖ SHA-256(clientDataJSON)
/// ```
///
/// The output is the input the verifier (or the on-chain `0x100`
/// precompile) consumes after one further SHA-256 hash. Most callers
/// instead want [`webauthn_signed_hash`], which returns the prehash
/// directly.
pub fn webauthn_signed_payload(authenticator_data: &[u8], client_data_json: &[u8]) -> Vec<u8> {
    let cdj_hash = Sha256::digest(client_data_json);
    let mut payload = Vec::with_capacity(authenticator_data.len() + 32);
    payload.extend_from_slice(authenticator_data);
    payload.extend_from_slice(&cdj_hash);
    payload
}

/// Compute the 32-byte SHA-256 prehash that a P-256 / RIP-7212 verifier
/// consumes. Equal to `SHA-256(authenticatorData ‖ SHA-256(clientDataJSON))`.
pub fn webauthn_signed_hash(authenticator_data: &[u8], client_data_json: &[u8]) -> [u8; 32] {
    let payload = webauthn_signed_payload(authenticator_data, client_data_json);
    Sha256::digest(&payload).into()
}

/// Verify a WebAuthn assertion against a registered P-256 public key.
///
/// `expected_challenge_b64url` is the challenge the relying party issued at
/// `navigator.credentials.get()` time; it must match the `challenge` field
/// inside `clientDataJSON` byte-for-byte (base64url, no padding, per the
/// WebAuthn spec).
///
/// `relying_party` is the [`WebAuthnRelyingParty`] policy the credential
/// must satisfy — either one exact pinned origin, or a registrable-domain
/// RP ID shared across its subdomains. Wildcard *origins* are not supported
/// by the spec and are not accepted; cross-subdomain reuse is expressed as
/// [`WebAuthnRelyingParty::RegistrableDomain`], which is a different
/// mechanism (RP ID scoping, WebAuthn L3 §5.1.3 step 8 / §7.1).
///
/// `expected_type` is `"webauthn.get"` for assertions and
/// `"webauthn.create"` for registrations; pass the value matching the
/// ceremony you initiated.
pub fn verify_webauthn_assertion(
    assertion: &WebAuthnAssertion,
    public_key_xy: &[u8],
    expected_challenge_b64url: &str,
    relying_party: &WebAuthnRelyingParty,
    expected_type: WebAuthnCeremonyType,
) -> Result<()> {
    // 1. Parse and validate clientDataJSON. Per the spec we may NOT
    // re-serialize, so we parse to inspect the fields and then discard the
    // parsed form — the bytes hashed below remain the original.
    let cdj: ClientDataJson = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|e| CryptoError::InvalidSignature(format!("clientDataJSON parse: {}", e)))?;

    if cdj.r#type != expected_type.as_str() {
        return Err(CryptoError::InvalidSignature(format!(
            "clientDataJSON type mismatch: expected {}, got {}",
            expected_type.as_str(),
            cdj.r#type
        )));
    }
    if cdj.challenge != expected_challenge_b64url {
        return Err(CryptoError::InvalidSignature(
            "clientDataJSON challenge mismatch".to_string(),
        ));
    }

    // 2. Validate authenticatorData minimum length. Checked before the
    // relying-party arm below because the `RegistrableDomain` arm reads the
    // leading 32-byte rpIdHash out of it.
    if assertion.authenticator_data.len() < AUTHENTICATOR_DATA_MIN_LEN {
        return Err(CryptoError::InvalidSignature(format!(
            "authenticatorData too short: {} bytes",
            assertion.authenticator_data.len()
        )));
    }

    // 3. Enforce the relying-party policy.
    match relying_party {
        WebAuthnRelyingParty::Origin(expected_origin) => {
            if &cdj.origin != expected_origin {
                return Err(CryptoError::InvalidSignature(format!(
                    "clientDataJSON origin mismatch: expected {}, got {}",
                    expected_origin, cdj.origin
                )));
            }
        }
        WebAuthnRelyingParty::RegistrableDomain { rp_id } => {
            let host = origin_host(&cdj.origin)?;
            let is_local = host == "localhost" || host == "127.0.0.1";
            if !is_local && !cdj.origin.starts_with("https://") {
                return Err(CryptoError::InvalidSignature(
                    "clientDataJSON origin must be https (except localhost)".to_string(),
                ));
            }
            // The dot-prefixed suffix test is load-bearing: a bare
            // `ends_with(rp_id)` would also accept `evilnetwork.tenzro.com`
            // for an RP ID of `network.tenzro.com`.
            if host != rp_id.as_str() && !host.ends_with(&format!(".{rp_id}")) {
                return Err(CryptoError::InvalidSignature(format!(
                    "clientDataJSON origin {} is not {rp_id} or a subdomain of it",
                    cdj.origin
                )));
            }
            // The origin string is browser-supplied; the rpIdHash is what
            // the authenticator itself committed to, and is the check that
            // actually binds the credential to this RP ID (WebAuthn L3
            // §7.2 step 13).
            let expected_rp_id_hash = Sha256::digest(rp_id.as_bytes());
            if assertion.authenticator_data[0..32] != expected_rp_id_hash[..] {
                return Err(CryptoError::InvalidSignature(
                    "authenticatorData rpIdHash does not match the configured RP ID".to_string(),
                ));
            }
        }
    }

    // 4. Enforce the User Present flag.
    let flags = assertion.authenticator_data[AUTHENTICATOR_DATA_FLAGS_OFFSET];
    if flags & AUTH_DATA_FLAG_UP == 0 {
        return Err(CryptoError::InvalidSignature(
            "authenticatorData User Present (UP) flag not set".to_string(),
        ));
    }
    // UV is enforced via the `_require_uv` wrapper variant — call sites
    // that need biometric assurance (high-value ops) go through that
    // path. Plain `verify_webauthn_assertion` allows UP-only because
    // some flows (low-value reads, recovery setup) accept it.

    // 5. Compute the hash the authenticator signed.
    let prehash = webauthn_signed_hash(&assertion.authenticator_data, &assertion.client_data_json);

    // 6. Unwrap signature from DER if needed and verify.
    let raw_sig = unwrap_der_signature(&assertion.signature)?;
    let p256_sig = P256Signature::from_bytes(raw_sig);
    let verifier = P256Verifier::from_public_key_bytes(public_key_xy)?;
    verifier.verify_prehash(&prehash, &p256_sig)
}

/// Same as [`verify_webauthn_assertion`] but additionally enforces the
/// UV (User Verification) flag in `authenticatorData.flags`. Call this
/// for any signing flow whose security model depends on user identity
/// being proven (biometric / PIN) rather than mere physical presence
/// (a touch). Reference: WebAuthn L3 §5.2.4, CTAP 2.2 §6.1.
pub fn verify_webauthn_assertion_require_uv(
    assertion: &WebAuthnAssertion,
    public_key_xy: &[u8],
    expected_challenge_b64url: &str,
    relying_party: &WebAuthnRelyingParty,
    expected_type: WebAuthnCeremonyType,
) -> Result<()> {
    verify_webauthn_assertion(
        assertion,
        public_key_xy,
        expected_challenge_b64url,
        relying_party,
        expected_type,
    )?;
    let flags = assertion.authenticator_data[AUTHENTICATOR_DATA_FLAGS_OFFSET];
    if flags & AUTH_DATA_FLAG_UV == 0 {
        return Err(CryptoError::InvalidSignature(
            "authenticatorData User Verification (UV) flag not set — \
             biometric or PIN required for this operation"
                .to_string(),
        ));
    }
    Ok(())
}

/// Relying Party identity policy for [`verify_webauthn_assertion`].
///
/// A WebAuthn credential is scoped to whichever RP ID the authenticator
/// committed to at creation time (the `rpIdHash` inside `authenticatorData`),
/// not to the `origin` string alone — `origin` is browser-supplied and on
/// its own only proves the ceremony ran somewhere under that host, not which
/// RP ID the credential is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthnRelyingParty {
    /// Exact-origin match (e.g. `https://keys.tenzro.xyz`) — the behavior of
    /// [`verify_webauthn_assertion`]. A credential is scoped to one origin
    /// and cannot be used from any other host, including a subdomain.
    Origin(String),
    /// Parent-domain RP ID (e.g. `network.tenzro.com`). Per WebAuthn L3
    /// §5.1.3 step 8 / §7.1, an RP ID may be any registrable-domain suffix
    /// of the origin, so a credential created under one subdomain
    /// authenticates under any other subdomain of the same RP ID —
    /// `alice.network.tenzro.com` and `bob.network.tenzro.com` share
    /// credentials.
    RegistrableDomain {
        /// The registrable domain both the origin's host and the
        /// authenticator's committed `rpIdHash` must match.
        rp_id: String,
    },
}

/// Extracts the host (no scheme, no port, no path) from an `Origin` string
/// as found in `clientDataJSON.origin`.
fn origin_host(origin: &str) -> Result<&str> {
    let without_scheme = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme);
    if host.is_empty() {
        return Err(CryptoError::InvalidSignature(
            "clientDataJSON origin has no host".to_string(),
        ));
    }
    Ok(host)
}

/// WebAuthn ceremony discriminator written to `clientDataJSON.type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAuthnCeremonyType {
    /// `navigator.credentials.create()` — passkey registration.
    Create,
    /// `navigator.credentials.get()` — assertion / signing.
    Get,
}

impl WebAuthnCeremonyType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

/// Decoded fields of the `clientDataJSON` blob.
///
/// Used for validation only — the bytes hashed during verification are
/// always the raw `clientDataJSON` to preserve the byte-exact contract with
/// the authenticator.
#[derive(Debug, Deserialize)]
struct ClientDataJson {
    r#type: String,
    challenge: String,
    origin: String,
    // Other fields (crossOrigin, tokenBinding) are present but not
    // material to verification — the byte-exact hash check covers them
    // implicitly.
}

/// authenticatorData layout: `rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ …`.
const AUTHENTICATOR_DATA_MIN_LEN: usize = 37;
const AUTHENTICATOR_DATA_FLAGS_OFFSET: usize = 32;
/// User Verification flag bit per the WebAuthn L3 / CTAP 2.2 spec.
/// Set by platform authenticators that successfully completed a
/// biometric / PIN ceremony with the user. UP alone (User Present)
/// only proves a touch — UV proves identity. High-value ops must
/// enforce UV; UP-only is insufficient.
pub const AUTH_DATA_FLAG_UV: u8 = 0x04;

/// authenticatorData flag bits (WebAuthn L3 §6.1).
const AUTH_DATA_FLAG_UP: u8 = 0x01; // User Present

/// Unwrap a DER-encoded ECDSA signature `SEQUENCE { r INTEGER, s INTEGER }`
/// to a raw 64-byte `r ‖ s` payload.
///
/// If `der_or_raw` is already 64 bytes, it is returned as-is — some
/// authenticators produce raw signatures.
///
/// DER integers are big-endian and may carry a leading `0x00` byte to
/// disambiguate the sign bit. Per the WebAuthn spec the integer payload is
/// then left-padded with zeros to 32 bytes for the precompile-compatible
/// raw form.
pub fn unwrap_der_signature(der_or_raw: &[u8]) -> Result<[u8; P256_SIGNATURE_LEN]> {
    // Fast path: already raw 64-byte form.
    if der_or_raw.len() == P256_SIGNATURE_LEN {
        let mut out = [0u8; P256_SIGNATURE_LEN];
        out.copy_from_slice(der_or_raw);
        return Ok(out);
    }

    // DER path: SEQUENCE (0x30) of two INTEGERs (0x02).
    if der_or_raw.len() < 8 || der_or_raw[0] != 0x30 {
        return Err(CryptoError::InvalidSignature(format!(
            "DER signature: missing SEQUENCE tag (got len {} byte0 0x{:02x})",
            der_or_raw.len(),
            der_or_raw.first().copied().unwrap_or(0),
        )));
    }
    let seq_len = der_or_raw[1] as usize;
    if seq_len != der_or_raw.len() - 2 {
        return Err(CryptoError::InvalidSignature(
            "DER signature: SEQUENCE length mismatch".to_string(),
        ));
    }
    let body = &der_or_raw[2..];

    // INTEGER r.
    if body.first().copied() != Some(0x02) {
        return Err(CryptoError::InvalidSignature(
            "DER signature: missing r INTEGER tag".to_string(),
        ));
    }
    let r_len = body[1] as usize;
    if 2 + r_len > body.len() {
        return Err(CryptoError::InvalidSignature(
            "DER signature: r INTEGER length out of range".to_string(),
        ));
    }
    let r_raw = &body[2..2 + r_len];

    // INTEGER s.
    let s_offset = 2 + r_len;
    if s_offset + 2 > body.len() || body[s_offset] != 0x02 {
        return Err(CryptoError::InvalidSignature(
            "DER signature: missing s INTEGER tag".to_string(),
        ));
    }
    let s_len = body[s_offset + 1] as usize;
    if s_offset + 2 + s_len != body.len() {
        return Err(CryptoError::InvalidSignature(
            "DER signature: s INTEGER length out of range".to_string(),
        ));
    }
    let s_raw = &body[s_offset + 2..];

    // Strip leading 0x00 sign-bit padding (DER may carry it; raw form does
    // not), then left-pad to 32 bytes.
    let r = strip_and_pad_to_32(r_raw)?;
    let s = strip_and_pad_to_32(s_raw)?;

    let mut out = [0u8; P256_SIGNATURE_LEN];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
    Ok(out)
}

fn strip_and_pad_to_32(int_bytes: &[u8]) -> Result<[u8; 32]> {
    let mut slice = int_bytes;
    // DER integers prepend 0x00 to disambiguate the sign bit when the high
    // bit is set; strip it for the raw form.
    if slice.len() == 33 && slice[0] == 0x00 {
        slice = &slice[1..];
    }
    if slice.len() > 32 {
        return Err(CryptoError::InvalidSignature(format!(
            "P-256 integer overflows 32 bytes after sign stripping: {}",
            slice.len()
        )));
    }
    let mut out = [0u8; 32];
    out[32 - slice.len()..].copy_from_slice(slice);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256::{P256KeyPair, P256Signer};

    #[test]
    fn unwrap_passes_through_raw_signature() {
        let raw = [7u8; 64];
        let unwrapped = unwrap_der_signature(&raw).unwrap();
        assert_eq!(unwrapped, raw);
    }

    #[test]
    fn unwrap_rejects_truncated_input() {
        assert!(unwrap_der_signature(&[0x30, 0x06]).is_err());
    }

    #[test]
    fn unwrap_round_trips_real_der_signature() {
        // Use the p256 crate's DER export to round-trip a real signature.
        use p256::ecdsa::Signature;
        use p256::ecdsa::signature::hazmat::PrehashSigner;

        let kp = P256KeyPair::generate();
        let signing_key = p256::ecdsa::SigningKey::from_slice(&kp.secret_bytes()).unwrap();
        let sig: Signature = signing_key.sign_prehash(&[1u8; 32]).unwrap();
        let der = sig.to_der();
        let unwrapped = unwrap_der_signature(der.as_bytes()).unwrap();
        let raw = sig.to_bytes();
        assert_eq!(unwrapped, *raw.as_slice());
    }

    #[test]
    fn signed_hash_matches_payload_then_sha256() {
        let auth_data = vec![0xAAu8; 37];
        let cdj =
            br#"{"type":"webauthn.get","challenge":"abc","origin":"https://keys.tenzro.xyz"}"#
                .to_vec();
        let payload = webauthn_signed_payload(&auth_data, &cdj);
        let direct_hash: [u8; 32] = Sha256::digest(&payload).into();
        let helper_hash = webauthn_signed_hash(&auth_data, &cdj);
        assert_eq!(direct_hash, helper_hash);
    }

    #[test]
    fn verify_assertion_round_trip() {
        // Build a minimal valid assertion from a fresh P-256 key, then
        // verify it through the public API.
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);

        let cdj = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTAx","origin":"https://keys.tenzro.xyz","crossOrigin":false}"#.to_vec();

        // authenticatorData: 32 bytes rpIdHash + 1 byte flags (UP set) +
        // 4 bytes signCount.
        let mut auth_data = vec![0u8; 32];
        auth_data.push(AUTH_DATA_FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());

        let prehash = webauthn_signed_hash(&auth_data, &cdj);
        let sig = signer.sign_prehash(&prehash);

        let assertion = WebAuthnAssertion {
            authenticator_data: auth_data,
            client_data_json: cdj,
            signature: sig.as_bytes().to_vec(),
            user_handle: None,
        };

        verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &WebAuthnRelyingParty::Origin("https://keys.tenzro.xyz".to_string()),
            WebAuthnCeremonyType::Get,
        )
        .unwrap();
    }

    #[test]
    fn verify_assertion_rejects_origin_mismatch() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let cdj = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTAx","origin":"https://attacker.example","crossOrigin":false}"#.to_vec();
        let mut auth_data = vec![0u8; 32];
        auth_data.push(AUTH_DATA_FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let prehash = webauthn_signed_hash(&auth_data, &cdj);
        let sig = signer.sign_prehash(&prehash);

        let assertion = WebAuthnAssertion {
            authenticator_data: auth_data,
            client_data_json: cdj,
            signature: sig.as_bytes().to_vec(),
            user_handle: None,
        };

        let res = verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &WebAuthnRelyingParty::Origin("https://keys.tenzro.xyz".to_string()),
            WebAuthnCeremonyType::Get,
        );
        assert!(matches!(res, Err(CryptoError::InvalidSignature(_))));
    }

    #[test]
    fn verify_assertion_rejects_challenge_mismatch() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let cdj = br#"{"type":"webauthn.get","challenge":"d3JvbmctY2hhbGxlbmdl","origin":"https://keys.tenzro.xyz"}"#.to_vec();
        let mut auth_data = vec![0u8; 32];
        auth_data.push(AUTH_DATA_FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let prehash = webauthn_signed_hash(&auth_data, &cdj);
        let sig = signer.sign_prehash(&prehash);

        let assertion = WebAuthnAssertion {
            authenticator_data: auth_data,
            client_data_json: cdj,
            signature: sig.as_bytes().to_vec(),
            user_handle: None,
        };

        let res = verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &WebAuthnRelyingParty::Origin("https://keys.tenzro.xyz".to_string()),
            WebAuthnCeremonyType::Get,
        );
        assert!(matches!(res, Err(CryptoError::InvalidSignature(_))));
    }

    #[test]
    fn verify_assertion_rejects_missing_user_present_flag() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let cdj = br#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdlLTAx","origin":"https://keys.tenzro.xyz"}"#.to_vec();
        let mut auth_data = vec![0u8; 32];
        auth_data.push(0); // UP flag NOT set
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let prehash = webauthn_signed_hash(&auth_data, &cdj);
        let sig = signer.sign_prehash(&prehash);

        let assertion = WebAuthnAssertion {
            authenticator_data: auth_data,
            client_data_json: cdj,
            signature: sig.as_bytes().to_vec(),
            user_handle: None,
        };

        let res = verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &WebAuthnRelyingParty::Origin("https://keys.tenzro.xyz".to_string()),
            WebAuthnCeremonyType::Get,
        );
        assert!(matches!(res, Err(CryptoError::InvalidSignature(_))));
    }

    #[test]
    fn verify_assertion_rejects_type_mismatch() {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        // type says webauthn.create but caller expects webauthn.get
        let cdj = br#"{"type":"webauthn.create","challenge":"Y2hhbGxlbmdlLTAx","origin":"https://keys.tenzro.xyz"}"#.to_vec();
        let mut auth_data = vec![0u8; 32];
        auth_data.push(AUTH_DATA_FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());
        let prehash = webauthn_signed_hash(&auth_data, &cdj);
        let sig = signer.sign_prehash(&prehash);

        let assertion = WebAuthnAssertion {
            authenticator_data: auth_data,
            client_data_json: cdj,
            signature: sig.as_bytes().to_vec(),
            user_handle: None,
        };

        let res = verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &WebAuthnRelyingParty::Origin("https://keys.tenzro.xyz".to_string()),
            WebAuthnCeremonyType::Get,
        );
        assert!(matches!(res, Err(CryptoError::InvalidSignature(_))));
    }

    /// Builds a `(assertion, public_key)` pair whose `authenticatorData`
    /// carries `sha256(rp_id)` as its rpIdHash — what a real authenticator
    /// would commit to for a `create()`/`get()` scoped to that RP ID.
    fn build_assertion_for_rp_id(
        rp_id: &str,
        origin: &str,
        challenge_b64url: &str,
    ) -> (WebAuthnAssertion, P256KeyPair) {
        let kp = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&kp);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_b64url}","origin":"{origin}"}}"#
        )
        .into_bytes();

        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(AUTH_DATA_FLAG_UP);
        auth_data.extend_from_slice(&0u32.to_be_bytes());

        let prehash = webauthn_signed_hash(&auth_data, &cdj);
        let sig = signer.sign_prehash(&prehash);

        (
            WebAuthnAssertion {
                authenticator_data: auth_data,
                client_data_json: cdj,
                signature: sig.as_bytes().to_vec(),
                user_handle: None,
            },
            kp,
        )
    }

    #[test]
    fn registrable_domain_accepts_any_subdomain_of_rp_id() {
        let rp = WebAuthnRelyingParty::RegistrableDomain {
            rp_id: "network.tenzro.com".to_string(),
        };
        // A credential minted while onboarding one node...
        let (assertion, kp) = build_assertion_for_rp_id(
            "network.tenzro.com",
            "https://alice.network.tenzro.com",
            "Y2hhbGxlbmdlLTAx",
        );
        // ...verifies against an assertion presented from a *different* node
        // under the same RP ID — the whole point of the fix.
        verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &rp,
            WebAuthnCeremonyType::Get,
        )
        .unwrap();

        let (assertion2, kp2) = build_assertion_for_rp_id(
            "network.tenzro.com",
            "https://bob.network.tenzro.com",
            "Y2hhbGxlbmdlLTAx",
        );
        verify_webauthn_assertion(
            &assertion2,
            &kp2.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &rp,
            WebAuthnCeremonyType::Get,
        )
        .unwrap();
    }

    #[test]
    fn registrable_domain_rejects_origin_outside_the_domain() {
        let rp = WebAuthnRelyingParty::RegistrableDomain {
            rp_id: "network.tenzro.com".to_string(),
        };
        let (assertion, kp) = build_assertion_for_rp_id(
            "network.tenzro.com",
            "https://attacker.example",
            "Y2hhbGxlbmdlLTAx",
        );
        let res = verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &rp,
            WebAuthnCeremonyType::Get,
        );
        assert!(matches!(res, Err(CryptoError::InvalidSignature(_))));
    }

    #[test]
    fn registrable_domain_rejects_suffix_lookalike() {
        // "evilnetwork.tenzro.com" ends with "network.tenzro.com" as a raw
        // string but is not a subdomain of it — the dot-prefixed suffix
        // check must reject this, not a bare `ends_with`.
        let rp = WebAuthnRelyingParty::RegistrableDomain {
            rp_id: "network.tenzro.com".to_string(),
        };
        let (assertion, kp) = build_assertion_for_rp_id(
            "network.tenzro.com",
            "https://evilnetwork.tenzro.com",
            "Y2hhbGxlbmdlLTAx",
        );
        let res = verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &rp,
            WebAuthnCeremonyType::Get,
        );
        assert!(matches!(res, Err(CryptoError::InvalidSignature(_))));
    }

    #[test]
    fn registrable_domain_rejects_rp_id_hash_mismatch() {
        // Origin is within the domain, but the authenticator committed to a
        // different RP ID than configured — the rpIdHash check must catch
        // this even though the origin-string check alone would pass.
        let rp = WebAuthnRelyingParty::RegistrableDomain {
            rp_id: "network.tenzro.com".to_string(),
        };
        let (assertion, kp) = build_assertion_for_rp_id(
            "some-other-rp-id.example",
            "https://alice.network.tenzro.com",
            "Y2hhbGxlbmdlLTAx",
        );
        let res = verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &rp,
            WebAuthnCeremonyType::Get,
        );
        assert!(matches!(res, Err(CryptoError::InvalidSignature(_))));
    }

    #[test]
    fn registrable_domain_rejects_non_https_origin() {
        let rp = WebAuthnRelyingParty::RegistrableDomain {
            rp_id: "network.tenzro.com".to_string(),
        };
        let (assertion, kp) = build_assertion_for_rp_id(
            "network.tenzro.com",
            "http://alice.network.tenzro.com",
            "Y2hhbGxlbmdlLTAx",
        );
        let res = verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &rp,
            WebAuthnCeremonyType::Get,
        );
        assert!(matches!(res, Err(CryptoError::InvalidSignature(_))));
    }

    #[test]
    fn registrable_domain_allows_http_localhost_for_dev() {
        let rp = WebAuthnRelyingParty::RegistrableDomain {
            rp_id: "localhost".to_string(),
        };
        let (assertion, kp) =
            build_assertion_for_rp_id("localhost", "http://localhost:8080", "Y2hhbGxlbmdlLTAx");
        verify_webauthn_assertion(
            &assertion,
            &kp.public_key_bytes(),
            "Y2hhbGxlbmdlLTAx",
            &rp,
            WebAuthnCeremonyType::Get,
        )
        .unwrap();
    }
}
