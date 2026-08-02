//! RFC 9421 HTTP Message Signature implementation
//!
//! Provides parsing, creation, and verification of HTTP message signatures
//! as defined in RFC 9421.
//!
//! # Algorithm coverage
//!
//! All RFC 9421 §3.3 algorithms are supported:
//!
//! - `ed25519` — Ed25519 (RFC 8032), via [`tenzro_crypto`]
//! - `ecdsa-p256-sha256` — ECDSA over NIST P-256 with SHA-256, via [`p256`]
//! - `ecdsa-p384-sha384` — ECDSA over NIST P-384 with SHA-384, via [`p384`]
//! - `rsa-pss-sha512` — RSASSA-PSS with SHA-512, MGF1-SHA-512, salt length = hash length, via [`rsa`]
//! - `rsa-pss-sha256` — RSASSA-PSS with SHA-256, MGF1-SHA-256, salt length = hash length
//! - `rsa-v1_5-sha256` — RSASSA-PKCS1-v1_5 with SHA-256
//! - `hmac-sha256` — HMAC-SHA-256 (symmetric)
//!
//! Public-key formats: ECDSA keys accept SubjectPublicKeyInfo DER (preferred) or
//! raw uncompressed SEC1 (`0x04 || X || Y`). RSA keys accept SPKI DER. Ed25519
//! accepts raw 32-byte public key bytes (matching `tenzro_crypto`).
//!
//! # Canonicalization (§2.1)
//!
//! Field values are normalized by stripping ASCII leading/trailing whitespace and
//! collapsing internal CR/LF + leading-whitespace runs into a single space, per
//! §2.1.1. This is a pragmatic subset of RFC 8941 Structured Field handling;
//! Structured Field re-serialization is not yet performed.
//!
//! # Derived components (§2.2)
//!
//! All HTTP request derived components defined in §2.2 are recognized:
//! `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`,
//! `@query`, `@query-param`. (`@status` is response-only and recognized but
//! requires the verifier to populate `RequestParts::status`.)

use crate::error::{PaymentError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tenzro_crypto::keys::{KeyPair, KeyType, PublicKey};
use tenzro_crypto::signatures::{
    Ed25519SignerImpl, Ed25519VerifierImpl, Signature, Signer, Verifier,
};
use tracing::debug;

use sha2::{Digest, Sha256, Sha512};
// `signature` 3.x is implemented by `ecdsa` 0.17-rc.18 (k256/p256/p384). The
// older `signature` 2.x is what `rsa` 0.9 still implements. Both versions ship
// the same trait names (`Signer`, `Verifier`, `RandomizedSigner`) and the
// trait scope is decided at the call site — alias each version explicitly so
// the resolver picks the right one per algorithm family.
use signature::{Signer as Sigv3Signer, Verifier as Sigv3Verifier};
use signature_v2::{Signer as Sigv2Signer, Verifier as Sigv2Verifier};
use subtle::ConstantTimeEq;

/// Supported RFC 9421 signature algorithms (§3.3 + the algorithm registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032).
    Ed25519,
    /// ECDSA over NIST P-256 with SHA-256.
    #[serde(rename = "ecdsa-p256-sha256")]
    EcdsaP256Sha256,
    /// ECDSA over NIST P-384 with SHA-384.
    #[serde(rename = "ecdsa-p384-sha384")]
    EcdsaP384Sha384,
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256, salt length = hash length.
    #[serde(rename = "rsa-pss-sha256")]
    RsaPssSha256,
    /// RSASSA-PSS with SHA-512, MGF1-SHA-512, salt length = hash length.
    #[serde(rename = "rsa-pss-sha512")]
    RsaPssSha512,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    #[serde(rename = "rsa-v1_5-sha256")]
    RsaV15Sha256,
    /// HMAC-SHA-256 (symmetric).
    #[serde(rename = "hmac-sha256")]
    HmacSha256,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl SignatureAlgorithm {
    /// Parse algorithm from its RFC 9421 string identifier.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ed25519" => Ok(SignatureAlgorithm::Ed25519),
            "ecdsa-p256-sha256" => Ok(SignatureAlgorithm::EcdsaP256Sha256),
            "ecdsa-p384-sha384" => Ok(SignatureAlgorithm::EcdsaP384Sha384),
            "rsa-pss-sha256" => Ok(SignatureAlgorithm::RsaPssSha256),
            "rsa-pss-sha512" => Ok(SignatureAlgorithm::RsaPssSha512),
            "rsa-v1_5-sha256" | "rsa-v1.5-sha256" => Ok(SignatureAlgorithm::RsaV15Sha256),
            "hmac-sha256" => Ok(SignatureAlgorithm::HmacSha256),
            _ => Err(PaymentError::Rfc9421Error(format!(
                "unsupported algorithm: {}",
                s
            ))),
        }
    }

    /// RFC 9421 string identifier for this algorithm.
    pub fn as_str(&self) -> &str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            SignatureAlgorithm::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            SignatureAlgorithm::RsaPssSha256 => "rsa-pss-sha256",
            SignatureAlgorithm::RsaPssSha512 => "rsa-pss-sha512",
            SignatureAlgorithm::RsaV15Sha256 => "rsa-v1_5-sha256",
            SignatureAlgorithm::HmacSha256 => "hmac-sha256",
        }
    }

    /// Whether the algorithm is asymmetric (public-key) or symmetric (HMAC).
    pub fn is_symmetric(&self) -> bool {
        matches!(self, SignatureAlgorithm::HmacSha256)
    }
}

/// Signature parameters from RFC 9421 §2.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureParams {
    /// Signature label.
    pub label: String,
    /// Unix timestamp when signature was created.
    pub created: Option<u64>,
    /// Unix timestamp when signature expires.
    pub expires: Option<u64>,
    /// Unique nonce for replay protection.
    pub nonce: Option<String>,
    /// Key identifier.
    pub keyid: String,
    /// Signature algorithm.
    pub alg: SignatureAlgorithm,
    /// Optional tag for additional context.
    pub tag: Option<String>,
}

/// Parsed signature input from a `Signature-Input` header.
#[derive(Debug, Clone)]
pub struct SignatureInput {
    /// Signature label.
    pub label: String,
    /// Covered components, e.g. `"@method"`, `"@path"`, `"content-type"`.
    pub covered_components: Vec<String>,
    /// Signature parameters.
    pub params: SignatureParams,
}

/// HTTP request parts needed for signature verification.
///
/// `query` is the raw query string without the leading `?` (or empty), as
/// required by `@query` (§2.2.7) and `@query-param` (§2.2.8). `scheme` is
/// `http`/`https`. `status` is only set on response signatures.
#[derive(Debug, Clone)]
pub struct RequestParts {
    /// HTTP method (e.g., "GET", "POST").
    pub method: String,
    /// Authority (host:port).
    pub authority: String,
    /// Request path, including any encoded characters but not the query.
    pub path: String,
    /// Raw query string (no leading `?`); empty if absent.
    pub query: String,
    /// URI scheme (`http` / `https`).
    pub scheme: String,
    /// HTTP response status code, if signing/verifying a response.
    pub status: Option<u16>,
    /// HTTP headers (lowercase keys).
    pub headers: HashMap<String, String>,
}

impl RequestParts {
    /// Construct a request-side `RequestParts` with default `https` scheme and empty query.
    pub fn for_request(
        method: impl Into<String>,
        authority: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            authority: authority.into(),
            path: path.into(),
            query: String::new(),
            scheme: "https".to_string(),
            status: None,
            headers: HashMap::new(),
        }
    }

    /// Set the query string (no leading `?`).
    pub fn with_query(mut self, q: impl Into<String>) -> Self {
        self.query = q.into();
        self
    }

    /// Set the URI scheme.
    pub fn with_scheme(mut self, s: impl Into<String>) -> Self {
        self.scheme = s.into();
        self
    }

    /// Set a single header (key is lowercased).
    pub fn with_header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.headers.insert(k.into().to_ascii_lowercase(), v.into());
        self
    }

    /// Mark this as a response signing context with the given status code.
    pub fn with_status(mut self, code: u16) -> Self {
        self.status = Some(code);
        self
    }
}

/// Signed HTTP headers ready to be passed to [`verify_http_signature`].
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// Raw `Signature-Input` header value (for diagnostics/logging).
    pub signature_input_raw: String,
    /// Base64-decoded signature bytes.
    pub signature_bytes: Vec<u8>,
    /// Parsed signature input.
    pub parsed: SignatureInput,
}

// ---------------------------------------------------------------------------
// Header parsing (§4.1)
// ---------------------------------------------------------------------------

/// Parse a `Signature-Input` header value (§4.1).
///
/// Format:
/// ```text
/// sig1=("@authority" "@path" "content-type");created=1701234567;nonce="abc123";keyid="agent_key_001";alg="ed25519";tag="agent-browser-auth"
/// ```
///
/// `sf` and `bs` parameter modifiers on covered components (e.g. `"x-list";sf`)
/// are accepted at the parser level; downstream `build_signature_base` does not
/// yet apply them.
pub fn parse_signature_input(header: &str) -> Result<SignatureInput> {
    let eq_pos = header
        .find('=')
        .ok_or_else(|| PaymentError::Rfc9421Error("missing '=' in Signature-Input".to_string()))?;

    let label = header[..eq_pos].trim().to_string();
    let rest = &header[eq_pos + 1..];

    let paren_start = rest
        .find('(')
        .ok_or_else(|| PaymentError::Rfc9421Error("missing '(' in Signature-Input".to_string()))?;
    let paren_end = rest
        .find(')')
        .ok_or_else(|| PaymentError::Rfc9421Error("missing ')' in Signature-Input".to_string()))?;
    if paren_end < paren_start {
        return Err(PaymentError::Rfc9421Error(
            "malformed Signature-Input: ')' before '('".to_string(),
        ));
    }

    let components_str = &rest[paren_start + 1..paren_end];
    // Components are space-separated quoted strings. Modifiers (`;sf`, `;bs`,
    // `;name="x"`, `;key="y"`) are parameters on each component — keep them
    // attached to the component string so the canonicalizer sees them.
    let covered_components: Vec<String> = parse_inner_list(components_str);

    let params_str = &rest[paren_end + 1..];
    let mut created = None;
    let mut expires = None;
    let mut nonce = None;
    let mut keyid = String::new();
    let mut alg = None;
    let mut tag = None;

    for part in params_str.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');

            match key {
                "created" => {
                    created = Some(value.parse::<u64>().map_err(|_| {
                        PaymentError::Rfc9421Error("invalid created timestamp".to_string())
                    })?);
                }
                "expires" => {
                    expires = Some(value.parse::<u64>().map_err(|_| {
                        PaymentError::Rfc9421Error("invalid expires timestamp".to_string())
                    })?);
                }
                "nonce" => {
                    nonce = Some(value.to_string());
                }
                "keyid" => {
                    keyid = value.to_string();
                }
                "alg" => {
                    alg = Some(SignatureAlgorithm::from_str(value)?);
                }
                "tag" => {
                    tag = Some(value.to_string());
                }
                _ => {
                    debug!("Unknown signature parameter: {}", key);
                }
            }
        }
    }

    if keyid.is_empty() {
        return Err(PaymentError::Rfc9421Error(
            "missing required parameter: keyid".to_string(),
        ));
    }

    let alg = alg
        .ok_or_else(|| PaymentError::Rfc9421Error("missing required parameter: alg".to_string()))?;

    Ok(SignatureInput {
        label: label.clone(),
        covered_components,
        params: SignatureParams {
            label,
            created,
            expires,
            nonce,
            keyid,
            alg,
            tag,
        },
    })
}

/// Parse the inner list of covered components.
///
/// Each entry is `"name"` optionally followed by `;param[=value]` modifiers.
/// We preserve the modifiers verbatim on the component string so that
/// `build_signature_base` can interpret them per §2.1.3.
fn parse_inner_list(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '"' {
            in_quotes = !in_quotes;
            buf.push(c);
        } else if c.is_whitespace() && !in_quotes {
            if !buf.is_empty() {
                out.push(buf.trim_matches('"').to_string());
                buf.clear();
            }
        } else {
            buf.push(c);
        }
        i += 1;
    }
    if !buf.is_empty() {
        out.push(buf.trim_matches('"').to_string());
    }
    out
}

// ---------------------------------------------------------------------------
// Signature base (§2.5)
// ---------------------------------------------------------------------------

/// Build the canonical signature base string per RFC 9421 §2.5.
pub fn build_signature_base(
    request_parts: &RequestParts,
    input: &SignatureInput,
) -> Result<String> {
    let mut lines = Vec::with_capacity(input.covered_components.len() + 1);

    for component in &input.covered_components {
        let line = canonicalize_component(component, request_parts)?;
        lines.push(line);
    }

    let components_list: Vec<String> = input
        .covered_components
        .iter()
        .map(|c| component_for_signature_params(c))
        .collect();

    let mut params_parts = vec![format!("({})", components_list.join(" "))];

    if let Some(created) = input.params.created {
        params_parts.push(format!("created={}", created));
    }
    if let Some(expires) = input.params.expires {
        params_parts.push(format!("expires={}", expires));
    }
    if let Some(ref nonce) = input.params.nonce {
        params_parts.push(format!("nonce=\"{}\"", nonce));
    }
    params_parts.push(format!("keyid=\"{}\"", input.params.keyid));
    params_parts.push(format!("alg=\"{}\"", input.params.alg.as_str()));
    if let Some(ref tag) = input.params.tag {
        params_parts.push(format!("tag=\"{}\"", tag));
    }

    lines.push(format!("\"@signature-params\": {}", params_parts.join(";")));

    Ok(lines.join("\n"))
}

/// Render a covered component back to the form it appears inside the
/// `("...")` list of `@signature-params`. Modifiers are preserved with their
/// surrounding quotes around the bare name only.
fn component_for_signature_params(raw: &str) -> String {
    // Split the component name from any modifiers (`;sf`, `;name="x"`, etc.).
    if let Some((name, rest)) = raw.split_once(';') {
        let name_lower = name.trim().to_ascii_lowercase();
        format!("\"{}\";{}", name_lower, rest)
    } else {
        format!("\"{}\"", raw.to_ascii_lowercase())
    }
}

/// Canonicalize a single covered component into a `"name": value` line.
fn canonicalize_component(raw: &str, parts: &RequestParts) -> Result<String> {
    // Component may carry parameters: `"x-list";sf`, `@query-param;name="q"`.
    let (name, params) = split_component(raw);
    let name_lower = name.to_ascii_lowercase();

    let value: String = if let Some(stripped) = name_lower.strip_prefix('@') {
        derived_component_value(stripped, &params, parts)?
    } else {
        // Regular HTTP field. We don't yet support `bs` (binary-wrapped) or
        // re-serialized Structured Field rendering — values are looked up and
        // run through field-value canonicalization (§2.1.1).
        let raw_val = parts
            .headers
            .get(&name_lower)
            .ok_or_else(|| PaymentError::Rfc9421Error(format!("missing header: {}", name_lower)))?;
        canonicalize_field_value(raw_val)
    };

    if params.is_empty() {
        Ok(format!("\"{}\": {}", name_lower, value))
    } else {
        // Render parameters back into the line per §2.1.3.
        let rendered_params: Vec<String> = params
            .iter()
            .map(|(k, v)| match v {
                Some(val) => format!("{}={}", k, val),
                None => k.clone(),
            })
            .collect();
        Ok(format!(
            "\"{}\";{}: {}",
            name_lower,
            rendered_params.join(";"),
            value
        ))
    }
}

/// Split a covered-component string `name[;p1[=v1][;p2[=v2]...]]` into its
/// name and (param, value) tuples. The name is returned with its surrounding
/// quotes stripped.
fn split_component(raw: &str) -> (String, Vec<(String, Option<String>)>) {
    let raw = raw.trim();
    if let Some((name, rest)) = raw.split_once(';') {
        let mut params = Vec::new();
        for part in rest.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((k, v)) = part.split_once('=') {
                params.push((k.trim().to_ascii_lowercase(), Some(v.trim().to_string())));
            } else {
                params.push((part.to_ascii_lowercase(), None));
            }
        }
        (name.trim().trim_matches('"').to_string(), params)
    } else {
        (raw.trim_matches('"').to_string(), Vec::new())
    }
}

/// Resolve a derived component (`@method`, `@authority`, etc.) per §2.2.
fn derived_component_value(
    name: &str,
    params: &[(String, Option<String>)],
    parts: &RequestParts,
) -> Result<String> {
    match name {
        "method" => Ok(parts.method.to_ascii_uppercase()),
        "authority" => Ok(parts.authority.to_ascii_lowercase()),
        "scheme" => Ok(parts.scheme.to_ascii_lowercase()),
        "path" => Ok(parts.path.clone()),
        "query" => Ok(if parts.query.is_empty() {
            "?".to_string()
        } else {
            format!("?{}", parts.query)
        }),
        "request-target" => {
            // §2.2.5: the request target as on the request line. We use the
            // origin form: path[?query].
            if parts.query.is_empty() {
                Ok(parts.path.clone())
            } else {
                Ok(format!("{}?{}", parts.path, parts.query))
            }
        }
        "target-uri" => {
            // §2.2.2: scheme://authority + path?query.
            let mut uri = format!("{}://{}{}", parts.scheme, parts.authority, parts.path);
            if !parts.query.is_empty() {
                uri.push('?');
                uri.push_str(&parts.query);
            }
            Ok(uri)
        }
        "query-param" => {
            // §2.2.8 — requires a `name` parameter; emit the (URL-decoded)
            // value of that single parameter.
            let key = params
                .iter()
                .find(|(k, _)| k == "name")
                .and_then(|(_, v)| v.as_ref())
                .ok_or_else(|| {
                    PaymentError::Rfc9421Error("@query-param requires `name` parameter".to_string())
                })?;
            let key = key.trim_matches('"');
            let decoded = find_query_param(&parts.query, key).ok_or_else(|| {
                PaymentError::Rfc9421Error(format!("query parameter {} not found", key))
            })?;
            Ok(decoded)
        }
        "status" => {
            let code = parts.status.ok_or_else(|| {
                PaymentError::Rfc9421Error(
                    "@status requested but RequestParts.status is None".to_string(),
                )
            })?;
            Ok(code.to_string())
        }
        other => Err(PaymentError::Rfc9421Error(format!(
            "unknown derived component: @{}",
            other
        ))),
    }
}

/// Find a query parameter by name, returning the (still URL-encoded) value.
fn find_query_param(query: &str, key: &str) -> Option<String> {
    if query.is_empty() {
        return None;
    }
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

/// Canonicalize an HTTP field value per §2.1.1.
///
/// - Strip leading/trailing whitespace.
/// - Replace any `\r\n` followed by whitespace (continuation lines) with a single space.
/// - Collapse runs of internal whitespace to a single space.
fn canonicalize_field_value(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    let mut in_ws = false;
    for ch in raw.chars() {
        if ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ' {
            if !in_ws && !s.is_empty() {
                s.push(' ');
                in_ws = true;
            }
        } else {
            s.push(ch);
            in_ws = false;
        }
    }
    s.trim().to_string()
}

// ---------------------------------------------------------------------------
// Verification (§3.2)
// ---------------------------------------------------------------------------

/// Verify an HTTP message signature against the supplied public key.
///
/// For HMAC, `public_key_bytes` is the shared secret.
pub fn verify_http_signature(
    request_parts: &RequestParts,
    signed_headers: &SignedHeaders,
    public_key_bytes: &[u8],
    algorithm: &SignatureAlgorithm,
) -> Result<()> {
    let signature_base = build_signature_base(request_parts, &signed_headers.parsed)?;
    let sig_bytes = &signed_headers.signature_bytes;

    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            verify_ed25519(public_key_bytes, signature_base.as_bytes(), sig_bytes)
        }
        SignatureAlgorithm::EcdsaP256Sha256 => {
            verify_ecdsa_p256(public_key_bytes, signature_base.as_bytes(), sig_bytes)
        }
        SignatureAlgorithm::EcdsaP384Sha384 => {
            verify_ecdsa_p384(public_key_bytes, signature_base.as_bytes(), sig_bytes)
        }
        SignatureAlgorithm::RsaPssSha256 => {
            verify_rsa_pss::<Sha256>(public_key_bytes, signature_base.as_bytes(), sig_bytes)
        }
        SignatureAlgorithm::RsaPssSha512 => {
            verify_rsa_pss::<Sha512>(public_key_bytes, signature_base.as_bytes(), sig_bytes)
        }
        SignatureAlgorithm::RsaV15Sha256 => {
            verify_rsa_pkcs1v15(public_key_bytes, signature_base.as_bytes(), sig_bytes)
        }
        SignatureAlgorithm::HmacSha256 => {
            verify_hmac_sha256(public_key_bytes, signature_base.as_bytes(), sig_bytes)
        }
    }
}

/// Create an HTTP message signature with the supplied private key (or HMAC secret).
pub fn create_http_signature(
    request_parts: &RequestParts,
    input: &SignatureInput,
    private_key_bytes: &[u8],
    algorithm: &SignatureAlgorithm,
) -> Result<Vec<u8>> {
    let signature_base = build_signature_base(request_parts, input)?;
    let msg = signature_base.as_bytes();

    match algorithm {
        SignatureAlgorithm::Ed25519 => sign_ed25519(private_key_bytes, msg),
        SignatureAlgorithm::EcdsaP256Sha256 => sign_ecdsa_p256(private_key_bytes, msg),
        SignatureAlgorithm::EcdsaP384Sha384 => sign_ecdsa_p384(private_key_bytes, msg),
        SignatureAlgorithm::RsaPssSha256 => sign_rsa_pss::<Sha256>(private_key_bytes, msg),
        SignatureAlgorithm::RsaPssSha512 => sign_rsa_pss::<Sha512>(private_key_bytes, msg),
        SignatureAlgorithm::RsaV15Sha256 => sign_rsa_pkcs1v15(private_key_bytes, msg),
        SignatureAlgorithm::HmacSha256 => sign_hmac_sha256(private_key_bytes, msg),
    }
}

// ----- Ed25519 -----

fn verify_ed25519(public_key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let pk = PublicKey::new(KeyType::Ed25519, public_key_bytes.to_vec());
    let sig = Signature::new(KeyType::Ed25519, sig_bytes.to_vec());
    let verifier = Ed25519VerifierImpl::new(pk)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid Ed25519 public key: {}", e)))?;
    verifier.verify(msg, &sig).map_err(|e| {
        PaymentError::Rfc9421Error(format!("Ed25519 signature verification failed: {}", e))
    })?;
    Ok(())
}

fn sign_ed25519(private_key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let keypair = KeyPair::from_bytes(KeyType::Ed25519, private_key_bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid Ed25519 private key: {}", e)))?;
    let signer = Ed25519SignerImpl::new(keypair).map_err(|e| {
        PaymentError::Rfc9421Error(format!("Ed25519 signer creation failed: {}", e))
    })?;
    let signature = signer
        .sign(msg)
        .map_err(|e| PaymentError::Rfc9421Error(format!("Ed25519 signing failed: {}", e)))?;
    Ok(signature.to_bytes())
}

// ----- ECDSA P-256 / P-384 -----

fn verify_ecdsa_p256(public_key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256Vk};
    let vk = parse_p256_verifying_key(public_key_bytes)?;
    let sig = P256Sig::from_slice(sig_bytes)
        .or_else(|_| P256Sig::from_der(sig_bytes))
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid P-256 signature: {}", e)))?;
    let _ = vk; // silence if both branches fail
    let vk2: P256Vk = parse_p256_verifying_key(public_key_bytes)?;
    Sigv3Verifier::verify(&vk2, msg, &sig).map_err(|e| {
        PaymentError::Rfc9421Error(format!("P-256 signature verification failed: {}", e))
    })?;
    Ok(())
}

fn parse_p256_verifying_key(bytes: &[u8]) -> Result<p256::ecdsa::VerifyingKey> {
    use p256::ecdsa::VerifyingKey;
    use p256::pkcs8::DecodePublicKey;

    // Try SPKI DER first.
    if let Ok(vk) = VerifyingKey::from_public_key_der(bytes) {
        return Ok(vk);
    }
    // Fall back to raw SEC1 (uncompressed: 0x04 || X || Y, 65 bytes).
    VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid P-256 public key: {}", e)))
}

fn sign_ecdsa_p256(private_key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use p256::ecdsa::Signature as P256Sig;
    let sk = parse_p256_signing_key(private_key_bytes)?;
    let sig: P256Sig = Sigv3Signer::sign(&sk, msg);
    Ok(sig.to_bytes().to_vec())
}

fn parse_p256_signing_key(bytes: &[u8]) -> Result<p256::ecdsa::SigningKey> {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::DecodePrivateKey;

    if let Ok(sk) = SigningKey::from_pkcs8_der(bytes) {
        return Ok(sk);
    }
    SigningKey::from_slice(bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid P-256 private key: {}", e)))
}

fn verify_ecdsa_p384(public_key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    use p384::ecdsa::{Signature as P384Sig, VerifyingKey as P384Vk};
    let vk: P384Vk = parse_p384_verifying_key(public_key_bytes)?;
    let sig = P384Sig::from_slice(sig_bytes)
        .or_else(|_| P384Sig::from_der(sig_bytes))
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid P-384 signature: {}", e)))?;
    Sigv3Verifier::verify(&vk, msg, &sig).map_err(|e| {
        PaymentError::Rfc9421Error(format!("P-384 signature verification failed: {}", e))
    })?;
    Ok(())
}

fn parse_p384_verifying_key(bytes: &[u8]) -> Result<p384::ecdsa::VerifyingKey> {
    use p384::ecdsa::VerifyingKey;
    use p384::pkcs8::DecodePublicKey;

    if let Ok(vk) = VerifyingKey::from_public_key_der(bytes) {
        return Ok(vk);
    }
    VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid P-384 public key: {}", e)))
}

fn sign_ecdsa_p384(private_key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use p384::ecdsa::Signature as P384Sig;
    let sk = parse_p384_signing_key(private_key_bytes)?;
    let sig: P384Sig = Sigv3Signer::sign(&sk, msg);
    Ok(sig.to_bytes().to_vec())
}

fn parse_p384_signing_key(bytes: &[u8]) -> Result<p384::ecdsa::SigningKey> {
    use p384::ecdsa::SigningKey;
    use p384::pkcs8::DecodePrivateKey;

    if let Ok(sk) = SigningKey::from_pkcs8_der(bytes) {
        return Ok(sk);
    }
    SigningKey::from_slice(bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid P-384 private key: {}", e)))
}

// ----- RSA-PSS / RSA-PKCS#1 v1.5 -----

fn verify_rsa_pss<H>(public_key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()>
where
    H: Digest + sha2::digest::FixedOutputReset + sha2::digest::const_oid::AssociatedOid,
{
    use rsa::RsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::pss::{Signature as PssSig, VerifyingKey as PssVk};

    let pk = RsaPublicKey::from_public_key_der(public_key_bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid RSA public key (DER): {}", e)))?;
    let vk: PssVk<H> = PssVk::<H>::new(pk);
    let sig = PssSig::try_from(sig_bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid RSA-PSS signature: {}", e)))?;
    // rsa 0.9 impls the `signature` 2.x `Verifier` — use the v2 alias.
    Sigv2Verifier::verify(&vk, msg, &sig).map_err(|e| {
        PaymentError::Rfc9421Error(format!("RSA-PSS signature verification failed: {}", e))
    })?;
    Ok(())
}

fn sign_rsa_pss<H>(private_key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>>
where
    H: Digest + sha2::digest::FixedOutputReset + sha2::digest::const_oid::AssociatedOid,
{
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pss::{Signature as PssSig, SigningKey as PssSk};
    // rsa 0.9 impls `signature` 2.x's `RandomizedSigner` (not v3).
    use signature_v2::RandomizedSigner;

    let sk = RsaPrivateKey::from_pkcs8_der(private_key_bytes).map_err(|e| {
        PaymentError::Rfc9421Error(format!("invalid RSA private key (PKCS#8 DER): {}", e))
    })?;
    let signing_key: PssSk<H> = PssSk::<H>::new(sk);
    let sig: PssSig = signing_key.sign_with_rng(&mut OsRng, msg);
    Ok(<PssSig as Into<Box<[u8]>>>::into(sig).to_vec())
}

fn verify_rsa_pkcs1v15(public_key_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    use rsa::RsaPublicKey;
    use rsa::pkcs1v15::{Signature as Pkcs1Sig, VerifyingKey as Pkcs1Vk};
    use rsa::pkcs8::DecodePublicKey;

    let pk = RsaPublicKey::from_public_key_der(public_key_bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid RSA public key (DER): {}", e)))?;
    let vk: Pkcs1Vk<Sha256> = Pkcs1Vk::<Sha256>::new(pk);
    let sig = Pkcs1Sig::try_from(sig_bytes)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid RSA-v1.5 signature: {}", e)))?;
    // rsa 0.9 impls the `signature` 2.x `Verifier` — use the v2 alias.
    Sigv2Verifier::verify(&vk, msg, &sig).map_err(|e| {
        PaymentError::Rfc9421Error(format!("RSA-v1.5 signature verification failed: {}", e))
    })?;
    Ok(())
}

fn sign_rsa_pkcs1v15(private_key_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use rsa::RsaPrivateKey;
    use rsa::pkcs1v15::{Signature as Pkcs1Sig, SigningKey as Pkcs1Sk};
    use rsa::pkcs8::DecodePrivateKey;

    let sk = RsaPrivateKey::from_pkcs8_der(private_key_bytes).map_err(|e| {
        PaymentError::Rfc9421Error(format!("invalid RSA private key (PKCS#8 DER): {}", e))
    })?;
    let signing_key: Pkcs1Sk<Sha256> = Pkcs1Sk::<Sha256>::new(sk);
    // rsa 0.9 impls the `signature` 2.x `Signer` — use the v2 alias.
    let sig: Pkcs1Sig = Sigv2Signer::sign(&signing_key, msg);
    Ok(<Pkcs1Sig as Into<Box<[u8]>>>::into(sig).to_vec())
}

// ----- HMAC-SHA-256 -----

fn verify_hmac_sha256(secret: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid HMAC key: {}", e)))?;
    Mac::update(&mut mac, msg);
    let computed = mac.finalize().into_bytes();
    if computed.ct_eq(sig_bytes).into() {
        Ok(())
    } else {
        Err(PaymentError::Rfc9421Error(
            "HMAC-SHA-256 signature verification failed".to_string(),
        ))
    }
}

fn sign_hmac_sha256(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .map_err(|e| PaymentError::Rfc9421Error(format!("invalid HMAC key: {}", e)))?;
    Mac::update(&mut mac, msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_ed25519_input() {
        let header = r#"sig1=("@authority" "@path" "content-type");created=1701234567;nonce="abc123";keyid="agent_key_001";alg="ed25519";tag="agent-browser-auth""#;

        let result = parse_signature_input(header);
        assert!(result.is_ok());

        let input = result.unwrap();
        assert_eq!(input.label, "sig1");
        assert_eq!(input.covered_components.len(), 3);
        assert_eq!(input.covered_components[0], "@authority");
        assert_eq!(input.covered_components[1], "@path");
        assert_eq!(input.covered_components[2], "content-type");

        assert_eq!(input.params.label, "sig1");
        assert_eq!(input.params.created, Some(1701234567));
        assert_eq!(input.params.nonce, Some("abc123".to_string()));
        assert_eq!(input.params.keyid, "agent_key_001");
        assert_eq!(input.params.alg, SignatureAlgorithm::Ed25519);
        assert_eq!(input.params.tag, Some("agent-browser-auth".to_string()));
    }

    #[test]
    fn test_parse_rsa_pss_input() {
        let header = r#"sig2=("@method" "@authority");keyid="rsa_key_001";alg="rsa-pss-sha512""#;

        let result = parse_signature_input(header);
        assert!(result.is_ok());

        let input = result.unwrap();
        assert_eq!(input.label, "sig2");
        assert_eq!(input.params.alg, SignatureAlgorithm::RsaPssSha512);
    }

    #[test]
    fn test_parse_missing_required_params() {
        // Missing keyid
        let header = r#"sig1=("@authority");alg="ed25519""#;
        let result = parse_signature_input(header);
        assert!(result.is_err());

        // Missing alg
        let header = r#"sig1=("@authority");keyid="key1""#;
        let result = parse_signature_input(header);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_signature_base() {
        let request_parts = RequestParts::for_request("POST", "api.example.com", "/payment")
            .with_header("content-type", "application/json")
            .with_header("content-length", "123");

        let input = SignatureInput {
            label: "sig1".to_string(),
            covered_components: vec![
                "@authority".to_string(),
                "@path".to_string(),
                "content-type".to_string(),
            ],
            params: SignatureParams {
                label: "sig1".to_string(),
                created: Some(1234567890),
                expires: None,
                nonce: Some("xyz".to_string()),
                keyid: "key1".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let base = build_signature_base(&request_parts, &input).unwrap();

        assert!(base.contains("\"@authority\": api.example.com"));
        assert!(base.contains("\"@path\": /payment"));
        assert!(base.contains("\"content-type\": application/json"));
        assert!(base.contains("\"@signature-params\""));
        assert!(base.contains("created=1234567890"));
        assert!(base.contains("nonce=\"xyz\""));
        assert!(base.contains("keyid=\"key1\""));
        assert!(base.contains("alg=\"ed25519\""));
    }

    #[test]
    fn test_round_trip_sign_verify_ed25519() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let private_key = keypair.to_bytes();
        let public_key = keypair.public_key().to_bytes();

        let request_parts = RequestParts::for_request("POST", "api.example.com", "/test")
            .with_header("content-type", "application/json");

        let input = SignatureInput {
            label: "sig1".to_string(),
            covered_components: vec![
                "@method".to_string(),
                "@authority".to_string(),
                "content-type".to_string(),
            ],
            params: SignatureParams {
                label: "sig1".to_string(),
                created: Some(1234567890),
                expires: None,
                nonce: Some("test-nonce".to_string()),
                keyid: "test-key".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let signature_bytes = create_http_signature(
            &request_parts,
            &input,
            &private_key,
            &SignatureAlgorithm::Ed25519,
        )
        .unwrap();

        let signed_headers = SignedHeaders {
            signature_input_raw: "test".to_string(),
            signature_bytes,
            parsed: input,
        };

        verify_http_signature(
            &request_parts,
            &signed_headers,
            &public_key,
            &SignatureAlgorithm::Ed25519,
        )
        .unwrap();
    }

    #[test]
    fn test_round_trip_sign_verify_ecdsa_p256() {
        use ::p256::elliptic_curve::Generate;
        use getrandom_0_4::{SysRng, rand_core::UnwrapErr};
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;

        let sk = SigningKey::generate_from_rng(&mut UnwrapErr(SysRng));
        let private_pkcs8 = sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let vk = sk.verifying_key();
        let public_sec1 = vk.to_sec1_point(false).as_bytes().to_vec();

        let request_parts =
            RequestParts::for_request("POST", "api.example.com", "/test").with_query("a=1&b=2");

        let input = SignatureInput {
            label: "sig".to_string(),
            covered_components: vec![
                "@method".to_string(),
                "@target-uri".to_string(),
                "@query".to_string(),
            ],
            params: SignatureParams {
                label: "sig".to_string(),
                created: Some(1700000000),
                expires: None,
                nonce: Some("n".to_string()),
                keyid: "p256".to_string(),
                alg: SignatureAlgorithm::EcdsaP256Sha256,
                tag: None,
            },
        };

        let sig = create_http_signature(
            &request_parts,
            &input,
            &private_pkcs8,
            &SignatureAlgorithm::EcdsaP256Sha256,
        )
        .unwrap();
        let signed = SignedHeaders {
            signature_input_raw: "x".to_string(),
            signature_bytes: sig,
            parsed: input,
        };
        verify_http_signature(
            &request_parts,
            &signed,
            &public_sec1,
            &SignatureAlgorithm::EcdsaP256Sha256,
        )
        .unwrap();
    }

    #[test]
    fn test_round_trip_sign_verify_ecdsa_p384() {
        use ::p384::elliptic_curve::Generate;
        use getrandom_0_4::{SysRng, rand_core::UnwrapErr};
        use p384::ecdsa::SigningKey;
        use p384::pkcs8::EncodePrivateKey;

        let sk = SigningKey::generate_from_rng(&mut UnwrapErr(SysRng));
        let private_pkcs8 = sk.to_pkcs8_der().unwrap().as_bytes().to_vec();
        let vk = sk.verifying_key();
        let public_sec1 = vk.to_sec1_point(false).as_bytes().to_vec();

        let request_parts = RequestParts::for_request("GET", "x.example.com", "/r");

        let input = SignatureInput {
            label: "sig".to_string(),
            covered_components: vec!["@method".to_string(), "@authority".to_string()],
            params: SignatureParams {
                label: "sig".to_string(),
                created: Some(1700000000),
                expires: None,
                nonce: None,
                keyid: "p384".to_string(),
                alg: SignatureAlgorithm::EcdsaP384Sha384,
                tag: None,
            },
        };

        let sig = create_http_signature(
            &request_parts,
            &input,
            &private_pkcs8,
            &SignatureAlgorithm::EcdsaP384Sha384,
        )
        .unwrap();
        let signed = SignedHeaders {
            signature_input_raw: "x".to_string(),
            signature_bytes: sig,
            parsed: input,
        };
        verify_http_signature(
            &request_parts,
            &signed,
            &public_sec1,
            &SignatureAlgorithm::EcdsaP384Sha384,
        )
        .unwrap();
    }

    #[test]
    fn test_round_trip_hmac_sha256() {
        let secret = b"a-shared-secret-32-bytes-long!!".to_vec();

        let request_parts = RequestParts::for_request("POST", "x.example.com", "/r");
        let input = SignatureInput {
            label: "sig".to_string(),
            covered_components: vec!["@method".to_string()],
            params: SignatureParams {
                label: "sig".to_string(),
                created: Some(1),
                expires: None,
                nonce: None,
                keyid: "shared".to_string(),
                alg: SignatureAlgorithm::HmacSha256,
                tag: None,
            },
        };

        let sig = create_http_signature(
            &request_parts,
            &input,
            &secret,
            &SignatureAlgorithm::HmacSha256,
        )
        .unwrap();
        let signed = SignedHeaders {
            signature_input_raw: "x".to_string(),
            signature_bytes: sig,
            parsed: input,
        };
        verify_http_signature(
            &request_parts,
            &signed,
            &secret,
            &SignatureAlgorithm::HmacSha256,
        )
        .unwrap();
    }

    #[test]
    fn test_derived_components_query_and_target_uri() {
        let request_parts = RequestParts::for_request("GET", "api.example.com", "/users")
            .with_query("id=42&q=hello")
            .with_scheme("https");

        let input = SignatureInput {
            label: "s".to_string(),
            covered_components: vec![
                "@target-uri".to_string(),
                "@query".to_string(),
                "@request-target".to_string(),
                "@scheme".to_string(),
            ],
            params: SignatureParams {
                label: "s".to_string(),
                created: None,
                expires: None,
                nonce: None,
                keyid: "k".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let base = build_signature_base(&request_parts, &input).unwrap();
        assert!(base.contains("\"@target-uri\": https://api.example.com/users?id=42&q=hello"));
        assert!(base.contains("\"@query\": ?id=42&q=hello"));
        assert!(base.contains("\"@request-target\": /users?id=42&q=hello"));
        assert!(base.contains("\"@scheme\": https"));
    }

    #[test]
    fn test_query_param_component_with_param_modifier() {
        let request_parts =
            RequestParts::for_request("GET", "x.example", "/r").with_query("a=1&b=two");

        let input = SignatureInput {
            label: "s".to_string(),
            covered_components: vec!["@query-param;name=\"b\"".to_string()],
            params: SignatureParams {
                label: "s".to_string(),
                created: None,
                expires: None,
                nonce: None,
                keyid: "k".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let base = build_signature_base(&request_parts, &input).unwrap();
        assert!(
            base.contains("\"@query-param\";name=\"b\": two"),
            "got: {}",
            base
        );
    }

    #[test]
    fn test_field_value_canonicalization_strips_obs_fold() {
        let request_parts = RequestParts::for_request("POST", "x.example", "/r")
            .with_header("x-multi", "  foo\r\n   bar\t baz   ");

        let input = SignatureInput {
            label: "s".to_string(),
            covered_components: vec!["x-multi".to_string()],
            params: SignatureParams {
                label: "s".to_string(),
                created: None,
                expires: None,
                nonce: None,
                keyid: "k".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let base = build_signature_base(&request_parts, &input).unwrap();
        assert!(base.contains("\"x-multi\": foo bar baz"), "got: {}", base);
    }

    #[test]
    fn test_status_component_for_response() {
        let parts = RequestParts::for_request("GET", "x.example", "/r").with_status(200);
        let input = SignatureInput {
            label: "s".to_string(),
            covered_components: vec!["@status".to_string()],
            params: SignatureParams {
                label: "s".to_string(),
                created: None,
                expires: None,
                nonce: None,
                keyid: "k".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };
        let base = build_signature_base(&parts, &input).unwrap();
        assert!(base.contains("\"@status\": 200"));
    }

    #[test]
    fn test_signature_algorithm_display() {
        assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "ed25519");
        assert_eq!(
            SignatureAlgorithm::RsaPssSha256.to_string(),
            "rsa-pss-sha256"
        );
        assert_eq!(
            SignatureAlgorithm::RsaPssSha512.to_string(),
            "rsa-pss-sha512"
        );
        assert_eq!(
            SignatureAlgorithm::EcdsaP256Sha256.to_string(),
            "ecdsa-p256-sha256"
        );
        assert_eq!(
            SignatureAlgorithm::EcdsaP384Sha384.to_string(),
            "ecdsa-p384-sha384"
        );
        assert_eq!(SignatureAlgorithm::HmacSha256.to_string(), "hmac-sha256");
    }

    #[test]
    fn test_signature_algorithm_from_str() {
        assert_eq!(
            SignatureAlgorithm::from_str("ed25519").unwrap(),
            SignatureAlgorithm::Ed25519
        );
        assert_eq!(
            SignatureAlgorithm::from_str("ED25519").unwrap(),
            SignatureAlgorithm::Ed25519
        );
        assert_eq!(
            SignatureAlgorithm::from_str("rsa-pss-sha256").unwrap(),
            SignatureAlgorithm::RsaPssSha256
        );
        assert_eq!(
            SignatureAlgorithm::from_str("rsa-pss-sha512").unwrap(),
            SignatureAlgorithm::RsaPssSha512
        );
        assert_eq!(
            SignatureAlgorithm::from_str("ecdsa-p256-sha256").unwrap(),
            SignatureAlgorithm::EcdsaP256Sha256
        );
        assert_eq!(
            SignatureAlgorithm::from_str("ecdsa-p384-sha384").unwrap(),
            SignatureAlgorithm::EcdsaP384Sha384
        );
        assert_eq!(
            SignatureAlgorithm::from_str("hmac-sha256").unwrap(),
            SignatureAlgorithm::HmacSha256
        );
        assert!(SignatureAlgorithm::from_str("unknown").is_err());
    }

    #[test]
    fn test_build_signature_base_missing_header() {
        let request_parts = RequestParts::for_request("POST", "api.example.com", "/test");
        let input = SignatureInput {
            label: "sig1".to_string(),
            covered_components: vec!["missing-header".to_string()],
            params: SignatureParams {
                label: "sig1".to_string(),
                created: None,
                expires: None,
                nonce: None,
                keyid: "key1".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let result = build_signature_base(&request_parts, &input);
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_malformed_input() {
        // Missing '='
        let header = "sig1";
        assert!(parse_signature_input(header).is_err());

        // Missing parentheses
        let header = r#"sig1=keyid="key1";alg="ed25519""#;
        assert!(parse_signature_input(header).is_err());

        // Unmatched parentheses
        let header = r#"sig1=("@authority";keyid="key1";alg="ed25519""#;
        assert!(parse_signature_input(header).is_err());
    }

    #[test]
    fn test_verify_with_wrong_key_fails() {
        let kp1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let kp2 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let private_key1 = kp1.to_bytes();
        let public_key2 = kp2.public_key().to_bytes();

        let request_parts = RequestParts::for_request("POST", "api.example.com", "/test")
            .with_header("content-type", "application/json");

        let input = SignatureInput {
            label: "sig1".to_string(),
            covered_components: vec!["@method".to_string()],
            params: SignatureParams {
                label: "sig1".to_string(),
                created: None,
                expires: None,
                nonce: None,
                keyid: "test-key".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let signature_bytes = create_http_signature(
            &request_parts,
            &input,
            &private_key1,
            &SignatureAlgorithm::Ed25519,
        )
        .unwrap();

        let signed_headers = SignedHeaders {
            signature_input_raw: "test".to_string(),
            signature_bytes,
            parsed: input,
        };

        let result = verify_http_signature(
            &request_parts,
            &signed_headers,
            &public_key2,
            &SignatureAlgorithm::Ed25519,
        );

        assert!(result.is_err());
    }
}
