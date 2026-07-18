//! Intel Tiber Trust Authority (ITA) integration for Tenzro Network.
//!
//! Tiber Trust Authority is Intel's hosted attestation appraisal service. A
//! relying party hands ITA a TDX Quote (plus an optional ITA-issued nonce),
//! and ITA returns a signed JWT — an [Entity Attestation Token (EAT)] —
//! containing parsed TEE claims (`tdx_mrtd`, `tdx_rtmr0..3`, `tdx_seamsvn`,
//! `attester_tcb_status`, …) and the appraisal verdict. The relying party
//! then verifies the JWT signature against ITA's published JWKS and decides
//! whether to trust the workload.
//!
//! This module is the alternative to running PCS collateral verification
//! ourselves inside [`crate::intel_tdx::IntelTdxProvider::verify_td_quote`] —
//! it's strictly hosted: a single HTTPS round trip in lieu of the full PCK
//! cert chain walk + QE signature verification.
//!
//! # Wire contract (verified against `intel/trustauthority-client-for-go`)
//!
//! - **`GET  {base_url}/appraisal/v2/nonce`** → `{val, iat, signature}` (all
//!   base64-encoded byte arrays). The nonce binds a fresh appraisal to the
//!   quote (Quote `report_data` must hash-bind the nonce).
//! - **`POST {base_url}/appraisal/v2/attest`** with a JSON body of:
//!     - `quote: base64` — the raw TDX Quote v4 bytes
//!     - `verifier_nonce?: {val, iat, signature}` — nonce returned by `GET /nonce`
//!     - `runtime_data?: base64`
//!     - `policy_ids?: [uuid]`
//!     - `user_data?: base64`
//!     - `event_log?: base64`
//!     - `token_signing_alg?: "PS384" | "RS256"`
//!     - `policy_must_match?: bool`
//!
//!   The response is `{token: "<JWT>"}`.
//!
//! Required headers on both: `x-api-key: <key>`, `Accept: application/json`,
//! plus `Content-Type: application/json` on POST. Per ITA docs, regional URLs
//! are `https://api.trustauthority.intel.com` (US) and
//! `https://api.eu.trustauthority.intel.com` (EU).
//!
//! # JWT verification
//!
//! Tokens are signed with `PS384` by default (or `RS256` if the caller asked
//! for it). The JOSE header carries:
//! - `jku` — JWKS URI to fetch
//! - `kid` — key ID to select from the JWKS
//! - `alg` — `PS384` or `RS256`
//!
//! [`verify_token`] fetches the JWKS from `jku` (or a caller-pinned override),
//! finds the JWK with the matching `kid`, builds a `DecodingKey` from the RSA
//! `n`/`e` parameters, and validates the token. The exact value of `jku`
//! against an allowlist of well-known ITA endpoints is the relying party's
//! call — we expose `TiberJwksPin` so callers can lock down the JWKS host.
//!
//! [Entity Attestation Token (EAT)]: https://datatracker.ietf.org/doc/draft-ietf-rats-eat/

#![cfg(feature = "intel-tiber")]

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use tenzro_types::tee::{AttestationResult, Measurement, TeeVendor};

use crate::error::{Result, TeeError};

/// Default US production endpoint.
pub const TIBER_API_URL_US: &str = "https://api.trustauthority.intel.com";

/// Default EU production endpoint.
pub const TIBER_API_URL_EU: &str = "https://api.eu.trustauthority.intel.com";

/// Path for fetching a verifier nonce.
pub const NONCE_PATH: &str = "/appraisal/v2/nonce";

/// Path for submitting a TDX Quote for appraisal.
pub const ATTEST_PATH: &str = "/appraisal/v2/attest";

/// Default per-request timeout (ITA p99 appraisal latency is ~2s).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum JWKS payload size we'll accept from the `jku` host.
const MAX_JWKS_BYTES: usize = 64 * 1024;

/// Token signing algorithms Tiber Trust Authority will issue.
///
/// `PS384` (RSASSA-PSS with SHA-384) is the default; `RS256` is offered for
/// constrained clients. We refuse to verify anything else even if the JOSE
/// header advertises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSigningAlg {
    Ps384,
    Rs256,
}

impl TokenSigningAlg {
    fn as_str(self) -> &'static str {
        match self {
            TokenSigningAlg::Ps384 => "PS384",
            TokenSigningAlg::Rs256 => "RS256",
        }
    }

    fn jwt(self) -> Algorithm {
        match self {
            TokenSigningAlg::Ps384 => Algorithm::PS384,
            TokenSigningAlg::Rs256 => Algorithm::RS256,
        }
    }
}

/// Optional pin on which JWKS host the relying party will trust.
///
/// Tiber JWTs carry the JWKS URI in the `jku` header. A passive verifier
/// could naively follow `jku` to any host, which is exactly the kind of
/// open-redirect that signed-by-an-attacker tokens love. Provide
/// `TiberJwksPin::AllowedHosts(["api.trustauthority.intel.com",
/// "api.eu.trustauthority.intel.com"])` to enforce that `jku` resolves to
/// the regional ITA endpoint you intended.
#[derive(Debug, Clone, Default)]
pub enum TiberJwksPin {
    /// Accept any `jku` URI verbatim. **Don't use this in production.**
    #[default]
    Any,
    /// Reject the token unless `jku`'s host equals one of these.
    AllowedHosts(Vec<String>),
    /// Bypass `jku` entirely and fetch from this URL.
    Override(String),
}

/// Verifier nonce returned by `GET /appraisal/v2/nonce`.
///
/// All three fields are base64-encoded byte arrays on the wire. We keep them
/// as `Vec<u8>` here because the caller hashes `val || iat` into the Quote's
/// `report_data` before submission, and the bytes need to round-trip into the
/// POST body unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierNonce {
    #[serde(with = "b64_bytes")]
    pub val: Vec<u8>,
    #[serde(with = "b64_bytes")]
    pub iat: Vec<u8>,
    #[serde(with = "b64_bytes")]
    pub signature: Vec<u8>,
}

mod b64_bytes {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&B64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64_STANDARD.decode(s.as_bytes()).map_err(D::Error::custom)
    }
}

/// Body of `POST /appraisal/v2/attest`.
#[derive(Debug, Clone, Serialize)]
pub struct AttestRequest {
    #[serde(with = "b64_bytes")]
    pub quote: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_nonce: Option<VerifierNonce>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub runtime_data: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub user_data: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub event_log: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_signing_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_must_match: Option<bool>,
}

mod b64_opt {
    use super::*;
    use serde::Serializer;

    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_str(&B64_STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }
}

/// Response from `POST /appraisal/v2/attest`.
#[derive(Debug, Clone, Deserialize)]
struct AttestResponse {
    token: String,
}

/// Subset of the Tiber EAT claims Tenzro consumes after JWT verification.
///
/// We only model claims a relying party actually acts on (binding, freshness,
/// TCB verdict, measurements). Additional Intel-specific claims are still
/// captured via the typed `extras` map for audit / logging.
#[derive(Debug, Clone, Deserialize)]
pub struct TiberClaims {
    pub iss: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub jti: Option<String>,
    /// Always `"https://portal.trustauthority.intel.com/eat_profile.html"`
    /// for TDX/SGX tokens issued by ITA. Treat any other value as suspect.
    pub eat_profile: Option<String>,
    /// `"enabled"` or `"disabled"`. Production TDs must report `"disabled"`.
    pub dbgstat: Option<String>,
    /// `"OK"`, `"OutOfDate"`, `"OutOfDateConfigurationNeeded"`, `"Revoked"`,
    /// or `"ConfigurationNeeded"`. Treat anything but `"OK"` as policy fail.
    pub attester_tcb_status: Option<String>,
    pub attester_tcb_date: Option<String>,
    pub attester_advisory_ids: Option<Vec<String>>,
    /// Hex-encoded measurement of the initial TD (SHA-384, 48 bytes).
    pub tdx_mrtd: Option<String>,
    pub tdx_rtmr0: Option<String>,
    pub tdx_rtmr1: Option<String>,
    pub tdx_rtmr2: Option<String>,
    pub tdx_rtmr3: Option<String>,
    pub tdx_mrsignerseam: Option<String>,
    pub tdx_seamsvn: Option<i64>,
    /// Catch-all for fields Intel adds without breaking us at the JSON layer.
    #[serde(flatten)]
    pub extras: serde_json::Map<String, serde_json::Value>,
}

/// Client for Intel Tiber Trust Authority.
#[derive(Debug, Clone)]
pub struct IntelTiberClient {
    base_url: String,
    api_key: String,
    http: Client,
    jwks_pin: TiberJwksPin,
    expected_iss: Option<String>,
}

impl IntelTiberClient {
    /// Builds a new ITA client.
    ///
    /// `base_url` is the regional ITA host (no trailing slash; one is stripped
    /// for you). `api_key` is the value Intel issues from the developer
    /// portal — it's sent as `x-api-key` on every request.
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self> {
        let mut base_url = base_url.into();
        if base_url.is_empty() {
            return Err(TeeError::ConfigurationError(
                "Intel Tiber base URL is empty".to_string(),
            ));
        }
        while base_url.ends_with('/') {
            base_url.pop();
        }
        let api_key = api_key.into();
        if api_key.is_empty() {
            return Err(TeeError::ConfigurationError(
                "Intel Tiber API key is empty".to_string(),
            ));
        }
        let http = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| TeeError::ConfigurationError(format!("HTTP client build failed: {e}")))?;

        Ok(Self {
            base_url,
            api_key,
            http,
            jwks_pin: TiberJwksPin::default(),
            expected_iss: None,
        })
    }

    /// Pins which JWKS host(s) will be honored when verifying tokens.
    pub fn with_jwks_pin(mut self, pin: TiberJwksPin) -> Self {
        self.jwks_pin = pin;
        self
    }

    /// Sets an expected `iss` claim — verification fails if the token's `iss`
    /// doesn't match. Intel-issued tokens use a stable issuer string per region.
    pub fn with_expected_issuer(mut self, iss: impl Into<String>) -> Self {
        self.expected_iss = Some(iss.into());
        self
    }

    /// Fetches a fresh verifier nonce. Bind it into the Quote's `report_data`
    /// (SHA-256 over `val || iat`, lower 32 bytes per ITA convention) before
    /// calling [`Self::attest`].
    pub async fn get_nonce(&self) -> Result<VerifierNonce> {
        let url = format!("{}{}", self.base_url, NONCE_PATH);
        let resp = self
            .http
            .get(&url)
            .header("x-api-key", &self.api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| TeeError::AttestationVerificationFailed(format!("ITA nonce GET failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(TeeError::AttestationVerificationFailed(format!(
                "ITA nonce returned HTTP {status}: {body}"
            )));
        }

        resp.json::<VerifierNonce>().await.map_err(|e| {
            TeeError::AttestationVerificationFailed(format!("ITA nonce body parse failed: {e}"))
        })
    }

    /// Submits a Quote for appraisal and returns the raw JWT string.
    ///
    /// The JWT is **not** yet verified — call [`Self::verify_token`] on the
    /// returned string to validate the signature against ITA's JWKS and
    /// extract the typed [`TiberClaims`].
    pub async fn attest(&self, request: &AttestRequest) -> Result<String> {
        let url = format!("{}{}", self.base_url, ATTEST_PATH);
        let resp = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(request)
            .send()
            .await
            .map_err(|e| {
                TeeError::AttestationVerificationFailed(format!("ITA attest POST failed: {e}"))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(TeeError::AttestationVerificationFailed(format!(
                "ITA attest returned HTTP {status}: {body}"
            )));
        }

        let parsed: AttestResponse = resp.json().await.map_err(|e| {
            TeeError::AttestationVerificationFailed(format!("ITA attest body parse failed: {e}"))
        })?;
        Ok(parsed.token)
    }

    /// Convenience wrapper: get a nonce, build a default `AttestRequest`, and
    /// return the appraisal JWT. The caller is responsible for ensuring the
    /// Quote's `report_data` field already binds the nonce (the binding
    /// happens inside the TEE before the Quote is generated, so we can't do
    /// it for them here).
    pub async fn get_token_with_nonce(
        &self,
        quote: Vec<u8>,
        nonce: VerifierNonce,
        token_signing_alg: TokenSigningAlg,
    ) -> Result<String> {
        let req = AttestRequest {
            quote,
            verifier_nonce: Some(nonce),
            runtime_data: None,
            policy_ids: Vec::new(),
            user_data: None,
            event_log: None,
            token_signing_alg: Some(token_signing_alg.as_str().to_string()),
            policy_must_match: None,
        };
        self.attest(&req).await
    }

    /// Verifies a Tiber-issued JWT and extracts the typed claims.
    ///
    /// Flow:
    /// 1. Decode the JOSE header to get `jku`, `kid`, `alg`.
    /// 2. Enforce `alg ∈ {PS384, RS256}` (ITA's two issued algorithms).
    /// 3. Apply [`TiberJwksPin`] against `jku`.
    /// 4. Fetch the JWKS, find the JWK with matching `kid`.
    /// 5. Verify the JWT signature against the JWK's RSA public key.
    /// 6. Validate `exp`/`nbf` and optionally `iss`.
    pub async fn verify_token(&self, token: &str) -> Result<TiberClaims> {
        // Decode header without verifying — we need `jku`/`kid`/`alg` to find
        // the right key to verify against.
        let header = jsonwebtoken::decode_header(token).map_err(|e| {
            TeeError::AttestationVerificationFailed(format!("ITA JWT header decode failed: {e}"))
        })?;
        let alg = match header.alg {
            Algorithm::PS384 => TokenSigningAlg::Ps384,
            Algorithm::RS256 => TokenSigningAlg::Rs256,
            other => {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "ITA token uses unsupported alg {other:?} (only PS384/RS256 issued)"
                )));
            }
        };
        let kid = header.kid.ok_or_else(|| {
            TeeError::AttestationVerificationFailed("ITA JWT header missing kid".to_string())
        })?;

        let jwks_url = match &self.jwks_pin {
            TiberJwksPin::Override(u) => u.clone(),
            TiberJwksPin::Any => header.jku.ok_or_else(|| {
                TeeError::AttestationVerificationFailed("ITA JWT header missing jku".to_string())
            })?,
            TiberJwksPin::AllowedHosts(hosts) => {
                let jku = header.jku.ok_or_else(|| {
                    TeeError::AttestationVerificationFailed(
                        "ITA JWT header missing jku".to_string(),
                    )
                })?;
                let parsed = reqwest::Url::parse(&jku).map_err(|e| {
                    TeeError::AttestationVerificationFailed(format!(
                        "ITA jku is not a valid URL: {e}"
                    ))
                })?;
                let host = parsed.host_str().ok_or_else(|| {
                    TeeError::AttestationVerificationFailed("ITA jku has no host".to_string())
                })?;
                if !hosts.iter().any(|h| h == host) {
                    return Err(TeeError::AttestationVerificationFailed(format!(
                        "ITA jku host '{host}' not in allowed list"
                    )));
                }
                jku
            }
        };

        // Fetch the JWKS (size-capped to avoid memory blow-ups on a malicious
        // host) and pick the JWK with matching kid.
        let jwks_resp = self
            .http
            .get(&jwks_url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                TeeError::AttestationVerificationFailed(format!("ITA JWKS fetch failed: {e}"))
            })?;
        if !jwks_resp.status().is_success() {
            return Err(TeeError::AttestationVerificationFailed(format!(
                "ITA JWKS fetch returned HTTP {}",
                jwks_resp.status()
            )));
        }
        let body = jwks_resp.bytes().await.map_err(|e| {
            TeeError::AttestationVerificationFailed(format!("ITA JWKS body read failed: {e}"))
        })?;
        if body.len() > MAX_JWKS_BYTES {
            return Err(TeeError::AttestationVerificationFailed(format!(
                "ITA JWKS body too large: {} > {MAX_JWKS_BYTES}",
                body.len()
            )));
        }
        let jwks: Jwks = serde_json::from_slice(&body).map_err(|e| {
            TeeError::AttestationVerificationFailed(format!("ITA JWKS parse failed: {e}"))
        })?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid.as_str()))
            .ok_or_else(|| {
                TeeError::AttestationVerificationFailed(format!(
                    "ITA JWKS has no key with kid={kid}"
                ))
            })?;
        if jwk.kty != "RSA" {
            return Err(TeeError::AttestationVerificationFailed(format!(
                "ITA JWK has unsupported kty={} (only RSA accepted)",
                jwk.kty
            )));
        }
        let n = jwk.n.as_deref().ok_or_else(|| {
            TeeError::AttestationVerificationFailed("ITA JWK missing n parameter".to_string())
        })?;
        let e = jwk.e.as_deref().ok_or_else(|| {
            TeeError::AttestationVerificationFailed("ITA JWK missing e parameter".to_string())
        })?;
        let decoding_key = DecodingKey::from_rsa_components(n, e).map_err(|err| {
            TeeError::AttestationVerificationFailed(format!(
                "ITA JWK -> DecodingKey conversion failed: {err}"
            ))
        })?;

        let mut validation = Validation::new(alg.jwt());
        validation.validate_exp = true;
        validation.validate_nbf = true;
        // Tiber tokens carry an `iss` but the exact string is region-specific;
        // require an explicit pin if the caller wants enforcement.
        if let Some(iss) = &self.expected_iss {
            validation.set_issuer(&[iss]);
        }

        let token_data = jsonwebtoken::decode::<TiberClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                TeeError::AttestationVerificationFailed(format!(
                    "ITA JWT signature verification failed: {e}"
                ))
            })?;
        Ok(token_data.claims)
    }

    /// Composite path — submit a Quote to Tiber, verify the returned JWT, and
    /// project the verified claims into the cross-vendor [`AttestationResult`]
    /// shape used by [`crate::AttestationVerifier`].
    ///
    /// This is the alternative entry point for relying parties that prefer
    /// hosted appraisal over running native PCS verification themselves. The
    /// returned `AttestationResult.details["verification_method"]` is set to
    /// `"intel_tiber"` so callers can distinguish.
    pub async fn verify_quote(
        &self,
        quote: Vec<u8>,
        nonce: Option<VerifierNonce>,
        token_signing_alg: TokenSigningAlg,
    ) -> Result<(AttestationResult, TiberClaims)> {
        let req = AttestRequest {
            quote,
            verifier_nonce: nonce,
            runtime_data: None,
            policy_ids: Vec::new(),
            user_data: None,
            event_log: None,
            token_signing_alg: Some(token_signing_alg.as_str().to_string()),
            policy_must_match: None,
        };
        let token = self.attest(&req).await?;
        let claims = self.verify_token(&token).await?;
        let result = claims_to_attestation_result(&claims)?;
        Ok((result, claims))
    }
}

/// Project verified Tiber EAT claims into the cross-vendor
/// [`AttestationResult`] used elsewhere in the crate.
///
/// The valid flag is `true` only if `attester_tcb_status == "OK"` and the
/// debug status is `"disabled"` — Intel's two hard go/no-go signals for a
/// production TD. Everything else lands in `details` for the relying party
/// to inspect.
pub fn claims_to_attestation_result(claims: &TiberClaims) -> Result<AttestationResult> {
    let tcb_ok = claims
        .attester_tcb_status
        .as_deref()
        .map(|s| s == "OK")
        .unwrap_or(false);
    let dbg_off = claims
        .dbgstat
        .as_deref()
        .map(|s| s == "disabled")
        .unwrap_or(false);
    let valid = tcb_ok && dbg_off;

    let mut measurements: Vec<Measurement> = Vec::new();
    let mut push_hex = |index: u32, register: &str, hex_opt: &Option<String>| -> Result<()> {
        if let Some(hex_str) = hex_opt {
            let value = hex::decode(hex_str.trim_start_matches("0x")).map_err(|e| {
                TeeError::AttestationVerificationFailed(format!(
                    "ITA claim {register} is not hex: {e}"
                ))
            })?;
            measurements.push(Measurement {
                index,
                algorithm: "SHA384".to_string(),
                value,
                register: register.to_string(),
                description: None,
            });
        }
        Ok(())
    };
    push_hex(0, "MRTD", &claims.tdx_mrtd)?;
    push_hex(0, "RTMR0", &claims.tdx_rtmr0)?;
    push_hex(1, "RTMR1", &claims.tdx_rtmr1)?;
    push_hex(2, "RTMR2", &claims.tdx_rtmr2)?;
    push_hex(3, "RTMR3", &claims.tdx_rtmr3)?;
    push_hex(0, "MRSIGNERSEAM", &claims.tdx_mrsignerseam)?;

    let mut details: HashMap<String, String> = HashMap::new();
    details.insert(
        "verification_method".to_string(),
        "intel_tiber".to_string(),
    );
    if let Some(tcb) = &claims.attester_tcb_status {
        details.insert("attester_tcb_status".to_string(), tcb.clone());
    }
    if let Some(date) = &claims.attester_tcb_date {
        details.insert("attester_tcb_date".to_string(), date.clone());
    }
    if let Some(dbg) = &claims.dbgstat {
        details.insert("dbgstat".to_string(), dbg.clone());
    }
    if let Some(eat) = &claims.eat_profile {
        details.insert("eat_profile".to_string(), eat.clone());
    }
    if let Some(svn) = claims.tdx_seamsvn {
        details.insert("tdx_seamsvn".to_string(), svn.to_string());
    }
    if let Some(advisories) = &claims.attester_advisory_ids
        && !advisories.is_empty()
    {
        details.insert(
            "attester_advisory_ids".to_string(),
            advisories.join(","),
        );
    }

    Ok(AttestationResult {
        valid,
        vendor: TeeVendor::IntelTdx,
        tcb_version: claims
            .attester_tcb_status
            .clone()
            .unwrap_or_default(),
        measurements,
        // Cert chain validation is delegated to Tiber — a successful JWT
        // verification against the JWKS implicitly attests to it.
        cert_chain_valid: valid,
        details,
        verified_at: tenzro_types::Timestamp::now(),
        ..Default::default()
    })
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_empty_url() {
        let err = IntelTiberClient::new("", "key").unwrap_err();
        assert!(matches!(err, TeeError::ConfigurationError(_)));
    }

    #[test]
    fn new_rejects_empty_key() {
        let err = IntelTiberClient::new(TIBER_API_URL_US, "").unwrap_err();
        assert!(matches!(err, TeeError::ConfigurationError(_)));
    }

    #[test]
    fn new_strips_trailing_slash() {
        let c = IntelTiberClient::new("https://api.trustauthority.intel.com///", "k").unwrap();
        assert_eq!(c.base_url, "https://api.trustauthority.intel.com");
    }

    #[test]
    fn signing_alg_round_trip() {
        assert_eq!(TokenSigningAlg::Ps384.as_str(), "PS384");
        assert_eq!(TokenSigningAlg::Rs256.as_str(), "RS256");
        assert_eq!(TokenSigningAlg::Ps384.jwt(), Algorithm::PS384);
        assert_eq!(TokenSigningAlg::Rs256.jwt(), Algorithm::RS256);
    }

    #[test]
    fn verifier_nonce_serde_round_trip() {
        let n = VerifierNonce {
            val: b"\x01\x02\x03".to_vec(),
            iat: b"\x04\x05".to_vec(),
            signature: b"\x06\x07\x08\x09".to_vec(),
        };
        let j = serde_json::to_string(&n).unwrap();
        // base64("\x01\x02\x03") = "AQID", base64("\x04\x05") = "BAU=", base64("\x06\x07\x08\x09") = "BgcICQ=="
        assert!(j.contains(r#""val":"AQID""#));
        assert!(j.contains(r#""iat":"BAU=""#));
        assert!(j.contains(r#""signature":"BgcICQ==""#));
        let parsed: VerifierNonce = serde_json::from_str(&j).unwrap();
        assert_eq!(parsed.val, n.val);
        assert_eq!(parsed.iat, n.iat);
        assert_eq!(parsed.signature, n.signature);
    }

    #[test]
    fn attest_request_serializes_only_provided_fields() {
        let req = AttestRequest {
            quote: b"\xaa\xbb".to_vec(),
            verifier_nonce: None,
            runtime_data: None,
            policy_ids: Vec::new(),
            user_data: None,
            event_log: None,
            token_signing_alg: None,
            policy_must_match: None,
        };
        let j = serde_json::to_string(&req).unwrap();
        assert!(j.contains(r#""quote":"qrs=""#));
        assert!(!j.contains("verifier_nonce"));
        assert!(!j.contains("runtime_data"));
        assert!(!j.contains("policy_ids"));
        assert!(!j.contains("user_data"));
        assert!(!j.contains("event_log"));
        assert!(!j.contains("token_signing_alg"));
        assert!(!j.contains("policy_must_match"));
    }

    #[test]
    fn attest_request_serializes_full_payload() {
        let req = AttestRequest {
            quote: b"\x00\x01".to_vec(),
            verifier_nonce: Some(VerifierNonce {
                val: b"n".to_vec(),
                iat: b"i".to_vec(),
                signature: b"s".to_vec(),
            }),
            runtime_data: Some(b"r".to_vec()),
            policy_ids: vec!["1d3f-…".to_string()],
            user_data: Some(b"u".to_vec()),
            event_log: Some(b"e".to_vec()),
            token_signing_alg: Some("PS384".to_string()),
            policy_must_match: Some(true),
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(v["quote"], "AAE=");
        assert_eq!(v["verifier_nonce"]["val"], "bg==");
        assert_eq!(v["runtime_data"], "cg==");
        assert_eq!(v["policy_ids"][0], "1d3f-…");
        assert_eq!(v["user_data"], "dQ==");
        assert_eq!(v["event_log"], "ZQ==");
        assert_eq!(v["token_signing_alg"], "PS384");
        assert_eq!(v["policy_must_match"], true);
    }

    #[test]
    fn jwks_pin_default_is_any() {
        assert!(matches!(TiberJwksPin::default(), TiberJwksPin::Any));
    }

    fn claims_with(tcb: Option<&str>, dbg: Option<&str>) -> TiberClaims {
        TiberClaims {
            iss: None,
            exp: None,
            iat: None,
            nbf: None,
            jti: None,
            eat_profile: Some(
                "https://portal.trustauthority.intel.com/eat_profile.html".to_string(),
            ),
            dbgstat: dbg.map(String::from),
            attester_tcb_status: tcb.map(String::from),
            attester_tcb_date: Some("2026-01-01T00:00:00Z".to_string()),
            attester_advisory_ids: Some(vec!["INTEL-SA-12345".to_string()]),
            tdx_mrtd: Some("00".repeat(48)),
            tdx_rtmr0: Some("11".repeat(48)),
            tdx_rtmr1: Some("22".repeat(48)),
            tdx_rtmr2: Some("33".repeat(48)),
            tdx_rtmr3: Some("44".repeat(48)),
            tdx_mrsignerseam: Some("ff".repeat(48)),
            tdx_seamsvn: Some(3),
            extras: Default::default(),
        }
    }

    #[test]
    fn projection_marks_valid_when_tcb_ok_and_debug_off() {
        let r = claims_to_attestation_result(&claims_with(Some("OK"), Some("disabled"))).unwrap();
        assert!(r.valid);
        assert!(r.cert_chain_valid);
        assert_eq!(r.vendor, TeeVendor::IntelTdx);
        assert_eq!(r.tcb_version, "OK");
        // MRTD + 4 RTMRs + MRSIGNERSEAM = 6 measurements
        assert_eq!(r.measurements.len(), 6);
        assert_eq!(r.measurements[0].register, "MRTD");
        assert_eq!(r.measurements[0].value.len(), 48);
        assert_eq!(r.measurements[0].algorithm, "SHA384");
        assert_eq!(r.details.get("verification_method").map(String::as_str), Some("intel_tiber"));
        assert_eq!(r.details.get("dbgstat").map(String::as_str), Some("disabled"));
        assert_eq!(r.details.get("attester_tcb_status").map(String::as_str), Some("OK"));
        assert_eq!(r.details.get("tdx_seamsvn").map(String::as_str), Some("3"));
        assert_eq!(
            r.details.get("attester_advisory_ids").map(String::as_str),
            Some("INTEL-SA-12345")
        );
    }

    #[test]
    fn projection_invalid_when_tcb_out_of_date() {
        let r = claims_to_attestation_result(&claims_with(Some("OutOfDate"), Some("disabled")))
            .unwrap();
        assert!(!r.valid);
        assert!(!r.cert_chain_valid);
    }

    #[test]
    fn projection_invalid_when_debug_enabled() {
        let r = claims_to_attestation_result(&claims_with(Some("OK"), Some("enabled"))).unwrap();
        assert!(!r.valid);
    }

    #[test]
    fn projection_rejects_non_hex_measurement() {
        let mut c = claims_with(Some("OK"), Some("disabled"));
        c.tdx_mrtd = Some("not-hex-bytes".to_string());
        assert!(claims_to_attestation_result(&c).is_err());
    }

    /// Live test requires `TIBER_API_URL` and `TIBER_API_KEY` env vars and a
    /// reachable Tiber Trust Authority endpoint. Run with:
    ///
    /// ```bash
    /// TIBER_API_URL=https://api.trustauthority.intel.com \
    /// TIBER_API_KEY=<key> \
    /// cargo test --features intel-tiber \
    ///   -p tenzro-tee intel_tiber::tests::live_nonce -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "requires TIBER_API_URL + TIBER_API_KEY and a reachable Tiber endpoint"]
    async fn live_nonce() {
        let url = std::env::var("TIBER_API_URL").expect("TIBER_API_URL");
        let key = std::env::var("TIBER_API_KEY").expect("TIBER_API_KEY");
        let client = IntelTiberClient::new(url, key).unwrap();
        let nonce = client.get_nonce().await.expect("nonce fetch");
        assert!(!nonce.val.is_empty());
        assert!(!nonce.iat.is_empty());
        assert!(!nonce.signature.is_empty());
    }
}
