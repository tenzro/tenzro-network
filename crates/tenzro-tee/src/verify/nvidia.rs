//! NVIDIA GPU confidential-computing evidence, verified as part of the CPU
//! confidential VM it runs in.
//!
//! A GPU in CC mode is not a trust boundary by itself: the confidential VM is
//! created by SEV-SNP or TDX and the GPU is admitted into it. So a GPU claim is
//! only meaningful as a *composite*: "this GPU is inside this CVM". Evidence
//! is therefore two legs answering one challenge:
//!
//! - the CPU leg, a TDX quote or SNP report carried under [`CPU_ANCHOR_KEY`],
//!   verified in full by [`super::verify_report`] with the policy's report
//!   data;
//! - the GPU leg, the NVIDIA attestation service's detached EAT bundle under
//!   [`NRAS_TOKEN_KEY`]. Every token's ES384 signature is verified against the
//!   service key set the verifier was configured with
//!   ([`VerifyPolicy::nvidia_jwks`]), and every GPU's `eat_nonce` must equal
//!   the first 32 bytes of the CPU leg's report data. Those bytes are the
//!   SHA-256 of the verifier's packet (see [`crate::report_data`]), so both
//!   legs answer the same challenge and neither can be swapped in from another
//!   session.
//!
//! Every token must name the NVIDIA attestation service as its issuer, and
//! the device tokens must carry the same `jti` as the overall token that
//! covers them, so a device token cannot be carried over from an earlier
//! bundle that verified.
//!
//! Per GPU the token must also say: measurements matched their reference
//! values, the device report's signature and certificate chain verified, the
//! driver and VBIOS reference manifests' signatures verified and their
//! certificates are valid with a good OCSP status, secure boot is on, and
//! debug is disabled. The overall token's verdict must be true.

use std::collections::BTreeMap;

use serde_json::Value;
use tenzro_types::tee::{AttestationReport, TeeVendor};

use super::{VerifiedAttestation, VerifyPolicy, fail};
use crate::error::Result;

/// Metadata key holding the CPU leg, a JSON `AttestationReport`.
pub const CPU_ANCHOR_KEY: &str = "cpu_anchor";
/// Metadata key holding the NVIDIA attestation service's EAT bundle.
pub const NRAS_TOKEN_KEY: &str = "nras_token";

fn b64url(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|e| fail(format!("JWT base64: {e}")))
}

/// The issuer every NRAS token must name. Without this a token signed by any
/// key in the configured set passes, whatever service issued it.
const NRAS_ISSUER: &str = "https://nras.attestation.nvidia.com";

/// Verify a raw (`r || s`) ES384 signature by the SEC1 P-384 public key
/// `sec1` over `signed`.
fn verify_es384(sec1: &[u8], signed: &[u8], signature: &[u8]) -> Result<()> {
    use p384::ecdsa::signature::Verifier;
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|_| fail("JWK is not a P-384 point"))?;
    let sig = p384::ecdsa::Signature::from_slice(signature)
        .map_err(|_| fail("JWT signature is not a raw ES384 signature"))?;
    vk.verify(signed, &sig)
        .map_err(|_| fail("NVIDIA token signature does not verify"))
}

/// Verify one ES384 JWT against `jwks` and return its claims.
fn verify_jwt(token: &str, jwks: &Value, now: u64) -> Result<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts.as_slice() else {
        return Err(fail("JWT does not have three parts"));
    };
    let header: Value =
        serde_json::from_slice(&b64url(h)?).map_err(|e| fail(format!("JWT header: {e}")))?;
    if header.get("alg").and_then(Value::as_str) != Some("ES384") {
        return Err(fail("NVIDIA token is not ES384"));
    }
    let kid = header.get("kid").and_then(Value::as_str);
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("JWKS has no keys"))?;
    let key = keys
        .iter()
        .find(|k| kid.is_some() && k.get("kid").and_then(Value::as_str) == kid)
        .ok_or_else(|| fail("no JWKS key for this token's kid"))?;
    if key.get("crv").and_then(Value::as_str) != Some("P-384") {
        return Err(fail("JWKS key is not P-384"));
    }
    let x = b64url(
        key.get("x")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("JWK x"))?,
    )?;
    let y = b64url(
        key.get("y")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("JWK y"))?,
    )?;
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    verify_es384(&sec1, format!("{h}.{p}").as_bytes(), &b64url(s)?)?;

    let claims: Value =
        serde_json::from_slice(&b64url(p)?).map_err(|e| fail(format!("JWT claims: {e}")))?;
    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("token has no exp"))?;
    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("token has no iat"))?;
    if now > exp || iat > now + 60 {
        return Err(fail("NVIDIA token is expired or not yet valid"));
    }
    let iss = claims
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if iss.trim_end_matches('/') != NRAS_ISSUER {
        return Err(fail(format!(
            "NVIDIA token was issued by '{iss}', not the attestation service"
        )));
    }
    Ok(claims)
}

fn claim_true(c: &Value, name: &str) -> Result<()> {
    if c.get(name).and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        Err(fail(format!("GPU claim {name} is not true")))
    }
}

fn cert_chain_good(c: &Value, name: &str) -> Result<()> {
    let chain = c
        .get(name)
        .ok_or_else(|| fail(format!("GPU claim {name} is missing")))?;
    let status = chain.get("x-nvidia-cert-status").and_then(Value::as_str);
    let ocsp = chain
        .get("x-nvidia-cert-ocsp-status")
        .and_then(Value::as_str);
    if status != Some("valid") || ocsp != Some("good") {
        return Err(fail(format!("{name} is not valid with a good OCSP status")));
    }
    Ok(())
}

/// Verify the GPU leg: the NRAS bundle against `jwks`, every GPU answering
/// `nonce_hex`. Returns the per-GPU `ueid`s.
pub fn verify_gpu_leg(
    bundle_json: &str,
    jwks: &Value,
    nonce_hex: &str,
    now: u64,
) -> Result<Vec<String>> {
    let bundle: Value =
        serde_json::from_str(bundle_json).map_err(|e| fail(format!("NRAS bundle: {e}")))?;
    let outer = bundle
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or_else(|| fail("NRAS bundle is not a detached EAT pair"))?;
    let overall_token = outer[0]
        .as_array()
        .and_then(|p| p.get(1))
        .and_then(Value::as_str)
        .ok_or_else(|| fail("NRAS bundle has no overall token"))?;
    let overall = verify_jwt(overall_token, jwks, now)?;
    claim_true(&overall, "x-nvidia-overall-att-result")?;
    let bundle_id = overall
        .get("jti")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("NRAS overall token has no jti"))?;

    let devices = outer[1]
        .as_object()
        .ok_or_else(|| fail("NRAS bundle has no device tokens"))?;
    let mut ueids = Vec::new();
    for token in devices.values().filter_map(Value::as_str) {
        let c = verify_jwt(token, jwks, now)?;
        if c.get("jti").and_then(Value::as_str) != Some(bundle_id) {
            return Err(fail("a GPU token belongs to a different NRAS bundle"));
        }
        if c.get("eat_nonce")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            != Some(nonce_hex.to_ascii_lowercase())
        {
            return Err(fail(
                "GPU evidence answers a different challenge than the CPU leg",
            ));
        }
        if !c
            .get("measres")
            .and_then(Value::as_str)
            .is_some_and(|m| m.eq_ignore_ascii_case("success"))
        {
            return Err(fail("GPU measurements do not match their reference values"));
        }
        claim_true(&c, "x-nvidia-gpu-attestation-report-signature-verified")?;
        claim_true(&c, "x-nvidia-gpu-attestation-report-nonce-match")?;
        claim_true(&c, "x-nvidia-gpu-arch-check")?;
        claim_true(&c, "x-nvidia-gpu-driver-rim-signature-verified")?;
        claim_true(&c, "x-nvidia-gpu-vbios-rim-signature-verified")?;
        claim_true(&c, "secboot")?;
        cert_chain_good(&c, "x-nvidia-gpu-attestation-report-cert-chain")?;
        cert_chain_good(&c, "x-nvidia-gpu-driver-rim-cert-chain")?;
        cert_chain_good(&c, "x-nvidia-gpu-vbios-rim-cert-chain")?;
        if c.get("dbgstat").and_then(Value::as_str) != Some("disabled") {
            return Err(fail("GPU debug is not disabled"));
        }
        ueids.push(
            c.get("ueid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        );
    }
    if ueids.is_empty() {
        return Err(fail("NRAS bundle carries no device tokens"));
    }
    Ok(ueids)
}

/// Verify a composite CPU + GPU report.
pub fn verify_composite(
    report: &AttestationReport,
    policy: &VerifyPolicy,
) -> Result<VerifiedAttestation> {
    let jwks: Value = serde_json::from_str(
        policy
            .nvidia_jwks
            .as_deref()
            .ok_or_else(|| fail("no NVIDIA attestation key set is configured"))?,
    )
    .map_err(|e| fail(format!("NVIDIA JWKS: {e}")))?;
    let cpu: AttestationReport = serde_json::from_str(
        report
            .metadata
            .get(CPU_ANCHOR_KEY)
            .ok_or_else(|| fail("GPU evidence carries no CPU confidential-VM report"))?,
    )
    .map_err(|e| fail(format!("CPU leg: {e}")))?;
    if !matches!(cpu.vendor, TeeVendor::IntelTdx | TeeVendor::AmdSevSnp) {
        return Err(fail(
            "a GPU can only be admitted inside a TDX or SEV-SNP VM",
        ));
    }
    let cpu_verified = super::verify_report(&cpu, policy)?;
    if policy.expected_user_data.len() < 32 {
        return Err(fail("composite challenge must be at least 32 bytes"));
    }
    let nonce_hex = hex::encode(&policy.expected_user_data[..32]);
    let bundle = report
        .metadata
        .get(NRAS_TOKEN_KEY)
        .ok_or_else(|| fail("GPU evidence carries no NVIDIA attestation token"))?;
    let ueids = verify_gpu_leg(bundle, &jwks, &nonce_hex, policy.now)?;

    let mut details: BTreeMap<String, String> = cpu_verified.details.clone();
    details.insert(
        "cpu_vendor".into(),
        cpu_verified.vendor.as_str().to_string(),
    );
    details.insert("gpu_ueids".into(), ueids.join(","));
    Ok(VerifiedAttestation {
        vendor: TeeVendor::NvidiaGpu,
        measurement: cpu_verified.measurement.clone(),
        user_data: cpu_verified.user_data.clone(),
        tcb_status: cpu_verified.tcb_status.clone(),
        platform_id: cpu_verified.platform_id.clone(),
        measurements: cpu_verified.measurements,
        details,
    })
}

#[cfg(test)]
mod tests {
    //! Tokens are built in the NVIDIA claims format and signed with a test
    //! ES384 key published in a test JWKS; the CPU leg is a test SEV-SNP
    //! report under a test ARK, verified with the same code as production.

    use super::*;
    use p384::ecdsa::signature::Signer;

    const NOW: u64 = 1_800_000_000;

    /// Wycheproof `ecdsa_secp384r1_sha384_p1363_test` (C2SP/wycheproof,
    /// `testvectors_v1`) against the ES384 check every NRAS token goes
    /// through: `valid` verifies, `invalid` does not.
    #[test]
    fn es384_wycheproof_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/ecdsa_secp384r1_sha384_p1363_test.json"
        );
        let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let (mut total, mut failures) = (0usize, Vec::new());
        for g in file["testGroups"].as_array().unwrap() {
            let pk = hex::decode(g["publicKey"]["uncompressed"].as_str().unwrap()).unwrap();
            for t in g["tests"].as_array().unwrap() {
                let want = match t["result"].as_str() {
                    Some("valid") => true,
                    Some("invalid") => false,
                    _ => continue,
                };
                total += 1;
                let msg = hex::decode(t["msg"].as_str().unwrap()).unwrap();
                let sig = hex::decode(t["sig"].as_str().unwrap()).unwrap();
                let got = verify_es384(&pk, &msg, &sig).is_ok();
                if got != want {
                    failures.push(format!("tc {}: says {got}, expected {want}", t["tcId"]));
                }
            }
        }
        assert!(total > 0, "no vectors were read");
        assert!(
            failures.is_empty(),
            "{} of {total}: {failures:?}",
            failures.len()
        );
    }

    fn service_key() -> p384::ecdsa::SigningKey {
        p384::ecdsa::SigningKey::from_slice(&[0x61; 48]).unwrap()
    }

    fn b64(b: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    pub(crate) fn jwks() -> String {
        let p = service_key().verifying_key().to_sec1_point(false);
        let b = p.as_bytes();
        serde_json::json!({"keys":[{"kid":"nras-1","kty":"EC","crv":"P-384","x":b64(&b[1..49]),"y":b64(&b[49..97])}]})
            .to_string()
    }

    fn jwt(claims: Value, key: &p384::ecdsa::SigningKey) -> String {
        let h = b64(br#"{"alg":"ES384","kid":"nras-1"}"#);
        let p = b64(claims.to_string().as_bytes());
        let sig: p384::ecdsa::Signature = key.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", b64(&sig.to_bytes()))
    }

    fn good_chain() -> Value {
        serde_json::json!({"x-nvidia-cert-status":"valid","x-nvidia-cert-ocsp-status":"good"})
    }

    pub(crate) fn gpu_claims(nonce_hex: &str) -> Value {
        serde_json::json!({
            "iat": NOW - 10, "exp": NOW + 3600, "eat_nonce": nonce_hex, "measres": "success",
            "iss": "https://nras.attestation.nvidia.com", "jti": "bundle-1",
            "ueid": "gpu-ueid-1", "secboot": true, "dbgstat": "disabled",
            "x-nvidia-gpu-attestation-report-signature-verified": true,
            "x-nvidia-gpu-attestation-report-nonce-match": true,
            "x-nvidia-gpu-arch-check": true,
            "x-nvidia-gpu-driver-rim-signature-verified": true,
            "x-nvidia-gpu-vbios-rim-signature-verified": true,
            "x-nvidia-gpu-attestation-report-cert-chain": good_chain(),
            "x-nvidia-gpu-driver-rim-cert-chain": good_chain(),
            "x-nvidia-gpu-vbios-rim-cert-chain": good_chain(),
        })
    }

    pub(crate) fn bundle(gpu: Value, key: &p384::ecdsa::SigningKey) -> String {
        let overall = serde_json::json!({
            "iat": NOW - 10, "exp": NOW + 3600, "x-nvidia-overall-att-result": true,
            "iss": "https://nras.attestation.nvidia.com", "jti": "bundle-1",
        });
        serde_json::json!([["JWT", jwt(overall, key)], {"GPU-0": jwt(gpu, key)}]).to_string()
    }

    #[test]
    fn a_signed_bundle_answering_the_nonce_verifies() {
        let jwks: Value = serde_json::from_str(&jwks()).unwrap();
        let b = bundle(gpu_claims("ab"), &service_key());
        assert_eq!(
            verify_gpu_leg(&b, &jwks, "ab", NOW).unwrap(),
            vec!["gpu-ueid-1"]
        );
    }

    #[test]
    fn an_unsigned_or_foreign_token_is_refused() {
        let jwks: Value = serde_json::from_str(&jwks()).unwrap();
        let other = p384::ecdsa::SigningKey::from_slice(&[0x62; 48]).unwrap();
        assert!(verify_gpu_leg(&bundle(gpu_claims("ab"), &other), &jwks, "ab", NOW).is_err());
        let unsigned = format!(
            "{}.{}.",
            b64(br#"{"alg":"none"}"#),
            b64(gpu_claims("ab").to_string().as_bytes())
        );
        let b = serde_json::json!([["JWT", unsigned.clone()], {"GPU-0": unsigned}]).to_string();
        assert!(verify_gpu_leg(&b, &jwks, "ab", NOW).is_err());
    }

    #[test]
    fn a_gpu_answering_another_nonce_is_refused() {
        let jwks: Value = serde_json::from_str(&jwks()).unwrap();
        let b = bundle(gpu_claims("cd"), &service_key());
        assert!(verify_gpu_leg(&b, &jwks, "ab", NOW).is_err());
    }

    #[test]
    fn a_debuggable_gpu_or_a_revoked_manifest_is_refused() {
        let jwks: Value = serde_json::from_str(&jwks()).unwrap();
        let mut c = gpu_claims("ab");
        c["dbgstat"] = "enabled".into();
        assert!(verify_gpu_leg(&bundle(c, &service_key()), &jwks, "ab", NOW).is_err());
        let mut c = gpu_claims("ab");
        c["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-ocsp-status"] = "revoked".into();
        assert!(verify_gpu_leg(&bundle(c, &service_key()), &jwks, "ab", NOW).is_err());
    }

    #[test]
    fn a_composite_needs_a_verified_cpu_leg() {
        let mut report = AttestationReport {
            vendor: TeeVendor::NvidiaGpu,
            ..Default::default()
        };
        report.metadata.insert(
            NRAS_TOKEN_KEY.into(),
            bundle(gpu_claims("ab"), &service_key()),
        );
        let mut policy = VerifyPolicy::now(vec![0xAB; 64]);
        policy.nvidia_jwks = Some(jwks());
        assert!(verify_composite(&report, &policy).is_err(), "no CPU leg");
        let cpu = AttestationReport {
            vendor: TeeVendor::AmdSevSnp,
            attestation_data: vec![0; 1184],
            ..Default::default()
        };
        report
            .metadata
            .insert(CPU_ANCHOR_KEY.into(), serde_json::to_string(&cpu).unwrap());
        assert!(
            verify_composite(&report, &policy).is_err(),
            "unsigned CPU leg"
        );
    }

    /// A token signed by a configured key but issued by something other than
    /// the attestation service does not stand in for one it issued.
    #[test]
    fn a_token_from_another_issuer_is_refused() {
        let jwks: Value = serde_json::from_str(&jwks()).unwrap();
        let mut c = gpu_claims("ab");
        c["iss"] = "https://attacker.example".into();
        assert!(verify_gpu_leg(&bundle(c, &service_key()), &jwks, "ab", NOW).is_err());
    }

    /// A device token from an earlier bundle cannot be carried into a new one:
    /// the overall token is what says this attestation happened, and the
    /// device tokens must belong to it.
    #[test]
    fn a_device_token_from_another_bundle_is_refused() {
        let jwks: Value = serde_json::from_str(&jwks()).unwrap();
        let mut c = gpu_claims("ab");
        c["jti"] = "bundle-0".into();
        assert!(verify_gpu_leg(&bundle(c, &service_key()), &jwks, "ab", NOW).is_err());
    }

    /// Nothing configured means nothing verifies, rather than a GPU report
    /// being taken at its word.
    #[test]
    fn without_a_configured_key_set_gpu_evidence_is_refused() {
        let report = AttestationReport {
            vendor: TeeVendor::NvidiaGpu,
            ..Default::default()
        };
        let policy = VerifyPolicy {
            nvidia_jwks: None,
            ..VerifyPolicy::now(vec![0; 64])
        };
        assert!(verify_composite(&report, &policy).is_err());
    }
}
