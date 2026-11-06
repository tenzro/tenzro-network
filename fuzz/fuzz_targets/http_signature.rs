//! Fuzzes HTTP message signatures (RFC 9421) as a node receives them: the
//! `Signature-Input` and `Signature` headers, the signature base built from
//! the request, verification under every algorithm, and the agent request
//! check.
//!
//! Input: request line fields, then `name: value` header lines, then an
//! empty line and the body. The key the signature is checked against comes
//! from the `x-fuzz-key` header (hex), so key parsing is covered too.
//! Property: nothing panics, and no request verifies (the fuzzer holds no
//! key that signed it).

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_payments::rfc9421::agent::{AgentKeyResolution, agent_key_of, verify_agent_request};
use tenzro_payments::rfc9421::{
    RequestParts, SignatureAlgorithm, SignedHeaders, build_signature_base, parse_signature_input,
    verify_http_signature,
};

const ALGORITHMS: [&str; 7] = [
    "ed25519",
    "ecdsa-p256-sha256",
    "ecdsa-p384-sha384",
    "rsa-pss-sha256",
    "rsa-pss-sha512",
    "rsa-v1_5-sha256",
    "hmac-sha256",
];

fn request(text: &str) -> (RequestParts, Option<&str>) {
    let (head, body) = match text.split_once("\n\n") {
        Some((h, b)) => (h, Some(b)),
        None => (text, None),
    };
    let mut lines = head.lines();
    let mut parts = RequestParts::for_request(
        lines.next().unwrap_or_default(),
        lines.next().unwrap_or_default(),
        lines.next().unwrap_or_default(),
    )
    .with_query(lines.next().unwrap_or_default());
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            parts = parts.with_header(k.trim().to_ascii_lowercase(), v.trim());
        }
    }
    (parts, body)
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let (parts, body) = request(text);
    if let Some(raw) = parts.headers.get("signature-input")
        && let Ok(parsed) = parse_signature_input(raw)
    {
        let _ = build_signature_base(&parts, &parsed);
        let algorithm =
            SignatureAlgorithm::from_str(ALGORITHMS[usize::from(which) % ALGORITHMS.len()])
                .expect("known algorithm");
        let signature_bytes = parts
            .headers
            .get("signature")
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let key = parts
            .headers
            .get("x-fuzz-key")
            .and_then(|k| hex::decode(k).ok())
            .unwrap_or_default();
        let signed = SignedHeaders {
            signature_input_raw: raw.clone(),
            signature_bytes,
            parsed,
        };
        let verified = verify_http_signature(&parts, &signed, &key, &algorithm);
        if !matches!(algorithm, SignatureAlgorithm::HmacSha256) {
            assert!(
                verified.is_err(),
                "a signature verified under a key the fuzzer chose"
            );
        }
    }
    let _ = agent_key_of(&parts);
    let resolution = AgentKeyResolution {
        agent_did: "did:tenzro:machine:fuzz".into(),
        root: "did:tenzro:human:fuzz".into(),
        keyid: "fuzz".into(),
        public_key: hex::encode([7u8; 64]),
        machine_did: "did:tenzro:machine:fuzz".into(),
        key_certification: String::new(),
        mandate: "00".into(),
        terms_version: 1,
        expires_at_ms: None,
        revoked: false,
        quarantined: false,
    };
    assert!(
        verify_agent_request(&parts, body.map(str::as_bytes), &resolution, 1_790_000_000).is_err()
    );
});
