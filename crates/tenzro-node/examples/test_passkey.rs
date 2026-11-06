//! A software operator passkey for PRIVATE TEST NETWORKS ONLY: it enrols and signs transport grants for the
//! delegated-TPM provider tests, standing in for the person who would approve with a hardware passkey. The key is a
//! fixed fixture derived from a seed, never a secret and never used on a real network. It only builds with the
//! `test-passkey` feature, which no default, release or deploy build enables, and it refuses to run unless
//! TENZRO_TEST_PASSKEY=private-test-network is set.
//!
//!   test_passkey enrol --seed N --label L            prints the enrolment (public key, relying party, label) as JSON
//!   test_passkey grant --seed N --endpoint HEX64 --label L --not-after-ms MS    prints the transport grant as JSON
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::{Digest, Sha256};
use tenzro_node::remote_tpm::{TransportGrant, grant_challenge};

const RP_ID: &str = "operator.example";

fn arg(args: &[String], name: &str) -> String {
    let i = args.iter().position(|a| a == name).unwrap_or_else(|| {
        eprintln!("missing {name}");
        std::process::exit(2)
    });
    args.get(i + 1).cloned().unwrap_or_else(|| {
        eprintln!("{name} needs a value");
        std::process::exit(2)
    })
}

fn main() {
    if std::env::var("TENZRO_TEST_PASSKEY").as_deref() != Ok("private-test-network") {
        eprintln!(
            "refused: test fixture, set TENZRO_TEST_PASSKEY=private-test-network on a private test network"
        );
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let seed: u8 = arg(&args, "--seed").parse().expect("seed 0-255");
    let key = SigningKey::from_slice(&[seed.max(1); 32]).expect("fixture key");
    let label = arg(&args, "--label");
    match args.first().map(String::as_str) {
        Some("enrol") => {
            let xy = key.verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec();
            println!(
                "{}",
                serde_json::json!({"public_key_xy": hex::encode(xy), "rp_id": RP_ID, "label": label})
            );
        }
        Some("grant") => {
            let ep: [u8; 32] = hex::decode(arg(&args, "--endpoint"))
                .ok()
                .and_then(|v| v.try_into().ok())
                .expect("--endpoint is 64 hex characters");
            let not_after_ms: u64 = arg(&args, "--not-after-ms").parse().expect("milliseconds");
            let challenge = grant_challenge(&ep, &label, not_after_ms);
            let cdj = serde_json::json!({
                "type": "webauthn.get",
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": format!("https://{RP_ID}"),
            })
            .to_string()
            .into_bytes();
            let mut ad = Sha256::digest(RP_ID.as_bytes()).to_vec();
            ad.push(0x05);
            ad.extend_from_slice(&[0, 0, 0, 1]);
            let hash = tenzro_crypto::webauthn::webauthn_signed_hash(&ad, &cdj);
            let sig: p256::ecdsa::Signature = key.sign_prehash(&hash).expect("sign");
            let grant = TransportGrant {
                endpoint_id: hex::encode(ep),
                label,
                not_after_ms,
                credential_id: URL_SAFE_NO_PAD.encode(b"cred"),
                authenticator_data: URL_SAFE_NO_PAD.encode(&ad),
                client_data_json: URL_SAFE_NO_PAD.encode(&cdj),
                signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            };
            println!("{}", serde_json::to_string(&grant).expect("json"));
        }
        _ => {
            eprintln!("usage: test_passkey enrol|grant ...");
            std::process::exit(2);
        }
    }
}
