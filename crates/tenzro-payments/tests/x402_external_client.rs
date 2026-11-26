//! An x402 client that knows nothing of Tenzro completes a paid request.
//!
//! The client side below is written from the x402 version 2 wire format
//! alone: it reads the `PAYMENT-REQUIRED` header as plain JSON, picks an
//! option it can pay, and answers with a `PAYMENT-SIGNATURE` header made of
//! plain JSON. No Tenzro type touches it. The server side then turns that
//! header into the credential its gate settles, and refuses a client that
//! changed the option it chose.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};
use tenzro_payments::PaymentChallenge;
use tenzro_payments::x402::wire::{
    check_accepted_matches, credential_from_header, payment_required_for, requirement_for,
};

fn challenge() -> PaymentChallenge {
    let mut extra = HashMap::new();
    extra.insert("scheme".to_string(), json!("exact-eip3009"));
    extra.insert("network".to_string(), json!("eip155:8453"));
    PaymentChallenge {
        challenge_id: "ch-ext-1".into(),
        protocol: "x402".into(),
        resource: "/v1/chat/completions".into(),
        amount: 2_500,
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
        recipient: "0x1111111111111111111111111111111111111111".into(),
        chain: "base".into(),
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(120),
        extra,
    }
}

/// What any x402 version 2 client does with a `PAYMENT-REQUIRED` header.
fn external_client_pays(payment_required_header: &str) -> String {
    let body: Value =
        serde_json::from_slice(&BASE64.decode(payment_required_header).unwrap()).unwrap();
    assert_eq!(body["x402Version"], 2);
    let option = body["accepts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["scheme"] == "exact")
        .or_else(|| {
            body["accepts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["scheme"] == "exact-eip3009")
        })
        .expect("an option this client can pay")
        .clone();
    let signed = json!({
        "x402Version": 2,
        "resource": body["resource"],
        "accepted": option,
        "payload": {
            "signature": format!("0x{}", "ab".repeat(65)),
            "authorization": {
                "from": "0x2222222222222222222222222222222222222222",
                "to": option["payTo"],
                "value": option["amount"],
                "validAfter": "0",
                "validBefore": "4102444800",
                "nonce": format!("0x{}", "cd".repeat(32)),
            }
        }
    });
    BASE64.encode(serde_json::to_vec(&signed).unwrap())
}

/// The header the node sends is plain JSON a client reads without Tenzro
/// code, the client's answer becomes the credential the gate settles, and
/// a client that swaps the network it chose is refused.
#[test]
fn an_external_x402_client_completes_a_paid_request() {
    let ch = challenge();
    let required = payment_required_for(&ch).to_base64().unwrap();
    let signature = external_client_pays(&required);

    let credential = credential_from_header(&signature).unwrap();
    assert_eq!(credential.challenge_id, "ch-ext-1");
    assert_eq!(credential.protocol, "x402");
    assert_eq!(credential.amount, 2_500);
    assert_eq!(
        credential.payer_address,
        "0x2222222222222222222222222222222222222222"
    );

    let mut answer: Value = serde_json::from_slice(&BASE64.decode(&signature).unwrap()).unwrap();
    let payload =
        tenzro_payments::x402::payment_payload::X402PaymentPayload::from_base64(&signature)
            .unwrap();
    check_accepted_matches(&payload, &requirement_for(&ch)).unwrap();

    answer["accepted"]["network"] = json!("eip155:1");
    let swapped = BASE64.encode(serde_json::to_vec(&answer).unwrap());
    let payload =
        tenzro_payments::x402::payment_payload::X402PaymentPayload::from_base64(&swapped).unwrap();
    assert!(check_accepted_matches(&payload, &requirement_for(&ch)).is_err());
}
