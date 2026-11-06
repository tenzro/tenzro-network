//! The message a payer signs for a `tenzro-hybrid` x402 requirement, as the
//! facilitator rebuilds it, pinned in sdk/fixtures/payments so the payer SDKs
//! sign the same bytes. Rewrite the vector with `TENZRO_WRITE_VECTORS=1`.

use std::path::Path;

use tenzro_payments::payer_auth::{authorization_message, payer_account};
use tenzro_payments::x402::X402PaymentRequirement;
use tenzro_payments::x402::wire::{self, CHALLENGE_ID_KEY};

#[test]
fn the_hybrid_authorization_vector_is_what_the_facilitator_verifies() {
    let mut requirement = X402PaymentRequirement::new(
        "tenzro-hybrid",
        "tenzro:1337",
        "90071992547409930",
        "0909090909090909090909090909090909090909090909090909090909090909",
        "TNZO",
        300,
    );
    requirement.set_extra(
        CHALLENGE_ID_KEY,
        serde_json::json!("c0ffee00-0000-4000-8000-000000000002"),
    );
    let resource = "https://pub.example/articles/2";
    let public_key = [0x42u8; 64];
    let max_amount: u128 = 90_071_992_547_409_930;

    let challenge = wire::challenge_from_requirement(&requirement, resource).unwrap();
    let payer = payer_account(&public_key);
    let message =
        authorization_message(&challenge, &payer, max_amount, &requirement.asset).unwrap();
    let vector = serde_json::json!({
        "description": "The message a payer signs (context tenzro/payment/authorization) for a tenzro-hybrid requirement, as the facilitator rebuilds the challenge from the requirement and the payload's resource.",
        "requirement": requirement,
        "resource": { "url": resource },
        "public_key": hex::encode(public_key),
        "max_amount": max_amount.to_string(),
        "payer_address": hex::encode(payer.as_bytes()),
        "message": hex::encode(&message),
    });
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/fixtures/payments/x402_hybrid_authorization.json");
    if std::env::var_os("TENZRO_WRITE_VECTORS").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&vector).unwrap() + "\n").unwrap();
    }
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(pinned, vector);
}

#[test]
fn the_challenge_authorization_vector_is_what_the_gateway_verifies() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/fixtures/payments/challenge_authorization.json");
    let pinned: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let challenge: tenzro_payments::types::PaymentChallenge =
        serde_json::from_value(pinned["challenge"].clone()).unwrap();
    let public_key = hex::decode(pinned["public_key"].as_str().unwrap()).unwrap();
    let max_amount: u128 = pinned["max_amount"].as_str().unwrap().parse().unwrap();

    let payer = payer_account(&public_key);
    assert_eq!(
        hex::encode(payer.as_bytes()),
        pinned["payer_address"].as_str().unwrap()
    );
    let message = authorization_message(&challenge, &payer, max_amount, &challenge.asset).unwrap();
    assert_eq!(hex::encode(&message), pinned["message"].as_str().unwrap());
}
