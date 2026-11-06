//! Fuzzes x402 payment headers a node receives: `PAYMENT-SIGNATURE`,
//! `PAYMENT-REQUIRED` and `PAYMENT-RESPONSE` values, the credential built
//! from a payment payload, and ERC-7710 redemption proofs with their
//! delegation chains.
//!
//! Property: nothing panics, and no fuzzed delegation chain verifies.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_payments::x402::erc7710::{
    Erc7710DelegationVerifier, RedemptionContext, decode_redemption_proof, recover_signer,
};
use tenzro_payments::x402::{
    X402PaymentPayload, X402PaymentRequired, X402SettlementResponse, wire,
};

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        let _ = recover_signer(&[7; 32], rest);
        return;
    };
    match which % 4 {
        0 => {
            if let Ok(payload) = X402PaymentPayload::from_base64(text) {
                let _ = wire::credential_from_payload(&payload);
                let _ = payload.to_base64();
            }
            let _ = wire::credential_from_header(text);
        }
        1 => {
            if let Ok(required) = X402PaymentRequired::from_base64(text) {
                let _ = required.to_base64();
            }
            let _ = X402SettlementResponse::from_base64(text);
        }
        2 => {
            if let Ok(proof) = decode_redemption_proof(text) {
                let ctx = RedemptionContext {
                    target: None,
                    selector: [0xa9, 0x05, 0x9c, 0xbb],
                    amount: 1,
                    timestamp: 1_790_000_000,
                };
                assert!(
                    Erc7710DelegationVerifier::default()
                        .verify_chain(&proof.chain, &ctx)
                        .is_err(),
                    "a fuzzed delegation chain verified"
                );
            }
        }
        _ => {
            let _ = recover_signer(&[7; 32], rest);
        }
    }
});
