//! Fuzzes identity material a node takes from outside: DIDs, DID documents,
//! signed DID envelopes, delegation scopes, KERI events and the ABI-encoded
//! answers of agent registries.
//!
//! The first byte picks the decoder; the property is that none of them
//! panics, whatever the input claims.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tenzro_identity::delegation::{DelegationEntry, DelegationScope};
use tenzro_identity::erc8004::abi;
use tenzro_identity::keri::KeriEvent;
use tenzro_identity::{DidDocument, TenzroDid, TenzroDidEnvelope};

fn p256_xy() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| {
        let pair = tenzro_crypto::P256KeyPair::from_secret_bytes(&[7; 32]).expect("scalar");
        pair.public_key_sec1()[1..].to_vec()
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let text = std::str::from_utf8(rest).ok();
    match which % 6 {
        0 => {
            if let Some(t) = text {
                let _ = TenzroDid::parse(t);
            }
        }
        1 => {
            if let Ok(doc) = serde_json::from_slice::<DidDocument>(rest) {
                let _ = tenzro_identity::extract_public_keys_from_document(&doc);
            }
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(rest) {
                let _ = tenzro_identity::envelope::p256_from_did_document(&value);
            }
        }
        2 => {
            if let Some(t) = text
                && let Ok(env) = TenzroDidEnvelope::from_header_value(t)
            {
                let _ = tenzro_identity::envelope::verify_envelope_with_key(&env, p256_xy());
                let _ = tenzro_identity::envelope::verify_envelope_ethr(&env);
                let _ = tenzro_identity::canonical_preimage(&env);
            }
        }
        3 => {
            if let Ok(scope) = serde_json::from_slice::<DelegationScope>(rest) {
                let child = scope.attenuate(&DelegationScope::unrestricted());
                let _ = DelegationScope::unrestricted().attenuate(&scope);
                let _ = scope.attenuate(&child);
                let _ = scope.is_active();
                let _ = scope.is_value_allowed(u128::MAX);
                let _ = scope.is_operation_allowed("transfer");
                let _ = scope.is_protocol_allowed("x402");
                let _ = scope.is_chain_allowed("tenzro");
            }
            if let Ok(entry) = serde_json::from_slice::<DelegationEntry>(rest) {
                let _ = entry.is_active();
            }
        }
        4 => {
            let mut events = serde_json::Deserializer::from_slice(rest).into_iter::<KeriEvent>();
            if let Some(Ok(prior)) = events.next() {
                let _ = prior.verify_said();
                if let Some(Ok(next)) = events.next() {
                    let _ = next.verify_said();
                    let _ = next.is_valid_rotation_of(&prior);
                }
            }
        }
        _ => {
            let _ = abi::decode_get_agent_uri(rest);
            let _ = abi::decode_get_agent_wallet(rest);
            let _ = abi::decode_is_feedback_revoked(rest);
            let _ = abi::decode_get_feedback_responses(rest);
            let _ = abi::decode_get_metadata(rest);
            let _ = abi::decode_get_feedback(rest);
            let _ = abi::decode_get_feedback_count(rest);
            let _ = abi::decode_get_validation(rest);
            let _ = abi::decode_get_agent(rest);
        }
    }
});
