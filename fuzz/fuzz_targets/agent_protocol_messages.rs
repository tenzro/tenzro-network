//! Fuzzes the agent-protocol messages a node takes from clients and other
//! agents: A2A requests with their signed DID envelope (metadata, task id,
//! canonical body digest and the signature check), A2A agent cards with
//! their signatures, and MCP client metadata documents with their client id.
//!
//! The first byte picks the message family. None of them may panic, and no
//! fuzzed envelope verifies against a wallet whose key nobody here holds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use tenzro_node::a2a::{agent_card, did_envelope};
use tenzro_node::mcp::client_metadata;

const METHODS: [&str; 6] = [
    "SendMessage",
    "SendStreamingMessage",
    "CancelTask",
    "GetTask",
    "tasks/pushNotificationConfig/set",
    "unknown",
];
const NOW_MS: i64 = 1_790_000_000_000;

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    match which % 3 {
        0 => {
            let Ok(params) = serde_json::from_slice::<Value>(rest) else {
                return;
            };
            let method = METHODS[(which as usize / 3) % METHODS.len()];
            let _ = did_envelope::requires_envelope(method);
            let _ = did_envelope::envelope_metadata(method, &params);
            let _ = did_envelope::envelope_task_id(method, &params);
            let _ = did_envelope::params_digest_hex(method, &params);
            // 0x5a.. is no key's wallet slot: neither a derived address left-aligned nor a key digest.
            let wallet = tenzro_types::Address::new([0x5a; 32]);
            assert!(
                did_envelope::verify_against_wallet(method, &params, wallet, NOW_MS).is_err(),
                "a fuzzed envelope verified against a wallet nobody holds"
            );
        }
        1 => {
            if let Ok(card) = serde_json::from_slice::<Value>(rest) {
                let _ = agent_card::canonical_payload(&card);
                let _ = agent_card::verify_agent_card(&card);
            }
        }
        _ => {
            let split = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
            let (id, body) = rest.split_at(split);
            if let Ok(id) = std::str::from_utf8(id) {
                let _ = client_metadata::parse_client_id_url(id);
                if let Ok(doc) = client_metadata::parse_document(id, body.get(1..).unwrap_or_default()) {
                    let _ = doc.allows_redirect("https://example.org/callback");
                }
            }
        }
    }
});
