//! Fuzzes gossip framing: any bytes a neighbour can publish.
//!
//! Properties:
//! - `validate_gossip_message` never panics, whatever the length prefixes,
//!   enum tags or nested payloads claim.
//! - A message that decodes re-encodes and decodes to the same value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_network::gossip_validation::validate_gossip_message;
use tenzro_network::message::NetworkMessage;

fuzz_target!(|data: &[u8]| {
    let _ = validate_gossip_message(data);
    if let Ok(msg) = NetworkMessage::from_bytes(data) {
        let bytes = msg.to_bytes().expect("a decoded message encodes");
        let again = NetworkMessage::from_bytes(&bytes).expect("an encoded message decodes");
        assert_eq!(again.to_bytes().expect("encodes"), bytes);
    }
});
