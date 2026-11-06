//! Fuzzes what a peer can send on the request, consensus and discovery
//! streams before any handler runs: the length-prefixed framing and the
//! discovery request body, plus the operator boot list.
//!
//! Properties:
//! - framing never panics, refuses a length above the limit, and returns
//!   exactly the announced bytes only when they all arrived;
//! - no decoder panics, whatever the length prefixes claim.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;

const LIMIT: usize = 1 << 20;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    })
}

fn announced(data: &[u8], big_endian: bool) -> Option<usize> {
    let len: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(if big_endian {
        u32::from_be_bytes(len)
    } else {
        u32::from_le_bytes(len)
    } as usize)
}

fuzz_target!(|data: &[u8]| {
    let rt = runtime();
    if let Ok(body) = rt.block_on(tenzro_iroh::request::read_request(&mut &data[..], LIMIT)) {
        let len = announced(data, false).expect("a request has a length");
        assert!(len <= LIMIT && body.len() == len && body[..] == data[4..4 + len]);
    }
    if let Ok(frame) = rt.block_on(tenzro_iroh::consensus::read_frame(&mut &data[..], LIMIT)) {
        let len = announced(data, true).expect("a frame has a length");
        assert!(len <= LIMIT && frame.len() == len && frame[..] == data[4..4 + len]);
    }
    let _ = serde_json::from_slice::<tenzro_iroh::discovery::DiscoveryRequest>(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = tenzro_iroh::identity_record::parse_boot_list(text);
    }
});
