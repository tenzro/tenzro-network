//! Every gossip payload must survive the wire format it is actually sent over.
//!
//! Gossip is bincode (`NetworkMessage::to_bytes`), which is **not
//! self-describing**: there are no field names on the wire, so the decoder
//! reads fields positionally. Two serde attributes are therefore unsound here
//! and produce no compile error, no test failure in any JSON-based test, and
//! no error at serialization time:
//!
//! - `skip_serializing_if` — the field is omitted, the decoder still reads one
//!   at that position, and every subsequent byte shifts.
//! - `flatten` — bincode cannot represent it at all.
//!
//! The damage is silent and delayed. A skipped `Option` near the end of an
//! embedded struct corrupts an enum discriminant several fields later, so the
//! error names a type that is entirely innocent. In production this read as
//! `tag for enum is not valid, found 64` and took provider discovery to zero
//! across every node simultaneously, while blocks and transactions kept
//! flowing — so the network looked healthy.
//!
//! These tests round-trip each broadcast payload through the real envelope.
//! They are deliberately built from `Default`, because the default is exactly
//! the case that breaks: `skip_serializing_if = "Option::is_none"` only omits
//! bytes when the value *is* `None`, which is the common case in the field and
//! the one a hand-built fixture with every field populated would miss.

use tenzro_network::message::{MessagePayload, NetworkMessage, ProviderAnnouncementMessage};

/// Round-trip a payload through the exact path gossip uses.
fn round_trip(payload: MessagePayload, what: &str) {
    let msg = NetworkMessage::new(payload);
    let bytes = msg
        .to_bytes()
        .unwrap_or_else(|e| panic!("{what}: serialization failed: {e}"));

    // Serialization succeeding proves nothing — `skip_serializing_if` writes
    // happily and only the decoder notices. The decode is the assertion.
    NetworkMessage::from_bytes(&bytes).unwrap_or_else(|e| {
        panic!(
            "{what}: {} bytes did not decode: {e}\n\
             This is the bincode/`skip_serializing_if` trap — check that no \
             field on this payload, or on any struct it embeds, carries \
             `skip_serializing_if` or `flatten`.",
            bytes.len()
        )
    });
}

/// The payload whose corruption took provider discovery to zero.
///
/// Built from `Default` on purpose: `capacity.jurisdiction` is `None` in the
/// default, and `None` is precisely when the byte went missing.
#[test]
fn a_default_provider_announcement_survives_the_wire() {
    round_trip(
        MessagePayload::ProviderAnnouncement(ProviderAnnouncementMessage::default()),
        "ProviderAnnouncement (default)",
    );
}

/// A populated announcement round-trips too, so the test does not merely
/// prove the empty case.
#[test]
fn a_populated_provider_announcement_survives_the_wire() {
    let mut ann = ProviderAnnouncementMessage {
        peer_id: "12D3KooWJ3hLCvmFdRB5KKXhfVEXVZw45b1Vs4kUq7TxStJZHubX".to_string(),
        provider_address: "0xabc".to_string(),
        provider_type: "ai".to_string(),
        served_models: vec!["qwen3.5-9b-mtp".to_string()],
        capabilities: vec!["inference".to_string()],
        rpc_endpoint: "http://127.0.0.1:8545".to_string(),
        status: "active".to_string(),
        ..Default::default()
    };
    // Nested defaults, so these stay assignments.
    ann.capacity.max_concurrent_requests = 8;
    ann.capacity.active_requests = 2;
    ann.trust_profile.identity_root = "tpm".to_string();

    round_trip(
        MessagePayload::ProviderAnnouncement(ann),
        "ProviderAnnouncement (populated)",
    );
}

/// A declared jurisdiction must survive the wire too.
///
/// `AdvertisedCapacity.jurisdiction` is `None` on every node today, which is
/// the only reason `JurisdictionClaim`'s own skipped field was not a second
/// outage waiting behind the first. The first operator to declare a
/// jurisdiction would have found it. Populate it here so that stays fixed.
#[test]
fn a_declared_jurisdiction_survives_the_wire() {
    let mut ann = ProviderAnnouncementMessage::default();
    ann.capacity.jurisdiction = Some(tenzro_types::model::JurisdictionClaim {
        country: "DE".to_string(),
        blocs: vec!["EU".to_string(), "EEA".to_string()],
        // `None` is the case that omitted a byte — keep it that way.
        attestation_hash: None,
        declared_at: Default::default(),
    });

    round_trip(
        MessagePayload::ProviderAnnouncement(ann),
        "ProviderAnnouncement (jurisdiction declared)",
    );
}

/// The size delta is the whole tell. A payload that serializes to *fewer*
/// bytes than it decodes is the signature of a skipped field, so pin the
/// property directly rather than only observing the decode error it causes.
#[test]
fn serializing_an_announcement_writes_every_field_it_reads() {
    let bytes = NetworkMessage::new(MessagePayload::ProviderAnnouncement(
        ProviderAnnouncementMessage::default(),
    ))
    .to_bytes()
    .expect("serialize");

    let decoded = NetworkMessage::from_bytes(&bytes).expect("decode");
    let reencoded = decoded.to_bytes().expect("re-serialize");

    assert_eq!(
        bytes.len(),
        reencoded.len(),
        "encode/decode/encode changed length — a field is being written that \
         is not read back, or vice versa"
    );
    assert_eq!(
        bytes, reencoded,
        "round-trip was not byte-stable; the wire form is not canonical"
    );
}
