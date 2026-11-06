//! Machine identities bound to transport endpoint keys.
//!
//! A node is addressed by its machine identity, `did:tenzro:machine:{id}`,
//! which derives from a P-256 key held in the machine's TPM 2.0 or Secure
//! Enclave. The key a transport authenticates the node by (for iroh, the
//! Ed25519 `EndpointId`) is made fresh at every boot and held only in
//! memory, so it is never the root of trust: the hardware key signs an
//! [`EndpointRecord`] naming the transport, the endpoint key, the relays the
//! endpoint is reachable through, and the record's lifetime. A peer is
//! accepted by identity only through [`EndpointRecord::verify`]: a record not
//! signed by the claimed identity, outside its lifetime, or naming another
//! endpoint key is refused.
//!
//! Nothing here depends on a particular transport: the endpoint key is a
//! transport tag and opaque bytes, compared exactly. A transport adapter
//! (for iroh, [`crate::identity_transport`]) turns a verified record into
//! something it can dial.
//!
//! A machine that serves the relay role says so in its own record
//! ([`EndpointRecord::serves_relay`]), so relays are announced and verified
//! by identity the same way endpoints are.
//!
//! A record carries no IP address. A node is reached through the relays it
//! names.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tenzro_device_key::HardwareSigner;
use tenzro_types::did_derivation::machine_did;
use url::Url;

use crate::error::{IrohError, IrohResult};

/// Domain separator of an endpoint record signature.
pub const ENDPOINT_RECORD_DOMAIN: &[u8] = b"tenzro/transport/endpoint-record";

/// Lifetime of a record this node signs.
pub const RECORD_LIFETIME_MS: u64 = 6 * 3_600 * 1_000;

/// Longest lifetime a record may claim. Bounds how long an endpoint the
/// machine no longer runs can be named by a replayed record.
pub const MAX_RECORD_LIFETIME_MS: u64 = 24 * 3_600 * 1_000;

/// How far ahead of the local clock a record may be issued.
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;

/// Most forwarders one record names.
pub const MAX_FORWARDERS_PER_RECORD: usize = 4;

/// Most relays one record may name.
pub const MAX_RELAYS_PER_RECORD: usize = 8;

/// Longest relay URL a record may carry.
pub const MAX_RELAY_URL_LEN: usize = 512;

/// Longest transport tag a record may carry.
pub const MAX_TRANSPORT_TAG_LEN: usize = 64;

/// Longest endpoint key a record may carry.
pub const MAX_ENDPOINT_KEY_LEN: usize = 256;

/// Most licences one record may state as accepted.
pub const MAX_ACCEPTED_LICENCES: usize = 64;

/// Longest licence id a record may carry.
pub const MAX_LICENCE_ID_LEN: usize = 64;

/// Prefix of the machine identities the transport addresses.
pub const MACHINE_DID_PREFIX: &str = "did:tenzro:machine:";

/// Why a record was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The record is not well formed.
    #[error("malformed endpoint record: {0}")]
    Malformed(&'static str),
    /// The record's key does not derive the identity it was offered for.
    #[error("endpoint record is not signed by the claimed machine identity")]
    NotTheClaimedIdentity,
    /// The signature does not verify under the record's key.
    #[error("endpoint record signature does not verify")]
    BadSignature,
    /// The record names another endpoint key, or another transport, than the
    /// one it was offered for.
    #[error("endpoint record names another endpoint")]
    WrongEndpoint,
    /// The record's lifetime has passed.
    #[error("endpoint record expired")]
    Expired,
    /// The record claims to be issued later than the local clock allows.
    #[error("endpoint record issued in the future")]
    IssuedInFuture,
    /// The record claims a lifetime longer than [`MAX_RECORD_LIFETIME_MS`].
    #[error("endpoint record lifetime out of bounds")]
    LifetimeOutOfBounds,
    /// A record with a higher sequence number is already held.
    #[error("endpoint record is stale: a newer one is held")]
    Stale,
    /// The record's ML-DSA binding does not verify.
    #[error("endpoint record ML-DSA binding does not verify")]
    BadPqBinding,
    /// The identity bound its records with an ML-DSA key, and this record
    /// carries no binding.
    #[error("endpoint record lacks the ML-DSA binding its identity uses")]
    PqBindingMissing,
    /// The record is bound by another ML-DSA key than the identity's.
    #[error("endpoint record is bound by another ML-DSA key than its identity's")]
    PqKeyChanged,
}

/// Who a record may be shared with.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecordScope {
    /// Any node of the network.
    Network,
    /// Only the members of the current epoch set.
    EpochSet,
    /// Only the machine identities listed, the counterparties a private node
    /// chose. The list is signed with the record, so no node holding the
    /// record can widen it.
    Counterparties(Vec<String>),
}

/// Most counterparties one record may list.
pub const MAX_COUNTERPARTIES: usize = 256;

impl RecordScope {
    /// Whether a record of this scope may go to anyone who asks, in a
    /// snapshot as well as by lookup.
    pub fn is_network_wide(&self) -> bool {
        matches!(self, Self::Network)
    }
}

/// A transport endpoint key: which transport, and the key bytes that
/// transport authenticates the endpoint by.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EndpointKey {
    /// The transport and key type, e.g. [`crate::identity_transport::TRANSPORT_IROH`].
    pub transport: String,
    /// The key, in the transport's own encoding.
    #[serde(with = "hex_bytes")]
    pub key: Vec<u8>,
}

/// A relay a machine is reachable through, by the relay operator's identity
/// and the URL the operator publishes for it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayRef {
    /// Machine identity of the relay operator.
    pub did: String,
    /// The relay's URL.
    pub url: Url,
}

/// A machine's signed statement of its transport endpoint for one boot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRecord {
    /// The machine's hardware P-256 key, uncompressed SEC1. The machine's
    /// identity is [`machine_did`] of this key.
    #[serde(with = "hex_bytes")]
    pub machine_key: Vec<u8>,
    /// The endpoint key peers authenticate the machine's transport by.
    pub endpoint: EndpointKey,
    /// Relays the endpoint is reachable through.
    pub relays: Vec<RelayRef>,
    /// Endpoints that forward packets to this endpoint (peer relays), by
    /// their endpoint keys: a peer reaches the endpoint through any of them.
    pub forwarders: Vec<EndpointKey>,
    /// The relay URL this machine serves, when it runs the relay role.
    pub serves_relay: Option<Url>,
    /// Who the record may be shared with.
    pub scope: RecordScope,
    /// Ids of the model licences the machine's operator accepted, sorted and
    /// distinct. A provider holding weights whose origin gates them behind
    /// a licence serves them only to a machine whose record states it.
    pub accepted_licences: Vec<String>,
    /// Increases with every record the machine signs; a record with a lower
    /// sequence than one held is stale.
    pub sequence: u64,
    /// When it was signed, in Unix milliseconds.
    pub issued_ms: u64,
    /// When it stops naming the endpoint, in Unix milliseconds.
    pub not_after_ms: u64,
    /// ECDSA P-256 over SHA-256 of the record message, raw `r || s`.
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    /// The ML-DSA leg of the endpoint's authentication, when the machine
    /// holds a hardware ML-DSA key (see [`crate::pq_endpoint`]). It is not
    /// part of the P-256 signed message, so a node that does not read it
    /// still verifies the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<crate::pq_endpoint::PqBinding>,
}

fn put_bytes(m: &mut Vec<u8>, b: &[u8]) {
    m.extend_from_slice(&(b.len() as u32).to_be_bytes());
    m.extend_from_slice(b);
}

/// What the machine signs: the domain, then every field but the signature.
pub(crate) fn record_message(r: &EndpointRecord) -> Vec<u8> {
    let mut m = Vec::with_capacity(256);
    put_bytes(&mut m, ENDPOINT_RECORD_DOMAIN);
    put_bytes(&mut m, &r.machine_key);
    put_bytes(&mut m, r.endpoint.transport.as_bytes());
    put_bytes(&mut m, &r.endpoint.key);
    m.extend_from_slice(&(r.relays.len() as u32).to_be_bytes());
    for relay in &r.relays {
        put_bytes(&mut m, relay.did.as_bytes());
        put_bytes(&mut m, relay.url.as_str().as_bytes());
    }
    m.extend_from_slice(&(r.forwarders.len() as u32).to_be_bytes());
    for f in &r.forwarders {
        put_bytes(&mut m, f.transport.as_bytes());
        put_bytes(&mut m, &f.key);
    }
    match &r.serves_relay {
        Some(url) => {
            m.push(1);
            put_bytes(&mut m, url.as_str().as_bytes());
        }
        None => m.push(0),
    }
    match &r.scope {
        RecordScope::Network => m.push(0),
        RecordScope::EpochSet => m.push(1),
        RecordScope::Counterparties(list) => {
            m.push(2);
            m.extend_from_slice(&(list.len() as u32).to_be_bytes());
            for did in list {
                put_bytes(&mut m, did.as_bytes());
            }
        }
    }
    m.extend_from_slice(&(r.accepted_licences.len() as u32).to_be_bytes());
    for id in &r.accepted_licences {
        put_bytes(&mut m, id.as_bytes());
    }
    m.extend_from_slice(&r.sequence.to_be_bytes());
    m.extend_from_slice(&r.issued_ms.to_be_bytes());
    m.extend_from_slice(&r.not_after_ms.to_be_bytes());
    m
}

/// Whether `did` is a machine identity in the form the transport addresses.
pub fn is_machine_did(did: &str) -> bool {
    did.strip_prefix(MACHINE_DID_PREFIX).is_some_and(|id| {
        id.len() == 64 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Whether `id` is a licence id in the form records carry: short, lowercase
/// ASCII letters, digits, `-`, `.` and `_`.
pub fn is_licence_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_LICENCE_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
}

fn check_relay_url(url: &Url) -> Result<(), RecordError> {
    if url.as_str().len() > MAX_RELAY_URL_LEN {
        return Err(RecordError::Malformed("relay URL too long"));
    }
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(RecordError::Malformed(
            "relay URL is not an http(s) URL with a host",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RecordError::Malformed("relay URL carries credentials"));
    }
    Ok(())
}

impl EndpointRecord {
    /// Signs, with the machine's hardware key, record number `sequence` of
    /// `endpoint` reachable through `relays`, shared within `scope`, stating
    /// the `accepted_licences` of the machine's operator, valid from `now_ms`
    /// for [`RECORD_LIFETIME_MS`].
    pub fn sign(
        signer: &dyn HardwareSigner,
        endpoint: EndpointKey,
        relays: Vec<RelayRef>,
        forwarders: Vec<EndpointKey>,
        serves_relay: Option<Url>,
        scope: RecordScope,
        mut accepted_licences: Vec<String>,
        sequence: u64,
        now_ms: u64,
    ) -> IrohResult<Self> {
        let machine_key = signer
            .public_key_sec1()
            .map_err(|e| IrohError::Backend(format!("machine key: {e}")))?
            .to_vec();
        let mut r = Self {
            machine_key,
            endpoint,
            relays,
            forwarders,
            serves_relay,
            scope,
            accepted_licences: {
                accepted_licences.sort();
                accepted_licences.dedup();
                accepted_licences
            },
            sequence,
            issued_ms: now_ms,
            not_after_ms: now_ms.saturating_add(RECORD_LIFETIME_MS),
            signature: Vec::new(),
            pq: None,
        };
        r.check_shape()
            .map_err(|e| IrohError::Backend(e.to_string()))?;
        r.signature = signer
            .sign(&record_message(&r))
            .map_err(|e| IrohError::Backend(format!("machine key refused to sign: {e}")))?
            .to_vec();
        Ok(r)
    }

    /// The machine identity whose key signed this record.
    pub fn machine_did(&self) -> String {
        machine_did(&self.machine_key)
    }

    /// This record as the relay it announces, when it announces one.
    pub fn as_relay(&self) -> Option<RelayRef> {
        self.serves_relay.as_ref().map(|url| RelayRef {
            did: self.machine_did(),
            url: url.clone(),
        })
    }

    fn check_shape(&self) -> Result<(), RecordError> {
        if self.machine_key.len() != 65 || self.machine_key[0] != 0x04 {
            return Err(RecordError::Malformed(
                "machine key is not an uncompressed P-256 point",
            ));
        }
        if self.endpoint.transport.is_empty()
            || self.endpoint.transport.len() > MAX_TRANSPORT_TAG_LEN
        {
            return Err(RecordError::Malformed("transport tag empty or too long"));
        }
        if self.endpoint.key.is_empty() || self.endpoint.key.len() > MAX_ENDPOINT_KEY_LEN {
            return Err(RecordError::Malformed("endpoint key empty or too long"));
        }
        if let RecordScope::Counterparties(list) = &self.scope
            && (list.len() > MAX_COUNTERPARTIES || !list.iter().all(|d| is_machine_did(d)))
        {
            return Err(RecordError::Malformed(
                "counterparties are not a short list of machine identities",
            ));
        }
        if self.accepted_licences.len() > MAX_ACCEPTED_LICENCES
            || !self.accepted_licences.iter().all(|id| is_licence_id(id))
            || !self.accepted_licences.windows(2).all(|w| w[0] < w[1])
        {
            return Err(RecordError::Malformed(
                "accepted licences are not a short sorted list of licence ids",
            ));
        }
        if self.forwarders.len() > MAX_FORWARDERS_PER_RECORD
            || self.forwarders.iter().any(|f| {
                f.transport.is_empty()
                    || f.transport.len() > MAX_TRANSPORT_TAG_LEN
                    || f.key.is_empty()
                    || f.key.len() > MAX_ENDPOINT_KEY_LEN
            })
        {
            return Err(RecordError::Malformed("forwarders"));
        }
        if self.relays.len() > MAX_RELAYS_PER_RECORD {
            return Err(RecordError::Malformed("too many relays"));
        }
        for relay in &self.relays {
            if !is_machine_did(&relay.did) {
                return Err(RecordError::Malformed(
                    "relay is not named by a machine identity",
                ));
            }
            check_relay_url(&relay.url)?;
        }
        if let Some(url) = &self.serves_relay {
            check_relay_url(url)?;
        }
        if self.not_after_ms <= self.issued_ms
            || self.not_after_ms - self.issued_ms > MAX_RECORD_LIFETIME_MS
        {
            return Err(RecordError::LifetimeOutOfBounds);
        }
        Ok(())
    }

    /// Checks, whatever the time, that the record is well formed and signed
    /// by its own machine key.
    pub fn check_signed(&self) -> Result<(), RecordError> {
        self.check_shape()?;
        if !tenzro_device_key::signer::verify_p256(
            &self.machine_key,
            &record_message(self),
            &self.signature,
        ) {
            return Err(RecordError::BadSignature);
        }
        Ok(())
    }

    /// Checks that the record is signed and current at `now_ms`.
    pub fn check_current(&self, now_ms: u64) -> Result<(), RecordError> {
        self.check_signed()?;
        if self.issued_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(RecordError::IssuedInFuture);
        }
        if self.not_after_ms <= now_ms {
            return Err(RecordError::Expired);
        }
        Ok(())
    }

    /// Accepts the record as `did`'s current statement of its endpoint,
    /// whichever it names: signed by the key `did` derives from, and current
    /// at `now_ms`.
    pub fn verify_identity(&self, did: &str, now_ms: u64) -> Result<(), RecordError> {
        self.check_current(now_ms)?;
        if self.machine_did() != did {
            return Err(RecordError::NotTheClaimedIdentity);
        }
        Ok(())
    }

    /// Accepts the record as `did`'s statement that it runs exactly
    /// `endpoint`, at `now_ms`. This is the check wherever a peer that
    /// authenticated with `endpoint` is accepted as `did`.
    pub fn verify(
        &self,
        did: &str,
        endpoint: &EndpointKey,
        now_ms: u64,
    ) -> Result<(), RecordError> {
        self.verify_identity(did, now_ms)?;
        if &self.endpoint != endpoint {
            return Err(RecordError::WrongEndpoint);
        }
        Ok(())
    }

    /// Whether the machine's operator accepted the licence `id`.
    pub fn accepts_licence(&self, id: &str) -> bool {
        self.accepted_licences
            .binary_search_by(|a| a.as_str().cmp(id))
            .is_ok()
    }

    /// Whether the record is past half its lifetime at `now_ms`, when the
    /// machine signs a fresh one.
    pub fn due_for_renewal(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_ms + (self.not_after_ms - self.issued_ms) / 2
    }
}

/// Most identities a [`RecordBook`] holds.
pub const MAX_BOOK_ENTRIES: usize = 65_536;

/// The newest current record of each machine identity.
#[derive(Debug, Default)]
pub struct RecordBook {
    by_did: HashMap<String, EndpointRecord>,
    pins: crate::pq_endpoint::PqPins,
}

impl RecordBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps `record` for `did` if it verifies at `now_ms` and its sequence
    /// is higher than the held record's, so replaying an old record cannot
    /// move an identity back to an endpoint it left. A lower sequence is
    /// refused as stale; the same sequence again is ignored. Once `did` has
    /// bound a record with an ML-DSA key, a record without that binding is
    /// refused (see [`crate::pq_endpoint::PqPins`]). Returns whether the
    /// record was kept.
    pub fn offer(
        &mut self,
        did: &str,
        record: EndpointRecord,
        now_ms: u64,
    ) -> Result<bool, RecordError> {
        record.verify_identity(did, now_ms)?;
        self.pins.check(did, &record)?;
        if let Some(held) = self.by_did.get(did).filter(|h| h.not_after_ms > now_ms) {
            if record.sequence < held.sequence {
                return Err(RecordError::Stale);
            }
            if record.sequence == held.sequence {
                return Ok(false);
            }
        }
        if !self.by_did.contains_key(did) && self.by_did.len() >= MAX_BOOK_ENTRIES {
            self.expire(now_ms);
            if self.by_did.len() >= MAX_BOOK_ENTRIES {
                return Ok(false);
            }
        }
        self.by_did.insert(did.to_string(), record);
        Ok(true)
    }

    /// Pins the hardware ML-DSA key `did` registered on chain (tagged with
    /// its scheme), so its records are held to it from the first one.
    pub fn pin_pq_key(&mut self, did: &str, machine_pq_key: Vec<u8>) {
        self.pins.pin(did, machine_pq_key);
    }

    /// The hardware ML-DSA key `did`'s records are held to, if any.
    pub fn pinned_pq_key(&self, did: &str) -> Option<&[u8]> {
        self.pins.get(did)
    }

    /// Every ML-DSA pin, to save across restarts.
    pub fn saved_pq_pins(&self) -> Vec<crate::pq_endpoint::SavedPin> {
        self.pins.saved()
    }

    /// Takes back ML-DSA pins saved by an earlier run (see
    /// [`crate::pq_endpoint::PqPins::restore`]).
    pub fn restore_pq_pins(&mut self, saved: Vec<crate::pq_endpoint::SavedPin>) {
        self.pins.restore(saved);
    }

    /// How many times the ML-DSA pins changed.
    pub fn pq_pin_changes(&self) -> u64 {
        self.pins.changes()
    }

    /// The record `did` holds at `now_ms`, while it is current.
    pub fn get(&self, did: &str, now_ms: u64) -> Option<&EndpointRecord> {
        self.by_did.get(did).filter(|r| r.not_after_ms > now_ms)
    }

    /// Drops every record whose lifetime has passed.
    pub fn expire(&mut self, now_ms: u64) {
        self.by_did.retain(|_, r| r.not_after_ms > now_ms);
    }

    /// Every identity with a current record at `now_ms`.
    pub fn current(&self, now_ms: u64) -> impl Iterator<Item = (&str, &EndpointRecord)> {
        self.by_did
            .iter()
            .filter(move |(_, r)| r.not_after_ms > now_ms)
            .map(|(d, r)| (d.as_str(), r))
    }

    /// The current record that names exactly `endpoint`, if any. Every record
    /// in the book verified when it was offered.
    pub fn naming(&self, endpoint: &EndpointKey, now_ms: u64) -> Option<&EndpointRecord> {
        self.current(now_ms)
            .find(|(_, r)| &r.endpoint == endpoint)
            .map(|(_, r)| r)
    }

    /// The identity in `set` whose current record names exactly `endpoint`,
    /// if any: whether a peer that authenticated with `endpoint` is certified
    /// by one of the identities in `set`. Every record in the book verified
    /// when it was offered.
    pub fn certifier_in<'a>(
        &'a self,
        endpoint: &EndpointKey,
        set: &HashSet<String>,
        now_ms: u64,
    ) -> Option<&'a str> {
        self.current(now_ms)
            .find(|(did, r)| &r.endpoint == endpoint && set.contains(*did))
            .map(|(did, _)| did)
    }
}

/// One entry of a boot list: a machine identity, optionally with the relay
/// it is reachable through, written `did:tenzro:machine:{id}` or
/// `did:tenzro:machine:{id}@{relay URL}`.
///
/// A boot entry names a machine, never a network address: a transport path or
/// a socket address is refused.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BootIdentity {
    /// The machine identity.
    pub did: String,
    /// The relay to ask for the identity's record, if the entry names one.
    pub relay: Option<Url>,
}

impl FromStr for BootIdentity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.starts_with('/') {
            return Err(format!(
                "boot entry {s:?} is a network address; boot entries name machine identities \
                 (did:tenzro:machine:<id>[@<relay url>])"
            ));
        }
        let (did, relay) = match s.split_once('@') {
            Some((did, relay)) => (did, Some(relay)),
            None => (s, None),
        };
        if !is_machine_did(did) {
            return Err(format!(
                "boot entry {s:?} does not name a machine identity (did:tenzro:machine:<64 hex>)"
            ));
        }
        let relay = match relay {
            Some(raw) => {
                let url =
                    Url::parse(raw).map_err(|e| format!("boot entry {s:?}: relay URL: {e}"))?;
                check_relay_url(&url).map_err(|e| format!("boot entry {s:?}: {e}"))?;
                Some(url)
            }
            None => None,
        };
        Ok(Self {
            did: did.to_string(),
            relay,
        })
    }
}

impl fmt::Display for BootIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.relay {
            Some(url) => write!(f, "{}@{}", self.did, url),
            None => f.write_str(&self.did),
        }
    }
}

impl Serialize for BootIdentity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for BootIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// Parses a comma-separated boot list, refusing the whole list if any entry
/// is not a machine identity.
pub fn parse_boot_list(raw: &str) -> Result<Vec<BootIdentity>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::parse)
        .collect()
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_device_key::signer::HardwareBackend;
    use tenzro_device_key::{DeviceKeyError, DeviceSignature};

    /// A software P-256 key standing in for a machine's hardware key.
    #[derive(Debug)]
    pub(crate) struct TestMachineKey(p256::ecdsa::SigningKey);

    impl TestMachineKey {
        pub(crate) fn from_seed(seed: u8) -> Self {
            let mut scalar = [0u8; 32];
            scalar[31] = seed.max(1);
            scalar[0] = 0x11;
            Self(p256::ecdsa::SigningKey::from_slice(&scalar).expect("valid scalar"))
        }

        pub(crate) fn did(&self) -> String {
            machine_did(&self.public_key_sec1().unwrap())
        }
    }

    impl HardwareSigner for TestMachineKey {
        fn backend(&self) -> HardwareBackend {
            HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            "test"
        }
        fn public_key_sec1(&self) -> Result<[u8; 65], DeviceKeyError> {
            let point = self.0.verifying_key().to_sec1_point(false);
            let mut out = [0u8; 65];
            out.copy_from_slice(point.as_bytes());
            Ok(out)
        }
        fn sign_prehash(&self, digest: &[u8; 32]) -> Result<DeviceSignature, DeviceKeyError> {
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).expect("sign");
            let mut out = [0u8; 64];
            out.copy_from_slice(&sig.to_bytes());
            Ok(out)
        }
    }

    const NOW: u64 = 1_900_000_000_000;

    fn endpoint(seed: u8) -> EndpointKey {
        EndpointKey {
            transport: "test/ed25519".to_string(),
            key: vec![seed; 32],
        }
    }

    fn relay(seed: u8) -> RelayRef {
        RelayRef {
            did: TestMachineKey::from_seed(seed).did(),
            url: Url::parse("https://relay.example.org").unwrap(),
        }
    }

    #[test]
    fn a_record_verifies_for_its_identity_and_endpoint() {
        let key = TestMachineKey::from_seed(1);
        let r = EndpointRecord::sign(
            &key,
            endpoint(1),
            vec![relay(9)],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            1,
            NOW,
        )
        .unwrap();
        r.verify(&key.did(), &endpoint(1), NOW + 1_000).unwrap();
        r.verify_identity(&key.did(), NOW).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let back: EndpointRecord = serde_json::from_str(&json).unwrap();
        back.verify(&key.did(), &endpoint(1), NOW).unwrap();
    }

    #[test]
    fn a_forged_record_signed_by_another_identity_is_rejected() {
        let victim = TestMachineKey::from_seed(1);
        let forger = TestMachineKey::from_seed(2);
        // Signed by the forger's own key: it verifies, but as the forger.
        let forged = EndpointRecord::sign(
            &forger,
            endpoint(7),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            1,
            NOW,
        )
        .unwrap();
        assert_eq!(
            forged.verify(&victim.did(), &endpoint(7), NOW),
            Err(RecordError::NotTheClaimedIdentity)
        );
        // The victim's key swapped in over the forger's signature.
        let mut swapped = forged.clone();
        swapped.machine_key = victim.public_key_sec1().unwrap().to_vec();
        assert_eq!(
            swapped.verify(&victim.did(), &endpoint(7), NOW),
            Err(RecordError::BadSignature)
        );
        // A genuine record altered after signing.
        let mut moved = EndpointRecord::sign(
            &victim,
            endpoint(1),
            vec![relay(9)],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            1,
            NOW,
        )
        .unwrap();
        moved.relays[0].url = Url::parse("https://elsewhere.example.org").unwrap();
        assert_eq!(
            moved.verify(&victim.did(), &endpoint(1), NOW),
            Err(RecordError::BadSignature)
        );
    }

    #[test]
    fn a_stale_or_expired_record_is_ignored() {
        let key = TestMachineKey::from_seed(1);
        let r = EndpointRecord::sign(
            &key,
            endpoint(1),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            1,
            NOW,
        )
        .unwrap();
        assert_eq!(
            r.verify(&key.did(), &endpoint(1), NOW + RECORD_LIFETIME_MS),
            Err(RecordError::Expired)
        );
        assert_eq!(
            r.verify(&key.did(), &endpoint(1), NOW - MAX_CLOCK_SKEW_MS - 1),
            Err(RecordError::IssuedInFuture)
        );
        let mut book = RecordBook::new();
        assert!(book.offer(&key.did(), r.clone(), NOW).unwrap());
        assert!(
            book.get(&key.did(), NOW + RECORD_LIFETIME_MS).is_none(),
            "an expired record names nothing"
        );
        assert_eq!(
            book.offer(&key.did(), r, NOW + RECORD_LIFETIME_MS),
            Err(RecordError::Expired)
        );
    }

    #[test]
    fn a_record_naming_a_different_endpoint_is_rejected() {
        let key = TestMachineKey::from_seed(1);
        let r = EndpointRecord::sign(
            &key,
            endpoint(1),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            1,
            NOW,
        )
        .unwrap();
        assert_eq!(
            r.verify(&key.did(), &endpoint(2), NOW),
            Err(RecordError::WrongEndpoint)
        );
        let other_transport = EndpointKey {
            transport: "other/ed25519".to_string(),
            key: vec![1; 32],
        };
        assert_eq!(
            r.verify(&key.did(), &other_transport, NOW),
            Err(RecordError::WrongEndpoint)
        );
        let mut rewritten = r.clone();
        rewritten.endpoint = endpoint(2);
        assert_eq!(
            rewritten.verify(&key.did(), &endpoint(2), NOW),
            Err(RecordError::BadSignature)
        );
    }

    #[test]
    fn a_record_claiming_too_long_a_lifetime_is_refused() {
        let key = TestMachineKey::from_seed(1);
        let mut r = EndpointRecord::sign(
            &key,
            endpoint(1),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            1,
            NOW,
        )
        .unwrap();
        r.not_after_ms = NOW + MAX_RECORD_LIFETIME_MS + 1;
        assert_eq!(r.check_signed(), Err(RecordError::LifetimeOutOfBounds));
    }

    #[test]
    fn the_book_keeps_the_newest_record_and_ignores_a_replay() {
        let key = TestMachineKey::from_seed(1);
        let old = EndpointRecord::sign(
            &key,
            endpoint(1),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            1,
            NOW,
        )
        .unwrap();
        let new = EndpointRecord::sign(
            &key,
            endpoint(2),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            2,
            NOW + 10,
        )
        .unwrap();
        let mut book = RecordBook::new();
        assert!(book.offer(&key.did(), new, NOW + 20).unwrap());
        assert_eq!(
            book.offer(&key.did(), old, NOW + 20),
            Err(RecordError::Stale),
            "a lower sequence is stale"
        );
        let again = book.get(&key.did(), NOW + 20).unwrap().clone();
        assert!(
            !book.offer(&key.did(), again, NOW + 20).unwrap(),
            "the same record again is ignored"
        );
        assert_eq!(
            book.get(&key.did(), NOW + 20).unwrap().endpoint,
            endpoint(2)
        );
        let other = TestMachineKey::from_seed(2);
        let foreign = EndpointRecord::sign(
            &other,
            endpoint(3),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            vec![],
            3,
            NOW + 30,
        )
        .unwrap();
        assert_eq!(
            book.offer(&key.did(), foreign, NOW + 30),
            Err(RecordError::NotTheClaimedIdentity)
        );
    }

    #[test]
    fn an_endpoint_is_certified_only_by_a_current_identity_in_the_set() {
        let member = TestMachineKey::from_seed(1);
        let outsider = TestMachineKey::from_seed(2);
        let mut book = RecordBook::new();
        book.offer(
            &member.did(),
            EndpointRecord::sign(
                &member,
                endpoint(1),
                vec![],
                Vec::new(),
                None,
                RecordScope::Network,
                vec![],
                1,
                NOW,
            )
            .unwrap(),
            NOW,
        )
        .unwrap();
        book.offer(
            &outsider.did(),
            EndpointRecord::sign(
                &outsider,
                endpoint(2),
                vec![],
                Vec::new(),
                None,
                RecordScope::Network,
                vec![],
                1,
                NOW,
            )
            .unwrap(),
            NOW,
        )
        .unwrap();
        let set: HashSet<String> = [member.did()].into_iter().collect();
        assert_eq!(
            book.certifier_in(&endpoint(1), &set, NOW),
            Some(member.did().as_str())
        );
        assert_eq!(
            book.certifier_in(&endpoint(2), &set, NOW),
            None,
            "certified, but not by a member"
        );
        assert_eq!(
            book.certifier_in(&endpoint(9), &set, NOW),
            None,
            "certified by no one"
        );
        assert_eq!(
            book.certifier_in(&endpoint(1), &set, NOW + RECORD_LIFETIME_MS),
            None,
            "expired"
        );
    }

    #[test]
    fn a_relay_record_announces_the_relay_by_identity() {
        let key = TestMachineKey::from_seed(4);
        let url = Url::parse("https://relay.example.org/").unwrap();
        let r = EndpointRecord::sign(
            &key,
            endpoint(4),
            vec![],
            Vec::new(),
            Some(url.clone()),
            RecordScope::Network,
            vec![],
            1,
            NOW,
        )
        .unwrap();
        assert_eq!(
            r.as_relay(),
            Some(RelayRef {
                did: key.did(),
                url
            })
        );
    }

    #[test]
    fn a_boot_list_names_machine_identities_and_refuses_network_addresses() {
        let did = TestMachineKey::from_seed(1).did();
        let entries = parse_boot_list(&format!("{did}, {did}@https://relay.example.org")).unwrap();
        assert_eq!(
            entries[0],
            BootIdentity {
                did: did.clone(),
                relay: None
            }
        );
        assert_eq!(
            entries[1].relay.as_ref().unwrap().as_str(),
            "https://relay.example.org/"
        );
        assert_eq!(
            entries[1].to_string().parse::<BootIdentity>().unwrap(),
            entries[1]
        );
        for refused in [
            "/ip4/192.0.2.10/tcp/9000/p2p/12D3KooWQYhTNQdmr3ArTeUHRYzFg94BKyTkoWBDWez9kSCVe2Xo",
            "/ip6/2001:db8::1/udp/9000/quic-v1",
            "/dns4/boot.example.org/tcp/9000",
            "192.0.2.10:9001",
            "did:tenzro:human:00",
            "did:tenzro:machine:not-hex",
        ] {
            assert!(
                refused.parse::<BootIdentity>().is_err(),
                "{refused} must be refused"
            );
        }
        assert!(
            parse_boot_list(&format!("{did},/ip4/192.0.2.10/tcp/9000")).is_err(),
            "one bad entry refuses the list"
        );
        assert!(
            format!("{did}@ftp://relay.example.org")
                .parse::<BootIdentity>()
                .is_err()
        );
        assert!(
            format!("{did}@https://user:pw@relay.example.org")
                .parse::<BootIdentity>()
                .is_err()
        );
    }
}
