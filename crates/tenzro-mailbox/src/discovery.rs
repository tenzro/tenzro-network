//! Finding a recipient's mailboxes in its DID document.
//!
//! A recipient publishes each mailbox as a service entry of type
//! [`MAILBOX_SERVICE_TYPE`] whose endpoint is the mailbox's address with the
//! digest of its operator key as fragment: `https://mbx.example.org#key=<hex>`.
//! A service endpoint is too short for the operator's ML-DSA key itself, so
//! the document pins the digest and [`crate::MailboxClient::connect`]
//! refuses a mailbox whose key does not hash to it.

use std::net::IpAddr;

use reqwest::Url;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tenzro_crypto::CompositePublicKey;

/// The service type a DID document gives its mailboxes.
pub const MAILBOX_SERVICE_TYPE: &str = "TenzroMailbox";

const KEY_DOMAIN: &[u8] = b"tenzro/mailbox/operator-key";
const KEY_FRAGMENT: &str = "#key=";

/// The digest a DID document pins an operator key by.
pub fn operator_key_digest(key: &CompositePublicKey) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KEY_DOMAIN);
    h.update((key.p256.len() as u32).to_be_bytes());
    h.update(&key.p256);
    let pq = key.pq.as_deref().unwrap_or_default();
    h.update((pq.len() as u32).to_be_bytes());
    h.update(pq);
    h.finalize().into()
}

/// The service endpoint a recipient publishes for the mailbox at `base`.
pub fn mailbox_endpoint(base: &str, operator: &CompositePublicKey) -> String {
    format!(
        "{}{KEY_FRAGMENT}{}",
        base.trim_end_matches('/'),
        hex::encode(operator_key_digest(operator))
    )
}

/// Whether a client may reach a mailbox at `base`: over https at a name or
/// a public address, or over http on this machine, where the operator's TLS
/// front end is the only other way in. A DID document is written by its
/// subject, so an address that names a private network is refused.
pub(crate) fn acceptable_base(base: &str) -> bool {
    let Ok(url) = Url::parse(base) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let ip = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok();
    match (url.scheme(), ip) {
        ("https", Some(ip)) => is_public(ip),
        ("https", None) => !is_local_name(host),
        ("http", Some(ip)) => ip.is_loopback(),
        ("http", None) => is_local_name(host),
        _ => false,
    }
}

fn is_local_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    name.eq_ignore_ascii_case("localhost") || name.to_ascii_lowercase().ends_with(".localhost")
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.octets()[0] == 0
                || (v4.octets()[0] == 100 && v4.octets()[1] & 0xc0 == 64))
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_public(IpAddr::V4(v4)),
            None => {
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.segments()[0] & 0xfe00 == 0xfc00
                    || v6.segments()[0] & 0xffc0 == 0xfe80)
            }
        },
    }
}

/// One mailbox a DID document names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEntry {
    /// The service entry's id, `<did>#<fragment>`.
    pub id: String,
    /// The mailbox's address, ending before `/mailbox/v1`.
    pub base: String,
    /// The digest of the operator key that signs its receipts.
    pub key_digest: [u8; 32],
}

impl MailboxEntry {
    /// Read a service endpoint written by [`mailbox_endpoint`].
    pub fn parse(id: &str, endpoint: &str) -> Option<Self> {
        let (base, digest) = endpoint.rsplit_once(KEY_FRAGMENT)?;
        if !acceptable_base(base) {
            return None;
        }
        let key_digest = hex::decode(digest).ok()?.try_into().ok()?;
        Some(Self {
            id: id.to_string(),
            base: base.trim_end_matches('/').to_string(),
            key_digest,
        })
    }
}

/// The mailboxes a resolved DID document names, in its order. Entries of
/// another type, or mailbox entries that are not well formed, are skipped.
pub fn mailboxes_in(document: &Value) -> Vec<MailboxEntry> {
    document["service"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| s["type"] == MAILBOX_SERVICE_TYPE)
        .filter_map(|s| MailboxEntry::parse(s["id"].as_str()?, s["serviceEndpoint"].as_str()?))
        .collect()
}
