//! The generic registry: one entry type for anything a participant defines
//! and others discover, held by the chain as opaque data.
//!
//! A unit of metered work, a service type, a price card, an application or
//! harness module, a dataset licence: each is an entry with an id, a short
//! kind tag, the content hash of the harness module that interprets it (its
//! anchor), and its data. The chain records who put it, its version and when,
//! and holds the owner's bond; it never reads the data. What an entry means,
//! how its units are metered and verified, and how it is priced and
//! discovered live in the harness module its anchor names, which stays its
//! developer's own.
//!
//! Ids are global and first come, first served, behind a governed bond. An
//! id that starts with a 64-hex-character account and a `/` can only be put
//! by that account, so an owner's own entries (its price cards) cannot be
//! squatted.
//!
//! Three kinds are reserved, because the standards layer and name lookup build
//! on them and their rules must hold from the first block:
//!
//! - `standard`: the anchor is the digest of the standard's machine-readable
//!   bundle (normative text, interface fragments, the governed parameters it
//!   depends on, conformance vectors). A bundle digest names one standard.
//! - `conformance`: the anchor is the digest of an implementation, the data
//!   the 32-byte bundle digests of the standing standards it passes.
//! - `name`: the id is the name, first come, behind its own governed bond,
//!   and only governance retires it.
//!
//! An entry of a reserved kind keeps that kind, and no entry moves into one.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::primitives::Address;

/// Longest entry id.
pub const MAX_ID_LEN: usize = 160;
/// Longest kind tag.
pub const MAX_KIND_LEN: usize = 24;
/// Domain tag of [`RegistryEntry::digest`].
pub const REGISTRY_DOMAIN: &[u8] = b"tenzro/registry-entry/v1";
/// Kind of a standard: the anchor is its bundle's digest.
pub const KIND_STANDARD: &str = "standard";
/// Kind of a conformance claim: the data lists the bundle digests passed.
pub const KIND_CONFORMANCE: &str = "conformance";
/// Kind of a name: first come, bonded, retired by governance only.
pub const KIND_NAME: &str = "name";
/// The kinds whose rules the chain enforces.
pub const RESERVED_KINDS: [&str; 3] = [KIND_STANDARD, KIND_CONFORMANCE, KIND_NAME];
/// Length of one bundle digest a conformance entry lists.
pub const DIGEST_LEN: usize = 32;

/// One version of a registry entry, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub id: String,
    /// What kind of thing the data describes (`unit`, `card`, `service`,
    /// `app`, ...). Free text for readers; the chain branches only on the
    /// [`RESERVED_KINDS`].
    pub kind: String,
    pub owner: Address,
    /// 1 for the first put of an id, one more for each put after.
    pub version: u64,
    /// SHA-256 of the harness module that interprets the entry, hex; all
    /// zero for none.
    pub anchor: String,
    /// The entry's data, hex. Bounded by a governed size.
    pub data: String,
    /// Bond held while the entry stands, in TNZO base units.
    #[serde(with = "crate::primitives::u128_serde")]
    pub bond: u128,
    /// When this version was put, unix ms.
    pub put_at_ms: i64,
    /// When the entry was retired, unix ms: by its owner, or by governance.
    #[serde(default)]
    pub retired_at_ms: Option<i64>,
}

impl RegistryEntry {
    /// SHA-256 over the version's identity and content, hex: what a receipt
    /// or usage record commits to when it names the entry.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        h.update(REGISTRY_DOMAIN);
        for s in [&self.id, &self.kind, &self.anchor, &self.data] {
            h.update((s.len() as u32).to_le_bytes());
            h.update(s.as_bytes());
        }
        h.update(self.owner.as_bytes());
        h.update(self.version.to_le_bytes());
        hex::encode(h.finalize())
    }

    /// The data, decoded.
    pub fn data_bytes(&self) -> Option<Vec<u8>> {
        hex::decode(&self.data).ok()
    }

    /// Whether the entry stood at `at_ms`.
    pub fn standing_at(&self, at_ms: i64) -> bool {
        self.put_at_ms <= at_ms && self.retired_at_ms.is_none_or(|r| at_ms < r)
    }
}

/// Why an id or kind is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("id must be 1..={MAX_ID_LEN} of [a-z0-9_.@/-]")]
    BadId,
    #[error("kind must be 1..={MAX_KIND_LEN} of [a-z0-9_-]")]
    BadKind,
    #[error("anchor must be 64 lower-case hex characters")]
    BadAnchor,
    #[error("a {0} entry needs a non-zero anchor")]
    ZeroAnchor(&'static str),
    #[error("a name must be {0}..={1} of [a-z0-9-], not starting or ending with '-'")]
    BadName(usize, usize),
    #[error("conformance data must be 1..={0} distinct 32-byte digests")]
    BadDigestList(usize),
    #[error("an entry of a reserved kind keeps its kind, and none moves into one")]
    KindFixed,
}

/// Whether the chain enforces rules for `kind`.
pub fn is_reserved_kind(kind: &str) -> bool {
    RESERVED_KINDS.contains(&kind)
}

/// Check that an entry of `previous` kind may be put as `kind`.
pub fn check_kind_change(previous: &str, kind: &str) -> Result<(), RegistryError> {
    (previous == kind || !(is_reserved_kind(previous) || is_reserved_kind(kind)))
        .then_some(())
        .ok_or(RegistryError::KindFixed)
}

/// Check that the anchor of a `kind` entry is not all zero.
pub fn check_nonzero_anchor(kind: &'static str, anchor: &str) -> Result<(), RegistryError> {
    (anchor.bytes().any(|b| b != b'0'))
        .then_some(())
        .ok_or(RegistryError::ZeroAnchor(kind))
}

/// Check a name: `min..=max` of `[a-z0-9-]`, no leading or trailing `-`.
pub fn check_name(name: &str, min: usize, max: usize) -> Result<(), RegistryError> {
    let ok = (min..=max).contains(&name.len())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    ok.then_some(()).ok_or(RegistryError::BadName(min, max))
}

/// The bundle digests a conformance entry's data lists: 1..=`max` distinct
/// 32-byte digests, back to back.
pub fn conformance_digests(data: &[u8], max: usize) -> Result<Vec<[u8; 32]>, RegistryError> {
    let bad = RegistryError::BadDigestList(max);
    if data.is_empty() || !data.len().is_multiple_of(DIGEST_LEN) || data.len() / DIGEST_LEN > max {
        return Err(bad);
    }
    let digests: Vec<[u8; 32]> = data.as_chunks::<DIGEST_LEN>().0.to_vec();
    let mut sorted = digests.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != digests.len() {
        return Err(bad);
    }
    Ok(digests)
}

/// Check an id: 1..=160 of `[a-z0-9_.@/-]`.
pub fn check_id(id: &str) -> Result<(), RegistryError> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'_' | b'.' | b'@' | b'/' | b'-')
        });
    ok.then_some(()).ok_or(RegistryError::BadId)
}

/// Check a kind tag: 1..=24 of `[a-z0-9_-]`.
pub fn check_kind(kind: &str) -> Result<(), RegistryError> {
    let ok = !kind.is_empty()
        && kind.len() <= MAX_KIND_LEN
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));
    ok.then_some(()).ok_or(RegistryError::BadKind)
}

/// Check an anchor: 64 lower-case hex characters.
pub fn check_anchor(anchor: &str) -> Result<(), RegistryError> {
    (anchor.len() == 64
        && anchor
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then_some(())
    .ok_or(RegistryError::BadAnchor)
}

/// The account an id is reserved to, when it starts with one: 64 hex
/// characters and a `/`.
pub fn reserved_owner(id: &str) -> Option<Address> {
    let (head, _) = id.split_once('/')?;
    if head.len() != 64 {
        return None;
    }
    let bytes: [u8; 32] = hex::decode(head).ok()?.try_into().ok()?;
    Some(Address::new(bytes))
}

/// The id of `owner`'s entry `name`: `<owner hex>/<name>`.
pub fn owned_id(owner: &Address, name: &str) -> String {
    format!("{}/{name}", hex::encode(owner.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> RegistryEntry {
        RegistryEntry {
            id: "bandwidth_bytes".into(),
            kind: "unit".into(),
            owner: Address::new([1; 32]),
            version: 1,
            anchor: "ab".repeat(32),
            data: hex::encode(b"{}"),
            bond: 5,
            put_at_ms: 10,
            retired_at_ms: None,
        }
    }

    #[test]
    fn ids_kinds_and_anchors_are_checked() {
        assert!(check_id("bandwidth_bytes").is_ok());
        assert!(check_id(&owned_id(&Address::new([2; 32]), "card/qwen3-0.6b")).is_ok());
        assert!(check_id("Bandwidth").is_err());
        assert!(check_id("").is_err());
        assert!(check_id(&"a".repeat(MAX_ID_LEN + 1)).is_err());
        assert!(check_kind("unit").is_ok());
        assert!(check_kind("unit/x").is_err());
        assert!(check_anchor(&"0".repeat(64)).is_ok());
        assert!(check_anchor("00").is_err());
    }

    #[test]
    fn reserved_kinds_are_fixed_and_their_fields_checked() {
        for k in RESERVED_KINDS {
            assert!(check_kind(k).is_ok() && is_reserved_kind(k));
            assert!(check_kind_change(k, k).is_ok());
            assert_eq!(check_kind_change("unit", k), Err(RegistryError::KindFixed));
            assert_eq!(check_kind_change(k, "unit"), Err(RegistryError::KindFixed));
        }
        assert!(check_kind_change("unit", "service").is_ok());
        assert!(check_kind_change(KIND_NAME, KIND_STANDARD).is_err());
        assert!(check_nonzero_anchor(KIND_STANDARD, &"0".repeat(64)).is_err());
        assert!(check_nonzero_anchor(KIND_STANDARD, &format!("{}1", "0".repeat(63))).is_ok());

        assert!(check_name("alice-01", 3, 63).is_ok());
        for bad in [
            "ab", "-alice", "alice-", "Alice", "al.ice", "al/ice", "al_ice",
        ] {
            assert!(check_name(bad, 3, 63).is_err(), "{bad}");
        }
        assert!(check_name(&"a".repeat(63), 3, 63).is_ok());
        assert!(check_name(&"a".repeat(64), 3, 63).is_err());

        let d = |b: u8| [b; DIGEST_LEN];
        let list = [d(1), d(2)].concat();
        assert_eq!(conformance_digests(&list, 2).unwrap(), vec![d(1), d(2)]);
        assert!(conformance_digests(&list, 1).is_err(), "above the limit");
        assert!(conformance_digests(&[], 4).is_err(), "empty");
        assert!(conformance_digests(&list[..33], 4).is_err(), "ragged");
        assert!(
            conformance_digests(&[d(1), d(1)].concat(), 4).is_err(),
            "repeated"
        );
    }

    #[test]
    fn an_owned_id_is_reserved_to_its_owner() {
        let a = Address::new([3; 32]);
        assert_eq!(reserved_owner(&owned_id(&a, "card/m")), Some(a));
        assert_eq!(reserved_owner("bandwidth_bytes"), None);
        assert_eq!(reserved_owner("short/x"), None);
    }

    #[test]
    fn the_digest_binds_content_owner_and_version() {
        let e = entry();
        let d = e.digest();
        for f in 0..5 {
            let mut x = e.clone();
            match f {
                0 => x.data = hex::encode(b"{ }"),
                1 => x.version = 2,
                2 => x.owner = Address::new([9; 32]),
                3 => x.anchor = "cd".repeat(32),
                _ => x.kind = "card".into(),
            }
            assert_ne!(x.digest(), d, "field {f}");
        }
        // Bookkeeping the chain adds does not change what was put.
        let mut x = e.clone();
        x.put_at_ms = 99;
        x.retired_at_ms = Some(100);
        assert_eq!(x.digest(), d);
    }

    #[test]
    fn an_entry_stands_from_its_put_until_its_retirement() {
        let mut e = entry();
        assert!(!e.standing_at(9) && e.standing_at(10));
        e.retired_at_ms = Some(20);
        assert!(e.standing_at(19) && !e.standing_at(20));
    }
}
