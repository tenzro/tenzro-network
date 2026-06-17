//! KERI (Key Event Receipt Infrastructure) compatibility layer.
//!
//! KERI defines a hash-chained Key Event Log (KEL) that gives self-
//! certifying identifiers persistent control through rotation rather than
//! requiring re-registration on key compromise. The Tenzro side does not
//! need a fully-KERI-conformant controller (KERI's primary deployments
//! anchor against ToD witnesses); it needs to *speak* KERI well enough
//! that long-lived autonomous Machine identities can publish a KEL that
//! third-party KERI verifiers can resolve.
//!
//! This module implements the minimum-viable KEL surface:
//!
//! - **Inception (`icp`)** — the genesis event committing to (a) the
//!   current signing-key set and (b) the next signing-key digests
//!   (pre-rotation). The event identifier `SAID` is the self-addressing
//!   identifier — `Blake3-256` over the canonical event with the `SAID`
//!   field zeroed out, then base64url-encoded with a `E` prefix per the
//!   KERI prefix table (`E` = Blake3-256 derivation code).
//! - **Rotation (`rot`)** — advances the key set: reveals the keys that
//!   the previous event pre-committed to and commits to the next round.
//! - **Interaction (`ixn`)** — anchors arbitrary data into the KEL.
//!
//! Pre-rotation is the entire KERI security model: even if today's keys
//! are compromised, the attacker still can't rotate because the *next*
//! keys are committed by digest, not by key, and the digests are
//! cryptographic.
//!
//! References:
//!   - IETF draft: <https://datatracker.ietf.org/doc/html/draft-ssmith-keri-00>
//!   - DIF KERI WG: <https://identity.foundation/keri/>

use std::collections::BTreeMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{IdentityError, Result};

/// SAID prefix character used by Tenzro. KERI's prefix table assigns `E`
/// to Blake3-256, but Tenzro standardises on SHA-256 (matching the rest of
/// the protocol) and uses `S` so KERI verifiers know to dispatch the
/// SHA-256 digest path. This is allowed by KERI's CESR codes.
pub const TENZRO_KERI_PREFIX: char = 'S';

/// KERI event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeriEventKind {
    /// Inception (`icp`) — genesis event for an identifier.
    Inception,
    /// Rotation (`rot`) — rotates the key set.
    Rotation,
    /// Interaction (`ixn`) — anchors arbitrary data.
    Interaction,
}

impl KeriEventKind {
    /// Canonical 3-character tag used by KERI's wire format.
    pub fn tag(&self) -> &'static str {
        match self {
            KeriEventKind::Inception => "icp",
            KeriEventKind::Rotation => "rot",
            KeriEventKind::Interaction => "ixn",
        }
    }
}

/// One KEL event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeriEvent {
    /// Event kind.
    pub kind: KeriEventKind,
    /// Sequence number (`s`). 0 for inception, monotone for every event.
    pub sequence: u64,
    /// Self-Addressing Identifier of the *previous* event (`p`). Empty
    /// for inception. Each non-inception event chains by digest, not by
    /// height alone.
    pub prior_said: String,
    /// Current signing-key set (public-key bytes, ordered for threshold).
    pub signing_keys: Vec<Vec<u8>>,
    /// Threshold for the current signing-key set (KERI `kt`).
    pub signing_threshold: u8,
    /// Digests of the next signing keys (`n`). Reveals happen on rotation.
    pub next_key_digests: Vec<[u8; 32]>,
    /// Threshold for the next signing-key set (KERI `nt`).
    pub next_threshold: u8,
    /// Arbitrary data anchor (used by interaction events; empty for icp/rot).
    pub anchors: Vec<Vec<u8>>,
    /// Self-Addressing Identifier of this event (`d`). Computed by
    /// `KeriEvent::compute_said` with this field replaced by `"#"`.
    pub said: String,
}

impl KeriEvent {
    /// Build an inception event. The caller supplies the current signing-key
    /// set, the next-key-digest set, and the thresholds. The SAID is
    /// computed deterministically and the resulting identifier prefix
    /// equals the inception event's SAID.
    pub fn inception(
        signing_keys: Vec<Vec<u8>>,
        signing_threshold: u8,
        next_key_digests: Vec<[u8; 32]>,
        next_threshold: u8,
    ) -> Result<Self> {
        if signing_keys.is_empty() {
            return Err(IdentityError::CredentialError(
                "inception requires at least one signing key".into(),
            ));
        }
        if (signing_threshold as usize) > signing_keys.len() {
            return Err(IdentityError::CredentialError(
                "signing_threshold exceeds signing_keys length".into(),
            ));
        }
        let mut ev = Self {
            kind: KeriEventKind::Inception,
            sequence: 0,
            prior_said: String::new(),
            signing_keys,
            signing_threshold,
            next_key_digests,
            next_threshold,
            anchors: Vec::new(),
            said: String::new(),
        };
        ev.said = ev.compute_said();
        Ok(ev)
    }

    /// Build a rotation event after a prior event. `signing_keys` must
    /// match the pre-committed `next_key_digests` from `prior` — the
    /// caller is responsible for that check; `is_valid_rotation_of`
    /// re-verifies after construction.
    pub fn rotation(
        prior: &KeriEvent,
        signing_keys: Vec<Vec<u8>>,
        signing_threshold: u8,
        next_key_digests: Vec<[u8; 32]>,
        next_threshold: u8,
    ) -> Result<Self> {
        if signing_keys.is_empty() {
            return Err(IdentityError::CredentialError(
                "rotation requires at least one signing key".into(),
            ));
        }
        if (signing_threshold as usize) > signing_keys.len() {
            return Err(IdentityError::CredentialError(
                "signing_threshold exceeds signing_keys length".into(),
            ));
        }
        let mut ev = Self {
            kind: KeriEventKind::Rotation,
            sequence: prior.sequence + 1,
            prior_said: prior.said.clone(),
            signing_keys,
            signing_threshold,
            next_key_digests,
            next_threshold,
            anchors: Vec::new(),
            said: String::new(),
        };
        ev.said = ev.compute_said();
        Ok(ev)
    }

    /// Build an interaction event chaining off a prior event. Key state is
    /// inherited from the prior event — only the anchor list is set.
    pub fn interaction(prior: &KeriEvent, anchors: Vec<Vec<u8>>) -> Self {
        let mut ev = Self {
            kind: KeriEventKind::Interaction,
            sequence: prior.sequence + 1,
            prior_said: prior.said.clone(),
            signing_keys: prior.signing_keys.clone(),
            signing_threshold: prior.signing_threshold,
            next_key_digests: prior.next_key_digests.clone(),
            next_threshold: prior.next_threshold,
            anchors,
            said: String::new(),
        };
        ev.said = ev.compute_said();
        ev
    }

    /// Compute the SAID over this event with the SAID field replaced by
    /// `"#"` per KERI's self-addressing rule. Returns the
    /// `<TENZRO_KERI_PREFIX>` + base64url(SHA-256(canonical event bytes)).
    pub fn compute_said(&self) -> String {
        let canonical = self.canonical_bytes_with_said("#");
        let mut h = Sha256::new();
        h.update(b"tenzro/keri/said");
        h.update(canonical);
        let digest: [u8; 32] = h.finalize().into();
        let b64 = base64_url(&digest);
        format!("{}{}", TENZRO_KERI_PREFIX, b64)
    }

    /// Canonical byte form of the event with `said` field substituted by
    /// the placeholder before hashing.
    fn canonical_bytes_with_said(&self, said_placeholder: &str) -> Vec<u8> {
        let projection = (
            self.kind.tag(),
            self.sequence,
            &self.prior_said,
            &self.signing_keys,
            self.signing_threshold,
            &self.next_key_digests,
            self.next_threshold,
            &self.anchors,
            said_placeholder,
        );
        bincode::serialize(&projection).unwrap_or_default()
    }

    /// Verify the event's stored SAID matches the recomputed value.
    pub fn verify_said(&self) -> bool {
        self.compute_said() == self.said
    }

    /// Validate that this rotation cleanly extends `prior`: the
    /// SHA-256 digests of `self.signing_keys` must match `prior.next_key_digests`
    /// (allowing for the threshold).
    pub fn is_valid_rotation_of(&self, prior: &KeriEvent) -> bool {
        if self.kind != KeriEventKind::Rotation {
            return false;
        }
        if self.prior_said != prior.said {
            return false;
        }
        if self.sequence != prior.sequence + 1 {
            return false;
        }
        for sk in &self.signing_keys {
            let mut h = Sha256::new();
            h.update(sk);
            let d: [u8; 32] = h.finalize().into();
            if !prior.next_key_digests.contains(&d) {
                return false;
            }
        }
        true
    }
}

/// Key Event Log — append-only ordered set of events keyed by sequence.
#[derive(Debug, Default)]
pub struct KeyEventLog {
    events: RwLock<BTreeMap<u64, KeriEvent>>,
}

impl KeyEventLog {
    /// New empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event. Inception goes at sequence 0; subsequent events
    /// must chain via `prior_said`.
    pub fn append(&self, event: KeriEvent) -> Result<()> {
        if !event.verify_said() {
            return Err(IdentityError::CredentialError("SAID mismatch".into()));
        }
        let mut ev = self.events.write().unwrap();
        match event.kind {
            KeriEventKind::Inception => {
                if !ev.is_empty() {
                    return Err(IdentityError::CredentialError(
                        "inception requires empty log".into(),
                    ));
                }
                if event.sequence != 0 {
                    return Err(IdentityError::CredentialError(
                        "inception sequence must be 0".into(),
                    ));
                }
            }
            KeriEventKind::Rotation | KeriEventKind::Interaction => {
                let prior = ev
                    .values()
                    .max_by_key(|e| e.sequence)
                    .ok_or_else(|| IdentityError::CredentialError(
                        "non-inception event requires prior".into(),
                    ))?;
                if event.prior_said != prior.said {
                    return Err(IdentityError::CredentialError(
                        "prior_said does not match latest event".into(),
                    ));
                }
                if event.sequence != prior.sequence + 1 {
                    return Err(IdentityError::CredentialError(
                        "sequence must advance by 1".into(),
                    ));
                }
                if event.kind == KeriEventKind::Rotation
                    && !event.is_valid_rotation_of(prior)
                {
                    return Err(IdentityError::CredentialError(
                        "rotation does not match prior next_key_digests".into(),
                    ));
                }
            }
        }
        ev.insert(event.sequence, event);
        Ok(())
    }

    /// Latest event (highest sequence).
    pub fn latest(&self) -> Option<KeriEvent> {
        self.events
            .read()
            .unwrap()
            .values()
            .max_by_key(|e| e.sequence)
            .cloned()
    }

    /// Number of events.
    pub fn len(&self) -> usize {
        self.events.read().unwrap().len()
    }

    /// Is the log empty?
    pub fn is_empty(&self) -> bool {
        self.events.read().unwrap().is_empty()
    }

    /// All events in sequence order.
    pub fn events(&self) -> Vec<KeriEvent> {
        self.events.read().unwrap().values().cloned().collect()
    }

    /// Identifier prefix = SAID of the inception event.
    pub fn prefix(&self) -> Option<String> {
        self.events.read().unwrap().get(&0).map(|e| e.said.clone())
    }
}

/// URL-safe base64 (without padding) — KERI's standard `B` and `E`
/// codes use this. We re-implement here so the crate doesn't grow a new
/// dependency on `base64` just for this module.
fn base64_url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8 | (bytes[i + 2] as u32);
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let n = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dig(key: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(key);
        h.finalize().into()
    }

    #[test]
    fn inception_then_rotation_extends_log() {
        let kel = KeyEventLog::new();
        let sk0 = vec![0xaa; 32];
        let sk1 = vec![0xbb; 32];
        let icp = KeriEvent::inception(
            vec![sk0.clone()],
            1,
            vec![dig(&sk1)],
            1,
        )
        .unwrap();
        kel.append(icp.clone()).unwrap();
        assert_eq!(kel.len(), 1);
        let sk2 = vec![0xcc; 32];
        let rot = KeriEvent::rotation(
            &icp,
            vec![sk1.clone()],
            1,
            vec![dig(&sk2)],
            1,
        )
        .unwrap();
        kel.append(rot.clone()).unwrap();
        assert_eq!(kel.len(), 2);
        assert_eq!(kel.latest().unwrap().said, rot.said);
    }

    #[test]
    fn rotation_with_wrong_key_rejected() {
        let kel = KeyEventLog::new();
        let sk0 = vec![0xaa; 32];
        let sk1 = vec![0xbb; 32];
        let icp = KeriEvent::inception(vec![sk0], 1, vec![dig(&sk1)], 1).unwrap();
        kel.append(icp.clone()).unwrap();
        let wrong_sk = vec![0xff; 32];
        let bad_rot =
            KeriEvent::rotation(&icp, vec![wrong_sk], 1, vec![dig(b"next")], 1).unwrap();
        let err = kel.append(bad_rot).unwrap_err();
        assert!(matches!(err, IdentityError::CredentialError(_)));
    }

    #[test]
    fn said_is_deterministic_and_verifies() {
        let ev = KeriEvent::inception(vec![vec![1, 2, 3]], 1, vec![[5u8; 32]], 1).unwrap();
        assert!(ev.verify_said());
        // SAID prefix is the Tenzro CESR-style code.
        assert!(ev.said.starts_with(TENZRO_KERI_PREFIX));
    }

    #[test]
    fn empty_signing_keys_rejected() {
        let err = KeriEvent::inception(vec![], 0, vec![], 0).unwrap_err();
        assert!(matches!(err, IdentityError::CredentialError(_)));
    }

    #[test]
    fn interaction_inherits_key_state() {
        let kel = KeyEventLog::new();
        let icp = KeriEvent::inception(vec![vec![1]], 1, vec![[7u8; 32]], 1).unwrap();
        kel.append(icp.clone()).unwrap();
        let ixn = KeriEvent::interaction(&icp, vec![b"anchor".to_vec()]);
        kel.append(ixn.clone()).unwrap();
        let latest = kel.latest().unwrap();
        assert_eq!(latest.kind, KeriEventKind::Interaction);
        assert_eq!(latest.signing_keys, icp.signing_keys);
    }

    #[test]
    fn prefix_is_inception_said() {
        let kel = KeyEventLog::new();
        let icp = KeriEvent::inception(vec![vec![9]], 1, vec![[1u8; 32]], 1).unwrap();
        kel.append(icp.clone()).unwrap();
        assert_eq!(kel.prefix().as_deref(), Some(icp.said.as_str()));
    }
}
