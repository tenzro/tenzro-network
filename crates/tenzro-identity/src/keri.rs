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
//! Every event carries signatures over its SAID by at least the threshold of
//! its signing keys: an inception and an interaction by the current keys, a
//! rotation by the keys it reveals, which must meet the prior event's next
//! threshold among its pre-committed digests. A signing key is an ML-DSA-65
//! verifying key (1952 bytes, signatures under [`KERI_ML_DSA_CONTEXT`]) or an
//! Ed25519 key (32 bytes). A log made with [`KeyEventLog::new`] takes ML-DSA-65
//! keys only: a new identity's events are post-quantum. A log made with
//! [`KeyEventLog::interoperating`] also takes Ed25519 keys, for logs that
//! third-party KERI verifiers resolve.
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

/// Domain separator of the bytes an event's signers sign: this tag and the
/// event's SAID.
pub const KERI_SIGNING_DOMAIN: &[u8] = b"tenzro/keri/event";

/// FIPS 204 context of an ML-DSA-65 signature on an event.
pub const KERI_ML_DSA_CONTEXT: &[u8] = b"tenzro/keri/event/ml-dsa-65";

/// Length of an ML-DSA-65 verifying key.
pub const KERI_ML_DSA_KEY_LEN: usize = tenzro_crypto::pq::ML_DSA_65_VK_LEN;

/// Length of an Ed25519 verifying key.
const ED25519_KEY_LEN: usize = 32;

/// Which signing keys a log accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeriKeyPolicy {
    /// ML-DSA-65 keys only. The default.
    #[default]
    PostQuantum,
    /// ML-DSA-65 or Ed25519 keys.
    AllowEd25519,
}

/// One controller signature on an event: the index of the signing key in the
/// event's signing-key set, and its signature over
/// [`KeriEvent::signing_message`]: ML-DSA-65 under [`KERI_ML_DSA_CONTEXT`]
/// for an ML-DSA-65 key, Ed25519 for an Ed25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeriSignature {
    /// Index into the event's `signing_keys`.
    pub index: u8,
    /// The signature: 3309 bytes for an ML-DSA-65 key, 64 for Ed25519.
    pub signature: Vec<u8>,
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
    /// Signatures by the event's signing keys over its SAID. Not part of the
    /// SAID.
    #[serde(default)]
    pub signatures: Vec<KeriSignature>,
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
            signatures: Vec::new(),
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
            sequence: prior.sequence.saturating_add(1),
            prior_said: prior.said.clone(),
            signing_keys,
            signing_threshold,
            next_key_digests,
            next_threshold,
            anchors: Vec::new(),
            said: String::new(),
            signatures: Vec::new(),
        };
        ev.said = ev.compute_said();
        Ok(ev)
    }

    /// Build an interaction event chaining off a prior event. Key state is
    /// inherited from the prior event — only the anchor list is set.
    pub fn interaction(prior: &KeriEvent, anchors: Vec<Vec<u8>>) -> Self {
        let mut ev = Self {
            kind: KeriEventKind::Interaction,
            sequence: prior.sequence.saturating_add(1),
            prior_said: prior.said.clone(),
            signing_keys: prior.signing_keys.clone(),
            signing_threshold: prior.signing_threshold,
            next_key_digests: prior.next_key_digests.clone(),
            next_threshold: prior.next_threshold,
            anchors,
            said: String::new(),
            signatures: Vec::new(),
        };
        ev.said = ev.compute_said();
        ev
    }

    /// The bytes the event's signing keys sign: [`KERI_SIGNING_DOMAIN`] and
    /// the SAID.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut m = KERI_SIGNING_DOMAIN.to_vec();
        m.extend_from_slice(self.said.as_bytes());
        m
    }

    /// Whether at least `signing_threshold` (and at least one) distinct
    /// signing keys signed the event's SAID.
    pub fn verify_signatures(&self) -> bool {
        let threshold = usize::from(self.signing_threshold);
        if threshold == 0 || threshold > self.signing_keys.len() {
            return false;
        }
        let message = self.signing_message();
        let mut signed = std::collections::BTreeSet::new();
        for s in &self.signatures {
            let Some(key) = self.signing_keys.get(usize::from(s.index)) else {
                return false;
            };
            let verified = match key.len() {
                KERI_ML_DSA_KEY_LEN => tenzro_crypto::pq::ml_dsa_verify(
                    key,
                    KERI_ML_DSA_CONTEXT,
                    &message,
                    &s.signature,
                )
                .is_ok(),
                ED25519_KEY_LEN => {
                    let public =
                        tenzro_crypto::PublicKey::new(tenzro_crypto::KeyType::Ed25519, key.clone());
                    let signature = tenzro_crypto::Signature::new(
                        tenzro_crypto::KeyType::Ed25519,
                        s.signature.clone(),
                    );
                    tenzro_crypto::signatures::verify(&public, &message, &signature).is_ok()
                }
                _ => false,
            };
            if !verified {
                return false;
            }
            signed.insert(s.index);
        }
        signed.len() >= threshold
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
        if prior.sequence.checked_add(1) != Some(self.sequence) {
            return false;
        }
        let mut revealed = std::collections::BTreeSet::new();
        for sk in &self.signing_keys {
            let mut h = Sha256::new();
            h.update(sk);
            let d: [u8; 32] = h.finalize().into();
            if !prior.next_key_digests.contains(&d) || !revealed.insert(d) {
                return false;
            }
        }
        // The keys revealed must carry the threshold the prior event
        // committed the next key set to.
        let committed = usize::from(prior.next_threshold).max(1);
        revealed.len() >= committed
    }
}

/// Key Event Log — append-only ordered set of events keyed by sequence.
#[derive(Debug, Default)]
pub struct KeyEventLog {
    events: RwLock<BTreeMap<u64, KeriEvent>>,
    policy: KeriKeyPolicy,
}

impl KeyEventLog {
    /// New empty log taking ML-DSA-65 signing keys only.
    pub fn new() -> Self {
        Self::default()
    }

    /// New empty log taking ML-DSA-65 or Ed25519 signing keys, for logs that
    /// KERI verifiers outside Tenzro resolve.
    pub fn interoperating() -> Self {
        Self {
            events: RwLock::default(),
            policy: KeriKeyPolicy::AllowEd25519,
        }
    }

    /// The signing keys this log accepts.
    pub fn policy(&self) -> KeriKeyPolicy {
        self.policy
    }

    /// Append an event. Inception goes at sequence 0; subsequent events
    /// must chain via `prior_said`.
    pub fn append(&self, event: KeriEvent) -> Result<()> {
        if !event.verify_said() {
            return Err(IdentityError::CredentialError("SAID mismatch".into()));
        }
        if !event.verify_signatures() {
            return Err(IdentityError::CredentialError(
                "the event is not signed by the threshold of its signing keys".into(),
            ));
        }
        if self.policy == KeriKeyPolicy::PostQuantum
            && event.kind != KeriEventKind::Interaction
            && event
                .signing_keys
                .iter()
                .any(|k| k.len() != KERI_ML_DSA_KEY_LEN)
        {
            return Err(IdentityError::CredentialError(
                "this log takes ML-DSA-65 signing keys only".into(),
            ));
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
                let prior = ev.values().max_by_key(|e| e.sequence).ok_or_else(|| {
                    IdentityError::CredentialError("non-inception event requires prior".into())
                })?;
                if event.prior_said != prior.said {
                    return Err(IdentityError::CredentialError(
                        "prior_said does not match latest event".into(),
                    ));
                }
                if prior.sequence.checked_add(1) != Some(event.sequence) {
                    return Err(IdentityError::CredentialError(
                        "sequence must advance by 1".into(),
                    ));
                }
                if event.kind == KeriEventKind::Interaction
                    && (event.signing_keys != prior.signing_keys
                        || event.signing_threshold != prior.signing_threshold
                        || event.next_key_digests != prior.next_key_digests
                        || event.next_threshold != prior.next_threshold)
                {
                    return Err(IdentityError::CredentialError(
                        "an interaction does not change the key state".into(),
                    ));
                }
                if event.kind == KeriEventKind::Rotation && !event.is_valid_rotation_of(prior) {
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
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

    fn key() -> Ed25519SignerImpl {
        Ed25519SignerImpl::generate().unwrap()
    }

    fn public(k: &Ed25519SignerImpl) -> Vec<u8> {
        k.public_key().as_bytes().to_vec()
    }

    fn dig(key: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(key);
        h.finalize().into()
    }

    /// `ev` signed by `signers`, at their indexes in its signing-key set.
    fn signed(mut ev: KeriEvent, signers: &[&Ed25519SignerImpl]) -> KeriEvent {
        let message = ev.signing_message();
        for k in signers {
            let index = ev
                .signing_keys
                .iter()
                .position(|p| *p == public(k))
                .expect("a signing key") as u8;
            ev.signatures.push(KeriSignature {
                index,
                signature: k.sign(&message).unwrap().as_bytes().to_vec(),
            });
        }
        ev
    }

    #[test]
    fn inception_then_rotation_extends_log() {
        let kel = KeyEventLog::interoperating();
        let (k0, k1, k2) = (key(), key(), key());
        let icp = KeriEvent::inception(vec![public(&k0)], 1, vec![dig(&public(&k1))], 1).unwrap();
        kel.append(signed(icp.clone(), &[&k0])).unwrap();
        assert_eq!(kel.len(), 1);
        let rot =
            KeriEvent::rotation(&icp, vec![public(&k1)], 1, vec![dig(&public(&k2))], 1).unwrap();
        kel.append(signed(rot.clone(), &[&k1])).unwrap();
        assert_eq!(kel.len(), 2);
        assert_eq!(kel.latest().unwrap().said, rot.said);
    }

    #[test]
    fn rotation_with_wrong_key_rejected() {
        let kel = KeyEventLog::interoperating();
        let (k0, k1, wrong) = (key(), key(), key());
        let icp = KeriEvent::inception(vec![public(&k0)], 1, vec![dig(&public(&k1))], 1).unwrap();
        kel.append(signed(icp.clone(), &[&k0])).unwrap();
        let bad_rot =
            KeriEvent::rotation(&icp, vec![public(&wrong)], 1, vec![dig(b"next")], 1).unwrap();
        let err = kel.append(signed(bad_rot, &[&wrong])).unwrap_err();
        assert!(matches!(err, IdentityError::CredentialError(_)));
    }

    /// A rotation that reveals fewer pre-committed keys than the prior
    /// event's next threshold is refused, as is one carrying no signature
    /// by the keys it reveals.
    #[test]
    fn a_rotation_meets_the_committed_threshold_and_is_signed() {
        let kel = KeyEventLog::interoperating();
        let (k0, k1, k2) = (key(), key(), key());
        let icp = KeriEvent::inception(
            vec![public(&k0)],
            1,
            vec![dig(&public(&k1)), dig(&public(&k2))],
            2,
        )
        .unwrap();
        kel.append(signed(icp.clone(), &[&k0])).unwrap();
        let short = KeriEvent::rotation(&icp, vec![public(&k1)], 1, vec![dig(b"n")], 1).unwrap();
        assert!(
            kel.append(signed(short, &[&k1])).is_err(),
            "one of two committed keys revealed"
        );
        let both = KeriEvent::rotation(&icp, vec![public(&k1), public(&k2)], 2, vec![dig(b"n")], 1)
            .unwrap();
        assert!(kel.append(both.clone()).is_err(), "no signature");
        assert!(
            kel.append(signed(both.clone(), &[&k1])).is_err(),
            "below the signing threshold"
        );
        let mut by_old_key = both.clone();
        by_old_key.signatures = signed(icp.clone(), &[&k0]).signatures;
        assert!(kel.append(by_old_key).is_err(), "signed by the prior key");
        kel.append(signed(both, &[&k1, &k2])).unwrap();
    }

    /// An interaction event cannot change the key state it inherits.
    #[test]
    fn an_interaction_cannot_change_the_key_state() {
        let kel = KeyEventLog::interoperating();
        let k0 = key();
        let icp = KeriEvent::inception(vec![public(&k0)], 1, vec![[7u8; 32]], 1).unwrap();
        kel.append(signed(icp.clone(), &[&k0])).unwrap();
        let other = key();
        let mut ixn = KeriEvent::interaction(&icp, vec![b"anchor".to_vec()]);
        ixn.signing_keys = vec![public(&other)];
        ixn.next_key_digests = vec![[8u8; 32]];
        ixn.said = ixn.compute_said();
        assert!(kel.append(signed(ixn, &[&other])).is_err());
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
        let kel = KeyEventLog::interoperating();
        let k0 = key();
        let icp = KeriEvent::inception(vec![public(&k0)], 1, vec![[7u8; 32]], 1).unwrap();
        kel.append(signed(icp.clone(), &[&k0])).unwrap();
        let ixn = KeriEvent::interaction(&icp, vec![b"anchor".to_vec()]);
        kel.append(signed(ixn, &[&k0])).unwrap();
        let latest = kel.latest().unwrap();
        assert_eq!(latest.kind, KeriEventKind::Interaction);
        assert_eq!(latest.signing_keys, icp.signing_keys);
    }

    fn pq_key() -> tenzro_crypto::pq::MlDsaSigningKey {
        tenzro_crypto::pq::MlDsaSigningKey::generate()
    }

    /// `ev` signed by the ML-DSA-65 `signers`, at their indexes.
    fn signed_pq(mut ev: KeriEvent, signers: &[&tenzro_crypto::pq::MlDsaSigningKey]) -> KeriEvent {
        let message = ev.signing_message();
        for k in signers {
            let index = ev
                .signing_keys
                .iter()
                .position(|p| p.as_slice() == k.verifying_key_bytes())
                .expect("a signing key") as u8;
            ev.signatures.push(KeriSignature {
                index,
                signature: k.sign(KERI_ML_DSA_CONTEXT, &message),
            });
        }
        ev
    }

    /// A new log is post-quantum: inception, pre-rotation and rotation run
    /// on ML-DSA-65 keys, and an Ed25519 key is refused.
    #[test]
    fn a_new_log_takes_ml_dsa_keys_and_refuses_ed25519() {
        let kel = KeyEventLog::new();
        assert_eq!(kel.policy(), KeriKeyPolicy::PostQuantum);
        let (k0, k1, k2) = (pq_key(), pq_key(), pq_key());
        let vk = |k: &tenzro_crypto::pq::MlDsaSigningKey| k.verifying_key_bytes().to_vec();
        let icp = KeriEvent::inception(vec![vk(&k0)], 1, vec![dig(&vk(&k1))], 1).unwrap();
        kel.append(signed_pq(icp.clone(), &[&k0])).unwrap();
        let rot = KeriEvent::rotation(&icp, vec![vk(&k1)], 1, vec![dig(&vk(&k2))], 1).unwrap();
        kel.append(signed_pq(rot.clone(), &[&k1])).unwrap();
        let ixn = KeriEvent::interaction(&rot, vec![b"anchor".to_vec()]);
        kel.append(signed_pq(ixn, &[&k1])).unwrap();
        assert_eq!(kel.len(), 3);

        // A new identity cannot start on Ed25519.
        let classical = key();
        let fresh = KeyEventLog::new();
        let icp = KeriEvent::inception(vec![public(&classical)], 1, vec![[1u8; 32]], 1).unwrap();
        let err = fresh.append(signed(icp.clone(), &[&classical])).unwrap_err();
        assert!(err.to_string().contains("ML-DSA-65 signing keys only"), "{err}");
        // The same event is taken by a log that interoperates.
        KeyEventLog::interoperating()
            .append(signed(icp, &[&classical]))
            .unwrap();
    }

    /// An ML-DSA-65 event signed by another key, by a tampered signature or
    /// under another context does not verify.
    #[test]
    fn an_ml_dsa_event_needs_its_own_keys_signature() {
        let (k0, other) = (pq_key(), pq_key());
        let vk = k0.verifying_key_bytes().to_vec();
        let icp = KeriEvent::inception(vec![vk.clone()], 1, vec![[7u8; 32]], 1).unwrap();
        assert!(signed_pq(icp.clone(), &[&k0]).verify_signatures());

        let mut by_other = icp.clone();
        by_other.signatures.push(KeriSignature {
            index: 0,
            signature: other.sign(KERI_ML_DSA_CONTEXT, &icp.signing_message()),
        });
        assert!(!by_other.verify_signatures());

        let mut tampered = signed_pq(icp.clone(), &[&k0]);
        tampered.signatures[0].signature[10] ^= 1;
        assert!(!tampered.verify_signatures());

        let mut wrong_context = icp.clone();
        wrong_context.signatures.push(KeriSignature {
            index: 0,
            signature: k0.sign(b"tenzro/keri/other", &icp.signing_message()),
        });
        assert!(!wrong_context.verify_signatures());
    }

    #[test]
    fn prefix_is_inception_said() {
        let kel = KeyEventLog::interoperating();
        let k0 = key();
        let icp = KeriEvent::inception(vec![public(&k0)], 1, vec![[1u8; 32]], 1).unwrap();
        kel.append(signed(icp.clone(), &[&k0])).unwrap();
        assert_eq!(kel.prefix().as_deref(), Some(icp.said.as_str()));
    }
}
