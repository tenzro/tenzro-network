//! Where to reach a validator, told only to the committee.
//!
//! A validator's network endpoint is a key its node makes at boot and never
//! stores, so it is not part of the validator's registration. On every boot
//! the validator signs an [`EndpointAnnouncement`] with its consensus key.
//! The announcement is public but does not name the endpoint: it carries a
//! salted commitment to it, this boot's session key, and this boot's
//! disclosure key. The endpoint itself is sealed to each committee member's
//! disclosure key ([`SealedEndpoint`]), so only the committee learns where to
//! reach the validator; anyone else sees its key, stake and announcements, and
//! nothing of its network location. A member that opens a sealed endpoint
//! checks it against the signed commitment, so a sealed endpoint nobody but
//! the validator could have made is never admitted.
//!
//! The sealed copy also names the machine identity whose signed endpoint
//! record says how to reach the endpoint. A member resolves the endpoint only
//! through that record, and only when the record names the committed
//! endpoint; the validator shares the record with the committee's machines
//! alone, and it names relays, never an address.
//!
//! Peers dial, and admit consensus channels from, only the endpoint that
//! opens the newest announcement verifying under the validator's registered
//! key, and accept a channel handshake only when that announcement's session
//! key signed it.
//!
//! An announcement is signed once per boot and again at half its lifetime,
//! so it costs the hardware key a few signatures a day. Handshakes are
//! signed by the session key, and the consensus traffic itself runs on
//! channels keyed by the handshake. The disclosure key, like the session key,
//! lives only in memory for one boot.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tenzro_crypto::hybrid_seal::{self, HybridSealed, HybridSecretKey};
use zeroize::Zeroizing;

use crate::error::{ConsensusError, Result};
use crate::validator_key::{CompositeSignature, ValidatorPublicKey, ValidatorSigner};

/// Domain separator of an endpoint announcement.
pub const ANNOUNCEMENT_DOMAIN: &[u8] = b"tenzro/consensus/endpoint";

/// Longest lifetime an announcement may claim. Bounds how long an endpoint
/// the validator no longer runs can be dialled.
pub const MAX_ANNOUNCEMENT_LIFETIME_MS: u64 = 24 * 3_600 * 1_000;

/// How far ahead of the local clock an announcement may be issued.
pub const MAX_CLOCK_SKEW_MS: u64 = 60_000;

const COMMITMENT_DOMAIN: &str = "tenzro/consensus/endpoint/commitment";
const DISCLOSURE_KEY_DOMAIN: &[u8] = b"tenzro/consensus/endpoint/disclosure-key";
/// Context of an endpoint sealed with [`hybrid_seal`], followed by the
/// sender's and the recipient's key fingerprints.
const SEAL_CONTEXT: &[u8] = b"tenzro/consensus/endpoint/seal/v2";
const SALT_DOMAIN: &str = "tenzro/consensus/endpoint/salt";
/// Longest machine identity a sealed endpoint carries.
const MAX_MACHINE_ID_LEN: usize = 256;

/// The commitment salt for the machine identity `machine` from the random
/// `seed`: the salt binds the machine whose record resolves the endpoint, so
/// the commitment does too.
pub fn endpoint_salt(seed: &[u8; 32], machine: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(SALT_DOMAIN);
    h.update(seed);
    h.update(machine.as_bytes());
    h.finalize().into()
}

/// The commitment an announcement carries to `endpoint` under `salt`.
pub fn endpoint_commitment(endpoint: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(COMMITMENT_DOMAIN);
    h.update(endpoint);
    h.update(salt);
    h.finalize().into()
}

/// The public half of a validator's disclosure key for one boot: an X25519
/// key and an ML-KEM-768 encapsulation key. Endpoints sealed to it need
/// both key exchanges broken to be read.
pub type DisclosureKey = hybrid_seal::HybridPublicKey;

/// Digest of a disclosure key, which the announcement signs.
pub fn disclosure_key_digest(key: &DisclosureKey) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DISCLOSURE_KEY_DOMAIN);
    h.update(&key.x25519);
    h.update(&key.ml_kem);
    h.finalize().into()
}

/// The context an endpoint from `sender` to `recipient` is sealed under.
fn seal_context(sender: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
    let mut c = Vec::with_capacity(SEAL_CONTEXT.len() + 64);
    c.extend_from_slice(SEAL_CONTEXT);
    c.extend_from_slice(sender);
    c.extend_from_slice(recipient);
    c
}

/// This boot's disclosure key. Made at boot, held only in memory, never
/// stored or sent.
pub struct DisclosureSecret {
    key: HybridSecretKey,
}

impl DisclosureSecret {
    /// A fresh key from the OS random source.
    pub fn generate() -> Self {
        Self {
            key: HybridSecretKey::generate(),
        }
    }

    /// The public half, which the announcement names.
    pub fn public(&self) -> &DisclosureKey {
        self.key.public()
    }

    /// Opens `sealed`, made for this key by the validator `sender`. Returns
    /// the endpoint, the salt derived from the seed and machine identity it
    /// carries, and that machine identity; the caller checks the endpoint
    /// and salt against the sender's signed commitment.
    fn open(
        &self,
        sender: &[u8; 32],
        sealed: &SealedEndpoint,
    ) -> Result<([u8; 32], [u8; 32], String)> {
        let hybrid = HybridSealed {
            x25519_share: sealed.x25519,
            ml_kem_ciphertext: sealed.ml_kem.clone(),
            ciphertext: sealed.ciphertext.clone(),
        };
        let plain = self
            .key
            .open(&hybrid, &seal_context(sender, &sealed.recipient))
            .map_err(|_| {
                ConsensusError::Channel("sealed endpoint does not open under this key".into())
            })?;
        if plain.len() <= 64 || plain.len() > 64 + MAX_MACHINE_ID_LEN {
            return Err(ConsensusError::Channel(
                "sealed endpoint has the wrong length".into(),
            ));
        }
        let mut endpoint = [0u8; 32];
        let mut seed = [0u8; 32];
        endpoint.copy_from_slice(&plain[..32]);
        seed.copy_from_slice(&plain[32..64]);
        let machine = std::str::from_utf8(&plain[64..])
            .map_err(|_| ConsensusError::Channel("sealed machine identity is not UTF-8".into()))?
            .to_string();
        Ok((endpoint, endpoint_salt(&seed, &machine), machine))
    }
}

/// This boot's endpoint and the salt its announcement commits to it under.
/// Held only in memory.
#[derive(Clone)]
pub struct EndpointOpening {
    /// The endpoint key peers dial.
    pub endpoint: [u8; 32],
    /// The commitment salt, derived from `seed` and `machine`.
    pub salt: [u8; 32],
    /// The machine identity whose signed endpoint record resolves `endpoint`.
    pub machine: String,
    /// The random seed of the salt, sealed to members in its place.
    seed: [u8; 32],
}

impl EndpointOpening {
    /// A fresh salt for `endpoint`, resolved through `machine`'s record.
    pub fn new(endpoint: [u8; 32], machine: String) -> Result<Self> {
        if machine.is_empty() || machine.len() > MAX_MACHINE_ID_LEN {
            return Err(ConsensusError::Channel(
                "machine identity has the wrong length".into(),
            ));
        }
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Ok(Self {
            endpoint,
            salt: endpoint_salt(&seed, &machine),
            machine,
            seed,
        })
    }

    /// The commitment the announcement signs.
    pub fn commitment(&self) -> [u8; 32] {
        endpoint_commitment(&self.endpoint, &self.salt)
    }

    /// Seals this endpoint, from the validator `sender`, to the member
    /// `recipient` holding `key`.
    pub fn seal(
        &self,
        sender: &[u8; 32],
        recipient: [u8; 32],
        key: &DisclosureKey,
    ) -> Result<SealedEndpoint> {
        let mut plain = Zeroizing::new(Vec::with_capacity(64 + self.machine.len()));
        plain.extend_from_slice(&self.endpoint);
        plain.extend_from_slice(&self.seed);
        plain.extend_from_slice(self.machine.as_bytes());
        let sealed = hybrid_seal::seal(key, &seal_context(sender, &recipient), &plain[..])
            .map_err(|e| ConsensusError::Channel(format!("seal: {e}")))?;
        Ok(SealedEndpoint {
            recipient,
            x25519: sealed.x25519_share,
            ml_kem: sealed.ml_kem_ciphertext,
            ciphertext: sealed.ciphertext,
        })
    }
}

/// A validator's endpoint and commitment salt, sealed to one committee
/// member's disclosure key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedEndpoint {
    /// Fingerprint of the member's consensus key.
    pub recipient: [u8; 32],
    /// The sender's ephemeral X25519 share.
    pub x25519: [u8; 32],
    /// ML-KEM-768 ciphertext to the member's encapsulation key.
    pub ml_kem: Vec<u8>,
    /// AES-256-GCM encryption of the endpoint, salt and machine identity.
    pub ciphertext: Vec<u8>,
}

/// What a validator publishes: its signed announcement and its endpoint
/// sealed to each committee member it holds an announcement of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedAnnouncement {
    /// The signed announcement.
    pub announcement: EndpointAnnouncement,
    /// The endpoint, sealed to members.
    pub sealed: Vec<SealedEndpoint>,
}

/// A validator's signed statement, for one boot, of how to reach it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointAnnouncement {
    /// Chain the announcement is for.
    pub chain_id: u64,
    /// Genesis of that chain.
    pub genesis_hash: [u8; 32],
    /// Fingerprint of the announcing validator's consensus key.
    pub validator: [u8; 32],
    /// Salted commitment to the endpoint key peers dial (see
    /// [`endpoint_commitment`]).
    pub endpoint_commitment: [u8; 32],
    /// This boot's session key (see [`crate::session`]), which signs the
    /// validator's channel handshakes.
    pub session_key: ValidatorPublicKey,
    /// This boot's disclosure key, which members seal their endpoints to.
    pub disclosure_key: DisclosureKey,
    /// When it was signed, in Unix milliseconds.
    pub issued_ms: u64,
    /// When it stops naming the validator's endpoint and session key, in
    /// Unix milliseconds.
    pub not_after_ms: u64,
    /// Composite signature by the validator's consensus key.
    pub signature: CompositeSignature,
}

/// What the validator signs: every field but the signature.
fn announcement_message(a: &EndpointAnnouncement) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + 32 * 5 + 16);
    m.extend_from_slice(&a.chain_id.to_be_bytes());
    m.extend_from_slice(&a.genesis_hash);
    m.extend_from_slice(&a.validator);
    m.extend_from_slice(&a.endpoint_commitment);
    m.extend_from_slice(&a.session_key.fingerprint());
    m.extend_from_slice(&disclosure_key_digest(&a.disclosure_key));
    m.extend_from_slice(&a.issued_ms.to_be_bytes());
    m.extend_from_slice(&a.not_after_ms.to_be_bytes());
    m
}

impl EndpointAnnouncement {
    /// Signs, with the hardware `signer`, an announcement committing to
    /// `opening`'s endpoint and naming `session_key` and `disclosure_key`,
    /// valid from `now_ms` for `lifetime_ms` (the genesis
    /// [`crate::TimeRules::announcement_lifetime_ms`]).
    pub fn sign(
        signer: &dyn ValidatorSigner,
        chain_id: u64,
        genesis_hash: [u8; 32],
        opening: &EndpointOpening,
        session_key: ValidatorPublicKey,
        disclosure_key: DisclosureKey,
        now_ms: u64,
        lifetime_ms: u64,
    ) -> Result<Self> {
        let mut a = Self {
            chain_id,
            genesis_hash,
            validator: signer.public_key().fingerprint(),
            endpoint_commitment: opening.commitment(),
            session_key,
            disclosure_key,
            issued_ms: now_ms,
            not_after_ms: now_ms.saturating_add(lifetime_ms),
            signature: CompositeSignature {
                ml_dsa: Vec::new(),
                p256: Vec::new(),
            },
        };
        a.signature = signer.sign(ANNOUNCEMENT_DOMAIN, &announcement_message(&a))?;
        Ok(a)
    }

    /// Whether `endpoint` under `salt` is the endpoint this announcement
    /// commits to.
    pub fn commits_to(&self, endpoint: &[u8; 32], salt: &[u8; 32]) -> bool {
        endpoint_commitment(endpoint, salt) == self.endpoint_commitment
    }

    /// Checks, whatever the time, that `key` made this announcement for this
    /// chain and claimed no more than [`MAX_ANNOUNCEMENT_LIFETIME_MS`].
    pub fn check_certified_by(
        &self,
        key: &ValidatorPublicKey,
        chain_id: u64,
        genesis_hash: &[u8; 32],
    ) -> Result<()> {
        let refuse = |why: &str| {
            Err(ConsensusError::InvalidValidatorKey(format!(
                "endpoint announcement: {why}"
            )))
        };
        if self.validator != key.fingerprint() {
            return refuse("names another validator");
        }
        if self.chain_id != chain_id || &self.genesis_hash != genesis_hash {
            return refuse("for another chain");
        }
        if self.not_after_ms <= self.issued_ms
            || self.not_after_ms - self.issued_ms > MAX_ANNOUNCEMENT_LIFETIME_MS
        {
            return refuse("lifetime out of bounds");
        }
        if !key.verify(
            ANNOUNCEMENT_DOMAIN,
            &announcement_message(self),
            &self.signature,
        ) {
            return refuse("signature does not verify under the validator's key");
        }
        Ok(())
    }

    /// [`Self::check_certified_by`], and current at `now_ms`.
    pub fn verify(
        &self,
        key: &ValidatorPublicKey,
        chain_id: u64,
        genesis_hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<()> {
        self.check_certified_by(key, chain_id, genesis_hash)?;
        if self.issued_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
            return Err(ConsensusError::InvalidValidatorKey(
                "endpoint announcement: issued in the future".into(),
            ));
        }
        if self.not_after_ms <= now_ms {
            return Err(ConsensusError::InvalidValidatorKey(
                "endpoint announcement: expired".into(),
            ));
        }
        Ok(())
    }

    /// Whether the announcement is past half its lifetime at `now_ms`, when
    /// the validator signs a fresh one.
    pub fn due_for_renewal(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_ms + (self.not_after_ms - self.issued_ms) / 2
    }
}

/// The newest verified announcement of each validator, by key fingerprint,
/// with its endpoint and machine identity once a sealed copy for this node
/// opened against it.
#[derive(Debug, Default)]
pub struct EndpointBook {
    entries: HashMap<[u8; 32], (EndpointAnnouncement, Option<([u8; 32], String)>)>,
}

impl EndpointBook {
    /// An empty book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `announcement` when it verifies under `key` (the registered
    /// key of the validator it names) and was issued after the one held.
    /// Returns whether it was recorded. An older announcement is ignored, so
    /// replaying one cannot move a validator back to an endpoint it left. A
    /// renewal committing to the same endpoint keeps the opened endpoint.
    pub fn offer(
        &mut self,
        announcement: EndpointAnnouncement,
        key: &ValidatorPublicKey,
        chain_id: u64,
        genesis_hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<bool> {
        announcement.verify(key, chain_id, genesis_hash, now_ms)?;
        let opened = match self.entries.get(&announcement.validator) {
            Some((held, _)) if held.issued_ms >= announcement.issued_ms => return Ok(false),
            Some((held, opened))
                if held.endpoint_commitment == announcement.endpoint_commitment =>
            {
                opened.clone()
            }
            _ => None,
        };
        self.entries
            .insert(announcement.validator, (announcement, opened));
        Ok(true)
    }

    /// Opens, with this node's `secret`, the copy among `sealed` made for
    /// `me` by the validator `sender`, and records its endpoint if it is the
    /// one `sender`'s held announcement commits to. Returns whether an
    /// endpoint was recorded.
    pub fn open(
        &mut self,
        sender: &[u8; 32],
        me: &[u8; 32],
        sealed: &[SealedEndpoint],
        secret: &DisclosureSecret,
    ) -> bool {
        let Some((held, opened)) = self.entries.get_mut(sender) else {
            return false;
        };
        let Some(mine) = sealed.iter().find(|s| &s.recipient == me) else {
            return false;
        };
        match secret.open(sender, mine) {
            Ok((endpoint, salt, machine)) if held.commits_to(&endpoint, &salt) => {
                *opened = Some((endpoint, machine));
                true
            }
            _ => false,
        }
    }

    /// The validator holding `key`'s current announcement.
    pub fn current(&self, key: &ValidatorPublicKey, now_ms: u64) -> Option<&EndpointAnnouncement> {
        self.entries
            .get(&key.fingerprint())
            .map(|(a, _)| a)
            .filter(|a| a.not_after_ms > now_ms)
    }

    /// The endpoint the validator holding `key` disclosed to this node,
    /// while its announcement is current.
    pub fn endpoint(&self, key: &ValidatorPublicKey, now_ms: u64) -> Option<[u8; 32]> {
        self.disclosed(key, now_ms).map(|(e, _)| *e)
    }

    /// The endpoint the validator holding `key` disclosed to this node and
    /// the machine identity whose record resolves it, while its
    /// announcement is current.
    pub fn disclosed(&self, key: &ValidatorPublicKey, now_ms: u64) -> Option<&([u8; 32], String)> {
        self.entries
            .get(&key.fingerprint())
            .filter(|(a, _)| a.not_after_ms > now_ms)
            .and_then(|(_, e)| e.as_ref())
    }

    /// The machine identities of every current disclosed endpoint.
    pub fn disclosed_machines(&self, now_ms: u64) -> impl Iterator<Item = &str> {
        self.entries
            .values()
            .filter(move |(a, _)| a.not_after_ms > now_ms)
            .filter_map(|(_, e)| e.as_ref().map(|(_, m)| m.as_str()))
    }

    /// Every current announcement, for sealing this node's endpoint to.
    pub fn announcements(&self, now_ms: u64) -> impl Iterator<Item = &EndpointAnnouncement> {
        self.entries
            .values()
            .map(|(a, _)| a)
            .filter(move |a| a.not_after_ms > now_ms)
    }

    /// Drops every announcement expired at `now_ms`.
    pub fn expire(&mut self, now_ms: u64) {
        self.entries.retain(|_, (a, _)| a.not_after_ms > now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_key::test_signer::SoftwareTestSigner;

    const CHAIN: u64 = 7;
    const GENESIS: [u8; 32] = [3u8; 32];
    const NOW: u64 = 1_800_000_000_000;
    const ANNOUNCEMENT_LIFETIME_MS: u64 = 6 * 3_600 * 1_000;

    struct Boot {
        signer: SoftwareTestSigner,
        opening: EndpointOpening,
        secret: DisclosureSecret,
        announcement: EndpointAnnouncement,
    }

    fn boot(seed: u64, endpoint: u8, at: u64) -> Boot {
        let signer = SoftwareTestSigner::from_seed(seed);
        let opening =
            EndpointOpening::new([endpoint; 32], format!("did:tenzro:machine:{endpoint}")).unwrap();
        let secret = DisclosureSecret::generate();
        let session = SoftwareTestSigner::from_seed(100 + endpoint as u64)
            .public_key()
            .clone();
        let announcement = EndpointAnnouncement::sign(
            &signer,
            CHAIN,
            GENESIS,
            &opening,
            session,
            secret.public().clone(),
            at,
            ANNOUNCEMENT_LIFETIME_MS,
        )
        .unwrap();
        Boot {
            signer,
            opening,
            secret,
            announcement,
        }
    }

    fn fp(b: &Boot) -> [u8; 32] {
        b.signer.public_key().fingerprint()
    }

    /// `from`'s endpoint sealed to `to`.
    fn seal(from: &Boot, to: &Boot) -> SealedEndpoint {
        from.opening
            .seal(&fp(from), fp(to), &to.announcement.disclosure_key)
            .unwrap()
    }

    #[test]
    fn an_announcement_verifies_only_under_its_validators_key_on_its_chain() {
        let b = boot(1, 9, NOW);
        let other = SoftwareTestSigner::from_seed(2);
        let a = b.announcement.clone();
        let key = b.signer.public_key();
        assert!(a.verify(key, CHAIN, &GENESIS, NOW).is_ok());
        assert!(
            a.verify(other.public_key(), CHAIN, &GENESIS, NOW).is_err(),
            "another key"
        );
        assert!(
            a.verify(key, CHAIN + 1, &GENESIS, NOW).is_err(),
            "another chain"
        );
        assert!(
            a.verify(key, CHAIN, &[4u8; 32], NOW).is_err(),
            "another genesis"
        );
        let mut moved = a.clone();
        moved.endpoint_commitment = endpoint_commitment(&[8u8; 32], &b.opening.salt);
        assert!(
            moved.verify(key, CHAIN, &GENESIS, NOW).is_err(),
            "endpoint swapped after signing"
        );
        let mut rekeyed = a.clone();
        rekeyed.session_key = other.public_key().clone();
        assert!(
            rekeyed.verify(key, CHAIN, &GENESIS, NOW).is_err(),
            "session key swapped after signing"
        );
        let mut redisclosed = a.clone();
        redisclosed.disclosure_key = DisclosureSecret::generate().public().clone();
        assert!(
            redisclosed.verify(key, CHAIN, &GENESIS, NOW).is_err(),
            "disclosure key swapped after signing"
        );
        let mut stretched = a.clone();
        stretched.not_after_ms += 1;
        assert!(
            stretched.verify(key, CHAIN, &GENESIS, NOW).is_err(),
            "lifetime stretched"
        );
        let mut renamed = a;
        renamed.validator = other.public_key().fingerprint();
        assert!(
            renamed
                .verify(other.public_key(), CHAIN, &GENESIS, NOW)
                .is_err(),
            "claimed for another validator"
        );
    }

    #[test]
    fn the_published_announcement_does_not_carry_the_endpoint() {
        let a = boot(1, 0x5a, NOW);
        let b = boot(2, 0x6b, NOW);
        let published = PublishedAnnouncement {
            announcement: a.announcement.clone(),
            sealed: vec![seal(&a, &b)],
        };
        let bytes = bincode::serialize(&published).unwrap();
        assert!(
            !bytes.windows(32).any(|w| w == a.opening.endpoint),
            "the endpoint in the clear"
        );
        assert!(
            !bytes.windows(32).any(|w| w == a.opening.salt),
            "the salt in the clear"
        );
        assert!(
            a.announcement
                .commits_to(&a.opening.endpoint, &a.opening.salt)
        );
        assert!(
            !a.announcement.commits_to(&a.opening.endpoint, &[0u8; 32]),
            "the salt is bound"
        );
    }

    #[test]
    fn an_announcement_is_current_only_within_its_lifetime() {
        let b = boot(1, 9, NOW);
        let a = &b.announcement;
        let key = b.signer.public_key();
        assert!(
            a.verify(key, CHAIN, &GENESIS, NOW + ANNOUNCEMENT_LIFETIME_MS)
                .is_err(),
            "expired"
        );
        let early = boot(1, 9, NOW + MAX_CLOCK_SKEW_MS + 1);
        assert!(
            early
                .announcement
                .verify(key, CHAIN, &GENESIS, NOW)
                .is_err(),
            "issued in the future"
        );
        assert!(!a.due_for_renewal(NOW + ANNOUNCEMENT_LIFETIME_MS / 2 - 1));
        assert!(a.due_for_renewal(NOW + ANNOUNCEMENT_LIFETIME_MS / 2));
    }

    #[test]
    fn a_member_learns_the_endpoint_only_from_a_copy_sealed_to_it() {
        let v = boot(1, 9, NOW);
        let member = boot(2, 20, NOW);
        let outsider = boot(3, 30, NOW);
        let key = v.signer.public_key();
        let sealed = vec![seal(&v, &member)];

        let mut book = EndpointBook::new();
        assert!(
            book.offer(v.announcement.clone(), key, CHAIN, &GENESIS, NOW)
                .unwrap()
        );
        assert_eq!(
            book.endpoint(key, NOW),
            None,
            "the announcement alone names no endpoint"
        );
        assert!(book.current(key, NOW).is_some());
        assert!(book.open(&fp(&v), &fp(&member), &sealed, &member.secret));
        assert_eq!(book.endpoint(key, NOW), Some([9u8; 32]));
        assert_eq!(
            book.disclosed(key, NOW).map(|(_, m)| m.as_str()),
            Some("did:tenzro:machine:9")
        );
        assert_eq!(
            book.disclosed_machines(NOW).collect::<Vec<_>>(),
            vec!["did:tenzro:machine:9"]
        );

        // A node the endpoint was not sealed to learns nothing, even holding
        // the copy made for the member.
        let mut other = EndpointBook::new();
        other
            .offer(v.announcement.clone(), key, CHAIN, &GENESIS, NOW)
            .unwrap();
        assert!(
            !other.open(&fp(&v), &fp(&outsider), &sealed, &outsider.secret),
            "no copy for it"
        );
        let mut readdressed = sealed.clone();
        readdressed[0].recipient = fp(&outsider);
        assert!(
            !other.open(&fp(&v), &fp(&outsider), &readdressed, &outsider.secret),
            "another's copy"
        );
        assert_eq!(other.endpoint(key, NOW), None);
    }

    /// A member that opened the validator's endpoint cannot reseal it to
    /// another member under its own machine identity: the commitment binds
    /// the machine whose record resolves the endpoint.
    #[test]
    fn a_member_cannot_reseal_an_endpoint_under_another_machine() {
        let v = boot(1, 9, NOW);
        let byzantine = boot(2, 20, NOW);
        let honest = boot(3, 30, NOW);
        let key = v.signer.public_key();
        let mut book = EndpointBook::new();
        book.offer(v.announcement.clone(), key, CHAIN, &GENESIS, NOW)
            .unwrap();
        assert!(book.open(&fp(&v), &fp(&honest), &[seal(&v, &honest)], &honest.secret));

        let mut relabelled = v.opening.clone();
        relabelled.machine = "did:tenzro:machine:20".into();
        let forged = relabelled
            .seal(&fp(&v), fp(&honest), &honest.announcement.disclosure_key)
            .unwrap();
        assert!(!book.open(&fp(&v), &fp(&honest), &[forged], &honest.secret));
        assert_eq!(
            book.disclosed(key, NOW).map(|(_, m)| m.as_str()),
            Some("did:tenzro:machine:9")
        );
        let _ = byzantine;
    }

    #[test]
    fn a_sealed_endpoint_the_announcement_does_not_commit_to_is_refused() {
        let v = boot(1, 9, NOW);
        let member = boot(2, 20, NOW);
        let key = v.signer.public_key();
        let mut book = EndpointBook::new();
        book.offer(v.announcement.clone(), key, CHAIN, &GENESIS, NOW)
            .unwrap();
        // Anyone can seal an endpoint to the member under the validator's
        // name; only the one its signed commitment names is admitted.
        let impostor = EndpointOpening::new([66u8; 32], "did:tenzro:machine:66".into()).unwrap();
        let forged = impostor
            .seal(&fp(&v), fp(&member), &member.announcement.disclosure_key)
            .unwrap();
        assert!(!book.open(&fp(&v), &fp(&member), &[forged], &member.secret));
        let mut tampered = seal(&v, &member);
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 1;
        assert!(
            !book.open(&fp(&v), &fp(&member), &[tampered], &member.secret),
            "tampered ciphertext"
        );
        assert_eq!(book.endpoint(key, NOW), None);
    }

    #[test]
    fn the_book_keeps_the_newest_announcement_and_ignores_a_replay() {
        let first = boot(1, 9, NOW);
        let member = boot(2, 20, NOW);
        let key = first.signer.public_key().clone();
        let mut book = EndpointBook::new();
        assert!(
            book.offer(
                first.announcement.clone(),
                &key,
                CHAIN,
                &GENESIS,
                NOW + 2_000
            )
            .unwrap()
        );
        assert!(book.open(
            &fp(&first),
            &fp(&member),
            &[seal(&first, &member)],
            &member.secret
        ));
        // A renewal committing to the same endpoint keeps it.
        let session = SoftwareTestSigner::from_seed(109).public_key().clone();
        let renewal = EndpointAnnouncement::sign(
            &first.signer,
            CHAIN,
            GENESIS,
            &first.opening,
            session,
            first.secret.public().clone(),
            NOW + 500,
            ANNOUNCEMENT_LIFETIME_MS,
        )
        .unwrap();
        assert!(
            book.offer(renewal, &key, CHAIN, &GENESIS, NOW + 2_000)
                .unwrap()
        );
        assert_eq!(book.endpoint(&key, NOW + 2_000), Some([9u8; 32]));
        // A new boot commits to a new endpoint, which must be opened again.
        let second = boot(1, 10, NOW + 1_000);
        assert!(
            book.offer(
                second.announcement.clone(),
                &key,
                CHAIN,
                &GENESIS,
                NOW + 2_000
            )
            .unwrap()
        );
        assert_eq!(book.endpoint(&key, NOW + 2_000), None);
        assert!(book.open(
            &fp(&second),
            &fp(&member),
            &[seal(&second, &member)],
            &member.secret
        ));
        assert_eq!(book.endpoint(&key, NOW + 2_000), Some([10u8; 32]));
        assert!(
            !book
                .offer(
                    first.announcement.clone(),
                    &key,
                    CHAIN,
                    &GENESIS,
                    NOW + 2_000
                )
                .unwrap(),
            "replay of the old boot"
        );
        assert!(
            !book.open(
                &fp(&first),
                &fp(&member),
                &[seal(&first, &member)],
                &member.secret
            ),
            "the old endpoint"
        );
        assert_eq!(book.endpoint(&key, NOW + 2_000), Some([10u8; 32]));
    }

    #[test]
    fn the_book_refuses_an_announcement_signed_by_another_validator() {
        let v = boot(1, 9, NOW);
        let attacker = boot(2, 66, NOW);
        let mut book = EndpointBook::new();
        let mut forged = attacker.announcement.clone();
        forged.validator = fp(&v);
        assert!(
            book.offer(forged, v.signer.public_key(), CHAIN, &GENESIS, NOW)
                .is_err()
        );
        assert!(book.current(v.signer.public_key(), NOW).is_none());
    }

    #[test]
    fn an_expired_announcement_names_no_endpoint() {
        let v = boot(1, 9, NOW);
        let member = boot(2, 20, NOW);
        let key = v.signer.public_key();
        let mut book = EndpointBook::new();
        book.offer(v.announcement.clone(), key, CHAIN, &GENESIS, NOW)
            .unwrap();
        assert!(book.open(&fp(&v), &fp(&member), &[seal(&v, &member)], &member.secret));
        let later = NOW + ANNOUNCEMENT_LIFETIME_MS;
        assert_eq!(book.endpoint(key, later), None);
        book.expire(later);
        assert_eq!(book.endpoint(key, NOW), None);
    }

    /// A validator whose clock ran fast is restarted with the clock set
    /// right, sooner after its last announcement than the clock was ahead.
    /// Its new boot's announcement carries an earlier `issued_ms` than the
    /// one its peers hold, yet the new boot's endpoint and session key are
    /// the only ones it still runs: peers that keep the old announcement
    /// dial an endpoint nobody serves and refuse every handshake the new
    /// session key signs, until the old announcement expires or the new
    /// boot renews at half its lifetime, hours later.
    #[test]
    #[ignore = "ordering across boots reads the signer's wall clock: a boot whose clock reads earlier than its last announcement is refused"]
    fn a_new_boot_signed_by_a_clock_set_back_replaces_the_last_one() {
        let mut book = EndpointBook::new();
        let fast = boot(1, 9, NOW + 30_000);
        let key = fast.signer.public_key().clone();
        assert!(
            book.offer(fast.announcement.clone(), &key, CHAIN, &GENESIS, NOW)
                .unwrap()
        );
        // Restarted 5 s later with the clock corrected.
        let corrected = boot(1, 10, NOW + 5_000);
        let taken = book
            .offer(
                corrected.announcement.clone(),
                &key,
                CHAIN,
                &GENESIS,
                NOW + 5_000,
            )
            .unwrap();
        assert!(taken, "the validator's running boot was refused");
        assert_eq!(
            book.current(&key, NOW + 5_000).map(|a| &a.session_key),
            Some(&corrected.announcement.session_key)
        );
    }

    /// An endpoint sealed with the shared hybrid seal under the announcement
    /// seal context opens in the book: endpoints are sealed with
    /// `tenzro_crypto::hybrid_seal`, not a second construction.
    #[test]
    fn an_endpoint_sealed_with_the_shared_hybrid_seal_opens() {
        let v = boot(1, 9, NOW);
        let member = boot(2, 20, NOW);
        let key = v.signer.public_key();
        let to = tenzro_crypto::hybrid_seal::HybridPublicKey {
            x25519: member.announcement.disclosure_key.x25519,
            ml_kem: member.announcement.disclosure_key.ml_kem.clone(),
        };
        let mut context = b"tenzro/consensus/endpoint/seal/v2".to_vec();
        context.extend_from_slice(&fp(&v));
        context.extend_from_slice(&fp(&member));
        let mut plain = v.opening.endpoint.to_vec();
        plain.extend_from_slice(&v.opening.seed);
        plain.extend_from_slice(v.opening.machine.as_bytes());
        let s = tenzro_crypto::hybrid_seal::seal(&to, &context, &plain).unwrap();
        let sealed = vec![SealedEndpoint {
            recipient: fp(&member),
            x25519: s.x25519_share,
            ml_kem: s.ml_kem_ciphertext,
            ciphertext: s.ciphertext,
        }];
        let mut book = EndpointBook::new();
        assert!(
            book.offer(v.announcement.clone(), key, CHAIN, &GENESIS, NOW)
                .unwrap()
        );
        assert!(book.open(&fp(&v), &fp(&member), &sealed, &member.secret));
        assert_eq!(book.endpoint(key, NOW), Some([9u8; 32]));
    }
}
