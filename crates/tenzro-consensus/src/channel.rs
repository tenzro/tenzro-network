//! Authenticated consensus channels between validators.
//!
//! Consensus messages carry no signatures; their sender is known because
//! they arrive over a channel only that validator could have opened. A
//! channel runs over one stream of the node's existing QUIC connection to the
//! peer. The transport's own key is not trusted for consensus: the channel is
//! set up by a handshake both validators authenticate with their session
//! keys (composite keys made at boot, each certified by the validator's
//! hardware key in its endpoint announcement, see [`crate::session`]), and
//! every frame on it carries a MAC under a key derived from that handshake.
//! A handshake therefore costs no hardware signature.
//!
//! Handshake (initiator I dials responder R):
//!
//! ```text
//! I -> R  Hello      chain, genesis, epoch, I, R, X25519 share, ML-KEM-768 key, nonce
//! R -> I  Challenge  X25519 share, ML-KEM-768 ciphertext, nonce
//! I -> R  Proof      I's composite signature over (transcript, "initiator")
//! R -> I  Accept     R's composite signature over (transcript, "responder")
//! ```
//!
//! The transcript is the hash of Hello and Challenge. The session keys come
//! from HKDF over both shared secrets (X25519 and ML-KEM-768) salted with the
//! transcript, one key per direction, so forging a frame needs both key
//! exchanges broken and impersonating a validator needs both ML-DSA-65 and
//! ECDSA-P256 broken. R signs only after I has proven it is a committee
//! member, so an unauthenticated dialer costs R no signature.
//!
//! Keys live only in memory for the life of the channel. A channel is bound
//! to one epoch and carries at most 2^32 frames each way; after either, the
//! peers run a fresh handshake.
//!
//! Frame: `sequence:u64 || payload || mac:[u8;32]`, the MAC being keyed
//! BLAKE3 over the direction, sequence and payload. Frames must arrive in
//! sequence order, so a replayed, reordered or dropped frame is refused.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::committee::{Committee, ValidatorIndex};
use crate::error::{ConsensusError, Result};
use crate::validator_key::{CompositeSignature, ValidatorSigner};
use crate::vertex::Digest;

/// Domain separator of handshake signatures.
pub const CHANNEL_DOMAIN: &[u8] = b"tenzro/consensus/channel";
/// Frames a channel carries in one direction before it must be re-keyed.
pub const MAX_FRAMES_PER_KEY: u64 = 1 << 32;

use crate::announce::EndpointAnnouncement;
use crate::kem::{ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN};
use crate::validator_key::ValidatorPublicKey;

/// The session key member `index`'s `announcement` certifies, refusing an
/// announcement its registered key did not make for this chain.
fn session_key_of<'a>(
    committee: &Committee,
    chain_id: u64,
    genesis_hash: &Digest,
    index: ValidatorIndex,
    announcement: &'a EndpointAnnouncement,
) -> Result<&'a ValidatorPublicKey> {
    let member = committee
        .member(index)
        .ok_or_else(|| bad("peer is not a committee member"))?;
    announcement
        .check_certified_by(&member.public_key, chain_id, genesis_hash)
        .map_err(|e| bad(&format!("peer's session key is not certified: {e}")))?;
    Ok(&announcement.session_key)
}

/// What a handshake is checked against.
#[derive(Clone, Copy)]
pub struct ChannelContext<'a> {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis hash.
    pub genesis_hash: &'a Digest,
    /// The current epoch's committee.
    pub committee: &'a Committee,
}

/// Which of a channel's two streams a handshake opens. Carried in `Hello`
/// for bookkeeping only: it plays no part in the key exchange or in
/// authenticating a frame, so a peer that lies about it only misroutes its
/// own traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StreamKind {
    /// Votes, echoes, certificates, handover frames and fetch requests:
    /// latency-sensitive and never to wait behind a bulk payload.
    Control,
    /// Proactive batch pushes and fetch replies: the traffic a round does
    /// not need to make progress, kept off the control stream so it cannot
    /// head-of-line block it under loss.
    Bulk,
}

/// Opening message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Chain id.
    pub chain_id: u64,
    /// Genesis hash.
    pub genesis_hash: Digest,
    /// Epoch the channel is for.
    pub epoch: u64,
    /// Which stream of the channel this handshake opens.
    pub kind: StreamKind,
    /// Initiator.
    pub initiator: ValidatorIndex,
    /// Responder the initiator means to reach.
    pub responder: ValidatorIndex,
    /// Initiator's ephemeral X25519 public key.
    pub x25519: [u8; 32],
    /// Initiator's ephemeral ML-KEM-768 encapsulation key.
    pub ml_kem: Vec<u8>,
    /// Initiator nonce.
    pub nonce: [u8; 32],
}

/// Responder's key-exchange reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// Responder's ephemeral X25519 public key.
    pub x25519: [u8; 32],
    /// ML-KEM-768 ciphertext to the initiator's key.
    pub ml_kem_ciphertext: Vec<u8>,
    /// Responder nonce.
    pub nonce: [u8; 32],
}

/// A composite signature over the transcript and the signer's role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptSignature {
    /// The signature.
    pub signature: CompositeSignature,
}

/// Each side's view of the one bidirectional channel.
pub struct Channel {
    peer: ValidatorIndex,
    epoch: u64,
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    send_seq: u64,
    recv_seq: u64,
    send_label: u8,
    recv_label: u8,
}

fn random32() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn transcript(hello: &Hello, challenge: &Challenge) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(b"tenzro/consensus/channel/transcript");
    h.update(&bincode::serialize(hello).expect("hello encodes"));
    h.update(&bincode::serialize(challenge).expect("challenge encodes"));
    h.finalize().into()
}

fn signed_message(t: &Digest, role: &[u8]) -> Vec<u8> {
    let mut m = t.to_vec();
    m.extend_from_slice(role);
    m
}

fn derive_keys(
    dh: &[u8; 32],
    kem: &[u8; 32],
    t: &Digest,
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(dh);
    ikm[32..].copy_from_slice(kem);
    let hk = Hkdf::<Sha256>::new(Some(t), ikm.as_ref());
    let mut i2r = Zeroizing::new([0u8; 32]);
    let mut r2i = Zeroizing::new([0u8; 32]);
    hk.expand(
        b"tenzro/consensus/channel/initiator-to-responder",
        i2r.as_mut(),
    )
    .expect("32 bytes is a valid HKDF length");
    hk.expand(
        b"tenzro/consensus/channel/responder-to-initiator",
        r2i.as_mut(),
    )
    .expect("32 bytes is a valid HKDF length");
    (i2r, r2i)
}

fn bad(why: &str) -> ConsensusError {
    ConsensusError::Channel(why.to_string())
}

/// The dialling side before the challenge arrives.
pub struct Initiator {
    hello: Hello,
    x25519: x25519_dalek::EphemeralSecret,
    ml_kem: crate::kem::EphemeralKem,
}

/// The dialling side after it sent its proof.
pub struct AwaitingAccept {
    responder: ValidatorIndex,
    epoch: u64,
    transcript: Digest,
    keys: (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>),
}

impl Initiator {
    /// Starts a handshake from `me` to `peer`.
    pub fn start(
        ctx: &ChannelContext<'_>,
        me: ValidatorIndex,
        peer: ValidatorIndex,
        kind: StreamKind,
    ) -> Result<(Self, Hello)> {
        if ctx.committee.member(me).is_none() || ctx.committee.member(peer).is_none() || me == peer
        {
            return Err(bad("both ends of a channel are distinct committee members"));
        }
        let x25519 = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ml_kem = crate::kem::EphemeralKem::generate();
        let hello = Hello {
            chain_id: ctx.chain_id,
            genesis_hash: *ctx.genesis_hash,
            epoch: ctx.committee.epoch,
            kind,
            initiator: me,
            responder: peer,
            x25519: x25519_dalek::PublicKey::from(&x25519).to_bytes(),
            ml_kem: ml_kem.encapsulation_key().to_vec(),
            nonce: random32(),
        };
        Ok((
            Self {
                hello: hello.clone(),
                x25519,
                ml_kem,
            },
            hello,
        ))
    }

    /// Completes the key exchange and signs the transcript with this
    /// validator's session key.
    pub fn on_challenge(
        self,
        challenge: &Challenge,
        signer: &dyn ValidatorSigner,
    ) -> Result<(AwaitingAccept, TranscriptSignature)> {
        if challenge.ml_kem_ciphertext.len() != ML_KEM_768_CT_LEN {
            return Err(bad("challenge carries a malformed ML-KEM ciphertext"));
        }
        let peer_share = x25519_dalek::PublicKey::from(challenge.x25519);
        let dh = self.x25519.diffie_hellman(&peer_share);
        if !dh.was_contributory() {
            return Err(bad("X25519 share is a low-order point"));
        }
        let kem = Zeroizing::new(
            self.ml_kem
                .decapsulate(&challenge.ml_kem_ciphertext)
                .map_err(|e| bad(&format!("ML-KEM decapsulation: {e}")))?,
        );
        let t = transcript(&self.hello, challenge);
        let keys = derive_keys(dh.as_bytes(), &kem, &t);
        let signature = signer.sign(CHANNEL_DOMAIN, &signed_message(&t, b"initiator"))?;
        Ok((
            AwaitingAccept {
                responder: self.hello.responder,
                epoch: self.hello.epoch,
                transcript: t,
                keys,
            },
            TranscriptSignature { signature },
        ))
    }
}

impl AwaitingAccept {
    /// Checks the responder's signature, under the session key its
    /// `announcement` certifies, and opens the channel.
    pub fn on_accept(
        self,
        ctx: &ChannelContext<'_>,
        accept: &TranscriptSignature,
        announcement: &EndpointAnnouncement,
    ) -> Result<Channel> {
        let key = session_key_of(
            ctx.committee,
            ctx.chain_id,
            ctx.genesis_hash,
            self.responder,
            announcement,
        )?;
        if ctx.committee.epoch != self.epoch
            || !key.verify(
                CHANNEL_DOMAIN,
                &signed_message(&self.transcript, b"responder"),
                &accept.signature,
            )
        {
            return Err(bad("responder's transcript signature does not verify"));
        }
        let (i2r, r2i) = self.keys;
        Ok(Channel {
            peer: self.responder,
            epoch: self.epoch,
            send_key: i2r,
            recv_key: r2i,
            send_seq: 0,
            recv_seq: 0,
            send_label: 0,
            recv_label: 1,
        })
    }
}

/// The answering side between challenge and proof.
pub struct Responder {
    hello: Hello,
    transcript: Digest,
    keys: (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>),
    /// This node's committee, stamped with the epoch `hello` actually
    /// named (see `on_hello`).
    committee: Committee,
}

impl Responder {
    /// Answers `hello` for validator `me`. Costs no signature.
    pub fn on_hello(
        ctx: &ChannelContext<'_>,
        me: ValidatorIndex,
        hello: &Hello,
    ) -> Result<(Self, Challenge)> {
        if hello.chain_id != ctx.chain_id || &hello.genesis_hash != ctx.genesis_hash {
            return Err(bad("hello is for another chain"));
        }
        // The channel is bucketed under whichever epoch hello actually
        // names, not this node's own current epoch: two validators can be
        // on either side of an epoch boundary relative to each other, and
        // either can dial the other. This does not weaken who can open a
        // channel: membership and the session-key signature below are
        // still checked against this node's real, current committee, so a
        // validator a reconfiguration has removed is still refused, and a
        // genuinely mismatched key still fails verification in `on_proof`,
        // whatever epoch the hello names.
        let mut committee = ctx.committee.clone();
        committee.epoch = hello.epoch;
        if hello.responder != me
            || hello.initiator == me
            || committee.member(hello.initiator).is_none()
        {
            return Err(bad("hello names the wrong ends"));
        }
        if hello.ml_kem.len() != ML_KEM_768_EK_LEN {
            return Err(bad("hello carries a malformed ML-KEM key"));
        }
        let (ct, kem) = crate::kem::encapsulate(&hello.ml_kem)
            .map_err(|e| bad(&format!("ML-KEM encapsulation: {e}")))?;
        let kem = Zeroizing::new(kem);
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let share = x25519_dalek::PublicKey::from(&secret).to_bytes();
        let dh = secret.diffie_hellman(&x25519_dalek::PublicKey::from(hello.x25519));
        if !dh.was_contributory() {
            return Err(bad("X25519 share is a low-order point"));
        }
        let challenge = Challenge {
            x25519: share,
            ml_kem_ciphertext: ct,
            nonce: random32(),
        };
        let t = transcript(hello, &challenge);
        let keys = derive_keys(dh.as_bytes(), &kem, &t);
        Ok((
            Self {
                hello: hello.clone(),
                transcript: t,
                keys,
                committee,
            },
            challenge,
        ))
    }

    /// Checks the initiator's proof, under the session key its
    /// `announcement` certifies; only then signs the transcript with this
    /// validator's session key and opens the channel.
    pub fn on_proof(
        self,
        ctx: &ChannelContext<'_>,
        proof: &TranscriptSignature,
        announcement: &EndpointAnnouncement,
        signer: &dyn ValidatorSigner,
    ) -> Result<(Channel, TranscriptSignature)> {
        let key = session_key_of(
            &self.committee,
            ctx.chain_id,
            ctx.genesis_hash,
            self.hello.initiator,
            announcement,
        )?;
        if !key.verify(
            CHANNEL_DOMAIN,
            &signed_message(&self.transcript, b"initiator"),
            &proof.signature,
        ) {
            return Err(bad("initiator's transcript signature does not verify"));
        }
        let signature = signer.sign(
            CHANNEL_DOMAIN,
            &signed_message(&self.transcript, b"responder"),
        )?;
        let (i2r, r2i) = self.keys;
        Ok((
            Channel {
                peer: self.hello.initiator,
                epoch: self.hello.epoch,
                send_key: r2i,
                recv_key: i2r,
                send_seq: 0,
                recv_seq: 0,
                send_label: 1,
                recv_label: 0,
            },
            TranscriptSignature { signature },
        ))
    }
}

fn mac(key: &[u8; 32], label: u8, seq: u64, payload: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(&[label]);
    h.update(&seq.to_be_bytes());
    h.update(&(payload.len() as u64).to_be_bytes());
    h.update(payload);
    h.finalize().into()
}

/// The sending half of a channel.
pub struct Sealer {
    key: Zeroizing<[u8; 32]>,
    seq: u64,
    label: u8,
}

/// The receiving half of a channel.
pub struct Opener {
    key: Zeroizing<[u8; 32]>,
    seq: u64,
    label: u8,
}

impl Sealer {
    /// Authenticates `payload` as the next frame to send.
    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        seal_with(&self.key, self.label, &mut self.seq, payload)
    }
}

impl Opener {
    /// Checks the next received frame and returns its payload.
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        open_with(&self.key, self.label, &mut self.seq, frame)
    }
}

fn seal_with(key: &[u8; 32], label: u8, seq: &mut u64, payload: &[u8]) -> Result<Vec<u8>> {
    if *seq >= MAX_FRAMES_PER_KEY {
        return Err(bad("channel key exhausted; re-key"));
    }
    let s = *seq;
    *seq += 1;
    let tag = mac(key, label, s, payload);
    let mut out = Vec::with_capacity(8 + payload.len() + 32);
    out.extend_from_slice(&s.to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn open_with(key: &[u8; 32], label: u8, seq: &mut u64, frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() < 40 {
        return Err(bad("frame too short"));
    }
    if *seq >= MAX_FRAMES_PER_KEY {
        return Err(bad("channel key exhausted; re-key"));
    }
    let got = u64::from_be_bytes(frame[..8].try_into().expect("8 bytes"));
    let (payload, tag) = frame[8..].split_at(frame.len() - 40);
    let expected = blake3::Hash::from(mac(key, label, *seq, payload));
    let tag: [u8; 32] = tag.try_into().expect("32 bytes");
    // `blake3::Hash` equality is constant-time.
    if got != *seq || expected != blake3::Hash::from(tag) {
        return Err(bad("frame fails authentication"));
    }
    *seq += 1;
    Ok(payload.to_vec())
}

impl Channel {
    /// The validator at the other end.
    pub fn peer(&self) -> ValidatorIndex {
        self.peer
    }

    /// Splits the channel into halves a writer and a reader task can own.
    pub fn split(self) -> (Sealer, Opener) {
        (
            Sealer {
                key: self.send_key,
                seq: self.send_seq,
                label: self.send_label,
            },
            Opener {
                key: self.recv_key,
                seq: self.recv_seq,
                label: self.recv_label,
            },
        )
    }

    /// The epoch the channel is bound to.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::test_support::committee;
    use crate::session::SessionKey;
    use crate::validator_key::test_signer::SoftwareTestSigner;

    /// One validator's boot: its session key and the announcement its
    /// hardware key signed for it.
    struct Boot {
        session: SessionKey,
        announcement: EndpointAnnouncement,
    }

    fn boots(signers: &[SoftwareTestSigner]) -> Vec<Boot> {
        signers
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let session = SessionKey::generate().unwrap();
                let announcement = EndpointAnnouncement::sign(
                    s,
                    1,
                    [9; 32],
                    &crate::announce::EndpointOpening::new(
                        [i as u8; 32],
                        format!("did:tenzro:machine:{i}"),
                    )
                    .unwrap(),
                    session.public_key().clone(),
                    crate::announce::DisclosureSecret::generate()
                        .public()
                        .clone(),
                    1_000,
                    3_600_000,
                )
                .unwrap();
                Boot {
                    session,
                    announcement,
                }
            })
            .collect()
    }

    fn handshake(c: &Committee, b: &[Boot]) -> (Channel, Channel) {
        let ctx = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: c,
        };
        let (i, hello) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let (r, challenge) = Responder::on_hello(&ctx, 1, &hello).unwrap();
        let (i, proof) = i.on_challenge(&challenge, &b[0].session).unwrap();
        let (rc, accept) = r
            .on_proof(&ctx, &proof, &b[0].announcement, &b[1].session)
            .unwrap();
        let ic = i.on_accept(&ctx, &accept, &b[1].announcement).unwrap();
        (ic, rc)
    }

    #[test]
    fn both_ends_agree_and_frames_flow_both_ways() {
        let (c, s) = committee(4);
        let (i, r) = handshake(&c, &boots(&s));
        assert_eq!((i.peer(), r.peer()), (1, 0));
        assert_eq!((i.epoch(), r.epoch()), (0, 0));
        let ((mut is, mut io), (mut rs, mut ro)) = (i.split(), r.split());
        let f = is.seal(b"vertex").unwrap();
        assert_eq!(ro.open(&f).unwrap(), b"vertex");
        let g = rs.seal(b"echo").unwrap();
        assert_eq!(io.open(&g).unwrap(), b"echo");
    }

    #[test]
    fn a_tampered_replayed_or_reflected_frame_is_refused() {
        let (c, s) = committee(4);
        let (i, r) = handshake(&c, &boots(&s));
        let ((mut is, _), (mut rs, mut ro)) = (i.split(), r.split());
        let f1 = is.seal(b"one").unwrap();
        let f2 = is.seal(b"two").unwrap();
        let mut bad = f1.clone();
        bad[9] ^= 1;
        assert!(ro.open(&bad).is_err(), "tampered");
        assert!(ro.open(&f2).is_err(), "out of order");
        assert_eq!(ro.open(&f1).unwrap(), b"one");
        assert!(ro.open(&f1).is_err(), "replayed");
        let back = rs.seal(b"x").unwrap();
        assert!(ro.open(&back).is_err(), "reflected to its sender");
    }

    #[test]
    fn a_bulk_handshake_completes_exactly_like_a_control_one() {
        // `kind` is bookkeeping only: a Bulk hello authenticates and derives
        // keys the same way a Control one does.
        let (c, s) = committee(4);
        let b = boots(&s);
        let ctx = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c,
        };
        let (i, hello) = Initiator::start(&ctx, 0, 1, StreamKind::Bulk).unwrap();
        assert_eq!(hello.kind, StreamKind::Bulk);
        let (r, challenge) = Responder::on_hello(&ctx, 1, &hello).unwrap();
        let (i, proof) = i.on_challenge(&challenge, &b[0].session).unwrap();
        let (rc, accept) = r
            .on_proof(&ctx, &proof, &b[0].announcement, &b[1].session)
            .unwrap();
        let ic = i.on_accept(&ctx, &accept, &b[1].announcement).unwrap();
        let ((mut is, _), (_, mut ro)) = (ic.split(), rc.split());
        assert_eq!(
            ro.open(&is.seal(b"bulk frame").unwrap()).unwrap(),
            b"bulk frame"
        );
    }

    #[test]
    fn an_impostor_cannot_complete_either_side() {
        let (c, s) = committee(4);
        let b = boots(&s);
        let ctx = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c,
        };
        // Validator 2 claims to be validator 0.
        let (i, hello) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let (r, ch) = Responder::on_hello(&ctx, 1, &hello).unwrap();
        let (_, proof) = i.on_challenge(&ch, &b[2].session).unwrap();
        assert!(
            r.on_proof(&ctx, &proof, &b[0].announcement, &b[1].session)
                .is_err()
        );
        // ... and presents its own announcement as validator 0's.
        let (i, hello) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let (r, ch) = Responder::on_hello(&ctx, 1, &hello).unwrap();
        let (_, proof) = i.on_challenge(&ch, &b[2].session).unwrap();
        assert!(
            r.on_proof(&ctx, &proof, &b[2].announcement, &b[1].session)
                .is_err()
        );
        // Validator 3 answers in place of validator 1.
        let (i, hello) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let (r, ch) = Responder::on_hello(&ctx, 1, &hello).unwrap();
        let (i, proof) = i.on_challenge(&ch, &b[0].session).unwrap();
        let (_, accept) = r
            .on_proof(&ctx, &proof, &b[0].announcement, &b[3].session)
            .unwrap();
        assert!(i.on_accept(&ctx, &accept, &b[1].announcement).is_err());
    }

    #[test]
    fn a_session_key_no_announcement_certifies_is_refused() {
        let (c, s) = committee(4);
        let b = boots(&s);
        let ctx = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c,
        };
        // Validator 0 signs with a key its hardware never certified, and
        // pairs it with an announcement naming that key but signed by
        // nobody's registered key.
        let rogue = SessionKey::generate().unwrap();
        let mut forged = b[0].announcement.clone();
        forged.session_key = rogue.public_key().clone();
        let (i, hello) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let (r, ch) = Responder::on_hello(&ctx, 1, &hello).unwrap();
        let (_, proof) = i.on_challenge(&ch, &rogue).unwrap();
        assert!(r.on_proof(&ctx, &proof, &forged, &b[1].session).is_err());
        // The hardware key itself, signing directly, is not the session key.
        let (i, hello) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let (r, ch) = Responder::on_hello(&ctx, 1, &hello).unwrap();
        let (_, proof) = i.on_challenge(&ch, &s[0]).unwrap();
        assert!(
            r.on_proof(&ctx, &proof, &b[0].announcement, &b[1].session)
                .is_err()
        );
    }

    #[test]
    fn a_proof_from_another_handshake_is_refused() {
        let (c, s) = committee(4);
        let b = boots(&s);
        let ctx = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c,
        };
        let (i1, h1) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let (_, ch1) = Responder::on_hello(&ctx, 1, &h1).unwrap();
        let (_, proof1) = i1.on_challenge(&ch1, &b[0].session).unwrap();
        let (_, h2) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let (r2, _) = Responder::on_hello(&ctx, 1, &h2).unwrap();
        assert!(
            r2.on_proof(&ctx, &proof1, &b[0].announcement, &b[1].session)
                .is_err()
        );
    }

    /// Seed 3054677367's netem window kept failing here long after the
    /// loss that caused it had cleared (TENZRO-INFLIGHT.md, 2026-10-21): a
    /// validator a stall isolates falls further behind the healthy
    /// majority for as long as the isolation lasts, not just one epoch's
    /// worth (measured directly in a netem-only replay: a 2-epoch gap
    /// between validators exchanging a hello), and every reconnect was
    /// refused because its hello correctly named the epoch the initiator
    /// was actually on. The responder must accept that and hand the
    /// channel over to it, not wait for both sides to agree on the epoch
    /// before they can talk at all.
    #[test]
    fn a_hello_for_a_later_epoch_is_accepted_and_the_channel_is_bound_to_it() {
        let (c, s) = committee(4);
        let b = boots(&s);
        let ctx_behind = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c,
        };
        let mut c_ahead = c.clone();
        c_ahead.epoch = c.epoch + 3;
        let ctx_ahead = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c_ahead,
        };
        let (i, hello) = Initiator::start(&ctx_ahead, 0, 1, StreamKind::Control).unwrap();
        assert_eq!(hello.epoch, c.epoch + 3);
        let (r, challenge) = Responder::on_hello(&ctx_behind, 1, &hello).unwrap();
        let (i, proof) = i.on_challenge(&challenge, &b[0].session).unwrap();
        let (rc, accept) = r
            .on_proof(&ctx_behind, &proof, &b[0].announcement, &b[1].session)
            .unwrap();
        let ic = i
            .on_accept(&ctx_ahead, &accept, &b[1].announcement)
            .unwrap();
        assert_eq!(rc.epoch(), c.epoch + 3);
        assert_eq!(ic.epoch(), c.epoch + 3);
    }

    /// The mirror image of the other direction, and just as real: in a
    /// mesh where every pair of validators dials each other, whichever one
    /// a stall isolates can be on either side of a given dial, so an
    /// initiator can just as well be the one left behind while the
    /// responder has already moved on.
    #[test]
    fn a_hello_for_an_earlier_epoch_is_also_accepted_and_the_channel_is_bound_to_it() {
        let (c, s) = committee(4);
        let b = boots(&s);
        let ctx_behind = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c,
        };
        let mut c_ahead = c.clone();
        c_ahead.epoch = c.epoch + 3;
        let ctx_ahead = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c_ahead,
        };
        let (i, hello) = Initiator::start(&ctx_behind, 0, 1, StreamKind::Control).unwrap();
        assert_eq!(hello.epoch, c.epoch);
        let (r, challenge) = Responder::on_hello(&ctx_ahead, 1, &hello).unwrap();
        let (i, proof) = i.on_challenge(&challenge, &b[0].session).unwrap();
        let (rc, accept) = r
            .on_proof(&ctx_ahead, &proof, &b[0].announcement, &b[1].session)
            .unwrap();
        let ic = i
            .on_accept(&ctx_behind, &accept, &b[1].announcement)
            .unwrap();
        assert_eq!(rc.epoch(), c.epoch);
        assert_eq!(ic.epoch(), c.epoch);
    }

    #[test]
    fn a_hello_for_another_chain_or_responder_is_refused() {
        let (c, _) = committee(4);
        let ctx = ChannelContext {
            chain_id: 1,
            genesis_hash: &[9; 32],
            committee: &c,
        };
        let (_, hello) = Initiator::start(&ctx, 0, 1, StreamKind::Control).unwrap();
        let mut h = hello.clone();
        h.chain_id = 2;
        assert!(Responder::on_hello(&ctx, 1, &h).is_err());
        assert!(Responder::on_hello(&ctx, 2, &hello).is_err());
        let mut h = hello;
        h.initiator = 40;
        assert!(Responder::on_hello(&ctx, 1, &h).is_err());
    }
}
