//! Sui: the bridge module's events, proven from checkpoints the validator
//! committee certified.
//!
//! **Messages.** A delivery's body is one Sui event in BCS (package id,
//! module, sender, struct type, contents). It must be
//! `<ramp>::bridge::TransferOut` emitted by the package at the route's
//! `ramp`, and its contents the transfer record of [`super::move_event`].
//! Outbound transfers are that record in BCS, which the bridge module
//! executes. A certified checkpoint is final, so the finality depth is 0.
//!
//! **Light client.** It starts from the route's anchor, the digest of an
//! end-of-epoch checkpoint summary, and takes the next epoch's committee
//! (BLS12-381 keys and stake) from that summary. Each later end-of-epoch
//! summary that the current committee certified hands over to the next
//! committee. A certificate counts when signers holding more than two
//! thirds of the epoch's stake signed the summary: an aggregate min-sig
//! BLS signature over the BCS intent message (scope `CheckpointSummary`)
//! followed by the epoch.
//!
//! A message proof is a certified summary, its checkpoint contents (whose
//! Blake2b-256 is the summary's content digest), the position of the
//! transaction in them, the transaction's effects (whose digest the
//! contents list, recording success and the events digest) and its events
//! (whose digest the effects name), and the event's position. The event at
//! that position must be exactly the delivered body.
//!
//! Encodings (big-endian lengths and counts):
//!
//! ```text
//! update      = 0x00 summary:bytes                  (bootstrap)
//!             | 0x01 summary:bytes certificate       (committee handover)
//! certificate = epoch:u64 signature:48 count:u16 { signer_index:u16 }
//! proof       = summary:bytes certificate contents:bytes tx_index:u32
//!               effects:bytes events:bytes event_index:u32
//! ```
//!
//! `bytes` is a u32 length and the BCS bytes; signer indexes ascend.

use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use blst::BLST_ERROR;
use blst::min_sig::{PublicKey, Signature};

use super::attestation::{MAX_PROOF_LEN, body_hash};
use super::canonical::{Reader, Writer};
use super::light_client::{LightClientHead, LightClientVerifier};
use super::move_event::{MoveTransfer, StructTag, read_identifier};
use super::state::RouteState;
use super::{
    BridgeRoute, BridgeRouteAdapter, ChainFamily, LightClientAnchor, LightClientKind, RouteAdapter,
    RouteMessage,
};
use crate::error::{BridgeError, Result};

/// Domain separation tag of Sui's min-sig BLS signatures.
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Intent scope of a checkpoint summary.
const INTENT_CHECKPOINT_SUMMARY: u8 = 2;

/// Largest committee accepted.
pub const MAX_COMMITTEE: usize = 1024;

const PUBKEY_LEN: usize = 96;
const MAX_ITEMS: usize = 1 << 20;
const MAX_EVENT_CONTENTS: usize = 64 * 1024;

fn refuse(what: impl Into<String>) -> BridgeError {
    BridgeError::TransferFailed(format!("sui light client: {}", what.into()))
}

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("sui event: {}", what.into()))
}

/// Sui's digest of a value of type `name` from its BCS: Blake2b-256 of the
/// type's name, `::`, and the BCS.
pub fn digest(name: &str, b: &[u8]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(name.as_bytes());
    h.update(b"::");
    h.update(b);
    h.finalize().into()
}

fn read_digest(r: &mut Reader<'_>) -> Result<[u8; 32]> {
    if r.uleb128(32)? != 32 {
        return Err(refuse("a digest is 32 bytes"));
    }
    r.array()
}

fn read_option<T>(
    r: &mut Reader<'_>,
    f: impl FnOnce(&mut Reader<'_>) -> Result<T>,
) -> Result<Option<T>> {
    match r.u8()? {
        0 => Ok(None),
        1 => f(r).map(Some),
        _ => Err(refuse("an option tag other than 0 or 1")),
    }
}

/// A Sui event. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuiEvent {
    pub package_id: [u8; 32],
    pub module: String,
    pub sender: [u8; 32],
    pub type_: StructTag,
    pub contents: Vec<u8>,
}

impl SuiEvent {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            package_id: r.array()?,
            module: read_identifier(r)?,
            sender: r.array()?,
            type_: StructTag::read(r, 0)?,
            contents: r.bcs_bytes(MAX_EVENT_CONTENTS)?.to_vec(),
        })
    }

    /// BCS encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.package_id)
            .bcs_bytes(self.module.as_bytes())
            .raw(&self.sender);
        self.type_.write(&mut w);
        w.bcs_bytes(&self.contents);
        w.into_bytes()
    }
}

/// The Sui adapter. See the module docs.
pub struct SuiAdapter;

impl RouteAdapter for SuiAdapter {
    fn transport(&self) -> BridgeRouteAdapter {
        BridgeRouteAdapter::Contract
    }

    fn family(&self) -> ChainFamily {
        ChainFamily::Sui
    }

    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        let e = SuiEvent::read(r)?;
        if e.package_id != route.ramp || !e.type_.is_transfer_out(&route.ramp) {
            return Err(bad("not a TransferOut event of the route's bridge package"));
        }
        let t = MoveTransfer::decode(&e.contents)?;
        Ok(t.inbound(ChainFamily::Sui, &e.contents))
    }

    fn encode_outbound(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<Vec<u8>> {
        Ok(MoveTransfer::outbound(route, msg)?.encode())
    }

    fn decode_outbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        MoveTransfer::read(r)?.read_back(route)
    }

    fn outbound_message_id(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<[u8; 32]> {
        MoveTransfer::outbound(route, msg)
            .and_then(|t| t.read_back(route))
            .map(|m| m.message_id)
    }

    fn finality_depth(&self, _route: &BridgeRoute) -> Result<u64> {
        Ok(0)
    }
}

// ---- checkpoints ----

/// The fields of a checkpoint summary the client uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub epoch: u64,
    pub sequence_number: u64,
    pub content_digest: [u8; 32],
    /// The next epoch's committee, on an end-of-epoch summary.
    pub next_committee: Option<Vec<([u8; PUBKEY_LEN], u64)>>,
}

fn read_commitments(r: &mut Reader<'_>) -> Result<()> {
    for _ in 0..r.uleb128(64)? {
        // Live object set or checkpoint artifacts: each is one digest.
        r.uleb128(1)?;
        read_digest(r)?;
    }
    Ok(())
}

impl Summary {
    /// Parse a complete BCS checkpoint summary.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let epoch = r.u64_le()?;
        let sequence_number = r.u64_le()?;
        let _network_total_transactions = r.u64_le()?;
        let content_digest = read_digest(&mut r)?;
        read_option(&mut r, read_digest)?;
        for _ in 0..4 {
            r.u64_le()?;
        }
        let _timestamp_ms = r.u64_le()?;
        read_commitments(&mut r)?;
        let next_committee = read_option(&mut r, |r| {
            let n = r.uleb128(MAX_COMMITTEE)?;
            let mut committee = Vec::with_capacity(n);
            for _ in 0..n {
                if r.uleb128(PUBKEY_LEN)? != PUBKEY_LEN {
                    return Err(refuse("a committee key is 96 bytes"));
                }
                committee.push((r.array()?, r.u64_le()?));
            }
            let _protocol_version = r.u64_le()?;
            read_commitments(r)?;
            Ok(committee)
        })?;
        r.bcs_bytes(MAX_ITEMS)?;
        r.finish()?;
        Ok(Self {
            epoch,
            sequence_number,
            content_digest,
            next_committee,
        })
    }
}

/// A committee certificate over a summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub epoch: u64,
    pub signature: [u8; 48],
    pub signers: Vec<u16>,
}

impl Certificate {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let epoch = r.u64_be()?;
        let signature = r.array()?;
        let n = r.u16_be()? as usize;
        if n > MAX_COMMITTEE {
            return Err(refuse("too many signers"));
        }
        let mut signers = Vec::with_capacity(n);
        for _ in 0..n {
            signers.push(r.u16_be()?);
        }
        if signers.windows(2).any(|w| w[0] >= w[1]) {
            return Err(refuse("signer indexes must ascend"));
        }
        Ok(Self {
            epoch,
            signature,
            signers,
        })
    }

    /// The fixed-layout encoding.
    pub fn write(&self, w: &mut Writer) {
        w.u64_be(self.epoch)
            .raw(&self.signature)
            .u16_be(self.signers.len() as u16);
        for s in &self.signers {
            w.u16_be(*s);
        }
    }

    /// Require more than two thirds of `committee`'s stake to have signed
    /// `summary_bcs`.
    fn verify(
        &self,
        committee: &[([u8; PUBKEY_LEN], u64)],
        summary: &Summary,
        summary_bcs: &[u8],
    ) -> Result<()> {
        if self.epoch != summary.epoch {
            return Err(refuse("the certificate is for another epoch"));
        }
        let total: u128 = committee.iter().map(|(_, s)| u128::from(*s)).sum();
        let mut signed = 0u128;
        let mut keys = Vec::with_capacity(self.signers.len());
        for i in &self.signers {
            let (pk, stake) = committee
                .get(*i as usize)
                .ok_or_else(|| refuse("a signer outside the committee"))?;
            keys.push(
                PublicKey::from_bytes(pk).map_err(|_| refuse("a committee key does not decode"))?,
            );
            signed += u128::from(*stake);
        }
        if signed * 3 <= total * 2 {
            return Err(refuse("signers hold two thirds of the stake or less"));
        }
        let mut msg = vec![INTENT_CHECKPOINT_SUMMARY, 0, 0];
        msg.extend_from_slice(summary_bcs);
        msg.extend_from_slice(&self.epoch.to_le_bytes());
        let sig = Signature::sig_validate(&self.signature, true)
            .map_err(|_| refuse("the aggregate signature does not decode"))?;
        let refs: Vec<&PublicKey> = keys.iter().collect();
        match sig.fast_aggregate_verify(true, &msg, BLS_DST, &refs) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(refuse("the committee's signature does not verify")),
        }
    }
}

/// Parse checkpoint contents (V2: each transaction's execution digests
/// with its user signatures, each with an optional version) and return the
/// execution digests.
fn contents_digests(b: &[u8]) -> Result<Vec<([u8; 32], [u8; 32])>> {
    let mut r = Reader::new(b);
    if r.uleb128(1)? != 1 {
        return Err(refuse("unknown checkpoint contents version"));
    }
    let n = r.uleb128(MAX_ITEMS)?;
    let mut digests = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        digests.push((read_digest(&mut r)?, read_digest(&mut r)?));
        for _ in 0..r.uleb128(64)? {
            r.bcs_bytes(4096)?;
            read_option(&mut r, |r| r.u64_le())?;
        }
    }
    r.finish()?;
    Ok(digests)
}

/// From a transaction's effects (V2): it succeeded, its digest and its
/// events digest. The rest of the effects is bound by their digest.
fn effects_prefix(b: &[u8]) -> Result<([u8; 32], Option<[u8; 32]>)> {
    let mut r = Reader::new(b);
    if r.uleb128(1)? != 1 {
        return Err(refuse("unknown effects version"));
    }
    if r.uleb128(1)? != 0 {
        return Err(refuse("the transaction did not succeed"));
    }
    let _executed_epoch = r.u64_le()?;
    for _ in 0..4 {
        r.u64_le()?;
    }
    let tx = read_digest(&mut r)?;
    read_option(&mut r, |r| r.u32_le())?;
    let events = read_option(&mut r, read_digest)?;
    Ok((tx, events))
}

/// The byte span of event `index` in BCS transaction events.
fn event_span(b: &[u8], index: usize) -> Result<(usize, usize)> {
    let mut r = Reader::new(b);
    let n = r.uleb128(MAX_ITEMS)?;
    let mut span = None;
    for i in 0..n {
        let start = r.position();
        SuiEvent::read(&mut r)?;
        if i == index {
            span = Some((start, r.position()));
        }
    }
    r.finish()?;
    span.ok_or_else(|| refuse("no event at that position"))
}

// ---- the client ----

fn prefix(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    anchor.store_key(route)
}

fn committee_key(route: &BridgeRoute, anchor: &LightClientAnchor, epoch: u64) -> String {
    format!("{}:committee:{epoch:020}", prefix(route, anchor))
}

fn head_key(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    prefix(route, anchor)
}

fn encode_committee(c: &[([u8; PUBKEY_LEN], u64)]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16_be(c.len() as u16);
    for (pk, stake) in c {
        w.raw(pk).u64_be(*stake);
    }
    w.into_bytes()
}

fn committee(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    epoch: u64,
) -> Result<Vec<([u8; PUBKEY_LEN], u64)>> {
    let b = state
        .get(&committee_key(route, anchor, epoch))
        .ok_or_else(|| refuse(format!("the committee of epoch {epoch} is not known")))?;
    let mut r = Reader::new(&b);
    let n = r.u16_be()? as usize;
    let mut c = Vec::with_capacity(n);
    for _ in 0..n {
        c.push((r.array()?, r.u64_be()?));
    }
    r.finish()?;
    Ok(c)
}

/// (current epoch, highest end-of-epoch checkpoint followed).
fn head(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
) -> Option<(u64, u64)> {
    let b = state.get(&head_key(route, anchor))?;
    let mut r = Reader::new(&b);
    let h = (r.u64_be().ok()?, r.u64_be().ok()?);
    r.finish().ok()?;
    Some(h)
}

fn trusted_digest(anchor: &LightClientAnchor) -> Result<[u8; 32]> {
    match anchor {
        LightClientAnchor::SuiCommittee {
            trusted_checkpoint_digest,
        } => Ok(*trusted_checkpoint_digest),
        _ => Err(refuse("the route's anchor is not a Sui anchor")),
    }
}

/// The BCS bytes of the event `proof` shows in a checkpoint certified by the
/// light client's committee: the summary and its certificate, the contents,
/// the transaction's effects and events, and the event's position.
fn proven_event(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    proof: &[u8],
) -> Result<Vec<u8>> {
    trusted_digest(anchor)?;
    let mut r = Reader::new(proof);
    let summary_bcs = r.be_bytes(MAX_PROOF_LEN)?;
    let cert = Certificate::read(&mut r)?;
    let contents = r.be_bytes(MAX_PROOF_LEN)?;
    let tx_index = r.u32_be()? as usize;
    let effects = r.be_bytes(MAX_PROOF_LEN)?;
    let events = r.be_bytes(MAX_PROOF_LEN)?;
    let event_index = r.u32_be()? as usize;
    r.finish()?;

    let summary = Summary::decode(summary_bcs)?;
    // Only the committee the client follows, and the one before it for
    // checkpoints up to its epoch's last, prove anything: a committee long
    // retired has nothing at stake and could certify any checkpoint.
    let (epoch, ended_at) =
        head(state, route, anchor).ok_or_else(|| refuse("the light client is not bootstrapped"))?;
    let current = summary.epoch == epoch;
    let just_ended =
        summary.epoch.checked_add(1) == Some(epoch) && summary.sequence_number <= ended_at;
    if !current && !just_ended {
        return Err(refuse(format!(
            "checkpoint {} of epoch {}; the client proves epoch {epoch} and epoch {} through checkpoint {ended_at}",
            summary.sequence_number,
            summary.epoch,
            epoch.saturating_sub(1)
        )));
    }
    cert.verify(
        &committee(state, route, anchor, summary.epoch)?,
        &summary,
        summary_bcs,
    )?;
    if digest("CheckpointContents", contents) != summary.content_digest {
        return Err(refuse("the contents are not the checkpoint's"));
    }
    let (tx, fx) = *contents_digests(contents)?
        .get(tx_index)
        .ok_or_else(|| refuse("no transaction at that position"))?;
    if digest("TransactionEffects", effects) != fx {
        return Err(refuse("the effects are not the transaction's"));
    }
    let (effects_tx, events_digest) = effects_prefix(effects)?;
    if effects_tx != tx || events_digest != Some(digest("TransactionEvents", events)) {
        return Err(refuse("the events are not the transaction's"));
    }
    let (start, end) = event_span(events, event_index)?;
    Ok(events[start..end].to_vec())
}

/// The Sui light client. Its state lives in route state.
#[derive(Debug, Default)]
pub struct SuiLightClient;

impl LightClientVerifier for SuiLightClient {
    fn kind(&self) -> LightClientKind {
        LightClientKind::SuiCommittee
    }

    fn proven_lock_record(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        lock: &[u8; 32],
        proof: &[u8],
    ) -> Result<super::receipt_proof::LockRecord> {
        let event = SuiEvent::read(&mut Reader::new(&proven_event(
            state, route, anchor, proof,
        )?))?;
        let t = &event.type_;
        if t.address != *lock || t.module != "settlement_lock" || t.type_args != 0 {
            return Err(refuse("the event is not the route's settlement lock's"));
        }
        super::receipt_proof::move_lock_record(&t.name, &event.contents)
    }

    fn verify(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        body: &[u8; 32],
        proof: &[u8],
    ) -> Result<()> {
        if body_hash(&proven_event(state, route, anchor, proof)?) != *body {
            return Err(refuse(
                "the event at that position is not the delivered one",
            ));
        }
        Ok(())
    }

    fn advance(
        &self,
        state: &mut dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        update: &[u8],
    ) -> Result<LightClientHead> {
        let trusted = trusted_digest(anchor)?;
        let mut r = Reader::new(update);
        let tag = r.u8()?;
        let summary_bcs = r.be_bytes(MAX_PROOF_LEN)?;
        let summary = Summary::decode(summary_bcs)?;
        let current = head(state, route, anchor);
        match (tag, current) {
            (0, None) => {
                r.finish()?;
                if digest("CheckpointSummary", summary_bcs) != trusted {
                    return Err(refuse("the bootstrap summary is not the anchor's"));
                }
            }
            (1, Some((epoch, _))) => {
                let cert = Certificate::read(&mut r)?;
                r.finish()?;
                if summary.epoch != epoch {
                    return Err(refuse(format!(
                        "a handover from epoch {}; the client follows epoch {epoch}",
                        summary.epoch
                    )));
                }
                cert.verify(
                    &committee(state, route, anchor, epoch)?,
                    &summary,
                    summary_bcs,
                )?;
            }
            (0, Some(_)) => return Err(refuse("already bootstrapped")),
            (1, None) => return Err(refuse("not bootstrapped from the anchor")),
            (t, _) => return Err(refuse(format!("unknown update tag {t}"))),
        }
        let next = summary
            .next_committee
            .as_ref()
            .ok_or_else(|| refuse("not an end-of-epoch summary"))?;
        if next.is_empty()
            || next
                .iter()
                .any(|(pk, stake)| *stake == 0 || PublicKey::key_validate(pk).is_err())
        {
            return Err(refuse("the next committee is empty or has an invalid key"));
        }
        let epoch = summary
            .epoch
            .checked_add(1)
            .ok_or_else(|| refuse("an epoch past the last"))?;
        state.apply(vec![
            (committee_key(route, anchor, epoch), encode_committee(next)),
            (
                head_key(route, anchor),
                [epoch.to_be_bytes(), summary.sequence_number.to_be_bytes()].concat(),
            ),
        ])?;
        Ok(LightClientHead {
            kind: "sui_committee",
            finalized: summary.sequence_number,
            period: epoch,
            next_known: false,
        })
    }

    fn head(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
    ) -> Option<LightClientHead> {
        head(state, route, anchor).map(|(epoch, seq)| LightClientHead {
            kind: "sui_committee",
            finalized: seq,
            period: epoch,
            next_known: false,
        })
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! A BLS committee that certifies synthetic checkpoints, for route
    //! tests.

    use blst::min_sig::{AggregateSignature, SecretKey};

    use super::*;

    pub struct Committee {
        pub keys: Vec<SecretKey>,
    }

    impl Committee {
        pub fn new(seed: u8, n: usize) -> Self {
            Self {
                keys: (0..n)
                    .map(|i| SecretKey::key_gen(&[seed.wrapping_add(i as u8); 32], &[]).unwrap())
                    .collect(),
            }
        }

        pub fn members(&self) -> Vec<([u8; PUBKEY_LEN], u64)> {
            self.keys
                .iter()
                .map(|k| (k.sk_to_pk().compress(), 2_500))
                .collect()
        }

        pub fn certify(&self, epoch: u64, summary_bcs: &[u8], signers: &[u16]) -> Certificate {
            let mut msg = vec![INTENT_CHECKPOINT_SUMMARY, 0, 0];
            msg.extend_from_slice(summary_bcs);
            msg.extend_from_slice(&epoch.to_le_bytes());
            let sigs: Vec<_> = signers
                .iter()
                .map(|i| self.keys[*i as usize].sign(&msg, BLS_DST, &[]))
                .collect();
            let refs: Vec<_> = sigs.iter().collect();
            Certificate {
                epoch,
                signature: AggregateSignature::aggregate(&refs, true)
                    .unwrap()
                    .to_signature()
                    .compress(),
                signers: signers.to_vec(),
            }
        }
    }

    fn digest_bcs(w: &mut Writer, d: &[u8; 32]) {
        w.uleb128(32).raw(d);
    }

    /// A checkpoint summary in BCS.
    pub fn summary(
        epoch: u64,
        seq: u64,
        content_digest: [u8; 32],
        next: Option<&Committee>,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_le(epoch).u64_le(seq).u64_le(1_000);
        digest_bcs(&mut w, &content_digest);
        w.u8(1);
        digest_bcs(&mut w, &[0x0c; 32]);
        for v in [1u64, 2, 3, 4] {
            w.u64_le(v);
        }
        w.u64_le(1_800_000_000_000).uleb128(0);
        match next {
            Some(c) => {
                w.u8(1).uleb128(c.keys.len());
                for (pk, stake) in c.members() {
                    w.uleb128(PUBKEY_LEN).raw(&pk).u64_le(stake);
                }
                w.u64_le(70).uleb128(1).uleb128(0);
                digest_bcs(&mut w, &[0x0e; 32]);
            }
            None => {
                w.u8(0);
            }
        }
        w.uleb128(0);
        w.into_bytes()
    }

    pub fn bootstrap(summary_bcs: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(0).be_bytes(summary_bcs);
        w.into_bytes()
    }

    pub fn handover(summary_bcs: &[u8], cert: &Certificate) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).be_bytes(summary_bcs);
        cert.write(&mut w);
        w.into_bytes()
    }

    /// Transaction events holding `events`, effects naming them, and
    /// contents listing the transaction at position 1.
    pub fn transaction(events: &[SuiEvent]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut w = Writer::new();
        w.uleb128(events.len());
        for e in events {
            w.raw(&e.encode());
        }
        let events_bcs = w.into_bytes();
        let tx = [0x7a; 32];
        let mut w = Writer::new();
        w.uleb128(1).uleb128(0).u64_le(9);
        for v in [5u64, 6, 7, 8] {
            w.u64_le(v);
        }
        digest_bcs(&mut w, &tx);
        w.u8(1).u32_le(0).u8(1);
        digest_bcs(&mut w, &digest("TransactionEvents", &events_bcs));
        w.raw(&[0xee; 40]);
        let effects = w.into_bytes();
        let mut w = Writer::new();
        w.uleb128(1).uleb128(2);
        digest_bcs(&mut w, &[0x01; 32]);
        digest_bcs(&mut w, &[0x02; 32]);
        w.uleb128(1).bcs_bytes(&[0x55; 97]).u8(0);
        digest_bcs(&mut w, &tx);
        digest_bcs(&mut w, &digest("TransactionEffects", &effects));
        w.uleb128(1).bcs_bytes(&[0x55; 97]).u8(0);
        (events_bcs, effects, w.into_bytes())
    }

    pub fn proof(
        summary_bcs: &[u8],
        cert: &Certificate,
        contents: &[u8],
        tx_index: u32,
        effects: &[u8],
        events: &[u8],
        event_index: u32,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.be_bytes(summary_bcs);
        cert.write(&mut w);
        w.be_bytes(contents)
            .u32_be(tx_index)
            .be_bytes(effects)
            .be_bytes(events)
            .u32_be(event_index);
        w.into_bytes()
    }
}

#[cfg(test)]
mod mainnet_tests {
    use base64::Engine as _;
    use serde_json::Value;

    use super::super::test_support::MemState;
    use super::super::{BridgeRouteAdapter, ChainFamily, MintRateLimit, VerifierQuorum};
    use super::*;

    /// Recorded from Sui mainnet through its GraphQL service: two consecutive
    /// end-of-epoch checkpoint summaries with their certificates, and a
    /// later checkpoint with its contents and one of its transactions'
    /// effects and events, all in BCS.
    const MAINNET: &str = include_str!("../../tests/fixtures/sui_mainnet.json");

    fn b64(v: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(v.as_str().unwrap())
            .unwrap()
    }

    fn certificate(cp: &Value, epoch: u64) -> Certificate {
        let sig = &cp["validatorSignatures"];
        let mut signers: Vec<u16> = sig["signersMap"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i.as_u64().unwrap() as u16)
            .collect();
        signers.sort_unstable();
        Certificate {
            epoch,
            signature: b64(&sig["signature"]).try_into().unwrap(),
            signers,
        }
    }

    #[test]
    fn mainnet_committees_are_followed_and_an_event_is_proven_through_its_effects() {
        let f: Value = serde_json::from_str(MAINNET).unwrap();
        let first = b64(&f["end_of_epoch_before"]["summaryBcs"]);
        let second = b64(&f["end_of_epoch"]["summaryBcs"]);
        let anchor = LightClientAnchor::SuiCommittee {
            trusted_checkpoint_digest: digest("CheckpointSummary", &first),
        };
        assert_eq!(
            anchor.id().to_vec(),
            bs58::decode(f["end_of_epoch_before"]["digest"].as_str().unwrap())
                .into_vec()
                .unwrap()
        );
        let route = BridgeRoute {
            adapter: BridgeRouteAdapter::Contract,
            family: ChainFamily::Sui,
            source_chain: "sui".into(),
            source_chain_id: 1,
            local_selector: 2,
            peer: [1; 32],
            ramp: [2; 32],
            local_endpoint: [3; 32],
            remote_token: [4; 32],
            verifiers: VerifierQuorum {
                set_index: 0,
                size: 0,
                members: vec![],
                threshold: 0,
            },
            blessing: None,
            light_client: Some(anchor.clone()),
            mint_limit: MintRateLimit {
                per_mint: 1,
                per_epoch: 1,
            },
            outflow: tenzro_types::bridge_route::LaneRateLimit {
                capacity: u128::MAX,
                rate: u128::MAX / 2,
            },
            lane_limits: None,
            ibc: None,
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
        };
        let lc = SuiLightClient;
        let mut s = MemState::default();
        let mut w = Writer::new();
        w.u8(0).be_bytes(&first);
        lc.advance(&mut s, &route, &anchor, &w.into_bytes())
            .unwrap();

        let epoch = Summary::decode(&second).unwrap().epoch;
        let mut forged = certificate(&f["end_of_epoch"], epoch);
        forged.signature[10] ^= 1;
        let handover = |c: &Certificate| {
            let mut w = Writer::new();
            w.u8(1).be_bytes(&second);
            c.write(&mut w);
            w.into_bytes()
        };
        assert!(
            lc.advance(&mut s.clone(), &route, &anchor, &handover(&forged))
                .is_err()
        );
        lc.advance(
            &mut s,
            &route,
            &anchor,
            &handover(&certificate(&f["end_of_epoch"], epoch)),
        )
        .unwrap();

        // An event of a transaction in a later checkpoint.
        let cp = &f["checkpoint"];
        let summary = b64(&cp["summaryBcs"]);
        let contents = b64(&cp["contentBcs"]);
        let cert = certificate(cp, Summary::decode(&summary).unwrap().epoch);
        let tx = bs58::decode(f["transaction"]["digest"].as_str().unwrap())
            .into_vec()
            .unwrap();
        let tx_index = contents_digests(&contents)
            .unwrap()
            .iter()
            .position(|(t, _)| t.as_slice() == tx.as_slice())
            .unwrap() as u32;
        let effects = b64(&f["transaction"]["effects"]["effectsBcs"]);
        let mut events = Writer::new();
        let list = f["transaction"]["effects"]["events"]["nodes"]
            .as_array()
            .unwrap();
        events.uleb128(list.len());
        for e in list {
            events.raw(&b64(&e["eventBcs"]));
        }
        let events = events.into_bytes();
        let event = b64(&list[0]["eventBcs"]);
        let proof = |cert: &Certificate, event_index: u32| {
            let mut w = Writer::new();
            w.be_bytes(&summary);
            cert.write(&mut w);
            w.be_bytes(&contents)
                .u32_be(tx_index)
                .be_bytes(&effects)
                .be_bytes(&events)
                .u32_be(event_index);
            w.into_bytes()
        };
        lc.verify(&s, &route, &anchor, &body_hash(&event), &proof(&cert, 0))
            .unwrap();
        // Another position, or a forged certificate, does not prove it.
        assert!(
            lc.verify(&s, &route, &anchor, &body_hash(&event), &proof(&cert, 1))
                .is_err()
        );
        let mut bad = cert.clone();
        bad.signers.pop();
        bad.signers.pop();
        bad.signature[3] ^= 1;
        assert!(
            lc.verify(&s, &route, &anchor, &body_hash(&event), &proof(&bad, 0))
                .is_err()
        );
    }
}
