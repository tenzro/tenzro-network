//! Aptos: the bridge module's events, proven from ledger infos the
//! validator set signed.
//!
//! **Messages.** A delivery's body is one module event (`ContractEvent::V2`)
//! in BCS. Its type must be `<ramp>::bridge::TransferOut` and its data the
//! transfer record of [`super::move_event`]. Outbound transfers are that
//! record in BCS. A ledger info with a quorum certificate is final, so the
//! finality depth is 0.
//!
//! **Light client.** It starts from the route's anchor, the hash of an
//! epoch-ending ledger info, and takes the next epoch's validators (BLS12-381
//! keys and voting power) from it. Each later epoch-ending ledger info that
//! the current validators signed hands over to the next set. A signature
//! counts when validators holding at least two thirds of the voting power
//! plus one signed: an aggregate min-pk BLS signature over the ledger info's
//! signing message (its hasher seed and its BCS).
//!
//! A message proof is a signed ledger info, a transaction's info and its
//! version with a transaction accumulator proof to the ledger info's
//! `executed_state_id`, and the event's index with an event accumulator
//! proof to the transaction's `event_root_hash`. The transaction must have
//! succeeded, and the proven event must be exactly the delivered body.
//!
//! Hashes follow Aptos: SHA3-256 of the type's seed (the SHA3-256 of
//! `APTOS::<TypeName>`) and the BCS, and accumulator nodes under their own
//! seeds.
//!
//! Encodings (big-endian lengths and counts):
//!
//! ```text
//! update = 0x00 ledger_info:bytes                    (bootstrap)
//!        | 0x01 ledger_info_with_signatures:bytes     (validator set handover)
//! proof  = ledger_info_with_signatures:bytes transaction_info:bytes version:u64
//!          count:u8 { sibling:32 } event_index:u64 count:u8 { sibling:32 }
//! ```

use blst::BLST_ERROR;
use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use sha3::{Digest, Sha3_256};

use super::attestation::{MAX_PROOF_LEN, body_hash};
use super::canonical::{Reader, Writer};
use super::light_client::{LightClientHead, LightClientVerifier};
use super::move_event::{MoveTransfer, read_struct_type_tag};
use super::state::RouteState;
use super::{
    BridgeRoute, BridgeRouteAdapter, ChainFamily, LightClientAnchor, LightClientKind, RouteAdapter,
    RouteMessage,
};
use crate::error::{BridgeError, Result};

/// Domain separation tag of Aptos's min-pk BLS signatures.
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Largest validator set accepted.
pub const MAX_VALIDATORS: usize = 1024;

const PUBKEY_LEN: usize = 48;
const SIGNATURE_LEN: usize = 96;
const MAX_DEPTH: usize = 63;
const MAX_EVENT_DATA: usize = 64 * 1024;

fn refuse(what: impl Into<String>) -> BridgeError {
    BridgeError::TransferFailed(format!("aptos light client: {}", what.into()))
}

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("aptos event: {}", what.into()))
}

fn sha3(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The hasher seed of an Aptos type: SHA3-256 of `APTOS::<name>`.
pub fn seed(name: &str) -> [u8; 32] {
    sha3(&[b"APTOS::", name.as_bytes()])
}

/// An Aptos crypto hash: SHA3-256 of the type's seed and its BCS.
pub fn crypto_hash(type_name: &str, bcs: &[u8]) -> [u8; 32] {
    sha3(&[&seed(type_name), bcs])
}

/// A hash value: its 32 bytes, with no length prefix (Aptos serializes
/// `HashValue` as a fixed array).
fn read_hash(r: &mut Reader<'_>) -> Result<[u8; 32]> {
    r.array()
}

/// Verify an accumulator proof of the leaf at `index` up to `root`.
fn verify_accumulator(
    hasher: &str,
    leaf: [u8; 32],
    index: u64,
    siblings: &[[u8; 32]],
    root: &[u8; 32],
) -> Result<()> {
    if siblings.len() > MAX_DEPTH || (siblings.len() < 64 && index >> siblings.len() != 0) {
        return Err(refuse("the index does not fit the accumulator proof"));
    }
    let s = seed(hasher);
    let mut node = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        node = if index >> level & 1 == 0 {
            sha3(&[&s, &node, sibling])
        } else {
            sha3(&[&s, sibling, &node])
        };
    }
    if node != *root {
        return Err(refuse(format!(
            "the {hasher} proof does not reach its root"
        )));
    }
    Ok(())
}

// ---- events ----

/// The Aptos adapter. See the module docs.
pub struct AptosAdapter;

/// Read a module event (`ContractEvent::V2`) and return its data.
fn read_event(r: &mut Reader<'_>, route: &BridgeRoute) -> Result<Vec<u8>> {
    if r.uleb128(1)? != 1 {
        return Err(bad("not a module event"));
    }
    let tag = read_struct_type_tag(r)?;
    let data = r.bcs_bytes(MAX_EVENT_DATA)?.to_vec();
    if !tag.is_transfer_out(&route.ramp) {
        return Err(bad("not a TransferOut event of the route's bridge module"));
    }
    Ok(data)
}

impl RouteAdapter for AptosAdapter {
    fn transport(&self) -> BridgeRouteAdapter {
        BridgeRouteAdapter::Contract
    }

    fn family(&self) -> ChainFamily {
        ChainFamily::Aptos
    }

    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        let data = read_event(r, route)?;
        Ok(MoveTransfer::decode(&data)?.inbound(ChainFamily::Aptos, &data))
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

// ---- ledger infos ----

/// One validator: its BLS key and voting power.
pub type Validator = ([u8; PUBKEY_LEN], u64);

/// The fields of a ledger info the client uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerInfo {
    pub epoch: u64,
    pub executed_state_id: [u8; 32],
    pub version: u64,
    /// The next epoch and its validators, on an epoch-ending ledger info.
    pub next_epoch: Option<(u64, Vec<Validator>)>,
}

impl LedgerInfo {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let epoch = r.u64_le()?;
        let _round = r.u64_le()?;
        let _id = read_hash(r)?;
        let executed_state_id = read_hash(r)?;
        let version = r.u64_le()?;
        let _timestamp_usecs = r.u64_le()?;
        let next_epoch = match r.u8()? {
            0 => None,
            1 => {
                let next = r.u64_le()?;
                let n = r.uleb128(MAX_VALIDATORS)?;
                let mut set = Vec::with_capacity(n);
                for _ in 0..n {
                    let _address: [u8; 32] = r.array()?;
                    if r.uleb128(PUBKEY_LEN)? != PUBKEY_LEN {
                        return Err(refuse("a validator key is 48 bytes"));
                    }
                    set.push((r.array()?, r.u64_le()?));
                }
                Some((next, set))
            }
            _ => return Err(refuse("an option tag other than 0 or 1")),
        };
        let _consensus_data_hash = read_hash(r)?;
        Ok(Self {
            epoch,
            executed_state_id,
            version,
            next_epoch,
        })
    }
}

/// A ledger info with its validators' aggregate signature.
struct SignedLedgerInfo<'a> {
    info: LedgerInfo,
    info_bcs: &'a [u8],
    bitmask: Vec<u8>,
    signature: Option<[u8; SIGNATURE_LEN]>,
}

impl<'a> SignedLedgerInfo<'a> {
    fn decode(b: &'a [u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.uleb128(0)? != 0 {
            return Err(refuse("unknown ledger info version"));
        }
        let start = r.position();
        let info = LedgerInfo::read(&mut r)?;
        let info_bcs = &b[start..r.position()];
        let bitmask = r.bcs_bytes(MAX_VALIDATORS / 8)?.to_vec();
        let signature = match r.u8()? {
            0 => None,
            1 => {
                if r.uleb128(SIGNATURE_LEN)? != SIGNATURE_LEN {
                    return Err(refuse("an aggregate signature is 96 bytes"));
                }
                Some(r.array()?)
            }
            _ => return Err(refuse("an option tag other than 0 or 1")),
        };
        r.finish()?;
        Ok(Self {
            info,
            info_bcs,
            bitmask,
            signature,
        })
    }

    /// Require validators of `set` holding at least two thirds of its
    /// voting power plus one to have signed.
    fn verify(&self, set: &[Validator]) -> Result<()> {
        if self.bitmask.len() != set.len().div_ceil(8) {
            return Err(refuse(
                "the signer bitmask does not match the validator set",
            ));
        }
        let total: u128 = set.iter().map(|(_, p)| u128::from(*p)).sum();
        let mut signed = 0u128;
        let mut keys = Vec::new();
        for (i, byte) in self.bitmask.iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) == 0 {
                    continue;
                }
                let (pk, power) = set
                    .get(i * 8 + bit)
                    .ok_or_else(|| refuse("a signer outside the validator set"))?;
                keys.push(
                    PublicKey::from_bytes(pk)
                        .map_err(|_| refuse("a validator key does not decode"))?,
                );
                signed += u128::from(*power);
            }
        }
        if signed < total * 2 / 3 + 1 {
            return Err(refuse(
                "signers hold less than two thirds of the voting power plus one",
            ));
        }
        let sig = Signature::sig_validate(
            &self
                .signature
                .ok_or_else(|| refuse("the ledger info is unsigned"))?,
            true,
        )
        .map_err(|_| refuse("the aggregate signature does not decode"))?;
        let refs: Vec<&PublicKey> = keys.iter().collect();
        let agg = AggregatePublicKey::aggregate(&refs, false)
            .map_err(|_| refuse("validator keys do not aggregate"))?
            .to_public_key();
        let msg = [seed("LedgerInfo").as_slice(), self.info_bcs].concat();
        match sig.verify(true, &msg, BLS_DST, &[], &agg, false) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(refuse("the validators' signature does not verify")),
        }
    }
}

/// From a transaction info (V0): it succeeded, and its event root.
fn transaction_event_root(b: &[u8]) -> Result<[u8; 32]> {
    let mut r = Reader::new(b);
    if r.uleb128(0)? != 0 {
        return Err(refuse("unknown transaction info version"));
    }
    let _gas_used = r.u64_le()?;
    if r.uleb128(0)? != 0 {
        return Err(refuse("the transaction did not succeed"));
    }
    let _transaction_hash = read_hash(&mut r)?;
    read_hash(&mut r)
}

fn read_siblings(r: &mut Reader<'_>) -> Result<Vec<[u8; 32]>> {
    let n = r.u8()? as usize;
    if n > MAX_DEPTH {
        return Err(refuse("accumulator proof too deep"));
    }
    (0..n).map(|_| r.array()).collect()
}

// ---- the client ----

fn prefix(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    anchor.store_key(route)
}

fn set_key(route: &BridgeRoute, anchor: &LightClientAnchor, epoch: u64) -> String {
    format!("{}:validators:{epoch:020}", prefix(route, anchor))
}

fn head_key(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    prefix(route, anchor)
}

fn validators(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    epoch: u64,
) -> Result<Vec<Validator>> {
    let b = state
        .get(&set_key(route, anchor, epoch))
        .ok_or_else(|| refuse(format!("the validators of epoch {epoch} are not known")))?;
    let mut r = Reader::new(&b);
    let n = r.u16_be()? as usize;
    let set = (0..n)
        .map(|_| Ok((r.array()?, r.u64_be()?)))
        .collect::<Result<Vec<_>>>()?;
    r.finish()?;
    Ok(set)
}

/// (current epoch, version of the ledger info that started it).
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

fn trusted_hash(anchor: &LightClientAnchor) -> Result<[u8; 32]> {
    match anchor {
        LightClientAnchor::AptosValidators {
            trusted_ledger_info_hash,
        } => Ok(*trusted_ledger_info_hash),
        _ => Err(refuse("the route's anchor is not an Aptos anchor")),
    }
}

/// The Aptos light client. Its state lives in route state.
#[derive(Debug, Default)]
pub struct AptosLightClient;

impl LightClientVerifier for AptosLightClient {
    fn kind(&self) -> LightClientKind {
        LightClientKind::AptosValidators
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
            return Err(refuse("the proven event is not the delivered one"));
        }
        Ok(())
    }

    fn proven_lock_record(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        lock: &[u8; 32],
        proof: &[u8],
    ) -> Result<super::receipt_proof::LockRecord> {
        let event = proven_event(state, route, anchor, proof)?;
        let mut r = Reader::new(&event);
        if r.uleb128(1)? != 1 {
            return Err(bad("not a module event"));
        }
        let tag = read_struct_type_tag(&mut r)?;
        let data = r.bcs_bytes(MAX_EVENT_DATA)?;
        r.finish()?;
        if tag.address != *lock || tag.module != "settlement_lock" || tag.type_args != 0 {
            return Err(refuse("the event is not the route's settlement lock's"));
        }
        super::receipt_proof::move_lock_record(&tag.name, data)
    }

    fn advance(
        &self,
        state: &mut dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        update: &[u8],
    ) -> Result<LightClientHead> {
        let trusted = trusted_hash(anchor)?;
        let mut r = Reader::new(update);
        let tag = r.u8()?;
        let bytes = r.be_bytes(MAX_PROOF_LEN)?;
        r.finish()?;
        let info = match (tag, head(state, route, anchor)) {
            (0, None) => {
                let mut ir = Reader::new(bytes);
                let info = LedgerInfo::read(&mut ir)?;
                ir.finish()?;
                if crypto_hash("LedgerInfo", bytes) != trusted {
                    return Err(refuse("the bootstrap ledger info is not the anchor's"));
                }
                info
            }
            (1, Some((epoch, _))) => {
                let signed = SignedLedgerInfo::decode(bytes)?;
                if signed.info.epoch != epoch {
                    return Err(refuse(format!(
                        "a handover from epoch {}; the client follows epoch {epoch}",
                        signed.info.epoch
                    )));
                }
                signed.verify(&validators(state, route, anchor, epoch)?)?;
                signed.info
            }
            (0, Some(_)) => return Err(refuse("already bootstrapped")),
            (1, None) => return Err(refuse("not bootstrapped from the anchor")),
            (t, _) => return Err(refuse(format!("unknown update tag {t}"))),
        };
        let (next, set) = info
            .next_epoch
            .as_ref()
            .ok_or_else(|| refuse("not an epoch-ending ledger info"))?;
        if info.epoch.checked_add(1) != Some(*next)
            || set.is_empty()
            || set
                .iter()
                .any(|(pk, p)| *p == 0 || PublicKey::key_validate(pk).is_err())
        {
            return Err(refuse("the next validator set is malformed"));
        }
        let mut w = Writer::new();
        w.u16_be(set.len() as u16);
        for (pk, p) in set {
            w.raw(pk).u64_be(*p);
        }
        state.apply(vec![
            (set_key(route, anchor, *next), w.into_bytes()),
            (
                head_key(route, anchor),
                [next.to_be_bytes(), info.version.to_be_bytes()].concat(),
            ),
        ])?;
        Ok(LightClientHead {
            kind: "aptos_validators",
            finalized: info.version,
            period: *next,
            next_known: false,
        })
    }

    fn head(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
    ) -> Option<LightClientHead> {
        head(state, route, anchor).map(|(epoch, version)| LightClientHead {
            kind: "aptos_validators",
            finalized: version,
            period: epoch,
            next_known: false,
        })
    }
}

/// Walk an event proof (signed ledger info, transaction accumulator, event
/// accumulator) and return the proven event's bytes.
fn proven_event(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    proof: &[u8],
) -> Result<Vec<u8>> {
    let mut r = Reader::new(proof);
    let signed = SignedLedgerInfo::decode(r.be_bytes(MAX_PROOF_LEN)?)?;
    let txn_info = r.be_bytes(4096)?;
    let version = r.u64_be()?;
    let txn_siblings = read_siblings(&mut r)?;
    let event = r.be_bytes(super::attestation::MAX_BODY_LEN)?;
    let event_index = r.u64_be()?;
    let event_siblings = read_siblings(&mut r)?;
    r.finish()?;

    // Only the validator set the client follows, and the one before it for
    // ledger infos up to its epoch's last version, prove anything: a set long
    // retired has nothing at stake and could sign any ledger info.
    let (epoch, ended_at) =
        head(state, route, anchor).ok_or_else(|| refuse("the light client is not bootstrapped"))?;
    let current = signed.info.epoch == epoch;
    let just_ended =
        signed.info.epoch.checked_add(1) == Some(epoch) && signed.info.version <= ended_at;
    if !current && !just_ended {
        return Err(refuse(format!(
            "a ledger info of epoch {} at version {}; the client proves epoch {epoch} and epoch {} through version {ended_at}",
            signed.info.epoch,
            signed.info.version,
            epoch.saturating_sub(1)
        )));
    }
    signed.verify(&validators(state, route, anchor, signed.info.epoch)?)?;
    if version > signed.info.version {
        return Err(refuse("the transaction is past the signed ledger info"));
    }
    verify_accumulator(
        "TransactionAccumulator",
        crypto_hash("TransactionInfo", txn_info),
        version,
        &txn_siblings,
        &signed.info.executed_state_id,
    )?;
    let event_root = transaction_event_root(txn_info)?;
    verify_accumulator(
        "EventAccumulator",
        crypto_hash("ContractEvent", event),
        event_index,
        &event_siblings,
        &event_root,
    )?;
    Ok(event.to_vec())
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! A BLS validator set that signs synthetic ledger infos, and
    //! accumulator proofs, for route tests.

    use blst::min_pk::{AggregateSignature, SecretKey};

    use super::*;

    pub struct Validators {
        pub keys: Vec<SecretKey>,
    }

    impl Validators {
        pub fn new(seed: u8, n: usize) -> Self {
            Self {
                keys: (0..n)
                    .map(|i| SecretKey::key_gen(&[seed.wrapping_add(i as u8); 32], &[]).unwrap())
                    .collect(),
            }
        }

        /// A ledger info signed by the validators at `signers`.
        pub fn sign(&self, info_bcs: &[u8], signers: &[usize]) -> Vec<u8> {
            let msg = [seed("LedgerInfo").as_slice(), info_bcs].concat();
            let sigs: Vec<_> = signers
                .iter()
                .map(|i| self.keys[*i].sign(&msg, BLS_DST, &[]))
                .collect();
            let refs: Vec<_> = sigs.iter().collect();
            let agg = AggregateSignature::aggregate(&refs, true)
                .unwrap()
                .to_signature();
            let mut mask = vec![0u8; self.keys.len().div_ceil(8)];
            for i in signers {
                mask[i / 8] |= 0x80 >> (i % 8);
            }
            let mut w = Writer::new();
            w.uleb128(0)
                .raw(info_bcs)
                .bcs_bytes(&mask)
                .u8(1)
                .uleb128(SIGNATURE_LEN)
                .raw(&agg.compress());
            w.into_bytes()
        }
    }

    fn hash_bcs(w: &mut Writer, h: &[u8; 32]) {
        w.raw(h);
    }

    /// A ledger info in BCS.
    pub fn ledger_info(
        epoch: u64,
        version: u64,
        executed_state_id: [u8; 32],
        next: Option<&Validators>,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_le(epoch).u64_le(3);
        hash_bcs(&mut w, &[0x1d; 32]);
        hash_bcs(&mut w, &executed_state_id);
        w.u64_le(version).u64_le(1_800_000_000_000_000);
        match next {
            Some(v) => {
                w.u8(1).u64_le(epoch + 1).uleb128(v.keys.len());
                for (i, k) in v.keys.iter().enumerate() {
                    w.raw(&[i as u8; 32])
                        .uleb128(PUBKEY_LEN)
                        .raw(&k.sk_to_pk().compress())
                        .u64_le(100);
                }
            }
            None => {
                w.u8(0);
            }
        }
        hash_bcs(&mut w, &[0x2d; 32]);
        w.into_bytes()
    }

    /// A module event of `tag_address::module::name` carrying `data`.
    pub fn event(tag_address: [u8; 32], module: &str, name: &str, data: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.uleb128(1)
            .uleb128(7)
            .raw(&tag_address)
            .bcs_bytes(module.as_bytes())
            .bcs_bytes(name.as_bytes())
            .uleb128(0)
            .bcs_bytes(data);
        w.into_bytes()
    }

    /// A successful transaction info whose events have `event_root`.
    pub fn transaction_info(event_root: [u8; 32]) -> Vec<u8> {
        let mut w = Writer::new();
        w.uleb128(0).u64_le(21).uleb128(0);
        hash_bcs(&mut w, &[0x3d; 32]);
        hash_bcs(&mut w, &event_root);
        hash_bcs(&mut w, &[0x4d; 32]);
        w.u8(0).u8(0);
        w.into_bytes()
    }

    /// The root of `leaves` under accumulator `hasher` and the proof of
    /// `index` (a full binary tree; `leaves.len()` is a power of two).
    pub fn accumulator(
        hasher: &str,
        leaves: &[[u8; 32]],
        index: usize,
    ) -> ([u8; 32], Vec<[u8; 32]>) {
        let s = seed(hasher);
        let mut layer = leaves.to_vec();
        let mut idx = index;
        let mut siblings = Vec::new();
        while layer.len() > 1 {
            siblings.push(layer[idx ^ 1]);
            layer = layer.chunks(2).map(|p| sha3(&[&s, &p[0], &p[1]])).collect();
            idx /= 2;
        }
        (layer[0], siblings)
    }

    /// The ledger info of a signed ledger info, without its signature.
    pub fn unsigned(signed: &[u8]) -> Vec<u8> {
        SignedLedgerInfo::decode(signed).unwrap().info_bcs.to_vec()
    }

    pub fn update(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(tag).be_bytes(bytes);
        w.into_bytes()
    }

    pub struct Proof<'a> {
        pub signed: &'a [u8],
        pub txn_info: &'a [u8],
        pub version: u64,
        pub txn_siblings: &'a [[u8; 32]],
        pub event: &'a [u8],
        pub event_index: u64,
        pub event_siblings: &'a [[u8; 32]],
    }

    impl Proof<'_> {
        pub fn encode(&self) -> Vec<u8> {
            let mut w = Writer::new();
            w.be_bytes(self.signed)
                .be_bytes(self.txn_info)
                .u64_be(self.version)
                .u8(self.txn_siblings.len() as u8);
            for s in self.txn_siblings {
                w.raw(s);
            }
            w.be_bytes(self.event)
                .u64_be(self.event_index)
                .u8(self.event_siblings.len() as u8);
            for s in self.event_siblings {
                w.raw(s);
            }
            w.into_bytes()
        }
    }
}
