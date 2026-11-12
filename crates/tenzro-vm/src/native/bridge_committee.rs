//! Bridge route committees, drawn from bonded attestors.
//!
//! Governance sets a route's committee sizes and thresholds; it never names
//! members. Any account bonded as an attestor that declared a bridge signing
//! key (`StakeCapacity::BridgeSigner`) is eligible. A `DrawCommittee`
//! operation, which anyone may submit, ranks the eligible accounts by a hash
//! of the route, the next set index, the first randomness-beacon value taken
//! at or after the moment the draw became due, and the account, divided by
//! the account's attestor stake, so more stake ranks earlier, and seats them
//! in rank order under the committee rules: one seat per account and per
//! signing key, and no RPC provider behind `threshold` or more seats. A
//! CCIP route's blessing committee is drawn after, from the accounts left.
//!
//! A draw is due when the route was installed with empty committees, when
//! the committees' term (`bridge.committee_term_ms`) has ended, or when an
//! equivocation broke them. Until it is drawn the route carries no traffic.
//!
//! Each drawn committee carries an expiry: the end of its term plus
//! `bridge.handover_window_ms`. Bridge contracts on external chains trust one
//! committee at a time and stop trusting it at its expiry. The committee a
//! contract trusts hands it over to the next one drawn here by signing
//! [`committee_handover_digest`] for that committee's set index, members,
//! threshold and expiry; any relayer submits the signatures, and the
//! contract accepts only a higher set index than the one it holds. Every
//! drawn committee is kept by set index so anyone can check a handover
//! against it.
//!
//! Only bonds whose stake and signer were in place before that beacon value
//! was taken are eligible, so nobody can choose a seat once the value is
//! known.
//!
//! A member stays bonded, and keeps its bridge signer, until its committee's
//! expiry, however early a new draw replaces that committee: the contract
//! may trust it until then. A member that signed two different deliveries
//! with one nonce is reported with both; a member that signed a handover to
//! anything but a committee drawn here, with its exact members, threshold
//! and expiry, from a committee it sat on, is reported with that signature. Either way the chain checks
//! the signature, takes `bridge.equivocation_slash_bps` of its attestor stake
//! into the insurance pool, and, if it sits on the route's committees,
//! empties them so they are drawn again.

use sha2::{Digest, Sha256};
use tenzro_bridge::route::attestation::{Delivery, attestation_digest, committee_handover_digest};
use tenzro_types::bridge_route::{BridgeRoute, BridgeRouteAdapter, VerifierMember, VerifierQuorum};
use tenzro_types::network::NetworkRole;
use tenzro_types::token::StakeCapacity;

use super::funding::{read_json, refuse, write_json};
use super::*;

/// Governed: how long a drawn committee serves before a new draw is due, ms.
pub const COMMITTEE_TERM_PARAM: &str = "bridge.committee_term_ms";
/// Genesis value of [`COMMITTEE_TERM_PARAM`]: thirty days.
pub const DEFAULT_COMMITTEE_TERM_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Governed: share of an equivocating member's attestor stake slashed, bps.
pub const EQUIVOCATION_SLASH_PARAM: &str = "bridge.equivocation_slash_bps";
/// Genesis value of [`EQUIVOCATION_SLASH_PARAM`].
pub const DEFAULT_EQUIVOCATION_SLASH_BPS: u64 = 5_000;
/// Governed: how long after its term ends a committee may still be handed
/// over from, ms; the bridge contracts stop trusting it then.
pub const HANDOVER_WINDOW_PARAM: &str = "bridge.handover_window_ms";
/// Genesis value of [`HANDOVER_WINDOW_PARAM`]: seven days.
pub const DEFAULT_HANDOVER_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// A drawn verifier committee as bridge contracts are handed it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommitteeSet {
    /// The committee.
    pub quorum: VerifierQuorum,
    /// Unix second after which bridge contracts stop trusting it.
    pub expires_at_secs: u64,
}

fn set_key(route_key: &str, set_index: u32) -> String {
    format!("bridge_committee_set:{route_key}:{set_index}")
}

/// Verifier committee `set_index` of the route stored under `route_key`.
pub fn read_committee_set(
    state: &dyn VmState,
    route_key: &str,
    set_index: u32,
) -> Option<CommitteeSet> {
    read_json(state, &set_key(route_key, set_index))
}

/// The digest committee `set_index` of `route` is handed over with.
pub fn handover_digest(chain_id: u64, route: &BridgeRoute, set: &CommitteeSet) -> [u8; 32] {
    committee_handover_digest(
        chain_id,
        route,
        set.quorum.set_index,
        &set.quorum.addresses(),
        set.quorum.threshold,
        set.expires_at_secs,
    )
}

/// When a route's committees were drawn and when the next draw is due.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommitteeTerm {
    /// Block time of the last draw, ms; zero before the first.
    pub drawn_at_ms: i64,
    /// Block time from which a draw is due, ms. The draw takes the first
    /// beacon value at or after it, so its submitter cannot choose one.
    pub due_at_ms: i64,
}

fn term_key(route_key: &str) -> String {
    format!("bridge_committee_term:{route_key}")
}

fn seats_key(account: &[u8]) -> String {
    format!("bridge_committee_seats:{}", hex::encode(account))
}

/// The term of the route stored under `route_key`.
pub fn read_term(state: &dyn VmState, route_key: &str) -> Option<CommitteeTerm> {
    read_json(state, &term_key(route_key))
}

/// Route keys `account` holds a seat on, and when each seat's term ends.
pub fn read_seats(state: &dyn VmState, account: &[u8]) -> Vec<(String, i64)> {
    read_json(state, &seats_key(account)).unwrap_or_default()
}

/// Whether `account` holds a bridge committee seat at `now_ms`.
pub fn seated(state: &dyn VmState, account: &[u8], now_ms: i64) -> bool {
    read_seats(state, account)
        .iter()
        .any(|(_, ends)| *ends > now_ms)
}

/// Give a route governance is about to install the set indexes of the route
/// it replaces, so the next draw continues the sequence bridge contracts
/// hold. A first install keeps zero.
pub(super) fn carry_set_indexes(state: &dyn VmState, route: &mut BridgeRoute) {
    if let Some(old) = read_bridge_route(state, route.adapter, &route.source_chain) {
        route.verifiers.set_index = old.verifiers.set_index;
        if let (Some(b), Some(old_b)) = (route.blessing.as_mut(), old.blessing.as_ref()) {
            b.set_index = old_b.set_index;
        }
    }
}

/// The storage key and value genesis writes for a route it installs whole:
/// its committees are due for a draw from the genesis time, as for a route an
/// enacted proposal installs.
pub fn genesis_term_entry(route: &BridgeRoute, genesis_ms: i64) -> Result<(String, Vec<u8>)> {
    let term = CommitteeTerm {
        drawn_at_ms: 0,
        due_at_ms: genesis_ms,
    };
    let blob = serde_json::to_vec(&term)
        .map_err(|e| VmError::Internal(format!("committee term serialization failed: {e}")))?;
    Ok((term_key(&route.storage_key()), blob))
}

/// Mark a newly installed route's committees as due for a draw at `now_ms`.
/// Members of the committees it replaced keep their seats until their
/// committees expire.
pub(super) fn on_route_installed(
    state: &mut dyn VmState,
    route: &BridgeRoute,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let term = CommitteeTerm {
        drawn_at_ms: 0,
        due_at_ms: now_ms,
    };
    write_json(state, &term_key(&route.storage_key()), &term, changes)?;
    Ok(())
}

/// An attestor eligible for a seat.
struct Candidate {
    account: Vec<u8>,
    address: [u8; 20],
    pq_public_key: Vec<u8>,
    rpc_provider: String,
    rank: u128,
}

/// The accounts eligible for a draw whose beacon value `mix` was taken at
/// `mix_at_ms`, in rank order. Only a bond whose stake and signer were
/// already in place before that value existed is eligible, so nobody can
/// bond, add stake or switch signers once the mix is known to pick a seat.
fn candidates(
    state: &dyn VmState,
    route_key: &str,
    set_index: u32,
    mix: &[u8; 32],
    mix_at_ms: i64,
) -> Vec<Candidate> {
    let role = NetworkRole::Attestor;
    let mut out: Vec<Candidate> = role_stake_totals(state)
        .into_iter()
        .filter(|(r, _)| *r == role)
        .flat_map(|(_, t)| t.stakers)
        .filter_map(|a| hex::decode(a).ok())
        .filter(|a| role_bonded(state, a, role))
        .filter_map(|account| {
            let stake = read_role_stake(state, &account, role)?;
            if stake.bonded_at_ms >= mix_at_ms {
                return None;
            }
            let StakeCapacity::BridgeSigner {
                address,
                rpc_provider,
                pq_public_key,
                ..
            } = stake.capacity
            else {
                return None;
            };
            let h: [u8; 32] = Sha256::new()
                .chain_update(b"tenzro/bridge/committee")
                .chain_update(route_key.as_bytes())
                .chain_update(set_index.to_le_bytes())
                .chain_update(mix)
                .chain_update(&account)
                .finalize()
                .into();
            let draw = u128::from_be_bytes(h[..16].try_into().ok()?);
            let weight = (stake.bonded / tenzro_types::constants::ONE_TNZO).max(1);
            Some(Candidate {
                rank: draw / weight,
                account,
                address,
                pq_public_key,
                rpc_provider: rpc_provider.trim().to_string(),
            })
        })
        .collect();
    out.sort_by(|a, b| a.rank.cmp(&b.rank).then_with(|| a.account.cmp(&b.account)));
    out
}

/// Seat `quorum.size` members from `pool` in rank order under the committee
/// rules, taking them out of `pool`.
fn seat(
    pool: &mut Vec<Candidate>,
    quorum: &VerifierQuorum,
    set_index: u32,
    label: &str,
) -> Result<VerifierQuorum> {
    let size = quorum.size as usize;
    let threshold = quorum.threshold as usize;
    let mut chosen: Vec<VerifierMember> = Vec::with_capacity(size);
    let mut by_rpc: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut i = 0;
    while chosen.len() < size && i < pool.len() {
        let c = &pool[i];
        let rpc_full = by_rpc.get(&c.rpc_provider).copied().unwrap_or(0) + 1 >= threshold;
        let address_taken = chosen.iter().any(|m| m.address == c.address);
        if rpc_full || address_taken {
            i += 1;
            continue;
        }
        let c = pool.remove(i);
        *by_rpc.entry(c.rpc_provider.clone()).or_default() += 1;
        chosen.push(VerifierMember {
            address: c.address,
            pq_public_key: c.pq_public_key,
            operator: hex::encode(&c.account),
            rpc_provider: c.rpc_provider,
        });
    }
    if chosen.len() < size {
        return Err(refuse(format!(
            "the {label} committee needs {size} bonded attestors with a bridge signer on distinct keys and \
             RPC providers; {} could be seated",
            chosen.len()
        )));
    }
    Ok(VerifierQuorum {
        set_index,
        size: quorum.size,
        members: chosen,
        threshold: quorum.threshold,
    })
}

/// Draw the committees of the route `adapter`/`source_chain` at `now_ms`.
pub(super) fn draw(
    state: &mut dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<serde_json::Value> {
    let mut route = read_bridge_route(state, adapter, source_chain).ok_or_else(|| {
        refuse(format!(
            "no governed {} route for '{source_chain}'",
            adapter.as_str()
        ))
    })?;
    let key = route.storage_key();
    let term = read_term(state, &key).ok_or_else(|| refuse("the route has no committee term"))?;
    if now_ms < term.due_at_ms {
        return Err(refuse(format!(
            "the route's committees are next drawn from {} ms",
            term.due_at_ms
        )));
    }
    let entry = super::beacon::first_at_or_after(state, term.due_at_ms).ok_or_else(|| {
        refuse(format!(
            "the randomness beacon has taken no value since {}; draw after its next contribution",
            term.due_at_ms
        ))
    })?;
    let mix =
        super::beacon::entry_mix(&entry).ok_or_else(|| refuse("the beacon value is malformed"))?;
    let set_index = route.verifiers.set_index.saturating_add(1);
    let mut pool = candidates(state, &key, set_index, &mix, entry.at_ms);
    let verifiers = seat(&mut pool, &route.verifiers, set_index, "verifiers")?;
    let blessing = match &route.blessing {
        Some(b) => Some(seat(
            &mut pool,
            b,
            b.set_index.saturating_add(1),
            "blessing",
        )?),
        None => None,
    };
    route.verifiers = verifiers;
    route.blessing = blessing;
    route
        .validate()
        .map_err(|e| refuse(format!("the drawn committees break the route rules: {e}")))?;
    let term_ms = network_param(state, COMMITTEE_TERM_PARAM);
    let ends = now_ms.saturating_add(i64::try_from(term_ms).unwrap_or(i64::MAX));
    let window = i64::try_from(network_param(state, HANDOVER_WINDOW_PARAM)).unwrap_or(i64::MAX);
    let expires_at_secs = u64::try_from(ends.saturating_add(window) / 1000).unwrap_or(0);
    // Seats last until the committee expires: a contract may trust it until then.
    let seat_ends = i64::try_from(expires_at_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    let set = CommitteeSet {
        quorum: route.verifiers.clone(),
        expires_at_secs,
    };
    write_json(state, &set_key(&key, set.quorum.set_index), &set, changes)?;
    let seated: Vec<String> = route
        .verifiers
        .members
        .iter()
        .chain(route.blessing.iter().flat_map(|b| b.members.iter()))
        .map(|m| m.operator.clone())
        .collect();
    for account_hex in &seated {
        let account = hex::decode(account_hex)
            .map_err(|e| VmError::Internal(format!("seat account: {e}")))?;
        let mut seats = read_seats(state, &account);
        let held = seats
            .iter()
            .filter(|(k, _)| *k == key)
            .map(|(_, e)| *e)
            .max()
            .unwrap_or(0);
        seats.retain(|(k, _)| *k != key);
        seats.push((key.clone(), seat_ends.max(held)));
        write_json(state, &seats_key(&account), &seats, changes)?;
    }
    write_json(state, &key, &route, changes)?;
    write_json(
        state,
        &term_key(&key),
        &CommitteeTerm {
            drawn_at_ms: now_ms,
            due_at_ms: ends,
        },
        changes,
    )?;
    Ok(serde_json::json!({
        "route": key,
        "set_index": route.verifiers.set_index,
        "verifiers": route.verifiers.members,
        "blessing": route.blessing.as_ref().map(|b| &b.members),
        "term_ends_ms": ends,
        "expires_at_secs": expires_at_secs,
    }))
}

/// Take `bridge.equivocation_slash_bps` of `account`'s attestor stake into
/// the insurance pool. Returns what was taken.
fn slash_member(
    state: &mut dyn VmState,
    account: &[u8],
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let bps = network_param(state, EQUIVOCATION_SLASH_PARAM).min(10_000) as u16;
    let taken = role_stake::take_role_stake(state, account, NetworkRole::Attestor, bps, changes)?;
    let pool = derive_insurance_pool_address().as_bytes().to_vec();
    let before = state.get_balance(&pool);
    let after = before.saturating_add(taken);
    state.set_balance(&pool, after);
    changes.push(StateChange::new(
        pool,
        b"balance".to_vec(),
        Some(before.to_le_bytes().to_vec()),
        Some(after.to_le_bytes().to_vec()),
    ));
    insurance::note_credit(state, taken, insurance::PoolSource::Slash, changes)?;
    Ok(taken)
}

/// Key of when a proven committee fault (an equivocation or a wrong
/// handover) last emptied the route's committees, unix ms.
pub fn fault_key(route_key: &str) -> String {
    format!("bridge_committee_fault:{route_key}")
}

/// When a proven committee fault last emptied the route's committees.
pub fn last_fault_ms(state: &dyn VmState, route_key: &str) -> Option<i64> {
    read_json(state, &fault_key(route_key))
}

/// Empty the route's committees: no traffic until they are drawn again.
/// The time is kept, so exits queued before it can be cancelled.
fn break_committees(
    state: &mut dyn VmState,
    mut route: BridgeRoute,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    route.verifiers.members.clear();
    if let Some(b) = route.blessing.as_mut() {
        b.members.clear();
    }
    let key = route.storage_key();
    write_json(state, &key, &route, changes)?;
    write_json(state, &fault_key(&key), &now_ms, changes)?;
    let drawn_at_ms = read_term(state, &key).map_or(0, |t| t.drawn_at_ms);
    write_json(
        state,
        &term_key(&key),
        &CommitteeTerm {
            drawn_at_ms,
            due_at_ms: now_ms,
        },
        changes,
    )?;
    Ok(())
}

/// A handover a committee member signed, as reported.
pub(super) struct SignedHandover {
    /// The committee the signer sat on.
    pub signed_by_set: u32,
    /// The committee the handover names.
    pub set_index: u32,
    pub members: Vec<[u8; 20]>,
    pub threshold: u32,
    pub expires_at_secs: u64,
    pub signature: [u8; 65],
}

/// Check that a member of committee `h.signed_by_set` signed a handover to
/// a committee this chain did not draw, slash it, and if it sits on the
/// route's committees, empty them for a new draw.
pub(super) fn report_wrong_handover(
    state: &mut dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
    chain_id: u64,
    h: &SignedHandover,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<serde_json::Value> {
    let route = read_bridge_route(state, adapter, source_chain).ok_or_else(|| {
        refuse(format!(
            "no governed {} route for '{source_chain}'",
            adapter.as_str()
        ))
    })?;
    let key = route.storage_key();
    let signers = read_committee_set(state, &key, h.signed_by_set)
        .ok_or_else(|| refuse(format!("the route drew no committee {}", h.signed_by_set)))?;
    let digest = committee_handover_digest(
        chain_id,
        &route,
        h.set_index,
        &h.members,
        h.threshold,
        h.expires_at_secs,
    );
    let signer = tenzro_bridge::secp256k1_multisig::recover_address(&digest, &h.signature)
        .ok_or_else(|| refuse("the signature does not recover"))?;
    let seat = signers
        .quorum
        .members
        .iter()
        .find(|m| m.address == signer)
        .cloned()
        .ok_or_else(|| {
            refuse(format!(
                "the signer sat on no seat of committee {}",
                h.signed_by_set
            ))
        })?;
    // The digest does not say which committee the signer signed from, so
    // the report's `signed_by_set` only locates the signer. A handover to a
    // committee exactly as drawn is honest whenever the signer sat on any
    // earlier drawn committee it could have handed over from; only a
    // handover no seat of the signer can account for is a fault.
    let drawn = read_committee_set(state, &key, h.set_index);
    let names_drawn = drawn.is_some_and(|d| {
        d.quorum.addresses() == h.members
            && d.quorum.threshold == h.threshold
            && d.expires_at_secs == h.expires_at_secs
    });
    let sat_before = || {
        (0..h.set_index).rev().any(|s| {
            read_committee_set(state, &key, s)
                .is_some_and(|set| set.quorum.members.iter().any(|m| m.address == signer))
        })
    };
    if names_drawn && sat_before() {
        return Err(refuse(
            "the handover names a committee this chain drew, from one its signer sat on",
        ));
    }
    let marker = format!(
        "bridge_wrong_handover:{}:{}",
        hex::encode(digest),
        hex::encode(signer)
    );
    if state
        .get_storage(&SYSTEM_ADDRESS, marker.as_bytes())
        .is_some()
    {
        return Err(refuse("this signature was already reported"));
    }
    write_json(state, &marker, &now_ms, changes)?;
    let account =
        hex::decode(&seat.operator).map_err(|e| VmError::Internal(format!("seat account: {e}")))?;
    let taken = slash_member(state, &account, changes)?;
    let sits = route
        .verifiers
        .members
        .iter()
        .chain(route.blessing.iter().flat_map(|b| b.members.iter()))
        .any(|m| m.operator == seat.operator);
    if sits {
        break_committees(state, route, now_ms, changes)?;
    }
    Ok(serde_json::json!({
        "route": key,
        "member": hex::encode(signer),
        "account": seat.operator,
        "slashed": taken.to_string(),
        "committees_broken": sits,
    }))
}

/// Check that `member` of the route signed two different deliveries with one
/// nonce, slash it, and empty the route's committees for a new draw.
pub(super) fn report_equivocation(
    state: &mut dyn VmState,
    adapter: BridgeRouteAdapter,
    source_chain: &str,
    member: [u8; 20],
    first: &[u8],
    second: &[u8],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<serde_json::Value> {
    let route = read_bridge_route(state, adapter, source_chain).ok_or_else(|| {
        refuse(format!(
            "no governed {} route for '{source_chain}'",
            adapter.as_str()
        ))
    })?;
    let seat = route
        .verifiers
        .members
        .iter()
        .chain(route.blessing.iter().flat_map(|b| b.members.iter()))
        .find(|m| m.address == member)
        .cloned()
        .ok_or_else(|| refuse("the address holds no seat on the route's committees"))?;
    let a = Delivery::decode(first).map_err(|e| refuse(format!("first delivery: {e}")))?;
    let b = Delivery::decode(second).map_err(|e| refuse(format!("second delivery: {e}")))?;
    if a.nonce != b.nonce {
        return Err(refuse("the two deliveries carry different nonces"));
    }
    let (da, db) = (
        attestation_digest(&route, &a),
        attestation_digest(&route, &b),
    );
    if da == db {
        return Err(refuse("the two deliveries attest the same message"));
    }
    // Both of the member's legs must be on both deliveries, so a forger of
    // secp256k1 signatures alone cannot frame a member.
    let seat_only = VerifierQuorum {
        set_index: 0,
        size: 1,
        members: vec![seat.clone()],
        threshold: 1,
    };
    let signed = |d: &Delivery, digest: &[u8; 32]| {
        let sigs: Vec<_> = d
            .committee
            .iter()
            .chain(d.blessing.iter())
            .filter(|(addr, _)| *addr == member)
            .copied()
            .collect();
        let pq: Vec<_> = d
            .committee_pq
            .iter()
            .chain(d.blessing_pq.iter())
            .filter(|(addr, _)| *addr == member)
            .cloned()
            .collect();
        !tenzro_bridge::route::attestation::dual_signers(&seat_only, digest, &sigs, &pq).is_empty()
    };
    if !signed(&a, &da) || !signed(&b, &db) {
        return Err(refuse("the member's signature is not on both deliveries"));
    }
    let account =
        hex::decode(&seat.operator).map_err(|e| VmError::Internal(format!("seat account: {e}")))?;
    let taken = slash_member(state, &account, changes)?;
    let key = route.storage_key();
    break_committees(state, route, now_ms, changes)?;
    Ok(serde_json::json!({
        "route": key,
        "member": hex::encode(member),
        "account": seat.operator,
        "slashed": taken.to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VmConfig;
    use crate::VmType;
    use crate::state_adapter::StateAdapter;
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_types::bridge_route::{BridgeRoute, ChainFamily, MintRateLimit};
    use tenzro_types::token::StakeOp;

    const T0: i64 = 1_000_000;

    fn key(seed: u8) -> SigningKey {
        let mut b = [0u8; 32];
        b[0] = 0x31;
        b[31] = seed;
        SigningKey::from_bytes((&b).into()).unwrap()
    }

    fn address(sk: &SigningKey) -> [u8; 20] {
        let point = sk.verifying_key().to_sec1_point(false);
        let h = tenzro_crypto::hash::keccak256(&point.as_bytes()[1..]);
        h.as_bytes()[12..].try_into().unwrap()
    }

    fn sign(sk: &SigningKey, digest: &[u8; 32]) -> [u8; 65] {
        let (sig, rec): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            sk.sign_prehash(digest).unwrap();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = rec.to_byte();
        out
    }

    fn pq_leg(sk: &SigningKey, digest: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let k = tenzro_bridge::route::attestation::testing::pq_key(&sk.to_bytes());
        (
            k.verifying_key_bytes().to_vec(),
            k.sign(tenzro_types::token::BRIDGE_SIGNER_PQ_CONTEXT, digest),
        )
    }

    fn route() -> BridgeRoute {
        BridgeRoute {
            adapter: BridgeRouteAdapter::Contract,
            family: ChainFamily::Sui,
            source_chain: "sui".into(),
            source_chain_id: 42,
            local_selector: 7_777,
            peer: [7u8; 32],
            ramp: [8u8; 32],
            local_endpoint: [9u8; 32],
            remote_token: [6u8; 32],
            verifiers: VerifierQuorum {
                set_index: 0,
                size: 3,
                members: Vec::new(),
                threshold: 2,
            },
            blessing: None,
            light_client: Some(
                tenzro_types::bridge_route::LightClientAnchor::SuiCommittee {
                    trusted_checkpoint_digest: [5u8; 32],
                },
            ),
            mint_limit: MintRateLimit {
                per_mint: 100,
                per_epoch: 1_000,
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
        }
    }

    async fn run(
        ex: &NativeExecutor,
        state: &mut StateAdapter,
        from: &[u8],
        selector: [u8; 4],
        body: Vec<u8>,
        at: i64,
    ) -> Result<ExecutionResult> {
        let mut data = selector.to_vec();
        data.extend(body);
        let mut tx = VmTransaction::new(
            from.to_vec(),
            None,
            0,
            data,
            10_000_000,
            0,
            0,
            VmType::Tenzro,
            1337,
        );
        tx.block_timestamp_ms = Some(at);
        ex.execute_transaction(&tx, state).await
    }

    /// Bond `account` as an attestor whose bridge signer is `sk`, reading
    /// source chains through `rpc`.
    async fn bond(
        ex: &NativeExecutor,
        state: &mut StateAdapter,
        account: &[u8],
        sk: &SigningKey,
        rpc: &str,
        stake: u128,
    ) {
        bond_at(ex, state, account, sk, rpc, stake, T0).await
    }

    /// [`bond`] at block time `at`.
    async fn bond_at(
        ex: &NativeExecutor,
        state: &mut StateAdapter,
        account: &[u8],
        sk: &SigningKey,
        rpc: &str,
        stake: u128,
        at: i64,
    ) {
        state.set_balance(account, 2 * stake);
        let digest = tenzro_types::token::bridge_signer_digest(account);
        let proof = sign(sk, &digest).to_vec();
        let (pq_public_key, pq_proof) = pq_leg(sk, &digest);
        let op = StakeOp::Bond {
            role: NetworkRole::Attestor,
            amount: stake,
            capacity: StakeCapacity::BridgeSigner {
                address: address(sk),
                rpc_provider: rpc.into(),
                proof,
                pq_public_key,
                pq_proof,
            },
        };
        run(
            ex,
            state,
            account,
            role_stake::SELECTOR_STAKE,
            serde_json::to_vec(&op).unwrap(),
            at,
        )
        .await
        .unwrap();
    }

    fn install(state: &mut StateAdapter) -> BridgeRoute {
        let r = route();
        r.validate_proposal().unwrap();
        let mut changes = Vec::new();
        write_json(state, &r.storage_key(), &r, &mut changes).unwrap();
        on_route_installed(state, &r, T0, &mut changes).unwrap();
        r
    }

    async fn draw_op(
        ex: &NativeExecutor,
        state: &mut StateAdapter,
        at: i64,
    ) -> Result<ExecutionResult> {
        let op = tenzro_types::bridge_transfer::BridgeOp::DrawCommittee {
            adapter: BridgeRouteAdapter::Contract,
            source_chain: "sui".into(),
        };
        state.set_balance(&[0xEE; 32], 1);
        run(
            ex,
            state,
            &[0xEE; 32],
            super::super::bridge::SELECTOR_BRIDGE,
            serde_json::to_vec(&op).unwrap(),
            at,
        )
        .await
    }

    #[tokio::test]
    async fn a_committee_is_drawn_from_bonded_attestors_with_a_bridge_signer() {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        let keys: Vec<SigningKey> = (1..=4).map(key).collect();
        for (i, sk) in keys.iter().enumerate() {
            bond(
                &ex,
                &mut state,
                &[i as u8 + 1; 32],
                sk,
                &format!("rpc-{i}"),
                floor,
            )
            .await;
        }
        // An attestor without a bridge signer is never drawn.
        role_stake::bond_role_for_test(&mut state, &[9u8; 32], NetworkRole::Attestor, 10 * floor);
        // A bridge signer whose proof is another account's is refused.
        state.set_balance(&[8u8; 32], 2 * floor);
        let stolen_digest = tenzro_types::token::bridge_signer_digest(&[1u8; 32]);
        let (stolen_pq_key, stolen_pq_proof) = pq_leg(&keys[0], &stolen_digest);
        let stolen = StakeOp::Bond {
            role: NetworkRole::Attestor,
            amount: floor,
            capacity: StakeCapacity::BridgeSigner {
                address: address(&keys[0]),
                rpc_provider: "rpc-x".into(),
                proof: sign(&keys[0], &stolen_digest).to_vec(),
                pq_public_key: stolen_pq_key,
                pq_proof: stolen_pq_proof,
            },
        };
        assert!(
            run(
                &ex,
                &mut state,
                &[8u8; 32],
                role_stake::SELECTOR_STAKE,
                serde_json::to_vec(&stolen).unwrap(),
                T0
            )
            .await
            .is_err()
        );

        install(&mut state);
        assert!(
            draw_op(&ex, &mut state, T0 + 1).await.is_err(),
            "no beacon value since the route was installed"
        );
        super::super::beacon::record_for_test(&mut state, T0 + 10);
        draw_op(&ex, &mut state, T0 + 20).await.unwrap();

        let drawn = read_bridge_route(&state, BridgeRouteAdapter::Contract, "sui").unwrap();
        assert_eq!(drawn.verifiers.members.len(), 3);
        assert_eq!(drawn.verifiers.set_index, 1);
        drawn.validate().unwrap();
        assert!(
            drawn
                .verifiers
                .members
                .iter()
                .all(|m| m.operator != hex::encode([9u8; 32]))
        );
        let seat_account = hex::decode(&drawn.verifiers.members[0].operator).unwrap();
        assert!(seated(&state, &seat_account, T0 + 20));

        // A seated member stays bonded until its term ends; a redraw is not
        // due before then.
        let unbond = StakeOp::Unbond {
            role: NetworkRole::Attestor,
            amount: floor,
        };
        assert!(
            run(
                &ex,
                &mut state,
                &seat_account,
                role_stake::SELECTOR_STAKE,
                serde_json::to_vec(&unbond).unwrap(),
                T0 + 30
            )
            .await
            .is_err()
        );
        assert!(draw_op(&ex, &mut state, T0 + 40).await.is_err());
    }

    #[tokio::test]
    async fn an_equivocating_member_is_slashed_and_its_committee_redrawn() {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        let keys: Vec<SigningKey> = (1..=3).map(key).collect();
        for (i, sk) in keys.iter().enumerate() {
            bond(
                &ex,
                &mut state,
                &[i as u8 + 1; 32],
                sk,
                &format!("rpc-{i}"),
                floor,
            )
            .await;
        }
        install(&mut state);
        super::super::beacon::record_for_test(&mut state, T0 + 10);
        draw_op(&ex, &mut state, T0 + 20).await.unwrap();
        let drawn = read_bridge_route(&state, BridgeRouteAdapter::Contract, "sui").unwrap();
        let member = drawn.verifiers.members[0].clone();
        let sk = keys.iter().find(|k| address(k) == member.address).unwrap();
        let delivery = |body: &[u8], with_pq: bool| {
            let mut d = Delivery {
                dest_chain_id: 1337,
                nonce: 5,
                expiry_ms: T0 + 1_000_000,
                body: body.to_vec(),
                proof: Vec::new(),
                committee: Vec::new(),
                committee_pq: Vec::new(),
                blessing: Vec::new(),
                blessing_pq: Vec::new(),
            };
            let digest = attestation_digest(&drawn, &d);
            d.committee.push((member.address, sign(sk, &digest)));
            if with_pq {
                let k = tenzro_bridge::route::attestation::testing::pq_key(&sk.to_bytes());
                d.committee_pq
                    .push(tenzro_bridge::route::attestation::testing::sign_pq(
                        &k,
                        member.address,
                        &digest,
                    ));
            }
            d.encode()
        };
        // Secp256k1 signatures alone do not convict a member: a forger of
        // that leg could frame an honest one.
        let classical_only = tenzro_types::bridge_transfer::BridgeOp::ReportEquivocation {
            adapter: BridgeRouteAdapter::Contract,
            source_chain: "sui".into(),
            member: member.address.to_vec(),
            first: delivery(b"pay alice", false),
            second: delivery(b"pay mallory", false),
        };
        state.set_balance(&[0xEF; 32], 1);
        assert!(
            run(
                &ex,
                &mut state,
                &[0xEF; 32],
                super::super::bridge::SELECTOR_BRIDGE,
                serde_json::to_vec(&classical_only).unwrap(),
                T0 + 40,
            )
            .await
            .is_err()
        );
        let op = tenzro_types::bridge_transfer::BridgeOp::ReportEquivocation {
            adapter: BridgeRouteAdapter::Contract,
            source_chain: "sui".into(),
            member: member.address.to_vec(),
            first: delivery(b"pay alice", true),
            second: delivery(b"pay mallory", true),
        };
        state.set_balance(&[0xEF; 32], 1);
        run(
            &ex,
            &mut state,
            &[0xEF; 32],
            super::super::bridge::SELECTOR_BRIDGE,
            serde_json::to_vec(&op).unwrap(),
            T0 + 50,
        )
        .await
        .unwrap();
        let account = hex::decode(&member.operator).unwrap();
        let left = read_role_stake(&state, &account, NetworkRole::Attestor)
            .unwrap()
            .bonded;
        assert_eq!(
            left,
            floor - floor * DEFAULT_EQUIVOCATION_SLASH_BPS as u128 / 10_000
        );
        let broken = read_bridge_route(&state, BridgeRouteAdapter::Contract, "sui").unwrap();
        assert!(
            broken.verifiers.members.is_empty(),
            "no traffic until the committee is drawn again"
        );
        // Bridge contracts may trust the broken committee until it expires.
        assert!(seated(&state, &account, T0 + 50));
    }

    fn handover_op(
        signed_by_set: u32,
        set: &CommitteeSet,
        sk: &SigningKey,
    ) -> tenzro_types::bridge_transfer::BridgeOp {
        let digest = handover_digest(1337, &route(), set);
        tenzro_types::bridge_transfer::BridgeOp::ReportWrongHandover {
            adapter: BridgeRouteAdapter::Contract,
            source_chain: "sui".into(),
            signed_by_set,
            set_index: set.quorum.set_index,
            members: set.quorum.addresses().concat(),
            threshold: set.quorum.threshold,
            expires_at_secs: set.expires_at_secs,
            signature: sign(sk, &digest).to_vec(),
        }
    }

    #[tokio::test]
    async fn a_handover_to_a_committee_the_chain_did_not_draw_is_slashed() {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        let keys: Vec<SigningKey> = (1..=6).map(key).collect();
        for (i, sk) in keys.iter().enumerate() {
            bond(
                &ex,
                &mut state,
                &[i as u8 + 1; 32],
                sk,
                &format!("rpc-{i}"),
                floor,
            )
            .await;
        }
        install(&mut state);
        super::super::beacon::record_for_test(&mut state, T0 + 10);
        draw_op(&ex, &mut state, T0 + 20).await.unwrap();
        let key_of = |a: [u8; 20]| keys.iter().find(|k| address(k) == a).unwrap().clone();
        let route_key = route().storage_key();
        let first = read_committee_set(&state, &route_key, 1).unwrap();
        let term = DEFAULT_COMMITTEE_TERM_MS as i64;
        let window = DEFAULT_HANDOVER_WINDOW_MS as i64;
        assert_eq!(
            first.expires_at_secs,
            ((T0 + 20 + term + window) / 1000) as u64
        );
        let member = first.quorum.members[0].clone();
        let account = hex::decode(&member.operator).unwrap();
        assert!(
            seated(&state, &account, T0 + 20 + term),
            "members stay bonded past the term, until the expiry"
        );

        // Set 1 hands over to a committee of its own choosing under index 2.
        let forged = CommitteeSet {
            quorum: VerifierQuorum {
                set_index: 2,
                ..first.quorum.clone()
            },
            expires_at_secs: first.expires_at_secs + 1_000_000,
        };
        let report = |op: &tenzro_types::bridge_transfer::BridgeOp| serde_json::to_vec(op).unwrap();
        state.set_balance(&[0xEF; 32], 1);
        let forged_op = handover_op(1, &forged, &key_of(member.address));
        run(
            &ex,
            &mut state,
            &[0xEF; 32],
            super::super::bridge::SELECTOR_BRIDGE,
            report(&forged_op),
            T0 + 50,
        )
        .await
        .unwrap();
        let left = read_role_stake(&state, &account, NetworkRole::Attestor)
            .unwrap()
            .bonded;
        assert_eq!(
            left,
            floor - floor * DEFAULT_EQUIVOCATION_SLASH_BPS as u128 / 10_000
        );
        assert!(
            read_bridge_route(&state, BridgeRouteAdapter::Contract, "sui")
                .unwrap()
                .verifiers
                .members
                .is_empty()
        );
        assert!(
            run(
                &ex,
                &mut state,
                &[0xEF; 32],
                super::super::bridge::SELECTOR_BRIDGE,
                report(&forged_op),
                T0 + 60
            )
            .await
            .is_err(),
            "one signature is slashed once"
        );

        // The committee drawn next continues the index; handing over to it
        // exactly as drawn is no fault.
        super::super::beacon::record_for_test(&mut state, T0 + 70);
        draw_op(&ex, &mut state, T0 + 80).await.unwrap();
        let second = read_committee_set(&state, &route_key, 2).unwrap();
        assert_eq!(
            read_bridge_route(&state, BridgeRouteAdapter::Contract, "sui")
                .unwrap()
                .verifiers
                .set_index,
            2
        );
        let honest_signer = key_of(first.quorum.members[1].address);
        let honest = handover_op(1, &second, &honest_signer);
        assert!(
            run(
                &ex,
                &mut state,
                &[0xEF; 32],
                super::super::bridge::SELECTOR_BRIDGE,
                report(&honest),
                T0 + 90
            )
            .await
            .is_err()
        );
        // A handover back to an older index is a fault, even to a drawn set.
        let backwards = handover_op(2, &first, &key_of(second.quorum.members[0].address));
        run(
            &ex,
            &mut state,
            &[0xEF; 32],
            super::super::bridge::SELECTOR_BRIDGE,
            report(&backwards),
            T0 + 95,
        )
        .await
        .unwrap();

        // A route governance installs again continues the sequence.
        let mut again = route();
        carry_set_indexes(&state, &mut again);
        assert_eq!(again.verifiers.set_index, 2);
    }

    /// Stake bonded, or a signer declared, once the beacon value a draw
    /// uses is known is not drawn: nobody can pick seats by bonding against
    /// a known mix.
    #[tokio::test]
    async fn a_bond_made_after_the_draws_beacon_value_is_not_drawn() {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        let keys: Vec<SigningKey> = (1..=6).map(key).collect();
        for (i, sk) in keys.iter().take(3).enumerate() {
            bond(
                &ex,
                &mut state,
                &[i as u8 + 1; 32],
                sk,
                &format!("rpc-{i}"),
                floor,
            )
            .await;
        }
        install(&mut state);
        super::super::beacon::record_for_test(&mut state, T0 + 10);
        for (i, sk) in keys.iter().enumerate().skip(3) {
            bond_at(
                &ex,
                &mut state,
                &[i as u8 + 1; 32],
                sk,
                &format!("rpc-{i}"),
                1_000 * floor,
                T0 + 15,
            )
            .await;
        }
        draw_op(&ex, &mut state, T0 + 20).await.unwrap();
        let drawn = read_bridge_route(&state, BridgeRouteAdapter::Contract, "sui").unwrap();
        let late: Vec<String> = (4u8..=6).map(|i| hex::encode([i; 32])).collect();
        assert!(
            drawn
                .verifiers
                .members
                .iter()
                .all(|m| !late.contains(&m.operator)),
            "a bond made after the beacon value was seated"
        );
    }

    /// A member that sat on two successive committees and signed the
    /// handover from the first to the second, exactly as drawn, is not
    /// slashed when the report names the second as the committee it signed
    /// from.
    #[tokio::test]
    async fn an_honest_handover_by_a_member_of_both_committees_is_not_slashed() {
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let floor = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        let keys: Vec<SigningKey> = (1..=4).map(key).collect();
        for (i, sk) in keys.iter().enumerate() {
            bond(
                &ex,
                &mut state,
                &[i as u8 + 1; 32],
                sk,
                &format!("rpc-{i}"),
                floor,
            )
            .await;
        }
        install(&mut state);
        super::super::beacon::record_for_test(&mut state, T0 + 10);
        draw_op(&ex, &mut state, T0 + 20).await.unwrap();
        let term = DEFAULT_COMMITTEE_TERM_MS as i64;
        super::super::beacon::record_for_test(&mut state, T0 + 20 + term + 5);
        draw_op(&ex, &mut state, T0 + 20 + term + 10).await.unwrap();
        let route_key = route().storage_key();
        let first = read_committee_set(&state, &route_key, 1).unwrap();
        let second = read_committee_set(&state, &route_key, 2).unwrap();
        let both = first
            .quorum
            .members
            .iter()
            .find(|m| second.quorum.members.iter().any(|n| n.address == m.address))
            .expect("three of four attestors twice share a member")
            .clone();
        let sk = keys.iter().find(|k| address(k) == both.address).unwrap();
        let account = hex::decode(&both.operator).unwrap();
        state.set_balance(&[0xEF; 32], 1);
        for signed_by in [1u32, 2] {
            let op = handover_op(signed_by, &second, sk);
            assert!(
                run(
                    &ex,
                    &mut state,
                    &[0xEF; 32],
                    super::super::bridge::SELECTOR_BRIDGE,
                    serde_json::to_vec(&op).unwrap(),
                    T0 + 20 + term + 20,
                )
                .await
                .is_err(),
                "an honest handover was slashed (reported as signed by set {signed_by})"
            );
        }
        assert_eq!(
            read_role_stake(&state, &account, NetworkRole::Attestor)
                .unwrap()
                .bonded,
            floor
        );
    }
}
