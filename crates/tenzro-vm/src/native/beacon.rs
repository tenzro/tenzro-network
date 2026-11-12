//! The chain's randomness beacon, in consensus state.
//!
//! Bonded validators contribute verifiable random function outputs. Each
//! contribution proves, with the validator's registered VRF key, the VRF
//! output on the beacon's current round and mix; the mix becomes the hash of
//! the old mix and that output, and the round advances. A VRF output is
//! unique per key and input, so a contributor cannot choose its value, and
//! because the input is the current mix, no output can be computed before
//! the mix it extends exists. The most a contributor can do is withhold.
//!
//! Every value the beacon took is kept with the block time it was taken at,
//! so a draw names its value by time rather than by when it is executed:
//! [`first_at_or_after`] returns the first value taken at or after a moment,
//! which nobody can change by choosing when to submit the draw.
//!
//! The VRF is elliptic-curve: an attacker who recovers the registered VRF
//! secrets can compute every contribution in advance. Once governance
//! enables [`COMMIT_REVEAL_STATUS`], each contribution also commits to a
//! fresh 32-byte secret and reveals the one its previous contribution
//! committed to, and the mix takes the revealed secret beside the VRF
//! output. A secret is hidden behind a hash until it is revealed, so the
//! beacon stays unpredictable while that hash holds even when the VRF does
//! not; withholding stays the only lever, as before, and the bond bounds it.
//! The commitment and the reveal travel after the VRF proof in the
//! contribution's proof bytes, so a node that has not upgraded refuses them
//! rather than reading them differently, and none is sent before the lever
//! is enabled.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::vrf::{VrfProof, VrfPublicKey};

use super::funding::{read_json, refuse, write_json};
use super::staking::{bonded_stake_of, vrf_key_of};
use super::*;

/// Gas for one contribution.
pub const GAS_BEACON_CONTRIBUTE: u64 = 60_000;
/// Topic of the log a contribution emits.
pub const BEACON_TOPIC: &[u8] = b"BeaconContributed";
/// Shortest time between two contributions of one validator, ms.
pub const MIN_CONTRIBUTION_INTERVAL_MS: i64 = 60_000;

const ALPHA_DOMAIN: &[u8] = b"tenzro/beacon/alpha";
const MIX_DOMAIN: &[u8] = b"tenzro/beacon/mix";
const GENESIS_DOMAIN: &[u8] = b"tenzro/beacon/genesis";
const HEAD_KEY: &str = "beacon:head";
const REVEAL_DOMAIN: &[u8] = b"tenzro/beacon/reveal";
const COMMITMENT_DOMAIN: &[u8] = b"tenzro/beacon/commitment";

/// Governance lever of commit-reveal contributions. Paused at genesis.
pub const COMMIT_REVEAL_STATUS: &str = "beacon.commit_reveal.status";

/// The secret a validator committed to and has not revealed yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconCommitment {
    /// The commitment, hex.
    pub commitment: String,
    /// How many commitments the validator made before this one: the index
    /// its secret derives under.
    pub index: u64,
}

fn commitment_key(addr: &[u8]) -> String {
    format!("beacon:commitment:{}", hex::encode(addr))
}

/// The commitment of `addr` to `secret`.
pub fn commitment_to(addr: &[u8], secret: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(COMMITMENT_DOMAIN)
        .chain_update((addr.len() as u32).to_le_bytes())
        .chain_update(addr)
        .chain_update(secret)
        .finalize()
        .into()
}

/// The secret `addr` committed to and has not revealed, if any.
pub fn commitment_of(state: &dyn VmState, addr: &[u8]) -> Option<BeaconCommitment> {
    read_json(state, &commitment_key(addr))
}

/// Whether contributions commit and reveal secrets.
pub fn commit_reveal_enabled(state: &dyn VmState) -> bool {
    matches!(
        lever_status(state, COMMIT_REVEAL_STATUS),
        crate::governance::LeverStatus::Enabled
    )
}

/// The proof bytes of a contribution: the VRF proof, then the commitment to
/// the next secret and the secret the last commitment named, when
/// commit-reveal is enabled.
pub fn contribution_proof(
    vrf_proof: &[u8],
    commitment: Option<&[u8; 32]>,
    reveal: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut out = vrf_proof.to_vec();
    if let Some(c) = commitment {
        out.extend_from_slice(c);
        if let Some(r) = reveal {
            out.extend_from_slice(r);
        }
    }
    out
}

/// One value the beacon took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconEntry {
    /// Its round: the count of contributions before it.
    pub round: u64,
    /// The mix after it, hex.
    pub mix: String,
    /// Block time it was taken at, ms.
    pub at_ms: i64,
    /// The validator that contributed it, hex.
    pub contributor: String,
}

/// Where the beacon stands: the next round and the current mix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconHead {
    /// The round the next contribution takes.
    pub round: u64,
    /// The current mix, hex.
    pub mix: String,
}

/// What a contribution carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconContribution {
    /// The round it is for.
    pub round: u64,
    /// The VRF proof over [`alpha`] of that round and the mix before it, hex.
    pub proof: String,
}

fn entry_key(round: u64) -> String {
    format!("beacon:entry:{round:016x}")
}

fn last_key(addr: &[u8]) -> String {
    format!("beacon:last:{}", hex::encode(addr))
}

/// The mix before any contribution.
pub fn genesis_mix() -> [u8; 32] {
    Sha256::digest(GENESIS_DOMAIN).into()
}

/// The beacon's head.
pub fn read_head(state: &dyn VmState) -> BeaconHead {
    read_json(state, HEAD_KEY).unwrap_or_else(|| BeaconHead {
        round: 0,
        mix: hex::encode(genesis_mix()),
    })
}

/// The value the beacon took at `round`.
pub fn read_entry(state: &dyn VmState, round: u64) -> Option<BeaconEntry> {
    read_json(state, &entry_key(round))
}

/// The VRF input of a contribution to `round` extending `mix`.
pub fn alpha(round: u64, mix: &[u8; 32]) -> Vec<u8> {
    [ALPHA_DOMAIN, &round.to_be_bytes(), mix].concat()
}

fn mix_bytes(head: &BeaconHead) -> [u8; 32] {
    hex::decode(&head.mix)
        .ok()
        .and_then(|b| b.try_into().ok())
        .unwrap_or_else(genesis_mix)
}

/// The first value the beacon took at or after `at_ms`, if it has taken one.
pub fn first_at_or_after(state: &dyn VmState, at_ms: i64) -> Option<BeaconEntry> {
    let rounds = read_head(state).round;
    // Entries are appended in block order, so their times never decrease.
    let (mut lo, mut hi) = (0u64, rounds);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match read_entry(state, mid) {
            Some(e) if e.at_ms >= at_ms => hi = mid,
            _ => lo = mid + 1,
        }
    }
    (lo < rounds).then(|| read_entry(state, lo)).flatten()
}

/// When `addr` last contributed, block time ms.
pub fn last_contribution(state: &dyn VmState, addr: &[u8]) -> Option<i64> {
    read_json(state, &last_key(addr))
}

/// The mix of an entry as bytes.
pub fn entry_mix(entry: &BeaconEntry) -> Option<[u8; 32]> {
    hex::decode(&entry.mix).ok()?.try_into().ok()
}

/// Apply one bonded validator's contribution.
pub(super) fn contribute(
    state: &mut dyn VmState,
    from: &[u8],
    now_ms: i64,
    payload: &[u8],
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let c: BeaconContribution = serde_json::from_slice(payload)
        .map_err(|e| VmError::InvalidTransaction(format!("Invalid beacon contribution: {e}")))?;
    // A contributor holds at least a validator's stake: each account is
    // one output its owner may choose to submit, so cheap accounts would let
    // one party choose among many.
    let floor = super::role_stake::stake_ladder(state).validator;
    if bonded_stake_of(state, from) < floor.max(1) {
        return Err(refuse(format!(
            "only accounts with at least a validator's stake of {floor} contribute to the beacon"
        )));
    }
    let head = read_head(state);
    if c.round != head.round {
        return Err(refuse(format!(
            "the beacon is at round {}, not {}",
            head.round, c.round
        )));
    }
    if let Some(last) = read_json::<i64>(state, &last_key(from))
        && now_ms < last.saturating_add(MIN_CONTRIBUTION_INTERVAL_MS)
    {
        return Err(refuse(format!(
            "this validator contributed at {last}; the next contribution is due from {}",
            last.saturating_add(MIN_CONTRIBUTION_INTERVAL_MS)
        )));
    }
    let key = vrf_key_of(state, from)
        .ok_or_else(|| refuse("no VRF key is registered for this validator"))?;
    let bytes = hex::decode(&c.proof).map_err(|_| refuse("the proof is not hex"))?;
    let vrf_len = tenzro_crypto::vrf::PROOF_LEN;
    let (commitment, reveal): (Option<[u8; 32]>, Option<[u8; 32]>) =
        match (commit_reveal_enabled(state), bytes.len()) {
            (false, n) if n == vrf_len => (None, None),
            (false, _) => return Err(refuse("the proof is not a VRF proof")),
            (true, n) if n == vrf_len + 32 => (bytes[vrf_len..].try_into().ok(), None),
            (true, n) if n == vrf_len + 64 => (
                bytes[vrf_len..vrf_len + 32].try_into().ok(),
                bytes[vrf_len + 32..].try_into().ok(),
            ),
            (true, _) => {
                return Err(refuse(
                    "a contribution commits to its next secret after the VRF proof",
                ));
            }
        };
    let proof = VrfProof::from_bytes(&bytes[..vrf_len.min(bytes.len())])
        .map_err(|_| refuse("the proof is not a VRF proof"))?;
    let held = commitment_of(state, from);
    match (&held, &reveal) {
        (Some(h), Some(r)) if hex::encode(commitment_to(from, r)) == h.commitment => {}
        (Some(_), Some(_)) => {
            return Err(refuse(
                "the revealed secret is not the one this validator committed to",
            ));
        }
        (Some(_), None) => {
            return Err(refuse(
                "this validator must reveal the secret it committed to",
            ));
        }
        (None, Some(_)) => return Err(refuse("this validator committed to no secret")),
        (None, None) => {}
    }
    let mix = mix_bytes(&head);
    let output = tenzro_crypto::vrf::verify(&VrfPublicKey(key), &alpha(head.round, &mix), &proof)
        .map_err(|e| {
        refuse(format!(
            "the VRF proof does not verify under the registered VRF key: {e}"
        ))
    })?;
    let mut hasher = Sha256::new()
        .chain_update(MIX_DOMAIN)
        .chain_update(mix)
        .chain_update(output.as_bytes());
    if let Some(r) = &reveal {
        hasher = hasher.chain_update(REVEAL_DOMAIN).chain_update(r);
    }
    let next: [u8; 32] = hasher.finalize().into();
    let mut changes = Vec::new();
    if let Some(c) = commitment {
        let index = held.as_ref().map_or(0, |h| h.index + 1);
        write_json(
            state,
            &commitment_key(from),
            &BeaconCommitment {
                commitment: hex::encode(c),
                index,
            },
            &mut changes,
        )?;
    }
    let entry = BeaconEntry {
        round: head.round,
        mix: hex::encode(next),
        at_ms: now_ms,
        contributor: hex::encode(from),
    };
    write_json(state, &entry_key(head.round), &entry, &mut changes)?;
    write_json(
        state,
        HEAD_KEY,
        &BeaconHead {
            round: head.round + 1,
            mix: entry.mix.clone(),
        },
        &mut changes,
    )?;
    write_json(state, &last_key(from), &now_ms, &mut changes)?;
    let log = Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![BEACON_TOPIC.to_vec()],
        serde_json::to_vec(&entry)
            .map_err(|e| VmError::Internal(format!("encode beacon log: {e}")))?,
    );
    Ok((changes, vec![log]))
}

/// How much later each backup submitter waits than the one before it, ms.
pub const BACKUP_STEP_MS: i64 = 20_000;

/// Whether a contribution for `round` can no longer execute because the
/// beacon has moved on to `head_round`. A later round is not stale: the
/// beacon may yet reach it.
pub fn is_stale(head_round: u64, round: u64) -> bool {
    round < head_round
}

/// [`is_stale`] against the head stored in `state`.
pub fn is_stale_at(state: &dyn VmState, round: u64) -> bool {
    is_stale(read_head(state).round, round)
}

/// How long into the round `me` waits before submitting its contribution,
/// ms, or `None` when `me` is not among the `eligible` contributors.
///
/// The eligible accounts are ranked by a hash of the round, the mix and the
/// account, so the order changes every round and no account can pick its
/// place. The first submits at once and each later one a [`BACKUP_STEP_MS`]
/// after the one before, so one contribution goes in per round and the rest
/// only when the ones ahead have not.
pub fn submission_delay_ms(
    round: u64,
    mix: &[u8; 32],
    me: &[u8],
    eligible: &[Vec<u8>],
) -> Option<i64> {
    let rank_of = |who: &[u8]| -> [u8; 32] {
        Sha256::new()
            .chain_update(b"tenzro/beacon/submitter/v1")
            .chain_update(round.to_be_bytes())
            .chain_update(mix)
            .chain_update(who)
            .finalize()
            .into()
    };
    if !eligible.iter().any(|a| a.as_slice() == me) {
        return None;
    }
    let mine = rank_of(me);
    let ahead = eligible
        .iter()
        .filter(|a| a.as_slice() != me && rank_of(a) < mine)
        .count();
    Some(ahead as i64 * BACKUP_STEP_MS)
}

/// Record a beacon value taken at `at_ms` with no contribution, for tests of
/// what draws from the beacon.
#[cfg(test)]
pub(crate) fn record_for_test(state: &mut dyn VmState, at_ms: i64) {
    let head = read_head(state);
    let next: [u8; 32] = Sha256::new()
        .chain_update(MIX_DOMAIN)
        .chain_update(mix_bytes(&head))
        .finalize()
        .into();
    let entry = BeaconEntry {
        round: head.round,
        mix: hex::encode(next),
        at_ms,
        contributor: String::new(),
    };
    let mut changes = Vec::new();
    write_json(state, &entry_key(head.round), &entry, &mut changes).unwrap();
    write_json(
        state,
        HEAD_KEY,
        &BeaconHead {
            round: head.round + 1,
            mix: entry.mix,
        },
        &mut changes,
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;
    use tenzro_crypto::vrf::{VrfProver, VrfSecretKey};

    fn validator(state: &mut StateAdapter, who: [u8; 32], sk: &VrfSecretKey) {
        let floor = super::super::role_stake::stake_ladder(state).validator;
        super::super::staking::add_bond(state, &who, floor, 0).unwrap();
        super::super::staking::index_vrf_key(state, &who, &sk.public_key().0);
    }

    fn contribution(state: &StateAdapter, sk: &VrfSecretKey) -> Vec<u8> {
        let head = read_head(state);
        let proof = sk.prove(&alpha(head.round, &mix_bytes(&head))).unwrap();
        serde_json::to_vec(&BeaconContribution {
            round: head.round,
            proof: hex::encode(proof.as_bytes()),
        })
        .unwrap()
    }

    #[test]
    fn contributions_advance_the_mix_and_are_found_by_time() {
        let mut state = StateAdapter::new();
        let (a, b) = (VrfSecretKey([1; 32]), VrfSecretKey([2; 32]));
        validator(&mut state, [0xA; 32], &a);
        validator(&mut state, [0xB; 32], &b);
        let start = read_head(&state).mix.clone();
        let p = contribution(&state, &a);
        contribute(&mut state, &[0xA; 32], 1_000, &p).unwrap();
        let p = contribution(&state, &b);
        contribute(&mut state, &[0xB; 32], 5_000, &p).unwrap();
        let head = read_head(&state);
        assert_eq!(head.round, 2);
        assert_ne!(head.mix, start);
        assert_eq!(first_at_or_after(&state, 0).unwrap().round, 0);
        assert_eq!(first_at_or_after(&state, 1_001).unwrap().round, 1);
        assert_eq!(first_at_or_after(&state, 5_000).unwrap().mix, head.mix);
        assert!(
            first_at_or_after(&state, 5_001).is_none(),
            "no value taken yet"
        );
    }

    #[test]
    fn a_contribution_must_be_the_validators_own_unique_output() {
        let mut state = StateAdapter::new();
        let (a, b) = (VrfSecretKey([1; 32]), VrfSecretKey([2; 32]));
        validator(&mut state, [0xA; 32], &a);
        // A proof under another key is refused.
        let forged = contribution(&state, &b);
        assert!(contribute(&mut state, &[0xA; 32], 1_000, &forged).is_err());
        // An account without stake is refused.
        let p = contribution(&state, &a);
        assert!(contribute(&mut state, &[0xC; 32], 1_000, &p).is_err());
        // A stale round is refused.
        contribute(&mut state, &[0xA; 32], 1_000, &p).unwrap();
        assert!(contribute(&mut state, &[0xA; 32], 100_000, &p).is_err());
        // Contributing again too soon is refused.
        let again = contribution(&state, &a);
        assert!(contribute(&mut state, &[0xA; 32], 2_000, &again).is_err());
        contribute(&mut state, &[0xA; 32], 61_000, &again).unwrap();
    }

    /// Once governance enables commit-reveal, each contribution commits to a
    /// secret bound to its validator and reveals the last one, and the mix
    /// takes the revealed secret: a contribution without its commitment, one
    /// that withholds or alters the reveal, or one revealing another
    /// validator's secret is refused. Before that, the extra bytes are
    /// refused, as a node that has not upgraded refuses them.
    #[test]
    fn commit_reveal_mixes_a_committed_secret_once_governance_enables_it() {
        let mut state = StateAdapter::new();
        let (a, b) = (VrfSecretKey([1; 32]), VrfSecretKey([2; 32]));
        let (wa, wb) = ([0xA; 32], [0xB; 32]);
        validator(&mut state, wa, &a);
        validator(&mut state, wb, &b);
        let s = |n: u8| [n; 32];
        let with = |state: &StateAdapter,
                    sk: &VrfSecretKey,
                    c: Option<[u8; 32]>,
                    r: Option<[u8; 32]>| {
            let head = read_head(state);
            let proof = sk.prove(&alpha(head.round, &mix_bytes(&head))).unwrap();
            serde_json::to_vec(&BeaconContribution {
                round: head.round,
                proof: hex::encode(contribution_proof(proof.as_bytes(), c.as_ref(), r.as_ref())),
            })
            .unwrap()
        };

        let early = with(&state, &a, Some(commitment_to(&wa, &s(1))), None);
        assert!(contribute(&mut state, &wa, 1_000, &early).is_err());
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(COMMIT_REVEAL_STATUS).as_bytes(),
            0u64.to_le_bytes().to_vec(),
        );
        assert!(commit_reveal_enabled(&state));
        let plain = contribution(&state, &a);
        assert!(contribute(&mut state, &wa, 1_000, &plain).is_err());

        let first = with(&state, &a, Some(commitment_to(&wa, &s(1))), None);
        contribute(&mut state, &wa, 1_000, &first).unwrap();
        assert_eq!(commitment_of(&state, &wa).unwrap().index, 0);
        let first_b = with(&state, &b, Some(commitment_to(&wb, &s(9))), None);
        contribute(&mut state, &wb, 1_000, &first_b).unwrap();

        let t = 70_000;
        let withheld = with(&state, &a, Some(commitment_to(&wa, &s(2))), None);
        assert!(contribute(&mut state, &wa, t, &withheld).is_err());
        let altered = with(&state, &a, Some(commitment_to(&wa, &s(2))), Some(s(3)));
        assert!(contribute(&mut state, &wa, t, &altered).is_err());
        let borrowed = with(&state, &a, Some(commitment_to(&wa, &s(2))), Some(s(9)));
        assert!(contribute(&mut state, &wa, t, &borrowed).is_err());
        let no_commitment = with(&state, &a, None, None);
        assert!(contribute(&mut state, &wa, t, &no_commitment).is_err());

        let head = read_head(&state);
        let output = tenzro_crypto::vrf::verify(
            &a.public_key(),
            &alpha(head.round, &mix_bytes(&head)),
            &a.prove(&alpha(head.round, &mix_bytes(&head))).unwrap(),
        )
        .unwrap();
        let revealed = with(&state, &a, Some(commitment_to(&wa, &s(2))), Some(s(1)));
        contribute(&mut state, &wa, t, &revealed).unwrap();
        let expected: [u8; 32] = Sha256::new()
            .chain_update(MIX_DOMAIN)
            .chain_update(mix_bytes(&head))
            .chain_update(output.as_bytes())
            .chain_update(REVEAL_DOMAIN)
            .chain_update(s(1))
            .finalize()
            .into();
        assert_eq!(read_head(&state).mix, hex::encode(expected));
        assert_eq!(commitment_of(&state, &wa).unwrap().index, 1);
    }

    /// An account with less than a validator's stake does not contribute:
    /// cheap accounts would let one party choose among many outputs.
    #[test]
    fn a_contribution_needs_a_validators_stake() {
        let mut state = StateAdapter::new();
        let a = VrfSecretKey([1; 32]);
        super::super::staking::add_bond(&mut state, &[0xA; 32], 1, 0).unwrap();
        super::super::staking::index_vrf_key(&mut state, &[0xA; 32], &a.public_key().0);
        let p = contribution(&state, &a);
        assert!(contribute(&mut state, &[0xA; 32], 1_000, &p).is_err());
    }

    #[test]
    fn only_rounds_behind_the_head_are_stale() {
        assert!(is_stale(5, 4));
        assert!(!is_stale(5, 5));
        assert!(!is_stale(5, 6));
    }

    #[test]
    fn one_submitter_goes_first_and_the_rest_back_it_up_in_turn() {
        let eligible: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 32]).collect();
        let mix = genesis_mix();
        let mut delays: Vec<i64> = eligible
            .iter()
            .map(|a| submission_delay_ms(7, &mix, a, &eligible).unwrap())
            .collect();
        delays.sort();
        assert_eq!(delays, vec![0, 20_000, 40_000, 60_000, 80_000]);
        assert_eq!(submission_delay_ms(7, &mix, &[9; 32], &eligible), None);
    }

    #[test]
    fn the_order_of_submitters_changes_with_the_round() {
        let eligible: Vec<Vec<u8>> = (0u8..8).map(|i| vec![i; 32]).collect();
        let mix = genesis_mix();
        let first = |round: u64| {
            eligible
                .iter()
                .position(|a| submission_delay_ms(round, &mix, a, &eligible) == Some(0))
        };
        let firsts: std::collections::HashSet<_> = (0..32).map(first).collect();
        assert!(firsts.len() > 1);
    }

    #[test]
    fn a_round_behind_the_stored_head_is_stale() {
        let mut state = StateAdapter::new();
        record_for_test(&mut state, 1);
        record_for_test(&mut state, 2);
        assert_eq!(read_head(&state).round, 2);
        assert!(is_stale_at(&state, 1));
        assert!(!is_stale_at(&state, 2));
        assert!(!is_stale_at(&state, 3));
    }
}
