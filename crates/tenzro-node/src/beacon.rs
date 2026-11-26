//! This validator's contributions to the chain's randomness beacon, and the
//! beacon's read surface.
//!
//! A bonded validator proves, with the VRF over its hardware-derived node
//! key, the output on the beacon's current round and mix, and submits it as
//! a `BeaconContribute` transaction (see `tenzro_vm::native::beacon`). The
//! key is derived per proof and never leaves the derivation.
//!
//! Once governance enables commit-reveal, each contribution also commits to
//! the validator's next beacon secret and reveals the last one. The secrets
//! derive from the hardware root under [`BEACON_SECRET_LABEL`] and the
//! commitment's index on chain, so nothing is stored and a restart reveals
//! the same secret it committed to.
//!
//! - `tenzro_getBeacon { round?, at_ms? }`: the head (round and mix), or the
//!   value taken at `round`, or the first value taken at or after `at_ms`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tenzro_crypto::vrf::VrfProver;
use tenzro_vm::native::beacon::{
    BACKUP_STEP_MS, BeaconEntry, MIN_CONTRIBUTION_INTERVAL_MS, alpha, first_at_or_after,
    hold_ends_at, read_entry, read_head, submission_delay_ms,
};
use tracing::{debug, info};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// How often a validator considers contributing.
const TICK: Duration = Duration::from_secs(30);

/// Derivation label of the beacon secrets.
pub const BEACON_SECRET_LABEL: &str = "tenzro/beacon/secret";

const SECRET_DOMAIN: &[u8] = b"tenzro/beacon/secret/v1";

/// The beacon secret of commitment `index`, from the root's secret `base`.
pub fn beacon_secret(base: &[u8; 32], index: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::new()
        .chain_update(SECRET_DOMAIN)
        .chain_update(base)
        .chain_update(index.to_be_bytes())
        .finalize()
        .into()
}

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn entry_json(e: &BeaconEntry) -> Value {
    json!({ "round": e.round, "mix": e.mix, "at_ms": e.at_ms, "contributor": e.contributor })
}

/// `tenzro_getBeacon`.
pub(crate) async fn handle_get_beacon(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let chain = crate::rpc::chain_state(node)?;
    if let Some(round) = params.get("round").and_then(Value::as_u64) {
        let e = read_entry(&chain, round)
            .ok_or_else(|| err(-32004, format!("the beacon has not taken round {round}")))?;
        return Ok(entry_json(&e));
    }
    if let Some(at) = params.get("at_ms").and_then(Value::as_i64) {
        let e = first_at_or_after(&chain, at)
            .ok_or_else(|| err(-32004, format!("the beacon has taken no value since {at}")))?;
        return Ok(entry_json(&e));
    }
    let head = read_head(&chain);
    let latest = head
        .round
        .checked_sub(1)
        .and_then(|r| read_entry(&chain, r));
    Ok(json!({ "round": head.round, "mix": head.mix, "latest": latest.as_ref().map(entry_json) }))
}

/// Whether `tx` is a beacon contribution for a round the beacon has already
/// left behind: one that can only revert when it executes.
pub(crate) fn is_stale_contribution(
    chain: &dyn tenzro_vm::VmState,
    tx: &tenzro_types::TransactionType,
) -> bool {
    match tx {
        tenzro_types::TransactionType::BeaconContribute { round, .. } => {
            tenzro_vm::native::beacon::is_stale_at(chain, *round)
        }
        _ => false,
    }
}

/// The accounts that may contribute now: active validators with a validator's
/// bond, a registered VRF key and no contribution in the last two intervals.
fn eligible_contributors(
    node: &Arc<TenzroNode>,
    chain: &tenzro_vm::StateAdapter,
    now: i64,
) -> Vec<Vec<u8>> {
    let Some(consensus) = node.consensus() else {
        return Vec::new();
    };
    let floor = tenzro_vm::native::stake_ladder(chain).validator.max(1);
    consensus
        .validator_set()
        .active_validators()
        .iter()
        .map(|v| v.address.as_bytes().to_vec())
        .filter(|a| {
            tenzro_vm::native::bonded_stake_of(chain, a) >= floor
                && tenzro_vm::native::vrf_key_of(chain, a).is_some()
                && rested(tenzro_vm::native::beacon::last_contribution(chain, a), now)
        })
        .collect()
}

/// What the last scan for traffic found and what it read it under. A scan reads
/// blocks, and an idle chain's tip stands still between ticks, so a tick under
/// the same round and tip takes the answer again; one that found traffic
/// keeps it for the round, as the blocks before it never change.
#[derive(Default)]
struct TrafficCache {
    read: Option<(i64, i64, u64, Option<i64>)>,
}

impl TrafficCache {
    /// The earlier answer for a scan from `after_ms` to `until_ms` with the
    /// chain at `tip`, when it still holds.
    fn reuse(&self, after_ms: i64, until_ms: i64, tip: u64) -> Option<Option<i64>> {
        let (after, until, at_tip, found) = self.read?;
        (after == after_ms && until == until_ms && (found.is_some() || at_tip == tip))
            .then_some(found)
    }
}

/// [`first_traffic_after`], reading no block when `cache` answers for the
/// round and the tip.
async fn first_traffic_cached(
    blocks: &impl tenzro_storage::traits::BlockStore,
    cache: &mut TrafficCache,
    after_ms: i64,
    until_ms: i64,
) -> Option<i64> {
    let tip = blocks.latest_height().await.ok()??.0;
    if let Some(found) = cache.reuse(after_ms, until_ms, tip) {
        return found;
    }
    let found = first_traffic_after(blocks, after_ms, until_ms).await;
    cache.read = Some((after_ms, until_ms, tip, found));
    found
}

/// Whether a validator whose last contribution was at `last` may send
/// another at `now`: two intervals after its last, so the next goes to
/// another validator first.
fn rested(last: Option<i64>, now: i64) -> bool {
    last.is_none_or(|last| now >= last.saturating_add(MIN_CONTRIBUTION_INTERVAL_MS * 2))
}

/// The most blocks [`first_traffic_after`] reads.
const TRAFFIC_SCAN_BLOCKS: u64 = 256;

/// The time of the first block later than `after_ms`, and no later than
/// `until_ms`, that holds a transaction other than the validators' own upkeep.
/// The blocks are read forward from the first one after `after_ms`, found by
/// its time, so every validator reads the same blocks; at most
/// [`TRAFFIC_SCAN_BLOCKS`] of them. `None` when none is found, a block cannot
/// be read, or the scan reaches its bound: the hold then runs to `until_ms`.
///
/// The rule is read from this node's own store and applied only to when this
/// node sends: a validator whose store reads differently sends earlier or
/// later, and the chain takes a contribution on its own rules whenever it
/// arrives.
async fn first_traffic_after(
    blocks: &impl tenzro_storage::traits::BlockStore,
    after_ms: i64,
    until_ms: i64,
) -> Option<i64> {
    use tenzro_types::primitives::BlockHeight;
    let tip = blocks.latest_height().await.ok()??.0;
    let later = |block: Option<tenzro_types::block::Block>| {
        block.is_some_and(|b| b.header.timestamp.as_millis() > after_ms)
    };
    let (mut lo, mut hi) = (0, tip.saturating_add(1));
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if later(blocks.get_block_by_height(BlockHeight(mid)).await.ok()?) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    let last = tip.min(lo.saturating_add(TRAFFIC_SCAN_BLOCKS - 1));
    for height in lo..=last {
        let block = blocks
            .get_block_by_height(BlockHeight(height))
            .await
            .ok()??;
        let at = block.header.timestamp.as_millis();
        if at > until_ms {
            return None;
        }
        if block
            .transactions
            .iter()
            .any(|t| !crate::checkpoint_recorder::is_upkeep(&t.transaction.tx_type))
        {
            return Some(at);
        }
    }
    None
}

/// When this round's turns begin, or `None` while the contribution is held.
/// Without the idle rule (`live` false) they begin when the beacon's latest
/// value was taken (`latest_ms`). Under it they begin where the hold ended
/// ([`hold_ends_at`]), so after a hold longer than every backup's wait the
/// validators still contribute one after another and not all at once, which
/// would let the block's orderer choose among their outputs.
fn turns_begin(
    live: bool,
    latest_ms: i64,
    idle_interval_ms: i64,
    first_traffic_ms: Option<i64>,
    now_ms: i64,
) -> Option<i64> {
    if live {
        hold_ends_at(latest_ms, idle_interval_ms, first_traffic_ms, now_ms)
    } else {
        Some(latest_ms)
    }
}

/// Submit one contribution when this node is a bonded validator, its
/// last one is old enough, and it is this node's turn in the round.
///
/// One validator is first in line for each round and the others back it up
/// in turn, each [`BACKUP_STEP_MS`] later than the one before. A node does
/// not send for a round it already sent for, nor when the head moved on
/// while its proof was being made. `sent` holds the round it last sent for.
async fn contribute_once(
    node: &Arc<TenzroNode>,
    sent: &mut Option<u64>,
    traffic: &mut TrafficCache,
) -> Result<bool, String> {
    let Some(submitter) = node.ledger_submitter() else {
        return Ok(false);
    };
    let account = submitter.address();
    let chain = crate::rpc::chain_state_of(node).ok_or("no chain state")?;
    if tenzro_vm::native::bonded_stake_of(&chain, account.as_bytes())
        < tenzro_vm::native::stake_ladder(&chain).validator.max(1)
    {
        return Ok(false);
    }
    if tenzro_vm::native::vrf_key_of(&chain, account.as_bytes()).is_none() {
        return Ok(false);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    if !rested(
        tenzro_vm::native::beacon::last_contribution(&chain, account.as_bytes()),
        now,
    ) {
        return Ok(false);
    }
    let head = read_head(&chain);
    if *sent == Some(head.round) {
        return Ok(false);
    }
    let mix: [u8; 32] = hex::decode(&head.mix)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("the beacon mix is malformed")?;
    let eligible = eligible_contributors(node, &chain, now);
    let delay = submission_delay_ms(head.round, &mix, account.as_bytes(), &eligible)
        .unwrap_or(eligible.len() as i64 * BACKUP_STEP_MS);
    let round_began = head
        .round
        .checked_sub(1)
        .and_then(|r| read_entry(&chain, r))
        .map_or(0, |e| e.at_ms);
    // While nobody uses the chain the beacon advances once per idle interval:
    // every contribution is an ordered transaction, so an idle chain would
    // otherwise make a block a minute for it alone. The interval bounds the
    // scan for traffic, which runs only under the rule.
    let live = tenzro_vm::native::beacon::idle_rule_live(&chain);
    let idle_interval = tenzro_vm::native::beacon::idle_interval_ms(&chain);
    let first_traffic = match node
        .storage()
        .filter(|_| live)
        .and_then(|s| tenzro_storage::BlockStoreImpl::new(s.clone()).ok())
    {
        Some(blocks) => {
            first_traffic_cached(
                &blocks,
                traffic,
                round_began,
                round_began.saturating_add(idle_interval),
            )
            .await
        }
        None => None,
    };
    let Some(turns_from) = turns_begin(live, round_began, idle_interval, first_traffic, now) else {
        return Ok(false);
    };
    if now < turns_from.saturating_add(delay) {
        return Ok(false);
    }
    let data_dir = node.config().data_dir.clone();
    let round = head.round;
    let commit = tenzro_vm::native::beacon::commit_reveal_enabled(&chain)
        .then(|| tenzro_vm::native::beacon::commitment_of(&chain, account.as_bytes()));
    let who = account.as_bytes().to_vec();
    let proof = tokio::task::spawn_blocking(move || {
        let prover = crate::keygen::NodeKeys::open(&data_dir)
            .map_err(|e| e.to_string())?
            .vrf_prover()
            .map_err(|e| e.to_string())?;
        let vrf = prover
            .prove(&alpha(round, &mix))
            .map_err(|e| e.to_string())?;
        let Some(held) = commit else {
            return Ok::<_, String>(vrf.as_bytes().to_vec());
        };
        let base = tenzro_device_key::DerivationRoot::open_or_create()
            .and_then(|root| root.endpoint_secret(BEACON_SECRET_LABEL))
            .map_err(|e| format!("beacon secret: {e}"))?;
        let next = held.as_ref().map_or(0, |h| h.index + 1);
        let reveal = held.map(|h| beacon_secret(&base, h.index));
        let commitment =
            tenzro_vm::native::beacon::commitment_to(&who, &beacon_secret(&base, next));
        Ok(tenzro_vm::native::beacon::contribution_proof(
            vrf.as_bytes(),
            Some(&commitment),
            reveal.as_ref(),
        ))
    })
    .await
    .map_err(|e| e.to_string())??;
    // Proving takes a moment; a block may have taken the round meanwhile.
    let chain = crate::rpc::chain_state_of(node).ok_or("no chain state")?;
    if tenzro_vm::native::beacon::is_stale_at(&chain, round) {
        return Ok(false);
    }
    let tx = tenzro_types::TransactionType::BeaconContribute { round, proof };
    crate::rpc::submit_as_validator(node, tx, tenzro_vm::native::beacon::GAS_BEACON_CONTRIBUTE)
        .await
        .map_err(|e| e.message)?;
    *sent = Some(round);
    Ok(true)
}

/// Contribute to the beacon while this node is a bonded validator.
pub fn spawn_contributor(node: Arc<TenzroNode>) {
    tokio::spawn(async move {
        let mut sent = None;
        let mut traffic = TrafficCache::default();
        loop {
            match contribute_once(&node, &mut sent, &mut traffic).await {
                Ok(true) => info!(target: "beacon", "contributed to the randomness beacon"),
                Ok(false) => {}
                Err(e) => debug!(target: "beacon", error = %e, "no beacon contribution this round"),
            }
            tokio::time::sleep(TICK).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::TransactionType;

    /// A store holding one block per entry of `chain`, heights from 1, each
    /// stamped with its entry's time and holding its entry's transactions.
    async fn block_store(
        dir: &std::path::Path,
        chain: &[(i64, Vec<TransactionType>)],
    ) -> tenzro_storage::BlockStoreImpl<tenzro_storage::RocksDbStore> {
        use tenzro_storage::traits::BlockStore as _;
        use tenzro_types::block::{Block, BlockHeader};
        use tenzro_types::primitives::{Address, BlockHeight, ChainId, Hash, Nonce, Timestamp};
        use tenzro_types::transaction::{SignedTransaction, Transaction};

        let store = Arc::new(tenzro_storage::RocksDbStore::open_default(dir).unwrap());
        let mut blocks = tenzro_storage::BlockStoreImpl::new(store).unwrap();
        let mut prev = Hash::new([1u8; 32]);
        for (i, (at_ms, types)) in chain.iter().enumerate() {
            let mut header = BlockHeader::new(
                BlockHeight(i as u64 + 1),
                prev,
                Hash::zero(),
                Hash::zero(),
                Address::new([2u8; 32]),
            );
            header.timestamp = Timestamp::new(*at_ms);
            let transactions = types
                .iter()
                .enumerate()
                .map(|(n, tx_type)| {
                    SignedTransaction::external(Transaction::new(
                        ChainId::from(1),
                        Address::new([3u8; 32]),
                        Address::default(),
                        Nonce::from(n as u64),
                        tx_type.clone(),
                        21_000,
                        1,
                    ))
                })
                .collect();
            let block = Block::new(header, transactions);
            prev = block.hash();
            blocks.put_block(&block).await.unwrap();
        }
        blocks
    }

    fn contribution(round: u64) -> TransactionType {
        TransactionType::BeaconContribute {
            round,
            proof: Vec::new(),
        }
    }

    /// Traffic is the first block after the latest value holding something
    /// other than upkeep; a block at or before the value, or after the end of
    /// the hold, does not count.
    #[tokio::test]
    async fn traffic_is_the_first_non_upkeep_block_after_the_latest_value() {
        let since = 1_000;
        let idle = tempfile::tempdir().unwrap();
        let blocks = block_store(
            idle.path(),
            &[
                (since, vec![contribution(0)]),
                (since + 500, vec![]),
                (since + 900, vec![contribution(1)]),
            ],
        )
        .await;
        assert_eq!(
            first_traffic_after(&blocks, since, since + 10_000).await,
            None
        );

        let used = tempfile::tempdir().unwrap();
        let blocks = block_store(
            used.path(),
            &[
                (since - 10, vec![TransactionType::Transfer { amount: 1 }]),
                (since, vec![contribution(0)]),
                (since + 500, vec![contribution(1)]),
                (since + 700, vec![TransactionType::Transfer { amount: 1 }]),
                (since + 900, vec![TransactionType::Transfer { amount: 1 }]),
            ],
        )
        .await;
        assert_eq!(
            first_traffic_after(&blocks, since, since + 10_000).await,
            Some(since + 700)
        );
        // After the end of the hold traffic changes nothing.
        assert_eq!(first_traffic_after(&blocks, since, since + 600).await, None);
    }

    /// The scan reads at most its bound of blocks forward from the latest
    /// value, the same blocks on every validator: traffic past the bound is
    /// not seen, and the hold runs to its end.
    #[tokio::test]
    async fn the_scan_reads_a_bounded_run_forward_from_the_latest_value() {
        let since = 1_000;
        let chain = |upkeep: u64| -> Vec<(i64, Vec<TransactionType>)> {
            std::iter::once((since, vec![contribution(0)]))
                .chain((1..=upkeep).map(|i| (since + i as i64, vec![contribution(i)])))
                .chain(std::iter::once((
                    since + upkeep as i64 + 1,
                    vec![TransactionType::Transfer { amount: 1 }],
                )))
                .collect()
        };
        let within = tempfile::tempdir().unwrap();
        let blocks = block_store(within.path(), &chain(TRAFFIC_SCAN_BLOCKS - 1)).await;
        assert_eq!(
            first_traffic_after(&blocks, since, i64::MAX).await,
            Some(since + TRAFFIC_SCAN_BLOCKS as i64)
        );
        let beyond = tempfile::tempdir().unwrap();
        let blocks = block_store(beyond.path(), &chain(TRAFFIC_SCAN_BLOCKS)).await;
        assert_eq!(first_traffic_after(&blocks, since, i64::MAX).await, None);
    }

    /// After a hold longer than every backup's wait, the turns begin where
    /// the hold ended: the first in line may send, the first backup not yet.
    /// Dormant, they begin at the latest value as before.
    #[test]
    fn a_lifted_hold_restarts_the_turns_where_it_ended() {
        let (latest, interval) = (0, 1_800_000);
        let now = interval + 1;
        let from = turns_begin(true, latest, interval, None, now).unwrap();
        assert_eq!(from, interval);
        let due = |delay: i64| now >= from + delay;
        assert!(due(0));
        assert!(!due(BACKUP_STEP_MS));
        // Counted from the latest value, every backup's turn would have passed.
        assert!(now >= latest + 3 * BACKUP_STEP_MS);

        assert_eq!(turns_begin(true, latest, interval, None, 5_000), None);
        assert_eq!(
            turns_begin(true, latest, interval, Some(7_000), 8_000),
            Some(7_000)
        );
        assert_eq!(
            turns_begin(false, latest, interval, None, 5_000),
            Some(latest)
        );
    }

    #[test]
    fn other_transactions_are_never_stale() {
        let state = tenzro_vm::StateAdapter::new();
        assert!(!is_stale_contribution(
            &state,
            &TransactionType::Transfer { amount: 1 }
        ));
    }

    #[test]
    fn a_contribution_for_the_head_round_is_not_stale() {
        let state = tenzro_vm::StateAdapter::new();
        let tx = TransactionType::BeaconContribute {
            round: 0,
            proof: Vec::new(),
        };
        assert!(!is_stale_contribution(&state, &tx));
    }

    /// A scan is read again only when the chain moved on, unless it found
    /// traffic, which stays found for the round.
    #[test]
    fn a_scan_is_read_again_only_when_the_tip_moves_or_the_round_does() {
        let mut cache = TrafficCache::default();
        assert_eq!(cache.reuse(100, 700, 9), None, "nothing read yet");
        cache.read = Some((100, 700, 9, None));
        assert_eq!(cache.reuse(100, 700, 9), Some(None), "same tip");
        assert_eq!(cache.reuse(100, 700, 10), None, "the tip moved");
        assert_eq!(cache.reuse(200, 800, 9), None, "another round");
        cache.read = Some((100, 700, 9, Some(450)));
        assert_eq!(
            cache.reuse(100, 700, 12),
            Some(Some(450)),
            "traffic stays found"
        );
    }

    /// A day of an idle chain, time-compressed: four validators each look
    /// every [`TICK`] at their own phase, send when rested and due by the
    /// round's turns, and each contribution the chain accepts is a block of
    /// its own. Under the idle rule the day holds fewer than 100 blocks and
    /// the beacon is never older than an idle interval and every turn;
    /// dormant it holds a block every minute or more.
    #[test]
    fn an_idle_chain_makes_fewer_than_100_beacon_blocks_a_day() {
        use sha2::{Digest, Sha256};
        const DAY: i64 = 86_400_000;
        const STEP: i64 = 1_000;
        let interval = 1_800_000;
        let validators: Vec<Vec<u8>> = (1..=4u8).map(|i| vec![i; 20]).collect();
        let tick = TICK.as_millis() as i64;
        let day = |live: bool| {
            let mut round = 0u64;
            let mut mix = tenzro_vm::native::beacon::genesis_mix();
            let mut latest = 0i64;
            let mut last: Vec<Option<i64>> = vec![None; validators.len()];
            let mut sent: Vec<Option<u64>> = vec![None; validators.len()];
            let (mut blocks, mut oldest) = (0u32, 0i64);
            let mut now = 0;
            while now < DAY {
                for (i, me) in validators.iter().enumerate() {
                    // Each validator looks on its own phase of the tick.
                    if (now - i as i64 * 7_000).rem_euclid(tick) != 0
                        || !rested(last[i], now)
                        || sent[i] == Some(round)
                    {
                        continue;
                    }
                    let eligible: Vec<Vec<u8>> = validators
                        .iter()
                        .zip(&last)
                        .filter(|(_, l)| rested(**l, now))
                        .map(|(v, _)| v.clone())
                        .collect();
                    let delay = submission_delay_ms(round, &mix, me, &eligible).unwrap();
                    let Some(from) = turns_begin(live, latest, interval, None, now) else {
                        continue;
                    };
                    if now < from + delay {
                        continue;
                    }
                    // The chain refuses one inside the interval; the round moved
                    // on otherwise.
                    if last[i].is_some_and(|l| now < l + MIN_CONTRIBUTION_INTERVAL_MS) {
                        continue;
                    }
                    sent[i] = Some(round);
                    oldest = oldest.max(now - latest);
                    blocks += 1;
                    round += 1;
                    latest = now;
                    last[i] = Some(now);
                    mix = Sha256::new()
                        .chain_update(mix)
                        .chain_update(me)
                        .finalize()
                        .into();
                }
                now += STEP;
            }
            (blocks, oldest)
        };
        let (live, oldest) = day(true);
        assert!(
            live < 100,
            "{live} beacon blocks in an idle day under the rule"
        );
        assert!(
            live >= (DAY / (interval + tick + 4 * BACKUP_STEP_MS)) as u32,
            "the beacon stopped: {live} blocks"
        );
        assert!(
            oldest <= interval + 4 * BACKUP_STEP_MS + tick,
            "the beacon grew {oldest} ms old"
        );
        let (dormant, _) = day(false);
        assert!(
            dormant >= (DAY / 60_000) as u32,
            "{dormant} beacon blocks in an idle day without the rule"
        );
    }
}
