//! Validator-side SLA attestation.
//!
//! Each validator probes every bonded compute provider on a schedule, tallies
//! how each provider answered within the epoch, and once the epoch closes
//! submits an `SlaAttest` native transaction carrying one outcome per
//! provider. The chain freezes a provider's verdict for the epoch once
//! attesters holding two thirds of bonded stake have spoken, and storage
//! billing settles on that verdict.
//!
//! An RPC operator that published an https endpoint for its stake is also
//! checked there each round: the endpoint must answer `eth_chainId` with this
//! network's chain id. Each check is one more observation for the stake's
//! verdict, so an endpoint that does not serve the network makes the stake
//! unavailable even while its node answers.
//!
//! A bonded wallet provider is checked at the domain its bond declares: the
//! probe is a fetch of that domain's provider document, answered when the
//! document names the bonding account. The same verdict marks the domain's
//! provider as staked, and the same unavailable penalty applies.
//!
//! A bonded edge operator is checked at the relay URL its bond published:
//! the relay must serve its operator's current signed record announcing
//! exactly that URL, the record every node admits a relay by, and the
//! operator's endpoint must forward a peer relay datagram. The same verdict
//! and unavailable penalty apply, out of the edge bond.
//!
//! Scoring a single probe and slashing on repeated failure stays in
//! [`tenzro_model::SlaManager`]; this module only schedules probes and turns
//! their results into a consensus record.

use std::sync::Arc;

use dashmap::DashMap;
use tenzro_network::NetworkService;
use tenzro_types::SlaOutcome;
use tenzro_types::network::NetworkRole;
use tenzro_types::token::StakeCapacity;
use tracing::{debug, warn};

use crate::node::TenzroNode;

/// How often a validator probes each bonded provider, ms: the governed
/// `sla.probe_interval_ms` in force.
fn probe_interval_ms(chain: Option<&tenzro_vm::StateAdapter>) -> i64 {
    sla_param(chain, tenzro_vm::native::SLA_PROBE_INTERVAL_PARAM)
}

/// How long a provider has to answer a scheduled probe, ms: the governed
/// `sla.probe_window_ms`, never longer than the probe interval.
fn probe_window_ms(chain: Option<&tenzro_vm::StateAdapter>) -> i64 {
    sla_param(chain, tenzro_vm::native::SLA_PROBE_WINDOW_PARAM).min(probe_interval_ms(chain))
}

fn sla_param(chain: Option<&tenzro_vm::StateAdapter>, key: &str) -> i64 {
    chain.map_or_else(
        || tenzro_vm::governance::genesis_param(key),
        |c| tenzro_vm::native::network_param(c, key),
    ) as i64
}

/// Per-(provider, epoch) probe results on this validator.
#[derive(Debug, Default)]
pub struct SlaTally {
    /// `(provider_did, epoch) -> (answered in time, failed)`.
    counts: DashMap<(String, u64), (u32, u32)>,
    /// `(provider_did, epoch) -> capacities verified work showed`.
    capacity: DashMap<(String, u64), Vec<u64>>,
    /// `challenge nonce -> (epoch, when the probe went out)`, for timing
    /// capacity probes on this validator's own clock.
    issued: DashMap<[u8; 32], (u64, i64)>,
}

impl SlaTally {
    /// Record one scored probe.
    pub fn record(&self, provider_did: &str, epoch: u64, answered: bool) {
        let mut entry = self
            .counts
            .entry((provider_did.to_string(), epoch))
            .or_insert((0, 0));
        if answered {
            entry.0 = entry.0.saturating_add(1);
        } else {
            entry.1 = entry.1.saturating_add(1);
        }
    }

    /// Note when a capacity probe went out.
    pub fn note_issued(&self, nonce: [u8; 32], epoch: u64, at_ms: i64) {
        self.issued.insert(nonce, (epoch, at_ms));
    }

    /// When the probe with `nonce` went out, once.
    pub fn take_issued(&self, nonce: &[u8; 32]) -> Option<i64> {
        self.issued.remove(nonce).map(|(_, (_, at))| at)
    }

    /// Record the capacity one verified capacity probe showed.
    pub fn record_capacity(&self, provider_did: &str, epoch: u64, capacity: u64) {
        self.capacity
            .entry((provider_did.to_string(), epoch))
            .or_default()
            .push(capacity);
    }

    /// Remove and return `epoch`'s outcomes, sorted by DID. A provider is
    /// available when it answered more than half of this validator's probes.
    /// Its capacity is its consensus participation when `participation_of`
    /// gives one, and otherwise the median of the capacities verified probes showed. Tallies older
    /// than `epoch` are dropped: their window has passed.
    pub fn take_epoch(
        &self,
        epoch: u64,
        participation_of: &dyn Fn(&str) -> Option<u64>,
    ) -> Vec<SlaOutcome> {
        let mut out: Vec<SlaOutcome> = self
            .counts
            .iter()
            .filter(|kv| kv.key().1 == epoch)
            .map(|kv| {
                let did = kv.key().0.clone();
                let capacity = match participation_of(&did) {
                    Some(bps) => Some(bps),
                    None => self.capacity.get(&(did.clone(), epoch)).and_then(|v| {
                        let mut v = v.clone();
                        v.sort_unstable();
                        v.get(v.len() / 2).copied()
                    }),
                };
                SlaOutcome {
                    provider_did: did,
                    available: kv.value().0 > kv.value().1,
                    capacity,
                }
            })
            .collect();
        self.counts.retain(|k, _| k.1 > epoch);
        self.capacity.retain(|k, _| k.1 > epoch);
        self.issued.retain(|_, v| v.0 > epoch);
        out.sort_by(|a, b| a.provider_did.cmp(&b.provider_did));
        out
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Issue one VRF-stamped probe to `provider_did` carrying `work`, register
/// it as outstanding and broadcast it on `tenzro/sla`. Registration happens
/// before the broadcast so a fast answer cannot race it.
async fn issue_probe_with_work(
    node: &TenzroNode,
    provider_did: &str,
    epoch: u64,
    round: u64,
    deadline_ms: i64,
    work: Option<tenzro_model::CapacityWork>,
) -> Result<tenzro_model::SlaProbe, String> {
    let manager = node
        .sla_manager()
        .ok_or_else(|| "SlaManager not initialized (validator-only)".to_string())?;
    let probe = manager
        .issue_probe(provider_did, epoch, round, deadline_ms, work)
        .map_err(|e| format!("issue_probe failed: {}", e))?;
    if probe.work.is_some() {
        node.sla_tally()
            .note_issued(probe.challenge_nonce, epoch, now_ms());
    }
    node.sla_outstanding_probes()
        .insert(hex::encode(probe.challenge_nonce), probe.clone());
    if let Some(network) = node.network() {
        let payload = bincode::serialize(&tenzro_model::SlaEnvelope::Probe(probe.clone()))
            .map_err(|e| format!("bincode serialize SlaProbe: {}", e))?;
        let msg = tenzro_network::NetworkMessage::new(tenzro_network::MessagePayload::Custom {
            topic: "tenzro/sla".to_string(),
            data: payload,
        });
        if let Err(e) = network.broadcast("tenzro/sla", msg).await {
            warn!(error = %e, "Failed to broadcast SLA probe on tenzro/sla");
        }
    }
    Ok(probe)
}

/// Issue one VRF-stamped probe to `provider_did`, register it as outstanding
/// and broadcast it on `tenzro/sla`. A bond that delivers storage claims
/// also proves their objects; any other subject gets a bare liveness probe.
pub(crate) async fn issue_probe(
    node: &TenzroNode,
    provider_did: &str,
    epoch: u64,
    round: u64,
    deadline_ms: i64,
) -> Result<tenzro_model::SlaProbe, String> {
    let work = crate::rpc::chain_state_of(node)
        .and_then(|chain| crate::capacity_probe::probe_work(&chain, provider_did));
    issue_probe_with_work(node, provider_did, epoch, round, deadline_ms, work).await
}

/// How often a validator runs a burst challenge against each operator
/// claiming more than one compute unit — about the governed probe interval
/// times this many rounds. Sparse enough that the matrix work stays a small
/// share of challenge energy; frequent enough that a run of it lands inside
/// any reasonably long-lived network, not just a token "per week" that a
/// short-lived deployment would never see fire.
const BURST_ROUNDS_BETWEEN: u64 = 36;

/// Groups `subjects`, each given with its owning account, by owner,
/// dropping any owner with only one: the key a burst challenge issues
/// against is one account behind several claimed provider DIDs, which a
/// single claimed unit is not.
fn group_by_owner(
    subjects: impl IntoIterator<Item = (String, Vec<u8>)>,
) -> std::collections::BTreeMap<Vec<u8>, Vec<String>> {
    let mut by_owner: std::collections::BTreeMap<Vec<u8>, Vec<String>> = Default::default();
    for (subject, owner) in subjects {
        by_owner.entry(owner).or_default().push(subject);
    }
    by_owner.retain(|_, subjects| subjects.len() > 1);
    by_owner
}

/// Every owner with more than one claimed, probeable compute unit, mapped
/// to the provider DIDs it claims. The owner is the account [`sla_subject`]
/// gives as the bond's payer — the same account behind several provider
/// DIDs is exactly the shape a burst challenge targets: one operator
/// claiming more distinct units than it may actually run.
pub(crate) fn operators_with_units(
    chain: &dyn tenzro_vm::VmState,
) -> std::collections::BTreeMap<Vec<u8>, Vec<String>> {
    group_by_owner(probe_subjects(chain).into_iter().filter_map(|subject| {
        let s = tenzro_vm::native::sla_subject(chain, &subject)?;
        (s.kind == tenzro_vm::native::SlaSubjectKind::ComputeBond).then_some((subject, s.owner))
    }))
}

/// On a validator, run a burst challenge every [`BURST_ROUNDS_BETWEEN`]
/// probe rounds against every operator claiming more than one compute
/// unit: every one of its units gets [`crate::capacity_probe::burst_work`]
/// in the same round, under the same deadline, in place of whatever its
/// ordinary probe would have asked for. One real accelerator backing more
/// claimed units than it owns cannot produce a genuine matrix proof for
/// every one of them inside that single window; scoring is the same
/// `SlaManager::score_response` plus `capacity_probe::capacity_kept` path
/// every probe goes through, so a unit that fails the burst fails its
/// epoch's SLA verdict exactly as a missed liveness probe would.
pub fn spawn_burst_challenge_scheduler(node: Arc<TenzroNode>) {
    if node.sla_manager().is_none() {
        return;
    }
    tokio::spawn(async move {
        loop {
            let interval = probe_interval_ms(crate::rpc::chain_state_of(&node).as_ref()).max(1);
            let wait = interval - now_ms().rem_euclid(interval);
            tokio::time::sleep(std::time::Duration::from_millis(wait as u64)).await;
            let Some(chain) = crate::rpc::chain_state_of(&node) else {
                continue;
            };
            let now = now_ms();
            let interval = probe_interval_ms(Some(&chain)).max(1);
            let round = (now / interval) as u64;
            if !round.is_multiple_of(BURST_ROUNDS_BETWEEN) {
                continue;
            }
            let epoch = (now / tenzro_vm::native::MARKET_EPOCH_MS) as u64;
            let window = probe_window_ms(Some(&chain));
            let deadline = now + window;
            for (_owner, subjects) in operators_with_units(&chain) {
                for subject in subjects {
                    let node = node.clone();
                    tokio::spawn(async move {
                        if let Err(e) = issue_probe_with_work(
                            &node,
                            &subject,
                            epoch,
                            round,
                            deadline,
                            Some(crate::capacity_probe::burst_work()),
                        )
                        .await
                        {
                            warn!(provider = %subject, error = %e, "burst challenge probe failed");
                        }
                    });
                }
            }
        }
    });
}

/// On a validator, probe every active bond whose answering hardware identity
/// is registered on chain, every governed probe interval. A bond with no
/// registered identity has nobody who may answer, so probing it would only record misses the provider cannot
/// avoid; it is left unprobed and its rentals void rather than miss.
pub fn spawn_probe_scheduler(node: Arc<TenzroNode>) {
    if node.sla_manager().is_none() {
        return;
    }
    tokio::spawn(async move {
        loop {
            // Rounds align to the governed interval, so every validator
            // probes in the same rounds.
            let interval = probe_interval_ms(crate::rpc::chain_state_of(&node).as_ref()).max(1);
            let wait = interval - now_ms().rem_euclid(interval);
            tokio::time::sleep(std::time::Duration::from_millis(wait as u64)).await;
            let Some(chain) = crate::rpc::chain_state_of(&node) else {
                continue;
            };
            let now = now_ms();
            let epoch = (now / tenzro_vm::native::MARKET_EPOCH_MS) as u64;
            let interval = probe_interval_ms(Some(&chain)).max(1);
            let window = probe_window_ms(Some(&chain));
            let round = (now / interval) as u64;
            for subject in probe_subjects(&chain) {
                if let Some((domain, account)) = wallet_provider_domain(&chain, &subject) {
                    let node = node.clone();
                    tokio::spawn(async move {
                        let named = domain_names_account(&node, &domain, &account).await;
                        node.sla_tally().record(&subject, epoch, named);
                    });
                    continue;
                }
                if let Some(url) = edge_relay(&chain, &subject) {
                    let node = node.clone();
                    tokio::spawn(async move {
                        let answers = match url {
                            Some(url) => relay_answers(&node, &url).await,
                            None => false,
                        };
                        node.sla_tally().record(&subject, epoch, answers);
                    });
                    continue;
                }
                if let Some(url) = rpc_endpoint(&chain, &subject) {
                    let node = node.clone();
                    let subject = subject.clone();
                    tokio::spawn(async move {
                        let serves = endpoint_serves_chain(&node, &url).await;
                        node.sla_tally().record(&subject, epoch, serves);
                    });
                }
                if let Err(e) = issue_probe(&node, &subject, epoch, round, now + window).await {
                    warn!(provider = %subject, error = %e, "scheduled SLA probe failed");
                }
            }
        }
    });
}

/// An SLA subject as chain state holds it: a compute bond, or a bonded
/// role stake.
pub(crate) fn chain_sla_subject(
    store: Option<&Arc<dyn tenzro_storage::KvStore>>,
    subject: &str,
) -> Option<tenzro_vm::native::SlaSubject> {
    let chain = tenzro_vm::StateAdapter::with_storage(store?.clone());
    tenzro_vm::native::sla_subject(&chain, subject)
}

/// Every subject a validator probes this round: eligible compute bonds and
/// every bonded role stake that owes an SLA, each only once the hardware
/// identity that answers for it is registered on chain.
pub(crate) fn probe_subjects(chain: &dyn tenzro_vm::VmState) -> Vec<String> {
    let role_stakes = tenzro_vm::native::role_stake_totals(chain)
        .into_iter()
        .filter(|(role, _)| tenzro_vm::native::role_owes_sla(*role))
        .flat_map(|(role, total)| {
            total
                .stakers
                .into_iter()
                .filter_map(|account| hex::decode(account).ok())
                .map(move |account| tenzro_vm::native::role_stake_subject(&account, role))
        });
    tenzro_vm::native::compute_bonds(chain)
        .into_iter()
        .filter(|bond| bond.is_eligible())
        .map(|bond| bond.provider_did)
        .chain(role_stakes)
        .filter(|subject| {
            // A wallet provider is checked at its domain and an edge operator
            // at its relay URL, neither of which needs a node identity to
            // answer.
            tenzro_vm::native::sla_subject(chain, subject).is_some_and(|s| {
                s.identity.is_some()
                    || matches!(
                        s.kind,
                        tenzro_vm::native::SlaSubjectKind::RoleStake(
                            NetworkRole::WalletProvider | NetworkRole::Edge
                        )
                    )
            })
        })
        .collect()
}

/// The `(domain, bonding account)` behind a wallet provider SLA subject, or
/// `None` for any other subject.
fn wallet_provider_domain(
    chain: &dyn tenzro_vm::VmState,
    subject: &str,
) -> Option<(String, Vec<u8>)> {
    let s = tenzro_vm::native::sla_subject(chain, subject)?;
    if s.kind != tenzro_vm::native::SlaSubjectKind::RoleStake(NetworkRole::WalletProvider) {
        return None;
    }
    match tenzro_vm::native::read_role_stake(chain, &s.owner, NetworkRole::WalletProvider)?.capacity
    {
        StakeCapacity::Domain(domain) => Some((domain, s.owner)),
        _ => None,
    }
}

/// The relay URL an edge operator's stake published, for its SLA subject.
/// A stake that published none answers no check, and is unavailable.
fn edge_relay(chain: &dyn tenzro_vm::VmState, subject: &str) -> Option<Option<url::Url>> {
    let s = tenzro_vm::native::sla_subject(chain, subject)?;
    if s.kind != tenzro_vm::native::SlaSubjectKind::RoleStake(NetworkRole::Edge) {
        return None;
    }
    let published =
        tenzro_vm::native::read_role_stake(chain, &s.owner, NetworkRole::Edge)?.endpoint;
    Some(published.and_then(|u| url::Url::parse(&u).ok()))
}

/// Largest relay record a relay check reads.
const RELAY_RECORD_MAX_BYTES: usize = 16 * 1024;

/// Whether the relay at `url` serves its operator's current signed record
/// announcing exactly `url` (the check every node admits a relay by, fetched
/// over HTTPS through the egress guard), and the operator's endpoint
/// forwards peer relay datagrams.
async fn relay_answers(node: &TenzroNode, url: &url::Url) -> bool {
    let target = tenzro_iroh::relay::identity_url(url);
    let egress = node.egress();
    let Ok(request) = egress.get(target.as_str(), crate::egress_guard::Scheme::HttpsOnly) else {
        return false;
    };
    let body = match egress
        .send(request.timeout(std::time::Duration::from_secs(10)))
        .await
    {
        Ok(r) if r.status().is_success() => {
            match r.with_limit(RELAY_RECORD_MAX_BYTES).bytes().await {
                Ok(b) => b,
                Err(e) => {
                    debug!(%url, error = %e, "relay record unreadable");
                    return false;
                }
            }
        }
        Ok(r) => {
            debug!(%url, status = %r.status(), "relay record unavailable");
            return false;
        }
        Err(e) => {
            debug!(%url, error = %e, "relay unreachable");
            return false;
        }
    };
    let record = match tenzro_iroh::relay::admit_relay_record(url, &body) {
        Ok(record) => record,
        Err(e) => {
            debug!(%url, error = %e, "relay record refused");
            return false;
        }
    };
    // The operator's endpoint also forwards packets between endpoints that
    // cannot reach each other directly: a datagram it is sent addressed to
    // the sender must come back.
    let (Some(resolver), Ok(addr)) = (
        node.iroh_resolver(),
        tenzro_iroh::identity_transport::endpoint_addr(&record),
    ) else {
        return false;
    };
    let forwards = tenzro_iroh::paths::forwarder_answers(
        resolver.endpoint(),
        addr,
        std::time::Duration::from_secs(15),
    )
    .await;
    if !forwards {
        debug!(%url, "relay operator does not forward");
    }
    forwards
}

/// The https endpoint an RPC operator's stake published, for its SLA subject.
fn rpc_endpoint(chain: &dyn tenzro_vm::VmState, subject: &str) -> Option<String> {
    let s = tenzro_vm::native::sla_subject(chain, subject)?;
    if s.kind != tenzro_vm::native::SlaSubjectKind::RoleStake(NetworkRole::Rpc) {
        return None;
    }
    tenzro_vm::native::read_role_stake(chain, &s.owner, NetworkRole::Rpc)?.endpoint
}

/// Largest JSON-RPC answer an endpoint check reads.
const ENDPOINT_ANSWER_MAX_BYTES: usize = 4 * 1024;

/// Whether the published RPC endpoint at `url` answers `eth_chainId` with this
/// network's chain id. An RPC operator answers for the endpoint it published,
/// as well as for its node.
async fn endpoint_serves_chain(node: &TenzroNode, url: &str) -> bool {
    let Some(want) = node
        .config()
        .genesis
        .as_ref()
        .map(|g| format!("0x{:x}", g.chain_id))
    else {
        return false;
    };
    let egress = node.egress();
    let Ok(request) = egress.post(url, crate::egress_guard::Scheme::HttpsOnly) else {
        return false;
    };
    let body =
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": [] });
    let request = request
        .timeout(std::time::Duration::from_secs(10))
        .json(&body);
    match egress.send(request).await {
        Ok(r) if r.status().is_success() => match r
            .with_limit(ENDPOINT_ANSWER_MAX_BYTES)
            .json::<serde_json::Value>()
            .await
        {
            Ok(v) => v
                .get("result")
                .and_then(|r| r.as_str())
                .is_some_and(|r| r.eq_ignore_ascii_case(&want)),
            Err(_) => false,
        },
        Ok(r) => {
            debug!(%url, status = %r.status(), "rpc endpoint answered with an error");
            false
        }
        Err(e) => {
            debug!(%url, error = %e, "rpc endpoint unreachable");
            false
        }
    }
}

/// Largest provider document a domain check reads.
const PROVIDER_DOCUMENT_MAX_BYTES: usize = 16 * 1024;

/// The document a wallet provider serves at
/// [`tenzro_vm::native::WALLET_PROVIDER_DOCUMENT_PATH`] on its domain.
#[derive(serde::Deserialize)]
struct ProviderDocument {
    accounts: Vec<String>,
}

/// Whether `https://<domain>/.well-known/tenzro-provider` names `account`.
/// Fetched over HTTPS through the egress guard, without following redirects,
/// so only the domain itself can answer for itself.
async fn domain_names_account(node: &TenzroNode, domain: &str, account: &[u8]) -> bool {
    let url = format!(
        "https://{domain}{}",
        tenzro_vm::native::WALLET_PROVIDER_DOCUMENT_PATH
    );
    let egress = node.egress();
    let Ok(request) = egress.get(&url, crate::egress_guard::Scheme::HttpsOnly) else {
        return false;
    };
    let response = match egress
        .send(request.timeout(std::time::Duration::from_secs(10)))
        .await
    {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            debug!(%domain, status = %r.status(), "wallet provider document unavailable");
            return false;
        }
        Err(e) => {
            debug!(%domain, error = %e, "wallet provider document unreachable");
            return false;
        }
    };
    match response
        .with_limit(PROVIDER_DOCUMENT_MAX_BYTES)
        .json::<ProviderDocument>()
        .await
    {
        Ok(doc) => document_names(&doc, account),
        Err(e) => {
            debug!(%domain, error = %e, "wallet provider document unreadable");
            false
        }
    }
}

fn document_names(doc: &ProviderDocument, account: &[u8]) -> bool {
    let want = hex::encode(account);
    doc.accounts.iter().any(|a| {
        a.trim()
            .trim_start_matches("0x")
            .eq_ignore_ascii_case(&want)
    })
}

/// On a validator, attest each closed epoch's probe outcomes on chain. Runs
/// once the last probe issued in the epoch is past its deadline.
pub fn spawn_attestation_submitter(node: Arc<TenzroNode>) {
    if node.sla_manager().is_none() {
        return;
    }
    tokio::spawn(async move {
        let epoch_ms = tenzro_vm::native::MARKET_EPOCH_MS;
        loop {
            let now = now_ms();
            let window = probe_window_ms(crate::rpc::chain_state_of(&node).as_ref());
            let next = (now / epoch_ms + 1) * epoch_ms + window + 30_000;
            tokio::time::sleep(std::time::Duration::from_millis((next - now).max(0) as u64)).await;

            let closed = (now_ms() / epoch_ms - 1).max(0) as u64;
            let _chain = crate::rpc::chain_state_of(&node);
            let participation_of = |_did: &str| None;
            let outcomes = node.sla_tally().take_epoch(closed, &participation_of);
            if outcomes.is_empty() {
                debug!(epoch = closed, "no SLA outcomes to attest");
                continue;
            }
            for chunk in outcomes.chunks(tenzro_vm::native::MAX_SLA_OUTCOMES) {
                let count = chunk.len();
                let tx = tenzro_types::TransactionType::SlaAttest {
                    epoch: closed,
                    outcomes: chunk.to_vec(),
                };
                let gas = tenzro_vm::native::GAS_SLA_ATTEST
                    + tenzro_vm::native::GAS_SLA_OUTCOME * count as u64;
                match crate::rpc::submit_as_validator(&node, tx, gas).await {
                    Ok(_) => debug!(epoch = closed, count, "attested SLA outcomes"),
                    Err(e) => warn!(
                        epoch = closed,
                        error = %e.message,
                        "could not attest SLA outcomes"
                    ),
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_by_owner_keeps_only_operators_with_more_than_one_unit() {
        let owner_a = vec![0xA; 32];
        let owner_b = vec![0xB; 32];
        let grouped = group_by_owner([
            ("unit-1".to_string(), owner_a.clone()),
            ("unit-2".to_string(), owner_a.clone()),
            ("unit-3".to_string(), owner_a.clone()),
            ("solo".to_string(), owner_b.clone()),
        ]);
        assert_eq!(grouped.len(), 1, "the single-unit owner is dropped");
        let units = grouped.get(&owner_a).unwrap();
        assert_eq!(units.len(), 3);
        assert!(units.contains(&"unit-1".to_string()));
        assert!(units.contains(&"unit-2".to_string()));
        assert!(units.contains(&"unit-3".to_string()));
        assert!(!grouped.contains_key(&owner_b));
    }

    #[test]
    fn a_provider_is_available_when_it_answered_most_probes() {
        let tally = SlaTally::default();
        for answered in [true, true, false] {
            tally.record("did:b", 7, answered);
        }
        for answered in [true, false] {
            tally.record("did:a", 7, answered);
        }
        tally.record("did:a", 8, true);
        tally.record("did:a", 6, true);

        let out = tally.take_epoch(7, &|_| None);
        assert_eq!(
            out,
            vec![
                SlaOutcome {
                    provider_did: "did:a".into(),
                    available: false,
                    capacity: None
                },
                SlaOutcome {
                    provider_did: "did:b".into(),
                    available: true,
                    capacity: None
                },
            ]
        );
        // Taken once; older epochs dropped, later ones kept.
        assert!(tally.take_epoch(7, &|_| None).is_empty());
        assert!(tally.take_epoch(6, &|_| None).is_empty());
        assert_eq!(tally.take_epoch(8, &|_| None).len(), 1);
    }

    #[test]
    fn capacity_is_participation_for_a_validator_and_the_median_otherwise() {
        let tally = SlaTally::default();
        tally.record("did:validator", 3, true);
        tally.record("did:ai", 3, true);
        tally.record("did:silent", 3, true);
        for c in [30, 10, 20] {
            tally.record_capacity("did:ai", 3, c);
        }
        // The validator signed three quarters of its epoch's certified rounds.
        let out = tally.take_epoch(3, &|did: &str| (did == "did:validator").then_some(7_500));
        let cap = |did: &str| out.iter().find(|o| o.provider_did == did).unwrap().capacity;
        assert_eq!(cap("did:validator"), Some(7_500));
        assert_eq!(cap("did:ai"), Some(20));
        assert_eq!(cap("did:silent"), None, "no verified work, no capacity");
    }

    #[test]
    fn scheduled_probes_leave_more_than_the_minimum_to_answer() {
        let bound =
            tenzro_vm::governance::governed_param(tenzro_vm::native::SLA_PROBE_WINDOW_PARAM)
                .unwrap();
        assert!(bound.min as i64 > tenzro_model::MIN_SLA_RESPONSE_WINDOW_MS);
        // Several probes per epoch, so one dropped packet is not a verdict.
        let bound =
            tenzro_vm::governance::governed_param(tenzro_vm::native::SLA_PROBE_INTERVAL_PARAM)
                .unwrap();
        assert!(tenzro_vm::native::MARKET_EPOCH_MS / bound.max as i64 >= 3);
    }

    #[test]
    fn a_provider_document_names_an_account_in_either_spelling() {
        let account = [0xab_u8; 32];
        let doc: ProviderDocument = serde_json::from_str(&format!(
            r#"{{"accounts": ["0x{}"]}}"#,
            hex::encode_upper(account)
        ))
        .unwrap();
        assert!(document_names(&doc, &account));
        assert!(!document_names(&doc, &[0xcd; 32]));
        let bare: ProviderDocument =
            serde_json::from_str(&format!(r#"{{"accounts": ["{}"]}}"#, hex::encode(account)))
                .unwrap();
        assert!(document_names(&bare, &account));
    }

    #[tokio::test]
    async fn a_wallet_provider_is_probed_at_its_domain_without_a_node_identity() {
        use tenzro_vm::{VmExecutor as _, VmState as _};
        let executor = tenzro_vm::NativeExecutor::new(tenzro_vm::VmConfig::default()).unwrap();
        let mut chain = tenzro_vm::StateAdapter::new();
        let account = [7u8; 32];
        chain.set_balance(
            &account,
            10 * tenzro_types::constants::MIN_WALLET_PROVIDER_STAKE,
        );
        let op = tenzro_types::token::StakeOp::Bond {
            role: NetworkRole::WalletProvider,
            amount: tenzro_types::constants::MIN_WALLET_PROVIDER_STAKE,
            capacity: StakeCapacity::Domain("wallet.example".into()),
        };
        let mut data = tenzro_vm::native::SELECTOR_STAKE.to_vec();
        data.extend(serde_json::to_vec(&op).unwrap());
        let mut tx = tenzro_vm::types::VmTransaction::new(
            account.to_vec(),
            None,
            0,
            data,
            1_000_000,
            0,
            0,
            tenzro_vm::VmType::Tenzro,
            1337,
        );
        tx.block_timestamp_ms = Some(1);
        executor.execute_transaction(&tx, &mut chain).await.unwrap();

        let subject = tenzro_vm::native::role_stake_subject(&account, NetworkRole::WalletProvider);
        assert!(probe_subjects(&chain).contains(&subject));
        assert_eq!(
            wallet_provider_domain(&chain, &subject),
            Some(("wallet.example".to_string(), account.to_vec()))
        );
    }

    /// An edge operator is probed at the relay URL its bond published,
    /// without a node identity, on the same SLA path as every other role.
    #[tokio::test]
    async fn an_edge_operator_is_probed_at_its_published_relay() {
        use tenzro_vm::{VmExecutor as _, VmState as _};
        let executor = tenzro_vm::NativeExecutor::new(tenzro_vm::VmConfig::default()).unwrap();
        let mut chain = tenzro_vm::StateAdapter::new();
        let account = [9u8; 32];
        chain.set_balance(
            &account,
            10 * tenzro_types::constants::MIN_EDGE_OPERATOR_STAKE,
        );
        for (nonce, op) in [
            tenzro_types::token::StakeOp::Bond {
                role: NetworkRole::Edge,
                amount: tenzro_types::constants::MIN_EDGE_OPERATOR_STAKE,
                capacity: StakeCapacity::None,
            },
            tenzro_types::token::StakeOp::Endpoint {
                role: NetworkRole::Edge,
                url: "https://relay.example.org/".into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let nonce = nonce as u128;
            let mut data = tenzro_vm::native::SELECTOR_STAKE.to_vec();
            data.extend(serde_json::to_vec(&op).unwrap());
            let mut tx = tenzro_vm::types::VmTransaction::new(
                account.to_vec(),
                None,
                nonce,
                data,
                1_000_000,
                0,
                0,
                tenzro_vm::VmType::Tenzro,
                1337,
            );
            tx.block_timestamp_ms = Some(1);
            executor.execute_transaction(&tx, &mut chain).await.unwrap();
        }
        let subject = tenzro_vm::native::role_stake_subject(&account, NetworkRole::Edge);
        assert!(probe_subjects(&chain).contains(&subject));
        assert_eq!(
            edge_relay(&chain, &subject),
            Some(Some(url::Url::parse("https://relay.example.org/").unwrap()))
        );
        let rpc = tenzro_vm::native::role_stake_subject(&account, NetworkRole::Rpc);
        assert_eq!(edge_relay(&chain, &rpc), None);
    }
}
