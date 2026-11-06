//! Demand-driven expert placement for distributed MoE serving.
//!
//! Routed-token load across a MoE layer is heavily skewed: a few experts
//! take most of the tokens. A fixed replication floor leaves those experts
//! queueing on their two holders while cold experts sit replicated for
//! nothing. Placement here follows measured demand instead, and counts only
//! demand and holders the integrity layer vouches for:
//!
//! * **Demand is metered from signed work.** A holder counts the tokens it
//!   executed for each expert — every one of them carried in an execution
//!   receipt it signed ([`ExpertLoadMeter`]). It advertises that decayed rate
//!   per expert in its MoE declaration, where it previously advertised one
//!   host-wide figure on every holding.
//! * **Replication tracks demand.** An expert's target replication is the
//!   floor plus one holder per `hot_threshold_tps` of demand, capped
//!   ([`target_replication`]), so a hot expert gains holders and a cooled one
//!   stops attracting them.
//! * **Proven-faulty holders do not count.** A holder whose execution was
//!   shown by re-execution to diverge from its signed activation commitment
//!   is recorded in the [`FaultLedger`]. It no longer counts toward any
//!   expert's replication, is never chosen to take on a new expert, and its
//!   demand figures are ignored, so a faulty holder cannot inflate an
//!   expert's heat or pin one of its copies.
//! * **Placement stays pull-based.** Each node computes the same plan from
//!   the same view with a rendezvous hash and acts only on rows naming
//!   itself; nothing lets one node make another allocate memory.
//!
//! None of this depends on the architecture: an expert is a
//! `(model, layer, expert)` triple, whatever the model's MoE layout.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tenzro_model::{ExpertId, MoeShardView, ReplicationPolicy};
use tenzro_types::primitives::Address;

/// Rendezvous-hash domain tag for demand-driven placement.
const PLACEMENT_DOMAIN: &[u8] = b"tenzro/moe/demand-placement";

/// Half-life of the metered token rate, in seconds.
const DEMAND_HALF_LIFE_SECS: f64 = 300.0;

/// Key of one expert of one model.
pub type ExpertKey = (String, u32, u32);

/// Exponentially decayed token rate per expert, from receipts this node
/// signed.
#[derive(Debug, Default)]
pub struct ExpertLoadMeter {
    rates: Mutex<HashMap<ExpertKey, (f64, Instant)>>,
}

impl ExpertLoadMeter {
    /// Count `tokens` executed for an expert now.
    pub fn record(&self, model_id: &str, layer: u32, expert: u32, tokens: usize) {
        self.record_at(model_id, layer, expert, tokens, Instant::now());
    }

    fn record_at(&self, model_id: &str, layer: u32, expert: u32, tokens: usize, now: Instant) {
        let mut rates = self.rates.lock();
        let entry = rates
            .entry((model_id.to_string(), layer, expert))
            .or_insert((0.0, now));
        let decayed = decay(entry.0, entry.1, now);
        // The decayed count divided by the mean lifetime of a token in the
        // window is the rate in tokens per second.
        *entry = (decayed + tokens as f64, now);
    }

    /// Tokens per second an expert is currently serving here.
    pub fn tps(&self, model_id: &str, layer: u32, expert: u32) -> u32 {
        self.tps_at(model_id, layer, expert, Instant::now())
    }

    fn tps_at(&self, model_id: &str, layer: u32, expert: u32, now: Instant) -> u32 {
        let rates = self.rates.lock();
        rates
            .get(&(model_id.to_string(), layer, expert))
            .map(|(count, at)| {
                let mean_life = DEMAND_HALF_LIFE_SECS / std::f64::consts::LN_2;
                (decay(*count, *at, now) / mean_life).round() as u32
            })
            .unwrap_or(0)
    }
}

fn decay(count: f64, at: Instant, now: Instant) -> f64 {
    let dt = now.saturating_duration_since(at).as_secs_f64();
    count * (-dt * std::f64::consts::LN_2 / DEMAND_HALF_LIFE_SECS).exp()
}

/// Providers shown by re-execution to have signed activations their
/// execution did not produce.
#[derive(Debug, Default)]
pub struct FaultLedger {
    faulty: Mutex<HashSet<Address>>,
}

impl FaultLedger {
    /// Record an upheld activation fraud proof against `provider`.
    pub fn record(&self, provider: Address) {
        self.faulty.lock().insert(provider);
    }

    /// Whether `provider` has a proven fault.
    pub fn is_faulty(&self, provider: &Address) -> bool {
        self.faulty.lock().contains(provider)
    }

    /// Snapshot of every proven-faulty provider.
    pub fn snapshot(&self) -> HashSet<Address> {
        self.faulty.lock().clone()
    }
}

/// This process's meter of the tokens it executed per expert.
pub fn load_meter() -> &'static ExpertLoadMeter {
    static METER: std::sync::OnceLock<ExpertLoadMeter> = std::sync::OnceLock::new();
    METER.get_or_init(ExpertLoadMeter::default)
}

/// The providers this process has proven faulty by re-execution.
pub fn fault_ledger() -> &'static FaultLedger {
    static LEDGER: std::sync::OnceLock<FaultLedger> = std::sync::OnceLock::new();
    LEDGER.get_or_init(FaultLedger::default)
}

/// The hardware identity key registered for the machine DID `provider`'s live
/// announcement was signed as. Execution receipts from that provider must be
/// certified by it.
pub fn announced_key(
    node: &crate::node::TenzroNode,
    provider: &Address,
) -> Option<tenzro_crypto::composite::CompositePublicKey> {
    let did = node
        .network_providers_snapshot()
        .into_iter()
        .find(|e| {
            Address::from_hex(e.announcement.provider_address.trim_start_matches("0x"))
                .is_ok_and(|a| &a == provider)
        })
        .map(|e| e.announcement.machine_did)?;
    crate::identity_bootstrap::registered_identity_key(&node.identity_registry_slot(), &did)
}

/// Holders an expert should have for `demand_tps` tokens per second: the
/// floor, plus one for each full `hot_threshold_tps` of demand, capped.
pub fn target_replication(policy: &ReplicationPolicy, demand_tps: u64) -> u32 {
    let extra = if policy.hot_threshold_tps == 0 {
        0
    } else {
        (demand_tps / policy.hot_threshold_tps as u64).min(u32::MAX as u64) as u32
    };
    policy
        .min_replication
        .saturating_add(extra)
        .min(policy.max_replication.max(policy.min_replication))
}

/// One expert a named provider should take on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementRow {
    pub expert: ExpertId,
    pub provider: Address,
    pub blob_uri: String,
    /// The replication the expert is being raised to.
    pub target: u32,
}

fn rendezvous_rank(key: &str, candidate: &Address) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PLACEMENT_DOMAIN);
    h.update(key.as_bytes());
    h.update(candidate.as_bytes());
    h.finalize().into()
}

/// Plan new holders for every expert whose sound replication is below its
/// demand-driven target. Holders in `faulty` count neither as replicas nor
/// as demand, and are never chosen. Experts with no fetchable blob among
/// their sound holders are skipped.
pub fn plan_placement(
    view: &MoeShardView,
    policy: &ReplicationPolicy,
    candidates: &[Address],
    faulty: &HashSet<Address>,
) -> Vec<PlacementRow> {
    let mut out = Vec::new();
    for expert in view.covered_experts() {
        let sound: Vec<_> = view
            .holders(expert)
            .into_iter()
            .filter(|h| !faulty.contains(&h.provider))
            .collect();
        let demand: u64 = sound.iter().map(|h| h.committed_tps as u64).sum();
        let target = target_replication(policy, demand);
        let missing = target.saturating_sub(sound.len() as u32) as usize;
        if missing == 0 {
            continue;
        }
        let Some(blob_uri) = sound.iter().find_map(|h| h.blob_uri.clone()) else {
            continue;
        };
        let held: HashSet<Address> = view
            .holders(expert)
            .into_iter()
            .map(|h| h.provider)
            .collect();
        let key = format!("{}/{}/{}", view.model_id(), expert.layer, expert.expert);
        let mut pool: Vec<&Address> = candidates
            .iter()
            .filter(|a| !held.contains(a) && !faulty.contains(a))
            .collect();
        pool.sort_by_key(|a| rendezvous_rank(&key, a));
        for provider in pool.into_iter().take(missing) {
            out.push(PlacementRow {
                expert,
                provider: *provider,
                blob_uri: blob_uri.clone(),
                target,
            });
        }
    }
    out
}

/// Whether an execution receipt was signed by the identity key registered
/// for the provider's machine DID, both legs. A receipt signed by any other
/// key proves nothing about that provider.
pub fn receipt_key_is_announced(
    receipt_key: &tenzro_crypto::composite::CompositePublicKey,
    announced_key: Option<&tenzro_crypto::composite::CompositePublicKey>,
) -> bool {
    announced_key == Some(receipt_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tenzro_types::model::{
        InferenceProvider, MoeExpertHolding, MoeExpertResidency, MoeProviderRole, ProviderStatus,
    };

    fn policy() -> ReplicationPolicy {
        ReplicationPolicy {
            min_replication: 2,
            max_replication: 6,
            hot_threshold_tps: 1_000,
        }
    }

    fn provider(tag: u8, holdings: &[(u32, u32)]) -> InferenceProvider {
        let mut p = InferenceProvider::new(Address::new([tag; 32]), format!("p{tag}"));
        p.status = ProviderStatus::Active;
        p.capacity.moe_roles = vec![MoeProviderRole::ExpertHolder];
        p.capacity.moe_holdings = holdings
            .iter()
            .map(|(expert, tps)| MoeExpertHolding {
                model_id: "m".into(),
                layer: 0,
                expert: *expert,
                residency: MoeExpertResidency::Warm,
                committed_tps: *tps,
                blob_uri: Some(format!("tenzro://blob/{expert:064x}")),
            })
            .collect();
        p
    }

    #[test]
    fn the_target_follows_demand_between_floor_and_cap() {
        let p = policy();
        assert_eq!(target_replication(&p, 0), 2);
        assert_eq!(target_replication(&p, 2_500), 4);
        assert_eq!(target_replication(&p, 1_000_000), 6);
    }

    #[test]
    fn a_hot_expert_gains_holders_and_a_cold_one_does_not() {
        let providers = [
            provider(1, &[(0, 1_500), (1, 10)]),
            provider(2, &[(0, 1_600), (1, 10)]),
            provider(3, &[]),
            provider(4, &[]),
        ];
        let view = MoeShardView::build("m", providers.iter());
        let candidates: Vec<Address> = providers.iter().map(|p| p.address).collect();
        let plan = plan_placement(&view, &policy(), &candidates, &HashSet::new());
        // Expert 0 carries 3,100 tps: target 2 + 3 = 5, three new holders
        // wanted but only two candidates are free. Expert 1 is at its floor.
        assert!(plan.iter().all(|r| r.expert.expert == 0));
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|r| r.target == 5));
    }

    #[test]
    fn a_proven_faulty_holder_counts_for_nothing() {
        let providers = [
            provider(1, &[(0, 10)]),
            provider(2, &[(0, 50_000)]),
            provider(3, &[]),
            provider(4, &[]),
        ];
        let view = MoeShardView::build("m", providers.iter());
        let candidates: Vec<Address> = providers.iter().map(|p| p.address).collect();
        let faulty: HashSet<Address> = [Address::new([2; 32])].into();
        let plan = plan_placement(&view, &policy(), &candidates, &faulty);
        // The faulty holder's inflated demand is ignored (target stays at the
        // floor of 2), it does not count as a replica (one sound holder), so
        // exactly one new holder is placed, and it is never the faulty one.
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].target, 2);
        assert_ne!(plan[0].provider, Address::new([2; 32]));
    }

    #[test]
    fn every_node_computes_the_same_plan() {
        let providers = [
            provider(1, &[(0, 5_000)]),
            provider(2, &[(0, 5_000)]),
            provider(3, &[]),
            provider(4, &[]),
            provider(5, &[]),
        ];
        let view = MoeShardView::build("m", providers.iter());
        let mut a: Vec<Address> = providers.iter().map(|p| p.address).collect();
        let plan_a = plan_placement(&view, &policy(), &a, &HashSet::new());
        a.reverse();
        let plan_b = plan_placement(&view, &policy(), &a, &HashSet::new());
        assert_eq!(plan_a, plan_b);
    }

    #[test]
    fn the_meter_decays_toward_zero() {
        let m = ExpertLoadMeter::default();
        let t0 = Instant::now();
        m.record_at("m", 0, 1, 433_000, t0);
        let fresh = m.tps_at("m", 0, 1, t0);
        assert!(fresh > 900 && fresh < 1_100, "{fresh}");
        let later = m.tps_at("m", 0, 1, t0 + Duration::from_secs(600));
        assert!(later < fresh / 3, "{later}");
        assert_eq!(m.tps("m", 0, 2), 0);
    }

    #[test]
    fn a_receipt_key_must_be_the_announced_key() {
        use tenzro_crypto::composite::{HybridSigner, testing::TestHybridSigner};
        let a = TestHybridSigner::hybrid(1).public_key().clone();
        let b = TestHybridSigner::hybrid(2).public_key().clone();
        let a_classical =
            tenzro_crypto::composite::CompositePublicKey::new(a.p256.clone(), None).unwrap();
        assert!(receipt_key_is_announced(&a, Some(&a)));
        assert!(!receipt_key_is_announced(&a, Some(&b)));
        assert!(!receipt_key_is_announced(&a, None));
        assert!(!receipt_key_is_announced(&a, Some(&a_classical)));
    }
}
