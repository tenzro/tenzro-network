//! Core Tenzro Network node implementation

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use tenzro_bridge::route::RouteFramework;
use tenzro_consensus::{EpochManager, ValidatorInfo};
use tenzro_identity::IdentityRegistry;
#[cfg(feature = "inference")]
use tenzro_model::{
    AudioRuntime, DetectionRuntime, ModelRuntime, SegmentationRuntime, TextEmbeddingRuntime,
    TextSegmentationRuntime, TimeseriesRuntime, VideoRuntime, VisionRuntime,
};
use tenzro_model::{HfDownloader, InferenceRouter, ModelRegistry, MtpKind, ProviderManager};
use tenzro_network::{MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService};
use tenzro_payments::gateway::TenzroPaymentGateway;
use tenzro_payments::mpp::server::MppPaymentServer;
use tenzro_payments::traits::PaymentGateway as PaymentGatewayTrait;
use tenzro_payments::x402::server::X402PaymentServer;
use tenzro_storage::{CF_MODEL_SERVICES, CF_MODELS, KvStore, RocksDbStore};
use tenzro_tee::{TeeProvider, TeeRegistry, detect_tee};
use tenzro_token::{NetworkTreasury, TnzoToken, TokenRegistry};
use tenzro_types::model::{ModelLocation, ModelServiceInstance, ServiceStatus};
use tenzro_types::{RoleSet, primitives::Address};
use tenzro_vm::{MultiVmRuntime, VmConfig, eip1559::FeeMarket};
use tenzro_wallet::TenzroWalletService;

use crate::config::NodeConfig;
use crate::consensus_driver::ConsensusHandle;
use crate::error::{NodeError, Result};
use crate::event_loop::{EventLoop, NodeEvent};
use crate::health::HealthMonitor;
use crate::metrics::MetricsCollector;

use dashmap::DashMap;
use sha2::{Digest, Sha256};

/// Length of an epoch in blocks (the height schedule; epochs also end on
/// the elapsed-time bound).
const EPOCH_DURATION_BLOCKS: u64 = 10_000;

/// Removes an equivocating validator from the committee rotation.
///
/// Block execution calls it when it replays a `CheckpointEquivocation` log
/// (a validator signed two different checkpoints with one index), so every
/// node acts at the same height. The slash itself is applied in consensus
/// state by the transaction that recorded the evidence; this drops the
/// validator from the next epoch's pending queue and jails it in the
/// validator registry.
pub struct EquivocationJailer {
    /// Epoch manager, whose next-epoch pending queue loses the validator.
    epoch_manager: Arc<EpochManager>,
    /// Permissionless validator registry. When wired, the validator is
    /// `jail()`ed so the next epoch transition cannot re-promote it until
    /// the jail period elapses.
    validator_registry: Option<Arc<tenzro_token::validator_registry::ValidatorRegistry>>,
}

impl EquivocationJailer {
    pub fn new(epoch_manager: Arc<EpochManager>) -> Self {
        Self {
            epoch_manager,
            validator_registry: None,
        }
    }

    /// Attach the permissionless validator registry so slashed validators are
    /// also flipped to `Jailed` status in the registry.
    pub fn with_validator_registry(
        mut self,
        registry: Arc<tenzro_token::validator_registry::ValidatorRegistry>,
    ) -> Self {
        self.validator_registry = Some(registry);
        self
    }
}

impl EquivocationJailer {
    /// Drops `validator`, which signed two checkpoints with index `index` in
    /// epoch `epoch`, from the next epoch's pending queue and jails it in the
    /// registry.
    pub fn report_checkpoint_equivocation(
        &self,
        validator: &Address,
        epoch: u64,
        index: u64,
        current_epoch: u64,
    ) {
        self.epoch_manager.remove_pending_validator(validator);
        let Some(registry) = self.validator_registry.as_ref() else {
            return;
        };
        match registry.jail(validator, current_epoch) {
            Ok(()) => tracing::warn!(
                validator = %validator,
                epoch,
                index,
                "Jailed validator for signing two checkpoints with one index"
            ),
            Err(e) => tracing::debug!(
                validator = %validator,
                index,
                error = %e,
                "Equivocating validator is not in the validator registry"
            ),
        }
    }
}

/// Node-level set of validator identities.
///
/// Answers whether an Ed25519 node key belongs to an active validator: the
/// live epoch's validator set once consensus runs, the genesis validator set
/// before that. The set is updated as the validator set changes across epochs.
pub struct NodeValidatorRegistry {
    /// Validator identity Ed25519 public keys seeded from the genesis
    /// validator set. Used as the identity check before (or without) a live
    /// consensus engine.
    genesis_identities: DashMap<Vec<u8>, ()>,
    /// Live epoch manager handle, installed once consensus is initialized.
    /// When present, identity checks consult the CURRENT epoch validator set
    /// so that validators admitted after genesis (stake-based joins) are
    /// recognized and validators rotated out stop being admitted.
    epoch_manager: parking_lot::RwLock<Option<Arc<EpochManager>>>,
}

impl Default for NodeValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeValidatorRegistry {
    /// Creates a new empty validator registry
    pub fn new() -> Self {
        Self {
            genesis_identities: DashMap::new(),
            epoch_manager: parking_lot::RwLock::new(None),
        }
    }

    /// Seeds a validator identity Ed25519 public key (from genesis config).
    pub fn add_identity(&self, ed25519_pubkey: Vec<u8>) {
        self.genesis_identities.insert(ed25519_pubkey, ());
    }

    /// Installs the live epoch manager so identity checks track the current
    /// epoch validator set instead of the static genesis set.
    pub fn set_epoch_manager(&self, epoch_manager: Arc<EpochManager>) {
        *self.epoch_manager.write() = Some(epoch_manager);
    }

    /// Checks whether an Ed25519 public key is the registered node key of an
    /// active validator. Consults the live epoch
    /// validator set when consensus is running (so stake-based joins and
    /// rotations are tracked), falling back to the genesis validator
    /// identities otherwise.
    pub fn is_validator_identity(&self, ed25519_pubkey: &[u8]) -> bool {
        if let Some(epoch_manager) = self.epoch_manager.read().as_ref() {
            let epoch = epoch_manager.current_epoch();
            return epoch
                .validator_set
                .iter()
                .any(|v| v.is_active() && v.node_key.as_slice() == ed25519_pubkey);
        }
        self.genesis_identities.contains_key(ed25519_pubkey)
    }
}

/// Hardware profile detected from the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_threads: usize,
    pub total_ram_gb: f64,
    pub gpus: Vec<tenzro_types::hardware::GpuDevice>,
    pub storage_available_gb: f64,
    pub tee_available: bool,
    pub tee_vendor: Option<String>,
    pub os: String,
    pub arch: String,
    pub device_fingerprint: String,
    /// Hex SHA-256 over the machine's per-unit hardware identifiers (SMBIOS
    /// system UUID, baseboard serial, NVIDIA GPU UUIDs).
    ///
    /// `None` when none of those are readable — a container without
    /// `/sys/class/dmi`, an unprivileged process on a host with no GPU, or
    /// macOS. Unlike `device_fingerprint`, which hashes a description of the
    /// hardware class, this identifies the individual unit.
    pub hardware_root: Option<String>,
    /// Labels of the identifier sources behind `hardware_root`, e.g.
    /// `["dmi:product_uuid", "gpu:uuid"]`. Never carries serial values.
    pub hardware_root_sources: Vec<String>,
}

/// A resource profile bound to a time window.
///
/// Extends the single provider-wide window into a schedule of named profiles:
/// "off-hours" runs the full model set at a high resident ceiling, "workday"
/// keeps the node for its owner. The profile names an existing tenzro-mode
/// profile (a resident ceiling + model set) rather than inlining a second copy
/// of those numbers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceWindow {
    pub name: String,
    pub start_hour: u8,
    pub end_hour: u8,
    /// Per-window timezone: two audiences live in two zones, so the window a
    /// user schedules is in the audience's clock, not the node's.
    pub timezone: String,
    pub days_of_week: [bool; 7],
    /// Resident ceiling for this window, in GiB. Applied HOT via
    /// MemoryBudget::set_resident_ceiling — no node restart.
    pub resident_ceiling_gb: u32,
    /// Models to hold resident during this window.
    pub models: Vec<String>,
}

impl ResourceWindow {
    /// Whether `hour` on `weekday` (0=Mon) falls in this window.
    ///
    /// Handles a window that wraps midnight (start > end), e.g. 17:00-09:00.
    ///
    /// Private: both arguments must already be in THIS window's timezone, and
    /// only [`Self::contains_at`] knows how to produce them. A public version
    /// invited callers to pass a UTC clock, which is the bug this replaced.
    fn contains(&self, weekday: usize, hour: u8) -> bool {
        if !self.days_of_week[weekday] {
            return false;
        }
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            hour >= self.start_hour || hour < self.end_hour
        }
    }

    /// The IANA zone this window is scheduled in, or UTC if the string does not
    /// name one.
    ///
    /// An unparseable zone falls back to UTC rather than erroring: a typo in
    /// one window must not take the scheduler down, and UTC is the value the
    /// field defaults to anyway.
    pub fn tz(&self) -> chrono_tz::Tz {
        self.timezone
            .parse::<chrono_tz::Tz>()
            .unwrap_or(chrono_tz::UTC)
    }

    /// Whether `instant` falls in this window, evaluated in the window's OWN
    /// timezone.
    ///
    /// `timezone` is applied here: a fixed UTC offset cannot express a zone
    /// such as `Europe/Berlin`, whose offset changes with the season.
    pub fn contains_at(&self, instant: chrono::DateTime<chrono::Utc>) -> bool {
        use chrono::{Datelike, Timelike};
        let local = instant.with_timezone(&self.tz());
        let weekday = local.weekday().num_days_from_monday() as usize;
        self.contains(weekday, local.hour() as u8)
    }

    /// When this window next ends, at or after `instant`, in UTC.
    ///
    /// Returns `None` if the window is not active at `instant`. Consumers use
    /// this to plan around a switch — draining in-flight work before the models
    /// are unloaded — rather than discovering the change through failures.
    ///
    /// Resolved by walking forward hour by hour (max 8 days, which covers any
    /// weekly pattern including a wrap-midnight window on a single active day)
    /// and converting back through the zone each step, so a DST transition
    /// inside the window is handled by the same conversion as everything else.
    pub fn ends_after(
        &self,
        instant: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        use chrono::Timelike;
        if !self.contains_at(instant) {
            return None;
        }
        let mut probe = instant;
        for _ in 0..(24 * 8) {
            let next = probe + chrono::Duration::hours(1);
            if !self.contains_at(next) {
                // Truncate to the hour boundary: the window ends on the hour,
                // not at the arbitrary minute the probe happens to land on.
                return next
                    .with_minute(0)
                    .and_then(|t| t.with_second(0))
                    .and_then(|t| t.with_nanosecond(0));
            }
            probe = next;
        }
        None
    }

    /// When this window next starts, strictly after `instant`, in UTC.
    ///
    /// `None` if it never starts within the next 8 days (e.g. `days_of_week`
    /// is all-false, which is a validly-expressible "never").
    pub fn starts_after(
        &self,
        instant: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        use chrono::Timelike;
        let mut probe = instant;
        let mut was_in = self.contains_at(instant);
        for _ in 0..(24 * 8) {
            probe += chrono::Duration::hours(1);
            let now_in = self.contains_at(probe);
            if now_in && !was_in {
                return probe
                    .with_minute(0)
                    .and_then(|t| t.with_second(0))
                    .and_then(|t| t.with_nanosecond(0));
            }
            was_in = now_in;
        }
        None
    }
}

/// What a reconcile pass should apply, computed from the active window.
///
/// Pure data — the loop that owns MemoryBudget and the model registry acts on
/// it, so the decision is testable without a running node.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduleAction {
    /// The resident ceiling to set, in bytes. None = leave the base default.
    pub resident_ceiling_bytes: Option<u64>,
    /// Models that should be resident now.
    pub want_models: Vec<String>,
    /// The active window's name, for logging. None = no window active.
    pub active_window: Option<String>,
}

/// Provider scheduling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSchedule {
    pub enabled: bool,
    pub start_hour: u8,
    pub end_hour: u8,
    pub timezone: String,
    pub days_of_week: [bool; 7], // Mon-Sun
    /// Resource/model windows. Empty = today's behaviour (availability only).
    #[serde(default)]
    pub windows: Vec<ResourceWindow>,
}

/// What a model declares it needs, across every modality catalog.
///
/// Returns `None` for an id no catalog knows, which the caller reports rather
/// than treating as zero — a typo that silently contributed nothing would make
/// an over-committed window look like it fits.
fn declared_min_ram_gb(id: &str) -> Option<u32> {
    if let Some(e) = tenzro_model::catalog::get_model_by_id(id) {
        return Some(e.min_ram_gb);
    }
    if let Some(e) = tenzro_model::catalog::get_vision_model_by_id(id) {
        return Some(e.min_ram_gb);
    }
    if let Some(e) = tenzro_model::catalog::get_embed_model_by_id(id) {
        return Some(e.min_ram_gb);
    }
    if let Some(e) = tenzro_model::catalog::get_segmentation_model_by_id(id) {
        return Some(e.min_ram_gb);
    }
    // The embedding and forecast catalogs declare no RAM figure. They are
    // recognised so a real id is never reported as a typo, and counted as 0
    // because inventing a number would corrupt the very total this check
    // exists to protect. Both are sub-gigabyte ONNX models, so the error is
    // small and in the safe direction — it can only make a window look
    // slightly emptier than it is, never fuller.
    if tenzro_model::catalog::get_text_embedding_model_by_id(id).is_some()
        || tenzro_model::catalog::get_forecast_model_by_id(id).is_some()
    {
        return Some(0);
    }
    None
}

/// A window that asks for more than it is allowed to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowOvercommit {
    pub window: String,
    /// What the members need together, in GiB.
    pub required_gb: u64,
    /// What the window permits.
    pub ceiling_gb: u32,
    /// The members counted, so an operator can see which to drop.
    pub members: Vec<(String, u32)>,
    /// Members named in the window that the catalog does not know. Reported
    /// rather than ignored: a typo silently reduces the total and would make
    /// an over-committed window look like it fits.
    pub unknown: Vec<String>,
}

impl std::fmt::Display for WindowOvercommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "window '{}' holds {} models needing {} GiB together, but its \
             resident ceiling is {} GiB",
            self.window,
            self.members.len(),
            self.required_gb,
            self.ceiling_gb
        )?;
        if !self.unknown.is_empty() {
            write!(f, " (unrecognised: {})", self.unknown.join(", "))?;
        }
        Ok(())
    }
}

impl ProviderSchedule {
    /// Refuse a schedule the machine could not honour.
    ///
    /// A window names models and a ceiling to hold them in. Nothing previously
    /// compared the two, so a window whose members could never fit was accepted
    /// at configuration time and discovered at the window boundary — as a
    /// stall, on a machine that by then had a stack half-loaded. The failure
    /// was hours away from the edit that caused it and looked nothing like it.
    ///
    /// Checking here turns that into an error the operator sees while still
    /// looking at the schedule they typed.
    ///
    /// Deliberately arithmetic on declared sizes, not a live memory reading:
    /// this answers "is this schedule self-consistent", which is a property of
    /// the configuration and true or false regardless of what the machine is
    /// doing right now. Whether the machine can honour it *at this moment* is a
    /// different question, asked at load time against measured ground.
    pub fn overcommitted_windows(&self) -> Vec<WindowOvercommit> {
        self.windows
            .iter()
            .filter(|w| w.resident_ceiling_gb > 0 && !w.models.is_empty())
            .filter_map(|w| {
                let mut members = Vec::new();
                let mut unknown = Vec::new();
                for id in &w.models {
                    // A stack mixes modalities — one may serve a text
                    // model, a vision-language model, an embedding model and a
                    // forecaster together — so every catalog is consulted
                    // rather than only the text one.
                    match declared_min_ram_gb(id) {
                        Some(gb) => members.push((id.clone(), gb)),
                        None => unknown.push(id.clone()),
                    }
                }
                let required_gb: u64 = members.iter().map(|(_, gb)| *gb as u64).sum();
                if required_gb > w.resident_ceiling_gb as u64 {
                    Some(WindowOvercommit {
                        window: w.name.clone(),
                        required_gb,
                        ceiling_gb: w.resident_ceiling_gb,
                        members,
                        unknown,
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for ProviderSchedule {
    fn default() -> Self {
        Self {
            enabled: false,
            start_hour: 0,
            end_hour: 24,
            timezone: "UTC".to_string(),
            days_of_week: [true; 7],
            windows: Vec::new(),
        }
    }
}

impl ProviderSchedule {
    /// The first window active at `instant`, each evaluated in its OWN
    /// timezone. Ordered; first match wins.
    pub fn active_window_at(
        &self,
        instant: chrono::DateTime<chrono::Utc>,
    ) -> Option<&ResourceWindow> {
        self.windows.iter().find(|w| w.contains_at(instant))
    }

    /// The window that starts soonest after `instant`, with its start time.
    ///
    /// Ties break on window order, matching `active_window_at`'s first-match
    /// rule, so "what runs next" agrees with what will actually be selected.
    pub fn next_window_at(
        &self,
        instant: chrono::DateTime<chrono::Utc>,
    ) -> Option<(&ResourceWindow, chrono::DateTime<chrono::Utc>)> {
        self.windows
            .iter()
            .filter_map(|w| w.starts_after(instant).map(|t| (w, t)))
            .min_by_key(|(_, t)| *t)
    }

    /// What to apply at `instant`, resolving windows in their own timezones.
    pub fn action_now(&self, instant: chrono::DateTime<chrono::Utc>) -> ScheduleAction {
        match self.active_window_at(instant) {
            Some(w) => ScheduleAction {
                resident_ceiling_bytes: Some(u64::from(w.resident_ceiling_gb) * 1024 * 1024 * 1024),
                want_models: w.models.clone(),
                active_window: Some(w.name.clone()),
            },
            None => ScheduleAction {
                resident_ceiling_bytes: None,
                want_models: Vec::new(),
                active_window: None,
            },
        }
    }
}

/// Default storage byte-epoch rate (wei) a freshly-spawned storage provider
/// charges before any operator override or dynamic-pricing switch. 1000 wei per
/// byte-epoch ≈ 0.001 TNZO to store 1 GiB for one epoch.
pub const DEFAULT_STORAGE_RATE_PER_BYTE_EPOCH: u128 = 1_000;

/// Default compute per-epoch rate (wei) a freshly-spawned compute provider
/// charges before any operator override or dynamic-pricing switch.
pub const DEFAULT_COMPUTE_RATE_PER_EPOCH: u128 = 1_000_000_000_000;

/// Length of one provider billing epoch: one chain hour, the unit compute
/// claims and SLA verdicts settle on.
pub const BILLING_EPOCH_INTERVAL_SECS: u64 = 3_600;

/// Rendezvous (HRW) replica set size for shard self-selection. This is the
/// top-`R` cut a storage-serving node applies when deciding which shards of an
/// announced object it should hold. It matches the default erasure scheme's
/// total shard count (4 data + 2 parity) so a node's expected share of any
/// object is one shard, and the union of every node's self-selected set covers
/// all shards under a converged membership view.
pub const DEFAULT_STORAGE_REPLICAS: usize = 6;

/// Minimum verified free disk (GB) a node must have to advertise the
/// StorageProvider role. Below this there is no point accepting deals — the
/// node could not honor a single redundancy slot. Storage is permissionless
/// but capacity is the one thing it cannot fake, so this is a hard floor.
pub const MIN_STORAGE_PROVIDER_FREE_GB: f64 = 10.0;

/// The operator's price cards: one that applies to every model this node
/// serves, and per-model cards that replace it for one model. Each is a
/// [`tenzro_types::price_card::RateCard`]: a price per unit (or unit at a
/// tier), in TNZO base units or in billionths of a dollar settled at the
/// chain's TNZO/USD rate. The operator sets every price; the network sets
/// none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderPricing {
    /// The card for any model without its own.
    pub default: tenzro_types::price_card::RateCard,
    /// Cards for single models, by catalog id.
    #[serde(default)]
    pub models: std::collections::BTreeMap<String, tenzro_types::price_card::RateCard>,
}

impl ProviderPricing {
    /// The card `model_id` is priced on.
    pub fn card_for(&self, model_id: &str) -> &tenzro_types::price_card::RateCard {
        self.models.get(model_id).unwrap_or(&self.default)
    }
}

impl Default for ProviderPricing {
    fn default() -> Self {
        Self {
            default: default_rate_card(),
            models: std::collections::BTreeMap::new(),
        }
    }
}

/// The card a node starts with when its operator has set none, in TNZO base
/// units: 0.0001 TNZO per input token, 0.0002 per output or hidden token, and
/// a price for every other unit the engines meter.
pub fn default_rate_card() -> tenzro_types::price_card::RateCard {
    use tenzro_types::meter::unit;
    use tenzro_types::price_card::{Denom, Rate, RateCard};
    let lines: [(&str, u128, u8); 19] = [
        (unit::INPUT_TOKENS, 100_000_000_000_000, 0),
        (unit::OUTPUT_TOKENS, 200_000_000_000_000, 0),
        (unit::REASONING_TOKENS, 200_000_000_000_000, 0),
        (unit::CACHED_READ_TOKENS, 10_000_000_000_000, 0),
        (unit::CACHED_WRITE_TOKENS, 300_000_000_000_000, 0),
        (unit::REASONING_LOOPS, 1_000_000_000_000_000, 0),
        (unit::IMAGE_TOKENS, 100_000_000_000_000, 0),
        // Per second of a millisecond unit.
        (unit::AUDIO_MS, 500_000_000_000_000, 3),
        (unit::VIDEO_MS, 1_000_000_000_000_000, 3),
        (unit::AUDIO_OUT_MS, 1_000_000_000_000_000, 3),
        // Generative media, world models and policies included, is priced
        // on its denoising work; their native units ride along unpriced.
        (unit::PIXEL_STEPS, 1_000_000_000, 0),
        (unit::FRAMES, 100_000_000_000_000, 0),
        (unit::CHARACTERS, 10_000_000_000_000, 0),
        (unit::RERANK_PAIRS, 50_000_000_000_000, 0),
        (unit::DECISION_QUESTIONS, 20_000_000_000_000, 0),
        (unit::TRAINED_TOKENS, 300_000_000_000_000, 0),
        (unit::FORECAST_POINTS, 200_000_000_000_000, 0),
        (unit::SESSION_MS, 100_000_000_000_000, 3),
        (unit::REQUESTS, 1_000_000_000_000_000, 0),
    ];
    RateCard {
        denom: Denom::Wei,
        lines: lines
            .into_iter()
            .map(|(k, p, e)| (k.to_string(), Rate::per(p, e)))
            .collect(),
        min_charge: 0,
    }
}

/// A card that prices every genesis billable unit at zero, for a model
/// offered at no charge (a non-commercial licence).
pub fn free_rate_card() -> tenzro_types::price_card::RateCard {
    use tenzro_types::price_card::{Denom, Rate, RateCard};
    RateCard {
        denom: Denom::Wei,
        lines: tenzro_types::meter::genesis_units()
            .into_iter()
            .filter(|u| u.billable)
            .map(|u| (u.id, Rate::per(0, 0)))
            .collect(),
        min_charge: 0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDownloadStatus {
    pub model_id: String,
    pub status: String, // "downloading", "completed", "failed", "not_started"
    pub progress_percent: f64,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// User resource tracking (models being used from providers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResource {
    pub resource_type: String,
    pub resource_id: String,
    pub added_at: u64,
}

/// Transaction history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryEntry {
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub asset: String,
    pub status: String,
    pub timestamp: u64,
    pub tx_type: String,
}

/// A model discovered via gossip from a remote provider.
/// Entries expire if not refreshed within `ttl_secs`.
#[derive(Debug, Clone)]
pub struct NetworkModelEntry {
    pub registration: tenzro_network::ModelRegistrationMessage,
    pub last_seen: std::time::Instant,
}

/// A provider discovered via gossip from a remote node.
/// Entries expire if not refreshed within `ttl_secs`.
#[derive(Debug, Clone)]
pub struct NetworkProviderEntry {
    pub announcement: tenzro_network::ProviderAnnouncementMessage,
    pub last_seen: std::time::Instant,
    /// The live load of each model it serves, from its latest accepted
    /// heartbeat: `(heartbeat time ms, loads)`.
    pub live_load: Option<(i64, Vec<tenzro_types::provider_listing::ModelLoad>)>,
}

/// The startup error for a subsystem whose persisted state exists but cannot
/// be read or decoded. Startup stops rather than running on empty state.
fn state_load_error(subsystem: &str, cause: impl std::fmt::Display) -> NodeError {
    NodeError::InvalidState(format!(
        "{subsystem}: stored state could not be loaded ({cause}); the node will not start on empty state"
    ))
}

/// The hardware key the node's batch signing service signs with: the
/// machine identity key, the one its machine DID derives from and is
/// registered under, so receivers verifying against the registered key
/// accept what is signed.
pub(crate) const SESSION_KEY_LABEL: &str = tenzro_types::did_derivation::MACHINE_KEY_LABEL;

/// This machine as an operator: its DID (from the hardware machine key) and
/// the ledger account of its hardware wallet key (TPM or Secure Enclave
/// P-256). The node earns into that account and bonds its roles from it when
/// no identity names another; naming the machine DID as `operator_did` names
/// that account.
#[derive(Clone)]
struct MachineOperator {
    did: Option<String>,
    account: Address,
}

fn machine_operator_of(
    identity_signer: Option<&Arc<dyn tenzro_crypto::composite::HybridSigner>>,
) -> Option<MachineOperator> {
    identity_signer.map(|s| MachineOperator {
        did: crate::identity_bootstrap::machine_did(),
        account: Address::new(s.public_key().account_slot()),
    })
}

/// The (DID, wallet) pair this node earns as, both taken from the same
/// identity so an announcement's DID and payee never disagree.
///
/// Free rather than a method so background tasks that outlive a `&self`
/// borrow can re-derive it per tick — an identity provisioned after
/// startup has to be picked up without a restart.
fn resolve_operator_identity(
    identity_registry: Option<&Arc<IdentityRegistry>>,
    machine: Option<&MachineOperator>,
    configured: Option<&str>,
) -> Option<(String, Address)> {
    use tenzro_identity::{IdentityData, IdentityStatus};

    let configured = configured.map(str::trim).filter(|d| !d.is_empty());
    // The machine itself, named as its own operator: its wallet is the
    // account its hardware key signs for, with no registry entry needed.
    if let (Some(did), Some(m)) = (configured, machine)
        && m.did.as_deref() == Some(did)
    {
        return Some((did.to_string(), m.account));
    }

    let registry = identity_registry?;
    let all = registry.list_all();
    let usable = |identity: &tenzro_identity::TenzroIdentity| {
        identity.status == IdentityStatus::Active && identity.wallet_address != Address::default()
    };

    // Named by the operator — no inference to do. Honoured ahead of the
    // wallet match so that naming an identity is decisive rather than advisory.
    if let Some(did) = configured {
        match all.iter().find(|(d, id)| d.as_str() == did && usable(id)) {
            Some((d, id)) => return Some((d.clone(), id.wallet_address)),
            None => warn!(
                "config names operator_did={did}, but this node's registry has no active \
                 identity by that DID with a wallet — falling back to inference"
            ),
        }
    }

    if let Some(wallet) = machine.map(|m| m.account)
        && let Some((did, _)) = all
            .iter()
            .filter(|(_, id)| usable(id) && id.wallet_address == wallet)
            .min_by(|a, b| a.0.cmp(&b.0))
    {
        return Some((did.clone(), wallet));
    }

    // Lower rank wins; ties break on the DID string.
    //
    // Machines outrank humans because a node *is* a machine. TDIP models a
    // node as `did:tenzro:machine:<controller>:<uuid>` when a human operator
    // delegates it, or `did:tenzro:machine:<device-key-id>` when it acts on its own;
    // a `did:tenzro:human:` identity denotes the person operating it, not the
    // hardware. Ranking humans first — as this did — meant a node whose
    // operator had registered themselves published its DID document under
    // *their* identity, and attributed every file, database and site it holds
    // to a person rather than to the machine.
    //
    // A delegated machine outranks an autonomous one: if a controller exists
    // there is an accountable human behind the node, which is the more
    // informative of the two identities to present.
    //
    // This is still inference — see `NodeConfig::operator_did` for naming it
    // outright, which is what a node with several enrolled machines needs.
    let rank = |data: &IdentityData| match data {
        IdentityData::Machine {
            controller_did: Some(_),
            ..
        } => 0u8,
        IdentityData::Machine {
            controller_did: None,
            ..
        } => 1,
        IdentityData::Human { .. } | IdentityData::Institution { .. } => 2,
    };

    // A node with a hardware wallet accepts an inferred identity only when it
    // is its own: the registry mirrors every identity on the chain, so ranking
    // all of them would hand an unregistered node the best-ranked stranger's
    // DID and account. Otherwise the caller falls back to the machine's
    // own account.
    let own_did = machine.map(|m| m.did.as_deref());
    all.iter()
        .filter(|(d, id)| usable(id) && own_did.is_none_or(|own| own == Some(d.as_str())))
        .min_by(|a, b| {
            rank(&a.1.identity_data)
                .cmp(&rank(&b.1.identity_data))
                .then_with(|| a.0.cmp(&b.0))
        })
        .map(|(did, id)| (did.clone(), id.wallet_address))
}

/// The wallet this node is paid at. See [`TenzroNode::operator_payee`] for
/// the resolution order.
fn resolve_operator_payee(
    identity_registry: Option<&Arc<IdentityRegistry>>,
    machine: Option<&MachineOperator>,
    configured: Option<&str>,
) -> Option<Address> {
    match resolve_operator_identity(identity_registry, machine, configured) {
        Some((_, wallet)) => Some(wallet),
        None => machine.map(|m| m.account),
    }
}

/// Runs the validator registry's epoch plan into the epoch manager's pending
/// queues, immediately before consensus computes the next committee.
///
/// Consensus owns the transition and knows nothing about the registry; this
/// is the seam between them.
pub(crate) struct RegistryEpochPlanStager {
    pub(crate) epoch_manager: Arc<tenzro_consensus::EpochManager>,
    pub(crate) registry: Arc<tenzro_token::validator_registry::ValidatorRegistry>,
    /// Chain state, for the governed validator self-stake the epoch gate
    /// admits candidates at, with its USD floor at the safety rate, and the
    /// governed exit churn.
    pub(crate) store: Option<Arc<dyn KvStore>>,
}

impl crate::consensus_driver::EpochPlanner for RegistryEpochPlanStager {
    fn unstage_next_epoch(&self, token: &str) {
        if let Err(e) = self.registry.restore_undo(token) {
            tracing::error!(error = %e, "The validator registry could not be put back after a failed derivation; the next try puts it back first");
        }
    }

    fn stage_next_epoch(&self) -> std::result::Result<String, String> {
        // How the registry stands before this boundary changes it, kept once
        // per boundary and first of all: the governed settings, the release of
        // jailed validators, the ejections and the status steps all follow.
        // When the record is already there an earlier staging ran: the
        // registry is put back as the record holds it before anything is
        // applied, and staging does not go on until that has worked, so a
        // staging that is repeated, or that follows a failed undo, never
        // applies the boundary twice.
        let tag = format!("boundary:{}", self.epoch_manager.current_epoch().number + 1);
        if self
            .registry
            .has_undo(&tag)
            .map_err(|e| format!("the undo record could not be looked for: {e}"))?
        {
            self.registry
                .restore_undo(&tag)
                .map_err(|e| format!("the registry could not be put back before staging: {e}"))?;
        } else {
            self.registry.clear_undo_prefix("boundary:");
            if !self.registry.write_undo(&tag, &self.registry.checkpoint()) {
                return Err(self
                    .registry
                    .take_storage_error()
                    .unwrap_or_else(|| "the undo record could not be written".to_string()));
            }
        }
        if let Some(store) = &self.store {
            let chain = tenzro_vm::StateAdapter::with_storage(store.clone());
            let ladder = tenzro_vm::native::entry_stake_ladder(&chain);
            let floor = ladder.validator;
            // A validator that also serves RPC holds the governed RPC operator
            // bond, `stake.rpc_tnzo`, as the rest of the network requires it.
            let rpc_floor = ladder.rpc;
            let exit_churn = u32::try_from(tenzro_vm::native::network_param(
                &chain,
                tenzro_vm::native::EXIT_CHURN_PARAM,
            ))
            .unwrap_or(u32::MAX);
            let jail_term =
                tenzro_vm::native::network_param(&chain, tenzro_vm::native::JAIL_TERM_PARAM);
            let mut cfg = self.registry.config();
            if cfg.min_self_stake != floor
                || cfg.min_rpc_provider_stake != rpc_floor
                || cfg.exit_churn_bps != exit_churn
                || cfg.jail_term_epochs != jail_term
            {
                cfg.min_self_stake = floor;
                cfg.min_rpc_provider_stake = rpc_floor;
                cfg.exit_churn_bps = exit_churn;
                cfg.jail_term_epochs = jail_term;
                self.registry.set_config(cfg);
            }
        }
        let chain = self
            .store
            .as_ref()
            .map(|store| tenzro_vm::StateAdapter::with_storage(store.clone()));
        // Jailed validators whose term has run out, or that governance
        // reinstated, return to candidacy before the plan admits candidates.
        if let Some(chain) = chain.as_ref() {
            let epoch = self.epoch_manager.current_epoch().number.saturating_add(1);
            let reinstated = |who: &tenzro_types::primitives::Address, jailed_at: u64| {
                tenzro_vm::native::reinstated_at_epoch(chain, who.as_bytes())
                    .is_some_and(|at| at >= jailed_at)
            };
            let released = self.registry.release_jailed(epoch, &reinstated);
            if !released.is_empty() {
                info!(count = released.len(), "Jailed validators released");
            }
        }
        // Validators gone for the governed number of epochs leave before the
        // plan is computed, so their exit completes at this boundary.
        if let Some(chain) = chain.as_ref() {
            let policy = tenzro_token::InactivityPolicy {
                max_missed_epochs: tenzro_vm::native::network_param(
                    chain,
                    tenzro_vm::native::INACTIVITY_LIMIT_PARAM,
                ),
                keep_active_at_least: usize::try_from(tenzro_vm::native::network_param(
                    chain,
                    tenzro_vm::native::ACTIVE_FLOOR_PARAM,
                ))
                .unwrap_or(usize::MAX),
            };
            if policy.max_missed_epochs > 0
                && let Ok(counts) = tenzro_vm::native::read_missed_epochs(chain)
            {
                let ejected = self.registry.eject_inactive(&policy, &counts);
                if !ejected.is_empty() {
                    info!(count = ejected.len(), "Inactive validators moved to exit");
                }
            }
        }
        let admitted = |ml_dsa: &[u8]| {
            let Some((scheme, _)) =
                tenzro_types::signature_scheme::SignatureScheme::split_public_key(ml_dsa)
            else {
                return false;
            };
            chain
                .as_ref()
                .is_none_or(|c| tenzro_vm::native::scheme_admitted(c, scheme))
        };
        crate::event_loop::EventLoop::stage_registry_epoch_plan(
            &self.epoch_manager,
            &self.registry,
            &admitted,
        );
        // While validator admission is closed no account that is not
        // admitted reaches the next committee, bonded or not.
        if let Some(chain) = chain.as_ref() {
            let refused = crate::validator_admission::enforce_committee(&self.epoch_manager, chain);
            if !refused.is_empty() {
                info!(
                    count = refused.len(),
                    "Validator admission is closed: accounts that are not admitted kept off the committee"
                );
            }
        }
        Ok(tag)
    }
}

/// Main Tenzro Network node
/// Block cache of the consensus records store: its records are small and
/// read back mostly at restart.
const CONSENSUS_RECORDS_MEMORY: usize = 32 << 20;
/// Memtable size per column family of the consensus records store.
const CONSENSUS_RECORDS_WRITE_BUFFER: usize = 4 << 20;

/// A rewrite of a load sample, shared with the monitor's thread.
pub type LoadReading = Arc<dyn Fn(&mut crate::load_monitor::LoadSample) + Send + Sync>;

pub struct TenzroNode {
    config: NodeConfig,
    pub(crate) state: Arc<RwLock<NodeState>>,

    // Core infrastructure
    storage: Option<Arc<RocksDbStore>>,
    /// This validator's consensus records (journal, vote boundaries,
    /// certificates, the vote high-water mark), in a store of their own under
    /// `<data_dir>/consensus` that shares no memory limit or write queue with
    /// the node's store.
    consensus_records: Option<Arc<RocksDbStore>>,
    network: Option<Arc<TenzroNetworkService>>,

    /// Consensus: mempool, finality and certificates on every networked node;
    /// the protocol core on a validator.
    consensus: Option<Arc<ConsensusHandle>>,
    /// The validator's hardware-held consensus key, when this machine holds
    /// one. A node without it follows the chain as a full node.
    validator_signer: Option<Arc<dyn tenzro_consensus::ValidatorSigner>>,
    /// The registered key of a validator rotating to `validator_signer`,
    /// while this machine holds it: it signs until the epoch boundary that
    /// seats the rotation.
    outgoing_validator_signer: Option<Arc<dyn tenzro_consensus::ValidatorSigner>>,
    /// Address of the validator this node's hardware key is registered to,
    /// in the genesis committee or the registry. Captured at
    /// `init_consensus()` time.
    local_validator_address: Option<Address>,

    /// The machine's hardware wallet key (TPM or Secure Enclave P-256, with
    /// the hardware ML-DSA-65 key where the chip has one): the node account,
    /// which signs the node's revocations, media receipts and attestations.
    /// `None` on a machine without one.
    identity_signer: Option<Arc<dyn tenzro_crypto::composite::HybridSigner>>,
    /// Open hash-locked delivery offers made at this node's HTTP-402 gates.
    sealed_offers: Arc<crate::sealed_delivery::SealedOffers>,

    /// The committee-resident Red Stuff DA backend, held concretely so the
    /// possession-challenge RPC surface (`tenzro_daChallenge*`) can reach the
    /// custody store and committee snapshot; coerced to `Arc<dyn DaBackend>`
    /// where a trait object is needed. `None` on non-validator roles or when
    /// committee-DA init fails.
    da_committee_backend: Option<Arc<crate::da_committee::DaCommitteeBackend>>,

    /// The objects this node certifies, until `da_retention::spawn` takes
    /// them to record each in consensus state.
    da_recorder_rx: parking_lot::Mutex<
        Option<tokio::sync::mpsc::UnboundedReceiver<crate::da_committee::CertifiedObject>>,
    >,

    /// Background possession-challenge driver: periodically audits a random
    /// committee member's custody of a random held blob and scores the result
    /// into the member's rolling availability score. Aborted on stop.
    da_possession_challenger: Option<crate::da_committee::PossessionChallenger>,

    /// Disk watermark flag, checked before accepting non-essential data.
    disk_guard: Arc<crate::storage_maintenance::DiskGuard>,

    /// The epoch proof log storage maintenance keeps, served over RPC.
    proof_log: Option<Arc<parking_lot::Mutex<crate::proof_log::ProofLog>>>,

    /// Models this node loaded for a demand surge.
    surge_state: crate::surge::SurgeState,

    /// Block history beyond the retention window, held in the committee DA
    /// layer. `None` where this node has no committee DA backend.
    history_archive: Option<Arc<crate::history_archive::HistoryArchive>>,

    /// The durable log of the chain's events, written with each executed
    /// block. `None` until storage is open.
    event_log: Option<Arc<tenzro_events::EventLog>>,

    /// Storage maintenance: retention, epoch snapshots, watermarks. Aborted
    /// on stop.
    storage_maintenance: Option<tokio::task::JoinHandle<()>>,

    /// The operator's own endpoint this node serves the `[connector]`
    /// section's models from, when the configuration has one.
    connector: Option<Arc<crate::connector::Connector>>,

    /// Batched hardware signing of the machine identity key (see `batch_signing`).
    batch_service: Option<Arc<tenzro_crypto::batch::BatchService>>,
    /// The signer every converted record type signs with: the hardware batch
    /// service of the machine identity key.
    records: Option<Arc<dyn tenzro_crypto::batch::RecordSigner>>,

    /// The machine sealing public key, derived on first request and kept, so
    /// answering for it does not reach the hardware per request.
    machine_sealing_public_key: std::sync::OnceLock<tenzro_crypto::hybrid_seal::HybridPublicKey>,

    // Execution layer
    vm_runtime: Option<Arc<MultiVmRuntime>>,

    // Services
    wallet_service: Option<Arc<TenzroWalletService>>,
    token: Option<Arc<TnzoToken>>,
    /// Accounts for the gas the executor debits per transaction. The event
    /// loop settles the fee market's treasury/burn split onto the ledger at
    /// every finalized block and records the movement here.
    fee_processor: Option<Arc<tenzro_token::FeeProcessor>>,
    /// Certifications, operator policies and model provenance.
    trust_ledger: Option<Arc<tenzro_trust::TrustLedger>>,
    /// Assembles the model catalog from the trust ledger.
    catalog_sync: Option<Arc<crate::catalog_sync::CatalogSync>>,
    /// Verifiable-inference commitment store + challenge lifecycle
    /// (TOPLOC scheme). Stores per-response top-k logit commitments
    /// under `commitment/<hash_hex>` and filed disputes under
    /// `challenge/<uuid>` in CF_CHALLENGES. Consulted by the
    /// `tenzro_*InferenceCommitment` / `tenzro_*InferenceChallenge`
    /// RPC handlers; commitments are written by the chat/inference
    /// handlers when the caller passes `verifiable: true`. `Some`
    /// only when RocksDB storage is available.
    challenge_manager: Option<Arc<crate::inference_challenge::ChallengeManager>>,
    /// SLA prober. Owns the validator's VRF signing key (byte-shared with the
    /// validator's Ed25519 identity per RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI)
    /// and issues VRF-stamped probes to providers; scores feed the validator's
    /// `SlaAttest` tally. `Some` only on validator-role nodes; `None` on
    /// ModelProvider / TeeProvider / LightClient. The probe scheduler, gossip `tenzro/sla` topic, and
    /// `tenzro_sla_*` RPC handlers consult this field.
    sla_manager: Option<Arc<tenzro_model::SlaManager>>,
    /// In-flight SLA probes awaiting provider response. Keyed by
    /// `challenge_nonce` (32 bytes hex-encoded for DashMap key ergonomics).
    /// Populated by `tenzro_slaIssueProbe` immediately before broadcasting
    /// the probe over `tenzro/sla`; drained by the gossip subscriber when
    /// a matching `SlaResponse` arrives, or by a periodic timeout sweeper
    /// that scores no-shows as `SlaResult::Missed` past `deadline_ms`.
    /// Empty on non-validator nodes.
    sla_outstanding_probes: Arc<DashMap<String, tenzro_model::SlaProbe>>,
    /// This validator's per-(provider, epoch) probe results, attested on chain
    /// as each epoch closes (`crate::sla_attest`).
    sla_tally: Arc<crate::sla_attest::SlaTally>,
    /// Permissionless ValidatorRegistry (Spec — dynamic validator set).
    /// Holds Candidate / PendingActive / Active / PendingExit / Exited /
    /// Jailed entries with EIP-8061-style churn budgeting. The post-block
    /// scan in `EventLoop::process_validator_logs` mirrors VM-emitted
    /// `ValidatorRegister` / `ValidatorExit` / `ValidatorMetadataUpdate`
    /// logs into this registry; the periodic epoch hook in the event
    /// loop calls `compute_epoch_transition()` and feeds the resulting
    /// plan into the consensus `EpochManager`'s pending queues.
    /// Persists to CF_TOKENS via `ValidatorRegistry::with_storage`.
    validator_registry: Option<Arc<tenzro_token::validator_registry::ValidatorRegistry>>,
    /// WebAuthnValidator — verifies passkey assertions against the passkeys
    /// each account's keystore links in consensus state.
    webauthn_validator: Option<Arc<tenzro_vm::WebAuthnValidator>>,
    /// Pending browser-mediated passkey auth sessions (CLI → browser →
    /// node), indexed by session_id. The CLI creates a session over RPC,
    /// the node-served `/auth/passkey` page completes the WebAuthn ceremony
    /// and posts the outcome back, the CLI polls until terminal. Persists to
    /// `CF_VALIDATOR_MODULES / erc7579/auth_session/` so sessions survive
    /// node restart.
    passkey_sessions: Option<Arc<crate::passkey_rpc::PasskeySessionStore>>,
    /// Adaptive burn governance dial. Holds the
    /// current `BurnRateConfig`, the `SupplyTargets` thresholds, and the
    /// most recent `SupplyMetricsSnapshot`. Read-only RPCs surface the
    /// recommendation produced by `compute_recommendation`; validators
    /// put the generator's drafts to on-chain governance and every node
    /// applies the enacted change here. Persists to CF_TOKENS via
    /// `BurnRateConfigManager::with_storage`.
    burn_rate_manager: Option<Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>>,
    /// Applies the network policy on-chain governance enacts.
    policy_applier: Option<Arc<crate::policy_reflection::PolicyApplier>>,
    treasury: Option<Arc<NetworkTreasury>>,

    /// OAuth 2.1 + DPoP + RAR auth engine. See `tenzro_auth::AuthEngine` for the
    /// trust model and storage layout (CF_AUDIT).
    auth_engine: Option<Arc<tenzro_auth::AuthEngine>>,

    /// Operator access gating: the policy in `access.toml`, the tier meter
    /// and sign-in challenges.
    access: Arc<crate::access::Access>,

    /// The record of every administrative call, kept in the data directory.
    admin_audit: Arc<crate::admin_audit::AdminAudit>,

    /// The shared handle this node is held through, bound once it exists,
    /// for components built before it (the overlay's MoE surface).
    self_ref: Arc<std::sync::OnceLock<std::sync::Weak<TenzroNode>>>,

    /// Payee settlement preferences — what asset each payee wants to be paid
    /// in. Held so the RPC surface can read and mutate them.
    settlement_preferences:
        Option<Arc<crate::settlement_preferences_bridge::NodeSettlementPreferences>>,

    // AI infrastructure
    model_registry: Option<Arc<ModelRegistry>>,
    provider_manager: Option<Arc<ProviderManager>>,
    inference_router: Option<Arc<InferenceRouter>>,
    /// Validator-observed prices, latency and reliability per provider and
    /// model, and the compute price index built from them.
    compute_observations: Arc<crate::compute_observations::ObservationWindow>,
    /// Usage tracker — recipient of every successful inference's
    /// `UsageRecord`. Persists per-model / per-provider / global stats
    /// to RocksDB CF_MODELS via `UsageTracker::with_storage`. Read by
    /// the `tenzro_listInferenceUsage` RPC.
    usage_tracker: Option<Arc<tenzro_model::UsageTracker>>,
    /// EU AI Act Art. 50(2) provenance store. Populated by the inference
    /// router (writer) and queried by the `tenzro_getContentProvenance` RPC
    /// (reader). Shared via `Arc` so both producer and consumer see the
    /// same SHA-256-keyed manifest cache.
    provenance_store: Option<Arc<tenzro_model::ProvenanceStore>>,
    /// Provenance signer used when this node serves a model itself — the
    /// `/v1/chat/completions` handler stamps a `tenzro_contentProvenance` manifest
    /// on locally-generated responses with it. Built from the node's
    /// long-term Ed25519 key so the manifest verifies against the
    /// announcement pubkey consumers pinned.
    provenance_signer: Option<tenzro_model::SharedProvenanceSigner>,
    /// Sealed-model manifest store — write-through cache of
    /// `SealedModelManifest` records under the `sealed:` prefix in
    /// CF_MODELS. Written by the seal/install RPC handlers, read by the
    /// get/list handlers and the unseal path.
    sealed_model_store: Option<Arc<tenzro_model::SealedModelStore>>,
    /// This node's hybrid X25519 + ML-KEM-768 recipient key for sealed model shards, derived on
    /// demand from hardware. Publishers wrap the per-artifact AES-256-GCM
    /// content key to its public half
    /// (`x25519-mlkem768-hkdf-sha256-envelope-aes-256-gcm`); the install path unwraps
    /// through it without holding the private half.
    model_recipient_key: Option<Arc<tenzro_keygen::DerivedHybridRecipient>>,
    /// Jurisdiction signer used when this node serves a model itself — the
    /// chat handlers stamp a `tenzro_jurisdiction` receipt on locally-
    /// generated responses with it. Built from the same long-term Ed25519
    /// key as the provenance signer so receipts verify against the
    /// announcement pubkey consumers pinned. `None` when the operator
    /// declared no jurisdiction or no node key is available.
    jurisdiction_signer: Option<tenzro_model::SharedJurisdictionSigner>,
    /// This node's operator-declared jurisdiction claim, built once at
    /// startup from `NodeConfig::jurisdiction_country` / `jurisdiction_blocs`
    /// and — when TEE hardware is present — bound to a fresh attestation
    /// report. Rides every provider announcement and every locally-signed
    /// jurisdiction receipt. `None` means this node never satisfies a
    /// jurisdiction pin (fail-closed).
    jurisdiction_claim: Option<tenzro_types::JurisdictionClaim>,

    // Background liveness sweeper — periodically marks silent skills/tools/
    // templates/tasks/sessions/services as Inactive and purges old terminal
    // rows. Held here so its `Drop` aborts the task on node shutdown.
    liveness_sweeper: Option<crate::liveness::LivenessSweeper>,

    /// Runs the autotune controller against the live bounds. Held here so its
    /// `Drop` aborts the task at shutdown.
    #[cfg(feature = "inference")]
    pub autotune: Arc<parking_lot::RwLock<Option<crate::autotune_sampler::AutotuneSampler>>>,

    // HuggingFace model integration
    pub hf_downloader: Option<Arc<HfDownloader>>,
    #[cfg(feature = "inference")]
    pub model_runtime: Option<Arc<ModelRuntime>>,

    /// Node-level admission control. Bounds total concurrent inference across
    /// every model and modality — the limit no per-model bound can express,
    /// since N models each at their own ceiling still add up to N times the
    /// intended load on one machine. Always present: a node with no admission
    /// layer has no way to refuse work before it becomes an outage.
    pub traffic: Arc<tenzro_model::traffic::TrafficManager>,

    /// Which models are warm, and what to tell a caller whose model is not.
    /// Lets the catalog exceed what fits in memory: everything is servable,
    /// a bounded subset is resident, and callers are told the difference
    /// rather than left on a socket until they time out.
    pub lifecycle: Arc<tenzro_model::lifecycle::ModelLifecycle>,

    /// Shared by every model runtime: one engine per loaded model, and ONNX
    /// requests admitted through `traffic`.
    #[cfg(feature = "inference")]
    pub model_host: Arc<tenzro_model::ModelHost>,

    // ONNX-backed runtimes (forecast, vision, text embedding, segmentation,
    // detection, audio, video), all claiming models and admitting requests
    // through `model_host`.
    #[cfg(feature = "inference")]
    pub timeseries_runtime: Arc<TimeseriesRuntime>,
    #[cfg(feature = "inference")]
    pub vision_runtime: Arc<VisionRuntime>,
    #[cfg(feature = "inference")]
    pub text_embedding_runtime: Arc<TextEmbeddingRuntime>,
    /// Cross-encoder rerankers on the Praecise engine, in process.
    #[cfg(feature = "inference")]
    pub rerank_runtime: Arc<tenzro_model::rerank_runtime::RerankRuntime>,
    /// Decision models on the Praecise engine, in process.
    #[cfg(feature = "inference")]
    pub decision_runtime: Arc<tenzro_model::decision_runtime::DecisionRuntime>,
    /// LoRA training on the Praecise engine, in process, on the CUDA device.
    #[cfg(feature = "inference")]
    pub training_runtime: Arc<tenzro_model::training_runtime::RoundTrainer>,
    /// Speech synthesis on the Praecise engine, in process.
    #[cfg(feature = "inference")]
    pub speech_runtime: Arc<tenzro_model::speech_runtime::SpeechRuntime>,
    /// Spoken replies from omni models on the Praecise engine, in process.
    #[cfg(feature = "inference")]
    pub omni_runtime: Arc<tenzro_model::omni_runtime::OmniRuntime>,
    #[cfg(feature = "inference")]
    pub segmentation_runtime: Arc<SegmentationRuntime>,
    #[cfg(feature = "inference")]
    pub text_segmentation_runtime: Arc<TextSegmentationRuntime>,
    #[cfg(feature = "inference")]
    pub detection_runtime: Arc<DetectionRuntime>,
    #[cfg(feature = "inference")]
    pub audio_runtime: Arc<AudioRuntime>,
    #[cfg(feature = "inference")]
    pub video_runtime: Arc<VideoRuntime>,

    /// Media models this node runs in process (see [`crate::media_models`]).
    #[cfg(feature = "inference")]
    pub media_models: crate::media_models::MediaModels,

    /// MoE expert-host runtime — per-expert FFN weights + gating networks
    /// for distributed mixture-of-experts serving. Serves both the local
    /// `tenzro_moe*` RPC surface and the `tenzro/moe` iroh ALPN.
    #[cfg(feature = "inference")]
    pub moe_runtime: Arc<tenzro_model::MoeExpertRuntime>,

    /// Shared iroh endpoint resolver. Constructed at node
    /// startup when `NodeConfig::iroh` is `Some`; held here so every
    /// consumer (the storage `IrohBlobsDaBackend`, direct `tenzro://blob/<hash>` URI fetches)
    /// shares the same endpoint, ALPN, and hash space.
    pub iroh_resolver: Option<Arc<tenzro_iroh::IrohBackedResolver>>,

    /// The relays this node verified, its relay role when it serves one, and
    /// the boot identities it resolves. Started first in [`Self::start`].
    pub identity_transport: Option<Arc<tenzro_iroh::IdentityTransport>>,

    /// Answers the onboarding protocol (status, owner-approval challenge,
    /// sponsored first registration); present once the iroh endpoint is up.
    pub(crate) onboard_server: Option<Arc<crate::identity_gate::OnboardServer>>,

    /// Deferred A2A JSON-RPC dispatcher over iroh.
    ///
    /// Registered on the iroh router at bind time (in `init_ai_infrastructure`)
    /// because `iroh::Router::spawn` sets ALPNs once and a second router
    /// would overwrite them. The backing dispatcher (which needs
    /// `Arc<TenzroNode>` for `A2aState`) is installed later from `main.rs`
    /// once `Arc::new(node)` exists. Until that happens, the dispatcher
    /// returns a JSON-RPC `-32603` "dispatcher not yet bound" envelope to
    /// connecting peers.
    pub iroh_a2a_dispatcher: Option<Arc<tenzro_iroh::DeferredJsonRpcDispatcher>>,
    /// Rewrites every load reading the monitor takes before it is applied.
    /// `None` in a running node, which acts on what it measures; an
    /// embedder that must not depend on the machine sets one before `start`.
    load_reading: Option<LoadReading>,
    /// The thread that samples the host and publishes the load level; ended
    /// by `stop`, which leaves the published level at GREEN.
    load_monitor: parking_lot::Mutex<Option<crate::load_monitor::MonitorThread>>,

    /// Deferred MCP-over-iroh stream handler. Same chicken-and-egg pattern
    /// as `iroh_a2a_dispatcher`: the `tenzro/mcp` ALPN is registered on the
    /// iroh router at bind time backed by an unbound trampoline, then the
    /// real `IrohMcpHandler` (which needs `Arc<TenzroNode>` to construct
    /// `TenzroMcpServer` instances per session) is installed from `main.rs`
    /// after `Arc::new(node)` exists.
    pub iroh_mcp_handler: Option<Arc<tenzro_iroh::DeferredMcpHandler>>,

    /// Deferred inference-over-iroh handler. Same chicken-and-egg pattern
    /// as `iroh_a2a_dispatcher`: the `tenzro/infer` ALPN is registered on the
    /// iroh router at bind time backed by an unbound trampoline, then the
    /// real handler (which needs `Arc<TenzroNode>` to call `handle_chat`)
    /// is installed from `main.rs` after `Arc::new(node)` exists.
    pub iroh_infer_dispatcher: Option<Arc<tenzro_iroh::DeferredRequestHandler>>,

    // Identity & Payments (TDIP + MPP/x402)
    identity_registry: Option<Arc<IdentityRegistry>>,
    /// The same registry, in a slot that exists before it does.
    ///
    /// `identity_registry` is a plain field set in `init_identity()`, which
    /// runs *after* `init_ai_infrastructure()`. Anything built in between that
    /// needs to reach the registry later cannot capture the field — it would
    /// capture `None` and keep it forever. That is what made the storage and
    /// compute runtimes resolve a payee the rest of the node disagreed with:
    /// they held a resolver closure that could only ever see the pre-identity
    /// fallback.
    ///
    /// Written once alongside `identity_registry`. Read through
    /// `identity_registry_now()`.
    identity_registry_slot: Arc<parking_lot::RwLock<Option<Arc<IdentityRegistry>>>>,
    payment_gateway: Option<Arc<TenzroPaymentGateway>>,
    x402_server: Option<Arc<X402PaymentServer>>,

    /// The facilitator the operator names (`payments.facilitator_url`), which
    /// settles the x402 payments A2A tasks ask for.
    x402_facilitator: Option<Arc<tenzro_payments::x402::CdpFacilitatorClient>>,
    /// The x402 facilitator this node serves to resource servers
    /// (`/facilitator/x402/verify`, `/settle`, `/supported`): Tenzro-scheme
    /// payments settle on this node's ledger rail and are held to the
    /// payer's Terms; EVM payments go through the scheme registry.
    x402_facilitator_service: Option<Arc<tenzro_payments::x402::X402Facilitator>>,

    /// Deferred event-loop sender slot for the ledger settlement submitter.
    /// `init_payments` builds the submitter before the event loop exists;
    /// `start()` fills this slot after `init_event_loop` so admitted
    /// settlement txs also gossip. `None` when no ledger rail was wired.
    /// The event-loop sender every transaction this node signs from the
    /// validator's ledger account is gossiped through once admitted locally
    /// (ledger submitter, checkpoint-signer records, equivocation reports),
    /// so every proposer holds the account's whole nonce sequence. Filled
    /// when the event loop starts.
    validator_tx_gossip: Arc<parking_lot::Mutex<Option<mpsc::Sender<NodeEvent>>>>,
    /// Payment sessions over on-chain escrows (MPP sessions, x402
    /// batch-settlement, payment channels). `None` without a ledger rail.
    payment_sessions: Option<Arc<tenzro_payments::mpp::MppSessionManager>>,
    /// Submits the node's settlement transactions (HTTP-402 settlements,
    /// voucher claims, saga settlements). `None` without a ledger rail.
    ledger_submitter: Option<Arc<crate::payment_rails::LedgerSubmitter>>,
    /// The one nonce allocator of the validator's ledger account: the ledger
    /// submitter, the checkpoint-signer recorder and equivocation reports.
    validator_nonces: Arc<crate::payment_rails::NonceReservation>,
    /// The same submitter, for components built before it that flag proven
    /// findings to consensus (trust-ledger findings).
    finding_submitter: Arc<std::sync::OnceLock<Arc<crate::payment_rails::LedgerSubmitter>>>,

    /// Client for every outbound fetch to a destination a caller names; see
    /// [`crate::egress_guard`].
    egress: Arc<crate::egress_guard::EgressGuard>,

    /// The supervisor's audit trail of agent actions; see
    /// [`crate::agent_audit`].
    agent_audit: Arc<crate::agent_audit::AgentAudit>,
    /// Signed records of agents' tool calls, [`crate::tool_call_record`].
    tool_calls: Arc<crate::tool_call_record::ToolCallLog>,

    /// The DA backend agent memory archives to and agent audit entries are
    /// placed in, once the agent runtime is up.
    agent_da: Option<Arc<dyn tenzro_storage::da::DaBackend>>,

    /// Trusted proxies, accepted `Host` names and batch cap for the HTTP
    /// listeners; see [`crate::http_surface`].
    http_surface: Arc<crate::http_surface::SurfacePolicy>,

    /// Session continuity: sessions served here and KV chains held as a
    /// successor. Set once by `kv_continuity::start`.
    #[cfg(feature = "inference")]
    pub(crate) kv_continuity: std::sync::OnceLock<Arc<crate::kv_continuity::KvContinuity>>,

    /// per-DID admission controller. Wired into the consensus
    /// mempool at startup (`set_admission`); also held here so RPC
    /// handlers (`tenzro_getMempoolLane`, `tenzro_getMempoolStats`) can
    /// consult buckets and stats without going through the engine.
    admission: Option<Arc<tenzro_consensus::admission::AdmissionController>>,

    // Token registry (unified cross-VM token tracking)
    token_registry: Option<Arc<TokenRegistry>>,

    // TEE (optional). The local hardware provider is retained so attestation
    // requests routed to this node (RPC `tenzro_attest`, MCP `attest`, agent
    // workloads requesting confidential execution) can call
    // `provider.generate_attestation(user_data)` instead of returning a stub.
    // Populated by `init_tee()`; consumed by the TEE attestation request path
    // and exposed via `tee_provider()` accessor.
    tee_provider: Option<Box<dyn TeeProvider>>,
    tee_registry: Option<Arc<TeeRegistry>>,

    /// Permit2 nonce bitmap. Tracks signed-and-spent permit nonces per
    /// owner so a relayer cannot replay a signature that has already
    /// been used. See [`tenzro_vm::permit2::Permit2NonceBitmap`].
    permit2_nonce_bitmap: Arc<tenzro_vm::permit2::Permit2NonceBitmap>,

    /// Chainlink Proof-of-Reserve pull adapter. Reads per-asset PoR
    /// aggregators and projects live readings into the reserve-attestation
    /// shape `tenzro_submitReserveAttestation` consumes — the automatic
    /// backing feed for tokenized-equity 1:1 mint (xStocks-class). Feeds are
    /// registered per tokenized asset; the adapter never signs (signing stays
    /// with the attestor identity at the RPC boundary).
    chainlink_por_adapter: Arc<tenzro_bridge::ChainlinkPorAdapter>,

    /// ERC-8004 on-chain agent-registry mirror (DID → sequential `agentId`).
    /// Populated during identity init with `NativeErc8004Mirror`, which
    /// dispatches signed EVM transactions to the canonical
    /// `IdentityRegistry` proxy at `addresses::IDENTITY_REGISTRY`.
    /// Settlement-outcome dispatchers read this to resolve a TDIP machine DID
    /// to the `uint256 agentId` allocated at registration time, which keys the
    /// `submitFeedback` row written into the on-chain `ReputationRegistry`.
    erc8004_agent_registry: Option<Arc<dyn tenzro_identity::erc8004::OnChainAgentRegistry>>,

    /// Per-node `erc8004-system` secp256k1 signer used by the two
    /// internal writer that has no caller signature: the TDIP
    /// `NativeErc8004Mirror::mirror_register_agent` path (fired from
    /// inside `IdentityRegistry::register_machine_with_fee`). It runs inside the node's trust boundary; `msg.sender` on the
    /// resulting EVM tx is the validator's `erc8004-system` address.
    /// User-facing RPC writes (`tenzro_registerAgent`,
    /// `submitFeedback`, `requestValidation`) stay caller-signed and
    /// do **not** use this signer — see the
    /// `project_erc8004_evm_architecture` memory for the locked
    /// signing-key decisions.
    ///
    /// The signer bakes the loopback JSON-RPC URL and chain_id at
    /// construction time; submission goes through the node's own
    /// `tenzro_sendRawTransaction`. `None` until storage is initialised
    /// (the URL needs `self.config.rpc_addr` and the genesis
    /// `chain_id` must be loaded first).
    erc8004_system_signer: Option<Arc<tenzro_bridge::evm_signer::EvmTransactionSigner>>,

    // Monitoring
    health_monitor: Arc<HealthMonitor>,
    metrics: Arc<MetricsCollector>,

    // Event loop
    event_loop_tx: Option<mpsc::Sender<NodeEvent>>,

    /// The ordered-segment feed of a node that holds no consensus key, kept
    /// so an in-process test chain can order blocks without a validator.
    #[cfg(test)]
    pub(crate) test_ordered_segments: Option<mpsc::Sender<crate::consensus_driver::OrderedSegment>>,

    /// Producer and index of this node's state snapshots, served over the
    /// iroh state-sync ALPN. Created once the iroh endpoint is bound.
    snapshot_store: Option<Arc<crate::snapshot::SnapshotStore>>,

    /// Peers, by iroh `EndpointId`, to restore state from at start. Set via
    /// [`TenzroNode::set_state_sync_peers`] before [`TenzroNode::start`].
    /// Tried in order until one serves a snapshot that verifies against the
    /// weak-subjectivity checkpoint; the checkpoint is required.
    state_sync_peers: Vec<tenzro_iroh::EndpointId>,
    /// Direct addresses the operator gave for state-sync peers; a peer with
    /// none is found by discovery.
    state_sync_addrs: Vec<tenzro_iroh::EndpointAddr>,

    /// Weak-subjectivity checkpoint `(height, block_hash)`: a finalized block
    /// the node trusts a priori. It anchors state sync (the snapshot at
    /// `height - STATE_ROOT_LAG` must be committed by this block) and every
    /// import path (the block imported at `height` must be this block). A
    /// long-range fork signed by an old validator supermajority passes every
    /// certificate check but not this one. `None` disables the check.
    weak_subjectivity_anchor: Option<(u64, [u8; 32])>,

    /// A recovery manifest to apply while consensus is initialised; see
    /// [`crate::recovery`].
    recovery: Option<crate::recovery::RecoveryRequest>,

    /// Live chain tip height — shared with EventLoop for lock-free RPC reads.
    ///
    /// The EventLoop updates this atomically on every finalized block (both local
    /// consensus blocks and gossiped network blocks). RPC handlers read it with
    /// Acquire ordering so they always see the true chain tip without any storage I/O.
    ///
    /// This bypasses BlockStoreImpl::latest_height() which reads CF_METADATA and is
    /// subject to the `should_update = height > latest` guard that freezes metadata
    /// when a fresh chain starts at height 1 while CF_METADATA still holds a stale
    /// value from a prior run (e.g. 9998). The atomic is immune to this because it
    /// is always set unconditionally on every finalized block.
    chain_tip: Arc<AtomicU64>,

    /// Tracks the latest `StatusMessage` height advertised by each peer on
    /// `tenzro/status`. Consumed by `eth_syncing` / `tenzro_syncing` to
    /// report a real network-tip estimate (not just `local_tip`) so external
    /// clients can see when this node is lagging behind the network.
    ///
    /// Populated by the inbound status subscription wired in `init_event_loop`;
    /// queried by RPC handlers via `network_tip()`.
    pub(crate) peer_status: Arc<tenzro_network::PeerStatusTracker>,

    // Provider state
    pub provider_schedule: Arc<RwLock<ProviderSchedule>>,
    /// Territorial licence enforcement. Consulted only for models whose licence
    /// carries a territorial term that reaches outputs — seven of the eight
    /// custom licences carry none, so the common path never touches it.
    pub territory: Arc<RwLock<crate::territory::TerritoryEnforcer>>,
    pub provider_pricing: Arc<RwLock<ProviderPricing>>,
    pub model_downloads: Arc<DashMap<String, ModelDownloadStatus>>,
    /// Background MoE expert-extraction jobs keyed by job id
    /// (`tenzro_moePrepareExperts` / `tenzro_moePrepareStatus`).
    #[cfg(feature = "inference")]
    pub moe_prepare_jobs: Arc<DashMap<String, crate::moe::MoePrepareJob>>,
    /// Models this node serves, each with its visibility override. `None`
    /// means the model follows the node's visibility.
    pub served_models: Arc<DashMap<String, Option<tenzro_types::Visibility>>>,
    pub model_services: Arc<DashMap<String, ModelServiceInstance>>,
    pub load_tracker: Arc<tenzro_model::LoadTracker>,
    /// In-memory store of recent chat-completion SSE streams keyed by
    /// completion id. Powers `Last-Event-ID`-based resume on
    /// `/v1/chat/completions`. GC is spawned at
    /// node init and runs every 30s; entries are evicted per
    /// [`crate::streaming::DEFAULT_TTL`] (finished) or
    /// [`crate::streaming::cursor::IN_FLIGHT_IDLE_TIMEOUT`] (in-flight).
    pub stream_cursors: crate::streaming::StreamCursorStore,
    /// Per-(provider, model) SLO histograms: TTFT, inter-token latency,
    /// completion/failure counters. Surfaced via `/metrics` as the
    /// `tenzro_inference_*` series. Cheap-to-clone (Arc inside).
    pub stream_slo_metrics: crate::streaming::StreamSloMetrics,
    /// Event bus for this node's live events (stream lifecycle, workflows).
    /// Read through `GET /events/node`, where each event about a resource
    /// reaches only the readers its visibility allows.
    /// Cheap-to-clone (`Arc` inside) — used by RPC handlers to publish.
    pub event_bus: Arc<tenzro_events::EventBus>,
    pub hardware_profile: Arc<RwLock<Option<HardwareProfile>>>,
    pub user_resources: Arc<DashMap<String, UserResource>>,
    pub transaction_history: Arc<RwLock<Vec<TransactionHistoryEntry>>>,
    pub runtime_roles: Arc<RwLock<RoleSet>>,
    /// The live economic policy — every rate the network charges, in one
    /// governance-settable block.
    ///
    /// Always present, so no settlement path has to decide what to do when it
    /// is absent. Before storage is wired it holds the defaults; once storage
    /// is available it is swapped for a persisted manager that hydrates
    /// whatever governance last applied.
    pub economic_policy: Arc<tenzro_token::EconomicPolicyManager>,
    /// Storage-provider runtime. `Some` only when this node's roles include
    /// `StorageProvider` — owns the object store, the per-epoch billing meter
    /// (PoR-gated), and the byte-epoch pricing policy. Spawned during startup
    /// once the iroh resolver and staking ledger are available.
    pub storage_runtime: Option<Arc<crate::storage_provider_runtime::StorageProviderRuntime>>,
    /// Single-use challenges authorizing changes to an account's custody.
    ///
    /// Always present: a node that served passkey enrollment must be able to
    /// gate the mutations that change who can spend from those accounts.
    pub custody_challenges: Arc<crate::passkey_rpc::CustodyChallengeStore>,
    /// The node's visibility: the default for every resource it offers that
    /// carries no override of its own. Shared with the event loop, which reads
    /// it on every heartbeat.
    pub node_visibility: Arc<RwLock<tenzro_types::Visibility>>,
    /// The cluster membership lists this node holds and the co-members it has
    /// found on the local network.
    cluster_identity: Arc<crate::cluster_identity::ClusterIdentity>,
    /// OAuth state for onboarding key management (shared with MCP server)
    pub oauth_state: Arc<RwLock<Option<Arc<crate::mcp::oauth::OAuthState>>>>,
    /// Models discovered from gossip network announcements.
    /// Key: "{model_id}:{provider}" to allow multiple providers per model.
    pub network_models: Arc<DashMap<String, NetworkModelEntry>>,
    /// Providers discovered from gossip network announcements.
    /// Key: peer_id — last writer wins (most recent heartbeat).
    pub network_providers: Arc<DashMap<String, NetworkProviderEntry>>,

    /// Optional source of the wallet-keystore password. When set, the wallet
    /// service is configured with `default_password` so a wallet's record is
    /// sealed to / read from the keystore on disk and the wallet PERSISTS
    /// across restarts. When `None`, the wallet is ephemeral
    /// (recreated every launch) — the historical behaviour.
    ///
    /// This is a trait object so `tenzro-node` stays platform-agnostic: the
    /// embedding app injects the implementation. Every implementation resolves
    /// the password from hardware — a Secure Enclave key gated by biometrics,
    /// or a TPM — because a password held anywhere else is a copy of the thing
    /// the keystore protects.
    keystore_unlocker: Option<Arc<dyn tenzro_keystore_unlock::KeystoreUnlocker>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeState {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}

// Validator key persistence lives in the `keygen` module. The running
// node never generates keys on `start` — it loads existing files and
// fails loud if any are missing. Generation is gated behind the
// explicit `tenzro-node init` operator subcommand. See `keygen.rs`
// for the rationale (universal production-BFT norm: zero major 2026
// BFT L1 does silent daemon-side auto-keygen on start).

/// Key prefix marking a model the operator deliberately offloaded.
///
/// # Why an offload needs a record of its own
///
/// Serving state lives in `CF_MODELS` under `served:<id>`, and stopping a model
/// used to mean deleting that row. Absence is not a decision: it reads exactly
/// like a model nobody ever asked for, so nothing downstream could tell "the
/// operator stopped this" from "this was never started", and every path that
/// rebuilds serving state was free to put it back.
///
/// It did. An operator freed 29 GB of GPU on a node, the process restarted, and
/// the startup reconcile reloaded the model 3.4 seconds later — reporting
/// success at every step, because each step was individually doing its job.
///
/// Two other ways the old shape lost the decision, both silent:
///
/// * **A crash mid-stop.** The runtime unload happened first and the row delete
///   last. Dying in between left the model unloaded *and* still recorded as
///   served, so the next start brought it back.
/// * **Another writer.** Network model services restore from
///   `CF_MODEL_SERVICES` on startup, a different store. Deleting the
///   `served:` row said nothing to that path.
///
/// So the decision is written down. The row's presence means "do not load
/// this", it outlives the process, and it is cleared only by an operator
/// explicitly serving the model again — which is the one event that genuinely
/// supersedes it.
pub const OFFLOAD_PREFIX: &str = "offloaded:";

/// The `CF_MODELS` key holding the operator's provider schedule, model stacks
/// included, so the stacks an operator defined are applied again after a
/// restart instead of reverting to an empty schedule.
pub const PROVIDER_SCHEDULE_KEY: &[u8] = b"schedule:provider";

/// The `CF_MODELS` key holding the price card the operator last set, which
/// replaces the configured one at startup.
pub const PROVIDER_PRICING_KEY: &[u8] = b"pricing:provider";

/// The replicable public record of `identity` as a `RegisterIdentity`
/// payload carrying `proof`. Its
/// [`tenzro_types::identity::registration_statement`] is what the controller
/// key signs.
pub fn identity_register_payload(
    identity: &tenzro_identity::TenzroIdentity,
    identity_type: &str,
    proof: tenzro_types::identity::RegistrationProof,
) -> tenzro_types::identity::RegisterIdentityPayload {
    let controller_pubkey = identity
        .public_keys
        .first()
        .map(|k| k.public_key.clone())
        .unwrap_or_default();
    let key_type = identity
        .public_keys
        .first()
        .map(|k| k.key_type.clone())
        .unwrap_or_else(|| "Ed25519".to_string());
    // HashMap to BTreeMap so the bincode tx-hash preimage is identical on
    // every node that re-serializes the received transaction.
    let metadata: std::collections::BTreeMap<String, String> = identity
        .metadata
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    tenzro_types::identity::RegisterIdentityPayload {
        did: identity.did_string(),
        identity_type: identity_type.to_string(),
        display_name: identity.display_name().to_string(),
        controller_pubkey,
        key_type,
        wallet_id: identity.wallet_id.clone(),
        wallet_address: identity.wallet_address,
        pq_verifying_key: identity.pq_verifying_key.clone(),
        metadata,
        proof,
    }
}

/// Label of the derived key behind this machine's network endpoint.
const ENDPOINT_KEY_LABEL: &str = "tenzro/transport/endpoint";

impl TenzroNode {
    /// Create a new Tenzro Network node
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Opening the node's own keys must not be shed by a loaded TPM queue.
        let _tpm = tenzro_device_key::tpm_exec::lifecycle();
        // The light build cannot fill a role that runs models; every way of
        // starting a node (the binary, an embedded handle) refuses here.
        crate::engine_roles::check(&config.roles, config.connector.is_some())
            .map_err(crate::error::NodeError::Config)?;
        crate::fd_limit::raise_to_hard_limit().map_err(crate::error::NodeError::Config)?;
        info!("Initializing Tenzro Network node");
        info!("Roles: {}", config.roles);
        info!("Data directory: {:?}", config.data_dir);

        // Ensure directories exist
        config.ensure_data_dir()?;
        config.ensure_models_dir()?;

        // The connector's endpoint and its API key, read before anything else
        // is opened so a misconfigured connector refuses to start.
        let connector = crate::connector::Connector::from_config(&config)
            .map_err(|e| crate::error::NodeError::Config(format!("connector: {e}")))?
            .map(Arc::new);

        // Initialize monitoring
        let health_monitor = Arc::new(HealthMonitor::new());
        let metrics = Arc::new(MetricsCollector::new());
        let initial_roles = config.roles.clone();
        let initial_visibility = config.visibility;

        // The chain id this node runs (see `NodeConfig::chain_id`). Used by the
        // peer status tracker to drop StatusMessages from peers on a different
        // chain — prevents a misconfigured peer or cross-chain noise from
        // poisoning the network-tip estimate consumed by `eth_syncing`.
        let chain_id = config.chain_id();
        let peer_status = tenzro_network::PeerStatusTracker::new(chain_id);
        #[cfg(feature = "inference")]
        let moe_disk_dir = config.data_dir.join("moe_experts");

        // The operator's own cards, as configured until it sets others.
        let provider_pricing = config.provider_rates.inference.clone();
        let access = Arc::new(crate::access::Access::new(Arc::new(
            crate::access::AccessPolicyStore::open(&config.data_dir)
                .map_err(crate::error::NodeError::Config)?,
        )));
        let admin_audit = Arc::new(
            crate::admin_audit::AdminAudit::open(&config.data_dir, &config.admin, chain_id)
                .map_err(|e| crate::error::NodeError::Config(format!("admin audit log: {e}")))?,
        );
        let agent_audit = Arc::new(crate::agent_audit::AgentAudit::default());
        let tool_calls = Arc::new(crate::tool_call_record::ToolCallLog::new(&config.data_dir));
        let egress = Arc::new(
            crate::egress_guard::EgressGuard::from_config(
                &config.egress,
                Arc::new(crate::machine_access::MachineAccessGrants::new(
                    config.operator_did.clone(),
                )),
            )
            .map_err(|e| crate::error::NodeError::Config(format!("egress: {e}")))?
            .with_quarantines(agent_audit.clone())
            .with_credentials(config.data_dir.clone()),
        );
        let http_surface = Arc::new(
            crate::http_surface::SurfacePolicy::from_config(
                &config,
                std::env::var("TENZRO_WEBAUTHN_RP_ID").ok().as_deref(),
            )
            .map_err(crate::error::NodeError::Config)?,
        );
        tracing::info!(
            hosts = ?http_surface.hosts(),
            "HTTP surface answers to these host names besides IP literals and localhost"
        );
        // Sized from the machine's core count. Two concurrent requests per
        // core: inference alternates compute and memory stalls, so a little
        // oversubscription lifts utilisation while more only deepens queues.
        let traffic = Arc::new(tenzro_model::traffic::TrafficManager::default());
        #[cfg(feature = "inference")]
        let model_host = Arc::new(
            tenzro_model::ModelHost::with_engines((*traffic).clone(), &config.engines)
                .map_err(|e| crate::error::NodeError::Config(format!("engines: {e}")))?,
        );

        let node = Self {
            config,
            state: Arc::new(RwLock::new(NodeState::Created)),
            storage: None,
            consensus_records: None,
            network: None,
            consensus: None,
            validator_signer: None,
            outgoing_validator_signer: None,
            local_validator_address: None,
            identity_signer: None,
            sealed_offers: Arc::new(crate::sealed_delivery::SealedOffers::default()),
            da_committee_backend: None,
            da_recorder_rx: parking_lot::Mutex::new(None),
            da_possession_challenger: None,
            disk_guard: Arc::new(crate::storage_maintenance::DiskGuard::default()),
            proof_log: None,
            surge_state: crate::surge::SurgeState::default(),
            history_archive: None,
            event_log: None,
            storage_maintenance: None,
            connector,
            batch_service: None,
            records: None,
            machine_sealing_public_key: std::sync::OnceLock::new(),
            vm_runtime: None,
            wallet_service: None,
            token: None,
            fee_processor: None,
            trust_ledger: None,
            catalog_sync: None,
            challenge_manager: None,
            sla_manager: None,
            sla_outstanding_probes: Arc::new(DashMap::new()),
            sla_tally: Arc::new(crate::sla_attest::SlaTally::default()),
            validator_registry: None,
            webauthn_validator: None,
            passkey_sessions: None,
            burn_rate_manager: None,
            policy_applier: None,
            treasury: None,
            auth_engine: None,
            access,
            admin_audit,
            self_ref: Arc::new(std::sync::OnceLock::new()),
            settlement_preferences: None,
            model_registry: None,
            provider_manager: None,
            inference_router: None,
            compute_observations: Arc::new(crate::compute_observations::ObservationWindow::new()),
            usage_tracker: None,
            provenance_store: None,
            provenance_signer: None,
            sealed_model_store: None,
            model_recipient_key: None,
            jurisdiction_signer: None,
            jurisdiction_claim: None,
            liveness_sweeper: None,
            #[cfg(feature = "inference")]
            autotune: Arc::new(parking_lot::RwLock::new(None)),
            hf_downloader: None,
            #[cfg(feature = "inference")]
            model_runtime: None,
            traffic,
            lifecycle: Arc::new(tenzro_model::lifecycle::ModelLifecycle::new()),
            #[cfg(feature = "inference")]
            timeseries_runtime: Arc::new(TimeseriesRuntime::with_host(model_host.clone())),
            #[cfg(feature = "inference")]
            vision_runtime: Arc::new(VisionRuntime::with_host(model_host.clone())),
            #[cfg(feature = "inference")]
            text_embedding_runtime: Arc::new(TextEmbeddingRuntime::with_host(model_host.clone())),
            #[cfg(feature = "inference")]
            rerank_runtime: Arc::new(tenzro_model::rerank_runtime::RerankRuntime::with_host(
                model_host.clone(),
            )),
            #[cfg(feature = "inference")]
            decision_runtime: Arc::new(tenzro_model::decision_runtime::DecisionRuntime::with_host(
                model_host.clone(),
            )),
            #[cfg(feature = "inference")]
            training_runtime: Arc::new(tenzro_model::training_runtime::RoundTrainer::with_host(
                model_host.clone(),
            )),
            #[cfg(feature = "inference")]
            speech_runtime: Arc::new(tenzro_model::speech_runtime::SpeechRuntime::with_host(
                model_host.clone(),
            )),
            #[cfg(feature = "inference")]
            omni_runtime: Arc::new(tenzro_model::omni_runtime::OmniRuntime::with_host(
                model_host.clone(),
            )),
            #[cfg(feature = "inference")]
            segmentation_runtime: Arc::new(SegmentationRuntime::with_host(model_host.clone())),
            #[cfg(feature = "inference")]
            text_segmentation_runtime: Arc::new(TextSegmentationRuntime::with_host(
                model_host.clone(),
            )),
            #[cfg(feature = "inference")]
            detection_runtime: Arc::new(DetectionRuntime::with_host(model_host.clone())),
            #[cfg(feature = "inference")]
            audio_runtime: Arc::new(AudioRuntime::with_host(model_host.clone())),
            #[cfg(feature = "inference")]
            video_runtime: Arc::new(VideoRuntime::with_host(model_host.clone())),
            #[cfg(feature = "inference")]
            media_models: crate::media_models::MediaModels::with_host(model_host.clone()),
            #[cfg(feature = "inference")]
            model_host,
            #[cfg(feature = "inference")]
            moe_runtime: Arc::new(tenzro_model::MoeExpertRuntime::with_config(
                tenzro_model::ResidencyConfig::auto().with_disk_dir(moe_disk_dir),
            )),
            iroh_resolver: None,
            identity_transport: None,
            onboard_server: None,
            iroh_a2a_dispatcher: None,
            load_reading: None,
            load_monitor: parking_lot::Mutex::new(None),
            iroh_mcp_handler: None,
            iroh_infer_dispatcher: None,
            identity_registry: None,
            identity_registry_slot: Arc::new(parking_lot::RwLock::new(None)),
            payment_gateway: None,
            x402_server: None,
            x402_facilitator: None,
            x402_facilitator_service: None,
            validator_tx_gossip: Arc::default(),
            payment_sessions: None,
            ledger_submitter: None,
            validator_nonces: Arc::default(),
            finding_submitter: Arc::new(std::sync::OnceLock::new()),
            egress: egress.clone(),
            agent_audit,
            tool_calls,
            agent_da: None,
            http_surface,
            #[cfg(feature = "inference")]
            kv_continuity: std::sync::OnceLock::new(),
            admission: None,
            token_registry: None,
            tee_provider: None,
            tee_registry: None,
            permit2_nonce_bitmap: Arc::new(tenzro_vm::permit2::Permit2NonceBitmap::new()),
            chainlink_por_adapter: Arc::new(tenzro_bridge::ChainlinkPorAdapter::new(String::new())),
            erc8004_agent_registry: None,
            erc8004_system_signer: None,
            health_monitor,
            metrics,
            event_loop_tx: None,
            #[cfg(test)]
            test_ordered_segments: None,
            snapshot_store: None,
            state_sync_peers: Vec::new(),
            state_sync_addrs: Vec::new(),
            weak_subjectivity_anchor: None,
            recovery: None,
            chain_tip: Arc::new(AtomicU64::new(0)),
            peer_status,
            provider_schedule: Arc::new(RwLock::new(ProviderSchedule::default())),
            territory: Arc::new(RwLock::new(crate::territory::TerritoryEnforcer::default())),
            provider_pricing: Arc::new(RwLock::new(provider_pricing)),
            model_downloads: Arc::new(DashMap::new()),
            #[cfg(feature = "inference")]
            moe_prepare_jobs: Arc::new(DashMap::new()),
            served_models: Arc::new(DashMap::new()),
            model_services: Arc::new(DashMap::new()),
            load_tracker: Arc::new(tenzro_model::LoadTracker::new()),
            stream_cursors: crate::streaming::StreamCursorStore::new(),
            stream_slo_metrics: crate::streaming::StreamSloMetrics::new(),
            event_bus: Arc::new(tenzro_events::EventBus::new(
                tenzro_events::EventBusConfig::default(),
            )),
            hardware_profile: Arc::new(RwLock::new(None)),
            user_resources: Arc::new(DashMap::new()),
            transaction_history: Arc::new(RwLock::new(Vec::new())),
            runtime_roles: Arc::new(RwLock::new(initial_roles)),
            storage_runtime: None,
            custody_challenges: Arc::new(crate::passkey_rpc::CustodyChallengeStore::new(chain_id)),
            node_visibility: Arc::new(RwLock::new(initial_visibility)),
            economic_policy: Arc::new(tenzro_token::EconomicPolicyManager::new()),
            cluster_identity: Arc::new(crate::cluster_identity::ClusterIdentity::new(chain_id)),
            oauth_state: Arc::new(RwLock::new(None)),
            network_models: Arc::new(DashMap::new()),
            network_providers: Arc::new(DashMap::new()),
            keystore_unlocker: None,
        };

        Ok(node)
    }

    /// Inject the keystore-password source that makes the wallet persistent
    /// across restarts. Call this BEFORE [`start`](Self::start) /
    /// [`init_wallet`](Self::init_wallet). See the `keystore_unlocker` field
    /// docs for the trait contract. Returns `self` for builder chaining.
    pub fn with_keystore_unlocker(
        mut self,
        unlocker: Arc<dyn tenzro_keystore_unlock::KeystoreUnlocker>,
    ) -> Self {
        self.keystore_unlocker = Some(unlocker);
        self
    }

    /// Set the keystore-password source on an already-constructed node (e.g.
    /// from an embedding app that built the node, then resolves the unlocker
    /// asynchronously). Same effect as [`with_keystore_unlocker`](Self::with_keystore_unlocker).
    pub fn set_keystore_unlocker(
        &mut self,
        unlocker: Arc<dyn tenzro_keystore_unlock::KeystoreUnlocker>,
    ) {
        self.keystore_unlocker = Some(unlocker);
    }

    /// Returns the live chain tip height maintained by the event loop.
    ///
    /// Reads the shared `Arc<AtomicU64>` that the event loop updates with
    /// `Ordering::Release` on every finalized block (both locally produced and
    /// gossip-received). This load uses `Ordering::Acquire` so all writes
    /// made before the store (block persistence, state commit) are visible.
    ///
    /// No storage I/O. Returns the actual current height regardless of whether
    /// CF_METADATA:latest_height is stale.
    pub fn chain_tip_height(&self) -> u64 {
        self.chain_tip.load(Ordering::Acquire)
    }

    /// Returns the maximum block height advertised by any fresh peer on
    /// `tenzro/status`, or `None` if no fresh peer status is recorded.
    ///
    /// "Fresh" = received within the last 60 seconds. Stale entries are
    /// excluded so that a peer that disconnects without sending an explicit
    /// goodbye doesn't pin the network tip at its last advertised height
    /// indefinitely.
    ///
    /// **Diagnostic only.** RPC handlers must call
    /// [`Self::network_tip_capped`] for sync detection — `network_tip`
    /// uses the unfiltered maximum and can be inflated by a single
    /// malicious peer.
    pub fn network_tip(&self) -> Option<u64> {
        self.peer_status.network_tip()
    }

    /// Robust network-tip estimator: median of fresh peer heights,
    /// capped at `local_tip + MAX_TIP_LEAD`. Used by `eth_syncing` /
    /// `tenzro_syncing` so a malicious peer cannot drag the local node
    /// into a fake-sync state.
    pub fn network_tip_capped(&self, local_tip: u64) -> Option<u64> {
        self.peer_status.network_tip_capped(local_tip)
    }

    /// Returns a snapshot of all non-expired network-discovered models.
    pub fn network_models_snapshot(&self) -> Vec<NetworkModelEntry> {
        let now = std::time::Instant::now();
        self.network_models
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.registration.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns a snapshot of all non-expired network-discovered providers.
    pub fn network_providers_snapshot(&self) -> Vec<NetworkProviderEntry> {
        let now = std::time::Instant::now();
        self.network_providers
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Start all subsystems
    pub async fn start(&mut self) -> Result<()> {
        // Opening the node's own keys must not be shed by a loaded TPM queue.
        let _tpm = tenzro_device_key::tpm_exec::lifecycle();
        {
            let mut state = self.state.write();
            // A node can only be started exactly once; any state other than
            // `Created` means we're either already running, in the middle of
            // a transition, or have been shut down. Distinguish "already
            // started" from generic invalid-state for operator clarity.
            match *state {
                NodeState::Created => {}
                NodeState::Starting | NodeState::Running => {
                    return Err(NodeError::AlreadyStarted("node".to_string()));
                }
                _ => {
                    return Err(NodeError::InvalidState(format!(
                        "Cannot start node in state {:?}",
                        *state
                    )));
                }
            }
            *state = NodeState::Starting;
        }

        info!("Starting Tenzro Network node...");

        // 1. Initialize storage
        self.init_storage().await?;

        // 1a. Identity transport: admit the boot relays, start this node's
        //     relay role if it serves one. Every iroh endpoint below relays
        //     through these.
        //     Staked edge operators' relays come from the chain state this
        //     node holds.
        let staked_relays = self
            .chain_state()
            .map(|chain| crate::identity_bootstrap::staked_relays(&chain))
            .unwrap_or_default();
        self.identity_transport =
            Some(crate::identity_bootstrap::start(&self.config, &staked_relays).await?);

        // 1b. State sync (optional). With peers and a weak-subjectivity
        //     checkpoint configured, restore the committed state the
        //     checkpoint block commits, verified bucket by bucket, before
        //     consensus and the validator registry come up and hydrate from
        //     it. Block-sync then imports from the restored height on.
        match self.join_plan().await {
            crate::state_sync_policy::JoinPlan::Replay(reason) => info!(
                ?reason,
                "Catching up by block replay from the local tip, not by snapshot"
            ),
            crate::state_sync_policy::JoinPlan::Snapshot(source) => {
                if source == crate::state_sync_policy::PeerSource::Boot {
                    self.adopt_boot_peers_for_state_sync().await;
                }
                if self.state_sync_peers.is_empty() {
                    warn!(
                        "Snapshot join planned but no peer resolved; continuing with block replay \
                         from the local tip"
                    );
                } else {
                    info!(peers = self.state_sync_peers.len(), "Starting state sync");
                    match self.restore_state_from_peers().await {
                        Ok(s) => info!(
                            height = s.height,
                            state_root = %s.state_root,
                            buckets_fetched = s.buckets_fetched,
                            "State sync complete: restored state reproduces the checkpoint's root"
                        ),
                        Err(e) => {
                            let interrupted = match &self.storage {
                                Some(s) => crate::snapshot::restore_interrupted(s).await?,
                                None => false,
                            };
                            if interrupted {
                                // The restore had begun: genesis state is cleared and some
                                // buckets are written. Replaying blocks on top of that
                                // cannot reproduce the chain's state, so do not.
                                return Err(NodeError::Other(format!(
                                    "state sync stopped part-way ({e}); restart to resume it \
                                     from the buckets already written, or wipe the data \
                                     directory to start over"
                                )));
                            }
                            warn!(
                                error = %e,
                                "State sync failed; continuing with block replay from the local tip"
                            );
                        }
                    }
                }
            }
        }

        // 2. Initialize network
        self.init_network().await?;

        // 3. Initialize TEE (if enabled)
        if self.config.tee_enabled {
            self.init_tee().await?;
        }

        // 3b. Drop any configured role this node's hardware can't back, so it
        // never advertises a capability it lacks. TEE detection (above) and the
        // disk probe decide; an operator who set `--roles tee` on a box without
        // an enclave boots as a normal node rather than falsely claiming TEE.
        // Validator/AI roles are unaffected (stake-gated / permissionless).
        self.prune_unsupported_roles().await;

        // 4. Initialize VM runtime
        self.init_vm().await?;

        // 5. Initialize token economics
        self.init_token_economics().await?;

        // 6. Initialize wallet service
        self.init_wallet().await?;

        // 6c. The machine's hardware wallet key (TPM or Secure Enclave
        // P-256, with the hardware ML-DSA-65 key where the chip has one): the
        // node account, which signs the transactions the node submits as
        // itself. A machine without one runs without it, and every path that
        // needs it refuses.
        match tenzro_device_key::HardwareHybridSigner::open_or_create(
            crate::machine_admission::MACHINE_WALLET_KEY_LABEL,
        ) {
            Ok(signer) => {
                let signer: Arc<dyn tenzro_crypto::composite::HybridSigner> = Arc::new(signer);
                self.identity_signer = Some(signer);
            }
            Err(e) => warn!(
                error = %e,
                "No hardware identity key: revocations, media receipts and attestations \
                 will not be signed"
            ),
        }

        // 6d. The batched hardware signer of the machine identity key, for
        // every record the node signs (receipts, attestations, deliveries,
        // announcements). On a TPM-less machine its roots are signed at the
        // provider set. A node with neither a key nor a provider set does not
        // start.
        let pq_required_from_ms = match self.chain_state() {
            Some(state) => tenzro_vm::native::network_param(
                &state,
                tenzro_vm::governance::PQ_LEG_REQUIRED_FROM_PARAM,
            ),
            None => tenzro_vm::governance::genesis_param(
                tenzro_vm::governance::PQ_LEG_REQUIRED_FROM_PARAM,
            ),
        };
        self.batch_service = Some(
            tokio::task::spawn_blocking(move || {
                crate::batch_signing::open_batch_service(
                    SESSION_KEY_LABEL,
                    crate::batch_signing::BatchSigningParams {
                        pq_required_from_ms,
                        ..crate::batch_signing::BatchSigningParams::default()
                    },
                )
            })
            .await
            .map_err(|e| NodeError::Internal(format!("batch signing task: {e}")))?
            .map_err(NodeError::Config)?,
        );
        self.records = self.batch_service.clone().map(|service| {
            Arc::new(tenzro_crypto::batch::BatchRecordSigner::new(
                service,
                crate::batch_signing::BatchSigningParams::default().receipt_wait(),
            )) as Arc<dyn tenzro_crypto::batch::RecordSigner>
        });

        // 7. Initialize consensus.
        //
        // Only validators propose and vote. Every other role still builds the
        // engine and leaves it unstarted: block-sync accepts a block only after
        // verifying its embedded commit-QC against the validator set active at
        // that block's height, and that set — plus the epoch transitions needed
        // to walk across boundaries while catching up — lives in the engine's
        // `EpochManager`. A ModelProvider without one fetches blocks it can
        // never accept, so its local height never leaves genesis.
        let should_init_consensus = self.config.roles.is_validator();
        if should_init_consensus {
            crate::consensus_runtime::enable(crate::tier::machine_cores());
        }
        self.init_consensus(!should_init_consensus).await?;

        // 7b. The validator identity set, for admitting compute
        // observations from active validators only.
        {
            let registry = Arc::new(NodeValidatorRegistry::new());

            // Seed the validator IDENTITY set from genesis (or, once consensus
            // runs, the live epoch's validator set).
            if let Some(genesis) = &self.config.genesis {
                for gv in &genesis.validators {
                    match hex::decode(gv.node_key.trim_start_matches("0x")) {
                        Ok(node_key) => registry.add_identity(node_key),
                        Err(e) => warn!(
                            node_key = %gv.node_key,
                            "Skipping malformed genesis validator node key: {}", e
                        ),
                    }
                }
            }

            // Prefer the live epoch's validator set once consensus is
            // running — it tracks stake-based joins and rotations that the
            // static genesis seed cannot.
            if let Some(consensus) = &self.consensus {
                registry.set_epoch_manager(consensus.epoch_manager().clone());
                // Validators' endpoint records are held to the ML-DSA key
                // each registered on chain.
                if let Some(identity) = &self.identity_transport {
                    crate::identity_bootstrap::keep_validators_pinned(
                        identity.clone(),
                        consensus.epoch_manager().clone(),
                        self.storage
                            .clone()
                            .map(|s| s as Arc<dyn tenzro_storage::KvStore>),
                    );
                }
            }

            // The compute market admits observations only from active
            // validator identities.
            self.compute_observations
                .set_observer_filter(Arc::new(move |pubkey: &[u8]| {
                    registry.is_validator_identity(pubkey)
                }));
        }

        // 8b. Initialize OAuth 2.1 + DPoP + RAR auth engine
        self.init_auth().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("auth", e.to_string());
        })?;

        // 9. Initialize AI infrastructure
        self.init_ai_infrastructure().await.inspect_err(|e| {
            self.health_monitor
                .mark_unhealthy("ai_infrastructure", e.to_string());
        })?;

        // 9-bis. Serve the committee DA and database replication ALPNs on the
        // endpoint bound above.
        //
        // Committee DA: validators erasure-code blobs, distribute slivers to
        // the committee and collect `2f+1` signed attestations into an
        // availability certificate. The store is durable (`CF_DA_COMMITTEE`)
        // so a restarted validator still serves the slivers it attested to.
        // Only validators run it (the committee IS the validator set).
        if should_init_consensus
            && let (Some(resolver), Some(consensus), Some(storage)) = (
                self.iroh_resolver.clone(),
                self.consensus.clone(),
                self.storage.clone(),
            )
        {
            self.init_committee_da(resolver, consensus, storage)
                .await
                .map_err(|e| NodeError::Internal(format!("committee DA init failed: {e}")))?;
            info!("Committee-resident DA backend + server wired");
        }
        // 10. Initialize identity registry (TDIP)
        self.init_identity().await.inspect_err(|e| {
            self.health_monitor
                .mark_unhealthy("identity", e.to_string());
        })?;

        // 10a. Every bonded role this node is configured for must be bonded in
        // chain state, from the operator account (the validator role by its
        // validator bond). A node does not serve a role it has not bonded.
        crate::role_bonds::check(self, &self.config.roles)
            .map_err(crate::error::NodeError::Config)?;

        // Serving delegated agents: answer for the key this machine holds
        // for each agent it is assigned to. Opt-in; a node that has not
        // opted in leaves the handler empty and every request is refused.
        if self.config.serves_agents()
            && let Some(resolver) = self.iroh_resolver.as_ref()
        {
            resolver.agent_key_handler().set(Arc::new(
                crate::agent_delegation::AgentKeyServer::new(
                    self.operator_did(),
                    self.machine_sealing_public_key().ok(),
                ),
            ));
            resolver
                .agent_token_handler()
                .set(Arc::new(crate::agent_delegation::AgentTokenServer));
            info!("Agent-serving handlers installed");
        }
        crate::machine_access::reconcile_owner(self);

        // 10b. Wire per-DID admission controller into the consensus
        //      mempool. Has to happen AFTER both consensus and identity
        //      are up — `NodeLaneResolver` reads from the
        //      `IdentityRegistry`, which does not exist at `init_consensus`
        //      time. Until this call executes the mempool
        //      applies size limits only; the window is bounded by the
        //      few async steps between init_consensus() and here, during
        //      which the node has not yet started servicing inbound traffic.
        if let (Some(consensus), Some(identity), Some(chain)) = (
            self.consensus.clone(),
            self.identity_registry.clone(),
            self.storage.clone(),
        ) {
            use crate::lane_resolver::NodeLaneResolver;
            use tenzro_consensus::admission::{AdmissionConfig, AdmissionController};

            let admission_config = AdmissionConfig::default();
            let resolver = Arc::new(NodeLaneResolver::new(
                identity,
                chain as Arc<dyn KvStore>,
                admission_config.min_verified_stake,
                admission_config.bond_promotes_to_delegated,
                admission_config.bond_min_for_promotion,
            ));
            let admission = Arc::new(AdmissionController::new(admission_config, resolver));
            match consensus.set_admission(admission.clone()) {
                Ok(()) => {
                    info!(
                        "per-DID admission controller wired into consensus mempool \
                         (verified={}/{} burst, delegated={}/{} burst, open={}/{} burst)",
                        admission.config().verified_refill_rate_per_sec,
                        admission.config().verified_burst,
                        admission.config().delegated_refill_rate_per_sec,
                        admission.config().delegated_burst,
                        admission.config().open_refill_rate_per_sec,
                        admission.config().open_burst,
                    );
                    self.admission = Some(admission);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Admission controller already wired — refusing to overwrite"
                    );
                }
            }
        }

        // 10c. Wire the live account state reader into the consensus mempool
        //      for stateful admission (nonce ordering + balance coverage).
        //      Reads the same VM execution state (CF_STATE) that block
        //      execution writes, via a fresh StateAdapter per lookup.
        if let (Some(consensus), Some(storage)) = (self.consensus.clone(), self.storage.clone()) {
            use crate::lane_resolver::NodeAccountStateReader;

            let reader = Arc::new(NodeAccountStateReader::new(storage as Arc<dyn KvStore>));
            match consensus.set_state_reader(reader) {
                Ok(()) => {
                    info!(
                        "Mempool stateful admission wired (nonce ordering + balance \
                         coverage from VM execution state)"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Mempool state reader already wired — refusing to overwrite"
                    );
                }
            }
        }

        // 10d. The identity gate at the mempool: a transaction from an
        //      account with no registered identity is not pooled (audit mode
        //      logs it instead). Node-local; the VM's rules are unchanged.
        if let (Some(consensus), Some(storage)) = (self.consensus.clone(), self.storage.clone()) {
            crate::identity_gate::install_mempool_gate(
                &self.config.onboarding,
                consensus.mempool(),
                storage as Arc<dyn KvStore>,
            );
        }

        // 11. Initialize payment gateway (MPP/x402)
        self.init_payments().await.inspect_err(|e| {
            self.health_monitor
                .mark_unhealthy("payments", e.to_string());
        })?;

        // 12. Initialize bridge
        self.init_bridge().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("bridge", e.to_string());
        })?;

        // 12a. Account abstraction and passkey custody
        self.init_account_abstraction();

        // 14. Initialize and start event loop
        self.init_event_loop().await.inspect_err(|e| {
            self.health_monitor
                .mark_unhealthy("event_loop", e.to_string());
        })?;

        // Now that the event loop is running, hand its sender to the ledger
        // settlement submitter so admitted settlement txs also gossip.
        // `init_payments` built the submitter before this point.
        if let Some(sender) = self.event_loop_tx.clone() {
            *self.validator_tx_gossip.lock() = Some(sender);
            info!("validator-account transactions wired to event-loop gossip sender");
        }

        // 15. Clean up stale model services from previous session
        self.cleanup_expired_model_services();

        // 16. Spawn the streaming cursor GC. The join handle is intentionally
        // detached — the task lifetime is bound to the StreamCursorStore Arc
        // inside, and it runs until the process exits.
        drop(
            self.stream_cursors
                .spawn_gc(std::time::Duration::from_secs(30)),
        );

        // 17. Storage maintenance: history retention into the committee DA
        //     layer, epoch snapshots, disk watermarks, memory charges.
        self.start_storage_maintenance();

        // 18. Permissionless / first-boot validator self-registration. A node
        // configured with the validator role + a self-stake registers itself
        // into the ValidatorRegistry using its own unsealed validator keys —
        // no CLI, no bearer token, no key export. An underfunded account is
        // skipped inside the call; any other failure stops startup.
        self.maybe_self_register_validator()
            .await
            .map_err(|e| NodeError::Config(format!("validator self-registration failed: {e}")))?;
        self.maybe_rotate_validator_key()
            .await
            .map_err(|e| NodeError::Config(format!("validator key rotation failed: {e}")))?;

        // Mark as running
        *self.state.write() = NodeState::Running;
        self.start_load_protection();
        info!("Tenzro Network node started successfully");

        Ok(())
    }

    /// Permissionless validator self-registration, run at the end of
    /// [`Self::start`].
    ///
    /// A node configured with the validator role and a self-stake registers
    /// itself into the ValidatorRegistry using its own unsealed validator keys:
    /// no CLI, no bearer token, no key export.
    ///
    /// If this node holds a hardware validator key, the validator role and a
    /// configured `validator_self_stake`, build a `RegisterValidator`
    /// transaction for that key and this node's node key, with both keys'
    /// proofs of possession, sign it with the node's account signer (all
    /// three derived from or held by this machine's hardware) and submit it
    /// to the local mempool (then gossip). Idempotent: skips if the
    /// key is already a genesis validator or already registered/in-flight,
    /// and skips (non-fatal) if the account is underfunded for stake + gas.
    async fn maybe_self_register_validator(&self) -> Result<()> {
        use tenzro_types::primitives::{Address, ChainId, Nonce};
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

        let self_stake = match self.config.validator_self_stake {
            Some(s) if self.config.roles.is_validator() => s,
            _ => return Ok(()),
        };
        let (Some(signer), Some(validator_key)) = (
            self.identity_signer().cloned(),
            self.validator_signer.clone(),
        ) else {
            return Ok(());
        };
        let node_keys = crate::keygen::NodeKeys::open(&self.config.data_dir)?;
        let node_key: [u8; 32] = node_keys
            .ed25519_public_key()?
            .as_bytes()
            .try_into()
            .map_err(|_| NodeError::Config("the node key is not a 32-byte Ed25519 key".into()))?;
        // The validator's ledger account: the address of the machine's
        // hardware P-256 key (`tenzro_crypto::account_slot`).
        // This is the tx.from the stake escrow debits, so it must be funded
        // before boot.
        let address = Address::new(signer.public_key().account_slot());

        if self.local_validator_address.is_some() {
            info!("Self-register: this node's validator key is already registered, skipping");
            return Ok(());
        }
        // Skip if already registered / in-flight (only re-register after a full Exit).
        if let Some(reg) = self.validator_registry()
            && let Some(entry) = reg.get(&address)
            && !matches!(
                entry.status,
                tenzro_token::validator_registry::ValidatorRegistryStatus::Exited
            )
        {
            info!(status = ?entry.status, "Self-register: already registered, skipping");
            return Ok(());
        }

        // While validator admission is closed only an admitted account may
        // register; say so here rather than let the refusal surface later.
        if let Some(chain) = crate::rpc::chain_state_of(self)
            && let Err(e) = tenzro_vm::validator_admission::check(&chain, address.as_bytes())
        {
            warn!("Self-register: {e}");
            return Ok(());
        }

        // Fail early below the policy floor (the epoch gate enforces it too).
        let floor = crate::rpc::chain_state_of(self)
            .map(|chain| tenzro_vm::native::entry_stake_ladder(&chain).validator)
            .unwrap_or_else(|| tenzro_types::network::StakeLadder::genesis().validator);
        if self_stake < floor {
            warn!(
                self_stake,
                min = floor,
                "Self-register: configured self_stake below minimum, skipping"
            );
            return Ok(());
        }

        // Balance gate: the account must cover stake + gas or the escrow (and
        // thus admission) will fail. Skip non-fatally so the operator can fund
        // it and restart.
        let gas_limit: u64 = 200_000;
        let Some(gas_price) = self.consensus().map(|c| c.node_tx_gas_price()) else {
            return Ok(());
        };
        let storage = match self.storage() {
            Some(s) => s.clone(),
            None => return Ok(()),
        };
        let (balance, nonce) = {
            let state =
                tenzro_vm::StateAdapter::with_storage(storage as Arc<dyn tenzro_storage::KvStore>);
            use tenzro_vm::traits::VmState as _;
            (
                state.get_balance(address.as_bytes()),
                state.get_nonce(address.as_bytes()),
            )
        };
        let needed =
            self_stake.saturating_add((gas_price as u128).saturating_mul(gas_limit as u128));
        if balance < needed {
            warn!(
                %address, balance, needed,
                "Self-register: validator account underfunded for stake + gas; fund it and restart"
            );
            return Ok(());
        }

        let chain_id = self.config.chain_id();
        let proof_of_possession = {
            let key = validator_key.clone();
            let from = address.as_bytes().to_vec();
            tokio::task::spawn_blocking(move || {
                tenzro_consensus::validator_key::prove_registration(&*key, &from, &node_key)
            })
            .await
            .map_err(|e| NodeError::Other(format!("self-register signing task: {e}")))??
        };
        let node_key_proof = tenzro_crypto::Signer::sign(
            &node_keys.ed25519_signer()?,
            &tenzro_consensus::validator_key::node_key_registration_message(
                address.as_bytes(),
                validator_key.public_key(),
                &node_key,
            ),
        )
        .map_err(|e| {
            NodeError::Config(format!("self-register: the node key refused to sign: {e}"))
        })?
        .to_bytes();
        let (vrf_key, vrf_key_proof) = {
            use tenzro_crypto::vrf::VrfProver as _;
            let prover = node_keys.vrf_prover()?;
            let vrf_key = prover.public_key().0;
            let proof = prover
                .prove(
                    &tenzro_consensus::validator_key::vrf_key_registration_alpha(
                        address.as_bytes(),
                        validator_key.public_key(),
                        &node_key,
                        &vrf_key,
                    ),
                )
                .map_err(|e| {
                    NodeError::Config(format!("self-register: the VRF key refused to prove: {e}"))
                })?;
            (vrf_key, proof.as_bytes().to_vec())
        };
        let tx = Transaction::new(
            ChainId::from(chain_id),
            address,
            Address::new([0u8; 32]),
            Nonce::from(nonce),
            TransactionType::RegisterValidator {
                ml_dsa_pubkey: validator_key.public_key().ml_dsa.clone(),
                p256_pubkey: validator_key.public_key().p256.clone(),
                node_key,
                proof_of_possession,
                node_key_proof,
                vrf_key,
                vrf_key_proof,
                withdrawal_address: address,
                self_stake,
                metadata_uri: String::new(),
            },
            gas_limit,
            gas_price,
        );
        let tx_hash = tx.hash();
        let composite = signer
            .sign(
                tenzro_crypto::composite::SignatureContext::Transaction,
                tx_hash.as_bytes(),
            )
            .map_err(|e| NodeError::Config(format!("self-register signing failed: {}", e)))?;
        let signed_tx = SignedTransaction::new(tx, signer.public_key().p256.clone(), composite);

        match self.consensus() {
            Some(consensus) => consensus
                .submit_transaction(signed_tx.clone())
                .map_err(|e| {
                    NodeError::Config(format!("self-register rejected by mempool: {}", e))
                })?,
            None => return Ok(()),
        }
        if let Some(sender) = self.event_sender() {
            let _ = sender
                .send(NodeEvent::LocallyAdmittedTransaction(signed_tx))
                .await;
        }
        info!(
            %address, self_stake,
            "Self-registered as validator (permissionless); pending epoch admission"
        );
        Ok(())
    }

    /// When this node's account is a registered validator whose consensus
    /// key in force is not the key of the scheme its config selects, ask the
    /// chain to rotate to that key: a `RotateValidatorKey` transaction with
    /// the new key's proof of possession, signed by the account and
    /// submitted to the local mempool. The node holds only the configured
    /// key, so it follows the chain until the epoch boundary that seats the
    /// new key and validates from there. Nothing is sent when the key is
    /// already in force or its rotation already requested.
    async fn maybe_rotate_validator_key(&self) -> Result<()> {
        use tenzro_types::primitives::{Address, ChainId, Nonce};
        use tenzro_types::transaction::{SignedTransaction, Transaction};

        let (Some(signer), Some(validator_key), Some(registry)) = (
            self.identity_signer().cloned(),
            self.validator_signer.clone(),
            self.validator_registry().cloned(),
        ) else {
            return Ok(());
        };
        let address = Address::new(signer.public_key().account_slot());
        let Some(entry) = registry.get(&address) else {
            return Ok(());
        };
        if entry.status == tenzro_token::validator_registry::ValidatorRegistryStatus::Exited {
            return Ok(());
        }
        let pending = registry.pending_key(&address);
        let rotation = {
            let key = validator_key.clone();
            tokio::task::spawn_blocking(move || {
                crate::validator_signer::key_rotation(
                    crate::validator_signer::RegisteredKey {
                        key: (&entry.ml_dsa_pubkey, &entry.p256_pubkey),
                        pending: pending.as_ref().map(|(m, e)| (m.as_slice(), e.as_slice())),
                    },
                    &*key,
                    address.as_bytes(),
                    &entry.node_key,
                )
            })
            .await
            .map_err(|e| NodeError::Other(format!("key rotation signing task: {e}")))??
        };
        let Some(rotation) = rotation else {
            return Ok(());
        };

        let gas_limit: u64 = 200_000;
        let (Some(gas_price), Some(storage)) = (
            self.consensus().map(|c| c.node_tx_gas_price()),
            self.storage().cloned(),
        ) else {
            return Ok(());
        };
        let nonce = {
            use tenzro_vm::traits::VmState as _;
            tenzro_vm::StateAdapter::with_storage(storage as Arc<dyn tenzro_storage::KvStore>)
                .get_nonce(address.as_bytes())
        };
        let tx = Transaction::new(
            ChainId::from(self.config.chain_id()),
            address,
            Address::new([0u8; 32]),
            Nonce::from(nonce),
            rotation,
            gas_limit,
            gas_price,
        );
        let composite = signer
            .sign(
                tenzro_crypto::composite::SignatureContext::Transaction,
                tx.hash().as_bytes(),
            )
            .map_err(|e| NodeError::Config(format!("key rotation signing failed: {e}")))?;
        let signed_tx = SignedTransaction::new(tx, signer.public_key().p256.clone(), composite);
        match self.consensus() {
            Some(consensus) => consensus
                .submit_transaction(signed_tx.clone())
                .map_err(|e| NodeError::Config(format!("key rotation rejected by mempool: {e}")))?,
            None => return Ok(()),
        }
        if let Some(sender) = self.event_sender() {
            let _ = sender
                .send(NodeEvent::LocallyAdmittedTransaction(signed_tx))
                .await;
        }
        info!(
            %address,
            scheme = %String::from_utf8_lossy(validator_key.public_key().scheme().label()),
            "Asked to rotate this validator's consensus key; it validates again from the \
             epoch boundary that seats the new key"
        );
        Ok(())
    }

    /// Replicate a freshly-created identity into consensus state via a
    /// `RegisterIdentity` native transaction.
    ///
    /// Historically each RPC registration handler wrote the identity
    /// **local-only** (`storage.put(CF_IDENTITIES, …)` + registry insert), so
    /// a DID created on node A never resolved on node B. This builds a
    /// `RegisterIdentity` tx carrying the identity's *replicable* public
    /// record — DID, controller pubkey, wallet bindings, verifying keys,
    /// metadata — signs it with the node's system hybrid signer, and submits
    /// it through the same consensus mempool path `tenzro_sendRawTransaction`
    /// uses (then gossips). Key MATERIAL (TEE-sealed / hardware-held signing keys) is never
    /// carried and stays node-local by design.
    ///
    /// The VM enforces DID uniqueness against consensus state; every node
    /// then mirrors the emitted `IdentityRegister` log into its
    /// `IdentityRegistry`, so the registration becomes async-confirmed and
    /// resolvable network-wide. Returns the submitted transaction hash.
    ///
    /// `proof` is the holder's own signature over the registration. This
    /// node's signer pays for the transaction and authorizes nothing about the
    /// identity, so without that proof the record would be whatever the
    /// submitter typed.
    pub async fn submit_identity_register(
        &self,
        identity: &tenzro_identity::TenzroIdentity,
        identity_type: &str,
        proof: tenzro_types::identity::RegistrationProof,
    ) -> Result<String> {
        use tenzro_types::primitives::{ChainId, Nonce};
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

        let payload = identity_register_payload(identity, identity_type, proof);

        let gas_limit: u64 = 200_000;
        let gas_price = self
            .consensus()
            .ok_or_else(|| {
                NodeError::Config(
                    "consensus not wired; cannot replicate identity registration".to_string(),
                )
            })?
            .node_tx_gas_price();

        // Sign with the node's hybrid signer — the same one x402 settlements use
        // for system-mediated txs. It exists only on a node that runs consensus;
        // a node without it cannot relay a replicated identity registration.
        let signer = self
            .identity_signer()
            .ok_or_else(|| {
                NodeError::Config(
                    "no hybrid signer on this node — identity replication requires a \
                     consensus node"
                        .to_string(),
                )
            })?
            .clone();
        // from = the account the signer's two keys derive, so the composite
        // signature verifies against a matching from account.
        let from_addr = Address::new(signer.public_key().account_slot());
        let chain_id = self.config.chain_id();
        let nonce = {
            let storage = self.storage().ok_or_else(|| {
                NodeError::Config("storage not wired; cannot replicate identity".to_string())
            })?;
            let state = tenzro_vm::StateAdapter::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>
            );
            use tenzro_vm::traits::VmState as _;
            state.get_nonce(from_addr.as_bytes())
        };
        let tx = Transaction::new(
            ChainId::from(chain_id),
            from_addr,
            Address::new([0u8; 32]),
            Nonce::from(nonce),
            TransactionType::RegisterIdentity {
                did: payload.did,
                identity_type: payload.identity_type,
                display_name: payload.display_name,
                controller_pubkey: payload.controller_pubkey,
                key_type: payload.key_type,
                wallet_id: payload.wallet_id,
                wallet_address: payload.wallet_address,
                pq_verifying_key: payload.pq_verifying_key,
                metadata: payload.metadata,
                proof: payload.proof,
            },
            gas_limit,
            gas_price,
        );
        let tx_hash = tx.hash();
        let composite = signer
            .sign(
                tenzro_crypto::composite::SignatureContext::Transaction,
                tx_hash.as_bytes(),
            )
            .map_err(|e| NodeError::Config(format!("identity-register signing failed: {}", e)))?;
        let signed_tx = SignedTransaction::new(tx, signer.public_key().p256.clone(), composite);
        let in_block_hash = signed_tx.clone().hash();
        let hash_str = format!("{}", in_block_hash);

        match self.consensus() {
            Some(consensus) => consensus
                .submit_transaction(signed_tx.clone())
                .map_err(|e| {
                    NodeError::Config(format!("identity-register rejected by mempool: {}", e))
                })?,
            None => {
                return Err(NodeError::Config(
                    "consensus not wired; cannot replicate identity registration".to_string(),
                ));
            }
        }
        if let Some(sender) = self.event_sender() {
            let _ = sender
                .send(NodeEvent::LocallyAdmittedTransaction(signed_tx))
                .await;
        }
        info!(
            did = %identity.did_string(),
            tx = %hash_str,
            "Submitted RegisterIdentity tx"
        );
        Ok(hash_str)
    }

    /// Stop all subsystems gracefully
    pub async fn stop(&mut self) -> Result<()> {
        {
            let mut state = self.state.write();
            // Only `Running` nodes can be stopped. `Created` / `Starting`
            // means the node hasn't reached a steady state yet — surface
            // that as the `NotStarted` variant so operators get an
            // actionable error rather than a generic state mismatch.
            match *state {
                NodeState::Running => {}
                NodeState::Created | NodeState::Starting => {
                    return Err(NodeError::NotStarted("node".to_string()));
                }
                _ => {
                    return Err(NodeError::InvalidState(format!(
                        "Cannot stop node in state {:?}",
                        *state
                    )));
                }
            }
            *state = NodeState::Stopping;
        }

        info!("Stopping Tenzro Network node...");

        // Stopping must not be shed by a loaded TPM queue, and the load level
        // this node published ends with it.
        let _tpm = tenzro_device_key::tpm_exec::lifecycle();
        if let Some(monitor) = self.load_monitor.lock().take() {
            monitor.stop();
        }

        // Stop in reverse order
        // Note: In a full implementation, each subsystem would have a proper shutdown method

        if let Some(mut challenger) = self.da_possession_challenger.take() {
            challenger.stop();
        }
        if let Some(task) = self.storage_maintenance.take() {
            task.abort();
        }
        self.history_archive = None;
        self.da_committee_backend = None;

        self.payment_gateway = None;
        self.x402_server = None;
        self.x402_facilitator = None;
        self.x402_facilitator_service = None;
        self.admission = None;
        self.identity_registry = None;
        *self.identity_registry_slot.write() = None;
        self.inference_router = None;
        self.provider_manager = None;
        self.model_registry = None;
        self.auth_engine = None;
        self.treasury = None;
        self.policy_applier = None;
        self.token = None;
        self.fee_processor = None;
        self.wallet_service = None;
        self.vm_runtime = None;
        if let Some(consensus) = self.consensus.take() {
            consensus.stop();
        }
        self.tee_registry = None;
        self.tee_provider = None;
        self.network = None;
        self.storage = None;

        *self.state.write() = NodeState::Stopped;
        info!("Tenzro Network node stopped");

        Ok(())
    }

    /// Get node status
    pub async fn status(&self) -> NodeStatus {
        let state = *self.state.read();
        let metrics = self.metrics.get_metrics();
        let health = self.health_monitor.get_status(
            tenzro_types::primitives::BlockHeight::from(0),
            metrics.peer_count as usize,
        );

        let (iroh_enabled, iroh_endpoint_id, iroh_alpns) = match &self.iroh_resolver {
            Some(resolver) => {
                let mut alpns = vec!["iroh-blobs".to_string()];
                if self.iroh_a2a_dispatcher.is_some() {
                    alpns.push("tenzro/a2a".to_string());
                }
                if self.iroh_mcp_handler.is_some() {
                    alpns.push("tenzro/mcp".to_string());
                }
                alpns.push("tenzro/moe".to_string());
                if self.iroh_infer_dispatcher.is_some() {
                    alpns.push("tenzro/infer".to_string());
                }
                (true, Some(resolver.endpoint().id().to_string()), alpns)
            }
            None => (false, None, Vec::new()),
        };

        NodeStatus {
            state: format!("{:?}", state),
            roles: self.config.roles.clone(),
            health_status: health.overall,
            uptime_secs: metrics.uptime_secs,
            block_height: self.chain_tip_height(),
            peer_count: metrics.peer_count,
            data_dir: self.config.data_dir.clone(),
            tee_capable: self.tee_provider.is_some(),
            tee_vendor: self.tee_provider.as_ref().map(|p| p.vendor()),
            iroh_enabled,
            iroh_endpoint_id,
            iroh_alpns,
            // The light build drives no GPU, so it hides none.
            #[cfg(feature = "inference")]
            hidden_gpus: self
                .model_runtime
                .as_ref()
                .map(|_| tenzro_model::runtime::detected_gpus().hidden_descriptions())
                .unwrap_or_default(),
            #[cfg(not(feature = "inference"))]
            hidden_gpus: Vec::new(),
        }
    }

    /// Get health monitor
    pub fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.health_monitor
    }

    /// Get metrics collector
    pub fn metrics(&self) -> &Arc<MetricsCollector> {
        &self.metrics
    }

    // Private initialization methods

    /// The iroh endpoint configuration: blob storage under the node's data
    /// dir. The endpoint key is fresh at every bind and held only in memory;
    /// the machine's hardware key certifies its `EndpointId` in the endpoint
    /// record it publishes.
    fn iroh_config(&self) -> tenzro_iroh::TenzroIrohConfig {
        let mut iroh_cfg = self.config.iroh.clone();
        iroh_cfg.data_dir = self.config.data_dir.join("iroh");
        iroh_cfg
    }

    /// The relays this node's iroh endpoints use.
    fn identity_relays(&self) -> Vec<tenzro_iroh::RelayRef> {
        self.identity_transport
            .as_ref()
            .map(|t| t.relays().to_vec())
            .unwrap_or_default()
    }

    /// Restores the committed state from the configured state-sync peers,
    /// verified against the weak-subjectivity checkpoint. Runs before the
    /// consensus engine and the validator registry are built, so both
    /// hydrate from the restored records. Binds the node's iroh endpoint for
    /// the duration and releases it before the long-lived one is bound.
    async fn restore_state_from_peers(&self) -> Result<crate::snapshot::SyncedState> {
        let (height, hash) = self.weak_subjectivity_anchor.ok_or_else(|| {
            NodeError::Config(
                "state sync needs a weak-subjectivity checkpoint to verify against".to_string(),
            )
        })?;
        let storage = self
            .storage
            .clone()
            .ok_or_else(|| NodeError::Internal("storage is not initialised".to_string()))?;
        // Dial-only, on an ephemeral port: the node's own endpoint binds the
        // configured address right after, and a closed endpoint's sockets
        // are not released until its last task finishes.
        let resolver = tenzro_iroh::IrohBackedResolver::bind_with_config(
            &self.iroh_config().dial_only(),
            self.identity_transport.as_deref(),
        )
        .await
        .map_err(|e| NodeError::Other(format!("bind iroh endpoint for state sync: {e}")))?;
        for addr in &self.state_sync_addrs {
            if let Err(e) = resolver.remember_addr(addr.clone()) {
                warn!(peer = %addr.id, error = %e, "State-sync peer address not recorded");
            }
        }
        let mut last_error = None;
        let mut synced = None;
        for peer in &self.state_sync_peers {
            let transport =
                crate::snapshot::IrohSnapshotTransport::new(resolver.clone(), Some(*peer));
            match crate::snapshot::state_sync(
                &storage,
                &transport,
                &transport,
                height,
                tenzro_types::Hash::new(hash),
                EPOCH_DURATION_BLOCKS,
            )
            .await
            {
                Ok(s) => {
                    synced = Some(s);
                    break;
                }
                Err(e) => {
                    warn!(%peer, error = %e, "State sync from peer failed; trying the next");
                    last_error = Some(e);
                }
            }
        }
        if let Err(e) = resolver.shutdown().await {
            warn!(error = %e, "Releasing the state-sync iroh endpoint failed");
        }
        drop(resolver);
        let _ = std::fs::remove_dir_all(self.iroh_config().dial_only().data_dir);
        synced.ok_or_else(|| {
            last_error.unwrap_or_else(|| NodeError::Config("no state-sync peers configured".into()))
        })
    }

    /// How this node catches up: by snapshot or by replaying blocks (see
    /// [`crate::state_sync_policy`]).
    async fn join_plan(&self) -> crate::state_sync_policy::JoinPlan {
        use tenzro_storage::BlockStore;
        let has_chain = match self.storage.clone() {
            Some(storage) => match tenzro_storage::block_store::BlockStoreImpl::new(storage) {
                Ok(blocks) => blocks
                    .latest_height()
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|h| h.0 > 0),
                Err(_) => true,
            },
            None => true,
        };
        crate::state_sync_policy::plan(crate::state_sync_policy::JoinFacts {
            mode: self.config.state_sync,
            is_validator: self.config.roles.is_validator(),
            named_peers: !self.state_sync_peers.is_empty(),
            has_checkpoint: self.weak_subjectivity_anchor.is_some(),
            has_chain,
        })
    }

    /// Takes the boot identities that resolve within a minute as the
    /// snapshot peers. Which of them holds a snapshot is learnt by asking:
    /// a peer without one answers so, and the next is tried.
    async fn adopt_boot_peers_for_state_sync(&mut self) {
        let Some(identity) = self.identity_transport.clone() else {
            return;
        };
        for _ in 0..60 {
            let addrs: Vec<_> = identity.peer_addrs().into_iter().map(|(_, a)| a).collect();
            if !addrs.is_empty() {
                self.state_sync_peers = addrs.iter().map(|a| a.id).collect();
                self.state_sync_addrs = addrs.into_iter().filter(|a| !a.addrs.is_empty()).collect();
                info!(
                    peers = self.state_sync_peers.len(),
                    "Snapshot peers taken from the resolved boot identities"
                );
                return;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    pub(crate) async fn init_storage(&mut self) -> Result<()> {
        info!("Initializing storage...");

        // Install the memory ledger before anything takes memory from it:
        // the store's cache and memtables are charged to it here, and every
        // model load admits against it later.
        self.install_memory_budget();
        let tier = self.config.resolved_tier();
        let storage_config = self.config.storage.store_config(
            self.config.data_dir.join("db"),
            tenzro_model::memory_budget::global(),
            &tier.tuning(crate::tier::machine_cores()),
        );
        info!(
            tier = %tier,
            memory_mib = storage_config.memory_bytes >> 20,
            background_jobs = storage_config.background_jobs,
            "Store sized for the {tier} tier"
        );
        let store = Arc::new(RocksDbStore::open(&storage_config)?);

        // Initialize genesis block if configured
        if let Some(genesis_config) = &self.config.genesis {
            info!("Initializing genesis block...");
            let _genesis_block = crate::genesis::initialize_genesis(&store, genesis_config).await?;
            info!("Genesis block initialized successfully");
        } else {
            // Without a genesis this node runs a local chain under the chain
            // id `chain_id` reports. Genesis is what records the chain id in
            // state, so it is recorded here instead; otherwise the VM checks
            // custody approvals against 0 while this node issues them for
            // its own chain id.
            use tenzro_vm::traits::VmState as _;
            let mut state =
                tenzro_vm::StateAdapter::with_storage(store.clone() as Arc<dyn KvStore>);
            if tenzro_vm::native::network_chain_id(&state) == 0 {
                state.set_storage(
                    &tenzro_vm::native::SYSTEM_ADDRESS,
                    tenzro_vm::native::NETWORK_CHAIN_ID_KEY.as_bytes(),
                    self.chain_id().to_le_bytes().to_vec(),
                );
                state.commit()?;
            }
        }

        self.storage = Some(store.clone());
        crate::agent_guardrails::attach_taint_store(store.clone() as Arc<dyn KvStore>);
        self.consensus_records = Some(Arc::new(RocksDbStore::open(
            &tenzro_storage::StorageConfig::new(self.config.data_dir.join("consensus"))
                .with_memory_bytes(CONSENSUS_RECORDS_MEMORY)
                .with_write_buffer_size(CONSENSUS_RECORDS_WRITE_BUFFER),
        )?));
        self.event_log = Some(Arc::new(tenzro_events::EventLog::open(
            store.clone() as Arc<dyn KvStore>
        )?));
        self.agent_audit
            .bind_storage(store.clone() as Arc<dyn KvStore>);
        self.egress.address_policy().grants().load(store.as_ref());
        self.health_monitor.mark_healthy("storage");
        self.cluster_identity = Arc::new(crate::cluster_identity::ClusterIdentity::with_storage(
            store.clone() as Arc<dyn tenzro_storage::KvStore>,
            self.http_surface.webauthn_rp_id(),
            self.chain_id(),
        ));

        // Restore the visibility the operator set at runtime; it takes
        // precedence over the configured value.
        if let Some(restored) =
            crate::visibility_rpc::load(&(store.clone() as Arc<dyn tenzro_storage::KvStore>))
        {
            info!(visibility = %restored, "Restored node visibility");
            *self.node_visibility.write() = restored;
        }

        // Swap in the persistent variants of the Permit2 /
        // The Permit2 nonce bitmap now that storage is available. The
        // default `::new()` variant installed at struct-creation time is
        // in-memory only and would drop nonces across restart.
        self.permit2_nonce_bitmap = Arc::new(tenzro_vm::permit2::Permit2NonceBitmap::with_storage(
            store.clone() as Arc<dyn tenzro_storage::KvStore>,
        ));
        // Chainlink Proof-of-Reserve pull adapter. The aggregator lives on an
        // external chain (e.g. eip155:1), so the operator supplies the RPC
        // endpoint via `TENZRO_POR_RPC_URL`; which aggregator speaks for an
        // asset is the feed a `SetReserveFeed` vote installed in consensus
        // state. Empty URL leaves the adapter unable to read until configured.
        let por_rpc_url = std::env::var("TENZRO_POR_RPC_URL").unwrap_or_default();
        self.chainlink_por_adapter = Arc::new(tenzro_bridge::ChainlinkPorAdapter::new(por_rpc_url));

        // Provision the per-node ERC-8004 system signer from the configured
        // hardware device, pointed at this node's own loopback JSON-RPC. Used
        // by node-internal writers (TDIP mirror, reputation dispatchers);
        // never for user-facing RPC writes. Without a configured device the
        // signer stays `None`, which leaves the ERC-8004 mirror disabled at
        // `init_identity()` while the rest of the node boots.
        let chain_id = self.config.chain_id();
        let loopback_rpc_url = format!("http://{}", self.config.rpc_addr);
        match self.config.bridge.erc8004_system_signer.as_ref() {
            Some(hw) => {
                match crate::hardware_evm_signer::build(hw, chain_id, loopback_rpc_url.clone())
                    .await
                {
                    Ok(signer) => {
                        let signer = Arc::new(signer);
                        info!(
                            target: "tenzro::erc8004",
                            address = %signer.sender_address(),
                            device = signer.device_kind(),
                            chain_id,
                            rpc = %loopback_rpc_url,
                            "erc8004-system signer ready (mirror + reputation dispatcher write path)"
                        );
                        self.erc8004_system_signer = Some(signer);
                    }
                    Err(e) => {
                        warn!(
                            target: "tenzro::erc8004",
                            error = %e,
                            "erc8004-system hardware signer unavailable — mirror and dispatchers disabled"
                        );
                    }
                }
            }
            None => {
                info!(
                    target: "tenzro::erc8004",
                    "no erc8004-system hardware signer configured — mirror and dispatchers disabled"
                );
            }
        }

        Ok(())
    }

    async fn init_network(&mut self) -> Result<()> {
        info!("Initializing network...");

        let state = self.chain_state();
        let limits = gossip_limits(state.as_ref().map(|s| s as &dyn tenzro_vm::VmState));
        let network = Arc::new(TenzroNetworkService::new(limits).await?);
        if let Some(storage) = self.storage.clone() {
            // Governed budgets change at an epoch boundary; follow them.
            let net = network.clone();
            tokio::spawn(async move {
                let mut current = limits;
                loop {
                    tokio::time::sleep(GOSSIP_LIMITS_REFRESH).await;
                    let state =
                        tenzro_vm::StateAdapter::with_storage(storage.clone() as Arc<dyn KvStore>);
                    let next = gossip_limits(Some(&state as &dyn tenzro_vm::VmState));
                    if next != current {
                        info!(?next, "gossip budgets changed by governance");
                        net.set_gossip_limits(next);
                        current = next;
                    }
                }
            });
        }
        self.network = Some(network);
        self.health_monitor.mark_healthy("network");

        Ok(())
    }

    async fn init_tee(&mut self) -> Result<()> {
        info!("Detecting TEE capability...");

        // TEE is an OPTIONAL capability — every node participates in
        // consensus regardless of whether it has a TEE. TEE-capable nodes
        // additionally serve confidential-compute and custodial-key
        // workloads on behalf of non-TEE peers.
        //
        // Treating TEE absence as a health "degradation" is wrong: a
        // commodity x86 box with no SEV/TDX is not malfunctioning — it
        // simply can't host the optional confidential-compute capability.
        // We therefore only register the "tee" subsystem in the health
        // monitor when a provider is actually present; absence is logged
        // and surfaces through the capability API instead of /health.
        // The NVIDIA attestation service's keys, if the operator supplied
        // them. Read before any evidence is verified, and fixed for the life
        // of the process: a report is only meaningful against the key set it
        // was checked with.
        if let Some(path) = self.config.nvidia_attestation_jwks_path.as_ref() {
            match std::fs::read_to_string(path) {
                Ok(jwks) => {
                    if tenzro_tee::configure_nvidia_jwks(jwks) {
                        info!("NVIDIA attestation key set loaded; GPU evidence can verify");
                    }
                }
                Err(e) => {
                    return Err(NodeError::Config(format!(
                        "nvidia_attestation_jwks_path is set but unreadable: {e}. \
                         Remove it to refuse GPU evidence, or fix the path — a \
                         node that silently could not read it would refuse every \
                         GPU report while looking configured."
                    )));
                }
            }
        }

        match detect_tee().await {
            Some(provider) => {
                let vendor = provider.vendor();
                info!(
                    tee_vendor = ?vendor,
                    "TEE capability available — node will advertise confidential-compute"
                );
                let registry = Arc::new(TeeRegistry::new(300));
                self.tee_registry = Some(registry);
                // Retain the local hardware provider so the attestation
                // request paths (RPC, MCP, agent workloads) can call
                // `tee_provider().generate_attestation(user_data)` directly
                // against the local enclave instead of returning a stub.
                self.tee_provider = Some(provider);
                self.health_monitor.mark_healthy("tee");
            }
            None => {
                info!(
                    "No TEE hardware on this node — participating in consensus only; \
                     confidential-compute workloads will route to TEE-capable peers"
                );
                // Deliberately do NOT register a "tee" subsystem in the
                // health monitor. `subsystem_is_ok` treats absence as OK,
                // so /health stays Healthy on commodity hardware and the
                // capability is reported via the dedicated TEE API.
            }
        }

        Ok(())
    }

    /// Returns true if this node has a TEE provider available and can
    /// serve confidential-compute / custodial-key workloads.
    ///
    /// All nodes participate in consensus; TEE-capable nodes additionally
    /// advertise this capability so peers can route TEE-gated workloads
    /// (confidential AI inference, custodial key management, attestation
    /// issuance) to them.
    pub fn has_tee_capability(&self) -> bool {
        self.tee_provider.is_some()
    }

    /// Returns the TEE vendor for this node, if any.
    pub fn tee_vendor(&self) -> Option<tenzro_types::tee::TeeVendor> {
        self.tee_provider.as_ref().map(|p| p.vendor())
    }

    async fn init_vm(&mut self) -> Result<()> {
        info!("Initializing VM runtime...");

        let mut vm_config = VmConfig::default();

        // Bind the VM's chain id to the genesis chain id. VmConfig::default()
        // carries the default test id (1337); leaving it unset makes the
        // executor reject EVERY transaction on any other chain with
        // "Chain ID mismatch" (the signing side already uses the genesis id),
        // which silently breaks all transfers and registrations on a fresh
        // network. There is no production genesis-less node, so fall back to the
        // default id only for tests that construct a node without genesis.
        vm_config.chain_id = self
            .config
            .genesis
            .as_ref()
            .map(|g| g.chain_id)
            .unwrap_or(vm_config.chain_id);
        info!(
            chain_id = vm_config.chain_id,
            "VM chain id bound to genesis"
        );

        let vm_runtime = Arc::new(MultiVmRuntime::new(vm_config).await?);

        // Wire the EIP-1559 fee market into the VM gas oracle. The oracle owns
        // the live FeeMarket; `eth_gasPrice` / `eth_maxPriorityFeePerGas` /
        // `eth_feeHistory` read it at request time, and the event loop
        // advances it after every block from the fee settlement that block
        // wrote to state (`record_settled_block`).
        // Without this wiring the oracle falls back to a static 1 Gwei and
        // the EIP-1559 module is dead code.
        // Starts from the base fee the next block will charge, as stored in
        // state by the last settled block.
        let fee_market = match self.storage.as_ref() {
            Some(storage) => {
                let chain =
                    tenzro_vm::StateAdapter::with_storage(storage.clone() as Arc<dyn KvStore>);
                FeeMarket::new(tenzro_vm::Eip1559Config {
                    initial_base_fee: tenzro_vm::ledger::block_base_fee(&chain),
                    ..tenzro_vm::ledger::fee_market_config(&chain)
                })
            }
            None => FeeMarket::default(),
        };
        vm_runtime.gas_oracle().set_fee_market(fee_market).await;

        self.vm_runtime = Some(vm_runtime);
        self.health_monitor.mark_healthy("vm");

        Ok(())
    }

    async fn init_token_economics(&mut self) -> Result<()> {
        info!("Initializing token economics...");

        // The native balance read model over the node's store (an in-memory
        // store for a node opened without one).
        let token = {
            use tenzro_token::tnzo::RocksDbBackend;
            let store: Arc<dyn KvStore> = match &self.storage {
                Some(storage) => storage.clone() as Arc<dyn KvStore>,
                None => Arc::new(tenzro_storage::MemoryStore::new()),
            };
            Arc::new(TnzoToken::new(Arc::new(RocksDbBackend::new(store))))
        };
        self.token = Some(token);

        // Fee accounting for the gas the executor debits per transaction.
        let fee_processor = if let Some(storage) = &self.storage {
            Arc::new(
                tenzro_token::FeeProcessor::with_storage(storage.clone() as Arc<dyn KvStore>)
                    .map_err(|e| {
                        NodeError::Other(format!("Failed to init fee processor: {}", e))
                    })?,
            )
        } else {
            Arc::new(tenzro_token::FeeProcessor::new())
        };
        self.fee_processor = Some(fee_processor);

        // Trust ledger, persisted in CF_CREDENTIALS and re-verified on load.
        self.trust_ledger = Some(Arc::new(match &self.storage {
            Some(storage) => {
                tenzro_trust::TrustLedger::with_storage(storage.clone() as Arc<dyn KvStore>)
                    .unwrap_or_else(|e| {
                        warn!("trust ledger could not be loaded ({}); starting empty", e);
                        tenzro_trust::TrustLedger::new()
                    })
            }
            None => tenzro_trust::TrustLedger::new(),
        }));

        // Initialize the verifiable-inference commitment store +
        // challenge lifecycle (TOPLOC scheme). Persists to
        // CF_CHALLENGES; hydrates filed challenges on boot. Requires
        // durable storage — commitments must survive restarts for
        // challenges to be resolvable, so no in-memory fallback.
        if let Some(storage) = &self.storage {
            self.challenge_manager = Some(
                crate::inference_challenge::ChallengeManager::new(
                    storage.clone() as Arc<dyn KvStore>
                )
                .map_err(|e| state_load_error("ChallengeManager", e))?,
            );
        }

        // Initialize permissionless ValidatorRegistry. Persists to
        // CF_TOKENS so candidate / active / pending-exit / jailed state
        // survives restarts. The post-block scan in EventLoop drives the
        // registry from VM-emitted logs; the epoch boundary hook calls
        // compute_epoch_transition() and feeds the resulting plan into
        // the consensus EpochManager.
        let validator_registry = if let Some(storage) = &self.storage {
            Arc::new(
                tenzro_token::validator_registry::ValidatorRegistry::with_storage(
                    storage.clone() as Arc<dyn KvStore>
                ),
            )
        } else {
            Arc::new(tenzro_token::validator_registry::ValidatorRegistry::new())
        };
        self.validator_registry = Some(validator_registry);

        // Initialize adaptive burn governance dial.
        // Registers the protocol primitives + read RPCs. Enacted changes
        // arrive through the policy applier; validators run the proposal
        // generator once their ledger submitter exists.
        let burn_rate_manager = if let Some(storage) = &self.storage {
            Arc::new(
                tenzro_token::adaptive_burn::BurnRateConfigManager::with_storage(
                    storage.clone() as Arc<dyn KvStore>
                )
                .map_err(|e| state_load_error("BurnRateConfigManager", e))?,
            )
        } else {
            Arc::new(tenzro_token::adaptive_burn::BurnRateConfigManager::new())
        };
        self.burn_rate_manager = Some(burn_rate_manager);

        // Swap the default economic policy for one backed by storage, so a
        // restart resumes whatever governance last applied rather than silently
        // reverting every rate to its default.
        if let Some(storage) = &self.storage {
            self.economic_policy = Arc::new(tenzro_token::EconomicPolicyManager::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ));
            info!(
                "Economic policy hydrated: operator {} bps validating / {} bps delegated, RPC provider {} bps",
                self.economic_policy.current().validating.operator_bps,
                self.economic_policy.current().delegated.operator_bps,
                self.economic_policy.current().delegated.rpc_provider_bps,
            );
        }

        // Initialize treasury with persistent storage if available
        let treasury_addr = tenzro_types::network_treasury_address();
        let treasury = if let Some(storage) = &self.storage {
            use tenzro_token::treasury::TreasuryStorageBackend;
            let backend = Arc::new(TreasuryStorageBackend::new(
                storage.clone() as Arc<dyn KvStore>
            ));
            Arc::new(NetworkTreasury::with_storage(treasury_addr, backend))
        } else {
            Arc::new(NetworkTreasury::new(treasury_addr))
        };
        self.treasury = Some(treasury);

        // Network policy is decided by on-chain governance. Every node applies
        // each enacted change from the block that carries it; at startup it
        // catches up on the settings consensus already holds.
        let policy_applier = Arc::new(crate::policy_reflection::PolicyApplier::new(
            self.economic_policy.clone(),
            self.burn_rate_manager.clone(),
            crate::policy_reflection::own_code_hash(),
        ));
        if let Some(storage) = &self.storage {
            let chain = tenzro_vm::StateAdapter::with_storage(storage.clone() as Arc<dyn KvStore>);
            policy_applier.hydrate(&chain);
        }
        self.policy_applier = Some(policy_applier);

        // Initialize unified token registry (cross-VM token tracking)
        let token_registry = if let Some(storage) = &self.storage {
            Arc::new(
                TokenRegistry::with_storage(storage.clone() as Arc<dyn KvStore>).map_err(|e| {
                    NodeError::Other(format!("Failed to init token registry: {}", e))
                })?,
            )
        } else {
            Arc::new(TokenRegistry::new())
        };
        // Define native TNZO at startup with the full cross-VM pointer
        // pair — wTNZO ERC-20 (EVM) and wTNZO SPL mint (SVM). Both share the
        // same underlying TNZO balance under the Sei V2 pointer model; the registry just records
        // the per-VM addresses so callers can resolve the token by any of them.
        let evm_addr = Some([
            0x10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        let svm_mint = Some(tenzro_vm::svm::spl_adapter::WTNZO_SPL_MINT);
        if let Err(e) = token_registry.define_tnzo(evm_addr, svm_mint) {
            warn!("TNZO token definition: {}", e);
        }

        // Register canonical Tempo L1 TIP-20 stablecoins so the catalog reflects
        // Tempo as a settlement venue of its own. Operator-supplied addresses
        // from `[payments] tempo_stablecoins` take precedence; symbols not
        // overridden fall back to deterministic placeholders so seeing-the-symbol
        // still gives downstream consumers a stable token_id pending canonical
        // Stripe/Paradigm issuance.
        for (symbol, name, decimals, addr_seed) in [
            ("USDC", "USD Coin (Tempo)", 6u8, 0xC1u8),
            ("PYUSD", "PayPal USD (Tempo)", 6u8, 0xC2u8),
            ("USDT", "Tether USD (Tempo)", 6u8, 0xC3u8),
        ] {
            // Skip if already registered on a previous boot — the catalog is
            // RocksDB-persisted, so this hot path runs on every restart.
            if token_registry.get_by_symbol(symbol).is_some() {
                continue;
            }

            // Operator override path: parse `0x...` hex (20 bytes). On malformed
            // input log + skip — don't fall through to the placeholder, since
            // the operator's intent was to pin a canonical address.
            let addr = if let Some(operator_hex) =
                self.config.payments.tempo_stablecoins.get(symbol)
            {
                let trimmed = operator_hex.trim_start_matches("0x");
                match hex::decode(trimmed) {
                    Ok(bytes) if bytes.len() == 20 => {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&bytes);
                        info!(
                            "Tempo TIP-20 {} using operator-supplied address 0x{}",
                            symbol, trimmed
                        );
                        a
                    }
                    Ok(bytes) => {
                        warn!(
                            "Tempo TIP-20 {} operator address has wrong length ({} bytes, want 20); skipping",
                            symbol,
                            bytes.len()
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "Tempo TIP-20 {} operator address is malformed hex ({}); skipping",
                            symbol, e
                        );
                        continue;
                    }
                }
            } else {
                // Deterministic placeholder: 19-byte zero-pad + per-symbol seed byte.
                let mut a = [0u8; 20];
                a[19] = addr_seed;
                a
            };

            if let Err(e) = token_registry.define_tip20(symbol, name, decimals, addr) {
                warn!("Tempo TIP-20 {} definition: {}", symbol, e);
            }
        }

        self.token_registry = Some(token_registry);

        self.health_monitor.mark_healthy("token");

        Ok(())
    }

    async fn init_wallet(&mut self) -> Result<()> {
        info!("Initializing wallet service...");

        // Anchor wallet keystore + contacts under the configured data
        // directory rather than the wallet crate's default relative
        // `./data/wallets`. The relative default breaks any caller whose
        // current working directory is read-only (e.g. a packaged macOS
        // .app launched by Finder) and silently splatters writes into
        // arbitrary cwd locations when it isn't.
        let wallet_dir = self.config.data_dir.join("wallets");
        let contacts_path = self.config.data_dir.join("contacts.json");

        // Resolve the keystore password from the injected unlocker, if any.
        // With a password, the wallet service seals and reads a wallet's
        // record in the on-disk keystore, so wallets PERSIST across restarts. Without an unlocker (or if it's unavailable — e.g. an
        // un-provisioned desktop build that can't reopen its Secure Enclave
        // key after a restart), the wallet stays EPHEMERAL and is recreated
        // each launch. We never fail node init over wallet persistence — a
        // node without a usable unlocker should still boot.
        let mut wallet_config = tenzro_wallet::service::WalletServiceConfig {
            keystore_path: wallet_dir,
            contacts_path,
            ..Default::default()
        };
        if let Some(unlocker) = &self.keystore_unlocker {
            match unlocker.unlock_password() {
                Ok(pw) => {
                    info!("Wallet keystore unlocked — wallets will persist across restarts");
                    wallet_config = wallet_config.with_default_password((*pw).clone());
                }
                Err(tenzro_keystore_unlock::UnlockError::Unavailable(reason)) => {
                    warn!(
                        "Wallet keystore unlock source unavailable ({reason}); wallet will be \
                         ephemeral (recreated each launch)"
                    );
                }
                Err(e) => {
                    warn!("Wallet keystore unlock failed ({e}); wallet will be ephemeral");
                }
            }
        }

        let wallet_service = Arc::new(TenzroWalletService::with_config(wallet_config)?);

        // Re-bind the hardware signer to every persisted wallet that holds this
        // machine's hardware wallet key.
        //
        // A signer is not part of a wallet's stored state — it cannot be,
        // since the private half never leaves the chip — so a wallet reloaded
        // from the keystore comes back signer-less and fails with "no signer
        // bound to wallet …". Binding only at creation was invisible while
        // wallets were ephemeral, because every wallet was necessarily
        // freshly created; making them persist is exactly what exposed it.
        //
        // Only same-key wallets are bound, so a wallet for some other key
        // stays watch-only rather than being handed this machine's key.
        if let Ok(device_signer) = tenzro_device_key::HardwareHybridSigner::open_or_create(
            crate::machine_admission::MACHINE_WALLET_KEY_LABEL,
        ) {
            use tenzro_crypto::HybridSigner as _;
            use tenzro_wallet::WalletService;
            let machine_p256 = device_signer.public_key().p256.clone();
            let signer: std::sync::Arc<dyn tenzro_crypto::HybridSigner> =
                std::sync::Arc::new(device_signer);
            let mut bound = 0usize;
            if let Ok(ids) = wallet_service.list_wallets().await {
                for id in ids {
                    if let Ok(Some(w)) = wallet_service.get_wallet(&id).await
                        && w.public_key.p256 == machine_p256
                    {
                        wallet_service.set_hybrid_signer(id, signer.clone());
                        bound += 1;
                    }
                }
            }
            if bound > 0 {
                info!("Re-bound the TPM validator signer to {bound} persisted wallet(s)");
            }
        }

        self.wallet_service = Some(wallet_service);
        self.health_monitor.mark_healthy("wallet");

        Ok(())
    }

    async fn init_consensus(&mut self, verify_only: bool) -> Result<()> {
        if verify_only {
            info!("Initializing consensus engine for block verification only...");
        } else {
            info!("Initializing consensus engine...");
        }

        // The hardware validator key, if this machine has one. A node without
        // one follows the chain: it imports every block under a checkpoint
        // certificate and never signs.
        let signer: Option<Arc<dyn tenzro_consensus::ValidatorSigner>> = if verify_only {
            None
        } else {
            crate::validator_signer::open_configured(
                self.config.consensus_key_scheme,
                crate::validator_signer::HardwareValidatorSigner::open_for,
            )
            .map_err(NodeError::Config)?
            .map(|s| Arc::new(s) as Arc<dyn tenzro_consensus::ValidatorSigner>)
        };

        // The genesis committee. It is fixed by the genesis file and nothing
        // else: every entry proves possession of its composite key over its
        // address and endpoint.
        let genesis_validators = self
            .config
            .genesis
            .as_ref()
            .map(|g| g.validators.as_slice())
            .unwrap_or_default();
        if genesis_validators.is_empty() && verify_only {
            warn!("No genesis committee: this node follows no chain and serves its roles only");
            return Ok(());
        }
        if genesis_validators.is_empty() {
            return Err(NodeError::Config(
                "The genesis names no validators. A chain starts from a genesis whose \
                 validators hold their consensus keys in hardware."
                    .to_string(),
            ));
        }
        let validators = genesis_validators
            .iter()
            .map(|gv| gv.decode())
            .collect::<Result<Vec<ValidatorInfo>>>()?;
        info!(
            validator_count = validators.len(),
            "Loaded the genesis committee"
        );
        if let Some(s) = signer.as_ref()
            && let Some(v) = validators.iter().find(|v| &v.public_key == s.public_key())
        {
            self.local_validator_address = Some(v.address);
        }

        // Seed permissionless ValidatorRegistry with the genesis validator
        // set as `Active` entries. This is restart-safe and idempotent:
        // `seed_genesis_active` skips any address that already has a registry
        // entry (e.g. on warm restarts where the entries hydrated from
        // CF_TOKENS, or where a validator has since exited and re-registered).
        // Without this, genesis validators would have no registry entry and
        // therefore couldn't be `jail()`ed on equivocation, nor surfaced via
        // `tenzro_listValidators`.
        if let Some(ref registry) = self.validator_registry {
            const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
            for v in &validators {
                // The registry holds stake in wei; the committee in whole TNZO.
                match registry.seed_genesis_active(
                    v.address,
                    v.public_key.ml_dsa.clone(),
                    v.public_key.p256.clone(),
                    v.node_key,
                    v.address, // withdrawal == operator address by default at genesis
                    v.stake.saturating_mul(ONE_TNZO),
                    String::new(),
                ) {
                    Ok(true) => {
                        info!(
                            validator = %v.address,
                            stake = v.stake,
                            "Seeded genesis validator into permissionless registry"
                        );
                    }
                    Ok(false) => {
                        // Already present (warm restart or prior re-registration).
                    }
                    Err(e) => {
                        return Err(NodeError::Other(format!(
                            "genesis validator {} could not be seeded into the validator registry: {e}",
                            v.address
                        )));
                    }
                }
            }
        }

        // Create epoch manager — backed by RocksDB when storage is available,
        // so validator-set history for past epochs survives restart and
        // block-sync can verify historical commit-QCs against the correct
        // set. Without persistence, a node falling behind across an epoch
        // boundary would reject every historical block as `InvalidValidatorSet`
        // and never re-converge — a liveness stall the history prevents.
        let epoch_manager = if let Some(ref storage) = self.storage {
            let epoch_store = std::sync::Arc::new(
                crate::epoch_state_store::RocksDbEpochStateStore::new(storage.clone()),
            );
            EpochManager::with_store(validators, EPOCH_DURATION_BLOCKS, epoch_store)?
        } else {
            // Ephemeral nodes (no storage) get an in-memory-only manager.
            // Used by tests and by short-lived light-client roles that don't
            // produce blocks and therefore don't traverse epoch transitions.
            EpochManager::new(validators, EPOCH_DURATION_BLOCKS)?
        };

        let storage = self
            .storage
            .clone()
            .ok_or_else(|| NodeError::Config("consensus needs the node's storage".to_string()))?;
        let kv: Arc<dyn KvStore> = storage.clone();
        let genesis_hash = {
            use tenzro_storage::BlockStore;
            tenzro_storage::block_store::BlockStoreImpl::new(storage.clone())?
                .get_block_by_height(tenzro_types::BlockHeight(0))
                .await?
                .ok_or_else(|| NodeError::Config("consensus needs the genesis block".to_string()))?
                .hash()
                .0
        };
        let chain_id = self
            .config
            .genesis
            .as_ref()
            .map(|g| g.chain_id)
            .unwrap_or_default();
        let epoch_manager = Arc::new(epoch_manager);
        // The ordering rules (DAG depth, committee seats) are the network's:
        // taken from the genesis whatever this node's own [consensus] says.
        let network = crate::config::network_consensus_config(
            self.config.consensus.as_ref(),
            self.config.genesis.as_ref(),
        )?;
        let consensus = ConsensusHandle::new(
            tenzro_consensus::ConsensusConfig {
                session_key_scheme: self.config.consensus_key_scheme,
                ..network
            },
            self.config
                .genesis
                .as_ref()
                .map(|g| g.time.clone())
                .unwrap_or_default(),
            chain_id,
            genesis_hash,
            epoch_manager.clone(),
            Some(kv.clone()),
            self.consensus_records
                .clone()
                .map(|r| r as Arc<dyn KvStore>),
        )?;
        if let Some(registry) = self.validator_registry.clone() {
            consensus.set_epoch_planner(Arc::new(RegistryEpochPlanStager {
                epoch_manager,
                registry,
                store: Some(kv.clone()),
            }));
        } else {
            warn!(
                "No validator registry wired: epoch transitions on this node will not change the committee"
            );
        }

        // A validator whose registered key is not the configured one keeps
        // the registered key in force, while this machine holds it, until the
        // epoch boundary that seats the configured key.
        if let (Some(configured), Some(registry), Some(account)) = (
            signer.clone(),
            self.validator_registry.as_ref(),
            self.identity_signer.as_ref(),
        ) && let Some(entry) = registry.get(&Address::new(account.public_key().account_slot()))
            && entry.status != tenzro_token::validator_registry::ValidatorRegistryStatus::Exited
            && let Ok(registered) = tenzro_consensus::ValidatorPublicKey::new(
                entry.ml_dsa_pubkey.clone(),
                entry.p256_pubkey.clone(),
            )
        {
            let keys = tokio::task::spawn_blocking(move || {
                crate::validator_signer::validator_keys(configured, Some(&registered), |k| {
                    crate::validator_signer::HardwareValidatorSigner::open_registered(k).map(
                        |held| {
                            held.map(|s| Arc::new(s) as Arc<dyn tenzro_consensus::ValidatorSigner>)
                        },
                    )
                })
            })
            .await
            .map_err(|e| NodeError::Other(format!("validator key task: {e}")))?;
            if keys.incoming.is_some() {
                self.local_validator_address = Some(entry.address);
                self.outgoing_validator_signer = Some(keys.in_force);
            }
        }

        // A validator key registered after genesis is found in the registry.
        if self.local_validator_address.is_none()
            && let Some(s) = signer.as_ref()
            && let Some(registry) = self.validator_registry.as_ref()
            && let Some(entry) = registry.list().into_iter().find(|e| {
                e.ml_dsa_pubkey == s.public_key().ml_dsa && e.p256_pubkey == s.public_key().p256
            })
        {
            self.local_validator_address = Some(entry.address);
        }

        if let Some(request) = self.recovery.take() {
            crate::recovery::apply(
                &request,
                &storage,
                &consensus,
                self.validator_registry.as_deref(),
                chain_id,
            )
            .await?;
        }

        self.validator_signer = signer;
        self.consensus = Some(consensus);
        self.health_monitor.mark_healthy("consensus");
        Ok(())
    }

    /// Makes this node able to validate, once the iroh endpoint its consensus
    /// channels run on is up. Consensus starts at once if this is a fresh
    /// chain and the key is in the genesis committee; otherwise the node
    /// follows, and starts at the first epoch handover that seats it.
    ///
    /// Returns the receivers the event loop takes ordered segments and
    /// certificates from.
    async fn start_validator_consensus(
        &mut self,
    ) -> Result<(
        mpsc::Receiver<crate::consensus_driver::OrderedSegment>,
        mpsc::UnboundedReceiver<tenzro_consensus::Certificate>,
    )> {
        let (ordered_tx, ordered_rx) = mpsc::channel(1024);
        let (certificates_tx, certificates_rx) = mpsc::unbounded_channel();
        let (Some(consensus), Some(signer)) =
            (self.consensus.clone(), self.validator_signer.clone())
        else {
            #[cfg(test)]
            {
                self.test_ordered_segments = Some(ordered_tx);
            }
            return Ok((ordered_rx, certificates_rx));
        };
        let Some(resolver) = self.iroh_resolver.clone() else {
            warn!(
                "No iroh endpoint: this node cannot open consensus channels and follows the chain"
            );
            return Ok((ordered_rx, certificates_rx));
        };
        let storage = self
            .storage
            .clone()
            .ok_or_else(|| NodeError::Config("consensus needs the node's storage".to_string()))?;
        let records = self
            .consensus_records
            .clone()
            .ok_or_else(|| NodeError::Config("consensus needs its records store".to_string()))?;
        let high_water: Arc<dyn tenzro_consensus::VoteHighWater> = Arc::new(
            tenzro_consensus::KvVoteHighWater::new(records as Arc<dyn KvStore>),
        );

        // Certificates this validator forms go to the event loop and to
        // every follower.
        let (formed_tx, mut formed_rx) = mpsc::unbounded_channel::<tenzro_consensus::Certificate>();
        // Followers get the session certificates a certificate names with
        // it, once per epoch (see `ConsensusHandle::publication`).
        let network = self.network.clone();
        let publisher = consensus.clone();
        // Its signers are recorded on chain, by one member per epoch (the
        // others only as timed fallbacks), only for checkpoints that certify
        // real work, and held to go with other traffic or just before the
        // epoch ends, so they earn the epoch's vote reward and an idle chain
        // goes quiet (see `checkpoint_recorder`). The record pays no fee,
        // and nothing waits on it: blocks and checkpoints go on whether or
        // not it lands.
        let record_chain = self
            .config
            .genesis
            .as_ref()
            .map(|g| g.chain_id)
            .unwrap_or_default();
        let recorder = self.identity_signer.clone().map(|signer| {
            crate::checkpoint_recorder::CheckpointRecorder::new(
                publisher.clone(),
                signer,
                storage.clone(),
                record_chain,
                self.validator_nonces.clone(),
                self.validator_tx_gossip.clone(),
                crate::checkpoint_recorder::rank_step_for(publisher.time_rules()),
                Arc::default(),
            )
        });
        tokio::spawn(async move {
            while let Some(cert) = formed_rx.recv().await {
                if let Some(recorder) = recorder.as_ref() {
                    recorder.on_certificate(&cert);
                }
                if let Some(net) = network.as_ref() {
                    let published = publisher.publication(cert.clone());
                    let payload = tenzro_network::MessagePayload::Certificate(
                        bincode::serialize(&published).expect("certificate encodes"),
                    );
                    let message = tenzro_network::NetworkMessage::new(payload);
                    if let Err(e) = net.broadcast("tenzro/certificates", message).await {
                        debug!(error = %e, "certificate not published");
                    }
                }
                if certificates_tx.send(cert).is_err() {
                    return;
                }
            }
        });

        // Proof that a validator signed two checkpoints with one index.
        let (evidence_tx, mut evidence_rx) =
            mpsc::unbounded_channel::<tenzro_consensus::CheckpointEquivocation>();
        // It is kept, and reported on chain from this node's account, which
        // the VM charges gas for; any other account may report it too.
        let evidence_store = storage.clone();
        let chain_id = self
            .config
            .genesis
            .as_ref()
            .map(|g| g.chain_id)
            .unwrap_or_default();
        let reporter = self.identity_signer.clone();
        let reporting = consensus.clone();
        let reporting_nonces = self.validator_nonces.clone();
        let reporting_gossip = self.validator_tx_gossip.clone();
        tokio::spawn(async move {
            while let Some(e) = evidence_rx.recv().await {
                if !e.is_valid(chain_id) {
                    continue;
                }
                let mut key = b"consensus/equivocation/".to_vec();
                key.extend_from_slice(&e.first.epoch.to_be_bytes());
                key.extend_from_slice(&e.first.index.to_be_bytes());
                key.extend_from_slice(&e.public_key.fingerprint());
                let value = bincode::serialize(&e).expect("evidence encodes");
                if let Err(err) = evidence_store.put(tenzro_storage::CF_AUDIT, &key, &value) {
                    warn!(error = %err, "failed to persist checkpoint equivocation evidence");
                }
                if let Some(signer) = reporter.as_ref()
                    && let Err(err) = report_checkpoint_equivocation(
                        &reporting,
                        signer,
                        &evidence_store,
                        chain_id,
                        &reporting_nonces,
                        &reporting_gossip,
                        value,
                    )
                {
                    warn!(error = %err, "checkpoint equivocation not reported on chain");
                }
            }
        });

        // Compact certificates this validator proves go to every follower and
        // light client.
        let (compact_tx, mut compact_rx) =
            mpsc::unbounded_channel::<tenzro_consensus::compact::CompactCertificate>();
        let compact_network = self.network.clone();
        tokio::spawn(async move {
            while let Some(cc) = compact_rx.recv().await {
                let Some(net) = compact_network.as_ref() else {
                    continue;
                };
                let payload = tenzro_network::MessagePayload::CompactCertificate(
                    bincode::serialize(&cc).expect("compact certificate encodes"),
                );
                if let Err(e) = net
                    .broadcast(
                        "tenzro/certificates",
                        tenzro_network::NetworkMessage::new(payload),
                    )
                    .await
                {
                    debug!(error = %e, "compact certificate not published");
                }
            }
        });

        // This validator's signed endpoint announcements go to every peer,
        // its endpoint only sealed to committee members.
        let (announce_tx, mut announce_rx) =
            mpsc::unbounded_channel::<tenzro_consensus::announce::PublishedAnnouncement>();
        let announce_network = self.network.clone();
        tokio::spawn(async move {
            while let Some(announcement) = announce_rx.recv().await {
                let Some(net) = announce_network.as_ref() else {
                    continue;
                };
                let payload = tenzro_network::MessagePayload::ValidatorEndpoint(
                    bincode::serialize(&announcement).expect("announcement encodes"),
                );
                if let Err(e) = net
                    .broadcast(
                        "tenzro/validators",
                        tenzro_network::NetworkMessage::new(payload),
                    )
                    .await
                {
                    debug!(error = %e, "endpoint announcement not published");
                }
            }
        });

        consensus.set_launcher(crate::consensus_driver::Launcher {
            signer: self
                .outgoing_validator_signer
                .clone()
                .unwrap_or(signer.clone()),
            high_water,
            endpoint: resolver.endpoint().clone(),
            identity: self.identity_transport.clone(),
            machine: crate::identity_bootstrap::machine_did(),
            handler: resolver.consensus_handler().clone(),
            segments: ordered_tx,
            certificates: formed_tx,
            compact: compact_tx,
            evidence: evidence_tx,
            announcements: announce_tx,
        });
        if self.outgoing_validator_signer.is_some() {
            consensus.set_incoming_key(signer.clone());
        }
        // A fresh chain starts at genesis; a restarted validator recovers
        // the epoch it was running from its journal. Otherwise the node
        // follows and starts at the first handover that seats its key.
        let tip = {
            use tenzro_storage::BlockStore;
            tenzro_storage::block_store::BlockStoreImpl::new(storage.clone())?
                .latest_height()
                .await?
                .map_or(0, |h| h.0)
        };
        if !crate::consensus_runtime::scoped(|| consensus.resume(tip))? {
            if let Some(recovery) = crate::recovery::pending_start(&storage, tip)? {
                crate::consensus_runtime::scoped(|| {
                    consensus.launch(recovery.epoch, recovery.start)
                })?;
            } else if consensus.latest_certificate().is_none() && tip == 0 {
                let start = self.genesis_start().await?;
                crate::consensus_runtime::scoped(|| consensus.launch(0, start))?;
            }
        }
        Ok((ordered_rx, certificates_rx))
    }

    /// Where the genesis epoch starts: after the genesis block, at its
    /// timestamp, with no checkpoint before it.
    async fn genesis_start(&self) -> Result<tenzro_consensus::EpochStart> {
        use tenzro_storage::BlockStore;
        let storage = self
            .storage
            .clone()
            .ok_or_else(|| NodeError::Config("consensus needs the node's storage".to_string()))?;
        let trie = tenzro_storage::StateTrie::new(storage.clone() as Arc<dyn KvStore>);
        let root = trie
            .root_at(0)?
            .ok_or_else(|| NodeError::Config("the genesis state is not committed".to_string()))?;
        let lookahead = crate::consensus_driver::governed_lookahead(Some(
            &(storage.clone() as Arc<dyn KvStore>),
        ));
        let block = tenzro_storage::block_store::BlockStoreImpl::new(storage)?
            .get_block_by_height(tenzro_types::BlockHeight(0))
            .await?
            .ok_or_else(|| NodeError::Config("consensus needs the genesis block".to_string()))?;
        Ok(tenzro_consensus::EpochStart {
            first_height: 1,
            first_checkpoint: 0,
            prev_checkpoint: [0; 32],
            timestamp_ms: block.header.timestamp.as_millis().max(0) as u64,
            base_blocks: vec![(0, block.hash().0, root.0)],
            leader_lookahead_rounds: lookahead,
        })
    }

    /// Wire the committee-resident Red Stuff DA backend.
    ///
    /// Builds a durable per-validator custody store, an `EpochManagerCommitteeView`
    /// that shapes erasure coding against the live validator set, a
    /// `IrohDaCommitteeSurface` over the `tenzro/da-committee` ALPN, the
    /// writer-side `DaCommitteeBackend`, and the inbound `DaCommitteeServer`
    /// installed behind that ALPN. The store is shared between the backend
    /// (writer side) and the server (custody side) so a sliver received over
    /// the wire is visible to a later local fetch.
    async fn init_committee_da(
        &mut self,
        resolver: Arc<tenzro_iroh::IrohBackedResolver>,
        consensus: Arc<ConsensusHandle>,
        storage: Arc<dyn KvStore>,
    ) -> Result<()> {
        use crate::da_committee::{DaCommitteeBackend, DaCommitteeStore, committee_address};
        use crate::da_committee_surface::{
            DaCommitteeServer, EpochManagerCommitteeView, IrohDaCommitteeSurface,
        };

        // The validator's session signer, certified by its hardware identity
        // key: signs this node's own attestations when it holds a sliver, and
        // its possession proofs.
        let signer: Arc<dyn tenzro_crypto::batch::RecordSigner> = Arc::new(
            crate::batch_signing::RuntimeSigner::new(self.records().cloned().ok_or_else(|| {
                crate::error::NodeError::Config(
                    "the DA committee needs the node's hardware identity key".to_string(),
                )
            })?),
        );
        let local_address = committee_address(signer.identity());

        // Durable custody store, hydrated from CF_DA_COMMITTEE.
        let store = Arc::new(
            DaCommitteeStore::with_storage(storage.clone())
                .map_err(|e| NodeError::Other(format!("committee-DA store: {e}")))?,
        );

        // CommitteeView over the live epoch validator set.
        let committee: Arc<dyn crate::da_committee::CommitteeView> =
            Arc::new(EpochManagerCommitteeView::new(
                consensus.epoch_manager().clone(),
                self.identity_registry_slot(),
            ));

        // Outbound surface: members are dialed at the endpoint their verified
        // consensus endpoint announcement names.
        let surface: Arc<dyn crate::da_committee::DaCommitteeSurface> =
            Arc::new(IrohDaCommitteeSurface::new(
                resolver.endpoint().clone(),
                committee.clone(),
                crate::da_committee_surface::announced_member_endpoints(consensus.clone()),
                local_address,
            ));

        // Writer-side backend and inbound server share the one signer.
        let (recorder, recorded) = tokio::sync::mpsc::unbounded_channel();
        *self.da_recorder_rx.lock() = Some(recorded);
        let backend = Arc::new(
            DaCommitteeBackend::new(signer.clone(), committee.clone(), surface, store.clone())
                .map_err(|e| NodeError::Other(format!("committee-DA backend: {e}")))?
                .with_recorder(recorder),
        );
        self.da_committee_backend = Some(backend.clone());

        // Background possession auditor: every interval, challenge
        // one random attester of one random held certificate to prove current
        // custody of its own sliver. 10 minutes keeps challenge traffic to a
        // single sliver round-trip per tick while still surfacing a member
        // that dropped its slivers within a handful of ticks.
        self.da_possession_challenger = Some(crate::da_committee::spawn_possession_challenger(
            backend,
            std::time::Duration::from_secs(600),
        ));

        // Inbound server, behind the endpoint's committee DA ALPN.
        resolver.da_committee_handler().set(Arc::new(
            DaCommitteeServer::new(committee, store, signer).with_history(storage),
        ));

        Ok(())
    }

    /// Initializes the OAuth 2.1 + DPoP + RAR auth engine.
    ///
    /// Tokens are ES256-signed by a P-256 key derived from the machine's
    /// hardware root, so they survive a restart and no node can mint
    /// another's. Validation is per node, not federated.
    ///
    /// `issuer` is the node's HTTP RPC URL; `audience` is the same URL
    /// — the RPC server is its own resource server.
    async fn init_auth(&mut self) -> Result<()> {
        info!("Initializing auth engine (OAuth 2.1 + DPoP + RAR)...");

        let storage = match self.storage.as_ref() {
            Some(s) => s.clone() as Arc<dyn tenzro_storage::KvStore>,
            None => {
                warn!("Storage not initialized; skipping auth engine init");
                return Ok(());
            }
        };

        // Access tokens are signed by a P-256 key derived from the machine's
        // hardware root: no token-signing secret exists on disk or in memory
        // beyond one signature.
        let keys = match crate::keygen::NodeKeys::open(&self.config.data_dir) {
            Ok(k) => k,
            Err(e) => {
                warn!("No hardware root for access tokens ({e}); the node issues none");
                return Ok(());
            }
        };
        let signer: Arc<dyn tenzro_auth::TokenSigner> =
            Arc::new(crate::access_signer::AccessTokenSigner::new(keys)?);

        let rpc_addr = if self.config.rpc_addr.is_empty() {
            "127.0.0.1:8545".to_string()
        } else {
            self.config.rpc_addr.clone()
        };
        let issuer = format!("http://{rpc_addr}");
        let audience = issuer.clone();

        let cfg = tenzro_auth::AuthEngineConfig::new(issuer, audience);
        let engine = tenzro_auth::AuthEngine::new(cfg, storage, signer)
            .map_err(|e| NodeError::Internal(format!("auth engine init: {}", e)))?;
        self.auth_engine = Some(Arc::new(engine));
        info!("AuthEngine initialized (CF_AUDIT hydrated)");
        self.health_monitor.mark_healthy("auth");

        Ok(())
    }

    /// The model runtime (llama.cpp GGUF inference) and, when the operator
    /// configured one, this machine's part of a model served across the
    /// operator's machines.
    #[cfg(feature = "inference")]
    fn init_model_runtime(&mut self) -> Result<()> {
        let model_runtime = Arc::new(ModelRuntime::with_host(self.model_host.clone())?);
        model_runtime.set_session_checkpoint_interval(std::time::Duration::from_secs(
            self.config.session_checkpoint_interval_secs,
        ));
        self.model_runtime = Some(model_runtime.clone());
        info!("Model runtime initialized");

        if let Some(pipeline) = self.config.layer_pipeline.clone() {
            let gguf_path = self.resolve_gguf_path(&pipeline.model_id);
            crate::layer_pipeline::spawn(
                pipeline,
                crate::layer_pipeline::Context {
                    runtime: model_runtime,
                    gguf_path,
                    membership: self.cluster_identity.own_cluster(),
                    signer: crate::identity_bootstrap::machine_signer(),
                },
            );
        }
        Ok(())
    }

    async fn init_ai_infrastructure(&mut self) -> Result<()> {
        info!("Initializing AI infrastructure...");

        // Initialize model registry with durable backing store when available.
        // ModelRegistry::with_storage() scans CF_MODELS for `info:` prefix keys
        // and rehydrates the in-memory catalog so models registered before the
        // restart remain discoverable.
        let acceptance = self.config.model_licensing.clone();
        let registry = if let Some(ref storage) = self.storage {
            Arc::new(
                ModelRegistry::with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>)
                    .with_acceptance_policy(acceptance),
            )
        } else {
            Arc::new(ModelRegistry::new().with_acceptance_policy(acceptance))
        };
        self.model_registry = Some(registry);

        // Initialize provider manager (with storage persistence if available)
        let provider_manager = if let Some(ref storage) = self.storage {
            Arc::new(ProviderManager::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>
            ))
        } else {
            Arc::new(ProviderManager::new())
        };
        self.provider_manager = Some(provider_manager.clone());
        // Routing reads each provider's standing from consensus: its bond and
        // the SLA verdicts the validators froze for it, refreshed from chain
        // state.
        if let Some(ref storage) = self.storage {
            let pm = provider_manager.clone();
            let storage = storage.clone() as Arc<dyn tenzro_storage::KvStore>;
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    tick.tick().await;
                    let chain = tenzro_vm::StateAdapter::with_storage(storage.clone());
                    let now = crate::calendar::now_ms() as i64;
                    pm.refresh_reputation(&|addr| {
                        crate::provider_standing::standing(&chain, addr.as_bytes(), now)
                    });
                }
            });
        }

        // Initialize usage tracker (with storage persistence if available).
        // The tracker is the producer-side aggregation point for every
        // successful inference's `UsageRecord`; a stored record that cannot
        // be loaded stops startup.
        let usage_tracker = if let Some(ref storage) = self.storage {
            Arc::new(
                tenzro_model::UsageTracker::with_storage(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>
                )
                .map_err(|e| state_load_error("UsageTracker", e))?,
            )
        } else {
            Arc::new(tenzro_model::UsageTracker::new())
        };
        self.usage_tracker = Some(usage_tracker.clone());

        // Sealed-model infrastructure: the manifest store hydrates
        // `sealed:`-prefixed records from CF_MODELS so sealed models
        // installed before a restart remain resolvable, and the X25519
        // recipient key is this node's decryption identity for
        // per-recipient wrapped content keys. Key failure is non-fatal:
        // the node can still seal (publisher role needs only recipients'
        // public keys) but cannot install sealed models addressed to it.
        let sealed_store = if let Some(ref storage) = self.storage {
            Arc::new(tenzro_model::SealedModelStore::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ))
        } else {
            Arc::new(tenzro_model::SealedModelStore::new())
        };
        self.sealed_model_store = Some(sealed_store);
        match crate::keygen::NodeKeys::open(&self.config.data_dir).and_then(|k| k.model_recipient())
        {
            Ok(recipient) => {
                use tenzro_crypto::hybrid_seal::HybridRecipient;
                info!(
                    "Sealed-model recipient key ready (hybrid key fingerprint {})",
                    hex::encode(recipient.public_key().fingerprint())
                );
                self.model_recipient_key = Some(Arc::new(recipient));
            }
            Err(e) => {
                tracing::warn!(
                    "No sealed-model recipient key ({}); this node cannot install sealed models",
                    e
                );
            }
        }

        // EU AI Act Art. 50(2): every node that serves inference produces a
        // signed provenance manifest for each response, signed by the P-256 leg
        // of this machine's hardware identity key. A machine with no such
        // hardware signs nothing: the router then marks responses
        // "synthetic_content=true" without a manifest rather than signing
        // with a key held in software. The store is shared with the
        // `tenzro_getContentProvenance` RPC so the read and write paths see
        // the same in-memory cache.
        let provenance_store = Arc::new(tenzro_model::ProvenanceStore::default());
        self.provenance_store = Some(provenance_store.clone());
        let provenance_signer: Option<tenzro_model::SharedProvenanceSigner> = match self
            .identity_signer
            .clone()
        {
            Some(signer) => Some(tenzro_model::HardwareProvenanceSigner::new(signer).into_shared()),
            None => {
                tracing::warn!(
                    "No hardware identity key for provenance manifests; responses will carry \
                         synthetic_content=true but no signed manifest"
                );
                None
            }
        };
        self.provenance_signer = provenance_signer.clone();

        // Operator-declared jurisdiction claim, built once here so the
        // provider announcement and the local response stamp agree on a
        // single claim. When the node has TEE hardware, the claim is bound
        // to a fresh attestation report whose user_data commits to the
        // declared country + blocs; the SHA-256 of the attestation evidence
        // rides the claim so relying parties can tie it back to the enclave.
        // Without TEE hardware the claim is operator-asserted only
        // (attestation_hash = None) — receipts still verify, they just
        // carry a weaker trust story. This is an attestation-bound locality
        // claim, not cryptographic proof of location: false declarations
        // are punished economically (slashing / reputation), not prevented
        // mathematically.
        if let Some(country) = &self.config.jurisdiction_country {
            let country = country.trim().to_ascii_uppercase();
            let blocs: Vec<String> = self
                .config
                .jurisdiction_blocs
                .iter()
                .map(|b| b.trim().to_ascii_uppercase())
                .filter(|b| !b.is_empty())
                .collect();
            let attestation_hash = if let Some(tee) = &self.tee_provider {
                let mut binding = b"tenzro/jurisdiction".to_vec();
                binding.extend_from_slice(country.as_bytes());
                for b in &blocs {
                    binding.push(0);
                    binding.extend_from_slice(b.as_bytes());
                }
                let user_data = tenzro_crypto::sha256(&binding);
                match tee.generate_attestation(user_data.as_bytes()).await {
                    Ok(report) => tenzro_types::Hash::from_bytes(
                        tenzro_crypto::sha256(&report.attestation_data).as_bytes(),
                    ),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to bind jurisdiction claim to TEE attestation ({}); \
                             claim will be operator-asserted only",
                            e
                        );
                        None
                    }
                }
            } else {
                None
            };
            tracing::info!(
                country = %country,
                blocs = ?blocs,
                attested = attestation_hash.is_some(),
                "Jurisdiction claim declared"
            );
            self.jurisdiction_claim = Some(tenzro_types::JurisdictionClaim {
                country,
                blocs,
                attestation_hash,
                declared_at: tenzro_types::Timestamp::now(),
            });

            // Jurisdiction signer: same node key as the provenance signer so
            // `tenzro_jurisdiction` receipts verify against the announcement
            // pubkey consumers pinned. No ephemeral fallback — a locality
            // claim that can't be bound to a registered provider key is not
            // worth stamping.
            self.jurisdiction_signer = match self.records.clone() {
                Some(signer) => {
                    Some(tenzro_model::Ed25519JurisdictionSigner::new(signer).into_shared())
                }
                None => {
                    tracing::warn!(
                        "Jurisdiction declared but no node key available; locally served \
                         responses will not carry jurisdiction receipts"
                    );
                    None
                }
            };
        }

        // Initialize inference router with the tracker attached so every
        // successful inference flows through `record_usage` for durable
        // per-model / per-provider / global aggregation, and stamps a
        // provenance manifest before returning each response.
        let router_transport = Arc::new(crate::infer::RouterTransport::default());
        let mut router_builder = InferenceRouter::new(provider_manager)
            .with_usage_tracker(usage_tracker)
            .with_provenance_store(provenance_store)
            .with_transport(router_transport.clone());
        if let Some(registry) = self.model_registry.clone() {
            router_builder = router_builder.with_registry(registry);
        }
        if let Some(signer) = provenance_signer {
            router_builder = router_builder.with_provenance_signer(signer);
        }
        // Provider receipts and manifests verify against the identity key
        // registered for the provider's machine DID, read at check time.
        let identity_slot = self.identity_registry_slot();
        router_builder = router_builder.with_identity_keys(Arc::new(move |did: &str| {
            crate::identity_bootstrap::registered_identity_key(&identity_slot, did)
        }));
        // On a validator, every routed call is signed with the node key and
        // fed to the compute market. Only validators' observations are
        // admitted anywhere, so other nodes make none; without a network or a
        // hardware key there is nobody to share them with or nothing to sign
        // them with.
        if self.config.roles.is_validator()
            && let Some(network) = self.network.clone()
        {
            match crate::keygen::NodeKeys::open(&self.config.data_dir) {
                Ok(keys) => {
                    let sink = crate::compute_index_reporter::spawn(
                        self.compute_observations.clone(),
                        keys,
                        network,
                    );
                    router_builder = router_builder.with_observation_sink(sink);
                }
                Err(e) => warn!(
                    "No node key for compute observations ({}); this node will not \
                     contribute to the price feed",
                    e
                ),
            }
        }
        let router = Arc::new(router_builder);
        self.inference_router = Some(router);

        // Tenzro iroh endpoint — single resolver shared
        // across the storage `IrohBlobsDaBackend` and
        // direct `tenzro://blob/<hash>` URI fetches. Construction is opt-in
        // via `NodeConfig::iroh`; when absent the node runs without an iroh
        // data plane (inline DA fallback only).
        //
        // Bound here — before its consumers in this function —
        // so downstream consumers in this function can detect `self.iroh_resolver`
        // and prefer the iroh-blobs DA backend over `InlineBackend`.
        //
        // The same endpoint carries the node's gossip topics (attached to
        // the network service below) and its consensus channels.
        // Iroh data plane is always bound, relaying through the relays the
        // identity transport admitted (none on an isolated node, which is
        // then reachable on direct paths only).
        let mut cfg = self.iroh_config();
        let relays = self.identity_relays();

        // Construct a deferred A2A dispatcher now so the `tenzro/a2a` ALPN is
        // registered on the iroh router at bind time. The real backing
        // dispatcher (which needs `Arc<TenzroNode>` for `A2aState`) gets
        // installed in `main.rs` after `Arc::new(node)`. Until then, the
        // dispatcher returns a JSON-RPC `-32603` envelope — peers see a
        // defined response rather than a hung stream.
        let a2a_deferred = Arc::new(tenzro_iroh::DeferredJsonRpcDispatcher::new("a2a"));
        self.iroh_a2a_dispatcher = Some(a2a_deferred.clone());

        let a2a_dispatcher: Arc<dyn tenzro_iroh::JsonRpcDispatcher> = a2a_deferred;

        // MCP-over-iroh: same trampoline pattern. The real handler
        // (`mcp::iroh_transport::IrohMcpHandler`) needs `Arc<TenzroNode>`
        // and is installed from `main.rs` after `Arc::new(node)`.
        let mcp_deferred = Arc::new(tenzro_iroh::DeferredMcpHandler::new());
        self.iroh_mcp_handler = Some(mcp_deferred.clone());
        let mcp_handler: Arc<dyn tenzro_iroh::McpStreamHandler> = mcp_deferred;

        // MoE-over-iroh: unlike A2A/MCP, the dispatcher needs only the
        // expert runtime and the announce-signer receipt identity, both of
        // which already exist — register the real one. Without a signer on
        // disk the holder serves receiptless and remote routers reject it,
        // matching the fail-closed provider-announcement policy. The light
        // build holds no experts and registers no MoE ALPN.
        #[cfg(feature = "inference")]
        let moe_dispatcher: Option<Arc<dyn tenzro_iroh::JsonRpcDispatcher>> = {
            let moe_receipt_identity = self
                .batch_service
                .clone()
                .zip(self.self_provider_address())
                .map(|(service, provider)| crate::moe::MoeReceiptIdentity {
                    service,
                    provider,
                    wait: crate::batch_signing::BatchSigningParams::default().receipt_wait(),
                });
            // `moe/execute` is a compute surface, gated by the access policy
            // once the node is bound behind its shared handle.
            Some(Arc::new(crate::moe::MoeIrohDispatcher::new(
                Arc::clone(&self.moe_runtime),
                moe_receipt_identity,
                Arc::clone(&self.self_ref),
            )))
        };
        #[cfg(not(feature = "inference"))]
        let moe_dispatcher: Option<Arc<dyn tenzro_iroh::JsonRpcDispatcher>> = None;

        // Inference-over-iroh: same trampoline pattern as A2A. The real
        // dispatcher (`crate::infer::IrohInferDispatcher`) needs
        // `Arc<TenzroNode>` to reach `handle_chat` and is installed from
        // `main.rs` after `Arc::new(node)`.
        let infer_deferred = Arc::new(tenzro_iroh::DeferredRequestHandler::new("inference"));
        self.iroh_infer_dispatcher = Some(infer_deferred.clone());
        let infer_dispatcher: Arc<dyn tenzro_iroh::RequestHandler> = infer_deferred;

        // The endpoint keeps one id across restarts: its key is derived from
        // this machine's hardware root at each boot and held only in memory,
        // so the records peers hold still name it after a restart. A key the
        // embedder already gave this endpoint is kept: nodes bound in one
        // process on one machine would otherwise all derive the same key and
        // take each other's offers for their own.
        if cfg.endpoint_secret.0.is_none() && !crate::identity_bootstrap::remote_tpm_configured() {
            match tenzro_device_key::derive::DerivationRoot::open_or_create()
                .and_then(|r| r.endpoint_secret(ENDPOINT_KEY_LABEL))
            {
                Ok(secret) => {
                    cfg.endpoint_secret = tenzro_iroh::EndpointSecret(Some(*secret));
                }
                Err(e) => {
                    warn!(error = %e, "no hardware root for a stable endpoint key; using one made for this boot")
                }
            }
        }
        match tenzro_iroh::IrohBackedResolver::bind_with_jsonrpc(
            &cfg,
            self.identity_transport.as_deref(),
            Some(a2a_dispatcher),
            Some(mcp_handler),
            moe_dispatcher,
            Some(infer_dispatcher),
        )
        .await
        {
            Ok(resolver) => {
                info!(
                    bind_addr = %cfg.bind_addr,
                    relays = relays.len(),
                    "Tenzro iroh resolver bound (endpoint key from the hardware root, persistent blob store, A2A + MCP + MoE + infer + http ALPNs registered)"
                );
                if let Some(identity) = &self.identity_transport {
                    crate::identity_bootstrap::announce(
                        identity,
                        resolver.endpoint().clone(),
                        &self.config,
                        &self.node_visibility.read(),
                    );
                }

                // Snapshots of the committed state are published as blobs on
                // this endpoint, and their manifests served over its
                // state-sync ALPN.
                if let Some(store) = self.storage.clone() {
                    let transport: Arc<dyn crate::snapshot::BlobStore> = Arc::new(
                        crate::snapshot::IrohSnapshotTransport::new(resolver.clone(), None),
                    );
                    let snapshot_store = Arc::new(
                        crate::snapshot::SnapshotStore::new(
                            store,
                            transport,
                            self.config
                                .snapshot
                                .clone()
                                .resolved(self.config.roles.is_validator()),
                        )
                        .with_data_dir(self.config.data_dir.clone()),
                    );
                    resolver.snapshot_directory().set(snapshot_store.clone());
                    // Snapshots past the retention (or whose lease ran out
                    // after a peer fetched them) are removed with their blobs.
                    {
                        let snapshot_store = snapshot_store.clone();
                        tokio::spawn(async move {
                            let mut tick =
                                tokio::time::interval(std::time::Duration::from_secs(600));
                            loop {
                                tick.tick().await;
                                if let Err(e) = snapshot_store.maintain().await {
                                    tracing::warn!(error = %e, "state snapshot retention failed");
                                }
                            }
                        });
                    }
                    self.snapshot_store = Some(snapshot_store);
                }
                for addr in &self.state_sync_addrs {
                    let _ = resolver.remember_addr(addr.clone());
                }
                // Gossip topics travel over this endpoint, joined through the
                // peers the operator named and every boot identity (the
                // genesis validators included) once its record resolves.
                if let Some(network) = &self.network {
                    let chain_id = self.config.chain_id();
                    match network.attach_gossip(resolver.gossip().clone(), chain_id) {
                        Ok(()) => {
                            network.add_gossip_peers(&self.state_sync_peers).await;
                            if let Some(identity) = &self.identity_transport {
                                network.set_gossip_identities(Arc::new(
                                    crate::identity_bootstrap::RecordedPeers {
                                        store: identity.store().clone(),
                                        consensus: self.consensus.clone(),
                                        registry: self.chain_registry(),
                                        gate: Some(resolver.identity_gate().clone()),
                                    },
                                ));
                                crate::identity_bootstrap::seed_gossip(
                                    identity,
                                    network.clone(),
                                    resolver.endpoint().clone(),
                                );
                            }
                        }
                        Err(e) => warn!(error = %e, "Gossip not attached to the iroh endpoint"),
                    }
                }
                router_transport.bind(resolver.endpoint().clone());
                self.install_identity_gate(&resolver);
                self.iroh_resolver = Some(resolver);
            }
            Err(e) => {
                // The endpoint carries Tenzro discovery; a node without it
                // cannot be found or find anyone, so it stops here rather
                // than run on some other discovery path.
                return Err(NodeError::Other(format!(
                    "iroh endpoint and Tenzro discovery did not start: {e}"
                )));
            }
        }

        // Where the agent audit trail's epoch entries are published: chosen
        // by `NodeConfig::da_backend`. `Auto` prefers iroh-blobs when the
        // resolver is bound and falls back to the in-process inline store.
        let da: Arc<dyn tenzro_storage::da::DaBackend> = match self.config.da_backend {
            crate::config::DaBackendSelector::Inline => {
                info!("Agent audit entries published with inline DA backend (da_backend=inline)");
                Arc::new(tenzro_storage::da::InlineBackend::new())
            }
            crate::config::DaBackendSelector::IrohBlobs => match self.iroh_resolver {
                Some(ref resolver) => {
                    info!(
                        "Agent audit entries published with iroh-blobs DA backend (da_backend=iroh_blobs)"
                    );
                    tenzro_iroh::IrohBlobsDaBackend::arc(resolver.clone())
                }
                None => {
                    return Err(NodeError::Other(
                        "da_backend=iroh_blobs requires the iroh resolver, but it is not bound"
                            .to_string(),
                    ));
                }
            },
            crate::config::DaBackendSelector::Committee => match self.da_committee_backend {
                Some(ref backend) => {
                    info!(
                        "Agent audit entries published with committee-resident DA backend (da_backend=committee)"
                    );
                    backend.clone()
                }
                None => {
                    return Err(NodeError::Other(
                            "da_backend=committee requires the committee-resident backend, but it is not bound (validator role + consensus required)".to_string(),
                        ));
                }
            },
            crate::config::DaBackendSelector::Auto => {
                if let Some(ref resolver) = self.iroh_resolver {
                    info!(
                        "Agent audit entries published with iroh-blobs DA backend (da_backend=auto)"
                    );
                    tenzro_iroh::IrohBlobsDaBackend::arc(resolver.clone())
                } else {
                    Arc::new(tenzro_storage::da::InlineBackend::new())
                }
            }
        };
        self.agent_da = Some(da);

        // The storage-provider runtime. Renters pay for kept objects through
        // storage compute claims in consensus state.
        if (self.config.roles.serves_storage() || self.config.roles.serves_ai())
            && self.storage.is_some()
        {
            // A resolver, not a value. The payee cannot be captured here:
            // this runs before the identity registry finishes loading, so
            // `operator_payee()` would answer with the machine-account fallback
            // and keep that answer for the life of the process — while staking
            // and settlement, resolving later, use the identity wallet. The
            // deal is then bonded against one address and its stake read from
            // another.
            //
            // The three inputs are cloned rather than capturing `self`, which
            // would make the runtime hold an `Arc` back to the node.
            let payee_registry = self.identity_registry_slot();
            let payee_machine = machine_operator_of(self.identity_signer.as_ref());
            let payee_configured = self.config.operator_did.clone();
            let provider_address: Arc<
                dyn Fn() -> Option<tenzro_types::primitives::Address> + Send + Sync,
            > = Arc::new(move || {
                // Read the slot per call. Before `init_identity()` this is
                // still `None` and the machine-account fallback applies; after
                // it, every caller agrees on the identity wallet.
                let guard = payee_registry.read();
                resolve_operator_payee(
                    guard.as_ref(),
                    payee_machine.as_ref(),
                    payee_configured.as_deref(),
                )
            });
            // Storage-provider runtime. Needs the iroh data plane for shard
            // transport.
            if self.config.roles.serves_storage() {
                match &self.iroh_resolver {
                    Some(resolver) => {
                        let resolver: Arc<dyn tenzro_iroh::IrohResolver> = resolver.clone();
                        let policy = self.config.provider_rates.storage.clone();
                        let storage_rate = policy.effective_rate();
                        let runtime = match &self.storage {
                            Some(kv) => crate::storage_provider_runtime::StorageProviderRuntime::with_storage(
                                provider_address.clone(),
                                resolver,
                                policy,
                                kv.clone() as Arc<dyn tenzro_storage::KvStore>,
                            ),
                            None => crate::storage_provider_runtime::StorageProviderRuntime::new(
                                provider_address.clone(),
                                resolver,
                                policy,
                            ),
                        };
                        self.storage_runtime = Some(Arc::new(runtime));
                        info!(
                            provider = ?provider_address(),
                            rate = storage_rate,
                            "Storage-provider runtime spawned (payee resolved per use)"
                        );
                    }
                    None => warn!(
                        "StorageProvider role set but iroh resolver unavailable; storage runtime not spawned"
                    ),
                }
            }

            // LAN discovery of the verified members of this node's cluster.
            if self.config.roles.serves_ai()
                && let Some(ref resolver) = self.iroh_resolver
            {
                self.cluster_identity
                    .spawn_lan_discovery(resolver.endpoint().clone());
            }
        } else if self.config.roles.serves_storage()
            || self.config.roles.serves_ai()
            || self.config.roles.serves_compute()
        {
            warn!(
                "Provider role set but state storage unavailable; storage/compute runtimes not spawned"
            );
        }

        // Intent routing (the inference router's model selection tier), with
        // the per-DID budget gate read from consensus Terms so intent-routed dispatch enforces the same
        // rolling-window ceiling as direct payments.
        if let Some(router) = self.inference_router.clone() {
            let mut meta = tenzro_model::routing::IntentPolicy::new()
                .with_local_jurisdiction(self.jurisdiction_claim.clone());
            if let Some(ref storage) = self.storage {
                meta = meta.with_budget_gate(Arc::new(crate::terms_gate::ChainTermsGate::new(
                    storage.clone() as Arc<dyn KvStore>,
                )));
            }
            // Wallet-balance ceiling: read the payer's on-chain TNZO balance so
            // no intent is ever routed to a model the payer cannot pay for.
            if let Some(ref token) = self.token {
                let balance = Arc::new(crate::router_inputs::TnzoBalanceProvider::new(
                    token.clone(),
                ));
                meta = meta.with_balance_provider(balance);
            }
            // Per-query difficulty: cluster prompts by embedding and score
            // candidates on the error rate each has actually shown in that
            // neighbourhood, instead of on declared parameter counts alone.
            // Observations persist so the index survives restarts.
            let difficulty = match self.storage.clone() {
                Some(storage) => tenzro_model::difficulty::DifficultyIndex::with_storage(
                    tenzro_model::difficulty::DEFAULT_CLUSTER_CAPACITY,
                    storage as Arc<dyn tenzro_storage::KvStore>,
                )
                .unwrap_or_else(|e| {
                    warn!("route difficulty index starting empty (hydrate failed): {e}");
                    tenzro_model::difficulty::DifficultyIndex::new(
                        tenzro_model::difficulty::DEFAULT_CLUSTER_CAPACITY,
                    )
                }),
                None => tenzro_model::difficulty::DifficultyIndex::new(
                    tenzro_model::difficulty::DEFAULT_CLUSTER_CAPACITY,
                ),
            };
            let clusters = difficulty.cluster_count();
            meta = meta.with_difficulty_index(Arc::new(difficulty));
            // Prompt embedding reuses the text-embedding runtime shared with the
            // agent memory tier. With no embedding model loaded, and in the
            // light build, which has no runtime, routing scores declared
            // metadata only.
            #[cfg(feature = "inference")]
            {
                meta = meta.with_prompt_embedder(Arc::new(
                    crate::router_inputs::RuntimePromptEmbedder::new(
                        self.text_embedding_runtime.clone(),
                    ),
                ));
            }
            // The offers other providers are announcing on `tenzro/models` right
            // now, scored alongside this node's own catalog. Without this the
            // intent tier only ever sees what this operator registered locally,
            // so what the network can serve would depend on per-node curation.
            // Each offer also names the address that serves it, so the provider
            // share follows from the winning offer.
            // The provider map is joined on so an offer arrives at selection
            // carrying the warm-prefix summary and concurrency its provider
            // signed, not just `{model, endpoint}` — that is what lets a
            // follow-up turn return to the provider already holding the
            // conversation's prefix instead of paying the prefill twice.
            meta = meta.with_network_catalog(Arc::new(
                crate::network_catalog::GossipNetworkCatalog::new(self.network_models.clone())
                    .with_providers(self.network_providers.clone())
                    .with_chain(self.storage.clone().map(|s| s as Arc<dyn KvStore>)),
            ));
            // Operator task→model overrides: the operator pins which served
            // model handles which kind of task; unpinned use cases keep
            // benchmark and measured selection. Two channels, both optional:
            // the `task_models` config table,
            // and the `TENZRO_TASK_MODELS` env var (a JSON object, e.g.
            // `{"code":"qwen3.8-27b","reasoning":"muse-glimmer-30b"}`) for
            // env-configured deployments that pass no config file. The env
            // entries are merged over the config table.
            let mut task_models = self.config.task_models.clone();
            if let Ok(raw) = std::env::var("TENZRO_TASK_MODELS") {
                let raw = raw.trim();
                if !raw.is_empty() {
                    match serde_json::from_str::<std::collections::HashMap<String, String>>(raw) {
                        Ok(env_map) => task_models.extend(env_map),
                        Err(e) => warn!(
                            "TENZRO_TASK_MODELS is not a valid JSON object of use_case->model_id; ignoring: {e}"
                        ),
                    }
                }
            }
            if !task_models.is_empty() {
                let mut pairs: Vec<String> = task_models
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                pairs.sort();
                info!("Task-model overrides active: {}", pairs.join(", "));
            }
            meta = meta.with_routing_preferences(task_models);
            if let Err(e) = meta.install(router) {
                return Err(crate::error::NodeError::Config(format!(
                    "intent routing: {e}"
                )));
            }
            info!(
                "Intent routing (intent → model) installed with {clusters} difficulty cluster(s)"
            );
        }

        // Background liveness sweeper: marks silent model service endpoints
        // Inactive and purges them past the configured TTL. Only runs when
        // storage is wired; in-memory mode (tests) skips it so they don't race.
        if let Some(ref storage) = self.storage {
            let sweeper = crate::liveness::spawn_liveness_sweeper(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                crate::liveness::LivenessConfig::default(),
            );
            self.liveness_sweeper = Some(sweeper);
            info!("Liveness sweeper spawned (5min cadence)");
        }

        // Initialize HuggingFace downloader. Weights are stored under the node's
        // persistent data_dir (data_dir/models by default) so they survive a
        // restart rather than being re-downloaded every boot.
        let models_dir = self.config.effective_models_dir();
        std::fs::create_dir_all(&models_dir).map_err(|e| {
            NodeError::Internal(format!("Failed to create models directory: {}", e))
        })?;
        let accepted = self.config.model_licensing.accepted_license_ids.clone();
        let hf_downloader = match self.iroh_resolver.as_ref() {
            Some(resolver) => {
                let fetcher =
                    crate::model_blob_fetcher_bridge::IrohBlobFetcher::arc(Arc::clone(resolver));
                info!("HuggingFace downloader wired with iroh peer-first blob fetcher");
                Arc::new(
                    HfDownloader::new(models_dir)
                        .with_blob_fetcher(fetcher)
                        .with_accepted_licences(accepted),
                )
            }
            None => {
                info!("HuggingFace downloader initialized (no iroh resolver — HF CDN only)");
                Arc::new(HfDownloader::new(models_dir).with_accepted_licences(accepted))
            }
        };
        self.hf_downloader = Some(hf_downloader);

        // The model runtime (llama.cpp GGUF inference), and this machine's
        // part of a model served across the operator's machines. The light
        // build has neither.
        #[cfg(feature = "inference")]
        self.init_model_runtime()?;

        // Quote honest cold-start times from the first request onward.
        self.seed_lifecycle_sizes();

        // The operator's model stacks, applied by the residency loop spawned
        // at the end of this function.
        self.restore_provider_schedule();
        self.restore_provider_pricing();

        // ═══════════════════════════════════════════════════════════════════════
        // An operator's offload is honoured before anything is restored.
        //
        // See `offload_key`: a model the operator stopped stays stopped across
        // restarts and crashes, and the way that is expressed is a row saying
        // so — not the absence of a row.
        let offloaded: std::collections::HashSet<String> = self
            .storage
            .as_ref()
            .and_then(|s| {
                s.get_keys_with_prefix(CF_MODELS, OFFLOAD_PREFIX.as_bytes())
                    .ok()
            })
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| std::str::from_utf8(k).ok())
                    .filter_map(|k| k.strip_prefix(OFFLOAD_PREFIX))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        // The runtime refuses to load them too, so no request path can bring
        // one back before the operator serves it again.
        #[cfg(feature = "inference")]
        if let Some(runtime) = self.model_runtime.as_ref() {
            for model_id in &offloaded {
                runtime.hold_stopped(model_id);
            }
        }

        // STARTUP RESTORATION: Restore served_models from RocksDB CF_MODELS
        // The existing gossip heartbeat will re-announce restored models to peers.
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref storage) = self.storage {
            match storage.get_keys_with_prefix(CF_MODELS, b"served:") {
                Ok(keys) => {
                    let mut restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(key_str) = std::str::from_utf8(key_bytes) {
                            let Some(model_id) = key_str.strip_prefix("served:") else {
                                continue;
                            };
                            let visibility = storage
                                .get(CF_MODELS, key_bytes)
                                .ok()
                                .flatten()
                                .and_then(|data| {
                                    serde_json::from_slice::<serde_json::Value>(&data).ok()
                                })
                                .and_then(|record| {
                                    crate::visibility_rpc::persisted_visibility(&record)
                                });
                            if offloaded.contains(model_id) {
                                // The operator stopped this one. Restoring it
                                // here is how a deliberate offload came back
                                // 3.4 seconds after a restart, holding 29 GB
                                // of GPU the operator had just freed.
                                info!(
                                    model_id = %model_id,
                                    "Not restoring: offloaded by the operator"
                                );
                                continue;
                            }
                            self.served_models.insert(model_id.to_string(), visibility);
                            restored += 1;
                        }
                    }
                    if restored > 0 {
                        info!(
                            "Restored {} served model(s) from RocksDB CF_MODELS on startup",
                            restored
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to restore served models from CF_MODELS on startup: {}",
                        e
                    );
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP RESTORATION: Restore model_services from RocksDB CF_MODEL_SERVICES
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref storage) = self.storage {
            match storage.get_keys_with_prefix(CF_MODEL_SERVICES, b"") {
                Ok(keys) => {
                    let mut restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(instance_id) = std::str::from_utf8(key_bytes)
                            && let Ok(Some(data)) = storage.get(CF_MODEL_SERVICES, key_bytes)
                            && let Ok(instance) = serde_json::from_slice::<
                                tenzro_types::model::ModelServiceInstance,
                            >(&data)
                        {
                            self.model_services
                                .insert(instance_id.to_string(), instance);
                            restored += 1;
                        }
                    }
                    if restored > 0 {
                        info!(
                            "Restored {} model service(s) from RocksDB CF_MODEL_SERVICES on startup",
                            restored
                        );
                    }

                    // Also restore network-discovered model endpoints (from gossip, persisted)
                    let mut net_restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(key_str) = std::str::from_utf8(key_bytes)
                            && key_str.starts_with("net_model:")
                            && let Ok(Some(data)) = storage.get(CF_MODEL_SERVICES, key_bytes)
                            && let Ok(reg) = serde_json::from_slice::<
                                tenzro_network::ModelRegistrationMessage,
                            >(&data)
                        {
                            // Only restore non-withdrawn, non-expired entries
                            if !reg.withdrawn {
                                let model_key =
                                    key_str.trim_start_matches("net_model:").to_string();
                                self.network_models.insert(
                                    model_key,
                                    NetworkModelEntry {
                                        registration: reg,
                                        last_seen: std::time::Instant::now(), // reset TTL
                                    },
                                );
                                net_restored += 1;
                            }
                        }
                    }
                    if net_restored > 0 {
                        info!(
                            "Restored {} network model endpoint(s) from RocksDB on startup",
                            net_restored
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to restore model services from CF_MODEL_SERVICES on startup: {}",
                        e
                    );
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP RECONCILE: auto-reload served models from disk, evict stale
        // entries whose GGUF file is gone or that no longer match the catalog.
        // This fixes the "model listed as serving but runtime says not loaded"
        // gap that occurred after restarts, because CF_MODELS/CF_MODEL_SERVICES
        // survive process death but the in-memory ModelRuntime starts empty.
        // ═══════════════════════════════════════════════════════════════════════
        let (reloaded, cleared_models, cleared_services) = self.reconcile_model_registry().await;
        if reloaded > 0 || cleared_models > 0 || cleared_services > 0 {
            info!(
                "Startup reconcile: auto-reloaded {} model(s), cleared {} served flag(s), pruned {} endpoint(s)",
                reloaded, cleared_models, cleared_services,
            );
        }

        // The connector's models are served from the operator's endpoint, so
        // they are flagged as served once the catalog is installed: a model
        // the catalog lists is refused, since the network pins weights for it
        // that this node cannot show it serves.
        if let Some(connector) = self.connector.clone() {
            connector
                .register(&self.served_models)
                .map_err(|e| NodeError::Config(format!("connector: {e}")))?;
        }

        // ═══════════════════════════════════════════════════════════════════════
        // SLA prober. Validators only: each probe's score feeds this
        // validator's per-epoch tally, which it submits as its `SlaAttest`
        // outcome. Probes are stamped by an ECVRF proof with the validator
        // Ed25519 key (RFC 9381 ECVRF over Curve25519 is byte-compatible with
        // Ed25519), derived per proof from the hardware root. A provider the
        // bonded stake freezes unavailable is slashed in consensus.
        // ═══════════════════════════════════════════════════════════════════════
        if self.config.roles.is_validator() {
            let keys = crate::keygen::NodeKeys::open(&self.config.data_dir)?;
            let vrf_prover = keys.vrf_prover()?;
            let issuer = keys.ed25519_public_key()?.to_address();
            let sla_manager = Arc::new(tenzro_model::SlaManager::new(issuer, vrf_prover));
            self.sla_manager = Some(sla_manager.clone());

            // Subscribe to `tenzro/sla` so provider responses are scored. Custom-topic transport with bincode payload
            // mirrors the agent-messaging pattern (no MessagePayload variant
            // explosion, no cross-crate type leak of tenzro-model into
            // tenzro-network). Outstanding probes are correlated by their
            // 32-byte challenge_nonce (hex-encoded for DashMap key).
            if let Some(network) = self.network.clone() {
                let outstanding = self.sla_outstanding_probes.clone();
                let tally = self.sla_tally.clone();
                let state_store = self
                    .storage
                    .clone()
                    .map(|s| s as Arc<dyn tenzro_storage::KvStore>);
                let commitments = self.challenge_manager.clone();
                tokio::spawn(async move {
                    match network.subscribe("tenzro/sla").await {
                        Ok(mut rx) => {
                            info!("SLA: subscribed to tenzro/sla");
                            while let Some(msg) = rx.recv().await {
                                let data = match msg.payload {
                                    tenzro_network::MessagePayload::Custom { data, .. } => data,
                                    _ => continue,
                                };
                                let any = match bincode::deserialize::<tenzro_model::SlaEnvelope>(
                                    &data,
                                ) {
                                    Ok(env) => match env.into_response() {
                                        Some(r) => r,
                                        // Probes are another validator's traffic on
                                        // the shared topic.
                                        None => continue,
                                    },
                                    Err(e) => {
                                        tracing::debug!(
                                            error = %e,
                                            "Ignoring undecodable payload on tenzro/sla"
                                        );
                                        continue;
                                    }
                                };
                                // Only the hardware identity registered on
                                // chain for the subject answers for it.
                                // Anything else is ignored, not scored:
                                // scoring it would let any peer answer for a
                                // provider it does not run, or answer badly
                                // first and get an honest provider marked as
                                // failing.
                                let registered = crate::sla_attest::chain_sla_subject(
                                    state_store.as_ref(),
                                    any.provider_did.as_str(),
                                )
                                .and_then(|subject| subject.identity);
                                let provider_did = any.provider_did.clone();
                                let Some(response) = any.into_verified(registered.as_ref()) else {
                                    tracing::debug!(
                                        provider = %provider_did,
                                        "Ignoring SLA response not signed by the subject's \
                                         registered hardware identity"
                                    );
                                    continue;
                                };
                                let nonce_hex = hex::encode(response.challenge_nonce);
                                let probe = match outstanding.remove(&nonce_hex) {
                                    Some((_, p)) => p,
                                    None => {
                                        tracing::debug!(
                                            provider = %response.provider_did,
                                            nonce = %nonce_hex,
                                            "SLA response references unknown probe — likely \
                                             issued by a different validator; dropping"
                                        );
                                        continue;
                                    }
                                };
                                let received_at_ms = chrono::Utc::now().timestamp_millis();
                                let result = tenzro_model::SlaManager::score_response(
                                    &probe,
                                    Some(&response),
                                    received_at_ms,
                                    registered.as_ref(),
                                );
                                // Capacity counts only from work that
                                // verifies, timed on this validator's clock
                                // from when the probe went out; it also
                                // gates availability below, so a response
                                // that signs on time but returns nothing
                                // genuine for the work asked of it — a
                                // storage claim unproven, or a burst
                                // challenge's matrix product left unanswered
                                // or faked — does not count as available
                                // either.
                                let issued_at = tally.take_issued(&probe.challenge_nonce);
                                let capacity = (!result.is_failure())
                                    .then(|| state_store.as_ref().zip(issued_at))
                                    .flatten()
                                    .and_then(|(store, issued_at)| {
                                        crate::capacity_probe::measure(
                                            &probe,
                                            &response,
                                            issued_at,
                                            received_at_ms,
                                            &tenzro_storage::StateTrie::new(store.clone()),
                                            commitments.as_deref(),
                                        )
                                    });
                                let kept = state_store.as_ref().is_some_and(|store| {
                                    crate::capacity_probe::capacity_kept(
                                        &tenzro_vm::StateAdapter::with_storage(store.clone()),
                                        &probe,
                                        &response,
                                        received_at_ms,
                                        capacity,
                                    )
                                });
                                tally.record(
                                    &probe.provider_did,
                                    probe.epoch,
                                    !result.is_failure() && kept,
                                );
                                if let Some(capacity) = capacity {
                                    tally.record_capacity(
                                        &probe.provider_did,
                                        probe.epoch,
                                        capacity,
                                    );
                                }
                                tracing::info!(
                                    provider = %probe.provider_did,
                                    epoch = probe.epoch,
                                    round = probe.round,
                                    result = result.as_reason(),
                                    "Applied SLA probe response"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to subscribe to tenzro/sla gossip topic: {}", e);
                        }
                    }
                });
            }
            // Silence is the common provider failure, so it has to be scored.
            // Without this sweep a probe that is never answered sits in the map
            // forever and never counts against the provider.
            {
                let outstanding = self.sla_outstanding_probes.clone();
                let tally = self.sla_tally.clone();
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
                    loop {
                        ticker.tick().await;
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        let expired: Vec<String> = outstanding
                            .iter()
                            .filter(|kv| now_ms > kv.value().deadline_ms)
                            .map(|kv| kv.key().clone())
                            .collect();
                        for nonce_hex in expired {
                            // `remove` is the arbiter: a response landing in the
                            // same instant either wins the entry and is scored
                            // by the subscriber, or loses it and is dropped as
                            // unknown. Either way the miss counts once.
                            let Some((_, probe)) = outstanding.remove(&nonce_hex) else {
                                continue;
                            };
                            let result = tenzro_model::SlaManager::score_response::<
                                tenzro_model::Verified,
                            >(&probe, None, now_ms, None);
                            tally.record(&probe.provider_did, probe.epoch, false);
                            tracing::info!(
                                provider = %probe.provider_did,
                                epoch = probe.epoch,
                                round = probe.round,
                                deadline_ms = probe.deadline_ms,
                                result = result.as_reason(),
                                "SLA probe expired without a response"
                            );
                        }
                    }
                });
            }

            info!("SLA prober wired: VRF-stamped probes feed this validator's SlaAttest tally");
        }

        // Responder half of the SLA exchange. Runs on every node, not just
        // providers by role, because a compute bond or a storage stake is
        // what makes a subject slashable and a validator may also serve. Without
        // this the detector would score every bonded provider as silent and
        // slash the whole set.
        // Answers are signed by the session signer this machine's hardware
        // identity key certified; a node without a hardware identity cannot
        // answer for anything, so the responder is skipped rather than
        // aborting startup.
        if let (Some(network), Some(service)) = (self.network.clone(), self.batch_service.clone()) {
            // Re-derived per probe rather than captured once: an identity
            // provisioned after startup has to start answering without a
            // restart.
            let identity_registry = self.identity_registry.clone();
            let machine_operator = machine_operator_of(self.identity_signer.as_ref());
            let configured_operator_did = self.config.operator_did.clone();
            // What a capacity probe's work runs on.
            #[cfg(feature = "inference")]
            let runtime = self.model_runtime.clone();
            let storage_runtime = self.storage_runtime.clone();
            let state_store = self
                .storage
                .clone()
                .map(|s| s as Arc<dyn tenzro_storage::KvStore>);
            tokio::spawn(async move {
                let mut rx = match network.subscribe("tenzro/sla").await {
                    Ok(rx) => rx,
                    Err(e) => {
                        warn!(error = %e, "SLA responder could not subscribe to tenzro/sla");
                        return;
                    }
                };
                while let Some(msg) = rx.recv().await {
                    let MessagePayload::Custom { data, .. } = msg.payload else {
                        continue;
                    };
                    let probe = match bincode::deserialize(&data) {
                        Ok(tenzro_model::SlaEnvelope::Probe(p)) => p,
                        Ok(tenzro_model::SlaEnvelope::Response(_)) => continue,
                        Err(_) => continue,
                    };

                    // The bond or role stake is the authority on which
                    // subject this node answers for: its owner is the wallet
                    // that funded it, so one funded by another wallet is
                    // another operator's to answer.
                    let payee = resolve_operator_payee(
                        identity_registry.as_ref(),
                        machine_operator.as_ref(),
                        configured_operator_did.as_deref(),
                    );
                    let subject = crate::sla_attest::chain_sla_subject(
                        state_store.as_ref(),
                        &probe.provider_did,
                    );
                    let (subject, payee) = match (subject, payee) {
                        (Some(subject), Some(payee)) if subject.owner == payee.as_bytes() => {
                            (subject, payee)
                        }
                        _ => continue,
                    };
                    // Validators only count answers signed by the identity
                    // registered for the subject; answering as any other
                    // identity is a miss.
                    if subject.identity.as_ref() != Some(service.identity()) {
                        warn!(
                            provider = %probe.provider_did,
                            "SLA probe for a bond this node runs, but the identity registered \
                             for it is not this machine's hardware identity"
                        );
                        continue;
                    }

                    // Verify before signing: the nonce is the issuer's VRF
                    // output, so an unverified probe is one an issuer could
                    // have ground to land an unmeetable deadline.
                    if let Err(e) = tenzro_model::SlaManager::verify_probe(&probe) {
                        warn!(
                            issuer = %hex::encode(probe.issuer.to_bytes()),
                            error = %e,
                            "Rejecting SLA probe with an invalid VRF proof"
                        );
                        continue;
                    }

                    let now_ms = chrono::Utc::now().timestamp_millis();
                    if now_ms > probe.deadline_ms {
                        debug!(
                            deadline_ms = probe.deadline_ms,
                            now_ms, "SLA probe arrived past its deadline — not answering"
                        );
                        continue;
                    }

                    #[cfg(feature = "inference")]
                    let result = crate::capacity_probe::perform(
                        runtime.as_ref(),
                        state_store.as_ref(),
                        storage_runtime.as_ref(),
                        &probe,
                    )
                    .await;
                    #[cfg(not(feature = "inference"))]
                    let result = crate::capacity_probe::perform(
                        state_store.as_ref(),
                        storage_runtime.as_ref(),
                        &probe,
                    )
                    .await;
                    // The answer waits for its batch signature, but never
                    // past the probe's deadline.
                    let remaining =
                        (probe.deadline_ms - chrono::Utc::now().timestamp_millis()).max(0) as u64;
                    let wait = crate::batch_signing::BatchSigningParams::default()
                        .receipt_wait()
                        .min(std::time::Duration::from_millis(remaining));
                    let probe_for_sign = probe.clone();
                    let service_for_sign = service.clone();
                    let signed = tokio::task::spawn_blocking(move || {
                        tenzro_model::SlaManager::start_response(
                            &probe_for_sign,
                            payee,
                            service_for_sign.as_ref(),
                            chrono::Utc::now().timestamp_millis(),
                            result,
                            tenzro_crypto::session::now_ms(),
                        )
                        .and_then(|pending| pending.finish(wait))
                    })
                    .await;
                    let response = match signed {
                        Ok(Ok(r)) => r,
                        Ok(Err(e)) => {
                            warn!(error = %e, "SLA response signing failed");
                            continue;
                        }
                        Err(e) => {
                            warn!(error = %e, "SLA response signing task failed");
                            continue;
                        }
                    };
                    let payload =
                        match bincode::serialize(&tenzro_model::SlaEnvelope::Response(response)) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!(error = %e, "SLA response serialize failed");
                                continue;
                            }
                        };
                    let out = NetworkMessage::new(MessagePayload::Custom {
                        topic: "tenzro/sla".to_string(),
                        data: payload,
                    });
                    if let Err(e) = network.broadcast("tenzro/sla", out).await {
                        warn!(error = %e, "SLA response broadcast failed");
                    } else {
                        debug!(
                            provider = %probe.provider_did,
                            epoch = probe.epoch,
                            round = probe.round,
                            "Answered SLA probe"
                        );
                    }
                }
            });
        }

        self.health_monitor.mark_healthy("ai");

        // Start the scheduled-residency loop now that the model runtime exists.
        #[cfg(feature = "inference")]
        self.spawn_residency_schedule_loop();

        Ok(())
    }

    #[cfg(feature = "inference")]
    fn spawn_residency_schedule_loop(&self) {
        let schedule = self.provider_schedule.clone();
        let served = self.served_models.clone();
        let runtime = match &self.model_runtime {
            Some(rt) => rt.clone(),
            // No runtime means this node does not serve models — nothing to schedule.
            None => return,
        };
        let models_dir = self.config.effective_models_dir();

        tokio::spawn(async move {
            // Every minute: fine enough that a window boundary is honoured promptly,
            // coarse enough to be free. The ceiling change and model reconcile are
            // idempotent, so re-running an already-applied window is a no-op.
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_window: Option<String> = None;
            // Members of the window last applied: the models this loop holds
            // resident, and the only ones it unloads.
            let mut held: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

            loop {
                ticker.tick().await;

                // Resolve each window in its OWN timezone. This used to pass a
                // UTC weekday/hour, so a `Europe/Berlin` window switched one
                // hour early in winter and two in summer — the `timezone` field
                // was stored and serialized but never actually applied.
                let action = schedule.read().action_now(chrono::Utc::now());

                // Only act when the active window changed, so we do not thrash the
                // runtime every minute. The action is still recomputed each tick so
                // a schedule edit or a wrap-midnight boundary is picked up.
                if action.active_window == last_window {
                    continue;
                }
                tracing::info!(
                    from = ?last_window,
                    to = ?action.active_window,
                    "residency schedule: window changed",
                );
                last_window = action.active_window.clone();

                // 1. Move the resident ceiling HOT. None restores the base default.
                if let Err(e) = tenzro_model::memory_budget::global()
                    .set_resident_ceiling(action.resident_ceiling_bytes)
                {
                    tracing::warn!(error = %format!("{e:?}"), "residency schedule: refused ceiling change");
                    // Do not proceed to serve models under a ceiling we could not set.
                    continue;
                }

                // 2. Reconcile the resident set: serve what the window wants, unload
                //    what it no longer does. When no window is active (want empty),
                //    nothing is force-unloaded — the base default ceiling governs and
                //    idle models age out normally; a scheduled window is additive
                //    intent, not a demand to strip the node bare.
                let want: std::collections::BTreeSet<String> =
                    action.want_models.iter().cloned().collect();

                // Unload first, so the memory a large model held is free for
                // the new window's members before they are admitted. Only the
                // previous window's members are unloaded — never a model an
                // operator loaded by hand.
                if action.active_window.is_some() {
                    for model_id in held.difference(&want) {
                        if !runtime.is_loaded(model_id) {
                            continue;
                        }
                        if let Err(e) = runtime.unload_model(model_id).await {
                            tracing::warn!(%model_id, error = %e, "residency schedule: unload failed");
                        } else {
                            served.remove(model_id);
                            tracing::info!(%model_id, "residency schedule: unloaded, not in the active window");
                        }
                    }
                    held = want.clone();
                }

                // Serve the missing ones.
                for model_id in &want {
                    if runtime.is_loaded(model_id) {
                        continue;
                    }
                    let gguf = models_dir.join(format!("{model_id}.gguf"));
                    if !gguf.exists() {
                        tracing::warn!(%model_id, "residency schedule: model not on disk, skipping");
                        continue;
                    }
                    match runtime.load_model(model_id, &gguf).await {
                        Ok(()) => {
                            served.insert(model_id.clone(), Default::default());
                            tracing::info!(%model_id, "residency schedule: served for the active window");
                        }
                        Err(e) => {
                            tracing::warn!(%model_id, error = %e, "residency schedule: load failed")
                        }
                    }
                }
            }
        });
        tracing::info!("residency schedule loop spawned (60s tick)");
    }

    async fn init_bridge(&mut self) -> Result<()> {
        info!("Initializing bridge...");
        if !self.config.bridge.enabled {
            info!("Bridge subsystem disabled");
        }

        self.health_monitor.mark_healthy("bridge");

        Ok(())
    }

    async fn init_identity(&mut self) -> Result<()> {
        info!("Initializing identity registry (TDIP)...");

        let mut registry = if let Some(storage) = &self.storage {
            info!("Identity registry initialized with persistent RocksDB storage");
            IdentityRegistry::with_storage(storage.clone() as Arc<dyn KvStore>)
        } else {
            warn!(
                "Identity registry initialized without persistent storage — data will be lost on restart"
            );
            IdentityRegistry::new()
        };
        registry =
            registry.with_evidence_verifier(Arc::new(crate::machine_admission::evidence_holds));

        // Wire the shared wallet service into the identity registry so the
        // binder-based registration path (`register_human_via_binder`) and
        // the rpc-level signing handlers operate against the same
        // `TenzroWalletService` instance. Without this binding, onboarding
        // RPCs that call `register_human_via_binder` would fail with
        // `WalletError("no wallet binder configured")`.
        if let Some(wallet_service) = self.wallet_service.clone() {
            let binder = Arc::new(tenzro_identity::WalletBinder::from_service(wallet_service));
            registry = registry.with_wallet_binder_arc(binder);
            info!(
                "Wallet binder wired: identity registrations provision permissionless wallets via the shared WalletService"
            );
        } else {
            warn!(
                "Wallet service unavailable at identity init — binder-based registration disabled"
            );
        }

        // Wire ERC-8004 auto-mirror: when a TDIP machine identity is
        // registered, submit a signed `register(string agentURI)` EVM
        // tx against the canonical IdentityRegistry proxy predeployed
        // at `addresses::IDENTITY_REGISTRY`. Returns immediately; the
        // tx is dispatched in a detached `tokio::spawn`. The off-chain
        // `did → agentId` index is populated by
        // `event_loop::process_erc8004_registered_logs` when the
        // resulting `Registered(uint256,string,address)` event lands
        // in a finalized block.
        //
        // Requires both storage (for the DID index in CF_IDENTITIES)
        // and the per-node `erc8004-system` signer (loaded or
        // silent-generated from `{data_dir}/validator_erc8004_system_key`).
        // The signer bakes the loopback JSON-RPC URL + chain_id so
        // submission goes through this node's own `tenzro_sendRawTransaction`.
        match (&self.storage, &self.erc8004_system_signer) {
            (Some(storage), Some(signer)) => {
                let mirror = Arc::new(crate::erc8004_mirror::NativeErc8004Mirror::new(
                    signer.clone(),
                    storage.clone() as Arc<dyn KvStore>,
                ));
                registry = registry.with_on_chain_agent_registry(mirror.clone());
                self.erc8004_agent_registry =
                    Some(mirror as Arc<dyn tenzro_identity::erc8004::OnChainAgentRegistry>);
                info!(
                    target: "tenzro::erc8004",
                    "ERC-8004 auto-mirror wired: TDIP machine registrations \
                     dispatch signed EVM tx to canonical IdentityRegistry proxy"
                );
            }
            (None, _) => {
                warn!(
                    target: "tenzro::erc8004",
                    "ERC-8004 auto-mirror NOT wired: storage unavailable \
                     (no DID index backing store)"
                );
            }
            (_, None) => {
                warn!(
                    target: "tenzro::erc8004",
                    "ERC-8004 auto-mirror NOT wired: erc8004-system signer \
                     unavailable (init_storage must run before init_identity)"
                );
            }
        }

        // Wire the AgentBond lookup. When set, every receipt
        // the principal-chain resolver produces carries `actor_bond` and
        // `controller_bond_aggregate` snapshots — regulators see real
        // skin-in-the-game on every settlement, payment, and lifecycle
        // event without recursive walks.
        if let Some(chain) = self.storage.clone() {
            registry = registry
                .with_bond_lookup(Arc::new(crate::lane_resolver::ChainBondLookup::new(
                    chain.clone() as Arc<dyn KvStore>,
                ))
                    as Arc<dyn tenzro_types::principal_chain::BondLookup>)
                .with_terms_lookup(Arc::new(crate::terms_gate::ChainTermsLookup::new(
                    chain as Arc<dyn KvStore>,
                )));
        } else {
            warn!(
                "chain storage unavailable at identity init: receipt bond fields and KYA Terms will be empty"
            );
        }

        // KYC tiers come from credentials on the assets the operator names.
        let kyc_assets =
            crate::lane_resolver::ChainKycResolver::parse_assets(&self.config.kyc_assets)
                .map_err(crate::error::NodeError::Config)?;
        match (&self.storage, kyc_assets.is_empty()) {
            (_, true) => {
                info!("no KYC asset is named (kyc_assets): every identity's KYC tier is unverified")
            }
            (Some(chain), false) => {
                info!(
                    assets = kyc_assets.len(),
                    "KYC tiers derived from the named assets' credentials"
                );
                registry = registry.with_kyc_resolver(Arc::new(
                    crate::lane_resolver::ChainKycResolver::new(
                        chain.clone() as Arc<dyn KvStore>,
                        kyc_assets,
                    ),
                ));
            }
            (None, false) => {
                return Err(crate::error::NodeError::Config(
                    "kyc_assets needs chain storage, which this node does not have".into(),
                ));
            }
        }

        let registry_arc = Arc::new(registry);
        self.identity_registry = Some(registry_arc.clone());

        // The model catalog: the entries of the accounts bonded as catalog
        // publishers with no upheld fault, narrowed to the publishers the operator names when it
        // names any, dropping any whose DID is revoked.
        if let Some(ledger) = self.trust_ledger.clone() {
            let registry = registry_arc.clone();
            let did_revoked: crate::catalog_sync::DidRevoked =
                Arc::new(move |did: &str| registry.is_revoked(did));
            let store = self.storage.clone();
            let admits: crate::catalog_sync::ChainAdmits =
                Arc::new(move |account: &[u8; 32], digest: &str| {
                    store.as_ref().is_some_and(|s| {
                        let chain =
                            tenzro_vm::StateAdapter::with_storage(s.clone() as Arc<dyn KvStore>);
                        tenzro_vm::native::role_bonded(
                            &chain,
                            account,
                            tenzro_types::NetworkRole::CatalogPublisher,
                        ) && !tenzro_vm::native::inference_fault::catalog_entry_faulted(
                            &chain, digest,
                        )
                    })
                });
            let sync = Arc::new(crate::catalog_sync::CatalogSync::new(
                ledger,
                self.config.catalog_publishers.clone(),
                admits,
                did_revoked,
            ));
            sync.refresh();
            sync.spawn_periodic();
            self.catalog_sync = Some(sync);
        }
        // Publish to the slot in the same breath, so a subsystem built before
        // this point can resolve against the real registry from now on.
        *self.identity_registry_slot.write() = Some(registry_arc.clone());

        self.health_monitor.mark_healthy("identity");

        Ok(())
    }

    /// Build the x402 scheme registry with EIP-3009 / Permit2 verified by the
    /// node itself, when the operator configured `payments.x402_facilitator`.
    /// Settlements broadcast through the operator's hardware-held relayer when
    /// `relayer_signer` is set, otherwise through `settlement_facilitator_url`,
    /// and every broadcast is confirmed on `evm_rpc_url` before it counts.
    /// `None` when the block is absent: the node offers no EIP-3009 or
    /// Permit2 scheme. A block that cannot run refuses the start.
    async fn build_x402_self_hosted_registry(
        &self,
        keys: Arc<dyn tenzro_payments::EnrolledKeys>,
    ) -> Result<Option<tenzro_payments::x402::scheme::SchemeRegistry>> {
        let Some(cfg) = self.config.payments.x402_facilitator.as_ref() else {
            return Ok(None);
        };
        if let Some(device) = &cfg.relayer_signer {
            return match crate::hardware_evm_signer::build(
                device,
                cfg.chain_id,
                cfg.evm_rpc_url.clone(),
            )
            .await
            {
                Ok(signer) => {
                    let signer = Arc::new(signer);
                    info!(
                        chain_id = cfg.chain_id,
                        rpc = %cfg.evm_rpc_url,
                        relayer = %signer.sender_address(),
                        "x402 EIP-3009 / Permit2 verified by this node; settled by its relayer"
                    );
                    Ok(Some(
                        tenzro_payments::x402::scheme::SchemeRegistry::with_local_relayer(
                            keys,
                            signer,
                            cfg.evm_rpc_url.clone(),
                        ),
                    ))
                }
                Err(e) => Err(NodeError::Config(format!(
                    "payments.x402_facilitator: the relayer signer for chain {} is unavailable ({e}); \
                     fix it or remove the x402_facilitator table",
                    cfg.chain_id
                ))),
            };
        }
        let Some(settlement) = cfg.settlement_facilitator_url.clone() else {
            return Err(NodeError::Config(
                "payments.x402_facilitator names neither relayer_signer nor settlement_facilitator_url"
                    .to_string(),
            ));
        };
        info!(
            chain_id = cfg.chain_id,
            rpc = %cfg.evm_rpc_url,
            settlement = %settlement,
            "x402 EIP-3009 / Permit2 verified by this node; settlements confirmed on-chain"
        );
        Ok(Some(
            tenzro_payments::x402::scheme::SchemeRegistry::with_local_facilitator(
                keys,
                cfg.evm_rpc_url.clone(),
                settlement,
            ),
        ))
    }

    async fn init_payments(&mut self) -> Result<()> {
        info!("Initializing payment gateway (MPP/x402)...");

        let chain_id = self.config.chain_id();
        let enrolled_keys: Arc<dyn tenzro_payments::EnrolledKeys> =
            Arc::new(crate::payment_rails::LedgerEnrolledKeys::new(
                self.storage.as_ref().map(|s| s.clone() as Arc<dyn KvStore>),
            ));
        let gateway = if let Some(ref storage) = self.storage {
            info!("Payment gateway initialized with persistent storage");
            TenzroPaymentGateway::with_storage(
                chain_id,
                enrolled_keys.clone(),
                storage.clone() as Arc<dyn KvStore>,
            )
        } else {
            warn!(
                "Payment gateway initialized without persistent storage — challenges will be lost on restart"
            );
            TenzroPaymentGateway::new(chain_id, enrolled_keys.clone())
        };
        let challenge_store = gateway.challenge_store();

        // Register the MPP protocol server. A node serving models bills by
        // consumption, so it issues `session` challenges (capped streaming
        // over the payer's on-chain escrow); a fixed-price node issues
        // one-shot `charge` challenges.
        let mut mpp_server = MppPaymentServer::new(enrolled_keys.clone())
            .with_default_chain("tenzro")
            .with_challenge_store(challenge_store.clone());
        if self.config.roles.serves_ai() {
            mpp_server = mpp_server.with_session_intent();
        }
        gateway.register_protocol(Arc::new(mpp_server));

        // Register the x402 protocol server. With a node signer the node signs
        // the offer on each challenge, so a buyer can check the price against
        // the node's key before paying. EIP-3009 / Permit2 verify on the
        // operator's own EVM RPC when one is configured, and through the
        // default facilitator otherwise.
        let self_hosted_registry = self
            .build_x402_self_hosted_registry(enrolled_keys.clone())
            .await?;

        let mut facilitator_ledger: Option<Arc<dyn tenzro_payments::gateway::SettlementRail>> =
            None;
        let mut facilitator_vouchers: Option<Arc<tenzro_payments::mpp::MppSessionManager>> = None;

        let mut x402_builder = X402PaymentServer::new(
            chain_id,
            vec![
                "tenzro".to_string(),
                "base".to_string(),
                "ethereum".to_string(),
            ],
            enrolled_keys.clone(),
        )
        .with_challenge_store(challenge_store.clone());

        // A node serving models bills by consumption, and a buyer cannot know
        // the token count — or the audio seconds, or the pixel-steps — before
        // the work runs. So it issues `upto` challenges: the amount is the
        // ceiling the buyer authorizes, and the metered actual settles beneath
        // it. A node serving only fixed-price resources keeps the exact-amount
        // default, because there the price *is* known up front.
        if self.config.roles.serves_ai() {
            // Beside the signed ceiling, the same challenge takes a voucher on
            // a channel the payer funded, which is how a payer with no key of
            // its own (a delegated agent) pays per call.
            x402_builder = x402_builder
                .with_scheme(tenzro_payments::x402::UPTO_SCHEME)
                .with_also_offered(tenzro_payments::x402::BATCH_SETTLEMENT_SCHEME);
            info!(
                "x402 challenges issued under the `{}` scheme — metered resources authorize a \
                 ceiling and settle the actual",
                tenzro_payments::x402::UPTO_SCHEME
            );
        }

        if let Some(registry) = &self_hosted_registry {
            x402_builder = x402_builder.with_scheme_registry(registry.clone());
        }

        match self.identity_signer.clone() {
            Some(signer) => {
                x402_builder = x402_builder.with_offer_signer(signer.clone());
                info!("x402 offers are signed by the node key");
                // Under `upto` the node's key is also its meter: every `upto`
                // challenge names it, and every charge beneath the ceiling
                // comes with a usage record it signed, which the buyer can
                // dispute on chain against the meter's bond.
                if self.config.roles.serves_ai() {
                    x402_builder = x402_builder.with_meter_signer(signer);
                    info!("x402 `upto` charges are metered by the node key");
                }
            }
            None => warn!("No node signer; x402 offers will be unsigned"),
        }

        let x402_server = Arc::new(x402_builder);
        gateway.register_protocol(x402_server.clone());
        self.x402_server = Some(x402_server);

        info!(
            "Registered payment protocols: {:?}",
            gateway.supported_protocols()
        );

        // Settlement rails. TNZO settles on the Tenzro Ledger with an
        // `PayerSettle` transaction carrying the payer's signed authorization;
        // the gateway issues a receipt only after it executed in a finalized
        // block. Escrow vouchers (MPP sessions, x402 batch-settlement) are
        // accepted against escrows read from VM state and claimed on-chain
        // by the voucher claimer.
        let gateway = if let (
            Some(consensus),
            Some(hybrid_signer),
            Some(node_addr),
            Some(storage),
        ) = (
            self.consensus.clone(),
            self.identity_signer.clone(),
            // The settle tx is sent from the validator's ledger account, the
            // address its two keys derive, not its consensus address.
            self.identity_signer
                .as_ref()
                .map(|s| Address::new(s.public_key().account_slot())),
            self.storage.clone(),
        ) {
            let submitter = Arc::new(crate::payment_rails::LedgerSubmitter::new(
                consensus,
                hybrid_signer,
                node_addr,
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                chain_id,
                self.validator_nonces.clone(),
                self.validator_tx_gossip.clone(),
            ));
            let ledger_rail = Arc::new(crate::payment_rails::LedgerRail::new(
                submitter.clone(),
                &self.config.payments.ledger_assets,
            ));
            // The claim margin is the real time a claim takes to land,
            // measured on the calendar clock escrow expiries are in.
            let claim_margin_ms = crate::calendar::wall_span_ms(
                tenzro_payments::mpp::session::DEFAULT_CLAIM_MARGIN_MS as u64,
            ) as i64;
            let sessions = Arc::new(
                tenzro_payments::mpp::MppSessionManager::with_storage(
                    Arc::new(crate::payment_rails::LedgerEscrowReader::new(
                        storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                        chain_id,
                    )),
                    storage.clone() as Arc<dyn KvStore>,
                )
                .with_claim_margin_ms(claim_margin_ms),
            );
            self.ledger_submitter = Some(submitter.clone());
            // The same account pays a machine's sponsored first registration,
            // when this node is configured to sponsor.
            if let Some(server) = &self.onboard_server {
                server.set_sink(Arc::new(crate::identity_gate::LedgerSink(
                    submitter.clone(),
                )));
            }
            let _ = self.finding_submitter.set(submitter.clone());
            // A validator drafts burn-dial changes from the supply metrics and
            // puts each to an on-chain vote from its own account.
            if let Some(burn_rate) = self.burn_rate_manager.clone()
                && self.config.roles.is_validator()
            {
                crate::policy_reflection::spawn_burn_proposer(burn_rate, submitter.clone());
                info!("Burn-dial proposer running: drafts go to on-chain governance");
            }
            crate::payment_rails::spawn_voucher_claimer(submitter, sessions.clone());
            self.payment_sessions = Some(sessions.clone());
            facilitator_ledger = Some(ledger_rail.clone());
            facilitator_vouchers = Some(sessions.clone());
            info!("Payment gateway settles TNZO on the ledger and accepts escrow vouchers");
            gateway.with_rail(ledger_rail).with_voucher_rail(sessions)
        } else {
            warn!(
                "Payment gateway has no ledger rail — consensus, signer, node address or storage \
                 not available; payments on this node are refused"
            );
            gateway
        };

        // Verifying and settling for other resource servers is a
        // facilitator's job, run outside the node; the A2A x402 extension
        // settles through the one the operator names.
        self.x402_facilitator = self
            .config
            .payments
            .facilitator_url
            .clone()
            .map(|url| Arc::new(tenzro_payments::x402::CdpFacilitatorClient::new(url)));

        // The x402 facilitator served to resource servers. It holds no funds:
        // Tenzro-scheme payments settle on the ledger rail, vouchers through
        // the gateway's own sessions (one escrow is accounted once however
        // its vouchers arrive), and every payment by a DID is held to that
        // DID's Terms.
        let mut facilitator = tenzro_payments::x402::X402Facilitator::new(
            chain_id,
            vec!["eip155:8453".to_string(), "eip155:1".to_string()],
            enrolled_keys.clone(),
        );
        if let Some(registry) = &self_hosted_registry {
            facilitator = facilitator.with_scheme_registry(registry.clone());
        }
        if let Some(rail) = facilitator_ledger {
            facilitator = facilitator.with_ledger_rail(rail);
        }
        if let Some(sessions) = facilitator_vouchers {
            facilitator = facilitator.with_voucher_rail(sessions);
        }
        if let Some(registry) = self.identity_registry.clone() {
            facilitator = facilitator.with_payer_resolver(registry.clone());
            if let Some(storage) = self.storage.clone() {
                facilitator = facilitator.with_mandate_keys(Arc::new(
                    crate::terms_gate::ChainMandateKeys::new(storage as Arc<dyn KvStore>, registry),
                ));
            }
        }
        if let Some(storage) = self.storage.clone() {
            let storage = storage as Arc<dyn KvStore>;
            facilitator = facilitator
                .with_terms_gate(Arc::new(crate::terms_gate::ChainTermsGate::new(
                    storage.clone(),
                )))
                .with_escrow_reader(Arc::new(crate::payment_rails::LedgerEscrowReader::new(
                    storage.clone(),
                    chain_id,
                )))
                .with_ledger_records(Arc::new(crate::payment_rails::LedgerPaymentRecords::new(
                    storage.clone(),
                )));
            if let Some(submitter) = self.ledger_submitter.clone() {
                facilitator = facilitator.with_plan_rail(Arc::new(
                    crate::payment_rails::LedgerPlanRail::new(submitter, storage),
                ));
            }
        }
        self.x402_facilitator_service = Some(Arc::new(facilitator));

        // A payer DID must stand behind the key that authorized the payment.
        let gateway = match self.identity_registry.clone() {
            Some(registry) => gateway.with_payer_resolver(registry),
            None => gateway,
        };

        // Receipts of settled challenges, so a retried credential gets its
        // receipt back after a restart too.
        let gateway = match self.storage.as_ref() {
            Some(storage) => {
                let store = Arc::new(crate::payment_receipt_store::NodeReceiptStore::new(
                    storage.clone() as Arc<dyn KvStore>,
                ));
                match tenzro_payments::ReceiptLedger::with_store(store) {
                    Ok(ledger) => gateway.with_receipt_ledger(Arc::new(ledger)),
                    Err(e) => {
                        warn!("payment receipt ledger hydration failed ({e}); starting empty");
                        gateway
                    }
                }
            }
            None => gateway,
        };

        // Attach the payee settlement-preference resolver. This is what lets a
        // payee who declared TNZO actually receive TNZO — and, more
        // importantly, what makes the node refuse rather than quietly credit
        // them the inbound stablecoin when no swap venue exists.
        let gateway = match self.storage.as_ref() {
            Some(store) => {
                let prefs = Arc::new(
                    crate::settlement_preferences_bridge::NodeSettlementPreferences::load(
                        store.clone() as Arc<dyn tenzro_storage::KvStore>,
                        tenzro_payments::settlement_asset::SettlementAsset::from_policy(
                            self.economic_policy.current().default_conversion,
                        ),
                    ),
                );
                self.settlement_preferences = Some(prefs.clone());
                gateway.with_settlement_preferences(prefs)
            }
            None => gateway,
        };

        self.payment_gateway = Some(Arc::new(gateway));
        self.health_monitor.mark_healthy("payments");

        Ok(())
    }

    /// Passkey custody on this node: the WebAuthn verifier for the
    /// ceremonies the node hosts (it reads keystores from consensus state)
    /// and the store of browser-mediated passkey sessions. Value and
    /// authority change only in consensus: accounts act through
    /// transactions their keystore authorizes, never through modules or
    /// operations held by one node.
    fn init_account_abstraction(&mut self) {
        // Passkeys are verified against a registrable-domain RP ID, not an
        // exact origin: a credential scoped to one hostname cannot
        // authenticate at another. This node's own RP ID serves the
        // ceremonies it hosts; a passkey a keystore links is verified for
        // the relying party the keystore records for it.
        //
        // The RP ID must not cover the site namespace:
        // every origin under it can request assertions, and those
        // hostnames serve other parties' content. See
        // `http_surface::webauthn_rp_id`, which refused to construct a
        // node configured otherwise.
        //
        // `TENZRO_WEBAUTHN_RELATED_ORIGINS` is a comma-separated list of
        // exact origins outside the RP ID that may use it for the hosted
        // ceremonies. Each one must also appear in the RP ID's
        // `/.well-known/webauthn`, or browsers will not offer the
        // credential there.
        let related_origins: Vec<String> = std::env::var("TENZRO_WEBAUTHN_RELATED_ORIGINS")
            .map(|v| {
                v.split(',')
                    .map(|o| o.trim().trim_end_matches('/').to_string())
                    .filter(|o| !o.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let webauthn_relying_party =
            tenzro_crypto::webauthn::WebAuthnRelyingParty::RegistrableDomain {
                rp_id: self.http_surface.webauthn_rp_id().to_string(),
                related_origins,
            };
        let webauthn_module_addr = {
            let mut a = [0u8; 20];
            a[18] = 0x10;
            a[19] = 0x20;
            a
        };
        let webauthn_validator = if let Some(ref storage) = self.storage {
            Arc::new(tenzro_vm::WebAuthnValidator::with_storage(
                webauthn_module_addr,
                webauthn_relying_party.clone(),
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ))
        } else {
            Arc::new(tenzro_vm::WebAuthnValidator::new(
                webauthn_module_addr,
                webauthn_relying_party.clone(),
            ))
        };
        self.webauthn_validator = Some(webauthn_validator);

        // Browser-mediated passkey sessions persist so a ceremony in flight
        // survives a restart.
        if let Some(ref storage) = self.storage {
            self.passkey_sessions = Some(Arc::new(
                crate::passkey_rpc::PasskeySessionStore::with_storage(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>
                ),
            ));
        }
        info!(webauthn_relying_party = ?webauthn_relying_party, "Passkey ceremonies initialized");
    }

    async fn init_event_loop(&mut self) -> Result<()> {
        info!("Initializing event loop...");

        // Ensure required subsystems are initialized
        let storage = self
            .storage
            .as_ref()
            .ok_or_else(|| NodeError::Internal("Storage not initialized".to_string()))?
            .clone();

        let vm_runtime = self
            .vm_runtime
            .as_ref()
            .ok_or_else(|| NodeError::Internal("VM runtime not initialized".to_string()))?
            .clone();

        // Create event loop with optional consensus and network.
        // Pass the shared chain_tip atomic so the event loop can update it on
        // every finalized block — enabling lock-free RPC reads via chain_tip_height().
        let event_loop = EventLoop::new(
            storage,
            vm_runtime,
            self.consensus.clone(),
            self.network.clone(),
            self.chain_tip.clone(),
            self.metrics.clone(),
        );

        // Every node takes certificates; a validator also takes the segments
        // its consensus orders. The iroh endpoint the channels run on is up
        // by now.
        let (ordered_rx, certificates_rx) = self.start_validator_consensus().await?;
        let event_loop = event_loop
            .with_ordered_segments(ordered_rx)
            .with_certificates(certificates_rx);
        let event_loop = match &self.event_log {
            Some(log) => event_loop.with_event_log(log.clone()),
            None => event_loop,
        };

        // Wire the weak-subjectivity checkpoint (if configured) so the
        // block-sync import path rejects any historical fork whose committed
        // state root at the anchor height diverges from the trusted value.
        let event_loop = if let Some((height, root)) = self.weak_subjectivity_anchor {
            event_loop.with_weak_subjectivity_anchor(height, tenzro_types::Hash::new(root))
        } else {
            event_loop
        };

        // Wire model services for periodic cleanup of expired network endpoints
        let event_loop = event_loop.with_model_services(self.model_services.clone());

        // Wire ModelRuntime + LoadTracker into the event loop so the heartbeat
        // can run the 1-hour idle TTL reconciler against live runtime state.
        #[cfg(feature = "inference")]
        let event_loop = if let Some(ref runtime) = self.model_runtime {
            event_loop.with_model_runtime(
                runtime.clone(),
                self.load_tracker.clone(),
                self.lifecycle.clone(),
            )
        } else {
            event_loop
        };

        // Wire model discovery state into the event loop for P2P model announcements
        let event_loop = event_loop.with_model_discovery(
            self.network_models.clone(),
            self.served_models.clone(),
            self.provider_pricing.clone(),
            self.provider_schedule.clone(),
        );

        // The advertisement policy. Shared rather than copied, so an operator
        // changing it at runtime takes effect on the next heartbeat.
        let event_loop = event_loop.with_node_visibility(self.node_visibility.clone());

        // Wire network_providers map for gossip-discovered provider merging
        let mut event_loop = event_loop.with_provider_discovery(self.network_providers.clone());

        // Bridge verified provider announcements into the ProviderManager so
        // the InferenceRouter (which dispatches chat traffic) sees them with
        // their advertised HardwareCapabilities. Absent on nodes with no
        // router (light clients that never route inference).
        if let Some(ref pm) = self.provider_manager {
            event_loop = event_loop
                .with_provider_manager(pm.clone(), self.local_validator_address().copied());
        }

        // Gossip announcements are signed as this machine's DID by the session
        // signer its hardware identity key certified; receivers verify them
        // against the key registered for the DID. A machine without a hardware
        // identity does not announce.
        match self.announce_identity() {
            Some(identity) => event_loop = event_loop.with_announce_identity(identity),
            None => {
                warn!("No hardware identity: this node will not sign or broadcast announcements")
            }
        }

        // Wire provider announcement broadcast context. Only providers (model
        // / TEE / storage / validator) self-announce; light clients stay
        // anonymous on this topic. Hardware is detected once at startup; the
        // served-models snapshot is re-read from the live `Arc<DashMap>` at
        // each tick.
        if self.config.roles.is_provider()
            || self.config.roles.is_validator()
            || self.config.roles.serves_edge()
        {
            // The probe shells out to vendor tools (nvidia-smi / rocm-smi /
            // sysctl) synchronously — keep it off the async executor.
            let mut hardware =
                tokio::task::spawn_blocking(tenzro_types::HardwareCapabilities::detect)
                    .await
                    .unwrap_or_default();
            // `config.tee_enabled` is the operator's intent; presence of an
            // initialized `tee_provider` means the runtime probe at startup
            // succeeded. Both must hold before we advertise TEE availability
            // to peers.
            hardware.tee_available = self.config.tee_enabled && self.tee_provider.is_some();

            let provider_address = self
                .operator_payee()
                .map(|addr| format!("0x{}", hex::encode(addr.as_bytes())))
                .unwrap_or_default();

            // A multi-role node advertises every capability it serves. The
            // `provider_type` string is a coarse routing hint; we pick the
            // most specific service role the node fills, falling back to
            // "general" for a validator-only node.
            let mut capabilities: Vec<String> = Vec::new();
            if self.config.roles.serves_ai() {
                capabilities.push("inference".to_string());
            }
            if self.config.roles.serves_tee() {
                capabilities.push("tee-attestation".to_string());
                capabilities.push("confidential-compute".to_string());
            }
            if self.config.roles.serves_compute() {
                // The renter brings their own work, so this says only that the
                // accelerator is for hire — not what runs on it.
                capabilities.push("accelerator-rental".to_string());
            }
            if self.config.roles.serves_storage() {
                capabilities.push("storage".to_string());
            }
            if self.config.roles.is_validator() {
                capabilities.push("consensus".to_string());
            }
            if self.config.roles.serves_edge() {
                // Serving nodes read this to discover which peers can terminate
                // public TLS and front them over the `tenzro/http` ALPN.
                capabilities.push("edge-ingress".to_string());
            }
            // Nodes that serve delegated agents announce their machine and
            // operator identities so controllers can assign them.
            let agent_serving = if self.config.serves_agents() {
                crate::identity_bootstrap::machine_did().zip(self.operator_did())
            } else {
                None
            };
            if agent_serving.is_some() {
                capabilities.push(crate::agent_delegation::AGENT_SERVING_CAPABILITY.to_string());
            }
            let provider_type: &str = if self.config.roles.serves_ai() {
                // Not "llm": this node may serve multimodal, image, video or
                // audio models, and usually serves several classes at once.
                tenzro_network::message::PROVIDER_TYPE_AI
            } else if self.config.roles.serves_tee() {
                "tee"
            } else if self.config.roles.serves_compute() {
                "compute"
            } else if self.config.roles.serves_storage() {
                "storage"
            } else if self.config.roles.serves_edge() {
                "edge"
            } else {
                "general"
            };

            // Cluster-serving profile: only an AI-serving node that is a
            // member of a verified cluster announces it, built fresh on each
            // announcement from the membership lists it holds.
            let cluster_identity = self
                .config
                .roles
                .serves_ai()
                .then(|| self.cluster_identity.clone());

            // Advertised serving capacity: read the node's own registered
            // provider entry if it has one, else fall back to the default
            // envelope. Only the numeric throughput/concurrency subset is
            // carried on gossip.
            let mut capacity = self
                .provider_manager
                .as_ref()
                .and_then(|pm| {
                    Address::from_hex(
                        provider_address
                            .strip_prefix("0x")
                            .unwrap_or(&provider_address),
                    )
                    .ok()
                    .and_then(|addr| pm.get_provider(&addr).ok())
                })
                .map(|p| p.capacity.advertised())
                .unwrap_or_else(|| tenzro_types::ProviderCapacity::default().advertised());
            // The built-in llama.cpp runtime reads raw logits in-process, so
            // any AI-serving node can produce TOPLOC commitments without
            // configuration.
            capacity.verifiable_inference = self.config.roles.serves_ai();
            // Operator-declared jurisdiction rides the announcement so remote
            // routers can hard-filter on it. Absent claim = this node never
            // satisfies a jurisdiction pin (fail-closed).
            capacity.jurisdiction = self.jurisdiction_claim.clone();
            capacity.verification = crate::verifiable_inference::offered_levels(self);
            // Rides the announcement so a buyer can quote a standby
            // reservation before any session names this node (see
            // `AdvertisedCapacity::standby_fee_per_hour`).
            capacity.standby_fee_per_hour = self.config.standby.fee_per_hour;
            #[cfg(feature = "inference")]
            if let Some(rt) = &self.model_runtime {
                capacity.standby_models = rt
                    .standby_models()
                    .into_iter()
                    .map(|m| m.model_id)
                    .collect();
            }

            let ctx = crate::event_loop::ProviderAnnouncementContext {
                hardware,
                region: self
                    .config
                    .region
                    .as_deref()
                    .and_then(|r| tenzro_types::provider_listing::coarse_region(r).ok()),
                provider_address,
                provider_type: provider_type.to_string(),
                capabilities,
                ttl_secs: 120,
                cluster_identity,
                capacity,
                agent_serving,
            };
            event_loop = event_loop.with_provider_announcement(ctx);
        }

        // A storage-serving node opts into HRW shard self-selection: inbound
        // shard-replication requests are ranked against its local membership
        // view and the top-`R` shards for this node are pinned locally. The
        // mDNS-discovered local-peer set lets self-selection fill replicas
        // from the caller's own LAN segment before spilling onto the wider
        // network — the local-machine → LAN-cluster → network progression the
        // model-serving tier uses, applied to shard placement.
        if self.config.roles.serves_storage() {
            event_loop = event_loop.with_storage_replicas(DEFAULT_STORAGE_REPLICAS);
            event_loop = event_loop.with_disk_guard(self.disk_guard.clone());
        }

        // Wire the snapshot ABCI store so the finality hook produces a
        // state-sync snapshot at the configured interval on producer nodes.
        let event_loop = if let Some(ref s) = self.snapshot_store {
            event_loop.with_snapshot_store(s.clone())
        } else {
            event_loop
        };

        // Wire kill-switch dependencies (post-execute scan side-effects:
        // lifecycle FSM, stake freeze/slash, cascade traversal, receipt
        // store). Each is best-effort: if a dependency is missing, the
        // matching side-effect is logged at debug and skipped.
        let event_loop = if let Some(ref registry) = self.identity_registry {
            event_loop.with_identity_registry(registry.clone())
        } else {
            event_loop
        };
        let event_loop = match self.auth_engine {
            Some(ref engine) => event_loop.with_auth_engine(engine.clone()),
            None => event_loop,
        };

        let event_loop = match self.token_registry {
            Some(ref registry) => event_loop.with_token_registry(registry.clone()),
            None => event_loop,
        };

        // Wire permissionless ValidatorRegistry. The event loop's
        // post-block scan mirrors VM-emitted ValidatorRegister /
        // ValidatorExit / ValidatorMetadataUpdate logs into this
        // registry, and the epoch boundary hook drives the resulting
        // EpochTransitionPlan into the consensus EpochManager queues.
        let event_loop = if let Some(ref vr) = self.validator_registry {
            event_loop.with_validator_registry(vr.clone())
        } else {
            event_loop
        };

        // Wire the adaptive-burn manager + canonical TNZO token so the
        // event loop's per-epoch supply observer feeds
        // `BurnRateConfigManager::record_metrics` at every epoch boundary.
        // Without this, `record_metrics` is dead code and the burn-rate
        // recommendation engine scores against a default snapshot —
        // governance would never see real network signal.
        let event_loop = if let Some(burn_rate) = self.burn_rate_manager.as_ref() {
            event_loop.with_burn_rate_manager(burn_rate.clone())
        } else {
            event_loop
        };

        // Wire the iroh resolver so the blob heartbeat can announce locally
        // held blobs on tenzro/blobs and inbound peer announcements populate
        // the resolver's blob-provider hint cache.
        let event_loop = if let Some(resolver) = self.iroh_resolver.clone() {
            event_loop.with_iroh_resolver(resolver)
        } else {
            event_loop
        };
        let event_loop = event_loop.with_sync_peers(
            self.state_sync_peers
                .iter()
                .map(|p| *p.as_bytes())
                .collect(),
        );
        let event_loop = event_loop
            .with_block_sync(self.config.block_sync.clone())
            .with_held_transactions(self.config.held_transactions.clone())
            .with_gpu_revocation(self.config.gpu_revocation.clone());

        // Recorded checkpoint equivocations: consensus state slashes the
        // bond; every node drops the validator from the next committee and
        // jails it in the registry at the same height.
        let event_loop = if let Some(consensus) = self.consensus.clone() {
            let mut jailer = EquivocationJailer::new(consensus.epoch_manager().clone());
            if let Some(registry) = self.validator_registry.clone() {
                jailer = jailer.with_validator_registry(registry);
            }
            event_loop.with_equivocation_jailer(Arc::new(jailer))
        } else {
            event_loop
        };

        let event_loop = if let Some(policy) = self.policy_applier.clone() {
            event_loop.with_policy_applier(policy)
        } else {
            event_loop
        };
        let event_loop = event_loop.with_sla_tally(self.sla_tally.clone());

        // Wire the fee processor so per-block gas settlement is recorded.
        let event_loop = if let Some(processor) = self.fee_processor.clone() {
            event_loop.with_fee_processor(processor)
        } else {
            event_loop
        };

        // Store the event sender for RPC to submit transactions
        self.event_loop_tx = Some(event_loop.event_sender());

        // Log the startup chain state using the event loop's chain-tip getters.
        // These calls produce valuable observability on every node restart and ensure
        // the getters are exercised at runtime rather than just sitting unused.
        {
            let initial_height = event_loop.current_height();
            // A node whose binary does not support the chain's protocol
            // version stops here, before it executes anything.
            if let Some(policy) = &self.policy_applier {
                policy
                    .startup_check(initial_height.0.saturating_add(1))
                    .map_err(|m| NodeError::Other(m.to_string()))?;
            }
            let initial_hash = event_loop.last_block_hash();
            info!(
                height = initial_height.0,
                last_hash = %initial_hash,
                "Event loop initialized, resuming from stored chain tip"
            );
        }

        // Wire block sync: subscribe to the gossip blocks topic and forward to event loop.
        // This follows the same pattern as the agent gossip bridge (init_ai_infrastructure).
        // All nodes subscribe; the event loop's height check skips blocks it
        // already has.
        if let Some(ref network) = self.network {
            let event_tx = event_loop.event_sender();
            let net_in = network.clone();
            tokio::spawn(async move {
                // Validated subscription: gossip passes a block on to other
                // nodes only after the event loop has checked its certificate.
                match net_in.subscribe_validated("tenzro/blocks").await {
                    Ok(mut rx) => {
                        tracing::info!("Block sync: subscribed to tenzro/blocks");
                        while let Some(held) = rx.recv().await {
                            let tenzro_network::ValidatedMessage { message, ticket } = held;
                            match message.payload {
                                tenzro_network::MessagePayload::Block(block) => {
                                    let height = block.height();
                                    tracing::debug!(height = %height, "Received block from gossip");
                                    let verdict = crate::event_loop::GossipVerdict::new(ticket);
                                    if let Err(e) =
                                        event_tx.send(NodeEvent::NetworkBlock(block, verdict)).await
                                    {
                                        tracing::error!(
                                            "Failed to forward network block to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                                // Anything else on the block topic is not a
                                // block and is not forwarded.
                                _ => ticket.reject(),
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to blocks gossip topic: {}", e);
                    }
                }
            });
            info!("Block sync wired to gossip (tenzro/blocks)");

            // Release notices: gossip, the downloads host and the cache.
            let notice_net = network.clone();
            let notice_dir = self.config().data_dir.clone();
            tokio::spawn(async move { crate::update_notice::start(notice_net, notice_dir).await });

            // Wire transaction gossip: subscribe to tenzro/transactions and
            // forward each inbound `MessagePayload::Transaction(tx)` into
            // `NodeEvent::NewTransaction`, which runs signature verification
            // and admits the tx to the local consensus mempool.
            //
            // Without this subscriber, RPC nodes publish transactions to the
            // gossip topic but no validator's mempool ever receives them,
            // so every block proposer emits an empty block. The chain looks
            // healthy — `eth_blockNumber`
            // advances normally but every finalized block has `tx_count=0`
            // and no transaction (transfer, contract call) ever
            // settles despite the JSON-RPC layer reporting `submitted:queued`.
            //
            // `Ingress::admit` does not re-broadcast on receive: the
            // gossip layer passes accepted messages on itself, and a fresh
            // envelope per relay would defeat its content-hash dedup.
            {
                let event_tx = event_loop.event_sender();
                let net_in = network.clone();
                tokio::spawn(async move {
                    match net_in.subscribe("tenzro/transactions").await {
                        Ok(mut rx) => {
                            tracing::info!("Transaction sync: subscribed to tenzro/transactions");
                            while let Some(msg) = rx.recv().await {
                                if let tenzro_network::MessagePayload::Transaction(mut tx) =
                                    msg.payload
                                {
                                    let tx_hash = tx.hash();
                                    tracing::debug!(
                                        hash = %tx_hash,
                                        "Received transaction from gossip"
                                    );
                                    if let Err(e) =
                                        event_tx.send(NodeEvent::NewTransaction(tx)).await
                                    {
                                        tracing::error!(
                                            error = %e,
                                            "Failed to forward gossiped transaction to event loop"
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to subscribe to transactions gossip topic"
                            );
                        }
                    }
                });
                info!("Transaction sync wired to gossip (tenzro/transactions)");
            }

            // Wire status gossip: subscribe to tenzro/status and feed
            // peer heights into the PeerStatusTracker so eth_syncing /
            // tenzro_syncing can report a real network-tip estimate.
            //
            // Outbound: every 10s broadcast our own StatusMessage with the
            // current chain tip. The PeerStatusTracker drops entries from
            // peers whose chain_id doesn't match (silent), so cross-chain
            // noise can't poison the estimate.
            {
                let net_status = network.clone();
                let peer_status_tracker = self.peer_status.clone();
                let local_chain_id = self.config.chain_id();
                tokio::spawn(async move {
                    let mut rx = match net_status.subscribe("tenzro/status").await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to subscribe to status gossip topic"
                            );
                            return;
                        }
                    };
                    tracing::info!("Status sync: subscribed to tenzro/status");
                    while let Some(msg) = rx.recv().await {
                        if let tenzro_network::MessagePayload::Status(status) = msg.payload {
                            // Drop messages from a different chain — defense
                            // against cross-chain gossip leak. Tracker also
                            // re-checks this, but doing it here keeps the log
                            // signal cleaner.
                            if status.chain_id != local_chain_id {
                                continue;
                            }
                            let peer_id =
                                match status.endpoint_id.parse::<tenzro_iroh::EndpointId>() {
                                    Ok(p) => p,
                                    Err(e) => {
                                        tracing::debug!(
                                            peer = %status.endpoint_id,
                                            error = %e,
                                            "Dropping StatusMessage with malformed endpoint_id"
                                        );
                                        continue;
                                    }
                                };
                            tracing::trace!(
                                peer = %peer_id,
                                height = status.height,
                                tee_capable = status.tee_capable,
                                tee_vendor = ?status.tee_vendor,
                                "Recorded peer status"
                            );
                            peer_status_tracker.record(
                                peer_id,
                                status.height,
                                status.chain_id,
                                status.tee_capable,
                                status.tee_vendor,
                            );
                        }
                    }
                });
                info!("Status sync wired to gossip (tenzro/status)");
            }

            // Outbound status broadcast tick: every 10s, broadcast our own
            // best block + height so peers can track our chain tip.
            {
                let net_out = network.clone();
                let chain_tip_atomic = self.chain_tip.clone();
                let peer_status_tracker = self.peer_status.clone();
                let local_chain_id = self.config.chain_id();
                // The status plane carries a chain-scoped protocol version
                // (`tenzro/<chain_id>/<version>`).
                let protocol_version =
                    format!("tenzro/{}/{}", local_chain_id, env!("CARGO_PKG_VERSION"));
                // TEE capability is fixed at startup (no hot-attach
                // path), so we snapshot it once here and embed it in
                // every status broadcast. Peers consult these fields to
                // discover routing targets for confidential-compute /
                // custodial workloads.
                let local_tee_capable = self.tee_provider.is_some();
                let local_tee_vendor = self.tee_provider.as_ref().map(|p| p.vendor());
                // This node's iroh endpoint id, stable for the lifetime of
                // the process.
                let local_endpoint_id = self.iroh_resolver().map(|r| r.endpoint_id().to_string());
                tokio::spawn(async move {
                    let Some(local_endpoint_id) = local_endpoint_id else {
                        tracing::warn!(
                            "Status broadcast: no iroh endpoint bound; not broadcasting"
                        );
                        return;
                    };
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    // Skip the immediate fire so we don't broadcast height=0
                    // before the chain tip has been hydrated from storage.
                    tick.tick().await;
                    loop {
                        tick.tick().await;
                        // Periodically prune stale entries from the tracker
                        // so the map stays bounded as peers drop off.
                        peer_status_tracker.prune_stale();

                        let height = chain_tip_atomic.load(std::sync::atomic::Ordering::Acquire);
                        let status = tenzro_network::StatusMessage {
                            endpoint_id: local_endpoint_id.clone(),
                            best_block: tenzro_types::Hash::zero(),
                            height,
                            chain_id: local_chain_id,
                            protocol_version: protocol_version.clone(),
                            tee_capable: local_tee_capable,
                            tee_vendor: local_tee_vendor,
                        };
                        let msg = tenzro_network::NetworkMessage::new(
                            tenzro_network::MessagePayload::Status(status),
                        );
                        if let Err(e) = net_out.broadcast("tenzro/status", msg).await {
                            tracing::debug!(
                                error = %e,
                                "Status broadcast failed (likely no gossip neighbours yet)"
                            );
                        }
                    }
                });
                info!("Status broadcast wired (every 10s on tenzro/status)");
            }

            // Checkpoint certificates published by validators. A follower
            // imports every block under one; the event loop verifies it
            // against the committee of its epoch before acting on it.
            if self.consensus.is_some() {
                let net_certs = network.clone();
                let events = event_loop.event_sender();
                let compact_follow = self.consensus.clone();
                tokio::spawn(async move {
                    let mut rx = match net_certs.subscribe("tenzro/certificates").await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to subscribe to tenzro/certificates");
                            return;
                        }
                    };
                    while let Some(msg) = rx.recv().await {
                        let bytes = match msg.payload {
                            tenzro_network::MessagePayload::Certificate(bytes) => bytes,
                            tenzro_network::MessagePayload::CompactCertificate(bytes) => {
                                // Checked off the runtime: verifying the proof is
                                // tens of milliseconds of work.
                                let Some(c) = compact_follow.clone() else {
                                    continue;
                                };
                                tokio::task::spawn_blocking(move || {
                                    match bincode::deserialize::<
                                        tenzro_consensus::compact::CompactCertificate,
                                    >(&bytes)
                                    {
                                        Ok(cc) => {
                                            if let Err(e) = c.accept_compact_certificate(&cc) {
                                                tracing::debug!(error = %e, "compact certificate from the network refused");
                                            }
                                        }
                                        Err(e) => {
                                            tracing::debug!(error = %e, "malformed compact certificate from the network")
                                        }
                                    }
                                });
                                continue;
                            }
                            _ => continue,
                        };
                        match bincode::deserialize::<tenzro_consensus::PublishedCertificate>(&bytes)
                        {
                            Ok(cert) => {
                                if events
                                    .send(NodeEvent::NetworkCertificate(Box::new(cert)))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "malformed certificate from the network")
                            }
                        }
                    }
                });
                info!("Checkpoint certificates wired to gossip (tenzro/certificates)");

                // Validators' signed endpoint announcements, with their
                // endpoints sealed to committee members: where this node, as a
                // member, dials the others and fetches blocks from them.
                let net_endpoints = network.clone();
                let book = self.consensus.clone();
                let admission_store = self.storage().cloned();
                tokio::spawn(async move {
                    let gate = crate::validator_admission::PeerGate::default();
                    let mut rx = match net_endpoints.subscribe("tenzro/validators").await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to subscribe to tenzro/validators");
                            return;
                        }
                    };
                    while let Some(msg) = rx.recv().await {
                        let tenzro_network::MessagePayload::ValidatorEndpoint(bytes) = msg.payload
                        else {
                            continue;
                        };
                        match bincode::deserialize::<
                            tenzro_consensus::announce::PublishedAnnouncement,
                        >(&bytes)
                        {
                            Ok(a) => {
                                // Closed validator admission: a key that is
                                // not an admitted account's gets no further.
                                let chain = admission_store.as_ref().map(|s| {
                                    tenzro_vm::StateAdapter::with_storage(
                                        s.clone() as Arc<dyn tenzro_storage::KvStore>
                                    )
                                });
                                if !gate.allows(
                                    chain.as_ref().map(|c| c as &dyn tenzro_vm::traits::VmState),
                                    &a.announcement.validator,
                                ) {
                                    continue;
                                }
                                // An endpoint a validator disclosed to this
                                // node, as a committee member, becomes a
                                // gossip peer of it.
                                if let Some(endpoint) =
                                    book.as_ref().and_then(|c| c.offer_announcement(a))
                                    && let Ok(id) = tenzro_iroh::EndpointId::from_bytes(&endpoint)
                                {
                                    net_endpoints.add_gossip_peers(&[id]).await;
                                }
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "malformed endpoint announcement from the network")
                            }
                        }
                    }
                });
                info!("Validator endpoint announcements wired to gossip (tenzro/validators)");
            }

            // Wire model discovery: subscribe to the gossip models topic and forward to event loop.
            // This enables decentralized P2P model discovery — no centralized registry required.
            let event_tx_models = event_loop.event_sender();
            let net_models = network.clone();
            tokio::spawn(async move {
                match net_models.subscribe("tenzro/models").await {
                    Ok(mut rx) => {
                        tracing::info!("Model discovery: subscribed to tenzro/models");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::ModelRegistration(reg) =
                                msg.payload
                                && let Err(e) = event_tx_models
                                    .send(NodeEvent::ModelAnnouncement(reg))
                                    .await
                            {
                                tracing::error!(
                                    "Failed to forward model announcement to event loop: {}",
                                    e
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to models gossip topic: {}", e);
                    }
                }
            });
            info!("Model discovery wired to gossip (tenzro/models)");

            // Wire provider discovery: subscribe to the gossip providers topic and forward to event loop.
            // This enables decentralized P2P provider discovery — every node learns about every provider
            // on the network via gossip heartbeats, with no central registry required.
            let event_tx_providers = event_loop.event_sender();
            let net_providers = network.clone();
            tokio::spawn(async move {
                match net_providers.subscribe("tenzro/providers").await {
                    Ok(mut rx) => {
                        tracing::info!("Provider discovery: subscribed to tenzro/providers");
                        while let Some(msg) = rx.recv().await {
                            let event = match msg.payload {
                                tenzro_network::MessagePayload::ProviderAnnouncement(ann) => {
                                    NodeEvent::ProviderAnnouncement(ann)
                                }
                                tenzro_network::MessagePayload::ProviderHeartbeat(hb) => {
                                    NodeEvent::ProviderHeartbeat(hb)
                                }
                                _ => continue,
                            };
                            if let Err(e) = event_tx_providers.send(event).await {
                                tracing::error!(
                                    "Failed to forward provider announcement to event loop: {}",
                                    e
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to providers gossip topic: {}", e);
                    }
                }
            });
            info!("Provider discovery wired to gossip (tenzro/providers)");

            // Wire blob availability discovery: subscribe to the gossip blobs topic
            // and forward to event loop. Announcements feed the iroh resolver's
            // blob-provider hint cache so hint-less `tenzro://blob/...` fetches
            // can dial announced holders.
            let event_tx_blobs = event_loop.event_sender();
            let net_blobs = network.clone();
            tokio::spawn(async move {
                match net_blobs.subscribe("tenzro/blobs").await {
                    Ok(mut rx) => {
                        tracing::info!("Blob discovery: subscribed to tenzro/blobs");
                        while let Some(msg) = rx.recv().await {
                            match msg.payload {
                                tenzro_network::MessagePayload::BlobAnnouncement(ann) => {
                                    if let Err(e) =
                                        event_tx_blobs.send(NodeEvent::BlobAnnouncement(ann)).await
                                    {
                                        tracing::error!(
                                            "Failed to forward blob announcement to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                                tenzro_network::MessagePayload::ShardReplication(req) => {
                                    if let Err(e) =
                                        event_tx_blobs.send(NodeEvent::ShardReplication(req)).await
                                    {
                                        tracing::error!(
                                            "Failed to forward shard replication to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to blobs gossip topic: {}", e);
                    }
                }
            });
            info!("Blob discovery wired to gossip (tenzro/blobs)");

            // Trust records ride `tenzro/trust`; each is re-verified on arrival.
            if let Some(ledger) = self.trust_ledger.clone() {
                crate::trust_hooks::spawn_subscriber(
                    ledger,
                    self.catalog_sync.clone(),
                    self.finding_sink(),
                    network.clone(),
                );
            }
        }

        // Spawn the event loop in the background
        tokio::spawn(async move {
            if let Err(e) = event_loop.run().await {
                tracing::error!(error = %e, "Event loop error");
            }
        });

        self.health_monitor.mark_healthy("event_loop");
        info!("Event loop started");

        Ok(())
    }

    /// Returns the identity registry (TDIP) if initialized
    pub fn identity_registry(&self) -> Option<&Arc<IdentityRegistry>> {
        self.identity_registry.as_ref()
    }
    /// Vendor attestation roots this node pins, decoded to DER.
    ///
    /// An entry that is not valid base64 is dropped rather than failing the
    /// call: one malformed root in a list must not make every other root
    /// unusable, and a dropped root simply means fewer chains verify — which
    /// fails closed.
    pub fn webauthn_trusted_roots(&self) -> Vec<Vec<u8>> {
        use base64::Engine;
        self.config
            .webauthn_trusted_roots
            .iter()
            .filter_map(|b| {
                base64::engine::general_purpose::STANDARD
                    .decode(b.trim())
                    .ok()
            })
            .collect()
    }

    /// The live economic policy — the rates every settlement on this node
    /// applies.
    pub fn economic_policy(&self) -> tenzro_types::economics::EconomicPolicy {
        self.economic_policy.current()
    }

    /// The RPC provider that validates on this node's behalf, and is therefore
    /// owed a share of what this node earns.
    ///
    /// Only consulted in [`tenzro_types::economics::NodeEconomicMode::PublicDelegated`]
    /// — a node that validates for itself owes no such leg. Returns `None` when
    /// the operator has not named one, which is refused at settlement rather
    /// than defaulted: paying that share to the treasury because nobody was
    /// configured would pay the wrong party without saying so.
    pub fn rpc_provider_payee(&self) -> Option<Address> {
        let configured = self.config.economics.rpc_provider_payee.as_deref()?;
        match Address::from_hex(configured) {
            Ok(addr) => Some(addr),
            Err(e) => {
                // Do not fail silently here. Returning `None` for an
                // unparseable address makes settlement refuse with "name them
                // in `[economics] rpc_provider_payee`" — to an operator who
                // did name one, and is now being told to do the thing they
                // already did. A mis-cased EIP-55 checksum is enough to
                // trigger it, so the log line has to say which value failed
                // and why.
                tracing::error!(
                    configured,
                    error = %e,
                    "[economics] rpc_provider_payee is not a valid address, so this node                      cannot name the RPC provider it owes a share to and settlement will                      refuse. Note that a 20-byte address is EIP-55 checksummed: mixed-case                      hex must carry the correct casing, or be all-lowercase."
                );
                None
            }
        }
    }

    /// The account a call to `model` settles to: the wallet of the operator
    /// this node hosts `model` for, else this node's payee. An error when
    /// `model` is hosted for an operator whose identity does not resolve: such
    /// a call is never settled to this node instead.
    pub fn payee_for_model(&self, model: &str) -> std::result::Result<Option<Address>, String> {
        match crate::hosted_operators::payee_for(
            self.identity_registry.as_deref(),
            &self.config.hosted_operators,
            model,
        ) {
            Some(resolved) => resolved.map(|(_, wallet)| Some(wallet)),
            None => Ok(self.operator_payee()),
        }
    }

    /// The fee leg this node declares on the calls it settles for a payer
    /// (see [`crate::config::PlatformFeeConfig`]).
    pub fn declared_platform_fee(&self) -> Option<tenzro_types::payment_authorization::AppMargin> {
        self.config.platform_fee.as_ref().and_then(|f| f.leg().ok())
    }

    /// The wallet this node is paid at.
    ///
    /// Both the advertised payee (model / provider gossip announcements) and
    /// the settled payee (inference, hosting, rental, storage) resolve through
    /// here, so the address a consumer sees in an offer is the address the
    /// transfer lands at. Resolution is total-ordered rather than
    /// registry-iteration-ordered, which means it is stable across restarts and
    /// identical for every caller on the node:
    ///
    /// 1. the identity whose wallet is this machine's hardware wallet account
    ///    (the account slot of its TPM or Secure Enclave P-256 key) — an
    ///    exact key ↔ wallet binding;
    /// 2. the lowest-DID active human or institution — the owner classes;
    /// 3. the lowest-DID active autonomous agent (no controller) — a node run by
    ///    an agent on its own behalf earns into that agent's wallet;
    /// 4. the lowest-DID active delegated agent — earns into the agent's own
    ///    wallet, with the controller retaining oversight through its
    ///    delegation scope;
    /// 5. the machine's hardware wallet account with no registry entry at
    ///    all, so a node that never provisioned an identity still has a
    ///    self-custodial payee, and its role bonds are staked from the account
    ///    its own hardware key signs for.
    pub fn operator_payee(&self) -> Option<Address> {
        resolve_operator_payee(
            self.identity_registry.as_ref(),
            machine_operator_of(self.identity_signer.as_ref()).as_ref(),
            self.config.operator_did.as_deref(),
        )
    }

    /// The identity registry as of now, via the slot rather than the field.
    ///
    /// Equivalent to `identity_registry` once `init_identity()` has run, and
    /// unlike the field it can be read by something constructed earlier.
    pub(crate) fn identity_registry_slot(
        &self,
    ) -> Arc<parking_lot::RwLock<Option<Arc<IdentityRegistry>>>> {
        self.identity_registry_slot.clone()
    }

    /// The DID that owns [`TenzroNode::operator_payee`]. `None` when this node
    /// has no provisioned identity and is falling back to its machine account, so
    /// a caller that needs an attributable DID (transparency-log recorder,
    /// provider announcement) can tell the difference instead of recording an
    /// empty string against a real wallet.
    pub fn operator_did(&self) -> Option<String> {
        resolve_operator_identity(
            self.identity_registry.as_ref(),
            machine_operator_of(self.identity_signer.as_ref()).as_ref(),
            self.config.operator_did.as_deref(),
        )
        .map(|(did, _)| did)
    }

    /// The machine's hardware identity key, if it has one.
    pub fn identity_signer(&self) -> Option<&Arc<dyn tenzro_crypto::composite::HybridSigner>> {
        self.identity_signer.as_ref()
    }

    /// The hardware-held validator consensus key, when this machine holds
    /// one.
    pub fn validator_signer(&self) -> Option<&Arc<dyn tenzro_consensus::ValidatorSigner>> {
        self.validator_signer.as_ref()
    }

    /// Open hash-locked delivery offers made at this node's HTTP-402 gates.
    pub fn sealed_offers(&self) -> &Arc<crate::sealed_delivery::SealedOffers> {
        &self.sealed_offers
    }

    /// Returns the per-node `erc8004-system` secp256k1 signer used by
    /// the two internal writers (TDIP mirror + Stripe SPT reputation
    /// dispatcher) to submit signed EVM tx against the canonical
    /// ERC-8004 proxies. Returns `None` when storage / signer init
    /// failed at `init_storage()` time — both internal write paths
    /// log-and-drop when this is absent.
    ///
    /// User-facing RPC writes (`tenzro_registerAgent`,
    /// `submitFeedback`, `requestValidation`) do **not** consume this
    /// signer; they are caller-signed via `tenzro_sendRawTransaction`.
    pub fn erc8004_system_signer(
        &self,
    ) -> Option<&Arc<tenzro_bridge::evm_signer::EvmTransactionSigner>> {
        self.erc8004_system_signer.as_ref()
    }

    /// Returns the [`OnChainAgentRegistry`] mirror that resolves TDIP
    /// machine DIDs to their sequential `uint256 agentId` allocated by
    /// the canonical on-chain `IdentityRegistry` proxy
    /// (`addresses::IDENTITY_REGISTRY`). Settlement-outcome
    /// dispatchers consult this before writing reputation rows so the
    /// `submitFeedback` subject word matches the `agentId` assigned at
    /// machine-identity registration time. Lookups read the off-chain
    /// `did → agentId` index in `CF_IDENTITIES` populated by
    /// `event_loop::process_erc8004_registered_logs`; callers MUST
    /// tolerate `None` for DIDs whose mirror tx has not yet been
    /// included in a finalized block. Returns `None` when the mirror
    /// wiring was skipped at `init_identity()` (no storage, no
    /// signer).
    ///
    /// [`OnChainAgentRegistry`]: tenzro_identity::erc8004::OnChainAgentRegistry
    pub fn erc8004_agent_registry(
        &self,
    ) -> Option<&Arc<dyn tenzro_identity::erc8004::OnChainAgentRegistry>> {
        self.erc8004_agent_registry.as_ref()
    }

    /// Returns the validator address this node uses as block proposer
    /// and consensus voter — set once in [`init_consensus`] from the
    /// loaded validator keypair. The Stripe SPT settlement-outcome
    /// dispatcher reads this to populate the `rater` field on the
    /// ERC-8004 `FeedbackEntry` row, anchoring the cross-write to the
    /// validator that observed the webhook. Returns `None` on
    /// non-validator roles.
    pub fn local_validator_address(&self) -> Option<&Address> {
        self.local_validator_address.as_ref()
    }

    /// Returns the payment gateway if initialized
    pub fn payment_gateway(&self) -> Option<&Arc<TenzroPaymentGateway>> {
        self.payment_gateway.as_ref()
    }

    /// The identity registry the identity gate reads: consensus chain state,
    /// believed once the chain has certified a checkpoint.
    fn chain_registry(&self) -> Option<Arc<dyn tenzro_iroh::RegistryView>> {
        let chain = self.storage.clone()? as Arc<dyn KvStore>;
        let consensus = self.consensus.clone();
        let ready: Arc<dyn Fn() -> bool + Send + Sync> =
            Arc::new(move || consensus.as_ref().is_some_and(|c| c.certified_height() > 0));
        Some(Arc::new(crate::identity_gate::ChainRegistry::new(
            chain, ready,
        )))
    }

    /// Turns on the identity gate for the peers of this node's iroh
    /// endpoint and the neighbours of its gossip: serves the onboarding
    /// protocol, installs the registry, protects the boot list and the
    /// validators, starts the standing sweep. The gate acts in the
    /// `[onboarding]` mode; in `audit` it logs what it would refuse.
    fn install_identity_gate(&mut self, resolver: &Arc<tenzro_iroh::IrohBackedResolver>) {
        use crate::identity_gate as ig;
        let cfg = self.config.onboarding.clone();
        let Some(chain) = self.storage.clone().map(|s| s as Arc<dyn KvStore>) else {
            return;
        };
        let gate = resolver.identity_gate().clone();
        // The onboarding protocol is served whatever the mode: it is how a
        // machine registers. It pays nobody's fee until the ledger rail is up
        // and `[onboarding.sponsor]` is on.
        if let Some(identity) = self.identity_transport.clone() {
            let server = Arc::new(ig::OnboardServer::new(
                &cfg,
                ig::names_from(identity.store().clone()),
                chain.clone(),
                gate.clone(),
                None,
                None,
            ));
            resolver.onboard_handler().set(server.clone());
            self.onboard_server = Some(server);
        }
        let Some(registry) = self.chain_registry() else {
            return;
        };
        let consensus = self.consensus.clone();
        let protected = ig::protected_identities(&self.config, consensus.as_deref(), Some(&chain));
        if ig::install_peer_gate(&cfg, &gate, registry, protected).is_none() {
            return;
        }
        // Validators come and go with the epoch: keep the protected set
        // current.
        {
            let (config, gate, chain, consensus) =
                (self.config.clone(), gate.clone(), chain.clone(), consensus);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    tick.tick().await;
                    gate.protect(ig::protected_identities(
                        &config,
                        consensus.as_deref(),
                        Some(&chain),
                    ));
                }
            });
        }
        if cfg.policy.mode == tenzro_onboarding_types::onboarding::GateMode::Enforce
            && let Some(network) = &self.network
        {
            network.set_gossip_registered_only(true);
        }
    }

    /// The ledger settlement submitter, when the ledger rail is up.
    pub fn ledger_submitter(&self) -> Option<&Arc<crate::payment_rails::LedgerSubmitter>> {
        self.ledger_submitter.as_ref()
    }

    /// Where proven findings (trust-ledger findings) are
    /// flagged to consensus from this validator's account.
    pub(crate) fn finding_sink(&self) -> Option<crate::agent_audit::FindingSink> {
        self.storage.clone().map(|s| {
            crate::agent_audit::FindingSink::new(
                self.finding_submitter.clone(),
                s as Arc<dyn KvStore>,
            )
        })
    }

    /// Payment sessions over on-chain escrows, when the ledger rail is up.
    pub fn payment_sessions(&self) -> Option<&Arc<tenzro_payments::mpp::MppSessionManager>> {
        self.payment_sessions.as_ref()
    }

    pub fn x402_server(&self) -> Option<&Arc<X402PaymentServer>> {
        self.x402_server.as_ref()
    }

    /// The facilitator the operator names, which settles the x402 payments
    /// A2A tasks ask for.
    pub fn x402_facilitator(&self) -> Option<&Arc<tenzro_payments::x402::CdpFacilitatorClient>> {
        self.x402_facilitator.as_ref()
    }

    /// The x402 facilitator this node serves to resource servers, once the
    /// payment gateway is up.
    pub fn x402_facilitator_service(&self) -> Option<&Arc<tenzro_payments::x402::X402Facilitator>> {
        self.x402_facilitator_service.as_ref()
    }

    /// The guarded client for fetches to caller-named destinations.
    pub fn egress(&self) -> &Arc<crate::egress_guard::EgressGuard> {
        &self.egress
    }

    /// Client-address, `Host` and batch policy for the HTTP listeners.
    pub fn http_surface(&self) -> &Arc<crate::http_surface::SurfacePolicy> {
        &self.http_surface
    }

    /// This node's payee as `0x` hex, the account escrows paying it name.
    pub fn payee_hex(&self) -> Option<String> {
        self.operator_payee()
            .map(|a| format!("0x{}", hex::encode(a.as_bytes())))
    }

    /// Session continuity, when it is running.
    #[cfg(feature = "inference")]
    pub fn kv_continuity(&self) -> Option<&Arc<crate::kv_continuity::KvContinuity>> {
        self.kv_continuity.get()
    }

    /// Returns the model registry if initialized
    pub fn model_registry(&self) -> Option<&Arc<ModelRegistry>> {
        self.model_registry.as_ref()
    }

    /// Returns the provider manager if initialized. Consumed by RPC handlers
    /// (`handle_provider_status`, `handle_register_provider`) to look up
    /// per-provider health, reputation, and circuit-breaker state.
    pub fn provider_manager(&self) -> Option<&Arc<ProviderManager>> {
        self.provider_manager.as_ref()
    }

    /// This node's own provider wallet address, resolved by
    /// [`TenzroNode::operator_payee`]. Self-installed provider entries (e.g.
    /// MoE expert-shard declarations) therefore key to the identical address
    /// remote peers see on gossip and pay at settlement.
    pub(crate) fn self_provider_address(&self) -> Option<Address> {
        self.operator_payee()
    }

    /// Validator-observed prices and the compute price index built from them.
    pub fn compute_observations(&self) -> &Arc<crate::compute_observations::ObservationWindow> {
        &self.compute_observations
    }

    /// Returns the inference router if initialized. Wired into the web
    /// API's `/chat` handler in `main.rs` so OpenAI-compatible chat
    /// completion requests can be dispatched to the correct serving
    /// provider.
    pub fn inference_router(&self) -> Option<&Arc<InferenceRouter>> {
        self.inference_router.as_ref()
    }

    /// Owned clone of the inference router Arc, for library consumers that
    /// need to keep a reference past the lifetime of the node borrow
    /// (typical in embedded-node apps where the app's UI thread shares a
    /// router with the node's RPC dispatcher).
    pub fn inference_router_arc(&self) -> Option<Arc<InferenceRouter>> {
        self.inference_router.clone()
    }

    /// Returns the committee-resident Red Stuff DA backend if this node is a
    /// validator with committee-DA wired. Read by the `tenzro_daChallenge`,
    /// `tenzro_daListChallenges`, `tenzro_daAvailability`, `tenzro_daCommittee`,
    /// and `tenzro_daListBlobs` RPC handlers.
    pub fn da_committee(&self) -> Option<&Arc<crate::da_committee::DaCommitteeBackend>> {
        self.da_committee_backend.as_ref()
    }

    /// The objects this node certifies, for the one task that records them.
    pub(crate) fn take_da_recorder(
        &self,
    ) -> Option<tokio::sync::mpsc::UnboundedReceiver<crate::da_committee::CertifiedObject>> {
        self.da_recorder_rx.lock().take()
    }

    /// Owned clone of the shared `ModelRuntime` Arc. The runtime is
    /// process-global by design (one `llama.cpp` backend per node), so
    /// every consumer — the RPC `tenzro_chat` handler, the embedded
    /// `/v1/chat/completions` web surface, the desktop app's local chat
    /// pane, and any provider-side serving wiring — must share this Arc
    /// rather than instantiating their own. Returns `None` only when AI
    /// infrastructure was disabled at startup.
    #[cfg(feature = "inference")]
    pub fn model_runtime_arc(&self) -> Option<Arc<ModelRuntime>> {
        self.model_runtime.clone()
    }

    /// Whether this node's model runtime holds `model_id` loaded. Never in the
    /// light build, which has no model runtime.
    pub fn runtime_has_loaded(&self, model_id: &str) -> bool {
        #[cfg(feature = "inference")]
        {
            self.model_runtime
                .as_ref()
                .is_some_and(|rt| rt.is_loaded(model_id))
        }
        #[cfg(not(feature = "inference"))]
        {
            let _ = model_id;
            false
        }
    }

    /// Node-level admission control. Every inference entry point must acquire
    /// through this and hold the guard for the request's life — a path that
    /// skips it is unbounded, and one unbounded path defeats the ceiling for
    /// all of them.
    pub fn traffic(&self) -> &Arc<tenzro_model::traffic::TrafficManager> {
        &self.traffic
    }

    /// Starts the load monitor and registers what the node gives back when
    /// memory runs short: the store's block cache and idle models.
    fn start_load_protection(&self) {
        let monitor = crate::load_monitor::LoadMonitor::new(Some(self.config.data_dir.clone()));
        if let Some(store) = self.storage.clone() {
            monitor.register(crate::memory_guard::StoreCache::reclaimer(store));
        }
        #[cfg(feature = "inference")]
        if let Some(runtime) = self.model_runtime.clone() {
            monitor.register(crate::memory_guard::IdleModels::reclaimer(
                runtime,
                self.lifecycle.clone(),
            ));
        }
        let reading = self.load_reading.clone();
        let thread = monitor.spawn_with(crate::load_monitor::SAMPLE_EVERY, move |s| {
            if let Some(reading) = &reading {
                reading(s);
            }
        });
        *self.load_monitor.lock() = Some(thread);
    }

    /// Warm-set tracking and cold-start messaging.
    pub fn lifecycle(&self) -> &Arc<tenzro_model::lifecycle::ModelLifecycle> {
        &self.lifecycle
    }

    /// Starts storage maintenance over the node's store. A committee member
    /// writes pruned history into the committee DA layer; a node outside the
    /// committee prunes only what a member archived and it verified, and
    /// reads it back from the same layer. A node with no DA layer to reach
    /// keeps the same window and deletes older history. A node that follows
    /// no chain keeps its full history.
    fn start_storage_maintenance(&mut self) {
        use crate::history_archive::{CertifiedCheckpoints, Handoff, HistoryArchive};
        let Some(storage) = self.storage.clone() else {
            return;
        };
        self.history_archive = match (&self.da_committee_backend, &self.consensus) {
            (Some(da), Some(consensus)) => HistoryArchive::new(
                storage.clone(),
                da.clone() as Arc<dyn tenzro_storage::da::DaBackend>,
                consensus.clone() as Arc<dyn CertifiedCheckpoints>,
                Handoff::Submit,
            )
            .inspect_err(
                |e| warn!(error = %e, "History archive unavailable: block history is kept in full"),
            )
            .ok()
            .map(Arc::new),
            (None, Some(consensus)) => {
                match (self.iroh_resolver.as_ref(), self.records().cloned()) {
                    (Some(resolver), Some(signer)) => match crate::da_committee_surface::follower_reader(
                        resolver.endpoint().clone(),
                        consensus.clone(),
                        self.identity_registry_slot(),
                        signer,
                    ) {
                        Ok((da, locator)) => HistoryArchive::new(
                            storage.clone(),
                            da,
                            consensus.clone() as Arc<dyn CertifiedCheckpoints>,
                            Handoff::Locate(locator),
                        )
                        .inspect_err(|e| warn!(error = %e, "History archive unavailable: block history is kept in full"))
                        .ok()
                        .map(Arc::new),
                        Err(e) => {
                            warn!(error = %e, "No committee DA reader: history below the retention window is deleted");
                            local_history(&storage, consensus)
                        }
                    },
                    _ => {
                        info!("No node transport or node key: history below the retention window is deleted");
                        local_history(&storage, consensus)
                    }
                }
            }
            _ => {
                info!("This node follows no chain: block history is kept in full");
                None
            }
        };
        if let Some(archive) = &self.history_archive {
            archive.set_drop_indexes(self.config.resolved_tier() == crate::tier::Tier::Edge);
        }
        let maintenance = crate::storage_maintenance::StorageMaintenance::new(
            storage,
            &self.config.data_dir,
            self.config.storage.clone(),
            self.disk_guard.clone(),
            self.health_monitor.clone(),
            self.history_archive.clone(),
            self.consensus.clone(),
            tenzro_model::memory_budget::global(),
        )
        .with_consensus_records(self.consensus_records.clone());
        self.proof_log = maintenance.proof_log();
        self.storage_maintenance =
            Some(tokio::spawn(maintenance.run(self.config.data_dir.clone())));
    }

    /// The epoch proof log: the handover chain proof and the handovers since.
    pub fn proof_log(&self) -> Option<&Arc<parking_lot::Mutex<crate::proof_log::ProofLog>>> {
        self.proof_log.as_ref()
    }

    /// The certification of checkpoint `index`: from genesis while the
    /// consensus records hold every handover before it, otherwise from the
    /// proof log, so a node that pruned them still certifies.
    pub fn certification(
        &self,
        index: u64,
    ) -> Option<tenzro_consensus::light_client::Certification> {
        crate::proof_log::certification(self.consensus()?, self.proof_log.as_deref(), index)
    }

    /// The handover program governance set, whose proofs a chained
    /// certification builds on.
    pub fn handover_program(&self) -> Option<[u8; 32]> {
        let storage = self.storage()?.clone() as Arc<dyn tenzro_storage::KvStore>;
        tenzro_vm::native::read_handover_program(&tenzro_vm::StateAdapter::with_storage(storage))
    }

    /// The disk watermark flag.
    pub fn disk_guard(&self) -> &Arc<crate::storage_maintenance::DiskGuard> {
        &self.disk_guard
    }

    /// Models this node loaded for a demand surge.
    pub fn surge_state(&self) -> &crate::surge::SurgeState {
        &self.surge_state
    }

    /// Block history beyond the local retention window, where this node has
    /// the committee DA backend.
    pub fn history_archive(&self) -> Option<&Arc<crate::history_archive::HistoryArchive>> {
        self.history_archive.as_ref()
    }

    /// Install the process-wide memory ledger from operator configuration.
    ///
    /// Called before any model can load. A misconfigured budget — a reserve
    /// larger than the machine, tier ceilings that together overcommit it —
    /// is logged and the node falls back to defaults derived from detected
    /// memory rather than refusing to start: an operator typo in one field
    /// should not take a validator offline.
    fn install_memory_budget(&self) {
        let config = self.config.memory.to_budget_config();
        let total_gib = config.total_bytes as f64 / 1_073_741_824.0;
        let reserve_gib = config.reserve_bytes as f64 / 1_073_741_824.0;

        match tenzro_model::memory_budget::install_global(config.clone()) {
            Ok(true) => info!(
                "Memory budget: {:.0} GiB total, {:.0} GiB reserved for OS/storage/services, \
                 {:.0} GiB resident tier, {:.0} GiB on-demand tier",
                total_gib,
                reserve_gib,
                config.resident_ceiling() as f64 / 1_073_741_824.0,
                config.on_demand_ceiling() as f64 / 1_073_741_824.0,
            ),
            Ok(false) => {
                debug!("Memory budget already installed; keeping the existing ledger")
            }
            Err(e) => warn!(
                "Invalid [memory] configuration ({e}); falling back to a budget derived from \
                 detected memory. Fix the config to control the split explicitly."
            ),
        }
    }

    /// Seed cold-load estimates from catalog sizes.
    ///
    /// Without this the first caller for a never-loaded model is quoted the
    /// floor estimate, which badly under-quotes a 35 GB MoE and trains callers
    /// to ignore the number. Sizes come from the catalog, so the estimate is
    /// reasonable before the model has ever been loaded; measured load times
    /// replace it after the first real load.
    fn seed_lifecycle_sizes(&self) {
        for entry in tenzro_model::get_model_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_text_embedding_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_embed_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_forecast_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_audio_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_vision_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_detection_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_segmentation_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_media_gen_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
        for entry in tenzro_model::get_tts_catalog() {
            self.lifecycle.declare_size(&entry.id, entry.size_bytes);
        }
    }

    /// Returns the local TEE hardware provider if one was detected at
    /// startup. Used by the RPC `tenzro_getTeeAttestation` handler and the
    /// MCP `attest` tool to generate attestations against the local
    /// enclave without re-running TEE auto-detection on every request.
    pub fn tee_provider(&self) -> Option<&dyn TeeProvider> {
        self.tee_provider.as_deref()
    }

    /// Checks whether this node's hardware can back every role in `roles`,
    /// returning a human-readable error naming the first role it cannot serve.
    ///
    /// The gate exists so a node cannot advertise a capability it does not
    /// have — otherwise any peer could claim to be a TEE or storage provider
    /// and collect work it can't honor. The policy is deliberately uneven:
    ///
    /// - `TeeProvider` is hard-gated: the node must have detected real TEE
    ///   hardware at startup (`tee_provider.is_some()`). Confidential compute
    ///   is a trust claim, so a self-report is never enough — and the quote is
    ///   re-verified at request time regardless.
    /// - `StorageProvider` requires verified free disk at or above
    ///   [`MIN_STORAGE_PROVIDER_FREE_GB`]. Capacity is the one storage input a
    ///   node cannot fake.
    /// - `ComputeProvider` requires a detected accelerator. The role rents the
    ///   card out by the hour, so a node without one has nothing to sell.
    /// - `ModelProvider` is permissionless: the floor is "can run the smallest
    ///   model on CPU" (Gemma 3 270M), which every machine that boots the node
    ///   clears, so there is nothing to reject. A GPU only widens which larger
    ///   models the node can serve, never whether it may join.
    /// - Validator / full-node / client roles are gated by stake and protocol
    ///   elsewhere, not by hardware, so they always pass here.
    pub async fn validate_role_capability(
        &self,
        roles: &RoleSet,
    ) -> std::result::Result<(), String> {
        if roles.serves_tee() && self.tee_provider.is_none() {
            return Err(
                "cannot serve the 'tee' role: no TEE hardware detected on this node \
                 (Intel TDX, AMD SEV-SNP, or AWS Nitro required)"
                    .to_string(),
            );
        }

        if roles.serves_storage() || roles.serves_compute() {
            // The hardware profile is populated lazily (first probe RPC), so an
            // absent profile means "not measured yet", not "zero disk" — detect
            // and cache on demand rather than rejecting on a missing reading.
            let measured = self.hardware_profile.read().clone();
            let profile = match measured {
                Some(hw) => hw,
                None => {
                    let hw = detect_hardware(&self.config.data_dir)
                        .await
                        .map_err(|e| format!("hardware probe failed: {e}"))?;
                    *self.hardware_profile.write() = Some(hw.clone());
                    hw
                }
            };

            let free_gb = profile.storage_available_gb;
            if roles.serves_storage() && free_gb < MIN_STORAGE_PROVIDER_FREE_GB {
                return Err(format!(
                    "cannot serve the 'storage' role: {free_gb:.1} GB free disk, \
                     need at least {MIN_STORAGE_PROVIDER_FREE_GB:.0} GB"
                ));
            }
            if roles.serves_compute() && profile.gpus.is_empty() {
                return Err(
                    "cannot serve the 'compute' role: no accelerator detected on this node \
                     (compute rents the card out by the hour, so there has to be one)"
                        .to_string(),
                );
            }
        }

        Ok(())
    }

    /// Removes from `config.roles` any role this node's hardware can't back,
    /// logging each drop. Called once at startup after TEE detection so every
    /// downstream reader (runtime spawn, capability announce, status) sees only
    /// roles the node can honor. A node never fails to boot over this — it just
    /// comes up serving fewer roles.
    async fn prune_unsupported_roles(&mut self) {
        let mut kept = Vec::new();
        let mut dropped = false;
        for role in self.config.roles.iter() {
            match self
                .validate_role_capability(&RoleSet::from_roles([role]))
                .await
            {
                Ok(()) => kept.push(role),
                Err(reason) => {
                    warn!("Dropping role '{role}' at startup: {reason}");
                    dropped = true;
                }
            }
        }
        if dropped {
            // Empty input falls back to the client role, so a node that loses
            // every configured role still has a valid identity.
            let pruned = RoleSet::from_roles(kept);
            info!("Roles after capability check: {pruned}");
            self.config.roles = pruned;
            *self.runtime_roles.write() = self.config.roles.clone();
        }
    }

    /// Returns the durable usage tracker, the producer-side recipient of
    /// every successful inference's `UsageRecord`. Used by the
    /// `tenzro_listInferenceUsage` RPC handler to surface marketplace observability data.
    pub fn usage_tracker(&self) -> Option<&Arc<tenzro_model::UsageTracker>> {
        self.usage_tracker.as_ref()
    }

    /// Returns the EU AI Act Art. 50(2) provenance store. Populated by the
    /// inference router on every successful response and queried by the
    /// `tenzro_getContentProvenance` RPC handler.
    pub fn provenance_store(&self) -> Option<&Arc<tenzro_model::ProvenanceStore>> {
        self.provenance_store.as_ref()
    }

    /// Returns the provenance signer used to stamp locally-served inference
    /// responses with a `tenzro_contentProvenance` manifest.
    pub fn provenance_signer(&self) -> Option<&tenzro_model::SharedProvenanceSigner> {
        self.provenance_signer.as_ref()
    }

    /// Returns the jurisdiction signer used to stamp locally-served
    /// inference responses with a `tenzro_jurisdiction` receipt.
    pub fn jurisdiction_signer(&self) -> Option<&tenzro_model::SharedJurisdictionSigner> {
        self.jurisdiction_signer.as_ref()
    }

    /// Returns the sealed-model manifest store (write-through to the
    /// `sealed:` prefix in CF_MODELS).
    pub fn sealed_model_store(&self) -> Option<&Arc<tenzro_model::SealedModelStore>> {
        self.sealed_model_store.as_ref()
    }

    /// Returns this node's hybrid X25519 + ML-KEM-768 recipient keypair for sealed model
    /// shards. `None` when the key file could not be loaded or minted.
    pub fn model_recipient_key(&self) -> Option<&Arc<tenzro_keygen::DerivedHybridRecipient>> {
        self.model_recipient_key.as_ref()
    }

    /// Returns this node's operator-declared jurisdiction claim, if any.
    /// Built once at startup; `None` means the node never satisfies a
    /// jurisdiction pin.
    pub fn jurisdiction_claim(&self) -> Option<&tenzro_types::JurisdictionClaim> {
        self.jurisdiction_claim.as_ref()
    }

    /// Returns the event loop sender for submitting transactions
    pub fn event_sender(&self) -> Option<&mpsc::Sender<NodeEvent>> {
        self.event_loop_tx.as_ref()
    }

    /// Consensus state as this node last committed it.
    pub fn chain_state(&self) -> Option<tenzro_vm::StateAdapter> {
        self.storage
            .as_ref()
            .map(|s| tenzro_vm::StateAdapter::with_storage(s.clone() as Arc<dyn KvStore>))
    }

    /// Returns the storage backend if initialized
    pub fn storage(&self) -> Option<&Arc<RocksDbStore>> {
        self.storage.as_ref()
    }

    /// The durable log of the chain's events, once storage is open.
    pub fn event_log(&self) -> Option<&Arc<tenzro_events::EventLog>> {
        self.event_log.as_ref()
    }

    /// Single-use challenges gating custody mutations.
    pub fn custody_challenges(&self) -> &Arc<crate::passkey_rpc::CustodyChallengeStore> {
        &self.custody_challenges
    }

    /// The chain id this node runs (see [`NodeConfig::chain_id`]). Custody
    /// approvals this node issues or checks are bound to it.
    pub fn chain_id(&self) -> u64 {
        self.config.chain_id()
    }

    /// The node's visibility.
    pub fn visibility(&self) -> tenzro_types::Visibility {
        *self.node_visibility.read()
    }

    /// The effective visibility of a model this node serves: its override when
    /// it has one, otherwise the node's visibility. `None` when not served.
    pub fn model_visibility(&self, model_id: &str) -> Option<tenzro_types::Visibility> {
        let node = self.visibility();
        self.served_models
            .get(model_id)
            .map(|e| tenzro_types::Visibility::resolve(*e.value(), node))
    }

    /// The cluster membership lists this node holds.
    pub fn cluster_identity(&self) -> &Arc<crate::cluster_identity::ClusterIdentity> {
        &self.cluster_identity
    }

    /// Returns the Permit2 nonce bitmap handle.
    pub fn permit2_nonce_bitmap(&self) -> Arc<tenzro_vm::permit2::Permit2NonceBitmap> {
        self.permit2_nonce_bitmap.clone()
    }

    pub fn chainlink_por_adapter(&self) -> Arc<tenzro_bridge::ChainlinkPorAdapter> {
        self.chainlink_por_adapter.clone()
    }

    /// Returns the Cosmos-style snapshot ABCI store if initialized.
    ///
    /// Used by the four snapshot RPCs and by the EventLoop's periodic
    /// snapshot producer.
    pub fn snapshot_store(&self) -> Option<&Arc<crate::snapshot::SnapshotStore>> {
        self.snapshot_store.as_ref()
    }

    /// Whether `commitment` is attested in committed consensus state, i.e. an
    /// `AttestZkProof` transaction verified its proof in a finalized block.
    /// This is the record the EVM `ZK_VERIFY` precompile (`0x1011`) reads.
    pub fn zk_commitment_attested(&self, commitment: &[u8; 32]) -> bool {
        match self.storage() {
            Some(storage) => {
                let state = tenzro_vm::StateAdapter::with_storage(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>
                );
                tenzro_vm::precompiles::zk_commitment_attested(&state, commitment)
            }
            None => false,
        }
    }

    /// Set a rewrite of every load reading before the monitor applies it,
    /// so the level does not follow the machine. Must be called before
    /// [`TenzroNode::start`].
    pub fn set_load_reading(&mut self, reading: LoadReading) {
        self.load_reading = Some(reading);
    }

    /// Set the peers to restore state from at start, by iroh `EndpointId`.
    /// Must be called before [`TenzroNode::start`], together with
    /// [`TenzroNode::set_weak_subjectivity_anchor`], which state sync
    /// verifies against.
    pub fn set_state_sync_peers(&mut self, peers: Vec<tenzro_iroh::EndpointAddr>) {
        self.state_sync_peers = peers.iter().map(|p| p.id).collect();
        self.state_sync_addrs = peers.into_iter().filter(|p| !p.addrs.is_empty()).collect();
    }

    /// Set the recovery manifest to apply at start (see [`crate::recovery`]).
    /// Must be called before [`TenzroNode::start`].
    pub fn set_recovery(&mut self, request: crate::recovery::RecoveryRequest) {
        self.recovery = Some(request);
    }

    /// Set the weak-subjectivity checkpoint `(height, block_hash)`, obtained
    /// out of band. State sync restores the snapshot this block commits, and
    /// every import path refuses any other block at `height`. Certificate
    /// verification alone cannot defeat a long-range fork: an attacker
    /// holding an old validator supermajority's keys can forge a
    /// self-consistent alternate history from any past epoch.
    pub fn set_weak_subjectivity_anchor(&mut self, height: u64, block_hash: [u8; 32]) {
        self.weak_subjectivity_anchor = Some((height, block_hash));
    }

    /// Returns the consensus engine if initialized.
    ///
    /// RPC handlers use this to inspect the in-flight mempool — e.g.
    /// `tenzro_getTransaction` falls back to the mempool when a hash isn't yet
    /// in `CF_TRANSACTIONS`, so callers can distinguish "pending" from "unknown"
    /// without polling forever.
    pub fn consensus(&self) -> Option<&Arc<ConsensusHandle>> {
        self.consensus.as_ref()
    }

    /// Returns the network treasury if initialized
    pub fn treasury(&self) -> Option<&Arc<NetworkTreasury>> {
        self.treasury.as_ref()
    }

    /// Returns the storage-provider runtime if this node serves the
    /// StorageProvider role and the runtime was spawned at startup.
    pub fn storage_runtime(
        &self,
    ) -> Option<&Arc<crate::storage_provider_runtime::StorageProviderRuntime>> {
        self.storage_runtime.as_ref()
    }

    /// Returns the admission controller if initialized. Wired
    /// during startup once consensus, identity, and staking are all up.
    pub fn admission(&self) -> Option<&Arc<tenzro_consensus::admission::AdmissionController>> {
        self.admission.as_ref()
    }

    /// Returns the token if initialized
    pub fn token(&self) -> Option<&Arc<TnzoToken>> {
        self.token.as_ref()
    }

    /// Returns the unified token registry if initialized
    pub fn token_registry(&self) -> Option<&Arc<TokenRegistry>> {
        self.token_registry.as_ref()
    }

    /// Returns the VM runtime if initialized
    pub fn vm_runtime(&self) -> Option<&Arc<MultiVmRuntime>> {
        self.vm_runtime.as_ref()
    }

    /// Returns the wallet service if initialized
    pub fn wallet_service(&self) -> Option<&Arc<TenzroWalletService>> {
        self.wallet_service.as_ref()
    }

    /// Applies the network policy on-chain governance enacts.
    pub fn policy_applier(&self) -> Option<&Arc<crate::policy_reflection::PolicyApplier>> {
        self.policy_applier.as_ref()
    }

    /// Returns the trust ledger if initialized.
    pub fn catalog_sync(&self) -> Option<&Arc<crate::catalog_sync::CatalogSync>> {
        self.catalog_sync.as_ref()
    }

    pub fn trust_ledger(&self) -> Option<&Arc<tenzro_trust::TrustLedger>> {
        self.trust_ledger.as_ref()
    }

    /// Returns the verifiable-inference commitment store + challenge
    /// manager if initialized. `Some` only when RocksDB storage is
    /// available. Read by the chat/inference handlers (commitment
    /// write path) and the `tenzro_*Inference{Commitment,Challenge}`
    /// RPC handlers.
    pub fn challenge_manager(&self) -> Option<&Arc<crate::inference_challenge::ChallengeManager>> {
        self.challenge_manager.as_ref()
    }

    /// Returns the SLA fault detector if initialized. `Some` only on
    /// validator-role nodes — the slashing authority requires consensus
    /// participation. Read by the `tenzro_sla*` RPC handlers.
    pub fn sla_manager(&self) -> Option<&Arc<tenzro_model::SlaManager>> {
        self.sla_manager.as_ref()
    }

    /// Returns the in-flight SLA probe correlator. Always present; empty on
    /// non-validator nodes. Probes inserted here by `tenzro_slaIssueProbe`
    /// are removed by the `tenzro/sla` gossip subscriber when a matching
    /// `SlaResponse` arrives.
    pub fn sla_outstanding_probes(&self) -> &Arc<DashMap<String, tenzro_model::SlaProbe>> {
        &self.sla_outstanding_probes
    }

    /// This validator's per-epoch SLA probe results, pending attestation.
    pub fn sla_tally(&self) -> &Arc<crate::sla_attest::SlaTally> {
        &self.sla_tally
    }

    /// Returns the permissionless ValidatorRegistry if initialized.
    pub fn validator_registry(
        &self,
    ) -> Option<&Arc<tenzro_token::validator_registry::ValidatorRegistry>> {
        self.validator_registry.as_ref()
    }

    /// Returns the shared WebAuthnValidator (passkey-bound primary validator).
    pub fn webauthn_validator(&self) -> Option<&Arc<tenzro_vm::WebAuthnValidator>> {
        self.webauthn_validator.as_ref()
    }

    /// Returns the pending passkey auth-session store used by the
    /// browser-mediated CLI login flow.
    pub fn passkey_sessions(&self) -> Option<&Arc<crate::passkey_rpc::PasskeySessionStore>> {
        self.passkey_sessions.as_ref()
    }

    /// Returns the adaptive burn governance dial manager.
    pub fn burn_rate_manager(
        &self,
    ) -> Option<&Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>> {
        self.burn_rate_manager.as_ref()
    }

    /// Operator access gating.
    pub fn access(&self) -> &Arc<crate::access::Access> {
        &self.access
    }

    /// The administrative audit log.
    pub fn admin_audit(&self) -> &Arc<crate::admin_audit::AdminAudit> {
        &self.admin_audit
    }

    /// Bind the shared handle this node is held through, so components built
    /// before it existed can reach it, and start watching the access policy
    /// file. Call once, right after wrapping the node in its `Arc`.
    pub fn bind_self(self: &Arc<Self>) {
        if self.self_ref.set(Arc::downgrade(self)).is_ok() {
            self.access.store().spawn_watcher();
        }
    }

    /// Returns the OAuth 2.1 + DPoP + RAR auth engine if initialized.
    pub fn auth_engine(&self) -> Option<&Arc<tenzro_auth::AuthEngine>> {
        self.auth_engine.as_ref()
    }

    /// Payee settlement preferences, once storage is open.
    pub fn settlement_preferences(
        &self,
    ) -> Option<&Arc<crate::settlement_preferences_bridge::NodeSettlementPreferences>> {
        self.settlement_preferences.as_ref()
    }

    /// Returns the active liveness sweeper config, if the sweeper is running.
    pub fn liveness_config(&self) -> Option<crate::liveness::LivenessConfig> {
        self.liveness_sweeper.as_ref().map(|s| s.config.clone())
    }

    /// Returns the network service if initialized
    pub fn network(&self) -> Option<&Arc<TenzroNetworkService>> {
        self.network.as_ref()
    }

    /// Node iroh resolver (single content-addressed endpoint). `None` until
    /// startup binds it. Used by storage-provider producers to read the local
    /// `EndpointId` when broadcasting shard-replication requests.
    pub fn iroh_resolver(&self) -> Option<&Arc<tenzro_iroh::IrohBackedResolver>> {
        self.iroh_resolver.as_ref()
    }

    /// The identity this node signs gossip announcements as: its batched
    /// hardware record signer, and the machine DID that key derives. `None`
    /// on a machine without a hardware identity.
    pub fn announce_identity(&self) -> Option<crate::event_loop::AnnounceIdentity> {
        Some(crate::event_loop::AnnounceIdentity::new(
            self.records()?.clone(),
        ))
    }

    /// The supervisor's audit trail of agent actions.
    pub fn agent_audit(&self) -> &Arc<crate::agent_audit::AgentAudit> {
        &self.agent_audit
    }

    /// The signed records of agents' tool calls this node served.
    pub fn tool_calls(&self) -> &Arc<crate::tool_call_record::ToolCallLog> {
        &self.tool_calls
    }

    /// The DA backend agent audit entries are placed in, once the agent
    /// runtime is up.
    pub fn agent_da(&self) -> Option<Arc<dyn tenzro_storage::da::DaBackend>> {
        self.agent_da.clone()
    }

    /// The connector this node serves models through, when it has one.
    pub fn connector(&self) -> Option<&Arc<crate::connector::Connector>> {
        self.connector.as_ref()
    }

    /// The connector model `model_id` names, when this node serves it from
    /// the operator's own endpoint.
    pub fn upstream_model(&self, model_id: &str) -> Option<&crate::connector::UpstreamModel> {
        self.connector.as_ref()?.model(model_id)
    }

    /// Give a node that was not started a record signer, for tests.
    #[cfg(test)]
    pub(crate) fn set_record_signer(
        &mut self,
        signer: impl tenzro_crypto::batch::RecordSigner + 'static,
    ) {
        self.records = Some(Arc::new(signer));
    }

    /// The batched hardware signer of the machine identity key.
    pub fn records(&self) -> Option<&Arc<dyn tenzro_crypto::batch::RecordSigner>> {
        self.records.as_ref()
    }

    /// The batched hardware signer of the machine identity key.
    pub fn batch_service(&self) -> Option<&Arc<tenzro_crypto::batch::BatchService>> {
        self.batch_service.as_ref()
    }

    /// The hybrid X25519 + ML-KEM-768 public key machine images and secrets
    /// are sealed to.
    pub fn machine_sealing_public_key(
        &self,
    ) -> Result<tenzro_crypto::hybrid_seal::HybridPublicKey> {
        if let Some(key) = self.machine_sealing_public_key.get() {
            return Ok(key.clone());
        }
        let recipient = crate::keygen::NodeKeys::open(&self.config.data_dir)?.machine_sealing()?;
        let key = tenzro_crypto::hybrid_seal::HybridRecipient::public_key(&recipient);
        Ok(self.machine_sealing_public_key.get_or_init(|| key).clone())
    }

    /// The bridge route framework block execution runs, for reading route
    /// state.
    pub fn route_framework(&self) -> &'static RouteFramework {
        tenzro_vm::native::bridge::route_framework()
    }

    /// Returns the node config
    /// This node's own addressing, assembled from live state.
    ///
    /// Every field is what the node actually has right now — a surface that
    /// is not running contributes nothing, so the resulting document never
    /// advertises something a caller would then fail to reach.
    pub async fn self_addressing(&self) -> crate::node_did_document::NodeAddressing {
        let (iroh_endpoint_id, iroh_alpns) = match &self.iroh_resolver {
            Some(resolver) => {
                let mut alpns = vec!["iroh-blobs".to_string()];
                if self.iroh_a2a_dispatcher.is_some() {
                    alpns.push("tenzro/a2a".to_string());
                }
                if self.iroh_mcp_handler.is_some() {
                    alpns.push("tenzro/mcp".to_string());
                }
                alpns.push("tenzro/moe".to_string());
                if self.iroh_infer_dispatcher.is_some() {
                    alpns.push("tenzro/infer".to_string());
                }
                (Some(resolver.endpoint().id().to_string()), alpns)
            }
            None => (None, Vec::new()),
        };

        crate::node_did_document::NodeAddressing {
            did: crate::identity_bootstrap::machine_did(),
            ed25519_public_key_hex: iroh_endpoint_id.clone(),
            ml_dsa_65_public_key: crate::identity_bootstrap::machine_ml_dsa_public(),
            iroh_endpoint_id,
            iroh_alpns,
            relays: self
                .identity_relays()
                .into_iter()
                .map(|r| r.url.to_string())
                .collect(),
            rpc_url: crate::exposure::rpc_url(&self.config),
            mcp_url: crate::exposure::mcp_endpoint(&self.config),
        }
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Enforces the operator model-license acceptance policy for a multi-modal
    /// ONNX catalog entry. The multi-modal runtimes (vision / audio / detection
    /// / segmentation / text-embedding / forecast / video) load ONNX bundles
    /// directly into their own runtime rather than through
    /// [`tenzro_model::ModelRegistry::register_model`], so the license gate that
    /// `register_model` applies to LM catalog entries would otherwise be bypassed
    /// on these load paths. The licence is the one the model's catalog entry
    /// declares. Returns `Ok(())` when the
    /// tier is admitted and, for a territorial licence, the node's declared
    /// jurisdiction is inside its grant; otherwise `Err` with a caller-facing
    /// message naming what the operator must change.
    pub fn check_model_license(&self, model_id: &str) -> std::result::Result<(), String> {
        use tenzro_types::model::LicenseTier;
        let licence = self.model_licence(model_id)?;
        // Every licence the weights are bound by must be admitted.
        let Some(refused) = licence
            .parts()
            .into_iter()
            .find(|p| !self.config.model_licensing.admits(p.tier, p.id))
        else {
            // A territorial licence also binds where this node runs.
            return crate::territory::check_licence_location(
                model_id,
                &licence,
                self.config.jurisdiction_country.as_deref(),
            );
        };
        let (tier, license_id) = (refused.tier, refused.id);
        let remedy = match tier {
            LicenseTier::NonCommercial => "operator must set --accept-non-commercial".to_string(),
            LicenseTier::CommercialCustom => format!(
                "operator must set --accept-license {}",
                license_id.unwrap_or("<id>")
            ),
            LicenseTier::Permissive | LicenseTier::Attribution => {
                "license tier is admitted by default".to_string()
            }
        };
        Err(format!(
            "model '{model_id}' has license tier {tier:?} which is not accepted: {remedy}"
        ))
    }

    /// The licence `model_id` is bound by: its catalog entry's.
    pub fn model_licence(
        &self,
        model_id: &str,
    ) -> std::result::Result<tenzro_model::catalog::Licence, String> {
        tenzro_model::catalog::entry(model_id)
            .map(|e| e.licence)
            .ok_or_else(|| format!("model '{model_id}' is not in this node's catalog"))
    }

    /// Register a model service instance (local or network).
    ///
    /// The instance is paid out to this node's operator payee in both cases. For
    /// a `Local` instance that is the node serving its own weights; for a
    /// `Network` instance the operator is registering an external endpoint they
    /// broker, so they are the counterparty of record on-chain and settle with
    /// the upstream themselves.
    pub fn register_model_service(
        &self,
        model_id: &str,
        model_name: &str,
        provider_name: &str,
        location: ModelLocation,
        mcp_endpoint: &str,
        parameters: &str,
    ) -> String {
        // Reuse this node's existing instance for the same model rather than
        // minting a second one. A node serves a model once — concurrency is
        // `max_concurrent` on the one instance, not a second registration — so
        // a re-serve is a refresh, not a new offer.
        //
        // Minting unconditionally meant every `tenzro model serve` of an
        // already-served model left another instance behind, persisted to
        // `CF_MODEL_SERVICES` and re-hydrated on boot, so restarting never
        // cleared them. `/v1/models` then listed one model several times and
        // peers saw duplicate offers for the same weights on the same node.
        let existing = self.model_services.iter().find_map(|e| {
            let v = e.value();
            (v.model_id == model_id && v.location == location)
                .then(|| (v.instance_id.clone(), v.created_at))
        });
        let (instance_id, created_at) = match existing {
            Some(pair) => pair,
            None => (
                uuid::Uuid::new_v4().to_string(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        };
        let pricing = self.provider_pricing.read();
        // A model under a non-commercial licence is offered at no charge.
        let free = crate::catalog_sync::non_commercial(self, model_id);

        let instance = ModelServiceInstance {
            instance_id: instance_id.clone(),
            model_id: model_id.to_string(),
            model_name: model_name.to_string(),
            // Named so a routed call that pinned this node's own offer resolves
            // against this instance rather than being treated as a remote
            // provider's, and so the provider share has a real payee.
            provider_address: self.operator_payee().unwrap_or_default(),
            provider_name: provider_name.to_string(),
            location,
            mcp_endpoint: mcp_endpoint.to_string(),
            status: ServiceStatus::Online,
            parameters: parameters.to_string(),
            pricing: if free {
                free_rate_card()
            } else {
                pricing.card_for(model_id).clone()
            },
            // Carried over on a refresh: the offer dates from when the model
            // was first served here, not from the last time it was re-served.
            created_at,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            load_info: None,
            iroh_endpoint_id: self
                .iroh_resolver
                .as_ref()
                .map(|r| r.endpoint_id().to_string())
                .unwrap_or_default(),
        };

        self.model_services
            .insert(instance_id.clone(), instance.clone());

        // Persist to RocksDB
        if let Some(ref storage) = self.storage
            && let Ok(data) = serde_json::to_vec(&instance)
            && let Err(e) = storage.put(CF_MODEL_SERVICES, instance_id.as_bytes(), &data)
        {
            warn!(
                "Failed to persist model service {} to RocksDB: {}",
                instance_id, e
            );
        }

        info!(
            "Registered model service: {} ({}) [{}]",
            model_id, instance_id, location
        );
        instance_id
    }

    /// Unregister a model service instance
    pub fn unregister_model_service(&self, instance_id: &str) {
        if let Some((_, instance)) = self.model_services.remove(instance_id) {
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, instance_id.as_bytes());
            }
            info!(
                "Unregistered model service: {} ({})",
                instance.model_id, instance_id
            );
        }
    }

    /// Unregister all model service instances for a given model_id
    pub fn unregister_model_services_by_model(&self, model_id: &str) {
        let ids: Vec<String> = self
            .model_services
            .iter()
            .filter(|entry| entry.value().model_id == model_id)
            .map(|entry| entry.key().clone())
            .collect();
        for id in &ids {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
        }
        info!("Unregistered all services for model: {}", model_id);
    }

    /// Remove expired network model service instances (TTL-based cleanup).
    /// Called periodically from the event loop's heartbeat tick.
    pub fn cleanup_expired_model_services(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ttl = 300; // 5 minutes
        let expired: Vec<String> = self
            .model_services
            .iter()
            .filter(|e| {
                let svc = e.value();
                matches!(svc.location, tenzro_types::model::ModelLocation::Network)
                    && svc.last_seen > 0
                    && now.saturating_sub(svc.last_seen) > ttl
            })
            .map(|e| e.key().clone())
            .collect();
        for id in &expired {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
            info!("Removed expired network model service: {}", id);
        }
        if !expired.is_empty() {
            info!("Cleaned up {} expired model services", expired.len());
        }
    }

    /// Resolve the GGUF file path for a given model_id by checking all known
    /// storage locations. Returns the first existing path or None.
    ///
    /// Mirrors the path-resolution logic in handle_serve_model.
    pub fn resolve_gguf_path(&self, model_id: &str) -> Option<std::path::PathBuf> {
        // One directory, one layout rule. The CLI and this node write to and
        // read from the same shared model store, so `HfDownloader` answering
        // for its own layout is the whole of the lookup — the three
        // hand-rolled `$HOME/.tenzro/models` probes that used to live here
        // existed only because the two disagreed about where models lived.
        self.hf_downloader.as_ref()?.resolve_local_gguf(model_id)
    }

    /// The checkpoint directory of a model served by a hosted engine, with
    /// the checkpoint's size: every file the catalog pins for the entry's
    /// repository, in `<models>/<model_id>-bundle/`. Each file's size and
    /// SHA-256 are checked against its pin, however it got there, so a hosted
    /// engine loads exactly the pinned bytes.
    pub fn resolve_hosted_checkpoint(
        &self,
        model_id: &str,
    ) -> std::result::Result<(std::path::PathBuf, u64), String> {
        use sha2::Digest;
        use std::io::Read;

        let entry = tenzro_model::get_model_by_id(model_id)
            .ok_or_else(|| format!("{model_id} is not in the catalog"))?;
        let pins: Vec<_> = tenzro_model::catalog::entry(model_id)
            .map(|e| e.components)
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.repo == entry.hf_repo)
            .collect();
        if pins.is_empty() {
            return Err(format!("the catalog pins no files for {}", entry.hf_repo));
        }
        let dir = self
            .config
            .effective_models_dir()
            .join(format!("{model_id}-bundle"));
        let mut total = 0;
        for pin in pins {
            let path = dir.join(pin.path);
            let mut file = std::fs::File::open(&path)
                .map_err(|e| format!("{} is not downloaded: {e}", path.display()))?;
            let mut hasher = sha2::Sha256::new();
            let mut buf = vec![0u8; 1 << 20];
            let mut size = 0u64;
            loop {
                let n = file
                    .read(&mut buf)
                    .map_err(|e| format!("reading {}: {e}", path.display()))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                size += n as u64;
            }
            let sha = hex::encode(hasher.finalize());
            if size != pin.size || sha != pin.sha256 {
                return Err(format!(
                    "{} does not match its pin ({size} bytes, sha256 {sha})",
                    path.display()
                ));
            }
            total += size;
        }
        Ok((dir, total))
    }

    /// Load the speculative-decoding drafter declared by a catalog entry for a
    /// model that just started serving. Never fails the serve: on any problem
    /// the target keeps serving without speculative decoding.
    ///
    /// Returns a status string surfaced in the serve response:
    /// - `"none"`                — catalog entry declares no MTP support
    /// - `"inline"`              — single-file MTP model; the draft head lives
    ///   inside the target GGUF itself (no separate drafter to load)
    /// - `"drafter_loaded"`      — drafter GGUF found locally and loaded
    /// - `"drafter_not_on_disk"` — drafter declared but not present locally;
    ///   the target is served batched (every slot, no speculation) until the
    ///   drafter is downloaded and the model re-served
    /// - `"drafter_load_failed"` — local drafter present but the runtime
    ///   rejected it (e.g. memory admission)
    /// - `"drafter_unavailable"` — drafter_id doesn't resolve in the catalog
    ///   or no runtime/downloader is available
    #[cfg(feature = "inference")]
    pub async fn autoload_drafter(
        &self,
        target_model_id: &str,
        entry: &tenzro_model::HfModelEntry,
    ) -> &'static str {
        if entry.mtp_kind == MtpKind::None {
            return "none";
        }
        let Some(drafter_id) = entry.drafter_id.as_deref() else {
            return "inline";
        };
        let Some(runtime) = self.model_runtime.clone() else {
            return "drafter_unavailable";
        };
        if runtime.has_drafter(target_model_id) {
            return "drafter_loaded";
        }
        let Some(drafter_entry) = tenzro_model::get_model_by_id(drafter_id) else {
            warn!(
                target = %target_model_id,
                drafter = %drafter_id,
                "Catalog declares a drafter that does not resolve — serving without MTP",
            );
            return "drafter_unavailable";
        };

        if let Some(path) = self.resolve_gguf_path(drafter_id) {
            return match runtime
                .load_drafter(target_model_id, &path, Some(drafter_entry.context_length))
                .await
            {
                Ok(()) => {
                    info!(
                        target = %target_model_id,
                        drafter = %drafter_id,
                        "Loaded MTP drafter for speculative decoding",
                    );
                    "drafter_loaded"
                }
                Err(e) => {
                    warn!(
                        target = %target_model_id,
                        drafter = %drafter_id,
                        "MTP drafter load failed: {} — serving without speculative decoding",
                        e,
                    );
                    "drafter_load_failed"
                }
            };
        }

        // Not on disk: serve without it. This used to start a background
        // download and load the drafter when it landed, which raced the
        // target's own load — the runtime picks serial or batched at load
        // from what is on disk at that moment, so a drafter arriving later
        // either could not attach (batched target) or, worse, attached to a
        // serial target whose advertised concurrency was already computed
        // without it. Placing a drafter is an operator act: download it, then
        // re-serve the target.
        warn!(
            target = %target_model_id,
            drafter = %drafter_id,
            "Catalog pairs this model with an MTP drafter that is not on disk — serving batched \
             without speculative decoding. To enable it: `tenzro model download {drafter_id}` and \
             re-serve {target_model_id}.",
        );
        "drafter_not_on_disk"
    }

    /// Evict Local ModelServiceInstance entries whose model is no longer loaded
    /// in the runtime AND have been idle (no `last_seen` update) for >= 1 hour.
    ///
    /// A model is considered "live" when `ModelRuntime::is_loaded()` returns true.
    /// If a local service still has a live runtime, its last_seen is refreshed
    /// (treated as liveness heartbeat). Otherwise, if it has been silent for
    /// more than 1 hour, the entry is removed from CF_MODEL_SERVICES and the
    /// served_models flag in CF_MODELS is cleared as well.
    ///
    /// Returns `(evicted_instance_count, cleared_served_models_count)` so
    /// callers (including the `tenzro_cleanupIdleLocalModelServices` RPC
    /// handler) can report how much state was reclaimed. The periodic
    /// EventLoop heartbeat also exercises this same logic inline; this
    /// method is the operator-callable on-demand entry point.
    pub fn cleanup_idle_local_model_services(&self) -> (usize, usize) {
        const IDLE_TTL_SECS: u64 = 3600; // 1 hour

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect candidates first to avoid holding DashMap refs across mutations
        let local_entries: Vec<(String, String, u64)> = self
            .model_services
            .iter()
            .filter(|e| {
                matches!(
                    e.value().location,
                    tenzro_types::model::ModelLocation::Local
                )
            })
            .map(|e| {
                (
                    e.key().clone(),
                    e.value().model_id.clone(),
                    e.value().last_seen,
                )
            })
            .collect();

        let mut evicted_instances: Vec<String> = Vec::new();
        let mut cleared_served: Vec<String> = Vec::new();

        for (instance_id, model_id, last_seen) in local_entries {
            let runtime_loaded = self.runtime_has_loaded(&model_id);

            if runtime_loaded {
                // Live — refresh last_seen as a heartbeat so idle timer is bound
                // to the most recent successful liveness check, not registration.
                if let Some(mut svc) = self.model_services.get_mut(&instance_id)
                    && svc.last_seen < now
                {
                    svc.last_seen = now;
                    if let Some(ref storage) = self.storage
                        && let Ok(data) = serde_json::to_vec(svc.value())
                    {
                        let _ = storage.put(CF_MODEL_SERVICES, instance_id.as_bytes(), &data);
                    }
                }
                continue;
            }

            // Runtime is not serving this model. If the entry has been silent
            // for >= IDLE_TTL_SECS (or has never been seen), evict it.
            let idle = last_seen == 0 || now.saturating_sub(last_seen) >= IDLE_TTL_SECS;
            if idle {
                self.model_services.remove(&instance_id);
                if let Some(ref storage) = self.storage {
                    let _ = storage.delete(CF_MODEL_SERVICES, instance_id.as_bytes());
                }
                evicted_instances.push(instance_id.clone());

                // If no other Local instance still exists for this model, clear
                // the served_models flag as well (CF_MODELS).
                let still_served_locally = self.model_services.iter().any(|e| {
                    e.value().model_id == model_id
                        && matches!(
                            e.value().location,
                            tenzro_types::model::ModelLocation::Local,
                        )
                });
                if !still_served_locally {
                    self.served_models.remove(&model_id);
                    self.load_tracker.unregister_model(&model_id);
                    if let Some(ref storage) = self.storage {
                        let _ =
                            storage.delete(CF_MODELS, format!("served:{}", model_id).as_bytes());
                    }
                    cleared_served.push(model_id);
                }
            }
        }

        if !evicted_instances.is_empty() {
            info!(
                "Evicted {} idle local model service(s); cleared {} served_models flag(s)",
                evicted_instances.len(),
                cleared_served.len(),
            );
        }
        (evicted_instances.len(), cleared_served.len())
    }

    /// Whether a served model runs on the serial single-context path: it
    /// loaded a multimodal projector, or it will speculate — an inline MTP
    /// head, or a separate drafter that is on disk now and will be attached.
    /// A catalog pairing whose drafter is absent does not count: the runtime
    /// serves that model through the batching engine and never attaches a
    /// drafter to it (`ModelRuntime::load_model_with_context` applies the
    /// same rule from the same evidence).
    #[cfg(feature = "inference")]
    pub fn serving_path_is_serial(&self, entry: &tenzro_model::HfModelEntry) -> bool {
        let drafter_on_disk = entry
            .drafter_id
            .as_deref()
            .is_some_and(|d| self.resolve_gguf_path(d).is_some());
        let speculates = entry.mtp_kind != tenzro_model::MtpKind::None
            && (entry.drafter_id.is_none() || drafter_on_disk);
        // The same rule the runtime loads by (`prefers_speculation`). A
        // projector no longer forces the serial path: the batching engine
        // prefills media per sequence.
        speculates && tenzro_model::runtime::prefers_speculation()
    }

    /// The most requests a served model can really run at once: one on the
    /// serial path, the slot budget on the continuous-batching engine. Every
    /// site that registers a model's concurrency — the boot path, `tenzro
    /// model serve` over RPC, and MCP — caps with this, so they cannot
    /// disagree about a model's capacity the way they once did.
    #[cfg(feature = "inference")]
    pub fn serving_capacity_cap(&self, entry: &tenzro_model::HfModelEntry) -> u32 {
        if self.serving_path_is_serial(entry) {
            1
        } else {
            tenzro_model::max_slots() as u32
        }
    }

    /// Register a served model with the load tracker, sizing max-concurrency
    /// against detected hardware. Shared by the serve path and the lazy loader
    /// so the concurrency budget is computed identically everywhere.
    #[cfg(feature = "inference")]
    pub(crate) async fn register_load_tracker(
        &self,
        model_id: &str,
        entry: &tenzro_model::HfModelEntry,
    ) {
        // The hardware profile is populated lazily by the first probe, so it is
        // routinely absent here: a model reloaded at boot, or lazily loaded on
        // first use, registers before anything has measured the machine.
        //
        // Assuming a 4 GB, GPU-less host in that window is not a conservative
        // default, it is a wrong one that never gets revisited — the estimate
        // is cached as the model's permanent concurrency cap. On this class of
        // box it resolves to a single slot for a model the machine can serve
        // dozens of, and every concurrent request after the first is refused
        // with "node at capacity: 1 of 1" while the node reports 40 free.
        //
        // Measure instead, and cache the reading the same way
        // `validate_role_capability` does, so the first caller to need a
        // profile pays for it once and every later one reads it.
        let profile = {
            let measured = self.hardware_profile.read().clone();
            match measured {
                Some(hw) => Some(hw),
                None => match detect_hardware(&self.config.data_dir).await {
                    Ok(hw) => {
                        *self.hardware_profile.write() = Some(hw.clone());
                        Some(hw)
                    }
                    Err(e) => {
                        warn!(
                            model_id = %model_id,
                            error = %e,
                            "Hardware probe failed while sizing concurrency; \
                             falling back to a single slot for this model",
                        );
                        None
                    }
                },
            }
        };

        let mem_max_concurrent = match profile {
            Some(profile) => {
                let gpu_vram = profile
                    .gpus
                    .first()
                    .map(|g| g.vram_gb as f64)
                    .unwrap_or(0.0);
                let has_gpu = !profile.gpus.is_empty() && gpu_vram > 0.0;
                tenzro_model::estimate_max_concurrent(
                    entry.min_ram_gb,
                    profile.total_ram_gb,
                    gpu_vram,
                    has_gpu,
                )
            }
            // Only reached when the probe itself failed, which is a real fault
            // rather than a timing window: serve one at a time until it works.
            None => 1,
        };
        // Cap the advertised/admitted concurrency at the serving path's REAL
        // concurrent capacity, not just what memory allows. A model that loads
        // a multimodal projector or an MTP drafter is served on the single-
        // mutex serial path (one decode at a time); everything else is served
        // through the continuous-batching engine with `max_slots` KV sequence
        // slots. Advertising the memory estimate (up to 32) for a serial model
        // admits a flood that then piles behind one mutex — each a full
        // generation — which presents as a stall/wedge under load. Admitting
        // real capacity sheds the surplus with a fast "retry later" instead.
        let is_serial = self.serving_path_is_serial(entry);
        let capacity_cap = self.serving_capacity_cap(entry);
        let max_concurrent = mem_max_concurrent.min(capacity_cap).max(1);
        info!(
            model_id = %model_id,
            max_concurrent,
            mem_max_concurrent,
            serving_path = if is_serial { "serial" } else { "batched" },
            "Registered per-model concurrency cap (real serving capacity)",
        );
        self.load_tracker.register_model(model_id, max_concurrent);
    }

    /// Load a served model into the runtime on demand.
    ///
    /// Serving weights are loaded lazily on the first inference rather than at
    /// boot, so a node's boot-time RAM is independent of how many models it
    /// holds. A holder that never receives an inference request keeps its
    /// models purely on disk. Idempotent: a no-op when already loaded.
    ///
    /// Returns `Ok(true)` when the model is loaded and ready, `Ok(false)` when
    /// it is not a locally-servable model on this node (caller falls back to
    /// remote routing or a not-serving error), and `Err` when a load was
    /// attempted and failed (e.g. memory admission).
    #[cfg(feature = "inference")]
    pub async fn ensure_local_model_loaded(
        &self,
        model_id: &str,
    ) -> std::result::Result<bool, String> {
        let Some(runtime) = self.model_runtime.as_ref() else {
            return Ok(false);
        };
        if runtime.is_loaded(model_id) {
            return Ok(true);
        }
        // Only load models this node has flagged as served.
        if !self.served_models.contains_key(model_id) {
            return Ok(false);
        }
        let Some(entry) = tenzro_model::get_model_by_id(model_id) else {
            return Ok(false);
        };
        let Some(path) = self.resolve_gguf_path(model_id) else {
            return Ok(false);
        };
        // Refused, or discarded on install, when the operator stops the model
        // while this request waits on the load: the stop wins.
        runtime
            .load_model_with_context(model_id, &path, Some(entry.context_length))
            .await
            .map_err(|e| e.to_string())?;
        // A stop that landed after the install has unloaded it again and
        // unregistered the tracker; registering it here would undo that.
        if !runtime.is_loaded(model_id) || !self.served_models.contains_key(model_id) {
            return Ok(false);
        }
        self.register_load_tracker(model_id, &entry).await;
        let _ = self.autoload_drafter(model_id, &entry).await;
        info!(model_id = %model_id, "Lazily loaded served model on first use");
        Ok(true)
    }

    /// Save the provider schedule so its model stacks survive a restart.
    ///
    /// Returns `Ok(false)` when this node has no storage to save into, and an
    /// error when the write failed, so the caller can tell the operator the
    /// schedule would not outlive the process.
    pub fn persist_provider_schedule(
        &self,
        schedule: &ProviderSchedule,
    ) -> std::result::Result<bool, String> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(false);
        };
        let bytes = serde_json::to_vec(schedule).map_err(|e| e.to_string())?;
        storage
            .put(CF_MODELS, PROVIDER_SCHEDULE_KEY, &bytes)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// Load the saved provider schedule into the node, before the residency
    /// loop first runs, so the active window's stack is loaded at startup.
    fn restore_provider_schedule(&self) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        match storage.get(CF_MODELS, PROVIDER_SCHEDULE_KEY) {
            Ok(Some(bytes)) => match serde_json::from_slice::<ProviderSchedule>(&bytes) {
                Ok(schedule) => {
                    info!(
                        stacks = schedule.windows.len(),
                        "Restored the provider schedule and its model stacks"
                    );
                    *self.provider_schedule.write() = schedule;
                }
                Err(e) => warn!(error = %e, "Saved provider schedule is unreadable; not applied"),
            },
            Ok(None) => {}
            Err(e) => warn!(error = %e, "Could not read the saved provider schedule"),
        }
    }

    /// Save the operator's price card so it outlives a restart. `Ok(false)`
    /// when this node has no storage to save into.
    pub fn persist_provider_pricing(
        &self,
        pricing: &ProviderPricing,
    ) -> std::result::Result<bool, String> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(false);
        };
        let bytes = serde_json::to_vec(pricing).map_err(|e| e.to_string())?;
        storage
            .put(CF_MODELS, PROVIDER_PRICING_KEY, &bytes)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }

    /// The price cards the operator last saved; None when none were saved.
    pub fn saved_provider_pricing(storage: &dyn KvStore) -> Option<ProviderPricing> {
        match storage.get(CF_MODELS, PROVIDER_PRICING_KEY) {
            Ok(Some(bytes)) => match serde_json::from_slice::<ProviderPricing>(&bytes) {
                Ok(pricing) => Some(pricing),
                Err(e) => {
                    warn!(error = %e, "Saved provider pricing is unreadable; the configured pricing applies");
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "Could not read the saved provider pricing");
                None
            }
        }
    }

    /// Load the saved price card over the configured one.
    fn restore_provider_pricing(&self) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        if let Some(pricing) = Self::saved_provider_pricing(storage.as_ref()) {
            info!("Restored the operator's provider pricing");
            *self.provider_pricing.write() = pricing;
        }
    }

    /// The `CF_MODELS` key recording that `model_id` was offloaded.
    pub fn offload_key(model_id: &str) -> Vec<u8> {
        format!("{OFFLOAD_PREFIX}{model_id}").into_bytes()
    }

    /// Whether the operator has offloaded this model.
    pub fn is_offloaded(&self, model_id: &str) -> bool {
        self.storage
            .as_ref()
            .and_then(|s| {
                s.get(CF_MODELS, &Self::offload_key(model_id))
                    .ok()
                    .flatten()
            })
            .is_some()
    }

    /// Record that the operator offloaded this model.
    ///
    /// Written *before* the model is unloaded, deliberately. The expensive,
    /// interruptible work — unloading weights, deregistering services, deleting
    /// rows — all happens after, so a crash at any point in it leaves a node
    /// that still knows the operator said stop. The reverse order loses the
    /// decision precisely when something went wrong, which is when it matters.
    pub fn record_offload(&self, model_id: &str, reason: &str) {
        if let Some(storage) = self.storage.as_ref() {
            let record = serde_json::json!({
                "model_id": model_id,
                "reason": reason,
                "at": chrono::Utc::now().to_rfc3339(),
            });
            match storage.put(
                CF_MODELS,
                &Self::offload_key(model_id),
                &serde_json::to_vec(&record).unwrap_or_default(),
            ) {
                Ok(()) => tracing::info!(
                    model_id,
                    reason,
                    "Offload recorded; it will survive restarts"
                ),
                Err(e) => tracing::warn!(
                    model_id,
                    error = %e,
                    "Could not record the offload — it will not survive a restart"
                ),
            }
        }
    }

    /// Forget an offload, because the operator asked for this model again.
    ///
    /// The only thing that clears it. An explicit serve is a newer decision by
    /// the same authority, so it wins; nothing automatic does.
    pub fn clear_offload(&self, model_id: &str) {
        if let Some(storage) = self.storage.as_ref()
            && self.is_offloaded(model_id)
        {
            let _ = storage.delete(CF_MODELS, &Self::offload_key(model_id));
            tracing::info!(
                model_id,
                "Offload cleared: the operator is serving this again"
            );
        }
    }

    pub async fn reconcile_model_registry(&self) -> (usize, usize, usize) {
        use tenzro_model::get_model_by_id;

        let mut reloaded: usize = 0;
        let mut cleared_models: usize = 0;
        let mut cleared_services: usize = 0;

        // Snapshot the served_models keys to avoid holding a DashMap iterator
        // while we mutate the map.
        //
        // Anything the operator offloaded is dropped from the snapshot rather
        // than reloaded. This runs at startup *and* on demand via
        // `tenzro model prune`, so without the check an offload survives
        // exactly until the next reconcile — which is worse than not being
        // honoured at all, because it looks like it worked.
        let served_ids: Vec<String> = self
            .served_models
            .iter()
            .map(|e| e.key().clone())
            // A connector model has no weights on this machine to check.
            .filter(|id| self.upstream_model(id).is_none())
            .filter(|id| {
                let suppressed = self.is_offloaded(id);
                if suppressed {
                    self.served_models.remove(id);
                    tracing::info!(model_id = %id, "Reconcile: staying offloaded by operator");
                }
                !suppressed
            })
            .collect();

        for model_id in &served_ids {
            // A multi-modal model has no GGUF, so the reload below would find
            // "no file", clear its serve flag and delete the row that records
            // how to load it. It is restored from that row once the node is
            // shared (`rpc::restore_multimodal_models`).
            let multimodal = self.storage.as_ref().is_some_and(|storage| {
                storage
                    .get(CF_MODELS, format!("served:{}", model_id).as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .is_some_and(|rec| rec.get("runtime").and_then(|v| v.as_str()).is_some())
            });
            if multimodal {
                continue;
            }

            let catalog = get_model_by_id(model_id);

            let gguf_path = self.resolve_gguf_path(model_id);

            let ok = match (catalog, gguf_path) {
                (Some(entry), Some(path)) => {
                    // Catalog entry + file present on disk. Keep the serve flag
                    // and register the load tracker, but do NOT warm the weights
                    // into the runtime here — the llama.cpp load is deferred to
                    // the first inference via `ensure_local_model_loaded`, so a
                    // node's boot RAM does not scale with the number of held
                    // models. A holder that never serves keeps them on disk.
                    #[cfg(feature = "inference")]
                    {
                        if self.model_runtime.is_some() {
                            self.register_load_tracker(model_id, &entry).await;
                            reloaded += 1;
                            info!(
                                model_id = %model_id,
                                path = %path.display(),
                                "Reconciled served model (weights load lazily on first use)",
                            );
                            true
                        } else {
                            // No runtime available at all — can't serve. Keep file,
                            // but don't keep the flag advertising we serve it.
                            warn!(
                                model_id = %model_id,
                                "ModelRuntime not initialized — clearing serve flag",
                            );
                            false
                        }
                    }
                    // The light build runs no model: the flag cannot be served.
                    #[cfg(not(feature = "inference"))]
                    {
                        let _ = (entry, path);
                        warn!(
                            model_id = %model_id,
                            "This light build runs no model — clearing serve flag",
                        );
                        false
                    }
                }
                (None, _) => {
                    warn!(
                        model_id = %model_id,
                        "Served model not found in catalog — clearing serve flag",
                    );
                    false
                }
                (_, None) => {
                    warn!(
                        model_id = %model_id,
                        "GGUF file missing for served model — clearing serve flag",
                    );
                    false
                }
            };

            if !ok {
                self.served_models.remove(model_id);
                self.load_tracker.unregister_model(model_id);
                if let Some(ref storage) = self.storage {
                    let _ = storage.delete(CF_MODELS, format!("served:{}", model_id).as_bytes());
                }
                // A hydrated ModelRegistry row from the previous process
                // lifetime would still say Active — flip it so routing stops
                // considering a model this node can no longer serve.
                if let Some(ref registry) = self.model_registry {
                    let _ = registry.deactivate_model(model_id);
                }
                cleared_models += 1;

                // Also clear any matching ModelServiceInstance rows for this model
                let svc_ids: Vec<String> = self
                    .model_services
                    .iter()
                    .filter(|e| e.value().model_id == *model_id)
                    .map(|e| e.key().clone())
                    .collect();
                for id in &svc_ids {
                    self.model_services.remove(id);
                    if let Some(ref storage) = self.storage {
                        let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
                    }
                    cleared_services += 1;
                }
            }
        }

        // Second pass: drop any orphaned Local ModelServiceInstance rows whose
        // model is not loaded and is no longer in served_models.
        let orphans: Vec<String> = self
            .model_services
            .iter()
            .filter(|e| {
                let svc = e.value();
                if !matches!(svc.location, tenzro_types::model::ModelLocation::Local) {
                    return false;
                }
                let loaded = self.runtime_has_loaded(&svc.model_id);
                let flagged = self.served_models.contains_key(&svc.model_id);
                !loaded && !flagged
            })
            .map(|e| e.key().clone())
            .collect();

        for id in &orphans {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
            cleared_services += 1;
            info!("Removed orphaned local model service: {}", id);
        }

        if reloaded > 0 || cleared_models > 0 || cleared_services > 0 {
            info!(
                "Model registry reconcile complete: reloaded={} cleared_models={} cleared_services={}",
                reloaded, cleared_models, cleared_services,
            );
        }

        // Register THIS node as a provider for its locally-served models in the
        // inference router, so intent-based competition dispatch
        // (tenzro_chatByIntent / `inference route --message`) can route to the
        // local models — not just direct tenzro_chat. Without this a
        // local/single-node deploy resolves the model (discovery) but hits
        // "no healthy provider" at dispatch. One provider entry (this node's
        // address) carries every served model; upserted so repeat reconciles
        // refresh the list.
        if let (Some(pm), Some(local_addr)) = (
            self.provider_manager.as_ref(),
            self.local_validator_address(),
        ) {
            let served: Vec<String> = self.served_models.iter().map(|e| e.key().clone()).collect();
            if !served.is_empty() {
                let local_addr = *local_addr;
                let mut provider =
                    tenzro_types::model::InferenceProvider::new(local_addr, "local".to_string());
                provider.status = tenzro_types::model::ProviderStatus::Active;
                provider.models = served;
                provider.endpoint_url = Some("http://127.0.0.1:8545/v1".to_string());
                let res = if pm.get_provider(&local_addr).is_ok() {
                    pm.update_provider(provider)
                } else {
                    pm.register_provider(provider, false)
                };
                match res {
                    Ok(()) => {
                        // Mark healthy now — a provider is only returned by
                        // get_active_providers_for_model if it has a recent
                        // heartbeat. Local serving has no gossip heartbeat, so we
                        // beat it here (and again in the 60s announce loop) to
                        // keep it inside the 5-minute freshness window.
                        let _ = pm.heartbeat(&local_addr);
                    }
                    Err(e) => {
                        warn!("Failed to register local node as inference provider: {}", e);
                    }
                }
            }
        }

        (reloaded, cleared_models, cleared_services)
    }

    /// Refresh the `last_seen` timestamp of every Local ModelServiceInstance
    /// for the given model_id. Called from the tenzro_chat handler after a
    /// successful local inference so the 1-hour idle TTL is bound to actual
    /// usage, not registration time.
    pub fn touch_local_model_service(&self, model_id: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ids: Vec<String> = self
            .model_services
            .iter()
            .filter(|e| {
                e.value().model_id == model_id
                    && matches!(
                        e.value().location,
                        tenzro_types::model::ModelLocation::Local,
                    )
            })
            .map(|e| e.key().clone())
            .collect();

        for id in ids {
            if let Some(mut svc) = self.model_services.get_mut(&id) {
                svc.last_seen = now;
                if let Some(ref storage) = self.storage
                    && let Ok(data) = serde_json::to_vec(svc.value())
                {
                    let _ = storage.put(CF_MODEL_SERVICES, id.as_bytes(), &data);
                }
            }
        }
    }

    /// List all model service instances
    pub fn list_model_services(&self) -> Vec<ModelServiceInstance> {
        self.model_services
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get a model service instance by instance_id
    pub fn get_model_service(&self, instance_id: &str) -> Option<ModelServiceInstance> {
        self.model_services
            .get(instance_id)
            .map(|entry| entry.value().clone())
    }

    /// Find a model service instance by model_id (returns first match)
    pub fn find_model_service_by_model_id(&self, model_id: &str) -> Option<ModelServiceInstance> {
        self.model_services
            .iter()
            .find(|entry| entry.value().model_id == model_id)
            .map(|entry| entry.value().clone())
    }

    /// Find a model service instance by model_id whose provider is not
    /// `exclude`. Used by the streaming re-prefill failover path to pick a
    /// different provider than the one that just dropped mid-stream.
    pub fn find_model_service_excluding(
        &self,
        model_id: &str,
        exclude: &tenzro_types::primitives::Address,
    ) -> Option<ModelServiceInstance> {
        self.model_services
            .iter()
            .find(|entry| {
                let svc = entry.value();
                svc.model_id == model_id && &svc.provider_address != exclude
            })
            .map(|entry| entry.value().clone())
    }
}

/// History kept to the retention window and deleted below it, on a node
/// with no DA layer to hand it to.
fn local_history(
    storage: &Arc<RocksDbStore>,
    consensus: &Arc<crate::consensus_driver::ConsensusHandle>,
) -> Option<Arc<crate::history_archive::HistoryArchive>> {
    crate::history_archive::HistoryArchive::local(
        storage.clone(),
        consensus.clone() as Arc<dyn crate::history_archive::CertifiedCheckpoints>,
    )
    .inspect_err(
        |e| warn!(error = %e, "History retention unavailable: block history is kept in full"),
    )
    .ok()
    .map(Arc::new)
}

/// Submits a `ReportCheckpointEquivocation` transaction carrying `evidence`
/// from the account of the node's hybrid signer, into the local mempool.
fn report_checkpoint_equivocation(
    consensus: &Arc<ConsensusHandle>,
    signer: &Arc<dyn tenzro_crypto::composite::HybridSigner>,
    storage: &Arc<RocksDbStore>,
    chain_id: u64,
    nonces: &crate::payment_rails::NonceReservation,
    gossip: &crate::payment_rails::GossipSlot,
    evidence: Vec<u8>,
) -> Result<()> {
    submit_validator_transaction(
        consensus,
        signer,
        storage,
        chain_id,
        nonces,
        gossip,
        tenzro_types::transaction::TransactionType::ReportCheckpointEquivocation { evidence },
        200_000,
    )
    .map(|_| ())
}

/// Submits `tx_type` from the account of the node's hybrid signer into the
/// local mempool, numbered and admitted by the account's one allocator, and
/// gossips it. Returns the nonce used, or `None` while the ML-DSA-65 key of
/// the account is not enrolled yet (its enrolment is on its way; nothing
/// else is admitted from the account before it has executed).
pub(crate) fn submit_validator_transaction(
    consensus: &Arc<ConsensusHandle>,
    signer: &Arc<dyn tenzro_crypto::composite::HybridSigner>,
    storage: &Arc<RocksDbStore>,
    chain_id: u64,
    nonces: &crate::payment_rails::NonceReservation,
    gossip: &crate::payment_rails::GossipSlot,
    tx_type: tenzro_types::transaction::TransactionType,
    gas_limit: u64,
) -> Result<Option<u64>> {
    // Every account transaction carries the ML-DSA-65 leg, checked against
    // the key the account enrolled. The first transaction of a validator
    // account is the enrolment of its hardware ML-DSA-65 key; nothing else
    // is admitted from it until that has executed.
    let kv: Arc<dyn KvStore> = storage.clone();
    if !ensure_pq_key_enrolled(consensus, signer, &kv, chain_id, nonces, gossip)? {
        return Ok(None);
    }
    let address = Address::new(signer.public_key().account_slot());
    // A record the protocol asks for pays no fee, so it names no gas price
    // and needs nothing in the account.
    let gas_price = if tx_type.pays_no_fee() {
        0
    } else {
        consensus.node_tx_gas_price()
    };
    let (nonce, signed) = nonces.admit_next(
        consensus,
        storage.clone() as Arc<dyn KvStore>,
        &address,
        |nonce| {
            let signed = sign_validator_transaction(
                signer.as_ref(),
                chain_id,
                nonce,
                tx_type,
                gas_limit,
                gas_price,
            )?;
            consensus.submit_transaction(signed.clone())?;
            Ok::<_, NodeError>((nonce, signed))
        },
    )?;
    crate::payment_rails::gossip_admitted(gossip, signed);
    Ok(Some(nonce))
}

/// Whether the ML-DSA-65 key of `signer` is the one enrolled for its account
/// on chain. When none is enrolled, submits the enrolment (proof of
/// possession by that key, signed with both legs, paid for like any other
/// transaction of the account) at most once per retry interval, and returns
/// false until it has executed. A different key enrolled is an error: only
/// the key holder rotates it.
pub(crate) fn ensure_pq_key_enrolled(
    consensus: &Arc<ConsensusHandle>,
    signer: &Arc<dyn tenzro_crypto::composite::HybridSigner>,
    storage: &Arc<dyn KvStore>,
    chain_id: u64,
    nonces: &crate::payment_rails::NonceReservation,
    gossip: &crate::payment_rails::GossipSlot,
) -> Result<bool> {
    use tenzro_crypto::composite::SignatureContext;
    use tenzro_types::account_signature::{AccountKeysOp, pq_enrollment_message};

    let public = signer.public_key();
    let key = public.pq.clone().ok_or_else(|| {
        NodeError::Config("the validator account signer has no ML-DSA-65 key".to_string())
    })?;
    let state = tenzro_vm::StateAdapter::with_storage(storage.clone());
    match tenzro_vm::account_keys::enrolled_pq_key(&state, &public.p256) {
        Some(enrolled) if enrolled == key => return Ok(true),
        Some(_) => {
            return Err(NodeError::Config(
                "the validator account has another ML-DSA-65 key enrolled than its signer holds"
                    .to_string(),
            ));
        }
        None => {}
    }
    // An enrolment of this key already waiting in the mempool is not
    // submitted again: while the chain makes no blocks (no quorum yet) it
    // cannot execute, and each further copy would only take the next nonce.
    let address = Address::new(public.account_slot());
    let pending = consensus.mempool().has_pending_from(&address, |s| {
        matches!(
            &s.transaction.tx_type,
            tenzro_types::transaction::TransactionType::AccountKeys {
                op: AccountKeysOp::EnrollPqKey { ml_dsa_public_key, .. },
            } if *ml_dsa_public_key == key
        )
    });
    if pending {
        if nonces.enrolment_due() {
            info!(
                "the validator account ML-DSA-65 key enrolment is submitted and waiting to execute \
                 (no block has included it yet, e.g. while waiting for quorum); not submitting another"
            );
        }
        return Ok(false);
    }
    if !nonces.enrolment_due() {
        return Ok(false);
    }
    let message = pq_enrollment_message(&public.account_slot(), &key);
    let possession = signer
        .sign(SignatureContext::PqKeyEnrollment, &message)
        .map_err(|e| NodeError::Other(format!("signing the key enrolment: {e}")))?
        .pq
        .ok_or_else(|| {
            NodeError::Other("the signer produced no ML-DSA-65 signature".to_string())
        })?;
    let gas_price = consensus.node_tx_gas_price();
    let (nonce, signed) = nonces.admit_next(consensus, storage.clone(), &address, |nonce| {
        let signed = sign_validator_transaction(
            signer.as_ref(),
            chain_id,
            nonce,
            tenzro_types::transaction::TransactionType::AccountKeys {
                op: AccountKeysOp::EnrollPqKey {
                    ml_dsa_public_key: key.clone(),
                    possession: possession.clone(),
                },
            },
            200_000,
            gas_price,
        )?;
        consensus.submit_transaction(signed.clone())?;
        Ok::<_, NodeError>((nonce, signed))
    })?;
    info!(nonce, "enrolling the validator account ML-DSA-65 key");
    crate::payment_rails::gossip_admitted(gossip, signed);
    Ok(false)
}

/// A transaction from the validator's own account, signed with its keys. The
/// account is the one that commits to both keys: the one its genesis entry
/// and self-stake name, which holds its funds, and the one the signatures
/// prove control of.
pub(crate) fn sign_validator_transaction(
    signer: &dyn tenzro_crypto::composite::HybridSigner,
    chain_id: u64,
    nonce: u64,
    tx_type: tenzro_types::transaction::TransactionType,
    gas_limit: u64,
    gas_price: u64,
) -> Result<tenzro_types::transaction::SignedTransaction> {
    use tenzro_types::primitives::{ChainId, Nonce};
    use tenzro_types::transaction::{SignedTransaction, Transaction};

    let tx = Transaction::new(
        ChainId::from(chain_id),
        Address::new(signer.public_key().account_slot()),
        Address::new([0u8; 32]),
        Nonce::from(nonce),
        tx_type,
        gas_limit,
        gas_price,
    );
    let signature = signer
        .sign(
            tenzro_crypto::composite::SignatureContext::Transaction,
            tx.hash().as_bytes(),
        )
        .map_err(|e| NodeError::Other(format!("signing a validator transaction: {e}")))?;
    Ok(SignedTransaction::new(
        tx,
        signer.public_key().p256.clone(),
        signature,
    ))
}

/// Detect hardware profile of the current system
pub async fn detect_hardware(data_dir: &std::path::Path) -> Result<HardwareProfile> {
    use sysinfo::{Disks, System};

    // Initialize system info
    let mut sys = System::new_all();
    sys.refresh_all();

    // CPU info
    let cpu_model = sys
        .cpus()
        .first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());
    let cpu_cores = sys.physical_core_count().unwrap_or(1);
    let cpu_threads = sys.cpus().len();

    // RAM info (convert bytes to GB)
    let total_ram_gb = sys.total_memory() as f64 / 1_073_741_824.0; // 1024^3

    // Storage info
    let disks = Disks::new_with_refreshed_list();
    let storage_available_gb = disks
        .iter()
        .find(|disk| data_dir.starts_with(disk.mount_point()))
        .map(|disk| disk.available_space() as f64 / 1_073_741_824.0)
        .unwrap_or(0.0);

    // OS and architecture
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    // GPU detection — shared probe (nvidia-smi / rocm-smi / Apple unified
    // memory) with vendor, compute capability, and FP8/FP4 derivation. The
    // probe shells out synchronously, so run it off the async executor.
    let gpus = tokio::task::spawn_blocking(tenzro_types::HardwareCapabilities::detect)
        .await
        .map(|caps| caps.gpus)
        .unwrap_or_default();

    // TEE detection
    let (tee_available, tee_vendor) = match detect_tee().await {
        Some(provider) => (true, Some(format!("{:?}", provider.vendor()))),
        None => (false, None),
    };

    // Per-unit hardware identity. Reads /sys/class/dmi and dlopens NVML, so
    // it runs off the async executor. Absent or root-only sources yield an
    // unrooted identity rather than an error.
    let hw_identity = tokio::task::spawn_blocking(tenzro_tee::HardwareIdentity::collect)
        .await
        .map_err(|e| NodeError::Other(format!("hardware identity probe panicked: {}", e)))?;
    let (hardware_root, hardware_root_sources) = if hw_identity.is_rooted() {
        (Some(hw_identity.root_hex()), hw_identity.sources().to_vec())
    } else {
        (None, Vec::new())
    };

    // Device fingerprint (SHA-256 hash of hardware characteristics)
    let fingerprint_input = format!(
        "{}|{}|{}|{}|{}|{}",
        cpu_model,
        cpu_cores,
        total_ram_gb as u64,
        gpus.iter()
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>()
            .join(","),
        os,
        arch
    );
    let mut hasher = Sha256::new();
    hasher.update(fingerprint_input.as_bytes());
    let device_fingerprint = format!("{:x}", hasher.finalize());

    Ok(HardwareProfile {
        cpu_model,
        cpu_cores,
        cpu_threads,
        total_ram_gb,
        gpus,
        storage_available_gb,
        tee_available,
        tee_vendor,
        os,
        arch,
        device_fingerprint,
        hardware_root,
        hardware_root_sources,
    })
}

/// Node status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub state: String,
    pub roles: RoleSet,
    pub health_status: crate::health::OverallHealth,
    pub uptime_secs: u64,
    pub block_height: u64,
    pub peer_count: u64,
    pub data_dir: PathBuf,
    /// Whether this node has a TEE provider available.
    ///
    /// All nodes participate in consensus regardless. TEE-capable nodes
    /// additionally serve confidential-compute and custodial-key
    /// workloads on behalf of non-TEE peers — peers consult this field
    /// to discover routing targets for TEE-gated requests.
    pub tee_capable: bool,
    /// TEE vendor for this node, if any (`None` on commodity hardware).
    pub tee_vendor: Option<tenzro_types::tee::TeeVendor>,
    /// Whether the iroh QUIC + Pkarr substrate is bound on this node
    /// (controlled by `NodeConfig::iroh`). When `true`, the node serves
    /// the `iroh-blobs` data plane and (for the A2A dispatcher) the
    /// `tenzro/a2a` ALPN alongside its HTTPS surfaces.
    pub iroh_enabled: bool,
    /// Iroh `EndpointId` in z-base-32 form (matches the format printed by
    /// `iroh node id`). `None` when iroh is not enabled. When the node was
    /// started with a TDIP-anchored secret key seed, the byte-decoded form
    /// of this value is identical to the node's Ed25519 validator public key.
    pub iroh_endpoint_id: Option<String>,
    /// ALPNs registered on the shared iroh router. Empty when iroh is not
    /// enabled. Includes `iroh-blobs` always; `tenzro/a2a` once the A2A
    /// dispatcher has been wired in `main.rs`.
    pub iroh_alpns: Vec<String>,
    /// GPUs present on this machine but hidden from the node by an empty
    /// device-visibility variable (`CUDA_VISIBLE_DEVICES`,
    /// `HIP_VISIBLE_DEVICES`, `ROCR_VISIBLE_DEVICES`), so its models run on
    /// the CPU. Empty when every GPU is visible or the model runtime is not up.
    pub hidden_gpus: Vec<String>,
}

/// How often a node rereads the governed gossip budgets.
const GOSSIP_LIMITS_REFRESH: std::time::Duration = std::time::Duration::from_secs(10);

/// Per-neighbour gossip budgets from the governed parameters in `state`, or
/// their registry values before the node has chain state.
fn gossip_limits(state: Option<&dyn tenzro_vm::VmState>) -> tenzro_network::GossipLimits {
    use tenzro_vm::governance as g;
    let param = |key| match state {
        Some(state) => tenzro_vm::native::network_param(state, key),
        None => g::genesis_param(key),
    };
    tenzro_network::GossipLimits {
        window: std::time::Duration::from_millis(param(g::GOSSIP_WINDOW_MS_PARAM)),
        consensus_messages: param(g::GOSSIP_CONSENSUS_MESSAGES_PARAM),
        general_messages: param(g::GOSSIP_GENERAL_MESSAGES_PARAM),
        ban: std::time::Duration::from_secs(param(g::GOSSIP_BAN_SECONDS_PARAM)),
    }
}

#[cfg(test)]
mod schedule_tests {
    use super::{ProviderSchedule, ResourceWindow};

    fn window(
        name: &str,
        start: u8,
        end: u8,
        days: [bool; 7],
        gib: u32,
        models: &[&str],
    ) -> ResourceWindow {
        ResourceWindow {
            name: name.into(),
            start_hour: start,
            end_hour: end,
            timezone: "UTC".into(),
            days_of_week: days,
            resident_ceiling_gb: gib,
            models: models.iter().map(|m| m.to_string()).collect(),
        }
    }

    const WEEKDAYS: [bool; 7] = [true, true, true, true, true, false, false];

    /// Build a window in a named IANA zone.
    fn tz_window(name: &str, start: u8, end: u8, tz: &str, models: &[&str]) -> ResourceWindow {
        let mut w = window(name, start, end, [true; 7], 100, models);
        w.timezone = tz.into();
        w
    }

    fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// The bug this fixes: `timezone` was stored and serialized but never
    /// applied, so every window was compared against a UTC clock. A Berlin
    /// window is UTC+2 in summer, so 08:00 UTC is 10:00 local — inside a
    /// 10:00-22:00 window — while a UTC comparison would call it outside.
    #[test]
    fn a_window_is_evaluated_in_its_own_timezone_not_utc() {
        let w = tz_window("media", 10, 22, "Europe/Berlin", &[]);

        // 08:00Z = 10:00 Berlin (CEST) -> inside.
        assert!(w.contains_at(utc("2026-08-27T08:00:00Z")));
        // The same instant judged as UTC would be 08:00, i.e. outside.
        assert!(!w.contains(3, 8), "sanity: 08:00 is outside 10-22");

        // 07:59Z = 09:59 Berlin -> still outside.
        assert!(!w.contains_at(utc("2026-08-27T07:59:00Z")));
    }

    /// DST is why a fixed offset is not enough. The same wall-clock window
    /// maps to a different UTC hour in January than in August.
    #[test]
    fn the_same_window_shifts_with_dst() {
        let w = tz_window("coding", 10, 22, "Europe/Berlin", &[]);

        // Winter: Berlin is UTC+1, so 09:00Z = 10:00 local -> inside.
        assert!(w.contains_at(utc("2026-01-15T09:00:00Z")));
        assert!(!w.contains_at(utc("2026-01-15T08:59:00Z")));

        // Summer: Berlin is UTC+2, so the boundary moves an hour earlier in UTC.
        assert!(w.contains_at(utc("2026-08-15T08:00:00Z")));
        assert!(!w.contains_at(utc("2026-08-15T07:59:00Z")));
    }

    /// An unparseable zone must not take the scheduler down — it falls back to
    /// UTC, which is what the field defaults to anyway.
    #[test]
    fn an_unknown_timezone_falls_back_to_utc() {
        let w = tz_window("typo", 10, 22, "Not/AZone", &[]);
        assert_eq!(w.tz(), chrono_tz::UTC);
        assert!(w.contains_at(utc("2026-08-27T10:00:00Z")));
    }

    /// `until` is what lets an app drain before a switch instead of
    /// discovering it through failures.
    #[test]
    fn ends_after_reports_the_windows_own_end() {
        let w = tz_window("coding", 0, 10, "Europe/Berlin", &[]);
        // 02:00Z = 04:00 Berlin, inside 00:00-10:00.
        let end = w.ends_after(utc("2026-08-27T02:00:00Z")).expect("active");
        // 10:00 Berlin in summer = 08:00Z.
        assert_eq!(end, utc("2026-08-27T08:00:00Z"));
    }

    #[test]
    fn ends_after_is_none_when_the_window_is_not_active() {
        let w = tz_window("media", 10, 22, "Europe/Berlin", &[]);
        assert!(w.ends_after(utc("2026-08-27T02:00:00Z")).is_none());
    }

    /// `starts_at` for the stack that runs next.
    #[test]
    fn starts_after_finds_the_next_opening() {
        let w = tz_window("media", 10, 22, "Europe/Berlin", &[]);
        // 02:00Z = 04:00 Berlin; the window opens 10:00 Berlin = 08:00Z.
        let start = w.starts_after(utc("2026-08-27T02:00:00Z")).expect("opens");
        assert_eq!(start, utc("2026-08-27T08:00:00Z"));
    }

    /// The scheduler must agree with what it advertises: whatever
    /// `next_window_at` names is what `active_window_at` will select once that
    /// instant arrives.
    #[test]
    fn next_window_matches_what_becomes_active() {
        let sched = ProviderSchedule {
            enabled: true,
            windows: vec![
                tz_window("coding", 0, 10, "Europe/Berlin", &["qwen3.8-flash-next"]),
                tz_window("media", 10, 24, "Europe/Berlin", &["ltx-2.5"]),
            ],
            ..Default::default()
        };
        let now = utc("2026-08-27T02:00:00Z"); // 04:00 Berlin -> coding
        assert_eq!(sched.active_window_at(now).unwrap().name, "coding");

        let (next, at) = sched.next_window_at(now).expect("a next window");
        assert_eq!(next.name, "media");
        assert_eq!(sched.active_window_at(at).unwrap().name, "media");
    }

    /// A stack is any number of models of any modality — nothing in the type
    /// constrains count or kind.
    #[test]
    fn a_stack_holds_any_number_and_mix_of_models() {
        let w = tz_window(
            "coding",
            0,
            10,
            "Europe/Berlin",
            &[
                "qwen3.8-flash-next",
                "muse-glimmer-30b",
                "qwen3-embedding-0.6b",
                "timesfm-2.5",
            ],
        );
        assert_eq!(w.models.len(), 4);
        let action = ProviderSchedule {
            enabled: true,
            windows: vec![w],
            ..Default::default()
        }
        .action_now(utc("2026-08-27T02:00:00Z"));
        assert_eq!(action.want_models.len(), 4);
        assert_eq!(action.active_window.as_deref(), Some("coding"));
    }

    #[test]
    fn a_daytime_window_contains_its_hours_only() {
        let w = window("workday", 9, 17, WEEKDAYS, 10, &[]);
        assert!(!w.contains(0, 8), "08:00 is before the window");
        assert!(w.contains(0, 9), "09:00 opens it");
        assert!(w.contains(0, 16), "16:00 still in");
        assert!(!w.contains(0, 17), "17:00 closes it (exclusive end)");
        assert!(!w.contains(5, 12), "Saturday is off");
    }

    #[test]
    fn a_window_that_wraps_midnight_is_handled() {
        // The off-hours case: 17:00 to 09:00 the next morning.
        let w = window("off-hours", 17, 9, WEEKDAYS, 80, &[]);
        assert!(w.contains(0, 20), "20:00 is in the evening half");
        assert!(w.contains(0, 3), "03:00 is in the morning half");
        assert!(!w.contains(0, 12), "noon is NOT off-hours");
        assert!(w.contains(0, 17), "17:00 opens it");
        assert!(!w.contains(0, 9), "09:00 closes it");
    }

    #[test]
    fn the_first_matching_window_wins() {
        // Two windows overlap at 10:00; ordering resolves it.
        let sched = ProviderSchedule {
            windows: vec![
                window("early", 8, 12, WEEKDAYS, 40, &["qwen"]),
                window("all-day", 0, 24, WEEKDAYS, 20, &["gemma"]),
            ],
            ..Default::default()
        };
        // 10:00 UTC on a Monday; both windows are UTC so the clock is direct.
        let active = sched
            .active_window_at(utc("2026-08-24T10:00:00Z"))
            .expect("10:00 matches");
        assert_eq!(active.name, "early", "first match wins, not all-day");
    }

    #[test]
    fn action_sets_the_ceiling_and_models_of_the_active_window() {
        let sched = ProviderSchedule {
            windows: vec![window(
                "off-hours",
                17,
                9,
                WEEKDAYS,
                80,
                &["qwen3.8-27b", "muse-glimmer-30b"],
            )],
            ..Default::default()
        };

        // 20:00 Monday → off-hours active.
        let a = sched.action_now(utc("2026-08-24T20:00:00Z"));
        assert_eq!(a.active_window.as_deref(), Some("off-hours"));
        assert_eq!(a.resident_ceiling_bytes, Some(80 * 1024 * 1024 * 1024));
        assert_eq!(a.want_models, vec!["qwen3.8-27b", "muse-glimmer-30b"]);
    }

    #[test]
    fn no_active_window_returns_to_the_base_default() {
        // A schedule whose only window is off-hours; at noon nothing is active,
        // so the ceiling returns to default (None) and no models are pinned.
        let sched = ProviderSchedule {
            windows: vec![window("off-hours", 17, 9, WEEKDAYS, 80, &["qwen"])],
            ..Default::default()
        };
        let a = sched.action_now(utc("2026-08-24T12:00:00Z"));
        assert_eq!(a.active_window, None);
        assert_eq!(
            a.resident_ceiling_bytes, None,
            "no window = base default ceiling"
        );
        assert!(a.want_models.is_empty());
    }

    #[test]
    fn a_schedule_with_no_windows_pins_nothing() {
        // No windows at all: the action is always the base default, so a node
        // that has not configured stacks keeps whatever residency it had.
        let sched = ProviderSchedule::default();
        assert!(sched.windows.is_empty());
        let a = sched.action_now(utc("2026-08-26T14:00:00Z"));
        assert_eq!(a.resident_ceiling_bytes, None);
        assert_eq!(a.active_window, None);
    }
}

#[cfg(test)]
mod schedule_capacity_tests {
    use super::*;

    fn window(name: &str, ceiling_gb: u32, models: &[&str]) -> ResourceWindow {
        ResourceWindow {
            name: name.to_string(),
            start_hour: 0,
            end_hour: 24,
            timezone: "UTC".to_string(),
            days_of_week: [true; 7],
            resident_ceiling_gb: ceiling_gb,
            models: models.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A schedule judged against the shipped catalogue: a node installs the
    /// catalogue its publishers signed, so a test installs the seed first.
    fn schedule(windows: Vec<ResourceWindow>) -> ProviderSchedule {
        tenzro_catalog::install_test_seed();
        ProviderSchedule {
            enabled: true,
            windows,
            ..Default::default()
        }
    }

    #[test]
    fn a_window_that_fits_is_accepted() {
        // granite4-1b declares 2 GiB; 8 is ample.
        let s = schedule(vec![window("small", 8, &["granite4-1b"])]);
        assert!(s.overcommitted_windows().is_empty());
    }

    #[test]
    fn a_window_that_cannot_fit_is_reported() {
        // The real shape of the bug: a ceiling far below what the members need.
        let s = schedule(vec![window("tight", 1, &["granite4-1b"])]);
        let over = s.overcommitted_windows();
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].window, "tight");
        assert!(over[0].required_gb > over[0].ceiling_gb as u64);
    }

    #[test]
    fn an_unknown_id_is_reported_not_silently_counted_as_zero() {
        // A typo must not make an over-committed window look like it fits.
        let s = schedule(vec![window("typo", 1, &["granite4-1b", "granite4-1bb"])]);
        let over = s.overcommitted_windows();
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].unknown, vec!["granite4-1bb".to_string()]);
    }

    #[test]
    fn a_window_with_no_ceiling_is_not_judged() {
        // 0 means "unset", not "no room" — judging it would refuse every
        // schedule written before ceilings existed.
        let s = schedule(vec![window("unset", 0, &["granite4-1b"])]);
        assert!(s.overcommitted_windows().is_empty());
    }

    #[test]
    fn an_empty_window_is_not_judged() {
        let s = schedule(vec![window("empty", 4, &[])]);
        assert!(s.overcommitted_windows().is_empty());
    }

    #[test]
    fn every_offending_window_is_reported_not_just_the_first() {
        // An operator fixing one and resubmitting to find another is the
        // failure mode this avoids.
        let s = schedule(vec![
            window("a", 1, &["granite4-1b"]),
            window("b", 8, &["granite4-1b"]),
            window("c", 1, &["granite4-1b"]),
        ]);
        let over = s.overcommitted_windows();
        assert_eq!(over.len(), 2);
        assert_eq!(over[0].window, "a");
        assert_eq!(over[1].window, "c");
    }

    #[test]
    fn the_message_names_the_window_and_both_numbers() {
        let s = schedule(vec![window("tight", 1, &["granite4-1b"])]);
        let msg = s.overcommitted_windows()[0].to_string();
        assert!(msg.contains("tight"), "{msg}");
        assert!(msg.contains("ceiling"), "{msg}");
    }

    #[test]
    fn a_schedule_with_no_windows_is_accepted() {
        // Availability-only schedules predate windows and must keep working.
        assert!(schedule(vec![]).overcommitted_windows().is_empty());
    }
}

#[cfg(test)]
mod offload_record_tests {
    use super::OFFLOAD_PREFIX;

    // What is covered here is the *shape* of the record and the key it lives
    // under. Exercising the handlers needs a node with RocksDB, which these
    // unit tests do not build; what they can catch is the thing that actually
    // went wrong — a key that does not round-trip, or a prefix that collides
    // with the serving rows it sits beside in the same column family.

    fn offload_key(model_id: &str) -> Vec<u8> {
        format!("{OFFLOAD_PREFIX}{model_id}").into_bytes()
    }

    /// **The collision that would undo this.** Offload records share
    /// `CF_MODELS` with the `served:` rows they suppress. If one prefix were a
    /// prefix of the other, the startup scan for `served:` would pick up
    /// offload rows — and a model the operator stopped would be restored as
    /// serving, which is the exact bug this exists to fix, arriving by a new
    /// route.
    #[test]
    fn the_offload_prefix_cannot_be_confused_with_a_served_row() {
        assert!(!OFFLOAD_PREFIX.starts_with("served:"));
        assert!(!"served:".starts_with(OFFLOAD_PREFIX));
        assert!(
            OFFLOAD_PREFIX.ends_with(':'),
            "a prefix without its separator matches too much"
        );
    }

    /// The key recovers the model id it was built from, for every id shape the
    /// catalog actually uses — dots and dashes included, since those are what
    /// `qwen3.8-27b-dflash` and friends are made of.
    #[test]
    fn a_key_round_trips_to_the_model_it_names() {
        for id in [
            "muse-glimmer-30b",
            "muse-glimmer-30b-dflash",
            "qwen3.8-27b",
            "timesfm-2.5-200m",
            "gemma4-e2b-mtp-draft",
        ] {
            let key = offload_key(id);
            let text = std::str::from_utf8(&key).expect("keys are utf-8");
            assert_eq!(text.strip_prefix(OFFLOAD_PREFIX), Some(id), "{id}");
        }
    }

    /// Two models do not share a record, so offloading one cannot silently
    /// offload another.
    #[test]
    fn distinct_models_get_distinct_keys() {
        assert_ne!(
            offload_key("muse-glimmer-30b"),
            offload_key("muse-glimmer-30b-dflash")
        );
    }

    /// A model id that is a prefix of another must not have its record found
    /// by a scan for the longer one, nor the reverse. `get` is exact, but the
    /// startup path lists by prefix, and this is the property that keeps the
    /// two consistent.
    #[test]
    fn one_model_id_being_a_prefix_of_another_does_not_leak() {
        let short = offload_key("muse-glimmer-30b");
        let long = offload_key("muse-glimmer-30b-dflash");
        assert!(long.starts_with(&short[..]), "the ids genuinely nest");
        assert_ne!(short, long, "but the keys are still distinct");
    }
}

/// A node's earning and bonding account must be its own, never a
/// stranger's. The identity registry on every node mirrors every identity on
/// the chain, so inference over it must not hand a node whose own account is
/// unregistered some other machine's identity.
#[cfg(test)]
mod operator_account_tests {
    use super::{MachineOperator, resolve_operator_identity, resolve_operator_payee};
    use tenzro_identity::{
        IdentityData, IdentityRegistry, IdentityStatus, TenzroDid, TenzroIdentity,
    };
    use tenzro_types::primitives::Address;

    fn account(seed: u8) -> Address {
        Address::new([seed; 32])
    }

    fn did(seed: u8) -> String {
        format!("did:tenzro:machine:{}", hex::encode([seed; 32]))
    }

    fn machine_identity(did: &str, wallet: Address, controller: Option<&str>) -> TenzroIdentity {
        TenzroIdentity {
            did: TenzroDid::parse(did).expect("DID"),
            public_keys: Vec::new(),
            identity_data: IdentityData::Machine {
                capabilities: Vec::new(),
                controller_did: controller.map(str::to_string),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address: wallet,
            wallet_id: String::new(),
            pq_verifying_key: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: Default::default(),
        }
    }

    fn human_identity(seed: u8, wallet: Address) -> TenzroIdentity {
        let mut id = machine_identity(&did(seed), wallet, None);
        id.did = TenzroDid::parse(&format!("did:tenzro:human:{}", hex::encode([seed; 32])))
            .expect("DID");
        id.identity_data = IdentityData::Human {
            display_name: "Owner".into(),
            controlled_machines: Vec::new(),
        };
        id
    }

    /// The registry of a node that has synced a chain on which the first machine (seed 1)
    /// registered its machine identity.
    fn registry_with_gpu_host() -> IdentityRegistry {
        let registry = IdentityRegistry::new();
        registry.upsert_identity_for_test(machine_identity(&did(1), account(1), None));
        registry
    }

    fn pi() -> MachineOperator {
        MachineOperator {
            did: Some(did(2)),
            account: account(2),
        }
    }

    #[test]
    fn an_unregistered_machine_does_not_take_another_machines_account() {
        let registry = std::sync::Arc::new(registry_with_gpu_host());
        // The Pi's own hardware wallet account has no registry entry.
        let payee = resolve_operator_payee(Some(&registry), Some(&pi()), None);
        assert_eq!(
            payee,
            Some(account(2)),
            "the Pi earns into its own account, not the gpu-host's"
        );
        assert_eq!(
            resolve_operator_identity(Some(&registry), Some(&pi()), None),
            None
        );
    }

    #[test]
    fn two_unregistered_machines_get_two_accounts() {
        let registry = std::sync::Arc::new(registry_with_gpu_host());
        let other = MachineOperator {
            did: Some(did(3)),
            account: account(3),
        };
        let a = resolve_operator_payee(Some(&registry), Some(&pi()), None);
        let b = resolve_operator_payee(Some(&registry), Some(&other), None);
        assert_ne!(a, b);
    }

    #[test]
    fn a_machine_registered_under_its_own_account_resolves_to_it() {
        let registry = std::sync::Arc::new(registry_with_gpu_host());
        registry.upsert_identity_for_test(machine_identity(&did(2), account(2), None));
        assert_eq!(
            resolve_operator_identity(Some(&registry), Some(&pi()), None),
            Some((did(2), account(2)))
        );
    }

    #[test]
    fn the_machines_own_did_resolves_to_its_registered_wallet() {
        let registry = std::sync::Arc::new(registry_with_gpu_host());
        registry.upsert_identity_for_test(machine_identity(&did(2), account(9), None));
        assert_eq!(
            resolve_operator_identity(Some(&registry), Some(&pi()), None),
            Some((did(2), account(9)))
        );
    }

    #[test]
    fn a_configured_operator_is_still_honoured() {
        let registry = std::sync::Arc::new(registry_with_gpu_host());
        registry.upsert_identity_for_test(human_identity(7, account(7)));
        let owner = format!("did:tenzro:human:{}", hex::encode([7u8; 32]));
        assert_eq!(
            resolve_operator_identity(Some(&registry), Some(&pi()), Some(&owner)),
            Some((owner, account(7)))
        );
    }

    #[test]
    fn a_node_with_no_hardware_wallet_still_infers_its_operator() {
        let registry = std::sync::Arc::new(registry_with_gpu_host());
        assert_eq!(
            resolve_operator_identity(Some(&registry), None, None),
            Some((did(1), account(1)))
        );
    }
}
