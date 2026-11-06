//! Persisted operator configuration.
//!
//! Everything onboarding decides — which roles the node serves, which
//! models it loads, when it accepts paid work, what it charges — lives
//! in one JSON file at `~/.tenzro/control/control.json`, loaded once
//! and written through on every mutation. It holds no secret: Control
//! proves it operates its node by signing in with the machine's hardware
//! key (see [`crate::rpc::rpc_result_admin`]).

use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};
use tenzro_types::network::{NetworkRole, RoleSet};

/* --------------------------------------------------------------------- */
/* shape                                                                  */
/* --------------------------------------------------------------------- */

/// One contiguous serving window, in the operator's local time.
///
/// `start_hour == end_hour` is an empty window, not a full day — a full
/// day is `always_on`, which is a different answer to a different
/// question. A window that wraps midnight (`start > end`) is honoured as
/// two spans, which is how "22:00 to 06:00" is normally meant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServingWindow {
    /// Local hour the window opens, 0–23.
    pub start_hour: u8,
    /// Local hour the window closes, 0–23. Exclusive.
    pub end_hour: u8,
    /// Days this window applies to, `0` = Monday through `6` = Sunday.
    /// Empty means every day.
    #[serde(default)]
    pub days: Vec<u8>,
}

/// When the node accepts paid work.
///
/// This governs the AI and storage roles only. A validator has no "off"
/// state — consensus participation is continuous or it is a liability to
/// the network — so [`Availability::is_serving_now`] is never consulted
/// for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Availability {
    /// Serve around the clock. When true, `windows` is ignored.
    pub always_on: bool,
    /// Windows in which paid serving is offered.
    #[serde(default)]
    pub windows: Vec<ServingWindow>,
}

impl Default for Availability {
    fn default() -> Self {
        Self {
            always_on: true,
            windows: Vec::new(),
        }
    }
}

impl Availability {
    /// Is the node inside a serving window right now?
    ///
    /// Takes the current local weekday and hour rather than reading the
    /// clock itself, so the schedule editor can preview a setting without
    /// waiting for the hour to come round.
    pub fn covers(&self, weekday: u8, hour: u8) -> bool {
        if self.always_on {
            return true;
        }
        self.windows.iter().any(|w| {
            let day_ok = w.days.is_empty() || w.days.contains(&weekday);
            if !day_ok {
                return false;
            }
            if w.start_hour == w.end_hour {
                false
            } else if w.start_hour < w.end_hour {
                hour >= w.start_hour && hour < w.end_hour
            } else {
                // Wraps midnight: 22→06 covers 22,23 and 0..5.
                hour >= w.start_hour || hour < w.end_hour
            }
        })
    }

    /// Is the node inside a serving window at this moment?
    pub fn is_serving_now(&self) -> bool {
        use chrono::{Datelike, Local, Timelike};
        let now = Local::now();
        // chrono weekday is Mon=0 via num_days_from_monday.
        let weekday = now.weekday().num_days_from_monday() as u8;
        self.covers(weekday, now.hour() as u8)
    }
}

/// What the node charges for AI inference, in wei per token.
///
/// The network clamps both figures server-side, so these are a request,
/// not a guarantee — [`NETWORK_MAX_INPUT_WEI`] and
/// [`NETWORK_MAX_OUTPUT_WEI`] are the ceilings a caller will ever be
/// quoted. Rates for non-token units (audio seconds, frames, cached
/// reads) are deliberately absent: the node inherits its own wei-scale
/// defaults for those, which is a better answer than a desktop UI
/// inventing ten more numbers the operator has no basis to set.
/// Overrides for how the embedded node divides memory between models and
/// everything else — mirrors `tenzro_node::config::MemoryConfig`. `None`
/// leaves the node on its own default (detected RAM, 16 GiB reserve, 60/40
/// resident/on-demand split of what's left).
///
/// Applied once, in [`crate::node::apply_memory`], before the embedded
/// node's runtimes spawn — there is no later call that could change a
/// running node's ceilings, so a value set here takes effect on the next
/// restart, not immediately.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryOverride {
    pub reserve_gb: Option<u32>,
    pub resident_ceiling_gb: Option<u32>,
    pub on_demand_ceiling_gb: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AiPricing {
    /// Wei charged per input token.
    pub input_price_per_token_wei: u128,
    /// Wei charged per output token.
    pub output_price_per_token_wei: u128,
}

/// Network ceiling on the price of one input token: 0.001 TNZO.
pub const NETWORK_MAX_INPUT_WEI: u128 = 1_000_000_000_000_000;

/// Network ceiling on the price of one output token: 0.002 TNZO.
pub const NETWORK_MAX_OUTPUT_WEI: u128 = 2_000_000_000_000_000;

impl Default for AiPricing {
    fn default() -> Self {
        PricingBracket::Standard.ai_pricing()
    }
}

/// Named starting points for AI pricing, expressed as a fraction of the
/// network ceiling.
///
/// An operator with no market position has no way to pick a number out
/// of the air, and a wrong guess is invisible until nobody routes to
/// them. Three brackets give a defensible starting point that can be
/// edited afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PricingBracket {
    /// 1% of ceiling. Wins price-sorted routing; thin margin.
    Economy,
    /// 10% of ceiling. The default.
    Standard,
    /// 50% of ceiling. For scarce hardware or long-context serving.
    Premium,
}

impl PricingBracket {
    /// Every bracket, in the order a picker should present them.
    pub const ALL: [PricingBracket; 3] = [Self::Economy, Self::Standard, Self::Premium];

    /// Stable identifier, matching the serde representation.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Economy => "economy",
            Self::Standard => "standard",
            Self::Premium => "premium",
        }
    }

    /// Basis points of the network ceiling this bracket charges.
    pub fn bps(&self) -> u128 {
        match self {
            Self::Economy => 100,
            Self::Standard => 1_000,
            Self::Premium => 5_000,
        }
    }

    /// The concrete rates this bracket resolves to.
    pub fn ai_pricing(&self) -> AiPricing {
        let bps = self.bps();
        AiPricing {
            input_price_per_token_wei: NETWORK_MAX_INPUT_WEI * bps / 10_000,
            output_price_per_token_wei: NETWORK_MAX_OUTPUT_WEI * bps / 10_000,
        }
    }
}

/// What the node offers as a storage provider.
///
/// A band rather than a single figure, because the storage runtime moves
/// its rate each billing epoch from how much of the pledged capacity is
/// actually taken. The floor is what it charges when nobody is storing
/// anything, the ceiling what it charges when it is full.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoragePricing {
    /// Gigabytes the operator commits to the network.
    pub capacity_gb: u64,
    /// Floor rate, wei per gigabyte-month.
    pub min_rate_wei: u128,
    /// Ceiling rate, wei per gigabyte-month.
    pub max_rate_wei: u128,
}

impl Default for StoragePricing {
    fn default() -> Self {
        Self {
            capacity_gb: 0,
            // 0.01 TNZO to 0.05 TNZO per GB-month.
            min_rate_wei: 10_000_000_000_000_000,
            max_rate_wei: 50_000_000_000_000_000,
        }
    }
}

/// What the node charges to rent its accelerators out by the hour.
///
/// One billing epoch on the node is an hour, so this is the per-epoch
/// compute rate with no conversion. It buys the whole machine's rentable
/// capacity for the term, not a share of it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComputePricing {
    /// Wei charged per hour of rental.
    pub rate_per_hour_wei: u128,
}

impl Default for ComputePricing {
    fn default() -> Self {
        Self {
            // The node's own reference rate, so an operator who never
            // touches this quotes what a headless node would.
            rate_per_hour_wei: 1_000_000_000_000,
        }
    }
}

/// What signs for the operator's account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Custody {
    /// No wallet has been set up yet.
    #[default]
    None,
    /// This machine's TPM 2.0 or Secure Enclave key: the account is that
    /// key's own ledger account, and every transaction from it is signed
    /// inside the hardware.
    Hardware,
}

/// Who this node runs as.
///
/// Held separately from the node's own identity registry so the dashboard
/// can name the operator before the node has finished starting.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Identity {
    /// The machine's DID, which its hardware key derives.
    #[serde(default)]
    pub did: String,
    /// Hex account address: the hardware key's own ledger account.
    #[serde(default)]
    pub address: String,
    /// Which signing backing is in use.
    #[serde(default)]
    pub custody: Custody,
    /// The name shown on the identity record.
    #[serde(default)]
    pub display_name: String,
}

/// The whole persisted operator configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ControlConfig {
    /// The operator this node runs as.
    #[serde(default)]
    pub identity: Identity,
    /// Roles the node advertises, as wire tokens (`validator`, `ai`,
    /// `storage`, `compute`, `cloud`, `tee`). Empty until onboarding
    /// completes.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Catalogue ids of the models the operator chose to serve.
    #[serde(default)]
    pub models: Vec<String>,
    /// When paid serving is offered.
    #[serde(default)]
    pub availability: Availability,
    /// AI inference rates.
    #[serde(default)]
    pub ai_pricing: AiPricing,
    /// Storage capacity and rate band.
    #[serde(default)]
    pub storage_pricing: StoragePricing,
    /// Accelerator-rental rate.
    #[serde(default)]
    pub compute_pricing: ComputePricing,
    /// Memory-budget ceilings for the embedded node. Applied at next
    /// restart, not live — see [`MemoryOverride`].
    #[serde(default)]
    pub memory: MemoryOverride,
    /// True once the operator has been all the way through onboarding.
    /// Drives whether the app opens on the setup flow or the dashboard.
    #[serde(default)]
    pub onboarded: bool,
}

/* --------------------------------------------------------------------- */
/* load / store                                                           */
/* --------------------------------------------------------------------- */

static CACHE: OnceLock<RwLock<ControlConfig>> = OnceLock::new();

/// Path of the config file.
pub fn config_path() -> Result<PathBuf, String> {
    Ok(crate::node::data_dir()?.join("control.json"))
}

fn cache() -> &'static RwLock<ControlConfig> {
    CACHE.get_or_init(|| RwLock::new(read_from_disk()))
}

/// Reads the file, tolerating absence and corruption.
///
/// A config that fails to parse is replaced rather than treated as
/// fatal: the alternative is an app that will not launch until the user
/// finds and deletes a JSON file, and everything in here is either
/// re-derivable or re-enterable.
fn read_from_disk() -> ControlConfig {
    let Ok(path) = config_path() else {
        return ControlConfig::default();
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return ControlConfig::default();
    };
    match serde_json::from_str::<ControlConfig>(&raw) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                "config file is unreadable ({}), starting from defaults",
                e
            );
            ControlConfig::default()
        }
    }
}

/// Writes the config, then tightens permissions.
///
/// On Unix it is written 0600: it says what this operator serves and
/// charges, which is nobody else's business. The write is create-truncate rather than atomic-rename because a torn
/// write here degrades to the corruption path above, which recovers.
fn write_to_disk(cfg: &ControlConfig) -> Result<(), String> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {}", parent.display(), e))?;
    }
    let json = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("failed to serialize config: {}", e))?;

    let mut f = std::fs::File::create(&path)
        .map_err(|e| format!("failed to open {}: {}", path.display(), e))?;
    f.write_all(json.as_bytes())
        .map_err(|e| format!("failed to write {}: {}", path.display(), e))?;
    f.flush()
        .map_err(|e| format!("failed to flush {}: {}", path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// A snapshot of the current configuration.
pub fn get() -> ControlConfig {
    cache().read().map(|g| g.clone()).unwrap_or_default()
}

/// Mutates the configuration and writes it through.
///
/// The lock is released before the disk write so a slow filesystem does
/// not block a concurrent read of settings the UI is already showing.
pub fn update<F>(f: F) -> Result<ControlConfig, String>
where
    F: FnOnce(&mut ControlConfig),
{
    let updated = {
        let mut guard = cache()
            .write()
            .map_err(|_| "config lock is poisoned".to_string())?;
        f(&mut guard);
        guard.clone()
    };
    write_to_disk(&updated)?;
    Ok(updated)
}

/* --------------------------------------------------------------------- */
/* roles                                                                  */
/* --------------------------------------------------------------------- */

/// The role set the node should start with.
///
/// Before onboarding completes this is a light client: the node joins
/// the network, syncs, and holds an identity, but advertises no service
/// it has not yet been configured to honour. Unparseable role strings
/// are dropped with a warning rather than failing startup — a config
/// naming one stale role should not keep the node off the network.
pub fn role_set() -> RoleSet {
    let cfg = get();
    if cfg.roles.is_empty() {
        return RoleSet::from_roles([NetworkRole::LightClient]);
    }
    let roles: Vec<NetworkRole> = cfg
        .roles
        .iter()
        .filter_map(|r| match NetworkRole::from_str(r) {
            Ok(role) => Some(role),
            Err(e) => {
                tracing::warn!("ignoring configured role {:?}: {}", r, e);
                None
            }
        })
        .collect();
    if roles.is_empty() {
        RoleSet::from_roles([NetworkRole::LightClient])
    } else {
        RoleSet::from_roles(roles)
    }
}

/// True if the configured roles include the validator role.
pub fn is_validator() -> bool {
    role_set().is_validator()
}

/// True if the node should be accepting paid work right now.
///
/// Validators are always serving; the schedule applies to the AI and
/// storage roles.
pub fn serving_now() -> bool {
    is_validator() || get().availability.is_serving_now()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_on_covers_every_hour() {
        let a = Availability::default();
        assert!(a.covers(0, 0));
        assert!(a.covers(6, 23));
    }

    #[test]
    fn plain_window_covers_its_own_hours_only() {
        let a = Availability {
            always_on: false,
            windows: vec![ServingWindow {
                start_hour: 9,
                end_hour: 17,
                days: vec![],
            }],
        };
        assert!(!a.covers(0, 8));
        assert!(a.covers(0, 9));
        assert!(a.covers(0, 16));
        assert!(!a.covers(0, 17));
    }

    #[test]
    fn window_wrapping_midnight_covers_both_spans() {
        let a = Availability {
            always_on: false,
            windows: vec![ServingWindow {
                start_hour: 22,
                end_hour: 6,
                days: vec![],
            }],
        };
        assert!(a.covers(0, 22));
        assert!(a.covers(0, 23));
        assert!(a.covers(0, 0));
        assert!(a.covers(0, 5));
        assert!(!a.covers(0, 6));
        assert!(!a.covers(0, 12));
    }

    #[test]
    fn empty_window_covers_nothing() {
        let a = Availability {
            always_on: false,
            windows: vec![ServingWindow {
                start_hour: 3,
                end_hour: 3,
                days: vec![],
            }],
        };
        assert!(!a.covers(0, 3));
    }

    #[test]
    fn day_filter_restricts_the_window() {
        let a = Availability {
            always_on: false,
            windows: vec![ServingWindow {
                start_hour: 9,
                end_hour: 17,
                days: vec![5, 6],
            }],
        };
        assert!(!a.covers(0, 12));
        assert!(a.covers(5, 12));
        assert!(a.covers(6, 12));
    }

    #[test]
    fn brackets_stay_under_the_network_ceiling() {
        for b in PricingBracket::ALL {
            let p = b.ai_pricing();
            assert!(p.input_price_per_token_wei <= NETWORK_MAX_INPUT_WEI);
            assert!(p.output_price_per_token_wei <= NETWORK_MAX_OUTPUT_WEI);
        }
    }

    #[test]
    fn brackets_are_ordered_cheapest_first() {
        let e = PricingBracket::Economy.ai_pricing();
        let s = PricingBracket::Standard.ai_pricing();
        let p = PricingBracket::Premium.ai_pricing();
        assert!(e.output_price_per_token_wei < s.output_price_per_token_wei);
        assert!(s.output_price_per_token_wei < p.output_price_per_token_wei);
    }
}
