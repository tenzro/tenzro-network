//! Resource tiers: how much of the machine the node takes.
//!
//! A node runs on anything from a 2 GB single-board computer to a GPU server.
//! The tier sets the defaults that depend on that: the store's memory and
//! background work, its open files and write buffers, and the async runtime's
//! threads. Every value the operator sets in the configuration wins over the
//! tier.
//!
//! - `edge`: small, embedded and edge devices (single-board computers such as
//!   the Raspberry Pi, the reference device; Jetson-class modules, mini PCs,
//!   NAS boxes, gateways). Small store, little background I/O, few threads.
//! - `validator`: a server that validates, stores and relays. Today's
//!   defaults.
//! - `provider`: a server that also serves models. The same storage and
//!   runtime defaults as `validator`; the engines take the rest of the
//!   machine through the memory budget.
//!
//! `auto` (the default) picks `provider` when the roles run models, `edge` on
//! a machine with at most [`EDGE_MAX_MEMORY`] of memory, and `validator`
//! otherwise.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tenzro_types::RoleSet;

/// The most memory a machine `auto` places in the edge tier has.
pub const EDGE_MAX_MEMORY: u64 = 8 << 30;

/// The tier as configured: one of the tiers, or derived from the machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierSetting {
    /// Derived from the roles and the machine's memory.
    #[default]
    Auto,
    /// Small, embedded and edge devices.
    Edge,
    /// Validating, storing and relaying servers.
    Validator,
    /// Servers that also serve models.
    Provider,
}

impl FromStr for TierSetting {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "edge" => Ok(Self::Edge),
            "validator" => Ok(Self::Validator),
            "provider" => Ok(Self::Provider),
            other => Err(format!(
                "unknown tier '{other}': expected auto, edge, validator or provider"
            )),
        }
    }
}

/// A resolved tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Edge,
    Validator,
    Provider,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Tier::Edge => "edge",
            Tier::Validator => "validator",
            Tier::Provider => "provider",
        })
    }
}

impl TierSetting {
    /// The tier for a node with `roles` on a machine with `memory_bytes`.
    pub fn resolve(self, roles: &RoleSet, memory_bytes: u64) -> Tier {
        match self {
            TierSetting::Edge => Tier::Edge,
            TierSetting::Validator => Tier::Validator,
            TierSetting::Provider => Tier::Provider,
            TierSetting::Auto => {
                if roles.serves_ai() || roles.serves_compute() || roles.serves_tee() {
                    Tier::Provider
                } else if memory_bytes <= EDGE_MAX_MEMORY {
                    Tier::Edge
                } else {
                    Tier::Validator
                }
            }
        }
    }
}

/// The defaults a tier sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tuning {
    /// The store's memory is this share (1/n) of the memory pool...
    pub storage_memory_divisor: u64,
    /// ...but at least this many bytes...
    pub storage_memory_min: u64,
    /// ...and at most this many.
    pub storage_memory_max: u64,
    /// Write buffer per column family, bytes.
    pub write_buffer_bytes: usize,
    /// Background flush and compaction jobs.
    pub background_jobs: i32,
    /// Rate compaction and flush may write at, MiB per second.
    pub background_write_mb_per_sec: u64,
    /// Files the store keeps open.
    pub max_open_files: i32,
    /// Async runtime worker threads.
    pub worker_threads: usize,
    /// Most threads the async runtime runs blocking work on.
    pub max_blocking_threads: usize,
}

impl Tier {
    /// This tier's defaults on a machine with `cores` cores.
    pub fn tuning(self, cores: usize) -> Tuning {
        match self {
            // Two of a Pi 5's four cores at most for the runtime, a store a
            // 2 GB board can hold beside the OS, and background writes paced
            // for an SD card.
            Tier::Edge => Tuning {
                storage_memory_divisor: 16,
                storage_memory_min: 32 << 20,
                storage_memory_max: 256 << 20,
                write_buffer_bytes: 16 << 20,
                background_jobs: 1,
                background_write_mb_per_sec: 16,
                max_open_files: 256,
                worker_threads: cores.clamp(1, 2),
                max_blocking_threads: 32,
            },
            Tier::Validator | Tier::Provider => Tuning {
                storage_memory_divisor: 32,
                storage_memory_min: 256 << 20,
                storage_memory_max: 4 << 30,
                write_buffer_bytes: 64 << 20,
                background_jobs: 2,
                background_write_mb_per_sec: 64,
                max_open_files: 1000,
                worker_threads: 2,
                max_blocking_threads: 512,
            },
        }
    }
}

/// This machine's memory, bytes.
pub fn machine_memory() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.total_memory()
}

/// This machine's cores.
pub fn machine_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(s: &str) -> RoleSet {
        s.parse().unwrap()
    }

    const GIB: u64 = 1 << 30;

    #[test]
    fn auto_puts_a_small_machine_in_the_edge_tier() {
        for gb in [2, 4, 8] {
            assert_eq!(
                TierSetting::Auto.resolve(&roles("light"), gb * GIB),
                Tier::Edge
            );
        }
        assert_eq!(
            TierSetting::Auto.resolve(&roles("validator"), 16 * GIB),
            Tier::Validator
        );
    }

    #[test]
    fn auto_puts_a_node_that_serves_models_in_the_provider_tier() {
        assert_eq!(
            TierSetting::Auto.resolve(&roles("ai"), 4 * GIB),
            Tier::Provider
        );
    }

    #[test]
    fn a_named_tier_is_taken_as_named() {
        assert_eq!(
            TierSetting::Edge.resolve(&roles("validator"), 128 * GIB),
            Tier::Edge
        );
        assert_eq!(
            TierSetting::Validator.resolve(&roles("light"), 2 * GIB),
            Tier::Validator
        );
    }

    #[test]
    fn the_server_tiers_keep_the_existing_defaults() {
        let t = Tier::Validator.tuning(20);
        assert_eq!(t.storage_memory_min, 256 << 20);
        assert_eq!(t.background_jobs, 2);
        assert_eq!(t.worker_threads, 2);
        assert_eq!(Tier::Provider.tuning(20), t);
    }

    #[test]
    fn the_edge_tier_fits_a_two_gigabyte_board() {
        let t = Tier::Edge.tuning(4);
        assert!(t.storage_memory_max <= 256 << 20);
        assert!(t.worker_threads <= 2);
        assert_eq!(Tier::Edge.tuning(1).worker_threads, 1);
    }

    #[test]
    fn a_tier_parses_from_its_name() {
        for (s, t) in [
            ("auto", TierSetting::Auto),
            ("edge", TierSetting::Edge),
            ("validator", TierSetting::Validator),
            ("provider", TierSetting::Provider),
        ] {
            assert_eq!(s.parse::<TierSetting>().unwrap(), t);
        }
        assert!("pi".parse::<TierSetting>().is_err());
    }
}
