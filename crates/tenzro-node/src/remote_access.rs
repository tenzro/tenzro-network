//! Scoped remote hardware access for rented nodes.
//!
//! When an operator rents their node to someone, that renter should be able to
//! use the hardware directly — not only through the node's RPCs. This module
//! is the authorization and confinement half of that; the transport half is
//! the `tenzro/shell` ALPN in [`tenzro_iroh::shell`].
//!
//! The model is GCP OS Login + IAP and AWS SSM Session Manager, not a handed-out
//! root SSH key: identity-scoped, short-lived, no inbound port, revocable at
//! the source, and audited.
//!
//! # Three factors, because each answers a different question
//!
//! 1. **A service key** — provisioned by the operator by hand, or minted
//!    automatically when a rental deposit lands. Establishes *which lease* a
//!    caller is invoking. On its own it proves only that someone was given a
//!    string.
//! 2. **A passkey ceremony against the caller's Tenzro wallet** — the
//!    browser-launch flow the wallet already runs (`gcloud auth login` shape:
//!    the CLI prints a link, the user verifies in a browser, the CLI polls).
//!    This is what makes a session attributable to a *person's wallet* rather
//!    than to whoever holds the key. A shared string cannot tell an operator
//!    who logged in; a passkey assertion can.
//! 3. **Membership in the lease's authorized-wallet list** — the operator says
//!    which wallets may use that service key. Without this, a leaked key is a
//!    full compromise; with it, a leaked key is useless to anyone whose wallet
//!    the operator did not name.
//!
//! All three are required. The service key alone opens nothing, and a wallet
//! not on the list opens nothing even with a valid passkey.
//!
//! # Revoking the lease revokes access
//!
//! The passkey ceremony yields a short-lived [`ShellGrant`], redeemable once.
//! There is no long-lived credential on the node to steal, and a revoked lease
//! invalidates every outstanding grant against it — so the operator has one
//! action, not two, and no window between them.

//! # No confinement, no shell
//!
//! [`ConfinementBackend`] is a trait with no default implementation that
//! returns a session. A node with none configured refuses every session rather
//! than dropping the renter onto the host.
//!
//! This is the load-bearing decision of the whole design. A container
//! namespace is not a defensible boundary against someone with a shell; the
//! renter is inside the same kernel as the operator's validator key, the
//! node's RocksDB, and any other tenant's slice. A VM boundary
//! ([`ConfinementKind::KataVm`]) is, and VFIO passthrough is what keeps GPU
//! access working through it. Since the boundary is what makes the feature
//! safe rather than an enhancement to it, its absence has to mean refusal.
//!
//! # A node cannot be a TEE provider and rent out a shell on the same enclave
//!
//! Interactive access invalidates the attestation posture `TeeProvider`
//! claims. A renter with a shell can read whatever the enclave holds, so the
//! measurement no longer implies to a relying party what they think it
//! implies. [`LeaseRegistry::open_lease`] refuses rather than letting an
//! operator quietly sell both.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tracing::{info, warn};

/// RocksDB key prefix for lease records.
const LEASE_PREFIX: &[u8] = b"access_lease:";
/// RocksDB key prefix for the service-key-digest → lease-id index.
const RENTER_INDEX_PREFIX: &[u8] = b"access_lease_key:";
/// RocksDB key prefix for filed session receipts, keyed
/// `<lease_id>:<zero-padded started_ms>:<receipt_id>` so a scan is ordered and
/// a per-lease scan is a prefix scan.
const SESSION_RECEIPT_PREFIX: &[u8] = b"access_session_receipt:";

/// Hard ceiling on a single interactive session, whatever the lease says.
///
/// A session that outlives the operator's attention is how "temporary access"
/// becomes permanent access. Reconnecting is cheap; the lease is still valid.
pub const MAX_SESSION_SECS: u64 = 12 * 60 * 60;

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/// A device class a lease may expose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceGrant {
    /// CPU cores, by count. The sandbox pins the session to that many.
    Cpu { cores: u32 },
    /// A specific accelerator by its host index, **in its entirety**.
    ///
    /// By index rather than "all GPUs" because a node with several may rent
    /// them to several people, and "all" is not a scope anyone chose.
    ///
    /// On a unified-memory machine this is a much larger grant than it looks:
    /// where VRAM *is* system memory (Apple Silicon, GB10), handing over the
    /// accelerator hands over the pool the node itself runs from. Prefer
    /// [`DeviceGrant::AcceleratorMemory`] there, and see
    /// [`DedicationMode`] for the case where whole-machine really is intended.
    Accelerator { index: u32 },
    /// A slice of one accelerator's memory, in MiB.
    ///
    /// The grant an operator usually wants: a renter gets a bounded share of
    /// a device that other tenants and the node's own models keep using. On
    /// unified-memory hardware this is the only way to rent an accelerator
    /// without renting the machine.
    AcceleratorMemory {
        /// Host index of the accelerator being sliced.
        index: u32,
        /// Ceiling in MiB.
        mib: u64,
    },
    /// System memory ceiling in MiB.
    Memory { mib: u64 },
    /// Disk the lease may occupy, in MiB.
    ///
    /// Separate from the workspace path: the path says *where*, this says
    /// *how much*. Without it a renter can fill the disk the node's RocksDB
    /// is writing to, which takes down the operator rather than the tenant.
    Storage { mib: u64 },
}

impl DeviceGrant {
    /// Accelerator memory this grant consumes, in MiB, if any.
    ///
    /// A whole-accelerator grant reports `None` rather than zero: its cost is
    /// "all of it", which is not a number and must not be summed with slices.
    pub fn accelerator_mib(&self) -> Option<u64> {
        match self {
            Self::AcceleratorMemory { mib, .. } => Some(*mib),
            _ => None,
        }
    }
}

/// How much of the machine a lease takes.
///
/// The distinction an operator has to be able to make deliberately. Renting
/// out a slice and renting out the box are different products with different
/// risk, and a scope that expresses only the second — or that reaches the
/// second by accident on unified-memory hardware — is not a choice the
/// operator made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedicationMode {
    /// Only the resources the scope names, bounded by its grants.
    ///
    /// The default, and the safe one: anything not granted stays with the
    /// operator, and [`ResourceLedger`] refuses a lease that would oversell
    /// what is left.
    #[default]
    Partial,
    /// The whole machine, for one tenant, for the term.
    ///
    /// Must be stated explicitly — never inferred from a scope that happens
    /// to name every device. An operator selling their whole node should have
    /// to say so, because it is the one mode where the node stops being able
    /// to serve anyone else, including its own public traffic.
    Exclusive,
}

/// What a session may reach on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkGrant {
    /// No egress. The default: a rented shell is for compute, and silence is
    /// the setting an operator would pick if asked.
    #[default]
    None,
    /// Egress to the public internet, no access to the host's local networks.
    ///
    /// The distinction matters because the operator's other services — their
    /// RPC, their metrics, their hypervisor's management plane — live on those
    /// local networks and are typically unauthenticated from inside.
    EgressOnly,
}

/// The confinement boundary a session runs inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinementKind {
    /// A Kata Containers VM, with VFIO passthrough for any granted
    /// accelerator.
    KataVm,
}

/// How a renter reaches what they rented.
///
/// Orthogonal to *what* is rented. The same carve-out of memory and
/// accelerator can be delivered as a shell someone SSHes into, or as the
/// node's ordinary API surfaces with capacity guaranteed behind them, and
/// those have very different risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessChannel {
    /// A confined interactive shell over the `tenzro/shell` ALPN.
    ///
    /// Requires a [`ConfinementBackend`]: a shell without a VM boundary puts
    /// the renter in the same kernel as the operator's validator key.
    Shell,
    /// The node's own service surfaces — JSON-RPC, `/v1/*` REST, MCP, A2A.
    ///
    /// **Needs no confinement**, because the renter never gets code execution
    /// on the host: they call handlers that already gate and validate every
    /// request. This is the safer product and, for most tenants, the one they
    /// actually want — they came for the models, not for a machine.
    ///
    /// Keeping it distinct from [`Self::Shell`] is what lets an operator with
    /// no sandbox configured still rent capacity out. Before this split,
    /// missing confinement blocked every lease, including ones that would
    /// never have run a process.
    Endpoints,
}

impl AccessChannel {
    /// Whether this channel puts the renter on the host and so needs a VM
    /// boundary.
    pub fn requires_confinement(self) -> bool {
        matches!(self, Self::Shell)
    }
}

/// How long a lease runs, and therefore how it is priced.
///
/// Terms are named rather than free-form seconds so pricing, renewal, and
/// the operator's own capacity planning can reason about them. An operator
/// selling a year of dedicated capacity is making a very different commitment
/// from one selling an hour, and the type should say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RentalTerm {
    /// Billed and renewable by the hour. The default: shortest commitment,
    /// and the one an operator can exit fastest if they need their machine.
    #[default]
    Hourly,
    /// Weekly.
    Weekly,
    /// Monthly, treated as 30 days.
    Monthly,
    /// Annual, treated as 365 days.
    Annual,
}

impl RentalTerm {
    /// Seconds in one billing period.
    ///
    /// Months are 30 days and years 365 rather than calendar-aware: a lease
    /// is a duration from an instant, not a date range, so calendar drift
    /// would make two leases opened days apart bill differently for the same
    /// words.
    pub fn seconds(self) -> u64 {
        match self {
            Self::Hourly => 3_600,
            Self::Weekly => 7 * 86_400,
            Self::Monthly => 30 * 86_400,
            Self::Annual => 365 * 86_400,
        }
    }

    /// Price for `periods` of this term given an hourly rate.
    ///
    /// Longer terms are the operator's opportunity cost of not being able to
    /// re-sell, so the arithmetic stays linear here and any discount is a
    /// pricing decision made above this — encoding a discount in the type
    /// would make it invisible to the operator setting the rate.
    pub fn total_price(self, price_per_hour: u128, periods: u64) -> u128 {
        let hours = u128::from(self.seconds() / 3_600) * u128::from(periods);
        price_per_hour.saturating_mul(hours)
    }

    /// Milliseconds `periods` of this term occupy.
    pub fn duration_ms(self, periods: u64) -> u64 {
        self.seconds().saturating_mul(periods).saturating_mul(1_000)
    }
}

/// What the operator is willing to rent out, and what is already committed.
///
/// The memory budget bounds what *models* may take; this bounds what
/// *tenants* may take. They are different questions with different owners —
/// an operator who is happy to rent 40 GB of accelerator memory may still
/// want their own models to have 60 — so the two ledgers are separate and a
/// lease is checked against this one.
///
/// Every capacity is what the operator chose to make rentable, not what the
/// machine physically has. A node with 121 GB may offer 60; the other 61 is
/// not undersold, it is retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RentableCapacity {
    /// CPU cores offered to tenants.
    pub cpu_cores: u32,
    /// System memory offered, MiB.
    pub memory_mib: u64,
    /// Per-accelerator memory offered, by host index, MiB.
    pub accelerator_mib: HashMap<u32, u64>,
    /// Disk offered, MiB.
    pub storage_mib: u64,
}

/// Why a lease cannot be accommodated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityShortfall {
    /// Which resource ran out.
    pub resource: String,
    /// What the lease asked for.
    pub requested: u64,
    /// What remains uncommitted.
    pub available: u64,
}

impl std::fmt::Display for CapacityShortfall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} exhausted: {} requested, {} still rentable",
            self.resource, self.requested, self.available
        )
    }
}

/// Tracks what has been committed to leases, so nothing is sold twice.
#[derive(Debug, Default)]
pub struct ResourceLedger {
    capacity: Option<RentableCapacity>,
    /// lease id -> its grants.
    committed: HashMap<String, Vec<DeviceGrant>>,
    /// The lease holding the machine exclusively, if any.
    exclusive_holder: Option<String>,
}

impl ResourceLedger {
    /// A ledger offering `capacity` to tenants.
    pub fn new(capacity: RentableCapacity) -> Self {
        Self {
            capacity: Some(capacity),
            committed: HashMap::new(),
            exclusive_holder: None,
        }
    }

    fn committed_cpu(&self) -> u32 {
        self.committed
            .values()
            .flatten()
            .filter_map(|g| match g {
                DeviceGrant::Cpu { cores } => Some(*cores),
                _ => None,
            })
            .sum()
    }

    fn committed_sum(&self, pick: impl Fn(&DeviceGrant) -> Option<u64>) -> u64 {
        self.committed.values().flatten().filter_map(pick).sum()
    }

    fn committed_accelerator(&self, index: u32) -> u64 {
        self.committed
            .values()
            .flatten()
            .filter_map(|g| match g {
                DeviceGrant::AcceleratorMemory { index: i, mib } if *i == index => Some(*mib),
                _ => None,
            })
            .sum()
    }

    /// Whether an accelerator has been granted whole to some lease.
    fn accelerator_taken_whole(&self, index: u32) -> Option<&String> {
        self.committed.iter().find_map(|(lease, grants)| {
            grants
                .iter()
                .any(|g| matches!(g, DeviceGrant::Accelerator { index: i } if *i == index))
                .then_some(lease)
        })
    }

    /// Commit a lease's grants, or explain why they do not fit.
    ///
    /// Checked and recorded together, so two leases opened concurrently
    /// cannot both be told the same capacity is free.
    pub fn commit(
        &mut self,
        lease_id: &str,
        grants: &[DeviceGrant],
        mode: DedicationMode,
    ) -> Result<(), CapacityShortfall> {
        if let Some(holder) = &self.exclusive_holder
            && holder != lease_id
        {
            return Err(CapacityShortfall {
                resource: format!("the whole machine (held exclusively by {holder})"),
                requested: 1,
                available: 0,
            });
        }

        // Exclusive means exclusive: it cannot be layered over leases that
        // already hold slices, because those tenants did not agree to be
        // displaced.
        if mode == DedicationMode::Exclusive {
            if !self.committed.is_empty() {
                return Err(CapacityShortfall {
                    resource: format!(
                        "exclusive dedication (blocked by {} existing lease(s))",
                        self.committed.len()
                    ),
                    requested: 1,
                    available: 0,
                });
            }
            self.exclusive_holder = Some(lease_id.to_string());
            self.committed.insert(lease_id.to_string(), grants.to_vec());
            return Ok(());
        }

        let Some(capacity) = &self.capacity else {
            // No declared capacity means nothing is offered for rent. Refusing
            // is right: an undeclared ledger is an operator who has not opted
            // in, not one offering everything.
            return Err(CapacityShortfall {
                resource: "rentable capacity (none declared by the operator)".to_string(),
                requested: 1,
                available: 0,
            });
        };

        for grant in grants {
            match grant {
                DeviceGrant::Cpu { cores } => {
                    let free = capacity.cpu_cores.saturating_sub(self.committed_cpu());
                    if *cores > free {
                        return Err(CapacityShortfall {
                            resource: "cpu_cores".to_string(),
                            requested: u64::from(*cores),
                            available: u64::from(free),
                        });
                    }
                }
                DeviceGrant::Memory { mib } => {
                    let used = self.committed_sum(|g| match g {
                        DeviceGrant::Memory { mib } => Some(*mib),
                        _ => None,
                    });
                    let free = capacity.memory_mib.saturating_sub(used);
                    if *mib > free {
                        return Err(CapacityShortfall {
                            resource: "memory_mib".to_string(),
                            requested: *mib,
                            available: free,
                        });
                    }
                }
                DeviceGrant::Storage { mib } => {
                    let used = self.committed_sum(|g| match g {
                        DeviceGrant::Storage { mib } => Some(*mib),
                        _ => None,
                    });
                    let free = capacity.storage_mib.saturating_sub(used);
                    if *mib > free {
                        return Err(CapacityShortfall {
                            resource: "storage_mib".to_string(),
                            requested: *mib,
                            available: free,
                        });
                    }
                }
                DeviceGrant::AcceleratorMemory { index, mib } => {
                    if let Some(holder) = self.accelerator_taken_whole(*index) {
                        return Err(CapacityShortfall {
                            resource: format!("accelerator {index} (held whole by {holder})"),
                            requested: *mib,
                            available: 0,
                        });
                    }
                    let offered = capacity.accelerator_mib.get(index).copied().unwrap_or(0);
                    let free = offered.saturating_sub(self.committed_accelerator(*index));
                    if *mib > free {
                        return Err(CapacityShortfall {
                            resource: format!("accelerator {index} memory (MiB)"),
                            requested: *mib,
                            available: free,
                        });
                    }
                }
                DeviceGrant::Accelerator { index } => {
                    // A whole-device grant collides with any slice already
                    // sold on it, in either direction.
                    if let Some(holder) = self.accelerator_taken_whole(*index) {
                        return Err(CapacityShortfall {
                            resource: format!("accelerator {index} (already whole to {holder})"),
                            requested: 1,
                            available: 0,
                        });
                    }
                    let sliced = self.committed_accelerator(*index);
                    if sliced > 0 {
                        return Err(CapacityShortfall {
                            resource: format!(
                                "accelerator {index} (cannot grant whole; {sliced} MiB already \
                                 sliced to other leases)"
                            ),
                            requested: 1,
                            available: 0,
                        });
                    }
                }
            }
        }

        self.committed.insert(lease_id.to_string(), grants.to_vec());
        Ok(())
    }

    /// Release a lease's commitments.
    pub fn release(&mut self, lease_id: &str) {
        self.committed.remove(lease_id);
        if self.exclusive_holder.as_deref() == Some(lease_id) {
            self.exclusive_holder = None;
        }
    }

    /// Whether the machine is currently held exclusively.
    pub fn exclusive_holder(&self) -> Option<&str> {
        self.exclusive_holder.as_deref()
    }

    /// What remains rentable, for an operator quoting a lease.
    pub fn remaining(&self) -> Option<RentableCapacity> {
        let capacity = self.capacity.as_ref()?;
        let mem_used = self.committed_sum(|g| match g {
            DeviceGrant::Memory { mib } => Some(*mib),
            _ => None,
        });
        let store_used = self.committed_sum(|g| match g {
            DeviceGrant::Storage { mib } => Some(*mib),
            _ => None,
        });
        Some(RentableCapacity {
            cpu_cores: capacity.cpu_cores.saturating_sub(self.committed_cpu()),
            memory_mib: capacity.memory_mib.saturating_sub(mem_used),
            accelerator_mib: capacity
                .accelerator_mib
                .iter()
                .map(|(i, offered)| {
                    let free = if self.accelerator_taken_whole(*i).is_some() {
                        0
                    } else {
                        offered.saturating_sub(self.committed_accelerator(*i))
                    };
                    (*i, free)
                })
                .collect(),
            storage_mib: capacity.storage_mib.saturating_sub(store_used),
        })
    }
}

/// What a lease entitles its holder to touch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessScope {
    /// Writable root for the session, inside the sandbox.
    pub workspace: PathBuf,
    /// Devices the session may use.
    pub devices: Vec<DeviceGrant>,
    /// Network reachability.
    #[serde(default)]
    pub network: NetworkGrant,
    /// Per-session wall-clock ceiling, seconds. Clamped to
    /// [`MAX_SESSION_SECS`].
    pub max_session_secs: u64,
    /// The confinement boundary. Not optional — see the module docs.
    pub confinement: ConfinementKind,

    /// Concurrent inference slots guaranteed to this lease.
    ///
    /// Zero — the default — means the holder shares the public pool like any
    /// other caller. A non-zero value is what makes "dedicated access"
    /// literal rather than aspirational: the node sets these slots aside at
    /// lease-open time and unleased traffic cannot occupy them, so a renter
    /// never queues behind free traffic on hardware they are paying for.
    ///
    /// Reserving costs the operator the idle capacity. That is the guarantee
    /// being sold, and [`crate::TrafficManager::reserve_for_lease`] refuses a
    /// lease that would leave too little for everyone else rather than
    /// silently degrading every existing lease.
    #[serde(default)]
    pub reserved_slots: u32,

    /// Model ids kept warm for this lease's term.
    ///
    /// Pinned on open and unpinned on revoke or expiry. Without this a
    /// renter's model can be evicted by least-recently-used pressure to serve
    /// somebody else, and they pay the cold-start on their next request —
    /// which is the opposite of what a dedicated lease promises.
    #[serde(default)]
    pub models: Vec<String>,

    /// Database ids this lease may reach.
    ///
    /// Empty means none: a lease grants no database access unless it says so,
    /// because the shell it opens already sits on the node's own disk and
    /// widening that by default would be a quiet privilege escalation.
    #[serde(default)]
    pub databases: Vec<String>,

    /// Resident memory this lease may hold, in bytes. `None` — the default —
    /// means the holder is bounded only by the node's own memory budget, the
    /// same as any other caller.
    ///
    /// A ceiling is what makes "dedicated" mean something on a coherent-memory
    /// part, where the accelerator pool *is* system RAM: without one, a
    /// lease's pipelines can crowd out the node's own models and the loser is
    /// whichever allocation happens to come second.
    ///
    /// Bytes rather than GB to match `tenzro_memoryBudget`, which the node's
    /// admission control already denominates that way — two units for one
    /// quantity is how a ceiling gets compared against the wrong number. An
    /// integer also keeps this struct `Eq`, which `f64` would not.
    pub max_memory_bytes: Option<u64>,

    /// Site ids this lease may publish, re-point or remove.
    ///
    /// Empty means none, matching `databases` rather than the API-key
    /// allow-lists: a lease is a grant of specific things, so widening it by
    /// default would hand a renter every site the node hosts.
    pub sites: Vec<String>,

    /// Storage deal ids this lease may read and write.
    #[serde(default)]
    pub storage_deals: Vec<String>,

    /// Agent ids this lease may drive.
    #[serde(default)]
    pub agents: Vec<String>,

    /// How the renter reaches all of the above.
    ///
    /// Empty is read as `[Endpoints]`: a lease that names no channel is a
    /// lease for the node's APIs, which is both the common case and the one
    /// that needs no sandbox. Requiring a shell has to be asked for.
    #[serde(default)]
    pub channels: Vec<AccessChannel>,

    /// Whether this lease carves out a slice or takes the machine.
    #[serde(default)]
    pub dedication: DedicationMode,

    /// The billing term this lease was sold on.
    #[serde(default)]
    pub term: RentalTerm,
}

impl AccessScope {
    /// Channels this scope actually grants, applying the empty-means-endpoints
    /// default.
    pub fn effective_channels(&self) -> Vec<AccessChannel> {
        if self.channels.is_empty() {
            vec![AccessChannel::Endpoints]
        } else {
            self.channels.clone()
        }
    }

    /// Whether this lease needs a confinement backend to be honoured.
    ///
    /// Only a shell does. An endpoints-only lease runs no tenant code on the
    /// host, so demanding a sandbox for it would block a safe product on the
    /// absence of a boundary it does not need.
    pub fn requires_confinement(&self) -> bool {
        self.effective_channels()
            .iter()
            .any(|c| c.requires_confinement())
    }

    /// Whether the renter may reach the node's API surfaces.
    pub fn grants_endpoints(&self) -> bool {
        self.effective_channels()
            .contains(&AccessChannel::Endpoints)
    }

    /// Whether the renter may open an interactive shell.
    pub fn grants_shell(&self) -> bool {
        self.effective_channels().contains(&AccessChannel::Shell)
    }
}

impl AccessScope {
    /// The session ceiling actually applied.
    pub fn effective_session_secs(&self) -> u64 {
        self.max_session_secs.clamp(1, MAX_SESSION_SECS)
    }

    /// Accelerator indices this scope grants.
    pub fn accelerators(&self) -> Vec<u32> {
        self.devices
            .iter()
            .filter_map(|d| match d {
                DeviceGrant::Accelerator { index } => Some(*index),
                _ => None,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Lease
// ---------------------------------------------------------------------------

/// Lifecycle of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    /// Sessions may be opened while unexpired.
    Active,
    /// The operator ended it. Terminal — a revoked lease is never reactivated,
    /// because "reactivate" and "issue a new one" differ only in whether the
    /// audit trail shows the gap.
    Revoked,
    /// Its term ran out and the sweep reclaimed what it held.
    ///
    /// Distinct from [`Self::Revoked`] because the two mean different things
    /// to an audit: a revoked lease was ended by a decision, an expired one
    /// simply finished. Also terminal — an expired lease is renewed by issuing
    /// a new one, not by reviving this record.
    Expired,
}

/// An operator's grant of interactive access to one renter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessLease {
    /// Stable identifier.
    pub lease_id: String,
    /// The compute rental this access accompanies, if any. Recorded so the
    /// audit trail joins a session to what was paid for.
    pub rental_id: Option<String>,
    /// The renter's TDIP DID, for the audit record and for an operator
    /// revoking by the name a human used.
    pub renter_did: String,
    /// SHA-256 digest of the service key that selects this lease.
    ///
    /// The digest, never the key: the operator hands the plaintext to the
    /// renter once and the node keeps only enough to recognise it.
    pub service_key_hash: String,
    /// Wallet accounts the operator will accept a passkey ceremony from,
    /// lowercase `0x`-prefixed.
    ///
    /// This is what makes a leaked service key survivable. It is also what
    /// makes a session attributable: the receipt names whichever of these
    /// wallets actually verified, not the lease as a whole.
    pub authorized_wallets: Vec<String>,
    /// What the renter may touch.
    pub scope: AccessScope,
    /// Unix milliseconds after which no session may start.
    pub expires_at_ms: u64,
    /// Current state.
    pub status: LeaseStatus,
    /// Unix milliseconds the lease was opened.
    pub created_at_ms: u64,
}

impl AccessLease {
    /// Whether a session may start right now.
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.status == LeaseStatus::Active && now_ms < self.expires_at_ms
    }

    /// Whether `wallet` is one the operator named on this lease.
    pub fn authorizes_wallet(&self, wallet: &str) -> bool {
        let wallet = wallet.to_ascii_lowercase();
        self.authorized_wallets
            .iter()
            .any(|w| w.to_ascii_lowercase() == wallet)
    }
}

/// A single redemption of a completed passkey ceremony.
///
/// Short-lived and single-use: it exists only to carry "this wallet verified,
/// just now, for this lease" from the browser ceremony across to the shell
/// stream the CLI opens next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellGrant {
    /// 32 random bytes, hex. Presenting it is the authorization to open one
    /// session, so it is treated as a secret and never logged.
    pub grant_id: String,
    /// The lease it was minted against.
    pub lease_id: String,
    /// The wallet that passed the passkey ceremony. This is the accountable
    /// party the session receipt names.
    pub wallet: String,
    /// Unix milliseconds after which it is dead.
    pub expires_at_ms: u64,
}

/// How long a grant stays redeemable.
///
/// Long enough for a CLI to notice the ceremony completed and open a stream;
/// short enough that a grant left in a shell history is worthless by the time
/// anyone reads it.
pub const GRANT_TTL_MS: u64 = 2 * 60 * 1000;

/// Why a session was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessDenied {
    /// No lease is selected by the presented service key.
    #[error("no access lease for this service key")]
    NoLease,
    /// The lease exists but the operator did not name this wallet.
    ///
    /// The message says which wallet was rejected — the caller already knows
    /// which one they used — but never lists the ones that would have worked.
    #[error("wallet {0} is not authorized on this lease")]
    WalletNotAuthorized(String),
    /// No completed passkey ceremony backs this session.
    #[error("no valid session grant; complete the passkey verification first")]
    NoGrant,
    /// The lease exists but the operator ended it.
    #[error("access lease {0} has been revoked")]
    Revoked(String),
    /// The lease exists but its term is over.
    #[error("access lease {0} expired")]
    Expired(String),
    /// The node has no confinement backend, so there is no boundary to run
    /// inside.
    #[error(
        "this node has no confinement backend configured; interactive sessions are refused \
         rather than run on the host"
    )]
    NoConfinement,
}

// ---------------------------------------------------------------------------
// Confinement
// ---------------------------------------------------------------------------

/// A live confined session.
#[async_trait]
pub trait SandboxSession: Send + Sync + std::fmt::Debug {
    /// Write bytes to the session's PTY.
    async fn write_stdin(&self, bytes: &[u8]) -> Result<(), String>;
    /// Read whatever the PTY has produced, blocking until there is some.
    /// Returns an empty vector when the session has ended.
    async fn read_output(&self) -> Result<Vec<u8>, String>;
    /// Tear the sandbox down. Called on disconnect and on the session
    /// deadline.
    async fn shutdown(&self) -> Result<(), String>;
}

/// Creates confined sessions.
///
/// Deliberately has no blanket or default implementation: a node that has not
/// configured one refuses sessions. See the module docs for why the absence of
/// a boundary must mean refusal rather than a weaker boundary.
#[async_trait]
pub trait ConfinementBackend: Send + Sync + std::fmt::Debug {
    /// Which boundary this backend provides.
    fn kind(&self) -> ConfinementKind;

    /// Start a sandbox for `lease` and return a handle to its PTY.
    async fn open(&self, lease: &AccessLease) -> Result<Box<dyn SandboxSession>, String>;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// The node's lease book.
pub struct LeaseRegistry {
    leases: RwLock<HashMap<String, AccessLease>>,
    /// service-key digest → lease id.
    by_service_key: RwLock<HashMap<String, String>>,
    /// Outstanding single-use grants from completed passkey ceremonies.
    ///
    /// In memory only. A grant that did not survive a restart is a session the
    /// user re-verifies for, which costs one browser tap; a grant that *did*
    /// survive one is a credential outliving the process that vouched for it.
    grants: RwLock<HashMap<String, ShellGrant>>,
    storage: Option<Arc<dyn KvStore>>,
    confinement: RwLock<Option<Arc<dyn ConfinementBackend>>>,
    /// Whether this node advertises the TEE-provider role.
    ///
    /// Captured rather than queried so the refusal in [`Self::open_lease`] is
    /// a property of the registry and testable without a whole node.
    serves_tee: bool,
    /// Admission control, for reserving a lease's guaranteed capacity.
    ///
    /// Optional so a registry can be built and tested without a control
    /// plane; a lease asking for reserved slots on a registry with none is
    /// refused rather than silently downgraded to shared capacity, because
    /// selling a guarantee the node cannot keep is worse than declining.
    traffic: Option<Arc<tenzro_model::traffic::TrafficManager>>,
    /// Model lifecycle, for pinning a lease's models warm for its term.
    lifecycle: Option<Arc<tenzro_model::lifecycle::ModelLifecycle>>,
    /// The node's admission policy, so a lease's service key is a *node*
    /// credential rather than one this registry alone recognises.
    ///
    /// There used to be two unrelated registries of "service keys": this one,
    /// scoped and expiring, and a flat digest set in the admission gate with
    /// no scope, expiry or subject. An operator holding a key could not tell
    /// which they had. Registering here makes the lease the single source: the
    /// grant carries the lease's term, so access stops when the rental does
    /// without anyone remembering to revoke it.
    ///
    /// Optional and behind a lock for the same reason as `confinement` — the
    /// registry is constructed before the node's gate exists, and is testable
    /// without one.
    admission: RwLock<Option<Arc<crate::admission::NodeAdmissionGate>>>,
    /// What has been committed to leases, so nothing is sold twice.
    ledger: Option<Arc<parking_lot::Mutex<ResourceLedger>>>,
}

impl LeaseRegistry {
    /// Attach the control plane so leases can reserve capacity and pin models.
    ///
    /// Without this a registry still issues leases, but only shared-capacity
    /// ones: [`Self::open_lease`] refuses any scope asking for
    /// `reserved_slots` or `models`, rather than accepting the lease and
    /// quietly not honouring it.
    pub fn with_control_plane(
        mut self,
        traffic: Arc<tenzro_model::traffic::TrafficManager>,
        lifecycle: Arc<tenzro_model::lifecycle::ModelLifecycle>,
    ) -> Self {
        self.traffic = Some(traffic);
        self.lifecycle = Some(lifecycle);
        self
    }

    /// Attach the rental ledger so device grants are committed and released
    /// with the lease that holds them.
    ///
    /// Without it a lease still opens, but its `devices` are advisory: nothing
    /// stops the same accelerator memory being promised to two tenants.
    pub fn with_resource_ledger(mut self, ledger: Arc<parking_lot::Mutex<ResourceLedger>>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Attach the node's admission gate.
    ///
    /// Every lease already in the book is registered as it is attached, so a
    /// node that rehydrated leases from storage before its gate existed still
    /// ends up with one registry rather than two views of the same keys.
    pub fn set_admission_gate(&self, gate: Arc<crate::admission::NodeAdmissionGate>) {
        for lease in self.leases.read().values() {
            if lease.status == LeaseStatus::Active {
                Self::register_grant(&gate, lease);
            }
        }
        *self.admission.write() = Some(gate);
    }

    /// Surfaces a rental key admits on.
    ///
    /// The model surfaces, not the web API. A renter bought compute and the
    /// models pinned for their term, and reaches them over JSON-RPC, MCP or
    /// A2A. The web API is the operator's own verification and status plane;
    /// renting a GPU does not buy it.
    const RENTAL_SURFACES: [tenzro_auth::ServiceSurface; 3] = [
        tenzro_auth::ServiceSurface::JsonRpc,
        tenzro_auth::ServiceSurface::Mcp,
        tenzro_auth::ServiceSurface::A2a,
    ];

    /// Register one lease's key with the node gate, bounded by its term.
    fn register_grant(gate: &Arc<crate::admission::NodeAdmissionGate>, lease: &AccessLease) {
        gate.accept_grant(
            tenzro_auth::ServiceKeyGrant::unrestricted(tenzro_auth::ServiceKeyHash::from_hex(
                lease.service_key_hash.clone(),
            ))
            .on_surfaces(Self::RENTAL_SURFACES)
            .for_lease(lease.lease_id.clone(), lease.expires_at_ms),
        );
    }

    /// A registry with no persistence and no confinement — refuses everything.
    pub fn new(serves_tee: bool) -> Self {
        Self {
            leases: RwLock::new(HashMap::new()),
            by_service_key: RwLock::new(HashMap::new()),
            grants: RwLock::new(HashMap::new()),
            storage: None,
            confinement: RwLock::new(None),
            serves_tee,
            traffic: None,
            lifecycle: None,
            ledger: None,
            admission: RwLock::new(None),
        }
    }

    /// Rehydrate leases from storage.
    pub fn with_storage(storage: Arc<dyn KvStore>, serves_tee: bool) -> Self {
        let registry = Self {
            leases: RwLock::new(HashMap::new()),
            by_service_key: RwLock::new(HashMap::new()),
            grants: RwLock::new(HashMap::new()),
            storage: Some(storage.clone()),
            confinement: RwLock::new(None),
            serves_tee,
            traffic: None,
            lifecycle: None,
            ledger: None,
            admission: RwLock::new(None),
        };

        match storage.scan_prefix(CF_SETTLEMENTS, LEASE_PREFIX) {
            Ok(rows) => {
                let mut leases = registry.leases.write();
                let mut by_key = registry.by_service_key.write();
                for (_, value) in rows {
                    match serde_json::from_slice::<AccessLease>(&value) {
                        Ok(lease) => {
                            by_key.insert(lease.service_key_hash.clone(), lease.lease_id.clone());
                            leases.insert(lease.lease_id.clone(), lease);
                        }
                        Err(e) => warn!("skipping undecodable access lease: {e}"),
                    }
                }
                if !leases.is_empty() {
                    info!(leases = leases.len(), "restored remote-access leases");
                }
            }
            Err(e) => warn!("could not read access leases: {e}"),
        }

        registry
    }

    /// Install the confinement backend. Without one, sessions are refused.
    pub fn set_confinement(&self, backend: Arc<dyn ConfinementBackend>) {
        *self.confinement.write() = Some(backend);
    }

    /// The configured confinement backend, if any.
    pub fn confinement(&self) -> Option<Arc<dyn ConfinementBackend>> {
        self.confinement.read().clone()
    }

    /// Open a lease.
    ///
    /// Refuses outright on a node that advertises `TeeProvider`: interactive
    /// access to an enclave invalidates the attestation posture that role
    /// claims, and selling both is selling one of them dishonestly.
    pub fn open_lease(&self, lease: AccessLease) -> Result<(), String> {
        if self.serves_tee {
            return Err(
                "this node advertises the TeeProvider role; interactive access would let a \
                 renter read whatever the enclave holds, so its measurement would no longer \
                 mean to a relying party what they take it to mean. Drop the TeeProvider role \
                 or do not rent out a shell — one enclave cannot honestly offer both"
                    .to_string(),
            );
        }
        if lease.service_key_hash.len() != 64
            || !lease
                .service_key_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err("service_key_hash must be a 64-character SHA-256 digest".to_string());
        }
        if lease.authorized_wallets.is_empty() {
            // A lease naming no wallet is a service key with nothing behind
            // it, which is exactly the compromise the wallet list exists to
            // prevent. Refuse rather than create a lease nobody can use and
            // everybody could if the check were ever relaxed.
            return Err(
                "a lease must name at least one authorized wallet; a service key alone is not \
                 an identity and cannot be held accountable for a session"
                    .to_string(),
            );
        }

        let wants_dedicated = lease.scope.reserved_slots > 0 || !lease.scope.models.is_empty();
        if wants_dedicated && (self.traffic.is_none() || self.lifecycle.is_none()) {
            return Err(
                "this lease asks for dedicated capacity or pinned models, but the registry has \
                 no control plane attached. Opening it would sell a guarantee the node cannot \
                 keep — attach one with `with_control_plane`, or open a shared-capacity lease"
                    .to_string(),
            );
        }

        // Commit the device grants first. Selling the same accelerator memory
        // to two tenants has to be refused at open time, not discovered when
        // the second one finds their slice occupied.
        if let Some(ledger) = self.ledger.as_ref()
            && (!lease.scope.devices.is_empty()
                || lease.scope.dedication == DedicationMode::Exclusive)
        {
            ledger
                .lock()
                .commit(
                    &lease.lease_id,
                    &lease.scope.devices,
                    lease.scope.dedication,
                )
                .map_err(|e| format!("cannot open lease {}: {e}", lease.lease_id))?;
        }

        // Reserve BEFORE persisting. Overselling is refused here rather than
        // discovered at the renter's first request, and a lease that cannot
        // be honoured should never reach storage.
        if let (Some(traffic), true) = (self.traffic.as_ref(), lease.scope.reserved_slots > 0) {
            traffic
                .reserve_for_lease(&lease.lease_id, lease.scope.reserved_slots)
                .map_err(|e| format!("cannot open lease {}: {e}", lease.lease_id))?;
        }

        let lease = AccessLease {
            service_key_hash: lease.service_key_hash.to_ascii_lowercase(),
            authorized_wallets: lease
                .authorized_wallets
                .iter()
                .map(|w| w.to_ascii_lowercase())
                .collect(),
            ..lease
        };

        if let Err(e) = self.persist(&lease) {
            // Hand the capacity back. Leaving it reserved against a lease that
            // does not exist would shrink the node permanently, one failed
            // open at a time.
            if let Some(traffic) = self.traffic.as_ref() {
                traffic.release_lease(&lease.lease_id);
            }
            if let Some(ledger) = self.ledger.as_ref() {
                ledger.lock().release(&lease.lease_id);
            }
            return Err(e);
        }

        // Pin the lease's models so LRU pressure from other traffic cannot
        // make the renter pay a cold start on hardware they are renting.
        if let Some(lifecycle) = self.lifecycle.as_ref() {
            for model_id in &lease.scope.models {
                lifecycle.pin(model_id);
            }
        }

        // Make the key a node credential, scoped to the model surfaces and
        // bounded by the lease's own term. Registered after persistence so a
        // key is never admitted for a lease that failed to store.
        if let Some(gate) = self.admission.read().as_ref() {
            Self::register_grant(gate, &lease);
        }

        self.by_service_key
            .write()
            .insert(lease.service_key_hash.clone(), lease.lease_id.clone());
        self.leases.write().insert(lease.lease_id.clone(), lease);
        Ok(())
    }

    /// Mint a lease from a paid compute rental.
    ///
    /// The second provisioning path, alongside an operator opening one by
    /// hand. The rental supplies the *term*: a lease minted this way expires
    /// when the rental's paid epochs run out, so access cannot outlive what
    /// the renter paid for, and an operator cannot accidentally grant a
    /// month's shell against a day's deposit.
    ///
    /// The identity still has to be supplied by the caller. A rental names an
    /// `Address`; a session is authenticated by an Ed25519 key. Deriving one
    /// from the other is not something this module may guess at — a wrong
    /// guess would hand someone else's shell to the wrong party.
    #[allow(clippy::too_many_arguments)]
    pub fn provision_from_rental(
        &self,
        rental_id: &str,
        renter_did: &str,
        service_key_hash: &str,
        authorized_wallets: Vec<String>,
        scope: AccessScope,
        term_ms: u64,
        now_ms: u64,
    ) -> Result<AccessLease, String> {
        if term_ms == 0 {
            return Err(
                "a rental with no remaining paid term grants no access; settle or extend the \
                 rental first"
                    .to_string(),
            );
        }
        let lease = AccessLease {
            lease_id: format!("lease-{rental_id}"),
            rental_id: Some(rental_id.to_string()),
            renter_did: renter_did.to_string(),
            service_key_hash: service_key_hash.to_ascii_lowercase(),
            authorized_wallets,
            scope,
            expires_at_ms: now_ms.saturating_add(term_ms),
            status: LeaseStatus::Active,
            created_at_ms: now_ms,
        };
        self.open_lease(lease.clone())?;
        Ok(lease)
    }

    /// Revoke a lease. Sessions opened under it are refused from the next
    /// authorization onward; live sessions are ended by the caller.
    pub fn revoke_lease(&self, lease_id: &str) -> Result<AccessLease, String> {
        let mut leases = self.leases.write();
        let lease = leases
            .get_mut(lease_id)
            .ok_or_else(|| format!("no such lease: {lease_id}"))?;
        lease.status = LeaseStatus::Revoked;
        let snapshot = lease.clone();
        drop(leases);
        // One action, not two. An outstanding grant is a credential against
        // this lease, and leaving it live would mean revocation had a window.
        self.grants.write().retain(|_, g| g.lease_id != lease_id);

        // The same reasoning reaches the node gate: a revoked lease whose key
        // still admitted on the service surfaces would be a revocation that
        // only closed the shell. Recorded as a revocation rather than a
        // removal so a config reload cannot re-admit the digest.
        if let Some(gate) = self.admission.read().as_ref()
            && let Err(e) = gate.revoke_key(&snapshot.service_key_hash)
        {
            warn!(
                lease = %lease_id,
                error = %e,
                "lease revoked but its service key could not be revoked on the node gate"
            );
        }

        // Return the guaranteed capacity. Requests already running against it
        // keep going — a revocation must not kill work mid-generation — and
        // their slots drain back to the public pool as they finish.
        if let Some(traffic) = self.traffic.as_ref() {
            traffic.release_lease(lease_id);
        }
        if let Some(ledger) = self.ledger.as_ref() {
            ledger.lock().release(lease_id);
        }

        // Unpin the lease's models. They stay warm until ordinary LRU pressure
        // reclaims them, so a revocation does not cost the next caller a
        // needless eviction.
        if let Some(lifecycle) = self.lifecycle.as_ref() {
            for model_id in &snapshot.scope.models {
                lifecycle.unpin(model_id);
            }
        }

        self.persist(&snapshot)?;
        Ok(snapshot)
    }

    /// Look a lease up by id.
    pub fn get(&self, lease_id: &str) -> Option<AccessLease> {
        self.leases.read().get(lease_id).cloned()
    }

    /// Every lease, newest first by creation.
    pub fn list(&self) -> Vec<AccessLease> {
        let mut all: Vec<_> = self.leases.read().values().cloned().collect();
        all.sort_by_key(|l| std::cmp::Reverse(l.created_at_ms));
        all
    }

    /// Stage one: which lease does this service key select?
    ///
    /// Deliberately does *not* authorize a session. A caller holding the key
    /// has established which lease they mean and nothing more; the passkey
    /// ceremony is what establishes who they are.
    pub fn lease_for_service_key(
        &self,
        service_key: &str,
        now_ms: u64,
    ) -> Result<AccessLease, AccessDenied> {
        let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            service_key.as_bytes(),
        ));
        let lease_id = self
            .by_service_key
            .read()
            .get(&digest)
            .cloned()
            .ok_or(AccessDenied::NoLease)?;
        let lease = self
            .leases
            .read()
            .get(&lease_id)
            .cloned()
            .ok_or(AccessDenied::NoLease)?;

        if lease.status == LeaseStatus::Revoked {
            return Err(AccessDenied::Revoked(lease.lease_id));
        }
        if now_ms >= lease.expires_at_ms {
            return Err(AccessDenied::Expired(lease.lease_id));
        }
        // Checked here, before the operator's user is sent off to a browser:
        // a node with nowhere safe to run the session should say so at the
        // first step rather than after a passkey tap.
        //
        // Only a shell needs the boundary. An endpoints-only lease runs no
        // tenant code on the host — the renter calls handlers that already
        // gate every request — so demanding a sandbox for it would block a
        // safe product on the absence of a boundary it does not use.
        if lease.scope.requires_confinement() && self.confinement.read().is_none() {
            return Err(AccessDenied::NoConfinement);
        }
        Ok(lease)
    }

    /// Release everything held by leases that have passed their expiry.
    ///
    /// Expiry already stops new sessions — `is_live` checks it — but that is
    /// only half of what an expiry means. Without this, an expired lease goes
    /// on holding its reserved concurrency slots, its committed accelerator
    /// memory, and its pinned models indefinitely, so a node that rented out
    /// capacity for an hour a month ago is still short that capacity today.
    /// The operator sees a machine that is mysteriously smaller than it should
    /// be, with nothing obviously wrong.
    ///
    /// Returns the ids swept. Idempotent: a lease already expired-and-swept is
    /// skipped, so running this on a timer costs nothing.
    pub fn sweep_expired(&self, now_ms: u64) -> Vec<String> {
        let expired: Vec<AccessLease> = {
            let leases = self.leases.read();
            leases
                .values()
                .filter(|l| l.status == LeaseStatus::Active && now_ms >= l.expires_at_ms)
                .cloned()
                .collect()
        };
        if expired.is_empty() {
            return Vec::new();
        }

        let mut swept = Vec::with_capacity(expired.len());
        for lease in expired {
            {
                let mut leases = self.leases.write();
                if let Some(live) = leases.get_mut(&lease.lease_id) {
                    live.status = LeaseStatus::Expired;
                }
            }
            // Same three releases as revocation, and for the same reason: a
            // credential or a claim that outlives the lease it belonged to is
            // the thing being prevented.
            self.grants
                .write()
                .retain(|_, g| g.lease_id != lease.lease_id);
            if let Some(traffic) = self.traffic.as_ref() {
                traffic.release_lease(&lease.lease_id);
            }
            if let Some(ledger) = self.ledger.as_ref() {
                ledger.lock().release(&lease.lease_id);
            }
            if let Some(lifecycle) = self.lifecycle.as_ref() {
                for model_id in &lease.scope.models {
                    lifecycle.unpin(model_id);
                }
            }

            let mut snapshot = lease.clone();
            snapshot.status = LeaseStatus::Expired;
            if let Err(e) = self.persist(&snapshot) {
                // The in-memory release already happened, which is the part
                // that matters for capacity. Log rather than abort the sweep:
                // one unpersistable lease must not stop the others being
                // reclaimed.
                warn!(lease_id = %lease.lease_id, error = %e, "could not persist lease expiry");
            }
            info!(lease_id = %lease.lease_id, "Lease expired; capacity released");
            swept.push(lease.lease_id);
        }
        swept
    }

    /// Stage two: a wallet has completed the passkey ceremony. Mint the
    /// single-use grant the CLI will present when it opens the stream.
    ///
    /// The wallet-list check lives here rather than at the ceremony because
    /// this is the point where "someone proved they hold wallet X" becomes
    /// "wallet X may use this hardware" — two claims the operator controls
    /// separately.
    pub fn mint_grant(
        &self,
        lease: &AccessLease,
        wallet: &str,
        grant_id: String,
        now_ms: u64,
    ) -> Result<ShellGrant, AccessDenied> {
        if !lease.authorizes_wallet(wallet) {
            return Err(AccessDenied::WalletNotAuthorized(wallet.to_string()));
        }
        let grant = ShellGrant {
            grant_id,
            lease_id: lease.lease_id.clone(),
            wallet: wallet.to_ascii_lowercase(),
            expires_at_ms: now_ms.saturating_add(GRANT_TTL_MS),
        };
        self.grants
            .write()
            .insert(grant.grant_id.clone(), grant.clone());
        Ok(grant)
    }

    /// Stage three: redeem a grant to open one session.
    ///
    /// Single-use — the grant is removed whether or not it turns out to be
    /// valid, so a replayed grant id fails on its second presentation even if
    /// the first one raced. The lease is re-read rather than trusted from the
    /// grant, so a revocation between minting and redeeming still bites.
    pub fn redeem_grant(
        &self,
        grant_id: &str,
        now_ms: u64,
    ) -> Result<(AccessLease, ShellGrant), AccessDenied> {
        let grant = self
            .grants
            .write()
            .remove(grant_id)
            .ok_or(AccessDenied::NoGrant)?;
        if now_ms >= grant.expires_at_ms {
            return Err(AccessDenied::NoGrant);
        }

        let lease = self
            .leases
            .read()
            .get(&grant.lease_id)
            .cloned()
            .ok_or(AccessDenied::NoLease)?;
        if lease.status == LeaseStatus::Revoked {
            return Err(AccessDenied::Revoked(lease.lease_id));
        }
        if now_ms >= lease.expires_at_ms {
            return Err(AccessDenied::Expired(lease.lease_id));
        }
        // Re-checked at redemption: the operator may have dropped this wallet
        // from the list in the two minutes since the ceremony.
        if !lease.authorizes_wallet(&grant.wallet) {
            return Err(AccessDenied::WalletNotAuthorized(grant.wallet));
        }
        if lease.scope.requires_confinement() && self.confinement.read().is_none() {
            return Err(AccessDenied::NoConfinement);
        }
        Ok((lease, grant))
    }

    /// File the receipt a finished session produced.
    ///
    /// The session driver used to build this envelope, log its commitment, and
    /// drop it. That made the audit trail a line in the operator's log rather
    /// than a record — unretrievable through any API, gone with log rotation,
    /// and impossible to answer "who had a shell on this box last month" from.
    /// A bounded, retrievable transcript is the bar the IAP/SSM comparison
    /// sets, and a commitment in a log file does not meet it.
    ///
    /// A node with no storage keeps the previous behaviour of not filing
    /// anything, rather than failing the session: the renter's work is done
    /// and refusing to return from it would help nobody.
    pub fn record_session_receipt(
        &self,
        lease_id: &str,
        started_ms: u64,
        receipt: &tenzro_storage::da::ReceiptEnvelope,
    ) -> Result<(), String> {
        let Some(store) = self.storage.as_ref() else {
            return Ok(());
        };
        let body = serde_json::to_vec(receipt).map_err(|e| e.to_string())?;
        let mut key = SESSION_RECEIPT_PREFIX.to_vec();
        // Zero-padded so the lexicographic scan order is chronological.
        key.extend_from_slice(
            format!("{lease_id}:{started_ms:020}:{}", receipt.commitment).as_bytes(),
        );
        store
            .put(CF_SETTLEMENTS, &key, &body)
            .map_err(|e| format!("session receipt persist failed: {e}"))
    }

    /// Filed session receipts, oldest first. `lease_id` narrows to one lease.
    pub fn session_receipts(
        &self,
        lease_id: Option<&str>,
    ) -> Vec<tenzro_storage::da::ReceiptEnvelope> {
        let Some(store) = self.storage.as_ref() else {
            return Vec::new();
        };
        let mut prefix = SESSION_RECEIPT_PREFIX.to_vec();
        if let Some(id) = lease_id {
            prefix.extend_from_slice(format!("{id}:").as_bytes());
        }
        let mut rows = match store.scan_prefix(CF_SETTLEMENTS, &prefix) {
            Ok(r) => r,
            Err(e) => {
                warn!("could not read session receipts: {e}");
                return Vec::new();
            }
        };
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows.into_iter()
            .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
            .collect()
    }

    fn persist(&self, lease: &AccessLease) -> Result<(), String> {
        let Some(store) = self.storage.as_ref() else {
            return Ok(());
        };
        let body = serde_json::to_vec(lease).map_err(|e| e.to_string())?;

        let mut key = LEASE_PREFIX.to_vec();
        key.extend_from_slice(lease.lease_id.as_bytes());
        store
            .put(CF_SETTLEMENTS, &key, &body)
            .map_err(|e| format!("lease persist failed: {e}"))?;

        let mut index = RENTER_INDEX_PREFIX.to_vec();
        index.extend_from_slice(lease.service_key_hash.as_bytes());
        store
            .put(CF_SETTLEMENTS, &index, lease.lease_id.as_bytes())
            .map_err(|e| format!("lease index persist failed: {e}"))
    }
}

impl std::fmt::Debug for LeaseRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseRegistry")
            .field("leases", &self.leases.read().len())
            .field("serves_tee", &self.serves_tee)
            .field(
                "confinement",
                &self.confinement.read().as_ref().map(|c| c.kind()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    const KEY: &str = "operator-issued-service-key";
    const WALLET: &str = "0xabc0000000000000000000000000000000000001";
    const OTHER_WALLET: &str = "0xdef0000000000000000000000000000000000002";

    #[derive(Debug)]
    struct FakeKata;

    #[async_trait]
    impl ConfinementBackend for FakeKata {
        fn kind(&self) -> ConfinementKind {
            ConfinementKind::KataVm
        }
        async fn open(&self, _lease: &AccessLease) -> Result<Box<dyn SandboxSession>, String> {
            Err("not used in these tests".to_string())
        }
    }

    fn digest(key: &str) -> String {
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(key.as_bytes()))
    }

    fn scope() -> AccessScope {
        AccessScope {
            workspace: PathBuf::from("/workspace"),
            devices: vec![
                DeviceGrant::Cpu { cores: 4 },
                DeviceGrant::Accelerator { index: 0 },
                DeviceGrant::Memory { mib: 32_768 },
            ],
            network: NetworkGrant::None,
            max_session_secs: 3600,
            confinement: ConfinementKind::KataVm,
            // Test fixtures share the public pool and pin nothing.
            reserved_slots: 0,
            models: Vec::new(),
            max_memory_bytes: None,
            sites: Vec::new(),
            databases: Vec::new(),
            storage_deals: Vec::new(),
            agents: Vec::new(),
            channels: Vec::new(),
            dedication: DedicationMode::Partial,
            term: RentalTerm::Hourly,
        }
    }

    fn lease(key: &str, expires_at_ms: u64) -> AccessLease {
        AccessLease {
            lease_id: format!("lease-{key}"),
            rental_id: Some("rental-1".to_string()),
            renter_did: "did:tenzro:human:abc".to_string(),
            service_key_hash: digest(key),
            authorized_wallets: vec![WALLET.to_string()],
            scope: scope(),
            expires_at_ms,
            status: LeaseStatus::Active,
            created_at_ms: 0,
        }
    }

    // ── Carve-outs, channels, and terms ──────────────────────────────

    fn capacity() -> RentableCapacity {
        RentableCapacity {
            cpu_cores: 16,
            memory_mib: 64 * 1024,
            accelerator_mib: HashMap::from([(0, 60 * 1024)]),
            storage_mib: 500 * 1024,
        }
    }

    #[test]
    fn an_operator_can_rent_a_slice_of_an_accelerator_not_only_the_whole_thing() {
        // The point of the carve-out. On unified-memory hardware, granting
        // "accelerator 0" hands over the pool the node runs from, so a
        // fractional grant is the only way to rent a GPU without renting the
        // machine.
        let mut ledger = ResourceLedger::new(capacity());
        ledger
            .commit(
                "a",
                &[DeviceGrant::AcceleratorMemory {
                    index: 0,
                    mib: 20 * 1024,
                }],
                DedicationMode::Partial,
            )
            .expect("20 of 60 GiB");
        ledger
            .commit(
                "b",
                &[DeviceGrant::AcceleratorMemory {
                    index: 0,
                    mib: 30 * 1024,
                }],
                DedicationMode::Partial,
            )
            .expect("another 30 — the same device serves both");

        let left = ledger.remaining().expect("declared");
        assert_eq!(left.accelerator_mib[&0], 10 * 1024);
    }

    #[test]
    fn the_same_resource_cannot_be_sold_twice() {
        let mut ledger = ResourceLedger::new(capacity());
        ledger
            .commit(
                "a",
                &[DeviceGrant::AcceleratorMemory {
                    index: 0,
                    mib: 50 * 1024,
                }],
                DedicationMode::Partial,
            )
            .expect("fits");
        let err = ledger
            .commit(
                "b",
                &[DeviceGrant::AcceleratorMemory {
                    index: 0,
                    mib: 20 * 1024,
                }],
                DedicationMode::Partial,
            )
            .expect_err("only 10 GiB remain");
        assert!(err.resource.contains("accelerator 0"), "{err}");
        assert_eq!(err.available, 10 * 1024);
    }

    #[test]
    fn a_whole_accelerator_and_a_slice_of_it_are_mutually_exclusive() {
        // Either direction is an oversell, and both are easy to do by
        // accident when quoting two leases minutes apart.
        let mut ledger = ResourceLedger::new(capacity());
        ledger
            .commit(
                "slice",
                &[DeviceGrant::AcceleratorMemory {
                    index: 0,
                    mib: 1024,
                }],
                DedicationMode::Partial,
            )
            .expect("fits");
        assert!(
            ledger
                .commit(
                    "whole",
                    &[DeviceGrant::Accelerator { index: 0 }],
                    DedicationMode::Partial
                )
                .is_err(),
            "cannot hand over a device already sliced"
        );

        let mut other = ResourceLedger::new(capacity());
        other
            .commit(
                "whole",
                &[DeviceGrant::Accelerator { index: 0 }],
                DedicationMode::Partial,
            )
            .expect("fits");
        assert!(
            other
                .commit(
                    "slice",
                    &[DeviceGrant::AcceleratorMemory {
                        index: 0,
                        mib: 1024
                    }],
                    DedicationMode::Partial
                )
                .is_err(),
            "cannot slice a device already handed over whole"
        );
    }

    #[test]
    fn renting_the_whole_machine_must_be_asked_for_and_blocks_everything_else() {
        let mut ledger = ResourceLedger::new(capacity());
        ledger
            .commit("whole", &[], DedicationMode::Exclusive)
            .expect("nothing else is out");
        assert_eq!(ledger.exclusive_holder(), Some("whole"));

        let err = ledger
            .commit(
                "other",
                &[DeviceGrant::Cpu { cores: 1 }],
                DedicationMode::Partial,
            )
            .expect_err("the machine is taken");
        assert!(err.resource.contains("whole machine"), "{err}");

        ledger.release("whole");
        assert_eq!(ledger.exclusive_holder(), None);
        ledger
            .commit(
                "other",
                &[DeviceGrant::Cpu { cores: 1 }],
                DedicationMode::Partial,
            )
            .expect("released");
    }

    #[test]
    fn exclusive_cannot_displace_tenants_who_are_already_there() {
        // They did not agree to be evicted mid-term.
        let mut ledger = ResourceLedger::new(capacity());
        ledger
            .commit(
                "sitting",
                &[DeviceGrant::Cpu { cores: 2 }],
                DedicationMode::Partial,
            )
            .expect("fits");
        let err = ledger
            .commit("greedy", &[], DedicationMode::Exclusive)
            .expect_err("someone is already here");
        assert!(err.resource.contains("existing lease"), "{err}");
    }

    #[test]
    fn a_ledger_with_no_declared_capacity_rents_nothing() {
        // An operator who has not said what is for sale has not opted in.
        // Reading silence as "everything" would be the worst possible default.
        let mut ledger = ResourceLedger::default();
        let err = ledger
            .commit(
                "a",
                &[DeviceGrant::Cpu { cores: 1 }],
                DedicationMode::Partial,
            )
            .expect_err("nothing declared");
        assert!(err.resource.contains("none declared"), "{err}");
    }

    #[test]
    fn cpu_memory_and_storage_are_each_bounded_separately() {
        let mut ledger = ResourceLedger::new(capacity());
        assert!(
            ledger
                .commit(
                    "a",
                    &[DeviceGrant::Cpu { cores: 99 }],
                    DedicationMode::Partial
                )
                .is_err()
        );
        assert!(
            ledger
                .commit(
                    "b",
                    &[DeviceGrant::Memory { mib: 999 * 1024 }],
                    DedicationMode::Partial
                )
                .is_err()
        );
        let err = ledger
            .commit(
                "c",
                &[DeviceGrant::Storage { mib: 999 * 1024 }],
                DedicationMode::Partial,
            )
            .expect_err("disk is finite too");
        assert_eq!(err.resource, "storage_mib");
    }

    #[test]
    fn a_lease_naming_no_channel_is_an_endpoints_lease() {
        // The common case: a tenant came for the models, not for a machine.
        let s = scope();
        assert!(s.channels.is_empty());
        assert_eq!(s.effective_channels(), vec![AccessChannel::Endpoints]);
        assert!(s.grants_endpoints());
        assert!(!s.grants_shell());
        assert!(!s.requires_confinement());
    }

    #[test]
    fn only_a_shell_lease_needs_a_confinement_backend() {
        // Before this split, a missing Kata launcher blocked every lease —
        // including ones that would never run a process on the host.
        let shell = AccessScope {
            channels: vec![AccessChannel::Shell],
            ..scope()
        };
        assert!(shell.requires_confinement());

        let both = AccessScope {
            channels: vec![AccessChannel::Endpoints, AccessChannel::Shell],
            ..scope()
        };
        assert!(
            both.requires_confinement(),
            "any shell drags in the boundary"
        );
    }

    #[test]
    fn an_endpoints_lease_opens_on_a_node_with_no_sandbox() {
        // The gap this closes: an operator with no launcher could rent
        // nothing at all, even pure API access.
        let registry = LeaseRegistry::new(false); // no confinement set
        let mut l = lease("k1", u64::MAX);
        l.scope = AccessScope {
            channels: vec![AccessChannel::Endpoints],
            ..scope()
        };
        registry.open_lease(l).expect("opens");

        let resolved = registry
            .lease_for_service_key("k1", 1)
            .expect("endpoints need no boundary");
        assert!(resolved.scope.grants_endpoints());
    }

    #[test]
    fn a_shell_lease_is_still_refused_without_a_sandbox() {
        // The load-bearing rule must survive the split intact.
        let registry = LeaseRegistry::new(false);
        let mut l = lease("k1", u64::MAX);
        l.scope = AccessScope {
            channels: vec![AccessChannel::Shell],
            ..scope()
        };
        registry.open_lease(l).expect("opens");
        assert!(matches!(
            registry.lease_for_service_key("k1", 1),
            Err(AccessDenied::NoConfinement)
        ));
    }

    #[test]
    fn rental_terms_price_and_span_the_right_amount_of_time() {
        assert_eq!(RentalTerm::Hourly.seconds(), 3_600);
        assert_eq!(RentalTerm::Weekly.seconds(), 7 * 86_400);
        assert_eq!(RentalTerm::Monthly.seconds(), 30 * 86_400);
        assert_eq!(RentalTerm::Annual.seconds(), 365 * 86_400);

        // 100/hour for one week.
        assert_eq!(RentalTerm::Weekly.total_price(100, 1), 100 * 24 * 7);
        // Three months.
        assert_eq!(RentalTerm::Monthly.total_price(100, 3), 100 * 24 * 30 * 3);
        assert_eq!(
            RentalTerm::Hourly.duration_ms(5),
            5 * 3_600 * 1_000,
            "duration must match the price basis or a lease outlives what was paid"
        );
    }

    #[test]
    fn the_default_term_is_the_shortest_commitment() {
        // An operator should fall into the term they can exit fastest.
        assert_eq!(RentalTerm::default(), RentalTerm::Hourly);
        assert_eq!(DedicationMode::default(), DedicationMode::Partial);
    }

    /// A scope asking for dedicated capacity and warm models.
    fn dedicated_scope(slots: u32, models: &[&str]) -> AccessScope {
        AccessScope {
            reserved_slots: slots,
            models: models.iter().map(|m| m.to_string()).collect(),
            ..scope()
        }
    }

    /// A registry with a real control plane behind it.
    fn with_plane(
        max_concurrent: u32,
        public_floor: u32,
    ) -> (
        LeaseRegistry,
        Arc<tenzro_model::traffic::TrafficManager>,
        Arc<tenzro_model::lifecycle::ModelLifecycle>,
    ) {
        let traffic = Arc::new(tenzro_model::traffic::TrafficManager::new(
            tenzro_model::traffic::TrafficConfig {
                max_concurrent,
                max_concurrent_batch: max_concurrent / 2,
                max_queue_depth: 64,
                public_floor,
            },
        ));
        let lifecycle = Arc::new(tenzro_model::lifecycle::ModelLifecycle::new());
        let registry = LeaseRegistry::new(false)
            .with_control_plane(Arc::clone(&traffic), Arc::clone(&lifecycle));
        registry.set_confinement(Arc::new(FakeKata));
        (registry, traffic, lifecycle)
    }

    /// A registry with a real ledger behind it.
    fn with_ledger(
        cap: RentableCapacity,
    ) -> (LeaseRegistry, Arc<parking_lot::Mutex<ResourceLedger>>) {
        let ledger = Arc::new(parking_lot::Mutex::new(ResourceLedger::new(cap)));
        let registry = LeaseRegistry::new(false).with_resource_ledger(Arc::clone(&ledger));
        registry.set_confinement(Arc::new(FakeKata));
        (registry, ledger)
    }

    #[test]
    fn an_expired_lease_gives_back_everything_it_held() {
        // The bug this fixes: expiry already stopped new sessions, but the
        // lease went on holding its reserved slots, its committed accelerator
        // memory and its pinned models forever. A node that rented capacity
        // for an hour last month was still short that capacity today, with
        // nothing obviously wrong.
        let traffic = Arc::new(tenzro_model::traffic::TrafficManager::new(
            tenzro_model::traffic::TrafficConfig {
                max_concurrent: 16,
                max_concurrent_batch: 8,
                max_queue_depth: 64,
                public_floor: 2,
            },
        ));
        let lifecycle = Arc::new(tenzro_model::lifecycle::ModelLifecycle::new());
        let ledger = Arc::new(parking_lot::Mutex::new(ResourceLedger::new(capacity())));
        let registry = LeaseRegistry::new(false)
            .with_control_plane(Arc::clone(&traffic), Arc::clone(&lifecycle))
            .with_resource_ledger(Arc::clone(&ledger));
        registry.set_confinement(Arc::new(FakeKata));

        let mut l = lease("k1", 1_000);
        l.scope = AccessScope {
            reserved_slots: 4,
            models: vec!["rented-model".to_string()],
            devices: vec![DeviceGrant::Cpu { cores: 8 }],
            ..scope()
        };
        registry.open_lease(l).expect("opens");
        assert_eq!(traffic.stats().reserved_slots, 4);
        assert!(lifecycle.is_pinned("rented-model"));
        assert_eq!(ledger.lock().remaining().unwrap().cpu_cores, 8);

        // Before the term ends, nothing is reclaimed.
        assert!(registry.sweep_expired(999).is_empty());
        assert_eq!(traffic.stats().reserved_slots, 4);

        let swept = registry.sweep_expired(1_001);
        assert_eq!(swept, vec!["lease-k1".to_string()]);
        assert_eq!(traffic.stats().reserved_slots, 0, "slots came back");
        assert!(!lifecycle.is_pinned("rented-model"), "model unpinned");
        assert_eq!(
            ledger.lock().remaining().unwrap().cpu_cores,
            16,
            "cores back"
        );
    }

    #[test]
    fn sweeping_twice_reclaims_once() {
        // It runs on a timer, so a second pass over an already-expired lease
        // must cost nothing rather than double-releasing.
        let registry = confined(false);
        registry.open_lease(lease("k1", 1_000)).expect("opens");
        assert_eq!(registry.sweep_expired(2_000).len(), 1);
        assert!(registry.sweep_expired(3_000).is_empty());
    }

    #[test]
    fn expiry_invalidates_outstanding_grants() {
        // A grant is a credential against the lease. One that outlives its
        // lease is exactly what revocation exists to prevent, and expiry is
        // no different.
        let registry = confined(false);
        registry.open_lease(lease(KEY, 5_000)).expect("opens");
        let resolved = registry
            .lease_for_service_key(KEY, 0)
            .expect("lease resolves");
        let grant = registry
            .mint_grant(&resolved, WALLET, "grant-1".to_string(), 0)
            .expect("ceremony completes");

        registry.sweep_expired(6_000);
        assert!(
            registry.redeem_grant(&grant.grant_id, 6_001).is_err(),
            "a grant must not survive its lease expiring"
        );
    }

    #[test]
    fn an_expired_lease_is_marked_expired_not_revoked() {
        // The two mean different things to an audit: revoked was a decision,
        // expired simply finished.
        let registry = confined(false);
        registry.open_lease(lease("k1", 100)).expect("opens");
        registry.sweep_expired(200);
        let all = registry.list();
        let l = all
            .iter()
            .find(|l| l.lease_id == "lease-k1")
            .expect("still on record");
        assert_eq!(l.status, LeaseStatus::Expired);
    }

    #[test]
    fn opening_a_lease_commits_its_device_grants() {
        let (registry, ledger) = with_ledger(capacity());
        let mut l = lease("k1", u64::MAX);
        l.scope = AccessScope {
            devices: vec![DeviceGrant::AcceleratorMemory {
                index: 0,
                mib: 20 * 1024,
            }],
            ..scope()
        };
        registry.open_lease(l).expect("fits");

        let left = ledger.lock().remaining().expect("declared");
        assert_eq!(
            left.accelerator_mib[&0],
            40 * 1024,
            "60 offered minus 20 sold"
        );
    }

    #[test]
    fn a_second_lease_cannot_be_sold_the_same_slice() {
        // The failure this exists to prevent: two tenants each told they hold
        // the same accelerator memory, discovered when the second one finds
        // it occupied.
        let (registry, _) = with_ledger(capacity());
        let mut first = lease("k1", u64::MAX);
        first.scope = AccessScope {
            devices: vec![DeviceGrant::AcceleratorMemory {
                index: 0,
                mib: 50 * 1024,
            }],
            ..scope()
        };
        registry.open_lease(first).expect("fits");

        let mut second = lease("k2", u64::MAX);
        second.scope = AccessScope {
            devices: vec![DeviceGrant::AcceleratorMemory {
                index: 0,
                mib: 20 * 1024,
            }],
            ..scope()
        };
        let err = registry.open_lease(second).expect_err("only 10 GiB remain");
        assert!(err.contains("accelerator 0"), "{err}");
    }

    #[test]
    fn revoking_a_lease_returns_its_devices_to_the_pool() {
        let (registry, ledger) = with_ledger(capacity());
        let mut l = lease("k1", u64::MAX);
        l.scope = AccessScope {
            devices: vec![DeviceGrant::Cpu { cores: 8 }],
            ..scope()
        };
        registry.open_lease(l).expect("fits");
        assert_eq!(ledger.lock().remaining().unwrap().cpu_cores, 8);

        registry.revoke_lease("lease-k1").expect("revokes");
        assert_eq!(ledger.lock().remaining().unwrap().cpu_cores, 16);
    }

    #[test]
    fn an_exclusive_lease_blocks_every_later_one() {
        let (registry, ledger) = with_ledger(capacity());
        let mut whole = lease("k1", u64::MAX);
        whole.scope = AccessScope {
            devices: Vec::new(),
            dedication: DedicationMode::Exclusive,
            ..scope()
        };
        registry.open_lease(whole).expect("nothing else is out");
        assert_eq!(ledger.lock().exclusive_holder(), Some("lease-k1"));

        let mut other = lease("k2", u64::MAX);
        other.scope = AccessScope {
            devices: vec![DeviceGrant::Cpu { cores: 1 }],
            ..scope()
        };
        assert!(registry.open_lease(other).is_err(), "the machine is taken");
    }

    #[test]
    fn a_registry_with_no_ledger_still_opens_ordinary_leases() {
        // Device grants become advisory without a ledger, which is the right
        // behaviour for a node that has not opted into renting at all.
        let registry = confined(false);
        let mut l = lease("k1", u64::MAX);
        l.scope = AccessScope {
            devices: vec![DeviceGrant::Cpu { cores: 4 }],
            ..scope()
        };
        registry.open_lease(l).expect("opens without a ledger");
    }

    #[test]
    fn opening_a_dedicated_lease_reserves_capacity_and_pins_its_models() {
        let (registry, traffic, lifecycle) = with_plane(8, 2);
        let mut l = lease("k1", u64::MAX);
        l.scope = dedicated_scope(4, &["qwen3.6-35b-a3b"]);

        registry.open_lease(l).expect("4 of 8 with a floor of 2");

        assert_eq!(traffic.stats().reserved_slots, 4);
        assert!(
            lifecycle.is_pinned("qwen3.6-35b-a3b"),
            "a rented model must not be LRU-evicted for someone else's request"
        );
    }

    #[test]
    fn a_lease_that_would_oversell_the_node_is_refused_at_open() {
        // Refusing the sale beats accepting it and silently degrading every
        // lease already running.
        let (registry, traffic, _) = with_plane(8, 2);
        let mut first = lease("k1", u64::MAX);
        first.scope = dedicated_scope(6, &[]);
        registry.open_lease(first).expect("6 of the 6 sellable");

        let mut second = lease("k2", u64::MAX);
        second.scope = dedicated_scope(2, &[]);
        let err = registry
            .open_lease(second)
            .expect_err("nothing sellable remains");
        assert!(err.contains("public traffic"), "{err}");
        assert_eq!(
            traffic.stats().reserved_slots,
            6,
            "unchanged by the refusal"
        );
    }

    #[test]
    fn revoking_a_dedicated_lease_returns_capacity_and_unpins() {
        let (registry, traffic, lifecycle) = with_plane(8, 2);
        let mut l = lease("k1", u64::MAX);
        l.scope = dedicated_scope(4, &["m1", "m2"]);
        registry.open_lease(l).expect("opens");

        registry.revoke_lease("lease-k1").expect("revokes");

        assert_eq!(traffic.stats().reserved_slots, 0);
        assert!(!lifecycle.is_pinned("m1"));
        assert!(!lifecycle.is_pinned("m2"));
    }

    #[test]
    fn a_dedicated_lease_is_refused_when_no_control_plane_is_attached() {
        // Accepting it would sell a guarantee nothing can keep. A registry
        // with no plane may still issue ordinary shared-capacity leases.
        let registry = confined(false);
        let mut l = lease("k1", u64::MAX);
        l.scope = dedicated_scope(4, &[]);
        let err = registry
            .open_lease(l)
            .expect_err("no plane means no guarantee");
        assert!(err.contains("control plane"), "{err}");

        let plain = lease("k2", u64::MAX);
        registry
            .open_lease(plain)
            .expect("a shared-capacity lease needs no plane");
    }

    #[test]
    fn a_shared_capacity_lease_reserves_nothing() {
        // The default must stay free: most leases are ordinary, and reserving
        // for them would strand capacity nobody asked to buy.
        let (registry, traffic, _) = with_plane(8, 2);
        registry.open_lease(lease("k1", u64::MAX)).expect("opens");
        assert_eq!(traffic.stats().reserved_slots, 0);
        assert_eq!(traffic.sellable_slots(), 6);
    }

    fn confined(serves_tee: bool) -> LeaseRegistry {
        let r = LeaseRegistry::new(serves_tee);
        r.set_confinement(Arc::new(FakeKata));
        r
    }

    /// The happy path, end to end: key selects the lease, the wallet that
    /// passkey-verified gets a grant, the grant opens one session.
    fn open_session(
        r: &LeaseRegistry,
        key: &str,
        wallet: &str,
        now: u64,
    ) -> Result<(AccessLease, ShellGrant), AccessDenied> {
        let lease = r.lease_for_service_key(key, now)?;
        let grant = r.mint_grant(&lease, wallet, "grant-1".to_string(), now)?;
        r.redeem_grant(&grant.grant_id, now)
    }

    // ---- the three factors -------------------------------------------------

    #[test]
    fn key_plus_authorized_wallet_opens_a_session() {
        let r = confined(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        let (lease, grant) = open_session(&r, KEY, WALLET, 0).unwrap();
        assert_eq!(grant.wallet, WALLET);
        assert_eq!(grant.lease_id, lease.lease_id);
    }

    /// The point of the wallet list: a leaked service key is not a
    /// compromise, because the leaker's wallet is not on it.
    #[test]
    fn a_leaked_service_key_opens_nothing_for_an_unlisted_wallet() {
        let r = confined(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        // The thief can select the lease — that is all a key does.
        assert!(r.lease_for_service_key(KEY, 0).is_ok());
        assert_eq!(
            open_session(&r, KEY, OTHER_WALLET, 0),
            Err(AccessDenied::WalletNotAuthorized(OTHER_WALLET.to_string()))
        );
    }

    #[test]
    fn a_wrong_service_key_selects_no_lease() {
        let r = confined(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        assert_eq!(
            r.lease_for_service_key("guess", 0).unwrap_err(),
            AccessDenied::NoLease
        );
    }

    /// A passkey ceremony that never happened means no grant, and no grant
    /// means no session however good the key is.
    #[test]
    fn a_service_key_alone_opens_no_session() {
        let r = confined(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        assert_eq!(
            r.redeem_grant("never-minted", 0).unwrap_err(),
            AccessDenied::NoGrant
        );
    }

    /// A lease naming no wallet is a service key with nothing behind it.
    #[test]
    fn a_lease_must_name_a_wallet() {
        let r = confined(false);
        let mut l = lease(KEY, u64::MAX);
        l.authorized_wallets.clear();
        let err = r.open_lease(l).unwrap_err();
        assert!(err.contains("authorized wallet"), "{err}");
    }

    #[test]
    fn wallets_and_keys_match_regardless_of_case() {
        let r = confined(false);
        let mut l = lease(KEY, u64::MAX);
        l.authorized_wallets = vec![WALLET.to_ascii_uppercase()];
        l.service_key_hash = l.service_key_hash.to_ascii_uppercase();
        r.open_lease(l).unwrap();
        assert!(open_session(&r, KEY, &WALLET.to_ascii_uppercase(), 0).is_ok());
    }

    // ---- grants ------------------------------------------------------------

    /// Single-use. A grant left in a shell history must not open a second
    /// session.
    #[test]
    fn a_grant_is_redeemable_exactly_once() {
        let r = confined(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        let lease = r.lease_for_service_key(KEY, 0).unwrap();
        let grant = r.mint_grant(&lease, WALLET, "g".to_string(), 0).unwrap();

        assert!(r.redeem_grant(&grant.grant_id, 0).is_ok());
        assert_eq!(
            r.redeem_grant(&grant.grant_id, 0).unwrap_err(),
            AccessDenied::NoGrant
        );
    }

    #[test]
    fn a_grant_expires() {
        let r = confined(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        let lease = r.lease_for_service_key(KEY, 0).unwrap();
        r.mint_grant(&lease, WALLET, "g".to_string(), 0).unwrap();
        assert_eq!(
            r.redeem_grant("g", GRANT_TTL_MS).unwrap_err(),
            AccessDenied::NoGrant
        );
    }

    /// One action, not two: the operator revokes the lease and every
    /// outstanding grant against it dies with it.
    #[test]
    fn revoking_the_lease_kills_outstanding_grants() {
        let r = confined(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        let l = r.lease_for_service_key(KEY, 0).unwrap();
        r.mint_grant(&l, WALLET, "g".to_string(), 0).unwrap();

        r.revoke_lease(&l.lease_id).unwrap();
        assert_eq!(r.redeem_grant("g", 0).unwrap_err(), AccessDenied::NoGrant);
        assert!(matches!(
            r.lease_for_service_key(KEY, 0),
            Err(AccessDenied::Revoked(_))
        ));
    }

    /// The operator may drop a wallet in the two minutes between the ceremony
    /// and the redemption, and that has to bite.
    #[test]
    fn dropping_a_wallet_invalidates_a_grant_already_minted_for_it() {
        let r = confined(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        let l = r.lease_for_service_key(KEY, 0).unwrap();
        r.mint_grant(&l, WALLET, "g".to_string(), 0).unwrap();

        let mut narrowed = l.clone();
        narrowed.authorized_wallets = vec![OTHER_WALLET.to_string()];
        r.open_lease(narrowed).unwrap();

        assert_eq!(
            r.redeem_grant("g", 0).unwrap_err(),
            AccessDenied::WalletNotAuthorized(WALLET.to_string())
        );
    }

    // ---- lease lifecycle ---------------------------------------------------

    #[test]
    fn expiry_is_the_credential_lifetime() {
        let r = confined(false);
        r.open_lease(lease(KEY, 1_000)).unwrap();
        assert!(r.lease_for_service_key(KEY, 999).is_ok());
        assert!(matches!(
            r.lease_for_service_key(KEY, 1_000),
            Err(AccessDenied::Expired(_))
        ));
    }

    // ---- the TEE rule ------------------------------------------------------

    /// A renter with a shell can read whatever the enclave holds, so the
    /// measurement stops meaning what a relying party takes it to mean. The
    /// node has to pick one.
    #[test]
    fn a_tee_provider_cannot_rent_out_a_shell() {
        let err = confined(true).open_lease(lease(KEY, u64::MAX)).unwrap_err();
        assert!(err.contains("TeeProvider"), "{err}");
    }

    #[test]
    fn a_node_that_is_not_a_tee_provider_can() {
        assert!(confined(false).open_lease(lease(KEY, u64::MAX)).is_ok());
    }

    // ---- no confinement, no shell -----------------------------------------

    /// The load-bearing refusal. A container namespace is not a boundary
    /// against someone with a shell, so "no boundary configured" must not
    /// degrade into "run it on the host". Refused at the first step, before
    /// anyone is sent to a browser.
    #[test]
    fn a_node_with_no_confinement_backend_refuses_before_the_passkey_step() {
        let r = LeaseRegistry::new(false);
        // Explicitly a shell lease. The rule is about interactive access, and
        // since channels were split an unqualified scope means endpoints —
        // which needs no boundary. Saying so here keeps the test testing what
        // its name claims rather than passing for an unrelated reason.
        let mut l = lease(KEY, u64::MAX);
        l.scope.channels = vec![AccessChannel::Shell];
        r.open_lease(l).unwrap();
        assert_eq!(
            r.lease_for_service_key(KEY, 0).unwrap_err(),
            AccessDenied::NoConfinement
        );
    }

    #[test]
    fn the_same_lease_works_once_a_boundary_exists() {
        let r = LeaseRegistry::new(false);
        r.open_lease(lease(KEY, u64::MAX)).unwrap();
        r.set_confinement(Arc::new(FakeKata));
        assert!(open_session(&r, KEY, WALLET, 0).is_ok());
    }

    // ---- provisioning ------------------------------------------------------

    /// The rental supplies the term, so access cannot outlive what was paid
    /// for.
    #[test]
    fn a_rental_provisioned_lease_expires_with_the_rental() {
        let r = confined(false);
        let lease = r
            .provision_from_rental(
                "rental-9",
                "did:tenzro:human:x",
                &digest("deposit-minted-key"),
                vec![WALLET.to_string()],
                scope(),
                60_000,
                1_000,
            )
            .unwrap();

        assert_eq!(lease.rental_id.as_deref(), Some("rental-9"));
        assert_eq!(lease.expires_at_ms, 61_000);
        assert!(
            r.lease_for_service_key("deposit-minted-key", 60_999)
                .is_ok()
        );
        assert!(matches!(
            r.lease_for_service_key("deposit-minted-key", 61_000),
            Err(AccessDenied::Expired(_))
        ));
    }

    /// A rental with nothing left on it is not a grant of anything.
    #[test]
    fn a_zero_term_rental_provisions_nothing() {
        let r = confined(false);
        assert!(
            r.provision_from_rental(
                "rental-0",
                "did:tenzro:human:x",
                &digest("k"),
                vec![WALLET.to_string()],
                scope(),
                0,
                0,
            )
            .is_err()
        );
        assert_eq!(
            r.lease_for_service_key("k", 0).unwrap_err(),
            AccessDenied::NoLease
        );
    }

    // ---- scope -------------------------------------------------------------

    /// A session that outlives the operator's attention is how temporary
    /// access becomes permanent access.
    #[test]
    fn the_session_ceiling_is_capped_whatever_the_lease_asks_for() {
        let mut s = scope();
        s.max_session_secs = u64::MAX;
        assert_eq!(s.effective_session_secs(), MAX_SESSION_SECS);
        s.max_session_secs = 0;
        assert_eq!(
            s.effective_session_secs(),
            1,
            "a zero-length session is a bug, not a policy"
        );
        s.max_session_secs = 600;
        assert_eq!(s.effective_session_secs(), 600);
    }

    #[test]
    fn a_scope_grants_named_accelerators_not_all_of_them() {
        assert_eq!(scope().accelerators(), vec![0]);
        let bare = AccessScope {
            devices: vec![DeviceGrant::Cpu { cores: 1 }],
            ..scope()
        };
        assert!(bare.accelerators().is_empty());
    }

    #[test]
    fn network_defaults_to_silence() {
        assert_eq!(NetworkGrant::default(), NetworkGrant::None);
    }

    // ---- persistence -------------------------------------------------------

    #[test]
    fn leases_and_revocations_survive_a_restart() {
        let store: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        {
            let r = LeaseRegistry::with_storage(store.clone(), false);
            r.set_confinement(Arc::new(FakeKata));
            r.open_lease(lease(KEY, u64::MAX)).unwrap();
            r.open_lease(lease("second-key", u64::MAX)).unwrap();
            r.revoke_lease("lease-second-key").unwrap();
        }

        let restarted = LeaseRegistry::with_storage(store, false);
        restarted.set_confinement(Arc::new(FakeKata));
        assert!(open_session(&restarted, KEY, WALLET, 0).is_ok());
        assert!(
            matches!(
                restarted.lease_for_service_key("second-key", 0),
                Err(AccessDenied::Revoked(_))
            ),
            "a revocation that did not survive the restart is not a revocation"
        );
        assert_eq!(restarted.list().len(), 2);
    }

    /// Grants are in memory by design: one deliberately does not survive the
    /// process that vouched for it.
    #[test]
    fn a_grant_does_not_survive_a_restart() {
        let store: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        {
            let r = LeaseRegistry::with_storage(store.clone(), false);
            r.set_confinement(Arc::new(FakeKata));
            r.open_lease(lease(KEY, u64::MAX)).unwrap();
            let l = r.lease_for_service_key(KEY, 0).unwrap();
            r.mint_grant(&l, WALLET, "g".to_string(), 0).unwrap();
        }

        let restarted = LeaseRegistry::with_storage(store, false);
        restarted.set_confinement(Arc::new(FakeKata));
        assert_eq!(
            restarted.redeem_grant("g", 0).unwrap_err(),
            AccessDenied::NoGrant
        );
    }
}
