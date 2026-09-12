//! What the machine actually has, as opposed to what the ledger believes.
//!
//! [`MemoryBudget`](crate::memory_budget::MemoryBudget) is an accounting
//! ledger: it compares a request against a ceiling and the commitments it has
//! recorded itself. That is the right shape for deciding whether *this node's
//! own models* fit inside their tier, and it is the wrong shape for deciding
//! whether the machine can survive the load, because a ledger cannot see
//! anything it did not allocate.
//!
//! The distinction is not academic. `sysinfo` was read once at startup for
//! `total_memory()` — a constant — and `available_memory()` was never called
//! anywhere in the tree. So when memory was consumed by something outside this
//! process, the ledger still showed room, admission still returned `Ok`, and
//! the load proceeded into a wall. That is how a host went unreachable while
//! every number tenzro held said it was fine.
//!
//! ## One axis here, the same shape for the rest
//!
//! Memory is the axis this node can measure without help, so it is the one
//! implemented. The type deliberately does not hard-code it: an [`Axis`] is a
//! named quantity with a headroom, and thermal, power, airflow or a building's
//! cooling loop are the same check with a different reading. Adding one means
//! adding a variant and a source, not restructuring the caller.
//!
//! ## Failing closed
//!
//! If the ground cannot be read, [`Ground::probe`] yields `Unknown` and
//! [`Ground::admits`] refuses. The alternative — treating an unreadable
//! machine as an empty one — is precisely the assumption that makes the
//! ledger dangerous, and re-introducing it here would defeat the module.

use std::fmt;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// A measurable physical quantity the machine is bounded by.
///
/// Named rather than typed as bytes, because the axes that matter next are not
/// all measured in bytes and a caller should not have to care which is which.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Axis {
    /// Memory the kernel says can be handed out without swapping.
    Memory,
}

impl Axis {
    pub fn as_str(&self) -> &'static str {
        match self {
            Axis::Memory => "memory",
        }
    }
}

impl fmt::Display for Axis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A reading on one axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// The axis was measured; this much headroom is genuinely free.
    Free(u64),
    /// The axis could not be read. Distinct from `Free(0)`: one is a full
    /// machine, the other is a blind one, and only the first can be reasoned
    /// about.
    Unknown,
}

/// Why a grounded admission was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroundDenied {
    /// What was being admitted, for the operator's benefit.
    pub key: String,
    pub axis: Axis,
    /// Bytes the load needs, headroom already applied.
    pub requested: u64,
    /// What the machine actually had free, or `None` when unreadable.
    pub measured_free: Option<u64>,
    /// The margin this node insists on keeping unused.
    pub margin: u64,
}

impl fmt::Display for GroundDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.measured_free {
            Some(free) => write!(
                f,
                "{} needs {} on the {} axis but the machine has {} free \
                 (keeping {} in reserve) — the budget ledger may show room, \
                 the machine does not",
                self.key,
                human(self.requested),
                self.axis,
                human(free),
                human(self.margin),
            ),
            None => write!(
                f,
                "{} was refused because the {} axis could not be measured — \
                 refusing rather than assuming an empty machine",
                self.key, self.axis,
            ),
        }
    }
}

impl std::error::Error for GroundDenied {}

/// How much of the machine this node declines to spend, whatever the ledger
/// permits.
///
/// Not a tuning knob so much as the difference between a machine that is full
/// and a machine that is wedged. Loading right up to the last free byte leaves
/// nothing for page cache, the allocator's own working set, or the processes
/// that are not models — and the failure at that boundary is not an allocation
/// error, it is a host that stops answering.
pub const DEFAULT_MARGIN_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// How long a reading may be reused.
///
/// Short, because the value of the measurement is that it is current; a cache
/// exists only so that admitting several models in a burst does not re-probe
/// per model.
const TTL: Duration = Duration::from_millis(750);

struct Cached {
    reading: Reading,
    taken: Instant,
}

/// Live measurement of the machine, with a short cache.
pub struct Ground {
    margin_bytes: u64,
    memory: Mutex<Option<Cached>>,
}

impl Ground {
    pub fn new(margin_bytes: u64) -> Self {
        Self {
            margin_bytes,
            memory: Mutex::new(None),
        }
    }

    /// The margin this instance keeps unused.
    pub fn margin_bytes(&self) -> u64 {
        self.margin_bytes
    }

    /// Read an axis, reusing a measurement taken within [`TTL`].
    pub fn probe(&self, axis: Axis) -> Reading {
        match axis {
            Axis::Memory => {
                let mut slot = self.memory.lock();
                if let Some(c) = slot.as_ref() {
                    if c.taken.elapsed() < TTL {
                        return c.reading;
                    }
                }
                let reading = measure_memory();
                *slot = Some(Cached {
                    reading,
                    taken: Instant::now(),
                });
                reading
            }
        }
    }

    /// Whether `bytes` can be taken on `axis` without eating the margin.
    ///
    /// This is the check the ledger cannot make. It is deliberately separate
    /// from `MemoryBudget::admit` rather than folded into it: the ledger
    /// answers "does this fit the operator's configured tier", this answers
    /// "does the machine have it", and a load needs both to be true. Two
    /// layers saying no for different reasons is the point.
    pub fn admits(&self, key: &str, axis: Axis, bytes: u64) -> Result<(), GroundDenied> {
        let deny = |measured_free| {
            Err(GroundDenied {
                key: key.to_string(),
                axis,
                requested: bytes,
                measured_free,
                margin: self.margin_bytes,
            })
        };

        match self.probe(axis) {
            // Refusing on an unreadable axis is the whole safety property; an
            // unmeasurable machine is not an empty one.
            Reading::Unknown => deny(None),
            Reading::Free(free) => {
                let spendable = free.saturating_sub(self.margin_bytes);
                if bytes > spendable {
                    deny(Some(free))
                } else {
                    Ok(())
                }
            }
        }
    }
}

impl Default for Ground {
    fn default() -> Self {
        Self::new(DEFAULT_MARGIN_BYTES)
    }
}

/// Ask the kernel what is genuinely available.
///
/// `available_memory` rather than `free_memory`: the latter excludes
/// reclaimable page cache and so reads near zero on any machine that has been
/// up for a while, which would refuse every load on a perfectly healthy host.
fn measure_memory() -> Reading {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let available = sys.available_memory();
    let total = sys.total_memory();
    // A platform that cannot report memory returns zeros rather than failing.
    // `Free(0)` would be indistinguishable from a genuinely full machine, and
    // the two deserve different words, so an implausible total is Unknown.
    if total == 0 {
        Reading::Unknown
    } else {
        Reading::Free(available)
    }
}

/// The process-wide ground.
///
/// A single instance so the short cache is shared: admitting a stack of four
/// models in a burst takes one measurement, not four.
///
/// `TENZRO_GROUND_MARGIN_GB` overrides the reserve for operators who have
/// measured their own machine. Setting it to `0` disables the margin but not
/// the check — the machine is still measured, and a load larger than free
/// memory is still refused.
pub fn global() -> &'static Ground {
    static GROUND: std::sync::OnceLock<Ground> = std::sync::OnceLock::new();
    GROUND.get_or_init(|| {
        let margin = std::env::var("TENZRO_GROUND_MARGIN_GB")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|gb| gb * 1024 * 1024 * 1024)
            .unwrap_or(DEFAULT_MARGIN_BYTES);
        Ground::new(margin)
    })
}

fn human(bytes: u64) -> String {
    const GIB: f64 = (1024 * 1024 * 1024) as f64;
    const MIB: f64 = (1024 * 1024) as f64;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1} GiB", b / GIB)
    } else {
        format!("{:.0} MiB", b / MIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    /// A ground whose reading is fixed, so the logic can be tested without
    /// depending on whatever the build machine happens to have free.
    fn fixed(free: Reading, margin: u64) -> Ground {
        let g = Ground::new(margin);
        *g.memory.lock() = Some(Cached {
            reading: free,
            taken: Instant::now(),
        });
        g
    }

    #[test]
    fn a_load_that_fits_under_the_margin_is_admitted() {
        let g = fixed(Reading::Free(40 * GIB), 8 * GIB);
        assert!(g.admits("m", Axis::Memory, 30 * GIB).is_ok());
    }

    #[test]
    fn a_load_that_would_eat_the_margin_is_refused() {
        // 40 free, 8 reserved, so 32 spendable — 33 must not pass.
        let g = fixed(Reading::Free(40 * GIB), 8 * GIB);
        assert!(g.admits("m", Axis::Memory, 33 * GIB).is_err());
    }

    #[test]
    fn the_boundary_itself_is_admitted() {
        let g = fixed(Reading::Free(40 * GIB), 8 * GIB);
        assert!(g.admits("m", Axis::Memory, 32 * GIB).is_ok());
    }

    #[test]
    fn an_unreadable_axis_refuses_rather_than_assuming_room() {
        // The entire point of the module: blind must not mean empty.
        let g = fixed(Reading::Unknown, 8 * GIB);
        let e = g.admits("m", Axis::Memory, 1).unwrap_err();
        assert_eq!(e.measured_free, None);
        assert!(e.to_string().contains("could not be measured"));
    }

    #[test]
    fn a_machine_with_less_free_than_the_margin_admits_nothing() {
        // saturating_sub must not wrap into a huge allowance.
        let g = fixed(Reading::Free(2 * GIB), 8 * GIB);
        assert!(g.admits("m", Axis::Memory, 1).is_err());
    }

    #[test]
    fn the_refusal_says_what_the_machine_had_not_what_the_ledger_thought() {
        let g = fixed(Reading::Free(3 * GIB), 8 * GIB);
        let msg = g.admits("qwen", Axis::Memory, 20 * GIB).unwrap_err().to_string();
        assert!(msg.contains("qwen"), "names the load: {msg}");
        assert!(msg.contains("3.0 GiB"), "reports measured free: {msg}");
        assert!(msg.contains("ledger"), "distinguishes ledger from machine: {msg}");
    }

    #[test]
    fn a_real_probe_returns_something_usable() {
        // Against the actual machine: whatever it says, it must not be Unknown
        // on a platform sysinfo supports, or every load would be refused.
        match Ground::default().probe(Axis::Memory) {
            Reading::Free(n) => assert!(n > 0, "a running machine has some memory free"),
            Reading::Unknown => panic!("sysinfo could not read memory on this platform"),
        }
    }

    #[test]
    fn readings_are_cached_within_the_ttl() {
        let g = Ground::default();
        let a = g.probe(Axis::Memory);
        let b = g.probe(Axis::Memory);
        assert_eq!(a, b, "a second probe inside the TTL reuses the reading");
    }
}
