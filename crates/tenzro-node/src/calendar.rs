//! The node's calendar clock.
//!
//! Genesis may run the calendar faster than block time (`[time]
//! calendar_scale`): calendar time is the genesis timestamp plus the time
//! since it, times the scale. Block execution reads the calendar from state;
//! rules the node checks against its own clock before anything reaches the
//! chain (recovery waits, payment expiries, x402 validity) read it here, so a
//! timestamp a client signs means the same on both sides. Scale 1, the
//! public network's, makes calendar time wall-clock time.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
struct Calendar {
    anchor_ms: i64,
    scale: i64,
}

static CALENDAR: OnceLock<Calendar> = OnceLock::new();

/// Runs this process's calendar `scale` times faster than wall-clock time
/// from `anchor_ms`, the genesis timestamp. Called once at startup from the
/// genesis; before it, and with scale 1, calendar time is wall-clock time.
pub fn install(anchor_ms: i64, scale: u64) {
    let _ = CALENDAR.set(Calendar {
        anchor_ms,
        scale: scale.clamp(1, i64::MAX as u64) as i64,
    });
}

/// Calendar time at wall-clock time `wall_ms`.
fn at(calendar: Option<&Calendar>, wall_ms: i64) -> i64 {
    match calendar {
        Some(c) if c.scale > 1 => c
            .anchor_ms
            .saturating_add(wall_ms.saturating_sub(c.anchor_ms).saturating_mul(c.scale)),
        _ => wall_ms,
    }
}

/// Calendar time now, Unix milliseconds.
pub fn now_ms() -> u64 {
    at(CALENDAR.get(), chrono::Utc::now().timestamp_millis()).max(0) as u64
}

/// A span of wall-clock time, in calendar milliseconds: how a window that
/// exists for real-world latency (a client answering a challenge, clocks
/// drifting apart) is measured against calendar timestamps.
pub fn wall_span_ms(ms: u64) -> u64 {
    let scale = CALENDAR.get().map_or(1, |c| c.scale as u64);
    ms.saturating_mul(scale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_time_runs_scale_times_faster_from_genesis() {
        let c = Calendar {
            anchor_ms: 1_000_000,
            scale: 8_640,
        };
        assert_eq!(at(Some(&c), 1_000_000), 1_000_000);
        // Ten wall seconds after genesis is one calendar day after it.
        assert_eq!(at(Some(&c), 1_010_000), 1_000_000 + 86_400_000);
        let one = Calendar {
            anchor_ms: 1_000_000,
            scale: 1,
        };
        assert_eq!(at(Some(&one), 5_000_000), 5_000_000);
        assert_eq!(at(None, 5_000_000), 5_000_000);
    }
}
