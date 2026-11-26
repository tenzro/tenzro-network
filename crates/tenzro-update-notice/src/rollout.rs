//! When an automatic install of a release may start on this machine.
//!
//! A release reaches every machine that armed automatic installs within the
//! same few minutes of its notice. Installed all at once, a release with a
//! fault takes them all down together, and nobody sees the fault on a few
//! machines first. So an ordinary release is staggered: each machine waits a
//! delay derived from its identity and the release, spread over the stagger
//! window, so the order differs per release and the same machine is not
//! always first. An operator may also name the hours (UTC) in which an
//! install may start, for a machine that is busy at other times.
//!
//! A security release, and one required by an epoch, takes the fast lane:
//! no stagger and no install hours. The fault it fixes is worse than the
//! risk of installing it everywhere at once.

use sha2::{Digest, Sha256};

use crate::notice::{Notice, Severity};

/// Where the named release channels live.
pub const CHANNEL_BASE: &str = "https://downloads.tenzro.com/update";

/// The release channels by name: `stable` (the default), `security`
/// (security releases only, as soon as they are out) and `beta` (releases
/// before they reach stable).
pub const CHANNEL_NAMES: [&str; 3] = ["stable", "security", "beta"];

/// The channel `name_or_url` names: a channel name becomes its URL under
/// [`CHANNEL_BASE`]; anything else is returned as given.
pub fn channel_url(name_or_url: &str) -> String {
    if CHANNEL_NAMES.contains(&name_or_url) {
        format!("{CHANNEL_BASE}/{name_or_url}")
    } else {
        name_or_url.to_string()
    }
}

const HOUR_MS: u64 = 3600 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;

/// The stagger window an ordinary release is spread over unless the
/// operator names another: two days.
pub const DEFAULT_STAGGER_HOURS: u16 = 48;

/// Most hours a stagger window may span.
pub const MAX_STAGGER_HOURS: u16 = 24 * 14;

/// The hours (UTC) in which an install may start: from `start` up to, not
/// including, `end`. `start > end` wraps past midnight; `start == end` is
/// refused when parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstallHours {
    pub start: u8,
    pub end: u8,
}

impl InstallHours {
    /// `"2-5"`: from 02:00 to 05:00 UTC.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (a, b) = s
            .split_once('-')
            .ok_or_else(|| format!("install hours are <start>-<end> in UTC hours, not '{s}'"))?;
        let hour = |t: &str| {
            t.trim()
                .parse::<u8>()
                .ok()
                .filter(|h| *h < 24)
                .ok_or_else(|| format!("'{t}' is not an hour from 0 to 23"))
        };
        let hours = Self {
            start: hour(a)?,
            end: hour(b)?,
        };
        if hours.start == hours.end {
            return Err("install hours name an empty window".to_string());
        }
        Ok(hours)
    }

    fn contains(&self, hour: u8) -> bool {
        if self.start < self.end {
            (self.start..self.end).contains(&hour)
        } else {
            hour >= self.start || hour < self.end
        }
    }

    /// The first moment at or after `at_ms` inside the window.
    pub fn next_open(&self, at_ms: u64) -> u64 {
        let hour = ((at_ms % DAY_MS) / HOUR_MS) as u8;
        if self.contains(hour) {
            return at_ms;
        }
        let ahead = (u64::from(self.start) + 24 - u64::from(hour)) % 24;
        let hour_start = at_ms - at_ms % HOUR_MS;
        hour_start + ahead * HOUR_MS
    }
}

/// Whether `notice` takes the fast lane: no stagger and no install hours.
pub fn fast_lane(notice: &Notice) -> bool {
    !matches!(notice.severity, Severity::Normal)
}

/// How long after its release this machine waits to install `version`: a
/// point of the stagger window chosen by SHA-256 of the machine's identity
/// and the version.
pub fn stagger_delay_ms(machine: &str, version: &str, stagger_hours: u16) -> u64 {
    let window = u64::from(stagger_hours.min(MAX_STAGGER_HOURS)) * HOUR_MS;
    if window == 0 {
        return 0;
    }
    let mut h = Sha256::new();
    h.update(b"tenzro/update-stagger/v1");
    h.update((machine.len() as u32).to_be_bytes());
    h.update(machine.as_bytes());
    h.update((version.len() as u32).to_be_bytes());
    h.update(version.as_bytes());
    let digest = h.finalize();
    let draw = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"));
    draw % window
}

/// The first moment at or after `now_ms` at which this machine may start an
/// automatic install of `notice`.
pub fn install_at_ms(
    notice: &Notice,
    machine: &str,
    stagger_hours: u16,
    hours: Option<InstallHours>,
    now_ms: u64,
) -> u64 {
    if fast_lane(notice) {
        return now_ms;
    }
    let due = notice
        .released_ms
        .saturating_add(stagger_delay_ms(machine, &notice.version, stagger_hours))
        .max(now_ms);
    hours.map_or(due, |h| h.next_open(due))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(severity: Severity) -> Notice {
        Notice {
            kind: "notice".into(),
            spec: crate::notice::SPEC.into(),
            channel: "stable".into(),
            version: "0.2.9".into(),
            min_compatible: "0.2.0".into(),
            released_ms: 10 * DAY_MS,
            issued_ms: 10 * DAY_MS,
            expires_ms: 20 * DAY_MS,
            severity,
            notes: String::new(),
            notes_url: String::new(),
            manifest_url: String::new(),
            platforms: Vec::new(),
            artifacts: Vec::new(),
        }
    }

    #[test]
    fn channel_names_resolve_under_the_downloads_host() {
        assert_eq!(
            channel_url("beta"),
            "https://downloads.tenzro.com/update/beta"
        );
        assert_eq!(
            channel_url("security"),
            "https://downloads.tenzro.com/update/security"
        );
        assert_eq!(channel_url("./beta"), "./beta");
        assert_eq!(
            channel_url("https://example.org/u"),
            "https://example.org/u"
        );
    }

    #[test]
    fn machines_spread_over_the_window_and_the_order_changes_per_release() {
        let window = u64::from(DEFAULT_STAGGER_HOURS) * HOUR_MS;
        let delays: Vec<u64> = (0..400)
            .map(|i| stagger_delay_ms(&format!("did:tenzro:machine:{i}"), "0.2.9", 48))
            .collect();
        assert!(delays.iter().all(|d| *d < window));
        let first_half = delays.iter().filter(|d| **d < window / 2).count();
        assert!((140..260).contains(&first_half), "{first_half} of 400");
        // The same machine, another release: another place in the order.
        let moved = (0..400)
            .filter(|i| {
                let m = format!("did:tenzro:machine:{i}");
                stagger_delay_ms(&m, "0.2.9", 48) != stagger_delay_ms(&m, "0.2.4", 48)
            })
            .count();
        assert!(moved > 390);
        assert_eq!(stagger_delay_ms("did:tenzro:machine:1", "0.2.9", 0), 0);
    }

    #[test]
    fn an_ordinary_release_waits_for_its_turn_and_a_security_release_does_not() {
        let n = notice(Severity::Normal);
        let machine = "did:tenzro:machine:7";
        let turn = n.released_ms + stagger_delay_ms(machine, &n.version, 48);
        assert_eq!(install_at_ms(&n, machine, 48, None, n.released_ms), turn);
        // A machine that learns of it after its turn installs at once.
        assert_eq!(install_at_ms(&n, machine, 48, None, turn + 1), turn + 1);
        for severity in [Severity::Security, Severity::RequiredByEpoch { epoch: 9 }] {
            let urgent = notice(severity);
            let hours = InstallHours::parse("2-3").unwrap();
            assert_eq!(
                install_at_ms(&urgent, machine, 48, Some(hours), urgent.released_ms),
                urgent.released_ms
            );
        }
    }

    #[test]
    fn install_hours_open_at_their_next_start_and_wrap_past_midnight() {
        let at = |day: u64, hour: u64| day * DAY_MS + hour * HOUR_MS;
        let night = InstallHours::parse("2-5").unwrap();
        assert_eq!(night.next_open(at(3, 3) + 59_000), at(3, 3) + 59_000);
        assert_eq!(night.next_open(at(3, 5)), at(4, 2));
        assert_eq!(night.next_open(at(3, 1) + 1), at(3, 2));
        let late = InstallHours::parse("22-1").unwrap();
        assert_eq!(late.next_open(at(3, 23)), at(3, 23));
        assert_eq!(late.next_open(at(3, 0)), at(3, 0));
        assert_eq!(late.next_open(at(3, 1)), at(3, 22));
        for bad in ["5", "3-3", "24-1", "a-b"] {
            assert!(InstallHours::parse(bad).is_err(), "{bad}");
        }
        // Stagger then hours: a turn outside the window waits for it.
        let n = notice(Severity::Normal);
        let machine = "did:tenzro:machine:7";
        let due = install_at_ms(&n, machine, 48, Some(night), n.released_ms);
        assert!(night.contains(((due % DAY_MS) / HOUR_MS) as u8));
        assert!(due >= n.released_ms + stagger_delay_ms(machine, &n.version, 48));
    }
}
