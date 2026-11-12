//! Number and time formatting shared by every progress surface.

use std::time::Duration;

/// A byte count in plain units: `1.50 KB`, `3.00 GB`.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else if v >= 10.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

/// A transfer speed: `41.6 MB/s`. A speed that is not known reads `-`.
pub fn byte_rate(per_sec: f64) -> String {
    if !per_sec.is_finite() || per_sec <= 0.0 {
        return "-".to_string();
    }
    format!("{}/s", bytes(per_sec as u64))
}

/// An item count with thousands separators: `12,345`.
pub fn count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// An item rate: `12.5 blocks/s`.
pub fn item_rate(per_sec: f64, unit: &str) -> String {
    if !per_sec.is_finite() || per_sec <= 0.0 {
        return "-".to_string();
    }
    if per_sec >= 100.0 {
        format!("{per_sec:.0} {unit}/s")
    } else {
        format!("{per_sec:.1} {unit}/s")
    }
}

/// A length of time: `12s`, `1m 05s`, `2h 03m`.
pub fn duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    }
}

/// The time left at the current speed, or `None` when there is no speed to go by.
pub fn eta(remaining: u64, per_sec: f64) -> Option<Duration> {
    if !per_sec.is_finite() || per_sec <= 0.0 {
        return None;
    }
    let secs = remaining as f64 / per_sec;
    if !secs.is_finite() || secs > 99.0 * 3600.0 {
        return None;
    }
    Some(Duration::from_secs(secs.ceil() as u64))
}

/// Whole percent, never above 100.
pub fn percent(done: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    ((done as u128 * 100) / total as u128).min(100) as u64
}

/// `s` cut to at most `n` characters, ending in `..` when it was cut.
pub fn clip(s: &str, n: usize) -> String {
    let len = s.chars().count();
    if len <= n {
        s.to_string()
    } else if n <= 2 {
        s.chars().take(n).collect()
    } else {
        let mut t: String = s.chars().take(n - 2).collect();
        t.push_str("..");
        t
    }
}

/// A bar exactly `width` characters wide, such as `[=====>    ]`. Empty when
/// there is no room for one.
pub fn bar(width: usize, done: u64, total: u64) -> String {
    if width < 4 {
        return String::new();
    }
    let inner = width - 2;
    let frac = if total == 0 {
        0.0
    } else {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    };
    let fill = ((frac * inner as f64) as usize).min(inner);
    let mut s = String::with_capacity(width);
    s.push('[');
    for i in 0..inner {
        s.push(if i < fill {
            '='
        } else if i == fill && frac > 0.0 {
            '>'
        } else {
            ' '
        });
    }
    s.push(']');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_use_plain_units() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1536), "1.50 KB");
        assert_eq!(bytes(150 * 1024 * 1024), "150 MB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.00 GB");
        assert_eq!(
            bytes(12 * 1024 * 1024 * 1024 + 512 * 1024 * 1024),
            "12.5 GB"
        );
    }

    #[test]
    fn speeds_read_as_sizes_per_second() {
        assert_eq!(byte_rate(0.0), "-");
        assert_eq!(byte_rate(f64::NAN), "-");
        assert_eq!(byte_rate(1_048_576.0 * 41.0), "41.0 MB/s");
        assert_eq!(item_rate(12.34, "blocks"), "12.3 blocks/s");
        assert_eq!(item_rate(250.0, "files"), "250 files/s");
    }

    #[test]
    fn counts_have_separators() {
        assert_eq!(count(7), "7");
        assert_eq!(count(1234), "1,234");
        assert_eq!(count(1_234_567), "1,234,567");
    }

    #[test]
    fn durations_are_short() {
        assert_eq!(duration(Duration::from_secs(9)), "9s");
        assert_eq!(duration(Duration::from_secs(65)), "1m 05s");
        assert_eq!(duration(Duration::from_secs(7380)), "2h 03m");
    }

    #[test]
    fn eta_needs_a_speed_and_a_sane_answer() {
        assert_eq!(eta(100, 0.0), None);
        assert_eq!(eta(100, 10.0), Some(Duration::from_secs(10)));
        assert_eq!(eta(101, 10.0), Some(Duration::from_secs(11)));
        assert_eq!(eta(u64::MAX, 1.0), None);
    }

    #[test]
    fn percent_is_clamped() {
        assert_eq!(percent(0, 0), 0);
        assert_eq!(percent(50, 200), 25);
        assert_eq!(percent(300, 200), 100);
    }

    #[test]
    fn clip_never_exceeds_the_width() {
        assert_eq!(clip("short", 10), "short");
        assert_eq!(clip("a long sentence", 8), "a long..");
        assert_eq!(clip("abc", 2), "ab");
        assert_eq!(clip("", 0), "");
    }

    #[test]
    fn bar_is_exactly_as_wide_as_asked() {
        for w in [4usize, 10, 33] {
            for done in [0u64, 1, 50, 99, 100, 500] {
                assert_eq!(bar(w, done, 100).chars().count(), w);
            }
        }
        assert_eq!(bar(3, 1, 2), "");
        assert_eq!(bar(10, 0, 100), "[        ]");
        assert_eq!(bar(10, 100, 100), "[========]");
        assert_eq!(bar(10, 50, 100), "[====>   ]");
    }
}
