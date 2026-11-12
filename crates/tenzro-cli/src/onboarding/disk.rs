//! Setup step: is there room for the node's data where the operator put it?
//!
//! The same numbers the node and `tenzro doctor` use
//! ([`tenzro_storage::resources`]): the free bytes of the volume that holds
//! the data directory against what the role needs, with the growth per day
//! stated. A directory with too little room is refused before anything is
//! written, and the message says what is wrong, why it matters and how to fix
//! it with `--data-dir` on another volume.

use std::path::{Path, PathBuf};

use tenzro_storage::resources::{self, GIB, Role, Verdict, VolumeStats};

/// The verdict for one directory and role.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The directory judged.
    pub dir: PathBuf,
    /// The role it was judged for.
    pub role: Role,
    /// The verdict.
    pub verdict: Verdict,
    /// Free bytes of the volume that holds (or would hold) the directory.
    pub free_bytes: u64,
}

/// The role whose needs a role set carries: the most demanding word wins
/// (`validator,ai` is a validator).
pub fn role_of(roles: &str) -> Role {
    let words: Vec<String> = roles
        .split(',')
        .map(|w| w.trim().to_ascii_lowercase())
        .collect();
    let has = |w: &str| words.iter().any(|x| x == w);
    if has("validator") {
        Role::Validator
    } else if has("rpc") || has("full") || has("fullnode") || has("full-node") {
        Role::Rpc
    } else if has("ai") || has("provider") || has("storage") || has("compute") {
        Role::Provider
    } else {
        Role::Participant
    }
}

/// Judges `dir` for `roles` on a measured `volume`.
pub fn judge_volume(roles: &str, dir: &Path, volume: &VolumeStats) -> Outcome {
    let role = role_of(roles);
    Outcome {
        dir: dir.to_path_buf(),
        role,
        verdict: resources::preflight(role, volume, dir),
        free_bytes: volume.free_bytes,
    }
}

/// Measures the volume under `dir` (it need not exist yet) and judges it.
/// A volume that cannot be measured is not refused: the node checks again
/// when it starts.
pub fn judge(roles: &str, dir: &Path) -> Outcome {
    match resources::volume_of(dir) {
        Ok(v) => judge_volume(roles, dir, &v),
        Err(_) => Outcome {
            dir: dir.to_path_buf(),
            role: role_of(roles),
            verdict: Verdict::Ok,
            free_bytes: 0,
        },
    }
}

/// The lines to show for an outcome: one `Disk` line, and the message when
/// there is one.
pub fn describe(o: &Outcome) -> (String, Option<String>) {
    let est = resources::role_estimate(o.role);
    let line = format!(
        "{:.0} GiB free at {}; a {:?} node grows about {:.1} GiB a day and settles near {} GiB",
        o.free_bytes as f64 / GIB as f64,
        o.dir.display(),
        o.role,
        est.growth_bytes_per_day as f64 / GIB as f64,
        est.steady_state_bytes / GIB,
    );
    let message = match &o.verdict {
        Verdict::Ok => None,
        Verdict::Warn(m) | Verdict::Refuse(m) => Some(m.clone()),
    };
    (line, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gib(n: u64) -> u64 {
        n * GIB
    }

    #[test]
    fn the_most_demanding_word_of_a_role_set_decides() {
        assert_eq!(role_of("validator,ai"), Role::Validator);
        assert_eq!(role_of("ai"), Role::Provider);
        assert_eq!(role_of("ai, storage"), Role::Provider);
        assert_eq!(role_of("rpc"), Role::Rpc);
        assert_eq!(role_of(""), Role::Participant);
        assert_eq!(role_of("participant"), Role::Participant);
    }

    #[test]
    fn a_small_volume_is_refused_for_a_validator_with_the_fix_named() {
        let v = VolumeStats::of(gib(120), gib(25));
        let o = judge_volume("validator", Path::new("/home/op/.tenzro"), &v);
        match &o.verdict {
            Verdict::Refuse(m) => {
                assert!(m.contains("/home/op/.tenzro"), "what: {m}");
                assert!(m.contains("a day"), "why, with the growth per day: {m}");
                assert!(m.contains("--data-dir"), "the fix: {m}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // The same volume is enough for a participant.
        assert_eq!(
            judge_volume("participant", Path::new("/x"), &v).verdict,
            Verdict::Ok
        );
    }

    #[test]
    fn a_tight_volume_warns_and_a_roomy_one_passes() {
        let tight = VolumeStats::of(gib(300), gib(70));
        assert!(matches!(
            judge_volume("validator", Path::new("/d"), &tight).verdict,
            Verdict::Warn(_)
        ));
        let roomy = VolumeStats::of(gib(4000), gib(3000));
        let o = judge_volume("validator", Path::new("/d"), &roomy);
        assert_eq!(o.verdict, Verdict::Ok);
        let (line, message) = describe(&o);
        assert!(line.contains("3000 GiB free") && line.contains("a day"));
        assert!(message.is_none());
    }

    #[test]
    fn a_directory_not_created_yet_is_measured_on_its_parent_volume() {
        let tmp = tempfile::tempdir().unwrap();
        let o = judge("participant", &tmp.path().join("new/data"));
        assert!(o.free_bytes > 0);
    }
}
