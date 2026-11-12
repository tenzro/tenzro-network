//! apply/rollback against a local channel and a local install: no network, no real binaries.

use super::manifest::fixture::*;
use super::manifest::{Class, FileEntry, Targets, TrustRoot};
use super::*;

const HOUR: u64 = 3_600_000;
const OLD_CLI: &[u8] = b"old tenzro cli \x00\x01\x02";
const OLD_NODE: &[u8] = b"old tenzro-node \xff\xfe";
const NEW_CLI: &[u8] = b"new tenzro cli";
/// Not an executable at all: a rollback must not care.
const NEW_NODE_BROKEN: &[u8] = b"\x00\x00 this binary will not start";

struct World {
    _tmp: tempfile::TempDir,
    channel: PathBuf,
    data: PathBuf,
    install: PathBuf,
    tk: Key,
    sk: Key,
}

impl World {
    fn new() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let p = |n: &str| {
            let d = tmp.path().join(n);
            std::fs::create_dir_all(&d).unwrap();
            d
        };
        World {
            channel: p("channel"),
            data: p("data"),
            install: p("install"),
            tk: Key::new(1),
            sk: Key::new(2),
            _tmp: tmp,
        }
    }

    fn ctx(&self) -> Ctx {
        Ctx {
            data_dir: self.data.clone(),
            channel: Channel::Dir(self.channel.clone()),
            root: TrustRoot {
                targets: vec![self.tk.sec1()],
                timestamp: vec![self.sk.sec1()],
            },
            platform: "x86_64-linux".into(),
            running: "0.2.1".parse().unwrap(),
        }
    }

    /// Publishes `files` (name, content) as release `release` with manifest number `version`.
    fn publish(
        &self,
        version: u64,
        release: &str,
        class: Class,
        ts_version: u64,
        files: &[(&str, &[u8])],
    ) -> Targets {
        std::fs::create_dir_all(self.channel.join("files")).unwrap();
        let entries: Vec<FileEntry> = files
            .iter()
            .map(|(n, c)| {
                std::fs::write(self.channel.join("files").join(n), c).unwrap();
                file(n, c)
            })
            .collect();
        let mut t = targets(version, release, entries);
        t.class = class;
        let tg = self.tk.sign_targets(&t);
        let ts = timestamp_for(&t, &tg, ts_version, now_ms() - HOUR, 24 * HOUR);
        std::fs::write(self.channel.join("targets.json"), &tg).unwrap();
        std::fs::write(
            self.channel.join("timestamp.json"),
            self.sk.sign_timestamp(&ts),
        )
        .unwrap();
        t
    }

    fn flat(&self) -> Layout {
        std::fs::write(self.install.join("tenzro"), OLD_CLI).unwrap();
        std::fs::write(self.install.join("tenzro-node"), OLD_NODE).unwrap();
        Layout::detect(&self.install)
    }

    /// What `install.sh` makes: versions/0.2.1/bin/*, current -> versions/0.2.1.
    /// Unix only: the update code installs versioned releases through symlinks and refuses to on other systems.
    #[cfg(unix)]
    fn versioned(&self) -> Layout {
        let bin = self.install.join("versions/0.2.1/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("tenzro"), OLD_CLI).unwrap();
        std::fs::write(bin.join("tenzro-node"), OLD_NODE).unwrap();
        std::fs::write(
            self.install.join("versions/0.2.1/README"),
            b"untouched file",
        )
        .unwrap();
        std::os::unix::fs::symlink("versions/0.2.1", self.install.join("current")).unwrap();
        Layout::detect(&self.install)
    }
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

#[tokio::test]
async fn check_reports_a_newer_c0_update_and_remembers_it() {
    let w = World::new();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    let found = check(&w.ctx(), now_ms()).await.unwrap();
    assert_eq!(
        found,
        Availability::Available {
            release: "0.2.2".into(),
            manifest_version: 4,
            description: "Fixes a checkpoint submission stall".into()
        }
    );
    let rec = update_state::load(&w.data).unwrap();
    assert_eq!(rec.last_check.unwrap().release, "0.2.2");
    assert_eq!(rec.highest_timestamp_version, 11);
}

#[tokio::test]
async fn check_on_the_current_release_says_up_to_date_and_a_non_c0_release_is_held() {
    let w = World::new();
    w.publish(4, "0.2.1", Class::C0, 11, &[("tenzro", OLD_CLI)]);
    assert_eq!(
        check(&w.ctx(), now_ms()).await.unwrap(),
        Availability::UpToDate
    );
    w.publish(5, "0.3.0", Class::C1, 12, &[("tenzro", NEW_CLI)]);
    assert!(matches!(
        check(&w.ctx(), now_ms()).await.unwrap(),
        Availability::Held {
            class: Class::C1,
            ..
        }
    ));
}

#[tokio::test]
async fn check_refuses_a_replayed_older_timestamp_after_a_newer_one_was_seen() {
    let w = World::new();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    check(&w.ctx(), now_ms()).await.unwrap();
    w.publish(4, "0.2.2", Class::C0, 8, &[("tenzro", NEW_CLI)]);
    let e = check(&w.ctx(), now_ms()).await.unwrap_err().to_string();
    assert!(e.contains("replayed timestamp"), "{e}");
}

#[cfg(unix)]
#[tokio::test]
async fn flat_apply_then_rollback_restores_the_original_bytes() {
    let w = World::new();
    let layout = w.flat();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro", NEW_CLI), ("tenzro-node", NEW_NODE_BROKEN)],
    );
    let a = apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(a.release, "0.2.2");
    assert_eq!(read(&w.install.join("tenzro")), NEW_CLI);
    assert_eq!(read(&w.install.join("tenzro-node")), NEW_NODE_BROKEN);
    // The previous binaries are kept beside the new ones.
    assert_eq!(read(&w.install.join("tenzro.prev")), OLD_CLI);
    assert_eq!(read(&w.install.join("tenzro-node.prev")), OLD_NODE);
    let rec = update_state::load(&w.data).unwrap();
    assert_eq!(rec.installed_manifest_version, 4);
    assert_eq!(
        rec.installed_sha256.unwrap(),
        hex::encode(Sha256::digest(NEW_NODE_BROKEN))
    );
    assert!(
        !update_state::update_dir(&w.data)
            .join(format!("staging-{}", std::process::id()))
            .exists()
    );

    // The new node binary cannot run; rollback only renames files.
    install::rollback(&layout).unwrap();
    assert_eq!(read(&w.install.join("tenzro")), OLD_CLI);
    assert_eq!(read(&w.install.join("tenzro-node")), OLD_NODE);
    assert!(!w.install.join("tenzro.prev").exists());
    assert!(
        install::rollback(&layout).is_err(),
        "a second rollback has nothing to restore"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn the_generated_rollback_script_restores_without_any_tenzro_binary() {
    let w = World::new();
    let layout = w.flat();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro", NEW_CLI), ("tenzro-node", NEW_NODE_BROKEN)],
    );
    let a = apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    let out = std::process::Command::new("sh")
        .arg(&a.rollback_script)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&w.install.join("tenzro")), OLD_CLI);
    assert_eq!(read(&w.install.join("tenzro-node")), OLD_NODE);
}

#[cfg(unix)]
#[tokio::test]
async fn versioned_apply_then_rollback_restores_the_original_release() {
    let w = World::new();
    let layout = w.versioned();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro", NEW_CLI), ("tenzro-node", NEW_NODE_BROKEN)],
    );
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    let cur = |n: &str| read(&w.install.join("current/bin").join(n));
    assert_eq!(
        std::fs::read_link(w.install.join("current")).unwrap(),
        Path::new("versions/0.2.2")
    );
    assert_eq!(cur("tenzro"), NEW_CLI);
    assert_eq!(cur("tenzro-node"), NEW_NODE_BROKEN);
    // Files the update did not name came along from the old release.
    assert_eq!(read(&w.install.join("current/README")), b"untouched file");
    // The old release is intact and is the previous one.
    assert_eq!(read(&w.install.join("versions/0.2.1/bin/tenzro")), OLD_CLI);
    assert_eq!(
        std::fs::read_link(w.install.join("previous")).unwrap(),
        Path::new("versions/0.2.1")
    );

    install::rollback(&layout).unwrap();
    assert_eq!(
        std::fs::read_link(w.install.join("current")).unwrap(),
        Path::new("versions/0.2.1")
    );
    assert_eq!(cur("tenzro"), OLD_CLI);
    assert_eq!(cur("tenzro-node"), OLD_NODE);
    assert!(install::rollback(&layout).is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn the_versioned_rollback_script_restores_too_and_a_third_release_prunes_the_first() {
    let w = World::new();
    let layout = w.versioned();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    let a = apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    w.publish(5, "0.2.3", Class::C0, 12, &[("tenzro", b"third")]);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert!(
        !w.install.join("versions/0.2.1").exists(),
        "only the new and previous releases are kept"
    );
    let out = std::process::Command::new("sh")
        .arg(&a.rollback_script)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(read(&w.install.join("current/bin/tenzro")), NEW_CLI);
}

// Unix only: on Windows apply refuses first (see the refusal tests below).
#[cfg(unix)]
#[tokio::test]
async fn a_file_that_does_not_match_its_signed_hash_leaves_the_install_untouched() {
    let w = World::new();
    let layout = w.flat();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro", NEW_CLI), ("tenzro-node", NEW_NODE_BROKEN)],
    );
    // Same length, different bytes: only the hash can tell.
    std::fs::write(
        w.channel.join("files/tenzro-node"),
        vec![b'x'; NEW_NODE_BROKEN.len()],
    )
    .unwrap();
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("hashes to"), "{e}");
    assert_eq!(read(&w.install.join("tenzro")), OLD_CLI);
    assert_eq!(read(&w.install.join("tenzro-node")), OLD_NODE);
    assert!(!w.install.join("tenzro.prev").exists());
    assert_eq!(
        update_state::load(&w.data)
            .unwrap()
            .installed_manifest_version,
        0
    );
    assert!(
        !update_state::update_dir(&w.data)
            .join(format!("staging-{}", std::process::id()))
            .exists()
    );
}

// Unix only: on Windows apply refuses first (see the refusal tests below).
#[cfg(unix)]
#[tokio::test]
async fn a_file_longer_than_its_signed_length_is_cut_off() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    let mut long = NEW_CLI.to_vec();
    long.extend_from_slice(b" and then some");
    std::fs::write(w.channel.join("files/tenzro"), long).unwrap();
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("larger than"), "{e}");
    assert_eq!(read(&w.install.join("tenzro")), OLD_CLI);
}

#[cfg(unix)]
#[tokio::test]
async fn apply_refuses_what_is_not_a_newer_c0_update() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.1", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("nothing to apply"), "{e}");
    w.publish(5, "0.3.0", Class::C2, 12, &[("tenzro", NEW_CLI)]);
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("not C0"), "{e}");
    // A downgrade: after installing manifest 4, a signed manifest 3 is refused.
    w.publish(4, "0.2.2", Class::C0, 13, &[("tenzro", NEW_CLI)]);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    w.publish(3, "0.2.2", Class::C0, 14, &[("tenzro", b"older manifest")]);
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("refusing a rollback"), "{e}");
    assert_eq!(read(&w.install.join("tenzro")), NEW_CLI);
}

// Unix only: on Windows apply refuses first (see the refusal tests below).
#[cfg(unix)]
#[tokio::test]
async fn a_forged_channel_is_refused_before_anything_is_downloaded() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    let mut ctx = w.ctx();
    ctx.root = TrustRoot {
        targets: vec![Key::new(9).sec1()],
        timestamp: vec![w.sk.sec1()],
    };
    let e = apply(&ctx, &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("not signed by a key this machine trusts"), "{e}");
    assert_eq!(read(&w.install.join("tenzro")), OLD_CLI);
    assert!(
        !update_state::update_dir(&w.data)
            .join(format!("staging-{}", std::process::id()))
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn layouts_are_detected_from_the_directory_and_from_the_executable() {
    let w = World::new();
    let v = w.versioned();
    assert!(matches!(v, Layout::Versioned { .. }));
    let exe = w.install.join("versions/0.2.1/bin/tenzro");
    assert_eq!(
        Layout::of_executable(&exe).unwrap(),
        Layout::Versioned {
            root: w.install.canonicalize().unwrap()
        }
    );
    let flat = tempfile::tempdir().unwrap();
    std::fs::write(flat.path().join("tenzro"), b"x").unwrap();
    assert!(matches!(
        Layout::of_executable(&flat.path().join("tenzro")).unwrap(),
        Layout::Flat { .. }
    ));
}

#[test]
fn channels_parse_urls_and_directories() {
    assert_eq!(
        Channel::parse("https://example.org/u/"),
        Channel::Http("https://example.org/u".into())
    );
    assert_eq!(
        Channel::parse("file:///srv/chan"),
        Channel::Dir("/srv/chan".into())
    );
    assert_eq!(
        Channel::parse("/srv/chan"),
        Channel::Dir("/srv/chan".into())
    );
}

// ---- the trial: boot attempts, the health window, automatic rollback, identity ----

#[cfg(unix)]
use super::health::{self, BootDecision, Observation, Policy, Reason, TrialState, Verdict};
#[cfg(unix)]
use std::cell::Cell;
#[cfg(unix)]
use std::rc::Rc;

#[cfg(unix)]
const KEY_BYTES: &[u8] = b"device key material that an update must never touch";

#[cfg(unix)]
impl World {
    /// A data directory with the files that make the node who it is.
    fn identity(&self) {
        let keys = self.data.join("device-keys/ab12");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("handle"), KEY_BYTES).unwrap();
        std::fs::write(self.data.join("hybrid_key.json"), b"{\"pq\":\"keep\"}").unwrap();
    }

    fn fingerprint(&self) -> String {
        health::identity_fingerprint(&health::identity_roots(&self.data)).unwrap()
    }

    /// Signs and installs release 0.2.2 (a node that will not start) over the versioned layout.
    async fn installed(&self, policy: Policy) -> Layout {
        let layout = self.versioned();
        self.publish(
            4,
            "0.2.2",
            Class::C0,
            11,
            &[("tenzro-node", NEW_NODE_BROKEN)],
        );
        apply_with(&self.ctx(), &layout, now_ms(), policy)
            .await
            .unwrap();
        layout
    }
}

#[cfg(unix)]
fn current_release(w: &World) -> String {
    std::fs::read_link(w.install.join("current"))
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

#[cfg(unix)]
/// A virtual clock: `sleep` moves it, nothing waits.
fn clock() -> Rc<Cell<u64>> {
    Rc::new(Cell::new(now_ms()))
}

#[cfg(unix)]
async fn gate(
    w: &World,
    layout: &Layout,
    t: &Rc<Cell<u64>>,
    probe: impl FnMut() -> anyhow::Result<Observation>,
) -> Verdict {
    let probe = std::cell::RefCell::new(probe);
    let (c, s) = (t.clone(), t.clone());
    health::run_gate(
        &w.data,
        layout,
        &health::identity_roots(&w.data),
        Duration::from_secs(10),
        move || c.get(),
        async move |d| s.set(s.get() + d.as_millis() as u64),
        async || (probe.borrow_mut())(),
    )
    .await
    .unwrap()
}

#[cfg(unix)]
fn ok(height: u64, certified: u64) -> anyhow::Result<Observation> {
    Ok(Observation { height, certified })
}

#[cfg(unix)]
#[tokio::test]
async fn apply_opens_a_trial_and_the_identity_files_are_untouched() {
    let w = World::new();
    w.identity();
    let before = w.fingerprint();
    w.installed(Policy::default()).await;
    assert_eq!(
        current_release(&w),
        "0.2.2",
        "the new release is in the slot that current now points at"
    );
    assert!(
        w.install.join("versions/0.2.1/bin/tenzro-node").is_file(),
        "the old slot is kept"
    );
    let t = health::load(&w.data).unwrap().unwrap();
    assert_eq!(
        (t.release.as_str(), t.state, t.boot_attempts),
        ("0.2.2", TrialState::Pending, 0)
    );
    assert_eq!(t.previous.as_deref(), Some("0.2.1"));
    assert_eq!(
        w.fingerprint(),
        before,
        "apply wrote nothing under the identity files"
    );
    assert_eq!(read(&w.data.join("device-keys/ab12/handle")), KEY_BYTES);
}

#[cfg(unix)]
#[tokio::test]
async fn a_release_that_stays_healthy_through_the_window_is_marked_good() {
    let w = World::new();
    w.identity();
    let layout = w.installed(Policy::default()).await;
    assert_eq!(
        health::record_boot(&w.data, &layout, now_ms()).unwrap(),
        BootDecision::Proceed { attempt: 1 }
    );
    let t = clock();
    let n = Cell::new(100);
    let v = gate(&w, &layout, &t, || {
        n.set(n.get() + 1);
        ok(n.get(), n.get() - 5)
    })
    .await;
    assert_eq!(v, Verdict::Good);
    let tr = health::load(&w.data).unwrap().unwrap();
    assert_eq!((tr.state, tr.boot_attempts), (TrialState::Good, 0));
    assert_eq!(
        current_release(&w),
        "0.2.2",
        "a good release stays installed"
    );
    assert_eq!(
        health::record_boot(&w.data, &layout, now_ms()).unwrap(),
        BootDecision::NoTrial,
        "starts are no longer counted"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_node_that_never_answers_is_rolled_back_when_the_window_ends() {
    let w = World::new();
    w.identity();
    let before = w.fingerprint();
    let layout = w
        .installed(Policy {
            window_ms: 60_000,
            ..Policy::default()
        })
        .await;
    health::record_boot(&w.data, &layout, now_ms()).unwrap();
    let t = clock();
    let v = gate(&w, &layout, &t, || {
        Err(anyhow::anyhow!("connection refused"))
    })
    .await;
    assert!(
        matches!(
            v,
            Verdict::RolledBack(Reason::WindowExpired {
                healthy_checks: 0,
                needed: 3
            })
        ),
        "{v:?}"
    );
    assert_eq!(
        current_release(&w),
        "0.2.1",
        "current points at the old slot again"
    );
    assert_eq!(read(&w.install.join("current/bin/tenzro-node")), OLD_NODE);
    let tr = health::load(&w.data).unwrap().unwrap();
    assert_eq!(tr.state, TrialState::RolledBack);
    let rec = update_state::load(&w.data).unwrap();
    assert_eq!(
        rec.installed_sha256,
        Some(update_state::file_sha256(&w.install.join("current/bin/tenzro-node")).unwrap())
    );
    assert_eq!(
        w.fingerprint(),
        before,
        "identity is the same after the rollback"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn finality_going_backwards_resets_the_run_of_healthy_checks() {
    let w = World::new();
    let layout = w
        .installed(Policy {
            window_ms: 50_000,
            ..Policy::default()
        })
        .await;
    health::record_boot(&w.data, &layout, now_ms()).unwrap();
    let t = clock();
    let seq = std::cell::RefCell::new(
        vec![(10, 10), (11, 11), (12, 5), (13, 13), (14, 14), (15, 15)].into_iter(),
    );
    // 10, 11 healthy; 5 is below 11 (reset); then 13, 14, 15 are three in a row.
    let v = gate(&w, &layout, &t, || {
        let (h, c) = seq.borrow_mut().next().unwrap_or((15, 15));
        ok(h, c)
    })
    .await;
    assert_eq!(v, Verdict::Good);
    assert_eq!(health::load(&w.data).unwrap().unwrap().certified_seen, 15);
}

#[cfg(unix)]
#[tokio::test]
async fn a_failed_probe_in_the_middle_does_not_count_toward_the_stable_run() {
    let w = World::new();
    let layout = w
        .installed(Policy {
            window_ms: 40_000,
            stable_checks: 3,
            ..Policy::default()
        })
        .await;
    health::record_boot(&w.data, &layout, now_ms()).unwrap();
    let t = clock();
    let i = Cell::new(0u64);
    // healthy, healthy, error, healthy, healthy, error ...: never three in a row inside 40 s at 10 s steps.
    let v = gate(&w, &layout, &t, || {
        i.set(i.get() + 1);
        if i.get().is_multiple_of(3) {
            Err(anyhow::anyhow!("timeout"))
        } else {
            ok(i.get(), i.get())
        }
    })
    .await;
    assert!(
        matches!(v, Verdict::RolledBack(Reason::WindowExpired { .. })),
        "{v:?}"
    );
    assert_eq!(current_release(&w), "0.2.1");
}

#[cfg(unix)]
#[tokio::test]
async fn the_boot_counter_rolls_back_a_release_that_keeps_crashing() {
    let w = World::new();
    w.identity();
    let before = w.fingerprint();
    let layout = w
        .installed(Policy {
            max_boot_attempts: 3,
            ..Policy::default()
        })
        .await;
    for attempt in 1..=3 {
        assert_eq!(
            health::record_boot(&w.data, &layout, now_ms()).unwrap(),
            BootDecision::Proceed { attempt }
        );
        assert_eq!(
            current_release(&w),
            "0.2.2",
            "start {attempt} still runs the new release"
        );
    }
    let fourth = health::record_boot(&w.data, &layout, now_ms()).unwrap();
    assert_eq!(
        fourth,
        BootDecision::RolledBack(Reason::BootAttempts {
            attempts: 3,
            limit: 3
        })
    );
    assert_eq!(current_release(&w), "0.2.1");
    assert_eq!(read(&w.install.join("current/bin/tenzro-node")), OLD_NODE);
    assert_eq!(
        health::load(&w.data).unwrap().unwrap().state,
        TrialState::RolledBack
    );
    assert_eq!(
        health::record_boot(&w.data, &layout, now_ms()).unwrap(),
        BootDecision::NoTrial,
        "the restored release is not counted"
    );
    assert_eq!(w.fingerprint(), before);
}

#[cfg(unix)]
#[tokio::test]
async fn a_start_after_the_window_ended_without_a_good_mark_rolls_back() {
    let w = World::new();
    let layout = w
        .installed(Policy {
            window_ms: 60_000,
            ..Policy::default()
        })
        .await;
    let t0 = now_ms();
    assert_eq!(
        health::record_boot(&w.data, &layout, t0).unwrap(),
        BootDecision::Proceed { attempt: 1 }
    );
    assert_eq!(
        health::record_boot(&w.data, &layout, t0 + 30_000).unwrap(),
        BootDecision::Proceed { attempt: 2 }
    );
    let late = health::record_boot(&w.data, &layout, t0 + 61_000).unwrap();
    assert!(
        matches!(late, BootDecision::RolledBack(Reason::WindowExpired { .. })),
        "{late:?}"
    );
    assert_eq!(current_release(&w), "0.2.1");
}

#[cfg(unix)]
#[tokio::test]
async fn changed_identity_files_fail_the_gate_and_roll_back() {
    let w = World::new();
    w.identity();
    let layout = w.installed(Policy::default()).await;
    health::record_boot(&w.data, &layout, now_ms()).unwrap();
    std::fs::write(w.data.join("device-keys/ab12/handle"), b"a different key").unwrap();
    let t = clock();
    let v = gate(&w, &layout, &t, || ok(1, 1)).await;
    assert_eq!(v, Verdict::RolledBack(Reason::IdentityChanged));
    assert_eq!(current_release(&w), "0.2.1");
}

#[cfg(unix)]
#[tokio::test]
async fn identity_is_the_same_across_update_forced_failure_and_manual_rollback() {
    let w = World::new();
    w.identity();
    let fp = w.fingerprint();
    let layout = w
        .installed(Policy {
            window_ms: 30_000,
            ..Policy::default()
        })
        .await;
    assert_eq!(w.fingerprint(), fp, "after update");
    health::record_boot(&w.data, &layout, now_ms()).unwrap();
    let t = clock();
    gate(&w, &layout, &t, || Err(anyhow::anyhow!("forced failure"))).await;
    assert_eq!(w.fingerprint(), fp, "after the automatic rollback");
    // Update again with a higher manifest, then undo it by hand.
    w.publish(5, "0.2.3", Class::C0, 12, &[("tenzro-node", b"newer node")]);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(current_release(&w), "0.2.3");
    install::rollback(&layout).unwrap();
    health::note_manual_rollback(&w.data).unwrap();
    assert_eq!(w.fingerprint(), fp, "after the manual rollback");
    assert_eq!(
        health::load(&w.data).unwrap().unwrap().reason,
        Some(Reason::Manual)
    );
    assert_eq!(read(&w.data.join("device-keys/ab12/handle")), KEY_BYTES);
}

#[cfg(unix)]
#[tokio::test]
async fn the_gate_refuses_when_no_trial_is_open_or_it_already_ended() {
    let none = World::new();
    let bare = none.versioned();
    let r = health::run_gate(
        &none.data,
        &bare,
        &[],
        Duration::from_secs(1),
        || 0,
        async |_| {},
        async || ok(1, 1),
    )
    .await;
    assert!(r.unwrap_err().to_string().contains("no update trial"));
    let w = World::new();
    let layout = w.installed(Policy::default()).await;
    health::record_boot(&w.data, &layout, now_ms()).unwrap();
    let t = clock();
    assert_eq!(gate(&w, &layout, &t, || ok(1, 1)).await, Verdict::Good);
    let again = health::run_gate(
        &w.data,
        &layout,
        &[],
        Duration::from_secs(1),
        || 0,
        async |_| {},
        async || ok(1, 1),
    )
    .await;
    assert!(again.unwrap_err().to_string().contains("already ended"));
}

#[cfg(unix)]
#[tokio::test]
async fn the_gate_reads_a_real_json_rpc_endpoint() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let result = if req.contains("eth_blockNumber") {
                    "\"0x2a\""
                } else {
                    "{\"certified\":\"0x28\"}"
                };
                let body = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{result}}}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                s.write_all(resp.as_bytes()).await.unwrap();
            });
        }
    });
    let client = reqwest::Client::new();
    assert_eq!(
        health::probe_rpc(&client, &url).await.unwrap(),
        Observation {
            height: 42,
            certified: 40
        }
    );
    assert!(
        health::probe_rpc(&client, "http://127.0.0.1:1")
            .await
            .is_err()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_rollback_made_while_the_gate_runs_ends_the_gate_as_rolled_back() {
    let w = World::new();
    let layout = w.installed(Policy::default()).await;
    let t = clock();
    let v = gate(&w, &layout, &t, || {
        // The service keeps failing to start the new release. Its fourth
        // start restores the previous one, and that one answers.
        for _ in 0..4 {
            health::record_boot(&w.data, &layout, now_ms()).unwrap();
        }
        ok(10, 5)
    })
    .await;
    assert!(
        matches!(
            v,
            Verdict::RolledBack(Reason::BootAttempts {
                attempts: 3,
                limit: 3
            })
        ),
        "{v:?}"
    );
    assert_eq!(current_release(&w), "0.2.1");
    assert_eq!(
        health::load(&w.data).unwrap().unwrap().state,
        TrialState::RolledBack,
        "the previous release answering does not mark the new one good"
    );
}

#[cfg(unix)]
/// Bare `tenzro update`: the decisions, and the whole flow on a stand-in machine.
mod whole {
    use std::path::PathBuf;
    use std::time::Duration;

    use anyhow::{Result, anyhow, bail};
    use clap::Parser;

    use super::*;
    use crate::commands::service::NodeService;
    use crate::commands::update::run::{self, Consent, Machine, Opts, Outcome, Plan, Role, Why};

    #[derive(Debug, Parser)]
    struct Cli {
        #[command(flatten)]
        update: UpdateCmd,
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("update").chain(args.iter().copied()))
    }

    #[test]
    fn the_bare_form_and_every_step_parse_and_their_options_do_not_mix() {
        assert!(parse(&[]).unwrap().update.step.is_none());
        assert!(
            parse(&["--yes", "--no-restart", "--channel", "/srv/channel"])
                .unwrap()
                .update
                .step
                .is_none()
        );
        for step in [
            "check",
            "apply",
            "verify",
            "rollback",
            "boot-check",
            "notices",
        ] {
            assert!(parse(&[step]).unwrap().update.step.is_some(), "{step}");
        }
        assert!(matches!(
            parse(&["apply", "--channel", "/srv/channel"])
                .unwrap()
                .update
                .step,
            Some(UpdateCommand::Apply(_))
        ));
        // An option of the bare form is not an option of a step, in either position.
        assert!(parse(&["--yes", "check"]).is_err());
        assert!(parse(&["check", "--yes"]).is_err());
        assert!(parse(&["apply", "--yes"]).is_err());
        assert!(parse(&["verify", "--no-restart"]).is_err());
    }

    #[test]
    fn nothing_is_installed_without_a_yes_or_a_terminal_to_ask_on() {
        assert_eq!(run::consent(true, true), Consent::Given);
        assert_eq!(run::consent(true, false), Consent::Given);
        assert_eq!(run::consent(false, true), Consent::Ask);
        assert_eq!(run::consent(false, false), Consent::Missing);
    }

    #[test]
    fn the_node_is_restarted_only_through_its_service_and_only_when_it_serves_no_role() {
        let unit = NodeService::Systemd(PathBuf::from("/etc/systemd/system/tenzro-node.service"));
        let agent = NodeService::Launchd(PathBuf::from(
            "/Users/a/Library/LaunchAgents/network.tenzro.node.plist",
        ));
        let none = NodeService::None;

        assert_eq!(run::plan("linux", &unit, Role::None, false), Plan::Restart);
        assert_eq!(run::plan("macos", &agent, Role::None, false), Plan::Restart);

        // --no-restart wins over everything.
        assert_eq!(
            run::plan("linux", &unit, Role::None, true),
            Plan::InstallOnly(Why::Asked)
        );
        assert_eq!(
            run::plan("linux", &unit, Role::Serves, true),
            Plan::InstallOnly(Why::Asked)
        );
        // A node that serves a role is never restarted here, whatever runs it.
        assert_eq!(
            run::plan("linux", &unit, Role::Serves, false),
            Plan::InstallOnly(Why::ServesRole)
        );
        assert_eq!(
            run::plan("macos", &agent, Role::Serves, false),
            Plan::InstallOnly(Why::ServesRole)
        );
        assert_eq!(
            run::plan("linux", &none, Role::Serves, false),
            Plan::InstallOnly(Why::ServesRole)
        );
        // No service, or a service of the other system: nothing to restart.
        assert_eq!(
            run::plan("linux", &none, Role::None, false),
            Plan::InstallOnly(Why::NoService)
        );
        assert_eq!(
            run::plan("macos", &none, Role::None, false),
            Plan::InstallOnly(Why::NoService)
        );
        assert_eq!(
            run::plan("linux", &agent, Role::None, false),
            Plan::InstallOnly(Why::NoService)
        );
        assert_eq!(
            run::plan("macos", &unit, Role::None, false),
            Plan::InstallOnly(Why::NoService)
        );
        assert_eq!(
            run::plan("windows", &none, Role::None, false),
            Plan::InstallOnly(Why::NoServiceHere)
        );
        assert_eq!(
            run::plan("windows", &unit, Role::None, false),
            Plan::InstallOnly(Why::NoServiceHere)
        );
        // A node that does not say what it serves is not restarted.
        assert_eq!(
            run::plan("linux", &unit, Role::Unknown, false),
            Plan::InstallOnly(Why::RoleUnknown)
        );
        assert_eq!(
            run::plan("macos", &agent, Role::Unknown, false),
            Plan::InstallOnly(Why::RoleUnknown)
        );
    }

    #[test]
    fn the_roles_a_node_reports_decide_whether_it_serves_one() {
        let role = |v: serde_json::Value| run::role_of(&v);
        assert_eq!(
            role(serde_json::json!({"roles": ["validator"]})),
            Role::Serves
        );
        assert_eq!(
            role(serde_json::json!({"roles": ["user", "provider"]})),
            Role::Serves
        );
        assert_eq!(
            role(serde_json::json!({"roles": "user, validator"})),
            Role::Serves
        );
        assert_eq!(role(serde_json::json!({"roles": ["user"]})), Role::None);
        assert_eq!(role(serde_json::json!({"roles": []})), Role::None);
        assert_eq!(role(serde_json::json!({"roles": "user"})), Role::None);
        assert_eq!(role(serde_json::json!({"height": 7})), Role::Unknown);
        assert_eq!(role(serde_json::json!({"roles": 3})), Role::Unknown);
    }

    #[cfg(unix)]
    #[test]
    fn a_service_that_starts_another_program_is_told_apart_from_the_node_just_installed() {
        let w = World::new();
        let layout = w.versioned();
        let node = layout.binary("tenzro-node");
        // Through `current`, or by the release directory `current` points at: the same file.
        assert_eq!(run::mismatch(Some(node.clone()), &node), None);
        assert_eq!(
            run::mismatch(
                Some(w.install.join("versions/0.2.1/bin/tenzro-node")),
                &node
            ),
            None
        );

        // A release directory that is no longer current.
        let old = w.install.join("versions/0.2.0/bin");
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("tenzro-node"), OLD_NODE).unwrap();
        let starts = old.join("tenzro-node");
        assert_eq!(
            run::mismatch(Some(starts.clone()), &node),
            Some(Why::OtherProgram {
                starts: Some(starts.display().to_string()),
                installed: node.display().to_string()
            })
        );
        // A program that is not there, and a unit that could not be read.
        assert!(matches!(
            run::mismatch(Some(PathBuf::from("/nowhere/tenzro-node")), &node),
            Some(Why::OtherProgram {
                starts: Some(_),
                ..
            })
        ));
        assert_eq!(
            run::mismatch(None, &node),
            Some(Why::OtherProgram {
                starts: None,
                installed: node.display().to_string()
            })
        );
    }

    #[cfg(unix)]
    /// A machine with no service and no node: it counts what the flow asks of
    /// it, and its clock moves only when the flow sleeps.
    struct Fake {
        data: PathBuf,
        layout: Layout,
        t: Rc<Cell<u64>>,
        plan: Plan,
        answer: bool,
        mismatch: Option<Why>,
        restart_fails: bool,
        healthy: bool,
        asked: Cell<u32>,
        planned: Cell<u32>,
        restarts: Cell<u32>,
        probes: Cell<u64>,
    }

    #[cfg(unix)]
    impl Fake {
        /// A machine over the install `w` already holds.
        fn new(w: &World, plan: Plan, healthy: bool) -> Fake {
            Fake {
                data: w.data.clone(),
                layout: Layout::detect(&w.install),
                t: clock(),
                plan,
                answer: true,
                mismatch: None,
                restart_fails: false,
                healthy,
                asked: Cell::new(0),
                planned: Cell::new(0),
                restarts: Cell::new(0),
                probes: Cell::new(0),
            }
        }
    }

    #[cfg(unix)]
    impl Machine for Fake {
        fn now(&self) -> u64 {
            self.t.get()
        }

        fn confirm(&self, _question: &str) -> Result<bool> {
            self.asked.set(self.asked.get() + 1);
            Ok(self.answer)
        }

        async fn plan(&self) -> Plan {
            self.planned.set(self.planned.get() + 1);
            self.plan.clone()
        }

        fn service_mismatch(&self, _layout: &Layout) -> Option<Why> {
            self.mismatch.clone()
        }

        async fn restart_advice(&self) -> String {
            "Restart between two epochs.".into()
        }

        fn restart(&self) -> Result<()> {
            self.restarts.set(self.restarts.get() + 1);
            if self.restart_fails {
                bail!(
                    "`sudo systemctl restart tenzro-node` failed; the node service was not restarted"
                );
            }
            // The unit counts the start before the node runs.
            health::record_boot(&self.data, &self.layout, self.t.get())?;
            Ok(())
        }

        async fn sleep(&self, d: Duration) {
            self.t.set(self.t.get() + d.as_millis() as u64);
        }

        async fn probe(&self) -> Result<Observation> {
            self.probes.set(self.probes.get() + 1);
            if self.healthy {
                ok(100 + self.probes.get(), 90 + self.probes.get())
            } else {
                Err(anyhow!("connection refused"))
            }
        }
    }

    #[cfg(unix)]
    fn opts(consent: Consent) -> Opts {
        Opts {
            consent,
            policy: Policy {
                window_ms: 60_000,
                ..Policy::default()
            },
            interval: Duration::from_secs(10),
        }
    }

    #[cfg(unix)]
    /// A world whose channel offers 0.2.2 over the installed 0.2.1.
    fn offered() -> (World, Layout) {
        let w = World::new();
        let layout = w.versioned();
        w.publish(
            4,
            "0.2.2",
            Class::C0,
            11,
            &[("tenzro-node", NEW_NODE_BROKEN)],
        );
        (w, layout)
    }

    #[cfg(unix)]
    fn trial_state(w: &World) -> Option<TrialState> {
        health::load(&w.data).unwrap().map(|t| t.state)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_whole_update_installs_restarts_once_and_marks_the_release_good() {
        let (w, layout) = offered();
        let m = Fake::new(&w, Plan::Restart, true);
        let out = run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Healthy);
        assert_eq!(m.restarts.get(), 1, "one restart, onto the new release");
        assert_eq!(m.asked.get(), 0, "--yes asks nothing");
        assert_eq!(m.probes.get(), 3, "three healthy checks in a row");
        assert_eq!(current_release(&w), "0.2.2");
        assert_eq!(trial_state(&w), Some(TrialState::Good));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_release_that_does_not_stay_healthy_is_rolled_back_and_the_service_restarted_onto_the_previous_one()
     {
        let (w, layout) = offered();
        w.identity();
        let before = w.fingerprint();
        let m = Fake::new(&w, Plan::Restart, false);
        let out = run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
            .await
            .unwrap();
        assert_eq!(
            out,
            Outcome::RolledBack {
                reason: Reason::WindowExpired {
                    healthy_checks: 0,
                    needed: 3
                },
                previous_runs: true
            }
        );
        assert_eq!(
            m.restarts.get(),
            2,
            "onto the new release, then back onto the previous one"
        );
        assert_eq!(current_release(&w), "0.2.1");
        assert_eq!(read(&w.install.join("current/bin/tenzro-node")), OLD_NODE);
        assert_eq!(trial_state(&w), Some(TrialState::RolledBack));
        assert_eq!(
            w.fingerprint(),
            before,
            "identity is the same after the rollback"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_up_to_date_machine_and_a_held_release_install_and_restart_nothing() {
        let w = World::new();
        let layout = w.versioned();
        w.publish(4, "0.2.1", Class::C0, 11, &[("tenzro", OLD_CLI)]);
        let m = Fake::new(&w, Plan::Restart, true);
        assert_eq!(
            run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
                .await
                .unwrap(),
            Outcome::UpToDate
        );

        w.publish(5, "0.3.0", Class::C1, 12, &[("tenzro", NEW_CLI)]);
        assert_eq!(
            run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
                .await
                .unwrap(),
            Outcome::Held
        );

        assert_eq!(
            (m.planned.get(), m.asked.get(), m.restarts.get()),
            (0, 0, 0)
        );
        assert_eq!(current_release(&w), "0.2.1");
        assert_eq!(trial_state(&w), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_unreadable_channel_is_an_error_and_installs_nothing() {
        let w = World::new();
        let layout = w.versioned();
        let m = Fake::new(&w, Plan::Restart, true);
        assert!(
            run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
                .await
                .is_err()
        );
        assert_eq!((m.planned.get(), m.restarts.get()), (0, 0));
        assert_eq!(current_release(&w), "0.2.1");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn with_no_terminal_and_no_yes_nothing_is_installed() {
        let (w, layout) = offered();
        let m = Fake::new(&w, Plan::Restart, true);
        let out = run::flow(&w.ctx(), &layout, &opts(Consent::Missing), &m)
            .await
            .unwrap();
        assert_eq!(
            out,
            Outcome::NeedsYes {
                release: "0.2.2".into()
            }
        );
        assert_eq!(
            (m.planned.get(), m.asked.get(), m.restarts.get()),
            (0, 0, 0)
        );
        assert_eq!(current_release(&w), "0.2.1");
        assert_eq!(trial_state(&w), None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn on_a_terminal_the_operator_is_asked_once_and_a_no_installs_nothing() {
        let (w, layout) = offered();
        let mut m = Fake::new(&w, Plan::Restart, true);
        m.answer = false;
        assert_eq!(
            run::flow(&w.ctx(), &layout, &opts(Consent::Ask), &m)
                .await
                .unwrap(),
            Outcome::Declined
        );
        assert_eq!((m.asked.get(), m.restarts.get()), (1, 0));
        assert_eq!(current_release(&w), "0.2.1");
        assert_eq!(trial_state(&w), None);

        m.answer = true;
        assert_eq!(
            run::flow(&w.ctx(), &layout, &opts(Consent::Ask), &m)
                .await
                .unwrap(),
            Outcome::Healthy
        );
        assert_eq!((m.asked.get(), m.restarts.get()), (2, 1));
        assert_eq!(current_release(&w), "0.2.2");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_node_that_serves_a_role_gets_the_release_installed_and_is_not_restarted() {
        let (w, layout) = offered();
        let m = Fake::new(&w, Plan::InstallOnly(Why::ServesRole), true);
        let out = run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Installed(Why::ServesRole));
        assert_eq!((m.restarts.get(), m.probes.get()), (0, 0));
        assert_eq!(current_release(&w), "0.2.2");
        assert_eq!(
            trial_state(&w),
            Some(TrialState::Pending),
            "the trial waits for the operator's restart and `tenzro update verify`"
        );

        // Run again before the restart: nothing is installed twice, and the trial stays open.
        let again = run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
            .await
            .unwrap();
        assert_eq!(again, Outcome::UpToDate);
        assert_eq!(m.restarts.get(), 0);
        assert_eq!(trial_state(&w), Some(TrialState::Pending));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_service_that_would_start_another_program_is_not_restarted() {
        let (w, layout) = offered();
        let mut m = Fake::new(&w, Plan::Restart, true);
        let why = Why::OtherProgram {
            starts: Some("/opt/old/tenzro-node".into()),
            installed: layout.binary("tenzro-node").display().to_string(),
        };
        m.mismatch = Some(why.clone());
        let out = run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Installed(why));
        assert_eq!((m.restarts.get(), m.probes.get()), (0, 0));
        assert_eq!(current_release(&w), "0.2.2");
        assert_eq!(trial_state(&w), Some(TrialState::Pending));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_restart_that_fails_is_an_error_and_leaves_the_release_installed_for_the_manual_steps()
     {
        let (w, layout) = offered();
        let mut m = Fake::new(&w, Plan::Restart, true);
        m.restart_fails = true;
        let err = run::flow(&w.ctx(), &layout, &opts(Consent::Given), &m)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "the node was not restarted onto 0.2.2");
        assert_eq!(
            (m.restarts.get(), m.probes.get()),
            (1, 0),
            "the health gate does not run against the old node"
        );
        assert_eq!(current_release(&w), "0.2.2");
        assert_eq!(trial_state(&w), Some(TrialState::Pending));
    }
}

#[test]
fn windows_is_told_to_install_the_msi_and_unix_systems_may_update_in_place() {
    let e = install::require_in_place_update("windows")
        .unwrap_err()
        .to_string();
    assert!(e.contains("MSI") && e.contains("Windows"), "{e}");
    for os in ["linux", "macos"] {
        install::require_in_place_update(os).unwrap();
    }
}

#[cfg(windows)]
#[tokio::test]
async fn apply_on_windows_refuses_before_reading_any_release() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("MSI"), "{e}");
    assert_eq!(read(&w.install.join("tenzro")), OLD_CLI);
}
