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
            platform_given: false,
            // These tests are about everything but the start check: their
            // stand-in binaries are not programs. The check's own tests run it.
            start_check: |_| Ok(()),
            running: "0.2.1".parse().unwrap(),
            // The flat fixture's `tenzro`: a flat install's release is that of
            // the `tenzro` running from it.
            exe: self.install.join("tenzro"),
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

    /// What `install.sh` and `install.ps1` make: versions/0.2.1/bin/*, the
    /// `RELEASE` file, and `current` pointing at versions/0.2.1 (a symbolic
    /// link on Unix, a junction on Windows).
    fn versioned(&self) -> Layout {
        let bin = self.install.join("versions/0.2.1/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join(install::file_name("tenzro")), OLD_CLI).unwrap();
        std::fs::write(bin.join(install::file_name("tenzro-node")), OLD_NODE).unwrap();
        std::fs::write(
            self.install.join("versions/0.2.1/README"),
            b"untouched file",
        )
        .unwrap();
        std::fs::write(self.install.join("versions/0.2.1/RELEASE"), b"0.2.1\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("versions/0.2.1", self.install.join("current")).unwrap();
        #[cfg(windows)]
        install::junction::point(
            &self.install.join("current"),
            &self.install.join("versions").join("0.2.1"),
        )
        .unwrap();
        Layout::detect(&self.install)
    }
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

#[tokio::test]
async fn check_reports_a_newer_c0_update_and_remembers_it() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    let found = check(&w.ctx(), &layout, now_ms()).await.unwrap();
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
    let layout = w.flat();
    w.publish(4, "0.2.1", Class::C0, 11, &[("tenzro", OLD_CLI)]);
    assert_eq!(
        check(&w.ctx(), &layout, now_ms()).await.unwrap(),
        Availability::UpToDate
    );
    w.publish(5, "0.3.0", Class::C1, 12, &[("tenzro", NEW_CLI)]);
    assert!(matches!(
        check(&w.ctx(), &layout, now_ms()).await.unwrap(),
        Availability::Held {
            class: Class::C1,
            ..
        }
    ));
}

#[tokio::test]
async fn check_refuses_a_replayed_older_timestamp_after_a_newer_one_was_seen() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    check(&w.ctx(), &layout, now_ms()).await.unwrap();
    w.publish(4, "0.2.2", Class::C0, 8, &[("tenzro", NEW_CLI)]);
    let e = check(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("replayed timestamp"), "{e}");
}

#[cfg(unix)]
/// The channel serves only a delta for the node binary, no full file: the
/// update still installs, rebuilt from the installed file, and the result is
/// the signed file. A delta from another base, or one that rebuilds the wrong
/// bytes, is not used and the missing full file then fails the update.
#[tokio::test]
async fn a_delta_from_the_installed_file_replaces_the_full_download() {
    let w = World::new();
    let layout = w.flat();
    // A delta is worth fetching only for a file larger than its own header.
    let old_node: Vec<u8> = (0..4096u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(w.install.join("tenzro-node"), &old_node).unwrap();
    let new_node = [old_node.as_slice(), b" and a patch"].concat();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro", NEW_CLI), ("tenzro-node", &new_node)],
    );
    let full = w.channel.join("files").join("tenzro-node");
    std::fs::remove_file(&full).unwrap();
    let base_sha = hex::encode(Sha256::digest(&old_node));
    let delta_at = w
        .channel
        .join(delta::delta_path("files/tenzro-node", &base_sha));

    // A delta made from another file is refused, and there is no full file.
    std::fs::write(&delta_at, delta::encode(b"some other build", &new_node)).unwrap();
    assert!(apply(&w.ctx(), &layout, now_ms()).await.is_err());

    std::fs::write(&delta_at, delta::encode(&old_node, &new_node)).unwrap();
    let a = apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(a.release, "0.2.2");
    assert_eq!(read(&w.install.join("tenzro-node")), new_node);
    assert_eq!(read(&w.install.join("tenzro")), NEW_CLI);
}

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
    // Files the update did not name came along from the old release; the
    // release file names the new release, and the old one keeps its own.
    assert_eq!(read(&w.install.join("current/README")), b"untouched file");
    assert_eq!(read(&w.install.join("current/RELEASE")), b"0.2.2\n");
    assert_eq!(read(&w.install.join("versions/0.2.1/RELEASE")), b"0.2.1\n");
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
    w.publish(5, "0.2.9", Class::C0, 12, &[("tenzro", b"third")]);
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
    let staged = staging_dir(&w.data).join(format!(
        "{}.part",
        hex::encode(Sha256::digest(NEW_NODE_BROKEN))
    ));
    assert!(
        !staged.exists(),
        "a file that failed its check is not resumed"
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
    assert_eq!(
        Channel::parse("stable"),
        Channel::Http("https://downloads.tenzro.com/update/stable".into())
    );
    assert_eq!(Channel::parse("./beta"), Channel::Dir("./beta".into()));
}

// ---- the trial: boot attempts, the health window, automatic rollback, identity ----

use super::health::{self, BootDecision, Policy, Reason, TrialState};
#[cfg(unix)]
use super::health::{Observation, Verdict};
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
    w.publish(5, "0.2.9", Class::C0, 12, &[("tenzro-node", b"newer node")]);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(current_release(&w), "0.2.9");
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
    fn every_role_but_following_the_chain_keeps_update_run_from_restarting_the_node() {
        use tenzro_types::{NetworkRole, RoleSet};
        let follows = [
            NetworkRole::FullNode,
            NetworkRole::LightClient,
            NetworkRole::MicroNode,
        ];
        for r in NetworkRole::ALL {
            // The status as the node serializes it: its role set, on its own and beside a follower role.
            for set in [vec![r], vec![NetworkRole::LightClient, r]] {
                let roles = serde_json::to_value(RoleSet::from_roles(set)).unwrap();
                let status = serde_json::json!({ "roles": roles });
                let want = if follows.contains(&r) {
                    Role::None
                } else {
                    Role::Serves
                };
                assert_eq!(run::role_of(&status), want, "{r:?} in {status}");
            }
        }
    }

    #[test]
    fn the_roles_a_node_reports_decide_whether_it_serves_one() {
        let role = |v: serde_json::Value| run::role_of(&v);
        // The names are the ones a node's status carries.
        assert_eq!(
            role(serde_json::json!({"roles": ["Validator"]})),
            Role::Serves
        );
        assert_eq!(
            role(serde_json::json!({"roles": ["LightClient", "StorageProvider"]})),
            Role::Serves
        );
        assert_eq!(
            role(serde_json::json!({"roles": "FullNode, Validator"})),
            Role::Serves
        );
        assert_eq!(
            role(serde_json::json!({"roles": ["LightClient"]})),
            Role::None
        );
        assert_eq!(role(serde_json::json!({"roles": []})), Role::Unknown);
        assert_eq!(role(serde_json::json!({"roles": ""})), Role::Unknown);
        assert_eq!(
            role(serde_json::json!({"roles": ["LightClient", {"role": "Validator"}]})),
            Role::Unknown
        );
        assert_eq!(role(serde_json::json!({"roles": "MicroNode"})), Role::None);
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

        async fn restart(&self) -> Result<()> {
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
fn an_msi_install_on_windows_is_told_to_use_the_msi_and_a_versioned_one_updates_everywhere() {
    let flat = Layout::Flat {
        dir: PathBuf::from("C:\\Program Files\\Tenzro\\bin"),
    };
    let versioned = Layout::Versioned {
        root: PathBuf::from("C:\\Users\\a\\.tenzro\\install"),
    };
    let e = install::require_in_place_update("windows", &flat)
        .unwrap_err()
        .to_string();
    assert!(e.contains("MSI") && e.contains("Windows"), "{e}");
    install::require_in_place_update("windows", &versioned).unwrap();
    for os in ["linux", "macos"] {
        install::require_in_place_update(os, &flat).unwrap();
        install::require_in_place_update(os, &versioned).unwrap();
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

// ---- Resuming an interrupted update, the update lock, a superseded trial.

/// The staging file name of `content` (its SHA-256); the staging tests are
/// Unix-only because they need a versioned install.
#[cfg(unix)]
fn sha(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

const BIG_NODE: &[u8] = b"a new tenzro-node, long enough to be cut in two halves of bytes";

#[cfg(unix)]
#[tokio::test]
async fn an_interrupted_download_is_resumed_from_the_bytes_already_staged() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro-node", BIG_NODE)]);
    let half = BIG_NODE.len() / 2;
    // What an earlier run received before it stopped.
    let staging = staging_dir(&w.data);
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(
        staging.join(format!("{}.part", sha(BIG_NODE))),
        &BIG_NODE[..half],
    )
    .unwrap();
    // The channel's first half is unreadable garbage now: the install can only
    // be right if the first half came from the staged bytes.
    let mut served = vec![b'?'; half];
    served.extend_from_slice(&BIG_NODE[half..]);
    std::fs::write(w.channel.join("files/tenzro-node"), &served).unwrap();

    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(read(&w.install.join("tenzro-node")), BIG_NODE);
    assert!(
        !staging.exists(),
        "a finished update leaves no staging behind"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_file_already_staged_whole_is_not_downloaded_again() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro-node", BIG_NODE)]);
    let staging = staging_dir(&w.data);
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join(sha(BIG_NODE)), BIG_NODE).unwrap();
    std::fs::remove_file(w.channel.join("files/tenzro-node")).unwrap();

    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(read(&w.install.join("tenzro-node")), BIG_NODE);
}

#[cfg(unix)]
#[tokio::test]
async fn a_corrupt_partial_download_is_discarded_and_the_next_run_starts_over() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro-node", BIG_NODE)]);
    let part = staging_dir(&w.data).join(format!("{}.part", sha(BIG_NODE)));
    std::fs::create_dir_all(part.parent().unwrap()).unwrap();
    std::fs::write(&part, b"not the start of the file").unwrap();

    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("hashes to"), "{e}");
    assert!(!part.exists());
    assert_eq!(read(&w.install.join("tenzro-node")), OLD_NODE);

    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(read(&w.install.join("tenzro-node")), BIG_NODE);
}

#[cfg(unix)]
#[tokio::test]
async fn an_install_stopped_after_the_switch_is_completed_and_gets_its_trial() {
    let w = World::new();
    let layout = w.versioned();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro-node", NEW_NODE_BROKEN)],
    );
    // An earlier run staged the file, built the release and switched
    // `current`, then stopped before it opened the trial and recorded the
    // install.
    let staging = staging_dir(&w.data);
    std::fs::create_dir_all(&staging).unwrap();
    let staged = staging.join(sha(NEW_NODE_BROKEN));
    std::fs::copy(w.channel.join("files/tenzro-node"), &staged).unwrap();
    install::install(
        &layout,
        "0.2.2",
        &[("tenzro-node".into(), staged)],
        None,
        None,
        &|_| Ok(()),
    )
    .unwrap();
    assert_eq!(current_release(&w), "0.2.2");
    assert!(health::load(&w.data).unwrap().is_none());

    let a = apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(a.installed.previous_release.as_deref(), Some("0.2.1"));
    assert_eq!(current_release(&w), "0.2.2");
    assert_eq!(
        std::fs::read_link(w.install.join("previous")).unwrap(),
        Path::new("versions/0.2.1"),
        "the fallback is still the release that ran before"
    );
    let t = health::load(&w.data).unwrap().unwrap();
    assert_eq!(
        (t.state, t.previous.as_deref()),
        (TrialState::Pending, Some("0.2.1"))
    );
    assert_eq!(
        update_state::load(&w.data)
            .unwrap()
            .installed_manifest_version,
        4
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_release_current_with_other_bytes_than_the_signed_ones_is_refused() {
    let w = World::new();
    let layout = w.versioned();
    let fake = w.install.join("fake");
    std::fs::write(&fake, b"some other build").unwrap();
    install::install(
        &layout,
        "0.2.2",
        &[("tenzro-node".into(), fake)],
        None,
        None,
        &|_| Ok(()),
    )
    .unwrap();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro-node", NEW_NODE_BROKEN)],
    );
    // The release installed is 0.2.2 already: the channel offers nothing newer.
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("nothing to apply"), "{e}");
    // With the signed file staged, as an interrupted run of this update
    // leaves it, the update is finished only if `current` holds those bytes.
    let staging = staging_dir(&w.data);
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join(sha(NEW_NODE_BROKEN)), NEW_NODE_BROKEN).unwrap();
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("already current"), "{e}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_half_built_or_rolled_back_release_directory_is_rebuilt_from_the_verified_files() {
    let w = World::new();
    let layout = w.versioned();
    // Left by a run that stopped after building the directory, before the switch.
    std::fs::create_dir_all(w.install.join("versions/0.2.2/bin")).unwrap();
    std::fs::write(w.install.join("versions/0.2.2/bin/tenzro-node"), b"half").unwrap();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro-node", NEW_NODE_BROKEN)],
    );
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(
        read(&w.install.join("current/bin/tenzro-node")),
        NEW_NODE_BROKEN
    );
    assert_eq!(read(&w.install.join("current/bin/tenzro")), OLD_CLI);

    // Rolled back, then the same release republished under a newer manifest.
    install::rollback(&layout).unwrap();
    assert_eq!(current_release(&w), "0.2.1");
    w.publish(5, "0.2.2", Class::C0, 12, &[("tenzro-node", BIG_NODE)]);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(current_release(&w), "0.2.2");
    assert_eq!(read(&w.install.join("current/bin/tenzro-node")), BIG_NODE);
}

#[cfg(unix)]
#[tokio::test]
async fn a_flat_install_stopped_between_two_renames_keeps_the_real_previous_binaries() {
    let w = World::new();
    let layout = w.flat();
    // The earlier run renamed `tenzro` into place and stopped before `tenzro-node`.
    std::fs::write(w.install.join("tenzro.prev"), OLD_CLI).unwrap();
    std::fs::write(w.install.join("tenzro"), NEW_CLI).unwrap();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro", NEW_CLI), ("tenzro-node", NEW_NODE_BROKEN)],
    );
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(read(&w.install.join("tenzro")), NEW_CLI);
    assert_eq!(read(&w.install.join("tenzro-node")), NEW_NODE_BROKEN);
    assert_eq!(read(&w.install.join("tenzro.prev")), OLD_CLI);
    assert_eq!(read(&w.install.join("tenzro-node.prev")), OLD_NODE);
    install::rollback(&layout).unwrap();
    assert_eq!(read(&w.install.join("tenzro")), OLD_CLI);
    assert_eq!(read(&w.install.join("tenzro-node")), OLD_NODE);
}

#[cfg(unix)]
#[tokio::test]
async fn a_second_update_on_the_same_data_directory_waits_for_the_first() {
    let w = World::new();
    let layout = w.flat();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro", NEW_CLI)]);
    let held = lock(&w.data).await.unwrap();
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("another `tenzro update` is running"), "{e}");
    assert_eq!(read(&w.install.join("tenzro")), OLD_CLI);
    drop(held);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(read(&w.install.join("tenzro")), NEW_CLI);
}

/// A process started while the lock was held keeps a copy of it until it runs
/// its program; the lock released in the meantime is taken once that copy goes.
#[cfg(unix)]
#[tokio::test]
async fn a_lock_held_a_moment_longer_by_a_starting_process_is_still_taken() {
    let w = World::new();
    let held = lock(&w.data).await.unwrap();
    let copy = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        drop(held);
    });
    lock(&w.data).await.unwrap();
    copy.join().unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn a_trial_ends_when_another_release_is_made_current_and_never_rolls_that_back() {
    let w = World::new();
    let layout = w.installed(Policy::default()).await;
    // The installer is run again during the trial and makes another release current.
    let other = w.install.join("versions/tenzro-0.2.9-abcdef/bin");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("tenzro-node"), b"installer build").unwrap();
    let tmp = w.install.join("current.new");
    std::os::unix::fs::symlink("versions/tenzro-0.2.9-abcdef", &tmp).unwrap();
    std::fs::rename(&tmp, w.install.join("current")).unwrap();

    let mut clk = 0u64;
    let e = health::run_gate(
        &w.data,
        &layout,
        &health::identity_roots(&w.data),
        Duration::from_secs(1),
        || {
            clk += 1;
            clk
        },
        async |_| {},
        async || ok(1, 1),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(e.contains("no longer applies"), "{e}");
    assert_eq!(
        health::load(&w.data).unwrap().unwrap().state,
        TrialState::Superseded
    );
    for _ in 0..5 {
        assert_eq!(
            health::record_boot(&w.data, &layout, now_ms()).unwrap(),
            BootDecision::NoTrial
        );
    }
    assert_eq!(current_release(&w), "tenzro-0.2.9-abcdef");
}

#[cfg(unix)]
#[tokio::test]
async fn a_start_after_the_installer_moved_current_is_not_counted_against_the_trial() {
    let w = World::new();
    let layout = w
        .installed(Policy {
            max_boot_attempts: 1,
            ..Policy::default()
        })
        .await;
    let tmp = w.install.join("current.new");
    std::os::unix::fs::symlink("versions/0.2.1", &tmp).unwrap();
    std::fs::rename(&tmp, w.install.join("current")).unwrap();
    std::fs::remove_file(w.install.join("previous")).unwrap();
    for _ in 0..3 {
        assert_eq!(
            health::record_boot(&w.data, &layout, now_ms()).unwrap(),
            BootDecision::NoTrial
        );
    }
    assert_eq!(current_release(&w), "0.2.1");
}

#[test]
fn junction_targets_are_absolute_local_paths_in_nt_form() {
    use install::junction::target_names;
    assert_eq!(
        target_names(r"C:\Users\a\.tenzro\install\versions\0.2.2").unwrap(),
        (
            r"\??\C:\Users\a\.tenzro\install\versions\0.2.2".to_string(),
            r"C:\Users\a\.tenzro\install\versions\0.2.2".to_string()
        )
    );
    assert_eq!(
        target_names(r"\\?\D:\t\versions\x\").unwrap().0,
        r"\??\D:\t\versions\x",
        "a verbatim prefix and a trailing separator are dropped"
    );
    assert_eq!(target_names(r"E:\").unwrap().0, r"\??\E:\");
    for bad in [
        r"\\server\share\x",
        r"\\?\UNC\server\share",
        r"versions\x",
        "/home/a/x",
        r"C:/a/b",
    ] {
        assert!(target_names(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_junction_reparse_buffer_has_the_mount_point_layout() {
    use install::junction::{MOUNT_POINT_TAG, reparse_data};
    let target = r"C:\t\versions\0.2.2";
    let b = reparse_data(target).unwrap();
    let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]) as usize;
    let utf16 = |s: &str| -> Vec<u8> { s.encode_utf16().flat_map(u16::to_le_bytes).collect() };
    let nt = utf16(r"\??\C:\t\versions\0.2.2");
    let print = utf16(target);
    assert_eq!(
        u32::from_le_bytes(b[0..4].try_into().unwrap()),
        MOUNT_POINT_TAG
    );
    assert_eq!(
        u16_at(4),
        b.len() - 8,
        "ReparseDataLength counts what follows the header"
    );
    assert_eq!(u16_at(6), 0);
    assert_eq!((u16_at(8), u16_at(10)), (0, nt.len()));
    assert_eq!((u16_at(12), u16_at(14)), (nt.len() + 2, print.len()));
    let names = &b[16..];
    assert_eq!(&names[..nt.len()], &nt[..]);
    assert_eq!(&names[nt.len()..nt.len() + 2], &[0, 0]);
    assert_eq!(&names[nt.len() + 2..nt.len() + 2 + print.len()], &print[..]);
    assert_eq!(&names[nt.len() + 2 + print.len()..], &[0, 0]);

    let long = format!(r"C:\{}", "a".repeat(9000));
    assert!(
        reparse_data(&long).is_err(),
        "longer than a reparse point can hold"
    );
}

#[test]
fn the_windows_rollback_script_runs_the_previous_release_on_the_install_and_data_directory() {
    let s = install::rollback_cmd(
        Path::new(r"C:\Users\a b\.tenzro\install"),
        Path::new(r"C:\Users\a b\.tenzro\instances\default"),
    );
    assert!(s.starts_with("@echo off\r\n"));
    assert!(s.contains(
        "\"C:\\Users\\a b\\.tenzro\\install\\previous\\bin\\tenzro.exe\" update rollback --install-dir \"C:\\Users\\a b\\.tenzro\\install\" --data-dir \"C:\\Users\\a b\\.tenzro\\instances\\default\"\r\n"
    ), "{s}");
    assert!(
        s.contains("exit /b 1"),
        "a missing previous release is an error"
    );
}

#[test]
fn binaries_are_named_with_the_platform_executable_suffix() {
    let l = Layout::Flat {
        dir: PathBuf::from("d"),
    };
    assert_eq!(
        l.binary("tenzro-node"),
        Path::new("d").join(format!("tenzro-node{}", std::env::consts::EXE_SUFFIX))
    );
}

// ---- The downgrade check is made against the installed release.

/// Sets the `RELEASE` file of the fixture's installed release.
fn set_installed_release(w: &World, text: &str) {
    std::fs::write(w.install.join("versions/0.2.1/RELEASE"), text).unwrap();
}

#[tokio::test]
async fn a_release_older_than_the_installed_one_is_refused_though_newer_than_the_running_tenzro() {
    let w = World::new();
    let layout = w.versioned();
    // An older `tenzro` (0.2.1) pointed at a newer install, with a fresh data
    // directory: only the installed release can tell 0.2.5 is a downgrade.
    set_installed_release(&w, "0.3.0\n");
    w.publish(9, "0.2.5", Class::C0, 11, &[("tenzro-node", BIG_NODE)]);
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("older than the installed 0.3.0") && e.contains("downgrade"),
        "{e}"
    );
    let e = check(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("older than the installed 0.3.0"), "{e}");
    assert_eq!(layout.current_release().as_deref(), Some("0.2.1"));
    assert!(!w.install.join("versions/0.2.5").exists());
    assert!(health::load(&w.data).unwrap().is_none());
}

#[tokio::test]
async fn a_newer_tenzro_updates_an_older_install_to_a_release_between_the_two() {
    let w = World::new();
    let layout = w.versioned();
    set_installed_release(&w, "0.2.0\n");
    let mut ctx = w.ctx();
    ctx.running = "0.4.0".parse().unwrap();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro-node", BIG_NODE)]);
    assert!(matches!(
        check(&ctx, &layout, now_ms()).await.unwrap(),
        Availability::Available { .. }
    ));
    apply(&ctx, &layout, now_ms()).await.unwrap();
    assert_eq!(layout.current_release().as_deref(), Some("0.2.2"));
    assert_eq!(
        install::installed_release(&layout, ctx.running, &ctx.exe).unwrap(),
        "0.2.2".parse().unwrap()
    );
}

#[tokio::test]
async fn an_install_with_no_release_file_is_compared_with_the_running_tenzro_only_when_it_is_that_release()
 {
    let w = World::new();
    let layout = w.versioned();
    std::fs::remove_file(w.install.join("versions/0.2.1/RELEASE")).unwrap();
    w.publish(4, "0.2.2", Class::C0, 11, &[("tenzro-node", BIG_NODE)]);
    // A `tenzro` running from elsewhere cannot vouch for what is installed.
    let e = apply(&w.ctx(), &layout, now_ms())
        .await
        .unwrap_err()
        .to_string();
    assert!(e.contains("has no RELEASE file"), "{e}");
    assert_eq!(layout.current_release().as_deref(), Some("0.2.1"));
    // The installed release's own `tenzro` is that release.
    let mut ctx = w.ctx();
    ctx.exe = w
        .install
        .join("versions/0.2.1/bin")
        .join(install::file_name("tenzro"));
    apply(&ctx, &layout, now_ms()).await.unwrap();
    assert_eq!(layout.current_release().as_deref(), Some("0.2.2"));
}

#[test]
fn a_flat_install_is_compared_with_the_tenzro_running_from_it_and_no_other() {
    let w = World::new();
    let layout = w.flat();
    let running = "0.2.1".parse().unwrap();
    assert_eq!(
        install::installed_release(&layout, running, &w.install.join("tenzro")).unwrap(),
        running
    );
    let elsewhere = w.data.join("tenzro");
    std::fs::write(&elsewhere, b"another tenzro").unwrap();
    let e = install::installed_release(&layout, running, &elsewhere)
        .unwrap_err()
        .to_string();
    assert!(e.contains("not recorded"), "{e}");
}

#[test]
fn a_release_file_that_names_no_release_is_an_error() {
    let w = World::new();
    let layout = w.versioned();
    set_installed_release(&w, "latest\n");
    let e = install::installed_release(&layout, "0.2.1".parse().unwrap(), &w.install)
        .unwrap_err()
        .to_string();
    assert!(e.contains("does not name a release"), "{e}");
}

// ---- Windows: the junction switch, an update and its rollback on NTFS.

/// The creation time of the pointer itself, not of what it points at: the
/// same before and after a switch means the entry was retargeted in place.
#[cfg(windows)]
fn pointer_created(link: &Path) -> std::time::SystemTime {
    std::fs::symlink_metadata(link).unwrap().created().unwrap()
}

#[cfg(windows)]
#[test]
fn a_junction_is_switched_in_place_and_back_and_read_through() {
    let w = World::new();
    let versions = w.install.join("versions");
    for (name, body) in [("a", OLD_CLI), ("b", NEW_CLI)] {
        std::fs::create_dir_all(versions.join(name).join("bin")).unwrap();
        std::fs::write(versions.join(name).join("bin").join("tenzro.exe"), body).unwrap();
    }
    let current = w.install.join("current");
    install::junction::point(&current, &versions.join("a")).unwrap();
    let layout = Layout::detect(&w.install);
    assert!(matches!(layout, Layout::Versioned { .. }), "{layout:?}");
    assert_eq!(layout.current_release().as_deref(), Some("a"));
    assert_eq!(read(&current.join("bin").join("tenzro.exe")), OLD_CLI);
    let born = pointer_created(&current);

    install::junction::point(&current, &versions.join("b")).unwrap();
    assert_eq!(layout.current_release().as_deref(), Some("b"));
    assert_eq!(read(&current.join("bin").join("tenzro.exe")), NEW_CLI);
    assert_eq!(
        std::fs::read_link(&current)
            .unwrap()
            .canonicalize()
            .unwrap(),
        versions.join("b").canonicalize().unwrap()
    );
    install::junction::point(&current, &versions.join("a")).unwrap();
    assert_eq!(read(&current.join("bin").join("tenzro.exe")), OLD_CLI);
    assert_eq!(
        pointer_created(&current),
        born,
        "the junction was retargeted in place, never removed and made again"
    );
    // The release directories are untouched by the switches.
    assert_eq!(read(&versions.join("b/bin/tenzro.exe")), NEW_CLI);

    // A real directory is never turned into a pointer.
    std::fs::create_dir_all(w.install.join("real")).unwrap();
    assert!(install::junction::point(&w.install.join("real"), &versions.join("a")).is_err());
}

#[cfg(windows)]
#[tokio::test]
async fn a_versioned_update_on_windows_switches_current_keeps_previous_and_rolls_back() {
    let w = World::new();
    let layout = w.versioned();
    assert!(matches!(layout, Layout::Versioned { .. }), "{layout:?}");
    let current = w.install.join("current");
    let born = pointer_created(&current);
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro", NEW_CLI), ("tenzro-node", NEW_NODE_BROKEN)],
    );
    let a = apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(a.installed.previous_release.as_deref(), Some("0.2.1"));
    assert_eq!(layout.current_release().as_deref(), Some("0.2.2"));
    assert_eq!(pointer_created(&current), born);
    assert_eq!(read(&current.join("bin/tenzro.exe")), NEW_CLI);
    assert_eq!(read(&current.join("bin/tenzro-node.exe")), NEW_NODE_BROKEN);
    assert_eq!(read(&current.join("README")), b"untouched file");
    assert_eq!(read(&current.join("RELEASE")), b"0.2.2\n");
    assert_eq!(read(&w.install.join("previous/bin/tenzro.exe")), OLD_CLI);
    assert!(a.rollback_script.ends_with("rollback.cmd"));
    assert_eq!(
        health::load(&w.data).unwrap().unwrap().state,
        TrialState::Pending
    );

    install::rollback(&layout).unwrap();
    assert_eq!(layout.current_release().as_deref(), Some("0.2.1"));
    assert_eq!(read(&current.join("bin/tenzro.exe")), OLD_CLI);
    assert!(!w.install.join("previous").exists());
    assert!(install::rollback(&layout).is_err());
}

#[cfg(windows)]
#[tokio::test]
async fn on_windows_the_start_count_rolls_back_a_release_that_will_not_start_and_a_third_prunes_the_first()
 {
    let w = World::new();
    let layout = w.versioned();
    w.publish(
        4,
        "0.2.2",
        Class::C0,
        11,
        &[("tenzro-node", NEW_NODE_BROKEN)],
    );
    let policy = Policy {
        max_boot_attempts: 1,
        ..Policy::default()
    };
    apply_with(&w.ctx(), &layout, now_ms(), policy)
        .await
        .unwrap();
    assert_eq!(
        health::record_boot(&w.data, &layout, now_ms()).unwrap(),
        BootDecision::Proceed { attempt: 1 }
    );
    assert!(matches!(
        health::record_boot(&w.data, &layout, now_ms()).unwrap(),
        BootDecision::RolledBack(Reason::BootAttempts { .. })
    ));
    assert_eq!(layout.current_release().as_deref(), Some("0.2.1"));
    assert_eq!(
        read(&w.install.join("current/bin/tenzro-node.exe")),
        OLD_NODE
    );

    w.publish(5, "0.2.9", Class::C0, 12, &[("tenzro-node", BIG_NODE)]);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    w.publish(6, "0.2.4", Class::C0, 13, &[("tenzro-node", b"fourth")]);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    let mut kept: Vec<String> = std::fs::read_dir(w.install.join("versions"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    kept.sort();
    assert_eq!(
        kept,
        ["0.2.9", "0.2.4"],
        "only current and previous are kept"
    );
    assert_eq!(
        read(&w.install.join("previous/bin/tenzro-node.exe")),
        BIG_NODE
    );
}

#[cfg(unix)]
const CPU_NODE: &[u8] = b"the cpu node";
#[cfg(unix)]
const EDGE_NODE: &[u8] = b"the edge node";
/// A node that answers `hardware` the way a build that starts here does.
#[cfg(unix)]
const NODE_STARTS: &[u8] = b"#!/bin/sh\necho 'build: CPU'\necho 'startup: ok'\n";
/// A node whose own check refuses this machine.
#[cfg(unix)]
const NODE_REFUSES: &[u8] =
    b"#!/bin/sh\necho 'build: Vulkan'\necho 'startup: refused (no usable Vulkan GPU)'\nexit 1\n";

#[cfg(unix)]
impl World {
    /// A versioned install whose current release directory is `dir`, as an
    /// installer or an earlier update left it.
    fn versioned_in(&self, dir: &str) -> Layout {
        let release = self.install.join("versions").join(dir);
        std::fs::create_dir_all(release.join("bin")).unwrap();
        std::fs::write(release.join("bin/tenzro"), OLD_CLI).unwrap();
        std::fs::write(release.join("bin/tenzro-node"), OLD_NODE).unwrap();
        std::fs::write(release.join("RELEASE"), b"0.2.1\n").unwrap();
        std::os::unix::fs::symlink(format!("versions/{dir}"), self.install.join("current"))
            .unwrap();
        Layout::detect(&self.install)
    }

    /// Publishes release 0.2.2 with one `tenzro-node` per (platform, content).
    fn publish_nodes(&self, nodes: &[(&str, &[u8])]) {
        let entries: Vec<FileEntry> = nodes
            .iter()
            .map(|(platform, content)| {
                let dir = self.channel.join("files").join(platform);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("tenzro-node"), content).unwrap();
                FileEntry {
                    platform: (*platform).into(),
                    path: format!("files/{platform}/tenzro-node"),
                    ..file("tenzro-node", content)
                }
            })
            .collect();
        let t = targets(4, "0.2.2", entries);
        let tg = self.tk.sign_targets(&t);
        let ts = timestamp_for(&t, &tg, 11, now_ms() - HOUR, 24 * HOUR);
        std::fs::write(self.channel.join("targets.json"), &tg).unwrap();
        std::fs::write(
            self.channel.join("timestamp.json"),
            self.sk.sign_timestamp(&ts),
        )
        .unwrap();
    }

    /// A context for this machine's own platform with the real start check,
    /// so a staged node is run.
    fn native_ctx(&self) -> Ctx {
        Ctx {
            platform: this_platform(),
            start_check: start_verdict,
            ..self.ctx()
        }
    }
}

#[cfg(unix)]
#[test]
fn the_build_kind_comes_from_the_build_file_or_the_installers_directory_name() {
    for (dir, kind) in [
        ("tenzro-node-linux-x86_64-cuda-0123456789ab", Some("cuda")),
        (
            "tenzro-node-linux-aarch64-cuda-orin-0123456789ab",
            Some("cuda-orin"),
        ),
        (
            "tenzro-node-linux-aarch64-cpu-bookworm-0123456789ab",
            Some("cpu-bookworm"),
        ),
        (
            "tenzro-node-windows-x86_64-vulkan-0123456789ab",
            Some("vulkan"),
        ),
        (
            "tenzro-node-macos-aarch64-metal-0123456789ab",
            Some("metal"),
        ),
        ("tenzro-node-linux-x86_64-cpu-0123456789ab", Some("cpu")),
        // No digest, a short digest, an unknown system: not an installer's name.
        ("tenzro-node-linux-x86_64-cuda", None),
        ("tenzro-node-linux-x86_64-cuda-0123", None),
        ("tenzro-node-plan9-x86_64-cuda-0123456789ab", None),
        ("0.2.1", None),
    ] {
        let w = World::new();
        let layout = w.versioned_in(dir);
        assert_eq!(layout.build_kind().as_deref(), kind, "{dir}");
    }
    // The file `tenzro update` writes wins over the name, and a flat install has no kind.
    let w = World::new();
    let layout = w.versioned_in("0.2.1");
    std::fs::write(w.install.join("versions/0.2.1/BUILD"), b"vulkan\n").unwrap();
    assert_eq!(layout.build_kind().as_deref(), Some("vulkan"));
    std::fs::write(w.install.join("versions/0.2.1/BUILD"), b"../etc\n").unwrap();
    assert_eq!(layout.build_kind(), None);
    assert_eq!(World::new().flat().build_kind(), None);
}

#[test]
fn each_build_kind_has_its_own_manifest_platform() {
    assert_eq!(channel_platform("x86_64-linux", None), "x86_64-linux");
    assert_eq!(
        channel_platform("x86_64-linux", Some("cpu")),
        "x86_64-linux"
    );
    assert_eq!(
        channel_platform("x86_64-linux", Some("cuda")),
        "x86_64-linux-cuda"
    );
    assert_eq!(
        channel_platform("aarch64-linux", Some("cpu-bookworm")),
        "aarch64-linux-cpu-bookworm"
    );
    assert_eq!(
        channel_platform("x86_64-windows", Some("vulkan")),
        "x86_64-windows-vulkan"
    );
    assert_eq!(
        channel_platform("aarch64-macos", Some("metal")),
        "aarch64-macos"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn an_update_keeps_the_installed_build_kind() {
    let w = World::new();
    let layout = w.versioned_in("tenzro-node-linux-x86_64-edge-0123456789ab");
    w.publish_nodes(&[("x86_64-linux", CPU_NODE), ("x86_64-linux-edge", EDGE_NODE)]);
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert_eq!(read(&w.install.join("current/bin/tenzro-node")), EDGE_NODE);
    assert_eq!(read(&w.install.join("current/BUILD")), b"edge\n");
    // The next update reads the kind from the file: the directory is now named by release.
    assert_eq!(current_release(&w), "0.2.2");
    assert_eq!(layout.build_kind().as_deref(), Some("edge"));
}

#[cfg(unix)]
#[tokio::test]
async fn an_update_without_the_installed_build_kind_changes_nothing() {
    let w = World::new();
    let layout = w.versioned_in("tenzro-node-linux-x86_64-cuda-0123456789ab");
    w.publish_nodes(&[("x86_64-linux", CPU_NODE)]);
    let err = apply(&w.ctx(), &layout, now_ms()).await.unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains("no cuda build for x86_64-linux") && text.contains("Nothing was changed"),
        "{text}"
    );
    assert_eq!(read(&w.install.join("current/bin/tenzro-node")), OLD_NODE);
    assert_eq!(
        current_release(&w),
        "tenzro-node-linux-x86_64-cuda-0123456789ab"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_platform_named_on_the_command_line_installs_the_kind_it_names_and_never_another() {
    // On an install with no recorded kind it is used as it is, and its kind is recorded.
    let w = World::new();
    let layout = w.versioned_in("0.2.1");
    w.publish_nodes(&[("x86_64-linux", CPU_NODE)]);
    let given = |w: &World, platform: &str| Ctx {
        platform: platform.into(),
        platform_given: true,
        ..w.ctx()
    };
    apply(&given(&w, "x86_64-linux"), &layout, now_ms())
        .await
        .unwrap();
    assert_eq!(read(&w.install.join("current/bin/tenzro-node")), CPU_NODE);
    assert_eq!(read(&w.install.join("current/BUILD")), b"cpu\n");

    // A CUDA install takes a platform naming CUDA, and records it.
    let w = World::new();
    let layout = w.versioned_in("tenzro-node-linux-x86_64-cuda-0123456789ab");
    w.publish_nodes(&[("x86_64-linux", CPU_NODE), ("x86_64-linux-cuda", EDGE_NODE)]);
    apply(&given(&w, "x86_64-linux-cuda"), &layout, now_ms())
        .await
        .unwrap();
    assert_eq!(read(&w.install.join("current/BUILD")), b"cuda\n");

    // It refuses a platform naming another kind, with nothing changed.
    let w = World::new();
    let layout = w.versioned_in("tenzro-node-linux-x86_64-cuda-0123456789ab");
    w.publish_nodes(&[("x86_64-linux", CPU_NODE)]);
    let err = apply(&given(&w, "x86_64-linux"), &layout, now_ms())
        .await
        .unwrap_err();
    let text = format!("{err:#}");
    assert!(
        text.contains(
            "this install is the cuda build and --platform x86_64-linux names the cpu build"
        ) && text.contains("Nothing was changed"),
        "{text}"
    );
    assert_eq!(read(&w.install.join("current/bin/tenzro-node")), OLD_NODE);
    assert_eq!(
        current_release(&w),
        "tenzro-node-linux-x86_64-cuda-0123456789ab"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_new_node_that_refuses_this_machine_leaves_the_installed_release_current() {
    for (dir, kind_suffix, hint) in [
        (
            "tenzro-node-linux-x86_64-vulkan-0123456789ab",
            "-vulkan",
            Some("keeps the vulkan build"),
        ),
        ("tenzro-node-linux-x86_64-cpu-0123456789ab", "", None),
    ] {
        let w = World::new();
        let layout = w.versioned_in(dir);
        let ctx = w.native_ctx();
        let cpu = ctx.platform.clone();
        let own = format!("{}{kind_suffix}", ctx.platform);
        // The CPU build of the release would start here; it is not taken in place of a refused GPU build.
        let mut nodes = vec![(own.as_str(), NODE_REFUSES)];
        if own != cpu {
            nodes.push((cpu.as_str(), NODE_STARTS));
        }
        w.publish_nodes(&nodes);
        let err = apply(&ctx, &layout, now_ms()).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("does not start on this machine (no usable Vulkan GPU)")
                && text.contains("The installed release stays current and nothing was changed"),
            "{text}"
        );
        match hint {
            Some(hint) => assert!(
                text.contains(hint) && text.contains("--target tenzro-node-"),
                "{text}"
            ),
            None => assert!(!text.contains("--target"), "{text}"),
        }
        assert_eq!(read(&w.install.join("current/bin/tenzro-node")), OLD_NODE);
        assert_eq!(current_release(&w), dir);
        // Nothing of the refused release is left beside the installed one, and no trial is open.
        let left: Vec<String> = std::fs::read_dir(w.install.join("versions"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, [dir]);
        assert!(!w.install.join("previous").exists());
        assert!(health::load(&w.data).unwrap().is_none());
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_new_node_that_starts_here_is_installed() {
    let w = World::new();
    let layout = w.versioned_in("tenzro-node-linux-x86_64-vulkan-0123456789ab");
    let ctx = w.native_ctx();
    let gpu = format!("{}-vulkan", ctx.platform);
    w.publish_nodes(&[
        (ctx.platform.as_str(), CPU_NODE),
        (gpu.as_str(), NODE_STARTS),
    ]);
    apply(&ctx, &layout, now_ms()).await.unwrap();
    assert_eq!(
        read(&w.install.join("current/bin/tenzro-node")),
        NODE_STARTS
    );
    assert_eq!(read(&w.install.join("current/BUILD")), b"vulkan\n");
}

#[cfg(unix)]
#[tokio::test]
async fn a_node_for_another_platform_is_not_run() {
    let w = World::new();
    let layout = w.versioned_in("tenzro-node-linux-x86_64-vulkan-0123456789ab");
    let ctx = Ctx {
        platform: "riscv64-plan9".into(),
        ..w.ctx()
    };
    w.publish_nodes(&[("riscv64-plan9-vulkan", NODE_REFUSES)]);
    apply(&ctx, &layout, now_ms()).await.unwrap();
    assert_eq!(
        read(&w.install.join("current/bin/tenzro-node")),
        NODE_REFUSES
    );
}

/// The start check's verdict on a stand-in node that answers `hardware` with `script`.
#[cfg(unix)]
fn verdict_of(script: &[u8], timeout_secs: u64) -> std::result::Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let node = dir.path().join("tenzro-node");
    std::fs::write(&node, script).unwrap();
    std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
    start_verdict_within(&node, std::time::Duration::from_secs(timeout_secs))
}

#[cfg(unix)]
#[test]
fn only_an_explicit_startup_ok_lets_a_new_node_be_made_current() {
    assert_eq!(verdict_of(NODE_STARTS, 30), Ok(()));
    assert_eq!(
        verdict_of(NODE_REFUSES, 30),
        Err("no usable Vulkan GPU".to_string())
    );
    let no = |script: &[u8], timeout: u64| verdict_of(script, timeout).unwrap_err();
    assert!(
        no(b"#!/bin/sh\necho 'startup: ok'\nexit 2\n", 30).contains("exited with 2"),
        "a yes with a failing exit is a no"
    );
    assert!(no(b"#!/bin/sh\nexit 3\n", 30).contains("exited with 3"));
    assert!(no(b"#!/bin/sh\necho 'build: CPU'\n", 30).contains("no startup verdict"));
    assert!(no(b"#!/bin/sh\necho 'startup: okay'\n", 30).contains("no startup verdict"));
    assert!(
        no(b"#!/bin/sh\nkill -SEGV $$\n", 30).contains("killed"),
        "a crash"
    );
    assert!(
        no(b"#!/nonexistent/interpreter\n", 30).contains("cannot be run"),
        "a missing loader or library"
    );
    assert!(
        no(b"\x7fELF\x02\x01\x01 not a program for this machine", 30).contains("cannot be run")
    );
    assert!(
        no(b"#!/bin/sh\nexec tail -f /dev/null\n", 1).contains("no answer within 1 s"),
        "a hang"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_new_node_that_cannot_answer_leaves_the_installed_release_current() {
    for (node, why) in [
        (&b"#!/bin/sh\nexit 1\n"[..], "exited with 1"),
        (
            &b"#!/bin/sh\necho 'build: Vulkan'\n"[..],
            "no startup verdict",
        ),
        (&b"not a program"[..], "cannot be run"),
    ] {
        let w = World::new();
        let dir = "tenzro-node-linux-x86_64-vulkan-0123456789ab";
        let layout = w.versioned_in(dir);
        let ctx = w.native_ctx();
        let gpu = format!("{}-vulkan", ctx.platform);
        w.publish_nodes(&[(gpu.as_str(), node)]);
        let err = apply(&ctx, &layout, now_ms()).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("does not start on this machine") && text.contains(why),
            "{why}: {text}"
        );
        assert_eq!(current_release(&w), dir, "{why}");
        assert_eq!(
            read(&w.install.join("current/bin/tenzro-node")),
            OLD_NODE,
            "{why}"
        );
        assert!(health::load(&w.data).unwrap().is_none(), "{why}");
    }
}

#[cfg(unix)]
#[test]
fn a_binary_changed_between_the_check_and_the_switch_is_not_made_current() {
    let w = World::new();
    let layout = w.versioned();
    let staged = w.data.join("staged-node");
    std::fs::write(&staged, b"the verified node").unwrap();
    let err = install::install(
        &layout,
        "0.2.2",
        &[("tenzro-node".into(), staged)],
        None,
        None,
        &|node| {
            std::fs::write(node, b"another node").unwrap();
            Ok(())
        },
    )
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("is not the verified one"),
        "{err:#}"
    );
    assert_eq!(current_release(&w), "0.2.1");
    let left: Vec<_> = std::fs::read_dir(w.install.join("versions"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["0.2.1"]);
}

#[cfg(unix)]
impl World {
    /// Publishes the libraries document of release 0.2.2, manifest 4, signed by the targets key.
    fn publish_libraries(&self, files: &[(&str, &str, &[u8])], links: &[(&str, &str, &str)]) {
        let entries: Vec<FileEntry> = files
            .iter()
            .map(|(platform, name, content)| {
                let path = format!("files/{platform}/{name}");
                let at = self.channel.join(&path);
                std::fs::create_dir_all(at.parent().unwrap()).unwrap();
                std::fs::write(&at, content).unwrap();
                FileEntry {
                    platform: (*platform).into(),
                    name: (*name).into(),
                    path,
                    ..file("tenzro", content)
                }
            })
            .collect();
        let l = super::manifest::Libraries {
            kind: "libraries".into(),
            spec: super::manifest::SPEC.into(),
            version: 4,
            release: "0.2.2".into(),
            // The digest of the payload of the targets document published beside it.
            targets_sha256: {
                let env: serde_json::Value =
                    serde_json::from_slice(&read(&self.channel.join("targets.json"))).unwrap();
                let payload = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    env["payload"].as_str().unwrap(),
                )
                .unwrap();
                sha(&payload)
            },
            files: entries,
            links: links
                .iter()
                .map(|(platform, name, target)| super::manifest::LibraryLink {
                    platform: (*platform).into(),
                    name: (*name).into(),
                    target: (*target).into(),
                })
                .collect(),
        };
        std::fs::write(
            self.channel.join("libraries.json"),
            self.tk.sign_libraries(&l),
        )
        .unwrap();
    }

    /// A CUDA install at 0.2.1 whose release keeps an ONNX Runtime in `lib/`.
    fn cuda_install(&self) -> Layout {
        let dir = "tenzro-node-linux-x86_64-cuda-0123456789ab";
        let layout = self.versioned_in(dir);
        let lib = self.install.join("versions").join(dir).join("lib");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(lib.join("libonnxruntime.so.1.20.0"), b"old ort").unwrap();
        std::fs::write(lib.join("libold-only.so"), b"old only").unwrap();
        std::os::unix::fs::symlink("libonnxruntime.so.1.20.0", lib.join("libonnxruntime.so.1"))
            .unwrap();
        layout
    }
}

#[cfg(unix)]
fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[cfg(unix)]
const CUDA_DIR: &str = "tenzro-node-linux-x86_64-cuda-0123456789ab";

#[cfg(unix)]
#[tokio::test]
async fn an_install_with_libraries_takes_the_new_releases_libraries() {
    let w = World::new();
    let layout = w.cuda_install();
    w.publish_nodes(&[("x86_64-linux-cuda", NODE_STARTS)]);
    w.publish_libraries(
        &[
            (
                "x86_64-linux-cuda",
                "lib/libonnxruntime.so.1.22.0",
                b"new ort",
            ),
            (
                "x86_64-linux-cuda",
                "lib/libonnxruntime_providers_cuda.so",
                b"cuda provider",
            ),
            ("x86_64-linux-vulkan", "lib/libother.so", b"another kind"),
        ],
        &[(
            "x86_64-linux-cuda",
            "lib/libonnxruntime.so.1",
            "lib/libonnxruntime.so.1.22.0",
        )],
    );
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    let lib = w.install.join("current/lib");
    assert_eq!(
        names_in(&lib),
        [
            "libonnxruntime.so.1",
            "libonnxruntime.so.1.22.0",
            "libonnxruntime_providers_cuda.so"
        ]
    );
    assert_eq!(read(&lib.join("libonnxruntime.so.1.22.0")), b"new ort");
    assert_eq!(
        std::fs::read_link(lib.join("libonnxruntime.so.1")).unwrap(),
        Path::new("libonnxruntime.so.1.22.0")
    );
    assert_eq!(read(&lib.join("libonnxruntime.so.1")), b"new ort");
    // The old release, kept as the previous one, still has its own libraries.
    assert_eq!(
        read(&w.install.join("previous/lib/libold-only.so")),
        b"old only"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn libraries_beside_the_binaries_in_bin_are_replaced_too() {
    let w = World::new();
    let layout = w.versioned_in(CUDA_DIR);
    let bin = w.install.join("versions").join(CUDA_DIR).join("bin");
    std::fs::write(bin.join("onnxruntime.dll"), b"old dll").unwrap();
    std::fs::write(bin.join("DirectML.dll"), b"old directml").unwrap();
    w.publish_nodes(&[("x86_64-linux-cuda", NODE_STARTS)]);
    w.publish_libraries(
        &[("x86_64-linux-cuda", "bin/onnxruntime.dll", b"new dll")],
        &[],
    );
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    let bin = w.install.join("current/bin");
    assert_eq!(names_in(&bin), ["onnxruntime.dll", "tenzro", "tenzro-node"]);
    assert_eq!(read(&bin.join("onnxruntime.dll")), b"new dll");
    assert_eq!(read(&bin.join("tenzro")), OLD_CLI);
}

#[cfg(unix)]
#[tokio::test]
async fn an_install_with_libraries_is_unchanged_without_good_libraries() {
    let cases: [(&str, fn(&World)); 5] = [
        ("no libraries document", |_| {}),
        ("another release", |w| {
            w.publish_libraries(
                &[(
                    "x86_64-linux-cuda",
                    "lib/libonnxruntime.so.1.22.0",
                    b"new ort",
                )],
                &[],
            );
            let env: serde_json::Value =
                serde_json::from_slice(&read(&w.channel.join("libraries.json"))).unwrap();
            // Re-signed for release 0.2.9: a valid document of another release.
            let mut l: super::manifest::Libraries = serde_json::from_slice(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    env["payload"].as_str().unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            l.release = "0.2.9".into();
            std::fs::write(w.channel.join("libraries.json"), w.tk.sign_libraries(&l)).unwrap();
        }),
        ("signed by the timestamp key", |w| {
            w.publish_libraries(
                &[(
                    "x86_64-linux-cuda",
                    "lib/libonnxruntime.so.1.22.0",
                    b"new ort",
                )],
                &[],
            );
            let env: serde_json::Value =
                serde_json::from_slice(&read(&w.channel.join("libraries.json"))).unwrap();
            let l: super::manifest::Libraries = serde_json::from_slice(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    env["payload"].as_str().unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            std::fs::write(w.channel.join("libraries.json"), w.sk.sign_libraries(&l)).unwrap();
        }),
        ("no libraries for this kind", |w| {
            w.publish_libraries(&[("x86_64-linux-vulkan", "lib/libother.so", b"x")], &[]);
        }),
        ("a library that is not the signed one", |w| {
            w.publish_libraries(
                &[(
                    "x86_64-linux-cuda",
                    "lib/libonnxruntime.so.1.22.0",
                    b"new ort",
                )],
                &[],
            );
            std::fs::write(
                w.channel
                    .join("files/x86_64-linux-cuda/lib/libonnxruntime.so.1.22.0"),
                // As long as the signed file, so the length check passes and the digest is what refuses it.
                b"bad ort",
            )
            .unwrap();
        }),
    ];
    for (case, prepare) in cases {
        let w = World::new();
        let layout = w.cuda_install();
        w.publish_nodes(&[("x86_64-linux-cuda", NODE_STARTS)]);
        prepare(&w);
        let err = apply(&w.ctx(), &layout, now_ms()).await.unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("nothing was changed") || text.contains("the signed manifest says"),
            "{case}: {text}"
        );
        assert_eq!(current_release(&w), CUDA_DIR, "{case}");
        assert_eq!(names_in(&w.install.join("versions")), [CUDA_DIR], "{case}");
        assert_eq!(
            read(&w.install.join("current/lib/libonnxruntime.so.1.20.0")),
            b"old ort",
            "{case}"
        );
        assert!(health::load(&w.data).unwrap().is_none(), "{case}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn an_install_without_libraries_never_reads_the_libraries_document() {
    let w = World::new();
    let layout = w.versioned_in("tenzro-node-linux-x86_64-cpu-0123456789ab");
    w.publish_nodes(&[("x86_64-linux", NODE_STARTS)]);
    std::fs::write(w.channel.join("libraries.json"), b"not a document").unwrap();
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    assert!(!w.install.join("current/lib").exists());
    assert_eq!(
        read(&w.install.join("current/bin/tenzro-node")),
        NODE_STARTS
    );
}

#[cfg(unix)]
#[tokio::test]
async fn an_update_replaces_the_console_whole() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new();
    let dir = "tenzro-node-linux-x86_64-cpu-0123456789ab";
    let layout = w.versioned_in(dir);
    let console = w.install.join("versions").join(dir).join("share/console");
    std::fs::create_dir_all(console.join("src")).unwrap();
    std::fs::write(console.join("index.html"), b"old page").unwrap();
    std::fs::write(console.join("old-only.css"), b"from the old console").unwrap();
    std::fs::write(console.join("src/old.js"), b"from the old console").unwrap();
    w.publish_nodes(&[("x86_64-linux", NODE_STARTS)]);
    w.publish_libraries(
        &[
            ("x86_64-linux", "share/console/index.html", b"new page"),
            ("x86_64-linux", "share/console/sw.js", b"worker"),
            ("x86_64-linux", "share/console/src/app.js", b"app"),
        ],
        &[],
    );
    apply(&w.ctx(), &layout, now_ms()).await.unwrap();
    let c = w.install.join("current/share/console");
    // Exactly the new release's files: nothing of the old console is left.
    assert_eq!(names_in(&c), ["index.html", "src", "sw.js"]);
    assert_eq!(names_in(&c.join("src")), ["app.js"]);
    assert_eq!(read(&c.join("index.html")), b"new page");
    assert_eq!(read(&c.join("src/app.js")), b"app");
    let mode = std::fs::metadata(c.join("index.html"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0, "a page is not made executable");
    // The previous release keeps its own console.
    assert_eq!(
        read(&w.install.join("previous/share/console/index.html")),
        b"old page"
    );
}
