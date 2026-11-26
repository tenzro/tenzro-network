//! The installers and `tenzro update` on one install directory, end to end.
//!
//! Releases are stand-ins: small programs, compiled here with `rustc`, that
//! answer `--version` and `hardware` the way `tenzro` and `tenzro-node` do and
//! otherwise run like a node (they record each start and stay up, or exit at
//! once when told to fail). The release folder is signed with a test release
//! key, and the installer scripts are run as published except for the key
//! they trust. No network and no TPM is used.
//!
//! - Every platform: `install.sh` (Unix) or `install.ps1` (Windows) installs
//!   three releases into a temporary prefix and switches `current` and
//!   `previous` the way `tenzro update` does, keeping exactly those two.
//! - Linux: release 1 is installed by `install.sh`, the node runs under a
//!   systemd user unit started with `systemd-run --user` whose start count is
//!   `<root>/current/bin/tenzro update boot-check` and whose program is
//!   `<root>/current/bin/tenzro-node`; `tenzro update` installs release 2 from
//!   a local signed channel, release 2 fails to start and the start count
//!   rolls it back to release 1, a downgrade is refused, and release 2
//!   published again passes the health check.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine as _;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::{Digest, Sha256};
use tenzro_cli::commands::update::install::{self, Layout};

const FAKE_SOURCE: &str = r#"
fn main() {
    let version = "@VERSION@";
    match std::env::args().nth(1).as_deref() {
        Some("--version") => println!("tenzro {version}"),
        Some("hardware") => println!("build: cpu\ngpus: 0\nstartup: ok"),
        _ => {
            if let Some(dir) = std::env::var_os("FAKE_NODE_DIR") {
                use std::io::Write;
                let dir = std::path::PathBuf::from(dir);
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.join("starts"))
                {
                    let _ = writeln!(f, "{version}");
                }
                if dir.join(format!("fail-{version}")).exists() {
                    std::process::exit(1);
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}
"#;

/// The release key fingerprint embedded in both installer scripts.
const PUBLISHED_KEY_FPR: &str = "c88aaee70b3c0bf17a994bad44963a6a72359b2e1497df9a15a40ed099aeb72d";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().unwrap_or_else(|e| panic!("run {cmd:?}: {e}"))
}

fn text(out: &Output) -> String {
    format!(
        "status {}\n--- stdout\n{}\n--- stderr\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Compiles the stand-in for release `version` into `dir`.
fn fake_binary(dir: &Path, version: &str) -> PathBuf {
    let src = dir.join(format!("fake-{version}.rs"));
    std::fs::write(&src, FAKE_SOURCE.replace("@VERSION@", version)).unwrap();
    let out = dir.join(format!("fake-{version}{}", std::env::consts::EXE_SUFFIX));
    let built = run(Command::new("rustc")
        .args(["--edition=2021", "--crate-name=fake", "-Cdebuginfo=0", "-o"])
        .arg(&out)
        .arg(&src));
    assert!(
        built.status.success(),
        "compile the stand-in: {}",
        text(&built)
    );
    out
}

/// A P-256 key standing in for the release key, for both the installer's
/// signed SHA256SUMS and the update channel's signed documents.
struct TestKey(SigningKey);

impl TestKey {
    fn new(seed: u8) -> Self {
        let mut scalar = [0u8; 32];
        scalar[0] = 0x31;
        scalar[31] = seed;
        TestKey(SigningKey::from_slice(&scalar).unwrap())
    }

    /// The uncompressed SEC1 point; only the Linux end-to-end channel uses it.
    #[cfg(target_os = "linux")]
    fn sec1(&self) -> Vec<u8> {
        self.0
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// The SubjectPublicKeyInfo, with the uncompressed point `install.ps1`
    /// reads from its last 64 bytes.
    fn spki_der(&self) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey;
        let der = p256::PublicKey::from(*self.0.verifying_key())
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        assert_eq!(der.len(), 91);
        der
    }

    fn spki_pem(&self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(self.spki_der());
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            lines.join("\n")
        )
    }

    fn sign(&self, message: &[u8]) -> p256::ecdsa::Signature {
        let digest: [u8; 32] = Sha256::digest(message).into();
        self.0.sign_prehash(&digest).unwrap()
    }
}

/// `script` (an installer) trusting `key` instead of the published release key.
fn rekeyed_script(script: &str, key: &TestKey) -> String {
    let begin = script.find("-----BEGIN PUBLIC KEY-----").unwrap();
    let end_marker = "-----END PUBLIC KEY-----";
    let end = script[begin..].find(end_marker).unwrap() + begin + end_marker.len();
    let out = format!("{}{}{}", &script[..begin], key.spki_pem(), &script[end..]);
    assert_eq!(out.matches(PUBLISHED_KEY_FPR).count(), 1);
    out.replace(PUBLISHED_KEY_FPR, &sha256_hex(&key.spki_der()))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The archive name the installer is pointed at with `--target`.
fn archive_name() -> String {
    let os = match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    };
    format!("tenzro-node-{os}-{}-cpu", std::env::consts::ARCH)
}

/// A release folder for `--from`/`-From`: the archive of `fake` (as both
/// `tenzro` and `tenzro-node`), SHA256SUMS and its signature. Returns the
/// folder and the release directory name the installer gives it.
fn release_folder(work: &Path, key: &TestKey, fake: &Path, label: &str) -> (PathBuf, String) {
    let name = archive_name();
    let stage = work.join(format!("stage-{label}"));
    let bin = stage.join(&name).join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for b in ["tenzro", "tenzro-node"] {
        std::fs::copy(fake, bin.join(install::file_name(b))).unwrap();
    }
    std::fs::write(stage.join(&name).join("NOTES"), label).unwrap();
    let folder = work.join(format!("release-{label}"));
    std::fs::create_dir_all(&folder).unwrap();
    let archive = if cfg!(windows) {
        let zip = folder.join(format!("{name}.zip"));
        let made = run(Command::new("powershell").args([
            "-NoProfile",
            "-Command",
            &format!(
                "Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::CreateFromDirectory('{}', '{}', [IO.Compression.CompressionLevel]::Optimal, $true)",
                stage.join(&name).display(),
                zip.display()
            ),
        ]));
        assert!(made.status.success(), "zip: {}", text(&made));
        zip
    } else {
        let tgz = folder.join(format!("{name}.tar.gz"));
        let made = run(Command::new("tar")
            .arg("-czf")
            .arg(&tgz)
            .arg("-C")
            .arg(&stage)
            .arg(&name));
        assert!(made.status.success(), "tar: {}", text(&made));
        tgz
    };
    let bytes = std::fs::read(&archive).unwrap();
    let digest = sha256_hex(&bytes);
    let sums = format!(
        "{digest}  {}\n",
        archive.file_name().unwrap().to_str().unwrap()
    );
    std::fs::write(folder.join("SHA256SUMS"), &sums).unwrap();
    let sig = key.sign(sums.as_bytes());
    std::fs::write(
        folder.join("SHA256SUMS.sig"),
        base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()),
    )
    .unwrap();
    (folder, format!("{name}-{}", &digest[..12]))
}

/// The installer for this platform, re-keyed, ready to run.
struct Installer {
    script: PathBuf,
    prefix: PathBuf,
    home: PathBuf,
}

impl Installer {
    fn new(work: &Path, key: &TestKey) -> Installer {
        let (src, file) = if cfg!(windows) {
            ("scripts/install/install.ps1", "install.ps1")
        } else {
            ("scripts/install/install.sh", "install.sh")
        };
        let script = work.join(file);
        let published = std::fs::read_to_string(repo_root().join(src)).unwrap();
        std::fs::write(&script, rekeyed_script(&published, key)).unwrap();
        let home = work.join("home");
        std::fs::create_dir_all(&home).unwrap();
        Installer {
            script,
            prefix: work.join("prefix"),
            home,
        }
    }

    fn root(&self) -> PathBuf {
        self.prefix.join("install")
    }

    /// Runs the installer from `folder`; panics unless it reports success.
    fn install(&self, folder: &Path) -> String {
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("powershell");
            c.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(&self.script)
                .arg("-From")
                .arg(folder)
                .arg("-Prefix")
                .arg(&self.prefix)
                .args(["-Target", &archive_name(), "-NoModifyPath"]);
            c
        } else {
            let mut c = Command::new("sh");
            c.arg(&self.script)
                .arg("--from")
                .arg(folder)
                .arg("--prefix")
                .arg(&self.prefix)
                .arg("--bin-dir")
                .arg(self.home.join("bin"))
                .args(["--target", &archive_name(), "--no-modify-path"]);
            c
        };
        let out = run(cmd
            .env("HOME", &self.home)
            .env("TERM", "dumb")
            .env("NO_COLOR", "1")
            .env_remove("TENZRO_HOME")
            .env_remove("TENZRO_BIN_DIR")
            .env_remove("TENZRO_DOWNLOAD_BASE"));
        let says = text(&out);
        assert!(
            out.status.success() && says.contains("is installed") && !says.contains("error:"),
            "the installer failed: {says}"
        );
        says
    }
}

/// The release directory a pointer (`current`, `previous`) names.
fn pointer(root: &Path, name: &str) -> Option<String> {
    std::fs::read_link(root.join(name))
        .ok()
        .and_then(|t| t.file_name().map(|n| n.to_string_lossy().into_owned()))
}

fn releases_on_disk(root: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(root.join("versions"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    v.sort();
    v
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

#[test]
fn the_installer_switches_current_and_previous_like_tenzro_update_and_keeps_exactly_those_two() {
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path();
    let key = TestKey::new(7);
    let installer = Installer::new(work, &key);
    let root = installer.root();
    let mut names = Vec::new();
    let mut folders = Vec::new();
    let mut fakes = Vec::new();
    for v in ["1.0.0", "1.1.0", "1.2.0"] {
        let fake = fake_binary(work, v);
        let (folder, name) = release_folder(work, &key, &fake, v);
        folders.push(folder);
        names.push(name);
        fakes.push(fake);
    }

    installer.install(&folders[0]);
    assert_eq!(
        pointer(&root, "current").as_deref(),
        Some(names[0].as_str())
    );
    assert_eq!(pointer(&root, "previous"), None);
    assert_eq!(
        std::fs::read_to_string(root.join("current").join("RELEASE")).unwrap(),
        "1.0.0\n"
    );
    #[cfg(windows)]
    let born = std::fs::symlink_metadata(root.join("current"))
        .unwrap()
        .created()
        .unwrap();

    installer.install(&folders[1]);
    assert_eq!(
        pointer(&root, "current").as_deref(),
        Some(names[1].as_str())
    );
    assert_eq!(
        pointer(&root, "previous").as_deref(),
        Some(names[0].as_str())
    );

    // A directory dated later than both, as a release `tenzro update` built
    // and was rolled back from leaves behind. Pruning by date would keep it
    // and delete the release that becomes `previous`.
    // Its date is set an hour ahead, so it is the newest whatever the file
    // system's time granularity.
    let stale = root.join("versions").join("0.9.9");
    std::fs::create_dir_all(stale.join("bin")).unwrap();
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    filetime::set_file_mtime(&stale, filetime::FileTime::from_system_time(later)).unwrap();
    installer.install(&folders[2]);
    assert_eq!(
        pointer(&root, "current").as_deref(),
        Some(names[2].as_str())
    );
    assert_eq!(
        pointer(&root, "previous").as_deref(),
        Some(names[1].as_str())
    );
    assert_eq!(
        releases_on_disk(&root),
        sorted(vec![names[1].clone(), names[2].clone()])
    );
    assert!(!root.join("current.update-tmp").exists());
    assert!(!root.join("previous.update-tmp").exists());
    #[cfg(windows)]
    assert_eq!(
        std::fs::symlink_metadata(root.join("current"))
            .unwrap()
            .created()
            .unwrap(),
        born,
        "the current junction was retargeted in place, never removed and made again"
    );

    // Run again with the release already current: nothing moves.
    installer.install(&folders[2]);
    assert_eq!(
        pointer(&root, "current").as_deref(),
        Some(names[2].as_str())
    );
    assert_eq!(
        pointer(&root, "previous").as_deref(),
        Some(names[1].as_str())
    );

    // Back to the previous release: the two swap, both are kept.
    installer.install(&folders[1]);
    assert_eq!(
        pointer(&root, "current").as_deref(),
        Some(names[1].as_str())
    );
    assert_eq!(
        pointer(&root, "previous").as_deref(),
        Some(names[2].as_str())
    );
    assert_eq!(
        releases_on_disk(&root),
        sorted(vec![names[1].clone(), names[2].clone()])
    );

    // `tenzro update` reads this install as the installer left it.
    let layout = Layout::detect(&root);
    assert!(matches!(layout, Layout::Versioned { .. }), "{layout:?}");
    assert_eq!(
        install::installed_release(&layout, "0.0.1".parse().unwrap(), Path::new("/nonexistent"))
            .unwrap(),
        "1.1.0".parse().unwrap()
    );
    assert_eq!(
        std::fs::read(
            root.join("current")
                .join("bin")
                .join(install::file_name("tenzro-node"))
        )
        .unwrap(),
        std::fs::read(&fakes[1]).unwrap()
    );
}

#[cfg(target_os = "linux")]
mod linux_end_to_end {
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    use super::*;

    const TARGETS_DOMAIN: &[u8] = b"tenzro-update/1\ntargets\n";
    const TIMESTAMP_DOMAIN: &[u8] = b"tenzro-update/1\ntimestamp\n";

    fn platform() -> String {
        format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    }

    fn envelope(key: &TestKey, domain: &[u8], payload: &serde_json::Value) -> Vec<u8> {
        let payload = serde_json::to_vec(payload).unwrap();
        let mut message = domain.to_vec();
        message.extend_from_slice(&payload);
        let sig = key.sign(&message);
        serde_json::to_vec(&serde_json::json!({
            "payload": base64::engine::general_purpose::STANDARD.encode(&payload),
            "signatures": [{
                "keyid": sha256_hex(&key.sec1()),
                "sig": hex::encode(sig.to_bytes()),
            }],
        }))
        .unwrap()
    }

    /// A local update channel signed with test keys.
    struct Channel {
        dir: PathBuf,
        targets_key: TestKey,
        timestamp_key: TestKey,
    }

    impl Channel {
        fn new(work: &Path) -> Channel {
            let dir = work.join("channel");
            std::fs::create_dir_all(dir.join("files")).unwrap();
            Channel {
                dir,
                targets_key: TestKey::new(11),
                timestamp_key: TestKey::new(12),
            }
        }

        fn trusted_keys(&self, work: &Path) -> PathBuf {
            let path = work.join("trusted-keys.json");
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "targets": [hex::encode(self.targets_key.sec1())],
                    "timestamp": [hex::encode(self.timestamp_key.sec1())],
                }))
                .unwrap(),
            )
            .unwrap();
            path
        }

        /// Publishes `node` as `tenzro-node` of release `release`, manifest `number`.
        fn publish(&self, number: u64, release: &str, node: &Path) {
            let bytes = std::fs::read(node).unwrap();
            let path = format!("files/{release}-{number}/tenzro-node");
            std::fs::create_dir_all(self.dir.join(&path).parent().unwrap()).unwrap();
            std::fs::write(self.dir.join(&path), &bytes).unwrap();
            let targets = envelope(
                &self.targets_key,
                TARGETS_DOMAIN,
                &serde_json::json!({
                    "_type": "targets",
                    "spec": "tenzro-update/1",
                    "version": number,
                    "release": release,
                    "class": "C0",
                    "description": "test release",
                    "files": [{
                        "platform": platform(),
                        "name": "tenzro-node",
                        "path": path,
                        "length": bytes.len(),
                        "sha256": sha256_hex(&bytes),
                    }],
                }),
            );
            let now = chrono::Utc::now().timestamp_millis() as u64;
            let timestamp = envelope(
                &self.timestamp_key,
                TIMESTAMP_DOMAIN,
                &serde_json::json!({
                    "_type": "timestamp",
                    "spec": "tenzro-update/1",
                    "version": number + 100,
                    "issued_ms": now - 3_600_000,
                    "expires_ms": now + 23 * 3_600_000,
                    "targets_version": number,
                    "targets_length": targets.len(),
                    "targets_sha256": sha256_hex(&targets),
                }),
            );
            std::fs::write(self.dir.join("targets.json"), targets).unwrap();
            std::fs::write(self.dir.join("timestamp.json"), timestamp).unwrap();
        }
    }

    /// The node under a systemd user unit, as the unit `tenzro setup` writes
    /// runs it: the start count first, then the program through `current`.
    struct Unit {
        name: String,
    }

    impl Unit {
        fn start(root: &Path, data: &Path, node_dir: &Path, home: &Path) -> Unit {
            let manager = run(Command::new("timeout").args([
                "30",
                "systemctl",
                "--user",
                "show-environment",
            ]));
            assert!(
                manager.status.success(),
                "this test needs a systemd user manager (systemctl --user): {}",
                text(&manager)
            );
            let name = format!("tenzro-update-e2e-{}", std::process::id());
            let tenzro = root.join("current/bin/tenzro");
            let started = run(Command::new("timeout")
                .args(["60", "systemd-run", "--user", "--collect", "--quiet"])
                .arg(format!("--unit={name}"))
                .args([
                    "-p",
                    "Restart=on-failure",
                    "-p",
                    "RestartSec=300ms",
                    "-p",
                    "StartLimitIntervalSec=0",
                    "-p",
                ])
                .arg(format!(
                    "ExecStartPre=-{} update boot-check --install-dir {} --data-dir {}",
                    tenzro.display(),
                    root.display(),
                    data.display()
                ))
                .arg(format!("--setenv=FAKE_NODE_DIR={}", node_dir.display()))
                .arg(format!("--setenv=HOME={}", home.display()))
                .arg("--setenv=TENZRO_NO_BANNER=1")
                .arg(root.join("current/bin/tenzro-node")));
            assert!(started.status.success(), "systemd-run: {}", text(&started));
            Unit { name }
        }

        /// What `tenzro update` does to the node service after an install.
        fn restart(&self) {
            let out = run(Command::new("timeout").args([
                "60",
                "systemctl",
                "--user",
                "restart",
                &self.name,
            ]));
            assert!(
                out.status.success(),
                "restart (status 124 = the unit start waited 60 s): {}",
                text(&out)
            );
        }

        fn active(&self) -> bool {
            run(Command::new("systemctl").args(["--user", "is-active", "--quiet", &self.name]))
                .status
                .success()
        }
    }

    impl Drop for Unit {
        fn drop(&mut self) {
            let _ = Command::new("systemctl")
                .args(["--user", "stop", &self.name])
                .output();
            let _ = Command::new("systemctl")
                .args(["--user", "reset-failed", &self.name])
                .output();
        }
    }

    fn starts(node_dir: &Path) -> Vec<String> {
        std::fs::read_to_string(node_dir.join("starts"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn trial(data: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(data.join("update/trial.json")).unwrap()).unwrap()
    }

    /// A node's JSON-RPC endpoint that answers healthy, for the health check.
    fn healthy_rpc() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let body = loop {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break String::new();
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let raw = String::from_utf8_lossy(&buf).into_owned();
                    if let Some(end) = raw.find("\r\n\r\n") {
                        let len = raw[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break raw[end + 4..].to_string();
                        }
                    }
                };
                let result = if body.contains("tenzro_getFinality") {
                    serde_json::json!({"certified": "0x8"})
                } else {
                    serde_json::json!("0x10")
                };
                let reply =
                    serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn install_update_failed_start_rollback_refused_downgrade_and_health_check() {
        let tmp = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let work = tmp.path();
        let data = work.join("data");
        let node_dir = work.join("node");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&node_dir).unwrap();

        // Release 1 (0.9.0), installed by install.sh. Its `tenzro` is this
        // build of the CLI, as in a real release, so the unit's start count
        // and every `tenzro update` below run from the install itself.
        let key = TestKey::new(7);
        let installer = Installer::new(work, &key);
        let root = installer.root();
        let (folder, r1) = release_folder(work, &key, &fake_binary(work, "0.9.0"), "r1");
        installer.install(&folder);
        let cli = root.join("versions").join(&r1).join("bin/tenzro");
        std::fs::remove_file(&cli).unwrap();
        if std::fs::hard_link(env!("CARGO_BIN_EXE_tenzro"), &cli).is_err() {
            std::fs::copy(env!("CARGO_BIN_EXE_tenzro"), &cli).unwrap();
        }
        let tenzro = root.join("current/bin/tenzro");

        let channel = Channel::new(work);
        let keys = channel.trusted_keys(work);
        let update = |step: &str, extra: &[&str]| -> Output {
            run(Command::new(&tenzro)
                .args(["update", step, "--install-dir"])
                .arg(&root)
                .arg("--data-dir")
                .arg(&data)
                .args(extra)
                .env("HOME", &installer.home)
                .env("TENZRO_NO_BANNER", "1")
                .env_remove("TENZRO_DATA_DIR")
                .env_remove("TENZRO_UPDATE_CHANNEL"))
        };
        let channel_args = [
            "--channel".to_string(),
            channel.dir.display().to_string(),
            "--trusted-keys".to_string(),
            keys.display().to_string(),
            "--platform".to_string(),
            platform(),
        ];
        let channel_args: Vec<&str> = channel_args.iter().map(String::as_str).collect();
        let apply = |extra: &[&str]| {
            let mut args = channel_args.clone();
            args.extend_from_slice(extra);
            update("apply", &args)
        };

        let unit = Unit::start(&root, &data, &node_dir, &installer.home);
        wait_for("release 1 to start", || {
            starts(&node_dir).last().map(String::as_str) == Some("0.9.0")
        });

        // Release 2 (0.9.1), from the signed channel: switched in beside release 1.
        let r2_node = fake_binary(work, "0.9.1");
        channel.publish(2, "0.9.1", &r2_node);
        let out = apply(&["--max-boot-attempts", "2"]);
        assert!(out.status.success(), "apply release 2: {}", text(&out));
        assert_eq!(pointer(&root, "current").as_deref(), Some("0.9.1"));
        assert_eq!(pointer(&root, "previous").as_deref(), Some(r1.as_str()));
        assert_eq!(
            std::fs::read_to_string(root.join("current/RELEASE")).unwrap(),
            "0.9.1\n"
        );
        assert_eq!(trial(&data)["state"], "pending");

        // Release 2 fails to start: the unit counts each start, and the third
        // start rolls back to release 1, which the unit then runs.
        std::fs::write(node_dir.join("fail-0.9.1"), b"").unwrap();
        let before = starts(&node_dir).len();
        unit.restart();
        wait_for("the rollback to release 1", || {
            let s = starts(&node_dir);
            s.len() > before && s.last().map(String::as_str) == Some("0.9.0")
        });
        let s = starts(&node_dir);
        assert_eq!(
            s[before..].iter().filter(|v| *v == "0.9.1").count(),
            2,
            "release 2 started as often as the start limit allows: {s:?}"
        );
        assert_eq!(pointer(&root, "current").as_deref(), Some(r1.as_str()));
        assert_eq!(pointer(&root, "previous"), None);
        let t = trial(&data);
        assert_eq!(t["state"], "rolled_back", "{t}");
        assert!(t["reason"].get("boot_attempts").is_some(), "{t}");
        assert!(unit.active());

        // A downgrade: older than the installed 0.9.0, though newer than the
        // running tenzro, and under a higher manifest number.
        channel.publish(3, "0.8.0", &r2_node);
        let out = apply(&[]);
        let says = text(&out);
        assert!(!out.status.success(), "a downgrade was applied: {says}");
        assert!(says.contains("older than the installed 0.9.0"), "{says}");
        let out = update("check", &channel_args);
        assert!(
            !out.status.success() && text(&out).contains("older than the installed 0.9.0"),
            "{}",
            text(&out)
        );
        assert_eq!(pointer(&root, "current").as_deref(), Some(r1.as_str()));

        // Release 2, fixed and published again: switched in, restarted, healthy.
        std::fs::remove_file(node_dir.join("fail-0.9.1")).unwrap();
        channel.publish(4, "0.9.1", &r2_node);
        let out = apply(&[]);
        assert!(
            out.status.success(),
            "apply release 2 again: {}",
            text(&out)
        );
        assert_eq!(pointer(&root, "current").as_deref(), Some("0.9.1"));
        assert_eq!(pointer(&root, "previous").as_deref(), Some(r1.as_str()));
        unit.restart();
        wait_for("release 2 to run", || {
            starts(&node_dir).last().map(String::as_str) == Some("0.9.1")
        });
        let rpc = healthy_rpc();
        let out = update("verify", &["--rpc-url", &rpc, "--interval-secs", "1"]);
        assert!(out.status.success(), "health check: {}", text(&out));
        assert_eq!(trial(&data)["state"], "good");
        assert!(unit.active());
        assert_eq!(starts(&node_dir).last().map(String::as_str), Some("0.9.1"));

        // Now 0.9.0 is a downgrade.
        channel.publish(5, "0.9.0", &r2_node);
        let out = apply(&[]);
        assert!(
            !out.status.success() && text(&out).contains("older than the installed 0.9.1"),
            "{}",
            text(&out)
        );
        assert_eq!(pointer(&root, "current").as_deref(), Some("0.9.1"));
        drop(unit);
    }
}
