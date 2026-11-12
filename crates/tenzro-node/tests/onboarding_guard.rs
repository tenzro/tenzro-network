//! R35, onboarding cannot be bypassed: the node's start verdict, guarded.
//!
//! A node starts only with its identity key in hardware: its own TPM or Secure Enclave, or another
//! machine's TPM under an operator passkey grant (`--tpm-key-holder`). There is no flag, environment
//! variable, config key or mode that starts one without. This file starts the real binary with every
//! bypass-shaped combination there is and asserts each is refused, and pins where in `main.rs` the
//! gate sits.
//!
//! The list of flags, subcommands and environment variables itself is guarded by
//! `scripts/supply-chain/check-onboarding.sh`, which fails on any that is not reviewed.
//!
//! The refusals are asserted where this process sees no hardware key store (as in
//! `no_tpm_refusal.rs`): on a machine with a TPM the binary would open it. The delegated-root cases
//! point at a socket that does not exist, so they are refused on every machine.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn node_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_tenzro-node")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_tenzro-node").map(PathBuf::from))
        .expect("cargo test names the tenzro-node binary in CARGO_BIN_EXE_tenzro-node")
}

/// How a run ended.
struct Ended {
    success: bool,
    stderr: String,
}

/// Start the node with `args` and `envs` over an empty data directory and wait for it to end. A node
/// that is still running after `limit` has started: it is killed and the test fails.
fn start(args: &[&str], envs: &[(&str, &str)], limit: Duration) -> Ended {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("node.toml");
    std::fs::write(&config, "").unwrap();
    let errf = dir.path().join("stderr");
    let mut cmd = Command::new(node_binary());
    cmd.args(["--log-format", "json", "-c"])
        .arg(&config)
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .args(args)
        .env_remove("RUST_LOG")
        .env("TENZRO_DEVICE_KEY_DIR", dir.path().join("device-keys"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&errf).unwrap());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let began = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Ended {
                success: status.success(),
                stderr: std::fs::read_to_string(&errf).unwrap_or_default(),
            };
        }
        if began.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = std::fs::read_to_string(&errf).unwrap_or_default();
            panic!("the node STARTED and kept running with {args:?} {envs:?}:\n{stderr}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

const LIMIT: Duration = Duration::from_secs(90);

type Case = (
    &'static str,
    Vec<&'static str>,
    Vec<(&'static str, &'static str)>,
);

/// Every way the start line can be shaped to look like a bypass: the `solo` and `dev` shortcuts, an
/// isolated chain, a funded developer chain, a self-staking validator, several roles, a missing
/// genesis, and the environment the flags also read.
fn bypass_shaped() -> Vec<Case> {
    let fund: &'static str = Box::leak(format!("0x{}", "ab".repeat(32)).into_boxed_str());
    vec![
        ("no flags", vec![], vec![]),
        ("--solo", vec!["--solo"], vec![]),
        ("--dev", vec!["--dev"], vec![]),
        ("--dev --fund", vec!["--dev", "--fund", fund], vec![]),
        (
            "isolated: --boot-nodes ''",
            vec!["--boot-nodes", ""],
            vec![],
        ),
        (
            "--solo validator that self-stakes",
            vec![
                "--solo",
                "--roles",
                "validator",
                "--validator-self-stake",
                "10000000000000000000000",
            ],
            vec![],
        ),
        (
            "validator and storage roles",
            vec!["--roles", "validator,storage"],
            vec![],
        ),
        (
            "a genesis file that is not there",
            vec!["--genesis", "/nonexistent/genesis.toml"],
            vec![],
        ),
        (
            "TENZRO_BOOT_NODES empty",
            vec![],
            vec![("TENZRO_BOOT_NODES", "")],
        ),
        ("TENZRO_TIER set", vec![], vec![("TENZRO_TIER", "edge")]),
        (
            "TENZRO_DEVICE_KEY_DIR at a scratch directory (set for every run here)",
            vec![],
            vec![],
        ),
        (
            "a key label with no key holder",
            vec!["--tpm-label", "x"],
            vec![],
        ),
    ]
}

#[test]
fn every_bypass_shaped_start_is_refused_on_a_machine_with_no_hardware_key() {
    if tenzro_device_key::signer::platform_backend().is_some() {
        eprintln!("this machine has a hardware key store; the no-TPM starts are not run here");
        return;
    }
    for (name, args, envs) in bypass_shaped() {
        let ended = start(&args, &envs, LIMIT);
        assert!(!ended.success, "a node started: {name}\n{}", ended.stderr);
        // Every case above is a valid start line, so a refusal that is not the gate's is a
        // different failure hiding the question.
        assert!(
            ended
                .stderr
                .contains(tenzro_node::identity_bootstrap::NO_HARDWARE_IDENTITY),
            "{name}: refused, but not by the hardware-identity gate:\n{}",
            ended.stderr
        );
    }
}

#[test]
fn a_delegated_root_that_is_not_there_does_not_start_a_node() {
    let missing = "/nonexistent/tenzro/holder.sock";
    let cases: Vec<Case> = vec![
        (
            "--tpm-key-holder with a label",
            vec!["--tpm-key-holder", missing, "--tpm-label", "x"],
            vec![],
        ),
        (
            "--tpm-key-holder without a label",
            vec!["--tpm-key-holder", missing],
            vec![],
        ),
        (
            "--solo over a missing holder",
            vec!["--solo", "--tpm-key-holder", missing, "--tpm-label", "x"],
            vec![],
        ),
        (
            "the holder from the environment",
            vec![],
            vec![
                ("TENZRO_TPM_KEY_HOLDER", missing),
                ("TENZRO_TPM_LABEL", "x"),
            ],
        ),
    ];
    for (name, args, envs) in cases {
        let ended = start(&args, &envs, LIMIT);
        assert!(
            !ended.success,
            "a node started on a delegated root that does not exist: {name}\n{}",
            ended.stderr
        );
    }
}

/// `--solo` and `--dev` are the two start flags named like a bypass. They are listed because both
/// are read after the gate; any other flag named like one fails here.
#[test]
fn no_start_flag_other_than_solo_and_dev_is_named_like_a_bypass() {
    let out = Command::new(node_binary()).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    let words = [
        "solo",
        "dev",
        "skip",
        "insecure",
        "software",
        "unsafe",
        "bypass",
        "anonymous",
        "mock",
        "fake",
        "unattested",
        "offline",
        "sandbox",
        "noauth",
        "unregistered",
    ];
    let mut flags = std::collections::BTreeSet::new();
    for tok in help.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
        if let Some(name) = tok.strip_prefix("--")
            && !name.is_empty()
        {
            flags.insert(name.to_string());
        }
    }
    assert!(
        flags.len() >= 20,
        "the help parse found only {} flags",
        flags.len()
    );
    for f in &flags {
        let parts: Vec<&str> = f.split('-').collect();
        let hit = parts.iter().any(|p| words.contains(p))
            || parts.windows(2).any(|w| {
                w[0] == "no"
                    && [
                        "identity", "wallet", "tpm", "auth", "hardware", "key", "passkey",
                    ]
                    .contains(&w[1])
            });
        assert!(
            !hit || f == "solo" || f == "dev",
            "--{f} is named like a way round the hardware-rooted identity: remove it, or make it \
             pass the start gate and list it here with the reason"
        );
    }
    assert!(
        flags.contains("solo") && flags.contains("dev"),
        "the listed exceptions moved: update this test"
    );
}

/// The gate sits before anything that makes a node a participant: storage, the node, the RPC and
/// web servers. Pinned by position in `main.rs`; moving a gate below one of them fails this.
#[test]
fn the_start_gate_comes_before_everything_that_makes_a_participant() {
    let main = include_str!("../src/main.rs");
    let gate_key_store = main
        .find("identity_bootstrap::require_hardware_key_store()")
        .expect("the key store gate");
    let gate_identity = main
        .find("identity_bootstrap::require_hardware_identity")
        .expect("the identity gate");
    assert!(gate_key_store < gate_identity);
    for participant in [
        "TenzroNode::new(",
        "RpcServer::new(",
        "web::WebServer::new(",
        "identity_bootstrap::start(",
        "keep_chain_policies(",
    ] {
        let hits: Vec<usize> = main.match_indices(participant).map(|(i, _)| i).collect();
        for at in &hits {
            let line_start = main[..*at].rfind('\n').map_or(0, |i| i + 1);
            let line = main[line_start..].lines().next().unwrap_or("");
            if line.trim_start().starts_with("//") {
                continue;
            }
            assert!(
                *at > gate_identity,
                "`{participant}` appears in main.rs before the hardware-identity gate: {line}"
            );
        }
    }
    // The administrative subcommands return before the node is built, and only run one-shot
    // commands (`run_subcommand`).
    let sub = main.find("cli.command.take()").expect("subcommand branch");
    assert!(sub < gate_key_store);
    let branch = &main[sub..gate_key_store];
    assert!(branch.contains("return run_subcommand(cmd, &config).await;"));
    assert!(!branch.contains("TenzroNode::new"));
}
