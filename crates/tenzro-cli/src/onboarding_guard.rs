//! R35, onboarding cannot be bypassed: the standing boundary guard for this crate.
//!
//! Nothing may start a participant, register a role, stake, accept a grant or serve unless the
//! machine behind it holds a hardware-rooted wallet and identity (TPM, delegated TPM, Secure
//! Enclave, passkey). This file lists every entry point the CLI has and fails when one is added
//! without being looked at:
//!
//! * no command, flag, alias or environment variable is named like a bypass (`solo`, `skip`,
//!   `insecure`, `software`, `dev` ...); the one that exists, `tenzro dev`, is listed with the
//!   reason it is safe;
//! * the CLI binds exactly the environment variables listed here, and the entry commands take
//!   exactly the flags listed here;
//! * every participation-shaped RPC the CLI calls (register, join, onboard, serve, accept,
//!   self-stake, enroll, set a role, request a grant) is gated by the node: operator-only, or a
//!   handler that checks the caller's proof; the two permissionless ones are named with why;
//! * the only code that submits a transaction is `keystore.rs`, which signs with the hardware
//!   signer;
//! * the set of files that can launch `tenzro-node` is fixed;
//! * no guided first-run plan starts the node, registers or stakes without a hardware key step
//!   and the setup step before it, and none of those steps can be skipped.
//!
//! The node's own start verdict is guarded by `crates/tenzro-node/tests/onboarding_guard.rs`, and
//! the node's flags, the environment variables read anywhere, the installers and the release
//! features by `scripts/supply-chain/check-onboarding.sh`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use clap::CommandFactory as _;
use tenzro_cli::tui::detect::{KeyRoot, Machine, Net, NodeBuild};
use tenzro_cli::tui::journey::{self, Opts};

const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src");

// ---------------------------------------------------------------------------------------------
// The command tree
// ---------------------------------------------------------------------------------------------

/// One command of the tree: its path, flags (long names and aliases) and bound environment names.
struct Node {
    path: String,
    flags: Vec<String>,
    envs: Vec<String>,
}

fn walk(cmd: &clap::Command, path: &str, out: &mut Vec<Node>) {
    let mut flags = Vec::new();
    let mut envs = Vec::new();
    for a in cmd.get_arguments() {
        if let Some(l) = a.get_long() {
            flags.push(format!("--{l}"));
        }
        for l in a.get_all_aliases().into_iter().flatten() {
            flags.push(format!("--{l}"));
        }
        if let Some(e) = a.get_env() {
            envs.push(e.to_string_lossy().into_owned());
        }
    }
    out.push(Node {
        path: path.to_string(),
        flags,
        envs,
    });
    for sub in cmd.get_subcommands() {
        walk(sub, &format!("{path} {}", sub.get_name()), out);
        for alias in sub.get_all_aliases() {
            walk(sub, &format!("{path} {alias}"), out);
        }
    }
}

fn tree() -> Vec<Node> {
    let mut out = Vec::new();
    walk(&super::Cli::command(), "tenzro", &mut out);
    out
}

/// Words that name a way round the hardware-rooted identity. Matched as whole words of a
/// command, flag or environment name (split on `-` and `_`).
const BYPASS_WORDS: &[&str] = &[
    "solo",
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
    "dev",
    "test",
    "sandbox",
    "noauth",
    "unregistered",
];

/// Word pairs: `--no-identity`, `--no-wallet` and the like.
const BYPASS_PAIRS: &[(&str, &str)] = &[
    ("no", "identity"),
    ("no", "wallet"),
    ("no", "tpm"),
    ("no", "auth"),
    ("no", "hardware"),
    ("no", "key"),
    ("no", "passkey"),
];

/// The names that match above and are safe, each with the reason.
///
/// * `tenzro dev` starts a local developer chain. It refuses before it does anything on a machine
///   with no hardware key store (`NEEDS_HARDWARE`, `commands/dev.rs`), and the node it starts
///   passes the same start gate as any node; its validator, identity and funded client keys are
///   the machine's hardware keys.
const BYPASS_NAMED_BUT_GATED: &[(&str, &str)] = &[("tenzro dev", "dev")];

fn bypass_words(name: &str) -> Vec<String> {
    let parts: Vec<String> = name
        .trim_start_matches('-')
        .split(['-', '_'])
        .map(str::to_lowercase)
        .collect();
    let mut hits: Vec<String> = parts
        .iter()
        .filter(|p| BYPASS_WORDS.contains(&p.as_str()))
        .cloned()
        .collect();
    for w in parts.windows(2) {
        if BYPASS_PAIRS.iter().any(|(a, b)| w[0] == *a && w[1] == *b) {
            hits.push(format!("{}-{}", w[0], w[1]));
        }
    }
    hits
}

#[test]
fn no_command_flag_alias_or_env_name_reads_as_a_bypass() {
    let mut found = Vec::new();
    for n in tree() {
        let own = n.path.rsplit(' ').next().unwrap_or("");
        let mut names = vec![(n.path.clone(), own.to_string())];
        names.extend(n.flags.iter().map(|f| (n.path.clone(), f.clone())));
        names.extend(n.envs.iter().map(|e| (n.path.clone(), e.clone())));
        for (path, name) in names {
            // The root command is named `tenzro`; its own name is not a finding.
            if path == "tenzro" && name == "tenzro" {
                continue;
            }
            for word in bypass_words(&name) {
                if !BYPASS_NAMED_BUT_GATED.contains(&(path.as_str(), word.as_str())) {
                    found.push(format!("{path}: {name} ({word})"));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "these read as a way round the hardware-rooted identity. Remove them, or, if they are \
         gated, add them to BYPASS_NAMED_BUT_GATED with the reason:\n{}",
        found.join("\n")
    );
}

/// The environment variables the CLI binds to a flag, with the command that binds them. Each is a
/// path, an endpoint, the release channel or the label of a key a TPM holds; none carries key
/// material and none names a role.
///
/// * `TENZRO_UPDATE_CHANNEL` says where releases are read from. A release is installed only when
///   the release keys this machine trusts signed it, wherever it was read from.
/// * `TENZRO_TPM_KEY_HOLDER` and `TENZRO_TPM_LABEL` are the socket of the key holder and the
///   label of the key it enrolled, for a machine whose keys are in another machine's TPM. The
///   key stays in that TPM and signs there.
const BOUND_ENV: &[(&str, &str)] = &[
    ("tenzro", "TENZRO_RPC"),
    ("tenzro node start", "TENZRO_DATA_DIR"),
    ("tenzro setup", "TENZRO_DATA_DIR"),
    ("tenzro update", "TENZRO_DATA_DIR"),
    ("tenzro update", "TENZRO_UPDATE_CHANNEL"),
    ("tenzro update apply", "TENZRO_DATA_DIR"),
    ("tenzro update apply", "TENZRO_UPDATE_CHANNEL"),
    ("tenzro update boot-check", "TENZRO_DATA_DIR"),
    ("tenzro update check", "TENZRO_DATA_DIR"),
    ("tenzro update check", "TENZRO_UPDATE_CHANNEL"),
    ("tenzro update notice", "TENZRO_DATA_DIR"),
    ("tenzro update notice", "TENZRO_UPDATE_CHANNEL"),
    ("tenzro update notices", "TENZRO_DATA_DIR"),
    ("tenzro update rollback", "TENZRO_DATA_DIR"),
    ("tenzro update verify", "TENZRO_DATA_DIR"),
    (
        "tenzro validator attach-attestation",
        "TENZRO_TPM_KEY_HOLDER",
    ),
    ("tenzro validator attach-attestation", "TENZRO_TPM_LABEL"),
    ("tenzro validator exit", "TENZRO_TPM_KEY_HOLDER"),
    ("tenzro validator exit", "TENZRO_TPM_LABEL"),
    ("tenzro validator register-machine", "TENZRO_TPM_KEY_HOLDER"),
    ("tenzro validator register-machine", "TENZRO_TPM_LABEL"),
];

#[test]
fn the_cli_binds_exactly_these_environment_variables() {
    let found: BTreeSet<(String, String)> = tree()
        .into_iter()
        .flat_map(|n| n.envs.into_iter().map(move |e| (n.path.clone(), e)))
        .collect();
    let want: BTreeSet<(String, String)> = BOUND_ENV
        .iter()
        .map(|(p, e)| (p.to_string(), e.to_string()))
        .collect();
    assert_eq!(
        found, want,
        "an environment variable was added to or removed from a CLI flag: decide whether it can \
         let a participant act without its hardware-rooted identity, then update BOUND_ENV"
    );
}

/// The flags of the commands that start, join, register or stake, exactly. A new flag on one of
/// them is a decision, not an accident: this fails until the list here is updated with it.
const ENTRY_FLAGS: &[(&str, &[&str])] = &[
    // `--role` and `--wallet` show where an application for a staked role stands, from what the
    // chain and the application record say. They read; they send nothing.
    (
        "tenzro join",
        &[
            "--rpc",
            "--name",
            "--origin",
            "--type",
            "--provider",
            "--role",
            "--wallet",
        ],
    ),
    // `--delegator` and the three `--delegation-*` flags name who delegates to an agent and on
    // what terms. Setup writes the terms to a file and pauses; the agent exists only once the
    // delegator has signed them with a passkey. `--restart` discards the saved place of an
    // unfinished setup.
    (
        "tenzro setup",
        &[
            "--path",
            "--rpc",
            "--name",
            "--mode",
            "--machine-name",
            "--visibility",
            "--operator",
            "--delegator",
            "--delegation-scopes",
            "--delegation-limit",
            "--delegation-hours",
            "--restart",
            "--roles",
            "--access",
            "--network-name",
            "--chain-id",
            "--data-dir",
            "--stake",
            "--validator-stake",
            "--bootstrap",
            "--genesis",
            "--provision-tpm",
            "--apply",
            "--yes",
            "--plain",
        ],
    ),
    (
        "tenzro node start",
        &[
            "--roles",
            "--config",
            "--data-dir",
            "--metrics",
            "--rpc-addr",
        ],
    ),
    (
        "tenzro node validator-self-stake",
        &["--additional", "--rpc"],
    ),
    (
        "tenzro dev",
        &["--data-dir", "--rpc-addr", "--key-namespace", "--fund"],
    ),
    ("tenzro wallet create-local", &["--key-namespace", "--rpc"]),
    (
        "tenzro validator register",
        &[
            "--key-namespace",
            "--ml-dsa-public-key",
            "--p256-public-key",
            "--node-key",
            "--proof-of-possession",
            "--node-key-proof",
            "--vrf-key",
            "--vrf-key-proof",
            "--withdrawal-address",
            "--self-stake",
            "--metadata-uri",
            "--rpc",
        ],
    ),
    // `--tpm-key-holder` and `--tpm-label` name the socket and the enrolled key label when this
    // machine's keys are in another machine's TPM. Registration still signs with that TPM's key
    // through the holder; the flags carry no key material.
    (
        "tenzro validator register-machine",
        &[
            "--key-namespace",
            "--tpm-key-holder",
            "--tpm-label",
            "--rpc",
        ],
    ),
    (
        "tenzro stake bond",
        &[
            "--role",
            "--amount",
            "--domain",
            "--bridge-signer",
            "--rpc-provider",
            "--signer-proof",
            "--pq-public-key",
            "--pq-proof",
            "--accelerators",
            "--terabytes",
            "--key-namespace",
            "--rpc",
        ],
    ),
    (
        "tenzro provider bond post",
        &["--did", "--address", "--amount", "--rpc"],
    ),
    (
        "tenzro model serve",
        &[
            "--rpc",
            "--cluster",
            "--force-single",
            "--public",
            "--gated",
            "--private",
            "--no-speculative",
            "--catalog-rpc",
        ],
    ),
    (
        "tenzro identity register-machine",
        &[
            "--controller",
            "--public-key",
            "--capabilities",
            "--request-out",
            "--request-in",
            "--did-envelope",
            "--rpc",
        ],
    ),
    (
        "tenzro identity register",
        &[
            "--name",
            "--identity-type",
            "--controller",
            "--public-key",
            "--capabilities",
            "--key-namespace",
            "--rpc",
        ],
    ),
    // Registers the identity that the account's own hardware key derives, signed by that key;
    // the flags carry no key material.
    (
        "tenzro identity register-account",
        &["--name", "--key-namespace", "--rpc"],
    ),
];

#[test]
fn the_entry_commands_take_exactly_these_flags() {
    let nodes: BTreeMap<String, Vec<String>> =
        tree().into_iter().map(|n| (n.path, n.flags)).collect();
    for (path, want) in ENTRY_FLAGS {
        let got = nodes
            .get(*path)
            .unwrap_or_else(|| panic!("the entry command `{path}` is gone: update ENTRY_FLAGS"));
        let got: BTreeSet<&str> = got.iter().map(String::as_str).collect();
        let want: BTreeSet<&str> = want.iter().copied().collect();
        assert_eq!(
            got, want,
            "`{path}` changed its flags. Check each new one cannot start, register, stake, accept \
             or serve without the hardware-rooted identity, then update ENTRY_FLAGS"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The RPCs the CLI calls
// ---------------------------------------------------------------------------------------------

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs")
            && p.file_name().and_then(|x| x.to_str()) != Some("onboarding_guard.rs")
        {
            out.push(p);
        }
    }
}

/// Every non-test source file of the CLI, relative path and the code before its test module.
fn sources() -> Vec<(String, String)> {
    let mut files = Vec::new();
    rs_files(Path::new(SRC), &mut files);
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(SRC)
                .unwrap()
                .display()
                .to_string()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).unwrap();
            let code = text.split("#[cfg(test)]").next().unwrap().to_string();
            (rel, code)
        })
        .collect()
}

/// The quoted `tenzro_*` method names in `code`.
fn rpc_methods(code: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = code;
    while let Some(i) = rest.find("\"tenzro_") {
        let tail = &rest[i + 1..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        if tail[end..].starts_with('"') {
            out.insert(tail[..end].to_string());
        }
        rest = &tail[end..];
    }
    out
}

/// The quoted strings of `pub const <name>` in the node's RPC gate file.
fn gate_strings(gates: &str, name: &str) -> BTreeSet<String> {
    let start = gates
        .find(&format!("pub const {name}"))
        .unwrap_or_else(|| panic!("rpc_gates.rs has no {name}"));
    let body = &gates[start..];
    let end = body.find("\n];").expect("array end");
    rpc_methods(&body[..end])
}

/// Methods whose name reads as taking part: registering, joining, onboarding, serving, accepting,
/// self-staking, enrolling, setting a role, asking for a grant.
fn participation_shaped(method: &str) -> bool {
    let m = method.trim_start_matches("tenzro_");
    [
        "register",
        "unregister",
        "join",
        "onboard",
        "serve",
        "accept",
        "validatorSelfStake",
        "stake",
        "unstake",
        "bond",
        "enroll",
        "setRole",
        "requestRemoteGrant",
        "grant",
        "provision",
        "delegate",
        "claim",
        "activate",
        "admit",
    ]
    .iter()
    .any(|p| m.starts_with(p))
}

/// Participation RPCs the node serves to any caller, and the reason each is safe. The node lists
/// them again, with its own wording, in `OPEN_WRITES` (`crates/tenzro-node/src/rpc_gates.rs`).
const OPEN_PARTICIPATION: &[(&str, &str)] = &[
    (
        "tenzro_joinAsMicroNode",
        "creates an identity only from the wallet key the caller presents: the handler refuses a \
         request without `public_key` (and a human one without `credential_id`)",
    ),
    (
        "tenzro_onboardAutonomousAgent",
        "creates a self-controlled identity bonded from its own new wallet, from the device key \
         the caller presents",
    ),
];

#[test]
fn every_participation_rpc_the_cli_calls_is_gated_by_the_node() {
    let gates_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tenzro-node/src/rpc_gates.rs");
    let Ok(gates) = std::fs::read_to_string(&gates_path) else {
        eprintln!(
            "{} is not in this checkout; the node's gate lists were not read",
            gates_path.display()
        );
        return;
    };
    let admin = gate_strings(&gates, "ADMIN_METHODS");
    let owner = gate_strings(&gates, "OWNER_METHODS");
    let open_writes = {
        let s = gates.find("OPEN_WRITES").expect("OPEN_WRITES");
        gates[s..].to_string()
    };

    let mut called = BTreeMap::new();
    for (file, code) in sources() {
        for m in rpc_methods(&code)
            .into_iter()
            .filter(|m| participation_shaped(m))
        {
            called.entry(m).or_insert_with(Vec::new).push(file.clone());
        }
    }
    assert!(
        called.len() >= 8,
        "the participation-shaped RPC scan found only {} methods: it has rotted ({called:?})",
        called.len()
    );

    let mut ungated = Vec::new();
    for (method, files) in &called {
        if admin.contains(method) || owner.contains(method) {
            continue;
        }
        match OPEN_PARTICIPATION.iter().find(|(m, _)| m == method) {
            Some(_) if open_writes.contains(&format!("\"{method}\"")) => {}
            _ => ungated.push(format!("{method} (called from {})", files.join(", "))),
        }
    }
    assert!(
        ungated.is_empty(),
        "the CLI calls a participation RPC the node serves to anyone. Make the node gate it \
         (ADMIN_METHODS: operator only, or OWNER_METHODS: the handler checks a proof), or list it \
         in OPEN_PARTICIPATION with why it is safe:\n{}",
        ungated.join("\n")
    );
}

// ---------------------------------------------------------------------------------------------
// Signing and launching
// ---------------------------------------------------------------------------------------------

#[test]
fn only_the_hardware_keystore_submits_transactions() {
    let mut elsewhere = Vec::new();
    for (file, code) in sources() {
        if file == "keystore.rs" {
            continue;
        }
        for m in [
            "\"tenzro_sendRawTransaction\"",
            "\"eth_sendRawTransaction\"",
            "\"eth_sendTransaction\"",
            "\"tenzro_sendTransaction\"",
        ] {
            if code.contains(m) {
                elsewhere.push(format!("{file} submits with {m}"));
            }
        }
    }
    assert!(
        elsewhere.is_empty(),
        "a transaction is submitted outside keystore.rs, which signs it with the machine's \
         hardware key:\n{}",
        elsewhere.join("\n")
    );

    let keystore = sources()
        .into_iter()
        .find(|(f, _)| f == "keystore.rs")
        .expect("keystore.rs")
        .1;
    assert!(
        keystore.contains("HardwareHybridSigner"),
        "keystore.rs no longer signs with the hardware signer"
    );
    for banned in [
        "SigningKey",
        "from_seed",
        "OsRng",
        "thread_rng",
        "generate_keypair",
        "KeyPair",
        "SoftwareSigner",
        "MemorySigner",
        "TestSigner",
    ] {
        assert!(
            !keystore.contains(banned),
            "keystore.rs holds a software signing path: {banned}"
        );
    }
}

/// The files that find or start `tenzro-node`. Every node they start passes the node's start gate
/// (`require_hardware_key_store` and `require_hardware_identity` in `tenzro-node/src/main.rs`),
/// so each is a way to ask for a node, not a way round the gate; a new file is still a decision.
const NODE_LAUNCHERS: &[&str] = &[
    "commands/dev.rs",
    "commands/doctor.rs",
    "commands/node.rs",
    "commands/preflight.rs",
    "commands/service.rs",
    "commands/setup.rs",
    "commands/tpm.rs",
    // The update commands hash, install and restore the binary as a file. Bare `tenzro update`
    // also restarts the node, and only by restarting its installed service, so the node that
    // runs afterwards is started by that service, through the same gate.
    "commands/update/health.rs",
    "commands/update/manifest.rs",
    "commands/update/mod.rs",
    "commands/update/run.rs",
    "commands/update/tests.rs",
    "tui/console.rs",
    "tui/detect.rs",
    "tui/journey.rs",
    "tui/runner.rs",
];

#[test]
fn only_these_files_launch_the_node() {
    let found: BTreeSet<String> = sources()
        .into_iter()
        .filter(|(_, code)| {
            [
                "locate_node_binary",
                "node_binary_path",
                "\"tenzro-node",
                "Prog::Node",
                "tenzro-node{",
            ]
            .iter()
            .any(|t| code.contains(t))
        })
        .map(|(f, _)| f)
        .collect();
    let want: BTreeSet<String> = NODE_LAUNCHERS.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        found, want,
        "the set of files that can launch tenzro-node changed: check the new one runs the node \
         only through its start gate, then update NODE_LAUNCHERS"
    );
}

// ---------------------------------------------------------------------------------------------
// The guided first run
// ---------------------------------------------------------------------------------------------

fn machine(root: KeyRoot) -> Machine {
    let mut m = Machine::blank();
    m.root = root;
    m.node_binary = Some(PathBuf::from("/usr/bin/tenzro-node"));
    m.node_build = Some(NodeBuild {
        flavour: "cpu".into(),
        startup_ok: true,
        refusal: None,
    });
    m
}

fn every_root() -> Vec<KeyRoot> {
    vec![
        KeyRoot::SecureEnclave,
        KeyRoot::NoSecureEnclave,
        KeyRoot::TpmReady,
        KeyRoot::TpmNeedsProvision,
        KeyRoot::TpmUnknown,
        KeyRoot::TpmNoAccess {
            reason: "denied".into(),
            in_tss: false,
        },
        KeyRoot::TpmNoAccess {
            reason: "denied".into(),
            in_tss: true,
        },
        KeyRoot::NoTpm,
    ]
}

#[test]
fn no_guided_plan_starts_registers_or_stakes_without_a_hardware_key_and_setup_first() {
    let net = Net::Reachable {
        chain_id: "0x1".into(),
    };
    let mut checked = 0;
    for root in every_root() {
        for delegated in [false, true] {
            for path in [journey::Path::Provide, journey::Path::Validate] {
                let m = machine(root.clone());
                let mut o = Opts::defaults(&m, tenzro_cli::endpoint::PUBLIC_RPC);
                o.delegated = delegated;
                let p = journey::plan(path, &m, &net, &o);
                let ctx = format!("{path:?} on {root:?}, delegated {delegated}");

                if p.blocked.is_some() {
                    assert!(
                        p.steps.is_empty() || p.steps.iter().all(|s| s.id != "start-node"),
                        "a blocked plan still starts the node: {ctx}"
                    );
                    continue;
                }
                // A plan that is not blocked has a hardware root: the machine's own, or the
                // delegated one the operator's passkey grants.
                assert!(
                    root.has_local_hardware() || delegated,
                    "a plan with no hardware root and no delegation is not blocked: {ctx}"
                );
                let ids: Vec<&str> = p.steps.iter().map(|s| s.id).collect();
                let at = |id: &str| ids.iter().position(|i| *i == id);
                let start = at("start-node").unwrap_or_else(|| panic!("no start-node step: {ctx}"));
                let setup = at("setup").unwrap_or_else(|| panic!("no setup step: {ctx}"));
                let key = ids
                    .iter()
                    .position(|i| ["hardware-key", "tpm-provision", "holder-install"].contains(i))
                    .unwrap_or_else(|| panic!("no hardware key step: {ctx}"));
                assert!(
                    key < setup && setup < start,
                    "key, setup, start out of order: {ids:?} ({ctx})"
                );
                if let Some(reg) = at("register") {
                    assert!(
                        start < reg,
                        "registering before the node runs: {ids:?} ({ctx})"
                    );
                }
                for fixed in [
                    "setup",
                    "start-node",
                    "tpm-provision",
                    "hardware-key",
                    "holder-install",
                ] {
                    if let Some(i) = at(fixed) {
                        assert!(!p.steps[i].skippable, "`{fixed}` can be skipped: {ctx}");
                    }
                }
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 6,
        "only {checked} plans were checked: the enumeration has rotted"
    );
}

#[test]
fn the_guided_local_chain_needs_a_hardware_key_and_using_the_network_runs_the_setup() {
    let net = Net::Reachable {
        chain_id: "0x1".into(),
    };
    for root in every_root() {
        let m = machine(root.clone());
        let o = Opts::defaults(&m, tenzro_cli::endpoint::PUBLIC_RPC);
        let local = journey::plan(journey::Path::Local, &m, &net, &o);
        assert_eq!(
            local.blocked.is_none(),
            root.has_local_hardware(),
            "the local chain's verdict does not follow the hardware key on {root:?}"
        );
        // Using the network needs no node, only the identity: the one step is `tenzro setup`, and
        // it cannot be skipped.
        let net_plan = journey::plan(journey::Path::UseNetwork, &m, &net, &o);
        let last = net_plan.steps.last().expect("a step");
        assert_eq!(last.id, "setup");
        assert!(!last.skippable);
        assert!(
            last.command_line()
                .unwrap()
                .starts_with("tenzro setup --yes --path network")
        );
        assert!(
            net_plan
                .steps
                .iter()
                .all(|s| s.id == "about" || s.id == "setup")
        );
    }
}

/// R33: a wallet is created only around a public key the identity presents; the wallet service
/// never generates, derives or stores a signing secret, and a wallet identity needs a passkey
/// credential id or a machine id.
#[test]
fn the_wallet_service_mints_no_key() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tenzro-wallet/src");
    let (Ok(service), Ok(identity)) = (
        std::fs::read_to_string(dir.join("service.rs")),
        std::fs::read_to_string(dir.join("identity_binding.rs")),
    ) else {
        eprintln!("tenzro-wallet is not in this checkout; not read");
        return;
    };
    let body = service
        .split("async fn provision_wallet")
        .nth(1)
        .expect("provision_wallet");
    let body = body.split("// === ").next().unwrap_or(body);
    let body = body.split("async fn ").next().unwrap_or(body);
    for banned in [
        "generate",
        "OsRng",
        "thread_rng",
        "from_seed",
        "SigningKey",
        "random",
    ] {
        assert!(
            !body.contains(banned),
            "provision_wallet mints or derives a key: {banned}"
        );
    }
    assert!(identity.contains("a human wallet needs a passkey credential id"));
    assert!(identity.contains("a machine wallet needs a machine id"));
}
