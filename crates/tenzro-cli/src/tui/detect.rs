//! What this machine can do, in plain words.
//!
//! `probe` reads the machine (hardware, the key store, the node program, the
//! public network); `findings` turns what was read into sentences with a fix
//! for every one that needs it. `findings` is pure, so each case (no TPM, no
//! network, a CPU build on a GPU machine) is tested without the machine.

use std::path::PathBuf;
use std::time::Duration;

use super::theme::Word;
use crate::commands::preflight::{Facts, Root};

/// Where this machine's keys can live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRoot {
    /// A Mac's Secure Enclave: nothing to set up.
    SecureEnclave,
    /// A Mac without a usable Secure Enclave.
    NoSecureEnclave,
    /// A TPM 2.0 with the node's keys in place.
    TpmReady,
    /// A TPM 2.0 that `tenzro-node tpm provision` has not been run on.
    TpmNeedsProvision,
    /// A TPM 2.0 whose provisioning state could not be read.
    TpmUnknown,
    /// A TPM exists and this user cannot open it. `in_tss` says whether the
    /// user already belongs to the `tss` group.
    TpmNoAccess { reason: String, in_tss: bool },
    /// No TPM device at all.
    NoTpm,
}

impl KeyRoot {
    /// Whether the node could start on this machine's own hardware once any
    /// provisioning is done.
    pub fn has_local_hardware(&self) -> bool {
        matches!(
            self,
            KeyRoot::SecureEnclave
                | KeyRoot::TpmReady
                | KeyRoot::TpmNeedsProvision
                | KeyRoot::TpmUnknown
        )
    }

    /// Whether keys are in place and nothing is left to provision.
    pub fn is_ready(&self) -> bool {
        matches!(self, KeyRoot::SecureEnclave | KeyRoot::TpmReady)
    }
}

/// Pure reading of the probe facts.
pub fn key_root(f: &Facts) -> KeyRoot {
    if f.root == Root::SecureEnclave {
        return if f.secure_enclave {
            KeyRoot::SecureEnclave
        } else {
            KeyRoot::NoSecureEnclave
        };
    }
    if !f.tpm_device {
        return KeyRoot::NoTpm;
    }
    if let Some(reason) = &f.tpm_open_error {
        return KeyRoot::TpmNoAccess {
            reason: reason.clone(),
            in_tss: f.groups.iter().any(|g| g == "tss"),
        };
    }
    match f.keys_provisioned {
        Some(true) => KeyRoot::TpmReady,
        Some(false) => KeyRoot::TpmNeedsProvision,
        None => KeyRoot::TpmUnknown,
    }
}

/// What `tenzro-node hardware` said about the build on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBuild {
    /// For example `cpu` or `cuda`.
    pub flavour: String,
    /// Whether the node would start here.
    pub startup_ok: bool,
    /// The refusal, when it would not.
    pub refusal: Option<String>,
}

/// Parse the output of `tenzro-node hardware`. Pure.
pub fn parse_node_hardware(out: &str) -> Option<NodeBuild> {
    let mut flavour = None;
    let mut startup: Option<(bool, Option<String>)> = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("build:") {
            flavour = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("startup:") {
            let v = v.trim();
            if v == "ok" {
                startup = Some((true, None));
            } else if let Some(r) = v.strip_prefix("refused") {
                let r = r.trim().trim_start_matches('(').trim_end_matches(')').trim();
                startup = Some((false, Some(r.to_string())));
            }
        }
    }
    let (startup_ok, refusal) = startup?;
    Some(NodeBuild {
        flavour: flavour.unwrap_or_default(),
        startup_ok,
        refusal,
    })
}

/// The public network, as reached from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Net {
    Checking,
    Reachable { chain_id: String },
    /// The name does not resolve.
    NotResolving,
    /// Resolved but did not answer (refused, timeout, TLS, HTTP error).
    NotAnswering { reason: String },
}

impl Net {
    pub fn is_reachable(&self) -> bool {
        matches!(self, Net::Reachable { .. })
    }
}

/// Everything the first-run screens know about the machine.
#[derive(Debug, Clone)]
pub struct Machine {
    pub os: String,
    pub arch: String,
    pub cpu: String,
    pub cores: usize,
    pub ram_gb: f64,
    pub disk_free_gb: f64,
    pub gpus: Vec<String>,
    pub root: KeyRoot,
    pub node_binary: Option<PathBuf>,
    pub node_build: Option<NodeBuild>,
    pub hostname: String,
}

impl Machine {
    /// A machine with plain defaults, for tests and the pending screen.
    pub fn blank() -> Self {
        Self {
            os: "linux".into(),
            arch: "x86_64".into(),
            cpu: "unknown".into(),
            cores: 1,
            ram_gb: 0.0,
            disk_free_gb: 0.0,
            gpus: Vec::new(),
            root: KeyRoot::TpmUnknown,
            node_binary: None,
            node_build: None,
            hostname: "tenzro".into(),
        }
    }
}

/// Read the machine.
pub async fn probe() -> Machine {
    let hw = crate::commands::hardware::detect_hardware_profile().await;
    let secure_enclave = crate::commands::setup::has_secure_enclave(&hw);
    let (facts, node_binary) = tokio::task::spawn_blocking(move || {
        let f = Facts::probe(secure_enclave);
        let nb = f.node_binary.clone();
        (f, nb)
    })
    .await
    .unwrap_or_else(|_| (Facts::probe(secure_enclave), None));
    let node_build = match node_binary.clone() {
        Some(p) => tokio::task::spawn_blocking(move || run_node_hardware(&p))
            .await
            .ok()
            .flatten(),
        None => None,
    };
    Machine {
        os: hw.os.clone(),
        arch: hw.arch.clone(),
        cpu: hw.cpu_model.clone(),
        cores: hw.cpu_cores,
        ram_gb: hw.total_ram_gb,
        disk_free_gb: hw.storage_available_gb,
        gpus: hw
            .gpus
            .iter()
            .map(|g| {
                if g.memory_gb > 0.0 {
                    format!("{} ({:.0} GB)", g.name, g.memory_gb)
                } else {
                    g.name.clone()
                }
            })
            .collect(),
        root: key_root(&facts),
        node_binary,
        node_build,
        hostname: crate::commands::setup::hostname_for_tui(),
    }
}

fn run_node_hardware(node: &std::path::Path) -> Option<NodeBuild> {
    let mut child = std::process::Command::new(node)
        .arg("hardware")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                return None;
            }
        }
    }
    let out = child.wait_with_output().ok()?;
    parse_node_hardware(&String::from_utf8_lossy(&out.stdout))
}

/// Ask a node whether it answers, within a short time.
pub async fn check_network(url: &str) -> Net {
    let rpc = crate::rpc::RpcClient::new(url);
    let call = rpc.call::<String>("eth_chainId", serde_json::json!([]));
    match tokio::time::timeout(Duration::from_secs(5), call).await {
        Err(_) => Net::NotAnswering {
            reason: "no answer within 5 seconds".into(),
        },
        Ok(Ok(id)) => Net::Reachable { chain_id: id },
        Ok(Err(e)) => match e
            .chain()
            .find_map(|c| c.downcast_ref::<crate::friendly::Unreachable>())
        {
            Some(u) if u.class == crate::friendly::Class::Dns => Net::NotResolving,
            Some(u) => Net::NotAnswering {
                reason: u.explained.why.clone(),
            },
            None => Net::NotAnswering {
                reason: e.to_string(),
            },
        },
    }
}

/// One plain-language line about the machine, with the fix when it needs one.
#[derive(Debug, Clone)]
pub struct Finding {
    pub label: &'static str,
    pub word: Word,
    pub text: String,
    pub fix: Vec<String>,
}

fn f(label: &'static str, word: Word, text: impl Into<String>) -> Finding {
    Finding {
        label,
        word,
        text: text.into(),
        fix: Vec::new(),
    }
}

/// The findings, in the order they are shown. Pure.
pub fn findings(m: &Machine, net: &Net, rpc_url: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    out.push(f("System", Word::Ok, format!("{} on {}", m.os, m.arch)));
    out.push(f(
        "Processor",
        Word::Ok,
        format!("{}, {} cores", m.cpu, m.cores),
    ));
    out.push(if m.ram_gb < 4.0 && m.ram_gb > 0.0 {
        let mut x = f(
            "Memory",
            Word::Watch,
            format!("{:.0} GB: enough to follow the network, too little to serve models", m.ram_gb),
        );
        x.fix.push("Use a machine with 16 GB or more to provide compute.".into());
        x
    } else {
        f("Memory", Word::Ok, format!("{:.0} GB", m.ram_gb))
    });
    out.push(if m.disk_free_gb > 0.0 && m.disk_free_gb < 20.0 {
        let mut x = f(
            "Disk",
            Word::Watch,
            format!("{:.0} GB free: the chain and models need more", m.disk_free_gb),
        );
        x.fix.push("Free some space, or point the node at a bigger disk with --data-dir.".into());
        x
    } else {
        f("Disk", Word::Ok, format!("{:.0} GB free", m.disk_free_gb))
    });
    out.push(if m.gpus.is_empty() {
        f(
            "Graphics",
            Word::Ok,
            "no GPU found: fine for using the network or validating, models will run on the CPU",
        )
    } else {
        f("Graphics", Word::Ok, m.gpus.join(", "))
    });

    out.push(match &m.root {
        KeyRoot::SecureEnclave => f("Hardware key", Word::Ok, "Secure Enclave: this Mac keeps its keys in hardware, nothing to set up"),
        KeyRoot::TpmReady => f("Hardware key", Word::Ok, "TPM 2.0 found, and this machine's Tenzro keys are in it"),
        KeyRoot::TpmNeedsProvision => {
            let mut x = f("Hardware key", Word::Action, "TPM 2.0 found; the Tenzro keys are not created in it yet (one step, done once)");
            x.fix.push("This setup creates them: tenzro-node tpm provision".into());
            x
        }
        KeyRoot::TpmUnknown => f("Hardware key", Word::Watch, "TPM 2.0 found; whether the Tenzro keys exist in it could not be read (tpm2-tools may be missing)"),
        KeyRoot::TpmNoAccess { reason, in_tss } => {
            let mut x = f("Hardware key", Word::Action, format!("TPM 2.0 found, but this user cannot open it ({reason})"));
            if *in_tss {
                x.fix.push("You are in the tss group already; check the device: ls -l /dev/tpmrm0".into());
            } else {
                x.fix.push("sudo usermod -aG tss $USER, then log out and in again".into());
            }
            x
        }
        KeyRoot::NoSecureEnclave => {
            let mut x = f("Hardware key", Word::Action, "no usable Secure Enclave on this Mac");
            x.fix.push("A Mac with Apple silicon or a T2 chip is needed to run a node.".into());
            x.fix.push("You can still use the network from here with a passkey.".into());
            x
        }
        KeyRoot::NoTpm => {
            let mut x = f("Hardware key", Word::Action, "no TPM 2.0 on this machine: it cannot hold a node's keys itself");
            x.fix.push("Turn the TPM on in the firmware settings (fTPM, PTT or Security Device), then reboot.".into());
            x.fix.push("Or keep the keys in another machine's TPM (a key holder), offered in the validator and provider paths.".into());
            x.fix.push("Or use the network with a passkey, which needs no TPM.".into());
            x
        }
    });

    out.push(match (&m.node_binary, &m.node_build) {
        (None, _) => {
            let mut x = f("Node program", Word::Action, "tenzro-node was not found next to tenzro or on PATH");
            x.fix.push("Install the Tenzro package for this machine; it puts tenzro and tenzro-node together.".into());
            x
        }
        (Some(_), Some(b)) if !b.startup_ok => {
            let why = b.refusal.clone().unwrap_or_default();
            let mut x = f("Node program", Word::Action, format!("this {} build of tenzro-node would refuse to start here: {}", b.flavour, why));
            if !m.gpus.is_empty() && b.flavour.to_lowercase().contains("cpu") {
                x.text = format!("this is the CPU build of tenzro-node, and this machine has a GPU ({}): the node refuses a CPU build here", m.gpus[0]);
                x.fix.push("Install the GPU (CUDA) package for this machine, or the CPU package on a machine without a GPU.".into());
            } else {
                x.fix.push("Install the package that matches this machine's graphics hardware.".into());
            }
            x
        }
        (Some(p), Some(b)) => f("Node program", Word::Ok, format!("{} build at {}", b.flavour, p.display())),
        (Some(p), None) => f("Node program", Word::Watch, format!("found at {}, but its hardware check did not answer", p.display())),
    });

    out.push(match net {
        Net::Checking => f("Network", Word::Unknown, format!("checking {rpc_url}")),
        Net::Reachable { chain_id } => f("Network", Word::Ok, format!("{rpc_url} answers (chain {chain_id})")),
        Net::NotResolving => {
            let mut x = f("Network", Word::Watch, format!("the network is not reachable yet: {} does not resolve", crate::friendly::host_of(rpc_url)));
            x.fix.push("You can still try Tenzro on this machine: it runs its own local chain.".into());
            x
        }
        Net::NotAnswering { reason } => {
            let mut x = f("Network", Word::Watch, format!("{rpc_url} did not answer: {reason}"));
            x.fix.push("Check this machine's internet connection, or try Tenzro on a local chain.".into());
            x
        }
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            root: Root::Tpm,
            secure_enclave: false,
            tpm_device: true,
            tpm_open_error: None,
            user: "u".into(),
            groups: vec![],
            missing_tools: vec![],
            node_binary: None,
            keys_provisioned: Some(true),
        }
    }

    #[test]
    fn key_root_covers_each_tpm_state() {
        let mut x = facts();
        assert_eq!(key_root(&x), KeyRoot::TpmReady);
        x.keys_provisioned = Some(false);
        assert_eq!(key_root(&x), KeyRoot::TpmNeedsProvision);
        x.keys_provisioned = None;
        assert_eq!(key_root(&x), KeyRoot::TpmUnknown);
        x.tpm_open_error = Some("denied".into());
        assert!(matches!(key_root(&x), KeyRoot::TpmNoAccess { in_tss: false, .. }));
        x.tpm_device = false;
        assert_eq!(key_root(&x), KeyRoot::NoTpm);
        let mut mac = facts();
        mac.root = Root::SecureEnclave;
        mac.secure_enclave = true;
        assert_eq!(key_root(&mac), KeyRoot::SecureEnclave);
        mac.secure_enclave = false;
        assert_eq!(key_root(&mac), KeyRoot::NoSecureEnclave);
    }

    #[test]
    fn node_hardware_output_is_parsed() {
        let ok = parse_node_hardware("build: cpu\ngpus: 0\nonnx: CPU\nstartup: ok\n").unwrap();
        assert!(ok.startup_ok && ok.flavour == "cpu");
        let bad = parse_node_hardware("build: cpu\ngpus: 1\nstartup: refused (CPU build on a GPU machine)\n").unwrap();
        assert!(!bad.startup_ok);
        assert_eq!(bad.refusal.as_deref(), Some("CPU build on a GPU machine"));
        assert!(parse_node_hardware("garbage").is_none());
    }

    #[test]
    fn no_tpm_gives_what_why_and_three_ways_forward() {
        let mut m = Machine::blank();
        m.root = KeyRoot::NoTpm;
        let all = findings(&m, &Net::Checking, "https://rpc.tenzro.com");
        let k = all.iter().find(|x| x.label == "Hardware key").unwrap();
        assert_eq!(k.word, Word::Action);
        assert!(k.text.contains("no TPM 2.0"));
        assert!(k.fix.len() >= 3);
    }

    #[test]
    fn an_unresolvable_network_is_a_notice_not_an_error_and_offers_local() {
        let m = Machine::blank();
        let all = findings(&m, &Net::NotResolving, "https://rpc.tenzro.com");
        let n = all.iter().find(|x| x.label == "Network").unwrap();
        assert_eq!(n.word, Word::Watch);
        assert!(n.text.contains("not reachable yet"));
        assert!(n.fix[0].contains("local chain"));
    }

    #[test]
    fn a_cpu_build_on_a_gpu_machine_says_to_install_the_gpu_package() {
        let mut m = Machine::blank();
        m.gpus = vec!["NVIDIA RTX 4090 (24 GB)".into()];
        m.node_binary = Some(PathBuf::from("/usr/bin/tenzro-node"));
        m.node_build = Some(NodeBuild {
            flavour: "cpu".into(),
            startup_ok: false,
            refusal: Some("cpu build on a gpu machine".into()),
        });
        let all = findings(&m, &Net::Checking, "https://rpc.tenzro.com");
        let n = all.iter().find(|x| x.label == "Node program").unwrap();
        assert_eq!(n.word, Word::Action);
        assert!(n.text.contains("CPU build"));
        assert!(n.fix[0].contains("CUDA"));
    }
}
