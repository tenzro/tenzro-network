//! Machine preflight for the hardware identity.
//!
//! A node's identity keys live in the machine's TPM 2.0 (Linux, Windows) or
//! Secure Enclave (macOS), and the node refuses to start without them. On
//! Linux and Windows the keys are created once per machine by
//! `tenzro-node tpm provision`, by a user who can open `/dev/tpmrm0`.
//!
//! This module looks at the machine before any of that is attempted and turns
//! each missing prerequisite into a check with the exact lines that fix it.
//! The probe (`Facts::probe`) reads the machine; `evaluate` turns facts into
//! checks and touches nothing, so every verdict is testable.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

/// The persistent handles `tenzro-node tpm provision` creates: the storage
/// root, the machine attestation key and the node identity key.
const PROVISIONED_HANDLES: [&str; 3] = ["0x81018000", "0x81018001", "0x81018100"];

/// The TPM tools the autonomous operator path shells out to.
const TPM_TOOLS: [&str; 4] = [
    "tpm2_create",
    "tpm2_createprimary",
    "tpm2_load",
    "tpm2_unseal",
];

/// Outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Satisfied.
    Pass,
    /// Not satisfied, and not blocking.
    Warn,
    /// Not satisfied, and nothing further can work until it is.
    Fail,
    /// A step that has to run, and can be run from here.
    Todo,
}

/// What fixes a check, as data: `tenzro doctor --fix` runs it and setup
/// offers it, so a finding and its fix never differ between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    /// The program and its arguments.
    pub argv: Vec<String>,
    /// Whether it needs the operating system's permission prompt (sudo).
    pub elevated: bool,
    /// What running it does, in one plain line.
    pub does: String,
}

impl Fix {
    pub fn new(does: impl Into<String>, elevated: bool, argv: &[&str]) -> Self {
        Self {
            argv: argv.iter().map(|a| a.to_string()).collect(),
            elevated,
            does: does.into(),
        }
    }
}

/// One line of the checklist and the lines that fix it.
#[derive(Debug, Clone)]
pub struct Check {
    pub label: &'static str,
    pub level: Level,
    pub detail: String,
    /// Commands or instructions that fix this check, one per line.
    pub fix: Vec<String>,
    /// The fix the machine can run for itself, when there is one.
    pub run: Option<Fix>,
}

impl Check {
    fn new(label: &'static str, level: Level, detail: impl Into<String>) -> Self {
        Self {
            label,
            level,
            detail: detail.into(),
            fix: Vec::new(),
            run: None,
        }
    }

    fn fix(mut self, lines: &[&str]) -> Self {
        self.fix = lines.iter().map(|l| l.to_string()).collect();
        self
    }

    fn run(mut self, fix: Option<Fix>) -> Self {
        self.run = fix;
        self
    }
}

/// The package managers a fix may use, in the order they are tried.
const PACKAGE_MANAGERS: [&str; 5] = ["apt-get", "dnf", "yum", "pacman", "zypper"];

/// The unit a `tenzro setup` service install writes.
pub const SERVICE_UNIT: &str = "tenzro-node";

/// The fix that installs `packages` with the first of `managers` this machine
/// has, if it has one.
pub fn install_fix(managers: &[String], packages: &[&str]) -> Option<Fix> {
    let manager: &str = PACKAGE_MANAGERS
        .iter()
        .copied()
        .find(|m| managers.iter().any(|have| have == m))?;
    let mut argv: Vec<&str> = match manager {
        "apt-get" | "dnf" | "yum" => vec![manager, "install", "-y"],
        "pacman" => vec![manager, "-S", "--noconfirm"],
        _ => vec![manager, "--non-interactive", "install"],
    };
    argv.extend_from_slice(packages);
    Some(Fix::new(
        format!("install {} with {manager}", packages.join(", ")),
        true,
        &argv,
    ))
}

/// Whether the node's service unit is installed and starts at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    pub installed: bool,
    pub enabled: bool,
}

/// How the TPM is named to the operator: Linux has a device file, Windows
/// reaches the TPM through TPM Base Services and has no `/dev` at all.
pub fn tpm_device_label(windows: bool) -> &'static str {
    if windows {
        "the Windows TPM (TPM Base Services)"
    } else {
        "/dev/tpmrm0"
    }
}

/// Label of the check that stands for the provisioning step.
pub const KEYS_LABEL: &str = "TPM keys";

/// Which family of machine root this host has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Root {
    Tpm,
    SecureEnclave,
}

/// What the machine looks like, as read by `Facts::probe`.
#[derive(Debug, Clone)]
pub struct Facts {
    pub root: Root,
    pub secure_enclave: bool,
    pub tpm_device: bool,
    /// Why `/dev/tpmrm0` could not be opened read-write, when it exists and
    /// could not.
    pub tpm_open_error: Option<String>,
    pub user: String,
    pub groups: Vec<String>,
    pub missing_tools: Vec<String>,
    pub node_binary: Option<PathBuf>,
    /// Whether the three persistent handles are present. `None` when that
    /// could not be read (no `tpm2_getcap`, or the device is not usable yet).
    pub keys_provisioned: Option<bool>,
    /// The package managers this machine has.
    pub package_managers: Vec<String>,
    /// Whether the clock is kept in step with a time server. `None` when the
    /// machine cannot say.
    pub clock_synced: Option<bool>,
    /// The node's service unit. `None` where the machine has no systemd.
    pub service: Option<Service>,
}

impl Facts {
    /// Read the machine. Opens `/dev/tpmrm0` once to learn whether this user
    /// may, and, only when it may and `tpm2_getcap` is installed, lists the
    /// persistent handles (a read of the TPM's handle table).
    pub fn probe(secure_enclave: bool) -> Self {
        let root = if cfg!(target_os = "macos") {
            Root::SecureEnclave
        } else {
            Root::Tpm
        };
        let tpm_device = if cfg!(windows) {
            // TPM Base Services answers for the TPM; there is no device file.
            tenzro_device_key::signer::platform_backend().is_some()
        } else {
            Path::new("/dev/tpmrm0").exists()
        };
        let tpm_open_error = if tpm_device && !cfg!(windows) {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tpmrm0")
                .err()
                .map(|e| e.to_string())
        } else {
            None
        };
        let user = std::env::var("USER").unwrap_or_default();
        let groups = command_stdout("id", &["-nG"])
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        let missing_tools = TPM_TOOLS
            .iter()
            .filter(|t| crate::commands::setup::which_on_path(t).is_none())
            .map(|t| t.to_string())
            .collect();
        let keys_provisioned = if tpm_device
            && tpm_open_error.is_none()
            && crate::commands::setup::which_on_path("tpm2_getcap").is_some()
        {
            command_stdout("tpm2_getcap", &["handles-persistent"])
                .map(|out| PROVISIONED_HANDLES.iter().all(|h| out.contains(h)))
        } else {
            None
        };
        let package_managers = PACKAGE_MANAGERS
            .iter()
            .filter(|m| crate::commands::setup::which_on_path(m).is_some())
            .map(|m| m.to_string())
            .collect();
        let clock_synced =
            command_stdout("timedatectl", &["show", "-p", "NTPSynchronized", "--value"])
                .map(|out| out.trim() == "yes");
        let service = command_stdout(
            "systemctl",
            &[
                "list-unit-files",
                &format!("{SERVICE_UNIT}.service"),
                "--no-legend",
            ],
        )
        .map(|out| Service {
            installed: !out.trim().is_empty(),
            enabled: command_stdout("systemctl", &["is-enabled", SERVICE_UNIT])
                .is_some_and(|state| state.trim() == "enabled"),
        });
        Self {
            root,
            secure_enclave,
            tpm_device,
            tpm_open_error,
            user,
            groups,
            missing_tools,
            node_binary: crate::commands::setup::locate_node_binary(),
            keys_provisioned,
            package_managers,
            clock_synced,
            service,
        }
    }
}

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Turn facts into the checklist. Pure.
pub fn evaluate(f: &Facts) -> Vec<Check> {
    let mut checks = Vec::new();

    checks.push(match &f.node_binary {
        Some(p) => Check::new("tenzro-node", Level::Pass, p.display().to_string()),
        None => Check::new(
            "tenzro-node",
            Level::Fail,
            "the node binary was not found next to `tenzro` or on PATH",
        )
        .fix(&[
            "Install the release archive for this machine; it ships bin/tenzro-node beside bin/tenzro.",
            "Then put both on PATH, for example: sudo install -m 0755 bin/tenzro-node bin/tenzro /usr/local/bin/",
        ]),
    });

    match f.clock_synced {
        Some(true) => checks.push(Check::new(
            "Clock",
            Level::Pass,
            "synchronised with a time server",
        )),
        Some(false) => checks.push(
            Check::new(
                "Clock",
                Level::Warn,
                "not synchronised: signed tokens, certificates and consensus depend on the time",
            )
            .fix(&["sudo timedatectl set-ntp true"])
            .run(Some(Fix::new(
                "switch time synchronisation on",
                true,
                &["timedatectl", "set-ntp", "true"],
            ))),
        ),
        None => {}
    }
    match f.service {
        Some(Service {
            installed: true,
            enabled: true,
        }) => checks.push(Check::new(
            "Service",
            Level::Pass,
            "installed and starts at boot",
        )),
        Some(Service {
            installed: true,
            enabled: false,
        }) => checks.push(
            Check::new(
                "Service",
                Level::Warn,
                "installed, but does not start at boot",
            )
            .fix(&["sudo systemctl enable tenzro-node"])
            .run(Some(Fix::new(
                "start the node's service at boot",
                true,
                &["systemctl", "enable", SERVICE_UNIT],
            ))),
        ),
        Some(Service {
            installed: false, ..
        }) => checks.push(
            Check::new(
                "Service",
                Level::Warn,
                "the node is not installed as a service, so it will not start at boot",
            )
            .fix(&["`tenzro setup` writes the service unit and shows the lines that install it."]),
        ),
        None => {}
    }

    if f.root == Root::SecureEnclave {
        checks.push(if f.secure_enclave {
            Check::new(
                "Secure Enclave",
                Level::Pass,
                "holds this machine's keys; there is no provisioning step on macOS",
            )
        } else {
            Check::new(
                "Secure Enclave",
                Level::Fail,
                "no usable Secure Enclave was detected on this Mac",
            )
            .fix(&["A Mac with a Secure Enclave (Apple silicon, or an Intel Mac with a T2 chip) is required."])
        });
        return checks;
    }

    if !f.tpm_device {
        checks.push(
            Check::new(
                "TPM 2.0",
                Level::Fail,
                format!("no TPM found ({})", tpm_device_label(cfg!(windows))),
            )
            .fix(&[
                "Turn the TPM on in the firmware settings (it may be called fTPM, PTT or Security Device), then reboot.",
                "No TPM at all (a Raspberry Pi, for example): the identity key can live in another machine's TPM; see docs/NODE.md, \"Raspberry Pi and other edge devices\".",
            ]),
        );
        return checks;
    }
    checks.push(Check::new(
        "TPM 2.0",
        Level::Pass,
        tpm_device_label(cfg!(windows)),
    ));

    match &f.tpm_open_error {
        None => checks.push(Check::new(
            "TPM access",
            Level::Pass,
            format!(
                "{} may open {}",
                display_user(&f.user),
                tpm_device_label(cfg!(windows))
            ),
        )),
        Some(err) => {
            let in_tss = f.groups.iter().any(|g| g == "tss");
            let mut c = Check::new(
                "TPM access",
                Level::Fail,
                format!(
                    "{} cannot open {}: {err}",
                    display_user(&f.user),
                    tpm_device_label(cfg!(windows))
                ),
            );
            if !in_tss && !f.user.is_empty() {
                c.run = Some(Fix::new(
                    format!(
                        "add {} to the tss group (it applies at the next login)",
                        f.user
                    ),
                    true,
                    &["usermod", "-aG", "tss", &f.user],
                ));
            }
            c.fix = if in_tss {
                vec![
                    "You are in the tss group already; check the device's group and mode: ls -l /dev/tpmrm0".to_string(),
                    "It should be group tss, mode 0660. If not, install tpm2-tss (it ships the udev rule).".to_string(),
                ]
            } else {
                vec![
                    format!("sudo usermod -aG tss {}", display_user(&f.user)),
                    "Log out and back in so the group applies (or run: newgrp tss), then re-run this command.".to_string(),
                ]
            };
            checks.push(c);
        }
    }

    // tpm2-tools are a Linux package; Windows has nothing to install.
    checks.extend((!cfg!(windows)).then(|| {
        if f.missing_tools.is_empty() {
            Check::new("tpm2-tools", Level::Pass, "installed")
        } else {
            Check::new(
                "tpm2-tools",
                Level::Warn,
                format!(
                    "missing: {}. The autonomous operator choice needs them.",
                    f.missing_tools.join(", ")
                ),
            )
            .fix(&[
                "Debian or Ubuntu: sudo apt install tpm2-tools",
                "Fedora or RHEL: sudo dnf install tpm2-tools",
            ])
            .run(install_fix(&f.package_managers, &["tpm2-tools"]))
        }
    }));

    let ready = f.node_binary.is_some() && f.tpm_open_error.is_none();
    checks.push(match f.keys_provisioned {
        Some(true) => Check::new(
            KEYS_LABEL,
            Level::Pass,
            "storage root, attestation key and identity key are in place",
        ),
        _ if !ready => Check::new(
            KEYS_LABEL,
            Level::Warn,
            "created once per machine by `tenzro-node tpm provision`, after the items above are fixed",
        ),
        Some(false) => Check::new(
            KEYS_LABEL,
            Level::Todo,
            "not created yet; `tenzro-node tpm provision` creates them once",
        )
        .fix(&["tenzro-node tpm provision"])
        .run(provision_fix(f)),
        None => Check::new(
            KEYS_LABEL,
            Level::Todo,
            "`tenzro-node tpm provision` creates them once; running it again keeps keys already in place",
        )
        .fix(&["tenzro-node tpm provision"])
        .run(provision_fix(f)),
    });

    checks
}

/// The fix that creates the TPM keys, with the node binary this machine has.
fn provision_fix(f: &Facts) -> Option<Fix> {
    let node = f.node_binary.as_ref()?.display().to_string();
    Some(Fix::new(
        "create this machine's TPM keys (once; keys already in place are kept)",
        false,
        &[&node, "tpm", "provision"],
    ))
}

fn display_user(user: &str) -> &str {
    if user.is_empty() { "this user" } else { user }
}

/// Whether any check blocks everything after it.
pub fn blocked(checks: &[Check]) -> bool {
    checks.iter().any(|c| c.level == Level::Fail)
}

/// Whether the provisioning step is still to run.
pub fn needs_provision(checks: &[Check]) -> bool {
    checks
        .iter()
        .any(|c| c.label == KEYS_LABEL && c.level == Level::Todo)
}

/// One rendered line of the checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A check and its verdict.
    Check(Level, String),
    /// One line of the fix for the check above it.
    Fix(String),
}

/// Render the checklist through `emit`, so the caller draws each line in its
/// own style. Fix lines follow only the checks that are not satisfied.
pub fn render(checks: &[Check], mut emit: impl FnMut(Line)) {
    for c in checks {
        emit(Line::Check(c.level, format!("{}: {}", c.label, c.detail)));
        if c.level != Level::Pass {
            for line in &c.fix {
                emit(Line::Fix(line.clone()));
            }
        }
    }
}

/// The checklist as plain text, for an error message.
pub fn report_text(checks: &[Check]) -> String {
    let mut out = String::new();
    render(checks, |line| match line {
        Line::Check(level, text) => {
            let mark = match level {
                Level::Pass => "ok",
                Level::Warn => "note",
                Level::Fail => "FAIL",
                Level::Todo => "todo",
            };
            out.push_str(&format!("  [{mark}] {text}\n"));
        }
        Line::Fix(text) => out.push_str(&format!("        {text}\n")),
    });
    out
}

/// Run `tenzro-node tpm provision`, with the terminal attached so its
/// output (the machine DID and node account) reaches the operator.
pub fn provision(node_binary: &Path) -> Result<()> {
    let status = std::process::Command::new(node_binary)
        .args(["tpm", "provision"])
        .status()
        .map_err(|e| anyhow!("could not run {}: {e}", node_binary.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "`tenzro-node tpm provision` exited with {status}; fix what it printed and run it again"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux() -> Facts {
        Facts {
            root: Root::Tpm,
            secure_enclave: false,
            tpm_device: true,
            tpm_open_error: None,
            user: "ada".into(),
            groups: vec!["ada".into(), "tss".into()],
            missing_tools: Vec::new(),
            node_binary: Some(PathBuf::from("/usr/local/bin/tenzro-node")),
            keys_provisioned: Some(false),
            package_managers: vec!["apt-get".into()],
            clock_synced: Some(true),
            service: Some(Service {
                installed: true,
                enabled: true,
            }),
        }
    }

    fn level_of(checks: &[Check], label: &str) -> Level {
        checks.iter().find(|c| c.label == label).unwrap().level
    }

    #[test]
    fn a_ready_machine_has_only_the_provisioning_step_left() {
        let checks = evaluate(&linux());
        assert!(!blocked(&checks));
        assert!(needs_provision(&checks));
        assert_eq!(level_of(&checks, "TPM access"), Level::Pass);
    }

    #[test]
    fn provisioned_keys_leave_nothing_to_do() {
        let mut f = linux();
        f.keys_provisioned = Some(true);
        assert!(!needs_provision(&evaluate(&f)));
    }

    #[test]
    fn unreadable_key_state_still_offers_the_idempotent_step() {
        let mut f = linux();
        f.keys_provisioned = None;
        assert!(needs_provision(&evaluate(&f)));
    }

    #[test]
    fn no_tpm_device_blocks_and_names_the_firmware_and_the_remote_tpm_route() {
        let mut f = linux();
        f.tpm_device = false;
        let checks = evaluate(&f);
        assert!(blocked(&checks));
        let tpm = checks.iter().find(|c| c.label == "TPM 2.0").unwrap();
        assert!(tpm.fix.iter().any(|l| l.contains("firmware")));
        assert!(tpm.fix.iter().any(|l| l.contains("docs/NODE.md")));
        assert!(!needs_provision(&checks));
    }

    #[test]
    fn windows_never_hears_about_a_dev_node() {
        assert!(!tpm_device_label(true).contains("/dev"));
        assert!(tpm_device_label(true).contains("TPM Base Services"));
        assert_eq!(tpm_device_label(false), "/dev/tpmrm0");
    }

    #[test]
    fn a_user_outside_the_tss_group_is_told_the_exact_command() {
        let mut f = linux();
        f.groups = vec!["ada".into()];
        f.tpm_open_error = Some("Permission denied (os error 13)".into());
        let checks = evaluate(&f);
        assert!(blocked(&checks));
        let access = checks.iter().find(|c| c.label == "TPM access").unwrap();
        assert_eq!(access.fix[0], "sudo usermod -aG tss ada");
        assert!(!needs_provision(&checks));
    }

    #[test]
    fn a_tss_member_who_still_cannot_open_the_device_gets_the_device_check() {
        let mut f = linux();
        f.tpm_open_error = Some("Permission denied (os error 13)".into());
        let access = evaluate(&f)
            .into_iter()
            .find(|c| c.label == "TPM access")
            .unwrap();
        assert!(access.fix[0].contains("ls -l /dev/tpmrm0"));
    }

    #[test]
    fn missing_tpm_tools_warn_without_blocking() {
        let mut f = linux();
        f.missing_tools = vec!["tpm2_create".into()];
        let checks = evaluate(&f);
        assert_eq!(level_of(&checks, "tpm2-tools"), Level::Warn);
        assert!(!blocked(&checks));
    }

    #[test]
    fn a_missing_node_binary_blocks_provisioning() {
        let mut f = linux();
        f.node_binary = None;
        let checks = evaluate(&f);
        assert!(blocked(&checks));
        assert!(!needs_provision(&checks));
    }

    #[test]
    fn a_mac_needs_its_secure_enclave_and_no_provisioning() {
        let mut f = linux();
        f.root = Root::SecureEnclave;
        f.secure_enclave = true;
        let checks = evaluate(&f);
        assert!(!blocked(&checks));
        assert!(!needs_provision(&checks));
        f.secure_enclave = false;
        assert!(blocked(&evaluate(&f)));
    }

    #[test]
    fn render_prints_fix_lines_only_for_unsatisfied_checks() {
        let mut lines = Vec::new();
        render(&evaluate(&linux()), |l| lines.push(l));
        assert!(lines.contains(&Line::Fix("tenzro-node tpm provision".into())));
        assert!(
            !lines
                .iter()
                .any(|l| matches!(l, Line::Fix(s) if s.contains("usermod")))
        );
    }

    fn run_of<'a>(checks: &'a [Check], label: &str) -> Option<&'a Fix> {
        checks
            .iter()
            .find(|c| c.label == label)
            .unwrap()
            .run
            .as_ref()
    }

    #[test]
    fn a_package_manager_is_chosen_in_a_fixed_order() {
        let have = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let fix = install_fix(&have(&["dnf", "apt-get"]), &["tpm2-tools"]).unwrap();
        assert_eq!(fix.argv, ["apt-get", "install", "-y", "tpm2-tools"]);
        assert!(fix.elevated);
        let fix = install_fix(&have(&["pacman"]), &["tpm2-tools"]).unwrap();
        assert_eq!(fix.argv, ["pacman", "-S", "--noconfirm", "tpm2-tools"]);
        let fix = install_fix(&have(&["zypper"]), &["tpm2-tools"]).unwrap();
        assert_eq!(fix.argv[..3], ["zypper", "--non-interactive", "install"]);
        assert_eq!(install_fix(&have(&[]), &["tpm2-tools"]), None);
    }

    #[test]
    fn missing_tools_carry_a_fix_the_machine_can_run() {
        let mut f = linux();
        f.missing_tools = vec!["tpm2_create".into()];
        let checks = evaluate(&f);
        let fix = run_of(&checks, "tpm2-tools").unwrap();
        assert_eq!(fix.argv.last().map(String::as_str), Some("tpm2-tools"));
        f.package_managers.clear();
        assert!(run_of(&evaluate(&f), "tpm2-tools").is_none());
    }

    #[test]
    fn a_user_outside_the_tss_group_gets_the_command_as_a_fix() {
        let mut f = linux();
        f.groups = vec!["ada".into()];
        f.tpm_open_error = Some("Permission denied (os error 13)".into());
        let checks = evaluate(&f);
        let fix = run_of(&checks, "TPM access").unwrap();
        assert_eq!(fix.argv, ["usermod", "-aG", "tss", "ada"]);
        assert!(fix.elevated);
        // A tss member's problem is the device, which no command here fixes.
        f.groups.push("tss".into());
        assert!(run_of(&evaluate(&f), "TPM access").is_none());
    }

    #[test]
    fn the_provisioning_step_is_a_fix_that_needs_no_prompt() {
        let checks = evaluate(&linux());
        let fix = run_of(&checks, KEYS_LABEL).unwrap();
        assert_eq!(fix.argv, ["/usr/local/bin/tenzro-node", "tpm", "provision"]);
        assert!(!fix.elevated);
    }

    #[test]
    fn a_clock_out_of_step_is_a_warning_with_its_fix() {
        let mut f = linux();
        f.clock_synced = Some(false);
        let checks = evaluate(&f);
        assert_eq!(level_of(&checks, "Clock"), Level::Warn);
        assert!(!blocked(&checks));
        assert_eq!(
            run_of(&checks, "Clock").unwrap().argv,
            ["timedatectl", "set-ntp", "true"]
        );
        f.clock_synced = None;
        assert!(evaluate(&f).iter().all(|c| c.label != "Clock"));
    }

    #[test]
    fn the_service_check_tells_not_installed_from_not_started_at_boot() {
        let mut f = linux();
        f.service = Some(Service {
            installed: true,
            enabled: false,
        });
        let checks = evaluate(&f);
        assert_eq!(level_of(&checks, "Service"), Level::Warn);
        assert_eq!(
            run_of(&checks, "Service").unwrap().argv,
            ["systemctl", "enable", "tenzro-node"]
        );
        f.service = Some(Service {
            installed: false,
            enabled: false,
        });
        let checks = evaluate(&f);
        assert_eq!(level_of(&checks, "Service"), Level::Warn);
        assert!(run_of(&checks, "Service").is_none());
        f.service = None;
        assert!(evaluate(&f).iter().all(|c| c.label != "Service"));
    }
}
