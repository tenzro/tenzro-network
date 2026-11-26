//! The host firewall in front of the node's UDP port.
//!
//! A node needs no inbound rule: it keeps outbound connections to its relays
//! and peers, and direct paths open by hole punching, which stateful host
//! firewalls let through because each side sends first. An inbound rule is
//! an optional improvement: peers can then open a direct path to the node
//! without punching first.
//!
//! Host firewalls that filter per application decide that:
//!
//! - Windows Defender Firewall blocks unsolicited inbound traffic by default.
//!   The first time a program listens, Windows asks whether to allow it; a
//!   dismissed prompt, or a user without administrator rights, leaves block
//!   rules for the program that win over any allow rule.
//! - The macOS application firewall, when turned on, refuses incoming
//!   connections to applications it was not told to allow.
//!
//! [`allow`], run when the operator asks (`tenzro-node doctor
//! --allow-inbound`, which the Windows task registration runs), adds one rule
//! for the node's UDP port and removes the block rules Windows left for the
//! node's binaries. It needs administrator rights, and says so when it lacks
//! them. Linux host firewalls are the operator's: the node only reports the
//! command to run.
//!
//! On Windows the rule is keyed to the port, not to the program. A versioned
//! install starts the node through the `current` junction, and the kernel
//! records the process under the release directory the junction resolves to
//! (`versions\<release>\bin\tenzro-node.exe`), which is what a program rule
//! is matched against; every update makes a new one, and `tenzro update` runs
//! without the rights to write a rule. A rule for the port holds across
//! updates. It covers the private profile only. On a network Windows files
//! as public (a café, an airport) inbound stays closed, since there the port
//! would be open to every machine on the network; on a domain network it
//! stays closed too, since a domain's firewall belongs to its administrator.
//! The node works on both through its relays and hole punching.

use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

/// The rule name the node's Windows firewall rule carries.
pub const WINDOWS_RULE_NAME: &str = "TenzroNode-UDP";

/// What the host firewall does with the node's port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallState {
    /// The firewall examined.
    pub system: String,
    /// Whether it is on, when that can be read.
    pub enabled: Option<bool>,
    /// Whether it lets peers reach the node's port, when that can be read.
    pub allows_node: Option<bool>,
    /// What was found, in plain words.
    pub detail: String,
    /// What to run to let peers in, when something is in the way.
    pub fix: Option<String>,
}

/// The UDP port the node's endpoint binds with `iroh`: the relay UDP port
/// while it serves the relay role, its bind port otherwise. `None` for a
/// private node, which binds no IP socket, and for a port left to the system
/// (`0`), which no rule can name ahead of time.
pub fn node_udp_port(iroh: &tenzro_iroh::TenzroIrohConfig) -> Option<u16> {
    if iroh.relay_only {
        return None;
    }
    let port = if iroh.relay.is_some() {
        iroh.relay_udp_port
    } else {
        iroh.bind_addr.port()
    };
    (port != 0).then_some(port)
}

/// The directory every release of the install `binary` belongs to: the root
/// of a versioned install (`<root>\current\bin` or `<root>\versions\<release>\bin`),
/// else the binary's own directory.
pub fn install_root(binary: &Path) -> std::path::PathBuf {
    let bin = binary.parent().unwrap_or(Path::new(""));
    let release = bin
        .parent()
        .filter(|_| bin.file_name().is_some_and(|n| n == "bin"));
    let named = |p: &Path, n: &str| p.file_name().is_some_and(|f| f == n);
    match release {
        Some(r) if named(r, "current") => r.parent().unwrap_or(r).to_path_buf(),
        Some(r) if r.parent().is_some_and(|v| named(v, "versions")) => {
            r.parent().and_then(Path::parent).unwrap_or(r).to_path_buf()
        }
        _ => bin.to_path_buf(),
    }
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

/// Whether this process may change the host firewall.
pub fn is_admin() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ],
        )
        .is_some_and(|o| o.trim().eq_ignore_ascii_case("true"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// `path` quoted for a PowerShell single-quoted string.
pub fn ps_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

/// The inbound block rules for any program under `root`: what a dismissed
/// prompt leaves, once per release directory it was shown for.
fn windows_block_rules(root: &Path) -> String {
    format!(
        "@(Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.Program -like ({r} + '\\*') }} | Get-NetFirewallRule | \
         Where-Object {{ $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' }})",
        r = ps_quote(root)
    )
}

/// The PowerShell that reads the firewall profiles, the categories of the
/// networks this machine is on, the ports of the node's rule and the block
/// rules for the node's binaries under `root`.
pub fn windows_query_script(root: &Path) -> String {
    format!(
        "$rule = Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue | Where-Object {{ $_.Enabled -eq 'True' }}; \
         'profiles=' + ((Get-NetFirewallProfile | ForEach-Object {{ \"$($_.Name):$($_.Enabled)\" }}) -join ','); \
         'networks=' + ((Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {{ \"$($_.NetworkCategory)\" }}) -join ','); \
         'rule=' + $(if ($rule) {{ (($rule | Get-NetFirewallPortFilter).LocalPort -join ',') }} else {{ '' }}); \
         'block=' + ((({blocks}) | ForEach-Object {{ $_.DisplayName }}) -join ';')",
        name = WINDOWS_RULE_NAME,
        blocks = windows_block_rules(root),
    )
}

/// The PowerShell that removes the inbound block rules for the node's
/// binaries under `root` and installs the node's one allow rule for UDP
/// `port`, replacing an earlier one.
pub fn windows_allow_script(root: &Path, port: u16) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; \
         foreach ($x in {blocks}) {{ 'removed block rule: ' + $x.DisplayName; $x | Remove-NetFirewallRule }}; \
         Remove-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue; \
         New-NetFirewallRule -Name '{name}' -DisplayName 'Tenzro node (UDP {port})' \
         -Description 'Lets Tenzro peers reach this node directly; keyed to the port, so it holds across updates. Added by tenzro-node doctor --allow-inbound.' \
         -Direction Inbound -Action Allow -Protocol UDP -LocalPort {port} -Profile Private | Out-Null; \
         'added rule {name}: inbound UDP {port} on the private profile; on public and domain networks inbound stays closed'",
        blocks = windows_block_rules(root),
        name = WINDOWS_RULE_NAME,
    )
}

/// Reads the Windows query script's output.
pub fn parse_windows_query(out: &str, port: u16) -> FirewallState {
    let field = |k: &str| {
        out.lines()
            .find_map(|l| l.trim().strip_prefix(k))
            .map(str::trim)
            .unwrap_or("")
    };
    let profiles: Vec<(String, bool)> = field("profiles=")
        .split(',')
        .filter_map(|p| p.split_once(':'))
        .map(|(n, e)| (n.to_string(), e.eq_ignore_ascii_case("true")))
        .collect();
    let enabled = if profiles.is_empty() {
        None
    } else {
        Some(profiles.iter().any(|(_, e)| *e))
    };
    let rule_ports: Vec<&str> = field("rule=")
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    let port_text = port.to_string();
    let rule_has_port = rule_ports.iter().any(|p| *p == port_text);
    let networks: Vec<&str> = field("networks=")
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    let no_private =
        !networks.is_empty() && !networks.iter().any(|n| n.eq_ignore_ascii_case("Private"));
    let blocks: Vec<&str> = field("block=")
        .split(';')
        .filter(|s| !s.is_empty())
        .collect();
    let fix =
        Some("from an administrator PowerShell: tenzro-node doctor --allow-inbound".to_string());
    let (allows_node, detail, fix) = match enabled {
        Some(false) => (
            Some(true),
            "Windows Defender Firewall is off on every profile".to_string(),
            None,
        ),
        _ if !blocks.is_empty() => (
            Some(false),
            format!(
                "block rules stop inbound traffic to the node: {}",
                blocks.join(", ")
            ),
            fix,
        ),
        _ if rule_has_port && no_private => (
            Some(false),
            format!(
                "the node's rule opens UDP {port} on private networks, and this machine is on no private network \
                 (public or domain only), where inbound stays closed; the node works through its relays and hole punching"
            ),
            None,
        ),
        _ if rule_has_port => (
            Some(true),
            format!("the node's rule lets peers reach it on UDP {port}"),
            None,
        ),
        Some(true) if !rule_ports.is_empty() => (
            Some(false),
            format!(
                "the node's rule opens UDP {} but the node binds UDP {port}",
                rule_ports.join(",")
            ),
            fix,
        ),
        Some(true) => (
            Some(false),
            format!("no rule lets peers reach the node on UDP {port}"),
            fix,
        ),
        None => (
            None,
            "the firewall profiles could not be read".to_string(),
            fix,
        ),
    };
    FirewallState {
        system: "Windows Defender Firewall".to_string(),
        enabled,
        allows_node,
        detail,
        fix,
    }
}

const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Reads `socketfilterfw`'s answers: the global state, block-all and the
/// binary's own entry.
pub fn parse_macos(global: &str, block_all: &str, app: &str, binary: &Path) -> FirewallState {
    let global = global.to_ascii_lowercase();
    let enabled = if global.contains("enabled") {
        Some(true)
    } else if global.contains("disabled") {
        Some(false)
    } else {
        None
    };
    let block_all = block_all.to_ascii_lowercase().contains("enabled");
    let app = app.to_ascii_lowercase();
    let fix = Some(format!(
        "sudo tenzro-node doctor --allow-inbound   (adds {} to the application firewall)",
        binary.display()
    ));
    let (allows_node, detail, fix) = match enabled {
        Some(false) => (Some(true), "the macOS application firewall is off".to_string(), None),
        _ if block_all => (
            Some(false),
            "the application firewall blocks all incoming connections; turn off \"Block all incoming connections\" in System Settings > Network > Firewall > Options".to_string(),
            None,
        ),
        _ if app.contains("permitted") => (Some(true), "the application firewall lets the node receive connections".to_string(), None),
        _ if app.contains("blocked") => (Some(false), "the application firewall blocks the node".to_string(), fix),
        Some(true) => (Some(false), "the application firewall is on and the node is not listed in it".to_string(), fix),
        None => (None, "the application firewall state could not be read".to_string(), fix),
    };
    FirewallState {
        system: "macOS application firewall".to_string(),
        enabled,
        allows_node,
        detail,
        fix,
    }
}

/// What the host firewall does with peers reaching `binary` on UDP `port`.
pub fn state(binary: &Path, port: u16) -> FirewallState {
    if cfg!(windows) {
        match run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &windows_query_script(&install_root(binary)),
            ],
        ) {
            Some(out) => parse_windows_query(&out, port),
            None => FirewallState {
                system: "Windows Defender Firewall".to_string(),
                enabled: None,
                allows_node: None,
                detail: "PowerShell could not be run to read the firewall".to_string(),
                fix: None,
            },
        }
    } else if cfg!(target_os = "macos") {
        let bin = binary.display().to_string();
        let global = run(SOCKETFILTERFW, &["--getglobalstate"]).unwrap_or_default();
        let block_all = run(SOCKETFILTERFW, &["--getblockall"]).unwrap_or_default();
        let app = run(SOCKETFILTERFW, &["--getappblocked", &bin]).unwrap_or_default();
        parse_macos(&global, &block_all, &app, binary)
    } else {
        FirewallState {
            system: "host firewall".to_string(),
            enabled: None,
            allows_node: None,
            detail: "the node does not manage Linux host firewalls".to_string(),
            fix: Some(format!(
                "if this host runs a firewall, allow inbound UDP {port}: `ufw allow {port}/udp`, or \
                 `firewall-cmd --permanent --add-port={port}/udp && firewall-cmd --reload`"
            )),
        }
    }
}

/// Lets peers reach `binary` on UDP `port` through the host firewall, with a
/// rule scoped to that binary and port. Returns what was done.
pub fn allow(binary: &Path, port: u16) -> Result<String, String> {
    if cfg!(not(any(windows, target_os = "macos"))) {
        return Err(state(binary, port).fix.unwrap_or_default());
    }
    if !is_admin() {
        return Err(if cfg!(windows) {
            "changing the firewall needs administrator rights: open PowerShell with \"Run as administrator\" and run \
             `tenzro-node doctor --allow-inbound` again"
                .to_string()
        } else {
            "changing the application firewall needs root: run `sudo tenzro-node doctor --allow-inbound`".to_string()
        });
    }
    if cfg!(windows) {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &windows_allow_script(&install_root(binary), port),
            ])
            .output()
            .map_err(|e| format!("run PowerShell: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() {
            return Err(format!(
                "{text}\n{}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(text)
    } else {
        let bin = binary.display().to_string();
        let current = state(binary, port);
        if current.enabled == Some(false) {
            return Ok("the macOS application firewall is off; nothing to change".to_string());
        }
        let mut done = Vec::new();
        for args in [["--add", bin.as_str()], ["--unblockapp", bin.as_str()]] {
            let out = run(SOCKETFILTERFW, &args).ok_or_else(|| format!("run {SOCKETFILTERFW}"))?;
            done.push(out.trim().to_string());
        }
        Ok(done.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_windows_rule_is_keyed_to_the_udp_port_on_the_private_profile() {
        let script = windows_allow_script(Path::new(r"C:\Users\op\.tenzro\install"), 9001);
        assert!(script.contains("-Protocol UDP -LocalPort 9001"));
        assert!(script.contains("-Profile Private |"));
        assert!(!script.contains("Domain") && !script.contains("-Profile Public"));
        assert!(script.contains("-Direction Inbound -Action Allow"));
        assert!(script.contains("-Name 'TenzroNode-UDP'"));
        // Keyed to the port: no program condition, so an update needs no new rule.
        assert!(!script.contains("-Program"));
        assert!(!script.contains("-LocalPort Any") && !script.contains("-Protocol Any"));
        // Block rules are removed for programs under the install root only.
        assert!(script.contains(r"$_.Program -like ('C:\Users\op\.tenzro\install' + '\*')"));
        assert!(script.contains("$_.Action -eq 'Block'"));
    }

    #[test]
    fn every_release_of_an_install_has_one_root() {
        let root = PathBuf::from("/home/op/.tenzro/install");
        for binary in [
            root.join("current").join("bin").join("tenzro-node.exe"),
            root.join("versions")
                .join("tenzro-node-windows-x86_64-cpu-0123456789ab")
                .join("bin")
                .join("tenzro-node.exe"),
        ] {
            assert_eq!(install_root(&binary), root, "{}", binary.display());
        }
        let flat = PathBuf::from("/opt/tenzro/bin/tenzro-node");
        assert_eq!(install_root(&flat), PathBuf::from("/opt/tenzro/bin"));
        let loose = PathBuf::from("/opt/tenzro/tenzro-node");
        assert_eq!(install_root(&loose), PathBuf::from("/opt/tenzro"));
    }

    #[test]
    fn the_port_is_the_one_the_endpoint_binds() {
        let mut iroh = tenzro_iroh::TenzroIrohConfig::default();
        assert_eq!(node_udp_port(&iroh), Some(9001));
        iroh.bind_addr.set_port(9100);
        assert_eq!(node_udp_port(&iroh), Some(9100));
        iroh.relay = Some(tenzro_iroh::RelayRoleConfig {
            bind_addr: "0.0.0.0:3340".parse().unwrap(),
            public_url: "https://relay.example".parse().unwrap(),
        });
        assert_eq!(
            node_udp_port(&iroh),
            Some(443),
            "the relay role binds its own port"
        );
        iroh.relay_udp_port = 28045;
        assert_eq!(node_udp_port(&iroh), Some(28045));
        iroh.relay = None;
        iroh.bind_addr.set_port(0);
        assert_eq!(
            node_udp_port(&iroh),
            None,
            "a port the system picks cannot be named in a rule"
        );
        iroh.bind_addr.set_port(9001);
        iroh.relay_only = true;
        assert_eq!(
            node_udp_port(&iroh),
            None,
            "a private node binds no IP socket"
        );
    }

    #[test]
    fn a_quote_in_the_path_cannot_end_the_powershell_string() {
        let q = ps_quote(Path::new(r"C:\it's\tenzro-node.exe"));
        assert_eq!(q, r"'C:\it''s\tenzro-node.exe'");
    }

    #[test]
    fn a_dismissed_windows_prompt_is_reported_as_blocking() {
        let s = parse_windows_query(
            "profiles=Domain:True,Private:True,Public:True\nnetworks=Private\nrule=9001\nblock=tenzro-node.exe;tenzro-node.exe\n",
            9001,
        );
        assert_eq!(
            s.allows_node,
            Some(false),
            "block rules win over allow rules"
        );
        assert!(
            s.fix
                .unwrap()
                .contains("tenzro-node doctor --allow-inbound")
        );
        let s = parse_windows_query(
            "profiles=Domain:True,Private:True,Public:True\nnetworks=Private,Public\nrule=9001\nblock=\n",
            9001,
        );
        assert_eq!(s.allows_node, Some(true));
        let s = parse_windows_query(
            "profiles=Domain:True,Private:True,Public:True\nnetworks=Private\nrule=\nblock=\n",
            9001,
        );
        assert_eq!(s.allows_node, Some(false));
        let s = parse_windows_query(
            "profiles=Domain:True,Private:True,Public:True\nnetworks=Private\nrule=9001\nblock=\n",
            443,
        );
        assert_eq!(s.allows_node, Some(false), "a rule for another port");
        assert!(
            s.detail
                .contains("opens UDP 9001 but the node binds UDP 443")
        );
        let s = parse_windows_query(
            "profiles=Domain:True,Private:True,Public:True\nnetworks=Public\nrule=9001\nblock=\n",
            9001,
        );
        assert_eq!(
            s.allows_node,
            Some(false),
            "inbound stays closed on a public network"
        );
        assert!(s.detail.contains("on no private network") && s.fix.is_none());
        let s = parse_windows_query(
            "profiles=Domain:True,Private:True,Public:True\nnetworks=DomainAuthenticated\nrule=9001\nblock=\n",
            9001,
        );
        assert_eq!(
            s.allows_node,
            Some(false),
            "inbound stays closed on a domain network"
        );
        let s = parse_windows_query(
            "profiles=Domain:False,Private:False,Public:False\nnetworks=Public\nrule=\nblock=\n",
            9001,
        );
        assert_eq!((s.enabled, s.allows_node), (Some(false), Some(true)));
    }

    #[test]
    fn the_macos_firewall_states_read_plainly() {
        let bin = Path::new("/usr/local/bin/tenzro-node");
        let off = parse_macos(
            "Firewall is disabled. (State = 0)",
            "Firewall has block all state set to disabled.",
            "",
            bin,
        );
        assert_eq!((off.enabled, off.allows_node), (Some(false), Some(true)));
        let unlisted = parse_macos(
            "Firewall is enabled. (State = 1)",
            "Firewall has block all state set to disabled.",
            "The application is not part of the firewall",
            bin,
        );
        assert_eq!(unlisted.allows_node, Some(false));
        assert!(
            unlisted
                .fix
                .unwrap()
                .starts_with("sudo tenzro-node doctor --allow-inbound")
        );
        let ok = parse_macos(
            "Firewall is enabled. (State = 1)",
            "disabled",
            "The application /usr/local/bin/tenzro-node is permitted",
            bin,
        );
        assert_eq!(ok.allows_node, Some(true));
        let all = parse_macos(
            "Firewall is enabled. (State = 1)",
            "Firewall has block all state set to enabled.",
            "",
            bin,
        );
        assert_eq!(all.allows_node, Some(false));
    }
}
