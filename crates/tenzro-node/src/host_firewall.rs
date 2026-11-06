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
//! [`allow`], run only when the operator asks (`tenzro-node doctor
//! --allow-inbound`), adds one rule scoped to the node binary and its UDP
//! port (on Windows, for the private and public profiles; a domain
//! network's rules belong to its administrator) and removes the block rules
//! Windows left for that binary. It needs administrator rights, and says so
//! when it lacks them. Linux host firewalls are the operator's: the node only
//! reports the command to run.

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

/// The PowerShell that reads the firewall profiles and the inbound rules
/// that name `binary`.
pub fn windows_query_script(binary: &Path) -> String {
    format!(
        "$r = @(Get-NetFirewallApplicationFilter -Program {p} -ErrorAction SilentlyContinue | Get-NetFirewallRule | \
         Where-Object {{ $_.Direction -eq 'Inbound' -and $_.Enabled -eq 'True' }}); \
         'profiles=' + ((Get-NetFirewallProfile | ForEach-Object {{ \"$($_.Name):$($_.Enabled)\" }}) -join ','); \
         'allow=' + @($r | Where-Object {{ $_.Action -eq 'Allow' }}).Count; \
         'block=' + (@($r | Where-Object {{ $_.Action -eq 'Block' }} | ForEach-Object {{ $_.DisplayName }}) -join ';')",
        p = ps_quote(binary)
    )
}

/// The PowerShell that removes the inbound block rules for `binary` and
/// installs the node's one allow rule for UDP `port`.
pub fn windows_allow_script(binary: &Path, port: u16) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $b = @(Get-NetFirewallApplicationFilter -Program {p} -ErrorAction SilentlyContinue | Get-NetFirewallRule | \
         Where-Object {{ $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' }}); \
         foreach ($x in $b) {{ 'removed block rule: ' + $x.DisplayName; $x | Remove-NetFirewallRule }}; \
         Remove-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue; \
         New-NetFirewallRule -Name '{name}' -DisplayName 'Tenzro node (UDP {port})' \
         -Description 'Lets Tenzro peers reach this node directly. Added by tenzro-node doctor --allow-inbound.' \
         -Direction Inbound -Action Allow -Program {p} -Protocol UDP -LocalPort {port} -Profile Private,Public | Out-Null; \
         'added rule {name}: inbound UDP {port} for ' + {p} + ' on the private and public profiles'",
        p = ps_quote(binary),
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
    let allows: usize = field("allow=").parse().unwrap_or(0);
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
        _ if allows > 0 => (
            Some(true),
            format!("an allow rule lets peers reach the node (UDP {port})"),
            None,
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
                &windows_query_script(binary),
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
                &windows_allow_script(binary, port),
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
    fn the_windows_rule_is_scoped_to_the_binary_and_its_udp_port() {
        let bin = PathBuf::from(r"C:\Program Files\Tenzro\tenzro-node.exe");
        let script = windows_allow_script(&bin, 9001);
        assert!(script.contains(r"-Program 'C:\Program Files\Tenzro\tenzro-node.exe'"));
        assert!(script.contains("-Protocol UDP -LocalPort 9001"));
        assert!(script.contains("-Profile Private,Public"));
        assert!(script.contains("-Direction Inbound -Action Allow"));
        assert!(!script.contains("-LocalPort Any") && !script.contains("-Protocol Any"));
        // Only block rules for this binary are removed.
        assert!(script.contains(
            "Get-NetFirewallApplicationFilter -Program 'C:\\Program Files\\Tenzro\\tenzro-node.exe'"
        ));
    }

    #[test]
    fn a_quote_in_the_path_cannot_end_the_powershell_string() {
        let q = ps_quote(Path::new(r"C:\it's\tenzro-node.exe"));
        assert_eq!(q, r"'C:\it''s\tenzro-node.exe'");
    }

    #[test]
    fn a_dismissed_windows_prompt_is_reported_as_blocking() {
        let s = parse_windows_query(
            "profiles=Domain:True,Private:True,Public:True\nallow=1\nblock=tenzro-node.exe;tenzro-node.exe\n",
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
            "profiles=Domain:True,Private:True,Public:True\nallow=1\nblock=\n",
            9001,
        );
        assert_eq!(s.allows_node, Some(true));
        let s = parse_windows_query(
            "profiles=Domain:True,Private:True,Public:True\nallow=0\nblock=\n",
            9001,
        );
        assert_eq!(s.allows_node, Some(false));
        let s = parse_windows_query(
            "profiles=Domain:False,Private:False,Public:False\nallow=0\nblock=\n",
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
