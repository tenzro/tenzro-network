//! Running the fixes the machine checklist carries.
//!
//! `tenzro doctor --fix` and `tenzro setup` read the same checklist
//! (`preflight::evaluate`); a check that the machine can repair for itself
//! carries its fix as data (`preflight::Fix`). This module lists what is
//! left to repair, asks for the operating system's permission once for all
//! the fixes that need it, and runs them in order.

use std::process::Command;

use anyhow::{Result, anyhow};

use crate::commands::preflight::{Check, Fix, Level};

/// One fix still to run, with the check it repairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step<'a> {
    pub label: &'a str,
    pub fix: &'a Fix,
}

/// What running one step came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub label: String,
    pub ok: bool,
    pub detail: String,
}

/// The fixes of every check that is not satisfied, in checklist order.
pub fn pending(checks: &[Check]) -> Vec<Step<'_>> {
    checks
        .iter()
        .filter(|c| c.level != Level::Pass)
        .filter_map(|c| {
            c.run.as_ref().map(|fix| Step {
                label: c.label,
                fix,
            })
        })
        .collect()
}

/// Whether running `steps` needs the operating system's permission prompt:
/// some step is elevated and the user is not already the administrator.
pub fn needs_prompt(steps: &[Step<'_>], is_root: bool) -> bool {
    !is_root && steps.iter().any(|s| s.fix.elevated)
}

/// The command line that runs `fix`: elevated through `sudo` (without a
/// second prompt: the one prompt came first) unless the user already is the
/// administrator.
pub fn command_line(fix: &Fix, is_root: bool) -> Vec<String> {
    if fix.elevated && !is_root {
        let mut line = vec!["sudo".to_string(), "-n".to_string()];
        line.extend(fix.argv.iter().cloned());
        line
    } else {
        fix.argv.clone()
    }
}

/// `text` quoted for a POSIX shell.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The one command line that runs every elevated step in `steps` under a
/// single request for the operating system's permission (polkit's `pkexec`):
/// for a client with no terminal, the helper the Control apps talk to.
/// `None` when no step needs it.
pub fn elevated_batch(steps: &[Step<'_>]) -> Option<Vec<String>> {
    let script = steps
        .iter()
        .filter(|s| s.fix.elevated)
        .map(|s| {
            s.fix
                .argv
                .iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join(" && ");
    (!script.is_empty()).then(|| vec!["pkexec".into(), "/bin/sh".into(), "-c".into(), script])
}

/// Run `steps` for a client with no terminal: the unelevated ones directly,
/// and all the elevated ones together under one `pkexec` prompt. Every step
/// gets an outcome. Without `pkexec` the elevated steps say so and run
/// nothing.
pub fn apply_without_terminal(steps: &[Step<'_>]) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    let run = |line: &[String]| -> std::result::Result<(), String> {
        let (program, args) = line.split_first().ok_or("an empty command")?;
        match Command::new(program).args(args).status() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("`{}` exited with {status}", line.join(" "))),
            Err(e) => Err(format!("`{}` could not run: {e}", line.join(" "))),
        }
    };
    for step in steps.iter().filter(|s| !s.fix.elevated) {
        let result = run(&step.fix.argv);
        outcomes.push(Outcome {
            label: step.label.to_string(),
            ok: result.is_ok(),
            detail: result.err().unwrap_or_else(|| step.fix.does.clone()),
        });
    }
    let elevated: Vec<&Step<'_>> = steps.iter().filter(|s| s.fix.elevated).collect();
    if let Some(batch) = elevated_batch(steps) {
        let result = if is_root() {
            run(&["/bin/sh".to_string(), "-c".to_string(), batch[3].clone()])
        } else if crate::commands::setup::which_on_path("pkexec").is_some() {
            run(&batch)
        } else {
            Err("this machine has no pkexec to ask for permission with; run the commands in a terminal".to_string())
        };
        for step in elevated {
            outcomes.push(Outcome {
                label: step.label.to_string(),
                ok: result.is_ok(),
                detail: result
                    .clone()
                    .err()
                    .unwrap_or_else(|| step.fix.does.clone()),
            });
        }
    }
    outcomes
}

/// The plan, one line per step, for the operator to read before any runs.
pub fn plan_text(steps: &[Step<'_>], is_root: bool) -> String {
    let mut out = String::new();
    for step in steps {
        out.push_str(&format!(
            "  {}: {} ({})\n",
            step.label,
            step.fix.does,
            command_line(step.fix, is_root).join(" ")
        ));
    }
    if needs_prompt(steps, is_root) {
        out.push_str(
            "  The steps marked sudo need your operating system's permission, asked once.\n",
        );
    }
    out
}

/// Whether this process runs as the administrator.
pub fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .is_some_and(|out| String::from_utf8_lossy(&out.stdout).trim() == "0")
}

/// Run `steps`: ask for the operating system's permission once if any step
/// needs it, then run each in order with the terminal attached. A step that
/// fails does not stop the ones after it; every outcome is returned.
pub fn apply(steps: &[Step<'_>]) -> Result<Vec<Outcome>> {
    let root = is_root();
    if needs_prompt(steps, root) {
        let granted = Command::new("sudo")
            .arg("-v")
            .status()
            .map_err(|e| anyhow!("could not ask for permission with sudo: {e}"))?;
        if !granted.success() {
            return Err(anyhow!(
                "the permission prompt was not accepted; nothing was changed"
            ));
        }
    }
    let mut outcomes = Vec::new();
    for step in steps {
        let line = command_line(step.fix, root);
        let (program, args) = line
            .split_first()
            .ok_or_else(|| anyhow!("the fix for {} names no command", step.label))?;
        let outcome = match Command::new(program).args(args).status() {
            Ok(status) if status.success() => Outcome {
                label: step.label.to_string(),
                ok: true,
                detail: step.fix.does.clone(),
            },
            Ok(status) => Outcome {
                label: step.label.to_string(),
                ok: false,
                detail: format!("`{}` exited with {status}", line.join(" ")),
            },
            Err(e) => Outcome {
                label: step.label.to_string(),
                ok: false,
                detail: format!("`{}` could not run: {e}", line.join(" ")),
            },
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(label: &'static str, level: Level, run: Option<Fix>) -> Check {
        Check {
            label,
            level,
            detail: String::new(),
            fix: Vec::new(),
            run,
        }
    }

    fn checks() -> Vec<Check> {
        vec![
            check(
                "Clock",
                Level::Pass,
                Some(Fix::new("sync", true, &["timedatectl", "set-ntp", "true"])),
            ),
            check(
                "tpm2-tools",
                Level::Warn,
                Some(Fix::new(
                    "install",
                    true,
                    &["apt-get", "install", "-y", "tpm2-tools"],
                )),
            ),
            check(
                "TPM keys",
                Level::Todo,
                Some(Fix::new(
                    "provision",
                    false,
                    &["tenzro-node", "tpm", "provision"],
                )),
            ),
            check("tenzro-node", Level::Fail, None),
        ]
    }

    #[test]
    fn only_unsatisfied_checks_with_a_fix_are_pending() {
        let checks = checks();
        let steps = pending(&checks);
        let labels: Vec<&str> = steps.iter().map(|s| s.label).collect();
        assert_eq!(labels, ["tpm2-tools", "TPM keys"]);
    }

    #[test]
    fn one_prompt_covers_every_elevated_step() {
        let checks = checks();
        let steps = pending(&checks);
        assert!(needs_prompt(&steps, false));
        assert!(!needs_prompt(&steps, true));
        assert!(
            !needs_prompt(&steps[1..], false),
            "the unelevated step alone asks nothing"
        );
    }

    #[test]
    fn an_elevated_step_runs_through_sudo_without_a_second_prompt() {
        let checks = checks();
        let steps = pending(&checks);
        assert_eq!(
            command_line(steps[0].fix, false),
            ["sudo", "-n", "apt-get", "install", "-y", "tpm2-tools"]
        );
        assert_eq!(
            command_line(steps[0].fix, true),
            ["apt-get", "install", "-y", "tpm2-tools"]
        );
        assert_eq!(
            command_line(steps[1].fix, false),
            ["tenzro-node", "tpm", "provision"]
        );
    }

    #[test]
    fn every_elevated_step_runs_under_one_pkexec_request() {
        let checks = checks();
        let steps = pending(&checks);
        let batch = elevated_batch(&steps).unwrap();
        assert_eq!(&batch[..3], ["pkexec", "/bin/sh", "-c"]);
        assert_eq!(batch[3], "'apt-get' 'install' '-y' 'tpm2-tools'");
        assert_eq!(elevated_batch(&steps[1..]), None);
        let odd = Fix::new("x", true, &["echo", "it's"]);
        let quoted = vec![Step {
            label: "x",
            fix: &odd,
        }];
        assert_eq!(elevated_batch(&quoted).unwrap()[3], "'echo' 'it'\\''s'");
    }

    #[test]
    fn the_plan_names_each_step_and_says_when_the_permission_is_asked() {
        let checks = checks();
        let steps = pending(&checks);
        let plan = plan_text(&steps, false);
        assert!(plan.contains("tpm2-tools: install (sudo -n apt-get install -y tpm2-tools)"));
        assert!(plan.contains("TPM keys: provision (tenzro-node tpm provision)"));
        assert!(plan.contains("asked once"));
        assert!(!plan_text(&steps[1..], false).contains("asked once"));
    }
}
