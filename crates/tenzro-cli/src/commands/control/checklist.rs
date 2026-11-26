//! `control_checklist` and `control_fix`: the machine checklist `tenzro
//! doctor` and `tenzro setup` read, for a client that is not the terminal.
//!
//! `control_checklist` answers each check with its verdict, the lines that
//! say what to do, and the fix the machine can run for itself (the command,
//! whether it needs the operating system's permission, and what it does).
//! `control_fix` runs the fixes of the checks it names, or of every check
//! that is not met when it names none. The fixes that need permission run
//! together under one request for it, the platform's own prompt, since this
//! helper has no terminal to ask in.

use serde_json::{Value, json};

use super::{INVALID_PARAMS, REFUSED, error};
use crate::commands::fixes;
use crate::commands::preflight::{self, Check, Level};

/// A check as JSON.
fn check_data(check: &Check) -> Value {
    json!({
        "label": check.label,
        "status": match check.level {
            Level::Pass => "ok",
            Level::Warn => "note",
            Level::Fail => "fail",
            Level::Todo => "todo",
        },
        "detail": check.detail,
        "fix": check.fix,
        "run": check.run.as_ref().map(|f| json!({
            "argv": f.argv,
            "elevated": f.elevated,
            "does": f.does,
        })),
    })
}

/// The checklist as JSON.
pub(crate) fn checklist_data(checks: &[Check]) -> Value {
    json!({
        "checks": checks.iter().map(check_data).collect::<Vec<_>>(),
        "blocked": preflight::blocked(checks),
    })
}

/// The checks of this machine, read now.
async fn read_checks() -> Vec<Check> {
    let secure_enclave = cfg!(target_os = "macos");
    tokio::task::spawn_blocking(move || {
        preflight::evaluate(&preflight::Facts::probe(secure_enclave))
    })
    .await
    .unwrap_or_default()
}

/// `control_checklist`.
pub(crate) async fn checklist() -> Value {
    checklist_data(&read_checks().await)
}

/// The labels a `control_fix` call names: `labels`, a list of check labels;
/// none means every check that is not met.
fn named(params: &Value) -> std::result::Result<Vec<String>, Value> {
    match params.get("labels") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(labels)) => labels
            .iter()
            .map(|l| {
                l.as_str().map(str::to_string).ok_or_else(|| {
                    error(
                        INVALID_PARAMS,
                        "'labels' is a list of check labels, as text",
                    )
                })
            })
            .collect(),
        Some(_) => Err(error(
            INVALID_PARAMS,
            "'labels' is a list of check labels, as text",
        )),
    }
}

/// `control_fix`: run the fixes, then read the checklist again.
pub(crate) async fn fix(params: &Value) -> std::result::Result<Value, Value> {
    let labels = named(params)?;
    let checks = read_checks().await;
    for label in &labels {
        match checks.iter().find(|c| c.label == label) {
            None => return Err(error(INVALID_PARAMS, &format!("no check named '{label}'"))),
            Some(c) if c.run.is_none() => {
                return Err(error(
                    REFUSED,
                    &format!("'{label}' has no fix this machine can run; its lines say what to do"),
                ));
            }
            Some(_) => {}
        }
    }
    let outcomes = {
        let steps: Vec<_> = fixes::pending(&checks)
            .into_iter()
            .filter(|s| labels.is_empty() || labels.iter().any(|l| l == s.label))
            .collect();
        let owned: Vec<(String, preflight::Fix)> = steps
            .iter()
            .map(|s| (s.label.to_string(), s.fix.clone()))
            .collect();
        tokio::task::spawn_blocking(move || {
            let steps: Vec<_> = owned
                .iter()
                .map(|(label, fix)| fixes::Step { label, fix })
                .collect();
            fixes::apply_without_terminal(&steps)
        })
        .await
        .map_err(|e| error(REFUSED, &format!("the fixes did not finish: {e}")))?
    };
    Ok(json!({
        "outcomes": outcomes.iter().map(|o| json!({
            "label": o.label,
            "ok": o.ok,
            "detail": o.detail,
        })).collect::<Vec<_>>(),
        "checklist": checklist_data(&read_checks().await),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(label: &'static str, level: Level, run: Option<preflight::Fix>) -> Check {
        Check {
            label,
            level,
            detail: "d".into(),
            fix: vec!["do it".into()],
            run,
        }
    }

    #[test]
    fn a_check_is_data_with_its_fix_when_it_has_one() {
        let fix = preflight::Fix::new("sync the clock", true, &["timedatectl", "set-ntp", "true"]);
        let data = checklist_data(&[
            check("Clock", Level::Warn, Some(fix)),
            check("tenzro-node", Level::Fail, None),
        ]);
        assert_eq!(data["blocked"], true);
        assert_eq!(data["checks"][0]["status"], "note");
        assert_eq!(data["checks"][0]["run"]["elevated"], true);
        assert_eq!(
            data["checks"][0]["run"]["argv"],
            json!(["timedatectl", "set-ntp", "true"])
        );
        assert_eq!(data["checks"][1]["status"], "fail");
        assert!(data["checks"][1]["run"].is_null());
    }

    #[test]
    fn the_labels_to_fix_are_a_list_of_text_or_absent() {
        assert_eq!(named(&json!({})).unwrap(), Vec::<String>::new());
        assert_eq!(named(&json!({ "labels": ["Clock"] })).unwrap(), ["Clock"]);
        assert_eq!(
            named(&json!({ "labels": "Clock" })).unwrap_err()["code"],
            INVALID_PARAMS
        );
        assert_eq!(
            named(&json!({ "labels": [1] })).unwrap_err()["code"],
            INVALID_PARAMS
        );
    }
}
