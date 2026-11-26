//! `control_update`: the update `tenzro update` runs, for an app.
//!
//! `check` asks the release channel. `apply` runs the whole update in the
//! background, as `tenzro update --yes` does, and every call made while it
//! runs reports how far it got. `rollback` puts the previous release back.
//! Both change this machine, so each needs `confirm` set to its own name.
//! A systemd unit belongs to the administrator, so the node is asked to
//! restart itself through its own `tenzro_restartNode`; a launchd agent is
//! this user's and is restarted as the terminal restarts it.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};

use super::{INVALID_PARAMS, REFUSED, error};
use crate::commands::service;
use crate::commands::update::Availability;
use crate::commands::update::install::RolledBack;
use crate::commands::update::run::{self, Outcome, Stage};

/// How long the release channel has to answer a check.
const CHECK_WAIT: Duration = Duration::from_secs(60);

const NOT_CONFIRMED: &str =
    "This changes the installed release: send it again with confirm set to the action's name";

type Boxed<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type Watch = Arc<dyn Fn(Stage) + Send + Sync>;
type Look = Box<dyn Fn() -> Boxed<Result<(String, Availability)>> + Send + Sync>;
/// Runs the whole update on the blocking thread it is called on, driving it
/// there with the runtime's handle: the update flow is not `Send`, so it
/// cannot be spawned onto the runtime's workers.
type Install = Box<dyn Fn(Watch) -> Result<Outcome> + Send + Sync>;
type RollBack = Box<dyn Fn() -> Result<RolledBack> + Send + Sync>;

/// How the last action stands.
struct Progress {
    running: bool,
    state: &'static str,
    current: Option<String>,
    latest: Option<String>,
    reason: Option<String>,
}

impl Progress {
    fn data(&self) -> Value {
        json!({
            "current": self.current,
            "latest": self.latest,
            "state": self.state,
            "reason": self.reason,
        })
    }

    fn end(&mut self, state: &'static str, reason: Option<String>) {
        self.running = false;
        self.state = state;
        self.reason = reason;
    }
}

/// The updates of this machine's release, one at a time.
pub(crate) struct Updates {
    look: Look,
    install: Install,
    roll_back: RollBack,
    progress: Mutex<Progress>,
}

impl Updates {
    /// Updates of the release this `tenzro` runs from, with `node` asked for
    /// its roles and its health.
    pub(crate) fn here(node: &str) -> Arc<Self> {
        let (looked, installing) = (node.to_string(), node.to_string());
        Self::with(
            Box::new(move || {
                let node = looked.clone();
                Box::pin(async move { run::look(&node).await })
            }),
            Box::new(move |watch| {
                tokio::runtime::Handle::current().block_on(run::unattended(&installing, &*watch))
            }),
            Box::new(run::roll_back_here),
        )
    }

    fn with(look: Look, install: Install, roll_back: RollBack) -> Arc<Self> {
        Arc::new(Self {
            look,
            install,
            roll_back,
            progress: Mutex::new(Progress {
                running: false,
                state: "idle",
                current: None,
                latest: None,
                reason: None,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Progress> {
        self.progress.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `control_update {action, confirm?}`.
    pub(crate) async fn call(self: &Arc<Self>, params: &Value) -> Result<Value, Value> {
        let action = params.get("action").and_then(Value::as_str);
        let confirmed = |name: &str| params.get("confirm").and_then(Value::as_str) == Some(name);
        let running = self.lock().running;
        match action {
            Some("check" | "apply") if running => Ok(self.lock().data()),
            Some("rollback") if running => Err(error(
                REFUSED,
                "An update is running: roll back once it has ended",
            )),
            Some("check") => Ok(self.check().await),
            Some(name @ ("apply" | "rollback")) if !confirmed(name) => {
                Err(error(REFUSED, NOT_CONFIRMED))
            }
            Some("apply") => Ok(self.apply()),
            Some("rollback") => Ok(self.roll_back().await),
            _ => Err(error(
                INVALID_PARAMS,
                "action must be check, apply or rollback",
            )),
        }
    }

    async fn check(&self) -> Value {
        let found = tokio::time::timeout(CHECK_WAIT, (self.look)()).await;
        let mut progress = self.lock();
        match found {
            Ok(Ok((current, offered))) => {
                let (latest, reason) = match offered {
                    Availability::UpToDate => (current.clone(), None),
                    Availability::Available { release, .. } => (release, None),
                    Availability::Held {
                        release,
                        description,
                        ..
                    } => {
                        let why = held(&release, &description);
                        (release, Some(why))
                    }
                };
                progress.current = Some(current);
                progress.latest = Some(latest);
                progress.end("idle", reason);
            }
            Ok(Err(e)) => progress.end("failed", Some(format!("{e:#}"))),
            Err(_) => progress.end("failed", Some("The release channel did not answer.".into())),
        }
        progress.data()
    }

    /// Starts the whole update and answers at once; it goes on in the
    /// background.
    fn apply(self: &Arc<Self>) -> Value {
        let mut progress = self.lock();
        progress.running = true;
        progress.state = "downloading";
        progress.reason = None;
        let me = self.clone();
        tokio::task::spawn_blocking(move || {
            let watching = me.clone();
            let watch: Watch = Arc::new(move |stage| {
                watching.lock().state = match stage {
                    Stage::Downloading => "downloading",
                    Stage::Restarting => "restarting",
                    Stage::Verifying => "verifying",
                };
            });
            let outcome = (me.install)(watch);
            me.finish(outcome);
        });
        progress.data()
    }

    fn finish(&self, outcome: Result<Outcome>) {
        let mut progress = self.lock();
        let installed = |progress: &mut Progress| {
            if progress.latest.is_some() {
                progress.current = progress.latest.clone();
            }
        };
        match outcome {
            Ok(Outcome::UpToDate) => {
                progress.end("done", Some("This machine runs the newest release.".into()))
            }
            Ok(Outcome::Held) => progress.end(
                "idle",
                Some("The newest release is not one an update installs in place.".into()),
            ),
            Ok(Outcome::NeedsYes { .. } | Outcome::Declined) => {
                progress.end("failed", Some("Nothing was installed.".into()))
            }
            Ok(Outcome::Installed(why)) => {
                installed(&mut progress);
                progress.end(
                    "done",
                    Some(format!(
                        "Installed. The node was not restarted: {}",
                        why.says()
                    )),
                )
            }
            Ok(Outcome::Healthy) => {
                installed(&mut progress);
                progress.end("done", None)
            }
            Ok(Outcome::RolledBack {
                reason,
                previous_runs,
            }) => {
                let again = if previous_runs {
                    String::new()
                } else {
                    format!(" {}", restart_hint())
                };
                progress.end(
                    "failed",
                    Some(format!(
                        "Rolled back to the previous release: {reason}.{again}"
                    )),
                )
            }
            Err(e) => progress.end("failed", Some(format!("{e:#}{}", needs_root(&e)))),
        }
    }

    async fn roll_back(self: &Arc<Self>) -> Value {
        let me = self.clone();
        let done = tokio::task::spawn_blocking(move || (me.roll_back)()).await;
        let mut progress = self.lock();
        match done {
            Ok(Ok(done)) => {
                progress.current = None;
                progress.end(
                    "done",
                    Some(format!(
                        "Restored the previous release ({}). {}",
                        done.restored.join(", "),
                        restart_hint()
                    )),
                )
            }
            Ok(Err(e)) => progress.end("failed", Some(format!("{e:#}{}", needs_root(&e)))),
            Err(_) => progress.end("failed", Some("The rollback stopped unfinished.".into())),
        }
        progress.data()
    }
}

/// Why a newer release is not installed by an update.
fn held(release: &str, description: &str) -> String {
    format!("Tenzro {release} is not installed by an update in place: {description}")
}

/// How the operator runs the release now in place.
fn restart_hint() -> String {
    match service::restart_command(&service::installed(std::env::consts::OS)) {
        Some(command) => format!("Restart the node to run it: {command}"),
        None => "Restart the node the way it was started to run it.".into(),
    }
}

/// What to add when `e` came from a file only the administrator may change.
fn needs_root(e: &anyhow::Error) -> &'static str {
    let denied = e.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
    });
    if denied {
        " The install belongs to this machine's administrator: run `sudo tenzro update --yes` in a terminal."
    } else {
        ""
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::commands::update::run::Why;
    use tokio::sync::Notify;

    fn release_of(available: &str) -> Look {
        let available = available.to_string();
        Box::new(move || {
            let available = available.clone();
            Box::pin(async move {
                Ok((
                    "0.2.2".to_string(),
                    Availability::Available {
                        release: available,
                        manifest_version: 7,
                        description: "fixes".into(),
                    },
                ))
            })
        })
    }

    fn no_install() -> Install {
        Box::new(|_| Ok(Outcome::UpToDate))
    }

    fn no_rollback() -> RollBack {
        Box::new(|| Ok(RolledBack { restored: vec![] }))
    }

    /// Updates that find nothing to do and change nothing.
    pub(crate) fn idle() -> Arc<Updates> {
        Updates::with(
            Box::new(|| Box::pin(async { Ok(("0.2.2".to_string(), Availability::UpToDate)) })),
            no_install(),
            no_rollback(),
        )
    }

    fn message(refusal: &Value) -> (i64, &str) {
        (
            refusal["code"].as_i64().unwrap(),
            refusal["message"].as_str().unwrap(),
        )
    }

    /// The progress once it is no longer `running`.
    async fn ended(updates: &Arc<Updates>) -> Value {
        for _ in 0..500 {
            if !updates.lock().running {
                return updates.lock().data();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the update never ended");
    }

    #[tokio::test]
    async fn a_check_says_what_runs_here_and_what_the_channel_offers() {
        let updates = Updates::with(release_of("0.2.9"), no_install(), no_rollback());
        let found = updates.call(&json!({ "action": "check" })).await.unwrap();
        assert_eq!(
            found,
            json!({ "current": "0.2.2", "latest": "0.2.9", "state": "idle", "reason": null })
        );

        let current = idle().call(&json!({ "action": "check" })).await.unwrap();
        assert_eq!(current["latest"], "0.2.2");

        let held = Updates::with(
            Box::new(|| {
                Box::pin(async {
                    Ok((
                        "0.2.2".to_string(),
                        Availability::Held {
                            release: "0.3.0".into(),
                            class: crate::commands::update::manifest::Class::C1,
                            description: "a new genesis".into(),
                        },
                    ))
                })
            }),
            no_install(),
            no_rollback(),
        );
        let found = held.call(&json!({ "action": "check" })).await.unwrap();
        assert_eq!(found["latest"], "0.3.0");
        assert_eq!(found["reason"], held_text());
    }

    fn held_text() -> String {
        held("0.3.0", "a new genesis")
    }

    #[tokio::test]
    async fn apply_and_rollback_change_nothing_unless_confirmed_by_name() {
        let updates = idle();
        for asked in [
            json!({ "action": "apply" }),
            json!({ "action": "apply", "confirm": "rollback" }),
            json!({ "action": "rollback", "confirm": true }),
            json!({ "action": "rollback", "confirm": "apply" }),
        ] {
            let refusal = updates.call(&asked).await.unwrap_err();
            assert_eq!(message(&refusal), (REFUSED, NOT_CONFIRMED), "{asked}");
        }
        assert_eq!(updates.lock().state, "idle");
        let refusal = updates
            .call(&json!({ "action": "upgrade" }))
            .await
            .unwrap_err();
        assert_eq!(refusal["code"], INVALID_PARAMS);
        let refusal = updates.call(&json!({})).await.unwrap_err();
        assert_eq!(refusal["code"], INVALID_PARAMS);
    }

    #[tokio::test]
    async fn an_update_reports_each_stage_while_it_runs_and_how_it_ended() {
        let go = Arc::new(Notify::new());
        let at = Arc::new(Notify::new());
        let (to_go, reached) = (go.clone(), at.clone());
        let updates = Updates::with(
            release_of("0.2.9"),
            Box::new(move |watch| {
                let (go, at) = (to_go.clone(), reached.clone());
                tokio::runtime::Handle::current().block_on(async move {
                    for stage in [Stage::Downloading, Stage::Restarting, Stage::Verifying] {
                        watch(stage);
                        at.notify_one();
                        go.notified().await;
                    }
                    Ok(Outcome::Healthy)
                })
            }),
            no_rollback(),
        );
        updates.call(&json!({ "action": "check" })).await.unwrap();
        let started = updates
            .call(&json!({ "action": "apply", "confirm": "apply" }))
            .await
            .unwrap();
        assert_eq!(started["state"], "downloading");

        for stage in ["downloading", "restarting", "verifying"] {
            at.notified().await;
            let now = updates.call(&json!({ "action": "check" })).await.unwrap();
            assert_eq!(now["state"], stage);
            // A second apply while one runs starts nothing; neither may a rollback.
            let again = updates
                .call(&json!({ "action": "apply", "confirm": "apply" }))
                .await
                .unwrap();
            assert_eq!(again["state"], stage);
            let refusal = updates
                .call(&json!({ "action": "rollback", "confirm": "rollback" }))
                .await
                .unwrap_err();
            assert_eq!(refusal["code"], REFUSED);
            go.notify_one();
        }

        let end = ended(&updates).await;
        assert_eq!(
            end,
            json!({ "current": "0.2.9", "latest": "0.2.9", "state": "done", "reason": null })
        );
    }

    #[tokio::test]
    async fn an_install_left_unrestarted_says_what_remains() {
        let why = Why::ServesRole;
        let says = why.says();
        let updates = Updates::with(
            release_of("0.2.9"),
            Box::new(move |_| Ok(Outcome::Installed(why.clone()))),
            no_rollback(),
        );
        updates
            .call(&json!({ "action": "apply", "confirm": "apply" }))
            .await
            .unwrap();
        let end = ended(&updates).await;
        assert_eq!(end["state"], "done");
        assert_eq!(
            end["reason"],
            format!("Installed. The node was not restarted: {says}")
        );
    }

    #[tokio::test]
    async fn an_install_that_fails_says_why_and_a_denied_one_who_may_run_it() {
        let updates = Updates::with(
            release_of("0.2.9"),
            Box::new(|_| {
                let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
                Err(anyhow::Error::new(denied).context("install into /opt/tenzro"))
            }),
            no_rollback(),
        );
        updates
            .call(&json!({ "action": "apply", "confirm": "apply" }))
            .await
            .unwrap();
        let end = ended(&updates).await;
        assert_eq!(end["state"], "failed");
        let reason = end["reason"].as_str().unwrap();
        assert!(reason.starts_with("install into /opt/tenzro: "), "{reason}");
        assert!(reason.ends_with("run `sudo tenzro update --yes` in a terminal."));
    }

    #[tokio::test]
    async fn a_rollback_restores_the_previous_release_and_says_how_to_run_it() {
        let updates = Updates::with(
            release_of("0.2.9"),
            no_install(),
            Box::new(|| {
                Ok(RolledBack {
                    restored: vec!["tenzro-node".into(), "tenzro".into()],
                })
            }),
        );
        let done = updates
            .call(&json!({ "action": "rollback", "confirm": "rollback" }))
            .await
            .unwrap();
        assert_eq!(done["state"], "done");
        let reason = done["reason"].as_str().unwrap();
        assert!(
            reason.starts_with(
                "Restored the previous release (tenzro-node, tenzro). Restart the node"
            ),
            "{reason}"
        );
    }

    #[tokio::test]
    async fn the_helper_answers_control_update() {
        let helper =
            super::super::tests::helper("http://127.0.0.1:1", super::super::tests::machine());
        let answer = helper
            .answer(br#"{"jsonrpc":"2.0","id":5,"method":"control_update","params":{"action":"check"}}"#)
            .await
            .unwrap();
        let answer: Value = serde_json::from_str(&answer).unwrap();
        assert_eq!(answer["result"]["state"], "idle");
        assert_eq!(answer["result"]["current"], "0.2.2");
    }
}
