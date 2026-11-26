//! `control_service`: start, stop, restart or repair the node service.
//!
//! The helper runs the same commands the terminal runs, through the service
//! `tenzro setup` installs. A systemd unit is the administrator's: the
//! terminal changes it with `sudo systemctl`, which has no terminal to ask on
//! here, so the helper runs `systemctl` as this user instead and systemd asks
//! polkit, whose agent in the desktop session shows the one prompt for an
//! administrator. Where no agent answers, the action is refused with the
//! command to run. A launchd agent is this user's own and is started and
//! stopped here. A
//! running node under a systemd unit is restarted by asking the node itself
//! (`tenzro_restartNode`); its unit starts it again. Stop and restart end a
//! running node, so each needs `confirm` set to its name.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;

use super::{INVALID_PARAMS, REFUSED, error};
use crate::commands::service::{self, NodeService, Switch};

const NOT_CONFIRMED: &str =
    "This ends the running node: send it again with confirm set to the action's name";

const SET_UP_FIRST: &str =
    "No node service is installed here: run `tenzro setup --apply` in a terminal to install it";

pub(super) type Run = Arc<dyn Fn(&[Vec<String>]) -> Result<()> + Send + Sync>;

/// The node service of one machine.
pub(crate) struct Service {
    os: &'static str,
    home: PathBuf,
    in_place: Arc<dyn Fn() -> bool + Send + Sync>,
    running: Arc<dyn Fn() -> NodeService + Send + Sync>,
    run: Run,
}

impl Service {
    /// This machine's, run with the commands the terminal runs.
    pub(crate) fn here() -> Self {
        let os = std::env::consts::OS;
        Self {
            os,
            home: tenzro_types::paths::home_dir().unwrap_or_default(),
            in_place: Arc::new(move || service::in_place(os)),
            running: Arc::new(move || service::installed(os)),
            run: Arc::new(|steps| service::run_steps(steps, "the node service was not changed")),
        }
    }

    /// `control_service {action, confirm?}`: the commands are run, and the
    /// answer is how the node then stands.
    pub(crate) async fn act(&self, params: &Value) -> Result<(), Value> {
        let action = params.get("action").and_then(Value::as_str);
        let confirmed = |name: &str| params.get("confirm").and_then(Value::as_str) == Some(name);
        let (in_place, running) = (self.in_place.clone(), self.running.clone());
        let (in_place, running) = tokio::task::spawn_blocking(move || (in_place(), running()))
            .await
            .map_err(|_| error(REFUSED, "The node service could not be read"))?;
        let steps = match action {
            Some(name @ ("stop" | "restart")) if !confirmed(name) => {
                return Err(error(REFUSED, NOT_CONFIRMED));
            }
            Some("repair") => {
                return Err(error(
                    REFUSED,
                    "Putting the node service back in place is `tenzro setup --apply`, run in a terminal",
                ));
            }
            Some("start" | "stop" | "restart") if !in_place => {
                return Err(error(REFUSED, SET_UP_FIRST));
            }
            Some("start") => self.switch(Switch::Start)?,
            Some("stop") => self.switch(Switch::Stop)?,
            Some("restart") => match running {
                NodeService::None => {
                    return Err(error(
                        REFUSED,
                        "The node service is not running: start it instead",
                    ));
                }
                running => service::restart_steps(&running)
                    .map_err(|e| error(REFUSED, &format!("{e:#}")))?,
            },
            _ => {
                return Err(error(
                    INVALID_PARAMS,
                    "action must be start, stop, restart or repair",
                ));
            }
        };
        let run = self.run.clone();
        if let Some(command) = administered(&steps) {
            let left = || {
                error(
                    REFUSED,
                    &format!(
                        "This needs this machine's administrator: run `{command}` in a terminal"
                    ),
                )
            };
            let asked = through_polkit(&steps).ok_or_else(left)?;
            return match tokio::task::spawn_blocking(move || run(&asked)).await {
                Ok(Ok(())) => Ok(()),
                _ => Err(left()),
            };
        }
        tokio::task::spawn_blocking(move || run(&steps))
            .await
            .map_err(|_| error(REFUSED, "The node service was not changed"))?
            .map_err(|e| error(REFUSED, &format!("{e:#}")))
    }

    /// Whether the node runs under a systemd unit, which only the
    /// administrator may restart: then the node restarts itself.
    pub(crate) async fn under_systemd(&self) -> bool {
        let running = self.running.clone();
        tokio::task::spawn_blocking(move || matches!(running(), NodeService::Systemd(_)))
            .await
            .unwrap_or(false)
    }

    fn switch(&self, switch: Switch) -> Result<Vec<Vec<String>>, Value> {
        service::switch_steps(self.os, &self.home, switch)
            .map_err(|e| error(REFUSED, &format!("{e:#}")))
    }
}

/// The steps with `sudo systemctl` run as this user, for systemd to ask
/// polkit; `None` when a step needs the administrator for anything else.
pub(super) fn through_polkit(steps: &[Vec<String>]) -> Option<Vec<Vec<String>>> {
    steps
        .iter()
        .map(|step| match step.split_first() {
            Some((sudo, rest)) if sudo == "sudo" => rest
                .first()
                .is_some_and(|program| program == "systemctl")
                .then(|| rest.to_vec()),
            _ => Some(step.clone()),
        })
        .collect()
}

/// The steps as one command, when any of them needs the administrator.
fn administered(steps: &[Vec<String>]) -> Option<String> {
    steps
        .iter()
        .any(|step| step.first().is_some_and(|program| program == "sudo"))
        .then(|| {
            steps
                .iter()
                .map(|step| step.join(" "))
                .collect::<Vec<_>>()
                .join(" && ")
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    /// A machine with `os`, its service in place or not and running as
    /// `running`; the commands it is asked to run are kept in `ran`.
    pub(crate) fn on(
        os: &'static str,
        in_place: bool,
        running: NodeService,
        ran: Arc<Mutex<Vec<String>>>,
    ) -> Service {
        Service {
            os,
            home: PathBuf::from("/home/op"),
            in_place: Arc::new(move || in_place),
            running: Arc::new(move || running.clone()),
            run: Arc::new(move |steps| {
                let mut ran = ran.lock().unwrap();
                ran.extend(steps.iter().map(|step| step.join(" ")));
                Ok(())
            }),
        }
    }

    /// A Linux machine whose systemd unit polkit will not let this user
    /// change: no agent answered, or the administrator said no.
    fn refused_by_polkit(ran: Arc<Mutex<Vec<String>>>) -> Service {
        let unit = PathBuf::from("/etc/systemd/system/tenzro-node.service");
        Service {
            run: Arc::new(move |steps| {
                ran.lock()
                    .unwrap()
                    .extend(steps.iter().map(|step| step.join(" ")));
                anyhow::bail!("Interactive authentication required.")
            }),
            ..on("linux", true, NodeService::Systemd(unit), Arc::default())
        }
    }

    fn message(refusal: &Value) -> (i64, String) {
        (
            refusal["code"].as_i64().unwrap(),
            refusal["message"].as_str().unwrap().to_string(),
        )
    }

    #[tokio::test]
    async fn a_launchd_agent_is_started_stopped_and_restarted_here() {
        let ran = Arc::new(Mutex::new(Vec::new()));
        let plist = PathBuf::from("/home/op/Library/LaunchAgents/network.tenzro.node.plist");
        let service = on(
            "macos",
            true,
            NodeService::Launchd(plist.clone()),
            ran.clone(),
        );
        service.act(&json!({ "action": "start" })).await.unwrap();
        service
            .act(&json!({ "action": "stop", "confirm": "stop" }))
            .await
            .unwrap();
        service
            .act(&json!({ "action": "restart", "confirm": "restart" }))
            .await
            .unwrap();
        let p = plist.display();
        assert_eq!(
            *ran.lock().unwrap(),
            vec![
                format!("launchctl load -w {p}"),
                format!("launchctl unload {p}"),
                format!("launchctl unload {p}"),
                format!("launchctl load -w {p}"),
            ]
        );
    }

    #[tokio::test]
    async fn a_systemd_unit_is_changed_through_polkit_without_sudo() {
        let ran = Arc::new(Mutex::new(Vec::new()));
        let unit = PathBuf::from("/etc/systemd/system/tenzro-node.service");
        let service = on("linux", true, NodeService::Systemd(unit), ran.clone());
        service.act(&json!({ "action": "start" })).await.unwrap();
        service
            .act(&json!({ "action": "stop", "confirm": "stop" }))
            .await
            .unwrap();
        assert_eq!(
            *ran.lock().unwrap(),
            vec!["systemctl start tenzro-node", "systemctl stop tenzro-node"]
        );
    }

    #[tokio::test]
    async fn a_systemd_unit_polkit_refuses_is_left_to_the_administrator_with_the_command() {
        let ran = Arc::new(Mutex::new(Vec::new()));
        let service = refused_by_polkit(ran.clone());
        for (asked, command) in [
            (
                json!({ "action": "start" }),
                "sudo systemctl start tenzro-node",
            ),
            (
                json!({ "action": "stop", "confirm": "stop" }),
                "sudo systemctl stop tenzro-node",
            ),
            (
                json!({ "action": "restart", "confirm": "restart" }),
                "sudo systemctl restart tenzro-node",
            ),
        ] {
            let refusal = service.act(&asked).await.unwrap_err();
            assert_eq!(
                message(&refusal),
                (
                    REFUSED,
                    format!(
                        "This needs this machine's administrator: run `{command}` in a terminal"
                    )
                ),
                "{asked}"
            );
        }
        assert!(
            ran.lock()
                .unwrap()
                .iter()
                .all(|step| step.starts_with("systemctl ")),
            "only systemctl, as this user"
        );
    }

    #[tokio::test]
    async fn ending_the_node_needs_its_name_and_a_missing_service_is_set_up_first() {
        let ran = Arc::new(Mutex::new(Vec::new()));
        let service = on("macos", true, NodeService::None, ran.clone());
        for asked in [
            json!({ "action": "stop" }),
            json!({ "action": "restart", "confirm": "stop" }),
            json!({ "action": "stop", "confirm": true }),
        ] {
            let refusal = service.act(&asked).await.unwrap_err();
            assert_eq!(
                message(&refusal),
                (REFUSED, NOT_CONFIRMED.into()),
                "{asked}"
            );
        }
        let refusal = service
            .act(&json!({ "action": "restart", "confirm": "restart" }))
            .await
            .unwrap_err();
        assert_eq!(
            message(&refusal).1,
            "The node service is not running: start it instead"
        );
        let refusal = service
            .act(&json!({ "action": "repair" }))
            .await
            .unwrap_err();
        assert!(message(&refusal).1.contains("tenzro setup --apply"));
        let refusal = service
            .act(&json!({ "action": "reload" }))
            .await
            .unwrap_err();
        assert_eq!(refusal["code"], INVALID_PARAMS);

        let bare = on("linux", false, NodeService::None, ran.clone());
        let refusal = bare.act(&json!({ "action": "start" })).await.unwrap_err();
        assert_eq!(message(&refusal), (REFUSED, SET_UP_FIRST.into()));
        assert!(ran.lock().unwrap().is_empty(), "nothing ran");
    }

    #[tokio::test]
    async fn a_systemd_node_that_runs_is_restarted_by_asking_it() {
        let node = crate::rpc::nonce_and_chain_id_tests::node_answering(&[(
            "tenzro_restartNode",
            r#"{"restarting":true}"#,
        )])
        .await;
        let ran = Arc::new(Mutex::new(Vec::new()));
        let unit = PathBuf::from("/etc/systemd/system/tenzro-node.service");
        let helper = super::super::tests::helper_serving(
            &node,
            on("linux", true, NodeService::Systemd(unit), ran.clone()),
        );
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"control_service","params":{"action":"restart","confirm":"restart"}}"#;
        let answer: Value =
            serde_json::from_str(&helper.answer(line.as_bytes()).await.unwrap()).unwrap();
        assert_eq!(
            answer["result"],
            json!({ "service": "running", "reason": null })
        );
        assert!(ran.lock().unwrap().is_empty(), "no command ran");
    }
}
