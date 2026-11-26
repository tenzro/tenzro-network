//! `control_keyHolders` and `control_useKeyHolder`: the key holder a machine
//! without its own TPM keeps its node's keys through.
//!
//! A key holder runs on this machine, on a Unix socket, and carries the
//! node's signing to a provider machine's TPM under a grant the operator's
//! passkey approved. The helper offers the one this machine was set up with
//! and the one at the place setup starts it, and asks each whether it
//! answers and holds a grant. Key holders are not found anywhere else:
//! when none answers here the answer says so and how to start one.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::{INVALID_PARAMS, REFUSED, error};
use crate::config::PersistedConfig;

/// How long a key holder has to answer whether it holds a grant.
const HOLDER_WAIT: Duration = Duration::from_secs(5);

/// What a key holder said: whether it answered, and why the node cannot use
/// it yet when it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Heard {
    pub answers: bool,
    pub wanted: Option<String>,
}

type Probe = Arc<dyn Fn(&Path) -> Heard + Send + Sync>;

/// The key holders this machine may use.
pub(crate) struct KeyHolders {
    /// Where setup starts the key holder.
    usual: PathBuf,
    /// The name a grant on this machine is asked under, unless one was given.
    machine: String,
    load: Box<dyn Fn() -> PersistedConfig + Send + Sync>,
    keep: Box<dyn Fn(&PersistedConfig) -> anyhow::Result<()> + Send + Sync>,
    probe: Probe,
}

impl KeyHolders {
    /// This machine's, kept in the CLI's configuration as setup keeps it.
    pub(crate) fn here() -> Self {
        use crate::tui::journey;
        Self {
            usual: journey::holder_socket(&tenzro_types::paths::default_data_dir()),
            machine: journey::sanitize_machine_name(&crate::commands::setup::hostname_for_tui()),
            load: Box::new(crate::config::load_config),
            keep: Box::new(crate::config::save_config),
            probe: Arc::new(|socket| {
                let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
                Heard {
                    answers: tenzro_device_key::remote::holder_id(socket).is_ok(),
                    wanted: tenzro_device_key::remote::grant_wanted(socket, now),
                }
            }),
        }
    }

    /// The sockets to ask: the one this machine was set up with, then the
    /// usual one, each with the grant label it goes with.
    fn candidates(&self) -> Vec<(PathBuf, String)> {
        let cfg = (self.load)();
        let label = cfg.key_holder_label.unwrap_or_else(|| self.machine.clone());
        let mut found = Vec::new();
        if let Some(socket) = cfg.key_holder_socket {
            found.push((PathBuf::from(socket), label.clone()));
        }
        if found.iter().all(|(socket, _)| *socket != self.usual) {
            found.push((self.usual.clone(), label));
        }
        found
    }

    async fn hear(&self, socket: &Path) -> Heard {
        let (probe, at) = (self.probe.clone(), socket.to_path_buf());
        let asked = tokio::task::spawn_blocking(move || probe(&at));
        match tokio::time::timeout(HOLDER_WAIT, asked).await {
            Ok(Ok(heard)) => heard,
            _ => Heard {
                answers: false,
                wanted: Some(format!(
                    "the key holder at {} did not answer",
                    socket.display()
                )),
            },
        }
    }

    fn row(socket: &Path, label: &str, heard: &Heard) -> Value {
        json!({
            "id": socket.display().to_string(),
            "label": label,
            "kind": "tpm",
            "reachable": heard.answers,
            "granted": heard.answers && heard.wanted.is_none(),
            "reason": heard.wanted,
        })
    }

    /// `control_keyHolders`.
    pub(crate) async fn list(&self) -> Result<Value, Value> {
        let cfg = (self.load)();
        let mut rows = Vec::new();
        let mut any_answers = false;
        for (socket, label) in self.candidates() {
            let heard = self.hear(&socket).await;
            any_answers |= heard.answers;
            let chosen = cfg.key_holder_socket.as_deref() == Some(&*socket.display().to_string());
            if heard.answers || chosen {
                rows.push(Self::row(&socket, &label, &heard));
            }
        }
        if !any_answers && rows.is_empty() {
            return Err(error(
                REFUSED,
                &format!(
                    "No key holder answers on this machine, and key holders elsewhere are not found by themselves. Start one with `tenzro-node tpm key-holder --socket {} --provider <PROVIDER-ENDPOINT>@<ADDRESS:PORT>`, then choose it here.",
                    self.usual.display()
                ),
            ));
        }
        Ok(Value::Array(rows))
    }

    /// `control_useKeyHolder {id, label?}`: keep the key holder at `id` as
    /// this machine's, as setup keeps it, once it answers. `granted` when its
    /// grant stands, `requested` while the grant is still to be approved
    /// and installed, `refused` when it does not answer.
    pub(crate) async fn choose(&self, params: &Value) -> Result<Value, Value> {
        let id = params
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| error(INVALID_PARAMS, "id names the key holder"))?;
        let (socket, label) = self
            .candidates()
            .into_iter()
            .find(|(socket, _)| socket.display().to_string() == id)
            .ok_or_else(|| error(INVALID_PARAMS, "No such key holder"))?;
        let label = match params.get("label").and_then(Value::as_str) {
            Some(given) => given.to_string(),
            None => label,
        };
        let heard = self.hear(&socket).await;
        if !heard.answers {
            return Ok(json!({ "state": "refused", "reason": heard.wanted }));
        }
        let mut cfg = (self.load)();
        cfg.key_holder_socket = Some(id.to_string());
        cfg.key_holder_label = Some(label);
        (self.keep)(&cfg)
            .map_err(|e| error(REFUSED, &format!("The key holder was not kept: {e:#}")))?;
        Ok(match heard.wanted {
            None => json!({ "state": "granted", "reason": null }),
            Some(why) => json!({ "state": "requested", "reason": why }),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Key holders with their configuration in `dir`, the usual socket
    /// there too, and each socket answering as `heard` says.
    pub(crate) fn kept_in(
        dir: &Path,
        heard: impl Fn(&Path) -> Heard + Send + Sync + 'static,
    ) -> KeyHolders {
        let (from, to) = (dir.to_path_buf(), dir.to_path_buf());
        KeyHolders {
            usual: dir.join("holder").join("h.sock"),
            machine: "pi-1".into(),
            load: Box::new(move || crate::config::load_config_in(&from)),
            keep: Box::new(move |cfg| crate::config::save_config_in(&to, cfg)),
            probe: Arc::new(heard),
        }
    }

    fn silent(_: &Path) -> Heard {
        Heard {
            answers: false,
            wanted: Some("no key holder answers".into()),
        }
    }

    fn granted(_: &Path) -> Heard {
        Heard {
            answers: true,
            wanted: None,
        }
    }

    #[tokio::test]
    async fn with_no_key_holder_here_the_answer_says_how_to_start_one() {
        let dir = tempfile::tempdir().unwrap();
        let holders = kept_in(dir.path(), silent);
        let refusal = holders.list().await.unwrap_err();
        assert_eq!(refusal["code"], REFUSED);
        let text = refusal["message"].as_str().unwrap();
        assert!(text.contains("are not found by themselves"), "{text}");
        assert!(
            text.contains(&format!(
                "tenzro-node tpm key-holder --socket {}",
                dir.path().join("holder").join("h.sock").display()
            )),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_key_holder_that_answers_is_listed_and_chosen_as_setup_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let holders = kept_in(dir.path(), granted);
        let usual = dir
            .path()
            .join("holder")
            .join("h.sock")
            .display()
            .to_string();
        assert_eq!(
            holders.list().await.unwrap(),
            json!([{
                "id": usual,
                "label": "pi-1",
                "kind": "tpm",
                "reachable": true,
                "granted": true,
                "reason": null,
            }])
        );
        let chosen = holders
            .choose(&json!({ "id": usual, "label": "desk" }))
            .await
            .unwrap();
        assert_eq!(chosen, json!({ "state": "granted", "reason": null }));
        let cfg = crate::config::load_config_in(dir.path());
        assert_eq!(cfg.key_holder_socket.as_deref(), Some(usual.as_str()));
        assert_eq!(cfg.key_holder_label.as_deref(), Some("desk"));
    }

    #[tokio::test]
    async fn a_key_holder_without_a_grant_is_kept_and_says_what_remains() {
        let dir = tempfile::tempdir().unwrap();
        let holders = kept_in(dir.path(), |_| Heard {
            answers: true,
            wanted: Some("the key holder has no grant".into()),
        });
        let usual = dir
            .path()
            .join("holder")
            .join("h.sock")
            .display()
            .to_string();
        let chosen = holders.choose(&json!({ "id": usual })).await.unwrap();
        assert_eq!(
            chosen,
            json!({ "state": "requested", "reason": "the key holder has no grant" })
        );
        let cfg = crate::config::load_config_in(dir.path());
        assert_eq!(cfg.key_holder_label.as_deref(), Some("pi-1"));
    }

    #[tokio::test]
    async fn the_chosen_key_holder_is_listed_while_it_is_silent_and_not_kept_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::config::load_config_in(dir.path());
        cfg.key_holder_socket = Some("/run/elsewhere.sock".into());
        cfg.key_holder_label = Some("desk".into());
        crate::config::save_config_in(dir.path(), &cfg).unwrap();
        let holders = kept_in(dir.path(), silent);
        let listed = holders.list().await.unwrap();
        assert_eq!(listed[0]["id"], "/run/elsewhere.sock");
        assert_eq!(listed[0]["reachable"], false);
        assert_eq!(listed.as_array().unwrap().len(), 1);
        let refused = holders
            .choose(&json!({ "id": "/run/elsewhere.sock" }))
            .await
            .unwrap();
        assert_eq!(refused["state"], "refused");
        let refusal = holders
            .choose(&json!({ "id": "/run/other.sock" }))
            .await
            .unwrap_err();
        assert_eq!(refusal["code"], INVALID_PARAMS);
    }
}
