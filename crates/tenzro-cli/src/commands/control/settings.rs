//! `control_settings` and `control_setSettings`: this machine's settings for
//! its node, as far as this release has them.
//!
//! `notifications` and `auto_update` are the release preferences
//! `tenzro update notices` writes. `start_at_boot` is whether the node
//! service starts with the machine; turning it on or off is the
//! administrator's, asked for through polkit as the node service is (see
//! `node_service`), and answered with the command to run where no agent asks.
//! Where the node keeps its data is not an app's to know, and is not among
//! them.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use tenzro_update_notice::banner::Prefs;

use super::node_service::{Run, through_polkit};
use super::{INVALID_PARAMS, REFUSED, error};
use crate::commands::service::{self, AtBoot};

/// The settings of one machine.
pub(crate) struct Settings {
    data_dir: PathBuf,
    at_boot: Arc<dyn Fn() -> Option<AtBoot> + Send + Sync>,
    run: Run,
}

impl Settings {
    /// This machine's: its node's data directory, as `tenzro update` finds
    /// it, and its node service.
    pub(crate) fn here() -> Self {
        Self {
            data_dir: std::env::var_os("TENZRO_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(tenzro_types::paths::default_data_dir),
            at_boot: Arc::new(|| service::at_boot(std::env::consts::OS)),
            run: Arc::new(|steps| service::run_steps(steps, "the node service was not changed")),
        }
    }

    /// `control_settings`. A setting this machine does not have is left out.
    pub(crate) async fn read(&self) -> Value {
        let at_boot = self.boot().await;
        let prefs = Prefs::load(&self.data_dir);
        let mut settings = Map::new();
        if let Some(at_boot) = at_boot {
            settings.insert("start_at_boot".into(), json!(at_boot.on));
        }
        settings.insert("auto_update".into(), json!(prefs.auto_install));
        settings.insert("notifications".into(), json!(prefs.notices));
        Value::Object(settings)
    }

    /// `control_setSettings {<name>: bool, ...}`: every change is checked
    /// before any is made, so a call that is refused changes nothing.
    pub(crate) async fn change(&self, params: &Value) -> Result<Value, Value> {
        let asked = params
            .as_object()
            .ok_or_else(|| error(INVALID_PARAMS, "name the settings to change"))?;
        let mut prefs = Prefs::load(&self.data_dir);
        let mut changed = false;
        let mut boot = None;
        for (name, value) in asked {
            let on = value
                .as_bool()
                .ok_or_else(|| error(INVALID_PARAMS, &format!("{name} is true or false")))?;
            match name.as_str() {
                "notifications" => prefs.notices = on,
                "auto_update" => prefs.auto_install = on,
                "start_at_boot" => match self.boot().await {
                    Some(at_boot) if at_boot.on != on => {
                        boot = Some(if on {
                            at_boot.turn_on
                        } else {
                            at_boot.turn_off
                        });
                        continue;
                    }
                    Some(_) => continue,
                    None => {
                        return Err(error(
                            REFUSED,
                            "No node service is installed here to start with this machine",
                        ));
                    }
                },
                _ => {
                    return Err(error(
                        INVALID_PARAMS,
                        &format!("This machine has no setting named {name}"),
                    ));
                }
            }
            changed = true;
        }
        // Every change has been checked; the administrator's is made first, so
        // one polkit refuses leaves the preferences as they were.
        if let Some(command) = boot {
            let left = || {
                error(
                    REFUSED,
                    &format!(
                        "Whether the node starts with this machine is the administrator's to change: run `{command}` in a terminal"
                    ),
                )
            };
            let step: Vec<Vec<String>> =
                vec![command.split_whitespace().map(String::from).collect()];
            let asked = through_polkit(&step).ok_or_else(left)?;
            let run = self.run.clone();
            match tokio::task::spawn_blocking(move || run(&asked)).await {
                Ok(Ok(())) => {}
                _ => return Err(left()),
            }
        }
        if changed && let Err(e) = prefs.save(&self.data_dir) {
            let command = format!(
                "sudo tenzro update notices {} --auto-install {}",
                if prefs.notices { "on" } else { "off" },
                if prefs.auto_install { "on" } else { "off" }
            );
            return Err(error(REFUSED, &why_not_saved(&e, &command)));
        }
        Ok(self.read().await)
    }

    /// Asking the service manager runs a program, so it runs off the
    /// answering thread.
    async fn boot(&self) -> Option<AtBoot> {
        let at_boot = self.at_boot.clone();
        tokio::task::spawn_blocking(move || at_boot())
            .await
            .ok()
            .flatten()
    }
}

/// What the app is told when the release preferences could not be written: the command that
/// changes them as the administrator when the user may not write them, and no path.
fn why_not_saved(e: &std::io::Error, command: &str) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "This machine's release preferences are its administrator's: run `{command}` in a terminal"
        )
    } else {
        format!("The settings were not saved: {e}")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Settings kept in `data_dir`, on a machine whose node service starts
    /// with it as `at_boot` says and whose polkit lets nothing be changed.
    pub(crate) fn kept_in(data_dir: PathBuf, at_boot: Option<bool>) -> Settings {
        Settings {
            data_dir,
            at_boot: Arc::new(move || {
                at_boot.map(|on| AtBoot {
                    on,
                    turn_on: "sudo systemctl enable tenzro-node".into(),
                    turn_off: "sudo systemctl disable tenzro-node".into(),
                })
            }),
            run: Arc::new(|_| anyhow::bail!("Interactive authentication required.")),
        }
    }

    fn message(refusal: &Value) -> (i64, &str) {
        (
            refusal["code"].as_i64().unwrap(),
            refusal["message"].as_str().unwrap(),
        )
    }

    #[tokio::test]
    async fn the_settings_are_the_release_preferences_and_the_service() {
        let dir = tempfile::tempdir().unwrap();
        let settings = kept_in(dir.path().to_path_buf(), Some(true));
        assert_eq!(
            settings.read().await,
            json!({
                "start_at_boot": true,
                "auto_update": false,
                "notifications": true,
            })
        );
        // Where the node keeps its data is not an app's to know.
        assert!(settings.read().await.get("data_dir").is_none());
        let no_service = kept_in(dir.path().to_path_buf(), None).read().await;
        assert!(no_service.get("start_at_boot").is_none(), "{no_service}");
    }

    #[tokio::test]
    async fn a_preference_is_changed_and_kept_where_the_terminal_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let settings = kept_in(dir.path().to_path_buf(), Some(true));
        let now = settings
            .change(&json!({ "notifications": false, "auto_update": true }))
            .await
            .unwrap();
        assert_eq!(now["notifications"], false);
        assert_eq!(now["auto_update"], true);
        let kept = Prefs::load(dir.path());
        assert!(!kept.notices);
        assert!(kept.auto_install);
        // Asking for the state it is already in changes nothing and is answered.
        let same = settings
            .change(&json!({ "start_at_boot": true }))
            .await
            .unwrap();
        assert_eq!(same["start_at_boot"], true);
    }

    #[tokio::test]
    async fn starting_with_the_machine_is_changed_through_polkit() {
        let dir = tempfile::tempdir().unwrap();
        let ran = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = ran.clone();
        let settings = Settings {
            run: Arc::new(move |steps| {
                kept.lock()
                    .unwrap()
                    .extend(steps.iter().map(|step| step.join(" ")));
                Ok(())
            }),
            ..kept_in(dir.path().to_path_buf(), Some(true))
        };
        settings
            .change(&json!({ "notifications": false, "start_at_boot": false }))
            .await
            .unwrap();
        assert_eq!(*ran.lock().unwrap(), vec!["systemctl disable tenzro-node"]);
        assert!(!Prefs::load(dir.path()).notices);
    }

    #[tokio::test]
    async fn a_change_that_is_not_the_users_is_refused_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let settings = kept_in(dir.path().to_path_buf(), Some(true));
        let refusal = settings
            .change(&json!({ "notifications": false, "start_at_boot": false }))
            .await
            .unwrap_err();
        assert_eq!(
            message(&refusal),
            (
                REFUSED,
                "Whether the node starts with this machine is the administrator's to change: run `sudo systemctl disable tenzro-node` in a terminal"
            )
        );
        assert!(Prefs::load(dir.path()).notices, "nothing was changed");

        for (asked, code) in [
            (json!({ "data_dir": true }), INVALID_PARAMS),
            (json!({ "keep_awake": true }), INVALID_PARAMS),
            (json!({ "notifications": "off" }), INVALID_PARAMS),
            (json!([true]), INVALID_PARAMS),
        ] {
            let refusal = settings.change(&asked).await.unwrap_err();
            assert_eq!(refusal["code"], code, "{asked}");
        }
        let refusal = kept_in(dir.path().to_path_buf(), None)
            .change(&json!({ "start_at_boot": true }))
            .await
            .unwrap_err();
        assert_eq!(refusal["code"], REFUSED);
    }

    #[test]
    fn a_data_directory_the_user_may_not_write_names_the_command() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let text = why_not_saved(&denied, "sudo tenzro update notices off --auto-install off");
        assert!(
            text.ends_with("run `sudo tenzro update notices off --auto-install off` in a terminal"),
            "{text}"
        );
        let other = std::io::Error::from(std::io::ErrorKind::StorageFull);
        assert!(why_not_saved(&other, "x").starts_with("The settings were not saved: "));
    }
}
