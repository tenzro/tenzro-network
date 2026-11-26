//! A restart the operator asks for.
//!
//! The node never starts itself again. It stands down the way a graceful exit
//! does, drains, and ends with [`STATUS`]; the service that runs it starts it
//! again (the systemd units declare that status a clean end that restarts the
//! unit, and launchd starts again a job that ends at all). A node no service
//! runs would stay down, so the request is refused there.

/// The status a node ends with when its operator asked for a restart: the
/// conventional "try again" status, which the node's systemd units name in
/// `SuccessExitStatus` and `RestartForceExitStatus`.
pub const STATUS: u8 = 75;

/// The label of the launchd job the installer writes.
const LAUNCHD_LABEL: &str = "network.tenzro.node";

/// The service manager that started this process and starts it again when it
/// ends with [`STATUS`]; `None` when the node was started any other way.
pub fn service() -> Option<&'static str> {
    service_of(std::env::consts::OS, std::process::id(), |name| {
        std::env::var(name).ok()
    })
}

/// systemd names the process it started in `SYSTEMD_EXEC_PID`; a process
/// started from a shell inside some other unit inherits the variable with
/// another process's number. launchd names the job in `XPC_SERVICE_NAME`.
fn service_of(os: &str, pid: u32, var: impl Fn(&str) -> Option<String>) -> Option<&'static str> {
    match os {
        "linux" => (var("SYSTEMD_EXEC_PID")?.parse() == Ok(pid)).then_some("systemd"),
        "macos" => (var("XPC_SERVICE_NAME")? == LAUNCHD_LABEL).then_some("launchd"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    #[test]
    fn a_process_systemd_started_is_restarted_by_systemd() {
        let started = env(&[("SYSTEMD_EXEC_PID", "4242")]);
        assert_eq!(service_of("linux", 4242, started), Some("systemd"));
    }

    #[test]
    fn a_process_started_from_a_shell_inside_a_unit_has_no_service() {
        let inherited = env(&[("SYSTEMD_EXEC_PID", "4242"), ("INVOCATION_ID", "abc")]);
        assert_eq!(service_of("linux", 4243, inherited), None);
        assert_eq!(service_of("linux", 4242, env(&[])), None);
        assert_eq!(
            service_of("linux", 4242, env(&[("SYSTEMD_EXEC_PID", "")])),
            None
        );
    }

    #[test]
    fn only_the_installed_launchd_job_is_restarted_by_launchd() {
        let job = env(&[("XPC_SERVICE_NAME", "network.tenzro.node")]);
        assert_eq!(service_of("macos", 1, job), Some("launchd"));
        let terminal = env(&[("XPC_SERVICE_NAME", "0")]);
        assert_eq!(service_of("macos", 1, terminal), None);
        assert_eq!(service_of("macos", 1, env(&[])), None);
    }

    #[test]
    fn a_system_with_no_service_for_the_node_has_none() {
        let both = env(&[
            ("SYSTEMD_EXEC_PID", "7"),
            ("XPC_SERVICE_NAME", "network.tenzro.node"),
        ]);
        assert_eq!(service_of("windows", 7, both), None);
    }

    /// Every systemd unit the node ships with starts it again on [`STATUS`]
    /// and does not count it as a failure.
    #[test]
    fn the_node_units_restart_on_the_restart_status_as_a_clean_end() {
        for unit in [
            include_str!("../tenzro-node.service"),
            include_str!("../../../scripts/launch/units/tenzro-testnet-node.service"),
            include_str!(
                "../../../scripts/release/cvm/mkosi.extra/usr/lib/systemd/system/tenzro-node.service"
            ),
        ] {
            for line in [
                format!("\nSuccessExitStatus={STATUS}\n"),
                format!("\nRestartForceExitStatus={STATUS}\n"),
            ] {
                assert!(unit.contains(&line), "{line:?}");
            }
        }
    }

    /// A test is never the process a service manager started.
    #[test]
    fn a_test_process_has_no_service() {
        assert_eq!(service(), None);
    }
}
