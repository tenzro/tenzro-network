//! Provider schedule management commands

use crate::output;
use crate::rpc::RpcClient;
use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

/// Provider schedule management
#[derive(Debug, Subcommand)]
pub enum ScheduleCommand {
    /// Set provider schedule
    Set(ScheduleSetCmd),
    /// Show current schedule
    Show(ScheduleShowCmd),
    /// Enable schedule
    Enable(ScheduleEnableCmd),
    /// Disable schedule
    Disable(ScheduleDisableCmd),
    /// Show model stacks: what is serving now, what runs next, and when
    Stacks(StacksShowCmd),
}

impl ScheduleCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Set(cmd) => cmd.execute().await,
            Self::Show(cmd) => cmd.execute().await,
            Self::Enable(cmd) => cmd.execute().await,
            Self::Disable(cmd) => cmd.execute().await,
            Self::Stacks(cmd) => cmd.execute().await,
        }
    }
}

/// Show model stacks and their switch times.
///
/// A "stack" is a scheduling window's named set of models. The switch times are
/// the point: an app that knows when its stack ends can drain in-flight work
/// rather than discovering the change through failures.
#[derive(Debug, Parser)]
pub struct StacksShowCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl StacksShowCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Model Stacks");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getModelStacks", serde_json::json!([]))
            .await?;

        let models_of = |v: &serde_json::Value| -> String {
            v.get("models")
                .and_then(|m| m.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| {
                            let id = m.get("id")?.as_str()?;
                            let state = m.get("state").and_then(|s| s.as_str()).unwrap_or("?");
                            Some(format!("{id} ({state})"))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };

        println!();
        match result.get("active") {
            Some(a) if !a.is_null() => {
                output::print_field(
                    "Active stack",
                    a.get("stack").and_then(|s| s.as_str()).unwrap_or("?"),
                );
                if let Some(u) = a.get("until").and_then(|u| u.as_str()) {
                    output::print_field("Until", u);
                }
                output::print_field("Models", &models_of(a));
            }
            // Distinguished from "no stacks configured" below, because the two
            // call for different fixes.
            _ => output::print_field("Active stack", "none — no window is active now"),
        }

        println!();
        match result.get("next") {
            Some(n) if !n.is_null() => {
                output::print_field(
                    "Next stack",
                    n.get("stack").and_then(|s| s.as_str()).unwrap_or("?"),
                );
                if let Some(t) = n.get("starts_at").and_then(|t| t.as_str()) {
                    output::print_field("Starts at", t);
                }
                output::print_field("Models", &models_of(n));
            }
            _ => output::print_field("Next stack", "none scheduled"),
        }

        let configured = result
            .get("stacks")
            .and_then(|s| s.as_array())
            .cloned()
            .unwrap_or_default();
        println!();
        if configured.is_empty() {
            output::print_field("Configured", "no stacks — every model stays as-is");
        } else {
            for w in &configured {
                let name = w.get("stack").and_then(|s| s.as_str()).unwrap_or("?");
                let tz = w.get("timezone").and_then(|s| s.as_str()).unwrap_or("UTC");
                let start = w.get("start_hour").and_then(|h| h.as_u64()).unwrap_or(0);
                let end = w.get("end_hour").and_then(|h| h.as_u64()).unwrap_or(0);
                let models = w
                    .get("models")
                    .and_then(|m| m.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                output::print_field(name, &format!("{start:02}:00-{end:02}:00 {tz} — {models}"));
            }
        }

        if let Some(t) = result.get("node_time").and_then(|t| t.as_str()) {
            println!();
            output::print_field("Node time", t);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ProviderSchedule {
    enabled: bool,
    start_hour: u8,
    end_hour: u8,
    timezone: String,
    days_of_week: [bool; 7],
    /// Model stacks — the named windows that decide which models are resident
    /// when. Carried through every `set` because the RPC replaces the whole
    /// schedule: omitting the field here silently deleted every configured
    /// stack, so a routine availability edit wiped the residency plan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    windows: Vec<serde_json::Value>,
}

/// Set provider schedule
#[derive(Debug, Parser)]
pub struct ScheduleSetCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,

    /// Start time (HH:MM format, 24-hour)
    #[arg(long)]
    pub start: String,

    /// End time (HH:MM format, 24-hour)
    #[arg(long)]
    pub end: String,

    /// Timezone (e.g., America/New_York, UTC)
    #[arg(long, default_value = "UTC")]
    pub timezone: String,

    /// Days of week (comma-separated: mon,tue,wed,thu,fri,sat,sun)
    #[arg(long, default_value = "mon,tue,wed,thu,fri")]
    pub days: String,
}

impl ScheduleSetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Set Provider Schedule");

        // Parse start and end times
        let start_hour = parse_time(&self.start)?;
        let end_hour = parse_time(&self.end)?;

        // Parse days
        let days_of_week = parse_days(&self.days)?;

        let rpc = RpcClient::new(&self.rpc);

        // Read the current schedule first and carry its windows forward. The
        // RPC replaces the schedule wholesale, so a `set` that did not do this
        // would delete every model stack as a side effect of changing hours.
        let existing: serde_json::Value = rpc
            .call("tenzro_getProviderSchedule", serde_json::json!([]))
            .await
            .unwrap_or(serde_json::Value::Null);
        let windows = existing
            .get("windows")
            .and_then(|w| w.as_array())
            .cloned()
            .unwrap_or_default();

        let schedule = ProviderSchedule {
            enabled: true,
            start_hour,
            end_hour,
            timezone: self.timezone.clone(),
            days_of_week,
            windows: windows.clone(),
        };

        println!();
        output::print_field("Start Time", &format!("{:02}:00", start_hour));
        output::print_field("End Time", &format!("{:02}:00", end_hour));
        output::print_field("Timezone", &self.timezone);
        output::print_field("Days", &self.days);
        if !windows.is_empty() {
            output::print_field("Model stacks kept", &windows.len().to_string());
        }
        println!();

        let spinner = output::create_spinner("Updating schedule...");

        let _: serde_json::Value = rpc
            .call("tenzro_setProviderSchedule", serde_json::json!([schedule]))
            .await?;

        spinner.finish_and_clear();

        output::print_success("Provider schedule updated successfully!");

        Ok(())
    }
}

/// Show current schedule
#[derive(Debug, Parser)]
pub struct ScheduleShowCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl ScheduleShowCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Provider Schedule");

        let spinner = output::create_spinner("Fetching schedule...");

        let rpc = RpcClient::new(&self.rpc);
        let schedule: ProviderSchedule = rpc
            .call("tenzro_getProviderSchedule", serde_json::json!([]))
            .await?;

        spinner.finish_and_clear();

        println!();
        output::print_status(
            "Enabled",
            if schedule.enabled { "Yes" } else { "No" },
            schedule.enabled,
        );
        output::print_field("Start Time", &format!("{:02}:00", schedule.start_hour));
        output::print_field("End Time", &format!("{:02}:00", schedule.end_hour));
        output::print_field("Timezone", &schedule.timezone);

        let days = format_days(&schedule.days_of_week);
        output::print_field("Active Days", &days);

        Ok(())
    }
}

/// Enable schedule
#[derive(Debug, Parser)]
pub struct ScheduleEnableCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl ScheduleEnableCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Enable Provider Schedule");

        let rpc = RpcClient::new(&self.rpc);

        // Get current schedule
        let mut schedule: ProviderSchedule = rpc
            .call("tenzro_getProviderSchedule", serde_json::json!([]))
            .await?;

        schedule.enabled = true;

        let spinner = output::create_spinner("Enabling schedule...");

        let _: serde_json::Value = rpc
            .call("tenzro_setProviderSchedule", serde_json::json!([schedule]))
            .await?;

        spinner.finish_and_clear();

        output::print_success("Provider schedule enabled!");

        Ok(())
    }
}

/// Disable schedule
#[derive(Debug, Parser)]
pub struct ScheduleDisableCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl ScheduleDisableCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Disable Provider Schedule");

        let rpc = RpcClient::new(&self.rpc);

        // Get current schedule
        let mut schedule: ProviderSchedule = rpc
            .call("tenzro_getProviderSchedule", serde_json::json!([]))
            .await?;

        schedule.enabled = false;

        let spinner = output::create_spinner("Disabling schedule...");

        let _: serde_json::Value = rpc
            .call("tenzro_setProviderSchedule", serde_json::json!([schedule]))
            .await?;

        spinner.finish_and_clear();

        output::print_success("Provider schedule disabled. Provider will run 24/7.");

        Ok(())
    }
}

// Helper functions

fn parse_time(time_str: &str) -> Result<u8> {
    let parts: Vec<&str> = time_str.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid time format. Use HH:MM (e.g., 09:00, 17:30)");
    }

    let hour: u8 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid hour: {}", parts[0]))?;

    if hour > 23 {
        anyhow::bail!("Hour must be 0-23");
    }

    Ok(hour)
}

fn parse_days(days_str: &str) -> Result<[bool; 7]> {
    let mut days = [false; 7];
    let day_names = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

    for day in days_str.split(',') {
        let day = day.trim().to_lowercase();
        if let Some(index) = day_names.iter().position(|&d| d == day) {
            days[index] = true;
        } else {
            anyhow::bail!(
                "Invalid day: {}. Use mon, tue, wed, thu, fri, sat, sun",
                day
            );
        }
    }

    Ok(days)
}

fn format_days(days: &[bool; 7]) -> String {
    let day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let active_days: Vec<&str> = days
        .iter()
        .enumerate()
        .filter_map(|(i, &active)| if active { Some(day_names[i]) } else { None })
        .collect();

    if active_days.is_empty() {
        "None".to_string()
    } else {
        active_days.join(", ")
    }
}
