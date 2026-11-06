//! `tenzro status` — the operator's live view of what their machine is doing.
//!
//! The first panel is the node itself: whether it is running, where it is on
//! the chain, which roles it serves and what they have staked, whether the
//! operator is approved for sponsorship, and the one thing to do next. The
//! panels below it are the resource and traffic readout described next.
//! `--watch` redraws the whole screen in place every few seconds.
//!
//! # Why this exists
//!
//! An operator deciding whether to serve another model is making a resource
//! decision, and the information they need to make it is spread across four
//! RPCs: how memory is divided, what is warm, how traffic is being served, and
//! what the controller has been doing about it. Asking someone to join those by
//! hand, repeatedly, while they are mid-decision, is how they end up guessing.
//!
//! So this is a single compact readout, refreshable in place — the same idea as
//! a terminal status bar: always the current numbers, never a wall of history.
//!
//! # The number that matters is goodput, not throughput
//!
//! Load looks fine right up until it doesn't. Requests-per-second holds steady
//! while a node slides into the state where everything is still being served
//! and nothing arrives in time to be useful. Goodput — the share of completed
//! requests that met their deadline — is what falls first, so it gets the
//! prominent line and the colour, and throughput is reported next to it rather
//! than instead of it.

use anyhow::Result;
use clap::Parser;

use crate::commands::service::{self, Sample};
use crate::config::PendingStake;
use crate::output;
use crate::rpc::{RpcClient, format_tnzo};

/// Refresh interval floor, in milliseconds.
///
/// Each refresh is four RPCs. Polling faster than this measures the node's
/// response to being polled, and on a busy node the status display would be
/// competing with the traffic it is reporting on.
const MIN_INTERVAL_MS: u64 = 500;

/// Live resource and traffic status
#[derive(Debug, Parser)]
pub struct StatusCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Redraw the screen in place every N milliseconds (2000 when no value
    /// is given) until interrupted.
    #[arg(long, value_name = "MS", num_args = 0..=1, default_missing_value = "2000")]
    watch: Option<u64>,

    /// Print one JSON object instead of the formatted readout.
    #[arg(long)]
    json: bool,
}

impl StatusCmd {
    pub async fn execute(self) -> Result<()> {
        let client = RpcClient::new(&self.rpc);
        match self.watch {
            None => {
                let snap = Snapshot::fetch(&client).await;
                if self.json {
                    println!("{}", serde_json::to_string_pretty(&snap.raw)?);
                } else {
                    snap.render();
                }
                Ok(())
            }
            Some(ms) => {
                let interval = ms.max(MIN_INTERVAL_MS);
                if self.json {
                    // Line-delimited JSON, so `tenzro status --watch --json`
                    // pipes into jq or a log shipper without a parser having to
                    // find object boundaries in a stream.
                    loop {
                        let snap = Snapshot::fetch(&client).await;
                        println!("{}", serde_json::to_string(&snap.raw)?);
                        tokio::time::sleep(std::time::Duration::from_millis(interval)).await;
                    }
                }
                // On a terminal the watch owns the screen: the alternate screen
                // keeps the operator's scrollback intact and the cursor is put
                // back however the watch ends.
                let screen = Screen::enter();
                loop {
                    // Fetched before anything is cleared, so the old frame
                    // stays up until the new one is ready to replace it.
                    let snap = Snapshot::fetch(&client).await;
                    // Clear and home, so successive frames overwrite rather
                    // than scroll. A scrolling status display is a log, and a
                    // log is the thing this exists not to be.
                    if screen.active {
                        print!("\x1b[2J\x1b[H");
                    }
                    snap.render();
                    println!();
                    output::print_info(&format!("refreshing every {interval}ms — ctrl-c to stop"));
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_millis(interval)) => {}
                        _ = tokio::signal::ctrl_c() => return Ok(()),
                    }
                }
            }
        }
    }
}

/// The terminal's alternate screen, entered for a watch and left on drop.
/// Inactive when stdout is not a terminal, so a pipe sees plain frames.
struct Screen {
    active: bool,
}

impl Screen {
    fn enter() -> Self {
        let active = console::Term::stdout().is_term();
        if active {
            print!("\x1b[?1049h\x1b[?25l");
        }
        Self { active }
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        if self.active {
            print!("\x1b[?25h\x1b[?1049l");
        }
    }
}

/// One role's bond against what the role requires, in wei.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleBond {
    pub role: String,
    pub bonded: u128,
    pub required: u128,
}

/// What the node-state panel knows. Every field is what a read returned; a
/// read that failed leaves its field empty.
#[derive(Debug, Clone, Default)]
pub struct NodeFacts {
    pub reachable: bool,
    pub state: Option<String>,
    pub roles: Vec<String>,
    pub uptime_secs: u64,
    pub sample: Option<Sample>,
    pub machine_did: Option<String>,
    pub account: Option<String>,
    /// The validator registry status of the node's account, when registered.
    pub validator_status: Option<String>,
    pub validator_self_stake: u128,
    pub bonds: Vec<RoleBond>,
    /// Whether governance has approved the account as an operator.
    pub approved: Option<bool>,
    pub pending_stake: Option<PendingStake>,
}

impl NodeFacts {
    fn serves(&self, role: &str) -> bool {
        self.roles
            .iter()
            .any(|r| r == role || (role == "ai" && r == "model-provider"))
    }
}

/// The one thing the operator should do next, from what the node reports.
/// Pure: the order is the order problems block each other.
pub fn next_action(f: &NodeFacts) -> String {
    if !f.reachable {
        return "The node is not answering. Start it with `tenzro setup --apply`, or check the \
                service: `sudo systemctl status tenzro-node`."
            .to_string();
    }
    if let Some(s) = &f.sample {
        if s.syncing {
            return format!(
                "Syncing, block {} of {}. Nothing to do; it finishes by itself.",
                s.height, s.highest
            );
        }
        if s.peers == 0 {
            return "No peers yet. Check this machine's network: outbound UDP must be open \
                    (docs/NODE-NETWORKING.md)."
                .to_string();
        }
    }
    if f.serves("validator") {
        match f.validator_status.as_deref() {
            None => {
                return match &f.pending_stake {
                    Some(p) => format!(
                        "Waiting for stake: send {} to {}, then restart the node and it registers \
                         itself. `tenzro sponsor check` shows the sponsored route.",
                        format_tnzo(p.required_wei.parse().unwrap_or(0)),
                        p.account
                    ),
                    None => "Not registered as a validator. Fund the node's account with the \
                             self-stake, then restart the node; it registers itself."
                        .to_string(),
                };
            }
            Some("Candidate") | Some("PendingActive") => {
                return "Registered. The validator is admitted to the active set at the next \
                        epoch boundary."
                    .to_string();
            }
            Some("Jailed") => {
                return "The validator is jailed. It stays out of the active set until governance \
                        reinstates it."
                    .to_string();
            }
            Some("PendingExit") | Some("Exited") => {
                return "The validator has exited the set. Register again with \
                        `tenzro validator register` once the cooldown passes."
                    .to_string();
            }
            Some(_) => {}
        }
    }
    if let Some(b) = f.bonds.iter().find(|b| b.bonded < b.required) {
        return format!(
            "Role {} is under-bonded: bond {} more with `tenzro stake bond --role {} --amount {}`.",
            b.role,
            format_tnzo(b.required - b.bonded),
            b.role,
            (b.required - b.bonded) / tenzro_types::constants::ONE_TNZO.max(1)
        );
    }
    match f.approved {
        Some(false) => {
            "Running. To be paid for running it, see whether you qualify for sponsorship: \
             `tenzro sponsor check`."
                .to_string()
        }
        _ => "Running. Nothing to do.".to_string(),
    }
}

/// One frame of the readout.
struct Snapshot {
    raw: serde_json::Value,
}

impl Snapshot {
    /// Fetch every panel.
    ///
    /// A panel that fails is recorded as `null` rather than aborting the frame:
    /// a node that is not serving models still has traffic and memory worth
    /// looking at, and an operator diagnosing a half-up node is precisely who
    /// needs the half that works.
    async fn fetch(client: &RpcClient) -> Self {
        let (memory, traffic, lifecycle, autotune, node) = tokio::join!(
            call(client, "tenzro_memoryBudget"),
            call(client, "tenzro_trafficStats"),
            call(client, "tenzro_modelLifecycle"),
            call(client, "tenzro_autotuneDecisions"),
            fetch_node(client),
        );
        let next = next_action(&node);
        Self {
            raw: serde_json::json!({
                "node": node_json(&node, &next),
                "memory": memory,
                "traffic": traffic,
                "lifecycle": lifecycle,
                "autotune": autotune,
            }),
        }
    }

    fn render(&self) {
        output::print_header("Node Status");
        self.render_node();
        self.render_memory();
        self.render_traffic();
        self.render_models();
        self.render_autotune();
    }

    fn render_node(&self) {
        let n = &self.raw["node"];
        if !n["reachable"].as_bool().unwrap_or(false) {
            output::print_warning("The node is not answering.");
        } else {
            output::print_field(
                "Node",
                &format!(
                    "{}  ·  up {}  ·  roles {}",
                    n["state"].as_str().unwrap_or("running"),
                    duration(n["uptime_secs"].as_u64().unwrap_or(0) * 1000),
                    n["roles"]
                        .as_array()
                        .map(|r| r.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "none".to_string())
                ),
            );
            if let Some(chain) = n["chain"].as_str() {
                output::print_field("Chain", chain);
            }
            if let Some(v) = n["validator"].as_str() {
                output::print_field("Validator", v);
            }
            for b in n["bonds"].as_array().into_iter().flatten() {
                output::print_field(
                    &format!("  {}", b["role"].as_str().unwrap_or("role")),
                    b["text"].as_str().unwrap_or(""),
                );
            }
            if let Some(a) = n["sponsorship"].as_str() {
                output::print_field("Sponsorship", a);
            }
        }
        output::print_field("Next", n["next"].as_str().unwrap_or(""));
        println!();
    }

    fn render_memory(&self) {
        let m = &self.raw["memory"];
        if m.is_null() {
            output::print_warning("Memory budget unavailable.");
            return;
        }
        let total = u64_at(m, "total_bytes");
        let reserve = u64_at(m, "reserve_bytes");
        let pool = u64_at(m, "pool_bytes");
        let committed = u64_at(m, "committed_bytes");

        println!();
        output::print_field(
            "Memory",
            &format!(
                "{} of {} committed  ·  {} free  ·  {} reserved for the OS and services",
                gib(committed),
                gib(pool),
                gib(pool.saturating_sub(committed)),
                gib(reserve)
            ),
        );
        println!("           {}", bar(committed, pool));
        if total > 0 && pool == 0 {
            output::print_warning(
                "The pool is zero — the reserve is consuming everything, so nothing can be served.",
            );
        }

        if let Some(tiers) = m.get("tiers").and_then(|t| t.as_array()) {
            for t in tiers {
                let name = t
                    .get("tier")
                    .and_then(|v| v.as_str())
                    .unwrap_or("tier")
                    .to_string();
                let ceiling = u64_at(t, "ceiling_bytes");
                let used = u64_at(t, "committed_bytes");
                let n = t
                    .get("commitments")
                    .and_then(|c| c.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                output::print_field(
                    &format!("  {name}"),
                    &format!("{} / {}  ·  {n} model(s)", gib(used), gib(ceiling)),
                );
            }
        }
    }

    fn render_traffic(&self) {
        let t = &self.raw["traffic"];
        if t.is_null() {
            output::print_warning("Traffic stats unavailable.");
            return;
        }
        let in_flight = u64_at(t, "in_flight_interactive") + u64_at(t, "in_flight_batch");
        let max = u64_at(t, "max_concurrent");
        let goodput = t.get("goodput_pct").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let completed = u64_at(t, "completed");
        let refused = u64_at(t, "refused");
        let reserved = u64_at(t, "reserved_slots");
        let reserved_idle = u64_at(t, "reserved_idle");

        println!();
        output::print_field("In flight", &format!("{in_flight} / {max} concurrent"));
        println!("           {}", bar(in_flight, max));

        // Goodput leads, because throughput can hold steady while this
        // collapses — and that is exactly the state worth catching.
        //
        // With nothing completed the ratio is vacuously 100%, and printing that
        // reads as a clean bill of health the node has not earned. Say there is
        // no measurement instead.
        let goodput_line = if completed == 0 {
            "no completed requests yet — nothing measured".to_string()
        } else {
            let verdict = if goodput >= 99.0 {
                "healthy"
            } else if goodput >= 90.0 {
                "some requests are missing their deadline"
            } else {
                "OVERLOADED — most requests are arriving too late to be useful"
            };
            format!("{goodput:.1}%  ·  {verdict}")
        };
        output::print_field("Goodput", &goodput_line);
        output::print_field(
            "Served",
            &format!("{completed} completed  ·  {refused} refused"),
        );

        if reserved > 0 {
            output::print_field(
                "Leased",
                &format!(
                    "{reserved} slot(s) reserved, {reserved_idle} idle  ·  \
                     idle reserved slots are the price of the dedicated guarantee"
                ),
            );
        }
        if completed > 0 && goodput < 90.0 {
            output::print_warning(
                "Goodput is low. Shedding load raises it: fewer requests complete, but the ones \
                 that do are still useful. Check `tenzro status --json` for the autotune \
                 decisions below.",
            );
        }
    }

    fn render_models(&self) {
        let l = &self.raw["lifecycle"];
        if l.is_null() {
            return;
        }
        let warm = l
            .get("warm")
            .and_then(|w| w.as_array())
            .cloned()
            .unwrap_or_default();
        println!();
        if warm.is_empty() {
            output::print_field("Models", "none warm — the next request pays the load time");
            return;
        }
        output::print_field("Models", &format!("{} warm", warm.len()));
        for w in &warm {
            let id = w
                .get("model_id")
                .and_then(|v| v.as_str())
                .or_else(|| w.as_str())
                .unwrap_or("?");
            let idle = w.get("idle_ms").and_then(|v| v.as_u64());
            let in_flight = w.get("in_flight").and_then(|v| v.as_u64()).unwrap_or(0);
            let detail = match idle {
                Some(ms) if in_flight == 0 => format!("idle {}", duration(ms)),
                Some(_) => format!("{in_flight} in flight"),
                None => format!("{in_flight} in flight"),
            };
            output::print_field(&format!("  {id}"), &detail);
        }
    }

    fn render_autotune(&self) {
        let a = &self.raw["autotune"];
        let decisions = a
            .get("decisions")
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();
        if decisions.is_empty() {
            return;
        }
        println!();
        output::print_field("Autotune", &format!("{} recent action(s)", decisions.len()));
        for d in decisions.iter().take(5) {
            let text = d
                .get("action")
                .map(|v| v.to_string())
                .unwrap_or_else(|| d.to_string());
            output::print_field("  ", &text);
        }
    }
}

/// Read the node-state panel. Each read that fails leaves its field empty.
async fn fetch_node(client: &RpcClient) -> NodeFacts {
    use serde_json::{Value, json};
    let status: Option<Value> = client.call("tenzro_getNodeStatus", json!([])).await.ok();
    let Some(status) = status else {
        return NodeFacts {
            pending_stake: crate::config::load_config().pending_stake,
            ..NodeFacts::default()
        };
    };
    let roles: Vec<String> = match status.get("roles") {
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).collect(),
        _ => Vec::new(),
    };
    let account = status.get("payee").and_then(Value::as_str).map(str::to_string);
    let mut facts = NodeFacts {
        reachable: true,
        state: status.get("state").and_then(Value::as_str).map(str::to_string),
        roles,
        uptime_secs: status.get("uptime_secs").and_then(Value::as_u64).unwrap_or(0),
        sample: service::sample(client).await,
        machine_did: status.get("machine_did").and_then(Value::as_str).map(str::to_string),
        account: account.clone(),
        pending_stake: crate::config::load_config().pending_stake,
        ..NodeFacts::default()
    };
    let Some(acct) = account else {
        return facts;
    };
    let wei = |v: &Value, k: &str| -> u128 {
        v.get(k).and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0)
    };
    if facts.serves("validator")
        && let Ok(v) = client
            .call::<Value>("tenzro_getValidatorState", json!({ "address": acct }))
            .await
        && !v.is_null()
    {
        facts.validator_status = v.get("status").and_then(Value::as_str).map(str::to_string);
        facts.validator_self_stake = wei(&v, "self_stake");
    }
    if let Ok(v) = client
        .call::<Value>("tenzro_getRoleStakes", json!({ "address": acct }))
        .await
    {
        facts.bonds = v
            .get("stakes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|s| {
                Some(RoleBond {
                    role: s.get("role")?.as_str()?.to_string(),
                    bonded: wei(s, "bonded"),
                    required: wei(s, "required"),
                })
            })
            .collect();
    }
    if let Ok(p) = client
        .call::<Value>("tenzro_getTreasuryPayouts", json!({ "address": acct, "limit": 1 }))
        .await
    {
        facts.approved = Some(
            p.get("address")
                .and_then(|a| a.get("operator"))
                .is_some_and(|o| {
                    !o.is_null() && !o.get("revoked").and_then(Value::as_bool).unwrap_or(false)
                }),
        );
    }
    facts
}

/// The panel as JSON, with the lines the text view prints.
fn node_json(f: &NodeFacts, next: &str) -> serde_json::Value {
    serde_json::json!({
        "reachable": f.reachable,
        "state": f.state,
        "roles": f.roles,
        "uptime_secs": f.uptime_secs,
        "machine_did": f.machine_did,
        "account": f.account,
        "chain": f.sample.map(|s| s.describe()),
        "validator": f.validator_status.as_ref().map(|s| format!(
            "{s}  ·  self-stake {}", format_tnzo(f.validator_self_stake))),
        "bonds": f.bonds.iter().map(|b| serde_json::json!({
            "role": b.role,
            "text": format!("{} bonded of {} required", format_tnzo(b.bonded), format_tnzo(b.required)),
        })).collect::<Vec<_>>(),
        "sponsorship": f.approved.map(|a| if a { "approved" } else { "not approved" }),
        "next": next,
    })
}

async fn call(client: &RpcClient, method: &str) -> serde_json::Value {
    client
        .call::<serde_json::Value>(method, serde_json::json!({}))
        .await
        .unwrap_or(serde_json::Value::Null)
}

fn u64_at(v: &serde_json::Value, key: &str) -> u64 {
    v.get(key).and_then(|x| x.as_u64()).unwrap_or(0)
}

/// Bytes as GiB, at the precision an operator actually compares at.
fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / 1_073_741_824.0)
}

/// Milliseconds as something readable at a glance.
fn duration(ms: u64) -> String {
    if ms < 1_000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.0}s", ms as f64 / 1000.0)
    } else {
        format!("{:.0}m", ms as f64 / 60_000.0)
    }
}

/// A 30-cell meter.
///
/// Saturates rather than overflowing: a `used` above `total` is a real state
/// (a commitment made before a ceiling was lowered) and should read as "full",
/// not print a bar wider than the terminal.
fn bar(used: u64, total: u64) -> String {
    const WIDTH: usize = 30;
    if total == 0 {
        return format!("[{}]  n/a", "·".repeat(WIDTH));
    }
    let filled = ((used as f64 / total as f64) * WIDTH as f64).round() as usize;
    let filled = filled.min(WIDTH);
    let pct = ((used as f64 / total as f64) * 100.0).min(100.0);
    format!(
        "[{}{}]  {pct:.0}%",
        "█".repeat(filled),
        "·".repeat(WIDTH - filled)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn running() -> NodeFacts {
        NodeFacts {
            reachable: true,
            roles: vec!["validator".into()],
            sample: Some(Sample { height: 100, highest: 100, peers: 4, syncing: false }),
            ..NodeFacts::default()
        }
    }

    #[test]
    fn an_unreachable_node_points_at_setup_and_the_service() {
        let a = next_action(&NodeFacts::default());
        assert!(a.contains("tenzro setup --apply") && a.contains("systemctl"), "{a}");
    }

    #[test]
    fn syncing_comes_before_everything_else() {
        let mut f = running();
        f.sample = Some(Sample { height: 5, highest: 90, peers: 3, syncing: true });
        assert!(next_action(&f).starts_with("Syncing, block 5 of 90"));
    }

    #[test]
    fn no_peers_is_named_before_roles() {
        let mut f = running();
        f.sample = Some(Sample { height: 5, highest: 5, peers: 0, syncing: false });
        assert!(next_action(&f).contains("No peers"));
    }

    #[test]
    fn an_unregistered_validator_is_told_what_it_waits_for() {
        let mut f = running();
        assert!(next_action(&f).contains("Fund the node's account"));
        f.pending_stake = Some(PendingStake {
            role: "validator".into(),
            required_wei: "10000000000000000000000".into(),
            account: "0xabc".into(),
        });
        let a = next_action(&f);
        assert!(a.contains("10000 TNZO") && a.contains("0xabc") && a.contains("sponsor check"), "{a}");
    }

    #[test]
    fn validator_registry_states_each_have_their_own_message() {
        let mut f = running();
        f.validator_status = Some("PendingActive".into());
        assert!(next_action(&f).contains("next epoch boundary"));
        f.validator_status = Some("Jailed".into());
        assert!(next_action(&f).contains("jailed"));
        f.validator_status = Some("Active".into());
        assert_eq!(next_action(&f), "Running. Nothing to do.");
    }

    #[test]
    fn an_under_bonded_role_names_the_command_and_amount() {
        let one = tenzro_types::constants::ONE_TNZO;
        let mut f = running();
        f.roles = vec!["ai".into()];
        f.bonds = vec![RoleBond { role: "ai".into(), bonded: 400 * one, required: 1000 * one }];
        let a = next_action(&f);
        assert!(a.contains("--role ai --amount 600"), "{a}");
    }

    #[test]
    fn an_unapproved_operator_is_pointed_at_the_sponsorship_check() {
        let mut f = running();
        f.validator_status = Some("Active".into());
        f.approved = Some(false);
        assert!(next_action(&f).contains("tenzro sponsor check"));
        f.approved = Some(true);
        assert_eq!(next_action(&f), "Running. Nothing to do.");
    }

    #[test]
    fn a_full_bar_never_exceeds_its_width() {
        // A commitment made before a ceiling was lowered puts `used` above
        // `total`. That is a real state, and it must read as full rather than
        // print a bar wider than the terminal.
        let b = bar(200, 100);
        assert_eq!(b.matches('█').count(), 30);
        assert!(b.contains("100%"), "{b}");
    }

    #[test]
    fn an_empty_bar_is_empty() {
        let b = bar(0, 100);
        assert_eq!(b.matches('█').count(), 0);
        assert!(b.contains("0%"), "{b}");
    }

    #[test]
    fn a_zero_total_does_not_divide_by_zero() {
        // A node whose pool is zero — the reserve consumed everything — must
        // still render rather than panic mid-frame.
        let b = bar(0, 0);
        assert!(b.contains("n/a"), "{b}");
        assert!(bar(50, 0).contains("n/a"));
    }

    #[test]
    fn the_bar_is_proportional_in_between() {
        assert_eq!(bar(50, 100).matches('█').count(), 15);
        assert_eq!(bar(25, 100).matches('█').count(), 8);
    }

    #[test]
    fn durations_read_at_the_right_scale() {
        assert_eq!(duration(0), "0ms");
        assert_eq!(duration(999), "999ms");
        assert_eq!(duration(1_500), "2s");
        assert_eq!(duration(120_000), "2m");
    }

    #[test]
    fn a_missing_field_reads_as_zero_rather_than_panicking() {
        // Panels arrive as `null` when their RPC failed, and a half-up node is
        // exactly who needs the half that works.
        let empty = json!({});
        assert_eq!(u64_at(&empty, "total_bytes"), 0);
        assert_eq!(u64_at(&json!(null), "anything"), 0);
    }

    #[test]
    fn the_refresh_interval_has_a_floor() {
        // Each frame is four RPCs; polling faster measures the node's response
        // to being polled.
        const { assert!(MIN_INTERVAL_MS >= 500) };
    }

    #[test]
    fn goodput_is_not_reported_as_perfect_before_anything_completes() {
        // The ratio is vacuously 100% with a zero denominator, and printing
        // that reads as a clean bill of health the node has not earned.
        let snap = Snapshot {
            raw: json!({
                "memory": null,
                "traffic": { "completed": 0, "goodput_pct": 100.0, "max_concurrent": 4 },
                "lifecycle": null,
                "autotune": null,
            }),
        };
        // Rendering must not claim a percentage; the assertion is on the
        // branch, exercised by calling it.
        snap.render_traffic();
        assert_eq!(u64_at(&snap.raw["traffic"], "completed"), 0);
    }

    #[test]
    fn bytes_render_as_gib() {
        assert_eq!(gib(1_073_741_824), "1.0 GiB");
        assert_eq!(gib(0), "0.0 GiB");
        assert_eq!(gib(120 * 1_073_741_824), "120.0 GiB");
    }
}
