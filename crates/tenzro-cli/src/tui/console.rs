//! The console: what a node is doing, on five screens and a health screen,
//! read over the same RPC the commands use. It only reads; sending, signing
//! and every key operation stay in the commands, where the key is held by the
//! machine's hardware. Nothing secret is ever shown.
//!
//! Screens mirror the TypeScript console in `sdk/tenzro-tui`: Overview,
//! Wallet, Models, Validators, Governance, with the same keys, footer and help
//! overlay, plus Health for operators. The header always carries one status
//! word; when the node stops answering the last values stay on screen marked
//! STALE rather than disappearing or passing for live.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::keys::{self, Act, CONSOLE, SCREENS};
use super::theme::{Theme, Word};
use super::ui;

/// One reading from the node: what it said and when, or why it could not.
#[derive(Debug, Clone)]
pub enum Reading<T> {
    Pending,
    Ok { value: T, at: Instant },
    Err { error: String, at: Instant, last: Option<(T, Instant)> },
}

impl<T: Clone> Reading<T> {
    fn from(result: Result<T, String>, prev: &Reading<T>) -> Self {
        let now = Instant::now();
        match result {
            Ok(value) => Reading::Ok { value, at: now },
            Err(error) => {
                let last = match prev {
                    Reading::Ok { value, at } => Some((value.clone(), *at)),
                    Reading::Err { last, .. } => last.clone(),
                    Reading::Pending => None,
                };
                Reading::Err { error, at: now, last }
            }
        }
    }

    /// The value, or the last good one.
    pub fn value(&self) -> Option<&T> {
        match self {
            Reading::Ok { value, .. } => Some(value),
            Reading::Err { last: Some((v, _)), .. } => Some(v),
            _ => None,
        }
    }

    pub fn is_stale(&self) -> bool {
        matches!(self, Reading::Err { last: Some(_), .. })
    }

    pub fn error(&self) -> Option<&str> {
        match self {
            Reading::Err { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Whether the key holder's grant still works.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    /// This node keeps its keys in its own hardware.
    NotUsed,
    Valid,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub status: Reading<Value>,
    pub chain_id: Reading<String>,
    pub syncing: Reading<bool>,
    pub finalized: Reading<u64>,
    pub models: Reading<Vec<Value>>,
    pub validators: Reading<Vec<Value>>,
    pub proposals: Reading<(Vec<Value>, u64)>,
    pub balance: Reading<(String, u128)>,
    pub validator_state: Reading<Value>,
    pub grant: Reading<Grant>,
}

impl Snapshot {
    pub fn empty() -> Self {
        Self {
            status: Reading::Pending,
            chain_id: Reading::Pending,
            syncing: Reading::Pending,
            finalized: Reading::Pending,
            models: Reading::Pending,
            validators: Reading::Pending,
            proposals: Reading::Pending,
            balance: Reading::Pending,
            validator_state: Reading::Pending,
            grant: Reading::Pending,
        }
    }
}

fn hex_u64(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}

fn list_of(v: Value, key: &str) -> Vec<Value> {
    match v {
        Value::Array(a) => a,
        Value::Object(mut o) => match o.remove(key) {
            Some(Value::Array(a)) => a,
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Read everything the screens show.
pub async fn collect(url: &str, account: Option<String>, prev: &Snapshot, holder: Option<(String, String)>) -> Snapshot {
    let rpc = crate::rpc::RpcClient::new(url);
    let call = |method: &'static str, params: Value| {
        let rpc = &rpc;
        async move {
            match tokio::time::timeout(Duration::from_secs(4), rpc.call::<Value>(method, params)).await {
                Err(_) => Err("timed out".to_string()),
                Ok(Err(e)) => Err(e.to_string()),
                Ok(Ok(v)) => Ok(v),
            }
        }
    };
    let (status, chain, sync, fin, models, vals, props) = tokio::join!(
        call("tenzro_getNodeStatus", json!([])),
        call("eth_chainId", json!([])),
        call("eth_syncing", json!([])),
        call("eth_getBlockByNumber", json!(["finalized", false])),
        call("tenzro_listModels", json!({ "loaded": true })),
        call("tenzro_listValidators", json!({})),
        call("tenzro_listProposals", json!({ "limit": 25 })),
    );
    let balance = match &account {
        Some(a) => Some((a.clone(), call("eth_getBalance", json!([a, "latest"])).await)),
        None => None,
    };
    let payee = status.as_ref().ok().and_then(|s| s.get("payee")).and_then(Value::as_str).map(str::to_string);
    let is_validator = status
        .as_ref()
        .ok()
        .and_then(|s| s.get("roles"))
        .map(|r| r.to_string().contains("alidator"))
        .unwrap_or(false);
    let vstate = match (&payee, is_validator) {
        (Some(p), true) => Some(call("tenzro_getValidatorState", json!({ "address": p })).await),
        _ => None,
    };
    let grant = match holder {
        None => Ok(Grant::NotUsed),
        Some((socket, label)) => Ok(check_grant(&socket, &label).await),
    };
    Snapshot {
        status: Reading::from(status, &prev.status),
        chain_id: Reading::from(chain.map(|v| v.as_str().unwrap_or("").to_string()), &prev.chain_id),
        syncing: Reading::from(sync.map(|v| !(v == Value::Bool(false) || v.is_null())), &prev.syncing),
        finalized: Reading::from(
            fin.map(|v| v.get("number").and_then(Value::as_str).map(hex_u64).unwrap_or(0)),
            &prev.finalized,
        ),
        models: Reading::from(models.map(|v| list_of(v, "models")), &prev.models),
        validators: Reading::from(vals.map(|v| list_of(v, "validators")), &prev.validators),
        proposals: Reading::from(
            props.map(|v| {
                let total = v.get("total").and_then(Value::as_u64).unwrap_or(0);
                let items = list_of(v, "proposals");
                let total = total.max(items.len() as u64);
                (items, total)
            }),
            &prev.proposals,
        ),
        balance: match balance {
            Some((a, r)) => Reading::from(
                r.map(|v| (a.clone(), crate::rpc::parse_hex_u128(v.as_str().unwrap_or("0x0")))),
                &prev.balance,
            ),
            None => Reading::Pending,
        },
        validator_state: match vstate {
            Some(r) => Reading::from(r, &prev.validator_state),
            None => Reading::Pending,
        },
        grant: Reading::from(grant, &prev.grant),
    }
}

/// Ask the provider, through the key holder, to sign something. Fails when
/// the grant is missing or over.
async fn check_grant(socket: &str, label: &str) -> Grant {
    let Some(node) = crate::commands::setup::locate_node_binary() else {
        return Grant::Failed("tenzro-node was not found".into());
    };
    let (socket, label) = (socket.to_string(), label.to_string());
    let run = tokio::task::spawn_blocking(move || {
        std::process::Command::new(node)
            .args(["tpm", "remote-check", "--key-holder", &socket, "--label", &label])
            .stdin(std::process::Stdio::null())
            .output()
    });
    match tokio::time::timeout(Duration::from_secs(20), run).await {
        Ok(Ok(Ok(out))) if out.status.success() => Grant::Valid,
        Ok(Ok(Ok(out))) => {
            let msg = String::from_utf8_lossy(&out.stderr);
            let first = msg.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("the check failed");
            Grant::Failed(first.trim().to_string())
        }
        _ => Grant::Failed("the check did not finish".into()),
    }
}

/// The one-word state. UNKNOWN is a state, never green. Pure.
pub fn headline(s: &Snapshot) -> (Word, String) {
    match &s.status {
        Reading::Pending => (Word::Unknown, "waiting for the first answer".into()),
        Reading::Err { error, last: None, .. } => (Word::Down, error.lines().next().unwrap_or("").to_string()),
        Reading::Err { last: Some(_), .. } => (Word::Unknown, "the node stopped answering; showing the last values".into()),
        Reading::Ok { value, .. } => {
            let state = value.get("state").and_then(Value::as_str).unwrap_or("Running");
            if state != "Running" {
                return (Word::Watch, format!("node state is {state}"));
            }
            if let Some(h) = value.get("health_status").and_then(Value::as_str)
                && h != "Healthy"
            {
                return (Word::Watch, format!("node health is {h}"));
            }
            if s.syncing.value() == Some(&true) {
                return (Word::Watch, "the node is catching up with the network".into());
            }
            if let Reading::Ok { value: Grant::Failed(why), .. } | Reading::Err { last: Some((Grant::Failed(why), _)), .. } = &s.grant {
                return (Word::Action, format!("the key holder's grant does not work: {why}"));
            }
            (Word::Ok, "the node is running and healthy".into())
        }
    }
}

pub fn fmt_age(secs: u64) -> String {
    match secs {
        0..=1 => "just now".into(),
        2..=59 => format!("{secs} s ago"),
        60..=3599 => format!("{} min ago", secs / 60),
        _ => format!("{} h ago", secs / 3600),
    }
}

pub fn fmt_duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    if d > 0 {
        format!("{d} d {h} h")
    } else if h > 0 {
        format!("{h} h {m} min")
    } else {
        format!("{m} min {} s", secs % 60)
    }
}

pub fn short_id(s: &str, head: usize, tail: usize) -> String {
    if s.chars().count() <= head + tail + 2 {
        s.to_string()
    } else {
        let h: String = s.chars().take(head).collect();
        let t: String = s.chars().rev().take(tail).collect::<Vec<_>>().into_iter().rev().collect();
        format!("{h}..{t}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Leave {
    Quit,
    /// Show the full command menu, then come back.
    More,
}

pub struct Console {
    pub theme: Theme,
    pub url: String,
    pub screen: usize,
    pub sel: usize,
    pub help: bool,
    pub edit: Option<String>,
    pub snap: Snapshot,
    pub leave: Option<Leave>,
    pub account: Arc<Mutex<Option<String>>>,
    rx: Receiver<Snapshot>,
    refresh: Arc<Notify>,
    tick_started: Instant,
}

impl Console {
    /// Build the console and start reading the node every five seconds.
    pub fn start(url: &str, theme: Theme, handle: &tokio::runtime::Handle) -> Self {
        let (tx, rx) = channel::<Snapshot>();
        let refresh = Arc::new(Notify::new());
        let cfg = crate::config::load_config();
        let account = Arc::new(Mutex::new(cfg.wallet_address.clone()));
        let holder = match (&cfg.key_holder_socket, &cfg.key_holder_label) {
            (Some(s), Some(l)) => Some((s.clone(), l.clone())),
            _ => None,
        };
        spawn_reader(handle, url.to_string(), account.clone(), refresh.clone(), tx, holder);
        let mut c = Self::offline(url, theme);
        c.rx = rx;
        c.refresh = refresh;
        c.account = account;
        c
    }

    /// A console with no reader (tests and the pending screen).
    pub fn offline(url: &str, theme: Theme) -> Self {
        let (_tx, rx) = channel();
        Self {
            theme,
            url: url.to_string(),
            screen: 0,
            sel: 0,
            help: false,
            edit: None,
            snap: Snapshot::empty(),
            leave: None,
            account: Arc::new(Mutex::new(None)),
            rx,
            refresh: Arc::new(Notify::new()),
            tick_started: Instant::now(),
        }
    }

    pub fn tick(&mut self) {
        while let Ok(s) = self.rx.try_recv() {
            self.snap = s;
        }
        let _ = self.tick_started;
    }

    pub fn on_key(&mut self, name: &str) {
        if let Some(buf) = self.edit.as_mut() {
            match name {
                "Esc" => self.edit = None,
                "Enter" => {
                    let v = buf.trim().to_string();
                    self.edit = None;
                    if let Ok(mut a) = self.account.lock() {
                        *a = if v.is_empty() { None } else { Some(v) };
                    }
                    self.refresh.notify_one();
                }
                "Backspace" => {
                    buf.pop();
                }
                "Ctrl-C" => self.leave = Some(Leave::Quit),
                n if n.chars().count() == 1 => buf.push_str(n),
                _ => {}
            }
            return;
        }
        let Some(act) = keys::act_for(CONSOLE, name) else { return };
        if self.help {
            match act {
                Act::Help | Act::Close => self.help = false,
                Act::Quit => self.leave = Some(Leave::Quit),
                _ => {}
            }
            return;
        }
        let n = SCREENS.len();
        match act {
            Act::Screen(i) => {
                self.screen = i;
                self.sel = 0;
            }
            Act::Next => {
                self.screen = (self.screen + 1) % n;
                self.sel = 0;
            }
            Act::Prev => {
                self.screen = (self.screen + n - 1) % n;
                self.sel = 0;
            }
            Act::Down => self.sel = self.sel.saturating_add(1).min(self.rows().saturating_sub(1)),
            Act::Up => self.sel = self.sel.saturating_sub(1),
            Act::Refresh => self.refresh.notify_one(),
            Act::Edit if self.screen == 1 => self.edit = Some(String::new()),
            Act::More => self.leave = Some(Leave::More),
            Act::Help => self.help = true,
            Act::Quit => self.leave = Some(Leave::Quit),
            _ => {}
        }
    }

    fn rows(&self) -> usize {
        match self.screen {
            2 => self.snap.models.value().map_or(0, Vec::len),
            3 => self.snap.validators.value().map_or(0, Vec::len),
            4 => self.snap.proposals.value().map_or(0, |p| p.0.len()),
            _ => 0,
        }
    }

    // ---- drawing ------------------------------------------------------

    pub fn view(&self, f: &mut Frame) {
        let t = &self.theme;
        if ui::too_small(f, t) {
            return;
        }
        let (h, body, ft) = ui::bands(f.area());
        let (word, reason) = headline(&self.snap);
        let height = self.snap.status.value().and_then(|s| s.get("block_height")).and_then(Value::as_u64);
        let mut right = vec![Span::styled(format!(" {} ", word.text()), t.status(word))];
        if let Some(hh) = height {
            right.push(Span::styled(format!(" height {hh} "), t.muted()));
        }
        if self.snap.status.is_stale() {
            right.push(Span::styled(" STALE ", t.status(Word::Watch)));
        }
        let right_w = right.iter().map(|s| s.width() as u16).sum::<u16>().min(h.width / 2);
        let prefix_w = " tenzro ".len() as u16 + 1 + self.url.len() as u16 + 2;
        let reason_w = h.width.saturating_sub(right_w).saturating_sub(prefix_w) as usize;
        ui::header(f, h, t, &format!("{}  {}", self.url, ui::clip(&reason, reason_w)), right);
        let [tabs, content] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(body);
        let mut spans = Vec::new();
        for (i, (k, name)) in SCREENS.iter().enumerate() {
            let style = if i == self.screen { t.selected() } else { t.muted() };
            spans.push(Span::styled(format!(" {k} {name} "), style));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), tabs);
        match self.screen {
            0 => self.overview(f, content),
            1 => self.wallet(f, content),
            2 => self.models(f, content),
            3 => self.validators(f, content),
            4 => self.governance(f, content),
            _ => self.health(f, content),
        }
        let foot = if self.edit.is_some() {
            "type an address, Enter to use it, Esc to cancel".to_string()
        } else {
            keys::footer(CONSOLE)
        };
        ui::footer(f, ft, t, &foot);
        if self.help {
            ui::help(f, t, CONSOLE, "Keys");
        }
    }

    fn kv(&self, k: &str, v: String) -> Line<'static> {
        Line::from(vec![Span::styled(format!(" {k:<14}"), self.theme.muted()), Span::raw(v)])
    }

    fn down_notice(&self) -> Option<Vec<Line<'static>>> {
        let t = &self.theme;
        match &self.snap.status {
            Reading::Err { error, last: None, .. } => {
                let mut v = vec![
                    Line::from(""),
                    Line::from(vec![Span::styled(" DOWN ", t.status(Word::Down)), Span::styled("Cannot reach a Tenzro node", t.bold())]),
                    Line::from(""),
                ];
                for l in error.lines() {
                    v.push(Line::from(format!(" {l}")));
                }
                v.push(Line::from(""));
                v.push(Line::from(Span::styled(" This screen refreshes by itself; press r to try now.", t.muted())));
                Some(v)
            }
            Reading::Pending => Some(vec![Line::from(""), Line::from(Span::styled(" Waiting for the node ...", t.muted()))]),
            _ => None,
        }
    }

    fn overview(&self, f: &mut Frame, area: Rect) {
        if let Some(n) = self.down_notice() {
            f.render_widget(Paragraph::new(n).wrap(Wrap { trim: false }), area);
            return;
        }
        let t = &self.theme;
        let s = self.snap.status.value().cloned().unwrap_or(Value::Null);
        let g = |k: &str| s.get(k).and_then(Value::as_str).unwrap_or("-").to_string();
        let roles = match s.get("roles") {
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "),
            Some(Value::String(x)) => x.clone(),
            _ => "-".into(),
        };
        let mut left = vec![Line::from(Span::styled(" Node", t.title()))];
        left.push(self.kv("State", g("state")));
        left.push(self.kv("Health", g("health_status")));
        left.push(self.kv("Uptime", s.get("uptime_secs").and_then(Value::as_u64).map_or("-".into(), fmt_duration)));
        left.push(self.kv("Roles", roles));
        left.push(Line::from(""));
        left.push(Line::from(Span::styled(" Identity", t.title())));
        left.push(self.kv("Machine", short_id(&g("machine_did"), 24, 8)));
        left.push(self.kv("Pays out to", short_id(&g("payee"), 12, 8)));
        let mut right = vec![Line::from(Span::styled(" Chain", t.title()))];
        right.push(self.kv("Chain id", self.snap.chain_id.value().map_or("-".into(), |c| if c.starts_with("0x") { hex_u64(c).to_string() } else { c.clone() })));
        right.push(self.kv("Height", s.get("block_height").and_then(Value::as_u64).map_or("-".into(), |h| h.to_string())));
        right.push(self.kv("Finalized", self.snap.finalized.value().map_or("-".into(), |h| h.to_string())));
        right.push(self.kv("Syncing", self.snap.syncing.value().map_or("-".into(), |b| if *b { "yes".into() } else { "no".into() })));
        right.push(self.kv("Peers", s.get("peer_count").and_then(Value::as_u64).map_or("-".into(), |p| p.to_string())));
        let [l, r] = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
        f.render_widget(Paragraph::new(left), l);
        f.render_widget(Paragraph::new(right), r);
    }

    fn wallet(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let acct = self.account.lock().ok().and_then(|a| a.clone());
        let mut v = vec![Line::from(Span::styled(" Wallet", t.title())), Line::from("")];
        if let Some(b) = &self.edit {
            v.push(Line::from(vec![Span::raw(" Account: "), Span::styled(format!("{b}_"), t.bold())]));
        } else if acct.is_none() {
            v.push(Line::from(" No account is chosen yet. Press e and type an address."));
            v.push(Line::from(Span::styled(" Setup saves yours; sending and signing stay in the tenzro commands.", t.muted())));
        } else {
            match &self.snap.balance {
                Reading::Ok { value: (a, wei), .. } | Reading::Err { last: Some(((a, wei), _)), .. } => {
                    v.push(self.kv("Account", a.clone()));
                    v.push(self.kv("Balance", format!("{} TNZO", crate::rpc::format_tnzo(*wei))));
                    if self.snap.balance.is_stale() {
                        v.push(Line::from(Span::styled(" STALE: the node did not answer the last time.", t.status(Word::Watch))));
                    }
                }
                Reading::Err { error, .. } => {
                    v.push(self.kv("Account", acct.unwrap_or_default()));
                    v.push(Line::from(format!(" Could not read the balance: {}", error.lines().next().unwrap_or(""))));
                }
                Reading::Pending => v.push(Line::from(" Reading ...")),
            }
        }
        f.render_widget(Paragraph::new(v), area);
    }

    fn table(&self, f: &mut Frame, area: Rect, heads: &[&str], widths: &[Constraint], rows: Vec<Vec<String>>, empty: &str) {
        let t = &self.theme;
        if rows.is_empty() {
            f.render_widget(Paragraph::new(vec![Line::from(""), Line::from(format!(" {empty}"))]), area);
            return;
        }
        let head = Row::new(heads.iter().map(|h| Cell::from(*h)).collect::<Vec<_>>()).style(t.title());
        let body: Vec<Row> = rows.into_iter().map(|r| Row::new(r.into_iter().map(Cell::from).collect::<Vec<_>>())).collect();
        let mut st = TableState::default();
        st.select(Some(self.sel));
        let table = Table::new(body, widths.to_vec())
            .header(head)
            .row_highlight_style(t.selected())
            .block(Block::default().borders(Borders::NONE));
        f.render_stateful_widget(table, area, &mut st);
    }

    fn models(&self, f: &mut Frame, area: Rect) {
        if let Some(e) = self.snap.models.error().filter(|_| self.snap.models.value().is_none()) {
            f.render_widget(Paragraph::new(format!(" Could not read models: {}", e.lines().next().unwrap_or(""))), area);
            return;
        }
        let yn = |v: &Value, k: &str| if v.get(k).and_then(Value::as_bool).unwrap_or(false) { "yes" } else { "no" }.to_string();
        let rows = self
            .snap
            .models
            .value()
            .map(|m| {
                m.iter()
                    .map(|x| {
                        vec![
                            x.get("model_id").and_then(Value::as_str).unwrap_or("-").to_string(),
                            x.get("type").or_else(|| x.get("model_type")).and_then(Value::as_str).unwrap_or("-").to_string(),
                            x.get("engine").and_then(Value::as_str).unwrap_or("-").to_string(),
                            x.get("visibility").and_then(Value::as_str).unwrap_or("-").to_string(),
                            yn(x, "loaded"),
                            yn(x, "serving"),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.table(
            f, area,
            &["MODEL", "TYPE", "ENGINE", "VISIBLE", "LOADED", "SERVING"],
            &[Constraint::Min(24), Constraint::Length(10), Constraint::Length(12), Constraint::Length(9), Constraint::Length(7), Constraint::Length(8)],
            rows,
            "This node holds no models yet. `tenzro model list` shows what can be served.",
        );
    }

    fn validators(&self, f: &mut Frame, area: Rect) {
        let rows = self
            .snap
            .validators
            .value()
            .map(|m| {
                m.iter()
                    .map(|x| {
                        let wei = x.get("self_stake").and_then(Value::as_str).and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
                        vec![
                            short_id(x.get("address").and_then(Value::as_str).unwrap_or("-"), 12, 8),
                            x.get("status").and_then(Value::as_str).unwrap_or("-").to_string(),
                            format!("{} TNZO", crate::rpc::format_tnzo(wei)),
                            x.get("activated_at_epoch").and_then(Value::as_u64).map_or("-".into(), |e| format!("epoch {e}")),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.table(
            f, area,
            &["ADDRESS", "STATUS", "SELF STAKE", "ACTIVE SINCE"],
            &[Constraint::Length(24), Constraint::Length(12), Constraint::Length(24), Constraint::Min(12)],
            rows,
            "No validators are registered yet.",
        );
    }

    fn governance(&self, f: &mut Frame, area: Rect) {
        let rows = self
            .snap
            .proposals
            .value()
            .map(|(items, _)| {
                items
                    .iter()
                    .map(|x| {
                        let p = x.get("proposal").unwrap_or(x);
                        let tally = x.get("tally").unwrap_or(&Value::Null);
                        let n = |k: &str| tally.get(k).and_then(Value::as_str).and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
                        vec![
                            short_id(p.get("id").and_then(Value::as_str).unwrap_or("-"), 6, 6),
                            x.get("kind").and_then(Value::as_str).unwrap_or("-").to_string(),
                            p.get("status").map(|s| s.as_str().map(str::to_string).unwrap_or(s.to_string())).unwrap_or("-".into()),
                            format!("{} TNZO", crate::rpc::format_tnzo(n("yes"))),
                            format!("{} TNZO", crate::rpc::format_tnzo(n("no"))),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.table(
            f, area,
            &["PROPOSAL", "KIND", "STATUS", "YES", "NO"],
            &[Constraint::Length(16), Constraint::Min(20), Constraint::Length(12), Constraint::Length(18), Constraint::Length(18)],
            rows,
            "No proposals yet.",
        );
    }

    fn health(&self, f: &mut Frame, area: Rect) {
        if let Some(n) = self.down_notice() {
            f.render_widget(Paragraph::new(n).wrap(Wrap { trim: false }), area);
            return;
        }
        let t = &self.theme;
        let s = self.snap.status.value().cloned().unwrap_or(Value::Null);
        let line = |w: Word, label: &str, text: String| {
            Line::from(vec![Span::styled(format!(" {:<8}", w.text()), t.status(w)), Span::styled(format!("{label:<14}"), t.bold()), Span::raw(text)])
        };
        let mut v = Vec::new();
        let peers = s.get("peer_count").and_then(Value::as_u64);
        v.push(match peers {
            Some(0) => line(Word::Watch, "Peers", "none yet: the node cannot hear the network. Check the boot nodes and the firewall (tenzro-node doctor)".into()),
            Some(n) => line(Word::Ok, "Peers", n.to_string()),
            None => line(Word::Unknown, "Peers", "unknown".into()),
        });
        let height = s.get("block_height").and_then(Value::as_u64);
        v.push(match (height, self.snap.syncing.value()) {
            (_, Some(true)) => line(Word::Watch, "Sync", "catching up with the network".into()),
            (Some(0), _) if peers.unwrap_or(0) > 0 => line(Word::Ok, "Sync", "height 0 with peers is normal on a quiet chain; it moves at the next block".into()),
            (Some(h), _) => line(Word::Ok, "Sync", format!("at the tip, height {h}")),
            _ => line(Word::Unknown, "Sync", "unknown".into()),
        });
        let roles = match s.get("roles") {
            Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "),
            Some(Value::String(x)) => x.clone(),
            _ => String::new(),
        };
        v.push(line(if roles.is_empty() { Word::Watch } else { Word::Ok }, "Roles", if roles.is_empty() { "none".into() } else { roles.clone() }));
        if roles.contains("alidator") {
            let vs = self.snap.validator_state.value();
            let st = vs.and_then(|x| x.get("status")).and_then(Value::as_str);
            v.push(match st {
                Some("Active") => line(Word::Ok, "Validator", "active: your node votes".into()),
                Some(other) => line(Word::Watch, "Validator", format!("{other}: not voting yet. Registration needs approval during the preview; see the validator steps in tenzro setup")),
                None => line(Word::Action, "Validator", "not registered. Ask for admission at https://tenzro.com/join, then restart the node with --validator-self-stake (see the validator steps in tenzro)".into()),
            });
        }
        v.push(match self.snap.grant.value() {
            Some(Grant::Valid) => line(Word::Ok, "Key holder", "the grant works. It ends at most 720 hours after install and is lost if the key holder restarts".into()),
            Some(Grant::Failed(why)) => line(Word::Action, "Key holder", format!("the grant does not work: {why}. Renew it: tenzro-node tpm grant-request, sign with the passkey, tenzro-node tpm grant-install")),
            Some(Grant::NotUsed) | None => line(Word::Ok, "Key", "kept in this machine's own hardware; there is no grant to expire".into()),
        });
        let age = match &self.snap.status {
            Reading::Ok { at, .. } | Reading::Err { at, .. } => fmt_age(at.elapsed().as_secs()),
            Reading::Pending => "never".into(),
        };
        v.push(Line::from(""));
        v.push(Line::from(Span::styled(format!(" Updated {age}. To stop cleanly: tenzro-node graceful-exit. To leave the validator set: tenzro validator exit."), t.muted())));
        f.render_widget(Paragraph::new(v).wrap(Wrap { trim: false }), area);
    }
}

fn spawn_reader(
    handle: &tokio::runtime::Handle,
    url: String,
    account: Arc<Mutex<Option<String>>>,
    refresh: Arc<Notify>,
    tx: Sender<Snapshot>,
    holder: Option<(String, String)>,
) {
    handle.spawn(async move {
        let mut prev = Snapshot::empty();
        let mut last_grant: Option<Instant> = None;
        loop {
            let acct = account.lock().ok().and_then(|a| a.clone());
            // The grant check asks the provider's TPM: once a minute, not every refresh.
            let check_now = holder.is_some() && last_grant.is_none_or(|t| t.elapsed() > Duration::from_secs(60));
            let h = if check_now { holder.clone() } else { None };
            let mut next = collect(&url, acct, &prev, h).await;
            if holder.is_some() && !check_now {
                next.grant = prev.grant.clone();
            }
            if check_now {
                last_grant = Some(Instant::now());
            }
            prev = next.clone();
            if tx.send(next).is_err() {
                break;
            }
            tokio::select! {
                _ = refresh.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::Depth;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn screen(c: &Console, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| c.view(f)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>().trim_end().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn live() -> Console {
        let mut c = Console::offline("http://127.0.0.1:8545", Theme::with_depth(Depth::None));
        let now = Instant::now();
        c.snap.status = Reading::Ok {
            value: json!({"state":"Running","health_status":"Healthy","block_height":42,"peer_count":3,"roles":["validator"],"uptime_secs":3700,"payee":"0xabc","machine_did":"did:tenzro:machine:xyz"}),
            at: now,
        };
        c.snap.chain_id = Reading::Ok { value: "0x539".into(), at: now };
        c.snap.syncing = Reading::Ok { value: false, at: now };
        c.snap.finalized = Reading::Ok { value: 40, at: now };
        c.snap.models = Reading::Ok { value: vec![json!({"model_id":"qwen","type":"text","loaded":true,"serving":true,"visibility":"public"})], at: now };
        c.snap.validators = Reading::Ok { value: vec![json!({"address":"0x1234567890abcdef1234567890abcdef","status":"Active","self_stake":"10000000000000000000000"})], at: now };
        c.snap.proposals = Reading::Ok { value: (vec![], 0), at: now };
        c.snap.grant = Reading::Ok { value: Grant::NotUsed, at: now };
        c
    }

    #[test]
    fn every_screen_draws_at_both_sizes_with_the_status_word() {
        for (w, h) in [(80, 24), (120, 40)] {
            let mut c = live();
            for (i, (key, name)) in SCREENS.iter().enumerate() {
                c.on_key(key);
                let s = screen(&c, w, h);
                assert!(s.contains("OK"), "screen {i} at {w}x{h}:\n{s}");
                assert!(s.contains(name));
                assert!(!s.contains('\u{1b}'));
            }
        }
    }

    #[test]
    fn a_node_that_is_down_says_what_why_fix_and_never_looks_live() {
        let mut c = Console::offline("http://127.0.0.1:8545", Theme::with_depth(Depth::None));
        let u = crate::friendly::explain(crate::friendly::Class::Refused, "http://127.0.0.1:8545");
        c.snap.status = Reading::Err {
            error: crate::friendly::Unreachable { url: "x".into(), class: crate::friendly::Class::Refused, detail: String::new(), explained: u }.to_string(),
            at: Instant::now(),
            last: None,
        };
        let s = screen(&c, 80, 24);
        assert!(s.contains("DOWN") && s.contains("Cannot reach") && s.contains("tenzro dev"), "{s}");
    }

    #[test]
    fn stale_data_is_marked_and_headline_is_unknown() {
        let mut c = live();
        let old = c.snap.status.clone();
        c.snap.status = Reading::from(Err("timed out".into()), &old);
        let (w, _) = headline(&c.snap);
        assert_eq!(w, Word::Unknown);
        assert!(screen(&c, 80, 24).contains("STALE"));
    }

    #[test]
    fn a_failed_key_holder_grant_is_an_action_not_ok() {
        let mut c = live();
        c.snap.grant = Reading::Ok { value: Grant::Failed("grant expired".into()), at: Instant::now() };
        assert_eq!(headline(&c.snap).0, Word::Action);
        c.on_key("6");
        let s = screen(&c, 80, 24);
        assert!(s.contains("ACTION") && s.contains("grant-install"), "{s}");
    }

    #[test]
    fn navigation_help_and_quit_use_the_shared_keys() {
        let mut c = live();
        c.on_key("Tab");
        assert_eq!(c.screen, 1);
        c.on_key("Shift-Tab");
        c.on_key("Shift-Tab");
        assert_eq!(c.screen, 5);
        c.on_key("?");
        assert!(screen(&c, 80, 24).contains("Quit and restore the terminal"));
        c.on_key("Esc");
        assert!(!c.help);
        c.on_key("m");
        assert_eq!(c.leave, Some(Leave::More));
        c.leave = None;
        c.on_key("q");
        assert_eq!(c.leave, Some(Leave::Quit));
    }

    #[test]
    fn the_account_can_be_edited_only_on_the_wallet_screen() {
        let mut c = live();
        c.on_key("e");
        assert!(c.edit.is_none());
        c.on_key("2");
        c.on_key("e");
        for k in ["0", "x", "1"] {
            c.on_key(k);
        }
        c.on_key("Enter");
        assert_eq!(c.account.lock().unwrap().as_deref(), Some("0x1"));
    }

    #[test]
    fn formats() {
        assert_eq!(fmt_age(0), "just now");
        assert_eq!(fmt_age(90), "1 min ago");
        assert_eq!(fmt_duration(3700), "1 h 1 min");
        assert_eq!(short_id("0123456789abcdef0123456789", 6, 4), "012345..6789");
        assert_eq!(hex_u64("0x10"), 16);
    }
}
