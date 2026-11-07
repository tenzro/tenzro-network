//! The first-run screens: welcome, what this machine can do, one question,
//! then the steps of the chosen path, ending in exactly one next command.
//!
//! `App` holds all the state and takes keys and ticks; it draws into any
//! ratatui frame, so the tests drive it with a test backend at 80x24 and
//! 120x40. Everything that touches the machine (probing, running a step's
//! command) goes through `detect` and `runner`.

use std::sync::mpsc::{Receiver, Sender, channel};

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::detect::{self, Finding, Machine, Net};
use super::journey::{self, Action, Blocked, Gate, Offer, Opts, Path, Plan, Step};
use super::keys::{self, Act, SETUP};
use super::runner::{self, Msg, Running};
use super::theme::{Theme, Word};
use super::ui;

/// How the first-run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Quit,
    /// Setup finished; `next` is the one command to run.
    Finished { next: String },
}

/// Results sent back from background work.
pub enum Probe {
    Machine(Box<Machine>),
    Net(Net),
    Waited(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    Welcome,
    Detect,
    Choose,
    Blocked,
    Steps,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepState {
    Pending,
    Done,
    Skipped,
    Failed(String),
}

pub struct App {
    pub theme: Theme,
    pub stage: Stage,
    pub rpc: String,
    pub machine: Option<Machine>,
    pub net: Net,
    pub choose_sel: usize,
    pub path: Option<Path>,
    pub opts: Option<Opts>,
    pub plan: Option<Plan>,
    pub blocked_sel: usize,
    pub idx: usize,
    pub states: Vec<StepState>,
    pub log: Vec<String>,
    pub typed: Option<String>,
    pub help: bool,
    pub quit_confirm: bool,
    pub detect_scroll: u16,
    pub outcome: Option<Outcome>,
    running: Option<Running>,
    waiting: bool,
    captured: Vec<String>,
    tx: Sender<Probe>,
    rx: Receiver<Probe>,
    handle: Option<tokio::runtime::Handle>,
}

impl App {
    pub fn new(rpc: &str, theme: Theme, handle: Option<tokio::runtime::Handle>) -> Self {
        let (tx, rx) = channel();
        Self {
            theme,
            stage: Stage::Welcome,
            rpc: rpc.to_string(),
            machine: None,
            net: Net::Checking,
            choose_sel: 0,
            path: None,
            opts: None,
            plan: None,
            blocked_sel: 0,
            idx: 0,
            states: Vec::new(),
            log: Vec::new(),
            typed: None,
            help: false,
            quit_confirm: false,
            detect_scroll: 0,
            outcome: None,
            running: None,
            waiting: false,
            captured: Vec::new(),
            tx,
            rx,
            handle,
        }
    }

    /// Start reading the machine and checking the network in the background.
    pub fn start_probes(&self) {
        if let Some(h) = &self.handle {
            let tx = self.tx.clone();
            h.spawn(async move {
                let m = detect::probe().await;
                let _ = tx.send(Probe::Machine(Box::new(m)));
            });
            let tx = self.tx.clone();
            let url = self.rpc.clone();
            h.spawn(async move {
                let n = detect::check_network(&url).await;
                let _ = tx.send(Probe::Net(n));
            });
        }
    }

    /// Feed a result in directly (tests, and the probes' own channel).
    pub fn deliver(&mut self, p: Probe) {
        match p {
            Probe::Machine(m) => {
                self.opts = Some(Opts::defaults(&m, &self.rpc));
                self.machine = Some(*m);
            }
            Probe::Net(n) => self.net = n,
            Probe::Waited(ok) => {
                self.waiting = false;
                if self.stage == Stage::Steps {
                    if ok {
                        self.states[self.idx] = StepState::Done;
                        self.log.push("The node answers.".into());
                    } else {
                        self.states[self.idx] = StepState::Failed("the node did not answer within a minute".into());
                        self.log.push("The node did not answer within a minute. Look at its log, then press Enter to wait again.".into());
                    }
                }
            }
        }
    }

    /// Whether a step's command (or a wait) is in progress.
    pub fn busy(&self) -> bool {
        self.running.is_some() || self.waiting
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(r) = &self.running {
            r.kill();
        }
    }
}

impl App {

    /// Drain background results and command output.
    pub fn tick(&mut self) {
        while let Ok(p) = self.rx.try_recv() {
            self.deliver(p);
        }
        let mut finished = None;
        if let Some(r) = &self.running {
            while let Ok(m) = r.rx.try_recv() {
                match m {
                    Msg::Line(l) => {
                        let l = l.trim_end().to_string();
                        self.captured.push(l.clone());
                        self.log.push(l);
                        if self.log.len() > 500 {
                            self.log.remove(0);
                        }
                    }
                    Msg::Exit(code) => {
                        finished = Some(code);
                        break;
                    }
                }
            }
        }
        if let Some(code) = finished {
            self.running = None;
            self.finish_step(code);
        }
    }

    fn step(&self) -> Option<&Step> {
        self.plan.as_ref().and_then(|p| p.steps.get(self.idx))
    }

    fn finish_step(&mut self, code: Option<i32>) {
        let step = self.step().cloned();
        let Some(step) = step else { return };
        if code == Some(0) {
            if let Action::Exec { save_as: Some(name), .. } = &step.action {
                let dir = self.opts.as_ref().map(|o| o.data_dir.clone()).unwrap_or_default();
                match runner::save_output(&dir, name, &self.captured.join("\n")) {
                    Ok(p) => self.log.push(format!("Kept the list in {}", p.display())),
                    Err(e) => self.log.push(format!("Could not keep the list: {e}")),
                }
            }
            if step.id == "holder-check"
                && let Some(o) = &self.opts
            {
                let mut cfg = crate::config::load_config();
                cfg.key_holder_socket = Some(o.holder_socket.clone());
                cfg.key_holder_label = Some(o.holder_label.clone());
                let _ = crate::config::save_config(&cfg);
            }
            self.states[self.idx] = StepState::Done;
        } else {
            let why = match code {
                Some(c) => format!("it stopped with exit code {c}"),
                None => "it was stopped".into(),
            };
            self.states[self.idx] = StepState::Failed(why);
        }
    }

    // ---- keys ---------------------------------------------------------

    pub fn on_key(&mut self, name: &str) {
        if self.help {
            if name == "Esc" || name == "?" {
                self.help = false;
            } else if name == "q" || name == "Ctrl-C" {
                self.request_quit();
            }
            return;
        }
        if self.quit_confirm {
            if name == "y" {
                if let Some(r) = &self.running {
                    r.kill();
                }
                self.outcome = Some(Outcome::Quit);
            } else {
                self.quit_confirm = false;
            }
            return;
        }
        if self.typed.is_some() {
            self.on_typed(name);
            return;
        }
        let Some(act) = keys::act_for(SETUP, name) else { return };
        match act {
            Act::Quit => self.request_quit(),
            Act::Help => self.help = true,
            Act::Close => {}
            _ => match self.stage {
                Stage::Welcome => {
                    if act == Act::Go {
                        self.stage = Stage::Detect;
                    }
                }
                Stage::Detect => self.on_detect(act),
                Stage::Choose => self.on_choose(act),
                Stage::Blocked => self.on_blocked(act),
                Stage::Steps => self.on_steps(act),
                Stage::Done => match act {
                    Act::Go => {
                        let next = self.plan.as_ref().map(|p| p.next.clone()).unwrap_or_else(|| "tenzro".into());
                        self.outcome = Some(Outcome::Finished { next });
                    }
                    Act::Back => self.stage = Stage::Steps,
                    _ => {}
                },
            },
        }
    }

    fn request_quit(&mut self) {
        if self.busy() {
            self.quit_confirm = true;
        } else {
            self.outcome = Some(Outcome::Quit);
        }
    }

    fn on_detect(&mut self, act: Act) {
        match act {
            Act::Go if self.machine.is_some() && self.net != Net::Checking => self.stage = Stage::Choose,
            Act::Back => self.stage = Stage::Welcome,
            Act::Down => self.detect_scroll = self.detect_scroll.saturating_add(1),
            Act::Up => self.detect_scroll = self.detect_scroll.saturating_sub(1),
            _ => {}
        }
    }

    fn on_choose(&mut self, act: Act) {
        match act {
            Act::Down => self.choose_sel = (self.choose_sel + 1) % Path::ALL.len(),
            Act::Up => self.choose_sel = (self.choose_sel + Path::ALL.len() - 1) % Path::ALL.len(),
            Act::Pick(i) if i < Path::ALL.len() => {
                self.choose_sel = i;
                self.select(Path::ALL[i]);
            }
            Act::Go => self.select(Path::ALL[self.choose_sel]),
            Act::Back => self.stage = Stage::Detect,
            _ => {}
        }
    }

    /// Choose a path and plan it.
    pub fn select(&mut self, path: Path) {
        let (Some(m), Some(o)) = (self.machine.clone(), self.opts.clone()) else { return };
        self.path = Some(path);
        let plan = journey::plan(path, &m, &self.net, &o);
        self.states = vec![StepState::Pending; plan.steps.len()];
        self.idx = 0;
        self.log.clear();
        self.blocked_sel = 0;
        self.stage = if plan.blocked.is_some() { Stage::Blocked } else { Stage::Steps };
        self.plan = Some(plan);
    }

    fn blocked(&self) -> Option<&Blocked> {
        self.plan.as_ref().and_then(|p| p.blocked.as_ref())
    }

    fn on_blocked(&mut self, act: Act) {
        let n = self.blocked().map(|b| b.offers.len() + 1).unwrap_or(1);
        match act {
            Act::Down => self.blocked_sel = (self.blocked_sel + 1) % n,
            Act::Up => self.blocked_sel = (self.blocked_sel + n - 1) % n,
            Act::Back => self.stage = Stage::Choose,
            Act::Go => {
                let offer = self.blocked().and_then(|b| b.offers.get(self.blocked_sel).cloned());
                match offer {
                    Some(Offer::SwitchTo(p)) => self.select(p),
                    Some(Offer::Delegate) => {
                        if let Some(o) = self.opts.as_mut() {
                            o.delegated = true;
                        }
                        if let Some(p) = self.path {
                            self.select(p);
                        }
                    }
                    Some(Offer::Finish) => {
                        // Saves the settings so the next `tenzro` opens the console.
                        let _ = crate::config::save_config(&crate::config::load_config());
                        self.outcome = Some(Outcome::Finished { next: "tenzro".into() });
                    }
                    None => self.stage = Stage::Choose,
                }
            }
            _ => {}
        }
    }

    fn on_steps(&mut self, act: Act) {
        match act {
            Act::Back => {
                if self.busy() {
                    return;
                }
                if self.idx == 0 {
                    self.stage = Stage::Choose;
                } else {
                    self.idx -= 1;
                    self.log.clear();
                }
            }
            Act::Skip => {
                if self.busy() {
                    return;
                }
                if self.step().is_some_and(|s| s.skippable) {
                    self.states[self.idx] = StepState::Skipped;
                    self.advance();
                }
            }
            Act::Go => self.go(),
            _ => {}
        }
    }

    fn advance(&mut self) {
        self.log.clear();
        self.captured.clear();
        self.idx += 1;
        if self.idx >= self.states.len() {
            self.idx = self.states.len().saturating_sub(1);
            self.stage = Stage::Done;
        }
    }

    fn go(&mut self) {
        if self.busy() {
            return;
        }
        let Some(step) = self.step().cloned() else { return };
        // A finished step: continue.
        if matches!(self.states[self.idx], StepState::Done | StepState::Skipped) {
            self.advance();
            return;
        }
        match (&step.action, &step.gate) {
            (Action::None, _) => {
                self.states[self.idx] = StepState::Done;
                self.advance();
            }
            (_, Gate::Typed(_)) => self.typed = Some(String::new()),
            _ => self.run_step(&step),
        }
    }

    fn on_typed(&mut self, name: &str) {
        let Some(step) = self.step().cloned() else { return };
        let Gate::Typed(word) = step.gate else { self.typed = None; return };
        let buf = self.typed.get_or_insert_with(String::new);
        match name {
            "Esc" => self.typed = None,
            "Ctrl-C" => {
                self.typed = None;
                self.request_quit();
            }
            "Backspace" => {
                buf.pop();
            }
            "Enter" => {
                if buf.trim().eq_ignore_ascii_case(word) {
                    self.typed = None;
                    self.run_step(&step);
                }
            }
            n if n.chars().count() == 1 => buf.push_str(n),
            _ => {}
        }
    }

    fn run_step(&mut self, step: &Step) {
        self.log.clear();
        self.captured.clear();
        match &step.action {
            Action::None => {}
            Action::Exec { prog, args, detached: true, .. } => {
                let dir = self.opts.as_ref().map(|o| o.data_dir.clone()).unwrap_or_default();
                let log = dir.join("node.log");
                match runner::spawn_detached(prog, args, &log) {
                    Ok(pid) => {
                        self.log.push(format!("Started (process {pid}). Its log: {}", log.display()));
                        self.states[self.idx] = StepState::Done;
                    }
                    Err(e) => self.states[self.idx] = StepState::Failed(e.to_string()),
                }
            }
            Action::Exec { prog, args, .. } => match runner::spawn(prog, args) {
                Ok(r) => self.running = Some(r),
                Err(e) => {
                    self.log.push(e.to_string());
                    self.states[self.idx] = StepState::Failed(e.to_string());
                }
            },
            Action::WaitRpc { url } => {
                if let Some(h) = &self.handle {
                    self.waiting = true;
                    self.log.push(format!("Waiting for {url} ..."));
                    let tx = self.tx.clone();
                    let url = url.clone();
                    h.spawn(async move {
                        let mut ok = false;
                        for _ in 0..30 {
                            if detect::check_network(&url).await.is_reachable() {
                                ok = true;
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                        let _ = tx.send(Probe::Waited(ok));
                    });
                }
            }
            Action::SaveLocalConfig => {
                let mut cfg = crate::config::load_config();
                cfg.endpoint = Some(crate::endpoint::LOCAL_RPC.to_string());
                match crate::config::save_config(&cfg) {
                    Ok(()) => {
                        self.log.push(format!("Saved to {}", crate::config::config_path().display()));
                        self.states[self.idx] = StepState::Done;
                    }
                    Err(e) => self.states[self.idx] = StepState::Failed(e.to_string()),
                }
            }
        }
    }

    // ---- drawing ------------------------------------------------------

    pub fn view(&self, f: &mut Frame) {
        if ui::too_small(f, &self.theme) {
            return;
        }
        let (h, body, ft) = ui::bands(f.area());
        let right = match self.stage {
            Stage::Steps | Stage::Done => {
                let n = self.states.len().max(1);
                vec![Span::styled(format!("step {} of {} ", (self.idx + 1).min(n), n), self.theme.muted())]
            }
            _ => vec![],
        };
        let ctx = match (&self.stage, self.path) {
            (Stage::Welcome, _) => "welcome".to_string(),
            (Stage::Detect, _) => "this machine".to_string(),
            (Stage::Choose, _) => "set up".to_string(),
            (_, Some(p)) => format!("set up: {}", p.label().to_lowercase()),
            _ => "set up".to_string(),
        };
        ui::header(f, h, &self.theme, &ctx, right);
        match self.stage {
            Stage::Welcome => self.draw_welcome(f, body),
            Stage::Detect => self.draw_detect(f, body),
            Stage::Choose => self.draw_choose(f, body),
            Stage::Blocked => self.draw_blocked(f, body),
            Stage::Steps => self.draw_steps(f, body),
            Stage::Done => self.draw_done(f, body),
        }
        ui::footer(f, ft, &self.theme, &self.footer_text());
        if self.help {
            ui::help(f, &self.theme, SETUP, "Keys");
        }
        if self.quit_confirm {
            let a = ui::centered(f.area(), 56, 5);
            f.render_widget(ratatui::widgets::Clear, a);
            f.render_widget(
                Paragraph::new(vec![
                    Line::from("A step is still running."),
                    Line::from("Press y to stop it and quit, or any other key to go on."),
                ])
                .block(Block::default().borders(Borders::ALL).title(" Quit? ")),
                a,
            );
        }
    }

    fn footer_text(&self) -> String {
        if self.typed.is_some() {
            return "type the word shown, then Enter  |  Esc cancels".into();
        }
        match self.stage {
            Stage::Welcome => "Enter begin  |  q quit".into(),
            Stage::Detect => "Enter continue  |  Up/Down scroll  |  b back  |  ? help  |  q quit".into(),
            Stage::Choose => "Up/Down or 1-4 choose  |  Enter select  |  b back  |  ? help  |  q quit".into(),
            Stage::Blocked => "Up/Down choose  |  Enter select  |  b back  |  q quit".into(),
            Stage::Steps => {
                let skip = if self.step().is_some_and(|s| s.skippable) { "  |  s skip" } else { "" };
                format!("Enter go  |  b back{skip}  |  ? help  |  q quit")
            }
            Stage::Done => "Enter finish  |  b back  |  q quit".into(),
        }
    }

    fn draw_welcome(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled("  Welcome to Tenzro", t.title())),
            Line::from(""),
            Line::from("  Tenzro is a network where people, AI agents and machines pay each other"),
            Line::from("  and share compute."),
            Line::from(""),
            Line::from("  It looks at this machine, asks you one question, and walks you through"),
            Line::from("  setting up. Every step shows the exact command before it runs, and"),
            Line::from("  your keys stay in your hardware."),
            Line::from(""),
            Line::from(vec![Span::raw("  Press "), Span::styled("Enter", t.command()), Span::raw(" to begin.")]),
        ];
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn finding_lines(&self, list: &[Finding], width: u16) -> Vec<Line<'static>> {
        let t = &self.theme;
        let mut out = Vec::new();
        for x in list {
            let label = Span::styled(format!(" {:<7} {:<14}", x.word.text(), x.label), t.status(x.word));
            out.extend(ui::hang(label, 23, &x.text, width, Style::default()));
            if x.word != Word::Ok {
                for fix in &x.fix {
                    out.extend(ui::hang(Span::raw(" ".repeat(23)), 23, &format!("fix: {fix}"), width, t.muted()));
                }
            }
        }
        out
    }

    fn draw_detect(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let [top, rest] = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(area);
        let ready = self.machine.is_some() && self.net != Net::Checking;
        f.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(" What this machine can do", t.title())),
                Line::from(Span::styled(
                    if ready { " Read, not changed. Press Enter to continue." } else { " Looking ..." },
                    t.muted(),
                )),
            ]),
            top,
        );
        let lines = match &self.machine {
            Some(m) => self.finding_lines(&detect::findings(m, &self.net, &self.rpc), area.width),
            None => vec![Line::from(" Reading this machine ...")],
        };
        f.render_widget(Paragraph::new(lines).scroll((self.detect_scroll, 0)), rest);
    }

    fn draw_choose(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let mut lines = vec![
            Line::from(""),
            Line::from(Span::styled(" What do you want to do?", t.title())),
            Line::from(""),
        ];
        for (i, p) in Path::ALL.iter().enumerate() {
            let sel = i == self.choose_sel;
            let mark = if sel { ">" } else { " " };
            let style = if sel { t.selected() } else { t.bold() };
            lines.push(Line::from(vec![
                Span::styled(format!(" {mark} {}. {}", i + 1, p.label()), style),
            ]));
            lines.push(Line::from(Span::styled(format!("      {}", ui::clip(p.blurb(), area.width.saturating_sub(8) as usize)), t.muted())));
            lines.push(Line::from(""));
        }
        f.render_widget(Paragraph::new(lines), area);
    }

    fn draw_blocked(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let Some(b) = self.blocked() else { return };
        let mut lines = vec![
            Line::from(""),
            Line::from(vec![Span::styled(" ACTION  ", t.status(Word::Action)), Span::styled(b.what.clone(), t.bold())]),
            Line::from(""),
        ];
        lines.extend(ui::hang(Span::styled(" Why   ", t.muted()), 7, &b.why, area.width, Style::default()));
        for (i, fix) in b.fix.iter().enumerate() {
            let lab = if i == 0 { " Fix   " } else { "       " };
            lines.extend(ui::hang(Span::styled(lab, t.muted()), 7, fix, area.width, Style::default()));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(" What would you like to do instead?", t.title())));
        let mut opts: Vec<String> = b.offers.iter().map(|o| o.label()).collect();
        opts.push("Go back and choose again".into());
        for (i, o) in opts.iter().enumerate() {
            let sel = i == self.blocked_sel;
            let style = if sel { t.selected() } else { Style::default() };
            lines.push(Line::from(Span::styled(
                format!(" {} {}", if sel { ">" } else { " " }, ui::clip(o, area.width.saturating_sub(5) as usize)),
                style,
            )));
        }
        f.render_widget(Paragraph::new(lines), area);
    }

    fn draw_steps(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let Some(plan) = &self.plan else { return };
        let list_w = if area.width >= 100 { 34 } else { 28 };
        let [left, right] = Layout::horizontal([Constraint::Length(list_w), Constraint::Min(30)]).areas(area);
        // The list of steps.
        let mut items = Vec::new();
        for (i, s) in plan.steps.iter().enumerate() {
            let mark = match &self.states[i] {
                StepState::Done => "[x]",
                StepState::Skipped => "[-]",
                StepState::Failed(_) => "[!]",
                StepState::Pending if i == self.idx => "[>]",
                StepState::Pending => "[ ]",
            };
            let style = if i == self.idx { t.selected() } else if matches!(self.states[i], StepState::Failed(_)) { t.status(Word::Down) } else { Style::default() };
            items.push(Line::from(Span::styled(
                format!(" {mark} {}", ui::clip(&s.title, list_w as usize - 6)),
                style,
            )));
        }
        f.render_widget(Paragraph::new(items).block(Block::default().borders(Borders::RIGHT)), left);

        // The current step.
        let Some(step) = plan.steps.get(self.idx) else { return };
        let log_h = if self.log.is_empty() && !self.busy() { 0 } else { 7.min(right.height / 3).max(4) };
        let [detail, logarea] = Layout::vertical([Constraint::Min(6), Constraint::Length(log_h)]).areas(right);
        let mut lines = vec![
            Line::from(Span::styled(format!(" {}", step.title), t.title())),
            Line::from(""),
        ];
        let w = right.width;
        let plain = Style::default();
        lines.extend(ui::hang(Span::styled(" What  ", t.muted()), 7, &step.what, w, plain));
        lines.extend(ui::hang(Span::styled(" Why   ", t.muted()), 7, &step.why, w, plain));
        if let Some(c) = &step.caution {
            lines.extend(ui::hang(Span::styled(" Note  ", t.status(Word::Watch)), 7, c, w, plain));
        }
        lines.push(Line::from(""));
        if let Some(cmd) = step.command_line() {
            let verb = if matches!(step.action, Action::Exec { detached: true, .. }) { " Starts " } else { " Runs   " };
            lines.extend(ui::hang(Span::styled(verb, t.muted()), 8, &cmd, w, t.command()));
        }
        if let Action::WaitRpc { url } = &step.action {
            lines.push(Line::from(vec![Span::styled(" Waits  ", t.muted()), Span::styled(url.clone(), t.command())]));
        }
        if !step.manual.is_empty() {
            lines.push(Line::from(Span::styled(" Run this yourself, in another terminal or on the other machine:", t.muted())));
            for m in &step.manual {
                lines.extend(ui::hang(Span::raw("   "), 3, m, w, t.command()));
            }
        }
        lines.push(Line::from(""));
        if let (Some(buf), Gate::Typed(word)) = (&self.typed, &step.gate) {
            lines.push(Line::from(vec![
                Span::styled(" This is not undone by Esc once it runs. ", t.status(Word::Action)),
            ]));
            lines.push(Line::from(vec![
                Span::raw(" Type "),
                Span::styled((*word).to_string(), t.command()),
                Span::raw(" to continue: "),
                Span::styled(format!("{buf}_"), t.bold()),
            ]));
        } else {
            lines.push(self.state_line(step));
        }
        f.render_widget(Paragraph::new(lines), detail);
        if log_h > 0 {
            let take = (log_h as usize).saturating_sub(2);
            let start = self.log.len().saturating_sub(take);
            let l: Vec<Line> = self.log[start..].iter().map(|s| Line::from(ui::clip(s, logarea.width as usize - 3))).collect();
            f.render_widget(
                Paragraph::new(l).block(Block::default().borders(Borders::TOP).title(Span::styled(" output ", t.muted()))),
                logarea,
            );
        }
    }

    fn state_line(&self, step: &Step) -> Line<'static> {
        let t = &self.theme;
        let enter = |what: &str| vec![Span::raw(" Press "), Span::styled("Enter", t.command()), Span::raw(what.to_string())];
        if self.busy() {
            return Line::from(vec![Span::styled(" RUNNING ", t.status(Word::Watch)), Span::raw("wait for it to finish")]);
        }
        match &self.states[self.idx] {
            StepState::Done => {
                let mut v = vec![Span::styled(" OK ", t.status(Word::Ok))];
                v.extend(enter(" to continue."));
                Line::from(v)
            }
            StepState::Failed(why) => {
                let mut v = vec![Span::styled(" FAILED ", t.status(Word::Down)), Span::raw(format!("{why}. "))];
                v.extend(enter(" to try again, b to go back"));
                if step.skippable {
                    v.push(Span::raw(", s to skip."));
                } else {
                    v.push(Span::raw("."));
                }
                Line::from(v)
            }
            _ => {
                let verb = match (&step.action, &step.gate) {
                    (Action::None, _) if !step.manual.is_empty() => " when you have done it.",
                    (Action::None, _) => " to continue.",
                    (_, Gate::Typed(_)) => " to type the confirmation, then run it.",
                    _ => " to run it.",
                };
                Line::from(enter(verb))
            }
        }
    }

    fn draw_done(&self, f: &mut Frame, area: Rect) {
        let t = &self.theme;
        let Some(plan) = &self.plan else { return };
        let mut lines = vec![Line::from(""), Line::from(Span::styled(" Setup finished", t.title())), Line::from("")];
        for (i, s) in plan.steps.iter().enumerate() {
            let (w, word) = match &self.states[i] {
                StepState::Done => (Word::Ok, "done"),
                StepState::Skipped => (Word::Watch, "skipped"),
                StepState::Failed(_) => (Word::Down, "failed"),
                StepState::Pending => (Word::Unknown, "not run"),
            };
            lines.push(Line::from(vec![
                Span::styled(format!(" {:<8}", word), t.status(w)),
                Span::raw(ui::clip(&s.title, area.width.saturating_sub(12) as usize)),
            ]));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(" Your next command:", t.muted())));
        lines.push(Line::from(vec![Span::raw("   "), Span::styled(plan.next.clone(), t.title())]));
        lines.push(Line::from(""));
        let what = if plan.next == "tenzro" { "open the console now" } else { "leave and print it" };
        lines.push(Line::from(vec![Span::raw(" Press "), Span::styled("Enter", t.command()), Span::raw(format!(" to {what}."))]));
        f.render_widget(Paragraph::new(lines), area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::detect::{KeyRoot, NodeBuild};
    use crate::tui::theme::Depth;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn app(root: KeyRoot, net: Net) -> App {
        let mut a = App::new(crate::endpoint::PUBLIC_RPC, Theme::with_depth(Depth::None), None);
        let mut m = Machine::blank();
        m.root = root;
        m.node_binary = Some("/usr/bin/tenzro-node".into());
        m.node_build = Some(NodeBuild { flavour: "cpu".into(), startup_ok: true, refusal: None });
        m.cpu = "Test CPU".into();
        m.cores = 8;
        m.ram_gb = 32.0;
        m.disk_free_gb = 500.0;
        a.deliver(Probe::Machine(Box::new(m)));
        a.deliver(Probe::Net(net));
        a
    }

    fn screen(a: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| a.view(f)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect::<String>().trim_end().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn keys(a: &mut App, ks: &[&str]) {
        for k in ks {
            a.on_key(k);
        }
    }

    #[test]
    fn welcome_detect_choose_at_both_sizes() {
        for (w, h) in [(80, 24), (120, 40)] {
            let mut a = app(KeyRoot::TpmReady, Net::NotResolving);
            let s = screen(&a, w, h);
            assert!(s.contains("Welcome to Tenzro"), "{s}");
            keys(&mut a, &["Enter"]);
            let s = screen(&a, w, h);
            assert!(s.contains("What this machine can do") && s.contains("TPM 2.0"), "{s}");
            assert!(s.contains("not reachable yet"), "{s}");
            keys(&mut a, &["Enter"]);
            let s = screen(&a, w, h);
            assert!(s.contains("What do you want to do?") && s.contains("Try a local chain"), "{s}");
        }
    }

    #[test]
    fn no_escape_codes_without_colour() {
        let mut a = app(KeyRoot::NoTpm, Net::NotResolving);
        keys(&mut a, &["Enter", "Enter"]);
        let s = screen(&a, 80, 24);
        assert!(!s.contains('\u{1b}'));
    }

    #[test]
    fn network_down_blocks_the_network_paths_and_offers_the_local_chain() {
        let mut a = app(KeyRoot::TpmReady, Net::NotResolving);
        keys(&mut a, &["Enter", "Enter", "1"]);
        assert_eq!(a.stage, Stage::Blocked);
        let s = screen(&a, 80, 24);
        assert!(s.contains("The network is not reachable yet") && s.contains("Try a local chain"), "{s}");
        keys(&mut a, &["Enter"]);
        assert_eq!(a.stage, Stage::Steps);
        assert_eq!(a.path, Some(Path::Local));
    }

    #[test]
    fn local_path_walks_to_one_next_command() {
        let mut a = app(KeyRoot::TpmReady, Net::NotResolving);
        keys(&mut a, &["Enter", "Enter", "4"]);
        assert_eq!(a.stage, Stage::Steps);
        // about, hardware-key, save
        keys(&mut a, &["Enter"]);
        keys(&mut a, &["Enter"]);
        assert_eq!(a.plan.as_ref().unwrap().steps[a.idx].id, "save");
        let s = screen(&a, 80, 24);
        assert!(s.contains("Save the setting"), "{s}");
    }

    #[test]
    fn provisioning_cannot_run_without_the_typed_word() {
        let mut a = app(KeyRoot::TpmNeedsProvision, Net::Reachable { chain_id: "0x1".into() });
        keys(&mut a, &["Enter", "Enter", "3"]);
        assert_eq!(a.stage, Stage::Steps);
        // hardware (info), precheck (skip), then provision.
        keys(&mut a, &["Enter", "s"]);
        assert_eq!(a.plan.as_ref().unwrap().steps[a.idx].id, "tpm-provision");
        // Skipping a non-skippable step does nothing.
        keys(&mut a, &["s"]);
        assert_eq!(a.plan.as_ref().unwrap().steps[a.idx].id, "tpm-provision");
        keys(&mut a, &["Enter"]);
        assert!(a.typed.is_some());
        let s = screen(&a, 80, 24);
        assert!(s.contains("Type provision to continue"), "{s}");
        // Wrong word, Enter: nothing runs.
        keys(&mut a, &["n", "o", "Enter"]);
        assert!(!a.busy() && a.typed.is_some());
        // Esc cancels safely.
        keys(&mut a, &["Esc"]);
        assert!(a.typed.is_none() && !a.busy());
        assert_eq!(a.states[a.idx], StepState::Pending);
    }

    #[test]
    fn staking_can_be_skipped_and_back_goes_one_step() {
        let mut a = app(KeyRoot::TpmReady, Net::Reachable { chain_id: "0x1".into() });
        keys(&mut a, &["Enter", "Enter", "3"]);
        let ids: Vec<_> = a.plan.as_ref().unwrap().steps.iter().map(|s| s.id).collect();
        let reg = ids.iter().position(|i| *i == "register").unwrap();
        a.idx = reg;
        keys(&mut a, &["b"]);
        assert_eq!(a.idx, reg - 1);
        a.idx = reg;
        keys(&mut a, &["s"]);
        assert_eq!(a.states[reg], StepState::Skipped);
    }

    #[test]
    fn too_small_says_so_and_does_not_panic() {
        let a = app(KeyRoot::TpmReady, Net::NotResolving);
        let s = screen(&a, 60, 15);
        assert!(s.contains("Terminal too small") && s.contains("80x24"), "{s}");
    }

    #[test]
    fn ctrl_c_quits_when_idle() {
        let mut a = app(KeyRoot::TpmReady, Net::NotResolving);
        keys(&mut a, &["Ctrl-C"]);
        assert_eq!(a.outcome, Some(Outcome::Quit));
    }

    #[test]
    fn the_validator_screens_fit_80x24() {
        let mut a = app(KeyRoot::TpmNeedsProvision, Net::Reachable { chain_id: "0x1".into() });
        keys(&mut a, &["Enter", "Enter", "3"]);
        let n = a.states.len();
        for i in 0..n {
            a.idx = i;
            let s = screen(&a, 80, 24);
            assert!(s.lines().count() <= 24);
            assert!(s.contains(&a.plan.as_ref().unwrap().steps[i].title[..8.min(a.plan.as_ref().unwrap().steps[i].title.len())]), "{s}");
        }
    }
}
