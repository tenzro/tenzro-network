//! The assistant inside the console: the conversation drawn in place of the
//! screens, the read-only tool it runs, and the command it hands to the
//! person's own terminal after a yes.

use std::io::BufRead;
use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use anyhow::{Result, anyhow};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use serde_json::Value;

use super::journey::Prog;
use super::runner::{self, Msg, Running};
use super::theme::Theme;
use super::ui;
use crate::assistant::chat::{Chat, Step, Who};
use crate::assistant::local;
use crate::assistant::model::Offer;
use crate::assistant::tools;
use crate::rpc::RpcClient;

/// Rows of the tool list shown above the prompt.
const PALETTE_ROWS: usize = 8;

const INTRO: &str = "Ask about running this node, or type / for the tools.\n\
A tool that only reads runs at once. One that changes this machine, or needs your key, \
shows its command and asks first.\n\
/assistant gives the assistant a model served by your own node, when you want one.";

/// Said when the console's node is not on this machine.
const NOT_OWN: &str = "The assistant's model runs on your own node, and this console is \
connected to a node on another machine, so questions are answered from the guides.";

/// The person's own node, which the assistant's model runs on.
pub struct Link {
    rpc: Arc<RpcClient>,
    handle: tokio::runtime::Handle,
}

impl Link {
    /// A link to the node at `url` when it is on this machine; none otherwise.
    pub fn to(url: &str, handle: &tokio::runtime::Handle) -> Option<Self> {
        let url = crate::endpoint::for_command(url);
        local::is_own_node(&url).then(|| Self {
            rpc: Arc::new(RpcClient::new(&url)),
            handle: handle.clone(),
        })
    }
}

/// What came back from the node.
enum Event {
    /// The served model questions go to, if any.
    Model(Option<String>),
    /// The reply to the request with this number.
    Reply(u64, Result<Value, String>),
    Offer(Result<Offer, String>),
}

/// What the console does after a key the assistant took.
#[derive(Debug, PartialEq, Eq)]
pub enum After {
    Stay,
    /// Show the screens again; the conversation is kept.
    Close,
    Quit,
}

pub struct Panel {
    chat: Chat,
    tool: Option<Running>,
    /// A command the person said yes to, for the driver to run on their
    /// terminal.
    pub handover: Option<Vec<String>>,
    /// Whether a question for a yes was showing when last checked.
    questioned: bool,
    link: Option<Link>,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    /// The number of the last request; a reply to an older one is dropped.
    asked: u64,
    /// Whether the node has been asked which model it serves.
    looked: bool,
}

impl Panel {
    pub fn new(link: Option<Link>) -> Self {
        let (tx, rx) = channel();
        Self {
            chat: Chat::new(),
            tool: None,
            handover: None,
            questioned: false,
            link,
            tx,
            rx,
            asked: 0,
            looked: false,
        }
    }

    pub fn on_key(&mut self, name: &str) -> After {
        // The node is asked nothing until the assistant is used.
        if !self.looked {
            self.looked = true;
            self.look();
        }
        let step = self.chat.on_key(name);
        self.act(step)
    }

    fn act(&mut self, step: Step) -> After {
        match step {
            Step::Stay => {}
            Step::Close => return After::Close,
            Step::Quit => {
                self.stop();
                return After::Quit;
            }
            Step::Run(argv) => self.run(&Prog::Cli, &argv),
            Step::Stop => self.stop(),
            Step::Handover(argv) => self.handover = Some(argv),
            Step::Ask(request) => self.ask(request),
            Step::Offer => self.offer(),
        }
        After::Stay
    }

    /// Asks the node which served model the questions go to.
    fn look(&self) {
        let Some(link) = &self.link else {
            return;
        };
        let rpc = link.rpc.clone();
        let tx = self.tx.clone();
        link.handle.spawn(async move {
            let model = local::served(&rpc).await;
            let _ = tx.send(Event::Model(model));
        });
    }

    fn ask(&mut self, request: Value) {
        self.asked += 1;
        let id = self.asked;
        let tx = self.tx.clone();
        let Some(link) = &self.link else {
            let _ = tx.send(Event::Reply(id, Err(NOT_OWN.to_string())));
            return;
        };
        let rpc = link.rpc.clone();
        link.handle.spawn(async move {
            let reply = local::ask(&rpc, request).await;
            let _ = tx.send(Event::Reply(id, reply));
        });
    }

    fn offer(&self) {
        let tx = self.tx.clone();
        let Some(link) = &self.link else {
            let _ = tx.send(Event::Offer(Err(NOT_OWN.to_string())));
            return;
        };
        let rpc = link.rpc.clone();
        link.handle.spawn(async move {
            let offer = local::offer(&rpc)
                .await
                .map_err(|e| format!("The node could not be asked: {e}"));
            let _ = tx.send(Event::Offer(offer));
        });
    }

    fn run(&mut self, prog: &Prog, argv: &[String]) {
        match runner::spawn(prog, argv) {
            Ok(tool) => self.tool = Some(tool),
            Err(e) => self.chat.failed(&e.to_string()),
        }
    }

    fn stop(&mut self) {
        if let Some(tool) = self.tool.take() {
            tool.kill();
        }
        self.handover = None;
        self.asked += 1;
        self.chat.finished(None);
    }

    /// Moves what the node replied and what the running tool printed into
    /// the conversation.
    pub fn tick(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            let step = match event {
                Event::Model(model) => {
                    self.chat.set_model(model);
                    Step::Stay
                }
                Event::Reply(id, reply) if id == self.asked => self.chat.replied(reply),
                Event::Reply(..) => Step::Stay,
                Event::Offer(offer) => {
                    self.chat.offered(offer);
                    Step::Stay
                }
            };
            self.act(step);
        }
        let Some(tool) = &self.tool else {
            return;
        };
        let mut ended = None;
        while let Ok(msg) = tool.rx.try_recv() {
            match msg {
                Msg::Line(line) => self.chat.output(&line),
                Msg::Exit(code) => ended = Some(code),
            }
        }
        if let Some(code) = ended {
            self.tool = None;
            self.chat.finished(code);
        }
    }

    /// The approved command came back from the person's terminal.
    pub fn handed_back(&mut self, result: Result<Option<i32>>) {
        match result {
            Ok(code) => self.chat.handed_back(code),
            Err(e) => self.chat.failed(&e.to_string()),
        }
        // What the person ran may have served or stopped a model.
        self.look();
    }

    /// Pasted text, which is only ever typed into the line.
    pub fn on_paste(&mut self, text: &str) {
        self.chat.paste(text);
    }

    /// Whether a question for a yes appeared since this was last asked. The
    /// driver then drops every key typed ahead of it, so nothing typed before
    /// the question was shown can answer it.
    pub fn question_appeared(&mut self) -> bool {
        let shown = self.chat.pending().is_some();
        let appeared = shown && !self.questioned;
        self.questioned = shown;
        appeared
    }

    /// The keys that do something right now.
    pub fn footer(&self) -> &'static str {
        if self.chat.pending().is_some() {
            "y then Enter run it  n leave it  Ctrl-C quit"
        } else if self.chat.running().is_some() {
            "Esc stop it  Ctrl-C quit"
        } else if self.chat.asking().is_some() {
            "Esc stop asking  Ctrl-C quit"
        } else if !self.chat.palette().is_empty() {
            "Up/Down choose  Tab complete  Enter run  Esc clear"
        } else if !self.chat.input().is_empty() {
            "Enter send  Esc clear  Ctrl-C quit"
        } else {
            "Enter send  / tools  Up/Down scroll  Esc back to the screens  Ctrl-C quit"
        }
    }

    pub fn view(&self, f: &mut Frame, t: &Theme, area: Rect) {
        let choices = self.chat.palette();
        let listed = choices.len().min(PALETTE_ROWS);
        let [title, talk, list, prompt] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(listed as u16),
            Constraint::Length(2),
        ])
        .areas(area);

        let scroll = self.chat.scroll();
        let mut head = vec![Span::styled(" Assistant ", t.selected())];
        if scroll > 0 {
            head.push(Span::styled(
                format!("  {scroll} lines back, Down returns"),
                t.muted(),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(head)), title);

        // Only the newest entries that reach the window are laid out, so a
        // long conversation costs no more to draw than a short one.
        let width = (talk.width as usize).saturating_sub(4);
        let height = talk.height as usize;
        let want = height + scroll + 2;
        let mut blocks = Vec::new();
        let mut count = 0;
        if self.chat.entries().is_empty() {
            blocks.push(rows(Who::Assistant, INTRO, width, t));
        }
        for entry in self.chat.entries().iter().rev() {
            if count >= want {
                break;
            }
            let block = rows(entry.who, &entry.text, width, t);
            count += block.len() + 1;
            blocks.push(block);
        }
        let mut lines: Vec<Line<'static>> = Vec::new();
        for block in blocks.into_iter().rev() {
            if !lines.is_empty() {
                lines.push(Line::default());
            }
            lines.extend(block);
        }
        let above = lines.len().saturating_sub(height);
        self.chat.seen(above);
        let skip = above - scroll.min(above);
        let shown: Vec<Line<'static>> = lines.into_iter().skip(skip).take(height).collect();
        f.render_widget(Paragraph::new(shown), talk);

        let first = self.chat.choice().saturating_sub(PALETTE_ROWS - 1);
        let room = (list.width as usize).saturating_sub(4);
        let list_rows: Vec<Line<'static>> = choices
            .iter()
            .enumerate()
            .skip(first)
            .take(PALETTE_ROWS)
            .map(|(i, row)| {
                let (mark, style) = if i == self.chat.choice() {
                    (">", t.selected())
                } else {
                    (" ", t.muted())
                };
                Line::from(Span::styled(
                    format!(" {mark} {}", ui::clip(&row.line, room)),
                    style,
                ))
            })
            .collect();
        f.render_widget(Paragraph::new(list_rows), list);

        let line = if let Some(command) = self.chat.pending() {
            Line::from(vec![
                Span::styled(format!(" Run {command}? "), t.bold()),
                Span::styled(
                    if self.chat.armed() {
                        "y, now Enter to run it"
                    } else {
                        "y / n"
                    },
                    t.accent(),
                ),
            ])
        } else if let Some(command) = self.chat.running() {
            Line::from(Span::styled(format!(" Running {command} ..."), t.muted()))
        } else if let Some(label) = self.chat.asking() {
            Line::from(Span::styled(format!(" {label} ..."), t.muted()))
        } else {
            let room = (prompt.width as usize).saturating_sub(5);
            let typed = self.chat.input().chars().count();
            let tail: String = self
                .chat
                .input()
                .chars()
                .skip(typed.saturating_sub(room))
                .collect();
            Line::from(vec![
                Span::styled(" > ", t.accent()),
                Span::raw(tail),
                Span::styled(" ", t.selected()),
            ])
        };
        let frame = Block::default()
            .borders(Borders::TOP)
            .border_style(t.muted());
        f.render_widget(Paragraph::new(line).block(frame), prompt);
    }
}

/// One part of the conversation as screen rows: what the person typed after
/// a `>`, what a tool printed beside a rule, the assistant's words plain.
fn rows(who: Who, text: &str, width: usize, t: &Theme) -> Vec<Line<'static>> {
    let (lead, lead_style, style) = match who {
        Who::You => (" > ", t.accent(), t.bold()),
        Who::Assistant => ("   ", Style::default(), Style::default()),
        Who::Output => (" │ ", t.muted(), Style::default()),
        Who::Model => (" · ", t.accent(), Style::default()),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        for row in wrap(&line.replace('\t', "    "), width) {
            let lead = if who == Who::You && !out.is_empty() {
                "   "
            } else {
                lead
            };
            out.push(Line::from(vec![
                Span::styled(lead, lead_style),
                Span::styled(row, style),
            ]));
        }
    }
    out
}

/// Breaks one line to the width at a space where it has one, keeping the
/// spacing an indented command or a table needs.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    if width == 0 {
        return out;
    }
    let mut start = 0;
    while chars.len() - start > width {
        let window = &chars[start..start + width];
        let indent = window.iter().take_while(|c| **c == ' ').count();
        let cut = match window.iter().rposition(|c| *c == ' ') {
            _ if chars[start + width] == ' ' => width,
            Some(space) if space > indent => space,
            _ => width,
        };
        out.push(chars[start..start + cut].iter().collect());
        start += cut;
        while chars.get(start) == Some(&' ') {
            start += 1;
        }
    }
    out.push(chars[start..].iter().collect());
    out
}

/// Runs a command the person approved on their own terminal, which the
/// caller has put back first, so a prompt for a key or a password works and
/// the output stays in the scrollback. The line printed first is the command
/// that was shown at the question, written from the list that is run. Enter
/// returns to the console.
pub fn run_attached(argv: &[String]) -> Result<Option<i32>> {
    let program =
        runner::resolve(&Prog::Cli).ok_or_else(|| anyhow!("this program was not found"))?;
    println!("{}\n", tools::shown(argv));
    let status = Command::new(program)
        .args(argv)
        .env("TENZRO_NO_BANNER", "1")
        .status()?;
    match status.code() {
        Some(0) => println!("\nDone."),
        Some(code) => println!("\nIt ended with exit code {code}."),
        None => println!("\nIt was stopped."),
    }
    println!("Press Enter to go back to the console.");
    std::io::stdin().lock().read_line(&mut String::new())?;
    Ok(status.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::Depth;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn drawn(p: &Panel, w: u16, h: u16) -> String {
        let theme = Theme::with_depth(Depth::None);
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| p.view(f, &theme, f.area())).unwrap();
        let buf = t.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn typed(p: &mut Panel, text: &str) {
        for c in text.chars() {
            assert_eq!(p.on_key(&c.to_string()), After::Stay);
        }
    }

    #[test]
    fn a_line_breaks_at_a_space_and_keeps_its_indent() {
        assert_eq!(wrap("one two three", 8), ["one two", "three"]);
        assert_eq!(
            wrap("  tenzro model serve", 14),
            ["  tenzro model", "serve"]
        );
        assert_eq!(wrap("  abcdefghij", 6), ["  abcd", "efghij"]);
        assert_eq!(wrap("", 6), [""]);
        assert_eq!(wrap("short", 0), Vec::<String>::new());
    }

    #[test]
    fn it_draws_the_tool_list_and_the_prompt_at_both_sizes() {
        let mut p = Panel::new(None);
        for (w, h) in [(80, 22), (120, 38)] {
            assert!(drawn(&p, w, h).contains("type / for the tools"));
        }
        typed(&mut p, "/st");
        for (w, h) in [(80, 22), (120, 38)] {
            let text = drawn(&p, w, h);
            assert!(text.contains(" > /status"), "{text}");
            assert!(text.contains("   /stake"), "{text}");
            assert!(text.contains(" > /st"), "{text}");
            assert!(!text.contains("/doctor"), "{text}");
        }
        assert_eq!(
            p.footer(),
            "Up/Down choose  Tab complete  Enter run  Esc clear"
        );
    }

    #[test]
    fn yes_hands_the_command_to_the_terminal_and_no_runs_nothing() {
        let mut p = Panel::new(None);
        typed(&mut p, "/serve qwen");
        assert_eq!(p.on_key("Enter"), After::Stay);
        let argv: Vec<String> = vec![
            "model".into(),
            "serve".into(),
            "qwen".into(),
            "--rpc".into(),
            "http://127.0.0.1:8545".into(),
        ];
        assert_eq!(
            tools::shown(&argv),
            "tenzro model serve qwen --rpc http://127.0.0.1:8545"
        );
        let question = format!("Run {}? y / n", tools::shown(&argv));
        assert!(drawn(&p, 80, 22).contains(&question));
        assert_eq!(p.on_key("n"), After::Stay);
        assert_eq!(p.handover, None);
        assert!(p.tool.is_none());
        assert!(drawn(&p, 80, 22).contains("Not run."));

        typed(&mut p, "/serve qwen");
        p.on_key("Enter");
        assert_eq!(p.on_key("y"), After::Stay);
        assert_eq!(p.handover, None, "y alone runs nothing");
        assert!(drawn(&p, 80, 22).contains("y, now Enter to run it"));
        assert_eq!(p.on_key("Enter"), After::Stay);
        assert!(p.tool.is_none());
        assert!(drawn(&p, 80, 22).contains(&format!("Running {}", tools::shown(&argv))));
        assert_eq!(p.handover.take(), Some(argv));
        p.handed_back(Ok(Some(1)));
        assert!(drawn(&p, 80, 22).contains(
            "tenzro model serve qwen --rpc http://127.0.0.1:8545 ended with exit code 1."
        ));
    }

    #[cfg(unix)]
    #[test]
    fn what_a_tool_prints_and_how_it_ended_reach_the_conversation() {
        use std::time::{Duration, Instant};

        let mut p = Panel::new(None);
        assert_eq!(p.chat.submit("/status"), Step::Run(vec!["status".into()]));
        p.run(
            &Prog::Other("sh"),
            &[
                "-c".into(),
                "echo height 12; printf '\\033[1;31mred\\033[0m \\033]0;title\\007alert\\n'; exit 3"
                    .into(),
            ],
        );
        let end = Instant::now() + Duration::from_secs(30);
        while p.tool.is_some() {
            assert!(Instant::now() < end, "the tool never ended");
            p.tick();
            std::thread::sleep(Duration::from_millis(10));
        }
        let text = drawn(&p, 80, 22);
        assert!(text.contains(" │ height 12"), "{text}");
        assert!(text.contains(" │ red alert"), "{text}");
        assert!(!text.contains(|c: char| c.is_control() && c != '\n'));
        assert!(
            text.contains("tenzro status ended with exit code 3."),
            "{text}"
        );
        assert_eq!(p.footer().split("  ").next(), Some("Enter send"));
    }

    #[cfg(unix)]
    #[test]
    fn escape_stops_the_tool_that_is_running() {
        let mut p = Panel::new(None);
        p.chat.submit("/status");
        p.run(&Prog::Other("sh"), &["-c".into(), "exec sleep 600".into()]);
        assert!(p.tool.is_some());
        assert_eq!(p.on_key("Esc"), After::Stay);
        assert!(p.tool.is_none());
        assert!(drawn(&p, 80, 22).contains("tenzro status was stopped."));
        assert_eq!(p.on_key("Esc"), After::Close);
    }

    #[test]
    fn a_command_that_cannot_start_is_said_plainly() {
        let mut p = Panel::new(None);
        p.chat.submit("/status");
        p.run(&Prog::Other("definitely-not-a-program-xyz"), &[]);
        assert!(p.tool.is_none());
        assert!(drawn(&p, 80, 22).contains("tenzro status could not be run"));
    }
}
