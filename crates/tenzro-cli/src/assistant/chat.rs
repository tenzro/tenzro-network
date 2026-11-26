//! The conversation with the assistant: what was said, what is being typed
//! and what is waiting for a yes. It holds no terminal and starts nothing;
//! each key returns the one thing the screen has to do next.

use std::cell::Cell;

use serde_json::Value;

use super::knowledge::Pack;
use super::model::{self, Offer, Proposal};
use super::reply::{self, Answer};
use super::router::{Route, route};
use super::tools::{self, Invocation, Risk, TOOLS};

/// Lines kept of one tool's output, and entries kept of the conversation.
const OUTPUT_LINES: usize = 400;
const ENTRIES: usize = 200;

/// Who a part of the conversation comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    You,
    Assistant,
    /// What a tool printed.
    Output,
    /// What the served model answered, as text only.
    Model,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub who: Who,
    pub text: String,
}

/// What the screen does after a key.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Stay,
    /// Put the conversation away and show the screens again.
    Close,
    Quit,
    /// Run a read-only tool and feed back what it prints.
    Run(Vec<String>),
    /// Stop the tool that is running.
    Stop,
    /// The person said yes: run this command on their own terminal.
    Handover(Vec<String>),
    /// Send this chat request to the node's served model.
    Ask(Value),
    /// Find what the node's catalog offers the assistant on this machine.
    Offer,
}

/// A command waiting for a yes, and whether it runs inside the conversation
/// (a read-only tool) or on the person's terminal.
struct Pending {
    invocation: Invocation,
    attached: bool,
}

/// What the node is being asked.
enum Ask {
    /// Whether one tool does what this question asks.
    Tool(String),
    /// An answer to this question from guide passages.
    Answer(String),
    /// What the catalog offers this machine.
    Offer,
}

/// One row of the list shown while a slash command is being typed.
#[derive(Debug, PartialEq, Eq)]
pub struct Choice {
    pub name: &'static str,
    pub line: String,
    /// The tool's command takes an argument the person still has to type.
    pub takes_argument: bool,
}

pub struct Chat {
    /// The guides, read the first time a question is asked.
    pack: Option<Pack>,
    entries: Vec<Entry>,
    input: String,
    choice: usize,
    pending: Option<Pending>,
    /// y was pressed for the waiting command; Enter runs it.
    armed: bool,
    /// The command offered once the pending one has run and succeeded.
    next: Option<Invocation>,
    running: Option<String>,
    /// The served model questions go to; without one the guides answer.
    model: Option<String>,
    asking: Option<Ask>,
    output_lines: usize,
    scroll: usize,
    /// Lines above the window when the conversation was last drawn.
    above: Cell<usize>,
}

impl Chat {
    pub fn new() -> Self {
        Self {
            pack: None,
            entries: Vec::new(),
            input: String::new(),
            choice: 0,
            pending: None,
            armed: false,
            next: None,
            running: None,
            model: None,
            asking: None,
            output_lines: 0,
            scroll: 0,
            above: Cell::new(0),
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn choice(&self) -> usize {
        self.choice
    }

    /// The command waiting for a yes, as the person would type it.
    pub fn pending(&self) -> Option<String> {
        self.pending.as_ref().map(|p| p.invocation.shell())
    }

    /// What the node is being asked, while a reply is awaited.
    pub fn asking(&self) -> Option<&'static str> {
        match self.asking {
            Some(Ask::Offer) => Some("Reading the node's catalog"),
            Some(_) => Some("Asking the model"),
            None => None,
        }
    }

    /// The served model questions go to; `None` leaves them to the guides.
    pub fn set_model(&mut self, model: Option<String>) {
        self.model = model;
    }

    /// Whether y was pressed for the waiting command, so Enter runs it.
    pub fn armed(&self) -> bool {
        self.armed
    }

    /// The command that is running.
    pub fn running(&self) -> Option<&str> {
        self.running.as_deref()
    }

    /// Lines scrolled back from the newest.
    pub fn scroll(&self) -> usize {
        self.scroll
    }

    /// The screen reports how many lines did not fit above the window, so
    /// scrolling back stops at the first line.
    pub fn seen(&self, above: usize) {
        self.above.set(above);
    }

    /// The tools a half-typed slash command can still become. Empty once the
    /// command has an argument, and while something waits or runs.
    pub fn palette(&self) -> Vec<Choice> {
        if self.pending.is_some() || self.running.is_some() || self.asking.is_some() {
            return Vec::new();
        }
        let Some(typed) = self.input.strip_prefix('/') else {
            return Vec::new();
        };
        if typed.contains(char::is_whitespace) {
            return Vec::new();
        }
        let typed = typed.to_ascii_lowercase();
        let mut rows = Vec::new();
        if "help".starts_with(&typed) {
            rows.push(Choice {
                name: "help",
                line: format!("/{:<13} List the tools", "help"),
                takes_argument: false,
            });
        }
        if "assistant".starts_with(&typed) {
            rows.push(Choice {
                name: "assistant",
                line: format!("/{:<13} Give the assistant a model", "assistant"),
                takes_argument: false,
            });
        }
        for tool in TOOLS.iter() {
            if tool.name.starts_with(&typed) || tool.aliases.iter().any(|a| a.starts_with(&typed)) {
                rows.push(Choice {
                    name: tool.name,
                    line: reply::tool_line(tool),
                    takes_argument: !tool.invocation(&[]).missing.is_empty(),
                });
            }
        }
        rows
    }

    pub fn on_key(&mut self, name: &str) -> Step {
        if name == "Ctrl-C" {
            return Step::Quit;
        }
        if self.pending.is_some() {
            return self.approval(name);
        }
        if self.running.is_some() {
            return if name == "Esc" {
                Step::Stop
            } else {
                Step::Stay
            };
        }
        if self.asking.is_some() {
            if name != "Esc" {
                return Step::Stay;
            }
            self.asking = None;
            self.say(Who::Assistant, "Not asked.".to_string());
            return Step::Stop;
        }
        match name {
            "Esc" if self.input.is_empty() => return Step::Close,
            "Esc" => self.type_over(String::new()),
            "Backspace" => {
                self.input.pop();
                self.choice = 0;
            }
            "Up" => self.up(),
            "Down" => self.down(),
            "Tab" => {
                if let Some(row) = self.palette().get(self.choice) {
                    self.type_over(format!("/{} ", row.name));
                }
            }
            "Enter" => return self.enter(),
            n if n.chars().count() == 1 => {
                self.input.push_str(n);
                self.choice = 0;
                self.scroll = 0;
            }
            _ => {}
        }
        Step::Stay
    }

    fn type_over(&mut self, text: String) {
        self.input = text;
        self.choice = 0;
    }

    fn up(&mut self) {
        if self.palette().is_empty() {
            self.scroll = (self.scroll + 1).min(self.above.get());
        } else {
            self.choice = self.choice.saturating_sub(1);
        }
    }

    fn down(&mut self) {
        let rows = self.palette().len();
        if rows == 0 {
            self.scroll = self.scroll.saturating_sub(1);
        } else {
            self.choice = (self.choice + 1).min(rows - 1);
        }
    }

    /// Enter sends the line. A half-typed slash command becomes the chosen
    /// tool first; a tool that takes an argument then waits for it.
    fn enter(&mut self) -> Step {
        let word = self.input.trim_start_matches('/');
        let exact = tools::find(word).is_some() || matches!(word, "help" | "?" | "assistant");
        if !exact && let Some(row) = self.palette().get(self.choice) {
            if row.takes_argument {
                self.type_over(format!("/{} ", row.name));
                return Step::Stay;
            }
            self.input = format!("/{}", row.name);
        }
        let line = std::mem::take(&mut self.input);
        self.choice = 0;
        self.submit(&line)
    }

    /// y and then Enter run the command that is waiting, two deliberate key
    /// presses; any other key after y takes the y back. n or Esc leaves it.
    fn approval(&mut self, name: &str) -> Step {
        match name {
            "y" | "Y" => {
                self.armed = true;
                Step::Stay
            }
            "Enter" if self.armed => {
                self.armed = false;
                let Some(Pending {
                    invocation,
                    attached,
                }) = self.pending.take()
                else {
                    return Step::Stay;
                };
                self.running = Some(invocation.shell());
                if attached {
                    self.output_lines = 0;
                    Step::Run(invocation.argv)
                } else {
                    Step::Handover(invocation.argv)
                }
            }
            "n" | "N" | "Esc" => {
                self.armed = false;
                self.pending = None;
                self.next = None;
                self.say(Who::Assistant, "Not run.".to_string());
                Step::Stay
            }
            _ => {
                self.armed = false;
                Step::Stay
            }
        }
    }

    /// Pasted text goes into the line being typed and nowhere else: it never
    /// answers a question or sends a line. Its line breaks become spaces and
    /// its control and formatting characters are dropped.
    pub fn paste(&mut self, text: &str) {
        if self.pending.is_some() || self.running.is_some() || self.asking.is_some() {
            return;
        }
        let text = text
            .chars()
            .map(|c| {
                if matches!(c, '\n' | '\r' | '\t') {
                    ' '
                } else {
                    c
                }
            })
            .filter(|c| !c.is_control() && !tools::is_invisible_format(*c));
        self.input.extend(text);
        self.choice = 0;
        self.scroll = 0;
    }

    /// One line from the person: a slash command or a question.
    pub fn submit(&mut self, line: &str) -> Step {
        let line = line.trim();
        if line.is_empty() {
            return Step::Stay;
        }
        self.say(Who::You, line.to_string());
        let text = match route(line) {
            Route::Empty => return Step::Stay,
            Route::Help => reply::help(),
            Route::Run { invocation, .. } => {
                if let Some(note) = invocation.left_out() {
                    self.say(Who::Assistant, note);
                }
                self.running = Some(invocation.shell());
                self.output_lines = 0;
                return Step::Run(invocation.argv);
            }
            Route::NeedsApproval { tool, invocation } if invocation.missing.is_empty() => {
                let about = format!("/{} {}", tool.name, tool.risk.label());
                let note = invocation.left_out();
                self.propose(about, invocation, false);
                if let Some(note) = note {
                    self.say(Who::Assistant, note);
                }
                return Step::Stay;
            }
            Route::NeedsApproval { tool, invocation }
            | Route::MissingArgument { tool, invocation } => {
                reply::missing_argument(tool, &invocation)
            }
            Route::RefusedArgument { tool, invocation } => {
                reply::refused_argument(tool, &invocation)
            }
            Route::UnknownTool { name, close } => reply::unknown_tool(&name, &close),
            Route::Assistant => {
                self.asking = Some(Ask::Offer);
                return Step::Offer;
            }
            Route::Question(question) => {
                if let Some(model_id) = &self.model {
                    let request = model::tool_request(model_id, &question);
                    self.asking = Some(Ask::Tool(question));
                    return Step::Ask(request);
                }
                self.guides(&question).0
            }
        };
        self.say(Who::Assistant, text);
        Step::Stay
    }

    /// What the guides hold for a question: the answer they give alone, the
    /// passages' sources, and the request that asks the model to answer from
    /// those passages when a model is served and the guides have any.
    fn guides(&mut self, question: &str) -> (String, Vec<String>, Option<Value>) {
        let model_id = self.model.clone();
        let pack = self.pack.get_or_insert_with(Pack::load);
        let answer = Answer::find(pack, question);
        let sources = answer.passages.iter().map(|p| p.citation()).collect();
        let request = match model_id {
            Some(id) if !answer.passages.is_empty() => {
                Some(model::answer_request(&id, question, &answer.passages))
            }
            _ => None,
        };
        (answer.text(), sources, request)
    }

    /// Puts a command to the person, exactly as it will run.
    fn propose(&mut self, about: String, invocation: Invocation, attached: bool) {
        let place = if attached { "here" } else { "on your terminal" };
        self.say(
            Who::Assistant,
            format!(
                "{about}. It runs this {place}:\n  {}\nPress y and then Enter to run it, n to leave it.",
                invocation.shell()
            ),
        );
        self.pending = Some(Pending {
            invocation,
            attached,
        });
        self.armed = false;
    }

    /// The served model's reply to what it was asked. A proposed tool becomes
    /// a question to the person and never runs by itself; words are kept as
    /// text only, with the sources the client gave the model.
    pub fn replied(&mut self, reply: Result<Value, String>) -> Step {
        let (question, answering) = match self.asking.take() {
            Some(Ask::Tool(question)) => (question, false),
            Some(Ask::Answer(question)) => (question, true),
            other => {
                self.asking = other;
                return Step::Stay;
            }
        };
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                let (text, _, _) = self.guides(&question);
                self.say(
                    Who::Assistant,
                    format!("The model could not be asked: {error}\n{text}"),
                );
                return Step::Stay;
            }
        };
        if answering {
            let words = model::text(&reply);
            let (text, sources, _) = self.guides(&question);
            if words.is_empty() {
                self.say(Who::Assistant, text);
            } else {
                let words: Vec<String> = words.lines().map(plain).collect();
                self.say(Who::Model, words.join("\n"));
                self.say(Who::Assistant, format!("From {}.", sources.join("; ")));
            }
            return Step::Stay;
        }
        match model::proposal(&reply) {
            Proposal::Call(tool, invocation) => {
                let about = format!("The model proposes /{} ({})", tool.name, tool.risk.label());
                self.propose(about, invocation, tool.risk == Risk::ReadOnly);
                return Step::Stay;
            }
            Proposal::Refused(line) => self.say(Who::Assistant, line.to_string()),
            Proposal::Nothing => {}
        }
        let (text, _, request) = self.guides(&question);
        match request {
            Some(request) => {
                self.asking = Some(Ask::Answer(question));
                Step::Ask(request)
            }
            None => {
                self.say(Who::Assistant, text);
                Step::Stay
            }
        }
    }

    /// What `/assistant` found. A model the node serves is used at once;
    /// otherwise the catalog's entry is offered as two commands, each asked
    /// on its own, the second only after the first succeeded.
    pub fn offered(&mut self, offer: Result<Offer, String>) {
        if !matches!(self.asking, Some(Ask::Offer)) {
            return;
        }
        self.asking = None;
        let offer = match offer {
            Ok(offer) => offer,
            Err(error) => {
                self.say(Who::Assistant, error);
                return;
            }
        };
        self.say(Who::Assistant, offer.text());
        if let Some(id) = offer.serving {
            self.model = Some(id);
            return;
        }
        if let Some(pick) = offer.pick {
            let [download, serve] = model::setup(&pick.id);
            self.next = Some(serve);
            self.propose("First, fetch the model".to_string(), download, false);
        }
    }

    /// A line the running tool printed.
    pub fn output(&mut self, line: &str) {
        if self.running.is_none() || self.output_lines > OUTPUT_LINES {
            return;
        }
        self.output_lines += 1;
        let line = if self.output_lines > OUTPUT_LINES {
            "(more was printed than is kept here; run the command yourself to see all of it)"
                .to_string()
        } else {
            plain(line)
        };
        match self.entries.last_mut() {
            Some(last) if last.who == Who::Output => {
                last.text.push('\n');
                last.text.push_str(&line);
            }
            _ => self.say(Who::Output, line),
        }
    }

    /// The running tool ended; `None` when it was stopped.
    pub fn finished(&mut self, code: Option<i32>) {
        let Some(command) = self.running.take() else {
            return;
        };
        match code {
            Some(0) => {}
            Some(code) => self.say(
                Who::Assistant,
                format!("{command} ended with exit code {code}."),
            ),
            None => self.say(Who::Assistant, format!("{command} was stopped.")),
        }
    }

    /// The command the person approved came back from their terminal.
    pub fn handed_back(&mut self, code: Option<i32>) {
        if code == Some(0)
            && let Some(command) = self.running.take()
        {
            self.say(Who::Assistant, format!("{command} finished."));
        }
        self.finished(code);
        let next = self.next.take();
        if code == Some(0)
            && let Some(serve) = next
        {
            let about = "Then serve it to this machine's own callers".to_string();
            self.propose(about, serve, false);
        }
    }

    /// The command could not be started.
    pub fn failed(&mut self, error: &str) {
        self.next = None;
        if let Some(command) = self.running.take() {
            self.say(
                Who::Assistant,
                format!("{command} could not be run: {error}"),
            );
        }
    }

    fn say(&mut self, who: Who, text: String) {
        self.entries.push(Entry { who, text });
        if self.entries.len() > ENTRIES {
            let extra = self.entries.len() - ENTRIES;
            self.entries.drain(..extra);
        }
        self.scroll = 0;
    }
}

/// What a tool printed, as text only. Terminal control sequences and control
/// characters are dropped, so a tool cannot move the cursor, recolour or
/// retitle the console it is shown in. After a carriage return only what was
/// written last stays, as a terminal would show it.
pub fn plain(line: &str) -> String {
    let mut out = String::new();
    let mut returned = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                Some('[') => skip_control_sequence(&mut chars),
                Some(']' | 'P' | 'X' | '^' | '_') => skip_control_string(&mut chars),
                Some('\u{20}'..='\u{2f}') => {
                    while chars
                        .next_if(|c| ('\u{20}'..='\u{2f}').contains(c))
                        .is_some()
                    {}
                    chars.next();
                }
                _ => {}
            },
            '\u{9b}' => skip_control_sequence(&mut chars),
            '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}' => skip_control_string(&mut chars),
            '\r' => returned = true,
            c if c.is_control() && c != '\t' => {}
            c if tools::is_invisible_format(c) => {}
            c => {
                if std::mem::take(&mut returned) {
                    out.clear();
                }
                if c == '\t' {
                    out.push_str("    ");
                } else {
                    out.push(c);
                }
            }
        }
    }
    out
}

/// The rest of a control sequence: parameters, then the one byte that ends it.
fn skip_control_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while chars
        .next_if(|c| ('\u{20}'..='\u{3f}').contains(c))
        .is_some()
    {}
    chars.next_if(|c| ('\u{40}'..='\u{7e}').contains(c));
}

/// The rest of a control string (a window title, a link), up to its
/// terminator or the end of the line.
fn skip_control_string(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(c) = chars.next() {
        match c {
            '\u{7}' | '\u{9c}' => return,
            '\u{1b}' => {
                chars.next_if_eq(&'\\');
                return;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::assistant::model::Picked;

    fn typed(chat: &mut Chat, text: &str) -> Step {
        let mut last = Step::Stay;
        for c in text.chars() {
            last = chat.on_key(&c.to_string());
        }
        last
    }

    fn last(chat: &Chat) -> &str {
        &chat.entries().last().expect("nothing was said").text
    }

    #[test]
    fn a_slash_lists_the_tools_and_typing_narrows_them() {
        let mut chat = Chat::new();
        assert!(chat.palette().is_empty());
        typed(&mut chat, "/");
        assert_eq!(chat.palette().len(), TOOLS.len() + 2);
        typed(&mut chat, "as");
        let names: Vec<_> = chat.palette().iter().map(|r| r.name).collect();
        assert_eq!(names, ["assistant"]);
        chat.on_key("Backspace");
        chat.on_key("Backspace");
        typed(&mut chat, "st");
        let names: Vec<_> = chat.palette().iter().map(|r| r.name).collect();
        assert_eq!(names, ["status", "start", "stop", "stake"]);
        typed(&mut chat, "atus now");
        assert!(chat.palette().is_empty());
    }

    #[test]
    fn enter_takes_the_chosen_tool_and_waits_for_an_argument_it_needs() {
        let mut chat = Chat::new();
        typed(&mut chat, "/doc");
        assert_eq!(chat.on_key("Enter"), Step::Run(vec!["doctor".into()]));
        assert_eq!(chat.running(), Some("tenzro doctor"));
        chat.finished(Some(0));

        typed(&mut chat, "/mod");
        chat.on_key("Down");
        assert_eq!(chat.palette()[chat.choice()].name, "model");
        assert_eq!(chat.on_key("Enter"), Step::Stay);
        assert_eq!(chat.input(), "/model ");
        typed(&mut chat, "qwen");
        assert_eq!(
            chat.on_key("Enter"),
            Step::Run(vec!["model".into(), "info".into(), "qwen".into()])
        );
    }

    #[test]
    fn a_name_typed_in_full_is_that_tool_whatever_the_list_shows_first() {
        let mut chat = Chat::new();
        typed(&mut chat, "/model");
        assert_eq!(chat.on_key("Enter"), Step::Stay);
        assert!(last(&chat).starts_with("/model needs <MODEL_ID>"));
        typed(&mut chat, "/nope");
        assert_eq!(chat.on_key("Enter"), Step::Stay);
        assert!(last(&chat).starts_with("There is no tool /nope."));
    }

    #[test]
    fn a_tool_that_reads_runs_and_its_output_joins_the_conversation() {
        let mut chat = Chat::new();
        assert_eq!(chat.submit("/status"), Step::Run(vec!["status".into()]));
        assert_eq!(typed(&mut chat, "x"), Step::Stay);
        assert_eq!(chat.input(), "");
        assert_eq!(chat.on_key("Esc"), Step::Stop);
        chat.output("height 12");
        chat.output("peers 3");
        assert_eq!(last(&chat), "height 12\npeers 3");
        chat.finished(Some(2));
        assert_eq!(last(&chat), "tenzro status ended with exit code 2.");
        assert_eq!(chat.running(), None);
        chat.output("late line");
        assert_eq!(last(&chat), "tenzro status ended with exit code 2.");
    }

    #[test]
    fn a_tool_that_changes_something_runs_only_after_a_yes() {
        let mut chat = Chat::new();
        assert_eq!(chat.submit("/serve qwen"), Step::Stay);
        assert_eq!(
            chat.pending().as_deref(),
            Some("tenzro model serve qwen --rpc http://127.0.0.1:8545")
        );
        assert!(last(&chat).contains("needs your key"));
        assert!(last(&chat).contains("tenzro model serve qwen --rpc http://127.0.0.1:8545"));
        for key in ["Enter", "x", "Tab", "Up"] {
            assert_eq!(chat.on_key(key), Step::Stay, "{key}");
            assert!(chat.pending().is_some(), "{key}");
        }
        assert_eq!(chat.on_key("n"), Step::Stay);
        assert_eq!(chat.pending(), None);
        assert_eq!(last(&chat), "Not run.");

        chat.submit("/serve qwen");
        assert_eq!(chat.on_key("y"), Step::Stay);
        assert!(chat.armed());
        assert_eq!(chat.on_key("x"), Step::Stay, "another key takes the y back");
        assert_eq!(chat.on_key("Enter"), Step::Stay);
        assert!(chat.pending().is_some());
        assert_eq!(chat.on_key("y"), Step::Stay);
        assert_eq!(
            chat.on_key("Enter"),
            Step::Handover(vec![
                "model".into(),
                "serve".into(),
                "qwen".into(),
                "--rpc".into(),
                "http://127.0.0.1:8545".into()
            ])
        );
        assert_eq!(chat.pending(), None);
        chat.handed_back(Some(0));
        assert_eq!(
            last(&chat),
            "tenzro model serve qwen --rpc http://127.0.0.1:8545 finished."
        );
        assert_eq!(chat.running(), None);
    }

    #[test]
    fn the_command_shown_is_the_command_that_runs() {
        for tool in tools::TOOLS {
            let holes = tool.command.split(' ').filter(|w| w.starts_with('<'));
            let values: Vec<String> = (0..holes.count())
                .map(|n| format!("v{n};$(x)'\"*"))
                .collect();
            let line = format!("/{} {}", tool.name, values.join(" "));
            let mut chat = Chat::new();
            let argv = match chat.submit(&line) {
                Step::Run(argv) => argv,
                Step::Stay => {
                    let offered = chat.pending().expect(&line);
                    assert!(last(&chat).contains(&format!("\n  {offered}\n")), "{line}");
                    assert_eq!(chat.on_key("y"), Step::Stay, "{line}");
                    let Step::Handover(argv) = chat.on_key("Enter") else {
                        panic!("{line} was not handed over");
                    };
                    assert_eq!(offered, tools::shown(&argv), "{line}");
                    argv
                }
                other => panic!("{line}: {other:?}"),
            };
            assert_eq!(argv, tool.invocation(&values).argv, "{line}");
            let shown = tools::shown(&argv);
            assert_eq!(chat.running(), Some(shown.as_str()), "{line}");
            // The text shown stands for exactly one argument list: a shell
            // reads it back as these words.
            #[cfg(unix)]
            {
                let words = shown.strip_prefix("tenzro ").unwrap();
                let out = std::process::Command::new("sh")
                    .args(["-c", &format!("printf '%s\\n' {words}")])
                    .output()
                    .unwrap();
                let read_back = String::from_utf8(out.stdout).unwrap();
                let expected: String = argv.iter().map(|w| format!("{w}\n")).collect();
                assert_eq!(read_back, expected, "{line}");
            }
        }
    }

    #[test]
    fn a_paste_is_text_and_never_an_answer() {
        let mut chat = Chat::new();
        chat.paste("/update\ny\n");
        assert_eq!(chat.input(), "/update y ");
        assert_eq!(chat.pending(), None);
        chat.type_over(String::new());
        chat.submit("/update");
        assert!(chat.pending().is_some());
        chat.paste("y\n");
        assert!(!chat.armed());
        assert_eq!(chat.input(), "");
        assert_eq!(chat.on_key("Enter"), Step::Stay);
        assert!(chat.pending().is_some());
        let mut chat = Chat::new();
        chat.paste("a\u{202e}b\u{1b}[2Jc\u{200b}");
        assert_eq!(chat.input(), "ab[2Jc");
    }

    #[test]
    fn what_a_tool_prints_is_kept_as_text_only() {
        assert_eq!(plain("\u{1b}[1;31mfailed\u{1b}[0m"), "failed");
        assert_eq!(plain("\u{1b}[2J\u{1b}[Hcleared\u{1b}[?25l"), "cleared");
        assert_eq!(plain("\u{1b}]0;a title\u{7}height 12"), "height 12");
        assert_eq!(
            plain("\u{1b}]8;;http://x\u{1b}\\link\u{1b}]8;;\u{1b}\\ after"),
            "link after"
        );
        assert_eq!(plain("\u{1b}(Bascii\u{1b}7\u{1b}8"), "ascii");
        assert_eq!(plain("\u{9b}31mred\u{9d}0;t\u{9c}."), "red.");
        assert_eq!(plain("10%\r50%\r100%"), "100%");
        assert_eq!(plain("done\r"), "done");
        assert_eq!(plain("a\tb\u{8}\u{7}\u{0}c"), "a    bc");
        assert_eq!(plain("cut \u{1b}[31"), "cut ");
        assert_eq!(plain("cut \u{1b}]0;never ended"), "cut ");
        assert_eq!(
            plain("abc\u{202e}fed\u{202c} \u{2066}x\u{2069}\u{200e}"),
            "abcfed x"
        );
        assert_eq!(
            plain("zero\u{200b}\u{200d}\u{feff}width\u{ad}"),
            "zerowidth"
        );
        assert_eq!(plain("end \u{1b}"), "end ");
        assert_eq!(plain("naïve ✓ 日本"), "naïve ✓ 日本");

        let mut chat = Chat::new();
        chat.submit("/status");
        chat.output("\u{1b}[32mheight\u{1b}[0m 12\u{1b}[?25l");
        chat.output("\u{1b}]0;gone\u{7}peers 3\u{1b}[1A");
        assert_eq!(last(&chat), "height 12\npeers 3");
    }

    #[test]
    fn a_changing_tool_without_its_argument_is_never_offered() {
        let mut chat = Chat::new();
        assert_eq!(chat.submit("/serve"), Step::Stay);
        assert_eq!(chat.pending(), None);
        assert!(last(&chat).starts_with("/serve needs <MODEL_ID>"));
        assert_eq!(chat.on_key("y"), Step::Stay);
        assert_eq!(chat.input(), "y");
    }

    #[test]
    fn plain_words_never_run_a_tool() {
        let mut chat = Chat::new();
        for line in ["stop the node", "update apply", "serve qwen and stake 100"] {
            assert_eq!(chat.submit(line), Step::Stay, "{line}");
            assert_eq!(chat.pending(), None, "{line}");
            assert_eq!(chat.running(), None, "{line}");
        }
    }

    #[test]
    fn a_question_is_answered_from_the_guides_or_not_at_all() {
        let mut chat = Chat::new();
        chat.submit("How do I install on Windows?");
        assert!(last(&chat).starts_with("From "), "{}", last(&chat));
        chat.submit("recipe for sourdough focaccia");
        assert!(last(&chat).contains("do not answer that"));
        assert_eq!(chat.entries().len(), 4);
        assert_eq!(chat.entries()[0].who, Who::You);
    }

    #[test]
    fn escape_clears_the_line_then_closes_and_ctrl_c_quits() {
        let mut chat = Chat::new();
        typed(&mut chat, "/sta");
        assert_eq!(chat.on_key("Esc"), Step::Stay);
        assert_eq!(chat.input(), "");
        assert_eq!(chat.on_key("Esc"), Step::Close);
        assert_eq!(chat.on_key("Ctrl-C"), Step::Quit);
    }

    #[test]
    fn scrolling_back_stops_at_the_first_line() {
        let mut chat = Chat::new();
        chat.submit("/help");
        chat.seen(2);
        for _ in 0..5 {
            chat.on_key("Up");
        }
        assert_eq!(chat.scroll(), 2);
        chat.on_key("Down");
        assert_eq!(chat.scroll(), 1);
        chat.submit("/help");
        assert_eq!(chat.scroll(), 0);
    }

    #[test]
    fn what_is_kept_has_a_bound() {
        let mut chat = Chat::new();
        chat.submit("/status");
        for i in 0..OUTPUT_LINES * 2 {
            chat.output(&format!("line {i}"));
        }
        assert_eq!(last(&chat).lines().count(), OUTPUT_LINES + 1);
        assert!(last(&chat).ends_with("to see all of it)"));
        chat.finished(Some(0));
        for _ in 0..ENTRIES {
            chat.submit("/nope");
        }
        assert_eq!(chat.entries().len(), ENTRIES);
    }

    fn told(chat: &Chat, who: Who) -> String {
        let entry = chat.entries().iter().rev().find(|e| e.who == who);
        entry.map(|e| e.text.clone()).unwrap_or_default()
    }

    fn uses(name: &str, input: Value) -> Value {
        json!({ "type": "tool_use", "id": "call_1", "name": name, "input": input })
    }

    fn said(blocks: Vec<Value>) -> Value {
        json!({ "role": "assistant", "content": blocks })
    }

    fn with_model() -> Chat {
        let mut chat = Chat::new();
        chat.set_model(Some("some-model".to_string()));
        chat
    }

    const ANSWERED: &str = "How do I install on Windows?";

    #[test]
    fn a_tool_the_model_proposes_waits_for_a_yes_with_its_exact_command() {
        let mut chat = with_model();
        let Step::Ask(request) = chat.submit("please serve some-model") else {
            panic!("the model is asked");
        };
        assert!(request["tools"].is_array());
        assert_eq!(chat.asking(), Some("Asking the model"));
        assert_eq!(chat.on_key("y"), Step::Stay);
        let reply = said(vec![uses("serve", json!({ "model_id": "other-model" }))]);
        assert_eq!(chat.replied(Ok(reply)), Step::Stay);
        assert_eq!(chat.asking(), None);
        assert_eq!(
            chat.pending().as_deref(),
            Some("tenzro model serve other-model --rpc http://127.0.0.1:8545")
        );
        assert!(
            told(&chat, Who::Assistant)
                .contains("\n  tenzro model serve other-model --rpc http://127.0.0.1:8545\n")
        );
        for key in ["Enter", "x", "Tab"] {
            assert_eq!(chat.on_key(key), Step::Stay);
        }
        assert_eq!(chat.on_key("n"), Step::Stay);
        assert_eq!(chat.pending(), None);

        let Step::Ask(_) = chat.submit("what is this node doing") else {
            panic!("the model is asked");
        };
        chat.replied(Ok(said(vec![uses("status", json!({}))])));
        assert_eq!(chat.pending().as_deref(), Some("tenzro status"));
        assert_eq!(chat.on_key("y"), Step::Stay);
        assert_eq!(chat.on_key("Enter"), Step::Run(vec!["status".to_string()]));
    }

    #[test]
    fn a_reply_naming_two_tools_or_a_bad_argument_offers_nothing() {
        let replies = [
            said(vec![uses("status", json!({})), uses("stop", json!({}))]),
            said(vec![uses("serve", json!({ "model_id": "x --public" }))]),
            said(vec![uses("serve", json!({ "model_id": "-x" }))]),
            said(vec![uses("shell", json!({ "command": "ls" }))]),
        ];
        for reply in replies {
            let mut chat = with_model();
            chat.submit("do several things at once");
            let step = chat.replied(Ok(reply));
            assert!(!matches!(step, Step::Run(_) | Step::Handover(_)));
            assert_eq!(chat.pending(), None);
            assert_eq!(chat.on_key("y"), Step::Stay);
        }
    }

    #[test]
    fn guide_text_given_to_the_model_never_becomes_a_question() {
        let mut chat = with_model();
        let Step::Ask(_) = chat.submit(ANSWERED) else {
            panic!("the model is asked");
        };
        let none = said(vec![json!({ "type": "text", "text": "NONE" })]);
        let Step::Ask(request) = chat.replied(Ok(none)) else {
            panic!("the guides answer this, so the model is asked to answer from them");
        };
        assert_eq!(request.get("tools"), None);
        let reply = said(vec![
            json!({ "type": "text", "text": "Run the installer.\u{1b}[2J\u{1b}]0;title\u{7}" }),
            uses("update", json!({})),
        ]);
        assert_eq!(chat.replied(Ok(reply)), Step::Stay);
        assert_eq!(chat.pending(), None);
        assert_eq!(chat.asking(), None);
        assert_eq!(told(&chat, Who::Model), "Run the installer.");
        assert!(told(&chat, Who::Assistant).starts_with("From "));
    }

    #[test]
    fn without_a_reply_the_guides_answer() {
        let mut chat = with_model();
        chat.submit(ANSWERED);
        assert_eq!(chat.replied(Err("refused".to_string())), Step::Stay);
        assert!(told(&chat, Who::Assistant).starts_with("The model could not be asked: refused\n"));
        assert_eq!(told(&chat, Who::Model), "");
    }

    #[test]
    fn esc_stops_asking_and_a_late_reply_is_dropped() {
        let mut chat = with_model();
        chat.submit("please serve some-model");
        assert_eq!(chat.on_key("Esc"), Step::Stop);
        assert_eq!(chat.asking(), None);
        let reply = said(vec![uses("status", json!({}))]);
        assert_eq!(chat.replied(Ok(reply)), Step::Stay);
        assert_eq!(chat.pending(), None);
    }

    fn offer(serving: Option<&str>) -> Offer {
        Offer {
            memory_gb: 16,
            serving: serving.map(str::to_string),
            pick: Some(Picked {
                id: "some-model".to_string(),
                licence: "Apache 2.0".to_string(),
                memory_gb: 8,
                download_bytes: 6_000_000_000,
            }),
        }
    }

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn the_assistant_model_is_set_up_by_two_commands_each_asked_on_its_own() {
        let mut chat = Chat::new();
        assert_eq!(chat.submit("/assistant"), Step::Offer);
        assert_eq!(chat.asking(), Some("Reading the node's catalog"));
        chat.offered(Ok(offer(None)));
        assert_eq!(
            chat.pending().as_deref(),
            Some("tenzro model download some-model")
        );
        let download = argv(&["model", "download", "some-model"]);
        chat.on_key("y");
        assert_eq!(chat.on_key("Enter"), Step::Handover(download));
        chat.handed_back(Some(0));
        let serve =
            "tenzro model serve some-model --private --idle-unload 30 --rpc http://127.0.0.1:8545";
        assert_eq!(chat.pending().as_deref(), Some(serve));
        let serve = argv(&[
            "model",
            "serve",
            "some-model",
            "--private",
            "--idle-unload",
            "30",
            "--rpc",
            "http://127.0.0.1:8545",
        ]);
        chat.on_key("y");
        assert_eq!(chat.on_key("Enter"), Step::Handover(serve));
        chat.handed_back(Some(0));
        assert_eq!(chat.pending(), None);

        let mut chat = Chat::new();
        chat.submit("/assistant");
        chat.offered(Ok(offer(None)));
        chat.on_key("y");
        chat.on_key("Enter");
        chat.handed_back(Some(1));
        assert_eq!(chat.pending(), None);

        let mut chat = Chat::new();
        chat.submit("/assistant");
        chat.offered(Ok(offer(None)));
        assert_eq!(chat.on_key("n"), Step::Stay);
        chat.handed_back(Some(0));
        assert_eq!(chat.pending(), None);
    }

    #[test]
    fn a_served_model_answers_at_once_and_an_unasked_offer_is_ignored() {
        let mut chat = Chat::new();
        chat.offered(Ok(offer(None)));
        assert_eq!(chat.pending(), None);
        assert!(!matches!(chat.submit("hello there"), Step::Ask(_)));
        chat.submit("/assistant");
        chat.offered(Ok(offer(Some("served-model"))));
        assert_eq!(chat.pending(), None);
        let Step::Ask(request) = chat.submit("hello there") else {
            panic!("the served model is asked");
        };
        assert_eq!(request["model_id"], "served-model");
    }
}
