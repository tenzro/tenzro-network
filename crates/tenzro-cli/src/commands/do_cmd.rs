//! `tenzro do`: the Tenzro Assistant without a screen. One line in, one
//! result out, for a person at a prompt or a script.

use std::io::{BufRead, IsTerminal};
use std::process::Stdio;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{Value, json};

use crate::assistant::chat::plain;
use crate::assistant::knowledge::{DOCS_URL, Pack};
use crate::assistant::local;
use crate::assistant::model::{self, Proposal};
use crate::assistant::reply::{self, Answer, excerpt};
use crate::assistant::router::{Route, route};
use crate::assistant::tools::{TOOLS, Tool};
use crate::rpc::RpcClient;

/// The request was understood and done.
const EXIT_OK: i32 = 0;
/// The node could not be asked.
const EXIT_FAILED: i32 = 1;
/// The line is not something the assistant can act on as written.
const EXIT_USAGE: i32 = 2;
/// The tool changes something: the command is shown for the operator to run.
const EXIT_NEEDS_APPROVAL: i32 = 3;
/// The shipped guides do not answer the question.
const EXIT_NO_ANSWER: i32 = 4;

/// Ask the Tenzro Assistant one thing: a slash command (`/status`, `/help`) or a question
///
/// A tool that only reads runs at once. A tool that changes this machine or
/// needs your key is never run from here: its exact command is printed and
/// the exit code is 3. A question is answered from the guides shipped in
/// this release, with the passages it comes from; when your own node serves
/// a model for the assistant, that model answers from the same passages, and
/// a tool it proposes is printed with its exact command and never run.
/// `/assistant` shows which model the node's catalog offers this machine and
/// the commands that fetch and serve it. With no argument, lines are read
/// from standard input.
///
/// Exit codes: 0 done, 1 the node could not be asked, 2 not understood,
/// 3 needs you to run the command, 4 the guides have no answer; a tool that
/// ran and failed gives its own code.
#[derive(Debug, Parser)]
pub struct DoCmd {
    /// A slash command with its arguments, or a question
    #[arg(value_name = "REQUEST")]
    request: Vec<String>,
}

fn tool_json(tool: &Tool) -> Value {
    json!({ "name": tool.name, "about": tool.about, "risk": tool.risk.label(), "command": format!("tenzro {}", tool.command) })
}

/// Runs a read-only tool as this same program and returns its exit code. In
/// JSON mode its output is captured into the result.
async fn run_tool(argv: &[String], json_output: bool) -> Result<(i32, Option<Value>)> {
    let program = std::env::current_exe().context("cannot find this program to run the tool")?;
    let mut child = tokio::process::Command::new(program);
    child
        .args(argv)
        .stdin(Stdio::null())
        .env("TENZRO_NO_BANNER", "1");
    if !json_output {
        let status = child.status().await.context("cannot start the tool")?;
        return Ok((status.code().unwrap_or(1), None));
    }
    let output = child
        .args(["--format", "json"])
        .output()
        .await
        .context("cannot start the tool")?;
    let text = String::from_utf8_lossy(&output.stdout);
    let value = serde_json::from_str(text.trim())
        .unwrap_or_else(|_| Value::String(text.trim().to_string()));
    Ok((output.status.code().unwrap_or(1), Some(value)))
}

/// The model the person's own node serves for the assistant.
struct Served {
    rpc: RpcClient,
    model_id: String,
}

/// The served model, looked up the first time a question needs it.
struct Model {
    looked: bool,
    served: Option<Served>,
}

impl Model {
    fn new() -> Self {
        Self {
            looked: false,
            served: None,
        }
    }

    async fn get(&mut self) -> Option<&Served> {
        if !self.looked {
            self.looked = true;
            let (url, _) = crate::endpoint::resolve();
            if local::is_own_node(&url) {
                let rpc = RpcClient::new(&url);
                if let Some(model_id) = local::served(&rpc).await {
                    self.served = Some(Served { rpc, model_id });
                }
            }
        }
        self.served.as_ref()
    }
}

/// The answer the shipped guides give alone.
fn from_guides(pack: &Pack, question: &str) -> (i32, String, Value) {
    let answer = Answer::find(pack, question);
    let passages: Vec<Value> = answer
        .passages
        .iter()
        .map(|p| json!({ "source": p.citation(), "text": excerpt(p.text) }))
        .collect();
    let answered = !answer.passages.is_empty();
    let object = json!({
        "status": if answered { "answered" } else { "no_answer" },
        "passages": passages,
        "tools": answer.tools.iter().copied().map(tool_json).collect::<Vec<_>>(),
        "docs": DOCS_URL,
    });
    (
        if answered { EXIT_OK } else { EXIT_NO_ANSWER },
        answer.text(),
        object,
    )
}

/// The served model's answer: a tool it proposes is printed, never run;
/// otherwise it answers from the guide passages. Whatever it cannot do, the
/// guides answer alone.
async fn from_model(served: &Served, pack: &Pack, question: &str) -> (i32, String, Value) {
    let guides = from_guides(pack, question);
    let request = model::tool_request(&served.model_id, question);
    let Ok(reply) = local::ask(&served.rpc, request).await else {
        return guides;
    };
    if let Proposal::Call(tool, invocation) = model::proposal(&reply) {
        let text = format!(
            "The model proposes /{} ({}). It is not run from here. Run it yourself:\n  {}",
            tool.name,
            tool.risk.label(),
            invocation.shell()
        );
        let object = json!({
            "status": "proposed",
            "model": served.model_id,
            "tool": tool.name,
            "risk": tool.risk.label(),
            "command": invocation.shell(),
        });
        return (EXIT_NEEDS_APPROVAL, text, object);
    }
    let answer = Answer::find(pack, question);
    if answer.passages.is_empty() {
        return guides;
    }
    let request = model::answer_request(&served.model_id, question, &answer.passages);
    let Ok(reply) = local::ask(&served.rpc, request).await else {
        return guides;
    };
    let words = model::text(&reply);
    if words.is_empty() {
        return guides;
    }
    let words: Vec<String> = words.lines().map(plain).collect();
    let words = words.join("\n");
    let sources: Vec<String> = answer.passages.iter().map(|p| p.citation()).collect();
    let (code, _, mut object) = guides;
    object["model"] = json!(served.model_id);
    object["answer"] = json!(words);
    (
        code,
        format!("{words}\n\nFrom {}.", sources.join("; ")),
        object,
    )
}

/// What `/assistant` reports from here: the model the node serves for the
/// assistant, or the catalog's entry for this machine and the two commands
/// that fetch and serve it, for the person to run.
async fn assistant_offer() -> (i32, String, Value) {
    let (url, _) = crate::endpoint::resolve();
    if !local::is_own_node(&url) {
        let text = format!(
            "The assistant's model runs on your own node, and this request goes to {url}, \
             so questions are answered from the guides."
        );
        return (
            EXIT_USAGE,
            text,
            json!({ "status": "not_own_node", "rpc": url }),
        );
    }
    let offer = match local::offer(&RpcClient::new(&url)).await {
        Ok(offer) => offer,
        Err(error) => {
            let text = format!("The node could not be asked: {error}");
            return (
                EXIT_FAILED,
                text,
                json!({ "status": "failed", "error": error }),
            );
        }
    };
    let mut text = offer.text();
    let mut commands = Vec::new();
    if offer.serving.is_none()
        && let Some(pick) = &offer.pick
    {
        text.push_str("\nRun them yourself, in this order:");
        for invocation in model::setup(&pick.id) {
            text.push_str(&format!("\n  {}", invocation.shell()));
            commands.push(invocation.shell());
        }
    }
    let object = json!({
        "status": "offer",
        "memory_gb": offer.memory_gb,
        "serving": offer.serving,
        "pick": offer.pick.as_ref().map(|p| json!({
            "id": p.id,
            "licence": p.licence,
            "memory_gb": p.memory_gb,
            "download_bytes": p.download_bytes,
        })),
        "commands": commands,
    });
    let code = if commands.is_empty() {
        EXIT_OK
    } else {
        EXIT_NEEDS_APPROVAL
    };
    (code, text, object)
}

/// Handles one line and returns its exit code. Text goes to standard output
/// as it is produced; in JSON mode exactly one object is printed.
async fn handle(line: &str, pack: &Pack, model: &mut Model, json_output: bool) -> Result<i32> {
    let (code, text, object) = match route(line) {
        Route::Empty => (
            EXIT_USAGE,
            "Nothing was asked. /help lists the tools.".to_string(),
            json!({ "status": "empty" }),
        ),
        Route::Help => {
            let tools: Vec<Value> = TOOLS.iter().map(tool_json).collect();
            (
                EXIT_OK,
                reply::help(),
                json!({ "status": "help", "tools": tools }),
            )
        }
        Route::Run { tool, invocation } => {
            if let Some(note) = invocation.left_out()
                && !json_output
            {
                eprintln!("{note}");
            }
            let (code, output) = run_tool(&invocation.argv, json_output).await?;
            let object = json!({ "status": "ran", "tool": tool.name, "command": invocation.shell(), "exit_code": code, "output": output, "left_out": invocation.extra });
            (code, String::new(), object)
        }
        Route::NeedsApproval { tool, invocation } => {
            let mut text = format!(
                "/{} {}, so it is not run from here. Run it yourself:\n  {}",
                tool.name,
                tool.risk.label(),
                invocation.shell()
            );
            if let Some(note) = invocation.left_out() {
                text = format!("{text}\n{note}");
            }
            (
                EXIT_NEEDS_APPROVAL,
                text,
                json!({ "status": "needs_approval", "tool": tool.name, "risk": tool.risk.label(), "command": invocation.shell(), "left_out": invocation.extra }),
            )
        }
        Route::RefusedArgument { tool, invocation } => (
            EXIT_USAGE,
            reply::refused_argument(tool, &invocation),
            json!({ "status": "refused_argument", "tool": tool.name, "refused": invocation.refused }),
        ),
        Route::MissingArgument { tool, invocation } => (
            EXIT_USAGE,
            reply::missing_argument(tool, &invocation),
            json!({ "status": "missing_argument", "tool": tool.name, "missing": invocation.missing, "command": invocation.shell() }),
        ),
        Route::UnknownTool { name, close } => {
            let names: Vec<String> = close.iter().map(|t| format!("/{}", t.name)).collect();
            (
                EXIT_USAGE,
                reply::unknown_tool(&name, &close),
                json!({ "status": "unknown_tool", "name": name, "close": names }),
            )
        }
        Route::Assistant => assistant_offer().await,
        Route::Question(question) => match model.get().await {
            Some(served) => from_model(served, pack, &question).await,
            None => from_guides(pack, &question),
        },
    };
    if json_output {
        println!("{object}");
    } else if !text.is_empty() {
        println!("{text}");
    }
    Ok(code)
}

impl DoCmd {
    pub async fn execute(self, json_output: bool) -> Result<()> {
        let pack = Pack::load();
        let mut model = Model::new();
        let mut code = EXIT_OK;
        if !self.request.is_empty() {
            code = handle(&self.request.join(" "), &pack, &mut model, json_output).await?;
        } else if std::io::stdin().is_terminal() {
            code = handle("", &pack, &mut model, json_output).await?;
        } else {
            for line in std::io::stdin().lock().lines() {
                let line = line.context("cannot read standard input")?;
                if line.trim().is_empty() {
                    continue;
                }
                let this = handle(&line, &pack, &mut model, json_output).await?;
                if this != EXIT_OK {
                    code = this;
                }
            }
        }
        if code != EXIT_OK {
            std::process::exit(code);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No served model: the tests never reach a node.
    fn guides_only() -> Model {
        Model {
            looked: true,
            served: None,
        }
    }

    #[test]
    fn a_request_keeps_its_words_in_order() {
        let cmd = DoCmd::parse_from(["do", "/stake", "validator", "100"]);
        assert_eq!(cmd.request.join(" "), "/stake validator 100");
        assert!(DoCmd::parse_from(["do"]).request.is_empty());
    }

    #[tokio::test]
    async fn a_changing_tool_and_an_unknown_one_give_their_codes_without_running_anything() {
        let pack = Pack::load();
        assert_eq!(
            handle("/serve some-model", &pack, &mut guides_only(), true)
                .await
                .unwrap(),
            EXIT_NEEDS_APPROVAL
        );
        assert_eq!(
            handle("/update", &pack, &mut guides_only(), true)
                .await
                .unwrap(),
            EXIT_NEEDS_APPROVAL
        );
        assert_eq!(
            handle("/nope", &pack, &mut guides_only(), true)
                .await
                .unwrap(),
            EXIT_USAGE
        );
        assert_eq!(
            handle("/model", &pack, &mut guides_only(), true)
                .await
                .unwrap(),
            EXIT_USAGE
        );
        assert_eq!(
            handle("/help", &pack, &mut guides_only(), true)
                .await
                .unwrap(),
            EXIT_OK
        );
        assert_eq!(
            handle("", &pack, &mut guides_only(), true).await.unwrap(),
            EXIT_USAGE
        );
        let flag = "/model --catalog-rpc=http://example.com";
        assert_eq!(
            handle(flag, &pack, &mut guides_only(), true).await.unwrap(),
            EXIT_USAGE
        );
        let check = handle("/update-check", &pack, &mut guides_only(), true).await;
        assert_eq!(check.unwrap(), EXIT_NEEDS_APPROVAL);
    }

    #[tokio::test]
    async fn a_question_is_answered_from_the_guides_or_not_at_all() {
        let pack = Pack::load();
        assert_eq!(
            handle(
                "How do I install on Windows?",
                &pack,
                &mut guides_only(),
                true
            )
            .await
            .unwrap(),
            EXIT_OK
        );
        assert_eq!(
            handle(
                "recipe for sourdough focaccia",
                &pack,
                &mut guides_only(),
                true
            )
            .await
            .unwrap(),
            EXIT_NO_ANSWER
        );
    }
}
