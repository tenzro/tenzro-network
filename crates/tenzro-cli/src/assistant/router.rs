//! Decides what a line of input asks for, with no model: a slash command is
//! a tool, anything else is a question.

use super::tools::{self, Invocation, Risk, TOOLS, Tool};

/// What one line of input asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Nothing was typed.
    Empty,
    /// A read-only tool with every argument given: run it.
    Run {
        tool: &'static Tool,
        invocation: Invocation,
    },
    /// A tool that changes something: show the command, never run it.
    NeedsApproval {
        tool: &'static Tool,
        invocation: Invocation,
    },
    /// A value refused for one of the tool's arguments.
    RefusedArgument {
        tool: &'static Tool,
        invocation: Invocation,
    },
    /// A read-only tool called without an argument it needs.
    MissingArgument {
        tool: &'static Tool,
        invocation: Invocation,
    },
    /// `/help`: the list of tools.
    Help,
    /// `/assistant`: what the node's catalog offers the assistant here.
    Assistant,
    /// A slash command no tool has; the tools whose name starts the same way.
    UnknownTool {
        name: String,
        close: Vec<&'static Tool>,
    },
    /// A question for the documentation.
    Question(String),
}

/// Routes one line. Plain language never selects a tool by itself.
pub fn route(input: &str) -> Route {
    let line = input.trim();
    if line.is_empty() {
        return Route::Empty;
    }
    let Some(command) = line.strip_prefix('/') else {
        return Route::Question(line.to_string());
    };
    let mut words = command.split_whitespace();
    let name = words.next().unwrap_or_default();
    if name.eq_ignore_ascii_case("help") || name == "?" {
        return Route::Help;
    }
    if name.eq_ignore_ascii_case("assistant") {
        return Route::Assistant;
    }
    let Some(tool) = tools::find(name) else {
        let lower = name.to_ascii_lowercase();
        let close = TOOLS
            .iter()
            .filter(|t| !lower.is_empty() && t.name.starts_with(&lower))
            .collect();
        return Route::UnknownTool {
            name: name.to_string(),
            close,
        };
    };
    let args: Vec<String> = words.map(str::to_string).collect();
    let invocation = tool.invocation(&args);
    if !invocation.refused.is_empty() {
        return Route::RefusedArgument { tool, invocation };
    }
    match tool.risk {
        Risk::ReadOnly if invocation.missing.is_empty() => Route::Run { tool, invocation },
        Risk::ReadOnly => Route::MissingArgument { tool, invocation },
        Risk::Confirm | Risk::Authority => Route::NeedsApproval { tool, invocation },
    }
}

/// The tools whose keywords appear in a question, best match first. Offered
/// beside an answer; the caller still has to type the slash command.
pub fn related(question: &str) -> Vec<&'static Tool> {
    let lower = question.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    let mut scored: Vec<(usize, &'static Tool)> = TOOLS
        .iter()
        .map(|t| (t.keywords.iter().filter(|k| words.contains(k)).count(), t))
        .filter(|(hits, _)| *hits > 0)
        .collect();
    scored.sort_by_key(|(hits, _)| std::cmp::Reverse(*hits));
    scored.into_iter().take(3).map(|(_, t)| t).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_only_slash_command_runs() {
        let Route::Run { tool, invocation } = route("  /st ") else {
            panic!("not run")
        };
        assert_eq!(tool.name, "status");
        assert_eq!(invocation.argv, ["status"]);
    }

    #[test]
    fn a_network_duty_is_read_freely_and_acted_on_only_after_approval() {
        assert!(matches!(route("/duties"), Route::Run { .. }));
        assert!(matches!(route("/challenges"), Route::Run { .. }));
        assert!(matches!(route("/challenge"), Route::MissingArgument { .. }));
        let id = "6f1c2a8e-3b4d-4e5f-9a0b-1c2d3e4f5a6b";
        let Route::NeedsApproval { tool, invocation } = route(&format!("/vote {id}")) else {
            panic!("a vote is not shown for approval")
        };
        assert_eq!(tool.risk, Risk::Authority);
        assert_eq!(
            invocation.shell(),
            format!("tenzro inference commit-vote {id}")
        );
        for line in [
            format!("/reexecute {id}"),
            format!("/reveal {id}"),
            format!("/finalize {id}"),
            "/contest ab12 0xabcd receipt.json inputs.json".to_string(),
        ] {
            assert!(
                matches!(route(&line), Route::NeedsApproval { .. }),
                "{line}"
            );
        }
        let names: Vec<&str> = related("which committee seat duties do I have?")
            .iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names.first(), Some(&"duties"));
    }

    #[test]
    fn a_changing_tool_is_shown_and_never_run() {
        for line in [
            "/serve qwen",
            "/stop",
            "/stake validator 100",
            "/update",
            "/download qwen",
        ] {
            assert!(matches!(route(line), Route::NeedsApproval { .. }), "{line}");
        }
        let Route::NeedsApproval { invocation, .. } = route("/serve qwen") else {
            unreachable!()
        };
        assert_eq!(
            invocation.shell(),
            "tenzro model serve qwen --rpc http://127.0.0.1:8545"
        );
    }

    #[test]
    fn a_read_only_tool_without_its_argument_does_not_run() {
        let Route::MissingArgument { invocation, .. } = route("/model") else {
            panic!("ran")
        };
        assert_eq!(invocation.missing, ["<MODEL_ID>"]);
    }

    #[test]
    fn an_unknown_slash_command_names_the_close_ones() {
        let Route::UnknownTool { name, close } = route("/sta") else {
            panic!("known")
        };
        assert_eq!(name, "sta");
        let names: Vec<_> = close.iter().map(|t| t.name).collect();
        assert_eq!(names, ["status", "start", "stake"]);
        assert_eq!(
            route("/"),
            Route::UnknownTool {
                name: String::new(),
                close: vec![]
            }
        );
    }

    #[test]
    fn plain_language_is_a_question_even_when_it_names_a_tool() {
        assert_eq!(
            route("stop the node"),
            Route::Question("stop the node".into())
        );
        assert_eq!(route("   "), Route::Empty);
        assert_eq!(route("/help"), Route::Help);
        let flag = route("/model --catalog-rpc=http://example.com");
        assert!(matches!(flag, Route::RefusedArgument { .. }), "{flag:?}");
        let flag = route("/serve -x");
        assert!(matches!(flag, Route::RefusedArgument { .. }), "{flag:?}");
        assert_eq!(route("/assistant"), Route::Assistant);
        assert_eq!(route("/?"), Route::Help);
    }

    #[test]
    fn related_tools_follow_the_question_words() {
        let names: Vec<_> = related("is my node synced and running?")
            .iter()
            .map(|t| t.name)
            .collect();
        assert_eq!(names.first(), Some(&"status"));
        assert!(related("tell me a story").is_empty());
    }
}
