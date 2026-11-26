//! What the assistant says back, in the words `tenzro do` and the console
//! share.

use super::knowledge::{DOCS_URL, Pack, Passage};
use super::router::related;
use super::tools::{self, Invocation, TOOLS, Tool};

/// Passages shown for one question, and the most text shown of each.
const PASSAGES: usize = 2;
const PASSAGE_CHARS: usize = 1500;

/// One tool on one line: its slash name, what it does and what running it
/// does to the machine.
pub fn tool_line(tool: &Tool) -> String {
    format!("/{:<13} {} ({})", tool.name, tool.about, tool.risk.label())
}

/// Every tool, one per line.
pub fn help() -> String {
    TOOLS.iter().map(tool_line).collect::<Vec<_>>().join("\n")
}

/// A tool was called without an argument its command takes.
pub fn missing_argument(tool: &Tool, invocation: &Invocation) -> String {
    format!(
        "/{} needs {}:\n  {}",
        tool.name,
        invocation.missing.join(" "),
        invocation.shell()
    )
}

/// A value refused for one of a tool's arguments.
pub fn refused_argument(tool: &Tool, invocation: &Invocation) -> String {
    format!(
        "/{} does not take {}: a value may not start with - or hold a control or formatting \
         character.",
        tool.name,
        tools::quoted(&invocation.refused)
    )
}

/// A slash command no tool has, with the tools whose name starts the same way.
pub fn unknown_tool(name: &str, close: &[&'static Tool]) -> String {
    let names: Vec<String> = close.iter().map(|t| format!("/{}", t.name)).collect();
    let hint = if names.is_empty() {
        String::new()
    } else {
        format!(" Close: {}.", names.join(", "))
    };
    format!("There is no tool /{name}.{hint} /help lists the tools.")
}

/// The start of a passage, cut at a line end.
pub fn excerpt(text: &str) -> &str {
    if text.len() <= PASSAGE_CHARS {
        return text;
    }
    let mut end = PASSAGE_CHARS;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    match text[..end].rfind('\n') {
        Some(line_end) => &text[..line_end],
        None => &text[..end],
    }
}

/// What the shipped guides hold for one question: the passages that answer
/// it, and the tools its words point at.
pub struct Answer<'a> {
    pub passages: Vec<&'a Passage>,
    pub tools: Vec<&'static Tool>,
}

impl<'a> Answer<'a> {
    pub fn find(pack: &'a Pack, question: &str) -> Self {
        Self {
            passages: pack.search(question, PASSAGES),
            tools: related(question),
        }
    }

    /// The answer as text: each passage under the guide and section it comes
    /// from, or a plain statement that the guides do not answer.
    pub fn text(&self) -> String {
        let mut text = String::new();
        for passage in &self.passages {
            text.push_str(&format!(
                "From {}:\n\n{}\n\n",
                passage.citation(),
                excerpt(passage.text)
            ));
        }
        if self.passages.is_empty() {
            text.push_str(&format!(
                "The guides shipped with this release do not answer that. See {DOCS_URL}.\n"
            ));
        }
        if !self.tools.is_empty() {
            text.push_str("Tools that may help:\n");
            for tool in &self.tools {
                text.push_str(&format!("  {}\n", tool_line(tool)));
            }
        }
        text.trim_end().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_passage_is_cut_at_a_line_end() {
        let long = format!("{}\n{}", "a".repeat(PASSAGE_CHARS - 10), "b".repeat(100));
        assert_eq!(excerpt(&long), "a".repeat(PASSAGE_CHARS - 10));
        assert_eq!(excerpt("short"), "short");
        let no_break = "é".repeat(PASSAGE_CHARS);
        assert!(excerpt(&no_break).len() <= PASSAGE_CHARS);
    }

    #[test]
    fn an_answer_names_where_it_comes_from_or_says_there_is_none() {
        let pack = Pack::load();
        let found = Answer::find(&pack, "How do I install on Windows?");
        assert!(!found.passages.is_empty());
        assert!(found.text().starts_with("From "));
        let none = Answer::find(&pack, "recipe for sourdough focaccia");
        assert!(none.passages.is_empty());
        assert!(none.text().contains("do not answer that"));
    }

    #[test]
    fn help_lists_every_tool_once() {
        let text = help();
        assert_eq!(text.lines().count(), TOOLS.len());
        for tool in TOOLS.iter() {
            assert!(
                text.contains(&format!("/{:<13} ", tool.name)),
                "{}",
                tool.name
            );
        }
    }
}
