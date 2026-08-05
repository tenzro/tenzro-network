//! Conformance: for every GGUF on this machine, does its own chat template
//! carry tools, and does llama.cpp derive a grammar from their schemas?
//!
//! The runtime never asks *which model* it is serving. It hands the tool array
//! to whatever template the GGUF ships and uses what comes back — so a new
//! model is supported by being installed, not by being added to a list. This
//! test exists to keep that honest: it enumerates the models directory and
//! reports on each, rather than pinning one file.
//!
//! What it asserts, per model that declares tool support:
//!
//! - the tool-aware render is non-empty (an empty render is a real failure
//!   mode — `render_chat_prompt` already had to guard the plain path against
//!   templates that return `Ok("")`);
//! - the rendered prompt actually mentions the tools it was given;
//! - if a grammar comes back it is lazy (an eager one would force *every*
//!   reply to be a tool call) and its triggers resolve to a leading token,
//!   because the pattern path in the vendored fork aborts the process.
//!
//! A model whose template ignores the tool array is *not* a failure — that is
//! precisely the case the preamble fallback exists for. It is reported so the
//! operator knows which path a given model takes.
//!
//! Ignored by default: it reads multi-gigabyte local model files.

use std::path::{Path, PathBuf};

use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, GrammarTriggerType, LlamaChatMessage, LlamaModel};

/// Where this node keeps its GGUFs. Overridable so the test follows the
/// operator's layout rather than assuming one.
fn models_dir() -> PathBuf {
    std::env::var("TENZRO_MODELS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".into()))
                .join(".tenzro/models")
        })
}

fn ggufs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "gguf"))
        .collect();
    out.sort();
    out
}

/// Two tools with distinct names and a required parameter each, so a rendered
/// prompt and a derived grammar both have something specific to contain.
const TOOLS_JSON: &str = r#"[
  {"type":"function","function":{
     "name":"read_file",
     "description":"Read a file from the workspace.",
     "parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}}},
  {"type":"function","function":{
     "name":"edit_file",
     "description":"Replace a string in a file.",
     "parameters":{"type":"object","properties":{
        "path":{"type":"string"},"old":{"type":"string"},"new":{"type":"string"}},
        "required":["path","old","new"]}}}
]"#;

#[test]
#[ignore = "reads the local GGUFs under ~/.tenzro/models"]
fn every_local_model_renders_tools_through_its_own_template() {
    let dir = models_dir();
    let models = ggufs(&dir);
    if models.is_empty() {
        eprintln!("no GGUFs under {} — nothing to check", dir.display());
        return;
    }

    let backend = LlamaBackend::init().expect("backend");
    let mut with_tools = 0usize;
    let mut problems: Vec<String> = Vec::new();

    for path in &models {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let model = match LlamaModel::load_from_file(&backend, path, &LlamaModelParams::default()) {
            Ok(m) => m,
            Err(e) => {
                problems.push(format!("{name}: will not load ({e})"));
                continue;
            }
        };

        let Ok(tmpl) = model.chat_template(None) else {
            println!("  {name}: no chat template — preamble fallback");
            continue;
        };

        let messages = vec![
            LlamaChatMessage::new("system".into(), "You are a coding agent.".into()).unwrap(),
            LlamaChatMessage::new("user".into(), "Read src/parser.rs.".into()).unwrap(),
        ];

        let res = match model.apply_chat_template_with_tools_oaicompat(
            &tmpl,
            &messages,
            Some(TOOLS_JSON),
            None,
            true,
        ) {
            Ok(r) => r,
            Err(e) => {
                println!("  {name}: template declines tools ({e}) — preamble fallback");
                continue;
            }
        };

        if res.prompt.trim().is_empty() {
            problems.push(format!(
                "{name}: tool-aware render returned an empty prompt, which tokenizes to \
                 zero tokens and fails the decode"
            ));
            continue;
        }

        let mentions_tools = res.prompt.contains("read_file") && res.prompt.contains("edit_file");
        if !mentions_tools {
            println!("  {name}: template ignores the tool array — preamble fallback");
            continue;
        }

        with_tools += 1;
        let grammar = res.grammar.as_deref().unwrap_or("");
        println!(
            "  {name}: native tools ✓  prompt={}B grammar={}B lazy={} triggers={}",
            res.prompt.len(),
            grammar.len(),
            res.grammar_lazy,
            res.grammar_triggers.len(),
        );

        if grammar.is_empty() {
            continue;
        }

        // An eager grammar would force every reply into a tool call.
        if !res.grammar_lazy {
            problems.push(format!("{name}: grammar is not lazy"));
        }
        if res.grammar_triggers.is_empty() {
            problems.push(format!(
                "{name}: lazy grammar declares no triggers, so it never constrains"
            ));
        }

        // Only the token-trigger path is usable in the vendored fork; a word
        // trigger has to resolve to a leading token whose piece opens the
        // grammar's root rule, or the runtime declines the grammar.
        for t in &res.grammar_triggers {
            if !matches!(t.trigger_type, GrammarTriggerType::Word) {
                continue;
            }
            let toks = model
                .str_to_token(&t.value, AddBos::Never)
                .unwrap_or_default();
            let Some(first) = toks.first().copied() else {
                problems.push(format!(
                    "{name}: trigger {:?} tokenizes to nothing",
                    t.value
                ));
                continue;
            };
            let mut dec = encoding_rs::UTF_8.new_decoder();
            let piece = model
                .token_to_piece(first, &mut dec, true, None)
                .unwrap_or_default();
            if piece.is_empty() || !t.value.starts_with(&piece) {
                problems.push(format!(
                    "{name}: trigger {:?} does not open with its own leading token {piece:?}",
                    t.value
                ));
            }
        }
    }

    println!(
        "\n{} model(s) checked, {} render tools natively",
        models.len(),
        with_tools
    );
    assert!(
        problems.is_empty(),
        "tool-template problems:\n  {}",
        problems.join("\n  ")
    );
}
